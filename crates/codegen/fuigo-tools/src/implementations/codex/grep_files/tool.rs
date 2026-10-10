//! `CodexGrepFilesTool` — file-path-only regex search via ripgrep.
//!
//! This is a faithful port of `codex-rs/core/src/tools/handlers/grep_files.rs`.
//! It returns **file paths only** (`--files-with-matches`), sorted by
//! modification time. See the plan document for the full diff vs the
//! fuigo-build `GrepTool`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tokio::time::timeout;

use crate::implementations::fuigo_build::grep::ripgrep::rg_path;
use crate::types::output::CodexGrepFilesOutput;
use crate::types::requirements::Expr;
#[allow(unused_imports)]
use crate::types::resources::Cwd;
use crate::types::tool::{ToolKind, ToolNamespace};

// ─── Constants ──────────────────────────────────────────────────────

const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 2000;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

// ─── Description ────────────────────────────────────────────────────

const DESCRIPTION: &str = "Finds files whose contents match the ${{ params.search.pattern }} and lists them by modification time.";

// ─── Input ──────────────────────────────────────────────────────────

fn default_limit() -> usize {
    DEFAULT_LIMIT
}

/// Input for the codex `grep_files` tool.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodexGrepFilesInput {
    /// Regular expression pattern to search for.
    pub pattern: String,

    /// Optional glob that limits which files are searched (e.g. "*.rs" or "*.{ts,tsx}").
    #[serde(default)]
    pub include: Option<String>,

    /// Directory or file path to search. Defaults to the session's working directory.
    #[serde(default)]
    pub path: Option<String>,

    /// Maximum number of file paths to return (defaults to 100).
    #[serde(default = "default_limit")]
    pub limit: usize,
}

// ─── Tool ───────────────────────────────────────────────────────────

/// Codex-namespace grep_files tool — file-path-only regex search.
///
/// Shares `ToolKind::Search` with the fuigo-build `GrepTool`. These tools are
/// namespace-exclusive — consumers enable either `FuigoBuild` or `Codex` search,
/// never both simultaneously. This follows the same pattern as
/// `CodexListDirTool`/`ListDirTool` (`ToolKind::ListDir`) and
/// `CodexReadFileTool`/`ReadFileImpl` (`ToolKind::Read`).
#[derive(Debug, Default)]
pub struct CodexGrepFilesTool;

// ─── rg execution ───────────────────────────────────────────────────

/// Run `rg --files-with-matches` and return matching file paths.
///
/// Direct port from `codex-rs/core/src/tools/handlers/grep_files.rs`.
#[cfg(test)]
async fn run_rg_search(
    pattern: &str,
    include: Option<&str>,
    search_path: &Path,
    limit: usize,
    cwd: &Path,
) -> Result<Vec<String>, String> {
    run_rg_search_excluding(pattern, include, search_path, limit, cwd, &[]).await
}

/// Run `rg --files-with-matches` skipping the managed Read-deny globs ([`DenyReadGlobs`]), as the fuigo-build grep does: a
/// search under a permitted root never reports a policy-forbidden file. The excludes come after the caller's `include`
/// so they win (ripgrep applies the last matching glob).
///
/// [`DenyReadGlobs`]: crate::types::resources::DenyReadGlobs
async fn run_rg_search_excluding(
    pattern: &str,
    include: Option<&str>,
    search_path: &Path,
    limit: usize,
    cwd: &Path,
    deny_read_globs: &[String],
) -> Result<Vec<String>, String> {
    let results = crate::util::read_deny::ResultFilter::new(cwd, deny_read_globs);
    if results.is_active() {
        return run_rg_search_filtered(pattern, include, search_path, limit, cwd, results).await;
    }
    let rg_exec = rg_path().map_err(|e| e.to_string())?;
    let mut command = Command::new(rg_exec);
    command
        .current_dir(cwd)
        .arg("--files-with-matches")
        .arg("--sortr=modified")
        .arg("--regexp")
        .arg(pattern)
        .arg("--no-messages");

    if let Some(glob) = include {
        command.arg("--glob").arg(glob);
    }
    for deny in deny_read_globs {
        command.arg("--glob").arg(format!("!{deny}"));
    }

    command.arg("--").arg(search_path);
    crate::util::detach_search_command(&mut command);

    let output = timeout(COMMAND_TIMEOUT, command.output())
        .await
        .map_err(|_| "rg timed out after 30 seconds".to_string())?
        .map_err(|err| {
            format!("failed to launch rg: {err}. Ensure ripgrep is installed and on PATH.")
        })?;

    match output.status.code() {
        Some(0) => Ok(parse_results(&output.stdout, limit)),
        Some(1) => Ok(Vec::new()),
        _ => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("rg failed: {stderr}"))
        }
    }
}

/// The read-rules path of [`run_rg_search_excluding`]: typed `--json` records, only allowed files kept.
async fn run_rg_search_filtered(
    pattern: &str,
    include: Option<&str>,
    search_path: &Path,
    limit: usize,
    cwd: &Path,
    results: crate::util::read_deny::ResultFilter,
) -> Result<Vec<String>, String> {
    let rg_exec = rg_path().map_err(|e| e.to_string())?;
    let mut command = Command::new(rg_exec);
    // Read rules (P198 round 4): ripgrep prints typed `--json` records and `RgJsonStream` keeps the allowed files.
    if cwd.is_dir() {
        command.current_dir(cwd);
    }
    command
        .arg("--json")
        .arg("--max-count")
        .arg("1")
        .arg("--sortr=modified")
        .arg("--regexp")
        .arg(pattern)
        .arg("--no-messages");

    if let Some(glob) = include {
        command.arg("--glob").arg(glob);
    }

    command.arg("--").arg(search_path);
    crate::util::detach_search_command(&mut command);

    let output = timeout(COMMAND_TIMEOUT, command.output())
        .await
        .map_err(|_| "rg timed out after 30 seconds".to_string())?
        .map_err(|err| {
            format!("failed to launch rg: {err}. Ensure ripgrep is installed and on PATH.")
        })?;

    let mut stream = crate::util::rg_json::RgJsonStream::new(crate::util::rg_json::RgJsonMode::Files, results);
    let _ = stream.feed(&output.stdout);
    let files = parse_found(stream.take_found(), limit);
    match output.status.code() {
        Some(0 | 1) => Ok(files),
        // ripgrep's OWN pattern or flag error names no file: passed through as without rules
        Some(code)
            if crate::util::rg_json::is_own_error(code, output.stdout.is_empty(), &output.stderr) =>
        {
            Err(format!("rg failed: {}", String::from_utf8_lossy(&output.stderr)))
        }
        // any other stderr names files and is never shown when read rules exist
        _ if !files.is_empty() => Ok(files),
        _ => Err("search failed for some paths".to_string()),
    }
}

/// The allowed paths of a filtered search, as text, up to `limit`.
fn parse_found(found: Vec<Vec<u8>>, limit: usize) -> Vec<String> {
    found
        .into_iter()
        .filter_map(|p| String::from_utf8(p).ok())
        .take(limit)
        .collect()
}

/// Parse newline-separated file paths from rg stdout.
///
/// Direct port from `codex-rs/core/src/tools/handlers/grep_files.rs`.
fn parse_results(stdout: &[u8], limit: usize) -> Vec<String> {
    let mut results = Vec::new();
    for line in stdout.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        if let Ok(text) = std::str::from_utf8(line) {
            if text.is_empty() {
                continue;
            }
            results.push(text.to_string());
            if results.len() == limit {
                break;
            }
        }
    }
    results
}

// ─── Tests ──────────────────────────────────────────────────────────

impl crate::types::tool_metadata::ToolMetadata for CodexGrepFilesTool {
    fn kind(&self) -> ToolKind {
        ToolKind::Search
    }

    fn tool_namespace(&self) -> ToolNamespace {
        ToolNamespace::Codex
    }

    fn description_template(&self) -> &str {
        DESCRIPTION
    }

    fn requires_expr(&self) -> Expr<crate::types::requirements::ToolRequirement> {
        Expr::True
    }
}

impl fuigo_tool_runtime::Tool for CodexGrepFilesTool {
    type Args = CodexGrepFilesInput;
    type Output = CodexGrepFilesOutput;

    fn id(&self) -> fuigo_tool_protocol::ToolId {
        fuigo_tool_protocol::ToolId::new("grep_files").expect("valid tool id")
    }

    fn description(
        &self,
        _ctx: &::fuigo_tool_runtime::ListToolsContext,
    ) -> fuigo_tool_types::ToolDescription {
        fuigo_tool_types::ToolDescription::new(
            "grep_files",
            crate::types::tool_metadata::ToolMetadata::sanitized_description_template(self),
        )
    }

    fn capabilities(&self) -> fuigo_tool_protocol::ToolCapabilities {
        fuigo_tool_protocol::ToolCapabilities {
            is_read_only: true,
            tool_scope: Some(fuigo_tool_protocol::ToolScope::Read),
            ..Default::default()
        }
    }

    #[tracing::instrument(name = "tool.codex_grep_files", skip_all)]
    async fn run(
        &self,
        ctx: fuigo_tool_runtime::ToolCallContext,
        input: CodexGrepFilesInput,
    ) -> Result<CodexGrepFilesOutput, fuigo_tool_runtime::ToolError> {
        use crate::types::tool_metadata::shared_resources;
        let resources = shared_resources(&ctx)?;

        let cwd = crate::types::tool_metadata::resolve_cwd(&ctx, &resources).await?;
        let deny_read_globs =
            crate::types::resources::deny_read_globs_for_call(&ctx, &*resources.lock().await);

        // Validation (exact codex rules)
        let pattern = input.pattern.trim().to_string();
        if pattern.is_empty() {
            return Ok(CodexGrepFilesOutput::Error(
                "pattern must not be empty".to_string(),
            ));
        }
        if input.limit == 0 {
            return Ok(CodexGrepFilesOutput::Error(
                "limit must be greater than zero".to_string(),
            ));
        }

        let limit = input.limit.min(MAX_LIMIT);

        // Resolve search path
        let search_path = match &input.path {
            Some(p) if !p.is_empty() => {
                let p = PathBuf::from(p);
                if p.is_absolute() { p } else { cwd.join(p) }
            }
            _ => cwd.clone(),
        };

        // Verify path exists
        if let Err(err) = tokio::fs::metadata(&search_path).await {
            return Ok(CodexGrepFilesOutput::Error(format!(
                "unable to access `{}`: {err}",
                search_path.display()
            )));
        }

        // Clean up include glob
        let include = input.include.as_deref().map(str::trim).and_then(|v| {
            if v.is_empty() {
                None
            } else {
                Some(v.to_string())
            }
        });

        // P198: ripgrep reads an explicit file despite an exclude, so a denied search path is refused before it runs.
        if input.path.as_deref().is_some_and(|p| !p.is_empty())
            && crate::util::read_deny::explicit_search_path_denied(&cwd, &deny_read_globs, &search_path).await
        {
            return Ok(CodexGrepFilesOutput::Error(format!(
                "{} is excluded by a read rule and cannot be searched.",
                search_path.display()
            )));
        }

        // Run rg
        let results = run_rg_search_excluding(
            &pattern,
            include.as_deref(),
            &search_path,
            limit,
            &cwd,
            &deny_read_globs,
        )
        .await;

        match results {
            Ok(files) if files.is_empty() => Ok(CodexGrepFilesOutput::NoMatches(
                "No matches found.".to_string(),
            )),
            Ok(files) => {
                let file_count = files.len();
                Ok(CodexGrepFilesOutput::Matches {
                    content: files.join("\n"),
                    file_count,
                })
            }
            Err(msg) => Ok(CodexGrepFilesOutput::Error(msg)),
        }
    }
}

#[cfg(test)]
mod tests {

    /// P198 part G reopened: interleaved records of two files through this tool's own re-render (`parse_found`).
    #[test]
    fn interleaved_json_records_give_each_allowed_file_once_and_no_denied_file() {
        use crate::util::rg_json::{RgJsonMode, RgJsonStream};
        use crate::util::rg_json_tests as fake;
        let f = fake::fx();
        for (lines, expect) in [(fake::interleaved_allowed(), 2usize), (fake::interleaved_with_denied(), 1usize)] {
            let results = crate::util::read_deny::ResultFilter::new(&f.cwd, &["secrets/**".to_string()]);
            let mut stream = RgJsonStream::new(RgJsonMode::Files, results);
            let _ = stream.feed((lines.join("\n") + "\n").as_bytes());
            let mut files = parse_found(stream.take_found(), 100);
            assert_eq!(files.len(), expect, "{files:?}");
            assert!(files.iter().all(|p| p.starts_with("src/")), "{files:?}");
            files.sort();
            files.dedup();
            assert_eq!(files.len(), expect);
        }
    }
    use super::*;
    use crate::types::resources::Resources;
    use std::process::Command as StdCommand;
    use tempfile::TempDir;

    /// Build a runtime `ToolCallContext` with the given resources.
    fn test_ctx(cwd: &Path) -> fuigo_tool_runtime::ToolCallContext {
        let mut resources = Resources::new();
        resources.insert(Cwd(cwd.to_path_buf()));
        let mut ctx = fuigo_tool_runtime::ToolCallContext::default();
        ctx.extensions.insert(resources.into_shared());
        ctx
    }
    fn rg_available() -> bool {
        // Probe the resolver the tool uses (hermetic under Bazel), not PATH.
        let Ok(rg) = rg_path() else {
            return false;
        };
        StdCommand::new(rg)
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Build a runtime `ToolCallContext` with the given resources.
    // ── Unit tests (parse_results) ──────────────────────────────

    #[test]
    fn parses_basic_results() {
        let stdout = b"/tmp/file_a.rs\n/tmp/file_b.rs\n";
        let parsed = parse_results(stdout, 10);
        assert_eq!(
            parsed,
            vec!["/tmp/file_a.rs".to_string(), "/tmp/file_b.rs".to_string()]
        );
    }

    #[test]
    fn parse_truncates_after_limit() {
        let stdout = b"/tmp/file_a.rs\n/tmp/file_b.rs\n/tmp/file_c.rs\n";
        let parsed = parse_results(stdout, 2);
        assert_eq!(
            parsed,
            vec!["/tmp/file_a.rs".to_string(), "/tmp/file_b.rs".to_string()]
        );
    }

    #[test]
    fn parse_skips_empty_lines() {
        let stdout = b"/tmp/file_a.rs\n\n\n/tmp/file_b.rs\n";
        let parsed = parse_results(stdout, 10);
        assert_eq!(
            parsed,
            vec!["/tmp/file_a.rs".to_string(), "/tmp/file_b.rs".to_string()]
        );
    }

    #[test]
    fn parse_returns_empty_for_empty_input() {
        let stdout = b"";
        let parsed = parse_results(stdout, 10);
        assert!(parsed.is_empty());
    }

    // ── Integration tests (run_rg_search) ───────────────────────

    #[tokio::test]
    async fn run_search_returns_results() {
        if !rg_available() {
            return;
        }
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("match.rs"), "needle in haystack").unwrap();
        std::fs::write(tmp.path().join("nomatch.rs"), "just hay").unwrap();

        let results = run_rg_search("needle", None, tmp.path(), 100, tmp.path())
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].contains("match.rs"));
    }

    #[tokio::test]
    async fn run_search_with_glob_filter() {
        if !rg_available() {
            return;
        }
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("alpha.rs"), "needle").unwrap();
        std::fs::write(tmp.path().join("beta.txt"), "needle").unwrap();

        let results = run_rg_search("needle", Some("*.rs"), tmp.path(), 100, tmp.path())
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].contains("alpha.rs"));
    }

    /// P173: the managed Read-deny globs are excluded, also against a caller `include` that matches the denied file.
    #[tokio::test]
    async fn run_search_skips_read_denied_files() {
        assert!(rg_available(), "ripgrep is required for this test");
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("secrets")).unwrap();
        std::fs::write(tmp.path().join("secrets").join("token.txt"), "needle").unwrap();
        std::fs::write(tmp.path().join("open.txt"), "needle").unwrap();
        let deny = vec!["**/secrets/**".to_owned()];
        for include in [None, Some("*.txt")] {
            let results =
                run_rg_search_excluding("needle", include, tmp.path(), 100, tmp.path(), &deny)
                    .await
                    .unwrap();
            assert_eq!(results.len(), 1, "{results:?} (include {include:?})");
            assert!(results[0].contains("open.txt"), "{results:?}");
        }
    }

    #[tokio::test]
    async fn run_search_respects_limit() {
        if !rg_available() {
            return;
        }
        let tmp = TempDir::new().unwrap();
        for i in 0..5 {
            std::fs::write(tmp.path().join(format!("file_{i}.rs")), "needle").unwrap();
        }

        let results = run_rg_search("needle", None, tmp.path(), 2, tmp.path())
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn run_search_handles_no_matches() {
        if !rg_available() {
            return;
        }
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("file.rs"), "no match here").unwrap();

        let results = run_rg_search("nonexistent_pattern_xyz", None, tmp.path(), 100, tmp.path())
            .await
            .unwrap();
        assert!(results.is_empty());
    }

    // ── Tool-level tests ────────────────────────────────────────

    #[tokio::test]
    async fn tool_reports_empty_pattern_error() {
        let tmp = TempDir::new().unwrap();
        let tool = CodexGrepFilesTool;

        let input = CodexGrepFilesInput {
            pattern: "  ".to_string(),
            include: None,
            path: None,
            limit: 100,
        };

        let result = fuigo_tool_runtime::Tool::run(&tool, test_ctx(tmp.path()), input)
            .await
            .unwrap();
        match result {
            CodexGrepFilesOutput::Error(msg) => {
                assert_eq!(msg, "pattern must not be empty");
            }
            other => panic!("Expected Error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn tool_reports_zero_limit_error() {
        let tmp = TempDir::new().unwrap();
        let tool = CodexGrepFilesTool;

        let input = CodexGrepFilesInput {
            pattern: "test".to_string(),
            include: None,
            path: None,
            limit: 0,
        };

        let result = fuigo_tool_runtime::Tool::run(&tool, test_ctx(tmp.path()), input)
            .await
            .unwrap();
        match result {
            CodexGrepFilesOutput::Error(msg) => {
                assert_eq!(msg, "limit must be greater than zero");
            }
            other => panic!("Expected Error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn tool_reports_no_matches() {
        if !rg_available() {
            return;
        }
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("file.rs"), "nothing interesting").unwrap();

        let tool = CodexGrepFilesTool;

        let input = CodexGrepFilesInput {
            pattern: "nonexistent_pattern_xyz".to_string(),
            include: None,
            path: None,
            limit: 100,
        };

        let result = fuigo_tool_runtime::Tool::run(&tool, test_ctx(tmp.path()), input)
            .await
            .unwrap();
        match result {
            CodexGrepFilesOutput::NoMatches(msg) => {
                assert_eq!(msg, "No matches found.");
            }
            other => panic!("Expected NoMatches, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn tool_collects_matches() {
        if !rg_available() {
            return;
        }
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("alpha.rs"), "needle here").unwrap();
        std::fs::write(tmp.path().join("beta.rs"), "needle there").unwrap();
        std::fs::write(tmp.path().join("gamma.txt"), "no match").unwrap();

        let tool = CodexGrepFilesTool;

        let input = CodexGrepFilesInput {
            pattern: "needle".to_string(),
            include: Some("*.rs".to_string()),
            path: None,
            limit: 100,
        };

        let result = fuigo_tool_runtime::Tool::run(&tool, test_ctx(tmp.path()), input)
            .await
            .unwrap();
        match result {
            CodexGrepFilesOutput::Matches {
                file_count,
                content,
            } => {
                assert_eq!(file_count, 2);
                assert!(content.contains("alpha.rs"));
                assert!(content.contains("beta.rs"));
                assert!(!content.contains("gamma.txt"));
            }
            other => panic!("Expected Matches, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn tool_reports_nonexistent_path_error() {
        let tmp = TempDir::new().unwrap();
        let tool = CodexGrepFilesTool;

        let input = CodexGrepFilesInput {
            pattern: "test".to_string(),
            include: None,
            path: Some("nonexistent_dir".to_string()),
            limit: 100,
        };

        let result = fuigo_tool_runtime::Tool::run(&tool, test_ctx(tmp.path()), input)
            .await
            .unwrap();
        match result {
            CodexGrepFilesOutput::Error(msg) => {
                assert!(
                    msg.contains("unable to access"),
                    "Expected path error, got: {msg}"
                );
            }
            other => panic!("Expected Error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn tool_clamps_limit_to_max() {
        if !rg_available() {
            return;
        }
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("file.rs"), "needle").unwrap();

        let tool = CodexGrepFilesTool;

        let input = CodexGrepFilesInput {
            pattern: "needle".to_string(),
            include: None,
            path: None,
            limit: 5000, // exceeds MAX_LIMIT (2000)
        };

        let result = fuigo_tool_runtime::Tool::run(&tool, test_ctx(tmp.path()), input)
            .await
            .unwrap();
        match result {
            CodexGrepFilesOutput::Matches { file_count, .. } => {
                assert_eq!(file_count, 1);
            }
            other => panic!("Expected Matches, got: {other:?}"),
        }
    }


    /// What the codex `grep_files` tool prints (match list, no-match text or error) for `FAKE`.
    async fn grep_files_text(cwd: std::path::PathBuf, path: Option<String>, deny: Option<Vec<String>>) -> String {
        let mut resources = Resources::new();
        resources.insert(Cwd(cwd));
        if let Some(deny) = deny {
            resources.insert(crate::types::resources::DenyReadGlobs(deny));
        }
        let mut ctx = fuigo_tool_runtime::ToolCallContext::default();
        ctx.extensions.insert(resources.into_shared());
        let input = CodexGrepFilesInput { pattern: "FAKE".to_string(), include: None, path, limit: 100 };
        match fuigo_tool_runtime::Tool::run(&CodexGrepFilesTool, ctx, input).await.unwrap() {
            CodexGrepFilesOutput::Matches { content, .. } => content,
            CodexGrepFilesOutput::NoMatches(m) | CodexGrepFilesOutput::Error(m) => m,
        }
    }

    /// P198 r2: absolute rule (also outside the cwd and through a symlinked cwd), bare name and siblings.
    #[tokio::test]
    async fn read_rules_follow_the_policy_matcher() {
        assert!(rg_available(), "ripgrep is required for this test");
        crate::util::read_deny::fixture::check_grep(|cwd, path, deny| async move {
            grep_files_text(cwd, path, Some(deny)).await
        })
        .await;
    }

    /// P198 round 4: binary notices, odd names, a failing ripgrep and "nothing denied" through the `--json` records.
    #[tokio::test]
    async fn json_records_hide_denied_files() {
        assert!(rg_available(), "ripgrep is required for this test");
        crate::util::read_deny::fixture::check_round4(|cwd, path, deny| async move {
            grep_files_text(cwd, path, Some(deny)).await
        })
        .await;
    }

    #[tokio::test]
    async fn rules_that_are_not_total_do_not_hide_a_directory() {
        assert!(rg_available(), "ripgrep is required for this test");
        crate::util::read_deny::fixture::check_round4_rules(|cwd, path, deny| async move {
            grep_files_text(cwd, path, Some(deny)).await
        })
        .await;
    }

    /// P198 r2: a denied explicit file, also through a symlink, is refused (the tool's only output mode is the file list).
    #[tokio::test]
    async fn a_denied_explicit_file_is_refused() {
        assert!(rg_available(), "ripgrep is required for this test");
        crate::util::read_deny::fixture::check_explicit_file(|cwd, path, deny| async move {
            grep_files_text(cwd, Some(path), Some(deny)).await
        })
        .await;
    }

    /// P198 r2: an empty rule list prints the same bytes as no rule object.
    #[tokio::test]
    async fn an_empty_rule_list_changes_nothing() {
        assert!(rg_available(), "ripgrep is required for this test");
        let t = crate::util::read_deny::fixture::tree();
        let none = grep_files_text(t.proj.clone(), None, None).await;
        assert!(none.contains("key_material.txt"), "{none}");
        let empty = grep_files_text(t.proj.clone(), None, Some(Vec::new())).await;
        // Same bytes up to ripgrep's parallel line order (the tool sorts by mtime, which ties here).
        assert_eq!(
            crate::util::read_deny::fixture::sorted_lines(&none),
            crate::util::read_deny::fixture::sorted_lines(&empty)
        );
    }

    /// P198 round 3: results are post-filtered by the policy matcher.
    #[tokio::test]
    async fn results_are_post_filtered_by_the_policy_matcher() {
        assert!(rg_available(), "ripgrep is required for this test");
        crate::util::read_deny::fixture::check_round3_with(
            |cwd, path, deny| async move { grep_files_text(cwd, path, Some(deny)).await },
            false,
        )
        .await;
    }

    /// P198 round 3 (Grok r2 finding 8): the tool prints paths only, so the refusal itself is what is asserted: with the
    /// check removed the denied file's path would be returned as a match.
    #[tokio::test]
    async fn a_denied_explicit_file_gets_the_refusal_not_a_path() {
        assert!(rg_available(), "ripgrep is required for this test");
        let t = crate::util::read_deny::fixture::tree();
        let direct = t.proj.join("secrets/key_material.txt").to_string_lossy().into_owned();
        let deny = vec!["secrets/**".to_string()];
        for path in ["secrets/key_material.txt", direct.as_str(), "keylink"] {
            let out = grep_files_text(t.proj.clone(), Some(path.to_string()), Some(deny.clone())).await;
            assert!(out.contains("excluded by a read rule"), "{path}: {out}");
        }
    }
}
