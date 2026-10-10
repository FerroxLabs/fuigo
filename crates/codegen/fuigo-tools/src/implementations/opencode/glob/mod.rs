//! `glob` tool — OpenCode architecture (`Tool` trait).
//!
//! File pattern matching using ripgrep's `--files` mode with glob filters.
//! Returns matching file paths sorted by modification time (most recent first),
//! capped at 100 results.

use std::path::PathBuf;
use std::process::Stdio;

use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::implementations::fuigo_build::grep::ripgrep::rg_path;
use crate::types::output::ToolOutput;
#[allow(unused_imports)]
use crate::types::resources::{
    Cwd, DisplayCwd, SharedResources, display_cwd_or_cwd, resolve_model_path,
};
use crate::types::tool::{ToolKind, ToolNamespace};
use crate::types::tool_io::ToolInput;

// ─── Constants ──────────────────────────────────────────────────────

const RESULT_LIMIT: usize = 100;

/// Hard cap on bytes read from ripgrep's stdout (5 MB).
const MAX_STDOUT_BYTES: usize = 5_000_000;

#[cfg(test)]
thread_local! {
    /// Test-only byte cap (0 = the real one); tests run on a current-thread runtime, so this is per test.
    static STDOUT_CAP_TEST: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn max_stdout_bytes() -> usize {
    #[cfg(test)]
    {
        let cap = STDOUT_CAP_TEST.with(|c| c.get());
        if cap > 0 {
            return cap;
        }
    }
    MAX_STDOUT_BYTES
}

/// The read-rules path of the stdout read: the byte cap counts what is KEPT, so it runs after the read-rule filter
/// (denied paths must not use up the budget that allowed names need). Returns the kept bytes and whether the cap hit.
async fn read_filtered_capped(
    child: &mut tokio::process::Child,
    result_filter: &mut crate::util::read_deny::RgNullStream,
) -> (Vec<u8>, bool) {
    let stdout_cap = max_stdout_bytes();
    let mut stdout_buf = Vec::with_capacity(stdout_cap.min(65_536));
    let mut truncated_by_bytes = false;
    if let Some(mut stdout_pipe) = child.stdout.take() {
        let mut tmp = [0u8; 8192];
        loop {
            match stdout_pipe.read(&mut tmp).await {
                Ok(0) => break,
                Ok(n) => {
                    let kept_chunk = result_filter.feed(&tmp[..n]);
                    if stdout_buf.len() + kept_chunk.len() <= stdout_cap {
                        stdout_buf.extend_from_slice(&kept_chunk);
                    } else {
                        let remaining = stdout_cap.saturating_sub(stdout_buf.len());
                        if remaining > 0 {
                            stdout_buf.extend_from_slice(&kept_chunk[..remaining]);
                        }
                        truncated_by_bytes = true;
                        let _ = child.start_kill();
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }
    (stdout_buf, truncated_by_bytes)
}

// ─── Description ────────────────────────────────────────────────────

const DESCRIPTION: &str = r#"Fast file pattern matching tool that works with any codebase size.

- Supports glob patterns like "**/*.js" or "src/**/*.ts" via the required ${{ params.list.pattern }} parameter
- Optionally set ${{ params.list.path }} to pick the directory to search in (defaults to the current working directory)
- Returns matching file paths sorted by modification time (most recent first), capped at 100 results
- Hidden (dot) files are included; .gitignore patterns are respected for paths the pattern does not explicitly match
- Use this tool when you need to find files by name patterns
- You can call multiple tools in a single response. It is always better to speculatively perform multiple searches as a batch that are potentially useful."#;

// ─── Input ──────────────────────────────────────────────────────────

/// Input for the `glob` tool.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct GlobInput {
    /// Glob pattern to match files against (e.g. "**/*.ts", "src/**/*.tsx").
    pub pattern: String,

    /// Directory to search in. Defaults to the current working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl TryFrom<ToolInput> for GlobInput {
    type Error = String;
    fn try_from(value: ToolInput) -> Result<Self, Self::Error> {
        match value {
            ToolInput::Dynamic(v) => {
                serde_json::from_value(v).map_err(|e| format!("GlobInput: {e}"))
            }
            _ => Err("expected Dynamic variant for GlobInput".into()),
        }
    }
}

impl From<GlobInput> for ToolInput {
    fn from(value: GlobInput) -> Self {
        ToolInput::Dynamic(serde_json::to_value(value).expect("GlobInput serializes to JSON"))
    }
}

// ─── Output ─────────────────────────────────────────────────────────

/// Structured output for the `glob` tool.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GlobOutput {
    /// Pre-formatted text for the model prompt.
    pub tool_output_for_prompt: String,
    /// Number of files included in `entries` (capped at `RESULT_LIMIT`).
    pub count: usize,
    /// Total files matched by ripgrep before the cap. May exceed `count`.
    /// When `truncated_by_bytes` was hit this is a lower bound.
    pub total_count: usize,
    /// Whether results were truncated at the limit.
    pub truncated: bool,
    /// Absolute paths of matched files included in `count`, sorted by mtime
    /// descending. Empty when `count == 0`.
    pub entries: Vec<String>,
    /// The model-facing workspace root used to resolve `path` -- equal to
    /// `display_cwd_or_cwd(cwd, display_cwd)`. Adapters that re-format the
    /// output use this as the relativization base when
    /// the model omits `path`, instead of re-resolving cwd themselves.
    pub cwd_for_display: String,
}

impl fuigo_tool_runtime::ToolOutput for GlobOutput {}

impl From<GlobOutput> for ToolOutput {
    fn from(output: GlobOutput) -> Self {
        ToolOutput::Text(output.tool_output_for_prompt.into())
    }
}

// ─── Tool ───────────────────────────────────────────────────────────

/// Glob tool — lists files matching a glob pattern, sorted by mtime.
#[derive(Debug, Default)]
pub struct GlobTool;

impl crate::types::tool_metadata::ToolMetadata for GlobTool {
    fn kind(&self) -> ToolKind {
        ToolKind::List
    }

    fn tool_namespace(&self) -> ToolNamespace {
        ToolNamespace::OpenCode
    }

    fn description_template(&self) -> &str {
        DESCRIPTION
    }
}

impl fuigo_tool_runtime::Tool for GlobTool {
    type Args = GlobInput;
    type Output = GlobOutput;

    fn id(&self) -> fuigo_tool_protocol::ToolId {
        fuigo_tool_protocol::ToolId::new("glob").expect("valid tool id")
    }

    fn description(
        &self,
        _ctx: &::fuigo_tool_runtime::ListToolsContext,
    ) -> fuigo_tool_types::ToolDescription {
        fuigo_tool_types::ToolDescription::new(
            "glob",
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

    #[tracing::instrument(name = "tool.glob", skip_all)]
    async fn run(
        &self,
        ctx: fuigo_tool_runtime::ToolCallContext,
        input: GlobInput,
    ) -> Result<GlobOutput, fuigo_tool_runtime::ToolError> {
        use crate::types::tool_metadata::shared_resources;
        let resources = shared_resources(&ctx)?;

        let cwd = crate::types::tool_metadata::resolve_cwd(&ctx, &resources).await?;
        let (display_cwd, deny_read_globs) = {
            let res = resources.lock().await;
            (
                res.get::<DisplayCwd>().map(|d| d.0.clone()),
                crate::types::resources::deny_read_globs_for_call(&ctx, &res),
            )
        };

        // ── Resolve search directory ────────────────────────────
        let search_dir = resolve_model_path(
            &cwd,
            display_cwd.as_deref(),
            &input.path.clone().unwrap_or_default(),
        );

        // P198 round 3: ripgrep prints an explicit file it is given, so a denied explicit path is refused before it runs.
        if input.path.as_deref().is_some_and(|p| !p.is_empty())
            && crate::util::read_deny::explicit_search_path_denied(&cwd, &deny_read_globs, &search_dir).await
        {
            return Ok(GlobOutput {
                tool_output_for_prompt: format!("Error: {} is excluded by a read rule and cannot be searched.", search_dir.display()),
                count: 0,
                total_count: 0,
                truncated: false,
                entries: Vec::new(),
                cwd_for_display: display_cwd_or_cwd(&cwd, display_cwd.as_deref()).display().to_string(),
            });
        }

        // ── Build ripgrep command ───────────────────────────────
        //   rg --files --glob='!.git/*' --hidden --glob=<pattern> <search_dir>
        let rg_exec = rg_path()?;
        let mut cmd = Command::new(rg_exec);
        cmd.arg("--files")
            .arg("--glob=!.git/*")
            .arg("--hidden")
            .arg("--glob")
            .arg(&input.pattern);
        // P198 round 3: no excludes. With rules, `--null` records are judged below and a denied file is dropped.
        let mut result_filter = crate::util::read_deny::RgNullStream::new_files(
            crate::util::read_deny::ResultFilter::new(&cwd, &deny_read_globs),
        );
        let filtering = result_filter.is_active();
        if filtering {
            cmd.arg("--null");
        } else {
            // Managed Read-deny globs become excludes, after the caller's pattern so they win (as in the grep tools, P173).
            for deny in &deny_read_globs {
                cmd.arg("--glob").arg(format!("!{deny}"));
            }
        }
        cmd.arg(&search_dir)
            .stdout(Stdio::piped())
            // stderr is never read; a pipe would block rg once warnings fill it.
            // Cached descriptor, not `Stdio::null()`: an unlinked `/dev/null`
            // must not fail the spawn.
            .stderr(fuigo_tty_utils::null_stdio());
        crate::util::detach_search_command(&mut cmd);

        #[allow(clippy::disallowed_methods)] // search helper, waited on below
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return Ok(GlobOutput {
                    tool_output_for_prompt: format!("Error running glob: {e}"),
                    count: 0,
                    total_count: 0,
                    truncated: false,
                    entries: Vec::new(),
                    cwd_for_display: display_cwd_or_cwd(&cwd, display_cwd.as_deref())
                        .display()
                        .to_string(),
                });
            }
        };

        // ── Read stdout with byte cap ───────────────────────────
        let mut stdout_buf = Vec::with_capacity(MAX_STDOUT_BYTES.min(65_536));
        let mut truncated_by_bytes = false;
        if filtering {
            (stdout_buf, truncated_by_bytes) = read_filtered_capped(&mut child, &mut result_filter).await;
        } else if let Some(mut stdout_pipe) = child.stdout.take() {
            let mut tmp = [0u8; 8192];
            loop {
                match stdout_pipe.read(&mut tmp).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if stdout_buf.len() + n <= MAX_STDOUT_BYTES {
                            stdout_buf.extend_from_slice(&tmp[..n]);
                        } else {
                            let remaining = MAX_STDOUT_BYTES.saturating_sub(stdout_buf.len());
                            if remaining > 0 {
                                stdout_buf.extend_from_slice(&tmp[..remaining]);
                            }
                            truncated_by_bytes = true;
                            let _ = child.start_kill();
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        if truncated_by_bytes {
            // Bounded reap: a D-state rg must not stall this future forever.
            crate::util::reap_killed_search_child(&mut child).await;
        } else {
            let _ = child.wait().await;
        }

        if filtering {
            stdout_buf.extend(result_filter.finish());
        }

        // ── Parse file paths from stdout ────────────────────────
        let stdout = String::from_utf8_lossy(&stdout_buf);
        let mut truncated = truncated_by_bytes;

        struct FileEntry {
            path: PathBuf,
            mtime_ms: i64,
        }

        // Collect every match so total_count is accurate. Cap stat()s and
        // the returned entry list at RESULT_LIMIT so we don't pay the syscall
        // cost on huge result sets, but keep counting lines past the cap so
        // the truncation marker can report the real overflow.
        let mut entries: Vec<FileEntry> = Vec::new();
        let mut total_count: usize = 0;
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            total_count += 1;

            if entries.len() >= RESULT_LIMIT {
                truncated = true;
                continue;
            }

            let full_path = search_dir.join(line);
            let mtime_ms = std::fs::metadata(&full_path)
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|t| {
                    t.duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as i64)
                        .unwrap_or(0)
                })
                .unwrap_or(0);

            entries.push(FileEntry {
                path: full_path,
                mtime_ms,
            });
        }

        // ── Sort by mtime descending (most recent first) ────────
        entries.sort_by_key(|b| std::cmp::Reverse(b.mtime_ms));

        // ── Format output ───────────────────────────────────────
        let count = entries.len();
        let cwd_for_display = display_cwd_or_cwd(&cwd, display_cwd.as_deref());
        let entry_paths: Vec<String> = entries
            .iter()
            .map(|e| e.path.display().to_string())
            .collect();

        let tool_output_for_prompt = if entry_paths.is_empty() {
            "No files found".to_string()
        } else {
            let mut lines: Vec<String> = entry_paths.clone();

            if truncated {
                lines.push(String::new());
                lines.push(format!(
                    "(Results are truncated: showing first {} results out of more. \
                     Use a more specific path or pattern to narrow results.)",
                    RESULT_LIMIT
                ));
            }

            // Wrap in workspace_result so the model sees the search context.
            format!(
                "<workspace_result workspace_path=\"{}\">\n{}\n</workspace_result>",
                cwd_for_display.display(),
                lines.join("\n"),
            )
        };

        Ok(GlobOutput {
            tool_output_for_prompt,
            count,
            total_count,
            truncated,
            entries: entry_paths,
            cwd_for_display: cwd_for_display.display().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::tool_metadata::test_ctx;

    use crate::types::resources::Resources;
    use tempfile::TempDir;

    fn test_resources(cwd: &std::path::Path) -> Resources {
        let mut resources = Resources::new();
        resources.insert(Cwd(cwd.to_path_buf()));
        resources
    }

    #[test]
    fn description_template_tracks_renamed_pattern_and_path() {
        use crate::types::template_renderer::TemplateRenderer;
        use crate::types::tool_metadata::ToolMetadata;
        use std::collections::HashMap;

        let tools = HashMap::from([(ToolKind::List, "glob".to_string())]);
        let params = HashMap::from([(
            ToolKind::List,
            HashMap::from([
                ("pattern".to_string(), "file_pattern".to_string()),
                ("path".to_string(), "search_dir".to_string()),
            ]),
        )]);
        let rendered = TemplateRenderer::new(tools, params)
            .render(ToolMetadata::description_template(&GlobTool))
            .unwrap();
        assert!(
            rendered.contains("file_pattern") && rendered.contains("search_dir"),
            "renamed pattern/path params must appear:\n{rendered}"
        );
    }

    #[tokio::test]
    async fn glob_finds_matching_files() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("hello.ts"), "console.log('hi');\n").unwrap();
        std::fs::write(tmp.path().join("world.ts"), "export {};\n").unwrap();
        std::fs::write(tmp.path().join("readme.md"), "# readme\n").unwrap();

        let tool = GlobTool;
        let resources = test_resources(tmp.path());

        let output = fuigo_tool_runtime::Tool::run(
            &tool,
            test_ctx(resources.into_shared()),
            GlobInput {
                pattern: "*.ts".to_string(),
                path: None,
            },
        )
        .await
        .unwrap();

        assert_eq!(output.count, 2);
        assert!(!output.truncated);
        assert!(output.tool_output_for_prompt.contains(".ts"));
        assert!(!output.tool_output_for_prompt.contains("readme.md"));
    }

    /// P173: Read-denied paths are excluded from the listing, from the toolset's `DenyReadGlobs` and from the call's
    /// own `CallDenyReadGlobs` alike.
    #[tokio::test]
    async fn glob_skips_read_denied_files() {
        for per_call in [false, true] {
            let tmp = TempDir::new().unwrap();
            std::fs::create_dir_all(tmp.path().join("secrets")).unwrap();
            std::fs::write(tmp.path().join("secrets").join("token.txt"), "x\n").unwrap();
            std::fs::write(tmp.path().join("visible.txt"), "x\n").unwrap();
            let mut resources = test_resources(tmp.path());
            let deny = vec!["**/secrets/**".to_string()];
            if !per_call {
                resources.insert(crate::types::resources::DenyReadGlobs(deny.clone()));
            }
            let mut ctx = test_ctx(resources.into_shared());
            if per_call {
                ctx.extensions
                    .insert(crate::types::resources::CallDenyReadGlobs(deny));
            }
            let output = fuigo_tool_runtime::Tool::run(
                &GlobTool,
                ctx,
                GlobInput {
                    pattern: "**/*.txt".to_string(),
                    path: None,
                },
            )
            .await
            .unwrap();
            assert!(
                output.tool_output_for_prompt.contains("visible.txt"),
                "per_call={per_call}: {}",
                output.tool_output_for_prompt
            );
            assert!(
                !output.tool_output_for_prompt.contains("token.txt"),
                "per_call={per_call}: a Read-denied file was listed: {}",
                output.tool_output_for_prompt
            );
        }
    }

    #[tokio::test]
    async fn glob_no_matches_returns_empty() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("readme.md"), "# readme\n").unwrap();

        let tool = GlobTool;
        let resources = test_resources(tmp.path());

        let output = fuigo_tool_runtime::Tool::run(
            &tool,
            test_ctx(resources.into_shared()),
            GlobInput {
                pattern: "*.xyz_nonexistent".to_string(),
                path: None,
            },
        )
        .await
        .unwrap();

        assert_eq!(output.count, 0);
        assert!(!output.truncated);
        assert!(output.tool_output_for_prompt.contains("No files found"));
    }

    /// One unreadable subdir must not lose sibling results or report
    /// truncation (rg's warnings go to a null stderr, not a droppable pipe).
    #[cfg(unix)]
    #[tokio::test]
    async fn glob_survives_unreadable_subdir() {
        use std::os::unix::fs::PermissionsExt;
        if nix::unistd::geteuid().is_root() {
            return; // chmod 0o000 doesn't bar root
        }
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("a.ts"), "x").unwrap();
        std::fs::write(tmp.path().join("b.ts"), "y").unwrap();
        let locked = tmp.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("c.ts"), "z").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

        let tool = GlobTool;
        let resources = test_resources(tmp.path());
        let output = fuigo_tool_runtime::Tool::run(
            &tool,
            test_ctx(resources.into_shared()),
            GlobInput {
                pattern: "*.ts".to_string(),
                path: None,
            },
        )
        .await;

        // Restore before asserting so TempDir cleanup works even on failure.
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();

        let output = output.unwrap();
        assert_eq!(output.count, 2, "visible files must all be returned");
        assert!(!output.truncated);
        assert!(output.tool_output_for_prompt.contains("a.ts"));
        assert!(output.tool_output_for_prompt.contains("b.ts"));
    }

    #[tokio::test]
    async fn glob_with_subdirectory_path() {
        let tmp = TempDir::new().unwrap();
        let sub = tmp.path().join("src");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("main.rs"), "fn main() {}\n").unwrap();
        std::fs::write(tmp.path().join("root.txt"), "root\n").unwrap();

        let tool = GlobTool;
        let resources = test_resources(tmp.path());

        let output = fuigo_tool_runtime::Tool::run(
            &tool,
            test_ctx(resources.into_shared()),
            GlobInput {
                pattern: "*.rs".to_string(),
                path: Some("src".to_string()),
            },
        )
        .await
        .unwrap();

        assert_eq!(output.count, 1);
        assert!(output.tool_output_for_prompt.contains("main.rs"));
        assert!(!output.tool_output_for_prompt.contains("root.txt"));
    }

    #[tokio::test]
    async fn glob_sorts_by_mtime_most_recent_first() {
        let tmp = TempDir::new().unwrap();

        // Create files with slight time gaps so mtime differs.
        std::fs::write(tmp.path().join("old.txt"), "old\n").unwrap();
        // Touch a second file after a small delay.
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(tmp.path().join("new.txt"), "new\n").unwrap();

        let tool = GlobTool;
        let resources = test_resources(tmp.path());

        let output = fuigo_tool_runtime::Tool::run(
            &tool,
            test_ctx(resources.into_shared()),
            GlobInput {
                pattern: "*.txt".to_string(),
                path: None,
            },
        )
        .await
        .unwrap();

        assert_eq!(output.count, 2);
        // "new.txt" should appear before "old.txt" in the output.
        let new_pos = output.tool_output_for_prompt.find("new.txt").unwrap();
        let old_pos = output.tool_output_for_prompt.find("old.txt").unwrap();
        assert!(
            new_pos < old_pos,
            "new.txt should appear before old.txt (mtime sort), got new@{} old@{}",
            new_pos,
            old_pos
        );
    }

    #[tokio::test]
    async fn glob_recursive_pattern() {
        let tmp = TempDir::new().unwrap();
        let nested = tmp.path().join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(tmp.path().join("top.rs"), "top\n").unwrap();
        std::fs::write(nested.join("deep.rs"), "deep\n").unwrap();

        let tool = GlobTool;
        let resources = test_resources(tmp.path());

        let output = fuigo_tool_runtime::Tool::run(
            &tool,
            test_ctx(resources.into_shared()),
            GlobInput {
                pattern: "**/*.rs".to_string(),
                path: None,
            },
        )
        .await
        .unwrap();

        assert_eq!(output.count, 2);
        assert!(output.tool_output_for_prompt.contains("top.rs"));
        assert!(output.tool_output_for_prompt.contains("deep.rs"));
    }

    #[test]
    fn tool_metadata() {
        use crate::types::tool_metadata::ToolMetadata;
        let tool = GlobTool;
        assert_eq!(fuigo_tool_runtime::Tool::id(&tool).as_str(), "glob");
        assert!(matches!(tool.kind(), ToolKind::List));
        assert!(matches!(tool.tool_namespace(), ToolNamespace::OpenCode));
    }

    #[test]
    fn serde_roundtrip() {
        let json = r#"{"pattern":"**/*.ts","path":"src"}"#;
        let input: GlobInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.pattern, "**/*.ts");
        assert_eq!(input.path.as_deref(), Some("src"));

        // Minimal — path omitted
        let json_min = r#"{"pattern":"*.rs"}"#;
        let input_min: GlobInput = serde_json::from_str(json_min).unwrap();
        assert_eq!(input_min.pattern, "*.rs");
        assert!(input_min.path.is_none());

        // Round-trip through serde_json::Value
        let value = serde_json::to_value(&input).unwrap();
        let back: GlobInput = serde_json::from_value(value).unwrap();
        assert_eq!(back.pattern, "**/*.ts");
        assert_eq!(back.path.as_deref(), Some("src"));
    }

    #[tokio::test]
    async fn absolute_path_parameter() {
        let tmp = TempDir::new().unwrap();
        let sub = tmp.path().join("abs_target");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("found.txt"), "data\n").unwrap();

        let tool = GlobTool;
        // cwd is the tmp root, but we pass the absolute path to the sub dir
        let resources = test_resources(tmp.path());

        let output = fuigo_tool_runtime::Tool::run(
            &tool,
            test_ctx(resources.into_shared()),
            GlobInput {
                pattern: "*.txt".to_string(),
                path: Some(sub.to_string_lossy().to_string()),
            },
        )
        .await
        .unwrap();

        assert_eq!(output.count, 1);
        assert!(output.tool_output_for_prompt.contains("found.txt"));
    }

    #[tokio::test]
    async fn empty_directory() {
        let tmp = TempDir::new().unwrap();
        // Directory exists but contains no files.

        let tool = GlobTool;
        let resources = test_resources(tmp.path());

        let output = fuigo_tool_runtime::Tool::run(
            &tool,
            test_ctx(resources.into_shared()),
            GlobInput {
                pattern: "*".to_string(),
                path: None,
            },
        )
        .await
        .unwrap();

        assert_eq!(output.count, 0);
        assert!(!output.truncated);
        assert!(output.tool_output_for_prompt.contains("No files found"));
    }

    #[tokio::test]
    async fn path_empty_string_defaults_to_cwd() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("root.rs"), "fn main() {}\n").unwrap();

        let tool = GlobTool;
        let resources = test_resources(tmp.path());

        let output = fuigo_tool_runtime::Tool::run(
            &tool,
            test_ctx(resources.into_shared()),
            GlobInput {
                pattern: "*.rs".to_string(),
                path: Some(String::new()),
            },
        )
        .await
        .unwrap();

        assert_eq!(output.count, 1);
        assert!(output.tool_output_for_prompt.contains("root.rs"));
    }

    #[tokio::test]
    async fn missing_cwd_resource() {
        let tool = GlobTool;
        let resources = Resources::new(); // No Cwd inserted

        let result = fuigo_tool_runtime::Tool::run(
            &tool,
            test_ctx(resources.into_shared()),
            GlobInput {
                pattern: "*.rs".to_string(),
                path: None,
            },
        )
        .await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Cwd not available")
        );
    }

    #[tokio::test]
    async fn result_cap_100() {
        let tmp = TempDir::new().unwrap();
        for i in 0..110 {
            std::fs::write(tmp.path().join(format!("file_{:03}.txt", i)), "data\n").unwrap();
        }

        let tool = GlobTool;
        let resources = test_resources(tmp.path());

        let output = fuigo_tool_runtime::Tool::run(
            &tool,
            test_ctx(resources.into_shared()),
            GlobInput {
                pattern: "*.txt".to_string(),
                path: None,
            },
        )
        .await
        .unwrap();

        assert_eq!(output.count, 100);
        assert!(output.truncated);
        assert!(
            output.tool_output_for_prompt.contains("showing first 100"),
            "expected truncation message, got: {}",
            output.tool_output_for_prompt
        );
    }

    #[tokio::test]
    async fn hidden_files_included() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join(".hidden.ts"), "hidden\n").unwrap();
        std::fs::write(tmp.path().join("visible.ts"), "visible\n").unwrap();

        let tool = GlobTool;
        let resources = test_resources(tmp.path());

        let output = fuigo_tool_runtime::Tool::run(
            &tool,
            test_ctx(resources.into_shared()),
            GlobInput {
                pattern: "*.ts".to_string(),
                path: None,
            },
        )
        .await
        .unwrap();

        assert!(
            output.count >= 2,
            "expected at least 2 files, got {}",
            output.count
        );
        assert!(
            output.tool_output_for_prompt.contains(".hidden.ts"),
            "hidden file should appear in output: {}",
            output.tool_output_for_prompt
        );
    }

    #[tokio::test]
    async fn gitignore_respected() {
        // ripgrep's positive --glob overrides .gitignore, so we test the
        // underlying ignore behavior by using a pattern that doesn't match
        // the ignored file. Without .gitignore, `rg --files --hidden`
        // *would* list ignored_dir/ contents, but with .gitignore they are
        // excluded from results that don't glob-override them.
        let tmp = TempDir::new().unwrap();

        // Initialize a git repo so ripgrep respects .gitignore.
        fuigo_test_utils::git::ensure_hermetic_git_on_path();
        let status = std::process::Command::new("git")
            .args(["init"])
            .current_dir(tmp.path())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("git must be available");
        assert!(status.success(), "git init failed");

        // Ignore an entire directory via .gitignore.
        std::fs::write(tmp.path().join(".gitignore"), "ignored_dir/\n").unwrap();

        // Create an ignored directory with a .txt file inside it.
        let ignored = tmp.path().join("ignored_dir");
        std::fs::create_dir(&ignored).unwrap();
        std::fs::write(ignored.join("secret.txt"), "should be ignored\n").unwrap();

        // Create a non-ignored .txt file.
        std::fs::write(tmp.path().join("visible.txt"), "should be found\n").unwrap();

        let tool = GlobTool;
        let resources = test_resources(tmp.path());

        // Pattern **/*.txt would match both files if .gitignore were not in
        // effect. Because ripgrep processes the ignore stack *before* applying
        // the glob whitelist for directory ignores, ignored_dir/ is pruned.
        let output = fuigo_tool_runtime::Tool::run(
            &tool,
            test_ctx(resources.into_shared()),
            GlobInput {
                pattern: "**/*.txt".to_string(),
                path: None,
            },
        )
        .await
        .unwrap();

        assert!(
            output.tool_output_for_prompt.contains("visible.txt"),
            "visible.txt should be in output: {}",
            output.tool_output_for_prompt
        );
        assert!(
            !output.tool_output_for_prompt.contains("secret.txt"),
            "secret.txt inside ignored_dir/ should be excluded by .gitignore: {}",
            output.tool_output_for_prompt
        );
    }

    #[tokio::test]
    async fn output_format_workspace_result() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("example.rs"), "fn main() {}\n").unwrap();

        let tool = GlobTool;
        let resources = test_resources(tmp.path());

        let output = fuigo_tool_runtime::Tool::run(
            &tool,
            test_ctx(resources.into_shared()),
            GlobInput {
                pattern: "*.rs".to_string(),
                path: None,
            },
        )
        .await
        .unwrap();

        assert!(
            output
                .tool_output_for_prompt
                .starts_with("<workspace_result"),
            "output should start with <workspace_result tag, got: {}",
            output.tool_output_for_prompt
        );
        assert!(
            output
                .tool_output_for_prompt
                .ends_with("</workspace_result>"),
            "output should end with </workspace_result>, got: {}",
            output.tool_output_for_prompt
        );
        assert!(
            output.tool_output_for_prompt.contains("workspace_path="),
            "output should contain workspace_path attribute, got: {}",
            output.tool_output_for_prompt
        );
    }


    /// P198 r2: an empty rule list prints the same bytes as no rule object, and an absolute rule hides what it names.
    #[tokio::test]
    async fn glob_with_an_empty_rule_list_changes_nothing() {
        let t = crate::util::read_deny::fixture::tree();
        let run = |deny: Option<Vec<String>>| {
            let mut resources = test_resources(&t.proj);
            if let Some(deny) = deny {
                resources.insert(crate::types::resources::DenyReadGlobs(deny));
            }
            async move {
                fuigo_tool_runtime::Tool::run(
                    &GlobTool,
                    test_ctx(resources.into_shared()),
                    GlobInput { pattern: "**/*.txt".to_string(), path: None },
                )
                .await
                .unwrap()
                .tool_output_for_prompt
            }
        };
        let none = run(None).await;
        assert!(none.contains("key_material.txt"), "{none}");
        let empty = run(Some(Vec::new())).await;
        // Same bytes up to ripgrep's parallel line order.
        assert_eq!(
            crate::util::read_deny::fixture::sorted_lines(&none),
            crate::util::read_deny::fixture::sorted_lines(&empty)
        );
        let abs = run(Some(vec![format!("{}/secrets/**", t.proj.display())])).await;
        assert!(!abs.contains("key_material.txt") && abs.contains("public.txt"), "{abs}");
    }

    async fn glob_text(cwd: std::path::PathBuf, path: Option<String>, deny: Vec<String>) -> (String, usize) {
        let mut resources = test_resources(&cwd);
        resources.insert(crate::types::resources::DenyReadGlobs(deny));
        let out = fuigo_tool_runtime::Tool::run(
            &GlobTool,
            test_ctx(resources.into_shared()),
            GlobInput { pattern: "**/*".to_string(), path },
        )
        .await
        .unwrap();
        (out.tool_output_for_prompt, out.total_count)
    }

    /// P198 round 4: odd names, a failing walk and "nothing denied" for the glob listing.
    #[tokio::test]
    async fn round4_contract() {
        crate::util::read_deny::fixture::check_round4(|cwd, path, deny| async move { glob_text(cwd, path, deny).await.0 })
            .await;
    }

    /// P198 round 4: the byte cap counts what the filter KEPT: a flood of denied names must not push allowed names out.
    #[tokio::test]
    async fn the_byte_cap_runs_after_the_filter() {
        let t = crate::util::read_deny::fixture::tree();
        let dir = t.base.join("capped");
        std::fs::create_dir_all(dir.join("secrets")).unwrap();
        for i in 0..400 {
            std::fs::write(dir.join(format!("secrets/{}-{i:04}.txt", "d".repeat(80))), "x").unwrap();
        }
        for i in 0..3 {
            std::fs::write(dir.join(format!("zz-ok{i}.txt")), "x").unwrap();
        }
        STDOUT_CAP_TEST.with(|c| c.set(2000));
        let (out, total) = glob_text(dir.clone(), None, vec!["secrets/**".to_string()]).await;
        STDOUT_CAP_TEST.with(|c| c.set(0));
        for i in 0..3 {
            assert!(out.contains(&format!("zz-ok{i}.txt")), "allowed name {i} lost to denied bytes: {out}");
        }
        assert_eq!(total, 3, "the total counts only allowed names: {out}");
    }

    /// P198 round 3: results are post-filtered by the policy matcher, and the totals exclude denied files.
    #[tokio::test]
    async fn results_are_post_filtered_by_the_policy_matcher() {
        crate::util::read_deny::fixture::check_round3(|cwd, path, deny| async move { glob_text(cwd, path, deny).await.0 })
            .await;
        let t = crate::util::read_deny::fixture::tree();
        let (_, all) = glob_text(t.proj.clone(), None, Vec::new()).await;
        let (_, fewer) = glob_text(t.proj.clone(), None, vec!["secrets/**".to_string()]).await;
        assert_eq!(fewer + 1, all, "the denied file is not in the total");
    }

    /// P198 round 3 (finding D): an explicit denied FILE is refused, not listed.
    #[tokio::test]
    async fn glob_of_a_denied_explicit_file_is_refused() {
        let t = crate::util::read_deny::fixture::tree();
        for path in ["secrets/key_material.txt", "keylink"] {
            let (out, _) = glob_text(t.proj.clone(), Some(path.to_string()), vec!["secrets/**".to_string()]).await;
            assert!(out.contains("excluded by a read rule"), "{path}: {out}");
        }
        let (out, _) = glob_text(t.proj.clone(), Some("public.txt".to_string()), vec!["secrets/**".to_string()]).await;
        assert!(out.contains("public.txt"), "{out}");
    }
}
