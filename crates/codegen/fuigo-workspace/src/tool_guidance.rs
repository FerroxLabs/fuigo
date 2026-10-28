//! Loader for `tool-guidance.toml`: user-settable text that is appended to, or replaces, a
//! built-in tool's description (the Harness "tool guidance" component).
//!
//! ```toml
//! [tools.read_file]
//! mode = "append"      # or "replace"
//! text = "Prefer small ranges."
//! ```
//!
//! Sources, highest priority first: the project `.fuigo/tool-guidance.toml` (only when the folder
//! is trusted), then `$FUIGO_HOME/tool-guidance.toml`. Entries merge per tool; the project wins.
//! A missing file changes nothing. Unknown tool names are warned about once and ignored. An entry
//! over [`MAX_ENTRY_CHARS`], or one that would push the file past [`MAX_TOTAL_CHARS`], is skipped.
//! `FUIGO_TOOL_GUIDANCE=none` (or `off`) disables loading; any other value is a file path that
//! replaces both default locations (this is what `--tool-guidance <path|none>` sets).
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use fuigo_agent::repo::RepoDirChain;
use fuigo_tools::tool_guidance::{GuidanceMode, ToolGuidance};
use parking_lot::Mutex;

pub const FILE_NAME: &str = "tool-guidance.toml";
pub const MAX_ENTRY_CHARS: usize = 2000;
pub const MAX_TOTAL_CHARS: usize = 8000;
pub const ENV_VAR: &str = "FUIGO_TOOL_GUIDANCE";

static WARNED: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

/// Warn once per distinct message for the life of the process.
fn warn_once(msg: String) {
    if WARNED.lock().insert(msg.clone()) {
        tracing::warn!("{msg}");
    }
}

/// Parse one file. Returns the accepted entries plus the warnings it produced (also logged once).
pub fn parse(
    src: &str,
    origin: &str,
    known: &HashSet<String>,
) -> (HashMap<String, ToolGuidance>, Vec<String>) {
    let mut out = HashMap::new();
    let mut warnings = Vec::new();
    let mut note = |w: String| {
        warn_once(w.clone());
        warnings.push(w);
    };
    let doc: toml::Table = match src.parse() {
        Ok(d) => d,
        Err(e) => {
            note(format!(
                "tool guidance: {origin} is not valid TOML, ignored ({e})"
            ));
            return (out, warnings);
        }
    };
    let Some(tools) = doc.get("tools").and_then(|v| v.as_table()) else {
        return (out, warnings);
    };
    let mut total = 0usize;
    for (name, entry) in tools {
        if !known.contains(name) {
            note(format!(
                "tool guidance: unknown tool `{name}` in {origin}, ignored"
            ));
            continue;
        }
        let Some(table) = entry.as_table() else {
            note(format!(
                "tool guidance: `[tools.{name}]` in {origin} is not a table, skipped"
            ));
            continue;
        };
        let mode = match table.get("mode").and_then(|v| v.as_str()) {
            Some("append") => GuidanceMode::Append,
            Some("replace") => GuidanceMode::Replace,
            _ => {
                note(format!(
                    "tool guidance: `[tools.{name}]` in {origin} needs mode = \"append\" or \"replace\", skipped"
                ));
                continue;
            }
        };
        let Some(text) = table.get("text").and_then(|v| v.as_str()) else {
            note(format!(
                "tool guidance: `[tools.{name}]` in {origin} has no `text`, skipped"
            ));
            continue;
        };
        let len = text.chars().count();
        if len > MAX_ENTRY_CHARS {
            note(format!(
                "tool guidance: `[tools.{name}]` in {origin} is {len} chars (max {MAX_ENTRY_CHARS}), skipped"
            ));
            continue;
        }
        if total + len > MAX_TOTAL_CHARS {
            note(format!(
                "tool guidance: `[tools.{name}]` in {origin} would exceed the {MAX_TOTAL_CHARS}-char total, skipped"
            ));
            continue;
        }
        total += len;
        out.insert(
            name.clone(),
            ToolGuidance {
                mode,
                text: text.to_owned(),
            },
        );
    }
    (out, warnings)
}

/// Read one guidance file. `root` set (a project file): the file actually opened must lie inside that folder, so a
/// project file linked elsewhere on the machine is not applied; `None` (user file, `FUIGO_TOOL_GUIDANCE`): follows
/// links.
fn read_file(
    path: &Path,
    root: Option<&fuigo_dirs::contained::PinnedRoot>,
    known: &HashSet<String>,
) -> HashMap<String, ToolGuidance> {
    match fuigo_dirs::contained::read_scoped(path, root) {
        Ok(src) => parse(&src, &path.display().to_string(), known).0,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
        Err(e) => {
            warn_once(format!(
                "tool guidance: cannot read {}: {e}",
                path.display()
            ));
            HashMap::new()
        }
    }
}

/// Merge the user file under the project files (cwd's wins over the repo root's).
/// `project_files` is repo-root-first, as [`project_files`] returns it.
pub fn load_from(
    project_files: &[PathBuf],
    user_file: Option<&Path>,
    known: &HashSet<String>,
) -> HashMap<String, ToolGuidance> {
    let mut merged = user_file.map(|p| read_file(p, None, known)).unwrap_or_default();
    for p in project_files {
        // `<dir>/.fuigo/tool-guidance.toml` is held to `<dir>`, pinned when this load starts.
        let Some(root) = p
            .parent()
            .and_then(Path::parent)
            .and_then(|dir| fuigo_dirs::contained::PinnedRoot::pin(dir).ok())
        else {
            continue;
        };
        merged.extend(read_file(p, Some(&root), known));
    }
    merged
}

/// `.fuigo/tool-guidance.toml` files from the git root down to `cwd`.
pub fn project_files(cwd: &Path) -> Vec<PathBuf> {
    RepoDirChain::resolve(cwd)
        .dirs
        .iter()
        .rev()
        .map(|d| d.join(".fuigo").join(FILE_NAME))
        .filter(|p| p.is_file())
        .collect()
}

fn folder_is_trusted(cwd: &Path) -> bool {
    crate::folder_trust::dir_trust(cwd).is_trusted()
}

/// What a session rooted at `cwd` should apply. Honors the trust gate and `FUIGO_TOOL_GUIDANCE`.
pub fn load_for_session(cwd: &Path, known: &HashSet<String>) -> HashMap<String, ToolGuidance> {
    load_with(
        std::env::var(ENV_VAR).ok().as_deref(),
        cwd,
        fuigo_config::user_fuigo_home()
            .map(|h| h.join(FILE_NAME))
            .as_deref(),
        known,
        folder_is_trusted,
    )
}

fn load_with(
    env: Option<&str>,
    cwd: &Path,
    user_file: Option<&Path>,
    known: &HashSet<String>,
    trusted: impl Fn(&Path) -> bool,
) -> HashMap<String, ToolGuidance> {
    match env.map(str::trim) {
        Some(v) if v.eq_ignore_ascii_case("none") || v.eq_ignore_ascii_case("off") => {
            return HashMap::new();
        }
        Some(v) if !v.is_empty() => return read_file(Path::new(v), None, known),
        _ => {}
    }
    let project = project_files(cwd);
    let project = if project.is_empty() || trusted(cwd) {
        project
    } else {
        warn_once(format!(
            "tool guidance: ignoring project {FILE_NAME} under {} (folder not trusted)",
            cwd.display()
        ));
        Vec::new()
    };
    load_from(&project, user_file, known)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known() -> HashSet<String> {
        ["read_file", "grep"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    }

    #[test]
    fn append_and_replace_parse() {
        let (m, w) = parse(
            "[tools.read_file]\nmode=\"append\"\ntext=\"a\"\n[tools.grep]\nmode=\"replace\"\ntext=\"b\"\n",
            "t",
            &known(),
        );
        assert!(w.is_empty(), "{w:?}");
        assert_eq!(
            m["read_file"],
            ToolGuidance {
                mode: GuidanceMode::Append,
                text: "a".into()
            }
        );
        assert_eq!(m["grep"].mode, GuidanceMode::Replace);
    }

    #[test]
    fn unknown_tool_is_warned_and_ignored() {
        let (m, w) = parse(
            "[tools.nope_xyz]\nmode=\"append\"\ntext=\"a\"\n",
            "t",
            &known(),
        );
        assert!(m.is_empty());
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("unknown tool `nope_xyz`"));
    }

    #[test]
    fn per_entry_cap_skips_only_that_entry() {
        let big = "x".repeat(MAX_ENTRY_CHARS + 1);
        let ok = "y".repeat(MAX_ENTRY_CHARS);
        let src = format!(
            "[tools.read_file]\nmode=\"append\"\ntext=\"{big}\"\n[tools.grep]\nmode=\"append\"\ntext=\"{ok}\"\n"
        );
        let (m, w) = parse(&src, "t", &known());
        assert!(!m.contains_key("read_file"));
        assert!(m.contains_key("grep"));
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn total_cap_skips_the_overflowing_entry() {
        let mut ks = known();
        let mut src = String::new();
        let each = "z".repeat(MAX_ENTRY_CHARS);
        for i in 0..5 {
            ks.insert(format!("t{i}"));
            src.push_str(&format!("[tools.t{i}]\nmode=\"append\"\ntext=\"{each}\"\n"));
        }
        let (m, w) = parse(&src, "t", &ks);
        assert_eq!(m.len(), MAX_TOTAL_CHARS / MAX_ENTRY_CHARS);
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn bad_mode_or_toml_is_skipped() {
        let (m, w) = parse(
            "[tools.grep]\nmode=\"prepend\"\ntext=\"a\"\n",
            "t",
            &known(),
        );
        assert!(m.is_empty() && w.len() == 1);
        let (m, w) = parse("not toml [[[", "t", &known());
        assert!(m.is_empty() && w.len() == 1);
    }

    fn write(dir: &Path, rel: &str, body: &str) -> PathBuf {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
        p
    }

    const PROJ: &str = "[tools.read_file]\nmode=\"replace\"\ntext=\"project\"\n";
    const USER: &str = "[tools.read_file]\nmode=\"append\"\ntext=\"user\"\n[tools.grep]\nmode=\"append\"\ntext=\"user-grep\"\n";

    #[test]
    fn absent_files_load_nothing() {
        let t = tempfile::tempdir().unwrap();
        let m = load_with(
            None,
            t.path(),
            Some(&t.path().join("none.toml")),
            &known(),
            |_| true,
        );
        assert!(m.is_empty());
    }

    #[test]
    fn project_wins_over_user_per_tool_when_trusted() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), &format!(".fuigo/{FILE_NAME}"), PROJ);
        let user = write(t.path(), "home/tool-guidance.toml", USER);
        let m = load_with(None, t.path(), Some(&user), &known(), |_| true);
        assert_eq!(m["read_file"].text, "project");
        assert_eq!(m["grep"].text, "user-grep");
    }

    #[test]
    fn project_file_ignored_when_untrusted() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), &format!(".fuigo/{FILE_NAME}"), PROJ);
        let user = write(t.path(), "home/tool-guidance.toml", USER);
        let m = load_with(None, t.path(), Some(&user), &known(), |_| false);
        assert_eq!(m["read_file"].text, "user");
    }

    /// Astra r4 Medium: a project guidance file linked outside its folder is not applied; one linked inside is; the
    /// user file still follows links.
    #[cfg(unix)]
    #[test]
    fn m5_project_guidance_linked_outside_its_folder_is_not_applied() {
        let t = tempfile::tempdir().unwrap();
        let repo = t.path().join("repo");
        let outside = write(t.path(), "outside/guidance.toml", PROJ);
        std::fs::create_dir_all(repo.join(".fuigo")).unwrap();
        std::os::unix::fs::symlink(&outside, repo.join(".fuigo").join(FILE_NAME)).unwrap();
        let m = load_from(&[repo.join(".fuigo").join(FILE_NAME)], None, &known());
        assert!(m.is_empty(), "outside project guidance applied: {m:?}");

        let inside = write(&repo, "docs/guidance.toml", PROJ);
        std::fs::remove_file(repo.join(".fuigo").join(FILE_NAME)).unwrap();
        std::os::unix::fs::symlink(&inside, repo.join(".fuigo").join(FILE_NAME)).unwrap();
        let m = load_from(&[repo.join(".fuigo").join(FILE_NAME)], None, &known());
        assert_eq!(m["read_file"].text, "project");

        let user_link = t.path().join("user-link.toml");
        std::os::unix::fs::symlink(&outside, &user_link).unwrap();
        let m = load_from(&[], Some(&user_link), &known());
        assert_eq!(m["read_file"].text, "project");
    }

    #[test]
    fn env_none_disables_and_env_path_replaces() {
        let t = tempfile::tempdir().unwrap();
        let user = write(t.path(), "home/tool-guidance.toml", USER);
        assert!(load_with(Some("none"), t.path(), Some(&user), &known(), |_| true).is_empty());
        let alt = write(t.path(), "alt.toml", PROJ);
        let m = load_with(
            Some(alt.to_str().unwrap()),
            t.path(),
            Some(&user),
            &known(),
            |_| true,
        );
        assert_eq!(m.len(), 1);
        assert_eq!(m["read_file"].text, "project");
    }
}
