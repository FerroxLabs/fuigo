//! P189: the session park holds; it never attributes processes to a session by pid, process group, session id
//! or environment marker. Every symbol of that earlier design is gone, and this test keeps it gone.

use std::path::{Path, PathBuf};

/// The deleted symbols. A later packet builds `stop` on a per-session cgroup instead.
const DELETED: &[&str] = &[
    "tool_reaper",
    "orphan_reaper",
    "tool_registry",
    "session_job",
    "FUIGO_AGENT_TOKEN",
    "FUIGO_AGENT_SESSION",
    "FUIGO_AGENT_OUTER",
    "PR_SET_CHILD_SUBREAPER",
    "set_spawn_gate",
    "spawn_barrier",
];

/// Older, unrelated uses that predate P189: `fuigo-workspace-daemon` makes itself the subreaper of its own
/// preview servers (nothing to do with session parking), and `fuigo-computer-hub-core` has its own
/// `tool_registry` test (a different registry, pinned by `fuigo-extra-ca`).
const ALLOWED: &[(&str, &str)] = &[
    ("crates/codegen/fuigo-workspace-daemon/src/preview_supervisor.rs", "PR_SET_CHILD_SUBREAPER"),
    ("crates/common/fuigo-computer-hub-core", "tool_registry"),
    ("crates/codegen/fuigo-extra-ca/tests/identity_body_guard.rs", "tool_registry"),
];

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if !matches!(name.as_ref(), "target" | ".git" | "node_modules" | "docs") {
                walk(&path, out);
            }
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("rs" | "toml" | "yml" | "yaml" | "sh" | "py" | "md")
        ) {
            out.push(path);
        }
    }
}

#[test]
fn no_process_attribution_symbol_remains() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut files = Vec::new();
    walk(&root, &mut files);
    assert!(files.len() > 500, "the walk found only {} files: wrong root {}", files.len(), root.display());
    let this = Path::new(file!()).file_name().expect("file name").to_owned();
    let mut found = Vec::new();
    for file in &files {
        if file.file_name() == Some(this.as_os_str()) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(file) else { continue };
        let rel = file.strip_prefix(&root).unwrap_or(file).to_string_lossy().replace('\\', "/");
        for symbol in DELETED {
            if text.contains(symbol)
                && !ALLOWED.iter().any(|(path, allowed)| rel.starts_with(path) && allowed == symbol)
            {
                found.push(format!("{rel}: {symbol}"));
            }
        }
    }
    assert!(found.is_empty(), "deleted process-attribution symbols are back:\n{}", found.join("\n"));
}
