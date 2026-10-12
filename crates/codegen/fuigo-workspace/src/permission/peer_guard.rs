//! Peer-influenced sessions and the protected set (peer messaging S6.1-S6.3, packet 6 part A).
//!
//! A session that has admitted a peer message is "peer-influenced". While that state holds, an edit-class tool
//! (write, edit, create, delete, move, `apply_patch`) aimed at a protected path is DENIED before any approving path
//! (allow-all, yolo, auto, accept-edits, saved grants, allow rules, the classifier) can see it. The guard only ever
//! makes a decision stricter: with the state clear, nothing in this module is consulted beyond one atomic load.
//!
//! PART B extension points (not built here): shell writes (`shell_access.rs`, S6.4), change detection of protected
//! files (S6.6), origin and the influenced flag in the classifier and `PreToolUse` payloads (S6.7).

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::permission::types::{AccessKind, EditTargets};

/// The live peer-influenced flag of one session, shared by every clone of its permission handle (read on every request).
#[derive(Clone, Debug, Default)]
pub struct PeerInfluence(Arc<AtomicBool>, Arc<AtomicBool>, crate::permission::peer_denials::DenialLog);

impl PeerInfluence {
    /// S7: the session tree's denial ring and carried denials (shared with subagents like the flag).
    pub fn denials(&self) -> &crate::permission::peer_denials::DenialLog {
        &self.2
    }
    /// S6.7: whether the running turn started from (or was joined by) a peer message. Set by the session, shared like the flag.
    pub fn peer_turn(&self) -> bool {
        self.1.load(Ordering::SeqCst)
    }
    pub fn set_peer_turn(&self, on: bool) {
        self.1.store(on, Ordering::SeqCst);
    }
    /// S6.7: the turn origin and influenced flag the classifier and `PreToolUse` payloads carry, or `None` (payload bytes
    /// unchanged) when the session is not influenced and the turn did not start from a peer message.
    pub fn payload_note(&self) -> Option<PeerPayloadNote> {
        let (influenced, peer_turn) = (self.is_set(), self.peer_turn());
        (influenced || peer_turn).then(|| PeerPayloadNote {
            origin: peer_turn.then(|| "peer_message".to_owned()),
            peer_influenced: influenced,
        })
    }
    pub fn new() -> Self {
        Self::default()
    }
    pub fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
    pub fn set(&self, influenced: bool) {
        self.0.store(influenced, Ordering::SeqCst);
    }
}

/// The S6.7 fields (field names follow the `UserPromptSubmit` payload: `origin` is `"peer_message"`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerPayloadNote {
    pub origin: Option<String>,
    pub peer_influenced: bool,
}

/// What the model is told when the guard denies (decision 41: always deny; the human lifts it with `/peers clear-influence`).
pub fn peer_guard_denial_text(path: &str) -> String {
    format!(
        "Denied: this session has read messages from another session, so it cannot change settings, hooks, \
         permission rules, MCP config, plugins, rule files or instruction files (CLAUDE.md, AGENTS.md and similar) \
         or peer config (`{path}`). The human can run `/peers clear-influence` in this session to lift the restriction."
    )
}

/// What the model is told when a shell command cannot be analysed while the session is peer-influenced.
pub fn peer_unanalysable_denial_text() -> String {
    "Denied: this session has read messages from another session, and this command could not be analysed (it uses \
     variables, substitutions, loops, subshells or another form whose write targets cannot be pinned), so it was not \
     run. Rewrite it as plain commands with literal paths, or the human can run `/peers clear-influence` in this \
     session to lift the restriction."
        .to_owned()
}

/// Whether an edit of `path` is blocked for a peer-influenced session: the existing protected-edit floor plus the
/// instruction and rule files (S6.2). `path` must be absolute; a relative or unresolvable path counts as protected, as
/// in the floor. Symlinks (leaf or parent) and `..` are resolved with the floor's own resolver.
pub fn is_peer_protected_path(path: &Path) -> bool {
    if crate::permission::shell_access::edit_target_protection(path).is_some() {
        return true;
    }
    // `edit_target_protection` already failed closed for relative and unresolvable paths.
    is_peer_protected_path_extension(path)
}

/// The part of the set that the floor does not know (S6.2 additions). `path` must be absolute.
pub(crate) fn is_peer_protected_path_extension(path: &Path) -> bool {
    let lexical = fuigo_paths::normalize_lexically(path);
    if instruction_set_match(&lexical) {
        return true;
    }
    crate::permission::policy::resolve_following_symlinks(path)
        .is_some_and(|resolved| instruction_set_match(&resolved))
}

/// Lexical-only form of [`is_peer_protected_path_extension`] (no filesystem access), for walking many tree entries.
pub(crate) fn is_peer_protected_lexical(path: &Path) -> bool {
    instruction_set_match(&fuigo_paths::normalize_lexically(path))
}

/// Whether `path` IS a bare container directory (`.claude`, `.fuigo`, `.cursor`), by spelling or after symlinks. A
/// copy, move or link that lands a tree, or a link, on it can create any rule or command file under it (S6.4).
pub(crate) fn is_peer_bare_container(path: &Path) -> bool {
    let bare = |p: &Path| {
        p.components().next_back().is_some_and(|c| match c {
            std::path::Component::Normal(n) => {
                matches!(n.to_string_lossy().to_ascii_lowercase().as_str(), ".claude" | ".fuigo" | ".cursor")
            }
            _ => false,
        })
    };
    bare(&fuigo_paths::normalize_lexically(path))
        || crate::permission::policy::resolve_following_symlinks(path).is_some_and(|resolved| bare(&resolved))
}

/// Directories under the Fuigo home that load rules, skills, agents, commands, plugins, hooks, peer config or memory.
const HOME_DIRS: [&str; 13] = [
    "sessions", "rules", "skills", "agents", "commands", "peers", "plugins", "hooks", "memory", "personas", "roles", "prompts", "workflows",
];

/// The audit log and its one rotation, by exact name (`peer_audit.rs` `FILE_NAME`, `ROTATED_NAME`).
fn is_audit_file_name(name: &str) -> bool {
    matches!(name, "peer-audit.jsonl" | "peer-audit.jsonl.1")
}

fn file_starts_with_audit(path: &Path, home: &Path) -> bool {
    path.parent() == Some(home)
        && path.file_name().is_some_and(|n| is_audit_file_name(&n.to_string_lossy().to_ascii_lowercase()))
}

/// The additions to the floor. Names compare case-insensitively, like the floor.
fn instruction_set_match(path: &Path) -> bool {
    let parts: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(p) => Some(p.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect();
    let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
    let Some(file) = parts.last().copied() else {
        return false;
    };
    // Instruction files read at every level (`fuigo-tools/src/types/compat.rs:425-440`, `agents_md_tracker.rs:20-31`).
    if matches!(file, "claude.md" | "claude.local.md" | "agents.md" | "agent.md") {
        return true;
    }
    // Rule, skill, agent and command directories (`agents_md_tracker.rs` RULES_DIRS, `skills/discovery.rs:26-29`).
    let in_rule_dir = parts.windows(2).any(|w| {
        matches!(w[0], ".claude" | ".fuigo" | ".cursor")
            && matches!(w[1], "rules" | "skills" | "skills-cursor" | "agents" | "commands")
    });
    if in_rule_dir {
        return true;
    }
    // Peer config, held store and audit log; plugins and their marketplace list; the `.fuigo` bundle directories that
    // define personas, roles, prompts and workflows (`fuigo-bundle/src/lib.rs`); the memory directory.
    if parts.windows(2).any(|w| {
        (w[0] == ".fuigo" && matches!(w[1], "peers" | "personas" | "roles" | "prompts" | "workflows" | "memory" | "sessions"))
            || (matches!(w[0], ".claude" | ".fuigo" | ".cursor") && w[1] == "plugins")
    }) {
        return true;
    }
    // The marketplace list lives in `<home>/plugins/` (`.fuigo`, `.cursor` or `~/.claude`), already covered above; the audit
    // log sits directly in the Fuigo home. Neither matches by file name alone, so an unrelated file of that name elsewhere is free.
    if is_audit_file_name(file) && parts.len() >= 2 && parts[parts.len() - 2] == ".fuigo" {
        return true;
    }
    // A relocated Fuigo home (`FUIGO_HOME`, no `.fuigo` component): the floor's helper handles case and a symlinked home.
    if crate::permission::shell_access::fuigo_home_matches(fuigo_config::user_fuigo_home().as_deref(), |home| {
        HOME_DIRS.iter().any(|d| path.starts_with(home.join(d))) || {
            file_starts_with_audit(path, home)
        }
    }) {
        return true;
    }
    // The runtime socket directory `$XDG_RUNTIME_DIR/fuigo/<hash>/peers`, used when the home path is too long for a socket
    // (S3.5): the inbox socket and locator may live there, so it is protected exactly like `<home>/peers`.
    if runtime_peers_dir_for_home().is_some_and(|d| path.starts_with(&d)) {
        return true;
    }
    // Git config: repo, worktree, submodule, and the user's own.
    let n = parts.len();
    (file == "config" && n >= 2 && parts[n - 2] == ".git")
        || (file == "config" && parts.windows(2).any(|w| w == [".git", "modules"]))
        || (file == "config.worktree" && parts.contains(&".git"))
        || file == ".gitconfig"
        || parts.ends_with(&[".config", "git", "config"])
}

/// `$XDG_RUNTIME_DIR/fuigo/<hash>/peers` for this process's Fuigo home, computed by the same pure function the inbox uses.
fn runtime_peers_dir_for_home() -> Option<std::path::PathBuf> {
    #[cfg(test)]
    if let Some((runtime, home)) = TEST_RUNTIME_DIR.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone() {
        return Some(fuigo_peer::runtime_peers_dir(&runtime, &home));
    }
    let runtime = std::path::PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?);
    if !runtime.is_absolute() {
        return None;
    }
    let home = fuigo_config::user_fuigo_home()?;
    Some(fuigo_peer::runtime_peers_dir(&runtime, &home))
}

/// Test seam: the (runtime directory, Fuigo home) the guard assumes; the process environment is never touched.
#[cfg(test)]
pub(crate) static TEST_RUNTIME_DIR: std::sync::RwLock<Option<(std::path::PathBuf, std::path::PathBuf)>> =
    std::sync::RwLock::new(None);

/// The guard (S6.3). `Some(reason)` means DENY. Consulted only when the session is peer-influenced; the caller checks
/// the flag first so a non-influenced session never reaches this.
pub fn peer_guard_denial(
    access: &AccessKind,
    edit_targets: Option<&EditTargets>,
    real_cwd: &Path,
    display_cwd: Option<&Path>,
) -> Option<String> {
    if let AccessKind::Bash(cmd) = access {
        // S6.4: write targets of the command, judged by the bash evaluator with the extended set; an unparseable
        // script counts as touching the set (only here, i.e. only while influenced).
        return crate::permission::manager::peer_bash_denial(cmd, real_cwd, display_cwd);
    }
    // PART B2: the hidden-write limit (S6.5): an interpreter, script or MCP tool write is not visible here.
    let AccessKind::Edit(single) = access else {
        return None;
    };
    let hit = |raw: &str| {
        let abs = fuigo_tools::types::resources::resolve_model_path(real_cwd, display_cwd, raw);
        is_peer_protected_path(&abs)
    };
    match edit_targets {
        Some(EditTargets::Paths(paths)) if !paths.is_empty() => paths
            .iter()
            .find(|p| hit(p))
            .map(|p| peer_guard_denial_text(p)),
        // Unparseable or empty: the existing refusal handles it (always a refusal).
        Some(_) => None,
        // `Task` is `Edit("task:<type>")`, not a file: skip the pseudo-path so a session whose cwd is inside a protected
        // directory can still spawn subagents.
        None if single.starts_with("task:") => None,
        None => hit(single).then(|| peer_guard_denial_text(single)),
    }
}

/// Whether `path` is a directory that holds one of the protected set's fixed well-known names (bounded: no walk).
pub(crate) fn peer_holds_protected(path: &Path) -> bool {
    const NAMES: &[&str] = &[
        "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "AGENT.md", ".git", ".gitconfig", ".claude", ".fuigo", ".cursor",
    ];
    path.file_name().is_some_and(|n| n == ".git") && path.exists()
        || path.is_dir() && NAMES.iter().any(|n| path.join(n).symlink_metadata().is_ok())
}
