use super::*;

/// Safe write sinks that do not touch a real file. Exact match.
pub(crate) fn is_safe_write_sink(path: &str) -> bool {
    matches!(path, "/dev/null" | "/dev/stdout" | "/dev/stderr")
}

/// Why acceptEdits must still prompt for this edit target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedEditReason {
    HookRoot,
    GitHooks,
    Ssh,
    StartupFile,
    Etc,
    FuigoConfig,
    FuigoSandbox,
    ClaudeSettings,
    CursorHooks,
    /// MCP / LSP server config (`mcp.json`, `lsp.json`, `.mcp.json`, `.cursor/mcp.json`, `.claude.json`): names programs Fuigo starts.
    McpConfig,
    /// Fail-closed / unclassified sensitive path; no user copy yet.
    Sensitive,
    /// A pinned launch permission policy file (by identity): never editable by the agent, in any mode.
    LaunchPolicy,
}

impl ProtectedEditReason {
    pub fn kind(self) -> &'static str {
        match self {
            Self::HookRoot => "hook_root",
            Self::GitHooks => "git_hooks",
            Self::Ssh => "ssh",
            Self::StartupFile => "startup_file",
            Self::Etc => "etc",
            Self::FuigoConfig => "fuigo_config",
            Self::FuigoSandbox => "fuigo_sandbox",
            Self::ClaudeSettings => "claude_settings",
            Self::CursorHooks => "cursor_hooks",
            Self::McpConfig => "mcp_config",
            Self::Sensitive => "sensitive",
            Self::LaunchPolicy => "launch_policy",
        }
    }

    pub fn description(self) -> Option<&'static str> {
        match self {
            Self::HookRoot => Some(
                "Note: This edit contains changes to hooks, which can be executed as code on later sessions without a separate execution approval.",
            ),
            Self::GitHooks => Some(
                "Note: This edit contains changes to Git hooks, which can run automatically on commit, push, or other Git actions without a separate execution approval.",
            ),
            Self::Ssh => Some(
                "Note: This edit contains changes under `.ssh`, which can affect credentials and authentication for future sessions.",
            ),
            Self::StartupFile => Some(
                "Note: This edit contains changes to a shell startup file, which can run automatically in future terminals without a separate execution approval.",
            ),
            Self::Etc => Some(
                "Note: This edit contains changes under `/etc`, which is system configuration and can affect this machine beyond the current project.",
            ),
            Self::FuigoConfig => Some(
                "Note: This edit contains changes to Fuigo config, which can alter permissions, tools, and other behavior in later sessions.",
            ),
            Self::FuigoSandbox => Some(
                "Note: This edit contains changes to the Fuigo sandbox config, which can loosen filesystem and network restrictions on commands.",
            ),
            Self::ClaudeSettings => Some(
                "Note: This edit contains changes to Claude-compatible settings, which can install hooks or change permission mode without a separate execution approval.",
            ),
            Self::CursorHooks => Some(
                "Note: This edit contains changes to Cursor hooks, which can run automatically in later sessions without a separate execution approval.",
            ),
            Self::McpConfig => Some(
                "Note: This edit contains changes to MCP or language-server config, which can start new programs in later sessions without a separate execution approval.",
            ),
            Self::Sensitive => None,
            Self::LaunchPolicy => Some(
                "Note: This edit targets the launch permission policy file, which the agent may not change.",
            ),
        }
    }
}

/// ACP `_meta` payload for protected-edit prompts (pager reads this for description).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectedEditPermission {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl ProtectedEditPermission {
    pub fn from_reason(reason: ProtectedEditReason) -> Self {
        Self {
            kind: reason.kind().to_owned(),
            description: reason.description().map(str::to_owned),
        }
    }
}

/// Whether an already-resolved direct edit target needs confirmation, and why.
///
/// The caller uses the edit tools' shared model-path resolver first.
/// This helper preserves its uncollapsed components for physical symlink and `..` resolution.
/// It also checks a separate lexical normalization for traversal aliases.
/// The reason for several targets: a pinned launch policy file ([`ProtectedEditReason::LaunchPolicy`], a hard refusal)
/// dominates every other reason; otherwise the first target's reason, as before. With no policy file pinned this stops
/// at the first protected target, so the unset path evaluates exactly what it did.
pub(crate) fn strongest_protection(
    reasons: impl IntoIterator<Item = Option<ProtectedEditReason>>,
) -> Option<ProtectedEditReason> {
    let mut first = None;
    for reason in reasons.into_iter().flatten() {
        if reason == ProtectedEditReason::LaunchPolicy {
            return Some(reason);
        }
        if first.is_none() {
            first = Some(reason);
            if !crate::permission::launch_policy::any_pins() {
                break;
            }
        }
    }
    first
}

pub(crate) fn edit_target_protection(path: &Path) -> Option<ProtectedEditReason> {
    edit_target_floor(path).or_else(|| {
        // Peer guard (S6.4): while a peer-influenced session's shell command is judged, the extended protected set
        // (instruction files, rule dirs, git config, session store) joins the floor for every shell write form.
        PEER_EXTENDED_SET
            .with(std::cell::Cell::get)
            .then(|| crate::permission::peer_guard::is_peer_protected_path_extension(path))
            .filter(|hit| *hit)
            .map(|_| ProtectedEditReason::Sensitive)
    })
}

/// Peer scope: a glob word, or an unquoted brace expansion (`{a,b}`, `{m..m}`), cannot be pinned to the name it makes.
pub(super) fn peer_unpinnable_word(word: &str) -> bool {
    word.contains(['*', '?', '['])
        || (word.contains('{') && (word.contains(',') || word.contains("..")))
}

thread_local! {
    /// Set only inside [`with_peer_extended_set`] (synchronous, same thread); never set on the ordinary permission path.
    static PEER_EXTENDED_SET: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether the peer-extended set is active on this thread (inside [`with_peer_extended_set`]).
pub(crate) fn peer_extended_set_active() -> bool {
    PEER_EXTENDED_SET.with(std::cell::Cell::get)
}

/// [`protected_edit_reason`] for an already-normalized path, plus the extended set inside the peer scope (lexical only).
pub(super) fn scoped_protected_reason(path: &Path) -> Option<ProtectedEditReason> {
    protected_edit_reason(path).or_else(|| {
        (peer_extended_set_active()
            && crate::permission::peer_guard::is_peer_protected_lexical(path))
        .then_some(ProtectedEditReason::Sensitive)
    })
}

/// Inside the peer scope: a destination directory that is itself `.claude`/`.fuigo`/`.cursor` (S6.4).
pub(super) fn peer_container_destination(dir: &Path) -> Option<ProtectedEditReason> {
    (peer_extended_set_active() && crate::permission::peer_guard::is_peer_bare_container(dir))
        .then_some(ProtectedEditReason::Sensitive)
}

/// Run `f` with the peer-extended protected set added to [`edit_target_protection`].
pub(crate) fn with_peer_extended_set<T>(f: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            PEER_EXTENDED_SET.with(|c| c.set(self.0));
        }
    }
    let _reset = Reset(PEER_EXTENDED_SET.with(|c| c.replace(true)));
    f()
}

pub(super) fn edit_target_floor(path: &Path) -> Option<ProtectedEditReason> {
    if !path.is_absolute() {
        return Some(ProtectedEditReason::Sensitive);
    }
    // 1.0.36 item a: a pinned launch policy file, by path or identity (hard links and other names count).
    if crate::permission::launch_policy::is_pinned_policy_file(path) {
        return Some(ProtectedEditReason::LaunchPolicy);
    }
    let lexical = fuigo_paths::normalize_lexically(path);
    if let Some(reason) = protected_edit_reason(&lexical) {
        return Some(reason);
    }
    let Some(resolved) = resolve_following_symlinks(path) else {
        return Some(ProtectedEditReason::Sensitive);
    };
    if let Some(reason) = protected_edit_reason(&resolved) {
        return Some(reason);
    }
    // u35 t1 (Grok d2 H3, Astra d2 M5): the files that decide folder trust, by physical path AND file identity, so a
    // hard link or another name for the store, the user config or the worktree registry is protected as itself.
    if crate::folder_trust::is_trust_input(&resolved) {
        return Some(ProtectedEditReason::FuigoConfig);
    }
    resolved_path_is_within_root(&resolved, Path::new("/etc"))
        .then_some(ProtectedEditReason::Sensitive)
}

/// Whether the (absolute) `path` is a protected edit target by its lexical form alone: no filesystem access, so a
/// large tree listing can be judged cheaply (P166 r13B).
pub(crate) fn lexical_path_is_protected(path: &Path) -> bool {
    protected_edit_reason(&fuigo_paths::normalize_lexically(path)).is_some()
}

pub(super) fn protected_edit_reason(path: &Path) -> Option<ProtectedEditReason> {
    let components: Vec<String> = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect();
    let string_components: Vec<&str> = components.iter().map(String::as_str).collect();
    let file = string_components.last().copied().unwrap_or("");
    const STARTUP_FILES: &[&str] = &[
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".bash_logout",
        ".profile",
        ".zshrc",
        ".zshenv",
        ".zprofile",
        ".zlogin",
        ".zlogout",
        ".kshrc",
        ".cshrc",
        ".tcshrc",
        ".login",
        ".logout",
        ".inputrc",
        ".xprofile",
    ];

    if protected_fuigo_hook_root(path, &string_components) {
        return Some(ProtectedEditReason::HookRoot);
    }
    if string_components.ends_with(&[".claude", "settings.json"])
        || string_components.ends_with(&[".claude", "settings.local.json"])
    {
        return Some(ProtectedEditReason::ClaudeSettings);
    }
    if string_components.ends_with(&[".cursor", "hooks.json"]) {
        return Some(ProtectedEditReason::CursorHooks);
    }
    if protected_vendor_mcp_config(&string_components) {
        return Some(ProtectedEditReason::McpConfig);
    }
    if protected_git_hooks_path(&string_components) {
        return Some(ProtectedEditReason::GitHooks);
    }
    if string_components.contains(&".ssh") {
        return Some(ProtectedEditReason::Ssh);
    }
    if STARTUP_FILES.contains(&file) {
        return Some(ProtectedEditReason::StartupFile);
    }
    if let Some(reason) = protected_fuigo_config_file(path, &string_components) {
        return Some(reason);
    }
    if let Some(reason) = protected_container_dir(
        path,
        &string_components,
        fuigo_config::user_fuigo_home().as_deref(),
    ) {
        return Some(reason);
    }
    if path == Path::new("/etc") || path.starts_with(Path::new("/etc")) {
        return Some(ProtectedEditReason::Etc);
    }
    None
}

/// Fuigo config files that alter permissions or sandbox restrictions; a silent edit would let the agent loosen its own guardrails.
/// Matched directly inside any `.fuigo` dir (user-global default and workspace overlays) and directly under a custom `$FUIGO_HOME`.
/// A custom home has no `.fuigo` component, so the component match alone cannot see it.
pub(super) fn protected_fuigo_config_file(
    path: &Path,
    components: &[&str],
) -> Option<ProtectedEditReason> {
    protected_fuigo_config_file_with_home(
        path,
        components,
        fuigo_config::user_fuigo_home().as_deref(),
    )
}

pub(super) fn protected_fuigo_config_file_with_home(
    path: &Path,
    components: &[&str],
    user_fuigo_home: Option<&Path>,
) -> Option<ProtectedEditReason> {
    let file = components.last().copied()?;
    let n = components.len();
    // Per-session grant store: `{home}/sessions/<scope>/permission.toml` or `permission_<client>.toml` (permission/state.rs).
    // Editing it grants the agent its own approvals.
    if (file == "permission.toml" || (file.starts_with("permission_") && file.ends_with(".toml")))
        && n >= 3
        && components.get(n - 3) == Some(&"sessions")
    {
        let in_dot_fuigo = n >= 4 && components.get(n - 4) == Some(&".fuigo");
        let in_fuigo_home = || {
            fuigo_home_matches(user_fuigo_home, |home| {
                path.parent()
                    .and_then(Path::parent)
                    .is_some_and(|sessions| sessions == home.join("sessions"))
            })
        };
        return (in_dot_fuigo || in_fuigo_home()).then_some(ProtectedEditReason::FuigoConfig);
    }
    // u35 t1: the folder-trust store and the worktree registry (whose records give a worktree its trust key) decide
    // folder trust: an edit is a trust grant. The registry's per-host variant on a network mount is
    // `worktrees.h-<host>.db`; its sidecars are `-wal`, `-shm` and `-journal`.
    let worktree_registry = file.starts_with("worktrees.")
        && [".db", ".db-wal", ".db-shm", ".db-journal"]
            .iter()
            .any(|ext| file.ends_with(ext));
    let reason = match file {
        fuigo_config::USER_CONFIG_FILENAME
        | fuigo_config::MANAGED_CONFIG_FILENAME
        | fuigo_config::REQUIREMENTS_FILENAME
        | fuigo_config::TRUSTED_FOLDERS_FILENAME => ProtectedEditReason::FuigoConfig,
        _ if worktree_registry => ProtectedEditReason::FuigoConfig,
        // Spawn configs: `lsp.json` starts language servers at the next load; `mcp.json` is the upstream daemon's MCP list.
        "mcp.json" | "lsp.json" => ProtectedEditReason::McpConfig,
        fuigo_config::SANDBOX_CONFIG_FILENAME => ProtectedEditReason::FuigoSandbox,
        _ => return None,
    };
    let in_dot_fuigo = n >= 2 && components.get(n - 2) == Some(&".fuigo");
    let in_fuigo_home = || fuigo_home_matches(user_fuigo_home, |home| path.parent() == Some(home));
    (in_dot_fuigo || in_fuigo_home()).then_some(reason)
}

/// P166/S5: directories that hold protected files, as a write TARGET (`cp -r x ~/.fuigo`, `mv cfg .cursor`, `mkdir .claude`).
/// A copy or move into one can create any protected file inside it, which no file-name check sees.
/// `.fuigo` and `$FUIGO_HOME` hold config, hooks, spawn configs and the grant stores (`sessions/<scope>/permission*.toml`);
/// `.cursor` holds `mcp.json` and `hooks.json`; `.claude` holds `settings*.json`.
pub(super) fn protected_container_dir(
    path: &Path,
    components: &[&str],
    user_fuigo_home: Option<&Path>,
) -> Option<ProtectedEditReason> {
    let n = components.len();
    match components.last().copied()? {
        ".fuigo" => return Some(ProtectedEditReason::FuigoConfig),
        ".cursor" => return Some(ProtectedEditReason::McpConfig),
        ".claude" => return Some(ProtectedEditReason::ClaudeSettings),
        _ => {}
    }
    let at = |i: usize| n.checked_sub(i).and_then(|i| components.get(i)).copied();
    // `.fuigo/sessions` and `.fuigo/sessions/<scope>`.
    let dot_fuigo_sessions = (at(2) == Some(".fuigo") && at(1) == Some("sessions"))
        || (at(3) == Some(".fuigo") && at(2) == Some("sessions"));
    let fuigo_home_tree = || {
        fuigo_home_matches(user_fuigo_home, |home| {
            let sessions = home.join("sessions");
            path == home || path == sessions || path.parent() == Some(sessions.as_path())
        })
    };
    (dot_fuigo_sessions || fuigo_home_tree()).then_some(ProtectedEditReason::FuigoConfig)
}

/// Vendor MCP server lists Fuigo loads and hot-reloads: project `.mcp.json` (repo root to cwd), `.cursor/mcp.json`
/// (project and home), and `.claude.json` (the config watcher reloads MCP from it). A new entry starts a program.
pub(super) fn protected_vendor_mcp_config(components: &[&str]) -> bool {
    matches!(
        components.last().copied(),
        Some(".mcp.json" | ".claude.json")
    ) || components.ends_with(&[".cursor", "mcp.json"])
}

/// True when `pred` holds for the user fuigo home in either its lexical or physically-resolved form.
/// Both forms are checked because callers hold a lexical and a resolved candidate path, and the home itself may sit behind a symlink.
/// The comparison is byte-exact (no case folding), like every other resolved-path check in this module.
pub(crate) fn fuigo_home_matches(home: Option<&Path>, pred: impl Fn(&Path) -> bool) -> bool {
    home.is_some_and(|home| {
        let lexical = fuigo_paths::normalize_lexically(home);
        pred(&lexical)
            || resolve_following_symlinks(&lexical).is_some_and(|resolved| pred(&resolved))
    })
}

pub(super) fn path_is_under_user_fuigo_hook_root(path: &Path, fuigo_home: &Path) -> bool {
    path.starts_with(fuigo_home.join("hooks")) || path == fuigo_home.join("hooks-paths")
}

pub(super) fn protected_fuigo_hook_root(path: &Path, components: &[&str]) -> bool {
    components
        .windows(2)
        .any(|pair| pair == [".fuigo", "hooks"])
        || components.ends_with(&[".fuigo", "hooks-paths"])
        || fuigo_home_matches(fuigo_config::user_fuigo_home().as_deref(), |home| {
            path_is_under_user_fuigo_hook_root(path, home)
        })
}

pub(super) fn protected_git_hooks_path(components: &[&str]) -> bool {
    // u35 t1 (design d2 §2.3): `.git/worktrees/<id>/gitdir` is a linked worktree's backlink, which decides its trust key.
    components
        .windows(2)
        .any(|pair| pair == [".git", "hooks"] || pair == [".git", "worktrees"])
        || components.iter().enumerate().any(|(git, component)| {
            *component == ".git"
                && components.get(git + 1) == Some(&"modules")
                && components[git + 2..]
                    .iter()
                    .skip(1)
                    .any(|component| *component == "hooks")
        })
}

/// `resolved_path` is already physical; resolve `root` so platform aliases such as macOS `/etc -> /private/etc` compare in the same namespace.
/// Resolution failure is conservative: the caller then requires confirmation.
pub(super) fn resolved_path_is_within_root(resolved_path: &Path, root: &Path) -> bool {
    resolve_following_symlinks(root)
        .map(|resolved_root| resolved_path.starts_with(resolved_root))
        .unwrap_or(true)
}
