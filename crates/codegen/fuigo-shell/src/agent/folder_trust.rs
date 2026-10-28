//! Folder-trust gate, consume side ("do you trust this folder?").
//!
//! Repo-local MCP / LSP servers, hooks, workflows, plugins, `.envrc`, permission policy, and project instructions and
//! skills are configured by files an attacker can ship inside a cloned repository. Every loader of such config asks
//! [`project_scope_allowed`], which is the workspace's one folder-trust decision
//! ([`fuigo_workspace::folder_trust::decide`], via the cached [`fuigo_workspace::folder_trust::dir_trust`]): the same
//! decision that lets the folder's shell commands run without asking (u35 t1). There is no separate cache here and no
//! exemption: a folder with no project settings, the user's home and the filesystem root are all untrusted until the
//! user says otherwise (the first is asked; the last two never are).
//!
//! The DECISION side (key, store, precedence, grants) lives in `fuigo-workspace`.

use std::collections::HashSet;
use std::path::Path;

use agent_client_protocol as acp;
use fuigo_workspace::trust::{TrustStore, workspace_key};

use fuigo_workspace::folder_trust::{
    PromptReason, TrustDecision, claude_project_mcp_names, decide, dir_trust, folder_trust_inert, persist_trust,
    prompt_for_trust,
};

use crate::session::managed_mcp::mcp_server_name;
use crate::util::config::{MCP_SCOPE_PROJECT, RemoteSettings};

// NOTE: this folder-trust store (`~/.fuigo/trusted_folders.toml`) is SEPARATE from the per-plugin trust store
// (`fuigo_agent::plugins::TrustStore` at `~/.fuigo/trusted-plugins`). Trusting a folder does NOT imply plugin trust
// and vice versa.

/// Compatibility alias; new call sites should use the workspace API directly.
pub use fuigo_workspace::folder_trust::grant_folder_trust;

/// `/untrust` for `cwd`'s folder: declined in the store and in this process (see
/// [`fuigo_workspace::folder_trust::revoke_folder_trust_store`]); the next command asks and project settings stop.
pub(crate) fn revoke_folder_trust(cwd: &Path) -> fuigo_workspace::folder_trust::RevokeOutcome {
    fuigo_workspace::folder_trust::revoke_folder_trust_store(cwd)
}

/// Whether `cwd`'s project settings (MCP/LSP servers, hooks, workflows, plugins, `.envrc`, permission rules,
/// instructions, skills) may load: the folder is Trusted ([`fuigo_workspace::folder_trust::decide`], not
/// interactive). Fail closed: an undecided, Legacy, declined or key-less folder is not.
pub(crate) fn project_scope_allowed(cwd: &Path) -> bool {
    #[cfg(test)]
    if let Some(forced) = test_override(cwd) {
        return forced;
    }
    dir_trust(cwd).is_trusted()
}

/// Whether an interactive trust PROMPT is warranted for `cwd` (the client can ask: it advertised the v2 capability).
pub(crate) fn prompt_warranted(cwd: &Path, _remote: Option<&RemoteSettings>) -> bool {
    matches!(decide(cwd, true), TrustDecision::Prompt(_))
}

/// Why the prompt for `cwd` would be asked (`None`: no prompt is warranted).
pub(crate) fn prompt_reason(cwd: &Path) -> Option<PromptReason> {
    match decide(cwd, true) {
        TrustDecision::Prompt(reason) => Some(reason),
        _ => None,
    }
}

/// Hand [`project_scope_allowed`] to fuigo-agent as the trust check for project agent files (`.fuigo/agents`,
/// `.claude/agents`). fuigo-agent cannot depend on this crate, and without the hook it loads no project agent at all.
/// Not cfg-gated: production entry points and the unit-test fixtures that need trusted loading both call it, and it is
/// set-once, so the only hook a process ever holds is this one.
pub fn install_project_agent_trust() {
    fuigo_agent::discovery::install_project_agent_trust(project_scope_allowed);
}

/// Display-only summary of which repo-local config kinds are present for `cwd`, for the trust prompt's UI.
pub(crate) fn detected_config_kinds(cwd: &Path) -> Vec<String> {
    fuigo_workspace::folder_trust::repo_config_kinds(cwd)
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// Project agents require folder trust; user/bundled/built-in agents always pass.
/// Shared by primary-session hook append (`agent_ops.rs`) and by subagent hook append and owned `mcpServers` spawn (`handle_request.rs`).
/// Plugin deny is call-site-only, before this predicate.
/// `trusted` is evaluated lazily so non-project agents skip the filesystem-walking trust verdict.
pub(crate) fn agent_inline_hooks_allowed(
    scope: fuigo_agent::config::AgentScope,
    trusted: impl FnOnce() -> bool,
) -> bool {
    scope != fuigo_agent::config::AgentScope::Project || trusted()
}

/// Agent inline hooks wait for folder trust whatever the agent's scope (unlike agent `mcpServers`, see
/// [`agent_inline_hooks_allowed`]): an untrusted folder runs only managed hooks.
/// `trusted` is evaluated lazily so a caller can defer the filesystem-walking trust verdict.
pub(crate) fn agent_hooks_allowed(trusted: impl FnOnce() -> bool) -> bool {
    trusted()
}

#[cfg(test)]
static TEST_OVERRIDES: std::sync::LazyLock<parking_lot::Mutex<std::collections::HashMap<std::path::PathBuf, bool>>> =
    std::sync::LazyLock::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));

#[cfg(test)]
fn test_override(cwd: &Path) -> Option<bool> {
    TEST_OVERRIDES.lock().get(&workspace_key(cwd)).copied()
}

/// Test-only: force the verdict for `cwd`'s folder in this process.
///
/// Tests use UNIQUE temp-dir keys and never globally clear the overrides, so they can run in parallel.
#[cfg(test)]
pub(crate) fn record_for_test(cwd: &Path, allowed: bool) {
    TEST_OVERRIDES.lock().insert(workspace_key(cwd), allowed);
}

/// Resolve `cwd`'s folder trust for a loader, asking on stderr when `allow_prompt` (only agent `initialize` for the
/// launch directory, before the TUI owns the terminal) and stdin/stderr are a terminal. Returns whether project
/// settings may load. A "yes" is saved as a grant (settings and commands); a "no" is held in this process and saved.
pub(crate) fn resolve_and_record(
    cwd: &Path,
    _remote: Option<&RemoteSettings>,
    allow_prompt: bool,
) -> bool {
    #[cfg(test)]
    if let Some(forced) = test_override(cwd) {
        return forced;
    }
    if folder_trust_inert() {
        return true;
    }
    let interactive = allow_prompt && stdio_is_terminal();
    match decide(cwd, interactive) {
        TrustDecision::Trusted => true,
        TrustDecision::Untrusted(_) => false,
        TrustDecision::Prompt(_) => {
            let Ok(key) = fuigo_workspace::trust::trust_key(cwd) else {
                return false;
            };
            stderr_prompt_decision(
                prompt_for_trust(&key),
                || persist_trust(&mut TrustStore::load(), &key),
                || fuigo_workspace::folder_trust::decline_folder_trust_key(&key),
            )
        }
    }
}

fn stdio_is_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// The launch directory's verdict (one call shared by the deferred init helpers).
pub(crate) fn resolve_launch_dir_trust(cwd: &Path, remote: Option<&RemoteSettings>) -> bool {
    let _ = remote;
    project_scope_allowed(cwd)
}

/// Whether project settings may load after the stderr trust prompt was answered. A "yes" that was not saved (or
/// recorded nothing) is reported on stderr and leaves the folder untrusted; a "no" is held in-process and saved, and a
/// failure to save it is reported too.
fn stderr_prompt_decision(
    accepted: bool,
    persist: impl FnOnce() -> fuigo_workspace::folder_trust::GrantOutcome,
    decline: impl FnOnce() -> Result<(), std::io::Error>,
) -> bool {
    if !accepted {
        if let Err(e) = decline() {
            fuigo_tty_utils::cli_eprintln!(
                "This folder is untrusted for this session, but the answer couldn't be saved ({e}); Fuigo will ask again next time."
            );
        }
        return false;
    }
    let outcome = persist();
    fuigo_workspace::folder_trust::report_cli_trust_grant(&outcome);
    outcome.dismisses_gate()
}

/// PROJECT-scoped MCP server display names for `cwd`: the names dropped from a merged server list when the workspace is untrusted.
///
/// SINGLE SOURCE OF TRUTH for "project-scoped MCP names" across ALL gate sites (session merge, the session-less agent pool, `fuigo mcp doctor`).
/// It MUST enumerate every project MCP source the loaders read.
/// Adding a new repo-local MCP source without extending this fn silently re-opens the gate.
/// `project_scoped_mcp_names_cover_every_source` guards that.
///
/// Name-based (not `ConfigSource`-based) ON PURPOSE.
/// It is the one primitive that works for BOTH the sourced session merge AND the flat `load_mcp_servers` agent-pool/doctor paths.
/// Those flat paths carry no `ConfigSource`.
/// Names use the same identity the merge dedups on ([`mcp_server_name`]).
///
/// Sources: project `.fuigo/config.toml [mcp_servers]` (NOT the user-tier global config).
/// Also project `.mcp.json` (`cwd` up to the repo root, never `$HOME`), project `.cursor/mcp.json`, and `~/.claude.json projects.<cwd>.mcpServers`.
///
/// Edge case: a name declared in BOTH a project config and the global
/// `~/.fuigo/config.toml` is dropped when untrusted. This is intended — untrusted
/// project content must not influence the command spawned for a shared name.
pub(crate) fn project_scoped_mcp_names(cwd: &Path) -> HashSet<String> {
    let mut names = HashSet::new();

    // `.fuigo/config.toml [mcp_servers]` entries tagged project (the loader's key is the display name, matching `mcp_server_name` of the merged server)
    for (name, (_cfg, scope)) in crate::util::config::load_mcp_server_configs_with_project(cwd) {
        if scope == MCP_SCOPE_PROJECT {
            names.insert(name);
        }
    }

    // Project `.mcp.json` (repo-root-down; this loader never reads $HOME).
    for server in crate::util::config::load_mcp_json_servers(cwd) {
        names.insert(mcp_server_name(&server).to_string());
    }

    // Project `.cursor/mcp.json` only
    // `load_cursor_mcp_servers` would also merge the user-scoped `~/.cursor/mcp.json`, so read the project file directly instead
    // Held to the repository like the session loader, so the names here are exactly the servers a session could load.
    if let Some(root) = crate::util::config::project_mcp_root(cwd) {
        for server in crate::util::config::load_mcp_json_file(&cwd.join(".cursor").join("mcp.json"), Some(&root)) {
            names.insert(mcp_server_name(&server).to_string());
        }
    }

    // `~/.claude.json projects.<cwd>.mcpServers` object keys.
    if let Some(claude_names) = claude_project_mcp_names(cwd) {
        names.extend(claude_names);
    }

    names
}

/// Drop repo-local (project-scoped) MCP servers from a merged server list when `cwd`'s workspace is untrusted.
/// No-op when project scope is allowed.
/// Mirrors [`filter_untrusted_project_lsp`].
///
/// Matches on display name ([`mcp_server_name`]) rather than the URL/key, so a project server is dropped regardless of transport.
/// That name is the same identity the merge dedups and the disabled/allowlist filters use.
/// A server from ANY tier (client/plugin/user/managed) whose name COLLIDES with a project-declared name is ALSO dropped when untrusted.
/// An untrusted repo must not influence the command spawned for that name (see [`project_scoped_mcp_names`]).
/// Servers with no project-name collision are kept.
pub(crate) fn filter_untrusted_project_mcp(
    cwd: &Path,
    merged: Vec<acp::McpServer>,
) -> Vec<acp::McpServer> {
    if project_scope_allowed(cwd) {
        return merged;
    }
    let project = project_scoped_mcp_names(cwd);
    merged
        .into_iter()
        .filter(|server| {
            let name = mcp_server_name(server);
            if project.contains(name) {
                tracing::warn!(
                    server = %name,
                    "folder untrusted: skipping repo-local (project-scoped) MCP server"
                );
                false
            } else {
                true
            }
        })
        .collect()
}

/// Drop repo-local (project-scoped) LSP servers from a sourced LSP map when `cwd`'s workspace is untrusted.
/// Mirrors the MCP session gate; user- and plugin-scoped servers are retained.
/// No-op when project scope is allowed.
///
/// Thin cwd-to-verdict wrapper over the shared [`fuigo_tools::implementations::lsp::config::filter_project_lsp_when_untrusted`] predicate.
/// Site B and the workspace build path therefore share one gate.
pub(crate) fn filter_untrusted_project_lsp(
    cwd: &Path,
    sourced: std::collections::BTreeMap<
        String,
        (
            fuigo_tools::implementations::lsp::config::LspServerConfig,
            fuigo_tools::types::config_source::ConfigSource,
        ),
    >,
) -> std::collections::BTreeMap<String, fuigo_tools::implementations::lsp::config::LspServerConfig>
{
    fuigo_tools::implementations::lsp::config::filter_project_lsp_when_untrusted(
        sourced,
        project_scope_allowed(cwd),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    // Used only by the consume-side regression test below
    // Imported here (not at module scope) so the non-test build doesn't carry an unused import
    use fuigo_workspace::folder_trust::repo_configs_present;

    /// A `git init`'d temp dir bounds `find_mcp_json_files` / `find_project_configs` to the temp dir.
    /// Those discover the enclosing repo and walk to its root, so they would otherwise reach any ancestor repo the system temp dir lives in.
    fn repo_tmp() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        git2::Repository::init(tmp.path()).unwrap();
        tmp
    }

    /// Simulate a release-stamped build so the folder-trust gate engages: an unstamped local/dev build auto-trusts and never gates/persists.
    /// Hold the returned guard for the test body (drop restores the prior value).
    fn simulate_release_build() -> EnvGuard {
        EnvGuard::set(fuigo_version::TEST_VERSION_ENV, "0.0.0-sim")
    }

    #[test]
    fn record_for_test_overrides_the_verdict() {
        let tmp = repo_tmp();
        record_for_test(tmp.path(), false);
        assert!(!project_scope_allowed(tmp.path()));
        record_for_test(tmp.path(), true);
        assert!(project_scope_allowed(tmp.path()));
    }

    /// u35 t1: `/trust` and the question's "yes" trust the folder at once (the one decision; no separate cache).
    #[test]
    #[serial_test::serial]
    fn grant_folder_trust_is_visible_to_project_scope() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let _sim = simulate_release_build();
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let tmp = repo_tmp();
        assert!(!project_scope_allowed(tmp.path()), "undecided: untrusted");
        assert!(grant_folder_trust(tmp.path()).dismisses_gate());
        assert!(project_scope_allowed(tmp.path()), "explicit grant must be visible to consume-side resolution");
    }

    /// `/untrust` of a trusted folder takes effect at once and reports that it was trusted.
    #[test]
    #[serial_test::serial]
    fn revoke_folder_trust_is_immediate() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let _sim = simulate_release_build();
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let tmp = repo_tmp();
        assert!(grant_folder_trust(tmp.path()).dismisses_gate());
        assert!(project_scope_allowed(tmp.path()));
        assert!(revoke_folder_trust(tmp.path()).was_trusted(), "a trusted folder reports was_trusted=true");
        assert!(!project_scope_allowed(tmp.path()), "untrust is immediate");
    }

    /// u35 t1: `/untrust` of a never-trusted folder records the "no" (the folder is not asked again).
    #[test]
    #[serial_test::serial]
    fn revoke_never_trusted_folder_records_the_no() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let _sim = simulate_release_build();
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let tmp = repo_tmp();
        assert!(!revoke_folder_trust(tmp.path()).was_trusted());
        assert!(!project_scope_allowed(tmp.path()));
        assert!(!prompt_warranted(tmp.path(), None), "a declined folder is not asked again");
        assert!(TrustStore::load().has_decision(&workspace_key(tmp.path())));
    }

    /// u35 t1: the home folder is never trusted and has nothing to revoke.
    #[test]
    #[serial_test::serial]
    fn home_is_never_trusted_and_revoke_is_not_applicable() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let _sim = simulate_release_build();
        let home = tempfile::tempdir().unwrap();
        let _home = EnvGuard::set("HOME", home.path());
        let fuigo_home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", fuigo_home.path());
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        git2::Repository::init(home.path()).unwrap();
        assert!(matches!(
            revoke_folder_trust(home.path()),
            fuigo_workspace::folder_trust::RevokeOutcome::NotApplicable
        ));
        assert!(!project_scope_allowed(home.path()), "$HOME is never trusted");
        assert!(!prompt_warranted(home.path(), None), "and never asked");
    }

    #[test]
    #[serial_test::serial]
    fn envrc_gate_drops_untrusted_then_loads_when_store_trusted() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let _sim = simulate_release_build();
        // The `.envrc` load sites gate on the folder-trust verdict
        // An `.envrc`-only untrusted clone resolves false (so the call site loads an empty env)
        // A store-trusted folder resolves true and the loader actually reads `.envrc`
        // FUIGO_HOME-isolated so the trust store is empty; FUIGO_FOLDER_TRUST unset so the default-on feature flag applies
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let tmp = repo_tmp();
        std::fs::write(tmp.path().join(".envrc"), "export GATED_ENVRC=1\n").unwrap();

        // Untrusted: the gate verdict is false, so the call site skips loading
        assert!(
            !resolve_and_record(tmp.path(), None, false),
            "untrusted `.envrc` clone must gate the load"
        );

        // Store-trust the folder: the verdict reconciles to true and the loader runs
        let mut store = TrustStore::load();
        store.grant(&workspace_key(tmp.path())).unwrap();
        assert!(resolve_and_record(tmp.path(), None, false));
        let env = fuigo_workspace::envrc::load_envrc_or_empty(tmp.path());
        assert_eq!(
            env.get("GATED_ENVRC"),
            Some(&"1".to_string()),
            "trusted folder must load `.envrc`"
        );
    }

    #[test]
    #[serial_test::serial]
    fn claude_env_gate_drops_project_env_when_untrusted() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let _sim = simulate_release_build();
        // The `.claude/settings.json` env load site mirrors `load_claude_env_with_project(cwd, project_scope_allowed(cwd))`
        // An untrusted clone's repo-tree env (which would feed BASH_ENV / GIT_SSH_COMMAND / ... to every subprocess) is dropped.
        // A store-trusted folder merges it
        // FUIGO_HOME-isolated so the trust store is empty; FUIGO_FOLDER_TRUST unset so the default-on feature flag applies
        use fuigo_workspace::permission::claude_settings::load_claude_env_with_project;
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let tmp = repo_tmp();
        let claude = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        std::fs::write(
            claude.join("settings.json"),
            r#"{"env": {"REPO_TREE_ENV_GATED": "1"}}"#,
        )
        .unwrap();

        // Untrusted: verdict false, so the repo-tree env is dropped
        assert!(!resolve_and_record(tmp.path(), None, false));
        let untrusted =
            load_claude_env_with_project(tmp.path(), resolve_and_record(tmp.path(), None, false));
        assert!(
            !untrusted.contains_key("REPO_TREE_ENV_GATED"),
            "untrusted folder must drop repo-tree .claude env"
        );

        // Store-trust: the verdict reconciles to true and the repo-tree env is merged
        let mut store = TrustStore::load();
        store.grant(&workspace_key(tmp.path())).unwrap();
        assert!(resolve_and_record(tmp.path(), None, false));
        let trusted =
            load_claude_env_with_project(tmp.path(), resolve_and_record(tmp.path(), None, false));
        assert_eq!(
            trusted.get("REPO_TREE_ENV_GATED"),
            Some(&"1".to_string()),
            "trusted folder must merge repo-tree .claude env"
        );
    }

    #[test]
    #[serial_test::serial]
    fn claude_env_gate_drops_subdir_project_env_when_untrusted() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let _sim = simulate_release_build();
        // RCE regression (subdir bypass)
        // A `.claude/settings.json` with `env` in a SUBDIR, the ONLY repo config, launched from that subdir must flip the folder untrusted
        // Its env must also be dropped
        // The env loader walks cwd to repo-root, so detection MUST walk too (a git-root-only probe missed this)
        // FUIGO_HOME-isolated so the trust store is empty
        use fuigo_workspace::permission::claude_settings::load_claude_env_with_project;
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let tmp = repo_tmp();
        let subdir = tmp.path().join("sub");
        let claude = subdir.join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        std::fs::write(
            claude.join("settings.json"),
            r#"{"env": {"SUBDIR_REPO_ENV_GATED": "1"}}"#,
        )
        .unwrap();

        // Detection walks cwd to root, so the subdir-only `.claude` is detected and the folder resolves untrusted
        assert!(
            repo_configs_present(&subdir),
            "subdir .claude/settings.json must be detected"
        );
        assert!(!resolve_and_record(&subdir, None, false));
        let untrusted =
            load_claude_env_with_project(&subdir, resolve_and_record(&subdir, None, false));
        assert!(
            !untrusted.contains_key("SUBDIR_REPO_ENV_GATED"),
            "untrusted subdir folder must drop its repo-tree .claude env"
        );

        // Granting trust re-enables it (proves the env file is real/loadable).
        let mut store = TrustStore::load();
        store.grant(&workspace_key(&subdir)).unwrap();
        assert!(resolve_and_record(&subdir, None, false));
        let trusted =
            load_claude_env_with_project(&subdir, resolve_and_record(&subdir, None, false));
        assert_eq!(
            trusted.get("SUBDIR_REPO_ENV_GATED"),
            Some(&"1".to_string()),
            "trusted folder must merge the subdir repo-tree .claude env"
        );
    }

    #[test]
    #[serial_test::serial]
    fn project_agent_inline_hooks_gated_when_untrusted_but_user_kept() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        // The production hook, installed first: "not loaded" below is the hook denying the folder.
        install_project_agent_trust();
        let _sim = simulate_release_build();
        // A cwd-discovered PROJECT agent loads only from a trusted folder, and its inline `hooks:` are gated on trust too
        // A user/built-in agent's hooks are kept
        // Exercises real discovery and the exact call-site predicate used at mvp_agent/subagent
        // FUIGO_HOME-isolated (empty store)
        use fuigo_agent::config::AgentScope;
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let tmp = repo_tmp();
        let agents = tmp.path().join(".fuigo").join("agents");
        std::fs::create_dir_all(&agents).unwrap();
        // A plain-named project agent carrying a command hook.
        std::fs::write(
            agents.join("reviewer.md"),
            "---\nname: reviewer\ndescription: x\nhooks:\n  PreToolUse:\n    - hooks:\n        - type: command\n          command: \"true\"\n---\nbody\n",
        )
        .unwrap();
        assert!(
            fuigo_agent::discovery::by_name_in_cwd("reviewer", tmp.path()).is_none(),
            "untrusted: the project agent file must not load at all"
        );

        // Exercise the REAL shared predicate both append sites use (not a copy).
        let allowed = |scope: AgentScope| {
            agent_inline_hooks_allowed(scope, || project_scope_allowed(tmp.path()))
        };

        // Untrusted: a project agent's inline hooks are dropped...
        assert!(
            !allowed(AgentScope::Project),
            "untrusted project agent inline hooks must be gated"
        );
        // ...while user/built-in agents (not cwd-sourced) keep their hooks.
        assert!(allowed(AgentScope::User));
        assert!(allowed(AgentScope::BuiltIn));
        // Agent HOOKS are stricter: an untrusted folder runs none, whatever the agent's scope.
        for scope in [AgentScope::Project, AgentScope::User, AgentScope::BuiltIn] {
            assert!(
                !agent_hooks_allowed(|| project_scope_allowed(tmp.path())),
                "untrusted: no agent hooks for {scope:?}"
            );
        }

        // Grant trust and reconcile the cache (as the post-grant reload flow does): the project agent loads and its inline hooks are appended
        let mut store = TrustStore::load();
        store.grant(&workspace_key(tmp.path())).unwrap();
        resolve_and_record(tmp.path(), None, false);
        let def = fuigo_agent::discovery::by_name_in_cwd("reviewer", tmp.path())
            .expect("trusted: the project agent loads");
        assert_eq!(def.scope, AgentScope::Project);
        assert!(def.hooks.is_some(), "project agent must carry inline hooks");
        assert!(
            allowed(def.scope),
            "trusted project agent inline hooks must be appended"
        );
        assert!(agent_hooks_allowed(|| project_scope_allowed(tmp.path())));
    }

    use fuigo_test_support::EnvGuard;

    #[test]
    #[serial_test::serial]
    fn project_scope_allowed_denies_untrusted_repo_with_configs() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        // Fail-closed (the dangerous case)
        // The setup: a release-stamped build, the feature on by default, an untrusted folder shipping code-exec config (here `.fuigo/hooks`)
        // With no store grant that must be DENIED
        // That holds even though no verdict was recorded first (the gate re-resolves fail-closed rather than defaulting open)
        // FUIGO_HOME-isolated (empty store); FUIGO_FOLDER_TRUST unset so the default-on flag applies
        let _sim = simulate_release_build();
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let tmp = repo_tmp();
        std::fs::create_dir_all(tmp.path().join(".fuigo").join("hooks")).unwrap();
        assert!(
            !project_scope_allowed(tmp.path()),
            "untrusted folder with repo configs must be denied (fail-closed)"
        );
    }

    /// u35 t1: there is no "no project settings, so trusted" exemption: an undecided folder is untrusted whatever it
    /// contains (its commands ask, and anything it later adds stays off).
    #[test]
    #[serial_test::serial]
    fn project_scope_allowed_denies_undecided_repo_without_configs() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let _sim = simulate_release_build();
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let tmp = repo_tmp();
        assert!(!project_scope_allowed(tmp.path()));
        assert!(!resolve_and_record(tmp.path(), None, false));
    }

    #[test]
    #[serial_test::serial]
    fn project_scope_allowed_allows_store_trusted_repo() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        // A folder the user explicitly trusted is ALLOWED even with repo-local configs present
        // FUIGO_HOME-isolated so the seeded store is the temp one; FUIGO_FOLDER_TRUST unset so the default-on flag applies
        let _sim = simulate_release_build();
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let tmp = repo_tmp();
        std::fs::create_dir_all(tmp.path().join(".fuigo").join("hooks")).unwrap();
        let mut store = TrustStore::load();
        store.grant(&workspace_key(tmp.path())).unwrap();
        assert!(
            project_scope_allowed(tmp.path()),
            "a store-trusted folder must be allowed"
        );
    }

    #[test]
    #[serial_test::serial]
    fn project_scope_allowed_allows_inert_local_build() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        // On a local/dev build the whole feature is inert (auto-trust): a folder with repo-local configs and an empty store is still ALLOWED
        // Assert only when compiled unstamped (mirrors the inert tests elsewhere)
        // FUIGO_TEST_VERSION is unset so `is_local_build()` is genuinely true
        let _unset_ver = EnvGuard::unset(fuigo_version::TEST_VERSION_ENV);
        if option_env!("FUIGO_VERSION").is_some() {
            return; // a release-stamped test binary is not a local build
        }
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let tmp = repo_tmp();
        std::fs::create_dir_all(tmp.path().join(".fuigo").join("hooks")).unwrap();
        assert!(
            project_scope_allowed(tmp.path()),
            "inert local/dev build must allow project scope even with configs"
        );
    }

    #[test]
    #[serial_test::serial]
    fn project_scope_allowed_denies_untrusted_plugin_only_repo() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        // A plugin-only untrusted repo (just `.fuigo/plugins/<x>/`, no hooks/MCP/LSP, no store grant) is repo-controlled code-exec
        // It must be DENIED
        // That is the verdict the shell plugin call sites feed into discover_plugins/build_for_cwd/reload
        // FUIGO_HOME-isolated (empty store); FUIGO_FOLDER_TRUST unset so the default-on flag applies
        let _sim = simulate_release_build();
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let tmp = repo_tmp();
        std::fs::create_dir_all(tmp.path().join(".fuigo").join("plugins").join("evil")).unwrap();
        assert!(
            !project_scope_allowed(tmp.path()),
            "plugin-only untrusted repo must be denied"
        );
    }

    #[test]
    #[serial_test::serial]
    fn project_scope_allowed_denies_untrusted_permission_only_repo() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        // Bridge: a clone whose ONLY repo-local config is `.fuigo/config.toml` `[permission]` (no MCP/hooks/plugins) must still gate
        // It produces untrusted via the real `repo_configs_present` / `decide` / `project_scope_allowed` path
        // Resolver unit tests inject `project_trusted = false` directly and miss this detector gap
        // Subdir launch exercises the cwd-to-git-root walk
        let _sim = simulate_release_build();
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let tmp = repo_tmp();
        let fuigo = tmp.path().join(".fuigo");
        std::fs::create_dir_all(&fuigo).unwrap();
        std::fs::write(
            fuigo.join("config.toml"),
            "[permission]\nallow = [\"Bash(*)\"]\n",
        )
        .unwrap();
        let subdir = tmp.path().join("crates").join("inner");
        std::fs::create_dir_all(&subdir).unwrap();
        assert!(
            !project_scope_allowed(&subdir),
            "permission-only untrusted repo must be denied from a subdirectory"
        );
    }

    #[test]
    #[serial_test::serial]
    fn project_scope_allowed_denies_untrusted_instruction_only_repo() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        // A clone whose ONLY project content is an AGENTS.md must gate: its instructions would otherwise reach the model ungated
        let _sim = simulate_release_build();
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let tmp = repo_tmp();
        std::fs::write(tmp.path().join("AGENTS.md"), "# project instructions\n").unwrap();
        let subdir = tmp.path().join("crates").join("inner");
        std::fs::create_dir_all(&subdir).unwrap();
        assert!(
            !project_scope_allowed(&subdir),
            "instruction-only untrusted repo must be denied from a subdirectory"
        );
    }

    #[test]
    #[serial_test::serial]
    fn project_scope_allowed_denies_untrusted_skill_only_repo() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        // A clone whose ONLY project content is a `.fuigo/skills` skill must gate the same way
        let _sim = simulate_release_build();
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let tmp = repo_tmp();
        let skill_dir = tmp.path().join(".fuigo").join("skills").join("repo-skill");
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(
            skill_dir.join("SKILL.md"),
            "---\nname: repo-skill\ndescription: test\n---\n",
        )
        .unwrap();
        assert!(
            !project_scope_allowed(tmp.path()),
            "skill-only untrusted repo must be denied"
        );
    }

    /// The optional workspace-user overlay (`FUIGO_ROOT` / `FUIGO_USER`) is project content too: its instructions and skills gate on trust and load once granted.
    #[tokio::test]
    #[serial_test::serial]
    async fn project_scope_allowed_denies_workspace_user_only_instructions() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let _sim = simulate_release_build();
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let tmp = repo_tmp();
        let workspace_user = tmp.path().join("x/alice");
        std::fs::create_dir_all(&workspace_user).unwrap();
        std::fs::write(
            workspace_user.join("AGENTS.md"),
            "workspace-user-only-instructions",
        )
        .unwrap();
        let skill_dir = workspace_user.join(".fuigo/skills/workspace-user-only-skill");
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(
            skill_dir.join("SKILL.md"),
            "---\nname: workspace-user-only-skill\ndescription: test\n---\n",
        )
        .unwrap();
        let _root = EnvGuard::set("FUIGO_ROOT", tmp.path().as_os_str());
        let _user = EnvGuard::set("FUIGO_USER", "alice");

        let cwd = tmp.path().to_string_lossy().into_owned();
        let verdict = project_scope_allowed(tmp.path());
        assert!(!verdict, "workspace-user-only markers must trigger trust");
        let instructions = fuigo_agent::prompt::agents_md::read_agents_config_with_paths(
            &cwd,
            fuigo_agent::prompt::skills::CompatConfig::default(),
            verdict,
        )
        .await;
        let skills = fuigo_agent::prompt::skills::list_skills(
            Some(&cwd),
            &fuigo_agent::prompt::skills::SkillsConfig::default(),
            fuigo_agent::prompt::skills::CompatConfig::default(),
            verdict,
        )
        .await;
        assert!(
            instructions
                .iter()
                .all(|config| config.content != "workspace-user-only-instructions")
        );
        assert!(
            skills
                .iter()
                .all(|skill| skill.name != "workspace-user-only-skill")
        );

        grant_folder_trust(tmp.path());
        let verdict = project_scope_allowed(tmp.path());
        assert!(verdict);
        let instructions = fuigo_agent::prompt::agents_md::read_agents_config_with_paths(
            &cwd,
            fuigo_agent::prompt::skills::CompatConfig::default(),
            verdict,
        )
        .await;
        let skills = fuigo_agent::prompt::skills::list_skills(
            Some(&cwd),
            &fuigo_agent::prompt::skills::SkillsConfig::default(),
            fuigo_agent::prompt::skills::CompatConfig::default(),
            verdict,
        )
        .await;
        assert!(
            instructions
                .iter()
                .any(|config| config.content == "workspace-user-only-instructions")
        );
        assert!(
            skills
                .iter()
                .any(|skill| skill.name == "workspace-user-only-skill")
        );
    }

    /// u35 t1: the remote kill switch is not read (owner decision D2): only the user's own config or env turns folder
    /// trust off.
    #[test]
    #[serial_test::serial]
    fn remote_kill_switch_is_ignored() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let _sim = simulate_release_build();
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let remote = RemoteSettings {
            folder_trust_enabled: Some(false),
            ..Default::default()
        };
        let tmp = repo_tmp();
        std::fs::create_dir_all(tmp.path().join(".fuigo").join("hooks")).unwrap();
        assert!(!resolve_and_record(tmp.path(), Some(&remote), false));
        assert!(!project_scope_allowed(tmp.path()));
        assert!(prompt_warranted(tmp.path(), Some(&remote)));
        // The user's own switch does turn it off.
        let _off = EnvGuard::set("FUIGO_FOLDER_TRUST", "0");
        assert!(project_scope_allowed(tmp.path()));
    }

    #[test]
    #[serial_test::serial]
    fn build_for_cwd_with_trust_verdict_gates_active_project_plugin() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let _sim = simulate_release_build();
        // Pins the SHELL plugin wiring end-to-end
        // The call-site expression is `build_for_cwd(cwd, &cfg, dirs, <folder-trust verdict>)`
        // It must keep an ENABLED project plugin OUT of `active_plugins()` while the folder is untrusted
        // It must let the plugin in after `grant_folder_trust`
        // The verdict/discovery/registry unit tests alone do NOT catch a silent un-gating here
        //
        // FUIGO_HOME-isolated so both the folder-trust store and the plugin trust store start empty (deterministic untrusted)
        // FUIGO_FOLDER_TRUST unset so the default-on flag applies; `#[serial]` because both are process-global
        use fuigo_agent::plugins::discovery::DiscoveryConfig;
        use fuigo_agent::plugins::{PluginRegistry, SharedPluginRegistryHandle};
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let tmp = repo_tmp();
        // A project plugin
        // Project scope is default-disabled, so name it in the `enabled` list to isolate the TRUST gate (not the enable gate)
        let plugin = tmp.path().join(".fuigo").join("plugins").join("trustgate");
        std::fs::create_dir_all(&plugin).unwrap();
        std::fs::write(plugin.join("plugin.json"), r#"{"name":"trustgate"}"#).unwrap();
        let cfg = DiscoveryConfig {
            enabled: vec!["trustgate".to_string()],
            ..Default::default()
        };
        let handle = SharedPluginRegistryHandle::new(None, vec![]);
        // Name-specific so ambient user plugins on the test host are irrelevant.
        let active_has = |reg: Option<std::sync::Arc<PluginRegistry>>| {
            reg.is_some_and(|r| r.active_plugins().iter().any(|p| p.name == "trustgate"))
        };

        // Untrusted: the verdict is false, so the plugin is still discovered but not trusted, and absent from `active_plugins()`
        let untrusted = handle.build_for_cwd(
            tmp.path(),
            &cfg,
            &[],
            resolve_and_record(tmp.path(), None, false),
        );
        assert!(
            !active_has(untrusted),
            "untrusted folder: enabled project plugin must be gated out of active_plugins()"
        );

        // Grant trust and recompute the same expression: the plugin becomes active
        grant_folder_trust(tmp.path());
        let trusted = handle.build_for_cwd(
            tmp.path(),
            &cfg,
            &[],
            resolve_and_record(tmp.path(), None, false),
        );
        assert!(
            active_has(trusted),
            "granted folder: enabled project plugin must appear in active_plugins()"
        );
    }

    #[test]
    #[serial_test::serial]
    fn discover_hooks_gates_then_loads_project_hook_via_trust_verdict() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let _sim = simulate_release_build();
        // End-to-end load path: the folder-trust verdict threaded into `discover_hooks` excludes a repo-local project hook while untrusted
        // It includes the hook after the folder is granted trust, the path where the regression historically re-opened
        // FUIGO_HOME-isolated so the grant writes to a temp store; FUIGO_FOLDER_TRUST unset so the default-on flag applies
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let tmp = repo_tmp();
        let hooks_dir = tmp.path().join(".fuigo").join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        // Top-level `{"hooks":{...}}` wrapper; no matcher means match-all
        // The parsed spec name is `<file_stem>:PreToolUse[..]`, so the file stem identifies it
        std::fs::write(
            hooks_dir.join("trust_load_gate.json"),
            r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"true"}]}]}}"#,
        )
        .unwrap();
        // Discovery prefixes project specs with `project/` and parse names them `<file_stem>:<event>[..]`, so the unique stem appears mid-name
        // `contains` matches it without coupling to the full name format.
        let has_project_hook = |reg: &fuigo_hooks::discovery::HookRegistry| {
            reg.all_hooks()
                .iter()
                .any(|h| h.name.contains("trust_load_gate"))
        };

        // Untrusted: verdict false, so discovery omits the project hook
        let untrusted = resolve_and_record(tmp.path(), None, false);
        assert!(!untrusted, "untrusted repo must resolve the gate false");
        // Mirror the production startup/reload path via the single load entry point.
        let git_root = fuigo_workspace::session::git::find_git_root_from_path(tmp.path()).ok();
        let (reg, _errs) = crate::util::hooks::discover_hooks(
            git_root.as_deref(),
            &fuigo_tools::types::compat::CompatConfig::default(),
            untrusted,
        );
        assert!(
            !has_project_hook(&reg),
            "untrusted: repo-local project hook must be gated out of discovery"
        );

        // Grant trust and re-resolve: discovery loads the project hook
        grant_folder_trust(tmp.path());
        let trusted = resolve_and_record(tmp.path(), None, false);
        assert!(trusted, "granted repo must resolve the gate true");
        let (reg, _errs) = crate::util::hooks::discover_hooks(
            git_root.as_deref(),
            &fuigo_tools::types::compat::CompatConfig::default(),
            trusted,
        );
        assert!(
            has_project_hook(&reg),
            "trusted: repo-local project hook must load"
        );
    }

    #[test]
    fn filter_untrusted_project_lsp_drops_only_project() {
        use fuigo_tools::implementations::lsp::config::LspServerConfig;
        use fuigo_tools::types::config_source::ConfigSource;
        use std::collections::BTreeMap;

        fn sourced() -> BTreeMap<String, (LspServerConfig, ConfigSource)> {
            let mut m = BTreeMap::new();
            m.insert(
                "proj".to_string(),
                (
                    LspServerConfig::default(),
                    ConfigSource::Project {
                        path: PathBuf::from("/repo/.fuigo/lsp.json"),
                    },
                ),
            );
            m.insert(
                "usr".to_string(),
                (
                    LspServerConfig::default(),
                    ConfigSource::User {
                        path: PathBuf::from("/home/.fuigo/lsp.json"),
                    },
                ),
            );
            m
        }

        // Untrusted workspace: only the project-scoped server is dropped.
        // `repo_tmp` git-inits so `workspace_key` yields a unique per-dir key even when `$TMPDIR` itself lives inside a git checkout
        let untrusted = repo_tmp();
        record_for_test(untrusted.path(), false);
        let kept = filter_untrusted_project_lsp(untrusted.path(), sourced());
        assert_eq!(kept.len(), 1);
        assert!(kept.contains_key("usr"));
        assert!(!kept.contains_key("proj"));

        // Trusted workspace (a different temp-dir key): both are retained.
        let trusted = repo_tmp();
        record_for_test(trusted.path(), true);
        let kept = filter_untrusted_project_lsp(trusted.path(), sourced());
        assert_eq!(kept.len(), 2);
        assert!(kept.contains_key("usr"));
        assert!(kept.contains_key("proj"));
    }

    #[test]
    fn load_servers_sourced_tags_project_lsp_json() {
        use fuigo_tools::implementations::lsp::config::load_servers_with_plugins_sourced;
        use fuigo_tools::types::config_source::ConfigSource;

        // A `<cwd>/.fuigo/lsp.json` server must be tagged `Project` so the gate can distinguish it from user/plugin servers
        // Asserts on the specific
        // key, so any real `~/.fuigo/lsp.json` on the test host is irrelevant.
        let tmp = repo_tmp();
        let fuigo = tmp.path().join(".fuigo");
        std::fs::create_dir_all(&fuigo).unwrap();
        std::fs::write(
            fuigo.join("lsp.json"),
            r#"{"projlsp": {"command": "true"}}"#,
        )
        .unwrap();

        let sourced = load_servers_with_plugins_sourced(tmp.path(), &[], &[], &[], &[]);
        let (_, source) = sourced.get("projlsp").expect("project server present");
        assert!(
            matches!(source, ConfigSource::Project { .. }),
            "project lsp.json must be tagged Project; got {source:?}"
        );
    }

    #[test]
    fn untrusted_workspace_drops_loaded_project_lsp() {
        use fuigo_tools::implementations::lsp::config::load_servers_with_plugins_sourced;

        // End-to-end of the load-site gate (Sites A/B)
        // A project server loaded from `<cwd>/.fuigo/lsp.json` is dropped once the workspace is untrusted
        let tmp = repo_tmp();
        let fuigo = tmp.path().join(".fuigo");
        std::fs::create_dir_all(&fuigo).unwrap();
        std::fs::write(
            fuigo.join("lsp.json"),
            r#"{"projlsp": {"command": "true"}}"#,
        )
        .unwrap();

        let sourced = load_servers_with_plugins_sourced(tmp.path(), &[], &[], &[], &[]);
        assert!(
            sourced.contains_key("projlsp"),
            "loader must see the project server"
        );

        record_for_test(tmp.path(), false);
        let kept = filter_untrusted_project_lsp(tmp.path(), sourced);
        assert!(
            !kept.contains_key("projlsp"),
            "untrusted folder must drop the project-scoped LSP server"
        );
    }

    fn http(name: &str) -> acp::McpServer {
        acp::McpServer::Http(
            acp::McpServerHttp::new(name.to_string(), format!("https://example.com/{name}"))
                .headers(vec![]),
        )
    }

    /// A git-init'd repo declaring two project-scoped MCP servers: `projjson` (`.mcp.json`) and `projtoml` (`.fuigo/config.toml [mcp_servers]`).
    fn repo_with_project_mcp() -> tempfile::TempDir {
        let tmp = repo_tmp();
        std::fs::write(
            tmp.path().join(".mcp.json"),
            r#"{"mcpServers": {"projjson": {"url": "https://proj.example.com/mcp"}}}"#,
        )
        .unwrap();
        let fuigo = tmp.path().join(".fuigo");
        std::fs::create_dir_all(&fuigo).unwrap();
        std::fs::write(
            fuigo.join("config.toml"),
            "[mcp_servers.projtoml]\nurl = \"https://projtoml.example.com/mcp\"\n",
        )
        .unwrap();
        tmp
    }

    /// Pins the three known repo-local FILE sources of [`project_scoped_mcp_names`].
    /// A project server declared in each of `.fuigo/config.toml`, `.mcp.json`, and `.cursor/mcp.json` must appear in the returned set.
    /// That catches a REGRESSION that drops one of them.
    /// It cannot catch a brand-new source TYPE added only to a loader; the single-source-of-truth doc on `project_scoped_mcp_names` is that guard.
    /// `~/.claude.json` is excluded: it lives under `$HOME` and a test must not clobber the real user file; its keys are covered by the shared reader.
    #[test]
    fn project_scoped_mcp_names_cover_every_source() {
        let tmp = repo_tmp();
        let fuigo = tmp.path().join(".fuigo");
        std::fs::create_dir_all(&fuigo).unwrap();
        std::fs::write(
            fuigo.join("config.toml"),
            "[mcp_servers.cfgsrv]\nurl = \"https://cfg.example.com/mcp\"\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join(".mcp.json"),
            r#"{"mcpServers": {"jsonsrv": {"url": "https://json.example.com/mcp"}}}"#,
        )
        .unwrap();
        let cursor = tmp.path().join(".cursor");
        std::fs::create_dir_all(&cursor).unwrap();
        std::fs::write(
            cursor.join("mcp.json"),
            r#"{"mcpServers": {"cursorsrv": {"url": "https://cursor.example.com/mcp"}}}"#,
        )
        .unwrap();

        let names = project_scoped_mcp_names(tmp.path());
        for expected in ["cfgsrv", "jsonsrv", "cursorsrv"] {
            assert!(
                names.contains(expected),
                "project_scoped_mcp_names missing {expected:?} — a project MCP source is no longer gated; got {names:?}"
            );
        }
    }

    /// P06. The source the guard above deliberately leaves out.
    ///
    /// `project_scoped_mcp_names_cover_every_source` pins the three repo-local FILE
    /// sources but excludes `~/.claude.json`, for a good reason it states outright: it
    /// lives under `$HOME` and a test must not clobber the real user file. The result was
    /// that the one MCP source living outside the repo had no regression test at all,
    /// while Contract C.2 asserted it was "the genuinely ungated read".
    ///
    /// **It is not ungated.** Verified against this baseline before writing anything, as
    /// C.2 requires. Both sides already gate it:
    ///   - detection: `claude_project_mcp_present` is called inside
    ///     `collect_repo_config_kinds`, which IS the gate via `repo_configs_present`;
    ///   - consumption: `project_scoped_mcp_names` reads it, so an untrusted repo's
    ///     entries are filtered like any other project source.
    ///
    /// So P06 does not change behaviour. It closes the coverage hole, which is the part
    /// the baseline was actually missing: nothing stopped a refactor from dropping this
    /// source and leaving `~/.claude.json` MCP servers ungated for an untrusted repo.
    ///
    /// `$HOME` is redirected to a temporary directory for the duration, so the real user
    /// file is never read or written. `EnvGuard` mutates process-global state, so this
    /// test must be `#[serial]`.
    #[test]
    #[serial_test::serial]
    fn claude_json_project_mcp_is_covered_by_the_project_scope() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        use fuigo_test_support::env::EnvGuard;

        let fake_home = tempfile::tempdir().unwrap();
        let repo = repo_tmp();
        let cwd = repo.path();

        std::fs::write(
            fake_home.path().join(".claude.json"),
            serde_json::to_string(&serde_json::json!({
                "projects": {
                    cwd.to_string_lossy(): {
                        "mcpServers": {
                            "claudesrv": { "url": "https://claude.example.com/mcp" }
                        }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let _home = EnvGuard::set("HOME", fake_home.path());

        // Sanity: the redirect took effect, so a failure below is about the gate and not
        // about the test reading the developer's real home.
        assert_eq!(
            fuigo_dirs::home_dir().as_deref(),
            Some(fake_home.path()),
            "HOME redirect did not take effect; refusing to assert against the real user file"
        );

        let names = project_scoped_mcp_names(cwd);
        assert!(
            names.contains("claudesrv"),
            "~/.claude.json projects.<cwd>.mcpServers is no longer project-scoped, so an \
             untrusted repo's MCP servers would not be filtered; got {names:?}"
        );
    }

    /// The other half: a `~/.claude.json` entry for a DIFFERENT cwd must not leak into
    /// this repo's project scope, or an unrelated project's servers would be filtered.
    #[test]
    #[serial_test::serial]
    fn claude_json_entries_for_another_cwd_are_not_project_scoped_here() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        use fuigo_test_support::env::EnvGuard;

        let fake_home = tempfile::tempdir().unwrap();
        let repo = repo_tmp();
        let other = tempfile::tempdir().unwrap();

        std::fs::write(
            fake_home.path().join(".claude.json"),
            serde_json::to_string(&serde_json::json!({
                "projects": {
                    other.path().to_string_lossy(): {
                        "mcpServers": {
                            "elsewhere": { "url": "https://elsewhere.example.com/mcp" }
                        }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let _home = EnvGuard::set("HOME", fake_home.path());
        let names = project_scoped_mcp_names(repo.path());
        assert!(
            !names.contains("elsewhere"),
            "another project's ~/.claude.json servers must not be scoped to this repo; got {names:?}"
        );
    }

    #[test]
    fn filter_untrusted_project_mcp_drops_only_project() {
        let merged = || {
            vec![
                http("projjson"),
                http("projtoml"),
                http("client"),
                http("global"),
            ]
        };

        // Untrusted: both project-declared servers are dropped
        // A client-supplied and a user/global server (neither in a project config) are retained
        let untrusted = repo_with_project_mcp();
        record_for_test(untrusted.path(), false);
        let kept = filter_untrusted_project_mcp(untrusted.path(), merged());
        let names: HashSet<&str> = kept.iter().map(mcp_server_name).collect();
        assert_eq!(names, ["client", "global"].into_iter().collect());

        // Trusted: every server is retained even with project configs present.
        let trusted = repo_with_project_mcp();
        record_for_test(trusted.path(), true);
        let kept = filter_untrusted_project_mcp(trusted.path(), merged());
        assert_eq!(kept.len(), 4);
    }







    #[test]
    #[serial_test::serial]
    fn resolve_launch_dir_trust_matches_resolve_and_record() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let _sim = simulate_release_build();
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let empty = repo_tmp();
        let untrusted = repo_tmp();
        std::fs::create_dir_all(untrusted.path().join(".fuigo").join("hooks")).unwrap();
        let trusted = repo_tmp();
        std::fs::create_dir_all(trusted.path().join(".fuigo").join("hooks")).unwrap();
        assert!(grant_folder_trust(trusted.path()).dismisses_gate());
        for (dir, want) in [(empty.path(), false), (untrusted.path(), false), (trusted.path(), true)] {
            let lt = resolve_launch_dir_trust(dir, None);
            assert_eq!(lt, resolve_and_record(dir, None, false));
            assert_eq!(lt, want, "{}", dir.display());
        }
    }

    #[test]
    #[serial_test::serial]
    fn local_build_is_inert_launch_trust_auto_trusts() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        // On a local/dev build the whole folder-trust system is inert
        // An untrusted repo that HAS repo-local configs (here an `.envrc`) with an EMPTY store still resolves trusted
        // `resolve_launch_dir_trust` returns true, and the `.envrc` loads without any grant
        // Assert the local branch ONLY when compiled unstamped (mirrors the workspace `is_local_build_honors_test_version_override`)
        // FUIGO_TEST_VERSION is unset so `is_local_build()` is genuinely true; FUIGO_HOME-isolated so the real store is never touched
        let _sim = EnvGuard::unset(fuigo_version::TEST_VERSION_ENV);
        if option_env!("FUIGO_VERSION").is_some() {
            return; // a release-stamped test binary is not a local build
        }
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let tmp = repo_tmp();
        std::fs::write(tmp.path().join(".envrc"), "export LOCAL_BUILD_ENVRC=1\n").unwrap();

        // The `.envrc` makes this a gating-eligible repo: on a release build it would resolve untrusted with an empty store
        // On a local build it does not
        assert!(
            repo_configs_present(tmp.path()),
            "the `.envrc` must make this a gating-eligible repo"
        );
        assert!(
            project_scope_allowed(tmp.path()),
            "local build: inert gate must auto-trust an untrusted repo that has configs"
        );
        assert!(
            resolve_launch_dir_trust(tmp.path(), None),
            "local build: launch-dir verdict must be trusted"
        );

        // The gated `.envrc` load (the call-site contract) runs because the gate is inert/trusted, so the var is present with no store grant
        let env = fuigo_workspace::envrc::load_envrc_or_empty(tmp.path());
        assert_eq!(
            env.get("LOCAL_BUILD_ENVRC"),
            Some(&"1".to_string()),
            "local build: `.envrc` must load without any store grant"
        );
    }

    #[test]
    #[serial_test::serial]
    fn prompt_warranted_true_for_undecided_repo() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let _sim = simulate_release_build();
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let with_configs = repo_tmp();
        std::fs::write(with_configs.path().join(".mcp.json"), "{}").unwrap();
        let without = repo_tmp();
        let plain = tempfile::tempdir().unwrap();
        for dir in [with_configs.path(), without.path(), plain.path()] {
            assert!(prompt_warranted(dir, None), "{}", dir.display());
            assert_eq!(prompt_reason(dir), Some(fuigo_workspace::folder_trust::PromptReason::New));
        }
    }


    #[test]
    #[serial_test::serial]
    fn prompt_warranted_false_when_store_trusted_and_upgrade_for_legacy() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let home = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("FUIGO_HOME", home.path());
        let _sim = simulate_release_build();
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let tmp = repo_tmp();
        let key = workspace_key(tmp.path());
        TrustStore::load().set_trusted_legacy(&key).unwrap();
        assert_eq!(prompt_reason(tmp.path()), Some(fuigo_workspace::folder_trust::PromptReason::Upgrade));
        assert!(!project_scope_allowed(tmp.path()), "a pre-1.0.35 record loads nothing until asked");
        assert!(grant_folder_trust(tmp.path()).dismisses_gate());
        assert!(!prompt_warranted(tmp.path(), None));
    }


    #[test]
    fn detected_config_kinds_summarizes_present_markers() {
        let tmp = repo_tmp();
        std::fs::write(tmp.path().join(".mcp.json"), "{}").unwrap();
        std::fs::create_dir_all(tmp.path().join(".fuigo").join("hooks")).unwrap();
        std::fs::write(tmp.path().join(".fuigo").join("lsp.json"), "{}").unwrap();
        std::fs::write(tmp.path().join(".envrc"), "export X=1\n").unwrap();
        let kinds = detected_config_kinds(tmp.path());
        assert!(kinds.contains(&"mcp".to_string()));
        assert!(kinds.contains(&"hooks".to_string()));
        assert!(kinds.contains(&"envrc".to_string()));
        // `lsp` is reported (a real gate reason), NOT filtered out, so an lsp-only repo never prompts with an empty reason list
        assert!(kinds.contains(&"lsp".to_string()));
    }

    #[test]
    fn detected_config_kinds_reports_lsp_only_repo() {
        // Regression for the "empty configKinds" bug: a repo gated SOLELY by `.fuigo/lsp.json` must still produce a non-empty reason list
        let tmp = repo_tmp();
        std::fs::create_dir_all(tmp.path().join(".fuigo")).unwrap();
        std::fs::write(tmp.path().join(".fuigo").join("lsp.json"), "{}").unwrap();
        let kinds = detected_config_kinds(tmp.path());
        assert_eq!(kinds, vec!["lsp".to_string()]);
    }

    /// P180 / u35 t1: the stderr trust prompt fails closed when nothing was saved: only a saved grant allows (there is
    /// no session-only grant). A "no" is held and saved; a refusal records nothing.
    #[test]
    fn p180_stderr_prompt_fails_closed_when_nothing_was_saved() {
        use fuigo_workspace::folder_trust::{GrantOutcome, GrantRefuse, PersistStatus};
        let no_decline = || -> Result<(), std::io::Error> { panic!("an accepted prompt declines nothing") };
        for reason in [GrantRefuse::Unreadable, GrantRefuse::NoHome, GrantRefuse::KeyMoved, GrantRefuse::UnsafeRoot] {
            assert!(!stderr_prompt_decision(true, || GrantOutcome::Refused { reason }, no_decline));
        }
        let key = std::path::PathBuf::from("/p180/key");
        assert!(stderr_prompt_decision(
            true,
            || GrantOutcome::Granted { key: key.clone(), persist: PersistStatus::Durable },
            no_decline
        ));
        assert!(!stderr_prompt_decision(
            true,
            || GrantOutcome::Granted {
                key: key.clone(),
                persist: PersistStatus::NotSaved { error: std::io::Error::other("denied") },
            },
            no_decline
        ));
        let mut declined = false;
        assert!(!stderr_prompt_decision(false, || panic!("a declined prompt grants nothing"), || {
            declined = true;
            Ok(())
        }));
        assert!(declined);
    }
}
