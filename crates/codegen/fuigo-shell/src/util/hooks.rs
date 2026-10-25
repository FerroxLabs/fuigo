use std::path::{Path, PathBuf};

use fuigo_config::resolve_global_hook_sources;
use fuigo_hooks::discovery::HookSource;
use fuigo_hooks::error::HookError;

/// Which hook tiers may run in this session.
///
/// `folder` is the folder-trust verdict: project hook files, plugin hooks and agent hooks need it.
/// `user` gates the user's own hooks (config layers other than managed policy, and the hook files under the user's home).
/// An interactive session treats `user` like `folder`, so an untrusted folder runs only managed-policy hooks (the root-owned
/// requirements and system `managed_config.toml` layers, see `HookProvenance::is_managed_policy`).
/// A headless (`-p`) session has no one to ask, so its user hooks run regardless; its project, plugin and agent hooks still
/// follow folder trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HookTrust {
    pub folder: bool,
    pub user: bool,
}

impl HookTrust {
    pub(crate) fn new(folder_trusted: bool, headless: bool) -> Self {
        Self {
            folder: folder_trusted,
            user: folder_trusted || headless,
        }
    }
}

/// A bare folder verdict is the interactive rule: user hooks follow it.
impl From<bool> for HookTrust {
    fn from(folder_trusted: bool) -> Self {
        Self::new(folder_trusted, false)
    }
}

/// Owned paths for hook sources. Callers borrow via `as_sources()`.
pub(crate) struct HookSourcePaths {
    pub global: Vec<PathBuf>,
    pub project: Vec<PathBuf>,
}

impl HookSourcePaths {
    /// Borrow as `HookSource` refs. Global (user) sources are excluded unless user hooks are trusted,
    /// project sources unless the folder is trusted.
    pub(crate) fn as_sources(
        &self,
        trust: impl Into<HookTrust>,
    ) -> (Vec<HookSource<'_>>, Vec<HookSource<'_>>) {
        let trust = trust.into();
        let global = if trust.user {
            self.global.iter().map(|p| path_to_source(p)).collect()
        } else {
            vec![]
        };
        let project = if trust.folder {
            self.project.iter().map(|p| path_to_source(p)).collect()
        } else {
            vec![]
        };
        (global, project)
    }
}

fn path_to_source(p: &Path) -> HookSource<'_> {
    if p.is_dir() {
        HookSource::Directory(p)
    } else {
        HookSource::SettingsFile(p)
    }
}

fn include_claude_hooks(compat: &fuigo_tools::types::compat::CompatConfig) -> bool {
    compat.claude.hooks
        && !crate::claude_import::is_claude_import_marked_with_log("discover_hook_source_paths")
}

fn include_cursor_hooks(compat: &fuigo_tools::types::compat::CompatConfig) -> bool {
    compat.cursor.hooks
}

/// Global and project hook source paths.
/// The registry file is never a discovery source; Claude and Cursor sources are appended when their compat gates are on.
pub(crate) fn discover_hook_source_paths(
    git_root: Option<&Path>,
    compat: &fuigo_tools::types::compat::CompatConfig,
) -> HookSourcePaths {
    discover_hook_source_paths_in(
        fuigo_config::user_fuigo_home().as_deref(),
        fuigo_dirs::home_dir().as_deref(),
        git_root,
        compat,
    )
}

/// [`discover_hook_source_paths`] with the two home-anchored roots passed in: `fuigo` is the
/// user fuigo home (`<fuigo>/hooks`, `<fuigo>/hooks-paths`) and `home` the user home
/// (`<home>/.claude/settings*.json`, `<home>/.cursor/hooks.json`).
///
/// The production entry point reads both from the environment; this seam exists so a test can
/// run the real discovery and assembly against directories it owns instead of the developer's
/// dotfiles. A test that used the environment-reading entry point read whatever the machine
/// happened to have under `$HOME`, and a stray `~/.cursor/hooks.json` turned an unrelated
/// assertion red.
fn discover_hook_source_paths_in(
    fuigo: Option<&Path>,
    home: Option<&Path>,
    git_root: Option<&Path>,
    compat: &fuigo_tools::types::compat::CompatConfig,
) -> HookSourcePaths {
    discover_hook_source_paths_with_dirs(fuigo, home, git_root, &[], compat)
}

/// The folders between the repository root (exclusive) and `cwd` (inclusive), outermost first: the places a launch from a
/// subfolder keeps project hooks besides the root's. Empty when `cwd` is the root or is not inside it.
pub(crate) fn project_hook_subdirs(cwd: &Path, git_root: &Path) -> Vec<PathBuf> {
    let canon = |p: &Path| dunce::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let (cwd, root) = (canon(cwd), canon(git_root));
    let Ok(relative) = cwd.strip_prefix(&root) else {
        return Vec::new();
    };
    let mut dirs = Vec::new();
    let mut current = root;
    for part in relative.components() {
        current = current.join(part);
        dirs.push(current.clone());
    }
    dirs
}

/// [`discover_hook_source_paths_in`] with the folders from [`project_hook_subdirs`]: each adds its own project sources after
/// the root's, so a nearer folder's hooks come later.
fn discover_hook_source_paths_with_dirs(
    fuigo: Option<&Path>,
    home: Option<&Path>,
    git_root: Option<&Path>,
    subdirs: &[PathBuf],
    compat: &fuigo_tools::types::compat::CompatConfig,
) -> HookSourcePaths {
    let include_claude = include_claude_hooks(compat);
    let include_cursor = include_cursor_hooks(compat);

    // An unreadable hooks-paths file keeps the fixed Fuigo sources; a hard resolve failure omits all Fuigo global sources
    let mut global: Vec<PathBuf> =
        match resolve_global_hook_sources(fuigo, /* reject_symlinks */ false) {
            Ok(resolved) => {
                if let Some(e) = &resolved.configured_error {
                    tracing::warn!(
                        error = %e,
                        "hooks-paths unreadable; retaining fixed Fuigo hook discovery sources only"
                    );
                }
                resolved
                    .discovery_sources()
                    .map(|s| s.path.clone())
                    .collect()
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "global hook source resolve hard-failed; omitting Fuigo global sources"
                );
                Vec::new()
            }
        };

    if let Some(h) = home {
        if include_claude {
            global.push(h.join(".claude").join("settings.json"));
            global.push(h.join(".claude").join("settings.local.json"));
        }
        if include_cursor {
            global.push(h.join(".cursor").join("hooks.json"));
        }
    }

    let mut project = Vec::new();
    if let Some(root) = git_root {
        if include_claude {
            project.push(root.join(".claude").join("settings.json"));
            project.push(root.join(".claude").join("settings.local.json"));
        }
        project.push(root.join(".fuigo").join("hooks"));
        if include_cursor {
            project.push(root.join(".cursor").join("hooks.json"));
        }
        for dir in subdirs {
            if include_claude {
                project.push(dir.join(".claude").join("settings.json"));
                project.push(dir.join(".claude").join("settings.local.json"));
            }
            project.push(dir.join(".fuigo").join("hooks"));
            if include_cursor {
                project.push(dir.join(".cursor").join("hooks.json"));
            }
        }
    }

    HookSourcePaths { global, project }
}

/// Single load entry point: build compat-aware sources, gate project sources on trust, then load.
/// Every session-startup and mid-session reload site routes through here so the source policy stays in one place.
pub(crate) fn discover_hooks(
    git_root: Option<&Path>,
    compat: &fuigo_tools::types::compat::CompatConfig,
    trusted: impl Into<HookTrust>,
) -> (fuigo_hooks::discovery::HookRegistry, Vec<HookError>) {
    // Read fresh each call (not cached): a mid-session `/hooks` reload must see an updated `config.toml` or `managed_config.toml`
    // This is lighter than `ConfigLayers::load` (only the small per-layer files, no campaigns, version overrides, or MDM)
    let config_layers = fuigo_config::hook_config_layers();
    assemble_hooks(&config_layers, git_root, compat, trusted)
}

/// [`discover_hooks`] for a session launched in `cwd`: the repository root's project hooks, then those kept in each
/// folder down to `cwd`.
pub(crate) fn discover_hooks_for_cwd(
    cwd: &Path,
    compat: &fuigo_tools::types::compat::CompatConfig,
    trusted: impl Into<HookTrust>,
) -> (fuigo_hooks::discovery::HookRegistry, Vec<HookError>) {
    let trusted = trusted.into();
    let git_root = fuigo_workspace::session::git::find_git_root_from_path(cwd).ok();
    let subdirs = git_root.as_deref().map(|root| project_hook_subdirs(cwd, root)).unwrap_or_default();
    let config_layers = fuigo_config::hook_config_layers();
    let sources = discover_hook_source_paths_with_dirs(
        fuigo_config::user_fuigo_home().as_deref(),
        fuigo_dirs::home_dir().as_deref(),
        git_root.as_deref(),
        &subdirs,
        compat,
    );
    if !trusted.user || !trusted.folder {
        note_hooks_skipped_untrusted(cwd, trusted, &config_layers, &sources);
    }
    assemble_hooks_from_sources(&config_layers, &sources, trusted)
}

/// Tell the user, once per folder, that hooks were left out because the folder is not trusted.
/// Same channel as the project-plugin gate (`tracing`); nothing is said when nothing was actually skipped.
fn note_hooks_skipped_untrusted(
    cwd: &Path,
    trust: HookTrust,
    config_layers: &[fuigo_config::HookConfigLayer],
    sources: &HookSourcePaths,
) {
    use std::collections::HashSet;
    use std::sync::{LazyLock, Mutex};
    static TOLD: LazyLock<Mutex<HashSet<PathBuf>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

    let user_skipped = !trust.user
        && (config_layers.iter().any(|l| !l.provenance().is_managed_policy())
            || sources.global.iter().any(|p| p.exists()));
    let project_skipped = !trust.folder && sources.project.iter().any(|p| p.exists());
    if !user_skipped && !project_skipped {
        return;
    }
    let first = TOLD
        .lock()
        .map(|mut told| told.insert(cwd.to_path_buf()))
        .unwrap_or(false);
    if first {
        tracing::warn!(
            folder = %cwd.display(),
            "hooks skipped: folder not trusted; only managed hooks from your organization run until you trust it (/hooks-trust)"
        );
    }
}

/// Combine config-layer hooks with the file-source hooks discovered under the user's home and
/// the project, and dedup once. `config_layers` is a parameter (not read here) so tests can
/// drive it with hand-built layers; the file sources come from the environment via
/// [`discover_hook_source_paths`], so a test that must not read the developer's dotfiles uses
/// [`assemble_hooks_from_sources`] with sources it discovered under its own roots.
pub(crate) fn assemble_hooks(
    config_layers: &[fuigo_config::HookConfigLayer],
    git_root: Option<&Path>,
    compat: &fuigo_tools::types::compat::CompatConfig,
    trusted: impl Into<HookTrust>,
) -> (fuigo_hooks::discovery::HookRegistry, Vec<HookError>) {
    assemble_hooks_from_sources(
        config_layers,
        &discover_hook_source_paths(git_root, compat),
        trusted,
    )
}

/// Pure, injectable core of [`assemble_hooks`]: nothing here reads the environment.
/// Config-layer specs go first.
/// The first-wins dedup in [`fuigo_hooks::discovery::registry_from_specs_deduped`] then lets a config hook beat a byte-identical file hook.
fn assemble_hooks_from_sources(
    config_layers: &[fuigo_config::HookConfigLayer],
    source_paths: &HookSourcePaths,
    trusted: impl Into<HookTrust>,
) -> (fuigo_hooks::discovery::HookRegistry, Vec<HookError>) {
    let trusted = trusted.into();
    // Only managed-policy layers are exempt from the trust gate; the user's own config layers wait for trust
    let admitted: Vec<fuigo_config::HookConfigLayer> = config_layers
        .iter()
        .filter(|l| trusted.user || l.provenance().is_managed_policy())
        .cloned()
        .collect();
    let (mut specs, mut errors) = fuigo_hooks::config::parse_hooks_from_config_layers(&admitted);

    let (global_sources, project_sources) = source_paths.as_sources(trusted);
    let (file_specs, file_errors) =
        fuigo_hooks::discovery::collect_specs_from_sources(&global_sources, &project_sources);
    specs.extend(file_specs);
    errors.extend(file_errors);

    (
        fuigo_hooks::discovery::registry_from_specs_deduped(specs),
        errors,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuigo_hooks::config::HookProvenance;
    use fuigo_hooks::event::HookEventName;

    fn write_requirements(dir: &Path, content: &str) {
        std::fs::write(dir.join("requirements.toml"), content).unwrap();
    }

    /// The real assembly ([`assemble_hooks_from_sources`]) over file sources discovered under
    /// two empty roots this test owns, standing in for the user fuigo home and the user home.
    ///
    /// The environment-reading [`assemble_hooks`] discovers `<home>/.claude/settings*.json` and
    /// `<home>/.cursor/hooks.json` under `fuigo_dirs::home_dir()`, i.e. the developer's real
    /// dotfiles: a malformed `~/.cursor/hooks.json` on the workstation made these tests fail
    /// with `ParseFile { path: "/Users/<dev>/.cursor/hooks.json", .. }`. Nothing here touches
    /// `HOME`, so the isolation holds whatever the process environment is and needs no
    /// serialisation against other env-mutating tests.
    fn assemble_under_empty_homes(
        layers: &[fuigo_config::HookConfigLayer],
        compat: &fuigo_tools::types::compat::CompatConfig,
    ) -> (fuigo_hooks::discovery::HookRegistry, Vec<HookError>) {
        let fuigo_home = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let sources =
            discover_hook_source_paths_in(Some(fuigo_home.path()), Some(home.path()), None, compat);
        assert!(
            sources.global.iter().all(|p| p.starts_with(fuigo_home.path()) || p.starts_with(home.path())),
            "every global hook source must sit under a root this test owns: {:?}",
            sources.global
        );
        assemble_hooks_from_sources(layers, &sources, false)
    }

    /// Folder-trust fixture: one hook in every tier, so a test reads which tiers ran from the registry.
    /// - managed: `requirements.toml` in the (root-owned) system dir, a managed-policy layer;
    /// - user config: `config.toml` under the user's fuigo home;
    /// - user file: `<fuigo home>/hooks/user.json`;
    /// - project file: `<repo>/.fuigo/hooks/project.json`.
    struct TierFixture {
        _dirs: Vec<tempfile::TempDir>,
        layers: Vec<fuigo_config::HookConfigLayer>,
        sources: HookSourcePaths,
    }

    fn tier_fixture() -> TierFixture {
        let system = tempfile::tempdir().unwrap();
        let fuigo_home = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let repo = tempfile::tempdir().unwrap();
        let toml_hook = |cmd: &str| {
            format!(
                "[[hooks.Stop]]\n[[hooks.Stop.hooks]]\ntype = \"command\"\ncommand = \"{cmd}\"\ntimeout = 5\n"
            )
        };
        let json_hook = |cmd: &str| {
            serde_json::json!({ "hooks": { "Stop": [ { "hooks": [
                { "type": "command", "command": cmd }
            ] } ] } })
            .to_string()
        };
        std::fs::write(system.path().join("requirements.toml"), toml_hook("/opt/policy/managed.sh")).unwrap();
        std::fs::write(fuigo_home.path().join("config.toml"), toml_hook("/home/u/user-config.sh")).unwrap();
        std::fs::create_dir_all(fuigo_home.path().join("hooks")).unwrap();
        std::fs::write(fuigo_home.path().join("hooks/user.json"), json_hook("/home/u/user-file.sh")).unwrap();
        std::fs::create_dir_all(repo.path().join(".fuigo/hooks")).unwrap();
        std::fs::write(repo.path().join(".fuigo/hooks/project.json"), json_hook("/repo/project-file.sh")).unwrap();

        let layers = fuigo_config::hook_config_layers_at(Some(system.path()), Some(fuigo_home.path()));
        let compat = fuigo_tools::types::compat::CompatConfig::default();
        let sources = discover_hook_source_paths_in(
            Some(fuigo_home.path()),
            Some(home.path()),
            Some(repo.path()),
            &compat,
        );
        TierFixture { _dirs: vec![system, fuigo_home, home, repo], layers, sources }
    }

    fn running(fx: &TierFixture, trust: impl Into<HookTrust>) -> Vec<String> {
        let (registry, errors) = assemble_hooks_from_sources(&fx.layers, &fx.sources, trust);
        assert!(errors.is_empty(), "errors: {errors:?}");
        let mut cmds: Vec<String> = registry
            .all_hooks()
            .into_iter()
            .filter_map(|s| s.command_raw.clone())
            .map(|c| c.rsplit('/').next().unwrap().to_owned())
            .collect();
        cmds.sort();
        cmds
    }

    #[test]
    fn untrusted_interactive_runs_only_managed_hooks() {
        let fx = tier_fixture();
        assert_eq!(
            running(&fx, HookTrust::new(false, false)),
            ["managed.sh"],
            "user config, user file and project hooks must stay off; the managed-policy hook must run"
        );
        // A bare folder verdict is the interactive rule
        assert_eq!(running(&fx, false), ["managed.sh"]);
    }

    #[test]
    fn trusted_runs_every_tier() {
        let fx = tier_fixture();
        let all = ["managed.sh", "project-file.sh", "user-config.sh", "user-file.sh"];
        assert_eq!(running(&fx, HookTrust::new(true, false)), all);
        assert_eq!(running(&fx, true), all);
        assert_eq!(running(&fx, HookTrust::new(true, true)), all);
    }

    #[test]
    fn headless_untrusted_runs_user_and_managed_but_not_project() {
        let fx = tier_fixture();
        assert_eq!(
            running(&fx, HookTrust::new(false, true)),
            ["managed.sh", "user-config.sh", "user-file.sh"],
            "headless treats user hooks as trusted; project hooks still follow folder trust"
        );
    }

    /// A temp policy layer pins hooks for `SessionStart`, `UserPromptSubmit`, and `PreToolUse`.
    /// It flows through the real requirements read (`hook_config_layers_at`) and the real assembly (`assemble_hooks`).
    /// All three register with `Requirements` provenance, the provenance the disable exemption keys on.
    #[test]
    fn requirements_layer_pins_hooks_with_requirements_provenance() {
        let system_dir = tempfile::tempdir().unwrap();
        write_requirements(
            system_dir.path(),
            r#"
[[hooks.SessionStart]]
[[hooks.SessionStart.hooks]]
type = "command"
command = "/opt/policy/pin-session-start.sh"
timeout = 5

[[hooks.UserPromptSubmit]]
[[hooks.UserPromptSubmit.hooks]]
type = "command"
command = "/opt/policy/pin-prompt-submit.sh"
timeout = 5

[[hooks.PreToolUse]]
matcher = "*"
[[hooks.PreToolUse.hooks]]
type = "command"
command = "/opt/policy/pin-pre-tool-use.sh"
timeout = 5
"#,
        );

        let layers = fuigo_config::hook_config_layers_at(Some(system_dir.path()), None);
        assert_eq!(layers.len(), 1, "one requirements layer expected");
        assert_eq!(layers[0].provenance(), HookProvenance::Requirements);
        assert_eq!(layers[0].source_name(), "requirements/system");

        let compat = fuigo_tools::types::compat::CompatConfig::default();
        let (registry, errors) = assemble_under_empty_homes(&layers, &compat);
        assert!(errors.is_empty(), "errors: {errors:?}");

        for (event, command) in [
            (HookEventName::SessionStart, "pin-session-start.sh"),
            (HookEventName::UserPromptSubmit, "pin-prompt-submit.sh"),
            (HookEventName::PreToolUse, "pin-pre-tool-use.sh"),
        ] {
            let spec = registry
                .hooks_for(event)
                .iter()
                .find(|s| {
                    s.command_raw
                        .as_deref()
                        .is_some_and(|c| c.contains(command))
                })
                .unwrap_or_else(|| panic!("pinned {event} hook must register"));
            assert_eq!(
                spec.layer,
                HookProvenance::Requirements,
                "pinned {event} hook must carry requirements provenance"
            );
            assert!(
                spec.is_managed_policy(),
                "requirements provenance must classify as managed policy"
            );
            assert!(
                spec.name.starts_with("requirements/system:"),
                "provenance-prefixed name expected, got {}",
                spec.name
            );
        }
    }

    /// A realistic enterprise policy hooks shape parses and registers through the real path.
    /// The shape: command hooks with `timeout: 5`, `PreToolUse` with `matcher: "*"` and two hooks in one group, and matcher-less lifecycle groups.
    /// The two `PreToolUse` hooks are byte-identical, so both parse but content dedup registers one effective hook.
    #[test]
    fn enterprise_policy_hooks_shape_registers() {
        let system_dir = tempfile::tempdir().unwrap();
        write_requirements(
            system_dir.path(),
            r#"
[[hooks.SessionStart]]
[[hooks.SessionStart.hooks]]
type = "command"
command = "policy/hooks/bin/lifecycle-audit.sh"
timeout = 5

[[hooks.PreToolUse]]
matcher = "*"
[[hooks.PreToolUse.hooks]]
type = "command"
command = "policy/hooks/bin/pretooluse-audit.sh"
timeout = 5
[[hooks.PreToolUse.hooks]]
type = "command"
command = "policy/hooks/bin/pretooluse-audit.sh"
timeout = 5

[[hooks.UserPromptSubmit]]
[[hooks.UserPromptSubmit.hooks]]
type = "command"
command = "policy/hooks/bin/lifecycle-audit.sh"
timeout = 5
"#,
        );

        let layers = fuigo_config::hook_config_layers_at(Some(system_dir.path()), None);
        assert_eq!(layers.len(), 1);

        // Parse level: the verbatim structure yields both PreToolUse handlers.
        let (specs, errors) = fuigo_hooks::config::parse_hooks_from_config_layers(&layers);
        assert!(errors.is_empty(), "errors: {errors:?}");
        let pre_specs: Vec<_> = specs
            .iter()
            .filter(|s| s.event == HookEventName::PreToolUse)
            .collect();
        assert_eq!(
            pre_specs.len(),
            2,
            "the PreToolUse group's two hooks must both parse"
        );
        for spec in &pre_specs {
            assert_eq!(spec.configured_matcher.as_deref(), Some("*"));
            let matcher = spec.matcher.as_ref().expect("matcher '*' compiles");
            assert!(
                matcher.is_match("run_terminal_command") && matcher.is_match("Bash"),
                "matcher '*' must match every tool"
            );
            assert_eq!(spec.timeout_ms, 5000, "timeout 5s converts to 5000ms");
        }

        // Registry level through the real assembly: all three events register with requirements provenance
        // The byte-identical PreToolUse duplicate collapses to one effective hook
        let compat = fuigo_tools::types::compat::CompatConfig::default();
        let (registry, errors) = assemble_under_empty_homes(&layers, &compat);
        assert!(errors.is_empty(), "errors: {errors:?}");
        for event in [
            HookEventName::SessionStart,
            HookEventName::UserPromptSubmit,
            HookEventName::PreToolUse,
        ] {
            let policy_hooks: Vec<_> = registry
                .hooks_for(event)
                .iter()
                .filter(|s| s.layer == HookProvenance::Requirements)
                .collect();
            assert!(
                !policy_hooks.is_empty(),
                "pinned {event} hook must register with requirements provenance"
            );
        }
        assert_eq!(
            registry
                .hooks_for(HookEventName::PreToolUse)
                .iter()
                .filter(|s| s.layer == HookProvenance::Requirements)
                .count(),
            1,
            "byte-identical duplicate collapses under content dedup"
        );
    }
}
