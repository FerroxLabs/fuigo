use std::path::{Path, PathBuf};

use fuigo_config::resolve_global_hook_sources;
use fuigo_hooks::discovery::HookSource;
use fuigo_hooks::error::HookError;

/// Owned paths for hook sources. Callers borrow via `as_sources()`.
pub(crate) struct HookSourcePaths {
    pub global: Vec<PathBuf>,
    pub project: Vec<PathBuf>,
}

impl HookSourcePaths {
    /// Borrow as `HookSource` refs. Project sources are excluded when untrusted.
    pub(crate) fn as_sources(
        &self,
        include_project: bool,
    ) -> (Vec<HookSource<'_>>, Vec<HookSource<'_>>) {
        let global = self.global.iter().map(|p| path_to_source(p)).collect();
        let project = if include_project {
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
    }

    HookSourcePaths { global, project }
}

/// Single load entry point: build compat-aware sources, gate project sources on trust, then load.
/// Every session-startup and mid-session reload site routes through here so the source policy stays in one place.
pub(crate) fn discover_hooks(
    git_root: Option<&Path>,
    compat: &fuigo_tools::types::compat::CompatConfig,
    trusted: bool,
) -> (fuigo_hooks::discovery::HookRegistry, Vec<HookError>) {
    // Read fresh each call (not cached): a mid-session `/hooks` reload must see an updated `config.toml` or `managed_config.toml`
    // This is lighter than `ConfigLayers::load` (only the small per-layer files, no campaigns, version overrides, or MDM)
    let config_layers = fuigo_config::hook_config_layers();
    assemble_hooks(&config_layers, git_root, compat, trusted)
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
    trusted: bool,
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
    trusted: bool,
) -> (fuigo_hooks::discovery::HookRegistry, Vec<HookError>) {
    let (mut specs, mut errors) =
        fuigo_hooks::config::parse_hooks_from_config_layers(config_layers);

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
