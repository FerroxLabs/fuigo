use super::*;

impl SessionActor {
    // ── Session hook registry: the one builder every load site uses ───

    /// The folder-trust verdict that gates a session's hook sources: the repo-local hook files and every `Project`-scope plugin's hooks.
    /// Every site that builds or rebuilds a session's hook registry (session spawn, the agent-hooks spawn override, `/hooks` reload, plugin-snapshot adoption) decides trust here, so no two sites can disagree about the same folder.
    /// It resolves and records like the session-start site always did, so a mid-session grant or revoke is seen on the next build.
    /// `remote` carries the remote kill-switch input; a site without remote settings passes `None`.
    pub(crate) fn session_hook_trust(
        cwd: &std::path::Path,
        remote: Option<&crate::util::config::RemoteSettings>,
    ) -> bool {
        crate::agent::folder_trust::resolve_and_record(cwd, remote, false)
    }

    /// The hook specs `plugins` contributes: each active plugin's hooks file, then its inline manifest hooks, in plugin order.
    /// A `Project`-scope plugin's hooks are admitted only while `project_trusted`.
    /// A plugin registry records the verdict current when it was BUILT, so one built before a `/hooks-untrust` still lists the repo's plugin as active; the verdict passed here is the current one.
    /// User, CLI and config-path plugins keep the registry's own trust decision.
    pub(crate) fn plugin_hook_specs(
        plugins: Option<&fuigo_agent::plugins::PluginRegistry>,
        project_trusted: bool,
    ) -> Vec<fuigo_hooks::config::HookSpec> {
        let Some(plugins) = plugins else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for plugin in plugins.active_plugins() {
            if plugin.scope == fuigo_agent::plugins::discovery::PluginScope::Project
                && !project_trusted
            {
                tracing::debug!(
                    plugin = %plugin.name,
                    "project plugin hooks skipped: folder not trusted"
                );
                continue;
            }
            if let Some(ref hooks_path) = plugin.hooks_path {
                let (specs, warnings) = fuigo_agent::plugins::hooks_adapter::parse_plugin_hooks(
                    hooks_path,
                    &plugin.name,
                    &plugin.root_str(),
                    &plugin.data_dir_str(),
                );
                for w in &warnings {
                    tracing::warn!("{w}");
                }
                out.extend(specs);
            }
            if let Some(ref inline_value) = plugin.inline_hooks {
                let (specs, warnings) =
                    fuigo_agent::plugins::hooks_adapter::parse_plugin_hooks_from_value(
                        inline_value,
                        &plugin.name,
                        &plugin.root_str(),
                        &plugin.data_dir_str(),
                    );
                for w in &warnings {
                    tracing::warn!("{w}");
                }
                out.extend(specs);
            }
        }
        out
    }

    /// A session's complete hook registry for `cwd`: config-layer and hook-file sources (`discover_hooks`), then the plugin hooks.
    /// Both halves are gated on the one `project_trusted` verdict (see [`Self::session_hook_trust`]).
    /// This is the initial load as well as the reload, so a plugin's hooks fire from a session's first turn, not only after something triggers a reload.
    pub(crate) fn build_session_hook_registry(
        cwd: &std::path::Path,
        compat: &fuigo_tools::types::compat::CompatConfig,
        plugins: Option<&fuigo_agent::plugins::PluginRegistry>,
        project_trusted: bool,
    ) -> (
        fuigo_hooks::discovery::HookRegistry,
        Vec<fuigo_hooks::error::HookError>,
    ) {
        let git_root = fuigo_workspace::session::git::find_git_root_from_path(cwd).ok();
        let (mut registry, errors) =
            crate::util::hooks::discover_hooks(git_root.as_deref(), compat, project_trusted);
        registry.append_specs(Self::plugin_hook_specs(plugins, project_trusted));
        (registry, errors)
    }

    /// The plugin set a hook reload takes its plugin hooks from: this session's plugins rediscovered for its cwd on `project_trusted`.
    /// A stored or freshly pushed plugin registry was built under the verdict current when it was built, and a trust change does not rebuild it:
    /// after `/hooks-untrust` it can still hold a plugin the repo contributed (a `.fuigo/plugins` dir, or a `[plugins].paths` entry in the
    /// repo's own config), and its hooks are arbitrary code.
    /// A session without a registry handle gets NO plugin hooks from a reload. That is every subagent: its stored `plugin_registry` is
    /// the process-wide snapshot (`subagent_spawn.rs`), not its parent's view of the workspace, so taking plugins from it would install
    /// another workspace's plugins (the same rule as the subagent spawn fallback). A subagent reaches a reload only by a typed
    /// `/hooks-trust` / `/hooks-untrust` in its task text; the automatic reload commands skip subagents.
    fn plugins_for_hook_reload(
        &self,
        cwd: &std::path::Path,
        project_trusted: bool,
    ) -> Option<Arc<fuigo_agent::plugins::PluginRegistry>> {
        let handle = self.plugin_registry_handle.as_ref()?;
        let disk_cfg = crate::config::resolve_effective_plugins_config(cwd).to_discovery_config();
        handle.build_for_cwd(cwd, &disk_cfg, &self.session_plugin_dirs(), project_trusted)
    }

    /// The plugin set a session's FIRST hook load takes its plugin hooks from.
    /// `built` was discovered before the session thread started, under the verdict current then; when the verdict at load time is
    /// untrusted (another session revoked the folder in between) the plugins are rediscovered on it, so no repo-contributed plugin
    /// admitted under the older verdict gets its hooks installed. A trusted verdict, or no registry handle, keeps `built`:
    /// a registry built while untrusted can only under-admit.
    pub(crate) fn plugins_for_initial_hooks(
        handle: Option<&fuigo_agent::plugins::SharedPluginRegistryHandle>,
        built: Option<Arc<fuigo_agent::plugins::PluginRegistry>>,
        cwd: &std::path::Path,
        project_trusted: bool,
    ) -> Option<Arc<fuigo_agent::plugins::PluginRegistry>> {
        let Some(handle) = handle.filter(|_| !project_trusted) else {
            return built;
        };
        let session_dirs = built
            .as_ref()
            .map(|r| r.session_plugin_dirs().to_vec())
            .unwrap_or_default();
        let disk_cfg = crate::config::resolve_effective_plugins_config(cwd).to_discovery_config();
        handle.build_for_cwd(cwd, &disk_cfg, &session_dirs, false)
    }

    /// The agent definition's own inline hooks, as the session it defines may run them under `project_trusted`.
    /// One derivation for the primary-session spawn override (`agent_ops`) and every reload, so a reload keeps an admitted agent's hooks
    /// and drops a project agent's hooks once the folder is untrusted. A plugin's agent gets none, for any session: the subagent spawn
    /// already refuses them ("not supported for security"), and an agent definition does not carry its plugin's trust.
    /// A subagent (only reached by a manual reload) also keeps the subagent spawn's `Stop` -> `SubagentStop` mapping.
    pub(crate) fn agent_inline_hook_specs(
        definition: &fuigo_agent::AgentDefinition,
        cwd: &std::path::Path,
        project_trusted: bool,
        is_subagent: bool,
    ) -> Vec<fuigo_hooks::config::HookSpec> {
        let Some(hooks_config) = definition.hooks.as_ref() else {
            return Vec::new();
        };
        if definition.plugin_name.is_some() {
            tracing::warn!(
                agent = %definition.name,
                plugin = ?definition.plugin_name,
                "ignoring hooks on plugin agent (not supported for security)"
            );
            return Vec::new();
        }
        if !crate::agent::folder_trust::agent_inline_hooks_allowed(definition.scope, || {
            project_trusted
        }) {
            return Vec::new();
        }
        let (specs, errors) = fuigo_hooks::config::parse_hooks_from_value_with_dir(
            &hooks_config.as_value(),
            &format!(
                "{}{}",
                fuigo_hooks::config::AGENT_HOOK_PREFIX,
                definition.name
            ),
            cwd,
        );
        for e in &errors {
            tracing::warn!(agent = %definition.name, error = ?e, "agent hook parse error");
        }
        if !is_subagent {
            return specs;
        }
        specs
            .into_iter()
            .map(|mut s| {
                if s.event == fuigo_hooks::event::HookEventName::Stop {
                    s.event = fuigo_hooks::event::HookEventName::SubagentStop;
                }
                s
            })
            .collect()
    }

    /// A primary session's spawn override (disk hooks + plugin hooks + its agent's inline hooks) was built before the session thread
    /// started, under the verdict current then. When the verdict at load time is untrusted, its plugin hooks are replaced by those of a
    /// rediscovery on that verdict (see [`Self::plugins_for_initial_hooks`]); a trusted verdict keeps the override as built.
    pub(crate) fn revalidate_override_plugin_hooks(
        override_reg: Arc<fuigo_hooks::discovery::HookRegistry>,
        handle: Option<&fuigo_agent::plugins::SharedPluginRegistryHandle>,
        built: Option<Arc<fuigo_agent::plugins::PluginRegistry>>,
        cwd: &std::path::Path,
        project_trusted: bool,
    ) -> Arc<fuigo_hooks::discovery::HookRegistry> {
        if project_trusted {
            return override_reg;
        }
        let plugins = Self::plugins_for_initial_hooks(handle, built, cwd, false);
        let mut registry = (*override_reg).clone();
        registry.remove_by_prefix("plugin/");
        registry.append_specs(Self::plugin_hook_specs(plugins.as_deref(), false));
        Arc::new(registry)
    }

    /// Re-derive the session's agent inline hooks after its agent definition changed (a zero-turn harness rebuild on model switch):
    /// the old agent's hooks go, the new one's come in under the same gate as at spawn, and the handle-visible copy follows.
    pub(super) fn replace_agent_inline_hooks(&self) {
        let cwd = std::path::Path::new(&self.session_info.cwd);
        let trusted = Self::session_hook_trust(cwd, None);
        let specs = Self::agent_inline_hook_specs(
            self.agent.borrow().definition(),
            cwd,
            trusted,
            self.startup_hints.is_subagent,
        );
        {
            let mut reg = self.hook_registry.borrow_mut();
            match reg.as_mut() {
                Some(arc_reg) => {
                    let hook_reg = Arc::make_mut(arc_reg);
                    hook_reg.remove_by_prefix(fuigo_hooks::config::AGENT_HOOK_PREFIX);
                    hook_reg.append_specs(specs);
                }
                None if !specs.is_empty() => {
                    let mut hook_reg = fuigo_hooks::discovery::HookRegistry::default();
                    hook_reg.append_specs(specs);
                    *reg = Some(Arc::new(hook_reg));
                }
                None => {}
            }
        }
        self.publish_hook_registry();
    }

    /// Copy the actor's registry into the handle-visible live cell, so a subagent spawned after a reload inherits what the parent fires now.
    /// Call after every write to `hook_registry`.
    fn publish_hook_registry(&self) {
        self.hook_registry_live
            .set(self.hook_registry.borrow().clone());
    }

    // ── Shared hook/plugin operation functions ────────────────────────

    /// Trust the current project via the unified folder-trust store.
    /// Same as `--trust`: also allows repo-local MCP/LSP for this folder.
    pub(super) fn do_hooks_trust_project(cwd: &str) -> Result<std::path::PathBuf, String> {
        let root =
            fuigo_workspace::session::git::find_git_root_from_path(std::path::Path::new(cwd))
                .map_err(|_| {
                    "Not in a git repository. Project hooks require a git worktree root."
                        .to_string()
                })?;
        fuigo_workspace::folder_trust::grant_folder_trust(&root);
        Ok(root)
    }

    /// Untrust the current project in the unified folder-trust store.
    /// Returns (git_root, was_trusted).
    pub(super) fn do_hooks_untrust_project(
        cwd: &str,
    ) -> Result<(std::path::PathBuf, bool), String> {
        let root =
            fuigo_workspace::session::git::find_git_root_from_path(std::path::Path::new(cwd))
                .map_err(|_| "Not in a git repository.".to_string())?;
        // revoke_folder_trust persists set_untrusted and downgrades the decision cache so the untrust applies at the next reload, not just restart
        let was_trusted = crate::agent::folder_trust::revoke_folder_trust(&root);
        Ok((root, was_trusted))
    }

    /// Re-resolve the repo `[mcp] max_output_bytes` cap for this session's cwd and update the toolset's `TruncationCfg` resource to match.
    /// Only that field changes, so any other `TruncationCfg` fields a host seeded are preserved.
    /// Clears the cap (restoring the process-global fallback) when the project tier no longer wins: the key was removed, or folder trust was revoked.
    /// `resolve_max_mcp_output_bytes_for_cwd` is trust-gated, so calling this after a trust change keeps the seeded cap matching the gate.
    /// Called from the `UpdateMcpServers` handler (project-config hot reload) and from the hooks-modal Trust/Untrust actions.
    pub(super) async fn reseed_mcp_output_cap(&self) {
        let resolved = crate::util::config::resolve_max_mcp_output_bytes_for_cwd(
            std::path::Path::new(&self.session_info.cwd),
        );
        let bridge = std::sync::Arc::clone(self.agent.borrow().tool_bridge());
        let toolset = bridge.toolset();
        let mut resources = toolset.resources.lock().await;
        let existing = resources
            .get::<fuigo_tools::types::resources::TruncationCfg>()
            .map(|c| c.0.clone());
        match (resolved, existing) {
            (resolved, Some(mut cfg)) => {
                if cfg.mcp_max_output_bytes != resolved {
                    cfg.mcp_max_output_bytes = resolved;
                    resources.insert(fuigo_tools::types::resources::TruncationCfg(cfg));
                }
            }
            (Some(v), None) => {
                resources.insert(fuigo_tools::types::resources::TruncationCfg(
                    fuigo_tools::types::context::TruncationConfig {
                        mcp_max_output_bytes: Some(v),
                        ..Default::default()
                    },
                ));
            }
            (None, None) => {}
        }
    }

    /// Resolve a potentially relative path against the session cwd.
    fn resolve_path(cwd: &str, path: &str) -> std::path::PathBuf {
        let p = std::path::Path::new(path);
        if p.is_relative() {
            std::path::Path::new(cwd).join(p)
        } else {
            p.to_path_buf()
        }
    }

    /// Whether `name` resolves to a managed-policy (non-disableable) hook in the live registry, keyed on the spec's typed `layer`, never on the name.
    /// Fails open on a missing registry or name: a disable entry that slips through is inert because the dispatcher re-checks provenance at run time.
    /// This modal check is UX; the dispatcher is the enforcement boundary.
    pub(super) fn is_managed_policy_hook(&self, name: &str) -> bool {
        self.hook_registry
            .borrow()
            .as_ref()
            .is_some_and(|registry| {
                registry
                    .find_by_name(name)
                    .is_some_and(|spec| spec.is_managed_policy())
            })
    }

    // ── Hooks/plugins action handlers (pager modal) ──────────────────

    /// Handle a hooks management action from the pager modal.
    pub(super) async fn handle_hooks_action(
        self: &Arc<Self>,
        action: fuigo_hooks_plugins_types::HooksAction,
    ) -> fuigo_hooks_plugins_types::ActionOutcome {
        use fuigo_hooks_plugins_types::{ActionOutcome, HooksAction, OutcomeStatus};

        match action {
            HooksAction::Reload => {
                let reload_msg = self.reload_hooks_impl().await;
                ActionOutcome {
                    status: OutcomeStatus::Success,
                    message: format!("Hooks reloaded.\n{reload_msg}"),
                    requires_reload: false,
                    requires_restart: false,
                }
            }
            HooksAction::Trust => match Self::do_hooks_trust_project(&self.session_info.cwd) {
                Err(e) => ActionOutcome {
                    status: OutcomeStatus::ValidationError,
                    message: e,
                    requires_reload: false,
                    requires_restart: false,
                },
                Ok(root) => {
                    let reload_msg = self.reload_hooks_impl().await;
                    // Trusting flips the project-config gate: re-seed the repo MCP output cap so it applies without waiting for a config edit
                    self.reseed_mcp_output_cap().await;
                    ActionOutcome {
                        status: OutcomeStatus::Success,
                        message: format!("Trusted: {}.\n{reload_msg}", root.display()),
                        requires_reload: false,
                        requires_restart: false,
                    }
                }
            },
            HooksAction::Untrust => match Self::do_hooks_untrust_project(&self.session_info.cwd) {
                Err(e) => ActionOutcome {
                    status: OutcomeStatus::ValidationError,
                    message: e,
                    requires_reload: false,
                    requires_restart: false,
                },
                Ok((root, false)) => {
                    // Another session may have revoked the folder already; this session's registry still has to follow the verdict
                    let _ = self.reload_hooks_impl().await;
                    ActionOutcome {
                        status: OutcomeStatus::NotFound,
                        message: format!("Not currently trusted: {}", root.display()),
                        requires_reload: false,
                        requires_restart: false,
                    }
                }
                Ok((root, true)) => {
                    let reload_msg = self.reload_hooks_impl().await;
                    // Revoking trust must drop a previously seeded repo MCP output cap right away, not at the next config reload
                    // The resolver is trust-gated, so this call clears it
                    self.reseed_mcp_output_cap().await;
                    ActionOutcome {
                        status: OutcomeStatus::Success,
                        message: format!("Untrusted: {}.\n{reload_msg}", root.display()),
                        requires_reload: false,
                        requires_restart: false,
                    }
                }
            },
            HooksAction::Add { path } => {
                if path.is_empty() {
                    return ActionOutcome {
                        status: OutcomeStatus::ValidationError,
                        message: "Path is required.".into(),
                        requires_reload: false,
                        requires_restart: false,
                    };
                }
                // CWE-427: add_hooks_path() validates path is under ~/.fuigo/.
                match crate::config::off_reactor({
                    let path = path.to_string();
                    move || crate::config::add_hooks_path(&path)
                })
                .await
                {
                    Ok(()) => ActionOutcome {
                        status: OutcomeStatus::Success,
                        message: {
                            let reload_msg = self.reload_hooks_impl().await;
                            format!("Added hook path: {path}.\n{reload_msg}")
                        },
                        requires_reload: false,
                        requires_restart: false,
                    },
                    Err(e) => ActionOutcome {
                        status: OutcomeStatus::ValidationError,
                        message: format!("Failed to add hook path: {e}"),
                        requires_reload: false,
                        requires_restart: false,
                    },
                }
            }
            HooksAction::Remove { path } => {
                if path.is_empty() {
                    return ActionOutcome {
                        status: OutcomeStatus::ValidationError,
                        message: "Path is required.".into(),
                        requires_reload: false,
                        requires_restart: false,
                    };
                }
                match crate::config::off_reactor({
                    let path = path.to_string();
                    move || crate::config::remove_hooks_path(&path)
                })
                .await
                {
                    Ok(true) => ActionOutcome {
                        status: OutcomeStatus::Success,
                        message: {
                            let reload_msg = self.reload_hooks_impl().await;
                            format!("Removed hook path: {path}.\n{reload_msg}")
                        },
                        requires_reload: false,
                        requires_restart: false,
                    },
                    // The message omits the path; the user's selection already identifies the source
                    Ok(false) => ActionOutcome {
                        status: OutcomeStatus::NotFound,
                        message: "Only user-added hook directories can be removed here.".to_owned(),
                        requires_reload: false,
                        requires_restart: false,
                    },
                    Err(e) => ActionOutcome {
                        status: OutcomeStatus::InternalError,
                        message: format!("Failed to remove hook path: {e}"),
                        requires_reload: false,
                        requires_restart: false,
                    },
                }
            }
            HooksAction::Disable { hook_name } => {
                // Internal spec names stay out of the user-facing message
                if self.is_managed_policy_hook(&hook_name) {
                    return ActionOutcome {
                        status: OutcomeStatus::ValidationError,
                        message: "This hook is enforced by managed policy and cannot be disabled."
                            .to_owned(),
                        requires_reload: false,
                        requires_restart: false,
                    };
                }
                match fuigo_hooks::trust::disable_hook(&hook_name) {
                    Ok(()) => ActionOutcome {
                        status: OutcomeStatus::Success,
                        message: "Hook disabled.".to_owned(),
                        requires_reload: false,
                        requires_restart: false,
                    },
                    Err(e) => ActionOutcome {
                        status: OutcomeStatus::InternalError,
                        message: format!("Failed to disable hook: {e}"),
                        requires_reload: false,
                        requires_restart: false,
                    },
                }
            }
            HooksAction::Enable { hook_name } => {
                match fuigo_hooks::trust::enable_hook(&hook_name) {
                    Ok(true) => ActionOutcome {
                        status: OutcomeStatus::Success,
                        message: "Hook enabled.".to_owned(),
                        requires_reload: false,
                        requires_restart: false,
                    },
                    Ok(false) => ActionOutcome {
                        status: OutcomeStatus::NotFound,
                        message: "Hook was not disabled.".to_owned(),
                        requires_reload: false,
                        requires_restart: false,
                    },
                    Err(e) => ActionOutcome {
                        status: OutcomeStatus::InternalError,
                        message: format!("Failed to enable hook: {e}"),
                        requires_reload: false,
                        requires_restart: false,
                    },
                }
            }
            HooksAction::ToggleSource {
                hook_names,
                disable,
            } => {
                let mut toggled = 0usize;
                let mut managed_skipped = 0usize;
                for name in &hook_names {
                    // Managed-policy hooks are exempt from bulk disable, same rule as the per-hook Disable action
                    if disable && self.is_managed_policy_hook(name) {
                        managed_skipped += 1;
                        continue;
                    }
                    let ok = if disable {
                        fuigo_hooks::trust::disable_hook(name).is_ok()
                    } else {
                        // Only an actual removal counts (Ok(false) means it wasn't disabled)
                        fuigo_hooks::trust::enable_hook(name) == Ok(true)
                    };
                    if ok {
                        toggled += 1;
                    }
                }
                let action = if disable { "Disabled" } else { "Enabled" };
                let mut message = format!("{action} {toggled}/{} hooks", hook_names.len());
                if managed_skipped > 0 {
                    message.push_str(&format!(
                        " ({managed_skipped} enforced by managed policy, not disabled)"
                    ));
                }
                ActionOutcome {
                    status: OutcomeStatus::Success,
                    message,
                    requires_reload: false,
                    requires_restart: false,
                }
            }
        }
    }

    /// Handle a plugins management action from the pager modal.
    pub(super) async fn handle_plugins_action(
        self: &Arc<Self>,
        action: fuigo_hooks_plugins_types::PluginsAction,
    ) -> fuigo_hooks_plugins_types::ActionOutcome {
        use fuigo_hooks_plugins_types::{ActionOutcome, OutcomeStatus, PluginsAction};

        match action {
            PluginsAction::Reload => match &self.plugin_registry_handle {
                Some(handle) => {
                    // An explicit user reload forces a full re-copy of local installs
                    let msg = self.reload_plugins_impl(handle, true).await;
                    ActionOutcome {
                        status: OutcomeStatus::Success,
                        message: msg,
                        requires_reload: false,
                        requires_restart: false,
                    }
                }
                None => ActionOutcome {
                    status: OutcomeStatus::Unsupported,
                    message: "No plugin registry handle available.".into(),
                    requires_reload: false,
                    requires_restart: false,
                },
            },
            PluginsAction::Install { source } => {
                if source.is_empty() {
                    return ActionOutcome {
                        status: OutcomeStatus::ValidationError,
                        message: "Source is required (git URL or local path).".into(),
                        requires_reload: false,
                        requires_restart: false,
                    };
                }
                let cwd = std::path::Path::new(&self.session_info.cwd);
                let install_source =
                    fuigo_agent::plugins::git_install::parse_install_source(&source, cwd);
                let registry = fuigo_agent::plugins::InstallRegistry::load();
                match fuigo_agent::plugins::git_install::install_from_source(
                    &install_source,
                    &registry,
                    crate::plugin::marketplace_require_sha(),
                ) {
                    Ok(result) => {
                        let repo = fuigo_agent::plugins::git_install::build_installed_repo(
                            &result,
                            &install_source,
                        );
                        let mut registry = registry;
                        registry.insert(result.repo_key.clone(), repo);
                        if let Err(e) = registry.save() {
                            tracing::warn!("Failed to save install registry: {e}");
                        }
                        let (names, post_warnings) =
                            crate::config::post_install_plugin_off_reactor(&result.repo_key).await;
                        let count = names.len();
                        let mut msg = format!(
                            "Installed {count} plugin(s) from {source}: {}",
                            names.join(", ")
                        );
                        for w in &post_warnings {
                            msg.push_str(&format!(" (warning: {w})"));
                        }
                        ActionOutcome {
                            status: OutcomeStatus::Success,
                            message: msg,
                            requires_reload: true,
                            requires_restart: false,
                        }
                    }
                    Err(e) => ActionOutcome {
                        status: OutcomeStatus::InternalError,
                        message: format!("Failed to install plugin: {e}"),
                        requires_reload: false,
                        requires_restart: false,
                    },
                }
            }
            PluginsAction::Uninstall {
                plugin_id,
                confirmed,
            } => {
                if plugin_id.is_empty() {
                    return ActionOutcome {
                        status: OutcomeStatus::ValidationError,
                        message: "Plugin ID is required.".into(),
                        requires_reload: false,
                        requires_restart: false,
                    };
                }
                // Extract plugin name from ID (last segment of "scope/hex8/name").
                let plugin_name = plugin_id.rsplit('/').next().unwrap_or(&plugin_id);
                let mut registry = fuigo_agent::plugins::InstallRegistry::load();
                match registry.find_plugin(plugin_name) {
                    None => ActionOutcome {
                        status: OutcomeStatus::NotFound,
                        message: format!("Plugin \"{plugin_name}\" not found in install registry."),
                        requires_reload: false,
                        requires_restart: false,
                    },
                    Some((repo_key, repo, _plugin)) => {
                        let repo_key = repo_key.to_string();
                        let repo_path = repo.path.clone();
                        let plugin_names: Vec<String> = repo.plugins.keys().cloned().collect();
                        let count = plugin_names.len();

                        // A multi-plugin repo needs confirmation before removal
                        if count > 1 && !confirmed {
                            return ActionOutcome {
                                status: OutcomeStatus::ConfirmationRequired,
                                message: format!(
                                    "Repo \"{repo_key}\" contains {count} plugin(s): {}. Uninstalling will remove all of them.",
                                    plugin_names.join(", ")
                                ),
                                requires_reload: false,
                                requires_restart: false,
                            };
                        }

                        // Proceed with removal.
                        if let Err(e) =
                            fuigo_agent::plugins::git_install::remove_repo_path(&repo_path)
                        {
                            tracing::warn!("Failed to remove repo path: {e}");
                        }
                        registry.remove(&repo_key);
                        if let Err(e) = registry.save() {
                            tracing::warn!("Failed to save install registry: {e}");
                        }
                        ActionOutcome {
                            status: OutcomeStatus::Success,
                            message: format!(
                                "Uninstalled repo \"{repo_key}\" ({count} plugin(s): {})",
                                plugin_names.join(", ")
                            ),
                            requires_reload: true,
                            requires_restart: false,
                        }
                    }
                }
            }
            PluginsAction::Update { plugin_id } => {
                let registry = fuigo_agent::plugins::InstallRegistry::load();
                let all_repos = registry.list();
                if all_repos.is_empty() {
                    return ActionOutcome {
                        status: OutcomeStatus::NotFound,
                        message: "No installed plugins to update.".into(),
                        requires_reload: false,
                        requires_restart: false,
                    };
                }

                let repos_to_update: Vec<(
                    String,
                    fuigo_agent::plugins::install_registry::InstalledRepo,
                )> = if let Some(ref id) = plugin_id {
                    let name = id.rsplit('/').next().unwrap_or(id);
                    match registry.find_plugin(name) {
                        Some((key, repo, _plugin)) => vec![(key.to_string(), repo.clone())],
                        None => {
                            return ActionOutcome {
                                status: OutcomeStatus::NotFound,
                                message: format!("Plugin \"{name}\" not found."),
                                requires_reload: false,
                                requires_restart: false,
                            };
                        }
                    }
                } else {
                    all_repos
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v.clone()))
                        .collect()
                };

                let mut messages = Vec::new();
                let mut any_updated = false;
                for (key, repo) in &repos_to_update {
                    match fuigo_agent::plugins::git_install::update_repo(
                        key,
                        repo,
                        crate::plugin::marketplace_require_sha(),
                    ) {
                        Ok(status) => {
                            use fuigo_agent::plugins::git_install::UpdateStatus;
                            match status {
                                UpdateStatus::Updated(result) => {
                                    if result.changed {
                                        any_updated = true;
                                        messages.push(format!("{key}: updated"));
                                    } else {
                                        messages.push(format!("{key}: already up to date"));
                                    }
                                }
                                UpdateStatus::Pinned { ref_name } => {
                                    messages.push(format!("{key}: pinned to {ref_name}"));
                                }
                                UpdateStatus::LiveLocal => {
                                    messages.push(format!("{key}: local symlink (already live)"));
                                }
                            }
                        }
                        Err(e) => {
                            messages.push(format!("{key}: update failed: {e}"));
                        }
                    }
                }
                if let Err(e) = registry.save() {
                    tracing::warn!("Failed to save install registry after update: {e}");
                }
                ActionOutcome {
                    status: OutcomeStatus::Success,
                    message: messages.join("\n"),
                    requires_reload: any_updated,
                    requires_restart: false,
                }
            }
            PluginsAction::Add { path } => {
                if path.is_empty() {
                    return ActionOutcome {
                        status: OutcomeStatus::ValidationError,
                        message: "Path is required.".into(),
                        requires_reload: false,
                        requires_restart: false,
                    };
                }
                let resolved = Self::resolve_path(&self.session_info.cwd, &path);
                let path_str = resolved.display().to_string();
                match crate::config::off_reactor({
                    let path_str = path_str.to_string();
                    move || crate::config::add_plugin_path(&path_str)
                })
                .await
                {
                    Ok(()) => {
                        let mut msg = format!("Added plugin path: {path_str}");
                        if let Some(ref handle) = self.plugin_registry_handle {
                            let reload_msg = self.reload_plugins_impl(handle, false).await;
                            msg.push('\n');
                            msg.push_str(&reload_msg);
                        }
                        ActionOutcome {
                            status: OutcomeStatus::Success,
                            message: msg,
                            requires_reload: false,
                            requires_restart: false,
                        }
                    }
                    Err(e) => ActionOutcome {
                        status: OutcomeStatus::InternalError,
                        message: format!("Failed to add plugin path: {e}"),
                        requires_reload: false,
                        requires_restart: false,
                    },
                }
            }
            PluginsAction::Enable { plugin_id } => {
                // Add to enabled list (for project plugins) and remove from disabled list.
                let r1 = crate::config::off_reactor({
                    let plugin_id = plugin_id.to_string();
                    move || crate::config::add_enabled_plugin(&plugin_id)
                })
                .await;
                let r2 = crate::config::off_reactor({
                    let plugin_id = plugin_id.to_string();
                    move || crate::config::remove_disabled_plugin(&plugin_id)
                })
                .await;
                match r1.and(r2) {
                    Ok(()) => {
                        if let Some(ref handle) = self.plugin_registry_handle {
                            let reload_msg = self.reload_plugins_impl(handle, false).await;
                            ActionOutcome {
                                status: OutcomeStatus::Success,
                                message: format!("Enabled: {plugin_id}.\n{reload_msg}"),
                                requires_reload: false,
                                requires_restart: false,
                            }
                        } else {
                            ActionOutcome {
                                status: OutcomeStatus::Success,
                                message: format!("Enabled: {plugin_id}. Restart to apply."),
                                requires_reload: false,
                                requires_restart: true,
                            }
                        }
                    }
                    Err(e) => ActionOutcome {
                        status: OutcomeStatus::InternalError,
                        message: format!("Failed to enable plugin: {e}"),
                        requires_reload: false,
                        requires_restart: false,
                    },
                }
            }
            PluginsAction::Disable { plugin_id } => {
                // Add to disabled list and remove from enabled list.
                let r1 = crate::config::off_reactor({
                    let plugin_id = plugin_id.to_string();
                    move || crate::config::add_disabled_plugin(&plugin_id)
                })
                .await;
                let r2 = crate::config::off_reactor({
                    let plugin_id = plugin_id.to_string();
                    move || crate::config::remove_enabled_plugin(&plugin_id)
                })
                .await;
                match r1.and(r2) {
                    Ok(()) => {
                        if let Some(ref handle) = self.plugin_registry_handle {
                            let reload_msg = self.reload_plugins_impl(handle, false).await;
                            ActionOutcome {
                                status: OutcomeStatus::Success,
                                message: format!("Disabled: {plugin_id}.\n{reload_msg}"),
                                requires_reload: false,
                                requires_restart: false,
                            }
                        } else {
                            ActionOutcome {
                                status: OutcomeStatus::Success,
                                message: format!("Disabled: {plugin_id}. Restart to apply."),
                                requires_reload: false,
                                requires_restart: true,
                            }
                        }
                    }
                    Err(e) => ActionOutcome {
                        status: OutcomeStatus::InternalError,
                        message: format!("Failed to disable plugin: {e}"),
                        requires_reload: false,
                        requires_restart: false,
                    },
                }
            }
            PluginsAction::Remove { path } => {
                if path.is_empty() {
                    return ActionOutcome {
                        status: OutcomeStatus::ValidationError,
                        message: "Path is required.".into(),
                        requires_reload: false,
                        requires_restart: false,
                    };
                }
                let resolved = Self::resolve_path(&self.session_info.cwd, &path);
                let path_str = resolved.display().to_string();
                match crate::config::off_reactor({
                    let path_str = path_str.to_string();
                    move || crate::config::remove_plugin_path(&path_str)
                })
                .await
                {
                    Ok(()) => {
                        let mut msg = format!("Removed plugin path: {path_str}");
                        if let Some(ref handle) = self.plugin_registry_handle {
                            let reload_msg = self.reload_plugins_impl(handle, false).await;
                            msg.push('\n');
                            msg.push_str(&reload_msg);
                        }
                        ActionOutcome {
                            status: OutcomeStatus::Success,
                            message: msg,
                            requires_reload: false,
                            requires_restart: false,
                        }
                    }
                    Err(e) => ActionOutcome {
                        status: OutcomeStatus::InternalError,
                        message: format!("Failed to remove plugin path: {e}"),
                        requires_reload: false,
                        requires_restart: false,
                    },
                }
            }
        }
    }

    /// Reload hooks mid-session: re-discovers global and project hooks, re-evaluates project trust, and re-appends plugin-contributed hooks.
    /// `pub(super)` so the `SessionCommand::ReloadHooks` arm in `run_session` (parent module) can call it after an interactive folder-trust grant.
    pub(super) async fn reload_hooks_impl(self: &std::sync::Arc<Self>) -> String {
        // Reconcile folder-trust so a mid-session /hooks-trust (or --trust) grant counts on reload, then gate project hook sources on the verdict
        let cwd = std::path::Path::new(&self.session_info.cwd);
        let is_trusted = Self::session_hook_trust(cwd, None);
        // The same builder as session spawn, so all vendors (compat and native), custom hook-paths and plugin hooks match the session-startup sites
        // Defense in depth: a subagent's reload never installs plugin hooks itself, whatever registry it holds (see `plugins_for_hook_reload`)
        let plugins_now = if self.startup_hints.is_subagent {
            None
        } else {
            self.plugins_for_hook_reload(cwd, is_trusted)
        };
        let (mut registry, errors) = Self::build_session_hook_registry(
            cwd,
            &self.rebuild_spec.compat,
            plugins_now.as_deref(),
            is_trusted,
        );
        // The session's agent hooks are part of its registry too (the spawn override put them there): re-derive them on the same verdict
        let agent_specs = Self::agent_inline_hook_specs(
            self.agent.borrow().definition(),
            cwd,
            is_trusted,
            self.startup_hints.is_subagent,
        );
        registry.append_specs(agent_specs);
        for err in &errors {
            tracing::warn!("hook reload error: {err}");
        }
        *self.hook_load_errors.borrow_mut() = errors.iter().map(|e| e.to_string()).collect();
        let hook_count = registry.len();
        {
            let mut reg = self.hook_registry.borrow_mut();
            if registry.is_empty() {
                *reg = None;
            } else {
                *reg = Some(std::sync::Arc::new(registry));
            }
        }
        self.publish_hook_registry();
        tracing::info!(hook_count, "hooks reloaded mid-session");

        // Notify pager about hooks change.
        // Extract all RefCell borrows into locals before the .await so no Ref guard is alive across the suspension point
        {
            let hooks = crate::extensions::hooks::current_hook_infos(
                self.hook_registry.borrow().as_deref(),
            );
            let load_errors = self.hook_load_errors.borrow().clone();
            let project_trusted = is_trusted;
            self.send_fuigo_notification(FuigoSessionUpdate::HooksChanged {
                hooks,
                project_trusted,
                load_errors,
            })
            .await;
        }
        format!("Hooks reloaded: {hook_count} hook(s) loaded.")
    }

    /// Shared plugin reload logic used by enable/disable/add/remove and the explicit `/plugins reload` command.
    /// Re-reads plugin config from disk, rebuilds the registry, reloads hooks, and returns a human-readable status message.
    /// `force` is `true` only for the explicit `/plugins reload`, which forces a full re-copy of local installs.
    /// Incidental toggles pass `false` for the cheap skip-unchanged path.
    pub(super) async fn reload_plugins_impl(
        self: &Arc<Self>,
        handle: &fuigo_agent::plugins::SharedPluginRegistryHandle,
        force: bool,
    ) -> String {
        let session_cwd = std::path::Path::new(&self.session_info.cwd);

        let sid = self.session_info.id.0.as_ref();
        fuigo_telemetry::unified_log::info("reload_plugins_impl: start", Some(sid), None);

        // Folder-trust gates repo-local project plugins (hooks/MCP)
        // Resolve and record the verdict for this cwd before the plugins-config read below, whose project-paths merge reads the gate
        // commands/list and the fan-out order these the same way, so no gate read ever precedes the site's own resolve
        // The session-start hook load already printed the folder-untrusted notice, so this resolve stays quiet
        let project_trusted =
            crate::agent::folder_trust::resolve_and_record(session_cwd, None, false);

        let t0 = std::time::Instant::now();
        // Resolve the effective [plugins] config: global, ancestor project configs, and the compat merge
        // Shared with commands/list and the eager fan-out so all paths discover the same plugins for this cwd
        let plugins_cfg = crate::config::resolve_effective_plugins_config(session_cwd);
        let config_read_ms = t0.elapsed().as_millis();

        let t2 = std::time::Instant::now();
        let discovery_config = plugins_cfg.to_discovery_config();
        let count = handle.reload(Some(session_cwd), &discovery_config, project_trusted, force);
        let discover_ms = t2.elapsed().as_millis();

        fuigo_telemetry::unified_log::info(
            "reload_plugins_impl: discovery done",
            Some(sid),
            Some(serde_json::json!({
                "config_read_ms": config_read_ms as u64,
                "discover_ms": discover_ms as u64,
                "total_ms": t0.elapsed().as_millis() as u64,
                "plugin_count": count,
            })),
        );

        // Adopt the freshly-rebuilt snapshot into this session (hooks, MCP, skills, client slash-command catalog)
        // Sessions with `_meta.pluginDirs` rebuild their own view instead; the shared snapshot never carries them
        let session_dirs = self.session_plugin_dirs();
        let new_registry_snapshot = if session_dirs.is_empty() {
            handle.snapshot()
        } else {
            handle.build_for_cwd(
                session_cwd,
                &discovery_config,
                &session_dirs,
                project_trusted,
            )
        };
        let (hooks_reloaded, mcp_changed, skill_count) = self
            .apply_plugin_registry_snapshot(new_registry_snapshot)
            .await;

        let mcp_status = if mcp_changed {
            "MCP refreshed"
        } else {
            "MCP unchanged"
        };
        format!(
            "Plugin registry rebuilt: {count} plugin(s), {hooks_reloaded} hook(s) reloaded, \
             {mcp_status}, {skill_count} skill(s) refreshed."
        )
    }

    /// This session's `_meta.pluginDirs`, recovered from the registry it was built with; empty when the session has none.
    pub(crate) fn session_plugin_dirs(&self) -> Vec<std::path::PathBuf> {
        self.plugin_registry
            .borrow()
            .as_ref()
            .map(|r| r.session_plugin_dirs().to_vec())
            .unwrap_or_default()
    }

    /// Re-merge this session's `_meta.pluginDirs` into a registry rebuilt by a process-wide fan-out (which knows nothing about per-session dirs).
    pub(crate) fn preserve_session_plugin_dirs(
        &self,
        incoming: Option<std::sync::Arc<fuigo_agent::plugins::PluginRegistry>>,
    ) -> Option<std::sync::Arc<fuigo_agent::plugins::PluginRegistry>> {
        let dirs = self.session_plugin_dirs();
        if dirs.is_empty() {
            return incoming;
        }
        let Some(handle) = self.plugin_registry_handle.as_ref() else {
            return incoming;
        };
        let session_cwd = std::path::Path::new(&self.session_info.cwd);
        let disk_cfg =
            crate::config::resolve_effective_plugins_config(session_cwd).to_discovery_config();
        // The one hook-trust predicate; the session's spawn resolve already recorded this cwd with the real remote
        let project_trusted = Self::session_hook_trust(session_cwd, None);
        handle.build_for_cwd(session_cwd, &disk_cfg, &dirs, project_trusted)
    }

    /// Apply a pre-built plugin registry snapshot to this session.
    /// Swaps the per-session registry, reloads plugin hooks, re-merges plugin MCP servers, re-scans skills, and notifies the client.
    /// Called by `reload_plugins_impl` in the originating session and by the `ReloadPlugins` command when plugins change in another session.
    /// Returns `(hooks_reloaded, mcp_changed, skill_count)`.
    /// [`crate::session::SessionCommand::SetClientMcpSeed`].
    pub(crate) fn set_client_mcp_seed(&self, seed: crate::session::managed_mcp::ClientMcpSeed) {
        *self.initial_client_mcp_servers.borrow_mut() = seed;
    }

    pub(super) async fn apply_plugin_registry_snapshot(
        self: &Arc<Self>,
        new_registry_snapshot: Option<std::sync::Arc<fuigo_agent::plugins::PluginRegistry>>,
    ) -> (usize, bool, usize) {
        let sid = self.session_info.id.0.as_ref();
        let session_cwd = std::path::Path::new(&self.session_info.cwd);

        *self.plugin_registry.borrow_mut() = new_registry_snapshot.clone();

        // Reload hooks in the current session
        let t_hooks = std::time::Instant::now();
        let hooks_reloaded: usize;
        // Plugin hooks come from this session's plugins rediscovered on the CURRENT verdict, exactly as in `reload_hooks_impl`:
        // the snapshot being adopted may have been built before a trust change (a fan-out racing a `/hooks-untrust`)
        // A `None` result means no plugin is left: it must strip the previous plugin hooks, not keep them
        {
            let project_trusted = Self::session_hook_trust(session_cwd, None);
            let plugins_now = self.plugins_for_hook_reload(session_cwd, project_trusted);
            let new_specs = Self::plugin_hook_specs(plugins_now.as_deref(), project_trusted);
            hooks_reloaded = new_specs.len();
            {
                let mut reg = self.hook_registry.borrow_mut();
                if let Some(ref mut arc_reg) = *reg {
                    let hook_reg = Arc::make_mut(arc_reg);
                    hook_reg.remove_by_prefix("plugin/");
                    hook_reg.append_specs(new_specs);
                } else if !new_specs.is_empty() {
                    // No registry yet: bootstrap config-layer and file hooks the way reload_hooks_impl does
                    // Starting from empty sources instead would let a plugin-first snapshot drop config hooks
                    let (mut new_reg, _errs) = Self::build_session_hook_registry(
                        session_cwd,
                        &self.rebuild_spec.compat,
                        None,
                        project_trusted,
                    );
                    new_reg.append_specs(new_specs);
                    *reg = Some(Arc::new(new_reg));
                }
            }
            self.publish_hook_registry();
        }

        fuigo_telemetry::unified_log::info(
            "reload_plugins_impl: hooks done",
            Some(sid),
            Some(serde_json::json!({
                "hooks_reload_ms": t_hooks.elapsed().as_millis() as u64,
                "hooks_reloaded": hooks_reloaded,
            })),
        );

        // Always re-merge plugin-contributed MCP servers and apply them via an order-insensitive diff
        // Unchanged servers stay connected; only added, changed, or removed ones are re-initialized
        // Merging unconditionally (no "plugins have MCP" guard) lets a removed plugin's server tear down cleanly
        // The diff keeps it a no-op when the effective set is unchanged
        // The order-sensitive `update_configs` would tear everything down instead, because merge order is non-deterministic
        // This mirrors the `UpdateMcpServers` command handler
        let t_mcp = std::time::Instant::now();
        let new_mcp_servers = crate::session::managed_mcp::merge_managed_mcp_servers(
            self.initial_client_mcp_servers.borrow().clone(),
            session_cwd,
            new_registry_snapshot.as_deref(),
            &self.rebuild_spec.compat,
        );
        let (mcp_diff, dispatch_event_tx) = {
            let mut mcp_state = self.mcp_state.lock().await;
            let diff = mcp_state.update_configs_diff(new_mcp_servers);
            let tx = mcp_state.client_event_tx();
            (diff, tx)
        };
        let mcp_changed = if let Some(diff) = mcp_diff {
            if (!diff.added.is_empty() || !diff.removed.is_empty())
                && let Some(tx) = &dispatch_event_tx
            {
                let _ = tx.send(fuigo_mcp::servers::McpClientEvent::ConfigDiff {
                    added: diff.added.clone(),
                    removed: diff.removed.clone(),
                });
            }
            for name in &diff.removed {
                let prefix = format!(
                    "{}{}",
                    name,
                    crate::session::mcp_servers::MCP_TOOL_NAME_DELIMITER
                );
                let removed_count = self
                    .agent
                    .borrow()
                    .tool_bridge()
                    .unregister_tools_by_prefix(&prefix);
                tracing::info!(
                    server = name.as_str(),
                    tools_removed = removed_count,
                    "Unregistered tools for removed MCP server (plugin reload)"
                );
            }
            self.ensure_mcp_tools_initialized().await;
            true
        } else {
            false
        };

        fuigo_telemetry::unified_log::info(
            "reload_plugins_impl: MCP done",
            Some(sid),
            Some(serde_json::json!({
                "mcp_merge_ms": t_mcp.elapsed().as_millis() as u64,
                "mcp_changed": mcp_changed,
            })),
        );

        // Refresh skills: re-scan from disk using the (already-updated) plugin registry.
        let t_skills = std::time::Instant::now();
        let skill_count = self.reload_skills_from_disk().await;
        fuigo_telemetry::unified_log::info(
            "reload_plugins_impl: skills done",
            Some(sid),
            Some(serde_json::json!({
                "skills_ms": t_skills.elapsed().as_millis() as u64,
                "skill_count": skill_count,
            })),
        );

        // Notify pager about registry changes so the modal auto-refreshes.
        // Extract all RefCell borrows into locals before the .await so no Ref guard is alive across the suspension point
        // Otherwise send_fuigo_notification's Notification hooks, which also borrow these RefCells, panic with BorrowMutError
        let t_notify = std::time::Instant::now();
        {
            let hooks = crate::extensions::hooks::current_hook_infos(
                self.hook_registry.borrow().as_deref(),
            );
            let load_errors = self.hook_load_errors.borrow().clone();
            // Report the folder-trust verdict so the flag matches the gated registry.
            let project_trusted = crate::agent::folder_trust::project_scope_allowed(
                std::path::Path::new(&self.session_info.cwd),
            );
            self.send_fuigo_notification(FuigoSessionUpdate::HooksChanged {
                hooks,
                project_trusted,
                load_errors,
            })
            .await;

            use crate::extensions::plugins::loaded_plugin_to_info;
            let plugins = {
                let reg = self.plugin_registry.borrow();
                match &*reg {
                    Some(registry) => registry
                        .list()
                        .iter()
                        .map(|p| loaded_plugin_to_info(p))
                        .collect(),
                    None => Vec::new(),
                }
            };
            self.send_fuigo_notification(FuigoSessionUpdate::PluginsChanged { plugins })
                .await;
        }

        fuigo_telemetry::unified_log::info(
            "apply_plugin_registry_snapshot: complete",
            Some(sid),
            Some(serde_json::json!({
                "notify_ms": t_notify.elapsed().as_millis() as u64,
                "hooks_reloaded": hooks_reloaded,
                "mcp_changed": mcp_changed,
                "skill_count": skill_count,
            })),
        );

        (hooks_reloaded, mcp_changed, skill_count)
    }
}

#[cfg(test)]
mod p07_plugin_hook_tests {
    use super::SessionActor;
    use fuigo_agent::plugins::SharedPluginRegistryHandle;
    use fuigo_agent::plugins::discovery::DiscoveryConfig;

    fn write_plugin(root: &std::path::Path, name: &str) {
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(
            root.join("plugin.json"),
            serde_json::json!({
                "name": name,
                "hooks": {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "true"}]}]}}
            })
            .to_string(),
        )
        .unwrap();
    }

    /// This test's plugins whose hooks are in `specs`; ambient plugins on the test host are ignored.
    fn plugin_names<'a>(
        specs: impl IntoIterator<Item = &'a fuigo_hooks::config::HookSpec>,
    ) -> Vec<String> {
        let mut names: Vec<String> = specs
            .into_iter()
            .filter_map(|s| s.name.strip_prefix("plugin/"))
            .filter_map(|rest| rest.split('/').next())
            .filter(|name| ["cligate", "projgate"].contains(name))
            .map(str::to_owned)
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// A plugin registry records the verdict current when it was BUILT; the hook builder must apply the CURRENT one.
    /// Built while trusted (as after `/hooks-trust`), the repo's plugin is active; after `/hooks-untrust` its hooks must not load,
    /// while a CLI-scope plugin (always trusted) is unaffected.
    #[test]
    fn project_plugin_hooks_follow_the_current_verdict_not_the_snapshot() {
        let repo = tempfile::tempdir().unwrap();
        git2::Repository::init(repo.path()).unwrap();
        write_plugin(&repo.path().join(".fuigo/plugins/projgate"), "projgate");
        let cli = tempfile::tempdir().unwrap();
        let cli_plugin = cli.path().join("cligate");
        write_plugin(&cli_plugin, "cligate");
        let cfg = DiscoveryConfig {
            enabled: vec!["projgate".to_string(), "cligate".to_string()],
            ..Default::default()
        };
        let handle = SharedPluginRegistryHandle::new(None, vec![]);
        let built_trusted = handle.build_for_cwd(repo.path(), &cfg, &[cli_plugin], true);
        let reg = built_trusted.as_deref();
        assert!(
            reg.is_some_and(|r| r.active_plugins().iter().any(|p| p.name == "projgate")),
            "fixture: the project plugin is active in a registry built while trusted"
        );

        assert_eq!(
            plugin_names(&SessionActor::plugin_hook_specs(reg, true)),
            vec!["cligate", "projgate"],
            "trusted: both plugins contribute their hooks"
        );
        assert_eq!(
            plugin_names(&SessionActor::plugin_hook_specs(reg, false)),
            vec!["cligate"],
            "untrusted now: the stale snapshot's project plugin must contribute nothing"
        );
    }

    /// Adopting a plugin snapshot built while the folder was trusted, after the folder was revoked (a fan-out racing `/hooks-untrust`):
    /// the session's plugin hooks follow the CURRENT verdict, so neither the repo's own plugin (`Project` scope) nor a plugin its config
    /// named in `[plugins].paths` (`ConfigPath` scope, auto-trusted under `$HOME`) is installed, and the handle-visible copy agrees.
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn adopting_a_stale_trusted_snapshot_installs_no_repo_plugin_hooks() {
        // Writes FUIGO_HOME / HOME, which every test in this binary reads: run in a process of its own
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        use fuigo_test_support::env::EnvGuard;
        let fuigo_home = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let _fh = EnvGuard::set("FUIGO_HOME", fuigo_home.path());
        let _h = EnvGuard::set("HOME", home.path());
        let _sim = EnvGuard::set(fuigo_version::TEST_VERSION_ENV, "0.0.0-p07-sim");
        let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
        let repo = tempfile::tempdir().unwrap();
        git2::Repository::init(repo.path()).unwrap();
        write_plugin(&repo.path().join(".fuigo/plugins/projgate"), "projgate");
        let cfg_plugin = home.path().join("cligate");
        write_plugin(&cfg_plugin, "cligate");
        let cfg = DiscoveryConfig {
            enabled: vec!["projgate".to_string(), "cligate".to_string()],
            config_paths: vec![cfg_plugin.clone()],
            ..Default::default()
        };
        let handle = SharedPluginRegistryHandle::new(None, vec![]);
        let stale = handle.build_for_cwd(repo.path(), &cfg, &[], true);
        assert_eq!(
            plugin_names(&SessionActor::plugin_hook_specs(stale.as_deref(), true)),
            vec!["cligate", "projgate"],
            "fixture: the snapshot built while trusted carries both repo-contributed plugins"
        );
        // The folder is untrusted now: configs present, no grant in the isolated store
        crate::agent::folder_trust::record_for_test(repo.path(), false);

        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let (gateway_tx, _gateway_rx) = tokio::sync::mpsc::unbounded_channel();
                let (persistence_tx, _persistence_rx) = tokio::sync::mpsc::unbounded_channel();
                let mut actor = crate::session::acp_session::support::create_test_actor(
                    0,
                    256_000,
                    85,
                    gateway_tx,
                    persistence_tx,
                )
                .await;
                actor.session_info.cwd = repo.path().display().to_string();
                actor.plugin_registry_handle = Some(handle.clone());
                *actor.hook_registry.borrow_mut() =
                    Some(std::sync::Arc::new(fuigo_hooks::discovery::HookRegistry::default()));
                let actor = std::sync::Arc::new(actor);
                let _ = actor.apply_plugin_registry_snapshot(stale).await;
                let installed = actor.hook_registry.borrow().clone().expect("registry");
                assert_eq!(
                    plugin_names(installed.all_hooks()),
                    Vec::<String>::new(),
                    "untrusted now: no repo-contributed plugin hook may be installed from the stale snapshot"
                );
                let published = actor.hook_registry_live.get().expect("published registry");
                assert_eq!(plugin_names(published.all_hooks()), Vec::<String>::new());
            })
            .await;
    }

    /// A session's first hook load after a revocation that raced its spawn: the spawn-built registry (trusted) is replaced by a
    /// rediscovery on the untrusted verdict, so a repo-config-path plugin's hooks are not installed; a trusted verdict keeps it as is.
    #[test]
    #[serial_test::serial]
    fn initial_hook_plugins_follow_an_untrusted_verdict_at_load() {
        // Writes FUIGO_HOME / HOME, which every test in this binary reads: run in a process of its own
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        use fuigo_test_support::env::EnvGuard;
        let fuigo_home = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let _fh = EnvGuard::set("FUIGO_HOME", fuigo_home.path());
        let _h = EnvGuard::set("HOME", home.path());
        let repo = tempfile::tempdir().unwrap();
        git2::Repository::init(repo.path()).unwrap();
        let cfg_plugin = home.path().join("cligate");
        write_plugin(&cfg_plugin, "cligate");
        let cfg = DiscoveryConfig {
            enabled: vec!["cligate".to_string()],
            config_paths: vec![cfg_plugin.clone()],
            ..Default::default()
        };
        let handle = SharedPluginRegistryHandle::new(None, vec![]);
        let built = handle.build_for_cwd(repo.path(), &cfg, &[], true);
        let names = |reg: Option<std::sync::Arc<fuigo_agent::plugins::PluginRegistry>>, trusted| {
            plugin_names(&SessionActor::plugin_hook_specs(reg.as_deref(), trusted))
        };
        assert_eq!(names(built.clone(), true), vec!["cligate"], "fixture");
        let kept = SessionActor::plugins_for_initial_hooks(
            Some(&handle),
            built.clone(),
            repo.path(),
            true,
        );
        assert_eq!(
            names(kept, true),
            vec!["cligate"],
            "trusted at load: the spawn-built set stands"
        );
        let redone =
            SessionActor::plugins_for_initial_hooks(Some(&handle), built, repo.path(), false);
        assert_eq!(
            names(redone, false),
            Vec::<String>::new(),
            "untrusted at load: the plugin admitted under the older verdict must not contribute hooks"
        );
    }

    /// The primary-session spawn override, built while trusted, loads after a revocation raced the spawn: its plugin hooks are
    /// replaced by the rediscovery on the untrusted verdict, its other hooks (the agent's own) are kept, and a trusted verdict keeps it all.
    #[test]
    #[serial_test::serial]
    fn a_trusted_override_loses_repo_plugin_hooks_under_an_untrusted_verdict() {
        // Writes FUIGO_HOME / HOME, which every test in this binary reads: run in a process of its own
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        use fuigo_test_support::env::EnvGuard;
        let fuigo_home = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let _fh = EnvGuard::set("FUIGO_HOME", fuigo_home.path());
        let _h = EnvGuard::set("HOME", home.path());
        let repo = tempfile::tempdir().unwrap();
        git2::Repository::init(repo.path()).unwrap();
        let cfg_plugin = home.path().join("cligate");
        write_plugin(&cfg_plugin, "cligate");
        let cfg = DiscoveryConfig {
            enabled: vec!["cligate".to_string()],
            config_paths: vec![cfg_plugin.clone()],
            ..Default::default()
        };
        let handle = SharedPluginRegistryHandle::new(None, vec![]);
        let built = handle.build_for_cwd(repo.path(), &cfg, &[], true);
        let mut reg = fuigo_hooks::discovery::HookRegistry::default();
        reg.append_specs(SessionActor::plugin_hook_specs(built.as_deref(), true));
        let (agent_specs, _) = fuigo_hooks::config::parse_hooks_from_value_with_dir(
            &serde_json::json!({"PreToolUse": [{"hooks": [{"type": "command", "command": "true"}]}]}),
            "agent:probe",
            repo.path(),
        );
        assert!(!agent_specs.is_empty(), "fixture: an agent hook");
        reg.append_specs(agent_specs);
        let reg = std::sync::Arc::new(reg);
        let total = reg.all_hooks().len();
        assert_eq!(plugin_names(reg.all_hooks()), vec!["cligate"], "fixture");

        let kept = SessionActor::revalidate_override_plugin_hooks(
            reg.clone(),
            Some(&handle),
            built.clone(),
            repo.path(),
            true,
        );
        assert_eq!(
            kept.all_hooks().len(),
            total,
            "trusted at load: the override stands"
        );
        let redone = SessionActor::revalidate_override_plugin_hooks(
            reg,
            Some(&handle),
            built,
            repo.path(),
            false,
        );
        assert_eq!(
            plugin_names(redone.all_hooks()),
            Vec::<String>::new(),
            "untrusted at load: the repo-config-path plugin's hook must go"
        );
        assert_eq!(
            redone.all_hooks().len(),
            total - 1,
            "the agent's own hook stays"
        );
    }

    /// An agent definition's inline hooks: admitted for a built-in agent, refused for a plugin's agent in any session.
    #[test]
    fn agent_inline_hooks_are_refused_for_plugin_agents() {
        let dir = tempfile::tempdir().unwrap();
        let mut def = fuigo_agent::AgentDefinition::from_json(&serde_json::json!({
            "name": "probe-agent",
            "description": "probe",
            "hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "true"}]}]}
        }))
        .unwrap();
        assert_eq!(
            SessionActor::agent_inline_hook_specs(&def, dir.path(), false, false).len(),
            1,
            "a built-in agent's own hook is admitted"
        );
        def.plugin_name = Some("someplugin".to_string());
        for is_subagent in [false, true] {
            assert!(
                SessionActor::agent_inline_hook_specs(&def, dir.path(), true, is_subagent)
                    .is_empty(),
                "a plugin agent's inline hooks are never admitted (subagent={is_subagent})"
            );
        }
    }

    /// F1: a reload in a session without a plugin registry handle (every subagent) installs no plugin hooks from its stored
    /// registry - for a subagent that is the process-wide snapshot - and a subagent's reload installs none even with a handle.
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn a_reload_without_a_session_plugin_view_installs_no_plugin_hooks() {
        // Writes FUIGO_HOME / HOME, which every test in this binary reads: run in a process of its own
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        use fuigo_test_support::env::EnvGuard;
        let fuigo_home = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let _fh = EnvGuard::set("FUIGO_HOME", fuigo_home.path());
        let _h = EnvGuard::set("HOME", home.path());
        let repo = tempfile::tempdir().unwrap();
        git2::Repository::init(repo.path()).unwrap();
        let cli = tempfile::tempdir().unwrap();
        let cli_plugin = cli.path().join("cligate");
        write_plugin(&cli_plugin, "cligate");
        let cfg = DiscoveryConfig {
            enabled: vec!["cligate".to_string()],
            ..Default::default()
        };
        let handle = SharedPluginRegistryHandle::new(None, vec![]);
        let process_snapshot = handle.build_for_cwd(repo.path(), &cfg, &[cli_plugin], true);
        assert_eq!(
            plugin_names(&SessionActor::plugin_hook_specs(
                process_snapshot.as_deref(),
                true
            )),
            vec!["cligate"],
            "fixture: the stored registry carries a plugin with a hook"
        );
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                for (is_subagent, with_handle) in [(false, false), (true, true)] {
                    let (gateway_tx, _gateway_rx) = tokio::sync::mpsc::unbounded_channel();
                    let (persistence_tx, _persistence_rx) = tokio::sync::mpsc::unbounded_channel();
                    let mut actor = crate::session::acp_session::support::create_test_actor(
                        0,
                        256_000,
                        85,
                        gateway_tx,
                        persistence_tx,
                    )
                    .await;
                    actor.session_info.cwd = repo.path().display().to_string();
                    actor.startup_hints.is_subagent = is_subagent;
                    *actor.plugin_registry.borrow_mut() = process_snapshot.clone();
                    actor.plugin_registry_handle = with_handle.then(|| handle.clone());
                    let actor = std::sync::Arc::new(actor);
                    let _ = actor.reload_hooks_impl().await;
                    let names = actor
                        .hook_registry
                        .borrow()
                        .as_ref()
                        .map(|r| plugin_names(r.all_hooks()))
                        .unwrap_or_default();
                    assert_eq!(
                        names,
                        Vec::<String>::new(),
                        "subagent={is_subagent} handle={with_handle}: no plugin hook from the stored registry"
                    );
                }
            })
            .await;
    }

    /// The session builder is the initial load: plugin hooks sit beside the disk hooks from the start.
    #[test]
    fn build_session_hook_registry_includes_plugin_hooks() {
        let repo = tempfile::tempdir().unwrap();
        git2::Repository::init(repo.path()).unwrap();
        let cli = tempfile::tempdir().unwrap();
        let cli_plugin = cli.path().join("cligate");
        write_plugin(&cli_plugin, "cligate");
        let cfg = DiscoveryConfig {
            enabled: vec!["cligate".to_string()],
            ..Default::default()
        };
        let handle = SharedPluginRegistryHandle::new(None, vec![]);
        let plugins = handle.build_for_cwd(repo.path(), &cfg, &[cli_plugin], false);
        let (registry, _errors) = SessionActor::build_session_hook_registry(
            repo.path(),
            &fuigo_tools::types::compat::CompatConfig::default(),
            plugins.as_deref(),
            false,
        );
        assert_eq!(plugin_names(registry.all_hooks()), vec!["cligate"]);
    }
}

#[cfg(test)]
#[path = "hooks_plugins_p141_tests.rs"]
mod p141_tests;
