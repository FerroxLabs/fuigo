//! Searches `.fuigo/agents/` and `.claude/agents/` from cwd to repo root (only in a folder the installed trust hook
//! trusts), then `~/.fuigo/agents/`, then `~/.claude/agents/`. Name-based dedup keeps highest priority.
//!
//! No agent file of any scope replaces a built-in agent: a file whose stem or frontmatter `name` is a built-in name is
//! skipped everywhere, and an agent name must be a single plain name (see [`is_valid_agent_name`]).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use fuigo_tools::implementations::skills::discovery::{SkillWalk, scan_md_files_in};
use fuigo_tools::types::config_source::ConfigSource;

use crate::config::{AgentDefinition, AgentScope, BuiltinAgentName};
use crate::error::AgentBuildError;
use crate::prompt::context::TemplateOverride;

/// Project-level agent directories to scan (`.fuigo/agents/` plus `.claude/agents/` for compat).
const PROJECT_AGENT_SUBDIRS: &[&str] = &[".fuigo/agents", ".claude/agents"];

/// Existing project-level agent dirs (`.fuigo/agents` / `.claude/agents`), walked from `cwd` up to the git worktree root (inclusive).
/// Returns `(existing dirs, git_root)`.
/// Mirrors [`crate::plugins::project_plugin_dirs`].
pub fn project_agent_dirs(cwd: Option<&Path>) -> (Vec<PathBuf>, Option<PathBuf>) {
    let Some(cwd) = cwd else {
        return (Vec::new(), None);
    };
    let chain = crate::repo::RepoDirChain::resolve(cwd);
    (project_agent_dirs_in(&chain.dirs), chain.git_root)
}

/// Existing project agent dirs (`.fuigo/agents` / `.claude/agents`) under each dir of a cwd-to-git-root chain ([`crate::repo::RepoDirChain`]).
///
/// This is the only place that walks `PROJECT_AGENT_SUBDIRS`.
/// The folder-trust detector (`repo_configs_present`) reuses it, so trust detection can never drift from discovery.
pub fn project_agent_dirs_in(chain_dirs: &[PathBuf]) -> Vec<PathBuf> {
    crate::repo::existing_subdirs_along(chain_dirs, PROJECT_AGENT_SUBDIRS)
}

// ── Project-agent trust hook and name validation ─────────────────────

/// The folder-trust verdict for project agent files, installed once by the host (fuigo-shell's `project_scope_allowed`).
/// fuigo-agent cannot depend on the crate that owns the trust store, so the host hands the check in.
static PROJECT_AGENT_TRUST: std::sync::OnceLock<fn(&Path) -> bool> = std::sync::OnceLock::new();

/// Install the folder-trust check for project agent files (`.fuigo/agents`, `.claude/agents`).
///
/// Set-once: a second call with the same function is a no-op, and a different function is ignored with an error, so
/// trust can never be swapped after install. Until a hook is installed, project agent files never load (fail closed).
pub fn install_project_agent_trust(f: fn(&Path) -> bool) {
    if let Err(rejected) = PROJECT_AGENT_TRUST.set(f)
        && let Some(installed) = PROJECT_AGENT_TRUST.get().copied()
        && !std::ptr::fn_addr_eq(installed, rejected)
    {
        tracing::error!("project agent trust hook already installed; ignoring a different hook");
    }
}

/// Whether project agent files under `cwd` may load: only when the installed hook trusts the folder.
/// No project agent dir along the walk means there is nothing to gate, so the hook is not consulted.
fn project_agents_trusted(cwd: &Path) -> bool {
    if project_agent_dirs(Some(cwd)).0.is_empty() {
        return false;
    }
    PROJECT_AGENT_TRUST.get().is_some_and(|trusted| trusted(cwd))
}

/// Whether `name` is a single plain agent name that can be joined onto an agents directory.
///
/// Rejects the empty name, `.` and `..`, any `/`, `\`, `:` or NUL, and anything `Path` does not read as exactly one
/// normal component (absolute paths and every Windows prefix: `C:x`, `\\?\..`, `\\server\share`).
pub fn is_valid_agent_name(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." {
        return false;
    }
    if name.contains(['/', '\\', ':', '\0']) {
        return false;
    }
    let mut components = Path::new(name).components();
    matches!(
        (components.next(), components.next()),
        (Some(std::path::Component::Normal(c)), None) if c == std::ffi::OsStr::new(name)
    )
}

/// `<dir>/<name>.md`, or `None` for a name that is not a single plain name: the one place a caller-supplied agent name
/// is joined onto a directory.
fn agent_file(dir: &Path, name: &str) -> Option<PathBuf> {
    is_valid_agent_name(name).then(|| dir.join(format!("{name}.md")))
}

fn warn_rejected_agent_name(name: &str) {
    tracing::warn!(agent_name = ?name, "rejected agent name");
}

/// Whether `name` is one of the built-in agent names (all [`BuiltinAgentName`] variants).
fn is_builtin(name: &str) -> bool {
    BuiltinAgentName::from_str(name).is_ok()
}

/// Whether an agent file must be skipped because its stem or its parsed frontmatter `name` is a built-in name.
/// Such a file could never be called (the built-in always wins), so it is neither returned nor listed.
fn names_a_builtin(path: &Path, def: Option<&AgentDefinition>) -> bool {
    path.file_stem()
        .and_then(|s| s.to_str())
        .is_some_and(is_builtin)
        || def.is_some_and(|d| is_builtin(&d.name))
}

// ── Subagent entry types ─────────────────────────────────────────────

/// A subagent entry for the Task tool description and spawn-time validation.
#[derive(Debug, Clone)]
pub struct SubagentEntry {
    pub name: String,
    pub description: String,
    pub source: SubagentSource,
    /// If this entry shadows a built-in, which one.
    pub shadows_builtin: Option<BuiltinAgentName>,
    pub config_source: ConfigSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubagentSource {
    /// One of the 3 built-in subagent types, not shadowed by a user agent.
    Builtin(BuiltinAgentName),
    /// User-defined agent from project, user, or bundled discovery.
    UserDefined { scope: AgentScope },
}

// ── all_subagents ────────────────────────────────────────────────────

/// Build the complete list of enabled subagents: built-ins, then discovered user agents, minus any toggled off via `[subagents.toggle]`.
///
/// No discovered agent of any scope shadows a built-in: one with a built-in name is skipped, keeping `visible == callable`.
pub fn all_subagents(cwd: &Path, toggle: &HashMap<String, bool>) -> Vec<SubagentEntry> {
    let fuigo = fuigo_config::user_fuigo_home();
    all_subagents_with_home(
        cwd,
        toggle,
        fuigo_dirs::home_dir().as_deref(),
        fuigo.as_deref(),
        project_agents_trusted(cwd),
    )
}

fn all_subagents_with_home(
    cwd: &Path,
    toggle: &HashMap<String, bool>,
    home: Option<&Path>,
    fuigo_home: Option<&Path>,
    project_trusted: bool,
) -> Vec<SubagentEntry> {
    let discovered = discover_with_home(cwd, home, fuigo_home, project_trusted);
    merge_subagents(discovered, toggle)
}

/// Internal: merge discovered agents with built-in subagents, apply toggles.
///
/// Separated from `all_subagents()` for testability without filesystem access.
fn merge_subagents(
    discovered: Vec<AgentDefinition>,
    toggle: &HashMap<String, bool>,
) -> Vec<SubagentEntry> {
    fn discovered_scope_priority(scope: AgentScope) -> usize {
        match scope {
            AgentScope::Project => 3,
            AgentScope::User => 2,
            AgentScope::Bundled => 1,
            AgentScope::BuiltIn => 0,
        }
    }

    // 1. Seed with built-in subagents
    let mut entries: Vec<SubagentEntry> = BuiltinAgentName::subagent_variants()
        .iter()
        .map(|b| {
            let def = b.definition();
            SubagentEntry {
                name: def.name,
                description: def.description,
                source: SubagentSource::Builtin(*b),
                shadows_builtin: None,
                config_source: ConfigSource::Builtin,
            }
        })
        .collect();

    // 2. Merge in discovered user-defined agents.
    //
    // No file of any scope shadows a built-in at lookup (`by_name_in_cwd()` returns the built-in first), so none may
    // shadow it in the visible list either; otherwise the `visible == callable` guarantee breaks.
    // Discovery already skips built-in-named files; this keeps the guarantee for any caller-built list.
    for def in discovered {
        if def.scope == AgentScope::BuiltIn || is_builtin(&def.name) {
            continue;
        }

        if let Some(pos) = entries.iter().position(|e| e.name == def.name) {
            let should_replace = match &entries[pos].source {
                SubagentSource::Builtin(_) => true,
                SubagentSource::UserDefined { scope } => {
                    discovered_scope_priority(def.scope) > discovered_scope_priority(*scope)
                }
            };
            if should_replace {
                let cs = source_from_agent_def(&def);
                entries[pos] = SubagentEntry {
                    name: def.name,
                    description: def.description,
                    source: SubagentSource::UserDefined { scope: def.scope },
                    shadows_builtin: None,
                    config_source: cs,
                };
            }
        } else {
            // This name is new, so append it after the built-ins
            let cs = source_from_agent_def(&def);
            entries.push(SubagentEntry {
                name: def.name,
                description: def.description,
                source: SubagentSource::UserDefined { scope: def.scope },
                shadows_builtin: None,
                config_source: cs,
            });
        }
    }

    // 3. Filter by toggle (omitted means enabled)
    entries
        .into_iter()
        .filter(|e| toggle.get(&e.name).copied().unwrap_or(true))
        .collect()
}

/// Discover all agent definitions from the filesystem.
///
/// Search order (highest priority first):
/// 1. `.fuigo/agents/` walking from `cwd` up to repo root
/// 2. `~/.fuigo/agents/` (user-level)
/// 3. `~/.claude/agents/` (compat user-level)
/// 4. `~/.fuigo/bundled/agents/` (bundled, lowest priority)
///
/// Deduplicates by name; higher-priority definitions win.
/// User-level agent directories in priority order: user fuigo agents, `.claude`
/// compat agents, then bundled. `.fuigo` dirs resolve from `fuigo_home`
/// (FUIGO_HOME-aware) plus the legacy literal `~/.fuigo` when FUIGO_HOME points
/// elsewhere; `.claude` resolves from `home`.
pub(crate) fn user_agent_dirs(
    home: Option<&Path>,
    fuigo_home: Option<&Path>,
) -> Vec<(std::path::PathBuf, AgentScope)> {
    // Legacy literal ~/.fuigo, included only when it differs from fuigo_home
    // (i.e. FUIGO_HOME points elsewhere) so agents left in the old location are
    // still discovered and stay consistent with scope_from_path classification.
    let legacy_fuigo = home
        .map(|h| h.join(".fuigo"))
        .filter(|legacy| fuigo_home != Some(legacy.as_path()));

    let mut dirs = Vec::new();
    if let Some(g) = fuigo_home {
        dirs.push((g.join("agents"), AgentScope::User));
    }
    if let Some(l) = &legacy_fuigo {
        dirs.push((l.join("agents"), AgentScope::User));
    }
    if let Some(h) = home {
        dirs.push((h.join(".claude").join("agents"), AgentScope::User));
    }
    if let Some(g) = fuigo_home {
        dirs.push((g.join("bundled").join("agents"), AgentScope::Bundled));
    }
    if let Some(l) = &legacy_fuigo {
        dirs.push((l.join("bundled").join("agents"), AgentScope::Bundled));
    }
    dirs
}

pub fn discover(cwd: &Path) -> Vec<AgentDefinition> {
    let fuigo = fuigo_config::user_fuigo_home();
    discover_with_home(
        cwd,
        fuigo_dirs::home_dir().as_deref(),
        fuigo.as_deref(),
        project_agents_trusted(cwd),
    )
}

fn discover_with_home(
    cwd: &Path,
    home: Option<&Path>,
    fuigo_home: Option<&Path>,
    project_trusted: bool,
) -> Vec<AgentDefinition> {
    let mut definitions = Vec::new();
    let mut seen_names = std::collections::HashSet::new();

    load_project_definitions(cwd, project_trusted, &mut definitions, &mut seen_names);

    for (dir, scope) in user_agent_dirs(home, fuigo_home) {
        if dir.is_dir() {
            load_definitions_from_dir(
                &dir,
                scope,
                &mut definitions,
                &mut seen_names,
                &mut SkillWalk::follow_links(),
            );
        }
    }

    definitions
}

/// Checks built-ins first, then user-level dirs, then bundled.
pub fn by_name(name: &str) -> Option<AgentDefinition> {
    let fuigo = fuigo_config::user_fuigo_home();
    by_name_with_home(name, fuigo_dirs::home_dir().as_deref(), fuigo.as_deref())
}

fn by_name_with_home(
    name: &str,
    home: Option<&Path>,
    fuigo_home: Option<&Path>,
) -> Option<AgentDefinition> {
    if !is_valid_agent_name(name) {
        warn_rejected_agent_name(name);
        return None;
    }
    if let Ok(builtin) = BuiltinAgentName::from_str(name) {
        return Some(builtin.definition());
    }

    for (agents_dir, scope) in user_agent_dirs(home, fuigo_home) {
        // A file whose frontmatter names a built-in could never be called by that name; it is not returned by its stem.
        if let Some(def) = load_definition_by_name(
            &agents_dir,
            name,
            "Failed to parse agent definition",
            Some(scope),
        ) && !is_builtin(&def.name)
        {
            return Some(def);
        }
    }

    None
}

/// Built-ins first, then project-level `.fuigo/agents/` (only in a trusted folder), then user-level, and finally bundled
/// definitions. No file of any scope shadows a built-in name.
pub fn by_name_in_cwd(name: &str, cwd: &Path) -> Option<AgentDefinition> {
    let fuigo = fuigo_config::user_fuigo_home();
    by_name_in_cwd_with_home(
        name,
        cwd,
        fuigo_dirs::home_dir().as_deref(),
        fuigo.as_deref(),
        project_agents_trusted(cwd),
    )
}

fn by_name_in_cwd_with_home(
    name: &str,
    cwd: &Path,
    home: Option<&Path>,
    fuigo_home: Option<&Path>,
    project_trusted: bool,
) -> Option<AgentDefinition> {
    if !is_valid_agent_name(name) {
        warn_rejected_agent_name(name);
        return None;
    }
    if let Some(def) = load_project_definition_by_name(name, cwd, project_trusted) {
        return Some(def);
    }

    by_name_with_home(name, home, fuigo_home)
}

/// These are the pre-defined agent profiles (`general-purpose`, `explore`, `plan`) that the Task tool can launch.
/// No agent file of any scope shadows these by name.
pub fn builtin_subagents() -> Vec<AgentDefinition> {
    BuiltinAgentName::subagent_variants()
        .iter()
        .map(|name| name.definition())
        .collect()
}

/// Return every built-in agent definition (all `BuiltinAgentName` variants, not just the subagent-launchable subset in [`builtin_subagents`]).
///
/// For cross-crate coverage and manifest checks: those crates pin a different `strum`, so they cannot call `BuiltinAgentName::iter()` themselves.
pub fn all_builtin_agent_definitions() -> Vec<AgentDefinition> {
    use strum::IntoEnumIterator;
    BuiltinAgentName::iter()
        .map(BuiltinAgentName::definition)
        .collect()
}

/// Parse only YAML frontmatter from an agent file, without loading the body.
pub fn parse_agent_frontmatter_only(path: &Path) -> Result<AgentDefinition, AgentBuildError> {
    AgentDefinition::from_file_frontmatter_only(path)
}

fn source_from_agent_def(def: &AgentDefinition) -> ConfigSource {
    let path = def.source_path.clone().unwrap_or_default();
    if let Some(ref pn) = def.plugin_name {
        ConfigSource::Plugin {
            plugin_name: pn.clone(),
            path,
        }
    } else {
        match def.scope {
            AgentScope::Project => ConfigSource::Project { path },
            AgentScope::User => ConfigSource::User { path },
            AgentScope::Bundled | AgentScope::BuiltIn => ConfigSource::Builtin,
        }
    }
}

// ── Plugin-aware variants ─────────────────────────────────────────────

/// One plugin-provided agent, addressable by its qualified `plugin:agent` name.
#[derive(Debug)]
pub struct PluginAgent {
    /// Qualified `plugin-name:agent-name` used to spawn (and toggle) the agent.
    pub qualified_name: String,
    /// Owning plugin's scope mapped to the agent scope model (project or user).
    pub scope: AgentScope,
    /// Parsed definition (`plugin_name` is set; `name` stays unqualified).
    pub definition: AgentDefinition,
}

/// Enumerate all agents provided by enabled plugins.
///
/// Loads every `*.md` in each enabled plugin's agent dirs.
/// Untrusted plugins are parsed frontmatter-only (see [`load_plugin_agent_definition`]).
pub fn plugin_agents(registry: &crate::plugins::PluginRegistry) -> Vec<PluginAgent> {
    plugin_agents_from(registry.enabled_plugins())
}

/// Agents of enabled AND trusted plugins: the only plugin agents a session can call.
fn callable_plugin_agents(registry: &crate::plugins::PluginRegistry) -> Vec<PluginAgent> {
    plugin_agents_from(registry.active_plugins())
}

fn plugin_agents_from(plugins: Vec<&crate::plugins::LoadedPlugin>) -> Vec<PluginAgent> {
    let mut agents = Vec::new();
    for plugin in plugins {
        // Contained: an agent dir or file linking outside the plugin folder is skipped (counted in `skipped_links`).
        let mut walk = SkillWalk::contained_pinned(plugin.pinned_root());
        for agent_dir in &plugin.agent_dirs {
            for path in scan_md_files_in(agent_dir, &mut walk) {
                let Some(def) = load_plugin_agent_definition(plugin, &path) else {
                    continue;
                };
                let scope = match plugin.scope {
                    crate::plugins::PluginScope::Project => AgentScope::Project,
                    _ => AgentScope::User,
                };
                agents.push(PluginAgent {
                    qualified_name: format!("{}:{}", plugin.name, def.name),
                    scope,
                    definition: def,
                });
            }
        }
    }
    agents
}

/// Build the complete list of enabled subagents, including plugin agents.
pub fn all_subagents_with_plugins(
    cwd: &Path,
    toggle: &HashMap<String, bool>,
    plugins: Option<&crate::plugins::PluginRegistry>,
) -> Vec<SubagentEntry> {
    let fuigo = fuigo_config::user_fuigo_home();
    all_subagents_with_plugins_and_home(
        cwd,
        toggle,
        plugins,
        fuigo_dirs::home_dir().as_deref(),
        fuigo.as_deref(),
        project_agents_trusted(cwd),
    )
}

fn all_subagents_with_plugins_and_home(
    cwd: &Path,
    toggle: &HashMap<String, bool>,
    plugins: Option<&crate::plugins::PluginRegistry>,
    home: Option<&Path>,
    fuigo_home: Option<&Path>,
    project_trusted: bool,
) -> Vec<SubagentEntry> {
    let discovered = discover_with_home(cwd, home, fuigo_home, project_trusted);
    let mut entries = merge_subagents(discovered, toggle);

    // Append plugin agents under qualified names
    if let Some(registry) = plugins {
        // Visible == callable: only trusted plugins' agents are offered (see `by_name_in_cwd_with_plugins`).
        for agent in callable_plugin_agents(registry) {
            // Skip if a native entry already has this qualified name
            if entries.iter().any(|e| e.name == agent.qualified_name) {
                continue;
            }

            // Toggles key on the qualified name (same name the list shows).
            if !toggle.get(&agent.qualified_name).copied().unwrap_or(true) {
                continue;
            }

            let config_source = ConfigSource::Plugin {
                plugin_name: agent.definition.plugin_name.clone().unwrap_or_default(),
                path: agent.definition.source_path.clone().unwrap_or_default(),
            };
            entries.push(SubagentEntry {
                name: agent.qualified_name,
                description: agent.definition.description,
                source: SubagentSource::UserDefined { scope: agent.scope },
                shadows_builtin: None,
                config_source,
            });
        }
    }

    entries
}

/// Checks project-level, built-ins, user-level, bundled, then plugin agents.
/// For plugin agents, the name can be qualified (e.g. `my-plugin:reviewer`).
pub fn by_name_in_cwd_with_plugins(
    name: &str,
    cwd: &Path,
    plugins: Option<&crate::plugins::PluginRegistry>,
) -> Option<AgentDefinition> {
    let fuigo = fuigo_config::user_fuigo_home();
    by_name_in_cwd_with_plugins_and_home(
        name,
        cwd,
        plugins,
        fuigo_dirs::home_dir().as_deref(),
        fuigo.as_deref(),
        project_agents_trusted(cwd),
    )
}

fn by_name_in_cwd_with_plugins_and_home(
    name: &str,
    cwd: &Path,
    plugins: Option<&crate::plugins::PluginRegistry>,
    home: Option<&Path>,
    fuigo_home: Option<&Path>,
    project_trusted: bool,
) -> Option<AgentDefinition> {
    let bare_valid = is_valid_agent_name(name);
    let qualified = name.split_once(':');
    if !bare_valid && qualified.is_none() {
        warn_rejected_agent_name(name);
        return None;
    }
    // First try native resolution (built-in > project > user > bundled); a qualified name is never a native name.
    if bare_valid
        && let Some(def) = by_name_in_cwd_with_home(name, cwd, home, fuigo_home, project_trusted)
    {
        return Some(def);
    }

    if plugins.is_none() && qualified.is_some() {
        tracing::debug!(agent_name = name, "qualified plugin agent name with no plugin registry");
    }
    // Try plugin agents
    if let Some(registry) = plugins {
        // Check if name is qualified (plugin-name:agent-name); both halves must be plain names.
        if let Some((plugin_name, agent_name)) = qualified {
            if !(is_valid_agent_name(plugin_name) && is_valid_agent_name(agent_name)) {
                warn_rejected_agent_name(name);
                return None;
            }
            // Callable only when the plugin is enabled AND trusted: an untrusted plugin's frontmatter still carries
            // `promptMode` / `userMessageTemplate` and must never reach a harness. Listing stays in `plugin_agents`.
            match registry.get(plugin_name) {
                Some(plugin) if plugin.enabled && plugin.trusted => {
                    for agent_dir in &plugin.agent_dirs {
                        if let Some(agent_file) = agent_file(agent_dir, agent_name)
                            && agent_file.is_file()
                            && let Some(mut def) = load_plugin_agent_definition(plugin, &agent_file)
                        {
                            substitute_plugin_vars(&mut def, plugin);
                            return Some(def);
                        }
                    }
                }
                Some(plugin) if plugin.enabled => {
                    tracing::warn!(
                        plugin = %plugin.name,
                        agent_name,
                        "plugin agent not callable: the plugin is not trusted"
                    );
                }
                _ => {}
            }
        }
        if !bare_valid {
            return None;
        }

        // Bare name lookup: only resolve if exactly one enabled and trusted plugin has this agent.
        let mut matches: Vec<(&crate::plugins::registry::LoadedPlugin, std::path::PathBuf)> =
            Vec::new();
        for plugin in registry.active_plugins() {
            for agent_dir in &plugin.agent_dirs {
                if let Some(agent_file) = agent_file(agent_dir, name)
                    && agent_file.is_file()
                    && inside_plugin(plugin, &agent_file)
                {
                    matches.push((plugin, agent_file));
                }
            }
        }
        if matches.len() == 1 {
            let (plugin, agent_file) = &matches[0];
            if let Some(mut def) = load_plugin_agent_definition(plugin, agent_file) {
                substitute_plugin_vars(&mut def, plugin);
                return Some(def);
            }
        } else if matches.len() > 1 {
            let plugin_names: Vec<&str> = matches.iter().map(|(p, _)| p.name.as_str()).collect();
            tracing::warn!(
                agent_name = name,
                plugins = ?plugin_names,
                "ambiguous bare agent name matches multiple plugins; use qualified name (plugin:agent)"
            );
        }
    }

    None
}

/// Load one plugin-provided agent file, tagged with its owning plugin.
///
/// Untrusted plugins are parsed frontmatter-only so their prompt body never reaches the model before the plugin is trusted.
/// A parse failure drops the agent from discovery entirely, so it is logged rather than swallowed.
fn load_plugin_agent_definition(
    plugin: &crate::plugins::LoadedPlugin,
    path: &Path,
) -> Option<AgentDefinition> {
    if !inside_plugin(plugin, path) {
        return None;
    }
    // The read itself is held to the plugin folder too: a link swapped in after the check above is refused here.
    let root = plugin.pinned_root();
    let loaded = if plugin.trusted {
        AgentDefinition::from_file_in(path, Some(&root))
    } else {
        AgentDefinition::from_file_frontmatter_only_in(path, Some(&root))
    };
    match loaded {
        Ok(mut def) => {
            def.plugin_name = Some(plugin.name.clone());
            Some(def)
        }
        Err(e) => {
            tracing::warn!(
                plugin = %plugin.name,
                path = %path.display(),
                error = %e,
                "Failed to parse plugin agent definition, skipping"
            );
            None
        }
    }
}

/// Whether a plugin agent file (and every link on its way) resolves inside the plugin folder.
fn inside_plugin(plugin: &crate::plugins::LoadedPlugin, path: &Path) -> bool {
    SkillWalk::contained_pinned(plugin.pinned_root()).admit(path)
}

/// The folder a project agents dir (`<dir>/.fuigo/agents`, `<dir>/.claude/agents`) belongs to: project agent files
/// must resolve inside it. User agent dirs follow links (user authority).
fn project_root_of_agents_dir(agents_dir: &Path) -> &Path {
    agents_dir
        .parent()
        .and_then(Path::parent)
        .unwrap_or(agents_dir)
}

/// Expand `${CLAUDE_PLUGIN_ROOT}` / `${CLAUDE_PLUGIN_DATA}` (and the Fuigo aliases) in a plugin agent's body so the model receives absolute paths.
fn substitute_plugin_vars(def: &mut AgentDefinition, plugin: &crate::plugins::LoadedPlugin) {
    // Untrusted plugins are loaded frontmatter-only (body is None), and most agents use a built-in system prompt
    // Skip computing root/data paths when there is nothing to expand
    let has_custom_prompt = matches!(def.system_prompt, TemplateOverride::Custom(_));
    if def.prompt_body.is_none() && !has_custom_prompt {
        return;
    }
    let (root, data) = (plugin.root_str(), plugin.data_dir_str());
    if let Some(body) = def.prompt_body.take() {
        def.prompt_body = Some(crate::plugins::manifest::substitute_env_vars(
            &body, &root, &data,
        ));
    }
    if let TemplateOverride::Custom(tpl) = &def.system_prompt {
        def.system_prompt = TemplateOverride::Custom(
            crate::plugins::manifest::substitute_env_vars(tpl, &root, &data),
        );
    }
}

/// Load project agent definitions from every `.fuigo/agents` / `.claude/agents` dir that [`project_agent_dirs`] finds along the cwd-to-git-root walk.
/// Loads nothing unless the folder is trusted.
fn load_project_definitions(
    cwd: &Path,
    trusted: bool,
    definitions: &mut Vec<AgentDefinition>,
    seen_names: &mut std::collections::HashSet<String>,
) {
    if !trusted {
        return;
    }
    for agents_dir in project_agent_dirs(Some(cwd)).0 {
        let mut walk = SkillWalk::contained(project_root_of_agents_dir(&agents_dir));
        load_definitions_from_dir(
            &agents_dir,
            AgentScope::Project,
            definitions,
            seen_names,
            &mut walk,
        );
    }
}

/// First project agent named `name` along the cwd-to-git-root walk from [`project_agent_dirs`], highest-priority dir first.
/// Nothing unless the folder is trusted, and never for a built-in name: not by stem (checked before any file is opened)
/// and not by the parsed frontmatter `name`.
fn load_project_definition_by_name(name: &str, cwd: &Path, trusted: bool) -> Option<AgentDefinition> {
    if !trusted || is_builtin(name) {
        return None;
    }
    for agents_dir in project_agent_dirs(Some(cwd)).0 {
        let agent_file = agent_file(&agents_dir, name)?;
        // The project folder is pinned once; the admission check and the read both compare against it.
        let Ok(project_root) = fuigo_dirs::contained::PinnedRoot::pin(project_root_of_agents_dir(&agents_dir))
        else {
            continue;
        };
        if !SkillWalk::contained_pinned(project_root.clone()).admit(&agent_file) {
            continue;
        }
        if let Some(def) = load_definition_from_path(
            &agent_file,
            name,
            "Failed to parse project agent definition",
            Some(AgentScope::Project),
            Some(&project_root),
        ) && !is_builtin(&def.name)
        {
            return Some(def);
        }
    }
    None
}

fn load_definition_by_name(
    dir: &Path,
    name: &str,
    error_message: &str,
    scope_override: Option<AgentScope>,
) -> Option<AgentDefinition> {
    let agent_file = agent_file(dir, name)?;
    load_definition_from_path(&agent_file, name, error_message, scope_override, None)
}

/// `root`: the folder the read must stay inside (project agents), `None` for user scope.
fn load_definition_from_path(
    agent_file: &Path,
    name: &str,
    error_message: &str,
    scope_override: Option<AgentScope>,
    root: Option<&fuigo_dirs::contained::PinnedRoot>,
) -> Option<AgentDefinition> {
    if !agent_file.is_file() {
        return None;
    }

    match AgentDefinition::from_file_in(agent_file, root) {
        Ok(mut def) => {
            if let Some(scope) = scope_override {
                def.scope = scope;
            }
            Some(def)
        }
        Err(e) => {
            tracing::warn!(
                name = name,
                path = %agent_file.display(),
                error = %e,
                context = error_message,
                "Failed to parse agent definition"
            );
            None
        }
    }
}

fn load_definitions_from_dir(
    dir: &Path,
    scope: AgentScope,
    definitions: &mut Vec<AgentDefinition>,
    seen_names: &mut std::collections::HashSet<String>,
    walk: &mut SkillWalk,
) {
    if !walk.admit(dir) {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        if !walk.admit(&path) {
            continue;
        }
        // Any scope: a built-in-named file could never be called, so it is not listed (and does not claim its name).
        if names_a_builtin(&path, None) {
            continue;
        }

        match AgentDefinition::from_file_in(&path, walk.root()) {
            Ok(mut def) => {
                if names_a_builtin(&path, Some(&def)) {
                    continue;
                }
                def.scope = scope;
                // Dedup by name; first occurrence (highest priority) wins
                if seen_names.insert(def.name.clone()) {
                    definitions.push(def);
                }
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "Failed to parse agent definition, skipping"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::discovery::{PluginId, PluginScope};
    use crate::plugins::manifest::PluginManifest;
    use crate::plugins::{LoadedPlugin, PluginRegistry};
    use std::fs;
    use std::path::PathBuf;

    fn test_origin_for_scope(scope: PluginScope) -> crate::plugins::PluginOrigin {
        use crate::plugins::PluginOrigin;
        match scope {
            PluginScope::CliOverride => PluginOrigin::CliOverride,
            PluginScope::Project => PluginOrigin::ProjectFuigo,
            PluginScope::User => PluginOrigin::UserFuigo,
            PluginScope::ConfigPath => PluginOrigin::ConfigPath,
        }
    }

    fn write_agent_file(dir: &std::path::Path, filename: &str, name: &str, desc: &str) {
        let content = format!("---\nname: {name}\ndescription: {desc}\n---\n");
        fs::write(dir.join(filename), content).unwrap();
    }

    fn make_plugin_registry(
        plugin_name: &str,
        scope: PluginScope,
        agent_dirs: Vec<PathBuf>,
    ) -> PluginRegistry {
        make_plugin_registry_with_trust(plugin_name, scope, agent_dirs, true)
    }

    fn make_plugin_registry_with_trust(
        plugin_name: &str,
        scope: PluginScope,
        agent_dirs: Vec<PathBuf>,
        trusted: bool,
    ) -> PluginRegistry {
        // The plugin root holds the agents dir, so the contained agent walk admits the fixture's files.
        let root = agent_dirs
            .first()
            .and_then(|d| d.parent())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(format!("/tmp/{plugin_name}")));
        let canonical = dunce::canonicalize(&root).unwrap_or_else(|_| root.clone());
        let loaded = LoadedPlugin {
            name: plugin_name.to_string(),
            id: PluginId::new(scope, &root, plugin_name),
            root: root.clone(),
            canonical_root: root.clone(),
            scope,
            origin: test_origin_for_scope(scope),
            trusted,
            enabled: true,
            version: Some("1.0.0".to_string()),
            description: Some(format!("Plugin {plugin_name}")),
            skill_dirs: vec![],
            command_dirs: vec![],
            agent_dirs,
            hooks_path: None,
            mcp_config_path: None,
            skill_count: 0,
            agent_count: 0,
            skill_names: vec![],
            agent_names: vec![],
            has_hooks: false,
            hook_count: 0,
            has_inline_hooks_only: false,
            lsp_config_path: None,
            mcp_server_count: 0,
            has_inline_mcp_only: false,
            lsp_server_count: 0,
            has_inline_lsp_only: false,
            inline_hooks: None,
            inline_mcp_servers: None,
            inline_lsp_servers: None,
            conflict: None,
            skipped_links: Default::default(),
        };

        let LoadedPlugin { agent_dirs, .. } = loaded;
        let discovered = crate::plugins::DiscoveredPlugin {
            manifest: PluginManifest {
                name: plugin_name.to_string(),
                version: Some("1.0.0".to_string()),
                description: Some(format!("Plugin {plugin_name}")),
                ..Default::default()
            },
            id: PluginId::new(scope, &root, plugin_name),
            root: root.clone(),
            canonical_root: canonical,
            scope,
            origin: test_origin_for_scope(scope),
            trusted,
            skill_dirs: vec![],
            command_dirs: vec![],
            agent_dirs,
            hooks_path: None,
            mcp_config_path: None,
            lsp_config_path: None,
            conflict: None,
        };
        PluginRegistry::from_discovered(vec![discovered], &[], &[plugin_name.to_string()])
    }

    #[test]
    fn user_agent_dirs_includes_legacy_fuigo_when_fuigo_home_differs() {
        let home = Path::new("/home/u");
        let fuigo = Path::new("/custom/fuigohome");
        let paths: Vec<_> = user_agent_dirs(Some(home), Some(fuigo))
            .into_iter()
            .map(|(p, _)| p)
            .collect();
        assert!(paths.contains(&fuigo.join("agents")));
        assert!(paths.contains(&home.join(".fuigo").join("agents")));
        assert!(paths.contains(&home.join(".claude").join("agents")));
        assert!(paths.contains(&fuigo.join("bundled").join("agents")));
        assert!(paths.contains(&home.join(".fuigo").join("bundled").join("agents")));
    }

    #[test]
    fn user_agent_dirs_dedups_legacy_when_fuigo_home_is_dot_fuigo() {
        let home = Path::new("/home/u");
        let fuigo = home.join(".fuigo");
        let count = user_agent_dirs(Some(home), Some(&fuigo))
            .into_iter()
            .filter(|(p, _)| *p == fuigo.join("agents"))
            .count();
        assert_eq!(
            count, 1,
            "no duplicate ~/.fuigo/agents when fuigo_home == ~/.fuigo"
        );
    }

    #[test]
    fn test_by_name_unknown_agent_is_not_builtin() {
        // Not a built-in, so this returns None unless a project or user-level agent file exists with that name
        let def = by_name("not-a-builtin-agent");
        assert!(def.is_none());
    }

    #[test]
    fn test_by_name_builtin_browser_use() {
        let def = by_name("browser-use");
        assert!(def.is_some());
        assert_eq!(def.unwrap().name, "browser-use");
    }

    #[test]
    fn test_by_name_builtin_fuigo_build() {
        let def = by_name("fuigo-build");
        assert!(def.is_some());
        assert_eq!(def.unwrap().name, "fuigo-build");
    }

    #[test]
    fn test_by_name_builtin_codex() {
        let def = by_name("codex");
        assert!(def.is_some());
        assert_eq!(def.unwrap().name, "codex");
    }

    #[test]
    fn test_by_name_unknown_returns_none() {
        let def = by_name("nonexistent-agent-xyz");
        assert!(def.is_none());
    }

    #[test]
    fn test_discover_finds_md_files() {
        let tmp = tempfile::tempdir().unwrap();
        let agents_dir = tmp.path().join(".fuigo").join("agents");
        fs::create_dir_all(&agents_dir).unwrap();

        write_agent_file(&agents_dir, "test-agent.md", "test-agent", "A test");
        write_agent_file(&agents_dir, "another.md", "another", "Another");

        let defs = discover_with_home(tmp.path(), None, None, true);
        assert_eq!(defs.len(), 2);
        let names: Vec<_> = defs.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"test-agent"));
        assert!(names.contains(&"another"));
    }

    #[test]
    fn test_discover_ignores_non_md_files() {
        let tmp = tempfile::tempdir().unwrap();
        let agents_dir = tmp.path().join(".fuigo").join("agents");
        fs::create_dir_all(&agents_dir).unwrap();

        write_agent_file(&agents_dir, "valid.md", "valid", "Valid agent");
        fs::write(agents_dir.join("readme.txt"), "not an agent").unwrap();
        fs::write(agents_dir.join("config.yaml"), "key: value").unwrap();

        let defs = discover_with_home(tmp.path(), None, None, true);
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].name, "valid");
    }

    #[test]
    fn test_discover_invalid_md_logged_not_error() {
        let tmp = tempfile::tempdir().unwrap();
        let agents_dir = tmp.path().join(".fuigo").join("agents");
        fs::create_dir_all(&agents_dir).unwrap();

        write_agent_file(&agents_dir, "good.md", "good", "Good agent");
        fs::write(agents_dir.join("bad.md"), "just text, no frontmatter").unwrap();

        let defs = discover_with_home(tmp.path(), None, None, true);
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].name, "good");
    }

    #[test]
    fn test_discover_dedup_by_name() {
        let tmp = tempfile::tempdir().unwrap();

        // Create two directories with same-named agents at different levels
        let inner_dir = tmp.path().join("subdir");
        fs::create_dir_all(&inner_dir).unwrap();

        let agents_dir_1 = tmp.path().join(".fuigo").join("agents");
        let agents_dir_2 = inner_dir.join(".fuigo").join("agents");
        fs::create_dir_all(&agents_dir_1).unwrap();
        fs::create_dir_all(&agents_dir_2).unwrap();

        write_agent_file(&agents_dir_1, "dup.md", "dup", "Parent version");
        write_agent_file(&agents_dir_2, "dup.md", "dup", "Child version");

        // Discover from the inner dir; the inner copy is found first and wins
        let defs = discover_with_home(&inner_dir, None, None, true);
        let dup_defs: Vec<_> = defs.iter().filter(|d| d.name == "dup").collect();
        assert_eq!(dup_defs.len(), 1, "Should dedup by name");
    }

    #[test]
    fn test_discover_includes_bundled_agents_at_lowest_priority() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("workspace");
        let home = tmp.path().join("home");
        let bundled_dir = home.join(".fuigo").join("bundled").join("agents");
        fs::create_dir_all(&cwd).unwrap();
        fs::create_dir_all(&bundled_dir).unwrap();

        write_agent_file(
            &bundled_dir,
            "bundled-agent.md",
            "bundled-agent",
            "Bundled agent",
        );

        let defs = discover_with_home(&cwd, Some(&home), Some(&home.join(".fuigo")), true);
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].name, "bundled-agent");
        assert_eq!(defs[0].scope, AgentScope::Bundled);
    }

    #[test]
    fn test_by_name_in_cwd_uses_bundled_when_no_higher_priority_match_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("workspace");
        let home = tmp.path().join("home");
        let bundled_dir = home.join(".fuigo").join("bundled").join("agents");
        fs::create_dir_all(&cwd).unwrap();
        fs::create_dir_all(&bundled_dir).unwrap();

        write_agent_file(
            &bundled_dir,
            "bundled-only.md",
            "bundled-only",
            "Bundled only",
        );

        let def =
            by_name_in_cwd_with_home("bundled-only", &cwd, Some(&home), Some(&home.join(".fuigo")), true)
                .unwrap();
        assert_eq!(def.scope, AgentScope::Bundled);
        assert_eq!(def.description, "Bundled only");
    }

    #[test]
    fn test_by_name_in_cwd_user_beats_bundled() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("workspace");
        let home = tmp.path().join("home");
        let user_dir = home.join(".fuigo").join("agents");
        let bundled_dir = home.join(".fuigo").join("bundled").join("agents");
        fs::create_dir_all(&cwd).unwrap();
        fs::create_dir_all(&user_dir).unwrap();
        fs::create_dir_all(&bundled_dir).unwrap();

        write_agent_file(&user_dir, "reviewer.md", "reviewer", "User reviewer");
        write_agent_file(&bundled_dir, "reviewer.md", "reviewer", "Bundled reviewer");

        let def =
            by_name_in_cwd_with_home("reviewer", &cwd, Some(&home), Some(&home.join(".fuigo")), true)
                .unwrap();
        assert_eq!(def.scope, AgentScope::User);
        assert_eq!(def.description, "User reviewer");
    }

    #[test]
    fn test_by_name_in_cwd_builtin_beats_bundled_for_builtin_names() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("workspace");
        let home = tmp.path().join("home");
        let bundled_dir = home.join(".fuigo").join("bundled").join("agents");
        fs::create_dir_all(&cwd).unwrap();
        fs::create_dir_all(&bundled_dir).unwrap();

        write_agent_file(&bundled_dir, "explore.md", "explore", "Bundled explore");

        let def = by_name_in_cwd_with_home("explore", &cwd, Some(&home), Some(&home.join(".fuigo")), true)
            .unwrap();
        assert_eq!(def.scope, AgentScope::BuiltIn);
        assert_ne!(def.description, "Bundled explore");
    }

    #[test]
    fn test_by_name_in_cwd_project_beats_bundled() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("workspace");
        let home = tmp.path().join("home");
        let project_dir = cwd.join(".fuigo").join("agents");
        let bundled_dir = home.join(".fuigo").join("bundled").join("agents");
        fs::create_dir_all(&project_dir).unwrap();
        fs::create_dir_all(&bundled_dir).unwrap();

        write_agent_file(&project_dir, "reviewer.md", "reviewer", "Project reviewer");
        write_agent_file(&bundled_dir, "reviewer.md", "reviewer", "Bundled reviewer");

        let def =
            by_name_in_cwd_with_home("reviewer", &cwd, Some(&home), Some(&home.join(".fuigo")), true)
                .unwrap();
        assert_eq!(def.scope, AgentScope::Project);
        assert_eq!(def.description, "Project reviewer");
    }

    #[test]
    fn test_by_name_in_cwd_project_shadows_builtin() {
        let tmp = tempfile::tempdir().unwrap();
        let agents_dir = tmp.path().join(".fuigo").join("agents");
        fs::create_dir_all(&agents_dir).unwrap();

        // A project-level "fuigo-build" in a TRUSTED folder: only the built-in-name rule can keep it out.
        // (The public-wrapper form of this case, with no trust hook installed, lives in
        // `tests/project_agent_trust_unset.rs`.)
        write_agent_file(
            &agents_dir,
            "fuigo-build.md",
            "fuigo-build",
            "Custom fuigo-build",
        );

        let def = by_name_in_cwd_with_home("fuigo-build", tmp.path(), None, None, true)
            .expect("the built-in resolves");
        assert_eq!(def.name, "fuigo-build");
        assert_eq!(def.scope, AgentScope::BuiltIn);
        assert_ne!(def.description, "Custom fuigo-build");
    }

    #[test]
    fn test_by_name_in_cwd_falls_back_to_builtin() {
        let tmp = tempfile::tempdir().unwrap();
        // No .fuigo/agents/ directory, so lookup falls back to the built-in

        let def = by_name_in_cwd("fuigo-build", tmp.path());
        assert!(def.is_some());
        let def = def.unwrap();
        assert_eq!(def.name, "fuigo-build");
        assert_eq!(def.scope, AgentScope::BuiltIn);
    }

    // ── all_subagents / merge_subagents tests ───────────────────────

    fn synthetic_agent(name: &str, desc: &str, scope: AgentScope) -> AgentDefinition {
        AgentDefinition {
            name: name.to_string(),
            description: desc.to_string(),
            scope,
            agents_md: false,
            ..AgentDefinition::general_purpose()
        }
    }

    #[test]
    fn test_orchestrator_from_str_resolves() {
        use std::str::FromStr;
        let variant = BuiltinAgentName::from_str("fuigo-build-orchestrator")
            .expect("from_str must resolve fuigo-build-orchestrator");
        assert_eq!(variant, BuiltinAgentName::FuigoBuildOrchestrator);
        let def = variant.definition();
        assert_eq!(def.name, "fuigo-build-orchestrator");
        assert!(
            def.prompt_body.is_some(),
            "orchestrator must have prompt_body"
        );
    }

    #[test]
    fn test_orchestrator_by_name_in_cwd() {
        let tmp = tempfile::tempdir().unwrap();
        let def = by_name_in_cwd("fuigo-build-orchestrator", tmp.path())
            .expect("by_name_in_cwd must find fuigo-build-orchestrator");
        assert_eq!(def.name, "fuigo-build-orchestrator");
        assert!(def.prompt_body.is_some());
    }

    #[test]
    fn test_merge_returns_3_builtins_when_no_user_agents() {
        let entries = merge_subagents(vec![], &HashMap::new());
        assert_eq!(entries.len(), 3);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"general-purpose"));
        assert!(names.contains(&"explore"));
        assert!(names.contains(&"plan"));
        for entry in &entries {
            assert!(
                matches!(&entry.source, SubagentSource::Builtin(_)),
                "expected Builtin source for '{}'",
                entry.name
            );
            assert!(entry.shadows_builtin.is_none());
        }
    }

    #[test]
    fn test_merge_filters_toggled_off_builtins() {
        let toggle = HashMap::from([("plan".to_string(), false)]);
        let entries = merge_subagents(vec![], &toggle);
        assert_eq!(entries.len(), 2);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"general-purpose"));
        assert!(names.contains(&"explore"));
        assert!(!names.contains(&"plan"));
    }

    #[test]
    fn test_merge_includes_user_defined_agents() {
        let discovered = vec![synthetic_agent(
            "code-reviewer",
            "Reviews code",
            AgentScope::Project,
        )];
        let entries = merge_subagents(discovered, &HashMap::new());
        assert_eq!(entries.len(), 4);
        let cr = entries.iter().find(|e| e.name == "code-reviewer").unwrap();
        assert_eq!(cr.description, "Reviews code");
        assert_eq!(
            cr.source,
            SubagentSource::UserDefined {
                scope: AgentScope::Project
            }
        );
        assert!(cr.shadows_builtin.is_none());
    }

    #[test]
    fn test_merge_filters_toggled_off_user_agents() {
        let discovered = vec![synthetic_agent(
            "code-reviewer",
            "Reviews code",
            AgentScope::Project,
        )];
        let toggle = HashMap::from([("code-reviewer".to_string(), false)]);
        let entries = merge_subagents(discovered, &toggle);
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().all(|e| e.name != "code-reviewer"));
    }

    #[test]
    fn test_merge_project_agent_shadows_builtin() {
        let discovered = vec![synthetic_agent(
            "explore",
            "Custom explore agent",
            AgentScope::Project,
        )];
        let entries = merge_subagents(discovered, &HashMap::new());
        assert_eq!(entries.len(), 3); // A project agent with a built-in name neither replaces nor appends
        let explore = entries.iter().find(|e| e.name == "explore").unwrap();
        assert_ne!(explore.description, "Custom explore agent");
        assert_eq!(
            explore.source,
            SubagentSource::Builtin(BuiltinAgentName::Explore)
        );
    }

    #[test]
    fn test_merge_shadowed_entry_has_shadows_builtin() {
        let discovered = vec![synthetic_agent(
            "explore",
            "Custom explore",
            AgentScope::Project,
        )];
        let entries = merge_subagents(discovered, &HashMap::new());
        let explore = entries.iter().find(|e| e.name == "explore").unwrap();
        assert_eq!(
            explore.shadows_builtin, None,
            "no file shadows a built-in, so shadows_builtin is never set"
        );
    }

    #[test]
    fn test_merge_user_level_builtin_name_is_skipped() {
        // A user-level (~/.fuigo/agents/) agent named "explore" should NOT shadow
        // the built-in — only project-level can do that.
        let discovered = vec![synthetic_agent(
            "explore",
            "User-level explore",
            AgentScope::User,
        )];
        let entries = merge_subagents(discovered, &HashMap::new());
        assert_eq!(entries.len(), 3);
        let explore = entries.iter().find(|e| e.name == "explore").unwrap();
        assert!(
            matches!(
                &explore.source,
                SubagentSource::Builtin(BuiltinAgentName::Explore)
            ),
            "user-level explore should not shadow built-in"
        );
    }

    #[test]
    fn test_merge_bundled_builtin_name_is_skipped() {
        let discovered = vec![synthetic_agent(
            "explore",
            "Bundled explore",
            AgentScope::Bundled,
        )];
        let entries = merge_subagents(discovered, &HashMap::new());
        let explore = entries.iter().find(|e| e.name == "explore").unwrap();
        assert!(matches!(
            &explore.source,
            SubagentSource::Builtin(BuiltinAgentName::Explore)
        ));
    }

    #[test]
    fn test_merge_user_unique_name_appended() {
        let discovered = vec![synthetic_agent(
            "migration-helper",
            "Helps with migrations",
            AgentScope::User,
        )];
        let entries = merge_subagents(discovered, &HashMap::new());
        assert_eq!(entries.len(), 4);
        // Verify ordering: built-ins first, then user
        assert!(matches!(&entries[0].source, SubagentSource::Builtin(_)));
        assert!(matches!(&entries[1].source, SubagentSource::Builtin(_)));
        assert!(matches!(&entries[2].source, SubagentSource::Builtin(_)));
        assert_eq!(entries[3].name, "migration-helper");
        assert_eq!(
            entries[3].source,
            SubagentSource::UserDefined {
                scope: AgentScope::User
            }
        );
    }

    #[test]
    fn test_merge_bundled_unique_name_appended() {
        let discovered = vec![synthetic_agent(
            "bundled-helper",
            "Helps from bundle",
            AgentScope::Bundled,
        )];
        let entries = merge_subagents(discovered, &HashMap::new());
        assert_eq!(entries[3].name, "bundled-helper");
        assert_eq!(
            entries[3].source,
            SubagentSource::UserDefined {
                scope: AgentScope::Bundled
            }
        );
    }

    #[test]
    fn test_merge_all_toggled_off_returns_empty() {
        let toggle = HashMap::from([
            ("general-purpose".to_string(), false),
            ("explore".to_string(), false),
            ("plan".to_string(), false),
        ]);
        let entries = merge_subagents(vec![], &toggle);
        assert!(entries.is_empty(), "all toggled off should return empty");
    }

    #[test]
    fn test_merge_invalid_user_agent_preserves_builtin() {
        // Simulate: discover() skips invalid files (returns empty for that file).
        // So if a user's explore.md is invalid, discover() won't include it, and the built-in explore remains
        let discovered = vec![]; // no valid user agents discovered
        let entries = merge_subagents(discovered, &HashMap::new());
        assert_eq!(entries.len(), 3);
        let explore = entries.iter().find(|e| e.name == "explore").unwrap();
        assert!(matches!(
            &explore.source,
            SubagentSource::Builtin(BuiltinAgentName::Explore)
        ));
    }

    #[test]
    fn test_merge_project_user_duplicate_project_wins() {
        let discovered = vec![
            synthetic_agent("my-agent", "Project version", AgentScope::Project),
            synthetic_agent("my-agent", "User version", AgentScope::User),
        ];
        let entries = merge_subagents(discovered, &HashMap::new());
        let my_agent: Vec<_> = entries.iter().filter(|e| e.name == "my-agent").collect();
        assert_eq!(my_agent.len(), 1, "should dedup by name");
        assert_eq!(
            my_agent[0].source,
            SubagentSource::UserDefined {
                scope: AgentScope::Project
            }
        );
    }

    #[test]
    fn test_merge_user_beats_bundled_for_visible_equals_callable() {
        let discovered = vec![
            synthetic_agent("reviewer", "Bundled reviewer", AgentScope::Bundled),
            synthetic_agent("reviewer", "User reviewer", AgentScope::User),
        ];
        let entries = merge_subagents(discovered, &HashMap::new());
        let reviewer = entries.iter().find(|e| e.name == "reviewer").unwrap();
        assert_eq!(reviewer.description, "User reviewer");
        assert_eq!(
            reviewer.source,
            SubagentSource::UserDefined {
                scope: AgentScope::User
            }
        );
    }

    #[test]
    fn test_all_subagents_with_project_agent_file() {
        let tmp = tempfile::tempdir().unwrap();
        let agents_dir = tmp.path().join(".fuigo").join("agents");
        fs::create_dir_all(&agents_dir).unwrap();

        write_agent_file(
            &agents_dir,
            "test-agent.md",
            "test-agent",
            "A test subagent",
        );

        let entries = all_subagents_with_home(tmp.path(), &HashMap::new(), None, None, true);
        assert_eq!(entries.len(), 4);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["general-purpose", "explore", "plan", "test-agent"]
        );
    }

    #[test]
    fn test_all_subagents_with_plugins_preserves_native_visibility() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("workspace");
        let home = tmp.path().join("home");
        let user_dir = home.join(".fuigo").join("agents");
        let bundled_dir = home.join(".fuigo").join("bundled").join("agents");
        fs::create_dir_all(&cwd).unwrap();
        fs::create_dir_all(&user_dir).unwrap();
        fs::create_dir_all(&bundled_dir).unwrap();

        write_agent_file(&user_dir, "reviewer.md", "reviewer", "User reviewer");
        write_agent_file(&bundled_dir, "reviewer.md", "reviewer", "Bundled reviewer");

        let plugin_root = tempfile::tempdir().unwrap();
        let plugin_agents = plugin_root.path().join("agents");
        fs::create_dir_all(&plugin_agents).unwrap();
        write_agent_file(&plugin_agents, "reviewer.md", "reviewer", "Plugin reviewer");

        let registry = make_plugin_registry("plugin-one", PluginScope::User, vec![plugin_agents]);
        let entries = all_subagents_with_plugins_and_home(
            &cwd,
            &HashMap::new(),
            Some(&registry),
            Some(&home),
            Some(&home.join(".fuigo")),
            true,
        );

        let native = entries.iter().find(|e| e.name == "reviewer").unwrap();
        assert_eq!(native.description, "User reviewer");
        assert_eq!(
            native.source,
            SubagentSource::UserDefined {
                scope: AgentScope::User
            }
        );
        assert!(entries.iter().any(|e| e.name == "plugin-one:reviewer"));
    }

    #[test]
    fn test_plugin_agents_filtered_by_qualified_toggle() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("workspace");
        let home = tmp.path().join("home");
        fs::create_dir_all(&cwd).unwrap();
        fs::create_dir_all(&home).unwrap();

        let plugin_root = tempfile::tempdir().unwrap();
        let plugin_agents = plugin_root.path().join("agents");
        fs::create_dir_all(&plugin_agents).unwrap();
        write_agent_file(&plugin_agents, "reviewer.md", "reviewer", "Plugin reviewer");

        let registry = make_plugin_registry("plugin-one", PluginScope::User, vec![plugin_agents]);

        let toggle = HashMap::from([("plugin-one:reviewer".to_string(), false)]);
        let entries = all_subagents_with_plugins_and_home(
            &cwd,
            &toggle,
            Some(&registry),
            Some(&home),
            Some(&home.join(".fuigo")),
            true,
        );
        assert!(
            !entries.iter().any(|e| e.name == "plugin-one:reviewer"),
            "toggled-off plugin agent must not be callable"
        );

        let entries = all_subagents_with_plugins_and_home(
            &cwd,
            &HashMap::new(),
            Some(&registry),
            Some(&home),
            Some(&home.join(".fuigo")),
            true,
        );
        assert!(entries.iter().any(|e| e.name == "plugin-one:reviewer"));
    }

    #[test]
    fn plugin_agent_with_unrecognized_color_is_still_discovered() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("workspace");
        let home = tmp.path().join("home");
        fs::create_dir_all(&cwd).unwrap();
        fs::create_dir_all(&home).unwrap();

        let plugin_root = tempfile::tempdir().unwrap();
        let plugin_agents = plugin_root.path().join("agents");
        fs::create_dir_all(&plugin_agents).unwrap();
        fs::write(
            plugin_agents.join("painter.md"),
            "---\nname: painter\ndescription: Plugin painter\ncolor: chartreuse\n---\nBody.\n",
        )
        .unwrap();

        let registry = make_plugin_registry("plugin-one", PluginScope::User, vec![plugin_agents]);
        let entries = all_subagents_with_plugins_and_home(
            &cwd,
            &HashMap::new(),
            Some(&registry),
            Some(&home),
            Some(&home.join(".fuigo")),
            true,
        );
        assert!(entries.iter().any(|e| e.name == "plugin-one:painter"));

        let def = by_name_in_cwd_with_plugins_and_home(
            "plugin-one:painter",
            &cwd,
            Some(&registry),
            Some(&home),
            Some(&home.join(".fuigo")),
            true,
        )
        .expect("agent must resolve despite the unrecognized color");
        assert_eq!(def.color, None, "unrecognized color must be dropped");
    }

    #[test]
    fn test_by_name_in_cwd_with_plugins_prefers_native_over_plugin_bare_name() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("workspace");
        let home = tmp.path().join("home");
        let bundled_dir = home.join(".fuigo").join("bundled").join("agents");
        fs::create_dir_all(&cwd).unwrap();
        fs::create_dir_all(&bundled_dir).unwrap();
        write_agent_file(&bundled_dir, "reviewer.md", "reviewer", "Bundled reviewer");

        let plugin_root = tempfile::tempdir().unwrap();
        let plugin_agents = plugin_root.path().join("agents");
        fs::create_dir_all(&plugin_agents).unwrap();
        write_agent_file(&plugin_agents, "reviewer.md", "reviewer", "Plugin reviewer");

        let registry = make_plugin_registry("plugin-one", PluginScope::User, vec![plugin_agents]);
        let def = by_name_in_cwd_with_plugins_and_home(
            "reviewer",
            &cwd,
            Some(&registry),
            Some(&home),
            Some(&home.join(".fuigo")),
            true,
        )
        .unwrap();

        assert_eq!(def.scope, AgentScope::Bundled);
        assert_eq!(def.description, "Bundled reviewer");
        assert!(def.plugin_name.is_none());
    }

    #[test]
    fn test_plugin_agent_body_resolves_plugin_root() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("workspace");
        let home = tmp.path().join("home");
        fs::create_dir_all(&cwd).unwrap();
        fs::create_dir_all(&home).unwrap();

        let plugin_dir = tempfile::tempdir().unwrap();
        let plugin_agents = plugin_dir.path().join("agents");
        fs::create_dir_all(&plugin_agents).unwrap();
        // Mirrors how enterprise plugin-dev agents reference the plugin root.
        let content = "---\nname: runner\ndescription: Runs a tool\n---\n\
            Run python3 \"${CLAUDE_PLUGIN_ROOT}/tools/x.py\"\n";
        fs::write(plugin_agents.join("runner.md"), content).unwrap();

        let registry = make_plugin_registry("plugin-one", PluginScope::User, vec![plugin_agents]);
        let expected_root = registry.get("plugin-one").unwrap().root_str();
        let resolved = format!("{expected_root}/tools/x.py");

        // Bare-name resolution path.
        let bare = by_name_in_cwd_with_plugins_and_home(
            "runner",
            &cwd,
            Some(&registry),
            Some(&home),
            Some(&home.join(".fuigo")),
            true,
        )
        .unwrap();
        let bare_body = bare.prompt_body.as_deref().unwrap();
        assert!(
            bare_body.contains(&resolved),
            "expected resolved root in: {bare_body}"
        );
        assert!(
            !bare_body.contains("${CLAUDE_PLUGIN_ROOT}"),
            "literal token must be gone: {bare_body}"
        );

        // Qualified-name resolution path.
        let qualified = by_name_in_cwd_with_plugins_and_home(
            "plugin-one:runner",
            &cwd,
            Some(&registry),
            Some(&home),
            Some(&home.join(".fuigo")),
            true,
        )
        .unwrap();
        let qualified_body = qualified.prompt_body.as_deref().unwrap();
        assert!(
            qualified_body.contains(&resolved),
            "expected resolved root in: {qualified_body}"
        );
        assert!(!qualified_body.contains("${CLAUDE_PLUGIN_ROOT}"));
    }

    #[test]
    fn test_substitute_plugin_vars_resolves_custom_system_prompt() {
        // `system_prompt` is internal (not frontmatter-driven)
        // Construct the definition directly to exercise the `TemplateOverride::Custom` branch
        let registry = make_plugin_registry("plugin-one", PluginScope::User, vec![]);
        let plugin = registry.get("plugin-one").unwrap();

        let mut def = AgentDefinition::default_fuigo_build();
        def.prompt_body = Some("Body ${CLAUDE_PLUGIN_ROOT}/x".to_string());
        def.system_prompt =
            TemplateOverride::Custom("Data at ${CLAUDE_PLUGIN_DATA}/db".to_string());

        substitute_plugin_vars(&mut def, plugin);

        let expected_body = format!("Body {}/x", plugin.root_str());
        let expected_prompt = format!("Data at {}/db", plugin.data_dir_str());
        assert_eq!(def.prompt_body.as_deref(), Some(expected_body.as_str()));
        match &def.system_prompt {
            TemplateOverride::Custom(tpl) => {
                assert_eq!(tpl, &expected_prompt);
                assert!(!tpl.contains("${CLAUDE_PLUGIN_DATA}"));
            }
            other => panic!("expected Custom system_prompt, got {other:?}"),
        }
    }

    #[test]
    fn test_all_subagents_toggle_filters_project_agent() {
        let tmp = tempfile::tempdir().unwrap();
        let agents_dir = tmp.path().join(".fuigo").join("agents");
        fs::create_dir_all(&agents_dir).unwrap();

        write_agent_file(
            &agents_dir,
            "test-agent.md",
            "test-agent",
            "A test subagent",
        );

        let toggle = HashMap::from([("test-agent".to_string(), false)]);
        let entries = all_subagents_with_home(tmp.path(), &toggle, None, None, true);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["general-purpose", "explore", "plan"]);
    }

    // ── u35: trust gate (test 6), name validation (test 8), built-in names (test 9) ──

    /// Project + user layout for the u35 cases: `<tmp>/workspace` (cwd) and `<tmp>/home/.fuigo` (fuigo_home).
    struct U35Layout {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        cwd: PathBuf,
        home: PathBuf,
        fuigo_home: PathBuf,
    }

    impl U35Layout {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().to_path_buf();
            let cwd = root.join("workspace");
            let home = root.join("home");
            let fuigo_home = home.join(".fuigo");
            fs::create_dir_all(cwd.join(".fuigo").join("agents")).unwrap();
            fs::create_dir_all(fuigo_home.join("agents")).unwrap();
            Self {
                _tmp: tmp,
                root,
                cwd,
                home,
                fuigo_home,
            }
        }
        fn project_agents(&self) -> PathBuf {
            self.cwd.join(".fuigo").join("agents")
        }
        fn user_agents(&self) -> PathBuf {
            self.fuigo_home.join("agents")
        }
        fn by_name(&self, name: &str, trusted: bool) -> Option<AgentDefinition> {
            by_name_in_cwd_with_home(
                name,
                &self.cwd,
                Some(&self.home),
                Some(&self.fuigo_home),
                trusted,
            )
        }
        fn discover(&self, trusted: bool) -> Vec<AgentDefinition> {
            discover_with_home(&self.cwd, Some(&self.home), Some(&self.fuigo_home), trusted)
        }
        fn subagents(&self, trusted: bool) -> Vec<SubagentEntry> {
            all_subagents_with_home(
                &self.cwd,
                &HashMap::new(),
                Some(&self.home),
                Some(&self.fuigo_home),
                trusted,
            )
        }
    }

    #[test]
    fn u35_project_agents_load_only_when_trusted() {
        let l = U35Layout::new();
        write_agent_file(&l.project_agents(), "reviewer.md", "reviewer", "Project reviewer");

        assert!(
            l.by_name("reviewer", false).is_none(),
            "untrusted: a project agent file must not load by name"
        );
        assert!(
            !l.discover(false).iter().any(|d| d.name == "reviewer"),
            "untrusted: a project agent file must not be listed"
        );
        assert!(!l.subagents(false).iter().any(|e| e.name == "reviewer"));

        let def = l.by_name("reviewer", true).expect("trusted: the project agent loads");
        assert_eq!(def.scope, AgentScope::Project);
        assert_eq!(def.description, "Project reviewer");
        assert!(l.discover(true).iter().any(|d| d.name == "reviewer"));
    }

    #[test]
    fn u35_untrusted_project_falls_through_to_user() {
        let l = U35Layout::new();
        write_agent_file(&l.project_agents(), "reviewer.md", "reviewer", "Project reviewer");
        write_agent_file(&l.user_agents(), "reviewer.md", "reviewer", "User reviewer");
        let def = l.by_name("reviewer", false).expect("user agent still resolves");
        assert_eq!(def.scope, AgentScope::User);
        assert_eq!(def.description, "User reviewer");
    }

    #[test]
    fn u35_is_valid_agent_name_table() {
        for bad in [
            "",
            ".",
            "..",
            "../x",
            "a/b",
            "a\\b",
            "/abs/x",
            "C:x",
            "\\\\?\\C:\\x",
            "\\\\srv\\s\\x",
            "x\0",
            "plug:../x",
        ] {
            assert!(!is_valid_agent_name(bad), "{bad:?} must be rejected");
        }
        for good in ["reviewer", "my_agent-2", "fuigo-build", "a.b"] {
            assert!(is_valid_agent_name(good), "{good:?} must be accepted");
        }
    }

    /// A real agent file sits at every traversal destination, so `None` proves the name was refused, not just missing.
    #[test]
    fn u35_traversal_names_resolve_to_nothing() {
        let l = U35Layout::new();
        let marker = "---\nname: evil\ndescription: escaped\n---\nU35-PWNED-MARKER\n";
        // `<root>/evil.md`: reached from the user dir by `../../../evil` and by its absolute path.
        fs::write(l.root.join("evil.md"), marker).unwrap();
        // `<cwd>/evil.md`: reached from the project dir by `../../evil`.
        fs::write(l.cwd.join("evil.md"), marker).unwrap();
        let abs = l.root.join("evil").to_string_lossy().into_owned();
        let names = [abs.as_str(), "../../../evil", "../../evil", "./evil", "..", ""];
        for name in names {
            assert!(
                by_name_with_home(name, Some(&l.home), Some(&l.fuigo_home)).is_none(),
                "by_name_with_home({name:?})"
            );
            for trusted in [false, true] {
                assert!(l.by_name(name, trusted).is_none(), "by_name_in_cwd_with_home({name:?}, {trusted})");
                assert!(
                    by_name_in_cwd_with_plugins_and_home(
                        name,
                        &l.cwd,
                        None,
                        Some(&l.home),
                        Some(&l.fuigo_home),
                        trusted,
                    )
                    .is_none(),
                    "by_name_in_cwd_with_plugins_and_home({name:?}, {trusted})"
                );
            }
        }
    }

    #[test]
    fn u35_qualified_plugin_names_are_validated_on_both_halves() {
        let l = U35Layout::new();
        let plugin_root = l.root.join("plug");
        let plugin_agents = plugin_root.join("agents");
        fs::create_dir_all(&plugin_agents).unwrap();
        // The escaped target: `<root>/plug/evil.md`, one level above the plugin's agent dir.
        fs::write(
            plugin_root.join("evil.md"),
            "---\nname: evil\ndescription: escaped\n---\nU35-PWNED-MARKER\n",
        )
        .unwrap();
        write_agent_file(&plugin_agents, "good.md", "good", "Plugin good");
        let registry = make_plugin_registry("plug", PluginScope::User, vec![plugin_agents]);
        let lookup = |name: &str| {
            by_name_in_cwd_with_plugins_and_home(
                name,
                &l.cwd,
                Some(&registry),
                Some(&l.home),
                Some(&l.fuigo_home),
                true,
            )
        };
        assert!(lookup("plug:../evil").is_none(), "agent half escapes the plugin dir");
        assert!(lookup("../plug:evil").is_none(), "plugin half is not a plain name");
        assert!(lookup("plug:good").is_some(), "a plain qualified name still resolves");
    }

    #[test]
    fn u35_project_builtin_stem_never_shadows_and_is_not_listed_under_its_frontmatter_name() {
        let l = U35Layout::new();
        // Stem is built-in, frontmatter name is not.
        fs::write(
            l.project_agents().join("explore.md"),
            "---\nname: notes\ndescription: sneaky\n---\nbody\n",
        )
        .unwrap();
        let def = l.by_name("explore", true).expect("built-in explore");
        assert_eq!(def.scope, AgentScope::BuiltIn);
        assert!(l.by_name("notes", true).is_none());
        assert!(!l.discover(true).iter().any(|d| d.name == "notes"));
    }

    #[test]
    fn u35_project_builtin_frontmatter_name_does_not_replace_the_builtin_row() {
        let l = U35Layout::new();
        // Stem is not built-in, frontmatter name is.
        fs::write(
            l.project_agents().join("notes.md"),
            "---\nname: explore\ndescription: sneaky\n---\nbody\n",
        )
        .unwrap();
        assert!(l.by_name("notes", true).is_none());
        assert!(!l.discover(true).iter().any(|d| d.name == "explore"));
        let explore = l
            .subagents(true)
            .into_iter()
            .find(|e| e.name == "explore")
            .expect("explore row");
        assert_eq!(explore.source, SubagentSource::Builtin(BuiltinAgentName::Explore));
        assert_eq!(explore.shadows_builtin, None);
    }

    #[test]
    fn u35_user_files_with_builtin_names_are_ignored() {
        let l = U35Layout::new();
        fs::write(
            l.user_agents().join("explore.md"),
            "---\nname: notes\ndescription: sneaky\n---\nbody\n",
        )
        .unwrap();
        fs::write(
            l.user_agents().join("notes.md"),
            "---\nname: explore\ndescription: sneaky\n---\nbody\n",
        )
        .unwrap();
        write_agent_file(&l.user_agents(), "codex.md", "codex", "User codex");
        assert_eq!(l.by_name("explore", false).unwrap().scope, AgentScope::BuiltIn);
        assert!(l.by_name("notes", false).is_none());
        assert_eq!(l.by_name("codex", false).unwrap().scope, AgentScope::BuiltIn);
        let names: Vec<String> = l.discover(false).into_iter().map(|d| d.name).collect();
        assert!(names.is_empty(), "no built-in-named user file is listed: {names:?}");
        let explore = l
            .subagents(false)
            .into_iter()
            .find(|e| e.name == "explore")
            .expect("explore row");
        assert_eq!(explore.source, SubagentSource::Builtin(BuiltinAgentName::Explore));
        assert!(!l.subagents(false).iter().any(|e| e.name == "codex"));
    }

    /// u35 r2 (Fable Low): a user file whose frontmatter names a built-in is skipped and the lookup goes on to the next
    /// user dir, on purpose, not `None`: discovery skips the same file and lists the next dir's file under that name, so
    /// stopping at `None` would list an agent that cannot be called. Callable and listed stay the same file.
    #[test]
    fn u35_builtin_named_user_file_falls_through_to_the_next_user_dir_in_lookup_and_list() {
        let l = U35Layout::new();
        fs::write(
            l.user_agents().join("notes.md"),
            "---\nname: explore\ndescription: sneaky\n---\nbody\n",
        )
        .unwrap();
        let claude = l.home.join(".claude").join("agents");
        fs::create_dir_all(&claude).unwrap();
        write_agent_file(&claude, "notes.md", "notes", "Claude notes");
        let called = l.by_name("notes", false).expect("the next user dir's notes is callable");
        assert_eq!(called.description, "Claude notes");
        let listed: Vec<AgentDefinition> =
            l.discover(false).into_iter().filter(|d| d.name == "notes").collect();
        assert_eq!(listed.len(), 1, "one notes row");
        assert_eq!(listed[0].description, "Claude notes", "the listed notes is the callable one");
        assert!(l.subagents(false).iter().any(|e| e.name == "notes" && e.description == "Claude notes"));
    }

    #[test]
    fn u35_user_files_with_plain_names_keep_working() {
        let l = U35Layout::new();
        write_agent_file(&l.user_agents(), "default.md", "default", "User default");
        write_agent_file(&l.user_agents(), "ask.md", "ask", "User ask");
        assert_eq!(l.by_name("default", false).unwrap().description, "User default");
        assert_eq!(l.by_name("ask", false).unwrap().description, "User ask");
    }

    /// An enabled plugin agent whose frontmatter asks for a full prompt and a custom user template.
    fn hostile_plugin_agent(dir: &std::path::Path) {
        fs::write(
            dir.join("reviewer.md"),
            "---\nname: reviewer\ndescription: Plugin reviewer\npromptMode: full\nuserMessageTemplate:\n  custom: \"U35-PLUGIN-MARKER\"\n---\nU35-PLUGIN-MARKER body\n",
        )
        .unwrap();
    }

    /// RED before the fix (Astra r1 High): an enabled but untrusted plugin's agent resolved by qualified and bare name,
    /// carrying `promptMode: full` and its custom `userMessageTemplate` into the harness rebuild.
    #[test]
    fn u35_untrusted_plugin_agents_are_not_callable() {
        use crate::config::PromptMode;
        use crate::prompt::user_message::UserMessageTemplate;
        let l = U35Layout::new();
        let plugin_root = tempfile::tempdir().unwrap();
        let agents = plugin_root.path().join("agents");
        fs::create_dir_all(&agents).unwrap();
        hostile_plugin_agent(&agents);
        for scope in [PluginScope::Project, PluginScope::User] {
            let untrusted =
                make_plugin_registry_with_trust("plug", scope, vec![agents.clone()], false);
            assert!(untrusted.get("plug").is_some_and(|p| p.enabled && !p.trusted));
            for name in ["plug:reviewer", "reviewer"] {
                let def = by_name_in_cwd_with_plugins_and_home(
                    name,
                    &l.cwd,
                    Some(&untrusted),
                    Some(&l.home),
                    Some(&l.fuigo_home),
                    true,
                );
                assert!(def.is_none(), "{scope:?} untrusted plugin agent {name:?} must not resolve: {def:?}");
            }
            let listed = all_subagents_with_plugins_and_home(
                &l.cwd,
                &HashMap::new(),
                Some(&untrusted),
                Some(&l.home),
                Some(&l.fuigo_home),
                true,
            );
            assert!(
                !listed.iter().any(|e| e.name == "plug:reviewer"),
                "visible == callable: an untrusted plugin agent is not offered"
            );
            // Metadata-only enumeration (the /agents modal) still sees it, with no prompt override surviving.
            let meta = plugin_agents(&untrusted);
            let reviewer = meta
                .iter()
                .find(|a| a.qualified_name == "plug:reviewer")
                .expect("metadata listing keeps untrusted plugin agents");
            assert!(reviewer.definition.prompt_body.is_none());
            assert_eq!(reviewer.definition.prompt_mode, PromptMode::Extend);
            assert!(matches!(
                reviewer.definition.user_message_template,
                UserMessageTemplate::Default
            ));
        }
        // Trusted: the same agent is callable by both names, with its own prompt.
        let trusted = make_plugin_registry_with_trust("plug", PluginScope::User, vec![agents], true);
        for name in ["plug:reviewer", "reviewer"] {
            let def = by_name_in_cwd_with_plugins_and_home(
                name,
                &l.cwd,
                Some(&trusted),
                Some(&l.home),
                Some(&l.fuigo_home),
                true,
            )
            .unwrap_or_else(|| panic!("trusted plugin agent {name:?} resolves"));
            assert_eq!(def.plugin_name.as_deref(), Some("plug"));
            assert_eq!(def.prompt_mode, PromptMode::Full);
        }
    }

    /// An untrusted plugin cannot take a bare name from a trusted one by making it ambiguous.
    #[test]
    fn u35_untrusted_plugin_does_not_make_a_trusted_bare_name_ambiguous() {
        let l = U35Layout::new();
        let good_root = tempfile::tempdir().unwrap();
        let good = good_root.path().join("agents");
        fs::create_dir_all(&good).unwrap();
        write_agent_file(&good, "reviewer.md", "reviewer", "Good reviewer");
        let bad_root = tempfile::tempdir().unwrap();
        let bad = bad_root.path().join("agents");
        fs::create_dir_all(&bad).unwrap();
        hostile_plugin_agent(&bad);
        let good_reg = make_plugin_registry_with_trust("good", PluginScope::User, vec![good], true);
        let bad_reg = make_plugin_registry_with_trust("bad", PluginScope::Project, vec![bad], false);
        let mut discovered: Vec<_> = Vec::new();
        for reg in [&good_reg, &bad_reg] {
            for p in reg.list() {
                discovered.push(crate::plugins::DiscoveredPlugin {
                    manifest: PluginManifest {
                        name: p.name.clone(),
                        ..Default::default()
                    },
                    id: p.id.clone(),
                    root: p.root.clone(),
                    canonical_root: p.canonical_root.clone(),
                    scope: p.scope,
                    origin: test_origin_for_scope(p.scope),
                    trusted: p.trusted,
                    skill_dirs: vec![],
                    command_dirs: vec![],
                    agent_dirs: p.agent_dirs.clone(),
                    hooks_path: None,
                    mcp_config_path: None,
                    lsp_config_path: None,
                    conflict: None,
                });
            }
        }
        let both = PluginRegistry::from_discovered(
            discovered,
            &[],
            &["good".to_string(), "bad".to_string()],
        );
        let def = by_name_in_cwd_with_plugins_and_home(
            "reviewer",
            &l.cwd,
            Some(&both),
            Some(&l.home),
            Some(&l.fuigo_home),
            true,
        )
        .expect("the trusted plugin's agent resolves by bare name");
        assert_eq!(def.plugin_name.as_deref(), Some("good"));
        assert_eq!(def.description, "Good reviewer");
    }

    /// m3: a plugin agent file linked outside the plugin folder is neither listed nor callable (qualified or bare);
    /// a link that stays inside the plugin still loads.
    #[cfg(unix)]
    #[test]
    fn m3_plugin_agent_linked_outside_plugin_is_not_loaded() {
        let tmp = tempfile::tempdir().unwrap();
        let plugin_root = tmp.path().join("plug");
        let agents = plugin_root.join("agents");
        let shared = plugin_root.join("shared");
        let outside = tmp.path().join("outside");
        for d in [&agents, &shared, &outside] {
            fs::create_dir_all(d).unwrap();
        }
        write_agent_file(&agents, "good.md", "good", "Good");
        write_agent_file(&shared, "inner.md", "inner", "Inner");
        write_agent_file(&outside, "secret.md", "leak", "Leak");
        std::os::unix::fs::symlink(shared.join("inner.md"), agents.join("inner.md")).unwrap();
        std::os::unix::fs::symlink(outside.join("secret.md"), agents.join("leak.md")).unwrap();

        let registry = make_plugin_registry("plug", PluginScope::User, vec![agents]);
        let mut names: Vec<String> = plugin_agents(&registry)
            .into_iter()
            .map(|a| a.qualified_name)
            .collect();
        names.sort();
        assert_eq!(names, ["plug:good", "plug:inner"]);
        for name in ["plug:leak", "leak"] {
            let def = by_name_in_cwd_with_plugins_and_home(
                name,
                tmp.path(),
                Some(&registry),
                None,
                None,
                false,
            );
            assert!(def.is_none(), "{name} resolved to a file outside the plugin");
        }
        assert!(
            by_name_in_cwd_with_plugins_and_home("plug:inner", tmp.path(), Some(&registry), None, None, false)
                .is_some()
        );
    }

    /// m3: a project agent file (`.fuigo/agents`) linked outside the project folder does not load, by listing or by
    /// name; the project's own agent does.
    #[cfg(unix)]
    #[test]
    fn m3_project_agent_linked_outside_project_is_not_loaded() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let agents = repo.join(".fuigo").join("agents");
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&agents).unwrap();
        fs::create_dir_all(&outside).unwrap();
        write_agent_file(&agents, "good.md", "good", "Good");
        write_agent_file(&outside, "secret.md", "leak", "Leak");
        std::os::unix::fs::symlink(outside.join("secret.md"), agents.join("leak.md")).unwrap();

        let names: Vec<String> = discover_with_home(&repo, None, None, true)
            .into_iter()
            .map(|d| d.name)
            .collect();
        assert_eq!(names, ["good"]);
        assert!(by_name_in_cwd_with_plugins_and_home("leak", &repo, None, None, None, true).is_none());
        assert!(by_name_in_cwd_with_plugins_and_home("good", &repo, None, None, None, true).is_some());
    }

    /// m4: an agent file is read only from inside its root, checked on the opened file; an in-root link reads; user
    /// scope (`None`) follows links.
    #[cfg(unix)]
    #[test]
    fn m4_agent_read_is_held_to_its_root() {
        let tmp = tempfile::tempdir().unwrap();
        let base = dunce::canonicalize(tmp.path()).unwrap();
        let repo = base.join("repo");
        let agents = repo.join(".fuigo").join("agents");
        std::fs::create_dir_all(&agents).unwrap();
        std::fs::create_dir_all(base.join("outside")).unwrap();
        let secret = base.join("outside").join("secret.md");
        std::fs::write(&secret, "---\nname: leak\ndescription: d\n---\nTOP SECRET\n").unwrap();
        std::fs::write(repo.join("real.md"), "---\nname: good\ndescription: d\n---\nown\n").unwrap();
        std::os::unix::fs::symlink(&secret, agents.join("leak.md")).unwrap();
        std::os::unix::fs::symlink(repo.join("real.md"), agents.join("good.md")).unwrap();

        let pinned = fuigo_dirs::contained::PinnedRoot::pin(&repo).unwrap();
        assert!(AgentDefinition::from_file_in(agents.join("leak.md"), Some(&pinned)).is_err());
        assert!(AgentDefinition::from_file_frontmatter_only_in(agents.join("leak.md"), Some(&pinned)).is_err());
        let good = AgentDefinition::from_file_in(agents.join("good.md"), Some(&pinned)).unwrap();
        assert_eq!(good.name, "good");
        let user = AgentDefinition::from_file_in(agents.join("leak.md"), None).unwrap();
        assert!(user.prompt_body.unwrap_or_default().contains("TOP SECRET"));
    }
}
