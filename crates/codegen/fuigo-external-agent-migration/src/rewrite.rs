use std::collections::HashSet;
use std::path::Path;

use toml::Value as TomlValue;
use toml::map::Map as TomlMap;
use tracing::warn;

use super::config_values::{
    ImportPermission, ImportRuleAction, ImportableItem, PathKind, format_rule_string,
};
use super::error::MigrationError;
use fuigo_config_types::McpServerConfig;

/// What [`merge_items_into_config`] decided for a `config.toml`.
#[derive(Debug, Default)]
pub struct ConfigPatch {
    /// The text to write, or `None` when nothing was added.
    pub contents: Option<String>,
    /// Entries newly added.
    pub count: usize,
}

/// `[claude_compat] imported = true` merged into `current` (the text of `config.toml`, `None` when the file does
/// not exist), everything else in it preserved.
///
/// # Errors
///
/// `current` is not valid TOML (it is never silently discarded: an atomic rewrite would otherwise drop every
/// section this import does not write), or `[claude_compat]` is not a table.
pub fn marker_config_text(
    config_path: &Path,
    current: Option<&str>,
) -> Result<String, MigrationError> {
    let mut root = read_toml_root(config_path, current, "refusing to write import marker")?;
    let table = root.as_table_mut().ok_or(MigrationError::NotATable {
        section: "config root",
    })?;
    let compat = table
        .entry("claude_compat")
        .or_insert_with(|| TomlValue::Table(TomlMap::new()));
    let compat_table = compat.as_table_mut().ok_or(MigrationError::NotATable {
        section: "[claude_compat]",
    })?;
    compat_table.insert("imported".to_string(), TomlValue::Boolean(true));
    toml::to_string_pretty(&root).map_err(|source| MigrationError::TomlSerialize {
        path: config_path.to_path_buf(),
        source,
    })
}

/// Merge the non-hook items of `items` into `current` (the text of the destination `config.toml`, `None` when it
/// does not exist). Hooks go to a separate file; see [`super::merge_hooks`].
///
/// Additive only: permission rules and paths are appended when not already listed, and environment variables and
/// MCP servers are added without overwriting an existing key or name.
///
/// # Errors
///
/// `current` is not valid TOML, or a section being merged into has the wrong TOML type.
pub fn merge_items_into_config(
    config_path: &Path,
    current: Option<&str>,
    items: &[ImportableItem],
) -> Result<ConfigPatch, MigrationError> {
    let mut root = read_toml_root(config_path, current, "refusing to import")?;
    let table = root.as_table_mut().ok_or(MigrationError::NotATable {
        section: "config root",
    })?;

    let mut permissions: Vec<&ImportPermission> = Vec::new();
    let mut env_vars: Vec<(&str, &str)> = Vec::new();
    let mut mcp_servers: Vec<(&str, &McpServerConfig)> = Vec::new();
    let mut skill_dirs: Vec<&str> = Vec::new();
    let mut rule_dirs: Vec<&str> = Vec::new();
    for item in items {
        match item {
            ImportableItem::Permission(rule) => permissions.push(rule),
            ImportableItem::EnvVar { key, value } => env_vars.push((key, value)),
            ImportableItem::McpServer { name, config } => mcp_servers.push((name, config)),
            // Hooks are written to .fuigo/hooks/ JSON files, not into config.toml.
            ImportableItem::Hook { .. } => {}
            ImportableItem::PathEntry { kind, path } => match kind {
                PathKind::Skill => skill_dirs.push(path.as_str()),
                PathKind::Rule => rule_dirs.push(path.as_str()),
            },
        }
    }

    let mut count = 0usize;
    if !permissions.is_empty() {
        count += merge_permissions(table, &permissions)?;
    }
    if !skill_dirs.is_empty() {
        count += merge_paths(table, "extra_skill_dirs", &skill_dirs)?;
    }
    if !rule_dirs.is_empty() {
        count += merge_paths(table, "extra_rule_dirs", &rule_dirs)?;
    }
    if !env_vars.is_empty() {
        count += merge_env_vars(table, &env_vars);
    }
    if !mcp_servers.is_empty() {
        count += merge_mcp_servers(table, &mcp_servers)?;
    }

    if count == 0 {
        return Ok(ConfigPatch::default());
    }
    let contents =
        toml::to_string_pretty(&root).map_err(|source| MigrationError::TomlSerialize {
            path: config_path.to_path_buf(),
            source,
        })?;
    Ok(ConfigPatch {
        contents: Some(contents),
        count,
    })
}

/// Parse `current`, reporting a parse error instead of silently discarding the file. A rewrite would otherwise
/// drop unrelated sections (`[model]`, `[ui]`, ...) of a hand-edited config that happens to have a trailing comma.
fn read_toml_root(
    config_path: &Path,
    current: Option<&str>,
    action: &'static str,
) -> Result<TomlValue, MigrationError> {
    match current {
        Some(text) => toml::from_str(text).map_err(|source| MigrationError::InvalidToml {
            action,
            path: config_path.to_path_buf(),
            source,
        }),
        None => Ok(TomlValue::Table(TomlMap::new())),
    }
}

/// Merge permission rules into `[permission]` using the compact format. Existing rules are preserved; new ones
/// are appended to the matching list (`allow`, `deny`, `ask`).
fn merge_permissions(
    table: &mut TomlMap<String, TomlValue>,
    rules: &[&ImportPermission],
) -> Result<usize, MigrationError> {
    let permission = table
        .entry("permission")
        .or_insert_with(|| TomlValue::Table(TomlMap::new()));
    let perm_table = permission.as_table_mut().ok_or(MigrationError::NotATable {
        section: "[permission]",
    })?;

    let mut allow_rules = Vec::new();
    let mut deny_rules = Vec::new();
    let mut ask_rules = Vec::new();
    for rule in rules {
        let formatted = format_rule_string(rule);
        match rule.action {
            ImportRuleAction::Allow => allow_rules.push(formatted),
            ImportRuleAction::Deny => deny_rules.push(formatted),
            ImportRuleAction::Ask => ask_rules.push(formatted),
        }
    }

    let mut count = 0;
    for (key, new_rules) in [
        ("allow", allow_rules),
        ("deny", deny_rules),
        ("ask", ask_rules),
    ] {
        if new_rules.is_empty() {
            continue;
        }
        let arr = perm_table
            .entry(key)
            .or_insert_with(|| TomlValue::Array(Vec::new()));
        let existing = arr
            .as_array_mut()
            .ok_or_else(|| MigrationError::NotAnArray {
                section: format!("permission.{key}"),
            })?;
        count += append_missing_strings(existing, new_rules);
    }
    Ok(count)
}

/// Merge environment variables into `[env]`. Existing keys are NOT overwritten.
fn merge_env_vars(table: &mut TomlMap<String, TomlValue>, vars: &[(&str, &str)]) -> usize {
    let env = table
        .entry("env")
        .or_insert_with(|| TomlValue::Table(TomlMap::new()));
    let Some(env_table) = env.as_table_mut() else {
        warn!("[env] in config.toml is not a table, skipping env import");
        return 0;
    };

    let mut count = 0;
    for (key, value) in vars {
        if !env_table.contains_key(*key) {
            env_table.insert((*key).to_string(), TomlValue::String((*value).to_string()));
            count += 1;
        }
    }
    count
}

/// Merge MCP server configs into `[mcp_servers]`. Existing servers are NOT overwritten.
fn merge_mcp_servers(
    table: &mut TomlMap<String, TomlValue>,
    servers: &[(&str, &McpServerConfig)],
) -> Result<usize, MigrationError> {
    let mcp = table
        .entry("mcp_servers")
        .or_insert_with(|| TomlValue::Table(TomlMap::new()));
    let mcp_table = mcp.as_table_mut().ok_or(MigrationError::NotATable {
        section: "[mcp_servers]",
    })?;

    let mut count = 0;
    for (name, config) in servers {
        if !mcp_table.contains_key(*name) {
            let serialized =
                toml::Value::try_from(*config).map_err(|source| MigrationError::McpSerialize {
                    name: (*name).to_string(),
                    source,
                })?;
            mcp_table.insert((*name).to_string(), serialized);
            count += 1;
        }
    }
    Ok(count)
}

/// Merge path strings into `[paths] <key>` (an array of strings). Existing entries are preserved; entries not
/// already present are appended. Returns the number newly added.
fn merge_paths(
    table: &mut TomlMap<String, TomlValue>,
    key: &str,
    new_paths: &[&str],
) -> Result<usize, MigrationError> {
    let paths = table
        .entry("paths")
        .or_insert_with(|| TomlValue::Table(TomlMap::new()));
    let paths_table = paths
        .as_table_mut()
        .ok_or(MigrationError::NotATable { section: "[paths]" })?;

    let arr = paths_table
        .entry(key)
        .or_insert_with(|| TomlValue::Array(Vec::new()));
    let existing = arr
        .as_array_mut()
        .ok_or_else(|| MigrationError::NotAnArray {
            section: format!("paths.{key}"),
        })?;
    Ok(append_missing_strings(existing, new_paths.iter().copied()))
}

fn append_missing_strings<S: AsRef<str> + Into<String>>(
    existing: &mut Vec<TomlValue>,
    new_values: impl IntoIterator<Item = S>,
) -> usize {
    let mut present: HashSet<String> = existing
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();

    let mut count = 0usize;
    for value in new_values {
        if present.insert(value.as_ref().to_string()) {
            existing.push(TomlValue::String(value.into()));
            count += 1;
        }
    }
    count
}

#[cfg(test)]
#[path = "rewrite_tests.rs"]
mod tests;
