use std::collections::HashSet;
use std::path::{Path, PathBuf};

use fuigo_config_types::McpServerConfig;
use tracing::{debug, info};

use super::config_values::{ClaudeSettingsSnapshot, ImportPlan, ImportableItem, PathKind};
use super::hooks_cla::extract_hooks_from_settings_file_in;
use super::scope::find_project_root;

/// Build an import plan from the source settings.
///
/// The caller has already located and (where its own policy allows) read the sources, so this crate does not
/// depend on the permission grammar or the MCP loaders:
///
/// - `settings_paths`: the source settings files, highest priority first. A path under `~/.claude` is global,
///   any other is project. For each, `snapshot` supplies its permission rules and environment variables
///   (`None` skips the file) and its `hooks` block is read here.
/// - `claude_json_servers`: MCP servers from `~/.claude.json` (user-level and this project's entry in one list).
///   Both are stored in the global scope.
/// - `mcp_json_servers`: MCP servers from the repository's `.mcp.json` files, stored in the project scope.
///
/// `~/.claude/{skills,rules}` and `<repo>/.claude/{skills,rules}` are discovered here, a project directory that
/// resolves to the same place as the global one (an import run from the home directory) only once.
#[must_use]
pub fn scan_importable_settings(
    cwd: &Path,
    settings_paths: &[PathBuf],
    mut snapshot: impl FnMut(&Path) -> Option<ClaudeSettingsSnapshot>,
    claude_json_servers: Vec<(String, McpServerConfig)>,
    mcp_json_servers: Vec<(String, McpServerConfig)>,
) -> ImportPlan {
    let mut plan = ImportPlan::default();
    // The home used for the global/project split must match the resolution everywhere else that reads `~/.claude`,
    // or the scan and the hash tiers disagree.
    let home = fuigo_dirs::home_dir();
    // Project settings are repository content: pin the project root once and read their hooks contained to it.
    let project_root = fuigo_dirs::contained::PinnedRoot::pin(&find_project_root(cwd)).ok();

    for path in settings_paths {
        let Some(settings) = snapshot(path) else {
            continue;
        };

        let is_global = home
            .as_ref()
            .is_some_and(|home| path.starts_with(home.join(".claude")));
        let target = if is_global {
            &mut plan.global_items
        } else {
            &mut plan.project_items
        };

        target.extend(
            settings
                .permissions
                .into_iter()
                .map(ImportableItem::Permission),
        );
        for (key, value) in settings.env {
            target.push(ImportableItem::EnvVar { key, value });
        }
        // Re-read from the JSON: the snapshot does not model `hooks`.
        if is_global {
            target.extend(extract_hooks_from_settings_file_in(path, None));
        } else if let Some(root) = project_root.as_ref() {
            target.extend(extract_hooks_from_settings_file_in(path, Some(root)));
        } else {
            debug!(path = %path.display(), "Cannot pin the project root; project hooks not imported");
        }
    }

    for (name, config) in claude_json_servers {
        plan.global_items.push(ImportableItem::McpServer {
            name,
            config: Box::new(config),
        });
    }
    for (name, config) in mcp_json_servers {
        plan.project_items.push(ImportableItem::McpServer {
            name,
            config: Box::new(config),
        });
    }

    scan_claude_path_dirs(cwd, &mut plan);

    if !plan.is_empty() {
        info!(
            global = plan.global_items.len(),
            project = plan.project_items.len(),
            "Scanned Claude settings for import"
        );
    }

    plan
}

/// Emit `PathEntry` items for the skill and rule directories, so they survive the runtime cutoff.
///
/// The same directory is never stored as both global and project: an import run from the home directory finds
/// the same directories in both scans.
fn scan_claude_path_dirs(cwd: &Path, plan: &mut ImportPlan) {
    let mut global_added = HashSet::new();

    if let Some(home) = fuigo_dirs::home_dir() {
        for (kind, dir) in existing_claude_path_dirs(&home) {
            let canonical = dunce::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
            global_added.insert(canonical);
            plan.global_items.push(ImportableItem::PathEntry {
                kind,
                path: dir.to_string_lossy().to_string(),
            });
        }
    }

    let project_root = find_project_root(cwd);
    for (kind, dir) in existing_claude_path_dirs(&project_root) {
        let canonical = dunce::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
        if global_added.contains(&canonical) {
            debug!(
                path = %dir.display(),
                "Skipping project .claude/ path that resolves to the same dir as the global entry"
            );
            continue;
        }
        plan.project_items.push(ImportableItem::PathEntry {
            kind,
            path: dir.to_string_lossy().to_string(),
        });
    }
}

fn existing_claude_path_dirs(root: &Path) -> impl Iterator<Item = (PathKind, PathBuf)> {
    [(PathKind::Skill, "skills"), (PathKind::Rule, "rules")]
        .into_iter()
        .map(move |(kind, sub)| (kind, root.join(".claude").join(sub)))
        .filter(|(_, dir)| dir.is_dir())
}

#[cfg(test)]
#[path = "source_cla_tests.rs"]
mod tests;
