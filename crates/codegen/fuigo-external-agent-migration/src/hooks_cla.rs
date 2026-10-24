use std::path::Path;

use tracing::{debug, warn};

use super::config_values::ImportableItem;
use super::error::MigrationError;

/// Parse the source `hooks` JSON of the settings file at `path` into [`ImportableItem::Hook`] items.
///
/// The `hooks` shape:
/// ```json
/// {
///   "hooks": {
///     "PreToolUse": [
///       { "matcher": "Bash", "hooks": [{ "type": "command", "command": "echo x", "timeout": 5 }] }
///     ]
///   }
/// }
/// ```
///
/// Each command handler becomes one item. HTTP handlers and other types are skipped: only shell commands are
/// imported. An unreadable or unparseable file yields nothing.
#[must_use]
pub fn extract_hooks_from_settings_file(path: &Path) -> Vec<ImportableItem> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) else {
        return Vec::new();
    };
    let Some(hooks_obj) = value.get("hooks").and_then(|v| v.as_object()) else {
        return Vec::new();
    };

    let mut items = Vec::new();
    for (event, groups_val) in hooks_obj {
        let Some(groups) = groups_val.as_array() else {
            continue;
        };
        for group in groups {
            let matcher = group
                .get("matcher")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            let Some(handlers) = group.get("hooks").and_then(|v| v.as_array()) else {
                continue;
            };
            for handler in handlers {
                let handler_type = handler.get("type").and_then(|v| v.as_str()).unwrap_or("");
                if handler_type != "command" {
                    debug!(
                        path = %path.display(),
                        event = %event,
                        handler_type = %handler_type,
                        "Skipping non-command hook handler during import"
                    );
                    continue;
                }
                let Some(command) = handler.get("command").and_then(|v| v.as_str()) else {
                    continue;
                };
                let timeout = handler.get("timeout").and_then(serde_json::Value::as_u64);
                items.push(ImportableItem::Hook {
                    event: event.clone(),
                    matcher: matcher.clone(),
                    command: command.to_string(),
                    timeout,
                });
            }
        }
    }
    items
}

/// What [`merge_hooks`] decided for `imported-from-claude.json`.
#[derive(Debug, Default)]
pub struct HooksMerge {
    /// The text to write, or `None` when nothing changed.
    pub contents: Option<String>,
    /// Hook entries newly added. A timeout refreshed in place changes `contents` but is not counted.
    pub added: usize,
}

/// Merge the [`ImportableItem::Hook`] items of `items` into `current` (the text of the destination
/// `imported-from-claude.json`, `None` when the file does not exist). `target` only names the file in errors.
///
/// The output is the JSON shape Fuigo's native hook loader reads from `.fuigo/hooks/*.json`, so no separate
/// config-side parser is needed. An entry with the same `(event, matcher, command)` is not added again; instead
/// its `timeout` is refreshed in place (or removed when the new hook has none), so re-importing after a timeout
/// change shows up in the output. A destination that is not JSON is replaced with fresh content, with a warning;
/// one that is JSON of the wrong shape is refused.
///
/// # Errors
///
/// A root, `hooks` value or event entry of the wrong JSON type, or a serialization failure.
pub fn merge_hooks(
    target: &Path,
    current: Option<&str>,
    items: &[ImportableItem],
) -> Result<HooksMerge, MigrationError> {
    let new_hooks: Vec<&ImportableItem> = items
        .iter()
        .filter(|item| matches!(item, ImportableItem::Hook { .. }))
        .collect();
    if new_hooks.is_empty() {
        return Ok(HooksMerge::default());
    }

    let mut root: serde_json::Value = match current {
        Some(text) => serde_json::from_str(text).unwrap_or_else(|error| {
            warn!(
                path = %target.display(),
                error = %error,
                "Existing imported-from-claude.json is malformed; replacing with fresh content. \
                 Manual edits in the malformed file will be lost."
            );
            serde_json::json!({})
        }),
        None => serde_json::json!({}),
    };
    let root_obj = root
        .as_object_mut()
        .ok_or_else(|| MigrationError::NotAJsonObject {
            place: format!("{}: root", target.display()),
        })?;
    let hooks_obj = root_obj
        .entry("hooks".to_string())
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(|| MigrationError::NotAJsonObject {
            place: format!("{}: hooks", target.display()),
        })?;

    let mut added = 0usize;
    // Whether the JSON changed at all, including an in-place timeout refresh that adds no entry.
    let mut dirty = false;
    for item in new_hooks {
        let ImportableItem::Hook {
            event,
            matcher,
            command,
            timeout,
        } = item
        else {
            continue;
        };

        let groups = hooks_obj
            .entry(event.clone())
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut()
            .ok_or_else(|| MigrationError::NotAJsonArray {
                path: target.to_path_buf(),
                event: event.clone(),
            })?;

        if refresh_existing_hook_timeout(groups, matcher.as_deref(), command, *timeout) {
            debug!(
                event = %event,
                matcher = ?matcher,
                command = %command,
                timeout = ?timeout,
                "Hook already present; refreshed timeout in place"
            );
            dirty = true;
            continue;
        }

        let mut handler = serde_json::Map::new();
        handler.insert("type".to_string(), serde_json::json!("command"));
        handler.insert("command".to_string(), serde_json::json!(command));
        if let Some(timeout) = timeout {
            handler.insert("timeout".to_string(), serde_json::json!(timeout));
        }
        let mut group = serde_json::Map::new();
        group.insert(
            "hooks".to_string(),
            serde_json::Value::Array(vec![serde_json::Value::Object(handler)]),
        );
        if let Some(matcher) = matcher {
            group.insert("matcher".to_string(), serde_json::json!(matcher));
        }
        groups.push(serde_json::Value::Object(group));
        added += 1;
    }

    if added == 0 && !dirty {
        return Ok(HooksMerge {
            contents: None,
            added,
        });
    }
    let contents = serde_json::to_string_pretty(&root).map_err(|source| {
        MigrationError::JsonSerialize {
            path: target.to_path_buf(),
            source,
        }
    })?;
    Ok(HooksMerge {
        contents: Some(contents),
        added,
    })
}

/// Update the timeout of the existing `(matcher, command)` handler. The matcher comparison only distinguishes
/// `None` from `Some(s)`, because extraction filters empty matcher strings to `None`.
fn refresh_existing_hook_timeout(
    groups: &mut [serde_json::Value],
    matcher: Option<&str>,
    command: &str,
    timeout: Option<u64>,
) -> bool {
    for group in groups.iter_mut() {
        if group.get("matcher").and_then(|v| v.as_str()) != matcher {
            continue;
        }
        let Some(handlers) = group.get_mut("hooks").and_then(|h| h.as_array_mut()) else {
            continue;
        };
        for handler in handlers.iter_mut() {
            let is_command = handler.get("type").and_then(|v| v.as_str()) == Some("command")
                && handler.get("command").and_then(|v| v.as_str()) == Some(command);
            if !is_command {
                continue;
            }
            if let Some(handler_obj) = handler.as_object_mut() {
                match timeout {
                    Some(timeout) => {
                        handler_obj.insert("timeout".to_string(), serde_json::json!(timeout));
                    }
                    None => {
                        handler_obj.remove("timeout");
                    }
                }
            }
            return true;
        }
    }
    false
}

#[cfg(test)]
#[path = "hooks_cla_tests.rs"]
mod tests;
