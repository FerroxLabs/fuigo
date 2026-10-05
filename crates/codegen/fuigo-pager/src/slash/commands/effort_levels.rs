//! Shared reasoning-effort dropdown levels for `/model` and `/effort`.

use fuigo_shell::sampling::types::{ReasoningEffort, ReasoningEffortOption};

use crate::slash::command::ArgItem;

/// Effort levels in the built-in fallback menu (strongest first).
/// `none`/`minimal` are still accepted by `ReasoningEffort::from_str` for power users.
pub(crate) const EFFORT_LEVELS: &[ReasoningEffort] = &[
    ReasoningEffort::Xhigh,
    ReasoningEffort::High,
    ReasoningEffort::Medium,
    ReasoningEffort::Low,
];

pub(crate) fn effort_description(level: ReasoningEffort) -> &'static str {
    match level {
        ReasoningEffort::None => "No reasoning",
        ReasoningEffort::Minimal => "Minimal reasoning",
        ReasoningEffort::Low => "Faster, lighter reasoning",
        ReasoningEffort::Medium => "Balanced reasoning",
        ReasoningEffort::High => "Heavy reasoning",
        ReasoningEffort::Xhigh => "Extended reasoning",
        ReasoningEffort::Max => "Maximum reasoning",
    }
}

/// The built-in menu used when the server sends no `reasoningEfforts`.
/// Reproduces the historical rows: labels are the lowercase level (via `Display`), descriptions from `effort_description`.
/// The active row is matched by value against the session effort at render time, so `default` is left unset here.
pub(crate) fn legacy_effort_options() -> Vec<ReasoningEffortOption> {
    EFFORT_LEVELS
        .iter()
        .map(|&level| ReasoningEffortOption {
            id: level.as_str().to_string(),
            value: level,
            label: level.to_string(),
            description: Some(effort_description(level).to_string()),
            default: false,
        })
        .collect()
}

/// `'a'` for the first row through `'z'` for the 26th; every later row shares `'z'`.
/// The prefix only breaks matcher ties in menu order, so a shared tail prefix costs nothing
/// a reasoning-effort menu will notice, and the arithmetic can never leave `u8`.
pub(crate) fn sort_prefix_for(idx: usize) -> char {
    const LAST: u8 = b'z' - b'a';
    char::from(b'a' + u8::try_from(idx).unwrap_or(LAST).min(LAST))
}


/// Build effort rows for autocomplete from a per-model option list.
///
/// - `mark_active` and `current_effort` mark the current session effort with `(active)`.
/// - `insert_text_for` controls what is inserted on select:
///   - `/effort`: the option id (`"deep"`)
///   - `/model` chained phase: `"ModelName deep"`
///
/// `match_text` gets an `a `/`b `/…` sort prefix so the matcher's alphabetical tiebreak preserves the option order.
pub(crate) fn build_effort_arg_items(
    options: &[ReasoningEffortOption],
    current_effort: Option<ReasoningEffort>,
    mark_active: bool,
    insert_text_for: impl Fn(&ReasoningEffortOption) -> String,
) -> Vec<ArgItem> {
    options
        .iter()
        .enumerate()
        .map(|(idx, option)| {
            let active = mark_active && current_effort == Some(option.value);
            let active_suffix = if active { " (active)" } else { "" };
            let insert_text = insert_text_for(option);
            // Sort-key prefix: 'a' for top row, 'b' for next, etc
            // Only affects matcher tiebreak ordering, never rendered
            // Rows past the 26th share 'z': the server list is a handful of levels, and an
            // unbounded `b'a' + idx` overflowed `u8` at the 160th option (a debug-build panic)
            let sort_prefix = sort_prefix_for(idx);
            ArgItem {
                display: format!("{}{active_suffix}", option.label),
                match_text: format!("{sort_prefix} {insert_text}"),
                insert_text,
                description: option.description.clone().unwrap_or_default(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sort_prefix_runs_a_to_z_then_saturates() {
        assert_eq!(sort_prefix_for(0), 'a');
        assert_eq!(sort_prefix_for(3), 'd');
        assert_eq!(sort_prefix_for(25), 'z');
        assert_eq!(sort_prefix_for(26), 'z');
        assert_eq!(sort_prefix_for(159), 'z');
        assert_eq!(sort_prefix_for(usize::MAX), 'z');
    }

    /// 160 valid options used to overflow `b'a' + idx as u8` (debug panic, release wrap into
    /// control characters); now every row builds and the first 26 keep their order.
    #[test]
    fn one_hundred_sixty_effort_options_build_without_overflow() {
        let options: Vec<ReasoningEffortOption> = (0..160)
            .map(|i| ReasoningEffortOption {
                id: format!("level-{i}"),
                value: ReasoningEffort::Medium,
                label: format!("Level {i}"),
                description: None,
                default: false,
            })
            .collect();
        let items = build_effort_arg_items(&options, None, false, |o| o.id.clone());
        assert_eq!(items.len(), 160);
        assert!(items[0].match_text.starts_with("a "));
        assert!(items[25].match_text.starts_with("z "));
        assert!(items[159].match_text.starts_with("z "));
        assert!(items.iter().all(|i| i.match_text.chars().next().is_some_and(|c| c.is_ascii_lowercase())));
    }
}
