//! Import another agent's settings (today: Claude's) into Fuigo configuration.
//!
//! This crate plans and merges; it does not own the file writes. [`scan_importable_settings`] turns the source
//! settings the caller has already read into an [`ImportPlan`], and [`merge_items_into_config`],
//! [`merge_hooks`] and [`marker_config_text`] turn a plan plus the current text of the destination file into the
//! text to write. The caller (`fuigo-shell`) reads the source files, takes the destination's lock, and writes the
//! result owner-only, so imported credentials never sit in a looser file than the config they merge into.
//!
//! Every merge is additive: existing entries are never removed or overwritten, and a destination that does not
//! parse is refused rather than rewritten.
#![deny(clippy::indexing_slicing)]
// The tests read parsed JSON/TOML by key and assert on the result; only shipped code must not index.
#![cfg_attr(test, allow(clippy::indexing_slicing))]

mod config_values;
mod error;
mod hooks_cla;
mod reporting;
mod rewrite;
mod scope;
mod source_cla;

pub use config_values::{
    ClaudeSettingsSnapshot, ImportPatternMode, ImportPermission, ImportPlan, ImportResult,
    ImportRuleAction, ImportTool, ImportableItem, PathKind, format_rule_string, redacted_env_value,
};
pub use error::MigrationError;
pub use hooks_cla::{
    HooksMerge, extract_hooks_from_settings_file, extract_hooks_from_settings_file_in, merge_hooks,
};
pub use rewrite::{ConfigPatch, marker_config_text, merge_items_into_config};
pub use scope::find_project_root;
pub use source_cla::scan_importable_settings;
