#![allow(
    unused_imports,
    unused_variables,
    unused_mut,
    unreachable_code,
    dead_code
)]
//! fuigo-pager: Fuigo TUI.
//!
//! A clean-room implementation built on the v3 pager rendering engine.
// CLI output goes through `fuigo_tty_utils::cli_println!`/`cli_print!`: a raw `println!` panics when
// stdout's reader is gone and `panic = "abort"` makes that a SIGABRT (R060). Build scripts and the
// best-effort macros themselves are the only places that write stdout directly.
#![deny(clippy::print_stdout)]
// Diagnostics go through `fuigo_tty_utils::cli_eprintln!`/`cli_eprint!` for the same reason: a raw
// `eprintln!` (or `dbg!`) panics when fd 2 is a dead pipe, a closed pane or a full disk (R070).
// Denied outside tests, where a failed harness stderr is not a shipped crash.
#![cfg_attr(not(test), deny(clippy::print_stderr, clippy::dbg_macro))]
pub mod acp;
pub mod actions;
pub mod app;
pub mod best_effort_stderr;
pub mod best_effort_stdout;
pub mod client_identity;
pub mod completions_cmd;
mod config_toml_edit;
mod config_write_queue;
pub mod diagnostics;
pub mod disk_usage_cmd;
pub mod docs;
pub mod doctor_cmd;
pub mod export_cmd;
pub(crate) mod fs_size;
pub mod git_info;
pub mod headless;
pub mod hyperlink_route;
pub mod inline_media_ffmpeg;
pub mod input_log;
pub mod mcp_cmd;
pub mod memory_cmd;
pub mod memory_release;
pub mod memory_trace;
#[path = "minimal/api.rs"]
pub mod minimal_api;
#[path = "minimal/hook.rs"]
pub mod minimal_hook;
pub mod models;
pub mod notifications;
#[allow(unused_imports, unused_macros)]
pub mod obf;
pub mod plugin_cmd;
mod provider_config_edit;
pub mod pty_wrap;
pub mod recent_dirs;
pub mod scrollback;
pub mod sessions_cmd;
pub mod settings;
pub mod share_cmd;
pub mod slash;
pub mod startup;
pub mod tips;
pub mod tool_usage;
pub mod tutorial_docs;
pub mod usage_cmd;
pub mod wrap_clipboard_image;
pub mod wrap_cmd;
pub(crate) mod wrap_filter;
pub(crate) mod wrap_restore;
pub use fuigo_gboom as gboom;
pub use fuigo_pager_render::key;
pub use fuigo_pager_render::{
    appearance, clipboard, glyphs, host, input, link_opener, modal_window_state, prompt_images,
    render, search, syntax, terminal, theme, util,
};
#[cfg(test)]
pub mod test_util;
#[cfg(test)]
mod theme_pin_guard_tests;
pub mod trace_cmd;
pub mod tracing;
pub mod unified_log;
pub mod views;
pub mod voice;
pub mod worktree_cmd;

/// Pins the insta setup that keeps test runs from writing into the source tree (`.cargo/config.toml` `[env]` + `.config/insta.yaml`).
#[cfg(test)]
mod insta_source_tree_tests {
    use std::path::Path;

    /// insta resolves its workspace root with `cargo metadata` at test time unless `INSTA_WORKSPACE_ROOT` was baked in at compile time.
    /// When that lookup fails (a test binary run directly, no cargo on `PATH`) it falls back to the crate directory,
    /// misses every committed snapshot, and writes a `.snap.new` per test under `crates/codegen/fuigo-pager/crates/...`.
    #[test]
    fn workspace_root_is_baked_in_so_a_direct_run_never_needs_cargo_metadata() {
        let Some(root) = option_env!("INSTA_WORKSPACE_ROOT") else {
            panic!(
                "INSTA_WORKSPACE_ROOT is not set at compile time; restore the [env] entry in .cargo/config.toml"
            );
        };
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert!(
            manifest.starts_with(root) && Path::new(root).join("Cargo.lock").is_file(),
            "INSTA_WORKSPACE_ROOT={root:?} is not the workspace root containing {manifest:?}"
        );
    }

    /// `behavior.update: no` is the second line of defence: even a mismatch writes nothing, only fails with its diff.
    #[test]
    fn insta_config_forbids_writing_snapshot_files() {
        let Some(root) = option_env!("INSTA_WORKSPACE_ROOT") else {
            panic!("INSTA_WORKSPACE_ROOT is not set at compile time");
        };
        let cfg = std::fs::read_to_string(Path::new(root).join(".config/insta.yaml"))
            .expect("workspace .config/insta.yaml must exist");
        // `behavior:` at column 0, then an indented `update:` inside it; a trailing `# comment` is not part of the value
        let mut in_behavior = false;
        let mut update = None;
        for line in cfg.lines() {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            if !line.starts_with(char::is_whitespace) {
                in_behavior = line.trim_end() == "behavior:";
            } else if in_behavior && let Some(v) = line.trim().strip_prefix("update:") {
                let v = v.split(" #").next().unwrap_or("").trim().trim_matches('"');
                update = Some(v.to_string());
            }
        }
        let update_no = update.as_deref() == Some("no");
        assert!(update_no, "insta.yaml must set `behavior.update: \"no\"`:\n{cfg}");
    }
}
