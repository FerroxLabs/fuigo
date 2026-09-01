//! Shared utilities used by both `fuigo-shell` and its downstream clients (e.g. `fuigo-pager-render`).
//! This crate sits upstream of `fuigo-shell` so it must never depend on it.

pub mod clipboard;
pub mod placeholder_images;
pub mod session;
pub mod stderr;
pub mod ui_config;
