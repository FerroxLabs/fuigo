//! Session files readable by their owner only (P120, R113 R3.5).
//!
//! Moved to `fuigo_session_writer::owner_only` in 1.0.41 (F5-W); this path re-exports it unchanged for the call sites
//! that still use it, until they write through `SessionWriter` (F5-C).

pub(crate) use fuigo_session_writer::owner_only::{copy, copy_async, create, open, owner_only, tighten, write, write_async};
