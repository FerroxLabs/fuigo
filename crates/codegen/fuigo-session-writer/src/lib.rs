//! The one write choke point for session folders (Fuigo 1.0.41, F5; design §5).
//!
//! Every mutation of a path inside a session folder, from any crate, goes through a [`SessionWriter`] (or a
//! [`SessionAppend`] it hands out). This crate is a leaf (`std`, `tokio`, `tracing`, `dunce`, `fuigo-config`,
//! `fuigo-secrets`) so that every crate that writes session folders can hold the token: `fuigo-shell`, `fuigo-tools`,
//! `fuigo-session-events` and `fuigo-shell-terminal`.
//!
//! - [`lock`]: the 1.0.30 cross-process writer lock, moved here unchanged.
//! - `owner_only`: the owner-only session file helpers, moved here unchanged (Windows branch excepted, see the module).
//! - [`SessionWriter`]: the counted in-process slot, the OS hold attached by the first mutating call, the write API.
//! - [`trace`]: the B-F5 attribution marks, off unless `FUIGO_F5_TRACE_DIR` is set.

pub mod lock;
#[doc(hidden)]
pub mod owner_only;
pub mod trace;
mod writer;

/// Test-only pause points (`cfg(test)`, or the `test-support` feature for other crates' tests).
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod seams;

pub use writer::{
    Busy, ClaimError, DELETING_PREFIX, LOCK_SIDECARS, Refusal, ReplaceError, SessionAppend, SessionWriter, delete_observer,
    disable_persistence, persistence_disabled, refusal,
};

#[cfg(debug_assertions)]
pub use writer::debug_live_writers;

#[allow(clippy::disallowed_methods, reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there")]
#[cfg(test)]
#[path = "writer_tests.rs"]
mod writer_tests;
