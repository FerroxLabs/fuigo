//! Moved to `fuigo_config::write_through` in P49, so `fuigo-workspace`'s
//! worktree apply shares the same replacement (symlinks written through,
//! mode/owner/ACLs preserved, owner-only temp). The writers in [`super`] and
//! their tests reach it through these names.

pub(crate) use fuigo_config::write_through::stage_file_atomically;
#[cfg(test)]
pub(crate) use fuigo_config::write_through::{create_temp_with, fault, write_file_atomically};

#[allow(clippy::disallowed_methods, reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there")]
#[cfg(test)]
#[path = "atomic_write_tests.rs"]
mod tests;
