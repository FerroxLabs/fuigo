//! Moved to `fuigo_config::write_through` in P49, so `fuigo-workspace`'s
//! worktree apply shares the same replacement (symlinks written through,
//! mode/owner/ACLs preserved, owner-only temp). The writers in [`super`] and
//! their tests reach it through these names.

pub(crate) use fuigo_config::write_through::stage_file_atomically;
#[cfg(test)]
pub(crate) use fuigo_config::write_through::{create_temp_with, fault, write_file_atomically};

#[cfg(test)]
#[path = "atomic_write_tests.rs"]
mod tests;
