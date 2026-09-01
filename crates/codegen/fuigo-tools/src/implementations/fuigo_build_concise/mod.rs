//! `FuigoBuildConcise` namespace — concise variants of core FuigoBuild tools.
//!
//! These tools share implementation with `fuigo_build` via `pub(crate)` helpers
//! but produce concise output (compact line numbers, shorter messages,
//! concise bash formatting).

pub mod bash;
pub mod read_file;
pub mod search_replace;

pub use bash::BashConciseTool;
pub use read_file::ReadFileConciseTool;
pub use search_replace::SearchReplaceConciseTool;
