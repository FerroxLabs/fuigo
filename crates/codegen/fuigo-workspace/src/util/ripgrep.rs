// Resolution (bundled binary, RG_BIN_PATH, Bazel runfiles, PATH) lives in the fuigo-tools crate
// This module only preserves the `crate::util::ripgrep` path
pub use fuigo_tools::util::rg_path;
