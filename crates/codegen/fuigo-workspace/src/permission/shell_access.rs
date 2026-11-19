//! Detect file reads/writes inside a shell command so a managed `Read`/`Edit` deny/ask can't be bypassed via a shell reader/writer/redirect.

use std::path::Path;

use tree_sitter::Node;

mod peer_cmd;
mod tripwire;
use tripwire::CommandExtras;

use crate::permission::bash_command_splitting::{
    MAX_INLINE_SHELL_DEPTH, MAX_WRAPPER_DEPTH, decode_shell_literal_spelling,
    normalize_command_words, try_parse_shell,
};
use crate::permission::exec_risk::{
    attached_git_c_path, config_words_set_command_valued, is_accepted_long_option_prefix,
    is_attached_git_config_c, is_git_config_env_flag, is_git_exec_env_assignment,
    is_git_repo_retarget_flag,
};
use crate::permission::policy::{
    CompiledPolicy, GateDecision, InlineShellScript, RuleBase, ShellWord, SymlinkFollow,
    combine_gate_decisions, follow_absolute_symlink, path_has_parent_dir,
    resolve_following_symlinks, resolve_following_symlinks_for_comparison, shell_dash_c_script,
};
use crate::permission::types::{AccessKind, Decision};

mod argument_decoding;
mod compiled_policy;
mod destination_writes;
mod git_writes;
mod protected_paths;
mod write_extraction;
mod write_facts;

pub use self::argument_decoding::*;
pub use self::compiled_policy::*;
pub use self::destination_writes::*;
pub use self::git_writes::*;
pub use self::protected_paths::*;
pub use self::write_extraction::*;
pub use self::write_facts::*;

#[cfg(test)]
mod tests;
