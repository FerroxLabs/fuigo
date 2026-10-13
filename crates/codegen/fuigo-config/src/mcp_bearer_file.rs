//! Small shared helpers for the MCP `bearer_token_file` setting: the user's home directory and a visible note when the
//! setting is ignored or refuses a server. The notes go where the saved-key refusals go (the log at warn level, and the
//! notice list `fuigo inspect` and the session show).

use std::path::PathBuf;

/// The user's home directory, for a `~/` path.
pub fn home_dir() -> Option<PathBuf> {
    fuigo_dirs::home_dir()
}

/// Record `note` once per process as a visible warning. The note must not hold file content.
pub fn record_note(note: String) {
    crate::key_naming::record_plain_note(note);
}
