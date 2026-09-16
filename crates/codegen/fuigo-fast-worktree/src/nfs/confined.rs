//! Fd-relative helpers + the single owned deleter used by daemon-down `rm`
//! and `clean-artifacts`. Never a weaker sibling of `grove_git::delete_owned`.
/// A worktree id is only ever a single `[A-Za-z0-9._-]+` path/ref segment that does
/// not start with `.`.
///
/// This is exactly the shape `worktree::plan::sanitize_worktree_id_base` produces, and
/// it is the shape `refs/fuigo/worktrees/<id>` and `worktree-backing/<id>` both need:
/// anything outside it (a space, a newline, a control byte, a separator) could split a
/// git ref argument or escape the backing dir. Rejecting by charset rather than by a
/// deny-list of separators keeps this from being a weaker sibling of the daemon's own
/// validator.
pub fn is_safe_worktree_id(id: &str) -> bool {
    !id.is_empty()
        && !id.starts_with('.')
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}
