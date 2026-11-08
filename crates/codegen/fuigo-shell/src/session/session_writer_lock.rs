//! One writer per session across processes (1.0.30 P30-DIRECT).
//!
//! The lock moved to [`fuigo_session_writer::lock`] in 1.0.41 (F5-W), so that every crate writing a session folder can
//! reach it through `SessionWriter`. This path re-exports it unchanged for the call sites that still use it, and keeps
//! what belongs to the shell: the ACP error conversion and [`session_open_elsewhere`], which resolves an id to a folder.

use std::path::Path;

pub use fuigo_session_writer::lock::HELD_ELSEWHERE;
pub(crate) use fuigo_session_writer::lock::{SESSION_WRITER_LOCK_FILE, SessionWriterLock, dir_open_elsewhere};

/// Another process holds the session.
#[derive(Debug)]
pub(crate) struct HeldElsewhere;

impl HeldElsewhere {
    pub(crate) fn into_acp_error(self) -> agent_client_protocol::Error {
        held_elsewhere_error()
    }
}

/// The refusal an open of a session held elsewhere answers: typed `session_unavailable` (clients that tell "held
/// elsewhere" from "missing" keep working), with [`HELD_ELSEWHERE`] as the headline too, so a window shows it as it is and
/// not under a generic "Internal error".
pub fn held_elsewhere_error() -> agent_client_protocol::Error {
    crate::acp_error::session_unavailable_headline(HELD_ELSEWHERE)
}

/// What a rename (or `/rename --auto`) of a session open in another process answers: that window owns its title.
pub const RENAME_HELD_ELSEWHERE: &str = "This session is open in another Fuigo window. Rename it there.";

/// [`RENAME_HELD_ELSEWHERE`] as a typed `session_unavailable`, like [`held_elsewhere_error`].
pub fn rename_held_elsewhere_error() -> agent_client_protocol::Error {
    crate::acp_error::session_unavailable_headline(RENAME_HELD_ELSEWHERE)
}

/// Whether `error` is the session writer's refusal for a session another process holds.
pub(crate) fn is_held_elsewhere(error: &std::io::Error) -> bool {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<fuigo_session_writer::Refusal>())
        .is_some_and(|refusal| *refusal == fuigo_session_writer::Refusal::HeldElsewhere)
}

/// What a claim that waited out its bound answers (design F5 §5.5): this process still has a writer of the session.
pub const STILL_CLOSING: &str = "This session is still closing. Try again in a moment.";

/// What a claim that must not wait answers when this process has the session open (fork target, import; §5.5).
pub const OPEN_HERE: &str = "This session is open. Close it first.";

/// How long a claim waits for this process's previous writer of the id (design F5 §5.5, §6.2).
pub(crate) const CLAIM_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// [`STILL_CLOSING`] as a typed `session_unavailable`, like [`held_elsewhere_error`].
pub fn still_closing_error() -> agent_client_protocol::Error {
    crate::acp_error::session_unavailable_headline(STILL_CLOSING)
}

/// [`OPEN_HERE`] as a typed `session_unavailable`.
pub fn open_here_error() -> agent_client_protocol::Error {
    crate::acp_error::session_unavailable_headline(OPEN_HERE)
}

/// Claim the writer of session `id` (folder `dir`), waiting up to [`CLAIM_WAIT`] for a previous writer of the id in
/// this process, with the eager OS attach (design F5 §5.5): `still closing` or `held elsewhere` otherwise.
pub(crate) async fn claim_writer(
    id: &str,
    dir: std::path::PathBuf,
) -> Result<fuigo_session_writer::SessionWriter, agent_client_protocol::Error> {
    let deadline = tokio::time::Instant::now() + CLAIM_WAIT;
    fuigo_session_writer::SessionWriter::claim(id, dir, deadline).await.map_err(|error| match error {
        fuigo_session_writer::ClaimError::StillClosing => still_closing_error(),
        fuigo_session_writer::ClaimError::HeldElsewhere => held_elsewhere_error(),
    })
}

/// Take the writer of session `id` (folder `dir`) without waiting, for an operation that refuses an open session
/// (fork target, import, subagent child; design F5 §5.5): `This session is open...` when this process has a writer of
/// it. The OS hold attaches at the first write, which refuses with `held elsewhere` and writes nothing.
pub(crate) fn try_claim_writer(
    id: &str,
    dir: std::path::PathBuf,
) -> Result<fuigo_session_writer::SessionWriter, agent_client_protocol::Error> {
    fuigo_session_writer::SessionWriter::try_claim(id, dir).map_err(|_busy| open_here_error())
}

/// Take this process's hold on the session in `session_dir` for writing ([`fuigo_session_writer::lock::acquire`]).
pub(crate) async fn acquire(session_dir: &Path) -> Result<Option<SessionWriterLock>, HeldElsewhere> {
    fuigo_session_writer::lock::acquire(session_dir).await.map_err(|fuigo_session_writer::lock::HeldElsewhere| HeldElsewhere)
}

/// Whether another process has the persisted session `session_id` open for writing: a starting window's check before it
/// opens the session, so it can refuse with [`HELD_ELSEWHERE`] instead of starting. Never creates the lock file. The
/// agent's own open stays the authority; this is only the early answer.
pub fn session_open_elsewhere(session_id: &str) -> bool {
    crate::session::persistence::find_persisted_session_dir(session_id).is_some_and(|dir| dir_open_elsewhere(&dir))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The refusal keeps its ACP shape and headline (the lock's own tests moved with it).
    #[test]
    fn a_refusal_is_session_unavailable_with_the_held_elsewhere_headline() {
        let error = HeldElsewhere.into_acp_error();
        assert!(format!("{error:?}").contains(HELD_ELSEWHERE), "{error:?}");
    }
}
