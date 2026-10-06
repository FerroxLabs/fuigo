//! What we have told one server about each open document.
//!
//! Two readers besides the client need this. Incremental servers require a
//! range on every change event, which is computed from where the previous
//! revision ended. And every diagnostic answer has to be attributed to a
//! document version — pull knows the version it asked about, and a pushed
//! report that omits `version` is credited with the newest version we had sent
//! when it arrived. Both of those happen off the client's thread, so the
//! versions live behind a shared handle rather than inside `LspClient`.

use std::collections::HashMap;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use async_lsp::lsp_types::Position;

/// The version a document is opened at.
///
/// Deliberately above [`super::diagnostics::NO_VERSION`], which is what a
/// report about a document we have never opened is credited: were they equal,
/// such a report would count as a verdict on our first edit to that file.
pub const FIRST_VERSION: i32 = 1;
const _: () = assert!(FIRST_VERSION > super::diagnostics::NO_VERSION);

/// The revision of one document that the server has.
#[derive(Debug, Clone)]
pub struct Tracked {
    /// Version of the last notification we successfully sent for it.
    pub version: i32,
    pub language_id: String,
    /// Where that revision ends. Two integers, not a copy of the text.
    pub end: Position,
}

/// What the next notification for a document should be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Update {
    /// The server has never seen this document.
    Open { version: i32 },
    /// The server has it at `previous_end`; send `version` next.
    Change {
        version: i32,
        previous_end: Position,
    },
}

impl Update {
    pub fn version(self) -> i32 {
        match self {
            Update::Open { version } | Update::Change { version, .. } => version,
        }
    }
}

/// Open documents for one server connection.
///
/// Cheap to clone (shared handle). Lock poisoning is recovered from in one
/// place: a panicking writer leaves the map structurally intact, and a stale
/// version beats no version at all.
#[derive(Debug, Clone, Default)]
pub struct Documents {
    inner: Arc<RwLock<HashMap<String, Tracked>>>,
    /// The version of a notification that is being put on the wire right now, per document,
    /// between [`Self::begin_send`] and [`Self::commit`]/[`Self::abandon_send`].
    ///
    /// The server can answer that notification before the sender gets to `commit` -- the
    /// reply is read on the connection's own task -- so a push naming the new version must
    /// not be capped at the old one. See [`Self::push_version_cap`].
    sending: Arc<RwLock<HashMap<String, i32>>>,
}

impl Documents {
    pub fn new() -> Self {
        Self::default()
    }

    /// What to send for `uri`, without recording it as sent.
    ///
    /// Deliberately separate from [`Self::commit`]: what is recorded here
    /// describes the text the *server* has, so a notification that failed to go
    /// out must not advance it. Advancing it anyway would aim every later
    /// incremental range at a revision the server never received — the same
    /// protocol violation the range exists to avoid.
    pub fn plan(&self, uri: &str) -> Update {
        match self.read().get(uri) {
            Some(tracked) => Update::Change {
                version: tracked.version.saturating_add(1),
                previous_end: tracked.end,
            },
            None => Update::Open {
                version: FIRST_VERSION,
            },
        }
    }

    /// Note that `version` of `uri` is about to be sent. Call before the send; follow with
    /// [`Self::commit`] once it is out, or [`Self::abandon_send`] if it failed.
    pub fn begin_send(&self, uri: &str, version: i32) {
        self.sending_write().insert(uri.to_string(), version);
    }

    /// The send begun by [`Self::begin_send`] did not go out.
    pub fn abandon_send(&self, uri: &str) {
        self.sending_write().remove(uri);
    }

    /// Record a notification that is on the wire.
    pub fn commit(&self, uri: &str, version: i32, language_id: &str, end: Position) {
        self.write()
            .entry(uri.to_string())
            .and_modify(|tracked| {
                tracked.version = version;
                tracked.end = end;
            })
            .or_insert_with(|| Tracked {
                version,
                language_id: language_id.to_string(),
                end,
            });
        // Cleared only AFTER the committed version has advanced: a reader that finds nothing in
        // flight is then guaranteed to find the new version committed.
        let mut sending = self.sending_write();
        if sending
            .get(uri)
            .is_some_and(|in_flight| *in_flight <= version)
        {
            sending.remove(uri);
        }
    }

    /// The newest version a pushed report can be about: the newest version we have sent, or are
    /// in the middle of sending. It caps a push that names its version, and is the arrival-order
    /// credit for one that does not.
    ///
    /// The server can receive a notification, analyze it and publish before the sender has
    /// recorded it as sent (the reply is read on the connection's own task). Using the committed
    /// version alone credited that report to the previous revision -- or, on a first open, to no
    /// revision at all -- so it never settled the edit it answered and the reader got nothing for
    /// that edit. Crediting from the moment the send begins rather than the moment it returns
    /// moves the arrival-order credit point by only the duration of the send call: a report about
    /// the old text arriving just after the commit was always equally indistinguishable.
    pub fn push_version_cap(&self, uri: &str) -> Option<i32> {
        // In-flight first, committed second; `commit` writes in the opposite order, so a send
        // that completes between the two reads is still seen.
        let in_flight = self.sending_read().get(uri).copied();
        let committed = self.version(uri);
        in_flight.max(committed)
    }

    /// The version the server has, or `None` if it has never been told about
    /// this document.
    pub fn version(&self, uri: &str) -> Option<i32> {
        self.read().get(uri).map(|tracked| tracked.version)
    }

    pub fn contains(&self, uri: &str) -> bool {
        self.read().contains_key(uri)
    }

    /// Every open document, as `(uri, language_id)` — what a restart replays.
    pub fn tracked(&self) -> Vec<(String, String)> {
        self.read()
            .iter()
            .map(|(uri, tracked)| (uri.clone(), tracked.language_id.clone()))
            .collect()
    }

    /// Every open document's URI. A refresh re-pulls all of them.
    pub fn uris(&self) -> Vec<String> {
        self.read().keys().cloned().collect()
    }

    /// Every open document with the version the server has, for re-asking
    /// questions a refresh has made open again.
    pub fn versions(&self) -> Vec<(String, i32)> {
        self.read()
            .iter()
            .map(|(uri, tracked)| (uri.clone(), tracked.version))
            .collect()
    }

    /// Forget everything, returning what was open so it can be closed.
    pub fn take_all(&self) -> Vec<String> {
        self.sending_write().clear();
        std::mem::take(&mut *self.write()).into_keys().collect()
    }

    /// Forget one document. Returns whether it was open.
    pub fn take(&self, uri: &str) -> bool {
        self.sending_write().remove(uri);
        self.write().remove(uri).is_some()
    }

    fn sending_read(&self) -> RwLockReadGuard<'_, HashMap<String, i32>> {
        self.sending.read().unwrap_or_else(|e| e.into_inner())
    }

    fn sending_write(&self) -> RwLockWriteGuard<'_, HashMap<String, i32>> {
        self.sending.write().unwrap_or_else(|e| e.into_inner())
    }

    fn read(&self) -> RwLockReadGuard<'_, HashMap<String, Tracked>> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> RwLockWriteGuard<'_, HashMap<String, Tracked>> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }
}

/// End position of `text`, i.e. the position just past its final character.
pub fn end_position(text: &str) -> Position {
    // `lines()` drops a trailing newline, which would give a position that is
    // short of the real end of the document, so count explicitly.
    let mut line = 0u32;
    let mut last_line_start = 0usize;
    for (idx, ch) in text.char_indices() {
        if ch == '\n' {
            line += 1;
            last_line_start = idx + 1;
        }
    }
    // LSP character offsets are UTF-16 code units.
    let character = text[last_line_start..].encode_utf16().count() as u32;
    Position { line, character }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "file:///a.cs";

    /// A push that names the version being sent is credited with it, before the sender commits.
    #[test]
    fn a_version_in_flight_caps_a_named_push() {
        let documents = Documents::new();
        // First open, answered before the sender commits.
        documents.begin_send(A, FIRST_VERSION);
        assert_eq!(documents.version(A), None, "nothing committed yet");
        assert_eq!(documents.push_version_cap(A), Some(FIRST_VERSION));
        documents.commit(A, FIRST_VERSION, "csharp", Position::default());
        assert_eq!(documents.push_version_cap(A), Some(FIRST_VERSION));

        // A change, answered before the sender commits.
        documents.begin_send(A, 2);
        assert_eq!(documents.version(A), Some(FIRST_VERSION));
        assert_eq!(documents.push_version_cap(A), Some(2));
        documents.commit(A, 2, "csharp", Position::default());
        assert_eq!(documents.push_version_cap(A), Some(2));
        assert!(
            documents.sending_read().get(A).is_none(),
            "a committed send leaves no in-flight claim behind"
        );
    }

    /// A send that failed leaves no claim behind.
    #[test]
    fn an_abandoned_send_does_not_raise_the_cap() {
        let documents = Documents::new();
        documents.commit(A, FIRST_VERSION, "csharp", Position::default());
        documents.begin_send(A, 2);
        documents.abandon_send(A);
        assert_eq!(documents.push_version_cap(A), Some(FIRST_VERSION));
        documents.begin_send(A, 2);
        assert!(documents.take(A));
        assert_eq!(documents.push_version_cap(A), None);
    }

    #[test]
    fn an_unknown_document_is_opened_above_the_no_version_marker() {
        let documents = Documents::new();
        assert_eq!(
            documents.plan(A),
            Update::Open {
                version: FIRST_VERSION
            }
        );
        assert_eq!(documents.version(A), None);
    }

    #[test]
    fn a_committed_document_is_changed_from_where_it_ended() {
        let documents = Documents::new();
        documents.commit(A, 1, "csharp", end_position("one\ntwo"));

        assert_eq!(
            documents.plan(A),
            Update::Change {
                version: 2,
                previous_end: Position {
                    line: 1,
                    character: 3
                },
            }
        );
        assert_eq!(documents.version(A), Some(1));
    }

    /// The plan is what to send; only a send that went out is committed. A
    /// failed one must leave the server's revision where it was, or the next
    /// incremental range will describe text the server never received.
    #[test]
    fn planning_alone_does_not_move_the_document() {
        let documents = Documents::new();
        documents.commit(A, 0, "csharp", end_position("one"));

        let planned = documents.plan(A);
        assert_eq!(
            documents.plan(A),
            planned,
            "planning twice is the same plan"
        );
        assert_eq!(documents.version(A), Some(0));
    }

    fn position(line: u32, character: u32) -> Position {
        Position { line, character }
    }

    #[test]
    fn end_position_counts_the_trailing_newline_as_a_new_line() {
        assert_eq!(end_position(""), position(0, 0));
        assert_eq!(end_position("abc"), position(0, 3));
        assert_eq!(end_position("abc\n"), position(1, 0));
        assert_eq!(end_position("const x = 1;\nabcde"), position(1, 5));
        assert_eq!(end_position("a\nb\nc\n"), position(3, 0));
    }

    #[test]
    fn end_position_measures_in_utf16_code_units() {
        // Astral-plane characters are two UTF-16 units; 'é' is one.
        assert_eq!(end_position("é"), position(0, 1));
        assert_eq!(end_position("🚀"), position(0, 2));
        assert_eq!(end_position("a\n🚀b"), position(1, 3));
    }

    #[test]
    fn take_all_empties_the_map() {
        let documents = Documents::new();
        documents.commit(A, FIRST_VERSION, "csharp", Position::default());
        assert_eq!(documents.take_all(), vec![A.to_string()]);
        assert!(documents.uris().is_empty());
        assert!(!documents.contains(A));
    }
}
