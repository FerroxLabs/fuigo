//! P188: what the current model response has streamed to clients that history has not accepted yet.
//!
//! A request that fails after streaming text is resent (by the sampler's retry loop or by the turn loop), and every
//! chunk of the failed attempt has already reached the client. Fuigo's own history keeps only the accepted attempt,
//! so without a signal an ACP client shows attempt 1 + attempt 2 + attempt 3 joined together. The session actor
//! notes here each visible chunk it forwards, and the next `RetryState::Retrying` it sends while anything is noted
//! carries `discardEmitted: true` (see [`crate::extensions::notification::RetryState::Retrying`]), which clears
//! the note. Committing the response to history (`record_response_items`) or starting a turn clears it too.

/// Unaccepted visible output of the current model response. Shared by the sampler-event drainer (which notes
/// chunks) and the turn loop (which accepts responses and sends retries), both on the session's `LocalSet`.
#[derive(Debug, Default)]
pub(crate) struct UnacceptedOutput {
    inner: parking_lot::Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    emitted: bool,
    message_id: Option<String>,
    /// `_meta.streamStartMs` of the attempt now streaming (`SamplingEvent::StreamStarted`).
    stream_start_ms: Option<i64>,
    /// Hosted-tool rows (`call_id`, tool name) sent as `tool_call` `in_progress` and not yet completed. A resend closes them.
    open_hosted: Vec<(String, String)>,
}

/// What a resend must void: the discarded response's provider id and the stream start its updates carried.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Discard {
    pub(crate) message_id: Option<String>,
    pub(crate) stream_start_ms: Option<i64>,
}

impl UnacceptedOutput {
    /// A visible chunk of the current response went to clients.
    pub(crate) fn note_emitted(&self) {
        self.inner.lock().emitted = true;
    }

    /// A new attempt began streaming at wall-clock `stream_start_ms`. Returns the attempt's id, which its updates
    /// carry as `_meta.streamStartMs`: that time, nudged past the previous attempt's id when the clock gives the same
    /// millisecond (or steps back), so no two attempts of a session ever share one and a discard names exactly one.
    pub(crate) fn claim_stream_start(&self, stream_start_ms: i64) -> i64 {
        let mut state = self.inner.lock();
        let id = match state.stream_start_ms {
            Some(previous) if stream_start_ms <= previous => previous + 1,
            _ => stream_start_ms,
        };
        state.stream_start_ms = Some(id);
        id
    }

    /// A hosted-tool row went to clients as `in_progress`: it is visible output, and it must be closed if the attempt dies.
    pub(crate) fn note_hosted_started(&self, call_id: &str, name: &str) {
        let mut state = self.inner.lock();
        state.emitted = true;
        if !state.open_hosted.iter().any(|(id, _)| id == call_id) {
            state.open_hosted.push((call_id.to_owned(), name.to_owned()));
        }
    }

    /// A hosted-tool row reached a terminal status: nothing to close. It marks no output of its own: a row that was
    /// shown already marked the attempt when it started, and a completion for a row never shown draws nothing.
    pub(crate) fn note_hosted_finished(&self, call_id: &str) {
        let mut state = self.inner.lock();
        state.open_hosted.retain(|(id, _)| id != call_id);
    }

    /// The hosted-tool rows still `in_progress`, taken (cleared) so each is closed exactly once.
    pub(crate) fn take_open_hosted(&self) -> Vec<(String, String)> {
        std::mem::take(&mut self.inner.lock().open_hosted)
    }

    /// Whether visible output awaits acceptance (a resend now owes a discard).
    pub(crate) fn is_owed(&self) -> bool {
        self.inner.lock().emitted
    }

    /// The current response's provider message id (Messages API `response_started`).
    pub(crate) fn note_message_id(&self, message_id: String) {
        self.inner.lock().message_id = Some(message_id);
    }

    /// Whether a resend now must tell clients to discard output, and the discarded response's message id. Taking it
    /// clears the note: the resend's own output starts a new response.
    pub(crate) fn take_discard(&self) -> Option<Discard> {
        let mut state = self.inner.lock();
        let message_id = state.message_id.take();
        std::mem::take(&mut state.emitted).then_some(Discard {
            message_id,
            stream_start_ms: state.stream_start_ms,
        })
    }

    /// The response was committed to history (or a new turn began): its output is accepted, nothing to discard.
    pub(crate) fn accept(&self) {
        let mut state = self.inner.lock();
        state.emitted = false;
        state.message_id = None;
        state.open_hosted.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discard_is_owed_only_after_visible_output_and_only_once() {
        let out = UnacceptedOutput::default();
        assert_eq!(out.take_discard(), None, "nothing streamed, nothing to discard");
        out.note_message_id("msg_1".into());
        assert_eq!(out.take_discard(), None, "an id alone is not output");
        out.note_emitted();
        assert_eq!(out.take_discard(), Some(Discard::default()), "the id was spent by the earlier take");
        assert_eq!(out.take_discard(), None, "a second resend with no new output owes nothing");
        assert_eq!(out.claim_stream_start(42), 42);
        out.note_message_id("msg_2".into());
        out.note_emitted();
        assert!(out.is_owed());
        assert_eq!(
            out.take_discard(),
            Some(Discard {
                message_id: Some("msg_2".into()),
                stream_start_ms: Some(42),
            })
        );
        out.note_emitted();
        out.accept();
        assert_eq!(out.take_discard(), None, "accepted output is never discarded");
        // Same millisecond, or a clock step back: still a new id, never a reused one
        assert_eq!(out.claim_stream_start(42), 43);
        assert_eq!(out.claim_stream_start(40), 44);
        assert_eq!(out.claim_stream_start(100), 100);
    }

    /// P201 r2: a completion for a row this session never showed (no start) puts nothing on a client's screen, so it
    /// owes no discard; a completion for a row it did show leaves the attempt marked.
    #[test]
    fn a_completion_without_a_shown_start_does_not_mark_the_attempt() {
        let out = UnacceptedOutput::default();
        out.note_hosted_finished("never-shown");
        assert!(!out.is_owed(), "an unseen row is not visible output");
        out.note_hosted_started("h1", "web_search");
        out.note_hosted_finished("h1");
        assert!(out.is_owed(), "the shown row stays visible output after it completes");
        assert!(out.take_open_hosted().is_empty(), "a completed row is not closed again");
    }
}
