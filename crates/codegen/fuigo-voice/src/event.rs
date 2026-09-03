/// Events emitted by [`crate::pipeline::run_voice_pipeline`] to the pager event loop.
///
/// # Why every variant carries a session id
///
/// A batch transcription is delivered by a task that outlives the recording:
/// the user releases, the upload runs, and the event arrives hundreds of
/// milliseconds later. By then the user may have started dictating somewhere
/// else. Without an identity on the event the consumer can only route to
/// whatever is bound *now*, which splices one prompt's dictation into another
/// and lets a stale failure tear down a live recording.
///
/// The id is minted by the pager on the press that started the session (see
/// [`crate::VoiceCommand::PttPress`]) and stamped on everything that session
/// emits, so the consumer can tell "this is mine" from "this belongs to a
/// session I have moved on from" without guessing from timing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoiceEvent {
    /// Partial transcript while the user is speaking (`interim_results` / non-final chunks).
    InterimTranscript { session: u64, text: String },

    /// Utterance complete (`speech_final` on streaming STT, or batch result).
    ///
    /// Streaming emits one of these per `speech_final` pause and keeps the mic
    /// open, so a single session can deliver several; batch delivers exactly
    /// one, after the release.
    UtteranceFinal { session: u64, text: String },

    /// A batch recording reached the capture cap while the user was still
    /// speaking, so `text` transcribes a recording that was cut short.
    ///
    /// Separate from [`Self::UtteranceFinal`] because the two need different
    /// handling, not because the text is dangerous: dictation lands in the
    /// prompt box and the user presses Enter, so nothing is executed on its
    /// own. The difference is that a truncated transcript *looks* complete.
    /// Delivered without a warning a half-sentence reads as the whole thing and
    /// the user sends it. So the text is still kept -- discarding minutes of
    /// dictation would be worse -- but the caller must say that it was cut.
    UtteranceTruncated {
        session: u64,
        text: String,
        /// The cap that was reached, in seconds of audio, for the message.
        limit_secs: u32,
    },

    /// This capture session is over: nothing further will be emitted for it.
    ///
    /// Carries no text and appends nothing. It exists because "the turn ended"
    /// and "text was delivered" are different facts, and inferring the first
    /// from the second was wrong in both directions: a trailing restatement that
    /// was correctly suppressed as a duplicate delivered nothing and so never
    /// ended the turn, wedging the consumer; and a consumer that ended the turn
    /// on the first final then discarded a later correction as belonging to
    /// nobody.
    ///
    /// Every session emits exactly one of these when its task finishes,
    /// whichever way it finished -- including after an [`Self::Error`], where the
    /// consumer has usually torn down already and ignores it.
    SessionEnded { session: u64 },

    /// Non-fatal or fatal error from capture or STT.
    ///
    /// The pipeline does not decide whether this should tear down the consumer's
    /// UI, because it cannot know which session the consumer is on. It reports
    /// the failure against `session` and lets the consumer decide: its own
    /// session's failure is a teardown, an older session's failure is news
    /// about dictation that was already in flight.
    Error {
        session: u64,
        /// Short description for a one-line toast.
        message: String,
        /// Optional longer fix steps, shown where more than one line fits.
        hint: Option<String>,
    },
}

impl VoiceEvent {
    /// The capture session this event belongs to.
    pub fn session(&self) -> u64 {
        match self {
            Self::InterimTranscript { session, .. }
            | Self::UtteranceFinal { session, .. }
            | Self::UtteranceTruncated { session, .. }
            | Self::SessionEnded { session }
            | Self::Error { session, .. } => *session,
        }
    }
}
