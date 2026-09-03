//! Applies [`VoiceEvent`]s from the voice pipeline to the prompt text and the dictation overlay.

use fuigo_voice::VoiceEvent;

use crate::app::app_view::{AppView, VoiceState, VoiceTarget};
use crate::views::prompt_widget::PromptWidget;

/// Joins the committed prompt text and a voice fragment with a space.
/// The space is skipped when the prompt is empty or already ends in whitespace, which keeps trailing newlines.
pub(crate) fn combine_prompt_with_voice_text(existing: &str, text: &str) -> String {
    if existing.trim().is_empty() {
        text.to_string()
    } else if existing.ends_with(char::is_whitespace) {
        format!("{existing}{text}")
    } else {
        format!("{existing} {text}")
    }
}

/// Appends `text` to `target`, the prompt bound when that dictation started.
///
/// The target is passed in rather than read from the current voice state: a
/// transcript can arrive after the user has moved on, and it belongs in the box
/// they dictated it into, not in whatever is bound when it lands.
///
/// The text goes at the end, or replaces a blank draft.
/// The caret follows only when it was already at the end; mid-text edits keep their place.
#[must_use]
fn append_voice_text_to_prompt(app: &mut AppView, target: VoiceTarget, text: &str) -> bool {
    let append = |prompt: &mut PromptWidget| {
        let existing = prompt.text();
        let cursor = prompt.cursor();
        let blank = existing.trim().is_empty();
        // A blank draft is a full replace, so the caret parks at the new end
        // Otherwise the text appends at the end, and the caret follows only if it was already there
        let follow_end = blank || cursor >= existing.len();
        let combined = combine_prompt_with_voice_text(existing, text);
        prompt.set_text(&combined);
        prompt.set_cursor(if follow_end { combined.len() } else { cursor });
    };
    match target {
        VoiceTarget::Agent(id) => {
            let Some(agent) = app.agents.get_mut(&id) else {
                return false;
            };
            append(&mut agent.prompt);
            true
        }
        target @ (VoiceTarget::DashboardDispatch | VoiceTarget::DashboardPeekReply(_)) => {
            let Some(dashboard) = app.dashboard.as_mut() else {
                return false;
            };
            // The peek reply box is shared across rows, so the text lands only if the bound row is still the peeked one
            let prompt = match target {
                VoiceTarget::DashboardPeekReply(rec) => {
                    let peeked = match dashboard.peek.as_ref().map(|p| &p.row) {
                        Some(crate::views::dashboard::DashboardRowId::TopLevel(id)) => Some(*id),
                        _ => None,
                    };
                    if peeked != Some(rec) {
                        return false;
                    }
                    &mut dashboard.peek_reply
                }
                _ => &mut dashboard.dispatch,
            };
            append(prompt);
            true
        }
    }
}

/// Move non-empty interim into the bound prompt and clear the overlay.
/// Does not stop the mic. Returns the promoted fragment.
pub(crate) fn commit_interim_into_prompt(app: &mut AppView) -> Option<String> {
    let interim = app
        .voice_interim()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)?;
    let target = app.voice_recording_target()?;
    if !append_voice_text_to_prompt(app, target, &interim) {
        return None;
    }
    app.voice_clear_interim();
    Some(interim)
}

/// How the capture session an event names relates to the pager's own state.
enum EventOwner {
    /// The session the pager is on now.
    Current(VoiceTarget),
    /// A session the user has moved on from that is still owed a delivery: they
    /// re-pressed while its recording was uploading. Carries the box it was
    /// dictated into.
    Detached(VoiceTarget),
    /// A session with no claim on anything: already delivered, cancelled, or
    /// evicted.
    Gone,
}

/// Decide who an event belongs to without changing anything.
///
/// Resolving ownership first is what stops a transcript from being routed to
/// whatever is bound when it happens to arrive.
fn owner_of(app: &AppView, session: u64) -> EventOwner {
    if app.voice_state.session() == Some(session) {
        return match app.voice_recording_target() {
            Some(target) => EventOwner::Current(target),
            None => EventOwner::Gone,
        };
    }
    match app
        .voice_detached
        .iter()
        .find(|(known, _)| *known == session)
    {
        Some((_, target)) => EventOwner::Detached(*target),
        None => EventOwner::Gone,
    }
}

/// Human wording for the capture cap, which is expressed in seconds.
///
/// Written out rather than dividing by 60 at the call site: the cap is a
/// constant that could be lowered, and integer division renders anything under
/// a minute as "0-minute".
fn describe_limit(limit_secs: u32) -> String {
    if limit_secs >= 60 && limit_secs.is_multiple_of(60) {
        format!("{}-minute", limit_secs / 60)
    } else {
        format!("{limit_secs}-second")
    }
}

/// Land a completed transcript in the box its dictation was bound to.
///
/// Returns whether the frame should redraw.
fn deliver_final(app: &mut AppView, session: u64, text: &str, truncated: Option<u32>) -> bool {
    let target = match owner_of(app, session) {
        // Delivering text does not end the turn. `VoiceEvent::SessionEnded`
        // does, and every session emits exactly one -- so a final that is
        // correctly suppressed as a duplicate cannot leave the session hanging,
        // and a later correction still has an owner to be delivered to.
        EventOwner::Current(target) => {
            app.voice_clear_interim();
            target
        }
        // The user re-pressed while this recording was uploading. Their words
        // still go where they said them -- and the entry stays until the session
        // ends, so a streaming correction that follows the first final is not
        // discarded as belonging to nobody.
        EventOwner::Detached(target) => target,
        EventOwner::Gone => return false,
    };
    if !text.trim().is_empty() && !append_voice_text_to_prompt(app, target, text.trim()) {
        // The box this was dictated into is gone (agent closed, peek moved on).
        // Say so: the words are lost either way, and losing them silently is
        // how a user concludes dictation "just doesn't work sometimes".
        app.show_toast("Voice: a transcript arrived for a prompt that is no longer open.");
        return true;
    }
    if let Some(limit_secs) = truncated {
        // The text is kept: discarding minutes of dictation would be a worse
        // outcome than a cut sentence. But it must not land silently -- a
        // truncated transcript reads as a complete one, and the user would send
        // it without knowing the end is missing.
        app.show_toast(&format!(
            "Voice: recording hit the {} limit; the end may be missing.",
            describe_limit(limit_secs)
        ));
    }
    true
}

/// Apply a voice event to app state. Returns whether the frame should redraw.
///
/// Every event names the capture session that produced it, and that is what
/// decides its fate. A transcription outlives its recording, so by the time one
/// arrives the user may have started dictating elsewhere, cancelled, or moved
/// to another agent -- and the right answer differs for each kind of event.
pub fn handle_voice_event(app: &mut AppView, event: VoiceEvent) -> bool {
    match event {
        VoiceEvent::InterimTranscript { session, text } => {
            // A live preview of a session that is no longer on screen has
            // nowhere to go: it would overwrite the overlay of the recording the
            // user is making now.
            if app.voice_state.session() != Some(session) {
                return false;
            }
            // Still a no-op unless recording, so a late interim after a stop
            // can't repopulate the overlay.
            app.voice_set_interim(text)
        }
        VoiceEvent::UtteranceFinal { session, text } => deliver_final(app, session, &text, None),
        VoiceEvent::UtteranceTruncated {
            session,
            text,
            limit_secs,
        } => deliver_final(app, session, &text, Some(limit_secs)),
        VoiceEvent::SessionEnded { session } => {
            match owner_of(app, session) {
                // The turn is over. Leaving `Stopping` in place would swallow
                // the user's next Enter forever waiting on a transcript that has
                // already been and gone.
                EventOwner::Current(_) => {
                    app.voice_clear_interim();
                    app.voice_state = VoiceState::Idle;
                    true
                }
                EventOwner::Detached(_) => {
                    app.voice_forget_detached(session);
                    false
                }
                // Already settled -- an error tore the session down before its
                // task finished, which is the common case.
                EventOwner::Gone => false,
            }
        }
        VoiceEvent::Error {
            session,
            message,
            hint,
        } => {
            let target = match owner_of(app, session) {
                // The user's own session failed: tear the dictation down, which
                // is what a dead mic or a refused endpoint should do.
                EventOwner::Current(target) => {
                    app.voice_reset();
                    Some(target)
                }
                // An older recording failed or was dropped. The user is owed the
                // news -- those words are gone -- but resetting here would tear
                // down the recording they have since started, leaving a live
                // microphone behind an idle UI.
                EventOwner::Detached(target) => {
                    app.voice_forget_detached(session);
                    Some(target)
                }
                EventOwner::Gone => return false,
            };
            app.show_toast(&format!("Voice: {message}"));
            // The hint holds long fix steps, so it goes to the agent or peek scrollback; a toast is one line, and dashboard dispatch has no scrollback
            if let Some(hint) = hint
                && let Some(VoiceTarget::Agent(id) | VoiceTarget::DashboardPeekReply(id)) = target
                && let Some(agent) = app.agents.get_mut(&id)
            {
                // Most voice messages are already sentences ("No speech was
                // detected. Voice stopped."), so appending a period unasked
                // renders "Voice stopped.." to the user.
                let message = message.strip_suffix('.').unwrap_or(&message);
                agent
                    .scrollback
                    .push_block(crate::scrollback::block::RenderBlock::system(format!(
                        "Voice: {message}. {hint}"
                    )));
            }
            true
        }
    }
}
