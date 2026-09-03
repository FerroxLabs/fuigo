//! Voice pipeline: mic capture goes to STT and transcripts come back as pager events.
//!
//! The pager drives capture with press/release commands.
//! They back both a toggle (`/voice`, `Ctrl+Shift+M`) and true push-to-talk (F12 hold), hence the `Ptt*` names.
//! A press may be followed by a release after a long hold or, for a toggle, a later stop.
//!
//! # Two transports
//!
//! [`crate::config::SttMode`] selects between them, and they are different
//! protocols rather than two URLs:
//!
//! - **Streaming** opens a WebSocket and receives interim transcripts as the
//!   user speaks.
//! - **Batch** records the whole utterance and sends one multipart POST on
//!   release. There is no live partial transcript, and `stt_interim_results`
//!   has nothing to act on.
//!
//! The choice is explicit because nothing here can probe what an endpoint
//! speaks: `stt_ws_url` derives `wss://` from any https base mechanically and
//! never negotiates, so "try streaming, fall back" would mean opening a socket
//! to find out.

#[cfg(feature = "audio")]
use std::collections::VecDeque;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::auth::SharedVoiceAuth;
#[cfg(feature = "audio")]
use crate::config::SttMode;
use crate::config::VoiceConfig;
use crate::error::VoiceError;
use crate::event::VoiceEvent;
#[cfg(feature = "audio")]
use crate::stt::batch::BatchSttClient;
#[cfg(feature = "audio")]
use crate::stt::{StreamingSttEvent, StreamingSttSession};

/// Commands from the pager event loop (toggle start/stop, or F12 push-to-talk).
///
/// The press and release carry a session id minted by the pager. The pager is
/// the side that has to mint it: it changes state on the keystroke, while the
/// pipeline only learns of the press a channel hop later, so an id assigned
/// here could not describe the UI state the events will be routed against.
#[derive(Debug)]
pub enum VoiceCommand {
    /// Begin streaming audio to STT (mic open until [`VoiceCommand::PttRelease`]).
    ///
    /// `session` identifies this capture for the whole of its life; every
    /// [`VoiceEvent`] it produces carries the same value.
    PttPress { session: u64 },
    /// End the capture session identified by `session` (`audio.done`, release mic).
    ///
    /// A release naming a session that is no longer active is dropped rather
    /// than applied to whatever is running. Ordering alone cannot be relied on:
    /// the pager re-sends a release that its non-blocking send shed, and a
    /// re-sent release has no ordering guarantee against later commands, so an
    /// unmatched one would end a recording the user had just started.
    PttRelease { session: u64 },
    /// Tear down the pipeline task.
    Shutdown,
}

/// One capture session, from the press that opened it until its reader task
/// ends.
///
/// # Superseding is always finish-and-detach, for both transports
///
/// Neither transport may be aborted on a new press, and for the same reason:
/// at the moment a press supersedes a session, that session is holding text
/// the user has already spoken and has not yet received.
///
/// - **Batch** holds the entire utterance in memory and has delivered nothing.
/// - **Streaming** has delivered only `InterimTranscript`s, which the pager
///   overwrites and never commits. Committed text comes from `speech_final` or
///   `Done` alone (see `run_streaming_reader`), and the server sends the
///   trailing one *after* `audio.done` -- so a press landing between the
///   release and that final destroys the utterance just as surely.
///
/// So a superseded session is told to stop capturing and left to finish. Its
/// handle moves to the pipeline's in-flight list, where `Shutdown` can still
/// reach it, and its events keep flowing stamped with its own session id --
/// the consumer routes them by that id rather than by what is bound now.
struct ActivePtt {
    /// The id minted by the pager for the press that opened this session.
    session: u64,
    finish_tx: mpsc::Sender<()>,
    reader: JoinHandle<()>,
}

/// Most finished-but-still-uploading batch sessions kept at once.
///
/// Each holds its recording (up to the cap) plus the WAV copy being uploaded,
/// so an unbounded list would let repeated presses accumulate hundreds of
/// megabytes. Past this the oldest is aborted.
///
/// That aborts a transcript this design otherwise promises to deliver: a
/// superseded session still emits its `UtteranceFinal`. So this is a real loss,
/// chosen over unbounded memory, and it takes four rapid presses with uploads
/// still in flight to reach. It is not silent: `supersede_session` emits a
/// `VoiceEvent::Error` stamped with the evicted session before aborting it, so
/// the user is told that one dictation was dropped rather than quietly losing
/// it.
pub const MAX_IN_FLIGHT_UPLOADS: usize = 3;

/// The batch HTTP client, built at most once per pipeline and shared by every
/// press.
///
/// Lazy rather than eager so a streaming-mode session never constructs one, and
/// so a construction failure surfaces as a `VoiceEvent::Error` on the press that
/// needed it rather than silently at startup where nothing is listening.
type BatchClientCell = Arc<tokio::sync::OnceCell<BatchSttClient>>;
#[cfg(not(feature = "audio"))]
use crate::stt::batch::BatchSttClient;

/// Run until [`VoiceCommand::Shutdown`].
pub async fn run_voice_pipeline(
    config: VoiceConfig,
    auth: SharedVoiceAuth,
    mut cmd_rx: mpsc::Receiver<VoiceCommand>,
    event_tx: mpsc::Sender<VoiceEvent>,
) {
    let mut active: Option<ActivePtt> = None;
    let batch: BatchClientCell = BatchClientCell::default();
    // Sessions that were superseded while still uploading. Kept so `Shutdown`
    // can actually stop them: a detached upload with no handle would keep
    // POSTing the user's microphone audio after they turned voice off.
    let mut in_flight: Vec<(u64, JoinHandle<()>)> = Vec::new();

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            VoiceCommand::Shutdown => break,
            VoiceCommand::PttPress { session } => {
                // Supersede any prior session (including one still draining its trailing final after a `PttRelease`) rather than ignoring the press
                // A rapid stop-then-start would otherwise be dropped here while the pager already flipped to "listening"
                // That leaves a dead mic behind a recording UI and lets the old session's final land on the new target
                // Aborting drops the old reader's capture and STT session, releasing the mic and socket at once
                // The pager normally sends a `PttRelease` between presses, so an `active` session here is one that is already stopping.
                // "Normally" and not "always": the pager re-sends a release its non-blocking send could not place immediately, and a re-send has no ordering guarantee against later commands, so a release can arrive after the press that superseded it -- or, if the pipeline is gone, never.
                // Superseding stops the session either way, so the invariant is a description of the common case, not something relied on. What the reordering does require is the session id on the release itself; see `VoiceCommand::PttRelease`.
                // We don't join the old reader, so its stream may still be releasing as the new one opens; cpal handles that brief overlap
                //
                // In batch mode the abort reaches only the capture task: once the
                // recording is final the transcription runs in a detached task
                // that this cannot cancel. That is deliberate — see
                // `start_batch_session`.
                if let Some(prev) = active.take() {
                    supersede_session(prev, &mut in_flight, &event_tx).await;
                }

                // Connect and device-open take hundreds of ms
                // Race them against the next command so a release/stop (or shutdown) arriving mid-connect cancels the start
                // Otherwise a quick tap-and-release would open a hot mic and append a spurious final after the user already let go
                // `biased` polls the start first so a just-completed session is always kept (dropping it would leak its reader)
                // Dropping an unfinished start cancels the connect
                // The concurrent mic-open still completes, but its handle is then dropped, releasing the device right away
                tokio::select! {
                    biased;
                    opened = open_session(&config, &auth, &event_tx, &batch, session) => {
                        active = opened;
                    }
                    next = cmd_rx.recv() => match next {
                        // Released before capture was ready; cancel the start
                        Some(VoiceCommand::PttRelease { session: releasing }) if releasing == session => {}
                        // A release naming an older session must not cancel this
                        // start. Winning this `select!` arm has already dropped
                        // the in-progress connect, so the start is re-issued
                        // rather than resumed; the abandoned mic-open completes
                        // and releases the device as its handle drops.
                        Some(VoiceCommand::PttRelease { .. }) => {
                            active = open_session(&config, &auth, &event_tx, &batch, session).await;
                        }
                        Some(VoiceCommand::Shutdown) | None => break,
                        // The pager normally sends a release between presses, so this is not the expected path; a shed release can reach it, so start fresh rather than assuming
                        Some(VoiceCommand::PttPress { session: next_session }) => {
                            active = open_session(&config, &auth, &event_tx, &batch, next_session).await;
                        }
                    },
                }
            }
            VoiceCommand::PttRelease { session } => {
                let Some(active_session) = active.as_ref() else {
                    continue;
                };
                // A release for a session that is no longer active ends nothing.
                // Applying it to whatever happens to be running would let a
                // re-sent release (see `VoiceCommand::PttRelease`) stop the
                // recording the user started after it.
                if active_session.session != session {
                    tracing::trace!(
                        released = session,
                        active = active_session.session,
                        "voice release for a session that is no longer active; ignored"
                    );
                    continue;
                }
                // The reader task owns the capture handle
                // Signalling it lets the reader stop the mic and end the utterance in a single place, matching the no-speech-watchdog teardown below
                let _ = active_session.finish_tx.send(()).await;
            }
        }
    }

    // Shutdown must stop everything, including a finished recording that is
    // mid-upload. The user turned voice off; continuing to send their audio is
    // not something to leave running.
    if let Some(session) = active {
        session.reader.abort();
    }
    for (_, handle) in in_flight {
        handle.abort();
    }
}

/// Stop `prev` capturing, let it finish delivering, and keep its handle where
/// `Shutdown` can still reach it.
///
/// See [`ActivePtt`] for why this is never an abort. `prev` keeps emitting
/// under its own session id; the consumer decides what to do with events from a
/// session it has moved on from.
async fn supersede_session(
    prev: ActivePtt,
    in_flight: &mut Vec<(u64, JoinHandle<()>)>,
    event_tx: &mpsc::Sender<VoiceEvent>,
) {
    // Tell it to stop capturing; it finishes delivering on its own.
    // A closed channel means it already stopped, which is not an error.
    let _ = prev.finish_tx.send(()).await;
    in_flight.retain(|(_, handle)| !handle.is_finished());
    #[cfg(feature = "audio")]
    while in_flight.len() >= MAX_IN_FLIGHT_UPLOADS {
        let (evicted, handle) = in_flight.remove(0);
        handle.abort();
        // Aborting destroys dictation the user already spoke, so it is reported
        // rather than dropped. It is stamped with the evicted session, not the
        // current one: this is news about an older recording and must not tear
        // down the one now in progress.
        let _ = event_tx
            .send(VoiceEvent::Error {
                session: evicted,
                message:
                    "An earlier dictation was dropped: too many recordings were still uploading."
                        .to_owned(),
                hint: Some(
                    "Wait for a dictation to finish transcribing before starting the next one."
                        .to_owned(),
                ),
            })
            .await;
    }
    in_flight.push((prev.session, prev.reader));
}

/// Open a capture session, emitting a `VoiceEvent::Error` (and returning `None`) on failure.
/// Extracted so the `PttPress` start can be raced against an incoming release in `select!` and reused for the defensive restart path.
async fn open_session(
    config: &VoiceConfig,
    auth: &SharedVoiceAuth,
    event_tx: &mpsc::Sender<VoiceEvent>,
    batch: &BatchClientCell,
    session: u64,
) -> Option<ActivePtt> {
    match start_capture_session(config, auth, event_tx, batch, session).await {
        Ok(opened) => Some(opened),
        Err(e) => {
            // Stamped with the session that failed to open, which is the one the
            // consumer just moved to -- so this failure does reset its state,
            // which is what a mic that will not open should do.
            let _ = event_tx
                .send(VoiceEvent::Error {
                    session,
                    message: e.to_string(),
                    hint: None,
                })
                .await;
            None
        }
    }
}

#[cfg(not(feature = "audio"))]
async fn start_capture_session(
    _config: &VoiceConfig,
    _auth: &SharedVoiceAuth,
    _event_tx: &mpsc::Sender<VoiceEvent>,
    _batch: &BatchClientCell,
    _session: u64,
) -> Result<ActivePtt, VoiceError> {
    Err(VoiceError::Config(
        "voice audio capture disabled (build without `audio` feature)".into(),
    ))
}

/// Hard cap on the pre-connect PCM backlog (memory safety).
/// Sized far above any real connect: the STT connect timeout aborts long before this is reached.
/// In practice it never drops; it only bounds a pathological hang.
#[cfg(feature = "audio")]
const BACKLOG_MAX_CHUNKS: usize = 1024;

/// Bridge mic PCM into the STT socket across the connect handshake.
///
/// Until `audio_tx_rx` yields the live STT sender, captured chunks accumulate in a bounded backlog, so the mic never backpressures during connect.
/// Once the sender arrives the backlog is flushed in order and capture streams live.
/// Holding the sender also defers the writer's `audio.done` until the backlog is drained on teardown.
/// Returns when the mic stops (`mic_rx` closed), the socket goes away (`audio_tx` closed), or connect fails (`audio_tx_rx` dropped).
///
/// **Streaming only.** At the cap this drops the *oldest* chunks, which is
/// right for a handshake bridge (the newest audio is what the socket wants) and
/// wrong for a recording, where it would silently delete the beginning of the
/// utterance. Batch accumulates in [`record_utterance`] instead.
#[cfg(feature = "audio")]
async fn forward_pcm(
    mut mic_rx: mpsc::Receiver<Vec<u8>>,
    mut audio_tx_rx: tokio::sync::oneshot::Receiver<mpsc::Sender<Vec<u8>>>,
) {
    let mut backlog: VecDeque<Vec<u8>> = VecDeque::new();
    let audio_tx = loop {
        tokio::select! {
            chunk = mic_rx.recv() => match chunk {
                // A normal connect stays well under the cap, so the lead-in is kept intact
                // Only a pathologically slow connect (which the connect timeout aborts anyway) drops its oldest chunks
                Some(c) => {
                    if backlog.len() == BACKLOG_MAX_CHUNKS {
                        backlog.pop_front();
                    }
                    backlog.push_back(c);
                }
                None => return, // mic stopped before the socket was ready
            },
            tx = &mut audio_tx_rx => match tx {
                Ok(tx) => break tx,
                Err(_) => return, // connect failed; the sender was dropped
            },
        }
    };
    for chunk in backlog {
        if audio_tx.send(chunk).await.is_err() {
            return;
        }
    }
    while let Some(chunk) = mic_rx.recv().await {
        if audio_tx.send(chunk).await.is_err() {
            break;
        }
    }
}

/// How long a session may run without any speech before it is torn down (instead of streaming a dead mic until the user gives up).
/// The first evidence of speech disarms it, so long dictation with pauses is unaffected.
#[cfg(feature = "audio")]
const NO_SPEECH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The one thing [`record_utterance`] does to a capture session: end it.
///
/// A trait rather than the concrete handle so the recording loop -- the cap, the
/// drain, the watchdog, supersede -- can be tested without a microphone. Opening
/// a real device needs a TCC grant the test binary does not have, which is why
/// this loop previously had no coverage at all.
#[cfg(feature = "audio")]
pub(crate) trait CaptureControl: Send + 'static {
    /// Release the device. Blocking; callers run it on the blocking pool.
    fn stop(self);
}

#[cfg(feature = "audio")]
impl CaptureControl for crate::audio::CaptureHandle {
    fn stop(self) {
        crate::audio::CaptureHandle::stop(self);
    }
}

/// Stop capture and wait for the device to be released.
///
/// `CaptureHandle::stop()` is three blocking calls -- kill the mic helper
/// child, reap it, join its reader thread -- so it runs on the blocking pool.
/// Called directly it parks a runtime worker that the pager's TUI shares, on
/// every push-to-talk release.
///
/// `Option::take` makes it idempotent: a session may be told to stop by the
/// user and again by the cap.
#[cfg(feature = "audio")]
async fn stop_capture<C: CaptureControl>(capture: &mut Option<C>) {
    if let Some(handle) = capture.take() {
        let _ = tokio::task::spawn_blocking(move || handle.stop()).await;
    }
}

/// Message and permission guidance for a session torn down for want of speech.
/// A denied grant is indistinguishable from not speaking because macOS may return silence instead of an error.
#[cfg(feature = "audio")]
fn no_speech_error() -> (String, Option<String>) {
    (
        "No speech was detected. Voice stopped.".to_owned(),
        Some(crate::probe::mic_fix_help().to_owned()),
    )
}

#[cfg(feature = "audio")]
async fn start_capture_session(
    config: &VoiceConfig,
    auth: &SharedVoiceAuth,
    event_tx: &mpsc::Sender<VoiceEvent>,
    batch: &BatchClientCell,
    session: u64,
) -> Result<ActivePtt, VoiceError> {
    match config.stt_mode {
        SttMode::Streaming => start_streaming_session(config, auth, event_tx, session).await,
        SttMode::Batch => start_batch_session(config, auth, event_tx, batch, session).await,
    }
}

#[cfg(feature = "audio")]
async fn start_streaming_session(
    config: &VoiceConfig,
    auth: &SharedVoiceAuth,
    event_tx: &mpsc::Sender<VoiceEvent>,
    session: u64,
) -> Result<ActivePtt, VoiceError> {
    // Open the mic concurrently with the bearer fetch and the connect handshake (TLS, WebSocket, `transcript.created`)
    // Both legs take hundreds of ms and used to run in series before any capture, clipping the first word of a hold
    let (mic_tx, mic_rx) = mpsc::channel::<Vec<u8>>(64);
    let sample_rate = config.sample_rate;
    // `spawn_pcm_capture` blocks until the device opens; keep it off the runtime.
    let capture_task =
        tokio::task::spawn_blocking(move || crate::audio::spawn_pcm_capture(sample_rate, mic_tx));

    // Drain mic before connect resolves so capture never backpressures while the socket comes up
    let (audio_tx_tx, audio_tx_rx) = tokio::sync::oneshot::channel::<mpsc::Sender<Vec<u8>>>();
    tokio::spawn(forward_pcm(mic_rx, audio_tx_rx));

    let connect = async {
        // The bearer is resolved for this destination, not in the abstract; the
        // provider may refuse a host it will not send a credential to.
        let endpoint = config.streaming_credential_endpoint()?;
        let bearer = crate::auth::require_bearer(auth, &endpoint).await?;
        StreamingSttSession::connect(config, &bearer).await
    };
    let (connect_res, capture_res) = tokio::join!(connect, capture_task);

    // Resolve the mic first so a device/permission failure wins over a socket error
    // The `?` on `connect_res` then drops `capture`, releasing the mic
    let capture = match capture_res {
        Ok(Ok(handle)) => handle,
        Ok(Err(e)) => return Err(e),
        Err(join_err) => {
            return Err(VoiceError::Config(format!(
                "voice capture task failed: {join_err}"
            )));
        }
    };
    let stt = connect_res?;

    // Hand the live sender to the forwarder; it flushes the backlog then streams.
    let audio_tx = stt
        .audio_sender()
        .ok_or_else(|| VoiceError::Stt("STT audio sender unavailable".into()))?;
    let _ = audio_tx_tx.send(audio_tx);

    let (finish_tx, finish_rx) = mpsc::channel::<()>(1);
    let out = event_tx.clone();
    let reader = tokio::spawn(async move {
        run_streaming_reader(stt, capture, finish_rx, session, out.clone()).await;
        // Exactly one terminal event per session, whichever way the reader
        // finished. The consumer closes the turn on this and nothing else.
        let _ = out.send(VoiceEvent::SessionEnded { session }).await;
    });

    Ok(ActivePtt {
        session,
        finish_tx,
        reader,
    })
}

/// The part of a live streaming STT socket the reader loop drives.
///
/// Narrow on purpose: a fake only has to answer `recv` and record `finish_audio`
/// to exercise the whole teardown path, and no shipped endpoint speaks this
/// protocol, so a test double is the only way to exercise it at all.
#[cfg(feature = "audio")]
trait StreamingControl: Send + 'static {
    /// Signal end-of-utterance. The server answers with its trailing final,
    /// which is the text this session exists to deliver.
    fn finish_audio(&mut self);
    /// The next event from the socket, or `None` once it closes.
    fn recv(&mut self) -> impl std::future::Future<Output = Option<StreamingSttEvent>> + Send;
}

#[cfg(feature = "audio")]
impl StreamingControl for StreamingSttSession {
    fn finish_audio(&mut self) {
        StreamingSttSession::finish_audio(self);
    }
    async fn recv(&mut self) -> Option<StreamingSttEvent> {
        StreamingSttSession::recv(self).await
    }
}

/// How long a finished streaming session waits for the server's trailing final
/// before giving up and releasing the socket.
///
/// The wait cannot be unbounded. Once the turn has ended this task exists only
/// to collect one more message, and a server that never sends it would
/// otherwise keep the task and its socket alive for the rest of the process.
/// Ten seconds is far longer than a re-transcription of a single turn takes and
/// still bounded.
#[cfg(feature = "audio")]
const STREAMING_FINISH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Compare two transcripts for "the server said the same thing again".
///
/// Whitespace-collapsed, lowercased, and stripped of terminal punctuation,
/// because a trailing restatement routinely differs from the chunk-level final
/// in exactly those: `"hello"` against `"Hello."`. Comparing raw text let that
/// pair through as two different utterances and appended both.
///
/// This cannot be exact, and the direction of the error is chosen: a
/// restatement that still looks different is delivered twice, which the user can
/// see and delete, rather than suppressed and lost.
#[cfg(feature = "audio")]
fn normalize_transcript(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
        .trim_end_matches(['.', '!', '?', ',', ';', ':'])
        .to_owned()
}

/// Sleep until `deadline`, or forever when there is none.
///
/// Lets a `select!` arm be armed by an `Option` without a guard that would have
/// to `unwrap` the same value on the other side.
#[cfg(feature = "audio")]
async fn sleep_until_opt(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// Drive a streaming session until the turn ends, stamping every event with
/// `session`.
///
/// Generic over the socket and the capture handle so the teardown path can be
/// tested; see [`StreamingControl`].
#[cfg(feature = "audio")]
async fn run_streaming_reader<S: StreamingControl, C: CaptureControl>(
    mut stt: S,
    capture: C,
    mut finish_rx: mpsc::Receiver<()>,
    session: u64,
    out: mpsc::Sender<VoiceEvent>,
) {
    let mut capture = Some(capture);
    // Tear down when no transcript arrives within the timeout; the first transcript disarms this
    let no_speech_deadline = tokio::time::Instant::now() + NO_SPEECH_TIMEOUT;
    let mut awaiting_speech = true;
    // Latches when the turn ends, by user release or by supersede. A
    // superseding press signals `finish_tx` and then drops it (see
    // `supersede_session`), so without this latch the subsequent channel close
    // would read as abandonment and discard the trailing final -- the very
    // utterance detaching exists to preserve.
    let mut finishing = false;
    // Armed once the turn ends, so a server that never sends its trailing final
    // cannot keep this task and its socket alive forever.
    let mut finish_deadline: Option<tokio::time::Instant> = None;
    // Chunk-final (`is_final && !speech_final`) text is locked: the server sends it as a delta of the turn
    // Stitch those deltas into the live preview so a long pauseless utterance keeps accumulating instead of resetting to the latest ~3s chunk
    // The committed prompt text only ever comes from `speech_final`
    // The server produces that as a clean one-pass re-transcription of the whole turn, better than stitched deltas
    // The prefix resets on each `speech_final`
    let mut locked_prefix = String::new();
    // The last text committed by a `speech_final`, if any. The server sends
    // `Done` after it restating the same turn, so without this the utterance is
    // delivered twice -- appended twice to the prompt when the session is
    // current, and, once detached, delivered once then dropped as an unknown
    // second event.
    //
    // Compared by content rather than tracked as a boolean: a `Done` that says
    // something *different* is carrying text no `speech_final` delivered, and
    // suppressing it would lose exactly the words this file exists to protect.
    let mut committed_text: Option<String> = None;
    loop {
        tokio::select! {
            // Disabled once the turn has ended: after that the only thing left
            // is the trailing final, and re-polling a closed channel here would
            // look like abandonment.
            msg = finish_rx.recv(), if !finishing => {
                if msg.is_some() {
                    // User ended the turn; stop the no-speech watchdog.
                    awaiting_speech = false;
                    finishing = true;
                    finish_deadline = Some(tokio::time::Instant::now() + STREAMING_FINISH_TIMEOUT);
                    stop_capture(&mut capture).await;
                    stt.finish_audio();
                } else {
                    return;
                }
            }
            _ = tokio::time::sleep_until(no_speech_deadline), if awaiting_speech => {
                // Tear down rather than streaming a dead mic until the user stops.
                stop_capture(&mut capture).await;
                stt.finish_audio();
                let (message, hint) = no_speech_error();
                let _ = out.send(VoiceEvent::Error { session, message, hint }).await;
                return;
            }
            () = sleep_until_opt(finish_deadline) => {
                tracing::warn!(
                    session,
                    "streaming STT sent no trailing final before the deadline; releasing the socket"
                );
                // Say so rather than just vanishing. The consumer put itself in
                // a stopping state when the user released and is waiting for
                // this session to end; with no event it would wait forever, and
                // the utterance would be lost with nothing on screen to say so.
                let _ = out
                    .send(VoiceEvent::Error {
                        session,
                        message: "Voice stopped: the transcription service did not answer."
                            .to_owned(),
                        hint: Some(
                            "The recording ended without a transcript. Try again, or switch \
                             `[voice].stt_mode` to \"batch\"."
                                .to_owned(),
                        ),
                    })
                    .await;
                return;
            }
            ev = stt.recv() => {
                match ev {
                    Some(StreamingSttEvent::Partial(p)) => {
                        let text = p.text.trim();
                        if text.is_empty() {
                            continue;
                        }
                        // Real speech arrived: disarm the no-speech watchdog.
                        awaiting_speech = false;
                        if !p.speech_final {
                            // New text no `speech_final` has committed yet, so a
                            // trailing `Done` would be carrying something real.
                            committed_text = None;
                        }

                        let event = if p.speech_final {
                            locked_prefix.clear();
                            committed_text = Some(normalize_transcript(&p.text));
                            VoiceEvent::UtteranceFinal { session, text: p.text }
                        } else if p.is_final {
                            // Lock this chunk's delta into the running preview.
                            if !locked_prefix.is_empty() {
                                locked_prefix.push(' ');
                            }
                            locked_prefix.push_str(text);
                            VoiceEvent::InterimTranscript {
                                session,
                                text: locked_prefix.clone(),
                            }
                        } else if locked_prefix.is_empty() {
                            VoiceEvent::InterimTranscript {
                                session,
                                text: text.to_owned(),
                            }
                        } else {
                            VoiceEvent::InterimTranscript {
                                session,
                                text: format!("{locked_prefix} {text}"),
                            }
                        };
                        // An interim is replaceable, so it must never block this
                        // loop: awaiting channel capacity here would park the
                        // task outside the `select!`, where neither the finish
                        // deadline nor the no-speech watchdog can fire. A final
                        // still awaits, because dropping one loses an utterance.
                        let is_final = matches!(event, VoiceEvent::UtteranceFinal { .. });
                        if is_final {
                            // The receiver is gone (the pager dropped the channel), so tear down
                            if out.send(event).await.is_err() {
                                return;
                            }
                        } else {
                            use tokio::sync::mpsc::error::TrySendError;
                            match out.try_send(event) {
                                Ok(()) => {}
                                // The consumer is behind; the next interim
                                // supersedes this one anyway.
                                Err(TrySendError::Full(_)) => {}
                                Err(TrySendError::Closed(_)) => return,
                            }
                        }
                    }
                    Some(StreamingSttEvent::Done { text }) => {
                        locked_prefix.clear();
                        // `Done` usually restates the turn a `speech_final` has
                        // already committed, and emitting both duplicated the
                        // utterance. But only a restatement is redundant: a
                        // `Done` carrying different text is the only delivery
                        // those words will ever get. "Same" here is what
                        // `normalize_transcript` can tell -- a comparison, not a
                        // proof of equivalence.
                        let normalized = normalize_transcript(&text);
                        let already_delivered =
                            committed_text.as_deref() == Some(normalized.as_str());
                        let delivered_now = if !normalized.is_empty() && !already_delivered {
                            awaiting_speech = false;
                            let _ = out
                                .send(VoiceEvent::UtteranceFinal { session, text })
                                .await;
                            committed_text = Some(normalized);
                            true
                        } else {
                            already_delivered
                        };
                        // Mid-session the mic stays open across pauses, so this
                        // is not the end. Once the turn has ended it is.
                        if finishing {
                            // Mid-session the mic stays open across pauses, so
                            // this is not the end. Once the turn has ended it
                            // is -- and the `SessionEnded` emitted when this
                            // task returns is what closes it for the consumer,
                            // whether or not this `Done` delivered anything.
                            let _ = delivered_now;
                            return;
                        }
                    }
                    Some(StreamingSttEvent::Error { message }) => {
                        let _ = out.send(VoiceEvent::Error { session, message, hint: None }).await;
                        return;
                    }
                    Some(StreamingSttEvent::Ready) | None => {
                        // The socket closed (or restated `transcript.created`)
                        // without ever finishing this turn. Returning silently
                        // left the consumer waiting for an end that never came,
                        // painting a live-mic UI over a device this task is
                        // about to drop -- the same stranding the finish
                        // deadline above reports, so it is reported the same way.
                        //
                        // Harmless once the turn really is over: an event for a
                        // session the consumer has already settled is ignored.
                        let _ = out
                            .send(VoiceEvent::Error {
                                session,
                                message: "Voice stopped: the transcription connection closed."
                                    .to_owned(),
                                hint: Some(
                                    "The recording ended without a transcript. Try again."
                                        .to_owned(),
                                ),
                            })
                            .await;
                        return;
                    }
                }
            }
        }
    }
}

/// Longest recording batch mode will hold, in seconds.
///
/// At the capture format (16 kHz, mono, 16-bit) that is 32 KB of PCM per
/// second, so five minutes is ~9.6 MB. Peak memory is roughly double that for
/// a moment: [`crate::stt::batch::pcm_to_wav`] copies the samples into a second
/// buffer before the PCM is dropped. The request body then borrows the WAV
/// rather than copying it again.
#[cfg(feature = "audio")]
const RECORDING_MAX_SECS: u32 = 300;

/// [`RECORDING_MAX_SECS`] as a byte count for `sample_rate`, mono 16-bit.
#[cfg(feature = "audio")]
fn recording_max_bytes(sample_rate: u32) -> usize {
    (sample_rate as usize) * 2 * (RECORDING_MAX_SECS as usize)
}

/// A finished recording and whether the cap ended it.
#[cfg(feature = "audio")]
struct Recording {
    pcm: Vec<u8>,
    truncated: bool,
}

/// Start a batch session: record now, transcribe on release.
///
/// # When the credential is resolved, and why twice
///
/// Once up front, concurrently with the mic opening, so a provider that refuses
/// the endpoint fails the session immediately rather than after the user has
/// finished speaking. The mic does open alongside that check -- both legs take
/// hundreds of ms and running them in series clips the first word -- so a
/// refusal discards samples that were already captured rather than preventing
/// their capture. They are never sent anywhere.
///
/// Then again in `transcribe_and_emit`, immediately before the POST. A
/// recording may run for the full five-minute cap and the upload for another
/// two minutes, which is long enough for a rotating session token fetched at
/// press time to have expired by the time it is used. Re-resolving costs a
/// cached lookup and removes a 401 that would destroy the whole recording,
/// since a POST carrying audio is not retried.
#[cfg(feature = "audio")]
async fn start_batch_session(
    config: &VoiceConfig,
    auth: &SharedVoiceAuth,
    event_tx: &mpsc::Sender<VoiceEvent>,
    batch: &BatchClientCell,
    session: u64,
) -> Result<ActivePtt, VoiceError> {
    let endpoint = crate::stt::batch::transcription_url(config)?;

    let (mic_tx, mic_rx) = mpsc::channel::<Vec<u8>>(64);
    let sample_rate = config.sample_rate;
    let capture_task =
        tokio::task::spawn_blocking(move || crate::audio::spawn_pcm_capture(sample_rate, mic_tx));

    // Fail fast on a refused endpoint or an unbuildable client, concurrently
    // with the device opening. The bearer fetched here is deliberately
    // discarded: it is a permission check, and the value actually sent is
    // resolved again just before the POST. See this function's docs.
    let prepare = async {
        let _permitted = crate::auth::require_bearer(auth, &endpoint).await?;
        let client = batch
            .get_or_try_init(|| async { BatchSttClient::new() })
            .await?;
        Ok::<_, VoiceError>(client.clone())
    };
    let (prepare_res, capture_res) = tokio::join!(prepare, capture_task);

    // Resolve the mic first so a device/permission failure wins over an auth
    // error, matching the streaming path. The `?` below then drops `capture`.
    let capture = match capture_res {
        Ok(Ok(handle)) => handle,
        Ok(Err(e)) => return Err(e),
        Err(join_err) => {
            return Err(VoiceError::Config(format!(
                "voice capture task failed: {join_err}"
            )));
        }
    };
    let client = prepare_res?;

    let (finish_tx, mut finish_rx) = mpsc::channel::<()>(1);
    let out = event_tx.clone();
    let config = config.clone();
    let auth = Arc::clone(auth);
    // One task owns the whole session: record, then transcribe. A new press
    // does NOT abort it (see `ActivePtt`) -- it signals `finish_tx` and moves
    // the handle to the pipeline's in-flight list, so the recording survives a
    // re-press and `Shutdown` can still stop the upload.
    let reader = tokio::spawn(async move {
        let Some(recording) =
            record_utterance(capture, mic_rx, &mut finish_rx, sample_rate, session, &out).await
        else {
            // No recording to transcribe (abandoned, or the no-speech watchdog
            // already reported). The turn is still over, and the consumer is
            // still owed that fact.
            let _ = out.send(VoiceEvent::SessionEnded { session }).await;
            return;
        };
        transcribe_and_emit(&client, &config, &auth, &endpoint, recording, session, &out).await;
        let _ = out.send(VoiceEvent::SessionEnded { session }).await;
    });

    Ok(ActivePtt {
        session,
        finish_tx,
        reader,
    })
}

/// Record until the user releases, the mic closes, or the cap is reached.
///
/// Returns `None` when the session ended without a recording to transcribe —
/// the pipeline dropped the session, or the no-speech watchdog fired (which
/// emits its own event).
///
/// # Draining, and what it does and does not guarantee
///
/// The recording is complete when `mic_rx` yields `None`, and only then.
/// `CaptureHandle::stop()` releases the device, but PCM already handed to the
/// channel is delivered by a separate producer, so returning as soon as
/// `stop()` returns would clip the final words. Reading to channel close is
/// what makes the tail land.
///
/// It does NOT guarantee nothing was lost in the middle. The subprocess
/// backends use `try_send` and **shed** a chunk when the 64-slot channel is
/// full (`audio/pipe.rs`), deliberately, so that teardown can never hang on a
/// stalled consumer. For streaming that is correct load-shedding; for a
/// recording it splices a gap out of the middle. This consumer is a memcpy and
/// cannot stall, so in practice the channel does not fill -- but a long enough
/// runtime stall would, and the only signal today is a `warn!` from the
/// producer. The check below turns that into something the user's own numbers
/// can show.
#[cfg(feature = "audio")]
async fn record_utterance<C: CaptureControl>(
    capture: C,
    mut mic_rx: mpsc::Receiver<Vec<u8>>,
    finish_rx: &mut mpsc::Receiver<()>,
    sample_rate: u32,
    session: u64,
    out: &mpsc::Sender<VoiceEvent>,
) -> Option<Recording> {
    let mut capture = Some(capture);

    let max_bytes = recording_max_bytes(sample_rate);
    let mut pcm: Vec<u8> = Vec::new();
    // Wall-clock span of the capture, to compare against the audio actually
    // received. They should match; a shortfall means chunks were shed.
    let mut first_chunk_at: Option<tokio::time::Instant> = None;
    let mut last_chunk_at: Option<tokio::time::Instant> = None;
    let mut truncated = false;
    // Latches when the turn ends, by user release or by supersede.
    let mut finishing = false;
    // Armed until the local gate sees speech. Batch learns nothing from the
    // endpoint until the very end, so without this a user who holds the key
    // with a muted mic would record for the full cap before being told.
    let mut awaiting_speech = true;
    let no_speech_deadline = tokio::time::Instant::now() + NO_SPEECH_TIMEOUT;

    loop {
        tokio::select! {
            chunk = mic_rx.recv() => match chunk {
                Some(chunk) => {
                    if truncated {
                        // Past the cap: keep draining so the capture thread is
                        // never blocked on a full channel, but keep nothing.
                        continue;
                    }
                    if pcm.len() + chunk.len() > max_bytes {
                        // Keep the part that fits rather than dropping the
                        // whole chunk: at 16 kHz a chunk is tens of
                        // milliseconds, and discarding it would cut a syllable
                        // off the end for no reason.
                        let room = max_bytes - pcm.len();
                        pcm.extend_from_slice(&chunk[..room]);
                        truncated = true;
                        // Stop the device now. The channel then closes once the
                        // producer exits, which ends this loop.
                        stop_capture(&mut capture).await;
                        continue;
                    }
                    let now = tokio::time::Instant::now();
                    first_chunk_at.get_or_insert(now);
                    last_chunk_at = Some(now);
                    pcm.extend_from_slice(&chunk);
                }
                // Every sender is gone: the capture thread exited and the
                // bridge flushed. This is the only place the recording is
                // considered complete.
                None => break,
            },
            // Disabled once the turn has ended: after that the only thing left
            // to do is drain `mic_rx`, and re-polling a closed channel here
            // would look like abandonment.
            msg = finish_rx.recv(), if !finishing => {
                // `None` here means the pipeline dropped this session before
                // the user ended it, so there is no completed recording to
                // deliver: return, releasing the device as `capture` drops.
                msg?;
                // The user ended the turn. A superseding press signals the same
                // way and then drops its `finish_tx` (see `supersede_session`),
                // so `finishing` has to latch here: treating the subsequent
                // channel close as abandonment would discard the finished
                // recording that supersede exists to preserve.
                finishing = true;
                // Silence is now judged on the whole recording, below, rather
                // than on a deadline.
                awaiting_speech = false;
                stop_capture(&mut capture).await;
            }
            _ = tokio::time::sleep_until(no_speech_deadline), if awaiting_speech => {
                // Decided locally, on the samples. The transcript cannot answer
                // this: the endpoint returns " Thank you." for pure silence.
                if crate::speech::contains_speech(&pcm, sample_rate) {
                    awaiting_speech = false;
                    continue;
                }
                stop_capture(&mut capture).await;
                let (message, hint) = no_speech_error();
                let _ = out
                    .send(VoiceEvent::Error {
                        session,
                        message,
                        hint,
                    })
                    .await;
                return None;
            }
        }
    }

    warn_if_audio_was_shed(&pcm, sample_rate, first_chunk_at, last_chunk_at);
    Some(Recording { pcm, truncated })
}

/// Compare captured audio against the wall-clock span it was captured over.
///
/// A recording that covers materially less time than it took to make means the
/// producer shed chunks (see `record_utterance`'s draining notes). This cannot
/// recover them; it makes an otherwise invisible corruption visible, so a
/// transcript that came back subtly wrong has something to point at.
#[cfg(feature = "audio")]
fn warn_if_audio_was_shed(
    pcm: &[u8],
    sample_rate: u32,
    first: Option<tokio::time::Instant>,
    last: Option<tokio::time::Instant>,
) {
    let (Some(first), Some(last)) = (first, last) else {
        return;
    };
    let elapsed = last.saturating_duration_since(first).as_secs_f64();
    // Under a second there is not enough span for the ratio to mean anything.
    if elapsed < 1.0 {
        return;
    }
    let bytes_per_sec = f64::from(sample_rate) * 2.0;
    #[allow(clippy::cast_precision_loss)] // a recording is at most ~10 MB
    let captured = pcm.len() as f64 / bytes_per_sec;
    // The span is measured between chunk arrivals, so it under-counts by at
    // most one chunk. 10% is far above that and far below a real gap.
    if captured < elapsed * 0.9 {
        tracing::warn!(
            captured_secs = captured,
            elapsed_secs = elapsed,
            "voice batch: recording is shorter than the time it was captured over;              PCM chunks were shed and the transcript may have a gap"
        );
    }
}

/// Gate the recording locally, then transcribe it and emit at most one event.
///
/// Every event is stamped with `session`, including failures. This task can
/// outlive the recording by the length of an upload, so by the time it reports
/// anything the user may have moved on -- but deciding what that means is the
/// consumer's job, not this one's. Suppressing failures here (which an earlier
/// revision did, to stop a stale error tearing down a live recording) also hid
/// them from the user whose dictation had just been lost; with an id on the
/// event the consumer can decline the teardown and still show the news.
#[cfg(feature = "audio")]
#[allow(clippy::too_many_arguments)] // one session's worth of state, not a grab bag
async fn transcribe_and_emit(
    client: &BatchSttClient,
    config: &VoiceConfig,
    auth: &SharedVoiceAuth,
    endpoint: &str,
    recording: Recording,
    session: u64,
    out: &mpsc::Sender<VoiceEvent>,
) {
    let report_error = |e: VoiceError| async move {
        let _ = out
            .send(VoiceEvent::Error {
                session,
                message: e.to_string(),
                hint: None,
            })
            .await;
    };

    let Recording { pcm, truncated } = recording;

    // Nothing was said: say so, and send nothing. Two reasons, and the second
    // matters as much as the first. The endpoint hallucinates a stock phrase
    // over silence, so a request would put words in the user's prompt that they
    // never spoke; and a recording of an empty room is not something to upload
    // for no reason.
    if !crate::speech::contains_speech(&pcm, config.sample_rate) {
        let (message, hint) = no_speech_error();
        let _ = out
            .send(VoiceEvent::Error {
                session,
                message,
                hint,
            })
            .await;
        return;
    }

    // Resolved now, not at press time: this recording may be five minutes old
    // and a rotating session token could have expired in between. There is no
    // retry, so a 401 here would destroy the whole utterance.
    let bearer = match crate::auth::require_bearer(auth, endpoint).await {
        Ok(bearer) => bearer,
        Err(e) => return report_error(e).await,
    };

    let wav = crate::stt::batch::pcm_to_wav(&pcm, config.sample_rate);
    // Release the PCM before the upload; the WAV is now the only copy.
    drop(pcm);

    match client.transcribe(config, &bearer, wav).await {
        Ok(text) if text.trim().is_empty() => {
            // The gate said speech and the endpoint disagreed. Report it the
            // same way rather than committing an empty utterance.
            let (message, hint) = no_speech_error();
            let _ = out
                .send(VoiceEvent::Error {
                    session,
                    message,
                    hint,
                })
                .await;
        }
        Ok(text) => {
            let event = if truncated {
                VoiceEvent::UtteranceTruncated {
                    session,
                    text: text.trim().to_owned(),
                    limit_secs: RECORDING_MAX_SECS,
                }
            } else {
                VoiceEvent::UtteranceFinal {
                    session,
                    text: text.trim().to_owned(),
                }
            };
            let _ = out.send(event).await;
        }
        Err(e) => report_error(e).await,
    }
}

#[cfg(all(test, feature = "audio"))]
mod tests {
    use super::*;

    /// Chunks captured before the STT sender arrives are flushed ahead of the live stream, with nothing reordered or dropped across the handoff.
    #[tokio::test]
    async fn forward_pcm_delivers_buffered_then_live_in_order() {
        let (mic_tx, mic_rx) = mpsc::channel::<Vec<u8>>(8);
        let (tx_tx, tx_rx) = tokio::sync::oneshot::channel();
        let (audio_tx, mut audio_rx) = mpsc::channel::<Vec<u8>>(8);
        let task = tokio::spawn(forward_pcm(mic_rx, tx_rx));

        // These chunks buffer before the live sender is handed over, then flush once it arrives
        // (Keep `mic_tx` open across the handoff: a mic that closes before the socket is ready discards the backlog; see the separate test.)
        mic_tx.send(vec![1]).await.unwrap();
        mic_tx.send(vec![2]).await.unwrap();
        tx_tx.send(audio_tx).unwrap();
        assert_eq!(audio_rx.recv().await, Some(vec![1]));
        assert_eq!(audio_rx.recv().await, Some(vec![2]));

        // Later chunks stream live, still in order
        mic_tx.send(vec![3]).await.unwrap();
        assert_eq!(audio_rx.recv().await, Some(vec![3]));

        drop(mic_tx);
        assert_eq!(audio_rx.recv().await, None, "ends when the mic closes");
        task.await.unwrap();
    }

    /// When the mic stops before the socket is ready, the forwarder exits cleanly.
    #[tokio::test]
    async fn forward_pcm_returns_when_mic_closes_before_connect() {
        let (mic_tx, mic_rx) = mpsc::channel::<Vec<u8>>(8);
        let (_tx_tx, tx_rx) = tokio::sync::oneshot::channel::<mpsc::Sender<Vec<u8>>>();
        let task = tokio::spawn(forward_pcm(mic_rx, tx_rx));
        drop(mic_tx);
        task.await.unwrap();
    }

    /// When connect fails (the oneshot sender is dropped without a value), the forwarder exits and discards the buffered audio.
    #[tokio::test]
    async fn forward_pcm_returns_when_connect_fails() {
        let (mic_tx, mic_rx) = mpsc::channel::<Vec<u8>>(8);
        let (tx_tx, tx_rx) = tokio::sync::oneshot::channel::<mpsc::Sender<Vec<u8>>>();
        let task = tokio::spawn(forward_pcm(mic_rx, tx_rx));
        mic_tx.send(vec![1]).await.unwrap();
        drop(tx_tx);
        task.await.unwrap();
    }

    #[test]
    fn no_speech_error_carries_permission_hint() {
        let (message, hint) = no_speech_error();
        assert_eq!(message, "No speech was detected. Voice stopped.");
        assert!(hint.is_some_and(|hint| hint.contains(crate::probe::mic_fix_help())));
    }

    /// A capture session that records whether it was stopped, standing in for
    /// the microphone. Stopping drops the sender clone the producer holds,
    /// which is exactly what closing the real device does to `mic_rx`.
    struct FakeCapture {
        stopped: Arc<std::sync::atomic::AtomicBool>,
        _mic_tx: mpsc::Sender<Vec<u8>>,
    }

    impl CaptureControl for FakeCapture {
        fn stop(self) {
            self.stopped
                .store(true, std::sync::atomic::Ordering::Release);
            // `self` drops here, releasing the producer's sender clone.
        }
    }

    /// 16 kHz mono PCM of `secs` seconds of a 200 Hz tone under a syllable-rate
    /// envelope: loud enough and high enough to pass the local speech gate.
    ///
    /// The envelope is not what makes it pass. `crate::speech` deliberately does
    /// NOT test amplitude modulation (it measured how much silence padded a clip
    /// rather than what the sound was, and rejected real speech), so a constant
    /// 200 Hz tone would clear the same two gates. The envelope is here only
    /// because it makes the fixture resemble the speech these tests stand in for.
    fn speechlike(secs: f32) -> Vec<u8> {
        use std::f32::consts::TAU;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let n = (16_000.0 * secs) as usize;
        let mut out = Vec::with_capacity(n * 2);
        for i in 0..n {
            #[allow(clippy::cast_precision_loss)]
            let t = i as f32 / 16_000.0;
            let envelope = 0.55 + 0.45 * (TAU * 3.5 * t).sin();
            #[allow(clippy::cast_possible_truncation)]
            let sample = ((TAU * 200.0 * t).sin() * envelope * 0.5 * f32::from(i16::MAX)) as i16;
            out.extend_from_slice(&sample.to_le_bytes());
        }
        out
    }

    /// A streaming socket under test control: events are pushed in from the
    /// test, and `finish_audio` is recorded rather than sent anywhere.
    struct FakeStream {
        events: mpsc::Receiver<StreamingSttEvent>,
        finished: Arc<std::sync::atomic::AtomicBool>,
    }

    impl StreamingControl for FakeStream {
        fn finish_audio(&mut self) {
            self.finished
                .store(true, std::sync::atomic::Ordering::Release);
        }
        async fn recv(&mut self) -> Option<StreamingSttEvent> {
            self.events.recv().await
        }
    }

    fn speech_final(text: &str) -> StreamingSttEvent {
        StreamingSttEvent::Partial(crate::stt::SttTranscriptPartial {
            text: text.to_owned(),
            is_final: true,
            speech_final: true,
        })
    }

    /// The loss `FinishAndDetach` exists to prevent, on the streaming transport:
    /// a press lands after the user released but before the server sent its
    /// trailing final. Aborting there destroyed the utterance, because committed
    /// text comes only from `speech_final` / `Done` -- every interim before it is
    /// overwritten and never committed.
    #[tokio::test]
    async fn a_supersede_between_release_and_the_trailing_final_still_delivers_it() {
        let (ev_tx, ev_rx) = mpsc::channel::<StreamingSttEvent>(8);
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stream = FakeStream {
            events: ev_rx,
            finished: Arc::clone(&finished),
        };
        let FakeSession {
            capture, stopped, ..
        } = fake_session();
        let (finish_tx, finish_rx) = mpsc::channel::<()>(1);
        let (out, mut out_rx) = mpsc::channel::<VoiceEvent>(8);

        let reader = tokio::spawn(run_streaming_reader(stream, capture, finish_rx, 7, out));

        // The user released and a new press superseded this session: signal the
        // finish, then drop the sender exactly as `supersede_session` does.
        finish_tx.send(()).await.unwrap();
        drop(finish_tx);
        // Wait until the reader has actually taken the finish -- stopping the
        // microphone is its observable half -- so the server's answer really does
        // arrive *after* the release, which is the case under test.
        while !stopped.load(std::sync::atomic::Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        // Only now does the server answer, which is the whole point.
        ev_tx
            .send(speech_final("the trailing final"))
            .await
            .unwrap();
        ev_tx
            .send(StreamingSttEvent::Done {
                text: String::new(),
            })
            .await
            .unwrap();

        let event = out_rx
            .recv()
            .await
            .expect("the utterance must be delivered");
        assert_eq!(
            event,
            VoiceEvent::UtteranceFinal {
                session: 7,
                text: "the trailing final".to_owned(),
            },
            "a detached streaming session must still deliver, stamped with its own id"
        );
        reader.await.unwrap();
        assert!(
            finished.load(std::sync::atomic::Ordering::Acquire),
            "the release must have signalled end-of-audio"
        );
        assert!(
            stopped.load(std::sync::atomic::Ordering::Acquire),
            "the microphone must be released as soon as the turn ends"
        );
    }

    /// The other half of detaching: a server that never sends the trailing final
    /// must not keep the task and its socket alive for the rest of the process.
    #[tokio::test(start_paused = true)]
    async fn a_detached_streaming_session_gives_up_on_its_own_deadline() {
        let (_ev_tx, ev_rx) = mpsc::channel::<StreamingSttEvent>(8);
        let stream = FakeStream {
            events: ev_rx,
            finished: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let FakeSession {
            capture, stopped, ..
        } = fake_session();
        let (finish_tx, finish_rx) = mpsc::channel::<()>(1);
        let (out, _out_rx) = mpsc::channel::<VoiceEvent>(8);

        let reader = tokio::spawn(run_streaming_reader(stream, capture, finish_rx, 9, out));
        finish_tx.send(()).await.unwrap();
        drop(finish_tx);

        // The deadline does not exist until the reader has taken the finish, so
        // moving the clock before that proves nothing about it. Stopping the
        // microphone is the observable half of taking the finish.
        while !stopped.load(std::sync::atomic::Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(STREAMING_FINISH_TIMEOUT + std::time::Duration::from_secs(1)).await;
        // Generous, and it cannot expire first: the reader's own deadline is now
        // in the past, so it is runnable and gets polled before the paused clock
        // is allowed to move again.
        tokio::time::timeout(std::time::Duration::from_secs(60), reader)
            .await
            .expect("the reader must give up rather than wait forever")
            .unwrap();
    }

    /// Dropping the finish channel *before* the turn ends is abandonment, not a
    /// finish: there is nothing to wait for, so the reader stops.
    #[tokio::test]
    async fn dropping_the_finish_channel_before_release_ends_the_reader() {
        let (_ev_tx, ev_rx) = mpsc::channel::<StreamingSttEvent>(8);
        let stream = FakeStream {
            events: ev_rx,
            finished: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let FakeSession { capture, .. } = fake_session();
        let (finish_tx, finish_rx) = mpsc::channel::<()>(1);
        let (out, _out_rx) = mpsc::channel::<VoiceEvent>(8);

        let reader = tokio::spawn(run_streaming_reader(stream, capture, finish_rx, 11, out));
        drop(finish_tx);
        tokio::time::timeout(std::time::Duration::from_secs(5), reader)
            .await
            .expect("an abandoned session must not linger")
            .unwrap();
    }

    /// The pieces of a stubbed capture session: the fake device, the producer's
    /// sender, the consumer's receiver, and a flag set when the device is
    /// explicitly stopped.
    struct FakeSession {
        capture: FakeCapture,
        mic_tx: mpsc::Sender<Vec<u8>>,
        mic_rx: mpsc::Receiver<Vec<u8>>,
        stopped: Arc<std::sync::atomic::AtomicBool>,
    }

    fn fake_session() -> FakeSession {
        let (mic_tx, mic_rx) = mpsc::channel::<Vec<u8>>(64);
        let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let capture = FakeCapture {
            stopped: Arc::clone(&stopped),
            _mic_tx: mic_tx.clone(),
        };
        FakeSession {
            capture,
            mic_tx,
            mic_rx,
            stopped,
        }
    }

    /// The release path: the user lets go, capture stops, and everything still
    /// in the channel is kept. Returning as soon as `stop()` returned would
    /// clip the tail.
    #[tokio::test]
    async fn release_stops_capture_and_keeps_every_queued_chunk() {
        let FakeSession {
            capture,
            mic_tx,
            mic_rx,
            stopped,
        } = fake_session();
        let (finish_tx, mut finish_rx) = mpsc::channel::<()>(1);
        let (out, _out_rx) = mpsc::channel::<VoiceEvent>(8);

        for _ in 0..4 {
            mic_tx.send(speechlike(0.1)).await.unwrap();
        }
        finish_tx.send(()).await.unwrap();
        drop(mic_tx); // the producer's own clone; the fake holds the other

        let recording = record_utterance(capture, mic_rx, &mut finish_rx, 16_000, 1, &out)
            .await
            .expect("a released recording is returned");
        assert!(stopped.load(std::sync::atomic::Ordering::Acquire));
        assert!(!recording.truncated);
        assert_eq!(
            recording.pcm.len(),
            speechlike(0.1).len() * 4,
            "every queued chunk must survive the drain"
        );
    }

    /// At the cap the recording stops, keeps the part of the final chunk that
    /// fits, and is marked truncated so the caller can say so.
    #[tokio::test]
    async fn the_cap_truncates_without_discarding_the_partial_chunk() {
        let FakeSession {
            capture,
            mic_tx,
            mic_rx,
            stopped,
        } = fake_session();
        let (_finish_tx, mut finish_rx) = mpsc::channel::<()>(1);
        let (out, _out_rx) = mpsc::channel::<VoiceEvent>(8);

        // A rate of 1 Hz makes the cap 2 bytes per second * 300s = 600 bytes.
        let max = recording_max_bytes(1);
        let feeder = tokio::spawn(async move {
            let chunk = vec![0u8; max / 2 + 10];
            for _ in 0..3 {
                if mic_tx.send(chunk.clone()).await.is_err() {
                    break;
                }
            }
        });

        let recording = record_utterance(capture, mic_rx, &mut finish_rx, 1, 1, &out)
            .await
            .expect("a capped recording is still returned");
        let _ = feeder.await;
        assert!(recording.truncated, "the cap must be reported");
        assert_eq!(
            recording.pcm.len(),
            max,
            "the buffer must be filled exactly to the cap, not left short"
        );
        assert!(stopped.load(std::sync::atomic::Ordering::Acquire));
    }

    /// Holding the key in silence past the watchdog tears the session down and
    /// says so. The decision is local: the endpoint answers " Thank you." for
    /// silence, so the transcript could not be used for this.
    #[tokio::test(start_paused = true)]
    async fn silence_past_the_watchdog_reports_no_speech_and_returns_nothing() {
        let FakeSession {
            capture,
            mic_tx,
            mic_rx,
            stopped,
        } = fake_session();
        let (_finish_tx, mut finish_rx) = mpsc::channel::<()>(1);
        let (out, mut out_rx) = mpsc::channel::<VoiceEvent>(8);

        let feeder = tokio::spawn(async move {
            // Digital silence, as a denied microphone produces.
            for _ in 0..5 {
                if mic_tx.send(vec![0u8; 3200]).await.is_err() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        });

        let recording = record_utterance(capture, mic_rx, &mut finish_rx, 16_000, 1, &out).await;
        assert!(recording.is_none(), "a silent session yields no recording");
        assert!(stopped.load(std::sync::atomic::Ordering::Acquire));
        match out_rx.try_recv() {
            Ok(VoiceEvent::Error { message, .. }) => {
                assert_eq!(message, "No speech was detected. Voice stopped.");
            }
            other => panic!("expected a no-speech error, got {other:?}"),
        }
        feeder.abort();
    }

    /// Real speech disarms the watchdog, so a long hold is not torn down while
    /// the user is still talking -- the bug that made batch mode unusable past
    /// ten seconds.
    #[tokio::test(start_paused = true)]
    async fn speech_disarms_the_watchdog_so_a_long_hold_survives() {
        let FakeSession {
            capture,
            mic_tx,
            mic_rx,
            stopped: _stopped,
        } = fake_session();
        let (finish_tx, mut finish_rx) = mpsc::channel::<()>(1);
        let (out, mut out_rx) = mpsc::channel::<VoiceEvent>(8);

        let feeder = tokio::spawn(async move {
            mic_tx.send(speechlike(1.0)).await.unwrap();
            // Well past NO_SPEECH_TIMEOUT.
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            mic_tx.send(speechlike(0.5)).await.unwrap();
            let _ = finish_tx.send(()).await;
        });

        let recording = record_utterance(capture, mic_rx, &mut finish_rx, 16_000, 1, &out)
            .await
            .expect("a 30s hold with speech must produce a recording");
        assert!(
            recording.pcm.len() > speechlike(1.0).len(),
            "audio from both sides of the pause must be kept"
        );
        assert!(
            out_rx.try_recv().is_err(),
            "no error event may be emitted for a hold that contained speech"
        );
        let _ = feeder.await;
    }

    /// Supersede signals `finish_tx` and then drops it. The recording must
    /// survive that: the whole point of detaching (see [`ActivePtt`]) is that a
    /// re-press does not destroy an utterance the user already finished
    /// speaking.
    #[tokio::test]
    async fn a_finished_recording_survives_its_finish_sender_being_dropped() {
        let FakeSession {
            capture,
            mic_tx,
            mic_rx,
            stopped,
        } = fake_session();
        let (finish_tx, mut finish_rx) = mpsc::channel::<()>(1);
        let (out, mut out_rx) = mpsc::channel::<VoiceEvent>(8);

        mic_tx.send(speechlike(0.5)).await.unwrap();
        drop(mic_tx);
        // Exactly what `supersede_session` does: signal, then let the sender go.
        finish_tx.send(()).await.unwrap();
        drop(finish_tx);

        let recording = record_utterance(capture, mic_rx, &mut finish_rx, 16_000, 1, &out)
            .await
            .expect("a superseded session must still deliver its recording");
        assert_eq!(recording.pcm.len(), speechlike(0.5).len());
        assert!(stopped.load(std::sync::atomic::Ordering::Acquire));
        assert!(
            out_rx.try_recv().is_err(),
            "no error event for a clean finish"
        );
    }

    /// A dropped pipeline (its `finish_tx` gone) ends the session and releases
    /// the device rather than recording into a channel nobody will read.
    #[tokio::test]
    async fn a_dropped_pipeline_ends_the_session_and_releases_the_device() {
        let FakeSession {
            capture,
            mic_tx: _mic_tx,
            mic_rx,
            stopped,
        } = fake_session();
        let (finish_tx, mut finish_rx) = mpsc::channel::<()>(1);
        let (out, _out_rx) = mpsc::channel::<VoiceEvent>(8);
        drop(finish_tx);

        let recording = record_utterance(capture, mic_rx, &mut finish_rx, 16_000, 1, &out).await;
        assert!(recording.is_none());
        // `capture` was dropped rather than stopped; `Drop` on the real handle
        // releases the device. The fake records only explicit stops.
        assert!(!stopped.load(std::sync::atomic::Ordering::Acquire));
    }

    #[test]
    fn the_recording_cap_is_the_documented_five_minutes() {
        // 16 kHz mono 16-bit = 32_000 B/s.
        assert_eq!(recording_max_bytes(16_000), 32_000 * 300);
        assert_eq!(RECORDING_MAX_SECS, 300);
    }
}
