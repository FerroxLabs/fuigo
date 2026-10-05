//! Records, at session load, a turn the previous process never finished so it does not look like a silent stop.

use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};

use crate::session::persistence::Summary;

/// `stop_reason` for a turn lost with its process; distinct from `error` and `cancelled` so trace consumers can tell them apart.
pub const INTERRUPTED_STOP_REASON: &str = "interrupted";

/// Transcript line and `turn_result.error` text.
pub const INTERRUPTED_MESSAGE: &str = "Fuigo stopped before this turn finished (the agent process exited or was restarted). Committed tool results were kept.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterruptedTurn {
    /// Trace turn number the previous process uploaded `metadata.json` under. `None` when it cannot be known:
    /// the summary's trace counter names the newest *received* prompt, so when the lost turn is not that prompt
    /// (another prompt was queued behind it) its trace turn is unknown and no `turn_result.json` is written.
    pub trace_turn: Option<u64>,
    /// Prompt id of that turn; the `request_id` in its `metadata.json`.
    pub prompt_id: String,
    /// `ts` of the unclosed `turn_started`, when readable.
    pub started_at: Option<String>,
}

impl InterruptedTurn {
    pub(crate) fn model_reminder(&self) -> String {
        "The previous turn was interrupted (the system exited or was restarted). Work before this message may have been lost."
            .to_string()
    }

    /// Closes the turn on the replay rail so clients paint an end marker. Meta matches the actor's own emits so it stays cursor-addressable.
    pub(crate) fn turn_completed_update(
        &self,
        session_id: &agent_client_protocol::SessionId,
    ) -> crate::session::storage::SessionUpdate {
        let update = crate::session::turn_completion::build_turn_completed(
            self.prompt_id.clone(),
            serde_json::json!(INTERRUPTED_STOP_REASON),
            serde_json::json!(INTERRUPTED_MESSAGE),
            None,
            None,
            None,
        );
        let notification = crate::extensions::notification::SessionNotification {
            session_id: session_id.clone(),
            update,
            meta: Some(serde_json::json!({
                "eventId": crate::util::event_id::generate_event_id(&session_id.0),
                "agentTimestampMs": chrono::Utc::now().timestamp_millis(),
            })),
        };
        crate::session::storage::SessionUpdate::Fuigo(Box::new(notification))
    }

    /// `turn_result.json` for the trace turn whose `metadata.json` the dead process already uploaded.
    pub(crate) fn turn_result(&self) -> crate::upload::trace::TurnResultMetadata {
        crate::upload::trace::TurnResultMetadata {
            schema_version: crate::upload::trace::GCS_SCHEMA_VERSION,
            request_id: self.prompt_id.clone(),
            completed: false,
            stop_reason: Some(INTERRUPTED_STOP_REASON.to_string()),
            total_tokens: None,
            input_tokens: None,
            cached_input_tokens: None,
            output_tokens: None,
            error: Some(INTERRUPTED_MESSAGE.to_string()),
            finished_at: chrono::Utc::now().to_rfc3339(),
            signals: None,
            turn_delta: None,
            resolved_model: None,
            subagents_spawned: Vec::new(),
            start_prompt_mode: None,
            end_prompt_mode: None,
        }
    }

    /// Closes the open `turn_started` in `events.jsonl` so the next load does not report this turn again.
    /// Reports failure: the caller must know whether the turn is still open.
    pub(crate) fn close_events_turn(&self, session_dir: &Path) -> std::io::Result<()> {
        close_events_turn_as(
            session_dir,
            fuigo_session_events::TurnOutcomeLabel::Interrupted,
        )
    }
}

fn close_events_turn_as(
    session_dir: &Path,
    outcome: fuigo_session_events::TurnOutcomeLabel,
) -> std::io::Result<()> {
    fuigo_session_events::append_event_checked(
        session_dir,
        fuigo_session_events::Event::TurnEnded {
            outcome,
            cancellation_category: None,
            cancellation_context: None,
        },
    )
}

/// A recorded interruption, plus the replay line that carries its marker to a client that will not replay.
#[derive(Debug, Clone)]
pub(crate) struct RecoveredTurn {
    pub(crate) turn: InterruptedTurn,
    /// The marker as an `updates.jsonl` line (`method` + `params`), for `forward_raw_replay_line`.
    pub(crate) marker_line: String,
}

/// What a recovery that declared a turn lost produced.
pub(crate) enum RecoveryOutcome {
    /// The marker is committed and the events turn closed (or its closure failed and was logged).
    Recorded(RecoveredTurn),
    /// The marker append outlived [`RECOVERY_APPEND_TIMEOUT`](crate::session::turn_owner_lock::RECOVERY_APPEND_TIMEOUT).
    /// The append is already queued and will still land, so it is not abandoned: [`DeferredRecovery::finish`]
    /// awaits it and then closes the turn. Until then this holds a *shared* turn-owner lock, so no other load (here
    /// or in another process) can start a second recovery and append a second marker, while actors can still run.
    Deferred(DeferredRecovery),
}

/// The open `turn_started` a deferred recovery will close: its `ts` and its own `prompt_id` (absent in old logs).
#[derive(Debug, Clone, PartialEq, Eq)]
struct OpenTurn {
    ts: Option<String>,
    prompt_id: Option<String>,
}

/// Lost turns whose marker is still being written, by session dir. An actor in this process that is about to start
/// a turn closes the lost one first ([`close_deferred_turn_before_new_turn`]), so its own `turn_started` never lands
/// inside the lost turn; otherwise [`DeferredRecovery::finish`] closes it when the marker commits. Whichever runs
/// first removes the entry, under this mutex, so the turn is closed exactly once.
static DEFERRED_CLOSURES: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<PathBuf, (u64, OpenTurn)>>,
> = std::sync::LazyLock::new(Default::default);
static DEFERRED_CLOSURE_IDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn deferred_closures()
-> std::sync::MutexGuard<'static, std::collections::HashMap<PathBuf, (u64, OpenTurn)>> {
    DEFERRED_CLOSURES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Removes this recovery's pending closure if it is still registered (and still this recovery's), returning it.
fn take_deferred_closure(
    closures: &mut std::collections::HashMap<PathBuf, (u64, OpenTurn)>,
    session_dir: &Path,
    id: u64,
) -> Option<OpenTurn> {
    match closures.get(session_dir) {
        Some((entry_id, _)) if *entry_id == id => {
            closures.remove(session_dir).map(|(_, open)| open)
        }
        _ => None,
    }
}

/// Closes `open` as interrupted only if it is still the newest turn event: a turn that started since (in another
/// process that shares the session) must not be closed in its place. `Ok(false)` when it was left alone.
fn close_if_still_open(session_dir: &Path, open: &OpenTurn) -> std::io::Result<bool> {
    match last_turn_event(&session_dir.join("events.jsonl"))? {
        Some(LastTurnEvent::Started { ts, prompt_id })
            if ts == open.ts && prompt_id == open.prompt_id =>
        {
            close_events_turn_as(
                session_dir,
                fuigo_session_events::TurnOutcomeLabel::Interrupted,
            )?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Called by an actor right before it writes `turn_started`. If this session has a lost turn whose marker is still
/// being written, the lost turn is closed now, so the new turn does not start inside it (and cannot later be closed
/// by it). The marker append was queued before anything this turn persists, so it still lands ahead of the turn.
pub(crate) fn close_deferred_turn_before_new_turn(session_dir: &Path) {
    let mut closures = deferred_closures();
    if closures.is_empty() {
        return;
    }
    let Some((_, open)) = closures.remove(session_dir) else {
        return;
    };
    match close_if_still_open(session_dir, &open) {
        Ok(true) => tracing::warn!(
            dir = %session_dir.display(),
            "a turn is starting while the previous process's lost turn is still being recorded; closed the lost turn first"
        ),
        Ok(false) => {}
        Err(error) => tracing::warn!(
            dir = %session_dir.display(),
            %error,
            "failed to close a lost turn before a new turn started"
        ),
    }
}

type PendingAppend = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<(), crate::session::persistence::DurableAppendError>,
            >,
    >,
>;

/// A recovery whose marker append outlived its bound; see [`RecoveryOutcome::Deferred`].
pub(crate) struct DeferredRecovery {
    append: PendingAppend,
    turn: InterruptedTurn,
    marker_line: String,
    session_dir: PathBuf,
    session_id: agent_client_protocol::SessionId,
    closure_id: u64,
    /// Keeps other recoveries out until the append resolves. Dropped with this value.
    _shared_hold: Option<crate::session::turn_owner_lock::TurnOwnerLock>,
}

impl std::fmt::Debug for DeferredRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeferredRecovery")
            .field("turn", &self.turn)
            .field("session_dir", &self.session_dir)
            .finish_non_exhaustive()
    }
}

impl Drop for DeferredRecovery {
    /// Dropped unfinished (the load failed): the turn stays open for the next load, which finds the marker if it did land.
    fn drop(&mut self) {
        let _ = take_deferred_closure(&mut deferred_closures(), &self.session_dir, self.closure_id);
    }
}

impl DeferredRecovery {
    /// The lost turn this recovery declared.
    pub(crate) fn turn(&self) -> &InterruptedTurn {
        &self.turn
    }

    /// Waits for the queued marker append, then closes the lost turn (unless an actor already did, just before its
    /// own turn started). `Some` when the marker committed, so the caller can tell a live client and the model.
    pub(crate) async fn finish(mut self) -> Option<RecoveredTurn> {
        let result = self.append.as_mut().await;
        // Held until the closure is written, so an actor cannot start a turn between the check and the append.
        let mut closures = deferred_closures();
        let pending = take_deferred_closure(&mut closures, &self.session_dir, self.closure_id);
        match result {
            Ok(()) => {}
            Err(crate::session::persistence::DurableAppendError::Committed(error)) => {
                tracing::warn!(
                    session_id = %self.session_id.0,
                    %error,
                    "late interrupted-turn marker committed with a bookkeeping failure"
                );
            }
            Err(error) => {
                if pending.is_some() {
                    tracing::warn!(
                        session_id = %self.session_id.0,
                        %error,
                        "late interrupted-turn marker not committed; the turn stays open for the next load unless a turn has started since"
                    );
                } else {
                    // An actor's pre-turn hook already took the closure before its own turn started, so this does not
                    // claim the turn stays open; whether the hook's close succeeded is logged where it ran.
                    tracing::warn!(
                        session_id = %self.session_id.0,
                        %error,
                        "late interrupted-turn marker not committed; an actor's pre-turn hook already took the closure, so this recovery leaves the turn alone (the hook logged whether its close succeeded)"
                    );
                }
                drop(closures);
                return None;
            }
        }
        if let Some(open) = pending {
            // Still registered: no actor in this process has started a turn since, so the lost turn is still open
            // unless another process sharing the session started one (checked).
            match close_if_still_open(&self.session_dir, &open) {
                Ok(true) => {}
                Ok(false) => tracing::warn!(
                    session_id = %self.session_id.0,
                    "late interrupted-turn marker committed, but a newer turn has started; the lost turn is left as is"
                ),
                Err(error) => tracing::warn!(
                    session_id = %self.session_id.0,
                    %error,
                    "late interrupted turn recorded but events.jsonl not closed; the next load reuses the marker and retries"
                ),
            }
        }
        drop(closures);
        Some(RecoveredTurn {
            turn: self.turn.clone(),
            marker_line: std::mem::take(&mut self.marker_line),
        })
    }
}

/// Records the turn the previous process never finished, exactly once, and only when that process is gone.
///
/// - Liveness first: without the exclusive turn-owner lock (another actor holds the session, or the lock cannot
///   be taken) nothing is declared, because an open turn in a live process is running, not lost.
/// - Idempotent: a marker an earlier, itself interrupted recovery already committed is reused, not appended again;
///   a turn that did reach a terminal replay record is closed with that outcome instead of being called a crash.
/// - The events log is closed only after the marker is durably committed, so a failed append leaves the turn open
///   for the next load to retry rather than losing the interruption for good.
/// - A failed closure is logged; the next load finds the committed marker and only retries the closure.
/// - The append is bounded; one that outlives the bound is not abandoned (it is already queued and will land) but
///   handed back as [`RecoveryOutcome::Deferred`], still holding a shared lock, for the caller to finish.
pub(crate) async fn recover_interrupted_turn<A, Fut>(
    session_dir: &Path,
    updates_path: Option<&Path>,
    summary: &Summary,
    session_id: &agent_client_protocol::SessionId,
    append: A,
) -> Option<RecoveryOutcome>
where
    A: FnOnce(crate::session::storage::SessionUpdate) -> Fut,
    Fut: std::future::Future<Output = Result<(), crate::session::persistence::DurableAppendError>>
        + 'static,
{
    use crate::session::turn_owner_lock::{
        RECOVERY_APPEND_TIMEOUT, RecoveryLock, report_lock_unavailable, try_recovery_lock,
    };

    // Idempotence rests on finding an earlier marker in `updates.jsonl`. Every shipped storage adapter (jsonl)
    // has one; a backend without it cannot rule out a duplicate marker, so nothing is declared there.
    let Some(updates_path) = updates_path else {
        tracing::debug!(
            session_id = %session_id.0,
            "interrupted-turn recovery skipped: storage has no updates file to check for an earlier marker"
        );
        return None;
    };
    let guard = match try_recovery_lock(session_dir) {
        RecoveryLock::Acquired(guard) => guard,
        RecoveryLock::HeldElsewhere => {
            tracing::debug!(
                session_id = %session_id.0,
                "interrupted-turn recovery skipped: a live actor holds the session"
            );
            return None;
        }
        RecoveryLock::Unknown(error) => {
            report_lock_unavailable(
                session_dir,
                &error,
                "interrupted-turn recovery skipped: session liveness unknown",
            );
            return None;
        }
    };
    let (turn, started_prompt_id) = detect_with_started_prompt_id(session_dir, summary)?;
    let prior = match newest_turn_completed(updates_path) {
        Ok(prior) => prior,
        Err(error) => {
            tracing::warn!(
                session_id = %session_id.0,
                %error,
                "interrupted-turn recovery skipped: updates.jsonl unreadable, so an earlier marker cannot be ruled out"
            );
            return None;
        }
    };
    let marker_line = match prior {
        Some(record) if record.prompt_id == turn.prompt_id => {
            if record.stop_reason != INTERRUPTED_STOP_REASON {
                // The turn reached its terminal record; only its events.jsonl closure was lost. Not a crash.
                let outcome = outcome_for_stop_reason(&record.stop_reason);
                if let Err(error) = close_events_turn_as(session_dir, outcome) {
                    tracing::warn!(
                        session_id = %session_id.0,
                        %error,
                        "failed to close an ended turn in events.jsonl"
                    );
                }
                return None;
            }
            // An earlier recovery committed the marker and stopped before closing the events log.
            record.line
        }
        _ => {
            let update = turn.turn_completed_update(session_id);
            let line = match serde_json::to_string(&update) {
                Ok(line) => line,
                Err(error) => {
                    tracing::warn!(session_id = %session_id.0, %error, "interrupted-turn marker did not serialize");
                    return None;
                }
            };
            // The one await under the exclusive lock is bounded, so an actor waiting for its shared lock is too.
            let mut pending: PendingAppend = Box::pin(append(update));
            let appended = match tokio::time::timeout(RECOVERY_APPEND_TIMEOUT, pending.as_mut())
                .await
            {
                Ok(result) => result,
                Err(_elapsed) => {
                    // The append is queued and will still land; dropping it would lose only the ack. Hand it back
                    // with the turn still to close, trading the exclusive lock for a shared one.
                    tracing::warn!(
                        session_id = %session_id.0,
                        "interrupted-turn marker append outlived its bound; finishing it in the background"
                    );
                    let closure_id =
                        DEFERRED_CLOSURE_IDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    deferred_closures().insert(
                        session_dir.to_path_buf(),
                        (
                            closure_id,
                            OpenTurn {
                                ts: turn.started_at.clone(),
                                prompt_id: started_prompt_id,
                            },
                        ),
                    );
                    return Some(RecoveryOutcome::Deferred(DeferredRecovery {
                        append: pending,
                        turn,
                        marker_line: line,
                        session_dir: session_dir.to_path_buf(),
                        session_id: session_id.clone(),
                        closure_id,
                        _shared_hold: guard.into_shared(),
                    }));
                }
            };
            match appended {
                Ok(()) => {}
                Err(crate::session::persistence::DurableAppendError::Committed(error)) => {
                    tracing::warn!(
                        session_id = %session_id.0,
                        %error,
                        "interrupted-turn marker committed with a bookkeeping failure"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        session_id = %session_id.0,
                        %error,
                        "interrupted-turn marker not committed; the turn stays open for the next load"
                    );
                    return None;
                }
            }
            line
        }
    };
    if let Err(error) = turn.close_events_turn(session_dir) {
        tracing::warn!(
            session_id = %session_id.0,
            %error,
            "interrupted turn recorded but events.jsonl not closed; the next load reuses the marker and retries"
        );
    }
    Some(RecoveryOutcome::Recorded(RecoveredTurn {
        turn,
        marker_line,
    }))
}

fn outcome_for_stop_reason(stop_reason: &str) -> fuigo_session_events::TurnOutcomeLabel {
    use fuigo_session_events::TurnOutcomeLabel;
    match stop_reason {
        INTERRUPTED_STOP_REASON => TurnOutcomeLabel::Interrupted,
        "cancelled" => TurnOutcomeLabel::Cancelled,
        // `prompt_complete_fields`: an `Err` turn stops as `error`, or `rate_limit` for a rate-limit error.
        "error" | "rate_limit" => TurnOutcomeLabel::Error,
        // `acp::StopReason`s other than `cancelled`: the turn ran to a normal end.
        "end_turn" | "max_tokens" | "max_turn_requests" | "refusal" => TurnOutcomeLabel::Completed,
        // A stop reason this build does not know (a newer shell wrote it). The turn *did* end, which is all this
        // closure asserts; it is labelled `completed` and the unknown reason is logged, not guessed at.
        other => {
            tracing::warn!(
                stop_reason = other,
                "unknown terminal stop reason; closing the events turn as completed"
            );
            TurnOutcomeLabel::Completed
        }
    }
}

/// `Some` when the newest turn in `session_dir` started but never ended. The turn is named by the `prompt_id` in its
/// own `turn_started`; `summary` names it only for logs written before that field existed, and gives its trace turn
/// only when the summary's newest prompt is that same turn.
pub(crate) fn detect_interrupted_turn(
    session_dir: &Path,
    summary: &Summary,
) -> Option<InterruptedTurn> {
    detect_with_started_prompt_id(session_dir, summary).map(|(turn, _)| turn)
}

/// [`detect_interrupted_turn`], plus the `prompt_id` exactly as its `turn_started` carries it (`None` in old logs).
fn detect_with_started_prompt_id(
    session_dir: &Path,
    summary: &Summary,
) -> Option<(InterruptedTurn, Option<String>)> {
    let (started_at, started_prompt_id) = match last_turn_event(&session_dir.join("events.jsonl")) {
        Ok(Some(LastTurnEvent::Started { ts, prompt_id })) => (ts, prompt_id),
        Ok(Some(LastTurnEvent::Ended) | None) => return None,
        Err(error) => {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(%error, "events.jsonl unreadable; no interrupted turn detected");
            }
            return None;
        }
    };
    // The turn names itself in `turn_started`. The summary's `request_id` is set when a prompt is *received*, so
    // with a prompt queued behind the running turn it names the queued prompt; it is only a fallback for logs
    // written before `turn_started` carried the prompt id.
    let (prompt_id, trace_turn) = match started_prompt_id.clone() {
        Some(prompt_id) => {
            let trace_turn = (summary.request_id.as_deref() == Some(prompt_id.as_str()))
                .then(|| summary.next_trace_turn.checked_sub(1))
                .flatten();
            (prompt_id, trace_turn)
        }
        None => (
            summary.request_id.clone()?,
            Some(summary.next_trace_turn.checked_sub(1)?),
        ),
    };
    Some((
        InterruptedTurn {
            trace_turn,
            prompt_id,
            started_at,
        },
        started_prompt_id,
    ))
}

/// Read size for the backward scan.
const SCAN_CHUNK_BYTES: usize = 64 * 1024;
/// Lines longer than this are skipped unparsed. A turn event is a few hundred bytes and a `turn_completed`
/// replay line carries at most the turn's final text, so neither is ever near it; memory stays bounded by
/// one chunk plus this cap whatever the file size.
const MAX_SCANNED_LINE_BYTES: usize = 8 * 1024 * 1024;

/// Visits the lines of `path` newest first until `visit` breaks, holding at most one chunk plus one line.
/// An unterminated last line (a torn tail) is visited like any other; empty lines are not visited.
fn scan_lines_backwards(
    path: &Path,
    mut visit: impl FnMut(&[u8]) -> std::ops::ControlFlow<()>,
) -> std::io::Result<()> {
    use std::ops::ControlFlow;

    let mut file = std::fs::File::open(path)?;
    let mut pos = file.metadata()?.len();
    let mut buf = vec![0u8; SCAN_CHUNK_BYTES];
    // The line being assembled continues past the start of the chunk just read. Its pieces are kept newest
    // first and joined once when the line is complete, so assembling an L-byte line costs O(L), not O(L^2).
    let mut pieces: Vec<Vec<u8>> = Vec::new();
    let mut carried = 0usize;
    let mut oversized = false;
    let mut emit = |head: &[u8], pieces: &[Vec<u8>], carried: usize, oversized: bool| {
        if oversized {
            return ControlFlow::Continue(());
        }
        if pieces.is_empty() {
            return if head.is_empty() {
                ControlFlow::Continue(())
            } else {
                visit(head)
            };
        }
        let mut whole = Vec::with_capacity(head.len() + carried);
        whole.extend_from_slice(head);
        for piece in pieces.iter().rev() {
            whole.extend_from_slice(piece);
        }
        visit(&whole)
    };
    while pos > 0 {
        let n = usize::try_from(pos.min(SCAN_CHUNK_BYTES as u64)).unwrap_or(SCAN_CHUNK_BYTES);
        pos -= n as u64;
        file.seek(SeekFrom::Start(pos))?;
        let chunk = &mut buf[..n];
        file.read_exact(chunk)?;
        let mut end = n;
        while let Some(newline) = chunk[..end].iter().rposition(|&b| b == b'\n') {
            if emit(&chunk[newline + 1..end], &pieces, carried, oversized).is_break() {
                return Ok(());
            }
            pieces.clear();
            carried = 0;
            oversized = false;
            end = newline;
        }
        if !oversized && end > 0 {
            if carried + end > MAX_SCANNED_LINE_BYTES {
                oversized = true;
                pieces = Vec::new();
                carried = 0;
            } else {
                pieces.push(chunk[..end].to_vec());
                carried += end;
            }
        }
    }
    let _ = emit(&[], &pieces, carried, oversized);
    Ok(())
}

/// The part of `updates.jsonl` that a load's replay showed to EVERY subscriber of the session.
#[derive(Debug, Clone)]
pub(crate) struct BroadcastReplay {
    updates_path: PathBuf,
    through: u64,
}

impl BroadcastReplay {
    /// `None` when the load carried nothing to everyone: no replay (`replayed_through` is `None`), no updates file, or
    /// a replay aimed at one client (the load named a `target_client_id`, the loader). In that last case any other
    /// attached client has not seen what the replay read, so it must still get a late marker from the live forward.
    pub(crate) fn new(
        updates_path: Option<PathBuf>,
        replayed_through: Option<u64>,
        target_client_id: Option<&serde_json::Value>,
    ) -> Option<Self> {
        if target_client_id.is_some() {
            return None;
        }
        Some(Self {
            updates_path: updates_path?,
            through: replayed_through?,
        })
    }
}

/// Runs `forward` (the live delivery of a late-committed marker) unless the load's replay already carried the marker
/// to every subscriber, which would show it twice. Returns whether `forward` ran. The lookup reads the file, so it
/// runs off the caller's LocalSet.
pub(crate) async fn forward_late_marker_unless_replayed<F, Fut>(
    replay: Option<BroadcastReplay>,
    marker_line: &str,
    forward: F,
) -> bool
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    if let Some(replay) = replay {
        let marker_line = marker_line.to_owned();
        let carried = tokio::task::spawn_blocking(move || {
            marker_within_replayed_range(&replay.updates_path, &marker_line, replay.through)
        })
        .await
        .unwrap_or(false);
        if carried {
            return false;
        }
    }
    forward().await;
    true
}

/// How far back from the replay's end [`marker_within_replayed_range`] looks.
const REPLAYED_MARKER_SEARCH_WINDOW: u64 = 1 << 20;

/// Whether `marker_line` is among the first `replayed_through` bytes of `updates_path`: a load whose replay read that
/// far already showed the marker to its client, so a late-committed marker must not be forwarded live a second time.
/// Unreadable file or empty marker: `false` (forward; a duplicate is better than a client that never learns).
pub(crate) fn marker_within_replayed_range(
    updates_path: &Path,
    marker_line: &str,
    replayed_through: u64,
) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    // `marker_line` is the bare `{"method":..,"params":..}` form; the file stores the same record wrapped in an
    // envelope that puts a `"timestamp"` first (`SessionUpdateEnvelope`). Dropping the opening brace leaves the
    // `"method":..,"params":..}` tail, which is a verbatim substring of the stored line.
    let needle = marker_line
        .trim_end()
        .strip_prefix('{')
        .unwrap_or_default()
        .as_bytes();
    if needle.is_empty() {
        return false;
    }
    let Ok(mut file) = std::fs::File::open(updates_path) else {
        return false;
    };
    // A late marker lands within milliseconds of the replay's last read, so only the tail of the replayed range is
    // searched (bounded I/O and memory on a huge transcript). A marker older than the window is a miss, and a miss
    // only costs a duplicate live forward, never a lost one.
    let replayed_through = replayed_through.min(file.metadata().map_or(0, |meta| meta.len()));
    let start = replayed_through.saturating_sub(REPLAYED_MARKER_SEARCH_WINDOW);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return false;
    }
    let mut window = Vec::new();
    if file
        .take(replayed_through - start)
        .read_to_end(&mut window)
        .is_err()
    {
        return false;
    }
    contains(&window, needle)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[derive(Debug, PartialEq, Eq)]
enum LastTurnEvent {
    Started {
        ts: Option<String>,
        prompt_id: Option<String>,
    },
    Ended,
}

/// The newest `turn_started`/`turn_ended` in the events log, found by scanning backwards: correct for a turn of
/// any length, and it reads only back to that event.
fn last_turn_event(path: &Path) -> std::io::Result<Option<LastTurnEvent>> {
    let mut found = None;
    scan_lines_backwards(path, |line| {
        if !contains(line, b"turn_started") && !contains(line, b"turn_ended") {
            return std::ops::ControlFlow::Continue(());
        }
        let Ok(event) = serde_json::from_slice::<serde_json::Value>(line) else {
            return std::ops::ControlFlow::Continue(());
        };
        found = match event.get("type").and_then(serde_json::Value::as_str) {
            Some("turn_started") => Some(LastTurnEvent::Started {
                ts: event
                    .get("ts")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                prompt_id: event
                    .get("prompt_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
            }),
            Some("turn_ended") => Some(LastTurnEvent::Ended),
            _ => return std::ops::ControlFlow::Continue(()),
        };
        std::ops::ControlFlow::Break(())
    })?;
    Ok(found)
}

/// The newest `turn_completed` replay record in `updates.jsonl`.
#[derive(Debug)]
struct TerminalRecord {
    prompt_id: String,
    stop_reason: String,
    line: String,
}

fn newest_turn_completed(path: &Path) -> std::io::Result<Option<TerminalRecord>> {
    let mut found = None;
    let result = scan_lines_backwards(path, |line| {
        if !contains(line, b"turn_completed") {
            return std::ops::ControlFlow::Continue(());
        }
        let Ok(envelope) = serde_json::from_slice::<serde_json::Value>(line) else {
            return std::ops::ControlFlow::Continue(());
        };
        let update = &envelope["params"]["update"];
        if update["sessionUpdate"] != "turn_completed" {
            return std::ops::ControlFlow::Continue(());
        }
        let (Some(prompt_id), Some(stop_reason)) =
            (update["prompt_id"].as_str(), update["stop_reason"].as_str())
        else {
            return std::ops::ControlFlow::Continue(());
        };
        found = Some(TerminalRecord {
            prompt_id: prompt_id.to_owned(),
            stop_reason: stop_reason.to_owned(),
            line: String::from_utf8_lossy(line).into_owned(),
        });
        std::ops::ControlFlow::Break(())
    });
    match result {
        Ok(()) => Ok(found),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
#[path = "interrupted_turn_tests.rs"]
mod tests;
