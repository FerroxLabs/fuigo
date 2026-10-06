use super::*;

use crate::session::info::Info;
use crate::session::persistence::default_model_id;

/// A `Summary` whose telemetry counter names a turn that was in flight.
fn summary_with_open_turn(dir: &std::path::Path) -> Summary {
    let mut summary = Summary::new(
        &Info {
            id: agent_client_protocol::SessionId::new("interrupted-turn-test"),
            cwd: dir.to_string_lossy().into_owned(),
        },
        default_model_id(),
    )
    .expect("summary");
    summary.next_trace_turn = 4;
    summary.request_id = Some("req-abc".into());
    summary
}

fn write_events(dir: &std::path::Path, lines: &[&str]) {
    std::fs::write(dir.join("events.jsonl"), format!("{}\n", lines.join("\n")))
        .expect("write events.jsonl");
}

const TURN_STARTED: &str = r#"{"ts":"2026-09-29T00:00:01.000Z","type":"turn_started","session_id":"interrupted-turn-test","turn_number":3,"model_id":"m","yolo_mode":false,"conversation_message_count":2,"session_relationship":"root","schema_version":"1.0"}"#;
const TURN_ENDED: &str =
    r#"{"ts":"2026-09-29T00:00:09.000Z","type":"turn_ended","outcome":"completed"}"#;
const TOOL_STARTED: &str =
    r#"{"ts":"2026-09-29T00:00:02.000Z","type":"tool_started","tool_name":"bash"}"#;

/// The crash case: the process died between `turn_started` and `turn_ended`.
/// On the baseline this loss is silent; the detector is what makes it reportable.
#[test]
fn detects_a_turn_the_previous_process_never_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED, TOOL_STARTED]);
    let summary = summary_with_open_turn(dir.path());

    let turn = detect_interrupted_turn(dir.path(), &summary).expect("interrupted turn detected");

    // `next_trace_turn` is the *next* turn, so the lost one is one behind it.
    assert_eq!(turn.trace_turn, Some(3));
    assert_eq!(turn.prompt_id, "req-abc");
    assert_eq!(turn.started_at.as_deref(), Some("2026-09-29T00:00:01.000Z"));
}

/// A turn that ended normally is not reported, so a clean resume paints no interrupted marker.
#[test]
fn a_closed_turn_is_not_interrupted() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED, TOOL_STARTED, TURN_ENDED]);
    let summary = summary_with_open_turn(dir.path());

    assert!(detect_interrupted_turn(dir.path(), &summary).is_none());
}

/// Only the newest turn matters: an earlier closed turn followed by an open one still reports.
#[test]
fn only_the_newest_turn_decides() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(
        dir.path(),
        &[TURN_STARTED, TURN_ENDED, TURN_STARTED, TOOL_STARTED],
    );
    let summary = summary_with_open_turn(dir.path());

    assert!(detect_interrupted_turn(dir.path(), &summary).is_some());
}

/// No `request_id` means no turn to name, so nothing is invented.
#[test]
fn a_summary_without_a_request_id_reports_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED]);
    let mut summary = summary_with_open_turn(dir.path());
    summary.request_id = None;

    assert!(detect_interrupted_turn(dir.path(), &summary).is_none());
}

/// A session that never ran a turn has `next_trace_turn == 0`; the subtraction must not wrap.
#[test]
fn a_session_with_no_turns_reports_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED]);
    let mut summary = summary_with_open_turn(dir.path());
    summary.next_trace_turn = 0;

    assert!(detect_interrupted_turn(dir.path(), &summary).is_none());
}

/// A missing `events.jsonl` (chat-kind or pre-events session) reports nothing rather than panicking.
#[test]
fn a_missing_events_log_reports_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let summary = summary_with_open_turn(dir.path());

    assert!(detect_interrupted_turn(dir.path(), &summary).is_none());
}

/// Garbage lines are skipped, not fatal: a partially written tail must not hide a real open turn.
#[test]
fn unparseable_lines_are_skipped() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &["{not json", TURN_STARTED, "\u{fffd}\u{fffd}"]);
    let summary = summary_with_open_turn(dir.path());

    assert!(detect_interrupted_turn(dir.path(), &summary).is_some());
}

/// The recovered turn is *reported*, not silently dropped: the replay marker and the trace
/// `turn_result.json` both carry the interrupted stop reason and the user-facing text.
#[test]
fn the_recovered_turn_is_reported_on_both_rails() {
    let turn = InterruptedTurn {
        trace_turn: Some(3),
        prompt_id: "req-abc".into(),
        started_at: None,
    };

    let result = turn.turn_result();
    assert!(!result.completed);
    assert_eq!(result.stop_reason.as_deref(), Some(INTERRUPTED_STOP_REASON));
    assert_eq!(result.error.as_deref(), Some(INTERRUPTED_MESSAGE));
    assert_eq!(result.request_id, "req-abc");

    let session_id = agent_client_protocol::SessionId::new("interrupted-turn-test");
    let update = turn.turn_completed_update(&session_id);
    let crate::session::storage::SessionUpdate::Fuigo(notification) = update else {
        panic!("the interrupted marker must ride the Fuigo extension rail");
    };
    assert_eq!(notification.session_id, session_id);
    assert!(
        notification.meta.as_ref().is_some_and(|m| m
            .get("eventId")
            .and_then(serde_json::Value::as_str)
            .is_some()),
        "the marker must be cursor-addressable, so it carries an eventId"
    );
    match notification.update {
        crate::extensions::notification::SessionUpdate::TurnCompleted {
            prompt_id,
            stop_reason,
            agent_result,
            ..
        } => {
            assert_eq!(prompt_id, "req-abc");
            assert_eq!(stop_reason, INTERRUPTED_STOP_REASON);
            assert_eq!(
                agent_result.as_deref(),
                Some(INTERRUPTED_MESSAGE),
                "the interrupted marker must name the loss, not leave the turn blank"
            );
        }
        other => panic!("expected a TurnCompleted terminal, got {other:?}"),
    }
}

/// The events log is closed so the next load does not report the same turn again.
#[test]
fn closing_the_events_turn_makes_the_next_load_quiet() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED]);
    let summary = summary_with_open_turn(dir.path());

    let turn = detect_interrupted_turn(dir.path(), &summary).expect("interrupted turn detected");
    turn.close_events_turn(dir.path())
        .expect("close the events turn");

    assert!(
        detect_interrupted_turn(dir.path(), &summary).is_none(),
        "a second load must not re-report a turn already closed as interrupted"
    );
    let events = std::fs::read_to_string(dir.path().join("events.jsonl")).expect("read events");
    assert!(
        events.contains(r#""outcome":"interrupted""#),
        "the close must label the outcome interrupted, not completed: {events}"
    );
}

// ---- Detection at any size (audit finding 3) ----

/// Mutant discriminated: the pre-fix 256 KiB tail read.
/// A long turn that crashes is still detected: its `turn_started` sits megabytes before the end of the log.
#[test]
fn a_turn_longer_than_any_tail_window_is_still_detected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut lines = vec![TURN_STARTED.to_owned()];
    // Varying line lengths so lines straddle the scan's chunk boundaries at many offsets.
    for i in 0..6000 {
        let pad = "x".repeat(100 + (i * 37) % 400);
        lines.push(format!(
            r#"{{"ts":"2026-09-29T00:00:02.000Z","type":"tool_completed","tool_name":"bash","duration_ms":1,"outcome":"success","tool_call_id":"{pad}"}}"#
        ));
    }
    let text = format!("{}\n", lines.join("\n"));
    assert!(
        text.len() > 1024 * 1024,
        "the fixture must dwarf the old window"
    );
    std::fs::write(dir.path().join("events.jsonl"), text).expect("write events");
    let summary = summary_with_open_turn(dir.path());

    let turn = detect_interrupted_turn(dir.path(), &summary).expect("long open turn detected");
    assert_eq!(turn.started_at.as_deref(), Some("2026-09-29T00:00:01.000Z"));
}

/// A line longer than the scan's per-line cap is skipped, not loaded whole, and does not hide the turn event before it.
#[test]
fn an_oversized_line_is_skipped_without_hiding_the_turn() {
    let dir = tempfile::tempdir().expect("tempdir");
    let huge = format!(
        r#"{{"ts":"2026-09-29T00:00:02.000Z","type":"tool_completed","tool_call_id":"{}"}}"#,
        "y".repeat(super::MAX_SCANNED_LINE_BYTES + 1)
    );
    write_events(dir.path(), &[TURN_STARTED, huge.as_str(), TOOL_STARTED]);
    let summary = summary_with_open_turn(dir.path());

    assert!(detect_interrupted_turn(dir.path(), &summary).is_some());
}

/// The backward scan visits every line exactly once, newest first, across chunk boundaries, with or without a
/// trailing newline.
#[test]
fn the_backward_scan_visits_every_line_newest_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("lines.txt");
    let expected: Vec<String> = (0..3000)
        .map(|i| format!("{i}:{}", "z".repeat((i * 53) % 300)))
        .collect();
    for trailing_newline in [true, false] {
        let mut text = expected.join("\n");
        if trailing_newline {
            text.push('\n');
        }
        std::fs::write(&path, text).expect("write");
        let mut seen = Vec::new();
        super::scan_lines_backwards(&path, |line| {
            seen.push(String::from_utf8(line.to_vec()).expect("utf8"));
            std::ops::ControlFlow::Continue(())
        })
        .expect("scan");
        seen.reverse();
        assert_eq!(seen, expected, "trailing_newline={trailing_newline}");
    }
}

// ---- Recovery: liveness, ordering, idempotency (audit findings 1, 2, 5) ----

use crate::session::persistence::DurableAppendError;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The recorded turn, for tests where the append resolves within the bound (never deferred).
fn recorded(outcome: Option<RecoveryOutcome>) -> Option<RecoveredTurn> {
    match outcome? {
        RecoveryOutcome::Recorded(recovered) => Some(recovered),
        RecoveryOutcome::Deferred(deferred) => panic!("unexpectedly deferred: {deferred:?}"),
    }
}

fn session_id() -> agent_client_protocol::SessionId {
    agent_client_protocol::SessionId::new("interrupted-turn-test")
}

fn read_events(dir: &std::path::Path) -> String {
    std::fs::read_to_string(dir.join("events.jsonl")).expect("read events")
}

fn last_turn_event_type(dir: &std::path::Path) -> Option<String> {
    read_events(dir)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v["type"].as_str().map(str::to_owned))
        .rfind(|t| t == "turn_started" || t == "turn_ended")
}

/// An `updates.jsonl` line holding `turn`'s interrupted marker, as the persistence actor writes it.
fn marker_envelope_line(turn: &InterruptedTurn) -> String {
    let update = turn.turn_completed_update(&session_id());
    serde_json::to_string(
        &crate::session::storage::SessionUpdateEnvelope::from_update(&update).expect("envelope"),
    )
    .expect("serialize envelope")
}

fn terminal_envelope_line(prompt_id: &str, stop_reason: &str) -> String {
    let update = crate::session::storage::SessionUpdate::Fuigo(Box::new(
        crate::extensions::notification::SessionNotification {
            session_id: session_id(),
            update: crate::session::turn_completion::build_turn_completed(
                prompt_id.to_owned(),
                serde_json::json!(stop_reason),
                serde_json::Value::Null,
                None,
                None,
                None,
            ),
            meta: None,
        },
    ));
    serde_json::to_string(
        &crate::session::storage::SessionUpdateEnvelope::from_update(&update).expect("envelope"),
    )
    .expect("serialize envelope")
}

async fn recover_with(
    dir: &std::path::Path,
    result: fn() -> Result<(), DurableAppendError>,
    appends: &Arc<AtomicUsize>,
) -> Option<RecoveredTurn> {
    let summary = summary_with_open_turn(dir);
    let appends = Arc::clone(appends);
    recorded(
        recover_interrupted_turn(
            dir,
            Some(&dir.join("updates.jsonl")),
            &summary,
            &session_id(),
            move |_update| async move {
                appends.fetch_add(1, Ordering::SeqCst);
                result()
            },
        )
        .await,
    )
}

fn not_committed() -> Result<(), DurableAppendError> {
    Err(DurableAppendError::NotCommitted(std::io::Error::other(
        "disk full",
    )))
}
fn ack_lost() -> Result<(), DurableAppendError> {
    Err(DurableAppendError::AcknowledgementLost(
        std::io::Error::other("actor stopped"),
    ))
}
fn committed_with_bookkeeping_failure() -> Result<(), DurableAppendError> {
    Err(DurableAppendError::Committed(std::io::Error::other(
        "fsync of the index failed",
    )))
}
fn landed() -> Result<(), DurableAppendError> {
    Ok(())
}

/// The ordinary crash: the marker is appended once and the events log is closed as interrupted.
#[tokio::test]
async fn recovery_appends_the_marker_then_closes_the_turn() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED, TOOL_STARTED]);
    let appends = Arc::new(AtomicUsize::new(0));

    let recovered = recover_with(dir.path(), landed, &appends)
        .await
        .expect("recorded");

    assert_eq!(appends.load(Ordering::SeqCst), 1);
    assert_eq!(recovered.turn.prompt_id, "req-abc");
    assert!(
        recovered
            .marker_line
            .contains(r#""stop_reason":"interrupted""#)
    );
    assert_eq!(
        last_turn_event_type(dir.path()).as_deref(),
        Some("turn_ended")
    );
    assert!(read_events(dir.path()).contains(r#""outcome":"interrupted""#));
}

/// Mutant discriminated: closing the events turn even when the durable append failed (audit finding 1).
/// A marker that did not commit (or whose commit is unknown) leaves the turn open, so the next load retries it.
#[tokio::test]
async fn an_uncommitted_marker_leaves_the_turn_open_for_the_next_load() {
    for (label, result) in [
        ("not committed", not_committed as fn() -> _),
        ("acknowledgement lost", ack_lost),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        write_events(dir.path(), &[TURN_STARTED, TOOL_STARTED]);
        let appends = Arc::new(AtomicUsize::new(0));

        assert!(
            recover_with(dir.path(), result, &appends).await.is_none(),
            "{label}: nothing is reported as recorded"
        );
        assert_eq!(appends.load(Ordering::SeqCst), 1);
        assert_eq!(
            last_turn_event_type(dir.path()).as_deref(),
            Some("turn_started"),
            "{label}: the turn must stay open so the interruption is not lost"
        );
        assert!(
            detect_interrupted_turn(dir.path(), &summary_with_open_turn(dir.path())).is_some(),
            "{label}: the next load detects it again"
        );
    }
}

/// `Committed` means the marker is on disk despite a bookkeeping error, so the turn is closed.
#[tokio::test]
async fn a_committed_marker_with_a_bookkeeping_error_still_closes_the_turn() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED]);
    let appends = Arc::new(AtomicUsize::new(0));

    assert!(
        recover_with(dir.path(), committed_with_bookkeeping_failure, &appends)
            .await
            .is_some()
    );
    assert_eq!(
        last_turn_event_type(dir.path()).as_deref(),
        Some("turn_ended")
    );
}

/// Mutant discriminated: skipping the turn-owner lock (audit finding 2).
/// A live actor elsewhere holds the session: its open turn is running, so nothing is appended or closed.
#[tokio::test]
async fn a_session_live_in_another_process_is_left_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED, TOOL_STARTED]);
    let before = read_events(dir.path());
    let live_owner = crate::session::turn_owner_lock::TurnOwnerLock::acquire(dir.path())
        .await
        .expect("not busy")
        .expect("owner lock");
    let appends = Arc::new(AtomicUsize::new(0));

    assert!(recover_with(dir.path(), landed, &appends).await.is_none());
    assert_eq!(
        appends.load(Ordering::SeqCst),
        0,
        "no marker for a live turn"
    );
    assert_eq!(
        read_events(dir.path()),
        before,
        "a live turn's log is untouched"
    );

    drop(live_owner);
    assert!(
        recover_with(dir.path(), landed, &appends).await.is_some(),
        "once the owner is gone the same turn is recoverable"
    );
    assert_eq!(
        appends.load(Ordering::SeqCst),
        1,
        "the marker is appended exactly once"
    );
}

/// Mutant discriminated: always appending a fresh marker (audit finding 5, crash between append and close).
/// An earlier recovery committed the marker and died before closing the log: the marker is reused, not duplicated.
#[tokio::test]
async fn a_marker_from_an_earlier_recovery_is_reused_not_duplicated() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED, TOOL_STARTED]);
    let turn =
        detect_interrupted_turn(dir.path(), &summary_with_open_turn(dir.path())).expect("detected");
    let earlier = marker_envelope_line(&turn);
    std::fs::write(
        dir.path().join("updates.jsonl"),
        format!(
            "{}\n{earlier}\n",
            terminal_envelope_line("older-prompt", "end_turn")
        ),
    )
    .expect("write updates");
    let appends = Arc::new(AtomicUsize::new(0));

    let recovered = recover_with(dir.path(), landed, &appends)
        .await
        .expect("still reported");

    assert_eq!(
        appends.load(Ordering::SeqCst),
        0,
        "the committed marker is not appended again"
    );
    assert_eq!(
        recovered.marker_line, earlier,
        "the client is sent the marker already on disk"
    );
    assert_eq!(
        last_turn_event_type(dir.path()).as_deref(),
        Some("turn_ended")
    );
}

/// A newest terminal record for an *older* prompt does not count: this turn gets its own marker.
#[tokio::test]
async fn an_older_turns_terminal_does_not_suppress_the_marker() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED]);
    std::fs::write(
        dir.path().join("updates.jsonl"),
        format!(
            "{}\n",
            terminal_envelope_line("older-prompt", INTERRUPTED_STOP_REASON)
        ),
    )
    .expect("write updates");
    let appends = Arc::new(AtomicUsize::new(0));

    assert!(recover_with(dir.path(), landed, &appends).await.is_some());
    assert_eq!(appends.load(Ordering::SeqCst), 1);
}

/// A turn that reached a terminal record (an ordinary error or cancel) whose events closure was lost is not a crash:
/// it is closed with its own outcome and nothing is reported as interrupted.
#[tokio::test]
async fn a_turn_with_a_terminal_record_is_closed_with_its_outcome_not_called_a_crash() {
    for (stop_reason, outcome) in [
        ("error", "error"),
        ("cancelled", "cancelled"),
        ("end_turn", "completed"),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        write_events(dir.path(), &[TURN_STARTED]);
        std::fs::write(
            dir.path().join("updates.jsonl"),
            format!("{}\n", terminal_envelope_line("req-abc", stop_reason)),
        )
        .expect("write updates");
        let appends = Arc::new(AtomicUsize::new(0));

        assert!(
            recover_with(dir.path(), landed, &appends).await.is_none(),
            "{stop_reason}"
        );
        assert_eq!(appends.load(Ordering::SeqCst), 0, "{stop_reason}");
        let events = read_events(dir.path());
        assert!(
            events.contains(&format!(r#""outcome":"{outcome}""#)),
            "{stop_reason}: {events}"
        );
        assert!(
            !events.contains(r#""outcome":"interrupted""#),
            "{stop_reason}: {events}"
        );
    }
}

/// Mutant discriminated: appending the closure without repairing a torn tail (audit finding 5).
/// The dead process left half a line; the closure must land on its own line so the next load sees it.
#[tokio::test]
async fn a_torn_events_tail_does_not_swallow_the_closure() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("events.jsonl"),
        format!("{TURN_STARTED}\n{{\"ts\":\"2026-09-29T00:00:03.000Z\",\"type\":\"tool_sta"),
    )
    .expect("write torn events");
    let appends = Arc::new(AtomicUsize::new(0));

    assert!(recover_with(dir.path(), landed, &appends).await.is_some());
    assert!(
        detect_interrupted_turn(dir.path(), &summary_with_open_turn(dir.path())).is_none(),
        "the closure must be readable after a torn tail"
    );
    assert!(recover_with(dir.path(), landed, &appends).await.is_none());
    assert_eq!(
        appends.load(Ordering::SeqCst),
        1,
        "a second load records nothing"
    );
}

/// A closure that cannot be written is reported, not swallowed (the pre-fix `EventWriter::emit` returned nothing).
/// The retry itself is `a_marker_from_an_earlier_recovery_is_reused_not_duplicated`: that is the state a failed
/// closure leaves behind.
#[test]
fn a_failed_closure_is_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let turn = InterruptedTurn {
        trace_turn: Some(3),
        prompt_id: "req-abc".into(),
        started_at: None,
    };
    assert!(
        turn.close_events_turn(&dir.path().join("gone")).is_err(),
        "a closure that did not land must be reported"
    );
}

// ---- v3: the turn names itself (N3), storage without updates (N4), bounded hold (N2), scan cost (N7), stop reasons (N8) ----

/// `turn_started` for prompt `A` as the v3 shell writes it.
const TURN_STARTED_A: &str = r#"{"ts":"2026-09-29T00:00:05.000Z","type":"turn_started","session_id":"s","turn_number":3,"model_id":"m","yolo_mode":false,"conversation_message_count":2,"session_relationship":"primary","schema_version":"1.0","prompt_id":"prompt-A"}"#;

/// Mutant discriminated: detection that names the turn by `summary.request_id` (N3).
/// Turn A was running and prompt B was queued behind it when the process died. The summary's `request_id` is
/// set at prompt *receipt*, so it names B; the lost turn is A, and only `turn_started` says so.
#[test]
fn the_lost_turn_is_named_by_its_own_turn_started_not_the_queued_prompt() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED_A, TOOL_STARTED]);
    let mut summary = summary_with_open_turn(dir.path());
    summary.request_id = Some("prompt-B-queued".into());

    let turn = detect_interrupted_turn(dir.path(), &summary).expect("detected");

    assert_eq!(turn.prompt_id, "prompt-A");
    assert_eq!(
        turn.trace_turn, None,
        "the summary's trace counter belongs to B, so A's trace turn is unknown and nothing is uploaded"
    );
}

/// The ordinary case with the v3 line: the summary names the same prompt, so the trace turn is known.
#[test]
fn a_turn_started_naming_the_summary_prompt_keeps_its_trace_turn() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED_A]);
    let mut summary = summary_with_open_turn(dir.path());
    summary.request_id = Some("prompt-A".into());

    let turn = detect_interrupted_turn(dir.path(), &summary).expect("detected");
    assert_eq!(turn.prompt_id, "prompt-A");
    assert_eq!(turn.trace_turn, Some(3));
}

/// The queued-prompt case end to end in recovery: the durable marker names A.
#[tokio::test]
async fn the_recovered_marker_names_the_running_turn_not_the_queued_prompt() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED_A]);
    let mut summary = summary_with_open_turn(dir.path());
    summary.request_id = Some("prompt-B-queued".into());

    let recovered = recorded(
        recover_interrupted_turn(
            dir.path(),
            Some(&dir.path().join("updates.jsonl")),
            &summary,
            &session_id(),
            |_update| async { Ok(()) },
        )
        .await,
    )
    .expect("recorded");
    assert!(recovered.marker_line.contains(r#""prompt_id":"prompt-A""#));
}

/// Mutant discriminated: recovery that proceeds without an updates file (N4).
/// Without `updates.jsonl` an earlier marker cannot be ruled out, so nothing is declared.
#[tokio::test]
async fn storage_without_an_updates_file_declares_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED]);
    let appends = Arc::new(AtomicUsize::new(0));
    let summary = summary_with_open_turn(dir.path());

    let counter = Arc::clone(&appends);
    let recovered = recover_interrupted_turn(
        dir.path(),
        None,
        &summary,
        &session_id(),
        move |_u| async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    )
    .await;

    assert!(recovered.is_none());
    assert_eq!(appends.load(Ordering::SeqCst), 0);
    assert_eq!(
        last_turn_event_type(dir.path()).as_deref(),
        Some("turn_started")
    );
}

/// Mutant discriminated: an unbounded marker append under the exclusive lock (N2).
/// An actor's wait for its shared lock is bounded only because recovery's exclusive hold is: an append that does not
/// complete within the bound is handed back as deferred, the exclusive lock is traded for a shared one (so an actor
/// can take its lock at once and no second recovery can start), and the turn stays open until the append resolves.
#[tokio::test(start_paused = true)]
async fn a_stuck_marker_append_downgrades_the_lock_at_the_bound() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED]);
    let summary = summary_with_open_turn(dir.path());

    let outcome = tokio::time::timeout(
        crate::session::turn_owner_lock::RECOVERY_APPEND_TIMEOUT * 3,
        recover_interrupted_turn(
            dir.path(),
            Some(&dir.path().join("updates.jsonl")),
            &summary,
            &session_id(),
            |_update| std::future::pending::<Result<(), DurableAppendError>>(),
        ),
    )
    .await
    .expect("recovery must give up its exclusive hold at the bound, not hold it forever");

    assert!(matches!(outcome, Some(RecoveryOutcome::Deferred(_))));
    assert_eq!(
        last_turn_event_type(dir.path()).as_deref(),
        Some("turn_started")
    );
    let actor = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        crate::session::turn_owner_lock::TurnOwnerLock::acquire(dir.path()),
    )
    .await
    .expect("an actor takes its shared lock at once")
    .expect("not busy");
    assert!(actor.is_some());
    assert!(matches!(
        crate::session::turn_owner_lock::try_recovery_lock(dir.path()),
        crate::session::turn_owner_lock::RecoveryLock::HeldElsewhere
    ));
    drop(outcome);
    drop(actor);
    assert!(recoverable_now(dir.path()));
}

/// The session is recoverable once every holder is gone: dropping a lock guard unlocks at once (P122), so this
/// is a plain check, not a wait.
fn recoverable_now(dir: &std::path::Path) -> bool {
    matches!(
        crate::session::turn_owner_lock::try_recovery_lock(dir),
        crate::session::turn_owner_lock::RecoveryLock::Acquired(_)
    )
}

/// Lines several chunks long are reassembled exactly (the O(L) piece list, N7).
#[test]
fn the_backward_scan_reassembles_lines_longer_than_a_chunk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("lines.txt");
    let expected: Vec<String> = (0..12)
        .map(|i| {
            format!(
                "{i}:{}",
                char::from(b'a' + i as u8)
                    .to_string()
                    .repeat(50_000 + i * 70_001)
            )
        })
        .collect();
    std::fs::write(&path, format!("{}\n", expected.join("\n"))).expect("write");
    let mut seen = Vec::new();
    super::scan_lines_backwards(&path, |line| {
        seen.push(String::from_utf8(line.to_vec()).expect("utf8"));
        std::ops::ControlFlow::Continue(())
    })
    .expect("scan");
    seen.reverse();
    assert_eq!(seen, expected);
}

/// Known stop reasons map to their outcome; an unknown one closes as `completed` (the turn did end) and is logged.
#[test]
fn stop_reasons_map_to_outcomes() {
    use fuigo_session_events::TurnOutcomeLabel as L;
    for (reason, expected) in [
        ("end_turn", "Completed"),
        ("max_tokens", "Completed"),
        ("max_turn_requests", "Completed"),
        ("refusal", "Completed"),
        ("cancelled", "Cancelled"),
        ("error", "Error"),
        ("rate_limit", "Error"),
        (INTERRUPTED_STOP_REASON, "Interrupted"),
        ("a_reason_from_a_newer_shell", "Completed"),
    ] {
        let got: L = super::outcome_for_stop_reason(reason);
        assert_eq!(format!("{got:?}"), expected, "{reason}");
    }
}

// ---- P09-F (F1): an append that outlives the bound still lands, so the recovery is finished, not abandoned ----

/// Longer than the bound, so recovery defers; the paused clock makes it instant.
const LATE: std::time::Duration = std::time::Duration::from_secs(15);

/// A persistence actor that commits the marker `delay` after it is queued: the line reaches `updates.jsonl`
/// then, whether or not anyone still waits for the acknowledgement.
fn lands_after(
    dir: &std::path::Path,
    delay: std::time::Duration,
    appends: &Arc<AtomicUsize>,
) -> impl FnOnce(
    crate::session::storage::SessionUpdate,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DurableAppendError>>>> {
    let updates = dir.join("updates.jsonl");
    let appends = Arc::clone(appends);
    move |update| {
        appends.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            let line = serde_json::to_string(
                &crate::session::storage::SessionUpdateEnvelope::from_update(&update)
                    .expect("envelope"),
            )
            .expect("serialize envelope");
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&updates)
                .expect("open updates");
            std::io::Write::write_all(&mut file, format!("{line}\n").as_bytes())
                .expect("append marker");
            Ok(())
        })
    }
}

async fn recover_late(dir: &std::path::Path, appends: &Arc<AtomicUsize>) -> DeferredRecovery {
    let summary = summary_with_open_turn(dir);
    match recover_interrupted_turn(
        dir,
        Some(&dir.join("updates.jsonl")),
        &summary,
        &session_id(),
        lands_after(dir, LATE, appends),
    )
    .await
    {
        Some(RecoveryOutcome::Deferred(deferred)) => deferred,
        Some(RecoveryOutcome::Recorded(_)) => panic!("an append past the bound must defer"),
        None => panic!("an append past the bound must not be abandoned"),
    }
}

/// `turn_started` / `turn_ended:<outcome>` in log order.
fn turn_event_sequence(dir: &std::path::Path) -> Vec<String> {
    read_events(dir)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| match v["type"].as_str()? {
            "turn_started" => Some("turn_started".to_owned()),
            "turn_ended" => Some(format!(
                "turn_ended:{}",
                v["outcome"].as_str().unwrap_or("?")
            )),
            _ => None,
        })
        .collect()
}

fn interrupted_markers_on_disk(dir: &std::path::Path) -> usize {
    std::fs::read_to_string(dir.join("updates.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains(r#""stop_reason":"interrupted""#))
        .count()
}

/// Turn C as the actor writes it: the pre-turn hook, then its `turn_started`.
fn start_turn_c(dir: &std::path::Path) {
    close_deferred_turn_before_new_turn(dir);
    append_event_line(dir, TURN_STARTED_C);
}
fn end_turn_c(dir: &std::path::Path) {
    append_event_line(dir, TURN_ENDED_C);
}
fn append_event_line(dir: &std::path::Path, line: &str) {
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(dir.join("events.jsonl"))
        .expect("open events");
    std::io::Write::write_all(&mut file, format!("{line}\n").as_bytes()).expect("append event");
}
const TURN_STARTED_C: &str = r#"{"ts":"2026-09-29T00:10:00.000Z","type":"turn_started","session_id":"interrupted-turn-test","turn_number":4,"model_id":"m","yolo_mode":false,"conversation_message_count":4,"session_relationship":"primary","schema_version":"1.0","prompt_id":"req-c"}"#;
const TURN_ENDED_C: &str =
    r#"{"ts":"2026-09-29T00:10:09.000Z","type":"turn_ended","outcome":"completed"}"#;

/// F1(a). Mutant discriminated: `DeferredRecovery::finish` that does not hand the committed marker back.
/// v3 dropped the append at the bound, so a marker that committed later never reached a live client. The deferred
/// recovery hands it back once it lands, for the load to forward live and to note for the model.
#[tokio::test(start_paused = true)]
async fn a_marker_that_lands_after_the_bound_is_still_reported_live() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED, TOOL_STARTED]);
    let appends = Arc::new(AtomicUsize::new(0));

    let deferred = recover_late(dir.path(), &appends).await;
    assert_eq!(interrupted_markers_on_disk(dir.path()), 0, "not landed yet");

    let recovered = deferred
        .finish()
        .await
        .expect("the late marker is reported once it commits");
    assert_eq!(recovered.turn.prompt_id, "req-abc");
    assert!(
        recovered
            .marker_line
            .contains(r#""stop_reason":"interrupted""#)
    );
    assert_eq!(interrupted_markers_on_disk(dir.path()), 1);
    assert_eq!(appends.load(Ordering::SeqCst), 1);
}

/// F1(b). Mutant discriminated: `finish` that does not close the events turn.
/// In v3 the late marker landed but the turn was never closed, so the next turn C started inside it and C's
/// `turn_ended` hid it. Now the lost turn is closed when its marker lands, before C, and the next load is quiet.
#[tokio::test(start_paused = true)]
async fn a_marker_that_lands_after_the_bound_closes_the_turn_before_the_next_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED, TOOL_STARTED]);
    let appends = Arc::new(AtomicUsize::new(0));

    recover_late(dir.path(), &appends)
        .await
        .finish()
        .await
        .expect("committed");
    start_turn_c(dir.path());
    end_turn_c(dir.path());

    assert_eq!(
        turn_event_sequence(dir.path()),
        [
            "turn_started",
            "turn_ended:interrupted",
            "turn_started",
            "turn_ended:completed"
        ]
    );
    assert!(recover_with(dir.path(), landed, &appends).await.is_none());
    assert_eq!(appends.load(Ordering::SeqCst), 1);
    assert_eq!(interrupted_markers_on_disk(dir.path()), 1);
}

/// F1(b), the other order. Mutant discriminated: the actor's pre-turn hook doing nothing.
/// Turn C starts while the marker is still being written: the lost turn is closed first, so C does not start
/// inside it, and the late commit does not close anything a second time.
#[tokio::test(start_paused = true)]
async fn a_turn_that_starts_before_the_late_marker_lands_does_not_start_inside_the_lost_turn() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED, TOOL_STARTED]);
    let appends = Arc::new(AtomicUsize::new(0));

    let deferred = recover_late(dir.path(), &appends).await;
    start_turn_c(dir.path());
    deferred.finish().await.expect("committed");
    end_turn_c(dir.path());

    assert_eq!(
        turn_event_sequence(dir.path()),
        [
            "turn_started",
            "turn_ended:interrupted",
            "turn_started",
            "turn_ended:completed"
        ]
    );
    assert_eq!(interrupted_markers_on_disk(dir.path()), 1);
}

/// F1(b), across processes. Mutant discriminated: `finish` closing without checking the newest turn event.
/// Another process sharing the session (its actor holds a shared lock too) starts a turn before the marker lands:
/// that turn is not this process's to close, so the late commit leaves the log alone.
#[tokio::test(start_paused = true)]
async fn a_late_marker_never_closes_a_turn_another_process_started() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED, TOOL_STARTED]);
    let appends = Arc::new(AtomicUsize::new(0));

    let deferred = recover_late(dir.path(), &appends).await;
    append_event_line(dir.path(), TURN_STARTED_C);
    deferred.finish().await.expect("committed");

    assert_eq!(
        turn_event_sequence(dir.path()),
        ["turn_started", "turn_started"],
        "the other process's running turn must not be closed"
    );
}

/// F1(c). Mutant discriminated: the deferred recovery not keeping a shared lock.
/// The session is unloaded and loaded again before the late marker lands. v3 had released every lock, so the
/// reload recovered the same turn and appended a second marker. The pending recovery keeps a shared lock, so the
/// reload stands down; once the marker lands the turn is closed and later loads are quiet.
#[tokio::test(start_paused = true)]
async fn a_reload_before_the_late_marker_lands_does_not_append_a_second_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED, TOOL_STARTED]);
    let appends = Arc::new(AtomicUsize::new(0));

    let deferred = recover_late(dir.path(), &appends).await;
    let reload_appends = Arc::new(AtomicUsize::new(0));
    assert!(
        recover_with(dir.path(), landed, &reload_appends)
            .await
            .is_none()
    );
    assert_eq!(
        reload_appends.load(Ordering::SeqCst),
        0,
        "the reload must not append a second marker"
    );

    deferred.finish().await.expect("committed");
    assert!(
        recover_with(dir.path(), landed, &reload_appends)
            .await
            .is_none()
    );
    assert_eq!(reload_appends.load(Ordering::SeqCst), 0);
    assert_eq!(interrupted_markers_on_disk(dir.path()), 1);
    assert_eq!(
        last_turn_event_type(dir.path()).as_deref(),
        Some("turn_ended")
    );
}

/// A deferred recovery dropped unfinished (its load failed) releases the session and leaves the turn open; the
/// next load reuses the marker if it landed. An actor starting a turn then has nothing to close.
#[tokio::test(start_paused = true)]
async fn a_deferred_recovery_dropped_unfinished_leaves_the_turn_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED, TOOL_STARTED]);
    let appends = Arc::new(AtomicUsize::new(0));

    drop(recover_late(dir.path(), &appends).await);
    let before = read_events(dir.path());
    close_deferred_turn_before_new_turn(dir.path());
    assert_eq!(read_events(dir.path()), before);
    assert!(recoverable_now(dir.path()));
}

/// Mutant discriminated: a late marker is forwarded live even though the load's replay already carried it (P09-F2 A2).
/// The load forwards a late marker only when it lies beyond the offset its replay read through.
#[test]
fn a_marker_the_replay_already_read_is_not_forwarded_again() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("updates.jsonl");
    let earlier = r#"{"method":"session/update","params":{"n":1}}"#;
    let marker = r#"{"method":"session/update","params":{"marker":"interrupted"}}"#;
    let later = r#"{"method":"session/update","params":{"n":2}}"#;
    std::fs::write(&path, format!("{earlier}\n{marker}\n{later}\n")).expect("write");
    let through_marker = (earlier.len() + 1 + marker.len() + 1) as u64;
    let through_earlier = (earlier.len() + 1) as u64;

    // The replay read past the marker: it carried it, so no live forward.
    assert!(marker_within_replayed_range(&path, marker, through_marker));
    assert!(marker_within_replayed_range(&path, marker, u64::MAX));
    // The marker landed after the replay's last read: it must be forwarded live.
    assert!(!marker_within_replayed_range(&path, marker, through_earlier));
    // A read that stops mid-marker did not carry it.
    assert!(!marker_within_replayed_range(&path, marker, through_marker - 5));
    // No updates file, or an empty marker: forward.
    assert!(!marker_within_replayed_range(&dir.path().join("none.jsonl"), marker, u64::MAX));
    assert!(!marker_within_replayed_range(&path, "", u64::MAX));
}

/// The search is bounded to a tail window: a marker far older than the replay's end is not found (a duplicate live
/// forward is the safe outcome), and the scan does not read the whole transcript.
#[test]
fn the_replayed_marker_search_is_bounded_to_a_tail_window() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("updates.jsonl");
    let marker = r#"{"method":"session/update","params":{"marker":"interrupted"}}"#;
    let filler = "x".repeat(1023) + "\n";
    let mut body = format!("{marker}\n");
    body.push_str(&filler.repeat(2048));
    std::fs::write(&path, &body).expect("write");
    assert!(!marker_within_replayed_range(&path, marker, body.len() as u64));
}

/// Mutant discriminated: searching for the bare marker string instead of its stored form (Astra, P09-F2 audit 2).
/// `updates.jsonl` stores the update inside `SessionUpdateEnvelope`, with a `"timestamp"` the recovery's own
/// `marker_line` does not have, so the lookup must match the production serialization, not a synthetic one.
#[test]
fn the_replayed_marker_is_found_in_the_stored_envelope_form() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED]);
    let summary = summary_with_open_turn(dir.path());
    let turn = detect_interrupted_turn(dir.path(), &summary).expect("interrupted turn");
    let update = turn.turn_completed_update(&session_id());
    let marker_line = serde_json::to_string(&update).expect("marker line");
    let stored = serde_json::to_string(
        &crate::session::storage::SessionUpdateEnvelope::from_update(&update).expect("envelope"),
    )
    .expect("stored line");
    assert!(stored.contains("\"timestamp\""), "{stored}");
    let path = dir.path().join("updates.jsonl");
    std::fs::write(&path, format!("{stored}\n")).expect("write");
    let len = std::fs::metadata(&path).expect("meta").len();
    assert!(marker_within_replayed_range(&path, &marker_line, len));
    assert!(!marker_within_replayed_range(&path, &marker_line, len - 3));
}

// ---- P09-F2: a late marker reaches every client exactly once (two clients, a deferred recovery) ----

/// Client A is loading the session; client B is already attached to it. The marker's live forward is what B gets
/// (and A too, when A's replay missed it); the load's replay is what A may already have. B's delivery is modelled by
/// a counted `forward` closure: these tests drive the real deferred recovery and the real replay-range decision, not
/// an ACP connection (the agent-level `finish_deferred_recovery` call site is not exercised; see R038).
/// A persistence actor that commits the marker the moment it is queued (so a replay that starts later reads it) but
/// acknowledges it only after `ack_delay`, which is what pushes recovery past its bound.
fn lands_at_once_acks_late(
    dir: &std::path::Path,
    ack_delay: std::time::Duration,
) -> impl FnOnce(
    crate::session::storage::SessionUpdate,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DurableAppendError>>>> {
    let updates = dir.join("updates.jsonl");
    move |update| {
        let line = serde_json::to_string(
            &crate::session::storage::SessionUpdateEnvelope::from_update(&update)
                .expect("envelope"),
        )
        .expect("serialize envelope");
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&updates)
            .expect("open updates");
        std::io::Write::write_all(&mut file, format!("{line}\n").as_bytes())
            .expect("append marker");
        Box::pin(async move {
            tokio::time::sleep(ack_delay).await;
            Ok(())
        })
    }
}

async fn deferred_from(
    dir: &std::path::Path,
    append: impl FnOnce(
        crate::session::storage::SessionUpdate,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DurableAppendError>>>>,
) -> DeferredRecovery {
    let summary = summary_with_open_turn(dir);
    match recover_interrupted_turn(
        dir,
        Some(&dir.join("updates.jsonl")),
        &summary,
        &session_id(),
        append,
    )
    .await
    {
        Some(RecoveryOutcome::Deferred(deferred)) => deferred,
        _ => panic!("an append past the bound must defer"),
    }
}

/// The live delivery to the other attached client, counted.
fn live_delivery(count: &Arc<AtomicUsize>) -> impl FnOnce() -> std::future::Ready<()> {
    let count = Arc::clone(count);
    move || {
        count.fetch_add(1, Ordering::SeqCst);
        std::future::ready(())
    }
}

fn updates_len(dir: &std::path::Path) -> u64 {
    std::fs::metadata(dir.join("updates.jsonl"))
        .map_or(0, |meta| meta.len())
}

fn seed_updates(dir: &std::path::Path) {
    std::fs::write(
        dir.join("updates.jsonl"),
        "{\"timestamp\":1,\"method\":\"session/update\",\"params\":{\"n\":1}}\n",
    )
    .expect("seed updates");
}

/// Mutant discriminated: `forward_late_marker_unless_replayed` forwarding regardless (P09-F2 A2, the skip).
/// The marker landed before the load's untargeted replay finished reading, so the replay carried it to both
/// clients; the late acknowledgement must not show it to B a second time.
#[tokio::test(start_paused = true)]
async fn an_untargeted_replay_that_carried_the_marker_is_not_forwarded_again() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED, TOOL_STARTED]);
    seed_updates(dir.path());
    let deferred = deferred_from(dir.path(), lands_at_once_acks_late(dir.path(), LATE)).await;
    let replay_read_through = updates_len(dir.path());

    let recovered = deferred.finish().await.expect("committed");
    let live = Arc::new(AtomicUsize::new(0));
    let forwarded = forward_late_marker_unless_replayed(
        BroadcastReplay::new(
            Some(dir.path().join("updates.jsonl")),
            Some(replay_read_through),
            None,
        ),
        &recovered.marker_line,
        live_delivery(&live),
    )
    .await;

    assert!(!forwarded);
    assert_eq!(live.load(Ordering::SeqCst), 0, "no duplicate for either client");
}

/// The marker lands after the replay's last read, so only the live forward can tell the clients; an earlier,
/// unrelated line inside the replayed range must not suppress it.
#[tokio::test(start_paused = true)]
async fn a_marker_that_lands_after_the_replay_read_is_forwarded_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED, TOOL_STARTED]);
    seed_updates(dir.path());
    let appends = Arc::new(AtomicUsize::new(0));
    let deferred = recover_late(dir.path(), &appends).await;
    let replay_read_through = updates_len(dir.path());

    let recovered = deferred.finish().await.expect("committed");
    assert!(updates_len(dir.path()) > replay_read_through, "it landed after the read");
    let live = Arc::new(AtomicUsize::new(0));
    let forwarded = forward_late_marker_unless_replayed(
        BroadcastReplay::new(
            Some(dir.path().join("updates.jsonl")),
            Some(replay_read_through),
            None,
        ),
        &recovered.marker_line,
        live_delivery(&live),
    )
    .await;

    assert!(forwarded);
    assert_eq!(live.load(Ordering::SeqCst), 1);
}

/// Mutant discriminated: dropping the `targeted` guard in `BroadcastReplay::new` (the round-1 HIGH).
/// Client A's load replays the marker, but to A alone (leader-targeted). Client B, attached, did not see it, so
/// the live forward must still happen.
#[tokio::test(start_paused = true)]
async fn a_targeted_replay_does_not_suppress_the_other_clients_live_delivery() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED, TOOL_STARTED]);
    seed_updates(dir.path());
    let deferred = deferred_from(dir.path(), lands_at_once_acks_late(dir.path(), LATE)).await;
    let replay_read_through = updates_len(dir.path());

    let recovered = deferred.finish().await.expect("committed");
    let replay = BroadcastReplay::new(
        Some(dir.path().join("updates.jsonl")),
        Some(replay_read_through),
        Some(&serde_json::json!("client-a")),
    );
    assert!(replay.is_none(), "a replay aimed at one client carried nothing to the others");
    let live = Arc::new(AtomicUsize::new(0));
    let forwarded =
        forward_late_marker_unless_replayed(replay, &recovered.marker_line, live_delivery(&live))
            .await;

    assert!(forwarded);
    assert_eq!(live.load(Ordering::SeqCst), 1, "B still hears of the lost turn");
}

/// A load that replays nothing (`session/resume`, or a no-replay load) carried nothing: the live forward runs.
#[tokio::test(start_paused = true)]
async fn a_load_with_no_replay_still_forwards_the_late_marker() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED, TOOL_STARTED]);
    let deferred = deferred_from(dir.path(), lands_at_once_acks_late(dir.path(), LATE)).await;
    let recovered = deferred.finish().await.expect("committed");
    let live = Arc::new(AtomicUsize::new(0));
    let forwarded = forward_late_marker_unless_replayed(
        BroadcastReplay::new(Some(dir.path().join("updates.jsonl")), None, None),
        &recovered.marker_line,
        live_delivery(&live),
    )
    .await;
    assert!(forwarded);
    assert_eq!(live.load(Ordering::SeqCst), 1);
}

// ---- P09-F2 A5: the deferred-finish failure message does not say the turn stays open when a hook closed it ----

#[derive(Clone, Default)]
struct LogBuf(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogBuf {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("log buffer")).into_owned()
    }
}

/// Captures this thread's `warn`+ events until the guard drops (the tests run on one thread).
fn capture_warnings() -> (LogBuf, tracing::subscriber::DefaultGuard) {
    let buffer = LogBuf::default();
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .finish();
    (buffer, tracing::subscriber::set_default(subscriber))
}

/// An append that outlives the bound and then fails to commit.
fn fails_late(
    delay: std::time::Duration,
) -> impl FnOnce(
    crate::session::storage::SessionUpdate,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DurableAppendError>>>> {
    move |_update| {
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            Err(DurableAppendError::NotCommitted(std::io::Error::other(
                "disk full",
            )))
        })
    }
}

/// Mutant discriminated: the hook branch reusing the "stays open" wording (A5). An actor's pre-turn hook took the
/// closure and closed the lost turn before its own turn started; saying the turn stays open would be false.
#[tokio::test(start_paused = true)]
async fn a_failed_late_marker_after_the_hook_closed_the_turn_does_not_claim_it_stays_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED, TOOL_STARTED]);
    let (logs, _guard) = capture_warnings();
    let deferred = deferred_from(dir.path(), fails_late(LATE)).await;

    close_deferred_turn_before_new_turn(dir.path());
    assert!(deferred.finish().await.is_none());

    let text = logs.text();
    assert!(text.contains("late interrupted-turn marker not committed"), "{text}");
    assert!(text.contains("pre-turn hook already took the closure"), "{text}");
    assert!(!text.contains("stays open"), "{text}");
}

/// The other branch: nothing closed the turn, so it genuinely stays open for the next load.
#[tokio::test(start_paused = true)]
async fn a_failed_late_marker_with_no_hook_says_the_turn_stays_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_events(dir.path(), &[TURN_STARTED, TOOL_STARTED]);
    let (logs, _guard) = capture_warnings();
    let deferred = deferred_from(dir.path(), fails_late(LATE)).await;

    assert!(deferred.finish().await.is_none());

    let text = logs.text();
    assert!(text.contains("the turn stays open for the next load"), "{text}");
    assert!(!text.contains("pre-turn hook"), "{text}");
}
