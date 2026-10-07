//! P188, Grok 4.7 review of the Astra r3 fixes (`099308277`): pin both lines so a revert goes red.
//!
//! - A queued `retrying` gets its `_fuigo` `eventId` when the session loop delivers it, not when it is queued. A
//!   direct `_fuigo` notification sent while the loop is blocked would otherwise carry a higher id than the retry
//!   still in the queue, and a client's per-rail high-water (`last_applied_fuigo_event_seq`) would drop the retry.
//! - Only `retrying` is queued. Terminal states (`failed`/`exhausted`) are delivered on the caller, so their
//!   `agent_error` notification hook never runs inside `SessionEvent::OrderedFuigo` on the session loop.
//! - The goal summary claims its `streamStartMs` through `claim_stream_start`, like a sampler attempt.
//!
//! "Blocked" here means nobody drains the session's event queue until the test hands an event to the loop itself.

use super::support::*;
use super::transient_retry_loop_tests::on_session_stack;
use super::*;
use crate::extensions::notification::{RetryState, SessionNotification, SessionUpdate};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;

fn run_local<F: std::future::Future>(fut: impl FnOnce() -> F) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    let local = tokio::task::LocalSet::new();
    rt.block_on(local.run_until(async move {
        fut().await;
    }));
}

/// A session actor whose loop is not running: its event queue and its client wire are in the test's hands.
struct BlockedLoop {
    actor: Arc<SessionActor>,
    events: UnboundedReceiver<SessionEvent>,
    wire: UnboundedReceiver<fuigo_acp_lib::AcpClientMessage>,
}

async fn blocked_loop() -> BlockedLoop {
    let (gateway_tx, wire) = tokio::sync::mpsc::unbounded_channel();
    let (persistence_tx, persistence_rx) = tokio::sync::mpsc::unbounded_channel();
    super::support::drain_persistence(persistence_rx);
    let (mut actor, events) = create_test_actor_ex(0, 256_000, 85, gateway_tx, persistence_tx).await;
    // Command hooks run with the workspace root as their working directory
    actor.hook_resolved_workspace_root = std::env::temp_dir().to_string_lossy().into_owned();
    BlockedLoop {
        actor: Arc::new(actor),
        events,
        wire,
    }
}

/// The `_fuigo` rail as the client received it so far: (kind, `eventId` counter).
fn fuigo_rail(wire: &mut UnboundedReceiver<fuigo_acp_lib::AcpClientMessage>) -> Vec<(&'static str, u64)> {
    let mut rail = Vec::new();
    while let Ok(msg) = wire.try_recv() {
        let fuigo_acp_lib::AcpClientMessage::ExtNotification(args) = msg else {
            continue;
        };
        if args.request.method.as_ref() != "fuigo/session_notification" {
            continue;
        }
        let notification: SessionNotification =
            serde_json::from_str(args.request.params.get()).expect("_fuigo notification json");
        let kind = match &notification.update {
            SessionUpdate::RetryState(RetryState::Retrying { .. }) => "retrying",
            SessionUpdate::RetryState(RetryState::Failed { .. }) => "failed",
            SessionUpdate::RetryState(RetryState::Exhausted { .. }) => "exhausted",
            SessionUpdate::HooksChanged { .. } => "hooks_changed",
            _ => "other",
        };
        // `{session_id}-{counter}`; clients compare the counter (fuigo-pager `last_applied_fuigo_event_seq`)
        let seq = notification
            .meta
            .as_ref()
            .and_then(|m| m.get("eventId"))
            .and_then(|v| v.as_str())
            .and_then(|id| id.rsplit('-').next())
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or_else(|| panic!("a `_fuigo` notification carries a numeric eventId: {:?}", notification.meta));
        rail.push((kind, seq));
    }
    rail
}

/// What a client applies from the rail: it drops any non-replay `_fuigo` update whose seq is at or below the highest
/// it already applied.
fn applied_by_client(rail: &[(&'static str, u64)]) -> Vec<&'static str> {
    let mut high_water: Option<u64> = None;
    let mut applied = Vec::new();
    for (kind, seq) in rail {
        if high_water.is_some_and(|last| *seq <= last) {
            continue;
        }
        high_water = Some(*seq);
        applied.push(*kind);
    }
    applied
}

fn retrying() -> RetryState {
    RetryState::Retrying {
        attempt: 1,
        max_retries: 3,
        reason: "stream closed before response.completed".into(),
        error_type: None,
        verdicts: None,
        discard_emitted: false,
        message_id: None,
        stream_start_ms: None,
    }
}

/// r3 line 2 (`deliver_fuigo_notification` mints the `eventId`): reverting it to minting at queue time hands the
/// queued retry a lower id than the `HooksChanged` sent directly behind it, and the client drops the retry.
#[test]
fn p188_queued_retry_outranks_a_direct_fuigo_notification_sent_while_the_loop_is_blocked() {
    on_session_stack(|| {
        run_local(|| async {
            let mut blocked = blocked_loop().await;

            blocked
                .actor
                .send_fuigo_notification(SessionUpdate::RetryState(retrying()))
                .await;
            let queued = blocked
                .events
                .try_recv()
                .expect("a `retrying` waits in the session's event queue");
            assert!(
                matches!(&queued, SessionEvent::OrderedFuigo(_)),
                "a `retrying` is queued as an ordered `_fuigo` update"
            );
            assert!(
                fuigo_rail(&mut blocked.wire).is_empty(),
                "nothing reaches the client while the loop is blocked"
            );

            // A direct `_fuigo` notification from another path while the loop is still blocked
            blocked
                .actor
                .send_fuigo_notification(SessionUpdate::HooksChanged {
                    hooks: Vec::new(),
                    project_trusted: false,
                    load_errors: Vec::new(),
                })
                .await;

            // The loop unblocks and delivers the retry
            let mut replay_buffer = crate::agent::update_chunk_merge::ReplayBuffer::new(
                blocked.actor.buffering_settings.clone(),
            );
            blocked
                .actor
                .handle_session_event(queued, &mut replay_buffer)
                .await;

            let rail = fuigo_rail(&mut blocked.wire);
            let kinds: Vec<_> = rail.iter().map(|(kind, _)| *kind).collect();
            assert_eq!(kinds, ["hooks_changed", "retrying"], "{rail:?}");
            assert!(
                rail[1].1 > rail[0].1,
                "the retry's eventId is minted at delivery, above the direct notification's: {rail:?}"
            );
            assert_eq!(
                applied_by_client(&rail),
                ["hooks_changed", "retrying"],
                "a client's high-water still applies the retry: {rail:?}"
            );
        })
    });
}

/// r3 line 1 (only `retrying` is queued): widening the queue back to every `RetryState` parks a `failed` behind the
/// blocked loop, so neither the client nor its `agent_error` hook sees it until the loop runs, and the hook is then
/// awaited inside `SessionEvent::OrderedFuigo`.
#[test]
#[serial_test::serial(disabled_hooks_file)]
fn p188_failed_retry_state_and_its_agent_error_hook_run_on_the_caller() {
    on_session_stack(|| {
        run_local(|| async {
            let dir = tempfile::tempdir().expect("tempdir");
            let hook_out = dir.path().join("agent_error.json");
            let command = format!("cat > '{}'", hook_out.display());
            let registry =
                fuigo_hooks::discovery::registry_from_specs_deduped(vec![fuigo_hooks::config::HookSpec {
                    name: "p188-agent-error-probe".to_string(),
                    event: fuigo_hooks::event::HookEventName::Notification,
                    handler_type: fuigo_hooks::config::HandlerType::Command,
                    configured_matcher: None,
                    matcher: None,
                    enabled: true,
                    command: Some(std::path::PathBuf::from(&command)),
                    command_raw: Some(command.clone()),
                    url: None,
                    url_raw: None,
                    timeout_ms: 30_000,
                    source_dir: dir.path().to_path_buf(),
                    extra_env: std::collections::HashMap::new(),
                    layer: fuigo_hooks::config::HookProvenance::Requirements,
                }]);
            let mut blocked = blocked_loop().await;
            *blocked.actor.hook_registry.borrow_mut() = Some(Arc::new(registry));

            blocked
                .actor
                .send_fuigo_notification(SessionUpdate::RetryState(RetryState::Failed {
                    error_type: "auth".into(),
                    message: "p188 terminal failure".into(),
                    verdicts: None,
                }))
                .await;

            // The loop never ran: everything below happened on the caller
            let rail = fuigo_rail(&mut blocked.wire);
            assert_eq!(
                rail.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
                ["failed"],
                "a terminal state reaches the client without the session loop: {rail:?}"
            );
            let mut queued_ordered = 0;
            while let Ok(event) = blocked.events.try_recv() {
                if matches!(event, SessionEvent::OrderedFuigo(_)) {
                    queued_ordered += 1;
                }
            }
            assert_eq!(queued_ordered, 0, "a terminal state is never queued as an ordered `_fuigo` update");
            let payload = std::fs::read_to_string(&hook_out)
                .expect("the agent_error notification hook ran on the caller, before the send returned");
            assert!(payload.contains("agent_error"), "{payload}");
            assert!(payload.contains("p188 terminal failure"), "{payload}");
        })
    });
}

/// Grok LOW: the goal summary's stream block claims its id like a sampler attempt, so it never shares one with the
/// attempt before or after it.
#[test]
fn p188_goal_summary_stream_start_is_claimed_not_raw_wall_clock() {
    on_session_stack(|| {
        run_local(|| async {
            let blocked = blocked_loop().await;
            let actor = &blocked.actor;
            // An attempt whose claimed id is ahead of the wall clock (a nudge or a clock step back)
            let ahead = chrono::Utc::now().timestamp_millis() + 60_000;
            assert_eq!(actor.unaccepted_output.claim_stream_start(ahead), ahead);

            let summary = actor.claim_out_of_band_stream_start();
            assert_eq!(summary, ahead + 1, "the summary's id is past the attempt's, never the raw clock");
            let meta = actor
                .chat_state_handle
                .get_notification_meta()
                .await
                .expect("notification meta");
            assert_eq!(meta.stream_start_ms, Some(summary), "the summary's chunks carry the claimed id");
            assert_eq!(
                actor.unaccepted_output.claim_stream_start(ahead + 1),
                ahead + 2,
                "the next attempt in the same millisecond still gets its own id"
            );
        })
    });

    // The summary path itself must use the claim, never a raw `record_stream_start(Utc::now())`
    let source = include_str!("../../acp_session_impl/goal_support.rs");
    let summarizer = source
        .split("async fn maybe_run_goal_summarizer")
        .nth(1)
        .and_then(|rest| rest.split("\n    }\n").next())
        .expect("maybe_run_goal_summarizer body");
    assert!(
        summarizer.contains("self.claim_out_of_band_stream_start();"),
        "the goal summary claims its stream start"
    );
    assert!(
        !summarizer.contains("record_stream_start("),
        "the goal summary never records an unclaimed stream start"
    );
}
