//! Retry progress on the standard ACP rail.
//! Every `RetryState` the shell sends on `_fuigo/session_notification` is mirrored as a live-only `session/update` `agent_thought_chunk` that stock ACP clients render.
//! A thought, never an `agent_message_chunk`: clients fold message chunks into the persisted answer.
//! The reasoning-only empty-response storm is capped at one resend.

use super::rate_limit_backoff_tests::{
    SessionKind, actor_under_test_for_session, actor_under_test_with_event_pump,
    actor_under_test_with_gateway, conversation_request, drain_persistence, pump_local_tasks,
    rate_limited_reply, sampler_surfaces_429,
};
use super::support::*;
use super::transient_retry_loop_tests::{on_session_stack, run_paused};
use super::*;
use crate::extensions::notification::RetryState;
use agent_client_protocol as acp;
use fuigo_test_support::{MockInferenceServer, MockModelEntry, ScriptedResponse, sse};
use std::sync::Arc;
use std::time::Duration;

/// Chunk `_meta` key the mirror carries; the pager and headless mode skip chunks tagged with it.
const RETRY_STATUS_KEY: &str = "fuigo/retryStatus";
const AGENT_MESSAGE: &str = "agent_message_chunk";
const AGENT_THOUGHT: &str = "agent_thought_chunk";

#[derive(Debug, Clone, PartialEq)]
enum Frame {
    /// `_fuigo/session_notification` `retry_state`.
    Fuigo(RetryState),
    /// Standard `session/update` text chunk (`agent_message_chunk` or `agent_thought_chunk`), with its `fuigo/retryStatus` chunk meta when tagged.
    Standard {
        kind: String,
        text: String,
        retry_status: Option<serde_json::Value>,
    },
}

type Frames = Arc<std::sync::Mutex<Vec<Frame>>>;

fn drain_frames(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<fuigo_acp_lib::AcpClientMessage>,
) -> Frames {
    use crate::extensions::notification::{SessionNotification, SessionUpdate};
    let captured: Frames = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = captured.clone();
    tokio::task::spawn_local(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                fuigo_acp_lib::AcpClientMessage::SessionNotification(args) => {
                    let chunk = match &args.request.update {
                        acp::SessionUpdate::AgentMessageChunk(chunk) => {
                            Some((AGENT_MESSAGE, chunk))
                        }
                        acp::SessionUpdate::AgentThoughtChunk(chunk) => {
                            Some((AGENT_THOUGHT, chunk))
                        }
                        _ => None,
                    };
                    if let Some((kind, chunk)) = chunk
                        && let acp::ContentBlock::Text(text) = &chunk.content
                    {
                        sink.lock().unwrap().push(Frame::Standard {
                            kind: kind.to_string(),
                            text: text.text.clone(),
                            retry_status: chunk
                                .meta
                                .as_ref()
                                .and_then(|m| m.get(RETRY_STATUS_KEY))
                                .cloned(),
                        });
                    }
                    let _ = args.response_tx.send(Ok(()));
                }
                fuigo_acp_lib::AcpClientMessage::ExtNotification(args)
                    if args.request.method.as_ref() == "fuigo/session_notification" =>
                {
                    if let Ok(SessionNotification {
                        update: SessionUpdate::RetryState(rs),
                        ..
                    }) = serde_json::from_str::<SessionNotification>(args.request.params.get())
                    {
                        sink.lock().unwrap().push(Frame::Fuigo(rs));
                    }
                }
                _ => {}
            }
        }
    });
    captured
}

/// The standard-rail mirror of `state`: a tagged thought chunk.
fn mirror(text: &str, state: &RetryState) -> Frame {
    Frame::Standard {
        kind: AGENT_THOUGHT.to_string(),
        text: text.to_string(),
        retry_status: Some(serde_json::to_value(state).expect("RetryState serializes")),
    }
}

fn is_retry_frame(frame: &Frame) -> bool {
    matches!(
        frame,
        Frame::Fuigo(_)
            | Frame::Standard {
                retry_status: Some(_),
                ..
            }
    )
}

async fn drive_turn(
    actor: Arc<SessionActor>,
    frames: Frames,
    server: &MockInferenceServer,
    req_id: &str,
) -> (
    Result<TurnOutcome, agent_client_protocol::Error>,
    Vec<Frame>,
    Duration,
    u32,
) {
    let requests_before = server.request_count();
    let started = tokio::time::Instant::now();
    let outcome = tokio::time::timeout(
        Duration::from_secs(900),
        actor.process_conversation_turn_with_recovery(
            req_id,
            None,
            None,
            None,
            &mut length_salvage::LengthSalvage::new(None),
        ),
    )
    .await
    .expect("turn must finish within timeout");
    pump_local_tasks().await;
    let elapsed = started.elapsed();
    let submissions = server.request_count() - requests_before;
    let frames = frames.lock().unwrap().clone();
    (outcome, frames, elapsed, submissions)
}

async fn run_turn(
    server: &MockInferenceServer,
    retry_policy: fuigo_sampler::RetryPolicy,
) -> (
    Result<TurnOutcome, agent_client_protocol::Error>,
    Vec<Frame>,
    Duration,
    u32,
) {
    let (actor, frames) =
        actor_under_test_with_gateway(server, SessionKind::Main, retry_policy, true, drain_frames)
            .await;
    drive_turn(actor, frames, server, "req-empty-response-status-test").await
}

#[test]
fn reasoning_only_storm_is_capped_and_mirrored_on_session_update() {
    on_session_stack(|| {
        run_paused(|| async {
            let server = MockInferenceServer::start_with_models(vec![MockModelEntry::new("test")])
                .await
                .expect("mock inference server");
            for _ in 0..20 {
                server.enqueue_response(
                    "/v1/responses",
                    ScriptedResponse::sse(sse::responses_api_reasoning_only_events(
                        "Let me think about this carefully",
                        "test",
                    )),
                );
            }
            let policy = fuigo_sampler::RetryPolicy {
                max_retries: fuigo_sampler::DEFAULT_MAX_RETRIES,
                ..Default::default()
            };

            let (outcome, frames, elapsed, submissions) = run_turn(&server, policy).await;

            let reason = "empty response from model (reasoning_only)";
            let retrying = |attempt| RetryState::Retrying {
                attempt,
                max_retries: 3,
                reason: reason.to_string(),
                error_type: Some("empty_response".to_string()),
            };
            // Spending the cap is an exhaustion, like the rate-limit path: the user watched
            // "(1/3)" and "(2/3)" climb, so the closing line names the attempts it took.
            let exhausted = RetryState::Exhausted {
                attempts: 3,
                reason: reason.to_string(),
                is_rate_limited: false,
                error_type: Some("empty_response".to_string()),
            };
            assert_eq!(
                frames,
                vec![
                    Frame::Fuigo(retrying(1)),
                    mirror(
                        "\n\nRetrying the model (1/3): empty response from model (reasoning_only)\n\n",
                        &retrying(1),
                    ),
                    Frame::Fuigo(retrying(2)),
                    mirror(
                        "\n\nRetrying the model (2/3): empty response from model (reasoning_only)\n\n",
                        &retrying(2),
                    ),
                    Frame::Fuigo(exhausted.clone()),
                    mirror(
                        "\n\nThe model request failed after 3 attempts: empty response from model (reasoning_only)\n\n",
                        &exhausted,
                    ),
                ],
                "both resends on both rails, then one exhaustion on both rails, each mirror an agent_thought_chunk \
                 opening its own paragraph after the model's streamed reasoning \
                 ({submissions} provider submissions, {elapsed:?} virtual)"
            );
            assert!(outcome.is_err(), "the turn fails once the cap is spent");
            assert_eq!(submissions, 3, "the original request plus two resends");
            assert!(
                elapsed < Duration::from_secs(10),
                "fails in seconds, not minutes: {elapsed:?}"
            );
        })
    });
}

/// The shell's own transient-retry rail (turn loop, not the sampler) is mirrored too: once per retry, and no failure once the turn recovers.
#[test]
fn shell_transient_retries_are_mirrored_once_each() {
    on_session_stack(|| {
        run_paused(|| async {
            let server = MockInferenceServer::start_with_models(vec![MockModelEntry::new("test")])
                .await
                .expect("mock inference server");
            server.enqueue_response(
                "/v1/responses",
                ScriptedResponse::text(503, "upstream overloaded"),
            );
            server.enqueue_response(
                "/v1/responses",
                ScriptedResponse::text(503, "upstream overloaded"),
            );
            // Once the queue drains, the mock serves its default success response.
            let policy = fuigo_sampler::RetryPolicy {
                max_retries: 0,
                ..Default::default()
            };

            let (outcome, frames, _elapsed, submissions) = run_turn(&server, policy).await;

            assert!(outcome.is_ok(), "two 503s then success completes the turn");
            assert_eq!(submissions, 3);
            let status: Vec<&Frame> = frames.iter().filter(|f| is_retry_frame(f)).collect();
            let state = |attempt| RetryState::Retrying {
                attempt,
                max_retries: 3,
                reason: "Server error; retrying request".to_string(),
                error_type: Some("api".to_string()),
            };
            assert_eq!(
                status,
                vec![
                    &Frame::Fuigo(state(1)),
                    &mirror(
                        "Retrying the model (1/3): Server error; retrying request\n\n",
                        &state(1)
                    ),
                    &Frame::Fuigo(state(2)),
                    &mirror(
                        "Retrying the model (2/3): Server error; retrying request\n\n",
                        &state(2)
                    ),
                ],
                "each shell-rail retry is mirrored once, and no failure is announced"
            );
        })
    });
}

/// One sampler retry (a 503), then a normal answer: the client's answer is exactly the model's text.
/// Murage appends every `agent_message_chunk` to the reply it stores and forwards; a retry line there corrupts the answer.
#[test]
fn a_retried_turn_answers_with_the_model_text_only() {
    const ANSWER: &str = "Hello there, this answer came after one retry.";
    on_session_stack(|| {
        run_paused(|| async {
            let server = MockInferenceServer::start_with_models(vec![MockModelEntry::new("test")])
                .await
                .expect("mock inference server");
            server.enqueue_response(
                "/v1/responses",
                ScriptedResponse::text(503, "upstream overloaded"),
            );
            server.enqueue_response(
                "/v1/responses",
                ScriptedResponse::sse(sse::responses_api_script_exact(ANSWER, "test")),
            );
            let policy = fuigo_sampler::RetryPolicy {
                max_retries: 3,
                ..Default::default()
            };
            let (actor, frames) = actor_under_test_with_event_pump(
                &server,
                SessionKind::Main,
                policy,
                true,
                drain_frames,
            )
            .await;

            let (outcome, frames, _elapsed, submissions) =
                drive_turn(actor, frames, &server, "req-empty-response-status-test").await;

            assert!(
                outcome.is_ok(),
                "the retried request answers: {:?}",
                outcome.as_ref().err()
            );
            assert_eq!(submissions, 2, "the 503 and its successful resend");
            let message_chunks: Vec<&str> = frames
                .iter()
                .filter_map(|f| match f {
                    Frame::Standard { kind, text, .. } if kind == AGENT_MESSAGE => {
                        Some(text.as_str())
                    }
                    _ => None,
                })
                .collect();
            assert!(
                message_chunks.iter().all(|t| !t.contains("Retrying")),
                "no retry text in agent_message_chunk: {message_chunks:?}"
            );
            assert_eq!(
                message_chunks.concat(),
                ANSWER,
                "the answer chunks concatenate to exactly the model's text: {frames:#?}"
            );
            let retry_frames: Vec<&Frame> = frames.iter().filter(|f| is_retry_frame(f)).collect();
            let Some(Frame::Fuigo(
                state @ RetryState::Retrying {
                    attempt,
                    max_retries,
                    reason,
                    ..
                },
            )) = retry_frames.first().copied()
            else {
                panic!("expected a Retrying state first: {frames:#?}");
            };
            assert_eq!(
                retry_frames,
                vec![
                    &Frame::Fuigo(state.clone()),
                    &mirror(
                        &format!("Retrying the model ({attempt}/{max_retries}): {reason}\n\n"),
                        state
                    ),
                ],
                "the retry is shown once, as a thought"
            );
        })
    });
}

/// The rate-limit terminal (`RetryState::Exhausted`, the sampler_turn rate-limited arm) is mirrored as a thought with its attempt count.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn rate_limit_exhaustion_is_mirrored_as_a_thought() {
    use crate::session::acp_session::RateLimitWaitConfig;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let server = MockInferenceServer::start_with_models(vec![MockModelEntry::new("test")])
                .await
                .expect("mock inference server");
            for _ in 0..=RateLimitWaitConfig::DEFAULT_MAX_ATTEMPTS {
                server.enqueue_response("/v1/responses", rate_limited_reply(1));
            }
            let (actor, frames) = actor_under_test_with_gateway(
                &server,
                SessionKind::Subagent,
                sampler_surfaces_429(),
                true,
                drain_frames,
            )
            .await;
            let request = conversation_request(&actor).await;
            let mut budget = actor.rate_limit_wait_budget();

            let outcome = tokio::time::timeout(
                Duration::from_secs(60),
                actor.run_turn_via_sampler(
                    request,
                    &mut budget,
                    transient_state(0, true),
                    false,
                    crate::session::acp_session::TurnParkState::Fresh,
                ),
            )
            .await
            .expect("turn must finish within timeout");
            assert!(outcome.is_err(), "a budget spent on 429s fails the turn");
            pump_local_tasks().await;

            let frames = frames.lock().unwrap().clone();
            let exhausted: Vec<&Frame> = frames
                .iter()
                .filter(|f| match f {
                    Frame::Fuigo(RetryState::Exhausted { .. }) => true,
                    Frame::Standard {
                        retry_status: Some(status),
                        ..
                    } => status["type"] == "exhausted",
                    _ => false,
                })
                .collect();
            let Some(Frame::Fuigo(
                state @ RetryState::Exhausted {
                    attempts, reason, ..
                },
            )) = exhausted.first().copied()
            else {
                panic!("expected an Exhausted state first: {frames:#?}");
            };
            assert_eq!(*attempts, RateLimitWaitConfig::DEFAULT_MAX_ATTEMPTS);
            assert_eq!(
                exhausted,
                vec![
                    &Frame::Fuigo(state.clone()),
                    &mirror(
                        &format!(
                            "The model request failed after {attempts} attempts: {reason}\n\n"
                        ),
                        state
                    ),
                ],
                "the exhaustion is shown once on each rail"
            );
        })
        .await;
}

/// Answer text already generated (held in the replay buffer's 10 ms / 2 KB merge window) reaches the client before a retry mirror sent after it.
#[tokio::test(flavor = "current_thread")]
async fn a_retry_mirror_never_overtakes_answer_text_already_generated() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (gateway_tx, gateway_rx) = tokio::sync::mpsc::unbounded_channel();
            let frames = drain_frames(gateway_rx);
            let (persistence_tx, persistence_rx) = tokio::sync::mpsc::unbounded_channel();
            drain_persistence(persistence_rx);
            let (mut actor, mut event_rx) =
                create_test_actor_ex(0, 256_000, 85, gateway_tx, persistence_tx).await;
            actor.buffering_settings = Some(crate::agent::update_chunk_merge::BufferingSettings {
                max_items: 100,
                max_bytes: 2048,
                max_duration_ms: 10,
            });
            let mut replay_buffer = crate::agent::update_chunk_merge::ReplayBuffer::new(
                actor.buffering_settings.clone(),
            );

            actor
                .send_update(
                    acp::SessionUpdate::AgentMessageChunk(acp::ContentChunk::new(
                        acp::ContentBlock::Text(acp::TextContent::new("Partial answer, ")),
                    )),
                    None,
                )
                .await;
            // The session loop drains it into the replay buffer, which holds it for merging
            while let Ok(event) = event_rx.try_recv() {
                actor.handle_session_event(event, &mut replay_buffer).await;
            }
            let retrying = RetryState::Retrying {
                attempt: 1,
                max_retries: 3,
                reason: "Server error; retrying request".to_string(),
                error_type: Some("api".to_string()),
            };
            actor
                .send_fuigo_notification(FuigoSessionUpdate::RetryState(retrying.clone()))
                .await;
            while let Ok(event) = event_rx.try_recv() {
                actor.handle_session_event(event, &mut replay_buffer).await;
            }
            // The loop's periodic flush
            actor
                .handle_session_event(
                    SessionEvent::FlushReplay { respond_to: None },
                    &mut replay_buffer,
                )
                .await;
            pump_local_tasks().await;

            let standard: Vec<Frame> = frames
                .lock()
                .unwrap()
                .iter()
                .filter(|f| matches!(f, Frame::Standard { .. }))
                .cloned()
                .collect();
            assert_eq!(
                standard,
                vec![
                    Frame::Standard {
                        kind: AGENT_MESSAGE.to_string(),
                        text: "Partial answer, ".to_string(),
                        retry_status: None,
                    },
                    mirror(
                        "Retrying the model (1/3): Server error; retrying request\n\n",
                        &retrying
                    ),
                ],
                "the text generated before the retry reaches the client first"
            );
        })
        .await;
}

/// A mirror queued from outside this actor gets everything a mirror sent from inside it gets:
/// the replay buffer flushed ahead of it, and its own paragraph after streamed reasoning.
///
/// The persistence actor's disk-full `retry_state` is the one mirror produced outside the session.
/// It reaches the client as `SessionEvent::RetryStatusMirror`, and the notification is built here,
/// where `turn_thought_text_emitted` and `current_prompt_id` live -- a `Send` actor on another task
/// can read neither, and a direct gateway send would also race the answer text already generated.
#[tokio::test(flavor = "current_thread")]
async fn a_mirror_queued_from_outside_the_actor_is_ordered_and_separated() {
    use crate::extensions::notification::{DISK_FULL_ERROR_TYPE, DISK_FULL_USER_MESSAGE};
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (gateway_tx, gateway_rx) = tokio::sync::mpsc::unbounded_channel();
            let frames = drain_frames(gateway_rx);
            let (persistence_tx, persistence_rx) = tokio::sync::mpsc::unbounded_channel();
            drain_persistence(persistence_rx);
            let (mut actor, mut event_rx) =
                create_test_actor_ex(0, 256_000, 85, gateway_tx, persistence_tx).await;
            actor.buffering_settings = Some(crate::agent::update_chunk_merge::BufferingSettings {
                max_items: 100,
                max_bytes: 2048,
                max_duration_ms: 10,
            });
            let mut replay_buffer = crate::agent::update_chunk_merge::ReplayBuffer::new(
                actor.buffering_settings.clone(),
            );

            actor
                .send_update(
                    acp::SessionUpdate::AgentMessageChunk(acp::ContentChunk::new(
                        acp::ContentBlock::Text(acp::TextContent::new("Saving your answer")),
                    )),
                    None,
                )
                .await;
            // The session loop drains it into the replay buffer, which holds it for merging
            while let Ok(event) = event_rx.try_recv() {
                actor.handle_session_event(event, &mut replay_buffer).await;
            }
            // The turn streamed reasoning before the write failed
            actor
                .turn_thought_text_emitted
                .store(true, std::sync::atomic::Ordering::Relaxed);

            let disk_full = RetryState::Failed {
                error_type: DISK_FULL_ERROR_TYPE.to_string(),
                message: DISK_FULL_USER_MESSAGE.to_string(),
            };
            actor
                .handle_session_event(
                    SessionEvent::RetryStatusMirror(Box::new(disk_full.clone())),
                    &mut replay_buffer,
                )
                .await;
            actor
                .handle_session_event(
                    SessionEvent::FlushReplay { respond_to: None },
                    &mut replay_buffer,
                )
                .await;
            pump_local_tasks().await;

            let standard: Vec<Frame> = frames
                .lock()
                .unwrap()
                .iter()
                .filter(|f| matches!(f, Frame::Standard { .. }))
                .cloned()
                .collect();
            assert_eq!(
                standard,
                vec![
                    Frame::Standard {
                        kind: AGENT_MESSAGE.to_string(),
                        text: "Saving your answer".to_string(),
                        retry_status: None,
                    },
                    mirror(
                        &format!(
                            "\n\nFuigo could not save this session: {DISK_FULL_USER_MESSAGE}\n\n"
                        ),
                        &disk_full
                    ),
                ],
                "the queued mirror follows the text already generated and opens its own paragraph"
            );
            assert!(
                !actor
                    .turn_thought_text_emitted
                    .load(std::sync::atomic::Ordering::Relaxed),
                "the separator is consumed, so a second mirror does not add another blank line"
            );
        })
        .await;
}

/// A durable execution scope for the turn `drive_turn` runs under `req_id`, as `handle_turn_input` opens one.
async fn open_execution(
    actor: &Arc<SessionActor>,
    req_id: &str,
) -> Arc<crate::session::execution_state::Execution> {
    open_execution_scope(actor, req_id, Default::default()).await
}

/// [`open_execution`] under a total-token budget, as a goal-bounded turn opens one.
/// A token limit is what makes `unknown_usage` deny later admissions at all.
async fn open_execution_with_budget(
    actor: &Arc<SessionActor>,
    req_id: &str,
    total_tokens: u64,
) -> Arc<crate::session::execution_state::Execution> {
    open_execution_scope(
        actor,
        req_id,
        crate::session::execution_state::TokenLimits {
            total: Some(total_tokens),
            output: None,
            initial_total: 0,
        },
    )
    .await
}

async fn open_execution_scope(
    actor: &Arc<SessionActor>,
    req_id: &str,
    limits: crate::session::execution_state::TokenLimits,
) -> Arc<crate::session::execution_state::Execution> {
    crate::session::execution_state::Execution::open(
        &actor.notifications.persistence_tx,
        &actor.session_info.id.to_string(),
        req_id,
        req_id,
        9,
        None,
        Some(9),
        limits,
        None,
    )
    .await
    .expect("execution scope is durable")
}

/// The execution-scope tests of THIS file must leave the registry slot every other test actor shares free.
///
/// `Execution::current(session_id)` is how a side call (a title, a recap) finds the live
/// execution, and every test actor answers to `test-actor`: an execution registered under
/// that id is visible to the ~12 recap and summary tests for as long as it lives. A mutex
/// held by the execution tests serialises them against each other and against nothing else.
///
/// The assertion is scoped to this file's own fixture rather than to the slot being empty:
/// a process-global absence would turn some future test's legitimate registration under
/// `test-actor` into a failure here instead of in the test that made it.
///
/// Its red is a MUTATION, not a pre-round failure: this file's fixtures have opened under their
/// own session id since they were written, so on the tree before this test there is nothing for
/// it to catch. It goes red when `actor_under_test_for_session` is pointed back at the shared
/// `test-actor` id, which is the regression it exists to stop.
#[test]
fn an_execution_scope_test_keeps_the_shared_session_slot_free() {
    on_session_stack(|| {
        run_paused(|| async {
            let server = MockInferenceServer::start_with_models(vec![MockModelEntry::new("test")])
                .await
                .expect("mock inference server");
            let (actor, _frames) = actor_under_test_for_session(
                &server,
                SessionKind::Main,
                fuigo_sampler::RetryPolicy::default(),
                true,
                drain_frames,
                "session-exec-scope-isolation",
            )
            .await;
            let session = actor.session_info.id.to_string();
            let execution = open_execution(&actor, "req-exec-scope-isolation").await;
            if let Some(shared) = crate::session::execution_state::Execution::current("test-actor")
            {
                assert!(
                    !Arc::ptr_eq(&shared, &execution),
                    "this file's execution-scope fixture claimed the registry slot every other \
                     test actor shares (`test-actor`); it must open under a session id of its own"
                );
            }
            assert!(
                crate::session::execution_state::Execution::current(&session).is_some(),
                "it registers under a session id of its own instead"
            );
            execution.release(&session);
        })
    });
}

/// [`sse::responses_api_reasoning_only_events`] with no usage reported at all.
///
/// A provider that reports usage on an empty reply charges it either way; the shape that
/// distinguishes a settlement from a supersede is the one with no usage, because only
/// `Change::Settle` turns that into `unknown_usage`.
fn reasoning_only_without_usage(reasoning: &str) -> Vec<fuigo_test_support::SseEvent> {
    sse::responses_api_reasoning_only_events(reasoning, "test")
        .into_iter()
        .map(|event| {
            let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&event.data) else {
                return event;
            };
            if value.get("type").and_then(serde_json::Value::as_str) == Some("response.completed")
                && let Some(response) = value.get_mut("response").and_then(|r| r.as_object_mut())
            {
                response.remove("usage");
            }
            fuigo_test_support::SseEvent::data(value.to_string())
        })
        .collect()
}

/// Empty replies must leave the execution's token budget usable.
///
/// `Change::Settle` with no reported usage sets `unknown_usage`, and that flag denies every
/// later admission under a token limit (`admit_attempt`) and finalizes the turn
/// (`turn.rs`'s `finalizing`). The empty-response path never settles: an attempt its own
/// resend takes over is handed off with `Change::Supersede`, which charges whatever usage
/// the provider did report and never sets the flag, and the last empty attempt, which
/// nothing takes over, is `Change::Abandon`ed and stays pending.
///
/// Pinned at one, two and three empty replies -- two in a row is the exact customer
/// scenario this release exists to fix -- and with the provider both reporting usage and
/// reporting none. The usage-less shape is the discriminating one: it is the only way a
/// settlement and a supersede differ, so a test that never sees it proves nothing.
#[test]
fn empty_replies_leave_the_execution_token_budget_usable() {
    const ANSWER: &str = "Here is the answer the resend produced.";
    const REASONING: &str = "Let me think about this carefully";
    for (budgeted, reports_usage) in [(true, true), (true, false), (false, true), (false, false)] {
        for empties in 1..=fuigo_sampler::EMPTY_RESPONSE_MAX_ATTEMPTS {
            // A runtime of its own per case: nothing carries over between them.
            on_session_stack(move || {
                run_paused(|| async move {
                    let server =
                        MockInferenceServer::start_with_models(vec![MockModelEntry::new("test")])
                            .await
                            .expect("mock inference server");
                    for _ in 0..empties {
                        let events = if reports_usage {
                            sse::responses_api_reasoning_only_events(REASONING, "test")
                        } else {
                            reasoning_only_without_usage(REASONING)
                        };
                        server.enqueue_response("/v1/responses", ScriptedResponse::sse(events));
                    }
                    server.enqueue_response(
                        "/v1/responses",
                        ScriptedResponse::sse(sse::responses_api_script_exact(ANSWER, "test")),
                    );
                    let policy = fuigo_sampler::RetryPolicy {
                        max_retries: fuigo_sampler::DEFAULT_MAX_RETRIES,
                        ..Default::default()
                    };
                    let (actor, frames) = actor_under_test_for_session(
                        &server,
                        SessionKind::Main,
                        policy,
                        false,
                        drain_frames,
                        "session-empty-budget",
                    )
                    .await;
                    let session = actor.session_info.id.to_string();
                    let req_id = "req-empty-budget";
                    let execution = if budgeted {
                        open_execution_with_budget(&actor, req_id, 1_000_000).await
                    } else {
                        open_execution(&actor, req_id).await
                    };

                    let (outcome, seen, _elapsed, submissions) =
                        drive_turn(actor.clone(), frames, &server, req_id).await;

                    let case = format!(
                        "{empties} empty replies, usage {reports_usage}, budget {budgeted}"
                    );
                    let state = execution.snapshot().await.expect("execution snapshot");
                    assert!(
                        !state.unknown_usage,
                        "{case}: the execution's usage must not become unknown: {state:?}"
                    );
                    assert!(
                        submissions
                            == empties
                                + u32::from(empties < fuigo_sampler::EMPTY_RESPONSE_MAX_ATTEMPTS)
                            && state.calls == u64::from(submissions),
                        "{case}: every empty attempt runs under the execution \
                         ({submissions} submissions, outcome {:?}, frames {seen:?}): {state:?}",
                        outcome.as_ref().err()
                    );
                    let later = uuid::Uuid::new_v4().to_string();
                    fuigo_sampling_types::ExecutionAdmission::admit(
                        execution.as_ref(),
                        fuigo_sampling_types::RequestPurpose::Work,
                        later,
                    )
                    .await
                    .unwrap_or_else(|error| {
                        panic!("{case}: the work after them is still admissible: {error} {state:?}")
                    });
                    execution.release(&session);
                })
            });
        }
    }
}

/// A turn its retry rescued must not report unresolved work.
///
/// The failed attempt's durable admission was never settled, so the terminal receipt came
/// back `partial` with the superseded attempt in `pending_attempts`, and a turn that had
/// answered was returned to the client as JSON-RPC `-32603`. Reproduced on the real binary
/// (1.0.11 through 1.0.18) by the `503_then_text` probe scenario.
#[test]
fn a_retry_that_answers_leaves_no_unresolved_attempt() {
    const ANSWER: &str = "Hello there, this answer came after one retry.";
    const REQ_ID: &str = "req-retry-receipt-rescued";
    on_session_stack(|| {
        run_paused(|| async {
            let server = MockInferenceServer::start_with_models(vec![MockModelEntry::new("test")])
                .await
                .expect("mock inference server");
            server.enqueue_response(
                "/v1/responses",
                ScriptedResponse::text(503, "upstream overloaded"),
            );
            server.enqueue_response(
                "/v1/responses",
                ScriptedResponse::sse(sse::responses_api_script_exact(ANSWER, "test")),
            );
            let policy = fuigo_sampler::RetryPolicy {
                max_retries: 3,
                ..Default::default()
            };
            let (actor, frames) = actor_under_test_for_session(
                &server,
                SessionKind::Main,
                policy,
                true,
                drain_frames,
                "session-retry-receipt-rescued",
            )
            .await;
            let execution = open_execution(&actor, REQ_ID).await;

            let (outcome, _frames, _elapsed, submissions) =
                drive_turn(actor.clone(), frames, &server, REQ_ID).await;

            assert!(
                outcome.is_ok(),
                "the retried request answers: {:?}",
                outcome.as_ref().err()
            );
            assert_eq!(submissions, 2, "the 503 and its successful resend");
            let state = execution.snapshot().await.expect("execution snapshot");
            // An optional side call (a title) may hold its own admission; only required work counts.
            let unresolved: Vec<&String> =
                state.pending.difference(&state.optional_attempts).collect();
            assert!(
                unresolved.is_empty(),
                "the resend took the 503 attempt over: {unresolved:?}"
            );
            assert!(
                state.calls >= 2,
                "both attempts keep their debit: {state:?}"
            );
            let receipt = execution.terminal(true).await.expect("terminal receipt");
            assert!(
                !receipt.partial,
                "a turn its retry rescued is not partial: {receipt:?}"
            );
            execution.release(&actor.session_info.id.to_string());
        })
    });
}

/// A turn that really failed still reports its unresolved attempt: the fix for the retry
/// path must not turn every failure into a clean receipt.
#[test]
fn a_turn_that_never_recovers_still_reports_its_attempt() {
    const REQ_ID: &str = "req-retry-receipt-failed";
    on_session_stack(|| {
        run_paused(|| async {
            let server = MockInferenceServer::start_with_models(vec![MockModelEntry::new("test")])
                .await
                .expect("mock inference server");
            for _ in 0..8 {
                server.enqueue_response(
                    "/v1/responses",
                    ScriptedResponse::sse(sse::responses_api_reasoning_only_events(
                        "Let me think about this carefully",
                        "test",
                    )),
                );
            }
            let policy = fuigo_sampler::RetryPolicy {
                max_retries: fuigo_sampler::DEFAULT_MAX_RETRIES,
                ..Default::default()
            };
            let (actor, frames) = actor_under_test_for_session(
                &server,
                SessionKind::Main,
                policy,
                false,
                drain_frames,
                "session-retry-receipt-failed",
            )
            .await;
            let execution = open_execution(&actor, REQ_ID).await;

            let (outcome, _frames, _elapsed, submissions) =
                drive_turn(actor.clone(), frames, &server, REQ_ID).await;

            assert!(outcome.is_err(), "the empty-response budget is spent");
            assert_eq!(submissions, 3, "the original request plus two resends");
            let receipt = execution.terminal(false).await.expect("terminal receipt");
            assert!(
                receipt.partial
                    && receipt
                        .pending_attempts
                        .iter()
                        .any(|id| !receipt.optional_pending_attempts.contains(id)),
                "the last attempt, which nothing took over, is still unresolved work: {receipt:?}"
            );
            execution.release(&actor.session_info.id.to_string());
        })
    });
}

/// Clients concatenate thought chunks: the mirror must not run into the model's last
/// reasoning sentence. It opens its own paragraph after streamed reasoning, and never
/// opens with a stray blank line when it is the turn's first thought text.
#[test]
fn a_mirror_after_reasoning_starts_its_own_paragraph() {
    const REASONING: &str = "Let me think about this carefully";
    on_session_stack(|| {
        run_paused(|| async {
            let server = MockInferenceServer::start_with_models(vec![MockModelEntry::new("test")])
                .await
                .expect("mock inference server");
            for _ in 0..8 {
                server.enqueue_response(
                    "/v1/responses",
                    ScriptedResponse::sse(sse::responses_api_reasoning_only_events(
                        REASONING, "test",
                    )),
                );
            }
            let policy = fuigo_sampler::RetryPolicy {
                max_retries: fuigo_sampler::DEFAULT_MAX_RETRIES,
                ..Default::default()
            };
            let (actor, frames) = actor_under_test_with_event_pump(
                &server,
                SessionKind::Main,
                policy,
                false,
                drain_frames,
            )
            .await;

            let (_outcome, frames, _elapsed, _submissions) =
                drive_turn(actor, frames, &server, "req-empty-response-status-test").await;

            // What a client that appends every thought chunk ends up showing.
            let thoughts: String = frames
                .iter()
                .filter_map(|f| match f {
                    Frame::Standard { kind, text, .. } if kind == AGENT_THOUGHT => {
                        Some(text.as_str())
                    }
                    _ => None,
                })
                .collect();
            let reasoning = format!("{REASONING} ");
            let retry = |n| {
                format!(
                    "\n\nRetrying the model ({n}/3): empty response from model (reasoning_only)\n\n"
                )
            };
            assert_eq!(
                thoughts,
                format!(
                    "{reasoning}{}{reasoning}{}{reasoning}\n\nThe model request failed after 3 attempts: empty response from model (reasoning_only)\n\n",
                    retry(1),
                    retry(2),
                ),
                "every mirror opens its own paragraph after the reasoning it follows: {frames:#?}"
            );
        })
    });
}
