//! Retry progress on the standard ACP rail.
//! Every `RetryState` the shell sends on `_fuigo/session_notification` is mirrored as a live-only `session/update` `agent_message_chunk` that stock ACP clients render.
//! The reasoning-only empty-response storm is capped at one resend.

use super::rate_limit_backoff_tests::{
    SessionKind, actor_under_test_with_gateway, pump_local_tasks,
};
use super::transient_retry_loop_tests::{on_session_stack, run_paused};
use super::*;
use crate::extensions::notification::RetryState;
use agent_client_protocol as acp;
use fuigo_test_support::{MockInferenceServer, MockModelEntry, ScriptedResponse, sse};
use std::sync::Arc;
use std::time::Duration;

/// Chunk `_meta` key the mirror carries; the pager and headless mode skip chunks tagged with it.
const RETRY_STATUS_KEY: &str = "fuigo/retryStatus";

#[derive(Debug, Clone, PartialEq)]
enum Frame {
    /// `_fuigo/session_notification` `retry_state`.
    Fuigo(RetryState),
    /// Standard `session/update` `agent_message_chunk` text, with its `fuigo/retryStatus` chunk meta when tagged.
    Standard {
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
                    if let acp::SessionUpdate::AgentMessageChunk(chunk) = &args.request.update
                        && let acp::ContentBlock::Text(text) = &chunk.content
                    {
                        sink.lock().unwrap().push(Frame::Standard {
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

fn mirror(text: &str, state: &RetryState) -> Frame {
    Frame::Standard {
        text: text.to_string(),
        retry_status: Some(serde_json::to_value(state).expect("RetryState serializes")),
    }
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
    let requests_before = server.request_count();
    let started = tokio::time::Instant::now();
    let outcome = tokio::time::timeout(
        Duration::from_secs(900),
        actor.process_conversation_turn_with_recovery(
            "req-empty-response-status-test",
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
            let retrying = RetryState::Retrying {
                attempt: 1,
                max_retries: 2,
                reason: reason.to_string(),
                error_type: Some("empty_response".to_string()),
            };
            let failed = RetryState::Failed {
                error_type: "empty_response".to_string(),
                message: reason.to_string(),
            };
            assert_eq!(
                frames,
                vec![
                    Frame::Fuigo(retrying.clone()),
                    mirror(
                        "Retrying the model (1/2): empty response from model (reasoning_only)\n\n",
                        &retrying,
                    ),
                    Frame::Fuigo(failed.clone()),
                    mirror(
                        "The model request failed: empty response from model (reasoning_only)\n\n",
                        &failed,
                    ),
                ],
                "one resend on both rails, then one failure on both rails \
                 ({submissions} provider submissions, {elapsed:?} virtual)"
            );
            assert!(outcome.is_err(), "the turn fails once the cap is spent");
            assert_eq!(submissions, 2, "the original request plus one resend");
            assert!(
                elapsed < Duration::from_secs(10),
                "fails in seconds, not minutes: {elapsed:?}"
            );
        })
    });
}

/// The shell's own transient-retry rail (turn loop, not the sampler) is mirrored too: once per retry, and no failure once the turn recovers.
/// The model's answer chunks ride the session event queue, which this harness does not drain; the pager and headless tests pin that untagged chunks still render.
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
            let status: Vec<&Frame> = frames
                .iter()
                .filter(|f| {
                    matches!(
                        f,
                        Frame::Fuigo(_)
                            | Frame::Standard {
                                retry_status: Some(_),
                                ..
                            }
                    )
                })
                .collect();
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
