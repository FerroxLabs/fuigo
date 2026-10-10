//! P188: a model request that fails after streaming text is resent, and the client must not show the dead attempt.
//!
//! Live report (ChatGPT subscription, GPT-5.6-Sol, Murage's ACP driver): one prompt showed three generations joined.
//! Each failed attempt's `agent_message_chunk`s had already reached the client; the only wire signal was
//! `retry_state{type:"retrying"}`, which said nothing about them. Fuigo's own history kept only the accepted attempt.
//! The fix stamps `discardEmitted: true` on the `retry_state` of a resend that follows visible output, delivered
//! after the dead attempt's chunks and before the resend's. These tests run a real sampler against a stub Responses
//! server whose first two streams close without `response.completed`.

use super::rate_limit_backoff_tests::{SessionKind, actor_under_test_with_event_pump};
use super::support::*;
use super::transient_retry_loop_tests::{on_session_stack, run_paused};
use super::*;
use crate::extensions::notification::RetryState;
use agent_client_protocol as acp;
use fuigo_test_support::{MockInferenceServer, MockModelEntry, ScriptedResponse, SseEvent, sse};
use std::sync::Arc;
use std::time::Duration;

/// What an ACP client receives, in order.
#[derive(Debug, Clone, PartialEq)]
enum Wire {
    /// `agent_message_chunk` text.
    Text(String),
    /// `agent_thought_chunk` text; `mirror` when it is the tagged standard-rail copy of a `retry_state`.
    Thought { text: String, mirror: bool },
    /// `_fuigo/session_notification` `retry_state`.
    Retry(RetryState),
    /// `tool_call` (P201): a row the client now shows, with its status.
    ToolCall { id: String, status: acp::ToolCallStatus },
    /// `tool_call_update` (P201) carrying a status.
    ToolUpdate { id: String, status: acp::ToolCallStatus },
}

type Captured = Arc<std::sync::Mutex<Vec<Wire>>>;

fn capture(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<fuigo_acp_lib::AcpClientMessage>,
) -> Captured {
    use crate::extensions::notification::{SessionNotification, SessionUpdate};
    let captured: Captured = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = captured.clone();
    tokio::task::spawn_local(async move {
        while let Some(msg) = rx.recv().await {
            let wire = match msg {
                fuigo_acp_lib::AcpClientMessage::SessionNotification(args) => {
                    let mirror = crate::extensions::notification::is_retry_status_update(
                        &args.request.update,
                    );
                    let wire = match &args.request.update {
                        acp::SessionUpdate::AgentMessageChunk(chunk) => match &chunk.content {
                            acp::ContentBlock::Text(t) => Some(Wire::Text(t.text.clone())),
                            _ => None,
                        },
                        acp::SessionUpdate::AgentThoughtChunk(chunk) => match &chunk.content {
                            acp::ContentBlock::Text(t) => Some(Wire::Thought {
                                text: t.text.clone(),
                                mirror,
                            }),
                            _ => None,
                        },
                        acp::SessionUpdate::ToolCall(call) => Some(Wire::ToolCall {
                            id: call.tool_call_id.0.to_string(),
                            status: call.status,
                        }),
                        acp::SessionUpdate::ToolCallUpdate(upd) => {
                            upd.fields.status.map(|status| Wire::ToolUpdate {
                                id: upd.tool_call_id.0.to_string(),
                                status,
                            })
                        }
                        _ => None,
                    };
                    let _ = args.response_tx.send(Ok(()));
                    wire
                }
                fuigo_acp_lib::AcpClientMessage::ExtNotification(args)
                    if args.request.method.as_ref() == "fuigo/session_notification" =>
                {
                    match serde_json::from_str::<SessionNotification>(args.request.params.get()) {
                        Ok(SessionNotification {
                            update: SessionUpdate::RetryState(rs),
                            ..
                        }) => Some(Wire::Retry(rs)),
                        _ => None,
                    }
                }
                _ => None,
            };
            if let Some(wire) = wire {
                sink.lock().unwrap().push(wire);
            }
        }
    });
    captured
}

/// The reply a client honouring the contract shows: text since the last discard.
fn visible_reply(wire: &[Wire]) -> String {
    let mut visible = String::new();
    for frame in wire {
        match frame {
            Wire::Text(t) => visible.push_str(t),
            Wire::Retry(RetryState::Retrying {
                discard_emitted: true,
                ..
            }) => visible.clear(),
            _ => {}
        }
    }
    visible
}

/// A Responses stream of `text` that closes without `response.completed` (what the ChatGPT backend did).
fn truncated(text: &str) -> ScriptedResponse {
    let mut events = sse::responses_api_script_exact(text, "test");
    // Drop `response.completed` and `[DONE]`
    events.truncate(events.len() - 2);
    ScriptedResponse::sse(events)
}

fn complete(text: &str) -> ScriptedResponse {
    ScriptedResponse::sse(sse::responses_api_script_exact(text, "test"))
}

async fn run(
    server: &MockInferenceServer,
    retry_policy: fuigo_sampler::RetryPolicy,
) -> (
    Result<TurnOutcome, agent_client_protocol::Error>,
    Vec<Wire>,
    Arc<SessionActor>,
) {
    let (actor, captured) = actor_under_test_with_event_pump(
        server,
        SessionKind::Main,
        retry_policy,
        true,
        capture,
    )
    .await;
    let outcome = tokio::time::timeout(
        Duration::from_secs(900),
        actor.process_conversation_turn_with_recovery(
            "req-p188-stream-retry",
            None,
            None,
            None,
            &mut length_salvage::LengthSalvage::new(None),
        ),
    )
    .await
    .expect("turn must finish within timeout");
    // Let the event pump deliver what the turn queued last
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    let wire = captured.lock().unwrap().clone();
    (outcome, wire, actor)
}

fn texts(wire: &[Wire]) -> String {
    wire.iter()
        .filter_map(|w| match w {
            Wire::Text(t) => Some(t.as_str()),
            _ => None,
        })
        .collect()
}

fn discards(wire: &[Wire]) -> Vec<usize> {
    wire.iter()
        .enumerate()
        .filter_map(|(i, w)| {
            matches!(
                w,
                Wire::Retry(RetryState::Retrying {
                    discard_emitted: true,
                    ..
                })
            )
            .then_some(i)
        })
        .collect()
}

fn index_of_text(wire: &[Wire], needle: &str) -> usize {
    wire.iter()
        .position(|w| matches!(w, Wire::Text(t) if t.contains(needle)))
        .unwrap_or_else(|| panic!("no text chunk with {needle:?} in {wire:?}"))
}

/// The sampler's own retry loop: A1 and A2 stream and die, A3 completes. The client must end up showing "A3" only,
/// and each dead attempt must be voided after its last chunk and before the next attempt's first.
#[test]
fn p188_sampler_resend_after_output_tells_the_client_to_discard_it() {
    on_session_stack(|| {
        run_paused(|| async {
            let server = MockInferenceServer::start_with_models(vec![MockModelEntry::new("test")])
                .await
                .expect("mock inference server");
            server.enqueue_response("/v1/responses", truncated("A1"));
            server.enqueue_response("/v1/responses", truncated("A2"));
            server.enqueue_response("/v1/responses", complete("A3"));
            let policy = fuigo_sampler::RetryPolicy {
                max_retries: fuigo_sampler::DEFAULT_MAX_RETRIES,
                ..Default::default()
            };

            let (outcome, wire, actor) = run(&server, policy).await;

            assert!(outcome.is_ok(), "the third attempt completes the turn: {:?}", outcome.as_ref().err());
            assert_eq!(texts(&wire), "A1A2A3", "every attempt's text did reach the client: {wire:?}");
            assert_eq!(
                visible_reply(&wire),
                "A3",
                "a client honouring discardEmitted shows only the accepted attempt: {wire:?}"
            );
            let d = discards(&wire);
            assert_eq!(d.len(), 2, "one discard per dead attempt: {wire:?}");
            let (a1, a2, a3) = (
                index_of_text(&wire, "A1"),
                index_of_text(&wire, "A2"),
                index_of_text(&wire, "A3"),
            );
            assert!(
                a1 < d[0] && d[0] < a2 && a2 < d[1] && d[1] < a3,
                "each discard lands between the attempt it voids and the next: {wire:?}"
            );
            // Stock clients get the void said in words on the standard-rail mirror
            assert!(
                wire.iter().any(|w| matches!(w, Wire::Thought { text, mirror: true }
                    if text.contains("discarding the partial reply above"))),
                "the mirror says the partial reply is discarded: {wire:?}"
            );
            // Fuigo's own history always kept only the accepted attempt
            assert_eq!(
                actor.chat_state_handle.get_trailing_assistant_report().await.as_deref(),
                Some("A3")
            );
        })
    });
}

/// The turn loop's own transient resend (sampler budget 0) is the other resend rail; it must void the dead text too.
#[test]
fn p188_turn_loop_resend_after_output_tells_the_client_to_discard_it() {
    on_session_stack(|| {
        run_paused(|| async {
            let server = MockInferenceServer::start_with_models(vec![MockModelEntry::new("test")])
                .await
                .expect("mock inference server");
            server.enqueue_response("/v1/responses", truncated("A1"));
            server.enqueue_response("/v1/responses", complete("A3"));
            let policy = fuigo_sampler::RetryPolicy {
                max_retries: 0,
                ..Default::default()
            };

            let (outcome, wire, _actor) = run(&server, policy).await;

            assert!(outcome.is_ok(), "the shell's resend completes the turn: {:?}", outcome.as_ref().err());
            assert_eq!(visible_reply(&wire), "A3", "{wire:?}");
            assert_eq!(discards(&wire).len(), 1, "{wire:?}");
        })
    });
}

/// A resend that follows no visible output owes no discard: the flag stays off (and off the wire).
#[test]
fn p188_resend_before_any_output_carries_no_discard() {
    on_session_stack(|| {
        run_paused(|| async {
            let server = MockInferenceServer::start_with_models(vec![MockModelEntry::new("test")])
                .await
                .expect("mock inference server");
            // `response.created` only, then the stream closes
            let mut events = sse::responses_api_script_exact("A1", "test");
            events.truncate(1);
            server.enqueue_response("/v1/responses", ScriptedResponse::sse(events));
            server.enqueue_response("/v1/responses", complete("A3"));
            let policy = fuigo_sampler::RetryPolicy {
                max_retries: fuigo_sampler::DEFAULT_MAX_RETRIES,
                ..Default::default()
            };

            let (outcome, wire, _actor) = run(&server, policy).await;

            assert!(outcome.is_ok(), "{:?}", outcome.as_ref().err());
            assert!(
                wire.iter().any(|w| matches!(w, Wire::Retry(RetryState::Retrying { .. }))),
                "the stream that died before output is still retried: {wire:?}"
            );
            assert!(discards(&wire).is_empty(), "nothing to discard: {wire:?}");
            assert_eq!(texts(&wire), "A3");
        })
    });
}

/// `completed.output: []` with the reply only in `output_item.done` (the ChatGPT backend) is that reply, not an empty
/// response: no resend, no discard, the text is history.
#[test]
fn p188_empty_completed_output_uses_output_item_done_without_a_retry() {
    on_session_stack(|| {
        run_paused(|| async {
            let server = MockInferenceServer::start_with_models(vec![MockModelEntry::new("test")])
                .await
                .expect("mock inference server");
            let mut events = sse::responses_api_script_exact("Hello there", "test");
            // [created, delta, delta, completed, DONE]: move the message into an `output_item.done`, empty the terminal output
            let completed_at = events.len() - 2;
            let mut completed: serde_json::Value =
                serde_json::from_str(&events[completed_at].data).expect("completed json");
            let item = completed["response"]["output"][0].clone();
            completed["response"]["output"] = serde_json::json!([]);
            events[completed_at] = SseEvent::data(completed.to_string());
            events.insert(
                completed_at,
                SseEvent::data(
                    serde_json::json!({
                        "type": "response.output_item.done",
                        "sequence_number": 90,
                        "output_index": 0,
                        "item": item,
                    })
                    .to_string(),
                ),
            );
            server.enqueue_response("/v1/responses", ScriptedResponse::sse(events));
            let policy = fuigo_sampler::RetryPolicy {
                max_retries: fuigo_sampler::DEFAULT_MAX_RETRIES,
                ..Default::default()
            };

            let (outcome, wire, actor) = run(&server, policy).await;

            assert!(outcome.is_ok(), "{:?}", outcome.as_ref().err());
            assert_eq!(server.request_count_for("/v1/responses"), 1, "no resend: {wire:?}");
            assert!(
                !wire.iter().any(|w| matches!(w, Wire::Retry(_))),
                "no retry at all: {wire:?}"
            );
            assert_eq!(
                actor.chat_state_handle.get_trailing_assistant_report().await.as_deref(),
                Some("Hello there")
            );
        })
    });
}

// ── P201: hosted tools (web_search, x_search, code_interpreter) inside a failed attempt ──

#[derive(Clone, Copy, Debug)]
enum Hosted {
    WebSearch,
    CodeInterpreter,
    XSearch,
}

impl Hosted {
    /// The Responses frames of one hosted run: the start frame and (when `finished`) its `output_item.done`.
    fn frames(self, id: &str, finished: bool) -> Vec<SseEvent> {
        let (start, done) = match self {
            Hosted::WebSearch => (
                serde_json::json!({"type":"response.web_search_call.in_progress","sequence_number":10,
                    "output_index":1,"item_id":id}),
                serde_json::json!({"type":"web_search_call","id":id,"status":"completed",
                    "action":{"type":"search","query":"q","sources":[]}}),
            ),
            Hosted::CodeInterpreter => (
                serde_json::json!({"type":"response.code_interpreter_call.in_progress","sequence_number":10,
                    "output_index":1,"item_id":id}),
                serde_json::json!({"type":"code_interpreter_call","id":id,"status":"completed",
                    "code":"print(1)","container_id":"cont_1","outputs":null}),
            ),
            Hosted::XSearch => (
                serde_json::json!({"type":"response.custom_tool_call_input.done","sequence_number":10,
                    "output_index":1,"item_id":id,"input":"{}"}),
                serde_json::json!({"type":"custom_tool_call","call_id":"call_x","name":"x_keyword_search",
                    "input":"{}","id":id}),
            ),
        };
        let mut frames = vec![SseEvent::data(start.to_string())];
        if finished {
            frames.push(SseEvent::data(
                serde_json::json!({"type":"response.output_item.done","sequence_number":11,
                    "output_index":1,"item":done})
                .to_string(),
            ));
        }
        frames
    }
}

/// `text`'s stream with `hosted` frames after `response.created`; `die` drops `response.completed` and `[DONE]`.
/// An empty `text` keeps only the hosted frames.
fn with_hosted(text: &str, hosted: Vec<SseEvent>, die: bool) -> ScriptedResponse {
    let mut events = sse::responses_api_script_exact(text, "test");
    if die {
        events.truncate(events.len() - 2);
    }
    if text.is_empty() {
        events.truncate(1);
    }
    let tail = events.split_off(1);
    events.extend(hosted);
    events.extend(tail);
    ScriptedResponse::sse(events)
}

fn tool_ix(wire: &[Wire], want: &Wire) -> usize {
    wire.iter().position(|w| w == want).unwrap_or_else(|| panic!("{want:?} missing in {wire:?}"))
}

fn count(wire: &[Wire], want: &Wire) -> usize {
    wire.iter().filter(|w| *w == want).count()
}

/// Status each row ends on, in first-seen order: a spinning row is one whose last status is `InProgress`.
fn spinning(wire: &[Wire]) -> Vec<String> {
    let mut last: Vec<(String, acp::ToolCallStatus)> = Vec::new();
    for w in wire {
        let (id, status) = match w {
            Wire::ToolCall { id, status } | Wire::ToolUpdate { id, status } => (id, status),
            _ => continue,
        };
        match last.iter_mut().find(|(i, _)| i == id) {
            Some(slot) => slot.1 = *status,
            None => last.push((id.clone(), *status)),
        }
    }
    last.into_iter()
        .filter(|(_, s)| matches!(s, acp::ToolCallStatus::InProgress))
        .map(|(i, _)| i)
        .collect()
}

fn call(id: &str, status: acp::ToolCallStatus) -> Wire {
    Wire::ToolCall { id: id.into(), status }
}

fn update(id: &str, status: acp::ToolCallStatus) -> Wire {
    Wire::ToolUpdate { id: id.into(), status }
}

async fn run_two_attempts(first: ScriptedResponse, second: ScriptedResponse) -> Vec<Wire> {
    let server = MockInferenceServer::start_with_models(vec![MockModelEntry::new("test")])
        .await
        .expect("mock inference server");
    server.enqueue_response("/v1/responses", first);
    server.enqueue_response("/v1/responses", second);
    let policy = fuigo_sampler::RetryPolicy {
        max_retries: fuigo_sampler::DEFAULT_MAX_RETRIES,
        ..Default::default()
    };
    let (outcome, wire, _actor) = run(&server, policy).await;
    assert!(outcome.is_ok(), "the second attempt completes the turn: {:?}", outcome.as_ref().err());
    wire
}

/// Attempt 1 starts a hosted tool and dies with nothing else on screen; attempt 2 runs its own and answers.
async fn hosted_row_only_case(kind: Hosted) {
    let wire = run_two_attempts(
        with_hosted("", kind.frames("h1", false), true),
        with_hosted("A2", kind.frames("h2", true), false),
    )
    .await;
    let d = discards(&wire);
    assert_eq!(d.len(), 1, "exactly one retry notice with discardEmitted: {wire:?}");
    let row = tool_ix(&wire, &call("h1", acp::ToolCallStatus::InProgress));
    let closed = tool_ix(&wire, &update("h1", acp::ToolCallStatus::Failed));
    let second = tool_ix(&wire, &call("h2", acp::ToolCallStatus::InProgress));
    assert!(
        row < d[0] && d[0] < closed && closed < second,
        "order: hosted row, the discard notice, the row's terminal update, then the resend's rows: {wire:?}"
    );
    assert_eq!(count(&wire, &update("h1", acp::ToolCallStatus::Failed)), 1, "closed once: {wire:?}");
    assert_eq!(texts(&wire), "A2", "the answer is shown once: {wire:?}");
    assert!(spinning(&wire).is_empty(), "no row is left spinning: {wire:?}");
}

#[test]
fn p201_web_search_row_of_a_failed_attempt_is_closed_after_the_discard() {
    on_session_stack(|| run_paused(|| hosted_row_only_case(Hosted::WebSearch)));
}

#[test]
fn p201_code_interpreter_row_of_a_failed_attempt_is_closed_after_the_discard() {
    on_session_stack(|| run_paused(|| hosted_row_only_case(Hosted::CodeInterpreter)));
}

#[test]
fn p201_x_search_row_of_a_failed_attempt_is_closed_after_the_discard() {
    on_session_stack(|| run_paused(|| hosted_row_only_case(Hosted::XSearch)));
}

/// Row and text in the dead attempt: still one notice, every row closed, and the text voided.
#[test]
fn p201_hosted_row_and_text_in_a_failed_attempt_get_one_notice_and_all_rows_closed() {
    on_session_stack(|| {
        run_paused(|| async {
            let wire = run_two_attempts(
                with_hosted("A1", Hosted::WebSearch.frames("h1", false), true),
                complete("A2"),
            )
            .await;
            let d = discards(&wire);
            assert_eq!(d.len(), 1, "one notice for the failed attempt: {wire:?}");
            assert_eq!(
                wire.iter().filter(|w| matches!(w, Wire::Retry(RetryState::Retrying { .. }))).count(),
                1,
                "never told twice: {wire:?}"
            );
            let closed = tool_ix(&wire, &update("h1", acp::ToolCallStatus::Failed));
            assert!(d[0] < closed, "the row is closed right after the notice that voids its attempt: {wire:?}");
            assert!(index_of_text(&wire, "A1") < d[0] && d[0] < index_of_text(&wire, "A2"), "{wire:?}");
            assert_eq!(visible_reply(&wire), "A2", "{wire:?}");
            assert!(spinning(&wire).is_empty(), "{wire:?}");
        })
    });
}

/// Attempt 1 dies before any event: no discard, no terminal update (guards against over-marking).
#[test]
fn p201_a_failed_attempt_with_no_event_sends_no_discard_and_closes_nothing() {
    on_session_stack(|| {
        run_paused(|| async {
            let wire = run_two_attempts(with_hosted("", vec![], true), complete("A2")).await;
            assert!(wire.iter().any(|w| matches!(w, Wire::Retry(RetryState::Retrying { .. }))), "{wire:?}");
            assert!(discards(&wire).is_empty(), "nothing was shown, nothing to discard: {wire:?}");
            assert!(
                !wire.iter().any(|w| matches!(w, Wire::ToolCall { .. } | Wire::ToolUpdate { .. })),
                "no tool rows at all: {wire:?}"
            );
            assert_eq!(texts(&wire), "A2");
        })
    });
}

/// A hosted run that finished inside the failed attempt is already terminal: no second terminal update.
#[test]
fn p201_a_hosted_row_that_completed_in_the_failed_attempt_is_not_closed_again() {
    on_session_stack(|| {
        run_paused(|| async {
            let wire = run_two_attempts(
                with_hosted("", Hosted::WebSearch.frames("h1", true), true),
                complete("A2"),
            )
            .await;
            let d = discards(&wire);
            assert_eq!(d.len(), 1, "the finished row is still on screen, so the notice discards: {wire:?}");
            let terminal = wire
                .iter()
                .filter(|w| matches!(w, Wire::ToolUpdate { id, .. } if id == "h1"))
                .count();
            assert_eq!(terminal, 1, "exactly the run's own terminal update, none added: {wire:?}");
            assert_eq!(count(&wire, &update("h1", acp::ToolCallStatus::Failed)), 0, "{wire:?}");
            assert!(spinning(&wire).is_empty(), "{wire:?}");
        })
    });
}
