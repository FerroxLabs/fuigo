//! 26-4 (L-EMPTY) and 26-5 (L-AUTOREFUSE): the end of a turn started by a peer message, through real turns against the mock
//! inference server. No test contacts a real service.
use super::*;
use crate::session::peer_admission::{NoticeKind, PeerNotice, now_mono};
use crate::session::peer_message::{force_peer_messaging_for_test, test_envelope};
use fuigo_peer::Envelope;

fn incomplete_content_filter(text: &str) -> ScriptedResponse {
    let mut events = responses_api_script_exact(text, "test");
    for event in &mut events {
        let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&event.data) else { continue };
        if value["type"] == "response.completed" {
            value["type"] = "response.incomplete".into();
            value["response"]["status"] = "incomplete".into();
            value["response"]["incomplete_details"] = serde_json::json!({ "reason": "content_filter" });
            value["response"]["output"][0]["status"] = "incomplete".into();
            event.data = value.to_string();
        }
    }
    ScriptedResponse::sse(events)
}

fn envelope(id: &str) -> Envelope {
    test_envelope(id, "lane <a>", "please do the thing")
}

fn peer_turn_request(env: &Envelope) -> TurnInputRequest {
    TurnInputRequest {
        prompt_id: format!("peer-message-{}", env.message_id),
        input_origin: InputOrigin::new(PromptOrigin::PeerMessage { message_id: env.message_id.clone(), from: env.from.to_string() }),
        ..task_request("please do the thing", Vec::new())
    }
}

/// A reply with no text: the shell treats a reply with no content at all as a failed sample and resends it, so the reply that
/// reaches the end of a turn without text is whitespace only (or a content-less provider refusal, tested separately).
fn enqueue_no_text(server: &MockInferenceServer) {
    server.enqueue_response("/v1/responses", ScriptedResponse::sse(responses_api_script_exact("\n", "test")));
}

struct Rig {
    server: MockInferenceServer,
    actor: Arc<SessionActor>,
}

async fn rig() -> Rig {
    let server = MockInferenceServer::start().await.expect("mock inference server");
    let (actor, _h, _c, _p) =
        actor_with_sampler(&server, Arc::new(RecordingTerminal { calls: Arc::new(AtomicUsize::new(0)) })).await;
    Rig { server, actor }
}

/// What `run_task` does around a peer-started turn: deliver, begin the turn, run it, then the end-of-turn hook.
async fn run_peer_turn(r: &Rig, env: &Envelope) -> PromptTurnResult {
    r.actor.peer_admission.note_delivered(env);
    let guard = r.actor.peer_admission.begin_turn(false, Some(&env.message_id));
    let request = peer_turn_request(env);
    let origin = request.input_origin.as_prompt_origin().clone();
    let result = run_parent_turn(&r.actor, request).await;
    r.actor.finish_peer_started_turn(&origin, &result);
    drop(guard);
    result
}

fn kinds(notices: &[PeerNotice]) -> Vec<NoticeKind> {
    notices.iter().map(|n| n.kind).collect()
}

fn text_of(n: &PeerNotice) -> String {
    let ev = crate::extensions::peer::notice_event("s", n);
    ev["update"]["text"].as_str().unwrap_or_default().to_owned()
}

/// A watch on the message: what the sender is told when the receiver settles it.
fn watch(r: &Rig, env: &Envelope) -> tokio::sync::mpsc::UnboundedReceiver<crate::session::peer_watch::Outbound> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let total = Arc::new(AtomicUsize::new(0));
    let gate = r.actor.peer_admission.gate();
    gate.watches.register_watch(&env.message_id, &env.from, &tx, &total).unwrap();
    gate.watches.settled(&env.message_id, &env.from, false, false, &tx);
    rx
}

fn sender_told(rx: &mut tokio::sync::mpsc::UnboundedReceiver<crate::session::peer_watch::Outbound>) -> Vec<fuigo_peer::NoticeKind> {
    let mut v = Vec::new();
    while let Ok(o) = rx.try_recv() {
        v.push(o.kind);
    }
    v
}

#[tokio::test(flavor = "current_thread")]
async fn empty_reply_shows_one_notice_and_refuses_the_message() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let _on = force_peer_messaging_for_test(true);
            let r = rig().await;
            enqueue_no_text(&r.server);
            let env = envelope("m1");
            let mut told = watch(&r, &env);
            let result = run_peer_turn(&r, &env).await;
            assert!(result.is_ok(), "the turn completed: {result:?}");
            let n = r.actor.peer_admission.take_notices(now_mono());
            assert_eq!(kinds(&n), vec![NoticeKind::PeerTurnNoReply, NoticeKind::ModelRefused], "{n:?}");
            assert_eq!(
                text_of(&n[0]),
                "The model ended the turn started by a message from lane &lt;a&gt; [3f2a9c10] without a reply."
            );
            assert_eq!(n[1].detail.as_deref(), Some("no action taken"));
            assert_eq!(sender_told(&mut told), vec![fuigo_peer::NoticeKind::Denied], "the sender got the refused notice, no idle after");
        })
        .await;
}

/// A reply with no content at all is resent; when the resends run out the turn FAILS (the user sees the error). Such a turn is
/// not judged: nothing is refused and no peer notice is added.
#[tokio::test(flavor = "current_thread")]
async fn a_contentless_reply_that_fails_the_turn_is_left_alone() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let _on = force_peer_messaging_for_test(true);
            let r = rig().await;
            for _ in 0..8 {
                r.server.enqueue_response("/v1/responses", ScriptedResponse::sse(responses_api_script_exact("", "test")));
            }
            let env = envelope("m1");
            let result = run_peer_turn(&r, &env).await;
            assert!(result.is_err(), "the turn failed: {result:?}");
            assert!(r.actor.peer_admission.take_notices(now_mono()).is_empty());
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn refusal_stop_shows_the_declined_notice_and_refuses() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let _on = force_peer_messaging_for_test(true);
            let r = rig().await;
            r.server.enqueue_response("/v1/responses", incomplete_content_filter(""));
            let env = envelope("m1");
            let mut told = watch(&r, &env);
            assert!(run_peer_turn(&r, &env).await.is_ok());
            let n = r.actor.peer_admission.take_notices(now_mono());
            assert_eq!(kinds(&n), vec![NoticeKind::PeerTurnDeclined, NoticeKind::ModelRefused], "{n:?}");
            assert_eq!(text_of(&n[0]), "The model declined to act on the message from lane &lt;a&gt; [3f2a9c10].");
            assert_eq!(sender_told(&mut told), vec![fuigo_peer::NoticeKind::Denied]);
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn text_only_reply_is_refused_and_its_text_is_still_shown() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let _on = force_peer_messaging_for_test(true);
            let r = rig().await;
            r.server.enqueue_response("/v1/responses", ScriptedResponse::sse(responses_api_script_exact("I will not do that.", "test")));
            let env = envelope("m1");
            let mut told = watch(&r, &env);
            assert!(run_peer_turn(&r, &env).await.is_ok());
            let n = r.actor.peer_admission.take_notices(now_mono());
            assert_eq!(kinds(&n), vec![NoticeKind::ModelRefused], "no peer-turn notice for a reply with text: {n:?}");
            assert_eq!(sender_told(&mut told), vec![fuigo_peer::NoticeKind::Denied]);
            let conversation = r.actor.chat_state_handle.get_conversation().await;
            assert!(
                conversation.iter().any(|i| i.text_content().contains("I will not do that.")),
                "the model's text is in the transcript"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_peer_turn_that_calls_a_tool_is_not_refused() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let _on = force_peer_messaging_for_test(true);
            let r = rig().await;
            r.server.enqueue_response(
                "/v1/responses",
                ScriptedResponse::sse(fuigo_test_support::sse::responses_api_reasoning_then_tool_call_events(
                    "thinking",
                    "call-1",
                    "no_such_tool_for_this_test",
                    "{}",
                    "test",
                )),
            );
            r.server.enqueue_response("/v1/responses", ScriptedResponse::sse(responses_api_script_exact("", "test")));
            let env = envelope("m1");
            let mut told = watch(&r, &env);
            assert!(run_peer_turn(&r, &env).await.is_ok());
            let n = r.actor.peer_admission.take_notices(now_mono());
            assert!(n.is_empty(), "acted on the message (a tool call was made): {n:?}");
            assert_eq!(sender_told(&mut told), vec![fuigo_peer::NoticeKind::Idle], "the normal idle notice, no refusal");
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_human_typed_turn_with_an_empty_reply_is_untouched() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let _on = force_peer_messaging_for_test(true);
            let r = rig().await;
            enqueue_no_text(&r.server);
            // A peer message was delivered earlier; the human types a prompt.
            r.actor.peer_admission.note_delivered(&envelope("m1"));
            let _g = r.actor.peer_admission.begin_turn(true, None);
            let request = user_request("hello");
            let origin = request.input_origin.as_prompt_origin().clone();
            let result = run_parent_turn(&r.actor, request).await;
            r.actor.finish_peer_started_turn(&origin, &result);
            assert!(r.actor.peer_admission.take_notices(now_mono()).is_empty());
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn the_model_refusing_itself_is_recorded_once() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let _on = force_peer_messaging_for_test(true);
            let r = rig().await;
            enqueue_no_text(&r.server);
            let env = envelope("m1");
            r.actor.peer_admission.note_delivered(&env);
            let guard = r.actor.peer_admission.begin_turn(false, Some("m1"));
            // The tool's handler, as the model's `refuse_peer_message` call reaches it.
            let args = fuigo_peer::tools::RefusePeerMessageArgs { message_id: "m1".into(), reason: "not mine".into() };
            r.actor.refuse_peer_message(&args).expect("refused by the model");
            let request = peer_turn_request(&env);
            let origin = request.input_origin.as_prompt_origin().clone();
            let result = run_parent_turn(&r.actor, request).await;
            r.actor.finish_peer_started_turn(&origin, &result);
            drop(guard);
            let n = r.actor.peer_admission.take_notices(now_mono());
            assert_eq!(kinds(&n), vec![NoticeKind::ModelRefused], "one refusal, no second automatic one, no no-reply notice: {n:?}");
            assert_eq!(n[0].detail.as_deref(), Some("not mine"));
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn flag_off_nothing_runs() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let r = rig().await;
            let env = envelope("m1");
            let _off = force_peer_messaging_for_test(false);
            r.server.enqueue_response("/v1/responses", ScriptedResponse::sse(responses_api_script_exact("hello there", "test")));
            assert!(run_peer_turn(&r, &env).await.is_ok());
            assert!(r.actor.peer_admission.take_notices(now_mono()).is_empty());
            assert!(!r.actor.peer_admission.turn_observed_anything(), "the per-reply hook was not reached with the flag off");
        })
        .await;
}

/// P28-DUP: `refuse_peer_message` makes the receiver-side peer state dirty (refused sender) while its own tool call is open.
/// The result handler (`handle_bridge_tool_success` / `handle_tool_error`) runs `persist_peer_state` BEFORE it pushes the
/// call's result, so the `peer_carried_denials` marker is appended first; that `push_user_message` runs the integrity repair,
/// which answers the still-open call with a synthetic "cancelled" result, and the real result then lands after the marker
/// (outside the contiguous run `dedup_duplicate_tool_results` scans). Here the dirty state is set just before the turn (no
/// persist runs between it and the result handler) and the call is a real tool (`todo_write`, success path).
#[tokio::test(flavor = "current_thread")]
async fn p28_dup_refusal_pending_when_a_tool_result_lands_leaves_one_result_per_call() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let _on = force_peer_messaging_for_test(true);
            let r = rig().await;
            *r.actor.agent.borrow_mut() = test_fuigo_build_agent_with_todo().await;
            r.server.enqueue_response(
                "/v1/responses",
                ScriptedResponse::sse(fuigo_test_support::sse::responses_api_reasoning_then_tool_call_events(
                    "thinking",
                    "call-1",
                    "todo_write",
                    r#"{"todos":[{"id":"t1","content":"do","status":"completed"}]}"#,
                    "test",
                )),
            );
            r.server.enqueue_response("/v1/responses", ScriptedResponse::sse(responses_api_script_exact("done", "test")));
            let env = envelope("m1");
            r.actor.peer_admission.note_delivered(&env);
            let guard = r.actor.peer_admission.begin_turn(false, Some("m1"));
            // What the `refuse_peer_message` tool does through the pump (sets the refused sender, `state_dirty`).
            let args = fuigo_peer::tools::RefusePeerMessageArgs { message_id: "m1".into(), reason: "not mine".into() };
            r.actor.refuse_peer_message(&args).expect("refused by the model");
            let request = peer_turn_request(&env);
            let result = run_parent_turn(&r.actor, request).await;
            drop(guard);
            assert!(result.is_ok(), "{result:?}");
            let bodies = r.server.request_bodies();
            assert!(bodies.len() >= 2, "a follow-up request was sent: {}", bodies.len());
            let input = bodies[1]["input"].as_array().cloned().unwrap_or_default();
            let outputs: Vec<&serde_json::Value> =
                input.iter().filter(|i| i["type"] == "function_call_output" && i["call_id"] == "call-1").collect();
            assert_eq!(
                outputs.len(),
                1,
                "exactly one tool result for call-1; follow-up input: {}",
                serde_json::to_string_pretty(&input).unwrap()
            );
            // P29-C: the marker stored while the call was open sits BEFORE the assistant item that made it.
            let stored = r.actor.chat_state_handle.get_conversation().await;
            assert_one_result_and_markers_before_call(&stored, "call-1");
            assert!(!fuigo_sampling_types::history_peer_carried(&stored).is_empty(), "the refusal state is stored");
        })
        .await;
}

type Conv = [fuigo_sampling_types::ConversationItem];

/// The placement contract of `push_state_marker_and_ack` as production callers hit it: exactly one `tool_result` for the call,
/// directly after the assistant item that made the call (a marker never splits that run), and at least one peer state marker
/// stored while the call was open, which therefore sits BEFORE that assistant item (never between call and result).
#[track_caller]
fn assert_one_result_and_markers_before_call(conv: &Conv, call_id: &str) {
    use fuigo_sampling_types::ConversationItem as C;
    let at = conv
        .iter()
        .position(|i| matches!(i, C::Assistant(a) if a.tool_calls.iter().any(|c| &*c.id == call_id)))
        .unwrap_or_else(|| panic!("no assistant item for {call_id}"));
    let results: Vec<usize> =
        conv.iter().enumerate().filter(|(_, i)| matches!(i, C::ToolResult(r) if r.tool_call_id == call_id)).map(|(n, _)| n).collect();
    assert_eq!(results, vec![at + 1], "one result for {call_id}, directly after its assistant item");
    let markers: Vec<usize> = conv.iter().enumerate().filter(|(_, i)| i.is_peer_influence_marker()).map(|(n, _)| n).collect();
    assert!(markers.iter().any(|&m| m < at), "a marker stored while the call was open sits before its assistant item: markers {markers:?}, call at {at}");
    assert!(!markers.contains(&(at + 1)), "no marker between the call and its result");
}

fn follow_up_results(r: &Rig, call_id: &str) -> usize {
    let bodies = r.server.request_bodies();
    assert!(bodies.len() >= 2, "a follow-up request was sent: {}", bodies.len());
    let input = bodies[1]["input"].as_array().cloned().unwrap_or_default();
    input.iter().filter(|i| i["type"] == "function_call_output" && i["call_id"] == call_id).count()
}

/// P29-C: the same as the success-path test, through `handle_tool_error` (tool_calls.rs, the dispatch-failure result handler:
/// it runs `persist_peer_state` before it pushes the failure result). `search_replace` on a file that does not exist fails in
/// dispatch.
#[tokio::test(flavor = "current_thread")]
async fn p29_dup_refusal_pending_when_a_tool_error_lands_leaves_one_result_per_call() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let _on = force_peer_messaging_for_test(true);
            let r = rig().await;
            *r.actor.agent.borrow_mut() = test_agent_with_tools(vec![
                fuigo_tools::registry::types::ToolConfig::for_tool::<fuigo_tools::implementations::fuigo_build::read_file::ReadFileTool>(),
                fuigo_tools::registry::types::ToolConfig::for_tool::<fuigo_tools::implementations::fuigo_build::search_replace::SearchReplaceTool>(),
            ])
            .await;
            let missing = format!("{}/p29-no-such-file.txt", r.actor.session_info.cwd);
            let args = serde_json::json!({"file_path": missing, "old_string": "a", "new_string": "b"}).to_string();
            r.server.enqueue_response(
                "/v1/responses",
                ScriptedResponse::sse(fuigo_test_support::sse::responses_api_reasoning_then_tool_call_events(
                    "thinking",
                    "call-1",
                    "search_replace",
                    &args,
                    "test",
                )),
            );
            r.server.enqueue_response("/v1/responses", ScriptedResponse::sse(responses_api_script_exact("done", "test")));
            let env = envelope("m1");
            r.actor.peer_admission.note_delivered(&env);
            let guard = r.actor.peer_admission.begin_turn(false, Some("m1"));
            let args = fuigo_peer::tools::RefusePeerMessageArgs { message_id: "m1".into(), reason: "not mine".into() };
            r.actor.refuse_peer_message(&args).expect("refused by the model");
            let result = run_parent_turn(&r.actor, peer_turn_request(&env)).await;
            drop(guard);
            assert!(result.is_ok(), "{result:?}");
            assert_eq!(follow_up_results(&r, "call-1"), 1, "exactly one tool result for call-1 in the follow-up request");
            let stored = r.actor.chat_state_handle.get_conversation().await;
            let failure = stored.iter().find_map(|i| match i {
                fuigo_sampling_types::ConversationItem::ToolResult(t) if t.tool_call_id == "call-1" => Some(t.content.to_string()),
                _ => None,
            });
            assert!(
                failure.as_deref().is_some_and(|m| m.starts_with("Tool `search_replace` failed:")),
                "the result came from handle_tool_error: {failure:?}"
            );
            assert_one_result_and_markers_before_call(&stored, "call-1");
            assert!(!fuigo_sampling_types::history_peer_carried(&stored).is_empty(), "the refusal state is stored");
        })
        .await;
}

/// P29-C: a denial made by the real permission manager (tool_calls.rs, right after `permissions.request`, which stores the
/// denial NOW, with the call still open). A peer-influenced session may not edit `CLAUDE.md`: the model's `search_replace` of it
/// is denied by policy with no prompt. One result for the call, and the `peer_denial` marker sits before its assistant item.
#[tokio::test(flavor = "current_thread")]
async fn p29_a_policy_denial_is_stored_now_and_leaves_one_result_per_call() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let _on = force_peer_messaging_for_test(true);
            let server = MockInferenceServer::start().await.expect("mock inference server");
            let (actor, _h, _c, _p) = actor_with_sampler_in(
                &server,
                Arc::new(RecordingTerminal { calls: Arc::new(AtomicUsize::new(0)) }),
                false,
                Some(false),
            )
            .await;
            let r = Rig { server, actor };
            *r.actor.agent.borrow_mut() = test_agent_with_tools(vec![
                fuigo_tools::registry::types::ToolConfig::for_tool::<fuigo_tools::implementations::fuigo_build::read_file::ReadFileTool>(),
                fuigo_tools::registry::types::ToolConfig::for_tool::<fuigo_tools::implementations::fuigo_build::search_replace::SearchReplaceTool>(),
            ])
            .await;
            let target = format!("{}/CLAUDE.md", r.actor.session_info.cwd);
            let args = serde_json::json!({"file_path": target, "old_string": "a", "new_string": "b"}).to_string();
            r.server.enqueue_response(
                "/v1/responses",
                ScriptedResponse::sse(fuigo_test_support::sse::responses_api_reasoning_then_tool_call_events(
                    "thinking",
                    "call-1",
                    "search_replace",
                    &args,
                    "test",
                )),
            );
            r.server.enqueue_response("/v1/responses", ScriptedResponse::sse(responses_api_script_exact("done", "test")));
            let env = envelope("m1");
            r.actor.peer_admission.note_delivered(&env);
            let guard = r.actor.peer_admission.begin_turn(false, Some("m1"));
            r.actor.mark_peer_influenced();
            let result = run_parent_turn(&r.actor, peer_turn_request(&env)).await;
            drop(guard);
            assert!(result.is_ok(), "{result:?}");
            assert_eq!(follow_up_results(&r, "call-1"), 1, "exactly one tool result for call-1 in the follow-up request");
            let stored = r.actor.chat_state_handle.get_conversation().await;
            assert_eq!(fuigo_sampling_types::history_peer_denials(&stored).len(), 1, "the denial is stored");
            assert_one_result_and_markers_before_call(&stored, "call-1");
        })
        .await;
}
