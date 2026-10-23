// Per-test-case module for the `leader_pty_e2e` integration test crate.
#[allow(unused_imports)]
use super::common::*;
use fuigo_pager_pty_harness::{AgentTurnExpectation, ScriptedResponse, SseEvent};
use serde_json::json;

const EDIT_DONE: &str = "P30_D1_EDIT_DONE";

/// One model turn that calls `name` with `arguments`, for both inference endpoints the agent may use.
fn expect_tool_turn(
    content: &ContentController,
    call_id: &str,
    name: &str,
    arguments: &str,
) -> AgentTurnExpectation {
    let responses = vec![
        SseEvent::data(
            json!({"type": "response.created", "sequence_number": 0, "response": {"id": "resp_d1", "object": "response",
                "created_at": 1234567890, "model": "test-model", "status": "in_progress", "output": []}})
            .to_string(),
        ),
        SseEvent::data(
            json!({"type": "response.completed", "sequence_number": 1, "response": {"id": "resp_d1", "object": "response",
                "created_at": 1234567890, "model": "test-model", "status": "completed",
                "output": [{"type": "function_call", "call_id": call_id, "name": name, "arguments": arguments}],
                "usage": {"input_tokens": 10, "output_tokens": 20, "total_tokens": 30,
                    "input_tokens_details": {"cached_tokens": 0}, "output_tokens_details": {"reasoning_tokens": 0}}}})
            .to_string(),
        ),
        SseEvent::data("[DONE]".to_string()),
    ];
    let chat = vec![
        SseEvent::data(
            json!({"id": "chatcmpl-d1", "object": "chat.completion.chunk", "created": 1234567890, "model": "test-model",
                "choices": [{"index": 0, "delta": {"role": "assistant", "content": null, "tool_calls": [{"index": 0,
                    "id": call_id, "type": "function", "function": {"name": name, "arguments": arguments}}]},
                    "finish_reason": null}]})
            .to_string(),
        ),
        SseEvent::data(
            json!({"id": "chatcmpl-d1", "object": "chat.completion.chunk", "created": 1234567890, "model": "test-model",
                "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}})
            .to_string(),
        ),
        SseEvent::data("[DONE]".to_string()),
    ];
    content.expect_agent_turn_with_responses(
        format!("tool turn {call_id}"),
        ScriptedResponse::sse(responses),
        ScriptedResponse::sse(chat),
    )
}

/// 1.0.30 (Windows check D1): a window that opened the owner's shared session and switched itself to Always-Approve
/// must not approve the OWNER's tool calls. The owner's edit still asks in the owner's window, the non-owner window gets
/// no prompt, and nothing changes until the owner answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "PTY e2e; run with cargo test -p fuigo-pager --test leader_pty_e2e -- --ignored --test-threads=1"]
async fn leader_non_owner_always_approve_cannot_approve_the_owners_tool_call() {
    let cluster = LeaderCluster::start(DEFAULT_ROWS, DEFAULT_COLS)
        .await
        .expect("start cluster");
    cluster
        .content()
        .set_response(format!("{} first turn payload.", turn_sentinel(1)));
    let fixture = cluster.content().home().join("p30_d1_needs_prompt.txt");
    std::fs::write(&fixture, "old line\n").expect("write fixture");
    let fixture_abs = dunce::canonicalize(&fixture).unwrap_or(fixture.clone());

    let mut a = cluster.spawn_leader(&[]).expect("spawn pager A");
    a.wait_for_text(WELCOME_SCREEN_SENTINEL, LEADER_TIMEOUT)
        .expect("A welcome");
    a.inject_keys(format!("{PROMPT}\r").as_bytes())
        .expect("A submit turn 1");
    a.wait_for_text(&turn_sentinel(1), STREAM_TIMEOUT)
        .expect("A turn 1");

    // C opens the owner's session (non-owner) and cycles Shift+Tab to Always-Approve on its side.
    let mut c = cluster.attach(&[]).expect("spawn pager C");
    c.wait_for_text(&turn_sentinel(1), LEADER_TIMEOUT)
        .expect("C replayed the owner's transcript");
    c.update(Duration::from_secs(2));
    for _ in 0..3 {
        c.inject_keys(b"\x1b[Z").expect("C BackTab");
        c.update(Duration::from_secs(2));
    }

    // The owner's turn edits a file, which needs permission.
    let _edit_turn = expect_tool_turn(
        cluster.content(),
        "call_p30_d1_edit",
        "search_replace",
        &json!({"file_path": fixture_abs.to_string_lossy(), "old_string": "old line", "new_string": "new line"}).to_string(),
    );
    cluster.content().set_response(EDIT_DONE);
    a.inject_keys(b"edit the fixture\r")
        .expect("A submits the edit");
    a.wait_for_text("No, reject", Duration::from_secs(90))
        .unwrap_or_else(|e| {
            panic!(
                "the owner must be asked ({e})\nA screen:\n{}",
                a.screen_contents()
            )
        });
    c.update(Duration::from_secs(3));
    a.update(Duration::from_millis(500));
    assert_eq!(
        std::fs::read_to_string(&fixture).expect("read fixture"),
        "old line\n",
        "the non-owner's always-approve must not approve the owner's edit\nC screen:\n{}",
        c.screen_contents()
    );
    assert!(
        a.contains_text("No, reject"),
        "the owner's prompt is still open\nA screen:\n{}",
        a.screen_contents()
    );
    assert!(
        !c.contains_text("No, reject"),
        "the non-owner gets no permission prompt\nC screen:\n{}",
        c.screen_contents()
    );

    // The owner approves once: the edit lands.
    a.inject_keys(b"\r").expect("A approves once");
    a.wait_for_text(EDIT_DONE, STREAM_TIMEOUT)
        .expect("turn settles after the owner's approval");
    assert_eq!(
        std::fs::read_to_string(&fixture).expect("read fixture"),
        "new line\n"
    );
    c.quit().expect("quit C");
    a.quit().expect("quit A");
}
