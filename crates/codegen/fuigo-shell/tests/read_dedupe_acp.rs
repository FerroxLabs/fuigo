//! A repeat `read_file` of an unchanged file whose earlier result is still in context returns a short
//! note instead of the content; after a shell command touches the workspace the content comes back.
//! One real agent over ACP; the mock model is scripted to read, read again, edit, then read once more.
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{AutoApproveClient, RPC_TIMEOUT, connect_and_auth, prompt_turn, run_agent_test};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_test_support::mock_server::LogEntry;
use fuigo_test_support::scripted::ScriptedResponse;
use fuigo_test_support::sse::chat_completions_reasoning_then_tool_call_events;
use fuigo_test_support::{InferenceEndpoint, InferenceRequestMatcher};
use serde_json::json;

async fn open_session(conn: &acp::ClientSideConnection, cwd: &std::path::Path) -> acp::SessionId {
    tokio::time::timeout(
        RPC_TIMEOUT,
        conn.new_session(
            acp::NewSessionRequest::new(cwd.to_path_buf()).meta(
                json!({
                    "modelId": "test-model",
                    "yoloMode": true,
                    "startupHints": { "nonInteractive": false, "skipGitStatus": true, "skipProjectLayout": true },
                })
                .as_object()
                .cloned(),
            ),
        ),
    )
    .await
    .expect("session/new timed out")
    .expect("session/new failed")
    .session_id
}

/// Last tool-result content the session sent back for `call_id`.
fn tool_output(requests: &[LogEntry], session: &acp::SessionId, call_id: &str) -> String {
    requests
        .iter()
        .filter(|r| r.path == "/v1/chat/completions")
        .filter(|r| r.header("x-fuigo-session-id") == Some(&*session.0))
        .filter_map(|r| r.body.as_ref().and_then(|b| b["messages"].as_array()).cloned())
        .flatten()
        .filter(|m| m["role"] == "tool" && m["tool_call_id"] == call_id)
        .filter_map(|m| m["content"].as_str().map(str::to_owned))
        .last()
        .unwrap_or_else(|| panic!("no tool result for {call_id} in any request of {}", session.0))
}

fn read_call(id: &str) -> ScriptedResponse {
    ScriptedResponse::sse(chat_completions_reasoning_then_tool_call_events(
        "",
        id,
        "read_file",
        r#"{"target_file":"a.txt"}"#,
        "test-model",
    ))
}

#[test]
fn repeat_read_of_unchanged_file_is_deduped_until_the_workspace_changes() {
    run_agent_test(|cwd, mock| async move {
        std::fs::write(cwd.join("a.txt"), "alpha\nbeta\n").unwrap();
        let fg = || InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions);
        let mut first = mock.expect_response("read-1", fg(), read_call("call_1"));
        let mut second = mock.expect_response("read-2", fg(), read_call("call_2"));
        let mut edit = mock.expect_response(
            "edit",
            fg(),
            ScriptedResponse::sse(chat_completions_reasoning_then_tool_call_events(
                "",
                "call_3",
                "run_terminal_command",
                r#"{"command":"printf 'gamma\n' >> a.txt","description":"append a line"}"#,
                "test-model",
            )),
        );
        let mut third = mock.expect_response("read-3", fg(), read_call("call_4"));

        let (conn, _) = connect_and_auth(AutoApproveClient, "read-dedupe").await;
        let session = open_session(&conn, &cwd).await;
        prompt_turn(&conn, &session, "Read a.txt twice, append to it, then read it again.").await;
        first.wait_satisfied().await;
        second.wait_satisfied().await;
        edit.wait_satisfied().await;
        third.wait_satisfied().await;

        let requests = mock.requests();
        let initial = tool_output(&requests, &session, "call_1");
        assert!(initial.contains("alpha") && initial.contains("beta"), "first read returns content: {initial}");
        let repeat = tool_output(&requests, &session, "call_2");
        assert!(
            repeat.contains("a.txt unchanged since your earlier read (2 lines, at turn 1); content omitted"),
            "repeat read of an unchanged file must return the note: {repeat}"
        );
        assert!(!repeat.contains("alpha"), "the note must not repeat the content: {repeat}");
        let after_edit = tool_output(&requests, &session, "call_4");
        assert!(
            after_edit.contains("gamma") && after_edit.contains("alpha") && !after_edit.contains("content omitted"),
            "a read after a shell command returns the content again: {after_edit}"
        );
    });
}
