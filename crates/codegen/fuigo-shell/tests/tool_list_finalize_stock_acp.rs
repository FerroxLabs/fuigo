//! Non-Responses backends keep the fail-closed finalize shape: the final-answer slot advertises no action tool at all,
//! and no `tool_choice` rides a request without `tools`, so a model or proxy that ignores `tool_choice` cannot act
//! there (release gate: scripts/memory-bench/native_smoke.py drives a scripted chat-completions model that does exactly
//! that). The constant-tool-list contract for the OpenAI Responses profile lives in tool_list_stability_acp.rs.
//! One test per binary: the model-call budget is a process-wide setting.
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{AutoApproveClient, RPC_TIMEOUT, connect_client, run_agent_test, spawn_agent_local_with_config};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_test_support::mock_server::LogEntry;
use fuigo_test_support::scripted::ScriptedResponse;
use fuigo_test_support::sse::chat_completions_reasoning_then_tool_call_events;
use fuigo_test_support::{InferenceEndpoint, InferenceRequestMatcher};
use serde_json::{Value, json};

const STOCK_MODEL: &str = "test-model";

fn main_turn_requests<'a>(requests: &'a [LogEntry], path: &str, session: &str) -> Vec<&'a LogEntry> {
    requests
        .iter()
        .filter(|r| r.path == path)
        .filter(|r| r.header("x-fuigo-session-id") == Some(session))
        .filter(|r| r.header("x-fuigo-turn-idx").is_some())
        .collect()
}

fn tool_names(body: &Value) -> Vec<String> {
    body["tools"]
        .as_array()
        .map(|tools| tools.iter().filter_map(|t| t["function"]["name"].as_str().map(str::to_owned)).collect())
        .unwrap_or_default()
}

async fn open_session(conn: &acp::ClientSideConnection, cwd: &std::path::Path, model: &str) -> acp::SessionId {
    tokio::time::timeout(
        RPC_TIMEOUT,
        conn.new_session(acp::NewSessionRequest::new(cwd.to_path_buf()).meta(json!({ "modelId": model }).as_object().cloned())),
    )
    .await
    .expect("session/new timed out")
    .expect("session/new failed")
    .session_id
}

async fn prompt_until_finalize(conn: &acp::ClientSideConnection, session: &acp::SessionId) {
    // A capacity-forced finalize ends in a partial execution receipt by design (bounded capacity), which the
    // prompt reports as an error; the request log, not the prompt result, is what this test is about.
    let result = tokio::time::timeout(
        RPC_TIMEOUT,
        conn.prompt(acp::PromptRequest::new(
            session.clone(),
            vec![acp::ContentBlock::Text(acp::TextContent::new("Read notes.txt twice, then summarize it.".to_owned()))],
        )),
    )
    .await
    .expect("prompt timed out");
    if let Err(e) = &result {
        assert!(e.to_string().contains("execution_id"), "unexpected prompt error: {e}");
    }
}

fn agent_config() -> fuigo_shell::agent::config::Config {
    let mut config = fuigo_shell::agent::config::Config::default();
    config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
    config
}

#[test]
fn stock_backend_finalize_advertises_no_action_tool() {
    unsafe { std::env::set_var("FUIGO_MAX_MODEL_CALLS", "3") };
    run_agent_test(|cwd, mock| async move {
        std::fs::write(cwd.join("notes.txt"), "hello\n").expect("fixture file");
        let matcher = InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions);
        let mut expectations = Vec::new();
        for (n, call_id) in ["call_1", "call_2"].iter().enumerate() {
            expectations.push(mock.expect_response(
                format!("tool-round-{n}"),
                matcher,
                ScriptedResponse::sse(chat_completions_reasoning_then_tool_call_events(
                    "reading",
                    call_id,
                    "read_file",
                    r#"{"target_file":"notes.txt"}"#,
                    STOCK_MODEL,
                )),
            ));
        }
        let (conn, _) = connect_client(AutoApproveClient, "tool-list-stability-stock", spawn_agent_local_with_config(agent_config())).await;
        let session = open_session(&conn, &cwd, STOCK_MODEL).await;
        prompt_until_finalize(&conn, &session).await;
        for expectation in &expectations {
            expectation.assert_satisfied();
        }

        let requests = mock.requests();
        let main = main_turn_requests(&requests, "/v1/chat/completions", &session.0);
        assert_eq!(main.len(), 3, "two tool rounds and one finalize request expected: {}", mock.request_log_summary());
        let bodies: Vec<&Value> = main.iter().map(|r| r.body.as_ref().expect("json body")).collect();
        let names = tool_names(bodies[0]);
        assert!(names.iter().any(|n| n == "read_file"), "tool rounds must advertise read_file: {names:?}");
        assert_eq!(tool_names(bodies[1]), names, "the second tool round keeps the same tools");
        // The final-answer slot offers nothing to call, and no `tool_choice` rides a request without `tools`
        // (chat-completions providers reject that pairing).
        assert!(tool_names(bodies[2]).is_empty(), "finalize request must advertise no action tool: {}", bodies[2]["tools"]);
        assert!(bodies[2].get("tool_choice").is_none_or(Value::is_null), "finalize request: {}", bodies[2]["tool_choice"]);
    });
}
