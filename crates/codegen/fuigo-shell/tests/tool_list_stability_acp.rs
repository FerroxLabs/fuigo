//! The advertised tool list is constant for a session: every main-turn request carries the byte-identical `tools`
//! array, including the finalize request, which closes the final-answer slot with `tool_choice: "none"` instead of
//! dropping the definitions (OpenAI prompt caching: keep `tools` constant, steer with `tool_choice`).
//! One real agent over ACP; the mock model keeps calling a tool until the process model-call budget forces finalize.
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{AutoApproveClient, RPC_TIMEOUT, connect_client, new_session, run_agent_test, spawn_agent_local_with_config};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_test_support::{InferenceEndpoint, InferenceRequestMatcher};
use fuigo_test_support::mock_server::LogEntry;
use fuigo_test_support::scripted::ScriptedResponse;
use fuigo_test_support::sse::chat_completions_reasoning_then_tool_call_events;
use serde_json::{Value, json};

const MODEL: &str = "test-model";

fn main_turn_requests<'a>(requests: &'a [LogEntry], session: &str) -> Vec<&'a LogEntry> {
    requests
        .iter()
        .filter(|r| r.path == "/v1/chat/completions")
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

#[test]
fn tool_list_is_identical_on_every_request_including_finalize() {
    // Three model calls per execution: two tool rounds, then the third call is the finalize slot.
    // One test in this binary; set before the helper creates any worker threads.
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
                    MODEL,
                )),
            ));
        }
        // The finalize request gets the fallback echo (a text reply), which ends the turn.
        let mut config = fuigo_shell::agent::config::Config::default();
        config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
        let (conn, _) = connect_client(AutoApproveClient, "tool-list-stability", spawn_agent_local_with_config(config)).await;
        let session = new_session(&conn, &cwd).await;
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
        for expectation in &expectations {
            expectation.assert_satisfied();
        }

        let requests = mock.requests();
        let main = main_turn_requests(&requests, &session.0);
        assert_eq!(main.len(), 3, "two tool rounds and one finalize request expected: {}", mock.request_log_summary());
        let bodies: Vec<&Value> = main.iter().map(|r| r.body.as_ref().expect("json body")).collect();
        let first_tools = serde_json::to_string(&bodies[0]["tools"]).unwrap();
        let names = tool_names(bodies[0]);
        assert!(names.iter().any(|n| n == "read_file"), "main-turn tools must include read_file: {names:?}");
        for (i, body) in bodies.iter().enumerate() {
            assert_eq!(
                serde_json::to_string(&body["tools"]).unwrap(),
                first_tools,
                "request {i} changed the serialized tools array (names: {:?} vs {names:?})",
                tool_names(body)
            );
        }
        // Tool rounds leave tool_choice open; the finalize request closes it with a real `none`.
        assert!(bodies[0].get("tool_choice").is_none_or(|v| v.is_null() || v == "auto"), "{}", bodies[0]["tool_choice"]);
        assert_eq!(bodies[2]["tool_choice"], json!("none"), "finalize request: {}", bodies[2]);
        // The finalize request still carried the full tool list, not an empty one.
        assert_eq!(tool_names(bodies[2]), names);
    });
}
