//! Cache-aligned side calls must replay the exact tool list the main turn last sent.
//! Adaptive presentation hides undiscovered media schemas from the main turn.
//! A side call that rebuilt the unprojected list re-added them and missed the prompt cache.
//! Full and compact presentation are checked on the same real ACP path.
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{
    AutoApproveClient, RPC_TIMEOUT, connect_client, ext_method, prompt_turn, run_agent_test,
    spawn_agent_local_with_config,
};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_test_support::{MockInferenceServer, ScriptedResponse, SseEvent};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

const DEFERRED_MEDIA: [&str; 4] = ["image_gen", "image_edit", "image_to_video", "reference_to_video"];

fn reply_tool(name: &str, args: Value) -> ScriptedResponse {
    ScriptedResponse::sse(vec![
        SseEvent::data(
            json!({
                "id": "side-call-alignment-fixture", "object": "chat.completion.chunk", "created": 0, "model": "test-model",
                "choices": [{"index": 0, "delta": {"role": "assistant", "tool_calls": [{
                    "index": 0, "id": "alignment-call-0", "type": "function",
                    "function": {"name": name, "arguments": args.to_string()}
                }]}, "finish_reason": "tool_calls"}]
            })
            .to_string(),
        ),
        SseEvent::data("[DONE]"),
    ])
}

fn tool_names(body: &Value) -> Vec<String> {
    body["tools"]
        .as_array()
        .map(|tools| {
            tools
                .iter()
                .filter_map(|t| t["function"]["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

async fn interactive_session(conn: &acp::ClientSideConnection, cwd: &std::path::Path) -> acp::SessionId {
    tokio::time::timeout(
        RPC_TIMEOUT,
        conn.new_session(
            acp::NewSessionRequest::new(cwd.to_path_buf()).meta(
                json!({
                    "modelId": "test-model",
                    "startupHints": {"nonInteractive": false, "skipGitStatus": true, "skipProjectLayout": true},
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

struct Captured {
    req_id: String,
    main: bool,
    body: Value,
}

/// Chat Completions requests for `session` in arrival order. Only main-turn requests carry `x-fuigo-turn-idx`.
fn captured(mock: &MockInferenceServer, session: &acp::SessionId) -> Vec<Captured> {
    mock.requests()
        .into_iter()
        .filter(|r| r.path == "/v1/chat/completions" && r.header("x-fuigo-session-id") == Some(&*session.0))
        .filter_map(|r| {
            Some(Captured {
                req_id: r.header("x-fuigo-req-id").unwrap_or_default().to_owned(),
                main: r.header("x-fuigo-turn-idx").is_some(),
                body: r.body.clone()?,
            })
        })
        .collect()
}

/// Waits for the first side call labelled `prefix` at or after index `from`.
/// Returns its index, its body, and the body of the last main-turn request sent before it.
async fn side_call_after(
    mock: &MockInferenceServer,
    session: &acp::SessionId,
    prefix: &str,
    from: usize,
) -> (usize, Value, Value) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let requests = captured(mock, session);
        if let Some(index) = (from..requests.len()).find(|&i| requests[i].req_id.starts_with(prefix)) {
            let main = requests[..index]
                .iter()
                .rev()
                .find(|r| r.main)
                .unwrap_or_else(|| panic!("{prefix}: no main-turn request precedes the side call"));
            return (index, requests[index].body.clone(), main.body.clone());
        }
        assert!(
            Instant::now() < deadline,
            "no {prefix} request arrived: {:?}",
            requests.iter().map(|r| r.req_id.clone()).collect::<Vec<_>>()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn assert_same_tools(side: &Value, main: &Value, what: &str) {
    let main_tools = main["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("{what}: main turn sent no tools"));
    assert!(!main_tools.is_empty(), "{what}: main turn sent an empty tool list");
    assert_eq!(
        serde_json::to_string(&side["tools"]).unwrap(),
        serde_json::to_string(&main["tools"]).unwrap(),
        "{what}: side-call tools differ from the main turn's last request\n side: {:?}\n main: {:?}",
        tool_names(side),
        tool_names(main)
    );
}

#[test]
fn cache_aligned_side_calls_replay_the_main_turn_tool_list() {
    run_agent_test(|cwd, mock| async move {
        // SAFETY: the only other live threads are the mock's HTTP workers, which never read env.
        unsafe {
            std::env::set_var("FUIGO_TURN_SUMMARY", "true");
            std::env::set_var("FUIGO_TITLE_REFRESH", "false");
        }
        let mut config = fuigo_shell::agent::config::Config::default();
        config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
        let (conn, _) = connect_client(
            AutoApproveClient,
            "side-call-tool-alignment",
            spawn_agent_local_with_config(config),
        )
        .await;

        for mode in ["full", "compact", "adaptive"] {
            // The mode is read per request, so one agent covers every mode with a fresh session each.
            // SAFETY: as above.
            unsafe { std::env::set_var("FUIGO_TOOL_PRESENTATION", mode) };
            let session = interactive_session(&conn, &cwd).await;
            prompt_turn(&conn, &session, "Reply DONE without using tools.").await;
            let (index, summary, main) = side_call_after(&mock, &session, "fuigo-turn-summary-", 0).await;
            assert_same_tools(&summary, &main, &format!("{mode} turn summary"));
            let offered = tool_names(&main);
            if mode == "adaptive" {
                assert!(
                    !offered.iter().any(|n| DEFERRED_MEDIA.contains(&n.as_str())),
                    "adaptive main turn advertised an undiscovered media schema: {offered:?}"
                );
            } else {
                assert!(
                    offered.iter().any(|n| n == "image_gen"),
                    "{mode} presentation must keep media schemas advertised: {offered:?}"
                );
            }
            ext_method(
                &conn,
                "fuigo/btw",
                json!({"sessionId": session.to_string(), "question": "What did you just do?"}),
            )
            .await;
            let (_, btw, main) = side_call_after(&mock, &session, "fuigo-btw-", index + 1).await;
            assert_same_tools(&btw, &main, &format!("{mode} /btw"));
        }

        // Still adaptive: after a scope=native reveal the next main request advertises the schema, and side calls follow it.
        let session = interactive_session(&conn, &cwd).await;
        mock.enqueue_response(
            "/v1/chat/completions",
            reply_tool("search_tool", json!({"query": "image_gen", "scope": "native"})),
        );
        prompt_turn(&conn, &session, "Discover the image tool without executing it, then finish.").await;
        let (index, summary, main) = side_call_after(&mock, &session, "fuigo-turn-summary-", 0).await;
        assert!(
            tool_names(&main).iter().any(|n| n == "image_gen"),
            "reveal did not reach the next main request: {:?}",
            tool_names(&main)
        );
        assert_same_tools(&summary, &main, "adaptive turn summary after native reveal");
        ext_method(&conn, "fuigo/recap", json!({"sessionId": session.to_string()})).await;
        let (index, recap, main) = side_call_after(&mock, &session, "fuigo-recap-", index + 1).await;
        assert_same_tools(&recap, &main, "adaptive recap after native reveal");

        prompt_turn(
            &conn,
            &session,
            &format!("Continuity fixture: {}", "completed observation; ".repeat(600)),
        )
        .await;
        ext_method(
            &conn,
            "fuigo/compact_conversation",
            json!({
                "session_id": session.to_string(),
                "user_context": "Preserve the user's instructions; summarize completed observations.",
            }),
        )
        .await;
        let (_, compaction, main) = side_call_after(&mock, &session, "fuigo-compact-", index + 1).await;
        assert_same_tools(&compaction, &main, "adaptive compaction");
    });
}
