//! OpenAI models without a configured `agent_type` run on the Codex harness (`apply_patch`, codex file tools) end to end over ACP.
//! Covers `session/new` with a stock client profile, the zero-turn model switch `fuigo -p -m` uses, a mid-session switch that must not fail,
//! a custom client profile that still wins, and non-interactive sessions that never advertise `ask_user_question`.
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{AutoApproveClient, RPC_TIMEOUT, connect_and_auth, prompt_turn, run_agent_test};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_test_support::MockModelEntry;
use fuigo_test_support::mock_server::LogEntry;
use serde_json::{Value, json};

const OPENAI_MODEL: &str = "gpt-5.6-acp-test";
const STOCK_MODEL: &str = "test-model";

async fn open_session(
    conn: &acp::ClientSideConnection,
    cwd: &std::path::Path,
    model: &str,
    non_interactive: bool,
    agent_profile: Option<Value>,
) -> acp::SessionId {
    let mut meta = json!({
        "modelId": model,
        "startupHints": {
            "nonInteractive": non_interactive,
            "skipGitStatus": true,
            "skipProjectLayout": true,
        },
    });
    if let Some(profile) = agent_profile {
        meta["agentProfile"] = profile;
    }
    tokio::time::timeout(
        RPC_TIMEOUT,
        conn.new_session(acp::NewSessionRequest::new(cwd.to_path_buf()).meta(meta.as_object().cloned())),
    )
    .await
    .expect("session/new timed out")
    .expect("session/new failed")
    .session_id
}

async fn switch_model(conn: &acp::ClientSideConnection, session: &acp::SessionId, model: &str) {
    tokio::time::timeout(
        RPC_TIMEOUT,
        conn.set_session_model(acp::SetSessionModelRequest::new(session.clone(), acp::ModelId::new(model))),
    )
    .await
    .expect("session/set_model timed out")
    .unwrap_or_else(|e| panic!("switching {} to {model} failed: {e}", session.0));
}

/// Tool names of the last main-turn inference request this session sent.
fn last_tool_names(requests: &[LogEntry], session: &acp::SessionId) -> Vec<String> {
    requests
        .iter()
        .filter(|r| r.path == "/v1/chat/completions")
        .filter(|r| r.header("x-fuigo-session-id") == Some(&*session.0))
        .filter_map(|r| r.body.as_ref().and_then(|body| body["tools"].as_array()))
        .filter(|tools| tools.iter().any(|t| t["function"]["name"] == "run_terminal_command"))
        .last()
        .unwrap_or_else(|| panic!("no main-turn request with tools for {}", session.0))
        .iter()
        .filter_map(|t| t["function"]["name"].as_str().map(str::to_owned))
        .collect()
}

fn assert_codex(tools: &[String], label: &str) {
    for required in ["apply_patch", "grep_files"] {
        assert!(tools.iter().any(|t| t == required), "{label}: codex harness must advertise {required}; got {tools:?}");
    }
    assert!(!tools.iter().any(|t| t == "search_replace"), "{label}: codex harness must not advertise search_replace; got {tools:?}");
}

fn assert_stock(tools: &[String], label: &str) {
    assert!(tools.iter().any(|t| t == "search_replace"), "{label}: stock harness must advertise search_replace; got {tools:?}");
    assert!(!tools.iter().any(|t| t == "apply_patch"), "{label}: stock harness must not advertise apply_patch; got {tools:?}");
}

#[test]
fn openai_models_default_to_codex_and_headless_sessions_hide_ask_user() {
    run_agent_test(|cwd, mock| async move {
        mock.set_models(vec![MockModelEntry::new(STOCK_MODEL), MockModelEntry::new(OPENAI_MODEL)]);
        let (conn, _) = connect_and_auth(AutoApproveClient, "openai-codex-harness").await;

        // session/new with the stock profile the pager derives from its flags.
        let fresh = open_session(&conn, &cwd, OPENAI_MODEL, false, Some(json!("fuigo-build-plan"))).await;
        prompt_turn(&conn, &fresh, "Reply DONE without using tools.").await;

        // `fuigo -p -m <openai model>`: open on the default model, then switch before the first turn.
        let switched = open_session(&conn, &cwd, STOCK_MODEL, true, None).await;
        switch_model(&conn, &switched, OPENAI_MODEL).await;
        prompt_turn(&conn, &switched, "Reply DONE without using tools.").await;

        // A mid-session switch to an inferred harness succeeds and keeps the running harness.
        let mid = open_session(&conn, &cwd, STOCK_MODEL, false, None).await;
        prompt_turn(&conn, &mid, "Reply DONE without using tools.").await;
        let mid_before = last_tool_names(&mock.requests(), &mid);
        switch_model(&conn, &mid, OPENAI_MODEL).await;
        prompt_turn(&conn, &mid, "Reply DONE without using tools.").await;

        // A custom client profile is an explicit choice and wins over the inferred harness.
        let custom_profile = json!({ "name": "custom-acp-profile", "description": "custom profile" });
        let custom = open_session(&conn, &cwd, OPENAI_MODEL, false, Some(custom_profile)).await;
        prompt_turn(&conn, &custom, "Reply DONE without using tools.").await;

        let requests = mock.requests();
        let fresh_tools = last_tool_names(&requests, &fresh);
        assert_codex(&fresh_tools, "session/new");
        assert!(fresh_tools.iter().any(|t| t == "ask_user_question"), "interactive session must keep ask_user_question; got {fresh_tools:?}");
        let switched_tools = last_tool_names(&requests, &switched);
        assert_codex(&switched_tools, "zero-turn switch");
        assert!(!switched_tools.iter().any(|t| t == "ask_user_question"), "non-interactive session must not advertise ask_user_question; got {switched_tools:?}");
        assert_stock(&mid_before, "stock model");
        assert!(mid_before.iter().any(|t| t == "ask_user_question"), "interactive stock session must keep ask_user_question; got {mid_before:?}");
        assert_stock(&last_tool_names(&requests, &mid), "mid-session switch");
        assert_stock(&last_tool_names(&requests, &custom), "custom profile");
    });
}
