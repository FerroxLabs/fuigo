//! OpenAI models without a configured `agent_type` run on the Codex harness (`apply_patch`, codex file tools) end to end over ACP.
//! Covers `session/new` with a stock client profile, the zero-turn model switch `fuigo -p -m` uses, a mid-session switch that must not fail,
//! a custom client profile that still wins, and non-interactive sessions that never advertise `ask_user_question`,
//! `todo_write` or the injected plan-mode tools. With no MCP server configured no session advertises
//! `search_tool`/`use_tool`; a session that registers in-process SDK MCP servers does.
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

/// The tools array of the last main-turn inference request this session sent.
fn last_tools(requests: &[LogEntry], session: &acp::SessionId) -> Vec<Value> {
    requests
        .iter()
        .filter(|r| r.path == "/v1/chat/completions")
        .filter(|r| r.header("x-fuigo-session-id") == Some(&*session.0))
        .filter_map(|r| r.body.as_ref().and_then(|body| body["tools"].as_array()))
        .rfind(|tools| tools.iter().any(|t| t["function"]["name"] == "run_terminal_command"))
        .unwrap_or_else(|| panic!("no main-turn request with tools for {}", session.0))
        .clone()
}

/// Tool names of the last main-turn inference request this session sent.
fn last_tool_names(requests: &[LogEntry], session: &acp::SessionId) -> Vec<String> {
    last_tools(requests, session)
        .iter()
        .filter_map(|t| t["function"]["name"].as_str().map(str::to_owned))
        .collect()
}

/// Description of `name` in the last main-turn request this session sent.
fn last_tool_description(requests: &[LogEntry], session: &acp::SessionId, name: &str) -> String {
    last_tools(requests, session)
        .iter()
        .find(|t| t["function"]["name"] == name)
        .and_then(|t| t["function"]["description"].as_str().map(str::to_owned))
        .unwrap_or_else(|| panic!("{name} missing from the last request of {}", session.0))
}

fn assert_has(tools: &[String], names: &[&str], label: &str) {
    for name in names {
        assert!(tools.iter().any(|t| t == name), "{label}: must advertise {name}; got {tools:?}");
    }
}

fn assert_lacks(tools: &[String], names: &[&str], label: &str) {
    for name in names {
        assert!(!tools.iter().any(|t| t == name), "{label}: must not advertise {name}; got {tools:?}");
    }
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
        let mid_before_tools = last_tools(&mock.requests(), &mid);
        let mid_before: Vec<String> =
            mid_before_tools.iter().filter_map(|t| t["function"]["name"].as_str().map(str::to_owned)).collect();
        switch_model(&conn, &mid, OPENAI_MODEL).await;
        prompt_turn(&conn, &mid, "Reply DONE without using tools.").await;

        // A custom client profile is an explicit choice and wins over the inferred harness.
        let custom_profile = json!({ "name": "custom-acp-profile", "description": "custom profile" });
        let custom = open_session(&conn, &cwd, OPENAI_MODEL, false, Some(custom_profile)).await;
        prompt_turn(&conn, &custom, "Reply DONE without using tools.").await;

        // In-process SDK MCP servers registered at session/new count as configured MCP.
        let with_mcp = tokio::time::timeout(
            RPC_TIMEOUT,
            conn.new_session(acp::NewSessionRequest::new(cwd.to_path_buf()).meta(
                json!({
                    "modelId": OPENAI_MODEL,
                    "startupHints": { "nonInteractive": true, "skipGitStatus": true, "skipProjectLayout": true },
                    "fuigo/mcp/servers": [{ "name": "sdk-tools", "serverId": "sdk-1" }],
                })
                .as_object()
                .cloned(),
            )),
        )
        .await
        .expect("session/new (mcp) timed out")
        .expect("session/new (mcp) failed")
        .session_id;
        prompt_turn(&conn, &with_mcp, "Reply DONE without using tools.").await;

        let requests = mock.requests();
        let fresh_tools = last_tool_names(&requests, &fresh);
        assert_codex(&fresh_tools, "session/new");
        assert!(fresh_tools.iter().any(|t| t == "ask_user_question"), "interactive session must keep ask_user_question; got {fresh_tools:?}");
        let switched_tools = last_tool_names(&requests, &switched);
        assert_codex(&switched_tools, "zero-turn switch");
        assert!(!switched_tools.iter().any(|t| t == "ask_user_question"), "non-interactive session must not advertise ask_user_question; got {switched_tools:?}");
        assert_eq!(
            fresh_tools.iter().any(|t| t == "spawn_subagent"),
            mid_before.iter().any(|t| t == "spawn_subagent"),
            "codex harness must match the stock harness on spawn_subagent; codex {fresh_tools:?} stock {mid_before:?}"
        );
        assert_stock(&mid_before, "stock model");
        assert!(mid_before.iter().any(|t| t == "ask_user_question"), "interactive stock session must keep ask_user_question; got {mid_before:?}");
        assert_stock(&last_tool_names(&requests, &mid), "mid-session switch");
        assert_stock(&last_tool_names(&requests, &custom), "custom profile");

        // Headless: no todo list is rendered and no plan-mode keybind exists, so neither is advertised.
        assert_lacks(&switched_tools, &["todo_write", "enter_plan_mode", "exit_plan_mode"], "non-interactive codex session");
        // Interactive default profile keeps them; the curated plan profile keeps the plan-mode tools.
        assert_has(&mid_before, &["todo_write", "enter_plan_mode", "exit_plan_mode"], "interactive stock session");
        assert_has(&fresh_tools, &["enter_plan_mode", "exit_plan_mode"], "interactive plan profile");
        // No MCP server is configured in this harness: the MCP meta-tools are dead bytes and stay out.
        for (label, tools) in [("headless", &switched_tools), ("interactive", &mid_before), ("plan profile", &fresh_tools)] {
            assert_lacks(tools, &["search_tool", "use_tool"], label);
        }
        // Registering SDK MCP servers at session/new brings them back.
        let mcp_tools = last_tool_names(&requests, &with_mcp);
        assert_codex(&mcp_tools, "sdk mcp session");
        assert_has(&mcp_tools, &["search_tool", "use_tool"], "session with fuigo/mcp/servers");
        assert_lacks(&mcp_tools, &["todo_write"], "headless session with MCP");
        // The codex read_file reads several paths in one call and says so; the output tool waits by default.
        let read_desc = last_tool_description(&requests, &switched, "read_file");
        assert!(read_desc.contains("several paths in one call") && read_desc.contains("whole files by default"), "read_file description: {read_desc}");
        let wait_desc = last_tool_description(&requests, &switched, "get_command_or_subagent_output");
        assert!(wait_desc.contains("Omit timeout_ms to wait up to 120000 ms"), "output tool description: {wait_desc}");
        let bash_desc = last_tool_description(&requests, &switched, "run_terminal_command");
        assert!(bash_desc.contains("keeps running in the background and you get a task id"), "shell description: {bash_desc}");

        // The compact-presentation catalog must track the live read_file definition on both harnesses: the compact
        // swap matches `original` + `parameters` byte-for-byte, so a stale entry silently disables compaction.
        // Both read_file tools state the shared per-call byte cap (40 KB, ~10K tokens) in the description and the
        // `files` parameter.
        let catalog: Vec<Value> =
            serde_json::from_str(include_str!("../src/session/compact_tool_descriptions.json")).expect("valid catalog");
        for (label, tools, own_param) in [("codex", last_tools(&requests, &switched), "file_path"), ("stock", mid_before_tools, "target_file")] {
            let live = tools
                .iter()
                .find(|t| t["function"]["name"] == "read_file")
                .unwrap_or_else(|| panic!("{label}: read_file missing"));
            let entry = catalog
                .iter()
                .find(|e| e["name"] == "read_file" && e["parameters"]["properties"].get(own_param).is_some())
                .unwrap_or_else(|| panic!("catalog has no read_file entry with a {own_param} parameter"));
            assert_eq!(live["function"]["description"], entry["original"], "{label}: compact catalog read_file description is stale");
            assert_eq!(
                live["function"]["parameters"]["properties"]["files"]["description"],
                entry["parameters"]["properties"]["files"]["description"],
                "{label}: compact catalog read_file `files` parameter is stale"
            );
            for text in [&live["function"]["description"], &live["function"]["parameters"]["properties"]["files"]["description"]] {
                let text = text.as_str().unwrap_or_default();
                assert!(text.contains("about 40 KB") && !text.contains("200 KB"), "{label}: read_file must state the 40 KB per-call cap: {text}");
            }
        }
    });
}
