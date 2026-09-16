//! The ACP harness must run the agent against its own home directory, not the
//! developer's. `fuigo_dirs::home_dir()` is `std::env::home_dir()`, and the
//! session MCP merge reads `$HOME/.claude.json` and `$HOME/.cursor/mcp.json`
//! (`util::config::mcp::load_claude_json_mcp_servers` /
//! `load_cursor_mcp_servers`, both on by default in `CompatConfig`). A harness
//! that leaves `HOME` alone therefore hands every ACP fixture whatever MCP
//! servers the machine happens to have configured - which flips
//! `mcp_configured` at `spawn_session_actor`, and with it whether
//! `search_tool`/`use_tool` are advertised at all.
//!
//! This binary stands in for that workstation: it points `HOME` at a directory
//! that *does* declare MCP servers before handing over to `run_agent_test`, and
//! then asserts none of it reached the session.
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{AutoApproveClient, connect_and_auth, new_session, prompt_turn, run_agent_test};

#[test]
fn harness_isolates_home_from_the_hosts_mcp_configuration() {
    // Kept alive for the whole test: dropping it would delete the poisoned home
    // mid-run and turn a leak back into a pass for the wrong reason.
    let host_home = tempfile::TempDir::new().expect("host home");
    std::fs::write(
        host_home.path().join(".claude.json"),
        r#"{"mcpServers":{"host-home-leak":{"command":"/nonexistent/host-home-leak","args":[]}}}"#,
    )
    .expect("write .claude.json");
    std::fs::create_dir_all(host_home.path().join(".cursor")).expect("host .cursor");
    std::fs::write(
        host_home.path().join(".cursor").join("mcp.json"),
        r#"{"mcpServers":{"cursor-home-leak":{"command":"/nonexistent/cursor-home-leak","args":[]}}}"#,
    )
    .expect("write .cursor/mcp.json");
    // SAFETY: one test per binary; no agent or mock thread exists yet.
    unsafe {
        std::env::set_var("HOME", host_home.path());
        std::env::set_var("USERPROFILE", host_home.path());
    }

    run_agent_test(|cwd, mock| async move {
        let (conn, _) = connect_and_auth(AutoApproveClient, "home-isolation-fixture").await;
        let session = new_session(&conn, &cwd).await;
        prompt_turn(&conn, &session, "Reply DONE without using tools.").await;

        let requests: Vec<serde_json::Value> = mock
            .requests()
            .iter()
            .filter(|r| r.path == "/v1/chat/completions")
            .filter_map(|r| {
                r.body
                    .as_ref()
                    .and_then(|b| serde_json::from_str(&b.to_string()).ok())
            })
            .collect();
        let request = requests
            .iter()
            .find(|r| {
                r["tools"]
                    .as_array()
                    .is_some_and(|tools| tools.iter().any(|t| t["function"]["name"] == "read_file"))
            })
            .expect("real main tool request");
        let tools: Vec<&str> = request["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["function"]["name"].as_str())
            .collect();

        // Default presentation is `full` (`tool_presentation.rs`), and this session
        // declares no MCP server of its own, so `AgentBuilder` drops the MCP
        // meta-tools (`builder.rs`, pinned by `mcp_meta_tools_follow_the_configured_signal`).
        // Their presence means an `$HOME` declaration was merged into the session.
        for leaked in ["search_tool", "use_tool"] {
            assert!(
                !tools.contains(&leaked),
                "the host home directory's MCP servers reached the session: {leaked} was advertised in {tools:?}"
            );
        }
        let body = request.to_string();
        for name in ["host-home-leak", "cursor-home-leak"] {
            assert!(
                !body.contains(name),
                "a server declared only in the host home directory reached the request: {name}"
            );
        }
    });
}
