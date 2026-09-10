//! Real ACP/request assembly proof, fake provider, isolated session state.
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{AutoApproveClient, connect_and_auth, new_session, prompt_turn, run_agent_test};

#[test]
fn compact_presentation_keeps_instructions_and_native_schemas() {
    // One test per binary; configure before mock or agent threads exist.
    unsafe { std::env::set_var("FUIGO_TOOL_PRESENTATION", "compact"); }
    run_agent_test(|cwd, mock| async move {
        std::fs::write(cwd.join("AGENTS.md"), "Project convention: KEEP_COMPACT_INSTRUCTION_719.\n").unwrap();
        let (conn, _) = connect_and_auth(AutoApproveClient, "compact-presentation-fixture").await;
        let session = new_session(&conn, &cwd).await;
        prompt_turn(&conn, &session, "Reply DONE without using tools.").await;
        let requests: Vec<serde_json::Value> = mock.requests().iter()
            .filter(|r| r.path == "/v1/chat/completions")
            .filter_map(|r| r.body.as_ref().and_then(|b| serde_json::from_str(&b.to_string()).ok()))
            .collect();
        let request = requests.iter().find(|r| r["tools"].as_array().is_some_and(|tools|
            tools.iter().any(|t| t["function"]["name"] == "read_file"))).expect("real main tool request");
        assert!(request["messages"].to_string().contains("KEEP_COMPACT_INSTRUCTION_719"), "AGENTS instruction absent");
        let tools = request["tools"].as_array().unwrap();
        for required in ["read_file", "search_replace", "run_terminal_command", "search_tool", "use_tool"] {
            assert!(tools.iter().any(|t| t["function"]["name"] == required), "lost tool {required}");
        }
        let catalog: Vec<serde_json::Value> = serde_json::from_str(include_str!("../src/session/compact_tool_descriptions.json")).unwrap();
        let mut applied = 0;
        for entry in catalog {
            if let Some(tool) = tools.iter().find(|t| t["function"]["name"] == entry["name"]) {
                if tool["function"]["description"] == entry["compact"] {
                    assert_eq!(tool["function"]["parameters"], entry["parameters"]);
                    applied += 1;
                }
            }
        }
        assert!(applied >= 5, "compact presentation did not activate on built-ins: {applied}");
    });
}
