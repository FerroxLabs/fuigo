//! Adaptive tool presentation must keep native child spawn reachable and must
//! never advertise an undiscovered deferred schema to the parent or the child.
//! One real native child on the existing ACP/mock harness, not a perf sweep.
#[allow(dead_code)]
mod acp_harness;
#[path = "perf_harness/mod.rs"]
mod perf_harness;
#[path = "subagent_sweep_support/mod.rs"]
mod support;

use serde_json::Value;

const DEFERRED_MEDIA: [&str; 4] = ["image_gen", "image_edit", "image_to_video", "reference_to_video"];

fn tool_names(body: &Value) -> Vec<String> {
    body["tools"]
        .as_array()
        .map(|tools| tools.iter().filter_map(|t| t["function"]["name"].as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

#[test]
fn adaptive_presentation_keeps_native_child_spawn_reachable() {
    // One test per binary; set before any agent or mock threads exist.
    unsafe {
        std::env::set_var("FUIGO_TOOL_PRESENTATION", "adaptive");
        std::env::set_var("FUIGO_MAX_MODEL_CALLS", "20");
        std::env::set_var("FUIGO_SWEEP_DEADLINE_S", "60");
        std::env::set_var("FUIGO_TURN_SUMMARY", "false");
    }
    let env = support::sweep_env_init();
    let server = env
        .mock_rt
        .block_on(fuigo_test_support::MockInferenceServer::start())
        .expect("mock server");
    unsafe {
        std::env::set_var("FUIGO_CLI_CHAT_PROXY_BASE_URL", server.url());
        std::env::set_var("FUIGO_API_BASE_URL", server.url());
    }
    let outcome = support::run_burst(&server, 1, "none", env.deadline);
    assert_eq!(outcome.rows.len(), 1, "one real native child must be observed");
    assert_eq!(outcome.failures, 0, "native child did not complete under adaptive presentation");

    let bodies: Vec<Value> = server
        .requests()
        .iter()
        .filter(|r| r.path == "/v1/chat/completions")
        .filter_map(|r| r.body.as_ref().and_then(|b| serde_json::from_str(&b.to_string()).ok()))
        .collect();
    assert!(bodies.len() >= 2, "expected parent and child inference requests, saw {}", bodies.len());
    assert!(
        bodies.iter().any(|b| tool_names(b).iter().any(|n| n == "spawn_subagent")),
        "adaptive presentation hid native child spawn from the parent"
    );
    for body in &bodies {
        let offered = tool_names(body);
        assert!(
            !offered.iter().any(|n| DEFERRED_MEDIA.contains(&n.as_str())),
            "an undiscovered deferred media schema was advertised: {offered:?}"
        );
    }
}
