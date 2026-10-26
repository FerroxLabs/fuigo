//! `FUIGO_MANAGED_HOOKS_ONLY` at the PROCESS boundary: an embedding app turns off every non-managed hook for one run.
//! A user hook (`$FUIGO_HOME/hooks`) writes a marker file; with the switch on the marker is never written, without it
//! the marker is written. The model is the mock server, so this runs offline in the test's private home.

use fuigo_test_support::{
    InferenceEndpoint, InferenceExpectation, InferenceRequestMatcher, MockInferenceServer,
    ScriptedResponse, TestSandbox, git_workdir, run_headless_in_sandbox_borrowed_with_env, sse,
};

fn pager_binary() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("PAGER_BINARY") {
        return std::path::absolute(&p)
            .unwrap_or_else(|e| panic!("failed to absolutize PAGER_BINARY {p}: {e}"));
    }
    option_env!("CARGO_BIN_EXE_fuigo-pager")
        .map(std::path::PathBuf::from)
        .expect("PAGER_BINARY is unset and this build is not `cargo test`")
}

/// One plain text reply on both wire backends (the resolved model picks one; the other goes unclaimed).
fn script_text_reply(server: &MockInferenceServer) -> Vec<InferenceExpectation> {
    vec![
        server.expect_response(
            "text reply (responses)",
            InferenceRequestMatcher::foreground(InferenceEndpoint::Responses),
            ScriptedResponse::sse(sse::responses_api_script_exact("hello", "test-model")),
        ),
        server.expect_response(
            "text reply (chat completions)",
            InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
            ScriptedResponse::sse(sse::chat_completion_script_exact("hello", "test-model")),
        ),
    ]
}

/// Run `fuigo -p` once in a fresh home whose user hooks directory holds a hook that touches a marker file on every
/// event the run reaches. Returns whether the marker exists afterwards.
async fn marker_written(env: &[(&str, &str)]) -> bool {
    let server = MockInferenceServer::start()
        .await
        .expect("start the mock inference server");
    server.preset_allow_access();
    let _expectations = script_text_reply(&server);
    let workdir = git_workdir();
    let sandbox = TestSandbox::builder().mock_url(server.url()).build();
    let marker = sandbox.root().join("user-hook-ran");
    let hooks_dir = sandbox.fuigo_home().join("hooks");
    std::fs::create_dir_all(&hooks_dir).expect("create the user hooks directory");
    let command = format!("touch '{}'", marker.display());
    let handler = serde_json::json!([{"hooks": [{"type": "command", "command": command}]}]);
    let doc = serde_json::json!({"hooks": {
        "SessionStart": handler, "UserPromptSubmit": handler, "Stop": handler,
    }});
    std::fs::write(hooks_dir.join("marker.json"), doc.to_string()).expect("write the user hook");

    let mut cmd = tokio::process::Command::new(pager_binary());
    cmd.args(["-p", "say hi", "--trust", "--output-format", "json"])
        .current_dir(workdir.workspace());
    let result = run_headless_in_sandbox_borrowed_with_env(cmd, &sandbox, env).await;
    assert!(
        !result.timed_out,
        "the run must end on its own\nstdout:\n{}\nstderr:\n{}\nrequests:\n{}",
        result.stdout,
        result.stderr,
        server.request_log_summary()
    );
    assert!(
        server.request_count() > 0,
        "the run must reach the model, or the hooks never had a chance to fire\nstderr:\n{}",
        result.stderr
    );
    marker.exists()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn user_hook_runs_without_the_managed_hooks_only_switch() {
    assert!(
        marker_written(&[]).await,
        "control: without FUIGO_MANAGED_HOOKS_ONLY the user hook must run, or the next test proves nothing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_hooks_only_env_stops_the_user_hook() {
    assert!(
        !marker_written(&[("FUIGO_MANAGED_HOOKS_ONLY", "1")]).await,
        "FUIGO_MANAGED_HOOKS_ONLY=1 must keep a user hook from running"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_hooks_only_env_zero_leaves_user_hooks_on() {
    assert!(
        marker_written(&[("FUIGO_MANAGED_HOOKS_ONLY", "0")]).await,
        "FUIGO_MANAGED_HOOKS_ONLY=0 must leave user hooks running"
    );
}
