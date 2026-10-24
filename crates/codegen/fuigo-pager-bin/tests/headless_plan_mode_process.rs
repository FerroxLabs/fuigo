//! `fuigo -p ... --permission-mode plan` is refused at the PROCESS boundary: plan mode needs a person to approve the plan
//! (`exit_plan_mode`), and a headless run has nobody to ask, so the flag must not silently run in another mode.

use fuigo_test_support::{MockInferenceServer, TestSandbox, git_workdir, run_headless_in_sandbox};

fn pager_binary() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("PAGER_BINARY") {
        return std::path::absolute(&p)
            .unwrap_or_else(|e| panic!("failed to absolutize PAGER_BINARY {p}: {e}"));
    }
    option_env!("CARGO_BIN_EXE_fuigo-pager")
        .map(std::path::PathBuf::from)
        .expect("PAGER_BINARY is unset and this build is not `cargo test`")
}

async fn run(
    server: &MockInferenceServer,
    args: &[&str],
    cwd: &std::path::Path,
) -> fuigo_test_support::HeadlessResult {
    let sandbox = TestSandbox::builder().mock_url(server.url()).build();
    let mut cmd = tokio::process::Command::new(pager_binary());
    cmd.args(args).current_dir(cwd);
    run_headless_in_sandbox(cmd, sandbox).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn headless_refuses_permission_mode_plan_before_any_model_request() {
    let server = MockInferenceServer::start()
        .await
        .expect("start the mock inference server");
    server.preset_allow_access();
    let sandbox = git_workdir();
    let result = run(
        &server,
        &[
            "-p",
            "say hi",
            "--trust",
            "--permission-mode",
            "plan",
            "--output-format",
            "json",
        ],
        sandbox.workspace(),
    )
    .await;
    assert!(
        !result.timed_out,
        "the run must end on its own\nstderr:\n{}",
        result.stderr
    );
    assert_ne!(
        result.status.code(),
        Some(0),
        "plan mode in a headless run must be refused, not run in another mode\nstdout:\n{}\nstderr:\n{}",
        result.stdout,
        result.stderr
    );
    assert!(
        result.stderr.contains("--permission-mode plan") && result.stderr.contains("headless"),
        "the error must name the flag and say why\nstderr:\n{}",
        result.stderr
    );
    assert_eq!(
        server.request_count(),
        0,
        "nothing may reach the model\nrequests:\n{}",
        server.request_log_summary()
    );
}
