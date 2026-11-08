//! 74.B22: `-p --resume <missing id> --output-format json` prints one JSON error object saying why the session
//! did not load, and exits non-zero. F12's `--no-session-persistence` conflict (exit 2) is covered in
//! `no_session_persistence_process.rs`.

use std::path::PathBuf;

use fuigo_test_support::{MockInferenceServer, TestSandbox, run_headless_in_sandbox_borrowed};

fn pager_binary() -> PathBuf {
    if let Ok(p) = std::env::var("PAGER_BINARY") {
        return std::path::absolute(&p).unwrap_or_else(|e| panic!("absolutize PAGER_BINARY {p}: {e}"));
    }
    option_env!("CARGO_BIN_EXE_fuigo-pager")
        .map(PathBuf::from)
        .expect("PAGER_BINARY is unset and this build is not `cargo test`")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resume_that_fails_before_the_session_opens_prints_one_json_error() {
    let server = MockInferenceServer::start().await.expect("mock server");
    server.preset_allow_access();
    let sandbox = TestSandbox::builder().git().mock_url(server.url()).build();
    let mut cmd = tokio::process::Command::new(pager_binary());
    cmd.args([
        "-p",
        "hi",
        "--trust",
        "--output-format",
        "json",
        "--resume",
        "0b6f7e0a-0000-4000-8000-000000000001",
    ])
    .current_dir(sandbox.workspace());
    let result = run_headless_in_sandbox_borrowed(cmd, &sandbox).await;
    assert!(!result.timed_out, "stderr:\n{}", result.stderr);
    assert_ne!(result.status.code(), Some(0), "stdout:\n{}", result.stdout);
    let lines: Vec<&str> = result.stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "exactly one JSON object on stdout\nstdout:\n{}\nstderr:\n{}", result.stdout, result.stderr);
    let doc: serde_json::Value = serde_json::from_str(lines[0])
        .unwrap_or_else(|e| panic!("stdout must be JSON ({e}): {}", result.stdout));
    assert_eq!(doc["type"], "error", "{doc}");
    assert!(
        doc["message"].as_str().is_some_and(|m| m.contains("Session does not exist")),
        "{doc}"
    );
}
