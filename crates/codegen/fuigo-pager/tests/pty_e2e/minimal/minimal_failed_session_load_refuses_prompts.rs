// Per-test-case module for the `pty_e2e` integration test crate.
#[allow(unused_imports)]
use crate::common::*;

/// U8 in `--minimal`: there are no toasts there, so the refusal must land in the scrollback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "PTY e2e; run the owning pty_e2e_* Cargo test with --ignored (see Cargo.toml)"]
async fn minimal_failed_session_load_refuses_prompts() {
    let content = ContentController::start().await.expect("start content");
    content.set_response(format!("{MOCK_RESPONSE_SENTINEL} unused."));
    let project = tempfile::tempdir().expect("create project dir");
    std::fs::create_dir_all(project.path().join(".git")).expect("create .git");
    let cwd = dunce::canonicalize(project.path()).expect("canonicalize project");

    let binary = pager_binary().expect("resolve pager binary");
    let session_id = create_then_break_a_session(&content, &binary, cwd.as_path());
    let requests_before = content.request_count();
    let mut harness =
        spawn_minimal_in_dir(&content, 40, 120, &["--resume", &session_id], cwd.as_path());
    harness
        .wait_for_full_text("Couldn't load session", RESUME_TIMEOUT)
        .unwrap_or_else(|e| {
            panic!(
                "the failed load was never reported: {e}\nscreen:\n{}",
                harness.screen_contents()
            )
        });
    harness
        .inject_keys(b"hello into a dead tab\r")
        .expect("submit a prompt");
    harness
        .wait_for_full_text("didn't open", Duration::from_secs(15))
        .unwrap_or_else(|e| {
            panic!(
                "the refusal note never showed: {e}\nscreen:\n{}",
                harness.screen_contents()
            )
        });
    let text = harness.full_text();
    assert!(
        text.contains("/resume") && text.contains("/new"),
        "the note must name the way out\n{text}"
    );
    assert_eq!(
        content.request_count(),
        requests_before,
        "a refused prompt must never reach the model"
    );
    quit_minimal(&mut harness);
}
