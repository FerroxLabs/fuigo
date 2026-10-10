// Per-test-case module for the `pty_e2e` integration test crate.
#[allow(unused_imports)]
use super::common::*;

/// U8: a tab whose `session/load` failed has no session. A prompt typed into it used to queue forever with no word.
/// Now it is refused with a hint (/resume or /new) and nothing reaches the model (`/new` itself is covered by the dispatch unit tests).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "PTY e2e; run the owning pty_e2e_* Cargo test with --ignored (see Cargo.toml)"]
async fn failed_session_load_refuses_prompts_with_a_resume_hint() {
    let content = ContentController::start().await.expect("start content");
    content.set_response(format!("{MOCK_RESPONSE_SENTINEL} first session."));
    let project = tempfile::tempdir().expect("create project dir");
    std::fs::create_dir_all(project.path().join(".git")).expect("create .git");
    let cwd = dunce::canonicalize(project.path()).expect("canonicalize project");

    let binary = pager_binary().expect("resolve pager binary");
    let session_id = create_then_break_a_session(&content, &binary, cwd.as_path());
    let requests_before = content.request_count();
    let mut harness = PtyHarness::spawn_with_content_in_dir(
        &binary,
        DEFAULT_ROWS,
        DEFAULT_COLS,
        &content,
        &["--no-leader", "--resume", &session_id],
        Some(cwd.as_path()),
    )
    .expect("spawn pager");
    harness
        .wait_for_text("Couldn't load session", RESUME_TIMEOUT)
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
        .wait_for_text("didn't open", Duration::from_secs(15))
        .unwrap_or_else(|e| {
            panic!(
                "the refusal notice never showed: {e}\nscreen:\n{}",
                harness.screen_contents()
            )
        });
    let screen = harness.screen_contents();
    assert!(
        screen.contains("/resume") && screen.contains("/new"),
        "the notice must name the way out\nscreen:\n{screen}"
    );
    assert_eq!(
        content.request_count(),
        requests_before,
        "a refused prompt must never reach the model"
    );

    assert!(
        !harness.contains_text("panicked"),
        "pager panicked\nscreen:\n{}",
        harness.screen_contents()
    );
    harness.quit().expect("clean quit");
}
