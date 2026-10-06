// Per-test-case module for the `pty_e2e` integration test crate.
#[allow(unused_imports)]
use super::common::*;

const FEEDBACK_LABEL_SENTINEL: &str = "How can we improve Fuigo?";
const TRACE_QUESTION_SENTINEL: &str = "Opt-in to provide your trace";
const DISABLED_SENTINEL: &str = "Feedback is disabled";
const REPORT: &str = "p152-disabled-feedback-report";

/// P152 (e2e lane B #3): with feedback disabled, `/feedback` must say so in ONE clear message.
/// The RC printed "Thanks for the feedback! The Fuigo team is on it." and then
/// "Couldn't send feedback: couldn't send feedback: Internal error: Feedback is disabled ...": a thank-you for a report
/// that never went out, a doubled prefix and an "Internal error" for a configuration state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "PTY e2e; run the owning pty_e2e_* Cargo test with --ignored (see Cargo.toml)"]
async fn feedback_disabled_says_so_once_without_thanks() {
    let content = ContentController::start().await.expect("start content");
    content.set_response(format!("{MOCK_RESPONSE_SENTINEL} ready for feedback."));

    let binary = pager_binary().expect("resolve pager binary");
    let mut harness = PtyHarness::spawn_with_content_env_in_dir(
        &binary,
        DEFAULT_ROWS,
        DEFAULT_COLS,
        &content,
        &["--yolo", "--trust"],
        &[("FUIGO_FEEDBACK_ENABLED", "false")],
        Some(content.home()),
    )
    .expect("spawn pager with feedback disabled");
    harness
        .wait_for_text(WELCOME_SCREEN_SENTINEL, WELCOME_TIMEOUT)
        .expect("welcome text");

    // Establish a session so the report has a session to go to.
    harness
        .inject_keys(format!("{PROMPT}\r").as_bytes())
        .expect("submit prompt");
    harness
        .wait_for_text(MOCK_RESPONSE_SENTINEL, Duration::from_secs(30))
        .expect("response rendered");

    harness.inject_keys(b"/feedback\r").expect("open /feedback");
    harness
        .wait_for_text(FEEDBACK_LABEL_SENTINEL, Duration::from_secs(15))
        .expect("feedback pane opens");
    harness
        .inject_keys(format!("{REPORT}\r").as_bytes())
        .expect("type + submit the report");
    harness.update(Duration::from_millis(400));
    if harness.contains_text(TRACE_QUESTION_SENTINEL) {
        harness.inject_keys(b"\x1b").expect("skip the trace question");
    }
    harness
        .wait_for_text(DISABLED_SENTINEL, Duration::from_secs(20))
        .expect("the disabled state is reported");
    harness.update(Duration::from_millis(500));

    let screen = harness.screen_contents();
    assert!(
        !screen.contains("Thanks for the feedback"),
        "a report that was not sent must not be thanked for\nscreen:\n{screen}"
    );
    assert_eq!(
        screen.matches(DISABLED_SENTINEL).count(),
        1,
        "the disabled state is said once\nscreen:\n{screen}"
    );
    assert!(
        !screen.to_lowercase().contains("couldn't send feedback: couldn't send feedback"),
        "no doubled prefix\nscreen:\n{screen}"
    );
    assert!(
        !screen.contains("Internal error"),
        "a configuration state is not an internal error\nscreen:\n{screen}"
    );
    assert!(
        !harness.contains_text("panicked"),
        "pager panicked\nscreen:\n{}",
        harness.screen_contents()
    );
    harness.quit().expect("clean quit");
}
