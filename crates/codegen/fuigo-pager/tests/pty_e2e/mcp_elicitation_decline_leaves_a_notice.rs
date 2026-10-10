// Per-test-case module for the `pty_e2e` integration test crate.
#[allow(unused_imports)]
use super::common::*;

/// B-tui #5: declining an MCP elicitation card tells the server and leaves a line in the scrollback.
/// Before, the card vanished and nothing in the transcript said the request had been refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "PTY e2e; run the owning pty_e2e_* Cargo test with --ignored (see Cargo.toml)"]
async fn mcp_elicitation_decline_leaves_a_notice() {
    let content = ContentController::start().await.expect("start content");
    content.set_response(format!("{MOCK_RESPONSE_SENTINEL} after the tool."));
    seed_elicit_mcp_server(&content);
    let _turn = expect_elicit_tool_turn(&content);

    let binary = pager_binary().expect("resolve pager binary");
    let mut harness = PtyHarness::spawn_with_content_in_dir(
        &binary,
        DEFAULT_ROWS,
        DEFAULT_COLS,
        &content,
        &["--trust", "--no-leader", "--yolo"],
        Some(content.home()),
    )
    .expect("spawn pager");
    harness
        .wait_for_text(WELCOME_SCREEN_SENTINEL, WELCOME_TIMEOUT)
        .expect("welcome text");
    harness
        .inject_keys(format!("{PROMPT}\r").as_bytes())
        .expect("submit prompt");
    harness
        .wait_for_text(ELICIT_MESSAGE, Duration::from_secs(90))
        .unwrap_or_else(|e| {
            panic!(
                "the elicitation card never drew: {e}\nscreen:\n{}",
                harness.screen_contents()
            )
        });

    // Tab moves to the action row; `d` declines.
    harness.inject_keys(b"\t").expect("focus the actions");
    harness.update(Duration::from_millis(300));
    harness.inject_keys(b"d").expect("decline");
    harness
        .wait_for_text(
            "Declined MCP \u{201c}ptyelicit\u{201d} request for input.",
            Duration::from_secs(30),
        )
        .unwrap_or_else(|e| {
            panic!(
                "no scrollback note after the decline: {e}\nscreen:\n{}",
                harness.screen_contents()
            )
        });
    harness
        .wait_for_text(MOCK_RESPONSE_SENTINEL, Duration::from_secs(60))
        .unwrap_or_else(|e| {
            panic!(
                "the turn did not carry on after the decline: {e}\nscreen:\n{}",
                harness.screen_contents()
            )
        });
    assert!(
        !harness.contains_text("panicked"),
        "pager panicked\nscreen:\n{}",
        harness.screen_contents()
    );
    harness.quit().expect("clean quit");
}
