// Per-test-case module for the `pty_e2e` integration test crate.
#[allow(unused_imports)]
use crate::common::*;

/// B-tui #3 / U10: `--minimal` draws the MCP elicitation card. Before, the card was open (and took every key) but
/// nothing painted it, so the turn sat on an invisible question. Ctrl+C cancels it and leaves a scrollback note.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "PTY e2e; run the owning pty_e2e_* Cargo test with --ignored (see Cargo.toml)"]
async fn minimal_mcp_elicitation_card_is_drawn() {
    let content = ContentController::start().await.expect("start content");
    content.set_response(format!("{MOCK_RESPONSE_SENTINEL} after the tool."));
    seed_elicit_mcp_server(&content);
    let _turn = expect_elicit_tool_turn(&content);

    let mut harness = spawn_minimal_in_dir(&content, 40, 120, &["--trust", "--yolo"], content.home());
    wait_minimal_ready(&mut harness);
    harness.inject_keys(b"go\r").expect("submit prompt");
    harness
        .wait_for_text(ELICIT_MESSAGE, Duration::from_secs(90))
        .unwrap_or_else(|e| {
            panic!(
                "minimal never drew the elicitation card: {e}\nscreen:\n{}",
                harness.screen_contents()
            )
        });
    for needle in ["ptyelicit", "Ticket title", "Accept", "Decline"] {
        assert!(
            harness.contains_text(needle),
            "{needle:?} must be on the card\nscreen:\n{}",
            harness.screen_contents()
        );
    }

    harness.inject_keys(b"\x03").expect("Ctrl+C cancels the card");
    harness
        .wait_for_full_text(
            "Dismissed MCP \u{201c}ptyelicit\u{201d} request for input without answering.",
            Duration::from_secs(30),
        )
        .unwrap_or_else(|e| {
            panic!(
                "no note after cancelling: {e}\nscreen:\n{}",
                harness.screen_contents()
            )
        });
    harness
        .wait_for_full_text(MOCK_RESPONSE_SENTINEL, Duration::from_secs(60))
        .expect("the turn carries on after the cancel");
    assert!(
        !harness.contains_text("panicked"),
        "pager panicked\nscreen:\n{}",
        harness.screen_contents()
    );
    quit_minimal(&mut harness);
}
