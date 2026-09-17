// Per-test-case module for the `pty_e2e` integration test crate.
#[allow(unused_imports)]
use super::common::*;

/// **A single Esc from the SCROLLBACK pane never cancels a running turn**: it points at Ctrl+C instead.
/// The policy treats Prompt and Scrollback identically while a turn runs, so neither pane's Esc cancels.
/// The footer's "Space:prompt" hint confirms the scrollback owns keys before the Esc is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn esc_from_scrollback_hints_cancel_key_instead_of_cancelling() {
    let content = ContentController::start().await.expect("start content");
    let long_response = format!(
        "{MOCK_RESPONSE_SENTINEL} {}",
        "streaming filler words for the cancellation window. ".repeat(120)
    );
    content.set_response(long_response);
    content.set_chunk_delay(Some(Duration::from_millis(50)));

    let binary = pager_binary().expect("resolve pager binary");
    let mut harness =
        PtyHarness::spawn_with_content(&binary, DEFAULT_ROWS, DEFAULT_COLS, &content, &[])
            .expect("spawn pager");

    harness
        .wait_for_text(WELCOME_SCREEN_SENTINEL, WELCOME_TIMEOUT)
        .expect("welcome text");

    harness
        .inject_keys(format!("{PROMPT}\r").as_bytes())
        .expect("submit prompt");
    harness
        .wait_for_text(MOCK_RESPONSE_SENTINEL, Duration::from_secs(30))
        .expect("stream started");

    // Leave the prompt with a SINGLE Tab (Esc is reserved for cancel/clear/rewind), then wait for the footer to prove the scrollback owns keys
    // Tab TOGGLES focus, so a second press could bounce back to the prompt; press once and poll the render, as `drive_to_scrollback_with_turn` does
    harness.inject_keys(b"\t").expect("tab to scrollback");
    harness
        .wait_for_text("Space:prompt", Duration::from_secs(10))
        .expect("scrollback must own keys before the Esc");

    // A single Esc from the scrollback leaves the turn running and names the cancel key
    harness.inject_keys(keys::ESC).expect("press esc");
    harness.update(Duration::from_millis(200));

    harness
        .wait_for_text("to cancel the turn", Duration::from_secs(15))
        .expect("mid-turn Esc must hint at the cancel key");

    harness.update(Duration::from_millis(600));
    let screen = harness.screen_contents();
    assert!(
        !screen.contains("Turn cancelled by user"),
        "Esc must not cancel the turn\nscreen:\n{screen}"
    );
    assert!(
        !harness.contains_text("panicked"),
        "pager panicked\nscreen:\n{}",
        harness.screen_contents()
    );

    harness.quit().expect("clean quit");
}
