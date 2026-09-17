// Per-test-case module for the `pty_e2e` integration test crate.
#[allow(unused_imports)]
use crate::common::*;

/// The prompt is always focused in minimal mode, so a mid-turn Esc reaches the policy's turn-running branch.
/// It never cancels: minimal has no toast slot, so the "Press <cancel key> to cancel the turn" hint is
/// committed to native scrollback as a system line, at most once per user turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn minimal_esc_hints_cancel_key_instead_of_cancelling() {
    let content = ContentController::start().await.expect("start content");
    // Paced, long stream so the turn is provably still running when Esc lands.
    let long = format!(
        "{MOCK_RESPONSE_SENTINEL} {}",
        "streaming filler words for the cancellation window. ".repeat(120)
    );
    content.set_response(long);
    content.set_chunk_delay(Some(Duration::from_millis(50)));

    let mut harness = spawn_minimal(&content);
    wait_minimal_ready(&mut harness);

    harness
        .inject_keys(format!("{PROMPT}\r").as_bytes())
        .expect("submit prompt");
    harness
        .wait_for_text(MOCK_RESPONSE_SENTINEL, Duration::from_secs(30))
        .expect("turn streaming in the live tail");

    harness.inject_keys(keys::ESC).expect("press esc");

    // Minimal commits the hint line to native scrollback and it may sit above the pinned viewport, so check the full text, not just the screen
    harness
        .wait_for_full_text("to cancel the turn", Duration::from_secs(15))
        .expect("cancel-key hint committed to scrollback");
    assert!(
        !harness.full_text().contains("Turn cancelled by user"),
        "Esc must not cancel the turn\nfull contents:\n{}",
        harness.full_text()
    );
    assert!(
        !harness.contains_text("panicked"),
        "pager panicked\nscreen:\n{}",
        harness.screen_contents()
    );

    quit_minimal(&mut harness);
}
