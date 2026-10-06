// Per-test-case module for the `pty_e2e` integration test crate.
#[allow(unused_imports)]
use super::common::*;

/// What the `/mcps` list shows under a server that is not connected and has a recorded cause.
const REASON_PREFIX: &str = "Not connected:";

/// P152 (e2e lane B #4): a configured server that failed to start is listed as `[unavailable]`, and the list must say
/// why. The RC showed only the badge and "no tools (server may not be connected)" although the shell had recorded the
/// cause. `/bin/cat` speaks no MCP, so its handshake fails within the configured 2 s startup timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "PTY e2e; run the owning pty_e2e_* Cargo test with --ignored (see Cargo.toml)"]
async fn mcp_menu_unavailable_server_shows_reason() {
    let content = ContentController::start().await.expect("start content");
    content.set_response(format!("{MOCK_RESPONSE_SENTINEL} mcp reason."));
    seed_mcp_server_config(&content);

    let binary = pager_binary().expect("resolve pager binary");
    let mut harness = PtyHarness::spawn_with_content_in_dir(
        &binary,
        DEFAULT_ROWS,
        DEFAULT_COLS,
        &content,
        &["--trust"],
        Some(content.home()),
    )
    .expect("spawn pager");
    harness
        .wait_for_text(WELCOME_SCREEN_SENTINEL, WELCOME_TIMEOUT)
        .expect("welcome text");

    // A turn makes the session start its MCP servers; the seeded one fails its handshake.
    harness
        .inject_keys(format!("{PROMPT}\r").as_bytes())
        .expect("submit prompt");
    harness
        .wait_for_text(MOCK_RESPONSE_SENTINEL, Duration::from_secs(60))
        .expect("response rendered");
    harness.update(Duration::from_secs(4));

    harness.inject_keys(b"/mcps\r").expect("submit /mcps");
    harness
        .wait_for_text("MCP Servers", Duration::from_secs(15))
        .expect("extensions modal open on MCP Servers tab");
    harness
        .wait_for_text(MCP_TEST_SERVER, MCP_MENU_LOAD_TIMEOUT)
        .expect("MCP server list loaded in menu");
    let found = harness.wait_for_text(REASON_PREFIX, Duration::from_secs(30));
    let screen = harness.screen_contents();
    assert!(
        found.is_ok(),
        "an unavailable server must show why it is unavailable\nscreen:\n{screen}"
    );
    assert!(
        screen.contains("[unavailable]"),
        "the server is still badged unavailable\nscreen:\n{screen}"
    );
    assert!(
        !harness.contains_text("panicked"),
        "pager panicked\nscreen:\n{}",
        harness.screen_contents()
    );
    harness.quit().expect("clean quit");
}
