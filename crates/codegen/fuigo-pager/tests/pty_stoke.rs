//! PTY e2e for the hidden `/stoke` screen: it closes on Esc, on `q` and on Ctrl-C, survives a resize in the middle of
//! the animation, and in every case (and when the pager is signalled while the fire is up) the terminal it hands back
//! is the one the shell expects: no alternate screen, no raw mode, cursor visible, mouse and paste modes off.
//!
//! These run in the ordinary `cargo test -p fuigo-pager` pass. The pager binary is the one `pager_binary()` builds.

// Shared support intentionally serves all PTY family crates.
#[allow(dead_code, unused_imports)]
#[path = "pty_e2e/common.rs"]
mod common;

use common::*;

const STOKE_LABEL: &str = "q to quit";
/// Footer of the prompt screen the fire is drawn over.
const PROMPT_HINT: &str = "Shift+Tab:mode";
const CTRL_C: &[u8] = b"\x03";

/// Boot the pager on the welcome screen and open the fire.
async fn open_stoke(content: &ContentController) -> PtyHarness {
    let binary = pager_binary().expect("resolve pager binary");
    let mut harness =
        PtyHarness::spawn_with_content(&binary, DEFAULT_ROWS, DEFAULT_COLS, content, &[])
            .expect("spawn pager");
    harness
        .wait_for_text(WELCOME_SCREEN_SENTINEL, WELCOME_TIMEOUT)
        .expect("welcome text");
    harness.inject_keys(b"/stoke").expect("type /stoke");
    harness.update(Duration::from_millis(300));
    harness.inject_keys(b"\r").expect("run /stoke");
    harness
        .wait_for_text(STOKE_LABEL, Duration::from_secs(15))
        .expect("the fire opens with its quit label");
    harness
}

/// The fire is up and animating: the frame keeps changing without any input.
fn assert_animating(harness: &mut PtyHarness) {
    let before = harness.screen_contents();
    harness.update(Duration::from_millis(600));
    let after = harness.screen_contents();
    assert_ne!(before, after, "the fire must keep moving while it is open");
}

/// What the child holds on the terminal while the TUI is up; proves the restore checks below have something to undo.
fn assert_tui_holds_the_terminal(harness: &PtyHarness) {
    let modes = harness.terminal_modes();
    assert!(
        modes.alt_screen || modes.bracketed_paste || modes.mouse_reporting,
        "the live TUI must have taken at least one terminal mode, got {modes:?}"
    );
    // Raw mode is read from the PTY's termios, which only exists on Unix.
    #[cfg(unix)]
    assert_eq!(
        harness.is_raw_mode(),
        Some(true),
        "the live TUI runs in raw mode"
    );
}

/// The terminal a shell gets back after the pager is gone.
fn assert_terminal_restored(harness: &PtyHarness, how: &str) {
    let modes = harness.terminal_modes();
    assert!(!modes.alt_screen, "{how}: left the alternate screen on: {modes:?}");
    assert!(!modes.bracketed_paste, "{how}: left bracketed paste on: {modes:?}");
    assert!(!modes.mouse_reporting, "{how}: left mouse reporting on: {modes:?}");
    assert!(!modes.focus_in_out, "{how}: left focus reporting on: {modes:?}");
    assert!(modes.show_cursor, "{how}: left the cursor hidden: {modes:?}");
    #[cfg(unix)]
    assert_eq!(
        harness.is_raw_mode(),
        Some(false),
        "{how}: left the terminal in raw mode (no echo, no line editing for the shell)"
    );
}

/// Leave through `/quit`, wait for the process and check what it handed back.
fn quit_and_assert_restored(harness: &mut PtyHarness, how: &str) {
    assert_tui_holds_the_terminal(harness);
    harness.inject_keys(b"/quit").expect("type /quit");
    harness.update(Duration::from_millis(300));
    harness.inject_keys(b"\r").expect("run /quit");
    let code = harness
        .wait_for_exit_and_drain(Duration::from_secs(20), Duration::from_secs(2))
        .unwrap_or_else(|e| panic!("{how}: pager did not exit: {e:#}"));
    assert_eq!(code, 0, "{how}: /quit exits cleanly");
    assert_terminal_restored(harness, how);
}

async fn close_with(key: &[u8], how: &str) {
    let content = ContentController::start().await.expect("start content");
    let mut harness = open_stoke(&content).await;
    assert_animating(&mut harness);
    harness.inject_keys(key).expect("close key");
    harness
        .wait_for_text_absent(STOKE_LABEL, Duration::from_secs(10))
        .unwrap_or_else(|e| {
            panic!("{how} must close the fire: {e:#}\nscreen:\n{}", harness.screen_contents())
        });
    assert!(
        harness.contains_text(PROMPT_HINT),
        "{how}: the prompt screen is back under the fire\nscreen:\n{}",
        harness.screen_contents()
    );
    assert!(
        !harness.contains_text("panicked"),
        "{how}: pager panicked\nscreen:\n{}",
        harness.screen_contents()
    );
    quit_and_assert_restored(&mut harness, how);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stoke_esc_closes_and_the_terminal_is_restored() {
    close_with(keys::ESC, "Esc").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stoke_q_closes_and_the_terminal_is_restored() {
    close_with(b"q", "q").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stoke_ctrl_c_closes_and_the_terminal_is_restored() {
    close_with(CTRL_C, "Ctrl-C").await;
}

/// A resize in the middle of the animation must neither panic nor strand the terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stoke_resize_mid_animation_neither_panics_nor_strands_the_terminal() {
    let content = ContentController::start().await.expect("start content");
    let mut harness = open_stoke(&content).await;
    assert_animating(&mut harness);
    for (rows, cols) in [(20, 60), (9, 30), (60, 200), (1, 1), (3, 10), (30, 100), (50, 120)] {
        harness.resize(rows, cols).expect("resize");
        harness.update(Duration::from_millis(150));
        assert!(
            harness.is_running().expect("poll pager"),
            "the pager died when resized to {rows}x{cols}\nscreen:\n{}",
            harness.screen_contents()
        );
        assert!(
            !harness.contains_text("panicked"),
            "pager panicked when resized to {rows}x{cols}\nscreen:\n{}",
            harness.screen_contents()
        );
    }
    harness
        .wait_for_text(STOKE_LABEL, Duration::from_secs(10))
        .expect("the fire is still up and labelled after the resizes");
    assert_animating(&mut harness);
    harness.inject_keys(keys::ESC).expect("esc");
    harness
        .wait_for_text_absent(STOKE_LABEL, Duration::from_secs(10))
        .expect("Esc closes the fire after a resize");
    quit_and_assert_restored(&mut harness, "resize");
}

/// The pager is signalled while the fire is up: it must still hand the terminal back.
#[cfg(unix)]
async fn signalled_while_stoke_is_open(signal: i32, expected_code: u32, how: &str) {
    let content = ContentController::start().await.expect("start content");
    let mut harness = open_stoke(&content).await;
    assert_tui_holds_the_terminal(&harness);
    harness.send_signal(signal).unwrap_or_else(|e| panic!("{how}: signal: {e:#}"));
    let code = harness
        .wait_for_exit_and_drain(Duration::from_secs(20), Duration::from_secs(2))
        .unwrap_or_else(|e| panic!("{how}: pager did not exit: {e:#}"));
    // The first signal asks for the graceful quit (exit 0 after a full teardown); a hard exit would be 128+N.
    assert!(
        code == 0 || code == expected_code,
        "{how}: exit code {code} is neither a clean quit nor the conventional {expected_code}"
    );
    assert_terminal_restored(&harness, how);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigterm_while_stoke_is_open_restores_the_terminal() {
    signalled_while_stoke_is_open(libc::SIGTERM, 143, "SIGTERM").await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigint_while_stoke_is_open_restores_the_terminal() {
    signalled_while_stoke_is_open(libc::SIGINT, 130, "SIGINT").await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sighup_while_stoke_is_open_restores_the_terminal() {
    signalled_while_stoke_is_open(libc::SIGHUP, 129, "SIGHUP").await;
}
