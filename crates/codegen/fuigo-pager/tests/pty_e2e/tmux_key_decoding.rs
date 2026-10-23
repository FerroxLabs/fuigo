// Per-test-case module for the `pty_e2e` integration test crate.
//
// Keyboard shortcuts inside a REAL tmux (the `tmux` binary, not an emulation): the outer terminal is the harness PTY,
// the pager runs in a tmux pane, and raw bytes are injected exactly as a terminal emulator would send them to tmux.
// tmux re-encodes each key for the pane according to its own settings, so this covers the whole chain
// outer terminal -> tmux -> pager key decoding -> action.
// Two tmux configurations are exercised: the default (`extended-keys off`) and `extended-keys on`.
#[allow(unused_imports)]
use super::common::*;

const TMUX: &str = "/usr/bin/tmux";

/// An idle in-session composer running inside a fresh tmux server, with its own socket and config.
async fn tmux_session(extended_keys: bool) -> (ContentController, PtyHarness, String) {
    let content = ContentController::start().await.expect("start content");
    content.set_response(format!("{MOCK_RESPONSE_SENTINEL} done."));
    let binary = pager_binary().expect("resolve pager binary");
    let socket = format!("fuigo-keys-{}-{extended_keys}", std::process::id());
    let conf = content.sandbox().home().join("tmux.conf");
    let body = if extended_keys {
        "set -g extended-keys on\nset -g status off\n"
    } else {
        "set -g extended-keys off\nset -g status off\n"
    };
    std::fs::write(&conf, body).expect("write tmux.conf");
    let conf_s = conf.to_string_lossy().into_owned();
    let bin_s = binary.to_string_lossy().into_owned();
    let mut harness = PtyHarness::spawn_with_content(
        Path::new(TMUX),
        DEFAULT_ROWS,
        DEFAULT_COLS,
        &content,
        &["-L", &socket, "-f", &conf_s, "new-session", &bin_s],
    )
    .expect("spawn the pager inside tmux");
    harness.set_respond_to_queries(true);
    harness
        .wait_for_text(WELCOME_SCREEN_SENTINEL, WELCOME_TIMEOUT)
        .expect("welcome text inside tmux");
    harness
        .inject_keys(format!("{PROMPT}\r").as_bytes())
        .expect("submit prompt");
    harness
        .wait_for_text(MOCK_RESPONSE_SENTINEL, Duration::from_secs(30))
        .expect("turn rendered");
    harness.update(Duration::from_secs(2));
    (content, harness, socket)
}

fn kill_tmux(socket: &str) {
    let _ = std::process::Command::new(TMUX)
        .args(["-L", socket, "kill-server"])
        .status();
}

/// Type `text`, let it render, then send `keys` and settle.
fn press(h: &mut PtyHarness, text: &str, keys: &[u8]) {
    if !text.is_empty() {
        h.inject_keys(text.as_bytes()).expect("type");
        h.update(Duration::from_millis(400));
    }
    h.inject_keys(keys).expect("keys");
    h.update(Duration::from_millis(1200));
}

/// Empty the composer with the stash chord (Alt+S), so the next probe starts clean.
fn clear_composer(h: &mut PtyHarness) {
    h.inject_keys(b"\x1bs").expect("alt+s");
    h.update(Duration::from_millis(800));
}

fn check_shortcuts(extended_keys: bool) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let (_content, mut h, socket) = rt.block_on(tmux_session(extended_keys));
    let ctx = format!("tmux extended-keys {extended_keys}");

    // Alt+S (ESC s): stash the draft. Also what the later probes use to clean up.
    press(&mut h, "stashme", b"\x1bs");
    assert!(!h.contains_text("stashme"), "{ctx}: Alt+S must stash the draft\n{}", h.screen_contents());

    // Alt+Enter (ESC CR): newline, not submit.
    press(&mut h, "line1", b"\x1b\r");
    h.inject_keys(b"line2").expect("type");
    h.update(Duration::from_millis(800));
    let screen = h.screen_contents();
    assert!(
        screen.contains("line1") && screen.contains("line2") && !screen.contains("line1line2"),
        "{ctx}: Alt+Enter must start a new line\n{screen}"
    );
    clear_composer(&mut h);

    // Shift+Left (CSI 1;2 D) selects, typing replaces the selection.
    press(&mut h, "abc", b"\x1b[1;2D");
    h.inject_keys(b"Z").expect("type over");
    h.update(Duration::from_millis(800));
    assert!(h.contains_text("abZ"), "{ctx}: Shift+Left must select the last char\n{}", h.screen_contents());
    clear_composer(&mut h);

    // Alt+Left (CSI 1;3 D) moves a word left.
    press(&mut h, "abc", b"\x1b[1;3D");
    h.inject_keys(b"Y").expect("type");
    h.update(Duration::from_millis(800));
    assert!(h.contains_text("Yabc"), "{ctx}: Alt+Left must move to the word start\n{}", h.screen_contents());
    clear_composer(&mut h);

    // Shift+Tab (CSI Z) cycles the mode.
    press(&mut h, "", b"\x1b[Z");
    assert!(
        h.contains_text("Switched to mode"),
        "{ctx}: Shift+Tab must cycle the mode\n{}",
        h.screen_contents()
    );

    // The cheatsheet key the footer advertises must open the cheatsheet, whatever tmux does to it.
    let screen = h.screen_contents();
    let (name, bytes): (&str, &[u8]) = if screen.contains("Ctrl+.:shortcuts") {
        ("Ctrl+.", b"\x1b[46;5u")
    } else {
        assert!(screen.contains("Ctrl+x:shortcuts"), "{ctx}: no cheatsheet key in the footer\n{screen}");
        ("Ctrl+x", b"\x18")
    };
    press(&mut h, "", bytes);
    assert!(
        h.contains_text("nav"),
        "{ctx}: the footer advertises {name} for shortcuts but it did not open the cheatsheet\n{}",
        h.screen_contents()
    );
    kill_tmux(&socket);
}

/// Default tmux (`extended-keys off`): the shortcuts the guide lists reach the pager.
#[test]
#[ignore]
fn shortcuts_work_in_tmux_with_default_settings() {
    check_shortcuts(false);
}

/// `extended-keys on`: same shortcuts, and the cheatsheet key the footer advertises really works.
#[test]
#[ignore]
fn shortcuts_work_in_tmux_with_extended_keys_on() {
    check_shortcuts(true);
}
