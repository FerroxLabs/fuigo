#![cfg(unix)]

use fuigo_pager_pty_harness::{ContentController, PtyHarness};
use std::time::{Duration, Instant};

fn binary() -> std::path::PathBuf {
    std::env::var_os("PAGER_BINARY")
        .map(Into::into)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_fuigo-pager").into())
}

const QUERY: &[u8] = b"\x1b[?u\x1b[c";
const TERMINAL: &[(&str, &str)] = &[
    ("TERM", "xterm-kitty"),
    ("TERM_PROGRAM", "kitty"),
    ("KITTY_WINDOW_ID", "1"),
    ("TMUX", ""),
    ("STY", ""),
    ("VTE_VERSION", ""),
    ("ZELLIJ", ""),
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_keyboard_query_does_not_stall_first_frame() {
    let content = ContentController::start().await.unwrap();
    let mut harness =
        PtyHarness::spawn_with_content_env(&binary(), 40, 100, &content, &[], TERMINAL).unwrap();
    // The emulator deliberately sends no terminal replies.
    harness.set_respond_to_queries(false);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        harness.update(Duration::from_millis(1));
        if harness
            .raw_output()
            .windows(QUERY.len())
            .any(|w| w == QUERY)
        {
            break;
        }
        assert!(Instant::now() < deadline, "keyboard query was not emitted");
    }
    let started = Instant::now();
    harness
        .wait_for_text("Quit", Duration::from_secs(10))
        .unwrap();
    let elapsed = started.elapsed();
    harness.quit().unwrap();
    eprintln!("silent keyboard query to first frame: {elapsed:?}");
    assert!(
        elapsed < Duration::from_secs(1),
        "silent terminal delayed startup: {elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unbracketed_200kb_paste_reaches_prompt_within_two_seconds() {
    let content = ContentController::start().await.unwrap();
    content.set_response("READY_FOR_PASTE");
    let mut harness =
        PtyHarness::spawn_with_content_env(&binary(), 40, 100, &content, &[], TERMINAL).unwrap();
    harness
        .wait_for_text("Quit", Duration::from_secs(20))
        .unwrap();
    harness.inject_keys(b"start\r").unwrap();
    harness
        .wait_for_text("READY_FOR_PASTE", Duration::from_secs(20))
        .unwrap();
    harness.wait_for_turn_idle(Duration::from_secs(20)).unwrap();
    // Ignore the child's bracketed-paste enable request. A terminal without
    // that protocol delivers just keystrokes, without CSI 200~/201~ wrappers.
    let text: String = (0..200_000)
        .map(|i| char::from(b'a' + (i % 26) as u8))
        .collect();
    let (cancel_watchdog, watchdog_rx) = std::sync::mpsc::channel::<()>();
    let pid = harness.child_pid().unwrap();
    let watchdog = std::thread::spawn(move || {
        if matches!(
            watchdog_rx.recv_timeout(Duration::from_secs(10)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ) {
            // SAFETY: only the test-owned child PID; the watchdog is cancelled
            // before that child is reaped, so its PID cannot have been reused.
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
            eprintln!("unbracketed paste exceeded the 10-second watchdog");
            // A blocking PTY write can remain parked after slave exit on some
            // kernels. End this test process so a regression cannot hang CI.
            std::process::exit(1);
        }
    });
    let started = Instant::now();
    for chunk in text.as_bytes().chunks(32_768) {
        harness
            .inject_keys(chunk)
            .unwrap_or_else(|e| panic!("paste write stalled for {:?}: {e}", started.elapsed()));
    }
    // Submit after the burst settles, then inspect the persisted user message.
    // The model request may compact large text, but the session update retains
    // the original draft. This includes persistence overhead, so it bounds the
    // time until the prompt contains every byte without production test hooks.
    harness.update(Duration::from_millis(100));
    harness.inject_keys(b"\r").unwrap();
    fn contains_draft(dir: &std::path::Path, text: &str) -> bool {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return false;
        };
        entries.flatten().any(|entry| {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                contains_draft(&entry.path(), text)
            } else if entry.file_name() == "updates.jsonl" {
                std::fs::read_to_string(entry.path()).is_ok_and(|events| events.contains(text))
            } else {
                false
            }
        })
    }
    let sessions = content.sandbox().fuigo_home().join("sessions");
    let mut observed = false;
    while started.elapsed() < Duration::from_secs(5) {
        harness.update(Duration::from_millis(5));
        if contains_draft(&sessions, &text) {
            observed = true;
            break;
        }
    }
    if !observed {
        eprintln!("paste screen: {}", harness.screen_contents());
    }
    let elapsed = started.elapsed();
    eprintln!("unbracketed paste: exact_200kb={observed}, elapsed={elapsed:?}");
    drop(cancel_watchdog);
    watchdog.join().unwrap();
    harness.quit().unwrap();
    assert!(observed, "the entire paste must be in the submitted draft");
    assert!(
        elapsed < Duration::from_secs(2),
        "paste stalled: {elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keyboard_reply_enables_protocol_even_without_trailing_da1() {
    for reply in [b"\x1b[?0u\x1b[?62c".as_slice(), b"\x1b[?0u".as_slice()] {
        let content = ContentController::start().await.unwrap();
        let mut harness =
            PtyHarness::spawn_with_content_env(&binary(), 40, 100, &content, &[], TERMINAL)
                .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            harness.update(Duration::from_millis(1));
            if harness
                .raw_output()
                .windows(QUERY.len())
                .any(|w| w == QUERY)
            {
                break;
            }
            assert!(Instant::now() < deadline, "keyboard query was not emitted");
        }
        let started = Instant::now();
        harness.inject_keys(reply).unwrap();
        harness
            .wait_for_text("Quit", Duration::from_secs(3))
            .unwrap();
        let elapsed = started.elapsed();
        assert!(
            harness.raw_output().windows(5).any(|w| w == b"\x1b[>3u"),
            "Kitty support must still be enabled"
        );
        harness.quit().unwrap();
        eprintln!("keyboard reply {reply:?} to first frame: {elapsed:?}");
        assert!(
            elapsed < Duration::from_secs(1),
            "a missing trailing DA1 must not hang startup: {elapsed:?}"
        );
    }
}

// Run exactly the library call used by App::init_terminal in an isolated PTY,
// excluding subsequent UI initialization from the 200 ms query measurement.
#[test]
fn keyboard_probe_child() {
    if std::env::var_os("FUIGO_KEYBOARD_PROBE_TEST_CHILD").is_none() {
        return;
    }
    crossterm::terminal::enable_raw_mode().unwrap();
    let started = Instant::now();
    let supported = crossterm::terminal::supports_keyboard_enhancement().unwrap_or(false);
    let elapsed = started.elapsed();
    let typeahead = if crossterm::event::poll(Duration::ZERO).unwrap() {
        matches!(crossterm::event::read().unwrap(), crossterm::event::Event::Key(key)
            if key.code == crossterm::event::KeyCode::Char('x'))
    } else {
        false
    };
    crossterm::terminal::disable_raw_mode().unwrap();
    fuigo_tty_utils::cli_println!(
        "PROBE_DONE supported={supported} typeahead={typeahead} micros={}",
        elapsed.as_micros()
    );
}

#[test]
fn keyboard_probe_has_one_200ms_deadline() {
    for (reply, supported, delay_ms) in [
        (b"".as_slice(), false, 0),
        (b"\x1b[?0u\x1b[?62c".as_slice(), true, 0),
        (b"\x1b[?0u".as_slice(), true, 0),
        (b"\x1b[?62c".as_slice(), false, 0),
        (b"x\x1b[?0u\x1b[?62c".as_slice(), true, 0),
        (b"\x1b[?0u".as_slice(), true, 150),
    ] {
        let mut harness = PtyHarness::new_inherited_env(
            &std::env::current_exe().unwrap(),
            20,
            100,
            &["--exact", "keyboard_probe_child", "--nocapture"],
            &[("FUIGO_KEYBOARD_PROBE_TEST_CHILD", "1")],
            None,
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !harness
            .raw_output()
            .windows(QUERY.len())
            .any(|w| w == QUERY)
        {
            harness.update(Duration::from_millis(1));
            assert!(Instant::now() < deadline, "query not emitted");
        }
        // A late flags reply must not start a fresh wait for the missing DA1.
        std::thread::sleep(Duration::from_millis(delay_ms));
        harness.inject_keys(reply).unwrap();
        harness
            .wait_for_text("PROBE_DONE", Duration::from_secs(3))
            .unwrap();
        let output = String::from_utf8_lossy(harness.raw_output());
        let micros: u64 = output
            .split("micros=")
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        eprintln!("reply={reply:?} delay_ms={delay_ms} query_micros={micros}");
        if reply.starts_with(b"x") {
            assert!(output.contains("typeahead=true"), "{output}");
        }
        assert!(
            output.contains(&format!("supported={supported}")),
            "{output}"
        );
        assert!(
            micros < if delay_ms == 150 { 250_000 } else { 400_000 },
            "keyboard query exceeded its deadline: {micros} us"
        );
    }
}

// Exec the real binary with a pipe on fd 0, preserving the controlling PTY on
// stdout/stderr. This forces crossterm to open /dev/tty for keyboard input.
#[test]
fn piped_stdin_child() {
    if std::env::var_os("FUIGO_PIPED_STDIN_TEST_CHILD").is_none() {
        return;
    }
    use std::os::unix::process::CommandExt;
    let error = std::process::Command::new(binary())
        .stdin(std::process::Stdio::piped())
        .exec();
    panic!("exec pager with piped stdin: {error}");
}

// macOS kqueue cannot register /dev/tty (EINVAL) when stdin is piped.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn piped_stdin_keeps_controlling_tty_keys_and_20kb_paste() {
    let content = ContentController::start().await.unwrap();
    content.set_response("READY_FOR_PIPED_PASTE");
    let mut env = TERMINAL.to_vec();
    env.push(("FUIGO_PIPED_STDIN_TEST_CHILD", "1"));
    let mut harness = PtyHarness::spawn_with_content_env(
        &std::env::current_exe().unwrap(),
        40,
        100,
        &content,
        &["--exact", "piped_stdin_child", "--nocapture"],
        &env,
    )
    .unwrap();
    harness
        .wait_for_text("Quit", Duration::from_secs(20))
        .unwrap();
    // Separate keystrokes exercise repeated idle -> readable transitions.
    for byte in b"typed_keys_via_controlling_tty" {
        harness.inject_keys(&[*byte]).unwrap();
        harness.update(Duration::from_millis(15));
    }
    harness.inject_keys(b"\r").unwrap();
    harness
        .wait_for_text("READY_FOR_PIPED_PASTE", Duration::from_secs(20))
        .unwrap();
    harness.wait_for_turn_idle(Duration::from_secs(20)).unwrap();
    let text: String = (0..20_000)
        .map(|i| char::from(b'a' + (i % 26) as u8))
        .collect();
    let (cancel, watchdog_rx) = std::sync::mpsc::channel::<()>();
    let pid = harness.child_pid().unwrap();
    let watchdog = std::thread::spawn(move || {
        if matches!(
            watchdog_rx.recv_timeout(Duration::from_secs(10)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ) {
            // SAFETY: the test-owned child is not reaped until cancellation.
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
            eprintln!("piped-stdin paste exceeded watchdog");
            std::process::exit(1);
        }
    });
    let started = Instant::now();
    // No bracketed-paste wrappers: one write must drain beyond a read buffer.
    harness.inject_keys(text.as_bytes()).unwrap();
    harness.update(Duration::from_millis(100));
    harness.inject_keys(b"\r").unwrap();
    fn has_draft(dir: &std::path::Path, text: &str) -> bool {
        std::fs::read_dir(dir).is_ok_and(|entries| {
            entries.flatten().any(|entry| {
                if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    has_draft(&entry.path(), text)
                } else if entry.file_name() == "updates.jsonl" {
                    std::fs::read_to_string(entry.path()).is_ok_and(|events| events.contains(text))
                } else {
                    false
                }
            })
        })
    }
    let sessions = content.sandbox().fuigo_home().join("sessions");
    let mut observed = false;
    while started.elapsed() < Duration::from_secs(5) {
        harness.update(Duration::from_millis(5));
        if has_draft(&sessions, &text) {
            observed = true;
            break;
        }
    }
    drop(cancel);
    watchdog.join().unwrap();
    eprintln!(
        "piped stdin: exact_20kb={observed} elapsed={:?}",
        started.elapsed()
    );
    harness.quit().unwrap();
    assert!(
        has_draft(&sessions, "typed_keys_via_controlling_tty"),
        "typed keys must arrive intact"
    );
    assert!(
        observed,
        "controlling tty must deliver the entire 20 KB paste"
    );
}
