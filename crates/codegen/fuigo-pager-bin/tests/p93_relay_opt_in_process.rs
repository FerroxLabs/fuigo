//! P93 at the PROCESS boundary: `fuigo agent headless`, with and without a leader, refuses a relay that FluxRouter
//! does not operate when no opt-in names its origin, exits with an error that says what to set and where, and never
//! gets as far as a leader or the relay.
//!
//! The leader-client path (`agent --leader headless`) is the one only this binary has: it hands the relay to a
//! leader instead of running `run_headless`, so without its own check the refusal would happen in the leader and the
//! client would wait forever. The relay URL's host does not resolve and nothing listens for it: a run that got past
//! the check would hang or fail differently, never print the refusal.

#![cfg(unix)]

use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn pager_binary() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("PAGER_BINARY") {
        return std::path::absolute(&p)
            .unwrap_or_else(|e| panic!("failed to absolutize PAGER_BINARY {p}: {e}"));
    }
    option_env!("CARGO_BIN_EXE_fuigo-pager")
        .map(std::path::PathBuf::from)
        .expect("PAGER_BINARY is unset and this build is not `cargo test`")
}

const RELAY_URL: &str = "wss://relay.invalid/ws";
const RELAY_ORIGIN: &str = "https://relay.invalid";

/// Run `fuigo <args>` hermetically with `FUIGO_WS_URL` at a relay FluxRouter does not operate; return the exit code
/// and stderr. The whole process group is killed at the deadline.
fn run(args: &[&str], ws_url_env: Option<&str>) -> (Option<i32>, String) {
    let sandbox = fuigo_test_support::TestSandbox::builder().build();
    let mut command = Command::new(pager_binary());
    command
        .args(args)
        .env_clear()
        .envs(sandbox.env())
        .env_remove("FUIGO_WS_URL")
        .env_remove("FUIGO_TRUSTED_RELAY_ORIGINS");
    if let Some(url) = ws_url_env {
        command.env("FUIGO_WS_URL", url);
    }
    #[allow(
        clippy::disallowed_methods,
        reason = "the child is placed in its own process group (process_group(0)) and the whole \
                  group is SIGKILLed on the deadline, so nothing it starts outlives this function"
    )]
    let mut child = command
        .current_dir(sandbox.workspace())
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fuigo");
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");
    let (text_tx, text_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = std::io::Read::read_to_string(&mut stderr_pipe, &mut text);
        let _ = text_tx.send(text);
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break Some(status);
        }
        if Instant::now() >= deadline {
            // SAFETY: plain kill(2) of the child's own process group.
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let stderr = text_rx.recv_timeout(Duration::from_secs(10)).unwrap_or_default();
    let status = status.unwrap_or_else(|| panic!("fuigo {args:?} did not exit within 60s; stderr:\n{stderr}"));
    (status.code(), stderr)
}

fn assert_refused(args: &[&str], ws_url_env: Option<&str>) {
    let (code, stderr) = run(args, ws_url_env);
    assert_ne!(code, Some(0), "fuigo {args:?} must fail; stderr:\n{stderr}");
    for needle in [
        RELAY_ORIGIN,
        "trusted_origins = [\"https://relay.invalid\"]",
        "[relay]",
        "FUIGO_TRUSTED_RELAY_ORIGINS=https://relay.invalid",
    ] {
        assert!(stderr.contains(needle), "fuigo {args:?}: missing {needle:?} in stderr:\n{stderr}");
    }
}

#[test]
fn headless_through_a_leader_refuses_a_relay_without_an_opt_in() {
    assert_refused(&["--no-auto-update", "agent", "--leader", "headless"], Some(RELAY_URL));
}

/// The relay named with `--fuigo-ws-url` is the one checked (and the one the leader is reached for), not the
/// configured one: here nothing is configured, and the flag names a relay nobody opted in to.
#[test]
fn headless_through_a_leader_checks_the_relay_named_on_the_command_line() {
    assert_refused(
        &["--no-auto-update", "agent", "--leader", "headless", "--fuigo-ws-url", RELAY_URL],
        None,
    );
}

#[test]
fn headless_without_a_leader_refuses_a_relay_without_an_opt_in() {
    assert_refused(&["--no-auto-update", "agent", "--no-leader", "headless"], Some(RELAY_URL));
}
