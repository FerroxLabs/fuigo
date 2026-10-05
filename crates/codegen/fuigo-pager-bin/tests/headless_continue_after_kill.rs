//! P143: `fuigo --continue -p` after a `-p` run was SIGKILLed mid-turn, at the PROCESS boundary (the built
//! `fuigo-pager` binary).
//!
//! The 1.0.21 RC hung the first `--continue` forever: the load recorded the lost turn, then awaited the client's
//! handling of the live interrupted-turn marker it forwards to a no-replay load. The headless client handles
//! notifications only once its `session/load` request has returned, so neither side could move. 1.0.20 had no
//! marker and ran the same step in well under a second.
//!
//! Also pins B23's other half: while another live process holds the session's exclusive recovery lock, the load
//! fails after the 60 s bound with the "being recovered by another Fuigo process" message instead of waiting forever,
//! and once that process lets go the next `--continue` recovers the turn and tells the model.

// Unix only: real signals, process groups and `flock` (`libc` is a Unix-only dependency of this package).
#![cfg(unix)]

use std::io::Read as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use fuigo_test_support::{MockInferenceServer, TestSandbox};

/// `InterruptedTurn::model_reminder`: what the next request must carry once the lost turn is recovered.
const REMINDER: &str = "The previous turn was interrupted";
/// `OwnerLockBusy::into_acp_error`.
const BUSY: &str = "being recovered by another Fuigo process";

fn pager_binary() -> PathBuf {
    if let Ok(p) = std::env::var("PAGER_BINARY") {
        return std::path::absolute(&p)
            .unwrap_or_else(|e| panic!("failed to absolutize PAGER_BINARY {p}: {e}"));
    }
    option_env!("CARGO_BIN_EXE_fuigo-pager")
        .map(PathBuf::from)
        .expect("PAGER_BINARY is unset and this build is not `cargo test`")
}

struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    elapsed: Duration,
}

/// Spawns `fuigo-pager <args>` in its own process group, so a kill reaches every process it started.
fn spawn(sandbox: &TestSandbox, args: &[&str]) -> std::process::Child {
    let mut cmd = std::process::Command::new(pager_binary());
    sandbox.apply_to_std_command(&mut cmd);
    cmd.env("FUIGO_MAX_RETRIES", "0")
        .args(args)
        .current_dir(sandbox.workspace())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    #[allow(clippy::disallowed_methods)] // test-owned child, waited on (or killed and reaped) by the caller
    cmd.spawn().expect("spawn fuigo-pager")
}

fn kill_group(child: &mut std::process::Child) {
    // SAFETY: kill(2) on the process group this test created for its own child.
    unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
    let _ = child.wait();
}

/// Kills (and reaps) the child's whole group however the test leaves, a failed assertion included.
struct GroupGuard(std::process::Child);

impl Drop for GroupGuard {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            kill_group(&mut self.0);
        }
    }
}

/// Runs `args` to the end; a run still going after `limit` is killed and fails the test as a hang.
fn run(sandbox: &TestSandbox, args: &[&str], limit: Duration) -> Out {
    let started = Instant::now();
    let mut guard = GroupGuard(spawn(sandbox, args));
    let child = &mut guard.0;
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let (tx_out, rx_out) = std::sync::mpsc::channel();
    let (tx_err, rx_err) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = so.read_to_end(&mut b);
        let _ = tx_out.send(String::from_utf8_lossy(&b).into_owned());
    });
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = se.read_to_end(&mut b);
        let _ = tx_err.send(String::from_utf8_lossy(&b).into_owned());
    });
    let status = loop {
        if let Some(st) = child.try_wait().expect("try_wait") {
            break st;
        }
        if started.elapsed() > limit {
            kill_group(child);
            let stderr = rx_err.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
            panic!(
                "`{}` hung: still running after {}s with no result\nstderr:\n{stderr}",
                args.join(" "),
                limit.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let elapsed = started.elapsed();
    let collect = |rx: std::sync::mpsc::Receiver<String>, what: &str| {
        rx.recv_timeout(Duration::from_secs(20))
            .unwrap_or_else(|_| panic!("{what} did not close after the run ended: {args:?}"))
    };
    Out {
        code: status.code(),
        stdout: collect(rx_out, "stdout"),
        stderr: collect(rx_err, "stderr"),
        elapsed,
    }
}

/// The one session directory the sandbox holds (the parent of its `events.jsonl`).
fn session_dir(sandbox: &TestSandbox) -> Option<PathBuf> {
    fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.file_name().is_some_and(|n| n == "events.jsonl") {
                found.push(dir.to_path_buf());
            }
        }
    }
    let mut found = Vec::new();
    walk(&sandbox.fuigo_home().join("sessions"), &mut found);
    assert!(found.len() <= 1, "one session expected: {found:?}");
    found.pop()
}

fn turn_started(sandbox: &TestSandbox) -> bool {
    session_dir(sandbox).is_some_and(|dir| {
        std::fs::read_to_string(dir.join("events.jsonl"))
            .is_ok_and(|events| events.contains("turn_started"))
    })
}

fn model_request_in_flight(server: &MockInferenceServer) -> bool {
    server.requests().iter().any(|e| {
        e.method == "POST" && (e.path.contains("completions") || e.path.contains("responses"))
    })
}

/// How often the interrupted-turn reminder appears in each model request since `from`.
fn reminders_since(server: &MockInferenceServer, from: usize) -> Vec<usize> {
    server
        .request_bodies()
        .iter()
        .skip(from)
        .map(|body| body.to_string().matches(REMINDER).count())
        .collect()
}

/// The continuation's model requests carry the reminder, never more than one copy each (side requests such as a
/// title may carry none).
fn assert_told_once(server: &MockInferenceServer, from: usize) {
    let counts = reminders_since(server, from);
    assert!(
        counts.contains(&1) && counts.iter().all(|&n| n <= 1),
        "the model is told exactly once: {counts:?}"
    );
}

/// Durable interrupted-turn markers in the session's `updates.jsonl`.
fn markers_on_disk(sandbox: &TestSandbox) -> usize {
    std::fs::read_to_string(session_dir(sandbox).unwrap().join("updates.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains("\"turn_completed\"") && l.contains("\"interrupted\""))
        .count()
}

/// A `-p` run whose model reply never arrives, SIGKILLed (with everything it started) once its turn is open
/// on disk and its model request is in flight: the turn is lost with its process.
fn lose_a_turn(server: &MockInferenceServer, sandbox: &TestSandbox) {
    server.set_chunk_delay(Some(Duration::from_secs(600)));
    let mut guard = GroupGuard(spawn(
        sandbox,
        &["-p", "first", "--trust", "--output-format", "streaming-json"],
    ));
    let child = &mut guard.0;
    let deadline = Instant::now() + Duration::from_secs(60);
    while !(turn_started(sandbox) && model_request_in_flight(server)) {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!("the first run ended before its turn was in flight: {status}");
        }
        assert!(Instant::now() < deadline, "the first run never put its turn in flight");
        std::thread::sleep(Duration::from_millis(25));
    }
    kill_group(child);
    server.set_chunk_delay(None);
    let events = std::fs::read_to_string(session_dir(sandbox).unwrap().join("events.jsonl")).unwrap();
    assert!(
        !events.contains("turn_ended"),
        "the killed run must leave its turn open:\n{events}"
    );
}

const CONTINUE: [&str; 6] = ["--continue", "-p", "again", "--trust", "--output-format", "json"];

/// The regression: the first `--continue` after the kill must run, not hang, and tell the model.
/// Mutant discriminated: awaiting the live marker's delivery inside `load_session`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn continue_after_a_killed_turn_runs_and_tells_the_model() {
    let server = MockInferenceServer::start().await.expect("start the mock inference server");
    server.preset_allow_access();
    let sandbox = TestSandbox::builder().git().mock_url(server.url()).build();
    let server = std::sync::Arc::new(server);
    let (s, sb) = (server.clone(), sandbox);
    let (out, sandbox) = tokio::task::spawn_blocking(move || {
        lose_a_turn(&s, &sb);
        let before = s.request_bodies().len();
        let out = run(&sb, &CONTINUE, Duration::from_secs(45));
        assert_told_once(&s, before);
        assert_eq!(markers_on_disk(&sb), 1, "one durable interrupted marker");
        // A second continuation finds the turn already recorded: no second marker, no second reminder.
        let again = s.request_bodies().len();
        let second = run(&sb, &CONTINUE, Duration::from_secs(45));
        assert_eq!(second.code, Some(0), "second run\nstderr:\n{}", second.stderr);
        assert!(
            reminders_since(&s, again).iter().all(|&n| n <= 1),
            "the history keeps the one reminder, nothing is added: {:?}",
            reminders_since(&s, again)
        );
        assert_eq!(markers_on_disk(&sb), 1, "still one durable interrupted marker");
        (out, sb)
    })
    .await
    .unwrap();
    assert_eq!(out.code, Some(0), "stdout:\n{}\nstderr:\n{}", out.stdout, out.stderr);
    let dir = session_dir(&sandbox).unwrap();
    let events = std::fs::read_to_string(dir.join("events.jsonl")).unwrap();
    assert!(
        events.contains("\"outcome\":\"interrupted\""),
        "the lost turn is recorded as interrupted:\n{events}"
    );
}

/// B23's bound: another live process holds the recovery lock, so the load fails after 60 s with the documented
/// message (and no model request); once that process lets go, `--continue` recovers the turn.
/// Mutant discriminated: an unbounded wait in `TurnOwnerLock::acquire`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_recoverer_elsewhere_bounds_the_load_then_releases_it() {
    let server = MockInferenceServer::start().await.expect("start the mock inference server");
    server.preset_allow_access();
    let sandbox = TestSandbox::builder().git().mock_url(server.url()).build();
    let server = std::sync::Arc::new(server);
    let s = server.clone();
    tokio::task::spawn_blocking(move || {
        lose_a_turn(&s, &sandbox);
        let dir = session_dir(&sandbox).unwrap();
        // This test process is the other live process: it holds the exclusive lock a recovery holds.
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join("turn_owner.lock"))
            .expect("open the turn owner lock");
        use std::os::fd::AsRawFd as _;
        // SAFETY: flock(2) on a descriptor this test owns.
        let rc = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(rc, 0, "the killed run must have released the session");

        let before = s.request_bodies().len();
        let busy = run(&sandbox, &CONTINUE, Duration::from_secs(120));
        assert_ne!(busy.code, Some(0), "stdout:\n{}\nstderr:\n{}", busy.stdout, busy.stderr);
        assert!(
            busy.stdout.contains(BUSY) || busy.stderr.contains(BUSY),
            "the refusal names the other process\nstdout:\n{}\nstderr:\n{}",
            busy.stdout,
            busy.stderr
        );
        assert!(
            busy.elapsed >= Duration::from_secs(55) && busy.elapsed < Duration::from_secs(100),
            "the refusal comes after the 60 s bound, not before and not much later: {:?}",
            busy.elapsed
        );
        assert_eq!(s.request_bodies().len(), before, "no model request while the session is held");
        let events = std::fs::read_to_string(dir.join("events.jsonl")).unwrap();
        assert!(!events.contains("turn_ended"), "a held session's turn is not declared lost:\n{events}");

        drop(lock);
        let out = run(&sandbox, &CONTINUE, Duration::from_secs(45));
        assert_eq!(out.code, Some(0), "stdout:\n{}\nstderr:\n{}", out.stdout, out.stderr);
        assert_told_once(&s, before);
        assert_eq!(markers_on_disk(&sandbox), 1, "one durable interrupted marker");
    })
    .await
    .unwrap();
}

/// Astra r1 HIGH: a session whose log holds a background task with no completion (its process died with the
/// session) gets a synthetic `task_completed` on load. The no-replay load must not wait for the headless client to
/// handle it, or `--continue -p` hangs exactly as the marker did. Present in 1.0.20 too.
/// Mutant discriminated: awaiting the reconciliation completions under `no_replay`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn continue_with_a_stale_background_task_runs() {
    let server = MockInferenceServer::start().await.expect("start the mock inference server");
    server.preset_allow_access();
    let sandbox = TestSandbox::builder().git().mock_url(server.url()).build();
    tokio::task::spawn_blocking(move || {
        let first = run(&sandbox, &["-p", "first", "--trust", "--output-format", "json"], Duration::from_secs(45));
        assert_eq!(first.code, Some(0), "first run\nstderr:\n{}", first.stderr);
        let dir = session_dir(&sandbox).unwrap();
        let updates = dir.join("updates.jsonl");
        let session_id = dir.file_name().unwrap().to_string_lossy().into_owned();
        let line = serde_json::json!({
            "method": "_fuigo/session/update",
            "params": {
                "sessionId": session_id,
                "update": {
                    "sessionUpdate": "task_backgrounded",
                    "tool_call_id": "call-p143",
                    "task_id": "task-p143",
                    "command": "sleep 999",
                    "cwd": sandbox.workspace().display().to_string(),
                },
            },
        });
        let mut log = std::fs::read_to_string(&updates).expect("read updates.jsonl");
        if !log.ends_with('\n') {
            log.push('\n');
        }
        log.push_str(&format!("{line}\n"));
        std::fs::write(&updates, log).expect("write updates.jsonl");

        let out = run(&sandbox, &CONTINUE, Duration::from_secs(45));
        assert_eq!(out.code, Some(0), "stdout:\n{}\nstderr:\n{}", out.stdout, out.stderr);
    })
    .await
    .unwrap();
}
