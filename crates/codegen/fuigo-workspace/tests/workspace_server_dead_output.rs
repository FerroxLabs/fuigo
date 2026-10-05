//! R077: `fuigo-workspace-server` must not die by SIGABRT when its stdout or stderr is gone.
//!
//! Release is `panic = "abort"`; `println!` / `eprintln!` panic on a failed write. At the parent of
//! R077 `--capabilities` with stdout a dead pipe or `/dev/full`, and `--server-id ""` with stderr
//! a dead pipe or `/dev/full`, both aborted with signal 6. Both print best-effort now: a gone
//! reader is not an error; a hard failure of the `--capabilities` result exits 1 (R060); a failed
//! diagnostic keeps the command's own exit code (R070).
#![cfg(unix)]

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

#[derive(Clone, Copy, Debug)]
enum Out {
    Live,
    DeadPipe,
    #[cfg(target_os = "linux")]
    Full,
}

fn attach(mode: Out) -> (Stdio, Option<std::io::PipeReader>) {
    match mode {
        Out::Live => (Stdio::piped(), None),
        Out::DeadPipe => {
            let (reader, writer) = std::io::pipe().expect("pipe");
            (Stdio::from(writer), Some(reader))
        }
        #[cfg(target_os = "linux")]
        Out::Full => {
            let full = std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .expect("/dev/full");
            (Stdio::from(full), None)
        }
    }
}

fn run(args: &[&str], stdout: Out, stderr: Out) -> std::process::Output {
    let dir = tempfile::tempdir().expect("tempdir");
    let (out, out_reader) = attach(stdout);
    let (err, err_reader) = attach(stderr);
    let mut command = Command::new(env!("CARGO_BIN_EXE_fuigo-workspace-server"));
    command
        .args(args)
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err);
    // Dropped before the child runs: its first write to that stream gets EPIPE.
    drop(out_reader);
    drop(err_reader);
    command.output().expect("spawn fuigo-workspace-server")
}

fn assert_exit(args: &[&str], stdout: Out, stderr: Out, code: i32) {
    let out = run(args, stdout, stderr);
    assert!(
        out.status.signal().is_none() && out.status.code() == Some(code),
        "{args:?} stdout {stdout:?} stderr {stderr:?}: expected exit {code}, got {:?} (signal \
         {:?}; 6 = SIGABRT from a panicking print)",
        out.status,
        out.status.signal()
    );
}

const CAPABILITIES: &[&str] = &["--capabilities"];
/// Rejected before anything else starts; the diagnostic is its only output (exit 3).
const BAD_SERVER_ID: &[&str] = &["--server-id", ""];

#[test]
fn live_streams_control() {
    let caps = run(CAPABILITIES, Out::Live, Out::Live);
    assert_eq!(Some(0), caps.status.code(), "{:?}", caps.status);
    serde_json::from_str::<serde_json::Value>(String::from_utf8_lossy(&caps.stdout).trim())
        .expect("capabilities are JSON on stdout");
    let bad = run(BAD_SERVER_ID, Out::Live, Out::Live);
    assert_eq!(Some(3), bad.status.code(), "{:?}", bad.status);
    let stderr = String::from_utf8_lossy(&bad.stderr);
    assert!(stderr.contains("invalid --server-id"), "{stderr}");
}

#[test]
fn a_dead_stdout_keeps_the_capabilities_exit_code() {
    assert_exit(CAPABILITIES, Out::DeadPipe, Out::Live, 0);
}

#[cfg(target_os = "linux")]
#[test]
fn a_full_stdout_fails_capabilities_instead_of_aborting() {
    assert_exit(CAPABILITIES, Out::Full, Out::Live, 1);
}

#[test]
fn a_dead_stderr_keeps_the_server_id_exit_code() {
    assert_exit(BAD_SERVER_ID, Out::Live, Out::DeadPipe, 3);
}

#[cfg(target_os = "linux")]
#[test]
fn a_full_stderr_keeps_the_server_id_exit_code() {
    assert_exit(BAD_SERVER_ID, Out::Live, Out::Full, 3);
}
