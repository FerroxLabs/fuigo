//! 74.B16: a command-line argument that is not valid UTF-8 must not crash the program at startup.
//! `--cwd` takes a path, so it accepts the bytes as they are; `-p` takes text, so it gets a usage error (exit 2)
//! rather than a panic (exit 101).

#![cfg(unix)]

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::PathBuf;
use std::process::{Command, Output};

fn pager_binary() -> PathBuf {
    if let Ok(p) = std::env::var("PAGER_BINARY") {
        return std::path::absolute(&p).unwrap_or_else(|e| panic!("absolutize PAGER_BINARY {p}: {e}"));
    }
    option_env!("CARGO_BIN_EXE_fuigo-pager")
        .map(PathBuf::from)
        .expect("PAGER_BINARY is unset and this build is not `cargo test`")
}

fn run(args: &[OsString]) -> Output {
    let root = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(pager_binary());
    cmd.args(args)
        .env("FUIGO_HOME", root.path().join("fuigo-home"))
        .env("HOME", root.path())
        .env_remove("RUST_BACKTRACE");
    cmd.output().expect("run the pager binary")
}

fn invalid_utf8() -> OsString {
    OsString::from_vec(vec![b'b', b'a', 0xff, 0xfe, b'd'])
}

#[test]
fn a_non_utf8_prompt_is_a_usage_error_not_a_crash() {
    let out = run(&[OsString::from("-p"), invalid_utf8()]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "usage error expected\nstderr:\n{stderr}");
    assert!(!stderr.contains("panicked"), "must not panic\nstderr:\n{stderr}");
    assert!(stderr.to_lowercase().contains("utf-8"), "names the problem\nstderr:\n{stderr}");
}

#[test]
fn a_non_utf8_cwd_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let odd = dir.path().join(OsString::from_vec(vec![b'd', 0xff, b'r']));
    std::fs::create_dir(&odd).unwrap();
    assert!(odd.as_os_str().as_bytes().contains(&0xff));
    let out = run(&[OsString::from("--cwd"), odd.into_os_string(), OsString::from("version")]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "--cwd with a non-UTF-8 path\nstderr:\n{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

/// 74.B16 (second half): past argument parsing, the leader client builds its client type from argv. Sandboxing is off
/// (no `--sandbox`), so this is the plain startup path with an existing non-UTF-8 `--cwd`.
#[test]
fn a_non_utf8_cwd_does_not_panic_the_leader_stdio_bridge() {
    let root = tempfile::tempdir().unwrap();
    let odd = root.path().join(OsString::from_vec(vec![b'd', 0xff, b'r']));
    std::fs::create_dir(&odd).unwrap();
    let home = root.path().join("fuigo-home");
    let sock = root.path().join("l.sock");
    let mut bridge = Command::new(pager_binary());
    bridge.env("FUIGO_HOME", &home).env("HOME", root.path()).env_remove("RUST_BACKTRACE").stdin(std::process::Stdio::null());
    bridge.args(vec![
        "--leader-socket".into(),
        sock.clone().into_os_string(),
        "--cwd".into(),
        odd.into_os_string(),
        "agent".into(),
        "--leader".into(),
        "stdio".into(),
    ]);
    #[allow(clippy::disallowed_methods)] // test fixture; waited for below, and its leader is stopped by home
    let mut child = bridge
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run the pager binary");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break Some(s);
        }
        if std::time::Instant::now() > deadline {
            child.kill().ok();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    let out = child.wait_with_output().unwrap();
    // The leader the bridge spawned lives on after it; stop every process that carries this private home.
    stop_processes_with_home(&home);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(status.is_some(), "the bridge did not exit on stdin EOF\nstderr:\n{stderr}");
    assert!(!stderr.contains("panicked"), "must not panic\nstderr:\n{stderr}");
    assert_ne!(status.unwrap().code(), Some(101), "panic exit code\nstderr:\n{stderr}");
}

/// SIGTERM every process (Linux: found through /proc) whose environment names `home` as FUIGO_HOME, then wait for it
/// to go, so the test leaves no leader behind.
fn stop_processes_with_home(home: &std::path::Path) {
    let needle = [b"FUIGO_HOME=".as_slice(), home.as_os_str().as_bytes(), b"\0"].concat();
    let me = std::process::id();
    let find = || -> Vec<u32> {
        let Ok(dir) = std::fs::read_dir("/proc") else { return Vec::new() };
        dir.flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
            .filter(|pid| *pid != me)
            .filter(|pid| {
                std::fs::read(format!("/proc/{pid}/environ"))
                    .is_ok_and(|env| env.windows(needle.len()).any(|w| w == needle.as_slice()))
            })
            .collect()
    };
    for _ in 0..50 {
        let pids = find();
        if pids.is_empty() {
            return;
        }
        for pid in pids {
            Command::new("kill").arg(pid.to_string()).output().ok();
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}
