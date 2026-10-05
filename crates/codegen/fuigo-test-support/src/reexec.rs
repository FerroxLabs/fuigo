//! Re-run the calling test in a child process with a controlled environment.
//!
//! Some production code reads the process environment once and caches it (`terminal_context()`), or reads it directly (`is_remote_session()`).
//! A test of such code depends on the shell that started the suite.
//! The fix is to run the test body in a child whose environment is set explicitly, in whichever direction the test needs.
//!
//! The child is recognised by a marker variable whose value names the PARENT's pid and the test.
//! A stale marker inherited from an outer shell does not match both, so an ordinary run is not mistaken for a child run.
//! (A marker forged to name the exact launcher pid and test is deliberate misuse, not something this guards against.)

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// SSH variables that make `is_remote_session()` / `terminal_context().is_ssh` report a remote session.
pub const SSH_VARS: [&str; 3] = ["SSH_CONNECTION", "SSH_TTY", "SSH_CLIENT"];

const MARKER: &str = "FUIGO_TEST_REEXEC_CHILD";

/// One environment edit for the child: `Some(v)` sets the variable (an empty `v` sets it empty), `None` removes it.
pub type EnvEdit<'a> = (&'a str, Option<&'a str>);

#[cfg(unix)]
fn parent_pid() -> Option<u32> {
    // SAFETY: getppid has no preconditions and cannot fail.
    Some(unsafe { libc::getppid() } as u32)
}

#[cfg(not(unix))]
fn parent_pid() -> Option<u32> {
    None
}

fn payload_for(raw: &str, ppid: Option<u32>, test: Option<&str>) -> Option<String> {
    let mut parts = raw.splitn(3, '|');
    let (pid, name, payload) = (parts.next()?, parts.next()?, parts.next()?);
    if ppid.is_some_and(|p| pid != p.to_string()) || test != Some(name) {
        return None;
    }
    Some(payload.to_owned())
}

/// The payload the parent passed, when this process is the child that the parent of this process spawned for THIS test; otherwise `None`.
/// The marker names the parent pid (checked where the platform can tell) and the test name, so a marker left in an outer shell does not match.
pub fn child_payload() -> Option<String> {
    let thread = std::thread::current();
    payload_for(&std::env::var(MARKER).ok()?, parent_pid(), thread.name())
}

/// Env var overriding the child deadline, in whole seconds.
pub const TIMEOUT_ENV: &str = "FUIGO_TEST_REEXEC_TIMEOUT_SECS";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

fn parse_timeout(v: Option<&str>) -> Duration {
    v.and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&s| s > 0)
        .map_or(DEFAULT_TIMEOUT, Duration::from_secs)
}

fn timeout_from_env() -> Duration {
    parse_timeout(std::env::var(TIMEOUT_ENV).ok().as_deref())
}

/// Spawn the calling test again (`--exact`, one thread) with `env` applied and `payload` handed to the child; panic unless it passed in time.
/// Call from the parent only. The calling thread must be the test's own (named) thread.
/// The child is killed and the test fails, naming itself, when it runs past the deadline (300 s, or `FUIGO_TEST_REEXEC_TIMEOUT_SECS`).
pub fn run_self_in_child(payload: &str, env: &[EnvEdit<'_>]) {
    if let Err(msg) = try_run_self_in_child(payload, env, timeout_from_env()) {
        panic!("{msg}");
    }
}

/// [`run_self_in_child`] with an explicit deadline and an `Err` instead of a panic.
pub fn try_run_self_in_child(payload: &str, env: &[EnvEdit<'_>], deadline: Duration) -> Result<(), String> {
    let name = std::thread::current()
        .name()
        .filter(|n| *n != "main")
        .map(str::to_owned)
        .expect("run_self_in_child needs a named test thread");
    // A marker naming our own parent means we ARE a child that failed to recognise itself; spawning again would recurse forever.
    if let (Ok(raw), Some(ppid)) = (std::env::var(MARKER), parent_pid())
        && raw.split('|').next() == Some(ppid.to_string().as_str())
    {
        panic!("{name}: re-exec child did not recognise itself (marker {raw:?}); refusing to recurse");
    }
    let mut cmd = Command::new(std::env::current_exe().expect("test executable"));
    cmd.args(["--exact", &name, "--test-threads=1"])
        .env(MARKER, format!("{}|{name}|{payload}", std::process::id()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        match v {
            Some(v) => cmd.env(k, v),
            None => cmd.env_remove(k),
        };
    }
    // The child is waited on below and killed at the deadline, so it cannot outlive this test.
    #[allow(clippy::disallowed_methods)]
    let mut child = cmd.spawn().expect("run the test in a child process");
    let drain = |pipe: Option<Box<dyn std::io::Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut p) = pipe {
                let _ = p.read_to_end(&mut buf);
            }
            buf
        })
    };
    let out_reader = drain(child.stdout.take().map(|p| Box::new(p) as _));
    let err_reader = drain(child.stderr.take().map(|p| Box::new(p) as _));
    let start = Instant::now();
    let (status, timed_out) = loop {
        match child.try_wait().expect("poll the child") {
            Some(status) => break (status, false),
            None if start.elapsed() >= deadline => {
                let _ = child.kill();
                break (child.wait().expect("reap the killed child"), true);
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    let stdout = String::from_utf8_lossy(&out_reader.join().unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&err_reader.join().unwrap_or_default()).into_owned();
    if timed_out {
        return Err(format!(
            "{name}: re-exec child timed out after {deadline:?} and was killed (env {env:?} payload {payload:?}; raise {TIMEOUT_ENV} if the host is slow):\n--- child stdout ---\n{stdout}\n--- child stderr ---\n{stderr}"
        ));
    }
    if status.success() && stdout.contains("1 passed;") {
        return Ok(());
    }
    Err(format!(
        "{name} failed in a child with env {env:?} payload {payload:?} ({status}):\n--- child stdout ---\n{stdout}\n--- child stderr ---\n{stderr}"
    ))
}

/// Run the whole calling test in a child with `env` applied.
/// Returns `true` in the parent once the child passed (the caller returns); `false` in the child, which runs the body.
pub fn rerun_test_with_env(env: &[EnvEdit<'_>]) -> bool {
    if child_payload().is_some() {
        return false;
    }
    run_self_in_child("", env);
    true
}

/// Whether an SSH session variable is set and non-empty in this process (the rule `terminal_context()` and `is_remote_session()` share).
pub fn ambient_ssh_present() -> bool {
    SSH_VARS
        .iter()
        .any(|k| std::env::var_os(k).is_some_and(|v| !v.is_empty()))
}

/// Re-run the calling test in a child whose environment says an SSH session is (`ssh == true`) or is not (`ssh == false`) present.
/// Returns `true` in the parent once the child passed (the caller returns); `false` when this process already matches, or in the child.
pub fn rerun_with_ssh_env(ssh: bool) -> bool {
    if child_payload().is_some() || ambient_ssh_present() == ssh {
        return false;
    }
    let mut env: Vec<EnvEdit<'_>> = SSH_VARS.iter().map(|k| (*k, None)).collect();
    if ssh {
        env[0] = ("SSH_CONNECTION", Some("127.0.0.1 50000 127.0.0.1 22"));
    }
    run_self_in_child("", &env);
    true
}

/// Parent-process guard for tests whose body asserts on a plain local session.
pub fn rerun_without_ambient_ssh() -> bool {
    rerun_with_ssh_env(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_must_name_this_process_parent_and_test() {
        let t = Some("a::b");
        assert_eq!(payload_for("42|a::b|remote", Some(42), t).as_deref(), Some("remote"));
        assert_eq!(payload_for("42|a::b|", Some(42), t).as_deref(), Some(""));
        // A marker inherited from an outer shell: other pid, other test, or malformed.
        assert_eq!(payload_for("41|a::b|remote", Some(42), t), None);
        assert_eq!(payload_for("42|a::c|remote", Some(42), t), None);
        assert_eq!(payload_for("42|a::b|remote", Some(42), Some("main")), None);
        assert_eq!(payload_for("42|a::b|remote", Some(42), None), None);
        assert_eq!(payload_for("remote", Some(42), t), None);
        assert_eq!(payload_for("", Some(42), t), None);
        // Without a parent pid to check (non-unix) the test name still has to match.
        assert_eq!(payload_for("7|a::b|x", None, t).as_deref(), Some("x"));
        assert_eq!(payload_for("7|a::c|x", None, t), None);
    }

    /// The child sees exactly the environment the parent asked for, in both directions, whatever shell started the suite.
    #[test]
    fn child_sees_the_requested_ssh_environment() {
        if let Some(expect) = child_payload() {
            assert_eq!(ambient_ssh_present(), expect == "remote", "{expect}");
            return;
        }
        let none = SSH_VARS.map(|k| (k, None));
        run_self_in_child("local", &none);
        run_self_in_child("remote", &[("SSH_TTY", Some("/dev/pts/3"))]);
        // An empty value is not a session.
        run_self_in_child("local", &[("SSH_CONNECTION", Some("")), ("SSH_TTY", None), ("SSH_CLIENT", None)]);
    }

    /// A child that never finishes is killed at the deadline and the failure names the test.
    #[test]
    fn hanging_child_is_killed_at_the_deadline() {
        if let Some(p) = child_payload() {
            if p == "hang" {
                std::thread::sleep(Duration::from_secs(600));
            }
            return;
        }
        let start = Instant::now();
        let err = try_run_self_in_child("hang", &[], Duration::from_secs(2)).expect_err("a hanging child must fail");
        assert!(start.elapsed() < Duration::from_secs(60), "deadline not enforced: {:?}", start.elapsed());
        assert!(err.contains("timed out"), "{err}");
        assert!(err.contains("reexec::tests::hanging_child_is_killed_at_the_deadline"), "{err}");
    }

    #[test]
    fn timeout_env_overrides_the_default() {
        assert_eq!(parse_timeout(None), Duration::from_secs(300));
        assert_eq!(parse_timeout(Some("45")), Duration::from_secs(45));
        assert_eq!(parse_timeout(Some(" 7 ")), Duration::from_secs(7));
        // Zero, negative and junk fall back to the default rather than disabling the deadline.
        for bad in ["0", "-3", "soon", ""] {
            assert_eq!(parse_timeout(Some(bad)), Duration::from_secs(300), "{bad}");
        }
    }
}
