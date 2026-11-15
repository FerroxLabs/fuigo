//! Run an external helper (ffmpeg, ffprobe, sips) with a wall-clock budget and a stdout cap (audit S9-F2).
//!
//! These helpers run on the draw path, so a crafted or slow input must not block the UI for as long as the helper
//! chooses to run. On a timeout the helper's whole process group is killed and reaped.
//! Same teardown contract as `fuigo_mermaid::subprocess::run_with_timeout`, with stdout captured (that function
//! returns no output, and this crate does not depend on the mermaid crate).

use std::io::Read;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Why a bounded run produced no output.
#[derive(Debug)]
pub enum BoundedError {
    /// The helper could not be spawned (not installed, fork failure).
    Spawn(std::io::Error),
    /// The helper outran its budget and was killed and reaped.
    Timeout,
    /// Waiting on the helper failed; it was killed and reaped.
    Wait(std::io::Error),
}

/// A finished helper run.
#[derive(Debug)]
pub struct BoundedOutput {
    pub status: ExitStatus,
    /// At most `max_stdout` bytes; `truncated` says whether more was produced.
    pub stdout: Vec<u8>,
    pub truncated: bool,
}

/// Spawn `cmd` with stdout piped, wait up to `timeout`, and return its status and at most `max_stdout` stdout bytes.
/// The caller configures stdin, stderr and the TTY detach (`fuigo_tty_utils::detach_std_command`).
pub fn run_bounded(
    mut cmd: Command,
    timeout: Duration,
    max_stdout: usize,
) -> Result<BoundedOutput, BoundedError> {
    cmd.stdout(Stdio::piped());
    #[allow(clippy::disallowed_methods)] // the child is waited for and reaped below on every path
    let mut child = cmd.spawn().map_err(BoundedError::Spawn)?;
    let mut pipe = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(pipe) = pipe.as_mut() {
            let _ = pipe.by_ref().take(max_stdout as u64 + 1).read_to_end(&mut buf);
        }
        buf
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                kill_group_and_reap(&mut child);
                let _ = reader.join();
                return Err(BoundedError::Timeout);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => {
                kill_group_and_reap(&mut child);
                let _ = reader.join();
                return Err(BoundedError::Wait(e));
            }
        }
    };
    let mut stdout = reader.join().unwrap_or_default();
    let truncated = stdout.len() > max_stdout;
    stdout.truncate(max_stdout);
    Ok(BoundedOutput {
        status,
        stdout,
        truncated,
    })
}

fn kill_group_and_reap(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        // The helper is its own group leader (`detach_std_command` runs `setsid`), so its pgid is its pid
        // SAFETY: killpg with a valid pid and a standard signal has no memory effects
        unsafe {
            libc::killpg(child.id() as libc::pid_t, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn detached(mut cmd: Command) -> Command {
        cmd.stdin(Stdio::null()).stderr(Stdio::null());
        fuigo_tty_utils::detach_std_command(&mut cmd);
        cmd
    }

    /// Audit S9-F2: a helper that outruns its budget is killed and reaped, and the call returns promptly.
    #[test]
    fn slow_helper_is_killed_and_reaped_at_the_budget() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let start = Instant::now();
        let r = run_bounded(detached(cmd), Duration::from_millis(200), 1024);
        assert!(matches!(r, Err(BoundedError::Timeout)), "got {r:?}");
        assert!(start.elapsed() < Duration::from_secs(10), "returned only after the helper finished");
    }

    #[test]
    fn grandchild_holding_the_pipe_does_not_outlive_the_timeout() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "sleep 30 & wait"]);
        let start = Instant::now();
        let r = run_bounded(detached(cmd), Duration::from_millis(200), 1024);
        assert!(matches!(r, Err(BoundedError::Timeout)), "got {r:?}");
        assert!(start.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn fast_helper_returns_capped_stdout() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "printf abcdefghij"]);
        let out = run_bounded(detached(cmd), Duration::from_secs(5), 4).unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, b"abcd");
        assert!(out.truncated);
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "printf abc"]);
        let out = run_bounded(detached(cmd), Duration::from_secs(5), 4).unwrap();
        assert_eq!((out.stdout.as_slice(), out.truncated), (&b"abc"[..], false));
    }
}
