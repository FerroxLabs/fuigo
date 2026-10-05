//! A stdout whose reader is gone must not turn a CLI subcommand into a crash.
//!
//! `fuigo models | head -1`, a parent that exited, or an Electron host that closed its end of
//! the pipe all leave fd 1 dead: every write fails with EPIPE (SIGPIPE is `SIG_IGN` in Rust
//! binaries). `println!` panics on that failure, and this workspace builds with
//! `panic = "abort"`, so the panic was a SIGABRT and a crash report. Four shipped 1.0.19 crash
//! reports carry exactly that stack, from `fuigo models`' first line
//! (`"You are not authenticated."`). The CLI subcommands now print best-effort
//! (`fuigo_tty_utils::cli_println!`), so the command runs to its normal exit.
//!
//! Covered with a dead stdout: `models` and `sessions list` (both reproduced aborting at the
//! parent of this change), `completions bash|zsh|fish` (clap_complete `expect`s on the writer it
//! is handed), `mcp doctor` (the shell's doctor printer) and `login --provider chatgpt --status`
//! (the shell's subscription printer, dispatched before the main runtime starts). A live-reader
//! control shows the same command still produces its output. On Linux, `/dev/full` stands in for
//! a stdout that fails for a reason other than a gone reader: the run must end with exit 1 and
//! exactly one diagnostic, also when stderr is dead too.
//!
//! Every child gets an empty temporary home as `HOME`, `FUIGO_HOME` and working directory, and
//! no inherited `FUIGO_*` variable, so the host's own install cannot leak in.
//!
//! Unix only: a dead pipe is the Unix failure shape this guards, and the helpers would be dead code on
//! Windows, where every case is excluded.
#![cfg(unix)]

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Resolve the pager binary like the other integration tests: `PAGER_BINARY` under Bazel
/// (runfiles-relative), else cargo's compile-time constant.
fn pager_binary() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("PAGER_BINARY") {
        return std::path::absolute(&p)
            .unwrap_or_else(|e| panic!("failed to absolutize PAGER_BINARY {p}: {e}"));
    }
    option_env!("CARGO_BIN_EXE_fuigo-pager")
        .map(std::path::PathBuf::from)
        .expect("PAGER_BINARY is unset and this build is not `cargo test`")
}

/// Generous bound for an offline CLI subcommand; a hang is reported as a failure, not a stall.
const DEADLINE: Duration = Duration::from_secs(120);

/// The stderr note `best_effort_stdout` writes once per process on a hard stdout failure.
const HARD_FAILURE_NOTE: &str = "fuigo: stdout write failed";

fn command(args: &[&str], home: &std::path::Path) -> Command {
    let mut command = Command::new(pager_binary());
    command
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("FUIGO_HOME", home.join(".fuigo"))
        .stdin(Stdio::null());
    // Nothing from the host install (keys, config paths, endpoints, deployment key) reaches the
    // child; the two variables set above are the only `FUIGO_*` it sees.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("FUIGO_") && key != "FUIGO_HOME" {
            command.env_remove(key);
        }
    }
    command
}

/// Spawn `command`, drain stderr, and wait with a deadline; kill it and fail when the deadline
/// passes. Returns the exit status and stderr.
fn run_bounded(mut command: Command, args: &[&str]) -> (std::process::ExitStatus, String) {
    #[allow(
        clippy::disallowed_methods,
        reason = "the child is waited on below with a deadline and killed and reaped when it \
                  passes, so nothing it starts outlives this function"
    )]
    let mut child = command.spawn().expect("spawn fuigo-pager");
    let mut stderr = child.stderr.take().expect("stderr piped");
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf);
        buf
    });
    let started = std::time::Instant::now();
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => break status,
            None if started.elapsed() > DEADLINE => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{args:?} did not exit within {DEADLINE:?}");
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    };
    let stderr = reader.join().expect("stderr reader");
    (status, String::from_utf8_lossy(&stderr).into_owned())
}

/// Run `args` with stdout attached to a pipe whose read end is already closed, so the child's
/// first stdout write gets EPIPE. Returns the exit status.
fn run_with_dead_stdout(args: &[&str]) -> std::process::ExitStatus {
    let home = tempfile::tempdir().expect("temp home");
    let (reader, writer) = std::io::pipe().expect("pipe");
    let mut command = command(args, home.path());
    command.stdout(Stdio::from(writer)).stderr(Stdio::piped());
    drop(reader);
    let (status, stderr) = run_bounded(command, args);
    assert!(
        !stderr.contains("failed printing to stdout"),
        "{args:?}: a stdout write panicked (this is the SIGABRT in the shipped crash reports):\n{stderr}"
    );
    assert!(
        !stderr.contains("failed to write completion"),
        "{args:?}: clap_complete panicked on the stdout it was handed:\n{stderr}"
    );
    assert!(
        !stderr.contains(HARD_FAILURE_NOTE),
        "{args:?}: a gone reader is not a hard failure and must not be reported as one:\n{stderr}"
    );
    status
}

fn assert_exited_normally(args: &[&str], status: std::process::ExitStatus) {
    use std::os::unix::process::ExitStatusExt;
    assert!(
        status.signal().is_none(),
        "{args:?} with a dead stdout died by signal {:?} (6 = SIGABRT from the panicking \
         write); it must run to a normal exit, status: {status:?}",
        status.signal()
    );
    assert_eq!(
        Some(0),
        status.code(),
        "{args:?} with a dead stdout must still complete and exit 0 (a gone reader is not a \
         failure), status: {status:?}"
    );
}

/// The shipped crash: `fuigo models` with nobody reading stdout.
#[test]
fn models_with_a_dead_stdout_exits_instead_of_aborting() {
    let args = ["models"];
    let status = run_with_dead_stdout(&args);
    assert_exited_normally(&args, status);
}

/// The second subcommand reproduced aborting at the parent of this change.
#[test]
fn sessions_list_with_a_dead_stdout_exits_instead_of_aborting() {
    let args = ["sessions", "list"];
    let status = run_with_dead_stdout(&args);
    assert_exited_normally(&args, status);
}

/// clap_complete writes the script itself and `expect`s on the writer; it must be handed a
/// buffer, never the raw stdout.
#[test]
fn completions_with_a_dead_stdout_exits_instead_of_aborting() {
    for shell in ["bash", "zsh", "fish"] {
        let args = ["completions", shell];
        let status = run_with_dead_stdout(&args);
        assert_exited_normally(&args, status);
    }
}

/// The MCP doctor report is printed by the shell crate.
#[test]
fn mcp_doctor_with_a_dead_stdout_exits_instead_of_aborting() {
    let args = ["mcp", "doctor"];
    let status = run_with_dead_stdout(&args);
    assert_exited_normally(&args, status);
}

/// The subscription printers live in the shell and run before the main runtime starts.
#[test]
fn login_status_with_a_dead_stdout_exits_instead_of_aborting() {
    let args = ["login", "--provider", "chatgpt", "--status"];
    let status = run_with_dead_stdout(&args);
    assert_exited_normally(&args, status);
}

/// Control: with a live reader the same command still says what it has to say, so the
/// best-effort path did not become a silent one.
#[test]
fn sessions_list_with_a_live_reader_still_prints() {
    let home = tempfile::tempdir().expect("temp home");
    let args = ["sessions", "list"];
    let mut command = command(&args, home.path());
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    #[allow(
        clippy::disallowed_methods,
        reason = "the child is waited on with a deadline and killed and reaped when it passes"
    )]
    let mut child = command.spawn().expect("spawn fuigo-pager");
    let mut stdout = child.stdout.take().expect("stdout piped");
    let reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stdout.read_to_string(&mut buf);
        buf
    });
    let mut stderr_pipe = child.stderr.take().expect("stderr piped");
    let stderr_reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr_pipe.read_to_string(&mut buf);
        buf
    });
    let started = std::time::Instant::now();
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => break status,
            None if started.elapsed() > DEADLINE => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{args:?} did not exit within {DEADLINE:?}");
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    };
    let stdout = reader.join().expect("stdout reader");
    let stderr = stderr_reader.join().expect("stderr reader");
    assert_eq!(Some(0), status.code(), "status: {status:?}, stderr:\n{stderr}");
    assert!(
        stdout.contains("No sessions found."),
        "expected the empty-home listing on stdout, got:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// `/dev/full` fails every write with ENOSPC: not a gone reader, so the output is truncated and
/// the run must say so, once, and exit 1. Multiple lines must not repeat the note.
#[cfg(target_os = "linux")]
#[test]
fn a_failing_stdout_exits_one_with_a_single_diagnostic() {
    let home = tempfile::tempdir().expect("temp home");
    let args = ["sessions", "list"];
    let mut command = command(&args, home.path());
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("/dev/full");
    command.stdout(Stdio::from(full)).stderr(Stdio::piped());
    let (status, stderr) = run_bounded(command, &args);
    assert_eq!(Some(1), status.code(), "status: {status:?}, stderr:\n{stderr}");
    assert_eq!(
        1,
        stderr.matches(HARD_FAILURE_NOTE).count(),
        "exactly one note per process, got stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked"),
        "a failing stdout must never panic (SIGABRT under panic=abort):\n{stderr}"
    );
}

/// The same hard failure with stderr also dead: the note cannot be written, and that must be
/// silent too. Still exit 1, still no signal.
#[cfg(target_os = "linux")]
#[test]
fn a_failing_stdout_with_a_dead_stderr_still_exits_one_without_aborting() {
    use std::os::unix::process::ExitStatusExt;
    let home = tempfile::tempdir().expect("temp home");
    let args = ["sessions", "list"];
    let mut command = command(&args, home.path());
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("/dev/full");
    let (reader, writer) = std::io::pipe().expect("pipe");
    command.stdout(Stdio::from(full)).stderr(Stdio::from(writer));
    drop(reader);
    #[allow(
        clippy::disallowed_methods,
        reason = "the child is waited on with a deadline and killed and reaped when it passes"
    )]
    let mut child = command.spawn().expect("spawn fuigo-pager");
    let started = std::time::Instant::now();
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => break status,
            None if started.elapsed() > DEADLINE => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{args:?} did not exit within {DEADLINE:?}");
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    };
    assert!(
        status.signal().is_none(),
        "died by signal {:?}; status: {status:?}",
        status.signal()
    );
    assert_eq!(Some(1), status.code(), "status: {status:?}");
}
