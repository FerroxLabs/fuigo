//! A dead or failing stderr must not turn a command into a crash, nor change its exit code.
//!
//! When the pane the pager was running in is closed, or `fuigo … 2>&1 | head` loses its reader,
//! fd 2's reader is gone and every write to it fails with EPIPE (SIGPIPE is `SIG_IGN` in Rust
//! binaries); a stderr on a full disk fails with ENOSPC. `eprintln!` panics on either failure,
//! and this workspace builds with `panic = "abort"`, so the panic was a SIGABRT: the user saw a
//! crash (and a crash report on the next launch) instead of the command's own exit, and a script
//! saw death by signal 6 instead of the exit code it branches on. Diagnostics now print
//! best-effort (`fuigo_tty_utils::cli_eprintln!`), and a failed diagnostic changes nothing.
//!
//! Covered, each with stderr as a dead pipe, as `/dev/full` (Linux) and closed (`2>&-`):
//! `logout` with no session (a success path that only talks on stderr), `mcp enable` / `mcp
//! remove` of an unknown server and `plugin install` without `--trust` (error paths: message on
//! stderr, then exit 1) — all four reproduced aborting with signal 6 at the parent of this
//! change — plus `setup` without a deployment key, an unknown flag (clap's usage error, exit 2)
//! and a headless prompt that is not authenticated (exit 1). The expected code of every case is
//! the code the same command exits with when stderr is live, which a control test pins. The same
//! holds for fuigo-telemetry's startup diagnostics (a bad `FUIGO_OTEL_FILTER`, an unwritable
//! `FUIGO_INSTRUMENTATION_LOG` in log and chrome mode), which print before any subcommand runs.
//!
//! Every child gets an empty temporary home as `HOME`, `FUIGO_HOME` and working directory, and
//! no inherited `FUIGO_*` variable, so the host's own install cannot leak in.
#![cfg(unix)]

use std::io::Read;
use std::os::unix::process::ExitStatusExt;
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

/// Each case: the arguments, the exit code the command ends with when stderr is live, and a
/// fragment of what it says on a live stderr (the control proves the message still lands).
const CASES: &[(&[&str], i32, &str)] = &[
    (&["logout"], 0, "No cached session to log out of."),
    (
        &["mcp", "enable", "no-such-server"],
        1,
        "No MCP server named 'no-such-server'.",
    ),
    (
        &["mcp", "remove", "no-such-server"],
        1,
        "No MCP server named 'no-such-server'",
    ),
    (
        &["plugin", "install", "./nowhere"],
        1,
        "requires confirmation",
    ),
    (&["setup"], 1, "No deployment key or team sign-in found."),
    (
        &["--definitely-not-a-flag"],
        2,
        "unexpected argument '--definitely-not-a-flag'",
    ),
    (&["-p", "hello"], 1, "Not signed in"),
];

/// Telemetry diagnostics printed while the pager builds its tracing layers, before any
/// subcommand runs (fuigo-telemetry). Each: the environment that triggers the diagnostic, the
/// command, its live exit code, and the diagnostic. All reproduced aborting with signal 6 at the
/// parent of P68's telemetry sweep when stderr is dead or full.
/// `(environment, arguments, live exit code, live stderr fragment)`.
type TelemetryCase = (
    &'static [(&'static str, &'static str)],
    &'static [&'static str],
    i32,
    &'static str,
);

const TELEMETRY_CASES: &[TelemetryCase] = &[
    (
        &[("FUIGO_OTEL_FILTER", "[[[bad")],
        &["logout"],
        0,
        "[otel] Invalid FUIGO_OTEL_FILTER '[[[bad'",
    ),
    (
        &[
            ("FUIGO_INSTRUMENTATION", "log"),
            ("FUIGO_INSTRUMENTATION_LOG", "/dev/null/p68.json"),
        ],
        &["logout"],
        0,
        "Failed to create instrumentation log directory",
    ),
    (
        &[
            ("FUIGO_INSTRUMENTATION", "chrome"),
            ("FUIGO_INSTRUMENTATION_LOG", "/dev/null/p68-trace.json"),
        ],
        &["logout"],
        0,
        "Failed to create chrome trace directory",
    ),
    // The trace path is a directory: the open fails after the directory step passes.
    (
        &[
            ("FUIGO_INSTRUMENTATION", "log"),
            ("FUIGO_INSTRUMENTATION_LOG", "/"),
        ],
        &["logout"],
        0,
        "Failed to open instrumentation log file",
    ),
    (
        &[
            ("FUIGO_INSTRUMENTATION", "chrome"),
            ("FUIGO_INSTRUMENTATION_LOG", "/"),
        ],
        &["logout"],
        0,
        "Failed to open chrome trace file",
    ),
    // The trace file opens but every write fails (ENOSPC). Chrome: its worker `unwrap`s the JSON
    // framing it writes and flushes at shutdown, which `logout` reaches (signal 6 at the parent
    // even with a live stderr). Log: `logout` emits no instrumentation event, so this pins only a
    // clean start and exit; the appender write path over `/dev/full` is fuigo-telemetry's
    // `the_appender_worker_over_a_full_disk_drains_without_panicking`. (Where `/dev/full` does not
    // exist the open fails instead, which is the case above.)
    (
        &[
            ("FUIGO_INSTRUMENTATION", "chrome"),
            ("FUIGO_INSTRUMENTATION_LOG", "/dev/full"),
        ],
        &["logout"],
        0,
        "No cached session to log out of.",
    ),
    (
        &[
            ("FUIGO_INSTRUMENTATION", "log"),
            ("FUIGO_INSTRUMENTATION_LOG", "/dev/full"),
        ],
        &["logout"],
        0,
        "No cached session to log out of.",
    ),
];

/// How stderr is attached to the child.
#[derive(Clone, Copy, Debug)]
enum Stderr {
    /// A pipe captured by the test (the control).
    Live,
    /// A pipe whose read end is closed before the child runs: every write gets EPIPE.
    DeadPipe,
    /// `/dev/full`: every write gets ENOSPC.
    #[cfg(target_os = "linux")]
    Full,
    /// fd 2 closed (`2>&-`), via a shell that closes it and then execs the binary.
    Closed,
}

/// Run `args` against an empty home with stderr attached as `mode`; stdout is captured so the
/// test never depends on the harness's own stdout. Returns the exit status and, for
/// [`Stderr::Live`], what was written to stderr.
fn run(args: &[&str], mode: Stderr) -> (std::process::ExitStatus, String) {
    run_with_env(&[], args, mode)
}

/// [`run`] with extra environment variables (set after the `FUIGO_*` scrub).
fn run_with_env(
    env: &[(&str, &str)],
    args: &[&str],
    mode: Stderr,
) -> (std::process::ExitStatus, String) {
    let home = tempfile::tempdir().expect("temp home");
    let bin = pager_binary();
    let mut command = match mode {
        Stderr::Closed => {
            let mut sh = Command::new("/bin/sh");
            sh.arg("-c")
                .arg("exec \"$0\" \"$@\" 2>&-")
                .arg(&bin)
                .args(args);
            sh
        }
        _ => {
            let mut c = Command::new(&bin);
            c.args(args);
            c
        }
    };
    command
        .current_dir(home.path())
        .env("HOME", home.path())
        .env("FUIGO_HOME", home.path().join(".fuigo"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
    // Nothing from the host install (keys, config paths, endpoints, deployment key) reaches the
    // child; the two variables set above are the only `FUIGO_*` it sees.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("FUIGO_") && key != "FUIGO_HOME" {
            command.env_remove(key);
        }
    }
    command.envs(env.iter().copied());
    let mut dead_reader = None;
    match mode {
        Stderr::Live => {
            command.stderr(Stdio::piped());
        }
        Stderr::DeadPipe => {
            let (reader, writer) = std::io::pipe().expect("pipe");
            command.stderr(Stdio::from(writer));
            dead_reader = Some(reader);
        }
        #[cfg(target_os = "linux")]
        Stderr::Full => {
            let full = std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .expect("/dev/full");
            command.stderr(Stdio::from(full));
        }
        Stderr::Closed => {
            command.stderr(Stdio::null());
        }
    }
    // The read end is dropped before the child runs, so its first stderr write gets EPIPE.
    drop(dead_reader);
    #[allow(
        clippy::disallowed_methods,
        reason = "the child is waited on below with a deadline and killed and reaped when it \
                  passes, so nothing it starts outlives this function"
    )]
    let mut child = command.spawn().expect("spawn fuigo-pager");
    let drain = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut buf);
            }
            String::from_utf8_lossy(&buf).into_owned()
        })
    };
    let stdout = drain(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let stderr = drain(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let started = std::time::Instant::now();
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => break status,
            None if started.elapsed() > DEADLINE => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{args:?} ({mode:?}) did not exit within {DEADLINE:?}");
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    };
    let _ = stdout.join().expect("stdout reader");
    (status, stderr.join().expect("stderr reader"))
}

/// Every case, with stderr attached as `mode`, exits with its live-stderr code and no signal.
fn assert_every_case_exits_normally(mode: Stderr) {
    let mut failures = Vec::new();
    let all = CASES
        .iter()
        .map(|(args, code, _)| (&[][..], *args, *code))
        .chain(
            TELEMETRY_CASES
                .iter()
                .map(|(env, args, code, _)| (*env, *args, *code)),
        );
    for (env, args, code) in all {
        let (status, _) = run_with_env(env, args, mode);
        if status.signal().is_some() || status.code() != Some(code) {
            failures.push(format!(
                "{env:?} {args:?}: expected exit {code}, got {status:?} (signal {:?}; 6 = SIGABRT \
                 from a panicking stderr write)",
                status.signal()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "with stderr {mode:?} every command must end exactly as it does with a live stderr:\n{}",
        failures.join("\n")
    );
}

/// Control: with a live stderr each case says what it has to say and exits with the code the
/// dead-stderr tests expect, so best-effort did not become silent and the codes are real.
#[test]
fn every_case_with_a_live_stderr_prints_and_exits_with_its_code() {
    for (args, code, says) in CASES {
        let (status, stderr) = run(args, Stderr::Live);
        assert_eq!(Some(*code), status.code(), "{args:?}: {status:?}\n{stderr}");
        assert!(
            stderr.contains(says),
            "{args:?}: expected {says:?} on stderr, got:\n{stderr}"
        );
        assert!(!stderr.contains("panicked"), "{args:?}:\n{stderr}");
    }
    for (env, args, code, says) in TELEMETRY_CASES {
        let (status, stderr) = run_with_env(env, args, Stderr::Live);
        assert_eq!(
            Some(*code),
            status.code(),
            "{env:?} {args:?}: {status:?}\n{stderr}"
        );
        assert!(
            stderr.contains(says),
            "{env:?} {args:?}: expected {says:?} on stderr, got:\n{stderr}"
        );
        assert!(!stderr.contains("panicked"), "{env:?} {args:?}:\n{stderr}");
    }
}

/// The closed-pane / gone-reader shape: EPIPE on every stderr write.
#[test]
fn every_case_with_a_dead_stderr_exits_instead_of_aborting() {
    assert_every_case_exits_normally(Stderr::DeadPipe);
}

/// A hard stderr failure (ENOSPC) is not a reason to fail, or to crash: the exit code is the
/// command's own.
#[cfg(target_os = "linux")]
#[test]
fn every_case_with_a_full_stderr_keeps_its_exit_code() {
    assert_every_case_exits_normally(Stderr::Full);
}

/// `2>&-`: the runtime reopens a closed fd 2 on `/dev/null` before `main`; nothing may change.
#[test]
fn every_case_with_a_closed_stderr_keeps_its_exit_code() {
    assert_every_case_exits_normally(Stderr::Closed);
}

/// The original U048 case, kept by name: `fuigo setup` without a deployment key prints its
/// report to stderr and exits 1, offline, with no terminal and no session.
#[test]
fn exit_report_with_a_dead_stderr_exits_instead_of_aborting() {
    let (status, _) = run(&["setup"], Stderr::DeadPipe);
    assert_eq!(
        Some(1),
        status.code(),
        "a dead stderr must still exit(1); a `None` code is death by signal (SIGABRT from the \
         panicking write), status: {status:?}"
    );
}
