//! R077: the workspace-wide print sweep, through the real binary.
//!
//! Release builds are `panic = "abort"`, and `println!` / `eprintln!` panic when the write fails:
//! a dead pipe (EPIPE) or a full disk (ENOSPC) turned a command into a SIGABRT. P05b/P68 swept the
//! pager, the shell CLI modules and fuigo-telemetry; this file covers what the workspace-wide
//! sweep found after them, each reproduced aborting with signal 6 at the parent of R077:
//!
//! - fuigo-update (`fuigo update`): the channel-switch notice and every other progress line went to
//!   stderr with `eprintln!`, and `update --check` printed its status with `println!`.
//! - fuigo-telemetry's `FUIGO_LOG_FILE` filter: an invalid `RUST_LOG` directive was reported by
//!   tracing-subscriber's lossy parse with a raw `eprintln!`.
//! - wayland-backend (fuigo-shared's clipboard probe in `doctor`): a compositor that hangs up was
//!   reported with a raw `eprintln!` (its `log` feature was off).
//! - fuigo-telemetry's console OTEL log exporter (`FUIGO_EXTERNAL_OTEL=1`,
//!   `OTEL_LOGS_EXPORTER=console`): `plugin install` of a missing path emits `plugin_loaded`, which
//!   the exporter writes to stderr from its own batch thread.
//!
//! Each case runs with stdout and stderr live (the control: exit code and what it says), stdout a
//! dead pipe, stdout `/dev/full`, stderr a dead pipe and stderr `/dev/full`. Nothing may die by a
//! signal. A dead reader changes no exit code; a hard stdout failure on a command whose stdout is
//! its result exits 1 (R060); a hard stderr failure changes nothing (R070).
//!
//! Every child gets an empty temporary home as `HOME`, `FUIGO_HOME` and working directory, and no
//! inherited `FUIGO_*` / `OTEL_*` / `npm_*` / `*_proxy` / `WAYLAND_*` / `DISPLAY` /
//! `XDG_RUNTIME_DIR` / `RUST_LOG` variable. The update cases
//! use the internal installer and point `FUIGO_CLI_BASE_URL` at a loopback port the test owns
//! (it hangs up on every request), so they never leave the machine.
#![cfg(unix)]

use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::time::Duration;

fn pager_binary() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("PAGER_BINARY") {
        return std::path::absolute(&p)
            .unwrap_or_else(|e| panic!("failed to absolutize PAGER_BINARY {p}: {e}"));
    }
    option_env!("CARGO_BIN_EXE_fuigo-pager")
        .map(std::path::PathBuf::from)
        .expect("PAGER_BINARY is unset and this build is not `cargo test`")
}

/// The update cases retry the (refused) channel-pointer fetch with backoff, ~8 s in all.
const DEADLINE: Duration = Duration::from_secs(120);

/// A loopback base this test owns: every connection is accepted and closed at once, so the
/// update fetch fails fast and no other process can answer on the port. The listener lives on
/// its accept thread for the rest of the test process.
fn failing_loopback_base() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            drop(stream);
        }
    });
    format!("http://127.0.0.1:{port}")
}

/// A fake Wayland compositor socket at `dir/wayland-r077` that accepts and closes every
/// connection: the client's first read fails, which wayland-backend reports (without its `log`
/// feature) with a raw `eprintln!`. Lives on its accept thread for the rest of the test process.
fn closing_wayland_socket(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).expect("runtime dir");
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).expect("chmod 700");
    let listener =
        std::os::unix::net::UnixListener::bind(dir.join("wayland-r077")).expect("bind wayland");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            drop(stream);
        }
    });
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Out {
    Live,
    DeadPipe,
    #[cfg(target_os = "linux")]
    Full,
}

struct Case {
    name: &'static str,
    args: &'static [&'static str],
    /// Extra environment; `BASE` is replaced by a loopback URL that fails every request,
    /// `HOME/<path>` by a path inside the temporary home.
    env: &'static [(&'static str, &'static str)],
    /// Exit code with both streams live (and with any dead reader, or a hard stderr failure).
    code: i32,
    /// Exit code when stdout fails hard (ENOSPC): 1 when stdout carries the result.
    full_stdout_code: i32,
    /// Exit code when stdout's reader is gone (EPIPE): the live code, except where a command
    /// already reports a broken result pipe itself.
    dead_stdout_code: i32,
    stdout_says: &'static str,
    stderr_says: &'static str,
    /// Serve a closing fake Wayland socket at `HOME/xdg/wayland-r077`.
    wayland: bool,
}

/// The internal installer (an inherited `npm_config_user_agent` would select npm, which ignores
/// `FUIGO_CLI_BASE_URL` and could reach `npm i -g`) against a closed loopback base.
const UPDATE_OFFLINE: &[(&str, &str)] = &[
    ("FUIGO_INSTALLER", "internal"),
    ("FUIGO_CLI_BASE_URL", "BASE"),
];

const CONSOLE_OTEL: &[(&str, &str)] = &[
    ("FUIGO_EXTERNAL_OTEL", "1"),
    ("OTEL_LOGS_EXPORTER", "console"),
    ("OTEL_METRICS_EXPORTER", "console"),
    ("OTEL_TRACES_EXPORTER", "none"),
];

const CASES: &[Case] = &[
    // fuigo-update: "Switched to alpha channel." (stderr), then the status (stdout). The check cannot reach its base,
    // so it exits 1 whatever happens to stdout (P145: a check that could not check is a failure).
    Case {
        name: "update --check",
        args: &["update", "--check", "--alpha"],
        env: UPDATE_OFFLINE,
        code: 1,
        full_stdout_code: 1,
        dead_stdout_code: 1,
        stdout_says: "Update check failed:",
        stderr_says: "Switched to alpha channel.",
        wayland: false,
    },
    // fuigo-update: the notice on stderr, then the fetch error; nothing on stdout.
    Case {
        name: "update",
        args: &["update", "--alpha"],
        env: UPDATE_OFFLINE,
        code: 1,
        full_stdout_code: 1,
        dead_stdout_code: 1,
        stdout_says: "",
        stderr_says: "Switched to alpha channel.",
        wayland: false,
    },
    // fuigo-telemetry console log exporter, written from its batch thread.
    Case {
        name: "plugin install (console OTEL)",
        args: &["plugin", "install", "./nowhere", "--trust"],
        env: CONSOLE_OTEL,
        code: 1,
        full_stdout_code: 1,
        dead_stdout_code: 1,
        stdout_says: "",
        stderr_says: "[external-otel] event=fuigo_code.plugin_loaded",
        wayland: false,
    },
    // fuigo-telemetry's `FUIGO_LOG_FILE` filter honours `RUST_LOG`; tracing-subscriber's lossy
    // parse reported an invalid directive with a raw `eprintln!` ("ignoring `[[[bad`").
    // Since P90 `logout` also reports the subscription store on stdout (`cli_println!`), so a
    // full stdout fails the result with 1 like every other stdout result; a vanished reader does not.
    Case {
        name: "logout (invalid RUST_LOG, FUIGO_LOG_FILE)",
        args: &["logout"],
        env: &[("RUST_LOG", "[[[bad"), ("FUIGO_LOG_FILE", "HOME/fuigo.log")],
        code: 0,
        full_stdout_code: 1,
        dead_stdout_code: 0,
        stdout_says: "All subscription credentials removed locally",
        stderr_says: "No cached session to log out of.",
        wayland: false,
    },
    // fuigo-shared's clipboard data-control probe (`doctor`) against a compositor that hangs up:
    // wayland-backend reported the broken connection with a raw `eprintln!` until its `log`
    // feature was enabled.
    Case {
        name: "doctor (Wayland compositor hangs up)",
        args: &["doctor", "--json"],
        env: &[
            ("XDG_RUNTIME_DIR", "HOME/xdg"),
            ("WAYLAND_DISPLAY", "wayland-r077"),
        ],
        code: 0,
        full_stdout_code: 1,
        // `doctor` reports a broken stdout as `Error: Broken pipe` and exits 1 (its own
        // writer; unchanged here, no signal either way).
        dead_stdout_code: 1,
        stdout_says: "\"id\"",
        stderr_says: "",
        wayland: true,
    },
];

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

/// Run `case` with stdout and stderr attached as given. Returns the status and the captured
/// (stdout, stderr) of the live streams.
fn run(case: &Case, stdout: Out, stderr: Out) -> (std::process::ExitStatus, String, String) {
    let home = tempfile::tempdir().expect("temp home");
    let mut command = Command::new(pager_binary());
    command
        .args(case.args)
        .current_dir(home.path())
        .env("HOME", home.path())
        .env("FUIGO_HOME", home.path().join(".fuigo"))
        .stdin(Stdio::null());
    for (key, _) in std::env::vars_os() {
        let key_text = key.to_string_lossy();
        // Host settings that would steer the child: fuigo/OTEL config, log filters, the npm
        // installer probe, and proxies (a proxy would carry even a loopback request off-box).
        let steering = key_text.starts_with("FUIGO_")
            || key_text.starts_with("OTEL_")
            || key_text == "RUST_LOG"
            || key_text.starts_with("npm_")
            || key_text.starts_with("WAYLAND_")
            || key_text == "DISPLAY"
            || key_text == "XDG_RUNTIME_DIR"
            || key_text.to_ascii_lowercase().ends_with("_proxy");
        if steering && key != "FUIGO_HOME" {
            command.env_remove(key);
        }
    }
    let base = failing_loopback_base();
    if case.wayland {
        closing_wayland_socket(&home.path().join("xdg"));
    }
    for (key, value) in case.env {
        command.env(
            key,
            match *value {
                "BASE" => base.clone(),
                v if v.starts_with("HOME/") => {
                    home.path().join(&v["HOME/".len()..]).display().to_string()
                }
                v => v.to_owned(),
            },
        );
    }
    let (out, out_reader) = attach(stdout);
    let (err, err_reader) = attach(stderr);
    command.stdout(out).stderr(err);
    // The read ends are dropped before the child runs, so its first write gets EPIPE.
    drop(out_reader);
    drop(err_reader);
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
    let out_text = drain(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let err_text = drain(
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
                panic!(
                    "{} (stdout {stdout:?}, stderr {stderr:?}) did not exit within {DEADLINE:?}",
                    case.name
                );
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    };
    (
        status,
        out_text.join().expect("stdout reader"),
        err_text.join().expect("stderr reader"),
    )
}

/// Every case with the given attachment exits with `expected(case)` and no signal.
fn assert_every_case(stdout: Out, stderr: Out, expected: impl Fn(&Case) -> i32) {
    let mut failures = Vec::new();
    for case in CASES {
        let code = expected(case);
        let (status, _, _) = run(case, stdout, stderr);
        if status.signal().is_some() || status.code() != Some(code) {
            failures.push(format!(
                "{}: expected exit {code}, got {status:?} (signal {:?}; 6 = SIGABRT from a \
                 panicking print)",
                case.name,
                status.signal()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "stdout {stdout:?}, stderr {stderr:?}:\n{}",
        failures.join("\n")
    );
}

/// Control: with both streams live each case says what it has to say, where, and exits with the
/// code the other tests expect.
#[test]
fn every_case_with_live_streams_prints_and_exits_with_its_code() {
    for case in CASES {
        let (status, stdout, stderr) = run(case, Out::Live, Out::Live);
        assert_eq!(
            Some(case.code),
            status.code(),
            "{}: {status:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            case.name
        );
        assert!(
            stdout.contains(case.stdout_says),
            "{}: expected {:?} on stdout, got:\n{stdout}",
            case.name,
            case.stdout_says
        );
        assert!(
            stderr.contains(case.stderr_says),
            "{}: expected {:?} on stderr, got:\n{stderr}",
            case.name,
            case.stderr_says
        );
        assert!(!stderr.contains("panicked"), "{}:\n{stderr}", case.name);
        // The invalid directive is dropped silently, not reported by tracing-subscriber's raw print.
        assert!(!stderr.contains("ignoring `"), "{}:\n{stderr}", case.name);
    }
}

#[test]
fn a_dead_stdout_changes_no_exit_code() {
    assert_every_case(Out::DeadPipe, Out::Live, |c| c.dead_stdout_code);
}

#[test]
fn a_dead_stderr_changes_no_exit_code() {
    assert_every_case(Out::Live, Out::DeadPipe, |c| c.code);
}

#[cfg(target_os = "linux")]
#[test]
fn a_full_stdout_fails_the_result_instead_of_aborting() {
    assert_every_case(Out::Full, Out::Live, |c| c.full_stdout_code);
}

#[cfg(target_os = "linux")]
#[test]
fn a_full_stderr_changes_no_exit_code() {
    assert_every_case(Out::Live, Out::Full, |c| c.code);
}
