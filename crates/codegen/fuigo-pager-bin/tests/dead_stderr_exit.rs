//! A closed terminal pane must not turn an exit into a crash.
//!
//! When the pane the pager was running in is closed, fd 2's reader is gone and every write to it
//! fails with EPIPE. `eprintln!` panics on that failure, and this workspace builds with
//! `panic = "abort"`, so the panic is a SIGABRT: the user sees a crash (and a crash report on the
//! next launch) instead of a clean exit. The user-facing exit reports therefore write
//! best-effort: one attempt, failure reported rather than raised.
//!
//! `fuigo setup` without a deployment key is the cheapest such path: it prints its report to
//! stderr and exits 1, offline, with no terminal and no session.

use std::process::{Command, Stdio};

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

#[cfg(unix)]
#[test]
fn exit_report_with_a_dead_stderr_exits_instead_of_aborting() {
    let home = tempfile::tempdir().expect("temp home");

    // The read end is dropped before the child runs, so its first stderr write gets EPIPE.
    let (reader, writer) = std::io::pipe().expect("pipe");
    let mut command = Command::new(pager_binary());
    command
        .arg("setup")
        .env("HOME", home.path())
        .env("FUIGO_HOME", home.path().join(".fuigo"))
        .env_remove("FUIGO_DEPLOYMENT_KEY")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(writer));
    drop(reader);

    let status = command.status().expect("spawn fuigo setup");

    assert_eq!(
        Some(1),
        status.code(),
        "a dead stderr must still exit(1); a `None` code is death by signal (SIGABRT from the \
         panicking write), status: {status:?}"
    );
}
