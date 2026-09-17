//! `fuigo-workspace-server` argument validation, exercised through the real binary.
//!
//! The one thing a unit test on `validate_before_daemonize` cannot catch is WHERE it is
//! called: after `daemonize()` has forked and taken the pidfile, the same error lands in the
//! daemon's log file and the user's terminal sees a silent exit 0. These tests run the binary.

use std::process::Command;

fn server() -> Command {
    Command::new(env!("CARGO_BIN_EXE_fuigo-workspace-server"))
}

/// `--daemonize` with no `--hub-url`: the error must reach the caller's stderr with a non-zero
/// exit, and neither the log file nor the pidfile may be created — proof that `daemonize()`
/// never ran. There is no default hub, so this is the ordinary "forgot the flag" path.
#[test]
fn daemonize_without_a_hub_url_fails_before_forking() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("server.log");
    let pid = dir.path().join("server.pid");
    let out = server()
        .args(["--daemonize", "--log-file"])
        .arg(&log)
        .arg("--pid-file")
        .arg(&pid)
        .arg("--cwd")
        .arg(dir.path())
        .output()
        .expect("spawn fuigo-workspace-server");

    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !out.status.success(),
        "must exit non-zero; status={:?} stderr={stderr}",
        out.status
    );
    assert!(
        stderr.contains("--hub-url is required"),
        "the user's terminal must carry the reason, got: {stderr}"
    );
    assert!(
        !log.exists(),
        "daemonize() forked before validation: {} was created",
        log.display()
    );
    assert!(
        !pid.exists(),
        "a pidfile was taken for a run that can never start: {}",
        pid.display()
    );
}

/// A malformed `--hub-url` takes the same early exit, for the same reason.
#[test]
fn daemonize_with_an_unparseable_hub_url_fails_before_forking() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("server.log");
    let pid = dir.path().join("server.pid");
    let out = server()
        .args(["--daemonize", "--hub-url", "not a url", "--log-file"])
        .arg(&log)
        .arg("--pid-file")
        .arg(&pid)
        .arg("--cwd")
        .arg(dir.path())
        .output()
        .expect("spawn fuigo-workspace-server");

    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(!out.status.success(), "status={:?}", out.status);
    assert!(stderr.contains("invalid --hub-url"), "{stderr}");
    assert!(!log.exists(), "{} was created", log.display());
    assert!(!pid.exists(), "{} was created", pid.display());
}

/// `--capabilities` is a probe and must still work with no hub configured at all: the
/// validation sits after that early return, not before it.
#[test]
fn capabilities_probe_needs_no_hub_url() {
    let out = server()
        .arg("--capabilities")
        .output()
        .expect("spawn fuigo-workspace-server");
    assert!(
        out.status.success(),
        "status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str::<serde_json::Value>(stdout.trim())
        .expect("capabilities must be JSON on stdout");
}
