//! `fuigo-workspace-server` argument validation, exercised through the real binary.
//!
//! The one thing a unit test on `validate_before_daemonize` cannot catch is WHERE it is
//! called: after `daemonize()` has forked and taken the pidfile, the same error lands in the
//! daemon's log file and the user's terminal sees a silent exit 0. These tests run the binary.

use std::process::Command;

fn server() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fuigo-workspace-server"));
    // Plain log text: the server colours its log lines unless NO_COLOR is set, and an escape
    // code inside `profile=minimal` would fail a positive match or pass a negative one.
    command.env("NO_COLOR", "1");
    command
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

#[cfg(all(target_os = "linux", feature = "sandbox-enforce"))]
#[test]
fn minimal_server_reexec_enforces_workspace_boundary() {
    let root = tempfile::tempdir().unwrap();
    let workspace = root.path().join("workspace");
    let home = root.path().join("state");
    std::fs::create_dir(&workspace).unwrap();
    std::fs::create_dir(&home).unwrap();
    let supported = fuigo_sandbox::SandboxManager::support_info().is_supported
        && Command::new("bwrap")
            .args(["--bind", "/", "/", "--", "true"])
            .status()
            .is_ok_and(|s| s.success());
    if !supported {
        assert!(
            std::env::var_os("SANDBOX_E2E_REQUIRE_ENFORCEMENT").is_none(),
            "kernel enforcement required"
        );
        return;
    }
    for missing_bwrap in [false, true] {
        let mut command = server();
        command
            .args(["--hub-url", "ws://127.0.0.1:1"])
            .arg("--auth-config")
            .arg(home.join("missing-auth.json"))
            .arg("--diag-socket")
            .arg(root.path().join("diag.sock"))
            .arg("--cwd")
            .arg(&workspace)
            .current_dir(&workspace)
            .env("FUIGO_HOME", &home)
            .env("FUIGO_SANDBOX_PROFILE", "minimal")
            .env_remove("__FUIGO_INSIDE_BWRAP")
            .env("RUST_LOG", "info");
        if missing_bwrap {
            command.env("PATH", &home);
        }
        let out = command.output().unwrap();
        let logs = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!logs.contains("continuing unsandboxed"), "{logs}");
        assert!(
            !logs.contains("Unrecognized FUIGO_SANDBOX_PROFILE"),
            "{logs}"
        );
        if missing_bwrap {
            assert!(!out.status.success());
            assert!(
                logs.contains("bwrap exec failed") && logs.contains("refusing to start"),
                "{logs}"
            );
        } else {
            // Daemon stdio opens the log for append after the real bwrap re-exec.
            // An existing launch-folder file must reject that writable open and
            // retain its contents. Missing auth makes any regressed daemon exit.
            let log = workspace.join("denied.log");
            std::fs::write(&log, "unchanged\n").unwrap();
            let denied = server()
                .args(["--daemonize", "--hub-url", "ws://127.0.0.1:1"])
                .arg("--auth-config")
                .arg(home.join("missing-auth.json"))
                .arg("--log-file")
                .arg(&log)
                .arg("--pid-file")
                .arg(home.join("server.pid"))
                .arg("--cwd")
                .arg(&workspace)
                .current_dir(&workspace)
                .env("FUIGO_HOME", &home)
                .env("FUIGO_SANDBOX_PROFILE", "minimal")
                .env_remove("__FUIGO_INSIDE_BWRAP")
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&denied.stderr);
            assert!(
                stderr.contains("Read-only file system (os error 30)"),
                "server's launch-folder log write must be denied: {denied:?}"
            );
            assert_eq!(std::fs::read_to_string(&log).unwrap(), "unchanged\n");
            assert!(
                !home.join("server.pid").exists(),
                "must fail opening log before taking pidfile"
            );
            assert!(
                logs.contains("Workspace server sandbox active")
                    && logs.contains("profile=minimal"),
                "{logs}"
            );
        }
    }
}

#[cfg(all(target_os = "linux", not(feature = "sandbox-enforce")))]
#[test]
fn minimal_without_enforcement_refuses_before_startup() {
    let root = tempfile::tempdir().unwrap();
    let output = server()
        .args(["--hub-url", "ws://127.0.0.1:1"])
        .arg("--auth-config")
        .arg(root.path().join("missing-auth.json"))
        .arg("--cwd")
        .arg(root.path())
        .current_dir(root.path())
        .env("FUIGO_HOME", root.path().join("state"))
        .env("FUIGO_SANDBOX_PROFILE", "minimal")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{output:?}");
    assert!(
        stderr.contains("minimal")
            && stderr.contains("sandbox-enforce")
            && stderr.contains("refusing to start"),
        "{output:?}"
    );
}
