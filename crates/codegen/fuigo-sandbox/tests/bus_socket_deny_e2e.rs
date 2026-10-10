//! P158 E2E (upstream 48271133): a sandboxed process cannot reach the D-Bus or systemd private
//! sockets, through which it could ask systemd or a bus service to start a unit outside the
//! sandbox. Soft-skips when enforcement is unavailable or no bus socket exists on the host;
//! `SANDBOX_E2E_REQUIRE_ENFORCEMENT` hard-requires enforcement.
// Test code: its prints reach a harness, never a user, so the workspace print deny is waived.
#![allow(clippy::print_stdout, clippy::print_stderr)]
#![cfg(all(unix, feature = "enforce"))]
use std::fs;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;

const SCENARIO_ENV: &str = "P158_BUS_E2E";
const WORKSPACE_ENV: &str = "P158_BUS_E2E_WORKSPACE";
const REQUIRE_ENV: &str = "SANDBOX_E2E_REQUIRE_ENFORCEMENT";

fn bus_sockets() -> Vec<PathBuf> {
    // SAFETY: getuid is always safe.
    let uid = unsafe { libc::getuid() };
    let named = std::env::var("DBUS_SESSION_BUS_ADDRESS")
        .ok()
        .and_then(|address| address.strip_prefix("unix:path=").map(PathBuf::from));
    let mut sockets = vec![
        PathBuf::from("/run/dbus/system_bus_socket"),
        PathBuf::from("/var/run/dbus/system_bus_socket"),
        PathBuf::from("/run/systemd/private"),
        PathBuf::from(format!("/run/user/{uid}/bus")),
        PathBuf::from(format!("/run/user/{uid}/systemd/private")),
    ];
    sockets.extend(named);
    sockets
}

/// The bus sockets a process outside the sandbox can connect to right now.
fn reachable_bus_sockets() -> Vec<PathBuf> {
    bus_sockets()
        .into_iter()
        .filter(|path| UnixStream::connect(path).is_ok())
        .collect()
}

fn unique_temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "fuigo-p158-bus-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dunce::canonicalize(&dir).expect("canonicalize temp dir")
}

#[cfg(target_os = "linux")]
fn bwrap_available() -> bool {
    Command::new("bwrap")
        .args(["--bind", "/", "/", "--", "true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn skip_if_enforcement_unavailable() -> bool {
    let require = std::env::var(REQUIRE_ENV).is_ok();
    let support = fuigo_sandbox::SandboxManager::support_info();
    if !support.is_supported {
        assert!(!require, "enforcement required but unsupported: {}", support.details);
        eprintln!("skipping: sandbox not supported ({})", support.details);
        return true;
    }
    #[cfg(target_os = "linux")]
    if !bwrap_available() {
        assert!(!require, "enforcement required but bwrap unavailable");
        eprintln!("skipping: bwrap not installed");
        return true;
    }
    false
}

fn fail(msg: String) -> ! {
    eprintln!("FAIL: {msg}");
    std::process::exit(1);
}

#[test]
#[ignore]
fn subprocess_entry() {
    if std::env::var(SCENARIO_ENV).is_err() {
        return;
    }
    let ws = PathBuf::from(std::env::var(WORKSPACE_ENV).unwrap());
    let profile = fuigo_sandbox::ProfileName::Workspace;
    #[cfg(target_os = "linux")]
    if !fuigo_sandbox::is_inside_bwrap() {
        match fuigo_sandbox::bwrap_reexec_for_profile(&profile, &ws) {
            Some(mut cmd) => {
                use std::os::unix::process::CommandExt;
                let err = cmd.exec();
                fail(format!("bwrap re-exec failed: {err}"));
            }
            None => fail("bwrap_reexec_for_profile returned None outside bwrap".into()),
        }
    }
    let mut sandbox = fuigo_sandbox::SandboxManager::new(profile, &ws);
    if let Err(e) = sandbox.apply(&ws) {
        fail(format!("sandbox apply failed: {e}"));
    }
    if !sandbox.is_applied() {
        fail("sandbox was not applied".into());
    }
    for socket in bus_sockets() {
        match UnixStream::connect(&socket) {
            Ok(_) => fail(format!("{} is reachable inside the sandbox", socket.display())),
            Err(e) => eprintln!("OK: {} unreachable ({e})", socket.display()),
        }
    }
    eprintln!("OK: p158 bus scenario passed");
}

fn run_child(ws: &Path, home: &Path, fuigo: &Path, bus: &Path) -> (bool, String) {
    let output = Command::new(std::env::current_exe().unwrap())
        .env("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={}", bus.display()))
        .env(SCENARIO_ENV, "1")
        .env(WORKSPACE_ENV, ws)
        .env("HOME", home)
        .env("FUIGO_HOME", fuigo)
        .env_remove("GIT_CONFIG_GLOBAL")
        .env_remove("XDG_CONFIG_HOME")
        .args(["--ignored", "--exact", "--nocapture", "subprocess_entry"])
        .output()
        .expect("spawn subprocess");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn p158_workspace_profile_cannot_reach_dbus_or_systemd_sockets() {
    if skip_if_enforcement_unavailable() {
        return;
    }
    eprintln!("host-reachable bus sockets: {:?}", reachable_bus_sockets());
    let home = unique_temp_dir("home");
    let fuigo = unique_temp_dir("fuigo");
    let ws = unique_temp_dir("ws");
    let bus_dir = unique_temp_dir("bus");
    fs::write(fuigo.join(fuigo_config::SANDBOX_CONFIG_FILENAME), "").unwrap();
    // A session bus the environment names (never vacuous: it is always reachable outside)
    let bus = bus_dir.join("session-bus");
    let listener = std::os::unix::net::UnixListener::bind(&bus).expect("bind fake session bus");
    assert!(UnixStream::connect(&bus).is_ok(), "the fake bus must be reachable outside");
    let (ok, stderr) = run_child(&ws, &home, &fuigo, &bus);
    drop(listener);
    for dir in [&home, &fuigo, &ws, &bus_dir] {
        let _ = fs::remove_dir_all(dir);
    }
    assert!(ok, "bus scenario failed\nstderr: {stderr}");
    assert!(
        stderr.contains("OK: p158 bus scenario passed"),
        "missing pass marker\nstderr: {stderr}"
    );
}
