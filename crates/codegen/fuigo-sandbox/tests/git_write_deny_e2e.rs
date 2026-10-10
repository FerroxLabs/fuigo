//! P158 E2E: a sandboxed process cannot plant a git hook or rewrite a git config that git later
//! runs outside the sandbox (subprocess; kernel-enforced: Linux bwrap + Landlock, macOS Seatbelt).
//! Soft-skips when enforcement is unavailable; `SANDBOX_E2E_REQUIRE_ENFORCEMENT` hard-requires it.
// Test code: its prints reach a harness, never a user, so the workspace print deny is waived.
#![allow(clippy::print_stdout, clippy::print_stderr)]
#![cfg(all(unix, feature = "enforce"))]
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SCENARIO_ENV: &str = "P158_E2E_SCENARIO";
const WORKSPACE_ENV: &str = "P158_E2E_WORKSPACE";
const HOME_ENV: &str = "P158_E2E_HOME";
const FUIGO_HOME_ENV: &str = "P158_E2E_FUIGO_HOME";
const REQUIRE_ENV: &str = "SANDBOX_E2E_REQUIRE_ENFORCEMENT";
const HOME_PROFILE: &str = "p158-home-writable";

struct TempDirGuard(PathBuf);
impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn unique_temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "fuigo-p158-e2e-{tag}-{}-{}",
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

fn is_denied(e: &std::io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EACCES) | Some(libc::EPERM) | Some(libc::EROFS) | Some(libc::EBUSY)
            | Some(libc::EXDEV)
    )
}

fn fail(msg: String) -> ! {
    eprintln!("FAIL: {msg}");
    std::process::exit(1);
}

fn expect_denied(label: &str, result: std::io::Result<()>) {
    match result {
        Err(e) if is_denied(&e) => eprintln!("OK: {label} denied"),
        Err(e) => fail(format!("{label}: unexpected error {e}")),
        Ok(()) => fail(format!("{label} was permitted")),
    }
}

fn expect_ok(label: &str, result: std::io::Result<()>) {
    match result {
        Ok(()) => eprintln!("OK: {label} allowed"),
        Err(e) => fail(format!("{label} should be allowed: {e}")),
    }
}

/// A repository with a `core.hooksPath` inside the workspace and no `info/` yet.
fn make_repo(ws: &Path) {
    fs::create_dir_all(ws.join(".git/hooks")).unwrap();
    fs::create_dir_all(ws.join(".git/objects")).unwrap();
    fs::create_dir_all(ws.join(".git/refs/heads")).unwrap();
    fs::write(ws.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    fs::write(
        ws.join(".git/config"),
        "[core]\n\trepositoryformatversion = 0\n\thooksPath = .githooks\n",
    )
    .unwrap();
    fs::write(ws.join(".git/hooks/pre-commit.sample"), "#!/bin/sh\n").unwrap();
    fs::create_dir_all(ws.join(".githooks")).unwrap();
    fs::write(ws.join(".githooks/pre-push"), "#!/bin/sh\nexit 0\n").unwrap();
}

fn run_scenario(scenario: &str, home: &Path, fuigo_home: &Path, ws: &Path) -> (bool, String) {
    let exe = std::env::current_exe().expect("current_exe");
    let output = Command::new(exe)
        .env(SCENARIO_ENV, scenario)
        .env(WORKSPACE_ENV, ws)
        .env(HOME_ENV, home)
        .env(FUIGO_HOME_ENV, fuigo_home)
        .env("HOME", home)
        .env("FUIGO_HOME", fuigo_home)
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

fn fixture(tag: &str) -> (PathBuf, PathBuf, PathBuf, [TempDirGuard; 3]) {
    let home = unique_temp_dir(&format!("{tag}-home"));
    let fuigo = unique_temp_dir(&format!("{tag}-fuigo"));
    let ws = unique_temp_dir(&format!("{tag}-ws"));
    fs::write(
        fuigo.join(fuigo_config::SANDBOX_CONFIG_FILENAME),
        format!(
            "[profiles.{HOME_PROFILE}]\nextends = \"workspace\"\nread_write = [\"{}\"]\n",
            home.display()
        ),
    )
    .unwrap();
    let guards = [
        TempDirGuard(home.clone()),
        TempDirGuard(fuigo.clone()),
        TempDirGuard(ws.clone()),
    ];
    (home, fuigo, ws, guards)
}

#[test]
#[ignore]
fn subprocess_entry() {
    let Ok(scenario) = std::env::var(SCENARIO_ENV) else {
        return;
    };
    let ws = PathBuf::from(std::env::var(WORKSPACE_ENV).unwrap());
    let home = PathBuf::from(std::env::var(HOME_ENV).unwrap());
    #[cfg(target_os = "linux")]
    if scenario == "spoof" {
        // The marker without bwrap: no read-only binds exist, so verification must refuse
        // SAFETY: single-threaded subprocess, before any other thread starts.
        unsafe { std::env::set_var("__FUIGO_INSIDE_BWRAP", "1") };
        let profile = fuigo_sandbox::ProfileName::Workspace;
        match fuigo_sandbox::verify_git_write_deny_enforced(&profile, &ws) {
            Err(e) => eprintln!("OK: spoofed bwrap refused: {e}"),
            Ok(()) => fail("spoofed bwrap passed git write-deny verification".into()),
        }
        eprintln!("OK: p158 scenario spoof passed");
        return;
    }
    let profile = match scenario.as_str() {
        "workspace" => fuigo_sandbox::ProfileName::Workspace,
        // P177: on Linux a home granted by `read_write` refuses the sandbox (a missing shell
        // startup file there would be creatable); the fixture home lies in the temp directory,
        // which the workspace profile keeps writable, so that profile makes it writable instead
        "home_writable" if cfg!(target_os = "linux") => fuigo_sandbox::ProfileName::Workspace,
        "home_writable" => fuigo_sandbox::ProfileName::Custom(HOME_PROFILE.to_string()),
        other => fail(format!("unknown scenario {other}")),
    };
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
    match scenario.as_str() {
        "workspace" => workspace_scenario(&ws),
        _ => home_writable_scenario(&home),
    }
    eprintln!("OK: p158 scenario {scenario} passed");
}

fn workspace_scenario(ws: &Path) {
    let git = ws.join(".git");
    match fs::read_to_string(git.join("config")) {
        Ok(text) if text.contains("hooksPath") => eprintln!("OK: config readable"),
        other => fail(format!("config must stay readable: {other:?}")),
    }
    expect_denied(
        "plant hooks/pre-commit",
        fs::write(git.join("hooks/pre-commit"), "#!/bin/sh\ntouch /tmp/pwned\n"),
    );
    expect_denied("mkdir in hooks", fs::create_dir(git.join("hooks/sub")));
    expect_denied(
        "rewrite config",
        fs::write(git.join("config"), "[core]\n\tfsmonitor = /tmp/evil\n"),
    );
    expect_denied("unlink config", fs::remove_file(git.join("config")));
    expect_denied(
        "rename config",
        fs::rename(git.join("config"), ws.join("config.moved")),
    );
    // `info/` stays writable: Fuigo's commit workflow seeds `info/exclude`
    expect_ok(
        "seed info/exclude",
        fs::create_dir_all(git.join("info")).and_then(|()| fs::write(git.join("info/exclude"), "x\n")),
    );
    expect_denied(
        "plant hooksPath hook",
        fs::write(ws.join(".githooks/pre-commit"), "#!/bin/sh\n"),
    );
    expect_denied(
        "rewrite hooksPath hook",
        fs::write(ws.join(".githooks/pre-push"), "#!/bin/sh\nevil\n"),
    );
    expect_denied("rename .git", fs::rename(&git, ws.join(".git-moved")));
    expect_ok("write object", fs::write(git.join("objects/probe"), "x"));
    expect_ok("write index", fs::write(git.join("index"), "x"));
    expect_ok("write worktree file", fs::write(ws.join("src.txt"), "x"));
}

fn home_writable_scenario(home: &Path) {
    expect_denied(
        "rewrite ~/.gitconfig",
        fs::write(home.join(".gitconfig"), "[core]\n\thooksPath = /tmp/evil\n"),
    );
    expect_ok(
        "mkdir ~/.config/git",
        fs::create_dir_all(home.join(".config/git")),
    );
    expect_denied(
        "create ~/.config/git/config",
        fs::write(home.join(".config/git/config"), "[core]\n\tfsmonitor = evil\n"),
    );
    expect_ok("write other home file", fs::write(home.join("notes.txt"), "x"));
}

#[test]
fn p158_workspace_git_hooks_and_config_are_write_denied() {
    if skip_if_enforcement_unavailable() {
        return;
    }
    let (home, fuigo, ws, _guards) = fixture("ws");
    make_repo(&ws);
    let (ok, stderr) = run_scenario("workspace", &home, &fuigo, &ws);
    assert!(ok, "workspace scenario failed\nstderr: {stderr}");
    assert!(
        stderr.contains("OK: p158 scenario workspace passed"),
        "missing pass marker\nstderr: {stderr}"
    );
    assert!(
        !ws.join(".git/hooks/pre-commit").exists(),
        "a hook was planted\nstderr: {stderr}"
    );
}

#[test]
fn p158_global_gitconfig_is_write_denied_when_home_is_writable() {
    if skip_if_enforcement_unavailable() {
        return;
    }
    let (home, fuigo, ws, _guards) = fixture("home");
    fs::write(home.join(".gitconfig"), "[user]\n\tname = me\n").unwrap();
    let (ok, stderr) = run_scenario("home_writable", &home, &fuigo, &ws);
    assert!(ok, "home scenario failed\nstderr: {stderr}");
    assert!(
        stderr.contains("OK: p158 scenario home_writable passed"),
        "missing pass marker\nstderr: {stderr}"
    );
    let text = fs::read_to_string(home.join(".gitconfig")).unwrap();
    assert!(!text.contains("evil"), "~/.gitconfig was rewritten: {text}");
}

/// A forged `__FUIGO_INSIDE_BWRAP` marker (no real read-only binds) fails the git verification,
/// for an existing `.git/config` and for a missing `.git/hooks` alike.
#[cfg(target_os = "linux")]
#[test]
fn p158_spoofed_bwrap_marker_fails_git_verification() {
    if skip_if_enforcement_unavailable() {
        return;
    }
    for with_hooks in [true, false] {
        let (home, fuigo, ws, _guards) = fixture("spoof");
        make_repo(&ws);
        if !with_hooks {
            fs::remove_dir_all(ws.join(".git/hooks")).unwrap();
            fs::remove_file(ws.join(".git/config")).unwrap();
        }
        let (ok, stderr) = run_scenario("spoof", &home, &fuigo, &ws);
        assert!(ok, "spoof scenario failed (hooks={with_hooks})\nstderr: {stderr}");
        assert!(
            stderr.contains("OK: spoofed bwrap refused"),
            "missing refusal (hooks={with_hooks})\nstderr: {stderr}"
        );
    }
}
