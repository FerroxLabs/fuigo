//! Shared helpers for integration tests.
//!
//! Each `tests/*.rs` integration test is its own binary, so each binary has its own `OnceLock<FUIGO_HOME>`.
//! The helpers below ensure the per-binary initialization is identical: same env-var set, same isolation guarantees, same reset between tests.
//!
//! Mirrors the FUIGO_HOME isolation pattern used in other integration tests.
//!
//! ## Usage
//!
//! ```ignore
//! mod common;
//! use common::{test_home, reset_home};
//!
//! #[tokio::test]
//! #[serial_test::serial]
//! async fn my_test() {
//!     let _ = test_home();   // initializes FUIGO_HOME once per binary
//!     reset_home();          // wipes state between tests
//!     // ...
//! }
//! ```

#![allow(dead_code)] // each test binary uses a different subset

#[cfg(unix)]
pub mod artifact_server;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

// ─────────────────────────────────────────────────────────────────────────────
// FUIGO_HOME isolation
// ─────────────────────────────────────────────────────────────────────────────

/// Returns a process-wide test `FUIGO_HOME`, initialized exactly once per test binary.
/// Once initialized, `fuigo_config::fuigo_home()` will resolve to this directory for the lifetime of the process.
///
/// Also clears env vars that the auto-update code consults so a parent shell's values can't pollute the baseline.
/// For example, running tests from `npm run` would otherwise inherit `npm_config_user_agent` and `NPM_TOKEN`.
pub fn test_home() -> &'static PathBuf {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.keep();
        // SAFETY: called once at OnceLock init, before any other thread touches
        // these env vars. Tests using this helper must be `#[serial]`.
        unsafe {
            std::env::set_var("FUIGO_HOME", &path);
            std::env::remove_var("FUIGO_TEST_VERSION");
            std::env::remove_var("NPM_TOKEN");
            std::env::remove_var("FUIGO_INSTALLER");
            std::env::remove_var("FUIGO_MANAGED_BY_NPM");
            std::env::remove_var("FUIGO_MANAGED_BY_INTERNAL");
        }
        path
    })
}

/// Wipe state in `FUIGO_HOME` between tests so each test sees a clean home.
/// Removes the well-known files and subdirectories the update path writes, and clears env vars that individual tests may set.
pub fn reset_home() {
    let home = test_home();
    let _ = std::fs::remove_file(home.join("config.toml"));
    let _ = std::fs::remove_file(home.join("version.json"));
    let _ = std::fs::remove_file(home.join("version.json.tmp"));
    let _ = std::fs::remove_dir_all(home.join("bin"));
    let _ = std::fs::remove_dir_all(home.join("downloads"));
    let _ = std::fs::remove_file(home.join(".npm-setup-failed"));
    // SAFETY: tests using this helper must be `#[serial]`.
    unsafe {
        std::env::remove_var("FUIGO_TEST_VERSION");
        std::env::remove_var("NPM_TOKEN");
        std::env::remove_var("FUIGO_INSTALLER");
    }
}

/// Override the version reported by `get_installed_fuigo_version()` for the
/// duration of the test (until [`reset_home`] or process exit).
pub fn set_test_version(v: &str) {
    // SAFETY: tests using this helper must be `#[serial]`.
    unsafe { std::env::set_var("FUIGO_TEST_VERSION", v) };
}

// ─────────────────────────────────────────────────────────────────────────────
// Install-test fixtures (shared by the blitz + convergence suites)
// ─────────────────────────────────────────────────────────────────────────────

/// Host `{os}-{arch}` string matching the versioned binary naming scheme (`fuigo-{version}-{platform}`).
pub fn host_platform() -> String {
    let os = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        panic!("unsupported test platform");
    };
    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        panic!("unsupported test arch");
    };
    format!("{os}-{arch}")
}

/// Minimal [`fuigo_update::UpdateConfig`] for install tests.
pub fn make_update_config(channel: &str) -> fuigo_update::UpdateConfig {
    fuigo_update::UpdateConfig {
        proxy_base_url: "http://test.invalid/v1".to_string(),
        auth_scope: "test".to_string(),
        deployment_key: None,
        alpha_test_key: None,
        channel: channel.to_string(),
        npm_registry: None,
    }
}

/// True if shell-script artifacts can execute in this environment.
/// False in restricted sandboxes (e.g. hermetic remote execution) that lack /bin/sh.
#[cfg(unix)]
pub fn can_exec_shell_scripts() -> bool {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("probe");
    std::fs::write(&p, b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::process::Command::new(&p)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A small real executable: exits 0 for `--version`, so the smoke-test passes.
pub fn small_good_artifact() -> Vec<u8> {
    b"#!/bin/sh\nexit 0\n".to_vec()
}

/// Backdate every file in `FUIGO_HOME/downloads` by ~2 hours.
///
/// `cleanup_old_downloads` deliberately never deletes a freshly-written binary or temp file (it may belong to a concurrent in-flight install).
/// Tests asserting the retention policy must therefore age their fixtures to look like real leftovers from previous releases.
pub fn backdate_downloads() {
    let downloads = test_home().join("downloads");
    let Ok(entries) = std::fs::read_dir(&downloads) else {
        return;
    };
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 60 * 60);
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_file()
            && let Ok(f) = std::fs::File::options().write(true).open(&p)
        {
            let _ = f.set_times(std::fs::FileTimes::new().set_modified(old));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PATH-override fake binary
// ─────────────────────────────────────────────────────────────────────────────

/// RAII guard that places a sh-script with name `name` at the head of `PATH`.
/// Restores `PATH` on drop.
///
/// All tests using this MUST be `#[serial]` because `PATH` is process-global.
pub struct FakeBinGuard {
    pub tmp: tempfile::TempDir,
    pub name: String,
    prev_path: OsString,
}

impl FakeBinGuard {
    /// Install a fake binary at `<tmp>/<name>` whose body is produced by `script_body(<tmp>)`, and prepend `<tmp>` to `PATH`.
    pub fn install<F>(name: &str, script_body: F) -> Self
    where
        F: FnOnce(&Path) -> String,
    {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let body = script_body(&dir);

        let script_path = dir.join(name);
        std::fs::write(&script_path, body).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let prev_path = std::env::var_os("PATH").unwrap_or_default();
        let mut new_path = OsString::from(&dir);
        new_path.push(":");
        new_path.push(&prev_path);
        // SAFETY: serial_test ensures no other thread races on PATH.
        unsafe { std::env::set_var("PATH", &new_path) };

        Self {
            tmp,
            name: name.to_string(),
            prev_path,
        }
    }

    /// Install a fake `npm` using the standard [`fake_npm_script`] template.
    ///
    /// Also places a fake `node` beside it (the updater runs the installed package's setup step with `node`), and
    /// points `FUIGO_HOME` at the per-binary test home so that step can never touch a real `~/.fuigo`.
    pub fn install_npm() -> Self {
        let _ = test_home();
        let g = Self::install("npm", fake_npm_script);
        let node = g.dir().join("node");
        std::fs::write(&node, fake_node_script(&g.dir())).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        g
    }

    /// Make the fake `node` (the package setup step) exit with `code` without installing anything.
    pub fn set_setup_exit_code(&self, code: i32) {
        std::fs::write(self.dir().join("node-exit"), code.to_string()).unwrap();
    }

    /// Argv + selected env, one line per fake `node` invocation.
    pub fn node_log(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir().join("node-args.log"))
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect()
    }

    /// Override the version the fake npm writes into the package it "installs" (default: the requested one).
    pub fn set_installed_package_version(&self, v: &str) {
        std::fs::write(self.dir().join("npm-pkg-version"), v).unwrap();
    }

    /// Install a fake `gh` using the standard [`fake_gh_script`] template.
    pub fn install_gh() -> Self {
        Self::install("gh", fake_gh_script)
    }

    /// The tempdir backing this guard (where canned stdout/stderr/exit files can be written by tests, and where `<name>-args.log` is appended).
    pub fn dir(&self) -> PathBuf {
        self.tmp.path().to_path_buf()
    }

    /// Argv lines logged by the fake script, one line per invocation.
    pub fn args_log(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir().join(format!("{}-args.log", self.name)))
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect()
    }

    pub fn set_stdout(&self, content: &str) {
        std::fs::write(self.dir().join(format!("{}-stdout", self.name)), content).unwrap();
    }

    pub fn set_stderr(&self, content: &str) {
        std::fs::write(self.dir().join(format!("{}-stderr", self.name)), content).unwrap();
    }

    pub fn set_alpha_stdout(&self, content: &str) {
        std::fs::write(
            self.dir().join(format!("{}-alpha-stdout", self.name)),
            content,
        )
        .unwrap();
    }

    pub fn set_stable_only_stdout(&self, content: &str) {
        std::fs::write(
            self.dir().join(format!("{}-stable-only-stdout", self.name)),
            content,
        )
        .unwrap();
    }

    pub fn set_with_pre_stdout(&self, content: &str) {
        std::fs::write(
            self.dir().join(format!("{}-with-pre-stdout", self.name)),
            content,
        )
        .unwrap();
    }

    /// Make every invocation hang for `secs` (an unreachable registry that never answers).
    pub fn set_sleep(&self, secs: u32) {
        std::fs::write(self.dir().join(format!("{}-sleep", self.name)), secs.to_string()).unwrap();
    }

    /// Make every invocation start a long-lived grandchild (a lifecycle script) and record its pid.
    pub fn set_grandchild(&self) {
        std::fs::write(self.dir().join(format!("{}-grandchild", self.name)), "1").unwrap();
    }

    /// Make only `npm i ...` start a long-lived grandchild (its lifecycle script) and record its pid.
    pub fn set_install_grandchild(&self) {
        std::fs::write(self.dir().join(format!("{}-install-grandchild", self.name)), "1").unwrap();
    }

    /// Pid of the grandchild started by [`Self::set_install_grandchild`].
    pub fn install_grandchild_pid(&self) -> Option<i32> {
        std::fs::read_to_string(self.dir().join(format!("{}-install-grandchild.pid", self.name)))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    /// Pid of the grandchild started by [`Self::set_grandchild`].
    pub fn grandchild_pid(&self) -> Option<i32> {
        std::fs::read_to_string(self.dir().join(format!("{}-grandchild.pid", self.name)))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    /// Working directories the fake npm ran in, one per invocation.
    pub fn cwd_log(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir().join(format!("{}-cwd.log", self.name)))
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect()
    }

    /// Make only `npm i ...` hang for `secs` (the registry answers `npm view`, then the install stalls).
    pub fn set_install_sleep(&self, secs: u32) {
        std::fs::write(
            self.dir().join(format!("{}-install-sleep", self.name)),
            secs.to_string(),
        )
        .unwrap();
    }

    /// Make only `npm view ...` exit with `code` (the registry refuses the preflight).
    pub fn set_view_exit_code(&self, code: i32) {
        std::fs::write(
            self.dir().join(format!("{}-view-exit", self.name)),
            code.to_string(),
        )
        .unwrap();
    }

    pub fn set_exit_code(&self, code: i32) {
        std::fs::write(
            self.dir().join(format!("{}-exit", self.name)),
            code.to_string(),
        )
        .unwrap();
    }
}

impl Drop for FakeBinGuard {
    fn drop(&mut self) {
        // SAFETY: serial_test ensures no other thread races on PATH.
        unsafe { std::env::set_var("PATH", &self.prev_path) };
    }
}

/// Single-quote a path for safe substitution into a sh script.
fn single_quote_for_sh(p: &Path) -> String {
    let s = p.to_string_lossy();
    // Escape any embedded single quotes (paranoid: tempdir paths shouldn't contain them, but defensively quote)
    let escaped = s.replace('\'', "'\\''");
    format!("'{escaped}'")
}

/// sh script body for a fake `npm`.
/// Logs argv to `<dir>/npm-args.log` and dispatches stdout based on the first matching argv pattern:
///
/// - argv contains `@alpha`     → cat `<dir>/npm-alpha-stdout`
/// - else                       → cat `<dir>/npm-stdout`
///
/// Always cats `<dir>/npm-stderr` to stderr (if exists).
/// Exits with the integer in `<dir>/npm-exit` (default 0).
pub fn fake_npm_script(dir: &Path) -> String {
    let dq = single_quote_for_sh(dir);
    format!(
        r#"#!/bin/sh
if [ "$1" = "root" ]; then
  # npm 11 masks UUID-looking path segments as ***: `npm-root-masked` makes the fake do the same
  if [ -f {dq}/npm-root-masked ]; then echo "/home/u/***/g/lib/node_modules"; else echo {dq}/npm-root; fi
  exit 0
fi
if [ "$1" = "explore" ]; then
  # npm explore -g fuigo -- <cmd...>: run <cmd> in the installed package directory
  echo "$@" >> {dq}/npm-explore.log
  cd {dq}/npm-root/fuigo || exit 1
  shift 4
  exec "$@"
fi
echo "$@" >> {dq}/npm-args.log
pwd >> {dq}/npm-cwd.log
if [ -f {dq}/npm-grandchild ]; then sleep 300 & echo $! > {dq}/npm-grandchild.pid; fi
if [ "$1" = "i" ] && [ -f {dq}/npm-install-grandchild ]; then sleep 300 & echo $! > {dq}/npm-install-grandchild.pid; fi
if [ -f {dq}/npm-sleep ]; then exec sleep "$(cat {dq}/npm-sleep)"; fi
if [ "$1" = "i" ] && [ -f {dq}/npm-install-sleep ]; then exec sleep "$(cat {dq}/npm-install-sleep)"; fi
if [ "$1" = "view" ] && [ -f {dq}/npm-view-exit ]; then
  if [ -f {dq}/npm-stderr ]; then cat {dq}/npm-stderr >&2; fi
  exit "$(cat {dq}/npm-view-exit)"
fi
if echo "$@" | grep -q '@alpha'; then
  if [ -f {dq}/npm-alpha-stdout ]; then cat {dq}/npm-alpha-stdout; fi
elif [ -f {dq}/npm-stdout ]; then
  cat {dq}/npm-stdout
fi
if [ -f {dq}/npm-stderr ]; then cat {dq}/npm-stderr >&2; fi
exit_code=0
if [ -f {dq}/npm-exit ]; then exit_code=$(cat {dq}/npm-exit); fi
if [ "$1" = "i" ] && [ "$exit_code" = "0" ]; then
  # "install" the package into the fake global root: only its manifest and the setup entry matter here
  ver=none
  for a in "$@"; do case "$a" in fuigo@*) ver="${{a#fuigo@}}";; esac; done
  case "$ver" in latest|alpha|none) ver=9.9.9;; esac
  if [ -f {dq}/npm-pkg-version ]; then ver=$(cat {dq}/npm-pkg-version); fi
  mkdir -p {dq}/npm-root/fuigo/bin
  printf '{{"name":"fuigo","version":"%s"}}' "$ver" > {dq}/npm-root/fuigo/package.json
  : > {dq}/npm-root/fuigo/bin/fuigo-bootstrap.js
fi
exit "$exit_code"
"#
    )
}

/// sh script body for a fake `node`: stands in for `node <root>/fuigo/bin/fuigo-bootstrap.js` with
/// `FUIGO_INSTALL_ONLY=1`, doing what the real setup step does (versioned binary + `fuigo` symlink under `$FUIGO_HOME/bin`).
/// Logs argv and env to `<dir>/node-args.log`; exits with `<dir>/node-exit` (and installs nothing) when that file exists.
pub fn fake_node_script(dir: &Path) -> String {
    let dq = single_quote_for_sh(dir);
    format!(
        r#"#!/bin/sh
echo "$@ INSTALL_ONLY=$FUIGO_INSTALL_ONLY FUIGO_HOME=$FUIGO_HOME REGISTRY=$FUIGO_NPM_REGISTRY" >> {dq}/node-args.log
pwd >> {dq}/node-cwd.log
if [ -f {dq}/node-exit ]; then echo "fake setup failing" >&2; exit "$(cat {dq}/node-exit)"; fi
pkg=$(dirname "$(dirname "$1")")
ver=$(sed -n 's/.*"version":"\([^"]*\)".*/\1/p' "$pkg/package.json")
if [ -n "$FUIGO_INSTALL_REPORT" ]; then printf '{{"version":"%s"}}' "$ver" > "$FUIGO_INSTALL_REPORT"; fi
mkdir -p "$FUIGO_HOME/bin"
printf '#!/bin/sh\n' > "$FUIGO_HOME/bin/fuigo-$ver"
chmod 755 "$FUIGO_HOME/bin/fuigo-$ver"
ln -sfn "fuigo-$ver" "$FUIGO_HOME/bin/fuigo"
exit 0
"#
    )
}

/// sh script body for a fake `gh`.
/// Logs argv to `<dir>/gh-args.log` and dispatches stdout based on `release list` argv:
///
/// - argv contains `release list --exclude-pre-releases` → `<dir>/gh-stable-only-stdout`
/// - argv contains `release list` (no exclude flag)      → `<dir>/gh-with-pre-stdout`
/// - else                                                 → `<dir>/gh-stdout`
///
/// Exits with `<dir>/gh-exit` (default 0).
pub fn fake_gh_script(dir: &Path) -> String {
    let dq = single_quote_for_sh(dir);
    format!(
        r#"#!/bin/sh
echo "$@" >> {dq}/gh-args.log
if echo "$@" | grep -q 'release list'; then
  if echo "$@" | grep -q '\-\-exclude-pre-releases'; then
    if [ -f {dq}/gh-stable-only-stdout ]; then cat {dq}/gh-stable-only-stdout; fi
  else
    if [ -f {dq}/gh-with-pre-stdout ]; then cat {dq}/gh-with-pre-stdout; fi
  fi
elif [ -f {dq}/gh-stdout ]; then
  cat {dq}/gh-stdout
fi
exit_code=0
if [ -f {dq}/gh-exit ]; then exit_code=$(cat {dq}/gh-exit); fi
exit "$exit_code"
"#
    )
}
