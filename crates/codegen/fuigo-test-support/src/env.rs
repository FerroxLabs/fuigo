//! Binary resolution, serial env guards, and git sandbox creation.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::sandbox::TestSandbox;

/// Parse env var `key` into `T`, falling back to `default` when it is unset or present-but-unparseable (warning in the latter case).
pub fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    let Ok(raw) = std::env::var(key) else {
        return default;
    };
    match raw.parse() {
        Ok(value) => value,
        Err(_) => {
            eprintln!("[test-support] ignoring unparseable {key}={raw:?}; using default");
            default
        }
    }
}

/// Run a config test with `FUIGO_HOME` set before the process-wide home cache initializes.
/// Returns the temporary home in the child; the parent checks the child and returns `None`.
pub fn fresh_process_home(test_name: &str) -> Option<PathBuf> {
    const CASE: &str = "FUIGO_TEST_FRESH_HOME_CASE";
    const FIXTURE: &str = ".fuigo-test-fixture";
    const ENTERED: &str = ".fuigo-test-entered";
    if std::env::var(CASE).ok().as_deref() == Some(test_name) {
        let home = PathBuf::from(std::env::var_os("FUIGO_HOME").expect("child home"));
        assert_eq!(
            std::fs::read_to_string(home.join(FIXTURE)).unwrap(),
            test_name
        );
        std::fs::write(home.join(ENTERED), test_name).unwrap();
        return Some(home);
    }
    let home = tempfile::tempdir().expect("isolated test home");
    std::fs::write(home.path().join(FIXTURE), test_name).unwrap();
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", test_name, "--nocapture"])
        .env("FUIGO_HOME", home.path())
        .env(CASE, test_name)
        // Alone in its process, so it may redirect the own-process keys.
        .env(OWN_PROCESS, test_name)
        .env_remove("FUIGO_CONFIG")
        .env_remove("FUIGO_CONFIG_PATH")
        .env_remove("FUIGO_CAMPAIGNS_OVERRIDE")
        .stdin(std::process::Stdio::null())
        // Captured, not inherited: the child's own `running 1 test` / `test result:`
        // lines would otherwise land in the parent's cargo log and can close an
        // unfinished binary's header in the gate's header/result count.
        .output()
        .expect("run isolated config test");
    assert!(
        output.status.success(),
        "isolated config test failed: {test_name} ({})\n--- child stdout ---\n{}\n--- child stderr ---\n{}",
        output.status,
        output_tail(&output.stdout),
        output_tail(&output.stderr),
    );
    assert_eq!(
        std::fs::read_to_string(home.path().join(ENTERED)).unwrap_or_default(),
        test_name,
        "the filter must execute the intended child test"
    );
    None
}

/// Variables whose value decides what EVERY test in a binary reads -- the fuigo
/// home, the OS home, and the endpoints `EndpointsConfig::default()` fills in
/// from the environment -- so a test that changes one must do it in a process
/// of its own (see [`rerun_in_own_process`]).
///
/// The anchor lock ([`PROCESS_ANCHORS`]) and `#[serial]` only exclude tests that
/// take them, and a reader of these variables takes nothing: it reaches them
/// through production code (`fuigo_dirs::fuigo_home()`, `home_dir()`,
/// `EndpointsConfig::default()`). Measured in the `fuigo-shell` lib binary (trio2
/// probe, three full runs): 179 tests redirect `FUIGO_HOME`, and 568 OTHER tests
/// observed two different homes inside their own lifetime -- e.g.
/// `session::prompt_history` wrote its fixture to one home and read back from
/// another, and failed. Running each writer in a child process keeps the shared
/// process's value constant, so no reader needs to know about any writer.
pub const OWN_PROCESS_KEYS: &[&str] = &[
    "FUIGO_HOME",
    // Redirects `AuthManager`'s auth.json for every test that builds a manager from the environment.
    "FUIGO_AUTH_PATH",
    "HOME",
    "USERPROFILE",
    "FUIGO_CLI_CHAT_PROXY_BASE_URL",
    "FUIGO_API_BASE_URL",
    "FUIGO_MODELS_BASE_URL",
    "FUIGO_MODELS_LIST_URL",
    "FUIGO_FEEDBACK_BASE_URL",
    "FUIGO_TRACE_UPLOAD_URL",
    "FUIGO_TRACE_UPLOAD_BUCKET",
    "FUIGO_TRACE_UPLOAD_REGION",
    "FUIGO_TRACE_UPLOAD_CREDENTIALS_FILE",
    "FUIGO_TRACE_UPLOAD_ENDPOINT_URL",
    "FUIGO_DEPLOYMENT_KEY",
    "FUIGO_MANAGED_CONFIG_URL",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "FUIGO_INTERNAL_OTLP_TRACES_ENDPOINT",
    "FUIGO_INTERNAL_OTLP_HEADERS",
    "OTEL_TRACES_EXPORTER",
    "OTEL_BSP_SCHEDULE_DELAY",
    "OTEL_TRACES_EXPORT_INTERVAL",
    "OTEL_EXPORTER_OTLP_TIMEOUT",
];

/// Set in a child started by [`rerun_in_own_process`] (or [`fresh_process_home`])
/// to the name of the one test it runs.
const OWN_PROCESS: &str = "FUIGO_TEST_OWN_PROCESS";
/// Where that child records that the `--exact` filter really ran the test.
const OWN_PROCESS_ENTERED: &str = "FUIGO_TEST_OWN_PROCESS_ENTERED";

/// The last ~8 KB of a child's captured output, for a failure message.
fn output_tail(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let start = text.len().saturating_sub(8000);
    let start = (start..text.len())
        .find(|i| text.is_char_boundary(*i))
        .unwrap_or(text.len());
    text[start..].to_owned()
}

/// The libtest name of the running test, or `None` on an unnamed thread or the
/// main thread (a test run with no siblings, so isolation is moot).
fn current_test_name() -> Option<String> {
    let current = std::thread::current();
    current
        .name()
        .filter(|name| *name != "main")
        .map(str::to_owned)
}

fn in_own_process(name: &str) -> bool {
    std::env::var(OWN_PROCESS).ok().as_deref() == Some(name)
}

/// Run the calling test again, alone, in a child process of this test binary.
///
/// Returns `true` in the parent once the child has passed -- the caller returns
/// at once -- and `false` in the child, so the caller carries on with its body.
/// Outside a child, a test on the main or an unnamed thread panics: it cannot be
/// re-run by name.
///
/// ```ignore
/// if fuigo_test_support::env::rerun_in_own_process() {
///     return;
/// }
/// ```
///
/// Required for every test that writes one of [`OWN_PROCESS_KEYS`]; inside the
/// `fuigo-shell` lib test binary an [`EnvGuard`] over one of them panics
/// otherwise. The child inherits the parent's environment and runs with
/// `--include-ignored --test-threads=1`; its output is captured and shown only
/// if it fails.
///
/// Not for `#[should_panic]` tests: the child's expected panic would come back to
/// the parent as a normal return. None of the callers is one.
pub fn rerun_in_own_process() -> bool {
    // In the child, recognise it by the variable, not only by the thread name: a
    // libtest that runs a lone test on the main thread must still record that the
    // filter reached it, or the parent would report "ran zero tests".
    if let Ok(child_of) = std::env::var(OWN_PROCESS) {
        let here = current_test_name();
        if here.is_none() || here.as_deref() == Some(child_of.as_str()) {
            if let Some(entered) = std::env::var_os(OWN_PROCESS_ENTERED) {
                std::fs::write(entered, &child_of).expect("record that the child ran");
            }
            return false;
        }
    }
    // Outside a child, a test on the main thread or an unnamed one cannot be re-run
    // by name -- and "main" does not mean "alone": libtest runs a test there when it
    // cannot spawn a thread for it, while others are still running. Returning
    // `false` would hand control back to a body that writes the shared process's
    // home or endpoints (some callers do it with raw `remove_var`, which no guard
    // sees), so refuse instead.
    let Some(name) = current_test_name() else {
        panic!(
            "rerun_in_own_process: this test is on the main or an unnamed thread outside a \
             process of its own, so it cannot be re-run by name, and its writes to \
             OWN_PROCESS_KEYS would be seen by every test running beside it. Refusing."
        );
    };
    let marker = tempfile::tempdir().expect("own-process marker dir");
    let entered = marker.path().join("entered");
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", &name, "--include-ignored", "--test-threads=1"])
        .env(OWN_PROCESS, &name)
        .env(OWN_PROCESS_ENTERED, &entered)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run the test in its own process");
    assert!(
        output.status.success(),
        "{name} failed in its own process ({}):\n--- child stdout ---\n{}\n--- child stderr ---\n{}",
        output.status,
        output_tail(&output.stdout),
        output_tail(&output.stderr),
    );
    assert_eq!(
        std::fs::read_to_string(&entered).unwrap_or_default(),
        name,
        "the --exact filter must run {name} itself in the child, not zero tests",
    );
    true
}

/// The `fuigo-shell`, `fuigo-pager` and `fuigo-workspace` lib test binaries are held to [`OWN_PROCESS_KEYS`]: every writer in them calls [`rerun_in_own_process`].
/// Other binaries that share `fuigo-test-support` keep their current contract.
fn enforces_own_process_keys() -> bool {
    static ENFORCED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENFORCED.get_or_init(|| {
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.file_name().map(|n| n.to_string_lossy().into_owned()))
            .is_some_and(|n| {
                n.starts_with("fuigo_shell-")
                    || n.starts_with("fuigo_pager-")
                    || n.starts_with("fuigo_workspace-")
            })
    })
}

fn check_own_process(key: &str) {
    if !OWN_PROCESS_KEYS.contains(&key) || !enforces_own_process_keys() {
        return;
    }
    // Strict: outside a child started for one test, NO thread may write these --
    // not an unnamed helper thread, and not the main thread, which libtest falls
    // back to when it cannot spawn a test thread while other tests still run.
    if std::env::var_os(OWN_PROCESS).is_some() {
        return;
    }
    let name =
        current_test_name().unwrap_or_else(|| "a test on an unnamed or main thread".to_owned());
    panic!(
        "{name} writes {key}, which every test in this binary reads through production code. \
         Start the test with `if fuigo_test_support::env::rerun_in_own_process() {{ return; }}` \
         so the write happens in a process of its own (see OWN_PROCESS_KEYS). On an unnamed or \
         main thread the test cannot be re-run by name, so the write is refused outright."
    );
}

/// Refuse a write to one of [`OWN_PROCESS_KEYS`] unless the caller runs in a child started for one test.
/// Unlike [`EnvGuard`] it is not limited to the `fuigo-shell`/`fuigo-pager` binaries, for callers that write the variable
/// without a guard (raw `set_var`) or that sit behind a helper of their own.
pub fn require_own_process_for(key: &str) {
    if OWN_PROCESS_KEYS.contains(&key) && std::env::var_os(OWN_PROCESS).is_none() {
        panic!(
            "a test writes {key} in the shared test process; start it with \
             `if fuigo_test_support::env::rerun_in_own_process() {{ return; }}`"
        );
    }
}

/// Refuse to continue unless the caller runs in a child started for one test.
/// For state that is shared by the whole test process but is not an environment variable (a process-wide cache, a global registry): `what` names it in the failure.
pub fn assert_own_process(what: &str) {
    if std::env::var_os(OWN_PROCESS).is_none() {
        panic!(
            "a test touches {what} in the shared test process; start it with \
             `if fuigo_test_support::env::rerun_in_own_process() {{ return; }}`"
        );
    }
}

/// Variables that decide where the WHOLE PROCESS reads its configuration from,
/// so a test that changes one silently redirects every other test running at
/// the same instant. A guard for one of these takes the process-wide anchor lock
/// for its whole lifetime, which is what actually makes it exclusive.
///
/// `#[serial_test::serial]` does not, on its own: its named groups exclude only
/// their own members. In the `fuigo-shell` lib binary `FUIGO_HOME` is written
/// by 85 tests in the unnamed `#[serial]` group, by
/// `consent_tests::set_consent_answer_is_monotonic_per_account` in the
/// `#[serial(FUIGO_HOME)]` group, and READ through `fuigo_dirs::resolve_fuigo_home`
/// by `#[serial(remote_sig_disarm)]` tests and by plain `#[test]`s with no group
/// at all — four disjoint populations running concurrently over one variable.
/// Measured effect: two identical full runs at `8e11724` disagreed by +3/-1 tests.
/// Adding a variable here is cheap; relying on an attribute is not.
///
/// One lock for all anchors, never one per key: two tests holding two different
/// locks still interleave their writes, and per-key locks admit ABBA deadlock
/// between tests that take them in opposite orders. The price is that NO test may
/// hold two anchor guards at once — before adding a key here, check that nothing
/// does:
///
/// ```text
/// rg -n 'EnvGuard::(set|unset)\("(FUIGO_HOME|<new key>)"' crates
/// ```
///
/// (zero functions in the workspace hold two, as of this commit).
pub const PROCESS_ANCHORS: &[&str] = &["FUIGO_HOME", "FUIGO_CLI_CHAT_PROXY_BASE_URL"];

/// Hand-rolled because a `std::sync::MutexGuard` field would make `EnvGuard`
/// `!Send`, and guards are held across `.await` in async tests.
/// Not reentrant: no test nests two guards over the same anchor (checked), and a
/// reentrant lock cannot be made sound for a future that migrates threads.
static ANCHOR_LOCK: (std::sync::Mutex<bool>, std::sync::Condvar) =
    (std::sync::Mutex::new(false), std::sync::Condvar::new());

/// Bounded, so a guard that is never dropped -- one stored in a `static` or a
/// `OnceLock`, as `fuigo-shell/tests/session_delete_evicts_index.rs` does -- turns
/// into a named diagnosis instead of a hung test binary. No unit test legitimately
/// holds a config anchor for minutes; a hang here is a leaked guard, not a slow test.
const ANCHOR_WAIT: std::time::Duration = std::time::Duration::from_secs(300);

fn anchor_lock(key: &str) {
    let (mutex, cv) = &ANCHOR_LOCK;
    // A panicking test poisons nothing that matters here: the flag is a plain
    // bool and its invariant is restored by `EnvGuard::drop` during unwind.
    let mut held = mutex.lock().unwrap_or_else(|e| e.into_inner());
    let budget = crate::scaled(ANCHOR_WAIT);
    let deadline = std::time::Instant::now() + budget;
    while *held {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        assert!(
            !left.is_zero(),
            "EnvGuard: waited {budget:?} for the process-anchor lock while setting {key}. \
             Some other test in this binary is still holding an EnvGuard over one of \
             {PROCESS_ANCHORS:?} -- most likely one parked in a `static`/`OnceLock`, which \
             is never dropped and so holds this lock for the life of the process. \
             Give that binary ONE anchor guard, or scope the guard to a test.",
        );
        let (g, _) = cv
            .wait_timeout(held, left)
            .unwrap_or_else(|e| e.into_inner());
        held = g;
    }
    *held = true;
}

fn anchor_unlock() {
    let (mutex, cv) = &ANCHOR_LOCK;
    let mut held = mutex.lock().unwrap_or_else(|e| e.into_inner());
    *held = false;
    cv.notify_one();
}

/// RAII guard for a single environment variable in tests.
/// It snapshots the prior value, applies the change, and restores the prior value (or unsets it) on drop, even if an assertion panics.
/// Restoring rather than always unsetting avoids clobbering vars a parent process/harness set (e.g. `RUST_LOG`).
///
/// For a key in [`PROCESS_ANCHORS`] the guard is exclusive process-wide: it
/// holds one process-wide lock until it drops, so no attribute is needed and none
/// can be forgotten. For every other key the caller MUST still be
/// `#[serial_test::serial]` — and in the UNNAMED group, because a named group
/// serialises against nothing but itself.
/// The `unsafe` `set_var`/`remove_var` are sound only when no other thread accesses the environment concurrently.
pub struct EnvGuard {
    key: &'static str,
    prior: Option<OsString>,
    anchored: bool,
}

impl EnvGuard {
    /// Set `key` to `value` for the guard's lifetime.
    pub fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
        let anchored = Self::acquire(key);
        let prior = std::env::var_os(key);
        // SAFETY: anchors are exclusive via `anchor_lock`; other keys rely on `#[serial]`.
        unsafe { std::env::set_var(key, value) };
        Self {
            key,
            prior,
            anchored,
        }
    }

    /// Unset `key` for the guard's lifetime.
    pub fn unset(key: &'static str) -> Self {
        let anchored = Self::acquire(key);
        let prior = std::env::var_os(key);
        // SAFETY: see [`EnvGuard::set`].
        unsafe { std::env::remove_var(key) };
        Self {
            key,
            prior,
            anchored,
        }
    }

    fn acquire(key: &str) -> bool {
        check_own_process(key);
        let anchored = PROCESS_ANCHORS.contains(&key);
        if anchored {
            anchor_lock(key);
        }
        anchored
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // SAFETY: see [`EnvGuard::set`].
        match self.prior.take() {
            Some(v) => unsafe { std::env::set_var(self.key, v) },
            None => unsafe { std::env::remove_var(self.key) },
        }
        // Restore before releasing, so a waiting setter never observes a
        // half-restored environment.
        if self.anchored {
            anchor_unlock();
        }
    }
}

/// A private `FUIGO_HOME` for the whole test, held exclusively.
///
/// Prefer this to a bare `EnvGuard::set("FUIGO_HOME", ...)` plus a `TempDir`: it
/// keeps the directory alive for exactly as long as the variable points at it.
/// Dropping the `TempDir` first is how a worktree created under `$FUIGO_HOME`
/// disappears from under the test that created it.
pub struct FuigoHome {
    // Declaration order is drop order: release the variable (and the anchor
    // lock) before the directory it names is deleted.
    _env: EnvGuard,
    dir: tempfile::TempDir,
}

impl FuigoHome {
    /// Point `FUIGO_HOME` at a fresh temporary directory until this is dropped.
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("temporary FUIGO_HOME");
        let _env = EnvGuard::set("FUIGO_HOME", dir.path());
        Self { _env, dir }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }
}

impl Default for FuigoHome {
    fn default() -> Self {
        Self::new()
    }
}

/// # Safety
/// No other thread may access the environment concurrently; call before any other thread exists.
pub unsafe fn isolate_fuigo_env(home: &Path) {
    // SAFETY: forwarded to the caller.
    unsafe {
        std::env::set_var("FUIGO_HOME", home);
        std::env::set_var("FUIGO_TELEMETRY_ENABLED", "false");
        std::env::set_var("FUIGO_FEEDBACK_ENABLED", "false");
        std::env::set_var("FUIGO_TRACE_UPLOAD", "false");
        for var in [
            "FUIGO_DEPLOYMENT_KEY",
            "FUIGO_MANAGED_CONFIG",
            "FUIGO_CONFIG",
            "FUIGO_CONFIG_PATH",
            "FUIGO_CLI_CHAT_PROXY_BASE_URL",
            "FUIGO_MODELS_BASE_URL",
            "FUIGO_MODELS_LIST_URL",
            "FUIGO_API_KEY",
            "FUIGO_API_KEY",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            std::env::remove_var(var);
        }
    }
}

fn workspace_root() -> PathBuf {
    // nth(3): crate is nested three levels below the cargo workspace root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root")
        .to_path_buf()
}

/// The arguments of the build that produces the local `fuigo-pager`. `--locked`: a test must never
/// rewrite `Cargo.lock` (the surrounding `cargo test` has already resolved it). The JSON messages
/// name the executable cargo actually produced, so its location is never guessed: `CARGO_BUILD_TARGET`,
/// `build.target-dir` and similar configuration all move it away from `target/debug/`, where an
/// older binary could otherwise be picked up although the build itself succeeded.
const PAGER_BUILD_ARGS: &[&str] = &[
    "build",
    "--locked",
    "--message-format=json-render-diagnostics",
    "-p",
    "fuigo-pager-bin",
    "--bin",
    "fuigo-pager",
];

/// The `executable` of the `fuigo-pager` bin artifact in cargo's JSON message stream.
fn pager_executable_from_messages(stdout: &str) -> Result<PathBuf, String> {
    let mut found = Vec::new();
    for line in stdout.lines() {
        let Ok(message) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if message["reason"] != "compiler-artifact" || message["target"]["name"] != "fuigo-pager" {
            continue;
        }
        let is_bin = message["target"]["kind"]
            .as_array()
            .is_some_and(|kinds| kinds.iter().any(|kind| kind == "bin"));
        if let (true, Some(executable)) = (is_bin, message["executable"].as_str()) {
            found.push(PathBuf::from(executable));
        }
    }
    match found.as_slice() {
        [executable] => Ok(executable.clone()),
        [] => Err(format!(
            "cargo reported no `fuigo-pager` executable artifact; stdout:\n{stdout}"
        )),
        _ => Err(format!(
            "cargo reported several `fuigo-pager` executables {found:?}; refusing to guess"
        )),
    }
}

/// Run `launcher` + [`PAGER_BUILD_ARGS`] in `workspace` and return the executable cargo built.
///
/// ALWAYS builds, even when a `fuigo-pager` already sits in the target dir: a binary left there by
/// another commit, branch or feature set is indistinguishable from a fresh one by its path, and a
/// test that spawns it would pass or fail against code that is not under test. Cargo's own
/// fingerprinting makes the build a no-op when the binary is already fresh, and serializes
/// concurrent test processes on the target dir's build lock (the outer `cargo test` does not hold
/// that lock while tests execute). Offline runs: the nested cargo has no `--offline` flag of its
/// own; it inherits `CARGO_NET_OFFLINE`, and needs no network when the dependency cache is complete.
fn rebuild_local_fuigo_binary(mut launcher: Command, workspace: &Path) -> Result<PathBuf, String> {
    launcher
        .current_dir(workspace)
        .args(PAGER_BUILD_ARGS)
        .stdin(std::process::Stdio::null())
        .envs(fuigo_tty_utils::pager_env());
    fuigo_tty_utils::detach_std_command(&mut launcher);
    let program = launcher.get_program().to_string_lossy().into_owned();
    let output = launcher
        .output()
        .map_err(|e| format!("failed to spawn {program} to build fuigo-pager: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        return Err(format!(
            "failed to build fuigo-pager for binary-driven tests (exit {:?})\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            output_tail(&output.stdout),
            output_tail(&output.stderr),
        ));
    }
    let binary = pager_executable_from_messages(&stdout)?;
    if !binary.exists() {
        return Err(format!(
            "fuigo-pager build completed but binary missing at {}",
            binary.display()
        ));
    }
    Ok(binary)
}

/// The locally built `fuigo-pager`, (re)built at most once per test process. The outcome --
/// success or the build error -- is latched, so every test in the process sees the same binary
/// and a failed build is reported to each caller without being retried by each.
fn local_fuigo_binary() -> PathBuf {
    static LOCAL: std::sync::OnceLock<Result<PathBuf, String>> = std::sync::OnceLock::new();
    LOCAL
        .get_or_init(|| {
            let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
            rebuild_local_fuigo_binary(Command::new(cargo), &workspace_root())
        })
        .clone()
        .unwrap_or_else(|error| panic!("{error}"))
}

/// Resolve the fuigo binary for binary-driven tests.
///
/// 1. `FUIGO_BINARY` (CI / Bazel / explicit override) -- used as given.
/// 2. `CARGO_BIN_EXE_fuigo-pager` -- cargo's own freshly built binary, when set.
/// 3. Otherwise a local build of `fuigo-pager`, always (re)built from the checked-out source and
///    located by cargo's own artifact report (see [`rebuild_local_fuigo_binary`]); a pre-existing
///    file is never trusted.
pub fn fuigo_binary() -> PathBuf {
    if let Ok(path) = std::env::var("FUIGO_BINARY") {
        let p = PathBuf::from(path);
        assert!(p.exists(), "FUIGO_BINARY does not exist: {}", p.display());
        // Bazel's FUIGO_BINARY is runfiles-relative; the harness spawns the child with a different cwd
        // Absolutize against the (runfiles-root) cwd now
        return std::path::absolute(&p).unwrap_or(p);
    }

    if let Ok(path) = std::env::var("CARGO_BIN_EXE_fuigo-pager") {
        let p = PathBuf::from(path);
        if p.exists() {
            return p;
        }
    }

    local_fuigo_binary()
}

pub fn git_workdir() -> TestSandbox {
    TestSandbox::builder().git().build()
}

#[cfg(test)]
mod own_process_keys_tests {
    use super::*;

    #[test]
    fn require_own_process_for_refuses_an_own_process_key_in_the_shared_process() {
        let refused = std::panic::catch_unwind(|| require_own_process_for("FUIGO_HOME"));
        assert!(
            refused.is_err(),
            "FUIGO_HOME in the shared process must be refused"
        );
        let refused = std::panic::catch_unwind(|| require_own_process_for("FUIGO_AUTH_PATH"));
        assert!(
            refused.is_err(),
            "FUIGO_AUTH_PATH in the shared process must be refused"
        );
        require_own_process_for("SOME_UNLISTED_KEY_FOR_P62");
    }

    #[test]
    fn auth_path_is_an_own_process_key() {
        assert!(
            OWN_PROCESS_KEYS.contains(&"FUIGO_AUTH_PATH"),
            "FUIGO_AUTH_PATH redirects the auth.json every environment-built AuthManager uses"
        );
    }
}

#[cfg(all(test, unix))]
mod local_binary_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// The JSON line cargo prints for the built `fuigo-pager`.
    fn artifact_line(executable: &Path) -> String {
        serde_json::json!({
            "reason": "compiler-artifact",
            "target": {"name": "fuigo-pager", "kind": ["bin"]},
            "executable": executable,
            "fresh": false,
        })
        .to_string()
    }

    /// A stand-in for cargo: records its arguments, writes "fresh" to `writes` (if any), prints
    /// `stdout` and exits with `exit`. Run through `/bin/sh <script>` rather than exec'd directly,
    /// so a sibling test thread forking while the script is written cannot cause ETXTBSY.
    fn fake_cargo(
        dir: &Path,
        writes: Option<&Path>,
        stdout: &str,
        exit: i32,
    ) -> (Command, PathBuf) {
        let args = dir.join("args.txt");
        let messages = dir.join("messages.jsonl");
        std::fs::write(&messages, stdout).unwrap();
        let write = writes
            .map(|binary| {
                format!(
                    "mkdir -p '{0}' && printf fresh > '{1}'\n",
                    binary.parent().unwrap().display(),
                    binary.display()
                )
            })
            .unwrap_or_default();
        let script = dir.join("fake-cargo.sh");
        std::fs::write(
            &script,
            format!(
                "printf '%s ' \"$@\" > '{}'\n{write}cat '{}'\nexit {exit}\n",
                args.display(),
                messages.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut launcher = Command::new("/bin/sh");
        launcher.arg(&script);
        (launcher, args)
    }

    #[test]
    fn an_existing_binary_is_rebuilt_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("debug/fuigo-pager");
        std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
        std::fs::write(&binary, "stale").unwrap();
        let (launcher, args) = fake_cargo(dir.path(), Some(&binary), &artifact_line(&binary), 0);

        let built = rebuild_local_fuigo_binary(launcher, dir.path()).expect("build succeeds");

        assert_eq!(
            std::fs::read_to_string(&args).expect("the build must run although the binary exists"),
            "build --locked --message-format=json-render-diagnostics -p fuigo-pager-bin --bin fuigo-pager "
        );
        assert_eq!(built, binary);
        assert_eq!(std::fs::read_to_string(&binary).unwrap(), "fresh");
    }

    /// Astra P69 HIGH: cargo can succeed while writing the executable somewhere other than
    /// `<target>/debug/` (`CARGO_BUILD_TARGET`, `build.target-dir`); a stale file at the guessed path
    /// must not be returned.
    #[test]
    fn the_executable_cargo_reports_wins_over_a_stale_file_at_the_default_path() {
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join("debug/fuigo-pager");
        std::fs::create_dir_all(stale.parent().unwrap()).unwrap();
        std::fs::write(&stale, "stale").unwrap();
        let built_at = dir
            .path()
            .join("x86_64-unknown-linux-gnu/debug/fuigo-pager");
        let messages = format!(
            "{{\"reason\":\"build-script-executed\"}}\nnot json\n{}\n{{\"reason\":\"build-finished\",\"success\":true}}\n",
            artifact_line(&built_at)
        );
        let (launcher, _) = fake_cargo(dir.path(), Some(&built_at), &messages, 0);

        let built = rebuild_local_fuigo_binary(launcher, dir.path()).expect("build succeeds");

        assert_eq!(built, built_at);
        assert_eq!(std::fs::read_to_string(&stale).unwrap(), "stale");
    }

    #[test]
    fn a_failed_build_is_an_error_even_with_a_stale_binary_present() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("debug/fuigo-pager");
        std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
        std::fs::write(&binary, "stale").unwrap();
        let (launcher, _) = fake_cargo(dir.path(), None, &artifact_line(&binary), 3);

        let error = rebuild_local_fuigo_binary(launcher, dir.path())
            .expect_err("a failed build must not fall back to the stale binary");
        assert!(error.contains("exit Some(3)"), "{error}");
    }

    #[test]
    fn a_build_that_reports_no_executable_is_an_error_even_with_a_stale_binary_present() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("debug/fuigo-pager");
        std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
        std::fs::write(&binary, "stale").unwrap();
        let (launcher, _) = fake_cargo(dir.path(), None, "{\"reason\":\"build-finished\"}\n", 0);

        let error = rebuild_local_fuigo_binary(launcher, dir.path()).unwrap_err();
        assert!(error.contains("no `fuigo-pager` executable"), "{error}");
    }

    #[test]
    fn a_reported_executable_that_does_not_exist_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("debug/fuigo-pager");
        let (launcher, _) = fake_cargo(dir.path(), None, &artifact_line(&binary), 0);

        let error = rebuild_local_fuigo_binary(launcher, dir.path()).unwrap_err();
        assert!(error.contains("binary missing"), "{error}");
    }

    /// End-to-end freshness probe (ignored: it builds the whole pager). The resolved binary's
    /// `--version` stamp must name the checked-out commit -- a binary left by another commit in
    /// the same target dir fails it. Run (with `FUIGO_BINARY` and `CARGO_BIN_EXE_fuigo-pager`
    /// unset, or the probe bypasses the rebuild): `cargo test -p fuigo-test-support --lib
    /// env::local_binary_tests::resolved_binary_is_built_from_the_checkout -- --ignored --exact`
    /// and check that it reports `1 passed`.
    #[test]
    #[ignore = "builds fuigo-pager; run explicitly (P69 stale-binary demonstration)"]
    fn resolved_binary_is_built_from_the_checkout() {
        for key in ["FUIGO_BINARY", "CARGO_BIN_EXE_fuigo-pager"] {
            assert!(
                std::env::var_os(key).is_none(),
                "unset {key}: it bypasses the local rebuild this probe qualifies"
            );
        }
        let head = Command::new("git")
            .current_dir(workspace_root())
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("git rev-parse");
        assert!(head.status.success(), "not a git checkout");
        let head = String::from_utf8(head.stdout).unwrap();
        let head12 = &head.trim()[..12];

        let binary = fuigo_binary();
        let version = Command::new(&binary)
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("run fuigo-pager --version");
        let stdout = String::from_utf8_lossy(&version.stdout);
        eprintln!(
            "P69 probe: HEAD={head12} binary={} version={}",
            binary.display(),
            stdout.trim()
        );
        assert!(version.status.success(), "--version failed: {version:?}");
        assert!(
            stdout.contains(&format!("({head12})")),
            "stale fuigo-pager: built from another commit (HEAD {head12}): {}",
            stdout.trim()
        );
    }
}
