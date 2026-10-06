//! Every read-modify-write of `auth.json` holds the cross-process `auth.json.lock`.
//!
//! Two kinds of test:
//! - **Hostile, two real processes.** The test binary re-runs itself twice ([`race_child`]); each child hammers one
//!   writer on its own scope while the other child hammers a different writer. Before each write a child checks that
//!   its own previous write is still on disk: only that child ever writes its scope, so anything older is a rollback by
//!   the other process (an unlocked read-modify-write that read before our write and wrote after it). The parent reads
//!   the file throughout and requires every read to parse (never torn, never missing) and each scope's version never to
//!   go backwards; at the end both children's last writes must be on disk.
//! - **Held lock, one process.** With the lock held by another open file, each writer must wait, give up after
//!   `AUTH_LOCK_TIMEOUT` with `TimedOut`, and leave the file byte-for-byte unchanged. Deterministic, and the only
//!   coverage of the devbox purge (a purge deletes the other scope by design, so it cannot take part in the race).
// Test, bench or example code: its prints reach a harness or a developer, never a user, so the
// workspace print deny (R077) is waived here.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::manager::lock;
use super::model::API_KEY_SCOPE;
use super::storage::{read_auth_json, write_auth_json};
use super::{AuthManager, AuthMode, FuigoAuth, FuigoComConfig};
use crate::auth::model::AuthStore;

const ROLE: &str = "FUIGO_AUTH_RACE_ROLE";
const HOME: &str = "FUIGO_AUTH_RACE_HOME";
const ROUNDS: &str = "FUIGO_AUTH_RACE_ROUNDS";
const PEER: &str = "FUIGO_AUTH_RACE_PEER";
/// Variables that would point an `AuthManager` somewhere other than the test's temp home; children never inherit them.
const AUTH_ENV: [&str; 3] = ["FUIGO_AUTH_PATH", "FUIGO_AUTH", "FUIGO_HOME"];
/// Upper bound on any wait in these tests, so a stuck writer fails instead of hanging the suite.
/// Lock-budget timeouts a child tolerates over its whole run before it calls the wait unbounded.
const MAX_TIMEOUTS: u32 = 5;
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(300);
const CHILD_TEST: &str = "auth::cross_process_race_tests::race_child";
const DONE: &str = "AUTH_RACE_CHILD_DONE";
const READY: &str = "AUTH_RACE_CHILD_READY";

/// Writes per child. Enough that an unlocked writer interleaves with the other process many times over (the R051
/// mutants are caught within the first rounds); small enough to finish in seconds on a lightly loaded host.
const DEFAULT_ROUNDS: u32 = 100;

/// The writer a child exercises. Each one owns exactly one scope of `auth.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// `AuthManager::update`, the login paths' writer; owns the manager scope.
    Update,
    /// `AuthManager::save_without_enrichment`; owns the manager scope.
    Save,
    /// `store_api_key` (sync); owns the API-key scope.
    StoreSync,
    /// `store_api_key_async`; owns the API-key scope.
    StoreAsync,
    /// `store_api_key` then `clear_api_key` (sync), alternating; owns the API-key scope.
    ClearSync,
    /// `store_api_key_async` then `clear_api_key_async`, alternating; owns the API-key scope.
    ClearAsync,
}

impl Role {
    fn name(self) -> &'static str {
        match self {
            Self::Update => "update",
            Self::Save => "save",
            Self::StoreSync => "store_sync",
            Self::StoreAsync => "store_async",
            Self::ClearSync => "clear_sync",
            Self::ClearAsync => "clear_async",
        }
    }

    fn parse(name: &str) -> Self {
        [
            Self::Update,
            Self::Save,
            Self::StoreSync,
            Self::StoreAsync,
            Self::ClearSync,
            Self::ClearAsync,
        ]
        .into_iter()
        .find(|r| r.name() == name)
        .unwrap_or_else(|| panic!("unknown race role {name:?}"))
    }

    fn scope(self) -> String {
        match self {
            Self::Update | Self::Save => FuigoComConfig::default().auth_scope(),
            Self::StoreSync | Self::StoreAsync | Self::ClearSync | Self::ClearAsync => {
                API_KEY_SCOPE.to_owned()
            }
        }
    }

    /// The access token this role writes in round `i` (round 0 is the parent's seed).
    fn key(self, i: u32) -> String {
        format!("{}-{i:06}", self.name())
    }

    /// Round `i` of a clearing role removes its scope instead of writing it.
    fn clears_in(self, i: u32) -> bool {
        matches!(self, Self::ClearSync | Self::ClearAsync) && i > 0 && i.is_multiple_of(2)
    }
}

fn manager_auth(key: String) -> FuigoAuth {
    FuigoAuth {
        refresh_token: Some(format!("rt-{key}")),
        key,
        expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        ..FuigoAuth::test_default()
    }
}

fn api_key_auth(key: String) -> FuigoAuth {
    FuigoAuth {
        key,
        auth_mode: AuthMode::ApiKey,
        ..Default::default()
    }
}

/// `auth.json` as both children first see it: each scope at round 0.
fn seed(home: &Path, a: Role, b: Role) {
    let mut store = AuthStore::new();
    for role in [a, b] {
        let auth = match role {
            Role::Update | Role::Save => manager_auth(role.key(0)),
            _ => api_key_auth(role.key(0)),
        };
        store.insert(role.scope(), auth);
    }
    write_auth_json(&home.join("auth.json"), &store).unwrap();
}

/// The round number of `scope`'s entry, `None` when the scope is absent.
fn round_of(store: &AuthStore, scope: &str) -> Option<u32> {
    let key = &store.get(scope)?.key;
    let (_, n) = key
        .rsplit_once('-')
        .unwrap_or_else(|| panic!("unversioned key {key:?}"));
    Some(
        n.parse()
            .unwrap_or_else(|_| panic!("unversioned key {key:?}")),
    )
}

/// The body each child process runs. Returns quietly when not launched as a child.
#[test]
#[ignore = "child body of the cross-process auth.json race tests; they run it in its own process"]
fn race_child() {
    let Ok(role) = std::env::var(ROLE) else {
        return;
    };
    let role = Role::parse(&role);
    let peer = Role::parse(&std::env::var(PEER).expect("race peer"));
    let home = PathBuf::from(std::env::var(HOME).expect("race home"));
    let rounds: u32 = std::env::var(ROUNDS).expect("race rounds").parse().unwrap();
    let path = home.join("auth.json");
    let scope = role.scope();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mgr = manager(&home);

    // Ready, then wait for the start line: the parent releases both children together.
    println!("{READY}");
    std::io::stdout().flush().unwrap();
    let mut go = String::new();
    std::io::stdin().lock().read_line(&mut go).unwrap();

    let mut timeouts = 0_u32;
    for i in 1..=rounds {
        // Halfway, wait until the peer has written at least once: the two processes' writes provably overlap, so a
        // pass cannot come from one child finishing before the other started.
        if i == rounds / 2 {
            let waited = std::time::Instant::now();
            while read_auth_json(&path)
                .ok()
                .is_some_and(|d| round_of(&d, &peer.scope()) == Some(0))
            {
                assert!(
                    waited.elapsed() < DEADLINE,
                    "{}: the peer never started writing",
                    role.name()
                );
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        // Only this process writes `scope`, so disk must still hold exactly what round i-1 left there.
        let disk = read_auth_json(&path)
            .unwrap_or_else(|e| panic!("{} round {i}: read: {e}", role.name()));
        let owned_before = serde_json::to_value(disk.get(&scope)).unwrap();
        let expected = (!role.clears_in(i - 1)).then_some(i - 1);
        assert_eq!(
            round_of(&disk, &scope),
            expected,
            "{} round {i}: the other process rolled back this process's write of round {}",
            role.name(),
            i - 1
        );
        let key = role.key(i);
        let write = || match role {
            Role::Update => rt.block_on(mgr.update(manager_auth(key.clone()))).map(drop),
            Role::Save => rt
                .block_on(mgr.save_without_enrichment(manager_auth(key.clone())))
                .map(drop),
            Role::StoreSync => super::store_api_key(&home, &key),
            Role::StoreAsync => rt.block_on(super::store_api_key_async(&home, &key)),
            Role::ClearSync if role.clears_in(i) => super::clear_api_key(&home),
            Role::ClearSync => super::store_api_key(&home, &key),
            Role::ClearAsync if role.clears_in(i) => rt.block_on(super::clear_api_key_async(&home)),
            Role::ClearAsync => rt.block_on(super::store_api_key_async(&home, &key)),
        };
        // The peer re-takes the lock every round, so on a loaded host a writer can wait out its whole budget. That is
        // allowed (the budget bounds the wait); writing anyway is not: a timed-out round must leave this scope as it
        // was, and is then retried.
        loop {
            match write() {
                Ok(()) => break,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut && timeouts < MAX_TIMEOUTS => {
                    timeouts += 1;
                    let disk = read_auth_json(&path).unwrap();
                    assert_eq!(
                        serde_json::to_value(disk.get(&scope)).unwrap(),
                        owned_before,
                        "{} round {i}: a timed-out write must leave this process's entry unchanged",
                        role.name()
                    );
                }
                Err(e) => panic!("{} round {i}: write: {e}", role.name()),
            }
        }
    }
    println!(
        "{DONE} role={} rounds={rounds} lock_timeouts={timeouts} contended={}",
        role.name(),
        lock::contended_acquires()
    );
}

/// Runs `f` on its own thread and fails the test if it has not returned within [`DEADLINE`].
fn within_deadline<T: Send + 'static>(what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(DEADLINE)
        .unwrap_or_else(|_| panic!("{what}: still waiting after {DEADLINE:?}"))
}

/// Owns the race's children and the reader's stop flag. On every exit path, a failed assertion included, it stops the
/// reader and kills and reaps any child the test has not already collected.
struct Harness {
    children: Vec<Option<std::process::Child>>,
    stop: Arc<AtomicBool>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for child in self.children.iter_mut().flatten() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Waits for the child in `slot` to exit and collects its output. The child stays in the [`Harness`] until it is reaped
/// here, so one owner both reaps and (on any failure, the deadline included) kills it: never a signal to a reused pid.
fn wait_with_deadline(
    slot: &mut Option<std::process::Child>,
    stdout: std::io::BufReader<std::process::ChildStdout>,
) -> std::process::Output {
    use std::io::Read;
    fn drain(mut pipe: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            bytes
        })
    }
    let child = slot.as_mut().expect("child not yet collected");
    let stdout = drain(stdout);
    let stderr = drain(child.stderr.take().unwrap());
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            started.elapsed() < DEADLINE,
            "race child {} did not finish within {DEADLINE:?}",
            child.id()
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    *slot = None;
    std::process::Output {
        status,
        stdout: stdout.join().unwrap(),
        stderr: stderr.join().unwrap(),
    }
}

/// Runs `a` and `b` in two processes against one `auth.json` and checks the file throughout.
fn race(a: Role, b: Role) {
    let rounds: u32 = fuigo_test_support::env::env_parse(ROUNDS, DEFAULT_ROUNDS);
    assert!(
        rounds >= 4,
        "{ROUNDS}={rounds}: a race needs rounds on both sides of the halfway rendezvous"
    );
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().to_path_buf();
    seed(&home, a, b);
    let exe = std::env::current_exe().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let mut harness = Harness {
        children: Vec::new(),
        stop: Arc::clone(&stop),
    };
    // Each child joins the guard the moment it exists, so a failure spawning the next still kills and reaps it.
    let roles = [a, b];
    for role in roles {
        let peer = if role == a { b } else { a };
        let mut cmd = Command::new(&exe);
        for var in AUTH_ENV {
            cmd.env_remove(var);
        }
        // Waited on (`wait_with_deadline`) or killed and reaped by `Harness` on every path, so it cannot outlive the test.
        #[allow(clippy::disallowed_methods)]
        let child = cmd
            .args([
                "--exact",
                CHILD_TEST,
                "--include-ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(ROLE, role.name())
            .env(PEER, peer.name())
            .env(HOME, &home)
            .env(ROUNDS, rounds.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn race child");
        harness.children.push(Some(child));
    }

    // Reader: every read parses and finds both scopes' versions monotonic (a clearing role's absent entry excepted).
    let reader = {
        let stop = Arc::clone(&stop);
        let path = home.join("auth.json");
        std::thread::spawn(move || {
            let mut seen = [0_u32; 2];
            let mut reads = 0_u64;
            while !stop.load(Ordering::SeqCst) {
                let store = read_auth_json(&path)
                    .unwrap_or_else(|e| panic!("read {reads}: auth.json must always parse: {e}"));
                for (slot, role) in [a, b].into_iter().enumerate() {
                    match round_of(&store, &role.scope()) {
                        Some(n) => {
                            assert!(
                                n >= seen[slot],
                                "read {reads}: {} went back from round {} to {n}",
                                role.name(),
                                seen[slot]
                            );
                            seen[slot] = n;
                        }
                        None => assert!(
                            matches!(role, Role::ClearSync | Role::ClearAsync),
                            "read {reads}: {} entry missing",
                            role.name()
                        ),
                    }
                }
                reads += 1;
            }
            reads
        })
    };

    // Both children are constructed and waiting before either is released.
    let mut early = Vec::new();
    for (role, child) in roles.iter().zip(harness.children.iter_mut().flatten()) {
        let stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        let ready = within_deadline(&format!("race child {} ready", role.name()), move || {
            let mut stdout = stdout;
            let mut line = String::new();
            while !line.contains(READY) {
                line.clear();
                if stdout.read_line(&mut line).unwrap() == 0 {
                    return None;
                }
            }
            Some(stdout)
        });
        early
            .push(ready.unwrap_or_else(|| {
                panic!("race child {} exited before it was ready", role.name())
            }));
    }
    for child in harness.children.iter_mut().flatten() {
        child.stdin.take().unwrap().write_all(b"go\n").unwrap();
    }
    let outputs: Vec<_> = roles
        .iter()
        .zip(early)
        .enumerate()
        .map(|(k, (role, stdout))| (*role, wait_with_deadline(&mut harness.children[k], stdout)))
        .collect();
    stop.store(true, Ordering::SeqCst);
    let reads = reader
        .join()
        .expect("reader saw a torn, missing or rolled-back auth.json");

    let mut contended = 0_u64;
    for (role, out) in &outputs {
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains(&format!("{DONE} role={}", role.name())),
            "race child {} failed ({}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
            role.name(),
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        if let Some(done) = stdout.lines().find(|l| l.starts_with(DONE)) {
            eprintln!("{done}");
        }
        contended += stdout
            .split_whitespace()
            .find_map(|w| w.strip_prefix("contended="))
            .and_then(|n| n.parse::<u64>().ok())
            .expect("child reports its lock contention");
    }
    // Evidence that the two processes' writes really overlapped: at least one acquire found the other holding the lock.
    assert!(
        contended > 0,
        "the two writers never contended for auth.json.lock; this run proves nothing about a race"
    );
    let last = read_auth_json(&home.join("auth.json")).unwrap();
    for role in [a, b] {
        let expected = (!role.clears_in(rounds)).then_some(rounds);
        assert_eq!(
            round_of(&last, &role.scope()),
            expected,
            "{}'s last write must be what is on disk",
            role.name()
        );
    }
    assert!(
        reads > 0,
        "the reader must have read the file during the race"
    );
}

#[test]
fn update_never_rolls_back_a_sibling_process_api_key_write() {
    race(Role::Update, Role::StoreSync);
}

#[test]
fn save_without_enrichment_never_rolls_back_a_sibling_process_write() {
    race(Role::Save, Role::StoreSync);
}

#[test]
fn store_api_key_never_rolls_back_a_sibling_process_token_rotation() {
    race(Role::StoreSync, Role::Update);
}

#[test]
fn store_api_key_async_never_rolls_back_a_sibling_process_token_rotation() {
    race(Role::StoreAsync, Role::Update);
}

#[test]
fn clear_api_key_never_rolls_back_a_sibling_process_token_rotation() {
    race(Role::ClearSync, Role::Update);
}

#[test]
fn clear_api_key_async_never_rolls_back_a_sibling_process_token_rotation() {
    race(Role::ClearAsync, Role::Update);
}

// ── Held lock: each writer waits, gives up with `TimedOut`, and leaves the file alone ──────────────────

/// A home whose `auth.json` holds a manager-scope token and an API key, with the lock held by another open file.
fn held_lock_home() -> (
    tempfile::TempDir,
    Vec<u8>,
    crate::auth::storage::AuthFileLock,
) {
    let dir = tempfile::tempdir().unwrap();
    let mut store = AuthStore::new();
    store.insert(Role::Update.scope(), manager_auth("held-000000".into()));
    store.insert(API_KEY_SCOPE.to_owned(), api_key_auth("held-000000".into()));
    let path = dir.path().join("auth.json");
    write_auth_json(&path, &store).unwrap();
    let before = std::fs::read(&path).unwrap();
    let held = lock::try_lock_auth_file_nonblocking(&path).expect("uncontended lock");
    (dir, before, held)
}

/// `result` came from a writer started at `started` against a held lock: it waited out the budget (not an immediate
/// refusal), gave up with `TimedOut`, and left the file alone.
fn assert_waited_out_and_untouched(
    dir: &Path,
    before: &[u8],
    started: std::time::Instant,
    result: std::io::Result<()>,
) {
    let waited = started.elapsed();
    assert!(
        waited >= crate::auth::manager::AUTH_LOCK_TIMEOUT,
        "the writer must wait out AUTH_LOCK_TIMEOUT before giving up (waited {waited:?})"
    );
    let err = result.expect_err("a writer must not write while another holds auth.json.lock");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
    assert_eq!(
        std::fs::read(dir.join("auth.json")).unwrap(),
        before,
        "auth.json must be byte-for-byte unchanged"
    );
}

/// A manager on exactly `dir/auth.json`, never redirected by `FUIGO_AUTH_PATH` / `FUIGO_AUTH` (these tests write,
/// purge and lock, and must never touch a real credential store). The proxy is a closed loopback port, so `update`'s
/// background `/user` enrichment fails fast offline.
fn manager(dir: &Path) -> Arc<AuthManager> {
    Arc::new(
        AuthManager::new_at_path(dir.join("auth.json"), FuigoComConfig::default())
            .with_proxy_base_url("http://127.0.0.1:9"),
    )
}

/// Runs a writer future with an outer deadline, so a writer stuck past its own budget fails the test.
async fn bounded<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, fut)
        .await
        .expect("the writer must give up within its lock budget, not hang")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn update_waits_for_a_held_lock_and_never_writes_unlocked() {
    let (dir, before, _held) = held_lock_home();
    let mgr = manager(dir.path());
    let started = std::time::Instant::now();
    let result = bounded(mgr.update(manager_auth("new-000001".into())))
        .await
        .map(drop);
    assert_waited_out_and_untouched(dir.path(), &before, started, result);
    assert_eq!(
        mgr.current_or_expired().map(|a| a.key).as_deref(),
        Some("new-000001"),
        "the process still gets the credential in memory"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn save_without_enrichment_waits_for_a_held_lock_and_never_writes_unlocked() {
    let (dir, before, _held) = held_lock_home();
    let mgr = manager(dir.path());
    let started = std::time::Instant::now();
    let result = bounded(mgr.save_without_enrichment(manager_auth("new-000001".into())))
        .await
        .map(drop);
    assert_waited_out_and_untouched(dir.path(), &before, started, result);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn devbox_purge_waits_for_a_held_lock_and_never_purges_unlocked() {
    let (dir, before, _held) = held_lock_home();
    let mgr = manager(dir.path());
    let started = std::time::Instant::now();
    let result = bounded(mgr.purge_and_save(manager_auth("new-000001".into())))
        .await
        .map(drop);
    assert_waited_out_and_untouched(dir.path(), &before, started, result);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn update_unless_superseded_waits_for_a_held_lock_and_never_writes_unlocked() {
    let (dir, before, _held) = held_lock_home();
    let mgr = manager(dir.path());
    let started = std::time::Instant::now();
    let result = bounded(mgr.update_unless_superseded(manager_auth("new-000001".into())))
        .await
        .map(drop);
    assert_waited_out_and_untouched(dir.path(), &before, started, result);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn edit_stored_credential_waits_for_a_held_lock_and_never_writes_unlocked() {
    let (dir, before, _held) = held_lock_home();
    let mgr = manager(dir.path());
    mgr.hot_swap(manager_auth("held-000000".into()));
    let started = std::time::Instant::now();
    let result = bounded(mgr.edit_stored_credential(|a| a.coding_data_retention_opt_out = true))
        .await
        .map(drop);
    assert_waited_out_and_untouched(dir.path(), &before, started, result);
    assert!(
        mgr.current_or_expired()
            .unwrap()
            .coding_data_retention_opt_out,
        "the acknowledged edit still reaches memory when the lock cannot be had"
    );
}

#[test]
fn store_api_key_waits_for_a_held_lock_and_never_writes_unlocked() {
    let (dir, before, _held) = held_lock_home();
    let started = std::time::Instant::now();
    let home = dir.path().to_owned();
    let result = within_deadline("store_api_key", move || {
        super::store_api_key(&home, "new-000001")
    });
    assert_waited_out_and_untouched(dir.path(), &before, started, result);
}

#[test]
fn clear_api_key_waits_for_a_held_lock_and_never_writes_unlocked() {
    let (dir, before, _held) = held_lock_home();
    let started = std::time::Instant::now();
    let home = dir.path().to_owned();
    let result = within_deadline("clear_api_key", move || super::clear_api_key(&home));
    assert_waited_out_and_untouched(dir.path(), &before, started, result);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn store_api_key_async_waits_for_a_held_lock_and_never_writes_unlocked() {
    let (dir, before, _held) = held_lock_home();
    let started = std::time::Instant::now();
    let result = bounded(super::store_api_key_async(dir.path(), "new-000001")).await;
    assert_waited_out_and_untouched(dir.path(), &before, started, result);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clear_api_key_async_waits_for_a_held_lock_and_never_writes_unlocked() {
    let (dir, before, _held) = held_lock_home();
    let started = std::time::Instant::now();
    let result = bounded(super::clear_api_key_async(dir.path())).await;
    assert_waited_out_and_untouched(dir.path(), &before, started, result);
}

// ── Same scope: a writer holding an older copy waits on the lock while a sibling rotates the tokens ────

/// Holds the lock, starts `write` (a writer holding the round-0 copy), waits until the manager records it waiting on
/// the lock, then commits a sibling's rotation to round 2 as the lock holder and releases. Returns the stored entry.
async fn sibling_rotates_while_writer_waits<F, Fut>(write: F) -> (FuigoAuth, tempfile::TempDir)
where
    F: FnOnce(Arc<AuthManager>) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<()>> + Send + 'static,
{
    let (dir, _before, held) = held_lock_home();
    let mgr = manager(dir.path());
    mgr.hot_swap(manager_auth("held-000000".into()));
    // Arms `update_lock_waits`, which counts writers that found the lock busy and are now waiting on it.
    mgr.enrichment_parked.store(true, Ordering::SeqCst);
    let writer = tokio::spawn(write(Arc::clone(&mgr)));
    let waited = std::time::Instant::now();
    while mgr.update_lock_waits() == 0 {
        assert!(
            waited.elapsed() < DEADLINE,
            "the writer must reach the held lock"
        );
        tokio::task::yield_now().await;
    }
    mgr.enrichment_parked.store(false, Ordering::SeqCst);
    let path = dir.path().join("auth.json");
    let mut store = read_auth_json(&path).unwrap();
    store.insert(Role::Update.scope(), manager_auth("held-000002".into()));
    write_auth_json(&path, &store).unwrap();
    drop(held);
    bounded(writer)
        .await
        .unwrap()
        .expect("the writer proceeds once the lock is released");
    let stored = read_auth_json(&path).unwrap()[&Role::Update.scope()].clone();
    (stored, dir)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn edit_stored_credential_keeps_a_rotation_that_landed_while_it_waited() {
    let (stored, _dir) = sibling_rotates_while_writer_waits(|mgr| async move {
        mgr.edit_stored_credential(|a| a.coding_data_retention_opt_out = true)
            .await
            .map(drop)
    })
    .await;
    assert_eq!(
        (stored.key.as_str(), stored.refresh_token.as_deref()),
        ("held-000002", Some("rt-held-000002")),
        "the edit must apply to the rotated credential, not restore the copy it started from"
    );
    assert!(
        stored.coding_data_retention_opt_out,
        "and the edit itself lands"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn update_unless_superseded_keeps_a_rotation_that_landed_while_it_waited() {
    let (stored, _dir) = sibling_rotates_while_writer_waits(|mgr| async move {
        let returned = mgr
            .update_unless_superseded(manager_auth("held-000000".into()))
            .await?;
        assert_eq!(
            returned.key, "held-000002",
            "the caller is handed the newer credential"
        );
        Ok(())
    })
    .await;
    assert_eq!(
        (stored.key.as_str(), stored.refresh_token.as_deref()),
        ("held-000002", Some("rt-held-000002")),
        "the old copy must not be written back over the rotation"
    );
}

/// Once the holder lets go, a waiting writer proceeds: the lock bounds the wait, it does not refuse the write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn update_proceeds_once_the_holder_releases() {
    let (stored, dir) = sibling_rotates_while_writer_waits(|mgr| async move {
        mgr.update(manager_auth("new-000003".into()))
            .await
            .map(drop)
    })
    .await;
    assert_eq!(
        stored.key, "new-000003",
        "a fresh login's credential is written after the wait"
    );
    assert_eq!(
        read_auth_json(&dir.path().join("auth.json")).unwrap()[API_KEY_SCOPE].key,
        "held-000000",
        "the read-modify-write keeps the other scope"
    );
}

// ── Disk lagging memory: a fresher mint whose persist failed must survive the snapshot writers ─────────

/// A home whose disk entry (round 1, minted an hour ago) lags the manager's in-memory credential (round 2, minted now),
/// as after a refresh whose disk write failed.
fn disk_lagging_memory() -> (tempfile::TempDir, Arc<AuthManager>) {
    let dir = tempfile::tempdir().unwrap();
    let mut store = AuthStore::new();
    store.insert(
        Role::Update.scope(),
        FuigoAuth {
            create_time: chrono::Utc::now() - chrono::Duration::hours(1),
            ..manager_auth("mem-000001".into())
        },
    );
    write_auth_json(&dir.path().join("auth.json"), &store).unwrap();
    let mgr = manager(dir.path());
    mgr.hot_swap(manager_auth("mem-000002".into()));
    (dir, mgr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn edit_stored_credential_keeps_a_fresher_in_memory_mint() {
    let (dir, mgr) = disk_lagging_memory();
    bounded(mgr.edit_stored_credential(|a| a.coding_data_retention_opt_out = true))
        .await
        .unwrap();
    let memory = mgr.current_or_expired().unwrap();
    assert_eq!(
        (memory.key.as_str(), memory.coding_data_retention_opt_out),
        ("mem-000002", true),
        "memory keeps its fresher tokens and takes the edit"
    );
    let disk =
        read_auth_json(&dir.path().join("auth.json")).unwrap()[&Role::Update.scope()].clone();
    assert_eq!(
        (disk.key.as_str(), disk.coding_data_retention_opt_out),
        ("mem-000001", true),
        "disk takes the edit in place; tokens never move between the copies"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn update_unless_superseded_writes_a_copy_fresher_than_disk() {
    let (dir, mgr) = disk_lagging_memory();
    let returned = bounded(mgr.update_unless_superseded(manager_auth("mem-000002".into())))
        .await
        .unwrap();
    assert_eq!(returned.key, "mem-000002");
    let disk =
        read_auth_json(&dir.path().join("auth.json")).unwrap()[&Role::Update.scope()].clone();
    assert_eq!(
        disk.key, "mem-000002",
        "disk lagging the caller's copy is healed, not taken as newer"
    );
    assert_eq!(mgr.current_or_expired().unwrap().key, "mem-000002");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn edit_stored_credential_reaches_memory_when_the_disk_write_fails() {
    let (dir, mgr) = disk_lagging_memory();
    let path = dir.path().join("auth.json");
    let before = std::fs::read(&path).unwrap();
    let fault = crate::auth::storage::inject_write_fault(&path);
    let result =
        bounded(mgr.edit_stored_credential(|a| a.coding_data_retention_opt_out = true)).await;
    drop(fault);
    result.expect_err("the injected write fault surfaces");
    assert_eq!(std::fs::read(&path).unwrap(), before, "disk unchanged");
    let memory = mgr.current_or_expired().unwrap();
    assert_eq!(
        (memory.key.as_str(), memory.coding_data_retention_opt_out),
        ("mem-000002", true),
        "memory takes the acknowledged edit despite the failed write"
    );
}

/// The caller re-persists the copy it read (round 1, which disk still holds), but this process has since refreshed
/// to round 2 in memory and failed to persist it. Memory is the newer copy and must not be overwritten.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn update_unless_superseded_keeps_a_newer_unpersisted_memory_mint() {
    let dir = tempfile::tempdir().unwrap();
    let caller_copy = FuigoAuth {
        create_time: chrono::Utc::now() - chrono::Duration::hours(1),
        ..manager_auth("mem-000001".into())
    };
    let mut store = AuthStore::new();
    store.insert(Role::Update.scope(), caller_copy.clone());
    write_auth_json(&dir.path().join("auth.json"), &store).unwrap();
    let mgr = manager(dir.path());
    mgr.hot_swap(manager_auth("mem-000002".into()));
    let returned = bounded(mgr.update_unless_superseded(caller_copy))
        .await
        .unwrap();
    assert_eq!(
        returned.key, "mem-000002",
        "the caller is handed the newer copy"
    );
    assert_eq!(
        mgr.current_or_expired().unwrap().key,
        "mem-000002",
        "the stale copy must not overwrite the newer in-memory mint"
    );
}

// ── P42 "held or handed out": a credential returned from disk is registered, memory untouched ──────────

/// Memory holds round 1 (registered); disk holds a sibling's round 2 that this process never loaded.
fn sibling_bearer_only_on_disk() -> (tempfile::TempDir, Arc<AuthManager>) {
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    mgr.hot_swap(manager_auth("sib-000001".into()));
    let mut store = AuthStore::new();
    store.insert(Role::Update.scope(), manager_auth("sib-000002".into()));
    write_auth_json(&dir.path().join("auth.json"), &store).unwrap();
    assert!(
        !mgr.is_session_bearer("sib-000002"),
        "precondition: the sibling's bearer is not yet known to this manager"
    );
    (dir, mgr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn update_unless_superseded_registers_the_sibling_bearer_it_hands_out() {
    let (_dir, mgr) = sibling_bearer_only_on_disk();
    let returned = bounded(mgr.update_unless_superseded(manager_auth("sib-000001".into())))
        .await
        .unwrap();
    assert_eq!(returned.key, "sib-000002", "the caller is handed the sibling's newer credential");
    assert!(
        mgr.is_session_bearer("sib-000002"),
        "a session bearer handed out must be recognised as one"
    );
    assert_eq!(
        mgr.current_or_expired().unwrap().key,
        "sib-000001",
        "registration does not replace the in-memory credential"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn edit_stored_credential_registers_the_disk_bearer_it_hands_out() {
    let (_dir, mgr) = sibling_bearer_only_on_disk();
    let returned = bounded(mgr.edit_stored_credential(|a| a.coding_data_retention_opt_out = true))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(returned.key, "sib-000002", "the edited disk entry is returned");
    assert!(
        mgr.is_session_bearer("sib-000002"),
        "a session bearer handed out must be recognised as one"
    );
    assert_eq!(
        mgr.current_or_expired().unwrap().key,
        "sib-000001",
        "registration does not replace the in-memory credential"
    );
}

#[test]
fn read_disk_auth_registers_the_sibling_bearer_it_hands_out() {
    let (_dir, mgr) = sibling_bearer_only_on_disk();
    let disk = mgr.read_disk_auth().expect("disk entry");
    assert_eq!(disk.key, "sib-000002");
    assert!(
        mgr.is_session_bearer("sib-000002"),
        "a session bearer handed out must be recognised as one"
    );
    assert_eq!(
        mgr.current_or_expired().unwrap().key,
        "sib-000001",
        "registration does not replace the in-memory credential"
    );
}
