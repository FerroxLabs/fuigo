//! Windows-only: the starter-side identity check after the lock is taken (1.0.24; the delete of stale lock files moved to the next release).
//! Every test works in a temp directory with its own lock and pipe names; nothing touches the real Fuigo home.
//! Dead leaders are child processes the test spawned itself and kills itself.
use super::lock::win::{IdQuery, PathOpen, decide};
use super::lock::{Identity, LockStep};
use super::*;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::time::Duration;
use std::process::{Child, Command, Stdio};
use tempfile::TempDir;

const CHILD_ENV: &str = "FUIGO_P3_CHILD_LOCK";
const ALWAYS_REPLACED: &dyn Fn(&File, &Path) -> Identity = &|_, _| Identity::Replaced;
const NO_CHECK: &dyn Fn(&File, &Path) -> Identity = &|_, _| Identity::NoCheck;
const HASHED: &str = "leader-0a1b2c3d";

fn lock_of(root: &Path, stem: &str) -> LeaderLock {
    LeaderLock::from_paths(root.join(format!("{stem}.lock")), root.join(format!("{stem}.sock")))
}

/// TEST ONLY, never reachable from product code: delete a lock file that a starter has open (unlocked or locked).
/// On the lane's NTFS this unlinks the name at once while the open handle stays valid.
fn test_only_delete_locked_file(path: &Path) {
    fs::remove_file(path).unwrap();
    assert!(!path.exists(), "the name is gone at once, though a handle is still open");
}

/// A child process (this test binary re-run on `child_holder`) that takes the lock and holds it until killed.
fn spawn_holder(lock: &Path) -> Child {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "leader::starter_identity_tests::child_holder", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, lock)
        .stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert!(out.read_line(&mut line).unwrap() > 0, "the child exited before it held the lock");
        if line.contains("P3-LOCKED") {
            break;
        }
    }
    child
}

/// Not a test on its own: the body of the child process. Without the env var it does nothing.
#[test]
fn child_holder() {
    let Some(lock) = std::env::var_os(CHILD_ENV) else { return };
    let lock = PathBuf::from(lock);
    let mut l = LeaderLock::from_paths(lock.clone(), lock.with_extension("sock"));
    assert!(l.try_acquire().unwrap());
    l.write_pid().unwrap();
    println!("P3-LOCKED");
    std::mem::forget(l); // a killed leader never runs Drop; neither does this one
    let mut sink = String::new();
    let _ = std::io::stdin().read_line(&mut sink); // blocks until the parent kills us
}

/// a (RED form): without the identity check a starter locks the deleted file and a second starter locks a new file of the
/// same name: TWO LEADERS. This is the hazard the check exists for; it shows the two-leader state is reachable.
#[test]
fn a_without_the_check_two_leaders_happen() {
    let temp = TempDir::new().unwrap();
    let mut first = lock_of(temp.path(), HASHED);
    let file = first.open_lock_file().unwrap(); // barrier: opened, not yet locked
    test_only_delete_locked_file(first.lock_path());
    let mut second = lock_of(temp.path(), HASHED);
    assert!(second.try_acquire().unwrap(), "the second starter creates and locks a new file");
    let first_step = first.lock_opened_with(file, NO_CHECK).unwrap();
    assert!(matches!(first_step, LockStep::Acquired), "TWO LEADERS: the first locked a deleted file");
}

/// a (GREEN form): the same sequence with the real check: exactly one leader.
#[test]
fn a_with_the_check_exactly_one_leader() {
    let temp = TempDir::new().unwrap();
    let mut first = lock_of(temp.path(), HASHED);
    let file = first.open_lock_file().unwrap();
    test_only_delete_locked_file(first.lock_path());
    let mut second = lock_of(temp.path(), HASHED);
    assert!(second.try_acquire().unwrap(), "the second starter creates and locks a new file");
    assert!(matches!(first.lock_opened(file).unwrap(), LockStep::Replaced), "a lock on a deleted file is not a lead");
    assert!(!first.is_held());
    assert!(!first.try_acquire().unwrap(), "the first starter now finds the new file locked: it is not a leader");
    assert!(second.is_held());
}

/// a, other order: the delete lands after the lock is taken is not a starter race; the file is simply gone. The check
/// sees the name missing and says Replaced.
#[test]
fn a_locked_then_deleted_is_replaced() {
    let temp = TempDir::new().unwrap();
    let first = lock_of(temp.path(), HASHED);
    let file = first.open_lock_file().unwrap();
    assert_eq!(super::lock::win::identity_of_path(&file, first.lock_path()), Identity::Same);
    test_only_delete_locked_file(first.lock_path());
    assert_eq!(super::lock::win::identity_of_path(&file, first.lock_path()), Identity::Replaced);
}

fn id(volume: u64, file: [u8; 16]) -> IdQuery {
    IdQuery::Id { volume, file }
}
fn low(n: u8) -> [u8; 16] {
    let mut f = [0u8; 16];
    f[0] = n;
    f
}

/// b: the decision table with injected ids.
#[test]
fn b_decision_table() {
    let a = id(7, low(1));
    assert_eq!(decide(a, PathOpen::Opened(a)), Identity::Same, "equal non-zero ids");
    assert_eq!(decide(a, PathOpen::Opened(id(7, low(2)))), Identity::Replaced, "different ids");
    assert_eq!(decide(a, PathOpen::Opened(id(8, low(1)))), Identity::Replaced, "different volume");
    assert_eq!(decide(a, PathOpen::Missing), Identity::Replaced, "the path no longer exists");
    assert_eq!(decide(IdQuery::Unavailable, PathOpen::Missing), Identity::Replaced, "missing wins over a failed query");
    assert_eq!(decide(id(7, [0; 16]), PathOpen::Opened(id(7, [0; 16]))), Identity::NoCheck, "zero ids: no check");
    assert_eq!(decide(a, PathOpen::Opened(id(7, [0; 16]))), Identity::NoCheck, "zero id on the path side");
    assert_eq!(decide(id(7, [0; 16]), PathOpen::Opened(a)), Identity::NoCheck, "zero id on the held side");
    assert_eq!(decide(IdQuery::Unavailable, PathOpen::Opened(a)), Identity::NoCheck, "query failed on the held handle");
    assert_eq!(decide(a, PathOpen::Opened(IdQuery::Unavailable)), Identity::NoCheck, "query failed on the fresh handle");
    assert_eq!(decide(a, PathOpen::OtherError), Identity::NoCheck, "fresh open failed for another reason");
}

/// b: two different 128-bit ids with equal low 64 bits are two files (the 64-bit index alone cannot tell them apart).
#[test]
fn b_equal_low_64_bits_but_different_128_bit_ids_are_replaced() {
    let mut x = low(5);
    let mut y = low(5);
    x[15] = 1;
    y[15] = 2;
    assert_eq!(decide(id(7, x), PathOpen::Opened(id(7, y))), Identity::Replaced);
    assert_eq!(decide(id(7, x), PathOpen::Opened(id(7, x))), Identity::Same);
}

/// c: `Replaced` over and over: the loop pauses between attempts (200 ms) and ends at the deadline with the usual error.
#[tokio::test]
async fn c_replaced_retries_pause_and_end_at_the_deadline() {
    let temp = TempDir::new().unwrap();
    let mut lock = lock_of(temp.path(), HASHED);
    let attempts = std::sync::atomic::AtomicUsize::new(0);
    let counting = |_: &File, _: &Path| {
        attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Identity::Replaced
    };
    let timeout = Duration::from_millis(1000);
    let start = std::time::Instant::now();
    let result = lock.acquire_reopen_timeout_with(timeout, &counting).await;
    let took = start.elapsed();
    assert!(matches!(result, Err(super::lock::LockError::Timeout(t)) if t == timeout), "ends with the Timeout error");
    let n = attempts.load(std::sync::atomic::Ordering::SeqCst);
    assert!((3..=8).contains(&n), "about deadline/200ms attempts, not a spin: {n}");
    assert!(took >= timeout && took < timeout * 3, "ended at the deadline: {took:?}");
    assert!(!lock.is_held());
}

/// d: a normal start on a real temp file (what every Windows start does): lock taken, the check says the same file.
#[test]
fn d_normal_start_is_same_file_and_leads() {
    let temp = TempDir::new().unwrap();
    let mut lock = lock_of(temp.path(), HASHED);
    let file = lock.open_lock_file().unwrap();
    assert_eq!(super::lock::win::identity_of_path(&file, lock.lock_path()), Identity::Same, "the volume gives usable ids");
    assert!(matches!(lock.lock_opened(file).unwrap(), LockStep::Acquired));
    assert!(lock.is_held());
    let mut other = lock_of(temp.path(), HASHED);
    assert!(!other.try_acquire().unwrap(), "a second starter is refused");
}

/// e: no product code deletes a dead leader's lock file: both the suffixed and the default file stay and are listed Stale.
#[tokio::test]
async fn e_dead_leader_files_stay_and_are_listed_stale() {
    let temp = TempDir::new().unwrap();
    for name in [format!("{HASHED}.lock"), "leader.lock".to_string()] {
        let path = temp.path().join(&name);
        let mut child = spawn_holder(&path);
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(path.exists(), "a killed leader leaves its file");
    }
    let listed = discover_leaders_in_with(temp.path(), false).await;
    assert_eq!(listed.len(), 2, "{listed:?}");
    assert!(listed.iter().all(|d| d.classification == LeaderDiscoveryState::Stale), "{listed:?}");
    assert!(temp.path().join(format!("{HASHED}.lock")).exists() && temp.path().join("leader.lock").exists());
}
