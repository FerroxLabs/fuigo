//! 1.0.30 P30-DIRECT: operations that change a session's folder without opening it (delete, and the startup sweep's
//! removal and cache pruning) respect the session's writer lock, so a window cannot change a session that is live in
//! another window. "Another process" is a second open of the lock file taken by the test: an OS lock belongs to the open
//! file, so it excludes this process's own opens exactly as another process's would (the real two-process case is
//! `session_writer_lock`'s crash test).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use filetime::FileTime;

use super::*;
use crate::session::info::Info;
use crate::session::session_writer_lock::{SESSION_WRITER_LOCK_FILE, acquire};

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(future)
}

/// What another Fuigo process holds while the session is open there.
fn foreign_hold(dir: &Path) -> std::fs::File {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join(SESSION_WRITER_LOCK_FILE))
        .expect("open lock file");
    file.try_lock().expect("the other process takes the session");
    file
}

/// The other window lets go. Unlocked explicitly, not just dropped: a child another test thread is forking at this moment
/// holds a copy of the descriptor until it execs, and would keep the lock past the drop.
fn release(window: std::fs::File) {
    window.unlock().expect("unlock");
}

/// Every file under `dir` with its bytes and mtime, sorted: what a refused change must leave exactly as it was.
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>, std::time::SystemTime)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>, std::time::SystemTime)>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
                out.push((path.clone(), std::fs::read(&path).unwrap(), modified));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}

const ID: &str = "p30-delete-held";

fn seed(root: &Path) -> (Info, PathBuf) {
    let info = Info { id: acp::SessionId::new(ID), cwd: "/work".to_owned() };
    block_on(JsonlStorageAdapter::with_root(root.to_path_buf()).init_session(&info, default_model_id())).expect("init");
    let dir = session_dir_in(root, &info);
    assert!(dir.join("summary.json").is_file());
    (info, dir)
}

/// A remote delete that records whether it was ever started.
fn tracked_remote(started: &Arc<AtomicBool>) -> RemoteDelete {
    let started = Arc::clone(started);
    Box::pin(async move {
        started.store(true, Ordering::SeqCst);
        Ok(())
    })
}

#[test]
fn a_delete_of_a_session_open_elsewhere_is_refused_and_touches_nothing() {
    let root = tempfile::tempdir().unwrap();
    let (_info, dir) = seed(root.path());
    let window_a = foreign_hold(&dir);
    let before = snapshot(&dir);
    let started = Arc::new(AtomicBool::new(false));

    let refused = block_on(delete_session_history_in(root.path(), ID, None, Some(tracked_remote(&started)), None));

    let error = refused.expect_err("a session open in another window was deleted");
    assert!(matches!(error, DeleteSessionError::HeldElsewhere), "{error:?}");
    assert!(error.to_string().contains(crate::session::session_writer_lock::HELD_ELSEWHERE), "{error}");
    assert!(!started.load(Ordering::SeqCst), "the cloud copy was deleted before the local lock check");
    assert_eq!(snapshot(&dir), before, "the refused delete changed the session's folder");
    release(window_a);
}

#[test]
fn a_delete_works_once_the_other_window_lets_go() {
    let root = tempfile::tempdir().unwrap();
    let (_info, dir) = seed(root.path());
    let window_a = foreign_hold(&dir);
    assert!(matches!(
        block_on(delete_session_history_in(root.path(), ID, None, None, None)),
        Err(DeleteSessionError::HeldElsewhere)
    ));
    release(window_a);

    let started = Arc::new(AtomicBool::new(false));
    let deleted = block_on(delete_session_history_in(root.path(), ID, None, Some(tracked_remote(&started)), None))
        .expect("free session");

    assert_eq!(deleted, SessionDeletion { local_removed: true, remote_removed: true });
    assert!(started.load(Ordering::SeqCst));
    assert!(!dir.exists(), "the session folder is gone");
}

#[test]
fn a_delete_of_a_session_nobody_holds_removes_it_and_frees_its_own_hold() {
    let root = tempfile::tempdir().unwrap();
    let (_info, dir) = seed(root.path());

    let deleted = block_on(delete_session_history_in(root.path(), ID, None, None, None)).expect("delete");

    assert_eq!(deleted, SessionDeletion { local_removed: true, remote_removed: false });
    assert!(!dir.exists());
    // The call let go of its own hold (a stale entry would refuse a session recreated at the same path).
    std::fs::create_dir_all(&dir).unwrap();
    let again = foreign_hold(&dir);
    drop(again);
}

#[test]
fn a_delete_of_a_session_live_in_this_process_is_not_refused() {
    let root = tempfile::tempdir().unwrap();
    let (_info, dir) = seed(root.path());
    // The session actor's hold in this process.
    let actor = block_on(acquire(&dir)).expect("free").expect("locked");

    let deleted = block_on(delete_session_history_in(root.path(), ID, None, None, None)).expect("same-process delete");

    assert!(deleted.local_removed);
    assert!(!dir.exists());
    drop(actor);
}

/// A swept root: `<root>/cwd/<id>` with every file `age` old.
fn swept_session(root: &Path, id: &str, age: FileTime) -> PathBuf {
    let dir = root.join("cwd").join(id);
    for rel in ["summary.json", "updates.jsonl"] {
        std::fs::create_dir_all(dir.join(rel).parent().unwrap()).unwrap();
        std::fs::write(dir.join(rel), b"x").unwrap();
        filetime::set_file_mtime(dir.join(rel), age).unwrap();
    }
    dir
}

fn days_ago(days: u64) -> FileTime {
    FileTime::from_system_time(std::time::SystemTime::now() - std::time::Duration::from_secs(days * 86_400))
}

fn sweep(root: &Path) -> CleanupStats {
    cleanup_stale_sessions_inner(root, 30, None, CleanupLevel::SessionsRoot)
}

#[test]
fn the_sweep_skips_an_idle_session_open_elsewhere_and_removes_it_once_free() {
    let root = tempfile::Builder::new().prefix("sessions-").tempdir().unwrap();
    let dir = swept_session(root.path(), "idle", days_ago(60));
    let window_a = foreign_hold(&dir);
    // The lock file is old like the rest: the session looks abandoned to anything but the lock.
    filetime::set_file_mtime(dir.join(SESSION_WRITER_LOCK_FILE), days_ago(60)).unwrap();
    let before = snapshot(&dir);

    let skipped = sweep(root.path());

    assert_eq!(skipped.sessions_removed, 0, "{skipped:?}");
    assert_eq!(snapshot(&dir), before, "the sweep changed a session open in another window");

    release(window_a);
    let removed = sweep(root.path());
    assert_eq!(removed.sessions_removed, 1, "{removed:?}");
    assert!(!dir.exists());
}

#[test]
fn the_sweep_does_not_prune_the_caches_of_a_session_open_elsewhere() {
    let root = tempfile::Builder::new().prefix("sessions-").tempdir().unwrap();
    let dir = swept_session(root.path(), "busy", days_ago(0));
    let stale_cache = dir.join("images/old.jpg");
    std::fs::create_dir_all(stale_cache.parent().unwrap()).unwrap();
    std::fs::write(&stale_cache, b"x").unwrap();
    filetime::set_file_mtime(&stale_cache, days_ago(60)).unwrap();
    let window_a = foreign_hold(&dir);

    let stats = sweep(root.path());
    assert_eq!(stats.files_deleted, 0, "{stats:?}");
    assert!(stale_cache.is_file(), "a cache file of a session open in another window was pruned");

    release(window_a);
    let freed = sweep(root.path());
    assert_eq!(freed.files_deleted, 1, "{freed:?} {:?}", snapshot(&dir));
    assert!(!stale_cache.exists());
}

#[test]
fn the_sweep_still_removes_an_idle_session_this_process_holds_no_lock_on() {
    let root = tempfile::Builder::new().prefix("sessions-").tempdir().unwrap();
    let dir = swept_session(root.path(), "idle", days_ago(60));
    assert_eq!(sweep(root.path()).sessions_removed, 1);
    assert!(!dir.exists());
    // And the sweep never creates a lock file of its own to do it.
    assert!(!root.path().join("cwd/idle").join(SESSION_WRITER_LOCK_FILE).exists());
}

#[test]
fn a_second_opener_during_a_delete_finds_no_session_and_cannot_take_the_lock() {
    let root = tempfile::tempdir().unwrap();
    let (info, dir) = seed(root.path());
    let storage = JsonlStorageAdapter::with_root(root.path().to_path_buf());
    let hold = block_on(acquire(&dir)).expect("free").expect("locked");
    let seen = std::cell::Cell::new(false);

    block_on(delete_local_session(&storage, &info, &dir, Some(hold), |tombstone| {
        seen.set(true);
        // The session's path names nothing and no lookup resolves the tombstone.
        assert!(!dir.exists());
        assert!(
            find_persisted_session_dir_by_id_in_root_result(ID, &root.path().join("sessions")).unwrap().is_none(),
            "an opener resolved a session that is being deleted"
        );
        // An opener by id has no folder to lock (`acquire` answers `None` for a missing folder and the open creates a fresh
        // session), never the doomed one.
        assert!(!dir.is_dir());
        assert!(!crate::session::session_writer_lock::dir_open_elsewhere(&dir));
        // And the doomed folder is still held: a foreign opener of its lock file is refused.
        let file = std::fs::OpenOptions::new().read(true).write(true).open(tombstone.join(SESSION_WRITER_LOCK_FILE)).unwrap();
        assert!(matches!(file.try_lock(), Err(std::fs::TryLockError::WouldBlock)));
    }))
    .expect("delete");

    assert!(seen.get());
    let cwd = dir.parent().unwrap();
    assert!(std::fs::read_dir(cwd).unwrap().next().is_none(), "no session or tombstone left in {cwd:?}");
}

#[test]
fn the_sweep_removes_a_leftover_delete_tombstone_unless_it_is_held() {
    let root = tempfile::Builder::new().prefix("sessions-").tempdir().unwrap();
    let cwd = root.path().join("cwd");
    let dead = cwd.join(format!("{DELETING_PREFIX}dead-1"));
    let live = cwd.join(format!("{DELETING_PREFIX}live-2"));
    for d in [&dead, &live] {
        std::fs::create_dir_all(d).unwrap();
        std::fs::write(d.join("summary.json"), b"x").unwrap();
    }
    let holder = foreign_hold(&live);

    sweep(root.path());
    assert!(!dead.exists(), "an abandoned tombstone was kept");
    assert!(live.exists(), "a tombstone someone holds was removed");

    release(holder);
    sweep(root.path());
    assert!(!live.exists());
}
