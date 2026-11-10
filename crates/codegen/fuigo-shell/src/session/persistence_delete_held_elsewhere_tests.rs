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

/// [`snapshot`] without the writer's own `session_writer.lock`, which the delete's claim creates before anything else:
/// the session's content.
fn content_snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>, std::time::SystemTime)> {
    let mut out = snapshot(dir);
    out.retain(|(path, _, _)| path.file_name() != Some(std::ffi::OsStr::new("session_writer.lock")));
    out
}

/// The delete observer is process-wide: the tests that set one take turns, so neither sees the other's steps.
static OBSERVER_TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn observer_turn() -> std::sync::MutexGuard<'static, ()> {
    OBSERVER_TURN.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
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
    let _turn = observer_turn();
    let root = tempfile::tempdir().unwrap();
    let (info, dir) = seed(root.path());
    // F5 (design §6.3): the delete is the session writer's `delete_tree`, claimed with the eager OS attach.
    let writer = block_on(fuigo_session_writer::SessionWriter::claim(
        info.id.0.to_string(),
        dir.clone(),
        tokio::time::Instant::now() + std::time::Duration::from_secs(5),
    ))
    .expect("claim");
    let tombstone = dir.parent().unwrap().join(format!("{DELETING_PREFIX}{ID}-{}", std::process::id()));
    let seen = Arc::new(AtomicBool::new(false));
    let checks = {
        let (seen, dir, tombstone, sessions) =
            (seen.clone(), dir.clone(), tombstone.clone(), root.path().join("sessions"));
        move |step: &'static str, folder: &Path| {
            // The observer is process-wide: only this delete's own rename is checked, never a concurrent delete's.
            if step != "local_rename" || folder != dir || !tombstone.is_dir() {
                return;
            }
            seen.store(true, Ordering::SeqCst);
            // The session's path names nothing and no lookup resolves the tombstone.
            assert!(!dir.exists());
            assert!(
                find_persisted_session_dir_by_id_in_root_result(ID, &sessions).unwrap().is_none(),
                "an opener resolved a session that is being deleted"
            );
            // An opener by id has no folder to lock, never the doomed one.
            assert!(!crate::session::session_writer_lock::dir_open_elsewhere(&dir));
            // And the doomed folder is still held: a foreign opener of its lock file is refused.
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(tombstone.join(SESSION_WRITER_LOCK_FILE))
                .unwrap();
            assert!(matches!(file.try_lock(), Err(std::fs::TryLockError::WouldBlock)));
        }
    };
    fuigo_session_writer::delete_observer::set(Some(Box::new(checks)));
    let deleted = block_on(delete_local_session(writer));
    fuigo_session_writer::delete_observer::set(None);
    deleted.expect("delete");

    assert!(seen.load(Ordering::SeqCst));
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

/// CT-DEL-O (design §9.2, order pinned, both remote outcomes): the remote delete runs while the folder is still under
/// its own name, byte-identical and held (a second opener of its lock is refused); then the writer's `delete_tree`
/// records `local_rename < hold_released < local_wipe`. A local-before-remote order fails the in-mock assertions.
#[test]
fn f5c_ct_del_o_remote_first_then_rename_release_wipe() {
    let _turn = observer_turn();
    for remote_succeeds in [true, false] {
        // Its own id: the slot is per id, and the other tests here share `ID`.
        let id = if remote_succeeds { "f5c-del-o-ok" } else { "f5c-del-o-404" };
        let root = tempfile::tempdir().unwrap();
        let (_info, dir) = seed_id(root.path(), id);
        let before = content_snapshot(&dir);
        let log = Arc::new(std::sync::Mutex::new(Vec::<&'static str>::new()));
        let remote: RemoteDelete = {
            let (log, dir, before) = (log.clone(), dir.clone(), before.clone());
            Box::pin(async move {
                assert!(dir.is_dir(), "the local folder was touched before the remote delete");
                assert_eq!(content_snapshot(&dir), before, "the local folder changed before the remote delete");
                let probe = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(dir.join(SESSION_WRITER_LOCK_FILE))
                    .expect("the hold's lock file");
                assert!(
                    matches!(probe.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
                    "the OS hold is not held during the remote delete"
                );
                log.lock().unwrap().push("remote_done");
                if remote_succeeds {
                    Ok(())
                } else {
                    Err(crate::remote::client::BackendError::RequestFailed { status: 404, body: String::new() })
                }
            })
        };
        let observer_log = log.clone();
        let tombstone = dir.parent().unwrap().join(format!("{DELETING_PREFIX}{id}-{}", std::process::id()));
        let watched = dir.clone();
        // The observer is process-wide: only steps of this delete (after its remote ran, its folder renamed away) count.
        fuigo_session_writer::delete_observer::set(Some(Box::new(move |step, folder| {
            let mut log = observer_log.lock().unwrap();
            let ours = folder == watched
                && log.first() == Some(&"remote_done")
                && !watched.exists()
                && (step == "local_wipe" || tombstone.exists());
            if ours {
                log.push(step);
            }
        })));
        let deleted = block_on(delete_session_history_in(root.path(), id, None, Some(remote), None));
        fuigo_session_writer::delete_observer::set(None);
        let deleted = deleted.expect("delete");
        assert!(deleted.local_removed);
        assert!(!dir.exists());
        let log = log.lock().unwrap().clone();
        assert_eq!(log[..4], ["remote_done", "local_rename", "hold_released", "local_wipe"], "{log:?}");
        assert!(fuigo_session_writer::SessionWriter::is_free(id), "the writer dropped after the wipe");
    }
}

/// CT-DEL-R (design §9.2): a remote delete that fails leaves the local folder byte-identical with no tombstone, releases
/// the hold and the slot, and a second delete then completes.
#[test]
fn f5c_ct_del_r_remote_failure_leaves_local_intact_and_releases() {
    const DEL_R: &str = "f5c-del-r";
    let root = tempfile::tempdir().unwrap();
    let (_info, dir) = seed_id(root.path(), DEL_R);
    let before = content_snapshot(&dir);
    let failing: RemoteDelete = Box::pin(async {
        Err(crate::remote::client::BackendError::RequestFailed { status: 503, body: String::new() })
    });
    let error = block_on(delete_session_history_in(root.path(), DEL_R, None, Some(failing), None)).unwrap_err();
    assert!(matches!(error, DeleteSessionError::Remote(_)), "{error:?}");
    assert_eq!(content_snapshot(&dir), before, "the local folder changed after a failed remote delete");
    let cwd = dir.parent().unwrap();
    assert_eq!(std::fs::read_dir(cwd).unwrap().count(), 1, "a tombstone was left beside the folder");
    assert!(fuigo_session_writer::SessionWriter::is_free(DEL_R), "the slot is free after a failed remote delete");
    release(foreign_hold(&dir));
    let deleted = block_on(delete_session_history_in(root.path(), DEL_R, None, None, None)).expect("second delete");
    assert!(deleted.local_removed && !dir.exists());
}

fn seed_id(root: &Path, id: &str) -> (Info, PathBuf) {
    let info = Info { id: acp::SessionId::new(id), cwd: "/work".to_owned() };
    block_on(JsonlStorageAdapter::with_root(root.to_path_buf()).init_session(&info, default_model_id())).expect("init");
    let dir = session_dir_in(root, &info);
    (info, dir)
}

/// A search-index row for `id`, so a delete's eviction can be seen.
fn seed_search_row(root: &Path, id: &str) -> PathBuf {
    let db = root.join("sessions").join("session_search.sqlite");
    std::fs::create_dir_all(db.parent().unwrap()).unwrap();
    let index = fuigo_session_search::fts::SessionSearchIndex::open_or_create(&db).expect("index");
    index
        .upsert_doc(&fuigo_session_search::fts::SessionDoc {
            session_id: id.to_owned(),
            cwd: "/work".to_owned(),
            updated_at_unix: 1,
            title: "title".to_owned(),
            content: "content".to_owned(),
            content_hash: "h".to_owned(),
        })
        .expect("upsert");
    db
}

fn search_row_present(db: &Path, id: &str) -> bool {
    let index = fuigo_session_search::fts::SessionSearchIndex::open_or_create(db).expect("index");
    index.get_content_hash(id).expect("read").is_some()
}

/// 79.B2: the folder is renamed away, then the wipe fails. The session is gone from the folder list, so its title-search
/// row must go too; the delete still reports the wipe failure.
#[test]
fn u42_b2_failed_wipe_after_rename_still_evicts_the_search_row() {
    let _turn = observer_turn();
    const ID: &str = "u42-b2-wipe";
    let root = tempfile::tempdir().unwrap();
    let (_info, dir) = seed_id(root.path(), ID);
    let db = seed_search_row(root.path(), ID);
    let tombstone = dir.parent().unwrap().join(format!("{DELETING_PREFIX}{ID}-{}", std::process::id()));
    let (watched, spoil) = (dir.clone(), tombstone.clone());
    // Between the rename and the wipe, the tombstone becomes a plain file: `remove_dir_all` of it fails.
    fuigo_session_writer::delete_observer::set(Some(Box::new(move |step, folder| {
        if step == "hold_released" && folder == watched && !watched.exists() && spoil.is_dir() {
            std::fs::remove_dir_all(&spoil).unwrap();
            std::fs::write(&spoil, b"x").unwrap();
        }
    })));
    let result = block_on(delete_session_history_in(root.path(), ID, None, None, None));
    fuigo_session_writer::delete_observer::set(None);
    assert!(matches!(result, Err(DeleteSessionError::Local(_))), "the wipe failure is still reported: {result:?}");
    assert!(!dir.exists(), "the folder was renamed away");
    assert!(!search_row_present(&db, ID), "a failed wipe left the title-search row of a session with no folder");
}

/// 79.B2: a second delete that names the workspace finds no folder (the first one removed it); the row the first one
/// left behind goes now. A session that still lives under another workspace keeps its row.
#[test]
fn u42_b2_second_delete_with_a_workspace_evicts_a_stale_row_but_not_a_live_one() {
    let root = tempfile::tempdir().unwrap();
    // Stale: no folder anywhere, row still indexed.
    let db = seed_search_row(root.path(), "u42-b2-stale");
    let result = block_on(delete_session_history_in(root.path(), "u42-b2-stale", Some("/work"), None, None))
        .expect("delete of an already-gone session");
    assert!(!result.local_removed);
    assert!(!search_row_present(&db, "u42-b2-stale"), "stale row survived a delete that named a workspace");
    // Live: the session is under /work, the delete names another workspace; nothing of it may be evicted.
    let (_info, dir) = seed_id(root.path(), "u42-b2-live");
    seed_search_row(root.path(), "u42-b2-live");
    let result = block_on(delete_session_history_in(root.path(), "u42-b2-live", Some("/elsewhere"), None, None))
        .expect("delete scoped to another workspace");
    assert!(!result.local_removed && dir.exists());
    assert!(search_row_present(&db, "u42-b2-live"), "a live session's row was evicted by a delete scoped to another workspace");
}
