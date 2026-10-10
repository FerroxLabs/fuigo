//! P172 (D1): the startup TTL sweep of `~/.fuigo/sessions/`.
//!
//! Before P172 the sweep deleted EVERY file older than the TTL (30 days by default) inside every session folder,
//! including the write-once files a resumable session still needs: compaction checkpoints, prompt offloads, rewind
//! points and history that an older turn wrote. A session used today but compacted 31 days ago lost its checkpoint,
//! and `/rewind` then failed. The sweep now judges a session as a unit and only prunes disposable caches.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use filetime::FileTime;
use tempfile::TempDir;

use super::sweep_pin::PinnedDir;
use super::{
    CleanupLevel, CleanupStats, MarkLiveError, SessionDirRename, StdRename, cleanup_session_dir_with, cleanup_stale_sessions_inner,
    mark_session_live, mark_session_live_waiting, mark_session_live_with, open_lock_nofollow, open_sweep_lock,
    prune_pinned_session_caches, session_last_activity_within, sweep_lock_path, touch_nofollow,
};

/// `mark_session_live` from synchronous test code (it waits asynchronously in production). The mark is released at
/// once, as when the actor already holds `turn_owner.lock`.
fn mark(session_dir: &Path) {
    drop(block_on(mark_session_live(session_dir)).expect("no sweep holds the session"));
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap().block_on(future)
}

const TTL_DAYS: u32 = 30;

/// A sessions root whose own name has no leading dot (`TempDir::new()` names start with `.tmp`, and the pre-P172
/// sweep skipped any folder whose name starts with a dot, so such a root would prove nothing).
fn sessions_tmp() -> TempDir {
    tempfile::Builder::new().prefix("sessions-").tempdir().unwrap()
}

fn days_ago(days: u64) -> FileTime {
    FileTime::from_system_time(SystemTime::now() - Duration::from_secs(days * 86_400))
}

/// Writes a small file (creating parents) and backdates it to `age`.
fn write(path: &Path, age: FileTime) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, b"x").unwrap();
    filetime::set_file_mtime(path, age).unwrap();
}

/// `sessions/<cwd>/<id>/` with `summary.json` and `updates.jsonl` at `age`.
fn write_session(root: &Path, cwd: &str, id: &str, age: FileTime) -> PathBuf {
    let dir = root.join(cwd).join(id);
    write(&dir.join("summary.json"), age);
    write(&dir.join("updates.jsonl"), age);
    dir
}

/// Everything in a session folder that a later resume or rewind reads, written by turns long ago.
const WRITE_ONCE_ARTIFACTS: [&str; 9] = [
    "compaction_checkpoints/a.json",
    "compaction_requests/r.json",
    "prompts/prompt_1.txt",
    "rewind_points.jsonl",
    "chat_history.jsonl",
    "assets/user-image.png",
    "tool_definitions.json",
    "summary.json.lock",
    "subagents/child/updates.jsonl",
];

/// The bug: a session in use today (its transcript was written today) lost every artifact an older turn wrote.
#[test]
fn a_session_in_use_keeps_its_old_checkpoints_offloads_and_history() {
    let tmp = sessions_tmp();
    let session = write_session(tmp.path(), "cwd", "s1", days_ago(0));
    for rel in WRITE_ONCE_ARTIFACTS {
        write(&session.join(rel), days_ago(60));
    }

    cleanup_stale_sessions_inner(tmp.path(), TTL_DAYS, None, CleanupLevel::SessionsRoot);

    for rel in WRITE_ONCE_ARTIFACTS {
        assert!(session.join(rel).is_file(), "{rel} must survive the sweep");
    }
}

fn sweep(root: &Path, live: Option<&Path>) -> CleanupStats {
    cleanup_stale_sessions_inner(root, TTL_DAYS, live, CleanupLevel::SessionsRoot)
}

#[test]
fn a_session_in_use_is_untouched_when_it_has_no_stale_cache() {
    let tmp = sessions_tmp();
    let session = write_session(tmp.path(), "cwd", "s1", days_ago(0));
    for rel in WRITE_ONCE_ARTIFACTS {
        write(&session.join(rel), days_ago(60));
    }

    assert_eq!(CleanupStats::default(), sweep(tmp.path(), None));
}

#[test]
fn a_session_in_use_has_only_its_stale_cache_files_swept() {
    let tmp = sessions_tmp();
    let session = write_session(tmp.path(), "cwd", "s1", days_ago(0));
    let old_blobs = ["images/1.jpg", "videos/1.mp4", "downloads/1.pdf", "terminal/t.log"];
    for rel in old_blobs {
        write(&session.join(rel), days_ago(60));
    }
    write(&session.join("images/2.jpg"), days_ago(0));
    // Just inside the TTL: kept
    write(&session.join("downloads/2.pdf"), days_ago(29));

    let stats = sweep(tmp.path(), None);

    assert_eq!(CleanupStats { files_deleted: 4, ..CleanupStats::default() }, stats);
    for rel in old_blobs {
        assert!(!session.join(rel).exists(), "{rel} must be swept");
    }
    assert!(session.join("images/2.jpg").is_file());
    assert!(session.join("downloads/2.pdf").is_file());
    assert!(session.join("images").is_dir(), "a cache folder is never removed");
}

#[test]
fn a_session_nobody_used_for_the_ttl_is_removed_whole() {
    let tmp = sessions_tmp();
    let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));
    write(&idle.join("compaction_checkpoints/a.json"), days_ago(40));
    let fresh = write_session(tmp.path(), "cwd", "fresh", days_ago(0));
    let summary_rewritten = write_session(tmp.path(), "cwd", "summary-rewritten", days_ago(40));
    write(&summary_rewritten.join("summary.json"), days_ago(1));

    let stats = sweep(tmp.path(), None);

    assert_eq!(CleanupStats { sessions_removed: 1, ..CleanupStats::default() }, stats);
    assert!(!idle.exists());
    assert!(fresh.join("updates.jsonl").is_file());
    assert!(summary_rewritten.join("updates.jsonl").is_file());
}

#[test]
fn the_live_session_is_never_removed_but_its_stale_cache_is_pruned() {
    let tmp = sessions_tmp();
    let live = write_session(tmp.path(), "cwd", "live", days_ago(40));
    write(&live.join("compaction_checkpoints/a.json"), days_ago(40));
    write(&live.join("prompts/prompt_0.txt"), days_ago(40));
    write(&live.join("images/1.jpg"), days_ago(40));
    write(&live.join("images/2.jpg"), days_ago(0));

    let stats = sweep(tmp.path(), Some(&live));

    assert_eq!(CleanupStats { files_deleted: 1, ..CleanupStats::default() }, stats);
    assert!(live.join("summary.json").is_file());
    assert!(live.join("updates.jsonl").is_file());
    assert!(live.join("compaction_checkpoints/a.json").is_file());
    assert!(live.join("prompts/prompt_0.txt").is_file());
    assert!(!live.join("images/1.jpg").exists());
    assert!(live.join("images/2.jpg").is_file());
}

/// Another process's sweep sees only mtimes, so an attach must bump one before it loads.
#[test]
fn mark_session_live_keeps_an_idle_session_out_of_a_foreign_sweep() {
    let tmp = sessions_tmp();
    let attaching = write_session(tmp.path(), "cwd", "attaching", days_ago(40));
    write(&attaching.join("compaction_checkpoints/a.json"), days_ago(40));
    let summary_before = std::fs::read(attaching.join("summary.json")).unwrap();
    let no_summary = tmp.path().join("cwd").join("no-summary");
    write(&no_summary.join("summary.json.lock"), days_ago(40));

    mark(&attaching);
    mark(&no_summary);
    mark(&tmp.path().join("cwd").join("not-created-yet"));
    let stats = sweep(tmp.path(), None);

    assert_eq!(CleanupStats { sessions_removed: 1, ..CleanupStats::default() }, stats);
    assert!(attaching.join("updates.jsonl").is_file());
    assert!(attaching.join("compaction_checkpoints/a.json").is_file());
    assert_eq!(summary_before, std::fs::read(attaching.join("summary.json")).unwrap(), "nothing is written");
    assert!(!no_summary.exists());
    assert!(!tmp.path().join("cwd").join("not-created-yet").exists(), "marking never creates a folder");
}

#[test]
fn a_stub_folder_follows_its_newest_file_or_its_own_mtime() {
    let tmp = sessions_tmp();
    let cwd = tmp.path().join("cwd");
    let lock_only = cwd.join("lock-only");
    write(&lock_only.join("summary.json.lock"), days_ago(40));
    let old_empty = cwd.join("old-empty");
    std::fs::create_dir_all(&old_empty).unwrap();
    filetime::set_file_mtime(&old_empty, days_ago(40)).unwrap();
    let fresh_empty = cwd.join("fresh-empty");
    std::fs::create_dir_all(&fresh_empty).unwrap();

    let stats = sweep(tmp.path(), None);

    assert_eq!(CleanupStats { sessions_removed: 2, ..CleanupStats::default() }, stats);
    assert!(!lock_only.exists());
    assert!(!old_empty.exists());
    assert!(fresh_empty.is_dir());
}

#[test]
fn dot_entries_are_kept_while_stray_files_follow_the_mtime_rule() {
    let tmp = sessions_tmp();
    let cwd = tmp.path().join("cwd");
    write(&cwd.join(".cwd"), days_ago(60));
    write(&tmp.path().join(".index/old.bin"), days_ago(60));
    write(&cwd.join(".hidden/old.bin"), days_ago(60));
    write_session(tmp.path(), "cwd", "fresh", days_ago(0));
    write(&cwd.join("prompt_history.jsonl"), days_ago(60));

    let stats = sweep(tmp.path(), None);

    assert_eq!(CleanupStats { files_deleted: 1, ..CleanupStats::default() }, stats);
    assert!(cwd.join(".cwd").is_file());
    assert!(tmp.path().join(".index/old.bin").is_file());
    assert!(cwd.join(".hidden/old.bin").is_file());
    assert!(!cwd.join("prompt_history.jsonl").exists());
}

#[test]
fn an_emptied_cwd_folder_is_removed_only_after_a_session_removal() {
    let tmp = sessions_tmp();
    write_session(tmp.path(), "emptied", "idle", days_ago(40));
    let untouched = tmp.path().join("untouched");
    std::fs::create_dir_all(&untouched).unwrap();
    write_session(tmp.path(), "kept", "fresh", days_ago(0));
    let hashed = tmp.path().join("hashed");
    write(&hashed.join(".cwd"), days_ago(60));
    write_session(tmp.path(), "hashed", "idle", days_ago(40));

    let stats = sweep(tmp.path(), None);

    assert_eq!(CleanupStats { dirs_removed: 1, sessions_removed: 2, ..CleanupStats::default() }, stats);
    assert!(!tmp.path().join("emptied").exists());
    assert!(untouched.is_dir());
    assert!(tmp.path().join("kept/fresh/summary.json").is_file());
    assert!(!hashed.join("idle").exists());
    assert!(hashed.join(".cwd").is_file());
}

// ── P146/P150 posture: the sweep never follows a symlink while deleting ──

/// A whole old outside session reached through a symlinked session folder.
#[cfg(unix)]
#[test]
fn a_symlinked_session_folder_is_skipped() {
    let tmp = sessions_tmp();
    let outside = TempDir::new().unwrap();
    let target = write_session(outside.path(), "cwd", "target", days_ago(40));
    let cwd = tmp.path().join("cwd");
    std::fs::create_dir_all(&cwd).unwrap();
    std::os::unix::fs::symlink(&target, cwd.join("link")).unwrap();

    let stats = sweep(tmp.path(), None);

    assert_eq!(CleanupStats::default(), stats);
    assert!(target.join("summary.json").is_file());
    assert!(cwd.join("link").symlink_metadata().is_ok());
}

/// A cache folder planted as a symlink to an outside folder full of old files: nothing outside is deleted, for a
/// session in use and for the live one alike.
#[cfg(unix)]
#[test]
fn a_symlinked_cache_folder_is_never_entered() {
    let tmp = sessions_tmp();
    let outside = TempDir::new().unwrap();
    write(&outside.path().join("precious.txt"), days_ago(60));
    let in_use = write_session(tmp.path(), "cwd", "in-use", days_ago(0));
    let live = write_session(tmp.path(), "cwd", "live", days_ago(0));
    std::os::unix::fs::symlink(outside.path(), in_use.join("images")).unwrap();
    std::os::unix::fs::symlink(outside.path(), live.join("downloads")).unwrap();

    let stats = sweep(tmp.path(), Some(&live));

    assert_eq!(0, stats.files_deleted, "{stats:?}");
    assert!(outside.path().join("precious.txt").is_file());
    assert!(in_use.join("images").symlink_metadata().unwrap().file_type().is_symlink());
}

/// A symlink inside a cache folder is not a regular file: it is left alone and its old target is never deleted.
#[cfg(unix)]
#[test]
fn a_symlink_inside_a_cache_folder_is_left_alone() {
    let tmp = sessions_tmp();
    let outside = TempDir::new().unwrap();
    let precious = outside.path().join("precious.txt");
    write(&precious, days_ago(60));
    let session = write_session(tmp.path(), "cwd", "s1", days_ago(0));
    std::fs::create_dir_all(session.join("terminal")).unwrap();
    std::os::unix::fs::symlink(&precious, session.join("terminal/old.log")).unwrap();
    write(&session.join("terminal/real-old.log"), days_ago(60));

    let stats = sweep(tmp.path(), None);

    assert_eq!(CleanupStats { files_deleted: 1, ..CleanupStats::default() }, stats);
    assert!(precious.is_file());
    assert!(session.join("terminal/old.log").symlink_metadata().is_ok());
    assert!(!session.join("terminal/real-old.log").exists());
}

/// An idle session holding a symlink to outside files is removed whole, but only the link goes: never its target.
#[cfg(unix)]
#[test]
fn removing_an_idle_session_never_follows_a_symlink_inside_it() {
    let tmp = sessions_tmp();
    let outside = TempDir::new().unwrap();
    write(&outside.path().join("precious.txt"), days_ago(60));
    let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));
    std::os::unix::fs::symlink(outside.path(), idle.join("compaction_checkpoints")).unwrap();

    let stats = sweep(tmp.path(), None);

    assert_eq!(1, stats.sessions_removed, "{stats:?}");
    assert!(!idle.exists());
    assert!(outside.path().join("precious.txt").is_file());
}

/// `mark_session_live` never follows a symlinked `summary.json`: the outside file's mtime is not touched.
#[cfg(unix)]
#[test]
fn mark_session_live_never_follows_a_symlinked_summary() {
    let tmp = sessions_tmp();
    let outside = TempDir::new().unwrap();
    let target = outside.path().join("summary.json");
    write(&target, days_ago(60));
    let session = tmp.path().join("cwd").join("s1");
    std::fs::create_dir_all(&session).unwrap();
    std::os::unix::fs::symlink(&target, session.join("summary.json")).unwrap();

    mark(&session);

    let mtime = FileTime::from_last_modification_time(&std::fs::metadata(&target).unwrap());
    assert_eq!(days_ago(60).unix_seconds(), mtime.unix_seconds());
}

// ── Astra r1 (HIGH): another process attaching an idle session while the sweep is deciding ──

/// A live actor anywhere holds `turn_owner.lock` shared for its whole life: its session is never removed, however
/// long it has been idle.
#[test]
fn an_idle_session_held_by_a_live_actor_is_kept() {
    let tmp = sessions_tmp();
    let held = write_session(tmp.path(), "cwd", "held", days_ago(40));
    write(&held.join("compaction_checkpoints/a.json"), days_ago(40));
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(held.join(crate::session::turn_owner_lock::TURN_OWNER_LOCK_FILE))
        .unwrap();
    fs2::FileExt::try_lock_shared(&lock).unwrap();

    let stats = sweep(tmp.path(), None);

    assert_eq!(CleanupStats::default(), stats);
    assert!(held.join("compaction_checkpoints/a.json").is_file());
    drop(lock);
}

/// The attach marks the session live after the sweep's first look but before it locks the session: the sweep looks
/// again under the lock and keeps it.
#[test]
fn an_attach_between_the_first_look_and_the_lock_keeps_the_session() {
    let tmp = sessions_tmp();
    let attaching = write_session(tmp.path(), "cwd", "attaching", days_ago(40));
    write(&attaching.join("prompts/prompt_0.txt"), days_ago(40));

    let stats = cleanup_session_dir_with(&attaching, TTL_DAYS, &StdRename, || mark(&attaching), || {}, |_| {});

    assert_eq!(CleanupStats::default(), stats);
    assert!(attaching.join("prompts/prompt_0.txt").is_file());
    assert!(attaching.join("updates.jsonl").is_file());
}

/// The lock file the sweep creates to lock a session is not activity: an idle session without one is still removed.
#[test]
fn the_sweeps_own_lock_file_is_not_activity() {
    let tmp = sessions_tmp();
    let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));
    write(&idle.join(crate::session::turn_owner_lock::TURN_OWNER_LOCK_FILE), days_ago(0));
    write(&sweep_lock_path(&idle).unwrap(), days_ago(0));

    let stats = cleanup_session_dir_with(&idle, TTL_DAYS, &StdRename, || {}, || {}, |_| {});

    assert_eq!(CleanupStats { sessions_removed: 1, ..CleanupStats::default() }, stats);
    assert!(!idle.exists());
}

/// A planted `turn_owner.lock` symlink is never opened through: the session is kept rather than removed unlocked.
#[cfg(unix)]
#[test]
fn an_idle_session_whose_lock_file_is_a_symlink_is_kept() {
    let tmp = sessions_tmp();
    let outside = TempDir::new().unwrap();
    let target = outside.path().join("target.lock");
    let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));
    std::os::unix::fs::symlink(&target, idle.join(crate::session::turn_owner_lock::TURN_OWNER_LOCK_FILE)).unwrap();

    let stats = sweep(tmp.path(), None);

    assert_eq!(0, stats.sessions_removed, "{stats:?}");
    assert!(idle.join("updates.jsonl").is_file());
    assert!(!target.exists(), "the link's target is never created");
}

// ── Astra r2/r3 (HIGH): an attach that starts after the sweep's last look ──

/// The sweep holds the session's sweep lock exclusively from its last look until the session has left its path. An attach that
/// starts in that window waits in `mark_session_live` (asynchronously) and then finds no session; it never marks or
/// loads a session that is being removed.
#[test]
fn an_attach_during_a_removal_waits_for_it_and_finds_nothing() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let tmp = sessions_tmp();
    let session = write_session(tmp.path(), "cwd", "removing", days_ago(40));
    let sweep_lock = open_sweep_lock(&session).expect("lock file");
    fs2::FileExt::try_lock_exclusive(&sweep_lock).expect("the sweep's exclusive lock");

    let marked = Arc::new(AtomicBool::new(false));
    let attach = {
        let (session, marked) = (session.clone(), Arc::clone(&marked));
        std::thread::spawn(move || {
            let outcome = block_on(mark_session_live_waiting(&session, Duration::from_secs(60)));
            marked.store(true, Ordering::SeqCst);
            outcome.is_ok()
        })
    };
    std::thread::sleep(Duration::from_millis(300));
    assert!(!marked.load(Ordering::SeqCst), "the attach must wait while the session is being removed");
    // What the sweep does while it holds the lock: take the session off its path
    std::fs::rename(&session, tmp.path().join("cwd").join(".fuigo-sweep-removing-test")).unwrap();
    drop(sweep_lock);

    assert!(attach.join().unwrap(), "the attach finds nothing to mark");
    assert!(!session.exists(), "the attach recreates nothing of a removed session");
}

/// A sweep stuck mid-removal does not make the attach load a session it is removing: the load fails with a retry.
#[test]
fn an_attach_fails_rather_than_loading_a_session_a_stuck_sweep_holds() {
    let tmp = sessions_tmp();
    let session = write_session(tmp.path(), "cwd", "stuck", days_ago(40));
    let sweep_lock = open_sweep_lock(&session).expect("lock file");
    fs2::FileExt::try_lock_exclusive(&sweep_lock).expect("the sweep's exclusive lock");
    let before = std::fs::metadata(session.join("summary.json")).unwrap().modified().unwrap();

    let outcome = block_on(mark_session_live_waiting(&session, Duration::from_millis(200)));

    assert!(matches!(outcome, Err(MarkLiveError::SweepBusy)), "{outcome:?}");
    assert_eq!(before, std::fs::metadata(session.join("summary.json")).unwrap().modified().unwrap());
    drop(sweep_lock);
}

/// Live actors hold `turn_owner.lock`, and a recovery holds it exclusively for seconds: a mark never waits for either.
#[test]
fn an_attach_never_waits_for_an_actor_or_a_recovery() {
    let tmp = sessions_tmp();
    let session = write_session(tmp.path(), "cwd", "live", days_ago(40));
    let recovery = open_lock_nofollow(&session, crate::session::turn_owner_lock::TURN_OWNER_LOCK_FILE).unwrap();
    fs2::FileExt::try_lock_exclusive(&recovery).expect("a recovery's exclusive lock");
    let before = std::fs::metadata(session.join("summary.json")).unwrap().modified().unwrap();

    let started = std::time::Instant::now();
    let outcome = block_on(mark_session_live_waiting(&session, Duration::from_secs(60)));

    assert!(outcome.is_ok());
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    assert!(std::fs::metadata(session.join("summary.json")).unwrap().modified().unwrap() > before);
}

/// Astra r3: once the session has left its path nothing can be opened there, so no attach can create a fresh
/// `turn_owner.lock` (a file the sweep's locks do not cover) and start an actor in the tree being deleted. The removal
/// renames the whole folder first, atomically.
#[test]
fn a_removed_session_leaves_its_path_before_anything_is_deleted() {
    let tmp = sessions_tmp();
    let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));
    write(&idle.join("prompts/prompt_0.txt"), days_ago(40));
    let mut seen = None;

    let stats = cleanup_session_dir_with(&idle, TTL_DAYS, &StdRename, || {}, || {}, |removing| {
        assert!(!idle.exists(), "the session's path is gone before deletion starts");
        assert!(open_lock_nofollow(&idle, crate::session::turn_owner_lock::TURN_OWNER_LOCK_FILE).is_none());
        assert!(block_on(mark_session_live(&idle)).is_ok());
        assert!(!idle.exists(), "an attach now recreates nothing");
        assert!(removing.join("prompts/prompt_0.txt").is_file(), "the content moved whole, nothing deleted yet");
        seen = Some(removing.to_path_buf());
    });

    assert_eq!(CleanupStats { sessions_removed: 1, ..CleanupStats::default() }, stats);
    let removing = seen.expect("the removal renamed the session first");
    assert!(removing.file_name().unwrap().to_string_lossy().starts_with(".fuigo-sweep-removing-idle-"));
    assert!(!removing.exists());
    assert!(!idle.exists());
}

/// A removal interrupted after the rename leaves a dot-named folder that is never listed; the next sweep finishes it.
#[test]
fn the_next_sweep_finishes_an_interrupted_removal() {
    let tmp = sessions_tmp();
    let leftover = tmp.path().join("cwd").join(".fuigo-sweep-removing-old-1-2");
    write(&leftover.join("updates.jsonl"), days_ago(40));
    let fresh = write_session(tmp.path(), "cwd", "fresh", days_ago(0));

    let stats = sweep(tmp.path(), None);

    assert_eq!(CleanupStats { dirs_removed: 1, ..CleanupStats::default() }, stats);
    assert!(!leftover.exists());
    assert!(fresh.join("updates.jsonl").is_file());
}

// ── P178 (audit of P172, MEDIUM): Windows cannot rename a folder that has an open handle beneath it ──

/// A rename that refuses the way NTFS does: a directory with any file or directory open anywhere beneath it cannot be
/// renamed (`ERROR_ACCESS_DENIED`, whatever the share mode). It inspects this process's open descriptors, so it sees
/// the sweep's own lock handles and those of an attach running in this process.
#[cfg(target_os = "linux")]
struct NtfsLikeRename;

#[cfg(target_os = "linux")]
impl SessionDirRename for NtfsLikeRename {
    fn rename(&self, dir: &PinnedDir, from: &OsStr, to: &OsStr) -> std::io::Result<()> {
        let from_path = dunce::canonicalize(dir.child_path(from))?;
        for fd in std::fs::read_dir("/proc/self/fd")?.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path())
                && target != from_path
                && target.starts_with(&from_path)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("Access is denied. (os error 5): {} is open", target.display()),
                ));
            }
        }
        dir.rename_child(from, to)
    }
}

/// Every rename the sweep may meet: the real one, and on Linux the NTFS rule.
fn renamers() -> Vec<(&'static str, &'static dyn SessionDirRename)> {
    #[allow(unused_mut)]
    let mut all: Vec<(&'static str, &'static dyn SessionDirRename)> = vec![("std", &StdRename)];
    #[cfg(target_os = "linux")]
    all.push(("ntfs-like", &NtfsLikeRename));
    all
}

fn entry_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> =
        std::fs::read_dir(dir).unwrap().map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    names
}

/// The double is not vacuous: it refuses exactly when something beneath the folder is open.
#[cfg(target_os = "linux")]
#[test]
fn the_ntfs_double_refuses_a_folder_with_an_open_file_beneath_it() {
    let tmp = sessions_tmp();
    let session = write_session(tmp.path(), "cwd", "s1", days_ago(0));
    write(&session.join("prompts/p.txt"), days_ago(0));
    let open = std::fs::File::open(session.join("prompts/p.txt")).unwrap();
    let cwd = PinnedDir::open_root(&tmp.path().join("cwd")).unwrap();
    let error = NtfsLikeRename.rename(&cwd, OsStr::new("s1"), OsStr::new("moved")).unwrap_err();
    assert_eq!(std::io::ErrorKind::PermissionDenied, error.kind());
    drop(open);
    NtfsLikeRename.rename(&cwd, OsStr::new("s1"), OsStr::new("moved")).unwrap();
}

/// The audit's repro: on Windows an idle session was never removed, because the sweep renamed it while it still held
/// its two lock files open inside it. Removal must work under the NTFS rule, and leave nothing behind.
#[test]
fn an_idle_session_is_removed_under_every_rename_rule() {
    for (rule, renamer) in renamers() {
        let tmp = sessions_tmp();
        let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));
        write(&idle.join("prompts/prompt_0.txt"), days_ago(40));

        let stats = cleanup_session_dir_with(&idle, TTL_DAYS, renamer, || {}, || {}, |_| {});

        assert_eq!(CleanupStats { sessions_removed: 1, ..CleanupStats::default() }, stats, "{rule}");
        assert!(!idle.exists(), "{rule}");
        assert!(entry_names(&tmp.path().join("cwd")).is_empty(), "{rule}: nothing left behind");
    }
}

/// Under the NTFS rule a handle another process (or this one) has open inside the session refuses the rename: the
/// session is kept whole, nothing is deleted, and no removal folder appears.
#[cfg(target_os = "linux")]
#[test]
fn an_open_handle_inside_an_idle_session_keeps_it_whole_under_the_ntfs_rule() {
    let tmp = sessions_tmp();
    let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));
    write(&idle.join("prompts/prompt_0.txt"), days_ago(40));
    let open = std::fs::File::open(idle.join("updates.jsonl")).unwrap();

    let stats = cleanup_session_dir_with(&idle, TTL_DAYS, &NtfsLikeRename, || {}, || {}, |_| {});

    assert_eq!(0, stats.sessions_removed, "{stats:?}");
    assert_eq!(1, stats.errors, "{stats:?}");
    assert!(idle.join("summary.json").is_file());
    assert!(idle.join("prompts/prompt_0.txt").is_file());
    assert!(entry_names(&tmp.path().join("cwd")).iter().all(|name| !name.starts_with(".fuigo-sweep-removing-")));
    drop(open);
}

/// The race protection P172 added holds under every rename rule. An attach between the sweep's last look and its
/// rename cannot mark the session (the sweep still holds its lock), so the sweep never removes a session an attach has
/// just marked; an attach before the sweep's locks keeps the session; an attach after the rename finds nothing.
#[test]
fn the_attach_races_hold_under_every_rename_rule() {
    for (rule, renamer) in renamers() {
        let tmp = sessions_tmp();
        let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));
        let mut during = None;
        let stats = cleanup_session_dir_with(
            &idle,
            TTL_DAYS,
            renamer,
            || {},
            || during = Some(block_on(mark_session_live_waiting(&idle, Duration::from_millis(100)))),
            |_| assert!(block_on(mark_session_live(&idle)).is_ok()),
        );
        assert!(during.expect("hook ran").is_err(), "{rule}: no mark between the last look and the rename");
        assert_eq!(1, stats.sessions_removed, "{rule}: {stats:?}");
        assert!(!idle.exists(), "{rule}: an attach after the rename recreates nothing");

        let attaching = write_session(tmp.path(), "cwd", "attaching", days_ago(40));
        let stats = cleanup_session_dir_with(&attaching, TTL_DAYS, renamer, || mark(&attaching), || {}, |_| {});
        assert_eq!(CleanupStats::default(), stats, "{rule}");
        assert!(attaching.join("updates.jsonl").is_file(), "{rule}");
    }
}

/// A sweep lock whose session no longer exists (deleted by hand) is cleared once it is older than the TTL.
#[test]
fn an_orphaned_sweep_lock_is_cleared_after_the_ttl() {
    let tmp = sessions_tmp();
    let gone = tmp.path().join("cwd").join("gone");
    let lock = sweep_lock_path(&gone).unwrap();
    write(&lock, days_ago(40));
    // A session's own lock is never removed, however old: an attach may hold it, and a fresh file at the same path
    // would let a sweep and that attach lock different files
    let fresh = write_session(tmp.path(), "cwd", "fresh", days_ago(0));
    let fresh_lock = sweep_lock_path(&fresh).unwrap();
    write(&fresh_lock, days_ago(40));
    // An orphan younger than the TTL may be a mark that is still running
    let young_orphan = sweep_lock_path(&tmp.path().join("cwd").join("young")).unwrap();
    write(&young_orphan, days_ago(1));

    sweep(tmp.path(), None);

    assert!(!lock.exists());
    assert!(!gone.exists());
    assert!(fresh.join("summary.json").is_file());
    assert!(fresh_lock.is_file());
    assert!(young_orphan.is_file());
}

// ── P178 (LOW): an attach that cannot bump `summary.json` ──

/// `touch` that fails for the named files, as a read-only file or a Windows sharing violation does.
fn touch_failing_for(names: &'static [&'static str]) -> impl Fn(&Path) -> std::io::Result<()> {
    move |path| {
        if names.iter().any(|name| path.file_name() == Some(std::ffi::OsStr::new(name))) {
            Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "read-only"))
        } else {
            touch_nofollow(path)
        }
    }
}

fn mtime(path: &Path) -> SystemTime {
    std::fs::metadata(path).unwrap().modified().unwrap()
}

/// `summary.json` cannot be bumped: the attach marks the transcript instead, and a sweep keeps the session.
#[test]
fn an_attach_that_cannot_bump_the_summary_marks_the_transcript_instead() {
    let tmp = sessions_tmp();
    let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));

    let outcome =
        block_on(mark_session_live_with(&idle, Duration::from_secs(5), &touch_failing_for(&["summary.json"])));

    assert!(outcome.is_ok());
    assert!(mtime(&idle.join("updates.jsonl")) > SystemTime::now() - Duration::from_secs(3600));
    assert_eq!(CleanupStats::default(), sweep(tmp.path(), None));
    assert!(idle.join("summary.json").is_file());
}

/// Nothing in an idle session can be bumped: the load fails clearly instead of loading a session a concurrent sweep
/// may remove under it (the actor's first write would then recreate half a session).
#[test]
fn an_idle_session_that_cannot_be_marked_at_all_is_not_loaded() {
    let tmp = sessions_tmp();
    let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));
    let before = mtime(&idle.join("summary.json"));

    let outcome = block_on(mark_session_live_with(
        &idle,
        Duration::from_secs(5),
        &touch_failing_for(&["summary.json", "updates.jsonl"]),
    ));

    assert!(matches!(outcome, Err(MarkLiveError::Unmarkable { .. })), "{outcome:?}");
    assert_eq!(before, mtime(&idle.join("summary.json")));
}

/// A session used within the last day cannot be swept by any TTL (the minimum is one day), so it still loads even
/// when nothing in it can be bumped.
#[test]
fn a_recently_used_session_that_cannot_be_marked_still_loads() {
    let tmp = sessions_tmp();
    let recent = write_session(tmp.path(), "cwd", "recent", days_ago(0));

    let outcome = block_on(mark_session_live_with(
        &recent,
        Duration::from_secs(5),
        &touch_failing_for(&["summary.json", "updates.jsonl"]),
    ));

    assert!(outcome.is_ok());
}

// ── P178 (LOW): activity inside subfolders ──

/// A session whose only recent writes are inside a subfolder is in use: it is kept.
#[test]
fn a_write_only_inside_a_subfolder_keeps_the_session() {
    for rel in [
        "subagents/child/updates.jsonl",
        "compaction_checkpoints/b.json",
        "prompts/prompt_9.txt",
        "terminal/t.log",
    ] {
        let tmp = sessions_tmp();
        let session = write_session(tmp.path(), "cwd", "s1", days_ago(40));
        write(&session.join(rel), days_ago(0));

        let stats = sweep(tmp.path(), None);

        assert_eq!(0, stats.sessions_removed, "{rel}: {stats:?}");
        assert!(session.join("summary.json").is_file(), "{rel}");
        assert!(session.join(rel).is_file(), "{rel}");
    }
}

/// The activity scan looks at a bounded number of entries; past the bound it gives up with an error (the session is
/// then kept, never judged on a partial look). It never follows a symlinked folder.
#[test]
fn the_activity_scan_is_bounded_and_never_follows_a_link() {
    let tmp = sessions_tmp();
    let session = write_session(tmp.path(), "cwd", "s1", days_ago(40));
    for i in 0..20 {
        write(&session.join(format!("subagents/c{i}/updates.jsonl")), days_ago(40));
    }

    assert!(session_last_activity_within(&session, 10).is_err());
    let newest = session_last_activity_within(&session, 1_000).unwrap().unwrap();
    assert!(newest < SystemTime::now() - Duration::from_secs(39 * 86_400));

    #[cfg(unix)]
    {
        let outside = TempDir::new().unwrap();
        write(&outside.path().join("fresh.txt"), days_ago(0));
        std::os::unix::fs::symlink(outside.path(), session.join("linked")).unwrap();
        let newest = session_last_activity_within(&session, 1_000).unwrap().unwrap();
        assert!(newest < SystemTime::now() - Duration::from_secs(39 * 86_400));
    }
}

// ── P178 Astra r1 ──

/// HIGH: a worktree identity repair records `summary.json`'s mtime, rewrites the file and restores the old mtime under
/// `summary.json.lock`. An attach that bumps the summary inside that window has its mark erased, and a sweep then
/// removes the session the attach is loading. The attach must bump under the same lock, and while a repair holds it,
/// mark the transcript (which the repair never touches).
#[test]
fn an_identity_repair_in_progress_cannot_erase_an_attachs_mark() {
    let tmp = sessions_tmp();
    let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));
    // The repair is between "record the mtime" and "restore it": it holds the summary's sidecar lock
    let repair = open_lock_nofollow(&idle, "summary.json.lock").expect("sidecar lock");
    fs2::FileExt::try_lock_exclusive(&repair).expect("the repair's exclusive lock");
    // An old session's sidecar lock is as old as its last summary write (a fresh one would itself count as activity)
    filetime::set_file_mtime(idle.join("summary.json.lock"), days_ago(40)).unwrap();

    let outcome = block_on(mark_session_live_waiting(&idle, Duration::from_millis(200)));
    // The repair restores the old mtime and releases its lock
    filetime::set_file_mtime(idle.join("summary.json"), days_ago(40)).unwrap();
    drop(repair);

    assert!(outcome.is_ok(), "{outcome:?}");
    // P176 (Astra r2): released first, so the timestamp alone must keep the session (a held mark keeps it anyway)
    drop(outcome);
    assert!(mtime(&idle.join("updates.jsonl")) > SystemTime::now() - Duration::from_secs(3600), "the transcript was marked");
    assert_eq!(CleanupStats::default(), sweep(tmp.path(), None), "the attach's mark survives the repair");
    assert!(idle.join("summary.json").is_file());
}

/// A mark with the sidecar lock free bumps the summary itself (the transcript keeps its own mtime).
#[test]
fn a_mark_with_no_repair_running_bumps_the_summary() {
    let tmp = sessions_tmp();
    let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));

    mark(&idle);

    assert!(mtime(&idle.join("summary.json")) > SystemTime::now() - Duration::from_secs(3600));
    assert!(mtime(&idle.join("updates.jsonl")) < SystemTime::now() - Duration::from_secs(39 * 86_400));
}

/// LOW: activity deeper than the old bound counts, and a tree deeper than the scan's bound keeps the session instead
/// of hiding its fresh files.
#[test]
fn deep_activity_counts_and_a_tree_past_the_depth_bound_is_kept() {
    let tmp = sessions_tmp();
    let nested = write_session(tmp.path(), "cwd", "nested", days_ago(40));
    write(&nested.join("subagents/a/subagents/b/prompts/p.txt"), days_ago(0));
    let too_deep = write_session(tmp.path(), "cwd", "too-deep", days_ago(40));
    write(&too_deep.join("a/b/c/d/e/f/g/h/i/old.txt"), days_ago(40));

    assert!(session_last_activity_within(&too_deep, 1_000).is_err());
    let stats = sweep(tmp.path(), None);

    assert_eq!(0, stats.sessions_removed, "{stats:?}");
    assert!(nested.join("summary.json").is_file());
    assert!(too_deep.join("summary.json").is_file());
}

/// LOW: an orphaned sweep lock that someone holds (a mark that lost the race with a removal) is not removed under them.
#[test]
fn a_held_orphaned_sweep_lock_is_kept() {
    let tmp = sessions_tmp();
    let gone = tmp.path().join("cwd").join("gone");
    let lock_path = sweep_lock_path(&gone).unwrap();
    write(&lock_path, days_ago(40));
    write_session(tmp.path(), "cwd", "fresh", days_ago(0));
    let held = std::fs::OpenOptions::new().read(true).write(true).open(&lock_path).unwrap();
    fs2::FileExt::try_lock_shared(&held).unwrap();

    sweep(tmp.path(), None);

    assert!(lock_path.is_file());
    drop(held);
}

/// An attach waiting on the sweep lock while the real sweep renames the session and unlinks the lock file: once the
/// lock is released it finds no session, recreates nothing, and no lock file is left behind.
#[test]
fn a_waiting_attach_survives_the_unlinked_lock_and_finds_nothing() {
    for (rule, renamer) in renamers() {
        let tmp = sessions_tmp();
        let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));
        let lock_path = sweep_lock_path(&idle).unwrap();
        let mut waiter = None;
        let stats = cleanup_session_dir_with(
            &idle,
            TTL_DAYS,
            renamer,
            || {},
            || {
                let idle = idle.clone();
                waiter =
                    Some(std::thread::spawn(move || block_on(mark_session_live_waiting(&idle, Duration::from_secs(60)))));
                wait_until_the_waiter_holds_the_lock(&lock_path);
            },
            |_| {},
        );
        let outcome = waiter.expect("hook ran").join().unwrap();
        // An attach that starts after the unlink finds nothing either, and creates no lock file
        assert!(block_on(mark_session_live(&idle)).is_ok(), "{rule}");

        assert!(outcome.is_ok(), "{rule}: {outcome:?}");
        // P176 (Astra r2): the waiter's mark holds the unlinked lock file; Windows deletes it once that closes
        drop(outcome);
        assert_eq!(1, stats.sessions_removed, "{rule}: {stats:?}");
        assert!(!idle.exists(), "{rule}");
        assert!(entry_names(&tmp.path().join("cwd")).is_empty(), "{rule}: {:?}", entry_names(&tmp.path().join("cwd")));
    }
}

/// Handshake for the waiter test: on Linux, until a second descriptor (the waiter's, beside the sweep's own) is open on
/// the original lock file; elsewhere a generous pause.
fn wait_until_the_waiter_holds_the_lock(lock_path: &Path) {
    #[cfg(target_os = "linux")]
    {
        let lock_path = dunce::canonicalize(lock_path).unwrap();
        let started = std::time::Instant::now();
        loop {
            let holders = std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .flatten()
                .filter(|fd| std::fs::read_link(fd.path()).is_ok_and(|target| target == lock_path))
                .count();
            if holders >= 2 {
                return;
            }
            assert!(started.elapsed() < Duration::from_secs(30), "the waiter never opened the sweep lock");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = lock_path;
        std::thread::sleep(Duration::from_millis(1_000));
    }
}

// ── P178 Astra r2 ──

/// HIGH: a repair has published a fresh summary and holds the sidecar lock before backdating it; the transcript cannot
/// be bumped. The fresh-looking summary is not trusted as recent use without the lock: the load fails.
#[test]
fn a_summary_a_repair_is_about_to_backdate_is_not_trusted_as_recent_use() {
    let tmp = sessions_tmp();
    let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));
    let repair = open_lock_nofollow(&idle, "summary.json.lock").expect("sidecar lock");
    fs2::FileExt::try_lock_exclusive(&repair).expect("the repair's exclusive lock");
    filetime::set_file_mtime(idle.join("summary.json.lock"), days_ago(40)).unwrap();
    // The repair's replacement summary, not yet backdated
    filetime::set_file_mtime(idle.join("summary.json"), days_ago(0)).unwrap();

    let outcome = block_on(mark_session_live_with(
        &idle,
        Duration::from_millis(200),
        &touch_failing_for(&["updates.jsonl"]),
    ));
    drop(repair);

    assert!(matches!(outcome, Err(MarkLiveError::Unmarkable { .. })), "{outcome:?}");
}

// ── P176: hardening left by P172 and P178 ──

/// Every file under `dir` (recursively) backdated to `age`: what a loader suspended past the TTL finds when it resumes.
fn backdate_tree(dir: &Path, age: FileTime) {
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        let file_type = std::fs::symlink_metadata(&path).unwrap().file_type();
        if file_type.is_dir() {
            backdate_tree(&path, age);
        } else if file_type.is_file() {
            filetime::set_file_mtime(&path, age).unwrap();
        }
    }
}

fn removal_folders(cwd: &Path) -> Vec<String> {
    entry_names(cwd).into_iter().filter(|name| name.starts_with(".fuigo-sweep-removing-")).collect()
}

/// P178 residual (MEDIUM): an attach whose sweep lock fails for a reason other than contention (a filesystem whose
/// locks fail for it but not for the sweep) marks without waiting, so its mark can land between the sweep's last look
/// and its rename. The sweep looks again once the session is off its path and puts it back.
#[test]
fn an_unguarded_mark_between_the_last_look_and_the_rename_puts_the_session_back() {
    for (rule, renamer) in renamers() {
        let tmp = sessions_tmp();
        let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));
        write(&idle.join("prompts/prompt_0.txt"), days_ago(40));

        // What such an attach does: bump the summary without holding any lock
        let stats =
            cleanup_session_dir_with(&idle, TTL_DAYS, renamer, || {}, || touch_nofollow(&idle.join("summary.json")).unwrap(), |_| {});

        assert_eq!(0, stats.sessions_removed, "{rule}: {stats:?}");
        assert!(idle.join("summary.json").is_file(), "{rule}: the session is back at its path");
        assert!(idle.join("prompts/prompt_0.txt").is_file(), "{rule}");
        assert!(removal_folders(&tmp.path().join("cwd")).is_empty(), "{rule}");
        // Its sweep lock stays: an attach may hold it
        assert!(sweep_lock_path(&idle).unwrap().is_file(), "{rule}");
    }
}

/// On a filesystem without usable locks the load still works (the mark goes ahead unguarded), and a sweep that cannot
/// lock the session keeps it.
#[test]
fn without_a_usable_sweep_lock_the_load_works_and_the_sweep_keeps_the_session() {
    let tmp = sessions_tmp();
    let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));
    // A folder where the lock file should be: neither the attach nor the sweep can open it as a lock
    std::fs::create_dir(sweep_lock_path(&idle).unwrap()).unwrap();

    let stats = cleanup_session_dir_with(&idle, TTL_DAYS, &StdRename, || {}, || {}, |_| {});
    assert_eq!(0, stats.sessions_removed, "{stats:?}");
    assert!(idle.join("updates.jsonl").is_file());

    let before = std::fs::metadata(idle.join("summary.json")).unwrap().modified().unwrap();
    let outcome = block_on(mark_session_live_waiting(&idle, Duration::from_millis(200)));
    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(std::fs::metadata(idle.join("summary.json")).unwrap().modified().unwrap() > before);
}

/// P178 residual (LOW): the mark's timestamp alone did not protect a load suspended past the TTL. The attach now holds
/// its mark (the session's sweep lock, shared) until its actor holds `turn_owner.lock`, so a sweep keeps the session
/// however old its files look meanwhile; once the mark is released (and no actor holds the session) it is removed.
#[test]
fn a_held_mark_keeps_a_session_whose_load_outlives_the_ttl() {
    for (rule, renamer) in renamers() {
        let tmp = sessions_tmp();
        let loading = write_session(tmp.path(), "cwd", "loading", days_ago(40));
        let held = block_on(mark_session_live(&loading)).expect("mark");
        backdate_tree(&loading, days_ago(40));

        let stats = cleanup_session_dir_with(&loading, TTL_DAYS, renamer, || {}, || {}, |_| {});
        assert_eq!(0, stats.sessions_removed, "{rule}: {stats:?}");
        assert!(loading.join("summary.json").is_file(), "{rule}");

        drop(held);
        let stats = cleanup_session_dir_with(&loading, TTL_DAYS, renamer, || {}, || {}, |_| {});
        assert_eq!(1, stats.sessions_removed, "{rule}: {stats:?}");
        assert!(!loading.exists(), "{rule}");
    }
}

/// P172/Fable (INFO): the folders above a session were not pinned. A cwd folder swapped for a symlink between the
/// sweep's last look and its rename led the rename and the deletion outside the sessions tree. Now the rename is
/// relative to the pinned cwd folder, and the sweep keeps the session when a folder on its path changed.
#[cfg(unix)]
#[test]
fn a_folder_above_the_session_swapped_for_a_link_never_leads_the_sweep_outside() {
    let tmp = sessions_tmp();
    let outside = TempDir::new().unwrap();
    let victim = write_session(outside.path(), "x", "idle", days_ago(40));
    write(&victim.join("victim.txt"), days_ago(40));
    let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));
    let cwd = tmp.path().join("cwd");
    let moved = tmp.path().join("cwd-moved");
    let renamer = CountingRename(std::cell::Cell::new(0));

    let stats = cleanup_session_dir_with(
        &idle,
        TTL_DAYS,
        &renamer,
        || {},
        || {
            std::fs::rename(&cwd, &moved).unwrap();
            std::os::unix::fs::symlink(outside.path().join("x"), &cwd).unwrap();
        },
        |_| {},
    );

    assert_eq!(0, renamer.0.get(), "a session whose path changed is not acted on at all");
    assert_eq!(0, stats.sessions_removed, "{stats:?}");
    assert!(victim.join("victim.txt").is_file(), "nothing outside the sessions tree is moved or deleted");
    assert!(victim.join("summary.json").is_file());
    assert!(entry_names(&outside.path().join("x")).iter().all(|name| !name.starts_with('.')), "no removal folder outside");
    assert!(moved.join("idle/summary.json").is_file(), "the session is kept when its path changed");
}

/// The production rename, counting its calls.
struct CountingRename(std::cell::Cell<usize>);

impl SessionDirRename for CountingRename {
    fn rename(&self, dir: &PinnedDir, from: &OsStr, to: &OsStr) -> std::io::Result<()> {
        self.0.set(self.0.get() + 1);
        StdRename.rename(dir, from, to)
    }
}

/// The same swap during a whole sweep's prune of a session in use: what is pruned is the pinned session's cache, never
/// a cache reached through the swapped-in link.
#[cfg(unix)]
#[test]
fn a_cache_prune_stays_in_the_pinned_session_when_a_folder_above_is_swapped() {
    let tmp = sessions_tmp();
    let outside = TempDir::new().unwrap();
    let foreign = write_session(outside.path(), "x", "s1", days_ago(0));
    write(&foreign.join("images/foreign.png"), days_ago(40));
    let session = write_session(tmp.path(), "cwd", "s1", days_ago(0));
    write(&session.join("images/old.png"), days_ago(40));
    let cwd = tmp.path().join("cwd");
    let moved = tmp.path().join("cwd-moved");

    let pinned = PinnedDir::open_root(&cwd).unwrap();
    std::fs::rename(&cwd, &moved).unwrap();
    std::os::unix::fs::symlink(outside.path().join("x"), &cwd).unwrap();
    let mut stats = CleanupStats::default();
    prune_pinned_session_caches(&pinned, OsStr::new("s1"), TTL_DAYS, &mut stats);

    assert!(foreign.join("images/foreign.png").is_file(), "nothing reached through the link is pruned");
    assert!(!moved.join("s1/images/old.png").exists(), "the pinned session's own stale cache is pruned");
    assert_eq!(1, stats.files_deleted, "{stats:?}");
}

/// A cwd folder that is a symlink is never entered by a whole sweep, and nothing beneath its target is touched.
#[cfg(unix)]
#[test]
fn a_symlinked_cwd_folder_is_never_entered() {
    let tmp = sessions_tmp();
    let outside = TempDir::new().unwrap();
    let foreign = write_session(outside.path(), "x", "idle", days_ago(40));
    write(&foreign.join("images/old.png"), days_ago(40));
    std::os::unix::fs::symlink(outside.path().join("x"), tmp.path().join("linked")).unwrap();

    let stats = sweep(tmp.path(), None);

    assert_eq!(0, stats.sessions_removed, "{stats:?}");
    assert!(foreign.join("summary.json").is_file());
    assert!(foreign.join("images/old.png").is_file());
}

/// A rename that, once it has moved the session, puts a non-empty folder at its old path: what an actor that
/// recreated the session folder there would leave.
struct RenameThenRecreate;

impl SessionDirRename for RenameThenRecreate {
    fn rename(&self, dir: &PinnedDir, from: &OsStr, to: &OsStr) -> std::io::Result<()> {
        dir.rename_child(from, to)?;
        write(&dir.child_path(from).join("updates.jsonl"), days_ago(0));
        Ok(())
    }
}

/// A session marked meanwhile that cannot be put back (its path was taken) is kept under a name no sweep removes,
/// never deleted.
#[test]
fn a_marked_session_whose_path_was_taken_is_kept_aside_never_deleted() {
    let tmp = sessions_tmp();
    let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));
    write(&idle.join("prompts/prompt_0.txt"), days_ago(40));

    let stats = cleanup_session_dir_with(
        &idle,
        TTL_DAYS,
        &RenameThenRecreate,
        || {},
        || touch_nofollow(&idle.join("summary.json")).unwrap(),
        |_| {},
    );

    assert_eq!(0, stats.sessions_removed, "{stats:?}");
    let cwd = tmp.path().join("cwd");
    let kept: Vec<String> = entry_names(&cwd).into_iter().filter(|name| name.starts_with(".fuigo-sweep-kept-idle-")).collect();
    assert_eq!(1, kept.len(), "{:?}", entry_names(&cwd));
    assert!(cwd.join(&kept[0]).join("prompts/prompt_0.txt").is_file());
    assert!(idle.join("updates.jsonl").is_file(), "what was recreated at the path is untouched");

    // No later sweep removes it, however old it gets
    backdate_tree(&cwd.join(&kept[0]), days_ago(400));
    sweep(tmp.path(), None);
    assert!(cwd.join(&kept[0]).join("prompts/prompt_0.txt").is_file());
}

/// A removal folder with activity newer than the TTL is not a finished decision (P176): the next sweep keeps it.
#[test]
fn a_removal_folder_with_fresh_activity_is_kept() {
    let tmp = sessions_tmp();
    let fresh_leftover = tmp.path().join("cwd").join(".fuigo-sweep-removing-busy-1-2");
    write(&fresh_leftover.join("updates.jsonl"), days_ago(0));

    sweep(tmp.path(), None);

    assert!(fresh_leftover.join("updates.jsonl").is_file());
}

// ── P176 Astra r1 (HIGH): a second sweep and the first one's put-back ──

/// A rename after which a second sweep of the whole tree runs, and then a mark whose descriptor was opened before the
/// rename lands on the moved folder.
struct RenameThenSecondSweep<'a> {
    root: &'a Path,
    second: std::cell::RefCell<Option<CleanupStats>>,
}

impl SessionDirRename for RenameThenSecondSweep<'_> {
    fn rename(&self, dir: &PinnedDir, from: &OsStr, to: &OsStr) -> std::io::Result<()> {
        dir.rename_child(from, to)?;
        *self.second.borrow_mut() = Some(sweep(self.root, None));
        let _ = touch_nofollow(&dir.child_path(to).join("summary.json"));
        Ok(())
    }
}

/// The first sweep holds the session's sweep lock until it has put the session back or committed to removing it, and a
/// second sweep deletes a removal folder only under that lock: it never deletes a folder the first one puts back.
#[test]
fn a_second_sweep_never_deletes_a_removal_the_first_may_still_put_back() {
    let tmp = sessions_tmp();
    let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));
    write(&idle.join("prompts/prompt_0.txt"), days_ago(40));
    let renamer = RenameThenSecondSweep { root: tmp.path(), second: std::cell::RefCell::new(None) };

    let first = cleanup_session_dir_with(&idle, TTL_DAYS, &renamer, || {}, || {}, |_| {});

    let second = renamer.second.borrow_mut().take().expect("the second sweep ran");
    assert_eq!(0, second.dirs_removed, "{second:?}");
    assert_eq!(0, first.sessions_removed, "{first:?}");
    assert!(idle.join("summary.json").is_file(), "put back whole");
    assert!(idle.join("prompts/prompt_0.txt").is_file());
    assert!(removal_folders(&tmp.path().join("cwd")).is_empty());
}

/// A removal folder its sweep has committed to (or left behind by a crash) is finished by the next sweep, and the
/// sweep lock that cleanup took for a session that no longer exists does not stay behind.
#[test]
fn an_orphaned_removal_folder_is_finished_under_its_sessions_lock() {
    let tmp = sessions_tmp();
    let leftover = tmp.path().join("cwd").join(".fuigo-sweep-removing-a-b-c-123-456");
    write(&leftover.join("updates.jsonl"), days_ago(40));
    // A name that does not parse is kept
    let odd = tmp.path().join("cwd").join(".fuigo-sweep-removing-odd");
    write(&odd.join("updates.jsonl"), days_ago(40));
    let fresh = write_session(tmp.path(), "cwd", "fresh", days_ago(0));

    let stats = sweep(tmp.path(), None);

    assert_eq!(1, stats.dirs_removed, "{stats:?}");
    assert!(!leftover.exists());
    assert!(odd.join("updates.jsonl").is_file());
    assert!(!sweep_lock_path(&tmp.path().join("cwd").join("a-b-c")).unwrap().exists());
    assert!(fresh.join("updates.jsonl").is_file());
}

/// While its session's sweep lock is held (a sweep deciding about it), a removal folder is left alone.
#[test]
fn a_removal_folder_whose_session_lock_is_held_is_left_alone() {
    let tmp = sessions_tmp();
    let leftover = tmp.path().join("cwd").join(".fuigo-sweep-removing-busy-1-2");
    write(&leftover.join("updates.jsonl"), days_ago(40));
    let lock = open_sweep_lock(&tmp.path().join("cwd").join("busy")).expect("lock file");
    fs2::FileExt::try_lock_exclusive(&lock).expect("the deciding sweep's lock");

    let stats = sweep(tmp.path(), None);

    assert_eq!(0, stats.dirs_removed, "{stats:?}");
    assert!(leftover.join("updates.jsonl").is_file());
    drop(lock);
}

// ── P176 Astra r3 (MEDIUM): the put-back never replaces what took the session's path ──

/// A rename that, once it has moved the session, leaves an EMPTY folder at its old path: a creator that recreated the
/// session folder and has not written into it yet.
struct RenameThenRecreateEmpty;

impl SessionDirRename for RenameThenRecreateEmpty {
    fn rename(&self, dir: &PinnedDir, from: &OsStr, to: &OsStr) -> std::io::Result<()> {
        dir.rename_child(from, to)?;
        std::fs::create_dir(dir.child_path(from)).unwrap();
        Ok(())
    }
}

/// A plain rename would replace that empty folder (the creator would then write into the put-back session); the
/// put-back never replaces anything, and the moved session is kept aside instead.
#[test]
fn a_put_back_never_replaces_an_empty_folder_that_took_the_path() {
    let tmp = sessions_tmp();
    let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));
    write(&idle.join("prompts/prompt_0.txt"), days_ago(40));

    let stats = cleanup_session_dir_with(
        &idle,
        TTL_DAYS,
        &RenameThenRecreateEmpty,
        || {},
        || touch_nofollow(&idle.join("summary.json")).unwrap(),
        |_| {},
    );

    assert_eq!(0, stats.sessions_removed, "{stats:?}");
    let cwd = tmp.path().join("cwd");
    let kept: Vec<String> = entry_names(&cwd).into_iter().filter(|name| name.starts_with(".fuigo-sweep-kept-idle-")).collect();
    assert_eq!(1, kept.len(), "{:?}", entry_names(&cwd));
    assert!(cwd.join(&kept[0]).join("prompts/prompt_0.txt").is_file());
    assert!(idle.is_dir() && entry_names(&idle).is_empty(), "the creator's folder is left as it was");
}

/// A filesystem without the no-replace rename (`EINVAL`): the put-back must not fall back to a plain rename, which
/// would replace the empty folder that took the path. The session is kept aside whole.
#[cfg(unix)]
#[test]
fn a_put_back_without_a_no_replace_rename_keeps_the_session_aside_and_replaces_nothing() {
    let tmp = sessions_tmp();
    let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));
    write(&idle.join("prompts/prompt_0.txt"), days_ago(40));

    // The empty folder appears only after the unsupported error, where a plain rename would have run
    let path = idle.clone();
    PinnedDir::fail_next_noreplace_with_einval(Some(Box::new(move || std::fs::create_dir(path).unwrap())));
    let stats = cleanup_session_dir_with(
        &idle,
        TTL_DAYS,
        &StdRename,
        || {},
        || touch_nofollow(&idle.join("summary.json")).unwrap(),
        |_| {},
    );

    assert_eq!(0, stats.sessions_removed, "{stats:?}");
    let cwd = tmp.path().join("cwd");
    let names = entry_names(&cwd);
    let kept: Vec<&String> = names.iter().filter(|name| name.starts_with(".fuigo-sweep-kept-idle-")).collect();
    assert_eq!(1, kept.len(), "{names:?}");
    assert!(names.iter().all(|name| !name.starts_with(".fuigo-sweep-removing-")), "{names:?}");
    assert!(cwd.join(kept[0]).join("prompts/prompt_0.txt").is_file());
    assert!(cwd.join(kept[0]).join("summary.json").is_file());
    assert!(idle.is_dir() && entry_names(&idle).is_empty(), "the creator's folder is not replaced");
}

/// Same error with nothing at the old path: no plain rename at all, the session is kept aside (a warning names it).
#[cfg(unix)]
#[test]
fn a_put_back_without_a_no_replace_rename_keeps_the_session_aside_even_when_the_path_is_free() {
    let tmp = sessions_tmp();
    let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));
    write(&idle.join("prompts/prompt_0.txt"), days_ago(40));

    let stats = cleanup_session_dir_with(
        &idle,
        TTL_DAYS,
        &StdRename,
        || {},
        || {
            touch_nofollow(&idle.join("summary.json")).unwrap();
            PinnedDir::fail_next_noreplace_with_einval(None);
        },
        |_| {},
    );

    assert_eq!(0, stats.sessions_removed, "{stats:?}");
    let cwd = tmp.path().join("cwd");
    let names = entry_names(&cwd);
    let kept: Vec<&String> = names.iter().filter(|name| name.starts_with(".fuigo-sweep-kept-idle-")).collect();
    assert_eq!(1, kept.len(), "{names:?}");
    assert!(!idle.exists(), "no plain rename put it back");
    assert!(cwd.join(kept[0]).join("prompts/prompt_0.txt").is_file());
}

#[test]
fn a_no_replace_rename_refuses_an_empty_folder_and_renames_otherwise() {
    let tmp = TempDir::new().unwrap();
    std::fs::create_dir(tmp.path().join("a")).unwrap();
    std::fs::create_dir(tmp.path().join("b")).unwrap();
    let dir = PinnedDir::open_root(tmp.path()).unwrap();

    let error = dir.rename_child_noreplace(OsStr::new("a"), OsStr::new("b")).unwrap_err();
    assert_eq!(std::io::ErrorKind::AlreadyExists, error.kind(), "{error}");
    dir.rename_child_noreplace(OsStr::new("a"), OsStr::new("c")).unwrap();
    assert!(tmp.path().join("c").is_dir() && !tmp.path().join("a").exists());
}

/// The production rename, run right after the cwd folder was swapped for a link (after the sweep's last check of the
/// path chain).
#[cfg(unix)]
struct SwapThenRename<'a> {
    cwd: &'a Path,
    moved: &'a Path,
    target: &'a Path,
}

#[cfg(unix)]
impl SessionDirRename for SwapThenRename<'_> {
    fn rename(&self, dir: &PinnedDir, from: &OsStr, to: &OsStr) -> std::io::Result<()> {
        std::fs::rename(self.cwd, self.moved).unwrap();
        std::os::unix::fs::symlink(self.target, self.cwd).unwrap();
        StdRename.rename(dir, from, to)
    }
}

/// Even a swap after the last check cannot lead the rename outside: it is relative to the pinned cwd folder, so it
/// moves the real session, and the look after the rename (through the swapped path) fails safe and puts it back.
#[cfg(unix)]
#[test]
fn a_folder_swapped_after_the_last_check_still_cannot_lead_the_rename_outside() {
    let tmp = sessions_tmp();
    let outside = TempDir::new().unwrap();
    let victim = write_session(outside.path(), "x", "idle", days_ago(40));
    write(&victim.join("victim.txt"), days_ago(40));
    let idle = write_session(tmp.path(), "cwd", "idle", days_ago(40));
    let (cwd, moved, target) = (tmp.path().join("cwd"), tmp.path().join("cwd-moved"), outside.path().join("x"));
    let renamer = SwapThenRename { cwd: &cwd, moved: &moved, target: &target };

    let stats = cleanup_session_dir_with(&idle, TTL_DAYS, &renamer, || {}, || {}, |_| {});

    assert_eq!(0, stats.sessions_removed, "{stats:?}");
    assert!(victim.join("victim.txt").is_file(), "nothing outside the sessions tree is moved or deleted");
    assert!(entry_names(&target).iter().all(|name| !name.starts_with('.')), "no removal folder outside");
    assert!(moved.join("idle/summary.json").is_file(), "the real session is put back whole");
}

/// Lock hygiene (R-lock-hygiene): a sweep's exclusive lock (the sweep lock, the turn-owner lock) is free once released,
/// even while a copy of its descriptor (a forked child's, here `try_clone`) lives on.
#[test]
fn a_released_sweep_lock_is_free_although_a_copy_of_its_descriptor_lives_on() {
    let tmp = TempDir::new().unwrap();
    let cwd = PinnedDir::open_root(tmp.path()).unwrap();
    let held = super::try_lock_exclusive_pinned(tmp.path(), &cwd, ".sweeping-s1").expect("first lock");
    let inherited = held.try_clone().unwrap();
    drop(held);
    let again = super::try_lock_exclusive_pinned(tmp.path(), &cwd, ".sweeping-s1");
    drop(inherited);
    assert!(again.is_some(), "the released sweep lock stayed held by an inherited descriptor");
}
