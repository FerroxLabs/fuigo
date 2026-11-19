//! One writer per session across processes (1.0.30 P30-DIRECT).
//!
//! With the shared leader off, every Fuigo window runs its own agent, and two windows could open the same session and
//! both write its folder (`plan_mode.json`, `updates.jsonl`, ...), each clobbering the other's state. A process that opens a
//! session for writing (new, load, resume, a fork's child, a subagent; the leader for the sessions it holds) therefore
//! holds an exclusive OS advisory lock on `<session_dir>/session_writer.lock` for as long as the session is live in it.
//! Another process's open is refused before it writes anything ([`HELD_ELSEWHERE`]).
//!
//! The lock is the OS's (`flock` on Unix, `LockFileEx` on Windows, through `std::fs::File::try_lock`): closing the file
//! releases it, and so does the process ending in any way (crash, kill), so there is no PID file and no stale lock to
//! judge. Within one process it is re-entrant: the agent's early check on load, the session actor, an old actor still
//! draining and a reconnect all share one open file, counted here, and the lock goes when the last of them lets go.
//! Read-only uses (listing, previews, export, search, a fork's snapshot of its parent) never take it.
//!
//! The file is empty and never read or written; no copy, fork or export lists it (they copy named files).
//!
//! Moved unchanged from `fuigo-shell/src/session/session_writer_lock.rs` in 1.0.41 (F5-W) so every crate that writes a
//! session folder can reach it through [`crate::SessionWriter`]. Only visibility changed. The ACP error conversion
//! (`into_acp_error`, `held_elsewhere_error`) and `session_open_elsewhere`, which resolves an id to a folder, stay in
//! `fuigo-shell`, whose old module path re-exports this one.
#![allow(
    clippy::disallowed_methods,
    reason = "the choke point: the session_writer.lock the writer holds for its folder (design F5 5.2)"
)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::Duration;

/// Lock file inside the session directory.
pub const SESSION_WRITER_LOCK_FILE: &str = "session_writer.lock";

/// What a refused open says: the session is fine, it is open somewhere else.
pub const HELD_ELSEWHERE: &str = "This session is open in another Fuigo window. Close it there, or turn on the shared \
leader (`--leader`) to use it from several windows.";

/// How long a contended open retries before it is refused. A real holder keeps the lock for the session's whole life;
/// this only rides out a momentary hold, such as a starting window's `session_open_elsewhere` check.
pub(crate) const CONTENDED_RETRY: Duration = Duration::from_millis(300);
pub(crate) const CONTENDED_POLL: Duration = Duration::from_millis(10);
/// How many passing lock errors in a row one session folder may have before its lock is given up for the process
/// (as for a filesystem without locks), so an error that never clears is not retried, with a failing open, on every write.
const MAX_TRANSIENT_FAILURES: u32 = 8;

/// Consecutive passing lock errors, by session directory.
static TRANSIENT: LazyLock<Mutex<HashMap<PathBuf, u32>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn transient_failures() -> MutexGuard<'static, HashMap<PathBuf, u32>> {
    TRANSIENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct Held {
    file: std::fs::File,
    holders: usize,
}

/// The sessions this process holds, by session directory.
static HELD: LazyLock<Mutex<HashMap<PathBuf, Held>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn held() -> MutexGuard<'static, HashMap<PathBuf, Held>> {
    HELD.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// This process's hold on one session; the session is released when the last hold for it drops.
#[derive(Debug)]
#[must_use = "the session is released when this drops"]
pub struct SessionWriterLock {
    key: PathBuf,
}

impl Drop for SessionWriterLock {
    fn drop(&mut self) {
        let mut held = held();
        let Some(entry) = held.get_mut(&self.key) else {
            return;
        };
        entry.holders = entry.holders.saturating_sub(1);
        if entry.holders == 0
            && let Some(entry) = held.remove(&self.key)
        {
            // Unlock explicitly: a child another thread is forking right now inherits a copy of the descriptor and would
            // otherwise keep the lock until it execs (see `turn_owner_lock::unlock_on_drop`).
            let _ = entry.file.unlock();
        }
    }
}

/// Another process holds the session.
#[derive(Debug)]
pub struct HeldElsewhere;

pub(crate) fn key_for(session_dir: &Path) -> PathBuf {
    dunce::canonicalize(session_dir).unwrap_or_else(|_| session_dir.to_path_buf())
}

#[cfg(test)]
thread_local! {
    /// Test seam: the next this-many lock-file opens on this thread fail with EMFILE.
    pub(crate) static FAIL_LOCK_OPENS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn open_lock_file(session_dir: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(test)]
    if FAIL_LOCK_OPENS.with(|n| {
        let left = n.get();
        n.set(left.saturating_sub(1));
        left > 0
    }) {
        return Err(std::io::Error::from_raw_os_error(24));
    }
    // Owner-only like every session file: a lock file other users can open is a lock they can hold.
    crate::owner_only::open(
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false),
        &session_dir.join(SESSION_WRITER_LOCK_FILE),
    )
}

/// Take this process's hold on the session in `session_dir` for writing.
///
/// `Ok(None)` when there is nothing to lock: no session folder yet (it is created by the open itself, which then takes
/// the lock again from its actor), or a filesystem without advisory locks (warned once; the session then opens unlocked,
/// as before). `Err(HeldElsewhere)` when another process has it open.
pub async fn acquire(session_dir: &Path) -> Result<Option<SessionWriterLock>, HeldElsewhere> {
    if !session_dir.is_dir() {
        return Ok(None);
    }
    let key = key_for(session_dir);
    let deadline = tokio::time::Instant::now() + CONTENDED_RETRY;
    loop {
        match try_acquire(session_dir, &key) {
            Attempt::Held(lock) => return Ok(Some(lock)),
            // Nothing held now; the writer's own attach retries a transient failure on its next mutating call.
            Attempt::Unlockable | Attempt::Transient => return Ok(None),
            Attempt::Contended if tokio::time::Instant::now() >= deadline => {
                tracing::info!(dir = %session_dir.display(), "session is open in another process; not opening it");
                return Err(HeldElsewhere);
            }
            Attempt::Contended => tokio::time::sleep(CONTENDED_POLL).await,
        }
    }
}

pub(crate) enum Attempt {
    Held(SessionWriterLock),
    Contended,
    /// This filesystem cannot lock at all (see [`locking_unsupported`]): the session opens unlocked for good.
    Unlockable,
    /// A passing error (descriptor limit, no space, a momentary EACCES or EIO): nothing is held this time, and the
    /// next attempt tries again (audit S12-F1).
    Transient,
}

/// Whether `error` says the filesystem has no advisory locks (ENOLCK, ENOSYS, ENOTSUP/EOPNOTSUPP, Windows
/// `ERROR_INVALID_FUNCTION`), as opposed to a passing failure.
fn locking_unsupported(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::Unsupported {
        return true;
    }
    #[cfg(target_os = "linux")]
    const UNSUPPORTED: &[i32] = &[37, 38, 95];
    #[cfg(target_os = "macos")]
    const UNSUPPORTED: &[i32] = &[77, 78, 45];
    #[cfg(windows)]
    const UNSUPPORTED: &[i32] = &[1];
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    const UNSUPPORTED: &[i32] = &[];
    error
        .raw_os_error()
        .is_some_and(|code| UNSUPPORTED.contains(&code))
}

fn classify(session_dir: &Path, key: &Path, error: &std::io::Error) -> Attempt {
    report_unlockable(session_dir, error);
    if locking_unsupported(error) {
        return Attempt::Unlockable;
    }
    let mut failures = transient_failures();
    let count = failures.entry(key.to_path_buf()).or_insert(0);
    *count += 1;
    if *count >= MAX_TRANSIENT_FAILURES {
        failures.remove(key);
        tracing::warn!(dir = %session_dir.display(), %error, "session writer lock keeps failing; giving up on it for this session");
        return Attempt::Unlockable;
    }
    Attempt::Transient
}

pub(crate) fn try_acquire(session_dir: &Path, key: &Path) -> Attempt {
    let mut held = held();
    if let Some(entry) = held.get_mut(key) {
        entry.holders += 1;
        return Attempt::Held(SessionWriterLock {
            key: key.to_path_buf(),
        });
    }
    let file = match open_lock_file(session_dir) {
        Ok(file) => file,
        Err(error) => return classify(session_dir, key, &error),
    };
    match file.try_lock() {
        Ok(()) => {
            transient_failures().remove(key);
            held.insert(key.to_path_buf(), Held { file, holders: 1 });
            Attempt::Held(SessionWriterLock {
                key: key.to_path_buf(),
            })
        }
        Err(std::fs::TryLockError::WouldBlock) => Attempt::Contended,
        Err(std::fs::TryLockError::Error(error)) => classify(session_dir, key, &error),
    }
}

fn report_unlockable(session_dir: &Path, error: &std::io::Error) {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::debug!(dir = %session_dir.display(), %error, "session writer lock unavailable");
    } else {
        tracing::warn!(
            dir = %session_dir.display(),
            %error,
            "session writer lock unavailable (filesystem without advisory locks?); this session is not protected \
             against being opened in a second window. Further occurrences log at debug"
        );
    }
}

/// Whether another process holds the session in `session_dir` for writing. Never creates the lock file.
pub fn dir_open_elsewhere(session_dir: &Path) -> bool {
    let path = session_dir.join(SESSION_WRITER_LOCK_FILE);
    if !path.is_file() {
        return false;
    }
    let held = held();
    if held.contains_key(&key_for(session_dir)) {
        return false;
    }
    let Ok(file) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
    else {
        return false;
    };
    match file.try_lock() {
        Ok(()) => {
            let _ = file.unlock();
            false
        }
        Err(std::fs::TryLockError::WouldBlock) => true,
        Err(std::fs::TryLockError::Error(_)) => false,
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there"
)]
#[cfg(test)]
#[path = "lock_tests.rs"]
mod tests;
