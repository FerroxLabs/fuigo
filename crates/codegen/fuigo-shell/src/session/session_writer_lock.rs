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

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::Duration;

/// Lock file inside the session directory.
pub(crate) const SESSION_WRITER_LOCK_FILE: &str = "session_writer.lock";

/// What a refused open says: the session is fine, it is open somewhere else.
pub const HELD_ELSEWHERE: &str = "This session is open in another Fuigo window. Close it there, or turn on the shared \
leader (`--leader`) to use it from several windows.";

/// How long a contended open retries before it is refused. A real holder keeps the lock for the session's whole life;
/// this only rides out a momentary hold, such as a starting window's [`session_open_elsewhere`] check.
const CONTENDED_RETRY: Duration = Duration::from_millis(300);
const CONTENDED_POLL: Duration = Duration::from_millis(10);

struct Held {
    file: std::fs::File,
    holders: usize,
}

/// The sessions this process holds, by session directory.
static HELD: LazyLock<Mutex<HashMap<PathBuf, Held>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn held() -> MutexGuard<'static, HashMap<PathBuf, Held>> {
    HELD.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// This process's hold on one session; the session is released when the last hold for it drops.
#[derive(Debug)]
#[must_use = "the session is released when this drops"]
pub(crate) struct SessionWriterLock {
    key: PathBuf,
}

impl Drop for SessionWriterLock {
    fn drop(&mut self) {
        let mut held = held();
        let Some(entry) = held.get_mut(&self.key) else { return };
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
pub(crate) struct HeldElsewhere;

impl HeldElsewhere {
    pub(crate) fn into_acp_error(self) -> agent_client_protocol::Error {
        held_elsewhere_error()
    }
}

/// The refusal an open of a session held elsewhere answers: typed `session_unavailable` (clients that tell "held
/// elsewhere" from "missing" keep working), with [`HELD_ELSEWHERE`] as the headline too, so a window shows it as it is and
/// not under a generic "Internal error".
pub fn held_elsewhere_error() -> agent_client_protocol::Error {
    crate::acp_error::session_unavailable_headline(HELD_ELSEWHERE)
}

fn key_for(session_dir: &Path) -> PathBuf {
    dunce::canonicalize(session_dir).unwrap_or_else(|_| session_dir.to_path_buf())
}

fn open_lock_file(session_dir: &Path) -> std::io::Result<std::fs::File> {
    // Owner-only like every session file: a lock file other users can open is a lock they can hold.
    crate::session::storage::owner_only::open(
        std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false),
        &session_dir.join(SESSION_WRITER_LOCK_FILE),
    )
}

/// Take this process's hold on the session in `session_dir` for writing.
///
/// `Ok(None)` when there is nothing to lock: no session folder yet (it is created by the open itself, which then takes
/// the lock again from its actor), or a filesystem without advisory locks (warned once; the session then opens unlocked,
/// as before). `Err(HeldElsewhere)` when another process has it open.
pub(crate) async fn acquire(session_dir: &Path) -> Result<Option<SessionWriterLock>, HeldElsewhere> {
    if !session_dir.is_dir() {
        return Ok(None);
    }
    let key = key_for(session_dir);
    let deadline = tokio::time::Instant::now() + CONTENDED_RETRY;
    loop {
        match try_acquire(session_dir, &key) {
            Attempt::Held(lock) => return Ok(Some(lock)),
            Attempt::Unlockable => return Ok(None),
            Attempt::Contended if tokio::time::Instant::now() >= deadline => {
                tracing::info!(dir = %session_dir.display(), "session is open in another process; not opening it");
                return Err(HeldElsewhere);
            }
            Attempt::Contended => tokio::time::sleep(CONTENDED_POLL).await,
        }
    }
}

enum Attempt {
    Held(SessionWriterLock),
    Contended,
    Unlockable,
}

fn try_acquire(session_dir: &Path, key: &Path) -> Attempt {
    let mut held = held();
    if let Some(entry) = held.get_mut(key) {
        entry.holders += 1;
        return Attempt::Held(SessionWriterLock { key: key.to_path_buf() });
    }
    let file = match open_lock_file(session_dir) {
        Ok(file) => file,
        Err(error) => {
            report_unlockable(session_dir, &error);
            return Attempt::Unlockable;
        }
    };
    match file.try_lock() {
        Ok(()) => {
            held.insert(key.to_path_buf(), Held { file, holders: 1 });
            Attempt::Held(SessionWriterLock { key: key.to_path_buf() })
        }
        Err(std::fs::TryLockError::WouldBlock) => Attempt::Contended,
        Err(std::fs::TryLockError::Error(error)) => {
            report_unlockable(session_dir, &error);
            Attempt::Unlockable
        }
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

/// Whether another process has the persisted session `session_id` open for writing: a starting window's check before it
/// opens the session, so it can refuse with [`HELD_ELSEWHERE`] instead of starting. Never creates the lock file. The
/// agent's own open stays the authority; this is only the early answer.
pub fn session_open_elsewhere(session_id: &str) -> bool {
    crate::session::persistence::find_persisted_session_dir(session_id).is_some_and(|dir| dir_open_elsewhere(&dir))
}

pub(crate) fn dir_open_elsewhere(session_dir: &Path) -> bool {
    let path = session_dir.join(SESSION_WRITER_LOCK_FILE);
    if !path.is_file() {
        return false;
    }
    let held = held();
    if held.contains_key(&key_for(session_dir)) {
        return false;
    }
    let Ok(file) = std::fs::OpenOptions::new().read(true).write(true).open(&path) else {
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

#[cfg(test)]
#[path = "session_writer_lock_tests.rs"]
mod tests;
