//! The session's snapshot lock (`snapshot.lock` in the session directory), P123 (K17).
//!
//! A session's transcript (`updates.jsonl`) and its model history (`chat_history.jsonl`) are two files written by separate
//! messages of the persistence actor. A fork copies both, and a copy that falls between the two writes of one turn start
//! (the prompt's echo in the transcript, the prompt in the chat history) gives the child a prompt in one file and not the
//! other. The two halves of a turn start are therefore written by the persistence actor while it holds this lock
//! (echo first, then the chat item), and a fork's snapshot holds it while it reads both files: the snapshot sees every turn
//! start in both files or in neither. The lock is advisory and per session directory, so it also holds between processes.
//!
//! Lock order (no cycle): this lock first, then a file's append lock (`<file>.jsonl.lock`). The actor never holds two
//! append locks at once, and a snapshot takes the chat history's before the transcript's.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The lock file's name inside the session directory.
pub(crate) const SNAPSHOT_LOCK_FILE: &str = "snapshot.lock";

/// How long a holder is waited for: a turn start or a snapshot takes milliseconds, so this is for one that is stuck.
pub(crate) const SNAPSHOT_LOCK_WAIT: Duration = Duration::from_secs(10);

/// Test seam: the lock files some caller found held, so a test can wait for a caller to be at the lock instead of sleeping.
#[cfg(test)]
pub(crate) static CONTENDED: std::sync::LazyLock<parking_lot::Mutex<std::collections::HashSet<PathBuf>>> =
    std::sync::LazyLock::new(|| parking_lot::Mutex::new(std::collections::HashSet::new()));

/// How long the persistence actor keeps the snapshot lock for one turn start before it asks whether the turn is still alive
/// (P135). A turn start ends the hold explicitly, by a drop guard on an in-process channel; this is the bound for a turn that
/// is gone without having sent its end (a bug, not an expected case), so a lost end cannot keep every fork refused for good.
/// A turn that is still running keeps its hold however long it takes (Astra P135 r1 H2, r2 H2: a Cursor image transcription
/// takes up to 240 s per image, 16 images), because releasing it would leave the prompt's echoes on disk with no chat item.
pub(crate) const SNAPSHOT_HOLD_MAX: Duration = Duration::from_secs(120);

/// Test seam: milliseconds that replace [`SNAPSHOT_HOLD_MAX`] when non-zero.
#[cfg(test)]
pub(crate) static HOLD_MAX_OVERRIDE_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Test seam: how many times the time limit released a hold (a fork waiting at the lock can win the race for it then).
#[cfg(test)]
pub(crate) static EXPIRY_RELEASES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(crate) fn hold_max() -> Duration {
    #[cfg(test)]
    {
        let ms = HOLD_MAX_OVERRIDE_MS.load(std::sync::atomic::Ordering::Relaxed);
        if ms != 0 {
            return Duration::from_millis(ms);
        }
    }
    SNAPSHOT_HOLD_MAX
}

/// The snapshot lock as the persistence actor holds it for one turn start: the lock file (closing it releases the lock),
/// the turn it belongs to, and when it was taken.
pub(crate) struct SnapshotHold {
    pub(crate) turn_id: u64,
    pub(crate) since: Instant,
    alive: std::sync::Weak<()>,
    _file: std::fs::File,
}

impl SnapshotHold {
    pub(crate) fn new(turn_id: u64, file: std::fs::File, alive: std::sync::Weak<()>) -> Self {
        Self { turn_id, since: Instant::now(), alive, _file: file }
    }
    /// Whether the turn that holds the lock still exists.
    pub(crate) fn turn_alive(&self) -> bool {
        self.alive.strong_count() > 0
    }
    pub(crate) fn expires_at(&self) -> Instant {
        self.since + hold_max()
    }
    pub(crate) fn expired(&self) -> bool {
        Instant::now() >= self.expires_at()
    }
}

pub(crate) fn lock_path(session_dir: &Path) -> PathBuf {
    session_dir.join(SNAPSHOT_LOCK_FILE)
}

/// Open `path` as a lock file (created when missing). `None` when it cannot be opened: the caller goes on without the lock.
fn open(path: &Path) -> Option<std::fs::File> {
    // Owner-only like every session file (P120): a lock file other users can open is a lock they can hold.
    match super::owner_only::open(std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false), path) {
        Ok(file) => Some(file),
        Err(error) => {
            tracing::debug!(%error, path = %path.display(), "no snapshot lock: it cannot be opened");
            None
        }
    }
}

/// Take `path` (a lock file) exclusively, waiting at most [`SNAPSHOT_LOCK_WAIT`] (polling, so the wait blocks the calling
/// thread). `Ok(None)`: the lock file cannot be opened or locked at all. `Err(Interrupted)`: it stayed held (retryable).
pub(crate) fn acquire_blocking(path: &Path, what: &Path) -> io::Result<Option<std::fs::File>> {
    let Some(file) = open(path) else {
        return Ok(None);
    };
    let deadline = Instant::now() + SNAPSHOT_LOCK_WAIT;
    loop {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => return Ok(Some(file)),
            Err(error) if error.kind() == fs2::lock_contended_error().kind() => {
                #[cfg(test)]
                CONTENDED.lock().insert(path.to_path_buf());
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        format!("Cannot copy the session: {} is being written. Nothing was created; try again.", what.display()),
                    ));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => {
                tracing::debug!(%error, path = %path.display(), "no snapshot lock: it cannot be taken");
                return Ok(None);
            }
        }
    }
}

/// [`acquire_blocking`] for an async task (the persistence actor): it yields while it waits, and gives up after
/// [`SNAPSHOT_LOCK_WAIT`] by going on without the lock (a snapshot that holds it for that long is stuck, and the actor must
/// not stop persisting for it).
pub(crate) async fn acquire_async(session_dir: &Path) -> Option<std::fs::File> {
    let path = lock_path(session_dir);
    let file = open(&path)?;
    let deadline = Instant::now() + SNAPSHOT_LOCK_WAIT;
    loop {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => return Some(file),
            Err(error) if error.kind() == fs2::lock_contended_error().kind() => {
                #[cfg(test)]
                CONTENDED.lock().insert(path.clone());
                if Instant::now() >= deadline {
                    tracing::warn!(path = %path.display(), "the session's snapshot lock stayed held; writing without it");
                    return None;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(error) => {
                tracing::debug!(%error, path = %path.display(), "no snapshot lock: it cannot be taken");
                return None;
            }
        }
    }
}
