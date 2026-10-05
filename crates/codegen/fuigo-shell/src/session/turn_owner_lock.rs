//! Cross-process liveness for a session's turns.
//!
//! `is_resident` only knows this process. A session can be live in another process (a second frontend, a
//! restarted shell racing the old one), and a load there must not declare that process's running turn lost.
//! Every session actor holds a *shared* advisory lock on `<session_dir>/turn_owner.lock` for its lifetime;
//! interrupted-turn recovery takes the *exclusive* lock without waiting. Exclusive succeeds only when no live
//! actor anywhere holds the session, and a process that dies (crash, kill, restart) releases its lock with it.
//! The exclusive holder is also the only recoverer, so two concurrent loads cannot both record the same turn.
//!
//! The lock file is empty and never read or written, so Windows' mandatory `LockFileEx` semantics cost nothing.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Lock file inside the session directory.
pub(crate) const TURN_OWNER_LOCK_FILE: &str = "turn_owner.lock";

/// Poll interval while a recovery holds the exclusive lock. The wait is awaited by the load itself, on the agent's
/// single-threaded `LocalSet` (see `spawn_session_on_thread`), so it is an async sleep: every other session's load
/// and the ACP connection keep running. (Before P09-F the wait ran inside `spawn_session_actor`, on the session's own
/// `current_thread` runtime; v2's blocking sleep stalled that session's thread, not the whole agent.)
const OWNER_POLL: Duration = Duration::from_millis(20);
/// After this long an actor still waiting logs once; it keeps waiting until [`OWNER_WAIT_LIMIT`].
const OWNER_WAIT_WARN_AFTER: Duration = Duration::from_secs(5);
/// How long a load waits for another process's recovery before failing with [`OwnerLockBusy`]. A live recoverer holds
/// the exclusive lock for at most [`RECOVERY_APPEND_TIMEOUT`] plus local I/O, so reaching this means the holder is
/// alive but not progressing (stopped in a debugger, wedged on I/O). Failing the load is the only safe exit: running
/// unlocked would let a later recovery declare this actor's live turn lost, and no actor means no `turn_started`.
pub(crate) const OWNER_WAIT_LIMIT: Duration = Duration::from_secs(60);

/// Upper bound on how long recovery may hold the exclusive lock across its one await (the durable marker append);
/// see `interrupted_turn::recover_interrupted_turn`. Everything else recovery does under the lock is bounded
/// local file I/O. This bound is what makes an actor's deadline-free wait safe.
pub(crate) const RECOVERY_APPEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Owner-only like every other session file (P145: it kept the folder's inherited ACL on Windows).
fn open_lock_file(session_dir: &Path) -> std::io::Result<std::fs::File> {
    crate::session::storage::owner_only::open(
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false),
        &session_dir.join(TURN_OWNER_LOCK_FILE),
    )
}

static UNKNOWN_WARNED: AtomicBool = AtomicBool::new(false);

/// A lock error that is not contention (e.g. NFS/SMB/FUSE without `flock`) disables the liveness signal for that
/// session. Warn the first time in this process so the degradation is visible; later ones log at debug.
pub(crate) fn report_lock_unavailable(
    session_dir: &Path,
    error: &std::io::Error,
    consequence: &str,
) {
    if UNKNOWN_WARNED.swap(true, Ordering::Relaxed) {
        tracing::debug!(dir = %session_dir.display(), %error, consequence, "turn owner lock unavailable");
    } else {
        tracing::warn!(
            dir = %session_dir.display(),
            %error,
            consequence,
            "turn owner lock unavailable (filesystem without advisory locks?); further occurrences log at debug"
        );
    }
}

/// Releases the advisory lock now, not when the last copy of the descriptor closes.
///
/// A `flock` belongs to the open file description, not to the descriptor. A child that another thread forks
/// (`Command::spawn`) inherits a copy of every open descriptor and keeps the lock alive until it execs (descriptors
/// are close-on-exec), so merely closing ours can leave the session looking live to everyone else for a moment. An
/// explicit unlock releases the description's lock whoever still holds a copy of it. Errors cannot be reported from
/// a destructor, and closing the descriptor (which follows) releases the lock anyway.
fn unlock_on_drop(file: &std::fs::File) {
    let _ = fs2::FileExt::unlock(file);
}

/// Held by a live session actor (or by a recovery whose marker is still being written); dropping it (or the process
/// dying) releases the session.
#[derive(Debug)]
pub(crate) struct TurnOwnerLock {
    /// `None` only inside `drop`. Dropping unlocks explicitly, see [`unlock_on_drop`].
    file: Option<std::fs::File>,
}

/// Another process held the session's exclusive recovery lock for [`OWNER_WAIT_LIMIT`].
#[derive(Debug)]
pub(crate) struct OwnerLockBusy {
    pub(crate) waited: Duration,
}

impl Drop for TurnOwnerLock {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            unlock_on_drop(&file);
        }
    }
}

#[cfg(test)]
impl TurnOwnerLock {
    /// The held descriptor, so a test can make an inherited copy of it (what a forked child holds before it execs).
    fn file(&self) -> &std::fs::File {
        self.file.as_ref().expect("a live lock holds its file")
    }
}

impl OwnerLockBusy {
    /// What `session/load` answers: the session is not broken, it is being recovered elsewhere, so retry.
    pub(crate) fn into_acp_error(self) -> agent_client_protocol::Error {
        crate::acp_error::session_unavailable(format!(
            "This session is being recovered by another Fuigo process (waited {}s for it). Retry loading the session \
             in a moment; if this persists, that process may be stuck and restarting it releases the session.",
            self.waited.as_secs()
        ))
    }
}

impl TurnOwnerLock {
    /// Shared lock for the actor's lifetime, taken before the actor exists, so it can never write a `turn_started`
    /// unlocked. While a recovery holds the exclusive lock this waits: recovery's hold is bounded by
    /// [`RECOVERY_APPEND_TIMEOUT`] plus local I/O. After [`OWNER_WAIT_LIMIT`] the holder is presumed hung and this
    /// returns [`OwnerLockBusy`] so the load fails with a retry message instead of waiting forever; the actor is then
    /// never constructed, so no `turn_started` is written unlocked. `Ok(None)` only when the lock cannot be taken at
    /// all (a missing session dir, or a filesystem without advisory locks, warned once per process).
    pub(crate) async fn acquire(session_dir: &Path) -> Result<Option<Self>, OwnerLockBusy> {
        let file = match open_lock_file(session_dir) {
            Ok(file) => file,
            // A missing session dir also means no events.jsonl, so there is no turn to protect.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(
                    dir = %session_dir.display(),
                    %error,
                    "turn owner lock file unavailable; this actor carries no cross-process liveness signal"
                );
                return Ok(None);
            }
            Err(error) => {
                report_lock_unavailable(
                    session_dir,
                    &error,
                    "this actor carries no cross-process liveness signal",
                );
                return Ok(None);
            }
        };
        let started = tokio::time::Instant::now();
        let mut warned = false;
        loop {
            // UFCS: std's inherent `File::try_lock_shared` (Rust 1.89+) returns a different error type.
            match fs2::FileExt::try_lock_shared(&file) {
                Ok(()) => return Ok(Some(Self { file: Some(file) })),
                Err(error) if fuigo_workspace::util::is_lock_contended(&error) => {
                    let waited = started.elapsed();
                    if waited >= OWNER_WAIT_LIMIT {
                        tracing::warn!(
                            dir = %session_dir.display(),
                            waited_secs = waited.as_secs(),
                            "another process has held this session's recovery lock past the limit; failing the load"
                        );
                        return Err(OwnerLockBusy { waited });
                    }
                    if !warned && waited >= OWNER_WAIT_WARN_AFTER {
                        warned = true;
                        tracing::warn!(
                            dir = %session_dir.display(),
                            "session actor still waiting for another process's interrupted-turn recovery"
                        );
                    }
                    tokio::time::sleep(OWNER_POLL).await;
                }
                Err(error) => {
                    report_lock_unavailable(
                        session_dir,
                        &error,
                        "this actor carries no cross-process liveness signal",
                    );
                    return Ok(None);
                }
            }
        }
    }
}

/// Outcome of asking whether any live actor holds the session.
#[derive(Debug)]
pub(crate) enum RecoveryLock {
    /// No live actor holds the session; recovery may proceed while this guard is held.
    Acquired(RecoveryGuard),
    /// A live actor (in this or another process) holds the session: its open turn is running, not lost.
    HeldElsewhere,
    /// Liveness could not be established; the caller must not declare a turn lost.
    Unknown(std::io::Error),
}

/// Exclusive hold on the session for the duration of one recovery.
#[derive(Debug)]
pub(crate) struct RecoveryGuard {
    /// `None` once [`RecoveryGuard::into_shared`] has handed the descriptor over; otherwise unlocked on drop.
    file: Option<std::fs::File>,
}

impl Drop for RecoveryGuard {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            unlock_on_drop(&file);
        }
    }
}

#[cfg(test)]
impl RecoveryGuard {
    /// See [`TurnOwnerLock::file`].
    fn file(&self) -> &std::fs::File {
        self.file.as_ref().expect("a live guard holds its file")
    }
}

impl RecoveryGuard {
    /// Trades the exclusive hold for a shared one, for a recovery whose marker append outlived its bound: an actor
    /// (here or elsewhere) can take its shared lock, while no other recovery can start and append a second marker.
    ///
    /// On Unix this is an in-place `flock` conversion on the same open file description. On Linux the conversion
    /// is atomic in kernels >= 4.1 (fs/locks.c), although the man page documents it as non-atomic; macOS
    /// conversion is non-atomic. Windows cannot convert, so there the exclusive lock is released first. Where a
    /// conversion is not atomic, the gap is the only window in which another process's non-blocking recovery could
    /// slip in. When the shared lock cannot be taken at all (logged, `None`), the descriptor is unlocked explicitly:
    /// a failed conversion does not promise to have released the exclusive hold (Linux can fail with `ENOMEM` before it
    /// touches the existing lock), and a forked child's copy of the descriptor would keep it.
    pub(crate) fn into_shared(self) -> Option<TurnOwnerLock> {
        self.into_shared_with(fs2::FileExt::try_lock_shared)
    }

    /// [`Self::into_shared`] with the conversion injected (tests make it fail).
    fn into_shared_with(
        mut self,
        lock_shared: impl FnOnce(&std::fs::File) -> std::io::Result<()>,
    ) -> Option<TurnOwnerLock> {
        // Taken out so that dropping `self` below does not unlock: the hold is handed over, not released.
        let file = self.file.take().expect("a live guard holds its file");
        #[cfg(windows)]
        let _ = fs2::FileExt::unlock(&file);
        match lock_shared(&file) {
            Ok(()) => Some(TurnOwnerLock { file: Some(file) }),
            Err(error) => {
                unlock_on_drop(&file);
                tracing::warn!(
                    %error,
                    "could not keep a shared turn-owner lock for a still-pending recovery; another load may record the turn again"
                );
                None
            }
        }
    }
}

/// Non-blocking exclusive lock: `Acquired` only when no actor anywhere holds the session.
pub(crate) fn try_recovery_lock(session_dir: &Path) -> RecoveryLock {
    let file = match open_lock_file(session_dir) {
        Ok(file) => file,
        Err(error) => return RecoveryLock::Unknown(error),
    };
    match fs2::FileExt::try_lock_exclusive(&file) {
        Ok(()) => RecoveryLock::Acquired(RecoveryGuard { file: Some(file) }),
        Err(error) if fuigo_workspace::util::is_lock_contended(&error) => {
            RecoveryLock::HeldElsewhere
        }
        Err(error) => RecoveryLock::Unknown(error),
    }
}

#[cfg(test)]
#[path = "turn_owner_lock_tests.rs"]
mod tests;
