//! [`SessionWriter`]: the one token that may mutate a session folder (design §5.1-§5.3).
//!
//! - **Slot.** One in-process slot per session id, counted by `Arc`: every clone keeps it, and the slot frees when the
//!   last clone drops. The slot keeps a `Weak` only for [`SessionWriter::resident`] (a fork's snapshot of a source open
//!   in this process, design §5.5-§5.6); an upgrade fails once the last clone is gone, so nothing can revive a writer
//!   that is going away. A contender gets [`Busy`], which can wait for the slot to free.
//! - **OS hold.** The 1.0.30 cross-process lock ([`crate::lock`]) lives inside the value. [`SessionWriter::claim`]
//!   attaches it eagerly when the folder exists; otherwise the first mutating call attaches it synchronously on the
//!   thread that does the I/O, creating the folder if it is missing (the only code that creates a session folder).
//!   Contended after the 300 ms retry: the call fails with [`Refusal::HeldElsewhere`] and writes nothing.
//! - **Writes.** Every mutation of a path under the folder is a method here, taking a relative path. The async methods
//!   move a clone of the writer into their blocking closure, and [`SessionAppend`] owns a clone, so no write can land
//!   after the writer is free.
//! - **Lock order.** `SLOTS` and `os_hold` are leaves, never nested and never held across an await. The lock module's
//!   `HELD` map is taken only inside `os_hold` (attach, release), never under `SLOTS`.
#![allow(clippy::disallowed_methods, reason = "the choke point: SessionWriter performs every session-folder mutation (design F5 5.1-5.3)")]

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

use crate::lock::{self, Attempt, SessionWriterLock};
use crate::{owner_only, trace};

/// Why a mutating call wrote nothing although its I/O would have worked. Carried inside the returned `io::Error`; read
/// it back with [`refusal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Another process holds the session (the 1.0.30 lock); [`lock::HELD_ELSEWHERE`] is the message.
    HeldElsewhere,
    /// The session was deleted through this writer ([`SessionWriter::delete_tree`]).
    Gone,
    /// Session persistence is off for this process ([`disable_persistence`], `--no-session-persistence`).
    PersistenceOff,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeldElsewhere => f.write_str(lock::HELD_ELSEWHERE),
            Self::Gone => f.write_str("this session was deleted; nothing was written"),
            Self::PersistenceOff => f.write_str("session persistence is off for this run; nothing was written"),
        }
    }
}

impl std::error::Error for Refusal {}

fn refused(refusal: Refusal) -> io::Error {
    io::Error::other(refusal)
}

/// The [`Refusal`] inside an error a writer method returned, if it was one.
pub fn refusal(error: &io::Error) -> Option<Refusal> {
    error.get_ref()?.downcast_ref::<Refusal>().copied()
}

/// Why [`SessionWriter::claim`] did not get the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimError {
    /// Another writer of this id in this process did not finish before the deadline ("still closing").
    StillClosing,
    /// Another process holds the session.
    HeldElsewhere,
}

/// The slot is taken by a live writer of the id in this process.
#[derive(Debug)]
pub struct Busy {
    rx: watch::Receiver<()>,
}

impl Busy {
    /// Wait until that writer is free, or until `deadline`. `true` when it freed.
    pub async fn freed_by(mut self, deadline: Instant) -> bool {
        // Nothing is ever sent: the only event is the sender dropping with the slot entry.
        tokio::time::timeout_at(deadline, self.rx.changed()).await.is_ok()
    }
}

enum HoldState {
    Unattached,
    Held(#[allow(dead_code, reason = "kept for its Drop: the counted OS hold")] SessionWriterLock),
    Unlockable,
    ReleasedForWipe,
}

struct Entry {
    generation: u64,
    tx: watch::Sender<()>,
    /// The slot's writer, for [`SessionWriter::resident`]; never upgraded once its last clone has dropped.
    writer: Weak<Inner>,
}

static SLOTS: LazyLock<Mutex<HashMap<String, Entry>>> = LazyLock::new(Mutex::default);
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
static TMP_SEQ: AtomicU64 = AtomicU64::new(1);
/// Replace tickets, taken when a replace is called (not when its blocking task runs): their order is the call order.
static REPLACE_SEQ: AtomicU64 = AtomicU64::new(1);

/// F12 (`--no-session-persistence`): from now until the process exits, no session folder is created or written. Every
/// mutating [`SessionWriter`] call fails with [`Refusal::PersistenceOff`] and touches nothing; the shell's writers
/// outside a session folder (prompt history, the search index, the TTL sweep) check [`persistence_disabled`]. One-way:
/// a headless run sets it before its agent starts, and nothing turns it back on.
pub fn disable_persistence() {
    fuigo_config::disable_session_persistence();
}

/// Whether [`disable_persistence`] was called in this process.
pub fn persistence_disabled() -> bool {
    fuigo_config::session_persistence_disabled()
}

fn slots() -> MutexGuard<'static, HashMap<String, Entry>> {
    SLOTS.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(debug_assertions)]
static LIVE: LazyLock<Mutex<HashMap<String, usize>>> = LazyLock::new(Mutex::default);

/// Debug builds: how many writer values (not clones) of `id` are alive. CT-W5 asserts it is 0 after a close.
#[cfg(debug_assertions)]
pub fn debug_live_writers(id: &str) -> usize {
    LIVE.lock().unwrap_or_else(PoisonError::into_inner).get(id).copied().unwrap_or(0)
}

struct Inner {
    id: String,
    generation: u64,
    dir: PathBuf,
    attach_retry: Duration,
    os_hold: Mutex<HoldState>,
    /// The newest replace ticket that landed, per file: held across each replace's rename, so an older replace (one
    /// whose blocking task outlived its dropped future) never lands after a newer one (review r1 H1).
    replaced: Mutex<HashMap<PathBuf, u64>>,
}

impl Inner {
    fn hold(&self) -> MutexGuard<'_, HoldState> {
        self.os_hold.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // The counted OS release first, then the slot: a waiter woken by the slot can attach at once.
        let hold = std::mem::replace(
            self.os_hold.get_mut().unwrap_or_else(PoisonError::into_inner),
            HoldState::Unattached,
        );
        drop(hold);
        #[cfg(any(test, feature = "test-support"))]
        crate::seams::pass(&format!("drop:{}", self.id));
        trace::free(&self.id, self.generation);
        let removed = {
            let mut slots = slots();
            // A stale drop (its entry already replaced by a newer generation) must not free the newer one.
            if slots.get(&self.id).is_some_and(|entry| entry.generation == self.generation) {
                slots.remove(&self.id)
            } else {
                None
            }
        };
        // Dropping the entry's sender wakes every waiter; done outside the `SLOTS` lock.
        drop(removed);
        #[cfg(debug_assertions)]
        {
            let mut live = LIVE.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(count) = live.get_mut(&self.id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    live.remove(&self.id);
                }
            }
        }
    }
}

/// The write token for one session folder. `Clone` is an `Arc` clone; the session is free when the last clone drops.
#[derive(Clone)]
pub struct SessionWriter(Arc<Inner>);

impl std::fmt::Debug for SessionWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionWriter").field("id", &self.0.id).field("generation", &self.0.generation).finish()
    }
}

impl SessionWriter {
    /// Take the slot for `id`, whose folder is `dir`, without waiting. Synchronous; the OS hold attaches at the first
    /// mutating call.
    pub fn try_claim(id: impl Into<String>, dir: impl Into<PathBuf>) -> Result<Self, Busy> {
        Self::try_claim_with(id.into(), dir.into(), lock::CONTENDED_RETRY)
    }

    /// [`try_claim`](Self::try_claim) for an unowned reader's best-effort repair: its first mutating call does not
    /// retry a contended OS lock (a listing never waits 300 ms per folder held by another process; Fable round-2 L6).
    pub fn try_claim_reader(id: impl Into<String>, dir: impl Into<PathBuf>) -> Result<Self, Busy> {
        Self::try_claim_with(id.into(), dir.into(), Duration::ZERO)
    }

    fn try_claim_with(id: String, dir: PathBuf, attach_retry: Duration) -> Result<Self, Busy> {
        let inner = {
            let mut slots = slots();
            if let Some(entry) = slots.get(&id) {
                return Err(Busy { rx: entry.tx.subscribe() });
            }
            let generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
            let (tx, _rx) = watch::channel(());
            let inner = Arc::new(Inner {
                id: id.clone(),
                generation,
                dir,
                attach_retry,
                os_hold: Mutex::new(HoldState::Unattached),
                replaced: Mutex::default(),
            });
            slots.insert(id.clone(), Entry { generation, tx, writer: Arc::downgrade(&inner) });
            inner
        };
        #[cfg(debug_assertions)]
        {
            *LIVE.lock().unwrap_or_else(PoisonError::into_inner).entry(id.clone()).or_default() += 1;
        }
        trace::claim(&id, inner.generation);
        Ok(Self(inner))
    }

    /// The writer that holds `id` in this process right now, if any (a clone: the session is not free until it drops).
    /// For a fork's snapshot of a source session that is open here in another adapter, whose lock sidecars must open
    /// through the source's own writer (design F5 §5.5, §5.6). `None` when no writer holds the id, or its last clone
    /// is already dropping.
    pub fn resident(id: &str) -> Option<Self> {
        slots().get(id).and_then(|entry| entry.writer.upgrade()).map(Self)
    }

    /// Take the slot for `id`, waiting until `deadline` for a previous writer of the id in this process to finish.
    /// When the folder exists, the OS hold is attached here (retrying a contended lock for at most
    /// `min(300 ms, deadline - now)`), so a cold load is refused before it reads anything.
    pub async fn claim(id: impl Into<String>, dir: impl Into<PathBuf>, deadline: Instant) -> Result<Self, ClaimError> {
        let (id, dir) = (id.into(), dir.into());
        loop {
            match Self::try_claim_with(id.clone(), dir.clone(), lock::CONTENDED_RETRY) {
                Ok(writer) => {
                    // On `HeldElsewhere` the writer drops here, which frees the slot.
                    writer.attach_eagerly(deadline).await?;
                    return Ok(writer);
                }
                Err(busy) => {
                    if !busy.freed_by(deadline).await {
                        return Err(ClaimError::StillClosing);
                    }
                }
            }
        }
    }

    async fn attach_eagerly(&self, deadline: Instant) -> Result<(), ClaimError> {
        let dir = &self.0.dir;
        if persistence_disabled() || !dir.is_dir() {
            return Ok(());
        }
        let key = lock::key_for(dir);
        let now = Instant::now();
        let retry_until = now + lock::CONTENDED_RETRY.min(deadline.saturating_duration_since(now));
        loop {
            {
                let mut state = self.0.hold();
                if !matches!(*state, HoldState::Unattached) {
                    return Ok(());
                }
                match lock::try_acquire(dir, &key) {
                    Attempt::Held(held) => {
                        *state = HoldState::Held(held);
                        self.create_lock_sidecars();
                        return Ok(());
                    }
                    Attempt::Unlockable => {
                        *state = HoldState::Unlockable;
                        return Ok(());
                    }
                    Attempt::Contended => {}
                }
            }
            if Instant::now() >= retry_until {
                tracing::info!(dir = %dir.display(), "session is open in another process; not opening it");
                return Err(ClaimError::HeldElsewhere);
            }
            tokio::time::sleep(lock::CONTENDED_POLL).await;
        }
    }

    /// Wait until no writer of `id` exists in this process, or until `deadline`. `true` when free.
    pub async fn wait_free(id: &str, deadline: Instant) -> bool {
        loop {
            let rx = match slots().get(id) {
                None => return true,
                Some(entry) => entry.tx.subscribe(),
            };
            if !(Busy { rx }).freed_by(deadline).await {
                return false;
            }
        }
    }

    /// Whether no writer of `id` exists in this process right now.
    pub fn is_free(id: &str) -> bool {
        !slots().contains_key(id)
    }

    /// The session id.
    pub fn id(&self) -> &str {
        &self.0.id
    }

    /// This writer's generation (unique per claim in this process).
    pub fn generation(&self) -> u64 {
        self.0.generation
    }

    /// The session folder. Computes a session path: outside the crates listed in `session-writer-crates.toml` it is a
    /// banned producer (design §5.4.3).
    pub fn dir(&self) -> &Path {
        &self.0.dir
    }

    // ---- the hold -------------------------------------------------------------------------------------------------

    /// The first step of every mutating call, on the thread that does the I/O (design §5.2). With `create`, a missing
    /// folder is created owner-only first; without it (remove, rename, the summary RMW), a missing folder is `NotFound`
    /// and nothing is created.
    fn ensure_dir_and_hold(&self, create: bool) -> io::Result<()> {
        let mut state = self.0.hold();
        self.attach_locked(&mut state, create)
    }

    /// [`ensure_dir_and_hold`](Self::ensure_dir_and_hold) on an `os_hold` guard the caller already has.
    fn attach_locked(&self, state: &mut HoldState, create: bool) -> io::Result<()> {
        // F12: the one gate every mutating call passes, before any folder, lock file or path is touched.
        if persistence_disabled() {
            return Err(refused(Refusal::PersistenceOff));
        }
        match *state {
            HoldState::Held(_) | HoldState::Unlockable => return Ok(()),
            HoldState::ReleasedForWipe => return Err(refused(Refusal::Gone)),
            HoldState::Unattached => {}
        }
        let dir = &self.0.dir;
        if !dir.is_dir() {
            if !create {
                return Err(io::Error::new(io::ErrorKind::NotFound, "session folder does not exist"));
            }
            trace::op(self.0.generation, &[dir.as_path()], || create_dir_durable(dir))?;
            trace::dir_created(self.0.generation, dir);
        }
        let key = lock::key_for(dir);
        let retry_until = std::time::Instant::now() + self.0.attach_retry;
        loop {
            match lock::try_acquire(dir, &key) {
                Attempt::Held(held) => {
                    *state = HoldState::Held(held);
                    self.create_lock_sidecars();
                    return Ok(());
                }
                Attempt::Unlockable => {
                    *state = HoldState::Unlockable;
                    return Ok(());
                }
                Attempt::Contended if std::time::Instant::now() >= retry_until => {
                    tracing::info!(dir = %dir.display(), "session is open in another process; not writing to it");
                    return Err(refused(Refusal::HeldElsewhere));
                }
                // Legal here: this is a blocking thread (a `spawn_blocking` closure or a `_sync` caller's thread).
                Attempt::Contended => std::thread::sleep(lock::CONTENDED_POLL),
            }
        }
    }

    /// Create the folder's missing [`LOCK_SIDECARS`] the moment this writer's OS hold attaches (review r1 H2). A fork in
    /// another process opens a held session's sidecars read-only and never creates one, so they must exist for as long
    /// as the session is held; created here, a live session always has them. Best effort: a sidecar that cannot be made
    /// leaves the fork's refusal ([`LOCK_SIDECARS`]) to say "try again".
    fn create_lock_sidecars(&self) {
        for name in LOCK_SIDECARS {
            let path = self.0.dir.join(name);
            if std::fs::symlink_metadata(&path).is_ok() {
                continue;
            }
            let created = trace::op(self.0.generation, &[&path], || {
                owner_only::open(OpenOptions::new().read(true).write(true).create(true).truncate(false), &path)
            });
            if let Err(error) = created {
                tracing::debug!(%error, path = %path.display(), "lock sidecar not created");
            }
        }
    }

    /// `dir.join(rel)` for a relative `rel` made only of normal components (no `..`, no root, no prefix, no `.`).
    fn resolve(&self, rel: &Path) -> io::Result<PathBuf> {
        let valid = rel.components().next().is_some() && rel.components().all(|c| matches!(c, Component::Normal(_)));
        if !valid {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("session file path must be relative and stay inside the session folder: {}", rel.display()),
            ));
        }
        Ok(self.0.dir.join(rel))
    }

    /// Create the directories between the folder and `rel`'s file, owner-only, one level at a time below the folder:
    /// never anything above it (a folder removed meanwhile fails `NotFound` instead of being recreated).
    fn ensure_parents(&self, rel: &Path) -> io::Result<()> {
        let Some(parent) = rel.parent() else { return Ok(()) };
        let mut path = self.0.dir.clone();
        for component in parent.components() {
            path.push(component);
            // Traced runs skip existing levels so an append into `terminal/` does not mark a no-op mkdir every time.
            if trace::enabled() && path.is_dir() {
                continue;
            }
            match trace::op(self.0.generation, &[&path], || create_one_dir_owner_only(&path)) {
                Ok(()) => trace::dir_created(self.0.generation, &path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Hold, validate, create parents, then run `op` on the absolute path between trace marks.
    fn mutate<T>(&self, rel: &Path, create: bool, op: impl FnOnce(&Path) -> io::Result<T>) -> io::Result<T> {
        let target = self.resolve(rel)?;
        self.ensure_dir_and_hold(create)?;
        if create {
            self.ensure_parents(rel)?;
        }
        #[cfg(any(test, feature = "test-support"))]
        crate::seams::pass(&format!("op:{}", self.0.id));
        trace::op(self.0.generation, &[&target], || op(&target))
    }

    async fn blocking<T: Send + 'static>(
        &self,
        f: impl FnOnce(&SessionWriter) -> io::Result<T> + Send + 'static,
    ) -> io::Result<T> {
        // The clone moves into the closure: the write keeps the writer until it has landed, even if this future is
        // dropped while it runs.
        let writer = self.clone();
        tokio::task::spawn_blocking(move || f(&writer)).await.map_err(io::Error::other)?
    }

    // ---- the write API (design §5.3) -----------------------------------------------------------------------------

    /// Append `bytes` to `rel`, creating it owner-only.
    pub fn append_sync(&self, rel: impl AsRef<Path>, bytes: &[u8]) -> io::Result<()> {
        self.mutate(rel.as_ref(), true, |path| {
            owner_only::open(OpenOptions::new().create(true).append(true), path)?.write_all(bytes)
        })
    }

    /// [`append_sync`](Self::append_sync) on the blocking pool.
    pub async fn append(&self, rel: impl Into<PathBuf>, bytes: Vec<u8>) -> io::Result<()> {
        let rel = rel.into();
        self.blocking(move |w| w.append_sync(&rel, &bytes)).await
    }

    /// Append one line to `rel` and sync it, first ending a torn last line (a writer that died mid-line) so the new line
    /// is not swallowed into it. `line` should end with `\n`. (`append_event_checked`'s fix, as a writer method.)
    pub fn append_line_checked_sync(&self, rel: impl AsRef<Path>, line: &[u8]) -> io::Result<()> {
        use std::io::{Read as _, Seek as _, SeekFrom};
        self.mutate(rel.as_ref(), true, |path| {
            let mut file = owner_only::open(OpenOptions::new().read(true).create(true).append(true), path)?;
            let len = file.metadata()?.len();
            let mut torn = false;
            if len > 0 {
                file.seek(SeekFrom::Start(len - 1))?;
                let mut last = [0u8; 1];
                file.read_exact(&mut last)?;
                torn = last[0] != b'\n';
            }
            // Append mode: the write lands at the end whatever the read position. One write, so the fix and the line
            // land together.
            let mut out = Vec::with_capacity(line.len() + 1);
            if torn {
                out.push(b'\n');
            }
            out.extend_from_slice(line);
            file.write_all(&out)?;
            file.sync_data()
        })
    }

    /// Replace `rel` atomically and durably: an owner-only temporary sibling, synced, renamed over `rel`, then the
    /// directory synced. A reader sees the old bytes or the new ones, never a mix.
    pub fn replace_atomic_sync(&self, rel: impl AsRef<Path>, bytes: &[u8]) -> io::Result<()> {
        self.replace_atomic_reporting_sync(rel, bytes).map_err(ReplaceError::into_io)
    }

    /// [`replace_atomic_sync`](Self::replace_atomic_sync) that says, when it fails, whether the rename over the target
    /// happened (as the shell's `write_bytes_atomic_reporting`).
    pub fn replace_atomic_reporting_sync(&self, rel: impl AsRef<Path>, bytes: &[u8]) -> Result<(), ReplaceError> {
        self.replace_ticketed(rel.as_ref(), bytes, REPLACE_SEQ.fetch_add(1, Ordering::Relaxed))
    }

    /// One replace with its call-order `ticket`. A replace called later that has already landed on `rel` makes this one
    /// a no-op (`Ok`: its bytes are superseded); otherwise it lands while holding the ticket map, so nothing older can
    /// land after it.
    fn replace_ticketed(&self, rel: &Path, bytes: &[u8], ticket: u64) -> Result<(), ReplaceError> {
        let mut landed = self.0.replaced.lock().unwrap_or_else(PoisonError::into_inner);
        if landed.get(rel).is_some_and(|&newer| newer > ticket) {
            return Ok(());
        }
        let result = self.replace_now(rel, bytes);
        if matches!(result, Ok(()) | Err(ReplaceError::Replaced(_))) {
            landed.insert(rel.to_path_buf(), ticket);
        }
        result
    }

    fn replace_now(&self, rel: &Path, bytes: &[u8]) -> Result<(), ReplaceError> {
        let target = self.resolve(rel).map_err(ReplaceError::NotReplaced)?;
        self.ensure_dir_and_hold(true).map_err(ReplaceError::NotReplaced)?;
        self.ensure_parents(rel).map_err(ReplaceError::NotReplaced)?;
        let tmp = temp_sibling(&target);
        trace::op(self.0.generation, &[&tmp, &target], || {
            let write_synced = || -> io::Result<()> {
                let mut file = owner_only::create(&tmp)?;
                file.write_all(bytes)?;
                durable::sync_file(&file)
            };
            let renamed = write_synced().and_then(|()| {
                #[cfg(any(test, feature = "test-support"))]
                crate::seams::pass(&format!("rename:{}", self.0.id));
                std::fs::rename(&tmp, &target)
            });
            match renamed {
                Ok(()) => durable::sync_parent(&target).map_err(ReplaceError::Replaced),
                Err(error) => {
                    let _ = std::fs::remove_file(&tmp);
                    Err(ReplaceError::NotReplaced(error))
                }
            }
        })
    }

    /// [`replace_atomic_sync`](Self::replace_atomic_sync) on the blocking pool.
    pub async fn replace_atomic(&self, rel: impl Into<PathBuf>, bytes: Vec<u8>) -> io::Result<()> {
        let rel = rel.into();
        let ticket = REPLACE_SEQ.fetch_add(1, Ordering::Relaxed);
        self.blocking(move |w| {
            #[cfg(any(test, feature = "test-support"))]
            crate::seams::pass(&format!("replace:{}", w.0.id));
            w.replace_ticketed(&rel, &bytes, ticket).map_err(ReplaceError::into_io)
        })
        .await
    }

    /// Create `rel` with `bytes`; `AlreadyExists` if it is there.
    pub fn create_new_sync(&self, rel: impl AsRef<Path>, bytes: &[u8]) -> io::Result<()> {
        self.mutate(rel.as_ref(), true, |path| {
            owner_only::open(OpenOptions::new().write(true).create_new(true), path)?.write_all(bytes)
        })
    }

    /// [`create_new_sync`](Self::create_new_sync) on the blocking pool.
    pub async fn create_new(&self, rel: impl Into<PathBuf>, bytes: Vec<u8>) -> io::Result<()> {
        let rel = rel.into();
        self.blocking(move |w| w.create_new_sync(&rel, &bytes)).await
    }

    /// Remove the file `rel`. Never creates the folder.
    pub fn remove_sync(&self, rel: impl AsRef<Path>) -> io::Result<()> {
        self.mutate(rel.as_ref(), false, |path| std::fs::remove_file(path))
    }

    /// Remove the directory `rel` and everything under it (a legacy directory where a file belongs, e.g. the
    /// `resources_state.json` repair 1.0.40 made by path). Never creates the folder: a missing folder is `NotFound`.
    pub fn remove_tree_sync(&self, rel: impl AsRef<Path>) -> io::Result<()> {
        self.mutate(rel.as_ref(), false, |path| std::fs::remove_dir_all(path))
    }

    /// [`remove_tree_sync`](Self::remove_tree_sync) on the blocking pool.
    pub async fn remove_tree(&self, rel: impl Into<PathBuf>) -> io::Result<()> {
        let rel = rel.into();
        self.blocking(move |w| w.remove_tree_sync(&rel)).await
    }

    /// [`remove_sync`](Self::remove_sync) on the blocking pool.
    pub async fn remove(&self, rel: impl Into<PathBuf>) -> io::Result<()> {
        let rel = rel.into();
        self.blocking(move |w| w.remove_sync(&rel)).await
    }

    /// Rename `from` to `to`, both inside the folder. Never creates the folder; creates `to`'s parents.
    pub fn rename_sync(&self, from: impl AsRef<Path>, to: impl AsRef<Path>) -> io::Result<()> {
        let (from, to) = (from.as_ref(), to.as_ref());
        let source = self.resolve(from)?;
        let target = self.resolve(to)?;
        self.ensure_dir_and_hold(false)?;
        self.ensure_parents(to)?;
        trace::op(self.0.generation, &[&source, &target], || std::fs::rename(&source, &target))
    }

    /// [`rename_sync`](Self::rename_sync) on the blocking pool.
    pub async fn rename(&self, from: impl Into<PathBuf>, to: impl Into<PathBuf>) -> io::Result<()> {
        let (from, to) = (from.into(), to.into());
        self.blocking(move |w| w.rename_sync(&from, &to)).await
    }

    /// Copy the file `src` (anywhere; only read) to `rel`, owner-only whatever `src`'s mode. Returns the bytes copied.
    pub fn copy_in_sync(&self, src: &Path, rel: impl AsRef<Path>) -> io::Result<u64> {
        self.mutate(rel.as_ref(), true, |path| owner_only::copy(src, path))
    }

    /// [`copy_in_sync`](Self::copy_in_sync) on the blocking pool.
    pub async fn copy_in(&self, src: impl Into<PathBuf>, rel: impl Into<PathBuf>) -> io::Result<u64> {
        let (src, rel) = (src.into(), rel.into());
        self.blocking(move |w| w.copy_in_sync(&src, &rel)).await
    }

    /// Move the file `src` (outside the folder: a fork's staging directory) to `rel`, replacing what is there. A rename,
    /// atomic on one filesystem, then the directory synced. Across filesystems (`EXDEV`) the bytes are copied to an
    /// owner-only temporary sibling of `rel`, synced and renamed over it (as [`replace_atomic_sync`](Self::replace_atomic_sync)),
    /// and then `src` is removed. `src` itself is never written.
    pub fn move_in_sync(&self, src: &Path, rel: impl AsRef<Path>) -> io::Result<()> {
        let rel = rel.as_ref();
        let target = self.resolve(rel)?;
        self.ensure_dir_and_hold(true)?;
        self.ensure_parents(rel)?;
        match trace::op(self.0.generation, &[&target], || rename_across(src, &target)) {
            Ok(()) => durable::sync_parent(&target),
            Err(error) if error.kind() != io::ErrorKind::CrossesDevices => Err(error),
            Err(_) => {
                let tmp = temp_sibling(&target);
                trace::op(self.0.generation, &[&tmp, &target], || {
                    let copied = (|| -> io::Result<()> {
                        owner_only::copy(src, &tmp)?;
                        durable::sync_file(&OpenOptions::new().write(true).open(&tmp)?)?;
                        std::fs::rename(&tmp, &target)
                    })();
                    if let Err(error) = copied {
                        let _ = std::fs::remove_file(&tmp);
                        return Err(error);
                    }
                    durable::sync_parent(&target)
                })?;
                // The copy has landed; the staged original outside the folder is the caller's to lose.
                let _ = std::fs::remove_file(src);
                Ok(())
            }
        }
    }

    /// [`move_in_sync`](Self::move_in_sync) on the blocking pool.
    pub async fn move_in(&self, src: impl Into<PathBuf>, rel: impl Into<PathBuf>) -> io::Result<()> {
        let (src, rel) = (src.into(), rel.into());
        self.blocking(move |w| w.move_in_sync(&src, &rel)).await
    }

    /// Publish `src_rel` under the new name `dst_rel` (a hard link, both inside the folder) without ever replacing:
    /// `AlreadyExists` when `dst_rel` is there, so of two racing publishers exactly one wins (a rename would replace).
    /// `src_rel`'s data is flushed first, so the published name never names unflushed bytes. Never creates the folder;
    /// the caller syncs the directory entry (the load repair's `.pre-repair` backup).
    pub fn hard_link_in_no_replace_sync(&self, src_rel: impl AsRef<Path>, dst_rel: impl AsRef<Path>) -> io::Result<()> {
        let (src_rel, dst_rel) = (src_rel.as_ref(), dst_rel.as_ref());
        let source = self.resolve(src_rel)?;
        let target = self.resolve(dst_rel)?;
        self.ensure_dir_and_hold(false)?;
        self.ensure_parents(dst_rel)?;
        trace::op(self.0.generation, &[&source, &target], || {
            durable::sync_file(&OpenOptions::new().write(true).open(&source)?)?;
            std::fs::hard_link(&source, &target)
        })
    }

    /// Open `rel` (creating it owner-only, read + append) and run `f` on the open file between the trace marks: for an
    /// append that inspects the tail before it writes and reports where it failed (the shell's commit-aware JSONL
    /// append, F5-C4). The file closes when `f` returns. An open failure is the outer error; `f`'s own result is inner.
    pub fn with_append_file<T>(&self, rel: impl AsRef<Path>, f: impl FnOnce(&mut File) -> T) -> io::Result<T> {
        self.mutate(rel.as_ref(), true, |path| {
            let mut file = owner_only::open(OpenOptions::new().read(true).create(true).append(true), path)?;
            Ok(f(&mut file))
        })
    }

    /// Flush an existing file `rel` to stable storage (a durability barrier, no content change). Never creates the
    /// folder or the file: a missing one is `NotFound`.
    pub fn sync_existing_sync(&self, rel: impl AsRef<Path>) -> io::Result<()> {
        self.mutate(rel.as_ref(), false, |path| durable::sync_file(&OpenOptions::new().write(true).open(path)?))
    }

    /// [`sync_existing_sync`](Self::sync_existing_sync) on the blocking pool.
    pub async fn sync_existing(&self, rel: impl Into<PathBuf>) -> io::Result<()> {
        let rel = rel.into();
        self.blocking(move |w| w.sync_existing_sync(&rel)).await
    }

    /// Create the folder itself (owner-only, durable) and attach the hold, writing nothing else: a session's setup.
    pub fn ensure_folder_sync(&self) -> io::Result<()> {
        self.ensure_dir_and_hold(true)
    }

    /// [`ensure_folder_sync`](Self::ensure_folder_sync), and a folder that already existed (an earlier, failed import)
    /// is made owner-only too.
    pub fn ensure_folder_owner_only_sync(&self) -> io::Result<()> {
        self.ensure_dir_and_hold(true)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = &self.0.dir;
            trace::op(self.0.generation, &[dir], || std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)))?;
        }
        Ok(())
    }

    /// Create the directory `rel` (and the ones between it and the folder) owner-only. Existing ones are kept.
    pub fn create_dir_sync(&self, rel: impl AsRef<Path>) -> io::Result<()> {
        let rel = rel.as_ref();
        self.resolve(rel)?;
        self.ensure_dir_and_hold(true)?;
        self.ensure_parents(&rel.join("x"))
    }

    /// [`create_dir_sync`](Self::create_dir_sync) on the blocking pool.
    pub async fn create_dir(&self, rel: impl Into<PathBuf>) -> io::Result<()> {
        let rel = rel.into();
        self.blocking(move |w| w.create_dir_sync(&rel)).await
    }

    /// `path` relative to this writer's folder, for a caller that names session files by absolute path. A path outside
    /// the folder is `InvalidInput`: such a write is not this writer's (F5-C4).
    pub fn rel_of<'p>(&self, path: &'p Path) -> io::Result<&'p Path> {
        path.strip_prefix(&self.0.dir).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not inside the session folder {}", path.display(), self.0.dir.display()),
            )
        })
    }

    /// Open `rel` for appending as a held handle that owns a clone of this writer (design §5.3, Astra M3): the writer
    /// cannot be free while the handle exists. For `events.jsonl` and the terminal logs.
    pub fn open_append(&self, rel: impl AsRef<Path>) -> io::Result<SessionAppend> {
        let rel = rel.as_ref();
        let file = self.mutate(rel, true, |path| owner_only::open(OpenOptions::new().create(true).append(true), path))?;
        Ok(SessionAppend { writer: self.clone(), file: Arc::new(file), path: self.0.dir.join(rel) })
    }

    /// Open (creating it if missing, never truncating) a lock sidecar such as `turn_owner.lock` or `snapshot.lock`, so
    /// sidecars are made through the writer and carry trace marks (design §5.6, Fable round-2 M4).
    pub fn open_lock(&self, rel: impl AsRef<Path>) -> io::Result<File> {
        self.mutate(rel.as_ref(), true, |path| {
            owner_only::open(OpenOptions::new().read(true).write(true).create(true).truncate(false), path)
        })
    }

    /// Run the summary read-modify-write `rmw(summary.json, summary.json.lock)` as this writer's work (for actor
    /// callers; `fuigo-shell`'s `apply_patch_locked`). Never creates the folder or any directory: a missing folder is
    /// `NotFound`. The marks cover the two named paths; the RMW's temporary sibling gets its own marks once the RMW's
    /// atomic write goes through [`replace_atomic_sync`](Self::replace_atomic_sync) (F5-C).
    pub fn summary<T>(&self, rmw: impl FnOnce(&Path, &Path) -> io::Result<T>) -> io::Result<T> {
        let summary = self.resolve(Path::new(SUMMARY_FILE))?;
        let lock = self.resolve(Path::new(SUMMARY_LOCK_FILE))?;
        self.ensure_dir_and_hold(false)?;
        #[cfg(any(test, feature = "test-support"))]
        crate::seams::pass(&format!("summary:{}", self.0.id));
        trace::op(self.0.generation, &[&lock, &summary], || rmw(&summary, &lock))
    }

    /// Delete the whole session folder (design §6.3 step 3), keeping 1.0.39's local order: rename the folder to
    /// `.fuigo-deleting-<id>-<pid>` beside it while still holding the OS hold; release the hold (state `ReleasedForWipe`,
    /// so any later mutating call on any clone returns [`Refusal::Gone`] and writes nothing); remove the tombstone. If
    /// the rename is refused (Windows: a file inside open without share-delete), release and then remove in place.
    /// A missing folder is success. The slot stays held throughout; it frees when the caller drops the writer.
    pub fn delete_tree_sync(&self) -> io::Result<()> {
        let dir = self.0.dir.clone();
        let mut state = self.0.hold();
        // Normally attached already (delete claims eagerly); a writer that never wrote attaches here, so the folder is
        // never renamed while another process holds it.
        match self.attach_locked(&mut state, false) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound && refusal(&error).is_none() => {
                *state = HoldState::ReleasedForWipe;
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        let tombstone = dir.file_name().and_then(|name| {
            let name = format!("{DELETING_PREFIX}{}-{}", name.to_string_lossy(), std::process::id());
            dir.parent().map(|parent| parent.join(name))
        });
        let renamed = tombstone.as_ref().is_some_and(|tombstone| {
            trace::op(self.0.generation, &[&dir, tombstone], || std::fs::rename(&dir, tombstone)).is_ok()
        });
        if renamed {
            delete_observer::note("local_rename", &dir);
        }
        // Release the hold: Windows then has no handle of ours in the folder being removed.
        drop(std::mem::replace(&mut *state, HoldState::ReleasedForWipe));
        drop(state);
        delete_observer::note("hold_released", &dir);
        let target = if renamed { tombstone.unwrap_or_else(|| dir.clone()) } else { dir.clone() };
        let result = match trace::op(self.0.generation, &[&target], || std::fs::remove_dir_all(&target)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        };
        delete_observer::note("local_wipe", &dir);
        result
    }

    /// [`delete_tree_sync`](Self::delete_tree_sync) on the blocking pool.
    pub async fn delete_tree(&self) -> io::Result<()> {
        self.blocking(|w| w.delete_tree_sync()).await
    }
}

/// `summary.json`, as the shell names it.
const SUMMARY_FILE: &str = "summary.json";
/// The lock sidecars a fork's snapshot takes ([`SessionWriter::open_lock`]; `fuigo-shell`'s `snapshot_lock` and the
/// append locks of `chat_history.jsonl` and `updates.jsonl`). Made when the writer's OS hold attaches, so a session held
/// by another process always has them; a fork that finds one missing there refuses instead of copying unlocked.
pub const LOCK_SIDECARS: [&str; 3] = ["snapshot.lock", "chat_history.jsonl.lock", "updates.jsonl.lock"];
/// The summary RMW's lock sidecar.
const SUMMARY_LOCK_FILE: &str = "summary.json.lock";
/// Prefix of a session folder being deleted (the shell's `DELETING_PREFIX`).
pub const DELETING_PREFIX: &str = ".fuigo-deleting-";

/// A failed [`SessionWriter::replace_atomic_reporting_sync`].
#[derive(Debug)]
pub enum ReplaceError {
    /// The target still holds what it held before (or does not exist, as before).
    NotReplaced(io::Error),
    /// The new bytes were renamed over the target and the directory sync after it failed.
    Replaced(io::Error),
}

impl ReplaceError {
    /// The underlying error.
    pub fn into_io(self) -> io::Error {
        match self {
            Self::NotReplaced(error) | Self::Replaced(error) => error,
        }
    }
}

/// An append handle that owns a clone of its [`SessionWriter`] (design §5.3): the writer is not free while it exists.
/// Fields drop in order: the file closes before the writer clone, so a handle holding the last clone has closed its
/// file before the writer is free (design §6.1; box B4).
#[derive(Debug)]
pub struct SessionAppend {
    file: Arc<File>,
    path: PathBuf,
    writer: SessionWriter,
}

impl SessionAppend {
    /// Append `bytes` (one write, at the end).
    pub fn write_all(&self, bytes: &[u8]) -> io::Result<()> {
        self.writer.ensure_dir_and_hold(false)?;
        trace::op(self.writer.0.generation, &[&self.path], || (&*self.file).write_all(bytes))
    }

    /// [`write_all`](Self::write_all) on the blocking pool; the closure owns a clone of the writer and of the file.
    pub async fn write_all_async(&self, bytes: Vec<u8>) -> io::Result<()> {
        let (file, path) = (self.file.clone(), self.path.clone());
        self.writer
            .blocking(move |w| {
                w.ensure_dir_and_hold(false)?;
                trace::op(w.0.generation, &[&path], || (&*file).write_all(&bytes))
            })
            .await
    }

    /// Cut the file to `len` bytes (a terminal log's size cap). Later appends land at the new end (append mode).
    pub fn set_len(&self, len: u64) -> io::Result<()> {
        self.writer.ensure_dir_and_hold(false)?;
        trace::op(self.writer.0.generation, &[&self.path], || self.file.set_len(len))
    }

    /// [`set_len`](Self::set_len) on the blocking pool.
    pub async fn set_len_async(&self, len: u64) -> io::Result<()> {
        let (file, path) = (self.file.clone(), self.path.clone());
        self.writer
            .blocking(move |w| {
                w.ensure_dir_and_hold(false)?;
                trace::op(w.0.generation, &[&path], || file.set_len(len))
            })
            .await
    }

    /// Flush the appended data to stable storage.
    pub fn sync_data(&self) -> io::Result<()> {
        self.file.sync_data()
    }

    /// The file's path, for display (the text shown to the model for a terminal log).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The writer this handle holds.
    pub fn writer(&self) -> &SessionWriter {
        &self.writer
    }
}

/// `std::fs::rename`, which tests can make fail with `EXDEV` (`CrossesDevices`) on their own thread.
fn rename_across(src: &Path, target: &Path) -> io::Result<()> {
    #[cfg(test)]
    if FORCE_EXDEV.with(std::cell::Cell::get) {
        return Err(io::Error::from(io::ErrorKind::CrossesDevices));
    }
    std::fs::rename(src, target)
}

#[cfg(test)]
thread_local! {
    /// Set by a test to make [`rename_across`] on its thread fail as a rename across filesystems does.
    pub(crate) static FORCE_EXDEV: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn temp_sibling(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{}.{}.tmp", std::process::id(), TMP_SEQ.fetch_add(1, Ordering::Relaxed)));
    PathBuf::from(name)
}

fn create_one_dir_owner_only(path: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(path)
}

/// Create the session folder (and its missing ancestors) owner-only, then sync every directory that gained an entry, so
/// the new chain survives power loss (as the shell's `create_dir_all_durable`).
fn create_dir_durable(dir: &Path) -> io::Result<()> {
    let mut first_existing = dir.parent();
    while let Some(ancestor) = first_existing {
        if ancestor.is_dir() {
            break;
        }
        first_existing = ancestor.parent();
    }
    fuigo_config::create_dir_all_owner_only(dir)?;
    if let Some(top) = first_existing {
        let mut current = dir.to_path_buf();
        while let Some(parent) = current.parent() {
            durable::sync_dir(parent)?;
            if parent == top {
                break;
            }
            current = parent.to_path_buf();
        }
    }
    Ok(())
}

mod durable {
    use std::io;
    use std::path::Path;

    /// One flush to stable media. `File::sync_all` is `F_FULLFSYNC` on Apple targets, `fsync` elsewhere on Unix and
    /// `FlushFileBuffers` on Windows: the single flush the shell's `sync_file_durable` makes.
    pub(super) fn sync_file(file: &std::fs::File) -> io::Result<()> {
        file.sync_all()
    }

    #[cfg(unix)]
    pub(super) fn sync_dir(dir: &Path) -> io::Result<()> {
        std::fs::File::open(dir)?.sync_all()
    }

    /// Windows has no supported directory-handle fsync; NTFS journals directory metadata (as the shell).
    #[cfg(not(unix))]
    pub(super) fn sync_dir(_dir: &Path) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn sync_parent(path: &Path) -> io::Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
        sync_dir(parent)
    }
}

/// The delete order log for CT-DEL-O (design §9.2): `local_rename`, `hold_released`, `local_wipe`. A no-op unless a test
/// installs an observer (`cfg(test)` here, or the `test-support` feature for `fuigo-shell`'s tests).
pub mod delete_observer {
    #[cfg(any(test, feature = "test-support"))]
    type Observer = Box<dyn Fn(&'static str, &std::path::Path) + Send + Sync>;

    #[cfg(any(test, feature = "test-support"))]
    static OBSERVER: std::sync::Mutex<Option<Observer>> = std::sync::Mutex::new(None);

    /// Install (or clear) the observer that receives each delete step, with the session folder (its own path, before the
    /// rename) the step belongs to. The observer is process-wide, so it sees every delete in the process, including the
    /// ones running concurrently on other test threads: an observer must act only on steps whose folder is its own.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set(observer: Option<Observer>) {
        *OBSERVER.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = observer;
    }

    pub(crate) fn note(step: &'static str, dir: &std::path::Path) {
        #[cfg(any(test, feature = "test-support"))]
        if let Some(observer) = OBSERVER.lock().unwrap_or_else(std::sync::PoisonError::into_inner).as_ref() {
            observer(step, dir);
        }
        #[cfg(not(any(test, feature = "test-support")))]
        let _ = (step, dir);
    }
}

/// CT-W2: put a newer generation's entry in place of the current one, as if the id had been freed and claimed again.
#[cfg(test)]
pub(crate) fn test_replace_slot(id: &str, generation: u64, tx: watch::Sender<()>) {
    slots().insert(id.to_owned(), Entry { generation, tx, writer: Weak::new() });
}

#[cfg(test)]
pub(crate) fn test_remove_slot(id: &str) {
    slots().remove(id);
}
