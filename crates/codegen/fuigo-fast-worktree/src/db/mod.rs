//! SQLite-backed metadata database for tracking worktrees.
//!
//! Gated behind the `metadata` cargo feature. When disabled, all DB operations
//! compile away to no-ops.

mod queries;
mod schema;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use fuigo_sqlite_journal::{BUSY_RETRY_BUDGET, JournalMode};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorktreeKind {
    Session,
    Ab,
    Pool,
    Fork,
    Manual,
    Subagent,
}

impl WorktreeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Ab => "ab",
            Self::Pool => "pool",
            Self::Fork => "fork",
            Self::Manual => "manual",
            Self::Subagent => "subagent",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        Self::from_str_exact(s).unwrap_or(Self::Manual)
    }

    /// Exact known kind key. Unknown → None (unlike [`Self::from_str_lossy`]).
    pub fn from_str_exact(s: &str) -> Option<Self> {
        match s {
            "session" => Some(Self::Session),
            "ab" => Some(Self::Ab),
            "pool" => Some(Self::Pool),
            "fork" => Some(Self::Fork),
            "manual" => Some(Self::Manual),
            "subagent" => Some(Self::Subagent),
            _ => None,
        }
    }

    /// Config key parse: trim + case-insensitive; unknown → None.
    pub fn from_str_opt(s: &str) -> Option<Self> {
        let t = s.trim();
        if let Some(k) = Self::from_str_exact(t) {
            return Some(k);
        }
        // Only allocate lowercase when needed.
        if t.bytes().any(|b| b.is_ascii_uppercase()) {
            Self::from_str_exact(&t.to_ascii_lowercase())
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorktreeStatus {
    Alive,
    Dead,
}

impl WorktreeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Alive => "alive",
            Self::Dead => "dead",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "alive" => Self::Alive,
            "dead" => Self::Dead,
            _ => Self::Dead,
        }
    }
}

pub const META_KEY_LABEL: &str = "label";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorktreeRecord {
    pub id: String,
    pub path: PathBuf,
    pub source_repo: PathBuf,
    pub repo_name: String,
    pub kind: WorktreeKind,
    pub creation_mode: String,
    pub git_ref: Option<String>,
    pub head_commit: Option<String>,
    pub session_id: Option<String>,
    pub creator_pid: Option<u32>,
    pub created_at: i64,
    pub last_accessed_at: Option<i64>,
    pub status: WorktreeStatus,
    pub metadata: Option<serde_json::Value>,
}

impl WorktreeRecord {
    /// The user-facing label from `metadata.label`; empty labels are `None`.
    pub fn label(&self) -> Option<&str> {
        self.metadata
            .as_ref()
            .and_then(|m| m.get(META_KEY_LABEL))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    }
}

#[derive(Default)]
pub struct ListFilter {
    pub repo_name: Option<String>,
    pub source_repo: Option<PathBuf>,
    pub kind: Option<WorktreeKind>,
    pub status: Option<WorktreeStatus>,
    pub include_dead: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DbStats {
    pub total_records: u64,
    pub alive_count: u64,
    pub dead_count: u64,
    pub db_file_bytes: u64,
}

pub struct WorktreeDb {
    conn: Connection,
}

/// Outcome of a read-only open. A corrupt file still reaches `Opened`, since
/// SQLite reads lazily and fails at the first query.
pub enum RegistryOpen {
    Opened { path: PathBuf, db: WorktreeDb },
    Absent { path: PathBuf },
    Busy { path: PathBuf, error: anyhow::Error },
    Failed { path: PathBuf, error: anyhow::Error },
}

#[derive(Debug)]
enum OpenFailure {
    Busy(anyhow::Error),
    Other(anyhow::Error),
}

const WORKTREES_DB_FILE: &str = "worktrees.db";

fn is_sqlite_busy(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(f, _) if is_busy_code(f.code))
}

fn is_busy_code(code: rusqlite::ErrorCode) -> bool {
    use rusqlite::ErrorCode;
    matches!(code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqliteFailureKind {
    Busy,
    Corrupt,
    Other,
}

/// What a SQLite failure says about the file. Only the damage codes justify
/// telling a user to delete their registry.
pub fn classify_sqlite_error(error: &anyhow::Error) -> SqliteFailureKind {
    use rusqlite::ErrorCode;
    let Some(rusqlite::Error::SqliteFailure(f, _)) = error.downcast_ref::<rusqlite::Error>() else {
        return SqliteFailureKind::Other;
    };
    if is_busy_code(f.code) {
        return SqliteFailureKind::Busy;
    }
    match f.code {
        ErrorCode::NotADatabase | ErrorCode::DatabaseCorrupt => SqliteFailureKind::Corrupt,
        _ => SqliteFailureKind::Other,
    }
}

impl WorktreeDb {
    /// Open (or create) the DB at `fuigo_home/worktrees.db`.
    pub fn open(fuigo_home: &Path) -> Result<Self> {
        Self::open_at(&fuigo_home.join(WORKTREES_DB_FILE))
    }

    /// Open with an explicit path.
    pub fn open_at(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create dir for DB: {}", parent.display()))?;
        }
        // The mode decision statfs's the parent dir created above.
        Self::open_at_with_journal_mode(path, JournalMode::for_db_path(path))
    }

    /// Open with an explicit journal mode — the seam tests use to exercise
    /// the network-filesystem decision on a local disk.
    fn open_at_with_journal_mode(path: &Path, journal_mode: JournalMode) -> Result<Self> {
        // Per-host sibling on network mounts (see JournalMode::effective_db_path).
        let path = journal_mode.effective_db_path(path);
        let conn = Connection::open(&path)
            .with_context(|| format!("failed to open worktree DB: {}", path.display()))?;
        let db = Self { conn };
        db.set_journal_mode(journal_mode)?;
        db.init_schema()?;
        Ok(db)
    }

    fn set_journal_mode(&self, mode: JournalMode) -> Result<()> {
        mode.apply_with_retry(&self.conn)
            .with_context(|| format!("failed to set journal mode {}", mode.as_str()))
    }

    /// Open the default DB at `~/.fuigo/worktrees.db`.
    ///
    /// Discovers fuigo home via `fuigo_dirs::resolve_fuigo_home` (`$FUIGO_HOME`,
    /// else the canonicalized `<home>/.fuigo`).
    /// Path is resolved fresh each call (env read plus a canonicalize) to
    /// support test overrides. Each call opens its own connection — callers in
    /// hot paths should cache the `WorktreeDb` instance.
    pub fn open_default() -> Result<Self> {
        Self::open(&resolve_fuigo_home()?)
    }

    fn journal_mode_and_base_path(fuigo_home: &Path) -> (JournalMode, PathBuf) {
        let base_path = fuigo_home.join(WORKTREES_DB_FILE);
        let mode = JournalMode::for_db_path(&base_path);
        (mode, base_path)
    }

    /// The path a read-write open would use (per-host on network mounts).
    /// Runs statfs and a hostname lookup, so resolve once and carry it.
    pub fn resolve_db_path(fuigo_home: &Path) -> PathBuf {
        let (mode, base_path) = Self::journal_mode_and_base_path(fuigo_home);
        mode.effective_db_path(&base_path)
    }

    /// Read-only open: creates no directory, database file, or schema. Not
    /// side-effect free, though: reading a WAL database leaves `-shm` and
    /// `-wal` sidecars, and a network-mount open still converts the journal.
    pub fn open_read_only(fuigo_home: &Path) -> RegistryOpen {
        let (mode, base_path) = Self::journal_mode_and_base_path(fuigo_home);
        let path = mode.effective_db_path(&base_path);
        match Self::open_read_only_at(mode, &path) {
            Ok(Some(db)) => RegistryOpen::Opened { path, db },
            Ok(None) => RegistryOpen::Absent { path },
            Err(OpenFailure::Busy(error)) => RegistryOpen::Busy { path, error },
            Err(OpenFailure::Other(error)) => RegistryOpen::Failed { path, error },
        }
    }

    fn open_read_only_at(mode: JournalMode, effective: &Path) -> Result<Option<Self>, OpenFailure> {
        let present = effective.try_exists().map_err(|e| {
            OpenFailure::Other(
                anyhow::Error::new(e)
                    .context(format!("cannot stat worktree DB: {}", effective.display())),
            )
        })?;
        if !present {
            return Ok(None);
        }
        let deadline = std::time::Instant::now() + BUSY_RETRY_BUDGET;
        let conn = Self::open_readonly_with_busy_retry(mode, effective, deadline)?;
        Ok(Some(Self { conn }))
    }

    /// Retry busy failures until `deadline`, which also bounds the network
    /// arm's journal conversion, so the wait cannot come to twice what the
    /// caller allowed.
    fn open_readonly_with_busy_retry(
        mode: JournalMode,
        path: &Path,
        deadline: std::time::Instant,
    ) -> Result<Connection, OpenFailure> {
        use std::time::{Duration, Instant};
        let start = Instant::now();
        let context = || format!("failed to open worktree DB read-only: {}", path.display());
        loop {
            match mode.open_readonly_until(path, deadline) {
                Ok(conn) => return Ok(conn),
                Err(e) if !is_sqlite_busy(&e) => {
                    return Err(OpenFailure::Other(anyhow::Error::new(e).context(context())));
                }
                Err(e) => {
                    if Instant::now() >= deadline {
                        let elapsed = start.elapsed();
                        return Err(OpenFailure::Busy(anyhow::Error::new(e).context(format!(
                            "{} (database busy after {elapsed:?})",
                            context()
                        ))));
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }

    /// Open an in-memory DB (for tests).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("failed to open in-memory DB")?;
        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn
            .execute_batch(schema::INIT_SQL)
            .context("failed to init worktree DB schema")?;

        let stored: Option<String> = self
            .conn
            .query_row(schema::GET_META, ["schema_version"], |row| row.get(0))
            .ok();

        let needs_update = match stored {
            None => true,
            Some(v) => v.parse::<u32>().unwrap_or(0) < schema::SCHEMA_VERSION,
        };
        if needs_update {
            self.conn.execute(
                schema::UPSERT_META,
                rusqlite::params!["schema_version", schema::SCHEMA_VERSION.to_string()],
            )?;
        }

        Ok(())
    }

    pub fn register(&self, record: &WorktreeRecord) -> Result<()> {
        queries::register(&self.conn, record)
    }

    pub fn unregister(&self, id: &str) -> Result<bool> {
        queries::unregister(&self.conn, id)
    }

    pub fn unregister_by_path(&self, path: &Path) -> Result<bool> {
        queries::unregister_by_path(&self.conn, path)
    }

    pub fn mark_dead(&self, id: &str) -> Result<bool> {
        queries::mark_dead(&self.conn, id)
    }

    pub fn touch(&self, id: &str) -> Result<bool> {
        queries::touch(&self.conn, id)
    }

    /// Look up a worktree by its DB ID only (no label or path fallback).
    pub fn get_by_id(&self, id: &str) -> Result<Option<WorktreeRecord>> {
        queries::get_by_id(&self.conn, id)
    }

    /// Look up by ID, label, or path.
    ///
    /// If `id_or_path` contains `/`, it's treated as a path (canonicalized
    /// before lookup). Otherwise it's looked up first as a DB ID, then as a
    /// worktree label (stored in `metadata.label`).
    pub fn get(&self, id_or_path: &str) -> Result<Option<WorktreeRecord>> {
        if id_or_path.contains('/') {
            let canon = PathBuf::from(id_or_path);
            let canon = dunce::canonicalize(&canon).unwrap_or(canon);
            queries::get_by_path(&self.conn, &canon)
        } else {
            let by_id = queries::get_by_id(&self.conn, id_or_path)?;
            if by_id.is_some() {
                return Ok(by_id);
            }
            queries::get_by_label(&self.conn, id_or_path)
        }
    }

    /// Look up a worktree by its label (stored in metadata JSON).
    pub fn get_by_label(&self, label: &str) -> Result<Option<WorktreeRecord>> {
        queries::get_by_label(&self.conn, label)
    }

    pub fn list(&self, filter: &ListFilter) -> Result<Vec<WorktreeRecord>> {
        queries::list(&self.conn, filter)
    }

    pub fn stats(&self) -> Result<DbStats> {
        queries::stats(&self.conn)
    }

    /// Mark all records whose paths no longer exist on disk as dead.
    /// Returns the number of records marked.
    pub fn sweep_dead(&self) -> Result<u64> {
        queries::sweep_dead(&self.conn)
    }

    /// Read a value from the `meta` table. `Ok(None)` when the key is absent.
    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        match self
            .conn
            .query_row(schema::GET_META, [key], |row| row.get(0))
        {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e).with_context(|| format!("failed to read meta key {key}")),
        }
    }

    /// Insert or replace a `meta` table value.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn
            .execute(schema::UPSERT_META, rusqlite::params![key, value])
            .with_context(|| format!("failed to write meta key {key}"))?;
        Ok(())
    }

    /// Test-only: run raw SQL (e.g. drop tables to force fail-closed paths).
    #[cfg(test)]
    pub(crate) fn execute_batch_for_test(&self, sql: &str) -> Result<()> {
        self.conn
            .execute_batch(sql)
            .context("execute_batch_for_test failed")?;
        Ok(())
    }
}

/// Derive a worktree ID from its destination path: `<basename>-<hash of full path>`
/// (the last component, minus any `worktree-` prefix, plus a full-path hash).
///
/// The basename alone collides across repos, and `INSERT OR REPLACE` would then evict
/// the other repo's record; hashing the full path keeps distinct worktrees distinct.
pub fn id_from_path(path: &Path) -> String {
    crate::worktree::plan::worktree_id_from_path(path)
}

/// Extract the repo name (last component) from a source repo path.
pub(crate) fn repo_name_from_path(source: &Path) -> String {
    source
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "repo".to_string())
}

pub fn now_epoch_secs() -> i64 {
    crate::time::epoch_secs()
}

/// Resolve the fuigo home: `$FUIGO_HOME`, else `<home>/.fuigo`.
pub fn resolve_fuigo_home() -> Result<PathBuf> {
    fuigo_dirs::resolve_fuigo_home()
        .context("neither $FUIGO_HOME nor a home directory could be resolved")
}

/// Serializes tests that mutate the process-global `FUIGO_HOME` env var so they
/// don't clobber each other under `cargo test`, where tests share one process
/// (nextest isolates per-process, but the suite must also pass under `cargo test`).
///
/// This lock covers `FUIGO_HOME` only. The grove env (`GROVE_DATA_DIR`, and the
/// `XDG_DATA_HOME` / `HOME` that `candidate_data_dirs` reads next to it) is
/// guarded by `crate::nfs::GROVE_ENV_LOCK`, which [`FuigoHomeFixture`] takes as
/// well — one lock per process-global, or two tests holding two different locks
/// still interleave their writes. Lock order: this one first, then
/// `GROVE_ENV_LOCK`; `nfs::GroveEnvGuard` takes only the second.
#[cfg(test)]
static FUIGO_HOME_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Test-only isolation for code that resolves the DB via `open_default()`.
///
/// Holds [`FUIGO_HOME_ENV_LOCK`] and `nfs::GROVE_ENV_LOCK`, points `FUIGO_HOME`
/// at a fresh private tmp dir, and confines everything `candidate_data_dirs()`
/// reads — `GROVE_DATA_DIR`, `XDG_DATA_HOME`, `HOME` — to that same tmp dir, so
/// a GC or rebuild pass under the fixture can neither scan the developer's real
/// `~/.local/share/grove` nor pick up the `GROVE_DATA_DIR` another test set
/// (`auto_gc::prune_removes_stale_registration_alive_and_dead_source` counted a
/// concurrent `nfs::remove` test's markers as its own dead records before this
/// was unconditional). All four are restored on drop, while both locks are
/// still held, so no waiting setter ever sees a half-restored environment.
///
/// Use instead of hand-rolling the lock + restore guard + tmp dir per test.
#[cfg(test)]
pub(crate) struct FuigoHomeFixture {
    _lock: std::sync::MutexGuard<'static, ()>,
    /// The same lock every other test writer of `GROVE_DATA_DIR` takes
    /// (`nfs::GroveEnvGuard`), held for the fixture's whole lifetime.
    _grove_lock: std::sync::MutexGuard<'static, ()>,
    prev: Option<std::ffi::OsString>,
    prev_xdg_data_home: Option<std::ffi::OsString>,
    prev_grove_data_dir: Option<std::ffi::OsString>,
    prev_home: Option<std::ffi::OsString>,
    prev_control_sock: Option<std::ffi::OsString>,
    /// The isolated fuigo home; pass to `WorktreeDb::open` to read the same DB
    /// `open_default()` writes to.
    pub home: PathBuf,
    _tmp: tempfile::TempDir,
}

#[cfg(test)]
impl FuigoHomeFixture {
    pub(crate) fn new() -> Self {
        let lock = FUIGO_HOME_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let grove_lock = crate::nfs::GROVE_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path().join("fuigo-home");
        std::fs::create_dir_all(&home).unwrap();
        // Warm up the DB (journal-mode conversion + schema) before exposing it
        // via FUIGO_HOME, sparing the test hot loop set_journal_mode's retry
        // sleeps. This open has exclusive access (nothing reaches the path
        // until FUIGO_HOME points here); set_journal_mode's retry is the actual
        // race fix.
        let _ = WorktreeDb::open(&home);
        // A private, empty grove data dir: `candidate_data_dirs()` puts the env
        // override first, so nothing under the fixture ever scans the host's.
        let grove_data = tmp.path().join("grove-data");
        std::fs::create_dir_all(&grove_data).unwrap();
        let xdg = tmp.path().join("xdg-data");
        std::fs::create_dir_all(&xdg).unwrap();
        let prev = std::env::var_os("FUIGO_HOME");
        let prev_xdg_data_home = std::env::var_os("XDG_DATA_HOME");
        let prev_grove_data_dir = std::env::var_os("GROVE_DATA_DIR");
        let prev_home = std::env::var_os("HOME");
        let prev_control_sock = std::env::var_os("GROVE_CONTROL_SOCK");
        // SAFETY: the fixture holds both env locks for its whole lifetime, and
        // every test writer of these variables takes one of them.
        unsafe {
            std::env::set_var("FUIGO_HOME", &home);
            std::env::set_var("XDG_DATA_HOME", &xdg);
            std::env::set_var("GROVE_DATA_DIR", &grove_data);
            std::env::set_var("HOME", tmp.path());
        }
        Self {
            _lock: lock,
            _grove_lock: grove_lock,
            prev,
            prev_xdg_data_home,
            prev_grove_data_dir,
            prev_home,
            prev_control_sock,
            home,
            _tmp: tmp,
        }
    }

    /// Point `GROVE_DATA_DIR` at `data` and `GROVE_CONTROL_SOCK` at `sock` for
    /// the rest of the fixture's lifetime — the daemon-down `rm` shape, with the
    /// registry isolated too. Restored on drop with the rest.
    pub(crate) fn set_grove_env(&mut self, data: &Path, sock: &Path) {
        // SAFETY: both env locks are held by this fixture.
        unsafe {
            std::env::set_var("GROVE_DATA_DIR", data);
            std::env::set_var("GROVE_CONTROL_SOCK", sock);
        }
    }

    /// Point grove lookup at the production shape, `$XDG_DATA_HOME/grove`, with
    /// `GROVE_DATA_DIR` unset (`XDG_DATA_HOME` and `HOME` are already confined
    /// to this fixture by `new`). Returns that grove dir, created.
    pub(crate) fn isolate_xdg_grove_data(&mut self) -> PathBuf {
        let grove = self._tmp.path().join("xdg-data").join("grove");
        std::fs::create_dir_all(&grove).unwrap();
        // SAFETY: both env locks are held by this fixture.
        unsafe { std::env::remove_var("GROVE_DATA_DIR") };
        grove
    }
}

#[cfg(test)]
impl Drop for FuigoHomeFixture {
    fn drop(&mut self) {
        // SAFETY: the fixture still holds both env locks here (fields drop after
        // this body), so no other test thread reads or writes the environment
        // during restore.
        unsafe {
            match self.prev.take() {
                Some(p) => std::env::set_var("FUIGO_HOME", p),
                None => std::env::remove_var("FUIGO_HOME"),
            }
            match self.prev_xdg_data_home.take() {
                Some(p) => std::env::set_var("XDG_DATA_HOME", p),
                None => std::env::remove_var("XDG_DATA_HOME"),
            }
            match self.prev_grove_data_dir.take() {
                Some(p) => std::env::set_var("GROVE_DATA_DIR", p),
                None => std::env::remove_var("GROVE_DATA_DIR"),
            }
            match self.prev_home.take() {
                Some(p) => std::env::set_var("HOME", p),
                None => std::env::remove_var("HOME"),
            }
            match self.prev_control_sock.take() {
                Some(p) => std::env::set_var("GROVE_CONTROL_SOCK", p),
                None => std::env::remove_var("GROVE_CONTROL_SOCK"),
            }
        }
    }
}

#[cfg(test)]
mod tests;
