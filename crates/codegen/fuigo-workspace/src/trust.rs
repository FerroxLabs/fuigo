//! Folder-trust store ("do you trust this folder?").
//!
//! Persists per-folder trust decisions to `~/.fuigo/trusted_folders.toml`.
//! This is the durable backing store for the VS-Code-style folder-trust gate that decides whether repo-local MCP / LSP servers may spawn.
//! Those servers run arbitrary commands from repo-controlled config files.
//!
//! TOML shape:
//! ```toml
//! [folders."/abs/repo/root"]
//! trusted = true
//! decided_at = 1780000000
//! ```
//!
//! A recorded grant covers that workspace key and descendants that still resolve to the same git root ([`workspace_key`]).
//! A nearer recorded decision wins.
//! Other workspace keys under the path, including nested git roots, are not covered.
//! The persisted file is written atomically with owner-only (`0600`) permissions.
//!
//! The store is rooted at [`fuigo_config::user_fuigo_home`], never the cwd-relative `./.fuigo` fallback.
//! That home is `None` when neither `$FUIGO_HOME` nor a home directory is set (e.g. a minimal container / CI).
//! In that no-home environment [`TrustStore::load`] yields an empty store that trusts nothing and persists nothing.
//! So a cloned repo can never ship a `./.fuigo/trusted_folders.toml` that self-trusts its own checkout (fail closed).

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Filename of the folder-trust store under `~/.fuigo/`.
pub const TRUST_FILE_NAME: &str = fuigo_config::TRUSTED_FOLDERS_FILENAME;

/// A single folder's trust record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderTrust {
    /// Whether the folder (and same-repo descendants) is trusted.
    pub trusted: bool,
    /// Unix timestamp (seconds) of when the decision was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<i64>,
}

/// On-disk document shape for `trusted_folders.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TrustDocument {
    #[serde(default)]
    folders: BTreeMap<String, FolderTrust>,
}

/// Result of a strict read of the store file. A failed read is not represented here: it is an `Err`.
enum StoreRead {
    /// No file at the path (nothing to lose): safe to create.
    Missing,
    /// Read and parsed; an empty or whitespace-only file is an empty document.
    Document(TrustDocument),
}

impl StoreRead {
    fn into_document(self) -> TrustDocument {
        match self {
            Self::Missing => TrustDocument::default(),
            Self::Document(doc) => doc,
        }
    }
}

/// Why a locked write did not publish.
#[derive(Debug)]
pub(crate) enum TrustPersistError {
    /// The existing store could not be read or parsed; nothing was written, so the user's grants are untouched.
    Unreadable(io::Error),
    /// The store was read (or is missing) but the lock, rename or write failed; no replacement was published.
    Publish(io::Error),
}

impl TrustPersistError {
    pub(crate) fn as_io(&self) -> &io::Error {
        match self {
            Self::Unreadable(e) | Self::Publish(e) => e,
        }
    }
}

impl From<TrustPersistError> for io::Error {
    fn from(err: TrustPersistError) -> Self {
        match err {
            TrustPersistError::Unreadable(e) | TrustPersistError::Publish(e) => e,
        }
    }
}

/// Whether a write actually recorded the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Recorded {
    /// Written to disk.
    Durable,
    /// Over-broad root or no backing path: nothing written.
    Skipped,
}

/// Persisted set of trusted folders.
///
/// Construct with [`TrustStore::load`] (production) or [`TrustStore::load_from`] (tests).
/// Mutating with [`TrustStore::set_trusted`] persists to disk.
///
/// `path` is `None` only in a no-home environment (see [`TrustStore::load`]): such a store holds no folders, trusts nothing, and persists nothing.
///
/// A backing file that exists but cannot be read or parsed fails closed (P167): the store trusts nothing, and every
/// write refuses with an error instead of replacing the user's file with a document built from an empty stand-in.
#[derive(Debug, Clone)]
pub struct TrustStore {
    doc: TrustDocument,
    /// Backing file, or `None` when no user home resolves; such a store trusts nothing and persists nothing.
    /// Never a cwd-relative path.
    path: Option<PathBuf>,
    /// False when the backing file exists but could not be read or parsed. That is not an empty document.
    disk_readable: bool,
}

impl TrustStore {
    /// Load the trust store from `<user_fuigo_home>/trusted_folders.toml`.
    ///
    /// When no user home resolves (see the module-level fail-closed note) the path is `None` and this returns an [`Self::empty`] store.
    /// A missing file is an empty store. A file that exists but cannot be read or parsed is NOT: the store is marked
    /// unreadable, trusts nothing, and refuses writes (logged), so the file is left exactly as it is.
    pub fn load() -> Self {
        match Self::default_path() {
            Some(path) => Self::load_from(path),
            None => Self::empty(),
        }
    }

    /// Load from a custom path (for tests).
    pub fn load_from(path: PathBuf) -> Self {
        match Self::read_doc_strict(&path) {
            Ok(read) => Self {
                doc: read.into_document(),
                path: Some(path),
                disk_readable: true,
            },
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "folder trust: failed to read trust store; trusting nothing and leaving the file untouched"
                );
                Self {
                    doc: TrustDocument::default(),
                    path: Some(path),
                    disk_readable: false,
                }
            }
        }
    }

    /// An empty store with no backing path: trusts nothing and persists nothing.
    /// Used for the no-home environment where [`Self::default_path`] resolves to `None`.
    /// `disk_readable` is true so a missing home is not confused with a corrupt file.
    fn empty() -> Self {
        Self {
            doc: TrustDocument::default(),
            path: None,
            disk_readable: true,
        }
    }

    /// False when the backing file exists but could not be read or parsed (fail closed: trusts nothing, writes refuse).
    pub fn disk_readable(&self) -> bool {
        self.disk_readable
    }

    /// Whether a backing file path exists (false for the no-home empty store).
    pub(crate) fn has_store_path(&self) -> bool {
        self.path.is_some()
    }

    /// Default on-disk path: `<user_fuigo_home>/trusted_folders.toml`, or `None` when no user home resolves.
    ///
    /// Resolves via [`fuigo_config::user_fuigo_home`], never [`fuigo_config::fuigo_home`], so it never falls back to a cwd-relative `./.fuigo`.
    /// That fallback would let an untrusted cloned repo's `.fuigo` masquerade as the user-global store and self-trust the checkout.
    pub fn default_path() -> Option<PathBuf> {
        Self::default_path_in(fuigo_config::user_fuigo_home())
    }

    /// Map a resolved user-fuigo-home to the store path, preserving "no home" as "no path" (never synthesizing a fallback).
    /// Split from [`Self::default_path`] so the no-home branch is unit-testable without the process-global home cache.
    /// A relative home (e.g. `FUIGO_HOME=.fuigo`) is also "no path": joining it would put the store under the cwd,
    /// where a cloned repo could ship its own `trusted_folders.toml` and self-trust its checkout.
    fn default_path_in(user_fuigo_home: Option<PathBuf>) -> Option<PathBuf> {
        let home = user_fuigo_home?;
        if !home.is_absolute() {
            return None;
        }
        Some(home.join(TRUST_FILE_NAME))
    }

    /// Whether `key` is trusted, per the MOST-SPECIFIC recorded decision that applies to this workspace.
    ///
    /// This is the SHARED folder-trust gate: repo-local MCP and LSP servers and project hooks all resolve trust through this rule.
    ///
    /// A grant covers the recorded key and descendants that share its [`workspace_key`] (one git root).
    /// When an ancestor and a nearer folder are both recorded, the longest prefix wins, so an explicit child untrust overrides an ancestor's trust.
    /// A descendant with its own workspace key is not covered.
    /// The query key is canonicalized here, so callers need not pre-canonicalize (symmetric with [`Self::set_trusted`]).
    ///
    /// Over-broad keys are ignored on read (fail closed): an empty/relative key, the filesystem root, or the user's home directory are never honored.
    /// That holds even if such a record reaches the file via hand-edit or migration; see [`is_unsafe_trust_root`].
    pub fn is_trusted(&self, key: &Path) -> bool {
        // An unreadable store is not an empty allow-list; fail closed.
        if !self.disk_readable {
            return false;
        }
        let query = canonicalize_or_owned(key);
        let query_id = workspace_id(&query);
        // Among recorded folders that cover this workspace, the longest match decides
        // Canonical, code-produced keys are normalized, so that longest match is unique
        // A hand-edited store could hold non-canonical aliases (e.g. `/a/b` vs `/a/b/`) that tie on depth.
        // On a tie we require EVERY tied record to be trusted, so a contradictory edit fails closed
        let mut best_depth: Option<usize> = None;
        let mut trusted = false;
        for (folder, record) in &self.doc.folders {
            let folder = Path::new(folder);
            if is_unsafe_trust_root(folder) || !query.starts_with(folder) {
                continue;
            }
            if workspace_id(folder) != query_id {
                continue;
            }
            let depth = folder.components().count();
            match best_depth {
                Some(d) if depth < d => {}
                Some(d) if depth == d => trusted &= record.trusted,
                _ => {
                    best_depth = Some(depth);
                    trusted = record.trusted;
                }
            }
        }
        trusted
    }

    /// Record `workspace_key` as **trusted** and persist to disk.
    ///
    /// The key is canonicalized before storage so alias spellings (symlinks, `/tmp` vs `/private/tmp`, …) still match later lookups.
    /// Keys are stored as UTF-8 strings (via `to_string_lossy`); a non-UTF-8 path (rare on Unix) is stored lossily.
    /// Such a path therefore fails closed (it won't match on lookup) rather than over-trusting.
    ///
    /// **Over-broad roots are refused:** a non-absolute key, the filesystem root, or the home directory records nothing and returns `Ok(())`.
    /// `is_trusted` then stays `false` for it on both read and write.
    /// A later [`Self::set_untrusted`] on the same folder flips the stored decision (the insert overwrites).
    /// See `record_decision` for the locked read-modify-write contract and the no-home `Ok(())` no-op.
    pub fn set_trusted(&mut self, workspace_key: &Path) -> io::Result<()> {
        self.record_decision(workspace_key, true)
    }

    /// Record `workspace_key` as **untrusted** ("Never" / explicitly declined) and persist to disk.
    ///
    /// Mirrors [`Self::set_trusted`] exactly (canonicalization and over-broad-root refusal) but stores `trusted = false`.
    /// [`Self::is_trusted`] already returns `false` for such a record.
    /// Recording it lets a consumer tell "explicitly declined" apart from "undecided" (e.g. to avoid re-prompting).
    /// A later [`Self::set_trusted`] flips it back.
    pub fn set_untrusted(&mut self, workspace_key: &Path) -> io::Result<()> {
        self.record_decision(workspace_key, false)
    }

    /// Number of recorded folders (for diagnostics / tests).
    pub fn len(&self) -> usize {
        self.doc.folders.len()
    }

    /// Whether the store has no recorded folders.
    pub fn is_empty(&self) -> bool {
        self.doc.folders.is_empty()
    }

    /// Whether `workspace_key` has an EXACT recorded decision (trusted OR untrusted); the cascade does not apply.
    /// Used by the legacy-hook-trust migration to avoid overriding a folder the user has already decided on.
    pub fn has_decision(&self, workspace_key: &Path) -> bool {
        let canonical = canonicalize_or_owned(workspace_key);
        self.doc
            .folders
            .contains_key(canonical.to_string_lossy().as_ref())
    }

    // ── Internal ──────────────────────────────────────────────────────

    /// Shared write path for [`Self::set_trusted`] / [`Self::set_untrusted`].
    ///
    /// Canonicalizes the key and refuses over-broad roots (non-absolute, filesystem root, home dir).
    /// A refused root warns, records nothing, and returns `Ok(())`.
    /// With no backing path (no-home environment) it likewise warns and returns `Ok(())`, so it never writes a cwd-relative file.
    /// Otherwise it performs a locked read-modify-write-commit:
    /// 1. take an exclusive advisory lock on a sidecar `*.toml.lock` file, held for the whole critical section, so concurrent writers serialize;
    /// 2. re-read the current on-disk document so a peer's decisions are merged rather than clobbered;
    /// 3. insert the record and persist atomically;
    /// 4. only on success commit the new document to memory; on any lock/persist error `self.doc` is left unchanged.
    ///
    /// A store that exists but cannot be read or parsed (at load or at the locked re-read) is an error and nothing is
    /// written: a failed read is never an empty document to insert into and publish over the user's grants.
    fn record_decision(&mut self, workspace_key: &Path, trusted: bool) -> io::Result<()> {
        self.record_decision_strict(workspace_key, trusted)?;
        Ok(())
    }

    /// [`Self::record_decision`] with the outcome kept apart: [`Recorded::Skipped`] for a refused root or no backing
    /// path, [`TrustPersistError::Unreadable`] when the existing store could not be read (nothing written), and
    /// [`TrustPersistError::Publish`] when the lock or the atomic write failed (nothing published).
    pub(crate) fn record_decision_strict(
        &mut self,
        workspace_key: &Path,
        trusted: bool,
    ) -> Result<Recorded, TrustPersistError> {
        let canonical = canonicalize_or_owned(workspace_key);
        if is_unsafe_trust_root(&canonical) {
            tracing::warn!(
                path = %canonical.display(),
                trusted,
                "folder trust: refusing to record an over-broad root (home, filesystem root, or non-absolute path); nothing recorded"
            );
            return Ok(Recorded::Skipped);
        }

        // No backing file (no-home env): record nothing. Callers must not treat this as a durable grant.
        let Some(path) = self.path.clone() else {
            tracing::warn!(
                path = %canonical.display(),
                trusted,
                "folder trust: no user fuigo home resolved; trust decision not recorded"
            );
            return Ok(Recorded::Skipped);
        };

        // Loaded unreadable: confirm before any setup, so a still-corrupt store reports Unreadable (not a publish error).
        if !self.disk_readable
            && let Err(e) = Self::read_doc_strict(&path)
        {
            return Err(TrustPersistError::Unreadable(e));
        }

        // The lock file lives beside the store, so ensure the dir exists first.
        let parent = path.parent().ok_or_else(|| {
            TrustPersistError::Publish(io::Error::new(
                io::ErrorKind::InvalidInput,
                "trust store path has no parent",
            ))
        })?;
        std::fs::create_dir_all(parent).map_err(TrustPersistError::Publish)?;

        // Serialize cross-process writers for the whole read-modify-write so a concurrent peer's records are preserved, not clobbered
        let _lock = ExclusiveLock::acquire(&path.with_extension("toml.lock"))
            .map_err(TrustPersistError::Publish)?;

        // Re-read under the lock (merges a peer's concurrent writes). A failed read is not an empty document and must not be written back.
        let mut doc = Self::read_doc_strict(&path)
            .map_err(TrustPersistError::Unreadable)?
            .into_document();
        doc.folders.insert(
            canonical.to_string_lossy().to_string(),
            FolderTrust {
                trusted,
                decided_at: now_unix(),
            },
        );

        // Commit to memory only after a successful durable write, so a failure leaves the in-memory store unchanged
        Self::persist_doc(&path, &doc).map_err(TrustPersistError::Publish)?;
        self.doc = doc;
        self.disk_readable = true;
        Ok(Recorded::Durable)
    }

    /// Strict read. Only a genuinely absent entry (`symlink_metadata` reports `NotFound` / `NotADirectory`) is
    /// [`StoreRead::Missing`]; an empty or whitespace-only file is an empty document. Every other failure is an error:
    /// unreadable, not valid TOML, or a directory squatting on the path.
    /// A symlink, even a dangling one, is never `Missing`: a follow-time `NotFound` must not let a write replace the link.
    fn read_doc_strict(path: &Path) -> io::Result<StoreRead> {
        // Probe without following so a dangling symlink is an existing entry, not Missing.
        let link_meta = match std::fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(e) if matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) => {
                return Ok(StoreRead::Missing);
            }
            Err(e) => return Err(e),
        };
        let is_symlink = link_meta.file_type().is_symlink();

        // Test-only seam: run a fixture's action in the window between the probe and the read.
        #[cfg(test)]
        if let Some(action) = AFTER_PROBE.with(|a| a.borrow_mut().take()) {
            action();
        }

        let contents = match std::fs::read_to_string(path) {
            Ok(c) if c.trim().is_empty() => return Ok(StoreRead::Document(TrustDocument::default())),
            Ok(c) => c,
            // Gone between the probe and the read: Missing only if a fresh no-follow probe still finds nothing there, so a
            // regular file swapped for a dangling link in that window is an error, not an empty document (Astra r1).
            Err(e)
                if !is_symlink
                    && matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory)
                    && std::fs::symlink_metadata(path).is_err_and(|p| {
                        matches!(p.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory)
                    }) =>
            {
                return Ok(StoreRead::Missing);
            }
            Err(e) => return Err(e),
        };
        toml::from_str::<TrustDocument>(&contents)
            .map(StoreRead::Document)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Write `doc` to `path` atomically (unique temp, fsync, rename) with owner-only (`0600`) permissions.
    ///
    /// Uses a unique temp file in the destination directory so concurrent writers never share a temp path.
    /// The temp is fsynced for crash durability, then renamed over the destination.
    /// `tempfile::NamedTempFile` creates the temp with `O_EXCL` and `0600` permissions on Unix.
    /// `persist` performs an atomic replace, including over an existing destination on Windows.
    fn persist_doc(path: &Path, doc: &TrustDocument) -> io::Result<()> {
        use std::io::Write;

        #[cfg(test)]
        if FAIL_PERSIST.with(std::cell::Cell::get) {
            return Err(io::Error::other("injected persist failure (test)"));
        }

        let parent = path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "trust store path has no parent",
            )
        })?;
        std::fs::create_dir_all(parent)?;

        let body = toml::to_string_pretty(doc)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Unique temp in the same directory (atomic rename requires same FS).
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        tmp.write_all(body.as_bytes())?;
        // Durably flush to disk before publishing so a crash can't leave a zero-length or stale store behind
        // (`File::flush` is a no-op for durability; `sync_all` is what guarantees the bytes hit disk.)
        tmp.as_file().sync_all()?;
        // Atomic publish.
        tmp.persist(path).map_err(|e| e.error)?;
        Ok(())
    }
}

/// Compute the trust **workspace key** for a working directory.
///
/// The key is the canonicalized git repository root when `cwd` is inside a repo (trust applies to the whole repo), otherwise the canonicalized `cwd`.
///
/// A fuigo-managed worktree first collapses onto its recorded source repo's git
/// ROOT (via the `~/.fuigo/worktrees.db` registry), so every `fuigo -w` worktree
/// shares one trust key regardless of creation mode (including standalone clones
/// that git can't link back to their source) and regardless of the subdir
/// `fuigo -w` was launched from (the recorded source repo may be a repo subdir).
/// Non-registry git worktrees fall through to the git-topology collapse below.
///
/// A linked git worktree collapses onto its MAIN checkout's root so every `fuigo -w` worktree of a repo shares one trust key.
/// The collapse fires ONLY for the conventional `<workdir>/.git` layout, i.e. the common gitdir resolves back to `<main_workdir>/.git`.
/// For bare or `--separate-git-dir` repos the common gitdir's inferred workdir would be the gitdir's parent, broader than the real checkout.
/// There the key falls back to the worktree's own workdir, so it is narrow and never widened.
/// Resolution is via git2 (honoring `core.worktree`), never by string manipulation of paths.
///
/// Finally, an over-broad derived root is rejected in favor of the cwd.
/// When `$HOME` is itself a git repo (dotfiles in home), the up-walk lands on the home dir.
/// [`is_unsafe_trust_root`] then re-scopes the key to the cwd, keeping trust bound to the working dir rather than the whole home subtree.
/// A cwd that IS home is out of scope: no narrower safe fallback exists.
pub fn workspace_key(cwd: &Path) -> PathBuf {
    let key = git_derived_workspace_key(cwd);
    if is_unsafe_trust_root(&key) {
        return canonicalize_or_owned(cwd);
    }
    key
}

/// The workspace key derived from git topology, before [`workspace_key`] rejects an over-broad root in favor of the cwd.
fn git_derived_workspace_key(cwd: &Path) -> PathBuf {
    // A fuigo-managed worktree (any creation mode, incl. standalone clones git can't link) collapses onto its recorded source repo so trust is shared.
    if let Some(source_repo) = crate::worktree::source_repo_for_cwd(&cwd.to_string_lossy()) {
        // Key on the source repo's git ROOT so every worktree of one repo shares ONE key regardless of the subdir fuigo -w was launched from
        // This matches the git-topology branch below
        // Fall back to the recorded path when the source repo is gone (a standalone worktree whose source was deleted still works)
        let root = git2::Repository::discover(&source_repo)
            .ok()
            .and_then(|r| r.workdir().map(canonicalize_or_owned));
        return root.unwrap_or_else(|| canonicalize_or_owned(&source_repo));
    }
    if let Ok(repo) = git2::Repository::discover(cwd) {
        // Share one trust key across a repo's worktrees instead of re-prompting per worktree.
        if repo.is_worktree()
            && let Ok(main) = git2::Repository::open(repo.commondir())
            && let Some(main_workdir) = main.workdir()
            && canonicalize_or_owned(&main_workdir.join(".git"))
                == canonicalize_or_owned(repo.commondir())
        {
            return canonicalize_or_owned(main_workdir);
        }
        if let Some(workdir) = repo.workdir() {
            return canonicalize_or_owned(workdir);
        }
    }
    canonicalize_or_owned(cwd)
}

/// Whether `path` resolves to the user's home directory.
pub fn is_home_dir(path: &Path) -> bool {
    let Some(home) = fuigo_dirs::home_dir() else {
        return false;
    };
    canonicalize_or_owned(path) == canonicalize_or_owned(&home)
}

/// Whether `key` is too broad to ever be a safe trust root: refused on write and ignored on read (fail closed).
///
/// Also consumed by [`crate::folder_trust`] as the "key can never be recorded" signal.
/// Such a key can't be durably gated, so it resolves Trusted instead of prompting on a decision that could never persist.
/// Public because the shell's revoke path refuses the same roots: an in-process deny for a key the store can never grant could never be lifted.
pub fn is_unsafe_trust_root(key: &Path) -> bool {
    !key.is_absolute() || key.parent().is_none() || is_home_dir(key)
}

/// `workspace_key` of the nearest existing ancestor (git2 discover fails on a missing path).
fn workspace_id(path: &Path) -> PathBuf {
    workspace_key(path.ancestors().find(|p| p.exists()).unwrap_or(path))
}

fn canonicalize_or_owned(path: &Path) -> PathBuf {
    dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn now_unix() -> Option<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)
}

/// RAII exclusive advisory lock on a sidecar lock file, released on drop.
///
/// Serializes concurrent `TrustStore` writers (multiple processes / instances
/// sharing `~/.fuigo/`) across the whole read-modify-write so updates merge
/// instead of clobbering each other.
/// The lock is advisory; only writers that take it (i.e. this code) coordinate, which is sufficient since this store is the sole writer of its file.
struct ExclusiveLock {
    file: std::fs::File,
}

impl ExclusiveLock {
    fn acquire(lock_path: &Path) -> io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        fs2::FileExt::lock_exclusive(&file)?;
        Ok(Self { file })
    }
}

impl Drop for ExclusiveLock {
    fn drop(&mut self) {
        // Best-effort unlock; the OS also releases the flock when `file` closes.
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

/// One-time migration of legacy project-hook trust grants into the unified folder-trust store.
/// Idempotent and guarded to run at most once per process.
///
/// The legacy `~/.fuigo/trusted-hook-projects` file listed one canonical project
/// path per line; each becomes a folder-trust grant so the unified gate honors prior decisions.
/// The legacy file is then renamed to `*.migrated` so it is read only once.
/// A no-op when the legacy file is absent/already migrated or no user fuigo home resolves.
pub fn migrate_legacy_hook_trust() {
    // Local/dev builds do NO trust-store I/O: skip the load and the legacy-file rename
    if crate::folder_trust::folder_trust_inert() {
        return;
    }
    static MIGRATED: Once = Once::new();
    MIGRATED.call_once(|| {
        let Some(legacy_file) = fuigo_hooks::trust::legacy_trust_file_path() else {
            return;
        };
        let mut store = TrustStore::load();
        let migrated = migrate_legacy_hook_trust_in(&legacy_file, &mut store);
        if migrated > 0 {
            tracing::info!(
                migrated,
                "migrated legacy hook-trust grants into folder-trust"
            );
        }
    });
}

/// [`migrate_legacy_hook_trust`] with explicit paths, so the migration is testable without the process-global fuigo-home cache.
/// Returns the number of grants seeded into `store`.
fn migrate_legacy_hook_trust_in(legacy_file: &Path, store: &mut TrustStore) -> usize {
    // A read error must NOT be mistaken for "no grants": bail without renaming
    // A transient/permission failure then can't permanently consume the legacy file
    let projects = match fuigo_hooks::trust::list_trusted_projects_with_file(legacy_file) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                path = %legacy_file.display(),
                error = %e,
                "failed to read legacy hook-trust file; leaving it in place for a future run"
            );
            return 0;
        }
    };
    // A store with no backing file, or one that could not be read, is not "no decision": do not seed into an empty
    // stand-in (the write would refuse, or have nowhere to go) and do not consume the legacy file.
    if store.path.is_none() || !store.disk_readable() {
        tracing::warn!(
            path = %legacy_file.display(),
            "leaving legacy hook-trust file in place; the folder-trust store has no readable document"
        );
        return 0;
    }
    let mut migrated = 0;
    let mut had_seed_error = false;
    for project in &projects {
        // Never override an existing decision: a folder the user has since trusted or untrusted keeps that decision
        // A re-run after a rename failure then can't silently re-trust a folder the user untrusted in between
        if store.has_decision(project) {
            continue;
        }
        if let Err(e) = store.set_trusted(project) {
            tracing::warn!(
                path = %project.display(),
                error = %e,
                "failed to migrate a legacy hook-trust grant"
            );
            // A seeding WRITE failure (e.g. a full disk) dropped this grant: leave the legacy file in place below so a future run retries it.
            had_seed_error = true;
            continue;
        }
        // set_trusted silently refuses over-broad roots (records nothing), so count only folders actually seeded
        if store.has_decision(project) {
            migrated += 1;
        }
    }
    // Rename so the legacy file is consumed exactly once, reached only after a SUCCESSFUL read AND with every grant seeded
    // A seeding write error leaves the file in place for a future run (mirrors the read-error bail)
    // Idempotent: skipped when already migrated/absent
    if had_seed_error {
        tracing::warn!(
            path = %legacy_file.display(),
            "leaving legacy hook-trust file in place after a seeding error; a future run will retry"
        );
    } else if legacy_file.exists() {
        let migrated_file = legacy_file.with_extension("migrated");
        if let Err(e) = std::fs::rename(legacy_file, &migrated_file) {
            tracing::warn!(
                path = %legacy_file.display(),
                error = %e,
                "failed to rename legacy hook-trust file after migration"
            );
        }
    }
    migrated
}

#[cfg(test)]
thread_local! {
    /// Test-only: an action [`TrustStore::read_doc_strict`] runs once between its no-follow probe and its read, so a
    /// test can swap the entry inside that window.
    static AFTER_PROBE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    /// Test-only: make [`TrustStore::persist_doc`] fail on this thread, AFTER the lock and the strict re-read, so a test
    /// reaches the final publication step (a fixture that blocks the lock or the read never gets there).
    static FAIL_PERSIST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrate_legacy_hook_trust_seeds_store_and_renames_file() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        // A real project dir so set_trusted's canonicalize succeeds.
        let project = tmp.path().join("repo");
        std::fs::create_dir_all(&project).unwrap();
        let project_key = canonicalize_or_owned(&project);

        // Legacy file with one canonical project path.
        let legacy = tmp.path().join("trusted-hook-projects");
        std::fs::write(&legacy, format!("{}\n", project_key.display())).unwrap();

        let mut store = TrustStore::load_from(store_path.clone());
        let migrated = migrate_legacy_hook_trust_in(&legacy, &mut store);
        assert_eq!(migrated, 1);
        assert!(store.is_trusted(&project_key), "migrated grant is trusted");

        // Legacy file renamed so it is read only once.
        assert!(!legacy.exists(), "legacy file consumed");
        assert!(
            legacy.with_extension("migrated").exists(),
            "renamed to .migrated"
        );

        // The grant persisted to disk.
        let reloaded = TrustStore::load_from(store_path);
        assert!(reloaded.is_trusted(&project_key));
    }

    #[test]
    fn migrate_legacy_hook_trust_does_not_override_existing_decision() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        let project = tmp.path().join("repo");
        std::fs::create_dir_all(&project).unwrap();
        let project_key = canonicalize_or_owned(&project);

        let legacy = tmp.path().join("trusted-hook-projects");
        std::fs::write(&legacy, format!("{}\n", project_key.display())).unwrap();

        // The user has ALREADY untrusted this folder in the unified store.
        let mut store = TrustStore::load_from(store_path);
        store.set_untrusted(&project_key).unwrap();

        let migrated = migrate_legacy_hook_trust_in(&legacy, &mut store);
        assert_eq!(migrated, 0, "an already-decided folder is not re-seeded");
        assert!(
            !store.is_trusted(&project_key),
            "the user's untrust decision is preserved, not overridden by migration"
        );
        // The legacy file is still consumed (renamed) so it is read only once.
        assert!(!legacy.exists());
        assert!(legacy.with_extension("migrated").exists());
    }

    #[test]
    fn migrate_legacy_hook_trust_is_noop_when_file_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        let legacy = tmp.path().join("trusted-hook-projects"); // never created

        let mut store = TrustStore::load_from(store_path);
        let migrated = migrate_legacy_hook_trust_in(&legacy, &mut store);
        assert_eq!(migrated, 0);
        assert!(store.is_empty(), "nothing recorded");
        assert!(
            !legacy.with_extension("migrated").exists(),
            "no rename without source"
        );
    }

    #[test]
    fn migrate_legacy_hook_trust_leaves_unreadable_file_in_place() {
        // A legacy file that EXISTS but can't be read must not be consumed
        // A transient read error would otherwise rename it and permanently drop every grant
        // Use a directory at the legacy path: it `exists()` but `read_to_string` errors (non-NotFound), portably simulating the failure
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        let legacy = tmp.path().join("trusted-hook-projects");
        std::fs::create_dir_all(&legacy).unwrap();

        let mut store = TrustStore::load_from(store_path);
        let migrated = migrate_legacy_hook_trust_in(&legacy, &mut store);
        assert_eq!(migrated, 0, "an unreadable legacy file seeds nothing");
        assert!(store.is_empty(), "nothing recorded on a read failure");
        assert!(legacy.exists(), "unreadable legacy file is left in place");
        assert!(
            !legacy.with_extension("migrated").exists(),
            "unreadable legacy file must not be consumed/renamed"
        );
    }

    #[test]
    fn migrate_legacy_hook_trust_leaves_file_in_place_on_seed_write_error() {
        // A seeding WRITE failure (e.g. a full disk) must not consume the legacy file either: leave it un-renamed so a future run retries the grants.
        // Force set_trusted to error at the WRITE: a directory squats on the store's lock file, so the lock cannot be taken
        // (robust even when run as root). P167: a directory at the store path itself is now an unreadable store, refused
        // before any write, so it no longer exercises the seed-write path.
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        std::fs::create_dir_all(store_path.with_extension("toml.lock")).unwrap();
        let project = tmp.path().join("repo");
        std::fs::create_dir_all(&project).unwrap();
        let project_key = canonicalize_or_owned(&project);

        let legacy = tmp.path().join("trusted-hook-projects");
        std::fs::write(&legacy, format!("{}\n", project_key.display())).unwrap();

        let mut store = TrustStore::load_from(store_path);
        assert!(store.disk_readable(), "the store reads (missing); only the write fails");
        let migrated = migrate_legacy_hook_trust_in(&legacy, &mut store);
        assert_eq!(migrated, 0, "a seeding write error seeds nothing");
        assert!(
            legacy.exists(),
            "legacy file is left in place on a seeding write error"
        );
        assert!(
            !legacy.with_extension("migrated").exists(),
            "a seeding write error must not consume/rename the legacy file"
        );
    }

    #[test]
    fn empty_store_trusts_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let store = TrustStore::load_from(tmp.path().join(TRUST_FILE_NAME));
        assert!(store.is_empty());
        assert!(!store.is_trusted(tmp.path()));
    }

    #[test]
    fn default_path_in_maps_home_and_preserves_no_home() {
        // With a resolvable home the store sits at <home>/trusted_folders.toml.
        // A platform-absolute home: `/home/alice/.fuigo` is not absolute on Windows (no drive), and P167 refuses relative homes.
        let home = std::env::temp_dir().join(".fuigo");
        assert!(home.is_absolute());
        assert_eq!(
            TrustStore::default_path_in(Some(home.clone())),
            Some(home.join(TRUST_FILE_NAME))
        );

        // With NO resolvable home the path is `None`, never a synthesized fallback
        // This is the regression guard that keeps the store off the cwd-relative `./.fuigo` that fuigo_home() would invent
        // That is how a cloned repo's own `<repo>/.fuigo/trusted_folders.toml` could masquerade as the user-global store and self-trust the checkout
        assert_eq!(TrustStore::default_path_in(None), None);
    }

    #[test]
    fn default_path_sources_from_user_fuigo_home() {
        // Pins the source: the production accessor reads user_fuigo_home() (Option, no cwd fallback), not fuigo_home()
        // The real regression guard is `default_path_in(None) == None` above
        assert_eq!(
            TrustStore::default_path(),
            fuigo_config::user_fuigo_home().map(|h| h.join(TRUST_FILE_NAME))
        );
    }

    #[test]
    fn no_home_store_trusts_nothing_and_persists_nothing() {
        // Simulate the no-home environment where `default_path()` is `None`: `load()` yields `empty()`, a store with no backing path
        // It must trust nothing and silently no-op on writes, never touching a cwd-relative `./.fuigo`
        let mut store = TrustStore::empty();
        assert!(store.is_empty());

        let key = Path::new("/some/abs/repo");
        assert!(!store.is_trusted(key), "no-home store trusts nothing");

        // set_trusted is a no-op that returns Ok and records nothing.
        store
            .set_trusted(key)
            .expect("no-home set_trusted is a no-op Ok");
        assert!(
            store.is_empty(),
            "no-home set_trusted must record nothing (in memory)"
        );
        assert!(
            !store.is_trusted(key),
            "still trusts nothing after the no-op write"
        );

        // set_untrusted likewise no-ops without panicking or recording.
        store
            .set_untrusted(key)
            .expect("no-home set_untrusted is a no-op Ok");
        assert!(store.is_empty());
    }

    #[test]
    fn set_trusted_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let key = canonicalize_or_owned(&repo);

        let mut store = TrustStore::load_from(store_path.clone());
        assert!(!store.is_trusted(&key));
        store.set_trusted(&key).unwrap();
        assert!(store.is_trusted(&key));

        // Reload from disk and verify persistence.
        let reloaded = TrustStore::load_from(store_path);
        assert!(reloaded.is_trusted(&key));
    }

    #[test]
    fn persist_overwrites_existing_and_round_trips_both() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        let repo_a = tmp.path().join("repo-a");
        let repo_b = tmp.path().join("repo-b");
        std::fs::create_dir_all(&repo_a).unwrap();
        std::fs::create_dir_all(&repo_b).unwrap();
        let key_a = canonicalize_or_owned(&repo_a);
        let key_b = canonicalize_or_owned(&repo_b);

        let mut store = TrustStore::load_from(store_path.clone());
        store.set_trusted(&key_a).unwrap();
        // The second persist runs over an already-existing destination file.
        store.set_trusted(&key_b).unwrap();

        // Both decisions survive the overwrite, after reloading from disk.
        let reloaded = TrustStore::load_from(store_path.clone());
        assert!(reloaded.is_trusted(&key_a));
        assert!(reloaded.is_trusted(&key_b));

        // The owner-only guarantee still holds after the overwrite, independent of umask (NamedTempFile creates 0600 on Unix regardless of umask)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&store_path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "trust store must stay 0600 after overwrite"
            );
        }
    }

    #[test]
    fn trust_cascades_to_subdirectories() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let child = repo.join("crates").join("inner");
        std::fs::create_dir_all(&child).unwrap();
        git2::Repository::init(&repo).unwrap();
        let repo_key = canonicalize_or_owned(&repo);
        let child_key = canonicalize_or_owned(&child);

        let mut store = TrustStore::load_from(tmp.path().join(TRUST_FILE_NAME));
        store.set_trusted(&repo_key).unwrap();

        assert!(store.is_trusted(&child_key));
        // A sibling outside the trusted root is NOT trusted.
        let sibling = canonicalize_or_owned(tmp.path()).join("other-repo");
        assert!(!store.is_trusted(&sibling));
        // The cascade is component-wise (`Path::starts_with`), so `…/repo` must not trust `…/repo-sibling` or `…/repository`
        let prefix_sibling = canonicalize_or_owned(tmp.path()).join("repo-sibling");
        assert!(
            !store.is_trusted(&prefix_sibling),
            "string-prefix sibling must NOT be trusted (cascade is component-wise)"
        );
    }

    #[test]
    fn parent_grant_does_not_cover_nested_git_root() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("work");
        let nested = parent.join("evil");
        std::fs::create_dir_all(&nested).unwrap();
        git2::Repository::init(&nested).unwrap();
        let parent_key = canonicalize_or_owned(&parent);
        let nested_key = canonicalize_or_owned(&nested);

        let mut store = TrustStore::load_from(tmp.path().join(TRUST_FILE_NAME));
        store.set_trusted(&parent_key).unwrap();

        assert!(
            store.is_trusted(&parent_key),
            "the granted folder stays trusted"
        );
        assert!(
            !store.is_trusted(&nested_key),
            "a nested git root must not inherit a parent grant"
        );
    }

    #[test]
    fn git_parent_grant_does_not_cover_nested_git_root() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("work");
        let nested = parent.join("evil");
        let sibling = parent.join("src");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();
        git2::Repository::init(&parent).unwrap();
        git2::Repository::init(&nested).unwrap();
        let parent_key = canonicalize_or_owned(&parent);
        let nested_key = canonicalize_or_owned(&nested);
        let sibling_key = canonicalize_or_owned(&sibling);

        let mut store = TrustStore::load_from(tmp.path().join(TRUST_FILE_NAME));
        store.set_trusted(&parent_key).unwrap();

        assert!(
            store.is_trusted(&parent_key),
            "the granted folder stays trusted"
        );
        assert!(
            store.is_trusted(&sibling_key),
            "a same-repo subdirectory is still covered"
        );
        assert!(
            !store.is_trusted(&nested_key),
            "a nested git root must not inherit a parent grant"
        );
        assert!(
            !store.is_trusted(&nested_key.join("src")),
            "a descendant of the nested git root must not inherit a parent grant"
        );
    }

    #[test]
    fn parent_grant_does_not_cover_nongit_descendant() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("work");
        let child = parent.join("tarball");
        std::fs::create_dir_all(&child).unwrap();
        let parent_key = canonicalize_or_owned(&parent);
        let child_key = canonicalize_or_owned(&child);

        // Plant a dummy .git because libgit2 discover ignores GIT_CEILING_DIRECTORIES.
        std::fs::write(tmp.path().join(".git"), "gitdir: /nonexistent\n").unwrap();

        let mut store = TrustStore::load_from(tmp.path().join(TRUST_FILE_NAME));
        store.set_trusted(&parent_key).unwrap();

        assert!(
            store.is_trusted(&parent_key),
            "the granted folder stays trusted"
        );
        assert!(
            !store.is_trusted(&child_key),
            "a non-git descendant must not inherit a parent grant"
        );
    }

    #[test]
    fn most_specific_decision_wins_over_ancestor_cascade() {
        // An explicit child untrust must override a trusted ancestor (the bug where an untrust was undone by the cascade on the next reload)
        // The longest-prefix match decides, so siblings of the untrusted child stay trusted via the ancestor
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("parent");
        let child = parent.join("child");
        let other = parent.join("other");
        std::fs::create_dir_all(&child).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        git2::Repository::init(&parent).unwrap();
        let parent_key = canonicalize_or_owned(&parent);
        let child_key = canonicalize_or_owned(&child);
        let other_key = canonicalize_or_owned(&other);

        let mut store = TrustStore::load_from(tmp.path().join(TRUST_FILE_NAME));
        store.set_trusted(&parent_key).unwrap();
        store.set_untrusted(&child_key).unwrap();

        assert!(store.is_trusted(&parent_key), "the ancestor stays trusted");
        assert!(
            !store.is_trusted(&child_key),
            "an explicit child untrust overrides the trusted ancestor"
        );
        assert!(
            !store.is_trusted(&child_key.join("nested")),
            "the untrust cascades to the child's own subdirectories"
        );
        assert!(
            store.is_trusted(&other_key),
            "a sibling without its own decision is still trusted via the ancestor"
        );

        // The most-specific-wins decision survives a reload from disk.
        let reloaded = TrustStore::load_from(tmp.path().join(TRUST_FILE_NAME));
        assert!(!reloaded.is_trusted(&child_key));
        assert!(reloaded.is_trusted(&other_key));
    }

    #[test]
    fn most_specific_trust_wins_over_untrusted_ancestor() {
        // The symmetric half of most-specific-wins: with an UNTRUSTED ancestor and a nearer TRUSTED child, the child IS trusted
        // That trust cascades to the child's own subdirectories
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("parent");
        let child = parent.join("child");
        std::fs::create_dir_all(&child).unwrap();
        git2::Repository::init(&parent).unwrap();
        let parent_key = canonicalize_or_owned(&parent);
        let child_key = canonicalize_or_owned(&child);

        let mut store = TrustStore::load_from(tmp.path().join(TRUST_FILE_NAME));
        store.set_untrusted(&parent_key).unwrap();
        store.set_trusted(&child_key).unwrap();

        assert!(
            !store.is_trusted(&parent_key),
            "the ancestor stays untrusted"
        );
        assert!(
            store.is_trusted(&child_key),
            "a nearer explicit trust overrides the untrusted ancestor"
        );
        assert!(
            store.is_trusted(&child_key.join("nested")),
            "the child's trust cascades to its own subdirectories"
        );

        // The decision survives a reload from disk.
        let reloaded = TrustStore::load_from(tmp.path().join(TRUST_FILE_NAME));
        assert!(!reloaded.is_trusted(&parent_key));
        assert!(reloaded.is_trusted(&child_key));
    }

    #[cfg(unix)]
    #[test]
    fn persisted_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();

        let mut store = TrustStore::load_from(store_path.clone());
        store.set_trusted(&canonicalize_or_owned(&repo)).unwrap();

        let mode = std::fs::metadata(&store_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "trust store must be 0600");
    }

    #[test]
    fn home_dir_is_not_persisted() {
        // Serialize with the test in this file that mutates $HOME: its temp $HOME window could otherwise flip is_home_dir mid-test
        // This test mutates no env itself
        let _lock = crate::ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        let Some(home) = fuigo_dirs::home_dir() else {
            return; // no home dir in this environment; nothing to assert
        };

        let mut store = TrustStore::load_from(store_path.clone());
        store.set_trusted(&home).unwrap();

        // Nothing was persisted, and the store still holds no folders.
        assert!(store.is_empty(), "home dir must not be recorded");
        assert!(
            !store_path.exists(),
            "no trust file should be written for the home dir"
        );
    }

    #[test]
    fn workspace_key_falls_back_to_cwd_outside_repo() {
        // A freshly created temp dir is not inside a git repo in CI sandboxes; the key should be the canonicalized dir itself
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("plain");
        std::fs::create_dir_all(&sub).unwrap();
        let key = workspace_key(&sub);
        assert!(key.is_absolute());
        // Only pin the fallback when the temp dir is outside any git repo (a dev/CI checkout may place $TMPDIR inside the source repository)
        if git2::Repository::discover(&sub).is_err() {
            assert_eq!(key, canonicalize_or_owned(&sub));
        }
    }

    #[test]
    fn workspace_key_ignores_home_git_repo_for_subdir() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        // Home-is-a-git-repo (dotfiles in $HOME): the git up-walk finds home as the repo root, but a subdir must key on the SUBDIR, not $HOME
        // Pin HOME and USERPROFILE: fuigo_dirs::home_dir reads USERPROFILE on Windows
        let _lock = crate::ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let _home_guard = crate::TestEnvGuard::set("HOME", home.path());
        let _userprofile_guard = crate::TestEnvGuard::set("USERPROFILE", home.path());
        git2::Repository::init(home.path()).unwrap();
        let civ = home.path().join("Documents").join("civ");
        std::fs::create_dir_all(&civ).unwrap();

        let key = workspace_key(&civ);
        assert_eq!(
            key,
            canonicalize_or_owned(&civ),
            "a subdir under a home git repo must key on the subdir, not $HOME"
        );
        assert!(
            !is_home_dir(&key),
            "the workspace key must never resolve to the home dir"
        );
    }

    #[test]
    fn empty_key_is_not_trusted() {
        // Fail closed: a degenerate `[folders.""] trusted = true` must not trust anything
        // The empty path is a prefix of every path, so honoring it would trust the whole filesystem (fail open)
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        std::fs::write(&store_path, "[folders.\"\"]\ntrusted = true\n").unwrap();

        let store = TrustStore::load_from(store_path);
        // The record loads, so this exercises the read-side guard (not a parse drop).
        assert!(!store.is_empty(), "empty-key record should still load");
        assert!(
            !store.is_trusted(Path::new("/some/arbitrary/path")),
            "an empty key must not trust the filesystem"
        );
    }

    #[test]
    fn malformed_store_fails_soft_to_empty() {
        // Corrupt TOML must fail closed: empty store, trust nothing, no panic.
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        std::fs::write(&store_path, "this is not = valid toml [[[").unwrap();

        let store = TrustStore::load_from(store_path);
        assert!(store.is_empty(), "malformed store must load as empty");
        assert!(!store.is_trusted(Path::new("/any/path")));
    }

    #[test]
    fn root_key_is_not_trusted() {
        // Fail closed: a `[folders."/"]` record must not trust every absolute path
        // The root is a prefix of all of them via the cascade, so it is ignored on read even if it reaches the file by hand-edit / migration
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        std::fs::write(&store_path, "[folders.\"/\"]\ntrusted = true\n").unwrap();

        let store = TrustStore::load_from(store_path);
        assert!(!store.is_empty(), "root-key record should still load");
        assert!(
            !store.is_trusted(Path::new("/any/abs/path")),
            "filesystem root must never be honored as a trust key"
        );
    }

    #[test]
    fn tied_conflicting_aliases_fail_closed() {
        // Two equal-depth, non-canonical aliases of the SAME folder carry CONFLICTING decisions
        // `Path::components()` normalizes the trailing slash so `/a/b` and `/a/b/` tie on depth, yet they load as distinct map keys
        // The tie branch ANDs the tied records, so any untrusted tied alias forces a fail-closed `false` REGARDLESS of map order
        // Asserting BOTH orderings pins this: a last-wins revert (return the LAST equal-depth record) returns `true` for ordering (b) below
        // A single pinned ordering would pass under both the AND-loop and the buggy last-wins form
        let fails_closed = |trusted_ab: bool, trusted_ab_slash: bool| {
            let tmp = tempfile::tempdir().unwrap();
            let store_path = tmp.path().join(TRUST_FILE_NAME);
            std::fs::write(
                &store_path,
                format!(
                    "[folders.'/a/b']\ntrusted = {trusted_ab}\n\
                     [folders.'/a/b/']\ntrusted = {trusted_ab_slash}\n"
                ),
            )
            .unwrap();
            let store = TrustStore::load_from(store_path);
            assert_eq!(store.len(), 2, "both alias records should load distinctly");
            // `/a/b/c` does not exist, so `canonicalize_or_owned` is a no-op; both aliases prefix it and tie on depth.
            !store.is_trusted(Path::new("/a/b/c"))
        };

        // (a) untrusted alias sorts LAST (`/a/b/`): caught by a revert to the original `any(trusted)` form, but NOT by a last-wins revert
        assert!(
            fails_closed(true, false),
            "tie with `/a/b` trusted + `/a/b/` untrusted must fail closed"
        );
        // (b) untrusted alias sorts FIRST (`/a/b`): a last-wins revert would return the last record (`/a/b/`, trusted)
        //     THIS ordering is what catches a last-wins regression; the AND-loop still yields false
        assert!(
            fails_closed(false, true),
            "tie with `/a/b` untrusted + `/a/b/` trusted must STILL fail closed"
        );
    }

    #[test]
    fn home_key_on_disk_is_not_honored() {
        // Serialize with the test in this file that mutates $HOME: its temp $HOME window could otherwise flip is_home_dir mid-test
        // This test mutates no env itself
        let _lock = crate::ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // A hand-edited / migrated `[folders."<home>"]` record must not trust repos under $HOME; the read side ignores it, matching set_trusted
        let Some(home) = fuigo_dirs::home_dir() else {
            return; // no home dir in this environment; nothing to assert
        };
        let canonical_home = canonicalize_or_owned(&home);
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        // TOML literal-string key avoids escaping issues on any platform.
        let body = format!(
            "[folders.'{}']\ntrusted = true\n",
            canonical_home.to_string_lossy()
        );
        std::fs::write(&store_path, body).unwrap();

        let store = TrustStore::load_from(store_path);
        let sub = canonical_home.join("some").join("sub");
        assert!(
            !store.is_trusted(&sub),
            "a home-dir key on disk must not be honored"
        );
    }

    #[cfg(unix)]
    #[test]
    fn set_trusted_canonicalizes_key() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        let real = tmp.path().join("real-repo");
        std::fs::create_dir_all(&real).unwrap();
        let link = tmp.path().join("link-repo");
        symlink(&real, &link).unwrap();

        // Trust via the symlink alias.
        let mut store = TrustStore::load_from(store_path);
        store.set_trusted(&link).unwrap();

        let canonical_real = canonicalize_or_owned(&real);
        assert!(
            store.is_trusted(&canonical_real),
            "set_trusted must store the canonical path so canonical lookups match"
        );
    }

    #[test]
    fn set_untrusted_records_explicit_deny() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let key = canonicalize_or_owned(&repo);

        let mut store = TrustStore::load_from(store_path.clone());
        store.set_untrusted(&key).unwrap();
        assert!(!store.is_trusted(&key), "an explicit deny is not trusted");
        assert!(!store.is_empty(), "the deny decision is recorded");

        // Reload from disk: the deny record persisted.
        let reloaded = TrustStore::load_from(store_path);
        assert!(!reloaded.is_trusted(&key));
        assert!(!reloaded.is_empty(), "deny record survives reload");
    }

    #[test]
    fn trust_decision_flips() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let key = canonicalize_or_owned(&repo);

        let mut store = TrustStore::load_from(store_path.clone());
        store.set_trusted(&key).unwrap();
        assert!(store.is_trusted(&key));
        store.set_untrusted(&key).unwrap();
        assert!(!store.is_trusted(&key), "untrust flips the stored bool");
        store.set_trusted(&key).unwrap();
        assert!(store.is_trusted(&key), "re-trust flips it back");
        // The insert overwrites: one record per folder, no duplicates
        assert_eq!(store.len(), 1);

        let reloaded = TrustStore::load_from(store_path);
        assert!(reloaded.is_trusted(&key));
        assert_eq!(reloaded.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn is_trusted_canonicalizes_query() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        let real = tmp.path().join("real-repo");
        std::fs::create_dir_all(&real).unwrap();
        let link = tmp.path().join("link-repo");
        symlink(&real, &link).unwrap();

        let mut store = TrustStore::load_from(store_path);
        store.set_trusted(&canonicalize_or_owned(&real)).unwrap();

        // A query via the symlink alias resolves to the trusted real dir.
        assert!(
            store.is_trusted(&link),
            "is_trusted must canonicalize the query so a symlink alias matches"
        );
    }

    #[test]
    fn concurrent_writers_do_not_clobber() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        let repo_a = tmp.path().join("repo-a");
        let repo_b = tmp.path().join("repo-b");
        std::fs::create_dir_all(&repo_a).unwrap();
        std::fs::create_dir_all(&repo_b).unwrap();
        let key_a = canonicalize_or_owned(&repo_a);
        let key_b = canonicalize_or_owned(&repo_b);

        // Two instances loaded while the file is empty: both start with an empty in-memory doc, mimicking two processes that raced the initial load
        let mut s1 = TrustStore::load_from(store_path.clone());
        let mut s2 = TrustStore::load_from(store_path.clone());
        s1.set_trusted(&key_a).unwrap();
        s2.set_trusted(&key_b).unwrap();

        // The locked re-read-merge means s2's write did not clobber s1's.
        let reloaded = TrustStore::load_from(store_path);
        assert!(
            reloaded.is_trusted(&key_a),
            "A must survive a concurrent write"
        );
        assert!(
            reloaded.is_trusted(&key_b),
            "B must survive a concurrent write"
        );
    }

    #[cfg(unix)]
    #[test]
    fn persist_failure_leaves_memory_unchanged() {
        // Deny the write: a directory squats on the store's lock file, so the locked write cannot start (robust even as root).
        // P167: a directory at the store path itself is an unreadable store, refused before any write, so it no longer
        // reaches the write path. It exercises the invariant: on a write error the in-memory doc is left unchanged
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        std::fs::create_dir_all(store_path.with_extension("toml.lock")).unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let key = canonicalize_or_owned(&repo);

        let mut store = TrustStore::load_from(store_path);
        let result = store.set_trusted(&key);
        assert!(
            result.is_err(),
            "persist over a directory destination must fail"
        );
        assert!(
            !store.is_trusted(&key),
            "memory must be unchanged on persist failure"
        );
    }

    /// Astra r2 #3: the failure at the very last step (publication), after the lock and a clean re-read of a store that
    /// already holds a grant: memory and disk keep exactly the prior state.
    #[test]
    fn p167_publication_failure_leaves_memory_and_disk_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        let kept = tmp.path().join("kept");
        let new = tmp.path().join("new");
        std::fs::create_dir_all(&kept).unwrap();
        std::fs::create_dir_all(&new).unwrap();
        let (kept, new) = (canonicalize_or_owned(&kept), canonicalize_or_owned(&new));
        let mut store = TrustStore::load_from(store_path.clone());
        store.set_trusted(&kept).unwrap();
        let before = std::fs::read(&store_path).unwrap();

        FAIL_PERSIST.with(|f| f.set(true));
        let result = store.record_decision_strict(&new, true);
        FAIL_PERSIST.with(|f| f.set(false));
        assert!(matches!(result, Err(TrustPersistError::Publish(_))), "{result:?}");
        assert!(!store.is_trusted(&new), "memory must not commit an unpublished grant");
        assert!(store.is_trusted(&kept), "the prior grant is still in memory");
        assert_eq!(std::fs::read(&store_path).unwrap(), before, "disk unchanged");
    }

    #[test]
    fn workspace_key_collapses_linked_worktrees_onto_main_checkout() {
        // Every linked `fuigo -w` worktree of a repo must share ONE trust key: its main checkout's root
        // Build a real repo and two linked worktrees and assert each collapses onto the main checkout (trusted once, not re-prompted per worktree)
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("main");
        std::fs::create_dir_all(&main).unwrap();
        let repo = git2::Repository::init(&main).unwrap();

        // Worktree creation requires a valid HEAD, so make an initial commit.
        let sig = git2::Signature::now("t", "t@t").unwrap();
        let tree = {
            let mut idx = repo.index().unwrap();
            let oid = idx.write_tree().unwrap();
            repo.find_tree(oid).unwrap()
        };
        repo.commit(Some("HEAD"), &sig, &sig, "init", &tree, &[])
            .unwrap();

        // Linked worktrees OUTSIDE the main dir (git2 creates the paths).
        let wt1 = dir.path().join("wt1");
        let wt2 = dir.path().join("wt2");
        repo.worktree("wt1", &wt1, None).unwrap();
        repo.worktree("wt2", &wt2, None).unwrap();

        let main_key = workspace_key(&main);
        // Parity: the main checkout keys off its own workdir.
        assert_eq!(main_key, canonicalize_or_owned(&main));
        assert_eq!(
            workspace_key(&wt1),
            main_key,
            "worktree must collapse onto main checkout"
        );
        assert_eq!(
            workspace_key(&wt2),
            main_key,
            "second worktree must share the same key"
        );
    }

    #[test]
    fn workspace_key_bare_repo_worktree_does_not_widen_to_parent() {
        // A bare repo's `commondir()` is the bare dir itself, so a naive `commondir().parent()` would key off the dir CONTAINING the repo
        // That would trust every sibling via the subdirectory cascade
        // The key must instead fall back to the worktree's OWN dir (narrow, never widened)
        let dir = tempfile::tempdir().unwrap();
        let bare = dir.path().join("repo.git");
        let repo = git2::Repository::init_bare(&bare).unwrap();

        // Worktree creation needs a valid HEAD; build an empty commit (bare repo has no index, so use a treebuilder for the empty tree)
        let sig = git2::Signature::now("t", "t@t").unwrap();
        let tree_oid = repo.treebuilder(None).unwrap().write().unwrap();
        let tree = repo.find_tree(tree_oid).unwrap();
        repo.commit(Some("HEAD"), &sig, &sig, "init", &tree, &[])
            .unwrap();

        let wt = dir.path().join("wt");
        repo.worktree("wt", &wt, None).unwrap();

        let key = workspace_key(&wt);
        assert_ne!(
            key,
            canonicalize_or_owned(dir.path()),
            "bare-repo worktree key must not widen to the parent dir"
        );
        assert_eq!(
            key,
            canonicalize_or_owned(&wt),
            "bare-repo worktree falls back to its own dir (narrow, safe)"
        );
    }

    #[test]
    fn workspace_key_separate_gitdir_worktree_does_not_widen() {
        // `git init --separate-git-dir` leaves `core.worktree` unset
        // The common gitdir's INFERRED workdir is then the PARENT of the relocated gitdir, not the checkout
        // The layout guard (`<workdir>/.git` must equal the common gitdir) rejects that
        // The key falls back to the worktree's own dir, never widening to the gitdir's parent
        let dir = tempfile::tempdir().unwrap();
        let checkout = dir.path().join("checkout");
        let gitdir = dir.path().join("gitstore");
        std::fs::create_dir_all(&checkout).unwrap();
        let run = |args: &[&str], cwd: &std::path::Path| {
            std::process::Command::new("git")
                .args(args)
                .current_dir(cwd)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@t")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@t")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        };
        // If git isn't usable for this layout, skip rather than report a false failure
        if !run(
            &[
                "init",
                "--separate-git-dir",
                gitdir.to_str().unwrap(),
                checkout.to_str().unwrap(),
            ],
            dir.path(),
        ) || !run(&["commit", "--allow-empty", "-m", "init"], &checkout)
        {
            return;
        }
        let wt = dir.path().join("wt");
        if !run(&["worktree", "add", wt.to_str().unwrap()], &checkout) {
            return;
        }

        // Only assert once the worktree is a linked worktree whose common gitdir is the relocated separate gitdir (the layout this test targets)
        let Ok(repo) = git2::Repository::discover(&wt) else {
            return;
        };
        if !repo.is_worktree() {
            return;
        }

        let key = workspace_key(&wt);
        // The invariant: the key is NOT a broad ancestor of the checkout.
        assert_ne!(
            key,
            canonicalize_or_owned(dir.path()),
            "separate-gitdir worktree key must not widen to the gitdir's parent"
        );
        assert_eq!(
            key,
            canonicalize_or_owned(&wt),
            "separate-gitdir worktree falls back to its own dir (narrow, safe)"
        );
    }

    // ── workspace_key registry collapse (fuigo-managed worktrees) ─────────

    // The crate-shared env lock and env guards travel as ONE value
    // Struct field order (see lib.rs) restores the env before the lock releases, no matter how the caller binds the fixture's return
    use crate::LockedTestEnv;

    /// Point `FUIGO_HOME` at an isolated tempdir and register one fuigo-managed worktree at `<home>/worktrees/repo/<name>`.
    /// The record stores `source_repo` and `creation_mode`.
    /// The worktree dir is a PLAIN directory (NOT a git linked worktree), so only the registry can collapse it.
    /// Returns `(env, worktree dir)`.
    /// The [`LockedTestEnv`] holds the lock and restores `FUIGO_HOME` on drop (before releasing the lock), so the caller may bind it any way.
    fn register_fuigo_worktree(
        temp: &tempfile::TempDir,
        name: &str,
        source_repo: &Path,
        creation_mode: &str,
    ) -> (LockedTestEnv, PathBuf) {
        use fuigo_fast_worktree::{WorktreeDb, WorktreeKind, WorktreeRecord, WorktreeStatus};

        // Canonicalize so macOS's `/var` (a symlink to `/private/var`) agrees between the stored record path and the canonicalized lookup query
        let root = dunce::canonicalize(temp.path()).unwrap();
        let home = root.join("fuigo-home");
        let wt = home.join("worktrees").join("repo").join(name);
        std::fs::create_dir_all(&wt).unwrap();

        // Acquire the lock, then set the env under it (LockedTestEnv restores the env before releasing the lock on drop)
        let env = LockedTestEnv::lock().set("FUIGO_HOME", &home);

        let db = WorktreeDb::open(&home).unwrap();
        let record = WorktreeRecord {
            id: name.to_string(),
            path: wt.clone(),
            source_repo: source_repo.to_path_buf(),
            repo_name: "repo".to_string(),
            kind: WorktreeKind::Session,
            creation_mode: creation_mode.to_string(),
            git_ref: None,
            head_commit: None,
            session_id: None,
            creator_pid: None,
            created_at: 100,
            last_accessed_at: None,
            status: WorktreeStatus::Alive,
            metadata: None,
        };
        db.register(&record).unwrap();
        (env, wt)
    }

    #[test]
    fn workspace_key_collapses_standalone_fuigo_worktree_onto_source_repo() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        // A standalone worktree is a full clone with its OWN `.git`, so git topology can't link it to its source
        // The registry (worktrees.db) must collapse it onto the recorded source repo so trust is shared
        // The worktree dir is a plain dir (no git), proving the REGISTRY path (not git topology) does the collapse
        // `source_repo` is a real git repo (as in production), so the git-root normalization is deterministic regardless of where `$TMPDIR` lives
        let temp = tempfile::TempDir::new().unwrap();
        let root = dunce::canonicalize(temp.path()).unwrap();
        let source_repo = root.join("source-repo");
        std::fs::create_dir_all(&source_repo).unwrap();
        git2::Repository::init(&source_repo).unwrap();

        let (_env, wt) = register_fuigo_worktree(&temp, "wt", &source_repo, "standalone");

        let expected = canonicalize_or_owned(&source_repo);
        assert_eq!(
            workspace_key(&wt),
            expected,
            "a standalone fuigo worktree must collapse onto its recorded source repo"
        );
        // A cwd nested below the worktree root collapses onto the same key (the registry walk ascends to the registered worktree)
        let nested = wt.join("crates").join("inner");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(
            workspace_key(&nested),
            expected,
            "a nested cwd in the worktree collapses onto the same source repo"
        );
    }

    #[test]
    fn workspace_key_collapses_worktree_onto_source_repo_git_root() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        // The registry records `source_repo` as the launch cwd, which may be a SUBDIR of the repo
        // workspace_key must key on the repo's git ROOT, not on `<repo>/sub`
        // A worktree launched from a subdir then shares ONE key with the source and linked worktrees (which key on the root)
        let temp = tempfile::TempDir::new().unwrap();
        let root = dunce::canonicalize(temp.path()).unwrap();
        let repo = root.join("realrepo");
        std::fs::create_dir_all(&repo).unwrap();
        git2::Repository::init(&repo).unwrap();
        let subdir = repo.join("crates").join("sub");
        std::fs::create_dir_all(&subdir).unwrap();

        let (_env, wt) = register_fuigo_worktree(&temp, "wt", &subdir, "standalone");

        assert_eq!(
            workspace_key(&wt),
            canonicalize_or_owned(&repo),
            "source_repo recorded as a subdir must collapse onto the repo git root"
        );
    }

    #[test]
    fn workspace_key_ignores_registry_for_cwd_outside_worktrees_dir() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        // A populated registry must NOT collapse a cwd OUTSIDE `<fuigo_home>/worktrees`
        // `worktree_record_for_cwd` skips the registry there, so the key falls back to git/cwd
        // Non-vacuous: the registry IS populated with a real git source repo that WOULD be returned for a worktree cwd
        // `outside` is its OWN git repo (under fuigo HOME but not under its `worktrees/`), so the fallback is deterministic (no conditional skip)
        // We assert the key is `outside`'s own root, never the source repo
        let temp = tempfile::TempDir::new().unwrap();
        let root = dunce::canonicalize(temp.path()).unwrap();
        let source_repo = root.join("source-repo");
        std::fs::create_dir_all(&source_repo).unwrap();
        git2::Repository::init(&source_repo).unwrap();

        let (_env, _wt) = register_fuigo_worktree(&temp, "wt", &source_repo, "standalone");

        // Under fuigo HOME but NOT under `<home>/worktrees`, and its own git repo.
        let outside = root.join("fuigo-home").join("not-worktrees").join("proj");
        std::fs::create_dir_all(&outside).unwrap();
        git2::Repository::init(&outside).unwrap();

        let key = workspace_key(&outside);
        assert_eq!(
            key,
            canonicalize_or_owned(&outside),
            "a cwd outside <fuigo_home>/worktrees keys on its own repo root"
        );
        assert_ne!(
            key,
            canonicalize_or_owned(&source_repo),
            "it must not collapse onto the populated registry's source repo"
        );
    }

    // ── P167 (S8): an unreadable or corrupt store fails closed and is never rewritten from an empty document ──

    /// A store with the user's grants, then corrupted: a grant must fail and leave the bytes exactly as they were.
    /// Ported from upstream `corrupt_store_is_not_rewritten_by_set_trusted`.
    #[test]
    fn p167_corrupt_store_is_not_rewritten_by_set_trusted() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        std::fs::write(&store_path, b"[folders.\"/tmp/keep\"]\ntrusted = true\n[[[ not toml").unwrap();
        let before = std::fs::read(&store_path).unwrap();

        let mut store = TrustStore::load_from(store_path.clone());
        assert!(!store.is_trusted(Path::new("/tmp/keep")));
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        assert!(
            store.set_trusted(&repo).is_err(),
            "a grant over an unreadable store must fail, not write a one-entry store"
        );
        assert_eq!(
            std::fs::read(&store_path).unwrap(),
            before,
            "a failed parse must not shrink or replace the file"
        );
        assert!(!TrustStore::load_from(store_path).is_trusted(&repo));
    }

    /// The deny path is the same write: an untrust over a corrupt store must not replace it either.
    #[test]
    fn p167_corrupt_store_is_not_rewritten_by_set_untrusted() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        std::fs::write(&store_path, b"folders = not-a-table\n").unwrap();
        let before = std::fs::read(&store_path).unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();

        let mut store = TrustStore::load_from(store_path.clone());
        assert!(store.set_untrusted(&repo).is_err());
        assert_eq!(std::fs::read(&store_path).unwrap(), before);
    }

    /// A store that exists but cannot be read (here a dangling symlink, which `read_to_string` reports as NotFound) is
    /// not a missing file: the grant must fail and the link must survive, not be replaced by a fresh one-entry store.
    #[cfg(unix)]
    #[test]
    fn p167_dangling_symlink_store_is_unreadable_not_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        let target = tmp.path().join("moved-away.toml");
        std::os::unix::fs::symlink(&target, &store_path).unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();

        let mut store = TrustStore::load_from(store_path.clone());
        assert!(
            store.set_trusted(&repo).is_err(),
            "a dangling store link must not be treated as an absent file"
        );
        let meta = std::fs::symlink_metadata(&store_path).unwrap();
        assert!(meta.file_type().is_symlink(), "the store link must not be replaced");
        assert!(!target.exists(), "nothing may be written through the dangling link");
    }

    /// A relative home would put the store under the cwd (a cloned repo could ship it): no path at all.
    #[test]
    fn p167_default_path_in_rejects_relative_home() {
        assert_eq!(TrustStore::default_path_in(Some(PathBuf::from(".fuigo"))), None);
        assert_eq!(TrustStore::default_path_in(Some(PathBuf::from("repo/.fuigo"))), None);
        assert_eq!(TrustStore::default_path_in(Some(PathBuf::new())), None);
    }

    /// Ported from upstream: a corrupt store is not "no decision", so the legacy hook-trust file must not be consumed
    /// into a store that then gets rewritten from an empty stand-in.
    #[test]
    fn p167_migrate_legacy_hook_trust_does_not_consume_on_unreadable_store() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        std::fs::write(&store_path, b"[[[not toml").unwrap();
        let before = std::fs::read(&store_path).unwrap();
        let project = tmp.path().join("repo");
        std::fs::create_dir_all(&project).unwrap();
        let legacy = tmp.path().join("trusted-hook-projects");
        std::fs::write(&legacy, format!("{}\n", canonicalize_or_owned(&project).display())).unwrap();

        let mut store = TrustStore::load_from(store_path.clone());
        assert_eq!(migrate_legacy_hook_trust_in(&legacy, &mut store), 0);
        assert!(legacy.exists(), "an unread store must not consume the legacy file");
        assert_eq!(std::fs::read(&store_path).unwrap(), before, "the store must not be rewritten");
    }

    /// P180 (P167 Astra LOW): the read-failed-with-NotFound branch must re-probe before it says Missing. A regular file
    /// that is swapped for a dangling link between the probe and the read is an existing entry the store cannot read:
    /// an error, never an empty store that a write would replace.
    #[cfg(unix)]
    #[test]
    fn p180_read_swapped_for_dangling_link_after_probe_is_an_error_not_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        std::fs::write(&store_path, "[folders]\n").unwrap();
        let target = tmp.path().join("moved-away.toml");

        let swap_path = store_path.clone();
        let swap_target = target.clone();
        AFTER_PROBE.with(|a| {
            *a.borrow_mut() = Some(Box::new(move || {
                std::fs::remove_file(&swap_path).unwrap();
                std::os::unix::fs::symlink(&swap_target, &swap_path).unwrap();
            }));
        });
        let result = TrustStore::read_doc_strict(&store_path);
        AFTER_PROBE.with(|a| *a.borrow_mut() = None);

        assert!(
            result.is_err(),
            "a link that appeared after the probe is an existing entry, not Missing"
        );
        assert!(std::fs::symlink_metadata(&store_path).unwrap().file_type().is_symlink());
        assert!(!target.exists());
    }

    /// P182: the Windows variant of the dangling-link swap test. Creating a file symlink on Windows needs the
    /// symlink privilege (or Developer Mode); when the OS refuses (`PermissionDenied` or raw error 1314) the swap cannot be staged and
    /// the test says so and returns, any other error fails it.
    #[cfg(windows)]
    #[test]
    fn p182_read_swapped_for_dangling_link_after_probe_is_an_error_not_missing_windows() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        std::fs::write(&store_path, "[folders]\n").unwrap();
        let target = tmp.path().join("moved-away.toml");

        // Probe the privilege first, outside the seam, so a refusal never leaves the store half swapped.
        let probe_link = tmp.path().join("privilege-probe");
        match std::os::windows::fs::symlink_file(&target, &probe_link) {
            Ok(()) => std::fs::remove_file(&probe_link).unwrap(),
            // 1314 = ERROR_PRIVILEGE_NOT_HELD, which Rust 1.94 reports as `Uncategorized`, not `PermissionDenied`
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(1314) => {
                eprintln!("skipped: no symlink privilege on this Windows host: {e}");
                return;
            }
            Err(e) => panic!("unexpected symlink error: {e}"),
        }

        let swap_path = store_path.clone();
        let swap_target = target.clone();
        AFTER_PROBE.with(|a| {
            *a.borrow_mut() = Some(Box::new(move || {
                std::fs::remove_file(&swap_path).unwrap();
                std::os::windows::fs::symlink_file(&swap_target, &swap_path).unwrap();
            }));
        });
        let result = TrustStore::read_doc_strict(&store_path);
        AFTER_PROBE.with(|a| *a.borrow_mut() = None);

        assert!(
            result.is_err(),
            "a link that appeared after the probe is an existing entry, not Missing"
        );
        assert!(std::fs::symlink_metadata(&store_path).unwrap().file_type().is_symlink());
        assert!(!target.exists());
    }

    /// P180: and the same window with the entry simply gone is still Missing (the re-probe finds nothing).
    #[test]
    fn p180_read_removed_after_probe_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join(TRUST_FILE_NAME);
        std::fs::write(&store_path, "[folders]\n").unwrap();

        let gone = store_path.clone();
        AFTER_PROBE.with(|a| {
            *a.borrow_mut() = Some(Box::new(move || std::fs::remove_file(&gone).unwrap()));
        });
        let result = TrustStore::read_doc_strict(&store_path);
        AFTER_PROBE.with(|a| *a.borrow_mut() = None);

        assert!(matches!(result, Ok(StoreRead::Missing)), "removed entry must be Missing");
    }
}
