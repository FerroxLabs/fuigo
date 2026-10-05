//! Markdown-based memory file storage.
//!
//! Handles reading and writing memory files (`.md`) for both global and workspace-scoped memory.
//! All workspace-scoped memory lives under `~/.fuigo/memory/{project-slug}-{hash8}/` to avoid polluting the user's repo.

use std::path::{Path, PathBuf};

use fuigo_tools::util::fuigo_home::fuigo_home;

/// Write-operation scope. Distinct from `fuigo_agent::config::MemoryScope` (agent memory dir).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryScope {
    /// Global memory, shared across all workspaces.
    Global,
    /// Workspace-scoped memory, specific to one project.
    Workspace,
}

/// Handles file I/O for the memory storage layer.
///
/// Memory files are human-readable/editable Markdown stored under `~/.fuigo/memory/`.
/// Workspace-scoped files live under a directory named `{project-slug}-{hash8}`, e.g. `~/.fuigo/memory/fuigo-a3f7b2c9/`.
#[derive(Debug, Clone)]
pub struct MemoryStorage {
    /// `~/.fuigo/memory/`
    global_dir: PathBuf,
    /// `~/.fuigo/memory/{project-slug}-{hash8}/`
    workspace_dir: PathBuf,
    /// The original workspace path (for logging / diagnostics).
    workspace_path: PathBuf,
    /// When true, workspace writes are silently skipped (temp-dir CWDs).
    ephemeral: bool,
    global_enabled: bool,
    /// Legacy folders this start left in place, not yet shown to the user before (P97).
    legacy_notices: Vec<LegacyMemoryNotice>,
    /// Pre-P91 folder names this workspace could have (P124): see [`MemoryStorage::stranded_legacy_folders`].
    legacy_dirs: Vec<PathBuf>,
}

/// Why a pre-P91 `org/repo` memory folder was not moved to its host-qualified name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyMemoryOutcome {
    /// The folder was proven to belong to this host and was moved.
    Adopted,
    /// The folder cannot be shown to belong to this host and was left untouched.
    NotAdopted { reason: String },
    /// The folder was proven but the move itself failed; it was left in place.
    MoveFailed { error: String },
    /// The host-qualified folder already exists and an older version has since written notes under
    /// the legacy name again (a downgrade after the move, R110). The two are never merged here.
    Stranded,
}

/// A one-time notice about a legacy memory folder that was not adopted (P97), or that an older
/// version wrote again after the move (R110). Shown once per legacy folder: a marker file in the
/// memory root records that it was shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyMemoryNotice {
    pub legacy: PathBuf,
    pub new: PathBuf,
    pub outcome: LegacyMemoryOutcome,
}

impl LegacyMemoryNotice {
    /// The text shown to the user. Names both folders and points at the user guide.
    pub fn message(&self) -> String {
        let why = match &self.outcome {
            LegacyMemoryOutcome::Adopted => return String::new(),
            LegacyMemoryOutcome::NotAdopted { .. } => {
                "Fuigo could not show that it belongs to this repository's host, so it was not used"
            }
            LegacyMemoryOutcome::MoveFailed { .. } => "Fuigo could not move it, so it was not used",
            LegacyMemoryOutcome::Stranded => {
                return format!(
                    "Fuigo: found memory written by an older version of Fuigo at {}, after this \
                     repository's memory had moved to {}. Fuigo uses the new folder and did not \
                     merge the two. If the old notes are yours, move them into the new folder by \
                     hand (see the Memory page of the user guide). Nothing was deleted.",
                    self.legacy.display(),
                    self.new.display()
                );
            }
        };
        format!(
            "Fuigo: found memory from an older version at {}. {why}. \
             Memory for this repository now lives at {}. If the old memory is yours, move its \
             contents to the new folder by hand (see the Memory page of the user guide). \
             Nothing was deleted.",
            self.legacy.display(),
            self.new.display()
        )
    }
}

impl MemoryStorage {
    /// Create a new `MemoryStorage` rooted at `~/.fuigo/memory/`.
    ///
    /// The workspace directory name is `{slug}-{hash8}` where `slug` is the project directory name and `hash8` is 8 hex chars from blake3.
    /// Directories are created lazily on first write, not here.
    pub fn new(cwd: &Path, root_override: Option<&Path>) -> Self {
        Self::new_inner(cwd, root_override, true)
    }

    /// Create a MemoryStorage with a flat root (no workspace hash subdirectory).
    /// Used for project/local-scoped agent memory where the root is already project-specific.
    pub fn new_flat(cwd: &Path, root: &Path) -> Self {
        Self::new_inner(cwd, Some(root), false)
    }

    fn new_inner(cwd: &Path, root_override: Option<&Path>, use_workspace_hash: bool) -> Self {
        let global_dir = root_override
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| fuigo_home().join("memory"));
        let ephemeral = use_workspace_hash && is_ephemeral_cwd(cwd);
        let mut legacy_notices = Vec::new();
        let mut legacy_dirs = Vec::new();
        let workspace_dir = if use_workspace_hash {
            let identity = workspace_identity(cwd);
            let workspace_dir = global_dir.join(&identity.dir_name);
            // Not skipped for ephemeral cwds: adoption is proof-gated, and a temp
            // worktree of a proven clone may legitimately be the first to start.
            if let Some(remote) = &identity.remote {
                let candidates: Vec<PathBuf> = identity
                    .legacy_dir_names
                    .iter()
                    .map(|name| global_dir.join(name))
                    .collect();
                legacy_notices =
                    migrate_legacy_workspace_dirs(&global_dir, &candidates, &workspace_dir, remote);
                legacy_dirs = candidates;
                for notice in &legacy_notices {
                    fuigo_file_utils::destination_gate::announce_notice(&notice.message());
                }
            }
            workspace_dir
        } else {
            global_dir.clone()
        };

        Self {
            global_dir,
            workspace_dir,
            workspace_path: cwd.to_path_buf(),
            ephemeral,
            global_enabled: true,
            legacy_notices,
            legacy_dirs,
        }
    }

    /// Legacy memory folders this start left in place that the user has not yet been told
    /// about (empty on every later start). Each was already announced through the startup
    /// notice queue when this storage was created.
    pub fn legacy_notices(&self) -> &[LegacyMemoryNotice] {
        &self.legacy_notices
    }

    /// Legacy memory folders (the pre-P91 `org/repo` names of this workspace) that exist beside the
    /// workspace folder and hold notes (P124). They were left by an older version, or were never
    /// adopted; Fuigo reads and deletes none of them. `fuigo memory clear` names them as not cleared.
    /// Empty for a flat root, a repository without a remote, and for folders an older version only
    /// initialised (template, index files, write lock, empty `sessions/`).
    pub fn stranded_legacy_folders(&self) -> Vec<PathBuf> {
        self.legacy_dirs
            .iter()
            .filter(|legacy| {
                legacy.as_path() != self.workspace_dir
                    && legacy.symlink_metadata().is_ok_and(|meta| meta.is_dir())
                    && holds_notes(legacy)
            })
            .cloned()
            .collect()
    }

    /// The text `fuigo memory clear` prints about [`Self::stranded_legacy_folders`] (P124): the path
    /// of each folder, that it was not cleared, and how to remove it. `None` when there is none.
    pub fn stranded_legacy_clear_notice(&self) -> Option<String> {
        let folders = self.stranded_legacy_folders();
        if folders.is_empty() {
            return None;
        }
        let mut text = String::from(
            "Not cleared: memory written by an older version of Fuigo is still on disk. \
             Fuigo does not read or delete it, so `fuigo memory clear` leaves it alone:",
        );
        for folder in &folders {
            text.push_str(&format!("\n  {}", folder.display()));
        }
        text.push_str(
            "\nIf you do not want those notes, remove the folder yourself (for example with rm -r \
             on the path above). Memory for this repository now lives at ",
        );
        text.push_str(&self.workspace_dir.display().to_string());
        text.push('.');
        Some(text)
    }

    /// Create a `MemoryStorage` with explicit paths (for testing).
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_paths(global_dir: PathBuf, workspace_dir: PathBuf) -> Self {
        Self {
            global_dir,
            workspace_dir,
            workspace_path: PathBuf::from("/test/workspace"),
            ephemeral: false,
            global_enabled: true,
            legacy_notices: Vec::new(),
            legacy_dirs: Vec::new(),
        }
    }

    pub fn global_dir(&self) -> &Path {
        &self.global_dir
    }

    /// Session policy for deliberate cross-project sharing. Raw storage callers
    /// retain their existing behavior until they supply a policy.
    pub fn with_global_enabled(mut self, enabled: bool) -> Self {
        self.global_enabled = enabled;
        self
    }

    pub fn global_enabled(&self) -> bool {
        self.global_enabled
    }

    pub fn workspace_dir(&self) -> &Path {
        &self.workspace_dir
    }

    /// Returns the original workspace path.
    pub fn workspace_path(&self) -> &Path {
        &self.workspace_path
    }

    /// Returns `true` if this storage targets an ephemeral (temp-dir) workspace.
    pub fn is_ephemeral(&self) -> bool {
        self.ephemeral
    }

    /// Count total indexed chunks via a read-only SQLite connection.
    /// Returns 0 if the index doesn't exist or the query fails.
    pub fn total_chunk_count(&self) -> usize {
        let db_path = self.workspace_dir.join("index.sqlite");
        // Journal-mode-aware open: never mmap a legacy WAL -shm on network mounts (SIGBUS); see fuigo_sqlite_journal::JournalMode::open_readonly
        fuigo_sqlite_journal::JournalMode::for_db_path(&db_path)
            .open_readonly(&db_path)
            .and_then(|c| c.query_row("SELECT COUNT(*) FROM chunks", [], |r| r.get::<_, i64>(0)))
            .unwrap_or(0) as usize
    }

    /// Path to the global `MEMORY.md`.
    pub fn global_memory_file(&self) -> PathBuf {
        self.global_dir.join("MEMORY.md")
    }

    /// Path to the workspace-scoped `MEMORY.md`.
    pub fn workspace_memory_file(&self) -> PathBuf {
        self.workspace_dir.join("MEMORY.md")
    }

    /// Only this workspace and the explicit global MEMORY.md are readable.
    /// Canonical checks reject sibling workspaces and symlink escapes.
    pub fn allows_path(&self, path: &Path) -> bool {
        let Ok(path) = dunce::canonicalize(path) else {
            return false;
        };
        let global = (!self
            .global_memory_file()
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink()))
        .then(|| dunce::canonicalize(self.global_memory_file()).ok())
        .flatten();
        let workspace = (!self
            .workspace_dir
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink()))
        .then(|| dunce::canonicalize(&self.workspace_dir).ok())
        .flatten();
        (self.global_enabled && global.as_ref() == Some(&path))
            || workspace.is_some_and(|root| {
                path.strip_prefix(root).is_ok_and(|relative| {
                    !relative
                        .components()
                        .any(|c| c.as_os_str().to_string_lossy().starts_with('.'))
                }) && path.extension().is_some_and(|ext| ext == "md")
            })
    }

    pub fn classify_source(&self, path: &Path) -> &'static str {
        if !self.allows_path(path) {
            return "denied";
        }
        if path == self.workspace_memory_file() {
            "workspace"
        } else if path == self.global_memory_file() {
            "global"
        } else {
            "session"
        }
    }

    /// Stable suffix for the whole ID; unlike a UUID prefix it includes random bits.
    pub fn session_suffix(session_id: &str) -> String {
        blake3::hash(session_id.as_bytes()).to_hex()[..32].to_owned()
    }

    /// Path to the workspace sessions directory.
    pub fn sessions_dir(&self) -> PathBuf {
        self.workspace_dir.join("sessions")
    }

    /// Write a daily session log file.
    ///
    /// File path: `~/.fuigo/memory/{project}-{hash8}/sessions/YYYY-MM-DD-{slug}-{sid8}.md`
    ///
    /// - `date`: e.g. `"2026-02-23"`
    /// - `slug`: short slug derived from the first user message
    /// - `session_id`: full session ID (hash of the full ID used as suffix)
    /// - `append`: when `true`, appends a timestamped section instead of overwriting.
    ///   Each section is separated by `---` and a timestamp header so the chunker treats them as distinct entries.
    pub fn write_daily_log(
        &self,
        date: &str,
        slug: &str,
        session_id: &str,
        content: &str,
        append: bool,
    ) -> std::io::Result<PathBuf> {
        let sessions_dir = self.sessions_dir();
        let sid8 = Self::session_suffix(session_id);
        let safe = |s: &str| {
            s.chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect::<String>()
        };
        let date = safe(date);
        let slug = safe(slug);
        let filename = format!("{date}-{slug}-{sid8}.md");
        let path = sessions_dir.join(&filename);

        if self.ephemeral {
            tracing::debug!(path = %path.display(), "MEMORY_EPHEMERAL_SKIP: daily log write skipped");
            return Ok(path);
        }

        validate_entry(content)?;
        update_file(&path, |old| {
            if append && !old.is_empty() {
                let timestamp = chrono::Utc::now().format("%H:%M:%S UTC");
                format!("{old}\n\n---\n\n<!-- flush {timestamp} -->\n\n{content}")
            } else {
                content.to_owned()
            }
        })?;
        tracing::debug!(path = %path.display(), append, "wrote daily session log");

        Ok(path)
    }

    /// Write the curated long-term `MEMORY.md` for the given scope.
    ///
    /// Creates parent directories as needed. Overwrites any existing content.
    pub fn write_long_term(&self, scope: MemoryScope, content: &str) -> std::io::Result<()> {
        if scope == MemoryScope::Global && !self.global_enabled {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "global memory is disabled; set memory.global_enabled = true to share"));
        }
        if self.ephemeral && scope == MemoryScope::Workspace {
            tracing::debug!("MEMORY_EPHEMERAL_SKIP: workspace long-term write skipped");
            return Ok(());
        }

        let path = match scope {
            MemoryScope::Global => {
                std::fs::create_dir_all(&self.global_dir)?;
                self.global_memory_file()
            }
            MemoryScope::Workspace => {
                std::fs::create_dir_all(&self.workspace_dir)?;
                self.workspace_memory_file()
            }
        };

        validate_entry(content)?;
        update_file(&path, |_| content.to_owned())?;
        tracing::debug!(path = %path.display(), scope = ?scope, "wrote long-term memory");

        Ok(())
    }

    /// Replace the exact dream input while holding the same OS lock as other memory writers.
    /// A private durable recovery version is kept before replacing any prior content.
    pub fn replace_dream_memory(&self, expected: &str, content: &str) -> std::io::Result<()> {
        if self.ephemeral {
            return Err(std::io::Error::other("ephemeral workspace"));
        }
        validate_entry(content)?;
        let path = self.workspace_memory_file();
        update_file_checked(&path, |old| {
            if old != expected {
                return Err(std::io::Error::other(
                    "MEMORY.md changed during consolidation; retry with current input",
                ));
            }
            if !old.is_empty() {
                use std::io::Write;
                let recovery = self.workspace_dir.join(".memory-recovery");
                std::fs::create_dir_all(&recovery)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&recovery, std::fs::Permissions::from_mode(0o700))?;
                }
                let mut backup = tempfile::NamedTempFile::new_in(&recovery)?;
                backup.write_all(old.as_bytes())?;
                backup.as_file().sync_all()?;
                backup.keep().map_err(|e| e.error)?;
                #[cfg(unix)]
                std::fs::File::open(&recovery)?.sync_all()?;
            }
            Ok(content.to_owned())
        })
    }

    /// Append content to the `MEMORY.md` for the given scope.
    ///
    /// The content is normalized via [`normalize_memory_content`], then appended with a blank-line separator from existing content.
    /// Creates parent directories and the file if they don't exist.
    /// Empty/whitespace-only content is silently ignored.
    pub fn append_to_memory(&self, scope: MemoryScope, content: &str) -> std::io::Result<()> {
        if scope == MemoryScope::Global && !self.global_enabled {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "global memory is disabled; set memory.global_enabled = true to share"));
        }
        if self.ephemeral && scope == MemoryScope::Workspace {
            tracing::debug!("MEMORY_EPHEMERAL_SKIP: workspace memory append skipped");
            return Ok(());
        }

        validate_entry(content)?;
        let normalized = normalize_memory_content(content);
        if normalized.is_empty() {
            return Ok(());
        }

        let path = match scope {
            MemoryScope::Global => {
                std::fs::create_dir_all(&self.global_dir)?;
                self.global_memory_file()
            }
            MemoryScope::Workspace => {
                std::fs::create_dir_all(&self.workspace_dir)?;
                self.workspace_memory_file()
            }
        };

        update_file(&path, |old| {
            if old.is_empty() {
                normalized.clone()
            } else {
                format!("{old}\n\n{normalized}")
            }
        })?;

        tracing::debug!(path = %path.display(), scope = ?scope, "appended to memory");
        Ok(())
    }

    /// Read a memory file, optionally returning only a range of lines.
    ///
    /// Rejected lines are blanked before selecting a range; original line offsets remain valid.
    ///
    /// - `from`: 0-based start line (default 0)
    /// - `lines`: max number of lines to return (default: all)
    ///
    /// The path must resolve (via `canonicalize`) to a location inside the memory directory tree.
    /// Both the path and the memory root must be canonicalizable; if either fails, the read is rejected.
    pub fn read_file(
        &self,
        path: &Path,
        from: Option<usize>,
        lines: Option<usize>,
    ) -> std::io::Result<String> {
        // Security: canonicalize both sides; fail hard if either doesn't exist
        let canonical = dunce::canonicalize(path)?;
        if !self.allows_path(&canonical) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "memory path is outside this workspace and global MEMORY.md",
            ));
        }

        // Read the canonicalized path, not the original, to prevent TOCTOU races.
        let content = crate::safety::filter_memory_lines(&std::fs::read_to_string(&canonical)?);

        let from = from.unwrap_or(0);
        match lines {
            Some(count) => {
                let selected: Vec<&str> = content.lines().skip(from).take(count).collect();
                Ok(selected.join("\n"))
            }
            None if from > 0 => {
                let selected: Vec<&str> = content.lines().skip(from).collect();
                Ok(selected.join("\n"))
            }
            None => Ok(content),
        }
    }

    /// List all memory files (`.md`) across global and workspace directories.
    ///
    /// Returns paths sorted by scope: global files first, then workspace files.
    pub fn list_memory_files(&self) -> std::io::Result<Vec<PathBuf>> {
        let mut files = Vec::new();

        // Global MEMORY.md
        let global_file = self.global_memory_file();
        if self.global_enabled && global_file.is_file() {
            files.push(global_file);
        }

        // Workspace MEMORY.md
        let workspace_file = self.workspace_memory_file();
        if workspace_file.is_file() {
            files.push(workspace_file);
        }

        // Workspace session logs
        let sessions_dir = self.sessions_dir();
        if sessions_dir.is_dir() {
            let mut session_files: Vec<PathBuf> = std::fs::read_dir(&sessions_dir)?
                .filter_map(|entry| {
                    let entry = entry.ok()?;
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) == Some("md") {
                        Some(path)
                    } else {
                        None
                    }
                })
                .collect();
            // Sort session logs by name (date-based, so chronological order).
            session_files.sort();
            files.extend(session_files);
        }

        files.retain(|p| self.allows_path(p));
        files.dedup();
        Ok(files)
    }

    /// Ensure the global memory directory exists and create a template `MEMORY.md` if one doesn't already exist.
    ///
    /// Called on first run with memory enabled to bootstrap the layout.
    pub fn ensure_initialized(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.global_dir)?;

        let global_file = self.global_memory_file();
        if self.global_enabled && !global_file.exists() {
            initialize_file(
                &global_file,
                "# Global Memory\n\
                 \n\
                 > This file is automatically managed by Fuigo's memory system.\n\
                 > You can also edit it manually — changes will be indexed on next session.\n\
                 \n\
                 ## Preferences\n\
                 \n\
                 <!-- Add any cross-project preferences here -->\n",
            )?;
            tracing::info!(path = %global_file.display(), "created global MEMORY.md template");
        }

        if self.ephemeral {
            tracing::debug!("MEMORY_EPHEMERAL_SKIP: workspace initialization skipped");
            return Ok(());
        }

        std::fs::create_dir_all(&self.workspace_dir)?;

        let workspace_file = self.workspace_memory_file();
        if !workspace_file.exists() {
            initialize_file(
                &workspace_file,
                format!(
                    "# Project Memory — {}\n\
                     \n\
                     > Auto-populated by dream consolidation. Edit freely.\n",
                    self.workspace_path.display()
                ),
            )?;
            tracing::info!(
                path = %workspace_file.display(),
                workspace = %self.workspace_path.display(),
                "created workspace MEMORY.md template"
            );
        }

        Ok(())
    }

    fn generation_path(&self) -> PathBuf {
        let identity = blake3::hash(self.global_dir.to_string_lossy().as_bytes()).to_hex();
        self.global_dir
            .parent()
            .unwrap_or(&self.global_dir)
            .join(".fuigo-memory-generations")
            .join(format!("{identity}.json"))
    }

    fn lock_generation(&self) -> std::io::Result<std::fs::File> {
        let path = self.generation_path();
        let parent = path.parent().unwrap();
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(path.with_extension("lock"))?;
        file.lock()?;
        Ok(file)
    }

    fn generations(&self) -> std::io::Result<std::collections::BTreeMap<String, u64>> {
        match std::fs::read_to_string(self.generation_path()) {
            Ok(text) => serde_json::from_str(&text).map_err(std::io::Error::other),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Default::default()),
            Err(e) => Err(e),
        }
    }

    fn workspace_generation_key(&self) -> String {
        blake3::hash(self.workspace_dir.to_string_lossy().as_bytes())
            .to_hex()
            .to_string()
    }

    fn read_generation(&self) -> std::io::Result<(u64, u64)> {
        let generations = self.generations()?;
        Ok((
            *generations.get("global").unwrap_or(&0),
            *generations
                .get(&self.workspace_generation_key())
                .unwrap_or(&0),
        ))
    }

    /// Snapshot before model inference. The epoch survives clearing the memory directory.
    pub fn generation(&self) -> std::io::Result<(u64, u64)> {
        let _lock = self.lock_generation()?;
        self.read_generation()
    }

    /// Clear and model-produced writes share this stable OS lock. A clear invalidates
    /// old snapshots without disabling new captures started afterward.
    pub fn with_generation<T>(
        &self,
        expected: (u64, u64),
        operation: impl FnOnce() -> std::io::Result<T>,
    ) -> std::io::Result<T> {
        let _lock = self.lock_generation()?;
        if self.read_generation()? != expected {
            return Err(std::io::Error::other(
                "memory cleared during inference; stale result discarded",
            ));
        }
        operation()
    }

    fn bump_generation(&self, key: String) -> std::io::Result<()> {
        let mut generations = self.generations()?;
        let epoch = generations.entry(key).or_default();
        *epoch = epoch
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("memory generation overflow"))?;
        let text = serde_json::to_string(&generations).map_err(std::io::Error::other)?;
        update_file(&self.generation_path(), |_| text)
    }

    /// Remove the entire workspace-scoped memory directory.
    ///
    /// Deletes MEMORY.md, sessions/, index.sqlite, and any other workspace files.
    /// The directory will be recreated on next session start via `ensure_initialized()`.
    /// Returns `Ok(true)` if the directory existed and was removed, `Ok(false)` if it didn't exist.
    pub fn clear_workspace(&self) -> std::io::Result<bool> {
        let _lock = self.lock_generation()?;
        self.bump_generation(self.workspace_generation_key())?;
        match std::fs::remove_dir_all(&self.workspace_dir) {
            Ok(()) => {
                tracing::info!(path = %self.workspace_dir.display(), "cleared workspace memory");
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Remove the global MEMORY.md file.
    ///
    /// Does not remove the global memory directory itself (other workspaces may have subdirectories there).
    /// The file will be recreated on next session start via `ensure_initialized()`.
    /// Returns `Ok(true)` if the file existed and was removed, `Ok(false)` if it didn't exist.
    pub fn clear_global(&self) -> std::io::Result<bool> {
        let _lock = self.lock_generation()?;
        self.bump_generation("global".into())?;
        let path = self.global_memory_file();
        match std::fs::remove_file(&path) {
            Ok(()) => {
                tracing::info!(path = %path.display(), "cleared global memory");
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Remove orphaned workspace directories under the memory root.
    ///
    /// Only genuinely empty directories qualify; retained memory, logs, recovery
    /// versions and other workspace data always prevent deletion. Empty temporary
    /// directories qualify immediately; other empty directories must meet the age gate.
    ///
    /// Returns the number of directories removed.
    pub fn gc(&self, max_age_days: u64) -> std::io::Result<usize> {
        let entries = match std::fs::read_dir(&self.global_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };

        let mut removed = 0usize;
        for entry in entries.flatten() {
            let path = entry.path();
            if !entry.file_type()?.is_dir() {
                continue;
            }
            if path == self.workspace_dir {
                continue;
            }

            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };

            let is_tmp = name.starts_with("tmp");
            let empty = is_empty_workspace(&path);

            let should_remove = if is_tmp {
                empty
            } else {
                empty && is_older_than(&path, max_age_days)
            };

            if should_remove {
                match std::fs::remove_dir(&path) {
                    Ok(()) => {
                        tracing::debug!(
                            path = %path.display(),
                            is_tmp,
                            empty,
                            "MEMORY_GC: removed orphaned workspace directory"
                        );
                        removed += 1;
                    }
                    Err(e) => {
                        tracing::debug!(
                            path = %path.display(),
                            error = %e,
                            "MEMORY_GC: failed to remove workspace directory"
                        );
                    }
                }
            }
        }

        Ok(removed)
    }
}

/// Never infer emptiness from absence of session files or follow links during GC.
fn is_empty_workspace(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_none())
}

fn validate_entry(content: &str) -> std::io::Result<()> {
    if !crate::safety::is_safe_memory(content) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "new memory entry rejected: credential material or instruction override detected",
        ));
    }
    Ok(())
}

/// Serialize read-modify-replace across threads/processes. A crash before rename
/// leaves the original intact; the OS releases the stable sidecar lock on exit.
pub(crate) fn update_file(path: &Path, update: impl FnOnce(&str) -> String) -> std::io::Result<()> {
    update_file_checked(path, |old| Ok(update(old)))
}

fn update_file_checked(
    path: &Path,
    update: impl FnOnce(&str) -> std::io::Result<String>,
) -> std::io::Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("missing parent"))?;
    std::fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let lock = options.open(parent.join(".memory-write.lock"))?;
    lock.lock()?;
    if path
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "memory write symlink",
        ));
    }
    let old = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    let content = update(&old)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(content.as_bytes())?;
    temp.as_file().sync_all()?;
    // Detect edits by non-cooperating editors made while preparing the replacement.
    let current = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    if current != old {
        return Err(std::io::Error::other(
            "memory changed before atomic replacement",
        ));
    }
    temp.persist(path).map_err(|e| e.error)?;
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

/// Returns `true` if `dir`'s mtime is older than `days` days ago.
fn is_older_than(dir: &Path, days: u64) -> bool {
    let Ok(metadata) = dir.metadata() else {
        return false;
    };
    let Ok(modified) = metadata.modified() else {
        return false;
    };
    let age = modified.elapsed().unwrap_or(std::time::Duration::ZERO);
    age > std::time::Duration::from_secs(days * 24 * 60 * 60)
}

/// Ensure content has proper Markdown heading structure for the memory chunker.
///
/// The chunker splits on `## ` boundaries, and the search pipeline uses headings for section-level ranking.
/// Raw text without headings produces low-quality chunks.
///
/// **Rules:**
/// 1. Content that already starts with `#` is left as-is (user-provided structure).
/// 2. Single-line content becomes `## {content}` (the note IS the heading).
/// 3. Multi-line with a first line of 80 chars or fewer: the first line becomes `## {first_line}`, the rest becomes the body paragraph.
/// 4. Multi-line with a longer first line: the heading is a generic `## Note` and the entire content becomes the body.
pub fn normalize_memory_content(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // Already has a Markdown heading, so preserve the user's structure
    if trimmed.starts_with('#') {
        return trimmed.to_string();
    }

    match trimmed.find('\n') {
        // Single-line: the note IS the heading
        None => format!("## {trimmed}"),

        // Multi-line: promote the first line to a heading if it's short enough
        Some(pos) => {
            let first_line = trimmed[..pos].trim();
            let rest = trimmed[pos..].trim();

            if first_line.len() <= 80 {
                format!("## {first_line}\n\n{rest}")
            } else {
                format!("## Note\n\n{trimmed}")
            }
        }
    }
}

/// Returns `true` if `cwd` resides under a system temp directory.
///
/// Subagent worktrees and other transient processes use temp-dir paths like `/tmp/…` or `/var/folders/…/T/…`.
/// Creating persistent workspace memory for these paths is wasteful and produces orphan directories.
fn is_ephemeral_cwd(cwd: &Path) -> bool {
    let canonical = dunce::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let s = canonical.to_string_lossy();
    let raw_s = cwd.to_string_lossy();

    let temp = std::env::temp_dir();
    let temp_canonical = dunce::canonicalize(&temp).unwrap_or(temp);

    canonical.starts_with(&temp_canonical)
        || raw_s.starts_with("/tmp/")
        || raw_s.starts_with("/var/tmp/")
        || (raw_s.contains("/var/folders/") && raw_s.contains("/T/"))
        || s.starts_with("/private/tmp/")
        || s.starts_with("/private/var/tmp/")
        || (s.contains("/private/var/folders/") && s.contains("/T/"))
}

/// Where a workspace's memory lives, and the pre-P91 name it may have used.
struct WorkspaceIdentity {
    /// `{slug}-{hash16}` for a remote identity, `{slug}-{hash8}` for a path identity.
    dir_name: String,
    /// Host-qualified remote identity (`host/org/repo`), when the directory is a
    /// Git repository with a usable `origin` remote.
    remote: Option<String>,
    /// `{slug}-{hash8(org/repo)}`: the host-less names this repository may have
    /// used before P91 (`org/repo`, and `org/repo.git` from an origin ending in
    /// `.git/`). Only for remote identities; path identities did not change.
    legacy_dir_names: Vec<String>,
}

/// Hex digits of the blake3 hash in a REMOTE identity's directory name. 64 bits:
/// a remote host is attacker-choosable, so a 32-bit suffix could be ground to
/// collide with a victim's `host/org/repo` (Astra P91 r1 #4). Path identities and
/// the pre-P91 names keep 8.
const REMOTE_HASH_HEX: usize = 16;
const PATH_HASH_HEX: usize = 8;

fn dir_name(slug: &str, hash_input: &str, hex: usize) -> String {
    let slug = if slug.is_empty() { "workspace" } else { slug };
    let hash = blake3::hash(hash_input.as_bytes());
    format!("{slug}-{}", &hash.to_hex()[..hex])
}

/// Compute a human-friendly workspace directory name.
///
/// Format: `{slug}-{hash}` where:
/// - `slug` is the repo or directory name, slugified (max 40 chars)
/// - `hash` is hex from blake3 of the identity: 16 chars for a remote identity, 8 for a path identity
///
/// **Identity strategy:** the git `origin` remote as `host/org/repo` is preferred, so every clone, worktree, and
/// copy of a repository from the SAME host shares one memory directory (ssh, https and `.git` forms of one host
/// map together). A remote with the same `org/repo` on a different host never shares it.
/// It falls back to the filesystem path when not inside a git repo or when no `origin` remote is configured.
#[cfg(test)]
fn compute_workspace_hash(cwd: &Path) -> String {
    workspace_identity(cwd).dir_name
}

fn workspace_identity(cwd: &Path) -> WorkspaceIdentity {
    if let Some(remote) = extract_repo_identity(cwd) {
        let slug = slugify(remote.rsplit('/').next().unwrap_or(&remote), 40);
        // Every URL form that maps to this identity had one of two pre-P91 keys:
        // `org/repo`, or `org/repo.git` for an origin ending in `.git/` (whose slug
        // was `repo-git`). Both are candidates, so equivalent clones agree on them.
        let path = remote.split_once('/').map_or(remote.as_str(), |(_, path)| path);
        let legacy_dir_names = [path.to_owned(), format!("{path}.git")]
            .iter()
            .map(|legacy| {
                let legacy_slug = slugify(legacy.rsplit('/').next().unwrap_or(legacy), 40);
                dir_name(&legacy_slug, legacy, PATH_HASH_HEX)
            })
            .collect();
        return WorkspaceIdentity {
            dir_name: dir_name(&slug, &remote, REMOTE_HASH_HEX),
            legacy_dir_names,
            remote: Some(remote),
        };
    }
    // Windows-only, non-git cwds: dunce changes the hash input, so the old-form dir is orphaned until gc() reaps it after max_age_days
    // That orphan is accepted over an unverifiable rename migration (Unix unchanged)
    let canonical = dunce::canonicalize(cwd).unwrap_or_else(|_| {
        tracing::warn!(
            path = %cwd.display(),
            "could not canonicalize workspace path for memory hash; using raw path"
        );
        cwd.to_path_buf()
    });
    let dir = canonical
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("workspace");
    WorkspaceIdentity {
        dir_name: dir_name(&slugify(dir, 40), &canonical.to_string_lossy(), PATH_HASH_HEX),
        remote: None,
        legacy_dir_names: Vec::new(),
    }
}

/// Extract the normalized `host/org/repo` identifier from the git remote URL.
///
/// Uses `git2` to discover the repository from `cwd` and read the `origin` remote URL.
/// Returns `None` if not a git repo, no `origin` remote, or the URL can't be normalized.
pub(crate) fn extract_repo_identity(cwd: &Path) -> Option<String> {
    let repo = git2::Repository::discover(cwd).ok()?;
    let remote = repo.find_remote("origin").ok()?;
    normalize_remote_url(remote.url()?)
}

/// Split a git remote URL into `(host, path)`.
///
/// Scheme (`https`, `ssh`, `git`, ...), user info and port are dropped and the host is lowercased, so
/// `git@github.com:acme/widgets.git`, `ssh://git@github.com:22/acme/widgets` and
/// `https://github.com/acme/widgets` all give `("github.com", "acme/widgets.git"/...)`.
/// `file://` URLs give an empty host. Anything that is not a URL or scp-like `user@host:path` gives `None`.
fn split_remote_url(url: &str) -> Option<(String, &str)> {
    let url = url.trim();
    let (authority, path) = if let Some((scheme, rest)) = url.split_once("://") {
        if scheme.is_empty()
            || !scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            return None;
        }
        rest.split_once('/')?
    } else {
        // scp-like: user@host:path (the `@` keeps Windows drive paths like C:\x out)
        let colon = url.find(':')?;
        if !url[..colon].contains('@') || url[..colon].contains('/') {
            return None;
        }
        (&url[..colon], &url[colon + 1..])
    };
    let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    let host = if let Some(bracketed) = host.strip_prefix('[') {
        // IPv6 literal, optionally followed by :port
        bracketed.split_once(']').map_or(bracketed, |(ip, _)| ip)
    } else {
        host.split(':').next().unwrap_or(host)
    };
    Some((host.trim_end_matches('.').to_ascii_lowercase(), path))
}

/// `org/repo` from a remote URL path. A trailing `/` is dropped before `.git`, so
/// `…/repo.git/` and `…/repo` are the same identity (pre-P91 code kept the `.git`
/// in that case; see `WorkspaceIdentity::legacy_dir_names`).
fn clean_remote_path(path: &str) -> Option<&str> {
    let cleaned = path
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .trim_end_matches('/')
        .trim_start_matches('/');
    (!cleaned.is_empty() && cleaned.contains('/')).then_some(cleaned)
}

/// Normalize a git remote URL to `host/org/repo` form.
///
/// - `git@github.com:acme/widgets.git`       → `"github.com/acme/widgets"`
/// - `https://github.com/acme/widgets.git`   → `"github.com/acme/widgets"`
/// - `ssh://git@github.com/acme/widgets`     → `"github.com/acme/widgets"`
/// - `https://evil.example/acme/widgets`     → `"evil.example/acme/widgets"` (a different identity)
fn normalize_remote_url(url: &str) -> Option<String> {
    let (host, path) = split_remote_url(url)?;
    Some(format!("{host}/{}", clean_remote_path(path)?))
}


/// Bounds on the evidence read from a legacy directory, so startup stays cheap.
/// Evidence beyond them is not skipped: it makes ownership unprovable.
const LEGACY_EVIDENCE_MAX_FILES: usize = 4096;
const LEGACY_EVIDENCE_MAX_BYTES: u64 = 8 << 20;

/// Workspace paths recorded inside a legacy memory directory: the path in the
/// `# Project Memory — <path>` header that [`MemoryStorage::ensure_initialized`]
/// writes, and the `workspace` field of every captured-claim provenance comment.
/// `None` when the evidence could not be read COMPLETELY (too many or too large
/// files, a symlink or other non-file entry, an unreadable file, an unparsable
/// provenance record): a partial read could hide another host's record, so the
/// caller must then treat ownership as unproven (Astra P91 r1 #2).
fn recorded_workspace_paths(legacy_dir: &Path) -> Option<std::collections::BTreeSet<PathBuf>> {
    const HEADER: &str = "# Project Memory — ";
    const PROVENANCE: &str = "<!-- fuigo-memory-provenance ";
    let mut files = Vec::new();
    match legacy_dir.join("MEMORY.md").symlink_metadata() {
        Ok(_) => files.push(legacy_dir.join("MEMORY.md")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return None,
    }
    match std::fs::read_dir(legacy_dir.join("sessions")) {
        Ok(entries) => {
            for entry in entries {
                let path = entry.ok()?.path();
                if path.extension().is_some_and(|ext| ext == "md") {
                    files.push(path);
                }
                if files.len() > LEGACY_EVIDENCE_MAX_FILES {
                    return None;
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return None,
    }
    let mut paths = std::collections::BTreeSet::new();
    for file in files {
        let meta = file.symlink_metadata().ok()?;
        if !meta.is_file() || meta.len() > LEGACY_EVIDENCE_MAX_BYTES {
            return None;
        }
        let text = std::fs::read_to_string(&file).ok()?;
        if let Some(path) = text.lines().next().and_then(|line| line.strip_prefix(HEADER)) {
            paths.insert(PathBuf::from(path.trim()));
        }
        for comment in text.split(PROVENANCE).skip(1) {
            let (json, _) = comment.split_once(" -->")?;
            // Every record must name its workspace: a record that does not is
            // evidence we cannot read, not evidence we may ignore (Astra P91 r2 #3).
            let value = serde_json::from_str::<serde_json::Value>(json).ok()?;
            paths.insert(PathBuf::from(value.get("workspace")?.as_str()?));
        }
    }
    Some(paths)
}

/// SQLite index files of a memory directory: `index.sqlite` and the per-host
/// network-mode sibling `index.h-<host>.sqlite`, each with its `-wal`, `-shm`
/// and `-journal` sidecars. Exact names only, so no user note is ever matched.
fn is_index_file(name: &str) -> bool {
    let base = ["-wal", "-shm", "-journal"]
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix))
        .unwrap_or(name);
    base == "index.sqlite"
        || base
            .strip_prefix("index.h-")
            .and_then(|rest| rest.strip_suffix(".sqlite"))
            .is_some_and(|host| !host.is_empty() && !host.contains(['/', '\\']))
}

/// Move a pre-P91 memory directory (keyed by `org/repo` only, host dropped) to the
/// host-qualified name, but only when that is provably the same project.
///
/// The legacy directory did not record the remote host, so it could have been
/// filled by a clone of `org/repo` from ANY host, including a hostile one. It is
/// adopted only when (a) its evidence could be read completely, (b) at least one
/// workspace path recorded inside it still exists on this machine and its `origin`
/// now has exactly the current `host/org/repo` identity, and (c) no recorded path
/// that still exists resolves to a different identity. Otherwise it is left
/// untouched (nothing is deleted) and a warning names both directories, so the
/// user can move it by hand if it is theirs.
///
/// The search index inside holds absolute paths to the old location, so before the
/// directory is published under its new name its index files are moved aside into a
/// fresh `.pre-p91-index-<pid>-<time>/` (a dot directory, never read by memory tools);
/// a session that opens the new directory therefore never meets an index that is
/// about to change. Migrations are serialised by `.memory-migrate.lock` in the root.
fn migrate_legacy_workspace_dirs(
    root: &Path,
    candidates: &[PathBuf],
    workspace_dir: &Path,
    identity: &str,
) -> Vec<LegacyMemoryNotice> {
    let is_dir = |path: &Path| path.symlink_metadata().is_ok_and(|meta| meta.is_dir());
    let published = || workspace_dir.symlink_metadata().is_ok();
    let mut notices = Vec::new();
    // A legacy folder that is gone (merged by hand, or never recreated) is news again if it ever
    // reappears: forget that it was announced. Done before any early return, so it also happens
    // when the new folder is absent too (Astra P110 r1 #4).
    for legacy in candidates {
        if legacy.as_path() != workspace_dir && !is_dir(legacy) {
            let _ = std::fs::remove_file(stranded_marker(root, legacy, workspace_dir));
            let _ = std::fs::remove_file(p97_marker(root, legacy, workspace_dir));
        }
    }
    if !candidates.iter().any(|legacy| is_dir(legacy)) {
        return notices;
    }
    if published() {
        // Under the migration lock too: an adopter retires both markers under it, so a start that
        // reads the P97 marker here cannot interleave with that retirement and leave a stranded
        // marker behind that silences the next recreation for good (Astra P110 r4 #1). If the lock
        // cannot be taken, decide anyway: a repeated notice is better than a silent one.
        //
        // Not taken at all when no legacy folder holds notes (P124): then there is nothing to decide,
        // and a lingering template-only folder must not cost every start the lock.
        if !candidates
            .iter()
            .any(|legacy| legacy.as_path() != workspace_dir && is_dir(legacy) && holds_notes(legacy))
        {
            return notices;
        }
        let _lock = migration_lock(root);
        return stranded_legacy_notices(root, candidates, workspace_dir);
    }
    // One migration at a time per memory root (Astra P91 r2 #5, r3 #3). Every
    // starter whose identity has ANY pending legacy candidate takes the lock, so an
    // equivalent clone cannot publish an empty destination while another starter
    // is moving the legacy directory there; after the lock each decides on the
    // current state (destination published, or legacy still pending).
    let Some(_lock) = migration_lock(root) else {
        return notices;
    };
    for legacy in candidates {
        if published() {
            break;
        }
        if legacy.as_path() != workspace_dir && is_dir(legacy) {
            let outcome = migrate_legacy_workspace_dir(legacy, workspace_dir, identity);
            if outcome == LegacyMemoryOutcome::Adopted {
                // The folder announced earlier (if any) is gone now: a later recreation under this
                // name is news (Astra P110 r2 #3). P97's marker first: a start that runs between the
                // two removals then finds the stranded marker still there and stays silent, instead of
                // re-creating it from the P97 marker and suppressing the next notice (r3 #1).
                let _ = std::fs::remove_file(p97_marker(root, legacy, workspace_dir));
                let _ = std::fs::remove_file(stranded_marker(root, legacy, workspace_dir));
            } else if first_notice(root, legacy, workspace_dir) {
                // Announced now: once the new folder exists, the check below must not announce the
                // same folder a second time. Only written together with a notice: a silent start
                // writes no marker, so retiring the P97 marker can never leave a marker behind that
                // silences a later recreation (Astra P110 r5 #1 #2).
                let notes = notes_fingerprint(legacy);
                let _ = create_marker(&stranded_marker(root, legacy, workspace_dir), &notes);
                notices.push(LegacyMemoryNotice {
                    legacy: legacy.clone(),
                    new: workspace_dir.to_path_buf(),
                    outcome,
                });
            }
        }
    }
    notices
}

/// The per-root migration lock, held until the returned file is dropped. `None` if it cannot be
/// opened or locked.
fn migration_lock(root: &Path) -> Option<std::fs::File> {
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(root.join(".memory-migrate.lock"))
        .ok()?;
    lock.lock().ok()?;
    Some(lock)
}

/// Record, under the migration lock, that the notice for this legacy folder (towards this
/// destination) has been shown. True only the first time. If the marker cannot be written the
/// notice is shown anyway: a repeated notice is better than a silent one.
fn first_notice(root: &Path, legacy: &Path, workspace_dir: &Path) -> bool {
    create_marker(&p97_marker(root, legacy, workspace_dir), &notes_fingerprint(legacy))
}

/// Marker of [`first_notice`] (P97; its name is unchanged so markers written by earlier versions count).
fn p97_marker(root: &Path, legacy: &Path, workspace_dir: &Path) -> PathBuf {
    let key = format!("{}\n{}", legacy.display(), workspace_dir.display());
    root.join(format!(".legacy-notice-{}", &blake3::hash(key.as_bytes()).to_hex()[..16]))
}

/// R110 (M1): the host-qualified folder exists, so P91 adoption never runs again. A legacy folder
/// that also exists was recreated by an older version after the move (a downgrade, or an old binary
/// sharing `~/.fuigo`) or was never adopted. When it holds notes, say so once, naming both folders;
/// never merge or move anything (P91's adoption rule is unchanged). The caller removes the marker
/// whenever the legacy folder is found absent, so a later recreation is announced again.
fn stranded_legacy_notices(root: &Path, candidates: &[PathBuf], workspace_dir: &Path) -> Vec<LegacyMemoryNotice> {
    let mut notices = Vec::new();
    for legacy in candidates {
        if legacy.as_path() == workspace_dir || !legacy.symlink_metadata().is_ok_and(|meta| meta.is_dir()) {
            continue;
        }
        // The cheap check first (P124, Fable phase 7 round 2 F3): a folder an older version only
        // initialised holds no notes, so it is neither announced nor hashed. Without this a legacy
        // folder that lingers forever was read and hashed on every start. Nothing else changes: a
        // folder without notes never produced a notice, whatever its markers say.
        if !holds_notes(legacy) {
            continue;
        }
        let marker = stranded_marker(root, legacy, workspace_dir);
        let notes = notes_fingerprint(legacy);
        if marker_is_current(&p97_marker(root, legacy, workspace_dir), &notes) {
            // P97 already told the user about this very folder (possibly before this version
            // existed, so only its own marker is there): do not announce it again (Astra P110 r1 #3).
            // No marker of our own: the P97 marker suppresses for as long as it exists, and a copy
            // would outlive its retirement and silence a later recreation (Astra P110 r5 #1 #2).
            continue;
        }
        if !create_marker(&marker, &notes) {
            continue;
        }
        tracing::warn!(
            legacy = %legacy.display(),
            new = %workspace_dir.display(),
            "MEMORY_MIGRATE: an older version wrote memory under the legacy name after the move; \
             it was not merged into the host-qualified directory"
        );
        notices.push(LegacyMemoryNotice {
            legacy: legacy.clone(),
            new: workspace_dir.to_path_buf(),
            outcome: LegacyMemoryOutcome::Stranded,
        });
    }
    notices
}

#[cfg(test)]
thread_local! {
    /// How many legacy folders this thread hashed (P124 test seam for the stranded-notice cost).
    pub(crate) static FINGERPRINT_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Marker for [`stranded_legacy_notices`]; distinct from the P97 marker of [`first_notice`].
fn stranded_marker(root: &Path, legacy: &Path, workspace_dir: &Path) -> PathBuf {
    let key = format!("{}\n{}", legacy.display(), workspace_dir.display());
    root.join(format!(".legacy-stranded-notice-{}", &blake3::hash(key.as_bytes()).to_hex()[..16]))
}

/// What a notice told the user about: a hash of every note in the legacy folder (each file's path
/// and contents; a symlink's target; what [`holds_notes`] treats as empty at the top level is left
/// out). A marker suppresses a notice only for exactly the notes it was written for, so new or
/// changed notes are announced again however the folder came back: recreated by an older version,
/// left behind by another clone's adoption, or a reused inode (Astra P110 r6, r7). A folder that
/// cannot be read gets a fingerprint that matches nothing: a doubt produces a notice.
fn notes_fingerprint(dir: &Path) -> String {
    #[cfg(test)]
    FINGERPRINT_CALLS.with(|calls| calls.set(calls.get() + 1));
    /// A name or link target exactly as the filesystem stores it, so two different names never hash
    /// alike (a lossy conversion maps every invalid byte to the same character; Astra P110 r8 #3).
    fn raw(name: &std::ffi::OsStr) -> Vec<u8> {
        #[cfg(unix)]
        {
            std::os::unix::ffi::OsStrExt::as_bytes(name).to_vec()
        }
        #[cfg(windows)]
        {
            std::os::windows::ffi::OsStrExt::encode_wide(name).flat_map(u16::to_le_bytes).collect()
        }
        #[cfg(not(any(unix, windows)))]
        {
            name.to_string_lossy().into_owned().into_bytes()
        }
    }
    fn walk(dir: &Path, rel: &[u8], top: bool, hasher: &mut blake3::Hasher) -> bool {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return false;
        };
        let mut listed = Vec::new();
        for entry in entries {
            let Ok(entry) = entry else {
                return false;
            };
            listed.push(entry);
        }
        listed.sort_by_key(|entry| entry.file_name());
        for entry in listed {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();
            let path = entry.path();
            // A failed P91 index move leaves a fresh `.pre-p91-index-*` folder on every attempt: it
            // holds index files, not notes, and must not make the same notes look new (r8 #1).
            if top
                && (name.starts_with(".pre-p91-index-")
                    || match name.as_ref() {
                        "MEMORY.md" => is_memory_template(&path),
                        ".memory-write.lock" => path.symlink_metadata().is_ok_and(|meta| meta.is_file()),
                        other => is_index_file(other),
                    })
            {
                continue;
            }
            let mut rel = rel.to_vec();
            rel.push(b'/');
            rel.extend_from_slice(&raw(&file_name));
            let Ok(meta) = path.symlink_metadata() else {
                return false;
            };
            hasher.update(&(rel.len() as u64).to_le_bytes());
            hasher.update(&rel);
            if meta.is_dir() {
                hasher.update(b"d");
                if !walk(&path, &rel, false, hasher) {
                    return false;
                }
            } else if meta.is_symlink() {
                let Ok(target) = std::fs::read_link(&path) else {
                    return false;
                };
                let target = raw(target.as_os_str());
                hasher.update(b"l");
                hasher.update(&(target.len() as u64).to_le_bytes());
                hasher.update(&target);
            } else if meta.is_file() {
                let Ok(file) = std::fs::File::open(&path) else {
                    return false;
                };
                hasher.update(b"f");
                hasher.update(&meta.len().to_le_bytes());
                if hasher.update_reader(file).is_err() {
                    return false;
                }
            } else {
                // A FIFO, socket or device: never opened (opening a FIFO with no writer blocks start-up
                // while the migration lock is held; Astra P110 r8 #2). Its presence is what counts.
                hasher.update(b"o");
            }
        }
        true
    }
    let mut hasher = blake3::Hasher::new();
    if walk(dir, b"", true, &mut hasher) {
        hasher.finalize().to_hex().to_string()
    } else {
        String::new()
    }
}

/// True when `marker` exists and records exactly these notes. An empty marker (a write cut short, or
/// one written before markers recorded notes; no released version wrote any) and an empty
/// fingerprint (notes that could not be read) match nothing: a doubt produces a notice.
fn marker_is_current(marker: &Path, notes: &str) -> bool {
    match std::fs::read_to_string(marker) {
        Ok(recorded) => !notes.is_empty() && recorded == notes,
        Err(_) => false,
    }
}

/// Claim `marker` for these notes; true unless it already recorded them. A marker for other notes is
/// taken over (written to a temporary file and renamed into place, so it is never left empty). As in
/// [`first_notice`], a marker that cannot be written means the notice is shown anyway.
fn create_marker(marker: &Path, notes: &str) -> bool {
    match std::fs::OpenOptions::new().write(true).create_new(true).open(marker) {
        Ok(mut file) => {
            let _ = std::io::Write::write_all(&mut file, notes.as_bytes());
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if marker_is_current(marker, notes) {
                return false;
            }
            let staged = marker.with_extension(format!("tmp-{}", std::process::id()));
            if std::fs::write(&staged, notes).is_err() || std::fs::rename(&staged, marker).is_err() {
                let _ = std::fs::remove_file(&staged);
            }
            true
        }
        Err(_) => true,
    }
}

/// True when a memory folder holds anything beyond what an older version creates before it writes
/// a note: its `MEMORY.md` template, search index files, the write lock and an empty `sessions/`.
/// Anything unreadable counts as notes, so a doubt produces a notice rather than silence.
fn holds_notes(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return true;
    };
    for entry in entries {
        let Ok(entry) = entry else {
            return true;
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let path = entry.path();
        let empty = match name.as_ref() {
            "MEMORY.md" => is_memory_template(&path),
            "sessions" => is_empty_workspace(&path),
            ".memory-write.lock" => path.symlink_metadata().is_ok_and(|meta| meta.is_file()),
            other => is_index_file(other),
        };
        if !empty {
            return true;
        }
    }
    false
}

/// The `MEMORY.md` template [`MemoryStorage::ensure_initialized`] writes (and 1.0.20 wrote), with
/// nothing added.
fn is_memory_template(path: &Path) -> bool {
    const HEADER: &str = "# Project Memory \u{2014} ";
    const NOTE: &str = "> Auto-populated by dream consolidation. Edit freely.";
    if !path.symlink_metadata().is_ok_and(|meta| meta.is_file() && meta.len() <= 4096) {
        return false;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let mut lines = text.lines();
    lines.next().is_some_and(|line| line.starts_with(HEADER))
        && lines.all(|line| line.trim().is_empty() || line.trim() == NOTE)
}

/// One candidate; the caller holds `.memory-migrate.lock` and has checked that the
/// destination does not exist and the legacy directory does.
fn migrate_legacy_workspace_dir(
    legacy_dir: &Path,
    workspace_dir: &Path,
    identity: &str,
) -> LegacyMemoryOutcome {
    let refuse = |reason: &str, detail: &[String]| {
        tracing::warn!(
            legacy = %legacy_dir.display(),
            new = %workspace_dir.display(),
            identity,
            reason,
            detail = ?detail,
            "MEMORY_MIGRATE: legacy workspace memory was not adopted: it cannot be shown to belong to this \
             remote host only; move it to the new directory by hand if it is yours"
        );
        LegacyMemoryOutcome::NotAdopted { reason: reason.to_owned() }
    };
    let Some(recorded) = recorded_workspace_paths(legacy_dir) else {
        return refuse("evidence could not be read completely", &[]);
    };
    let mut proven = false;
    let mut foreign = Vec::new();
    for path in recorded {
        if !path.is_absolute() || !path.exists() {
            continue;
        }
        match extract_repo_identity(&path) {
            Some(other) if other == identity => proven = true,
            Some(other) => foreign.push(format!("{} ({other})", path.display())),
            None => {}
        }
    }
    if !foreign.is_empty() {
        return refuse("recorded by a clone of another host", &foreign);
    }
    if !proven {
        return refuse("no recorded clone of this host still exists", &[]);
    }
    // A FRESH directory we create ourselves (create_dir fails on anything already
    // there, including a symlink), so nothing is followed or overwritten (r2 #4).
    let aside = legacy_dir.join(format!(
        ".pre-p91-index-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let mut aside_created = false;
    if let Ok(entries) = std::fs::read_dir(legacy_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !is_index_file(&name) {
                continue;
            }
            let mut move_aside = || -> std::io::Result<()> {
                if !aside_created {
                    std::fs::create_dir(&aside)?;
                    aside_created = true;
                }
                std::fs::rename(entry.path(), aside.join(name.as_ref()))
            };
            let moved = move_aside();
            if let Err(error) = moved {
                // Never publish a directory whose stale index is still in place.
                refuse(&format!("could not move index file {name} aside: {error}"), &[]);
                return LegacyMemoryOutcome::MoveFailed { error: format!("index file {name}: {error}") };
            }
        }
    }
    if let Err(error) = std::fs::rename(legacy_dir, workspace_dir) {
        tracing::warn!(
            legacy = %legacy_dir.display(),
            new = %workspace_dir.display(),
            %error,
            "MEMORY_MIGRATE: could not move legacy workspace memory"
        );
        return LegacyMemoryOutcome::MoveFailed { error: error.to_string() };
    }
    tracing::info!(
        legacy = %legacy_dir.display(),
        new = %workspace_dir.display(),
        identity,
        "MEMORY_MIGRATE: moved legacy workspace memory to its host-qualified directory"
    );
    LegacyMemoryOutcome::Adopted
}

/// Generate a URL-safe slug (e.g., from the first user message): lowercase, non-alphanumerics become `-`, consecutive dashes collapse.
/// Truncates to `max_len` characters (not bytes) and strips leading/trailing `-`.
pub fn slugify(input: &str, max_len: usize) -> String {
    let slug: String = input
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();

    // Collapse consecutive dashes
    let mut result = String::with_capacity(slug.len());
    let mut prev_dash = false;
    for c in slug.chars() {
        if c == '-' {
            if !prev_dash {
                result.push('-');
            }
            prev_dash = true;
        } else {
            result.push(c);
            prev_dash = false;
        }
    }

    // Truncate by char count (safe for multi-byte), then trim dashes
    let truncated: String = result.chars().take(max_len).collect();
    truncated.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Prepend the hermetic git binary (via `GIT_BIN_PATH`) to `PATH`.
    /// `Command::new("git")` and `git2`'s discovery then resolve to the hermetic static binary instead of system-installed git.
    ///
    /// Safe to call multiple times; only the first call mutates `PATH`.
    fn ensure_hermetic_git_on_path() {
        use std::path::PathBuf;
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            if let Ok(git_bin) = std::env::var("GIT_BIN_PATH") {
                let p = PathBuf::from(&git_bin);
                let p = if p.is_relative() {
                    std::env::current_dir().unwrap().join(&p)
                } else {
                    p
                };
                if let Some(dir) = p.parent() {
                    let cur = std::env::var("PATH").unwrap_or_default();
                    unsafe {
                        std::env::set_var("PATH", format!("{}:{}", dir.display(), cur));
                    }
                }
            }
        });
    }

    #[test]
    fn test_compute_workspace_hash_deterministic() {
        let hash1 = compute_workspace_hash(Path::new("/some/workspace"));
        let hash2 = compute_workspace_hash(Path::new("/some/workspace"));
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_workspace_hash_human_readable() {
        let name = compute_workspace_hash(Path::new("/users/me/work/fuigo"));
        assert!(
            name.starts_with("fuigo-"),
            "should start with project name slug, got: {name}"
        );
        // Format: {slug}-{8 hex chars}
        let parts: Vec<&str> = name.rsplitn(2, '-').collect();
        assert_eq!(
            parts[0].len(),
            8,
            "hash suffix should be 8 hex chars, got: {name}"
        );
        assert!(
            parts[0].chars().all(|c| c.is_ascii_hexdigit()),
            "hash suffix should be hex, got: {name}"
        );
    }

    #[test]
    fn test_compute_workspace_hash_different_paths() {
        let hash1 = compute_workspace_hash(Path::new("/workspace/a"));
        let hash2 = compute_workspace_hash(Path::new("/workspace/b"));
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_workspace_hash_same_dirname_different_parent() {
        // Two "app" dirs in different parents get different names (hash differs)
        let name1 = compute_workspace_hash(Path::new("/users/alice/app"));
        let name2 = compute_workspace_hash(Path::new("/users/bob/app"));
        assert!(name1.starts_with("app-"), "got: {name1}");
        assert!(name2.starts_with("app-"), "got: {name2}");
        assert_ne!(
            name1, name2,
            "same dir name but different parents should differ"
        );
    }

    #[test]
    fn test_slugify_basic() {
        assert_eq!(slugify("Hello World", 20), "hello-world");
    }

    #[test]
    fn test_slugify_special_chars() {
        assert_eq!(
            slugify("Fix the bug in auth/login.rs", 30),
            "fix-the-bug-in-auth-login-rs"
        );
    }

    #[test]
    fn test_slugify_truncation() {
        assert_eq!(slugify("a very long message here", 10), "a-very-lon");
    }

    #[test]
    fn test_slugify_leading_trailing_dashes() {
        assert_eq!(slugify("---hello---", 20), "hello");
    }

    #[test]
    fn test_slugify_consecutive_special_chars() {
        assert_eq!(slugify("hello!!!world", 20), "hello-world");
    }

    #[test]
    fn test_slugify_empty() {
        assert_eq!(slugify("", 20), "");
    }

    #[test]
    fn test_storage_write_and_read_daily_log() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("abc123");
        let storage = MemoryStorage::with_paths(global_dir, workspace_dir);

        let content = "## Session Summary\n\nWorked on feature X.";
        let path = storage
            .write_daily_log("2026-02-23", "fix-auth", "session12345678", content, false)
            .unwrap();

        assert!(path.exists());
        assert!(
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .contains(&format!(
                    "2026-02-23-fix-auth-{}",
                    MemoryStorage::session_suffix("session12345678")
                ))
        );

        let read_back = storage.read_file(&path, None, None).unwrap();
        assert_eq!(read_back, content);
    }

    #[test]
    fn test_storage_read_file_with_line_range() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("abc123");
        let storage = MemoryStorage::with_paths(global_dir, workspace_dir);

        let content = "line 0\nline 1\nline 2\nline 3\nline 4";
        let path = storage
            .write_daily_log("2026-02-23", "test", "sess12345678", content, false)
            .unwrap();

        // Read lines 1..3 (0-indexed)
        let partial = storage.read_file(&path, Some(1), Some(2)).unwrap();
        assert_eq!(partial, "line 1\nline 2");
    }

    #[test]
    fn test_storage_write_long_term_global() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("abc123");
        let storage = MemoryStorage::with_paths(global_dir.clone(), workspace_dir);

        storage
            .write_long_term(MemoryScope::Global, "# Global\n\nSome knowledge.")
            .unwrap();

        let path = global_dir.join("MEMORY.md");
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "# Global\n\nSome knowledge.");
    }

    #[test]
    fn test_storage_write_long_term_workspace() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("abc123");
        let storage = MemoryStorage::with_paths(global_dir, workspace_dir.clone());

        storage
            .write_long_term(MemoryScope::Workspace, "# Project\n\nProject info.")
            .unwrap();

        let path = workspace_dir.join("MEMORY.md");
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "# Project\n\nProject info.");
    }

    #[test]
    fn test_storage_list_memory_files() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("abc123");
        let storage = MemoryStorage::with_paths(global_dir, workspace_dir);

        // Initially empty
        let files = storage.list_memory_files().unwrap();
        assert!(files.is_empty());

        // Write some files
        storage
            .write_long_term(MemoryScope::Global, "global")
            .unwrap();
        storage
            .write_long_term(MemoryScope::Workspace, "workspace")
            .unwrap();
        storage
            .write_daily_log("2026-02-23", "test", "sess12345678", "session log", false)
            .unwrap();

        let files = storage.list_memory_files().unwrap();
        assert_eq!(files.len(), 3);

        // Global MEMORY.md comes first
        assert!(files[0].ends_with("MEMORY.md"));
        assert!(
            files[0]
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                == "memory"
        );
    }

    #[test]
    fn test_storage_ensure_initialized() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("abc123");
        let storage = MemoryStorage::with_paths(global_dir.clone(), workspace_dir.clone());

        storage.ensure_initialized().unwrap();

        assert!(global_dir.join("MEMORY.md").exists());
        assert!(workspace_dir.join("MEMORY.md").exists());

        // Calling again is idempotent (does not overwrite)
        let content_before = std::fs::read_to_string(global_dir.join("MEMORY.md")).unwrap();
        storage.ensure_initialized().unwrap();
        let content_after = std::fs::read_to_string(global_dir.join("MEMORY.md")).unwrap();
        assert_eq!(content_before, content_after);
    }

    #[test]
    fn test_storage_read_file_rejects_outside_path() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("abc123");
        std::fs::create_dir_all(&global_dir).unwrap();
        let storage = MemoryStorage::with_paths(global_dir, workspace_dir);

        // Try to read a file outside the memory directory
        let outside = tmp.path().join("outside.md");
        std::fs::write(&outside, "secret").unwrap();

        let result = storage.read_file(&outside, None, None);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn test_storage_daily_log_overwrites() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("abc123");
        let storage = MemoryStorage::with_paths(global_dir, workspace_dir);

        let path1 = storage
            .write_daily_log("2026-02-23", "test", "sess12345678", "first", false)
            .unwrap();
        let path2 = storage
            .write_daily_log("2026-02-23", "test", "sess12345678", "second", false)
            .unwrap();

        assert_eq!(path1, path2);
        let content = std::fs::read_to_string(&path2).unwrap();
        assert_eq!(content, "second");
    }

    #[test]
    fn test_storage_daily_log_append() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("abc123");
        let storage = MemoryStorage::with_paths(global_dir, workspace_dir);

        let path1 = storage
            .write_daily_log("2026-02-23", "flush", "sess12345678", "## First", true)
            .unwrap();
        // First write to a new file uses write (no separator).
        let content = std::fs::read_to_string(&path1).unwrap();
        assert_eq!(content, "## First");

        let path2 = storage
            .write_daily_log("2026-02-23", "flush", "sess12345678", "## Second", true)
            .unwrap();
        assert_eq!(path1, path2);

        let content = std::fs::read_to_string(&path2).unwrap();
        assert!(
            content.starts_with("## First"),
            "original content preserved"
        );
        assert!(content.contains("---"), "separator present");
        assert!(content.contains("<!-- flush"), "timestamp marker present");
        assert!(content.contains("## Second"), "appended content present");
    }

    // -----------------------------------------------------------------------
    // normalize_memory_content tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_single_line() {
        assert_eq!(
            normalize_memory_content("prefer tabs over spaces"),
            "## prefer tabs over spaces"
        );
    }

    #[test]
    fn test_normalize_already_has_h2_heading() {
        let input = "## Build conventions\n\nCargo workspace, run clippy before push";
        assert_eq!(normalize_memory_content(input), input);
    }

    #[test]
    fn test_normalize_already_has_h1_heading() {
        let input = "# Top Level\n\nSome body text.";
        assert_eq!(normalize_memory_content(input), input);
    }

    #[test]
    fn test_normalize_multiline_short_first_line() {
        assert_eq!(
            normalize_memory_content("This project uses React 18\nThe build system is Vite"),
            "## This project uses React 18\n\nThe build system is Vite"
        );
    }

    #[test]
    fn test_normalize_multiline_long_first_line() {
        let long_line = "a".repeat(81);
        let input = format!("{long_line}\nMore details here");
        let result = normalize_memory_content(&input);
        assert!(result.starts_with("## Note\n\n"));
        assert!(result.contains(&long_line));
        assert!(result.contains("More details here"));
    }

    #[test]
    fn test_normalize_multiline_exactly_80_chars() {
        let line_80 = "a".repeat(80);
        let input = format!("{line_80}\nbody");
        let result = normalize_memory_content(&input);
        assert!(
            result.starts_with("## aaaa"),
            "80-char first line should be promoted to heading"
        );
        assert!(!result.starts_with("## Note"));
    }

    #[test]
    fn test_normalize_empty() {
        assert_eq!(normalize_memory_content(""), "");
    }

    #[test]
    fn test_normalize_whitespace_only() {
        assert_eq!(normalize_memory_content("   \n  \n  "), "");
    }

    #[test]
    fn test_normalize_trims_surrounding_whitespace() {
        assert_eq!(
            normalize_memory_content("  prefer tabs  "),
            "## prefer tabs"
        );
    }

    #[test]
    fn test_normalize_preserves_internal_newlines() {
        let input = "First line\nSecond line\nThird line";
        let result = normalize_memory_content(input);
        assert_eq!(result, "## First line\n\nSecond line\nThird line");
    }

    // -----------------------------------------------------------------------
    // append_to_memory tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_append_to_memory_workspace_empty_file() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("abc123");
        let storage = MemoryStorage::with_paths(global_dir, workspace_dir.clone());

        storage
            .append_to_memory(MemoryScope::Workspace, "prefer tabs")
            .unwrap();

        let content = std::fs::read_to_string(workspace_dir.join("MEMORY.md")).unwrap();
        assert_eq!(content, "## prefer tabs");
    }

    #[test]
    fn test_append_to_memory_global() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("abc123");
        let storage = MemoryStorage::with_paths(global_dir.clone(), workspace_dir);

        storage
            .append_to_memory(MemoryScope::Global, "always use UTC")
            .unwrap();

        let content = std::fs::read_to_string(global_dir.join("MEMORY.md")).unwrap();
        assert_eq!(content, "## always use UTC");
    }

    #[test]
    fn test_append_to_memory_adds_separator() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("abc123");
        let storage = MemoryStorage::with_paths(global_dir, workspace_dir.clone());

        storage
            .append_to_memory(MemoryScope::Workspace, "first note")
            .unwrap();
        storage
            .append_to_memory(MemoryScope::Workspace, "second note")
            .unwrap();

        let content = std::fs::read_to_string(workspace_dir.join("MEMORY.md")).unwrap();
        assert_eq!(content, "## first note\n\n## second note");
    }

    #[test]
    fn test_append_to_memory_normalizes_content() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("abc123");
        let storage = MemoryStorage::with_paths(global_dir, workspace_dir.clone());

        storage
            .append_to_memory(MemoryScope::Workspace, "raw text without heading")
            .unwrap();

        let content = std::fs::read_to_string(workspace_dir.join("MEMORY.md")).unwrap();
        assert!(
            content.starts_with("## "),
            "should have been normalized with a heading"
        );
    }

    #[test]
    fn test_append_to_memory_preserves_user_heading() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("abc123");
        let storage = MemoryStorage::with_paths(global_dir, workspace_dir.clone());

        storage
            .append_to_memory(
                MemoryScope::Workspace,
                "## My Custom Heading\n\nDetails here.",
            )
            .unwrap();

        let content = std::fs::read_to_string(workspace_dir.join("MEMORY.md")).unwrap();
        assert_eq!(content, "## My Custom Heading\n\nDetails here.");
    }

    #[test]
    fn test_append_to_memory_ignores_empty_content() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("abc123");
        let storage = MemoryStorage::with_paths(global_dir, workspace_dir.clone());

        storage
            .append_to_memory(MemoryScope::Workspace, "   ")
            .unwrap();

        assert!(!workspace_dir.join("MEMORY.md").exists());
    }

    // -----------------------------------------------------------------------
    // clear_workspace / clear_global tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_clear_workspace_removes_directory() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("abc123");
        let storage = MemoryStorage::with_paths(global_dir, workspace_dir.clone());

        storage.ensure_initialized().unwrap();
        storage
            .write_daily_log("2026-05-05", "test", "sess12345678", "log content", false)
            .unwrap();
        assert!(workspace_dir.is_dir());
        assert!(workspace_dir.join("MEMORY.md").exists());

        let removed = storage.clear_workspace().unwrap();
        assert!(removed);
        assert!(!workspace_dir.exists());
    }

    #[test]
    fn test_clear_workspace_returns_false_when_missing() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("nonexistent");
        let storage = MemoryStorage::with_paths(global_dir, workspace_dir);

        let removed = storage.clear_workspace().unwrap();
        assert!(!removed);
    }

    #[test]
    fn test_clear_global_removes_file_but_not_directory() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("abc123");
        let storage = MemoryStorage::with_paths(global_dir.clone(), workspace_dir);

        storage.ensure_initialized().unwrap();
        assert!(global_dir.join("MEMORY.md").exists());

        let removed = storage.clear_global().unwrap();
        assert!(removed);
        assert!(!global_dir.join("MEMORY.md").exists());
        assert!(global_dir.is_dir(), "global directory itself should remain");
    }

    #[test]
    fn test_clear_global_returns_false_when_missing() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("abc123");
        std::fs::create_dir_all(&global_dir).unwrap();
        let storage = MemoryStorage::with_paths(global_dir, workspace_dir);

        let removed = storage.clear_global().unwrap();
        assert!(!removed);
    }

    #[test]
    fn test_clear_workspace_then_reinitialize() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("abc123");
        let storage = MemoryStorage::with_paths(global_dir, workspace_dir.clone());

        storage.ensure_initialized().unwrap();
        storage
            .append_to_memory(MemoryScope::Workspace, "custom entry")
            .unwrap();
        let before = std::fs::read_to_string(workspace_dir.join("MEMORY.md")).unwrap();
        assert!(before.contains("custom entry"));

        storage.clear_workspace().unwrap();
        storage.ensure_initialized().unwrap();

        let after = std::fs::read_to_string(workspace_dir.join("MEMORY.md")).unwrap();
        assert!(
            !after.contains("custom entry"),
            "reinitialized file should be a fresh template"
        );
        assert!(after.contains("Project Memory"));
    }

    // -----------------------------------------------------------------------
    // normalize_remote_url tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_ssh_url() {
        assert_eq!(
            normalize_remote_url("git@github.com:acme/widgets.git"),
            Some("github.com/acme/widgets".to_string())
        );
    }

    #[test]
    fn test_normalize_https_url() {
        assert_eq!(
            normalize_remote_url("https://github.com/acme/widgets.git"),
            Some("github.com/acme/widgets".to_string())
        );
    }

    #[test]
    fn test_normalize_https_no_dot_git() {
        assert_eq!(
            normalize_remote_url("https://github.com/acme/widgets"),
            Some("github.com/acme/widgets".to_string())
        );
    }

    #[test]
    fn test_normalize_ssh_with_scheme() {
        assert_eq!(
            normalize_remote_url("ssh://git@github.com/acme/widgets"),
            Some("github.com/acme/widgets".to_string())
        );
    }

    #[test]
    fn test_normalize_self_hosted() {
        assert_eq!(
            normalize_remote_url("git@gitlab.example.com:team/project.git"),
            Some("gitlab.example.com/team/project".to_string())
        );
    }

    #[test]
    fn test_normalize_no_org_returns_none() {
        assert_eq!(normalize_remote_url("git@github.com:widgets.git"), None);
    }

    #[test]
    fn test_normalize_no_colon_returns_none() {
        assert_eq!(normalize_remote_url("just-a-path"), None);
    }

    #[test]
    fn test_normalize_empty_returns_none() {
        assert_eq!(normalize_remote_url(""), None);
    }

    #[test]
    fn test_normalize_deep_path() {
        assert_eq!(
            normalize_remote_url("https://github.com/acme/tools/sub.git"),
            Some("github.com/acme/tools/sub".to_string())
        );
    }

    #[test]
    fn test_normalize_protocols_produce_same_identity() {
        let ssh = normalize_remote_url("git@github.com:acme/widgets.git");
        let https = normalize_remote_url("https://github.com/acme/widgets.git");
        let ssh_scheme = normalize_remote_url("ssh://git@github.com/acme/widgets.git");
        assert_eq!(ssh, https);
        assert_eq!(https, ssh_scheme);
    }

    // -----------------------------------------------------------------------
    // extract_repo_identity tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_repo_identity_from_current_repo() {
        ensure_hermetic_git_on_path();
        let tmp = TempDir::new().unwrap();
        let repo = git2::Repository::init(tmp.path()).unwrap();
        repo.remote("origin", "git@github.com:example/demo.git")
            .unwrap();

        let identity = extract_repo_identity(tmp.path());
        assert!(
            identity.is_some(),
            "should detect repo identity from git directory with origin remote"
        );
        let id = identity.unwrap();
        assert_eq!(id, "github.com/example/demo");
    }

    #[test]
    fn test_extract_repo_identity_non_git_dir() {
        let tmp = TempDir::new().unwrap();
        let identity = extract_repo_identity(tmp.path());
        assert_eq!(identity, None, "non-git directory should return None");
    }

    #[test]
    fn test_compute_workspace_hash_uses_repo_identity() {
        // Two different paths in the same repo should produce the same hash.
        ensure_hermetic_git_on_path();
        let tmp = TempDir::new().unwrap();
        let repo = git2::Repository::init(tmp.path()).unwrap();
        repo.remote("origin", "git@github.com:example/demo.git")
            .unwrap();

        let subdir = tmp.path().join("subdir");
        std::fs::create_dir(&subdir).unwrap();

        let hash1 = compute_workspace_hash(tmp.path());
        let hash2 = compute_workspace_hash(&subdir);
        assert_eq!(
            hash1, hash2,
            "different subdirs of same repo should share identity"
        );
    }

    #[test]
    fn test_compute_workspace_hash_non_git_falls_back() {
        let tmp = TempDir::new().unwrap();
        let hash = compute_workspace_hash(tmp.path());
        // Should still produce a valid slug-hash format
        assert!(hash.contains('-'), "should have slug-hash format: {hash}");
        let parts: Vec<&str> = hash.rsplitn(2, '-').collect();
        assert_eq!(parts[0].len(), 8, "hash suffix should be 8 hex chars");
    }

    // -----------------------------------------------------------------------
    // is_ephemeral_cwd tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ephemeral_linux_tmp() {
        assert!(is_ephemeral_cwd(Path::new("/tmp/foo")));
        assert!(is_ephemeral_cwd(Path::new("/tmp/subagent-worktree-123")));
    }

    #[test]
    fn test_ephemeral_linux_var_tmp() {
        assert!(is_ephemeral_cwd(Path::new("/var/tmp/bar")));
        assert!(is_ephemeral_cwd(Path::new("/var/tmp/nested/deep")));
    }

    #[test]
    fn test_ephemeral_macos_var_folders() {
        assert!(is_ephemeral_cwd(Path::new(
            "/var/folders/xx/yyyyyyyy/T/tmpABCDEF"
        )));
        assert!(is_ephemeral_cwd(Path::new(
            "/private/var/folders/xx/yyyyyyyy/T/tmpABCDEF"
        )));
    }

    #[test]
    fn test_ephemeral_macos_private_tmp() {
        assert!(is_ephemeral_cwd(Path::new("/private/tmp/foo")));
        assert!(is_ephemeral_cwd(Path::new("/private/var/tmp/bar")));
    }

    #[test]
    fn test_non_ephemeral_normal_paths() {
        assert!(!is_ephemeral_cwd(Path::new("/home/user/project")));
        assert!(!is_ephemeral_cwd(Path::new("/home/user/src")));
        assert!(!is_ephemeral_cwd(Path::new("/Users/dev/work/repo")));
        assert!(!is_ephemeral_cwd(Path::new("/opt/workspace")));
    }

    #[test]
    fn test_ephemeral_storage_skips_workspace_writes() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("ephemeral-abc12345");

        let storage = MemoryStorage {
            global_enabled: true,
            global_dir: global_dir.clone(),
            workspace_dir: workspace_dir.clone(),
            workspace_path: PathBuf::from("/tmp/test"),
            ephemeral: true,
            legacy_notices: Vec::new(),
            legacy_dirs: Vec::new(),
        };

        // write_daily_log returns Ok but must not create the file
        let path = storage
            .write_daily_log("2026-05-07", "test", "sess12345678", "content", false)
            .unwrap();
        assert!(!path.exists());

        // write_long_term for workspace should no-op
        storage
            .write_long_term(MemoryScope::Workspace, "should not write")
            .unwrap();
        assert!(!workspace_dir.join("MEMORY.md").exists());

        // write_long_term for global should still work
        storage
            .write_long_term(MemoryScope::Global, "global content")
            .unwrap();
        assert!(global_dir.join("MEMORY.md").exists());
    }

    #[test]
    fn test_ephemeral_storage_skips_append() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("ephemeral-abc12345");

        let storage = MemoryStorage {
            global_enabled: true,
            global_dir: global_dir.clone(),
            workspace_dir: workspace_dir.clone(),
            workspace_path: PathBuf::from("/tmp/test"),
            ephemeral: true,
            legacy_notices: Vec::new(),
            legacy_dirs: Vec::new(),
        };

        // Workspace append should be skipped
        storage
            .append_to_memory(MemoryScope::Workspace, "should skip")
            .unwrap();
        assert!(!workspace_dir.join("MEMORY.md").exists());

        // Global append should still work
        storage
            .append_to_memory(MemoryScope::Global, "global note")
            .unwrap();
        assert!(global_dir.join("MEMORY.md").exists());
    }

    #[test]
    fn test_ephemeral_storage_skips_workspace_init() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("ephemeral-abc12345");

        let storage = MemoryStorage {
            global_enabled: true,
            global_dir: global_dir.clone(),
            workspace_dir: workspace_dir.clone(),
            workspace_path: PathBuf::from("/tmp/test"),
            ephemeral: true,
            legacy_notices: Vec::new(),
            legacy_dirs: Vec::new(),
        };

        storage.ensure_initialized().unwrap();

        assert!(global_dir.join("MEMORY.md").exists());
        assert!(!workspace_dir.exists());
    }

    #[test]
    fn test_ephemeral_flag_set_via_new() {
        // A temp-dir CWD should produce an ephemeral storage
        let storage = MemoryStorage::new(Path::new("/tmp/fake-worktree"), None);
        assert!(storage.is_ephemeral());

        // A normal CWD should not
        let storage = MemoryStorage::new(Path::new("/home/user/project"), None);
        assert!(!storage.is_ephemeral());
    }

    #[test]
    fn test_new_flat_never_ephemeral() {
        // new_flat uses use_workspace_hash=false, so ephemeral should always be false
        let storage = MemoryStorage::new_flat(Path::new("/tmp/something"), Path::new("/tmp/root"));
        assert!(!storage.is_ephemeral());
    }

    // -----------------------------------------------------------------------
    // gc tests
    // -----------------------------------------------------------------------

    fn set_dir_mtime_days_ago(dir: &Path, days: u64) {
        let t =
            std::time::SystemTime::now() - std::time::Duration::from_secs(days * 24 * 60 * 60 + 60);
        filetime::set_file_mtime(dir, filetime::FileTime::from_system_time(t)).unwrap();
    }

    #[test]
    fn test_gc_empty_tmp_removed_unconditionally() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("current-ws");
        let storage = MemoryStorage::with_paths(global_dir.clone(), workspace_dir);

        // Create an empty tmp dir (no sessions subdir)
        std::fs::create_dir_all(global_dir.join("tmp-abc12345")).unwrap();

        let removed = storage.gc(30).unwrap();
        assert_eq!(removed, 1);
        assert!(!global_dir.join("tmp-abc12345").exists());
    }

    #[test]
    fn test_gc_nonempty_tmp_young_kept() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("current-ws");
        let storage = MemoryStorage::with_paths(global_dir.clone(), workspace_dir);

        // Create a non-empty tmp dir that is young (mtime = now)
        let tmp_ws = global_dir.join("tmp-def12345");
        let sessions = tmp_ws.join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        std::fs::write(sessions.join("2026-05-01-test-sess1234.md"), "log").unwrap();

        let removed = storage.gc(30).unwrap();
        assert_eq!(removed, 0);
        assert!(tmp_ws.exists());
    }

    #[test]
    fn test_gc_nonempty_tmp_old_preserved() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("current-ws");
        let storage = MemoryStorage::with_paths(global_dir.clone(), workspace_dir);

        // Create a non-empty tmp dir that is old (over 7 days)
        let tmp_ws = global_dir.join("tmp-ghi12345");
        let sessions = tmp_ws.join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        std::fs::write(sessions.join("2026-04-01-old-sess1234.md"), "log").unwrap();
        set_dir_mtime_days_ago(&tmp_ws, 8);

        let removed = storage.gc(30).unwrap();
        assert_eq!(removed, 0);
        assert!(tmp_ws.exists());
    }

    #[test]
    fn test_gc_empty_workspace_old_removed() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("current-ws");
        let storage = MemoryStorage::with_paths(global_dir.clone(), workspace_dir);

        // Create an empty workspace dir older than max_age_days
        let old_ws = global_dir.join("old-project-ab123456");
        std::fs::create_dir_all(&old_ws).unwrap();
        set_dir_mtime_days_ago(&old_ws, 31);

        let removed = storage.gc(30).unwrap();
        assert_eq!(removed, 1);
        assert!(!old_ws.exists());
    }

    #[test]
    fn test_gc_empty_workspace_young_kept() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("current-ws");
        let storage = MemoryStorage::with_paths(global_dir.clone(), workspace_dir);

        // Create an empty workspace dir younger than max_age_days
        let young_ws = global_dir.join("young-project-cd123456");
        std::fs::create_dir_all(&young_ws).unwrap();

        let removed = storage.gc(30).unwrap();
        assert_eq!(removed, 0);
        assert!(young_ws.exists());
    }

    #[test]
    fn test_gc_nonempty_workspace_never_removed() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("current-ws");
        let storage = MemoryStorage::with_paths(global_dir.clone(), workspace_dir);

        // Create a non-empty workspace dir that is old
        let active_ws = global_dir.join("active-project-ef123456");
        let sessions = active_ws.join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        std::fs::write(sessions.join("2026-01-01-work-sess1234.md"), "log").unwrap();
        set_dir_mtime_days_ago(&active_ws, 60);

        let removed = storage.gc(30).unwrap();
        assert_eq!(removed, 0);
        assert!(active_ws.exists());
    }

    #[test]
    fn test_gc_skips_files_in_root() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("current-ws");
        let storage = MemoryStorage::with_paths(global_dir.clone(), workspace_dir);

        // Create a file (not a directory) in the memory root
        std::fs::create_dir_all(&global_dir).unwrap();
        std::fs::write(global_dir.join("MEMORY.md"), "global").unwrap();

        let removed = storage.gc(30).unwrap();
        assert_eq!(removed, 0);
        assert!(global_dir.join("MEMORY.md").exists());
    }

    #[test]
    fn test_gc_nonexistent_root_returns_zero() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("does-not-exist");
        let workspace_dir = global_dir.join("ws");
        let storage = MemoryStorage::with_paths(global_dir, workspace_dir);

        let removed = storage.gc(30).unwrap();
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_gc_returns_correct_count() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("current-ws");
        let storage = MemoryStorage::with_paths(global_dir.clone(), workspace_dir);

        // 2 empty tmp dirs (removed unconditionally)
        std::fs::create_dir_all(global_dir.join("tmp-one-12345678")).unwrap();
        std::fs::create_dir_all(global_dir.join("tmp-two-12345678")).unwrap();

        // 1 empty old workspace (removed)
        let old = global_dir.join("old-ws-12345678");
        std::fs::create_dir_all(&old).unwrap();
        set_dir_mtime_days_ago(&old, 31);

        // 1 non-empty workspace (kept)
        let active = global_dir.join("active-12345678");
        let sessions = active.join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        std::fs::write(sessions.join("log.md"), "x").unwrap();

        let removed = storage.gc(30).unwrap();
        assert_eq!(removed, 3);
    }

    #[test]
    fn test_gc_curated_memory_without_sessions_is_preserved() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        let workspace_dir = global_dir.join("current-ws");
        let storage = MemoryStorage::with_paths(global_dir.clone(), workspace_dir);

        // A workspace with MEMORY.md and index.sqlite but no sessions/
        let ws = global_dir.join("orphan-ab123456");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(ws.join("MEMORY.md"), "# Project").unwrap();
        std::fs::write(ws.join("index.sqlite"), "").unwrap();
        set_dir_mtime_days_ago(&ws, 31);

        let removed = storage.gc(30).unwrap();
        assert_eq!(removed, 0, "curated memory must survive retention");
        assert!(ws.exists());
    }

    #[test]
    fn test_gc_skips_current_workspace() {
        let tmp = TempDir::new().unwrap();
        let global_dir = tmp.path().join("memory");
        // workspace_dir points at a real directory inside global_dir
        let workspace_dir = global_dir.join("my-project-ab123456");
        let storage = MemoryStorage::with_paths(global_dir.clone(), workspace_dir.clone());

        // Create the current workspace: old, no sessions, so it would qualify for GC
        std::fs::create_dir_all(&workspace_dir).unwrap();
        std::fs::write(workspace_dir.join("MEMORY.md"), "# My project").unwrap();
        set_dir_mtime_days_ago(&workspace_dir, 60);

        // Create another old empty workspace that SHOULD be removed
        let other = global_dir.join("other-cd123456");
        std::fs::create_dir_all(&other).unwrap();
        set_dir_mtime_days_ago(&other, 31);

        let removed = storage.gc(30).unwrap();
        assert_eq!(removed, 1, "only the other workspace should be removed");
        assert!(workspace_dir.exists(), "current workspace must survive GC");
        assert!(!other.exists());
    }

    // -----------------------------------------------------------------------
    // is_empty_workspace / is_older_than unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_empty_workspace_no_sessions_dir() {
        let tmp = TempDir::new().unwrap();
        let ws = tmp.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        assert!(is_empty_workspace(&ws));
    }

    #[test]
    fn test_is_empty_workspace_empty_sessions_dir() {
        let tmp = TempDir::new().unwrap();
        let ws = tmp.path().join("ws");
        std::fs::create_dir_all(ws.join("sessions")).unwrap();
        assert!(!is_empty_workspace(&ws));
    }

    #[test]
    fn test_is_empty_workspace_with_session_files() {
        let tmp = TempDir::new().unwrap();
        let ws = tmp.path().join("ws");
        let sessions = ws.join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        std::fs::write(sessions.join("2026-01-01-test-sess1234.md"), "log").unwrap();
        assert!(!is_empty_workspace(&ws));
    }

    #[test]
    fn test_is_older_than_new_dir() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("fresh");
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!is_older_than(&dir, 1));
    }

    #[test]
    fn test_is_older_than_old_dir() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("old");
        std::fs::create_dir_all(&dir).unwrap();
        set_dir_mtime_days_ago(&dir, 10);
        assert!(is_older_than(&dir, 7));
        assert!(!is_older_than(&dir, 15));
    }

    #[test]
    fn test_total_chunk_count_missing_and_empty_index() {
        let tmp = TempDir::new().unwrap();
        let storage = MemoryStorage::with_paths(
            tmp.path().join("memory"),
            tmp.path().join("memory").join("test_ws"),
        );

        // A missing index counts as 0, and the journal-safe open must never create it
        assert_eq!(storage.total_chunk_count(), 0);
        assert!(!storage.workspace_dir().join("index.sqlite").exists());

        let _idx = crate::index::MemoryIndex::open_or_create(
            &storage.workspace_dir().join("index.sqlite"),
            storage.clone(),
            fuigo_config_types::MemoryIndexConfig::default(),
            64,
        )
        .unwrap();
        assert_eq!(storage.total_chunk_count(), 0);
    }
}

fn initialize_file(path: &Path, content: impl AsRef<str>) -> std::io::Result<()> {
    update_file(path, |old| {
        if old.is_empty() {
            content.as_ref().to_owned()
        } else {
            old.to_owned()
        }
    })
}

#[cfg(test)]
mod repair_tests {
    use super::*;
    #[test]
    fn full_session_ids_do_not_collide() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = MemoryStorage::with_paths(tmp.path().into(), tmp.path().join("ws"));
        let a = storage
            .write_daily_log("2026-09-07", "flush", "01a07abb-aaaa", "first", false)
            .unwrap();
        let b = storage
            .write_daily_log("2026-09-07", "flush", "01a07abb-bbbb", "second", false)
            .unwrap();
        assert_ne!(a, b);
        assert_eq!(std::fs::read_to_string(a).unwrap(), "first");
    }
    #[test]
    fn sibling_read_is_denied() {
        let tmp = tempfile::tempdir().unwrap();
        let a = MemoryStorage::with_paths(tmp.path().into(), tmp.path().join("a"));
        let b = MemoryStorage::with_paths(tmp.path().into(), tmp.path().join("b"));
        b.write_long_term(MemoryScope::Workspace, "private sibling")
            .unwrap();
        assert_eq!(
            a.read_file(&b.workspace_memory_file(), None, None)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(a.classify_source(&b.workspace_memory_file()), "denied");
    }
    #[test]
    fn concurrent_appends_preserve_every_record() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = MemoryStorage::with_paths(tmp.path().into(), tmp.path().join("ws"));
        let handles: Vec<_> = (0..16)
            .map(|i| {
                let storage = storage.clone();
                std::thread::spawn(move || {
                    storage
                        .append_to_memory(MemoryScope::Workspace, &format!("record-{i:02}"))
                        .unwrap()
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let text = storage
            .read_file(&storage.workspace_memory_file(), None, None)
            .unwrap();
        for i in 0..16 {
            assert_eq!(text.matches(&format!("record-{i:02}")).count(), 1);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(storage.workspace_memory_file())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn interrupted_update_preserves_original() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("MEMORY.md");
        update_file(&path, |_| "complete original".into()).unwrap();
        let result =
            std::panic::catch_unwind(|| update_file(&path, |_| panic!("synthetic interruption")));
        assert!(result.is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "complete original");
        update_file(&path, |_| "complete replacement".into()).unwrap();
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            "complete replacement"
        );
    }
    #[test]
    fn clear_invalidates_inflight_writes_but_allows_new_capture() {
        let tmp = tempfile::tempdir().unwrap();
        let storage =
            MemoryStorage::with_paths(tmp.path().join("memory"), tmp.path().join("memory/ws"));
        let before = storage.generation().unwrap();
        storage.clear_workspace().unwrap();
        assert!(
            storage
                .with_generation(before, || storage
                    .write_long_term(MemoryScope::Workspace, "## Stale"))
                .is_err()
        );
        assert!(!storage.workspace_memory_file().exists());
        let current = storage.generation().unwrap();
        storage
            .with_generation(current, || {
                storage.write_long_term(MemoryScope::Workspace, "## Fresh")
            })
            .unwrap();
        storage.clear_global().unwrap();
        assert!(
            storage
                .with_generation(current, || storage
                    .write_long_term(MemoryScope::Workspace, "## Stale again"))
                .is_err()
        );
        assert_eq!(
            std::fs::read_to_string(storage.workspace_memory_file()).unwrap(),
            "## Fresh"
        );
    }
    #[test]
    fn recovery_markdown_is_never_readable_or_listed() {
        let tmp = tempfile::tempdir().unwrap();
        let storage =
            MemoryStorage::with_paths(tmp.path().join("memory"), tmp.path().join("memory/ws"));
        let recovery = storage.workspace_dir().join(".memory-recovery/old.md");
        std::fs::create_dir_all(recovery.parent().unwrap()).unwrap();
        std::fs::write(&recovery, "## Deleted fact").unwrap();
        assert!(!storage.allows_path(&recovery));
        assert!(storage.read_file(&recovery, None, None).is_err());
        assert!(!storage.list_memory_files().unwrap().contains(&recovery));
    }
    #[cfg(unix)]
    #[test]
    fn scope_roots_cannot_be_redirected_by_symlinks() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let global = tmp.path().join("memory");
        let sibling = global.join("sibling");
        std::fs::create_dir_all(&sibling).unwrap();
        let private = sibling.join("MEMORY.md");
        std::fs::write(&private, "## Sibling fact").unwrap();
        let storage = MemoryStorage::with_paths(global.clone(), global.join("workspace"));
        symlink(&private, storage.global_memory_file()).unwrap();
        assert!(!storage.allows_path(&private));
        assert!(!storage.allows_path(&storage.global_memory_file()));
        symlink(&sibling, storage.workspace_dir()).unwrap();
        assert!(!storage.allows_path(&storage.workspace_memory_file()));
    }
}
