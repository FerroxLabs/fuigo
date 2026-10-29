//! Shared types for copy operations.

use std::fs::Metadata;
use std::path::PathBuf;
use std::sync::Arc;

use dashmap::{DashMap, DashSet};

/// A structured report about dirty (modified/untracked/deleted) files in the source worktree.
#[derive(Clone, Debug, Default)]
pub struct DirtyFilesReport {
    pub modified_files: u64,
    pub untracked_files: u64,
    pub deleted_files: u64,
}

/// Statistics from a copy operation.
#[derive(Clone, Debug, Default)]
pub struct CopyStats {
    pub files_copied: u64,
    pub dirs_created: u64,
    pub symlinks_copied: u64,
    pub files_skipped: u64,
    /// Non-fatal issues encountered while copying (human-readable, one per problem).
    pub issues: Vec<String>,
    /// Entries that could not be copied at all, with the reason. A subset of
    /// `issues` kept structured so the caller can tell which of them are tracked
    /// by git (those abort worktree creation; the rest only warn).
    pub failed: Vec<CopyFailure>,
    /// Set when the walker hit an error that left entries unvisited but named no
    /// path (a directory read that failed mid-way, an error on the root itself),
    /// so it is unknown which entries were lost. Holds that error's text. The
    /// caller then checks the tracked files against the destination.
    pub unscoped_walk_error: Option<String>,
}

/// One entry the copy engine failed to replicate.
#[derive(Clone, Debug)]
pub struct CopyFailure {
    /// Path relative to the copy source root. For a walker error on a directory
    /// this is the directory, which covers everything beneath it.
    pub rel_path: PathBuf,
    /// The human-readable issue line (also present in `CopyStats::issues`).
    pub message: String,
    /// The failure was a full disk (`ErrorKind::StorageFull`).
    pub storage_full: bool,
}

impl CopyStats {
    /// Merge another stats into this one.
    pub fn merge(&mut self, other: CopyStats) {
        self.files_copied += other.files_copied;
        self.dirs_created += other.dirs_created;
        self.symlinks_copied += other.symlinks_copied;
        self.files_skipped += other.files_skipped;
        self.issues.extend(other.issues);
        self.failed.extend(other.failed);
        if self.unscoped_walk_error.is_none() {
            self.unscoped_walk_error = other.unscoped_walk_error;
        }
    }
}

/// The one classifier that decides whether an error is a full disk, for every
/// producer (worker, mode-setting, walker). Looks for a typed
/// `ErrorKind::StorageFull` anywhere in the `source()` chain.
pub(crate) fn is_storage_full(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if let Some(io) = e.downcast_ref::<std::io::Error>()
            && io.kind() == std::io::ErrorKind::StorageFull
        {
            return true;
        }
        cur = e.source();
    }
    false
}

/// Kind of filesystem entry to replicate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CopyEntryKind {
    File,
    Dir,
    Symlink,
}

/// Entry to be processed by a worker.
#[derive(Debug)]
pub(crate) struct CopyEntry {
    pub(crate) rel_path: PathBuf,
    pub(crate) kind: CopyEntryKind,
}

/// Configuration for the parallel copy operation.
#[derive(Clone, Debug, Default)]
pub(crate) struct ParallelCopyConfig {
    /// Number of parallel workers (0 = num_cpus)
    pub num_workers: usize,
    /// Channel buffer size per shard
    pub channel_buffer: usize,
    /// Files to skip (relative paths)
    pub skip_files: Option<Arc<DashSet<PathBuf>>>,
    /// Whether to respect `.gitignore` rules
    pub respect_gitignore: bool,
    /// Additional patterns to skip (glob patterns)
    pub skip_patterns: Vec<String>,
}

/// Result of a parallel copy operation, including stats and the set of copied paths.
#[derive(Clone, Debug, Default)]
pub(crate) struct ParallelCopyResult {
    pub stats: CopyStats,
    /// All relative paths that were successfully copied (for deduplication in subsequent copies).
    pub copied_paths: DashSet<PathBuf>,
    /// Metadata for files that were copied (for index updates). Only regular files, not symlinks/dirs.
    pub file_metadata: DashMap<PathBuf, Metadata>,
}
