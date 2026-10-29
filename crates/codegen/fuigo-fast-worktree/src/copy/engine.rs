//! Parallel copy engine.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use crossbeam::channel::{Sender, bounded};
use dashmap::{DashMap, DashSet};
use ignore::{WalkBuilder, WalkState};
use tokio_util::sync::CancellationToken;

use crate::copy::shard::shard_for_path;
use crate::copy::skip::build_skip_matcher;
use crate::copy::types::{
    CopyEntry, CopyEntryKind, CopyFailure, CopyStats, ParallelCopyConfig, ParallelCopyResult,
    is_storage_full,
};
use crate::copy::worker::{WorkerCtx, run_worker};

/// Copy files from source to dest using parallel workers with hash-based sharding.
///
/// Returns both stats and the set of paths that were copied (for deduplication).
/// Maximum worker threads to prevent FD exhaustion on macOS.
/// macOS default ulimit is 256. With 8 workers + 8 walker threads = 16 threads,
/// each can have ~10 FDs open (deeply nested dirs), leaving headroom for other uses.
#[cfg(target_os = "macos")]
const MAX_PARALLEL_WORKERS: usize = 8;

#[cfg(not(target_os = "macos"))]
const MAX_PARALLEL_WORKERS: usize = 32;

pub(crate) fn copy_parallel(
    source: &Path,
    dest: &Path,
    config: ParallelCopyConfig,
    cancellation_token: CancellationToken,
) -> Result<ParallelCopyResult> {
    let num_workers = if config.num_workers == 0 {
        num_cpus::get().min(MAX_PARALLEL_WORKERS)
    } else {
        config.num_workers.min(MAX_PARALLEL_WORKERS)
    };

    // Build skip patterns matcher.
    let skip_matcher = if !config.skip_patterns.is_empty() {
        Some(build_skip_matcher(&config.skip_patterns)?)
    } else {
        None
    };

    // Create bounded channels for each shard.
    let channels: Vec<_> = (0..num_workers)
        .map(|_| bounded::<CopyEntry>(config.channel_buffer))
        .collect();

    // Shared atomic counters for stats.
    let files_copied = Arc::new(AtomicU64::new(0));
    let dirs_created = Arc::new(AtomicU64::new(0));
    let symlinks_copied = Arc::new(AtomicU64::new(0));
    let files_skipped = Arc::new(AtomicU64::new(0));
    let issues: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let failed: Arc<std::sync::Mutex<Vec<CopyFailure>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let unscoped: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));

    // Track successfully copied paths for deduplication.
    let copied_paths: Arc<DashSet<std::path::PathBuf>> = Arc::new(DashSet::new());

    // Collect file metadata for index updates.
    let file_metadata: Arc<DashMap<std::path::PathBuf, std::fs::Metadata>> =
        Arc::new(DashMap::new());

    // Spawn worker threads.
    let workers: Vec<_> = channels
        .iter()
        .map(|(_, rx)| {
            let rx = rx.clone();
            let ctx = WorkerCtx {
                source: source.to_path_buf(),
                dest: dest.to_path_buf(),
                files_copied: Arc::clone(&files_copied),
                dirs_created: Arc::clone(&dirs_created),
                symlinks_copied: Arc::clone(&symlinks_copied),
                issues: Arc::clone(&issues),
                failed: Arc::clone(&failed),
                copied_paths: Arc::clone(&copied_paths),
                file_metadata: Arc::clone(&file_metadata),
            };

            std::thread::spawn(move || run_worker(rx, ctx))
        })
        .collect();

    // Collect senders for the walker.
    let senders: Vec<Sender<CopyEntry>> = channels.iter().map(|(tx, _)| tx.clone()).collect();

    // Build the walker.
    // IMPORTANT: Limit walker threads to match num_workers to avoid FD exhaustion.
    // On macOS, the default FD limit (256) can easily be exceeded when:
    // - num_cpus walker threads (default) × directories open per thread
    // - Plus num_workers copy workers × files being copied
    // Deep directory trees (15+ levels) amplify this significantly.
    let mut builder = WalkBuilder::new(source);
    builder
        .hidden(false) // Include hidden files.
        .git_ignore(config.respect_gitignore)
        .git_global(false) // Never use global gitignore (~/.config/git/ignore) —
        // it contains personal preferences irrelevant to worktree creation.
        .git_exclude(false) // Never use .git/info/exclude — external tooling
        // can append broad patterns (*.min.js, *.zip) that
        // incorrectly skip git-tracked files. The `ignore` crate doesn't
        // check tracking status, so tracked files matching these patterns
        // get silently dropped during the copy.
        .threads(num_workers) // Limit walker parallelism to avoid FD exhaustion
        .filter_entry(|entry| {
            // Always skip .git directory.
            entry.file_name() != ".git"
        });

    let walker = builder.build_parallel();

    // Clone data for the walker closure.
    let source_for_walker = source.to_path_buf();
    let skip_files = config.skip_files.clone();
    let files_skipped_walker = Arc::clone(&files_skipped);
    let skip_matcher = skip_matcher.map(Arc::new);
    let issues_walker = Arc::clone(&issues);
    let failed_walker = Arc::clone(&failed);
    let unscoped_walker = Arc::clone(&unscoped);

    // Run the parallel walker.
    walker.run(|| {
        let senders = senders.clone();
        let source = source_for_walker.clone();
        let n = num_workers;
        let skip_files = skip_files.clone();
        let files_skipped = Arc::clone(&files_skipped_walker);
        let skip_matcher = skip_matcher.clone();
        let issues = Arc::clone(&issues_walker);
        let failed = Arc::clone(&failed_walker);
        let unscoped = Arc::clone(&unscoped_walker);
        let cancellation_token = cancellation_token.clone();

        Box::new(move |entry_result| {
            // Check for cancellation
            if cancellation_token.is_cancelled() {
                return WalkState::Quit;
            }

            let entry = match entry_result {
                Ok(e) => e,
                Err(err) => {
                    record_walk_error(&source, &err, &issues, &failed, &unscoped);
                    return WalkState::Continue;
                }
            };

            // Get relative path.
            let rel_path = match entry.path().strip_prefix(&source) {
                Ok(p) => p.to_path_buf(),
                Err(_) => return WalkState::Continue,
            };

            // Skip root.
            if rel_path.as_os_str().is_empty() {
                return WalkState::Continue;
            }

            // Check if this file should be skipped (already copied or explicitly skipped).
            if let Some(ref skip) = skip_files
                && skip.contains(&rel_path)
            {
                files_skipped.fetch_add(1, Ordering::Relaxed);
                return WalkState::Continue;
            }

            // Check skip patterns.
            if let Some(ref matcher) = skip_matcher
                && matcher.is_match(&rel_path)
            {
                files_skipped.fetch_add(1, Ordering::Relaxed);
                return WalkState::Continue;
            }

            let file_type = entry.file_type();
            let is_dir = file_type.as_ref().map(|ft| ft.is_dir()).unwrap_or(false);
            let is_symlink = file_type
                .as_ref()
                .map(|ft| ft.is_symlink())
                .unwrap_or(false);

            let kind = if is_dir {
                CopyEntryKind::Dir
            } else if is_symlink {
                CopyEntryKind::Symlink
            } else {
                CopyEntryKind::File
            };

            // Compute shard and send.
            let shard = shard_for_path(&rel_path, n);
            let _ = senders[shard].send(CopyEntry { rel_path, kind });

            WalkState::Continue
        })
    });

    // Close senders to signal workers to finish.
    drop(senders);
    for (tx, _) in channels {
        drop(tx);
    }

    // Wait for all workers.
    for worker in workers {
        let _ = worker.join();
    }

    // Collect issues.
    drop(issues_walker);
    drop(failed_walker);
    drop(unscoped_walker);
    let issues = match Arc::try_unwrap(issues) {
        Ok(mutex) => mutex.into_inner().unwrap_or_default(),
        Err(arc) => arc.lock().unwrap().clone(),
    };

    let failed = match Arc::try_unwrap(failed) {
        Ok(mutex) => mutex.into_inner().unwrap_or_default(),
        Err(arc) => arc.lock().unwrap().clone(),
    };

    let unscoped_walk_error = unscoped.lock().unwrap().take();

    let copied_paths = match Arc::try_unwrap(copied_paths) {
        Ok(set) => set,
        Err(arc) => {
            let mut set = DashSet::new();
            set.extend(arc.iter().map(|p| p.clone()));
            set
        }
    };

    let file_metadata = match Arc::try_unwrap(file_metadata) {
        Ok(map) => map,
        Err(arc) => {
            let map = DashMap::new();
            for entry in arc.iter() {
                map.insert(entry.key().clone(), entry.value().clone());
            }
            map
        }
    };

    Ok(ParallelCopyResult {
        stats: CopyStats {
            files_copied: files_copied.load(Ordering::Relaxed),
            dirs_created: dirs_created.load(Ordering::Relaxed),
            symlinks_copied: symlinks_copied.load(Ordering::Relaxed),
            files_skipped: files_skipped.load(Ordering::Relaxed),
            issues,
            failed,
            unscoped_walk_error,
        },
        copied_paths,
        file_metadata,
    })
}

/// The path an `ignore` walker error is about, if it carries one.
fn walk_error_path(err: &ignore::Error) -> Option<&Path> {
    match err {
        ignore::Error::WithPath { path, .. } => Some(path),
        ignore::Error::WithLineNumber { err, .. } | ignore::Error::WithDepth { err, .. } => {
            walk_error_path(err)
        }
        ignore::Error::Loop { child, .. } => Some(child),
        _ => None,
    }
}

/// Whether the walker error means entries could not be visited (an unreadable
/// directory, a symlink loop) rather than a bad ignore-file line, which only
/// loses a pattern.
fn walk_error_is_unvisited(err: &ignore::Error) -> bool {
    match err {
        ignore::Error::Partial(_)
        | ignore::Error::Glob { .. }
        | ignore::Error::UnrecognizedFileType(_)
        | ignore::Error::InvalidDefinition => false,
        ignore::Error::WithPath { err, .. }
        | ignore::Error::WithLineNumber { err, .. }
        | ignore::Error::WithDepth { err, .. } => walk_error_is_unvisited(err),
        _ => true,
    }
}

/// Whether a walker error is a full disk. `ignore::Error` has no `source()`
/// chain, so unwrap its wrappers and hand the inner `io::Error` to the shared
/// classifier.
fn walk_error_storage_full(err: &ignore::Error) -> bool {
    match err {
        ignore::Error::Io(e) => is_storage_full(e),
        ignore::Error::WithPath { err, .. }
        | ignore::Error::WithLineNumber { err, .. }
        | ignore::Error::WithDepth { err, .. } => walk_error_storage_full(err),
        ignore::Error::Partial(errs) => errs.iter().any(walk_error_storage_full),
        _ => false,
    }
}

/// Report a walker error instead of dropping it: it is an issue, and when it
/// loses entries it is also a failure. A named path is a failure of that path
/// (and everything beneath it); an error that loses entries without naming a
/// path (a directory read failing mid-way, the root) sets `unscoped`, so the
/// caller checks every tracked file against the destination rather than assume
/// the lost entries were untracked. A full disk is always a failure.
fn record_walk_error(
    source: &Path,
    err: &ignore::Error,
    issues: &std::sync::Mutex<Vec<String>>,
    failed: &std::sync::Mutex<Vec<CopyFailure>>,
    unscoped: &std::sync::Mutex<Option<String>>,
) {
    let rel = walk_error_path(err)
        .and_then(|p| p.strip_prefix(source).ok())
        .filter(|rel| !rel.as_os_str().is_empty());
    let message = match rel {
        Some(rel) => format!("walk {}: {}", rel.display(), err),
        None => format!("walk: {err}"),
    };
    issues.lock().unwrap().push(message.clone());
    let storage_full = walk_error_storage_full(err);
    if storage_full || walk_error_is_unvisited(err) {
        match rel {
            Some(rel) => failed.lock().unwrap().push(CopyFailure {
                rel_path: rel.to_path_buf(),
                message,
                storage_full,
            }),
            None if storage_full => failed.lock().unwrap().push(CopyFailure {
                rel_path: std::path::PathBuf::new(),
                message,
                storage_full,
            }),
            None => {
                unscoped.lock().unwrap().get_or_insert(message);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::copy::types::ParallelCopyConfig;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_copy_parallel_simple() {
        let src = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();

        // Create some files
        std::fs::write(src.path().join("file1.txt"), "content1").unwrap();
        std::fs::write(src.path().join("file2.txt"), "content2").unwrap();
        std::fs::create_dir(src.path().join("subdir")).unwrap();
        std::fs::write(src.path().join("subdir/file3.txt"), "content3").unwrap();

        let config = ParallelCopyConfig {
            num_workers: 2,
            channel_buffer: 64,
            respect_gitignore: false,
            ..Default::default()
        };

        let result =
            copy_parallel(src.path(), dest.path(), config, CancellationToken::new()).unwrap();

        assert_eq!(result.stats.files_copied, 3);
        assert!(dest.path().join("file1.txt").exists());
        assert!(dest.path().join("file2.txt").exists());
        assert!(dest.path().join("subdir/file3.txt").exists());
        assert_eq!(result.copied_paths.len(), 4); // 3 files + 1 dir
    }

    #[test]
    fn test_copy_parallel_with_skip() {
        let src = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();

        std::fs::write(src.path().join("keep.txt"), "keep").unwrap();
        std::fs::write(src.path().join("skip.txt"), "skip").unwrap();

        let skip = DashSet::new();
        skip.insert(PathBuf::from("skip.txt"));

        let config = ParallelCopyConfig {
            num_workers: 2,
            channel_buffer: 64,
            skip_files: Some(Arc::new(skip)),
            respect_gitignore: false,
            ..Default::default()
        };

        let result =
            copy_parallel(src.path(), dest.path(), config, CancellationToken::new()).unwrap();

        assert_eq!(result.stats.files_copied, 1);
        assert_eq!(result.stats.files_skipped, 1);
        assert!(dest.path().join("keep.txt").exists());
        assert!(!dest.path().join("skip.txt").exists());
    }

    #[test]
    fn test_copy_parallel_only_ignored() {
        fuigo_test_utils::require_git!();
        let src = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();

        // Create a tracked file
        std::fs::write(src.path().join("tracked.txt"), "tracked").unwrap();

        // Create an "ignored" directory
        std::fs::create_dir(src.path().join("node_modules")).unwrap();
        std::fs::write(src.path().join("node_modules/pkg.txt"), "pkg").unwrap();

        // Create .gitignore
        std::fs::write(src.path().join(".gitignore"), "node_modules/").unwrap();

        // Initialize git repo
        std::process::Command::new("git")
            .current_dir(src.path())
            .args(["init"])
            .output()
            .unwrap();

        // Copy only ignored files (skip unignored paths)
        let config = ParallelCopyConfig {
            num_workers: 2,
            channel_buffer: 64,
            skip_files: Some(Arc::new(
                crate::copy::collect_unignored_paths(src.path(), 1).unwrap(),
            )),
            ..Default::default()
        };

        let _result =
            copy_parallel(src.path(), dest.path(), config, CancellationToken::new()).unwrap();

        // Should have copied node_modules but not tracked.txt
        assert!(dest.path().join("node_modules/pkg.txt").exists());
        assert!(!dest.path().join("tracked.txt").exists());
    }

    #[test]
    fn test_copy_parallel_with_cancellation_token_cancelled() {
        use tokio_util::sync::CancellationToken;

        let src = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();

        // Create some files
        std::fs::write(src.path().join("file1.txt"), "content1").unwrap();
        std::fs::write(src.path().join("file2.txt"), "content2").unwrap();
        std::fs::write(src.path().join("file3.txt"), "content3").unwrap();

        // Create cancellation token - cancel immediately (pre-cancelled)
        let token = CancellationToken::new();
        token.cancel();

        let config = ParallelCopyConfig {
            num_workers: 2,
            channel_buffer: 64,
            respect_gitignore: false,
            ..Default::default()
        };

        // Pass the PRE-CANCELLED token (not a fresh one): the walker checks
        // cancellation first thing in every callback and quits, so nothing is
        // ever queued to the workers.
        let result = copy_parallel(src.path(), dest.path(), config, token).unwrap();

        assert_eq!(
            result.stats.files_copied, 0,
            "a pre-cancelled token must short-circuit the copy before any file is written"
        );
    }

    #[test]
    fn test_copy_parallel_cancellation_token_not_cancelled() {
        use tokio_util::sync::CancellationToken;

        let src = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();

        // Create some files
        std::fs::write(src.path().join("file1.txt"), "content1").unwrap();
        std::fs::write(src.path().join("file2.txt"), "content2").unwrap();

        let config = ParallelCopyConfig {
            num_workers: 2,
            channel_buffer: 64,
            respect_gitignore: false,
            ..Default::default()
        };

        let result =
            copy_parallel(src.path(), dest.path(), config, CancellationToken::new()).unwrap();

        // All files should be copied
        assert_eq!(result.stats.files_copied, 2);
        assert!(dest.path().join("file1.txt").exists());
        assert!(dest.path().join("file2.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_copy_parallel_replicates_symlink() {
        // Exercises the worker's CopyEntryKind::Symlink arm: a symlink in the
        // source tree must be replicated AS a symlink (not dereferenced).
        let src = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();

        std::fs::write(src.path().join("target.txt"), "content").unwrap();
        std::os::unix::fs::symlink("target.txt", src.path().join("link.txt")).unwrap();

        let config = ParallelCopyConfig {
            num_workers: 2,
            channel_buffer: 64,
            respect_gitignore: false,
            ..Default::default()
        };

        let result =
            copy_parallel(src.path(), dest.path(), config, CancellationToken::new()).unwrap();

        assert_eq!(result.stats.symlinks_copied, 1);
        let meta = std::fs::symlink_metadata(dest.path().join("link.txt")).unwrap();
        assert!(
            meta.file_type().is_symlink(),
            "link must be replicated as a symlink"
        );
        assert_eq!(
            std::fs::read_link(dest.path().join("link.txt")).unwrap(),
            PathBuf::from("target.txt")
        );
    }

    #[test]
    fn copy_failure_is_reported_with_its_path_and_the_rest_still_copies() {
        let src = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        std::fs::write(src.path().join("blocked.txt"), "x").unwrap();
        std::fs::write(src.path().join("fine.txt"), "y").unwrap();
        // A directory where the file must go makes that one copy fail.
        std::fs::create_dir(dest.path().join("blocked.txt")).unwrap();

        let config = ParallelCopyConfig {
            num_workers: 2,
            channel_buffer: 64,
            respect_gitignore: false,
            ..Default::default()
        };
        let result =
            copy_parallel(src.path(), dest.path(), config, CancellationToken::new()).unwrap();

        assert_eq!(result.stats.failed.len(), 1, "{:?}", result.stats.failed);
        assert_eq!(result.stats.failed[0].rel_path, PathBuf::from("blocked.txt"));
        assert!(!result.stats.failed[0].storage_full);
        assert_eq!(result.stats.issues.len(), 1);
        assert!(result.stats.issues[0].starts_with("copy blocked.txt:"));
        assert!(!result.copied_paths.contains(&PathBuf::from("blocked.txt")));
        assert!(dest.path().join("fine.txt").exists());
    }

    #[test]
    fn walker_error_is_an_issue_and_an_unvisited_failure() {
        let issues = std::sync::Mutex::new(Vec::new());
        let failed = std::sync::Mutex::new(Vec::new());
        let unscoped = std::sync::Mutex::new(None);
        let err = ignore::Error::WithPath {
            path: PathBuf::from("/src/locked"),
            err: Box::new(ignore::Error::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            ))),
        };
        record_walk_error(Path::new("/src"), &err, &issues, &failed, &unscoped);

        let issues = issues.into_inner().unwrap();
        let failed = failed.into_inner().unwrap();
        assert_eq!(issues.len(), 1);
        assert!(issues[0].starts_with("walk locked:"), "{issues:?}");
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].rel_path, PathBuf::from("locked"));
    }

    #[test]
    fn ignore_file_syntax_error_warns_but_is_not_an_unvisited_failure() {
        let issues = std::sync::Mutex::new(Vec::new());
        let failed = std::sync::Mutex::new(Vec::new());
        let unscoped = std::sync::Mutex::new(None);
        let err = ignore::Error::WithPath {
            path: PathBuf::from("/src/.gitignore"),
            err: Box::new(ignore::Error::Partial(vec![ignore::Error::Glob {
                glob: Some("[".into()),
                err: "unclosed".into(),
            }])),
        };
        record_walk_error(Path::new("/src"), &err, &issues, &failed, &unscoped);

        assert_eq!(issues.into_inner().unwrap().len(), 1);
        assert!(failed.into_inner().unwrap().is_empty());
    }

    fn record(err: &ignore::Error) -> (Vec<CopyFailure>, Option<String>) {
        let issues = std::sync::Mutex::new(Vec::new());
        let failed = std::sync::Mutex::new(Vec::new());
        let unscoped = std::sync::Mutex::new(None);
        record_walk_error(Path::new("/src"), err, &issues, &failed, &unscoped);
        assert_eq!(issues.into_inner().unwrap().len(), 1);
        (failed.into_inner().unwrap(), unscoped.into_inner().unwrap())
    }

    #[test]
    fn pathless_walker_io_error_is_unscoped_not_dropped() {
        // What `ignore` reports for a read_dir failure part-way through a directory.
        let err = ignore::Error::WithDepth {
            depth: 2,
            err: Box::new(ignore::Error::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            ))),
        };
        let (failed, unscoped) = record(&err);
        assert!(failed.is_empty());
        assert!(unscoped.expect("unscoped").starts_with("walk:"));
    }

    #[test]
    fn root_walker_error_is_unscoped() {
        let err = ignore::Error::WithPath {
            path: PathBuf::from("/src"),
            err: Box::new(ignore::Error::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            ))),
        };
        let (failed, unscoped) = record(&err);
        assert!(failed.is_empty());
        assert!(unscoped.is_some());
    }

    #[test]
    fn walker_storage_full_is_a_storage_full_failure_with_or_without_a_path() {
        let full = || ignore::Error::Io(std::io::Error::from(std::io::ErrorKind::StorageFull));
        let (failed, unscoped) = record(&ignore::Error::WithPath {
            path: PathBuf::from("/src/dir"),
            err: Box::new(full()),
        });
        assert!(unscoped.is_none());
        assert_eq!(failed.len(), 1);
        assert!(failed[0].storage_full);
        assert_eq!(failed[0].rel_path, PathBuf::from("dir"));

        let (failed, unscoped) = record(&ignore::Error::WithDepth {
            depth: 1,
            err: Box::new(full()),
        });
        assert!(unscoped.is_none());
        assert_eq!(failed.len(), 1);
        assert!(failed[0].storage_full);
    }
}
