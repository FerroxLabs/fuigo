//! Which copy failures must abort worktree creation.
//!
//! A tracked file that did not reach the new worktree is a worktree that is not
//! the one the user asked for: git would show the file as deleted. That aborts
//! the create with a typed [`TrackedCopyError`]. A failure on an untracked or
//! ignored file only warns (it stays in `CopyStats::issues`). A full disk aborts
//! whatever the file, as it always has.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use dashmap::DashSet;

use crate::copy::types::CopyStats;

/// Most file names quoted in the error text; the full list is in the log.
const MAX_NAMED: usize = 3;

/// The create stopped because tracked files could not be copied into the new
/// worktree. Its `Display` is the one line the user sees; every failure is
/// logged by [`check_copy_failures`].
#[derive(Debug)]
pub struct TrackedCopyError {
    /// Up to [`MAX_NAMED`] failed tracked paths.
    pub paths: Vec<PathBuf>,
    /// Count of tracked paths that failed (or of all failures, on a full disk).
    pub total: usize,
    /// First failure's issue text, e.g. `copy a/b.txt: Permission denied (os error 13)`.
    pub first_reason: String,
    disk_full: Option<std::io::Error>,
}

impl std::fmt::Display for TrackedCopyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let noun = match (self.disk_full.is_some(), self.total) {
            (true, 1) => "file",
            (true, _) => "files",
            (false, 1) => "tracked file",
            (false, _) => "tracked files",
        };
        write!(
            f,
            "couldn't copy {} {noun} into the worktree: {}",
            self.total, self.first_reason
        )?;
        if self.total > 1 {
            write!(f, " (and {} more; see the log)", self.total - 1)?;
        }
        Ok(())
    }
}

impl std::error::Error for TrackedCopyError {
    /// A full disk keeps its typed `StorageFull` root so the disk-full path
    /// ([`crate::OUT_OF_DISK_CONTEXT`]) still recognises it.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.disk_full
            .as_ref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

/// Log every copy problem, then fail with [`TrackedCopyError`] if a tracked file
/// (or the disk) is among them. `source_root` is the git root the copy read from
/// and `dest` the tree it wrote to. `skipped` is the set the copy deliberately
/// did not copy (relative paths).
pub(crate) fn check_copy_failures(
    source_root: &Path,
    dest: &Path,
    skipped: Option<&DashSet<PathBuf>>,
    stats: &CopyStats,
) -> Result<()> {
    for issue in &stats.issues {
        tracing::warn!(issue = %issue, "worktree copy problem");
    }
    if stats.failed.is_empty() && stats.unscoped_walk_error.is_none() {
        return Ok(());
    }

    let disk_full = stats.failed.iter().any(|f| f.storage_full);
    let mut aborting: Vec<(PathBuf, String)> = Vec::new();
    if disk_full {
        aborting.extend(
            stats
                .failed
                .iter()
                .map(|f| (f.rel_path.clone(), f.message.clone())),
        );
    } else {
        let index = load_index(source_root)?;
        let hit = tracked_failures(&index, stats);
        aborting.extend(
            stats
                .failed
                .iter()
                .filter(|f| hit.contains(&f.rel_path))
                .map(|f| (f.rel_path.clone(), f.message.clone())),
        );
        // A walker error that named no path (so it is unknown what it cost):
        // only now, on this error path, check each tracked file reached `dest`.
        if let Some(walk_error) = &stats.unscoped_walk_error {
            for rel in missing_tracked(&index, source_root, dest, skipped) {
                if aborting.iter().any(|(p, _)| *p == rel) {
                    continue;
                }
                let message = format!(
                    "tracked file {} was not copied after: {walk_error}",
                    rel.display()
                );
                aborting.push((rel, message));
            }
        }
    }

    let Some((_, first_reason)) = aborting.first() else {
        return Ok(());
    };
    let err = TrackedCopyError {
        paths: aborting
            .iter()
            .take(MAX_NAMED)
            .map(|(p, _)| p.clone())
            .collect(),
        total: aborting.len(),
        first_reason: first_reason.clone(),
        disk_full: disk_full.then(|| std::io::Error::from(std::io::ErrorKind::StorageFull)),
    };
    tracing::error!(error = %err, "worktree copy aborted");
    Err(anyhow::Error::new(err))
}

fn load_index(source_root: &Path) -> Result<gix::index::File> {
    let repo = gix::discover(source_root)
        .map_err(|e| anyhow::anyhow!("failed to discover git repo: {e}"))?;
    let index = repo
        .index_or_load_from_head()
        .map_err(|e| anyhow::anyhow!("failed to load git index: {e}"))
        .context("could not tell whether the files that failed to copy are tracked")?;
    Ok(index.into_owned())
}

/// A git index path as a native path, losslessly. Git stores `/`-separated
/// byte strings: on Unix those bytes are the file name verbatim (a `\` is an
/// ordinary character), on Windows `/` is the separator.
fn native_path(index_path: &[u8]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        PathBuf::from(std::ffi::OsStr::from_bytes(index_path))
    }
    #[cfg(not(unix))]
    {
        PathBuf::from(String::from_utf8_lossy(index_path).replace('/', "\\"))
    }
}

/// The failed paths that are at, or beneath, a path in the git index. Paths are
/// compared as native `Path`s (component-wise), never through a lossy string.
fn tracked_failures(index: &gix::index::File, stats: &CopyStats) -> HashSet<PathBuf> {
    let failed: HashSet<&Path> = stats.failed.iter().map(|f| f.rel_path.as_path()).collect();
    let mut hit: HashSet<PathBuf> = HashSet::new();
    for entry in index.entries() {
        let path = native_path(entry.path(index));
        // The path itself, then each ancestor directory.
        for ancestor in path.ancestors() {
            if !ancestor.as_os_str().is_empty() && failed.contains(ancestor) {
                hit.insert(ancestor.to_path_buf());
            }
        }
    }
    hit
}

/// Index entries that exist in the source, were not deliberately skipped, and
/// are absent from `dest`.
fn missing_tracked(
    index: &gix::index::File,
    source_root: &Path,
    dest: &Path,
    skipped: Option<&DashSet<PathBuf>>,
) -> Vec<PathBuf> {
    let mut missing = Vec::new();
    for entry in index.entries() {
        let rel = native_path(entry.path(index));
        if skipped.is_some_and(|s| s.contains(&rel)) {
            continue;
        }
        if std::fs::symlink_metadata(source_root.join(&rel)).is_err() {
            continue; // not in the source working tree (deleted, sparse): nothing to copy
        }
        if std::fs::symlink_metadata(dest.join(&rel)).is_err() {
            missing.push(rel);
        }
    }
    missing
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::copy::types::CopyFailure;
    use fuigo_test_utils::git::{git_commit_all, init_git_repo};

    fn failure(rel: &str, storage_full: bool) -> CopyFailure {
        CopyFailure {
            rel_path: PathBuf::from(rel),
            message: format!("copy {rel}: Permission denied (os error 13)"),
            storage_full,
        }
    }

    fn stats(failed: Vec<CopyFailure>) -> CopyStats {
        CopyStats {
            issues: failed.iter().map(|f| f.message.clone()).collect(),
            failed,
            ..Default::default()
        }
    }

    fn repo() -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        init_git_repo(dir.path());
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/tracked.txt"), "t").unwrap();
        std::fs::write(dir.path().join("top.txt"), "t").unwrap();
        git_commit_all(dir.path(), "initial");
        std::fs::write(dir.path().join("untracked.txt"), "u").unwrap();
        dir
    }

    #[test]
    fn no_failures_is_ok() {
        fuigo_test_utils::require_git!();
        let dir = repo();
        check_copy_failures(dir.path(), dir.path(), None, &CopyStats::default()).unwrap();
    }

    #[test]
    fn untracked_failure_only_warns() {
        fuigo_test_utils::require_git!();
        let dir = repo();
        check_copy_failures(dir.path(), dir.path(), None, &stats(vec![failure("untracked.txt", false)])).unwrap();
    }

    #[test]
    fn tracked_failure_aborts_with_typed_error() {
        fuigo_test_utils::require_git!();
        let dir = repo();
        let err = check_copy_failures(dir.path(), dir.path(), None,
            &stats(vec![
                failure("untracked.txt", false),
                failure("sub/tracked.txt", false),
            ]),
        )
        .unwrap_err();
        let typed = err.downcast_ref::<TrackedCopyError>().expect("typed error");
        assert_eq!(typed.total, 1);
        assert_eq!(typed.paths, vec![PathBuf::from("sub/tracked.txt")]);
        let text = err.to_string();
        assert!(text.contains("sub/tracked.txt"), "{text}");
        assert!(text.contains("copy 1 tracked file into"), "{text}");
        assert!(!text.contains("more"), "{text}");
    }

    #[test]
    fn failed_directory_covers_tracked_files_beneath_it() {
        fuigo_test_utils::require_git!();
        let dir = repo();
        let err = check_copy_failures(dir.path(), dir.path(), None, &stats(vec![failure("sub", false)])).unwrap_err();
        assert!(err.downcast_ref::<TrackedCopyError>().is_some());
    }

    #[test]
    fn several_failures_are_counted_in_one_line() {
        fuigo_test_utils::require_git!();
        let dir = repo();
        let err = check_copy_failures(dir.path(), dir.path(), None,
            &stats(vec![
                failure("sub/tracked.txt", false),
                failure("top.txt", false),
            ]),
        )
        .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("couldn't copy 2 tracked files"), "{text}");
        assert!(text.contains("(and 1 more; see the log)"), "{text}");
        assert!(!text.contains('\n'), "{text}");
    }

    #[test]
    fn disk_full_aborts_even_for_untracked_and_stays_typed() {
        fuigo_test_utils::require_git!();
        let dir = repo();
        let err = check_copy_failures(dir.path(), dir.path(), None, &stats(vec![failure("untracked.txt", true)]))
            .unwrap_err();
        assert!(
            err.chain().any(|c| c
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::StorageFull)),
            "typed StorageFull must stay in the chain: {err:#}"
        );
    }

    // ---- lossless native path matching ----

    #[cfg(unix)]
    fn repo_with_names(names: &[&std::ffi::OsStr]) -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        init_git_repo(dir.path());
        std::fs::write(dir.path().join("seed.txt"), "s").unwrap();
        for n in names {
            std::fs::write(dir.path().join(n), "t").unwrap();
        }
        git_commit_all(dir.path(), "initial");
        dir
    }

    #[cfg(unix)]
    #[test]
    fn tracked_name_with_a_backslash_aborts() {
        fuigo_test_utils::require_git!();
        let dir = repo_with_names(&[std::ffi::OsStr::new("a\\b.txt")]);
        let err = check_copy_failures(
            dir.path(),
            dir.path(),
            None,
            &stats(vec![failure("a\\b.txt", false)]),
        )
        .unwrap_err();
        let typed = err.downcast_ref::<TrackedCopyError>().expect("typed error");
        assert_eq!(typed.paths, vec![PathBuf::from("a\\b.txt")]);
    }

    #[cfg(unix)]
    #[test]
    fn untracked_backslash_name_is_not_conflated_with_a_tracked_slash_path() {
        fuigo_test_utils::require_git!();
        // `x/y.txt` is tracked; the untracked file is literally named `x\y.txt`.
        let dir = tempfile::TempDir::new().unwrap();
        init_git_repo(dir.path());
        std::fs::create_dir(dir.path().join("x")).unwrap();
        std::fs::write(dir.path().join("x/y.txt"), "t").unwrap();
        git_commit_all(dir.path(), "initial");
        std::fs::write(dir.path().join("x\\y.txt"), "u").unwrap();
        check_copy_failures(
            dir.path(),
            dir.path(),
            None,
            &stats(vec![failure("x\\y.txt", false)]),
        )
        .expect("an untracked name that only looks like a tracked path must warn, not abort");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tracked_non_utf8_name_aborts_and_untracked_non_utf8_warns() {
        use std::os::unix::ffi::OsStrExt;
        fuigo_test_utils::require_git!();
        let tracked = std::ffi::OsStr::from_bytes(b"bad\xff.txt");
        let dir = repo_with_names(&[tracked]);
        let untracked = std::ffi::OsStr::from_bytes(b"bad\xfe.txt");
        std::fs::write(dir.path().join(untracked), "u").unwrap();

        let fail = |name: &std::ffi::OsStr| CopyFailure {
            rel_path: PathBuf::from(name),
            message: "copy: Permission denied (os error 13)".into(),
            storage_full: false,
        };
        // U+FFFD lossy conversion would conflate both names; they must stay distinct.
        check_copy_failures(
            dir.path(),
            dir.path(),
            None,
            &stats(vec![fail(untracked)]),
        )
        .expect("untracked non-UTF-8 name only warns");
        let err = check_copy_failures(
            dir.path(),
            dir.path(),
            None,
            &stats(vec![fail(tracked)]),
        )
        .unwrap_err();
        assert!(err.downcast_ref::<TrackedCopyError>().is_some());
    }

    // ---- unknown-scope walker errors ----

    fn unscoped_stats() -> CopyStats {
        CopyStats {
            issues: vec!["walk: IO error".into()],
            unscoped_walk_error: Some("walk: IO error".into()),
            ..Default::default()
        }
    }

    #[test]
    fn unscoped_walk_error_aborts_when_a_tracked_file_is_missing_from_dest() {
        fuigo_test_utils::require_git!();
        let src = repo();
        let dest = tempfile::TempDir::new().unwrap();
        // `top.txt` made it; `sub/tracked.txt` did not.
        std::fs::write(dest.path().join("top.txt"), "t").unwrap();
        let err =
            check_copy_failures(src.path(), dest.path(), None, &unscoped_stats()).unwrap_err();
        let typed = err.downcast_ref::<TrackedCopyError>().expect("typed error");
        assert_eq!(typed.paths, vec![PathBuf::from("sub/tracked.txt")]);
        assert!(err.to_string().contains("walk: IO error"), "{err}");
    }

    #[test]
    fn unscoped_walk_error_only_warns_when_every_tracked_file_reached_dest() {
        fuigo_test_utils::require_git!();
        let src = repo();
        let dest = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dest.path().join("sub")).unwrap();
        std::fs::write(dest.path().join("sub/tracked.txt"), "t").unwrap();
        std::fs::write(dest.path().join("top.txt"), "t").unwrap();
        check_copy_failures(src.path(), dest.path(), None, &unscoped_stats()).unwrap();
    }

    #[test]
    fn unscoped_check_ignores_deliberately_skipped_and_source_absent_files() {
        fuigo_test_utils::require_git!();
        let src = repo();
        let dest = tempfile::TempDir::new().unwrap();
        std::fs::write(dest.path().join("top.txt"), "t").unwrap();
        // `sub/tracked.txt` was skipped on purpose (a modified file in a clean mode).
        let skipped = DashSet::new();
        skipped.insert(PathBuf::from("sub/tracked.txt"));
        check_copy_failures(src.path(), dest.path(), Some(&skipped), &unscoped_stats()).unwrap();
        // ...and a tracked file deleted from the source working tree is nothing to copy.
        std::fs::remove_file(src.path().join("sub/tracked.txt")).unwrap();
        check_copy_failures(src.path(), dest.path(), None, &unscoped_stats()).unwrap();
    }
}
