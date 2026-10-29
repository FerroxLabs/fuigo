//! Worker logic for replicating a single filesystem entry.

use std::collections::HashSet;
use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::{DashMap, DashSet};

use crate::copy::cow;
use crate::copy::types::{CopyEntry, CopyEntryKind, CopyFailure, is_storage_full};

pub(crate) struct WorkerCtx {
    pub source: PathBuf,
    pub dest: PathBuf,
    pub files_copied: Arc<AtomicU64>,
    pub dirs_created: Arc<AtomicU64>,
    pub symlinks_copied: Arc<AtomicU64>,
    pub issues: Arc<std::sync::Mutex<Vec<String>>>,
    pub failed: Arc<std::sync::Mutex<Vec<CopyFailure>>>,
    pub copied_paths: Arc<DashSet<PathBuf>>,
    pub file_metadata: Arc<DashMap<PathBuf, Metadata>>,
}

/// Why one entry could not be replicated.
#[derive(Debug)]
struct EntryError {
    message: String,
    storage_full: bool,
}

impl EntryError {
    fn new(message: String, err: &(dyn std::error::Error + 'static)) -> Self {
        Self {
            message,
            storage_full: is_storage_full(err),
        }
    }
}

pub(crate) fn run_worker(rx: crossbeam::channel::Receiver<CopyEntry>, ctx: WorkerCtx) {
    // Track created directories to avoid redundant mkdir calls.
    let mut created_dirs: HashSet<PathBuf> = HashSet::new();

    for entry in rx {
        let src = ctx.source.join(&entry.rel_path);
        let dst = ctx.dest.join(&entry.rel_path);

        let outcome = process_entry(
            &entry,
            &src,
            &dst,
            &mut created_dirs,
            &ctx.files_copied,
            &ctx.dirs_created,
            &ctx.symlinks_copied,
            &ctx.file_metadata,
        );

        match outcome {
            Ok(warning) => {
                if let Some(warning) = warning {
                    ctx.issues.lock().unwrap().push(warning);
                }
                ctx.copied_paths.insert(entry.rel_path);
            }
            Err(err) => {
                ctx.issues.lock().unwrap().push(err.message.clone());
                ctx.failed.lock().unwrap().push(CopyFailure {
                    rel_path: entry.rel_path,
                    message: err.message,
                    storage_full: err.storage_full,
                });
            }
        }
    }
}

/// A copied file whose source mode could not be applied. Normally that is a
/// warning, but a full disk is classified (by the shared classifier) before it
/// can become one, so it still aborts.
fn mode_outcome(rel_path: &Path, err: std::io::Error) -> Result<Option<String>, EntryError> {
    if is_storage_full(&err) {
        return Err(EntryError::new(
            format!("mode {}: {}", rel_path.display(), err),
            &err,
        ));
    }
    Ok(Some(format!(
        "mode not preserved for {}: {}",
        rel_path.display(),
        err
    )))
}

/// Replicate one entry. `Ok(Some(_))` is a copied entry with a warning (the
/// source mode could not be applied); `Err` is a failed entry.
fn process_entry(
    entry: &CopyEntry,
    src: &Path,
    dst: &Path,
    created_dirs: &mut HashSet<PathBuf>,
    files_copied: &AtomicU64,
    dirs_created: &AtomicU64,
    symlinks_copied: &AtomicU64,
    file_metadata: &DashMap<PathBuf, Metadata>,
) -> Result<Option<String>, EntryError> {
    // Ensure parent directory exists.
    if let Some(parent) = dst.parent()
        && !parent.as_os_str().is_empty()
        && created_dirs.insert(parent.to_path_buf())
        && let Err(e) = std::fs::create_dir_all(parent)
        && e.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(EntryError::new(
            format!("mkdir {}: {}", parent.display(), e),
            &e,
        ));
    }

    match entry.kind {
        CopyEntryKind::Dir => match std::fs::create_dir_all(dst) {
            Ok(()) => {
                dirs_created.fetch_add(1, Ordering::Relaxed);
                Ok(None)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
            Err(e) => Err(EntryError::new(
                format!("mkdir {}: {}", entry.rel_path.display(), e),
                &e,
            )),
        },
        CopyEntryKind::Symlink => {
            let target = std::fs::read_link(src).map_err(|e| {
                EntryError::new(format!("read_link {}: {}", entry.rel_path.display(), e), &e)
            })?;
            cow::replace_symlink(&target, dst).map_err(|e| {
                EntryError::new(format!("symlink {}: {}", entry.rel_path.display(), e), &e)
            })?;
            symlinks_copied.fetch_add(1, Ordering::Relaxed);
            Ok(None)
        }
        CopyEntryKind::File => {
            let mode_error = cow::clone_file_keeping_on_mode_error(src, dst).map_err(|e| {
                EntryError::new(
                    format!("copy {}: {}", entry.rel_path.display(), e),
                    e.as_ref(),
                )
            })?;
            files_copied.fetch_add(1, Ordering::Relaxed);

            // Collect file metadata for index updates
            if let Ok(metadata) = std::fs::metadata(dst) {
                file_metadata.insert(entry.rel_path.clone(), metadata);
            }

            match mode_error {
                Some(e) => mode_outcome(&entry.rel_path, e),
                None => Ok(None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_error_on_a_full_disk_is_a_storage_full_failure_not_a_warning() {
        let err = mode_outcome(
            Path::new("a/b.txt"),
            std::io::Error::from(std::io::ErrorKind::StorageFull),
        )
        .unwrap_err();
        assert!(err.storage_full);
        assert!(err.message.starts_with("mode a/b.txt:"), "{}", err.message);
    }

    #[test]
    fn other_mode_errors_stay_warnings() {
        let warning = mode_outcome(
            Path::new("a/b.txt"),
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        )
        .unwrap()
        .expect("a warning");
        assert!(warning.starts_with("mode not preserved for a/b.txt:"), "{warning}");
    }

    #[test]
    fn worker_error_classification_finds_storage_full() {
        let io = std::io::Error::from(std::io::ErrorKind::StorageFull);
        assert!(EntryError::new("copy x".into(), &io).storage_full);
        let other = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert!(!EntryError::new("copy x".into(), &other).storage_full);
    }
}
