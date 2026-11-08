//! Session-scoped file storage with crash-safe atomic writes and budgets.
//!
//! Each [`SessionFileWriter`] manages a single subdirectory and file
//! extension, producing files named `1.jpg`, `2.mp4`, `3.pdf`, etc.
//! The counter is lazily initialised from existing files on disk so
//! resumed sessions don't overwrite previous output.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use anyhow::Context;
use fuigo_session_writer::SessionWriter;

use crate::types::resources::{Resources, SessionFolder, SessionFolderWriter};

/// A session folder as the tools see it: the path (read, and shown to the model) and, when the session has one, its
/// writer, through which every write inside it goes (design F5 §5.4.2). Without a writer (headless runs, the
/// workspace daemon's own tree, tests) the folder is never written by path: saves fail (F5-C4).
#[derive(Clone, Debug)]
pub(crate) struct SessionFiles {
    folder: PathBuf,
    writer: Option<SessionWriter>,
}

impl SessionFiles {
    /// The folder and, when the session has one, its writer.
    pub(crate) fn new(folder: PathBuf, writer: Option<SessionWriter>) -> Self {
        Self { folder, writer }
    }

    /// A test folder with its own writer claimed under a fresh id (the folder itself is the writer's directory).
    #[cfg(test)]
    pub(crate) fn at(folder: impl Into<PathBuf>) -> Self {
        let folder = folder.into();
        let writer = SessionWriter::try_claim(uuid::Uuid::now_v7().to_string(), &folder).expect("claim a test writer");
        Self { folder, writer: Some(writer) }
    }

    /// A folder with no writer, as a session folder without one (tests).
    #[cfg(test)]
    pub(crate) fn at_without_writer(folder: impl Into<PathBuf>) -> Self {
        Self { folder: folder.into(), writer: None }
    }

    /// The session's folder and writer from the toolset's resources; `None` without a [`SessionFolder`].
    pub(crate) fn from_resources(res: &Resources) -> Option<Self> {
        let folder = res.get::<SessionFolder>()?.0.clone();
        Some(Self::new(folder, res.get::<SessionFolderWriter>().map(|w| w.0.clone())))
    }

    /// [`Self::from_resources`], failing as `require::<SessionFolder>()` does.
    pub(crate) fn require(res: &Resources) -> Result<Self, fuigo_tool_runtime::ToolError> {
        res.require::<SessionFolder>()?;
        Ok(Self::from_resources(res).expect("SessionFolder checked above"))
    }

    /// The session's writer, when it has one.
    pub(crate) fn writer(&self) -> Option<&SessionWriter> {
        self.writer.as_ref()
    }
}

impl std::ops::Deref for SessionFiles {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.folder
    }
}

const IMAGE_MAX_BYTES: u64 = 1024 * 1024 * 1024; // 1 GB
const VIDEO_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GB
const DEFAULT_MAX_BYTES: u64 = 1024 * 1024 * 1024; // 1 GB

fn budget_for(dir_name: &str) -> u64 {
    match dir_name {
        "images" => IMAGE_MAX_BYTES,
        "videos" => VIDEO_MAX_BYTES,
        _ => DEFAULT_MAX_BYTES,
    }
}

/// Persists numbered files to `<session_folder>/<dir_name>/<N>.<ext>`.
///
/// Writes are crash-safe: data is written to a temp file, fsynced, then
/// atomically renamed into place via `tempfile::NamedTempFile::persist`.
#[derive(Clone, Debug)]
pub(crate) struct SessionFileWriter {
    dir_name: &'static str,
    ext: &'static str,
    counter: Arc<AtomicU32>,
    bytes_written: Arc<AtomicU64>,
    max_total_bytes: u64,
}

impl SessionFileWriter {
    pub(crate) fn new(dir_name: &'static str, ext: &'static str) -> Self {
        let max_total_bytes = budget_for(dir_name);
        Self {
            dir_name,
            ext,
            counter: Arc::new(AtomicU32::new(0)),
            bytes_written: Arc::new(AtomicU64::new(0)),
            max_total_bytes,
        }
    }

    /// Save `bytes` to the next numbered file, returning the absolute path.
    ///
    /// `ext_override` writes a different file type without needing a
    /// separate writer (e.g. saving a PNG from a JPG-default writer).
    #[tracing::instrument(skip_all, fields(dir = self.dir_name))]
    pub(crate) async fn save(
        &self,
        session_folder: &SessionFiles,
        bytes: &[u8],
        ext_override: Option<&str>,
    ) -> anyhow::Result<PathBuf> {
        let dir = session_folder.join(self.dir_name);

        // The session folder is never written by path: the folder and the subdirectory are created by the writer's
        // first write (owner-only).
        let Some(writer) = session_folder.writer() else {
            anyhow::bail!("no session writer: refusing to write the session folder by path");
        };

        // Lazy-init: scan existing files for counter resume + byte accounting.
        // compare_exchange ensures only the winner initialises; losers no-op.
        if self.counter.load(Ordering::Relaxed) == 0
            && let Ok((max_n, total_bytes)) = scan_dir_stats(&dir, session_folder.writer(), self.dir_name).await
            && self
                .counter
                .compare_exchange(0, max_n, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.bytes_written.fetch_add(total_bytes, Ordering::Relaxed);
        }

        let n = self.counter.fetch_add(1, Ordering::Relaxed) + 1;

        let size = bytes.len() as u64;
        let new_total = self.bytes_written.fetch_add(size, Ordering::Relaxed) + size;
        if new_total > self.max_total_bytes {
            self.bytes_written.fetch_sub(size, Ordering::Relaxed);
            self.counter.fetch_sub(1, Ordering::Relaxed);
            anyhow::bail!(
                "byte budget exceeded: {}/{} bytes in {}",
                new_total,
                self.max_total_bytes,
                self.dir_name
            );
        }

        let ext = ext_override.unwrap_or(self.ext);
        let path = dir.join(format!("{n}.{ext}"));

        // The writer's atomic replace: owner-only temp, sync, rename, directory sync. The number was reserved past
        // every existing file, so nothing is replaced.
        let result: anyhow::Result<()> = writer
            .replace_atomic(Path::new(self.dir_name).join(format!("{n}.{ext}")), bytes.to_vec())
            .await
            .with_context(|| format!("persist to {}", path.display()));

        if let Err(e) = result {
            self.counter.fetch_sub(1, Ordering::Relaxed);
            self.bytes_written.fetch_sub(size, Ordering::Relaxed);
            return Err(e);
        }

        tracing::debug!(bytes = size, "file saved");
        Ok(path)
    }
}

/// Scan `dir` for stats: (max counter N from any `N.*` file, total bytes of all files).
/// Also removes orphan `.tmp*` files left behind by interrupted writes.
/// With the session's `writer`, an orphan is removed through it (`dir_name` is `dir` relative to the session folder).
async fn scan_dir_stats(
    dir: &Path,
    writer: Option<&SessionWriter>,
    dir_name: &str,
) -> Result<(u32, u64), std::io::Error> {
    let mut max = 0u32;
    let mut total_bytes = 0u64;
    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Remove orphan temp files from interrupted writes
        if name_str.starts_with(".tmp") {
            match writer {
                Some(writer) => {
                    let _ = writer.remove(Path::new(dir_name).join(&name)).await;
                }
                None => tracing::warn!(
                    path = %entry.path().display(),
                    "no session writer: not removing an orphan temp file by path"
                ),
            }
            continue;
        }

        // Track the highest numbered file (any extension)
        if let Some(stem) = name_str.split_once('.').map(|(s, _)| s)
            && let Ok(n) = stem.parse::<u32>()
        {
            max = max.max(n);
        }

        // Sum bytes for budget init
        if let Ok(meta) = entry.metadata().await {
            total_bytes += meta.len();
        }
    }
    Ok((max, total_bytes))
}

#[allow(clippy::disallowed_methods, reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there")]
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn save_creates_numbered_files() {
        let tmp = tempfile::tempdir().unwrap();
        let writer = SessionFileWriter::new("images", "jpg");

        let p1 = writer.save(&SessionFiles::at(tmp.path()), b"img1", None).await.unwrap();
        let p2 = writer.save(&SessionFiles::at(tmp.path()), b"img2", None).await.unwrap();

        assert_eq!(p1.file_name().unwrap(), "1.jpg");
        assert_eq!(p2.file_name().unwrap(), "2.jpg");
        assert_eq!(tokio::fs::read(&p1).await.unwrap(), b"img1");
        assert_eq!(tokio::fs::read(&p2).await.unwrap(), b"img2");
    }

    #[tokio::test]
    async fn save_resumes_counter_from_existing_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("downloads");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("1.pdf"), b"").await.unwrap();
        tokio::fs::write(dir.join("5.pdf"), b"").await.unwrap();
        tokio::fs::write(dir.join("readme.txt"), b"").await.unwrap();

        let writer = SessionFileWriter::new("downloads", "pdf");
        let path = writer.save(&SessionFiles::at(tmp.path()), b"new", None).await.unwrap();

        assert_eq!(path.file_name().unwrap(), "6.pdf");
    }

    #[tokio::test]
    async fn save_uses_ext_override() {
        let tmp = tempfile::tempdir().unwrap();
        let writer = SessionFileWriter::new("downloads", "pdf");

        let p1 = writer.save(&SessionFiles::at(tmp.path()), b"doc", Some("docx")).await.unwrap();
        assert_eq!(p1.file_name().unwrap(), "1.docx");
    }

    #[tokio::test]
    async fn scan_dir_stats_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let (max, bytes) = scan_dir_stats(tmp.path(), None, "").await.unwrap();
        assert_eq!(max, 0);
        assert_eq!(bytes, 0);
    }

    #[tokio::test]
    async fn scan_dir_stats_finds_max_and_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("1.mp4"), b"aaaa")
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("3.mp4"), b"bbbbbb")
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("2.mp4"), b"cc")
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("hero.mp4"), b"")
            .await
            .unwrap();
        let (max, bytes) = scan_dir_stats(tmp.path(), None, "").await.unwrap();
        assert_eq!(max, 3);
        assert_eq!(bytes, 4 + 6 + 2); // aaaa + bbbbbb + cc
    }

    #[tokio::test]
    async fn scan_dir_stats_cleans_orphan_tmp() {
        let tmp = tempfile::tempdir().unwrap();
        let id = uuid::Uuid::now_v7().to_string();
        let writer = SessionWriter::try_claim(id, tmp.path()).unwrap();
        tokio::fs::write(tmp.path().join(".tmp123"), b"orphan")
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("1.jpg"), b"keep")
            .await
            .unwrap();
        let (max, _) = scan_dir_stats(tmp.path(), Some(&writer), "").await.unwrap();
        assert_eq!(max, 1);
        assert!(!tmp.path().join(".tmp123").exists());
    }

    /// F5-C4: with no session writer a save writes nothing (no folder, no file) and returns the error, and a scan
    /// leaves an orphan temp file alone.
    #[tokio::test]
    async fn save_without_a_writer_refuses_to_write_by_path() {
        let tmp = tempfile::tempdir().unwrap();
        let folder = tmp.path().join("session");
        let files = SessionFiles::at_without_writer(&folder);
        let err = SessionFileWriter::new("images", "jpg").save(&files, b"img", None).await.unwrap_err();
        assert!(err.to_string().contains("no session writer"), "{err}");
        assert!(!folder.exists(), "a writer-less save created the session folder");

        tokio::fs::write(tmp.path().join(".tmp9"), b"orphan").await.unwrap();
        scan_dir_stats(tmp.path(), None, "").await.unwrap();
        assert!(tmp.path().join(".tmp9").exists(), "a writer-less scan removed a file by path");
    }

    #[tokio::test]
    async fn scan_dir_stats_missing_dir() {
        let dir = Path::new("/nonexistent/path/that/does/not/exist");
        assert!(scan_dir_stats(dir, None, "").await.is_err());
    }

    /// Through the session's writer (design F5 §5.4.2): numbered files land owner-only in the subdirectory it
    /// creates, and once the writer released the folder for a delete a save fails without recreating the folder
    /// (1.0.40's by-path save recreated it).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn save_through_the_session_writer() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "storage-save-through-the-writer";
        let folder = tmp.path().join(id);
        let session_writer = SessionWriter::try_claim(id, &folder).unwrap();
        let files = SessionFiles::new(folder.clone(), Some(session_writer.clone()));
        let writer = SessionFileWriter::new("images", "jpg");
        let p1 = writer.save(&files, b"img1", None).await.unwrap();
        assert_eq!(p1, folder.join("images").join("1.jpg"));
        assert_eq!(tokio::fs::read(&p1).await.unwrap(), b"img1");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p1).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(folder.join("images")).unwrap().permissions().mode() & 0o777, 0o700);
        }

        session_writer.delete_tree().await.unwrap();
        assert!(writer.save(&files, b"img2", None).await.is_err());
        assert!(!folder.exists(), "a save after the delete recreated the session folder");
    }
}
