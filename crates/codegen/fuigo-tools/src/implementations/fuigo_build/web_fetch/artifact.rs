use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;
use fs2::FileExt;
use fuigo_session_writer::SessionWriter;

use crate::implementations::fuigo_build::storage::SessionFiles;

const ARTIFACT_DIR: &str = "web_fetch";
const ALLOCATION_FILE: &str = ".allocation";
const COUNTER_WIDTH: usize = 10;
const MAX_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Debug, Default)]
pub(super) struct WebFetchArtifactWriter;

impl WebFetchArtifactWriter {
    pub(super) async fn save(
        &self,
        session_folder: &SessionFiles,
        bytes: &[u8],
        extension: &str,
    ) -> anyhow::Result<PathBuf> {
        let dir = session_folder.join(ARTIFACT_DIR);
        if let Some(writer) = session_folder.writer() {
            // Through the session's writer: it creates the folder and `web_fetch/` owner-only on first use.
            let (writer, data, extension) = (writer.clone(), bytes.to_vec(), extension.to_owned());
            return tokio::task::spawn_blocking(move || save_locked_through(&writer, &dir, &data, &extension))
                .await
                .context("spawn_blocking panicked")?;
        }
        anyhow::bail!("no session writer: refusing to write the session folder by path")
    }
}

/// The locked save through the session's writer: the allocation file is its lock sidecar (`open_lock`), an orphan
/// temp is removed through it, and the artifact is published with its atomic replace. The number is reserved under
/// the lock past every existing artifact, so the publish never replaces one.
fn save_locked_through(writer: &SessionWriter, dir: &Path, data: &[u8], extension: &str) -> anyhow::Result<PathBuf> {
    let rel_dir = Path::new(ARTIFACT_DIR);
    let mut allocation = writer.open_lock(rel_dir.join(ALLOCATION_FILE)).context("open allocation file")?;
    allocation.lock_exclusive().context("lock allocation file")?;

    let (max_existing, total_bytes) = scan_artifacts(dir, Some(writer))?;
    let number = reserve_number(&mut allocation, max_existing)?;
    let new_total = total_bytes
        .checked_add(u64::try_from(data.len()).context("artifact size exceeds u64")?)
        .context("artifact byte count overflow")?;
    if new_total > MAX_TOTAL_BYTES {
        anyhow::bail!("byte budget exceeded: {new_total}/{MAX_TOTAL_BYTES} bytes in {ARTIFACT_DIR}");
    }

    let name = format!("{number}.{extension}");
    let path = dir.join(&name);
    writer
        .replace_atomic_sync(rel_dir.join(&name), data)
        .with_context(|| format!("persist to {}", path.display()))?;
    Ok(path)
}

#[allow(clippy::disallowed_methods, reason = "lock sidecar (design F5 5.6): the .allocation counter, opened through SessionWriter::open_lock; rewrites only that handle")]
fn reserve_number(file: &mut std::fs::File, max_existing: u32) -> anyhow::Result<u32> {
    let stored = read_reserved_number(file)?.unwrap_or(max_existing);
    let next = stored
        .max(max_existing)
        .checked_add(1)
        .context("artifact number exhausted")?;
    file.seek(SeekFrom::Start(0))
        .context("seek allocation file")?;
    write!(file, "{next:0width$}", width = COUNTER_WIDTH).context("write allocation file")?;
    file.set_len(COUNTER_WIDTH as u64)
        .context("truncate allocation file")?;
    file.sync_all().context("fsync allocation file")?;
    Ok(next)
}

fn read_reserved_number(file: &mut std::fs::File) -> anyhow::Result<Option<u32>> {
    let len = file.metadata().context("stat allocation file")?.len();
    if len == 0 {
        return Ok(Some(0));
    }
    if len != COUNTER_WIDTH as u64 {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(0))
        .context("seek allocation file")?;
    let mut bytes = [0; COUNTER_WIDTH];
    file.read_exact(&mut bytes)
        .context("read allocation file")?;
    Ok(std::str::from_utf8(&bytes)
        .ok()
        .and_then(|stored| stored.parse().ok()))
}

/// With the session's `writer`, an orphan temp is removed through it.
fn scan_artifacts(dir: &Path, writer: Option<&SessionWriter>) -> Result<(u32, u64), std::io::Error> {
    let mut max = 0u32;
    let mut total_bytes = 0u64;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(".tmp") {
            match writer {
                Some(writer) => {
                    let _ = writer.remove_sync(Path::new(ARTIFACT_DIR).join(&*name));
                }
                None => tracing::warn!(
                    path = %entry.path().display(),
                    "no session writer: not removing an orphan temp file by path"
                ),
            }
            continue;
        }
        if name.starts_with('.') {
            continue;
        }
        if let Some(stem) = name.split_once('.').map(|(stem, _)| stem)
            && let Ok(number) = stem.parse::<u32>()
        {
            max = max.max(number);
        }
        if let Ok(metadata) = entry.metadata()
            && metadata.is_file()
        {
            total_bytes = total_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| std::io::Error::other("artifact byte count overflow"))?;
        }
    }
    Ok((max, total_bytes))
}

#[allow(clippy::disallowed_methods, reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there")]
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allocation_recovers_malformed_state_and_failed_reservation() {
        let tmp = tempfile::tempdir().unwrap();
        let session = tmp.path().join("session");
        tokio::fs::create_dir_all(session.join(ARTIFACT_DIR))
            .await
            .unwrap();
        tokio::fs::write(session.join(ARTIFACT_DIR).join("5.txt"), b"existing")
            .await
            .unwrap();
        tokio::fs::write(session.join(ARTIFACT_DIR).join(ALLOCATION_FILE), b"torn")
            .await
            .unwrap();
        let writer = WebFetchArtifactWriter;

        assert!(
            writer
                .save(&SessionFiles::at(&session), b"failed", "/../ext")
                .await
                .is_err()
        );
        let saved = writer.save(&SessionFiles::at(&session), b"recovered", "txt").await.unwrap();

        assert_eq!(saved.file_name().unwrap(), "7.txt");
        assert_eq!(
            tokio::fs::read_to_string(session.join(ARTIFACT_DIR).join(ALLOCATION_FILE))
                .await
                .unwrap(),
            "0000000007"
        );
    }

    #[tokio::test]
    async fn concurrent_writes_same_session_have_distinct_intact_files() {
        let tmp = tempfile::tempdir().unwrap();
        let writer = WebFetchArtifactWriter;
        let files = SessionFiles::at(tmp.path());
        let payload_a: &[u8] = b"payload from writer a";
        let payload_b: &[u8] = b"different payload from writer b";

        let (saved_a, saved_b) = tokio::join!(
            writer.save(&files, payload_a, "txt"),
            writer.save(&files, payload_b, "txt"),
        );
        let saved_a = saved_a.unwrap();
        let saved_b = saved_b.unwrap();

        assert_ne!(saved_a, saved_b);
        assert_eq!(tokio::fs::read(saved_a).await.unwrap(), payload_a);
        assert_eq!(tokio::fs::read(saved_b).await.unwrap(), payload_b);
    }

    /// Through the session's writer (design F5 §5.4.2): concurrent saves still get distinct, intact artifacts and the
    /// allocation counter, and once the writer released the folder for a delete a save writes nothing and does not
    /// recreate it (1.0.40's by-path save recreated the deleted folder).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn through_the_session_writer() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "web-fetch-artifact-through-the-writer";
        let folder = tmp.path().join(id);
        let session_writer = SessionWriter::try_claim(id, &folder).unwrap();
        let files = SessionFiles::new(folder.clone(), Some(session_writer.clone()));
        let writer = WebFetchArtifactWriter;
        let (saved_a, saved_b) = tokio::join!(writer.save(&files, b"a", "txt"), writer.save(&files, b"bb", "txt"));
        let (saved_a, saved_b) = (saved_a.unwrap(), saved_b.unwrap());
        assert_ne!(saved_a, saved_b);
        assert_eq!(tokio::fs::read(&saved_a).await.unwrap().len() + tokio::fs::read(&saved_b).await.unwrap().len(), 3);
        assert_eq!(
            tokio::fs::read_to_string(folder.join(ARTIFACT_DIR).join(ALLOCATION_FILE)).await.unwrap(),
            "0000000002"
        );

        session_writer.delete_tree().await.unwrap();
        assert!(writer.save(&files, b"late", "txt").await.is_err());
        assert!(!folder.exists(), "a save after the delete recreated the session folder");
    }

    /// F5-C4: with no session writer a save writes nothing and returns the error.
    #[tokio::test]
    async fn save_without_a_writer_refuses_to_write_by_path() {
        let tmp = tempfile::tempdir().unwrap();
        let folder = tmp.path().join("session");
        let err = WebFetchArtifactWriter
            .save(&SessionFiles::at_without_writer(&folder), b"x", "txt")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no session writer"), "{err}");
        assert!(!folder.exists(), "a writer-less save created the session folder");
    }
}
