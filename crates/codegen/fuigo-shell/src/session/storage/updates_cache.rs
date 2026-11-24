//! F5 (1.0.47): one `session/load` reads `updates.jsonl` from disk once.
//!
//! A resume used to read the whole file once per reader (compaction-checkpoint scans, the prompt scan, the replay,
//! the orphaned-task scan). While a [`LoadScope`] is alive those readers share one copy. Every use re-checks the
//! file's length, mtime and identity, so an append or a replaced file in between is read afresh; the copy is freed
//! when the last scope ends. Outside a scope [`read`] is a plain read.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Stamp {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    identity: (u64, u64),
}

fn stamp(path: &Path) -> io::Result<Stamp> {
    let meta = std::fs::metadata(path)?;
    Ok(Stamp {
        len: meta.len(),
        modified: meta.modified().ok(),
        #[cfg(unix)]
        identity: {
            use std::os::unix::fs::MetadataExt as _;
            (meta.dev(), meta.ino())
        },
    })
}

struct Entry {
    path: PathBuf,
    stamp: Stamp,
    bytes: Arc<[u8]>,
}

static SCOPES: AtomicUsize = AtomicUsize::new(0);
static CACHE: Mutex<Vec<Entry>> = Mutex::new(Vec::new());
static DISK_READS: AtomicUsize = AtomicUsize::new(0);

/// Shares `updates.jsonl` reads between the readers of one session load while it is alive.
#[must_use]
pub(crate) struct LoadScope(());

impl LoadScope {
    pub(crate) fn enter() -> Self {
        SCOPES.fetch_add(1, Ordering::SeqCst);
        Self(())
    }
}

impl Drop for LoadScope {
    fn drop(&mut self) {
        if SCOPES.fetch_sub(1, Ordering::SeqCst) == 1 {
            CACHE.lock().unwrap_or_else(PoisonError::into_inner).clear();
        }
    }
}

fn read_disk(path: &Path) -> io::Result<Arc<[u8]>> {
    DISK_READS.fetch_add(1, Ordering::SeqCst);
    std::fs::read(path).map(Arc::from)
}

/// The whole file at `path`: the load's shared copy while a [`LoadScope`] is alive and the file is unchanged, else
/// read from disk. Errors are those of `std::fs::read` (`NotFound` included).
pub(crate) fn read(path: &Path) -> io::Result<Arc<[u8]>> {
    if SCOPES.load(Ordering::SeqCst) == 0 {
        return read_disk(path);
    }
    let before = stamp(path)?;
    // Held across the read so two readers of one load (the session thread and the agent's) do not both read it.
    let mut cache = CACHE.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(entry) = cache
        .iter()
        .find(|entry| entry.path == path && entry.stamp == before)
    {
        return Ok(Arc::clone(&entry.bytes));
    }
    let bytes = read_disk(path)?;
    // A write between the stat and the read leaves this copy unvalidated: use it, but do not share it.
    let settled = bytes.len() as u64 == before.len && stamp(path).ok() == Some(before);
    if settled && SCOPES.load(Ordering::SeqCst) > 0 {
        cache.retain(|entry| entry.path != path);
        cache.push(Entry {
            path: path.to_path_buf(),
            stamp: before,
            bytes: Arc::clone(&bytes),
        });
    }
    Ok(bytes)
}

/// `bytes` as text; invalid UTF-8 is `InvalidData`, as `std::fs::read_to_string` reports it.
pub(crate) fn utf8(bytes: &[u8]) -> io::Result<&str> {
    std::str::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Reads of `updates.jsonl` that went to disk, for tests.
#[doc(hidden)]
pub fn disk_reads() -> usize {
    DISK_READS.load(Ordering::SeqCst)
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "test code: writes files in a test-owned temp dir; no product session writer runs there"
)]
mod tests {
    use super::*;

    // One test: the scope count and the read counter are process-global.
    #[test]
    fn a_scope_shares_one_read_and_rereads_a_changed_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("updates.jsonl");
        std::fs::write(&path, b"one\n").expect("seed");

        let start = disk_reads();
        let _ = read(&path).expect("read");
        let _ = read(&path).expect("read");
        assert_eq!(
            disk_reads() - start,
            2,
            "outside a scope every read goes to disk"
        );

        let scope = LoadScope::enter();
        let start = disk_reads();
        assert_eq!(&*read(&path).expect("read"), b"one\n");
        assert_eq!(&*read(&path).expect("read"), b"one\n");
        assert_eq!(
            disk_reads() - start,
            1,
            "inside a scope the readers share one read"
        );

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open");
        std::io::Write::write_all(&mut file, b"two\n").expect("append");
        assert_eq!(
            &*read(&path).expect("read"),
            b"one\ntwo\n",
            "an append is read afresh"
        );
        assert_eq!(disk_reads() - start, 2);

        std::fs::write(&path, b"\xff\n").expect("invalid utf-8");
        assert_eq!(
            utf8(&read(&path).expect("read"))
                .expect_err("invalid utf-8")
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            read(&dir.path().join("missing"))
                .expect_err("missing")
                .kind(),
            io::ErrorKind::NotFound
        );

        drop(scope);
        assert!(
            CACHE.lock().expect("cache").is_empty(),
            "the copy is freed with the last scope"
        );
    }
}
