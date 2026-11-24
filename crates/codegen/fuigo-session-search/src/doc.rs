//! Turns a session record plus its extracted text into an index document.

use std::path::Path;

use crate::fts::{SessionDoc, SessionSearchIndex};
use crate::source::IndexableSession;

pub(crate) fn should_skip_session(updates_path: &Path, max_size: u64) -> bool {
    match std::fs::metadata(updates_path) {
        Ok(meta) => meta.len() > max_size,
        Err(_) => false,
    }
}

/// A transcript's length and mtime, recorded with its index row so an unchanged file is not re-read.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct FileStamp {
    pub(crate) len: i64,
    pub(crate) mtime_ns: i64,
}

impl FileStamp {
    /// `None` when the file is missing or the platform reports no mtime; the caller then extracts as before.
    pub(crate) fn of(path: &Path) -> Option<Self> {
        let meta = std::fs::metadata(path).ok()?;
        let mtime = meta
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        Some(Self {
            len: i64::try_from(meta.len()).ok()?,
            mtime_ns: i64::try_from(mtime.as_nanos()).ok()?,
        })
    }
}

#[derive(Debug)]
pub(crate) enum UpsertOutcome {
    Indexed {
        bytes_read: u64,
    },
    /// Content hash matched the existing index entry.
    Unchanged {
        bytes_read: u64,
    },
    /// Nothing to write: the store exposes no updates file.
    NoContent,
}

/// Upsert `doc` unless the stored content hash already matches, then record `stamp` (taken before extraction) against the row.
pub(crate) fn upsert_unless_unchanged(
    index: &SessionSearchIndex,
    doc: &SessionDoc,
    bytes_read: u64,
    stamp: Option<FileStamp>,
) -> Result<UpsertOutcome, rusqlite::Error> {
    let outcome = if let Ok(Some(existing_hash)) = index.get_content_hash(&doc.session_id)
        && existing_hash == doc.content_hash
    {
        UpsertOutcome::Unchanged { bytes_read }
    } else {
        index.upsert_doc(doc)?;
        UpsertOutcome::Indexed { bytes_read }
    };
    if let Some(stamp) = stamp {
        index.set_file_stamp(&doc.session_id, stamp, &doc.content_hash)?;
    }
    Ok(outcome)
}

/// The title is hashed alongside the content so a rename is not deduped away by an unchanged transcript.
pub(crate) fn build_session_doc(session: &IndexableSession, content: String) -> SessionDoc {
    // S2 (Astra r2 N1): the index is a new file under the sessions root, and extraction joins chunks that were scrubbed
    // one by one (or comes from a legacy transcript), so the assembled text goes through the at-rest layer before it is
    // hashed and bound.
    let title = crate::fts::at_rest_text(&session.title);
    let content = crate::fts::at_rest_text(&content);

    let mut hasher = blake3::Hasher::new();
    hasher.update(title.as_bytes());
    hasher.update(b"\0");
    hasher.update(content.as_bytes());
    let content_hash = hasher.finalize().to_hex().to_string();

    SessionDoc {
        session_id: session.session_id.clone(),
        cwd: session.cwd.clone(),
        updated_at_unix: session.updated_at_unix,
        title,
        content,
        content_hash,
    }
}

#[cfg(test)]
#[path = "doc_tests.rs"]
mod tests;
