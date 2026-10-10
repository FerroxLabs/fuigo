//! Log files in the per-turn session archive.
//!
//! The archive copy is rebuilt in memory at every turn end, and logs grow without bound, so they are bounded twice:
//! each log keeps at most [`MAX_ARCHIVED_LOG_BYTES`] (both ends around a marker, so "full output at" pointers still
//! lead somewhere after a restore), and `terminal/` logs are admitted newest first until
//! [`MAX_ARCHIVED_TERMINAL_BYTES`] is spent.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use super::CopiedSessionFile;

/// Session subdirectory holding each command's complete output.
pub(super) const TERMINAL_DIR: &str = "terminal";

/// Largest log kept whole in the per-turn session archive; a larger log keeps its first and last half of this.
pub(super) const MAX_ARCHIVED_LOG_BYTES: u64 = 1024 * 1024;

/// Total `terminal/` log bytes in one archive copy.
pub(super) const MAX_ARCHIVED_TERMINAL_BYTES: u64 = 16 * 1024 * 1024;

pub(super) const TRIM_MARKER: &[u8] = b"\n[... trimmed for the session archive ...]\n";

/// Reads a log whole when it fits in [`MAX_ARCHIVED_LOG_BYTES`], otherwise its first and last halves around [`TRIM_MARKER`].
///
/// A log is never dropped because it changed size: if it shrank (rotation, truncation) after the size check, what is
/// there now is read from the start, capped. When the log is valid UTF-8, a cut never splits a codepoint.
pub(super) fn read_log_for_archive(file: File) -> io::Result<Vec<u8>> {
    read_log_with_hook(file, || {})
}

/// [`read_log_for_archive`] with a hook between the head read and the tail seek, so a test can change the file there.
pub(super) fn read_log_with_hook(mut file: File, between_head_and_tail: impl FnOnce()) -> io::Result<Vec<u8>> {
    let len = file.metadata()?.len();
    let mut data = Vec::with_capacity(len.min(MAX_ARCHIVED_LOG_BYTES) as usize + TRIM_MARKER.len());
    if len <= MAX_ARCHIVED_LOG_BYTES {
        // A log that is still being written can grow past `len` before this read.
        file.take(MAX_ARCHIVED_LOG_BYTES).read_to_end(&mut data)?;
        return Ok(data);
    }
    let half = MAX_ARCHIVED_LOG_BYTES / 2;
    (&mut file).take(half).read_to_end(&mut data)?;
    between_head_and_tail();
    let still_long = file.metadata().is_ok_and(|m| m.len() > MAX_ARCHIVED_LOG_BYTES);
    if still_long && file.seek(SeekFrom::End(-(half as i64))).is_ok() {
        let mut tail = Vec::with_capacity(half as usize);
        if (&mut file).take(half).read_to_end(&mut tail).is_ok() {
            trim_split_codepoint_at_end(&mut data);
            data.extend_from_slice(TRIM_MARKER);
            let skip = split_codepoint_prefix(&tail);
            data.extend_from_slice(&tail[skip..]);
            return Ok(data);
        }
    }
    // The log shrank or could not be sought: keep what is there now rather than dropping it.
    file.seek(SeekFrom::Start(0))?;
    data.clear();
    file.take(MAX_ARCHIVED_LOG_BYTES).read_to_end(&mut data)?;
    Ok(data)
}

/// Drops a trailing partial codepoint (at most 3 bytes) when everything before it is valid UTF-8.
fn trim_split_codepoint_at_end(head: &mut Vec<u8>) {
    if let Err(e) = std::str::from_utf8(head)
        && e.error_len().is_none()
        && head.len() - e.valid_up_to() <= 3
    {
        head.truncate(e.valid_up_to());
    }
}

/// How many leading continuation bytes (at most 3) of `tail` belong to a codepoint the cut split, when the rest is valid UTF-8.
fn split_codepoint_prefix(tail: &[u8]) -> usize {
    let skip = tail.iter().take(3).take_while(|b| (**b & 0xC0) == 0x80).count();
    if skip > 0 && std::str::from_utf8(&tail[skip..]).is_ok() {
        skip
    } else {
        0
    }
}

/// Adds `terminal/` logs, newest first, until [`MAX_ARCHIVED_TERMINAL_BYTES`] is spent: a long session keeps thousands.
///
/// Fuigo keeps its no-follow read (P146): every log is opened relative to the session folder without following a link,
/// so a link planted in `terminal/` (or `terminal/` itself being a link) pulls nothing from outside the session.
pub(super) fn collect_terminal_logs(base: &Path, files: &mut Vec<CopiedSessionFile>) {
    let dir = base.join(TERMINAL_DIR);
    // `read_dir` follows a symlinked `terminal/`, which would copy its target's files; the session walker skips symlinks too.
    if !std::fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir()) {
        return;
    }
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    let mut logs: Vec<_> = entries
        .flatten()
        .filter_map(|entry| {
            // `DirEntry::file_type` and `metadata` do not follow a link: a symlink is neither a file nor admitted here.
            if !entry.file_type().ok()?.is_file() {
                return None;
            }
            let meta = entry.metadata().ok()?;
            Some((meta.modified().ok(), meta.len(), entry.path()))
        })
        .collect();
    // Equal mtimes (coarse clocks, bulk writes) fall back to the file name so the budget cut is stable.
    logs.sort_by(|(ma, _, pa), (mb, _, pb)| mb.cmp(ma).then_with(|| pa.cmp(pb)));

    let mut budget = MAX_ARCHIVED_TERMINAL_BYTES;
    let mut left_out = 0_usize;
    for (_, len, path) in logs {
        let Some(left) = budget.checked_sub(len.min(MAX_ARCHIVED_LOG_BYTES)) else {
            left_out += 1;
            continue;
        };
        let Ok(rel_path) = path.strip_prefix(base) else {
            continue;
        };
        let Some(name) = super::copied_file_name(rel_path) else {
            continue;
        };
        let file = match crate::session::storage::open_beneath_nofollow(base, rel_path) {
            Ok(file) => file,
            Err(crate::session::storage::BeneathRefusal::Io(error)) => {
                tracing::warn!(?error, "Failed to open terminal log during session copy");
                continue;
            }
            Err(crate::session::storage::BeneathRefusal::Refused(what)) => {
                tracing::warn!(path = %path.display(), what, "session copy: file refused");
                continue;
            }
        };
        match read_log_for_archive(file) {
            Ok(data) => {
                budget = left;
                files.push(CopiedSessionFile {
                    name,
                    data,
                });
            }
            Err(e) => tracing::warn!(?e, "Failed to read terminal log during session copy"),
        }
    }
    if left_out > 0 {
        tracing::debug!(
            left_out,
            "session archive: left out older terminal logs over the per-copy budget"
        );
    }
}
