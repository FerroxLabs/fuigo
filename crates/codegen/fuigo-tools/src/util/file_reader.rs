//! Regular-file-only, optionally byte-capped reads for tool file access (P166/S12; upstream 4247f661 `file_reader.rs`).
//!
//! A plain `fs::read` of a FIFO blocks in `open(2)` until a writer appears (a hung tool call), and a read of a device
//! such as `/dev/zero` never ends. These reads refuse anything but a regular file before reading a byte.
//! Symlinks are followed, as the read tools always did; the no-follow session-store reads (P146) do not use this path.

use std::{io, path::Path};

use tokio::io::AsyncReadExt;

/// Prefix of the `InvalidInput` message for a FIFO, device, socket or other non-regular source.
pub const NOT_REGULAR_FILE: &str = "not a regular file";

fn non_regular_kind(file_type: &std::fs::FileType) -> &'static str {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if file_type.is_fifo() {
            return "a FIFO (named pipe)";
        }
        if file_type.is_char_device() {
            return "a character device";
        }
        if file_type.is_block_device() {
            return "a block device";
        }
        if file_type.is_socket() {
            return "a socket";
        }
    }
    let _ = file_type;
    "a special file"
}

fn require_regular(metadata: &std::fs::Metadata) -> io::Result<()> {
    if metadata.is_file() {
        return Ok(());
    }
    if metadata.is_dir() {
        return Err(io::Error::new(io::ErrorKind::IsADirectory, "is a directory"));
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "{NOT_REGULAR_FILE}: it is {}",
            non_regular_kind(&metadata.file_type())
        ),
    ))
}

fn too_large(max_bytes: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::FileTooLarge,
        format!("file exceeds the {max_bytes} byte read limit"),
    )
}

/// Read a whole regular file, following symlinks.
///
/// With `max_bytes`, never acquires more than `max_bytes + 1` bytes: a larger file (or one that grows past the cap
/// while being read) is a `FileTooLarge` error, never a silently truncated read.
///
/// # Errors
/// I/O errors; `IsADirectory` for a directory; `InvalidInput` (message starting with [`NOT_REGULAR_FILE`]) for a FIFO,
/// device, socket or other special file; `FileTooLarge` over the cap.
pub async fn read_regular_file(path: &Path, max_bytes: Option<usize>) -> io::Result<Vec<u8>> {
    // Refuse before open: opening a FIFO blocks and opening a device can have side effects.
    let metadata = tokio::fs::metadata(path).await?;
    require_regular(&metadata)?;
    if let Some(max) = max_bytes
        && metadata.len() > u64::try_from(max).unwrap_or(u64::MAX)
    {
        return Err(too_large(max));
    }
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    // If the path is swapped for a FIFO after the stat, the open still returns at once instead of blocking.
    #[cfg(unix)]
    options.custom_flags((nix::fcntl::OFlag::O_NONBLOCK | nix::fcntl::OFlag::O_NOCTTY).bits());
    let mut file = options.open(path).await?;
    // The opened object decides, not the earlier stat.
    require_regular(&file.metadata().await?)?;
    let expected = usize::try_from(metadata.len()).unwrap_or(0);
    match max_bytes {
        Some(max) => read_capped(file, max, expected).await,
        None => {
            let mut bytes = Vec::with_capacity(expected);
            file.read_to_end(&mut bytes).await?;
            Ok(bytes)
        }
    }
}

/// Read `reader` to its end, acquiring at most `max + 1` bytes; more than `max` is `FileTooLarge`.
/// Bounds sources whose size the stat did not show (procfs, a file that grows after the stat).
async fn read_capped<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
    max: usize,
    size_hint: usize,
) -> io::Result<Vec<u8>> {
    let probe = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::with_capacity(size_hint.min(max));
    reader.take(probe).read_to_end(&mut bytes).await?;
    if bytes.len() > max {
        return Err(too_large(max));
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "file_reader_tests.rs"]
mod tests;
