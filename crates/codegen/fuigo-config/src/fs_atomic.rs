//! Atomic file writes, shared by the managed-cache marker, the signature sidecar, and downstream identifier caches (e.g. the telemetry agent id).
//!
//! Also home to the cross-process advisory lock that serializes whole
//! read-modify-write cycles over the user's `config.toml`; see
//! [`lock_config_for_write`].

use std::path::{Path, PathBuf};
use std::time::Duration;

/// Write to a temp file then rename, so a torn write can't leave a half-written file.
/// The temp name is unique per writer (pid and counter) and `create_new`, so concurrent writers don't collide.
/// `mode` (unix only) is applied at temp-file creation, so the final file never exists with looser permissions.
/// The temp file's own data is `sync_all`ed before the rename, so a power loss cannot publish the new name over
/// bytes that never reached the disk. The containing directory is NOT synced, so the rename itself can still be
/// lost in a crash — in which case the previous file survives whole, which is the property this function promises.
pub fn write_atomically(
    final_path: &Path,
    contents: &str,
    mode: Option<u32>,
) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    static WRITE_NONCE: AtomicU64 = AtomicU64::new(0);

    let dir = final_path.parent().unwrap_or_else(|| Path::new("."));
    let name = final_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_owned());
    let nonce = WRITE_NONCE.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!("{name}.{}.{nonce}.tmp", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let result = options
        .open(&tmp)
        .and_then(|mut f| {
            f.write_all(contents.as_bytes())?;
            f.sync_all()
        })
        .and_then(|()| std::fs::rename(&tmp, final_path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Mode to create a replacement for `path` with.
///
/// `rename` swaps the inode, so the destination's own mode does not survive on its own: the existing file's
/// mode is read here and re-applied by [`write_atomically`], which is what keeps a user's `chmod 600
/// config.toml` in force. `default_mode` is used when `path` does not exist (or cannot be stat'ed).
/// Always `None` off unix, where [`write_atomically`] ignores `mode` entirely.
#[cfg(unix)]
#[must_use]
pub fn replacement_mode(path: &Path, default_mode: u32) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt as _;
    match std::fs::metadata(path) {
        // The existing mode, minus group and world. `config.toml` can hold
        // credentials — the Claude import writes environment values into it —
        // and faithfully restoring a permissive mode on every rewrite would keep
        // a world-readable config world-readable forever.
        Ok(md) => Some(md.permissions().mode() & 0o700),
        Err(_) => Some(default_mode),
    }
}

/// `write_atomically` ignores `mode` off unix, so there is nothing to compute.
#[cfg(not(unix))]
#[must_use]
pub fn replacement_mode(_path: &Path, _default_mode: u32) -> Option<u32> {
    None
}

/// The lock file guarding `config_path`: the config path with `.lock` appended,
/// e.g. `~/.fuigo/config.toml.lock`.
///
/// One identity, derived from the config path itself, so every writer that
/// takes the lock contends on the same file rather than on a name of its own.
#[must_use]
pub fn config_lock_path(config_path: &Path) -> PathBuf {
    let mut name = config_path.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

/// How long a writer waits for a contended `config.toml` lock before giving up.
///
/// A hard cap with polling rather than a blocking `lock_exclusive`: a wedged or
/// stale holder must never freeze the UI. A write that fails and says so beats
/// one that hangs.
pub const CONFIG_LOCK_MAX_WAIT: Duration = Duration::from_secs(2);

/// How long each poll sleeps while waiting for a contended lock.
const CONFIG_LOCK_RETRY_DELAY: Duration = Duration::from_millis(20);

/// An exclusive advisory `flock` held over one `config.toml` read-modify-write
/// cycle. Dropping it closes the file, which releases the lock — including when
/// the holding process dies.
#[derive(Debug)]
pub struct ConfigWriteLock {
    /// Held only for its `flock`; the contents are never read or written.
    _file: std::fs::File,
}

/// Take the exclusive lock on `config_path` for a read-modify-write cycle.
///
/// # What this does and does not guarantee
///
/// The lock is ADVISORY: it serializes exactly the writers that call this
/// function, and nothing else. A writer that reads and renames without taking
/// it can still overwrite a concurrent writer's change, because `rename` is
/// atomic per-file but says nothing about the read that preceded it.
///
/// The writers that take it are: `/provider` (`fuigo-pager`'s
/// `provider_config_edit`), `set_hint_at` (`fuigo-pager`'s `config_toml_edit`),
/// `set_default_agent`/`toggle_agent` (`fuigo-pager`'s `views::agents_modal`),
/// the shell settings path (`fuigo-shell`'s `util::config::persist::update_config`),
/// the marketplace config writes (`fuigo-shell`'s `extensions::marketplace`),
/// the dashboard persist (`fuigo-pager`'s
/// `views::dashboard::state::write_persisted_to_path`), the `marketplace
/// add`/`remove` CLI paths (`fuigo-pager`'s `plugin_cmd`), the ACP connect-flag
/// write (`fuigo-pager`'s `acp::apply_config_writes`), and the user-scope MCP
/// writes (`fuigo-shell`'s `util::config::mcp`, which takes this *and* the
/// process-local `SAVE_LOCK`), and the Claude-import writers (`fuigo-shell`'s
/// `claude_import::write_import_marker` and `apply_items_to_config`).
///
/// The list is load-bearing, not decoration: a new writer that skips this
/// function silently reintroduces the lost update, and nothing here can detect
/// it. It is also the kind of claim that rots -- an earlier revision of this
/// comment asserted the list was exhaustive while four writers were missing
/// from it -- so treat it as a claim to re-verify, not a fact to trust.
///
/// # Errors
///
/// - `TimedOut` when the lock is still held after [`CONFIG_LOCK_MAX_WAIT`].
/// - Any other I/O error from creating or opening the lock file, or from a
///   `flock` that failed for a reason other than contention (e.g. a filesystem
///   that does not implement it). The error is propagated rather than silently
///   proceeding unlocked, so a caller never believes it is serialized when it is not.
pub fn lock_config_for_write(config_path: &Path) -> std::io::Result<ConfigWriteLock> {
    use fs2::FileExt as _;

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let lock_path = config_lock_path(config_path);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        // The contents are irrelevant; truncate(false) also silences
        // clippy::suspicious_open_options.
        .truncate(false)
        .open(&lock_path)?;

    let deadline = std::time::Instant::now() + CONFIG_LOCK_MAX_WAIT;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(ConfigWriteLock { _file: file }),
            Err(e) if lock_is_contended(&e) => {}
            Err(e) => return Err(e),
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "{} is locked by another Fuigo process; gave up after {:?} \
                     rather than blocking. Retry, or remove that lock file if no \
                     other Fuigo is running.",
                    lock_path.display(),
                    CONFIG_LOCK_MAX_WAIT
                ),
            ));
        }
        std::thread::sleep(CONFIG_LOCK_RETRY_DELAY.min(remaining));
    }
}

/// Run `body` while holding the `config_path` write lock, releasing it after.
///
/// `body` must perform the whole read-modify-write: reading outside the lock
/// and only writing inside it is exactly the lost update this guards against.
/// Carries the same advisory caveats as [`lock_config_for_write`].
///
/// # Errors
///
/// Only lock acquisition failures; `body`'s own result is returned in `Ok`.
pub fn locked_read_modify_write<T>(
    config_path: &Path,
    body: impl FnOnce() -> T,
) -> std::io::Result<T> {
    let _lock = lock_config_for_write(config_path)?;
    Ok(body())
}

/// Not `WouldBlock`: Windows surfaces contention (ERROR_LOCK_VIOLATION) as `Uncategorized`.
fn lock_is_contended(e: &std::io::Error) -> bool {
    let contended = fs2::lock_contended_error();
    e.kind() == contended.kind() && e.raw_os_error() == contended.raw_os_error()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_path_is_the_config_path_with_a_lock_suffix() {
        assert_eq!(
            config_lock_path(Path::new("/home/u/.fuigo/config.toml")),
            PathBuf::from("/home/u/.fuigo/config.toml.lock"),
        );
    }

    /// The lock is exclusive across independently opened handles, which is what
    /// makes it work between two processes rather than only within one.
    #[test]
    fn a_second_holder_is_refused_until_the_first_drops() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");

        let first = lock_config_for_write(&config).expect("first holder");
        let err = lock_config_for_write(&config).expect_err("second holder must not get in");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");

        drop(first);
        lock_config_for_write(&config).expect("released lock must be re-acquirable");
    }

    /// A missing `~/.fuigo` must not make locking fail before the config can be created.
    #[test]
    fn locking_creates_a_missing_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("nested/deeper/config.toml");

        let _lock = lock_config_for_write(&config).expect("lock");
        assert!(config_lock_path(&config).exists());
    }

    #[test]
    fn write_atomically_leaves_no_temp_file_and_writes_the_contents() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("f.txt");

        write_atomically(&target, "hello", None).unwrap();

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello");
        let strays: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(strays.is_empty(), "temp files left behind: {strays:?}");
    }
}
