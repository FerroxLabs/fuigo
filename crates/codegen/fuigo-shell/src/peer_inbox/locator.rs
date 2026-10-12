//! Locator file read and update, relative to a [`CheckedDir`] (S3.4). Synchronous: use `spawn_blocking`.

#[cfg(any(unix, not(windows)))]
use super::{CheckedDir, Disabled};

#[cfg(windows)]
pub(crate) use super::win_locator::{read_locator, update_locator, update_locator_rewriting};

#[cfg(not(any(unix, windows)))]
pub(crate) fn read_locator(_dir: &CheckedDir, _name: &str) -> Result<Option<Vec<u8>>, Disabled> {
    Err(Disabled::UnsupportedPlatform)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn update_locator(
    _dir: &CheckedDir,
    _name: &str,
    _f: impl FnOnce(Option<&[u8]>) -> Option<Vec<u8>>,
) -> Result<(), Disabled> {
    Err(Disabled::UnsupportedPlatform)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn update_locator_rewriting(
    _dir: &CheckedDir,
    _name: &str,
    _f: impl FnOnce(Option<&[u8]>) -> Option<Vec<u8>>,
) -> Result<(), Disabled> {
    Err(Disabled::UnsupportedPlatform)
}

#[cfg(unix)]
pub(crate) use imp::{read_locator, update_locator, update_locator_rewriting};

#[cfg(unix)]
mod imp {
    use super::super::dirs::{check_file, cstr, errno, fstat};
    use super::super::{Disabled, Reject, MAX_LOCATOR_BYTES};
    use super::CheckedDir;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::sync::atomic::{AtomicU64, Ordering};

    const LOCK_NAME: &str = ".lock";
    /// Total time `update_locator` waits for the directory lock before giving up with `Disabled::LockBusy`.
    const LOCK_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);
    const LOCK_RETRY_GAP: std::time::Duration = std::time::Duration::from_millis(10);
    const TMP_PREFIX: &str = ".tmp-";

    fn validate_name(name: &str) -> Result<(), Disabled> {
        let bad = name.is_empty()
            || name.len() > 200
            || name == "."
            || name == ".."
            || name.contains(['/', '\0'])
            || name == LOCK_NAME
            || name.starts_with(TMP_PREFIX);
        if bad { Err(Disabled::InvalidName) } else { Ok(()) }
    }

    /// Read a locator file. `Ok(None)` if absent. A file failing any check returns
    /// `Err(Disabled::Rejected(reason))`: the caller treats that as "rewrite" and the bytes are never parsed.
    pub(crate) fn read_locator(dir: &CheckedDir, name: &str) -> Result<Option<Vec<u8>>, Disabled> {
        validate_name(name)?;
        read_at(dir.raw(), name)
    }

    fn read_at(dirfd: RawFd, name: &str) -> Result<Option<Vec<u8>>, Disabled> {
        let c = cstr(name)?;
        // SAFETY: valid dirfd and NUL-terminated name. O_NONBLOCK so a FIFO swapped in cannot block the open.
        let fd = unsafe {
            libc::openat(
                dirfd,
                c.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return match errno() {
                libc::ENOENT => Ok(None),
                e if e == libc::ELOOP || e == libc::EMLINK => Err(Disabled::Rejected(Reject::Symlink)),
                e => Err(Disabled::Io(e)),
            };
        }
        // SAFETY: fresh descriptor.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let st = fstat(owned.as_raw_fd())?;
        check_file(&st, Some(MAX_LOCATOR_BYTES)).map_err(Disabled::Rejected)?;
        let mut buf = Vec::new();
        let n = std::fs::File::from(owned)
            .take(MAX_LOCATOR_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(|e| Disabled::Io(e.raw_os_error().unwrap_or(0)))?;
        if n as u64 > MAX_LOCATOR_BYTES {
            return Err(Disabled::Rejected(Reject::TooLarge));
        }
        Ok(Some(buf))
    }

    /// Exclusive `flock` on the directory's lock file; released on every path (RAII, including panics).
    struct LockGuard(OwnedFd);

    impl Drop for LockGuard {
        fn drop(&mut self) {
            // SAFETY: valid fd. Closing also releases; the explicit unlock is belt and braces.
            unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
        }
    }

    fn acquire_lock(dirfd: RawFd) -> Result<LockGuard, Disabled> {
        let c = cstr(LOCK_NAME)?;
        let base = libc::O_RDWR | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
        let mut fd = -1;
        for _ in 0..4 {
            // SAFETY: valid dirfd and name.
            fd = unsafe {
                libc::openat(dirfd, c.as_ptr(), base | libc::O_CREAT | libc::O_EXCL, 0o600 as libc::c_uint)
            };
            if fd >= 0 {
                // We created it: set the mode exactly (umask may have stripped bits).
                // SAFETY: valid fd.
                if unsafe { libc::fchmod(fd, 0o600) } != 0 {
                    let e = errno();
                    // SAFETY: fd is ours.
                    unsafe { libc::close(fd) };
                    return Err(Disabled::Io(e));
                }
                break;
            }
            if errno() != libc::EEXIST {
                return Err(Disabled::Io(errno()));
            }
            // SAFETY: valid dirfd and name; no O_CREAT, so an existing symlink is refused.
            fd = unsafe { libc::openat(dirfd, c.as_ptr(), base) };
            if fd >= 0 {
                break;
            }
            match errno() {
                libc::ENOENT => continue,
                e if e == libc::ELOOP || e == libc::EMLINK => {
                    return Err(Disabled::LockRejected(Reject::Symlink));
                }
                e => return Err(Disabled::Io(e)),
            }
        }
        if fd < 0 {
            return Err(Disabled::Io(errno()));
        }
        // SAFETY: fresh descriptor.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let st = fstat(owned.as_raw_fd())?;
        check_file(&st, None).map_err(Disabled::LockRejected)?;
        // Bounded: a same-user process that holds the lock must not be able to stall us. LOCK_NB in a short
        // retry loop with a total deadline; on timeout the caller gets the typed `LockBusy`.
        let give_up = std::time::Instant::now() + LOCK_DEADLINE;
        loop {
            // SAFETY: valid fd. Non-blocking.
            if unsafe { libc::flock(owned.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let e = errno();
            if e == libc::EWOULDBLOCK || e == libc::EAGAIN {
                if std::time::Instant::now() >= give_up {
                    return Err(Disabled::LockBusy);
                }
                std::thread::sleep(LOCK_RETRY_GAP);
            } else if e != libc::EINTR {
                return Err(Disabled::Io(e));
            }
        }
        Ok(LockGuard(owned))
    }

    /// Removes the temp file on drop unless it was renamed into place.
    struct TempGuard<'a> {
        dirfd: RawFd,
        name: &'a std::ffi::CStr,
        armed: bool,
    }

    impl Drop for TempGuard<'_> {
        fn drop(&mut self) {
            if self.armed {
                // SAFETY: valid dirfd and name.
                unsafe { libc::unlinkat(self.dirfd, self.name.as_ptr(), 0) };
            }
        }
    }

    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    fn write_temp_and_rename(dirfd: RawFd, name: &str, bytes: &[u8]) -> Result<(), Disabled> {
        let target = cstr(name)?;
        for _ in 0..8 {
            let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let tmp_name = format!("{TMP_PREFIX}{}-{seq}", std::process::id());
            let tmp = cstr(&tmp_name)?;
            // SAFETY: valid dirfd and name; O_EXCL|O_NOFOLLOW means we never open an existing entry.
            let fd = unsafe {
                libc::openat(
                    dirfd,
                    tmp.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0o600 as libc::c_uint,
                )
            };
            if fd < 0 {
                if errno() == libc::EEXIST {
                    continue;
                }
                return Err(Disabled::Io(errno()));
            }
            // SAFETY: fresh descriptor.
            let owned = unsafe { OwnedFd::from_raw_fd(fd) };
            let mut guard = TempGuard { dirfd, name: &tmp, armed: true };
            // SAFETY: valid fd.
            if unsafe { libc::fchmod(owned.as_raw_fd(), 0o600) } != 0 {
                return Err(Disabled::Io(errno()));
            }
            let mut file = std::fs::File::from(owned);
            file.write_all(bytes).map_err(|e| Disabled::Io(e.raw_os_error().unwrap_or(0)))?;
            file.sync_all().map_err(|e| Disabled::Io(e.raw_os_error().unwrap_or(0)))?;
            drop(file);
            // SAFETY: valid dirfd and names.
            if unsafe { libc::renameat(dirfd, tmp.as_ptr(), dirfd, target.as_ptr()) } != 0 {
                return Err(Disabled::Io(errno()));
            }
            guard.armed = false;
            // Make the rename durable. Best effort: the file content is already synced.
            // SAFETY: valid fd.
            unsafe { libc::fsync(dirfd) };
            return Ok(());
        }
        Err(Disabled::Io(libc::EEXIST))
    }

    fn update_impl(
        dir: &CheckedDir,
        name: &str,
        rewrite_rejected: bool,
        f: impl FnOnce(Option<&[u8]>) -> Option<Vec<u8>>,
    ) -> Result<(), Disabled> {
        validate_name(name)?;
        let dirfd = dir.raw();
        let _lock = acquire_lock(dirfd)?;
        let current = match read_at(dirfd, name) {
            Ok(v) => v,
            Err(Disabled::Rejected(_)) if rewrite_rejected => None,
            Err(e) => return Err(e),
        };
        match f(current.as_deref()) {
            None => {
                let c = cstr(name)?;
                // SAFETY: valid dirfd and name; flags 0 never removes a directory.
                if unsafe { libc::unlinkat(dirfd, c.as_ptr(), 0) } != 0 && errno() != libc::ENOENT {
                    return Err(Disabled::Io(errno()));
                }
                Ok(())
            }
            Some(bytes) => {
                if bytes.len() as u64 > MAX_LOCATOR_BYTES {
                    return Err(Disabled::OutputTooLarge);
                }
                write_temp_and_rename(dirfd, name, &bytes)
            }
        }
    }

    /// Read-modify-write under the directory lock. `f` gets the current bytes (`None` if absent) and returns the
    /// new bytes, or `None` to remove the file. A present file that fails its checks REFUSES the update
    /// (`Err(Rejected(..))`, `f` not called, nothing written). Blocks on the lock: use `spawn_blocking`.
    pub(crate) fn update_locator(
        dir: &CheckedDir,
        name: &str,
        f: impl FnOnce(Option<&[u8]>) -> Option<Vec<u8>>,
    ) -> Result<(), Disabled> {
        update_impl(dir, name, false, f)
    }

    /// Like [`update_locator`], but a present file that fails its checks is treated as absent (`f` gets `None`)
    /// and replaced by `rename`, which never follows or writes through the bad entry. Blocks: use `spawn_blocking`.
    pub(crate) fn update_locator_rewriting(
        dir: &CheckedDir,
        name: &str,
        f: impl FnOnce(Option<&[u8]>) -> Option<Vec<u8>>,
    ) -> Result<(), Disabled> {
        update_impl(dir, name, true, f)
    }
}
