//! `CheckedDir`: the checked `<home>/peers` directory handle (S3.3). Unix here; Windows in `win_dirs.rs`.

#[cfg(not(any(unix, windows)))]
use super::Disabled;

#[cfg(not(any(unix, windows)))]
#[derive(Debug)]
pub(crate) struct CheckedDir {
    _private: (),
}

#[cfg(not(any(unix, windows)))]
impl CheckedDir {
    pub(crate) fn open(_home: &std::path::Path) -> Result<CheckedDir, Disabled> {
        Err(Disabled::UnsupportedPlatform)
    }
    pub(crate) fn create_or_open(_home: &std::path::Path) -> Result<CheckedDir, Disabled> {
        Err(Disabled::UnsupportedPlatform)
    }
    pub(crate) fn create_under(_base: &std::path::Path, _levels: &[&str]) -> Result<CheckedDir, Disabled> {
        Err(Disabled::UnsupportedPlatform)
    }
}

#[cfg(windows)]
pub(crate) use super::win_dirs::CheckedDir;
#[cfg(unix)]
pub(crate) use imp::CheckedDir;
#[cfg(unix)]
pub(super) use imp::{check_file, cstr, errno, fstat};

#[cfg(unix)]
mod imp {
    // Field types differ per platform (macOS `st_mode` is u16), so same-type casts are intentional.
    #![allow(clippy::unnecessary_cast)]
    use super::super::{Disabled, Reject};
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::path::{Component, Path, PathBuf};

    #[cfg(any(target_os = "linux", target_os = "android"))]
    const SEARCH_ONLY: libc::c_int = libc::O_PATH;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const SEARCH_ONLY: libc::c_int = libc::O_RDONLY;

    const DIR_FLAGS: libc::c_int = libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC;

    pub(in super::super) fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    pub(in super::super) fn cstr(name: &str) -> Result<CString, Disabled> {
        CString::new(name).map_err(|_| Disabled::InvalidName)
    }

    pub(in super::super) fn fstat(fd: RawFd) -> Result<libc::stat, Disabled> {
        let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
        // SAFETY: `st` is a valid out pointer; `fd` is an open descriptor owned by the caller.
        if unsafe { libc::fstat(fd, st.as_mut_ptr()) } != 0 {
            return Err(Disabled::Io(errno()));
        }
        // SAFETY: fstat succeeded and filled the struct.
        Ok(unsafe { st.assume_init() })
    }

    pub(in super::super) fn mode_bits(st: &libc::stat) -> u32 {
        st.st_mode as u32
    }

    pub(in super::super) fn euid() -> u32 {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    }

    /// The S3.4 file checks shared by locator and lock files. `max_size` is checked before any read.
    pub(in super::super) fn check_file(
        st: &libc::stat,
        max_size: Option<u64>,
    ) -> Result<(), Reject> {
        let fmt = mode_bits(st) & libc::S_IFMT as u32;
        if fmt == libc::S_IFLNK as u32 {
            return Err(Reject::Symlink);
        }
        if fmt != libc::S_IFREG as u32 {
            return Err(Reject::NotRegular);
        }
        if st.st_uid != euid() {
            return Err(Reject::WrongOwner);
        }
        if mode_bits(st) & 0o7777 != 0o600 {
            return Err(Reject::WrongMode);
        }
        if st.st_nlink as u64 != 1 {
            return Err(Reject::HardLinked);
        }
        if max_size.is_some_and(|max| (st.st_size as u64) > max) {
            return Err(Reject::TooLarge);
        }
        Ok(())
    }

    enum DirErr {
        Missing,
        Symlink,
        NotDir,
        Io(i32),
    }

    fn openat_dir(dirfd: RawFd, name: &std::ffi::OsStr, extra: libc::c_int) -> Result<OwnedFd, DirErr> {
        use std::os::unix::ffi::OsStrExt;
        let c = CString::new(name.as_bytes()).map_err(|_| DirErr::NotDir)?;
        // SAFETY: valid NUL-terminated name; flags are plain open flags.
        let fd = unsafe { libc::openat(dirfd, c.as_ptr(), extra | DIR_FLAGS) };
        if fd >= 0 {
            // SAFETY: openat returned a fresh descriptor that nothing else owns.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        let e = errno();
        match e {
            libc::ENOENT => Err(DirErr::Missing),
            x if x == libc::ELOOP || x == libc::ENOTDIR || x == libc::EMLINK => {
                let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
                // SAFETY: valid name and out pointer.
                let r = unsafe {
                    libc::fstatat(dirfd, c.as_ptr(), st.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW)
                };
                if r == 0 {
                    // SAFETY: fstatat succeeded.
                    let st = unsafe { st.assume_init() };
                    if mode_bits(&st) & libc::S_IFMT as u32 == libc::S_IFLNK as u32 {
                        return Err(DirErr::Symlink);
                    }
                }
                Err(DirErr::NotDir)
            }
            other => Err(DirErr::Io(other)),
        }
    }

    fn writable_by_others(mode: u32) -> bool {
        mode & (libc::S_IWGRP as u32 | libc::S_IWOTH as u32) != 0 && mode & libc::S_ISVTX as u32 == 0
    }

    fn check_ancestor(fd: &OwnedFd) -> Result<(), Disabled> {
        let st = fstat(fd.as_raw_fd())?;
        if st.st_uid != euid() && st.st_uid != 0 {
            return Err(Disabled::AncestorWrongOwner);
        }
        if writable_by_others(mode_bits(&st)) {
            return Err(Disabled::AncestorWritableByOthers);
        }
        Ok(())
    }

    /// Walk from `/` down to the home with no-follow opens, checking every ancestor (S3.3). The home's PARENT
    /// path is canonicalised first (a root-owned `/home` symlink is a normal layout); the home itself is never
    /// resolved: a symlinked home fails closed.
    fn open_home(home: &Path) -> Result<OwnedFd, Disabled> {
        if !home.is_absolute() {
            return Err(Disabled::HomeNotAbsolute);
        }
        let mut parts = Vec::new();
        for c in home.components() {
            match c {
                Component::RootDir => {}
                Component::Normal(s) => parts.push(s),
                _ => return Err(Disabled::HomePathNotNormal),
            }
        }
        let Some((last, parents)) = parts.split_last() else {
            return Err(Disabled::HomePathNotNormal);
        };
        let mut parent = PathBuf::from("/");
        parent.extend(parents);
        // Unix-only code (the Windows verbatim-path ban does not apply). Only the home PARENT is resolved; the home never is.
        #[allow(clippy::disallowed_methods)]
        let canon = std::fs::canonicalize(&parent).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Disabled::AncestorMissing,
            _ => Disabled::Io(e.raw_os_error().unwrap_or(0)),
        })?;
        // SAFETY: constant NUL-terminated path.
        let root = unsafe {
            libc::open(c"/".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
        };
        if root < 0 {
            return Err(Disabled::Io(errno()));
        }
        // SAFETY: fresh descriptor.
        let mut cur = unsafe { OwnedFd::from_raw_fd(root) };
        check_ancestor(&cur)?;
        for comp in canon.components() {
            let Component::Normal(name) = comp else { continue };
            cur = openat_dir(cur.as_raw_fd(), name, SEARCH_ONLY).map_err(|e| match e {
                DirErr::Missing => Disabled::AncestorMissing,
                DirErr::Symlink => Disabled::AncestorSymlink,
                DirErr::NotDir => Disabled::AncestorNotDirectory,
                DirErr::Io(n) => Disabled::Io(n),
            })?;
            check_ancestor(&cur)?;
        }
        let home_fd = openat_dir(cur.as_raw_fd(), last, SEARCH_ONLY).map_err(|e| match e {
            DirErr::Missing => Disabled::HomeMissing,
            DirErr::Symlink => Disabled::SymlinkedHome,
            DirErr::NotDir => Disabled::HomeNotDirectory,
            DirErr::Io(n) => Disabled::Io(n),
        })?;
        let st = fstat(home_fd.as_raw_fd())?;
        if st.st_uid != euid() {
            return Err(Disabled::HomeWrongOwner);
        }
        // Stricter than for an ancestor: a sticky bit does not excuse a group- or world-writable HOME,
        // because another user could then create `peers` inside it.
        if mode_bits(&st) & (libc::S_IWGRP as u32 | libc::S_IWOTH as u32) != 0 {
            return Err(Disabled::HomeWritableByOthers);
        }
        Ok(home_fd)
    }

    fn check_peers(fd: &OwnedFd) -> Result<(), Disabled> {
        let st = fstat(fd.as_raw_fd())?;
        if st.st_uid != euid() {
            return Err(Disabled::PeersWrongOwner);
        }
        if mode_bits(&st) & 0o7777 != 0o700 {
            return Err(Disabled::PeersWrongMode);
        }
        Ok(())
    }

    /// `mkdirat` (0700) when missing, then a no-follow open and the owner and mode checks over the fd.
    fn create_or_open_level(parent: &OwnedFd, name: &str, is_peers: bool) -> Result<OwnedFd, Disabled> {
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(Disabled::InvalidName);
        }
        let c = cstr(name)?;
        let mut created = false;
        // SAFETY: valid fd and NUL-terminated single-component name; mkdirat never follows a final symlink.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), 0o700) } == 0 {
            created = true;
        } else if errno() != libc::EEXIST {
            return Err(Disabled::Io(errno()));
        }
        let fd = openat_dir(parent.as_raw_fd(), std::ffi::OsStr::new(name), libc::O_RDONLY).map_err(|e| match (e, is_peers) {
            (DirErr::Missing, true) => Disabled::PeersMissing,
            (DirErr::Symlink, true) => Disabled::PeersSymlink,
            (DirErr::NotDir, true) => Disabled::PeersNotDirectory,
            (DirErr::Missing, false) => Disabled::AncestorMissing,
            (DirErr::Symlink, false) => Disabled::AncestorSymlink,
            (DirErr::NotDir, false) => Disabled::AncestorNotDirectory,
            (DirErr::Io(n), _) => Disabled::Io(n),
        })?;
        if created {
            // SAFETY: valid fd. The umask may have stripped bits; we made it, so set it exactly.
            if unsafe { libc::fchmod(fd.as_raw_fd(), 0o700) } != 0 {
                return Err(Disabled::Io(errno()));
            }
        }
        if is_peers {
            check_peers(&fd)?;
        } else {
            let st = fstat(fd.as_raw_fd())?;
            if st.st_uid != euid() {
                return Err(Disabled::AncestorWrongOwner);
            }
            if mode_bits(&st) & (libc::S_IWGRP as u32 | libc::S_IWOTH as u32) != 0 {
                return Err(Disabled::AncestorWritableByOthers);
            }
        }
        Ok(fd)
    }

    /// The checked `<home>/peers` directory. Holds the directory fd; all later file access is relative to it.
    #[derive(Debug)]
    pub(crate) struct CheckedDir {
        fd: OwnedFd,
    }

    impl CheckedDir {
        /// Open `<home>/peers`, checking home, every ancestor and the directory itself. Never creates anything.
        pub(crate) fn open(home: &Path) -> Result<CheckedDir, Disabled> {
            Self::open_inner(home, false)
        }

        /// The ONLY function in this module that creates a directory: makes `<home>/peers` (mode 0700) if
        /// missing, then re-checks it through the fd. The home itself must already exist and pass its checks.
        pub(crate) fn create_or_open(home: &Path) -> Result<CheckedDir, Disabled> {
            Self::open_inner(home, true)
        }

        fn open_inner(home: &Path, create: bool) -> Result<CheckedDir, Disabled> {
            let home_fd = open_home(home)?;
            let mut created = false;
            if create {
                // SAFETY: valid fd and NUL-terminated name.
                let r = unsafe { libc::mkdirat(home_fd.as_raw_fd(), c"peers".as_ptr(), 0o700) };
                if r == 0 {
                    created = true;
                } else if errno() != libc::EEXIST {
                    return Err(Disabled::Io(errno()));
                }
            }
            let fd = openat_dir(
                home_fd.as_raw_fd(),
                std::ffi::OsStr::new("peers"),
                libc::O_RDONLY,
            )
            .map_err(|e| match e {
                DirErr::Missing => Disabled::PeersMissing,
                DirErr::Symlink => Disabled::PeersSymlink,
                DirErr::NotDir => Disabled::PeersNotDirectory,
                DirErr::Io(n) => Disabled::Io(n),
            })?;
            if created {
                // The umask may have stripped bits; we made it, so set it exactly.
                // SAFETY: valid fd.
                if unsafe { libc::fchmod(fd.as_raw_fd(), 0o700) } != 0 {
                    return Err(Disabled::Io(errno()));
                }
            }
            check_peers(&fd)?;
            Ok(CheckedDir { fd })
        }

        /// Create (one component at a time, relative to a directory fd, with no-follow opens) and check the levels
        /// `levels` under `base`, then `<base>/<levels>/peers`. `base` must be an absolute, plain path whose last
        /// directory is ours and not group- or world-writable (else `RuntimeDirUnavailable`). Each level must be
        /// ours and not group- or world-writable; `peers` must be exactly 0700. A symlink at any level is refused
        /// and nothing is created through it.
        pub(crate) fn create_under(base: &Path, levels: &[&str]) -> Result<CheckedDir, Disabled> {
            let mut cur = open_home(base).map_err(|_| Disabled::RuntimeDirUnavailable)?;
            for name in levels {
                cur = create_or_open_level(&cur, name, false)?;
            }
            let fd = create_or_open_level(&cur, "peers", true)?;
            Ok(CheckedDir { fd })
        }

        pub(in super::super) fn raw(&self) -> RawFd {
            self.fd.as_raw_fd()
        }
    }
}
