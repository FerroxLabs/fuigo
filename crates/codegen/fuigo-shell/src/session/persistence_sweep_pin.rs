//! P176: the folders the session sweep works in are pinned, so a folder above a session that is swapped for a symlink
//! (or a junction) while the sweep runs can never make it rename, prune or delete anything outside the sessions tree.
//!
//! - Unix: every folder below the sweep's root is opened with `O_DIRECTORY | O_NOFOLLOW` relative to its parent's
//!   descriptor, and every destructive operation (`renameat`, `unlinkat`) and every look it acts on (`fstatat` with
//!   `AT_SYMLINK_NOFOLLOW`, the entry list) is relative to a pinned descriptor, never to a path.
//! - Windows: every pinned folder is held by a handle opened without `FILE_SHARE_DELETE` (and, below the root, with
//!   `FILE_FLAG_OPEN_REPARSE_POINT`, refused when it is a reparse point). While it is held the folder cannot be renamed,
//!   replaced or deleted, and NTFS refuses to rename any folder above an open handle, so the folder's path keeps naming
//!   the folder that was checked: the check and the open are one step. An EMPTY held folder can still be turned into a
//!   junction in place, so every deletion opens its entry itself, checks by final path that it sits directly in the
//!   pinned folder, and deletes through that handle.
//!
//! Path-based reads of the sweep (the activity scan, the lock files an attach also opens by path) are tied to the pins
//! by [`PinnedDir::still_at_path`], which the sweep checks for the whole chain right before it renames a session away.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// What an entry is, its own type (a link is never followed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EntryKind {
    Dir,
    File,
    /// A symlink, a reparse point, or anything else that is neither a real folder nor a regular file.
    Other,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct EntryInfo {
    pub(super) kind: EntryKind,
    pub(super) modified: Option<SystemTime>,
}

/// How deep [`PinnedDir::remove_child_tree`] goes. A session the sweep judged is at most
/// `ACTIVITY_SCAN_MAX_DEPTH` deep; anything deeper stays as a leftover rather than being walked without bound.
const REMOVE_TREE_MAX_DEPTH: usize = 64;

/// One folder the sweep works in, held open for as long as the sweep works in it.
#[derive(Debug)]
pub(super) struct PinnedDir {
    /// The path the sweep names this folder by (logs, the live-session comparison, path-based reads).
    path: PathBuf,
    /// Unix: the `O_DIRECTORY` descriptor. Windows: the handle that keeps the folder (and every folder above it) in
    /// place.
    handle: std::fs::File,
    /// Whether [`Self::path`] may be a link to this folder (only the sweep's root: the user's `~/.fuigo` may live
    /// elsewhere).
    follows_path: bool,
    /// Windows: the path every operation goes through. Below the root it is the root's resolved path joined with real
    /// folder names, so no link anywhere in it.
    #[cfg(windows)]
    os_path: PathBuf,
}

impl PinnedDir {
    /// The sweep's root. Its own path may be a link; nothing below it is ever followed.
    pub(super) fn open_root(path: &Path) -> io::Result<Self> {
        imp::open_root(path)
    }

    /// The real folder `name` in this one, never through a link: a link, a reparse point, or a file there is refused.
    pub(super) fn open_child(&self, name: &OsStr) -> io::Result<Self> {
        imp::open_child(self, name)
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn child_path(&self, name: &OsStr) -> PathBuf {
        self.path.join(name)
    }

    /// Whether this folder's path still names this folder (a real folder, the same one), as checked right before the
    /// sweep acts on what it read through paths.
    pub(super) fn still_at_path(&self) -> bool {
        imp::still_at_path(self)
    }

    /// The names in this folder (without `.` and `..`), read from the pinned folder.
    pub(super) fn entry_names(&self) -> io::Result<Vec<OsString>> {
        imp::entry_names(self)
    }

    /// `name`'s own type and mtime, never through a link.
    pub(super) fn child_info(&self, name: &OsStr) -> io::Result<EntryInfo> {
        imp::child_info(self, name)
    }

    /// Renames `from` to `to`, both in this folder.
    pub(super) fn rename_child(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        imp::rename_child(self, from, to)
    }

    /// Renames `from` to `to`, both in this folder, failing when anything (even an empty folder) is at `to`.
    pub(super) fn rename_child_noreplace(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        imp::rename_child_noreplace(self, from, to)
    }

    /// Like [`Self::rename_child_noreplace`], but where the filesystem or system has no no-replace rename it fails
    /// with `Unsupported` and renames nothing (no look-then-rename window).
    pub(super) fn rename_child_noreplace_strict(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        imp::rename_child_noreplace_strict(self, from, to)
    }

    /// Test-only: the next no-replace rename on this thread reports `EINVAL`, as a filesystem without that call does;
    /// `in_gap` runs at the moment a plain rename would have followed (after the look at the destination).
    #[cfg(all(test, unix))]
    pub(super) fn fail_next_noreplace_with_einval(in_gap: Option<Box<dyn FnOnce()>>) {
        imp::FORCE_EINVAL_ONCE.with(|flag| flag.set(true));
        imp::GAP_HOOK.with(|hook| *hook.borrow_mut() = in_gap);
    }

    /// Removes the non-folder entry `name` (a link is removed itself, never its target).
    pub(super) fn remove_child_file(&self, name: &OsStr) -> io::Result<()> {
        imp::remove_child_file(self, name)
    }

    /// Removes the empty folder `name`.
    pub(super) fn remove_child_empty_dir(&self, name: &OsStr) -> io::Result<()> {
        imp::remove_child_empty_dir(self, name)
    }

    /// Removes `name` and everything beneath it. A link anywhere in the tree is removed itself, never followed.
    pub(super) fn remove_child_tree(&self, name: &OsStr) -> io::Result<()> {
        imp::remove_child_tree(self, name)
    }

    /// Opens (creating, owner-only) the lock file `name` in this folder without following a link at that name. `None`
    /// when it cannot be opened that way (a planted link, a folder there).
    pub(super) fn open_lock(&self, name: &str) -> Option<std::fs::File> {
        imp::open_lock(self, name)
    }
}

#[cfg(unix)]
mod imp {
    use std::ffi::{OsStr, OsString};
    use std::io;
    use std::os::fd::{AsFd as _, OwnedFd};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    use nix::fcntl::{AtFlags, OFlag, openat, renameat};
    use nix::sys::stat::{FileStat, Mode, SFlag, fstat, fstatat};
    use nix::unistd::{UnlinkatFlags, unlinkat};

    use super::{EntryInfo, EntryKind, PinnedDir, REMOVE_TREE_MAX_DEPTH};

    const DIR_FLAGS: OFlag = OFlag::O_RDONLY
        .union(OFlag::O_DIRECTORY)
        .union(OFlag::O_NOFOLLOW)
        .union(OFlag::O_CLOEXEC);

    // `MetadataExt::dev`/`ino` widen the same fields the same way
    #[allow(clippy::unnecessary_cast)]
    fn identity(stat: &FileStat) -> (u64, u64) {
        (stat.st_dev as u64, stat.st_ino as u64)
    }

    fn pinned(path: std::path::PathBuf, fd: OwnedFd, follows_path: bool) -> io::Result<PinnedDir> {
        let handle = std::fs::File::from(fd);
        let stat = fstat(handle.as_fd()).map_err(io::Error::from)?;
        if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR {
            return Err(io::Error::other("not a folder"));
        }
        Ok(PinnedDir { path, handle, follows_path })
    }

    pub(super) fn open_root(path: &Path) -> io::Result<PinnedDir> {
        let fd = openat(
            nix::fcntl::AT_FDCWD,
            path,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        pinned(path.to_path_buf(), fd, true)
    }

    pub(super) fn open_child(dir: &PinnedDir, name: &OsStr) -> io::Result<PinnedDir> {
        let fd = openat(dir.handle.as_fd(), name, DIR_FLAGS, Mode::empty()).map_err(io::Error::from)?;
        pinned(dir.path.join(name), fd, false)
    }

    pub(super) fn still_at_path(dir: &PinnedDir) -> bool {
        let at_path = if dir.follows_path { std::fs::metadata(&dir.path) } else { std::fs::symlink_metadata(&dir.path) };
        let Ok(at_path) = at_path else {
            return false;
        };
        let Ok(held) = fstat(dir.handle.as_fd()) else {
            return false;
        };
        at_path.file_type().is_dir() && (at_path.dev(), at_path.ino()) == identity(&held)
    }

    pub(super) fn entry_names(dir: &PinnedDir) -> io::Result<Vec<OsString>> {
        // A second descriptor for the listing, so the pinned one is never consumed or repositioned
        let fd = openat(dir.handle.as_fd(), ".", DIR_FLAGS, Mode::empty()).map_err(io::Error::from)?;
        let mut listing = nix::dir::Dir::from_fd(fd).map_err(io::Error::from)?;
        let mut names = Vec::new();
        for entry in listing.iter() {
            let entry = entry.map_err(io::Error::from)?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                names.push(OsStr::from_bytes(name).to_os_string());
            }
        }
        Ok(names)
    }

    fn info_of(stat: &FileStat) -> EntryInfo {
        let kind = match SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT {
            SFlag::S_IFDIR => EntryKind::Dir,
            SFlag::S_IFREG => EntryKind::File,
            _ => EntryKind::Other,
        };
        #[allow(clippy::unnecessary_cast)]
        let (secs, nanos) = (stat.st_mtime as i64, stat.st_mtime_nsec as i64);
        let modified = if secs >= 0 {
            SystemTime::UNIX_EPOCH.checked_add(Duration::new(secs.unsigned_abs(), u32::try_from(nanos).unwrap_or(0)))
        } else {
            SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))
        };
        EntryInfo { kind, modified }
    }

    pub(super) fn child_info(dir: &PinnedDir, name: &OsStr) -> io::Result<EntryInfo> {
        let stat = fstatat(dir.handle.as_fd(), name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
        Ok(info_of(&stat))
    }

    pub(super) fn rename_child(dir: &PinnedDir, from: &OsStr, to: &OsStr) -> io::Result<()> {
        renameat(dir.handle.as_fd(), from, dir.handle.as_fd(), to).map_err(io::Error::from)
    }

    #[cfg(test)]
    thread_local! {
        pub(super) static FORCE_EINVAL_ONCE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        pub(super) static GAP_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    }

    #[cfg(test)]
    fn run_gap_hook() {
        if let Some(hook) = GAP_HOOK.with(|hook| hook.borrow_mut().take()) {
            hook();
        }
    }

    /// Linux `renameat2(RENAME_NOREPLACE)`, macOS `renameatx_np(RENAME_EXCL)`. Where the filesystem or system has no
    /// such rename, `to` is looked up first and the plain rename runs only when nothing is there (a narrow window,
    /// stated in the receipt).
    pub(super) fn rename_child_noreplace(dir: &PinnedDir, from: &OsStr, to: &OsStr) -> io::Result<()> {
        noreplace(dir, from, to, true)
    }

    /// The same call without the look-then-plain-rename fallback: `Unsupported` where the call is missing.
    pub(super) fn rename_child_noreplace_strict(dir: &PinnedDir, from: &OsStr, to: &OsStr) -> io::Result<()> {
        noreplace(dir, from, to, false)
    }

    /// The raw call: `Ok` when renamed, else the OS error (or `Other` for an unusable name).
    fn raw_noreplace(dir: &PinnedDir, from: &OsStr, to: &OsStr) -> io::Result<()> {
        use std::os::fd::AsRawFd as _;
        let (Ok(from_c), Ok(to_c)) = (std::ffi::CString::new(from.as_bytes()), std::ffi::CString::new(to.as_bytes()))
        else {
            return Err(io::Error::other("a name with a NUL byte"));
        };
        let fd = dir.handle.as_raw_fd();
        #[cfg(target_os = "linux")]
        #[allow(clippy::unnecessary_cast)]
        // SAFETY: renameat2(2) relative to a live directory descriptor, on two NUL-terminated names.
        let rc = unsafe {
            libc::syscall(libc::SYS_renameat2, fd, from_c.as_ptr(), fd, to_c.as_ptr(), libc::RENAME_NOREPLACE)
        } as i64;
        #[cfg(target_vendor = "apple")]
        #[allow(clippy::unnecessary_cast)]
        // SAFETY: renameatx_np(2) relative to a live directory descriptor, on two NUL-terminated names.
        let rc = unsafe { libc::renameatx_np(fd, from_c.as_ptr(), fd, to_c.as_ptr(), libc::RENAME_EXCL) } as i64;
        #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
        let rc: i64 = {
            let _ = (fd, &from_c, &to_c);
            -1
        };
        if rc == 0 {
            return Ok(());
        }
        Err(io::Error::last_os_error())
    }

    fn noreplace(dir: &PinnedDir, from: &OsStr, to: &OsStr, plain_fallback: bool) -> io::Result<()> {
        #[cfg(test)]
        let raw = if FORCE_EINVAL_ONCE.with(|flag| flag.replace(false)) {
            Err(io::Error::from_raw_os_error(libc::EINVAL))
        } else {
            raw_noreplace(dir, from, to)
        };
        #[cfg(not(test))]
        let raw = raw_noreplace(dir, from, to);
        let Err(error) = raw else {
            return Ok(());
        };
        if error.kind() == io::ErrorKind::Other && error.raw_os_error().is_none() {
            return Err(error);
        }
        let unsupported = cfg!(not(any(target_os = "linux", target_vendor = "apple")))
            || matches!(error.raw_os_error(), Some(libc::EINVAL | libc::ENOSYS | libc::ENOTSUP));
        if !unsupported {
            return Err(error);
        }
        if !plain_fallback {
            #[cfg(test)]
            run_gap_hook();
            return Err(io::Error::new(io::ErrorKind::Unsupported, format!("no no-replace rename here: {error}")));
        }
        match child_info(dir, to) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                #[cfg(test)]
                run_gap_hook();
                rename_child(dir, from, to)
            }
            Err(error) => Err(error),
            Ok(_) => Err(io::Error::from(io::ErrorKind::AlreadyExists)),
        }
    }

    pub(super) fn remove_child_file(dir: &PinnedDir, name: &OsStr) -> io::Result<()> {
        unlinkat(dir.handle.as_fd(), name, UnlinkatFlags::NoRemoveDir).map_err(io::Error::from)
    }

    pub(super) fn remove_child_empty_dir(dir: &PinnedDir, name: &OsStr) -> io::Result<()> {
        unlinkat(dir.handle.as_fd(), name, UnlinkatFlags::RemoveDir).map_err(io::Error::from)
    }

    pub(super) fn remove_child_tree(dir: &PinnedDir, name: &OsStr) -> io::Result<()> {
        remove_tree_at(dir, name, 0)
    }

    fn remove_tree_at(dir: &PinnedDir, name: &OsStr, depth: usize) -> io::Result<()> {
        if child_info(dir, name)?.kind != EntryKind::Dir {
            return remove_child_file(dir, name);
        }
        if depth >= REMOVE_TREE_MAX_DEPTH {
            return Err(io::Error::other(format!("folders nested deeper than {REMOVE_TREE_MAX_DEPTH}")));
        }
        // A folder swapped for a link after the look above is refused here (`O_NOFOLLOW`), never entered
        let child = open_child(dir, name)?;
        for entry in entry_names(&child)? {
            remove_tree_at(&child, &entry, depth + 1)?;
        }
        drop(child);
        remove_child_empty_dir(dir, name)
    }

    pub(super) fn open_lock(dir: &PinnedDir, name: &str) -> Option<std::fs::File> {
        let opened = openat(
            dir.handle.as_fd(),
            name,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        );
        let path = dir.path.join(name);
        match opened {
            Ok(fd) => {
                let file = std::fs::File::from(fd);
                if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
                    return None;
                }
                crate::session::storage::owner_only::tighten(&file, &path).ok()?;
                Some(file)
            }
            Err(error) => {
                tracing::debug!(
                    target: "fuigo_shell::session::persistence",
                    file = %path.display(),
                    %error,
                    "SESSION_LOCK_UNAVAILABLE"
                );
                None
            }
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::{OsStr, OsString};
    use std::io;
    use std::path::Path;

    use super::{EntryInfo, EntryKind, PinnedDir, REMOVE_TREE_MAX_DEPTH};

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const FILE_SHARE_DELETE: u32 = 0x4;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    /// `FILE_READ_ATTRIBUTES | FILE_TRAVERSE`, as P154's `hold_folders_beneath_windows` (verified on Windows): an open
    /// for attribute access alone is not share-checked and would not keep the folder in place.
    const DIR_ACCESS: u32 = 0x80 | 0x20;
    /// `DELETE | FILE_READ_ATTRIBUTES`.
    const DELETE_ACCESS: u32 = 0x0001_0000 | 0x80;
    /// `FILE_INFO_BY_HANDLE_CLASS::FileDispositionInfo` and `FileDispositionInfoEx`.
    const FILE_DISPOSITION_INFO: i32 = 4;
    const FILE_DISPOSITION_INFO_EX: i32 = 21;
    const FILE_DISPOSITION_FLAG_DELETE: u32 = 0x1;
    const FILE_DISPOSITION_FLAG_POSIX_SEMANTICS: u32 = 0x2;
    const FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE: u32 = 0x10;
    const ERROR_INVALID_FUNCTION: i32 = 1;
    const ERROR_NOT_SUPPORTED: i32 = 50;
    const ERROR_INVALID_PARAMETER: i32 = 87;

    // kernel32 is linked by std.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetFileInformationByHandle(file: *mut std::ffi::c_void, class: i32, info: *const std::ffi::c_void, size: u32) -> i32;
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }

    fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
        use std::os::windows::fs::MetadataExt as _;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    /// Opens the folder at `os_path` as a handle without `FILE_SHARE_DELETE`; below the root the entry itself
    /// (`FILE_FLAG_OPEN_REPARSE_POINT`), refused unless it is a real folder. The open and the check are one step: the
    /// checked handle is the one kept.
    fn open_dir_handle(os_path: &Path, follow: bool) -> io::Result<std::fs::File> {
        use std::os::windows::fs::OpenOptionsExt as _;
        let reparse = if follow { 0 } else { FILE_FLAG_OPEN_REPARSE_POINT };
        // FILE_SHARE_WRITE: the sweep renames a session inside a pinned folder, and a rename opens its target folder
        // for adding an entry, which a pin without write sharing would refuse
        let handle = std::fs::OpenOptions::new()
            .access_mode(DIR_ACCESS)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | reparse)
            .open(os_path)?;
        let metadata = handle.metadata()?;
        if !metadata.is_dir() || is_reparse_point(&metadata) {
            return Err(io::Error::other("not a real folder"));
        }
        Ok(handle)
    }

    pub(super) fn open_root(path: &Path) -> io::Result<PinnedDir> {
        // The root's own path may be a link; everything below goes through its resolved path, which has none
        let os_path = dunce::canonicalize(path)?;
        let handle = open_dir_handle(&os_path, true)?;
        Ok(PinnedDir { path: path.to_path_buf(), handle, follows_path: true, os_path })
    }

    /// The child is checked from its own handle to sit directly in `dir` (final paths, as P154's
    /// `hold_folders_beneath_windows`): a pinned folder turned into a junction in place (possible while it is empty)
    /// would otherwise lead the open outside (Astra r2).
    pub(super) fn open_child(dir: &PinnedDir, name: &OsStr) -> io::Result<PinnedDir> {
        let os_path = dir.os_path.join(name);
        let handle = open_dir_handle(&os_path, false)?;
        ensure_direct_child(dir, &handle, name)?;
        Ok(PinnedDir { path: dir.path.join(name), handle, follows_path: false, os_path })
    }

    pub(super) fn still_at_path(dir: &PinnedDir) -> bool {
        // The held handle keeps `os_path` in place; `path` must still lead to a real folder
        let at_path = if dir.follows_path { std::fs::metadata(&dir.path) } else { std::fs::symlink_metadata(&dir.path) };
        at_path.is_ok_and(|metadata| metadata.is_dir() && (dir.follows_path || !is_reparse_point(&metadata)))
            && std::fs::symlink_metadata(&dir.os_path).is_ok_and(|metadata| metadata.is_dir() && !is_reparse_point(&metadata))
    }

    pub(super) fn entry_names(dir: &PinnedDir) -> io::Result<Vec<OsString>> {
        std::fs::read_dir(&dir.os_path)?.map(|entry| entry.map(|entry| entry.file_name())).collect()
    }

    pub(super) fn child_info(dir: &PinnedDir, name: &OsStr) -> io::Result<EntryInfo> {
        let metadata = std::fs::symlink_metadata(dir.os_path.join(name))?;
        let kind = if is_reparse_point(&metadata) || metadata.file_type().is_symlink() {
            EntryKind::Other
        } else if metadata.is_dir() {
            EntryKind::Dir
        } else if metadata.is_file() {
            EntryKind::File
        } else {
            EntryKind::Other
        };
        Ok(EntryInfo { kind, modified: metadata.modified().ok() })
    }

    pub(super) fn rename_child(dir: &PinnedDir, from: &OsStr, to: &OsStr) -> io::Result<()> {
        std::fs::rename(dir.os_path.join(from), dir.os_path.join(to))
    }

    pub(super) fn rename_child_noreplace_strict(dir: &PinnedDir, from: &OsStr, to: &OsStr) -> io::Result<()> {
        rename_child_noreplace(dir, from, to)
    }

    /// `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING`: fails when anything is at `to`.
    pub(super) fn rename_child_noreplace(dir: &PinnedDir, from: &OsStr, to: &OsStr) -> io::Result<()> {
        use std::os::windows::ffi::OsStrExt as _;
        let wide = |name: &OsStr| -> Vec<u16> { dir.os_path.join(name).as_os_str().encode_wide().chain(Some(0)).collect() };
        let (from_w, to_w) = (wide(from), wide(to));
        // SAFETY: two NUL-terminated UTF-16 paths that live across the call; flags 0 never replace.
        if unsafe { MoveFileExW(from_w.as_ptr(), to_w.as_ptr(), 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// A pin does not stop an EMPTY folder from being turned into a junction in place (an open for
    /// `FILE_WRITE_ATTRIBUTES` alone is not share-checked; P154, Astra r1). So nothing is deleted by path: the entry is
    /// opened itself (`FILE_FLAG_OPEN_REPARSE_POINT`), must really sit directly in the pinned folder (final paths of both
    /// handles), and is deleted through that handle.
    pub(super) fn remove_child_file(dir: &PinnedDir, name: &OsStr) -> io::Result<()> {
        delete_entry(dir, name, false)
    }

    pub(super) fn remove_child_empty_dir(dir: &PinnedDir, name: &OsStr) -> io::Result<()> {
        delete_entry(dir, name, true)
    }

    /// Opens `name` itself with `DELETE` access, checks it sits directly in `dir`, and deletes it through that handle:
    /// a file, a link or junction (the link itself), or, with `empty_dir`, an empty real folder.
    fn delete_entry(dir: &PinnedDir, name: &OsStr, empty_dir: bool) -> io::Result<()> {
        use std::os::windows::fs::OpenOptionsExt as _;
        let entry = std::fs::OpenOptions::new()
            .access_mode(DELETE_ACCESS)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(dir.os_path.join(name))?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() && !is_reparse_point(&metadata) && !empty_dir {
            return Err(io::Error::other("a folder, not a file"));
        }
        ensure_direct_child(dir, &entry, name)?;
        mark_for_deletion(&entry)?;
        // Deleted when the last handle to it closes
        drop(entry);
        Ok(())
    }

    /// As `std::fs::remove_dir_all` does: POSIX semantics (the name goes at once, even while another process still
    /// holds the entry open) ignoring the read-only attribute; on a volume or Windows version without them
    /// (`ERROR_INVALID_PARAMETER`, `ERROR_NOT_SUPPORTED`, `ERROR_INVALID_FUNCTION`), the classic disposition.
    fn mark_for_deletion(entry: &std::fs::File) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle as _;
        let flags: u32 = FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
        // SAFETY: a live handle opened with DELETE access; FILE_DISPOSITION_INFO_EX is one ULONG (u32).
        let done = unsafe {
            SetFileInformationByHandle(entry.as_raw_handle(), FILE_DISPOSITION_INFO_EX, std::ptr::from_ref(&flags).cast(), 4)
        };
        if done != 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(ERROR_INVALID_PARAMETER | ERROR_NOT_SUPPORTED | ERROR_INVALID_FUNCTION)) {
            return Err(error);
        }
        let delete: u8 = 1;
        // SAFETY: as above; FILE_DISPOSITION_INFO is one BOOLEAN (u8).
        let done = unsafe {
            SetFileInformationByHandle(entry.as_raw_handle(), FILE_DISPOSITION_INFO, std::ptr::from_ref(&delete).cast(), 1)
        };
        if done == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    /// `entry` (an open handle) is `name` directly inside the pinned `dir`, by the final paths of both handles.
    fn ensure_direct_child(dir: &PinnedDir, entry: &std::fs::File, name: &OsStr) -> io::Result<()> {
        use crate::session::storage::{final_path_windows, is_direct_child_windows};
        let parent = final_path_windows(&dir.handle)?;
        let here = final_path_windows(entry)?;
        if is_direct_child_windows(&parent, &here, name) {
            Ok(())
        } else {
            Err(io::Error::other("not directly in the pinned folder (a folder on its path was replaced)"))
        }
    }

    pub(super) fn remove_child_tree(dir: &PinnedDir, name: &OsStr) -> io::Result<()> {
        remove_tree_at(dir, name, 0)
    }

    /// Every entry is removed through a handle checked to sit directly in its pinned parent, and every folder is pinned
    /// (and checked the same way, [`open_child`]) while its entries are removed (Astra r2: no path-based
    /// `remove_dir_all` after the check).
    fn remove_tree_at(dir: &PinnedDir, name: &OsStr, depth: usize) -> io::Result<()> {
        if child_info(dir, name)?.kind != EntryKind::Dir {
            // A file, a link or a junction is removed itself, never its target
            return delete_entry(dir, name, false);
        }
        if depth >= REMOVE_TREE_MAX_DEPTH {
            return Err(io::Error::other(format!("folders nested deeper than {REMOVE_TREE_MAX_DEPTH}")));
        }
        let child = open_child(dir, name)?;
        for entry in entry_names(&child)? {
            remove_tree_at(&child, &entry, depth + 1)?;
        }
        // Released first: the pin (no FILE_SHARE_DELETE) would refuse the folder's own deletion
        drop(child);
        delete_entry(dir, name, true)
    }

    /// The lock file is opened (or created) as the entry itself, checked to sit directly in the pinned folder BEFORE
    /// its ACL is tightened, and a file this created elsewhere (the pinned folder was turned into a junction while it
    /// was empty) is deleted again through its own handle (Astra r3).
    pub(super) fn open_lock(dir: &PinnedDir, name: &str) -> Option<std::fs::File> {
        let name = OsStr::new(name);
        let path = dir.os_path.join(name);
        let (file, created) = match open_lock_handle(&path, false) {
            Ok(file) => (file, false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => match open_lock_handle(&path, true) {
                Ok(file) => (file, true),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (open_lock_handle(&path, false).ok()?, false),
                Err(_) => return None,
            },
            Err(_) => return None,
        };
        let regular = file.metadata().is_ok_and(|metadata| metadata.is_file() && !is_reparse_point(&metadata));
        if !regular || ensure_direct_child(dir, &file, name).is_err() {
            if created {
                let _ = mark_for_deletion(&file);
            }
            return None;
        }
        crate::session::storage::owner_only::tighten(&file, &path).ok()?;
        Some(file)
    }

    fn open_lock_handle(path: &Path, create_new: bool) -> io::Result<std::fs::File> {
        use std::os::windows::fs::OpenOptionsExt as _;
        // GENERIC_READ | GENERIC_WRITE | DELETE: DELETE so a file created in the wrong place can be removed again
        const LOCK_ACCESS: u32 = 0x8000_0000 | 0x4000_0000 | 0x0001_0000;
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(create_new)
            .access_mode(LOCK_ACCESS)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }
}

#[cfg(test)]
#[path = "persistence_sweep_pin_tests.rs"]
mod tests;
