//! Reading repository- and plugin-scoped files without leaving their folder.
//!
//! A repository or plugin decides what files sit in its folder, including symbolic links. A file Fuigo reads into the
//! prompt or loads as configuration from such a folder (a skill, command, agent, instruction or rules file, a plugin
//! manifest, its hooks or MCP file) must be a file of that folder, not wherever a link points. Checking the path once
//! when it is discovered is not enough: the link can be swapped between that check and the read.
//!
//! [`open_contained`] closes that gap. The root is a [`PinnedRoot`]: resolved ONCE, when the scope is admitted
//! (session start, plugin discovery), and never resolved again. Every read resolves the path, refuses a target
//! outside the pinned root, opens the resolved path without following a final-component link, then asks the
//! operating system where the OPENED handle really is (Linux `/proc/self/fd/N`, macOS `F_GETPATH`, Windows
//! `GetFinalPathNameByHandleW`) and requires that inside the pinned root as well. The bytes are read from that same
//! handle, so what was checked is what is read. Because the root is not re-resolved, replacing the whole root folder
//! (or one of its ancestors) with a link after admission moves every resolved path outside the pinned root, and the
//! read is refused. Where the handle's path cannot be asked (a Unix other than Linux and macOS), the read fails
//! closed: re-resolving the pathname and comparing inodes after the open is itself racy.
//!
//! User-scope files (`~/.fuigo`, `~/.claude`, `[skills].paths`, ...) do not use this: links there are the user's own.
//!
//! Hard links are not refused by design. A clone or an archive cannot create a hard link to a file outside its own
//! tree, and a same-folder hard link (`ln AGENTS.md CLAUDE.md`) is a common, legitimate setup that a link-count check
//! would break; creating a hard link to an outside file needs local write access to the folder already. On macOS a
//! hard-linked file may still be refused: `F_GETPATH` reports the name the file was last looked up by, which can be
//! its outside name. That refusal fails closed.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// The error kind used when a path resolves outside its root.
pub const OUTSIDE_ROOT: io::ErrorKind = io::ErrorKind::PermissionDenied;

/// A scope root (repository, project folder, plugin folder) resolved once, at admission. Containment checks compare
/// against this resolved path and never resolve the root again, so a root swapped for a link later cannot move the
/// boundary with it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PinnedRoot(PathBuf);

impl PinnedRoot {
    /// Resolve `root` (all links followed) and pin the result. Fails when the root does not exist.
    pub fn pin(root: &Path) -> io::Result<Self> {
        dunce::canonicalize(root).map(Self)
    }

    /// [`Self::pin`] for an optional root (`None` = user scope, nothing to pin).
    pub fn pin_opt(root: Option<&Path>) -> io::Result<Option<Self>> {
        root.map(Self::pin).transpose()
    }

    /// Pin a path the caller already resolved with `dunce::canonicalize` when the scope was admitted (for example a
    /// plugin's `canonical_root`). A path that is not in fact resolved only makes reads fail closed.
    pub fn from_canonical(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    /// The pinned, resolved root path.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for PinnedRoot {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

fn outside(path: &Path, target: &Path, root: &Path) -> io::Error {
    io::Error::new(
        OUTSIDE_ROOT,
        format!(
            "{} resolves to {}, outside {}",
            path.display(),
            target.display(),
            root.display()
        ),
    )
}

/// Whether `path` resolves (all links followed) inside the pinned `root`. Fails closed: a path that cannot be
/// resolved is not contained.
pub fn is_contained(path: &Path, root: &PinnedRoot) -> bool {
    match dunce::canonicalize(path) {
        Ok(path) => path.starts_with(root.path()),
        Err(_) => false,
    }
}

/// Open `path` for reading only if the file actually opened lies inside the pinned `root` (see the module docs).
///
/// Errors: the path cannot be resolved, the path resolves outside the root ([`OUTSIDE_ROOT`]), the final component
/// was swapped for a link after resolving, the opened object is not a regular file, the opened handle is not inside
/// the root, or the platform cannot say where the handle is (fails closed).
pub fn open_contained(path: &Path, root: &PinnedRoot) -> io::Result<File> {
    let root = root.path();
    let resolved = dunce::canonicalize(path)?;
    if !resolved.starts_with(root) {
        return Err(outside(path, &resolved, root));
    }
    let file = open_no_follow(&resolved)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    let opened = confirm_opened(handle_path(&file), &resolved)?;
    if !opened.starts_with(root) {
        return Err(outside(path, &opened, root));
    }
    Ok(file)
}

/// The handle's real path, or a fail-closed error when the platform cannot report it.
fn confirm_opened(handle: Option<PathBuf>, resolved: &Path) -> io::Result<PathBuf> {
    handle.ok_or_else(|| {
        tracing::debug!(
            path = %resolved.display(),
            "contained read skipped: this platform cannot report where an opened file is"
        );
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!("cannot confirm where {} was opened", resolved.display()),
        )
    })
}

/// Read `path` as UTF-8 only if it lies inside the pinned `root`; see [`open_contained`].
pub fn read_contained(path: &Path, root: &PinnedRoot) -> io::Result<String> {
    let mut file = open_contained(path, root)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

/// Read `path` as bytes only if it lies inside the pinned `root`; see [`open_contained`].
pub fn read_contained_bytes(path: &Path, root: &PinnedRoot) -> io::Result<Vec<u8>> {
    let mut file = open_contained(path, root)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;
    Ok(content)
}

/// [`read_contained`] when `root` is set (repository or plugin scope); a plain read that follows links when it is
/// `None` (user scope).
pub fn read_scoped(path: &Path, root: Option<&PinnedRoot>) -> io::Result<String> {
    match root {
        Some(root) => read_contained(path, root),
        None => std::fs::read_to_string(path),
    }
}

/// [`open_contained`] when `root` is set; a plain open when it is `None`.
pub fn open_scoped(path: &Path, root: Option<&PinnedRoot>) -> io::Result<File> {
    match root {
        Some(root) => open_contained(path, root),
        None => File::open(path),
    }
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    // O_NONBLOCK: a FIFO planted at the path must not block the open; a regular file ignores it.
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(windows)]
fn open_no_follow(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_FLAG_OPEN_REPARSE_POINT: a reparse point (symlink, junction) swapped in at the final component is opened
    // as itself, which then fails the regular-file check instead of being followed.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_no_follow(path: &Path) -> io::Result<File> {
    File::open(path)
}

/// Where the opened handle really is, as the operating system reports it.
#[cfg(target_os = "linux")]
fn handle_path(file: &File) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn handle_path(file: &File) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let mut buf = vec![0u8; libc::PATH_MAX as usize + 1];
    // SAFETY: F_GETPATH writes a NUL-terminated path of at most PATH_MAX bytes into `buf`, which holds PATH_MAX + 1.
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) };
    if rc == -1 {
        return None;
    }
    let len = buf.iter().position(|&b| b == 0)?;
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..len])))
}

#[cfg(windows)]
fn handle_path(file: &File) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW};

    let handle = HANDLE(file.as_raw_handle());
    let mut buf = vec![0u16; 1024];
    loop {
        // SAFETY: `handle` is a live file handle owned by `file`; the buffer length is passed via the slice.
        let len = unsafe { GetFinalPathNameByHandleW(handle, &mut buf, FILE_NAME_NORMALIZED) } as usize;
        if len == 0 {
            return None;
        }
        if len < buf.len() {
            let path = PathBuf::from(std::ffi::OsString::from_wide(&buf[..len]));
            // `\\?\C:\...` -> `C:\...` when that is lossless, matching how `dunce::canonicalize` spells the root.
            return Some(dunce::simplified(&path).to_path_buf());
        }
        // Too small: `len` is the size needed, including the terminating NUL.
        buf.resize(len + 1, 0);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios", windows)))]
fn handle_path(_file: &File) -> Option<PathBuf> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(p: &Path) -> PinnedRoot {
        PinnedRoot::pin(p).unwrap()
    }

    #[test]
    fn reads_a_plain_file_inside_the_root() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.md"), "inside").unwrap();
        let root = pin(tmp.path());
        assert_eq!(read_contained(&tmp.path().join("a.md"), &root).unwrap(), "inside");
        assert_eq!(read_contained_bytes(&tmp.path().join("a.md"), &root).unwrap(), b"inside");
        assert!(is_contained(&tmp.path().join("a.md"), &root));
    }

    #[test]
    fn missing_paths_are_not_contained() {
        let tmp = tempfile::tempdir().unwrap();
        let root = pin(tmp.path());
        assert!(!is_contained(&tmp.path().join("nope"), &root));
        assert!(read_contained(&tmp.path().join("nope"), &root).is_err());
        assert!(PinnedRoot::pin(&tmp.path().join("missing-root")).is_err());
        assert!(PinnedRoot::pin_opt(None).unwrap().is_none());
    }

    #[test]
    fn a_directory_is_not_read() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("d")).unwrap();
        assert!(read_contained(&tmp.path().join("d"), &pin(tmp.path())).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn link_inside_the_root_is_read_link_outside_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("real.md"), "inside").unwrap();
        std::fs::write(tmp.path().join("secret.md"), "SECRET").unwrap();
        std::os::unix::fs::symlink(root.join("real.md"), root.join("in.md")).unwrap();
        std::os::unix::fs::symlink(tmp.path().join("secret.md"), root.join("out.md")).unwrap();
        std::os::unix::fs::symlink(tmp.path(), root.join("updir")).unwrap();
        let pinned = pin(&root);

        assert_eq!(read_contained(&root.join("in.md"), &pinned).unwrap(), "inside");
        let err = read_contained(&root.join("out.md"), &pinned).unwrap_err();
        assert_eq!(err.kind(), OUTSIDE_ROOT);
        assert!(read_contained(&root.join("updir").join("secret.md"), &pinned).is_err());
        assert!(!is_contained(&root.join("out.md"), &pinned));
        // User scope follows the link.
        assert_eq!(read_scoped(&root.join("out.md"), None).unwrap(), "SECRET");
    }

    /// Astra r4 High: the root is pinned at admission. Replacing the whole root folder with a link to an outside
    /// tree after that moves every path outside the pinned root, so the read is refused instead of the boundary
    /// moving with the link.
    #[cfg(unix)]
    #[test]
    fn m5_whole_root_replaced_by_link_after_pinning_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("plugin");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("SKILL.md"), "inside").unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("SKILL.md"), "SECRET").unwrap();
        let pinned = pin(&root);
        assert_eq!(read_contained(&root.join("SKILL.md"), &pinned).unwrap(), "inside");

        std::fs::rename(&root, tmp.path().join("plugin.old")).unwrap();
        std::os::unix::fs::symlink(&outside, &root).unwrap();
        let err = read_contained(&root.join("SKILL.md"), &pinned).unwrap_err();
        assert_eq!(err.kind(), OUTSIDE_ROOT);
        assert!(!is_contained(&root.join("SKILL.md"), &pinned));
    }

    /// The same for an ancestor of the root: the repository folder holding the plugin is swapped for a link.
    #[cfg(unix)]
    #[test]
    fn m5_root_ancestor_replaced_by_link_after_pinning_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(repo.join("plugins/p")).unwrap();
        std::fs::write(repo.join("plugins/p/a.md"), "inside").unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(outside.join("plugins/p")).unwrap();
        std::fs::write(outside.join("plugins/p/a.md"), "SECRET").unwrap();
        let pinned = pin(&repo.join("plugins/p"));

        std::fs::rename(&repo, tmp.path().join("repo.old")).unwrap();
        std::os::unix::fs::symlink(&outside, &repo).unwrap();
        assert!(read_contained(&repo.join("plugins/p/a.md"), &pinned).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_is_refused_without_blocking() {
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("pipe.md");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(read_contained(&fifo, &pin(tmp.path())).is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn handle_path_names_the_opened_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("a.md");
        std::fs::write(&path, "x").unwrap();
        let resolved = dunce::canonicalize(&path).unwrap();
        let file = File::open(&resolved).unwrap();
        assert_eq!(handle_path(&file).unwrap(), resolved);
    }

    /// Astra r4 High: without a handle path the read fails closed instead of re-resolving the pathname.
    #[test]
    fn m5_no_handle_path_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let err = confirm_opened(None, &tmp.path().join("a.md")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    /// Windows: a directory junction inside the root that points outside is refused (the handle's final path is
    /// outside); one that points inside is read.
    #[cfg(windows)]
    #[test]
    fn m5_windows_junction_outside_is_refused_inside_is_read() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::fs::write(root.join("real").join("a.md"), "inside").unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("a.md"), "SECRET").unwrap();
        let junction = |link: &Path, target: &Path| {
            std::process::Command::new("cmd")
                .arg("/C")
                .arg("mklink")
                .arg("/J")
                .arg(link)
                .arg(target)
                .status()
                .unwrap()
                .success()
        };
        assert!(junction(&root.join("out"), &outside));
        assert!(junction(&root.join("in"), &root.join("real")));
        let pinned = pin(&root);
        assert_eq!(read_contained(&root.join("in").join("a.md"), &pinned).unwrap(), "inside");
        assert!(read_contained(&root.join("out").join("a.md"), &pinned).is_err());
    }

    /// Windows: a path spelled with different letter case or through an 8.3 short name still resolves to the same
    /// normalized path as the pinned root, so an inside file is read and nothing outside passes the prefix check.
    #[cfg(windows)]
    #[test]
    fn m5_windows_case_and_short_name_spellings_resolve_to_the_pinned_root() {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("LongRootFolderName");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("Readme.md"), "inside").unwrap();
        let pinned = pin(&root);
        let upper = PathBuf::from(root.to_string_lossy().to_uppercase()).join("README.MD");
        assert_eq!(read_contained(&upper, &pinned).unwrap(), "inside");

        let wide: Vec<u16> = root.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut buf = vec![0u16; 1024];
        // SAFETY: `wide` is NUL-terminated; the buffer length is passed via the slice.
        let len = unsafe {
            windows::Win32::Storage::FileSystem::GetShortPathNameW(
                windows::core::PCWSTR(wide.as_ptr()),
                Some(&mut buf),
            )
        } as usize;
        if len > 0 && len < buf.len() {
            // Short names can be disabled per volume; when one exists it must resolve to the same pinned root.
            let short = PathBuf::from(std::ffi::OsString::from_wide(&buf[..len]));
            assert_eq!(read_contained(&short.join("Readme.md"), &pinned).unwrap(), "inside");
            assert_eq!(PinnedRoot::pin(&short).unwrap(), pinned);
        }
    }
}
