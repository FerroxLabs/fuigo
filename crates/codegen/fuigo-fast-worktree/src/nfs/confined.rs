//! The confinement primitives for anything that deletes on the grove daemon's
//! behalf while the daemon is down: the worktree-id validator shared by pin GC,
//! marker parsing and `rm`, and the one fd-relative deleter of a worktree's
//! backing dir — [`open_backing_dir_confined`] followed by
//! [`ConfinedBackingDir::delete`] — used by daemon-down `rm`
//! ([`super::remove`]). Ref deletes are confined separately, in
//! `liveness::delete_pin_ref_gated`.
//!
//! The deleter never resolves a path below the data dir by name. It normalises
//! the data dir's spelling, opens it once, then walks `worktree-backing` and
//! `<id>` with `openat` + `O_NOFOLLOW` relative to the previous fd, and deletes
//! the contents with `unlinkat` relative to the fds it opened. A symlink on any
//! of those components — or anywhere inside the tree — is refused or unlinked,
//! never followed, so what is deleted is exactly what sits at
//! `<data_dir>/worktree-backing/<id>` on the filesystem the data dir lives on.
//! Opening and deleting are two steps so that `rm` can take every refusal
//! BEFORE it touches the pin ref, and then delete through the fds it validated.
//!
//! Which data dir is confined to is the caller's decision: `rm` uses the one
//! whose `worktree-backing/<id>` carries a backing marker naming the dest being
//! removed — a DB-recorded path only once that marker has been read, else the
//! candidate data dir a marker was found under — never a bare recorded path.
use anyhow::{Context, Result, bail};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

/// A worktree id is only ever a single `[A-Za-z0-9._-]+` path/ref segment that does
/// not start with `.`.
///
/// This is exactly the shape `worktree::plan::sanitize_worktree_id_base` produces, and
/// it is the shape `refs/fuigo/worktrees/<id>` and `worktree-backing/<id>` both need:
/// anything outside it (a space, a newline, a control byte, a separator) could split a
/// git ref argument or escape the backing dir. Rejecting by charset rather than by a
/// deny-list of separators keeps this from being a weaker sibling of the daemon's own
/// validator.
pub fn is_safe_worktree_id(id: &str) -> bool {
    !id.is_empty()
        && !id.starts_with('.')
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

/// The fds for exactly `<data_dir>/worktree-backing/<worktree_id>`, opened by
/// [`open_backing_dir_confined`] and consumed by [`ConfinedBackingDir::delete`].
/// While it is held, the directory it names cannot be swapped for another by
/// renaming a component above it: every later operation is relative to these fds.
#[derive(Debug)]
pub(super) struct ConfinedBackingDir {
    root_fd: OwnedFd,
    id_fd: OwnedFd,
    worktree_id: String,
    shown: PathBuf,
}

/// Open exactly `<data_dir>/worktree-backing/<worktree_id>` for deletion, or
/// refuse. `Ok(None)` means `<worktree_id>` is absent, which is the one
/// legitimate "retry after a partial failure" shape: the previous `rm` got as
/// far as removing the backing dir and nothing is left to confine. An absent
/// data dir or an absent `worktree-backing` is a refusal — a location that does
/// not exist cannot be the one this worktree's content lives in, and treating
/// it as done is how a stale recorded path once left real content untracked.
///
/// Confinement, component by component:
///
/// * **Spelling.** `data_dir` is rebuilt from `Path::components()` first, which
///   drops a trailing `/`, `/.` or `//` and any interior `.` or `//`. POSIX
///   resolves a path whose LAST character is `/` (or whose last component is
///   `.`) as "the directory this names", which follows a symlink even under
///   `O_NOFOLLOW` — `open("<link>/", O_DIRECTORY|O_NOFOLLOW)` opens the target
///   on Linux 6.8 and macOS 25 alike — so the gate has to see the real final
///   name, not the operator's spelling of it. A `..` component is refused
///   outright: the kernel resolves `..` physically, through whatever symlink
///   precedes it, so `<link>/x/..` would name the link's target and be followed
///   while `<link>` is refused; refusing the spelling keeps the gate
///   spelling-independent. An empty path is refused.
/// * **Ancestors of `data_dir`** are followed. The data dir is the trusted root —
///   it comes from the operator's own `GROVE_DATA_DIR` / XDG / home, or from the
///   backing path the daemon recorded — and its ancestors are the operator's
///   filesystem layout (`/var` is a symlink on every macOS host). What is deleted
///   is then `<canonical data dir>/worktree-backing/<id>`, which is inside the
///   invariant however the ancestors are arranged.
/// * **`data_dir` itself** is opened with `O_NOFOLLOW`: a symlink there is refused.
///   Confinement has to start at a real directory, or the two components below
///   would be "confined" relative to wherever the link points.
/// * **`worktree-backing`** and **`<id>`** are opened with `openat(prev_fd, name,
///   O_DIRECTORY | O_NOFOLLOW)`, so a symlink at either is refused and a
///   non-directory is refused — by fd, not by re-resolving a path whose prefix
///   could have been swapped underneath. Neither name can carry a spelling: the
///   first is a constant and the second passed [`is_safe_worktree_id`].
/// * **Inside the backing dir** every entry is `lstat`ed and removed with
///   `unlinkat` relative to its parent's fd; a symlink is unlinked, never
///   followed, and subdirectories are opened `O_NOFOLLOW` before recursion.
///
/// Closed under: every spelling of `data_dir` that normalises to the same
/// sequence of names (trailing `/`, `/.`, `//`, interior `.` and `//`), a
/// symlink at `data_dir`, at `worktree-backing`, at `<id>`, chained through any
/// of them, relative or absolute, and anywhere inside the backing tree.
/// Not closed under: a symlink on an ancestor of `data_dir` (deliberate, above),
/// and a `data_dir` that is itself a bind mount or another filesystem's root —
/// mounts are not symlinks and are followed like any real directory.
pub(super) fn open_backing_dir_confined(
    data_dir: &Path,
    worktree_id: &str,
) -> Result<Option<ConfinedBackingDir>> {
    if !is_safe_worktree_id(worktree_id) {
        bail!("refusing backing delete for unsafe worktree id {worktree_id:?}");
    }
    let data_dir = normalize_data_dir(data_dir)?;
    let backing_root_name = super::liveness::WORKTREE_BACKING_DIR;
    let shown = data_dir.join(backing_root_name).join(worktree_id);

    let data_fd = match open_dir_nofollow(None, data_dir.as_os_str()) {
        Ok(fd) => fd,
        Err(OpenDirError::Absent) => bail!(
            "grove data dir {} does not exist; refusing to treat an absent \
             backing location as deleted",
            data_dir.display()
        ),
        Err(OpenDirError::Symlink) => bail!(
            "grove data dir {} is a symlink; refusing to confine a delete to it",
            data_dir.display()
        ),
        Err(OpenDirError::NotDir) => bail!(
            "grove data dir {} is not a directory; refusing delete",
            data_dir.display()
        ),
        Err(OpenDirError::Io(e)) => {
            return Err(e).context(format!("open grove data dir {}", data_dir.display()));
        }
    };
    let root_fd = match open_dir_nofollow(Some(&data_fd), OsStr::new(backing_root_name)) {
        Ok(fd) => fd,
        Err(OpenDirError::Absent) => bail!(
            "{} does not exist; refusing to treat an absent backing root as deleted",
            data_dir.join(backing_root_name).display()
        ),
        Err(OpenDirError::Symlink) => bail!(
            "{} is a symlink; refusing to follow it out of {}",
            data_dir.join(backing_root_name).display(),
            data_dir.display()
        ),
        Err(OpenDirError::NotDir) => bail!(
            "{} is not a directory; refusing delete",
            data_dir.join(backing_root_name).display()
        ),
        Err(OpenDirError::Io(e)) => {
            return Err(e).context(format!(
                "open {}",
                data_dir.join(backing_root_name).display()
            ));
        }
    };
    let id_fd = match open_dir_nofollow(Some(&root_fd), OsStr::new(worktree_id)) {
        Ok(fd) => fd,
        Err(OpenDirError::Absent) => return Ok(None),
        Err(OpenDirError::Symlink) => bail!(
            "backing {} is a symlink; refusing to follow it out of {}",
            shown.display(),
            backing_root_name
        ),
        Err(OpenDirError::NotDir) => bail!(
            "backing {} is not a directory; refusing delete",
            shown.display()
        ),
        Err(OpenDirError::Io(e)) => {
            return Err(e).context(format!("open backing {}", shown.display()));
        }
    };
    Ok(Some(ConfinedBackingDir {
        root_fd,
        id_fd,
        worktree_id: worktree_id.to_owned(),
        shown,
    }))
}

impl ConfinedBackingDir {
    /// The path this handle was opened as, for messages.
    pub(super) fn shown(&self) -> &Path {
        &self.shown
    }

    /// Empty and remove the backing dir through the fds opened by
    /// [`open_backing_dir_confined`]; nothing is resolved by path.
    pub(super) fn delete(self) -> Result<()> {
        let Self {
            root_fd,
            id_fd,
            worktree_id,
            shown,
        } = self;
        remove_dir_contents_at(&id_fd)
            .with_context(|| format!("emptying backing {}", shown.display()))?;
        drop(id_fd);
        unlinkat(&root_fd, OsStr::new(&worktree_id), true)
            .with_context(|| format!("removing backing {}", shown.display()))
    }
}

/// `data_dir` rebuilt from its components: one spelling per path, with the last
/// component a real name so `O_NOFOLLOW` applies to it. Refuses `..` and the
/// empty path (see [`open_backing_dir_confined`]).
fn normalize_data_dir(data_dir: &Path) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    for c in data_dir.components() {
        match c {
            Component::ParentDir => bail!(
                "grove data dir {} is spelled with `..`; refusing to confine a delete \
                 to a path the kernel would resolve through a symlink",
                data_dir.display()
            ),
            // `components()` keeps `.` only as a leading component, where it
            // means "relative to the cwd" and is never a symlink.
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        bail!("grove data dir is empty; refusing delete");
    }
    Ok(out)
}

enum OpenDirError {
    Absent,
    Symlink,
    NotDir,
    Io(io::Error),
}

/// `openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)`.
/// With `dirfd == None` the name is resolved from the cwd like `open(2)`, which
/// is how the trusted root is entered; every later call is fd-relative.
fn open_dir_nofollow(dirfd: Option<&OwnedFd>, name: &OsStr) -> Result<OwnedFd, OpenDirError> {
    let c = CString::new(name.as_bytes()).map_err(|_| {
        OpenDirError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains an interior NUL",
        ))
    })?;
    let at = dirfd.map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd);
    // SAFETY: `c` is a valid NUL-terminated string; `at` is either AT_FDCWD or
    // an fd we own for the duration of the call.
    let fd = unsafe {
        libc::openat(
            at,
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd >= 0 {
        // SAFETY: a fresh fd that nothing else owns.
        return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    let e = io::Error::last_os_error();
    Err(match e.raw_os_error() {
        Some(libc::ENOENT) => OpenDirError::Absent,
        // With O_DIRECTORY set, a symlink under O_NOFOLLOW comes back as "not a
        // directory" (ENOTDIR) on both Linux 6.8 and macOS 25 (measured with
        // `open(<link>, O_RDONLY|O_DIRECTORY|O_NOFOLLOW)` on each); ELOOP is
        // what open(2) documents for the flag without O_DIRECTORY, and FreeBSD
        // says EMLINK. All three are refusals; the lstat below only decides
        // which refusal to name.
        Some(libc::ELOOP) | Some(libc::ENOTDIR) | Some(libc::EMLINK) => match lstat_at(at, &c) {
            Ok(st) if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK => OpenDirError::Symlink,
            Ok(_) => OpenDirError::NotDir,
            Err(le) if le.kind() == io::ErrorKind::NotFound => OpenDirError::Absent,
            Err(_) => OpenDirError::Io(e),
        },
        _ => OpenDirError::Io(e),
    })
}

fn lstat_at(at: libc::c_int, c: &CStr) -> io::Result<libc::stat> {
    // SAFETY: `st` is fully written by a successful fstatat; `c` is NUL-terminated.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatat(at, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

/// Remove everything inside the directory `dir` refers to, fd-relative. Entries
/// are classified with `fstatat(AT_SYMLINK_NOFOLLOW)`, so a symlink — to a
/// directory or anywhere else — is `unlinkat`ed as a link and never entered.
fn remove_dir_contents_at(dir: &OwnedFd) -> io::Result<()> {
    for name in list_dir_at(dir)? {
        let st = fstatat_nofollow(dir, &name)?;
        if (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            let child = match open_dir_nofollow(Some(dir), &name) {
                Ok(fd) => fd,
                // Swapped for a link or removed between lstat and open: not ours
                // to follow. A vanished entry is fine; anything else is an error.
                Err(OpenDirError::Absent) => continue,
                Err(OpenDirError::Symlink) => {
                    return Err(io::Error::other(format!(
                        "{} became a symlink during delete; refusing to follow it",
                        Path::new(&name).display()
                    )));
                }
                Err(OpenDirError::NotDir) => {
                    return Err(io::Error::other(format!(
                        "{} changed type during delete; refusing",
                        Path::new(&name).display()
                    )));
                }
                Err(OpenDirError::Io(e)) => return Err(e),
            };
            remove_dir_contents_at(&child)?;
            drop(child);
            unlinkat(dir, &name, true)?;
        } else {
            unlinkat(dir, &name, false)?;
        }
    }
    Ok(())
}

/// Names of the entries in `dir` (excluding `.` and `..`), read through a
/// duplicated fd so `dir` itself stays usable for the fd-relative calls.
fn list_dir_at(dir: &OwnedFd) -> io::Result<Vec<OsString>> {
    let dup = dir.try_clone()?;
    // SAFETY: `fdopendir` takes ownership of the fd; `closedir` below releases it.
    let stream = unsafe { libc::fdopendir(dup.into_raw_fd()) };
    if stream.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut names = Vec::new();
    let result = loop {
        set_errno(0);
        // SAFETY: `stream` is a valid DIR* until `closedir`.
        let ent = unsafe { libc::readdir(stream) };
        if ent.is_null() {
            if !ERRNO_RESETTABLE {
                // Cannot tell end-of-stream from an error here; treat as end.
                break Ok(());
            }
            let e = io::Error::last_os_error();
            break match e.raw_os_error() {
                Some(0) | None => Ok(()),
                Some(_) => Err(e),
            };
        }
        // SAFETY: `ent` points at a valid dirent whose d_name is NUL-terminated.
        let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        names.push(OsString::from_vec(bytes.to_vec()));
    };
    // SAFETY: closes the DIR* and the fd `fdopendir` took over.
    unsafe { libc::closedir(stream) };
    result.map(|()| names)
}

fn fstatat_nofollow(dir: &OwnedFd, name: &OsStr) -> io::Result<libc::stat> {
    let c = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interior NUL"))?;
    lstat_at(dir.as_raw_fd(), &c)
}

fn unlinkat(dir: &OwnedFd, name: &OsStr, is_dir: bool) -> io::Result<()> {
    let c = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interior NUL"))?;
    let flags = if is_dir { libc::AT_REMOVEDIR } else { 0 };
    // SAFETY: `c` is NUL-terminated and `dir` is an fd we own.
    let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), flags) };
    if rc != 0 {
        let e = io::Error::last_os_error();
        // Already gone is what we wanted.
        if e.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(e);
    }
    Ok(())
}

/// Whether [`set_errno`] can clear errno on this target, which is what lets
/// `readdir` returning NULL be told apart from an error.
const ERRNO_RESETTABLE: bool = cfg!(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "linux",
    target_os = "android"
));

fn set_errno(v: i32) {
    // SAFETY: writes the calling thread's errno slot.
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    unsafe {
        *libc::__error() = v;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe {
        *libc::__errno_location() = v;
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "linux",
        target_os = "android"
    )))]
    let _ = v;
}

#[cfg(test)]
mod tests {
    use super::super::liveness::WORKTREE_BACKING_DIR;
    use super::*;
    use tempfile::TempDir;

    fn plant(tmp: &Path, id: &str) -> (PathBuf, PathBuf) {
        let data = tmp.join("grove");
        let backing = data.join(WORKTREE_BACKING_DIR).join(id);
        std::fs::create_dir_all(backing.join("nested")).unwrap();
        std::fs::write(backing.join("nested/blob"), b"x").unwrap();
        (data, backing)
    }

    #[test]
    fn normalize_gives_one_spelling_per_path() {
        for spelled in ["/a/b/", "/a/b/.", "/a/b//", "/a//b", "/a/./b", "/a/b/./"] {
            assert_eq!(
                normalize_data_dir(Path::new(spelled)).unwrap(),
                Path::new("/a/b"),
                "{spelled}"
            );
        }
        assert_eq!(
            normalize_data_dir(Path::new("rel/")).unwrap(),
            Path::new("rel")
        );
        assert_eq!(
            normalize_data_dir(Path::new("./rel/")).unwrap(),
            Path::new("./rel")
        );
        assert_eq!(normalize_data_dir(Path::new(".")).unwrap(), Path::new("."));
        for refused in ["/a/../b", "/a/b/..", "..", "a/.."] {
            let err = normalize_data_dir(Path::new(refused)).unwrap_err();
            assert!(format!("{err:#}").contains(".."), "{refused}: {err:#}");
        }
        let err = normalize_data_dir(Path::new("")).unwrap_err();
        assert!(format!("{err:#}").contains("empty"), "{err:#}");
    }

    /// An absent `<id>` is the retry-after-partial-failure shape and is `None`;
    /// an absent data dir or backing root is a refusal, never success.
    #[test]
    fn absent_id_is_none_but_absent_data_dir_or_backing_root_is_refused() {
        let tmp = TempDir::new().unwrap();
        let data = tmp.path().join("grove");
        let err = open_backing_dir_confined(&data, "wt-x").unwrap_err();
        assert!(
            format!("{err:#}").contains("does not exist"),
            "absent data dir: {err:#}"
        );
        std::fs::create_dir(&data).unwrap();
        let err = open_backing_dir_confined(&data, "wt-x").unwrap_err();
        assert!(
            format!("{err:#}").contains("does not exist"),
            "absent backing root: {err:#}"
        );
        std::fs::create_dir(data.join(WORKTREE_BACKING_DIR)).unwrap();
        assert!(
            open_backing_dir_confined(&data, "wt-x").unwrap().is_none(),
            "absent <id> only is the legitimate retry shape"
        );
    }

    #[test]
    fn open_then_delete_removes_exactly_the_id_however_the_data_dir_is_spelled() {
        let tmp = TempDir::new().unwrap();
        let (data, backing) = plant(tmp.path(), "wt-a");
        let (_, sibling) = plant(tmp.path(), "wt-b");
        let mut spelled = data.as_os_str().to_os_string();
        spelled.push("/./");
        let handle = open_backing_dir_confined(Path::new(&spelled), "wt-a")
            .unwrap()
            .expect("present");
        assert_eq!(handle.shown(), data.join(WORKTREE_BACKING_DIR).join("wt-a"));
        handle.delete().unwrap();
        assert!(!backing.exists());
        assert!(sibling.join("nested/blob").is_file(), "the sibling stays");
        assert!(data.join(WORKTREE_BACKING_DIR).is_dir(), "the root stays");
    }

    #[test]
    fn a_symlinked_data_dir_is_refused_under_every_spelling() {
        let tmp = TempDir::new().unwrap();
        let (real, backing) = plant(tmp.path(), "wt-a");
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        for suffix in ["", "/", "/.", "//", "/./"] {
            let mut spelled = link.as_os_str().to_os_string();
            spelled.push(suffix);
            let err = open_backing_dir_confined(Path::new(&spelled), "wt-a").unwrap_err();
            assert!(
                format!("{err:#}").contains("symlink"),
                "spelled {spelled:?}: {err:#}"
            );
        }
        let mut via_dotdot = link.as_os_str().to_os_string();
        via_dotdot.push(format!("/{WORKTREE_BACKING_DIR}/.."));
        let err = open_backing_dir_confined(Path::new(&via_dotdot), "wt-a").unwrap_err();
        assert!(format!("{err:#}").contains(".."), "{err:#}");
        assert!(
            backing.join("nested/blob").is_file(),
            "nothing behind the link touched"
        );
    }
}
