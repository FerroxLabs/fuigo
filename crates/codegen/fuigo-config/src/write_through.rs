//! Crash- and reader-safe, metadata-preserving replacement of a whole file
//! (moved here from `fuigo-shell`'s `config::atomic_write` in P49, so every
//! crate can share it: the shell's `config.toml`/`hooks-paths` writers and
//! `fuigo-workspace`'s worktree apply).
//!
//! The writers that use it used to call `std::fs::write`, which truncates the
//! file and then writes it. A reader that opens the file between the two (the
//! config watcher, a second Fuigo, the pager, an editor) sees an empty or
//! partial file. An empty user `config.toml` loads as `Ok(empty table)`, so
//! that reader silently drops every setting -- including the trusted-origins
//! set (R013 §1.5, Astra v1 #3).
//!
//! [`write_file_atomically`] instead writes a temp file in the target's own
//! directory, `fsync`s it, `rename`s it over the target and (on unix) `fsync`s
//! the directory. A reader opening the path sees either the whole old file or
//! the whole new one, and a write that fails at any point before the rename
//! leaves the old file untouched. [`stage_file_atomically`] stops before the
//! rename, for `crate::fs_atomic::edit_locked`.
//!
//! # What is kept from the old in-place write
//!
//! - **Symlinks are written through, not replaced.** `std::fs::write` follows a
//!   symlinked file and rewrites the file it points at, leaving the link in
//!   place (a dotfiles repo that links `~/.fuigo/config.toml` keeps working).
//!   That is kept: the link chain is resolved first and the replacement is made
//!   beside the final target, so the link survives. A dangling link is followed
//!   too, creating its target, as `std::fs::write` did.
//! - **Permissions are preserved exactly.** `rename` installs a new inode, so
//!   the old file's mode does not carry over by itself. The temp file of an
//!   EXISTING file is created `0600` (so no other user can open it while it
//!   fills), written, and only then given the original owner/group
//!   (when they cannot be restored exactly -- not root, someone else's file --
//!   the replacement is REFUSED with `PermissionDenied` and the file left as it
//!   was: publishing the temp would grant the mode to the wrong owner or group,
//!   and an in-place rewrite would not be atomic) and the original mode, all
//!   of `0o7777`. Applying the mode after the write also
//!   keeps setuid/setgid bits, which a write by a process without `CAP_FSETID`
//!   would clear. A NEW file is created per [`NewFileMode`]: `0600` for the
//!   config writers (these files sit beside credentials), or `0o666 & !umask`
//!   exactly as `std::fs::write` would, for ordinary files.
//! - **ACLs are carried over.** Linux: every extended attribute, the POSIX
//!   access ACL among them (see [`xattrs`]). Windows: the DACL, exactly, as a
//!   protected DACL (run on Windows); macOS: the extended ACL (see
//!   [`native_acl`]; compile-checked only).
//! - **An existing file this process may not write is still refused.** A rename
//!   only needs write access to the directory, so a read-only file would
//!   otherwise be silently replaced. The target is opened for writing (without
//!   truncating it) first, so the error is the one the old write gave.

use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Symlink hops followed before giving up, matching Linux's `MAXSYMLINKS`.
const MAX_SYMLINK_HOPS: usize = 40;

/// Replace `path` with `contents` so that no reader ever observes a partial file.
///
/// See the module docs for the symlink, permission and read-only semantics.
/// New files are created owner-only ([`NewFileMode::OwnerOnly`]).
/// Does NOT take any lock: callers doing a read-modify-write must hold
/// `crate::fs_atomic::lock_config_for_write` across both halves, or use
/// `crate::fs_atomic::edit_locked` with [`stage_file_atomically`].
///
/// # Errors
///
/// Any I/O error from resolving `path`, probing it for write access, creating,
/// writing or syncing the temp file, or the rename. On every error path the
/// temp file is removed and the original file is left exactly as it was.
pub fn write_file_atomically(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    stage_file_atomically(path, contents)?.commit()
}

/// How a file that does not exist yet is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewFileMode {
    /// `0600` on unix: for files that sit beside credentials (`config.toml`).
    OwnerOnly,
    /// `0o666 & !umask` on unix, exactly what `std::fs::write` creates.
    Default,
}

/// [`write_file_atomically`], with the mode a NEW file gets chosen by
/// `new_file` (an existing file always keeps its own metadata).
///
/// # Errors
///
/// As [`write_file_atomically`].
pub fn replace_file_contents(
    path: &Path,
    contents: &[u8],
    new_file: NewFileMode,
) -> std::io::Result<()> {
    stage_with(path, contents, new_file)?.commit()
}

/// Everything [`write_file_atomically`] does before the rename: resolve the
/// write-through target, probe it, create the temp, write and `fsync` it. On
/// unix the original's ACL, owner and mode are applied by the returned
/// replacement's `commit` (under a writer's lock, from the file being replaced
/// then), just before the rename and the directory sync; elsewhere they are
/// applied here. Dropped uncommitted, it removes the temp (and the macOS
/// staging directory).
///
/// # Errors
///
/// As [`write_file_atomically`], short of the rename; the temp is removed.
pub fn stage_file_atomically(
    path: &Path,
    contents: &[u8],
) -> std::io::Result<crate::fs_atomic::StagedReplacement> {
    stage_with(path, contents, NewFileMode::OwnerOnly)
}

/// [`stage_file_atomically`] with the mode a NEW file gets chosen by `new_file`.
///
/// # Errors
///
/// As [`stage_file_atomically`].
pub fn stage_file_atomically_with(
    path: &Path,
    contents: &[u8],
    new_file: NewFileMode,
) -> std::io::Result<crate::fs_atomic::StagedReplacement> {
    stage_with(path, contents, new_file)
}

fn stage_with(
    path: &Path,
    contents: &[u8],
    new_file: NewFileMode,
) -> std::io::Result<crate::fs_atomic::StagedReplacement> {
    let target = resolve_write_target(path)?;
    let dir = match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = target.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} has no file name", target.display()),
        )
    })?;

    // Not a regular file (a device, a FIFO, a socket): renaming over it would
    // destroy it, so it is written in place at commit, as `std::fs::write` did.
    // Atomicity means nothing for such a target. (A directory still fails, as
    // `std::fs::write` failed on one.)
    if let Ok(md) = std::fs::metadata(&target)
        && !md.is_file()
        && !md.is_dir()
    {
        // Written by the commit (under the writer's lock, after validation),
        // never here: a write to a device or a FIFO cannot be taken back.
        // Bound to the special file seen here: an optimistic commit requires
        // the edited snapshot to be this very file, never a regular config
        // that took its name back meanwhile.
        return Ok(crate::fs_atomic::StagedReplacement::written_in_place_at_commit(
            target,
            contents.to_vec(),
        )
        .from_original(crate::fs_atomic::FileKey::of(&md)));
    }
    let existing = match std::fs::OpenOptions::new().write(true).open(&target) {
        // The write-access probe: no truncate, no create, so it changes
        // nothing. Kept open: its metadata and extended attributes (the ACL)
        // are taken from it, so they all describe the same file.
        Ok(probe) => {
            let md = probe.metadata()?;
            Some((md, probe))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let source = existing
        .as_ref()
        .and_then(|(md, _)| crate::fs_atomic::FileKey::of(md));

    // macOS: the temp is born inside a private, ACL-free staging directory
    // (see [`staging`]); elsewhere directly beside the target. Not for a new
    // ordinary file ([`NewFileMode::Default`]): it has no original ACL to copy,
    // so it must get exactly the ACL creation in the target directory gives
    // (inherited entries included), as `std::fs::write` did.
    let staging = if existing.is_none() && new_file == NewFileMode::Default {
        None
    } else {
        staging::Staging::create(&dir, name)?
    };
    let temp_dir = staging
        .as_ref()
        .map_or(dir.as_path(), staging::Staging::path);
    // The temp of an existing file is owner-only while it fills; its real
    // mode is applied after the write.
    let create_mode = match (&existing, new_file) {
        (Some(_), _) | (None, NewFileMode::OwnerOnly) => 0o600,
        (None, NewFileMode::Default) => 0o666,
    };
    // Unix: a temp inside a staging directory is created through that
    // directory's handle (opened through its parent), never re-resolved by path.
    #[cfg(unix)]
    let pre_opened = staging.as_ref().and_then(staging::Staging::handle);
    #[cfg(not(unix))]
    let pre_opened = ();
    #[cfg_attr(not(unix), allow(unused_variables))]
    let (tmp, file, handle) = create_temp_in(temp_dir, name, create_mode, pre_opened)?;
    #[cfg(any(test, feature = "test-seams"))]
    fault::temp_created(&tmp);
    // From here on the temp is ours: `staged` removes it on every failure
    // (through the handle of the directory it was created in, so also after
    // that directory moved), then drops the staging directory (which must be
    // empty to go).
    let mut staged = crate::fs_atomic::StagedReplacement::new_unbound(tmp, target.clone(), dir);
    #[cfg(unix)]
    if let Some(handle) = handle {
        staged = staged.with_dir_handle(handle);
    }

    if let Some(staging) = staging {
        staged = staged.keep_alive(staging);
    }
    // Test seam shared with `fs_atomic` (`stage_fault::fail_writes_under` and
    // friends): fail after the temp exists, so its removal is exercised.
    #[cfg(any(test, feature = "test-seams"))]
    if crate::fs_atomic::stage_fault::armed_for(&target) {
        // The handle first: Windows cannot remove a file still open (share mode 0).
        drop(file);
        drop(staged);
        return Err(std::io::Error::other("injected write failure (test)"));
    }
    // Unix: the temp stays owner-only and carries no metadata of anyone's
    // while it waits (possibly unlocked) for its commit. The original's
    // owner, xattrs/ACL and mode are put on it in the commit, under the
    // writer's lock, taken from the file being replaced AT THAT MOMENT -- so
    // contents and metadata can never come from two different versions, and
    // nothing is exposed before the replacement is validated.
    //
    // The commit re-probes the target whatever staging saw (a file that was
    // missing then may be there now), and finishes through the descriptor the
    // temp was created with (a restrictive umask may leave it unopenable).
    #[cfg(unix)]
    {
        let _ = (source, &existing);
        let mut file = file;
        write_contents(&mut file, contents)?;
        file.sync_all()?;
        let original = target.clone();
        staged = staged.finish_with(move |_tmp| apply_original_metadata(&original, &file));
        Ok(staged)
    }
    #[cfg(not(unix))]
    {
        if fill_temp(file, existing.as_ref(), contents)? {
            return Ok(staged.from_original(source));
        }
        drop(staged);
        Err(owner_not_kept(&target))
    }
}

/// The refusal when a replacement could not keep the original's owner and
/// group (see `apply_existing_permissions`): publishing the temp would
/// re-grant the mode to another owner or group, and rewriting in place would
/// give up atomicity, so the file is left exactly as it was.
fn owner_not_kept(target: &Path) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "{}: its owner and group cannot be kept by this user, so it is not replaced",
            target.display()
        ),
    )
}

/// Commit-time half of a unix replacement (run under the writer's lock, just
/// before the rename): give the temp (`file`, its creation descriptor) the ACL,
/// owner, xattrs and mode of the file at `target` now, after re-probing that
/// file for write access (a read-only target is refused, as before). Nothing
/// to do when there is no file there: the temp keeps its creation mode.
#[cfg(unix)]
fn apply_original_metadata(target: &Path, file: &std::fs::File) -> std::io::Result<()> {
    let probe = match std::fs::OpenOptions::new().write(true).open(target) {
        Ok(probe) => probe,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let md = probe.metadata()?;
    native_acl::copy(&probe, file)?;
    if apply_existing_permissions(file, &md, &probe)? {
        Ok(())
    } else {
        Err(owner_not_kept(target))
    }
}

/// macOS has no share modes, and a new file inherits the directory's
/// inheritable ACL entries, which (unlike the mode) can grant another
/// principal access. Whoever opens the temp in the moment before its ACL is
/// replaced keeps that descriptor, and with it the contents written later.
///
/// So on macOS the temp is created inside a fresh `0700` staging directory
/// whose own extended ACL is cleared before anything is created in it: the
/// temp inherits nothing, and no other principal can look it up (a retained
/// descriptor on the staging directory does not help: every lookup through it
/// is checked against its current, cleared ACL). The finished temp is renamed
/// from there onto the target -- same filesystem, so still one atomic
/// `rename(2)` -- and the staging directory is removed.
///
/// Compile-checked for `aarch64-apple-darwin`; not run. Elsewhere a no-op:
/// Linux masks inherited ACL entries with the `0600` creation mode, and
/// Windows opens the temp with share mode 0.
mod staging {
    use std::path::{Path, PathBuf};

    /// The private directory; removed (best-effort) when dropped.
    pub(super) struct Staging {
        dir: PathBuf,
        /// The parent directory, held open so the staging directory is removed
        /// from wherever it is when dropped (`unlinkat(AT_REMOVEDIR)`), even
        /// if the parent was moved meanwhile.
        #[cfg(unix)]
        parent: Option<crate::fs_atomic::DirHandle>,
        /// The staging directory itself, opened through `parent`; the temp is
        /// created through it (see `create_temp_in`).
        #[cfg(unix)]
        own: Option<crate::fs_atomic::DirHandle>,
    }

    impl Staging {
        pub(super) fn path(&self) -> &Path {
            &self.dir
        }

        /// A handle on the staging directory, when it was opened through its parent.
        #[cfg(unix)]
        pub(super) fn handle(&self) -> Option<crate::fs_atomic::DirHandle> {
            self.own.as_ref().and_then(|h| h.try_clone().ok())
        }

        #[cfg(target_os = "macos")]
        pub(super) fn create(
            parent: &Path,
            name: &std::ffi::OsStr,
        ) -> std::io::Result<Option<Self>> {
            use std::os::unix::fs::DirBuilderExt as _;
            type AclT = *mut std::ffi::c_void;
            const ACL_TYPE_EXTENDED: std::ffi::c_uint = 0x0000_0100;
            unsafe extern "C" {
                fn acl_set_fd_np(
                    fd: std::ffi::c_int,
                    acl: AclT,
                    ty: std::ffi::c_uint,
                ) -> std::ffi::c_int;
                fn acl_init(count: std::ffi::c_int) -> AclT;
                fn acl_free(obj: *mut std::ffi::c_void) -> std::ffi::c_int;
            }
            let mut last_err = None;
            let parent_handle = crate::fs_atomic::DirHandle::open_or_none(parent);
            let mut parent_handle = Some(parent_handle);
            for _ in 0..16 {
                let nonce = super::NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let dir_name = format!(
                    ".{}.{}.{nonce}.staging",
                    super::short_name(name),
                    std::process::id()
                );
                let dir = parent.join(&dir_name);
                // Created through the same parent handle its removal uses, so
                // both name the same directory even if the parent's path is
                // re-pointed in between.
                let created = match parent_handle.as_ref().and_then(Option::as_ref) {
                    Some(h) => h.create_dir(std::ffi::OsStr::new(&dir_name), 0o700),
                    None => std::fs::DirBuilder::new().mode(0o700).create(&dir),
                };
                match created {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        last_err = Some(e);
                        continue;
                    }
                    Err(e) => return Err(e),
                }
                let mut staging = Self {
                    dir,
                    parent: parent_handle.take().flatten(),
                    own: None,
                };
                // The directory just made, opened through the same parent
                // handle (by path only when there is none).
                let own = match &staging.parent {
                    Some(p) => p.open_child_dir(std::ffi::OsStr::new(&dir_name))?,
                    None => crate::fs_atomic::DirHandle::open_read_only(&staging.dir)?,
                };
                let handle_fd = own.raw_fd();
                staging.own = Some(own);
                // SAFETY: allocates an empty ACL, freed below.
                let acl = unsafe { acl_init(0) };
                if acl.is_null() {
                    return Err(std::io::Error::last_os_error());
                }
                // SAFETY: valid descriptor and a valid ACL owned here.
                let rc = unsafe { acl_set_fd_np(handle_fd, acl, ACL_TYPE_EXTENDED) };
                let set = if rc == 0 {
                    Ok(())
                } else {
                    let e = std::io::Error::last_os_error();
                    // A filesystem without ACLs cannot have handed any down.
                    match e.raw_os_error() {
                        Some(libc::ENOTSUP | libc::EOPNOTSUPP) => Ok(()),
                        _ => Err(e),
                    }
                };
                // SAFETY: `acl` came from acl_init.
                unsafe {
                    acl_free(acl);
                }
                set?; // on error `staging` drops and removes the directory
                return Ok(Some(staging));
            }
            Err(last_err.unwrap_or_else(|| std::io::Error::other("no free staging name")))
        }

        #[cfg(not(target_os = "macos"))]
        #[allow(clippy::unnecessary_wraps)]
        pub(super) fn create(
            _parent: &Path,
            _name: &std::ffi::OsStr,
        ) -> std::io::Result<Option<Self>> {
            Ok(None)
        }
    }

    impl Drop for Staging {
        fn drop(&mut self) {
            #[cfg(unix)]
            if let (Some(parent), Some(name)) = (&self.parent, self.dir.file_name()) {
                let _ = parent.remove_dir(name);
                return;
            }
            let _ = std::fs::remove_dir(&self.dir);
        }
    }
}

/// Follow `path` through any chain of symlinks to the file a write-through
/// would modify. Relative link targets resolve against the link's directory.
fn resolve_write_target(path: &Path) -> std::io::Result<PathBuf> {
    let mut current = path.to_path_buf();
    // `MAX_SYMLINK_HOPS` links may be followed; the entry after the last one
    // must then be a non-link (or missing).
    for hop in 0..=MAX_SYMLINK_HOPS {
        match std::fs::symlink_metadata(&current) {
            Ok(md) if md.file_type().is_symlink() && hop == MAX_SYMLINK_HOPS => break,
            Ok(md) if md.file_type().is_symlink() => {
                let link = std::fs::read_link(&current)?;
                current = if link.is_absolute() {
                    link
                } else {
                    current
                        .parent()
                        .map_or_else(|| link.clone(), |parent| parent.join(&link))
                };
            }
            Ok(_) => return Ok(current),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(current),
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other(format!(
        "{}: too many levels of symbolic links",
        path.display()
    )))
}

/// `name` cut to at most 64 bytes (on a char boundary) for use inside a temp
/// or staging name, so a target whose own name is near the filesystem's
/// 255-byte limit still gets a valid temp name.
fn short_name(name: &std::ffi::OsStr) -> String {
    let lossy = name.to_string_lossy();
    let mut end = lossy.len().min(64);
    while !lossy.is_char_boundary(end) {
        end -= 1;
    }
    lossy[..end].to_owned()
}

/// Per-process counter that makes temp names unique within this process.
static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Create a fresh temp file beside the target, `mode` (before the umask) on unix.
///
/// The name is unique per process and per call, and `create_new` never opens a
/// file that already exists: a name left behind by a crashed process (a reused
/// pid) is skipped for the next one rather than reused or deleted. The leading
/// dot keeps it out of casual listings.
fn create_temp_in(
    dir: &Path,
    name: &std::ffi::OsStr,
    mode: u32,
    pre_opened: TempDirHandle,
) -> std::io::Result<(PathBuf, std::fs::File, TempDirHandle)> {
    create_temp_with_mode(dir, name, mode, pre_opened, || {
        NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    })
}

/// The handle of the directory a temp was created in (unix; nothing elsewhere).
#[cfg(unix)]
type TempDirHandle = Option<crate::fs_atomic::DirHandle>;
#[cfg(not(unix))]
type TempDirHandle = ();

/// [`create_temp_in`] at `0600` with the nonce source injected (tests drive it directly).
#[cfg(any(test, feature = "test-seams"))]
#[doc(hidden)]
pub fn create_temp_with(
    dir: &Path,
    name: &std::ffi::OsStr,
    next_nonce: impl FnMut() -> u64,
) -> std::io::Result<(PathBuf, std::fs::File)> {
    #[cfg(unix)]
    let pre_opened = None;
    #[cfg(not(unix))]
    let pre_opened = ();
    create_temp_with_mode(dir, name, 0o600, pre_opened, next_nonce).map(|(tmp, file, _)| (tmp, file))
}

fn create_temp_with_mode(
    dir: &Path,
    name: &std::ffi::OsStr,
    #[cfg_attr(not(unix), allow(unused_variables))] mode: u32,
    #[cfg_attr(not(unix), allow(unused_variables))] pre_opened: TempDirHandle,
    mut next_nonce: impl FnMut() -> u64,
) -> std::io::Result<(PathBuf, std::fs::File, TempDirHandle)> {
    const ATTEMPTS: usize = 16;
    // Unix: the temp is created (and later removed) through a handle on its
    // directory, opened before the temp exists (or handed in already open).
    #[cfg(unix)]
    let mut handle = pre_opened.or_else(|| crate::fs_atomic::DirHandle::open_or_none(dir));
    let mut last_err = None;
    for _ in 0..ATTEMPTS {
        let nonce = next_nonce();
        let tmp_name = format!(".{}.{}.{nonce}.tmp", short_name(name), std::process::id());
        let tmp = dir.join(&tmp_name);
        #[cfg(unix)]
        let opened = match &handle {
            Some(h) => h.create_new(std::ffi::OsStr::new(&tmp_name), mode),
            None => {
                use std::os::unix::fs::OpenOptionsExt as _;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(mode)
                    .open(&tmp)
            }
        };
        #[cfg(not(unix))]
        let opened = {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt as _;
                // GENERIC_WRITE | WRITE_DAC: the original's DACL is set through this
                // handle. Share mode 0: while it is open nobody else can open the
                // temp, so the DACL it inherited from the directory, before the
                // original's replaces it, grants no one a handle.
                options.access_mode(0x4000_0000 | 0x0004_0000).share_mode(0);
            }
            options.open(&tmp)
        };
        match opened {
            #[cfg(unix)]
            Ok(file) => return Ok((tmp, file, handle.take())),
            #[cfg(not(unix))]
            Ok(file) => return Ok((tmp, file, ())),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last_err = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::other("no free temp file name")))
}

/// Fill the temp: ACL, contents, the original's metadata, `fsync`. The handle
/// is closed on return, before anything could remove or rename the temp.
#[cfg(not(unix))]
fn fill_temp(
    mut file: std::fs::File,
    existing: Option<&(std::fs::Metadata, std::fs::File)>,
    contents: &[u8],
) -> std::io::Result<bool> {
    // Before any content: an ACL the temp inherited from its directory must not
    // expose it while it fills (Windows DACLs and macOS ACLs override the mode).
    if let Some((_, original)) = existing {
        native_acl::copy(original, &file)?;
    }
    write_contents(&mut file, contents)?;
    // After the write: the content never sat in a file looser than 0600, and a
    // write cannot clear setuid/setgid bits applied before it.
    if let Some((md, original)) = existing
        && !apply_existing_permissions(&file, md, original)?
    {
        return Ok(false);
    }
    file.sync_all()?;
    Ok(true)
}

#[cfg(unix)]
fn apply_existing_permissions(
    file: &std::fs::File,
    md: &std::fs::Metadata,
    original: &std::fs::File,
) -> std::io::Result<bool> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    // Owner first: on Linux a chown by root clears setuid/setgid, so the mode
    // has to be applied after it to survive. The owner AND group must come out
    // exactly as the original's: the original mode re-applied to a temp owned
    // by another user or group would hand that mode's bits to them (a `0660`
    // `alice:project` file rewritten by bob would become `bob:staff 0660`).
    // When they cannot be restored (not root, someone else's file), the
    // caller refuses the replacement.
    let wanted = (md.uid(), md.gid());
    if std::os::unix::fs::fchown(file, Some(wanted.0), Some(wanted.1)).is_err() {
        let _ = std::os::unix::fs::fchown(file, None, Some(wanted.1));
    }
    let now = file.metadata()?;
    #[cfg(any(test, feature = "test-seams"))]
    let forced = fault::CHOWN_FAILS.with(std::cell::Cell::get);
    #[cfg(not(any(test, feature = "test-seams")))]
    let forced = false;
    if forced || (now.uid(), now.gid()) != wanted {
        return Ok(false);
    }
    #[cfg(target_os = "linux")]
    xattrs::copy(original, file)?;
    #[cfg(target_os = "macos")]
    macos_xattrs::copy(original, file);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = original;
    // Mode last: with an access ACL present this sets the ACL mask from the
    // group bits, which is exactly the original's mask.
    file.set_permissions(std::fs::Permissions::from_mode(md.mode() & 0o7777))?;
    Ok(true)
}

/// macOS extended attributes (Finder info, resource forks, quarantine...)
/// carried from the replaced file, best-effort: `fcopyfile` with
/// `COPYFILE_XATTR` only (the ACL is copied exactly by `native_acl`; letting
/// `fcopyfile` copy it too would merge inherited entries). Compile-checked only.
#[cfg(target_os = "macos")]
mod macos_xattrs {
    use std::os::fd::AsRawFd as _;

    const COPYFILE_XATTR: u32 = 1 << 2;

    unsafe extern "C" {
        fn fcopyfile(
            from: std::ffi::c_int,
            to: std::ffi::c_int,
            state: *mut std::ffi::c_void,
            flags: u32,
        ) -> std::ffi::c_int;
    }

    pub(super) fn copy(from: &std::fs::File, to: &std::fs::File) {
        // SAFETY: two valid descriptors; a null state is allowed.
        let _ = unsafe {
            fcopyfile(
                from.as_raw_fd(),
                to.as_raw_fd(),
                std::ptr::null_mut(),
                COPYFILE_XATTR,
            )
        };
    }
}

/// Extended attributes, the POSIX access ACL among them, carried from the
/// replaced file to its replacement.
///
/// `rename` installs a new inode, so an ACL on the old file -- one granting a
/// named service user access while denying the owning group, say -- would
/// otherwise be dropped, and re-applying the bare mode would hand its group
/// bits (the ACL mask) to the whole owning group. The in-place write this
/// replaced kept the inode, ACL and all. Likewise an access ACL the temp file
/// INHERITED from a default ACL on the directory, which the original did not
/// have, is removed.
///
/// The access ACL is load-bearing: failing to copy or strip it is an error, and
/// the write is refused rather than broadening access. Other attributes are
/// copied best-effort (`security.*`/`trusted.*` need privileges; SELinux gives
/// the new file the directory's default context).
#[cfg(target_os = "linux")]
mod xattrs {
    use std::ffi::{CStr, CString};
    use std::os::fd::AsRawFd as _;

    const ACCESS_ACL: &CStr = c"system.posix_acl_access";

    pub(super) fn copy(from: &std::fs::File, to: &std::fs::File) -> std::io::Result<()> {
        let names = list(from)?;
        // Set only once the original's ACL is really on the replacement. A
        // listed ACL that vanished before it could be read counts as absent,
        // so an ACL the temp inherited is still stripped below.
        let mut acl_copied = false;
        for name in &names {
            let is_acl = name.as_c_str() == ACCESS_ACL;
            #[cfg(any(test, feature = "test-seams"))]
            if is_acl && super::fault::ACL_VANISHES.with(std::cell::Cell::get) {
                continue; // listed, then gone before the read (ENODATA)
            }
            let result = get(from, name).and_then(|value| match value {
                Some(value) => set(to, name, &value).map(|()| true),
                None => Ok(false),
            });
            match result {
                Ok(copied) => acl_copied |= is_acl && copied,
                Err(e) if is_acl => return Err(e),
                Err(_) => {}
            }
        }
        if !acl_copied {
            remove_if_present(to, ACCESS_ACL)?;
        }
        Ok(())
    }

    /// `None` when the filesystem has no xattr support: nothing to carry.
    fn list(f: &std::fs::File) -> std::io::Result<Vec<CString>> {
        loop {
            // SAFETY: a null buffer with size 0 asks only for the required size.
            let size = unsafe { libc::flistxattr(f.as_raw_fd(), std::ptr::null_mut(), 0) };
            if size < 0 {
                let e = std::io::Error::last_os_error();
                return match e.raw_os_error() {
                    Some(libc::ENOTSUP) => Ok(Vec::new()),
                    _ => Err(e),
                };
            }
            if size == 0 {
                return Ok(Vec::new());
            }
            let mut buf = vec![0u8; size.cast_unsigned()];
            // SAFETY: `buf` is valid for `buf.len()` bytes of writes.
            let got =
                unsafe { libc::flistxattr(f.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if got < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::ERANGE) {
                    continue; // grew between the two calls
                }
                return Err(e);
            }
            if got.cast_unsigned() > buf.len() {
                continue; // a size report, not a fill: retry with the new size
            }
            buf.truncate(got.cast_unsigned());
            return Ok(buf
                .split(|b| *b == 0)
                .filter(|n| !n.is_empty())
                .filter_map(|n| CString::new(n).ok())
                .collect());
        }
    }

    /// `None` when the attribute vanished between list and get.
    fn get(f: &std::fs::File, name: &CStr) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            // SAFETY: a null buffer with size 0 asks only for the required size.
            let size =
                unsafe { libc::fgetxattr(f.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
            if size < 0 {
                let e = std::io::Error::last_os_error();
                return match e.raw_os_error() {
                    Some(libc::ENODATA) => Ok(None),
                    _ => Err(e),
                };
            }
            if size == 0 {
                return Ok(Some(Vec::new()));
            }
            let mut buf = vec![0u8; size.cast_unsigned()];
            // SAFETY: `buf` is valid for `buf.len()` bytes of writes.
            let got = unsafe {
                libc::fgetxattr(
                    f.as_raw_fd(),
                    name.as_ptr(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                )
            };
            if got < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::ERANGE) {
                    continue;
                }
                return Err(e);
            }
            if got.cast_unsigned() > buf.len() {
                continue;
            }
            buf.truncate(got.cast_unsigned());
            return Ok(Some(buf));
        }
    }

    fn set(f: &std::fs::File, name: &CStr, value: &[u8]) -> std::io::Result<()> {
        // SAFETY: `name` is NUL-terminated and `value` is valid for `value.len()` bytes.
        let rc = unsafe {
            libc::fsetxattr(
                f.as_raw_fd(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn remove_if_present(f: &std::fs::File, name: &CStr) -> std::io::Result<()> {
        // SAFETY: `name` is NUL-terminated.
        let rc = unsafe { libc::fremovexattr(f.as_raw_fd(), name.as_ptr()) };
        if rc == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::ENODATA | libc::ENOTSUP) => Ok(()),
            _ => Err(e),
        }
    }
}

#[cfg(not(unix))]
fn apply_existing_permissions(
    file: &std::fs::File,
    md: &std::fs::Metadata,
    _original: &std::fs::File,
) -> std::io::Result<bool> {
    // The only permission Windows exposes through std is the read-only bit, and
    // the write-access probe has already refused a read-only target. The owner
    // is not changed by a replacement made by the same user.
    file.set_permissions(md.permissions())?;
    Ok(true)
}

/// The platform ACL that std cannot see, copied EXACTLY from the replaced file
/// to the temp before it is written: the DACL on Windows, the extended ACL on
/// macOS. Without it, `rename` would install the temp's ACL -- inherited from
/// the directory, possibly broader -- in place of a restrictive one the
/// in-place write used to keep. (Linux carries its ACL as an xattr; see
/// [`xattrs`].)
///
/// Windows: the original's DACL, inherited entries included, is set on the
/// temp as a PROTECTED DACL, so nothing is re-inherited from the directory and
/// the replacement grants exactly what the original granted. The cost: if the
/// original inherited from its directory, later changes to the directory no
/// longer flow to it. Never broader is the property kept. Exercised on Windows
/// by R033's native check; see there.
///
/// macOS: `acl_get_fd_np`/`acl_set_fd_np` with `ACL_TYPE_EXTENDED` (not
/// `fcopyfile`, which merges in the destination's inherited entries). An
/// original without an extended ACL gives the temp an empty one, removing any
/// entries it inherited. Compile-checked only.
mod native_acl {
    #[cfg(windows)]
    pub(super) fn copy(from: &std::fs::File, to: &std::fs::File) -> std::io::Result<()> {
        use std::os::windows::io::AsRawHandle as _;
        use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
        use windows::Win32::Security::Authorization::{
            GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo,
        };
        use windows::Win32::Security::{
            ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR,
        };

        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: valid handle; the out-pointers live for the call. `sd` owns
        // the returned descriptor (`dacl` points into it) and is freed below.
        let rc = unsafe {
            GetSecurityInfo(
                HANDLE(from.as_raw_handle()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                Some(&mut sd),
            )
        };
        if rc.0 != 0 {
            return Err(std::io::Error::from_raw_os_error(rc.0 as i32));
        }
        // SAFETY: valid handle opened with WRITE_DAC; `dacl` is valid while
        // `sd` lives. A null DACL (grants everyone) is copied as null.
        let rc = unsafe {
            SetSecurityInfo(
                HANDLE(to.as_raw_handle()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(dacl),
                None,
            )
        };
        // SAFETY: `sd` was allocated by GetSecurityInfo with LocalAlloc.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sd.0)));
        }
        if rc.0 != 0 {
            return Err(std::io::Error::from_raw_os_error(rc.0 as i32));
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub(super) fn copy(from: &std::fs::File, to: &std::fs::File) -> std::io::Result<()> {
        use std::os::fd::AsRawFd as _;
        type AclT = *mut std::ffi::c_void;
        const ACL_TYPE_EXTENDED: std::ffi::c_uint = 0x0000_0100;
        unsafe extern "C" {
            fn acl_get_fd_np(fd: std::ffi::c_int, ty: std::ffi::c_uint) -> AclT;
            fn acl_set_fd_np(
                fd: std::ffi::c_int,
                acl: AclT,
                ty: std::ffi::c_uint,
            ) -> std::ffi::c_int;
            fn acl_init(count: std::ffi::c_int) -> AclT;
            fn acl_free(obj: *mut std::ffi::c_void) -> std::ffi::c_int;
        }
        // SAFETY: valid descriptor. NULL with ENOENT means "no extended ACL".
        let mut acl = unsafe { acl_get_fd_np(from.as_raw_fd(), ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::ENOENT) => {}
                // No ACL support here: the original has none and the temp
                // (same filesystem) cannot have inherited any.
                Some(libc::ENOTSUP | libc::EOPNOTSUPP) => return Ok(()),
                _ => return Err(e),
            }
            // SAFETY: allocates an empty ACL, freed below.
            acl = unsafe { acl_init(0) };
            if acl.is_null() {
                return Err(std::io::Error::last_os_error());
            }
        }
        // SAFETY: valid descriptor and a valid ACL owned by this function.
        let rc = unsafe { acl_set_fd_np(to.as_raw_fd(), acl, ACL_TYPE_EXTENDED) };
        let result = if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        };
        // SAFETY: `acl` came from acl_get_fd_np or acl_init.
        unsafe {
            acl_free(acl);
        }
        result
    }

    #[cfg(not(any(windows, target_os = "macos")))]
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn copy(_from: &std::fs::File, _to: &std::fs::File) -> std::io::Result<()> {
        Ok(())
    }
}

/// `write_all`, with a test-only fault seam: when [`fail_after`] is set on this
/// thread, exactly that many bytes are written and then an error is returned,
/// modelling a disk-full or I/O error mid-write.
fn write_contents(file: &mut std::fs::File, contents: &[u8]) -> std::io::Result<()> {
    #[cfg(any(test, feature = "test-seams"))]
    if let Some(limit) = fault::FAIL_AFTER.with(std::cell::Cell::get) {
        let cut = limit.min(contents.len());
        file.write_all(&contents[..cut])?;
        return Err(std::io::Error::other("injected write failure (test)"));
    }
    file.write_all(contents)
}

/// Test seams (`cfg(test)` here, the `test-seams` feature for other crates'
/// tests; never in a shipped build).
#[cfg(any(test, feature = "test-seams"))]
#[doc(hidden)]
pub mod fault {
    use std::path::{Path, PathBuf};

    thread_local! {
        /// Bytes [`super::write_contents`] writes before failing; `None` = no fault.
        pub static FAIL_AFTER: std::cell::Cell<Option<usize>> =
            const { std::cell::Cell::new(None) };
        /// The original's access ACL is listed but gone by the time it is read.
        pub static ACL_VANISHES: std::cell::Cell<bool> =
            const { std::cell::Cell::new(false) };
        /// Owner/group restoration "fails" (as for a non-root process
        /// rewriting someone else's file), forcing the refusal.
        pub static CHOWN_FAILS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// Every temp created by any thread, with its mode at creation. Global so
    /// a test can see temps made on a blocking pool; filter by your own dir.
    pub static TEMPS_CREATED: std::sync::Mutex<Vec<(PathBuf, Option<u32>)>> =
        std::sync::Mutex::new(Vec::new());

    /// The temps recorded under `dir`.
    pub fn temps_under(dir: &Path) -> Vec<(PathBuf, Option<u32>)> {
        TEMPS_CREATED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(p, _)| p.starts_with(dir))
            .cloned()
            .collect()
    }

    /// Run `f` with the fault armed on this thread, disarming it afterwards.
    pub fn with_write_failing_after<T>(bytes: usize, f: impl FnOnce() -> T) -> T {
        struct Disarm;
        impl Drop for Disarm {
            fn drop(&mut self) {
                FAIL_AFTER.with(|c| c.set(None));
            }
        }
        FAIL_AFTER.with(|c| c.set(Some(bytes)));
        let _disarm = Disarm;
        f()
    }

    pub(super) fn temp_created(tmp: &Path) {
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::metadata(tmp).ok().map(|m| m.permissions().mode() & 0o7777)
        };
        #[cfg(not(unix))]
        let mode = None;
        TEMPS_CREATED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((tmp.to_path_buf(), mode));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Until its commit (which runs under the writer's lock), a staged temp is
    /// owner-only and carries none of the original's metadata, so it exposes
    /// nothing even if the original changes before the commit; the commit then
    /// gives it the original's mode.
    #[cfg(unix)]
    #[test]
    fn a_staged_temp_stays_private_until_its_commit() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "a = 1\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let staged = stage_file_atomically(&path, b"a = 2\n").unwrap();
        let tmp = staged.temp_path().unwrap().to_path_buf();
        assert_eq!(
            std::fs::metadata(&tmp).unwrap().permissions().mode() & 0o7777,
            0o600,
            "no metadata before the commit"
        );
        staged.commit().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "a = 2\n");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o644
        );
    }

    /// A non-regular target (here a FIFO with a reader) is written in place,
    /// never renamed over: the node survives.
    #[cfg(unix)]
    #[test]
    fn a_non_regular_target_is_written_in_place_not_replaced() {
        use std::io::Read as _;
        use std::os::unix::fs::FileTypeExt as _;
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pipe");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let reader = {
            let fifo = fifo.clone();
            std::thread::spawn(move || {
                let mut s = String::new();
                std::fs::File::open(&fifo).unwrap().read_to_string(&mut s).unwrap();
                s
            })
        };
        write_file_atomically(&fifo, b"through\n").unwrap();
        assert_eq!(reader.join().unwrap(), "through\n");
        assert!(std::fs::symlink_metadata(&fifo).unwrap().file_type().is_fifo());
    }

    /// Staging for a non-regular target writes nothing: the write happens in
    /// the commit (under the lock, after validation). Staging against a FIFO
    /// with no reader therefore returns at once instead of blocking in a write.
    #[cfg(unix)]
    #[test]
    fn staging_for_a_non_regular_target_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pipe");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let staged = stage_file_atomically(&fifo, b"x\n").map(|s| s.temp_path().is_none());
            let _ = tx.send(staged.is_ok());
        });
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(5)),
            Ok(true),
            "staging must not write to (or block on) the FIFO"
        );
    }

    /// A target that was missing when the temp was staged but exists at the
    /// commit still gets the commit-time probe: the replacement takes that
    /// file's metadata (and a read-only one would be refused), instead of
    /// replacing it as if it were new.
    #[cfg(unix)]
    #[test]
    fn a_target_that_appears_after_staging_is_still_probed_at_commit() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let staged = stage_file_atomically(&path, b"new\n").unwrap();
        std::fs::write(&path, "old\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        staged.commit().unwrap();
        // It took the metadata of the file that is there now.
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o640
        );
    }
}
