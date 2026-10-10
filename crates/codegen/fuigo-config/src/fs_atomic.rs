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
///
/// This is [`stage_atomically`] followed at once by the rename. A read-modify-write of a shared file should use
/// [`edit_locked`] instead, which stages (and syncs) outside the file's lock and renames inside it.
pub fn write_atomically(
    final_path: &Path,
    contents: &str,
    mode: Option<u32>,
) -> std::io::Result<()> {
    let mut staged = stage_atomically(final_path, contents.as_bytes(), mode)?;
    staged.sync_dir = false;
    staged.commit()
}

/// The first half of [`write_atomically`]: create the uniquely named temp beside `final_path`, write `contents`
/// and `sync_all` it, but do not rename it. Same naming, `create_new` and `mode` rules as [`write_atomically`].
///
/// The returned [`StagedReplacement`] renames it over `final_path` on [`StagedReplacement::commit`] (and then
/// syncs the directory), or removes it when dropped uncommitted.
///
/// # Errors
///
/// Any I/O error creating, writing or syncing the temp; the temp is removed again.
pub fn stage_atomically(
    final_path: &Path,
    contents: &[u8],
    mode: Option<u32>,
) -> std::io::Result<StagedReplacement> {
    let (staged, mut file) = create_staged_temp(final_path, mode)?;
    let written = write_temp(&mut file, final_path, contents);
    // The handle is closed before `staged` could remove the temp (Windows cannot
    // delete a file that is still open); on failure `staged` removes it.
    drop(file);
    written?;
    Ok(staged)
}

/// Write `contents` into a fresh temp and `sync_all` it.
fn write_temp(
    file: &mut std::fs::File,
    #[cfg_attr(not(any(test, feature = "test-seams")), allow(unused_variables))] target: &Path,
    contents: &[u8],
) -> std::io::Result<()> {
    use std::io::Write as _;
    #[cfg(any(test, feature = "test-seams"))]
    if stage_fault::armed_for(target) {
        let cut = contents.len().min(8);
        let _ = file.write_all(&contents[..cut]);
        return Err(std::io::Error::other("injected write failure (test)"));
    }
    file.write_all(contents).and_then(|()| file.sync_all())
}

/// [`stage_atomically`] for a writer that keeps the replaced file's mode
/// EXACTLY, group and world bits included (the shell's MCP, marketplace and
/// plugin-source writers always did). Replaces a symlink at `final_path`, as
/// [`stage_atomically`] does.
///
/// The temp is created `0600` and stays so while it waits for its commit: the
/// target's mode is read and put on it by the commit (under the writer's
/// lock, just before the rename), so a looser mode of some OTHER version of
/// the file can never be on a temp holding these contents before the
/// replacement is validated. A missing target keeps `0600` (a new file). As
/// before, a mode that cannot be read or applied is not an error: the file is
/// then published `0600`. Off unix the mode is not touched.
///
/// # Errors
///
/// As [`stage_atomically`].
pub fn stage_atomically_keeping_mode(
    final_path: &Path,
    contents: &[u8],
) -> std::io::Result<StagedReplacement> {
    let (staged, mut file) = create_staged_temp(final_path, Some(0o600))?;
    let written = write_temp(&mut file, final_path, contents);
    #[cfg(unix)]
    {
        if let Err(e) = written {
            drop(file);
            return Err(e);
        }
        let target = final_path.to_path_buf();
        Ok(staged.finish_with(move |_tmp| {
            use std::os::unix::fs::PermissionsExt as _;
            if let Ok(md) = std::fs::metadata(&target) {
                let _ = file.set_permissions(std::fs::Permissions::from_mode(
                    md.permissions().mode() & 0o7777,
                ));
            }
            Ok(())
        }))
    }
    #[cfg(not(unix))]
    {
        drop(file);
        written?;
        Ok(staged)
    }
}

/// Per-process counter that makes [`stage_atomically`]'s temp names unique.
static WRITE_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Name attempts [`create_staged_temp`] makes before giving up: a name left by
/// a crashed process with the same (reused) pid is skipped, not reused.
const TEMP_NAME_ATTEMPTS: usize = 16;

/// Create the uniquely named, empty temp for `final_path` in its directory and
/// hand back the [`StagedReplacement`] that owns it (and removes it on drop),
/// plus the open handle to fill it through.
///
/// On unix the directory is opened first and the temp is created and later
/// removed through that directory handle, so a temp whose directory is moved
/// away (or swapped and restored) while it is staged is still removed from
/// wherever it ended up.
fn create_staged_temp(
    final_path: &Path,
    mode: Option<u32>,
) -> std::io::Result<(StagedReplacement, std::fs::File)> {
    use std::sync::atomic::Ordering;

    let dir = final_path.parent().unwrap_or_else(|| Path::new("."));
    let name = final_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_owned());
    // The name part is bounded, so a name near the 255-byte limit still fits.
    let mut end = name.len().min(64);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    #[cfg(unix)]
    let mut handle = DirHandle::open_or_none(dir);
    let mut last_err = None;
    for _ in 0..TEMP_NAME_ATTEMPTS {
        let nonce = WRITE_NONCE.fetch_add(1, Ordering::Relaxed);
        let tmp_name = format!("{}.{}.{nonce}.tmp", &name[..end], std::process::id());
        let tmp = dir.join(&tmp_name);
        #[cfg(unix)]
        let opened = match &handle {
            Some(h) => h.create_new(std::ffi::OsStr::new(&tmp_name), mode.unwrap_or(0o666)),
            None => {
                use std::os::unix::fs::OpenOptionsExt as _;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(mode.unwrap_or(0o666))
                    .open(&tmp)
            }
        };
        #[cfg(not(unix))]
        let opened = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp);
        match opened {
            Ok(file) => {
                // From here the temp is ours: the staged value removes it on every failure.
                #[allow(unused_mut)] // a handle is attached on unix only
                let mut staged =
                    StagedReplacement::new_unbound(tmp, final_path.to_path_buf(), dir.to_path_buf());
                #[cfg(unix)]
                if let Some(h) = handle.take() {
                    staged = staged.with_dir_handle(h);
                }
                // The requested mode exactly: the creation mode is masked by
                // the umask, and a restrictive one (say `0400`) would publish
                // a config its owner cannot read back.
                #[cfg(unix)]
                if let Some(mode) = mode {
                    use std::os::unix::fs::PermissionsExt as _;
                    file.set_permissions(std::fs::Permissions::from_mode(mode & 0o7777))?;
                }
                #[cfg(not(unix))]
                let _ = mode;
                return Ok((staged, file));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last_err = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::other("no free temp file name")))
}

/// A directory opened once, so a temp created in it can be removed from it
/// later even if the directory has since been moved or another directory put
/// at its path (cleanup by `unlinkat` on this handle, never by path).
#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct DirHandle(std::fs::File);

#[cfg(unix)]
impl DirHandle {
    /// Open `dir` (`.` for an empty path) as a directory handle. On Linux the
    /// handle is `O_PATH`, which needs no read permission on the directory
    /// (only what creating and renaming a temp in it needed before); elsewhere
    /// it is a read-only open, and callers fall back to path-based creation
    /// and removal when that is refused (see [`DirHandle::open_or_none`]).
    pub(crate) fn open(dir: &Path) -> std::io::Result<Self> {
        use std::os::fd::FromRawFd as _;
        use std::os::unix::ffi::OsStrExt as _;
        let dir = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        let c_dir = std::ffi::CString::new(dir.as_os_str().as_bytes())?;
        // Search-only first (no read permission needed on the directory):
        // `O_PATH` on Linux, `O_SEARCH` on macOS (a kernel without it refuses
        // the flag, and the read-only open below is tried); read-only elsewhere.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let modes = [libc::O_PATH];
        #[cfg(target_os = "macos")]
        let modes = [libc::O_SEARCH, libc::O_RDONLY];
        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
        let modes = [libc::O_RDONLY];
        let mut last = None;
        for access in modes {
            // SAFETY: a NUL-terminated path; the descriptor is owned by the File.
            let fd = unsafe {
                libc::open(c_dir.as_ptr(), access | libc::O_DIRECTORY | libc::O_CLOEXEC)
            };
            if fd >= 0 {
                // SAFETY: `fd` is a fresh descriptor nobody else owns.
                return Ok(Self(unsafe { std::fs::File::from_raw_fd(fd) }));
            }
            last = Some(std::io::Error::last_os_error());
        }
        Err(last.unwrap_or_else(|| std::io::Error::other("no directory open mode")))
    }

    /// [`open`](Self::open), or `None` when the directory cannot be opened as
    /// a handle (then the temp is created and removed by path, as before P61).
    pub(crate) fn open_or_none(dir: &Path) -> Option<Self> {
        Self::open(dir).ok()
    }

    /// `openat(O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC)` of `name` in this
    /// directory, `mode` before the umask.
    pub(crate) fn create_new(
        &self,
        name: &std::ffi::OsStr,
        mode: u32,
    ) -> std::io::Result<std::fs::File> {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        use std::os::unix::ffi::OsStrExt as _;
        let c_name = std::ffi::CString::new(name.as_bytes())?;
        // SAFETY: a valid directory descriptor and a NUL-terminated name; the
        // returned descriptor is owned by the File built from it.
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                libc::c_uint::from(mode & 0o7777),
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh descriptor nobody else owns.
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    /// The directory `name` in this one, opened read-only through this handle
    /// (`openat(O_DIRECTORY | O_NOFOLLOW)`), so it is that child and no other.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))] // macOS staging directories
    pub(crate) fn open_child_dir(&self, name: &std::ffi::OsStr) -> std::io::Result<Self> {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        use std::os::unix::ffi::OsStrExt as _;
        let c_name = std::ffi::CString::new(name.as_bytes())?;
        // SAFETY: a valid directory descriptor and a NUL-terminated name; the
        // returned descriptor is owned by the File built from it.
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh descriptor nobody else owns.
        Ok(Self(unsafe { std::fs::File::from_raw_fd(fd) }))
    }

    /// `dir` opened read-only (`O_RDONLY | O_DIRECTORY`), e.g. to set its ACL.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))] // macOS staging directories
    pub(crate) fn open_read_only(dir: &Path) -> std::io::Result<Self> {
        let file = std::fs::File::open(dir)?;
        if !file.metadata()?.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                format!("{} is not a directory", dir.display()),
            ));
        }
        Ok(Self(file))
    }

    /// A second handle on the same directory.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))] // macOS staging directories
    pub(crate) fn try_clone(&self) -> std::io::Result<Self> {
        self.0.try_clone().map(Self)
    }

    /// The raw descriptor (for `acl_set_fd_np` on the macOS staging directory).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd as _;
        self.0.as_raw_fd()
    }

    /// `mkdirat` of `name` in this directory, `mode` before the umask.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))] // macOS staging directories
    pub(crate) fn create_dir(&self, name: &std::ffi::OsStr, mode: u32) -> std::io::Result<()> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::ffi::OsStrExt as _;
        let c_name = std::ffi::CString::new(name.as_bytes())?;
        let mode = libc::mode_t::try_from(mode & 0o7777).map_err(std::io::Error::other)?;
        // SAFETY: a valid directory descriptor and a NUL-terminated name.
        if unsafe { libc::mkdirat(self.0.as_raw_fd(), c_name.as_ptr(), mode) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// `unlinkat(AT_REMOVEDIR)` of the (empty) directory `name` in this directory.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))] // macOS staging directories
    pub(crate) fn remove_dir(&self, name: &std::ffi::OsStr) -> std::io::Result<()> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::ffi::OsStrExt as _;
        let c_name = std::ffi::CString::new(name.as_bytes())?;
        // SAFETY: a valid directory descriptor and a NUL-terminated name.
        if unsafe { libc::unlinkat(self.0.as_raw_fd(), c_name.as_ptr(), libc::AT_REMOVEDIR) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// `unlinkat` of `name` in this directory.
    pub(crate) fn unlink(&self, name: &std::ffi::OsStr) -> std::io::Result<()> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::ffi::OsStrExt as _;
        let c_name = std::ffi::CString::new(name.as_bytes())?;
        // SAFETY: a valid directory descriptor and a NUL-terminated name.
        if unsafe { libc::unlinkat(self.0.as_raw_fd(), c_name.as_ptr(), 0) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

/// [`stage_atomically`] for replacing whatever is at `final_path` now: the mode
/// is the existing file's minus group and world bits ([`replacement_mode`]'s
/// rule), read through one handle together with the file's identity, which the
/// replacement records ([`StagedReplacement::source`]); `default_mode` for a
/// file that does not exist.
///
/// # Errors
///
/// As [`stage_atomically`], plus a failure to open or stat the existing file.
pub fn stage_atomically_from_existing(
    final_path: &Path,
    contents: &[u8],
    default_mode: u32,
) -> std::io::Result<StagedReplacement> {
    let (mode, source) = match std::fs::File::open(final_path) {
        Ok(f) => {
            let md = f.metadata()?;
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt as _;
                Some(md.permissions().mode() & 0o700)
            };
            #[cfg(not(unix))]
            let mode = None;
            (mode, FileKey::of(&md))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            let mode = Some(default_mode);
            #[cfg(not(unix))]
            let mode = {
                let _ = default_mode;
                None
            };
            (mode, None)
        }
        Err(e) => return Err(e),
    };
    Ok(stage_atomically(final_path, contents, mode)?.from_original(source))
}

/// Test seam (`cfg(test)` here, the `test-seams` feature for other crates' tests): make
/// [`stage_atomically`] fail mid-write on this thread, after creating its temp.
#[cfg(any(test, feature = "test-seams"))]
#[doc(hidden)]
pub mod stage_fault {
    use std::path::{Path, PathBuf};

    thread_local! {
        pub static FAIL_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// Directories under which every stage fails (any thread), for writers
    /// that stage on a blocking pool. Registered by [`fail_writes_under`].
    static FAIL_UNDER: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());

    /// Make every stage of a target under `dir` fail mid-write, on any thread,
    /// until the returned guard drops. (A child process gets the same through
    /// the `FUIGO_TEST_FAIL_STAGE_UNDER` environment variable.)
    #[must_use]
    pub fn fail_writes_under(dir: &Path) -> FailUnder {
        FAIL_UNDER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(dir.to_path_buf());
        FailUnder(dir.to_path_buf())
    }

    /// Disarms [`fail_writes_under`] when dropped.
    #[derive(Debug)]
    pub struct FailUnder(PathBuf);

    impl Drop for FailUnder {
        fn drop(&mut self) {
            let mut dirs = FAIL_UNDER
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(i) = dirs.iter().position(|d| *d == self.0) {
                dirs.remove(i);
            }
        }
    }

    /// Whether a stage of `target` must fail.
    pub(crate) fn armed_for(target: &Path) -> bool {
        if FAIL_WRITE.with(std::cell::Cell::get) {
            return true;
        }
        if let Some(dir) = std::env::var_os("FUIGO_TEST_FAIL_STAGE_UNDER")
            && target.starts_with(&dir)
        {
            return true;
        }
        FAIL_UNDER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|d| target.starts_with(d))
    }
}

/// A finished replacement: a temp file whose contents (and metadata) are already written and synced, waiting to
/// be renamed over its target.
///
/// Built by [`stage_atomically`], or by any writer with its own temp-file policy (the shell's write-through
/// `config.toml` writer builds one with [`StagedReplacement::new`]). [`commit`](Self::commit) does only what must
/// happen under a writer's lock: the `rename` and the directory `fsync`. Dropping it uncommitted removes the temp.
#[must_use = "an uncommitted replacement is discarded when dropped"]
pub struct StagedReplacement {
    /// The temp file; `None` once renamed (or removed).
    tmp: Option<PathBuf>,
    target: PathBuf,
    /// Directory synced after the rename (best-effort, unix only).
    dir: PathBuf,
    /// Whether [`commit`](Self::commit) syncs `dir`. Off only for [`write_atomically`], which never did.
    sync_dir: bool,
    /// Dropped after the rename or the temp's removal, e.g. a private staging directory the temp lives in.
    keep_alive: Option<Box<dyn std::any::Any + Send>>,
    /// What staging saw at the target when it took metadata from it: `Some(Some(key))` that
    /// file, `Some(None)` nothing (a new file); `None` when metadata is deferred to the commit.
    source: Option<Option<FileKey>>,
    /// Run on the temp's path in [`commit`](StagedReplacement::commit), before the rename.
    finish: Option<Finish>,
    /// Contents the commit writes into `target` in place (see `written_in_place_at_commit`).
    in_place: Option<Vec<u8>>,
    /// The directory the temp was created in, held open so the temp is removed
    /// from THAT directory (`unlinkat`) even if it has been moved meanwhile.
    #[cfg(unix)]
    dir_handle: Option<DirHandle>,
}

/// Commit-time work on a staged temp (see [`StagedReplacement::finish_with`]).
type Finish = Box<dyn FnOnce(&Path) -> std::io::Result<()> + Send>;

/// A file's (device, inode), where std exposes them (unix); `None` elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileKey {
    dev: u64,
    ino: u64,
}

impl FileKey {
    /// The key of the file `md` describes.
    #[cfg(unix)]
    #[must_use]
    pub fn of(md: &std::fs::Metadata) -> Option<Self> {
        use std::os::unix::fs::MetadataExt as _;
        Some(Self {
            dev: md.dev(),
            ino: md.ino(),
        })
    }

    /// No key off unix (where [`edit_locked`] makes no optimistic pass).
    #[cfg(not(unix))]
    #[must_use]
    pub fn of(_md: &std::fs::Metadata) -> Option<Self> {
        None
    }
}

impl std::fmt::Debug for StagedReplacement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagedReplacement")
            .field("tmp", &self.tmp)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl StagedReplacement {
    /// Take ownership of a finished temp file `tmp`, to be renamed over `target`; `dir` is the directory synced
    /// after the rename. From this call on, the temp is removed if the value is dropped uncommitted.
    ///
    /// On unix the temp's directory is opened here, and the temp is later
    /// removed through that handle; a writer that created the temp through a
    /// directory handle of its own passes it with `with_dir_handle` instead,
    /// which closes the window between the temp's creation and this call.
    pub fn new(tmp: PathBuf, target: PathBuf, dir: PathBuf) -> Self {
        #[cfg(unix)]
        let handle = tmp.parent().and_then(|p| DirHandle::open(p).ok());
        #[allow(unused_mut)] // assigned on unix only
        let mut staged = Self::new_unbound(tmp, target, dir);
        #[cfg(unix)]
        {
            staged.dir_handle = handle;
        }
        staged
    }

    /// [`new`](Self::new) without a directory handle (removal by path).
    pub(crate) fn new_unbound(tmp: PathBuf, target: PathBuf, dir: PathBuf) -> Self {
        Self {
            tmp: Some(tmp),
            target,
            dir,
            sync_dir: true,
            keep_alive: None,
            source: None,
            finish: None,
            in_place: None,
            #[cfg(unix)]
            dir_handle: None,
        }
    }

    /// Remove the temp through `handle`, the directory it was created in.
    #[cfg(unix)]
    pub(crate) fn with_dir_handle(mut self, handle: DirHandle) -> Self {
        self.dir_handle = Some(handle);
        self
    }

    /// Remove the temp `tmp` (best-effort): through the directory handle when
    /// there is one, so a temp whose directory moved is still found; by path
    /// otherwise.
    fn remove_temp(&self, tmp: &Path) {
        #[cfg(unix)]
        if let (Some(handle), Some(name)) = (&self.dir_handle, tmp.file_name()) {
            let _ = handle.unlink(name);
            return;
        }
        let _ = std::fs::remove_file(tmp);
    }

    /// Run `finish` on the temp's path at commit time, just before the rename
    /// (so under the writer's lock); its error fails the commit and removes the
    /// temp. For metadata that must describe the file as it is when replaced.
    pub fn finish_with(
        mut self,
        finish: impl FnOnce(&Path) -> std::io::Result<()> + Send + 'static,
    ) -> Self {
        self.finish = Some(Box::new(finish));
        self
    }

    /// Record what staging saw at the target: the file whose metadata the temp
    /// was given, or `None` when it found no file there (and so chose a new
    /// file's mode).
    pub fn from_original(mut self, source: Option<FileKey>) -> Self {
        self.source = Some(source);
        self
    }

    /// A replacement written IN PLACE by its commit (no temp, no rename): for a
    /// target that is not a regular file -- a device, a FIFO -- which a rename
    /// would destroy. Nothing is written before the commit.
    pub fn written_in_place_at_commit(target: PathBuf, contents: Vec<u8>) -> Self {
        Self {
            tmp: None,
            dir: target.parent().map(Path::to_path_buf).unwrap_or_default(),
            target,
            sync_dir: false,
            keep_alive: None,
            source: None,
            finish: None,
            in_place: Some(contents),
            #[cfg(unix)]
            dir_handle: None,
        }
    }

    /// The path the temp will be renamed onto.
    #[must_use]
    pub fn target(&self) -> &Path {
        &self.target
    }

    /// What staging saw at the target (see [`from_original`](Self::from_original));
    /// `None` when the metadata is applied at commit instead.
    #[must_use]
    pub fn source(&self) -> Option<Option<FileKey>> {
        self.source
    }

    /// Rename onto `entry` instead: the target's own directory entry in
    /// another spelling (see [`identity::entry_as_on_disk`]). Nothing to do
    /// for a replacement written in place.
    fn land_on(&mut self, entry: PathBuf) {
        if self.tmp.is_some() {
            self.target = entry;
        }
    }

    /// Keep `guard` alive until the temp has been renamed or removed, then drop it.
    pub fn keep_alive(mut self, guard: impl std::any::Any + Send) -> Self {
        self.keep_alive = Some(Box::new(guard));
        self
    }

    /// The temp file's path (until committed).
    #[must_use]
    pub fn temp_path(&self) -> Option<&Path> {
        self.tmp.as_deref()
    }

    /// Rename the temp over the target, then `fsync` the directory (unix, best-effort).
    ///
    /// # Errors
    ///
    /// The `rename` error; the temp is then removed and the target left as it was.
    pub fn commit(mut self) -> std::io::Result<()> {
        if let Some(contents) = self.in_place.take() {
            return std::fs::write(&self.target, contents);
        }
        let Some(tmp) = self.tmp.take() else {
            return Ok(());
        };
        if let Some(finish) = self.finish.take()
            && let Err(e) = finish(&tmp)
        {
            self.remove_temp(&tmp);
            return Err(e);
        }
        if let Err(e) = std::fs::rename(&tmp, &self.target) {
            self.remove_temp(&tmp);
            return Err(e);
        }
        drop(self.keep_alive.take());
        if self.sync_dir {
            sync_dir(&self.dir);
        }
        Ok(())
    }
}

impl Drop for StagedReplacement {
    fn drop(&mut self) {
        if let Some(tmp) = self.tmp.take() {
            self.remove_temp(&tmp);
        }
        drop(self.keep_alive.take());
    }
}

/// Best-effort `fsync` of a directory, so a completed rename in it survives a crash. Skipped off unix, where std
/// cannot open a directory for syncing.
pub fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    }) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
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

/// A lock file for `path` kept OUT of `path`'s directory: `<locks_dir>/<prefix>-<hash>.lock`,
/// `<hash>` naming the file's identity, so every spelling of one file (a
/// symlinked project directory, `..` through an existing link, the real path)
/// gets the same lock, and nothing is dropped beside the file (in a user's
/// repository, a sessions directory, a plugin install directory).
///
/// The identity is the file's DIRECTORY resolved the way the kernel will
/// resolve it once a writer has created what is missing: component by
/// component, each prefix canonicalized when it exists, a missing component
/// appended as is, and `..` after a missing component taken lexically (a
/// missing directory's parent is the prefix before it). It therefore does not
/// change when the first writer creates a missing directory. The file name
/// itself is not resolved. (Moved here from the shell's `rmw_lock_path` in P72,
/// unchanged, so the shell and the other crates share it.)
#[must_use]
pub fn lock_path_in(locks_dir: &Path, prefix: &str, path: &Path) -> PathBuf {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let (dir, name) = match (absolute.parent(), absolute.file_name()) {
        (Some(dir), Some(name)) => (dir.to_path_buf(), name.to_owned()),
        _ => (absolute.clone(), std::ffi::OsString::new()),
    };
    let mut resolved = PathBuf::new();
    for part in dir.components() {
        match part {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                resolved = dunce::canonicalize(resolved.join("..")).unwrap_or_else(|_| {
                    let mut up = resolved.clone();
                    up.pop();
                    up
                });
            }
            other => {
                let next = resolved.join(other);
                resolved = dunce::canonicalize(&next).unwrap_or(next);
            }
        }
    }
    let identity = resolved.join(name);
    let digest = ring::digest::digest(
        &ring::digest::SHA256,
        identity.as_os_str().as_encoded_bytes(),
    );
    let hex: String = digest.as_ref()[..12]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    locks_dir.join(format!("{prefix}-{hex}.lock"))
}

/// The NAME lock of a Fuigo state file (P72, identity rewritten in P79):
/// `<fuigo home>/locks/state-<hash>.lock`, `<hash>` naming the file's
/// [`identity`] so that every path naming one file -- through a symlink in
/// the directory or at the name (these writers write THROUGH one), through
/// `..`, in another case on a case-insensitive volume -- gives the same lock,
/// on every platform. Every writer of one state file takes it, through
/// [`edit_state_file`] or [`lock_state_file`], which also take the file's
/// inode lock when it exists.
///
/// # Errors
///
/// When the identity cannot be established (the module docs of [`identity`]
/// list what that takes). It fails closed: there is no fallback to a
/// path-string lock, which could split.
pub fn state_lock_path(path: &Path) -> std::io::Result<PathBuf> {
    Ok(name_lock_path(&identity::identity(path)?.name))
}

/// The lock file of a state file's name ([`identity::Identity::name`]). The
/// hash is [`lock_path_in`]'s, of the same bytes wherever nothing is folded
/// and the path has a plain spelling (the module docs of [`identity`]).
fn name_lock_path(name: &[u8]) -> PathBuf {
    name_lock_path_in(&state_locks_dir(), name)
}

/// [`name_lock_path`] in the lock directory `locks`.
fn name_lock_path_in(locks: &Path, name: &[u8]) -> PathBuf {
    let digest = ring::digest::digest(&ring::digest::SHA256, name);
    let hex: String = digest.as_ref()[..12]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    locks.join(format!("state-{hex}.lock"))
}

/// Where the state locks live: `<fuigo home>/locks`. In this crate's own
/// unit tests, a directory private to the test process ([`test_locks`]).
fn state_locks_dir() -> PathBuf {
    #[cfg(test)]
    {
        test_locks::dir()
    }
    #[cfg(not(test))]
    {
        fuigo_dirs::fuigo_home().join("locks")
    }
}

/// The state locks of this crate's unit tests: a temp directory of the test
/// process, removed when it exits. The tests take hundreds of state locks,
/// and the fuigo home is whoever runs them's own unless the harness gives
/// them another (on Windows a native run left a thousand lock files in the
/// user's real `.fuigo\locks`).
///
/// A process that does not leave through the C runtime's `exit` keeps its
/// directory (a kill; on Windows also a failing test run, which std ends
/// with `ExitProcess`). The next test process removes it -- and only a
/// directory whose owner is gone: each process holds an exclusive `flock`
/// on a marker file in its directory for as long as it lives, and a
/// directory is removed only by whoever can take that lock. The marker
/// gets its name only once it is locked (as a queue ticket does), so a
/// marker that can be locked is never one whose owner is still starting.
#[cfg(test)]
mod test_locks {
    use fs2::FileExt as _;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock, PoisonError};

    static DIR: OnceLock<PathBuf> = OnceLock::new();
    /// This process's hold on its directory (the locked marker file).
    static OWNED: Mutex<Option<std::fs::File>> = Mutex::new(None);

    const PREFIX: &str = "fuigo-config-test-locks-";
    const MARKER: &str = "owner.lock";

    unsafe extern "C" {
        /// The C runtime's `atexit` (libc, and the Windows CRT).
        fn atexit(callback: extern "C" fn()) -> std::ffi::c_int;
    }

    extern "C" fn remove() {
        // The marker is closed first: Windows cannot remove a directory
        // holding a file that is still open.
        drop(OWNED.lock().unwrap_or_else(PoisonError::into_inner).take());
        if let Some(dir) = DIR.get() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// Remove the directories under `temp` that test processes now gone
    /// left: those whose marker's lock is free. A directory without a
    /// marker is left alone (its owner may be about to publish it). The
    /// lock is let go before the removal (Windows cannot remove an open
    /// file's directory): nobody takes a dead owner's marker for keeps.
    pub(super) fn sweep(temp: &Path) {
        for entry in std::fs::read_dir(temp).into_iter().flatten().flatten() {
            if !entry.file_name().to_string_lossy().starts_with(PREFIX) {
                continue;
            }
            let Ok(marker) = std::fs::File::open(entry.path().join(MARKER)) else {
                continue;
            };
            if marker.try_lock_exclusive().is_ok() {
                drop(marker);
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    }

    /// Create a lock directory under `temp` and take its marker's lock.
    pub(super) fn create(temp: &Path) -> (PathBuf, std::fs::File) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = temp.join(format!("{PREFIX}{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("the test lock directory");
        // Locked under a private name, then given the name `sweep` looks for.
        let unpublished = dir.join(format!("{MARKER}.new"));
        let marker = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&unpublished)
            .expect("the test lock directory's marker");
        marker.try_lock_exclusive().expect("a fresh marker is free");
        std::fs::rename(&unpublished, dir.join(MARKER)).expect("publishing the marker");
        (dir, marker)
    }

    pub(super) fn dir() -> PathBuf {
        DIR.get_or_init(|| {
            let temp = std::env::temp_dir();
            sweep(&temp);
            let (dir, marker) = create(&temp);
            *OWNED.lock().unwrap_or_else(PoisonError::into_inner) = Some(marker);
            // SAFETY: a plain function with nothing to unwind, registered once.
            let _ = unsafe { atexit(remove) };
            dir
        })
        .clone()
    }
}

/// The lock file of a state file's inode ([`identity::Identity::inode`]):
/// one of [`INODE_LOCK_STRIPES`] files, picked by a hash of the inode. Not a
/// file per inode: every replace makes a new inode, and lock files are never
/// removed. Two files on one stripe only wait for each other.
fn inode_lock_path_in(locks: &Path, inode: &[u8]) -> PathBuf {
    let digest = ring::digest::digest(&ring::digest::SHA256, inode);
    let bytes = digest.as_ref();
    let stripe = u16::from_be_bytes([bytes[0], bytes[1]]) % INODE_LOCK_STRIPES;
    locks.join(format!("state-inode-{stripe:03x}.lock"))
}

/// [`inode_lock_path_in`] the state lock directory (tests ask for it).
#[cfg(test)]
fn inode_lock_path(inode: &[u8]) -> PathBuf {
    inode_lock_path_in(&state_locks_dir(), inode)
}

const INODE_LOCK_STRIPES: u16 = 1024;

/// Take the state lock of `path`: its name lock ([`state_lock_path`]) and,
/// when the file exists, the lock of its inode, in that order. Each is kept
/// only if the identity it was taken for is still the file's once it is held.
///
/// Two locks because neither covers every writer (the module docs of
/// [`identity`]). The name lock is all a missing file has, and it keeps two
/// writers of one name apart across a replace (the rename every writer here
/// ends with gives the name a new inode). The inode lock adds every writer
/// that reaches the same file under a name this module cannot equate: a hard
/// link (also one made while a writer holds the lock), an NTFS short name,
/// another normal form. A writer queued on the lock of an inode the name no
/// longer has lets go of both and starts again.
///
/// No deadlock: a writer holds one name lock and then at most one inode lock,
/// and waits for a name lock only while it holds nothing. Callers must not
/// take another lock while they hold this one (none does).
///
/// The name itself only moves when a symlink is re-pointed or a directory's
/// case-sensitivity is changed.
///
/// # Errors
///
/// As [`state_lock_path`] and [`lock_file_for_write`]; also when the identity
/// does not settle in a few rounds.
pub fn lock_state_file(path: &Path) -> std::io::Result<ConfigWriteLock> {
    take_state_lock(path).map(|(lock, _)| lock)
}

/// [`lock_state_file`], with the identity the locks were granted for.
fn take_state_lock(path: &Path) -> std::io::Result<(ConfigWriteLock, identity::Identity)> {
    take_state_lock_in(path, CONFIG_LOCK_MAX_WAIT, &state_locks_dir)
}

/// [`take_state_lock`] with the give-up time and the lock directory as
/// parameters (tests use short times; a test that keeps an inode stripe busy
/// for seconds uses a lock directory of its own, so that no other test's
/// file can share that stripe). The directory is asked for only once the
/// path has an identity: a path that is refused does not get the fuigo home
/// looked up (and created) on its way out.
///
/// The inode lock is waited for while the name lock is HELD, so the writers
/// queued on the name lock see their holder do nothing for as long as it
/// queues on its inode stripe, which other files share. Every move of that
/// queue is therefore passed on to them ([`lock_at_within_behind`]): they
/// give up only when nothing moved for `stall` on EITHER lock, which is the
/// rule a single lock has.
fn take_state_lock_in(
    path: &Path,
    stall: Duration,
    locks: &dyn Fn() -> PathBuf,
) -> std::io::Result<(ConfigWriteLock, identity::Identity)> {
    let mut wanted = identity::identity(path)?;
    let locks = &locks();
    for _ in 0..8 {
        let mut lock = lock_at_within(&name_lock_path_in(locks, &wanted.name), stall)?;
        let held = identity::identity(path)?;
        if held.name != wanted.name {
            wanted = held;
            continue;
        }
        let inode_lock = held
            .inode
            .as_deref()
            .map(|inode| inode_lock_path_in(locks, inode));
        let Some(inode_lock) = inode_lock else {
            // A missing file: the name is all there is.
            return Ok((lock, held));
        };
        let inode_lock = lock_at_within_behind(&inode_lock, stall, Some(&lock))?;
        let now = identity::identity(path)?;
        if now == held {
            lock._inode = Some(Box::new(inode_lock));
            return Ok((lock, held));
        }
        // `inode_lock` and then `lock` are released here.
        wanted = now;
    }
    Err(std::io::Error::other(format!(
        "the lock identity of {} kept changing; not locking it",
        path.display()
    )))
}

/// Test seam: is `thread` (of this process) queued for a lock of this module
/// right now, behind another thread's turn? Lets a test wait until the very
/// writer it started really is waiting, instead of sleeping and hoping.
#[cfg(any(test, feature = "test-seams"))]
#[must_use]
pub fn thread_is_queued_for_a_lock(thread: std::thread::ThreadId) -> bool {
    turn::is_queued(thread)
}

/// [`edit_locked_with_lock`] on [`state_lock_path`]: the read-modify-write of
/// a Fuigo state file (`pager.toml`, a persona, `announcements.json`,
/// `slash-mru.json`, a prompt history, the plugin install registry), with no
/// lock file left beside it.
///
/// # Errors
///
/// As [`edit_locked`]; [`EditError::Lock`] also when the file's lock identity
/// cannot be established ([`state_lock_path`]).
pub fn edit_state_file<T, E>(
    path: &Path,
    stage: impl FnMut(&[u8]) -> std::io::Result<StagedReplacement>,
    edit: impl FnMut(Current<'_>) -> Result<Edit<T>, E>,
) -> Result<T, EditError<E>> {
    edit_locked_for(path, LockFor::State, stage, edit)
}

/// Which lock a read-modify-write takes: a fixed lock file, or a state file's
/// own ([`take_state_lock`], re-derived every time it is taken).
#[derive(Clone, Copy)]
enum LockFor<'a> {
    Path(&'a Path),
    State,
}

impl LockFor<'_> {
    fn take(self, path: &Path) -> std::io::Result<Taken> {
        match self {
            LockFor::Path(lock_path) => lock_file_for_write(lock_path).map(|lock| Taken {
                _lock: lock,
                granted_for: None,
            }),
            LockFor::State => take_state_lock(path).map(|(lock, identity)| Taken {
                _lock: lock,
                granted_for: Some(identity),
            }),
        }
    }
}

/// A lock taken through [`LockFor`], and, for a state file, the identity it
/// was granted for.
struct Taken {
    _lock: ConfigWriteLock,
    granted_for: Option<identity::Identity>,
}

impl Taken {
    /// Refuse unless `path`, and the file `staged` will be renamed onto,
    /// both still have the identity this lock was granted for. An outsider
    /// who re-pointed a symlink on the path, or put another file at the name,
    /// while the lock was held would otherwise have what was read under the
    /// lock written to a file the lock does not cover (also when the link was
    /// put back after the replacement was staged for the other file).
    fn check_still_covers(&self, path: &Path, staged: &StagedReplacement) -> std::io::Result<()> {
        let Some(granted_for) = &self.granted_for else {
            return Ok(());
        };
        if identity::identity(path)? == *granted_for
            && identity::identity(staged.target())? == *granted_for
        {
            return Ok(());
        }
        Err(std::io::Error::other(format!(
            "{} became another file while its lock was held; not writing it",
            path.display()
        )))
    }
}

impl Taken {
    /// For a state file: make `staged` replace the file's directory entry
    /// under the spelling it has ON DISK, not the one this writer was given
    /// (the module docs of [`identity`], "One lock, one directory entry").
    /// Where the rename would otherwise respell the entry (Windows), a write
    /// through an 8.3 short name removed the long name, and the next writer
    /// through the long name started from an empty file while holding the
    /// very same locks.
    ///
    /// Fails closed: where the spelling cannot be established (on Windows, a
    /// directory the writer may not list), nothing is written. Landing on
    /// the spelling given instead would keep the loss for exactly those
    /// directories.
    fn land_on_the_entry(&self, staged: &mut StagedReplacement) -> std::io::Result<()> {
        if self.granted_for.is_none() {
            return Ok(());
        }
        let found = identity::entry_as_on_disk(staged.target());
        if let Some(entry) = entry_to_land_on(staged.target(), found)? {
            staged.land_on(entry);
        }
        Ok(())
    }
}

/// What [`Taken::land_on_the_entry`] makes of the lookup of `target`'s
/// on-disk spelling: another spelling to land on, none, or -- when the
/// lookup failed, for whatever reason -- a refusal.
fn entry_to_land_on(
    target: &Path,
    found: std::io::Result<Option<PathBuf>>,
) -> std::io::Result<Option<PathBuf>> {
    found.map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "cannot establish the on-disk name of {}; not writing it: {e}",
                target.display()
            ),
        )
    })
}

/// How long a writer waiting for a contended lock goes on waiting while NOTHING
/// ahead of it moves, before it gives up.
///
/// Not a cap on the whole wait (P72): a writer behind a queue of live writers
/// keeps its place as long as that queue moves, and is refused only when the
/// writer at its head has held the lock (or the queue has been stuck) for this
/// long. A wedged or stopped holder therefore still cannot freeze a caller for
/// more than this, while a loaded host, where every holder is slow but alive,
/// no longer turns a long queue into a refusal (the old 2 s total cap did:
/// R064 §5.3). Because the queue is FIFO across processes too (see
/// [`lock_config_for_write`]), a writer's total wait is bounded by the number
/// of writers ahead of it when it queued, times this -- plus, on a state
/// file's name lock, what its holder waits for on the file's inode stripe,
/// which is handed on as progress ([`take_state_lock_in`]) and is
/// bounded the same way by the writers ahead on that stripe.
pub const CONFIG_LOCK_MAX_WAIT: Duration = Duration::from_secs(10);

/// An exclusive advisory `flock` held over one `config.toml` read-modify-write
/// cycle, plus this process's turn in the lock's FIFO queue. Dropping it closes
/// the file, which releases the `flock` (also when the holding process dies),
/// and then passes the turn to the next waiter in this process.
#[derive(Debug)]
pub struct ConfigWriteLock {
    /// A state file's inode lock, taken after this one
    /// ([`lock_state_file`]). Declared first: released first.
    _inode: Option<Box<ConfigWriteLock>>,
    /// Held only for its `flock`; the contents are never read or written.
    /// Declared before the queue places, so it is released before they are handed on.
    _file: HeldFlock,
    /// This process's place in the cross-process queue (`None` when the queue
    /// directory could not be used); dropped next, which lets the next process in.
    _ticket: Option<xq::Ticket>,
    _turn: turn::Turn,
}

impl ConfigWriteLock {
    /// Tell the writers queued behind this (held) lock that its holder is
    /// not stuck: it moved up the queue of the next lock it needs
    /// ([`lock_at_within_behind`]). Threads of this process see the queue's
    /// progress count move; other processes see this holder's ticket change
    /// ([`xq::wait_for_head`]).
    fn pass_on_progress(&self) {
        if let Some(ticket) = &self._ticket {
            ticket.touch();
        }
        turn::note_progress(self._turn.key());
    }
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
/// The writers that take it (P61 inventory, 2026-10-02, extended by P72) -- all but a few through
/// [`edit_locked`] / [`edit_locked_with_lock`]:
///
/// - `fuigo-pager`: `/provider` (`provider_config_edit`), `set_hint_at`
///   (`config_toml_edit`), the agents modal (`views::agents_modal`), the
///   dashboard persist (`views::dashboard::state::write_persisted_to_path`),
///   `marketplace add`/`remove` (`plugin_cmd`), the ACP connect-flag write
///   (`acp::apply_config_writes`);
/// - `fuigo-shell`: the settings save (`util::config::persist::update_config`,
///   on [`edit_locked_with_lock`] since P72), every MCP writer
///   (`util::config::mcp`, through `persist::edit_config_file`), the
///   marketplace writers (`extensions::marketplace`), the Claude import
///   (`claude_import::write_import_marker`, `apply_items_to_config`), the
///   plugin-list writers (`config::edit_config_string_list`), and
///   `hooks-paths` (`config::add_hooks_path_to_file` /
///   `remove_hooks_path_from_file`, under `hooks-paths.lock`);
/// - `fuigo-shell` state files, through `persist::edit_config_file` on a lock
///   under `~/.fuigo/locks/` (`persist::rmw_lock_path`): `mcp_preferences.json`,
///   `claude_import_state.json`, the marketplace JSON fallbacks
///   (`plugin::try_remove_from_json_object`), and a project's
///   `.fuigo/config.toml`;
/// - `fuigo-hooks`: `disabled-hooks` (`trust::disable_hook` / `enable_hook`,
///   under `disabled-hooks.lock`);
/// - `fuigo-shell`'s models cache (`agent::models::cache`), on its own lock path;
/// - Fuigo state files, through [`edit_state_file`] (or, for appends,
///   [`lock_file_for_write`]) on [`state_lock_path`] under `~/.fuigo/locks/`
///   (P72): `pager.toml` (`fuigo-pager-render`), personas
///   (`fuigo-pager` `views::persona_detail`), `announcements.json`
///   (`fuigo-announcements`), `slash-mru.json` (`fuigo-pager` `slash::mru`), a
///   prompt history's appends and truncation (`fuigo-shell`
///   `session::prompt_history`), and the plugin install registry
///   (`fuigo-agent` `plugins::install_registry`); and a hooks directory's
///   `imported-from-claude.json` (`fuigo-shell` `claude_import`, on
///   `persist::rmw_lock_path`).
///
/// The list is load-bearing, not decoration: a new writer that skips this
/// function silently reintroduces the lost update, and nothing here can detect
/// it. It is also the kind of claim that rots -- an earlier revision of this
/// comment asserted the list was exhaustive while four writers were missing
/// from it -- so treat it as a claim to re-verify, not a fact to trust.
///
/// # Errors
///
/// - `TimedOut` when nothing ahead of this writer moved for
///   [`CONFIG_LOCK_MAX_WAIT`] (the holder is wedged, stopped, or slower than that).
/// - Any other I/O error from creating or opening the lock file, or from a
///   `flock` that failed for a reason other than contention (e.g. a filesystem
///   that does not implement it). The error is propagated rather than silently
///   proceeding unlocked, so a caller never believes it is serialized when it is not.
pub fn lock_config_for_write(config_path: &Path) -> std::io::Result<ConfigWriteLock> {
    lock_config_for_write_within(config_path, CONFIG_LOCK_MAX_WAIT)
}

/// [`lock_config_for_write`] on an explicit lock file rather than the one
/// derived from a config path ([`config_lock_path`]): for a file whose lock
/// must not sit beside it (a project's `.fuigo/config.toml`, inside the
/// user's repository). Same queue, wait and caveats; the lock file's parent
/// directory is created.
///
/// # Errors
///
/// As [`lock_config_for_write`].
pub fn lock_file_for_write(lock_path: &Path) -> std::io::Result<ConfigWriteLock> {
    lock_at_within(lock_path, CONFIG_LOCK_MAX_WAIT)
}

/// [`lock_config_for_write`] with the give-up time as a parameter (tests use short ones).
///
/// Three stages. `stall` is how long each may go on with nothing ahead of this
/// writer moving; every move ahead of it starts that time again.
///
/// 1. **This process's turn, strictly FIFO.** Every thread of this process that
///    wants the lock on the same file takes a ticket and waits, on a condition
///    variable, for its number to be served. A holder that releases and
///    immediately re-requests goes to the back of the queue, so no waiter can be
///    starved by back-to-back holders (the old 20 ms polling waiter could: the
///    holder re-took the lock in the microseconds between two polls, every time).
///    A waiter that gives up leaves its ticket marked abandoned, and it is
///    skipped.
/// 2. **This process's place in the cross-process queue, FIFO (P72).** The
///    thread whose turn it is registers a ticket file in the lock's queue
///    directory (`.<lock name>.queue`, beside the lock file; see [`xq`]),
///    named by its arrival time, and waits until no LIVE ticket older than its
///    own is left. A ticket is live while its writer holds an exclusive `flock`
///    on it, which the kernel drops when the writer exits however it exits, so
///    a crashed writer's ticket is skipped (and removed), never waited on. A
///    process that releases and at once re-requests queues behind every
///    process already waiting, so no process can be starved by others, and a
///    writer's whole wait is bounded by the writers ahead of it when it
///    queued, each holding for at most `stall` (the holder of a state
///    file's name lock: once it has its inode lock too; see
///    [`CONFIG_LOCK_MAX_WAIT`]). If the queue directory cannot
///    be used (a read-only directory, a filesystem without hard links), this
///    stage is skipped: the writer is then still excluded by stage 3, only not
///    ordered.
/// 3. **The `flock` itself, blocking.** Mutual exclusion comes from this alone
///    (the queue only orders the writers that use it; an older Fuigo takes
///    only this lock). If another process holds it, the request blocks in the
///    kernel and is woken when the lock is released, rather than sleeping
///    blind between polls. The blocking call runs on a helper thread, so the
///    wait can still give up; there is at most ONE such helper per lock file,
///    however many waits time out against a wedged holder (a later turn re-uses
///    the one already blocked). A grant that arrives when no turn is waiting
///    for it is released at once.
fn lock_config_for_write_within(
    config_path: &Path,
    stall: Duration,
) -> std::io::Result<ConfigWriteLock> {
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    lock_at_within(&config_lock_path(config_path), stall)
}

/// A lock file whose `flock` is released by an explicit `unlock` when this drops,
/// before the handle closes. Closing alone is not enough: the lock belongs to
/// the open file description, so a child that another thread forks
/// (`Command::spawn`) between our open and its exec holds a copy of the
/// descriptor and keeps the lock alive until it execs (R-flake-rewind; rows
/// 190, 193, 194). Unlocking a handle that holds no lock is harmless.
#[derive(Debug)]
pub(crate) struct HeldFlock(std::fs::File);

impl HeldFlock {
    pub(crate) fn new(file: std::fs::File) -> Self {
        Self(file)
    }
}

impl std::ops::Deref for HeldFlock {
    type Target = std::fs::File;
    fn deref(&self) -> &std::fs::File {
        &self.0
    }
}

impl Drop for HeldFlock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

/// Open (creating) a writer lock file. Its contents are irrelevant, but it sits beside the user's
/// config and state (`config.toml.lock`, `~/.fuigo/locks/*`), so it is created owner-only (0600) on
/// Unix like the files it guards (P150, D6), and one left looser by an older version is tightened
/// (best effort: a filesystem without modes must not stop the write).
pub(crate) fn open_lock_file(lock_path: &Path) -> std::io::Result<HeldFlock> {
    open_lock_file_raw(lock_path).map(HeldFlock::new)
}

fn open_lock_file_raw(lock_path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    // truncate(false): the contents are irrelevant; it also silences clippy::suspicious_open_options.
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        options.mode(0o600);
        let file = options.open(lock_path)?;
        if file
            .metadata()
            .is_ok_and(|meta| meta.permissions().mode() & 0o777 != 0o600)
        {
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    options.open(lock_path)
}

/// [`lock_config_for_write_within`] on the lock file itself.
fn lock_at_within(lock_path: &Path, stall: Duration) -> std::io::Result<ConfigWriteLock> {
    lock_at_within_behind(lock_path, stall, None)
}

/// [`lock_at_within`] by a writer that already HOLDS `outer` (a state file's
/// name lock, while it queues for the inode lock). Whenever the queue ahead
/// of it here moves, in this process or across processes, that is passed on
/// to the writers queued behind `outer`
/// ([`ConfigWriteLock::pass_on_progress`]), whose holder would otherwise
/// look wedged to them for the whole of this wait.
///
/// The wait of stage 3 (another process holding the `flock` outside the
/// queue) has no move to report. It is itself over after `stall`, and its
/// grant is passed on, so the writers behind `outer` give the holder its
/// time from then.
fn lock_at_within_behind(
    lock_path: &Path,
    stall: Duration,
    outer: Option<&ConfigWriteLock>,
) -> std::io::Result<ConfigWriteLock> {
    use fs2::FileExt as _;

    if let Some(parent) = lock_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let lock_path = lock_path.to_path_buf();
    let timed_out = || {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "{} is locked by another Fuigo writer; gave up after {:?} \
                 without progress rather than blocking. Retry, or remove that \
                 lock file if no other Fuigo is running.",
                lock_path.display(),
                stall
            ),
        )
    };
    let pass_on = || {
        if let Some(outer) = outer {
            outer.pass_on_progress();
        }
    };
    // Stage 1.
    let moved: Option<&dyn Fn()> = if outer.is_some() { Some(&pass_on) } else { None };
    let turn = turn::wait(turn::key_for(&lock_path), stall, moved).ok_or_else(timed_out)?;
    // Stage 2.
    let ticket = match xq::register(&lock_path) {
        Ok(ticket) => Some(ticket),
        Err(e) => {
            tracing::debug!(
                lock = %lock_path.display(),
                error = %e,
                "lock queue unavailable; waiting for the lock unordered"
            );
            None
        }
    };
    if let Some(ticket) = &ticket
        && !xq::wait_for_head(ticket, stall, || {
            turn::note_progress(turn.key());
            pass_on();
        })
    {
        return Err(timed_out());
    }
    // Stage 3.
    let file = open_lock_file(&lock_path)?;

    match file.try_lock_exclusive() {
        Ok(()) => {
            // (Nothing to pass on: whatever this writer waited for in the
            // two queues has been passed on by them.)
            xq::trace_granted(&lock_path);
            return Ok(ConfigWriteLock {
                _inode: None,
                _file: file,
                _ticket: ticket,
                _turn: turn,
            });
        }
        Err(e) if lock_is_contended(&e) => {}
        Err(e) => return Err(e),
    }
    // Held by another process (an older Fuigo, or one whose queue directory
    // differs): block in the kernel on this file's helper thread, so the wait
    // can still give up (stage 3 docs).
    drop(file);
    let deadline = std::time::Instant::now() + stall;
    match turn::await_flock(turn.key(), &lock_path, deadline) {
        Ok(file) => {
            xq::trace_granted(&lock_path);
            // The wait for the `flock` itself had no move to pass on, and
            // may have used up most of the time the writers behind `outer`
            // give its holder: the grant starts that time again.
            pass_on();
            Ok(ConfigWriteLock {
                _inode: None,
                _file: file,
                _ticket: ticket,
                _turn: turn,
            })
        }
        Err(Some(e)) => Err(e),
        Err(None) => Err(timed_out()),
    }
}

/// The in-process FIFO queue in front of each lock file (stage 1 of
/// [`lock_config_for_write_within`]).
#[path = "fs_atomic_identity.rs"]
mod identity;

mod turn {
    use std::collections::{BTreeSet, HashMap};
    use std::path::{Path, PathBuf};
    use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
    use std::time::{Duration, Instant};

    /// One lock file's queue: tickets are handed out from `next`; `serving` is
    /// the ticket whose turn it is.
    #[derive(Default)]
    struct Queue {
        next: u64,
        serving: u64,
        /// Bumped by the turn holder whenever the cross-process queue ahead of
        /// it moves: progress the threads queued behind it count too.
        progress: u64,
        /// Tickets whose waiters gave up; skipped when reached.
        abandoned: BTreeSet<u64>,
        /// The blocking `flock` helper thread is running (at most one).
        helper_running: bool,
        /// The turn holder is waiting for the helper's grant.
        waiting: bool,
        /// The helper's grant, handed to the waiting turn holder.
        granted: Option<super::HeldFlock>,
        /// The helper's failure, handed to the waiting turn holder.
        failed: Option<std::io::Error>,
    }

    impl Queue {
        /// Nobody holds, waits, or has a helper outstanding.
        fn idle(&self) -> bool {
            self.serving == self.next && !self.helper_running
        }
    }

    #[cfg(test)]
    thread_local! {
        /// Helper threads this thread started (tests: at most one per blocked lock file).
        pub(super) static HELPERS_SPAWNED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// Every queue with a holder or a waiter, by lock-file identity. An idle
    /// queue is removed, so this does not grow with the number of files ever
    /// locked.
    static QUEUES: Mutex<Option<HashMap<PathBuf, Queue>>> = Mutex::new(None);
    /// Signalled whenever any queue's `serving` or `progress` moves.
    static SERVED: Condvar = Condvar::new();

    fn queues() -> MutexGuard<'static, Option<HashMap<PathBuf, Queue>>> {
        // A panic while holding this mutex cannot leave a queue half-updated in
        // a way that matters more than refusing every later writer would.
        QUEUES.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The queue identity for `lock_path`: its directory resolved, so two
    /// spellings of one file share a queue. (Two spellings that resolve
    /// differently still exclude each other through the `flock`; they only
    /// lose the FIFO order between them.)
    pub(super) fn key_for(lock_path: &Path) -> PathBuf {
        match (lock_path.parent(), lock_path.file_name()) {
            (Some(dir), Some(name)) => dunce::canonicalize(if dir.as_os_str().is_empty() {
                Path::new(".")
            } else {
                dir
            })
            .map_or_else(|_| lock_path.to_path_buf(), |d| d.join(name)),
            _ => lock_path.to_path_buf(),
        }
    }

    /// This thread's turn at one lock file; dropping it serves the next ticket.
    #[derive(Debug)]
    pub(super) struct Turn {
        key: PathBuf,
    }

    impl Turn {
        pub(super) fn key(&self) -> &Path {
            &self.key
        }
    }

    /// Test seam: the threads of this process waiting for their turn at a
    /// lock, each while it waits ([`super::thread_is_queued_for_a_lock`]).
    #[cfg(any(test, feature = "test-seams"))]
    static QUEUED: Mutex<Vec<std::thread::ThreadId>> = Mutex::new(Vec::new());

    #[cfg(any(test, feature = "test-seams"))]
    pub(super) fn is_queued(thread: std::thread::ThreadId) -> bool {
        QUEUED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&thread)
    }

    /// This thread's entry in [`QUEUED`], from the moment it finds the turn
    /// taken until it is served or gives up.
    #[cfg(any(test, feature = "test-seams"))]
    struct QueuedMark;

    #[cfg(any(test, feature = "test-seams"))]
    impl QueuedMark {
        fn new() -> Self {
            QUEUED
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(std::thread::current().id());
            Self
        }
    }

    #[cfg(any(test, feature = "test-seams"))]
    impl Drop for QueuedMark {
        fn drop(&mut self) {
            let me = std::thread::current().id();
            let mut queued = QUEUED.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(at) = queued.iter().position(|t| *t == me) {
                queued.swap_remove(at);
            }
        }
    }

    /// Record that the cross-process queue ahead of `key`'s turn holder moved,
    /// so the threads waiting behind it start their stall time again.
    pub(super) fn note_progress(key: &Path) {
        let mut guard = queues();
        if let Some(queue) = guard.as_mut().and_then(|m| m.get_mut(key)) {
            queue.progress += 1;
        }
        drop(guard);
        SERVED.notify_all();
    }

    /// Stage 3: wait (until `deadline`) for the cross-process `flock` on
    /// `lock_path`, which another process holds. Called only by the holder of
    /// `key`'s turn, so at most one caller per key is ever in here.
    ///
    /// `Err(None)` is a timeout; `Err(Some(e))` the helper's own failure.
    pub(super) fn await_flock(
        key: &Path,
        lock_path: &Path,
        deadline: Instant,
    ) -> Result<super::HeldFlock, Option<std::io::Error>> {
        let mut guard = queues();
        {
            let queue = guard
                .as_mut()
                .and_then(|m| m.get_mut(key))
                .expect("the turn holder's queue exists");
            queue.waiting = true;
            if !queue.helper_running {
                queue.helper_running = true;
                let (key, lock_path) = (key.to_path_buf(), lock_path.to_path_buf());
                let spawned = std::thread::Builder::new()
                    .name("fuigo-config-lock".to_owned())
                    .spawn(move || helper(&key, &lock_path));
                if let Err(e) = spawned {
                    queue.helper_running = false;
                    queue.waiting = false;
                    return Err(Some(e));
                }
                #[cfg(test)]
                HELPERS_SPAWNED.with(|n| n.set(n.get() + 1));
            }
        }
        loop {
            let queue = guard
                .as_mut()
                .and_then(|m| m.get_mut(key))
                .expect("the turn holder's queue exists");
            if let Some(file) = queue.granted.take() {
                queue.waiting = false;
                return Ok(file);
            }
            if let Some(e) = queue.failed.take() {
                queue.waiting = false;
                return Err(Some(e));
            }
            let now = Instant::now();
            if now >= deadline {
                // The helper stays blocked for whoever asks next; if nobody
                // does, it releases the lock the moment it gets it.
                queue.waiting = false;
                return Err(None);
            }
            guard = SERVED
                .wait_timeout(guard, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// The helper thread: block for the `flock`, then hand it to the waiting
    /// turn holder, or release it at once when nobody is waiting any more.
    fn helper(key: &Path, lock_path: &Path) {
        use fs2::FileExt as _;
        let result = super::open_lock_file(lock_path)
            .and_then(|file| file.lock_exclusive().map(|()| file));
        let mut guard = queues();
        if let Some(map) = guard.as_mut()
            && let Some(queue) = map.get_mut(key)
        {
            queue.helper_running = false;
            match result {
                Ok(file) if queue.waiting => queue.granted = Some(file),
                Err(e) if queue.waiting => queue.failed = Some(e),
                // Too late: dropping the file releases the lock -- here, before
                // the queue can be seen idle (a `_` pattern would not drop it).
                too_late => drop(too_late),
            }
            if queue.idle() {
                map.remove(key);
            }
        }
        drop(guard);
        SERVED.notify_all();
    }

    /// Take a ticket for `key` and wait until it is served. Gives up (`None`)
    /// once neither `serving` nor `progress` has moved for `stall`; the ticket
    /// is then abandoned, so nobody waits on it.
    ///
    /// `moved` is called (with the queues unlocked) each time this waiter sees
    /// the queue ahead of it move, the move that serves it included: a waiter
    /// that holds another lock passes that on to the writers queued behind it
    /// there.
    pub(super) fn wait(key: PathBuf, stall: Duration, moved: Option<&dyn Fn()>) -> Option<Turn> {
        let mut guard = queues();
        let queue = guard.get_or_insert_with(HashMap::new).entry(key.clone()).or_default();
        let ticket = queue.next;
        queue.next += 1;
        let mut seen = (queue.serving, queue.progress);
        let mut deadline = Instant::now() + stall;
        #[cfg(any(test, feature = "test-seams"))]
        let _queued = (queue.serving != ticket).then(QueuedMark::new);
        loop {
            let queue = guard
                .as_mut()
                .and_then(|m| m.get_mut(&key))
                .expect("a queue with an outstanding ticket is never removed");
            if queue.serving == ticket {
                // Reaching the turn after a wait is a move like any other
                // (the cross-process queue may come next, with its own wait).
                let waited = (queue.serving, queue.progress) != seen;
                drop(guard);
                if waited && let Some(moved) = moved {
                    moved();
                }
                return Some(Turn { key });
            }
            let now = Instant::now();
            if (queue.serving, queue.progress) != seen {
                seen = (queue.serving, queue.progress);
                deadline = now + stall;
                if let Some(moved) = moved {
                    // Unlocked for the call (it takes the queues itself), then
                    // everything is looked at again before waiting.
                    drop(guard);
                    moved();
                    guard = queues();
                    continue;
                }
            }
            if now >= deadline {
                queue.abandoned.insert(ticket);
                return None;
            }
            guard = SERVED
                .wait_timeout(guard, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    impl Drop for Turn {
        fn drop(&mut self) {
            let mut guard = queues();
            if let Some(map) = guard.as_mut()
                && let Some(queue) = map.get_mut(&self.key)
            {
                queue.serving += 1;
                while queue.abandoned.remove(&queue.serving) {
                    queue.serving += 1;
                }
                if queue.idle() {
                    map.remove(&self.key);
                }
            }
            drop(guard);
            SERVED.notify_all();
        }
    }

    /// Whether any queue is live for `key` (tests: an idle queue is removed).
    #[cfg(test)]
    pub(super) fn is_tracked(key: &Path) -> bool {
        queues().as_ref().is_some_and(|m| m.contains_key(key))
    }

    /// Tickets handed out for `key` and not yet served (holder included).
    #[cfg(test)]
    pub(super) fn outstanding(key: &Path) -> u64 {
        queues()
            .as_ref()
            .and_then(|m| m.get(key))
            .map_or(0, |q| q.next - q.serving)
    }
}

/// The cross-process FIFO queue in front of each lock file (stage 2 of
/// [`lock_config_for_write_within`], P72).
///
/// A queue is a directory beside the lock file, `.<lock name>.queue`, which
/// exists only while some writer is queued (the last one out removes it). Each
/// waiting or holding process has one ticket in it: a file named
/// `<arrival time, ns, 32 digits>.<pid>.<nonce>.t`, so the names sort in
/// arrival order and are never reused. Its writer holds an exclusive `flock`
/// on the ticket from before the name appears (the file is created under a
/// private name, locked, then hard-linked to its ticket name) until after the
/// name is gone (unlinked, then closed). So a ticket name whose file is NOT
/// locked belongs to a writer that died: it is skipped and removed by
/// whoever finds it. A writer is at the head once no live ticket sorts before
/// its own; it then takes the lock file's `flock` (stage 3).
///
/// The arrival stamp is the system clock's, but never below one more than
/// the largest stamp already in the queue, so a clock stepped back cannot put
/// a newcomer ahead of writers already queued. (Two writers registering at the
/// same instant may sort either way; a writer that scanned the queue, stalled,
/// and only then linked its ticket can sort ahead of one that linked in
/// between -- once.) Mutual exclusion is the `flock`'s, never the queue's.
mod xq {
    use fs2::FileExt as _;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    /// Ticket names end with this; private (pre-link) names start with `.`.
    const TICKET_SUFFIX: &str = ".t";
    const PRIVATE_SUFFIX: &str = ".reg";
    /// A private pre-link file this old whose writer is gone is removed.
    const PRIVATE_STALE_AGE: Duration = Duration::from_secs(60);
    /// Longest pause between two looks at the queue.
    const MAX_PAUSE: Duration = Duration::from_millis(16);

    static NONCE: AtomicU64 = AtomicU64::new(0);

    /// The queue directory for `lock_path`.
    pub(super) fn dir_for(lock_path: &Path) -> PathBuf {
        let name = lock_path
            .file_name()
            .map_or_else(|| "lock".to_owned(), |n| n.to_string_lossy().into_owned());
        lock_path.with_file_name(format!(".{name}.queue"))
    }

    /// One process's place in a queue. Dropping it unlinks the name, then
    /// closes the file (which releases its `flock`), then removes the queue
    /// directory if that left it empty (so an idle lock leaves nothing but
    /// its lock file behind).
    #[derive(Debug)]
    pub(super) struct Ticket {
        path: PathBuf,
        name: String,
        file: Option<super::HeldFlock>,
    }

    impl Drop for Ticket {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
            drop(self.file.take());
            if let Some(dir) = self.path.parent() {
                // Fails while another writer has a ticket in it, as it should.
                let _ = std::fs::remove_dir(dir);
            }
        }
    }

    impl Ticket {
        /// Say that this ticket's writer, which holds the lock, is itself
        /// moving up the queue of another lock it needs: the ticket's
        /// modification time changes, which the writers behind it count as
        /// progress ([`wait_for_head`]). Best-effort.
        pub(super) fn touch(&self) {
            if let Some(file) = &self.file {
                let _ = file.set_modified(SystemTime::now());
            }
        }
    }

    /// Join the back of `lock_path`'s queue.
    pub(super) fn register(lock_path: &Path) -> std::io::Result<Ticket> {
        let dir = dir_for(lock_path);
        sweep_private(&dir);
        let pid = std::process::id();
        let mut last_err = None;
        for _ in 0..16 {
            // (Again on every attempt: an idle queue's directory is removed by
            // the last writer to leave it, possibly just now.)
            std::fs::create_dir_all(&dir)?;
            let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
            let private = dir.join(format!(".{pid}.{nonce}{PRIVATE_SUFFIX}"));
            let file = match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&private)
            {
                Ok(file) => file,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::NotFound
                    ) =>
                {
                    last_err = Some(e);
                    continue;
                }
                Err(e) => {
                    let _ = std::fs::remove_dir(&dir);
                    return Err(e);
                }
            };
            // Locked BEFORE the ticket name exists, so a ticket name is never
            // seen unlocked while its writer is alive.
            // Guarded the moment the lock is taken, so even a panic below unlocks explicitly (a lock that is
            // only closed can outlive the handle while a forked child holds a copy of the descriptor).
            let locked = file.lock_exclusive();
            let file = super::HeldFlock::new(file);
            let linked = locked.and_then(|()| {
                // Behind every ticket already there, whatever the clock says:
                // a clock stepped back must not let a newcomer (or a writer
                // re-queueing) sort ahead of writers already waiting.
                let stamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
                    .max(latest_stamp(&dir).map_or(0, |s| s.saturating_add(1)));
                let name = format!("{stamp:032}.{pid:010}.{nonce:020}{TICKET_SUFFIX}");
                let path = dir.join(&name);
                std::fs::hard_link(&private, &path).map(|()| (name, path))
            });
            let _ = std::fs::remove_file(&private);
            match linked {
                Ok((name, path)) => {
                    trace("Q", lock_path);
                    return Ok(Ticket {
                        path,
                        name,
                        file: Some(file),
                    });
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::NotFound
                    ) =>
                {
                    last_err = Some(e);
                }
                Err(e) => {
                    // Closed first: on Windows the private file is only gone
                    // once its last handle is, and the directory with it.
                    drop(file);
                    let _ = std::fs::remove_dir(&dir);
                    return Err(e);
                }
            }
        }
        // Leave no idle queue directory behind (a filesystem without hard
        // links fails here every time).
        let _ = std::fs::remove_dir(&dir);
        Err(last_err.unwrap_or_else(|| std::io::Error::other("no free lock-queue ticket name")))
    }

    /// The largest arrival stamp among the tickets in `dir` (live or not).
    fn latest_stamp(dir: &Path) -> Option<u128> {
        std::fs::read_dir(dir)
            .ok()?
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|name| name.ends_with(TICKET_SUFFIX) && !name.starts_with('.'))
            .filter_map(|name| name.split('.').next()?.parse::<u128>().ok())
            .max()
    }

    /// Wait until `ticket` is at the head of its queue: `true`, or `false`
    /// once no ticket ahead of it has gone away, or been touched by its
    /// writer ([`Ticket::touch`]), for `stall`. `progressed` is called
    /// whenever one has.
    pub(super) fn wait_for_head(
        ticket: &Ticket,
        stall: Duration,
        mut progressed: impl FnMut(),
    ) -> bool {
        let Some(dir) = ticket.path.parent() else {
            return true;
        };
        // Each live ticket ahead, with its modification time.
        let mut seen: Vec<(String, Option<SystemTime>)> = Vec::new();
        let mut deadline = Instant::now() + stall;
        let mut pause = Duration::from_millis(1);
        loop {
            let ahead = live_ahead(dir, &ticket.name);
            if ahead.is_empty() {
                // The last one ahead leaving is progress too: threads of this
                // process queued behind this one start their wait again.
                if !seen.is_empty() {
                    progressed();
                }
                return true;
            }
            let now = Instant::now();
            // Gone, or touched: either way its entry is not what it was.
            if seen.iter().any(|was| !ahead.contains(was)) {
                deadline = now + stall;
                pause = Duration::from_millis(1);
                progressed();
            }
            seen = ahead;
            if now >= deadline {
                return false;
            }
            std::thread::sleep(pause.min(deadline - now));
            pause = (pause * 2).min(MAX_PAUSE);
        }
    }

    /// The live tickets in `dir` that sort before `mine`, sorted, each with
    /// its modification time (`None` when it cannot be read: the ticket is
    /// on its way out). Dead ones (unlocked) are removed on the way.
    fn live_ahead(dir: &Path, mine: &str) -> Vec<(String, Option<SystemTime>)> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut ahead: Vec<(String, Option<SystemTime>)> = entries
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|name| {
                name.ends_with(TICKET_SUFFIX) && !name.starts_with('.') && name.as_str() < mine
            })
            .filter(|name| is_live(&dir.join(name)))
            .map(|name| {
                let touched = std::fs::metadata(dir.join(&name))
                    .and_then(|md| md.modified())
                    .ok();
                (name, touched)
            })
            .collect();
        ahead.sort();
        ahead
    }

    /// Whether the ticket at `path` belongs to a writer that is still there.
    /// One whose `flock` can be taken is a dead writer's, and is removed (its
    /// name is unique, so this never removes a newer ticket).
    pub(super) fn is_live(path: &Path) -> bool {
        let Ok(file) = std::fs::File::open(path) else {
            // Gone (or, on Windows, being deleted).
            return false;
        };
        match fs2::FileExt::try_lock_shared(&file) {
            Ok(()) => {
                // Unlocked explicitly on every path, not only by the close.
                let _probe = super::HeldFlock::new(file);
                let _ = std::fs::remove_file(path);
                false
            }
            Err(e) => super::lock_is_contended(&e),
        }
    }

    /// Remove private pre-link files left by writers that died between
    /// creating one and linking it (old, and unlocked).
    fn sweep_private(dir: &Path) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !(name.starts_with('.') && name.ends_with(PRIVATE_SUFFIX)) {
                continue;
            }
            let old = entry
                .metadata()
                .and_then(|md| md.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age >= PRIVATE_STALE_AGE);
            if old
                && let Ok(file) = std::fs::File::open(entry.path())
                && file.try_lock_exclusive().is_ok()
            {
                // Unlocked explicitly on every path, not only by the close.
                let _probe = super::HeldFlock::new(file);
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    /// Test seam: when `<lock file>.trace` exists, append `Q <pid>` to it when
    /// this process joins the lock's queue and `G <pid>` when it is granted
    /// the lock, one `O_APPEND` write each (the contention test reads the order).
    #[cfg(any(test, feature = "test-seams"))]
    fn trace(what: &str, lock_path: &Path) {
        use std::io::Write as _;
        let mut path = lock_path.as_os_str().to_owned();
        path.push(".trace");
        // Only an existing trace file is written to (never created).
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(path) {
            let _ = f.write_all(format!("{what} {}\n", std::process::id()).as_bytes());
        }
    }

    #[cfg(not(any(test, feature = "test-seams")))]
    fn trace(_what: &str, _lock_path: &Path) {}

    /// [`trace`] of a grant (stage 3 done).
    pub(super) fn trace_granted(lock_path: &Path) {
        trace("G", lock_path);
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

/// What one pass of an [`edit_locked`] edit decided.
#[derive(Debug)]
pub enum Edit<T> {
    /// Replace the file with `contents`, then return `value`.
    Replace { contents: Vec<u8>, value: T },
    /// Leave the file alone and return the value.
    Keep(T),
}

/// Why [`edit_locked`] failed.
#[derive(Debug)]
pub enum EditError<E> {
    /// The write lock could not be taken (`TimedOut` included).
    Lock(std::io::Error),
    /// Staging or committing the replacement failed. The file is unchanged.
    Write(std::io::Error),
    /// The edit itself refused (its own error).
    Edit(E),
}

impl<E: std::fmt::Display> std::fmt::Display for EditError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lock(e) => write!(f, "could not lock the file: {e}"),
            Self::Write(e) => write!(f, "could not write the file: {e}"),
            Self::Edit(e) => e.fmt(f),
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for EditError<E> {}

impl From<EditError<std::io::Error>> for std::io::Error {
    fn from(e: EditError<std::io::Error>) -> Self {
        match e {
            EditError::Lock(e) | EditError::Write(e) | EditError::Edit(e) => e,
        }
    }
}

/// Optimistic passes [`edit_locked`] makes before it falls back to doing the
/// whole cycle under the lock.
///
/// None on Windows: std exposes no change time there, so a DACL tightened on
/// the original between the stage and the lock would not show in the
/// snapshot, and the staged temp (carrying the old DACL) would be published.
/// There the whole cycle, fsync included, runs under the (fair) lock.
fn optimistic_passes() -> usize {
    if cfg!(windows) { 0 } else { 2 }
}

/// Read-modify-write `path` under [`lock_config_for_write`], with the slow part
/// of the write (filling and `fsync`ing the temp file) done OUTSIDE the lock.
///
/// - `edit` is given the file's current bytes ([`Current`]) and decides:
///   replace it with new contents, or keep it. It must decide from those bytes,
///   not by reading the file again. It may be called more than once, so it
///   must not have side effects.
/// - `stage` turns the new contents into a finished, synced temp file beside
///   the target (e.g. [`stage_atomically_from_existing`]); it carries the
///   writer's own policy for mode, symlinks and ACLs. If it took metadata from
///   the existing file it must record which ([`StagedReplacement::from_original`]):
///   an optimistic commit then requires that to be the file `edit` was given.
///   Better still, it defers that metadata to the commit
///   ([`StagedReplacement::finish_with`]), as `write_through` does on unix.
///
/// # How a pass works
///
/// 1. Snapshot the file (bytes and inode identity, read through one handle)
///    and run `edit` on those bytes.
/// 2. `stage` the new contents, with no lock held: the `fsync` happens here.
/// 3. Take the lock, snapshot once more, and only if the file is still exactly
///    the version `edit` was given (and the path still has no symlink), `commit`: `rename` and directory `fsync`, the only
///    work done under the lock. Otherwise discard the temp and start again.
///
/// After [`optimistic_passes`] such passes have been overtaken, the next pass
/// runs `edit`, `stage` and `commit` all under the lock, as a plain locked
/// read-modify-write would, so a writer always makes progress under sustained
/// contention (and the lock's FIFO turn bounds how long it waits for that).
/// The same locked pass is used at once when the file cannot be snapshotted
/// (unreadable): `edit` then meets the read error itself, under the lock, as
/// before; and when the path runs through a symlink anywhere (see
/// `path_is_link_free`), or on Windows (see `optimistic_passes`).
///
/// A [`Edit::Keep`] decided on a stable snapshot returns without the lock: the
/// file was that version at some instant, which is all a locked read promised.
///
/// The parent directory is created (as [`lock_config_for_write`] does) only
/// once there is something to write.
///
/// # Errors
///
/// [`EditError::Edit`] for `edit`'s own error, [`EditError::Lock`] when the
/// lock cannot be taken, [`EditError::Write`] when staging or the rename fails.
pub fn edit_locked<T, E>(
    path: &Path,
    stage: impl FnMut(&[u8]) -> std::io::Result<StagedReplacement>,
    edit: impl FnMut(Current<'_>) -> Result<Edit<T>, E>,
) -> Result<T, EditError<E>> {
    edit_locked_with_lock(path, &config_lock_path(path), stage, edit)
}

/// [`edit_locked`] serialized on the lock file `lock_path` rather than on the
/// one beside `path` ([`config_lock_path`]); see [`lock_file_for_write`]. Every
/// writer of one file must use the same lock file.
///
/// # Errors
///
/// As [`edit_locked`].
pub fn edit_locked_with_lock<T, E>(
    path: &Path,
    lock_path: &Path,
    stage: impl FnMut(&[u8]) -> std::io::Result<StagedReplacement>,
    edit: impl FnMut(Current<'_>) -> Result<Edit<T>, E>,
) -> Result<T, EditError<E>> {
    edit_locked_for(path, LockFor::Path(lock_path), stage, edit)
}

fn edit_locked_for<T, E>(
    path: &Path,
    lock: LockFor<'_>,
    mut stage: impl FnMut(&[u8]) -> std::io::Result<StagedReplacement>,
    mut edit: impl FnMut(Current<'_>) -> Result<Edit<T>, E>,
) -> Result<T, EditError<E>> {
    sweep_stale_temps_once(path);
    for _ in 0..optimistic_passes() {
        // Optimism only while the path has no symlink anywhere along it,
        // checked on every pass and again under the lock: through a link, the
        // name could resolve elsewhere between the read and the rename.
        if !path_is_link_free(path) {
            break;
        }
        // A file caught mid-write is a change (try again); one that cannot be
        // read at all goes to the locked pass, where `edit` meets the error.
        let before = match FileSnapshot::take(path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        // `edit` decides from exactly the bytes the snapshot read (one handle),
        // never from a second read that could see another version.
        #[cfg(test)]
        test_hooks::after_snapshot(path);
        let decided = edit(Ok(before.bytes()));
        let (contents, value) = match decided {
            Err(e) => return Err(EditError::Edit(e)),
            Ok(Edit::Keep(value)) => return Ok(value),
            Ok(Edit::Replace { contents, value }) => (contents, value),
        };
        ensure_parent(path).map_err(EditError::Write)?;
        let staged = stage(&contents).map_err(EditError::Write)?;
        #[cfg(test)]
        test_hooks::after_stage(path);
        if commit_if_unchanged_inner(path, lock, &before, staged)? {
            return Ok(value);
        }
        // Overtaken between the read and the lock: discard and re-read.
    }
    locked_pass(path, lock, &mut stage, &mut edit)
}

/// The commit step of [`edit_locked_with_lock`]: take the lock and rename
/// `staged` over `path` only if `path` is still exactly `before`. `Ok(false)`
/// when it was overtaken (the temp is then removed).
fn commit_if_unchanged_inner<E>(
    path: &Path,
    lock: LockFor<'_>,
    before: &FileSnapshot,
    mut staged: StagedReplacement,
) -> Result<bool, EditError<E>> {
    let lock = lock.take(path).map_err(EditError::Lock)?;
    // Commit only a temp staged for THIS path from THIS file: staging ran
    // unlocked, so it must not have seen a different file at the path
    // (one swapped in and back out while it ran).
    if staged.target() == path
        && staged.source().is_none_or(|seen| seen == before.key())
        && path_is_link_free(path)
        && FileSnapshot::take(path).is_ok_and(|now| &now == before)
    {
        lock.land_on_the_entry(&mut staged)
            .map_err(EditError::Write)?;
        staged.commit().map_err(EditError::Write)?;
        drop(lock);
        return Ok(true);
    }
    drop(lock);
    drop(staged);
    Ok(false)
}

/// One version of a file, read for an optimistic read-modify-write whose edit
/// cannot run inside [`edit_locked`] (P72: the shell's settings save, whose
/// edit borrows from an async caller and so cannot move to a blocking
/// thread). The caller decides from [`Self::current`], stages the result
/// itself, and commits it with [`commit_if_unchanged`]; when that reports the
/// file was overtaken, it takes a new snapshot and decides again. After a few
/// such rounds it should fall back to a fully locked cycle, as
/// [`edit_locked`] does.
#[derive(Debug)]
pub struct Snapshot(FileSnapshot);

impl Snapshot {
    /// Read `path` for an optimistic pass. `Ok(None)` when no optimistic pass
    /// is possible -- the path runs through a symlink, or on Windows (see
    /// `optimistic_passes`) -- and the caller must use a locked cycle;
    /// `Err` for a file that cannot be read (or was written while read).
    ///
    /// # Errors
    ///
    /// As described.
    pub fn take(path: &Path) -> std::io::Result<Option<Self>> {
        if optimistic_passes() == 0 || !path_is_link_free(path) {
            return Ok(None);
        }
        FileSnapshot::take(path).map(|s| Some(Self(s)))
    }

    /// The bytes read (`None`: the file does not exist), as [`edit_locked`]'s
    /// edit is given them.
    pub fn current(&self) -> Current<'_> {
        Ok(self.0.bytes())
    }
}

/// [`edit_locked_with_lock`]'s commit, for a [`Snapshot`] the caller decided
/// from: take the lock `lock_path`, and rename `staged` over `path` only if
/// `path` is still exactly that version (same bytes, inode, mode, times, link
/// chain) and `staged` was made for it. `Ok(true)`: committed. `Ok(false)`:
/// overtaken -- nothing was written and the temp is removed.
///
/// # Errors
///
/// [`EditError::Lock`] when the lock cannot be taken, [`EditError::Write`]
/// when the rename fails (the file is then unchanged).
pub fn commit_if_unchanged(
    path: &Path,
    lock_path: &Path,
    before: &Snapshot,
    staged: StagedReplacement,
) -> Result<bool, EditError<std::convert::Infallible>> {
    commit_if_unchanged_inner(path, LockFor::Path(lock_path), &before.0, staged)
}

/// One read-modify-write of `path` done wholly under the lock `lock_path`:
/// read, `edit` (called exactly once), `stage` and commit. The fsync of the
/// temp happens under the lock here, as in every pre-P49 writer.
///
/// For a writer whose edit cannot be repeated or must see the file through its
/// own loader (the shell's settings save): it gets the same lock, the same
/// atomic commit and the same temp cleanup as [`edit_locked`], without the
/// optimistic passes. A file the edit needs read differently can be read by
/// the edit itself: the lock is held while it runs.
///
/// # Errors
///
/// As [`edit_locked`].
pub fn edit_under_lock<T, E>(
    path: &Path,
    lock_path: &Path,
    stage: impl FnOnce(&[u8]) -> std::io::Result<StagedReplacement>,
    edit: impl FnOnce(Current<'_>) -> Result<Edit<T>, E>,
) -> Result<T, EditError<E>> {
    sweep_stale_temps_once(path);
    locked_pass(path, LockFor::Path(lock_path), stage, edit)
}

/// The locked pass shared by [`edit_locked_with_lock`] and [`edit_under_lock`].
fn locked_pass<T, E>(
    path: &Path,
    lock: LockFor<'_>,
    stage: impl FnOnce(&[u8]) -> std::io::Result<StagedReplacement>,
    edit: impl FnOnce(Current<'_>) -> Result<Edit<T>, E>,
) -> Result<T, EditError<E>> {
    let lock = lock.take(path).map_err(EditError::Lock)?;
    let current = match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    };
    let current: Current<'_> = match &current {
        Ok(bytes) => Ok(bytes.as_deref()),
        Err(e) => Err(e),
    };
    match edit(current).map_err(EditError::Edit)? {
        Edit::Keep(value) => Ok(value),
        Edit::Replace { contents, value } => {
            ensure_parent(path).map_err(EditError::Write)?;
            let mut staged = stage(&contents).map_err(EditError::Write)?;
            // (Dropping `staged` on a refusal removes the temp.)
            lock.check_still_covers(path, &staged)
                .map_err(EditError::Lock)?;
            lock.land_on_the_entry(&mut staged)
                .map_err(EditError::Write)?;
            staged.commit().map_err(EditError::Write)?;
            Ok(value)
        }
    }
}

/// Create `path`'s parent directory (as [`lock_config_for_write`] does), once
/// there is something to write.
fn ensure_parent(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => std::fs::create_dir_all(p),
        _ => Ok(()),
    }
}

/// How old a leftover temp must be before [`sweep_stale_temps_once`] removes
/// it. A live writer holds its temp for the length of one write (staging, at
/// most [`CONFIG_LOCK_MAX_WAIT`] waiting for the lock, the rename); an hour is
/// far beyond that. The age is only the second guard: a temp whose writer
/// process is still running is never removed, however old.
pub const STALE_TEMP_AGE: Duration = Duration::from_secs(60 * 60);

/// [`sweep_stale_temps`] for `path` with [`STALE_TEMP_AGE`], at most once per
/// path per process (the first edit of each file), best-effort. [`edit_locked`]
/// and [`edit_under_lock`] call it; a writer that commits through the lower
/// level pieces calls it itself.
pub fn sweep_stale_temps_once(path: &Path) {
    use std::collections::HashSet;
    use std::sync::Mutex;
    static SWEPT: Mutex<Option<HashSet<PathBuf>>> = Mutex::new(None);
    {
        let mut swept = SWEPT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !swept
            .get_or_insert_with(HashSet::new)
            .insert(path.to_path_buf())
        {
            return;
        }
    }
    let _ = sweep_stale_temps(path, STALE_TEMP_AGE);
    // A write-through writer stages beside the file a symlink resolves to.
    if let Ok(real) = dunce::canonicalize(path)
        && real != path
    {
        let _ = sweep_stale_temps(&real, STALE_TEMP_AGE);
    }
}

/// Remove the temps a crashed writer left beside `path`, and nothing else.
///
/// A directory entry is removed only if ALL of these hold:
///
/// - its name is one of OUR temp names for `path`'s file name (see
///   [`temp_owner_pid`]): [`stage_atomically`]'s `<name>.<pid>.<nonce>.tmp`,
///   `write_through`'s `.<name>.<pid>.<nonce>.tmp`, or one of the two names
///   the writers replaced in P61 used (`<name>.tmp.<pid>.<nanos>`,
///   `<name>.dashboard.tmp.<pid>`) -- `<name>` cut to 64 bytes as the writers
///   cut it -- or `write_through`'s macOS staging directory
///   `.<name>.<pid>.<nonce>.staging`, of which only our temps inside are
///   removed, then the directory if that leaves it empty;
/// - it is a regular file (not a link, not a directory) -- for a staging
///   directory: a directory, not a link;
/// - it was last modified at least `min_age` ago;
/// - the pid in its name is not this process, and no process with that pid
///   exists (`kill(pid, 0)` says `ESRCH`). A live writer's temp is never
///   removed, however old; a reused pid only keeps a stale temp longer.
///
/// Unix only: elsewhere nothing is removed (no liveness check is available
/// through std, and the age alone cannot tell a stalled writer from a dead one).
///
/// Returns the paths removed.
pub fn sweep_stale_temps(path: &Path, min_age: Duration) -> Vec<PathBuf> {
    #[cfg_attr(not(unix), allow(unused_mut))] // nothing is swept off unix
    let mut removed = Vec::new();
    #[cfg(unix)]
    {
        let Some(name) = path.file_name() else {
            return removed;
        };
        let name = name.to_string_lossy();
        let dir = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let Ok(entries) = std::fs::read_dir(dir) else {
            return removed;
        };
        let now = std::time::SystemTime::now();
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let Some(entry_name) = file_name.to_str() else {
                continue;
            };
            if let Some(pid) = staging_owner_pid(entry_name, &name) {
                // A macOS write-through staging directory a crashed writer
                // left: its own temps go, then the directory if that empties it.
                let staging = dir.join(entry_name);
                let Ok(md) = std::fs::symlink_metadata(&staging) else {
                    continue;
                };
                let old_enough = md
                    .modified()
                    .ok()
                    .and_then(|m| now.duration_since(m).ok())
                    .is_some_and(|age| age >= min_age);
                if md.file_type().is_dir() && old_enough && writer_is_gone(pid) {
                    if let Ok(inner) = std::fs::read_dir(&staging) {
                        for inner in inner.flatten() {
                            let inner_name = inner.file_name();
                            // Only that same dead writer's temps, each old
                            // enough itself (writing a file does not touch
                            // its directory's mtime).
                            let is_ours = inner_name
                                .to_str()
                                .and_then(|n| temp_owner_pid(n, &name))
                                == Some(pid);
                            let inner_path = staging.join(&inner_name);
                            if is_ours
                                && std::fs::symlink_metadata(&inner_path).is_ok_and(|m| {
                                    m.file_type().is_file()
                                        && m.modified()
                                            .ok()
                                            .and_then(|t| now.duration_since(t).ok())
                                            .is_some_and(|age| age >= min_age)
                                })
                                && std::fs::remove_file(&inner_path).is_ok()
                            {
                                removed.push(inner_path);
                            }
                        }
                    }
                    if std::fs::remove_dir(&staging).is_ok() {
                        removed.push(staging);
                    }
                }
                continue;
            }
            let Some(pid) = temp_owner_pid(entry_name, &name) else {
                continue;
            };
            let candidate = dir.join(entry_name);
            let Ok(md) = std::fs::symlink_metadata(&candidate) else {
                continue;
            };
            let old_enough = md
                .modified()
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .is_some_and(|age| age >= min_age);
            if !md.file_type().is_file() || !old_enough || !writer_is_gone(pid) {
                continue;
            }
            if std::fs::remove_file(&candidate).is_ok() {
                removed.push(candidate);
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (path, min_age);
    removed
}

/// The writer pid in `entry` when it is one of our temp names for the file
/// `name` (see [`sweep_stale_temps`]); `None` for anything else.
#[cfg_attr(not(unix), allow(dead_code))]
fn temp_owner_pid(entry: &str, name: &str) -> Option<u32> {
    fn digits(s: &str) -> bool {
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
    }
    fn pid_dot_number(rest: &str) -> Option<u32> {
        let (pid, n) = rest.split_once('.')?;
        if digits(pid) && digits(n) {
            pid.parse().ok()
        } else {
            None
        }
    }
    let mut end = name.len().min(64);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    let short = &name[..end];
    for prefix in [format!("{short}."), format!(".{short}.")] {
        if let Some(pid) = entry
            .strip_prefix(prefix.as_str())
            .and_then(|rest| rest.strip_suffix(".tmp"))
            .and_then(pid_dot_number)
        {
            return Some(pid);
        }
    }
    if let Some(pid) = entry
        .strip_prefix(format!("{name}.tmp.").as_str())
        .and_then(pid_dot_number)
    {
        return Some(pid);
    }
    entry
        .strip_prefix(format!("{name}.dashboard.tmp.").as_str())
        .filter(|pid| digits(pid))
        .and_then(|pid| pid.parse().ok())
}

/// The writer pid in `entry` when it is `write_through`'s macOS staging
/// directory name for the file `name`: `.<name>.<pid>.<nonce>.staging`.
#[cfg_attr(not(unix), allow(dead_code))]
fn staging_owner_pid(entry: &str, name: &str) -> Option<u32> {
    let mut end = name.len().min(64);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    let rest = entry
        .strip_prefix(format!(".{}.", &name[..end]).as_str())?
        .strip_suffix(".staging")?;
    let (pid, nonce) = rest.split_once('.')?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if digits(pid) && digits(nonce) {
        pid.parse().ok()
    } else {
        None
    }
}

/// Whether the process `pid` is certainly gone: not this process, a real pid,
/// and `kill(pid, 0)` fails with `ESRCH`. Anything else (alive, someone
/// else's -- `EPERM` --, or unknowable) counts as possibly alive.
#[cfg(unix)]
fn writer_is_gone(pid: u32) -> bool {
    if pid == std::process::id() {
        return false;
    }
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    // SAFETY: signal 0 only checks for the process's existence.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return false;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

/// What [`edit_locked`] hands its `edit`: the file's bytes (`None` when it does
/// not exist), or the error reading it gave.
pub type Current<'a> = Result<Option<&'a [u8]>, &'a std::io::Error>;

/// Whether no component of `path` (made absolute), nor `path` itself, is a
/// symlink. Missing trailing components count as link-free (they are created as
/// directories by the writer). An unreadable component is not link-free.
fn path_is_link_free(path: &Path) -> bool {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path),
            Err(_) => return false,
        }
    };
    let mut prefix = PathBuf::new();
    for component in absolute.components() {
        prefix.push(component);
        match std::fs::symlink_metadata(&prefix) {
            Ok(md) if md.file_type().is_symlink() => return false,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
            Err(_) => return false,
        }
    }
    true
}

/// What [`edit_locked`] compares to tell whether a file changed: its bytes and
/// the identity of the inode they were read from, both taken through one
/// handle. A replacement (new inode), an in-place write (size, mtime, ctime), a
/// `chmod`/`chown`/ACL change (ctime, mode) and a retargeted symlink all show.
#[derive(Debug, PartialEq, Eq)]
struct FileSnapshot {
    /// `None` when the file does not exist.
    contents: Option<(Vec<u8>, FileIdentity)>,
    /// The path's own (not followed) identity, then that of every symlink the
    /// path resolves through, each with its link text, so a swapped or
    /// retargeted link anywhere in the chain shows -- even when both old and
    /// new destinations are missing, or hold identical bytes.
    links: Vec<(Option<FileIdentity>, Option<PathBuf>)>,
}

/// Symlink hops a snapshot follows (Linux's `MAXSYMLINKS`).
const SNAPSHOT_MAX_HOPS: usize = 40;

/// The identity and link text of `path` and of each symlink it resolves
/// through, stopping at the first non-link (or missing) entry.
fn link_chain(path: &Path) -> std::io::Result<Vec<(Option<FileIdentity>, Option<PathBuf>)>> {
    let mut chain = Vec::new();
    let mut current = path.to_path_buf();
    for _ in 0..=SNAPSHOT_MAX_HOPS {
        match std::fs::symlink_metadata(&current) {
            Ok(md) if md.file_type().is_symlink() => {
                let target = std::fs::read_link(&current)?;
                chain.push((Some(FileIdentity::of(&md)), Some(target.clone())));
                current = if target.is_absolute() {
                    target
                } else {
                    current
                        .parent()
                        .map_or_else(|| target.clone(), |parent| parent.join(&target))
                };
            }
            Ok(md) => {
                chain.push((Some(FileIdentity::of(&md)), None));
                return Ok(chain);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                chain.push((None, None));
                return Ok(chain);
            }
            Err(e) => return Err(e),
        }
    }
    // A loop: still comparable, the chain itself is recorded.
    Ok(chain)
}

#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

#[cfg(not(unix))]
#[derive(Debug, PartialEq, Eq)]
struct FileIdentity {
    size: u64,
    readonly: bool,
    modified: Option<std::time::SystemTime>,
}

impl FileIdentity {
    #[cfg(unix)]
    fn of(md: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            dev: md.dev(),
            ino: md.ino(),
            size: md.size(),
            mode: md.mode(),
            uid: md.uid(),
            gid: md.gid(),
            mtime: (md.mtime(), md.mtime_nsec()),
            ctime: (md.ctime(), md.ctime_nsec()),
        }
    }

    #[cfg(not(unix))]
    fn of(md: &std::fs::Metadata) -> Self {
        Self {
            size: md.len(),
            readonly: md.permissions().readonly(),
            modified: md.modified().ok(),
        }
    }
}

impl FileSnapshot {
    /// The bytes read, `None` for a missing file.
    fn bytes(&self) -> Option<&[u8]> {
        self.contents.as_ref().map(|(b, _)| b.as_slice())
    }

    /// The key of the file read, `None` for a missing file (and off unix).
    fn key(&self) -> Option<FileKey> {
        #[cfg(unix)]
        {
            self.contents.as_ref().map(|(_, id)| FileKey {
                dev: id.dev,
                ino: id.ino,
            })
        }
        #[cfg(not(unix))]
        {
            None
        }
    }

    fn take(path: &Path) -> std::io::Result<Self> {
        use std::io::Read as _;
        let links = link_chain(path)?;
        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    contents: None,
                    links,
                });
            }
            Err(e) => return Err(e),
        };
        let first = FileIdentity::of(&file.metadata()?);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let second = FileIdentity::of(&file.metadata()?);
        if first != second {
            // Written while being read: report it as a change, never as a version.
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "file changed while it was read",
            ));
        }
        // A link retargeted while the file was read shows as a change.
        if link_chain(path)? != links {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "a link changed while the file was read",
            ));
        }
        Ok(Self {
            contents: Some((bytes, second)),
            links,
        })
    }
}

/// Test-only seams inside [`edit_locked`].
#[cfg(test)]
pub(crate) mod test_hooks {
    use std::path::Path;

    type Hook = Option<Box<dyn FnMut(&Path)>>;

    thread_local! {
        static AFTER_STAGE: std::cell::RefCell<Hook> = const { std::cell::RefCell::new(None) };
    }

    /// Run `hook` on this thread after each optimistic stage, before the lock.
    pub(crate) fn set_after_stage(hook: Hook) {
        AFTER_STAGE.with(|h| *h.borrow_mut() = hook);
    }

    thread_local! {
        static AFTER_SNAPSHOT: std::cell::RefCell<Hook> = const { std::cell::RefCell::new(None) };
    }

    /// Run `hook` on this thread right after each optimistic snapshot, before `edit`.
    pub(crate) fn set_after_snapshot(hook: Hook) {
        AFTER_SNAPSHOT.with(|h| *h.borrow_mut() = hook);
    }

    pub(super) fn after_snapshot(path: &Path) {
        AFTER_SNAPSHOT.with(|h| {
            if let Some(hook) = h.borrow_mut().as_mut() {
                hook(path);
            }
        });
    }

    pub(super) fn after_stage(path: &Path) {
        AFTER_STAGE.with(|h| {
            if let Some(hook) = h.borrow_mut().as_mut() {
                hook(path);
            }
        });
    }
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

    // ---- P49: fair lock ----

    fn spin_until(what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !cond() {
            assert!(std::time::Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::yield_now();
        }
    }

    fn key_of(config: &Path) -> PathBuf {
        turn::key_for(&config_lock_path(config))
    }

    /// The flake behind R033 §0.4 / R037: a holder that releases and at once
    /// re-takes the lock starved a polling waiter past the 2 s give-up. Queued
    /// in FIFO order, the waiter gets the very next turn.
    #[test]
    fn a_back_to_back_holder_cannot_starve_a_waiter() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let holding = std::sync::Arc::new(std::sync::Barrier::new(2));
        let hog = {
            let (config, stop, holding) = (config.clone(), stop.clone(), holding.clone());
            std::thread::spawn(move || {
                let mut first = true;
                let mut holds = 0u32;
                // Bounded so a broken lock cannot hang the test binary.
                while !stop.load(std::sync::atomic::Ordering::SeqCst) && holds < 400 {
                    let lock = lock_config_for_write_within(&config, Duration::from_secs(10))
                        .expect("hog lock");
                    if first {
                        holding.wait();
                        first = false;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                    drop(lock); // ...and straight back in, no gap
                    holds += 1;
                }
            })
        };
        holding.wait();
        let started = std::time::Instant::now();
        let got = lock_config_for_write(&config);
        let waited = started.elapsed();
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let got = got.expect("a waiter behind a back-to-back holder must get its turn");
        assert!(
            waited < CONFIG_LOCK_MAX_WAIT,
            "waited {waited:?}; the waiter should get the next turn"
        );
        drop(got);
        hog.join().unwrap();
    }

    /// Waiters are served in the order they queued.
    #[test]
    fn waiters_are_served_in_arrival_order() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let key = key_of(&config);
        let holder = lock_config_for_write(&config).unwrap();
        let order = std::sync::Arc::new(Mutex::new(Vec::new()));
        let mut waiters = Vec::new();
        for i in 0..5u64 {
            let (config, order) = (config.clone(), order.clone());
            waiters.push(std::thread::spawn(move || {
                let lock = lock_config_for_write_within(&config, Duration::from_secs(20))
                    .expect("queued waiter");
                order.lock().unwrap().push(i);
                drop(lock);
            }));
            // The holder's ticket plus i + 1 waiters.
            spin_until("waiter to queue", || turn::outstanding(&key) == i + 2);
        }
        drop(holder);
        for w in waiters {
            w.join().unwrap();
        }
        assert_eq!(*order.lock().unwrap(), vec![0, 1, 2, 3, 4]);
        assert!(!turn::is_tracked(&key), "an idle queue must be removed");
    }

    /// A waiter that gives up must not leave a ticket everyone behind it waits on.
    #[test]
    fn an_abandoned_ticket_does_not_block_the_next_waiter() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let holder = lock_config_for_write(&config).unwrap();
        let err = std::thread::scope(|s| {
            s.spawn(|| lock_config_for_write_within(&config, Duration::from_millis(50)))
                .join()
                .unwrap()
                .expect_err("held lock")
        });
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
        drop(holder);
        let next = lock_config_for_write_within(&config, Duration::from_millis(500))
            .expect("the abandoned ticket must be skipped");
        drop(next);
        assert!(!turn::is_tracked(&key_of(&config)));
    }

    /// Another process's `flock` (here: a separately opened handle that never
    /// went through this process's queue) is waited for, and taken once freed.
    #[test]
    fn a_lock_held_by_another_process_is_taken_when_released() {
        use fs2::FileExt;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let foreign = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(config_lock_path(&config))
            .unwrap();
        foreign.lock_exclusive().unwrap();
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            FileExt::unlock(&foreign).unwrap();
            foreign
        });
        let started = std::time::Instant::now();
        let lock = lock_config_for_write_within(&config, Duration::from_secs(20))
            .expect("taken once the other holder lets go");
        assert!(started.elapsed() >= Duration::from_millis(250));
        let foreign = releaser.join().unwrap();
        assert!(
            foreign.try_lock_exclusive().is_err(),
            "we must really hold the flock now"
        );
        drop(lock);
    }

    /// Waits that time out against another process's lock share ONE blocked
    /// helper thread (no pile-up against a wedged holder), and the helper's
    /// late grant is released at once when nobody is waiting for it.
    #[test]
    fn timed_out_cross_process_waits_share_one_helper_and_release_a_late_grant() {
        use fs2::FileExt;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let key = key_of(&config);
        let foreign = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(config_lock_path(&config))
            .unwrap();
        foreign.lock_exclusive().unwrap();
        let spawned_before = turn::HELPERS_SPAWNED.with(std::cell::Cell::get);
        for _ in 0..20 {
            let err = lock_config_for_write_within(&config, Duration::from_millis(10))
                .expect_err("held by the other process");
            assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
        }
        assert_eq!(
            turn::HELPERS_SPAWNED.with(std::cell::Cell::get) - spawned_before,
            1,
            "20 timed-out waits must share one helper thread"
        );
        FileExt::unlock(&foreign).unwrap();
        // The helper now gets the flock, finds nobody waiting, drops it, and
        // the idle queue is removed: wait for exactly that.
        spin_until("helper to finish", || !turn::is_tracked(&key));
        foreign
            .try_lock_exclusive()
            .expect("the helper's late grant must have been released");
        FileExt::unlock(&foreign).unwrap();
        drop(lock_config_for_write_within(&config, Duration::from_millis(500)).unwrap());
    }

    /// A late-granted `flock` is released even when another thread forks a
    /// child at that moment (the child holds a copy of the descriptor until it
    /// execs, and a lock that is only closed outlives our handle).
    /// Linux only: the reproduction was made there, and the test forks inside the test process while other tests hold
    /// locks of their own.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_late_grant_is_released_while_another_thread_keeps_forking_children() {
        stress(50);
    }

    /// The same body at 300 iterations, the count of the red proof (about 65 s on the build box): RC checklist.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "RC checklist: run with --ignored"]
    fn a_late_grant_is_released_while_another_thread_keeps_forking_children_300() {
        stress(300);
    }

    /// Stops and joins the forking thread also when an assertion panics.
    #[cfg(target_os = "linux")]
    struct Forker(std::sync::Arc<std::sync::atomic::AtomicBool>, Option<std::thread::JoinHandle<()>>);

    #[cfg(target_os = "linux")]
    impl Drop for Forker {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::Relaxed);
            if let Some(thread) = self.1.take() {
                let _ = thread.join();
            }
        }
    }

    /// Starts a thread that forks `true` in a loop until the returned guard drops.
    #[cfg(target_os = "linux")]
    fn forker() -> Forker {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread = {
            let stop = std::sync::Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = std::process::Command::new("true").status();
                }
            })
        };
        Forker(stop, Some(thread))
    }

    #[cfg(target_os = "linux")]
    fn stress(iterations: usize) {
        let _forker = forker();
        for _ in 0..iterations {
            timed_out_cross_process_waits_share_one_helper_and_release_a_late_grant();
        }
    }

    /// A shared probe lock taken by `is_live` is released while another thread forks children.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_probe_lock_is_released_while_another_thread_keeps_forking_children() {
        use fs2::FileExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ticket");
        let _forker = forker();
        let started = std::time::Instant::now();
        while started.elapsed() < Duration::from_secs(3) {
            std::fs::write(&path, b"").unwrap();
            let watcher = std::fs::File::open(&path).unwrap();
            assert!(!xq::is_live(&path), "nobody holds the ticket");
            watcher
                .try_lock_exclusive()
                .expect("the probe's shared lock must be released, not outlive it in a forked child");
            fs2::FileExt::unlock(&watcher).unwrap();
        }
    }

    // ---- P49: edit_locked ----

    fn other_holds_lock(config: &Path) -> bool {
        use fs2::FileExt;
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(config_lock_path(config))
            .unwrap();
        match f.try_lock_exclusive() {
            Ok(()) => {
                FileExt::unlock(&f).unwrap();
                false
            }
            Err(_) => true,
        }
    }

    /// Append `line` to the file at `path` (missing = empty), through `edit_locked`.
    fn append_line(path: &Path, line: &str) -> Result<(), EditError<std::io::Error>> {
        edit_locked(
            path,
            |bytes| stage_atomically_from_existing(path, bytes, 0o600),
            |current| {
                let mut s = match current {
                    Ok(bytes) => String::from_utf8_lossy(bytes.unwrap_or_default()).into_owned(),
                    Err(e) => return Err(std::io::Error::new(e.kind(), e.to_string())),
                };
                s.push_str(line);
                s.push('\n');
                Ok(Edit::Replace {
                    contents: s.into_bytes(),
                    value: (),
                })
            },
        )
    }

    /// An outside writer: plain read-append-rename (no lock, so it can land
    /// inside another writer's unlocked window).
    fn sneak_in(path: &Path, line: &str) {
        let mut s = std::fs::read_to_string(path).unwrap_or_default();
        s.push_str(line);
        s.push('\n');
        write_atomically(path, &s, None).unwrap();
    }

    fn lines(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// The `fsync`ing stage runs with the lock free; only the commit holds it.
    #[cfg(not(windows))] // no optimistic passes there
    #[test]
    fn the_temp_is_staged_without_the_lock_and_committed_with_it() {
        let dir = tempfile::tempdir().unwrap();
        // Canonical: optimism needs a link-free path (macOS /var is a link).
        let path = dunce::canonicalize(dir.path()).unwrap().join("config.toml");
        std::fs::write(&path, "a\n").unwrap();
        let mut staged_unlocked = None;
        edit_locked(
            &path,
            |bytes| {
                staged_unlocked = Some(!other_holds_lock(&path));
                stage_atomically_from_existing(&path, bytes, 0o600)
            },
            |_| {
                Ok::<_, std::io::Error>(Edit::Replace {
                    contents: b"a\nb\n".to_vec(),
                    value: (),
                })
            },
        )
        .unwrap();
        assert_eq!(staged_unlocked, Some(true), "staging must not hold the lock");
        assert_eq!(lines(&path), ["a", "b"]);
    }

    /// A writer that lands between the stage and the lock is not overwritten:
    /// the stale temp is discarded and the edit re-run on the new version.
    #[cfg(not(windows))] // no optimistic passes there
    #[test]
    fn a_write_between_stage_and_lock_is_not_lost() {
        let dir = tempfile::tempdir().unwrap();
        // Canonical: optimism needs a link-free path (macOS /var is a link).
        let path = dunce::canonicalize(dir.path()).unwrap().join("config.toml");
        std::fs::write(&path, "base\n").unwrap();
        let mut fired = false;
        test_hooks::set_after_stage(Some(Box::new(move |p: &Path| {
            if !fired {
                fired = true;
                sneak_in(p, "theirs");
            }
        })));
        let result = append_line(&path, "mine");
        test_hooks::set_after_stage(None);
        result.unwrap();
        assert_eq!(lines(&path), ["base", "theirs", "mine"]);
        let strays: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(strays.is_empty(), "discarded temps left behind: {strays:?}");
    }

    /// A writer that lands while the edit is reading makes the pass restart.
    #[cfg(not(windows))] // no optimistic passes there
    #[test]
    fn a_write_during_the_edit_restarts_it() {
        let dir = tempfile::tempdir().unwrap();
        // Canonical: optimism needs a link-free path (macOS /var is a link).
        let path = dunce::canonicalize(dir.path()).unwrap().join("config.toml");
        std::fs::write(&path, "base\n").unwrap();
        let mut calls = 0;
        edit_locked(
            &path,
            |bytes| stage_atomically_from_existing(&path, bytes, 0o600),
            |current| {
                calls += 1;
                let mut s = String::from_utf8_lossy(current.unwrap().unwrap()).into_owned();
                if calls == 1 {
                    // Lands after the snapshot this edit was given.
                    sneak_in(&path, "theirs");
                }
                s.push_str("mine\n");
                Ok::<_, std::io::Error>(Edit::Replace {
                    contents: s.into_bytes(),
                    value: (),
                })
            },
        )
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(lines(&path), ["base", "theirs", "mine"]);
    }

    /// The edit decides from the bytes the snapshot read, never from a second
    /// read of the path that could see another version.
    #[cfg(not(windows))]
    #[test]
    fn the_edit_gets_the_snapshot_bytes_not_a_reread() {
        let dir = tempfile::tempdir().unwrap();
        let path = dunce::canonicalize(dir.path()).unwrap().join("config.toml");
        std::fs::write(&path, "A\n").unwrap();
        let mut fired = false;
        test_hooks::set_after_snapshot(Some(Box::new(move |p: &Path| {
            if !fired {
                fired = true;
                write_atomically(p, "B\n", None).unwrap();
            }
        })));
        let mut seen = Vec::new();
        let result = edit_locked(
            &path,
            |bytes| stage_atomically_from_existing(&path, bytes, 0o600),
            |current| {
                seen.push(String::from_utf8_lossy(current.unwrap().unwrap()).into_owned());
                Ok::<_, std::io::Error>(Edit::Keep(()))
            },
        );
        test_hooks::set_after_snapshot(None);
        result.unwrap();
        assert_eq!(seen, ["A\n"]);
    }

    /// Overtaken on every optimistic pass, the writer still finishes: the last
    /// pass does the whole cycle under the lock.
    #[cfg(not(windows))] // no optimistic passes there
    #[test]
    fn sustained_interference_falls_back_to_a_locked_pass() {
        let dir = tempfile::tempdir().unwrap();
        // Canonical: optimism needs a link-free path (macOS /var is a link).
        let path = dunce::canonicalize(dir.path()).unwrap().join("config.toml");
        std::fs::write(&path, "base\n").unwrap();
        let mut n = 0;
        test_hooks::set_after_stage(Some(Box::new(move |p: &Path| {
            n += 1;
            sneak_in(p, &format!("theirs{n}"));
        })));
        let mut stages = Vec::new();
        let result = edit_locked(
            &path,
            |bytes| {
                stages.push(other_holds_lock(&path));
                stage_atomically_from_existing(&path, bytes, 0o600)
            },
            |current| {
                let mut s = String::from_utf8_lossy(current.unwrap().unwrap()).into_owned();
                s.push_str("mine\n");
                Ok::<_, std::io::Error>(Edit::Replace {
                    contents: s.into_bytes(),
                    value: (),
                })
            },
        );
        test_hooks::set_after_stage(None);
        result.unwrap();
        assert_eq!(
            stages,
            [false, false, true],
            "two unlocked stages, then one under the lock"
        );
        assert_eq!(lines(&path), ["base", "theirs1", "theirs2", "mine"]);
    }

    /// Windows makes no optimistic pass: the temp is staged with the lock held.
    #[cfg(windows)]
    #[test]
    fn on_windows_the_temp_is_staged_under_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "a\n").unwrap();
        let mut staged_locked = None;
        edit_locked(
            &path,
            |bytes| {
                staged_locked = Some(other_holds_lock(&path));
                stage_atomically_from_existing(&path, bytes, 0o600)
            },
            |_| {
                Ok::<_, std::io::Error>(Edit::Replace {
                    contents: b"b\n".to_vec(),
                    value: (),
                })
            },
        )
        .unwrap();
        assert_eq!(staged_locked, Some(true));
        assert_eq!(lines(&path), ["b"]);
    }

    /// A path through a symlinked directory gets no optimistic pass: staging
    /// happens under the lock (an A-B-A switch of that link would be invisible).
    #[cfg(unix)]
    #[test]
    fn a_path_through_a_directory_link_is_edited_under_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(dir.path()).unwrap();
        std::fs::create_dir(root.join("real")).unwrap();
        std::os::unix::fs::symlink("real", root.join("current")).unwrap();
        let path = root.join("current/config.toml");
        std::fs::write(&path, "a\n").unwrap();
        assert!(!path_is_link_free(&path));
        assert!(path_is_link_free(&root.join("real/config.toml")));
        let mut staged_locked = None;
        edit_locked(
            &path,
            |bytes| {
                staged_locked = Some(other_holds_lock(&path));
                stage_atomically_from_existing(&path, bytes, 0o600)
            },
            |_| {
                Ok::<_, std::io::Error>(Edit::Replace {
                    contents: b"b\n".to_vec(),
                    value: (),
                })
            },
        )
        .unwrap();
        assert_eq!(staged_locked, Some(true));
        assert_eq!(lines(&root.join("real/config.toml")), ["b"]);
    }

    /// A path that becomes a symlink while an optimistic pass runs is not
    /// committed optimistically: eligibility is re-checked under the lock.
    #[cfg(unix)]
    #[test]
    fn a_path_that_turns_into_a_link_mid_pass_is_finished_under_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(dir.path()).unwrap();
        let path = root.join("config.toml");
        let real = root.join("real.toml");
        std::fs::write(&path, "a\n").unwrap();
        std::fs::write(&real, "a\n").unwrap();
        let mut stages = Vec::new();
        let mut first = true;
        edit_locked(
            &path,
            |bytes| {
                stages.push(other_holds_lock(&path));
                if first {
                    first = false;
                    // Another holder turns the name into a link to a file
                    // with the very same bytes.
                    std::fs::remove_file(&path).unwrap();
                    std::os::unix::fs::symlink("real.toml", &path).unwrap();
                }
                stage_atomically_from_existing(&path, bytes, 0o600)
            },
            |_| {
                Ok::<_, std::io::Error>(Edit::Replace {
                    contents: b"b\n".to_vec(),
                    value: (),
                })
            },
        )
        .unwrap();
        assert_eq!(stages, [false, true], "re-done under the lock");
    }

    /// A different file swapped in at the path WHILE the temp is staged (its
    /// directory moved aside and back) must not have its metadata, or its
    /// location, committed: the staged temp is bound to the file `edit` read.
    #[cfg(unix)]
    #[test]
    fn a_file_swapped_in_during_staging_is_not_what_gets_committed() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(dir.path()).unwrap();
        let live = root.join("live");
        std::fs::create_dir(&live).unwrap();
        let path = live.join("config.toml");
        std::fs::write(&path, "a\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut swaps = 0;
        edit_locked(
            &path,
            |bytes| {
                if swaps == 0 {
                    swaps += 1;
                    // Another lock holder: move the directory aside, put a
                    // looser file in its place, stage against it, restore.
                    std::fs::rename(&live, root.join("live.aside")).unwrap();
                    std::fs::create_dir(&live).unwrap();
                    std::fs::write(&path, "a\n").unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                        .unwrap();
                    let staged = stage_atomically_from_existing(&path, bytes, 0o600);
                    // Put the original back; the decoy (and the temp staged in
                    // it) is moved out of the way, where it stays.
                    std::fs::rename(&live, root.join("live.decoy")).unwrap();
                    std::fs::rename(root.join("live.aside"), &live).unwrap();
                    return staged;
                }
                stage_atomically_from_existing(&path, bytes, 0o600)
            },
            |_| {
                Ok::<_, std::io::Error>(Edit::Replace {
                    contents: b"b\n".to_vec(),
                    value: (),
                })
            },
        )
        .unwrap();
        assert_eq!(lines(&path), ["b"]);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o600,
            "the decoy's mode must not be published"
        );
    }

    /// Staging that found NO file at the path (its directory swapped for an
    /// empty one and back) chose a new file's mode; that must not be committed
    /// over the file `edit` was given, which keeps its own mode.
    #[cfg(unix)]
    #[test]
    fn a_file_missing_only_during_staging_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(dir.path()).unwrap();
        let live = root.join("live");
        std::fs::create_dir(&live).unwrap();
        let path = live.join("config.toml");
        std::fs::write(&path, "a\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let mut first = true;
        edit_locked(
            &path,
            |bytes| {
                if first {
                    first = false;
                    std::fs::rename(&live, root.join("live.aside")).unwrap();
                    std::fs::create_dir(&live).unwrap();
                    let staged = stage_atomically_from_existing(&path, bytes, 0o600);
                    std::fs::rename(&live, root.join("live.empty")).unwrap();
                    std::fs::rename(root.join("live.aside"), &live).unwrap();
                    return staged;
                }
                stage_atomically_from_existing(&path, bytes, 0o600)
            },
            |_| {
                Ok::<_, std::io::Error>(Edit::Replace {
                    contents: b"b\n".to_vec(),
                    value: (),
                })
            },
        )
        .unwrap();
        assert_eq!(lines(&path), ["b"]);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o400
        );
    }

    /// A FIFO seen at the path only while staging (its directory swapped and
    /// restored) must not turn the commit into an in-place write over the
    /// regular config `edit` was given: that config is still replaced
    /// atomically (a new inode), never truncated in place.
    #[cfg(unix)]
    #[test]
    fn a_special_file_seen_only_during_staging_does_not_cause_an_in_place_write() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(dir.path()).unwrap();
        let live = root.join("live");
        std::fs::create_dir(&live).unwrap();
        let path = live.join("config.toml");
        std::fs::write(&path, "a\n").unwrap();
        let ino = std::fs::metadata(&path).unwrap().ino();
        let mut first = true;
        edit_locked(
            &path,
            |bytes| {
                if first {
                    first = false;
                    std::fs::rename(&live, root.join("live.aside")).unwrap();
                    std::fs::create_dir(&live).unwrap();
                    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                    // SAFETY: valid NUL-terminated path.
                    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
                    let staged = crate::write_through::stage_file_atomically(&path, bytes);
                    std::fs::rename(&live, root.join("live.fifo")).unwrap();
                    std::fs::rename(root.join("live.aside"), &live).unwrap();
                    return staged;
                }
                crate::write_through::stage_file_atomically(&path, bytes)
            },
            |_| {
                Ok::<_, std::io::Error>(Edit::Replace {
                    contents: b"b\n".to_vec(),
                    value: (),
                })
            },
        )
        .unwrap();
        assert_eq!(lines(&path), ["b"]);
        assert_ne!(
            std::fs::metadata(&path).unwrap().ino(),
            ino,
            "replaced atomically, not rewritten in place"
        );
    }

    /// Many threads, many increments, none lost.
    #[test]
    fn concurrent_edits_lose_no_update() {
        // Not alongside the P61 multi-process tests (see `HEAVY_IO`).
        let _alone = HEAVY_IO.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        const THREADS: usize = 8;
        const EACH: usize = 25;
        let dir = tempfile::tempdir().unwrap();
        let path = std::sync::Arc::new(dir.path().join("counter"));
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let path = path.clone();
                std::thread::spawn(move || {
                    for i in 0..EACH {
                        append_line(&path, &format!("{t}-{i}")).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let mut got = lines(&path);
        got.sort();
        let mut want: Vec<String> = (0..THREADS)
            .flat_map(|t| (0..EACH).map(move |i| format!("{t}-{i}")))
            .collect();
        want.sort();
        assert_eq!(got, want);
    }

    /// A decision to keep the file takes no lock and creates nothing.
    #[cfg(not(windows))] // the locked pass takes the lock, which creates the directory
    #[test]
    fn keeping_the_file_creates_no_directory_and_no_lock() {
        let dir = tempfile::tempdir().unwrap();
        // Canonical: the optimistic pass needs a link-free path (macOS /var).
        let root = dunce::canonicalize(dir.path()).unwrap();
        let path = root.join("missing/config.toml");
        let v = edit_locked(
            &path,
            |_| panic!("nothing to stage"),
            |_| Ok::<_, std::io::Error>(Edit::Keep(7)),
        )
        .unwrap();
        assert_eq!(v, 7);
        assert!(!root.join("missing").exists());
    }

    /// The edit's own error comes back as such, and nothing is written.
    #[test]
    fn the_edits_error_is_returned_and_nothing_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "keep\n").unwrap();
        let err = edit_locked::<(), _>(
            &path,
            |bytes| stage_atomically_from_existing(&path, bytes, 0o600),
            |_| Err("refused"),
        )
        .unwrap_err();
        assert!(matches!(err, EditError::Edit("refused")), "{err:?}");
        assert_eq!(lines(&path), ["keep"]);
    }

    /// A staged temp that is never committed is removed; a failed commit too.
    #[test]
    fn an_uncommitted_or_failed_replacement_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("f");
        let staged = stage_atomically(&target, b"x", None).unwrap();
        let tmp = staged.temp_path().unwrap().to_path_buf();
        assert!(tmp.exists());
        drop(staged);
        assert!(!tmp.exists());

        // Renaming a file over a non-empty directory fails.
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("inner"), "").unwrap();
        let staged = stage_atomically(&target, b"x", None).unwrap();
        let tmp = staged.temp_path().unwrap().to_path_buf();
        staged.commit().expect_err("cannot replace a directory");
        assert!(!tmp.exists());
    }

    /// Retargeting an intermediate link counts as a change even when both
    /// destinations are missing (nothing in the bytes or the outer link moves).
    #[cfg(unix)]
    #[test]
    fn a_snapshot_sees_an_intermediate_link_retargeted_between_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let selector = dir.path().join("selector");
        std::os::unix::fs::symlink("selector", &path).unwrap();
        std::os::unix::fs::symlink("missing-a", &selector).unwrap();
        let a = FileSnapshot::take(&path).unwrap();
        assert_eq!(a, FileSnapshot::take(&path).unwrap());
        std::fs::remove_file(&selector).unwrap();
        std::os::unix::fs::symlink("missing-b", &selector).unwrap();
        assert_ne!(a, FileSnapshot::take(&path).unwrap());
    }

    /// A permission change alone (same bytes, same inode) counts as a change.
    #[cfg(unix)]
    #[test]
    fn a_snapshot_sees_a_mode_change() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, "x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let a = FileSnapshot::take(&path).unwrap();
        assert_eq!(a, FileSnapshot::take(&path).unwrap());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_ne!(a, FileSnapshot::take(&path).unwrap());
    }

    use std::sync::Mutex;
}

/// Serializes the tests that hammer one file with fsyncs from many threads or
/// processes, so they do not slow each other down on a loaded host. (Since P72
/// a slow but moving queue no longer turns into a refusal; this only keeps
/// their run time down.)
#[cfg(test)]
pub(crate) static HEAVY_IO: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
#[path = "fs_atomic_p61_tests.rs"]
mod p61_tests;

#[cfg(test)]
#[path = "fs_atomic_p72_tests.rs"]
mod p72_tests;

#[cfg(test)]
#[path = "fs_atomic_p79_tests.rs"]
mod p79_tests;

/// P150 (D6, S14/B20): the writer lock beside `config.toml` (`config.toml.lock`) is created owner-only, and one an
/// older version left 0644 is tightened when it is next taken.
#[cfg(all(test, unix))]
#[test]
fn p150_config_lock_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let lock = config_lock_path(&config);
    drop(lock_config_for_write(&config).unwrap());
    assert_eq!(mode(&lock), 0o600, "a new config.toml.lock must be owner-only");
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();
    drop(lock_config_for_write(&config).unwrap());
    assert_eq!(mode(&lock), 0o600, "a looser config.toml.lock is tightened");
}
