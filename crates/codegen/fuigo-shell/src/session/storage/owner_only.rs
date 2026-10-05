//! Session files readable by their owner only (P120, R113 R3.5).
//!
//! A session file holds the conversation as the model saw it, tool output included. The session directory is created
//! 0700, but a file made inside it with the default mode is 0644 (the umask decides), and one made by an older version
//! or restored from a backup stays that way. Every session file is therefore created 0600 and tightened to 0600 when
//! it is opened for writing.
//!
//! - **Unix**: `mode(0o600)` at creation, so there is no window with a looser mode (a umask can only remove bits), and
//!   an `fchmod` on the opened descriptor when an existing file has any other mode (no path race).
//! - **Windows**: there are no mode bits. The equivalent is an ACL that grants access to the current user only, applied
//!   with [`crate::util::secure_file::ensure_owner_only_permissions`] (the same call the auth store uses). It rewrites
//!   the DACL, so it runs at every open for writing (a cache of protected paths would trust a file replaced
//!   since). The Windows branch is not exercised by the Linux tests.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Make `options` create a file 0600 (Unix); a no-op elsewhere.
pub(crate) fn owner_only(options: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
}

/// Tighten an already opened session file to owner-only. Call after every open for writing.
///
/// Best effort, never fatal (P134, row 122): 1.0.20 never changed a session file's mode, so a filesystem that has no
/// Unix modes (vfat, exFAT, some FUSE and SMB mounts: `fchmod` answers EPERM, ENOTSUP or EINVAL) must not stop a
/// session from being saved. The file is still CREATED 0600 where the OS honours that; a failed tightening is logged
/// once per process and the write goes on.
pub(crate) fn tighten(file: &File, path: &Path) -> io::Result<()> {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    tighten_with(file, path, platform_tighten, &WARNED, |path, error| {
        tracing::warn!(
            path = %path.display(),
            error = %error,
            "session file: could not restrict it to owner-only (a filesystem without Unix permissions?); continuing unprotected"
        );
    });
    Ok(())
}

/// [`tighten`] with the platform call, the warn-once flag and the warning injected. A failure is reported through
/// `warn` the first time `warned` is clear and swallowed every time.
fn tighten_with(
    file: &File,
    path: &Path,
    chmod: impl FnOnce(&File, &Path) -> io::Result<()>,
    warned: &std::sync::atomic::AtomicBool,
    warn: impl FnOnce(&Path, &io::Error),
) {
    if let Err(error) = chmod(file, path)
        && !warned.swap(true, std::sync::atomic::Ordering::Relaxed)
    {
        warn(path, &error);
    }
}

fn platform_tighten(file: &File, path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = path;
        #[cfg(all(test, unix))]
        if test_seam::fail_chmod() {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        let metadata = file.metadata()?;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        // Applied at every open for writing, never cached: a cached path would trust a file that was replaced since.
        // (The DACL rewrite is a few system calls; the cost on a streaming session is not measured on Windows.)
        let _ = file;
        crate::util::secure_file::ensure_owner_only_permissions(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (file, path);
        Ok(())
    }
}

/// Test seam: make the platform tightening fail on THIS thread, as `fchmod` does on a filesystem without modes.
#[cfg(all(test, unix))]
pub(crate) mod test_seam {
    use std::cell::Cell;
    thread_local! { static FAIL: Cell<bool> = const { Cell::new(false) }; }
    pub(crate) fn fail_chmod() -> bool {
        FAIL.with(Cell::get)
    }
    /// Fail the tightening on this thread until the guard drops.
    pub(crate) struct FailChmod;
    impl FailChmod {
        pub(crate) fn new() -> Self {
            FAIL.with(|f| f.set(true));
            Self
        }
    }
    impl Drop for FailChmod {
        fn drop(&mut self) {
            FAIL.with(|f| f.set(false));
        }
    }
}

/// Open `path` with `options` (0600 on creation) and tighten it.
pub(crate) fn open(options: &mut OpenOptions, path: &Path) -> io::Result<File> {
    let file = owner_only(options).open(path)?;
    tighten(&file, path)?;
    Ok(file)
}

/// `File::create` for a session file.
pub(crate) fn create(path: &Path) -> io::Result<File> {
    open(OpenOptions::new().write(true).create(true).truncate(true), path)
}

/// `std::fs::write` for a session file.
pub(crate) fn write(path: &Path, bytes: impl AsRef<[u8]>) -> io::Result<()> {
    use std::io::Write as _;
    create(path)?.write_all(bytes.as_ref())
}

/// `std::fs::copy` for a session file: the copy is created owner-only whatever the mode of the source.
pub(crate) fn copy(src: &Path, dst: &Path) -> io::Result<u64> {
    let mut source = File::open(src)?;
    let mut target = create(dst)?;
    io::copy(&mut source, &mut target)
}

/// [`copy`] on the blocking pool.
pub(crate) async fn copy_async(src: &Path, dst: &Path) -> io::Result<u64> {
    let (src, dst) = (src.to_path_buf(), dst.to_path_buf());
    tokio::task::spawn_blocking(move || copy(&src, &dst)).await.map_err(io::Error::other)?
}

/// `tokio::fs::write` for a session file.
pub(crate) async fn write_async(path: impl AsRef<Path>, bytes: impl AsRef<[u8]> + Send + 'static) -> io::Result<()> {
    let path = path.as_ref().to_path_buf();
    tokio::task::spawn_blocking(move || write(&path, bytes))
        .await
        .map_err(io::Error::other)?
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// The file is BORN 0600: no window between creation and the tightening, whatever the umask.
    #[test]
    fn p120_a_new_file_is_born_owner_only_even_with_a_zero_umask() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("born");
        // SAFETY: umask only changes the process's default creation mask; restored below.
        let previous = unsafe { libc::umask(0) };
        let created = owner_only(OpenOptions::new().write(true).create_new(true)).open(&path);
        unsafe { libc::umask(previous) };
        created.unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn p120_copy_makes_an_owner_only_copy_of_a_loose_file() {
        let dir = tempfile::tempdir().unwrap();
        let (src, dst) = (dir.path().join("src"), dir.path().join("dst"));
        std::fs::write(&src, b"content").unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(copy(&src, &dst).unwrap(), 7);
        assert_eq!(std::fs::read(&dst).unwrap(), b"content");
        assert_eq!(std::fs::metadata(&dst).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn p134_a_failed_tightening_is_warned_once_and_never_fails_the_open() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.jsonl");
        let file = std::fs::File::create(&path).unwrap();
        let (warned, warnings) = (AtomicBool::new(false), AtomicUsize::new(0));
        for kind in [libc::EPERM, libc::ENOTSUP, libc::EINVAL, libc::EIO] {
            tighten_with(
                &file,
                &path,
                |_, _| Err(io::Error::from_raw_os_error(kind)),
                &warned,
                |_, _| {
                    warnings.fetch_add(1, Ordering::SeqCst);
                },
            );
        }
        assert_eq!(warnings.load(Ordering::SeqCst), 1, "one warning for the process, not one per open");
    }

    #[test]
    fn p134_open_and_write_succeed_when_fchmod_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.jsonl");
        let _fail = test_seam::FailChmod::new();
        let mut file = open(OpenOptions::new().read(true).create(true).append(true), &path)
            .expect("a refused fchmod must not fail the open");
        io::Write::write_all(&mut file, b"{}\n").unwrap();
        write(&dir.path().join("w"), b"x").expect("write");
        create(&dir.path().join("c")).expect("create");
        copy(&path, &dir.path().join("copy")).expect("copy");
        assert_eq!(std::fs::read(&path).unwrap(), b"{}\n");
    }
}
