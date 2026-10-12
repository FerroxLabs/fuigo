//! Locator file read and update on Windows (packet 15b). Same contract as the unix `locator.rs`: one small file
//! (`MAX_LOCATOR_BYTES`) inside the checked peers directory; a read never follows a link and rejects a file that is
//! not a regular single-link file owned by us with a DACL for nobody else; an update takes an exclusive lock on a
//! lock file (bounded wait, `LockBusy`), re-reads under the lock, calls `f`, writes a temp file in the same directory
//! and replaces the locator with one `MoveFileExW`. Synchronous blocking I/O: use `spawn_blocking`. Nothing is built
//! from file content and nothing is logged.
//!
//! Every file is opened by `<checked dir path>\<name>` with `FILE_FLAG_OPEN_REPARSE_POINT`, so a link is opened as
//! the link itself, and every check runs on the HANDLE (`GetFileInformationByHandle`, owner and DACL by handle).
//!
//! Identity (round 1, the PATH variant): the path string is only a way to NAME the held `peers` directory. Before each
//! operation `CheckedDir::verify` compares the directory the path names now with the held handle (volume serial + file
//! id), and after each open `CheckedDir::verify_file` proves the file lives in the held directory. Any mismatch is
//! `Disabled::PeersMoved` and nothing is written or deleted. Deletes act on the handle that was checked
//! (`FileDispositionInfo`), never on a name looked up again. With every ancestor pinned open by `CheckedDir`, this is
//! defence in depth.

use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_CREATION_DISPOSITION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ, FILE_INFO_BY_HANDLE_CLASS, FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_MODE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, GetFileInformationByHandle, GetFileType, LOCKFILE_EXCLUSIVE_LOCK,
    LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    OPEN_ALWAYS, OPEN_EXISTING, SetFileInformationByHandle, UnlockFileEx,
};
use windows::Win32::System::IO::OVERLAPPED;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PCWSTR;

use super::win_pipe::sys::owner_and_dacl;
use super::win_policy::{locator_dacl_ok, locator_owner_ok, owner_only_sddl};
use super::{CheckedDir, Disabled, MAX_LOCATOR_BYTES, Reject};
use crate::leader::peer_auth::win as auth;

/// `DELETE` access right (needed to mark a file for deletion through its own handle).
const DELETE_ACCESS: u32 = 0x1_0000;
/// `FILE_INFO_BY_HANDLE_CLASS` value of `FileDispositionInfo`.
const FILE_DISPOSITION_INFO_CLASS: i32 = 4;
const LOCK_NAME: &str = ".lock";
const TMP_PREFIX: &str = ".tmp-";
/// Total time `update_locator` waits for the directory lock before `Disabled::LockBusy`.
const LOCK_DEADLINE: Duration = Duration::from_secs(2);
const LOCK_RETRY_GAP: Duration = Duration::from_millis(10);
/// How long an open, a delete or the replace is retried when something else (a reader, an antivirus scanner, an
/// indexer) holds the file in a way that conflicts. Then `Disabled::Io(code)`.
const SHARING_RETRY_BOUND: Duration = Duration::from_millis(750);
const SHARING_RETRY_GAP: Duration = Duration::from_millis(5);

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_FILE_EXISTS: i32 = 80;
const ERROR_SHARING_VIOLATION: i32 = 32;
const ERROR_LOCK_VIOLATION: i32 = 33;
const ERROR_ALREADY_EXISTS: i32 = 183;

fn code_of(e: &windows::core::Error) -> i32 {
    e.code().0 & 0xFFFF
}

fn io_code(e: &std::io::Error) -> Disabled {
    Disabled::Io(e.raw_os_error().unwrap_or(0))
}

/// Does `name` end in a Windows device name (`CON`, `NUL.txt`, `COM1`, ...)? The base is the part before the first dot.
fn is_reserved_device(name: &str) -> bool {
    let base = name.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
    match base.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$" => true,
        b => {
            let rest = b.strip_prefix("COM").or_else(|| b.strip_prefix("LPT"));
            // COM0 and LPT0 count too; the superscript digits are devices as well.
            matches!(rest, Some(r) if r.chars().count() == 1 && r.chars().all(|c| c.is_ascii_digit() || matches!(c, '\u{b9}' | '\u{b2}' | '\u{b3}')))
        }
    }
}

fn validate_name(name: &str) -> Result<(), Disabled> {
    let bad = name.is_empty()
        || name.len() > 200
        || name == "."
        || name == ".."
        || name.chars().any(|c| (c as u32) < 0x20 || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'))
        || name.ends_with('.')
        || name.ends_with(' ')
        || name.eq_ignore_ascii_case(LOCK_NAME)
        || name.len() >= TMP_PREFIX.len() && name[..TMP_PREFIX.len()].eq_ignore_ascii_case(TMP_PREFIX)
        || is_reserved_device(name);
    if bad { Err(Disabled::InvalidName) } else { Ok(()) }
}

fn wide(p: &Path) -> Result<Vec<u16>, Disabled> {
    let mut v: Vec<u16> = p.as_os_str().encode_wide().collect();
    if v.contains(&0) {
        return Err(Disabled::InvalidName);
    }
    v.push(0);
    Ok(v)
}

/// The user SID text of this process (cached).
fn our_sid() -> Result<&'static str, Disabled> {
    static SID: OnceLock<Result<String, u32>> = OnceLock::new();
    match SID.get_or_init(auth::own_sid) {
        Ok(s) => Ok(s.as_str()),
        Err(c) => Err(Disabled::Io(*c as i32)),
    }
}

/// Is our token elevated? (An elevated process owns what it creates as BUILTIN\Administrators by default.)
fn token_elevated() -> bool {
    static ELEVATED: OnceLock<bool> = OnceLock::new();
    *ELEVATED.get_or_init(|| {
        let mut token = HANDLE::default();
        // SAFETY: the pseudo handle of the current process needs no closing; `token` is writable.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
            return false;
        }
        let token = auth::Owned(token);
        match auth::token_info_buf(token.0, TokenElevation) {
            // SAFETY: on success the buffer starts with a TOKEN_ELEVATION (8-byte aligned storage).
            Ok(buf) => unsafe { (*buf.as_ptr().cast::<TOKEN_ELEVATION>()).TokenIsElevated != 0 },
            Err(_) => false,
        }
    })
}

/// `CreateFileW` with the raw Win32 error code on failure.
fn create(
    path: &[u16],
    access: u32,
    share: FILE_SHARE_MODE,
    disposition: FILE_CREATION_DISPOSITION,
    sec: Option<*const SECURITY_ATTRIBUTES>,
    flags: FILE_FLAGS_AND_ATTRIBUTES,
) -> Result<OwnedHandle, i32> {
    // SAFETY: `path` is NUL-terminated; `sec`, when present, points at a live SECURITY_ATTRIBUTES owned by the caller.
    let h = unsafe { CreateFileW(PCWSTR(path.as_ptr()), access, share, sec, disposition, flags, None) }
        .map_err(|e| code_of(&e))?;
    // SAFETY: CreateFileW succeeded, so `h` is a fresh handle that nothing else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(h.0) })
}

fn retryable(code: i32) -> bool {
    matches!(code, ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION | ERROR_ACCESS_DENIED)
}

/// The explicit owner-only descriptor every new file gets: owner us, PROTECTED DACL (nothing inherited), one ACE for us.
fn owner_only_security() -> Result<auth::PipeSecurity, Disabled> {
    let sid = our_sid()?;
    let sddl = owner_only_sddl(sid).ok_or(Disabled::Io(0))?;
    auth::PipeSecurity::from_sddl(&sddl).map_err(|e| Disabled::Io(e.raw_os_error().unwrap_or(0)))
}

/// Judge an open file ON ITS HANDLE: regular disk file (no reparse point, no directory), one link, within `cap`,
/// owned by us, DACL for nobody else. Returns the size. Never reads the content.
fn check_handle(h: &OwnedHandle, cap: Option<u64>) -> Result<u64, Disabled> {
    let raw = HANDLE(h.as_raw_handle());
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `raw` is a live file handle; `info` is a writable out structure.
    unsafe { GetFileInformationByHandle(raw, &mut info) }.map_err(|e| Disabled::Io(code_of(&e)))?;
    let attrs = info.dwFileAttributes;
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(Disabled::Rejected(Reject::Symlink));
    }
    // SAFETY: live handle.
    if attrs & FILE_ATTRIBUTE_DIRECTORY.0 != 0 || unsafe { GetFileType(raw) } != FILE_TYPE_DISK {
        return Err(Disabled::Rejected(Reject::NotRegular));
    }
    if info.nNumberOfLinks != 1 {
        return Err(Disabled::Rejected(Reject::HardLinked));
    }
    let size = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
    if cap.is_some_and(|c| size > c) {
        return Err(Disabled::Rejected(Reject::TooLarge));
    }
    let ours = our_sid()?;
    // A NULL DACL (everyone) comes back as code 0: that is a wrong mode, not an I/O error.
    let (owner, dacl) = owner_and_dacl(raw).map_err(|c| if c == 0 { Disabled::Rejected(Reject::WrongMode) } else { Disabled::Io(c as i32) })?;
    if !locator_owner_ok(&owner, ours, token_elevated()) {
        return Err(Disabled::Rejected(Reject::WrongOwner));
    }
    if !locator_dacl_ok(&dacl, ours) {
        return Err(Disabled::Rejected(Reject::WrongMode));
    }
    Ok(size)
}

/// Read `<dir>\<name>`. `exclusive_share`: a writer under the lock holds the file without write or delete sharing
/// while it reads; a plain reader lets a replace proceed (`FILE_SHARE_DELETE`).
fn read_at(dir: &CheckedDir, name: &str, exclusive_share: bool) -> Result<Option<Vec<u8>>, Disabled> {
    dir.verify()?;
    let w = wide(&dir.path().join(name))?;
    let share = if exclusive_share { FILE_SHARE_READ } else { FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE };
    let give_up = Instant::now() + SHARING_RETRY_BOUND;
    let h = loop {
        match create(
            &w,
            FILE_GENERIC_READ.0,
            share,
            OPEN_EXISTING,
            None,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        ) {
            Ok(h) => break h,
            Err(ERROR_FILE_NOT_FOUND) => return Ok(None),
            Err(c) if retryable(c) && Instant::now() < give_up => std::thread::sleep(SHARING_RETRY_GAP),
            Err(c) => return Err(Disabled::Io(c)),
        }
    };
    dir.verify_file(HANDLE(h.as_raw_handle()), name)?;
    check_handle(&h, Some(MAX_LOCATOR_BYTES))?;
    let mut buf = Vec::new();
    let n = std::fs::File::from(h).take(MAX_LOCATOR_BYTES + 1).read_to_end(&mut buf).map_err(|e| io_code(&e))?;
    if n as u64 > MAX_LOCATOR_BYTES {
        return Err(Disabled::Rejected(Reject::TooLarge));
    }
    Ok(Some(buf))
}

/// Read a locator file. `Ok(None)` if absent. A file failing any check returns `Err(Disabled::Rejected(reason))`;
/// its bytes are never parsed. A sharing conflict (a replace in flight, a scanner) is retried for a short bound.
pub(crate) fn read_locator(dir: &CheckedDir, name: &str) -> Result<Option<Vec<u8>>, Disabled> {
    validate_name(name)?;
    read_at(dir, name, false)
}

/// Exclusive `LockFileEx` on the directory's lock file; released on every path (RAII).
struct LockGuard(OwnedHandle);

impl Drop for LockGuard {
    fn drop(&mut self) {
        let mut ov = OVERLAPPED::default();
        // SAFETY: valid handle holding the lock. Closing also releases; the explicit unlock is belt and braces.
        let _ = unsafe { UnlockFileEx(HANDLE(self.0.as_raw_handle()), None, 1, 0, &mut ov) };
    }
}

fn acquire_lock(dir: &CheckedDir) -> Result<LockGuard, Disabled> {
    dir.verify()?;
    let give_up = Instant::now() + LOCK_DEADLINE;
    let w = wide(&dir.path().join(LOCK_NAME))?;
    let mut sec = owner_only_security()?;
    let sec_ptr = sec.as_raw().cast_const().cast::<SECURITY_ATTRIBUTES>();
    let h = loop {
        // OPEN_ALWAYS: an existing entry is opened as it is (a link as the link), a missing one is created with the
        // owner-only descriptor. Other processes may open it too: they must, to wait on it.
        match create(
            &w,
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_ALWAYS,
            Some(sec_ptr),
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        ) {
            Ok(h) => break h,
            Err(c) if retryable(c) => {
                if Instant::now() >= give_up {
                    return Err(if c == ERROR_ACCESS_DENIED { Disabled::Io(c) } else { Disabled::LockBusy });
                }
                std::thread::sleep(LOCK_RETRY_GAP);
            }
            Err(c) => return Err(Disabled::Io(c)),
        }
    };
    drop(sec);
    dir.verify_file(HANDLE(h.as_raw_handle()), LOCK_NAME)?;
    check_handle(&h, None).map_err(|e| match e {
        Disabled::Rejected(r) => Disabled::LockRejected(r),
        other => other,
    })?;
    loop {
        let mut ov = OVERLAPPED::default();
        // SAFETY: valid handle; `ov` is a zeroed OVERLAPPED (offset 0) that lives across the call. Locks byte 0 only.
        let r = unsafe {
            LockFileEx(HANDLE(h.as_raw_handle()), LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, None, 1, 0, &mut ov)
        };
        match r {
            Ok(()) => return Ok(LockGuard(h)),
            Err(e) if code_of(&e) == ERROR_LOCK_VIOLATION => {
                if Instant::now() >= give_up {
                    return Err(Disabled::LockBusy);
                }
                std::thread::sleep(LOCK_RETRY_GAP);
            }
            Err(e) => return Err(Disabled::Io(code_of(&e))),
        }
    }
}

/// Removes the temp file on drop unless it was moved into place (through the verified, handle-based delete).
struct TempGuard<'a> {
    dir: &'a CheckedDir,
    name: String,
    armed: bool,
}

impl Drop for TempGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_at(self.dir, &self.name);
        }
    }
}

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn replace(from: &[u16], to: &[u16]) -> Result<(), Disabled> {
    let give_up = Instant::now() + SHARING_RETRY_BOUND;
    loop {
        // SAFETY: both paths are NUL-terminated.
        let r = unsafe {
            MoveFileExW(PCWSTR(from.as_ptr()), PCWSTR(to.as_ptr()), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)
        };
        match r {
            Ok(()) => return Ok(()),
            Err(e) if retryable(code_of(&e)) && Instant::now() < give_up => std::thread::sleep(SHARING_RETRY_GAP),
            Err(e) => return Err(Disabled::Io(code_of(&e))),
        }
    }
}

/// Mark the file behind `h` for deletion through that very handle (`FileDispositionInfo`): no name is looked up again.
fn delete_by_handle(h: &OwnedHandle) -> Result<(), i32> {
    let flag: u8 = 1; // FILE_DISPOSITION_INFO { DeleteFile: BOOLEAN }
    // SAFETY: live handle opened with DELETE access; the buffer is one BOOLEAN and the size passed is 1.
    unsafe {
        SetFileInformationByHandle(
            HANDLE(h.as_raw_handle()),
            FILE_INFO_BY_HANDLE_CLASS(FILE_DISPOSITION_INFO_CLASS),
            std::ptr::addr_of!(flag).cast(),
            1,
        )
    }
    .map_err(|e| code_of(&e))
}

fn write_temp_and_replace(dir: &CheckedDir, name: &str, bytes: &[u8]) -> Result<(), Disabled> {
    dir.verify()?;
    let target = wide(&dir.path().join(name))?;
    let mut sec = owner_only_security()?;
    let sec_ptr = sec.as_raw().cast_const().cast::<SECURITY_ATTRIBUTES>();
    for _ in 0..8 {
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp_name = format!("{TMP_PREFIX}{}-{seq}", std::process::id());
        let tmp = wide(&dir.path().join(&tmp_name))?;
        // CREATE_NEW: never opens an existing entry. Share mode 0: nobody else holds the temp file while we write it.
        let h = match create(
            &tmp,
            FILE_GENERIC_WRITE.0 | DELETE_ACCESS,
            FILE_SHARE_MODE(0),
            CREATE_NEW,
            Some(sec_ptr),
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        ) {
            Ok(h) => h,
            Err(ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS) => continue,
            Err(c) => return Err(Disabled::Io(c)),
        };
        if let Err(e) = dir.verify_file(HANDLE(h.as_raw_handle()), &tmp_name) {
            // created somewhere else than the held directory: remove it through its own handle
            let _ = delete_by_handle(&h);
            return Err(e);
        }
        let mut guard = TempGuard { dir, name: tmp_name, armed: true };
        let mut file = std::fs::File::from(h);
        file.write_all(bytes).map_err(|e| io_code(&e))?;
        // FlushFileBuffers.
        file.sync_all().map_err(|e| io_code(&e))?;
        drop(file);
        dir.verify()?;
        replace(&tmp, &target)?;
        guard.armed = false;
        return Ok(());
    }
    Err(Disabled::Io(ERROR_FILE_EXISTS))
}

/// Delete `<dir>\<name>`: open it (a link as the link itself) with `DELETE` access, prove on the handle that it lives in
/// the held directory, and delete through that handle. A missing file is `Ok`.
fn remove_at(dir: &CheckedDir, name: &str) -> Result<(), Disabled> {
    dir.verify()?;
    let w = wide(&dir.path().join(name))?;
    let give_up = Instant::now() + SHARING_RETRY_BOUND;
    loop {
        let opened = create(
            &w,
            DELETE_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            None,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        );
        let code = match opened {
            Err(ERROR_FILE_NOT_FOUND) => return Ok(()),
            Err(c) => c,
            Ok(h) => {
                dir.verify_file(HANDLE(h.as_raw_handle()), name)?;
                match delete_by_handle(&h) {
                    Ok(()) => return Ok(()),
                    Err(c) => c,
                }
            }
        };
        if retryable(code) && Instant::now() < give_up {
            std::thread::sleep(SHARING_RETRY_GAP);
        } else {
            return Err(Disabled::Io(code));
        }
    }
}

fn update_impl(
    dir: &CheckedDir,
    name: &str,
    rewrite_rejected: bool,
    f: impl FnOnce(Option<&[u8]>) -> Option<Vec<u8>>,
) -> Result<(), Disabled> {
    validate_name(name)?;
    let _lock = acquire_lock(dir)?;
    let current = match read_at(dir, name, true) {
        Ok(v) => v,
        Err(Disabled::Rejected(_)) if rewrite_rejected => None,
        Err(e) => return Err(e),
    };
    match f(current.as_deref()) {
        None => remove_at(dir, name),
        Some(bytes) => {
            if bytes.len() as u64 > MAX_LOCATOR_BYTES {
                return Err(Disabled::OutputTooLarge);
            }
            write_temp_and_replace(dir, name, &bytes)
        }
    }
}

/// Packet 15c: delete the `.tmp-*` files a crash between write and replace left in `dir`. Under the directory lock. Only a
/// plain file whose name starts with the temp prefix, whose last write is older than `older`, that opens with full sharing
/// (a file somebody still holds is skipped) and passes the owner / DACL / one-link checks (so only OUR files go), and at
/// most `max` of them. Returns how many were removed. Never follows a link: a reparse point fails the handle check.
pub(crate) fn sweep_stale_temps(dir: &CheckedDir, older: Duration, max: usize) -> Result<usize, Disabled> {
    let _lock = acquire_lock(dir)?;
    let mut removed = 0usize;
    let entries = std::fs::read_dir(dir.path()).map_err(|e| io_code(&e))?;
    for entry in entries.take(1024).flatten() {
        if removed >= max {
            break;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
        if !name.as_bytes().get(..TMP_PREFIX.len()).is_some_and(|b| b.eq_ignore_ascii_case(TMP_PREFIX.as_bytes())) {
            continue;
        }
        let Ok(w) = wide(&dir.path().join(&name)) else { continue };
        // ONE handle for the whole decision and the delete.
        let Ok(h) = create(
            &w,
            FILE_GENERIC_READ.0 | DELETE_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            None,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        ) else {
            continue;
        };
        dir.verify_file(HANDLE(h.as_raw_handle()), &name)?;
        if check_handle(&h, None).is_err() || age_of(&h).is_none_or(|age| age < older) {
            continue;
        }
        if delete_by_handle(&h).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Age of the file behind `h` from its last-write time (read on the handle).
fn age_of(h: &OwnedHandle) -> Option<Duration> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: live file handle; `info` is a writable out structure.
    unsafe { GetFileInformationByHandle(HANDLE(h.as_raw_handle()), &mut info) }.ok()?;
    let ticks = (u64::from(info.ftLastWriteTime.dwHighDateTime) << 32) | u64::from(info.ftLastWriteTime.dwLowDateTime);
    // FILETIME counts 100 ns from 1601-01-01; the Unix epoch is 11_644_473_600 s later.
    let unix_ticks = ticks.checked_sub(11_644_473_600 * 10_000_000)?;
    let written = std::time::UNIX_EPOCH + Duration::new(unix_ticks / 10_000_000, ((unix_ticks % 10_000_000) * 100) as u32);
    std::time::SystemTime::now().duration_since(written).ok()
}

/// Read-modify-write under the directory lock. `f` gets the current bytes (`None` if absent) and returns the new
/// bytes, or `None` to remove the file. A present file that fails its checks REFUSES the update
/// (`Err(Rejected(..))`, `f` not called, nothing written). Blocks on the lock: use `spawn_blocking`.
pub(crate) fn update_locator(
    dir: &CheckedDir,
    name: &str,
    f: impl FnOnce(Option<&[u8]>) -> Option<Vec<u8>>,
) -> Result<(), Disabled> {
    update_impl(dir, name, false, f)
}

/// Like [`update_locator`], but a present file that fails its checks is treated as absent (`f` gets `None`) and the
/// entry NAME is replaced by the move (a link or a hard-linked name is replaced, never written through; a directory
/// cannot be replaced and returns `Io`). Blocks: use `spawn_blocking`.
pub(crate) fn update_locator_rewriting(
    dir: &CheckedDir,
    name: &str,
    f: impl FnOnce(Option<&[u8]>) -> Option<Vec<u8>>,
) -> Result<(), Disabled> {
    update_impl(dir, name, true, f)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::sync::Arc;
    use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SetFileSecurityW};
    use windows::Win32::Storage::FileSystem::CreateHardLinkW;

    const NAME: &str = "hosts.json";

    fn setup() -> (tempfile::TempDir, CheckedDir) {
        let td = tempfile::tempdir().unwrap();
        let dir = CheckedDir::for_test(td.path().to_path_buf());
        (td, dir)
    }

    fn names(td: &tempfile::TempDir) -> Vec<String> {
        let mut v: Vec<_> =
            std::fs::read_dir(td.path()).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        v.sort();
        v
    }

    fn put(dir: &CheckedDir, bytes: &[u8]) {
        let b = bytes.to_vec();
        update_locator(dir, NAME, move |_| Some(b)).unwrap();
    }

    fn wide_of(p: &Path) -> Vec<u16> {
        wide(p).unwrap()
    }

    #[test]
    fn round_trip_and_second_update_sees_first() {
        let (td, dir) = setup();
        assert_eq!(read_locator(&dir, NAME), Ok(None));
        update_locator(&dir, NAME, |cur| {
            assert!(cur.is_none());
            Some(b"one".to_vec())
        })
        .unwrap();
        assert_eq!(read_locator(&dir, NAME), Ok(Some(b"one".to_vec())));
        update_locator(&dir, NAME, |cur| {
            assert_eq!(cur, Some(&b"one"[..]));
            Some(b"two".to_vec())
        })
        .unwrap();
        assert_eq!(read_locator(&dir, NAME), Ok(Some(b"two".to_vec())));
        // no temp file left behind
        assert_eq!(names(&td), vec![".lock".to_owned(), NAME.to_owned()]);
        update_locator(&dir, NAME, |_| None).unwrap();
        assert_eq!(read_locator(&dir, NAME), Ok(None));
    }

    fn open_for_read(path: &Path) -> OwnedHandle {
        create(
            &wide_of(path),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            None,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        )
        .unwrap()
    }

    #[test]
    fn created_files_are_owner_only_and_protected() {
        let (td, dir) = setup();
        put(&dir, b"x");
        let ours = our_sid().unwrap();
        for n in [NAME, ".lock"] {
            let h = open_for_read(&td.path().join(n));
            let (owner, dacl) = owner_and_dacl(HANDLE(h.as_raw_handle())).unwrap();
            assert_eq!(owner, ours, "{n}");
            assert_eq!(dacl.flags, "P", "{n}");
            assert_eq!(dacl.aces.len(), 1, "{n}");
            assert_eq!(dacl.aces[0].trustee, ours, "{n}");
            assert!(dacl.aces[0].flags.is_empty(), "{n}");
        }
    }

    #[test]
    fn oversize_output_is_refused_and_old_content_kept() {
        let (td, dir) = setup();
        put(&dir, b"old");
        let r = update_locator(&dir, NAME, |_| Some(vec![b'a'; MAX_LOCATOR_BYTES as usize + 1]));
        assert_eq!(r, Err(Disabled::OutputTooLarge));
        assert_eq!(read_locator(&dir, NAME), Ok(Some(b"old".to_vec())));
        // exactly the cap is fine
        put(&dir, &vec![b'b'; MAX_LOCATOR_BYTES as usize]);
        assert_eq!(names(&td), vec![".lock".to_owned(), NAME.to_owned()]);
    }

    #[test]
    fn directory_is_not_regular() {
        let (td, dir) = setup();
        std::fs::create_dir(td.path().join(NAME)).unwrap();
        assert_eq!(read_locator(&dir, NAME), Err(Disabled::Rejected(Reject::NotRegular)));
        assert_eq!(update_locator(&dir, NAME, |_| panic!("f must not run")), Err(Disabled::Rejected(Reject::NotRegular)));
    }

    #[test]
    fn hard_link_is_rejected() {
        let (td, dir) = setup();
        put(&dir, b"x");
        let link = wide_of(&td.path().join("other"));
        let orig = wide_of(&td.path().join(NAME));
        // SAFETY: both paths NUL-terminated.
        unsafe { CreateHardLinkW(PCWSTR(link.as_ptr()), PCWSTR(orig.as_ptr()), None) }.unwrap();
        assert_eq!(read_locator(&dir, NAME), Err(Disabled::Rejected(Reject::HardLinked)));
        // rewriting replaces the name, not the other link
        update_locator_rewriting(&dir, NAME, |cur| {
            assert!(cur.is_none());
            Some(b"fresh".to_vec())
        })
        .unwrap();
        assert_eq!(read_locator(&dir, NAME), Ok(Some(b"fresh".to_vec())));
        assert_eq!(std::fs::read(td.path().join("other")).unwrap(), b"x");
    }

    #[test]
    fn oversize_file_is_rejected() {
        let (td, dir) = setup();
        std::fs::write(td.path().join(NAME), vec![b'z'; MAX_LOCATOR_BYTES as usize + 1]).unwrap();
        assert_eq!(read_locator(&dir, NAME), Err(Disabled::Rejected(Reject::TooLarge)));
    }

    #[test]
    fn symlink_is_rejected_when_the_machine_allows_one() {
        let (td, dir) = setup();
        std::fs::write(td.path().join("target"), b"secret").unwrap();
        if std::os::windows::fs::symlink_file(td.path().join("target"), td.path().join(NAME)).is_err() {
            return; // no symlink privilege on this machine
        }
        assert_eq!(read_locator(&dir, NAME), Err(Disabled::Rejected(Reject::Symlink)));
        update_locator_rewriting(&dir, NAME, |cur| {
            assert!(cur.is_none());
            Some(b"fresh".to_vec())
        })
        .unwrap();
        assert_eq!(std::fs::read(td.path().join("target")).unwrap(), b"secret");
        assert_eq!(read_locator(&dir, NAME), Ok(Some(b"fresh".to_vec())));
    }

    #[test]
    fn extra_users_ace_is_wrong_mode() {
        let (td, dir) = setup();
        put(&dir, b"x");
        let ours = our_sid().unwrap();
        let mut sec = auth::PipeSecurity::from_sddl(&format!("O:{ours}D:P(A;;FA;;;{ours})(A;;GRGW;;;BU)")).unwrap();
        // SAFETY: `as_raw` points at the live SECURITY_ATTRIBUTES inside `sec`.
        let sd = unsafe { (*sec.as_raw().cast::<SECURITY_ATTRIBUTES>()).lpSecurityDescriptor };
        let path = wide_of(&td.path().join(NAME));
        // SAFETY: NUL-terminated path and a live descriptor.
        unsafe { SetFileSecurityW(PCWSTR(path.as_ptr()), DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR(sd)) }.unwrap();
        assert_eq!(read_locator(&dir, NAME), Err(Disabled::Rejected(Reject::WrongMode)));
        assert_eq!(update_locator(&dir, NAME, |_| panic!("f must not run")), Err(Disabled::Rejected(Reject::WrongMode)));
        // rewriting replaces the file with a fresh owner-only one
        update_locator_rewriting(&dir, NAME, |cur| {
            assert!(cur.is_none());
            Some(b"fresh".to_vec())
        })
        .unwrap();
        assert_eq!(read_locator(&dir, NAME), Ok(Some(b"fresh".to_vec())));
    }

    #[test]
    fn invalid_names() {
        let (_td, dir) = setup();
        for n in [
            "", ".", "..", "a:b", "hosts.json:stream", "a/b", "a\\b", "..\\x", "x.", "x ", "CON", "con", "nul.txt", "COM1",
            "lpt9.json", "AUX", "PRN", ".lock", ".LOCK", ".tmp-1", "a*b", "a\0b",
        ] {
            assert_eq!(read_locator(&dir, n), Err(Disabled::InvalidName), "{n:?}");
            assert_eq!(update_locator(&dir, n, |_| None), Err(Disabled::InvalidName), "{n:?}");
        }
        assert!(validate_name("hosts.json").is_ok());
        assert!(validate_name("console.json").is_ok());
    }

    fn hold_lock(dir: std::path::PathBuf, hold: Duration) -> (mpsc::Receiver<()>, std::thread::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel();
        let t = std::thread::spawn(move || {
            let g = acquire_lock(&CheckedDir::for_test(dir)).unwrap();
            tx.send(()).unwrap();
            std::thread::sleep(hold);
            drop(g);
        });
        (rx, t)
    }

    #[test]
    fn a_long_hold_makes_the_update_return_lock_busy_after_about_two_seconds() {
        let (td, dir) = setup();
        let (rx, t) = hold_lock(td.path().to_path_buf(), Duration::from_secs(3));
        rx.recv().unwrap();
        let start = Instant::now();
        let r = update_locator(&dir, NAME, |_| Some(b"x".to_vec()));
        let took = start.elapsed();
        assert_eq!(r, Err(Disabled::LockBusy));
        assert!(took >= Duration::from_millis(1900) && took < Duration::from_millis(2900), "{took:?}");
        t.join().unwrap();
        assert_eq!(read_locator(&dir, NAME), Ok(None));
    }

    #[test]
    fn a_short_hold_is_waited_out() {
        let (td, dir) = setup();
        let (rx, t) = hold_lock(td.path().to_path_buf(), Duration::from_millis(500));
        rx.recv().unwrap();
        update_locator(&dir, NAME, |_| Some(b"x".to_vec())).unwrap();
        t.join().unwrap();
        assert_eq!(read_locator(&dir, NAME), Ok(Some(b"x".to_vec())));
    }

    #[test]
    fn two_threads_lose_no_update() {
        let (td, dir) = setup();
        let dir = Arc::new(dir);
        let mut ts = Vec::new();
        for _ in 0..2 {
            let d = Arc::clone(&dir);
            ts.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    update_locator(&d, NAME, |cur| {
                        let n: u64 = cur.and_then(|b| std::str::from_utf8(b).ok()).and_then(|s| s.parse().ok()).unwrap_or(0);
                        Some((n + 1).to_string().into_bytes())
                    })
                    .unwrap();
                }
            }));
        }
        for t in ts {
            t.join().unwrap();
        }
        assert_eq!(read_locator(&dir, NAME), Ok(Some(b"100".to_vec())));
        assert_eq!(names(&td), vec![".lock".to_owned(), NAME.to_owned()]);
    }

    #[test]
    fn a_reader_during_replaces_never_sees_a_partial_or_empty_file() {
        let (_td, dir) = setup();
        put(&dir, &[b'a'; 4000]);
        let dir = Arc::new(dir);
        let writer = {
            let d = Arc::clone(&dir);
            std::thread::spawn(move || {
                for i in 0..200u32 {
                    let b = b'a' + (i % 26) as u8;
                    update_locator(&d, NAME, move |_| Some(vec![b; 4000])).unwrap();
                }
            })
        };
        let mut reads = 0u32;
        while !writer.is_finished() {
            let got = read_locator(&dir, NAME).unwrap().expect("present");
            assert_eq!(got.len(), 4000);
            assert!(got.iter().all(|&c| c == got[0]));
            reads += 1;
        }
        writer.join().unwrap();
        assert!(reads > 0);
    }

    #[test]
    fn sweep_removes_old_temp_case_insensitively_through_its_handle_and_keeps_fresh_ones() {
        let (td, dir) = setup();
        put(&dir, b"x");
        std::fs::rename(td.path().join(NAME), td.path().join(".TMP-9-1")).unwrap();
        put(&dir, b"y");
        std::fs::rename(td.path().join(NAME), td.path().join(".tmp-9-2")).unwrap();
        put(&dir, b"keep");
        // nothing is old enough yet
        assert_eq!(sweep_stale_temps(&dir, Duration::from_secs(3600), 10), Ok(0));
        assert!(td.path().join(".TMP-9-1").exists());
        assert_eq!(sweep_stale_temps(&dir, Duration::ZERO, 10), Ok(2));
        assert_eq!(names(&td), vec![".lock".to_owned(), NAME.to_owned()]);
        assert_eq!(read_locator(&dir, NAME), Ok(Some(b"keep".to_vec())));
    }

    #[test]
    fn a_peers_path_that_no_longer_names_the_held_directory_is_peers_moved_and_changes_nothing() {
        let held = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        std::fs::write(other.path().join("hosts.json"), b"theirs").unwrap();
        std::fs::write(other.path().join(".tmp-1-1"), b"stale").unwrap();
        let before = names(&other);
        let dir = CheckedDir::mismatched_for_test(held.path(), other.path().to_path_buf());
        assert_eq!(update_locator(&dir, NAME, |_| Some(b"mine".to_vec())), Err(Disabled::PeersMoved));
        assert_eq!(update_locator(&dir, NAME, |_| None), Err(Disabled::PeersMoved));
        assert_eq!(update_locator_rewriting(&dir, NAME, |_| None), Err(Disabled::PeersMoved));
        assert_eq!(read_locator(&dir, NAME), Err(Disabled::PeersMoved));
        assert_eq!(sweep_stale_temps(&dir, Duration::ZERO, 10), Err(Disabled::PeersMoved));
        assert_eq!(names(&other), before);
        assert_eq!(std::fs::read(other.path().join("hosts.json")).unwrap(), b"theirs");
        assert!(names(&held).is_empty());
    }
}
