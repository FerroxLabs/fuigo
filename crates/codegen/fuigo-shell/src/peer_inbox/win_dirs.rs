//! Windows `CheckedDir`: the checked `<home>\peers` directory (packet 15a; the Windows twin of the unix `dirs.rs`).
//! Windows only. The decisions are pure and live in `win_policy.rs` (`parse_home_path`, `dir_dacl_acceptable`,
//! `owner_acceptable`, `dir_kind_from_attrs`, `volume_has_acls`); this file only reads the OS facts that feed them.
//!
//! Every directory of the chain (drive root, each ancestor, the home, `peers`) is opened ONCE with
//! `CreateFileW(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)` and every fact (reparse point, directory,
//! volume ACL support, owner, DACL) is read from that HANDLE. ALL of these handles stay open inside [`CheckedDir`] with
//! a share mode WITHOUT `FILE_SHARE_DELETE` (round 1: an open child does NOT block the rename of its parent, so every
//! ancestor is pinned by its own handle), so none of them can be renamed or deleted while the inbox runs. Locator I/O
//! is by path string; [`CheckedDir::verify`] / [`CheckedDir::verify_file`] re-check, before and after each operation,
//! that the path still names the held `peers` directory (volume serial + 128-bit file id) and that an opened file lives
//! in it (`GetFinalPathNameByHandleW`); a mismatch is `Disabled::PeersMoved` and nothing is written or deleted.
//! Every Win32 failure is `Disabled::Io(code)`; nothing is logged and no string is built from file content.
//!
//! Owner rule: the owner SID is our user SID (compared with `EqualSid`), or BUILTIN\Administrators when our token is
//! elevated and has that group enabled: a directory created by an elevated administrator is owned by the
//! Administrators group by default, not by the user.

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows::Win32::Security::{
    ACL, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, SID_AND_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER, TokenElevation,
    TokenGroups, TokenUser, WinBuiltinAdministratorsSid,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_INFO_BY_HANDLE_CLASS, FILE_SHARE_MODE, GETFINALPATHNAMEBYHANDLE_FLAGS, GetDriveTypeW, GetFileInformationByHandle,
    GetFileInformationByHandleEx, GetFinalPathNameByHandleW, GetVolumeInformationByHandleW,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PCWSTR;

use super::win_policy::{
    DirDacl, DirKind, DirRole, RawAce, dir_dacl_acceptable, dir_kind_from_attrs, owner_acceptable, parse_home_path,
    raw_aces_from_summary, volume_has_acls,
};
use super::Disabled;
use crate::leader::peer_auth::win as auth;

const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;
const ERROR_ALREADY_EXISTS: u32 = 183;
const DRIVE_FIXED: u32 = 3;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const READ_CONTROL: u32 = 0x2_0000;
/// Kept handles: others may read and write entries but NOT delete or rename the directory.
const SHARE_KEPT: FILE_SHARE_MODE = FILE_SHARE_MODE(0x1 | 0x2);
/// Most components accepted in a home path (drive root included); each one costs a held handle.
const MAX_CHAIN: usize = 64;
/// `FILE_INFO_BY_HANDLE_CLASS` value of `FileIdInfo`.
const FILE_ID_INFO_CLASS: i32 = 18;
const OPEN_EXISTING: FILE_CREATION_DISPOSITION = FILE_CREATION_DISPOSITION(3);
// FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
const OPEN_DIR_FLAGS: FILE_FLAGS_AND_ATTRIBUTES = FILE_FLAGS_AND_ATTRIBUTES(0x0200_0000 | 0x0020_0000);

/// An open directory handle, closed on drop.
#[derive(Debug)]
struct DirHandle(HANDLE);
// SAFETY: a kernel handle is valid from any thread; this type has no interior state.
unsafe impl Send for DirHandle {}
unsafe impl Sync for DirHandle {}
impl Drop for DirHandle {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by `open_dir` and is closed exactly once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn io(code: u32) -> Disabled {
    Disabled::Io(code as i32)
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Open `path` as a directory-or-anything handle without following a final reparse point.
fn open_dir(path: &str, share: FILE_SHARE_MODE) -> Result<DirHandle, u32> {
    let w = wide(path);
    // SAFETY: `w` is NUL-terminated and outlives the call; no security attributes, no template.
    let h = unsafe {
        CreateFileW(PCWSTR(w.as_ptr()), FILE_READ_ATTRIBUTES | READ_CONTROL, share, None, OPEN_EXISTING, OPEN_DIR_FLAGS, None)
    }
    .map_err(|e| auth::code(&e))?;
    Ok(DirHandle(h))
}

fn attributes(h: &DirHandle) -> Result<u32, u32> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `h` is a live handle; `info` is a writable struct.
    unsafe { GetFileInformationByHandle(h.0, &mut info) }.map_err(|e| auth::code(&e))?;
    Ok(info.dwFileAttributes)
}

/// Who we are: user SID (token buffer and text), BUILTIN\Administrators, and whether that group is usable now.
struct Me {
    token_user: Vec<u64>,
    text: String,
    admins: [u64; 9],
    admins_usable: bool,
}

impl Me {
    fn current() -> Result<Me, u32> {
        let mut tok = HANDLE::default();
        // SAFETY: pseudo handle of this process needs no closing; `tok` is writable.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) }.map_err(|e| auth::code(&e))?;
        let tok = auth::Owned(tok);
        let token_user = auth::token_info_buf(tok.0, TokenUser)?;
        // SAFETY: on success the buffer starts with a TOKEN_USER whose SID points into the same buffer.
        let sid = unsafe { (*token_user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let text = auth::sid_to_string(sid)?;
        let mut admins = [0u64; 9];
        let mut size = 68u32; // SECURITY_MAX_SID_SIZE
        // SAFETY: `admins` is 72 writable bytes, at least `size`.
        unsafe { CreateWellKnownSid(WinBuiltinAdministratorsSid, None, Some(PSID(admins.as_mut_ptr().cast())), &mut size) }
            .map_err(|e| auth::code(&e))?;
        let mut me = Me { token_user, text, admins, admins_usable: false };
        me.admins_usable = me.compute_admins_usable(tok.0);
        Ok(me)
    }

    fn user(&self) -> PSID {
        // SAFETY: `token_user` holds a TOKEN_USER filled by the OS (checked in `current`).
        unsafe { (*self.token_user.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }

    fn admins_sid(&self) -> PSID {
        PSID(self.admins.as_ptr().cast_mut().cast::<c_void>())
    }

    /// The token is elevated AND BUILTIN\Administrators is an enabled (not deny-only) group of it.
    fn compute_admins_usable(&self, token: HANDLE) -> bool {
        let Ok(el) = auth::token_info_buf(token, TokenElevation) else { return false };
        // SAFETY: on success the buffer starts with a TOKEN_ELEVATION.
        if unsafe { (*el.as_ptr().cast::<TOKEN_ELEVATION>()).TokenIsElevated } == 0 {
            return false;
        }
        let Ok(buf) = auth::token_info_buf(token, TokenGroups) else { return false };
        let g = buf.as_ptr().cast::<TOKEN_GROUPS>();
        // SAFETY: the OS filled `GroupCount` entries of `Groups` inside the buffer.
        let groups = unsafe {
            std::slice::from_raw_parts(std::ptr::addr_of!((*g).Groups).cast::<SID_AND_ATTRIBUTES>(), (*g).GroupCount as usize)
        };
        // SE_GROUP_ENABLED = 0x4, SE_GROUP_USE_FOR_DENY_ONLY = 0x10
        groups.iter().any(|sa| {
            sa.Attributes & 0x4 != 0
                && sa.Attributes & 0x10 == 0
                // SAFETY: both pointers are valid SIDs (token buffer and `self.admins`).
                && unsafe { EqualSid(sa.Sid, self.admins_sid()) }.is_ok()
        })
    }
}

/// Frees a LocalAlloc'd security descriptor.
struct SdGuard(PSECURITY_DESCRIPTOR);
impl Drop for SdGuard {
    fn drop(&mut self) {
        // SAFETY: allocated by `GetSecurityInfo` with LocalAlloc; freed once.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

/// Owner and DACL facts of one open directory.
struct DirSecurity {
    owner_is_us: bool,
    owner_is_admins: bool,
    /// `None` = NULL DACL (everyone has full access).
    dacl: Option<(bool, Vec<RawAce>)>,
}

fn read_security(h: &DirHandle, me: &Me) -> Result<DirSecurity, u32> {
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `h` is a live handle opened with READ_CONTROL; `owner` and `dacl` point into `sd`, freed by the guard
    // only after the last use below.
    let status = unsafe {
        GetSecurityInfo(
            h.0,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            Some(&mut sd),
        )
    };
    if status.0 != 0 {
        return Err(status.0);
    }
    let _guard = SdGuard(sd);
    if owner.0.is_null() {
        return Err(0);
    }
    // SAFETY: `owner` is a valid SID inside `sd`; `me` SIDs are valid.
    let owner_is_us = unsafe { EqualSid(owner, me.user()) }.is_ok();
    let owner_is_admins = unsafe { EqualSid(owner, me.admins_sid()) }.is_ok();
    if dacl.is_null() {
        return Ok(DirSecurity { owner_is_us, owner_is_admins, dacl: None });
    }
    let (_owner_text, summary) = super::win_pipe::sys::read_owner_dacl(sd, owner, dacl)?;
    let parsed = raw_aces_from_summary(&summary).ok_or(0u32)?;
    Ok(DirSecurity { owner_is_us, owner_is_admins, dacl: Some(parsed) })
}

fn dacl_ok(sec: &DirSecurity, role: DirRole, me: &Me) -> bool {
    match &sec.dacl {
        None => dir_dacl_acceptable(role, &DirDacl::Null, &me.text),
        Some((protected, aces)) => dir_dacl_acceptable(role, &DirDacl::Aces { protected: *protected, aces }, &me.text),
    }
}

fn is_missing(code: u32) -> bool {
    code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND
}

/// Create `path` with an explicit PROTECTED DACL: full control (inherited by files and subdirectories) for us only.
fn create_private_dir(path: &str, me: &Me) -> Result<(), u32> {
    let mut sec = auth::PipeSecurity::from_sddl(&format!("D:P(A;OICI;FA;;;{})", me.text))
        .map_err(|e| e.raw_os_error().unwrap_or(0) as u32)?;
    let w = wide(path);
    // SAFETY: `w` is NUL-terminated; `sec` owns the descriptor `as_raw` points at until it drops after the call.
    let r = unsafe { CreateDirectoryW(PCWSTR(w.as_ptr()), Some(sec.as_raw().cast::<SECURITY_ATTRIBUTES>().cast_const())) };
    match r {
        Ok(()) => Ok(()),
        Err(e) => {
            let c = auth::code(&e);
            if c == ERROR_ALREADY_EXISTS { Ok(()) } else { Err(c) }
        }
    }
}

/// Every directory handle of the chain, all opened without `FILE_SHARE_DELETE`.
#[derive(Debug)]
struct Held {
    /// Drive root down to the home's parent.
    _ancestors: Vec<DirHandle>,
    _home: DirHandle,
    peers: DirHandle,
}

/// Volume serial number and 128-bit file id of an open handle (`FILE_ID_INFO`).
fn file_id(h: HANDLE) -> Result<(u64, [u8; 16]), u32> {
    #[repr(C)]
    struct IdInfo {
        volume: u64,
        id: [u8; 16],
    }
    let mut info = IdInfo { volume: 0, id: [0; 16] };
    // SAFETY: live handle; `info` has the layout of FILE_ID_INFO (u64 + 16 bytes) and the size passed is its size.
    unsafe {
        GetFileInformationByHandleEx(
            h,
            FILE_INFO_BY_HANDLE_CLASS(FILE_ID_INFO_CLASS),
            std::ptr::addr_of_mut!(info).cast::<c_void>(),
            std::mem::size_of::<IdInfo>() as u32,
        )
    }
    .map_err(|e| auth::code(&e))?;
    Ok((info.volume, info.id))
}

/// The final (normalised, DOS) path of an open handle, as UTF-16 units.
fn final_path(h: HANDLE) -> Result<Vec<u16>, u32> {
    let mut buf = vec![0u16; 1024];
    for _ in 0..2 {
        // SAFETY: live handle; `buf` is a writable slice of the length the API is told.
        let n = unsafe { GetFinalPathNameByHandleW(h, &mut buf, GETFINALPATHNAMEBYHANDLE_FLAGS(0)) } as usize;
        if n == 0 {
            return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32);
        }
        if n < buf.len() {
            buf.truncate(n);
            return Ok(buf);
        }
        buf = vec![0u16; n + 1];
    }
    Err(0)
}

/// The checked `<home>\peers` directory. Holds every directory handle of the chain (no `FILE_SHARE_DELETE`).
#[derive(Debug)]
pub(crate) struct CheckedDir {
    path: PathBuf,
    held: Option<Held>,
}

impl CheckedDir {
    /// Open `<home>\peers`, checking the path, every ancestor, the home and the directory itself. Never creates anything.
    pub(crate) fn open(home: &Path) -> Result<CheckedDir, Disabled> {
        Self::open_inner(home, false, 0)
    }

    /// Like [`open`](Self::open), but creates `peers` (owner-only protected DACL) when it is missing. The home itself must exist.
    pub(crate) fn create_or_open(home: &Path) -> Result<CheckedDir, Disabled> {
        Self::open_inner(home, true, 0)
    }

    /// Tests only: `create_or_open` with the ancestors below chain index `dacl_from` trusted for their DACL (see `open_inner`).
    #[cfg(test)]
    pub(crate) fn create_or_open_trusting(home: &Path, dacl_from: usize) -> Result<CheckedDir, Disabled> {
        Self::open_inner(home, true, dacl_from)
    }

    /// There is no unix-style runtime directory on Windows.
    pub(crate) fn create_under(_base: &Path, _levels: &[&str]) -> Result<CheckedDir, Disabled> {
        Err(Disabled::RuntimeDirUnavailable)
    }

    /// Absolute path of the checked `peers` directory.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// No checks at all: for tests of other modules.
    #[cfg(test)]
    pub(crate) fn for_test(path: PathBuf) -> CheckedDir {
        CheckedDir { path, held: None }
    }

    /// Tests only: a dir whose held `peers` handle is `held_dir` while its path string names `path` (what a directory
    /// swapped after the check looks like).
    #[cfg(all(test, windows))]
    pub(crate) fn mismatched_for_test(held_dir: &Path, path: PathBuf) -> CheckedDir {
        let open = || open_dir(held_dir.to_str().unwrap(), SHARE_KEPT).expect("open held dir");
        CheckedDir { path, held: Some(Held { _ancestors: Vec::new(), _home: open(), peers: open() }) }
    }

    /// Is `path` still the directory that was checked? Re-opens it (not following a final reparse point) and compares
    /// its volume serial + file id with the held handle. Any difference or failure is `PeersMoved`. Nothing held
    /// (tests of other modules) is accepted.
    pub(crate) fn verify(&self) -> Result<(), Disabled> {
        let Some(held) = &self.held else { return Ok(()) };
        let now = open_dir(self.path.to_str().ok_or(Disabled::PeersMoved)?, FILE_SHARE_MODE(0x1 | 0x2 | 0x4))
            .map_err(|_| Disabled::PeersMoved)?;
        let a = file_id(held.peers.0).map_err(|_| Disabled::PeersMoved)?;
        let b = file_id(now.0).map_err(|_| Disabled::PeersMoved)?;
        if a == b { Ok(()) } else { Err(Disabled::PeersMoved) }
    }

    /// Does the open file `file` live directly in the held `peers` directory under the name `name`? Compares the
    /// handle's final path with the held directory's final path plus `\name` (case-insensitive).
    pub(crate) fn verify_file(&self, file: HANDLE, name: &str) -> Result<(), Disabled> {
        let Some(held) = &self.held else { return Ok(()) };
        let dir = final_path(held.peers.0).map_err(|_| Disabled::PeersMoved)?;
        let f = final_path(file).map_err(|_| Disabled::PeersMoved)?;
        let lower = |v: &[u16]| String::from_utf16_lossy(v).to_lowercase();
        let want = format!("{}\\{}", lower(&dir), name.to_lowercase());
        if lower(&f) == want { Ok(()) } else { Err(Disabled::PeersMoved) }
    }

    /// `dacl_from`: ancestors with a chain index below it are checked for reparse point / directory only, not for their
    /// DACL. Production always passes 0; tests pass the depth of their temp root, because the machine's shared temp
    /// directories (for example `F:\Temp`, where Authenticated Users have Modify) are exactly what the rule refuses.
    fn open_inner(home: &Path, create: bool, dacl_from: usize) -> Result<CheckedDir, Disabled> {
        let text = home.to_str().ok_or(Disabled::HomePathNotNormal)?;
        let chain = parse_home_path(text)?;
        if chain.len() > MAX_CHAIN {
            return Err(Disabled::HomePathNotNormal);
        }
        let me = Me::current().map_err(io)?;
        let root = wide(&chain[0]);
        // SAFETY: `root` is NUL-terminated.
        if unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) } != DRIVE_FIXED {
            return Err(Disabled::HomePathNotNormal);
        }
        let last = chain.len() - 1;
        let mut ancestors = Vec::with_capacity(last);
        for (i, p) in chain[..last].iter().enumerate() {
            // Kept open (no FILE_SHARE_DELETE) for the life of the CheckedDir: pins the ancestor against rename.
            let h = open_dir(p, SHARE_KEPT).map_err(|c| if is_missing(c) { Disabled::AncestorMissing } else { io(c) })?;
            match dir_kind_from_attrs(attributes(&h).map_err(io)?) {
                DirKind::Reparse => return Err(Disabled::AncestorSymlink),
                DirKind::NotDirectory => return Err(Disabled::AncestorNotDirectory),
                DirKind::Directory => {}
            }
            if i >= dacl_from {
                let sec = read_security(&h, &me).map_err(io)?;
                if !dacl_ok(&sec, DirRole::Ancestor, &me) {
                    return Err(Disabled::AncestorWritableByOthers);
                }
            }
            ancestors.push(h);
        }

        let home_h = open_dir(&chain[last], SHARE_KEPT).map_err(|c| if is_missing(c) { Disabled::HomeMissing } else { io(c) })?;
        match dir_kind_from_attrs(attributes(&home_h).map_err(io)?) {
            DirKind::Reparse => return Err(Disabled::SymlinkedHome),
            DirKind::NotDirectory => return Err(Disabled::HomeNotDirectory),
            DirKind::Directory => {}
        }
        let mut fs_flags = 0u32;
        // SAFETY: live handle; only the flags out parameter is requested.
        unsafe { GetVolumeInformationByHandleW(home_h.0, None, None, None, Some(&mut fs_flags), None) }
            .map_err(|e| io(auth::code(&e)))?;
        if !volume_has_acls(fs_flags) {
            return Err(Disabled::HomeWritableByOthers);
        }
        let sec = read_security(&home_h, &me).map_err(io)?;
        if !owner_acceptable(sec.owner_is_us, sec.owner_is_admins, me.admins_usable) {
            return Err(Disabled::HomeWrongOwner);
        }
        if !dacl_ok(&sec, DirRole::Home, &me) {
            return Err(Disabled::HomeWritableByOthers);
        }

        // The home handle (no FILE_SHARE_DELETE) pins the home, so `peers` is created and opened by path safely.
        let peers_path = format!("{}\\peers", chain[last]);
        let peers_h = match open_dir(&peers_path, SHARE_KEPT) {
            Ok(h) => h,
            Err(c) if is_missing(c) => {
                if !create {
                    return Err(Disabled::PeersMissing);
                }
                create_private_dir(&peers_path, &me).map_err(io)?;
                open_dir(&peers_path, SHARE_KEPT).map_err(io)?
            }
            Err(c) => return Err(io(c)),
        };
        match dir_kind_from_attrs(attributes(&peers_h).map_err(io)?) {
            DirKind::Reparse => return Err(Disabled::PeersSymlink),
            DirKind::NotDirectory => return Err(Disabled::PeersNotDirectory),
            DirKind::Directory => {}
        }
        let sec = read_security(&peers_h, &me).map_err(io)?;
        if !owner_acceptable(sec.owner_is_us, sec.owner_is_admins, me.admins_usable) {
            return Err(Disabled::PeersWrongOwner);
        }
        if !dacl_ok(&sec, DirRole::Peers, &me) {
            return Err(Disabled::PeersWrongMode);
        }
        Ok(CheckedDir { path: PathBuf::from(peers_path), held: Some(Held { _ancestors: ancestors, _home: home_h, peers: peers_h }) })
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::fs;

    fn private_root() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    /// `open` / `create_or_open` for a home under `root`: ancestors at or above `root` are trusted for their DACL.
    fn open_in(root: &Path, home: &Path, create: bool) -> Result<CheckedDir, Disabled> {
        let depth = parse_home_path(root.to_str().unwrap()).unwrap().len();
        CheckedDir::open_inner(home, create, depth)
    }

    fn me_text() -> String {
        Me::current().expect("token").text
    }

    /// Create `path` with the given SDDL as its DACL (a Win32 call, no `icacls`).
    fn mkdir_sddl(path: &Path, sddl: &str) {
        let mut sec = auth::PipeSecurity::from_sddl(sddl).expect("sddl");
        let w = wide(path.to_str().unwrap());
        // SAFETY: NUL-terminated name; descriptor lives in `sec` across the call.
        unsafe { CreateDirectoryW(PCWSTR(w.as_ptr()), Some(sec.as_raw().cast::<SECURITY_ATTRIBUTES>().cast_const())) }
            .expect("CreateDirectoryW");
    }

    fn owner_only_home(root: &Path, name: &str) -> PathBuf {
        let home = root.join(name);
        mkdir_sddl(&home, &format!("D:P(A;OICI;FA;;;{})", me_text()));
        home
    }

    #[test]
    fn owner_only_home_is_accepted_and_peers_created_then_reopened() {
        let root = private_root();
        let home = owner_only_home(root.path(), "home");
        assert!(matches!(open_in(root.path(), &home, false), Err(Disabled::PeersMissing)));
        let made = open_in(root.path(), &home, true).expect("create_or_open");
        assert_eq!(made.path(), home.join("peers"));
        assert!(made.path().is_dir());
        let again = open_in(root.path(), &home, false).expect("open");
        assert_eq!(again.path(), made.path());
        drop(open_in(root.path(), &home, true).expect("idempotent"));
        // the held handles do not allow the directory to be renamed
        assert!(fs::rename(&home, root.path().join("moved")).is_err());
        drop((made, again));
        assert!(fs::rename(&home, root.path().join("moved")).is_ok());
    }

    #[test]
    fn default_inherited_home_is_accepted() {
        let root = private_root();
        let home = root.path().join("h");
        // what a default profile directory looks like: us, SYSTEM and Administrators with full control
        mkdir_sddl(&home, &format!("D:(A;OICI;FA;;;{})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", me_text()));
        let r = open_in(root.path(), &home, true);
        assert!(r.is_ok(), "{r:?}");
    }

    #[test]
    fn home_with_users_modify_is_refused() {
        let root = private_root();
        let home = root.path().join("shared");
        // Users:(M) = modify (0x1301bf) for BUILTIN\Users
        mkdir_sddl(&home, &format!("D:P(A;OICI;FA;;;{})(A;OICI;0x1301bf;;;BU)", me_text()));
        assert!(matches!(open_in(root.path(), &home, true), Err(Disabled::HomeWritableByOthers)));
    }

    #[test]
    fn inherit_only_and_read_only_strangers_do_not_refuse_the_home() {
        let root = private_root();
        let home = root.path().join("ro");
        mkdir_sddl(&home, &format!("D:P(A;OICI;FA;;;{})(A;OICI;GR;;;BU)(A;OICIIO;0x1301bf;;;AU)", me_text()));
        let r = open_in(root.path(), &home, true);
        assert!(r.is_ok(), "{r:?}");
    }

    #[test]
    fn existing_peers_with_extra_access_is_refused() {
        let root = private_root();
        let home = owner_only_home(root.path(), "home");
        let peers = home.join("peers");
        mkdir_sddl(&peers, &format!("D:P(A;OICI;FA;;;{})(A;OICI;GR;;;BU)", me_text()));
        assert!(matches!(open_in(root.path(), &home, false), Err(Disabled::PeersWrongMode)));
        // an inherited (unprotected) peers directory is refused too
        let home2 = owner_only_home(root.path(), "home2");
        fs::create_dir(home2.join("peers")).unwrap();
        assert!(matches!(open_in(root.path(), &home2, true), Err(Disabled::PeersWrongMode)));
    }

    #[test]
    fn missing_and_not_directory() {
        let root = private_root();
        assert!(matches!(open_in(root.path(), &root.path().join("nope"), false), Err(Disabled::HomeMissing)));
        let file = root.path().join("f");
        fs::write(&file, b"x").unwrap();
        assert!(matches!(open_in(root.path(), &file, false), Err(Disabled::HomeNotDirectory)));
        assert!(matches!(open_in(root.path(), &root.path().join("nope").join("deeper"), false), Err(Disabled::AncestorMissing)));
    }

    #[test]
    fn ancestor_rules_apply_below_the_trusted_root() {
        let root = private_root();
        let me = me_text();
        // a shared directory (Users:(M) modify) above the home: refused
        let shared = root.path().join("shared");
        mkdir_sddl(&shared, &format!("D:P(A;OICI;FA;;;{me})(A;OICI;0x1301bf;;;BU)"));
        let home = shared.join("home");
        mkdir_sddl(&home, &format!("D:P(A;OICI;FA;;;{me})"));
        assert!(matches!(open_in(root.path(), &home, true), Err(Disabled::AncestorWritableByOthers)));
        // a read-only-for-others ancestor is fine
        let calm = root.path().join("calm");
        mkdir_sddl(&calm, &format!("D:P(A;OICI;FA;;;{me})(A;OICI;GR;;;BU)(A;OICI;FA;;;SY)"));
        let home = calm.join("home");
        mkdir_sddl(&home, &format!("D:P(A;OICI;FA;;;{me})"));
        let r = open_in(root.path(), &home, true);
        assert!(r.is_ok(), "{r:?}");
        // DELETE for a stranger on the direct parent
        let del = root.path().join("del");
        mkdir_sddl(&del, &format!("D:P(A;OICI;FA;;;{me})(A;OICI;SDRC;;;BU)"));
        let home = del.join("home");
        mkdir_sddl(&home, &format!("D:P(A;OICI;FA;;;{me})"));
        assert!(matches!(open_in(root.path(), &home, true), Err(Disabled::AncestorWritableByOthers)));
        // ... and, since round 1, on any higher ancestor too
        let outer = root.path().join("outer");
        mkdir_sddl(&outer, &format!("D:P(A;OICI;FA;;;{me})(A;OICI;SDRC;;;BU)"));
        let inner = outer.join("inner");
        mkdir_sddl(&inner, &format!("D:P(A;OICI;FA;;;{me})"));
        let home = inner.join("home");
        mkdir_sddl(&home, &format!("D:P(A;OICI;FA;;;{me})"));
        let r = open_in(root.path(), &home, true);
        assert!(matches!(r, Err(Disabled::AncestorWritableByOthers)), "{r:?}");
    }

    #[test]
    fn bad_paths_are_refused_before_any_file_access() {
        assert!(matches!(CheckedDir::open(Path::new(r"relative\dir")), Err(Disabled::HomeNotAbsolute)));
        assert!(matches!(CheckedDir::open(Path::new(r"C:\Users\..\Users")), Err(Disabled::HomePathNotNormal)));
        assert!(matches!(CheckedDir::open(Path::new(r"\\server\share\x")), Err(Disabled::HomePathNotNormal)));
        assert!(matches!(CheckedDir::open(Path::new(r"\\?\C:\Windows")), Err(Disabled::HomePathNotNormal)));
        assert!(matches!(CheckedDir::open(Path::new(r"\\.\C:\Windows")), Err(Disabled::HomePathNotNormal)));
        assert!(matches!(CheckedDir::create_under(Path::new(r"C:\x"), &["a"]), Err(Disabled::RuntimeDirUnavailable)));
    }

    /// Make a junction with `cmd /C mklink /J` (no privilege needed). Fails the test when it cannot be made.
    fn junction(link: &Path, target: &Path) {
        let out = std::process::Command::new("cmd").args(["/C", "mklink", "/J"]).arg(link).arg(target).output();
        let ok = out.as_ref().is_ok_and(|o| o.status.success());
        assert!(ok, "could not create a junction with `mklink /J` (a normal user can): {out:?}");
    }

    #[test]
    fn junction_or_symlink_as_home_or_ancestor_is_refused() {
        let root = private_root();
        let real = owner_only_home(root.path(), "real");
        fs::create_dir(real.join("sub")).unwrap();
        let link = root.path().join("link");
        junction(&link, &real);
        assert!(matches!(open_in(root.path(), &link, false), Err(Disabled::SymlinkedHome)));
        assert!(matches!(open_in(root.path(), &link.join("sub"), false), Err(Disabled::AncestorSymlink)));
        // A directory symlink needs a privilege a normal account may lack: exercised only where it can be made.
        let sym = root.path().join("sym");
        if std::os::windows::fs::symlink_dir(&real, &sym).is_ok() {
            assert!(matches!(open_in(root.path(), &sym, false), Err(Disabled::SymlinkedHome)));
        }
    }

    #[test]
    fn every_ancestor_is_pinned_while_a_checked_dir_lives() {
        let root = private_root();
        let outer = root.path().join("outer");
        mkdir_sddl(&outer, &format!("D:P(A;OICI;FA;;;{})", me_text()));
        let mid = outer.join("mid");
        mkdir_sddl(&mid, &format!("D:P(A;OICI;FA;;;{})", me_text()));
        let home = mid.join("home");
        mkdir_sddl(&home, &format!("D:P(A;OICI;FA;;;{})", me_text()));
        let dir = open_in(root.path(), &home, true).expect("open");
        // grandparent, parent and the drive-level ancestors cannot be renamed
        let moved = root.path().join("outer-moved");
        let e = fs::rename(&outer, &moved).expect_err("grandparent rename must fail");
        // The OS reports a sharing violation (32) or access denied (5) depending on the object; the proof that the pin is the
        // cause is that the same rename succeeds once the CheckedDir is dropped (asserted below).
        assert!(matches!(e.raw_os_error(), Some(5 | 32)), "{e:?}");
        assert!(fs::rename(&mid, outer.join("mid-moved")).is_err());
        assert!(fs::rename(root.path(), root.path().with_extension("moved")).is_err());
        drop(dir);
        assert!(fs::rename(&outer, &moved).is_ok());
    }

    #[test]
    fn too_deep_home_is_refused() {
        let mut p = PathBuf::from(r"C:\");
        for i in 0..70 {
            p.push(format!("d{i}"));
        }
        assert!(matches!(CheckedDir::open(&p), Err(Disabled::HomePathNotNormal)));
    }

    /// SDDL-style one-line summary of a directory's owner and DACL.
    fn summary(sec: &DirSecurity) -> String {
        let owner = if sec.owner_is_us { "us" } else if sec.owner_is_admins { "BA" } else { "other" };
        match &sec.dacl {
            None => format!("O:{owner} D:NULL"),
            Some((protected, aces)) => {
                let list: Vec<String> =
                    aces.iter().map(|a| format!("({};{:#x};{:#x};{})", a.ace_type, a.flags, a.mask, a.trustee_sid)).collect();
                format!("O:{owner} D:{}{}", if *protected { "P" } else { "" }, list.join(""))
            }
        }
    }

    /// The real profile directory of the current user, asked from the OS for this process's token. Not `%USERPROFILE%`:
    /// a test lane may redirect that variable to a directory whose parent is not a default Windows directory.
    fn os_profile_dir() -> String {
        #[link(name = "userenv")]
        unsafe extern "system" {
            fn GetUserProfileDirectoryW(token: *mut core::ffi::c_void, dir: *mut u16, size: *mut u32) -> i32;
        }
        let mut tok = HANDLE::default();
        // SAFETY: the pseudo-handle of this process is always valid; `tok` is a valid out-pointer.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) }.expect("process token");
        let mut buf = vec![0u16; 1024];
        let mut len = 1024u32;
        // SAFETY: `buf` holds `len` UTF-16 units and `len` is a valid in/out pointer; the token handle is open.
        let ok = unsafe { GetUserProfileDirectoryW(tok.0.cast(), buf.as_mut_ptr(), &mut len) };
        // SAFETY: `tok` was opened above and is closed exactly once.
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(tok) };
        assert!(ok != 0, "GetUserProfileDirectoryW failed");
        let n = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..n])
    }

    fn live_levels() -> Vec<(String, String, bool)> {
        let me = Me::current().expect("token");
        let profile = os_profile_dir();
        let drive = Path::new(&profile).ancestors().last().unwrap().to_string_lossy().into_owned();
        let users = Path::new(&profile).parent().unwrap().to_string_lossy().into_owned();
        [drive, users, profile]
            .into_iter()
            .map(|p| {
                let h = open_dir(&p, SHARE_KEPT).expect("open");
                let sec = read_security(&h, &me).expect("read_security");
                let ok = dacl_ok(&sec, DirRole::Ancestor, &me);
                (p, summary(&sec), ok)
            })
            .collect()
    }

    /// The live default ACLs of this machine: the ancestor rule must accept `C:\`, `C:\Users` and the profile
    /// directory, or a default install would not start (the audit's "a live machine ACL was not read").
    #[test]
    fn live_default_acls_pass_the_ancestor_rule() {
        for (p, sum, ok) in live_levels() {
            assert!(ok, "the ancestor rule refuses the live default ACL of {p}: {sum}");
        }
    }

    #[test]
    fn current_identity_is_readable() {
        let me = Me::current().expect("token");
        assert!(super::super::win_policy::is_sid_text(&me.text));
        let _ = me.admins_usable;
    }
}
