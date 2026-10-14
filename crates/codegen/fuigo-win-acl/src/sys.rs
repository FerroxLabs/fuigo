//! The OS-calling part (Windows only): the SID and token helpers, the bounded binary ACE reader, and the file check.
//! The helpers and the reader are moved unchanged from `fuigo-shell` (`leader/peer_auth.rs`, `peer_inbox/win_pipe.rs`,
//! `peer_inbox/win_locator.rs`).

use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::sync::OnceLock;

use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, GetSecurityInfo, SE_KERNEL_OBJECT};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION, GetAce,
    GetAclInformation, GetSecurityDescriptorControl, GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    PSID, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_TYPE_DISK, GetFileInformationByHandle,
    GetDriveTypeW, GetFileType,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{PCWSTR, PWSTR};

use crate::policy::{DaclSummary, RawAce, dacl_summary_from_binary, locator_dacl_ok, locator_owner_ok};

pub fn code(e: &windows::core::Error) -> u32 {
    (e.code().0 as u32) & 0xFFFF
}

pub struct Owned(pub HANDLE);
impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by this module and is closed once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// `S-1-...` text of a SID.
pub fn sid_to_string(sid: PSID) -> Result<String, u32> {
    let mut text = PWSTR::null();
    // SAFETY: `sid` points at a valid SID owned by the caller; `text` receives a LocalAlloc'd string.
    unsafe { ConvertSidToStringSidW(sid, &mut text) }.map_err(|e| code(&e))?;
    // SAFETY: on success `text` is a NUL-terminated wide string.
    let s = unsafe { text.to_string() }.map_err(|_| 0u32);
    // SAFETY: the string was allocated by the call above with LocalAlloc.
    let _ = unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
    s
}

/// The raw bytes of one `GetTokenInformation` class (8-byte aligned), or the Win32 error.
pub fn token_info_buf(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Result<Vec<u64>, u32> {
    let mut needed = 0u32;
    // SAFETY: size probe; the expected failure is "insufficient buffer" and sets `needed`.
    let _ = unsafe { GetTokenInformation(token, class, None, 0, &mut needed) };
    if needed == 0 {
        return Err(0);
    }
    // u64 elements: the buffer is at least 8-byte aligned for TOKEN_USER and the other token structs.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: `buf` holds at least `needed` bytes.
    unsafe { GetTokenInformation(token, class, Some(buf.as_mut_ptr().cast()), needed, &mut needed) }
        .map_err(|e| code(&e))?;
    Ok(buf)
}

/// The user SID text of an open token (needs `TOKEN_QUERY`).
pub fn token_user_sid(token: HANDLE) -> Result<String, u32> {
    let buf = token_info_buf(token, TokenUser)?;
    // SAFETY: on success the buffer starts with a TOKEN_USER whose SID points into the same buffer.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    sid_to_string(sid)
}

/// The token user SID text of the process behind `process` (needs `PROCESS_QUERY_LIMITED_INFORMATION`).
pub fn process_token_user_sid(process: HANDLE) -> Result<String, u32> {
    let mut token = HANDLE::default();
    // SAFETY: `process` is a live process handle; `token` is writable.
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.map_err(|e| code(&e))?;
    let token = Owned(token);
    token_user_sid(token.0)
}

/// The user account of this process.
pub fn own_sid() -> Result<String, u32> {
    // SAFETY: the pseudo handle of the current process needs no closing.
    process_token_user_sid(unsafe { GetCurrentProcess() })
}

/// Owner and DACL of a kernel object, read from the BINARY descriptor (no SDDL text, so no well-known-SID aliases):
/// the owner and every trustee are rendered with `ConvertSidToStringSidW`, the ACE type, flags and mask are the
/// numbers in the ACL, and "protected" is the `SE_DACL_PROTECTED` control bit. Any shape we do not understand is an error.
pub fn owner_and_dacl(handle: HANDLE) -> Result<(String, DaclSummary), u32> {
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    // SAFETY: `handle` is a live pipe handle; `owner` and `dacl` point into `sd`, a LocalAlloc'd descriptor that is
    // freed only after the last use below.
    let status =
        unsafe { GetSecurityInfo(handle, SE_KERNEL_OBJECT, info, Some(&mut owner), None, Some(&mut dacl), None, Some(&mut sd)) };
    if status.0 != 0 {
        return Err(status.0);
    }
    let r = read_owner_dacl(sd, owner, dacl);
    // SAFETY: `sd` was allocated by GetSecurityInfo with LocalAlloc and nothing borrowed from it is used again.
    let _ = unsafe { LocalFree(Some(HLOCAL(sd.0))) };
    r
}

/// The part of [`owner_and_dacl`] that borrows from the descriptor. `dacl` NULL (no DACL = everyone) is an error.
pub fn read_owner_dacl(sd: PSECURITY_DESCRIPTOR, owner: PSID, dacl: *mut ACL) -> Result<(String, DaclSummary), u32> {
    if owner.0.is_null() || dacl.is_null() {
        return Err(0);
    }
    let owner_text = sid_to_string(owner)?;
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: `sd` is the live descriptor from GetSecurityInfo; both out pointers are writable locals.
    unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) }.map_err(|e| code(&e))?;
    let mut size = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` is a valid ACL inside `sd`; `size` is a writable ACL_SIZE_INFORMATION of the stated length.
    unsafe {
        GetAclInformation(
            dacl,
            (&mut size as *mut ACL_SIZE_INFORMATION).cast::<c_void>(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    }
    .map_err(|e| code(&e))?;
    if size.AceCount > 16 {
        return Err(0);
    }
    let min = (std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart) + 8) as u16;
    let mut aces = Vec::new();
    for i in 0..size.AceCount {
        let mut p: *mut c_void = std::ptr::null_mut();
        // SAFETY: `dacl` is valid and `i` is below the AceCount just read; `p` receives a pointer INTO the ACL.
        unsafe { GetAce(dacl, i, &mut p) }.map_err(|e| code(&e))?;
        if p.is_null() {
            return Err(0);
        }
        // SAFETY: every ACE starts with an ACE_HEADER; `p` points at one inside the live ACL (alignment 4).
        let header = unsafe { p.cast::<ACE_HEADER>().read() };
        if header.AceSize < min {
            return Err(0);
        }
        // Only the two basic ACE kinds (ACCESS_ALLOWED_ACE_TYPE = 0, ACCESS_DENIED_ACE_TYPE = 1) have the layout
        // { Header, Mask, Sid }. Object ACEs and anything unknown are reported by type alone: no Mask and no SID is
        // read from them, and the policy refuses every type that is not a plain allow.
        if header.AceType > 1 {
            aces.push(RawAce { ace_type: header.AceType, flags: header.AceFlags, mask: 0, trustee_sid: String::new() });
            continue;
        }
        let ace = p.cast::<ACCESS_ALLOWED_ACE>();
        // SAFETY: the header says the ACE is at least `min` bytes, which covers Header, Mask and the first 8 SID bytes.
        let mask = unsafe { std::ptr::addr_of!((*ace).Mask).read() };
        // SAFETY: only the address of `SidStart` is taken (no read); it lies inside the `min` bytes checked above.
        let sid_ptr = unsafe { std::ptr::addr_of_mut!((*ace).SidStart) }.cast::<u8>();
        // A SID is { Revision: u8, SubAuthorityCount: u8, IdentifierAuthority: [u8; 6], SubAuthority: [u32; count] }.
        // SAFETY: byte 1 of the SID is inside the first 8 SID bytes, which `min` guarantees are inside the ACE.
        let sub_count = usize::from(unsafe { sid_ptr.add(1).read() });
        let sid_len = 8 + 4 * sub_count;
        let sid_off = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        // The whole SID must lie inside this ACE before anything walks it (at most 15 sub-authorities exist).
        if sub_count > 15 || sid_off + sid_len > usize::from(header.AceSize) {
            return Err(0);
        }
        let sid = PSID(sid_ptr.cast::<c_void>());
        // A SID that does not convert makes the trustee empty, which matches nothing (fails closed).
        let trustee_sid = sid_to_string(sid).unwrap_or_default();
        aces.push(RawAce { ace_type: header.AceType, flags: header.AceFlags, mask, trustee_sid });
    }
    Ok((owner_text, dacl_summary_from_binary(control & 0x1000 != 0, &aces)))
}

/// The user SID text of this process (cached).
pub fn our_sid() -> Result<&'static str, u32> {
    static SID: OnceLock<Result<String, u32>> = OnceLock::new();
    match SID.get_or_init(own_sid) {
        Ok(s) => Ok(s.as_str()),
        Err(c) => Err(*c),
    }
}

/// Is our token elevated? (An elevated process owns what it creates as BUILTIN\Administrators by default.)
pub fn token_elevated() -> bool {
    static ELEVATED: OnceLock<bool> = OnceLock::new();
    *ELEVATED.get_or_init(|| {
        let mut token = HANDLE::default();
        // SAFETY: the pseudo handle of the current process needs no closing; `token` is writable.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
            return false;
        }
        let token = Owned(token);
        match token_info_buf(token.0, TokenElevation) {
            // SAFETY: on success the buffer starts with a TOKEN_ELEVATION (8-byte aligned storage).
            Ok(buf) => unsafe { (*buf.as_ptr().cast::<TOKEN_ELEVATION>()).TokenIsElevated != 0 },
            Err(_) => false,
        }
    })
}

/// Why an open file was not accepted. `Io` carries the raw Win32 error code of the call that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAclRefusal {
    /// A Win32 call failed: file information, our own SID, or the owner and DACL could not be read (or have a shape
    /// we do not understand, code 0 excepted: see `OtherPrincipals`).
    Io(i32),
    /// The handle is a reparse point (symlink, junction, ...).
    ReparsePoint,
    /// A directory, or not a disk file.
    NotRegular,
    /// More than one hard link (or none).
    MultipleLinks,
    /// Larger than the caller's cap.
    TooLarge,
    /// Owner is neither us nor (when our token is elevated) BUILTIN\Administrators.
    WrongOwner,
    /// The DACL is NULL (everyone), or has an ACE that is not a plain allow for us, SYSTEM or Administrators.
    OtherPrincipals,
}

/// Judge an open file ON ITS HANDLE: regular disk file (no reparse point, no directory), one link, within `cap` when
/// given, owned by us, DACL for nobody else. Returns the size. Never reads the content. The handle must be opened
/// with `FILE_FLAG_OPEN_REPARSE_POINT` so a link is judged as the link itself.
pub fn check_owner_only_file_capped(h: &impl AsRawHandle, cap: Option<u64>) -> Result<u64, FileAclRefusal> {
    let raw = HANDLE(h.as_raw_handle());
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `raw` is a live file handle; `info` is a writable out structure.
    unsafe { GetFileInformationByHandle(raw, &mut info) }.map_err(|e| FileAclRefusal::Io(code(&e) as i32))?;
    let attrs = info.dwFileAttributes;
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(FileAclRefusal::ReparsePoint);
    }
    // SAFETY: live handle.
    if attrs & FILE_ATTRIBUTE_DIRECTORY.0 != 0 || unsafe { GetFileType(raw) } != FILE_TYPE_DISK {
        return Err(FileAclRefusal::NotRegular);
    }
    if info.nNumberOfLinks != 1 {
        return Err(FileAclRefusal::MultipleLinks);
    }
    let size = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
    if cap.is_some_and(|c| size > c) {
        return Err(FileAclRefusal::TooLarge);
    }
    let ours = our_sid().map_err(|c| FileAclRefusal::Io(c as i32))?;
    // A NULL DACL (everyone) comes back as code 0: that is a wrong mode, not an I/O error.
    let (owner, dacl) = owner_and_dacl(raw).map_err(|c| if c == 0 { FileAclRefusal::OtherPrincipals } else { FileAclRefusal::Io(c as i32) })?;
    if !locator_owner_ok(&owner, ours, token_elevated()) {
        return Err(FileAclRefusal::WrongOwner);
    }
    if !locator_dacl_ok(&dacl, ours) {
        return Err(FileAclRefusal::OtherPrincipals);
    }
    Ok(size)
}

/// [`check_owner_only_file_capped`] without a size cap.
pub fn check_owner_only_file(h: &impl AsRawHandle) -> Result<u64, FileAclRefusal> {
    check_owner_only_file_capped(h, None)
}

/// Is `root` (a drive root such as `Z:\`) a network drive? Not an ACL rule: a separate question callers ask BEFORE they
/// open a path, because opening on a network drive talks to the file server (it can stall, and the server decides what
/// owner and permissions it reports). `GetDriveTypeW` answers from local drive data and does not contact the server.
///
/// `true` only for `DRIVE_REMOTE`. `DRIVE_NO_ROOT_DIR`, `DRIVE_UNKNOWN` and every local type are `false`, so a drive that
/// does not exist is left to fail in the normal open.
pub fn drive_is_remote(root: &str) -> bool {
    const DRIVE_REMOTE: u32 = 4;
    let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the call.
    unsafe { GetDriveTypeW(PCWSTR(wide.as_ptr())) == DRIVE_REMOTE }
}

#[cfg(test)]
mod drive_tests {
    use super::drive_is_remote;

    #[test]
    fn the_system_drive_is_not_remote_and_a_missing_one_is_not_refused() {
        let system = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        assert!(!drive_is_remote(&format!("{system}\\")));
        assert!(!drive_is_remote("not a drive"));
    }
}
