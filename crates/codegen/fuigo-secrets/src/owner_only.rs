//! Restrict a file to its owner (P145).
//!
//! The Windows owner-only ACL lived only in `fuigo-shell-base` (`util::secure_file`). Crates below it in the dependency
//! graph (`fuigo-session-events`, which writes `events.jsonl`, and `fuigo-tools`, which writes `resources_state.json`)
//! could not call it, so on Windows those session files kept the ACL inherited from the folder: readable by every
//! user a permissive `FUIGO_HOME` grants (release note K18). The implementation now lives here, in a leaf crate every
//! writer can reach; `fuigo-shell-base` delegates to it, so there is one copy.
//!
//! - **Unix**: mode 0600 when the file has any other mode.
//! - **Windows**: a protected DACL (inheritance removed) with one entry granting the current user full control,
//!   the equivalent of 0600.

use std::io;
use std::path::Path;

/// Make `path` readable and writable by the current user only. Errors propagate (callers decide whether a failure is
/// fatal); a missing file is `NotFound`.
pub fn restrict_to_owner(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let metadata = std::fs::metadata(path)?;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        set_windows_owner_only_acl(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Ok(())
    }
}

/// Create the directory `path` (not its parents) readable and writable by the current user only, from the moment it
/// exists; fails if the name already exists, so a planted directory or link is never adopted (P145, Astra r2 #5).
///
/// - **Unix**: `mkdir` with mode 0700.
/// - **Windows**: `CreateDirectoryW` with a security descriptor whose protected DACL grants the current user full control,
///   inherited by everything created inside (`OBJECT_INHERIT | CONTAINER_INHERIT`), so files npm writes there are
///   owner-only too and nothing is ever readable through the parent's ACL.
pub fn create_owner_only_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(windows)]
    {
        create_windows_owner_only_dir(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::create_dir(path)
    }
}

#[cfg(windows)]
fn create_windows_owner_only_dir(path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::{CloseHandle, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, SET_ACCESS, SetEntriesInAclW, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        ACL, CONTAINER_INHERIT_ACE, GetTokenInformation, InitializeSecurityDescriptor, OBJECT_INHERIT_ACE,
        PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SetSecurityDescriptorControl,
        SetSecurityDescriptorDacl, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows::Win32::Storage::FileSystem::CreateDirectoryW;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::PCWSTR;

    // SAFETY: every pointer passed below points into a buffer that outlives the call (`token_user_buffer`, `sd`,
    // `wide_path`); the ACL from SetEntriesInAclW is freed exactly once; the token handle is closed on every path.
    unsafe {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        let mut token_user_buffer = vec![0u8; len as usize];
        let got = GetTokenInformation(token, TokenUser, Some(token_user_buffer.as_mut_ptr() as *mut _), len, &mut len);
        let _ = CloseHandle(token);
        got.map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
        let user_sid = (*(token_user_buffer.as_ptr() as *const TOKEN_USER)).User.Sid;

        let access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: 0x10000000, // GENERIC_ALL
            grfAccessMode: SET_ACCESS,
            grfInheritance: OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: windows::Win32::Security::Authorization::NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: windows::core::PWSTR(user_sid.0 as *mut u16),
            },
        };
        let mut acl: *mut ACL = std::ptr::null_mut();
        let r = SetEntriesInAclW(Some(&[access]), None, &mut acl);
        if r.0 != 0 {
            return Err(io::Error::from_raw_os_error(r.0 as i32));
        }
        let result = (|| -> io::Result<()> {
            let mut sd = SECURITY_DESCRIPTOR::default();
            let psd = PSECURITY_DESCRIPTOR(&mut sd as *mut SECURITY_DESCRIPTOR as *mut _);
            InitializeSecurityDescriptor(psd, 1).map_err(io::Error::other)?; // SECURITY_DESCRIPTOR_REVISION
            SetSecurityDescriptorDacl(psd, true, Some(acl), false).map_err(io::Error::other)?;
            SetSecurityDescriptorControl(psd, SE_DACL_PROTECTED, SE_DACL_PROTECTED).map_err(io::Error::other)?;
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: psd.0,
                bInheritHandle: false.into(),
            };
            let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
            CreateDirectoryW(PCWSTR::from_raw(wide.as_ptr()), Some(&sa)).map_err(|e| io::Error::from_raw_os_error(e.code().0 & 0xFFFF))
        })();
        let _ = LocalFree(Some(HLOCAL(acl as *mut _)));
        result
    }
}

/// Replace the DACL of `path` with a protected one granting only the current user (Windows `0600`).
///
/// 1. Removes inherited permissions (`PROTECTED_DACL_SECURITY_INFORMATION`).
/// 2. Grants `GENERIC_ALL` to the process token's user SID, nothing else.
#[cfg(windows)]
pub fn set_windows_owner_only_acl(path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::{CloseHandle, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW, SetNamedSecurityInfoW,
        TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        ACE_FLAGS, ACL, DACL_SECURITY_INFORMATION, GetTokenInformation,
        PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::PCWSTR;

    // SAFETY: every pointer handed to the Win32 calls below points into a buffer that lives until the call returns
    // (`token_user_buffer`, `wide_path`), and the ACL from SetEntriesInAclW is freed exactly once with LocalFree.
    unsafe {
        let mut token_handle = windows::Win32::Foundation::HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle)
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;

        let mut return_length = 0u32;
        let _ = GetTokenInformation(token_handle, TokenUser, None, 0, &mut return_length);

        let mut token_user_buffer = vec![0u8; return_length as usize];
        GetTokenInformation(
            token_handle,
            TokenUser,
            Some(token_user_buffer.as_mut_ptr() as *mut _),
            return_length,
            &mut return_length,
        )
        .map_err(|e| {
            let _ = CloseHandle(token_handle);
            io::Error::new(io::ErrorKind::PermissionDenied, e)
        })?;

        // TOKEN_USER starts with a SID_AND_ATTRIBUTES whose first field is the PSID.
        let token_user = &*(token_user_buffer.as_ptr() as *const TOKEN_USER);
        let user_sid = token_user.User.Sid;

        let explicit_access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: 0x10000000, // GENERIC_ALL
            grfAccessMode: SET_ACCESS,
            grfInheritance: ACE_FLAGS(0), // files: nothing to inherit
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation:
                    windows::Win32::Security::Authorization::NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: windows::core::PWSTR(user_sid.0 as *mut u16),
            },
        };

        let mut new_acl: *mut ACL = std::ptr::null_mut();
        let result = SetEntriesInAclW(Some(&[explicit_access]), None, &mut new_acl);
        if result.0 != 0 {
            let _ = CloseHandle(token_handle);
            return Err(io::Error::from_raw_os_error(result.0 as i32));
        }

        let wide_path: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let result = SetNamedSecurityInfoW(
            PCWSTR::from_raw(wide_path.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new_acl),
            None,
        );

        let _ = LocalFree(Some(HLOCAL(new_acl as *mut _)));
        let _ = CloseHandle(token_handle);

        if result.0 != 0 {
            return Err(io::Error::from_raw_os_error(result.0 as i32));
        }
    }

    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn p145_restrict_to_owner_tightens_a_loose_file() {
        let dir = tempfile_dir();
        let path = dir.join("f");
        std::fs::write(&path, b"x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        restrict_to_owner(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn p145_restrict_to_owner_reports_a_missing_file() {
        let dir = tempfile_dir();
        let err = restrict_to_owner(&dir.join("missing")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn p145_create_owner_only_dir_is_0700_and_refuses_an_existing_name() {
        let dir = tempfile_dir();
        let made = dir.join("cache");
        create_owner_only_dir(&made).unwrap();
        assert_eq!(std::fs::metadata(&made).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(create_owner_only_dir(&made).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// No `tempfile` dev-dependency in this leaf crate: a unique directory under the system temp dir.
    fn tempfile_dir() -> std::path::PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("fuigo-secrets-p145-{}-{seq}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        dir
    }
}
