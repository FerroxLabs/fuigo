//! Test helpers (feature `test-support`, Windows only): create a file or a folder with a chosen DACL from the first byte,
//! so tests of code that uses [`crate::check_owner_only_file_capped`] need no `icacls` and never write a loose file.
//!
//! The descriptor is applied by `CreateFileW` / `CreateDirectoryW` at creation (CREATE_NEW), as production code does, so
//! there is no window in which the file has another DACL. `trustee` is an SDDL alias or SID, e.g. `BU` (BUILTIN\Users),
//! `WD` (Everyone).

use std::ffi::c_void;
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::Path;

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_MODE};
use windows::core::PCWSTR;

use crate::sys::code;

fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

fn win_err(e: &windows::core::Error) -> io::Error {
    io::Error::from_raw_os_error(code(e) as i32)
}

/// A descriptor built from SDDL text, freed on drop.
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Descriptor {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let text: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `text` is NUL-terminated; `sd` receives a LocalAlloc'd descriptor freed in `Drop`.
        unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(text.as_ptr()), SDDL_REVISION_1, &mut sd, None) }
            .map_err(|e| win_err(&e))?;
        Ok(Self(sd))
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: false.into(),
        }
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW with LocalAlloc; freed once.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0.cast::<c_void>()))) };
    }
}

fn our_sid_text() -> io::Result<&'static str> {
    crate::our_sid().map_err(|c| io::Error::from_raw_os_error(c as i32))
}

/// Create `path` (it must not exist) with exactly this descriptor and write `bytes` to it.
pub fn write_file_with_sddl(path: &Path, sddl: &str, bytes: &[u8]) -> io::Result<()> {
    let sd = Descriptor::from_sddl(sddl)?;
    let attrs = sd.attributes();
    let wide_path = wide(path);
    // SAFETY: `wide_path` is NUL-terminated; `attrs` points at a descriptor that lives until the end of this function.
    let handle = unsafe {
        CreateFileW(PCWSTR(wide_path.as_ptr()), FILE_GENERIC_WRITE.0, FILE_SHARE_MODE(0), Some(&attrs), CREATE_NEW, FILE_ATTRIBUTE_NORMAL, None)
    }
    .map_err(|e| win_err(&e))?;
    // SAFETY: CreateFileW succeeded, so `handle` is a fresh handle that nothing else owns.
    let mut file = unsafe { std::fs::File::from_raw_handle(handle.0) };
    file.write_all(bytes)
}

/// Create `path` (it must not exist) as a folder with exactly this descriptor.
pub fn create_dir_with_sddl(path: &Path, sddl: &str) -> io::Result<()> {
    let sd = Descriptor::from_sddl(sddl)?;
    let attrs = sd.attributes();
    let wide_path = wide(path);
    // SAFETY: `wide_path` is NUL-terminated; `attrs` points at a descriptor that lives until the end of this function.
    unsafe { CreateDirectoryW(PCWSTR(wide_path.as_ptr()), Some(&attrs)) }.map_err(|e| win_err(&e))
}

/// A file only we can use: owner us, protected DACL, one ACE for us ([`crate::owner_only_sddl`]).
pub fn write_owner_only_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let sddl = crate::owner_only_sddl(our_sid_text()?).ok_or_else(|| io::Error::other("our SID is not valid"))?;
    write_file_with_sddl(path, &sddl, bytes)
}

/// A file owned by us whose protected DACL also lets `trustee` read it (the shape the checker must refuse).
pub fn write_file_also_readable_by(path: &Path, bytes: &[u8], trustee: &str) -> io::Result<()> {
    let sid = our_sid_text()?;
    write_file_with_sddl(path, &format!("O:{sid}D:P(A;;GA;;;{sid})(A;;GR;;;{trustee})"), bytes)
}

/// A folder (protected DACL: nothing comes from ITS parent) that grants us everything and `trustee` read access, both
/// inheritable. A file created inside with default security INHERITS the `trustee` ACE.
pub fn create_dir_inheriting_read_for(path: &Path, trustee: &str) -> io::Result<()> {
    let sid = our_sid_text()?;
    create_dir_with_sddl(path, &format!("O:{sid}D:P(A;OICI;GA;;;{sid})(A;OICI;GR;;;{trustee})"))
}

/// A folder that grants only us, inheritable: a file created inside with default security inherits just our ACE.
pub fn create_dir_inheriting_owner_only(path: &Path) -> io::Result<()> {
    let sid = our_sid_text()?;
    create_dir_with_sddl(path, &format!("O:{sid}D:P(A;OICI;GA;;;{sid})"))
}
