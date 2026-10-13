//! The Windows side of `bearer_token_file`: which path strings are refused before anything is opened (pure, compiled and
//! tested on every OS), and the open-and-judge step (Windows only).
//!
//! The file rule itself is `fuigo_win_acl::check_owner_only_file_capped`, the one checker the peer locator also uses. This
//! module only opens the file the way that checker needs and maps its refusals.

use super::BearerTokenFileError;

/// Device names Windows resolves in ANY folder (`C:\dir\NUL`), with or without an extension.
const RESERVED: &[&str] =
    &["CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "CONIN$", "CONOUT$"];

/// Refuse, before opening anything, a path that is not a plain file on a local drive:
///
/// * a device or extended path (`\\.\pipe\x`, `\\.\COM1`, `\\?\...`) and a network path (`\\server\share\x`, `//server/x`):
///   anything that begins with two separators. Opening a pipe would connect to its server, and a network path would
///   authenticate to a host and can stall;
/// * a device name as any component (`CON`, `NUL`, `COM1`, `LPT1`, `CONIN$`, ... with or without an extension);
/// * an alternate data stream (`file.txt:stream`): a `:` anywhere but the drive letter.
///
/// Both `\` and `/` separate components. A relative path is not judged here (the caller refuses it as not absolute).
pub(crate) fn path_problem(path: &str) -> Option<BearerTokenFileError> {
    let unified = path.replace('/', "\\");
    if unified.starts_with("\\\\") {
        return Some(BearerTokenFileError::UnsupportedPath);
    }
    // After an optional `X:` drive prefix there is no other colon.
    let rest = match unified.as_bytes() {
        [drive, b':', ..] if drive.is_ascii_alphabetic() => &unified[2..],
        _ => unified.as_str(),
    };
    if rest.contains(':') {
        return Some(BearerTokenFileError::UnsupportedPath);
    }
    for component in rest.split('\\') {
        // `NUL.txt`, `nul .txt` and `NUL:` all reach the device: judge the part before the first dot, minus trailing spaces.
        let stem = component.split('.').next().unwrap_or("").trim_end_matches(' ');
        if RESERVED.iter().any(|name| stem.eq_ignore_ascii_case(name)) {
            return Some(BearerTokenFileError::UnsupportedPath);
        }
    }
    None
}

/// The drive root (`X:\`) of a path that starts with a drive letter, else `None`. Pure.
#[cfg(any(windows, test))]
pub(crate) fn drive_root(path: &str) -> Option<String> {
    match path.as_bytes() {
        [drive, b':', ..] if drive.is_ascii_alphabetic() => Some(format!("{}:\\", char::from(*drive))),
        _ => None,
    }
}

#[cfg(windows)]
pub(crate) use sys::open_checked;
#[cfg(all(windows, test))]
pub(crate) use sys::open_judged;

#[cfg(windows)]
mod sys {
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::Path;

    use fuigo_win_acl::{FileAclRefusal, check_owner_only_file_capped};

    use super::BearerTokenFileError;
    use crate::bearer_token_file::MAX_TOKEN_FILE_BYTES;

    // Win32 values, spelled out so this crate needs no `windows` dependency.
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const FILE_SHARE_DELETE: u32 = 0x4;
    /// Open a reparse point (symlink, junction, ...) ITSELF instead of following it, so the checker sees the link.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const ERROR_ACCESS_DENIED: i32 = 5;

    /// Open `path` read-only, WITHOUT following a reparse point in the final component, and judge the OPEN HANDLE with the
    /// shared checker (not a reparse point, regular disk file, one link, within 16 KiB, owned by us or, for an elevated
    /// token, Administrators, DACL for us, SYSTEM and Administrators only). The returned file is that same handle.
    ///
    /// Share mode is read + write + delete: the user (or the program that rotates the token) can overwrite, rename over or
    /// delete the file while Fuigo has it open for the instant of a read. A stricter mode would make a rotation fail with a
    /// sharing violation. It costs no safety: the file is judged and read through this one handle, and only the owner and
    /// the accounts the rule allows can write it.
    ///
    /// Never blocks: no byte is read before the checker has accepted a regular DISK file, and opening a disk file, a
    /// directory or a device does not wait (the path rules in [`super::path_problem`] already keep pipes, UNC paths and
    /// device names out; a pipe or console that still got here fails the checker, which accepts `FILE_TYPE_DISK` only).
    ///
    /// THE enforcement point for every Windows open of the token file (`preflight`, `read_token_sync` and so the per-request
    /// read all come through here): first the path rules ([`super::path_problem`]) and the network-drive refusal, both
    /// BEFORE anything is opened, then the open and the judgement.
    pub(crate) fn open_checked(path: &Path) -> Result<std::fs::File, BearerTokenFileError> {
        let text = path.to_string_lossy();
        if let Some(problem) = super::path_problem(&text) {
            return Err(problem);
        }
        // A mapped network drive (`Z:\tok`): the open would contact the file server, which can stall and which chooses the
        // owner and permissions it reports. Refused first. A drive that does not exist (or whose type is unknown) is not
        // refused here; the open fails as usual.
        if super::drive_root(&text).is_some_and(|root| fuigo_win_acl::drive_is_remote(&root)) {
            return Err(BearerTokenFileError::UnsupportedPath);
        }
        open_judged(path)
    }

    /// The open and the judgement, without the path rules. Use [`open_checked`]; this exists so tests can reach the
    /// checker with a path the rules would stop.
    pub(crate) fn open_judged(path: &Path) -> Result<std::fs::File, BearerTokenFileError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|error| {
                // Without backup semantics a directory cannot be opened as a file: "access denied". Say what it is.
                let is_dir = error.raw_os_error() == Some(ERROR_ACCESS_DENIED)
                    && std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir());
                if is_dir { BearerTokenFileError::NotRegular } else { BearerTokenFileError::Unreadable }
            })?;
        check_owner_only_file_capped(&file, Some(MAX_TOKEN_FILE_BYTES)).map_err(map_refusal)?;
        Ok(file)
    }

    pub(crate) fn map_refusal(refusal: FileAclRefusal) -> BearerTokenFileError {
        match refusal {
            FileAclRefusal::ReparsePoint => BearerTokenFileError::Symlink,
            FileAclRefusal::NotRegular => BearerTokenFileError::NotRegular,
            FileAclRefusal::MultipleLinks => BearerTokenFileError::MultipleLinks,
            FileAclRefusal::TooLarge => BearerTokenFileError::TooLarge,
            FileAclRefusal::WrongOwner => BearerTokenFileError::WrongOwner,
            FileAclRefusal::OtherPrincipals => BearerTokenFileError::TooPermissive,
            // A Win32 call failed (file info, our SID, security info): fail closed, generic reason.
            FileAclRefusal::Io(_) => BearerTokenFileError::Unreadable,
        }
    }
}

#[cfg(test)]
mod path_tests {
    use super::*;

    #[test]
    fn device_network_stream_and_reserved_paths_are_refused() {
        for bad in [
            r"\\.\pipe\token", "//./pipe/token", r"\\.\COM1", r"\\?\C:\x\tok", r"\\?\GLOBALROOT\Device\x", r"\\server\share\tok",
            "//server/share/tok", r"C:\dir\NUL", r"C:\dir\nul.txt", r"C:\dir\CON", r"C:\dir\COM1", r"C:\dir\lpt9.tok", r"C:\dir\CONIN$",
            r"C:\dir\tok:stream", r"C:\dir\tok:stream:$DATA", r"C:\NUL\tok", "C:/dir/aux", r"C:\dir\NUL .txt",
        ] {
            assert_eq!(path_problem(bad), Some(BearerTokenFileError::UnsupportedPath), "{bad:?}");
        }
    }

    #[test]
    fn the_drive_root_is_taken_from_the_letter() {
        assert_eq!(drive_root(r"Z:\tok").as_deref(), Some(r"Z:\"));
        assert_eq!(drive_root("c:/a/b").as_deref(), Some(r"c:\"));
        assert_eq!(drive_root(r"\\server\share\x"), None);
        assert_eq!(drive_root(r"tok"), None);
        assert_eq!(drive_root(""), None);
    }

    #[test]
    fn ordinary_local_paths_pass() {
        for ok in [r"C:\Users\me\.config\tok", "C:/Users/me/tok", r"D:\a b\tok.txt", r"C:\dir\console", r"C:\dir\nullable", r"C:\dir\com10", r"C:\dir\LPT0"] {
            assert_eq!(path_problem(ok), None, "{ok:?}");
        }
    }
}
