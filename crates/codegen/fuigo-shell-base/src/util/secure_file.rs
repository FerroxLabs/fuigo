//! Cross-platform secure file operations.
//!
//! Creates files that only the current user can read or write, for sensitive data like authentication tokens.
//!
//! - **Unix**: mode 0o600 (owner read/write only)
//! - **Windows**: an ACL that grants access only to the current user
//!
//! The data is stored in plaintext; OS file permissions are the only protection.
//! A keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service) or encryption would be stronger.
//! The tokens stored this way are short-lived (7-30 days TTL with automatic refresh), so file permissions are enough for most use cases.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

/// Write `contents` to `path` with secure permissions (owner read/write only).
///
/// On Unix, this sets mode 0o600.
/// On Windows, this restricts the file's ACL to grant access only to the current user.
pub fn write_secure_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = open_secure_file(path)?;
    file.write_all(contents)?;
    file.flush()?;

    // Re-assert owner-only bits: `OpenOptions::mode` only applies on create, so an existing world-readable file would otherwise keep open perms
    ensure_owner_only_permissions(path)?;

    Ok(())
}

/// Opens a file for writing with secure permissions set during creation (Unix) or prepares it for permission setting after creation (Windows).
///
/// Callers that write secret material should also call [`ensure_owner_only_permissions`] after the write (or use [`write_secure_file`]).
/// `mode(0o600)` only applies when the file is newly created, not when truncating an existing path.
pub fn open_secure_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.truncate(true).write(true).create(true);

    #[cfg(unix)]
    {
        options.mode(0o600);
    }

    options.open(path)
}

/// Ensure `path` is owner-read/write only (Unix `0o600` / Windows user ACL).
///
/// Best-effort on missing files (`NotFound` is ignored).
/// Other errors propagate so callers can fail closed when tightening a secret store.
///
/// Use on **load** of credential files so a hand-copied or restored world-readable `auth.json` is tightened before the process continues.
pub fn ensure_owner_only_permissions(path: &Path) -> io::Result<()> {
    match ensure_owner_only_permissions_inner(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn ensure_owner_only_permissions_inner(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let metadata = std::fs::metadata(path)?;
        let mode = metadata.permissions().mode();
        if mode & 0o777 != 0o600 {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        set_windows_secure_permissions(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Ok(())
    }
}

/// Sets Windows-specific secure permissions on a file: inherited permissions removed, full control for the current
/// user only (the equivalent of Unix 0o600).
///
/// The implementation lives in `fuigo_secrets::owner_only` (P145) so that crates below this one in the dependency graph
/// (the `events.jsonl` and `resources_state.json` writers) use the same ACL.
#[cfg(windows)]
pub fn set_windows_secure_permissions(path: &Path) -> io::Result<()> {
    fuigo_secrets::owner_only::set_windows_owner_only_acl(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_write_secure_file_creates_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test_secure.txt");

        write_secure_file(&file_path, b"test content").unwrap();

        assert!(file_path.exists());
        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "test content");
    }

    #[test]
    fn test_write_secure_file_creates_parent_dirs() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("nested").join("dir").join("test.txt");

        write_secure_file(&file_path, b"nested content").unwrap();

        assert!(file_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_unix_permissions() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test_perms.txt");

        write_secure_file(&file_path, b"secure content").unwrap();

        let metadata = fs::metadata(&file_path).unwrap();
        let mode = metadata.permissions().mode();
        // Check that only owner has read/write (0o600), ignoring file type bits
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn ensure_owner_only_tightens_world_readable_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("loose.txt");
        fs::write(&file_path, b"secret").unwrap();
        let mut loose = fs::metadata(&file_path).unwrap().permissions();
        loose.set_mode(0o644);
        fs::set_permissions(&file_path, loose).unwrap();
        assert_eq!(
            fs::metadata(&file_path).unwrap().permissions().mode() & 0o777,
            0o644
        );

        ensure_owner_only_permissions(&file_path).unwrap();
        assert_eq!(
            fs::metadata(&file_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_secure_file_tightens_existing_world_readable_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("existing.txt");
        fs::write(&file_path, b"old").unwrap();
        let mut loose = fs::metadata(&file_path).unwrap().permissions();
        loose.set_mode(0o666);
        fs::set_permissions(&file_path, loose).unwrap();

        write_secure_file(&file_path, b"new secret").unwrap();
        assert_eq!(
            fs::metadata(&file_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read_to_string(&file_path).unwrap(), "new secret");
    }
}
