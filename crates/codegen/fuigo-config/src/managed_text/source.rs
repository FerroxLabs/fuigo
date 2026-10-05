use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use super::{ManagedConfigError, ManagedConfigPlan};

pub(super) const MAX_SYMLINKS: usize = 40;
pub(super) const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SourceState {
    pub bytes: Option<Vec<u8>>,
    pub hash: String,
    pub mode: Option<u32>,
    pub identity: Option<FileIdentity>,
}

impl SourceState {
    pub fn text<'a>(&'a self, path: &Path) -> Result<&'a str, ManagedConfigError> {
        match self.bytes.as_deref() {
            Some(bytes) => std::str::from_utf8(bytes).map_err(|_| ManagedConfigError::UnsafePath {
                path: path.to_path_buf(),
                reason: "file is not valid UTF-8".to_owned(),
            }),
            None => Ok(""),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ParentPlan {
    parent: PathBuf,
    existing_chain: Vec<PathIdentity>,
    first_missing: Option<PathBuf>,
}

impl ParentPlan {
    pub fn capture(parent: &Path) -> Result<Self, ManagedConfigError> {
        let mut chain = Vec::new();
        let mut current = PathBuf::new();
        let mut first_missing = None;
        for component in parent.components() {
            current.push(component.as_os_str());
            if matches!(component, Component::Prefix(_) | Component::RootDir) {
                continue;
            }
            match fs::symlink_metadata(&current) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() {
                        return Err(ManagedConfigError::UnsafePath {
                            path: current,
                            reason: "symlinked parent directory is not allowed".to_owned(),
                        });
                    }
                    if !metadata.is_dir() {
                        return Err(ManagedConfigError::UnsafePath {
                            path: current,
                            reason: "parent component is not a directory".to_owned(),
                        });
                    }
                    chain.push(PathIdentity {
                        path: current.clone(),
                        identity: FileIdentity::of_entry(&current, &metadata).map_err(
                            |source| ManagedConfigError::Read {
                                path: current.clone(),
                                source,
                            },
                        )?,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    first_missing = Some(current.clone());
                    break;
                }
                Err(source) => {
                    return Err(ManagedConfigError::Read {
                        path: current,
                        source,
                    });
                }
            }
        }
        Ok(Self {
            parent: parent.to_path_buf(),
            existing_chain: chain,
            first_missing,
        })
    }

    pub fn ensure_and_anchor(&self) -> Result<ParentAnchor, ManagedConfigError> {
        self.revalidate_existing()?;
        fs::create_dir_all(&self.parent).map_err(|source| ManagedConfigError::Write {
            path: self.parent.clone(),
            source,
        })?;
        self.revalidate_existing()?;
        let current = Self::capture(&self.parent)?;
        if current.first_missing.is_some()
            || !current.existing_chain.starts_with(&self.existing_chain)
        {
            return Err(ManagedConfigError::ParentChanged(self.parent.clone()));
        }
        ParentAnchor::capture(&self.parent)
    }

    pub fn revalidate_planned(&self) -> Result<(), ManagedConfigError> {
        self.revalidate_existing()?;
        if self.first_missing.is_none() {
            let current = Self::capture(&self.parent)?;
            if current.existing_chain != self.existing_chain {
                return Err(ManagedConfigError::ParentChanged(self.parent.clone()));
            }
        }
        Ok(())
    }

    fn revalidate_existing(&self) -> Result<(), ManagedConfigError> {
        for expected in &self.existing_chain {
            let metadata = fs::symlink_metadata(&expected.path)
                .map_err(|_| ManagedConfigError::ParentChanged(expected.path.clone()))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(ManagedConfigError::ParentChanged(expected.path.clone()));
            }
            // An identity that cannot be read is a parent that changed.
            match FileIdentity::of_entry(&expected.path, &metadata) {
                Ok(identity) if identity == expected.identity => {}
                _ => return Err(ManagedConfigError::ParentChanged(expected.path.clone())),
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct ParentAnchor {
    path: PathBuf,
    identity: FileIdentity,
    // Unix syncs through it; elsewhere it only names the directory the
    // identity was read from.
    #[cfg_attr(not(unix), allow(dead_code))]
    directory: fs::File,
}

impl ParentAnchor {
    fn capture(path: &Path) -> Result<Self, ManagedConfigError> {
        let metadata = fs::symlink_metadata(path).map_err(|source| ManagedConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ManagedConfigError::ParentChanged(path.to_path_buf()));
        }
        let read_error = |source| ManagedConfigError::Read {
            path: path.to_path_buf(),
            source,
        };
        let directory = open_directory(path).map_err(read_error)?;
        let identity = FileIdentity::of_open(&directory, &metadata).map_err(read_error)?;
        Ok(Self {
            path: path.to_path_buf(),
            identity,
            directory,
        })
    }

    pub fn revalidate(&self) -> Result<(), ManagedConfigError> {
        let current = Self::capture(&self.path)?;
        if current.identity != self.identity {
            return Err(ManagedConfigError::ParentChanged(self.path.clone()));
        }
        Ok(())
    }

    pub fn sync(&self) -> Result<(), ManagedConfigError> {
        #[cfg(unix)]
        {
            self.directory
                .sync_all()
                .map_err(|source| ManagedConfigError::Sync {
                    path: self.path.clone(),
                    source,
                })
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PathIdentity {
    path: PathBuf,
    identity: FileIdentity,
}

/// Which file an entry is, as far as the file system tells: equal for the
/// same file however its contents, times or name change, different for any
/// other file that exists at the same time. That detects a replacement while
/// the original still exists (a rename swap, the usual atomic write). It is
/// not, alone, proof against delete-then-recreate: no handle is kept between
/// plan and apply, and a file system may hand a deleted file's id to a later
/// one (Unix inode numbers and the 64-bit index of FAT-like volumes are
/// reused readily; NTFS and ReFS ids were not seen to repeat).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileIdentity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    // Windows: the volume serial number and the file id. Not the length and
    // the modified time: a directory's modified time moves whenever an entry
    // is created in it, so every parent directory would "change" under the
    // transaction's own backup and temp files, and under any other writer in
    // an ancestor.
    #[cfg(windows)]
    volume: u64,
    #[cfg(windows)]
    id: u128,
    // Which query answered (128-bit id or the 64-bit index). Two answers from
    // different queries never compare equal.
    #[cfg(windows)]
    wide: bool,
    #[cfg(not(any(unix, windows)))]
    len: u64,
    #[cfg(not(any(unix, windows)))]
    modified: Option<std::time::SystemTime>,
}

impl FileIdentity {
    /// Identity of the entry at `path` itself (a link is not followed);
    /// `metadata` is its `symlink_metadata`.
    fn of_entry(path: &Path, metadata: &fs::Metadata) -> io::Result<Self> {
        #[cfg(not(windows))]
        {
            let _ = path;
            Ok(Self::from_metadata(metadata))
        }
        #[cfg(windows)]
        {
            let _ = metadata;
            Self::from_handle(&open_for_identity(path, false)?)
        }
    }

    /// Identity of the file `path` resolves to (links are followed);
    /// `metadata` is its `metadata`.
    fn of_target(path: &Path, metadata: &fs::Metadata) -> io::Result<Self> {
        #[cfg(not(windows))]
        {
            let _ = path;
            Ok(Self::from_metadata(metadata))
        }
        #[cfg(windows)]
        {
            let _ = metadata;
            Self::of_file(path)
        }
    }

    /// Identity of the file `path` resolves to right now.
    #[cfg(windows)]
    pub(crate) fn of_file(path: &Path) -> io::Result<Self> {
        Self::from_handle(&open_for_identity(path, true)?)
    }

    /// Identity of an open directory; on Windows the handle supplies it,
    /// elsewhere `metadata` (read before the open) does.
    fn of_open(file: &fs::File, metadata: &fs::Metadata) -> io::Result<Self> {
        #[cfg(not(windows))]
        {
            let _ = file;
            Ok(Self::from_metadata(metadata))
        }
        #[cfg(windows)]
        {
            let _ = metadata;
            Self::from_handle(file)
        }
    }

    #[cfg(not(windows))]
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            Self {
                dev: metadata.dev(),
                ino: metadata.ino(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                len: metadata.len(),
                modified: metadata.modified().ok(),
            }
        }
    }

    /// The 128-bit id where the file system has one (NTFS, and ReFS, whose
    /// ids do not fit 64 bits); the 64-bit index where it does not (FAT, some
    /// network shares). Any other failure of the first query is an error, not
    /// a reason to answer with the weaker one.
    #[cfg(windows)]
    fn from_handle(file: &fs::File) -> io::Result<Self> {
        match Self::wide_from_handle(file)? {
            Some(identity) => Ok(identity),
            None => Self::narrow_from_handle(file),
        }
    }

    /// `None`: this file system does not answer the 128-bit query.
    #[cfg(windows)]
    fn wide_from_handle(file: &fs::File) -> io::Result<Option<Self>> {
        use std::os::windows::io::AsRawHandle as _;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Storage::FileSystem::{
            FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
        };
        const ERROR_INVALID_FUNCTION: i32 = 1;
        const ERROR_NOT_SUPPORTED: i32 = 50;
        const ERROR_INVALID_PARAMETER: i32 = 87;
        let mut info = FILE_ID_INFO::default();
        // SAFETY: the handle is open for the duration of the call; `info` is a
        // valid, writable FILE_ID_INFO of exactly the size passed.
        let read = unsafe {
            GetFileInformationByHandleEx(
                HANDLE(file.as_raw_handle()),
                FileIdInfo,
                (&raw mut info).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        };
        match read.map_err(|error| win32_io_error(&error)) {
            Ok(()) => Ok(Some(Self {
                volume: info.VolumeSerialNumber,
                id: u128::from_le_bytes(info.FileId.Identifier),
                wide: true,
            })),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(ERROR_INVALID_FUNCTION | ERROR_NOT_SUPPORTED | ERROR_INVALID_PARAMETER)
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    #[cfg(windows)]
    fn narrow_from_handle(file: &fs::File) -> io::Result<Self> {
        use std::os::windows::io::AsRawHandle as _;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the handle is open for the duration of the call and `info`
        // is a valid out-pointer.
        unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }
            .map_err(|error| win32_io_error(&error))?;
        Ok(Self {
            volume: u64::from(info.dwVolumeSerialNumber),
            id: u128::from((u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow)),
            wide: false,
        })
    }
}

/// The `windows` crate reports a failed call as an HRESULT; `io::Error` wants
/// the Win32 code inside it (so that 5 is `PermissionDenied`, and so on).
#[cfg(windows)]
fn win32_io_error(error: &windows::core::Error) -> io::Error {
    const FACILITY_WIN32: u32 = 0x8007;
    let code = error.code().0 as u32;
    if code >> 16 == FACILITY_WIN32 {
        io::Error::from_raw_os_error((code & 0xFFFF) as i32)
    } else {
        io::Error::other(error.clone())
    }
}

/// Opens the parent directory that anchors a transaction.
fn open_directory(path: &Path) -> io::Result<fs::File> {
    #[cfg(windows)]
    {
        open_for_identity(path, false)
    }
    #[cfg(not(windows))]
    {
        fs::File::open(path)
    }
}

/// Opens a file or a directory only to ask what it is. Plain `File::open`
/// cannot open a directory on Windows ("Access is denied"): that takes
/// `FILE_FLAG_BACKUP_SEMANTICS`. No read or write access is requested (as
/// `lstat` needs none), and every sharing mode is granted so the handle never
/// stops another process from writing, renaming or removing the entry.
/// `follow_links == false` opens a symlink or junction itself, not its target.
#[cfg(windows)]
fn open_for_identity(path: &Path, follow_links: bool) -> io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const SHARE_READ_WRITE_DELETE: u32 = 0x1 | 0x2 | 0x4;
    let mut flags = FILE_FLAG_BACKUP_SEMANTICS;
    if !follow_links {
        flags |= FILE_FLAG_OPEN_REPARSE_POINT;
    }
    fs::OpenOptions::new()
        .access_mode(0)
        .share_mode(SHARE_READ_WRITE_DELETE)
        .custom_flags(flags)
        .open(path)
}

pub(super) fn absolute_lexical(path: &Path) -> Result<PathBuf, ManagedConfigError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| ManagedConfigError::Read {
                path: path.to_path_buf(),
                source,
            })?
            .join(path)
    };
    Ok(normalize_lexically(&absolute))
}

fn normalize_lexically(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

pub(super) fn resolve_final_symlink(path: &Path) -> Result<PathBuf, ManagedConfigError> {
    let mut current = physicalize_parent(path)?;
    let mut followed = false;
    let mut seen = HashSet::new();
    for _ in 0..MAX_SYMLINKS {
        if !seen.insert(current.clone()) {
            return Err(ManagedConfigError::UnsafePath {
                path: path.to_path_buf(),
                reason: "symlink cycle detected".to_owned(),
            });
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                followed = true;
                let link = fs::read_link(&current).map_err(|source| ManagedConfigError::Read {
                    path: current.clone(),
                    source,
                })?;
                current = if link.is_absolute() {
                    normalize_lexically(&link)
                } else {
                    normalize_lexically(
                        &current
                            .parent()
                            .unwrap_or_else(|| Path::new("/"))
                            .join(link),
                    )
                };
            }
            Ok(_) => return Ok(current),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !followed => {
                return Ok(current);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ManagedConfigError::UnsafePath {
                    path: path.to_path_buf(),
                    reason: "symlink target does not exist".to_owned(),
                });
            }
            Err(source) => {
                return Err(ManagedConfigError::Read {
                    path: current,
                    source,
                });
            }
        }
    }
    Err(ManagedConfigError::UnsafePath {
        path: path.to_path_buf(),
        reason: format!("symlink chain exceeds {MAX_SYMLINKS} links"),
    })
}

fn physicalize_parent(path: &Path) -> Result<PathBuf, ManagedConfigError> {
    let Some(parent) = path.parent() else {
        return Ok(path.to_path_buf());
    };
    let mut probe = parent;
    let mut missing = Vec::new();
    loop {
        match dunce::canonicalize(probe) {
            Ok(canonical) => {
                let mut physical = canonical;
                for component in missing.iter().rev() {
                    physical.push(component);
                }
                if let Some(name) = path.file_name() {
                    physical.push(name);
                }
                return Ok(physical);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = probe
                    .file_name()
                    .ok_or_else(|| ManagedConfigError::UnsafePath {
                        path: path.to_path_buf(),
                        reason: "could not resolve config parent".to_owned(),
                    })?;
                missing.push(name.to_os_string());
                probe = probe
                    .parent()
                    .ok_or_else(|| ManagedConfigError::UnsafePath {
                        path: path.to_path_buf(),
                        reason: "could not resolve config parent".to_owned(),
                    })?;
            }
            Err(source) => {
                return Err(ManagedConfigError::Read {
                    path: probe.to_path_buf(),
                    source,
                });
            }
        }
    }
}

pub(super) fn read_source(path: &Path) -> Result<SourceState, ManagedConfigError> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SourceState {
                bytes: None,
                hash: blake3::hash(&[]).to_hex().to_string(),
                mode: default_mode(),
                identity: None,
            });
        }
        Err(source) => {
            return Err(ManagedConfigError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if !metadata.file_type().is_file() {
        return Err(ManagedConfigError::UnsafePath {
            path: path.to_path_buf(),
            reason: "target is not a regular file".to_owned(),
        });
    }
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(ManagedConfigError::UnsafePath {
            path: path.to_path_buf(),
            reason: format!("file exceeds {MAX_CONFIG_BYTES} bytes"),
        });
    }
    let bytes = fs::read(path).map_err(|source| ManagedConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if bytes.contains(&0) {
        return Err(ManagedConfigError::UnsafePath {
            path: path.to_path_buf(),
            reason: "file contains NUL bytes".to_owned(),
        });
    }
    Ok(SourceState {
        hash: blake3::hash(&bytes).to_hex().to_string(),
        bytes: Some(bytes),
        mode: file_mode(&metadata),
        identity: Some(FileIdentity::of_target(path, &metadata).map_err(|source| {
            ManagedConfigError::Read {
                path: path.to_path_buf(),
                source,
            }
        })?),
    })
}

pub(super) fn revalidate(plan: &ManagedConfigPlan) -> Result<(), ManagedConfigError> {
    plan.parent_plan.revalidate_planned()?;
    let target = resolve_final_symlink(&plan.requested_path)?;
    if target != plan.target_path {
        return Err(ManagedConfigError::StalePlan(plan.requested_path.clone()));
    }
    let current = read_source(&target)?;
    if current != plan.original {
        return Err(ManagedConfigError::StalePlan(plan.requested_path.clone()));
    }
    Ok(())
}

#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt as _;
    Some(metadata.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn file_mode(_: &fs::Metadata) -> Option<u32> {
    None
}

#[cfg(unix)]
fn default_mode() -> Option<u32> {
    Some(0o644)
}

#[cfg(not(unix))]
fn default_mode() -> Option<u32> {
    None
}

#[cfg(all(test, windows))]
pub(super) mod windows_tests {
    use super::*;

    /// A junction: the directory link that needs no privilege to create.
    /// Both paths are quoted for `cmd` (so `&`, spaces and the like in a temp
    /// path stay part of the name) and the wait is bounded.
    pub(in crate::managed_text) fn junction(link: &Path, target: &Path) {
        use std::os::windows::process::CommandExt as _;
        for path in [link, target] {
            // The two things quoting cannot protect from `cmd`.
            assert!(
                !path.to_string_lossy().contains(['%', '"']),
                "junction fixture cannot name {}",
                path.display()
            );
        }
        #[allow(clippy::disallowed_methods)]
        // The fixture's child is waited on with a bound below
        let mut child = std::process::Command::new("cmd")
            .args(["/d", "/c", "mklink", "/J"])
            .raw_arg(format!("\"{}\" \"{}\"", link.display(), target.display()))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let started = std::time::Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if started.elapsed() > std::time::Duration::from_secs(30) {
                let _ = child.kill();
                panic!("mklink /J did not finish within 30 s");
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        assert!(status.success(), "mklink /J failed: {status}");
    }

    fn entry(path: &Path) -> FileIdentity {
        FileIdentity::of_entry(path, &fs::symlink_metadata(path).unwrap()).unwrap()
    }

    fn target(path: &Path) -> FileIdentity {
        FileIdentity::of_target(path, &fs::metadata(path).unwrap()).unwrap()
    }

    /// The identity names the file: it survives a rewrite, a rename and new
    /// entries in a directory, and no two live entries share one.
    #[test]
    fn an_identity_follows_the_file_not_its_contents_times_or_name() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("directory");
        fs::create_dir(&directory).unwrap();
        let file = directory.join("file");
        fs::write(&file, "one").unwrap();
        let other = directory.join("other");
        fs::write(&other, "one").unwrap();

        let directory_identity = entry(&directory);
        let file_identity = target(&file);
        assert_eq!(entry(&file), file_identity);
        assert_eq!(FileIdentity::of_file(&file).unwrap(), file_identity);
        assert_ne!(file_identity, target(&other));
        assert_ne!(file_identity, directory_identity);

        fs::write(&file, "a longer second version").unwrap();
        fs::write(directory.join("third"), "x").unwrap();
        assert_eq!(target(&file), file_identity);
        assert_eq!(entry(&directory), directory_identity);

        let renamed = temp.path().join("renamed");
        fs::rename(&directory, &renamed).unwrap();
        assert_eq!(entry(&renamed), directory_identity);
        assert_eq!(target(&renamed.join("file")), file_identity);

        // The anchor's handle names the same directory as the path does.
        let anchor = ParentAnchor::capture(&renamed).unwrap();
        assert_eq!(anchor.identity, directory_identity);
        anchor.revalidate().unwrap();
    }

    /// `of_entry` is `lstat`: a junction has its own identity. `of_target`
    /// is `stat`: through the junction it is the directory behind it.
    #[test]
    fn a_junction_has_its_own_identity_and_its_target_s_only_when_followed() {
        // `&` and a space in the names: the fixture must not be shell-parsed.
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real & true");
        fs::create_dir(&real).unwrap();
        let link = temp.path().join("link & alias");
        junction(&link, &real);

        assert_ne!(entry(&link), entry(&real));
        assert_eq!(target(&link), entry(&real));
    }

    /// The 64-bit index (the answer on file systems without 128-bit ids) is an
    /// identity too, and is never mistaken for a 128-bit answer.
    #[test]
    fn the_64_bit_index_identifies_files_and_never_equals_a_128_bit_id() {
        let temp = tempfile::tempdir().unwrap();
        let one = temp.path().join("one");
        let two = temp.path().join("two");
        fs::write(&one, "same").unwrap();
        fs::write(&two, "same").unwrap();
        let narrow = |path: &Path| {
            FileIdentity::narrow_from_handle(&open_for_identity(path, true).unwrap()).unwrap()
        };

        assert_eq!(narrow(&one), narrow(&one));
        assert_ne!(narrow(&one), narrow(&two));
        assert_eq!(narrow(temp.path()), narrow(temp.path()));
        assert!(!narrow(&one).wide);

        let handle = open_for_identity(&one, true).unwrap();
        let chosen = FileIdentity::of_file(&one).unwrap();
        match FileIdentity::wide_from_handle(&handle).unwrap() {
            // This volume has 128-bit ids (NTFS, ReFS): that is the answer,
            // and it is not the narrow one.
            Some(wide) => {
                assert!(wide.wide);
                assert_eq!(chosen, wide);
                assert_ne!(chosen, narrow(&one));
            }
            // It has not: the narrow one is the answer.
            None => assert_eq!(chosen, narrow(&one)),
        }
    }

    /// A measurement, not a guarantee: on a volume with 128-bit ids, 200
    /// rounds of deleting a file and creating it again under the same name,
    /// with the same bytes, never brought an identity back. It does not show
    /// that an id can never be reused, and a plan is still not protected
    /// against delete-then-recreate (see `FileIdentity`).
    #[test]
    fn two_hundred_recreations_of_a_file_never_repeat_a_128_bit_id() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("file");
        fs::write(&path, "same").unwrap();
        let original = FileIdentity::of_file(&path).unwrap();
        if !original.wide {
            // A 64-bit index may be reused; nothing to assert on this volume.
            return;
        }
        let mut seen = HashSet::from([(original.volume, original.id)]);
        for round in 0..200 {
            fs::remove_file(&path).unwrap();
            fs::write(&path, "same").unwrap();
            let recreated = FileIdentity::of_file(&path).unwrap();
            assert!(
                seen.insert((recreated.volume, recreated.id)),
                "round {round}: {recreated:?} was seen before"
            );
        }
    }

    /// A failed Win32 call keeps its Win32 meaning as an `io::Error`.
    #[test]
    fn a_win32_failure_keeps_its_error_kind() {
        use windows::core::{Error, HRESULT};
        let denied = win32_io_error(&Error::from(HRESULT::from_win32(5)));
        assert_eq!(denied.raw_os_error(), Some(5));
        assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
        let missing = win32_io_error(&Error::from(HRESULT::from_win32(2)));
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
        // Not a Win32 code: carried as is, never misread as one.
        let other = win32_io_error(&Error::from(HRESULT(0x8000_4005_u32 as i32)));
        assert_eq!(other.raw_os_error(), None);
    }

    /// The anchor's handle asks for no access and shares everything: while it
    /// is held, others still create, replace and delete files in the
    /// directory, and rename or remove the directory itself. (Windows does
    /// refuse to rename a directory ABOVE any open handle, this one or the
    /// transaction's lock file alike; that lasts for one apply and ends when
    /// the anchor is dropped.)
    #[test]
    fn a_held_anchor_does_not_stop_work_in_or_on_the_directory() {
        let temp = tempfile::tempdir().unwrap();
        let outer = temp.path().join("outer");
        let directory = outer.join("directory");
        fs::create_dir_all(&directory).unwrap();
        let anchor = ParentAnchor::capture(&directory).unwrap();

        fs::write(directory.join("a"), "a").unwrap();
        fs::write(directory.join("b"), "b").unwrap();
        fs::rename(directory.join("b"), directory.join("a")).unwrap();
        fs::remove_file(directory.join("a")).unwrap();
        anchor.revalidate().unwrap();

        let renamed = outer.join("renamed");
        fs::rename(&directory, &renamed).unwrap();
        assert!(matches!(
            anchor.revalidate(),
            Err(ManagedConfigError::Read { .. })
        ));
        fs::remove_dir(&renamed).unwrap();
        assert!(!renamed.exists());

        drop(anchor);
        fs::rename(&outer, temp.path().join("outer-renamed")).unwrap();
    }
}
