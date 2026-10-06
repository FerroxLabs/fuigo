//! Lock identity of a state file (P79): which locks two spellings of one
//! file share.
//!
//! Two paths that name the same file must always meet on ONE lock, on every
//! platform, or two writers can both hold "the" lock and one update is lost.
//! Spellings that differ are: a symlink or `..` in the directory part, a
//! symlink at the file name (these writers write THROUGH it), a different
//! case on a case-insensitive volume (`Agent.toml` / `agent.toml`; APFS and
//! NTFS by default, ext4 casefold or vfat on Linux), a hard link, and
//! whatever else a filesystem equates (an NTFS short name, another Unicode
//! normal form).
//!
//! # What the identity is
//!
//! An [`Identity`] has two parts and a writer takes a lock for each
//! ([`super::lock_state_file`]): the NAME lock always, then the INODE lock
//! when the file exists. Neither is enough alone. A name is all a missing
//! file has, and it is what stays put when a writer replaces the file (every
//! writer here ends with a rename, which gives the name a new inode). The
//! inode is what every spelling of an existing file shares whether or not
//! this module knows why they are one file, and it is what a hard link made
//! under a writer's feet shares with the name the writer locked.
//!
//! 1. The DIRECTORY is resolved as the kernel will once a writer has created
//!    what is missing: each existing prefix canonicalised, a missing
//!    component appended as is, `..` after a missing component taken
//!    lexically. It therefore does not change when the first writer creates a
//!    missing directory. On Windows the resolution is kept in the EXACT
//!    (verbatim, `\\?\`) form throughout, which names one object whatever
//!    its spelling (`Dir.` is not `Dir` there); only the finished path is put
//!    in its plain form, as a whole, to be the name.
//! 2. A symlink at the file name is followed (the writers write through it),
//!    from where the directory resolved to, and the result resolved again,
//!    up to 40 links.
//! 3. **The name** is the resolved path, each component case-folded when the
//!    directory's volume is case-insensitive. A directory's case-sensitivity
//!    is PROBED in the nearest existing directory, not guessed from the
//!    platform, and asked every time (a remembered answer could outlive
//!    the directory it was about): an entry in it whose
//!    ASCII-case-swapped spelling resolves to the same file (and is not a
//!    hard link) says insensitive; one that does not resolve, or resolves to
//!    another file, says sensitive -- but only if the entry itself was the
//!    same file before and after the question (a writer renaming a temp over
//!    it mid-probe would otherwise read as "another file"); when no entry
//!    among the first 64 can say, or the directory cannot be listed, a probe
//!    file is created and removed. The file's own state does not matter, so
//!    a missing file and the file once created have one name. Where nothing
//!    is folded, and the path has a plain spelling (every unix path; on
//!    Windows, not one that only the verbatim form can name, like a final
//!    `state.`, nor one whose length puts it past the plain form), and the
//!    two resolve the path alike (P72 did not follow a final link after
//!    `missing/..`), the name is byte for byte the one P72 hashed, so a P72
//!    process and this one share the lock file there.
//! 4. **The inode** of a file that exists: `dev`/`ino` on unix, volume
//!    serial + file index on Windows. It is NOT stable (a replace changes
//!    it), so it is re-derived once its lock is held, and a writer queued on
//!    the lock of an inode the name no longer has lets go and starts again.
//!
//! # Fail closed
//!
//! Anything the identity needs that cannot be established (a prefix that can
//! be neither resolved nor shown missing, a file that cannot be examined, a
//! symlink loop, a probe that fails) is an ERROR, never a path-string
//! fallback that could split. One case is not an error: a directory that can
//! be neither listed nor written in cannot be asked about case, and for a
//! file that EXISTS in it the name is then taken as spelled. Its writers can
//! only write in place (nothing can be created or renamed there), and they
//! all meet on the inode lock. A missing file there is refused.
//!
//! What exists of the directory part must BE a directory. Unix refuses a path
//! through a regular file by itself (`ENOTDIR`); Windows reports it as "path
//! not found", which would read here as "the rest does not exist yet", so it
//! is checked: for the deepest part that exists, and for one that `..` steps
//! out of (the lexical step would otherwise hide a `file/..` the kernel
//! refuses; on Windows such a path is made absolute, lexically, by the
//! system itself, and opens).
//!
//! # The fold
//!
//! Per path component: NFD, then upper-casing and lower-casing every
//! character, twice (once is not idempotent: U+1E9E goes to U+00DF, which
//! goes to `ss`), then NFD; ASCII only for a component that is not Unicode.
//! It is at least as coarse as Unicode full case folding, so the NFC and NFD
//! spellings of a name, and its case variants, share a name lock on a
//! case-insensitive volume. Coarser is safe: two files sharing one lock only
//! wait for each other.
//!
//! # What the name does not cover
//!
//! Spellings this module cannot equate by name -- a volume whose own table
//! folds more than the fold above, a case-SENSITIVE but
//! normalisation-insensitive volume (APFS-sensitive, HFS+), an NTFS 8.3 short
//! name -- meet on the inode lock once the file exists. Only two writers
//! CREATING one missing file through two such spellings at once are not
//! excluded.
//!
//! # One lock, one directory entry
//!
//! Spellings that share a lock must also end up in one file. Every writer
//! here ends with a rename onto the path, and Windows gives the replaced
//! entry the spelling the rename was asked for: after a write through
//! `AGENT.TOML` the file is called that, and after one through an 8.3 short
//! name (`LONGFI~1.TOM`) the long name is GONE, so the next writer through
//! the long name starts from nothing. A state file's replacement is therefore
//! renamed onto the entry's on-disk spelling ([`entry_as_on_disk`]). Linux
//! and macOS keep the existing entry's spelling by themselves when a file is
//! renamed over it (seen on vfat and on APFS; a test says so wherever the
//! test directory is case-insensitive), so nothing is done there. Not
//! covered: a volume served by a Windows machine to another system.
//!
//! # What a lock on a path cannot do
//!
//! The identity is that of the path when the lock is granted. An outsider who
//! re-points a symlink on the path while a writer holds the lock sends that
//! writer's remaining I/O elsewhere; [`super::edit_state_file`]'s locked pass
//! derives the identity again just before it commits and refuses when it
//! moved, which leaves only the instant between that check and the rename.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Component, Path, PathBuf};

/// What the filesystem says a name is (the name itself, not what a final
/// symlink points at).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FileId {
    pub dev: u64,
    pub ino: u64,
    pub nlink: u64,
    pub is_dir: bool,
    /// When the inode last changed (unix `ctime`; zero where there is none).
    /// Not part of what makes two names one file: it tells an inode from a
    /// later one that was given the same number.
    pub changed: (i64, i64),
}

impl FileId {
    fn same_file(&self, other: &Self) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }
}

/// [`FileId`] of `path` without following a final symlink.
#[cfg(unix)]
pub(super) fn file_id(path: &Path) -> io::Result<FileId> {
    use std::os::unix::fs::MetadataExt as _;
    let md = std::fs::symlink_metadata(path)?;
    Ok(FileId {
        dev: md.dev(),
        ino: md.ino(),
        nlink: md.nlink(),
        is_dir: md.is_dir(),
        changed: (md.ctime(), md.ctime_nsec()),
    })
}

#[cfg(windows)]
pub(super) fn file_id(path: &Path) -> io::Result<FileId> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, GetFileInformationByHandle,
    };
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    // No access rights needed to ask for the identity; backup semantics lets a
    // directory be opened, open-reparse-point keeps a link from being followed.
    let file = std::fs::OpenOptions::new()
        .access_mode(0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `file` is a live handle for the call and `info` a valid out-pointer.
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }
        .map_err(io::Error::from)?;
    Ok(FileId {
        dev: u64::from(info.dwVolumeSerialNumber),
        ino: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        nlink: u64::from(info.nNumberOfLinks),
        is_dir: info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0,
        // The file index carries NTFS's sequence number: a reused record
        // already differs.
        changed: (0, 0),
    })
}

/// What a state file's locks are named after (module docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Identity {
    /// The resolved path, folded where the volume is case-insensitive.
    pub name: Vec<u8>,
    /// The file's inode, when it exists.
    pub inode: Option<Vec<u8>>,
}

/// `name` with its ASCII letters in the other case, if it has any. ASCII
/// only: every case-insensitive filesystem folds those, while what a
/// filesystem does with `ß` or a dotted `İ` differs from table to table, and a
/// swap the volume does not honour would read as "sensitive".
fn other_case(name: &OsStr) -> Option<OsString> {
    let upper = name.to_ascii_uppercase();
    if upper.as_os_str() != name {
        return Some(upper);
    }
    let lower = name.to_ascii_lowercase();
    (lower.as_os_str() != name).then_some(lower)
}

/// [`file_id`], a missing name being `None`.
fn file_id_if_any(path: &Path) -> io::Result<Option<FileId>> {
    match file_id(path) {
        Ok(id) => Ok(Some(id)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// What the directory entry `entry` and its other-case spelling `alt` say
/// about their directory: `Some(true)` insensitive, `Some(false)` sensitive,
/// `None` nothing.
///
/// The entry is examined before AND after `alt`: only an entry that was one
/// and the same file throughout (same inode, link count and change time) can
/// say "sensitive". State files are replaced by rename and temps come and go
/// beside them, so without the second look a probe racing a writer would see
/// "`alt` is missing" or "`alt` is another file" on an insensitive volume,
/// and that writer's name lock would split from everyone else's.
pub(super) fn verdict_of(entry: &Path, alt: &Path) -> io::Result<Option<bool>> {
    let Some(before) = file_id_if_any(entry)? else {
        return Ok(None); // gone since listed
    };
    #[cfg(test)]
    probe_seam::run();
    let other = file_id_if_any(alt)?;
    if file_id_if_any(entry)? != Some(before) {
        return Ok(None);
    }
    Ok(match other {
        // Resolves to the very entry: insensitive, unless it is a second hard
        // link of one file, which says nothing about case.
        Some(other) if other.same_file(&before) => {
            (before.nlink == 1 || before.is_dir).then_some(true)
        }
        _ => Some(false),
    })
}

/// Is `dir` (an existing directory) case-insensitive? See the module docs.
pub(super) fn dir_is_case_insensitive(dir: &Path) -> io::Result<bool> {
    const ENTRIES_TRIED: usize = 64;
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => Some(entries),
        // A directory may be written in without being listable: the probe
        // file decides.
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => None,
        Err(e) => return Err(e),
    };
    for entry in entries.into_iter().flatten().take(ENTRIES_TRIED) {
        let name = entry?.file_name();
        let Some(alt) = other_case(&name) else {
            continue;
        };
        if let Some(verdict) = verdict_of(&dir.join(&name), &dir.join(&alt))? {
            return Ok(verdict);
        }
    }
    probe_with_a_file(dir)
}

/// The probe of last resort: no usable entry, so make one. The name is
/// unique, mixed case, and removed at once.
fn probe_with_a_file(dir: &Path) -> io::Result<bool> {
    static SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let serial = SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = format!(".Fuigo-Case-Probe-{}-{nanos}-{serial}", std::process::id());
    let probe = dir.join(&name);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)?;
    let verdict = verdict_of(&probe, &dir.join(name.to_ascii_lowercase()));
    let removed = std::fs::remove_file(&probe);
    let verdict = verdict?;
    removed?;
    // Nobody else has a reason to touch this name; if somebody did, there is
    // no answer.
    verdict.ok_or_else(|| {
        io::Error::other(format!(
            "the case probe in {} was interfered with",
            dir.display()
        ))
    })
}

/// Case folding of a path, component by component (module docs, "The fold").
/// A path that is its own fold comes back byte for byte.
pub(super) fn fold(path: &Path) -> PathBuf {
    path.components()
        .map(|part| fold_name(part.as_os_str()))
        .collect()
}

fn fold_name(name: &OsStr) -> OsString {
    match name.to_str() {
        Some(s) => {
            use unicode_normalization::UnicodeNormalization as _;
            // Decompose first: canonically equivalent spellings must fold
            // alike (Unicode's canonical caseless matching).
            s.nfd()
                .flat_map(char::to_uppercase)
                .flat_map(char::to_lowercase)
                .flat_map(char::to_uppercase)
                .flat_map(char::to_lowercase)
                .nfd()
                .collect::<String>()
                .into()
        }
        None => name.to_ascii_lowercase(),
    }
}

/// `path` canonical in the platform's EXACT form: what `dunce::canonicalize`
/// gives on unix, and on Windows the verbatim (`\\?\`) path, which is read
/// literally. Every filesystem question here is put in that form: taken apart
/// and put together again in the plain form, a name like `Dir.` or `link.`
/// would be read by the Win32 rules, as `Dir` and `link`, other objects.
#[allow(clippy::disallowed_methods)] // the verbatim form is the point; names go through `plain`
fn canonical_exact(path: &Path) -> io::Result<PathBuf> {
    std::fs::canonicalize(path)
}

/// The plain spelling of a finished exact path, for the NAME only. Applied
/// to the whole path at once (no filesystem access), so a path keeps one
/// spelling whether or not its directories exist yet. P72 hashed the plain
/// spelling of the DIRECTORY with the name appended: the same bytes, except
/// where the name itself keeps the whole path verbatim (module docs).
fn plain(path: &Path) -> PathBuf {
    dunce::simplified(path).to_path_buf()
}

/// The directory `dir` resolved as the kernel will once what is missing
/// exists (exact form), plus the deepest prefix that exists (the directory
/// to probe).
fn resolve_dir(dir: &Path) -> io::Result<(PathBuf, PathBuf)> {
    let mut resolved = PathBuf::new();
    let mut existing = PathBuf::new();
    // How many components of `resolved`, past `existing`, do not exist.
    let mut missing = 0usize;
    for part in dir.components() {
        match part {
            // A Windows prefix alone (`C:`, `\\server\share`) names the
            // drive's current directory or nothing; it is resolved with its
            // root, next.
            Component::Prefix(_) => resolved.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                // Lexical both ways: past a missing component its parent is
                // the prefix before it (back on what exists, resolution
                // resumes), and what exists is canonical, so its parent is
                // its parent (the root's is the root). What exists must be a
                // directory to have one: the kernel refuses `file/..`.
                if missing == 0
                    && !resolved.as_os_str().is_empty()
                    && std::fs::metadata(&resolved).is_ok_and(|md| !md.is_dir())
                {
                    return Err(io::Error::new(
                        io::ErrorKind::NotADirectory,
                        format!("{} is not a directory", plain(&resolved).display()),
                    ));
                }
                resolved.pop();
                if missing > 0 {
                    missing -= 1;
                } else {
                    existing = resolved.clone();
                }
            }
            other => {
                resolved.push(other);
                if missing > 0 {
                    missing += 1;
                    continue;
                }
                match canonical_exact(&resolved) {
                    Ok(real) => {
                        existing = real.clone();
                        resolved = real;
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => missing = 1,
                    Err(e) => return Err(e),
                }
            }
        }
    }
    Ok((resolved, existing))
}

/// Where `path` leads, in the exact form: its directory resolved
/// ([`resolve_dir`]: the resolution, and the deepest existing prefix), and
/// the file name there, a symlink at that name followed (also when it
/// dangles) and the result resolved again, up to 40 links, as
/// `write_through::resolve_write_target` follows them.
fn resolve(path: &Path) -> io::Result<(PathBuf, PathBuf, OsString)> {
    const MAX_LINKS: usize = 40;
    let mut target = std::path::absolute(path)?;
    for followed in 0..=MAX_LINKS {
        let (Some(dir), Some(name)) = (target.parent(), target.file_name()) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a file path", path.display()),
            ));
        };
        let (resolved, existing) = resolve_dir(dir)?;
        if existing.as_os_str().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no part of {} exists", path.display()),
            ));
        }
        // What exists is used as a directory from here on (module docs, "Fail
        // closed"): on Windows nothing else would say that it is not one.
        if !std::fs::metadata(&existing)?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!(
                    "{}: {} is not a directory",
                    path.display(),
                    plain(&existing).display()
                ),
            ));
        }
        let spelled = resolved.join(name);
        // Only a directory that exists can hold a link.
        let is_link = resolved == existing
            && match std::fs::symlink_metadata(&spelled) {
                Ok(md) => md.file_type().is_symlink(),
                Err(e) if e.kind() == io::ErrorKind::NotFound => false,
                Err(e) => return Err(e),
            };
        if !is_link {
            return Ok((resolved, existing, name.to_owned()));
        }
        if followed == MAX_LINKS {
            break;
        }
        let next = std::fs::read_link(&spelled)?;
        target = if next.is_relative() {
            resolved.join(next)
        } else {
            next
        };
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{}: too many levels of symbolic links", path.display()),
    ))
}

/// The identity of the state file at `path`. `case_insensitive` is asked
/// about an existing directory and decides the folding (injected so the
/// case-insensitive rules can be tested on any filesystem).
pub(super) fn identity_with(
    path: &Path,
    case_insensitive: &dyn Fn(&Path) -> io::Result<bool>,
) -> io::Result<Identity> {
    let (resolved, existing, name) = resolve(path)?;
    let spelled = resolved.join(&name);
    let inode = if resolved == existing {
        file_id_if_any(&spelled)?
            .filter(|id| !id.is_dir)
            .map(|id| format!("inode:{:x}:{:x}", id.dev, id.ino).into_bytes())
    } else {
        None
    };
    let insensitive = match case_insensitive(&existing) {
        Ok(verdict) => verdict,
        // Neither listable nor writable (module docs, "Fail closed").
        Err(e) if inode.is_some() && cannot_be_asked(&e) => false,
        Err(e) => return Err(e),
    };
    let named = plain(&spelled);
    let named = if insensitive { fold(&named) } else { named };
    Ok(Identity {
        name: named.into_os_string().into_encoded_bytes(),
        inode,
    })
}

/// The directory entry `path` names, in its ON-DISK spelling, when that is
/// not the spelling given (another case, an 8.3 short name): `None` when the
/// spelling is the entry's own, when there is no such entry, and on every
/// platform but Windows (module docs, "One lock, one directory entry").
///
/// Only the final component is looked at, and a link there is not followed:
/// this is the entry a rename onto `path` replaces. The answer names the same
/// file as `path` (checked), in the exact form: its directory resolved, its
/// name the entry's own, whatever the Win32 rules would make of it.
///
/// # Errors
///
/// When the directory cannot be asked (it may not be listed), and when the
/// entry found is not the file `path` names.
#[cfg(windows)]
pub(super) fn entry_as_on_disk(path: &Path) -> io::Result<Option<PathBuf>> {
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
    use windows::Win32::Storage::FileSystem::{FindClose, FindFirstFileW, WIN32_FIND_DATAW};
    use windows::core::PCWSTR;
    // As `resolve` reads a path: made absolute (which is where Win32 drops a
    // trailing dot or space of a plain path), then the directory in the
    // exact form, so the name is looked up literally and at any length.
    let absolute = std::path::absolute(path)?;
    let (Some(dir), Some(name)) = (absolute.parent(), absolute.file_name()) else {
        return Ok(None);
    };
    let dir = match canonical_exact(dir) {
        Ok(dir) => dir,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    // `FindFirstFileW` takes a pattern. No file name can hold a wildcard, so
    // a name that does names nothing.
    const WILDCARDS: [u16; 5] = [0x2a, 0x3f, 0x3c, 0x3e, 0x22]; // * ? < > "
    if name.encode_wide().any(|c| c == 0 || WILDCARDS.contains(&c)) {
        return Ok(None);
    }
    let asked = dir.join(name);
    let wide: Vec<u16> = asked
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut found = WIN32_FIND_DATAW::default();
    // SAFETY: `wide` is NUL-terminated and outlives the call; `found` is a
    // valid out-pointer.
    let search = match unsafe { FindFirstFileW(PCWSTR(wide.as_ptr()), &mut found) } {
        Ok(search) => search,
        Err(e) => {
            // The Win32 code out of the HRESULT (`io::Error::from` would keep
            // the HRESULT, which has no `ErrorKind`).
            let code = e.code().0;
            let e = if code.cast_unsigned() >> 16 == 0x8007 {
                io::Error::from_raw_os_error(code & 0xffff)
            } else {
                io::Error::other(e)
            };
            return if e.kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(e)
            };
        }
    };
    // SAFETY: `search` is the live handle `FindFirstFileW` returned.
    let _ = unsafe { FindClose(search) };
    let len = found
        .cFileName
        .iter()
        .position(|c| *c == 0)
        .unwrap_or(found.cFileName.len());
    let on_disk = OsString::from_wide(&found.cFileName[..len]);
    if on_disk == name {
        return Ok(None);
    }
    // In the exact directory, as it was looked up: put back into the plain
    // spelling of `path`, a name only the exact form can spell (the long
    // name `Long.toml.` of a short name `LONG~1.TOM`) would be read by the
    // Win32 rules, as another file.
    entry_if_same_file(&asked, &dir.join(&on_disk))
}

/// `entry`, if it is the very file `asked` names (both in the exact form);
/// `None` if `asked` names nothing any more. A rename must not be sent
/// anywhere but where the path leads, and the search that found `entry`
/// matches names by rules of its own.
///
/// # Errors
///
/// When `asked` names a file and `entry` is not that file: its on-disk name
/// is then not established.
#[cfg(windows)]
pub(super) fn entry_if_same_file(asked: &Path, entry: &Path) -> io::Result<Option<PathBuf>> {
    let Some(asked_id) = file_id_if_any(asked)? else {
        return Ok(None);
    };
    match file_id_if_any(entry)? {
        Some(found) if found.same_file(&asked_id) => Ok(Some(entry.to_path_buf())),
        _ => Err(io::Error::other(format!(
            "{} is listed as {}, which is not the same file",
            plain(asked).display(),
            plain(entry).display()
        ))),
    }
}

/// Not on Windows: the kernel keeps an existing entry's spelling when a file
/// is renamed over it (module docs, "One lock, one directory entry").
#[cfg(not(windows))]
#[allow(clippy::unnecessary_wraps)] // one signature with the Windows function
pub(super) fn entry_as_on_disk(_path: &Path) -> io::Result<Option<PathBuf>> {
    Ok(None)
}

/// A probe that failed because the directory may not be written in.
fn cannot_be_asked(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem
    )
}

/// [`identity_with`] on the real filesystem.
pub(super) fn identity(path: &Path) -> io::Result<Identity> {
    identity_with(path, &dir_is_case_insensitive)
}

/// Test seam: a hook run on the probing thread between the first look at an
/// entry and the look at its other-case spelling.
#[cfg(test)]
pub(super) mod probe_seam {
    use std::cell::RefCell;

    type Hook = Option<Box<dyn FnMut()>>;

    thread_local! {
        static HOOK: RefCell<Hook> = const { RefCell::new(None) };
    }

    pub(in super::super) fn set(hook: Hook) {
        HOOK.with(|h| *h.borrow_mut() = hook);
    }

    pub(super) fn run() {
        // Taken out for the call, so a hook may itself use the probe.
        let hook = HOOK.with(|h| h.borrow_mut().take());
        if let Some(mut hook) = hook {
            hook();
            HOOK.with(|h| {
                h.borrow_mut().get_or_insert(hook);
            });
        }
    }
}
