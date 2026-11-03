//! Disk-full classification for failed git writes (1.0.39 item 7, B-F1).
//!
//! git reports a full disk only as an exit status plus stderr. A failed git write classifies as
//! [`GitStorageFull`] only by (a) an anchored ENOSPC stderr line, (b) a known free-space probe under a
//! floor beside a git write-failure line (class W) and no other named cause, or (c) for the with-checkout add, a fit
//! check showing the tree could not fit. Everything else is exactly the 1.0.38 `"{what} failed: {stderr}"` error. A
//! probe error never classifies.
//!
//! The rule is an allow-list of recorded shapes, not a deny-list: disk-full is typed only on the shapes the BF-8
//! recordings show (rule Q, rule U, and the two exact errno-less class W forms), plus the probe/fit conditions beside
//! a W line. Every other line, including any write line that carries an errno of its own, is class O and keeps the
//! 1.0.38 behaviour.

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

/// Free space on one filesystem. `inodes` is `None` when the filesystem reports no inode count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Avail {
    pub bytes: u64,
    pub inodes: Option<u64>,
}

/// What a tree checkout needs: blob bytes and entries (files, links, directories).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Need {
    pub bytes: u64,
    pub entries: u64,
}

/// Under this many free bytes a filesystem counts as full.
pub const STORAGE_FLOOR_BYTES: u64 = 4 * 1024 * 1024;
/// Under this many free inodes a filesystem counts as full.
pub const STORAGE_FLOOR_INODES: u64 = 64;

/// Free space on the filesystem holding a path.
pub trait FreeSpaceProbe {
    fn avail(&self, path: &Path) -> io::Result<Avail>;
}

/// `statvfs(3)`: bytes from `f_bavail * f_frsize`, inodes from `f_favail` (`None` when `f_files` is 0).
pub struct StatvfsProbe;

impl FreeSpaceProbe for StatvfsProbe {
    #[cfg(unix)]
    fn avail(&self, path: &Path) -> io::Result<Avail> {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: `c` is a valid NUL-terminated path and `st` a writable statvfs.
        if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        #[allow(clippy::unnecessary_cast)]
        let bytes = (st.f_bavail as u64).saturating_mul(st.f_frsize as u64);
        #[allow(clippy::unnecessary_cast)]
        let inodes = (st.f_files as u64 != 0).then_some(st.f_favail as u64);
        Ok(Avail { bytes, inodes })
    }

    /// No probe off unix: unknown, so only an anchored stderr line can classify.
    #[cfg(not(unix))]
    fn avail(&self, _path: &Path) -> io::Result<Avail> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// Which rule decided a [`GitStorageFull`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageFullBy {
    /// An anchored ENOSPC stderr line (BF-3 rule Q or U).
    Line,
    /// A known probe under a floor beside a write-failure line (W), no other named cause.
    Floor,
    /// The with-checkout add: the tree could not fit (BF-7).
    Fit,
}

/// A git write that failed because the disk (or its inode table) is full. Its `source()` is an
/// `io::Error` of kind `StorageFull`, so typed disk-full checks match it with no text.
#[derive(Debug)]
pub struct GitStorageFull {
    pub what: String,
    pub stderr: String,
    pub path: PathBuf,
    pub available: Option<Avail>,
    pub need: Option<Need>,
    pub by: StorageFullBy,
    io: io::Error,
}

impl std::fmt::Display for GitStorageFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Trimmed so the space note ends git's last line instead of starting a line of its own; `stderr` keeps the
        // verbatim text, and only a classified failure reaches this (the unclassified error is untouched 1.0.38 text).
        write!(f, "{} failed: {}", self.what, self.stderr.trim_end())?;
        let fs = self.path.display();
        match (self.by, self.available, self.need) {
            (StorageFullBy::Line, ..) | (_, None, _) => {
                write!(f, " (git reported no space left on the device)")
            }
            (StorageFullBy::Floor, Some(a), _) if a.bytes < STORAGE_FLOOR_BYTES => {
                write!(f, " (only {} KiB free on {fs})", a.bytes / 1024)
            }
            (StorageFullBy::Floor, Some(a), _) => {
                write!(f, " (only {} inodes free on {fs})", a.inodes.unwrap_or(0))
            }
            (StorageFullBy::Fit, Some(a), Some(n)) if a.bytes < n.bytes + STORAGE_FLOOR_BYTES => {
                write!(
                    f,
                    " (the checkout needs {} KiB; only {} KiB free on {fs})",
                    n.bytes.div_ceil(1024),
                    a.bytes / 1024
                )
            }
            (StorageFullBy::Fit, Some(a), Some(n)) => write!(
                f,
                " (the checkout needs {} files; only {} inodes free on {fs})",
                n.entries,
                a.inodes.unwrap_or(0)
            ),
            (StorageFullBy::Fit, Some(a), None) => {
                write!(f, " (only {} KiB free on {fs})", a.bytes / 1024)
            }
        }
    }
}

impl std::error::Error for GitStorageFull {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.io)
    }
}

/// BF-3 stderr rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineRule {
    /// `...'<path>': No space left on device` (strerror after a quoted path).
    Q,
    /// `error: unable to create file <path>: No space left on device` (git's unquoted checkout line).
    U,
}

/// BF-3a line class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineClass {
    /// Disk-full line (rule Q or U).
    S,
    /// errno-less checkout write, exactly `error: unable to write file <path>` (no `:` in the path) or
    /// `error: unable to write file '<path>'` (nothing after the closing quote).
    W,
    /// Recognised summary without errno.
    R,
    /// Informational.
    I,
    /// Anything else: a named cause of its own.
    O,
}

const ENOSPC_TAIL: &str = ": No space left on device";
const RULE_U_PREFIX: &str = "error: unable to create file ";
const CLASS_W_PREFIX: &str = "error: unable to write file ";
const CLASS_R_PREFIX: &str = "fatal: Could not reset index file to revision '";
const CLASS_I_PREFIX: &str = "Preparing worktree (";

/// The BF-3 rule a single line (trailing `\r` trimmed) matches, if any.
pub fn line_rule(line: &str) -> Option<LineRule> {
    let line = line.strip_suffix('\r').unwrap_or(line);
    let tail = line.rfind('\'').map_or(line, |i| &line[i + 1..]);
    if tail == ENOSPC_TAIL {
        Some(LineRule::Q)
    } else if line.starts_with(RULE_U_PREFIX) && line.ends_with(ENOSPC_TAIL) {
        Some(LineRule::U)
    } else {
        None
    }
}

/// The BF-3a class of a single non-empty line (trailing `\r` trimmed).
pub fn line_class(line: &str) -> LineClass {
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line_rule(line).is_some() {
        LineClass::S
    } else if line
        .strip_prefix(CLASS_W_PREFIX)
        .is_some_and(is_errno_less_path)
    {
        LineClass::W
    } else if line
        .strip_prefix(CLASS_R_PREFIX)
        .is_some_and(|rest| rest.len() >= 2 && rest.ends_with("'."))
    {
        LineClass::R
    } else if line.starts_with(CLASS_I_PREFIX) {
        LineClass::I
    } else {
        LineClass::O
    }
}

/// The rest of a class W line: a bare path with no `:` (git's `error()` form), or one single-quoted path with
/// nothing after the closing quote. Any strerror suffix (`'<p>': Permission denied`) fails both and is class O.
fn is_errno_less_path(rest: &str) -> bool {
    match rest.strip_prefix('\'') {
        Some(q) => q
            .strip_suffix('\'')
            .is_some_and(|p| !p.is_empty() && !p.contains('\'')),
        None => !rest.is_empty() && !rest.contains(':'),
    }
}

/// Every non-empty stderr line (trailing `\r` trimmed) with its class.
pub fn classify_lines(stderr: &str) -> Vec<(&str, LineClass)> {
    stderr
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .filter(|l| !l.is_empty())
        .map(|l| (l, line_class(l)))
        .collect()
}

/// Free space on the filesystem holding `path` (the test seam replaces it in tests).
pub fn probe(path: &Path) -> io::Result<Avail> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(r) = seam::probe(path) {
        return r;
    }
    StatvfsProbe.avail(path)
}

fn under_floor(a: &Avail) -> bool {
    a.bytes < STORAGE_FLOOR_BYTES || a.inodes.is_some_and(|i| i < STORAGE_FLOOR_INODES)
}

fn cannot_fit(a: &Avail, n: &Need) -> bool {
    a.bytes < n.bytes.saturating_add(STORAGE_FLOOR_BYTES)
        || a.inodes
            .is_some_and(|i| i < n.entries.saturating_add(STORAGE_FLOOR_INODES))
}

/// `need` of `git_ref`'s tree: a recursive walk counting entries and adding each blob's size from its
/// object header (no decompression).
pub fn tree_need(repo_path: &Path, git_ref: &str) -> anyhow::Result<Need> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(r) = seam::need() {
        return r;
    }
    let repo = gix::discover(repo_path)?;
    // HEAD, a full ref name, or a full object id; anything else is a walk error (1.0.38 fallback).
    let id = if git_ref == "HEAD" {
        repo.head_id()?.detach()
    } else if let Ok(mut r) = repo.find_reference(git_ref) {
        r.peel_to_id()?.detach()
    } else {
        gix::ObjectId::from_hex(git_ref.as_bytes())?
    };
    let root = repo.find_object(id)?.peel_to_tree()?.id;
    let mut need = Need {
        bytes: 0,
        entries: 0,
    };
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        let tree = repo.find_tree(id)?;
        for entry in tree.iter() {
            let entry = entry?;
            need.entries += 1;
            let mode = entry.mode();
            if mode.is_tree() {
                stack.push(entry.oid().to_owned());
            } else if mode.is_blob_or_symlink() {
                need.bytes += repo.find_header(entry.oid())?.size();
            }
        }
    }
    Ok(need)
}

/// The fit check's inputs: the with-checkout add's source repository and ref (BF-7).
pub struct FitCheck<'a> {
    pub repo: &'a Path,
    pub git_ref: &'a str,
}

/// `fs_paths` for a `worktree add`: `dest`'s nearest existing parent and the source's git common dir
/// (falling back to the source itself). Computed only after a failed add.
pub fn add_fs_paths(dest: &Path, source: &Path) -> Vec<PathBuf> {
    let mut parent = dest.parent();
    while let Some(p) = parent {
        if p.as_os_str().is_empty() {
            parent = None;
            break;
        }
        if matches!(p.try_exists(), Ok(true)) {
            break;
        }
        parent = p.parent();
    }
    let parent = parent.map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let common = gix::discover(source)
        .map(|r| r.common_dir().to_path_buf())
        .unwrap_or_else(|_| source.to_path_buf());
    vec![parent, common]
}

/// Classify a failed (non-zero exit) git write. Returns a [`GitStorageFull`] only by BF-2's three rules;
/// otherwise exactly the 1.0.38 error `"{what} failed: {stderr}"`.
pub fn git_write_failure(
    what: &str,
    status: &ExitStatus,
    stderr: &str,
    fs_paths: &[PathBuf],
    fit: Option<FitCheck<'_>>,
) -> anyhow::Error {
    let lines = classify_lines(stderr);
    let typed = |by, path: &Path, available, need| {
        tracing::warn!(what, ?status, ?by, path = %path.display(), ?available, ?need, "git write failed on a full disk");
        anyhow::Error::new(GitStorageFull {
            what: what.to_string(),
            stderr: stderr.to_string(),
            path: path.to_path_buf(),
            available,
            need,
            by,
            io: io::Error::from(io::ErrorKind::StorageFull),
        })
    };
    let first = fs_paths
        .first()
        .map_or_else(|| PathBuf::from("."), Clone::clone);
    if lines.iter().any(|(_, c)| *c == LineClass::S) {
        return typed(StorageFullBy::Line, &first, None, None);
    }
    if !lines.iter().any(|(_, c)| *c == LineClass::O) {
        // Floor needs git's own word that a write failed (a W line; the R summary never classifies on its own, BF-3a);
        // an empty, informational-only or summary-only failure keeps the 1.0.38 fallback whatever the probe says.
        let write_failed = lines.iter().any(|(_, c)| *c == LineClass::W);
        let mut first_avail = None;
        for (i, p) in fs_paths.iter().enumerate() {
            if let Ok(a) = probe(p) {
                if i == 0 {
                    first_avail = Some(a);
                }
                if write_failed && under_floor(&a) {
                    return typed(StorageFullBy::Floor, p, Some(a), None);
                }
            }
        }
        if let (Some(fit), Some(a)) = (fit, first_avail)
            && lines.iter().any(|(_, c)| *c == LineClass::W)
        {
            match tree_need(fit.repo, fit.git_ref) {
                Ok(n) if cannot_fit(&a, &n) => {
                    return typed(StorageFullBy::Fit, &first, Some(a), Some(n));
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!(error = %e, "worktree fit check skipped: tree walk failed")
                }
            }
        }
    }
    anyhow::anyhow!("{what} failed: {stderr}")
}

/// Thread-local overrides for the probe and the tree walk, with call counters.
#[cfg(any(test, feature = "test-support"))]
pub mod seam {
    use super::{Avail, Need};
    use std::cell::{Cell, RefCell};
    use std::io;
    use std::path::Path;

    type ProbeFn = Box<dyn Fn(&Path) -> io::Result<Avail>>;
    type NeedFn = Box<dyn Fn() -> anyhow::Result<Need>>;

    thread_local! {
        static PROBE: RefCell<Option<ProbeFn>> = const { RefCell::new(None) };
        static NEED: RefCell<Option<NeedFn>> = const { RefCell::new(None) };
        static PROBE_CALLS: Cell<usize> = const { Cell::new(0) };
        static NEED_CALLS: Cell<usize> = const { Cell::new(0) };
    }

    /// Clears every override on drop.
    pub struct SeamGuard(());
    impl Drop for SeamGuard {
        fn drop(&mut self) {
            PROBE.with(|p| *p.borrow_mut() = None);
            NEED.with(|n| *n.borrow_mut() = None);
        }
    }

    /// Reset the counters and install overrides on this thread (`None` keeps the real one).
    pub fn install(probe: Option<ProbeFn>, need: Option<NeedFn>) -> SeamGuard {
        PROBE_CALLS.with(|c| c.set(0));
        NEED_CALLS.with(|c| c.set(0));
        PROBE.with(|p| *p.borrow_mut() = probe);
        NEED.with(|n| *n.borrow_mut() = need);
        SeamGuard(())
    }

    pub fn probe_calls() -> usize {
        PROBE_CALLS.with(Cell::get)
    }

    pub fn need_calls() -> usize {
        NEED_CALLS.with(Cell::get)
    }

    pub(super) fn probe(path: &Path) -> Option<io::Result<Avail>> {
        PROBE_CALLS.with(|c| c.set(c.get() + 1));
        PROBE.with(|p| p.borrow().as_ref().map(|f| f(path)))
    }

    pub(super) fn need() -> Option<anyhow::Result<Need>> {
        NEED_CALLS.with(|c| c.set(c.get() + 1));
        NEED.with(|n| n.borrow().as_ref().map(|f| f()))
    }
}

#[cfg(test)]
#[path = "space_tests.rs"]
mod tests;
