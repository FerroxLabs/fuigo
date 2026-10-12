//! Change detection of protected files for a peer-influenced session (peer messaging S6.6, packet 6 part B2).
//!
//! When a session becomes peer-influenced, [`Watch::snapshot`] records size, mtime and a SHA-256 of each existing
//! protected file that is cheap to list (the well-known instruction and config files of the working directory, its
//! ancestors, the user's home and the Fuigo home, plus the top level of the rule, hook and peer directories). After every
//! tool call [`Watch::recheck`] stats each recorded file and hashes one only when its size or mtime moved.
//!
//! Limits: at most [`MAX_PRESENT`] files are read, each at most [`MAX_FILE_BYTES`]; larger files are skipped (listed by
//! [`Watch::skipped`], never watched). A copy of every snapshotted file is kept in memory ([`Watch::copy_of`]) for a later
//! restore command; no restore is offered yet. A file that did not exist counts as a change only when it is on the fixed
//! list of well-known names (recorded as "absent"). Nothing here keeps or logs file content: a [`Change`] holds a path and
//! two hashes.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use sha2::{Digest, Sha256};

/// Most files whose content is read and kept.
pub(crate) const MAX_PRESENT: usize = 64;
/// Most absent well-known names recorded.
const MAX_ABSENT: usize = 256;
/// Largest file that is hashed and copied; a larger one is skipped.
pub(crate) const MAX_FILE_BYTES: u64 = 256 * 1024;
/// Recorded in place of a hash for a file over the size cap: its stat fields are compared, its bytes are never read.
const OVERSIZE: &str = "oversize";
/// Recorded in place of a hash for a FIFO, socket or device: never opened.
const SPECIAL: &str = "special";
const MAX_ANCESTORS: usize = 16;

/// Well-known file names relative to a directory that can hold project or user instructions and config.
const DIR_FILES: &[&str] = &[
    "CLAUDE.md",
    "CLAUDE.local.md",
    "AGENTS.md",
    "AGENT.md",
    ".mcp.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".cursor/hooks.json",
    ".cursor/mcp.json",
    ".fuigo/config.toml",
    ".fuigo/sandbox.toml",
    ".git/config",
];
/// Directories whose top-level files are watched when they exist.
const DIR_LISTS: &[&str] = &[
    ".claude/rules",
    ".fuigo/rules",
    ".cursor/rules",
    ".claude/commands",
    ".claude/agents",
    ".fuigo/commands",
    ".fuigo/agents",
    ".fuigo/hooks",
    ".git/hooks",
];
/// Skill directories: each subdirectory's `SKILL.md` is watched (the name set of the directory itself is recorded too).
const SKILL_LISTS: &[&str] = &[".claude/skills", ".fuigo/skills"];
/// Well-known names directly in the Fuigo home.
const FUIGO_HOME_FILES: &[&str] = &["config.toml", "sandbox.toml", "managed_config.toml", "requirements.toml", "AGENTS.md", "CLAUDE.md"];
const FUIGO_HOME_LISTS: &[&str] = &["rules", "hooks", "commands", "agents"];
const FUIGO_HOME_SKILLS: &[&str] = &["skills"];
/// Lists under the user's home (`~/.claude/...`); late in the order, so among the first dropped over the file cap.
const HOME_LISTS: &[&str] = &[".claude/rules", ".claude/commands", ".claude/agents"];
const HOME_SKILLS: &[&str] = &[".claude/skills"];
const HOME_FILES: &[&str] = &[".gitconfig", ".claude/settings.json", ".claude/CLAUDE.md"];

/// Where to look.
#[derive(Debug, Clone, Default)]
pub(crate) struct Roots {
    pub cwd: PathBuf,
    pub home: Option<PathBuf>,
    pub fuigo_home: Option<PathBuf>,
}

/// What a watched path is, from `symlink_metadata` (never following a link).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A regular file: its content is read (capped) and hashed.
    File,
    /// A symlink: recorded as (symlink, target string); never opened, never read through.
    Symlink,
    /// A FIFO, socket or device: never opened; only its stat fields are compared.
    Special,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Stat {
    kind: Kind,
    len: u64,
    mtime: Option<SystemTime>,
    /// Change time, inode and device: an equal-length rewrite followed by a reset mtime still moves the ctime.
    #[cfg(unix)]
    ctime: (i64, i64),
    #[cfg(unix)]
    ino: u64,
    #[cfg(unix)]
    dev: u64,
}

#[derive(Debug, Clone)]
enum State {
    Absent,
    Present { stat: Stat, hash: String, copy: Vec<u8> },
}

#[derive(Debug, Clone)]
struct Entry {
    path: PathBuf,
    state: State,
}

/// One protected file whose content changed. Hashes are lowercase SHA-256 hex; `None` means the file is absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Change {
    pub path: PathBuf,
    pub old_hash: Option<String>,
    pub new_hash: Option<String>,
}

/// The path of the finding raised when the protected files could not be read (a hung or failed read): fail closed. It has no
/// hashes and names no real file.
pub(crate) const UNREADABLE_PATH: &str = "(protected files could not be read)";

impl Change {
    /// The finding for a baseline or recheck that did not finish (timeout, panic, died task).
    pub(crate) fn unreadable() -> Self {
        Self { path: PathBuf::from(UNREADABLE_PATH), old_hash: None, new_hash: None }
    }
    pub(crate) fn is_unreadable(&self) -> bool {
        self.old_hash.is_none() && self.new_hash.is_none() && self.path.as_os_str() == UNREADABLE_PATH
    }
}

/// The name set of a watched directory (hash of the sorted names).
#[derive(Debug, Clone)]
struct DirEntry {
    path: PathBuf,
    names: Vec<PathBuf>,
    hash: String,
    /// The directory's own (mtime, ctime, inode). Compared only when the listing was cut at [`MAX_PRESENT`] names, where a name
    /// outside the window would not change `hash`: a created, removed or renamed entry moves the directory's own times.
    stat: Option<DirStat>,
}

type DirStat = (Option<SystemTime>, (i64, i64), u64);

fn dir_stat(path: &Path) -> Option<DirStat> {
    let md = std::fs::symlink_metadata(path).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Some((md.modified().ok(), (md.ctime(), md.ctime_nsec()), md.ino()))
    }
    #[cfg(not(unix))]
    {
        Some((md.modified().ok(), (0, 0), 0))
    }
}

/// A path is attacker-influenced text (a file name made by a peer-driven command): escape control, bidi, zero-width and
/// line-separator characters, and cap the result at 200 characters (the `...` marker included).
pub(crate) fn display_path(path: &Path) -> String {
    const MAX: usize = 200;
    let mut pieces: Vec<String> = Vec::new();
    let mut total = 0usize;
    for c in path.to_string_lossy().chars() {
        let bad = c.is_control()
            || matches!(c, '\u{200b}'..='\u{200f}' | '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}' | '\u{061c}');
        let piece = if bad { format!("\\u{{{:x}}}", c as u32) } else { c.to_string() };
        total += piece.chars().count();
        pieces.push(piece);
        if total > MAX + 16 {
            break; // far past the cap: no need to escape the rest of a huge name
        }
    }
    if total <= MAX {
        return pieces.concat();
    }
    let mut out = String::new();
    let mut n = 0usize;
    for p in pieces {
        let len = p.chars().count();
        if n + len > MAX - 3 {
            break;
        }
        out.push_str(&p);
        n += len;
    }
    out.push_str("...");
    out
}

fn names_hash(names: &[PathBuf]) -> String {
    let mut h = Sha256::new();
    for n in names {
        h.update(n.to_string_lossy().as_bytes());
        h.update([0u8]);
    }
    format!("{:x}", h.finalize())
}

#[derive(Debug, Default)]
pub(crate) struct Watch {
    entries: Vec<Entry>,
    dirs: Vec<DirEntry>,
    skipped: Vec<PathBuf>,
    /// Changes found by a recheck and not yet taken by the caller: a recheck cancelled between the file work and the
    /// application of its result leaves its findings here, so the next call still reports them.
    pending: Vec<Change>,
}

/// The shared watch: file work runs on a blocking thread under this mutex, never under a session state lock.
pub(crate) type SharedWatch = std::sync::Arc<std::sync::Mutex<Watch>>;

/// Run [`Watch::recheck`] and park its findings in `pending` (blocking file work; call from `spawn_blocking`).
pub(crate) fn recheck_into_pending(shared: &SharedWatch) {
    let mut w = shared.lock().unwrap_or_else(|p| p.into_inner());
    let found = w.recheck();
    w.pending.extend(found);
}

/// Take the findings parked by [`recheck_into_pending`] (no file work).
pub(crate) fn drain_pending(shared: &SharedWatch) -> Vec<Change> {
    std::mem::take(&mut shared.lock().unwrap_or_else(|p| p.into_inner()).pending)
}

/// What the admission state holds: the watch (once armed) and whether a change tripped the `integrity` hold.
#[derive(Debug, Default)]
pub(crate) struct IntegrityState {
    watch: Option<SharedWatch>,
    armed: bool,
    /// The baseline is being read on a blocking thread (the result is adopted with [`Self::adopt`]).
    arming: bool,
    tripped: bool,
    /// Bumped by every reset, so a recheck that took the watch before a clear cannot put it back (or trip) after it.
    generation: u64,
}

impl IntegrityState {
    pub(crate) fn armed(&self) -> bool {
        self.armed
    }
    pub(crate) fn tripped(&self) -> bool {
        self.tripped
    }
    pub(crate) fn arming(&self) -> bool {
        self.arming
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    /// Mark the baseline read as started; `false` when armed, arming or tripped already (nothing to do).
    pub(crate) fn begin_arming(&mut self) -> bool {
        if self.armed || self.arming || self.tripped {
            return false;
        }
        self.arming = true;
        true
    }
    /// The baseline wait timed out: the hold goes up and nothing is left arming (no second read starts while the first is parked).
    /// `false` when it was not arming (nothing to do).
    pub(crate) fn trip_timeout(&mut self) -> bool {
        if !self.arming {
            return false;
        }
        self.arming = false;
        self.tripped = true;
        true
    }
    /// Adopt a baseline read for `generation`; dropped (nothing changes) when a reset happened since it started.
    pub(crate) fn adopt(&mut self, watch: Watch, generation: u64) {
        if generation == self.generation {
            self.arming = false;
            self.arm_with(watch);
        }
    }
    pub(crate) fn arm_with(&mut self, watch: Watch) {
        if !self.armed {
            self.armed = true;
            self.watch = Some(std::sync::Arc::new(std::sync::Mutex::new(watch)));
        }
    }
    /// Restore the hold from stored history: tripped, nothing left to watch (a resumed hold needs no baseline).
    pub(crate) fn restore_tripped(&mut self) {
        self.armed = true;
        self.arming = false;
        self.tripped = true;
        self.watch = None;
    }
    /// The watch for a recheck, or `None` when not armed or already tripped.
    pub(crate) fn take_for_check(&self) -> Option<(SharedWatch, u64)> {
        if self.tripped { None } else { self.watch.clone().map(|w| (w, self.generation)) }
    }
    /// Apply a recheck result. `false` (and nothing changes) when a reset happened in between.
    pub(crate) fn put_back(&mut self, tripped: bool, generation: u64) -> bool {
        if generation != self.generation {
            return false;
        }
        self.tripped |= tripped;
        true
    }
    /// The human's clear: drop the watch and the hold; any recheck in flight is void.
    pub(crate) fn reset(&mut self) {
        let generation = self.generation.wrapping_add(1);
        *self = Self { generation, ..Self::default() };
    }
}

fn hash_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// The hash used for a path in the audit log: a path may hold a user name, so only its hash is written.
pub(crate) fn path_hash(path: &Path) -> String {
    hash_hex(path.to_string_lossy().as_bytes())
}

fn stat_of(path: &Path) -> Option<Stat> {
    // `symlink_metadata`: a symlink is itself the thing watched, never followed.
    let md = std::fs::symlink_metadata(path).ok()?;
    let ft = md.file_type();
    let kind = if ft.is_symlink() {
        Kind::Symlink
    } else if ft.is_file() {
        Kind::File
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt as _;
            if ft.is_fifo() || ft.is_socket() || ft.is_block_device() || ft.is_char_device() {
                Kind::Special
            } else {
                return None;
            }
        }
        #[cfg(not(unix))]
        return None;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Some(Stat { kind, len: md.len(), mtime: md.modified().ok(), ctime: (md.ctime(), md.ctime_nsec()), ino: md.ino(), dev: md.dev() })
    }
    #[cfg(not(unix))]
    {
        Some(Stat { kind, len: md.len(), mtime: md.modified().ok() })
    }
}

/// The hash of a symlink's recorded state: its target string, never the target's content.
fn symlink_hash(path: &Path) -> Option<String> {
    let target = std::fs::read_link(path).ok()?;
    let mut h = Sha256::new();
    h.update(b"symlink\0");
    h.update(target.to_string_lossy().as_bytes());
    Some(format!("{:x}", h.finalize()))
}

/// The hash and copy for a path whose stat says `kind`. A symlink is hashed by its target string and a special file is
/// never opened.
fn read_state(path: &Path, kind: Kind) -> Option<(String, Vec<u8>)> {
    match kind {
        Kind::File => read_capped(path).map(|b| (hash_hex(&b), b)),
        Kind::Symlink => symlink_hash(path).map(|h| (h, Vec::new())),
        Kind::Special => Some((SPECIAL.to_owned(), Vec::new())),
    }
}

/// Read at most the cap plus one byte, so a file that grew past the cap is still hashed (and so differs).
fn read_capped(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let mut buf = Vec::new();
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // A path swapped to a FIFO since the stat must not block the open, nor a swapped symlink be followed.
        opts.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let f = opts.open(path).ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    f.take(MAX_FILE_BYTES + 1).read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// The first [`MAX_PRESENT`] names of a directory (the read stops there, so a huge directory is not read whole), sorted.
fn capped_names(dir: &Path) -> Option<Vec<PathBuf>> {
    if !std::fs::symlink_metadata(dir).ok()?.file_type().is_dir() {
        return None; // a symlinked directory is never listed through
    }
    let rd = std::fs::read_dir(dir).ok()?;
    let mut names: Vec<PathBuf> = rd.filter_map(Result::ok).take(MAX_PRESENT).map(|e| e.path()).collect();
    names.sort();
    Some(names)
}

/// List a directory: its path goes to `dirs` (its name set is recorded; an added or removed name is a change) and its
/// entries to `out`. With `skills`, each entry is a skill directory and its `SKILL.md` is listed instead.
fn list_files(dir: &Path, skills: bool, out: &mut Vec<PathBuf>, dirs: &mut Vec<PathBuf>) {
    // A symlinked directory is watched as the link itself (never listed through).
    if std::fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_symlink()) {
        out.push(dir.to_path_buf());
        return;
    }
    let Some(names) = capped_names(dir) else { return };
    dirs.push(dir.to_path_buf());
    out.extend(names.into_iter().map(|n| {
        if skills && std::fs::symlink_metadata(&n).is_ok_and(|m| m.file_type().is_dir()) { n.join("SKILL.md") } else { n }
    }));
}

/// The fixed list (watched even when absent) and the listed files (watched only when present).
///
/// Over the file cap the later `listed` entries are dropped first (reported by [`Watch::skipped`]): the order is the working
/// directory and its ancestors (nearest first), then the Fuigo home, then `~/.claude/...`, then the memory directory last.
fn candidates(roots: &Roots) -> (Vec<PathBuf>, Vec<PathBuf>, Vec<PathBuf>) {
    let mut fixed = Vec::new();
    let mut listed = Vec::new();
    let mut dirs = Vec::new();
    for dir in roots.cwd.ancestors().take(MAX_ANCESTORS) {
        fixed.extend(DIR_FILES.iter().map(|f| dir.join(f)));
        for d in DIR_LISTS {
            list_files(&dir.join(d), false, &mut listed, &mut dirs);
        }
        for d in SKILL_LISTS {
            list_files(&dir.join(d), true, &mut listed, &mut dirs);
        }
    }
    if let Some(f) = &roots.fuigo_home {
        fixed.extend(FUIGO_HOME_FILES.iter().map(|n| f.join(n)));
        for d in FUIGO_HOME_LISTS {
            list_files(&f.join(d), false, &mut listed, &mut dirs);
        }
        for d in FUIGO_HOME_SKILLS {
            list_files(&f.join(d), true, &mut listed, &mut dirs);
        }
    }
    if let Some(h) = &roots.home {
        fixed.extend(HOME_FILES.iter().map(|f| h.join(f)));
        for d in HOME_LISTS {
            list_files(&h.join(d), false, &mut listed, &mut dirs);
        }
        for d in HOME_SKILLS {
            list_files(&h.join(d), true, &mut listed, &mut dirs);
        }
    }
    if let Some(f) = &roots.fuigo_home {
        list_files(&f.join("memory"), false, &mut listed, &mut dirs);
    }
    (fixed, listed, dirs)
}

impl Watch {
    /// Record the current state of every candidate. Reads at most [`MAX_PRESENT`] files of at most [`MAX_FILE_BYTES`].
    pub(crate) fn snapshot(roots: &Roots) -> Self {
        let (fixed, listed, dirs) = candidates(roots);
        let mut w = Self::default();
        for d in dirs {
            if let Some(names) = capped_names(&d) {
                let hash = names_hash(&names);
                let stat = dir_stat(&d);
                w.dirs.push(DirEntry { path: d, names, hash, stat });
            }
        }
        let mut seen = HashSet::new();
        let mut present = 0usize;
        let mut absent = 0usize;
        let n_fixed = fixed.len();
        for (i, path) in fixed.into_iter().chain(listed).enumerate() {
            if !seen.insert(path.clone()) {
                continue;
            }
            match stat_of(&path) {
                // Only the fixed names are recorded as absent; a listed file is present by construction.
                None if i < n_fixed && absent < MAX_ABSENT && std::fs::symlink_metadata(&path).is_err() => {
                    absent += 1;
                    w.entries.push(Entry { path, state: State::Absent });
                }
                None => {}
                // Too big to hash: only its stat fields are kept (no content, no hash), so a change still trips the hold.
                Some(stat) if stat.kind == Kind::File && stat.len > MAX_FILE_BYTES => {
                    w.skipped.push(path.clone());
                    if present < MAX_PRESENT {
                        present += 1;
                        w.entries.push(Entry { path, state: State::Present { stat, hash: OVERSIZE.to_owned(), copy: Vec::new() } });
                    }
                }
                Some(_) if present >= MAX_PRESENT => w.skipped.push(path),
                Some(stat) => {
                    let Some((hash, copy)) = read_state(&path, stat.kind) else { continue };
                    present += 1;
                    w.entries.push(Entry { path, state: State::Present { stat, hash, copy } });
                }
            }
        }
        w
    }

    /// Files not watched because they are over the size cap or past the file cap.
    pub(crate) fn skipped(&self) -> &[PathBuf] {
        &self.skipped
    }

    #[cfg(test)]
    pub(crate) fn watched_len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(crate) fn watched_len_absent(&self) -> usize {
        self.entries.iter().filter(|e| matches!(e.state, State::Absent)).count()
    }

    /// The in-memory copy taken at snapshot (kept for a future restore command; none is offered yet).
    #[allow(dead_code)]
    pub(crate) fn copy_of(&self, path: &Path) -> Option<&[u8]> {
        self.entries.iter().find(|e| e.path == path).and_then(|e| match &e.state {
            State::Present { copy, .. } => Some(copy.as_slice()),
            State::Absent => None,
        })
    }

    /// Stat every recorded file and the name set of every watched directory; hash only a file whose size or mtime moved. Each change is reported once (the recorded state
    /// moves to what was seen).
    pub(crate) fn recheck(&mut self) -> Vec<Change> {
        let mut out = Vec::new();
        let mut added: Vec<PathBuf> = Vec::new();
        for d in &mut self.dirs {
            let names = capped_names(&d.path).unwrap_or_default();
            let hash = names_hash(&names);
            let stat = dir_stat(&d.path);
            // A listing cut at the cap can miss a new or removed name: then the directory's own times decide.
            let cut = d.names.len() >= MAX_PRESENT || names.len() >= MAX_PRESENT;
            let stat_only = hash == d.hash && cut && stat != d.stat;
            if hash != d.hash || stat_only {
                added.extend(names.iter().filter(|n| !d.names.contains(n)).cloned());
                let new_hash = if stat_only { hash_hex(format!("{hash}|{stat:?}").as_bytes()) } else { hash.clone() };
                out.push(Change { path: d.path.clone(), old_hash: Some(std::mem::replace(&mut d.hash, hash)), new_hash: Some(new_hash) });
                d.names = names;
            }
            d.stat = stat;
        }
        // A name that appeared is watched from now on (within the file cap).
        for path in added {
            let path = if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_dir()) { path.join("SKILL.md") } else { path };
            if self.entries.iter().any(|e| e.path == path) || self.entries.len() >= MAX_PRESENT + MAX_ABSENT {
                continue;
            }
            if let Some(stat) = stat_of(&path)
                && (stat.kind != Kind::File || stat.len <= MAX_FILE_BYTES)
                && let Some((hash, copy)) = read_state(&path, stat.kind)
            {
                self.entries.push(Entry { path, state: State::Present { stat, hash, copy } });
            }
        }
        for e in &mut self.entries {
            let now = stat_of(&e.path);
            match (&mut e.state, now) {
                (State::Absent, None) => {}
                (State::Absent, Some(stat)) => {
                    let h = read_state(&e.path, stat.kind).map(|(h, _)| h).unwrap_or_default();
                    out.push(Change { path: e.path.clone(), old_hash: None, new_hash: Some(h.clone()) });
                    e.state = State::Present { stat, hash: h, copy: Vec::new() };
                }
                (State::Present { hash, .. }, None) => {
                    out.push(Change { path: e.path.clone(), old_hash: Some(hash.clone()), new_hash: None });
                    e.state = State::Absent;
                }
                (State::Present { stat, hash, .. }, Some(new)) => {
                    // A symlink's target string is cheap to read, so it is compared even when the stat fields are equal.
                    if *stat == new && new.kind != Kind::Symlink {
                        continue;
                    }
                    if hash == OVERSIZE {
                        *stat = new;
                        out.push(Change { path: e.path.clone(), old_hash: Some(OVERSIZE.to_owned()), new_hash: Some("oversize-changed".to_owned()) });
                        continue;
                    }
                    // An unreadable path (a swap to a FIFO or a link since the stat) is a change, never skipped.
                    let nh = read_state(&e.path, new.kind).map(|(h, _)| h).unwrap_or_else(|| "unreadable".to_owned());
                    *stat = new;
                    if nh != *hash {
                        out.push(Change { path: e.path.clone(), old_hash: Some(hash.clone()), new_hash: Some(nh.clone()) });
                        *hash = nh;
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
#[path = "peer_integrity_tests.rs"]
mod tests;
