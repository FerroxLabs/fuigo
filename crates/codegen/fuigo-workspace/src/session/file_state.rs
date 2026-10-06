//! Captures and restores file states at specific points during a session.
//! Each "rewind point" corresponds to a user prompt and stores snapshots of all files that were read or modified during that prompt's processing.
//!
//! Paths in `FileSnapshot` and `RewindPoint` are stored as `FlexiblePath`: a `RelPathBuf` relative to the session CWD, or an absolute `PathBuf`.
//! Relative paths keep sessions portable across machines; absolute ones come from older sessions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::file_system::{AsyncFileSystem, AsyncFsWrapper, bytes_to_string};
// Minimal duplicate of the shell crate's ToolContext, kept to break a dependency cycle
// Only the fields and methods the rewind logic needs survive, with the public API unchanged
#[derive(Clone)]
pub struct ToolContext {
    pub cwd: std::path::PathBuf,
    pub fs: crate::file_system::AsyncFsWrapper,
}
impl ToolContext {
    pub fn new_local_context(
        cwd: std::path::PathBuf,
        fs: crate::file_system::AsyncFsWrapper,
        _runner: std::sync::Arc<dyn std::any::Any + Send + Sync>,
    ) -> Self {
        Self { cwd, fs }
    }
}
impl Default for ToolContext {
    fn default() -> Self {
        Self {
            cwd: std::path::PathBuf::new(),
            fs: crate::file_system::AsyncFsWrapper::new(std::sync::Arc::new(
                crate::file_system::MockFs::new(std::path::PathBuf::new()),
            )),
        }
    }
}
use fuigo_paths::{RelPathBuf, ToAbsPath};

/// Either a relative path (preferred) or an absolute path kept for older sessions that stored absolute paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FlexiblePath {
    Relative(RelPathBuf),
    Absolute(PathBuf),
}

impl FlexiblePath {
    pub fn from_rel(path: RelPathBuf) -> Self {
        Self::Relative(path)
    }

    pub fn as_path(&self) -> &Path {
        match self {
            Self::Relative(p) => p.as_ref(),
            Self::Absolute(p) => p.as_ref(),
        }
    }

    /// For relative paths, joins with root. For absolute paths, returns as-is.
    pub fn to_absolute(&self, root: &Path) -> PathBuf {
        match self {
            Self::Relative(p) => p.to_absolute(root),
            Self::Absolute(p) => p.clone(),
        }
    }

    /// A relative path is cloned; an absolute path under root becomes relative, any other absolute path stays as-is.
    pub fn try_to_relative(&self, root: &Path) -> FlexiblePath {
        match self {
            Self::Relative(p) => Self::Relative(p.clone()),
            Self::Absolute(p) => match RelPathBuf::from_absolute(root, p) {
                Ok(rel) => Self::Relative(rel),
                Err(_) => Self::Absolute(p.clone()),
            },
        }
    }

    pub fn is_relative(&self) -> bool {
        matches!(self, Self::Relative(_))
    }

    /// Get the path as a string for serialization
    fn as_str(&self) -> &str {
        match self {
            Self::Relative(p) => p.as_str(),
            Self::Absolute(p) => p.to_str().unwrap_or(""),
        }
    }
}

impl From<RelPathBuf> for FlexiblePath {
    fn from(path: RelPathBuf) -> Self {
        Self::Relative(path)
    }
}

impl AsRef<Path> for FlexiblePath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl std::fmt::Display for FlexiblePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Relative(p) => write!(f, "{}", p.as_str()),
            Self::Absolute(p) => write!(f, "{}", p.display()),
        }
    }
}

impl ToAbsPath for FlexiblePath {
    fn to_abs_path(&self, root: &Path) -> std::borrow::Cow<'_, Path> {
        match self {
            Self::Relative(p) => std::borrow::Cow::Owned(p.to_absolute(root)),
            Self::Absolute(p) => std::borrow::Cow::Borrowed(p.as_path()),
        }
    }
}

impl ToAbsPath for &FlexiblePath {
    fn to_abs_path(&self, root: &Path) -> std::borrow::Cow<'_, Path> {
        match self {
            FlexiblePath::Relative(p) => std::borrow::Cow::Owned(p.to_absolute(root)),
            FlexiblePath::Absolute(p) => std::borrow::Cow::Borrowed(p.as_path()),
        }
    }
}

mod flexible_path_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(path: &FlexiblePath, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(path.as_str())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<FlexiblePath, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match RelPathBuf::try_from(s.clone()) {
            Ok(rel_path) => Ok(FlexiblePath::Relative(rel_path)),
            // Fall back to PathBuf for absolute paths from older sessions
            Err(_) => Ok(FlexiblePath::Absolute(PathBuf::from(s))),
        }
    }
}

mod flexible_path_map_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(
        map: &HashMap<FlexiblePath, FileSnapshot>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map_ser = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            map_ser.serialize_entry(k.as_str(), v)?;
        }
        map_ser.end()
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<HashMap<FlexiblePath, FileSnapshot>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map: HashMap<String, FileSnapshot> = HashMap::deserialize(deserializer)?;
        let mut result = HashMap::with_capacity(map.len());
        for (k, v) in map {
            let path = match RelPathBuf::try_from(k.clone()) {
                Ok(rel_path) => FlexiblePath::Relative(rel_path),
                Err(_) => FlexiblePath::Absolute(PathBuf::from(k)),
            };
            result.insert(path, v);
        }
        Ok(result)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSnapshot {
    /// Path to the file (relative to session CWD preferred, absolute for legacy sessions).
    #[serde(with = "flexible_path_serde")]
    pub path: FlexiblePath,
    /// None if the file didn't exist
    pub content: Option<String>,
    pub captured_at: DateTime<Utc>,
}

impl FileSnapshot {
    pub fn new(path: RelPathBuf, content: Option<String>) -> Self {
        Self {
            path: FlexiblePath::Relative(path),
            content,
            captured_at: Utc::now(),
        }
    }

    pub fn new_flexible(path: FlexiblePath, content: Option<String>) -> Self {
        Self {
            path,
            content,
            captured_at: Utc::now(),
        }
    }

    pub fn as_path(&self) -> &Path {
        self.path.as_path()
    }

    /// For relative paths, joins with root. For absolute paths, returns as-is.
    pub fn to_absolute_path(&self, root: &Path) -> PathBuf {
        self.path.to_absolute(root)
    }

    /// Returns a copy with the path converted to relative when it is absolute and under root.
    pub fn normalize_to_relative(&self, root: &Path) -> FileSnapshot {
        FileSnapshot {
            path: self.path.try_to_relative(root),
            content: self.content.clone(),
            captured_at: self.captured_at,
        }
    }

    pub fn normalize_to_relative_mut(&mut self, root: &Path) {
        self.path = self.path.try_to_relative(root);
    }
}

/// Snapshots of all files that were accessed (read or modified) while one user prompt was processed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewindPoint {
    /// Index of the user prompt in the session (0-based)
    pub prompt_index: usize,
    pub created_at: DateTime<Utc>,
    /// File snapshots captured BEFORE any operations for this prompt.
    #[serde(with = "flexible_path_map_serde")]
    pub file_snapshots: HashMap<FlexiblePath, FileSnapshot>,
    /// File snapshots captured AFTER all operations for this prompt completed.
    /// Used to detect external modifications: if the current file differs from its after-snapshot, something else changed it.
    #[serde(default, with = "flexible_path_map_serde")]
    pub after_snapshots: HashMap<FlexiblePath, FileSnapshot>,
}

impl RewindPoint {
    pub fn new(prompt_index: usize) -> Self {
        Self {
            prompt_index,
            created_at: Utc::now(),
            file_snapshots: HashMap::new(),
            after_snapshots: HashMap::new(),
        }
    }

    /// Add a file snapshot to this rewind point (if not already present)
    pub fn add_snapshot(&mut self, snapshot: FileSnapshot) {
        // Only capture the first snapshot for each file (the state BEFORE any operations)
        self.file_snapshots
            .entry(snapshot.path.clone())
            .or_insert(snapshot);
    }

    /// Set the after-snapshot for a file (what the agent wrote)
    pub fn set_after_snapshot(&mut self, snapshot: FileSnapshot) {
        self.after_snapshots.insert(snapshot.path.clone(), snapshot);
    }

    pub fn get_snapshot(&self, path: &FlexiblePath) -> Option<&FileSnapshot> {
        self.file_snapshots.get(path)
    }

    pub fn get_snapshot_by_rel(&self, path: &RelPathBuf) -> Option<&FileSnapshot> {
        self.file_snapshots
            .get(&FlexiblePath::Relative(path.clone()))
    }

    pub fn snapshot_paths(&self) -> Vec<&FlexiblePath> {
        self.file_snapshots.keys().collect()
    }

    /// Converts absolute paths under root to relative, for portability when saving sessions.
    pub fn normalize_to_relative(&mut self, root: &Path) {
        // Normalize file_snapshots
        let old_snapshots = std::mem::take(&mut self.file_snapshots);
        for (path, mut snapshot) in old_snapshots {
            let new_path = path.try_to_relative(root);
            snapshot.path = new_path.clone();
            self.file_snapshots.insert(new_path, snapshot);
        }

        // Normalize after_snapshots
        let old_after = std::mem::take(&mut self.after_snapshots);
        for (path, mut snapshot) in old_after {
            let new_path = path.try_to_relative(root);
            snapshot.path = new_path.clone();
            self.after_snapshots.insert(new_path, snapshot);
        }
    }
}

/// Lightweight metadata for a single rewind point: what the rewind picker needs (which prompts have snapshots, and when).
/// It carries none of the (potentially huge) file contents. Produced by [`scan_rewind_point_metas`].
#[derive(Debug)]
pub struct RewindPointMeta {
    pub prompt_index: usize,
    pub created_at: DateTime<Utc>,
    pub num_file_snapshots: usize,
}

/// Open a `rewind_points.jsonl` for streaming. `NotFound` becomes `Ok(None)` (no file yet).
/// Other I/O errors propagate so callers can distinguish "absent" from "transiently unreadable" and avoid discarding on-disk history.
fn open_rewind_points(path: &Path) -> io::Result<Option<io::BufReader<std::fs::File>>> {
    match std::fs::File::open(path) {
        Ok(f) => Ok(Some(io::BufReader::new(f))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Call `visit(line_number, line)` for every non-blank line of a `rewind_points.jsonl` (1-based numbers, surrounding
/// whitespace trimmed). Lines are bytes, not text: a record cut short inside a multi-byte character is one damaged line,
/// never an I/O error that fails the whole read (P114). A missing file visits nothing.
fn visit_rewind_lines(path: &Path, mut visit: impl FnMut(usize, &[u8])) -> io::Result<()> {
    let Some(mut reader) = open_rewind_points(path)? else {
        return Ok(());
    };
    let mut line = Vec::new();
    let mut number = 0usize;
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            return Ok(());
        }
        number += 1;
        let trimmed = line.trim_ascii();
        if !trimmed.is_empty() {
            visit(number, trimmed);
        }
    }
}

/// Stream-parse a `rewind_points.jsonl` file line-by-line (bounded memory; the file can be hundreds of MB), skipping malformed lines with a `warn!`.
/// A missing file is `Ok(empty)`; a transient I/O error propagates as `Err` so callers don't treat an unreadable file as empty and drop history.
/// This is the LENIENT reader; the load and the rewrite paths keep the malformed lines (see [`read_rewind_points_lines`]).
fn read_rewind_jsonl_lines<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<Vec<T>> {
    let mut out = Vec::new();
    visit_rewind_lines(path, |_, line| match serde_json::from_slice::<T>(line) {
        Ok(v) => out.push(v),
        Err(e) => tracing::warn!(
            error = %e,
            path = %path.display(),
            "skipping malformed rewind_points.jsonl line"
        ),
    })?;
    Ok(out)
}

/// Read all rewind points (full content), skipping malformed rows.
#[cfg(test)]
fn read_rewind_points_file(path: &Path) -> io::Result<Vec<RewindPoint>> {
    read_rewind_jsonl_lines(path)
}

/// One line of a `rewind_points.jsonl`, in file order (P114).
#[derive(Debug, Clone)]
pub enum RewindPointsLine {
    Point(RewindPoint),
    /// A line that does not parse, kept byte for byte. An append cut short (a kill, a power loss, `ENOSPC`) leaves one,
    /// which the next append terminates as its own line (`append_jsonl_line_sync` in the shell).
    Damaged { line: usize, raw: Vec<u8> },
}

/// How long a read waits for an append in progress (another process writing a large row) before giving up for now.
const APPEND_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// What became of the shell's append lock for a read.
enum AppendLockForRead {
    /// Held shared: no append is in progress while the file is read.
    Held(#[allow(dead_code)] std::fs::File),
    /// The lock file could not be opened or locked: the read is unlocked, so an unfinished last row may be an append
    /// still in progress.
    Unavailable,
    /// The caller holds the append lock exclusively (a rewrite of the file): no append can be in progress, so an
    /// unfinished last row is damage, not a write still running.
    HeldByCaller,
}

/// Take the shell's append lock (`rewind_points.jsonl.lock`, held exclusively by `append_jsonl_line_sync`) shared, so
/// a read never sees an append in progress (Astra P114 r1 #2). It waits at most [`APPEND_LOCK_WAIT`] without blocking
/// on the OS lock (r2 #2): an append still running after that is reported as `WouldBlock`, which keeps the deferred
/// source for a later attempt. Call it off the async event loop (it sleeps while it waits).
fn lock_rewind_points_for_read(path: &Path) -> io::Result<AppendLockForRead> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    // The shell's append creates this file owner-only (P120); a read that gets there first must not leave it looser.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let lock = match options.open(path.with_extension("jsonl.lock")) {
        Ok(lock) => {
            // A lock file an older Fuigo made group- or world-readable is tightened too.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let _ = lock.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
            lock
        }
        Err(e) => {
            tracing::debug!(error = %e, path = %path.display(), "rewind_points read without the append lock");
            return Ok(AppendLockForRead::Unavailable);
        }
    };
    let deadline = std::time::Instant::now() + APPEND_LOCK_WAIT;
    loop {
        match fs2::FileExt::try_lock_shared(&lock) {
            Ok(()) => return Ok(AppendLockForRead::Held(lock)),
            Err(e) if e.kind() == fs2::lock_contended_error().kind() => {
                if std::time::Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        format!("{} is being written by another Fuigo process", path.display()),
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(e) => {
                tracing::debug!(error = %e, path = %path.display(), "rewind_points read without the append lock");
                return Ok(AppendLockForRead::Unavailable);
            }
        }
    }
}

/// Read every line of a `rewind_points.jsonl` in file order, keeping the ones that do not parse. A missing file is
/// `Ok(empty)`; an I/O error is `Err` (nothing was read, and reading again may succeed). Appends are held off while it
/// reads (see [`lock_rewind_points_for_read`]). Without the lock, an unfinished last row (no newline yet) may be an
/// append in progress, so the read fails with `WouldBlock` instead of recording it as damage for good (r2 #3).
pub fn read_rewind_points_lines(path: &Path) -> io::Result<Vec<RewindPointsLine>> {
    let is_file = match std::fs::metadata(path) {
        Ok(meta) => meta.is_file(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let lock = if is_file { lock_rewind_points_for_read(path)? } else { AppendLockForRead::Unavailable };
    read_rewind_points_lines_with(path, lock)
}

/// [`read_rewind_points_lines`] for a caller that already holds the append lock (`rewind_points.jsonl.lock`) exclusively
/// across a read-modify-write of the file, as the shell's truncate and merge do (P123): taking the shared lock here
/// would wait for the caller's own lock, and no append is in progress while it is held, so an unfinished last row is read
/// as damage.
pub fn read_rewind_points_lines_holding_append_lock(path: &Path) -> io::Result<Vec<RewindPointsLine>> {
    match std::fs::metadata(path) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    }
    read_rewind_points_lines_with(path, AppendLockForRead::HeldByCaller)
}

fn read_rewind_points_lines_with(path: &Path, lock: AppendLockForRead) -> io::Result<Vec<RewindPointsLine>> {
    let Some(mut reader) = open_rewind_points(path)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    let mut line = Vec::new();
    let mut number = 0usize;
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            return Ok(out);
        }
        number += 1;
        let terminated = line.last() == Some(&b'\n');
        let trimmed = line.trim_ascii();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_slice::<RewindPoint>(trimmed) {
            Ok(point) => out.push(RewindPointsLine::Point(point)),
            Err(_) if !terminated && matches!(lock, AppendLockForRead::Unavailable) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "line {number} of {} is unfinished and may still be being written",
                        path.display()
                    ),
                ));
            }
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), line = number, "damaged rewind_points.jsonl line");
                out.push(RewindPointsLine::Damaged { line: number, raw: trimmed.to_vec() });
            }
        }
    }
}

/// The file bytes of `lines`, one per line, damaged ones exactly as they were read.
pub fn encode_rewind_points_lines(lines: &[RewindPointsLine]) -> serde_json::Result<Vec<u8>> {
    let mut out = Vec::new();
    for line in lines {
        match line {
            RewindPointsLine::Point(point) => serde_json::to_writer(&mut out, point)?,
            RewindPointsLine::Damaged { raw, .. } => out.extend_from_slice(raw),
        }
        out.push(b'\n');
    }
    Ok(out)
}

/// The prompt a damaged row holds the saved files of, read from what survives of it (P114).
///
/// A row is a serialized [`RewindPoint`], whose first field is `prompt_index`, and an append that is cut short keeps
/// its start: a torn row still begins `{"prompt_index":N,`. Every record start in the line is checked, so a line where
/// an older version concatenated a torn record with the next one is bounded by the larger index. `None` when any record
/// start in the line is cut before its index is complete, or the line does not begin with one: then nothing tells
/// which prompt it held. (A record start cannot occur inside saved file contents or paths: their quotes are escaped.)
///
/// The prompt comes from the row itself, not from the rows around it: concurrent writers to one session (two processes
/// on it) or rows left by a failed rewrite before P114 make the neighbours' order prove nothing (Astra P114 r1 #1).
fn damaged_row_prompt(raw: &[u8]) -> Option<usize> {
    const START: &[u8] = b"{\"prompt_index\":";
    if !raw.starts_with(START) || !is_single_value_prefix(raw) {
        return None;
    }
    // Every record header in the line must be whole: a key `"prompt_index"` that opens an object, then `:`, digits and
    // `,` (P114 r3 #1: a second record cut right after its first key is found here, not passed over).
    const HEADER: &[u8] = b"{\"prompt_index\"";
    let mut highest = 0usize;
    let mut rest = raw;
    while let Some(at) = rest.windows(HEADER.len()).position(|w| w == HEADER) {
        let after = &rest[at + HEADER.len()..];
        let after = after.strip_prefix(b":")?;
        let digits = after.iter().take_while(|b| b.is_ascii_digit()).count();
        if digits == 0 || after.get(digits) != Some(&b',') {
            return None;
        }
        let index: usize = std::str::from_utf8(&after[..digits]).ok()?.parse().ok()?;
        highest = highest.max(index);
        rest = &after[digits..];
    }
    Some(highest)
}

/// Whether `raw` can be the start of ONE JSON value cut short, with no second record hidden in its tail (P114 r2 #1).
///
/// A second record appended onto a torn one (versions before the newline healing) starts with `{`, which JSON accepts
/// only where a value is expected; anywhere else the line is not a valid prefix. Where a value is expected (right after
/// a `:`), a second record that kept its whole `{"prompt_index":N,` start is found by the marker scan; one cut before
/// that leaves the innermost open object without a complete first key, which is refused here. Inside a string, a
/// second record's `{` and `{"` read as content, so a line ending in them is refused as well. A single torn row cut
/// at one of those points is refused too (it then identifies nothing, as before P114).
fn is_single_value_prefix(raw: &[u8]) -> bool {
    #[derive(Clone, Copy, PartialEq)]
    enum Expect {
        Value,
        KeyOrEnd,
        Key,
        Colon,
        CommaOrEnd,
    }
    // Per open container: is it an object, and how many of its keys are complete.
    let mut stack: Vec<(bool, usize)> = Vec::new();
    let mut expect = Expect::Value;
    let mut i = 0;
    let mut started = false;
    while i < raw.len() {
        let b = raw[i];
        if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            i += 1;
            continue;
        }
        if started && stack.is_empty() {
            return false; // something after the one top-level value
        }
        started = true;
        match expect {
            Expect::Value => match b {
                b'{' => {
                    stack.push((true, 0));
                    expect = Expect::KeyOrEnd;
                    i += 1;
                }
                b'[' => {
                    stack.push((false, 0));
                    expect = Expect::Value;
                    i += 1;
                }
                b']' if stack.last().is_some_and(|(object, _)| !object) => {
                    stack.pop();
                    expect = Expect::CommaOrEnd;
                    i += 1;
                }
                b'"' => match skip_string(raw, i + 1) {
                    Some(end) => {
                        i = end;
                        expect = Expect::CommaOrEnd;
                    }
                    None => break, // cut inside a string value
                },
                b'-' | b'0'..=b'9' => {
                    i += 1;
                    while i < raw.len() && matches!(raw[i], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-') {
                        i += 1;
                    }
                    expect = Expect::CommaOrEnd;
                }
                b't' | b'f' | b'n' => {
                    let word: &[u8] = match b {
                        b't' => b"true",
                        b'f' => b"false",
                        _ => b"null",
                    };
                    let rest = &raw[i..];
                    let n = rest.len().min(word.len());
                    if rest[..n] != word[..n] {
                        return false;
                    }
                    i += n;
                    expect = Expect::CommaOrEnd;
                }
                _ => return false,
            },
            Expect::KeyOrEnd | Expect::Key => match b {
                b'}' if expect == Expect::KeyOrEnd => {
                    stack.pop();
                    expect = Expect::CommaOrEnd;
                    i += 1;
                }
                b'"' => match skip_string(raw, i + 1) {
                    Some(end) => {
                        if let Some(top) = stack.last_mut() {
                            top.1 += 1;
                        }
                        i = end;
                        expect = Expect::Colon;
                    }
                    None => break, // cut inside a key
                },
                _ => return false,
            },
            Expect::Colon => {
                if b != b':' {
                    return false;
                }
                expect = Expect::Value;
                i += 1;
            }
            Expect::CommaOrEnd => match (b, stack.last()) {
                (b',', Some((true, _))) => {
                    expect = Expect::Key;
                    i += 1;
                }
                (b',', Some((false, _))) => {
                    expect = Expect::Value;
                    i += 1;
                }
                (b'}', Some((true, _))) | (b']', Some((false, _))) => {
                    stack.pop();
                    expect = Expect::CommaOrEnd;
                    i += 1;
                }
                _ => return false,
            },
        }
    }
    // Inside a string, another record's first byte `{` is ordinary content and its `"` closes the string; only from
    // the `p` that follows is the line no longer one value. So a line ending in `{` or `{"` may hide a record cut there.
    if raw.ends_with(b"{") || raw.ends_with(b"{\"") {
        return false;
    }
    // Cut short: the innermost open object must already have a complete key, or its `{` may be another record's.
    stack.last().is_none_or(|(object, keys)| !object || *keys > 0)
}

/// The index just past the closing quote of the JSON string whose body starts at `from`, or `None` when it is cut.
fn skip_string(raw: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i < raw.len() {
        match raw[i] {
            b'\\' => i += 2,
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// A row of `rewind_points.jsonl` that cannot be read: the saved file contents of one prompt are lost (P114).
#[derive(Debug, Clone)]
pub struct DamagedRewindRow {
    pub path: PathBuf,
    /// 1-based line number when the file was read.
    pub line: usize,
    /// The prompt whose saved files it held, when what survives of it says so.
    pub prompt: Option<usize>,
}

impl DamagedRewindRow {
    /// Whether a file rewind to `target` (which restores the rows of prompts `target` and later) may need this row.
    fn needed_by(&self, target: usize) -> bool {
        self.prompt.is_none_or(|prompt| prompt >= target)
    }

    fn describe(&self) -> String {
        let prompt = match self.prompt {
            Some(prompt) => format!("the saved files of prompt #{prompt}"),
            None => "the saved files of a prompt it no longer identifies".to_string(),
        };
        format!(
            "{prompt} (line {} of {} when this session read it)",
            self.line,
            self.path.display()
        )
    }
}

/// The damaged rows of `lines` (read from `path`).
fn damaged_rewind_rows(path: &Path, lines: &[RewindPointsLine]) -> Vec<DamagedRewindRow> {
    lines
        .iter()
        .filter_map(|line| match line {
            RewindPointsLine::Damaged { line, raw } => Some(DamagedRewindRow {
                path: path.to_path_buf(),
                line: *line,
                prompt: damaged_row_prompt(raw),
            }),
            RewindPointsLine::Point(_) => None,
        })
        .collect()
}

/// `rewind_points.jsonl` after a file rewind to `from_index`: the rows of prompts `from_index` and later are dropped.
/// Damaged rows are kept where they are: they record which prompts' saved files are missing, so dropping them would
/// let a later rewind report a complete restore without them (P114).
pub fn truncate_rewind_points_lines(lines: Vec<RewindPointsLine>, from_index: usize) -> Vec<RewindPointsLine> {
    lines
        .into_iter()
        .filter(|line| match line {
            RewindPointsLine::Point(point) => point.prompt_index < from_index,
            RewindPointsLine::Damaged { .. } => true,
        })
        .collect()
}

/// `rewind_points.jsonl` after a conversation-only rewind to `target_index`: [`merge_rewind_points_from`] on the
/// readable rows, then every damaged row, kept for the reason [`truncate_rewind_points_lines`] gives.
pub fn merge_rewind_points_lines(lines: Vec<RewindPointsLine>, target_index: usize) -> Vec<RewindPointsLine> {
    let mut points = Vec::new();
    let mut damaged = Vec::new();
    for line in lines {
        match line {
            RewindPointsLine::Point(point) => points.push(point),
            RewindPointsLine::Damaged { .. } => damaged.push(line),
        }
    }
    let mut out: Vec<RewindPointsLine> = merge_rewind_points_from(points, target_index)
        .into_iter()
        .map(RewindPointsLine::Point)
        .collect();
    out.extend(damaged);
    out
}

/// Counts the entries of a JSON map without allocating its keys or values.
struct MapEntryCount(usize);

impl<'de> Deserialize<'de> for MapEntryCount {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = usize;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a map")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<usize, A::Error> {
                let mut n = 0;
                while map
                    .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                    .is_some()
                {
                    n += 1;
                }
                Ok(n)
            }
        }
        deserializer.deserialize_map(V).map(MapEntryCount)
    }
}

/// Cheaply scan `rewind_points.jsonl` for per-point metadata, streaming without allocating file-content `String`s.
/// `MapEntryCount` just counts `file_snapshots`; serde skips the other fields.
/// `file_snapshots` is required, mirroring `RewindPoint`, so the picker rejects exactly the lines the on-rewind full load would.
/// It never advertises a rewind target that won't materialize.
fn scan_rewind_point_metas(path: &Path) -> io::Result<Vec<RewindPointMeta>> {
    #[derive(Deserialize)]
    struct MetaRow {
        prompt_index: usize,
        created_at: DateTime<Utc>,
        file_snapshots: MapEntryCount,
    }
    Ok(read_rewind_jsonl_lines::<MetaRow>(path)?
        .into_iter()
        .map(|r| RewindPointMeta {
            prompt_index: r.prompt_index,
            created_at: r.created_at,
            num_file_snapshots: r.file_snapshots.0,
        })
        .collect())
}

/// Fold rewind points at indices `>= target_index` into the point at `target_index - 1`, drop the folded points, and return the survivors.
/// Before-snapshots keep the earliest (via `or_insert`), after-snapshots the latest.
/// `target_index == 0` clears everything (no predecessor).
///
/// Pure (no I/O), so the in-memory tracker and the persistence path that treats the disk as authoritative share it and can't diverge.
pub fn merge_rewind_points_from(
    mut points: Vec<RewindPoint>,
    target_index: usize,
) -> Vec<RewindPoint> {
    if target_index == 0 {
        return Vec::new();
    }
    points.sort_by_key(|p| p.prompt_index);
    // Enforce one point per prompt_index, guarding a corrupt/legacy file with duplicate-index lines
    // The normal append-once-per-prompt flow never hits this
    points.dedup_by_key(|p| p.prompt_index);
    let split = points.partition_point(|p| p.prompt_index < target_index);
    // Indices >= target_index, ascending (so after-snapshots keep the latest).
    let to_merge = points.split_off(split);
    if let Some(previous) = points
        .iter_mut()
        .find(|p| p.prompt_index == target_index - 1)
    {
        // Consume `to_merge` by value: the large file-content snapshots move into `previous` instead of being cloned
        for merged in to_merge {
            for (path, snapshot) in merged.file_snapshots {
                // or_insert: we own `snapshot`; earliest before-snapshot wins.
                previous.file_snapshots.entry(path).or_insert(snapshot);
            }
            for (path, snapshot) in merged.after_snapshots {
                previous.after_snapshots.insert(path, snapshot);
            }
        }
    }
    points
}

/// The tracker maintains a list of rewind points, one per user prompt.
/// Each rewind point captures the state of files BEFORE they are read or modified during that prompt's processing.
///
/// A tracker built via [`with_lazy_source`] does NOT read the (potentially huge) persisted rewind points up front, so resuming a session is cheap.
/// They load on demand the first time a rewind *operation* needs them (see [`ensure_historical_loaded`]).
/// Live capture and persisting the current prompt's point (`get_rewind_point`) deliberately skip the load, so "resume then keep working" stays fast.
/// The picker uses the metadata-only [`get_rewind_point_metas`].
///
/// [`with_lazy_source`]: FileStateTracker::with_lazy_source
/// [`ensure_historical_loaded`]: FileStateTracker::ensure_historical_loaded
/// [`get_rewind_point_metas`]: FileStateTracker::get_rewind_point_metas
#[derive(Debug)]
pub struct FileStateTracker {
    /// All rewind points for this session, indexed by prompt_index
    rewind_points: Arc<Mutex<HashMap<usize, RewindPoint>>>,
    current_prompt_index: Arc<Mutex<Option<usize>>>,
    /// Deferred historical source: `Some(path)` until the points are lazily loaded (then `None`); `None` from the start without a lazy source.
    lazy_source: Arc<Mutex<Option<PathBuf>>>,
    /// Rows of the historical source that cannot be read (P111, P114). The points they held are missing for the rest
    /// of this tracker's life, so [`FileStateTracker::try_get_rewind_points_for`] refuses every rewind that may need
    /// them (each names its prompt when what survives of it says so; see [`damaged_row_prompt`]).
    damaged_rows: Arc<Mutex<Vec<DamagedRewindRow>>>,
}

impl Default for FileStateTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl FileStateTracker {
    pub fn new() -> Self {
        Self {
            rewind_points: Arc::new(Mutex::new(HashMap::new())),
            current_prompt_index: Arc::new(Mutex::new(None)),
            lazy_source: Arc::new(Mutex::new(None)),
            damaged_rows: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create a tracker that lazily loads its historical rewind points from `lazy_path` on first rewind access (resume path).
    /// The in-memory set starts empty; on load, live captures win over disk (`or_insert`).
    pub fn with_lazy_source(lazy_path: PathBuf) -> Self {
        Self {
            rewind_points: Arc::new(Mutex::new(HashMap::new())),
            current_prompt_index: Arc::new(Mutex::new(None)),
            lazy_source: Arc::new(Mutex::new(Some(lazy_path))),
            damaged_rows: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Materialize the deferred historical rewind points (no-op if already loaded or no lazy source).
    /// Triggered by rewind *operations* that need full file contents.
    /// In-memory points win over disk via `or_insert`, so concurrent live captures are never lost.
    ///
    /// The `lazy_source` lock is held across the (large, blocking) read and merge.
    /// Releasing it early would let a concurrent rewind observe `lazy_source == None` mid-merge and skip/truncate historical points.
    /// The source is consumed only on a SUCCESSFUL read.
    /// A transient error leaves it set to retry (never operating on or persisting a partial set).
    async fn ensure_historical_loaded(&self) {
        let _ = self.load_historical().await;
    }

    /// Load the deferred source. A read error is returned and the lazy source stays set, so nothing partial is merged
    /// and a later load can retry. Rows that do not parse are recorded in `damaged_rows`, never silently dropped.
    async fn load_historical(&self) -> io::Result<()> {
        let mut source = self.lazy_source.lock().await;
        // Clone the path so we can clear `source` after a successful read.
        let Some(path) = source.clone() else {
            return Ok(()); // already loaded, or never lazy
        };
        // Off the event loop: the read can wait for another process's append and the file can be large (P114 r2 #2).
        let read_path = path.clone();
        let read = tokio::task::spawn_blocking(move || read_rewind_points_lines(&read_path))
            .await
            .unwrap_or_else(|e| Err(io::Error::other(e)));
        let lines = match read {
            Ok(lines) => lines,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %path.display(),
                    "deferred rewind-point load failed; leaving lazy source set to retry"
                );
                return Err(e);
            }
        };
        let damaged = damaged_rewind_rows(&path, &lines);
        {
            let mut points = self.rewind_points.lock().await;
            for line in lines {
                if let RewindPointsLine::Point(p) = line {
                    points.entry(p.prompt_index).or_insert(p);
                }
            }
        }
        self.damaged_rows.lock().await.extend(damaged);
        // Success: consume the source so subsequent calls are no-ops.
        *source = None;
        Ok(())
    }

    pub async fn begin_prompt(&self, prompt_index: usize) {
        let mut current = self.current_prompt_index.lock().await;
        *current = Some(prompt_index);

        // Create a new rewind point for this prompt if it doesn't exist
        let mut points = self.rewind_points.lock().await;
        points
            .entry(prompt_index)
            .or_insert_with(|| RewindPoint::new(prompt_index));
    }

    /// This captures after-snapshots for all files that were touched during the prompt.
    ///
    /// The caller passes the explicit `prompt_index` so end_prompt works even when begin_prompt was never received (e.g. RPC failure in proxy mode).
    #[tracing::instrument(name = "session.end_prompt", skip_all, fields(prompt_index = prompt_index))]
    pub async fn end_prompt(&self, fs: &AsyncFsWrapper, prompt_index: usize) {
        // Clear internal current-prompt tracking.
        {
            let mut current = self.current_prompt_index.lock().await;
            *current = None;
        }

        // Capture after-snapshots for all files that were touched
        let paths_to_capture: Vec<FlexiblePath> = {
            let points = self.rewind_points.lock().await;
            if let Some(point) = points.get(&prompt_index) {
                point.file_snapshots.keys().cloned().collect()
            } else {
                vec![]
            }
        };

        for flex_path in paths_to_capture {
            let content = match &flex_path {
                FlexiblePath::Relative(rel_path) => fs
                    .try_read_file(rel_path)
                    .await
                    .and_then(|opt| opt.map(bytes_to_string).transpose())
                    .unwrap_or(None),
                FlexiblePath::Absolute(abs_path) => {
                    fs.try_read_to_string(abs_path).await.unwrap_or(None)
                }
            };

            let snapshot = FileSnapshot::new_flexible(flex_path, content);

            let mut points = self.rewind_points.lock().await;
            if let Some(point) = points.get_mut(&prompt_index) {
                point.set_after_snapshot(snapshot);
            }
        }
    }

    /// This should be called BEFORE reading or writing a file.
    ///
    /// `path` is the absolute path to the file. It will be converted to a `RelPathBuf` (using `cwd`) for storage.
    /// Files outside the CWD are silently skipped (they don't need rewind tracking since the agent shouldn't modify them).
    ///
    /// NOTE: This method is similar to `capture_file_state_with_fs`.
    /// They are kept separate due to type system constraints (`AsyncFileSystem` trait vs `AsyncFsWrapper` concrete type).
    /// Keep them in sync when making changes.
    pub async fn capture_file_state<F: AsyncFileSystem + ?Sized>(
        &self,
        fs: &F,
        path: &Path,
        cwd: &Path,
    ) -> Result<(), crate::file_system::FsError> {
        // Skip files outside the CWD; they don't need rewind tracking (e.g., /etc/hosts, system files, files in other projects)
        let Ok(rel_path) = RelPathBuf::from_absolute(cwd, path) else {
            return Ok(());
        };

        let current = self.current_prompt_index.lock().await;
        let Some(prompt_index) = *current else {
            // Not currently processing a prompt, skip capture
            return Ok(());
        };
        drop(current); // Release lock before async operations

        let content = fs
            .try_read_file(path)
            .await?
            .map(bytes_to_string)
            .transpose()?;

        let snapshot = FileSnapshot::new(rel_path, content);

        // Add to the current rewind point
        let mut points = self.rewind_points.lock().await;
        if let Some(point) = points.get_mut(&prompt_index) {
            point.add_snapshot(snapshot);
        }

        Ok(())
    }

    /// Capture a file's current state before an operation using `AsyncFsWrapper`.
    ///
    /// Files outside the CWD are silently skipped (they don't need rewind tracking).
    ///
    /// NOTE: This method is similar to `capture_file_state`.
    /// They are kept separate due to type system constraints (`AsyncFsWrapper` concrete type vs generic `AsyncFileSystem` trait).
    /// Keep them in sync when making changes.
    pub async fn capture_file_state_with_fs(
        &self,
        fs: &AsyncFsWrapper,
        path: &Path,
        cwd: &Path,
    ) -> Result<(), crate::file_system::FsError> {
        // Skip files outside the CWD; they don't need rewind tracking (e.g., /etc/hosts, system files, files in other projects)
        let Ok(rel_path) = RelPathBuf::from_absolute(cwd, path) else {
            return Ok(());
        };

        let current = self.current_prompt_index.lock().await;
        let Some(prompt_index) = *current else {
            // Not currently processing a prompt, skip capture
            return Ok(());
        };
        drop(current); // Release lock before async operations

        let content = fs
            .try_read_file(path)
            .await?
            .map(bytes_to_string)
            .transpose()?;

        let snapshot = FileSnapshot::new(rel_path, content);

        // Add to the current rewind point
        let mut points = self.rewind_points.lock().await;
        if let Some(point) = points.get_mut(&prompt_index) {
            point.add_snapshot(snapshot);
        }

        Ok(())
    }

    /// Unlike `capture_file_state`, this does NOT read from the filesystem.
    /// The caller provides the content directly (e.g., from a `FileWritten` notification that already carries `previous_content`).
    ///
    /// `path` is the absolute path. `cwd` is used to convert it to a relative path.
    /// Files outside the CWD are silently skipped.
    pub async fn add_before_snapshot_for_prompt(
        &self,
        prompt_index: usize,
        path: &Path,
        cwd: &Path,
        content: Option<String>,
    ) {
        // Skip files outside the CWD
        let Ok(rel_path) = RelPathBuf::from_absolute(cwd, path) else {
            return;
        };

        let snapshot = FileSnapshot::new(rel_path, content);

        let mut points = self.rewind_points.lock().await;
        let point = points
            .entry(prompt_index)
            .or_insert_with(|| RewindPoint::new(prompt_index));
        point.add_snapshot(snapshot);
    }

    /// The rewind points a file rewind to `target` restores from, or why they cannot all be read.
    ///
    /// Like [`get_rewind_points`](Self::get_rewind_points), but fails when the deferred historical points cannot be
    /// read instead of returning only the in-memory ones, and when a damaged row may hold the saved files of prompt
    /// `target` or a later one. A rewind that restores files must not plan from a partial set: it would report the
    /// files of the missing rows as restored when they were not (P111). A damaged row that only earlier prompts can
    /// hold stops nothing (P114).
    pub async fn try_get_rewind_points_for(&self, target: usize) -> Result<Vec<RewindPoint>, RewindPointsUnavailable> {
        let source = self.lazy_source.lock().await.clone();
        if let Err(error) = self.load_historical().await {
            return Err(RewindPointsUnavailable::Unreadable { path: source, error });
        }
        {
            let damaged = self.damaged_rows.lock().await;
            let needed: Vec<DamagedRewindRow> = damaged.iter().filter(|row| row.needed_by(target)).cloned().collect();
            if !needed.is_empty() {
                let first_working_target = damaged
                    .iter()
                    .map(|row| row.prompt.map(|prompt| prompt + 1))
                    .try_fold(0, |first, after| after.map(|after| first.max(after)));
                return Err(RewindPointsUnavailable::Damaged { needed, first_working_target });
            }
        }
        let points = self.rewind_points.lock().await;
        let mut result: Vec<RewindPoint> = points.values().cloned().collect();
        result.sort_by_key(|p| p.prompt_index);
        Ok(result)
    }

    /// Get all rewind points (materializes the deferred historical set).
    pub async fn get_rewind_points(&self) -> Vec<RewindPoint> {
        self.ensure_historical_loaded().await;
        let points = self.rewind_points.lock().await;
        let mut result: Vec<RewindPoint> = points.values().cloned().collect();
        result.sort_by_key(|p| p.prompt_index);
        result
    }

    /// Lightweight metadata for every known rewind point, for the rewind picker.
    /// Combines in-memory points with a metadata-only scan of the lazy disk source.
    /// It never materializes file contents and never consumes the source, so a later rewind still does the full load.
    /// In-memory points win on conflict.
    ///
    /// Lock order mirrors [`ensure_historical_loaded`] (`lazy_source` outer, `rewind_points` inner).
    /// Holding `lazy_source` across both the in-memory snapshot and the disk scan stops a concurrent rewind's load from interleaving.
    /// An interleaved load could make the picker miss points.
    pub async fn get_rewind_point_metas(&self) -> Vec<RewindPointMeta> {
        let source = self.lazy_source.lock().await;
        let mut metas: HashMap<usize, RewindPointMeta> = {
            let points = self.rewind_points.lock().await;
            points
                .values()
                .map(|p| {
                    (
                        p.prompt_index,
                        RewindPointMeta {
                            prompt_index: p.prompt_index,
                            created_at: p.created_at,
                            num_file_snapshots: p.file_snapshots.len(),
                        },
                    )
                })
                .collect()
        };
        if let Some(path) = source.as_ref() {
            match scan_rewind_point_metas(path) {
                Ok(scanned) => {
                    for meta in scanned {
                        metas.entry(meta.prompt_index).or_insert(meta);
                    }
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    path = %path.display(),
                    "rewind-point metadata scan failed; picker shows in-memory points only"
                ),
            }
        }
        let mut result: Vec<RewindPointMeta> = metas.into_values().collect();
        result.sort_by_key(|m| m.prompt_index);
        result
    }

    /// Intentionally does NOT trigger the historical load: a just-completed prompt's point is always in memory.
    /// This is the live persistence path, so "resume then keep working" stays fast.
    pub async fn get_rewind_point(&self, prompt_index: usize) -> Option<RewindPoint> {
        let points = self.rewind_points.lock().await;
        points.get(&prompt_index).cloned()
    }

    pub async fn current_prompt_index(&self) -> Option<usize> {
        *self.current_prompt_index.lock().await
    }

    /// Clear all rewind points after (and including) the specified prompt index.
    /// This is used when rewinding to truncate future history.
    pub async fn truncate_from(&self, prompt_index: usize) {
        self.ensure_historical_loaded().await;
        let mut points = self.rewind_points.lock().await;
        points.retain(|&idx, _| idx < prompt_index);
    }

    /// Merge rewind points at indices >= `target_index` into the previous point (`target_index - 1`), then remove the merged points.
    ///
    /// Used by ConversationOnly rewind: the conversation is rewound but files are untouched.
    /// The file effects of the discarded prompts must therefore be folded into the last surviving prompt's rewind point.
    /// This ensures:
    /// - `/rewind 0` can still undo all file effects (merged into point N-1)
    /// - A new prompt at `target_index` gets a fresh rewind point with correct before-snapshots (the current disk state)
    ///
    /// For `target_index == 0` there is no previous point to merge into, so all points are cleared.
    pub async fn merge_and_remove_from(&self, target_index: usize) {
        self.ensure_historical_loaded().await;
        let mut points = self.rewind_points.lock().await;
        // Move the points out (no clone), merge, then rebuild the map.
        let all: Vec<RewindPoint> = std::mem::take(&mut *points).into_values().collect();
        for p in merge_rewind_points_from(all, target_index) {
            points.insert(p.prompt_index, p);
        }
    }

    pub async fn max_prompt_index(&self) -> Option<usize> {
        self.ensure_historical_loaded().await;
        let points = self.rewind_points.lock().await;
        points.keys().max().copied()
    }

    /// Call this before saving the session so its paths are portable.
    pub async fn normalize_all_to_relative(&self, root: &Path) {
        self.ensure_historical_loaded().await;
        let mut points = self.rewind_points.lock().await;
        for point in points.values_mut() {
            point.normalize_to_relative(root);
        }
    }

    /// Used when saving sessions so all paths are portable.
    pub async fn get_rewind_points_normalized(&self, root: &Path) -> Vec<RewindPoint> {
        self.ensure_historical_loaded().await;
        let points = self.rewind_points.lock().await;
        let mut result: Vec<RewindPoint> = points
            .values()
            .map(|p| {
                let mut normalized = p.clone();
                normalized.normalize_to_relative(root);
                normalized
            })
            .collect();
        result.sort_by_key(|p| p.prompt_index);
        result
    }
}

/// Why a file rewind cannot read every saved file content it needs (P111, P114).
#[derive(Debug)]
pub enum RewindPointsUnavailable {
    /// The saved file contents could not be read at all (an I/O error). Nothing was loaded; a later attempt reads them
    /// again.
    Unreadable { path: Option<PathBuf>, error: io::Error },
    /// Rows the rewind may need are damaged. Reading them again cannot help.
    Damaged {
        needed: Vec<DamagedRewindRow>,
        /// The earliest target no damaged row can stop, when every damaged row names its prompt.
        first_working_target: Option<usize>,
    },
}

impl RewindPointsUnavailable {
    /// The refusal of a file rewind to `target`. `valid_targets_below`: targets of file rewinds must lie below it (the
    /// conversation's prompt count), when known. `conversation_only_rewind`: the caller offers a conversation-only
    /// rewind, which needs no saved file contents.
    pub fn refusal_message(&self, target: usize, valid_targets_below: Option<usize>, conversation_only_rewind: bool) -> String {
        match self {
            Self::Unreadable { path, error } => format!(
                "Cannot rewind files to prompt #{target}: the saved file contents{} could not be read ({error}). \
                 Nothing was changed. Once the file can be read (check its permissions and free disk space), run the \
                 same rewind again.",
                path.as_ref().map(|path| format!(" ({})", path.display())).unwrap_or_default()
            ),
            Self::Damaged { needed, first_working_target } => {
                let rows = needed.iter().map(DamagedRewindRow::describe).collect::<Vec<_>>().join("; ");
                let working = match first_working_target {
                    Some(first) if valid_targets_below.is_none_or(|below| *first < below) => {
                        format!(" A file rewind to prompt #{first} or later still works.")
                    }
                    Some(first) => format!(" File rewinds to prompt #{first} or later will work once the session has reached them."),
                    None => " A damaged row that no longer identifies its prompt may belong to any of them, so no file \
                             rewind of this session can restore files any more."
                        .to_string(),
                };
                let conversation = if conversation_only_rewind {
                    " A conversation-only rewind does not need these saved contents: it rewinds the conversation and \
                     leaves your files as they are."
                } else {
                    ""
                };
                format!(
                    "Cannot rewind files to prompt #{target}: the saved file contents it needs are damaged and cannot be \
                     read: {rows}. (This happens when Fuigo stops or the disk fills while it saves them.) Reading \
                     them again cannot repair them, and restoring only the other files would leave these unrestored. \
                     Nothing was changed.{working}{conversation}"
                )
            }
        }
    }
}

// Canonical in fuigo-workspace-types; re-exported for existing paths.
pub use fuigo_workspace_types::rpc::session::{
    ConflictType, FileRewindConflict, FileRewindResponse,
};

/// Rewind files to the state before `target_prompt_index`.
///
/// Shared implementation used by both `hub_server.rs` (workspace-side) and potentially `acp_session.rs` (shell-side). Performs:
/// 1. Gather earliest before-snapshot per file from points >= target
/// 2. Detect conflicts (external modifications since the agent's writes)
/// 3. Revert files to their before-snapshot state
/// 4. Truncate rewind points from the target onward
pub async fn rewind_files(
    tracker: &FileStateTracker,
    fs: &crate::file_system::AsyncFsWrapper,
    target_prompt_index: usize,
) -> FileRewindResponse {
    // Strict read of the saved contents: a lazy load that fails or skips rows would make the revert silently partial
    // and the truncation below would then drop the snapshots of the files it never restored (P111, as in the shell's
    // rewind handler).
    let all_points = match tracker.try_get_rewind_points_for(target_prompt_index).await {
        Ok(points) => points,
        Err(unavailable) => {
            return FileRewindResponse {
                success: false,
                target_prompt_index,
                reverted_files: Vec::new(),
                clean_files: Vec::new(),
                conflicts: Vec::new(),
                error: Some(unavailable.refusal_message(target_prompt_index, None, false)),
            };
        }
    };

    let mut reverted_files = Vec::new();
    let mut clean_files = Vec::new();
    let mut conflicts = Vec::new();
    let mut had_errors = false;
    let mut failed_files: Vec<String> = Vec::new();

    // Collect files to revert: gather earliest before-snapshot per file
    let mut files_to_revert: HashMap<FlexiblePath, Option<String>> = HashMap::new();

    for point in all_points
        .iter()
        .filter(|p| p.prompt_index >= target_prompt_index)
    {
        for (path, before_snapshot) in &point.file_snapshots {
            files_to_revert
                .entry(path.clone())
                .or_insert_with(|| before_snapshot.content.clone());
        }
    }

    // Conflict detection and revert
    for (rel_path, content) in &files_to_revert {
        let current_content = match fs.try_read_to_string(rel_path).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(?rel_path, ?e, "rewind: failed to read current content");
                None
            }
        };
        let after_content = all_points
            .iter()
            .rev()
            .find_map(|p| p.after_snapshots.get(rel_path))
            .and_then(|s| s.content.clone());

        if current_content == after_content {
            clean_files.push(rel_path.to_string());
        } else {
            let conflict_type = if current_content.is_none() && after_content.is_some() {
                ConflictType::DeletedExternally
            } else if current_content.is_some() && after_content.is_none() {
                ConflictType::CreatedExternally
            } else {
                ConflictType::ModifiedExternally
            };
            conflicts.push(FileRewindConflict {
                path: rel_path.to_string(),
                conflict_type,
            });
        }

        // Perform the revert; AsyncFsWrapper resolves FlexiblePath via ToAbsPath
        match content {
            Some(data) => {
                if let Err(e) = fs.write_file(rel_path, data.as_bytes()).await {
                    tracing::warn!(?rel_path, ?e, "rewind: failed to restore file");
                    failed_files.push(format!("{rel_path} (could not restore it: {e})"));
                    had_errors = true;
                    continue;
                }
            }
            None => {
                // A file the agent created is deleted. An existence check that fails proves nothing about the file, so
                // it is a failure of that file, never "already deleted" (P111, Astra r4: DI-02 on this path).
                let failure = match fs.exists(rel_path).await {
                    Ok(false) => None,
                    Ok(true) => fs
                        .delete_file(rel_path)
                        .await
                        .err()
                        .map(|e| format!("could not delete it: {e}")),
                    Err(e) => Some(format!("could not check whether it exists: {e}")),
                };
                if let Some(reason) = failure {
                    tracing::warn!(?rel_path, %reason, "rewind: file not reverted");
                    failed_files.push(format!("{rel_path} ({reason})"));
                    had_errors = true;
                    continue;
                }
            }
        }
        reverted_files.push(rel_path.to_string());
    }

    // Truncate rewind points from the target index onward.
    // Skip truncation when errors occurred so retry data is preserved.
    if !had_errors {
        tracker.truncate_from(target_prompt_index).await;
    }

    let error = if had_errors {
        failed_files.sort();
        Some(format!(
            "Some files could not be reverted: {}. Their saved contents are kept; fix the cause and run the same rewind \
             again.",
            failed_files.join("; ")
        ))
    } else {
        None
    };

    FileRewindResponse {
        success: !had_errors,
        target_prompt_index,
        reverted_files,
        clean_files,
        conflicts,
        error,
    }
}

/// A lightweight clone-able handle that tools use to request file state capture.
#[derive(Clone)]
pub struct FileStateHandle {
    tracker: Arc<FileStateTracker>,
}

impl FileStateHandle {
    pub fn new(tracker: Arc<FileStateTracker>) -> Self {
        Self { tracker }
    }

    /// Capture file state before an operation.
    ///
    /// `path` is the absolute path to the file.
    /// `cwd` is used to convert it to a relative path for portable storage.
    pub async fn capture<F: AsyncFileSystem + ?Sized>(
        &self,
        fs: &F,
        path: &Path,
        cwd: &Path,
    ) -> Result<(), crate::file_system::FsError> {
        self.tracker.capture_file_state(fs, path, cwd).await
    }

    /// Capture file state before an operation using `AsyncFsWrapper`.
    ///
    /// `path` is the absolute path to the file.
    /// `cwd` is used to convert it to a relative path for portable storage.
    pub async fn capture_with_fs(
        &self,
        fs: &AsyncFsWrapper,
        path: &Path,
        cwd: &Path,
    ) -> Result<(), crate::file_system::FsError> {
        self.tracker.capture_file_state_with_fs(fs, path, cwd).await
    }

    pub fn tracker(&self) -> &Arc<FileStateTracker> {
        &self.tracker
    }
}

#[cfg(test)]
mod tests {
    use super::ToolContext; // from stub above
    use super::*;
    use crate::file_system::MockFs;
    use std::sync::Arc;
    use fuigo_paths::AbsPathBuf;

    #[tokio::test]
    async fn test_rewind_point_creation() {
        let tracker = FileStateTracker::new();
        let cwd = AbsPathBuf::new(PathBuf::from("/test")).unwrap();
        let fs = Arc::new(MockFs::new(cwd.to_path_buf()));
        let fs_wrapper = crate::file_system::AsyncFsWrapper::new(fs);
        let ctx = ToolContext::new_local_context(cwd.to_path_buf(), fs_wrapper, Arc::new(()));

        // Start a prompt
        tracker.begin_prompt(0).await;
        assert_eq!(tracker.current_prompt_index().await, Some(0));

        // End the prompt
        tracker.end_prompt(&ctx.fs, 0).await;
        assert_eq!(tracker.current_prompt_index().await, None);

        let point = tracker.get_rewind_point(0).await;
        assert!(point.is_some());
        assert_eq!(point.unwrap().prompt_index, 0);
    }

    #[tokio::test]
    async fn test_truncate_from() {
        let tracker = FileStateTracker::new();
        let cwd = AbsPathBuf::new(PathBuf::from("/test")).unwrap();
        let fs = Arc::new(MockFs::new(cwd.to_path_buf()));
        let fs_wrapper = crate::file_system::AsyncFsWrapper::new(fs);
        let ctx = ToolContext::new_local_context(cwd.to_path_buf(), fs_wrapper, Arc::new(()));

        // Create multiple rewind points
        for i in 0..5 {
            tracker.begin_prompt(i).await;
            tracker.end_prompt(&ctx.fs, i).await;
        }

        let points = tracker.get_rewind_points().await;
        assert_eq!(points.len(), 5);

        tracker.truncate_from(3).await;

        let points = tracker.get_rewind_points().await;
        assert_eq!(points.len(), 3);
        assert!(tracker.get_rewind_point(0).await.is_some());
        assert!(tracker.get_rewind_point(1).await.is_some());
        assert!(tracker.get_rewind_point(2).await.is_some());
        assert!(tracker.get_rewind_point(3).await.is_none());
    }

    #[test]
    fn test_file_snapshot() {
        let snapshot = FileSnapshot::new(
            RelPathBuf::new("src/file.txt").unwrap(),
            Some("content".into()),
        );

        assert_eq!(snapshot.as_path(), Path::new("src/file.txt"));
        assert_eq!(snapshot.content, Some("content".into()));
    }

    #[test]
    fn test_rewind_point_add_snapshot() {
        let mut point = RewindPoint::new(0);

        // Add the first snapshot (using relative paths)
        let snapshot1 = FileSnapshot::new(RelPathBuf::new("src/a.txt").unwrap(), Some("v1".into()));
        point.add_snapshot(snapshot1);

        // Adding a second snapshot for the same file is ignored
        let snapshot2 = FileSnapshot::new(RelPathBuf::new("src/a.txt").unwrap(), Some("v2".into()));
        point.add_snapshot(snapshot2);

        let retrieved = point
            .get_snapshot_by_rel(&RelPathBuf::new("src/a.txt").unwrap())
            .unwrap();
        assert_eq!(retrieved.content, Some("v1".into()));
    }

    #[test]
    fn test_flexible_path_try_to_relative() {
        let root = Path::new("/home/user/project");

        // An already-relative path stays relative
        let rel = FlexiblePath::Relative(RelPathBuf::new("src/file.txt").unwrap());
        let result = rel.try_to_relative(root);
        assert!(result.is_relative());
        assert_eq!(result.as_path(), Path::new("src/file.txt"));

        // An absolute path under root becomes relative
        let abs = FlexiblePath::Absolute(PathBuf::from("/home/user/project/src/file.txt"));
        let result = abs.try_to_relative(root);
        assert!(result.is_relative());
        assert_eq!(result.as_path(), Path::new("src/file.txt"));

        // An absolute path outside root stays absolute
        let abs_other = FlexiblePath::Absolute(PathBuf::from("/other/path/file.txt"));
        let result = abs_other.try_to_relative(root);
        assert!(!result.is_relative());
        assert_eq!(result.as_path(), Path::new("/other/path/file.txt"));
    }

    #[test]
    fn test_rewind_point_normalize_to_relative() {
        let root = Path::new("/home/user/project");
        let mut point = RewindPoint::new(0);

        // Add a snapshot with an absolute path (simulating old session data)
        let abs_snapshot = FileSnapshot::new_flexible(
            FlexiblePath::Absolute(PathBuf::from("/home/user/project/src/main.rs")),
            Some("fn main() {}".into()),
        );
        point.add_snapshot(abs_snapshot);

        // Add a snapshot with a relative path
        let rel_snapshot = FileSnapshot::new(
            RelPathBuf::new("src/lib.rs").unwrap(),
            Some("pub mod foo;".into()),
        );
        point.add_snapshot(rel_snapshot);

        // Before normalization, we have mixed paths
        assert_eq!(point.file_snapshots.len(), 2);

        point.normalize_to_relative(root);

        for (path, snapshot) in &point.file_snapshots {
            assert!(path.is_relative(), "Path {:?} should be relative", path);
            assert!(
                snapshot.path.is_relative(),
                "Snapshot path {:?} should be relative",
                snapshot.path
            );
        }

        // Verify we can still retrieve by relative path
        let main_snapshot = point.get_snapshot_by_rel(&RelPathBuf::new("src/main.rs").unwrap());
        assert!(main_snapshot.is_some());
        assert_eq!(main_snapshot.unwrap().content, Some("fn main() {}".into()));
    }

    #[test]
    fn test_deserialize_file_snapshot_with_absolute_path() {
        // Simulate JSON from an older session that stored absolute paths
        let json = r#"{
            "path": "/home/user/project/src/main.rs",
            "content": "fn main() {}",
            "captured_at": "2024-01-01T00:00:00Z"
        }"#;

        let snapshot: FileSnapshot = serde_json::from_str(json).unwrap();

        assert!(!snapshot.path.is_relative());
        assert_eq!(
            snapshot.path.as_path(),
            Path::new("/home/user/project/src/main.rs")
        );
        assert_eq!(snapshot.content, Some("fn main() {}".into()));

        // It can still be normalized to relative
        let root = Path::new("/home/user/project");
        let normalized = snapshot.normalize_to_relative(root);
        assert!(normalized.path.is_relative());
        assert_eq!(normalized.path.as_path(), Path::new("src/main.rs"));
    }

    #[test]
    fn test_deserialize_file_snapshot_with_relative_path() {
        // Simulate JSON from a newer session that stores relative paths
        let json = r#"{
            "path": "src/main.rs",
            "content": "fn main() {}",
            "captured_at": "2024-01-01T00:00:00Z"
        }"#;

        let snapshot: FileSnapshot = serde_json::from_str(json).unwrap();

        assert!(snapshot.path.is_relative());
        assert_eq!(snapshot.path.as_path(), Path::new("src/main.rs"));
    }

    #[test]
    fn test_deserialize_rewind_point_with_absolute_paths() {
        // Simulate JSON from an older session with absolute paths in the hashmap keys
        let json = r#"{
            "prompt_index": 0,
            "created_at": "2024-01-01T00:00:00Z",
            "file_snapshots": {
                "/home/user/project/src/main.rs": {
                    "path": "/home/user/project/src/main.rs",
                    "content": "fn main() {}",
                    "captured_at": "2024-01-01T00:00:00Z"
                },
                "/home/user/project/src/lib.rs": {
                    "path": "/home/user/project/src/lib.rs",
                    "content": "pub mod foo;",
                    "captured_at": "2024-01-01T00:00:00Z"
                }
            },
            "after_snapshots": {}
        }"#;

        let point: RewindPoint = serde_json::from_str(json).unwrap();

        assert_eq!(point.prompt_index, 0);
        assert_eq!(point.file_snapshots.len(), 2);

        for path in point.file_snapshots.keys() {
            assert!(
                !path.is_relative(),
                "Expected absolute path, got {:?}",
                path
            );
        }

        // After normalization, all paths are relative
        let root = Path::new("/home/user/project");
        let mut normalized_point = point.clone();
        normalized_point.normalize_to_relative(root);

        for (path, snapshot) in &normalized_point.file_snapshots {
            assert!(path.is_relative(), "Expected relative path, got {:?}", path);
            assert!(
                snapshot.path.is_relative(),
                "Expected relative snapshot path, got {:?}",
                snapshot.path
            );
        }

        // Retrieval by relative path works after normalization
        let main_snapshot =
            normalized_point.get_snapshot_by_rel(&RelPathBuf::new("src/main.rs").unwrap());
        assert!(main_snapshot.is_some());
        assert_eq!(main_snapshot.unwrap().content, Some("fn main() {}".into()));
    }

    #[test]
    fn test_deserialize_rewind_point_with_mixed_paths() {
        // Simulate JSON with a mix of absolute and relative paths (edge case)
        let json = r#"{
            "prompt_index": 1,
            "created_at": "2024-01-01T00:00:00Z",
            "file_snapshots": {
                "/home/user/project/src/old.rs": {
                    "path": "/home/user/project/src/old.rs",
                    "content": "// old file",
                    "captured_at": "2024-01-01T00:00:00Z"
                },
                "src/new.rs": {
                    "path": "src/new.rs",
                    "content": "// new file",
                    "captured_at": "2024-01-01T00:00:00Z"
                }
            },
            "after_snapshots": {}
        }"#;

        let point: RewindPoint = serde_json::from_str(json).unwrap();

        assert_eq!(point.file_snapshots.len(), 2);

        // Normalize
        let root = Path::new("/home/user/project");
        let mut normalized = point.clone();
        normalized.normalize_to_relative(root);

        for path in normalized.file_snapshots.keys() {
            assert!(path.is_relative(), "Expected relative path, got {:?}", path);
        }

        // Both files are retrievable
        assert!(
            normalized
                .get_snapshot_by_rel(&RelPathBuf::new("src/old.rs").unwrap())
                .is_some()
        );
        assert!(
            normalized
                .get_snapshot_by_rel(&RelPathBuf::new("src/new.rs").unwrap())
                .is_some()
        );
    }

    #[test]
    fn test_serialize_always_produces_string_paths() {
        let snapshot = FileSnapshot::new(
            RelPathBuf::new("src/file.txt").unwrap(),
            Some("content".into()),
        );

        let json = serde_json::to_string(&snapshot).unwrap();

        assert!(json.contains("\"path\":\"src/file.txt\""));

        let abs_snapshot = FileSnapshot::new_flexible(
            FlexiblePath::Absolute(PathBuf::from("/abs/path/file.txt")),
            Some("content".into()),
        );

        let abs_json = serde_json::to_string(&abs_snapshot).unwrap();

        assert!(abs_json.contains("\"path\":\"/abs/path/file.txt\""));
    }

    // ── Lazy historical rewind-point loading ──────────────────────────────────

    /// Build a rewind point at `idx` with the given (relative path, content) files.
    fn point_with_files(idx: usize, files: &[(&str, &str)]) -> RewindPoint {
        let mut p = RewindPoint::new(idx);
        for (path, content) in files {
            p.add_snapshot(FileSnapshot::new(
                RelPathBuf::new(path).unwrap(),
                Some((*content).to_string()),
            ));
        }
        p
    }

    /// Persist rewind points to a temp `rewind_points.jsonl` (one JSON per line).
    fn write_rewind_file(points: &[RewindPoint]) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for p in points {
            writeln!(f, "{}", serde_json::to_string(p).unwrap()).unwrap();
        }
        f.flush().unwrap();
        f
    }

    /// Write raw lines (verbatim) to a temp `rewind_points.jsonl`.
    fn write_rewind_raw(body: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "{body}").unwrap();
        f.flush().unwrap();
        f
    }

    #[tokio::test]
    async fn lazy_get_rewind_point_singular_does_not_load() {
        let file = write_rewind_file(&[
            point_with_files(0, &[("a.rs", "v0")]),
            point_with_files(1, &[("b.rs", "v1")]),
        ]);
        let tracker = FileStateTracker::with_lazy_source(file.path().to_path_buf());

        // Singular lookup must NOT trigger the historical load (live-persist path).
        assert!(tracker.get_rewind_point(0).await.is_none());
        // Nothing materialized yet.
        assert!(tracker.get_rewind_point(1).await.is_none());

        // A plural query (a rewind operation) loads the full set.
        let points = tracker.get_rewind_points().await;
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].prompt_index, 0);
        assert_eq!(points[1].prompt_index, 1);
        // Now singular lookups see the loaded points.
        assert!(tracker.get_rewind_point(0).await.is_some());
    }

    #[tokio::test]
    async fn lazy_metas_scan_without_full_load() {
        let file = write_rewind_file(&[
            point_with_files(0, &[("a.rs", "v0"), ("b.rs", "v0b")]),
            point_with_files(1, &[("c.rs", "v1")]),
            point_with_files(2, &[]),
        ]);
        let tracker = FileStateTracker::with_lazy_source(file.path().to_path_buf());

        let metas = tracker.get_rewind_point_metas().await;
        assert_eq!(metas.len(), 3);
        assert_eq!(metas[0].prompt_index, 0);
        assert_eq!(metas[0].num_file_snapshots, 2);
        assert_eq!(metas[1].num_file_snapshots, 1);
        assert_eq!(metas[2].num_file_snapshots, 0);

        // The metadata scan must NOT consume the lazy source: a later rewind operation still gets the full file-content snapshots
        assert!(tracker.get_rewind_point(0).await.is_none());
        let points = tracker.get_rewind_points().await;
        assert_eq!(points.len(), 3);
        assert_eq!(
            points[0]
                .get_snapshot_by_rel(&RelPathBuf::new("a.rs").unwrap())
                .and_then(|s| s.content.clone()),
            Some("v0".to_string())
        );
    }

    #[tokio::test]
    async fn lazy_keeps_new_points_and_loads_historical_for_rewind() {
        // Historical points 0,1 on disk; nothing in memory.
        let file = write_rewind_file(&[
            point_with_files(0, &[("a.rs", "h0")]),
            point_with_files(1, &[("b.rs", "h1")]),
        ]);
        let tracker = FileStateTracker::with_lazy_source(file.path().to_path_buf());

        // A new prompt during the resumed session adds an in-memory point (no load).
        let cwd = Path::new("/repo");
        tracker
            .add_before_snapshot_for_prompt(2, Path::new("/repo/c.rs"), cwd, Some("new2".into()))
            .await;
        assert!(tracker.get_rewind_point(2).await.is_some());
        // Historical still not loaded.
        assert!(tracker.get_rewind_point(0).await.is_none());

        // Rewinding to a pre-resume prompt loads the historical set and keeps the new in-memory point
        let all = tracker.get_rewind_points().await;
        assert_eq!(all.len(), 3);
        assert_eq!(
            all.iter().map(|p| p.prompt_index).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );

        // truncate_from(1) keeps only the pre-resume prompt 0.
        tracker.truncate_from(1).await;
        let remaining = tracker.get_rewind_points().await;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].prompt_index, 0);
        assert_eq!(
            remaining[0]
                .get_snapshot_by_rel(&RelPathBuf::new("a.rs").unwrap())
                .and_then(|s| s.content.clone()),
            Some("h0".to_string())
        );
    }

    #[tokio::test]
    async fn lazy_live_capture_wins_over_disk_at_conflicting_index() {
        // Disk has point 0 with content "disk".
        let file = write_rewind_file(&[point_with_files(0, &[("a.rs", "disk")])]);
        let tracker = FileStateTracker::with_lazy_source(file.path().to_path_buf());

        // A LIVE capture at the same index 0 (before any historical load) adds an in-memory point 0 with different content
        let cwd = Path::new("/repo");
        tracker
            .add_before_snapshot_for_prompt(0, Path::new("/repo/a.rs"), cwd, Some("mem".into()))
            .await;

        // The on-rewind historical load must NOT clobber the in-memory point 0 (`or_insert` keeps the live capture)
        let points = tracker.get_rewind_points().await;
        assert_eq!(points.len(), 1);
        assert_eq!(
            points[0]
                .get_snapshot_by_rel(&RelPathBuf::new("a.rs").unwrap())
                .and_then(|s| s.content.clone()),
            Some("mem".to_string())
        );
    }

    #[tokio::test]
    async fn lazy_metas_combine_memory_and_disk() {
        let file = write_rewind_file(&[point_with_files(0, &[("a.rs", "h0")])]);
        let tracker = FileStateTracker::with_lazy_source(file.path().to_path_buf());

        // New in-memory point at index 1.
        let cwd = Path::new("/repo");
        tracker
            .add_before_snapshot_for_prompt(1, Path::new("/repo/b.rs"), cwd, Some("new".into()))
            .await;

        let metas = tracker.get_rewind_point_metas().await;
        assert_eq!(metas.len(), 2);
        assert_eq!(metas[0].prompt_index, 0); // from disk
        assert_eq!(metas[0].num_file_snapshots, 1);
        assert_eq!(metas[1].prompt_index, 1); // from memory
        assert_eq!(metas[1].num_file_snapshots, 1);
    }

    #[tokio::test]
    async fn lazy_missing_file_is_empty_not_error() {
        let tracker =
            FileStateTracker::with_lazy_source(PathBuf::from("/nonexistent/rewind_points.jsonl"));
        assert!(tracker.get_rewind_points().await.is_empty());
        assert!(tracker.get_rewind_point_metas().await.is_empty());
    }

    #[tokio::test]
    async fn lazy_merge_and_remove_loads_historical() {
        // ConversationOnly rewind path: merge_and_remove_from must see history.
        let file = write_rewind_file(&[
            point_with_files(0, &[("a.rs", "h0")]),
            point_with_files(1, &[("b.rs", "h1")]),
            point_with_files(2, &[("c.rs", "h2")]),
        ]);
        let tracker = FileStateTracker::with_lazy_source(file.path().to_path_buf());

        // Merge points >= 1 into point 0's predecessor (index 0).
        tracker.merge_and_remove_from(1).await;
        let points = tracker.get_rewind_points().await;
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].prompt_index, 0);
        // Point 0 now also carries the merged files from points 1 and 2
        assert!(
            points[0]
                .get_snapshot_by_rel(&RelPathBuf::new("b.rs").unwrap())
                .is_some()
        );
        assert!(
            points[0]
                .get_snapshot_by_rel(&RelPathBuf::new("c.rs").unwrap())
                .is_some()
        );
    }

    /// `get_rewind_points_normalized` is a rewind op and must trigger the historical load.
    #[tokio::test]
    async fn lazy_get_rewind_points_normalized_loads_historical() {
        let file = write_rewind_file(&[point_with_files(0, &[("a.rs", "h0")])]);
        let tracker = FileStateTracker::with_lazy_source(file.path().to_path_buf());
        let normalized = tracker
            .get_rewind_points_normalized(Path::new("/repo"))
            .await;
        assert_eq!(normalized.len(), 1);
        assert_eq!(normalized[0].prompt_index, 0);
    }

    /// `max_prompt_index` is a rewind op and must trigger the load.
    #[tokio::test]
    async fn lazy_max_prompt_index_loads_historical() {
        let file = write_rewind_file(&[point_with_files(0, &[]), point_with_files(4, &[])]);
        let tracker = FileStateTracker::with_lazy_source(file.path().to_path_buf());
        assert_eq!(tracker.max_prompt_index().await, Some(4));
    }

    /// Concurrent live capture and rewind query: must not deadlock, and the full set after both complete must contain every point.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lazy_concurrent_capture_and_rewind() {
        let file = write_rewind_file(&[
            point_with_files(0, &[("a.rs", "h0")]),
            point_with_files(1, &[("b.rs", "h1")]),
        ]);
        let tracker = Arc::new(FileStateTracker::with_lazy_source(
            file.path().to_path_buf(),
        ));

        let t1 = tracker.clone();
        let capture = async move {
            let cwd = PathBuf::from("/repo");
            t1.add_before_snapshot_for_prompt(2, &cwd.join("c.rs"), &cwd, Some("new".into()))
                .await;
        };
        let t2 = tracker.clone();
        let query = async move { t2.get_rewind_points().await };
        let (_, points) = tokio::join!(capture, query);

        // The historical set is always visible to the query.
        assert!(points.iter().any(|p| p.prompt_index == 0));
        assert!(points.iter().any(|p| p.prompt_index == 1));

        // After both complete, every point (historical and live) is present
        let final_all = tracker.get_rewind_points().await;
        assert_eq!(
            final_all.iter().map(|p| p.prompt_index).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn scan_rewind_point_metas_reads_counts() {
        let file = write_rewind_file(&[
            point_with_files(0, &[("a.rs", "x"), ("b.rs", "y")]),
            point_with_files(5, &[("c.rs", "z")]),
        ]);
        let metas = scan_rewind_point_metas(file.path()).unwrap();
        assert_eq!(metas.len(), 2);
        assert_eq!(metas[0].prompt_index, 0);
        assert_eq!(metas[0].num_file_snapshots, 2);
        assert_eq!(metas[1].prompt_index, 5);
        assert_eq!(metas[1].num_file_snapshots, 1);
    }

    // ── pure merge_rewind_points_from branch coverage ────────────────────────

    #[test]
    fn merge_pure_target_zero_clears_all() {
        let pts = vec![
            point_with_files(0, &[("a.rs", "0")]),
            point_with_files(1, &[("b.rs", "1")]),
        ];
        assert!(merge_rewind_points_from(pts, 0).is_empty());
    }

    #[test]
    fn merge_pure_folds_before_or_insert_and_after_latest_wins() {
        // shared.rs touched by both points; only1.rs only by p1.
        let mut p0 = RewindPoint::new(0);
        p0.add_snapshot(FileSnapshot::new(
            RelPathBuf::new("shared.rs").unwrap(),
            Some("p0-before".into()),
        ));
        p0.set_after_snapshot(FileSnapshot::new(
            RelPathBuf::new("shared.rs").unwrap(),
            Some("p0-after".into()),
        ));
        let mut p1 = RewindPoint::new(1);
        p1.add_snapshot(FileSnapshot::new(
            RelPathBuf::new("shared.rs").unwrap(),
            Some("p1-before".into()),
        ));
        p1.add_snapshot(FileSnapshot::new(
            RelPathBuf::new("only1.rs").unwrap(),
            Some("p1-only".into()),
        ));
        p1.set_after_snapshot(FileSnapshot::new(
            RelPathBuf::new("shared.rs").unwrap(),
            Some("p1-after".into()),
        ));

        let merged = merge_rewind_points_from(vec![p0, p1], 1);
        assert_eq!(merged.len(), 1);
        let m0 = &merged[0];
        assert_eq!(m0.prompt_index, 0);
        // before-snapshot: earliest (p0) wins for shared.rs (or_insert keeps it).
        assert_eq!(
            m0.get_snapshot_by_rel(&RelPathBuf::new("shared.rs").unwrap())
                .unwrap()
                .content,
            Some("p0-before".into())
        );
        // p1's only1.rs before-snapshot is folded in.
        assert!(
            m0.get_snapshot_by_rel(&RelPathBuf::new("only1.rs").unwrap())
                .is_some()
        );
        // after-snapshot: latest (p1) wins for shared.rs (insert overwrites).
        let after_key = FlexiblePath::Relative(RelPathBuf::new("shared.rs").unwrap());
        assert_eq!(
            m0.after_snapshots.get(&after_key).unwrap().content,
            Some("p1-after".into())
        );
    }

    #[test]
    fn merge_pure_missing_predecessor_drops_merged_effects() {
        // points [0, 3], target 3: predecessor index 2 is absent (gap), so the merged point 3's file effects are dropped
        let merged = merge_rewind_points_from(
            vec![
                point_with_files(0, &[("a.rs", "0")]),
                point_with_files(3, &[("b.rs", "3")]),
            ],
            3,
        );
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].prompt_index, 0);
        assert!(
            merged[0]
                .get_snapshot_by_rel(&RelPathBuf::new("b.rs").unwrap())
                .is_none()
        );
    }

    #[test]
    fn merge_pure_dedups_duplicate_indices() {
        // Two lines with the same prompt_index (corrupt/legacy) collapse to one.
        let merged = merge_rewind_points_from(
            vec![
                point_with_files(0, &[("a.rs", "first")]),
                point_with_files(0, &[("a.rs", "second")]),
            ],
            5,
        );
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].prompt_index, 0);
    }

    /// Blank/whitespace and malformed lines are skipped; both readers (full load and meta scan) recover exactly the valid points.
    #[tokio::test]
    async fn readers_recover_from_blank_and_malformed_lines() {
        let p0 = serde_json::to_string(&point_with_files(0, &[("a.rs", "v0")])).unwrap();
        let p2 = serde_json::to_string(&point_with_files(2, &[("c.rs", "v2")])).unwrap();
        let file = write_rewind_raw(&format!("\n   \n{p0}\ngarbage{{not json\n{p2}\n"));

        let full = read_rewind_points_file(file.path()).unwrap();
        assert_eq!(
            full.iter().map(|p| p.prompt_index).collect::<Vec<_>>(),
            vec![0, 2]
        );
        let metas = scan_rewind_point_metas(file.path()).unwrap();
        assert_eq!(
            metas.iter().map(|m| m.prompt_index).collect::<Vec<_>>(),
            vec![0, 2]
        );

        // Same via the tracker's lazy load.
        let tracker = FileStateTracker::with_lazy_source(file.path().to_path_buf());
        let points = tracker.get_rewind_points().await;
        assert_eq!(
            points.iter().map(|p| p.prompt_index).collect::<Vec<_>>(),
            vec![0, 2]
        );
    }

    /// A zero-byte file (distinct from a missing file) is `Ok(empty)`.
    #[test]
    fn readers_handle_zero_byte_file() {
        let file = tempfile::NamedTempFile::new().unwrap();
        assert!(read_rewind_points_file(file.path()).unwrap().is_empty());
        assert!(scan_rewind_point_metas(file.path()).unwrap().is_empty());
    }

    /// A missing file is `Ok(empty)` (fresh session); a real I/O error (here: a directory) is `Err`.
    /// The `Err` lets the caller keep the lazy source set rather than treat it as empty.
    #[test]
    fn readers_distinguish_missing_from_io_error() {
        let missing = PathBuf::from("/nonexistent/dir/rewind_points.jsonl");
        assert!(read_rewind_points_file(&missing).unwrap().is_empty());
        assert!(scan_rewind_point_metas(&missing).unwrap().is_empty());

        let dir = tempfile::tempdir().unwrap();
        assert!(read_rewind_points_file(dir.path()).is_err());
        assert!(scan_rewind_point_metas(dir.path()).is_err());
    }

    /// A filesystem whose existence check fails for one path, the way a permission-denied parent directory makes
    /// `exists` fail (root ignores the permission bits, so the error is injected here instead of with chmod).
    struct ExistsFailsFs {
        inner: MockFs,
        failing: PathBuf,
    }

    #[async_trait::async_trait]
    impl crate::file_system::AsyncFileSystem for ExistsFailsFs {
        fn root(&self) -> &Path {
            self.inner.root()
        }
        async fn exists(&self, path: &Path) -> Result<bool, crate::file_system::FsError> {
            if path == self.failing {
                return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied").into());
            }
            self.inner.exists(path).await
        }
        async fn read_file(&self, path: &Path) -> Result<Vec<u8>, crate::file_system::FsError> {
            self.inner.read_file(path).await
        }
        async fn write_file(&self, path: &Path, data: &[u8]) -> Result<(), crate::file_system::FsError> {
            self.inner.write_file(path, data).await
        }
        async fn delete_file(&self, path: &Path) -> Result<(), crate::file_system::FsError> {
            self.inner.delete_file(path).await
        }
    }

    /// P111 (Astra r4 #5): the workspace rewind (`rewind_to` -> `rewind_files`) treated an existence-check error on a
    /// file the agent created as "already deleted": it listed the file as reverted, reported success and dropped the
    /// saved snapshots. The file must be reported as not reverted, the rewind must fail, and the snapshots must stay.
    #[tokio::test]
    async fn rewind_files_reports_an_existence_check_error_as_a_failed_file() {
        let root = PathBuf::from("/proj");
        let created = root.join("locked/created.txt");
        let edited = root.join("edited.txt");
        let fs = ExistsFailsFs { inner: MockFs::new(root.clone()), failing: created.clone() };
        fs.inner.write_file(&created, b"agent created").await.unwrap();
        fs.inner.write_file(&edited, b"agent edit").await.unwrap();
        let fs = crate::file_system::AsyncFsWrapper::new(Arc::new(fs));
        let tracker = FileStateTracker::new();
        tracker.add_before_snapshot_for_prompt(1, &created, &root, None).await;
        tracker.add_before_snapshot_for_prompt(1, &edited, &root, Some("original".into())).await;

        let response = rewind_files(&tracker, &fs, 1).await;

        assert!(!response.success, "{response:?}");
        assert!(
            !response.reverted_files.iter().any(|path| path.contains("created.txt")),
            "a file whose existence could not be checked is not reverted: {response:?}"
        );
        let error = response.error.clone().unwrap_or_default();
        assert!(error.contains("created.txt") && error.contains("exists"), "{error}");
        assert_eq!(fs.read_to_string(&created).await.unwrap(), "agent created");
        let points = tracker.get_rewind_points().await;
        assert!(
            points.iter().any(|p| p.prompt_index == 1 && p.file_snapshots.len() == 2),
            "the saved contents are kept for a retry"
        );
    }

    /// P111: the workspace rewind read the saved contents leniently, so an unreadable `rewind_points.jsonl` made it
    /// restore only the in-memory points and then truncate. It must change nothing and fail instead.
    #[tokio::test]
    async fn rewind_files_stops_when_the_saved_contents_cannot_be_read() {
        let root = PathBuf::from("/proj");
        let edited = root.join("edited.txt");
        let mock = MockFs::new(root.clone());
        mock.write_file(&edited, b"agent edit").await.unwrap();
        let fs = crate::file_system::AsyncFsWrapper::new(Arc::new(mock));
        // The deferred source cannot be read: it is a directory.
        let unreadable = tempfile::tempdir().unwrap();
        let tracker = FileStateTracker::with_lazy_source(unreadable.path().to_path_buf());
        tracker.add_before_snapshot_for_prompt(1, &edited, &root, Some("original".into())).await;

        let response = rewind_files(&tracker, &fs, 1).await;

        assert!(!response.success, "{response:?}");
        assert!(response.reverted_files.is_empty(), "{response:?}");
        assert_eq!(fs.read_to_string(&edited).await.unwrap(), "agent edit", "nothing was changed");
    }

    // ── P114: a damaged rewind_points.jsonl row refuses only the rewinds that need it ──

    /// Write raw bytes (verbatim, possibly invalid UTF-8) to a temp `rewind_points.jsonl`.
    fn write_rewind_bytes(body: &[u8]) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(body).unwrap();
        f.flush().unwrap();
        f
    }

    /// A torn append of `point`: the process stopped inside a multi-byte character of a saved file, and the next append
    /// terminated the partial record with a newline (`append_jsonl_line_sync`).
    fn torn_row(point: &RewindPoint) -> Vec<u8> {
        let full = serde_json::to_vec(point).unwrap();
        let accent = full.windows(2).position(|w| w == "é".as_bytes()).expect("the point holds an é");
        full[..accent + 1].to_vec()
    }

    fn rewind_file_of(rows: &[Vec<u8>]) -> tempfile::NamedTempFile {
        let mut body = Vec::new();
        for row in rows {
            body.extend_from_slice(row);
            body.push(b'\n');
        }
        write_rewind_bytes(&body)
    }

    async fn project_fs(files: &[(&str, &str)]) -> (PathBuf, crate::file_system::AsyncFsWrapper) {
        let root = PathBuf::from("/proj");
        let mock = MockFs::new(root.clone());
        for (name, content) in files {
            mock.write_file(&root.join(name), content.as_bytes()).await.unwrap();
        }
        (root, crate::file_system::AsyncFsWrapper::new(Arc::new(mock)))
    }

    /// P114 (Fable P111 #1): a torn row between readable ones. What survives of it says it held prompt 2's saved files;
    /// a rewind to prompt 3 needs only prompts 3 and 4 and must restore their files, while rewinds to 1 and 2 must
    /// refuse, change nothing, and say which file and line is damaged and which rewinds still work, never "try again"
    /// (retrying cannot repair it).
    #[tokio::test]
    async fn a_torn_middle_row_refuses_only_the_rewinds_that_need_it() {
        let (root, fs) = project_fs(&[("a.rs", "a now"), ("b.rs", "b now"), ("c.rs", "c now")]).await;
        let file = rewind_file_of(&[
            serde_json::to_vec(&point_with_files(1, &[("a.rs", "a before 1")])).unwrap(),
            torn_row(&point_with_files(2, &[("d.rs", "café before 2")])),
            serde_json::to_vec(&point_with_files(3, &[("b.rs", "b before 3")])).unwrap(),
            serde_json::to_vec(&point_with_files(4, &[("c.rs", "c before 4")])).unwrap(),
        ]);
        let tracker = FileStateTracker::with_lazy_source(file.path().to_path_buf());

        for target in [1, 2] {
            let refused = rewind_files(&tracker, &fs, target).await;
            assert!(!refused.success, "target {target}: {refused:?}");
            assert!(refused.reverted_files.is_empty(), "target {target}: {refused:?}");
            let error = refused.error.clone().unwrap_or_default();
            assert!(error.contains(&file.path().display().to_string()), "names the file: {error}");
            assert!(error.contains("line 2"), "names the line: {error}");
            assert!(error.contains("prompt #2"), "names the prompt: {error}");
            assert!(error.contains("prompt #3 or later"), "says which rewinds still work: {error}");
            assert!(error.contains("Nothing was changed"), "{error}");
            assert!(!error.to_lowercase().contains("try again"), "retrying cannot help: {error}");
        }
        for (name, now) in [("a.rs", "a now"), ("b.rs", "b now"), ("c.rs", "c now")] {
            assert_eq!(fs.read_to_string(&root.join(name)).await.unwrap(), now, "a refused rewind changed {name}");
        }

        let restored = rewind_files(&tracker, &fs, 3).await;
        assert!(restored.success, "a rewind that does not need the damaged row works: {restored:?}");
        assert_eq!(restored.reverted_files.len(), 2, "{restored:?}");
        assert_eq!(fs.read_to_string(&root.join("b.rs")).await.unwrap(), "b before 3");
        assert_eq!(fs.read_to_string(&root.join("c.rs")).await.unwrap(), "c before 4");
        assert_eq!(fs.read_to_string(&root.join("a.rs")).await.unwrap(), "a now");

        // Still refused afterwards: the damaged row's files are lost for good.
        let again = rewind_files(&tracker, &fs, 1).await;
        assert!(!again.success, "{again:?}");
        assert_eq!(fs.read_to_string(&root.join("a.rs")).await.unwrap(), "a now");
    }

    /// P114 (Fable P111 #1): the torn row is the newest one (the process stopped while saving the last prompt's files).
    /// Rewinds to its prompt or earlier are refused; once the resumed session has later prompts, rewinds to those work.
    #[tokio::test]
    async fn a_torn_last_row_refuses_rewinds_to_its_prompt_and_earlier() {
        let (root, fs) = project_fs(&[("a.rs", "a now"), ("b.rs", "b now"), ("e.rs", "e now")]).await;
        let file = rewind_file_of(&[
            serde_json::to_vec(&point_with_files(1, &[("a.rs", "a before 1")])).unwrap(),
            serde_json::to_vec(&point_with_files(2, &[("b.rs", "b before 2")])).unwrap(),
            torn_row(&point_with_files(3, &[("d.rs", "café before 3")])),
        ]);
        let tracker = FileStateTracker::with_lazy_source(file.path().to_path_buf());

        for target in [1, 2, 3] {
            let refused = rewind_files(&tracker, &fs, target).await;
            assert!(!refused.success, "target {target}: {refused:?}");
            let error = refused.error.clone().unwrap_or_default();
            assert!(error.contains("line 3") && error.contains("prompt #3"), "{error}");
            assert!(!error.to_lowercase().contains("try again"), "{error}");
        }
        assert_eq!(fs.read_to_string(&root.join("a.rs")).await.unwrap(), "a now");
        assert_eq!(fs.read_to_string(&root.join("b.rs")).await.unwrap(), "b now");

        // The resumed session runs prompts 3 and 4; prompt 4 edits e.rs.
        tracker.begin_prompt(3).await;
        tracker.begin_prompt(4).await;
        tracker.add_before_snapshot_for_prompt(4, &root.join("e.rs"), &root, Some("e before 4".into())).await;

        let restored = rewind_files(&tracker, &fs, 4).await;
        assert!(restored.success, "{restored:?}");
        assert_eq!(fs.read_to_string(&root.join("e.rs")).await.unwrap(), "e before 4");
        let refused = rewind_files(&tracker, &fs, 3).await;
        assert!(!refused.success, "prompt 3 is the damaged row's prompt: {refused:?}");
    }

    /// P114 (Astra r1 #1): the damaged row's prompt comes from the row itself, never from its neighbours. Two processes
    /// on one session can append `P0, P1, damaged P2, P1, P2`: the neighbours would bound the damaged row by prompt 1
    /// and let a rewind to 2 restore only the second process's files. A line an older version concatenated, or one cut
    /// before its index is complete, identifies its prompt only when every record start in it is whole.
    #[tokio::test]
    async fn a_damaged_row_is_identified_by_what_survives_of_it() {
        let torn2 = torn_row(&point_with_files(2, &[("x.rs", "café x")]));
        let full7 = serde_json::to_vec(&point_with_files(7, &[("y.rs", "y")])).unwrap();
        assert_eq!(damaged_row_prompt(&torn2), Some(2));
        assert_eq!(
            damaged_row_prompt(&[torn2.clone(), full7.clone()].concat()),
            None,
            "a record appended inside a torn one's string: the line is not one value"
        );
        // Astra r2 #1: a second record cut inside its own start, appended where a value or a string continues.
        let p2 = serde_json::to_vec(&point_with_files(2, &[("x.rs", "x")])).unwrap();
        let at = |needle: &str| p2.windows(needle.len()).position(|w| w == needle.as_bytes()).unwrap() + needle.len();
        let after_colon = &p2[..at("\"created_at\":")];
        let in_string = &p2[..at("\"created_at\":\"20")];
        for cut in [after_colon, in_string] {
            for tail in [&b"{"[..], &b"{\"prompt_ind"[..], &b"{\"prompt_index\":"[..]] {
                assert_eq!(damaged_row_prompt(&[cut, tail].concat()), None, "{}", String::from_utf8_lossy(&[cut, tail].concat()));
            }
        }
        // Astra r3 #1: a second record cut right after its first key; a header cut inside its digits (M6).
        assert_eq!(damaged_row_prompt(&[after_colon, &b"{\"prompt_index\""[..]].concat()), None);
        assert_eq!(damaged_row_prompt(&[after_colon, &b"{\"prompt_index\"  "[..]].concat()), None);
        assert_eq!(damaged_row_prompt(b"{\"prompt_index\":1"), None, "the index may have had more digits");
        assert_eq!(damaged_row_prompt(&[after_colon, &b"{\"prompt_index\":7"[..]].concat()), None);
        let whole_second = [after_colon, &full7[..full7.len() - 1]].concat();
        assert_eq!(damaged_row_prompt(&whole_second), Some(7), "a second record whose start survived is counted");
        assert_eq!(damaged_row_prompt(&[&b"{\"prompt_index\":1"[..], &full7[..]].concat()), None, "index cut short");
        assert_eq!(damaged_row_prompt(b"{\"prompt_ind"), None);
        assert_eq!(damaged_row_prompt(b"garbage{not json"), None);
        let quoted = serde_json::to_vec(&point_with_files(1, &[("q.rs", "{\"prompt_index\":99,")])).unwrap();
        assert_eq!(damaged_row_prompt(&quoted[..quoted.len() - 3]), Some(1), "file contents cannot fake a record start");

        let (root, fs) = project_fs(&[("x.rs", "x now"), ("y.rs", "y now")]).await;
        let file = rewind_file_of(&[
            serde_json::to_vec(&point_with_files(0, &[])).unwrap(),
            serde_json::to_vec(&point_with_files(1, &[])).unwrap(),
            torn2,
            serde_json::to_vec(&point_with_files(1, &[])).unwrap(),
            serde_json::to_vec(&point_with_files(2, &[("y.rs", "y before 2")])).unwrap(),
        ]);
        let tracker = FileStateTracker::with_lazy_source(file.path().to_path_buf());
        let refused = rewind_files(&tracker, &fs, 2).await;
        assert!(!refused.success, "the damaged row is prompt 2's: {refused:?}");
        assert_eq!(fs.read_to_string(&root.join("y.rs")).await.unwrap(), "y now", "nothing restored");
        assert!(rewind_files(&tracker, &fs, 3).await.success);

        let file = rewind_file_of(&[b"{\"prompt_ind".to_vec(), serde_json::to_vec(&point_with_files(5, &[])).unwrap()]);
        let tracker = FileStateTracker::with_lazy_source(file.path().to_path_buf());
        let refused = rewind_files(&tracker, &fs, 9).await;
        assert!(!refused.success, "{refused:?}");
        let error = refused.error.unwrap_or_default();
        assert!(error.contains("line 1") && error.contains("no longer identifies"), "{error}");
    }

    /// P114: the rewrites keep every damaged row (they record which prompts' saved files are missing).
    #[test]
    fn rewrites_keep_damaged_rows() {
        let torn = torn_row(&point_with_files(2, &[("d.rs", "café")]));
        let line = |idx: usize| RewindPointsLine::Point(point_with_files(idx, &[("f.rs", "v")]));
        let damaged = || RewindPointsLine::Damaged { line: 2, raw: torn.clone() };
        let shape = |lines: &[RewindPointsLine]| -> Vec<Option<usize>> {
            lines
                .iter()
                .map(|l| match l {
                    RewindPointsLine::Point(p) => Some(p.prompt_index),
                    RewindPointsLine::Damaged { .. } => None,
                })
                .collect()
        };
        let merged = merge_rewind_points_lines(vec![line(1), damaged(), line(3), line(4), line(5)], 5);
        assert_eq!(shape(&merged), vec![Some(1), Some(3), Some(4), None]);
        let merged = merge_rewind_points_lines(vec![line(1), damaged(), line(3), line(4)], 3);
        assert_eq!(shape(&merged), vec![Some(1), None]);
        let truncated = truncate_rewind_points_lines(vec![line(1), damaged(), line(3), line(4)], 2);
        assert_eq!(shape(&truncated), vec![Some(1), None]);
        let encoded = encode_rewind_points_lines(&truncated).unwrap();
        assert!(encoded.ends_with(&[torn.as_slice(), &b"\n"[..]].concat()), "the damaged row is kept byte for byte");
    }

    /// P114: a conversation-only rewind keeps the damaged row and its prompt, so a file rewind to a later prompt of the
    /// continued session works and one to its prompt stays refused.
    #[tokio::test]
    async fn a_damaged_row_keeps_its_prompt_through_a_merge() {
        let (root, fs) = project_fs(&[("e.rs", "e now")]).await;
        let file = rewind_file_of(&[
            serde_json::to_vec(&point_with_files(1, &[("a.rs", "a before 1")])).unwrap(),
            torn_row(&point_with_files(2, &[("d.rs", "café before 2")])),
            serde_json::to_vec(&point_with_files(5, &[("b.rs", "b before 5")])).unwrap(),
        ]);
        let tracker = FileStateTracker::with_lazy_source(file.path().to_path_buf());
        tracker.merge_and_remove_from(2).await;
        tracker.begin_prompt(2).await;
        tracker.begin_prompt(3).await;
        tracker.add_before_snapshot_for_prompt(3, &root.join("e.rs"), &root, Some("e before 3".into())).await;

        let restored = rewind_files(&tracker, &fs, 3).await;
        assert!(restored.success, "{restored:?}");
        assert_eq!(fs.read_to_string(&root.join("e.rs")).await.unwrap(), "e before 3");
        assert!(!rewind_files(&tracker, &fs, 2).await.success, "rewinds to prompt 2 stay refused");
    }

    /// P132 (P114 follow-up): the lock file a READ creates is owner-only, like the one the shell's append creates.
    #[cfg(unix)]
    #[test]
    fn the_reader_creates_its_lock_file_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let mut body = serde_json::to_vec(&point_with_files(1, &[("a.rs", "a before 1")])).unwrap();
        body.push(b'\n');
        let file = write_rewind_bytes(&body);
        let lock_path = file.path().with_extension("jsonl.lock");
        let _ = std::fs::remove_file(&lock_path);
        read_rewind_points_lines(file.path()).unwrap();
        let mode = std::fs::metadata(&lock_path).expect("the read creates the lock file").permissions().mode() & 0o777;
        let _ = std::fs::remove_file(&lock_path);
        assert_eq!(mode, 0o600, "reader-created lock file mode {mode:o}");
    }

    /// P114 (Astra r1 #2): a load that overlaps an append in progress (another process writing a large row) must not
    /// record the unfinished row as damage for good. The load waits for the append lock, then reads the whole row.
    #[test]
    fn a_load_waits_for_an_append_in_progress() {
        let full = serde_json::to_vec(&point_with_files(2, &[("b.rs", "b before 2")])).unwrap();
        let (head, tail) = full.split_at(full.len() / 2);
        let mut body = serde_json::to_vec(&point_with_files(1, &[("a.rs", "a before 1")])).unwrap();
        body.push(b'\n');
        body.extend_from_slice(head);
        let file = write_rewind_bytes(&body);
        let path = file.path().to_path_buf();
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path.with_extension("jsonl.lock"))
            .unwrap();
        fs2::FileExt::lock_exclusive(&lock).unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        let reader_path = path.clone();
        let reader = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
            let tracker = FileStateTracker::with_lazy_source(reader_path);
            let result = runtime.block_on(tracker.try_get_rewind_points_for(1));
            tx.send(result.map(|points| points.iter().map(|p| p.prompt_index).collect::<Vec<_>>()).map_err(|e| format!("{e:?}")))
                .unwrap();
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(rx.try_recv().is_err(), "the load waits while the append holds the lock");
        {
            use std::io::Write;
            let mut writer = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            writer.write_all(tail).unwrap();
            writer.write_all(b"\n").unwrap();
        }
        fs2::FileExt::unlock(&lock).unwrap();
        let loaded = rx.recv_timeout(std::time::Duration::from_secs(30)).expect("the load finishes");
        reader.join().unwrap();
        let _ = std::fs::remove_file(path.with_extension("jsonl.lock"));
        assert_eq!(loaded, Ok(vec![1, 2]), "the finished row is read, not recorded as damage");
    }

    /// P135 (P120 rule): the append lock a read creates is owner-only, like every other session file.
    #[cfg(unix)]
    #[test]
    fn the_lock_file_a_read_creates_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let file = write_rewind_bytes(b"");
        let path = file.path().to_path_buf();
        let lock_path = path.with_extension("jsonl.lock");
        let _ = std::fs::remove_file(&lock_path);
        let _held = lock_rewind_points_for_read(&path).unwrap();
        let mode = std::fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;
        let _ = std::fs::remove_file(&lock_path);
        assert_eq!(mode & 0o077, 0, "the lock file is accessible to others: {mode:o}");
    }

    /// P114 (Astra r2 #2): a load never blocks the session's event loop on another process's append, and gives up after
    /// a bounded wait with a retryable error, keeping the deferred source.
    #[test]
    fn a_load_does_not_block_the_event_loop_on_a_held_append_lock() {
        let mut body = serde_json::to_vec(&point_with_files(1, &[("a.rs", "a before 1")])).unwrap();
        body.push(b'\n');
        let file = write_rewind_bytes(&body);
        let path = file.path().to_path_buf();
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path.with_extension("jsonl.lock"))
            .unwrap();
        fs2::FileExt::lock_exclusive(&lock).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        let tracker = FileStateTracker::with_lazy_source(path.clone());
        let started = std::time::Instant::now();
        let (loaded, ticked_at) = runtime.block_on(async {
            tokio::join!(tracker.try_get_rewind_points_for(1), async {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                started.elapsed()
            })
        });
        let waited = started.elapsed();
        assert!(ticked_at < std::time::Duration::from_secs(2), "the event loop kept running: {ticked_at:?}");
        assert!(waited >= APPEND_LOCK_WAIT, "it waited for the append: {waited:?}");
        let error = match loaded {
            Err(RewindPointsUnavailable::Unreadable { error, .. }) => error,
            other => panic!("a busy lock is a retryable read error: {other:?}"),
        };
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock, "{error}");
        fs2::FileExt::unlock(&lock).unwrap();
        let points = runtime.block_on(tracker.try_get_rewind_points_for(1)).expect("the source was kept for a retry");
        assert_eq!(points.iter().map(|p| p.prompt_index).collect::<Vec<_>>(), vec![1]);
        let _ = std::fs::remove_file(path.with_extension("jsonl.lock"));
    }

    /// P114 (Astra r2 #3): when the append lock cannot be taken, an unfinished last row may be an append in progress, so
    /// it is a retryable read error, never damage recorded for good.
    #[tokio::test]
    async fn an_unfinished_last_row_read_without_the_lock_is_retried_not_damage() {
        let full = serde_json::to_vec(&point_with_files(2, &[("b.rs", "b before 2")])).unwrap();
        let (head, tail) = full.split_at(full.len() / 2);
        let mut body = serde_json::to_vec(&point_with_files(1, &[("a.rs", "a before 1")])).unwrap();
        body.push(b'\n');
        body.extend_from_slice(head);
        let file = write_rewind_bytes(&body);
        let path = file.path().to_path_buf();
        // The lock file cannot be opened: a directory stands in its place.
        std::fs::create_dir(path.with_extension("jsonl.lock")).unwrap();
        let tracker = FileStateTracker::with_lazy_source(path.clone());
        let first = tracker.try_get_rewind_points_for(1).await;
        assert!(
            matches!(&first, Err(RewindPointsUnavailable::Unreadable { error, .. }) if error.kind() == io::ErrorKind::WouldBlock),
            "{first:?}"
        );
        {
            use std::io::Write;
            let mut writer = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            writer.write_all(tail).unwrap();
            writer.write_all(b"\n").unwrap();
        }
        let points = tracker.try_get_rewind_points_for(1).await.expect("the finished row is read on the retry");
        assert_eq!(points.iter().map(|p| p.prompt_index).collect::<Vec<_>>(), vec![1, 2]);
        let _ = std::fs::remove_dir(path.with_extension("jsonl.lock"));
    }
}
