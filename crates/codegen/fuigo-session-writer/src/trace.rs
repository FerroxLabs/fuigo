//! Attribution marks for the B-F5 box test (design §9.4). Off unless `FUIGO_F5_TRACE_DIR` is set at startup; then the
//! cost of a write is one branch.
//!
//! When it is set (the harness sets it to `<FUIGO_HOME>/f5-marks`), the writer makes zero-byte marker files there, so
//! one recursive inotify watch on `<FUIGO_HOME>` sees the marks and the session folder's own events in one kernel-ordered
//! queue:
//!
//! - `claim.<id>.<gen>` when a writer takes the slot, `free.<id>.<gen>` when it lets go (after the OS hold is released,
//!   before the slot is, so `free` of one generation precedes `claim` of the next);
//! - `b.<gen>.<seq>.<pathhash>` / `e.<gen>.<seq>.<pathhash>` around every mutating syscall, on the thread that does it,
//!   one pair per path the syscall touches (a rename touches two);
//! - `d.<gen>.<seq>.<pathhash>` after the writer creates a directory; it then waits (2 s at most) for the harness to
//!   create `<parent of the trace dir>/f5-acks/d.<gen>.<seq>`, so the harness's watch on the new directory is in place
//!   before anything is written into it; on timeout it makes `dto.<gen>.<seq>`, which fails the run;
//! - `x.<gen>.<seq>` when the target's `(len, mtime_ns)` changed between the `b` mark and the writer's own syscall,
//!   which only a write that bypasses the writer can cause (the independent detector of §9.4);
//! - `rb.<seq>.<pathhash>` / `re.<seq>.<pathhash>` around the sanctioned summary read-modify-write (§5.5), which runs
//!   without a writer.
//!
//! `<pathhash>` is FNV-1a 64 over the absolute path's bytes, as 16 lowercase hex digits.
//!
//! Directory creation by the writer is itself a mutating syscall: it runs between `b`/`e` marks for the new directory,
//! and the `d` mark (with its ack) follows the `e`.
//!
//! Built with `--cfg f5_trace_control` (the build script sets it when `FUIGO_F5_TRACE_CONTROL=1` at build time; never
//! in a shipped build), the paused-writer negative control of §9.4 is available: with `FUIGO_F5_PAUSE=<file name>` set,
//! the first marked syscall on a path with that file name stops after its `b` marks and its `(len, mtime_ns)` record,
//! makes `p.<gen>.<seq>.<pathhash>`, and waits (30 s at most) for `<f5-acks>/p.<gen>.<seq>` before it re-checks the
//! record and runs. With `FUIGO_F5_PAUSE_ARM=<file name>` also set, the pause is armed only once `<f5-acks>/<file name>`
//! exists, so a case can hold the first such syscall after a chosen step (B4 holds a close-time write).
//!
//! The `(len, mtime_ns)` detector (`x` marks) judges a path only when no other marked syscall on it ran during the
//! method's `b`-to-check span: concurrent writer threads may legitimately touch one path, and such a change is not
//! attributable (the §9.4 limit).

use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// The environment variable that turns the marks on.
pub const TRACE_DIR_ENV: &str = "FUIGO_F5_TRACE_DIR";

const ACK_TIMEOUT: Duration = Duration::from_secs(2);
const ACK_POLL: Duration = Duration::from_millis(5);

#[derive(Clone)]
struct Tracer {
    marks: PathBuf,
    acks: PathBuf,
}

impl Tracer {
    fn at(marks: PathBuf) -> Self {
        let acks = marks.parent().map_or_else(|| PathBuf::from("f5-acks"), |parent| parent.join("f5-acks"));
        Self { marks, acks }
    }
}

static TRACER: LazyLock<Option<Tracer>> =
    LazyLock::new(|| std::env::var_os(TRACE_DIR_ENV).map(|dir| Tracer::at(PathBuf::from(dir))));

static SEQ: AtomicU64 = AtomicU64::new(1);

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    /// Tests turn tracing on for their own thread instead of through the process-wide environment variable.
    static TEST_TRACER: std::cell::RefCell<Option<Tracer>> = const { std::cell::RefCell::new(None) };
}

/// Turn the marks on for the calling thread only (tests; other crates through `test-support`).
#[cfg(any(test, feature = "test-support"))]
pub fn set_test_trace_dir(marks: Option<PathBuf>) {
    TEST_TRACER.with(|t| *t.borrow_mut() = marks.map(Tracer::at));
}

fn tracer() -> Option<Tracer> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(tracer) = TEST_TRACER.with(|t| t.borrow().clone()) {
        return Some(tracer);
    }
    TRACER.clone()
}

/// Whether marks are being written.
pub fn enabled() -> bool {
    #[cfg(any(test, feature = "test-support"))]
    if TEST_TRACER.with(|t| t.borrow().is_some()) {
        return true;
    }
    TRACER.is_some()
}

#[allow(clippy::disallowed_methods, reason = "B-F5 attribution marks (design F5 9.4): zero-byte files under FUIGO_F5_TRACE_DIR, off by default; not inside a session folder")]
fn mark(tracer: &Tracer, name: &str) {
    // A mark that cannot be made shows up as a missing mark, which fails the run; nothing else to do here.
    let _ = std::fs::create_dir_all(&tracer.marks);
    let _ = std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(tracer.marks.join(name));
}

/// FNV-1a 64 of the path's bytes, 16 hex digits.
pub fn path_hash(path: &Path) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in path.as_os_str().as_encoded_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}

pub(crate) fn claim(id: &str, generation: u64) {
    if let Some(tracer) = tracer() {
        mark(&tracer, &format!("claim.{id}.{generation}"));
    }
}

pub(crate) fn free(id: &str, generation: u64) {
    if let Some(tracer) = tracer() {
        mark(&tracer, &format!("free.{id}.{generation}"));
    }
}

fn stamp(path: &Path) -> Option<(u64, u128)> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    let mtime = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos());
    Some((metadata.len(), mtime))
}

/// Run `op`, the writer's syscall on `paths`, between `b` and `e` marks for each path. With marks off this is `op()`.
pub(crate) fn op<T>(generation: u64, paths: &[&Path], op: impl FnOnce() -> T) -> T {
    let Some(tracer) = tracer() else { return op() };
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let hashes: Vec<String> = paths.iter().map(|p| path_hash(p)).collect();
    for hash in &hashes {
        mark(&tracer, &format!("b.{generation}.{seq}.{hash}"));
    }
    let started = overlap_begin(&hashes);
    let in_flight = InFlight(&hashes);
    let before: Vec<_> = paths.iter().map(|p| stamp(p)).collect();
    #[cfg(test)]
    crate::seams::pass(&format!("trace-b:{}", hashes.first().map_or("", String::as_str)));
    #[cfg(f5_trace_control)]
    control::pause(&tracer, generation, seq, paths, &hashes);
    let after: Vec<_> = paths.iter().map(|p| stamp(p)).collect();
    let overlapped = overlapped(&hashes, &started);
    if before.iter().zip(&after).zip(&overlapped).any(|((b, a), shared)| b != a && !shared) {
        mark(&tracer, &format!("x.{generation}.{seq}"));
    }
    let result = op();
    drop(in_flight);
    for hash in hashes.iter().rev() {
        mark(&tracer, &format!("e.{generation}.{seq}.{hash}"));
    }
    result
}

/// Per path hash: marked syscalls started, and those still in flight (marks on only).
type Overlaps = std::collections::HashMap<String, (u64, u64)>;
static OVERLAPS: LazyLock<std::sync::Mutex<Overlaps>> = LazyLock::new(Default::default);

fn overlaps() -> std::sync::MutexGuard<'static, Overlaps> {
    OVERLAPS.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// This syscall starts on `hashes`: count it, and return each path's start count and whether another was in flight.
fn overlap_begin(hashes: &[String]) -> Vec<(u64, bool)> {
    let mut map = overlaps();
    hashes
        .iter()
        .map(|hash| {
            let entry = map.entry(hash.clone()).or_insert((0, 0));
            *entry = (entry.0 + 1, entry.1 + 1);
            (entry.0, entry.1 > 1)
        })
        .collect()
}

/// Whether another marked syscall on each path ran at any time between `overlap_begin` and now. Its own change to the
/// path cannot be told from an unmarked one, so the `(len, mtime_ns)` detector does not judge that path (the stated
/// limit of §9.4: a same-path write inside another marked window is not attributable).
fn overlapped(hashes: &[String], started: &[(u64, bool)]) -> Vec<bool> {
    let map = overlaps();
    hashes
        .iter()
        .zip(started)
        .map(|(hash, &(count, busy))| busy || map.get(hash).is_some_and(|&(now, live)| now != count || live > 1))
        .collect()
}

/// Ends the in-flight count of a marked syscall, on unwind too (a stuck count would silence the detector).
struct InFlight<'a>(&'a [String]);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        let mut map = overlaps();
        for hash in self.0 {
            if let Some(entry) = map.get_mut(hash) {
                entry.1 = entry.1.saturating_sub(1);
            }
        }
    }
}

/// The paused-writer hook of the §9.4 negative control (`--cfg f5_trace_control` only).
#[cfg(f5_trace_control)]
mod control {
    use std::path::Path;
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    const PAUSE_ENV: &str = "FUIGO_F5_PAUSE";
    const PAUSE_TIMEOUT: Duration = Duration::from_secs(30);

    const ARM_ENV: &str = "FUIGO_F5_PAUSE_ARM";

    static PAUSE: LazyLock<Option<std::ffi::OsString>> = LazyLock::new(|| std::env::var_os(PAUSE_ENV));
    static ARM: LazyLock<Option<std::ffi::OsString>> = LazyLock::new(|| std::env::var_os(ARM_ENV));
    static FIRED: AtomicBool = AtomicBool::new(false);

    pub(super) fn pause(tracer: &super::Tracer, generation: u64, seq: u64, paths: &[&Path], hashes: &[String]) {
        let Some(name) = PAUSE.as_deref() else { return };
        let Some(index) = paths.iter().position(|p| p.file_name() == Some(name)) else { return };
        if ARM.as_deref().is_some_and(|arm| !tracer.acks.join(arm).exists()) {
            return;
        }
        if FIRED.swap(true, Ordering::SeqCst) {
            return;
        }
        let hash = hashes.get(index).map_or("", String::as_str);
        super::mark(tracer, &format!("p.{generation}.{seq}.{hash}"));
        let ack = tracer.acks.join(format!("p.{generation}.{seq}"));
        let deadline = std::time::Instant::now() + PAUSE_TIMEOUT;
        while !ack.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(super::ACK_POLL);
        }
    }
}

/// The writer created `dir`: mark it, then wait (bounded) for the harness's acknowledgement that it watches `dir`.
pub(crate) fn dir_created(generation: u64, dir: &Path) {
    let Some(tracer) = tracer() else { return };
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    mark(&tracer, &format!("d.{generation}.{seq}.{}", path_hash(dir)));
    let ack = tracer.acks.join(format!("d.{generation}.{seq}"));
    let deadline = std::time::Instant::now() + ACK_TIMEOUT;
    while !ack.exists() {
        if std::time::Instant::now() >= deadline {
            mark(&tracer, &format!("dto.{generation}.{seq}"));
            return;
        }
        std::thread::sleep(ACK_POLL);
    }
}

/// The `rb` marks of a sanctioned summary section that awaits (the liveness mark's lock wait, §5.6), made now; the
/// matching `re` marks are made when the guard drops. With marks off this is an empty guard.
pub fn sanctioned_rmw_guard(paths: &[&Path]) -> RmwMarks {
    let Some(tracer) = tracer() else { return RmwMarks(None) };
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let hashes: Vec<String> = paths.iter().map(|p| path_hash(p)).collect();
    for hash in &hashes {
        mark(&tracer, &format!("rb.{seq}.{hash}"));
    }
    RmwMarks(Some((tracer, seq, hashes)))
}

/// See [`sanctioned_rmw_guard`]: makes the `re` marks on drop.
#[must_use = "the section's re marks are made when this drops"]
pub struct RmwMarks(Option<(Tracer, u64, Vec<String>)>);

impl Drop for RmwMarks {
    fn drop(&mut self) {
        if let Some((tracer, seq, hashes)) = self.0.take() {
            for hash in hashes.iter().rev() {
                mark(&tracer, &format!("re.{seq}.{hash}"));
            }
        }
    }
}

/// Run the sanctioned summary read-modify-write (§5.5), which holds no writer, between `rb` and `re` marks for each of
/// `paths` (`summary.json`, `summary.json.lock`, and the temporary sibling when the caller names it).
pub fn sanctioned_rmw<T>(paths: &[&Path], op: impl FnOnce() -> T) -> T {
    let Some(tracer) = tracer() else { return op() };
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let hashes: Vec<String> = paths.iter().map(|p| path_hash(p)).collect();
    for hash in &hashes {
        mark(&tracer, &format!("rb.{seq}.{hash}"));
    }
    let result = op();
    for hash in hashes.iter().rev() {
        mark(&tracer, &format!("re.{seq}.{hash}"));
    }
    result
}
