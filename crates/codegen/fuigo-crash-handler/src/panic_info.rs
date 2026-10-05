//! Panic classification recorded before `abort`.
//!
//! Release builds use `panic = "abort"`, so every panic ends in SIGABRT and
//! the signal handler alone cannot tell a panic from any other abort, nor a
//! broken-pipe panic (user-environment noise) from a real defect. The panic
//! hook runs in normal context on the panicking thread *before* the abort,
//! so it classifies the panic there and leaves a few fixed-size facts in
//! static storage that the signal handler copies into the blob:
//!
//! - a class code (benign broken pipe / benign disk full / other),
//! - the panicking thread's name (capped, path separators removed),
//! - the panicking thread's id, so the handler only attributes the abort to
//!   the panic when it fires on that same thread.
//!
//! The free-form panic message is never stored: it can carry user content.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use crate::format::{PanicClass, THREAD_NAME_LEN};

const EMPTY: u8 = 0;
const WRITING: u8 = 1;
const READY: u8 = 2;

/// One recorded panic. Each panicking thread claims its own record, so a
/// panic on one thread can never hide (or relabel) another thread's.
struct Record {
    state: AtomicU8,
    thread_id: AtomicU64,
    class: AtomicU8,
    thread_name: UnsafeCell<[u8; THREAD_NAME_LEN]>,
}

// SAFETY: `thread_name` is written only by the thread that won the
// EMPTY -> WRITING transition and read only after observing READY
// (Release/Acquire), so access is never concurrent.
unsafe impl Sync for Record {}

/// Concurrent panics recorded at once; more than this many threads panicking
/// together is not a case worth more memory (extra ones are reported as a
/// plain SIGABRT).
const RECORDS: usize = 8;

#[allow(clippy::declare_interior_mutable_const)]
const EMPTY_RECORD: Record = Record {
    state: AtomicU8::new(EMPTY),
    thread_id: AtomicU64::new(0),
    class: AtomicU8::new(0),
    thread_name: UnsafeCell::new([0; THREAD_NAME_LEN]),
};
static PANICS: [Record; RECORDS] = [EMPTY_RECORD; RECORDS];
static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Classify a panic message: the single list of user-environment noise.
/// The Sentry filter (`fuigo-telemetry` `sentry.rs`, `is_broken_pipe_panic`)
/// calls this too, so reporting and the local notice can never disagree.
pub fn classify_panic_message(message: &str) -> PanicClass {
    if message.contains("Broken pipe") || message.contains("os error 32") {
        PanicClass::BenignBrokenPipe
    } else if message.contains("No space left on device") || message.contains("os error 28") {
        PanicClass::BenignNoSpace
    } else {
        PanicClass::None
    }
}

/// Label stored instead of a thread name that looks like a path.
pub const PATH_LIKE_THREAD_NAME: &str = "<path-like name>";

/// Cap a thread name to [`THREAD_NAME_LEN`] bytes (on a char boundary) and
/// replace control characters. A name containing a path separator is
/// replaced whole by [`PATH_LIKE_THREAD_NAME`], so a filesystem path can
/// never reach the report.
pub fn sanitize_thread_name(name: &str) -> String {
    if name.contains('/') || name.contains('\\') {
        return PATH_LIKE_THREAD_NAME.to_string();
    }
    let mut out = String::with_capacity(THREAD_NAME_LEN);
    for c in name.chars() {
        let c = if c.is_control() { '_' } else { c };
        if out.len() + c.len_utf8() > THREAD_NAME_LEN {
            break;
        }
        out.push(c);
    }
    out
}

/// Identifier of the calling thread, comparable between the panic hook and
/// the signal handler (both run on the faulting thread).
#[cfg(unix)]
pub(crate) fn current_thread_id() -> u64 {
    // pthread_self only reads the thread pointer; safe in a signal handler.
    unsafe { libc::pthread_self() as usize as u64 }
}

#[cfg(windows)]
pub(crate) fn current_thread_id() -> u64 {
    unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() as u64 }
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn current_thread_id() -> u64 {
    0
}

/// Record a panic for the calling thread. The first panic on a thread wins:
/// with `panic = "abort"` it is the one that aborts, and a follow-on "panic
/// in a function that cannot unwind" must not overwrite its class.
pub(crate) fn record_panic(message: &str, thread_name: Option<&str>) {
    let tid = current_thread_id();
    if PANICS.iter().any(|r| {
        r.state.load(Ordering::Acquire) != EMPTY && r.thread_id.load(Ordering::Acquire) == tid
    }) {
        return;
    }
    let Some(record) = PANICS.iter().find(|r| {
        r.state
            .compare_exchange(EMPTY, WRITING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }) else {
        return; // all records in use
    };
    let name = sanitize_thread_name(thread_name.unwrap_or("<unnamed>"));
    // SAFETY: this thread won EMPTY -> WRITING on `record`; nobody else
    // touches the buffer until READY is published below.
    unsafe {
        let buf = &mut *record.thread_name.get();
        buf.fill(0);
        buf[..name.len()].copy_from_slice(name.as_bytes());
    }
    record
        .class
        .store(classify_panic_message(message).to_u8(), Ordering::Relaxed);
    record.thread_id.store(tid, Ordering::Release);
    record.state.store(READY, Ordering::Release);
}

#[cfg(unix)]
/// What the signal handler copies into the blob. Async-signal-safe: atomics
/// and a read of a static buffer published with Release/Acquire.
pub(crate) struct PanicSnapshot {
    pub class: u8,
    pub thread_name: &'static [u8; THREAD_NAME_LEN],
}

#[cfg(unix)]
/// The panic recorded on the calling thread, if any. Async-signal-safe:
/// atomic loads and a reference into static storage.
pub(crate) fn snapshot_for_current_thread() -> Option<PanicSnapshot> {
    let tid = current_thread_id();
    let record = PANICS.iter().find(|r| {
        r.state.load(Ordering::Acquire) == READY && r.thread_id.load(Ordering::Acquire) == tid
    })?;
    Some(PanicSnapshot {
        class: record.class.load(Ordering::Relaxed),
        // SAFETY: READY was published after the last write to the buffer.
        thread_name: unsafe { &*record.thread_name.get() },
    })
}

/// Install the classifying panic hook once, chained in front of whatever
/// hook is already set (Sentry, the default printer). Hooks installed later
/// (telemetry, the TUI teardown hook) wrap this one and call it in turn.
pub(crate) fn install_hook() {
    if HOOK_INSTALLED.swap(true, Ordering::AcqRel) {
        return;
    }
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = info.payload_as_str().unwrap_or("");
        record_panic(message, std::thread::current().name());
        previous(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_like_the_sentry_filter() {
        for m in [
            "failed printing to stdout: Broken pipe (os error 32)",
            "called `Result::unwrap()` on an `Err` value: Os { code: 32, kind: BrokenPipe, message: \"Broken pipe\" }",
            "write failed: os error 32",
        ] {
            assert_eq!(
                classify_panic_message(m),
                PanicClass::BenignBrokenPipe,
                "{m}"
            );
        }
        for m in [
            "No space left on device (os error 28)",
            "flush: os error 28",
        ] {
            assert_eq!(classify_panic_message(m), PanicClass::BenignNoSpace, "{m}");
        }
        for m in [
            "index out of bounds: the len is 3 but the index is 7",
            "attempt to subtract with overflow",
            "",
        ] {
            assert_eq!(classify_panic_message(m), PanicClass::None, "{m}");
        }
    }

    #[test]
    fn thread_names_are_capped_and_pathless() {
        assert_eq!(sanitize_thread_name("main"), "main");
        assert_eq!(
            sanitize_thread_name("/home/alice/secret\\proj"),
            PATH_LIKE_THREAD_NAME
        );
        assert_eq!(sanitize_thread_name("a\nb"), "a_b");
        let long = "x".repeat(100);
        assert_eq!(sanitize_thread_name(&long).len(), THREAD_NAME_LEN);
        // Multi-byte chars never split.
        let wide = "é".repeat(40);
        let s = sanitize_thread_name(&wide);
        assert!(s.len() <= THREAD_NAME_LEN && s.chars().all(|c| c == 'é'));
    }
}
