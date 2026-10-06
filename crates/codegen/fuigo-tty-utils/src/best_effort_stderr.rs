//! Stderr output for paths where fd 2 may already be dead.
//!
//! `eprintln!` / `eprint!` panic when the write to stderr fails ("failed printing to stderr"),
//! and this workspace builds with `panic = "abort"`, so the panic is a SIGABRT plus a crash
//! report: the same failure [`crate::best_effort_stdout`] removed for stdout. Rust leaves
//! SIGPIPE at `SIG_IGN`, so a stderr whose reader is gone (a closed terminal pane, `fuigo … 2>&1
//! | head`, a parent that exited, an Electron host that closed its end) hands every write
//! `EPIPE`; a stderr pointed at a full disk hands it `ENOSPC`; a hung-up tty hands it `EIO`.
//! Every one of those turned a warning, a usage error or a "not authenticated" line into an
//! abort, and the exit code the caller was waiting for into death by signal 6.
//!
//! Every diagnostic therefore prints through [`cli_eprintln!`] / [`cli_eprint!`]:
//!
//! - `BrokenPipe` (the reader is gone): the text is dropped and [`reader_gone`] turns true.
//! - `WouldBlock` (a tty or pipe left non-blocking by a Node/Electron parent): retried briefly.
//!   Once one call has used up its whole budget the stream counts as stalled and later calls
//!   stop waiting for it (first refusal is final) until a write gets through again, so a reader
//!   that never drains costs one pause, not one per line.
//! - Anything else (`EIO`, `ENOSPC`, an exhausted retry budget): the text is dropped and
//!   [`hard_failure`] turns true.
//!
//! # What a hard stderr failure does: nothing more
//!
//! It never panics, never aborts, never exits, and never changes the exit code. That differs
//! from stdout on purpose. Stdout carries the command's *result*, so truncated stdout is a
//! wrong answer and [`crate::best_effort_stdout`] turns it into exit 1. Stderr carries
//! *commentary about* the result: the command's outcome is already in its exit code and its
//! side effects, and neither is altered by a diagnostic nobody could read. A command that
//! succeeded has still succeeded (`fuigo sessions list 2>/dev/full` lists the sessions and exits
//! 0, as GNU tools do); a command that failed still exits with its own failure code, which is
//! what a script checks. Promoting "could not print a warning" to a failure would make success
//! depend on where the caller pointed fd 2, and there is no channel left to explain it on:
//! stderr is the channel that failed, stdout belongs to the command's data, and a log line
//! through `tracing` lands on the same dead stderr in the CLI modes. The flag is there for a
//! caller that wants to know (a prompt that must not proceed unseen can check the returned
//! [`Outcome`]).
//!
//! A *closed* fd 2 (`2>&-`) never reaches this policy: the Rust runtime reopens closed standard
//! fds on `/dev/null` before `main` on Unix, and std treats `EBADF` on a standard stream as
//! success, so those writes report `Written`.
//!
//! Stderr is unbuffered: each call renders its text once and hands it to one locked write, so a
//! line is not interleaved with another thread's and a retry never re-evaluates the arguments.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

pub use crate::best_effort_stdout::Outcome;
use crate::best_effort_stdout::{WOULD_BLOCK_RETRIES, classify, write_all_bytes_within};

/// Bookkeeping for one output stream. A type rather than loose statics so the policy can be
/// driven against a private instance and an in-process writer in tests.
struct Stream {
    reader_gone: AtomicBool,
    hard_failure: AtomicBool,
    /// The last write ran out its whole `WouldBlock` budget; cleared by the next success.
    stalled: AtomicBool,
}

impl Stream {
    const fn new() -> Self {
        Self {
            reader_gone: AtomicBool::new(false),
            hard_failure: AtomicBool::new(false),
            stalled: AtomicBool::new(false),
        }
    }

    /// Write all of `bytes` to `w` under the policy above, recording the outcome. Never panics.
    fn write(&self, w: &mut impl Write, bytes: &[u8]) -> Outcome {
        self.write_within(w, bytes, WOULD_BLOCK_RETRIES)
    }

    /// [`Stream::write`] with at most `would_block_retries` short waits (fewer when stalled).
    fn write_within(&self, w: &mut impl Write, bytes: &[u8], would_block_retries: u32) -> Outcome {
        let budget = if self.stalled.load(Ordering::Relaxed) {
            0
        } else {
            would_block_retries
        };
        match write_all_bytes_within(w, bytes, budget) {
            Ok(()) => {
                self.stalled.store(false, Ordering::Relaxed);
                Outcome::Written
            }
            Err(e) => {
                // Only a waited-out budget marks the stream stalled; a one-attempt write's
                // single refusal says nothing about how long the reader takes to drain.
                if e.kind() == std::io::ErrorKind::WouldBlock && budget > 0 {
                    self.stalled.store(true, Ordering::Relaxed);
                }
                let outcome = classify(&e);
                match outcome {
                    Outcome::ReaderGone => self.reader_gone.store(true, Ordering::Relaxed),
                    // Nothing is reported: stderr is the channel that just failed.
                    _ => self.hard_failure.store(true, Ordering::Relaxed),
                }
                outcome
            }
        }
    }
}

static STDERR: Stream = Stream::new();

/// `true` once a stderr write met `BrokenPipe` in this process: nobody is reading diagnostics.
pub fn reader_gone() -> bool {
    STDERR.reader_gone.load(Ordering::Relaxed)
}

/// `true` once a stderr write failed for a reason other than a gone reader. Informational: by
/// policy (module docs) it changes neither the exit code nor the control flow.
pub fn hard_failure() -> bool {
    STDERR.hard_failure.load(Ordering::Relaxed)
}

/// Write `bytes` to the process stderr, best-effort, recording the outcome in the process flags.
pub fn eprint_bytes(bytes: &[u8]) -> Outcome {
    let stderr = std::io::stderr();
    let mut err = stderr.lock();
    STDERR.write(&mut err, bytes)
}

/// Write formatted text to the process stderr, best-effort. The arguments are rendered once.
pub fn eprint_fmt(args: std::fmt::Arguments<'_>) -> Outcome {
    eprint_bytes(args.to_string().as_bytes())
}

/// Write `line` and a newline to `w`; `false` when the write failed. Never panics.
///
/// The writer is a parameter so callers can be tested against a closed pipe in-process.
pub fn write_line(w: &mut impl Write, line: &str) -> bool {
    crate::best_effort_stdout::write_line(w, line)
}

/// `line` plus a newline to the process stderr in ONE attempt (no `WouldBlock` wait), outcome
/// discarded. For exit and shutdown paths that run against a deadline of their own: a stalled
/// terminal must not stretch it.
pub fn eprint_line(line: &str) {
    let _ = eprint_line_reported(line);
}

/// [`eprint_line`], reporting whether the line was written.
pub fn eprint_line_reported(line: &str) -> bool {
    let text = format!("{line}\n");
    let stderr = std::io::stderr();
    let mut err = stderr.lock();
    STDERR.write_within(&mut err, text.as_bytes(), 0) == Outcome::Written
}

/// `eprintln!` that never panics on a dead, full or non-blocking stderr; the outcome is recorded
/// in [`reader_gone`] / [`hard_failure`] and otherwise discarded.
///
/// Evaluates to `()` so it drops into every position `eprintln!` occupied.
#[macro_export]
macro_rules! cli_eprintln {
    () => {{
        let _ = $crate::best_effort_stderr::eprint_fmt(::std::format_args!("\n"));
    }};
    ($($arg:tt)*) => {{
        let _ = $crate::best_effort_stderr::eprint_fmt(::std::format_args!(
            "{}\n",
            ::std::format_args!($($arg)*)
        ));
    }};
}

/// `eprint!` that never panics on a dead, full or non-blocking stderr; see [`cli_eprintln!`].
#[macro_export]
macro_rules! cli_eprint {
    ($($arg:tt)*) => {{
        let _ = $crate::best_effort_stderr::eprint_fmt(::std::format_args!($($arg)*));
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_line_appends_a_newline_and_reports_success() {
        let mut buf = Vec::new();
        assert!(write_line(&mut buf, "Finishing session…"));
        assert_eq!(buf, "Finishing session…\n".as_bytes());
    }

    /// Closing the read end makes every write fail with EPIPE, like the dead tty a closed pane
    /// leaves behind. SIGPIPE is ignored in Rust binaries, so the write returns an error;
    /// `eprintln!` would panic here and `panic = "abort"` would SIGABRT.
    #[test]
    fn a_dead_pipe_is_reader_gone_not_a_panic() {
        let (reader, mut writer) = std::io::pipe().expect("pipe");
        drop(reader);
        assert!(!write_line(&mut writer, "unreachable"));
        let stream = Stream::new();
        assert_eq!(
            stream.write(&mut writer, b"You are not authenticated.\n"),
            Outcome::ReaderGone
        );
        assert!(stream.reader_gone.load(Ordering::Relaxed));
        assert!(
            !stream.hard_failure.load(Ordering::Relaxed),
            "a gone reader is not a hard failure"
        );
    }

    /// A writer answering from a script: each entry is the reply to one `write` call; once the
    /// script is used up every write is accepted whole.
    struct Scripted {
        replies: std::collections::VecDeque<Option<std::io::ErrorKind>>,
        seen: Vec<u8>,
        calls: u32,
    }

    impl Scripted {
        fn new(replies: impl IntoIterator<Item = Option<std::io::ErrorKind>>) -> Self {
            Self {
                replies: replies.into_iter().collect(),
                seen: Vec::new(),
                calls: 0,
            }
        }
        fn refusing(kind: std::io::ErrorKind, times: usize) -> Self {
            Self::new(std::iter::repeat_n(Some(kind), times))
        }
    }

    impl Write for Scripted {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.calls += 1;
            match self.replies.pop_front() {
                Some(Some(kind)) => Err(kind.into()),
                Some(None) | None => {
                    self.seen.extend_from_slice(buf);
                    Ok(buf.len())
                }
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// `/dev/full` (`ENOSPC`), a hung-up tty (`EIO`) and a writer that accepts nothing are hard
    /// failures: recorded, text dropped, no panic.
    #[test]
    fn other_io_errors_are_recorded_as_hard_failures() {
        for kind in [
            std::io::ErrorKind::StorageFull,
            std::io::ErrorKind::Other,
            std::io::ErrorKind::PermissionDenied,
        ] {
            let stream = Stream::new();
            let mut w = Scripted::refusing(kind, 1);
            assert_eq!(
                stream.write(&mut w, b"warning\n"),
                Outcome::Failed,
                "{kind:?}"
            );
            assert!(stream.hard_failure.load(Ordering::Relaxed), "{kind:?}");
            assert!(!stream.reader_gone.load(Ordering::Relaxed), "{kind:?}");
            assert!(w.seen.is_empty(), "{kind:?}");
        }
    }

    /// A stream that failed once is still tried the next time: fd 2 can come back (a pipe that
    /// drained, a redirect that was restored), and then the line must land.
    #[test]
    fn a_failure_does_not_silence_later_lines() {
        let stream = Stream::new();
        let mut w = Scripted::refusing(std::io::ErrorKind::StorageFull, 1);
        assert_eq!(stream.write(&mut w, b"first\n"), Outcome::Failed);
        assert_eq!(stream.write(&mut w, b"second\n"), Outcome::Written);
        assert_eq!(w.seen, b"second\n");
    }

    /// A non-blocking stderr that is only briefly full still gets the line, once, in order.
    #[test]
    fn would_block_is_retried_within_the_budget() {
        let stream = Stream::new();
        let mut w = Scripted::refusing(std::io::ErrorKind::WouldBlock, 3);
        assert_eq!(stream.write(&mut w, b"warning: x\n"), Outcome::Written);
        assert_eq!(w.seen, b"warning: x\n");
        assert_eq!(w.calls, 4);
        assert!(!stream.stalled.load(Ordering::Relaxed));
        assert!(!stream.hard_failure.load(Ordering::Relaxed));
    }

    /// A reader that never drains costs one full budget, not one per line: after the first
    /// exhausted call the stream is stalled and each later line gives up on its first refusal,
    /// until a write gets through and the budget comes back.
    #[test]
    fn a_stalled_stream_stops_being_waited_for_until_it_recovers() {
        let stream = Stream::new();
        let budget = WOULD_BLOCK_RETRIES as usize;
        // Call 1: budget + 1 refusals (the initial try and every retry). Call 2: one refusal.
        // Call 3: accepted. Call 4: three refusals, then accepted (budget is back).
        let mut w = Scripted::new(
            std::iter::repeat_n(Some(std::io::ErrorKind::WouldBlock), budget + 2)
                .chain([None])
                .chain(std::iter::repeat_n(Some(std::io::ErrorKind::WouldBlock), 3)),
        );
        assert_eq!(stream.write(&mut w, b"one\n"), Outcome::Failed);
        assert_eq!(w.calls as usize, budget + 1);
        assert!(stream.stalled.load(Ordering::Relaxed));
        assert!(stream.hard_failure.load(Ordering::Relaxed));

        assert_eq!(stream.write(&mut w, b"two\n"), Outcome::Failed);
        assert_eq!(
            w.calls as usize,
            budget + 2,
            "a stalled stream gets one attempt, no waiting"
        );

        assert_eq!(stream.write(&mut w, b"three\n"), Outcome::Written);
        assert!(!stream.stalled.load(Ordering::Relaxed));

        assert_eq!(stream.write(&mut w, b"four\n"), Outcome::Written);
        assert_eq!(w.seen, b"three\nfour\n");
    }

    /// The one-attempt entry points (`eprint_line*`, used against shutdown deadlines) never
    /// wait on `WouldBlock`: one refusal is the answer.
    #[test]
    fn a_zero_budget_write_gives_up_on_the_first_would_block() {
        let stream = Stream::new();
        let mut w = Scripted::refusing(std::io::ErrorKind::WouldBlock, 1);
        assert_eq!(stream.write_within(&mut w, b"notice\n", 0), Outcome::Failed);
        assert_eq!(w.calls, 1);
        assert!(
            !stream.stalled.load(Ordering::Relaxed),
            "one refusal is not a stall: later lines keep their budget"
        );
    }

    /// The macros type as `()` so they fit every statement and match-arm position `eprintln!`
    /// held, and they compile with no arguments, a literal, and format arguments. Writing to
    /// the test harness's stderr is fine: it is live.
    #[test]
    fn macros_type_as_unit() {
        let unit: () = crate::cli_eprintln!();
        let also: () = crate::cli_eprintln!("literal");
        let n = 3;
        let third: () = crate::cli_eprintln!("{} warning(s), {n}", n);
        let fourth: () = crate::cli_eprint!("{}", "no newline\n");
        let _ = (unit, also, third, fourth);
    }
}
