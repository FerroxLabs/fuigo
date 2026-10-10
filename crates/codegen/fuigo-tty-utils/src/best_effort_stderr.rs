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

/// Write Fuigo's own control text to the process stderr unfiltered: the sign-in spinner's `CR ESC [ K`, trusted colour.
/// Only [`cli_eprint_trusted!`] may call this (it accepts a string literal and nothing else); the name and
/// `doc(hidden)` keep it out of the API, and a test pins that the workspace has no other caller. Any value another
/// party wrote belongs in [`crate::Untrusted`] on the filtered path ([`eprint_fmt`]), never here.
#[doc(hidden)]
pub fn __eprint_trusted_literal(text: &'static str) -> Outcome {
    eprint_bytes(text.as_bytes())
}

/// Reset of all terminal attributes. Fuigo writes it through the trusted path before its own denial and notice lines,
/// so styling left behind by earlier output cannot restyle or hide them.
pub const RESET_ATTRIBUTES: &str = "\x1b[0m";

/// The sign-in flow's spinner clear: carriage return, erase to end of line. Fuigo-written, so it uses the trusted path;
/// the line filter refuses it in any text another party touched.
pub const CLEAR_LINE: &str = "\r\x1b[K";

/// Write formatted text to the process stderr, best-effort. The arguments are rendered once.
pub fn eprint_fmt(args: std::fmt::Arguments<'_>) -> Outcome {
    let stderr = std::io::stderr();
    let mut err = stderr.lock();
    write_fmt_scrubbed(&mut err, args)
}

/// [`eprint_fmt`] against any writer. Diagnostics interpolate names, paths and messages from project files and servers,
/// so the text goes through the shared terminal filter before it is written.
fn write_fmt_scrubbed(w: &mut impl Write, args: std::fmt::Arguments<'_>) -> Outcome {
    let text = args.to_string();
    STDERR.write(w, crate::scrub_terminal_text(&text).as_bytes())
}

/// Write `line` and a newline to `w` through the terminal line filter ([`crate::scrub_terminal_text`]); `false` when
/// the write failed. Never panics. The filter runs here, so a caller cannot forget it. For Fuigo's own voice on the
/// process stderr use [`write_fuigo_line`], which also resets terminal attributes first.
///
/// The writer is a parameter so callers can be tested against a closed pipe in-process.
pub fn write_line(w: &mut impl Write, line: &str) -> bool {
    write_line_scrubbed(w, line, false)
}

/// [`write_line`] for Fuigo's own denial and notice lines: when the process stderr is a terminal the line starts with
/// [`RESET_ATTRIBUTES`] written on the trusted path.
pub fn write_fuigo_line(w: &mut impl Write, line: &str) -> bool {
    use std::io::IsTerminal;
    write_fuigo_line_with(w, line, std::io::stderr().is_terminal())
}

/// [`write_fuigo_line`] with the terminal decision made by the caller (tests, and writers that know their own stream).
pub fn write_fuigo_line_with(w: &mut impl Write, line: &str, reset: bool) -> bool {
    write_line_scrubbed(w, line, reset)
}

/// Writes the trusted reset when `reset` is set, then `body`; one buffer, one write call.
fn write_reset_and(w: &mut impl Write, reset: bool, body: &[u8]) -> bool {
    if !reset {
        return STDERR.write_within(w, body, 0) == Outcome::Written;
    }
    // One buffer, one write: the reset and the line cannot be split by another writer on the same stream.
    let mut buf = Vec::with_capacity(RESET_ATTRIBUTES.len() + body.len());
    buf.extend_from_slice(RESET_ATTRIBUTES.as_bytes());
    buf.extend_from_slice(body);
    STDERR.write_within(w, &buf, 0) == Outcome::Written
}

/// `line` plus a newline to the process stderr in ONE attempt (no `WouldBlock` wait), outcome
/// discarded. For exit and shutdown paths that run against a deadline of their own: a stalled
/// terminal must not stretch it.
pub fn eprint_line(line: &str) {
    let _ = eprint_line_reported(line);
}

/// [`eprint_line`], reporting whether the line was written.
pub fn eprint_line_reported(line: &str) -> bool {
    use std::io::IsTerminal;
    let stderr = std::io::stderr();
    let reset = stderr.is_terminal();
    let mut err = stderr.lock();
    write_line_scrubbed(&mut err, line, reset)
}

/// [`eprint_line_reported`] against any writer; the line goes through the shared terminal filter. `reset` writes
/// [`RESET_ATTRIBUTES`] first (set when the writer is a terminal): these lines are Fuigo's own voice and follow
/// untrusted stream content, which must not leave styling behind that hides or restyles them.
fn write_line_scrubbed(w: &mut impl Write, line: &str, reset: bool) -> bool {
    let text = format!("{line}\n");
    write_reset_and(w, reset, crate::scrub_terminal_text(&text).as_bytes())
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

/// Trusted-bytes counterpart of [`cli_eprint!`]: a `'static` literal written without the line filter (see
/// [`best_effort_stderr::__eprint_trusted_literal`]).
#[macro_export]
macro_rules! cli_eprint_trusted {
    ($text:literal) => {{
        let _ = $crate::best_effort_stderr::__eprint_trusted_literal($text);
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

    /// P181 (Grok round): diagnostics are display text, so an escape sequence in an interpolated name never reaches fd 2.
    #[test]
    fn diagnostics_are_scrubbed_before_they_are_written() {
        let mut buf = Vec::new();
        assert_eq!(
            write_fmt_scrubbed(&mut buf, format_args!("warn: {}\u{2028}end\n", "a\x1b]0;t\x07b")),
            Outcome::Written
        );
        assert_eq!(String::from_utf8(buf).unwrap(), "warn: a ]0;t b end\n");
        let mut buf = Vec::new();
        assert!(write_line_scrubbed(&mut buf, "x\u{e0041}\x1b[31my\x1b[2J", false));
        assert_eq!(String::from_utf8(buf).unwrap(), "x [31my [2J\n");
        let mut buf = Vec::new();
        assert!(write_line_scrubbed(&mut buf, "\r\x1b[Kfuigo: forged\x1b[8m", false));
        assert_eq!(String::from_utf8(buf).unwrap(), "  [Kfuigo: forged [8m\n");
    }

    /// P181 (S5, M4, c): Fuigo's one production grey (the device-code warning) is trusted literal bytes around scrubbed
    /// text, and renders exactly `ESC[90m text ESC[0m LF` on a terminal; the spinner erase equals [`CLEAR_LINE`].
    #[test]
    fn the_device_code_grey_renders_its_exact_bytes() {
        let mut w = Scripted::new([]);
        assert_eq!(STDERR.write(&mut w, "\x1b[90m".as_bytes()), Outcome::Written);
        assert_eq!(
            write_fmt_scrubbed(&mut w, format_args!("Only continue with a code you requested. Don't share it with anyone.")),
            Outcome::Written
        );
        assert_eq!(STDERR.write(&mut w, "\x1b[0m\n".as_bytes()), Outcome::Written);
        assert_eq!(
            w.seen,
            b"\x1b[90mOnly continue with a code you requested. Don't share it with anyone.\x1b[0m\n".to_vec()
        );
        assert_eq!(CLEAR_LINE, "\r\x1b[K");
    }

    /// P181 (S3): the sign-in spinner's erase-line and Fuigo's own colour reach the terminal through the trusted path
    /// exactly, while the same bytes in the filtered path lose the erase-line AND the colour (S5: the line filter passes no escape).
    #[test]
    fn trusted_control_text_is_exact_and_the_filtered_path_refuses_the_erase() {
        let mut w = Scripted::new([]);
        assert_eq!(STDERR.write(&mut w, CLEAR_LINE.as_bytes()), Outcome::Written);
        assert_eq!(w.seen, b"\r\x1b[K");
        let mut buf = Vec::new();
        assert_eq!(
            write_fmt_scrubbed(&mut buf, format_args!("{CLEAR_LINE}\x1b[1;32m\u{2713} Signed in\x1b[0m\n")),
            Outcome::Written
        );
        assert_eq!(String::from_utf8(buf).unwrap(), "  [K [1;32m\u{2713} Signed in [0m\n");
    }

    /// P181 (S5, M4): a foreground colour that hides text (`ESC[30m`, `ESC[90m`, truecolor) never survives the filter.
    #[test]
    fn the_line_filter_passes_no_colour_sequence() {
        for hide in ["\x1b[30m", "\x1b[37m", "\x1b[90m", "\x1b[97m", "\x1b[38;5;0m", "\x1b[38;2;0;0;0m", "\x1b[1;32m"] {
            let mut buf = Vec::new();
            assert_eq!(write_fmt_scrubbed(&mut buf, format_args!("a{hide}hidden")), Outcome::Written);
            let out = String::from_utf8(buf).unwrap();
            assert!(!out.contains('\x1b'), "{out:?}");
            let mut buf = Vec::new();
            assert!(write_line_scrubbed(&mut buf, &format!("a{hide}hidden"), false));
            assert!(!String::from_utf8(buf).unwrap().contains('\x1b'));
        }
        assert_eq!(crate::scrub_terminal_text("x\x1b[30mY").as_ref(), "x [30mY");
    }

    /// P181 (S5, L1): the reset and the line are ONE write call, so no other writer lands between them.
    #[test]
    fn reset_and_line_are_one_write() {
        struct Count(Vec<Vec<u8>>);
        impl Write for Count {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.push(b.to_vec());
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut w = Count(Vec::new());
        assert!(write_line_scrubbed(&mut w, "fuigo: blocked", true));
        assert_eq!(w.0, vec![b"\x1b[0mfuigo: blocked\n".to_vec()]);
    }

    /// P181 (Grok r3): Fuigo's own lines start with a trusted reset when the stream is a terminal, and the model's
    /// restyling bytes cannot follow it; the reset is not written for a pipe or file.
    #[test]
    fn fuigo_lines_start_with_a_reset_on_a_terminal_only() {
        let mut buf = Vec::new();
        assert!(write_line_scrubbed(&mut buf, "fuigo: blocked \x1b[30;40m", true));
        assert_eq!(buf, b"\x1b[0mfuigo: blocked  [30;40m\n");
        let mut buf = Vec::new();
        assert!(write_line_scrubbed(&mut buf, "fuigo: blocked", false));
        assert_eq!(buf, b"fuigo: blocked\n");
        let mut buf = Vec::new();
        assert!(write_line(&mut buf, "a\x1b[2Jb"));
        assert_eq!(buf, b"a [2Jb\n");
    }

    /// P181 (Grok r3, L4): the unfiltered writer has one caller in the workspace, the literal macro.
    #[test]
    fn the_unfiltered_literal_writer_is_called_only_by_its_macro() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut stack = vec![root];
        let mut callers = Vec::new();
        while let Some(dir) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for e in rd.flatten() {
                let path = e.path();
                if path.is_dir() {
                    if path.file_name().is_some_and(|n| n == "target" || n == "node_modules") {
                        continue;
                    }
                    stack.push(path);
                } else if path.extension().is_some_and(|x| x == "rs")
                    && std::fs::read_to_string(&path).is_ok_and(|t| t.contains(concat!("__eprint_trusted", "_literal(")))
                {
                    callers.push(path);
                }
            }
        }
        assert_eq!(callers.len(), 1, "{callers:?}");
        assert!(callers[0].ends_with("best_effort_stderr.rs"), "{callers:?}");
    }

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
