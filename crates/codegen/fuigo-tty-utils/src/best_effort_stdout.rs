//! Stdout output for CLI paths where fd 1's reader may already be gone.
//!
//! `println!` / `print!` panic when the write to stdout fails ("failed printing to stdout"), and
//! this workspace builds with `panic = "abort"`, so the panic is a SIGABRT plus a crash report.
//! Rust leaves SIGPIPE at `SIG_IGN`, so a pipe whose reader exited (`fuigo models | head`, a
//! parent that died, an Electron host that closed its end) hands every write `EPIPE` instead of
//! terminating the process quietly. Four shipped-binary crash reports (fuigo 1.0.19, macOS) show
//! exactly this stack, `std::io::stdio::_print` → `panic_fmt` → `abort`, from `fuigo models`'
//! first `println!("You are not authenticated.")`.
//!
//! Every CLI subcommand therefore prints through [`cli_println!`] / [`cli_print!`]:
//!
//! - `BrokenPipe` (the reader is gone): the text is dropped silently and [`reader_gone`] turns
//!   true, so an output-only command can stop early. Nobody is reading, so nothing is lost.
//! - `WouldBlock` (a tty left non-blocking by a Node/Electron parent): retried briefly.
//! - Anything else (`EIO`, `ENOSPC`, a retry budget exhausted): the text is dropped, the failure
//!   is reported once on stderr (best-effort), and [`hard_failure`] turns true so the binary can
//!   end with a non-zero exit instead of pretending its machine-readable output was complete.
//!
//! Stderr has the same failure mode (`eprintln!` panics on a failed write); its counterpart is
//! [`crate::best_effort_stderr`] with `cli_eprintln!` / `cli_eprint!`.
//!
//! Nothing here panics or exits the process: the command runs to its normal exit, so guards
//! (agent shutdown, child cleanup, telemetry flush) still run. This crate hosts the helper
//! because both the pager and the shell print from CLI paths and both already depend on it.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

/// How many short waits a `WouldBlock` write or flush gets before it counts as a hard failure.
pub(crate) const WOULD_BLOCK_RETRIES: u32 = 25;
/// Pause between `WouldBlock` retries (worst case `WOULD_BLOCK_RETRIES` × this per call).
const WOULD_BLOCK_PAUSE: std::time::Duration = std::time::Duration::from_millis(10);

static READER_GONE: AtomicBool = AtomicBool::new(false);
static HARD_FAILURE: AtomicBool = AtomicBool::new(false);

/// What became of one best-effort write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Every byte was written (and flushed, for the process-stdout entry points).
    Written,
    /// The reader is gone (`BrokenPipe`); the text was dropped and nobody missed it.
    ReaderGone,
    /// Another I/O failure, or `WouldBlock` beyond the retry budget; the text was dropped.
    Failed,
}

/// `true` once a stdout write met `BrokenPipe` in this process: the reader is gone for good.
/// Output-only commands use it to stop doing work nobody will see.
pub fn reader_gone() -> bool {
    READER_GONE.load(Ordering::Relaxed)
}

/// `true` once a stdout write failed for a reason other than a gone reader. The binary turns
/// this into a non-zero exit so truncated output is never reported as success.
pub fn hard_failure() -> bool {
    HARD_FAILURE.load(Ordering::Relaxed)
}

pub(crate) fn classify(e: &std::io::Error) -> Outcome {
    if e.kind() == std::io::ErrorKind::BrokenPipe {
        Outcome::ReaderGone
    } else {
        Outcome::Failed
    }
}

/// Write all of `bytes` to `w`, retrying `Interrupted` and (briefly) `WouldBlock`.
/// Partial progress is kept across retries, so no byte is written twice.
pub fn write_all_bytes(w: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
    write_all_bytes_within(w, bytes, WOULD_BLOCK_RETRIES)
}

/// [`write_all_bytes`] with an explicit `WouldBlock` budget: `would_block_retries` short waits
/// for the whole call, `0` meaning the first `WouldBlock` is the answer.
pub(crate) fn write_all_bytes_within(
    w: &mut impl Write,
    mut bytes: &[u8],
    would_block_retries: u32,
) -> std::io::Result<()> {
    let mut retries = 0u32;
    while !bytes.is_empty() {
        match w.write(bytes) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if retries >= would_block_retries {
                    return Err(e);
                }
                retries += 1;
                std::thread::sleep(WOULD_BLOCK_PAUSE);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Flush `w`, retrying `Interrupted` and (briefly) `WouldBlock`.
pub fn flush_retrying(w: &mut impl Write) -> std::io::Result<()> {
    let mut retries = 0u32;
    loop {
        match w.flush() {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if retries >= WOULD_BLOCK_RETRIES {
                    return Err(e);
                }
                retries += 1;
                std::thread::sleep(WOULD_BLOCK_PAUSE);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Write `bytes` to `w` and flush; the failure, if any, classified. Never panics.
///
/// The writer is a parameter so the policy can be tested against a closed pipe or a failing
/// writer in-process; the process-stdout entry points below add the bookkeeping flags.
pub fn write_bytes(w: &mut impl Write, bytes: &[u8]) -> Outcome {
    match write_all_bytes(w, bytes).and_then(|()| flush_retrying(w)) {
        Ok(()) => Outcome::Written,
        Err(e) => classify(&e),
    }
}

/// [`write_bytes`] of formatted text. The arguments are rendered once, so a retry never
/// re-evaluates them.
pub fn write_fmt(w: &mut impl Write, args: std::fmt::Arguments<'_>) -> Outcome {
    write_bytes(w, args.to_string().as_bytes())
}

/// [`write_fmt`] of `line` plus a newline; `true` when it was written.
pub fn write_line(w: &mut impl Write, line: &str) -> bool {
    write_fmt(w, format_args!("{line}\n")) == Outcome::Written
}

fn record(outcome: Outcome, describe: impl FnOnce() -> String) -> Outcome {
    match outcome {
        Outcome::Written => {}
        Outcome::ReaderGone => READER_GONE.store(true, Ordering::Relaxed),
        Outcome::Failed => {
            // One note per process; stderr may be just as dead, so its own failure is ignored.
            if !HARD_FAILURE.swap(true, Ordering::Relaxed) {
                let _ = writeln!(std::io::stderr(), "fuigo: {}", describe());
            }
        }
    }
    outcome
}

fn stdout_outcome(bytes: &[u8]) -> Outcome {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    match write_all_bytes(&mut out, bytes).and_then(|()| flush_retrying(&mut out)) {
        Ok(()) => Outcome::Written,
        Err(e) => record(classify(&e), || format!("stdout write failed: {e}")),
    }
}

/// Write `bytes` to the process stdout, best-effort, recording the outcome in the process flags.
pub fn print_bytes(bytes: &[u8]) -> Outcome {
    stdout_outcome(bytes)
}

/// Write formatted text to the process stdout, best-effort, recording the outcome in the
/// process flags. `std::io::Stdout` is line-buffered; text without a trailing newline (a
/// completion script) is flushed here so a later write cannot reorder it.
pub fn print_fmt(args: std::fmt::Arguments<'_>) -> Outcome {
    use std::io::IsTerminal;
    let text = args.to_string();
    stdout_outcome(stdout_text(&text, std::io::stdout().is_terminal()).as_bytes())
}

/// What [`print_fmt`] writes for `text`. On a terminal it is display text and goes through the shared filter; on a pipe
/// or a file it may be data (a JSON document, a script) and stays exact.
fn stdout_text(text: &str, terminal: bool) -> std::borrow::Cow<'_, str> {
    if terminal {
        crate::scrub_terminal_text(text)
    } else {
        std::borrow::Cow::Borrowed(text)
    }
}

/// A [`Write`] for CLI subcommands that print human output through a writer parameter (tables, reports, a transcript).
/// On a terminal it holds the text until [`Write::flush`] or drop and writes it through the shared terminal filter, so a
/// path, branch or server name carrying an escape sequence cannot reach the screen; whole-text filtering also keeps a
/// sequence split across two `write` calls from slipping through. On a pipe or a file it passes every write straight
/// through, since there the text may be data.
pub struct DisplayWriter<W: Write> {
    inner: W,
    terminal: bool,
    pending: Vec<u8>,
}

impl<W: Write> DisplayWriter<W> {
    pub fn new(inner: W, terminal: bool) -> Self {
        Self {
            inner,
            terminal,
            pending: Vec::new(),
        }
    }
}

/// The process stdout as a [`DisplayWriter`]; filtered when it is a terminal.
pub fn display_stdout() -> DisplayWriter<std::io::StdoutLock<'static>> {
    use std::io::IsTerminal;
    let stdout = std::io::stdout();
    let terminal = stdout.is_terminal();
    DisplayWriter::new(stdout.lock(), terminal)
}

impl<W: Write> Write for DisplayWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.terminal {
            self.pending.extend_from_slice(buf);
            Ok(buf.len())
        } else {
            self.inner.write(buf)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.pending.is_empty() {
            // Keep an incomplete UTF-8 tail for the next flush; anything else invalid shows as U+FFFD
            let split = match std::str::from_utf8(&self.pending) {
                Ok(_) => self.pending.len(),
                Err(e) if e.error_len().is_none() => e.valid_up_to(),
                Err(_) => self.pending.len(),
            };
            let tail = self.pending.split_off(split);
            let text = String::from_utf8_lossy(&self.pending).into_owned();
            self.pending = tail;
            self.inner.write_all(crate::scrub_terminal_text(&text).as_bytes())?;
        }
        self.inner.flush()
    }
}

impl<W: Write> Drop for DisplayWriter<W> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// `println!` that never panics on a dead or non-blocking stdout; the outcome is recorded in
/// [`reader_gone`] / [`hard_failure`] and otherwise discarded.
///
/// Evaluates to `()` so it drops into every position `println!` occupied.
#[macro_export]
macro_rules! cli_println {
    () => {{
        let _ = $crate::best_effort_stdout::print_fmt(::std::format_args!("\n"));
    }};
    ($($arg:tt)*) => {{
        let _ = $crate::best_effort_stdout::print_fmt(::std::format_args!(
            "{}\n",
            ::std::format_args!($($arg)*)
        ));
    }};
}

/// `print!` that never panics on a dead or non-blocking stdout; see [`cli_println!`].
#[macro_export]
macro_rules! cli_print {
    ($($arg:tt)*) => {{
        let _ = $crate::best_effort_stdout::print_fmt(::std::format_args!($($arg)*));
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P181 (Grok round): on a terminal, stdout text is display text; on a pipe it stays exact (it may be data).
    #[test]
    fn terminal_text_is_scrubbed_and_piped_text_is_not() {
        assert_eq!(stdout_text("plug\x1b]0;t\x07in\u{2028}\n", true), "plug ]0;t in \n");
        assert_eq!(stdout_text("a\x1bb\u{2028}\n", false), "a\x1bb\u{2028}\n");
    }

    /// P181 (Grok round): human output written through a writer is scrubbed as a whole on a terminal, even when a
    /// sequence arrives split across writes, and is exact on a pipe.
    #[test]
    fn display_writer_scrubs_on_a_terminal_and_is_exact_on_a_pipe() {
        let mut shown = Vec::new();
        {
            let mut w = DisplayWriter::new(&mut shown, true);
            w.write_all(b"branch \x1b").unwrap();
            w.write_all(b"]0;owned\x07 \xe2\x80").unwrap();
            w.write_all(b"\xa8end\n").unwrap();
        }
        assert_eq!(String::from_utf8(shown).unwrap(), "branch  ]0;owned   end\n");
        let mut piped = Vec::new();
        {
            let mut w = DisplayWriter::new(&mut piped, false);
            w.write_all(b"a\x1b]0;t\x07b\n").unwrap();
        }
        assert_eq!(piped, b"a\x1b]0;t\x07b\n");
    }

    #[test]
    fn write_line_appends_a_newline_and_reports_success() {
        let mut buf = Vec::new();
        assert!(write_line(&mut buf, "Available models:"));
        assert_eq!(buf, "Available models:\n".as_bytes());
    }

    #[test]
    fn write_fmt_renders_arguments_once() {
        let mut buf = Vec::new();
        let name = "flux-auto";
        assert_eq!(
            write_fmt(&mut buf, format_args!("  * {name} (default)\n")),
            Outcome::Written
        );
        assert_eq!(buf, "  * flux-auto (default)\n".as_bytes());
    }

    /// Closing the read end makes every write fail with EPIPE: the pipe `fuigo models | head`
    /// leaves behind, or the parent that exited. SIGPIPE is ignored in Rust binaries, so the
    /// write returns an error; `println!` would panic here and `panic = "abort"` would SIGABRT.
    #[test]
    fn a_dead_pipe_is_reader_gone_not_a_panic() {
        let (reader, mut writer) = std::io::pipe().expect("pipe");
        drop(reader);
        assert_eq!(
            write_fmt(&mut writer, format_args!("You are not authenticated.\n")),
            Outcome::ReaderGone
        );
        assert!(!write_line(&mut writer, "Available models:"));
    }

    /// A writer that fails `refusals` times with `kind` before accepting bytes three at a time.
    struct Flaky {
        kind: std::io::ErrorKind,
        refusals: u32,
        seen: Vec<u8>,
        flush_refusals: u32,
    }

    impl Flaky {
        fn new(kind: std::io::ErrorKind, refusals: u32) -> Self {
            Self {
                kind,
                refusals,
                seen: Vec::new(),
                flush_refusals: 0,
            }
        }
    }

    impl Write for Flaky {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.refusals > 0 {
                self.refusals -= 1;
                return Err(self.kind.into());
            }
            // Short writes exercise the remaining-bytes loop.
            let n = buf.len().min(3);
            self.seen.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            if self.flush_refusals > 0 {
                self.flush_refusals -= 1;
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            Ok(())
        }
    }

    /// A tty left non-blocking by a Node/Electron parent answers `WouldBlock` for a while;
    /// the line still lands, in order, with no byte written twice.
    #[test]
    fn would_block_is_retried_and_short_writes_complete_the_line() {
        let mut w = Flaky::new(std::io::ErrorKind::WouldBlock, 3);
        w.flush_refusals = 2;
        assert_eq!(
            write_bytes(&mut w, b"Default model: flux-auto\n"),
            Outcome::Written
        );
        assert_eq!(w.seen, b"Default model: flux-auto\n");
    }

    #[test]
    fn would_block_beyond_the_budget_is_a_hard_failure_not_a_panic() {
        let mut w = Flaky::new(std::io::ErrorKind::WouldBlock, u32::MAX);
        assert_eq!(write_bytes(&mut w, b"never\n"), Outcome::Failed);
        assert!(w.seen.is_empty());
    }

    /// `EIO` (a hung-up tty) and `ENOSPC` are not a gone reader: they are reported as failures
    /// so the binary can exit non-zero instead of claiming complete output.
    #[test]
    fn other_io_errors_are_hard_failures() {
        for kind in [
            std::io::ErrorKind::Other,
            std::io::ErrorKind::StorageFull,
            std::io::ErrorKind::WriteZero,
        ] {
            let mut w = Flaky::new(kind, u32::MAX);
            assert_eq!(write_bytes(&mut w, b"x\n"), Outcome::Failed, "{kind:?}");
        }
    }

    /// `Interrupted` is transparently retried, like `write_all` does.
    #[test]
    fn interrupted_is_retried_without_counting_against_the_budget() {
        let mut w = Flaky::new(std::io::ErrorKind::Interrupted, 100);
        assert_eq!(write_bytes(&mut w, b"ok\n"), Outcome::Written);
        assert_eq!(w.seen, b"ok\n");
    }

    /// The macros type as `()` so they fit every statement and match-arm position `println!`
    /// held, and they compile with no arguments, a literal, and format arguments. Writing to
    /// the test harness's stdout is fine: it is live, so no flag flips.
    #[test]
    fn macros_type_as_unit() {
        let unit: () = crate::cli_println!();
        let also: () = crate::cli_println!("literal");
        let n = 3;
        let third: () = crate::cli_println!("{} model(s), {n}", n);
        let fourth: () = crate::cli_print!("{}", "no newline\n");
        let _ = (unit, also, third, fourth);
    }

    #[test]
    fn classify_separates_a_gone_reader_from_everything_else() {
        assert_eq!(
            classify(&std::io::ErrorKind::BrokenPipe.into()),
            Outcome::ReaderGone
        );
        assert_eq!(classify(&std::io::ErrorKind::Other.into()), Outcome::Failed);
        assert_eq!(
            classify(&std::io::ErrorKind::WouldBlock.into()),
            Outcome::Failed
        );
    }
}
