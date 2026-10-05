//! Cross-platform crash handler with startup crash detection.
//!
//! - **Unix**: SIGBUS/SIGSEGV/SIGABRT via `sigaction(2)`. SIGABRT capture
//!   means `panic = "abort"` builds (every shipped release) leave a crash
//!   report when a Rust panic aborts the process.
//! - **Windows**: access violations via `SetUnhandledExceptionFilter`.
//!   SIGABRT capture is Unix-only — `abort()` on Windows does not route
//!   through the unhandled-exception filter.
//!
//! # Crash slots
//!
//! Each process writes into its own slot, `crash_dir/crash-<pid>-<start>.bin`
//! (`<start>` is the OS process start-time token), opened at [`install`]
//! and filled only if the process dies of a fatal signal. A clean exit
//! deletes the empty slot (Unix: `atexit`); empty slots of dead owners left
//! by a kill or a Windows exit are removed by the next startup's
//! [`sweep_dead_slots`] or [`check_previous_crashes`]. Only slots whose
//! owner is provably dead — a pid that is gone, or now belongs to a process
//! with a different start time — are ever touched, so concurrent sessions
//! never read, truncate or delete each other's evidence. A dead owner's
//! blob is claimed by an atomic rename (two sessions starting together
//! report it once) and deleted only after its report is safely on disk.
//!
//! Everything stays local: the crate has no network code. Reports are
//! written owner-only under `crash_dir`.
//!
//! # Usage
//!
//! ```rust,no_run
//! use std::path::PathBuf;
//!
//! let crash_dir = PathBuf::from("/home/user/.myapp/crash");
//!
//! let reports = fuigo_crash_handler::check_previous_crashes(&crash_dir, "0.1.0");
//! if let Some(notice) = fuigo_crash_handler::startup_notice(&reports) {
//!     eprintln!("{notice}");
//! }
//!
//! fuigo_crash_handler::install(fuigo_crash_handler::CrashHandlerConfig {
//!     app_version: "0.1.0".to_string(),
//!     crash_dir: crash_dir.clone(),
//! });
//! ```

pub mod format;
mod handler;
pub mod image;
pub mod panic_info;
pub mod process;
pub mod symbolicate;
pub mod terminal;

use std::path::{Path, PathBuf};

pub use format::{CrashKind, PanicClass};
pub use symbolicate::{ResolvedFrame, Symbolication};

/// Archived reports kept under `crash_dir/history/`.
const MAX_HISTORY: usize = 10;
/// Upper bound on owner checks per startup (bounded work even if the
/// directory fills up). Entries are streamed, not collected; only names that
/// are ours (slots, claims, the legacy slot) count, so unrelated files can
/// never use the budget up, and live slots number at most the sessions
/// running right now.
const MAX_OWNER_CHECKS: usize = 4096;
/// Upper bound on crash reports produced per startup.
const MAX_REPORTS_PER_SCAN: usize = 32;
/// The single fixed slot written by builds before per-process slots.
const LEGACY_SLOT: &str = "last-crash.bin";
const CLAIM_INFIX: &str = ".claim-";

/// Configuration for the crash handler.
pub struct CrashHandlerConfig {
    /// Application version string (e.g. "0.1.169-alpha.2").
    pub app_version: String,
    /// Directory where crash dumps are written.
    /// Created if it does not exist.
    pub crash_dir: PathBuf,
}

/// Information about a crash from an earlier session.
#[derive(Debug)]
pub struct CrashReport {
    /// Human-readable signal name (e.g. "SIGBUS (Bus error)").
    pub signal_name: &'static str,
    /// The `si_code` from `siginfo_t`.
    pub si_code: i32,
    /// The faulting memory address.
    pub faulting_address: u64,
    /// Unix timestamp of the crash.
    pub timestamp: u64,
    /// Pid of the crashed process.
    pub pid: u32,
    /// Application version at crash time.
    pub app_version: String,
    /// Panic, stack overflow, or raw signal.
    pub kind: CrashKind,
    /// Panic classification (benign classes are user-environment noise).
    pub class: PanicClass,
    /// Panicking thread's name (sanitized), for panics.
    pub thread_name: Option<String>,
    /// One-line description ("Rust panic on thread 'main'", ...).
    pub summary: String,
    /// User-environment noise (broken pipe, disk full): the report is kept
    /// but no "crashed" notice should be shown.
    pub benign: bool,
    /// Symbolicated backtrace frames.
    pub backtrace: Vec<ResolvedFrame>,
    /// How symbolication went.
    pub symbolication: Symbolication,
    /// Path to the saved human-readable crash report.
    pub report_path: PathBuf,
}

/// Install the crash handler for SIGBUS, SIGSEGV, and SIGABRT (Unix; on
/// Windows only access violations are captured).
///
/// Must be called early in `main()`, before any async runtime or thread
/// spawning. Creates `crash_dir` if it does not exist, opens this process's
/// own slot, records the main image's base/extent/identity for later
/// symbolication, and installs a panic hook (chained in front of the
/// existing one) that classifies panics before `abort`.
///
/// Returns `true` if the handler was installed successfully.
/// On unsupported platforms, this is a no-op that returns `false`.
pub fn install(config: CrashHandlerConfig) -> bool {
    handler::install(&config.crash_dir, &config.app_version)
}

/// The slot file this process installed, if any.
pub fn installed_slot_path() -> Option<PathBuf> {
    handler::installed_slot_path()
}

/// Close and delete this process's (empty) slot. Called automatically at a
/// clean exit on Unix; safe to call more than once.
pub fn release_slot() {
    handler::release_slot()
}

/// Install a minimal SIGSEGV/SIGBUS/SIGABRT handler that only restores the
/// terminal.
///
/// On Unix, saves the current termios state, allocates an alternate signal
/// stack, and registers a handler that writes terminal restore escape
/// sequences to stderr, restores termios, then re-raises with default
/// disposition (preserving core dumps).
///
/// On Windows, registers an unhandled-exception filter that writes restore
/// sequences; no termios equivalent.
///
/// No-op on unsupported platforms.
///
/// No crash reporting (no file I/O, no stack walking). If [`install`] is
/// called later, it replaces these handlers with full crash-reporting
/// variants.
pub fn install_terminal_restore_only() {
    handler::install_terminal_restore_only()
}

/// Upgrade SIGSEGV/SIGBUS/SIGABRT handlers to include terminal escape code
/// restoration. Call when TUI modes are enabled.
pub fn enable_terminal_escape_restore() {
    handler::enable_terminal_escape_restore()
}

/// Downgrade SIGSEGV/SIGBUS/SIGABRT handlers to termios-only restoration.
/// Call when TUI modes are disabled.
pub fn disable_terminal_escape_restore() {
    handler::disable_terminal_escape_restore()
}

/// File name of the slot owned by process `pid` started at `token`.
pub fn slot_file_name(pid: u32, token: u64) -> String {
    format!("crash-{pid}-{token}.bin")
}

/// Inverse of [`slot_file_name`].
pub fn parse_slot_file_name(name: &str) -> Option<(u32, u64)> {
    let inner = name.strip_prefix("crash-")?.strip_suffix(".bin")?;
    let (pid, token) = inner.split_once('-')?;
    let all_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !all_digits(pid) || !all_digits(token) {
        return None;
    }
    Some((pid.parse().ok()?, token.parse().ok()?))
}

/// `<original>.claim-<claimer pid>-<claimer start token>` → (original, pid, token).
fn parse_claim_name(name: &str) -> Option<(&str, u32, u64)> {
    let (orig, claimer) = name.rsplit_once(CLAIM_INFIX)?;
    let (pid, token) = claimer.split_once('-')?;
    let pid: u32 = pid.parse().ok()?;
    let token: u64 = token.parse().ok()?;
    if orig == LEGACY_SLOT || parse_slot_file_name(orig).is_some() {
        Some((orig, pid, token))
    } else {
        None
    }
}

fn claim_file_name(original: &str, pid: u32, token: u64) -> String {
    format!("{original}{CLAIM_INFIX}{pid}-{token}")
}

/// Names this crate owns in the crash dir.
fn is_crash_entry(name: &str) -> bool {
    name == LEGACY_SLOT || parse_slot_file_name(name).is_some() || parse_claim_name(name).is_some()
}

/// What a crash-dir entry is, from the point of view of process `(me, my_token)`.
enum Entry<'a> {
    /// A slot or abandoned claim whose owner is provably dead; the payload
    /// is the slot's original file name.
    Dead(&'a str),
    /// A pre-1.0.21 `last-crash.bin`. Its owner is unknown (an old build may
    /// still hold it open), so only a written blob is ever claimed and an
    /// empty one is never deleted.
    Legacy,
    /// Live, our own, or not ours: never touched.
    Skip,
}

fn classify<'a>(name: &'a str, me: u32, my_token: u64) -> Entry<'a> {
    if name == LEGACY_SLOT {
        return Entry::Legacy;
    }
    if let Some((pid, token)) = parse_slot_file_name(name) {
        if (pid, token) == (me, my_token) {
            return Entry::Skip; // this process's own slot
        }
        // Alive and AliveUnverified are both left alone: age is never a
        // substitute for proof of death.
        return match process::owner_state(pid, token) {
            process::Owner::Dead => Entry::Dead(name),
            _ => Entry::Skip,
        };
    }
    if let Some((orig, pid, token)) = parse_claim_name(name) {
        // A reader that died mid-claim; its claim is up for grabs once that
        // reader (pid + start time, so a recycled pid does not pin it) is dead.
        if (pid, token) == (me, my_token) {
            return Entry::Skip;
        }
        return match process::owner_state(pid, token) {
            process::Owner::Dead => Entry::Dead(orig),
            _ => Entry::Skip,
        };
    }
    Entry::Skip
}

/// Remove empty slots (and empty abandoned claims) whose owner is dead —
/// what a SIGKILLed process or a Windows exit leaves behind. Never reads,
/// claims or deletes a written blob, and never touches a live slot, so it
/// is safe for every process (headless, editor child, leader) to run at
/// startup. Returns the number of files removed.
pub fn sweep_dead_slots(crash_dir: &Path) -> usize {
    let me = std::process::id();
    let my_token = process::start_token(me).unwrap_or(0);
    let Ok(entries) = std::fs::read_dir(crash_dir) else {
        return 0;
    };
    let mut removed = 0;
    let mut budget = MAX_OWNER_CHECKS;
    for entry in entries.filter_map(|e| e.ok()) {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !is_crash_entry(&name) {
            continue;
        }
        if budget == 0 {
            break;
        }
        budget -= 1;
        if !matches!(classify(&name, me, my_token), Entry::Dead(_)) {
            continue;
        }
        let path = entry.path();
        let empty = std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file() && m.len() == 0);
        if empty && std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Check for crashes from earlier sessions.
///
/// Streams `crash_dir` (bounded) for crash slots whose owner process is
/// provably dead, claims each one by atomic rename, symbolicates it, writes
/// a human-readable report under `crash_dir/history/` (and
/// `crash_dir/last-crash-report.txt`), and only then removes the blob. If
/// the report cannot be written the claim is put back for a later startup.
/// Empty slots of dead owners are removed silently. Slots of live processes
/// — including this one — are never touched.
///
/// `current_version` is this build's version; a crash from another version
/// is reported with raw module offsets instead of (wrong) symbols. Pass ""
/// to skip the version comparison (the binary identity is still checked).
///
/// Returns the reports newest first, benign ones included (see
/// [`CrashReport::benign`] and [`startup_notice`]).
pub fn check_previous_crashes(crash_dir: &Path, current_version: &str) -> Vec<CrashReport> {
    let me = std::process::id();
    let my_token = process::start_token(me).unwrap_or(0);
    let Ok(entries) = std::fs::read_dir(crash_dir) else {
        return Vec::new();
    };

    let mut local: Option<symbolicate::LocalImage<'_>> = None;
    let mut reports = Vec::new();
    let mut budget = MAX_OWNER_CHECKS;
    for entry in entries.filter_map(|e| e.ok()) {
        if reports.len() >= MAX_REPORTS_PER_SCAN || budget == 0 {
            break;
        }
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !is_crash_entry(&name) {
            continue;
        }
        budget -= 1;
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let original = match classify(&name, me, my_token) {
            Entry::Dead(orig) => orig.to_string(),
            // Only a written legacy blob is evidence.
            Entry::Legacy if meta.len() > 0 => name.clone(),
            Entry::Legacy | Entry::Skip => continue,
        };

        // Claim atomically: exactly one reader wins the rename.
        let claimed = crash_dir.join(claim_file_name(&original, me, my_token));
        if std::fs::rename(&path, &claimed).is_err() {
            continue;
        }
        let put_back = || {
            let _ = std::fs::rename(&claimed, crash_dir.join(&original));
        };
        let data = match std::fs::read(&claimed) {
            Ok(data) => data,
            Err(_) => {
                put_back();
                continue;
            }
        };
        let Some(blob) = format::CrashBlob::parse(&data) else {
            // Empty slot (a clean or SIGKILLed exit) or not a crash blob.
            let _ = std::fs::remove_file(&claimed);
            continue;
        };
        let local = local.get_or_insert_with(|| symbolicate::LocalImage::current(current_version));
        match build_report(crash_dir, &blob, local) {
            Ok(report) => {
                let _ = std::fs::remove_file(&claimed);
                reports.push(report);
            }
            // Keep the evidence: a later startup retries.
            Err(_) => put_back(),
        }
    }

    reports.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    if let Some(newest) = reports.first()
        && let Ok(text) = std::fs::read(&newest.report_path)
    {
        let _ = write_owner_only_atomic(&crash_dir.join("last-crash-report.txt"), &text);
    }
    // Never prune a report this scan produced: the notice names one of them.
    let keep: Vec<&Path> = reports.iter().map(|r| r.report_path.as_path()).collect();
    prune_history(crash_dir, &keep);
    reports
}

/// Check for a crash from the previous session; the newest report, if any.
///
/// Compatibility wrapper over [`check_previous_crashes`] without a version
/// comparison.
pub fn check_previous_crash(crash_dir: &Path) -> Option<CrashReport> {
    check_previous_crashes(crash_dir, "").into_iter().next()
}

fn build_report(
    crash_dir: &Path,
    blob: &format::CrashBlob,
    local: &symbolicate::LocalImage<'_>,
) -> std::io::Result<CrashReport> {
    let (frames, symbolication) = symbolicate::resolve_frames_with(blob, local);
    let report_text = symbolicate::format_report_with(blob, &frames, Some(symbolication));

    let history_dir = crash_dir.join("history");
    std::fs::create_dir_all(&history_dir)?;
    let report_path = history_dir.join(format!("crash-{}-{}.txt", blob.timestamp, blob.pid));
    write_owner_only_atomic(&report_path, report_text.as_bytes())?;

    Ok(CrashReport {
        signal_name: symbolicate::signal_name(blob.signal),
        si_code: blob.si_code,
        faulting_address: blob.si_addr,
        timestamp: blob.timestamp,
        pid: blob.pid,
        app_version: blob.app_version.clone(),
        kind: blob.kind,
        class: blob.class,
        thread_name: blob.thread_name.clone(),
        summary: symbolicate::describe(blob),
        benign: blob.kind == CrashKind::Panic && blob.class.is_benign(),
        backtrace: frames,
        symbolication,
        report_path,
    })
}

/// The startup notice for `reports` (newest first), or `None` when there is
/// nothing worth telling the user — no reports, or only benign ones (a
/// closed output pipe or a full disk is not a Fuigo crash; those reports
/// are still kept on disk).
pub fn startup_notice(reports: &[CrashReport]) -> Option<String> {
    let real: Vec<&CrashReport> = reports.iter().filter(|r| !r.benign).collect();
    let newest = real.first()?;
    let mut lines = Vec::new();
    if real.len() == 1 {
        lines.push("Fuigo crashed during your last session.".to_string());
    } else {
        lines.push(format!("Fuigo crashed in {} earlier sessions.", real.len()));
    }
    lines.push(format!("  What:    {}", newest.summary));
    lines.push(format!("  Version: {}", newest.app_version));
    lines.push(format!("  Report:  {}", newest.report_path.display()));
    if real.len() > 1
        && let Some(dir) = newest.report_path.parent()
    {
        lines.push(format!("  Others:  {}", dir.display()));
    }
    lines.push("  The report stays on this computer; nothing was uploaded.".to_string());
    Some(lines.join("\n"))
}

/// Write `contents` with owner-only permissions when the platform allows it.
///
/// Crash reports may include source paths and backtraces; when they land under
/// `$FUIGO_HOME` they must not be world-readable.
fn write_owner_only(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        // mode() only applies on create — force owner-only before writing so a
        // preexisting 0644 file never holds sensitive content while world-readable.
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o600);
        file.set_permissions(perms)?;
        file.write_all(contents)?;
        file.flush()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}

/// [`write_owner_only`] to a temporary sibling, then rename into place, so a
/// reader never sees (and the notice never names) a half-written report.
fn write_owner_only_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| std::io::Error::other("report path has no file name"))?;
    let tmp = path.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()));
    let result = write_owner_only(&tmp, contents).and_then(|()| std::fs::rename(&tmp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// A report younger than this is never pruned: another session may have
/// just written it and be about to name it in its notice.
const HISTORY_PRUNE_GRACE: std::time::Duration = std::time::Duration::from_secs(3600);

/// Keep the newest [`MAX_HISTORY`] reports, every path in `keep`, and every
/// report younger than [`HISTORY_PRUNE_GRACE`] (written by a concurrent reader).
fn prune_history(crash_dir: &Path, keep: &[&Path]) {
    let history_dir = crash_dir.join("history");
    if let Ok(entries) = std::fs::read_dir(&history_dir) {
        let mut files: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "txt"))
            .collect();
        files.sort();
        if files.len() > MAX_HISTORY {
            for old in &files[..files.len() - MAX_HISTORY] {
                let fresh = std::fs::metadata(old)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_none_or(|age| age < HISTORY_PRUNE_GRACE);
                if !keep.contains(&old.as_path()) && !fresh {
                    let _ = std::fs::remove_file(old);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_previous_crash_returns_none_when_no_file() {
        let dir = PathBuf::from("/tmp/fuigo-crash-handler-test-nonexistent");
        assert!(check_previous_crash(&dir).is_none());
    }

    #[cfg(unix)]
    fn unique_tmp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fuigo-crash-handler-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("create tmp dir");
        dir
    }

    #[cfg(unix)]
    fn blob_v2(pid: u32, kind: CrashKind, class: PanicClass, thread: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; format::MAX_FILE_SIZE];
        let id = [0u8; format::BUILD_ID_LEN];
        let n = unsafe {
            let off = format::writer::write_header(
                &mut buf,
                &format::RawHeader {
                    signal: 6,
                    si_code: 0,
                    si_addr: 0,
                    pid,
                    timestamp: 1_800_000_000,
                    n_frames: 1,
                    app_version: b"test",
                    kind: kind.to_u8(),
                    class: class.to_u8(),
                    image_base: 0,
                    image_lo: 0,
                    image_hi: 0,
                    build_id: &id,
                    exe_len: 0,
                    start_token: 0,
                    thread_name: thread,
                },
            );
            format::writer::write_frame(&mut buf, off, 0x1234)
        };
        buf.truncate(n);
        buf
    }

    #[cfg(unix)]
    #[allow(clippy::disallowed_methods)] // `true` is waited on immediately
    fn dead_pid() -> u32 {
        let mut c = std::process::Command::new("true").spawn().expect("spawn");
        let pid = c.id();
        c.wait().expect("wait");
        pid
    }

    #[test]
    fn slot_names_round_trip_and_reject_lookalikes() {
        assert_eq!(slot_file_name(42, 7), "crash-42-7.bin");
        assert_eq!(parse_slot_file_name("crash-42-7.bin"), Some((42, 7)));
        for bad in [
            "last-crash.bin",
            "crash-42.bin",
            "crash-42-7.bin.claim-9",
            "crash--7.bin",
            "crash-4x-7.bin",
            "crash-42-7-1.bin",
            "crash-1712678587.txt",
        ] {
            assert_eq!(parse_slot_file_name(bad), None, "{bad}");
        }
        assert_eq!(
            parse_claim_name(&claim_file_name("crash-42-7.bin", 9, 11)),
            Some(("crash-42-7.bin", 9, 11))
        );
        assert_eq!(
            parse_claim_name("last-crash.bin.claim-9-0"),
            Some(("last-crash.bin", 9, 0))
        );
        assert_eq!(parse_claim_name("crash-42-7.bin.claim-9"), None, "no token");
        assert_eq!(parse_claim_name("notes.txt.claim-9-1"), None);
    }

    #[cfg(unix)]
    #[test]
    fn live_slot_is_never_touched() {
        let dir = unique_tmp_dir("live-slot");
        let me = std::process::id();
        let token = process::start_token(me).unwrap_or(0);
        // Another live session's slot: use this test process's identity but
        // a different file than the reader skips as "own" — the parent pid.
        let ppid = std::os::unix::process::parent_id();
        let ptoken = process::start_token(ppid).unwrap_or(0);
        let live = dir.join(slot_file_name(ppid, ptoken));
        std::fs::write(
            &live,
            blob_v2(ppid, CrashKind::Signal, PanicClass::None, b""),
        )
        .expect("seed");
        let own = dir.join(slot_file_name(me, token));
        std::fs::write(&own, b"").expect("seed own");
        let reports = check_previous_crashes(&dir, "");
        assert!(
            reports.is_empty(),
            "live slots are not reports: {reports:?}"
        );
        assert!(live.exists(), "a live session's slot must stay");
        assert_eq!(
            std::fs::read(&live).expect("read").len(),
            blob_v2(ppid, CrashKind::Signal, PanicClass::None, b"").len()
        );
        assert!(own.exists(), "the reader's own slot must stay");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn dead_slot_is_reported_once_and_archived() {
        let dir = unique_tmp_dir("dead-slot");
        let pid = dead_pid();
        let slot = dir.join(slot_file_name(pid, 99));
        std::fs::write(
            &slot,
            blob_v2(pid, CrashKind::Signal, PanicClass::None, b""),
        )
        .expect("seed");
        let empty = dir.join(slot_file_name(pid, 98));
        std::fs::write(&empty, b"").expect("seed empty");

        let reports = check_previous_crashes(&dir, "");
        assert_eq!(reports.len(), 1, "{reports:?}");
        assert_eq!(reports[0].pid, pid);
        assert!(reports[0].report_path.starts_with(dir.join("history")));
        assert!(reports[0].report_path.exists());
        assert!(dir.join("last-crash-report.txt").exists());
        assert!(!slot.exists(), "blob consumed");
        assert!(!empty.exists(), "dead owner's empty slot swept");
        assert!(check_previous_crashes(&dir, "").is_empty(), "reported once");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn recycled_pid_slot_is_treated_as_dead() {
        let dir = unique_tmp_dir("pid-reuse");
        // The pid is alive (it is this process), but the start time in the
        // name is not this process's: the original owner is gone.
        let me = std::process::id();
        let token = process::start_token(me).expect("token");
        let slot = dir.join(slot_file_name(me, token.wrapping_add(1)));
        std::fs::write(&slot, blob_v2(me, CrashKind::Signal, PanicClass::None, b"")).expect("seed");
        let reports = check_previous_crashes(&dir, "");
        assert_eq!(
            reports.len(),
            1,
            "pid reuse must not hide a dead owner's crash"
        );
        assert!(!slot.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn old_format_blobs_are_reported_without_symbols() {
        let dir = unique_tmp_dir("legacy");
        let v1 =
            format::writer::encode_v1(11, 1, 0x10, 4242, 1_700_000_000, b"1.0.20", &[0x5555_1234]);
        std::fs::write(dir.join(LEGACY_SLOT), &v1).expect("seed legacy");
        let pid = dead_pid();
        std::fs::write(dir.join(slot_file_name(pid, 5)), &v1).expect("seed v1 slot");
        let reports = check_previous_crashes(&dir, "1.0.21");
        assert_eq!(reports.len(), 2, "{reports:?}");
        for r in &reports {
            assert_eq!(r.symbolication, Symbolication::LegacyFormat);
            assert_eq!(r.app_version, "1.0.20");
            assert!(r.backtrace.iter().all(|f| f.symbol_name.is_none()));
            assert!(!r.benign);
            let text = std::fs::read_to_string(&r.report_path).expect("report");
            assert!(text.contains("0x0000000055551234"), "{text}");
            assert!(text.contains("old report format"), "{text}");
        }
        assert!(!dir.join(LEGACY_SLOT).exists());
        // An EMPTY legacy slot may be a live old build's: left alone.
        std::fs::write(dir.join(LEGACY_SLOT), b"").expect("seed empty legacy");
        assert!(check_previous_crashes(&dir, "").is_empty());
        assert!(dir.join(LEGACY_SLOT).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn abandoned_claim_is_recovered() {
        let dir = unique_tmp_dir("claim");
        let reader = dead_pid();
        let owner = dead_pid();
        let name = claim_file_name(&slot_file_name(owner, 3), reader, 77);
        std::fs::write(
            dir.join(&name),
            blob_v2(owner, CrashKind::Signal, PanicClass::None, b""),
        )
        .expect("seed");
        let reports = check_previous_crashes(&dir, "");
        assert_eq!(reports.len(), 1);
        let left: Vec<String> = std::fs::read_dir(&dir)
            .expect("ls")
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.contains(".bin"))
            .collect();
        assert!(left.is_empty(), "claim consumed: {left:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn claim_of_a_recycled_reader_pid_is_recovered() {
        let dir = unique_tmp_dir("claim-reuse");
        // The claimer pid is alive (this process) but with another start
        // time: the reader that made the claim is gone.
        let me = std::process::id();
        let token = process::start_token(me).expect("token");
        let owner = dead_pid();
        let name = claim_file_name(&slot_file_name(owner, 3), me, token.wrapping_add(1));
        std::fs::write(
            dir.join(&name),
            blob_v2(owner, CrashKind::Signal, PanicClass::None, b""),
        )
        .expect("seed");
        assert_eq!(check_previous_crashes(&dir, "").len(), 1);
        assert!(!dir.join(&name).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn unverified_live_slot_is_kept_however_old() {
        let dir = unique_tmp_dir("aged-live");
        // Token 0 = the owner recorded no start time: alive but unverified.
        let ppid = std::os::unix::process::parent_id();
        let slot = dir.join(slot_file_name(ppid, 0));
        std::fs::write(&slot, b"").expect("seed");
        let old = libc::timeval {
            tv_sec: 1_000_000_000,
            tv_usec: 0,
        };
        let c = std::ffi::CString::new(slot.to_str().expect("utf8")).expect("cstr");
        assert_eq!(unsafe { libc::utimes(c.as_ptr(), [old, old].as_ptr()) }, 0);
        assert!(check_previous_crashes(&dir, "").is_empty());
        assert_eq!(sweep_dead_slots(&dir), 0);
        assert!(slot.exists(), "age must never stand in for proof of death");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn sweep_removes_only_empty_dead_slots() {
        let dir = unique_tmp_dir("sweep");
        let pid = dead_pid();
        let empty_dead = dir.join(slot_file_name(pid, 1));
        std::fs::write(&empty_dead, b"").expect("seed");
        let written_dead = dir.join(slot_file_name(pid, 2));
        std::fs::write(
            &written_dead,
            blob_v2(pid, CrashKind::Signal, PanicClass::None, b""),
        )
        .expect("seed");
        let ppid = std::os::unix::process::parent_id();
        let live = dir.join(slot_file_name(
            ppid,
            process::start_token(ppid).unwrap_or(0),
        ));
        std::fs::write(&live, b"").expect("seed");
        std::fs::write(dir.join(LEGACY_SLOT), b"").expect("seed");
        assert_eq!(sweep_dead_slots(&dir), 1);
        assert!(!empty_dead.exists());
        assert!(
            written_dead.exists(),
            "evidence is left for an interactive session"
        );
        assert!(live.exists());
        assert!(dir.join(LEGACY_SLOT).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn announced_report_survives_history_pruning() {
        let dir = unique_tmp_dir("prune");
        // One older real crash and MAX_HISTORY+1 newer benign ones in one backlog.
        let real = dead_pid();
        let mut real_blob = blob_v2(real, CrashKind::Panic, PanicClass::None, b"main");
        real_blob[22..30].copy_from_slice(&1_700_000_000u64.to_le_bytes());
        std::fs::write(dir.join(slot_file_name(real, 1)), &real_blob).expect("seed");
        for i in 0..(MAX_HISTORY as u64 + 1) {
            let mut b = blob_v2(
                4_000_000 + i as u32,
                CrashKind::Panic,
                PanicClass::BenignBrokenPipe,
                b"main",
            );
            b[22..30].copy_from_slice(&(1_800_000_000u64 + i).to_le_bytes());
            std::fs::write(dir.join(slot_file_name(real, 100 + i)), &b).expect("seed");
        }
        let reports = check_previous_crashes(&dir, "");
        assert_eq!(reports.len(), MAX_HISTORY + 2);
        let notice = startup_notice(&reports).expect("the real crash is announced");
        let real_report = reports.iter().find(|r| !r.benign).expect("real");
        assert!(notice.contains(&real_report.report_path.display().to_string()));
        assert!(
            real_report.report_path.exists(),
            "an announced report must exist"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_readers_fresh_report_is_not_pruned() {
        let dir = unique_tmp_dir("prune-race");
        let history = dir.join("history");
        std::fs::create_dir_all(&history).expect("mkdir");
        let set_old = |p: &Path| {
            let t = libc::timeval {
                tv_sec: 1_000_000_000,
                tv_usec: 0,
            };
            let c = std::ffi::CString::new(p.to_str().expect("utf8")).expect("cstr");
            assert_eq!(unsafe { libc::utimes(c.as_ptr(), [t, t].as_ptr()) }, 0);
        };
        // MAX_HISTORY old archived reports with newer names, and one report
        // another reader just wrote (older crash time, fresh file).
        for i in 0..MAX_HISTORY {
            let p = history.join(format!("crash-18000000{i:02}-1.txt"));
            std::fs::write(&p, b"old").expect("seed");
            set_old(&p);
        }
        let theirs = history.join("crash-1700000000-2.txt");
        std::fs::write(&theirs, b"theirs").expect("seed");
        // This reader finds nothing new, but still prunes.
        assert!(check_previous_crashes(&dir, "").is_empty());
        assert!(
            theirs.exists(),
            "another reader's fresh report must survive pruning"
        );
        // Once it is old, normal retention applies.
        set_old(&theirs);
        check_previous_crashes(&dir, "");
        assert!(!theirs.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn evidence_survives_a_failed_report_write() {
        let dir = unique_tmp_dir("persist");
        let pid = dead_pid();
        let slot = dir.join(slot_file_name(pid, 4));
        let blob = blob_v2(pid, CrashKind::Signal, PanicClass::None, b"");
        std::fs::write(&slot, &blob).expect("seed");
        // A file where the history directory should be: the report cannot be written.
        std::fs::write(dir.join("history"), b"").expect("block history");
        assert!(check_previous_crashes(&dir, "").is_empty());
        assert_eq!(std::fs::read(&slot).expect("blob put back"), blob);
        std::fs::remove_file(dir.join("history")).expect("unblock");
        let reports = check_previous_crashes(&dir, "");
        assert_eq!(reports.len(), 1, "a later startup reports it");
        assert!(reports[0].report_path.exists());
        assert!(!slot.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn benign_panics_are_kept_but_not_announced() {
        let dir = unique_tmp_dir("benign");
        let pid = dead_pid();
        std::fs::write(
            dir.join(slot_file_name(pid, 1)),
            blob_v2(pid, CrashKind::Panic, PanicClass::BenignBrokenPipe, b"main"),
        )
        .expect("seed");
        let reports = check_previous_crashes(&dir, "");
        assert_eq!(reports.len(), 1);
        assert!(reports[0].benign);
        assert_eq!(reports[0].thread_name.as_deref(), Some("main"));
        assert!(
            reports[0].report_path.exists(),
            "benign reports are still kept"
        );
        assert!(
            startup_notice(&reports).is_none(),
            "no notice for a broken pipe"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn notice_names_the_local_report_and_says_nothing_uploaded() {
        let dir = unique_tmp_dir("notice");
        let (a, b) = (dead_pid(), dead_pid());
        std::fs::write(
            dir.join(slot_file_name(a, 1)),
            blob_v2(
                a,
                CrashKind::Panic,
                PanicClass::None,
                b"tokio-runtime-worker",
            ),
        )
        .expect("seed");
        std::fs::write(
            dir.join(slot_file_name(b, 1)),
            blob_v2(b, CrashKind::Panic, PanicClass::BenignNoSpace, b"main"),
        )
        .expect("seed");
        let reports = check_previous_crashes(&dir, "");
        let notice = startup_notice(&reports).expect("one real crash");
        assert!(
            notice.starts_with("Fuigo crashed during your last session."),
            "{notice}"
        );
        assert!(
            notice.contains("Rust panic on thread 'tokio-runtime-worker'"),
            "{notice}"
        );
        assert!(
            notice.contains(&dir.join("history").display().to_string()),
            "{notice}"
        );
        assert!(notice.contains("nothing was uploaded"), "{notice}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_owner_only_creates_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = unique_tmp_dir("create-0600");
        let path = dir.join("report.txt");
        write_owner_only(&path, b"secret").expect("write");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "new file must be owner-only");
        assert_eq!(std::fs::read(&path).expect("read"), b"secret");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_owner_only_tightens_preexisting_0644() {
        use std::os::unix::fs::PermissionsExt;

        let dir = unique_tmp_dir("tighten-0644");
        let path = dir.join("report.txt");
        std::fs::write(&path, b"old").expect("seed");
        let mut perms = std::fs::metadata(&path).expect("meta").permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms).expect("set 0644");
        assert_eq!(
            std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777,
            0o644
        );

        write_owner_only(&path, b"new-secret").expect("overwrite");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "overwrite must tighten to owner-only");
        assert_eq!(std::fs::read(&path).expect("read"), b"new-secret");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
