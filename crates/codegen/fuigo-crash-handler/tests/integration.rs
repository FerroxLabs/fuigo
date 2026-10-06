//! Integration tests for fuigo-crash-handler.
//!
//! These tests verify that installing the crash handler does not interfere
//! with normal program operation (tokio runtime, signal handling),
//! and that it correctly captures crash data when a fatal signal fires.
//!
//! Tests that send fatal signals use subprocess isolation: the test process
//! re-executes itself with an env var that selects the crash scenario, so
//! the parent can verify outcomes without dying.
// Test, bench or example code: its prints reach a harness or a developer, never a user, so the
// workspace print deny (R077) is waived here.
#![allow(clippy::print_stdout, clippy::print_stderr)]
#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use fuigo_crash_handler::format::CrashBlob;
use fuigo_crash_handler::{CrashKind, PanicClass, Symbolication};

fn scenario_command(scenario: &str, crash_dir: &Path) -> Command {
    let exe = std::env::current_exe().expect("current_exe");
    let mut cmd = Command::new(exe);
    cmd.env("CRASH_TEST_SCENARIO", scenario)
        .env("CRASH_TEST_DIR", crash_dir.as_os_str())
        .arg("--ignored")
        .arg("--exact")
        .arg("--nocapture")
        .arg("subprocess_entry");
    cmd
}

/// Re-invoke the current test binary as a subprocess with the given scenario.
/// Returns (exit status, stdout, stderr, pid).
// Test children are waited on (or killed by their own crash) before the test returns.
#[allow(clippy::disallowed_methods)]
fn run_scenario_pid(
    scenario: &str,
    crash_dir: &Path,
) -> (std::process::ExitStatus, String, String, u32) {
    let child = scenario_command(scenario, crash_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn subprocess");
    let pid = child.id();
    let output = child.wait_with_output().expect("wait");
    (
        output.status,
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        pid,
    )
}

fn run_scenario(scenario: &str, crash_dir: &Path) -> (std::process::ExitStatus, String, String) {
    let (status, out, err, _) = run_scenario_pid(scenario, crash_dir);
    (status, out, err)
}

/// The slot file(s) a given process left in `dir`.
fn slots_of(dir: &Path, pid: u32) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .and_then(fuigo_crash_handler::parse_slot_file_name)
                        .is_some_and(|(owner, _)| owner == pid)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The single slot `pid` left behind, parsed.
fn crash_blob_of(dir: &Path, pid: u32) -> (PathBuf, CrashBlob) {
    let slots = slots_of(dir, pid);
    assert_eq!(slots.len(), 1, "exactly one slot for pid {pid}: {slots:?}");
    let data = std::fs::read(&slots[0]).expect("read crash slot");
    let blob = CrashBlob::parse(&data).expect("crash blob should parse");
    (slots[0].clone(), blob)
}

/// Start a scenario that installs, prints READY on stderr, then waits for a
/// line on stdin before continuing.
#[allow(clippy::disallowed_methods)] // waited on by every caller
fn spawn_waiting(scenario: &str, crash_dir: &Path) -> Child {
    let mut child = scenario_command(scenario, crash_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let stderr = child.stderr.take().expect("stderr");
    let mut lines = BufReader::new(stderr).lines();
    loop {
        match lines.next() {
            Some(Ok(l)) if l.contains("READY") => break,
            Some(Ok(_)) => continue,
            other => panic!("child exited before READY: {other:?}"),
        }
    }
    // Keep draining stderr so the child never blocks on a full pipe.
    std::thread::spawn(move || for _ in lines {});
    child
}

fn release(child: &mut Child) {
    let mut stdin = child.stdin.take().expect("stdin");
    stdin.write_all(b"go\n").expect("write");
    drop(stdin);
}

fn aslr_enabled() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/randomize_va_space")
        .map(|s| s.trim() != "0")
        .unwrap_or(true)
}

// ── Crash sites with distinctive names ─────────────────────────────────

#[inline(never)]
fn p05a_marker_segv_site() {
    // A real invalid store (not raise()), emitted inline so the faulting PC
    // is inside this function; black_box hides the address from the optimizer.
    unsafe { *(std::hint::black_box(8usize) as *mut u8) = 1 };
}

#[inline(never)]
fn p05a_marker_abort_site() {
    std::process::abort();
}

#[inline(never)]
fn p05a_marker_panic_site(message: &str) -> ! {
    // The hook runs first (normal context), then abort — exactly the
    // sequence `panic = "abort"` produces in release builds. Test binaries
    // unwind, so the payload is caught and the abort made explicit on the
    // same thread.
    let message = message.to_string();
    let _ = std::panic::catch_unwind(move || panic!("{message}"));
    std::process::abort();
}

fn wait_for_go() {
    eprintln!("READY");
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
}

// ── Subprocess entry point ──────────────────────────────────────────────

/// This test is `#[ignore]`d so it only runs when invoked as a subprocess
/// by the parent test via `run_scenario`. The `CRASH_TEST_SCENARIO` env
/// var selects which scenario to execute.
#[test]
#[ignore]
fn subprocess_entry() {
    let scenario = match std::env::var("CRASH_TEST_SCENARIO") {
        Ok(s) => s,
        Err(_) => return, // not a subprocess invocation
    };
    let crash_dir = std::env::var("CRASH_TEST_DIR").expect("CRASH_TEST_DIR");
    let crash_dir = std::path::PathBuf::from(crash_dir);

    // Install the crash handler before anything else.
    let config = fuigo_crash_handler::CrashHandlerConfig {
        app_version: "0.0.0-test".to_string(),
        crash_dir,
    };
    fuigo_crash_handler::install(config);

    match scenario.as_str() {
        // Scenario 1: install handler, run tokio runtime with concurrent work, exit cleanly.
        "tokio_normal" => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async {
                // Spawn several concurrent tasks to stress the runtime.
                let mut handles = Vec::new();
                for i in 0..20 {
                    handles.push(tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                        i * i
                    }));
                }
                let mut sum = 0u64;
                for h in handles {
                    sum += h.await.unwrap();
                }
                // Also test signal infrastructure coexistence.
                // Register a tokio SIGTERM handler (same as the pager does).
                #[cfg(unix)]
                {
                    use tokio::signal::unix::{SignalKind, signal};
                    let _term = signal(SignalKind::terminate())
                        .expect("tokio SIGTERM handler should work alongside crash handler");
                }
                eprintln!("tokio_normal: sum={sum}, all tasks completed");
            });
        }

        // Scenario 2: install handler, do sync file I/O and computation, exit cleanly.
        "sync_normal" => {
            let tmp = tempfile::tempdir().expect("tempdir");
            for i in 0..50 {
                let path = tmp.path().join(format!("file-{i}.txt"));
                std::fs::write(&path, format!("contents {i}")).expect("write");
                let data = std::fs::read_to_string(&path).expect("read");
                assert!(data.contains(&format!("{i}")));
            }
            eprintln!("sync_normal: 50 files written and read back");
        }

        // Scenario 3: install handler, send ourselves SIGBUS, verify crash file written.
        "sigbus" => {
            // Give the handler a moment to be fully installed, then crash.
            unsafe { libc::raise(libc::SIGBUS) };
        }

        // Scenario 4: install handler, send ourselves SIGSEGV.
        "sigsegv" => {
            unsafe { libc::raise(libc::SIGSEGV) };
        }

        // Scenario 6: install handler, abort. This is the path every Rust
        // panic takes in release builds (panic = "abort" → SIGABRT).
        "sigabrt" => {
            std::process::abort();
        }

        // Recording stopped mid-session (the remote switch-off path): a later
        // crash leaves nothing behind.
        "release_then_segv" => {
            let slot = fuigo_crash_handler::installed_slot_path().expect("installed");
            assert!(slot.exists(), "install succeeded before the release");
            eprintln!("INSTALLED_BEFORE_RELEASE");
            fuigo_crash_handler::release_slot();
            p05a_marker_segv_site();
        }

        // A real invalid memory write in a named function.
        "segv_marker" => p05a_marker_segv_site(),
        "abort_marker" => p05a_marker_abort_site(),

        // Install, wait for the parent, then crash / exit.
        "wait_then_segv" => {
            wait_for_go();
            p05a_marker_segv_site();
        }
        "wait_then_exit" => {
            wait_for_go();
        }

        // Panics on a named worker thread, the hook classifies, abort follows.
        "panic_real" => {
            let h = std::thread::Builder::new()
                .name("p05a/worker\\x".into())
                .spawn(|| {
                    p05a_marker_panic_site("index out of bounds: the len is 3 but the index is 7")
                })
                .expect("spawn");
            let _ = h.join();
        }
        "panic_broken_pipe" => {
            p05a_marker_panic_site("failed printing to stdout: Broken pipe (os error 32)");
        }
        "panic_enospc" => {
            p05a_marker_panic_site("write log: No space left on device (os error 28)");
        }
        // A panic that was caught on one thread must not label an unrelated
        // abort on another thread as a panic.
        "caught_panic_then_abort_elsewhere" => {
            let _ = std::thread::Builder::new()
                .name("catcher".into())
                .spawn(|| std::panic::catch_unwind(|| panic!("Broken pipe")))
                .expect("spawn")
                .join();
            std::process::abort();
        }

        // Thread `first` records a benign panic and lingers; thread `second`
        // then panics (benign) and aborts. Each thread has its own record,
        // so the abort is still classified as `second`'s benign panic.
        "concurrent_benign_panics" => {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::Builder::new()
                .name("first".into())
                .spawn(move || {
                    let _ = std::panic::catch_unwind(|| panic!("write: Broken pipe (os error 32)"));
                    tx.send(()).expect("send");
                    loop {
                        std::thread::park();
                    }
                })
                .expect("spawn");
            rx.recv().expect("first recorded");
            let _ = std::thread::Builder::new()
                .name("second".into())
                .spawn(|| p05a_marker_panic_site("flush: Broken pipe (os error 32)"))
                .expect("spawn")
                .join();
        }

        // A forked child crashes and exits: the parent's slot must stay
        // intact and empty, and survive the child's exit.
        "fork_child_crash" => {
            let slot = fuigo_crash_handler::installed_slot_path().expect("slot");
            let crash_dir = slot.parent().expect("dir").to_path_buf();
            for mode in ["crash", "exit", "reinstall_exit", "reinstall_crash"] {
                let pid = unsafe { libc::fork() };
                if pid == 0 {
                    if mode.starts_with("reinstall") {
                        // The child installs its own slot. That must succeed,
                        // must not delete the inherited (parent's) slot, and
                        // the child's atexit / crash touch only its own slot.
                        let ok =
                            fuigo_crash_handler::install(fuigo_crash_handler::CrashHandlerConfig {
                                app_version: "0.0.0-child".to_string(),
                                crash_dir: crash_dir.clone(),
                            });
                        if !ok {
                            unsafe { libc::_exit(3) };
                        }
                    }
                    unsafe {
                        if mode.ends_with("crash") {
                            libc::raise(libc::SIGSEGV);
                        }
                        libc::exit(0);
                    }
                }
                let mut status = 0;
                unsafe { libc::waitpid(pid, &mut status, 0) };
                let how = if libc::WIFSIGNALED(status) {
                    format!("signal={}", libc::WTERMSIG(status))
                } else {
                    format!("exit={}", libc::WEXITSTATUS(status))
                };
                eprintln!("CHILD mode={mode} pid={pid} {how}");
            }
            let len = std::fs::metadata(&slot).map(|m| m.len());
            eprintln!("PARENT_SLOT_AFTER_FORKS={len:?}");
            // The parent's slot is still usable: its own crash lands there.
            p05a_marker_segv_site();
        }

        // Scenario 5: tokio runtime + signal coexistence, then clean shutdown.
        "tokio_signals" => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async {
                use tokio::signal::unix::{SignalKind, signal};
                let mut usr1 = signal(SignalKind::user_defined1()).expect("SIGUSR1 handler");

                // Send ourselves SIGUSR1 and verify tokio receives it
                // (proves our SIGBUS/SIGSEGV handler doesn't clobber other signals).
                unsafe { libc::raise(libc::SIGUSR1) };
                tokio::time::timeout(std::time::Duration::from_secs(2), usr1.recv())
                    .await
                    .expect("SIGUSR1 should arrive within 2s");

                eprintln!("tokio_signals: SIGUSR1 received, signal coexistence OK");
            });
        }

        other => {
            eprintln!("unknown scenario: {other}");
            std::process::exit(99);
        }
    }
}

// ── Parent test cases ───────────────────────────────────────────────────

#[test]
fn handler_does_not_interfere_with_tokio_runtime() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (status, _stdout, stderr) = run_scenario("tokio_normal", tmp.path());
    assert!(
        status.success(),
        "tokio_normal should exit 0, got {status:?}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("all tasks completed"),
        "should see completion message\nstderr: {stderr}"
    );
    // A clean exit removes the process's own (empty) slot.
    let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
        .expect("ls")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .collect();
    assert!(
        leftovers.is_empty(),
        "clean exit must leave no slot: {leftovers:?}"
    );
}

#[test]
fn handler_does_not_clobber_other_signal_handlers() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (status, _stdout, stderr) = run_scenario("tokio_signals", tmp.path());
    assert!(
        status.success(),
        "tokio_signals should exit 0, got {status:?}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("signal coexistence OK"),
        "SIGUSR1 should be delivered through tokio\nstderr: {stderr}"
    );
}

#[test]
fn sigbus_produces_valid_crash_blob() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (status, _stdout, _stderr, pid) = run_scenario_pid("sigbus", tmp.path());

    // Process should have been killed by a signal.
    // We expect SIGBUS, but the frame-pointer walker may hit unmapped memory
    // and cause a secondary SIGSEGV (SA_RESETHAND ensures it terminates).
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        let sig = status.signal();
        assert!(
            sig == Some(libc::SIGBUS) || sig == Some(libc::SIGSEGV),
            "process should be killed by SIGBUS or SIGSEGV, got signal={sig:?} status={status:?}"
        );
    }

    // The crash slot should be parseable.
    let (crash_file, blob) = crash_blob_of(tmp.path(), pid);

    // On macOS SIGBUS=10, on Linux SIGBUS=7, SIGSEGV=11 on both.
    // The frame-pointer walker may cause a secondary SIGSEGV.
    assert!(
        blob.signal == 7 || blob.signal == 10 || blob.signal == 11,
        "signal should be SIGBUS or SIGSEGV, got {}",
        blob.signal
    );
    assert_eq!(blob.app_version, "0.0.0-test");
    assert!(blob.pid > 0, "PID should be nonzero");
    assert!(blob.timestamp > 0, "timestamp should be nonzero");

    // check_previous_crash should produce a report.
    let report = fuigo_crash_handler::check_previous_crash(tmp.path())
        .expect("should produce a crash report");
    assert!(report.signal_name.contains("SIGBUS"));
    assert_eq!(report.app_version, "0.0.0-test");
    assert!(report.report_path.exists(), "report file should be written");

    // Crash blob should be consumed (deleted).
    assert!(
        !crash_file.exists(),
        "crash file should be deleted after processing"
    );
}

#[test]
fn sigsegv_produces_valid_crash_blob() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (status, _stdout, _stderr, pid) = run_scenario_pid("sigsegv", tmp.path());

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        let sig = status.signal();
        assert_eq!(
            sig,
            Some(libc::SIGSEGV),
            "process should be killed by SIGSEGV, got signal={sig:?} status={status:?}"
        );
    }

    let (_, blob) = crash_blob_of(tmp.path(), pid);
    assert_eq!(blob.signal, 11, "signal should be SIGSEGV (11)");
    assert_eq!(blob.pid, pid);
    assert_eq!(blob.app_version, "0.0.0-test");
}

#[test]
fn sigabrt_produces_valid_crash_blob() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (status, _stdout, _stderr, pid) = run_scenario_pid("sigabrt", tmp.path());

    // The handler must re-raise with default disposition so the process
    // still dies with SIGABRT semantics. The frame-pointer walker may hit
    // unmapped memory and cause a secondary SIGSEGV (as in the SIGBUS test).
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        let sig = status.signal();
        assert!(
            sig == Some(libc::SIGABRT) || sig == Some(libc::SIGSEGV),
            "process should be killed by SIGABRT (or a secondary SIGSEGV), got signal={sig:?} status={status:?}"
        );
    }

    let (crash_file, blob) = crash_blob_of(tmp.path(), pid);
    assert_eq!(
        blob.kind,
        CrashKind::Signal,
        "a bare abort() is not a panic"
    );
    assert_eq!(
        blob.signal, 6,
        "signal should be SIGABRT (6), got {}",
        blob.signal
    );
    assert_eq!(blob.app_version, "0.0.0-test");
    assert!(blob.pid > 0, "PID should be nonzero");
    assert!(blob.timestamp > 0, "timestamp should be nonzero");

    // check_previous_crash should produce a SIGABRT-labelled report.
    let report = fuigo_crash_handler::check_previous_crash(tmp.path())
        .expect("should produce a crash report");
    assert!(
        report.signal_name.contains("SIGABRT"),
        "report should name SIGABRT, got {}",
        report.signal_name
    );
    assert_eq!(report.app_version, "0.0.0-test");
    assert!(report.report_path.exists(), "report file should be written");
    assert!(
        !crash_file.exists(),
        "crash file should be deleted after processing"
    );
}

#[test]
fn clean_exit_does_not_produce_crash_report() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Run both scenarios and verify no crash artifacts.
    for scenario in &["tokio_normal", "sync_normal", "tokio_signals"] {
        let (status, _stdout, stderr) = run_scenario(scenario, tmp.path());
        assert!(status.success(), "{scenario} failed: {stderr}");
    }
    // check_previous_crash should return None.
    let report = fuigo_crash_handler::check_previous_crash(tmp.path());
    assert!(report.is_none(), "no crash report after clean exits");
}

// ── P05a: per-process slots, ASLR symbolication, panic classification ──

fn frame_names(report: &fuigo_crash_handler::CrashReport) -> Vec<String> {
    report
        .backtrace
        .iter()
        .filter_map(|f| f.symbol_name.clone())
        .collect()
}

#[test]
fn two_concurrent_sessions_do_not_clobber_each_other() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // A installs first and stays alive; B installs after A and crashes.
    // With one shared file, B's install truncated A's slot and the reader
    // deleted it, losing A's later crash.
    let mut a = spawn_waiting("wait_then_segv", tmp.path());
    let a_pid = a.id();
    let (_, _, _, b_pid) = run_scenario_pid("segv_marker", tmp.path());
    assert_ne!(a_pid, b_pid);

    let a_slots = slots_of(tmp.path(), a_pid);
    assert_eq!(a_slots.len(), 1, "A has its own slot while alive");
    let first = fuigo_crash_handler::check_previous_crashes(tmp.path(), "");
    assert_eq!(first.len(), 1, "only B (dead) is reported: {first:?}");
    assert_eq!(first[0].pid, b_pid);
    assert!(
        a_slots[0].exists(),
        "a live session's slot is never touched"
    );
    assert_eq!(std::fs::metadata(&a_slots[0]).expect("meta").len(), 0);

    release(&mut a);
    let status = a.wait().expect("wait A");
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        status.signal(),
        Some(libc::SIGSEGV),
        "A crashed: {status:?}"
    );
    let second = fuigo_crash_handler::check_previous_crashes(tmp.path(), "");
    assert_eq!(second.len(), 1, "A's crash survived B: {second:?}");
    assert_eq!(second[0].pid, a_pid);
    assert!(fuigo_crash_handler::check_previous_crashes(tmp.path(), "").is_empty());
}

#[test]
fn two_readers_report_a_dead_blob_once() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_, _, _, pid) = run_scenario_pid("segv_marker", tmp.path());
    let dir = tmp.path().to_path_buf();
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let d = dir.clone();
            std::thread::spawn(move || fuigo_crash_handler::check_previous_crashes(&d, "").len())
        })
        .collect();
    let total: usize = readers.into_iter().map(|h| h.join().expect("join")).sum();
    assert_eq!(
        total, 1,
        "the atomic claim lets exactly one reader report pid {pid}"
    );
}

#[test]
fn clean_exit_removes_own_slot_and_live_slot_is_kept() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut a = spawn_waiting("wait_then_exit", tmp.path());
    let a_pid = a.id();
    assert_eq!(
        slots_of(tmp.path(), a_pid).len(),
        1,
        "slot exists while running"
    );
    assert!(fuigo_crash_handler::check_previous_crashes(tmp.path(), "").is_empty());
    assert_eq!(
        slots_of(tmp.path(), a_pid).len(),
        1,
        "reader left the live slot alone"
    );
    release(&mut a);
    assert!(a.wait().expect("wait").success());
    assert!(
        slots_of(tmp.path(), a_pid).is_empty(),
        "clean exit deletes the slot"
    );
}

#[test]
fn forked_child_cannot_write_or_delete_the_parent_slot() {
    use std::os::unix::process::ExitStatusExt;
    let tmp = tempfile::tempdir().expect("tempdir");
    let (status, _out, err, parent) = run_scenario_pid("fork_child_crash", tmp.path());
    assert_eq!(
        status.signal(),
        Some(libc::SIGSEGV),
        "the parent crashes last: {status:?} {err}"
    );
    assert!(
        err.contains("PARENT_SLOT_AFTER_FORKS=Ok(0)"),
        "parent slot must still exist and be empty after forked children crashed, exited and re-installed: {err}"
    );
    let child = |mode: &str| -> (u32, String) {
        let line = err
            .lines()
            .find(|l| l.starts_with(&format!("CHILD mode={mode} ")))
            .unwrap_or_else(|| panic!("no line for {mode}: {err}"));
        let pid = line
            .split("pid=")
            .nth(1)
            .and_then(|r| r.split(' ').next())
            .expect("pid");
        (
            pid.parse().expect("pid"),
            line.rsplit(' ').next().expect("how").to_string(),
        )
    };
    let segv = format!("signal={}", libc::SIGSEGV);
    assert_eq!(child("crash").1, segv);
    assert_eq!(child("exit").1, "exit=0");
    assert_eq!(
        child("reinstall_exit").1,
        "exit=0",
        "the child's install() succeeded"
    );
    let (crashed_child, how) = child("reinstall_crash");
    assert_eq!(
        how, segv,
        "the reinstalled child crashed (install succeeded first)"
    );

    // The parent's own crash went into the parent's slot.
    let (_, parent_blob) = crash_blob_of(tmp.path(), parent);
    assert_eq!(parent_blob.pid, parent);
    assert_eq!(parent_blob.app_version, "0.0.0-test");
    // The reinstalled child's crash went into the child's own slot.
    let (_, child_blob) = crash_blob_of(tmp.path(), crashed_child);
    assert_eq!(child_blob.pid, crashed_child);
    assert_eq!(child_blob.app_version, "0.0.0-child");
    // Nothing else: the plain children wrote nothing, the reinstall_exit child
    // released its own slot at exit.
    let mut left: Vec<String> = std::fs::read_dir(tmp.path())
        .expect("ls")
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    left.sort();
    assert_eq!(
        left.len(),
        2,
        "exactly the parent's and the crashed child's slots: {left:?}"
    );
}

#[test]
fn sigsegv_report_symbolicates_across_aslr() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (status, _, _, pid) = run_scenario_pid("segv_marker", tmp.path());
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(libc::SIGSEGV));
    let (_, blob) = crash_blob_of(tmp.path(), pid);
    let crashed = blob.image.expect("v2 blob records the image");
    let here = fuigo_crash_handler::image::current_image().expect("own image");
    assert_eq!(crashed.span(), here.span(), "same binary");
    if aslr_enabled() {
        assert_ne!(
            crashed.base, here.base,
            "the crashed process and this reader must be mapped at different bases"
        );
        // Negative control: the raw absolute PC means nothing here.
        let mut raw_name = None;
        backtrace::resolve(blob.frames[0] as *mut std::ffi::c_void, |s| {
            raw_name = raw_name.take().or_else(|| s.name().map(|n| n.to_string()));
        });
        assert!(
            !raw_name
                .unwrap_or_default()
                .contains("p05a_marker_segv_site"),
            "resolving the absolute address must not hit the marker by accident"
        );
    }

    let reports = fuigo_crash_handler::check_previous_crashes(tmp.path(), "");
    assert_eq!(reports.len(), 1);
    let r = &reports[0];
    assert_eq!(r.symbolication, Symbolication::Resolved);
    let names = frame_names(r);
    assert!(
        names
            .first()
            .is_some_and(|n| n.contains("p05a_marker_segv_site")),
        "the crash PC must resolve to the faulting function, got {names:?}"
    );
    let text = std::fs::read_to_string(&r.report_path).expect("report");
    assert!(text.contains("p05a_marker_segv_site"), "{text}");
    assert!(text.contains("fuigo+0x"), "{text}");
}

#[test]
fn sigabrt_report_symbolicates_the_aborting_function() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_, _, _, pid) = run_scenario_pid("abort_marker", tmp.path());
    let (_, blob) = crash_blob_of(tmp.path(), pid);
    assert_eq!(blob.signal, 6);
    assert_eq!(blob.kind, CrashKind::Signal);
    let reports = fuigo_crash_handler::check_previous_crashes(tmp.path(), "");
    let names = frame_names(&reports[0]);
    assert!(
        names.iter().any(|n| n.contains("p05a_marker_abort_site")),
        "some frame must resolve to the function that called abort(), got {names:?}"
    );
}

#[test]
fn foreign_build_is_not_symbolicated() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_, _, _, _pid) = run_scenario_pid("segv_marker", tmp.path());
    let reports = fuigo_crash_handler::check_previous_crashes(tmp.path(), "9.9.9-other");
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].symbolication, Symbolication::DifferentBuild);
    assert!(
        frame_names(&reports[0]).is_empty(),
        "no guessed symbols for another build"
    );
    assert!(
        reports[0].backtrace[0].module_offset.is_some(),
        "offsets kept for offline use"
    );
}

#[test]
fn real_panic_is_classified_with_thread_name() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (status, _, _, pid) = run_scenario_pid("panic_real", tmp.path());
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(libc::SIGABRT), "{status:?}");
    let (_, blob) = crash_blob_of(tmp.path(), pid);
    assert_eq!(blob.kind, CrashKind::Panic);
    assert_eq!(blob.class, PanicClass::None);
    assert_eq!(
        blob.thread_name.as_deref(),
        Some("<path-like name>"),
        "a path-like name is never stored"
    );
    let reports = fuigo_crash_handler::check_previous_crashes(tmp.path(), "");
    assert!(!reports[0].benign);
    let notice = fuigo_crash_handler::startup_notice(&reports).expect("a real panic is announced");
    assert!(
        notice.contains("Rust panic on thread '<path-like name>'"),
        "{notice}"
    );
    let text = std::fs::read_to_string(&reports[0].report_path).expect("report");
    assert!(
        !text.contains("index out of bounds"),
        "the panic message is never stored: {text}"
    );
}

#[test]
fn benign_panics_keep_a_report_but_raise_no_notice() {
    for (scenario, class) in [
        ("panic_broken_pipe", PanicClass::BenignBrokenPipe),
        ("panic_enospc", PanicClass::BenignNoSpace),
    ] {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_, _, _, pid) = run_scenario_pid(scenario, tmp.path());
        let (_, blob) = crash_blob_of(tmp.path(), pid);
        assert_eq!(blob.kind, CrashKind::Panic, "{scenario}");
        assert_eq!(blob.class, class, "{scenario}");
        let reports = fuigo_crash_handler::check_previous_crashes(tmp.path(), "");
        assert_eq!(reports.len(), 1);
        assert!(reports[0].benign, "{scenario}");
        assert!(reports[0].report_path.exists(), "{scenario}: report kept");
        assert!(
            fuigo_crash_handler::startup_notice(&reports).is_none(),
            "{scenario}: no crashed notice"
        );
    }
}

#[test]
fn caught_panic_elsewhere_does_not_label_an_abort() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_, _, _, pid) = run_scenario_pid("caught_panic_then_abort_elsewhere", tmp.path());
    let (_, blob) = crash_blob_of(tmp.path(), pid);
    assert_eq!(blob.signal, 6);
    assert_eq!(
        blob.kind,
        CrashKind::Signal,
        "the abort ran on a different thread"
    );
    assert_eq!(blob.class, PanicClass::None);
    let reports = fuigo_crash_handler::check_previous_crashes(tmp.path(), "");
    assert!(fuigo_crash_handler::startup_notice(&reports).is_some());
}

#[test]
fn concurrent_benign_panics_are_each_classified() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_, _, _, pid) = run_scenario_pid("concurrent_benign_panics", tmp.path());
    let (_, blob) = crash_blob_of(tmp.path(), pid);
    assert_eq!(
        blob.kind,
        CrashKind::Panic,
        "the aborting thread's own panic was recorded"
    );
    assert_eq!(blob.class, PanicClass::BenignBrokenPipe);
    assert_eq!(blob.thread_name.as_deref(), Some("second"));
    let reports = fuigo_crash_handler::check_previous_crashes(tmp.path(), "");
    assert!(fuigo_crash_handler::startup_notice(&reports).is_none());
}

#[test]
fn crash_after_release_leaves_no_slot() {
    use std::os::unix::process::ExitStatusExt;
    let tmp = tempfile::tempdir().expect("tempdir");
    let (status, _, err, pid) = run_scenario_pid("release_then_segv", tmp.path());
    assert!(
        err.contains("INSTALLED_BEFORE_RELEASE"),
        "recording was running first: {err}"
    );
    assert_eq!(
        status.signal(),
        Some(libc::SIGSEGV),
        "still dies of the signal: {status:?}"
    );
    assert!(
        slots_of(tmp.path(), pid).is_empty(),
        "no slot, no blob after release_slot"
    );
    assert!(fuigo_crash_handler::check_previous_crashes(tmp.path(), "").is_empty());
}
