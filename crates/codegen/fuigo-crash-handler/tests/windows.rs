//! Windows-only: a real access violation in a subprocess, reported and
//! symbolicated by the next process (run natively, outside WSL).

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(target_arch = "x86_64")]
use fuigo_crash_handler::Symbolication;

#[allow(clippy::disallowed_methods)] // waited on before returning
fn run_scenario_pid(scenario: &str, crash_dir: &Path) -> (std::process::ExitStatus, u32) {
    let exe = std::env::current_exe().expect("current_exe");
    let child = Command::new(exe)
        .env("CRASH_TEST_SCENARIO", scenario)
        .env("CRASH_TEST_DIR", crash_dir.as_os_str())
        .args([
            "--ignored",
            "--exact",
            "--nocapture",
            "win_subprocess_entry",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn");
    let pid = child.id();
    let out = child.wait_with_output().expect("wait");
    (out.status, pid)
}

#[inline(never)]
fn p05c_marker_av_site() {
    // A real invalid store: the faulting PC is in this function.
    unsafe { *(std::hint::black_box(8usize) as *mut u8) = 1 };
}

#[test]
#[ignore]
fn win_subprocess_entry() {
    let Ok(scenario) = std::env::var("CRASH_TEST_SCENARIO") else {
        return;
    };
    let crash_dir = PathBuf::from(std::env::var("CRASH_TEST_DIR").expect("dir"));
    // No Windows Error Reporting dialog for the deliberate fault.
    unsafe {
        windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode(0x0001 | 0x0002);
    }
    assert!(fuigo_crash_handler::install(
        fuigo_crash_handler::CrashHandlerConfig {
            app_version: "0.0.0-win".to_string(),
            crash_dir,
        }
    ));
    match scenario.as_str() {
        "av" => p05c_marker_av_site(),
        "clean" => {}
        other => panic!("unknown scenario {other}"),
    }
}

fn slots(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| fuigo_crash_handler::parse_slot_file_name(n).is_some())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn access_violation_is_recorded_and_symbolicated_by_the_next_process() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (status, pid) = run_scenario_pid("av", tmp.path());
    assert!(!status.success(), "the child died of the fault: {status:?}");
    assert_eq!(slots(tmp.path()).len(), 1, "the child left its slot");

    let reports = fuigo_crash_handler::check_previous_crashes(tmp.path(), "");
    assert_eq!(reports.len(), 1, "{reports:?}");
    let r = &reports[0];
    assert_eq!(r.pid, pid);
    assert_eq!(r.app_version, "0.0.0-win");
    assert!(r.report_path.exists());
    // PC capture (and so symbolication) is x86_64-only on Windows: the ARM64
    // CONTEXT layout is not read, so an ARM64 report carries no frames.
    #[cfg(target_arch = "x86_64")]
    {
        assert_eq!(
            r.symbolication,
            Symbolication::Resolved,
            "same build, PE identity present"
        );
        let first = r.backtrace[0].symbol_name.clone().unwrap_or_default();
        assert!(
            first.contains("p05c_marker_av_site"),
            "frame 0 must resolve to the faulting function (MSVC double adjust compensated): {:?}",
            r.backtrace
                .iter()
                .map(|f| f.symbol_name.clone())
                .collect::<Vec<_>>()
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    assert!(
        r.backtrace.is_empty(),
        "documented limitation: no PC capture off x86_64"
    );
    assert!(slots(tmp.path()).is_empty(), "the blob was consumed");
    assert!(fuigo_crash_handler::startup_notice(&reports).is_some());
}

#[test]
fn clean_exit_slot_is_swept_by_the_next_start() {
    // std::process::exit / main return on Windows uses ExitProcess, which
    // skips CRT atexit, so the empty slot survives the exit; the sweep run
    // by every non-interactive start removes it once its owner is dead.
    let tmp = tempfile::tempdir().expect("tempdir");
    let (status, pid) = run_scenario_pid("clean", tmp.path());
    assert!(status.success(), "{status:?}");
    let left = slots(tmp.path());
    assert_eq!(
        left.len(),
        1,
        "the exited child's empty slot survives exit: {left:?}"
    );
    assert_eq!(
        fuigo_crash_handler::parse_slot_file_name(&left[0]).map(|(p, _)| p),
        Some(pid)
    );
    assert_eq!(
        std::fs::metadata(tmp.path().join(&left[0]))
            .expect("meta")
            .len(),
        0
    );
    assert_eq!(
        fuigo_crash_handler::sweep_dead_slots(tmp.path()),
        1,
        "exactly that slot swept"
    );
    assert!(slots(tmp.path()).is_empty());
    assert!(fuigo_crash_handler::check_previous_crashes(tmp.path(), "").is_empty());
}
