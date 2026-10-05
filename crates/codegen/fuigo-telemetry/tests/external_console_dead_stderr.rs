//! R077: the console OTEL exporters (`FUIGO_EXTERNAL_OTEL=1`, `OTEL_LOGS_EXPORTER=console`,
//! `OTEL_METRICS_EXPORTER=console`) write records to stderr from their own export threads. With
//! a raw `eprintln!` a dead or full stderr panicked that thread, and release is
//! `panic = "abort"`: the whole process died with SIGABRT.
//!
//! No offline CLI command records a metric (they come from sessions, and the agent/headless
//! entrypoints suppress console output), so this drives the real pipeline in a child process: the
//! child initialises the external stream with both console exporters, emits `SessionNew` (the
//! `session.count` metric) and `PluginInstalled` (a `plugin_loaded` log record), and shuts the
//! stream down, which exports both. Its panic hook aborts, as release does. The binary-level log-exporter case is
//! fuigo-pager-bin's `dead_output_sweep` (`plugin install`).
#![cfg(unix)]

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

use fuigo_telemetry::external;

const CHILD_ENV: &str = "FUIGO_R077_CONSOLE_CHILD";

#[derive(Clone, Copy, Debug)]
enum Stderr {
    Live,
    DeadPipe,
    #[cfg(target_os = "linux")]
    Full,
}

fn run_child(mode: Stderr) -> std::process::Output {
    let mut command = Command::new(std::env::current_exe().expect("test binary"));
    command
        .args([
            "--exact",
            "console_exporter_child",
            "--ignored",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
    let mut dead_reader = None;
    match mode {
        Stderr::Live => {
            command.stderr(Stdio::piped());
        }
        Stderr::DeadPipe => {
            let (reader, writer) = std::io::pipe().expect("pipe");
            command.stderr(Stdio::from(writer));
            dead_reader = Some(reader);
        }
        #[cfg(target_os = "linux")]
        Stderr::Full => {
            let full = std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .expect("/dev/full");
            command.stderr(Stdio::from(full));
        }
    }
    // Dropped before the child runs: every stderr write gets EPIPE.
    drop(dead_reader);
    #[allow(
        clippy::disallowed_methods,
        reason = "output() waits for the child, so it never outlives this function"
    )]
    let output = command.output().expect("spawn child");
    output
}

/// The child half: real external stream, both console exporters, one event with a metric.
#[test]
#[ignore = "run only as the child of the tests below"]
fn console_exporter_child() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    // Release is `panic = "abort"`; tests unwind. Make any panic (an export thread's included)
    // end the process the way release does.
    std::panic::set_hook(Box::new(|_| std::process::abort()));
    let mut cfg = external::ExternalOtelConfig::resolve_with(
        |name| match name {
            "FUIGO_EXTERNAL_OTEL" => Some("1".into()),
            "OTEL_LOGS_EXPORTER" | "OTEL_METRICS_EXPORTER" => Some("console".into()),
            "OTEL_METRIC_EXPORT_INTERVAL" => Some("100".into()),
            "OTEL_BLRP_SCHEDULE_DELAY" => Some("100".into()),
            _ => None,
        },
        None,
    )
    .expect("console config resolves");
    cfg.client = external::config::ExternalClientInfo {
        service_version: "0.0.0-test".into(),
        client_version: "0.0.0-test".into(),
        // A CLI entrypoint: agent/headless suppress console output.
        app_entrypoint: "cli".into(),
    };
    external::init(Some(cfg));
    assert!(external::is_active(), "the console stream must be active");
    fuigo_telemetry::log_event(fuigo_telemetry::events::SessionNew {
        session_id: "sess-r077".into(),
        client_identifier: None,
        client_version: None,
        is_git_repo: false,
        permission_mode: fuigo_telemetry::enums::PermissionMode::Ask,
    });
    fuigo_telemetry::log_event(fuigo_telemetry::events::PluginInstalled {
        install_kind: fuigo_telemetry::events::InstallKind::Local,
        success: false,
        trust: true,
        error_category: Some("install_failed".into()),
    });
    external::flush();
    external::shutdown();
    println!("R077_CHILD_DONE");
}

fn assert_child_survives(mode: Stderr) {
    let out = run_child(mode);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && out.status.signal().is_none(),
        "stderr {mode:?}: the child must finish normally, got {:?} (signal {:?}; 6 = SIGABRT from \
         a panicking console export)\nstdout:\n{stdout}",
        out.status,
        out.status.signal()
    );
    assert!(
        stdout.contains("R077_CHILD_DONE"),
        "child did not run:\n{stdout}"
    );
}

/// Control: with a live stderr both exporters print, so the dead/full cases below are not
/// vacuous.
#[test]
fn console_exporters_print_logs_and_metrics_to_a_live_stderr() {
    let out = run_child(Stderr::Live);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{:?}\n{stderr}", out.status);
    assert!(
        stderr.contains("[external-otel] event="),
        "log exporter output missing:\n{stderr}"
    );
    assert!(
        stderr.contains("[external-otel] metric="),
        "metric exporter output missing:\n{stderr}"
    );
}

#[test]
fn console_exporters_survive_a_dead_stderr() {
    assert_child_survives(Stderr::DeadPipe);
}

#[cfg(target_os = "linux")]
#[test]
fn console_exporters_survive_a_full_stderr() {
    assert_child_survives(Stderr::Full);
}
