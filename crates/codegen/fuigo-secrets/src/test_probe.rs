//! Test support (feature `test-support`): prove that a child process of the code under test does not inherit Fuigo's
//! own secrets (P120). The secret names are LITERAL on purpose: a probe that read the registry would plant nothing
//! once the registry was emptied, and pass.
//!
//! A test calls [`in_parent`] first. In the parent it re-runs itself in a fresh test process whose environment holds
//! every secret (and `P120_BENIGN=kept`) and returns `true`; the child (`false`) runs the body, then checks what its
//! own child wrote with [`assert_clean`].

use std::path::{Path, PathBuf};

/// Fuigo's own secret variables (the registry's built-in list).
pub const SECRETS: &[&str] = &[
    "FUIGO_API_KEY",
    "FUIGO_CODE_API_KEY",
    "FLUX_API_KEY",
    "FUIGO_AGENT_SECRET",
    "FUIGO_AUTH",
    "FUIGO_AUTH_PATH",
    "FUIGO_DEPLOYMENT_KEY",
    "FUIGO_EXTRA_AUTH_KEY",
    "FUIGO_TRACE_UPLOAD_CREDENTIALS_FILE",
    "FUIGO_INTERNAL_OTLP_HEADERS",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
    "OTEL_EXPORTER_OTLP_METRICS_HEADERS",
    "FUIGO_TELEMETRY_EVENTS_API_KEY",
    "FUIGO_TELEMETRY_MIXPANEL_TOKEN",
];

/// Re-run `test_name` in a fresh test process holding every [`SECRETS`] entry plus `extra` names (a name a config
/// would register as a credential; the child registers it before the body) and `P120_BENIGN=kept`. `true` in the
/// parent (which must then return), `false` in the child.
pub fn in_parent(test_name: &str, extra: &[&str]) -> bool {
    if std::env::var("P120_CHILD_TEST").as_deref() == Ok(test_name) {
        return false;
    }
    let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
    cmd.arg(test_name)
        .args(["--test-threads=1", "--nocapture"])
        .env("P120_CHILD_TEST", test_name)
        .env("P120_BENIGN", "kept");
    for name in SECRETS.iter().chain(extra) {
        cmd.env(name, "fake-p120-ambient");
    }
    let output = cmd.output().unwrap();
    let diagnostics = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .replace("fake-p120-", "[redacted]-");
    assert!(output.status.success(), "isolated P120 probe failed: {diagnostics}");
    assert!(
        diagnostics.contains("test result: ok. 1 passed"),
        "the P120 child must run exactly one test: {diagnostics}"
    );
    true
}

/// A fresh empty directory for a probe.
pub fn scratch_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A shell script that dumps its environment to `out`, as `path`, executable.
#[cfg(unix)]
pub fn write_env_dump_script(path: &Path, out: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(path, format!("#!/bin/sh\nenv > '{}'\n", out.display())).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Assert `dump` (an `env` listing a probed child wrote) holds the benign variable and none of [`SECRETS`] or `extra`.
/// Names only are reported, never values.
pub fn assert_clean(dump: &str, extra: &[&str]) {
    assert!(
        dump.lines().any(|line| line == "P120_BENIGN=kept"),
        "control: the child did not inherit the ordinary environment, so the probe proves nothing:\n{}",
        dump.lines().map(|l| l.split('=').next().unwrap_or("")).collect::<Vec<_>>().join(" ")
    );
    let leaked: Vec<&str> = SECRETS
        .iter()
        .chain(extra)
        .copied()
        .filter(|name| dump.lines().any(|line| line.starts_with(&format!("{name}="))))
        .collect();
    assert!(leaked.is_empty(), "the child inherited Fuigo's secrets: {leaked:?}");
}

/// Assert `dump` still holds `name` (a credential name a config registered, which is the USER's own and must reach
/// the user's own tools: P120 follow-up). Names only are reported.
pub fn assert_kept(dump: &str, name: &str) {
    assert!(
        dump.lines().any(|line| line.starts_with(&format!("{name}="))),
        "the child lost the user's own credential variable {name}, which no Fuigo secret filter may remove"
    );
}
