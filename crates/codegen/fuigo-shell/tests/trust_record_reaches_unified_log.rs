//! A trust-set write made BEFORE any `Config` path runs still reaches the unified
//! log once the process installs the sink (as the product binary does at start).
//!
//! Own process: the trust set and the sink are process-wide.

#[test]
fn a_write_queued_before_any_config_path_reaches_the_unified_log() {
    fuigo_telemetry::unified_log::redirect_to_temp_for_tests();

    // A caller outside `agent/config.rs`, before anything installed a sink.
    let installed =
        fuigo_shell::util::set_trusted_api_origins(["https://record-probe.example/v1".to_string()]);
    assert!(
        installed.is_some(),
        "this process's first seed must install"
    );

    fuigo_shell::agent::config::install_trust_record_sink();

    let log = fuigo_telemetry::unified_log::snapshot_log().expect("unified log readable");
    let log = String::from_utf8_lossy(&log);
    let line = log
        .lines()
        .find(|l| l.contains("trusted API origins: process baseline"))
        .unwrap_or_else(|| panic!("no baseline record in the unified log:\n{log}"));
    assert!(line.contains("record-probe.example"), "{line}");
    assert!(line.contains("\"via\":\"seed\""), "{line}");
    // Never the configured string itself, only scheme/host/port.
    assert!(!line.contains("/v1"), "{line}");
}
