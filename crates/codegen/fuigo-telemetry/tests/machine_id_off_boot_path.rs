//! Fresh-process pins; the assertions consume process-global state.

#[test]
fn env_override_pins_the_agent_id_without_persisting_it() {
    let home = tempfile::tempdir().expect("tempdir");
    // SAFETY: single-threaded here; set before anything caches `fuigo_home()`.
    unsafe {
        std::env::set_var("FUIGO_HOME", home.path());
        std::env::set_var("FUIGO_AGENT_ID", "pinned-agent-id");
    }
    assert_eq!(fuigo_telemetry::id::agent_id(), "pinned-agent-id");
    assert!(!home.path().join("agent_id").exists());
}
