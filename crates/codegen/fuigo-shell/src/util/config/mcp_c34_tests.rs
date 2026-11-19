//! review C3-4: a failed credential cleanup when a server is removed is surfaced, not discarded.
#![allow(
    clippy::disallowed_methods,
    reason = "test code: fixtures write files in a test-owned FUIGO_HOME"
)]

#[tokio::test]
#[serial_test::serial]
async fn failed_credential_cleanup_on_server_removal_is_surfaced() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let _env = fuigo_test_support::EnvGuard::set("FUIGO_HOME", home.path());
    let config = home.path().join("config.toml");
    std::fs::write(
        &config,
        "[mcp_servers.c34srv]\nurl = \"https://h.invalid/mcp\"\n",
    )
    .unwrap();
    // A damaged credentials file makes the locked removal return an error.
    std::fs::write(home.path().join("mcp_credentials.json"), b"{ not json").unwrap();

    let removed = super::delete_mcp_server_config_at(&config, "c34srv")
        .await
        .unwrap();
    assert!(removed, "the server itself is removed");
    let notes = fuigo_config::key_naming::refusal_notes();
    assert!(
        notes
            .iter()
            .any(|n| n.contains("c34srv") && n.contains("saved sign-in")),
        "no notice for the failed cleanup: {notes:?}"
    );
}

/// C7-03: the notice for a damaged store never carries the file's contents (a serde type error quotes the value).
#[tokio::test]
#[serial_test::serial]
async fn removal_notice_never_carries_credential_store_contents() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let _env = fuigo_test_support::EnvGuard::set("FUIGO_HOME", home.path());
    let config = home.path().join("config.toml");
    std::fs::write(
        &config,
        "[mcp_servers.c703srv]\nurl = \"https://h.invalid/mcp\"\n",
    )
    .unwrap();
    std::fs::write(
        home.path().join("mcp_credentials.json"),
        br#"{"c703srv:https://h.invalid/mcp":"SECRET-C703-TOKEN"}"#,
    )
    .unwrap();

    assert!(
        super::delete_mcp_server_config_at(&config, "c703srv")
            .await
            .unwrap()
    );
    let notes = fuigo_config::key_naming::refusal_notes();
    let note = notes
        .iter()
        .find(|n| n.contains("c703srv") && n.contains("saved sign-in"))
        .expect("a notice");
    assert!(!note.contains("SECRET-C703-TOKEN"), "{note}");
    assert!(
        note.contains("mcp_credentials.json"),
        "the store path is named: {note}"
    );
}
