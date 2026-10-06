//! P133 (final-audit finding): a refused reference to the saved API key reached only `tracing::warn!`, so a project
//! config that named the key in 1.0.20 failed with no word to the user. The note is now sent to the session. Red first.

use agent_client_protocol as acp;

use super::{build_minimal_agent_for_tests, make_test_handle};
use crate::session::SessionCommand;

fn record_refusal(file: &str) {
    let mut v: toml::Value =
        toml::from_str("[mcp_servers.s]\ncommand = \"x\"\nenv = { T = \"${FUIGO_API_KEY}\" }\n").unwrap();
    let refused = fuigo_config::key_naming::refuse_key_references_in_toml(&mut v, file);
    assert!(!refused.is_empty());
    fuigo_config::key_naming::report_refusals(&refused);
}

#[tokio::test(flavor = "current_thread")]
async fn a_refused_key_reference_is_announced_to_the_session() {
    let agent = build_minimal_agent_for_tests();
    let mut handle = make_test_handle("m", false, None);
    handle.info.cwd = "/p133/repo/src".to_owned();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    handle.cmd_tx = tx;
    let sid = acp::SessionId::new("p133-announce");
    agent.insert_resident(&sid, handle);
    // P136 (Astra r3 #4): a refusal belongs to the session whose setup recorded it, tagged when it was recorded. One
    // recorded outside any session, or by another session set up at the same time (a project file or a label that is
    // no path at all), is not this session's; the shared FUIGO_CONFIG_PATH file this session loaded is.
    let mine = fuigo_config::key_naming::NoticeScope::new();
    let theirs = fuigo_config::key_naming::NoticeScope::new();
    record_refusal("/p133/earlier/.fuigo/config.toml");
    mine.run(|| record_refusal("/p133/repo/.fuigo/config.toml"));
    theirs.run(|| {
        record_refusal("/p133/other-project/.fuigo/config.toml");
        record_refusal("MCP server `p136-theirs` supplied by the ACP client");
    });
    mine.run(|| record_refusal("/opt/p136-shared/.fuigo/config.toml"));

    agent.announce_config_notices(&sid, mine).await;

    let mut notices = Vec::new();
    while let Ok(cmd) = rx.try_recv() {
        if let SessionCommand::NotifyConfigNotice { notice } = cmd {
            notices.push(notice);
        }
    }
    assert!(
        notices.iter().any(|n| n.contains("/p133/repo/.fuigo/config.toml") && n.contains("FUIGO_API_KEY")),
        "the session was told nothing about the refused reference: {notices:?}"
    );
    assert!(
        notices.iter().any(|n| n.starts_with("/opt/p136-shared/.fuigo/config.toml")),
        "the shared FUIGO_CONFIG_PATH file's refusal was suppressed: {notices:?}"
    );
    assert!(
        notices.iter().all(|n| !n.contains("/p133/other-project/") && !n.contains("/p133/earlier/") && !n.contains("p136-theirs")),
        "another session's refusal reached this session: {notices:?}"
    );
}

/// P138 d-2: a `session/new` that fails (here: before `initialize`) closes its notice scope. 300 of them must not push a
/// live session's scope out of the open set (cap 256).
#[tokio::test(flavor = "current_thread")]
async fn failing_session_new_calls_do_not_evict_a_live_scope() {
    let agent = build_minimal_agent_for_tests();
    let live = fuigo_config::key_naming::NoticeScope::new();
    live.run(|| record_refusal("/p138/live/.fuigo/config.toml"));
    for _ in 0..300 {
        let req = acp::NewSessionRequest::new(std::path::PathBuf::from("/p138/repo"));
        assert!(agent.new_session_inner(req).await.is_err(), "precondition: the call fails");
    }
    let notes = live.notes();
    assert!(
        notes.iter().any(|n| n.contains("/p138/live/")),
        "failing session/new calls evicted a live session's scope: {notes:?}"
    );
}

/// P138 d-2: announcing to a session that is gone still closes the scope.
#[tokio::test(flavor = "current_thread")]
async fn announcing_to_an_absent_session_closes_the_scope() {
    let agent = build_minimal_agent_for_tests();
    let scope = fuigo_config::key_naming::NoticeScope::new();
    scope.run(|| record_refusal("/p138/gone/.fuigo/config.toml"));
    agent.announce_config_notices(&acp::SessionId::new("p138-absent"), scope).await;
    scope.run(|| record_refusal("/p138/gone/later.toml"));
    assert!(scope.notes().is_empty(), "the scope stayed open after the announce found no session");
}
