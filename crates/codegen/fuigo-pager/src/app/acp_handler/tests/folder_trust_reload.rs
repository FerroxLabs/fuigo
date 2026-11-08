#![cfg_attr(rustfmt, rustfmt::skip)]
//! F5-P: the pager's reload after a durable folder-trust grant (design F5 §4.1, §6.2, §8).
use super::*;
use crate::app::actions::{Action, Effect, TaskResult};
use crate::app::dispatch::dispatch;
use crate::app::folder_trust_reload::{self as ftr, Phase};
use crate::scrollback::block::RenderBlock;

const SID: &str = "sess-1";

fn ext(params: serde_json::Value) -> AcpClientMessage {
    let (tx, _rx) = tokio::sync::oneshot::channel();
    let raw = serde_json::value::to_raw_value(&params).unwrap();
    AcpClientMessage::ExtNotification(fuigo_acp_lib::AcpArgs {
        request: acp::ExtNotification::new("fuigo/session/update", raw.into()),
        response_tx: tx,
    })
}

/// What the agent sends after a durable grant (F5-N `folder_trust_reload_params`).
fn reload_notice(sid: &str) -> AcpClientMessage {
    ext(serde_json::json!({ "sessionId": sid, "update": { "sessionUpdate": "folder_trust_reload" } }))
}

/// What the agent sends after a grant that was not saved: the transient reopen notice, and no reload.
fn not_saved_notice(sid: &str) -> AcpClientMessage {
    ext(serde_json::json!({
        "sessionId": sid,
        "update": { "sessionUpdate": "config_notice", "message": "Folder trust is on. Reopen this session to use it." },
    }))
}

fn loaded(sid: &str) -> TaskResult {
    TaskResult::SessionLoaded {
        agent_id: AgentId(0),
        session_id: acp::SessionId::new(sid),
        models: None,
        code_restored: false,
        restore_summary: None,
        restore_degree: None,
        running_prompt_id: None,
        scheduler_background_loops: None,
        attempt: 0,
    }
}

fn closes(effects: &[Effect]) -> usize {
    effects.iter().filter(|e| matches!(e, Effect::FolderTrustClose { session_id, .. } if session_id.0.as_ref() == SID)).count()
}

fn take_pending(app: &mut AppView) -> Vec<Effect> {
    std::mem::take(&mut app.pending_effects)
}

fn has_system_text(agent: &AgentView, text: &str) -> bool {
    (0..agent.scrollback.len()).any(|i| {
        matches!(agent.scrollback.get(i).map(|e| &e.block), Some(RenderBlock::System(b)) if b.text == text)
    })
}

fn closed(app: &mut AppView, outcome: Result<String, String>) -> Vec<Effect> {
    dispatch(
        Action::TaskComplete(TaskResult::FolderTrustClosed { agent_id: AgentId(0), session_id: acp::SessionId::new(SID), outcome }),
        app,
    )
}

/// Only the reload notice owes a reload; a grant that was not saved (its reopen notice) never closes the session.
#[test]
fn ftr_only_a_durable_grant_reload_notice_closes_the_session() {
    let mut app = make_app_with_agent(SID);
    let _ = handle(not_saved_notice(SID), &mut app);
    assert_eq!(closes(&take_pending(&mut app)), 0, "a not-saved grant must not start a reload");
    assert_eq!(app.agents[&AgentId(0)].folder_trust_reload, None);

    let _ = handle(reload_notice(SID), &mut app);
    assert_eq!(closes(&take_pending(&mut app)), 1, "the reload notice closes the idle session once");
    assert_eq!(app.agents[&AgentId(0)].folder_trust_reload, Some(Phase::Closing));
    let _ = handle(reload_notice(SID), &mut app);
    assert_eq!(closes(&take_pending(&mut app)), 0, "a repeat notice while reloading starts nothing");
}

/// A reattach whose load response says the reload is still owed starts it; a plain load does not.
#[test]
fn ftr_owed_meta_on_reattach_starts_the_reload() {
    let mut app = make_app_with_agent(SID);
    let plain = dispatch(Action::TaskComplete(loaded(SID)), &mut app);
    assert_eq!(closes(&plain), 0, "a load without the owed meta behaves as before");
    assert_eq!(app.agents[&AgentId(0)].folder_trust_reload, None);

    let owed = dispatch(Action::TaskComplete(TaskResult::FolderTrustReloadOwed { loaded: Box::new(loaded(SID)) }), &mut app);
    assert_eq!(closes(&owed), 1, "the owed reload starts on reattach: {owed:?}");
    assert_eq!(app.agents[&AgentId(0)].folder_trust_reload, Some(Phase::Closing));
    let owed_meta: acp::Meta = serde_json::from_value(serde_json::json!({ "fuigo/folderTrustReload": { "owed": true } })).unwrap();
    assert!(ftr::owed_in_meta(Some(&owed_meta)));
    assert!(!ftr::owed_in_meta(None));
}

/// R3: a running turn defers the close; it starts once the session is idle.
#[test]
fn ftr_a_running_turn_defers_the_close_until_idle() {
    let mut app = make_app_with_agent(SID);
    app.agents.get_mut(&AgentId(0)).unwrap().session.state = AgentState::TurnRunning;
    let _ = handle(reload_notice(SID), &mut app);
    assert_eq!(closes(&take_pending(&mut app)), 0, "never closes mid-turn");
    assert_eq!(app.agents[&AgentId(0)].folder_trust_reload, Some(Phase::Owed));
    assert!(!ftr::holds_input(&app), "an owed reload does not hold input before it starts");

    app.agents.get_mut(&AgentId(0)).unwrap().session.state = AgentState::Idle;
    assert_eq!(closes(&ftr::poll(&mut app)), 1, "idle: the close starts");
}

/// The unsent draft, the scroll position and the session id survive the close and the reload.
#[test]
fn ftr_draft_scroll_and_session_survive_the_reload() {
    let mut app = make_app_with_agent(SID);
    let id = AgentId(0);
    {
        let agent = app.agents.get_mut(&id).unwrap();
        for i in 0..4 {
            agent.scrollback.push_block(RenderBlock::user_prompt(format!("question {i}")));
            let tall = (0..8).map(|p| format!("answer {i} para {p}")).collect::<Vec<_>>().join("\n\n");
            agent.scrollback.push_block(RenderBlock::agent_message(tall));
        }
        agent.scrollback.prepare_layout(80, 6);
        agent.scrollback.goto_bottom();
        agent.scrollback.scroll_up(7);
        agent.prompt.set_text("my unsent draft");
        agent.last_seen_event_id = Some(format!("{SID}-42"));
    }
    let offset = app.agents[&id].scrollback.scroll_offset();
    let entries = app.agents[&id].scrollback.len();
    assert!(offset > 0);

    let _ = handle(reload_notice(SID), &mut app);
    assert_eq!(closes(&take_pending(&mut app)), 1);
    // A send while the reload holds input keeps the draft and sends nothing.
    let held = dispatch(Action::SendPrompt("my unsent draft".into()), &mut app);
    assert!(held.is_empty(), "held send emits nothing: {held:?}");
    assert_eq!(app.agents[&id].prompt.text(), "my unsent draft");
    assert_eq!(app.agents[&id].session.queue_len(), 0);
    assert_eq!(app.agents[&id].toast.as_ref().map(|t| t.0.as_str()), Some(ftr::HOLD_NOTICE));

    let effects = closed(&mut app, Ok("closed".into()));
    let (generation, meta) = match effects.as_slice() {
        [Effect::FolderTrustLoad { session_id, generation, meta, .. }] => {
            assert_eq!(session_id.0.as_ref(), SID, "the same session is loaded again");
            (*generation, meta.clone())
        }
        other => panic!("closed must load once: {other:?}"),
    };
    assert_eq!(meta["cursor"], serde_json::json!(format!("{SID}-42")), "only the tail replays");
    assert_eq!(meta["yoloMode"], serde_json::json!(false));
    assert!(ftr::holds_input(&app));

    let done = dispatch(
        Action::TaskComplete(TaskResult::FolderTrustLoaded { agent_id: id, session_id: acp::SessionId::new(SID), generation, result: Ok(()) }),
        &mut app,
    );
    assert!(done.iter().all(|e| !matches!(e, Effect::FolderTrustClose { .. } | Effect::FolderTrustLoad { .. })));
    let agent = app.agents.get_mut(&id).unwrap();
    assert_eq!(agent.folder_trust_reload, None);
    assert_eq!(agent.session.session_id.as_ref().map(|s| s.0.as_ref()), Some(SID));
    assert_eq!(agent.prompt.text(), "my unsent draft", "the draft survives");
    assert!(has_system_text(agent, ftr::RELOADED));
    assert_eq!(agent.scrollback.len(), entries + 1, "the transcript is kept, plus the reloaded note");
    agent.scrollback.prepare_layout(80, 6);
    assert_eq!(agent.scrollback.scroll_offset(), offset, "the scroll position survives");
    assert!(!agent.scrollback.is_follow_mode());
    assert!(!ftr::holds_input(&app), "input is released");
}

/// A close that answers `timeout` says so, releases input and never loads.
#[test]
fn ftr_a_timeout_close_tells_the_user_and_never_loads() {
    let mut app = make_app_with_agent(SID);
    app.agents.get_mut(&AgentId(0)).unwrap().prompt.set_text("keep me");
    let _ = handle(reload_notice(SID), &mut app);
    assert_eq!(closes(&take_pending(&mut app)), 1);

    let effects = closed(&mut app, Ok("timeout".into()));
    assert!(effects.iter().all(|e| !matches!(e, Effect::FolderTrustLoad { .. })), "no load after a timeout: {effects:?}");
    let agent = &app.agents[&AgentId(0)];
    assert_eq!(agent.folder_trust_reload, None);
    assert!(has_system_text(agent, ftr::CLOSE_TIMEOUT));
    assert_eq!(agent.prompt.text(), "keep me");
    assert!(!ftr::holds_input(&app));

    // No answer at all (the effect's own wait ran out) also releases input and says why.
    let _ = handle(reload_notice(SID), &mut app);
    assert_eq!(closes(&take_pending(&mut app)), 1);
    let effects = closed(&mut app, Err(ftr::CLOSE_NO_ANSWER.into()));
    assert!(effects.iter().all(|e| !matches!(e, Effect::FolderTrustLoad { .. })));
    assert!(!ftr::holds_input(&app));
    assert!(ftr::close_outcome(None) == "closed");
}

/// §8 / F7: the untrusted session's command and skill list is gone when the load starts and does not come back.
#[test]
fn ftr_untrusted_commands_are_dropped_when_the_load_starts() {
    let mut app = make_app_with_agent(SID);
    let id = AgentId(0);
    app.agents.get_mut(&id).unwrap().session.available_commands =
        vec![acp::AvailableCommand::new("untrusted-skill", "from before the grant")];
    let _ = handle(reload_notice(SID), &mut app);
    assert_eq!(closes(&take_pending(&mut app)), 1);
    let effects = closed(&mut app, Ok("closed".into()));
    let Some(Effect::FolderTrustLoad { generation, .. }) = effects.first() else { panic!("{effects:?}") };
    let generation = *generation;
    assert!(app.agents[&id].session.available_commands.is_empty(), "dropped at load start");

    let _ = dispatch(
        Action::TaskComplete(TaskResult::FolderTrustLoaded { agent_id: id, session_id: acp::SessionId::new(SID), generation, result: Ok(()) }),
        &mut app,
    );
    assert!(app.agents[&id].session.available_commands.is_empty(), "the trusted session sends its own list");
}

/// A session that never sees a grant is untouched: no close, no hold, sends go through.
#[test]
fn ftr_a_session_without_a_grant_behaves_as_before() {
    let mut app = make_app_with_agent(SID);
    let _ = handle(not_saved_notice(SID), &mut app);
    let _ = dispatch(Action::TaskComplete(loaded(SID)), &mut app);
    assert_eq!(closes(&take_pending(&mut app)), 0);
    assert!(!ftr::holds_input(&app));
    let effects = dispatch(Action::SendPrompt("hello".into()), &mut app);
    assert_eq!(app.agents[&AgentId(0)].folder_trust_reload, None);
    assert!(app.agents[&AgentId(0)].toast.as_ref().map(|t| t.0.as_str()) != Some(ftr::HOLD_NOTICE), "{effects:?}");
}
