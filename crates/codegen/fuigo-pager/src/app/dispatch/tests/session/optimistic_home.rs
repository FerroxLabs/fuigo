//! The session is created when the TUI opens on Welcome; the first interaction reveals it.

use super::*;
use crate::app::app_view::{InputOutcome, PasteProvenance};
use crate::app::dispatch::session::lifecycle::{
    handle_session_created, handle_session_failed, maybe_create_home_session,
};
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

fn key_event(code: KeyCode, mods: KeyModifiers) -> Event {
    Event::Key(KeyEvent {
        code,
        modifiers: mods,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    })
}

/// Feed `ev` to Welcome, require `ActionThenForward(LeaveHome)`, and run it through the event loop's forward path.
fn leave_home_with(app: &mut AppView, ev: &Event) -> Vec<Effect> {
    let outcome = app.handle_input(ev);
    let InputOutcome::ActionThenForward(Action::LeaveHome) = outcome else {
        panic!("expected ActionThenForward(LeaveHome), got {outcome:?}");
    };
    crate::app::event_loop::dispatch_then_forward(
        Action::LeaveHome,
        ev,
        std::time::Instant::now(),
        PasteProvenance::Terminal,
        app,
    )
}

fn creates_session(effects: &[Effect]) -> bool {
    effects
        .iter()
        .any(|e| matches!(e, Effect::CreateSession { .. }))
}

fn bind_home_session(app: &mut AppView) {
    let home = app.home_session_agent.expect("home session");
    let _ = handle_session_created(app, home, acp::SessionId::new("home-sid"), None, None);
}

#[test]
fn drain_without_session_intent_creates_home_session_and_stays_on_welcome() {
    let mut app = test_app();
    assert!(app.session_startup_allowed());
    assert!(matches!(app.active_view, ActiveView::Welcome));
    assert!(app.agents.is_empty());

    let effects = drain_startup_actions(&mut app);

    assert!(
        matches!(app.active_view, ActiveView::Welcome),
        "home must stay up after the optimistic create, got {:?}",
        app.active_view
    );
    assert_eq!(app.agents.len(), 1);
    assert_eq!(app.home_session_agent, Some(AgentId(0)));
    assert!(
        creates_session(&effects),
        "expected CreateSession, got {effects:?}"
    );
}

#[test]
fn maybe_create_home_session_is_idempotent() {
    let mut app = test_app();
    let first = maybe_create_home_session(&mut app);
    let second = maybe_create_home_session(&mut app);
    assert_eq!(app.agents.len(), 1);
    assert!(!first.is_empty());
    assert!(
        second.is_empty(),
        "a second create must not spawn another agent"
    );
}

#[test]
fn maybe_create_home_session_skips_when_gated() {
    let mut app = test_app();
    app.auth_state = AuthState::Pending { error: None };
    let effects = maybe_create_home_session(&mut app);
    assert!(effects.is_empty());
    assert!(app.agents.is_empty());
    assert!(app.home_session_agent.is_none());
}

#[test]
fn maybe_create_home_session_skips_when_startup_will_leave_home() {
    let mut app = test_app();
    app.deferred_startup.prompt = Some("from cli".into());
    let effects = maybe_create_home_session(&mut app);
    assert!(effects.is_empty());
    assert!(app.agents.is_empty());
    assert!(app.home_session_agent.is_none());
}

#[test]
fn maybe_create_home_session_skips_when_access_blocked() {
    let mut app = test_app();
    app.gate = Some(fuigo_shell::auth::GateInfo {
        message: "paywall".into(),
    });
    let effects = maybe_create_home_session(&mut app);
    assert!(effects.is_empty());
    assert!(app.agents.is_empty());
}

#[test]
fn maybe_create_home_session_does_not_consume_pending_chat() {
    let mut app = test_app();
    app.deferred_startup.pending_chat = true;
    maybe_create_home_session(&mut app);
    assert!(
        app.deferred_startup.pending_chat,
        "optimistic home must not steal leftover /chat"
    );
    assert!(
        app.home_session()
            .is_none_or(|a| !a.chat_kind && !a.conversation_entry)
    );
}

#[test]
fn welcome_keystroke_reveals_home_session_and_types() {
    for focused in [true, false] {
        let mut app = test_app();
        maybe_create_home_session(&mut app);
        let home = app.home_session_agent.expect("home session");
        app.welcome_prompt_focused = focused;
        app.welcome_menu_index = (!focused).then_some(0);

        let effects = leave_home_with(&mut app, &key_event(KeyCode::Char('h'), KeyModifiers::NONE));
        assert!(
            !creates_session(&effects),
            "keystroke must reuse the optimistic session, got {effects:?}"
        );
        assert!(matches!(app.active_view, ActiveView::Agent(id) if id == home));
        assert!(app.home_session_agent.is_none());
        assert_eq!(app.agents.len(), 1);
        assert_eq!(app.agents.get(&home).map(|a| a.prompt.text()), Some("h"));
        assert!(app.welcome_menu_index.is_none());
    }
}

#[test]
fn welcome_paste_reveals_home_session() {
    let mut app = test_app();
    maybe_create_home_session(&mut app);
    let home = app.home_session_agent.expect("home session");

    let effects = leave_home_with(&mut app, &Event::Paste("fix the bug".into()));
    assert!(!creates_session(&effects));
    assert!(matches!(app.active_view, ActiveView::Agent(id) if id == home));
    assert_eq!(
        app.agents.get(&home).map(|a| a.prompt.text()),
        Some("fix the bug")
    );
}

#[test]
fn welcome_shift_tab_reveals_home_session_in_plan_mode() {
    let mut app = test_app();
    maybe_create_home_session(&mut app);
    let home = app.home_session_agent.expect("home session");

    let effects = leave_home_with(&mut app, &key_event(KeyCode::BackTab, KeyModifiers::SHIFT));
    assert!(!creates_session(&effects));
    assert!(matches!(app.active_view, ActiveView::Agent(id) if id == home));
    let Some(agent) = app.agents.get(&home) else {
        panic!("expected agent {home:?}");
    };
    assert!(
        agent.plan_mode_pending.unwrap_or(agent.plan_mode_active),
        "the forwarded Shift+Tab must enter Plan on the revealed session"
    );
}

#[test]
fn welcome_enter_reveals_home_session_and_carries_the_draft() {
    let mut app = test_app();
    maybe_create_home_session(&mut app);
    let home = app.home_session_agent.expect("home session");
    app.welcome_prompt_focused = true;
    app.welcome_prompt.set_text("hello");

    let outcome = app.handle_input(&key_event(KeyCode::Enter, KeyModifiers::NONE));
    let InputOutcome::Action(Action::LeaveHome) = outcome else {
        panic!("expected LeaveHome, got {outcome:?}");
    };
    let effects = dispatch(Action::LeaveHome, &mut app);
    assert!(!creates_session(&effects), "got {effects:?}");
    assert!(matches!(app.active_view, ActiveView::Agent(id) if id == home));
    assert_eq!(app.agents.get(&home).map(|a| a.prompt.text()), Some("hello"));
    assert_eq!(app.welcome_prompt.text(), "");
}

#[test]
fn welcome_shift_tab_honors_always_worktree() {
    let mut app = test_app_git();
    app.new_session_worktree_mode = crate::app::app_view::WorktreeMode::Always;
    assert!(maybe_create_home_session(&mut app).is_empty());

    let effects = leave_home_with(&mut app, &key_event(KeyCode::BackTab, KeyModifiers::SHIFT));
    assert!(
        effects
            .iter()
            .any(|e| matches!(e, Effect::CreateWorktreeSession { .. })),
        "got {effects:?}"
    );
    let ActiveView::Agent(id) = app.active_view else {
        panic!("Shift+Tab must leave home, got {:?}", app.active_view);
    };
    let Some(agent) = app.agents.get(&id) else {
        panic!("expected agent {id:?}");
    };
    assert!(agent.plan_mode_pending.unwrap_or(agent.plan_mode_active));
}

/// Skills that reached the hidden home session must be in the revealed composer's slash catalog.
#[test]
fn skills_on_the_hidden_home_session_reach_the_revealed_composer() {
    let mut app = test_app();
    maybe_create_home_session(&mut app);
    let home = app.home_session_agent.expect("home session");
    {
        let agent = app.agents.get_mut(&home).unwrap();
        agent.session.available_commands = vec![acp::AvailableCommand::new(
            "my-skill".to_string(),
            "A skill".to_string(),
        )];
        agent.session.available_commands_generation += 1;
    }

    let _ = leave_home_with(&mut app, &key_event(KeyCode::Char('/'), KeyModifiers::NONE));
    assert!(
        app.agents.get(&home).is_some_and(|a| a
            .prompt
            .slash_controller
            .registry()
            .get("my-skill")
            .is_some()),
        "reveal must sync the husk's ACP commands into the composer"
    );
}

#[test]
fn worktree_from_welcome_abandons_home() {
    let mut app = test_app_git();
    maybe_create_home_session(&mut app);
    bind_home_session(&mut app);
    let home = app.home_session_agent.expect("home session");

    let effects = dispatch(
        Action::NewWorktreeSession {
            load_session_id: None,
            label: None,
            git_ref: None,
        },
        &mut app,
    );
    assert!(
        !app.agents.contains_key(&home),
        "Ctrl+W must drop the unused in-cwd husk"
    );
    assert!(app.home_session_agent.is_none());
    assert!(
        effects.iter().any(|e| matches!(
            e,
            Effect::DeleteSession { session_id, after, .. }
                if session_id == "home-sid" && *after == crate::app::actions::AfterSessionDelete::UnusedHusk
        )),
        "the bound husk must be deleted on the agent, got {effects:?}"
    );
    let ActiveView::Agent(id) = app.active_view else {
        panic!("Ctrl+W must leave home, got {:?}", app.active_view);
    };
    assert_ne!(id, home);
}

#[test]
fn dashboard_from_welcome_exits_back_to_welcome() {
    let mut app = test_app();
    maybe_create_home_session(&mut app);
    let home = app.home_session_agent.expect("home session");

    let _ = crate::app::dispatch::dashboard::dispatch_open_dashboard(&mut app);
    assert!(matches!(app.active_view, ActiveView::AgentDashboard));
    assert_eq!(app.home_session_agent, Some(home));

    let _ = crate::app::dispatch::dashboard::dispatch_exit_dashboard(&mut app);
    assert!(
        matches!(app.active_view, ActiveView::Welcome),
        "closing the dashboard must not reveal the unused home session, got {:?}",
        app.active_view
    );
    assert_eq!(app.home_session_agent, Some(home));
    assert!(app.agents.contains_key(&home));
}

#[test]
fn load_from_welcome_abandons_home() {
    let mut app = test_app();
    maybe_create_home_session(&mut app);
    let home = app.home_session_agent.expect("home session");

    let _ = dispatch(
        Action::LoadSession("resume-me".into(), None, false),
        &mut app,
    );
    assert!(
        !app.agents.contains_key(&home),
        "resume must drop the unused home husk"
    );
    assert!(app.home_session_agent.is_none());
    assert!(matches!(app.active_view, ActiveView::Agent(_)));
}

#[test]
fn explicit_new_session_from_welcome_abandons_home() {
    let mut app = test_app();
    maybe_create_home_session(&mut app);
    bind_home_session(&mut app);
    let home = app.home_session_agent.expect("home session");

    let effects = dispatch(Action::NewSession, &mut app);
    assert!(!app.agents.contains_key(&home));
    assert!(app.home_session_agent.is_none());
    assert!(creates_session(&effects), "got {effects:?}");
    assert!(
        effects
            .iter()
            .any(|e| matches!(e, Effect::DeleteSession { session_id, .. } if session_id == "home-sid")),
        "got {effects:?}"
    );
}

#[test]
fn session_failed_for_home_clears_the_husk_and_stays_on_welcome() {
    let mut app = test_app();
    maybe_create_home_session(&mut app);
    let home = app.home_session_agent.expect("home session");

    let _ = handle_session_failed(&mut app, home, "boom".into());
    assert!(app.home_session_agent.is_none());
    assert!(app.optimistic_home_husk.is_none());
    assert!(!app.agents.contains_key(&home));
    assert!(matches!(app.active_view, ActiveView::Welcome));

    // A later keystroke opens a fresh session instead of dereferencing the failed husk.
    let effects = leave_home_with(&mut app, &key_event(KeyCode::Char('x'), KeyModifiers::NONE));
    assert!(creates_session(&effects), "got {effects:?}");
}
