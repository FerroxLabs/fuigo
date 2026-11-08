//! F11: `/trust` opens the trust screens, and a grant from them reaches the shell exactly as typed `/hooks-trust`
//! does, so it settles through the one grant path (`settle_session_grant`, then the F5 reload; shell side proven by
//! `fuigo-shell/tests/f5b3_session_grant_acp.rs`).

use super::*;
use crate::app::app_view::InputOutcome;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// The agent-bound prompts in `effects`, without their random prompt ids.
fn sent_prompts(effects: &[Effect]) -> Vec<(AgentId, String, String)> {
    effects
        .iter()
        .filter_map(|e| match e {
            Effect::SendPrompt { agent_id, session_id, text, .. } => {
                Some((*agent_id, session_id.0.to_string(), text.clone()))
            }
            _ => None,
        })
        .collect()
}

fn press(app: &mut AppView, c: char) -> InputOutcome {
    let agent = app.agents.get_mut(&AgentId(0)).unwrap();
    agent.handle_modal_key(&KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
}

fn open_trust(app: &mut AppView, status: crate::views::trust_modal::TrustStatus) {
    let effects = dispatch(Action::SendPrompt("/trust".into()), app);
    assert!(sent_prompts(&effects).is_empty(), "/trust is a pager screen in the full-screen app: nothing reaches the agent");
    let agent = app.agents.get_mut(&AgentId(0)).unwrap();
    let Some(crate::views::modal::ActiveModal::FolderTrust { state }) = agent.active_modal.as_mut() else {
        panic!("/trust opens the folder trust screens");
    };
    // The build under test is a local build (folder trust off); pin the status the screen shows.
    state.snapshot.status = status;
    state.snapshot.key = Some(state.snapshot.cwd.clone());
}

#[test]
fn f11_trust_grant_settles_like_hooks_trust() {
    let mut typed = test_app_with_agent();
    let expected = sent_prompts(&dispatch(Action::SendPrompt("/hooks-trust".into()), &mut typed));
    assert_eq!(expected.len(), 1, "typed /hooks-trust goes to the shell");

    let mut app = test_app_with_agent();
    open_trust(&mut app, crate::views::trust_modal::TrustStatus::Undecided);
    assert!(matches!(press(&mut app, 't'), InputOutcome::Changed), "t asks to confirm");
    let InputOutcome::Action(action) = press(&mut app, 'y') else {
        panic!("y confirms the grant");
    };
    assert!(app.agents[&AgentId(0)].active_modal.is_none(), "the grant closes the screens");
    let got = sent_prompts(&dispatch(action, &mut app));
    assert_eq!(got, expected, "the grant is the shell's /hooks-trust for the same session");
}

#[test]
fn f11_trust_revoke_this_folder_is_hooks_untrust() {
    let mut typed = test_app_with_agent();
    let expected = sent_prompts(&dispatch(Action::SendPrompt("/hooks-untrust".into()), &mut typed));
    assert_eq!(expected.len(), 1);

    let mut app = test_app_with_agent();
    open_trust(&mut app, crate::views::trust_modal::TrustStatus::Trusted);
    press(&mut app, 'u');
    let InputOutcome::Action(action) = press(&mut app, 'y') else {
        panic!("y confirms the revoke");
    };
    assert_eq!(sent_prompts(&dispatch(action, &mut app)), expected);
}

#[test]
fn f11_trust_revoke_other_folder_keeps_screens_and_toasts() {
    let mut app = test_app_with_agent();
    open_trust(&mut app, crate::views::trust_modal::TrustStatus::Trusted);
    let other = std::path::PathBuf::from("/nonexistent-f11/other");
    let effects = dispatch(Action::DeclineFolderTrust(other), &mut app);
    assert!(sent_prompts(&effects).is_empty(), "another folder's revoke sends nothing to the agent");
    assert!(
        matches!(app.agents[&AgentId(0)].active_modal, Some(crate::views::modal::ActiveModal::FolderTrust { .. })),
        "the list stays open"
    );
    assert!(read_toast(&app).contains("Stopped trusting /nonexistent-f11/other"), "{}", read_toast(&app));
}

/// Fable r1 M1: a confirm takes `y` only; `Enter` (and `Y`) cancel it, as the screen and the docs say.
#[test]
fn r1m1_enter_does_not_confirm_a_grant() {
    for key in [KeyCode::Enter, KeyCode::Char('Y')] {
        let mut app = test_app_with_agent();
        open_trust(&mut app, crate::views::trust_modal::TrustStatus::Undecided);
        assert!(matches!(press(&mut app, 't'), InputOutcome::Changed), "t asks to confirm");
        let agent = app.agents.get_mut(&AgentId(0)).unwrap();
        let outcome = agent.handle_modal_key(&KeyEvent::new(key, KeyModifiers::NONE));
        assert!(!matches!(outcome, InputOutcome::Action(_)), "{key:?} granted the folder");
        assert!(
            matches!(app.agents[&AgentId(0)].active_modal, Some(crate::views::modal::ActiveModal::FolderTrust { .. })),
            "{key:?} cancels the confirm and keeps the screens"
        );
    }
}

/// Fable r1 M2: when the "no" for another folder cannot be saved, the toast says the folder is still trusted (the
/// agent and new sessions decide from the store), and keeps the error.
#[test]
fn r1m2_an_unsaved_decline_says_the_folder_is_still_trusted() {
    let error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "read-only home");
    let toast = crate::app::dispatch::status::decline_toast("/r1m2/other", &Err(error));
    assert!(toast.contains("still trusted"), "{toast}");
    assert!(toast.contains("read-only home"), "{toast}");
    assert!(!toast.starts_with("Stopped trusting"), "{toast}");
}
