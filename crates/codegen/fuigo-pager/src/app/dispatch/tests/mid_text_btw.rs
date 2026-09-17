//! A mid-message `/btw` token hoists the whole submission into the side question.

use super::*;
use crate::views::btw_overlay::BtwOverlayState;
use pretty_assertions::assert_eq;

const TYPED: &str = "explain the controller. /btw what is a WBC";
const QUESTION: &str = "explain the controller. what is a WBC";

fn assert_fullscreen_side_question(effects: &[Effect], question: &str) {
    assert!(
        matches!(
            effects,
            [Effect::SendBtw { question: sent, minimal_request_id: None, .. }] if sent == question
        ),
        "expected exactly one fullscreen /btw send of {question:?}, got {effects:?}"
    );
}

#[test]
fn mid_text_btw_sends_whole_message_as_side_question() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);

    let effects = dispatch(Action::SendPrompt(TYPED.to_owned()), &mut app);

    assert_fullscreen_side_question(&effects, QUESTION);
    let agent = &app.agents[&id];
    assert!(
        matches!(
            &agent.btw_state,
            Some(BtwOverlayState::Loading { question }) if question == QUESTION
        ),
        "{:?}",
        agent.btw_state
    );
    assert_eq!("", agent.prompt.text());
}

#[test]
fn mid_text_btw_while_turn_running_bypasses_queue() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    app.agents.get_mut(&id).unwrap().session.state = AgentState::TurnRunning;

    let effects = dispatch(Action::SendPrompt(TYPED.to_owned()), &mut app);

    assert_fullscreen_side_question(&effects, QUESTION);
    assert!(app.agents[&id].session.pending_prompts.is_empty());
}

#[test]
fn mid_text_btw_history_keeps_typed_text() {
    let mut app = test_app_with_agent();

    dispatch(Action::SendPrompt(TYPED.to_owned()), &mut app);

    assert_eq!(
        vec![TYPED.to_owned()],
        app.agents[&AgentId(0)].session.prompt_history
    );
}

#[test]
fn leading_unknown_command_with_btw_is_not_hoisted() {
    let mut app = test_app_with_agent();

    let effects = dispatch(Action::SendPrompt("/nope hi /btw q".to_owned()), &mut app);

    assert!(
        matches!(
            effects.as_slice(),
            [Effect::SendPrompt { text, .. }] if text == "/nope hi /btw q"
        ),
        "{effects:?}"
    );
}

#[test]
fn literal_follow_up_with_btw_is_not_hoisted() {
    let mut app = test_app_with_agent();

    let effects = dispatch(Action::SubmitFollowUp("prose /btw q".to_owned()), &mut app);

    assert!(
        matches!(
            effects.as_slice(),
            [Effect::SendPrompt { text, .. }] if text == "prose /btw q"
        ),
        "{effects:?}"
    );
}

#[test]
fn mid_text_other_builtin_still_passes_through() {
    let mut app = test_app_with_agent();

    let effects = dispatch(Action::SendPrompt("great /compact go".to_owned()), &mut app);

    assert!(
        matches!(
            effects.as_slice(),
            [Effect::SendPrompt { text, .. }] if text == "great /compact go"
        ),
        "{effects:?}"
    );
}
