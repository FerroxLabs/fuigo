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

/// A leading image chip is composer chrome, not text the model should read.
/// The hoist scans the chip-stripped submission, so `[Image #1] explain /btw q`
/// asks `explain q` — the `[Image #1]` marker never reaches the side question.
#[test]
fn leading_image_chip_is_not_carried_into_the_side_question() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    let typed = {
        let prompt = &mut app.agents.get_mut(&id).unwrap().prompt;
        prompt
            .insert_image(crate::prompt_images::PastedImage {
                element_id: fuigo_ratatui_textarea::ElementId::from_raw(0),
                display_number: 0,
                mime_type: "image/png".into(),
                dimensions: Some((100, 80)),
                byte_len: 2048,
                encoded_bytes: Some(vec![0u8; 16].into()),
                source_path: None,
                staged_temp_path: None,
                session_image_path: None,
                preview: crate::prompt_images::PromptImagePreview::default(),
            })
            .unwrap();
        prompt.append_text("explain the controller. /btw what is a WBC");
        prompt.text().to_owned()
    };
    assert!(typed.starts_with("[Image #1] "), "{typed:?}");

    let effects = dispatch(Action::SendPrompt(typed), &mut app);

    assert_fullscreen_side_question(&effects, QUESTION);
}
