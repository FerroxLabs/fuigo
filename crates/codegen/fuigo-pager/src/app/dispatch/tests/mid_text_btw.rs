//! `/btw` starts a side question only at the start of the message; typed later in the text it is plain text.

use super::*;
use crate::views::btw_overlay::BtwOverlayState;
use pretty_assertions::assert_eq;

const TYPED: &str = "explain the controller. /btw what is a WBC";
const QUESTION: &str = "what is a WBC";

fn assert_fullscreen_side_question(effects: &[Effect], question: &str) {
    assert!(
        matches!(
            effects,
            [Effect::SendBtw { question: sent, request_id: Some(_), .. }] if sent == question
        ),
        "expected exactly one fullscreen /btw send of {question:?}, got {effects:?}"
    );
}

fn assert_plain_prompt(effects: &[Effect], text: &str) {
    assert!(
        matches!(effects, [Effect::SendPrompt { text: sent, .. }] if sent == text),
        "expected the message to go to the main conversation as typed ({text:?}), got {effects:?}"
    );
}

#[test]
fn mid_text_btw_is_plain_text() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);

    let effects = dispatch(Action::SendPrompt(TYPED.to_owned()), &mut app);

    assert_plain_prompt(&effects, TYPED);
    assert!(app.agents[&id].btw_state.is_none());
}

#[test]
fn leading_btw_is_still_a_side_question() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);

    let effects = dispatch(Action::SendPrompt(format!("/btw {QUESTION}")), &mut app);

    assert_fullscreen_side_question(&effects, QUESTION);
    assert!(
        matches!(
            &app.agents[&id].btw_state,
            Some(BtwOverlayState::Loading { question }) if question == QUESTION
        ),
        "{:?}",
        app.agents[&id].btw_state
    );
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

    assert_plain_prompt(&effects, "/nope hi /btw q");
}

#[test]
fn literal_follow_up_with_btw_is_not_hoisted() {
    let mut app = test_app_with_agent();

    let effects = dispatch(Action::SubmitFollowUp("prose /btw q".to_owned()), &mut app);

    assert_plain_prompt(&effects, "prose /btw q");
}

#[test]
fn mid_text_other_builtin_still_passes_through() {
    let mut app = test_app_with_agent();

    let effects = dispatch(Action::SendPrompt("great /compact go".to_owned()), &mut app);

    assert_plain_prompt(&effects, "great /compact go");
}

fn typed_with_leading_image_chip(app: &mut AppView, tail: &str) -> String {
    let prompt = &mut app.agents.get_mut(&AgentId(0)).unwrap().prompt;
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
    prompt.append_text(tail);
    let typed = prompt.text().to_owned();
    assert!(typed.starts_with("[Image #1] "), "{typed:?}");
    typed
}

/// A leading image chip is composer chrome, not text the model should read.
/// `[Image #1] /btw q` still begins with the command once the chip is stripped, and the marker never reaches the side question.
#[test]
fn leading_image_chip_is_not_carried_into_the_side_question() {
    let mut app = test_app_with_agent();
    let typed = typed_with_leading_image_chip(&mut app, &format!("/btw {QUESTION}"));

    let effects = dispatch(Action::SendPrompt(typed), &mut app);

    assert_fullscreen_side_question(&effects, QUESTION);
}

#[test]
fn image_chip_then_text_then_btw_is_plain_text() {
    let mut app = test_app_with_agent();
    let typed = typed_with_leading_image_chip(&mut app, TYPED);

    let effects = dispatch(Action::SendPrompt(typed), &mut app);

    assert!(
        !effects.iter().any(|e| matches!(e, Effect::SendBtw { .. })),
        "{effects:?}"
    );
}
