use super::*;
use crate::acp::model_state::ModelState;
use crate::slash::commands::tests::make_ctx;
use agent_client_protocol as acp;
use std::num::NonZeroU64;

fn model_id() -> acp::ModelId {
    acp::ModelId::new("model-a")
}

fn session_id() -> acp::SessionId {
    acp::SessionId::new("sess")
}

#[test]
fn supported_window_selects_on_the_current_model() {
    let state = model_with_windows(serde_json::json!([256_000, 500_000]));
    let sid = session_id();
    let mut ctx = exec_ctx(&state, Some(&sid));

    match ContextWindowCommand.run(&mut ctx, "500k") {
        CommandResult::Action(Action::SetContextWindow {
            model_id: id,
            window,
        }) => {
            assert_eq!(model_id(), id);
            assert_eq!(NonZeroU64::new(500_000), Some(window));
        }
        other => panic!("expected SetContextWindow, got {other:?}"),
    }
    // The raw token count is accepted too
    assert!(matches!(
        ContextWindowCommand.run(&mut ctx, "500000"),
        CommandResult::Action(Action::SetContextWindow { .. })
    ));
}

#[test]
fn unsupported_window_is_refused_with_the_list() {
    let state = model_with_windows(serde_json::json!([256_000, 500_000]));
    let sid = session_id();
    let mut ctx = exec_ctx(&state, Some(&sid));

    for token in ["1m", "0", "junk", "300k", "999999999999999999999k"] {
        match ContextWindowCommand.run(&mut ctx, token) {
            CommandResult::Error(msg) => {
                assert_eq!(
                    format!("unknown context window '{token}'; use one of: 256k, 500k"),
                    msg
                );
            }
            other => panic!("expected Error for {token}, got {other:?}"),
        }
    }
}

#[test]
fn no_argument_lists_the_choices_and_marks_default_and_selection() {
    let mut state = model_with_windows(serde_json::json!([256_000, 500_000]));
    state.context_window_selection = Some(500_000);
    let mut ctx = exec_ctx(&state, None);

    match ContextWindowCommand.run(&mut ctx, "") {
        CommandResult::Message(msg) => {
            assert!(msg.contains("256k (default)"), "{msg}");
            assert!(msg.contains("500k (active)"), "{msg}");
            assert!(!msg.contains("256k (default) (active)"), "{msg}");
        }
        other => panic!("expected Message, got {other:?}"),
    }
}

#[test]
fn a_model_without_a_list_says_so() {
    for state in [
        model_with_windows(serde_json::json!([])),
        model_with_windows(serde_json::json!([256_000])),
    ] {
        assert!(
            ContextWindowCommand
                .suggest_args(&app_ctx(&state), "")
                .is_none()
        );
        let sid = session_id();
        let mut ctx = exec_ctx(&state, Some(&sid));
        for args in ["256k", ""] {
            assert!(matches!(
                ContextWindowCommand.run(&mut ctx, args),
                CommandResult::Error(msg) if msg.contains("no selectable context windows")
            ));
        }
    }
}

#[test]
fn a_selection_the_model_does_not_list_is_not_shown() {
    let mut state = model_with_windows(serde_json::json!([256_000, 500_000]));
    state.context_window_selection = Some(900_000);
    assert_eq!(state.get_context_window(), Some(256_000));
    state.context_window_selection = Some(500_000);
    assert_eq!(state.get_context_window(), Some(500_000));
    state.context_window_selection = None;
    assert_eq!(state.get_context_window(), Some(256_000));
}

#[test]
fn suggest_marks_default_and_active_rows() {
    let mut state = model_with_windows(serde_json::json!([256_000, 500_000]));
    state.context_window_selection = Some(500_000);

    let items = ContextWindowCommand
        .suggest_args(&app_ctx(&state), "")
        .expect("a two-window model supports suggestions");

    let [first, second] = items.as_slice() else {
        panic!("expected 2 items: {items:?}");
    };
    assert_eq!(first.display, "256k");
    assert_eq!(first.description, "Default • 256000 tokens");
    assert_eq!(second.display, "500k (active)");
    assert_eq!(second.insert_text, "500k");
}

#[test]
fn missing_model_or_session_errors() {
    let empty = ModelState::default();
    let sid = session_id();
    let mut ctx = exec_ctx(&empty, Some(&sid));

    assert!(matches!(
        ContextWindowCommand.run(&mut ctx, "256k"),
        CommandResult::Error(msg) if msg.contains("No active model")
    ));

    let state = model_with_windows(serde_json::json!([256_000, 500_000]));
    let mut ctx = exec_ctx(&state, None);

    assert!(matches!(
        ContextWindowCommand.run(&mut ctx, "256k"),
        CommandResult::Error(msg) if msg.contains("No active session")
    ));
}

#[test]
fn format_and_parse_round_trip() {
    for (window, label) in [(256_000, "256k"), (500_000, "500k"), (1_000_000, "1m")] {
        assert_eq!(format_window(window), label);
        assert_eq!(parse_window_token(label), Some(window));
    }

    assert_eq!(parse_window_token("500000"), Some(500_000));
    assert_eq!(parse_window_token("500K"), Some(500_000));
    assert_eq!(parse_window_token("junk"), None);
}

fn model_with_windows(windows: serde_json::Value) -> ModelState {
    let id = model_id();
    let mut info = acp::ModelInfo::new(id.clone(), "Model A".to_string());
    let meta = serde_json::json!({
        "totalContextTokens": 256_000,
        "contextWindows": windows,
    });
    info.meta = meta.as_object().cloned();
    let mut state = ModelState::default();
    state.available.insert(id.clone(), info);
    state.current = Some(id);
    state
}

fn exec_ctx<'a>(
    models: &'a ModelState,
    session_id: Option<&'a acp::SessionId>,
) -> CommandExecCtx<'a> {
    CommandExecCtx {
        session_id,
        ..make_ctx(models)
    }
}

fn app_ctx(models: &ModelState) -> AppCtx<'_> {
    AppCtx {
        models,
        cwd: std::path::Path::new("."),
        has_session_announcements: false,
        billing_surface_visible: true,
        usage_command_visible: true,
        workflows_available: true,
        saved_workflows: &[],
        workflow_runs: &[],
        screen_mode: crate::app::ScreenMode::Fullscreen,
        current_title: None,
    }
}
