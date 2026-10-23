//! Tests for conversation rewind dispatchers and prompt-entry lookup.

use super::*;

#[test]
fn cancel_does_not_rewind_when_in_flight_block_committed() {
    // Minimal-mode regression: a user-prompt block commits to native scrollback immediately (it is never `is_running`)
    // A committed block can't be "un-printed", so cancelling must not rewind it
    // A rewind would `remove_entry` it from state while the printed copy stays on screen, then restore the text into the input, showing it twice
    // The dogfood bug: double-Esc on a just-promoted queued prompt
    let mut app = test_app_with_agent();
    let id = AgentId(0);

    dispatch(Action::SendPrompt("queued prompt".into()), &mut app);
    assert!(app.agents[&id].session.in_flight_prompt.is_some());
    assert_eq!(app.agents[&id].scrollback.len(), 1);

    // Simulate minimal's commit pass printing the user block into native scrollback (sets the entry's `committed` flag)
    let entry_id = app.agents[&id]
        .session
        .in_flight_prompt
        .as_ref()
        .unwrap()
        .scrollback_entry;
    let idx = app.agents[&id].scrollback.index_of_id(entry_id).unwrap();
    app.agents
        .get_mut(&id)
        .unwrap()
        .scrollback
        .mark_committed(idx);

    let effects = dispatch(Action::CancelTurn, &mut app);
    assert_eq!(effects.len(), 1);
    assert!(matches!(&effects[0], Effect::CancelTurn { .. }));

    // Standard cancel, not the rewind: the prompt is not restored to the input and the committed block stays in scrollback (no duplicate)
    assert!(
        app.agents[&id].prompt.text().is_empty(),
        "committed in-flight block must not be rewound into the input"
    );
    assert_eq!(
        app.agents[&id].scrollback.len(),
        1,
        "committed block must stay in scrollback (it's already printed)"
    );
    assert!(app.agents[&id].session.state.is_cancelling());
}

#[test]
fn rewind_then_resubmit_drains_immediately_and_discards_orphan() {
    // After a rewind, state is Idle so a follow-up prompt can drain without waiting for the cancelled turn's PromptResponse
    let mut app = test_app_with_agent();
    let id = AgentId(0);

    dispatch(Action::SendPrompt("first".into()), &mut app);
    let first_pid = app.agents[&id].session.current_prompt_id.clone();
    assert!(first_pid.is_some());
    dispatch(Action::CancelTurn, &mut app);
    assert!(app.agents[&id].session.state.is_idle());
    assert!(app.agents[&id].session.current_prompt_id.is_none());

    // User edits and re-submits without waiting.
    let effects = dispatch(Action::SendPrompt("second".into()), &mut app);
    assert_eq!(effects.len(), 1);
    assert!(matches!(&effects[0], Effect::SendPrompt { text, .. } if text == "second"));
    assert!(app.agents[&id].session.state.is_turn_running());
    let second_pid = app.agents[&id].session.current_prompt_id.clone();
    assert!(second_pid.is_some());
    assert_ne!(first_pid, second_pid);

    // The cancelled "first" PromptResponse arrives mid-second-turn, carrying first_pid
    // It mismatches current_prompt_id (second_pid), so it is discarded; state for "second" is untouched
    dispatch(
        Action::TaskComplete(TaskResult::PromptResponse {
            agent_id: id,
            result: Ok(acp::PromptResponse::new(acp::StopReason::Cancelled).meta(
                serde_json::json!({ "promptId": first_pid })
                    .as_object()
                    .cloned(),
            )),
            http_status: None,
            verdicts: None,
            prompt_id: None,
        }),
        &mut app,
    );
    assert!(app.agents[&id].session.state.is_turn_running());
    assert_eq!(app.agents[&id].session.current_prompt_id, second_pid);
}

/// Ctrl+C rewind cancel carries the rewound turn's prompt id.
#[test]
fn cancel_rewind_effect_carries_the_rewound_prompt_id() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);

    dispatch(Action::SendPrompt("rewind me".into()), &mut app);
    let pid = app.agents[&id]
        .session
        .current_prompt_id
        .clone()
        .expect("turn running");

    let effects = dispatch(Action::CancelTurn, &mut app);
    assert!(
        matches!(
            effects.as_slice(),
            [Effect::CancelTurn {
                rewind_prompt_id: Some(p),
                ..
            }] if *p == pid
        ),
        "rewind cancel must carry the captured prompt id, got {effects:?}"
    );
    let agent = &app.agents[&id];
    assert!(agent.session.state.is_idle());
    assert_eq!(agent.prompt.text(), "rewind me");
    assert!(agent.is_rewound_prompt(&pid));
}

fn shared_row(id: &str, text: &str, position: usize) -> crate::app::prompt_queue::QueueEntryWire {
    crate::app::prompt_queue::QueueEntryWire {
        id: id.into(),
        version: 1,
        owner: None,
        last_editor: None,
        kind: "prompt".into(),
        text: text.into(),
        position,
        combined_texts: None,
    }
}

/// An early Ctrl+C can land before the server's `queue/changed` removes the just-sent prompt's own row from the
/// shared queue. That row is the in-flight prompt itself, not a held follow-up: the rewind still happens, drops
/// the row locally, and the cancel carries the rewound id.
#[test]
fn cancel_rewinds_when_the_only_shared_row_is_the_in_flight_prompt() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);

    dispatch(Action::SendPrompt("rewind me".into()), &mut app);
    let pid = app.agents[&id]
        .session
        .current_prompt_id
        .clone()
        .expect("turn running");
    app.agents.get_mut(&id).unwrap().shared_queue = vec![shared_row(&pid, "rewind me", 0)];

    let effects = dispatch(Action::CancelTurn, &mut app);
    assert!(
        matches!(
            effects.as_slice(),
            [Effect::CancelTurn {
                rewind_prompt_id: Some(p),
                ..
            }] if *p == pid
        ),
        "the in-flight prompt's own row must not block the rewind, got {effects:?}"
    );
    let agent = &app.agents[&id];
    assert!(agent.session.state.is_idle());
    assert_eq!(agent.prompt.text(), "rewind me");
    assert!(
        agent.shared_queue.is_empty(),
        "the rewound prompt's own row is dropped locally"
    );
    assert!(agent.is_rewound_prompt(&pid));
}

/// Any OTHER queued row is a follow-up held behind the turn: the standard cancel runs so the agent drains it next.
#[test]
fn cancel_does_not_rewind_when_another_shared_row_is_queued() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);

    dispatch(Action::SendPrompt("keep running".into()), &mut app);
    let pid = app.agents[&id]
        .session
        .current_prompt_id
        .clone()
        .expect("turn running");
    app.agents.get_mut(&id).unwrap().shared_queue = vec![
        shared_row(&pid, "keep running", 0),
        shared_row("p2", "follow-up", 1),
    ];

    let effects = dispatch(Action::CancelTurn, &mut app);
    assert!(
        matches!(
            effects.as_slice(),
            [Effect::CancelTurn {
                rewind_prompt_id: None,
                ..
            }]
        ),
        "a held follow-up must force the standard cancel, got {effects:?}"
    );
    let agent = &app.agents[&id];
    assert!(
        agent.prompt.text().is_empty(),
        "no rewind into the composer"
    );
    assert_eq!(
        agent.shared_queue.len(),
        2,
        "the standard cancel leaves the queue to the agent"
    );
    assert!(!agent.is_rewound_prompt(&pid));
}

/// No prompt id means no optimistic rewind; send a standard cancel.
#[test]
fn cancel_without_prompt_id_skips_rewind_and_sends_normal_cancel() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);

    dispatch(Action::SendPrompt("cannot rewind".into()), &mut app);
    assert!(app.agents[&id].session.in_flight_prompt.is_some());
    // Simulate the id being gone while the stash survives.
    app.agents.get_mut(&id).unwrap().session.current_prompt_id = None;

    let effects = dispatch(Action::CancelTurn, &mut app);
    assert!(
        matches!(
            effects.as_slice(),
            [Effect::CancelTurn {
                rewind_prompt_id: None,
                ..
            }]
        ),
        "id-less cancel must not request a rewind, got {effects:?}"
    );
    let agent = &app.agents[&id];
    assert!(
        agent.prompt.text().is_empty(),
        "no optimistic composer restore without an id"
    );
    assert_eq!(
        agent.scrollback.len(),
        1,
        "the prompt block stays in scrollback (standard cancel)"
    );
    assert!(agent.session.state.is_cancelling());
}

/// Rewind point for the fixture's single prompt.
fn rewind_point(prompt_index: usize) -> crate::views::rewind::RewindPointInfo {
    crate::views::rewind::RewindPointInfo {
        prompt_index,
        created_at: String::new(),
        num_file_snapshots: 0,
        prompt_preview: Some("fix the bug".into()),
        has_file_changes: false,
    }
}

/// Points-loaded task result carrying the fixture's single rewind point.
fn points_loaded(id: AgentId) -> Action {
    Action::TaskComplete(TaskResult::RewindPointsLoaded {
        agent_id: id,
        points: vec![rewind_point(0)],
    })
}

/// Successful rewind/execute response (conversation-only).
fn rewind_success(target: usize, prompt_text: &str) -> crate::views::rewind::RewindResponse {
    crate::views::rewind::RewindResponse {
        success: true,
        target_prompt_index: target,
        reverted_files: vec![],
        clean_files: vec![],
        conflicts: vec![],
        error: None,
        mode: Some("conversation_only".into()),
        prompt_text: Some(prompt_text.into()),
    }
}

/// Classic `/rewind` with a selected turn also lands on the confirm when confirm-before-rewind is on (default).
#[test]
fn classic_rewind_target_zero_opens_confirm() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    {
        let agent = app.agents.get_mut(&id).unwrap();
        agent
            .scrollback
            .push_block(RenderBlock::user_prompt("fix the bug"));
        agent
            .scrollback
            .push_block(RenderBlock::agent_message("done"));
        agent.scrollback.prepare_layout(80, 40);
        agent.scrollback.set_selected(Some(0));
    }

    let effects = dispatch(Action::Rewind, &mut app);
    assert!(
        matches!(&effects[0], Effect::FetchRewindPoints { .. }),
        "got {effects:?}"
    );
    let effects = dispatch(points_loaded(id), &mut app);
    assert!(
        effects.is_empty(),
        "confirm setting on waits for Yes/No, got {effects:?}"
    );

    assert!(matches!(
        app.agents[&id].rewind_state.as_ref().unwrap().phase,
        crate::views::rewind::RewindPhase::Confirm {
            target_prompt_index: 0,
            ..
        }
    ));
}

/// Settings action updates the live confirm-before-rewind value.
#[test]
fn set_confirm_before_rewind_updates_live_value() {
    let mut app = test_app_with_agent();
    assert!(app.current_ui.confirm_before_rewind_enabled());

    let effects = dispatch(Action::SetConfirmBeforeRewind(false), &mut app);
    assert!(
        matches!(
            &effects[0],
            Effect::PersistSetting {
                key: "confirm_before_rewind",
                value: crate::settings::SettingValue::Bool(false),
                ..
            }
        ),
        "got {effects:?}"
    );
    assert!(!app.current_ui.confirm_before_rewind_enabled());
    assert_eq!(app.current_ui.confirm_before_rewind, Some(false));

    let effects = dispatch(Action::SetConfirmBeforeRewind(false), &mut app);
    assert!(
        effects.is_empty(),
        "idempotent when already false, got {effects:?}"
    );
}

/// Multi-turn fixture with two user prompts for the picker and non-zero-target tests.
fn app_with_two_turns() -> AppView {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    {
        let agent = app.agents.get_mut(&id).unwrap();
        agent.session.session_id = Some(acp::SessionId::new("sess".to_string()));
        for i in 0..2 {
            let mut b = UserPromptBlock::new(format!("turn {i}"));
            b.prompt_index = Some(i);
            agent.scrollback.push_block(RenderBlock::UserPrompt(b));
            agent
                .scrollback
                .push_block(RenderBlock::agent_message("ok"));
        }
        agent.scrollback.prepare_layout(80, 40);
    }
    app
}

/// With confirm-before-rewind off, picking a non-zero turn executes immediately.
#[test]
fn picker_select_nonzero_target_executes_immediately_when_confirm_off() {
    let mut app = app_with_two_turns();
    app.current_ui.confirm_before_rewind = Some(false);
    let id = AgentId(0);

    dispatch(Action::RewindShowPicker, &mut app);
    dispatch(
        Action::TaskComplete(TaskResult::RewindPointsLoaded {
            agent_id: id,
            points: vec![rewind_point(1), rewind_point(0)],
        }),
        &mut app,
    );
    assert!(matches!(
        app.agents[&id].rewind_state.as_ref().unwrap().phase,
        crate::views::rewind::RewindPhase::Picker { .. }
    ));

    let effects = dispatch(Action::RewindPickerSelect(1), &mut app);
    assert!(
        matches!(
            &effects[0],
            Effect::RewindExecute {
                target_prompt_index: 1,
                ..
            }
        ),
        "got {effects:?}"
    );
    assert!(matches!(
        app.agents[&id].rewind_state.as_ref().unwrap().phase,
        crate::views::rewind::RewindPhase::Previewing {
            target_prompt_index: 1,
            scope: crate::views::rewind::RewindScope::All,
        }
    ));
}

/// With confirm-before-rewind on (default), picking a non-zero target opens confirm.
#[test]
fn picker_select_nonzero_target_opens_confirm_when_setting_on() {
    let mut app = app_with_two_turns();
    assert!(app.current_ui.confirm_before_rewind_enabled());
    let id = AgentId(0);

    dispatch(Action::RewindShowPicker, &mut app);
    dispatch(
        Action::TaskComplete(TaskResult::RewindPointsLoaded {
            agent_id: id,
            points: vec![rewind_point(1), rewind_point(0)],
        }),
        &mut app,
    );

    let effects = dispatch(Action::RewindPickerSelect(1), &mut app);
    assert!(
        effects.is_empty(),
        "confirm setting on waits, got {effects:?}"
    );
    assert!(matches!(
        app.agents[&id].rewind_state.as_ref().unwrap().phase,
        crate::views::rewind::RewindPhase::Confirm {
            target_prompt_index: 1,
            active_idx: 0,
            ..
        }
    ));
}

/// Picking any target (including 0) opens confirm when the setting is on.
#[test]
fn picker_select_target_zero_opens_confirm() {
    let mut app = app_with_two_turns();
    let id = AgentId(0);

    dispatch(Action::RewindShowPicker, &mut app);
    dispatch(
        Action::TaskComplete(TaskResult::RewindPointsLoaded {
            agent_id: id,
            points: vec![rewind_point(1), rewind_point(0)],
        }),
        &mut app,
    );

    let effects = dispatch(Action::RewindPickerSelect(0), &mut app);
    assert!(
        effects.is_empty(),
        "confirm setting on waits for Yes/No, got {effects:?}"
    );
    assert!(matches!(
        app.agents[&id].rewind_state.as_ref().unwrap().phase,
        crate::views::rewind::RewindPhase::Confirm {
            target_prompt_index: 0,
            active_idx: 0,
            ..
        }
    ));
}

/// Confirm Yes executes conversation-only rewind.
#[test]
fn confirm_yes_executes_rewind() {
    let mut app = app_with_two_turns();
    let id = AgentId(0);

    dispatch(Action::RewindShowPicker, &mut app);
    dispatch(
        Action::TaskComplete(TaskResult::RewindPointsLoaded {
            agent_id: id,
            points: vec![rewind_point(1), rewind_point(0)],
        }),
        &mut app,
    );
    dispatch(Action::RewindPickerSelect(1), &mut app);
    assert!(matches!(
        app.agents[&id].rewind_state.as_ref().unwrap().phase,
        crate::views::rewind::RewindPhase::Confirm {
            target_prompt_index: 1,
            ..
        }
    ));

    let effects = dispatch(Action::RewindConfirm(1), &mut app);
    assert!(
        matches!(
            &effects[0],
            Effect::RewindExecute {
                target_prompt_index: 1,
                ..
            }
        ),
        "got {effects:?}"
    );
    assert!(matches!(
        app.agents[&id].rewind_state.as_ref().unwrap().phase,
        crate::views::rewind::RewindPhase::Previewing {
            target_prompt_index: 1,
            scope: crate::views::rewind::RewindScope::All,
        }
    ));
}

/// "Yes, and don't ask again" turns the setting off and executes this rewind.
#[test]
fn confirm_never_ask_persists_setting_off_and_executes() {
    let mut app = app_with_two_turns();
    assert!(app.current_ui.confirm_before_rewind_enabled());
    let id = AgentId(0);

    dispatch(Action::RewindShowPicker, &mut app);
    dispatch(
        Action::TaskComplete(TaskResult::RewindPointsLoaded {
            agent_id: id,
            points: vec![rewind_point(1), rewind_point(0)],
        }),
        &mut app,
    );
    dispatch(Action::RewindPickerSelect(1), &mut app);

    let effects = dispatch(Action::RewindConfirmNeverAsk(1), &mut app);
    assert!(
        effects.iter().any(|e| matches!(
            e,
            Effect::PersistSetting {
                key: "confirm_before_rewind",
                value: crate::settings::SettingValue::Bool(false),
                ..
            }
        )),
        "must persist setting off, got {effects:?}"
    );
    assert!(
        effects.iter().any(|e| matches!(
            e,
            Effect::RewindExecute {
                target_prompt_index: 1,
                ..
            }
        )),
        "must execute rewind, got {effects:?}"
    );
    assert!(!app.current_ui.confirm_before_rewind_enabled());
    assert_eq!(app.current_ui.confirm_before_rewind, Some(false));
    assert!(
        app.agents[&id].toast.is_none(),
        "never-ask must not toast settings checkmark, got {:?}",
        app.agents[&id].toast
    );
    assert!(matches!(
        app.agents[&id].rewind_state.as_ref().unwrap().phase,
        crate::views::rewind::RewindPhase::Previewing {
            target_prompt_index: 1,
            scope: crate::views::rewind::RewindScope::All,
        }
    ));
}

/// With confirm off, target 0 executes immediately (same as non-zero targets).
#[test]
fn picker_select_target_zero_executes_immediately_when_confirm_off() {
    let mut app = app_with_two_turns();
    app.current_ui.confirm_before_rewind = Some(false);
    let id = AgentId(0);

    dispatch(Action::RewindShowPicker, &mut app);
    dispatch(
        Action::TaskComplete(TaskResult::RewindPointsLoaded {
            agent_id: id,
            points: vec![rewind_point(1), rewind_point(0)],
        }),
        &mut app,
    );

    let effects = dispatch(Action::RewindPickerSelect(0), &mut app);
    assert!(
        matches!(
            &effects[0],
            Effect::RewindExecute {
                target_prompt_index: 0,
                ..
            }
        ),
        "got {effects:?}"
    );
    assert!(matches!(
        app.agents[&id].rewind_state.as_ref().unwrap().phase,
        crate::views::rewind::RewindPhase::Previewing {
            target_prompt_index: 0,
            scope: crate::views::rewind::RewindScope::All,
        }
    ));
}

/// Non-zero success keeps earlier turns, truncates from the target, and toasts.
#[test]
fn rewind_success_nonzero_target_keeps_prefix_and_toasts() {
    let mut app = app_with_two_turns();
    let id = AgentId(0);
    let len_before = app.agents[&id].scrollback.len();

    dispatch(
        Action::TaskComplete(TaskResult::RewindExecuteComplete {
            agent_id: id,
            response: rewind_success(1, "turn 1"),
        }),
        &mut app,
    );

    let agent = &app.agents[&id];
    assert!(
        agent.scrollback.len() < len_before,
        "tail from target 1 must drop"
    );
    assert!(matches!(
        &agent.scrollback.entry(0).unwrap().block,
        RenderBlock::UserPrompt(b) if b.text == "turn 0"
    ));
    assert!(matches!(
        &agent.scrollback.entry(1).unwrap().block,
        RenderBlock::AgentMessage(_)
    ));
    assert_eq!(
        agent.scrollback.len(),
        2,
        "only turn 0 (prompt + reply) remains"
    );
    assert_eq!(
        agent.toast.as_ref().map(|(m, _)| m.as_str()),
        Some("Reverted conversation")
    );
}

/// Classic points-loaded path with confirm off executes immediately.
#[test]
fn classic_points_loaded_target_zero_executes_when_confirm_off() {
    let mut app = test_app_with_agent();
    app.current_ui.confirm_before_rewind = Some(false);
    let id = AgentId(0);
    {
        let agent = app.agents.get_mut(&id).unwrap();
        agent
            .scrollback
            .push_block(RenderBlock::user_prompt("fix the bug"));
        agent
            .scrollback
            .push_block(RenderBlock::agent_message("done"));
        agent.scrollback.prepare_layout(80, 40);
        agent.scrollback.set_selected(Some(0));
    }

    dispatch(Action::Rewind, &mut app);
    let effects = dispatch(points_loaded(id), &mut app);
    assert!(
        matches!(
            &effects[0],
            Effect::RewindExecute {
                target_prompt_index: 0,
                ..
            }
        ),
        "got {effects:?}"
    );
    assert!(matches!(
        app.agents[&id].rewind_state.as_ref().unwrap().phase,
        crate::views::rewind::RewindPhase::Previewing {
            target_prompt_index: 0,
            scope: crate::views::rewind::RewindScope::All,
        }
    ));
}

#[test]
fn stacked_rewinds_each_get_their_own_pid_and_orphans_drop_independently() {
    // Two rewinds leave two cancelled PromptResponses to drain
    // Each carries its own promptId; both fail to match current_prompt_id (None) and are silently discarded with no banner
    let mut app = test_app_with_agent();
    let id = AgentId(0);

    dispatch(Action::SendPrompt("a".into()), &mut app);
    let pid_a = app.agents[&id].session.current_prompt_id.clone();
    dispatch(Action::CancelTurn, &mut app);
    dispatch(Action::SendPrompt("b".into()), &mut app);
    let pid_b = app.agents[&id].session.current_prompt_id.clone();
    dispatch(Action::CancelTurn, &mut app);
    assert_ne!(pid_a, pid_b);
    assert!(app.agents[&id].session.current_prompt_id.is_none());

    let pr = |pid: &Option<String>| {
        Action::TaskComplete(TaskResult::PromptResponse {
            agent_id: id,
            result: Ok(acp::PromptResponse::new(acp::StopReason::Cancelled)
                .meta(serde_json::json!({ "promptId": pid }).as_object().cloned())),
            http_status: None,
            verdicts: None,
            prompt_id: None,
        })
    };
    dispatch(pr(&pid_a), &mut app);
    dispatch(pr(&pid_b), &mut app);
    assert_eq!(app.agents[&id].scrollback.len(), 0);
    assert!(app.agents[&id].session.state.is_idle());
}

fn user_block(text: &str, pi: Option<usize>) -> RenderBlock {
    let mut b = UserPromptBlock::new(text);
    b.prompt_index = pi;
    RenderBlock::UserPrompt(b)
}

/// A successful conversation rewind truncates the transcript tail (`remove_from`); the purge must fire exactly once.
#[test]
fn rewind_success_truncation_releases_retained_memory() {
    use crate::memory_release::test_support;
    test_support::install_counting_hook();

    let response = crate::views::rewind::RewindResponse {
        success: true,
        target_prompt_index: 0,
        reverted_files: Vec::new(),
        clean_files: Vec::new(),
        conflicts: Vec::new(),
        error: None,
        mode: Some("conversation_only".into()),
        prompt_text: Some("alpha".into()),
    };

    let mut app = test_app_with_agent();
    let id = AgentId(0);
    if let Some(agent) = app.agents.get_mut(&id) {
        agent.scrollback.push_block(user_block("alpha", Some(0)));
        agent.scrollback.push_block(RenderBlock::agent_message("a"));
    }
    let len_before = app.agents[&id].scrollback.len();
    let before = test_support::calls();
    dispatch(
        Action::TaskComplete(TaskResult::RewindExecuteComplete {
            agent_id: id,
            response,
        }),
        &mut app,
    );
    assert!(
        app.agents[&id].scrollback.len() < len_before,
        "fixture sanity: the conversation rewind must truncate entries"
    );
    assert_eq!(
        test_support::calls(),
        before + 1,
        "the rewound tail dropped — exactly one purge"
    );
}

/// A successful rewind confirms via a toast in the full TUI; minimal mode keeps the scrollback system block (it never renders toasts).
#[test]
fn rewind_success_toasts_in_full_tui_and_commits_system_block_in_minimal() {
    let response = crate::views::rewind::RewindResponse {
        success: true,
        target_prompt_index: 0,
        reverted_files: Vec::new(),
        clean_files: Vec::new(),
        conflicts: Vec::new(),
        error: None,
        mode: Some("conversation_only".into()),
        prompt_text: None,
    };

    let mut app = test_app_with_agent();
    let id = AgentId(0);
    if let Some(agent) = app.agents.get_mut(&id) {
        agent.scrollback.push_block(user_block("alpha", Some(0)));
        agent.scrollback.push_block(RenderBlock::agent_message("a"));
    }
    dispatch(
        Action::TaskComplete(TaskResult::RewindExecuteComplete {
            agent_id: id,
            response: response.clone(),
        }),
        &mut app,
    );
    assert_eq!(
        app.agents[&id].toast.as_ref().map(|(m, _)| m.as_str()),
        Some("Reverted conversation")
    );
    assert_eq!(
        app.agents[&id].scrollback.len(),
        0,
        "the confirmation must not land in scrollback in the full TUI"
    );

    let mut app = test_app_with_agent();
    app.screen_mode = crate::app::ScreenMode::Minimal;
    if let Some(agent) = app.agents.get_mut(&id) {
        agent.scrollback.push_block(user_block("alpha", Some(0)));
        agent.scrollback.push_block(RenderBlock::agent_message("a"));
    }
    dispatch(
        Action::TaskComplete(TaskResult::RewindExecuteComplete {
            agent_id: id,
            response,
        }),
        &mut app,
    );
    assert!(app.agents[&id].toast.is_none());
    assert_eq!(last_system_text(&app, id), "Reverted conversation");
}

#[test]
fn primary_path_returns_correct_idx_for_each_prompt() {
    let mut sb = ScrollbackState::new();
    let alpha = sb.push_block(user_block("alpha", Some(0)));
    sb.push_block(RenderBlock::agent_message("a"));
    let bravo = sb.push_block(user_block("bravo", Some(1)));
    sb.push_block(RenderBlock::agent_message("b"));
    let charlie = sb.push_block(user_block("charlie", Some(2)));
    sb.push_block(RenderBlock::agent_message("c"));

    let alpha_idx = sb.index_of_id(alpha).unwrap();
    let bravo_idx = sb.index_of_id(bravo).unwrap();
    let charlie_idx = sb.index_of_id(charlie).unwrap();

    assert_eq!(
        find_user_prompt_entry_for_shell_index(&sb, 0),
        Some(alpha_idx)
    );
    assert_eq!(
        find_user_prompt_entry_for_shell_index(&sb, 1),
        Some(bravo_idx)
    );
    assert_eq!(
        find_user_prompt_entry_for_shell_index(&sb, 2),
        Some(charlie_idx)
    );
}

/// Interjections render as standard user prompts but the shell never numbers them.
/// The positional fallback must skip them or every mapping after an interjection is off by one.
#[test]
fn fallback_path_skips_interjections() {
    let mut sb = ScrollbackState::new();
    let alpha = sb.push_block(user_block("alpha", None));
    sb.push_block(RenderBlock::agent_message("a"));
    sb.push_block(RenderBlock::interjection_prompt("mid-turn steer"));
    sb.push_block(RenderBlock::agent_message("a2"));
    let bravo = sb.push_block(user_block("bravo", None));

    let alpha_idx = sb.index_of_id(alpha).unwrap();
    let bravo_idx = sb.index_of_id(bravo).unwrap();

    assert_eq!(
        find_user_prompt_entry_for_shell_index(&sb, 0),
        Some(alpha_idx)
    );
    assert_eq!(
        find_user_prompt_entry_for_shell_index(&sb, 1),
        Some(bravo_idx),
        "index 1 must map to the next real prompt, not the interjection"
    );
}

/// Selecting an interjection (or an entry after it within the same turn) anchors rewind on the enclosing turn's prompt, not the next turn's.
#[test]
fn shell_prompt_index_at_resolves_interjection_to_enclosing_turn() {
    use super::super::rewind::shell_prompt_index_at;

    let mut sb = ScrollbackState::new();
    sb.push_block(user_block("alpha", Some(0)));
    sb.push_block(RenderBlock::agent_message("a"));
    let ij = sb.push_block(RenderBlock::interjection_prompt("mid-turn steer"));
    sb.push_block(RenderBlock::agent_message("a2"));
    sb.push_block(user_block("bravo", Some(1)));

    let ij_idx = sb.index_of_id(ij).unwrap();
    assert_eq!(shell_prompt_index_at(&sb, ij_idx), Some(0));
    // A block after the interjection but before the next prompt still belongs to turn 0
    assert_eq!(shell_prompt_index_at(&sb, ij_idx + 1), Some(0));
}

/// Legacy meta-less scrollbacks: the positional count inside `shell_prompt_index_at` must also exclude interjections.
#[test]
fn shell_prompt_index_at_counting_fallback_skips_interjections() {
    use super::super::rewind::shell_prompt_index_at;

    let mut sb = ScrollbackState::new();
    sb.push_block(user_block("alpha", None));
    sb.push_block(RenderBlock::interjection_prompt("steer"));
    let bravo = sb.push_block(user_block("bravo", None));

    let bravo_idx = sb.index_of_id(bravo).unwrap();
    assert_eq!(shell_prompt_index_at(&sb, bravo_idx), Some(1));
}

#[test]
fn fallback_path_returns_correct_idx_when_prompt_index_is_none() {
    let mut sb = ScrollbackState::new();
    let alpha = sb.push_block(user_block("alpha", None));
    sb.push_block(RenderBlock::agent_message("a"));
    let bravo = sb.push_block(user_block("bravo", None));
    sb.push_block(RenderBlock::agent_message("b"));
    let charlie = sb.push_block(user_block("charlie", None));
    sb.push_block(RenderBlock::agent_message("c"));

    let alpha_idx = sb.index_of_id(alpha).unwrap();
    let bravo_idx = sb.index_of_id(bravo).unwrap();
    let charlie_idx = sb.index_of_id(charlie).unwrap();

    assert_eq!(
        find_user_prompt_entry_for_shell_index(&sb, 0),
        Some(alpha_idx)
    );
    assert_eq!(
        find_user_prompt_entry_for_shell_index(&sb, 1),
        Some(bravo_idx)
    );
    assert_eq!(
        find_user_prompt_entry_for_shell_index(&sb, 2),
        Some(charlie_idx)
    );
}

fn files_response(
    mode: &str,
    success: bool,
    reverted: &[&str],
    conflicts: &[(&str, &str)],
) -> crate::views::rewind::RewindResponse {
    crate::views::rewind::RewindResponse {
        success,
        target_prompt_index: 1,
        reverted_files: reverted.iter().map(|s| s.to_string()).collect(),
        clean_files: vec![],
        conflicts: conflicts
            .iter()
            .map(|(p, t)| crate::views::rewind::RewindConflictInfo {
                path: p.to_string(),
                conflict_type: t.to_string(),
            })
            .collect(),
        error: None,
        mode: Some(mode.to_string()),
        prompt_text: None,
    }
}

fn phase_of(app: &AppView, id: AgentId) -> crate::views::rewind::RewindPhase {
    app.agents[&id].rewind_state.as_ref().unwrap().phase.clone()
}

/// "Yes" rewinds conversation and files: a dry run first (nothing changes), then the real thing once the engine reports no conflicts.
#[test]
fn rewind_all_previews_then_executes_when_clean() {
    use crate::views::rewind::RewindScope;
    let mut app = app_with_two_turns();
    let id = AgentId(0);
    dispatch(Action::RewindShowPicker, &mut app);
    dispatch(
        Action::TaskComplete(TaskResult::RewindPointsLoaded {
            agent_id: id,
            points: vec![rewind_point(1), rewind_point(0)],
        }),
        &mut app,
    );
    dispatch(Action::RewindPickerSelect(1), &mut app);
    let effects = dispatch(Action::RewindConfirm(1), &mut app);
    assert!(
        matches!(&effects[0], Effect::RewindExecute { mode: RewindScope::All, force: false, .. }),
        "first request must be a dry run, got {effects:?}"
    );
    let effects = dispatch(
        Action::TaskComplete(TaskResult::RewindExecuteComplete {
            agent_id: id,
            response: files_response("all", false, &[], &[]),
        }),
        &mut app,
    );
    assert!(
        matches!(&effects[0], Effect::RewindExecute { mode: RewindScope::All, force: true, target_prompt_index: 1, .. }),
        "clean preview must proceed, got {effects:?}"
    );
    assert!(matches!(phase_of(&app, id), crate::views::rewind::RewindPhase::Executing { .. }));
}

/// Files changed outside Fuigo are listed and NOT overwritten unless the user says so.
#[test]
fn rewind_conflicts_are_reported_and_not_overwritten_until_confirmed() {
    use crate::views::rewind::{ConflictChoice, RewindPhase, RewindScope};
    let mut app = app_with_two_turns();
    let id = AgentId(0);
    dispatch(Action::RewindShowPicker, &mut app);
    dispatch(
        Action::TaskComplete(TaskResult::RewindPointsLoaded {
            agent_id: id,
            points: vec![rewind_point(1), rewind_point(0)],
        }),
        &mut app,
    );
    dispatch(Action::RewindPickerSelect(1), &mut app);
    dispatch(Action::RewindConfirm(1), &mut app);
    let effects = dispatch(
        Action::TaskComplete(TaskResult::RewindExecuteComplete {
            agent_id: id,
            response: files_response("all", false, &[], &[("src/a.rs", "modified_externally")]),
        }),
        &mut app,
    );
    assert!(effects.is_empty(), "a conflict must not execute anything: {effects:?}");
    let RewindPhase::Conflicts { conflicts, scope, .. } = phase_of(&app, id) else {
        panic!("expected the conflict prompt");
    };
    assert_eq!(scope, RewindScope::All);
    assert_eq!(conflicts[0].path, "src/a.rs");


    // Keep files: conversation-only, forced.
    let effects = dispatch(Action::RewindConflict(ConflictChoice::KeepFiles), &mut app);
    assert!(
        matches!(&effects[0], Effect::RewindExecute { mode: RewindScope::ConversationOnly, force: true, .. }),
        "got {effects:?}"
    );
}

#[test]
fn rewind_conflict_overwrite_forces_the_same_scope_and_cancel_sends_nothing() {
    use crate::views::rewind::{ConflictChoice, RewindScope};
    for (choice, expect_send) in [(ConflictChoice::Overwrite, true), (ConflictChoice::Cancel, false)] {
        let mut app = app_with_two_turns();
        let id = AgentId(0);
        dispatch(Action::RewindShowPicker, &mut app);
        dispatch(
            Action::TaskComplete(TaskResult::RewindPointsLoaded {
                agent_id: id,
                points: vec![rewind_point(1), rewind_point(0)],
            }),
            &mut app,
        );
        dispatch(Action::RewindPickerSelect(1), &mut app);
        dispatch(Action::RewindConfirmScoped(1, RewindScope::FilesOnly), &mut app);
        dispatch(
            Action::TaskComplete(TaskResult::RewindExecuteComplete {
                agent_id: id,
                response: files_response("files_only", false, &[], &[("b.txt", "deleted_externally")]),
            }),
            &mut app,
        );
        let effects = dispatch(Action::RewindConflict(choice), &mut app);
        if expect_send {
            assert!(
                matches!(&effects[0], Effect::RewindExecute { mode: RewindScope::FilesOnly, force: true, .. }),
                "got {effects:?}"
            );
        } else {
            assert!(effects.is_empty());
            assert!(app.agents[&id].rewind_state.is_none());
        }
    }
}

/// Conversation only touches no file, so it skips the dry run.
#[test]
fn rewind_conversation_only_executes_directly() {
    use crate::views::rewind::RewindScope;
    let mut app = app_with_two_turns();
    let id = AgentId(0);
    dispatch(Action::RewindShowPicker, &mut app);
    dispatch(
        Action::TaskComplete(TaskResult::RewindPointsLoaded {
            agent_id: id,
            points: vec![rewind_point(1), rewind_point(0)],
        }),
        &mut app,
    );
    dispatch(Action::RewindPickerSelect(1), &mut app);
    let effects = dispatch(Action::RewindConfirmScoped(1, RewindScope::ConversationOnly), &mut app);
    assert!(
        matches!(&effects[0], Effect::RewindExecute { mode: RewindScope::ConversationOnly, force: true, .. }),
        "got {effects:?}"
    );
}

/// The result names the restored files (from the engine's `reverted_files`), and a files-only rewind leaves the transcript alone.
#[test]
fn rewind_result_lists_restored_files_and_files_only_keeps_the_transcript() {
    use crate::views::rewind::RewindPhase;
    let mut app = app_with_two_turns();
    let id = AgentId(0);
    let before = app.agents[&id].scrollback.len();
    app.agents.get_mut(&id).unwrap().rewind_state = Some(crate::views::rewind::RewindState {
        phase: RewindPhase::Executing { target_prompt_index: 1 },
        anchor_entry_idx: 0,
        stashed_draft: None,
        selected_prompt_index: None,
    });
    dispatch(
        Action::TaskComplete(TaskResult::RewindExecuteComplete {
            agent_id: id,
            response: files_response("files_only", true, &["a.txt", "dir/b.txt"], &[]),
        }),
        &mut app,
    );
    let sb = &app.agents[&id].scrollback;
    assert_eq!(sb.len(), before + 1, "files only must not remove any turn");
    let text = last_system_text(&app, id);
    assert!(text.contains("Restored 2 files"), "{text}");
    assert!(text.contains("a.txt") && text.contains("dir/b.txt"), "{text}");

    assert_eq!(
        crate::app::dispatch::rewind::rewind_result_message(&files_response("all", true, &["x"], &[])),
        "Reverted conversation and 1 file"
    );
    assert_eq!(
        crate::app::dispatch::rewind::rewind_result_message(&files_response("conversation_only", true, &[], &[])),
        "Reverted conversation"
    );
}
