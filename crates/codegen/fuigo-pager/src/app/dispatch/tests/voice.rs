//! Tests for voice mode enable, toggle, and stop dispatchers.

use super::*;

/// Plan mode must not gate voice.
/// Typing `/voice` and Enter through the real input path (prompt keys, then the slash registry, then dispatch) starts recording.
/// With `plan_mode_active` set it behaves exactly like normal mode.
#[test]
fn voice_slash_submit_starts_recording_in_plan_mode() {
    use crate::app::app_view::InputOutcome;
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
    if !fuigo_voice::AUDIO_SUPPORTED {
        return;
    }
    let mut app = test_app_with_agent();
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    app.voice_cmd_tx = Some(tx);
    // The production reveal path flips the flag AND the `/voice` visibility in each slash registry together
    app.apply_voice_mode_enabled(true);
    let agent = app.agents.get_mut(&AgentId(0)).unwrap();
    agent.plan_mode_active = true;
    agent.set_active_pane(crate::views::agent::ActivePane::Prompt, false);

    for ch in "/voice".chars() {
        app.handle_input(&Event::Key(KeyEvent::new(
            KeyCode::Char(ch),
            KeyModifiers::NONE,
        )));
    }
    let out = app.handle_input(&Event::Key(KeyEvent::new(
        KeyCode::Enter,
        KeyModifiers::NONE,
    )));
    let InputOutcome::Action(action) = out else {
        panic!("Enter on /voice must produce a submit action, got {out:?}");
    };
    dispatch(action, &mut app);
    assert!(
        app.voice_listening(),
        "typed /voice + Enter must start recording in plan mode"
    );
}

#[test]
fn voice_on_welcome_noop_when_startup_gated() {
    // Auth or folder trust unresolved: voice must not create a session (that would bypass the startup gate)
    // It stays a silent no-op on welcome
    let mut app = test_app();
    app.auth_state = AuthState::Pending { error: None };
    app.voice_mode_enabled = true;
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    app.voice_cmd_tx = Some(tx);

    dispatch(Action::EnableVoiceMode, &mut app);

    assert!(app.agents.is_empty(), "no session created while gated");
    assert!(matches!(app.active_view, ActiveView::Welcome));
    assert!(!app.voice_listening());
}

#[test]
fn voice_final_appends_to_prompt_with_single_space() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    app.voice_state = VoiceState::Stopping {
        session: 1,
        target: VoiceTarget::Agent(id),
        interim: None,
    };
    let p = &mut app.agents.get_mut(&id).unwrap().prompt;
    p.set_text("hello");
    p.set_cursor(5);
    let redraw = crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::UtteranceFinal {
            session: 1,
            text: "world".into(),
        },
    );
    assert!(redraw);
    let p = &app.agents.get(&id).unwrap().prompt;
    assert_eq!(p.text(), "hello world");
    assert_eq!(p.cursor(), "hello world".len());
}

#[test]
fn voice_final_preserves_mid_text_cursor() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    app.voice_state = VoiceState::Recording {
        session: 1,
        hold: false,
        target: VoiceTarget::Agent(id),
        interim: Some("partial".into()),
    };
    let p = &mut app.agents.get_mut(&id).unwrap().prompt;
    p.set_text("hello world");
    p.set_cursor(5);

    crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::UtteranceFinal {
            session: 1,
            text: "again".into(),
        },
    );

    let p = &app.agents.get(&id).unwrap().prompt;
    assert_eq!(p.text(), "hello world again");
    assert_eq!(p.cursor(), 5);
    assert!(app.voice_listening());
    assert!(app.voice_interim().is_none());
}

#[test]
fn voice_final_into_empty_prompt_has_no_leading_space() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    app.voice_state = VoiceState::Stopping {
        session: 1,
        target: VoiceTarget::Agent(id),
        interim: None,
    };
    crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::UtteranceFinal {
            session: 1,
            text: "hi there".into(),
        },
    );
    let p = &app.agents.get(&id).unwrap().prompt;
    assert_eq!(p.text(), "hi there");
    assert_eq!(p.cursor(), "hi there".len());
}

#[test]
fn voice_final_replaces_whitespace_only_draft() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    app.voice_state = VoiceState::Stopping {
        session: 1,
        target: VoiceTarget::Agent(id),
        interim: None,
    };
    let p = &mut app.agents.get_mut(&id).unwrap().prompt;
    p.set_text("  \n");
    p.set_cursor(0);
    crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::UtteranceFinal {
            session: 1,
            text: "hi".into(),
        },
    );
    let p = &app.agents.get(&id).unwrap().prompt;
    assert_eq!(p.text(), "hi");
    assert_eq!(p.cursor(), 2);
}

#[test]
fn voice_final_preserves_trailing_newline() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    app.voice_state = VoiceState::Stopping {
        session: 1,
        target: VoiceTarget::Agent(id),
        interim: None,
    };
    app.agents
        .get_mut(&id)
        .unwrap()
        .prompt
        .set_text("line one\n");
    crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::UtteranceFinal {
            session: 1,
            text: "line two".into(),
        },
    );
    // Newline preserved: dictation lands on the new line.
    assert_eq!(
        app.agents.get(&id).unwrap().prompt.text(),
        "line one\nline two"
    );
}

/// A Ctrl+Space release ends only a session a Ctrl+Space hold started.
/// A recording from `/voice` or a Ctrl+Space toggle is left running; its release isn't ours.
#[test]
fn voice_ctrl_space_release_leaves_toggle_recording_running() {
    if !fuigo_voice::AUDIO_SUPPORTED {
        return;
    }
    let mut app = test_app_with_agent();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    app.voice_mode_enabled = true;
    app.voice_cmd_tx = Some(tx);

    // Ctrl+Space starts a toggle recording (no hold-ownership).
    dispatch(Action::VoiceToggle, &mut app);
    assert!(app.voice_listening());
    assert!(!app.voice_state.hold());
    let _ = rx.try_recv(); // drain the PttPress

    // A stray Ctrl+Space release must not stop it.
    dispatch(Action::VoiceStop, &mut app);
    assert!(
        app.voice_listening(),
        "Ctrl+Space release must not stop a toggle session"
    );
    assert!(
        rx.try_recv().is_err(),
        "no PttRelease for a non-hold session"
    );
}

/// A free-tier user hitting the voice keybinding gets the SuperGrok upsell instead of a doomed voice session.
/// The keybinding bypasses the slash registry, so this dispatcher is the enforcement point.
#[test]
fn voice_keybinding_on_restricted_tier_opens_upsell() {
    if !fuigo_voice::AUDIO_SUPPORTED {
        return; // The tier check runs after the AUDIO_SUPPORTED gate.
    }
    let mut app = test_app_with_agent();
    app.voice_mode_enabled = true;
    // A personal login without a subscription tier is free tier, so voice is restricted
    app.apply_auth_meta(&fuigo_shell::auth::AuthMeta::default());
    assert!(app.is_voice_tier_restricted());

    dispatch(Action::EnableVoiceMode, &mut app);

    assert!(
        app.agents.get(&AgentId(0)).unwrap().question_view.is_some(),
        "restricted-tier voice keybinding must open the SuperGrok upsell"
    );
    assert!(
        !app.voice_listening(),
        "voice must not start on a restricted tier"
    );
}

/// A paid-tier user's voice keybinding is not intercepted by the tier gate.
#[test]
fn voice_keybinding_on_paid_tier_not_gated() {
    if !fuigo_voice::AUDIO_SUPPORTED {
        return;
    }
    let mut app = test_app_with_agent();
    app.voice_mode_enabled = true;
    let meta = fuigo_shell::auth::AuthMeta {
        subscription_tier: Some("SuperGrok".into()),
        ..Default::default()
    };
    app.apply_auth_meta(&meta);
    assert!(!app.is_voice_tier_restricted());

    dispatch(Action::EnableVoiceMode, &mut app);

    // No upsell modal; the paid user proceeds down the normal voice path
    assert!(
        app.agents.get(&AgentId(0)).unwrap().question_view.is_none(),
        "paid-tier voice must not be intercepted by the tier gate"
    );
}

#[test]
fn voice_interim_sets_then_error_clears_state() {
    let mut app = test_app_with_agent();
    app.voice_state = VoiceState::Recording {
        session: 1,
        hold: false,
        target: VoiceTarget::Agent(AgentId(0)),
        interim: None,
    };
    crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::InterimTranscript {
            session: 1,
            text: "partial".into(),
        },
    );
    assert_eq!(app.voice_interim(), Some("partial"));

    crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::Error {
            session: 1,
            message: "boom".into(),
            hint: None,
        },
    );
    assert!(!app.voice_listening());
    assert!(app.voice_interim().is_none());
}

#[test]
fn voice_error_hint_lands_in_bound_agent_scrollback() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    let before = app.agents.get(&id).unwrap().scrollback.len();

    // Hint follows the bound target (like finals), not the active view.
    app.active_view = ActiveView::AgentDashboard;
    app.voice_state = VoiceState::Recording {
        session: 1,
        hold: false,
        target: VoiceTarget::Agent(id),
        interim: None,
    };
    crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::Error {
            session: 1,
            message: "no speech detected".into(),
            hint: Some("allow terminal mic access in system settings".into()),
        },
    );
    let agent = app.agents.get(&id).unwrap();
    assert_eq!(agent.scrollback.len(), before + 1);
    let text = match agent
        .scrollback
        .get(agent.scrollback.len() - 1)
        .map(|e| &e.block)
    {
        Some(crate::scrollback::block::RenderBlock::System(b)) => b.text.as_str(),
        other => panic!("expected system hint block, got {other:?}"),
    };
    assert!(
        text.contains("no speech detected")
            && text.contains("allow terminal mic access in system settings"),
        "scrollback should carry short message + long hint, got {text:?}"
    );

    // A message that is already a sentence must not gain a second full stop.
    // The real one is "No speech was detected. Voice stopped.", which rendered
    // as "Voice stopped.." to the user.
    app.voice_state = VoiceState::Recording {
        session: 1,
        hold: false,
        target: VoiceTarget::Agent(id),
        interim: None,
    };
    crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::Error {
            session: 1,
            message: "No speech was detected. Voice stopped.".into(),
            hint: Some("check the input device".into()),
        },
    );
    let agent = app.agents.get(&id).unwrap();
    let text = match agent
        .scrollback
        .get(agent.scrollback.len() - 1)
        .map(|e| &e.block)
    {
        Some(crate::scrollback::block::RenderBlock::System(b)) => b.text.as_str(),
        other => panic!("expected system hint block, got {other:?}"),
    };
    assert!(!text.contains(".."), "doubled full stop in {text:?}");
    assert!(
        text.contains("Voice stopped. check the input device"),
        "{text:?}"
    );

    // No hint while still bound: toast only, no scrollback growth
    app.voice_state = VoiceState::Recording {
        session: 1,
        hold: false,
        target: VoiceTarget::Agent(id),
        interim: None,
    };
    let before = app.agents.get(&id).unwrap().scrollback.len();
    crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::Error {
            session: 1,
            message: "boom".into(),
            hint: None,
        },
    );
    assert_eq!(app.agents.get(&id).unwrap().scrollback.len(), before);
}

#[test]
fn voice_error_hint_dropped_for_dashboard_dispatch() {
    // The dispatch box has no scrollback; only the dashboard toast survives.
    let mut app = test_app_with_agent();
    app.active_view = ActiveView::AgentDashboard;
    ensure_dashboard_state(&mut app);
    app.voice_state = VoiceState::Recording {
        session: 1,
        hold: false,
        target: VoiceTarget::DashboardDispatch,
        interim: None,
    };
    let before = app.agents.get(&AgentId(0)).unwrap().scrollback.len();
    crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::Error {
            session: 1,
            message: "no speech detected".into(),
            hint: Some("allow terminal mic access in system settings".into()),
        },
    );
    assert_eq!(
        app.agents.get(&AgentId(0)).unwrap().scrollback.len(),
        before
    );
    assert!(
        app.dashboard
            .as_ref()
            .is_some_and(|d| d.error_toast.is_some())
    );
}

#[test]
fn voice_interim_ignored_after_stop() {
    // Late interim events that arrive after recording stopped must not repopulate the overlay
    let mut app = test_app_with_agent();
    app.voice_state = VoiceState::Idle; // Not recording, so interim is None
    let redraw = crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::InterimTranscript {
            session: 1,
            text: "late".into(),
        },
    );
    assert!(!redraw, "stale interim event must not request a redraw");
    assert!(
        app.voice_interim().is_none(),
        "stale interim event must not set voice_interim"
    );
}

#[test]
fn voice_interim_kept_on_stop_then_cleared_by_final() {
    // An explicit stop keeps the last interim on screen (no flicker) until the trailing final commits it; the final then clears the interim
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    app.voice_state = VoiceState::Recording {
        session: 1,
        hold: false,
        target: VoiceTarget::Agent(id),
        interim: Some("partial".into()),
    };

    app.voice_stop_keeping_final();
    assert!(!app.voice_listening());
    assert_eq!(
        app.voice_interim(),
        Some("partial"),
        "stop keeps the interim"
    );

    crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::UtteranceFinal {
            session: 1,
            text: "partial".into(),
        },
    );
    assert_eq!(app.voice_interim(), None, "final clears the interim");
    assert_eq!(app.agents.get(&id).unwrap().prompt.text(), "partial");
}

#[test]
fn voice_toggle_starts_and_stops() {
    // Starting routes through the `/voice` gate, which requires compiled-in audio capture; skip on builds without a `cpal` backend
    if !fuigo_voice::AUDIO_SUPPORTED {
        return;
    }
    let mut app = test_app_with_agent();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    app.voice_mode_enabled = true;
    app.voice_ui_active = true;
    app.voice_cmd_tx = Some(tx);

    dispatch(Action::VoiceToggle, &mut app);
    assert!(app.voice_listening());
    assert!(matches!(
        rx.try_recv(),
        Ok(fuigo_voice::VoiceCommand::PttPress { .. })
    ));

    dispatch(Action::VoiceToggle, &mut app);
    assert!(!app.voice_listening());
    assert!(matches!(
        rx.try_recv(),
        Ok(fuigo_voice::VoiceCommand::PttRelease { .. })
    ));
}

#[test]
fn voice_toggle_silent_no_op_when_flag_disabled() {
    // With the voice gate off (kill switch or env force-off), the voice key is a silent no-op: no recording, and no toast
    let mut app = test_app_with_agent();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    app.voice_mode_enabled = false;
    app.voice_cmd_tx = Some(tx);
    dispatch(Action::VoiceToggle, &mut app);
    assert!(
        !app.voice_listening(),
        "must not start recording when the flag is off"
    );
    assert!(
        !app.voice_ui_active,
        "voice mode must not arm with flag off"
    );
    assert!(rx.try_recv().is_err(), "no PttPress with flag off");
}

#[test]
fn voice_toggle_starts_without_voice_mode_prereq() {
    // Ctrl+Space is a direct start; it no longer requires `/voice` first
    // Skip when audio capture isn't compiled in (see sibling test).
    if !fuigo_voice::AUDIO_SUPPORTED {
        return;
    }
    let mut app = test_app_with_agent();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    app.voice_mode_enabled = true;
    app.voice_ui_active = false;
    app.voice_cmd_tx = Some(tx);
    dispatch(Action::VoiceToggle, &mut app);
    assert!(app.voice_ui_active, "Ctrl+Space enables voice mode");
    assert!(
        app.voice_listening(),
        "Ctrl+Space starts recording without a /voice prerequisite"
    );
    assert!(matches!(
        rx.try_recv(),
        Ok(fuigo_voice::VoiceCommand::PttPress { .. })
    ));
}

#[test]
fn voice_mode_enable_starts_recording_and_stays_on() {
    // `/voice` gates on compiled-in audio capture; skip when the build has no `cpal` backend (e.g. Bazel or headless), where enabling is a no-op.
    if !fuigo_voice::AUDIO_SUPPORTED {
        return;
    }
    let mut app = test_app_with_agent();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    app.voice_mode_enabled = true;
    app.voice_cmd_tx = Some(tx);

    // `EnableVoiceMode` (the Ctrl+Space hold-press start) begins recording when the pipeline is already up
    dispatch(Action::EnableVoiceMode, &mut app);
    assert!(app.voice_ui_active);
    assert!(app.voice_listening(), "start begins recording");
    assert!(
        !app.voice_state.pending_cold_start(),
        "pipeline already up — no re-request"
    );
    assert!(matches!(
        rx.try_recv(),
        Ok(fuigo_voice::VoiceCommand::PttPress { .. })
    ));

    // `EnableVoiceMode` is start-only (not a toggle): running it again while already recording is idempotent, no stop, no second PttPress
    dispatch(Action::EnableVoiceMode, &mut app);
    assert!(app.voice_ui_active, "start never turns voice mode off");
    assert!(app.voice_listening());
    assert!(
        rx.try_recv().is_err(),
        "no second PttPress while already recording"
    );
}

#[test]
fn voice_mode_on_requests_lazy_pipeline_when_missing() {
    // Skip when audio capture isn't compiled in (see sibling test).
    if !fuigo_voice::AUDIO_SUPPORTED {
        return;
    }
    let mut app = test_app_with_agent();
    app.voice_mode_enabled = true;
    // No voice_cmd_tx: the first /voice asks the event loop to spawn
    dispatch(Action::EnableVoiceMode, &mut app);
    assert!(app.voice_ui_active);
    assert!(
        app.voice_state.pending_cold_start(),
        "event loop should spawn the pipeline and auto-start capture"
    );
}

#[test]
fn voice_toggle_while_spawn_pending_keeps_start_armed() {
    // A second Ctrl+Space while the pipeline is still spawning re-affirms the queued start rather than cancelling it
    // There's no visible recording yet to toggle off
    if !fuigo_voice::AUDIO_SUPPORTED {
        return;
    }
    let mut app = test_app_with_agent();
    app.voice_mode_enabled = true;
    app.voice_state = VoiceState::ColdStart {
        hold: false,
        target: VoiceTarget::Agent(AgentId(0)),
    };

    dispatch(Action::VoiceToggle, &mut app);
    assert!(
        app.voice_state.pending_cold_start(),
        "Ctrl+Space re-affirms the queued auto-start (does not cancel it)"
    );
    assert!(!app.voice_listening());
}

#[test]
fn voice_toggle_preserves_pending_ctrl_space_hold_cancel() {
    // A Ctrl+Space quick-tap queues a hold-owned cold-start
    // A Ctrl+Space toggle arriving before the pipeline spawns must re-affirm it without clearing hold-ownership
    // The matching Ctrl+Space release then still cancels the tap
    if !fuigo_voice::AUDIO_SUPPORTED {
        return;
    }
    let mut app = test_app_with_agent();
    app.voice_mode_enabled = true;
    app.voice_state = VoiceState::ColdStart {
        hold: true,
        target: VoiceTarget::Agent(AgentId(0)),
    };

    dispatch(Action::VoiceToggle, &mut app);
    assert!(
        app.voice_state.hold(),
        "toggle must not clear the Ctrl+Space hold-ownership"
    );

    dispatch(Action::VoiceStop, &mut app);
    assert!(
        !app.voice_state.pending_cold_start(),
        "the matching Ctrl+Space release still cancels the queued tap"
    );
}

#[test]
fn voice_toggle_can_always_stop_even_with_flag_disabled() {
    let mut app = test_app_with_agent();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    // Recording was started while the flag was on, then it flipped off.
    app.voice_cmd_tx = Some(tx);
    app.voice_state = VoiceState::Recording {
        session: 1,
        hold: false,
        target: VoiceTarget::Agent(AgentId(0)),
        interim: None,
    };
    app.voice_mode_enabled = false;
    app.voice_ui_active = false;

    dispatch(Action::VoiceToggle, &mut app);
    assert!(
        !app.voice_listening(),
        "must stop an active recording even with the flag off"
    );
    assert!(matches!(
        rx.try_recv(),
        Ok(fuigo_voice::VoiceCommand::PttRelease { .. })
    ));
}

#[test]
fn voice_stop_stops_and_drops_pending_cold_start() {
    // The Ctrl+Space hold release stops capture and cancels a queued cold-start
    // A release that arrives while the pipeline is still spawning can't leave a hot mic running after the key is up
    let mut app = test_app_with_agent();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    app.voice_cmd_tx = Some(tx);
    // A live recording started by a Ctrl+Space hold-press
    app.voice_state = VoiceState::Recording {
        session: 1,
        hold: true,
        target: VoiceTarget::Agent(AgentId(0)),
        interim: None,
    };

    dispatch(Action::VoiceStop, &mut app);
    assert!(!app.voice_listening());
    assert!(!app.voice_state.pending_cold_start());
    assert!(!app.voice_state.hold());
    assert!(matches!(
        rx.try_recv(),
        Ok(fuigo_voice::VoiceCommand::PttRelease { .. })
    ));
}

/// A stray Ctrl+Space release must NOT cancel a cold-start queued by `/voice` or a Ctrl+Space toggle (`hold` is false for those).
#[test]
fn voice_stop_leaves_non_hold_cold_start_armed() {
    let mut app = test_app_with_agent();
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    app.voice_cmd_tx = Some(tx);
    // Queued by /voice, not Ctrl+Space (hold inactive).
    app.voice_state = VoiceState::ColdStart {
        hold: false,
        target: VoiceTarget::Agent(AgentId(0)),
    };

    dispatch(Action::VoiceStop, &mut app);
    assert!(
        app.voice_state.pending_cold_start(),
        "a /voice cold-start must survive an unrelated Ctrl+Space release"
    );
}

/// Changing the STT language shuts down a running pipeline (it holds the VoiceConfig it was spawned with) and persists the preference.
/// The next capture then cold-starts a pipeline with the new language.
/// A mid-recording change also ends the in-flight session so the mic indicator clears at once.
/// Otherwise it would linger until the dead pipeline's channel-close is misreported.
#[test]
fn voice_stt_language_change_recycles_pipeline() {
    let mut app = test_app_with_agent();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    app.voice_cmd_tx = Some(tx);
    app.voice_state = VoiceState::Recording {
        session: 1,
        hold: false,
        target: VoiceTarget::Agent(AgentId(0)),
        interim: Some("hola".to_string()),
    };

    let effects = dispatch(Action::SetVoiceSttLanguage("es".to_string()), &mut app);

    assert_eq!(app.voice_config.language, "es");
    assert_eq!(app.current_ui.voice_stt_language.as_deref(), Some("es"));
    assert!(
        app.voice_cmd_tx.is_none(),
        "handle must drop so the event loop respawns with the new config"
    );
    assert!(
        !app.voice_listening(),
        "recycling the pipeline must end the in-flight session (no lingering hot mic)"
    );
    // The release comes first, then the shutdown. This test previously asserted
    // that `Shutdown` was the *only* command, which held only because the sender
    // was taken out of the `AppView` before `voice_reset` ran -- so the reset had
    // nothing to send to and the microphone was never actually released.
    assert!(
        matches!(
            rx.try_recv(),
            Ok(fuigo_voice::VoiceCommand::PttRelease { .. })
        ),
        "the in-flight session must be released before the pipeline is torn down"
    );
    assert!(matches!(
        rx.try_recv(),
        Ok(fuigo_voice::VoiceCommand::Shutdown)
    ));
    assert!(matches!(
        effects.as_slice(),
        [Effect::PersistSetting {
            key: "voice_stt_language",
            ..
        }]
    ));
}

/// With the UI key unset and a `[voice].language` in effect, selecting the UI default (English) must still commit.
/// The rollback value is the language actually in effect, not the unset-UI default.
#[test]
fn voice_stt_language_english_commits_over_voice_config_language() {
    let mut app = test_app_with_agent();
    app.voice_config.language = "es".into(); // [voice].language; UI key unset

    let effects = dispatch(Action::SetVoiceSttLanguage("en".to_string()), &mut app);

    assert_eq!(app.voice_config.language, "en");
    assert_eq!(app.current_ui.voice_stt_language.as_deref(), Some("en"));
    assert!(matches!(
        effects.as_slice(),
        [Effect::PersistSetting {
            key: "voice_stt_language",
            value: crate::settings::SettingValue::Enum("en"),
            rollback_value: crate::settings::SettingValue::Enum("es"),
        }]
    ));
}

/// Re-selecting the persisted language is a no-op: no persist, and the running pipeline is left alone.
/// An unset UI key never no-ops; the first explicit selection always commits (pins the choice to `[ui]`).
#[test]
fn voice_stt_language_noop_keeps_pipeline() {
    let mut app = test_app_with_agent();
    app.current_ui.voice_stt_language = Some("es".to_string());
    app.voice_config.language = "es".into();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    app.voice_cmd_tx = Some(tx);

    let effects = dispatch(Action::SetVoiceSttLanguage("es".to_string()), &mut app);

    assert!(effects.is_empty());
    assert!(app.voice_cmd_tx.is_some(), "pipeline must survive a no-op");
    assert!(rx.try_recv().is_err());

    // An unset UI key with a matching live value still commits (pins the choice)
    // The language is unchanged, so the pipeline must NOT be recycled
    app.current_ui.voice_stt_language = None;
    let effects = dispatch(Action::SetVoiceSttLanguage("es".to_string()), &mut app);
    assert!(!effects.is_empty(), "explicit pick must persist when unset");
    assert_eq!(app.current_ui.voice_stt_language.as_deref(), Some("es"));
    assert!(
        app.voice_cmd_tx.is_some(),
        "re-pinning the same language must not cut off dictation"
    );
    assert!(
        rx.try_recv().is_err(),
        "no Shutdown when language is unchanged"
    );

    // A non-canonical stored value (hand-edited or invalid on disk) re-commits so the clean canonical is rewritten
    // Still no language change, so the pipeline survives
    app.current_ui.voice_stt_language = Some("ES!".to_string());
    let effects = dispatch(Action::SetVoiceSttLanguage("es".to_string()), &mut app);
    assert!(
        !effects.is_empty(),
        "invalid stored value must be rewritten"
    );
    assert_eq!(app.current_ui.voice_stt_language.as_deref(), Some("es"));
    assert!(
        app.voice_cmd_tx.is_some(),
        "rewriting a non-canonical mirror must not recycle the pipeline"
    );
    assert!(
        rx.try_recv().is_err(),
        "no Shutdown when language is unchanged"
    );
}

/// `auto` is stored as the preference (not a resolved locale code) so the voice crate re-resolves it from the locale on each STT connect.
#[test]
fn voice_stt_language_auto_stored_unresolved() {
    let mut app = test_app_with_agent();

    let _ = dispatch(Action::SetVoiceSttLanguage("auto".to_string()), &mut app);

    assert_eq!(app.voice_config.language, "auto");
    assert_eq!(app.current_ui.voice_stt_language.as_deref(), Some("auto"));
}

#[test]
fn voice_submit_includes_interim() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    app.voice_cmd_tx = Some(tx);
    app.agents.get_mut(&id).unwrap().prompt.set_text("hello");
    app.voice_state = VoiceState::Recording {
        session: 1,
        hold: false,
        target: VoiceTarget::Agent(id),
        interim: Some("world".into()),
    };

    let effects = dispatch(Action::SendPrompt("hello".into()), &mut app);
    let Effect::SendPrompt { text, .. } = &effects[0] else {
        panic!("expected SendPrompt, got {effects:?}");
    };
    assert_eq!(text, "hello world");
    assert!(!app.voice_listening());
    assert!(matches!(
        rx.try_recv(),
        Ok(fuigo_voice::VoiceCommand::PttRelease { .. })
    ));
}

#[test]
fn voice_submit_interim_only() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    app.voice_state = VoiceState::Recording {
        session: 1,
        hold: false,
        target: VoiceTarget::Agent(id),
        interim: Some("ghost only".into()),
    };

    let effects = dispatch(Action::SendPrompt(String::new()), &mut app);
    let Effect::SendPrompt { text, .. } = &effects[0] else {
        panic!("expected SendPrompt, got {effects:?}");
    };
    assert_eq!(text, "ghost only");
    assert!(!app.voice_listening());
}

#[test]
fn voice_submit_follow_up_keeps_chip_literal() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    app.agents.get_mut(&id).unwrap().prompt.set_text("draft");
    app.voice_state = VoiceState::Recording {
        session: 1,
        hold: false,
        target: VoiceTarget::Agent(id),
        interim: Some("dictated".into()),
    };

    let effects = dispatch(Action::SubmitFollowUp("chip text".into()), &mut app);
    let Effect::SendPrompt { text, .. } = &effects[0] else {
        panic!("expected SendPrompt, got {effects:?}");
    };
    assert_eq!(text, "chip text");
    assert_eq!(app.agents.get(&id).unwrap().prompt.text(), "draft dictated");
    assert!(!app.voice_listening());
}

// --- Session identity: where a transcript goes when the user has moved on ----

/// The bug session ids exist for: dictate into agent A, re-press while looking
/// at agent B, and A's transcript arrives after the switch. Routing by "whatever
/// is bound now" spliced A's words into B's prompt.
#[test]
fn a_detached_transcript_lands_in_the_box_it_was_dictated_into() {
    let mut app = test_app_with_two_agents();
    let (a, b) = (AgentId(0), AgentId(1));
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    app.voice_cmd_tx = Some(tx);

    app.voice_begin_recording(VoiceTarget::Agent(a), false);
    let first = app.voice_state.session().expect("recording has a session");
    // The user re-presses, now bound to B. A's recording is still uploading.
    app.voice_begin_recording(VoiceTarget::Agent(b), false);
    let second = app.voice_state.session().expect("recording has a session");
    assert_ne!(first, second, "each press mints a new session");

    crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::UtteranceFinal {
            session: first,
            text: "words for A".into(),
        },
    );

    assert_eq!(app.agents.get(&a).unwrap().prompt.text(), "words for A");
    assert_eq!(
        app.agents.get(&b).unwrap().prompt.text(),
        "",
        "the newer target must not receive the older session's dictation"
    );
}

/// A hard teardown is a cancel. Dictation the user cancelled must not reappear
/// in a prompt box once its upload finishes.
#[test]
fn a_transcript_from_a_hard_reset_session_is_dropped() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    app.voice_cmd_tx = Some(tx);

    app.voice_begin_recording(VoiceTarget::Agent(id), false);
    let session = app.voice_state.session().unwrap();
    app.voice_reset();

    let redraw = crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::UtteranceFinal {
            session,
            text: "cancelled".into(),
        },
    );
    assert!(!redraw);
    assert_eq!(app.agents.get(&id).unwrap().prompt.text(), "");
}

/// The hot-mic hazard: an older session's failure must not tear down the
/// recording the user has since started.
#[test]
fn a_stale_error_does_not_reset_a_live_recording() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    app.voice_cmd_tx = Some(tx);

    app.voice_begin_recording(VoiceTarget::Agent(id), false);
    let stale = app.voice_state.session().unwrap();
    app.voice_begin_recording(VoiceTarget::Agent(id), false);
    let live = app.voice_state.session().unwrap();

    crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::Error {
            session: stale,
            message: "upload failed".into(),
            hint: None,
        },
    );

    assert!(
        app.voice_listening(),
        "the live recording must survive an older session's failure"
    );
    assert_eq!(app.voice_state.session(), Some(live));
}

/// The current session's own failure still tears the dictation down: a dead mic
/// or a refused endpoint should not leave a listening UI behind.
#[test]
fn the_current_sessions_error_still_resets() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    app.voice_cmd_tx = Some(tx);

    app.voice_begin_recording(VoiceTarget::Agent(id), false);
    let session = app.voice_state.session().unwrap();
    crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::Error {
            session,
            message: "No speech was detected. Voice stopped.".into(),
            hint: None,
        },
    );
    assert!(!app.voice_listening());
    assert!(matches!(app.voice_state, VoiceState::Idle));
}

/// A superseded session that then fails is news the user is owed -- those words
/// are gone -- but it is not a teardown.
#[test]
fn a_detached_session_failure_is_reported_without_a_reset() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    app.voice_cmd_tx = Some(tx);

    app.voice_begin_recording(VoiceTarget::Agent(id), false);
    let stale = app.voice_state.session().unwrap();
    app.voice_begin_recording(VoiceTarget::Agent(id), false);

    let redraw = crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::Error {
            session: stale,
            message: "An earlier dictation was dropped".into(),
            hint: None,
        },
    );
    assert!(redraw, "the user must be told");
    assert!(app.voice_listening(), "but nothing is torn down");
    assert!(
        !app.voice_detached.iter().any(|(s, _)| *s == stale),
        "a resolved session is forgotten"
    );
}

/// An interim for a session that is no longer on screen would overwrite the
/// overlay of the recording being made now.
#[test]
fn a_stale_interim_is_dropped() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    app.voice_state = VoiceState::Recording {
        session: 9,
        hold: false,
        target: VoiceTarget::Agent(id),
        interim: Some("live".into()),
    };
    let redraw = crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::InterimTranscript {
            session: 8,
            text: "stale".into(),
        },
    );
    assert!(!redraw);
    assert_eq!(app.voice_interim(), Some("live"));
}

/// Delivering text does not end the turn; `SessionEnded` does. A final that is
/// suppressed as a duplicate would otherwise leave the session hanging, and a
/// correction arriving after the first final would have no owner.
#[test]
fn the_session_ends_on_session_ended_not_on_a_final() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    app.voice_state = VoiceState::Stopping {
        session: 3,
        target: VoiceTarget::Agent(id),
        interim: None,
    };
    crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::UtteranceFinal {
            session: 3,
            text: "once".into(),
        },
    );
    assert!(
        matches!(app.voice_state, VoiceState::Stopping { .. }),
        "the text landed, but the pipeline has not said the turn is over"
    );

    crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::SessionEnded { session: 3 },
    );
    assert!(matches!(app.voice_state, VoiceState::Idle));

    // Past the end, a stray event for that session has no claim on anything.
    crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::UtteranceFinal {
            session: 3,
            text: "twice".into(),
        },
    );
    assert_eq!(app.agents.get(&id).unwrap().prompt.text(), "once");
}

/// Streaming emits a final per `speech_final` pause and keeps the mic open, so
/// a final while `Recording` must not end the session.
#[test]
fn a_final_while_recording_keeps_the_session_live() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    app.voice_state = VoiceState::Recording {
        session: 4,
        hold: false,
        target: VoiceTarget::Agent(id),
        interim: None,
    };
    crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::UtteranceFinal {
            session: 4,
            text: "first".into(),
        },
    );
    assert!(app.voice_listening());
    crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::UtteranceFinal {
            session: 4,
            text: "second".into(),
        },
    );
    assert_eq!(app.agents.get(&id).unwrap().prompt.text(), "first second");
}

// --- Enter during a batch dictation: who owns the key ------------------------

/// The interception's reason for existing: with an empty composer no view turns
/// Enter into a send, so without this the key would do nothing at all while the
/// microphone stayed open.
#[test]
fn enter_during_a_batch_recording_stops_it_and_is_consumed() {
    use crate::app::app_view::InputOutcome;
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    app.voice_cmd_tx = Some(tx);
    app.agents
        .get_mut(&id)
        .unwrap()
        .set_active_pane(crate::views::agent::ActivePane::Prompt, false);
    app.voice_begin_recording(VoiceTarget::Agent(id), false);

    let out = app.handle_input(&Event::Key(KeyEvent::new(
        KeyCode::Enter,
        KeyModifiers::NONE,
    )));

    assert!(matches!(out, InputOutcome::Changed));
    assert!(!app.voice_listening(), "the recording is ended");
    assert!(
        matches!(app.voice_state, VoiceState::Stopping { .. }),
        "and kept, so the transcript still has somewhere to land: {:?}",
        app.voice_state
    );
}

/// A blocking card sits *over* a visible prompt without being a modal, so the
/// weaker "is the box on screen" check let the interception steal its Enter and
/// leave it unanswerable. The dictation is worth less than the ability to answer.
#[test]
fn enter_belongs_to_an_open_blocking_card_not_to_the_dictation() {
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    app.voice_cmd_tx = Some(tx);
    app.agents
        .get_mut(&id)
        .unwrap()
        .set_active_pane(crate::views::agent::ActivePane::Prompt, false);
    app.voice_begin_recording(VoiceTarget::Agent(id), false);
    app.agents.get_mut(&id).unwrap().plan_approval_view =
        Some(crate::app::agent_view::test_fixtures::make_plan_approval_view_state());

    let _ = app.handle_input(&Event::Key(KeyEvent::new(
        KeyCode::Enter,
        KeyModifiers::NONE,
    )));

    assert!(
        app.voice_listening(),
        "the interception must not fire while something inline owns Enter"
    );
}

/// Same rule for a pane that is not the prompt: Enter there is the pane's.
#[test]
fn enter_outside_the_prompt_pane_does_not_stop_the_dictation() {
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    app.voice_cmd_tx = Some(tx);
    app.voice_begin_recording(VoiceTarget::Agent(id), false);
    app.agents
        .get_mut(&id)
        .unwrap()
        .set_active_pane(crate::views::agent::ActivePane::Scrollback, false);

    let _ = app.handle_input(&Event::Key(KeyEvent::new(
        KeyCode::Enter,
        KeyModifiers::NONE,
    )));

    assert!(app.voice_listening());
}

/// The interception tells the user "press Enter again to send". Doing exactly
/// that, before the upload finishes, used to destroy the dictation: the second
/// Enter reached the submit funnel, which keyed its soft-stop on
/// `voice_listening()` -- false in `Stopping` -- and hard-reset instead, so the
/// arriving final belonged to no one and was dropped without a toast.
#[test]
fn following_the_press_enter_again_advice_does_not_lose_the_dictation() {
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    app.voice_cmd_tx = Some(tx);
    app.agents
        .get_mut(&id)
        .unwrap()
        .set_active_pane(crate::views::agent::ActivePane::Prompt, false);
    app.agents.get_mut(&id).unwrap().prompt.set_text("fix the");
    app.voice_begin_recording(VoiceTarget::Agent(id), false);
    let session = app.voice_state.session().expect("recording");

    // First Enter: the interception stops the capture and says to press again.
    let _ = app.handle_input(&Event::Key(KeyEvent::new(
        KeyCode::Enter,
        KeyModifiers::NONE,
    )));
    assert!(matches!(app.voice_state, VoiceState::Stopping { .. }));

    // Second Enter, while the upload is still in flight: this submits.
    let _ = app.handle_input(&Event::Key(KeyEvent::new(
        KeyCode::Enter,
        KeyModifiers::NONE,
    )));

    // The transcript arrives afterwards and must still have somewhere to go.
    let redraw = crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::UtteranceFinal {
            session,
            text: "the build".into(),
        },
    );
    assert!(redraw, "the dictation must be delivered, not dropped");
    assert!(
        app.agents
            .get(&id)
            .unwrap()
            .prompt
            .text()
            .contains("the build"),
        "the words the user spoke must land in the box they dictated into, got {:?}",
        app.agents.get(&id).unwrap().prompt.text()
    );
}

/// A routine failure on the *current* session must not destroy transcripts that
/// other sessions are still uploading.
///
/// The sequence is ordinary: dictate into A, re-press, then say nothing — the
/// no-speech watchdog fires for the new session. An earlier revision cleared the
/// whole detached ledger on any error teardown, so A's words vanished silently.
#[test]
fn a_current_session_failure_does_not_cancel_other_sessions_transcripts() {
    let mut app = test_app_with_two_agents();
    let (a, b) = (AgentId(0), AgentId(1));
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    app.voice_cmd_tx = Some(tx);

    app.voice_begin_recording(VoiceTarget::Agent(a), false);
    let first = app.voice_state.session().unwrap();
    app.voice_begin_recording(VoiceTarget::Agent(b), false);
    let second = app.voice_state.session().unwrap();

    // The new session hits the no-speech watchdog.
    crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::Error {
            session: second,
            message: "No speech was detected. Voice stopped.".into(),
            hint: None,
        },
    );
    assert!(matches!(app.voice_state, VoiceState::Idle));

    // The first session's upload finishes afterwards. Those words were spoken.
    crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::UtteranceFinal {
            session: first,
            text: "words for A".into(),
        },
    );
    assert_eq!(
        app.agents.get(&a).unwrap().prompt.text(),
        "words for A",
        "an unrelated session's failure must not discard this transcript"
    );
}

/// Turning voice off entirely is different: nothing is left to deliver with, so
/// every pending transcript is abandoned rather than surfacing later.
#[test]
fn cancelling_dictation_wholesale_drops_detached_sessions() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    app.voice_cmd_tx = Some(tx);

    app.voice_begin_recording(VoiceTarget::Agent(id), false);
    let first = app.voice_state.session().unwrap();
    app.voice_begin_recording(VoiceTarget::Agent(id), false);
    app.voice_cancel_all_dictation();

    let redraw = crate::voice::handle_voice_event(
        &mut app,
        fuigo_voice::VoiceEvent::UtteranceFinal {
            session: first,
            text: "abandoned".into(),
        },
    );
    assert!(!redraw);
    assert_eq!(app.agents.get(&id).unwrap().prompt.text(), "");
}

/// Esc is the way out of a transcription that never lands: Enter is swallowed
/// while one is pending, so without this the composer would be unsendable and
/// uncancellable for as long as the upload hangs.
#[test]
fn esc_abandons_a_pending_transcription() {
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    app.voice_cmd_tx = Some(tx);
    app.agents
        .get_mut(&id)
        .unwrap()
        .set_active_pane(crate::views::agent::ActivePane::Prompt, false);
    app.voice_begin_recording(VoiceTarget::Agent(id), false);
    let _ = app.handle_input(&Event::Key(KeyEvent::new(
        KeyCode::Enter,
        KeyModifiers::NONE,
    )));
    assert!(matches!(app.voice_state, VoiceState::Stopping { .. }));

    let _ = app.handle_input(&Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));

    assert!(
        matches!(app.voice_state, VoiceState::Idle),
        "Esc must release the composer, got {:?}",
        app.voice_state
    );
}
