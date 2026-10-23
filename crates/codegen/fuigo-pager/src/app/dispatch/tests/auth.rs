//! Tests for login, logout, account switching, and auth-code dispatchers.

use super::*;

#[test]
fn cta_mcps_loaded_needs_auth_opens_modal_and_seeds() {
    use crate::app::agent_view::CtaPhase;
    use crate::views::extensions_modal::{ExtensionsTab, TabDataState};
    use crate::views::mcps_modal::{McpSectionId, McpServerDisplayStatus, section_key};
    let mut app = test_app_with_agent();
    app.team_id = Some("team-uuid".into());
    let id = AgentId(0);
    app.agents.get_mut(&id).unwrap().plugin_cta.phase = CtaPhase::AwaitingMcps {
        name: "figma".into(),
    };
    let servers = vec![
        cta_mcp_server("fuigo_com_managed", None, McpServerDisplayStatus::Ready),
        cta_mcp_server("local-srv", None, McpServerDisplayStatus::Ready),
        cta_mcp_server("other-srv", Some("slack"), McpServerDisplayStatus::Ready),
        cta_mcp_server(
            "figma-srv",
            Some("figma"),
            McpServerDisplayStatus::NeedsAuth,
        ),
    ];
    let effects = dispatch(
        Action::TaskComplete(TaskResult::PluginCtaMcpsLoaded {
            agent_id: id,
            plugin_name: "figma".into(),
            result: Ok(servers),
        }),
        &mut app,
    );
    // The CTA is finished; the modal owns the flow from here
    assert_eq!(app.agents[&id].plugin_cta.phase, CtaPhase::Hidden);
    // Modal opened to the MCP Servers tab.
    let modal = app.agents[&id]
        .extensions_modal
        .as_ref()
        .expect("extensions modal should be open");
    assert_eq!(modal.active_tab, ExtensionsTab::McpServers);
    // MCP tab seeded directly from the read we already have (no flash).
    match &modal.mcps_data {
        TabDataState::Loaded(servers) => assert_eq!(servers.len(), 4),
        other => panic!("expected mcps_data Loaded, got {other:?}"),
    }
    // Managed, Local, and other plugins collapsed; only the target plugin expanded
    let collapsed = &modal.mcps_collapsed_sections;
    assert!(collapsed.contains(&section_key(&McpSectionId::Managed)));
    assert!(collapsed.contains(&section_key(&McpSectionId::Local)));
    assert!(collapsed.contains(&section_key(&McpSectionId::Plugin("slack".into()))));
    assert!(!collapsed.contains(&section_key(&McpSectionId::Plugin("figma".into()))));
    assert!(modal.mcps_section_collapse_initialized);
    // Emits the same full set of tab fetches as a manual open so no tab is stuck Loading, plus the candidate refresh
    assert_eq!(
        effects
            .iter()
            .filter(|e| matches!(e, Effect::FetchHooksList { .. }))
            .count(),
        1
    );
    assert_eq!(
        effects
            .iter()
            .filter(|e| matches!(e, Effect::FetchPluginsList { .. }))
            .count(),
        1
    );
    assert_eq!(
        effects
            .iter()
            .filter(|e| matches!(e, Effect::FetchMarketplaceList { .. }))
            .count(),
        1
    );
    assert_eq!(
        effects
            .iter()
            .filter(|e| matches!(e, Effect::FetchMcpsList { .. }))
            .count(),
        1
    );
    assert_eq!(
        effects
            .iter()
            .filter(|e| matches!(e, Effect::FetchSkillsList { .. }))
            .count(),
        1
    );
    assert!(
        effects
            .iter()
            .any(|e| matches!(e, Effect::FetchPluginCtaCatalog { .. }))
    );
}

#[test]
fn cta_mcps_loaded_no_needs_auth_terminal_sets_installed() {
    use crate::app::agent_view::CtaPhase;
    use crate::views::mcps_modal::McpServerDisplayStatus;
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    {
        let cta = &mut app.agents.get_mut(&id).unwrap().plugin_cta;
        cta.phase = CtaPhase::AwaitingMcps {
            name: "figma".into(),
        };
        cta.expects_mcp = true;
    }
    // The plugin server is present and Ready (terminal, no auth), so the CTA settles now
    let servers = vec![cta_mcp_server(
        "figma-srv",
        Some("figma"),
        McpServerDisplayStatus::Ready,
    )];
    let effects = dispatch(
        Action::TaskComplete(TaskResult::PluginCtaMcpsLoaded {
            agent_id: id,
            plugin_name: "figma".into(),
            result: Ok(servers),
        }),
        &mut app,
    );
    assert_eq!(
        app.agents[&id].plugin_cta.phase,
        CtaPhase::Installed {
            name: "figma".into()
        }
    );
    assert!(app.agents[&id].extensions_modal.is_none());
    // No modal repopulation; settling emits the auto-dismiss timer and the candidate refresh, and never re-fetches the MCP list
    assert!(
        !effects
            .iter()
            .any(|e| matches!(e, Effect::FetchMcpsList { .. }))
    );
    assert!(
        !effects
            .iter()
            .any(|e| matches!(e, Effect::RetryPluginCtaMcps { .. }))
    );
    assert!(
        effects
            .iter()
            .any(|e| matches!(e, Effect::DismissCtaInstalled { .. }))
    );
    assert!(
        effects
            .iter()
            .any(|e| matches!(e, Effect::FetchPluginCtaCatalog { .. }))
    );
}

#[test]
fn cta_mcps_loaded_later_needs_auth_opens_handoff() {
    use crate::app::agent_view::CtaPhase;
    use crate::views::mcps_modal::McpServerDisplayStatus;
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    {
        let cta = &mut app.agents.get_mut(&id).unwrap().plugin_cta;
        cta.phase = CtaPhase::AwaitingMcps {
            name: "figma".into(),
        };
        cta.expects_mcp = true;
        // Several polls already elapsed before the server reached NeedsAuth.
        cta.mcp_attempt = 5;
    }
    let effects = dispatch(
        Action::TaskComplete(TaskResult::PluginCtaMcpsLoaded {
            agent_id: id,
            plugin_name: "figma".into(),
            result: Ok(vec![cta_mcp_server(
                "figma-srv",
                Some("figma"),
                McpServerDisplayStatus::NeedsAuth,
            )]),
        }),
        &mut app,
    );
    // NeedsAuth is terminal: the modal opens immediately even mid-poll
    assert_eq!(app.agents[&id].plugin_cta.phase, CtaPhase::Hidden);
    assert!(app.agents[&id].extensions_modal.is_some());
    assert!(
        !effects
            .iter()
            .any(|e| matches!(e, Effect::RetryPluginCtaMcps { .. }))
    );
}

// ── agent-bound kinds (bash) ─────────

/// A bash command typed while a turn is running goes straight to the server: an Effect and an optimistic echo, no local queue entry.
#[test]
fn bash_while_running_is_server_authoritative() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    app.agents.get_mut(&id).unwrap().session.state = AgentState::TurnRunning;

    let effects = dispatch(Action::SendBashCommand("ls -la".into()), &mut app);
    let pid = match &effects[0] {
        Effect::SendBashCommand {
            command, prompt_id, ..
        } => {
            assert_eq!(command, "ls -la");
            prompt_id.clone()
        }
        other => panic!("expected immediate SendBashCommand, got {other:?}"),
    };
    assert_eq!(app.agents[&id].session.queue_len(), 0);
    // Optimistic echo present with kind="bash".
    let q = app
        .shared_prompt_queue("test-session")
        .expect("echo present");
    assert_eq!(q.len(), 1);
    assert_eq!(q[0].id, pid);
    assert_eq!(q[0].kind, "bash");
    assert_eq!(q[0].text, "ls -la");
}

#[test]
fn auth_complete_triggers_bundle_status_fetch() {
    let mut app = test_app();
    app.auth_state = AuthState::Authenticating {
        request_seq: 1,
        handle: None,
        auth_url: None,
        mode: AuthMode::Pending,
    };

    let effects = dispatch(
        Action::TaskComplete(TaskResult::AuthComplete {
            request_seq: 1,
            meta: None,
        }),
        &mut app,
    );

    assert!(matches!(app.auth_state, AuthState::Done));
    // The pager only refreshes the on-disk catalog snapshot; the bundle download runs inside the shell after auth
    assert!(
        effects
            .iter()
            .any(|e| matches!(e, Effect::FetchBundleStatus))
    );
}

#[test]
fn auth_complete_with_deferred_load_also_fetches_status() {
    let mut app = test_app();
    app.auth_state = AuthState::Authenticating {
        request_seq: 1,
        handle: None,
        auth_url: None,
        mode: AuthMode::Pending,
    };
    app.deferred_startup.session =
        Some(crate::app::session_startup::DeferredSessionStartup::Load {
            session_id: "test-session".into(),
            session_cwd: None,
            chat_kind: false,
        });

    let effects = dispatch(
        Action::TaskComplete(TaskResult::AuthComplete {
            request_seq: 1,
            meta: None,
        }),
        &mut app,
    );

    assert!(
        effects
            .iter()
            .any(|e| matches!(e, Effect::FetchBundleStatus))
    );
    assert!(
        effects
            .iter()
            .any(|e| matches!(e, Effect::LoadSession { .. }))
    );
    assert!(app.deferred_startup.session.is_none());
}

/// `/login` from the welcome screen (startup, logged out) must not stash a return view; the normal login-then-load flow is preserved.
#[test]
fn login_from_welcome_does_not_stash_return_view() {
    let mut app = test_app();
    assert_eq!(app.active_view, ActiveView::Welcome);

    dispatch(Action::Login, &mut app);

    assert_eq!(app.active_view, ActiveView::Welcome);
    assert_eq!(app.auth_return_view, None);
}

/// Compact-auth recovery: the prompt is held across an auto-compact 401, stashed on PromptResponse, and resubmitted on a mid-session AuthComplete.
#[test]
fn e2e_compact_auth_failure_holds_prompt_and_resubmits_after_login() {
    use crate::app::acp_handler::apply_session_event_for_test;
    use crate::app::agent::{AgentState, InFlightPrompt};
    use crate::scrollback::EntryId;
    use crate::scrollback::block::RenderBlock;
    use fuigo_shell::extensions::notification::{RetryState, SessionUpdate as FuigoSessionUpdate};

    let mut app = test_app_with_agent();
    let id = AgentId(0);
    {
        let agent = app.agents.get_mut(&id).unwrap();
        agent.session.state = AgentState::TurnRunning;
        agent.turn_started_at = Some(std::time::Instant::now());
        agent.session.session_id = Some(acp::SessionId::new("sess-compact-auth-e2e"));
        agent.session.current_prompt_id = Some("prompt-1".into());
        agent.session.in_flight_prompt = Some(InFlightPrompt {
            text: "please continue after login".into(),
            images: Vec::new(),
            scrollback_entry: EntryId::new(1),
            combined_scrollback_entries: Vec::new(),
            chip_elements: Vec::new(),
        });

        apply_session_event_for_test(
            &FuigoSessionUpdate::AutoCompactStarted {
                tokens_used: 180_000,
                context_window: 200_000,
                percentage: 90,
                reason: "threshold".into(),
            },
            &mut agent.session,
            &mut agent.scrollback,
        );
        assert!(
            agent.session.in_flight_prompt.is_none(),
            "cancel rewind must still be blocked mid-compact"
        );
        assert_eq!(
            agent
                .session
                .compact_held_prompt
                .as_ref()
                .map(|p| p.text.as_str()),
            Some("please continue after login"),
            "must hold the prompt text for reauth auto-resubmit"
        );

        apply_session_event_for_test(
            &FuigoSessionUpdate::AutoCompactFailed {
                error: "authentication problem — re-authenticate using /login and retry.".into(),
            },
            &mut agent.session,
            &mut agent.scrollback,
        );
        assert!(agent.session.compact_held_prompt.is_some());

        apply_session_event_for_test(
            &FuigoSessionUpdate::RetryState(RetryState::Failed {
                error_type: "auth".into(),
                message: "Unauthorized (401): compaction failed".into(),
                verdicts: None,
            }),
            &mut agent.session,
            &mut agent.scrollback,
        );
        let has_reauth = (0..agent.scrollback.len()).any(|i| {
            matches!(
                agent.scrollback.entry(i).map(|e| &e.block),
                Some(RenderBlock::SessionEvent(ev))
                    if matches!(ev.event, SessionEvent::ReAuthRequired)
            )
        });
        assert!(has_reauth, "RetryState auth must show ReAuthRequired");
    }

    dispatch(
        Action::TaskComplete(TaskResult::PromptResponse {
            agent_id: id,
            result: Err("Unauthorized (401)".to_string()),
            http_status: Some(401),
            verdicts: None,
            prompt_id: Some("prompt-1".into()),
        }),
        &mut app,
    );
    assert_eq!(
        app.agents[&id]
            .reauth_stashed_prompt
            .as_ref()
            .map(|p| p.text.as_str()),
        Some("please continue after login"),
        "PromptResponse must stash the compact-held prompt for AuthComplete"
    );

    dispatch(Action::Login, &mut app);
    let seq = authenticating_seq(&app);
    let effects = dispatch(
        Action::TaskComplete(TaskResult::AuthComplete {
            request_seq: seq,
            meta: None,
        }),
        &mut app,
    );
    assert!(
        app.agents[&id].reauth_stashed_prompt.is_none(),
        "stash consumed on AuthComplete"
    );
    assert!(
        effects.iter().any(|e| matches!(
            e,
            Effect::SendPrompt { .. } | Effect::SendPromptBlocks { .. }
        )),
        "AuthComplete must resubmit the prompt so compact runs again with valid auth, got: {effects:?}"
    );
}

/// Without `compact_held_prompt`, clearing `in_flight_prompt` when compact starts leaves nothing for reauth to stash.
#[test]
fn pre_fix_compact_start_without_hold_cannot_stash_for_reauth() {
    use crate::app::agent::AgentState;
    use crate::scrollback::block::RenderBlock;

    let mut app = test_app_with_agent();
    let id = AgentId(0);
    {
        let agent = app.agents.get_mut(&id).unwrap();
        agent.session.state = AgentState::TurnRunning;
        agent.turn_started_at = Some(std::time::Instant::now());
        agent.session.session_id = Some(acp::SessionId::new("sess-pre-fix"));
        agent.session.current_prompt_id = Some("p1".into());
        agent.session.in_flight_prompt = None;
        agent.session.compact_held_prompt = None;
        agent
            .scrollback
            .push_block(RenderBlock::session_event(SessionEvent::ReAuthRequired));
    }
    dispatch(
        Action::TaskComplete(TaskResult::PromptResponse {
            agent_id: id,
            result: Err("Unauthorized (401)".to_string()),
            http_status: Some(401),
            verdicts: None,
            prompt_id: Some("p1".into()),
        }),
        &mut app,
    );
    assert!(
        app.agents[&id].reauth_stashed_prompt.is_none(),
        "without compact_held / in_flight, reauth cannot stash — the pre-fix bug"
    );
}

/// A second auth-failed turn with no rewindable prompt (`in_flight_prompt == None`) must not clobber the stash from an earlier 401.
#[test]
fn second_auth_failure_does_not_clobber_reauth_stash() {
    use crate::scrollback::block::RenderBlock;
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    {
        let agent = app.agents.get_mut(&id).unwrap();
        agent.reauth_stashed_prompt = Some(crate::app::agent::InFlightPrompt {
            text: "first prompt".into(),
            images: Vec::new(),
            scrollback_entry: crate::scrollback::EntryId::new(0),
            combined_scrollback_entries: Vec::new(),
            chip_elements: Vec::new(),
        });
        agent
            .scrollback
            .push_block(RenderBlock::session_event(SessionEvent::ReAuthRequired));
        agent.session.state = AgentState::TurnRunning;
        agent.turn_started_at = Some(std::time::Instant::now());
        agent.session.in_flight_prompt = None;
    }

    dispatch(
        Action::TaskComplete(TaskResult::PromptResponse {
            agent_id: id,
            result: Err("Unauthorized (401)".to_string()),
            http_status: Some(401),
            verdicts: None,
            prompt_id: None,
        }),
        &mut app,
    );

    assert_eq!(
        app.agents[&id]
            .reauth_stashed_prompt
            .as_ref()
            .map(|prompt| prompt.text.as_str()),
        Some("first prompt"),
        "a None in_flight_prompt must not wipe an earlier stash"
    );
}

/// Cancelling a mid-session re-auth drops the stashed prompt so it is not silently resubmitted on a later, unrelated login.
#[test]
fn cancel_login_drops_reauth_stashed_prompt() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    app.agents.get_mut(&id).unwrap().reauth_stashed_prompt =
        Some(crate::app::agent::InFlightPrompt {
            text: "stale".into(),
            images: Vec::new(),
            scrollback_entry: crate::scrollback::EntryId::new(0),
            combined_scrollback_entries: Vec::new(),
            chip_elements: Vec::new(),
        });

    dispatch(Action::Login, &mut app);
    dispatch(Action::CancelLogin, &mut app);

    assert!(
        app.agents[&id].reauth_stashed_prompt.is_none(),
        "cancelling re-auth must drop the stashed prompt"
    );
}

/// Cancelling a mid-session re-auth strips the stale `ReAuthRequired` prompt from scrollback.
/// A later `PromptResponse` can then no longer re-detect it and re-stash the prompt for silent resubmission.
#[test]
fn cancel_login_strips_reauth_prompt_from_scrollback() {
    use crate::scrollback::block::RenderBlock;
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    {
        let agent = app.agents.get_mut(&id).unwrap();
        agent.reauth_stashed_prompt = Some(crate::app::agent::InFlightPrompt {
            text: "stale".into(),
            images: Vec::new(),
            scrollback_entry: crate::scrollback::EntryId::new(0),
            combined_scrollback_entries: Vec::new(),
            chip_elements: Vec::new(),
        });
        agent
            .scrollback
            .push_block(RenderBlock::session_event(SessionEvent::ReAuthRequired));
    }

    dispatch(Action::Login, &mut app);
    dispatch(Action::CancelLogin, &mut app);

    let sb = &app.agents[&id].scrollback;
    let has_reauth = (0..sb.len()).any(|i| {
        matches!(
            sb.entry(i).map(|e| &e.block),
            Some(RenderBlock::SessionEvent(ev)) if matches!(ev.event, SessionEvent::ReAuthRequired)
        )
    });
    assert!(
        !has_reauth,
        "cancelling re-auth must strip the stale re-auth prompt from scrollback"
    );
}

/// Empty `auth_methods` (the preferred_method pin is unavailable) must not invent `grok.com` or start an OIDC flow the agent did not advertise.
#[test]
fn login_with_empty_auth_methods_fails_closed() {
    let mut app = test_app_with_agent();
    app.auth_methods.clear();
    app.login_method_id = None;

    let effects = dispatch(Action::Login, &mut app);

    assert!(
        effects.is_empty(),
        "must not start Authenticate without an advertised method"
    );
    assert_eq!(
        app.active_view,
        ActiveView::Agent(AgentId(0)),
        "must stay on the session view"
    );
    assert!(
        matches!(
            &app.auth_state,
            AuthState::Pending { error: Some(msg) }
                if msg.contains("preferred_method=api_key")
        ),
        "must surface pin-unavailable error, got {:?}",
        app.auth_state
    );
    assert!(app.login_method_id.is_none());
}

/// Puts the app in `Authenticating` with a live task's abort handle installed, as the event loop would.
/// Returns the task's JoinHandle and the seq.
/// Callers assert the task actually gets aborted (`unwrap_err().is_cancelled()`), not merely that the handle slot was cleared.
fn install_live_auth_task(
    app: &mut AppView,
    rt: &tokio::runtime::Runtime,
) -> (tokio::task::JoinHandle<()>, u64) {
    dispatch(Action::Login, app);
    let task = rt.spawn(std::future::pending::<()>());
    match &mut app.auth_state {
        AuthState::Authenticating {
            handle,
            request_seq,
            ..
        } => {
            *handle = Some(task.abort_handle());
            (task, *request_seq)
        }
        other => panic!("expected Authenticating after Login, got {other:?}"),
    }
}

fn test_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
}

/// A second `/login` while already authenticating must abort the prior auth task and bump the seq.
/// Single-flight: never two device-code requests running at once.
#[test]
fn login_while_authenticating_aborts_prior_task() {
    let rt = test_runtime();
    let mut app = test_app_with_agent();
    let (prior_task, first_seq) = install_live_auth_task(&mut app, &rt);

    let effects = dispatch(Action::Login, &mut app);

    rt.block_on(async {
        assert!(
            prior_task.await.unwrap_err().is_cancelled(),
            "prior auth task must be aborted"
        );
    });
    match &app.auth_state {
        AuthState::Authenticating { request_seq, .. } => {
            assert!(
                *request_seq > first_seq,
                "re-login must bump request_seq for single-flight"
            );
        }
        other => panic!("expected Authenticating after re-Login, got {other:?}"),
    }
    assert!(
        effects
            .iter()
            .any(|e| matches!(e, Effect::Authenticate { .. })),
        "re-login must emit a new Authenticate"
    );
}

/// A stale `AuthComplete` (its abort lost the race because the task had already finished) must not complete the new attempt.
/// The request-seq guard is the only protection here.
#[test]
fn stale_auth_complete_after_relogin_is_ignored() {
    let mut app = test_app_with_agent();
    dispatch(Action::Login, &mut app);
    let first_seq = match &app.auth_state {
        AuthState::Authenticating { request_seq, .. } => *request_seq,
        other => panic!("expected Authenticating after Login, got {other:?}"),
    };
    dispatch(Action::Login, &mut app); // re-login bumps to seq2

    dispatch(
        Action::TaskComplete(TaskResult::AuthComplete {
            request_seq: first_seq,
            meta: None,
        }),
        &mut app,
    );

    match &app.auth_state {
        AuthState::Authenticating { request_seq, .. } => {
            assert!(
                *request_seq > first_seq,
                "stale AuthComplete must leave the new attempt authenticating"
            );
        }
        other => panic!("stale AuthComplete must be ignored, got {other:?}"),
    }
}

/// Switch-account while authenticating goes through the same single-flight abort as `/login` (sibling entry point).
#[test]
fn switch_account_while_authenticating_aborts_prior_task() {
    let rt = test_runtime();
    let mut app = test_app_with_agent();
    let (prior_task, first_seq) = install_live_auth_task(&mut app, &rt);

    dispatch(Action::SwitchAccount, &mut app);

    rt.block_on(async {
        assert!(
            prior_task.await.unwrap_err().is_cancelled(),
            "prior auth task must be aborted on switch-account"
        );
    });
    match &app.auth_state {
        AuthState::Authenticating { request_seq, .. } => {
            assert!(*request_seq > first_seq, "switch must bump request_seq");
        }
        other => panic!("expected Authenticating after SwitchAccount, got {other:?}"),
    }
}

/// Cancelling a mid-session login aborts the in-flight auth task (not just restores the view) so a retry cannot race a still-polling prior attempt.
#[test]
fn cancel_login_aborts_prior_task() {
    let rt = test_runtime();
    let mut app = test_app_with_agent();
    // Login from a session view stashes `auth_return_view`, making CancelLogin live.
    let (prior_task, _) = install_live_auth_task(&mut app, &rt);

    dispatch(Action::CancelLogin, &mut app);

    rt.block_on(async {
        assert!(
            prior_task.await.unwrap_err().is_cancelled(),
            "cancel must abort the in-flight auth task"
        );
    });
}

/// Cancelling a mid-session login returns to the session rather than quitting the app, and clears the stashed view and auth state.
#[test]
fn cancel_login_restores_view() {
    let mut app = test_app_with_agent();
    dispatch(Action::Login, &mut app);
    assert_eq!(app.active_view, ActiveView::Welcome);
    let prior_seq = match &app.auth_state {
        AuthState::Authenticating { request_seq, .. } => *request_seq,
        other => panic!("expected Authenticating after Login, got {other:?}"),
    };

    let effects = dispatch(Action::CancelLogin, &mut app);

    assert!(
        matches!(
            effects.as_slice(),
            [Effect::CancelAuth { request_seq }] if *request_seq == prior_seq
        ),
        "cancel must tell the shell to stop the in-flight auth poll for this attempt"
    );
    assert_eq!(app.active_view, ActiveView::Agent(AgentId(0)));
    assert_eq!(app.auth_return_view, None);
    assert!(matches!(app.auth_state, AuthState::Done));
}

/// `CancelLogin` outside a mid-session login is a no-op (must not move off the welcome screen or panic).
#[test]
fn cancel_login_noop_without_stashed_view() {
    let mut app = test_app();
    let effects = dispatch(Action::CancelLogin, &mut app);
    assert!(effects.is_empty());
    assert_eq!(app.active_view, ActiveView::Welcome);
    assert_eq!(app.auth_return_view, None);
}

#[test]
fn auth_complete_extracts_show_resolved_model_from_meta() {
    let mut app = test_app();
    app.auth_state = AuthState::Authenticating {
        request_seq: 1,
        handle: None,
        auth_url: None,
        mode: AuthMode::Pending,
    };
    assert!(app.show_resolved_model);

    dispatch(
        Action::TaskComplete(TaskResult::AuthComplete {
            request_seq: 1,
            meta: Some(serde_json::json!({ "show_resolved_model": false })),
        }),
        &mut app,
    );

    assert!(!app.show_resolved_model);
}

#[test]
fn auth_complete_preserves_show_resolved_model_when_absent() {
    let mut app = test_app();
    app.show_resolved_model = false;
    app.auth_state = AuthState::Authenticating {
        request_seq: 1,
        handle: None,
        auth_url: None,
        mode: AuthMode::Pending,
    };

    dispatch(
        Action::TaskComplete(TaskResult::AuthComplete {
            request_seq: 1,
            meta: Some(serde_json::to_value(fuigo_shell::auth::AuthMeta::default()).unwrap()),
        }),
        &mut app,
    );

    assert!(!app.show_resolved_model);
}

#[tokio::test]
#[serial_test::serial]
async fn typed_and_discovered_keys_complete_acp_authentication() {
    use fuigo_acp_lib::AcpAgentMessage;
    use fuigo_test_support::EnvGuard;
    let _key = EnvGuard::set("FUIGO_API_KEY", "sk-test-first-run-key");
    for discovered in [false, true] {
        let mut app = test_app_with_agent();
        let effects = if discovered {
            dispatch(Action::UseDetectedKey("FUIGO_API_KEY".into()), &mut app)
        } else {
            dispatch(Action::EnterApiKey, &mut app);
            dispatch(
                Action::SubmitApiKey(crate::app::actions::SecretKey(
                    "sk-test-first-run-key".into(),
                )),
                &mut app,
            )
        };
        assert!(matches!(
            app.auth_state,
            crate::app::app_view::AuthState::Authenticating { .. }
        ));
        let effect = effects
            .into_iter()
            .find(|e| matches!(e, Effect::SubmitApiKey { .. }))
            .expect("key submission");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let (progress_tx, _progress_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut tasks = tokio::task::JoinSet::new();
        crate::app::effects::execute(
            effect,
            &mut tasks,
            &tx,
            std::path::Path::new("."),
            &Default::default(),
            &progress_tx,
        );
        let AcpAgentMessage::ExtMethod(store) = rx.recv().await.unwrap() else {
            panic!("store first")
        };
        let raw =
            serde_json::value::to_raw_value(&serde_json::json!({"result": {"ok": true}})).unwrap();
        store
            .response_tx
            .send(Ok(agent_client_protocol::ExtResponse::new(
                std::sync::Arc::from(raw),
            )))
            .unwrap();
        let message = tokio::select! {
            message = rx.recv() => message.expect("authenticate request"),
            result = tasks.join_next() => panic!("UI completed before authentication: {result:?}"),
        };
        let AcpAgentMessage::Authenticate(auth) = message else {
            panic!("authenticate next")
        };
        assert_eq!(auth.request.method_id.0.as_ref(), "fuigo.api_key");
        auth.response_tx
            .send(Ok(agent_client_protocol::AuthenticateResponse::new()))
            .unwrap();
        let result = tasks.join_next().await.unwrap().unwrap();
        assert!(matches!(result, TaskResult::AuthComplete { .. }));
        dispatch(Action::TaskComplete(result), &mut app);
        assert!(matches!(
            app.auth_state,
            crate::app::app_view::AuthState::Done
        ));
    }
}

// ---- the sign-in picker: one list for first run, `/login` and the CLI ----

fn picker_app() -> crate::app::app_view::AppView {
    let mut app = test_app();
    app.auth_state = crate::app::app_view::AuthState::Pending { error: None };
    app
}

/// `/login` used to start the OIDC flow (`Effect::Authenticate`), which errors "No OAuth2 issuer is
/// configured" for almost every user. It opens the picker and contacts nothing.
#[test]
fn login_opens_the_picker_and_never_starts_the_oidc_flow() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    app.active_view = ActiveView::Agent(id);
    app.auth_state = AuthState::Done;
    let effects = dispatch(Action::OpenSignInPicker, &mut app);
    assert!(effects.is_empty(), "opening the picker sends nothing: {effects:?}");
    assert!(matches!(app.active_view, ActiveView::Welcome));
    assert!(matches!(app.auth_state, AuthState::Pending { error: None }));
    assert!(app.picker_modal);
    assert!(matches!(app.auth_return_view, Some(ActiveView::Agent(a)) if a == id));
}

#[test]
fn cancelling_the_picker_returns_to_the_session_and_changes_nothing() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    app.active_view = ActiveView::Agent(id);
    app.auth_state = AuthState::Done;
    dispatch(Action::OpenSignInPicker, &mut app);
    let effects = dispatch(Action::CancelPicker, &mut app);
    assert!(effects.is_empty());
    assert!(matches!(app.active_view, ActiveView::Agent(a) if a == id));
    assert!(matches!(app.auth_state, AuthState::Done));
    assert!(!app.picker_modal);
}

#[test]
fn choosing_a_subscription_starts_its_sign_in_and_polls_for_the_url() {
    use fuigo_shell::auth::subscription::SubscriptionProvider;
    let mut app = picker_app();
    let effects = dispatch(Action::SignInSubscription(SubscriptionProvider::Xai), &mut app);
    assert!(effects.iter().any(|e| matches!(
        e,
        Effect::SubscriptionSignIn { provider: SubscriptionProvider::Xai, .. }
    )));
    assert!(effects.iter().any(|e| matches!(e, Effect::PollSubscriptionUrl { .. })));
    assert!(
        !effects.iter().any(|e| matches!(e, Effect::Authenticate { .. })),
        "a subscription sign-in is not the OIDC flow"
    );
    assert!(matches!(app.auth_state, AuthState::Authenticating { .. }));
    assert_eq!(app.subscription_signin, Some(SubscriptionProvider::Xai));
}

#[test]
fn esc_during_a_subscription_sign_in_returns_to_the_picker() {
    use fuigo_shell::auth::subscription::SubscriptionProvider;
    let mut app = picker_app();
    dispatch(Action::SignInSubscription(SubscriptionProvider::Chatgpt), &mut app);
    let effects = dispatch(Action::CancelSignIn, &mut app);
    assert!(effects.is_empty());
    assert!(matches!(app.auth_state, AuthState::Pending { error: None }));
    assert_eq!(app.subscription_signin, None);
}

/// A code pasted during a subscription sign-in belongs to that flow, not to the OIDC code exchange.
#[test]
fn a_pasted_code_during_a_subscription_sign_in_goes_to_the_subscription_flow() {
    use fuigo_shell::auth::subscription::SubscriptionProvider;
    let mut app = picker_app();
    dispatch(Action::SignInSubscription(SubscriptionProvider::Xai), &mut app);
    let effects = dispatch(Action::SubmitAuthCode("fake-pasted-code".into()), &mut app);
    assert!(effects.iter().any(|e| matches!(e, Effect::SubscriptionCode { .. })), "{effects:?}");
    assert!(!effects.iter().any(|e| matches!(e, Effect::SubmitAuthCode { .. })));
    assert!(!format!("{effects:?}").contains("fake-pasted-code"), "a pasted code must not be Debug-printable");
}

#[test]
fn the_provider_key_page_opens_and_goes_back() {
    let mut app = picker_app();
    dispatch(Action::ProviderKeysPage, &mut app);
    assert_eq!(app.picker_page, crate::app::pending_menu::PickerPage::ProviderKeys);
    dispatch(Action::PickerBack, &mut app);
    assert_eq!(app.picker_page, crate::app::pending_menu::PickerPage::Main);
}

#[test]
fn a_provider_key_row_with_no_key_says_what_to_export() {
    let mut app = picker_app();
    app.sign_in_status = fuigo_shell::auth::provider_status::ProviderStatus::collect(
        std::path::Path::new("/nonexistent-fuigo-home"),
        |_| None,
        false,
    );
    dispatch(Action::ProviderKeyInfo("anthropic".into()), &mut app);
    let note = app.sign_in_notice.expect("a note");
    assert!(note.contains("not set") && note.contains("ANTHROPIC_API_KEY"), "{note}");
}

/// Signing in is the only step: when the browser sign-in completes the picker closes and the screen says
/// who is signed in and what happens next, with no further instruction.
#[test]
fn a_finished_subscription_sign_in_closes_the_picker_and_says_what_happened() {
    use fuigo_shell::auth::subscription::SubscriptionProvider;
    let mut app = picker_app();
    app.picker_modal = true;
    let effects = dispatch(Action::SignInSubscription(SubscriptionProvider::Xai), &mut app);
    let request_seq = effects
        .iter()
        .find_map(|e| match e {
            Effect::SubscriptionSignIn { request_seq, .. } => Some(*request_seq),
            _ => None,
        })
        .expect("sign-in effect");
    dispatch(
        Action::TaskComplete(TaskResult::AuthComplete { request_seq, meta: None }),
        &mut app,
    );
    assert!(matches!(app.auth_state, AuthState::Done));
    assert!(!app.picker_modal);
    assert_eq!(app.subscription_signin, None);
    let notice = app.sign_in_notice.expect("a notice");
    assert!(notice.starts_with("Signed in to Grok subscription"), "{notice}");
    assert!(!notice.contains(" as "), "no display identity is known, so no opaque id is shown: {notice}");
    assert!(notice.contains("Default model:") && notice.ends_with("Use /model to switch."), "{notice}");
    assert!(!notice.contains("config.toml") && !notice.contains("models --provider"), "{notice}");
}

#[test]
fn signing_out_reports_that_tokens_are_removed_locally_not_revoked() {
    use fuigo_shell::auth::subscription::SubscriptionProvider;
    let mut app = picker_app();
    dispatch(
        Action::TaskComplete(TaskResult::SubscriptionSignedOut {
            provider: SubscriptionProvider::Chatgpt,
            error: None,
        }),
        &mut app,
    );
    let notice = app.sign_in_notice.expect("a notice");
    assert!(notice.contains("Signed out of ChatGPT subscription"), "{notice}");
    assert!(notice.contains("not revoked"), "{notice}");
}

#[test]
fn the_sign_out_row_asks_the_effect_to_remove_that_subscription() {
    use fuigo_shell::auth::subscription::SubscriptionProvider;
    let mut app = picker_app();
    let effects = dispatch(Action::SignOutSubscription(SubscriptionProvider::Xai), &mut app);
    assert!(effects.iter().any(|e| matches!(
        e,
        Effect::SubscriptionSignOut { provider: SubscriptionProvider::Xai }
    )));
}

// ---- an explicitly set default that nothing can reach: say why, offer the usable models ----

fn pick_model_entry(id: &str, name: &str, meta: serde_json::Value) -> (acp::ModelId, acp::ModelInfo) {
    let id = acp::ModelId::new(std::sync::Arc::from(id));
    (id.clone(), acp::ModelInfo::new(id, name.to_string()).meta(meta.as_object().cloned()))
}

/// The user's default is a Flux Router model, Flux is not set up, a Grok subscription is.
fn app_with_unusable_default() -> crate::app::app_view::AppView {
    let mut app = test_app_with_agent();
    app.auth_state = AuthState::Done;
    for (id, info) in [
        pick_model_entry(
            "gpt-5",
            "GPT-5",
            serde_json::json!({ "connect": "needs a Flux Router key (fluxrouter.ai)",
                "routes": [{ "key": "gpt-5", "label": "Flux Router", "badge": "via Flux Router",
                            "reason": "needs a Flux Router key (fluxrouter.ai)", "word": "flux", "ready": false }] }),
        ),
        pick_model_entry(
            "xai/grok-4.7",
            "Grok 4.7",
            serde_json::json!({ "routes": [{ "key": "xai/grok-4.7", "label": "Grok subscription",
                "badge": "included in your Grok subscription", "reason": "included", "word": "grok", "ready": true },
                { "key": "xai-key/grok-4.7", "label": "xAI key", "badge": "your xAI key", "reason": "billed", "word": "xai", "ready": true }] }),
        ),
        pick_model_entry("xai-key/grok-4.7", "grok-4.7 (xAI key)", serde_json::json!({ "altRouteOf": "xai/grok-4.7" })),
    ] {
        app.models.available.insert(id, info);
    }
    app.models.current = Some(acp::ModelId::new(std::sync::Arc::from("gpt-5")));
    app
}

#[test]
fn an_unusable_explicit_default_opens_pick_a_model_with_the_reason() {
    let mut app = app_with_unusable_default();
    assert!(app.open_model_pick_if_default_unusable(Some("gpt-5")));
    assert!(matches!(app.auth_state, AuthState::Pending { error: None }));
    assert_eq!(app.picker_page, crate::app::pending_menu::PickerPage::PickModel);
    let note = app.sign_in_notice.clone().expect("a note");
    assert!(note.contains("GPT-5") && note.contains("can't be used"), "{note}");
    assert!(note.contains("needs a Flux Router key") && note.ends_with("Pick a model:"), "{note}");
    let status = app.sign_in_menu_status();
    let rows = crate::app::pending_menu::menu_entries_for(&status, false, app.picker_page, &app.models, false);
    let labels: Vec<&str> = rows.iter().map(|r| r.label.as_str()).collect();
    assert_eq!(labels[0], "Grok 4.7 \u{b7} included in your Grok subscription", "{labels:?}");
    assert_eq!(labels.len(), 4, "one usable model, the toggle, more connections, quit: {labels:?}");
    assert!(labels[1].contains("default model: off"), "{labels:?}");
}

#[test]
fn a_usable_unset_or_hopeless_default_leaves_the_screen_alone() {
    // No explicit default: the welcome screen is unchanged.
    let mut app = app_with_unusable_default();
    assert!(!app.open_model_pick_if_default_unusable(None));
    assert!(matches!(app.auth_state, AuthState::Done));
    // The explicit default is reachable: nothing to say.
    let mut app = app_with_unusable_default();
    assert!(!app.open_model_pick_if_default_unusable(Some("Grok 4.7")));
    // Nothing is usable at all: the sign-in picker's job, not this page.
    let mut app = app_with_unusable_default();
    app.models.available.shift_remove(&acp::ModelId::new(std::sync::Arc::from("xai/grok-4.7")));
    assert!(!app.open_model_pick_if_default_unusable(Some("gpt-5")));
}

#[test]
fn choosing_a_model_starts_on_it_and_leaves_the_explicit_default_alone() {
    let mut app = app_with_unusable_default();
    app.open_model_pick_if_default_unusable(Some("gpt-5"));
    let effects = dispatch(Action::PickWelcomeModel(0), &mut app);
    assert!(matches!(app.auth_state, AuthState::Done));
    assert_eq!(app.models.current.as_ref().map(|m| m.0.as_ref()), Some("xai/grok-4.7"));
    assert!(
        !effects.iter().any(|e| matches!(e, Effect::PersistPreferredModel { .. } | Effect::PersistSetting { .. })),
        "the explicit default is not saved over: {effects:?}"
    );
    let note = app.sign_in_notice.clone().unwrap();
    assert!(note.contains("Grok 4.7") && note.contains("Your default model is unchanged"), "{note}");
    // The completed switch to it is not saved as the default either.
    let id = AgentId(0);
    let model = acp::ModelId::new(std::sync::Arc::from("xai/grok-4.7"));
    app.agents.get_mut(&id).unwrap().session.models.available = app.models.available.clone();
    let done = dispatch(
        Action::TaskComplete(TaskResult::SwitchModelComplete {
            agent_id: id,
            model_id: model,
            effort: None,
            result: Ok(()),
            prev_model_id: None,
        }),
        &mut app,
    );
    assert!(!done.iter().any(|e| matches!(e, Effect::PersistPreferredModel { .. })), "{done:?}");
}

#[test]
fn make_default_saves_the_pick_as_the_default() {
    let mut app = app_with_unusable_default();
    app.open_model_pick_if_default_unusable(Some("gpt-5"));
    dispatch(Action::ToggleMakeDefault, &mut app);
    assert!(app.pick_make_default);
    let effects = dispatch(Action::PickWelcomeModel(0), &mut app);
    assert!(
        effects.iter().any(|e| matches!(e, Effect::PersistPreferredModel { model_id, .. } if model_id.0.as_ref() == "xai/grok-4.7")),
        "{effects:?}"
    );
    assert!(app.sign_in_notice.clone().unwrap().contains("saved as your default"));
}
