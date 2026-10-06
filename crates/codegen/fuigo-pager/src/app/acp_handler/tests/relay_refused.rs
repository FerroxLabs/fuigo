#![cfg_attr(rustfmt, rustfmt::skip)]
    use super::*;

    const MESSAGE: &str = "Fuigo will not sync this session to the relay at https://relay.example: FluxRouter does not operate it. \
        add `trusted_origins = [\"https://relay.example\"]` under `[relay]` in your user config /home/u/.fuigo/config.toml";

    fn refused_notif(params: &serde_json::Value) -> acp::ExtNotification {
        acp::ExtNotification::new(
            "fuigo/relay/refused",
            std::sync::Arc::from(serde_json::value::to_raw_value(params).unwrap()),
        )
    }

    fn params() -> serde_json::Value {
        serde_json::json!({ "origin": "https://relay.example", "use": "sync", "message": MESSAGE })
    }

    fn system_texts(app: &AppView, id: AgentId) -> Vec<String> {
        let sb = &app.agents.get(&id).unwrap().scrollback;
        (0..sb.len())
            .filter_map(|i| match sb.get(i).map(|e| &e.block) {
                Some(RenderBlock::System(b)) => Some(b.text.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_refused_relay_is_shown_in_the_session_with_how_to_trust_it() {
        let mut app = make_app_with_agent("sess-1");
        assert!(handle_ext_notification(&refused_notif(&params()), &mut app));
        let texts = system_texts(&app, AgentId(0));
        assert_eq!(texts, vec![MESSAGE.to_string()], "which relay, why and how to trust it, in the scrollback");
        let toast = app.agents.get(&AgentId(0)).unwrap().toast.as_ref().map(|(m, _)| m.clone());
        assert!(
            toast.as_deref().is_some_and(|t| t.contains("https://relay.example")),
            "a toast names the relay: {toast:?}"
        );
    }

    #[test]
    fn the_same_refusal_is_shown_once_per_session() {
        let mut app = make_app_with_agent("sess-1");
        assert!(handle_ext_notification(&refused_notif(&params()), &mut app));
        assert!(handle_ext_notification(&refused_notif(&params()), &mut app));
        assert_eq!(system_texts(&app, AgentId(0)).len(), 1);
    }

    #[test]
    fn a_session_opened_after_the_refusal_shows_it_too() {
        let mut app = make_app_with_agent("sess-1");
        assert!(handle_ext_notification(&refused_notif(&params()), &mut app));
        let id = AgentId(7);
        app.agents.insert(id, make_agent(Some("sess-2")));
        app.apply_relay_refusal(id);
        assert_eq!(system_texts(&app, id), vec![MESSAGE.to_string()]);
        app.apply_relay_refusal(id);
        assert_eq!(system_texts(&app, id).len(), 1, "once");
    }

    #[test]
    fn control_characters_in_the_message_never_reach_the_terminal() {
        let mut app = make_app_with_agent("sess-1");
        let p = serde_json::json!({ "origin": "https://r.example\u{1b}[2J", "message": "bad\u{1b}[31m text\u{7}" });
        assert!(handle_ext_notification(&refused_notif(&p), &mut app));
        for t in system_texts(&app, AgentId(0)) {
            assert!(!t.chars().any(char::is_control), "{t:?}");
        }
    }

    #[test]
    fn a_refusal_without_a_message_is_ignored() {
        let mut app = make_app_with_agent("sess-1");
        assert!(!handle_ext_notification(&refused_notif(&serde_json::json!({ "origin": "https://r.example" })), &mut app));
        assert!(system_texts(&app, AgentId(0)).is_empty());
    }

    fn sync_params(session_id: &str) -> serde_json::Value {
        serde_json::json!({ "origin": "https://relay.example", "use": "sync", "message": MESSAGE, "sessionId": session_id })
    }

    #[test]
    fn a_sync_refusal_is_shown_in_that_session_only() {
        let mut app = make_app_with_agent("sess-1");
        app.agents.insert(AgentId(5), make_agent(Some("sess-5")));
        assert!(handle_ext_notification(&refused_notif(&sync_params("sess-5")), &mut app));
        assert_eq!(system_texts(&app, AgentId(5)), vec![MESSAGE.to_string()]);
        assert!(system_texts(&app, AgentId(0)).is_empty(), "another session shows it");
        // A session opened later that is not the refused one shows nothing.
        let id = AgentId(8);
        app.agents.insert(id, make_agent(Some("sess-8")));
        app.apply_relay_refusal(id);
        assert!(system_texts(&app, id).is_empty(), "a later, different session shows a stale sync refusal");
    }

    #[test]
    fn a_sync_refusal_that_arrives_before_its_session_is_shown_when_it_appears() {
        let mut app = make_app_with_agent("sess-1");
        assert!(handle_ext_notification(&refused_notif(&sync_params("sess-9")), &mut app));
        assert!(system_texts(&app, AgentId(0)).is_empty());
        let id = AgentId(9);
        app.agents.insert(id, make_agent(Some("sess-9")));
        app.apply_relay_refusal(id);
        assert_eq!(system_texts(&app, id), vec![MESSAGE.to_string()]);
        app.apply_relay_refusal(id);
        assert_eq!(system_texts(&app, id).len(), 1, "once");
    }

    #[test]
    fn once_the_leader_clears_its_refusal_new_sessions_show_nothing() {
        let mut app = make_app_with_agent("sess-1");
        assert!(handle_ext_notification(&refused_notif(&params()), &mut app));
        let cleared = acp::ExtNotification::new(
            "fuigo/relay/refusal_cleared",
            std::sync::Arc::from(serde_json::value::to_raw_value(&serde_json::json!({})).unwrap()),
        );
        assert!(handle_ext_notification(&cleared, &mut app));
        let id = AgentId(7);
        app.agents.insert(id, make_agent(Some("sess-7")));
        app.apply_relay_refusal(id);
        assert!(system_texts(&app, id).is_empty(), "a cleared refusal was shown in a new session");
    }

    #[test]
    fn a_refusal_during_a_running_turn_waits_for_the_turn_to_end() {
        let mut app = make_app_with_agent("sess-1");
        app.agents.get_mut(&AgentId(0)).unwrap().session.state = crate::app::agent::AgentState::TurnRunning;
        assert!(handle_ext_notification(&refused_notif(&params()), &mut app));
        assert!(
            system_texts(&app, AgentId(0)).is_empty(),
            "a block appended mid-answer would make minimal mode commit the partial answer"
        );
        app.agents.get_mut(&AgentId(0)).unwrap().session.state = crate::app::agent::AgentState::Idle;
        let _ = crate::app::turn_completion::apply_terminal_outcome(
            crate::app::turn_completion::TerminalApply::ViewerFinalized,
            &mut app,
            AgentId(0),
            true,
        );
        assert_eq!(system_texts(&app, AgentId(0)), vec![MESSAGE.to_string()]);
    }

    #[test]
    fn a_refusal_during_a_streaming_wake_turn_waits_until_it_is_quiet() {
        let mut app = make_app_with_agent("sess-1");
        // Idle, but a background wake turn is streaming (minimal mode counts it as running).
        app.agents.get_mut(&AgentId(0)).unwrap().note_streaming_wake_turn("wake-1");
        assert!(handle_ext_notification(&refused_notif(&params()), &mut app));
        assert!(app.tick_demand() != crate::app::app_view::TickDemand::None, "the tick must stay alive for it");
        let _ = app.tick();
        assert!(system_texts(&app, AgentId(0)).is_empty(), "appended into a streaming wake turn");
        app.agents.get_mut(&AgentId(0)).unwrap().running_wake_turn = None;
        assert!(app.tick(), "the tick shows it once quiet and asks for a redraw");
        assert_eq!(system_texts(&app, AgentId(0)), vec![MESSAGE.to_string()]);
        let _ = app.tick();
        assert_eq!(system_texts(&app, AgentId(0)).len(), 1, "shown once");
    }

    #[test]
    fn a_refusal_deferred_by_a_busy_session_is_shown_by_the_tick_without_any_turn_end() {
        let mut app = make_app_with_agent("sess-1");
        app.agents.get_mut(&AgentId(0)).unwrap().session.state = crate::app::agent::AgentState::TurnRunning;
        assert!(handle_ext_notification(&refused_notif(&params()), &mut app));
        let _ = app.tick();
        assert!(system_texts(&app, AgentId(0)).is_empty());
        // The turn ends through the driver's own response path, which never reaches a terminal-outcome hook.
        app.agents.get_mut(&AgentId(0)).unwrap().session.state = crate::app::agent::AgentState::Idle;
        let _ = app.tick();
        assert_eq!(system_texts(&app, AgentId(0)), vec![MESSAGE.to_string()]);
    }
