#![cfg_attr(rustfmt, rustfmt::skip)]
    use super::*;

    fn notice_notif(params: &serde_json::Value) -> acp::ExtNotification {
        acp::ExtNotification::new(
            "fuigo/leader/notice",
            std::sync::Arc::from(serde_json::value::to_raw_value(params).unwrap()),
        )
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

    /// P142: a notice from the leader's process is shown once, as a system note in the active session.
    #[test]
    fn a_leader_notice_is_shown_once_in_the_active_session() {
        let mut app = make_app_with_agent("sess-1");
        let text = "Fuigo found notes in the old memory folder /a; they were not moved to /b.";
        assert!(handle_ext_notification(&notice_notif(&serde_json::json!({ "message": text })), &mut app));
        assert_eq!(system_texts(&app, AgentId(0)), vec![text.to_string()]);
        app.tick();
        app.tick();
        assert_eq!(system_texts(&app, AgentId(0)).len(), 1, "once");
    }

    /// P142: never into a running turn; the tick shows it as soon as the session is quiet.
    #[test]
    fn a_leader_notice_waits_for_a_quiet_session() {
        let mut app = make_app_with_agent("sess-1");
        app.agents.get_mut(&AgentId(0)).unwrap().session.state = AgentState::TurnRunning;
        assert!(handle_ext_notification(&notice_notif(&serde_json::json!({ "message": "later" })), &mut app));
        assert!(system_texts(&app, AgentId(0)).is_empty(), "not into a running turn");
        app.tick();
        assert!(system_texts(&app, AgentId(0)).is_empty());
        app.agents.get_mut(&AgentId(0)).unwrap().session.state = AgentState::Idle;
        app.tick();
        assert_eq!(system_texts(&app, AgentId(0)), vec!["later".to_string()]);
    }

    /// P142 (Astra r1 HIGH): on the welcome screen nothing goes into the hidden home session (it is thrown away when
    /// another session opens); the notice waits, asks for a tick once a session is on screen, and shows there once.
    #[test]
    fn a_leader_notice_on_the_welcome_screen_waits_for_a_session_on_screen() {
        let mut app = make_app_with_agent("sess-1");
        app.agents.insert(AgentId(5), make_agent(Some("home")));
        app.home_session_agent = Some(AgentId(5));
        app.active_view = ActiveView::Welcome;
        assert!(handle_ext_notification(&notice_notif(&serde_json::json!({ "message": "welcome" })), &mut app));
        app.tick();
        assert!(system_texts(&app, AgentId(5)).is_empty(), "not into the hidden home session");
        assert!(system_texts(&app, AgentId(0)).is_empty());
        switch_active_to(&mut app, AgentId(0));
        assert_ne!(app.tick_demand(), crate::app::app_view::TickDemand::None, "a pending notice asks for a tick");
        app.tick();
        assert_eq!(system_texts(&app, AgentId(0)), vec!["welcome".to_string()]);
        assert!(app.leader_notices.is_empty());
    }

    /// P142 (Astra r1): a notice no session on screen showed before the TUI quit is kept for the print after the
    /// terminal restore, once.
    #[test]
    #[serial_test::serial(p142_unshown_leader_notices)]
    fn an_unshown_leader_notice_is_printed_after_exit() {
        let mut app = make_app_with_agent("sess-1");
        app.active_view = ActiveView::Welcome;
        assert!(handle_ext_notification(&notice_notif(&serde_json::json!({ "message": "p142 at exit" })), &mut app));
        let _ = crate::app::event_loop::finish_run(&mut app);
        let kept = crate::app::take_unshown_leader_notices();
        assert_eq!(kept.iter().filter(|n| n.as_str() == "p142 at exit").count(), 1, "{kept:?}");
        assert!(!crate::app::take_unshown_leader_notices().iter().any(|n| n == "p142 at exit"), "once");
    }

    /// P142 (Astra r2 HIGH): the kept notices are written only when the terminal restore joined its writer; after a
    /// timed-out join nothing is written (it would block teardown).
    #[test]
    #[serial_test::serial(p142_unshown_leader_notices)]
    fn unshown_leader_notices_are_printed_only_to_a_reading_terminal() {
        let text = format!("p142 restore {}", uuid::Uuid::new_v4());
        crate::app::keep_unshown_leader_notices(vec![text.clone()]);
        let mut written = Vec::new();
        crate::app::print_unshown_leader_notices(&Ok(crate::render::draw::WriterJoin::TimedOut), |l| written.push(l.to_owned()));
        crate::app::print_unshown_leader_notices(&Err(std::io::Error::other("restore failed")), |l| written.push(l.to_owned()));
        assert!(!written.contains(&text), "nothing written to a terminal that is not reading");
        crate::app::print_unshown_leader_notices(&Ok(crate::render::draw::WriterJoin::Joined), |l| written.push(l.to_owned()));
        assert_eq!(written.iter().filter(|l| **l == text).count(), 1);
    }

    /// P142 (Astra r3 MEDIUM): while a fullscreen subagent is open the parent's transcript is hidden; the notice waits
    /// for the parent to be on screen again instead of going into its hidden scrollback.
    #[test]
    fn a_leader_notice_waits_while_a_fullscreen_subagent_hides_the_parent() {
        let mut app = make_app_with_agent("sess-1");
        app.agents.get_mut(&AgentId(0)).unwrap().active_subagent = Some("child-1".to_owned());
        assert!(handle_ext_notification(&notice_notif(&serde_json::json!({ "message": "behind child" })), &mut app));
        app.tick();
        assert!(system_texts(&app, AgentId(0)).is_empty(), "not into the hidden parent transcript");
        assert_eq!(app.leader_notices, vec!["behind child".to_string()], "still pending");
        app.agents.get_mut(&AgentId(0)).unwrap().active_subagent = None;
        app.tick();
        assert_eq!(system_texts(&app, AgentId(0)), vec!["behind child".to_string()]);
    }

    /// The prefixed spelling is accepted too; a notice without a message is ignored.
    #[test]
    fn leader_notice_spellings_and_malformed_params() {
        let mut app = make_app_with_agent("sess-1");
        let prefixed = acp::ExtNotification::new(
            "_fuigo/leader/notice",
            std::sync::Arc::from(serde_json::value::to_raw_value(&serde_json::json!({ "message": "x" })).unwrap()),
        );
        assert!(handle_ext_notification(&prefixed, &mut app));
        for bad in [serde_json::json!({}), serde_json::json!({ "message": 3 }), serde_json::json!({ "message": "  " })] {
            assert!(!handle_ext_notification(&notice_notif(&bad), &mut app), "{bad}");
        }
        assert_eq!(system_texts(&app, AgentId(0)), vec!["x".to_string()]);
    }

    // ── wire-level proof: a real leader, the TUI's own registration, the real ACP decoder ──

    #[cfg(unix)]
    async fn next_leader_notice(rx: &mut fuigo_acp_lib::AcpClientRx, text: &str) -> AcpClientMessage {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let msg = tokio::time::timeout_at(deadline, rx.recv())
                .await
                .unwrap_or_else(|_| panic!("the leader notice {text:?} never reached the TUI"))
                .expect("bridge channel closed");
            if let AcpClientMessage::ExtNotification(ext) = &msg
                && ext.request.method.as_ref() == "fuigo/leader/notice"
                && ext.request.params.get().contains(text)
            {
                return msg;
            }
        }
    }

    /// P142 (e2e A1 T1): a notice the leader's process printed (an old memory folder, F13/B1) before the TUI attached,
    /// and one printed while it is attached, both reach the TUI's scrollback through a real leader and the real decoder.
    #[cfg(unix)]
    #[tokio::test]
    async fn real_leader_process_notices_reach_the_tui() {
        let held = format!("p142 pager held {}", uuid::Uuid::new_v4());
        fuigo_file_utils::destination_gate::announce_notice(&held);
        let mut leader = crate::acp::leader_bridge::real_leader_harness::bridge_to_real_leader_as(
            "0.1.150",
            crate::acp::tui_leader_capabilities(&crate::acp::ConnectFlags::default(), None),
        )
        .await;
        let mut app = make_app_with_agent("sess-1");
        let msg = next_leader_notice(&mut leader.bridge.channel.rx, &held).await;
        assert!(handle(msg, &mut app), "the handler must act on the notice");
        assert_eq!(system_texts(&app, AgentId(0)), vec![held.clone()]);

        let live = format!("p142 pager live {}", uuid::Uuid::new_v4());
        fuigo_file_utils::destination_gate::announce_notice(&live);
        let msg = next_leader_notice(&mut leader.bridge.channel.rx, &live).await;
        assert!(handle(msg, &mut app));
        assert_eq!(system_texts(&app, AgentId(0)), vec![held, live]);
    }
