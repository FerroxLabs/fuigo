#![cfg_attr(rustfmt, rustfmt::skip)]
    use super::*;

    fn toast_157_150() -> String {
        crate::glyphs::sanitize_toast_message(
            "⚠ Version mismatch: client 0.1.157, leader 0.1.150. Restart fuigo to match",
        )
        .into_owned()
    }

    fn version_mismatch_notif(params: &serde_json::Value) -> acp::ExtNotification {
        acp::ExtNotification::new(
            "fuigo/leader/version_mismatch",
            std::sync::Arc::from(serde_json::value::to_raw_value(params).unwrap()),
        )
    }

    fn both_versions_notif() -> acp::ExtNotification {
        version_mismatch_notif(&serde_json::json!({
            "clientVersion": "0.1.157",
            "leaderVersion": "0.1.150",
            "message": "Client version 0.1.157 differs from leader version 0.1.150.",
        }))
    }

    fn agent_toast(app: &AppView, id: AgentId) -> Option<&str> {
        app.agents
            .get(&id)
            .and_then(|a| a.toast.as_ref().map(|(msg, _)| msg.as_str()))
    }

    #[test]
    fn version_mismatch_shows_copied_style_toast() {
        let mut app = make_app_with_agent("sess-1");
        assert!(handle_ext_notification(&both_versions_notif(), &mut app));
        assert_eq!(agent_toast(&app, AgentId(0)), Some(toast_157_150().as_str()));
        assert!(
            app.agents.get(&AgentId(0)).unwrap().scrollback.is_empty(),
            "mismatch must not persist in scrollback"
        );
    }

    #[test]
    fn version_mismatch_toast_works_without_message_field() {
        let mut app = make_app_with_agent("sess-1");
        assert!(handle_ext_notification(
            &version_mismatch_notif(&serde_json::json!({
                "clientVersion": "0.2.1",
                "leaderVersion": "0.2.0",
            })),
            &mut app,
        ));
        let expected = crate::glyphs::sanitize_toast_message(
            "⚠ Version mismatch: client 0.2.1, leader 0.2.0. Restart fuigo to match",
        )
        .into_owned();
        assert_eq!(agent_toast(&app, AgentId(0)), Some(expected.as_str()));
    }

    #[test]
    fn version_mismatch_on_welcome_uses_welcome_toast() {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = AppView::new(
            tx,
            ModelState::default(),
            Vec::new(),
            crate::render::draw::EscapeWriter::disconnected(),
        );
        app.leader_mode = true;
        assert!(matches!(app.active_view, ActiveView::Welcome));
        assert!(app.agents.is_empty());
        assert!(handle_ext_notification(&both_versions_notif(), &mut app));
        assert_eq!(
            app.welcome_toast.as_ref().map(|(msg, _)| msg.as_str()),
            Some(toast_157_150().as_str())
        );
        assert!(app.agents.is_empty());
    }

    #[test]
    fn version_mismatch_survives_reconnect_success_toasts() {
        let mut app = make_app_with_agent("sess-1");
        assert!(handle_ext_notification(&both_versions_notif(), &mut app));
        let mismatch = toast_157_150();
        assert_eq!(agent_toast(&app, AgentId(0)), Some(mismatch.as_str()));

        app.show_toast("Reconnected. Reloading session...");
        assert_eq!(agent_toast(&app, AgentId(0)), Some(mismatch.as_str()));
        app.show_toast("Reconnected.");
        assert_eq!(agent_toast(&app, AgentId(0)), Some(mismatch.as_str()));
        app.show_toast("Session restored. In-progress tools and terminals were lost.");
        assert_eq!(agent_toast(&app, AgentId(0)), Some(mismatch.as_str()));

        app.show_toast("Session restore failed. Kept the existing transcript.");
        assert_eq!(
            agent_toast(&app, AgentId(0)),
            Some("Session restore failed. Kept the existing transcript.")
        );
    }

    #[test]
    fn version_mismatch_on_welcome_survives_reconnected_toast() {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = AppView::new(
            tx,
            ModelState::default(),
            Vec::new(),
            crate::render::draw::EscapeWriter::disconnected(),
        );
        app.leader_mode = true;
        assert!(handle_ext_notification(&both_versions_notif(), &mut app));
        let mismatch = toast_157_150();
        assert_eq!(
            app.welcome_toast.as_ref().map(|(msg, _)| msg.as_str()),
            Some(mismatch.as_str())
        );
        app.show_toast("Reconnected.");
        assert_eq!(
            app.welcome_toast.as_ref().map(|(msg, _)| msg.as_str()),
            Some(mismatch.as_str())
        );
        app.show_toast("Connection failed: boom");
        assert_eq!(
            app.welcome_toast.as_ref().map(|(msg, _)| msg.as_str()),
            Some("Connection failed: boom")
        );
    }

    #[test]
    fn unknown_ext_method_returns_false_and_shows_no_toast() {
        let mut app = make_app_with_agent("sess-1");
        let notif = acp::ExtNotification::new(
            "fuigo/leader/not_a_method",
            std::sync::Arc::from(
                serde_json::value::to_raw_value(&serde_json::json!({
                    "clientVersion": "0.1.157",
                    "leaderVersion": "0.1.150",
                }))
                .unwrap(),
            ),
        );
        assert!(!handle_ext_notification(&notif, &mut app));
        assert!(agent_toast(&app, AgentId(0)).is_none());
        assert!(app.agents.get(&AgentId(0)).unwrap().scrollback.is_empty());
    }

    #[test]
    fn version_mismatch_missing_versions_does_not_panic() {
        let mut app = make_app_with_agent("sess-1");
        for params in [
            serde_json::json!({}),
            serde_json::json!({ "message": "only a message\nwith\nnewlines" }),
            serde_json::json!({ "clientVersion": "0.1.157" }),
            serde_json::json!({ "leaderVersion": "0.1.150" }),
            serde_json::json!({ "clientVersion": "", "leaderVersion": "0.1.150" }),
            serde_json::json!({ "clientVersion": "\n\t", "leaderVersion": "0.1.150" }),
            serde_json::json!({ "clientVersion": "   ", "leaderVersion": "0.1.150" }),
            serde_json::Value::String("not-an-object".into()),
        ] {
            assert!(
                !handle_ext_notification(&version_mismatch_notif(&params), &mut app),
                "malformed params must return false: {params}"
            );
        }
        assert!(agent_toast(&app, AgentId(0)).is_none());
        assert!(app.agents.get(&AgentId(0)).unwrap().scrollback.is_empty());
    }

    #[test]
    fn version_mismatch_scrubs_control_chars_in_versions() {
        let mut app = make_app_with_agent("sess-1");
        assert!(handle_ext_notification(
            &version_mismatch_notif(&serde_json::json!({
                "clientVersion": "0.1.157\n\u{0007}x",
                "leaderVersion": "0.1.150\r\n",
            })),
            &mut app,
        ));
        let text = agent_toast(&app, AgentId(0)).expect("toast");
        let expected = crate::glyphs::sanitize_toast_message(
            "⚠ Version mismatch: client 0.1.157  x, leader 0.1.150  . Restart fuigo to match",
        )
        .into_owned();
        assert_eq!(text, expected);
        assert!(
            !text.chars().any(char::is_control),
            "control chars must not reach toast: {text:?}"
        );
    }

    // ── wire-level proof: real leader bytes through the real ACP decode path ──

    async fn recv_decoded(rx: &mut fuigo_acp_lib::AcpClientRx) -> AcpClientMessage {
        tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("version-mismatch notice never reached the pager: the ACP decoder rejected the wire method")
            .expect("bridge channel closed")
    }

    fn assert_decoded_version_mismatch(msg: &AcpClientMessage) {
        let AcpClientMessage::ExtNotification(ext) = msg else {
            panic!("expected an ExtNotification, got another message");
        };
        assert_eq!(ext.request.method.as_ref(), "fuigo/leader/version_mismatch");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_leader_version_mismatch_reaches_pager_toast() {
        let mut leader =
            crate::acp::leader_bridge::real_leader_harness::bridge_to_real_leader("0.1.157", "0.1.150")
                .await;
        let msg = recv_decoded(&mut leader.bridge.channel.rx).await;
        assert_decoded_version_mismatch(&msg);
        let mut app = make_app_with_agent("sess-1");
        assert!(handle(msg, &mut app), "the handler must act on the notice");
        assert_eq!(agent_toast(&app, AgentId(0)), Some(toast_157_150().as_str()));
    }

    /// An older leader sends the bare method; a new pager must still show the toast (bridge normalization).
    #[tokio::test]
    async fn legacy_unprefixed_leader_version_mismatch_reaches_pager_toast() {
        let (leader_tx, _outbound_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut bridge = crate::acp::leader_bridge::bridge_channels(
            leader_tx,
            inbound_rx,
            cancel.clone(),
            None,
            fuigo_shell::leader::ReconnectPolicy::bounded(),
        )
        .unwrap();
        inbound_tx
            .send(
                r#"{"jsonrpc":"2.0","method":"fuigo/leader/version_mismatch","params":{"clientVersion":"0.1.157","leaderVersion":"0.1.150"}}"#
                    .to_string(),
            )
            .unwrap();
        let msg = recv_decoded(&mut bridge.channel.rx).await;
        assert_decoded_version_mismatch(&msg);
        let mut app = make_app_with_agent("sess-1");
        assert!(handle(msg, &mut app));
        assert_eq!(agent_toast(&app, AgentId(0)), Some(toast_157_150().as_str()));
        cancel.cancel();
    }

    #[test]
    fn version_mismatch_handler_accepts_prefixed_and_bare_method() {
        for method in ["fuigo/leader/version_mismatch", "_fuigo/leader/version_mismatch"] {
            let mut app = make_app_with_agent("sess-1");
            let notif = acp::ExtNotification::new(
                method,
                std::sync::Arc::from(
                    serde_json::value::to_raw_value(&serde_json::json!({
                        "clientVersion": "0.1.157",
                        "leaderVersion": "0.1.150",
                    }))
                    .unwrap(),
                ),
            );
            assert!(handle_ext_notification(&notif, &mut app), "{method}");
            assert_eq!(agent_toast(&app, AgentId(0)), Some(toast_157_150().as_str()), "{method}");
        }
    }
