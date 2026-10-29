//! u36 (item b), through the public `MvpAgent`: a session 1.0.35 saved while browsing (its stored head is the bare
//! browsing body) cold-loads in its normal mode with its normal head (the head a never-browser session in the same
//! cwd gets), persisted once; a second load changes nothing. Its transcript replays in order, every line marked
//! `isReplay`, and the historical `browser_use` mode line does not put the session back in browser mode.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use acp::Agent as _;
use agent_client_protocol as acp;
use fuigo_sampling_types::ConversationItem;
use fuigo_test_support::EnvGuard;
use serde_json::json;

const COLD_TEST: &str =
    "agent::mvp_agent::tests::u36_browser_mode_acp_tests::cold_load_repairs_a_1_0_35_browser_head";

/// A session notification the client saw: its update kind, whether it was marked `isReplay`, and its text or mode id.
#[derive(Debug, PartialEq)]
struct Seen {
    kind: String,
    replay: bool,
    payload: String,
}

fn seen(notification: &acp::SessionNotification) -> Seen {
    let value = serde_json::to_value(notification).expect("notification json");
    let update = &value["update"];
    let payload = update["content"]["text"]
        .as_str()
        .or_else(|| update["currentModeId"].as_str())
        .unwrap_or_default()
        .to_owned();
    Seen {
        kind: update["sessionUpdate"].as_str().unwrap_or_default().to_owned(),
        replay: value["_meta"]["isReplay"] == true,
        payload,
    }
}

/// The 1.0.35 transcript of a browsing turn: the prompt, the `browser_use` mode line, the answer.
fn seed_updates(dir: &std::path::Path, id: &str) {
    use crate::session::storage::{SessionUpdate, SessionUpdateEnvelope};
    let session = acp::SessionId::new(id);
    let updates = [
        acp::SessionUpdate::UserMessageChunk(
            acp::ContentChunk::new(acp::ContentBlock::Text(acp::TextContent::new("browse the docs")))
                .meta(json!({ "promptIndex": 0 }).as_object().cloned()),
        ),
        acp::SessionUpdate::CurrentModeUpdate(acp::CurrentModeUpdate::new(acp::SessionModeId::new("browser_use"))),
        acp::SessionUpdate::AgentMessageChunk(acp::ContentChunk::new(acp::ContentBlock::Text(
            acp::TextContent::new("done"),
        ))),
    ];
    let mut content = String::new();
    for update in updates {
        let update = SessionUpdate::Acp(Box::new(acp::SessionNotification::new(session.clone(), update)));
        content.push_str(&serde_json::to_string(&SessionUpdateEnvelope::from_update(&update).unwrap()).unwrap());
        content.push('\n');
    }
    std::fs::write(dir.join("updates.jsonl"), content).unwrap();
}

fn stored_head(dir: &std::path::Path) -> String {
    let items = crate::session::storage::JsonlStorageAdapter::new()
        .load_chat_history_from_dir(dir)
        .expect("chat history");
    match items.first() {
        Some(ConversationItem::System(sys)) => sys.content.to_string(),
        other => panic!("no stored head: {other:?}"),
    }
}

#[test]
#[serial_test::serial]
fn cold_load_repairs_a_1_0_35_browser_head() {
    let Some(_home) = fuigo_test_support::env::fresh_process_home(COLD_TEST) else {
        return;
    };
    fuigo_extra_ca::ensure_default_crypto_provider();
    let mock_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("mock runtime");
    let server = mock_rt
        .block_on(fuigo_test_support::MockInferenceServer::start())
        .expect("mock server");
    let home = tempfile::tempdir().expect("home");
    let workdir = tempfile::tempdir().expect("workdir");
    let url = server.url();
    let _env = [
        EnvGuard::set("HOME", home.path()),
        EnvGuard::set("USERPROFILE", home.path()),
        EnvGuard::set("FUIGO_CLI_CHAT_PROXY_BASE_URL", &url),
        EnvGuard::set("FUIGO_API_BASE_URL", &url),
        EnvGuard::set("FUIGO_API_KEY", "test-key-for-ci"),
        EnvGuard::set("FUIGO_TELEMETRY_ENABLED", "false"),
        EnvGuard::set("FUIGO_FEEDBACK_ENABLED", "false"),
        EnvGuard::set("FUIGO_TRACE_UPLOAD", "false"),
        EnvGuard::set("FUIGO_TURN_SUMMARY", "false"),
        EnvGuard::unset("FUIGO_MODELS_BASE_URL"),
        EnvGuard::unset("FUIGO_MODELS_LIST_URL"),
    ];
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("agent runtime");
    tokio::task::LocalSet::new().block_on(&rt, async {
        use crate::session::storage::{JsonlStorageAdapter, StorageAdapter};
        let body = crate::session::browser_mode::browser_body();
        let id = "u36-cold-browser";
        let control_id = "u36-cold-control";
        let mut dirs = Vec::new();
        for (sid, browsed) in [(id, true), (control_id, false)] {
            let info = crate::session::info::Info {
                id: acp::SessionId::new(sid),
                cwd: workdir.path().to_string_lossy().into_owned(),
            };
            JsonlStorageAdapter::new()
                .init_session(&info, acp::ModelId::new("test-model"))
                .await
                .expect("init session");
            let dir = crate::session::persistence::session_dir(&info);
            // The shape 1.0.35 saved after a turn in browser mode whose memory context was later invalidated: `B\n\n`.
            // The never-browser control has no stored head: the load installs the session's normal one.
            let mut items = vec![ConversationItem::user("browse the docs"), ConversationItem::assistant("done")];
            if browsed {
                items.insert(0, ConversationItem::system(format!("{body}\n\n")));
                seed_updates(&dir, sid);
            }
            let mut chat = String::new();
            for item in items {
                chat.push_str(&serde_json::to_string(&item).unwrap());
                chat.push('\n');
            }
            std::fs::write(dir.join(crate::session::storage::CHAT_HISTORY_FILE), chat).unwrap();
            dirs.push(dir);
        }
        let (dir, control_dir) = (dirs[0].clone(), dirs[1].clone());

        let agent_config = crate::agent::config::Config::default();
        let (tx, mut gw_rx) = tokio::sync::mpsc::unbounded_channel();
        let notifications: Rc<RefCell<Vec<Seen>>> = Rc::default();
        let sink = Rc::clone(&notifications);
        let agent = super::MvpAgent::new(
            super::GatewaySender::new(tx),
            &agent_config,
            Arc::new(agent_config.create_auth_manager()),
            None,
        )
        .expect("agent");
        tokio::task::spawn_local(async move {
            while let Some(message) = gw_rx.recv().await {
                match message {
                    fuigo_acp_lib::AcpClientMessage::ExtNotification(args) => {
                        let _ = args.response_tx.send(Ok(()));
                    }
                    fuigo_acp_lib::AcpClientMessage::SessionNotification(args) => {
                        if args.request.session_id.0.as_ref() == "u36-cold-browser" {
                            sink.borrow_mut().push(seen(&args.request));
                        }
                        let _ = args.response_tx.send(Ok(()));
                    }
                    _ => {}
                }
            }
        });
        agent
            .initialize(
                acp::InitializeRequest::new(acp::ProtocolVersion::V1)
                    .client_capabilities(
                        acp::ClientCapabilities::new()
                            .fs(acp::FileSystemCapabilities::new())
                            .terminal(false),
                    )
                    .meta(
                        json!({
                            "startupHints": {"nonInteractive": true, "skipGitStatus": true, "skipProjectLayout": true},
                            "clientType": "u36-browser",
                            "clientVersion": "0.0-test",
                        })
                        .as_object()
                        .cloned(),
                    ),
            )
            .await
            .expect("initialize");
        let load = || acp::LoadSessionRequest::new(acp::SessionId::new(id), workdir.path().to_path_buf());
        let loaded = tokio::time::timeout(Duration::from_secs(120), agent.load_session(load()))
            .await
            .expect("load timed out")
            .expect("load failed");
        assert_eq!(loaded.modes.expect("modes").current_mode_id.0.as_ref(), "default");
        // The transcript replays in order, every line marked `isReplay`; the historical `browser_use` line is
        // forwarded as history and the load still answers `default` (asserted above).
        let replayed: Vec<Seen> = std::mem::take(&mut *notifications.borrow_mut());
        let transcript: Vec<&Seen> =
            replayed.iter().filter(|n| ["browse the docs", "browser_use", "done"].contains(&n.payload.as_str())).collect();
        assert_eq!(
            transcript,
            [
                &Seen { kind: "user_message_chunk".into(), replay: true, payload: "browse the docs".into() },
                &Seen { kind: "current_mode_update".into(), replay: true, payload: "browser_use".into() },
                &Seen { kind: "agent_message_chunk".into(), replay: true, payload: "done".into() },
            ],
            "replayed in order, all isReplay: {replayed:?}"
        );
        assert!(
            !replayed.iter().any(|n| n.kind == "current_mode_update" && !n.replay && n.payload == "browser_use"),
            "no live browser_use mode update on cold load: {replayed:?}"
        );
        let head = stored_head(&dir);
        assert!(!crate::session::browser_mode::is_legacy_browser_head(&head), "repaired: {head:?}");
        assert!(!head.contains(body), "no browsing text is left in the stored head");
        // The repaired head is exactly the head a never-browser session in the same cwd is given.
        let control = tokio::time::timeout(
            Duration::from_secs(120),
            agent.load_session(acp::LoadSessionRequest::new(
                acp::SessionId::new(control_id),
                workdir.path().to_path_buf(),
            )),
        )
        .await
        .expect("control load timed out")
        .expect("control load failed");
        assert_eq!(control.modes.expect("modes").current_mode_id.0.as_ref(), "default");
        assert_eq!(head, stored_head(&control_dir), "repaired head equals the never-browser control head");
        // A resident attach (and a later load) makes no further migration change.
        let again = agent.load_session(load()).await.expect("second load");
        assert_eq!(again.modes.expect("modes").current_mode_id.0.as_ref(), "default");
        assert_eq!(stored_head(&dir), head);
        // Browser mode on the live session is reported truthfully and stores nothing.
        agent
            .set_session_mode(acp::SetSessionModeRequest::new(acp::SessionId::new(id), "browser_use"))
            .await
            .expect("set browser_use");
        let resident = agent.load_session(load()).await.expect("resident load");
        assert_eq!(resident.modes.expect("modes").current_mode_id.0.as_ref(), "browser_use");
        assert_eq!(stored_head(&dir), head, "browser mode writes no head");
    });
}
