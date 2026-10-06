//! P143 (Astra r2 MEDIUM): a recovery whose marker append outlives its bound must still tell the model before the
//! first continuation request. The reminder used to be queued by the deferred finisher only after the late append
//! committed, so a prompt sent right after the load went out without it.
//!
//! Real time (the recovery bound is 10 s), env redirected, so it runs alone in its own process.

use agent_client_protocol::{self as acp, Agent as _};
use fuigo_test_support::EnvGuard;
use serde_json::{Value, json};

use crate::session::info::Info;
use crate::session::storage::{JsonlStorageAdapter, StorageAdapter};

const TEST: &str = "agent::mvp_agent::tests::deferred_reminder_order_tests::a_deferred_recovery_tells_the_model_before_the_first_continuation";
const PROMPT: &str = "prompt-lost-with-its-process";
const ID: &str = "deferred-reminder";
/// `InterruptedTurn::model_reminder`.
const REMINDER: &str = "The previous turn was interrupted";

/// Acknowledges every gateway message, as a client would.
fn pump(mut gw_rx: tokio::sync::mpsc::UnboundedReceiver<fuigo_acp_lib::AcpClientMessage>) {
    tokio::task::spawn_local(async move {
        while let Some(message) = gw_rx.recv().await {
            match message {
                fuigo_acp_lib::AcpClientMessage::ExtNotification(args) => {
                    let _ = args.response_tx.send(Ok(()));
                }
                fuigo_acp_lib::AcpClientMessage::SessionNotification(args) => {
                    let _ = args.response_tx.send(Ok(()));
                }
                _ => {}
            }
        }
    });
}

/// A session whose previous process died mid-turn.
async fn seed_crashed_session(cwd: &std::path::Path) -> std::path::PathBuf {
    let info = Info {
        id: acp::SessionId::new(ID),
        cwd: cwd.to_string_lossy().into_owned(),
    };
    JsonlStorageAdapter::new()
        .init_session(&info, acp::ModelId::new("test-model"))
        .await
        .expect("init session");
    let dir = crate::session::persistence::session_dir(&info);
    let summary_path = dir.join("summary.json");
    let mut summary: Value =
        serde_json::from_slice(&std::fs::read(&summary_path).expect("read summary")).expect("summary");
    summary["request_id"] = Value::from(PROMPT);
    summary["next_trace_turn"] = Value::from(1);
    std::fs::write(&summary_path, serde_json::to_vec_pretty(&summary).unwrap()).expect("summary");
    std::fs::write(
        dir.join("events.jsonl"),
        format!(
            "{}\n",
            json!({
                "ts": "2026-09-29T00:00:01.000Z", "type": "turn_started", "session_id": ID,
                "turn_number": 0, "model_id": "test-model", "yolo_mode": false,
                "conversation_message_count": 0, "session_relationship": "primary",
                "schema_version": "1.0",
            })
        ),
    )
    .expect("events");
    dir
}

/// Model requests (bodies) that reached the mock, with how often each carries the reminder.
fn reminder_counts(server: &fuigo_test_support::MockInferenceServer) -> Vec<usize> {
    server
        .requests()
        .iter()
        .filter(|e| e.method == "POST" && (e.path.contains("completions") || e.path.contains("responses")))
        .filter_map(|e| e.body.as_ref())
        .map(|body| body.to_string().matches(REMINDER).count())
        .collect()
}

/// Mutant discriminated: queuing the reminder from the deferred finisher (after the late append) instead of the load.
#[test]
#[serial_test::serial]
fn a_deferred_recovery_tells_the_model_before_the_first_continuation() {
    let Some(_home) = fuigo_test_support::env::fresh_process_home(TEST) else {
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
    server.preset_allow_access();
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
        EnvGuard::set("FUIGO_PROMPT_SUGGESTIONS", "false"),
        // `fresh_process_home` keeps these from the parent; custom model endpoints outrank the mock API URL.
        EnvGuard::unset("FUIGO_MODELS_BASE_URL"),
        EnvGuard::unset("FUIGO_MODELS_LIST_URL"),
    ];

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("agent runtime");
    tokio::task::LocalSet::new().block_on(&rt, async {
        let agent_config = crate::agent::config::Config::default();
        let (tx, gw_rx) = tokio::sync::mpsc::unbounded_channel();
        let agent = std::rc::Rc::new(
            crate::agent::mvp_agent::MvpAgent::new(
                crate::agent::mvp_agent::GatewaySender::new(tx),
                &agent_config,
                std::sync::Arc::new(agent_config.create_auth_manager()),
                None,
            )
            .expect("agent"),
        );
        pump(gw_rx);
        let init = agent
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
                            "clientType": "deferred-reminder-order",
                            "clientVersion": "0.0-test",
                        })
                        .as_object()
                        .cloned(),
                    ),
            )
            .await
            .expect("initialize");
        let method = init
            .auth_methods
            .iter()
            .find(|m| &*m.id().0 == "fuigo.api_key")
            .expect("api key auth method");
        agent
            .authenticate(
                acp::AuthenticateRequest::new(method.id().clone())
                    .meta(json!({ "headless": true }).as_object().cloned()),
            )
            .await
            .expect("authenticate");

        let dir = seed_crashed_session(workdir.path()).await;
        let release = crate::session::persistence::test_seam::hold_next_durable_ack(ID);
        tokio::time::timeout(
            std::time::Duration::from_secs(120),
            agent.load_session(
                acp::LoadSessionRequest::new(acp::SessionId::new(ID), workdir.path().to_path_buf())
                    .meta(json!({ "noReplay": true }).as_object().cloned()),
            ),
        )
        .await
        .expect("load timed out")
        .expect("load failed");
        assert_eq!(
            crate::session::persistence::test_seam::finishers_done(ID),
            0,
            "recovery must have deferred (the marker's ack is held)"
        );

        // The continuation, while the late marker's ack is still held.
        let prompting = std::rc::Rc::clone(&agent);
        let prompt = tokio::task::spawn_local(async move {
            prompting
                .prompt(acp::PromptRequest::new(
                    acp::SessionId::new(ID),
                    vec![acp::ContentBlock::Text(acp::TextContent::new("again".to_owned()))],
                ))
                .await
        });
        // The request must go out while the late marker's ack is still held: that is the race being pinned.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        while reminder_counts(&server).is_empty() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let while_held = reminder_counts(&server);
        release.release();
        tokio::time::timeout(std::time::Duration::from_secs(60), prompt)
            .await
            .expect("prompt timed out")
            .expect("prompt task")
            .expect("prompt failed");
        assert!(
            !while_held.is_empty(),
            "the continuation's model request did not go out while the late marker's ack was held"
        );
        assert_eq!(
            while_held[0], 1,
            "the first continuation request, sent before the late marker committed, carries the reminder once: {while_held:?}"
        );
        let counts = reminder_counts(&server);
        assert_eq!(
            counts[0], 1,
            "the first continuation request carries the reminder exactly once: {counts:?}"
        );
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        while crate::session::persistence::test_seam::finishers_done(ID) == 0 {
            assert!(tokio::time::Instant::now() < deadline, "the deferred finisher never completed");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let updates = std::fs::read_to_string(dir.join("updates.jsonl")).expect("updates");
        assert_eq!(
            updates
                .lines()
                .filter(|l| l.contains("\"turn_completed\"") && l.contains(PROMPT) && l.contains("\"interrupted\""))
                .count(),
            1,
            "one durable marker"
        );
    });
}
