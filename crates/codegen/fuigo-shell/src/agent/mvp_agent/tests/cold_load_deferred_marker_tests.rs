//! P09-F2: the cold `session/load` path, end to end through `attach_session`, for a recovery whose marker append
//! outlives its bound. The persistence actor's test seam writes the marker at once but holds its acknowledgement, so
//! recovery returns `Deferred` while the marker is already on disk when the load's replay reads it. This pins the
//! `BroadcastReplay::new(.., target_client_id)` hand-off in `attach_session`, which the finisher-level tests cannot reach.
//!
//! Real time (the recovery bound is 10 s per load), env redirected, so it runs alone in its own process.

use std::cell::RefCell;
use std::rc::Rc;

use agent_client_protocol::{self as acp, Agent as _};
use fuigo_test_support::EnvGuard;
use serde_json::{Value, json};

use crate::session::info::Info;
use crate::session::storage::{JsonlStorageAdapter, StorageAdapter};

const TEST: &str = "agent::mvp_agent::tests::cold_load_deferred_marker_tests::a_cold_load_delivers_a_deferred_marker_to_every_client_exactly_once";
const PROMPT: &str = "prompt-lost-with-its-process";

#[derive(Debug)]
struct Seen {
    session: String,
    replay: bool,
    stamped_for: Option<Value>,
}

fn pump(
    mut gw_rx: tokio::sync::mpsc::UnboundedReceiver<fuigo_acp_lib::AcpClientMessage>,
) -> Rc<RefCell<Vec<Seen>>> {
    let seen = Rc::new(RefCell::new(Vec::new()));
    let sink = Rc::clone(&seen);
    tokio::task::spawn_local(async move {
        while let Some(message) = gw_rx.recv().await {
            match message {
                fuigo_acp_lib::AcpClientMessage::ExtNotification(args) => {
                    if let Ok(params) = serde_json::from_str::<Value>(args.request.params.get())
                        && params["update"]["stop_reason"] == "interrupted"
                        && params["update"]["prompt_id"] == PROMPT
                    {
                        sink.borrow_mut().push(Seen {
                            session: params["sessionId"].as_str().unwrap_or_default().to_owned(),
                            replay: params["_meta"]["isReplay"] == true,
                            stamped_for: params["_meta"].get("fuigo/leaderClientId").cloned(),
                        });
                    }
                    let _ = args.response_tx.send(Ok(()));
                }
                fuigo_acp_lib::AcpClientMessage::SessionNotification(args) => {
                    let _ = args.response_tx.send(Ok(()));
                }
                _ => {}
            }
        }
    });
    seen
}

/// A session whose previous process died mid-turn.
async fn seed_crashed_session(cwd: &std::path::Path, id: &str) {
    let info = Info {
        id: acp::SessionId::new(id),
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
                "ts": "2026-09-29T00:00:01.000Z", "type": "turn_started", "session_id": id,
                "turn_number": 0, "model_id": "test-model", "yolo_mode": false,
                "conversation_message_count": 0, "session_relationship": "primary",
                "schema_version": "1.0",
            })
        ),
    )
    .expect("events");
}

fn last_turn_event(cwd: &std::path::Path, id: &str) -> Value {
    let info = Info {
        id: acp::SessionId::new(id),
        cwd: cwd.to_string_lossy().into_owned(),
    };
    std::fs::read_to_string(crate::session::persistence::session_dir(&info).join("events.jsonl"))
        .expect("read events")
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .rfind(|v| v["type"] == "turn_started" || v["type"] == "turn_ended")
        .expect("a turn event")
}

/// Loads `id` cold with the marker's ack held, so recovery cannot finish inside its bound and defers (asserted: the
/// lost turn is still open when the load returns). The marker is already on disk, so the load's replay reads it.
/// Then the ack is released and the finisher awaited to completion before the gateway's markers are collected.
async fn load_with_held_ack(
    agent: &crate::agent::mvp_agent::MvpAgent,
    seen: &Rc<RefCell<Vec<Seen>>>,
    cwd: &std::path::Path,
    id: &str,
    target: Option<u64>,
) -> Vec<Seen> {
    seed_crashed_session(cwd, id).await;
    let release = crate::session::persistence::test_seam::hold_next_durable_ack(id);
    let mut request = acp::LoadSessionRequest::new(acp::SessionId::new(id), cwd.to_path_buf());
    if let Some(client) = target {
        request = request.meta(json!({ "fuigo/leaderClientId": client }).as_object().cloned());
    }
    tokio::time::timeout(std::time::Duration::from_secs(120), agent.load_session(request))
        .await
        .expect("load timed out")
        .expect("load failed");
    assert_eq!(
        last_turn_event(cwd, id)["type"],
        "turn_started",
        "recovery must have deferred: a recorded one would have closed the lost turn"
    );
    assert_eq!(crate::session::persistence::test_seam::finishers_done(id), 0);
    release.release();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    while crate::session::persistence::test_seam::finishers_done(id) == 0 {
        assert!(tokio::time::Instant::now() < deadline, "the deferred finisher never completed");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let mut mine = Vec::new();
    seen.borrow_mut().retain_mut(|s| {
        if s.session == id {
            mine.push(Seen {
                session: std::mem::take(&mut s.session),
                replay: s.replay,
                stamped_for: s.stamped_for.take(),
            });
            false
        } else {
            true
        }
    });
    // The seam orders the marker's write before the load's replay, so the replay must carry it.
    assert!(
        mine.iter().any(|s| s.replay),
        "expected the recovery marker in the load's replay; the replay or its delivery failed: {mine:?}"
    );
    mine
}

#[test]
#[serial_test::serial]
fn a_cold_load_delivers_a_deferred_marker_to_every_client_exactly_once() {
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
        let agent = crate::agent::mvp_agent::MvpAgent::new(
            crate::agent::mvp_agent::GatewaySender::new(tx),
            &agent_config,
            std::sync::Arc::new(agent_config.create_auth_manager()),
            None,
        )
        .expect("agent");
        let seen = pump(gw_rx);
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
                            "clientType": "cold-load-deferred-marker",
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

        // Untargeted load: the replay reached every subscriber, so the late marker must not be sent again.
        let broadcast =
            load_with_held_ack(&agent, &seen, workdir.path(), "cold-broadcast", None).await;
        assert_eq!(broadcast.len(), 1, "one delivery to every client: {broadcast:?}");
        assert!(broadcast[0].replay && broadcast[0].stamped_for.is_none(), "{broadcast:?}");

        // Targeted load (leader client 7): the replay went to client 7 alone, so another attached client still needs
        // the live copy. Mutant discriminated: `attach_session` handing `BroadcastReplay::new` no target.
        let targeted =
            load_with_held_ack(&agent, &seen, workdir.path(), "cold-targeted", Some(7)).await;
        assert_eq!(targeted.len(), 2, "client 7's replay plus the live copy for the others: {targeted:?}");
        assert!(
            targeted.iter().any(|s| s.replay && s.stamped_for == Some(json!(7))),
            "{targeted:?}"
        );
        assert!(
            targeted.iter().any(|s| !s.replay && s.stamped_for.is_none()),
            "{targeted:?}"
        );
    });
}
