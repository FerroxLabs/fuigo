//! P176 (P178 residual, LOW): a `session/load` holds its mark (the session's sweep lock, shared) until its actor holds
//! `turn_owner.lock`. Before P176 only the mark's timestamp protected the load, so a load suspended past the TTL
//! between its mark and its actor could see another process's sweep remove the session under it.
//!
//! End to end through the real load: right before the actor takes `turn_owner.lock`, the test seam backdates every file
//! of the session past the TTL (a suspended loader) and runs a real sweep of that folder, as another process would.
//! Env redirected, so it runs alone in its own process.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use agent_client_protocol::{self as acp, Agent as _};
use fuigo_test_support::EnvGuard;
use serde_json::json;

use crate::session::info::Info;
use crate::session::storage::{JsonlStorageAdapter, StorageAdapter};

const TEST: &str =
    "agent::mvp_agent::tests::sweep_mark_load_tests::a_load_suspended_past_the_ttl_before_its_actor_keeps_its_session";
const SESSION: &str = "sweep-mark-load";

static HOOK_RAN: AtomicBool = AtomicBool::new(false);
static REMOVED: AtomicU32 = AtomicU32::new(u32::MAX);

fn backdate_tree(dir: &std::path::Path, age: filetime::FileTime) {
    for entry in std::fs::read_dir(dir).expect("session folder").flatten() {
        let path = entry.path();
        let file_type = std::fs::symlink_metadata(&path).expect("entry").file_type();
        if file_type.is_dir() {
            backdate_tree(&path, age);
        } else if file_type.is_file() {
            filetime::set_file_mtime(&path, age).expect("backdate");
        }
    }
}

#[test]
#[serial_test::serial]
fn a_load_suspended_past_the_ttl_before_its_actor_keeps_its_session() {
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
        EnvGuard::unset("FUIGO_MODELS_BASE_URL"),
        EnvGuard::unset("FUIGO_MODELS_LIST_URL"),
    ];

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("agent runtime");
    tokio::task::LocalSet::new().block_on(&rt, async {
        let agent_config = crate::agent::config::Config::default();
        let (tx, mut gw_rx) = tokio::sync::mpsc::unbounded_channel();
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
        let agent = crate::agent::mvp_agent::MvpAgent::new(
            crate::agent::mvp_agent::GatewaySender::new(tx),
            &agent_config,
            std::sync::Arc::new(agent_config.create_auth_manager()),
            None,
        )
        .expect("agent");
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
                            "clientType": "sweep-mark-load",
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

        let info = Info {
            id: acp::SessionId::new(SESSION),
            cwd: workdir.path().to_string_lossy().into_owned(),
        };
        JsonlStorageAdapter::new()
            .init_session(&info, acp::ModelId::new("test-model"))
            .await
            .expect("init session");
        let session_dir = crate::session::persistence::session_dir(&info);
        assert!(session_dir.join("summary.json").is_file());

        crate::session::persistence::test_seam::before_turn_owner_lock(SESSION, |dir| {
            // The loader was suspended past the TTL after its mark: its bump no longer counts
            backdate_tree(dir, filetime::FileTime::from_unix_time(1_000_000_000, 0));
            let removed = crate::session::persistence::test_seam::sweep_session_dir(dir, 30);
            REMOVED.store(removed, Ordering::SeqCst);
            HOOK_RAN.store(true, Ordering::SeqCst);
        });
        let request = acp::LoadSessionRequest::new(acp::SessionId::new(SESSION), workdir.path().to_path_buf());
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), agent.load_session(request))
            .await
            .expect("load timed out");

        assert!(HOOK_RAN.load(Ordering::SeqCst), "the load never reached its actor's turn_owner.lock");
        assert_eq!(
            0,
            REMOVED.load(Ordering::SeqCst),
            "a sweep removed the session between the load's mark and its actor"
        );
        assert!(outcome.is_ok(), "{outcome:?}");
        assert!(session_dir.join("summary.json").is_file(), "the session is whole after the load");
    });
}
