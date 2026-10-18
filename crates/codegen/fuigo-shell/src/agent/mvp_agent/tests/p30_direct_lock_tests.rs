//! 1.0.30 P30-DIRECT: with the shared leader off, two Fuigo processes could open the same session and both write its
//! folder (window C's Shift+Tab rewrote window A's `plan_mode.json`). A process that opens a session for writing now holds
//! an exclusive OS lock on `session_writer.lock` in the session's folder for as long as the session is live there; another
//! process's open is refused before it writes anything, and the lock goes with the holder (close, drop, crash).
//!
//! "Another process" is a second open of the lock file taken by the test itself: an OS lock (Unix `flock`, Windows
//! `LockFileEx`) belongs to the open file, so it excludes this process's own opens exactly as another process's would. The
//! real two-process case runs in the pager's PTY suite and in `session_writer_lock`'s crash test.
//! Env redirected, so it runs alone in its own process.

use agent_client_protocol::{self as acp, Agent as _};
use fuigo_test_support::EnvGuard;
use serde_json::json;

use crate::session::info::Info;
use crate::session::storage::{JsonlStorageAdapter, StorageAdapter};

const TEST: &str = "agent::mvp_agent::tests::p30_direct_lock_tests::a_session_open_in_another_process_is_not_opened_again";
const SESSION: &str = "p30-direct-lock";
const LEADER_SESSION: &str = "p30-direct-lock-leader";
const LOCK_FILE: &str = "session_writer.lock";
const REFUSAL: &str = "This session is open in another Fuigo window";

/// Every file under `dir` with its bytes, sorted: what a refused open must leave exactly as it was.
fn snapshot(dir: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    fn walk(dir: &std::path::Path, out: &mut Vec<(std::path::PathBuf, Vec<u8>)>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push((path.clone(), std::fs::read(&path).unwrap_or_default()));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}

/// What another Fuigo process holds while the session is open there.
fn hold_as_another_process(session_dir: &std::path::Path) -> std::fs::File {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(session_dir.join(LOCK_FILE))
        .expect("open lock file");
    file.try_lock().expect("the other process takes the session");
    file
}

/// Whether another process could take the session right now.
fn another_process_could_open(session_dir: &std::path::Path) -> bool {
    let Ok(file) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(session_dir.join(LOCK_FILE))
    else {
        return true;
    };
    match file.try_lock() {
        Ok(()) => {
            let _ = file.unlock();
            true
        }
        Err(std::fs::TryLockError::WouldBlock) => false,
        Err(std::fs::TryLockError::Error(e)) => panic!("lock error: {e}"),
    }
}

async fn wait_until_another_process_could_open(session_dir: &std::path::Path, what: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !another_process_could_open(session_dir) {
        assert!(std::time::Instant::now() < deadline, "{what}: the session stayed locked");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

async fn make_agent(leader: bool) -> crate::agent::mvp_agent::MvpAgentHandle {
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
    let mut agent = crate::agent::mvp_agent::MvpAgent::new(
        crate::agent::mvp_agent::GatewaySender::new(tx),
        &agent_config,
        std::sync::Arc::new(agent_config.create_auth_manager()),
        None,
    )
    .expect("agent");
    if leader {
        agent.set_leader_mode();
    }
    let init = agent
        .initialize(
            acp::InitializeRequest::new(acp::ProtocolVersion::V1)
                .client_capabilities(acp::ClientCapabilities::new().fs(acp::FileSystemCapabilities::new()).terminal(false))
                .meta(
                    json!({
                        "startupHints": {"nonInteractive": true, "skipGitStatus": true, "skipProjectLayout": true},
                        "clientType": "p30-direct-lock",
                        "clientVersion": "0.0-test",
                    })
                    .as_object()
                    .cloned(),
                ),
        )
        .await
        .expect("initialize");
    let method = init.auth_methods.iter().find(|m| &*m.id().0 == "fuigo.api_key").expect("api key auth method");
    agent
        .authenticate(
            acp::AuthenticateRequest::new(method.id().clone()).meta(json!({ "headless": true }).as_object().cloned()),
        )
        .await
        .expect("authenticate");
    agent
}

async fn load(
    agent: &crate::agent::mvp_agent::MvpAgentHandle,
    session: &str,
    cwd: &std::path::Path,
) -> Result<acp::LoadSessionResponse, acp::Error> {
    let request = acp::LoadSessionRequest::new(acp::SessionId::new(session), cwd.to_path_buf());
    tokio::time::timeout(std::time::Duration::from_secs(120), agent.load_session(request)).await.expect("load timed out")
}

async fn seed(session: &str, cwd: &std::path::Path) -> std::path::PathBuf {
    let info = Info { id: acp::SessionId::new(session), cwd: cwd.to_string_lossy().into_owned() };
    JsonlStorageAdapter::new().init_session(&info, acp::ModelId::new("test-model")).await.expect("init session");
    let dir = crate::session::persistence::session_dir(&info);
    assert!(dir.join("summary.json").is_file());
    dir
}

#[test]
#[serial_test::serial]
fn a_session_open_in_another_process_is_not_opened_again() {
    let Some(_home) = fuigo_test_support::env::fresh_process_home(TEST) else {
        return;
    };
    fuigo_extra_ca::ensure_default_crypto_provider();
    let mock_rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().expect("mock runtime");
    let server = mock_rt.block_on(fuigo_test_support::MockInferenceServer::start()).expect("mock server");
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
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("agent runtime");
    tokio::task::LocalSet::new().block_on(&rt, async {
        // Direct mode (the default): this process is window C, the test's own lock open is window A.
        let agent = make_agent(false).await;
        let dir = seed(SESSION, workdir.path()).await;
        let window_a = hold_as_another_process(&dir);
        let before = snapshot(&dir);
        let refused = load(&agent, SESSION, workdir.path()).await;
        let error = refused.expect_err("a session open in another window was opened again");
        assert!(error.to_string().contains(REFUSAL) || format!("{error:?}").contains(REFUSAL), "{error:?}");
        assert_eq!(snapshot(&dir), before, "the refused open wrote into the session's folder");

        // Window A closes (or crashes: the OS drops its lock either way): C may open the session now, and then holds it.
        drop(window_a);
        load(&agent, SESSION, workdir.path()).await.expect("load after the other window closed");
        assert!(!another_process_could_open(&dir), "the open session is not locked against other windows");
        // Opening it again in the same process (a reconnect, a second tab) is not refused.
        load(&agent, SESSION, workdir.path()).await.expect("re-open in the same process");
        assert!(!another_process_could_open(&dir));
        // Closing it releases it.
        agent.close_session(acp::CloseSessionRequest::new(acp::SessionId::new(SESSION))).await.expect("close");
        wait_until_another_process_could_open(&dir, "after close").await;

        // The shared leader takes the same lock for the sessions it holds: a direct-mode window cannot open a session
        // the leader cold-loaded, and the leader cannot cold-load one a direct window has open.
        let leader = make_agent(true).await;
        let leader_dir = seed(LEADER_SESSION, workdir.path()).await;
        let direct_window = hold_as_another_process(&leader_dir);
        let before = snapshot(&leader_dir);
        let error = load(&leader, LEADER_SESSION, workdir.path()).await.expect_err("the leader opened a session a direct window holds");
        assert!(error.to_string().contains(REFUSAL) || format!("{error:?}").contains(REFUSAL), "{error:?}");
        assert_eq!(snapshot(&leader_dir), before, "the leader's refused cold load wrote into the session's folder");
        drop(direct_window);
        load(&leader, LEADER_SESSION, workdir.path()).await.expect("leader cold load");
        assert!(!another_process_could_open(&leader_dir), "a direct window could open a session the leader holds");
        // The leader stamps its owner verdict on a close; this test is the owner.
        let owner = json!({ crate::leader::protocol::LEADER_OWNER_STATE_KEY: "self" }).as_object().cloned();
        leader
            .close_session(acp::CloseSessionRequest::new(acp::SessionId::new(LEADER_SESSION)).meta(owner))
            .await
            .expect("close");
        wait_until_another_process_could_open(&leader_dir, "after the leader closed it").await;
    });
}

const ADMIN_TEST: &str = "agent::mvp_agent::tests::p30_direct_lock_tests::a_session_open_in_another_process_is_not_renamed_or_unpinned";
const ADMIN_SESSION: &str = "p30-direct-lock-admin";

async fn admin_call(
    agent: &crate::agent::mvp_agent::MvpAgentHandle,
    method: &str,
    params: serde_json::Value,
) -> Result<acp::ExtResponse, acp::Error> {
    let raw = serde_json::value::to_raw_value(&params).expect("params");
    agent.ext_method(acp::ExtRequest::new(method.to_owned(), std::sync::Arc::from(raw))).await
}

/// Renaming a session (or restoring its automatic title) rewrites its `summary.json` without opening it, so it takes
/// the same lock: a session open in another window is refused, untouched; one nobody holds is renamed.
#[test]
#[serial_test::serial]
fn a_session_open_in_another_process_is_not_renamed_or_unpinned() {
    let Some(_home) = fuigo_test_support::env::fresh_process_home(ADMIN_TEST) else {
        return;
    };
    fuigo_extra_ca::ensure_default_crypto_provider();
    let mock_rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().expect("mock runtime");
    let server = mock_rt.block_on(fuigo_test_support::MockInferenceServer::start()).expect("mock server");
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
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("agent runtime");
    tokio::task::LocalSet::new().block_on(&rt, async {
        let agent = make_agent(false).await;
        let dir = seed(ADMIN_SESSION, workdir.path()).await;
        let cwd = workdir.path().to_string_lossy().into_owned();
        let window_a = hold_as_another_process(&dir);
        let before = snapshot(&dir);

        let rename = json!({ "sessionId": ADMIN_SESSION, "title": "Taken over", "cwd": cwd });
        let error = admin_call(&agent, "fuigo/session/rename", rename.clone()).await.expect_err("renamed a session open elsewhere");
        assert!(format!("{error:?}").contains(REFUSAL), "{error:?}");
        let unpin = json!({ "sessionId": ADMIN_SESSION, "title": "", "resetToAuto": true, "cwd": cwd });
        let error = admin_call(&agent, "fuigo/session/rename", unpin).await.expect_err("unpinned a session open elsewhere");
        assert!(format!("{error:?}").contains(REFUSAL), "{error:?}");
        assert_eq!(snapshot(&dir), before, "a refused rename wrote into the other window's session");

        drop(window_a);
        admin_call(&agent, "fuigo/session/rename", rename).await.expect("rename once the other window closed");
        assert!(another_process_could_open(&dir), "the rename kept the session locked after it returned");
        let summary = std::fs::read_to_string(dir.join("summary.json")).expect("summary");
        assert!(summary.contains("Taken over"), "{summary}");
    });
}
