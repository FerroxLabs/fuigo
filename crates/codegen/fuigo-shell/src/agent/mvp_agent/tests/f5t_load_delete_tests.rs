//! F5-T (design F5 §6.2, §6.3, §9.2): load and delete on the session's writer, in a real agent with a redirected home.
//! Env redirected, so each runs alone in its own process.

use agent_client_protocol as acp;
use fuigo_test_support::EnvGuard;
use serde_json::json;

use super::p30_direct_lock_tests::{admin_call, load, make_agent, seed, snapshot};

const LOAD_TEST: &str =
    "agent::mvp_agent::tests::f5t_load_delete_tests::f5t_a_cold_load_waits_for_the_writer_and_never_on_an_old_thread";
const DELETE_TEST: &str =
    "agent::mvp_agent::tests::f5t_load_delete_tests::f5t_delete_answers_still_closing_within_its_budget_and_touches_nothing";

fn with_agent_env(test: &str, body: impl AsyncFnOnce(&std::path::Path)) {
    let Some(_home) = fuigo_test_support::env::fresh_process_home(test) else {
        return;
    };
    fuigo_extra_ca::ensure_default_crypto_provider();
    let mock_rt =
        tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().expect("mock runtime");
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
    tokio::task::LocalSet::new().block_on(&rt, body(workdir.path()));
}

/// CT6b/CT10 (design F5 §6.2): a cold load claims the session's writer with the waiting claim, so it waits for a
/// previous writer of the id that is still letting go and then loads; it never waits on an old actor thread the agent
/// still tracks (1.0.40 drained that thread for up to 5 s first, and then went on whether or not it had finished).
#[test]
#[serial_test::serial]
fn f5t_a_cold_load_waits_for_the_writer_and_never_on_an_old_thread() {
    with_agent_env(LOAD_TEST, async |workdir| {
        const SESSION: &str = "f5t-cold-load";
        let agent = make_agent(false).await;
        let dir = seed(SESSION, workdir).await;
        let sid = acp::SessionId::new(SESSION);
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        agent.session_registry.set_thread(
            &sid,
            crate::session::SessionThread::from_handle(std::thread::spawn(move || {
                let _ = stop_rx.recv();
            })),
        );
        let writer = fuigo_session_writer::SessionWriter::try_claim(SESSION, dir.clone()).expect("claim");
        let letting_go = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(500));
            drop(writer);
        });
        let started = std::time::Instant::now();
        let loaded = load(&agent, SESSION, workdir).await;
        let elapsed = started.elapsed();
        loaded.expect("the load must wait for the writer to let go, then load");
        assert!(elapsed >= std::time::Duration::from_millis(450), "the load did not wait for the writer ({elapsed:?})");
        assert!(
            elapsed < std::time::Duration::from_secs(4),
            "the load took {elapsed:?}: it waited on the old thread, not only on the writer"
        );
        letting_go.join().unwrap();
        drop(stop_tx);
    });
}

/// CT9/CT-DEL (design F5 §6.3 step 1): delete claims the writer within its own 8 s budget. A writer of the id still
/// held in this process gets `still closing` inside that budget, with the folder untouched; once it lets go, the
/// delete removes the folder. 1.0.40 claimed with a fresh 10 s wait after the teardown, past the budget.
#[test]
#[serial_test::serial]
fn f5t_delete_answers_still_closing_within_its_budget_and_touches_nothing() {
    with_agent_env(DELETE_TEST, async |workdir| {
        const SESSION: &str = "f5t-delete";
        let agent = make_agent(false).await;
        let dir = seed(SESSION, workdir).await;
        let before = snapshot(&dir);
        let params = json!({ "sessionId": SESSION, "cwd": workdir.to_string_lossy() });
        let writer = fuigo_session_writer::SessionWriter::try_claim(SESSION, dir.clone()).expect("claim");
        let started = std::time::Instant::now();
        let error = admin_call(&agent, "fuigo/session/delete", params.clone())
            .await
            .expect_err("deleted a session whose writer is still held");
        let elapsed = started.elapsed();
        assert!(
            format!("{error:?}").contains(crate::session::session_writer_lock::STILL_CLOSING),
            "{error:?}"
        );
        let budget = crate::agent::mvp_agent::session_lifecycle::DELETE_TOTAL_BUDGET;
        assert!(
            elapsed <= budget + std::time::Duration::from_millis(500),
            "delete answered after {elapsed:?}, past its {budget:?} budget"
        );
        assert_eq!(snapshot(&dir), before, "a refused delete touched the session folder");
        drop(writer);
        admin_call(&agent, "fuigo/session/delete", params).await.expect("delete once the writer is free");
        assert!(!dir.exists(), "the delete left the session folder");
    });
}
