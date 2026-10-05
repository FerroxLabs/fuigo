//! P83: tearing an agent down right after `initialize` must not corrupt the heap.
//!
//! The end-to-end case: a real `MvpAgent` behind a real ACP connection on a `LocalSet`, sent `initialize`; the set and
//! its runtime are then dropped AT ONCE, while the start-up tasks `initialize` spawned are still pending. Before the fix
//! this aborted the process at thread exit (glibc: `tcache_thread_shutdown(): unaligned tcache chunk detected`;
//! AddressSanitizer: heap-use-after-free in the settings single-flight's `LeaderGuard::drop`, see R090), so the test
//! runs in a process of its own and the parent asserts that the child exited cleanly.
//!
//! The mechanism, without relying on the allocator to notice: a bound background task is dropped while every field of
//! its agent is still alive, whether the agent's owner drops it with the `LocalSet` running (an aborted agent task) or
//! the `LocalSet` itself is dropped and shuts down the owner's task first (tokio drops tasks oldest first).

use std::cell::Cell;
use std::rc::{Rc, Weak};
use std::sync::Arc;
use std::time::Duration;

use agent_client_protocol::{self as acp};
use fuigo_acp_lib::{AcpAgentGatewayReceiver as GatewayReceiver, LineBufferedRead};
use fuigo_test_support::EnvGuard;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use crate::auth::{AuthMode, FuigoAuth, GROK_OAUTH2_ISSUER};

const TEST: &str =
    "agent::mvp_agent::tests::p83_teardown_tests::dropping_the_agents_local_set_right_after_initialize_is_clean";

fn session() -> FuigoAuth {
    FuigoAuth {
        auth_mode: AuthMode::Oidc,
        oidc_issuer: Some(GROK_OAUTH2_ISSUER.to_string()),
        email: Some("ada@corp.example".into()),
        team_id: Some("team-7f3e".into()),
        refresh_token: Some("rt".into()),
        expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        ..FuigoAuth::test_default()
    }
}

#[test]
#[serial_test::serial]
fn dropping_the_agents_local_set_right_after_initialize_is_clean() {
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
    let url = server.url();
    let _env = [
        EnvGuard::set("HOME", home.path()),
        EnvGuard::set("USERPROFILE", home.path()),
        EnvGuard::set("FUIGO_CLI_CHAT_PROXY_BASE_URL", &url),
        EnvGuard::set("FUIGO_API_BASE_URL", &url),
        EnvGuard::set("FUIGO_TELEMETRY_ENABLED", "false"),
        EnvGuard::set("FUIGO_FEEDBACK_ENABLED", "false"),
        EnvGuard::set("FUIGO_TRACE_UPLOAD", "false"),
        EnvGuard::set("FUIGO_TURN_SUMMARY", "false"),
        EnvGuard::unset("FUIGO_MODELS_BASE_URL"),
        EnvGuard::unset("FUIGO_MODELS_LIST_URL"),
    ];
    crate::auth::set_test_oauth2_issuer(GROK_OAUTH2_ISSUER);
    crate::agent::config::Config::install_test_trusted_origins();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("agent runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let agent_config = crate::agent::config::Config::default();
        let auth_manager = Arc::new(agent_config.create_auth_manager());
        auth_manager.hot_swap(session());
        let (tx, gw_rx) = tokio::sync::mpsc::unbounded_channel();
        let agent = crate::agent::mvp_agent::MvpAgent::new(
            crate::agent::mvp_agent::GatewaySender::new(tx),
            &agent_config,
            auth_manager,
            None,
        )
        .expect("agent");
        // Wired as `agent/app.rs` wires it.
        let (mut to_agent, agent_reads) = tokio::io::duplex(1024 * 1024);
        let (agent_writes, from_agent) = tokio::io::duplex(1024 * 1024);
        let incoming = LineBufferedRead::spawn_local(agent_reads.compat());
        let (conn, handle_io) =
            acp::AgentSideConnection::new(agent, agent_writes.compat_write(), incoming, |fut| {
                tokio::task::spawn_local(fut);
            });
        tokio::task::spawn_local(GatewayReceiver::new(gw_rx, conn).run());
        tokio::task::spawn_local(handle_io);
        let mut from_agent = BufReader::new(from_agent);

        let params = acp::InitializeRequest::new(acp::ProtocolVersion::V1)
            .client_capabilities(acp::ClientCapabilities::new().fs(acp::FileSystemCapabilities::new()))
            .meta(
                json!({
                    "startupHints": { "nonInteractive": true, "skipGitStatus": true, "skipProjectLayout": true },
                    "clientType": "p83-teardown",
                    "clientVersion": "0.0-test",
                })
                .as_object()
                .cloned(),
            );
        let initialize = json!({ "jsonrpc": "2.0", "id": 0, "method": "initialize", "params": params });
        to_agent.write_all(format!("{initialize}\n").as_bytes()).await.expect("write initialize");
        loop {
            let mut line = String::new();
            let read = tokio::time::timeout(Duration::from_secs(60), from_agent.read_line(&mut line))
                .await
                .expect("the agent answers")
                .expect("the agent's stream is readable");
            assert_ne!(read, 0, "the agent closed its stream before answering initialize");
            let Ok(frame) = serde_json::from_str::<Value>(line.trim_end()) else {
                continue;
            };
            if frame.get("method").is_none() && frame["id"] == json!(0) {
                assert!(frame.get("result").is_some(), "initialize succeeded: {line}");
                break;
            }
        }
    });
    // The point of the test: the set (with the agent and every start-up task `initialize` left pending) and then its
    // runtime are dropped at once, as any embedder or test that tears an agent down does.
    drop(local);
    drop(rt);
}

/// Records, when a bound task is dropped, whether its agent was still whole: an `Rc` the agent owns (one of its fields)
/// is alive exactly until the agent's fields are dropped. The probe never dereferences the agent itself.
struct DropProbe {
    agent_field: Weak<Cell<bool>>,
    seen: Rc<Cell<Option<bool>>>,
}

impl Drop for DropProbe {
    fn drop(&mut self) {
        self.seen.set(Some(self.agent_field.upgrade().is_some()));
    }
}

/// Spawns a never-ending task bound to `agent`, holding a probe; returns what the probe will see.
fn spawn_probed_task(agent: &super::MvpAgent) -> Rc<Cell<Option<bool>>> {
    let seen = Rc::new(Cell::new(None));
    let probe = DropProbe {
        agent_field: Rc::downgrade(&agent.settings_reapply_in_flight),
        seen: Rc::clone(&seen),
    };
    let before = agent.bound_tasks.pending();
    agent.spawn_bound(move |_agent_ref| Box::pin(async move {
        let _probe = probe;
        std::future::pending::<()>().await;
    }));
    assert_eq!(agent.bound_tasks.pending(), before + 1);
    seen
}

#[test]
fn an_agent_dropped_by_its_owner_drops_its_bound_tasks_first() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        // Behind an `Rc`, as every owner keeps it: the agent never moves once it has spawned bound work.
        let agent = Rc::new(super::build_minimal_agent_for_tests());
        let seen = spawn_probed_task(&agent);
        tokio::task::yield_now().await;
        assert_eq!(seen.get(), None, "the bound task is running");
        // The owner lets go of the agent while the `LocalSet` keeps running (an embedder aborting the agent's task).
        drop(agent);
        assert_eq!(seen.get(), Some(true), "the bound task was dropped with the agent, before its fields");
        tokio::task::yield_now().await;
    });
}

#[test]
fn a_dropped_local_set_drops_bound_tasks_while_their_agent_is_whole() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    let local = tokio::task::LocalSet::new();
    let seen = local.block_on(&rt, async {
        let agent = Rc::new(super::build_minimal_agent_for_tests());
        // The owner is a task spawned BEFORE the bound one, as the ACP connection's request task is: tokio shuts the
        // set's tasks down oldest first, so the owner (and with it the agent) goes first.
        let owner = Rc::clone(&agent);
        tokio::task::spawn_local(async move {
            let _owner = owner;
            std::future::pending::<()>().await;
        });
        let seen = spawn_probed_task(&agent);
        drop(agent);
        tokio::task::yield_now().await;
        assert_eq!(seen.get(), None, "the agent and its bound task are alive");
        seen
    });
    drop(local);
    assert_eq!(seen.get(), Some(true), "the bound task was dropped before its agent's fields");
    drop(rt);
}

#[test]
fn a_bound_tasks_handle_completes_when_the_agent_drops_it() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let agent = Rc::new(super::build_minimal_agent_for_tests());
        let (started_tx, started) = tokio::sync::oneshot::channel();
        let handle = agent.spawn_bound(move |_agent_ref| Box::pin(async move {
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        }));
        started.await.expect("the bound task ran and is now parked");
        assert!(!handle.is_finished());
        // Nothing else will ever wake the parked driver: the agent taking its future away must.
        drop(agent);
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("the handle completes once the agent dropped its task")
            .expect("without a panic");
    });
}

#[test]
fn a_panicking_bound_task_destructor_still_lets_every_other_bound_task_drop_first() {
    struct PanicOnDrop;
    impl Drop for PanicOnDrop {
        fn drop(&mut self) {
            panic!("p83: a bound task's destructor panics");
        }
    }
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let agent = Rc::new(super::build_minimal_agent_for_tests());
        // Spawned first, so the agent drops it first.
        let panics = PanicOnDrop;
        agent.spawn_bound(move |_agent_ref| Box::pin(async move {
            let _panics = panics;
            std::future::pending::<()>().await;
        }));
        let seen = spawn_probed_task(&agent);
        let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(agent)));
        assert!(dropped.is_err(), "the destructor's panic is not swallowed");
        assert_eq!(seen.get(), Some(true), "the other bound task was dropped too, before the agent's fields");
    });
}

thread_local! {
    /// The agent's only owner, for a bound future's destructor to release (the re-entrant drop below).
    static OWNER: std::cell::RefCell<Option<Rc<super::MvpAgentHandle>>> = const { std::cell::RefCell::new(None) };
}

/// Releases the agent's only owner when dropped: the agent is then dropped from inside a bound future's destructor.
struct ReleasesTheOwner;

impl Drop for ReleasesTheOwner {
    fn drop(&mut self) {
        let owner = OWNER.with(|owner| owner.borrow_mut().take());
        drop(owner);
    }
}

/// Completes at once but keeps its field until it is destroyed.
struct ReadyButHolding(#[allow(dead_code)] ReleasesTheOwner);

impl std::future::Future for ReadyButHolding {
    type Output = ();

    fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        std::task::Poll::Ready(())
    }
}

/// An agent dropped from inside one of its own bound futures -- while the future is being destroyed on completion, or
/// cancelled by its `LocalSet` -- cannot free itself under that future: the process aborts (fail-stop). Each case runs
/// in a child process, which must die of SIGABRT after arming.
#[cfg(unix)]
#[test]
fn an_agent_dropped_from_inside_its_own_bound_future_aborts() {
    use std::os::unix::process::ExitStatusExt;
    const NAME: &str =
        "agent::mvp_agent::tests::p83_teardown_tests::an_agent_dropped_from_inside_its_own_bound_future_aborts";
    const CHILD: &str = "FUIGO_P83_REENTRANT_CHILD";
    let Some(mode) = std::env::var(CHILD).ok() else {
        for mode in ["completed", "cancelled"] {
            let out = std::process::Command::new(std::env::current_exe().expect("test executable"))
                .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
                .env(CHILD, mode)
                .stdin(std::process::Stdio::null())
                .output()
                .expect("run the child");
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(stderr.contains("P83CHILD armed"), "{mode}: the child got as far as arming: {stderr}");
            assert_eq!(out.status.signal(), Some(6), "{mode}: the child aborts: {stderr}");
        }
        return;
    };
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let agent = Rc::new(super::build_minimal_agent_for_tests());
        let release = ReleasesTheOwner;
        if mode == "completed" {
            // Ready on its first poll, still holding `release`: it is destroyed by the driver after completing.
            agent.spawn_bound(move |_agent_ref| Box::pin(ReadyButHolding(release)));
        } else {
            agent.spawn_bound(move |_agent_ref| Box::pin(async move {
                let _release = release;
                std::future::pending::<()>().await;
            }));
        }
        OWNER.with(|owner| *owner.borrow_mut() = Some(agent));
        eprintln!("P83CHILD armed");
        // `completed`: the driver runs the future to completion and destroys it.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
    });
    // `cancelled`: the set drops the parked driver, which destroys the future.
    drop(local);
    drop(rt);
    eprintln!("P83CHILD survived");
}
