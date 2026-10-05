//! P93: the agent is bridged to a relay FluxRouter does not operate only when the user opted in to its origin.
//!
//! Through the real startup paths: the leader's relay start (`spawn_leader_relay`, eager, on demand, and the
//! deferred arm a hot-reloaded session takes), headless-relay startup (`run_headless`) and the headless relay
//! connection it opens (`spawn_headless_relay`). The relay is a mock WebSocket server reached through the P42 TLS
//! front (`SessionFront`, `HTTPS_PROXY`): `wss://service.example.test` is a configured relay that FluxRouter does
//! not operate, `wss://api.fluxrouter.ai` is a FluxRouter-operated one, and both land on the same mock, which counts
//! every TCP connection it accepts and every byte it reads. "Refused" means zero TCP connections reached the relay,
//! so not one frame (not even `initialize`) was sent; every refusal test also shows the same setup connecting once
//! the opt-in is present, so a refusal cannot pass by the mock being unreachable.
//!
//! Each test runs alone in a fresh process (the front's proxy and CA variables latch process-wide, and the opt-in is
//! read from `$FUIGO_HOME/config.toml` and the environment).
use super::*;
use crate::agent::relay_opt_in::TRUSTED_RELAY_ORIGINS_ENV;
use crate::test_support::session_wire::SessionFront;
use fuigo_test_support::EnvGuard;
use std::sync::atomic::AtomicU64;
use tokio::io::{AsyncRead as _, AsyncWrite as _};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

pub(super) const SERVICE_ORIGIN: &str = "https://service.example.test";

/// What the mock relay saw.
#[derive(Clone, Default)]
pub(super) struct RelaySeen {
    tcp_connections: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
    websockets: Arc<AtomicU64>,
}

impl RelaySeen {
    pub(super) fn tcp(&self) -> u64 {
        self.tcp_connections.load(Ordering::SeqCst)
    }
    pub(super) fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::SeqCst)
    }
    pub(super) fn websockets(&self) -> u64 {
        self.websockets.load(Ordering::SeqCst)
    }
}

/// A byte-counting stream wrapper, so the mock can report how much reached it.
struct Counting {
    inner: tokio::net::TcpStream,
    bytes: Arc<AtomicU64>,
}

impl tokio::io::AsyncRead for Counting {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        let read = buf.filled().len() - before;
        self.bytes.fetch_add(read as u64, Ordering::SeqCst);
        polled
    }
}

impl tokio::io::AsyncWrite for Counting {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The mock relay: accepts WebSockets, holds each open, counts TCP connections, bytes read and WebSockets.
pub(super) async fn spawn_counting_relay() -> (std::net::SocketAddr, RelaySeen) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = RelaySeen::default();
    let counters = seen.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counters.tcp_connections.fetch_add(1, Ordering::SeqCst);
            let counters = counters.clone();
            tokio::spawn(async move {
                let stream = Counting {
                    inner: stream,
                    bytes: counters.bytes.clone(),
                };
                let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                counters.websockets.fetch_add(1, Ordering::SeqCst);
                // Read (and count) whatever the agent sends until the test ends.
                use futures_util::StreamExt as _;
                while let Ok(Some(_)) =
                    tokio::time::timeout(Duration::from_secs(30), ws.next()).await
                {}
            });
        }
    });
    (addr, seen)
}

/// The child-process guard plus a started front, with the opt-in environment variable cleared.
fn child(test: &str) -> Option<(SessionFront, EnvGuard)> {
    fuigo_test_support::env::fresh_process_home(&format!("agent::app::p93_relay_opt_in_tests::{test}"))?;
    let front = SessionFront::start();
    crate::auth::set_test_oauth2_issuer(crate::auth::GROK_OAUTH2_ISSUER);
    crate::agent::config::Config::install_test_trusted_origins();
    Some((front, EnvGuard::unset(TRUSTED_RELAY_ORIGINS_ENV)))
}

/// `(ws_url, ws_origin)` of the mock at `addr` as a relay FluxRouter does NOT operate (`wss://service.example.test`).
pub(super) fn service_relay(front: &SessionFront, addr: std::net::SocketAddr) -> (String, String) {
    let https = front.front_service(&format!("http://{addr}/ws"));
    (https.replacen("https://", "wss://", 1), SERVICE_ORIGIN.to_owned())
}

/// The same mock as the FluxRouter-operated relay (`wss://api.fluxrouter.ai`).
pub(super) fn fluxrouter_relay(front: &SessionFront, addr: std::net::SocketAddr) -> (String, String) {
    let https = front.front(&format!("http://{addr}/ws"));
    (
        https.replacen("https://", "wss://", 1),
        "https://api.fluxrouter.ai".to_owned(),
    )
}

pub(super) fn relay_session() -> FuigoAuth {
    FuigoAuth {
        auth_mode: AuthMode::Oidc,
        oidc_issuer: Some(crate::auth::GROK_OAUTH2_ISSUER.to_string()),
        ..FuigoAuth::test_default()
    }
}

pub(super) fn com_config((ws_url, ws_origin): (String, String)) -> crate::auth::FuigoComConfig {
    crate::auth::FuigoComConfig {
        fuigo_ws_url: ws_url,
        fuigo_ws_origin: ws_origin,
        ..Default::default()
    }
}

/// The production constructor the leader and headless relay use.
pub(super) fn relay_config(relay: (String, String)) -> crate::agent::relay::RelayConfig {
    crate::agent::relay::RelayConfig::for_session(&relay_session(), &com_config(relay), None, None)
        .expect("an x.ai OIDC session is relay-eligible")
}

/// Write the user config file (`$FUIGO_HOME/config.toml`).
pub(super) fn write_user_config(body: &str) {
    let home = fuigo_config::user_fuigo_home().expect("the child has a FUIGO_HOME");
    std::fs::write(home.join("config.toml"), body).unwrap();
}

pub(super) fn user_opt_in(origins: &[&str]) -> String {
    let list: Vec<String> = origins.iter().map(|o| format!("\"{o}\"")).collect();
    format!("[relay]\ntrusted_origins = [{}]\n", list.join(", "))
}

/// What the leader's relay start left behind; kept alive for the rest of the test (the handle cancels its loop on
/// drop, and dropping the demand sender tells a waiting relay task that the leader is shutting down).
pub(super) struct LeaderStart {
    slot: Rc<std::cell::RefCell<Option<crate::agent::relay::RelayHandle>>>,
    sender: Rc<Mutex<Option<mpsc::UnboundedSender<String>>>>,
    demand_tx: watch::Sender<bool>,
    _ws_to_agent_rx: mpsc::UnboundedReceiver<String>,
}

impl LeaderStart {
    pub(super) fn started(&self) -> bool {
        self.slot.borrow().is_some()
    }
    pub(super) fn sender_installed(&self) -> bool {
        self.sender.lock().is_some()
    }
    /// What the leader's IPC server does when a headless client registers (`leader/server.rs`: every headless
    /// registration notifies, the value stays `true`).
    pub(super) async fn headless_client_registers(&self) {
        self.demand_tx.send_replace(true);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Start the leader's relay for `relay` exactly as `run_leader` does (`spawn_leader_relay`), eagerly or on demand,
/// without yielding and with no headless client registered yet.
pub(super) fn spawn_leader(relay: (String, String), on_demand: bool, cancel: &CancellationToken) -> LeaderStart {
    let (ws_to_agent_tx, ws_to_agent_rx) = mpsc::unbounded_channel();
    let sender: Rc<Mutex<Option<mpsc::UnboundedSender<String>>>> = Rc::new(Mutex::new(None));
    let (demand_tx, demand_rx) = watch::channel(false);
    let slot = Rc::new(std::cell::RefCell::new(None));
    spawn_leader_relay(
        slot.clone(),
        relay_config(relay),
        on_demand,
        demand_rx,
        ws_to_agent_tx,
        sender.clone(),
        cancel.clone(),
        crate::leader::RelayRefusalBoard::detached(),
    );
    LeaderStart {
        slot,
        sender,
        demand_tx,
        _ws_to_agent_rx: ws_to_agent_rx,
    }
}

/// [`spawn_leader`], and on demand a headless client registers at once.
async fn leader_start(
    relay: (String, String),
    on_demand: bool,
    cancel: &CancellationToken,
) -> LeaderStart {
    let start = spawn_leader(relay, on_demand, cancel);
    if on_demand {
        start.headless_client_registers().await;
    }
    start
}

/// The deferred arm a leader that booted without a session takes when an eligible session is hot-reloaded
/// (`DeferredRelayArm::arm_if_eligible`), without yielding.
fn spawn_deferred(relay: (String, String), cancel: &CancellationToken) -> LeaderStart {
    let (ws_to_agent_tx, ws_to_agent_rx) = mpsc::unbounded_channel();
    let sender: Rc<Mutex<Option<mpsc::UnboundedSender<String>>>> = Rc::new(Mutex::new(None));
    let (demand_tx, demand_rx) = watch::channel(false);
    let slot = Rc::new(std::cell::RefCell::new(None));
    let fuigo_com_config = com_config(relay);
    let tmp = tempfile::tempdir().unwrap();
    let auth_manager = Arc::new(AuthManager::new(tmp.path(), fuigo_com_config.clone()));
    let arm = DeferredRelayArm {
        relay_on_demand: false,
        relay_demand_rx: demand_rx,
        ws_to_agent_tx,
        agent_to_ws_tx: sender.clone(),
        cancel: cancel.clone(),
        slot: slot.clone(),
        refusal_board: crate::leader::RelayRefusalBoard::detached(),
        fuigo_com_config,
        alpha_test_key: None,
    };
    assert!(arm.arm_if_eligible(&relay_session(), &auth_manager).is_none());
    std::mem::forget(tmp);
    LeaderStart {
        slot,
        sender,
        demand_tx,
        _ws_to_agent_rx: ws_to_agent_rx,
    }
}

/// [`spawn_deferred`]: whether a relay task was started. The parts are leaked so a started relay keeps running.
fn deferred_arm(relay: (String, String), cancel: &CancellationToken) -> bool {
    let start = spawn_deferred(relay, cancel);
    let started = start.started();
    std::mem::forget(start);
    started
}

/// Wait until the relay accepted a WebSocket, or fail.
pub(super) async fn assert_connects(seen: &RelaySeen, context: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while seen.websockets() == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the relay was never connected: {context}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Give a wrongly started relay task time to connect, then require that nothing reached the relay.
pub(super) async fn assert_nothing_reached(seen: &RelaySeen, context: &str) {
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(seen.tcp(), 0, "a refused relay got a TCP connection: {context}");
    assert_eq!(seen.bytes(), 0, "a refused relay got bytes: {context}");
}

fn assert_refused(start: &LeaderStart, context: &str) {
    assert!(!start.started(), "a relay task was started for a refused relay: {context}");
    assert!(
        !start.sender_installed(),
        "the bridge to a refused relay was installed: {context}"
    );
}

/// No opt-in: the leader starts no relay for a relay FluxRouter does not operate (eager, on demand, and the deferred
/// arm), and nothing reaches it. Control: the same relay, opted in through the user config, connects.
#[test]
fn leader_refuses_a_relay_fluxrouter_does_not_operate_without_an_opt_in() {
    let Some((front, _env)) = child("leader_refuses_a_relay_fluxrouter_does_not_operate_without_an_opt_in") else {
        return;
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (addr, seen) = spawn_counting_relay().await;
        let relay = service_relay(&front, addr);
        let cancel = CancellationToken::new();
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                assert_refused(&leader_start(relay.clone(), false, &cancel).await, "eager");
                assert_refused(&leader_start(relay.clone(), true, &cancel).await, "on demand");
                assert!(!deferred_arm(relay.clone(), &cancel), "deferred arm started a relay");
                assert_nothing_reached(&seen, "no opt-in").await;
                // Control: the same relay through the same front, opted in.
                write_user_config(&user_opt_in(&[SERVICE_ORIGIN]));
                let start = leader_start(relay, false, &cancel).await;
                assert!(start.started() && start.sender_installed());
                assert_connects(&seen, "opted in after the refusals").await;
            })
            .await;
        cancel.cancel();
    });
}

/// A leader that refused (eager or on demand; the deferred arm: next test) does not need a restart once the user opts
/// in: the next headless client that registers makes it decide again, re-reading the user config file. Before the
/// opt-in, a registration changes nothing.
#[test]
fn a_refusing_leader_bridges_once_opted_in_and_a_headless_client_registers() {
    let Some((front, _env)) =
        child("a_refusing_leader_bridges_once_opted_in_and_a_headless_client_registers")
    else {
        return;
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (addr, seen) = spawn_counting_relay().await;
        let relay = service_relay(&front, addr);
        let cancel = CancellationToken::new();
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let eager = leader_start(relay.clone(), false, &cancel).await;
                let on_demand = leader_start(relay.clone(), true, &cancel).await;
                assert_refused(&eager, "eager, before the opt-in");
                assert_refused(&on_demand, "on demand, before the opt-in");
                // A headless client registers before any opt-in: still refused.
                eager.headless_client_registers().await;
                on_demand.headless_client_registers().await;
                assert_refused(&eager, "eager, a registration without an opt-in");
                assert_refused(&on_demand, "on demand, a registration without an opt-in");
                assert_nothing_reached(&seen, "registrations without an opt-in").await;
                // The user opts in; the opt-in alone starts nothing (the leader decides on a registration) ...
                write_user_config(&user_opt_in(&[SERVICE_ORIGIN]));
                tokio::time::sleep(Duration::from_millis(300)).await;
                assert_refused(&eager, "eager, opted in, no registration yet");
                // ... and the next headless registration bridges.
                eager.headless_client_registers().await;
                on_demand.headless_client_registers().await;
                assert!(eager.started() && eager.sender_installed(), "eager, after the registration");
                assert!(
                    on_demand.started() && on_demand.sender_installed(),
                    "on demand, after the registration"
                );
                let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                while seen.websockets() < 2 {
                    assert!(tokio::time::Instant::now() < deadline, "both relays connect");
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await;
        cancel.cancel();
    });
}

/// A headless registration that arrives right after the refusal, before the leader's relay task first runs (the user
/// opted in meanwhile), is not swallowed: the same leader decides again and bridges. Eager, on demand and deferred;
/// nothing yields between the refusal, the opt-in and the registration.
#[test]
fn a_registration_right_after_the_refusal_is_not_lost() {
    let Some((front, _env)) = child("a_registration_right_after_the_refusal_is_not_lost") else {
        return;
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (addr, seen) = spawn_counting_relay().await;
        let relay = service_relay(&front, addr);
        let cancel = CancellationToken::new();
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let starts = [
                    spawn_leader(relay.clone(), false, &cancel),
                    spawn_leader(relay.clone(), true, &cancel),
                    spawn_deferred(relay.clone(), &cancel),
                ];
                for (start, what) in starts.iter().zip(["eager", "on demand", "deferred"]) {
                    assert_refused(start, what);
                }
                write_user_config(&user_opt_in(&[SERVICE_ORIGIN]));
                for start in &starts {
                    start.demand_tx.send_replace(true);
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
                for (start, what) in starts.iter().zip(["eager", "on demand", "deferred"]) {
                    assert!(
                        start.started() && start.sender_installed(),
                        "{what}: the registration after the refusal was lost"
                    );
                }
                let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                while seen.websockets() < 3 {
                    assert!(tokio::time::Instant::now() < deadline, "all three relays connect");
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await;
        cancel.cancel();
    });
}

/// `[relay] trusted_origins` in the user config file opts the leader in for that origin (eager, on demand, deferred).
#[test]
fn leader_bridges_a_relay_opted_in_through_the_user_config() {
    let Some((front, _env)) = child("leader_bridges_a_relay_opted_in_through_the_user_config") else {
        return;
    };
    write_user_config(&user_opt_in(&["https://unrelated.example", "wss://service.example.test:443/"]));
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (addr, seen) = spawn_counting_relay().await;
        let relay = service_relay(&front, addr);
        let cancel = CancellationToken::new();
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let eager = leader_start(relay.clone(), false, &cancel).await;
                assert!(eager.started() && eager.sender_installed(), "eager");
                assert_connects(&seen, "eager, user config opt-in").await;
                let on_demand = leader_start(relay.clone(), true, &cancel).await;
                assert!(on_demand.started() && on_demand.sender_installed(), "on demand");
                assert!(deferred_arm(relay, &cancel), "deferred arm");
                let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                while seen.websockets() < 3 {
                    assert!(tokio::time::Instant::now() < deadline, "all three relays connect");
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await;
        cancel.cancel();
    });
}

/// `FUIGO_TRUSTED_RELAY_ORIGINS` opts the leader in for that origin (no user config file).
#[test]
fn leader_bridges_a_relay_opted_in_through_the_environment() {
    let Some((front, _env)) = child("leader_bridges_a_relay_opted_in_through_the_environment") else {
        return;
    };
    let _opt_in = EnvGuard::set(
        TRUSTED_RELAY_ORIGINS_ENV,
        "https://unrelated.example, https://service.example.test",
    );
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (addr, seen) = spawn_counting_relay().await;
        let relay = service_relay(&front, addr);
        let cancel = CancellationToken::new();
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let start = leader_start(relay, false, &cancel).await;
                assert!(start.started() && start.sender_installed());
                assert_connects(&seen, "environment opt-in").await;
            })
            .await;
        cancel.cancel();
    });
}

/// An opt-in for a different origin (another host, another port, cleartext instead of TLS) does not cover the relay.
#[test]
fn an_opt_in_for_a_different_origin_is_refused() {
    let Some((front, _env)) = child("an_opt_in_for_a_different_origin_is_refused") else {
        return;
    };
    write_user_config(&user_opt_in(&["https://relay.example", "https://service.example.test:8443"]));
    let _opt_in = EnvGuard::set(
        TRUSTED_RELAY_ORIGINS_ENV,
        "http://service.example.test ws://service.example.test http://service.example.test:443 https://sub.service.example.test",
    );
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (addr, seen) = spawn_counting_relay().await;
        let relay = service_relay(&front, addr);
        let cancel = CancellationToken::new();
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                assert_refused(&leader_start(relay.clone(), false, &cancel).await, "other origins");
                assert_nothing_reached(&seen, "opt-ins for other origins").await;
                // Control: naming this origin connects.
                write_user_config(&user_opt_in(&[SERVICE_ORIGIN]));
                let start = leader_start(relay, false, &cancel).await;
                assert!(start.started());
                assert_connects(&seen, "this origin opted in").await;
            })
            .await;
        cancel.cancel();
    });
}

/// An opt-in written anywhere but the user config file and the environment is ignored: a repository's
/// `.fuigo/config.toml` (the folder trusted, the process inside the repository), the `FUIGO_CONFIG` overlay, and the
/// console-synced `managed_config.toml`.
#[test]
fn an_opt_in_in_a_project_overlay_or_managed_config_is_ignored() {
    let Some((front, _env)) = child("an_opt_in_in_a_project_overlay_or_managed_config_is_ignored") else {
        return;
    };
    let opt_in = user_opt_in(&[SERVICE_ORIGIN]);
    let repo = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(repo.path().join(".git")).unwrap();
    std::fs::create_dir_all(repo.path().join(".fuigo")).unwrap();
    std::fs::write(repo.path().join(".fuigo/config.toml"), &opt_in).unwrap();
    std::env::set_current_dir(repo.path()).unwrap();
    fuigo_workspace::folder_trust::grant_folder_trust(repo.path());
    assert!(
        crate::agent::folder_trust::project_scope_allowed(repo.path()),
        "the repository is trusted, so its project config is honoured where project config applies"
    );
    assert!(
        crate::config::find_project_configs(repo.path())
            .iter()
            .any(|p| p.ends_with(".fuigo/config.toml")),
        "the project config is discovered"
    );
    let _overlay = EnvGuard::set(
        "FUIGO_CONFIG",
        format!(r#"{{"relay":{{"trusted_origins":["{SERVICE_ORIGIN}"]}}}}"#),
    );
    let home = fuigo_config::user_fuigo_home().unwrap();
    std::fs::write(home.join("managed_config.toml"), &opt_in).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (addr, seen) = spawn_counting_relay().await;
        let relay = service_relay(&front, addr);
        let cancel = CancellationToken::new();
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                assert_refused(&leader_start(relay.clone(), false, &cancel).await, "project/overlay/managed");
                assert_nothing_reached(&seen, "project, overlay and managed opt-ins").await;
                // Control: the same opt-in in the user config file connects.
                write_user_config(&opt_in);
                let start = leader_start(relay, false, &cancel).await;
                assert!(start.started());
                assert_connects(&seen, "user config opt-in").await;
            })
            .await;
        cancel.cancel();
    });
}

/// A FluxRouter-operated relay needs no opt-in (none anywhere): eager, on demand and deferred all connect.
#[test]
fn a_fluxrouter_relay_is_bridged_without_an_opt_in() {
    let Some((front, _env)) = child("a_fluxrouter_relay_is_bridged_without_an_opt_in") else {
        return;
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (addr, seen) = spawn_counting_relay().await;
        let relay = fluxrouter_relay(&front, addr);
        let cancel = CancellationToken::new();
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let eager = leader_start(relay.clone(), false, &cancel).await;
                assert!(eager.started(), "eager");
                let on_demand = leader_start(relay.clone(), true, &cancel).await;
                assert!(on_demand.started(), "on demand");
                assert!(deferred_arm(relay, &cancel), "deferred");
                let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                while seen.websockets() < 3 {
                    assert!(tokio::time::Instant::now() < deadline, "all three relays connect");
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await;
        cancel.cancel();
    });
}

/// Headless-relay startup refuses a relay FluxRouter does not operate before anything else (no login), with an error
/// that names the origin and what to set where; nothing reaches the relay.
#[test]
fn headless_startup_refuses_a_relay_fluxrouter_does_not_operate_without_an_opt_in() {
    let Some((front, _env)) =
        child("headless_startup_refuses_a_relay_fluxrouter_does_not_operate_without_an_opt_in")
    else {
        return;
    };
    let _key = EnvGuard::unset(crate::agent::auth_method::FUIGO_API_KEY_ENV_VAR);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (addr, seen) = spawn_counting_relay().await;
        let agent_config = AgentConfig {
            fuigo_com_config: com_config(service_relay(&front, addr)),
            ..AgentConfig::default()
        };
        let outcome =
            tokio::time::timeout(Duration::from_secs(30), run_headless(&agent_config, false, None))
                .await
                .expect("a refused headless start returns at once");
        let error = outcome.expect_err("headless startup must refuse the relay").to_string();
        for needle in [
            SERVICE_ORIGIN,
            "trusted_origins = [\"https://service.example.test\"]",
            "[relay]",
            "FUIGO_TRUSTED_RELAY_ORIGINS=https://service.example.test",
        ] {
            assert!(error.contains(needle), "missing {needle:?} in {error}");
        }
        assert_nothing_reached(&seen, "headless startup").await;
    });
}

/// The headless relay connection itself (`spawn_headless_relay`, what `run_headless` opens after login) is refused
/// without an opt-in, and opened with one.
#[test]
fn headless_relay_connection_requires_the_opt_in() {
    let Some((front, _env)) = child("headless_relay_connection_requires_the_opt_in") else {
        return;
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (addr, seen) = spawn_counting_relay().await;
        let relay = service_relay(&front, addr);
        let cancel = CancellationToken::new();
        let (tx, _rx) = mpsc::unbounded_channel();
        let refused = spawn_headless_relay(relay_config(relay.clone()), tx.clone(), cancel.clone(), None)
            .err()
            .expect("no opt-in: refused")
            .to_string();
        assert!(refused.contains("trusted_origins"), "{refused}");
        assert_nothing_reached(&seen, "headless relay without opt-in").await;
        write_user_config(&user_opt_in(&[SERVICE_ORIGIN]));
        let (_to_ws, handle) = spawn_headless_relay(relay_config(relay), tx, cancel.clone(), None)
            .expect("opted in: connects");
        assert_connects(&seen, "headless relay, opted in").await;
        drop(handle);
        cancel.cancel();
    });
}
