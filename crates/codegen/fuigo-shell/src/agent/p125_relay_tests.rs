//! P125: relay sync (TUI session sharing) is gated by the relay opt-in like the bridges, and the leader's refusal of a
//! relay is published for its clients.
//!
//! Same harness as P93 (a mock relay behind the P42 TLS front; "refused" means zero TCP connections reached it, and
//! every refusal test shows the same setup connecting once the opt-in is present). Each test runs alone in a fresh
//! process.
use super::p93_relay_opt_in_tests::{
    SERVICE_ORIGIN, assert_connects, assert_nothing_reached, fluxrouter_relay, relay_config, service_relay,
    spawn_counting_relay, user_opt_in, write_user_config,
};
use super::*;
use crate::agent::relay_opt_in::{RELAY_REFUSED_METHOD, TRUSTED_RELAY_ORIGINS_ENV};
use crate::test_support::session_wire::SessionFront;
use fuigo_test_support::EnvGuard;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

fn child(test: &str) -> Option<(SessionFront, EnvGuard)> {
    fuigo_test_support::env::fresh_process_home(&format!("agent::app::p125_relay_tests::{test}"))?;
    let front = SessionFront::start();
    crate::auth::set_test_oauth2_issuer(crate::auth::GROK_OAUTH2_ISSUER);
    crate::agent::config::Config::install_test_trusted_origins();
    Some((front, EnvGuard::unset(TRUSTED_RELAY_ORIGINS_ENV)))
}

/// What the TUI's session sync does for `relay`: build the sync and push one notification through it.
fn start_sync(relay: (String, String)) -> Box<dyn std::any::Any> {
    Box::new( crate::relay::RelaySync::new(
        "p125-session".to_owned(),
        relay_config(relay),
        crate::relay::AgentType::Tui,
        None,
        None,
    ))
}

/// No opt-in: relay sync to a relay FluxRouter does not operate sends nothing, not even a TCP connection.
/// Control: the same relay opted in through the user config is synced to.
#[test]
fn relay_sync_to_an_unopted_relay_sends_nothing() {
    let Some((front, _env)) = child("relay_sync_to_an_unopted_relay_sends_nothing") else {
        return;
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (addr, seen) = spawn_counting_relay().await;
        let relay = service_relay(&front, addr);
        let refused = start_sync(relay.clone());
        assert_nothing_reached(&seen, "relay sync, no opt-in").await;
        drop(refused);
        write_user_config(&user_opt_in(&[SERVICE_ORIGIN]));
        let _opted_in = start_sync(relay);
        assert_connects(&seen, "relay sync, opted in through the user config").await;
    });
}

/// An opt-in for another origin does not cover this relay.
#[test]
fn relay_sync_ignores_an_opt_in_for_another_origin() {
    let Some((front, _env)) = child("relay_sync_ignores_an_opt_in_for_another_origin") else {
        return;
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (addr, seen) = spawn_counting_relay().await;
        write_user_config(&user_opt_in(&["https://other.example.test"]));
        let _sync = start_sync(service_relay(&front, addr));
        assert_nothing_reached(&seen, "relay sync, opt-in for another origin").await;
    });
}

/// The environment variable opts in too.
#[test]
fn relay_sync_honours_the_environment_opt_in() {
    let Some((front, _env)) = child("relay_sync_honours_the_environment_opt_in") else {
        return;
    };
    let _opt_in = EnvGuard::set(TRUSTED_RELAY_ORIGINS_ENV, SERVICE_ORIGIN);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (addr, seen) = spawn_counting_relay().await;
        let _sync = start_sync(service_relay(&front, addr));
        assert_connects(&seen, "relay sync, opted in through the environment").await;
    });
}

/// A FluxRouter-operated relay needs no opt-in (unchanged).
#[test]
fn relay_sync_to_a_fluxrouter_relay_needs_no_opt_in() {
    let Some((front, _env)) = child("relay_sync_to_a_fluxrouter_relay_needs_no_opt_in") else {
        return;
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (addr, seen) = spawn_counting_relay().await;
        let _sync = start_sync(fluxrouter_relay(&front, addr));
        assert_connects(&seen, "relay sync to a FluxRouter relay").await;
    });
}

fn refusal_params(board: &crate::leader::RelayRefusalBoard) -> serde_json::Value {
    let payload = board.current().expect("the leader published its refusal");
    let line: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(line["method"], format!("_{RELAY_REFUSED_METHOD}"));
    line["params"].clone()
}

/// The leader refuses the relay (eager and on demand): the refusal is published for its clients, saying which relay,
/// why and how to trust it. Once the user opts in and a headless client registers, it is cleared.
#[test]
fn the_leaders_refusal_is_published_for_its_clients_until_the_relay_is_opted_in() {
    let Some((front, _env)) =
        child("the_leaders_refusal_is_published_for_its_clients_until_the_relay_is_opted_in")
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
                for on_demand in [false, true] {
                    let board = crate::leader::RelayRefusalBoard::detached();
                    let (ws_to_agent_tx, _ws_to_agent_rx) = mpsc::unbounded_channel();
                    let (demand_tx, demand_rx) = watch::channel(false);
                    let slot = Rc::new(std::cell::RefCell::new(None));
                    spawn_leader_relay(
                        slot.clone(),
                        relay_config(relay.clone()),
                        on_demand,
                        demand_rx,
                        ws_to_agent_tx,
                        Rc::new(Mutex::new(None)),
                        cancel.clone(),
                        board.clone(),
                    );
                    let params = refusal_params(&board);
                    assert_eq!(params["origin"], SERVICE_ORIGIN, "on_demand={on_demand}");
                    assert_eq!(params["use"], "bridge");
                    let message = params["message"].as_str().unwrap();
                    for needle in [
                        SERVICE_ORIGIN,
                        "FluxRouter does not operate it",
                        "trusted_origins = [\"https://service.example.test\"]",
                        "FUIGO_TRUSTED_RELAY_ORIGINS=https://service.example.test",
                    ] {
                        assert!(message.contains(needle), "missing {needle:?}: {message}");
                    }
                    // The user opts in; the next headless registration decides again and clears the refusal.
                    write_user_config(&user_opt_in(&[SERVICE_ORIGIN]));
                    demand_tx.send_replace(true);
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    assert!(board.current().is_none(), "on_demand={on_demand}: the refusal outlived the opt-in");
                    assert!(slot.borrow().is_some(), "on_demand={on_demand}: the opted-in relay was not started");
                    assert_connects(&seen, "after the opt-in").await;
                    let _ = std::fs::remove_file(
                        fuigo_config::user_fuigo_home().unwrap().join("config.toml"),
                    );
                }
            })
            .await;
        cancel.cancel();
    });
}

/// A relay FluxRouter operates publishes no refusal.
#[test]
fn a_fluxrouter_relay_publishes_no_refusal() {
    let Some((front, _env)) = child("a_fluxrouter_relay_publishes_no_refusal") else {
        return;
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (addr, _seen) = spawn_counting_relay().await;
        let cancel = CancellationToken::new();
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let board = crate::leader::RelayRefusalBoard::detached();
                let (ws_to_agent_tx, _rx) = mpsc::unbounded_channel();
                let (_demand_tx, demand_rx) = watch::channel(false);
                spawn_leader_relay(
                    Rc::new(std::cell::RefCell::new(None)),
                    relay_config(fluxrouter_relay(&front, addr)),
                    false,
                    demand_rx,
                    ws_to_agent_tx,
                    Rc::new(Mutex::new(None)),
                    cancel.clone(),
                    board.clone(),
                );
                assert!(board.current().is_none());
            })
            .await;
        cancel.cancel();
    });
}

/// A mock relay that, like the real one, sends `initialize` once a WebSocket is up and records every text frame the
/// agent writes.
async fn spawn_recording_relay() -> (std::net::SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let frames = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = frames.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let sink = sink.clone();
            tokio::spawn(async move {
                use futures_util::{SinkExt as _, StreamExt as _};
                let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1}}"#;
                let _ = ws.send(tokio_tungstenite::tungstenite::Message::text(init)).await;
                while let Ok(Some(Ok(msg))) = tokio::time::timeout(Duration::from_secs(30), ws.next()).await {
                    if let Ok(text) = msg.into_text() {
                        sink.lock().unwrap().push(text.to_string());
                    }
                }
            });
        }
    });
    (addr, frames)
}

/// Allowed sync still syncs (Astra r1): an opted-in relay that completes the handshake receives the queued and
/// flushed session notification, not just a connection.
#[test]
fn relay_sync_to_an_opted_in_relay_delivers_the_session() {
    let Some((front, _env)) = child("relay_sync_to_an_opted_in_relay_delivers_the_session") else {
        return;
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (addr, frames) = spawn_recording_relay().await;
        write_user_config(&user_opt_in(&[SERVICE_ORIGIN]));
        let sync = crate::relay::RelaySync::new(
            "p125-delivery".to_owned(),
            relay_config(service_relay(&front, addr)),
            crate::relay::AgentType::Tui,
            None,
            None,
        )
        .expect("an opted-in relay is synced to");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !sync.is_connected() {
            assert!(tokio::time::Instant::now() < deadline, "the sync never completed the handshake");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        sync.queue(agent_client_protocol::SessionNotification::new(
            agent_client_protocol::SessionId::new("p125-delivery"),
            agent_client_protocol::SessionUpdate::AgentMessageChunk(agent_client_protocol::ContentChunk::new(
                agent_client_protocol::ContentBlock::Text(agent_client_protocol::TextContent::new(
                    "p125-transcript-marker".to_string(),
                )),
            )),
        ));
        sync.flush();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if frames.lock().unwrap().iter().any(|f| f.contains("p125-transcript-marker")) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the transcript never reached the opted-in relay: {:?}",
                frames.lock().unwrap()
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    });
}
