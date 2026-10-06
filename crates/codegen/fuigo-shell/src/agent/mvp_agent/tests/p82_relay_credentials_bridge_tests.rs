//! P82: the relay bridge, end to end, with the REAL agent and the REAL relay socket session.
//!
//! Wired as `agent/app.rs` wires leader mode: one agent; its input fed by the local IPC clients (namespaced ids, as the
//! leader server rewrites them) and by the relay reader; every line it writes copied to the local client AND to the
//! relay socket writer (`run_websocket_session` with the production decision `RelayConfig::for_session(..)
//! .body_identity()`). The relay side is the other end of an in-memory WebSocket, so the test asserts on the frames
//! actually written to the relay socket. It pins:
//!
//! * the local client asks for the bearer and the API key and gets both, as before (local unchanged);
//! * a relay that is not FluxRouter-operated asks for both and gets a JSON-RPC error for each; the agent never sees
//!   those requests; no frame written to that relay's socket carries either credential, not even the mirrored answers
//!   to the local client's requests;
//! * a FluxRouter relay asks for both and gets the agent's answers byte for byte (first-party unchanged).
//!
//! Env redirected (`FUIGO_API_KEY`, homes), so it runs alone in its own process.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use agent_client_protocol::{self as acp};
use fuigo_acp_lib::{AcpAgentGatewayReceiver as GatewayReceiver, LineBufferedRead};
use fuigo_test_support::EnvGuard;
use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::{Message, Utf8Bytes, protocol::Role};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use tokio_util::sync::CancellationToken;

use crate::agent::relay::{RelayBodyIdentity, RelayConfig, run_websocket_session};
use crate::auth::{AuthMode, FuigoAuth, FuigoComConfig, GROK_OAUTH2_ISSUER};

const TEST: &str = "agent::mvp_agent::tests::p82_relay_credentials_bridge_tests::a_bridged_relay_is_handed_credentials_only_by_fluxrouter";
const FLUXROUTER_RELAY: &str = "wss://api.fluxrouter.ai/ws/relay";
const OTHER_RELAYS: [&str; 2] = ["wss://relay.example/ws", "wss://other-relay.example/ws"];
const BEARER: &str = "p82-session-bearer.eyJzdWIiOiJwODIifQ.c2ln";
const API_KEY: &str = "xai-p82-environment-api-key-0123456789";

fn session() -> FuigoAuth {
    FuigoAuth {
        auth_mode: AuthMode::Oidc,
        oidc_issuer: Some(GROK_OAUTH2_ISSUER.to_string()),
        key: BEARER.to_string(),
        refresh_token: Some("p82-refresh".into()),
        expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        ..FuigoAuth::test_default()
    }
}

/// The production decision for a relay at `ws_url`.
fn relay_identity(ws_url: &str) -> RelayBodyIdentity {
    let ctx = FuigoComConfig {
        fuigo_ws_url: ws_url.to_owned(),
        ..FuigoComConfig::default()
    };
    RelayConfig::for_session(&session(), &ctx, None, None)
        .expect("an x.ai OIDC session is relay-eligible")
        .body_identity()
}

fn parse(line: &str) -> Value {
    serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}"))
}

/// Wait until `lines` holds the agent's answer to `id` (a response: no `method`); return it.
async fn answer(lines: &Rc<RefCell<Vec<String>>>, id: &Value) -> String {
    for _ in 0..600 {
        if let Some(line) = lines
            .borrow()
            .iter()
            .find(|line| {
                let frame = parse(line);
                frame.get("method").is_none() && &frame["id"] == id
            })
            .cloned()
        {
            return line;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no answer to {id} in {:?}", lines.borrow());
}

/// The relay side of one socket session: read text frames until every id in `ids` has been answered (a response or
/// an error), then half a second more. Returns every text frame, in order.
async fn relay_reads(
    server_rx: &mut futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>>,
    ids: &[Value],
) -> Vec<String> {
    let mut got: Vec<String> = Vec::new();
    let answered = |got: &Vec<String>| {
        ids.iter().all(|id| {
            got.iter().any(|frame| {
                let frame = parse(frame);
                frame.get("method").is_none() && &frame["id"] == id
            })
        })
    };
    // One deadline for the whole wait: the writer's keepalive pings arrive every 15 s, so a per-frame timeout would
    // never expire when an answer is missing.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while !answered(&got) {
        match tokio::time::timeout_at(deadline, server_rx.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => got.push(text.to_string()),
            Ok(Some(Ok(_))) => continue,
            other => panic!("the relay side saw {other:?} after {got:?}"),
        }
    }
    let quiet = tokio::time::Instant::now() + Duration::from_millis(500);
    while let Ok(Some(Ok(message))) = tokio::time::timeout_at(quiet, server_rx.next()).await {
        if let Message::Text(text) = message {
            got.push(text.to_string());
        }
    }
    got
}

#[test]
#[serial_test::serial]
fn a_bridged_relay_is_handed_credentials_only_by_fluxrouter() {
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
        EnvGuard::unset("FUIGO_AGENT_METADATA"),
        EnvGuard::unset("FUIGO_CODE_API_KEY"),
        // What `fuigo/getApiKey` hands out (the environment key; Murage's ACP driver sets it the same way).
        EnvGuard::set("FUIGO_API_KEY", API_KEY),
    ];
    crate::auth::set_test_oauth2_issuer(GROK_OAUTH2_ISSUER);
    crate::agent::config::Config::install_test_trusted_origins();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("agent runtime");
    let local = tokio::task::LocalSet::new();
    // A failed assertion unwinds out of `block_on`; the panic is re-raised after the set and its runtime are dropped.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| local.block_on(&rt, async {
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

        // The agent behind its ACP connection, wired as `agent/app.rs` wires it.
        let (mut to_agent, agent_reads) = tokio::io::duplex(4 * 1024 * 1024);
        let (agent_writes, from_agent) = tokio::io::duplex(4 * 1024 * 1024);
        let incoming = LineBufferedRead::spawn_local(agent_reads.compat());
        let (conn, handle_io) =
            acp::AgentSideConnection::new(agent, agent_writes.compat_write(), incoming, |fut| {
                tokio::task::spawn_local(fut);
            });
        tokio::task::spawn_local(GatewayReceiver::new(gw_rx, conn).run());
        tokio::task::spawn_local(handle_io);

        // The agent's input: the local client's lines and the relay reader's, one line each (`app.rs`: both bridges
        // write into the same incoming stream).
        let (agent_in_tx, mut agent_in_rx) = mpsc::unbounded_channel::<String>();
        tokio::task::spawn_local(async move {
            while let Some(line) = agent_in_rx.recv().await {
                to_agent.write_all(line.as_bytes()).await.expect("agent input");
                to_agent.write_all(b"\n").await.expect("agent input");
            }
        });
        // The agent's output: every line to the local client, and to the relay writer while one is connected
        // (`app.rs:984-1000`, leader mode).
        let local_lines: Rc<RefCell<Vec<String>>> = Rc::default();
        let relay_slot: Rc<RefCell<Option<mpsc::UnboundedSender<String>>>> = Rc::default();
        {
            let local_lines = local_lines.clone();
            let relay_slot = relay_slot.clone();
            tokio::task::spawn_local(async move {
                let mut reader = BufReader::new(from_agent);
                let mut line = String::new();
                loop {
                    line.clear();
                    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                        break;
                    }
                    let msg = line.trim_end_matches(['\r', '\n']).to_string();
                    if msg.is_empty() {
                        continue;
                    }
                    if let Some(tx) = relay_slot.borrow().as_ref() {
                        let _ = tx.send(msg.clone());
                    }
                    local_lines.borrow_mut().push(msg);
                }
            });
        }

        // 1. The local client initialises and asks for both credentials: it gets them, as before.
        let params = acp::InitializeRequest::new(acp::ProtocolVersion::V1)
            .client_capabilities(acp::ClientCapabilities::new().fs(acp::FileSystemCapabilities::new()).terminal(false))
            .meta(
                json!({
                    "startupHints": { "nonInteractive": true, "skipGitStatus": true, "skipProjectLayout": true },
                    "clientType": "p82-relay-bridge",
                    "clientVersion": "0.0-test",
                })
                .as_object()
                .cloned(),
            );
        let local_request = |id: &str, method: &str| json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": {} });
        agent_in_tx
            .send(json!({ "jsonrpc": "2.0", "id": "1|0", "method": "initialize", "params": params }).to_string())
            .unwrap();
        answer(&local_lines, &json!("1|0")).await;

        // 2. Relays, one after the other, each on its own socket session to the same agent.
        let mut next_local = 1;
        for relay in OTHER_RELAYS.iter().chain([FLUXROUTER_RELAY].iter()).copied() {
            let fluxrouter = relay == FLUXROUTER_RELAY;
            let (client, server) = tokio::io::duplex(1024 * 1024);
            let client_ws = tokio_tungstenite::WebSocketStream::from_raw_socket(client, Role::Client, None).await;
            let server_ws = tokio_tungstenite::WebSocketStream::from_raw_socket(server, Role::Server, None).await;
            let (mut server_tx, mut server_rx) = server_ws.split();
            let (ws_to_agent_tx, mut ws_to_agent_rx) = mpsc::unbounded_channel::<String>();
            let (agent_to_ws_tx, mut agent_to_ws_rx) = mpsc::unbounded_channel::<String>();
            *relay_slot.borrow_mut() = Some(agent_to_ws_tx);
            let relay_lines: Rc<RefCell<Vec<String>>> = Rc::default();
            {
                let agent_in_tx = agent_in_tx.clone();
                let relay_lines = relay_lines.clone();
                tokio::task::spawn_local(async move {
                    while let Some(line) = ws_to_agent_rx.recv().await {
                        relay_lines.borrow_mut().push(line.clone());
                        let _ = agent_in_tx.send(line);
                    }
                });
            }
            let cancel = CancellationToken::new();
            let session = {
                let cancel = cancel.clone();
                let identity = relay_identity(relay);
                tokio::task::spawn_local(async move {
                    run_websocket_session(client_ws, &ws_to_agent_tx, &mut agent_to_ws_rx, &cancel, &identity).await
                })
            };

            // The local client asks for both while this relay is connected (the relay receives copies of the answers).
            let bearer_id = format!("1|{next_local}");
            let key_id = format!("1|{}", next_local + 1);
            next_local += 2;
            agent_in_tx.send(local_request(&bearer_id, "_fuigo/auth/getBearerToken").to_string()).unwrap();
            agent_in_tx.send(local_request(&key_id, "_fuigo/getApiKey").to_string()).unwrap();
            let local_bearer = parse(&answer(&local_lines, &json!(bearer_id)).await);
            let local_key = parse(&answer(&local_lines, &json!(key_id)).await);
            assert_eq!(local_bearer["result"]["result"]["token"], BEARER, "the local client gets the bearer: {local_bearer}");
            assert_eq!(local_key["result"]["result"]["key"], API_KEY, "the local client gets the API key: {local_key}");

            // The relay asks for both (and for something ordinary, answered by the agent).
            for (id, method) in [(21, "_fuigo/auth/getBearerToken"), (22, "_fuigo/getApiKey"), (23, "_fuigo/auth/info")] {
                let request = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": {} }).to_string();
                server_tx.send(Message::Text(Utf8Bytes::from(request))).await.expect("relay sends");
            }
            let ids = [json!(21), json!(22), json!(23), json!(bearer_id), json!(key_id)];
            let got = relay_reads(&mut server_rx, &ids).await;
            cancel.cancel();
            let ended = tokio::time::timeout(Duration::from_secs(10), session).await.expect("session ends").expect("task");
            assert!(ended.is_ok(), "{relay}: {ended:?}");
            *relay_slot.borrow_mut() = None;

            let frame_for = |id: Value| {
                got.iter()
                    .find(|frame| {
                        let frame = parse(frame);
                        frame.get("method").is_none() && frame["id"] == id
                    })
                    .cloned()
                    .unwrap_or_else(|| panic!("{relay}: no frame for {id} in {got:?}"))
            };
            let handed = relay_lines.borrow().clone();
            if fluxrouter {
                // First-party: the relay's requests reach the agent as they were sent, and every frame the relay
                // receives is the agent's own line, byte for byte: the bearer and the key included.
                assert_eq!(handed.len(), 3, "{relay}: {handed:?}");
                for id in [21, 22] {
                    let line = answer(&local_lines, &json!(id)).await;
                    assert_eq!(frame_for(json!(id)), line, "{relay}");
                }
                assert_eq!(parse(&frame_for(json!(21)))["result"]["result"]["token"], BEARER, "{relay}");
                assert_eq!(parse(&frame_for(json!(22)))["result"]["result"]["key"], API_KEY, "{relay}");
                let lines = local_lines.borrow().clone();
                for frame in &got {
                    assert!(lines.contains(frame), "{relay}: a frame that is not the agent's line: {frame}");
                }
                continue;
            }
            // Hostile: each credential request refused with an error carrying its id; the agent never saw it.
            for (id, method) in [(21, "_fuigo/auth/getBearerToken"), (22, "_fuigo/getApiKey")] {
                let refusal = parse(&frame_for(json!(id)));
                assert_eq!(refusal["error"]["code"], -32600, "{relay}: {refusal}");
                assert!(refusal["error"]["message"].as_str().unwrap().contains(method), "{relay}: {refusal}");
                assert!(refusal.get("result").is_none(), "{relay}: {refusal}");
                assert!(
                    !local_lines.borrow().iter().any(|line| parse(line)["id"] == json!(id)),
                    "{relay}: the agent answered request {id}, so it was handed it"
                );
            }
            assert_eq!(handed, [r#"{"jsonrpc":"2.0","id":23,"method":"_fuigo/auth/info","params":{}}"#], "{relay}");
            assert!(parse(&frame_for(json!(23))).get("result").is_some(), "{relay}: the ordinary request is answered");
            // The local client's answers reach this relay too (leader mode), without the credentials.
            assert_eq!(parse(&frame_for(json!(bearer_id)))["result"]["result"], json!({}), "{relay}");
            assert_eq!(parse(&frame_for(json!(key_id)))["result"]["result"], json!({}), "{relay}");
            // On the socket's bytes: neither credential, in any frame.
            for frame in &got {
                for secret in [BEARER, API_KEY] {
                    assert!(!frame.contains(secret), "{relay}: a credential reached the relay socket: {frame}");
                }
            }
        }
    })));
    // The set, with the agent and its start-up tasks still in flight, is dropped as any owner drops it (P83 fixed the
    // teardown abort R086 §1 item 4 found; before it, the set had to be leaked).
    drop(local);
    drop(rt);
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
