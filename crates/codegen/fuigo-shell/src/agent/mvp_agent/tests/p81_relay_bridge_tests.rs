//! P81: the relay bridge, end to end, with the REAL agent as the producer.
//!
//! `agent/app.rs` forwards every line the agent writes to the relay socket (headless-relay mode and leader mode). This
//! test stands up a real `MvpAgent` behind a real ACP connection, sends it raw JSON-RPC requests, reads the lines it
//! writes exactly as the bridge does, and hands each line to the relay writer's filter with the PRODUCTION decision
//! for three relays (`RelayConfig::for_session(..).body_identity()`: the relay URL of the config, the persisted
//! machine id of this process). It pins, on the agent's own bytes:
//!
//! * the local client (stdio / IPC) still receives the persisted machine id in `initialize` (unchanged);
//! * a FluxRouter-operated relay receives every line byte for byte;
//! * a relay that is not FluxRouter-operated never receives the machine id: it gets the pseudonym for its own origin
//!   in the same place, the per-process `agentInstanceId` unchanged, and no host name;
//! * the same for who is signed in: `fuigo/auth/info` over the wire, and the `authenticate` /
//!   `fuigo/auth/check_subscription` metadata as the agent builds it.
//!
//! Env redirected and a process-wide machine id read, so it runs alone in its own process.

use std::sync::Arc;
use std::time::Duration;

use agent_client_protocol::{self as acp};
use fuigo_acp_lib::{AcpAgentGatewayReceiver as GatewayReceiver, LineBufferedRead};
use fuigo_test_support::EnvGuard;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use crate::agent::relay::{RelayBodyIdentity, RelayConfig, relay_outbound_frame};
use crate::auth::{AuthMode, FuigoAuth, FuigoComConfig, GROK_OAUTH2_ISSUER};

const TEST: &str =
    "agent::mvp_agent::tests::p81_relay_bridge_tests::a_bridged_relay_receives_the_agents_own_responses_by_relay_operator";
const FLUXROUTER_RELAY: &str = "wss://api.fluxrouter.ai/ws/relay";
const OTHER_RELAYS: [&str; 2] = ["wss://relay.example/ws", "wss://other-relay.example/ws"];

fn session() -> FuigoAuth {
    FuigoAuth {
        auth_mode: AuthMode::Oidc,
        oidc_issuer: Some(GROK_OAUTH2_ISSUER.to_string()),
        email: Some("ada@corp.example".into()),
        first_name: Some("Ada".into()),
        last_name: Some("Lovelace".into()),
        team_id: Some("team-7f3e".into()),
        team_name: Some("Analytical Engines".into()),
        organization_id: Some("org-19c2".into()),
        organization_name: Some("Corp Example".into()),
        principal_type: Some("Team".into()),
        principal_id: Some("principal-51aa".into()),
        team_role: Some("admin".into()),
        profile_image_asset_id: Some("asset-77".into()),
        refresh_token: Some("rt".into()),
        expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        ..FuigoAuth::test_default()
    }
}

/// Every value of [`session`] that says who is signed in.
const ACCOUNT_VALUES: [&str; 9] = [
    "ada@corp.example",
    "Ada",
    "Lovelace",
    "asset-77",
    "team-7f3e",
    "Analytical Engines",
    "org-19c2",
    "Corp Example",
    "principal-51aa",
];
/// The fields of `fuigo/auth/info` that say who is signed in (`AuthInfoResponse`).
const ACCOUNT_INFO_FIELDS: [&str; 9] = [
    "email",
    "firstName",
    "lastName",
    "profileImageUrl",
    "teamId",
    "teamName",
    "organizationId",
    "organizationName",
    "principalId",
];

/// The production decision for a relay at `ws_url`: built by the constructor the leader and the headless relay use.
fn relay_identity(ws_url: &str) -> RelayBodyIdentity {
    let ctx = FuigoComConfig {
        fuigo_ws_url: ws_url.to_owned(),
        ..FuigoComConfig::default()
    };
    RelayConfig::for_session(&session(), &ctx, None, None)
        .expect("an x.ai OIDC session is relay-eligible")
        .body_identity()
}

/// The agent's next line that answers request `id` (notifications and agent requests in between are returned too).
async fn response_line(
    reader: &mut BufReader<tokio::io::DuplexStream>,
    id: u64,
    seen: &mut Vec<String>,
) -> String {
    loop {
        let mut line = String::new();
        let read = tokio::time::timeout(Duration::from_secs(60), reader.read_line(&mut line))
            .await
            .expect("the agent answers")
            .expect("the agent's stream is readable");
        assert_ne!(read, 0, "the agent closed its stream before answering request {id}");
        // Exactly what the bridge in `agent/app.rs` forwards.
        let line = line.trim_end_matches(['\r', '\n']).to_string();
        if line.is_empty() {
            continue;
        }
        seen.push(line.clone());
        let frame: Value = serde_json::from_str(&line).expect("the agent writes JSON lines");
        if frame.get("method").is_none() && frame["id"] == json!(id) {
            return line;
        }
    }
}

#[test]
#[serial_test::serial]
fn a_bridged_relay_receives_the_agents_own_responses_by_relay_operator() {
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
        // The embedder's metadata and a fixed machine id would both change what `initialize` carries.
        EnvGuard::unset("FUIGO_AGENT_METADATA"),
        EnvGuard::unset("FUIGO_AGENT_ID"),
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
        let mut from_agent = BufReader::new(from_agent);
        let mut seen = Vec::new();

        let params = acp::InitializeRequest::new(acp::ProtocolVersion::V1)
            .client_capabilities(
                acp::ClientCapabilities::new()
                    .fs(acp::FileSystemCapabilities::new())
                    .terminal(false),
            )
            .meta(
                json!({
                    "startupHints": { "nonInteractive": true, "skipGitStatus": true, "skipProjectLayout": true },
                    "clientType": "p81-relay-bridge",
                    "clientVersion": "0.0-test",
                })
                .as_object()
                .cloned(),
            );
        let initialize = json!({ "jsonrpc": "2.0", "id": 0, "method": "initialize", "params": params });
        to_agent.write_all(format!("{initialize}\n").as_bytes()).await.expect("write initialize");
        let init_line = response_line(&mut from_agent, 0, &mut seen).await;

        // 1. The local client (stdio / IPC) receives what the agent wrote: the persisted machine id, as before.
        let machine_id = fuigo_telemetry::id::agent_id();
        let instance_id = fuigo_telemetry::id::agent_instance_id();
        let local: Value = serde_json::from_str(&init_line).unwrap();
        let meta = &local["result"]["_meta"];
        assert_eq!(meta["agentId"], machine_id.as_str(), "the local response carries the machine id: {init_line}");
        assert_eq!(meta["agentInstanceId"], instance_id.as_str(), "{init_line}");
        assert_ne!(machine_id, instance_id);
        let hostname = meta["hostname"].as_str().expect("the local response carries the host name").to_owned();
        assert_eq!(init_line.matches(&machine_id).count(), 1, "positive control: exactly one place: {init_line}");

        // `fuigo/auth/info`, asked as an ACP extension request: the local client is told who is signed in, as before.
        to_agent
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"_fuigo/auth/info\",\"params\":{}}\n")
            .await
            .expect("write auth/info");
        let info_line = response_line(&mut from_agent, 1, &mut seen).await;
        let info: Value = serde_json::from_str(&info_line).unwrap();
        for (field, value) in ACCOUNT_INFO_FIELDS.iter().zip([
            "ada@corp.example",
            "Ada",
            "Lovelace",
            "fuigo-asset:///asset-77",
            "team-7f3e",
            "Analytical Engines",
            "org-19c2",
            "Corp Example",
            "principal-51aa",
        ]) {
            assert_eq!(info["result"][*field], value, "the local response says who is signed in: {info_line}");
        }
        assert_eq!(info["result"]["teamRole"], "admin", "{info_line}");

        // 2. A FluxRouter-operated relay: every line the agent wrote, byte for byte.
        let fluxrouter = relay_identity(FLUXROUTER_RELAY);
        for line in &seen {
            assert_eq!(&relay_outbound_frame(&fluxrouter, line.clone()), line);
        }

        // 3. Any other relay: never the machine id, in no line; in `initialize` its own pseudonym instead, the
        //    per-process instance id unchanged, no host name, and nothing else different.
        let mut keys = Vec::new();
        for relay in OTHER_RELAYS {
            let identity = relay_identity(relay);
            for line in &seen {
                let sent = relay_outbound_frame(&identity, line.clone());
                assert!(!sent.is_empty(), "{relay}: a readable line is delivered: {line}");
                assert!(!sent.contains(&machine_id), "{relay} received the machine id: {sent}");
                for value in ACCOUNT_VALUES {
                    assert!(!sent.contains(value), "{relay} was told who is signed in ({value}): {sent}");
                }
            }
            // `fuigo/auth/info`: the same response without the nine fields, nothing else different.
            let mut expected_info = info.clone();
            for field in ACCOUNT_INFO_FIELDS {
                assert!(expected_info["result"].as_object_mut().unwrap().shift_remove(field).is_some(), "{field}");
            }
            let sent_info = relay_outbound_frame(&identity, info_line.clone());
            assert_eq!(sent_info, expected_info.to_string(), "{relay}");
            assert_eq!(expected_info["result"]["teamRole"], "admin");
            assert_eq!(expected_info["result"]["principalType"], "Team");
            let key = fuigo_extra_ca::fluxrouter::destination_pseudonym(relay, &machine_id);
            let host_field = format!(r#""hostname":{},"#, serde_json::to_string(&hostname).unwrap());
            let expected = init_line
                .replacen(&format!(r#""agentId":"{machine_id}""#), &format!(r#""agentId":"{key}""#), 1)
                .replacen(&host_field, "", 1);
            assert_eq!(
                expected.len() + host_field.len() + machine_id.len(),
                init_line.len() + key.len(),
                "both fields are where the replace looks: {init_line}"
            );
            let sent = relay_outbound_frame(&identity, init_line.clone());
            assert_eq!(sent, expected, "{relay}");
            let remote: Value = serde_json::from_str(&sent).unwrap();
            assert_eq!(remote["result"]["_meta"]["agentId"], key.as_str(), "{relay}");
            assert_eq!(remote["result"]["_meta"]["agentInstanceId"], instance_id.as_str(), "{relay}");
            assert!(remote["result"]["_meta"].get("hostname").is_none(), "{relay}");
            // The same key again (a reconnect builds the decision from the same config; a restart reads the same
            // persisted id).
            assert_eq!(relay_outbound_frame(&relay_identity(relay), init_line.clone()), expected, "{relay}");
            keys.push(key);
        }
        assert_ne!(keys[0], keys[1], "one key per relay");
        assert!(keys.iter().all(|key| *key != machine_id && key.len() == 36), "{keys:?}");
    });
    // The set, with the agent and its start-up tasks still in flight this soon after `initialize`, is dropped here as
    // any owner drops it. Before P83 this aborted the process at thread exit (R086 §1 item 4), and the set was leaked.
    drop(local);
    drop(rt);
}

/// P81: the `authenticate` response and `fuigo/auth/check_subscription`, with the metadata the REAL agent builds
/// (`auth_response_with_meta`), through the relay writer's filter.
#[tokio::test]
async fn the_agents_auth_metadata_tells_only_a_fluxrouter_relay_who_is_signed_in() {
    let agent = super::build_agent_with_auth(session());
    let response = agent.auth_response_with_meta();
    let authenticate = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{}}}"#, serde_json::to_string(&response).unwrap());
    // As `extensions::auth::handle_check_subscription` builds its result.
    let check = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "result": { "authenticated": response.meta.is_some(), "meta": response.meta },
    })
    .to_string();
    let decision = |relay: &str| RelayBodyIdentity::for_relay(relay, fuigo_telemetry::id::agent_id);
    for (frame, place) in [(authenticate, "_meta"), (check, "meta")] {
        let local: Value = serde_json::from_str(&frame).unwrap();
        let meta = &local["result"][place];
        assert_eq!(meta["email"], "ada@corp.example", "the local response says who is signed in: {frame}");
        assert_eq!(meta["team_id"], "team-7f3e", "{frame}");
        assert_eq!(meta["team_name"], "Analytical Engines", "{frame}");
        assert_eq!(relay_outbound_frame(&decision(FLUXROUTER_RELAY), frame.clone()), frame);
        for relay in OTHER_RELAYS {
            let sent = relay_outbound_frame(&decision(relay), frame.clone());
            for value in ACCOUNT_VALUES {
                assert!(!sent.contains(value), "{relay} was told who is signed in ({value}): {sent}");
            }
            let mut expected = local.clone();
            for field in ["email", "team_id", "team_name"] {
                assert!(expected["result"][place].as_object_mut().unwrap().shift_remove(field).is_some(), "{field}");
            }
            assert_eq!(sent, expected.to_string(), "{relay}: only who is signed in is withheld");
            // What the account may do is still delivered.
            assert_eq!(expected["result"][place]["team_role"], "admin");
            assert_eq!(expected["result"][place]["auth_mode"], "Oidc");
        }
    }
}
