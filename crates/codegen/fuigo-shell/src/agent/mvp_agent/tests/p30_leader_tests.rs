//! 1.0.30 P30-LEADER: the shared-leader ownership model.
//!
//! ONE authority decides who may change a session: the leader's `OwnerBoard`. It stamps its verdict
//! (`fuigo/leaderOwnerState`, `fuigo/leaderOwnedSessions`, `fuigo/leaderForeignSessions`) on owner-gated requests after
//! stripping client-supplied values; the agent keeps no owner map and trusts only the stamp. Ownership moves only on
//! `session/new`, a non-foreign load or resume, a token reclaim within the grace window, and the pending-claimant rule
//! (a connection that loaded the session while it was foreign takes it over when the owner is gone, with no reload).
//! Sending a prompt or any other message for a session never grants anything.
//!
//! The end-to-end tests run the REAL `run_leader_server` and the agent's real entry points; the only stand-in is the agent's
//! answers to `session/new` / `session/load`, which the rig supplies.

use std::path::Path;
use std::time::Duration;

use agent_client_protocol as acp;
use acp::Agent as _;
use serde_json::{Value, json};

use super::{build_minimal_agent_for_tests, make_test_handle, MvpAgentHandle};
use crate::leader::drivers::{Claimer, OwnerBoard, OwnerState};
use crate::leader::protocol::{
    ClientId, LEADER_CONNECTION_ID_KEY, LEADER_FOREIGN_DRIVER_KEY, LEADER_FOREIGN_SESSIONS_KEY, LEADER_OWNED_SESSIONS_KEY,
    LEADER_OWNER_STATE_KEY, LEADER_OWNER_TOKEN_METHOD, LEADER_RECONNECT_TOKEN_KEY,
};
use crate::leader::server::{
    RELAY_CONNECTION_ID, stamp_inbound_client_identity, stamp_owner_authority, stamp_relay_connection_identity_with,
};
use crate::leader::{ClientCapabilities, ClientMode, LeaderClient};
use crate::session::SessionCommand;

const GRACE_LONG: Duration = Duration::from_secs(8);
const GRACE_SHORT: Duration = Duration::from_millis(500);
/// Long enough for a test to act inside the window on a loaded host, short enough to see it end.
const GRACE_MED: Duration = Duration::from_millis(1500);

fn leader_agent() -> MvpAgentHandle {
    let mut agent = build_minimal_agent_for_tests();
    agent.set_leader_mode();
    agent
}

fn load_request(session: &str, conn: u64, foreign: bool, extra: Value) -> acp::LoadSessionRequest {
    let mut meta = json!({ LEADER_CONNECTION_ID_KEY: conn, LEADER_FOREIGN_DRIVER_KEY: foreign });
    if let (Some(m), Some(e)) = (meta.as_object_mut(), extra.as_object()) {
        m.extend(e.clone());
    }
    serde_json::from_value(json!({ "sessionId": session, "cwd": "/tmp", "mcpServers": [], "_meta": meta })).unwrap()
}

fn drain(rx: &mut tokio::sync::mpsc::UnboundedReceiver<SessionCommand>) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(cmd) = rx.try_recv() {
        out.push(
            match cmd {
                SessionCommand::SetClientMcpSeed { .. } => "SetClientMcpSeed",
                SessionCommand::UpdateMcpServers { .. } => "UpdateMcpServers",
                SessionCommand::ReplaceSystemPrompt { .. } => "ReplaceSystemPrompt",
                SessionCommand::SetClientHooks { .. } => "SetClientHooks",
                SessionCommand::UpdateAttachPolicy { .. } => "UpdateAttachPolicy",
                SessionCommand::ResetPermissionState => "ResetPermissionState",
                _ => "other",
            }
            .to_string(),
        );
    }
    out
}

fn stdio_seed() -> crate::session::managed_mcp::ClientMcpSeed {
    vec![acp::McpServer::Stdio(acp::McpServerStdio::new("steer", std::path::PathBuf::from("/bin/steer")))].into()
}

/// A resident session on `agent` whose actor commands arrive on the returned receiver.
fn resident(agent: &MvpAgentHandle, sid: &str) -> (acp::SessionId, tokio::sync::mpsc::UnboundedReceiver<SessionCommand>) {
    let id = acp::SessionId::new(sid);
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mut handle = make_test_handle("grok-3", false, Some("fuigo-pager"));
    handle.cmd_tx = tx;
    agent.insert_resident(&id, handle);
    (id, rx)
}

// ---------------------------------------------------------------------------------------------------------------------
// A foreign load keeps the session's MCP servers, system prompt and client hooks (M2).
// ---------------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn foreign_attach_keeps_mcp_servers_system_prompt_and_hooks() {
    let agent = leader_agent();
    let sid = acp::SessionId::new("steer-sess");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut handle = make_test_handle("grok-3", false, None);
    handle.cmd_tx = tx;
    agent.insert_resident(&sid, handle);
    let meta = json!({
        "systemPromptOverride": "obey window B",
        "fuigo/hooks": { "PreToolUse": [{ "hookCallbackIds": ["cb"] }] }
    });
    let meta = meta.as_object().unwrap();

    // Foreign: nothing is replaced.
    agent.apply_resident_attach_mcp(&sid, true, stdio_seed(), vec![], None);
    agent.apply_attach_prompt_and_hooks(&sid, Some(meta), None, true);
    assert_eq!(drain(&mut rx), Vec::<String>::new(), "a foreign load must not steer the session");
    assert!(
        agent.resident_handle(&sid).unwrap().initial_client_mcp_servers.is_empty(),
        "the foreign loader's MCP seed must not be stored"
    );

    // The owner's reload (and a cold load) still replaces all three, as before.
    agent.apply_resident_attach_mcp(&sid, false, stdio_seed(), vec![], None);
    agent.apply_attach_prompt_and_hooks(&sid, Some(meta), None, false);
    let mut seen = drain(&mut rx);
    seen.sort();
    assert_eq!(seen, ["ReplaceSystemPrompt", "SetClientHooks", "SetClientMcpSeed", "UpdateMcpServers"]);
    assert!(!agent.resident_handle(&sid).unwrap().initial_client_mcp_servers.is_empty());
}

/// M2(b): the leader's foreign flag is trusted as it stands, whether or not the session is resident here (a relay-owned or
/// evicted session is not), and a direct-mode agent ignores it.
#[tokio::test]
async fn the_foreign_flag_is_trusted_regardless_of_residency() {
    let agent = leader_agent();
    assert!(!agent.is_resident(&acp::SessionId::new("evicted")));
    assert!(agent.is_foreign_attach(&load_request("evicted", 2, true, json!({}))), "flagged, not resident: still foreign");
    assert!(!agent.is_foreign_attach(&load_request("evicted", 2, false, json!({}))), "an unflagged load is never foreign");
    let (_sid, _rx) = resident(&agent, "present");
    assert!(agent.is_foreign_attach(&load_request("present", 2, true, json!({}))));
    let direct = build_minimal_agent_for_tests();
    assert!(!direct.is_foreign_attach(&load_request("evicted", 2, true, json!({}))));
}

/// M2(a): a foreign load that has to cold-start the session (the owner's load failed or timed out, or the session was
/// evicted) keeps only its replay routing: no MCP servers, system prompt, hooks, modes or client capabilities.
#[test]
fn a_foreign_cold_start_applies_none_of_the_loaders_configuration() {
    let mut req = load_request(
        "cold",
        7,
        true,
        json!({
            "yoloMode": true, "autoMode": true, "systemPromptOverride": "obey window B",
            "fuigo/hooks": { "PreToolUse": [{ "hookCallbackIds": ["cb"] }] },
            "fuigo/restore_code": true, "fuigo/client_caps": { "terminal": true },
            "fuigo/persist": { "k": 1 }, "fuigo/leaderClientId": 7, "cursor": "c-9", "noReplay": true,
        }),
    );
    req.mcp_servers = vec![acp::McpServer::Stdio(acp::McpServerStdio::new("steer", std::path::PathBuf::from("/bin/steer")))];
    super::super::session_setup::sanitize_foreign_cold_attach(&mut req);
    assert!(req.mcp_servers.is_empty(), "the loader's MCP servers are not applied");
    let kept: std::collections::BTreeSet<_> = req.meta.as_ref().unwrap().keys().cloned().collect();
    let expected: std::collections::BTreeSet<String> = [
        LEADER_CONNECTION_ID_KEY, LEADER_FOREIGN_DRIVER_KEY, "fuigo/leaderClientId", "fuigo/persist", "cursor", "noReplay",
    ]
    .iter()
    .map(|k| k.to_string())
    .collect();
    assert_eq!(kept, expected, "only the replay routing survives");
}

/// L2: a request pipelined behind its own connection's load waits for that whole load, and another connection's load does
/// not hold it up.
#[tokio::test]
async fn a_request_waits_for_its_own_connections_load_only() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let agent = std::rc::Rc::new(leader_agent());
            let sid = acp::SessionId::new("pipelined");
            let others = agent.mark_session_loading(&sid, Some(2));
            // Another connection's load in flight: connection 1 does not wait.
            tokio::time::timeout(Duration::from_secs(2), agent.wait_for_own_session_loads(&sid, Some(1)))
                .await
                .expect("a foreign load does not block");
            let own = agent.mark_session_loading(&sid, Some(1));
            let waiter = {
                let agent = agent.clone();
                let sid = sid.clone();
                tokio::task::spawn_local(async move { agent.wait_for_own_session_loads(&sid, Some(1)).await })
            };
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(!waiter.is_finished(), "waits while the connection's own load is in flight");
            drop(own);
            tokio::time::timeout(Duration::from_secs(2), waiter).await.expect("released when the load ends").unwrap();
            drop(others);
        })
        .await;
}

// ---------------------------------------------------------------------------------------------------------------------
// The leader stamps; the agent obeys the stamp (H1, M1).
// ---------------------------------------------------------------------------------------------------------------------

/// `method`/`params` as `who` would send them, through the leader's real stamping passes. `forged`: the client's attempt to
/// write the verdict itself, in `_meta` and at the top of the params. `who == None`: a message that skipped the leader.
fn wire_from(method: &str, mut params: Value, who: Option<Claimer>, board: &OwnerBoard, forged: Option<&str>) -> Value {
    if let Some(f) = forged {
        params[LEADER_OWNER_STATE_KEY] = json!(f);
        params["_meta"] = json!({ LEADER_OWNER_STATE_KEY: f, LEADER_CONNECTION_ID_KEY: 99 });
    }
    let mut wire = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    match who {
        Some(Claimer::Client(id)) => {
            stamp_inbound_client_identity(&mut wire, "fuigo-pager", id);
            stamp_owner_authority(&mut wire, Claimer::Client(id), board);
        }
        Some(Claimer::Relay) => {
            wire = serde_json::from_str(&stamp_relay_connection_identity_with(&wire.to_string(), board)).unwrap();
        }
        None => {}
    }
    wire
}

fn cl(n: u64) -> Option<Claimer> {
    Some(Claimer::Client(ClientId(n)))
}

fn ext(method: &str, params: &Value) -> acp::ExtRequest {
    acp::ExtRequest::new(method.to_string(), serde_json::value::to_raw_value(params).unwrap().into())
}

const REFUSED: &str = "driven by another client";

#[tokio::test]
async fn set_mode_set_model_and_set_config_require_the_owner_verdict() {
    let agent = leader_agent();
    let (_sid, mut rx) = resident(&agent, "owned");
    let board = OwnerBoard::default();
    board.claim("owned", Claimer::Client(ClientId(5)));

    let mode = |who: Option<Claimer>, forged: Option<&str>| -> acp::SetSessionModeRequest {
        let wire = wire_from("session/set_mode", json!({ "sessionId": "owned", "modeId": "plan" }), who, &board, forged);
        serde_json::from_value(wire["params"].clone()).unwrap()
    };
    // The leader overwrites a forged verdict.
    let forged = serde_json::to_value(mode(cl(6), Some("self"))).unwrap();
    assert_eq!(forged["_meta"][LEADER_OWNER_STATE_KEY], "other", "a client cannot write its own verdict");

    // Non-owner, forged-verdict and unstamped requests change nothing.
    for (who, forged) in [(cl(6), None), (cl(6), Some("self")), (None, None), (Some(Claimer::Relay), Some("self"))] {
        let err = agent.set_session_mode(mode(who, forged)).await.expect_err("non-owner set_mode must be refused");
        assert_eq!(err.code, acp::Error::invalid_request().code);
    }
    assert!(rx.try_recv().is_err(), "no SessionMode command reached the session");
    let model: acp::SetSessionModelRequest = serde_json::from_value(
        wire_from("session/set_model", json!({ "sessionId": "owned", "modelId": "grok-3" }), cl(6), &board, None)["params"].clone(),
    )
    .unwrap();
    assert!(agent.set_session_model(model).await.is_err(), "non-owner set_model refused");
    let config: acp::SetSessionConfigOptionRequest = serde_json::from_value(
        wire_from(
            "session/set_config_option",
            json!({ "sessionId": "owned", "configId": "reasoning_effort", "value": "high" }),
            cl(6),
            &board,
            Some("self"),
        )["params"]
            .clone(),
    )
    .unwrap();
    assert!(agent.set_session_config_option(config).await.is_err(), "non-owner set_config_option refused");
    assert!(rx.try_recv().is_err(), "nothing reached the session actor");

    // The owner's set_mode goes through.
    let (result, ()) = tokio::join!(agent.set_session_mode(mode(cl(5), None)), async {
        match rx.recv().await.unwrap() {
            SessionCommand::SessionMode { responds_to, .. } => responds_to.send(()).unwrap(),
            _ => panic!("expected SessionMode"),
        }
    });
    assert!(result.is_ok(), "the owner may change the mode");

    // A session nobody owns is not changeable by anyone through these (the owner check is strict).
    let meta = |state: &str| json!({ LEADER_OWNER_STATE_KEY: state }).as_object().cloned();
    assert!(agent.ensure_session_owner(meta("self").as_ref(), "t").is_ok());
    for state in ["other", "none", "bogus"] {
        assert!(agent.ensure_session_owner(meta(state).as_ref(), "t").is_err(), "{state}");
    }
    assert!(agent.ensure_session_owner(None, "t").is_err());
    // Direct mode is unchanged.
    let direct = build_minimal_agent_for_tests();
    assert!(direct.ensure_session_owner(None, "t").is_ok());
}

/// H1: `fuigo/toggle_plan_mode` (the pager's Shift+Tab) is owner-gated like set_mode.
#[tokio::test]
async fn plan_mode_toggle_by_a_non_owner_is_ignored_and_the_owner_works() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let agent = leader_agent();
            let (_sid, mut rx) = resident(&agent, "plan-sess");
            let board = OwnerBoard::default();
            board.claim("plan-sess", Claimer::Client(ClientId(5)));
            let board_ref = &board;
            let toggle = |who: Option<Claimer>, forged: Option<&'static str>| async move {
                let board = board_ref;
                let mut wire = super::real_wire_ext_notification("fuigo/toggle_plan_mode", json!({ "sessionId": "plan-sess" })).await;
                assert_eq!(wire["method"], "_fuigo/toggle_plan_mode");
                if let Some(f) = forged {
                    wire["params"][LEADER_OWNER_STATE_KEY] = json!(f);
                }
                match who {
                    Some(Claimer::Client(id)) => {
                        stamp_inbound_client_identity(&mut wire, "fuigo-pager", id);
                        stamp_owner_authority(&mut wire, Claimer::Client(id), board);
                    }
                    Some(Claimer::Relay) => {
                        wire = serde_json::from_str(&stamp_relay_connection_identity_with(&wire.to_string(), board)).unwrap();
                    }
                    None => {}
                }
                wire
            };
            // Another window, the relay, a forged verdict and a message that skipped the leader: nothing changes.
            for (who, forged) in [(cl(6), None), (cl(6), Some("self")), (Some(Claimer::Relay), None), (None, None)] {
                let wire = toggle(who, forged).await;
                super::deliver_like_the_agent(&agent, &wire).await;
                assert!(rx.try_recv().is_err(), "a non-owner's plan toggle reached the session ({who:?})");
            }
            // The owner's toggle switches the mode.
            let wire = toggle(cl(5), None).await;
            assert_eq!(wire["params"][LEADER_OWNER_STATE_KEY], "self");
            let ((), mode) = tokio::join!(super::deliver_like_the_agent(&agent, &wire), async {
                match rx.recv().await.unwrap() {
                    SessionCommand::SessionMode { session_mode, responds_to } => {
                        responds_to.send(()).unwrap();
                        session_mode.0.to_string()
                    }
                    _ => panic!("expected SessionMode"),
                }
            });
            assert_eq!(mode, "plan");
        })
        .await;
}

/// M1: the session admin methods are refused to a non-owner and allowed to the owner and, when nobody owns the session, to
/// anyone. (The refusal is the same error the other owner-gated requests give; the allowed cases run the real handler.)
#[tokio::test]
async fn session_admin_methods_are_owner_or_unowned_only() {
    let agent = leader_agent();
    let board = OwnerBoard::default();
    board.claim("admin", Claimer::Client(ClientId(5)));
    let admin = [
        ("fuigo/session/rename", json!({ "sessionId": "admin", "title": "x" })),
        ("fuigo/session/delete", json!({ "sessionId": "admin" })),
        ("fuigo/session/update_mcp_servers", json!({ "sessionId": "admin", "mcpServers": [] })),
        ("fuigo/session/close", json!({ "sessionId": "admin" })),
        ("fuigo/session/park", json!({ "sessionId": "admin" })),
        ("fuigo/session/unpark", json!({ "sessionId": "admin" })),
    ];
    for (method, params) in &admin {
        for (who, forged) in [(cl(6), None), (cl(6), Some("self")), (None, None), (Some(Claimer::Relay), None)] {
            let wire = wire_from(&format!("_{method}"), params.clone(), who, &board, forged);
            let err = agent.ext_method(ext(method, &wire["params"])).await.expect_err(method);
            assert!(format!("{err:?}").contains(REFUSED), "{method} by {who:?} must be refused, got {err:?}");
        }
        // The owner and (below) anyone on an unowned session are not refused. (`stamp` reaches the agent as it would.)
        let owner = wire_from(&format!("_{method}"), params.clone(), cl(5), &board, None);
        assert_eq!(owner["params"][LEADER_OWNER_STATE_KEY], "self", "{method}");
        let nobody = OwnerBoard::default();
        let unowned = wire_from(&format!("_{method}"), params.clone(), cl(6), &nobody, None);
        assert_eq!(unowned["params"][LEADER_OWNER_STATE_KEY], "none", "{method}");
        for wire in [&owner, &unowned] {
            assert!(agent.ensure_owner_ext(&wire["params"].to_string(), true, method).is_ok(), "{method}");
        }
    }
    // The real handlers run for the owner and for an unowned session (these two fail on "unknown session" before touching anything).
    for who_board in [(cl(5), &board), (cl(6), &OwnerBoard::default())] {
        for (method, params) in [
            ("fuigo/session/update_mcp_servers", json!({ "sessionId": "admin", "mcpServers": [] })),
            ("fuigo/session/park", json!({ "sessionId": "admin" })),
        ] {
            let wire = wire_from(&format!("_{method}"), params, who_board.0, who_board.1, None);
            let err = agent.ext_method(ext(method, &wire["params"])).await.expect_err("unknown session");
            assert!(!format!("{err:?}").contains(REFUSED), "{method} reached its handler: {err:?}");
        }
        let wire = wire_from("_fuigo/session/close", json!({ "sessionId": "admin" }), who_board.0, who_board.1, None);
        agent.ext_method(ext("fuigo/session/close", &wire["params"])).await.expect("close of a non-resident session");
    }
    // The typed `session/close` follows the same rule.
    let close = |who: Option<Claimer>, board: &OwnerBoard| -> acp::CloseSessionRequest {
        serde_json::from_value(wire_from("session/close", json!({ "sessionId": "admin" }), who, board, None)["params"].clone()).unwrap()
    };
    assert!(agent.close_session(close(cl(6), &board)).await.is_err());
    assert!(agent.close_session(close(cl(5), &board)).await.is_ok());
    assert!(agent.close_session(close(cl(6), &OwnerBoard::default())).await.is_ok());
    // Direct mode is unchanged.
    let direct = build_minimal_agent_for_tests();
    assert!(direct.close_session(serde_json::from_value(json!({ "sessionId": "admin" })).unwrap()).await.is_ok());
}

/// M1: `fuigo/permissions/reset` resets the caller's own sessions and the ones nobody owns, never another connection's.
#[tokio::test]
async fn permissions_reset_skips_sessions_somebody_else_owns() {
    let agent = leader_agent();
    let (_a, mut rx_a) = resident(&agent, "mine");
    let (_b, mut rx_b) = resident(&agent, "theirs");
    let (_c, mut rx_c) = resident(&agent, "nobodys");
    let (_r, mut rx_r) = resident(&agent, "relays");
    let board = OwnerBoard::default();
    board.claim("mine", Claimer::Client(ClientId(1)));
    board.claim("theirs", Claimer::Client(ClientId(2)));
    board.claim("relays", Claimer::Relay);
    let reset = |who: Option<Claimer>, forged: Option<&str>| {
        let mut params = json!({});
        if forged.is_some() {
            params[LEADER_FOREIGN_SESSIONS_KEY] = json!([]);
            params["_meta"] = json!({ LEADER_FOREIGN_SESSIONS_KEY: [] });
        }
        wire_from("_fuigo/permissions/reset", params, who, &board, forged)
    };
    // Connection 1 (forging an empty skip list): only its own and the unowned session are reset.
    super::deliver_like_the_agent(&agent, &reset(cl(1), Some("x"))).await;
    assert_eq!(drain(&mut rx_a), ["ResetPermissionState"], "the caller's own reset still works");
    assert_eq!(drain(&mut rx_c), ["ResetPermissionState"], "a session nobody owns is reset");
    assert!(drain(&mut rx_b).is_empty() && drain(&mut rx_r).is_empty(), "another connection's and the relay's are not");
    // The relay resets its own session (and the unowned one).
    super::deliver_like_the_agent(&agent, &reset(Some(Claimer::Relay), None)).await;
    assert_eq!(drain(&mut rx_r), ["ResetPermissionState"]);
    assert_eq!(drain(&mut rx_c), ["ResetPermissionState"]);
    assert!(drain(&mut rx_a).is_empty() && drain(&mut rx_b).is_empty());
    // Skipping the leader (no stamp): fail closed in leader mode.
    super::deliver_like_the_agent(&agent, &reset(None, None)).await;
    for rx in [&mut rx_a, &mut rx_b, &mut rx_c, &mut rx_r] {
        assert!(drain(rx).is_empty());
    }
    // Direct mode resets every session, as before.
    let direct = build_minimal_agent_for_tests();
    let (_d, mut rx_d) = resident(&direct, "direct");
    super::deliver_like_the_agent(&direct, &json!({ "method": "_fuigo/permissions/reset", "params": {} })).await;
    assert_eq!(drain(&mut rx_d), ["ResetPermissionState"]);
}

// ---------------------------------------------------------------------------------------------------------------------
// The relay path.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn relay_stamp_flags_a_foreign_load_claims_a_free_one_and_never_claims_by_messaging() {
    let board = OwnerBoard::default();
    board.claim("held", Claimer::Client(ClientId(3)));
    let load = |sid: &str, extra: Value| {
        let mut meta = json!({ "yoloMode": true, LEADER_FOREIGN_DRIVER_KEY: false, LEADER_CONNECTION_ID_KEY: 1 });
        meta.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        json!({ "jsonrpc": "2.0", "id": 1, "method": "session/load",
                "params": { "sessionId": sid, "cwd": "/tmp", "mcpServers": [], "_meta": meta } })
        .to_string()
    };
    // Owned by a local client: flagged (a remote-supplied `false` is overwritten), the relay's token is stripped and unused.
    let out: Value = serde_json::from_str(&stamp_relay_connection_identity_with(
        &load("held", json!({ LEADER_RECONNECT_TOKEN_KEY: "0".repeat(32) })),
        &board,
    ))
    .unwrap();
    assert_eq!(out["params"]["_meta"][LEADER_FOREIGN_DRIVER_KEY], true);
    assert_eq!(out["params"]["_meta"][LEADER_CONNECTION_ID_KEY], RELAY_CONNECTION_ID);
    assert!(out["params"]["_meta"].get(LEADER_RECONNECT_TOKEN_KEY).is_none());
    assert_eq!(board.owner_state("held", Claimer::Relay), OwnerState::Other, "a foreign relay load does not make the relay the owner");
    // Not owned: a remote-supplied `true` is stripped, and the relay now owns it.
    let out: Value = serde_json::from_str(&stamp_relay_connection_identity_with(
        &load("free", json!({ LEADER_FOREIGN_DRIVER_KEY: true })),
        &board,
    ))
    .unwrap();
    assert!(out["params"]["_meta"].get(LEADER_FOREIGN_DRIVER_KEY).is_none());
    assert_eq!(board.owner_state("free", Claimer::Relay), OwnerState::SelfOwner);
    // Other relay messages never create or take a claim.
    let prompt = |sid: &str| json!({ "jsonrpc": "2.0", "id": 2, "method": "session/prompt", "params": { "sessionId": sid } }).to_string();
    stamp_relay_connection_identity_with(&prompt("held"), &board);
    stamp_relay_connection_identity_with(&prompt("only-prompted"), &board);
    assert_eq!(board.owner_state("held", Claimer::Relay), OwnerState::Other);
    assert_eq!(board.owner_state("only-prompted", Claimer::Relay), OwnerState::Unowned, "a prompt is not a claim");
    // Batches and set_mode get the same treatment, with the leader's verdict for the relay.
    let batch = json!([
        { "jsonrpc": "2.0", "id": 3, "method": "session/set_mode", "params": { "sessionId": "free", "modeId": "plan", "_meta": { LEADER_CONNECTION_ID_KEY: 1, LEADER_OWNER_STATE_KEY: "other" } } },
        { "jsonrpc": "2.0", "id": 4, "method": "session/set_mode", "params": { "sessionId": "held", "modeId": "plan", "_meta": { LEADER_OWNER_STATE_KEY: "self" } } }
    ])
    .to_string();
    let out: Value = serde_json::from_str(&stamp_relay_connection_identity_with(&batch, &board)).unwrap();
    assert_eq!(out[0]["params"]["_meta"][LEADER_CONNECTION_ID_KEY], RELAY_CONNECTION_ID);
    assert_eq!(out[0]["params"]["_meta"][LEADER_OWNER_STATE_KEY], "self");
    assert_eq!(out[1]["params"]["_meta"][LEADER_OWNER_STATE_KEY], "other", "a forged verdict is replaced");
}

/// A batch from a local client gets the same treatment per element: a forged verdict hidden in one is replaced.
#[tokio::test]
async fn e2e_a_forged_verdict_inside_a_batch_is_replaced() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            let mut a = rig.client().await;
            rig.new_session(&mut a, 1, "batch").await;
            let mut m = rig.client().await;
            let batch = json!([
                { "jsonrpc": "2.0", "id": 5, "method": "session/set_mode", "params": { "sessionId": "batch", "modeId": "plan",
                    "_meta": { LEADER_OWNER_STATE_KEY: "self", LEADER_CONNECTION_ID_KEY: 1 } } }
            ]);
            m.send(batch.to_string()).unwrap();
            let fwd = rig.next().await;
            assert_eq!(fwd[0]["params"]["_meta"][LEADER_OWNER_STATE_KEY], "other");
            assert_ne!(fwd[0]["params"]["_meta"][LEADER_CONNECTION_ID_KEY], 1);
            a.cancel();
            m.cancel();
            rig.stop();
        })
        .await;
}

/// Everything the leader stamps, once, per method (and the client-supplied copies are always removed).
#[test]
fn the_leader_stamps_exactly_the_owner_gated_methods() {
    let board = OwnerBoard::default();
    board.claim("mine", Claimer::Client(ClientId(1)));
    board.claim("theirs", Claimer::Client(ClientId(2)));
    let stamp = |method: &str, params: Value| wire_from(method, params, cl(1), &board, Some("self"));
    // Typed requests carry the verdict in `_meta`.
    for (m, sid, want) in [
        ("session/set_mode", "mine", "self"),
        ("session/set_model", "theirs", "other"),
        ("session/set_config_option", "nowhere", "none"),
        ("session/close", "mine", "self"),
    ] {
        let w = stamp(m, json!({ "sessionId": sid }));
        assert_eq!(w["params"]["_meta"][LEADER_OWNER_STATE_KEY], want, "{m}");
        assert!(w["params"].get(LEADER_OWNER_STATE_KEY).is_none(), "{m}: a forged top-level verdict is removed");
    }
    // Extensions carry it at the top of the params.
    for m in [
        "_fuigo/toggle_plan_mode", "_fuigo/session/rename", "_fuigo/session/delete", "_fuigo/session/update_mcp_servers",
        "_fuigo/session/close", "_fuigo/session/park", "_fuigo/session/unpark",
    ] {
        let w = stamp(m, json!({ "sessionId": "theirs" }));
        assert_eq!(w["params"][LEADER_OWNER_STATE_KEY], "other", "{m}");
        assert!(w["params"]["_meta"].get(LEADER_OWNER_STATE_KEY).is_none(), "{m}: a forged `_meta` verdict is removed");
        assert_eq!(stamp(m, json!({ "sessionId": "mine" }))["params"][LEADER_OWNER_STATE_KEY], "self");
        assert_eq!(stamp(m, json!({}))["params"][LEADER_OWNER_STATE_KEY], "other", "{m}: no session named fails closed");
    }
    // The session-less machine-wide ones carry lists.
    let yolo = stamp("_fuigo/yolo_mode_changed", json!({ "yolo_mode": true, LEADER_OWNED_SESSIONS_KEY: ["theirs"] }));
    assert_eq!(yolo["params"][LEADER_OWNED_SESSIONS_KEY], json!(["mine"]));
    let reset = stamp("_fuigo/permissions/reset", json!({ LEADER_FOREIGN_SESSIONS_KEY: [] }));
    assert_eq!(reset["params"][LEADER_FOREIGN_SESSIONS_KEY], json!(["theirs"]));
    // Everything else is left alone but still has forged keys removed.
    let other = stamp("session/prompt", json!({ "sessionId": "theirs" }));
    assert!(other["params"].get(LEADER_OWNER_STATE_KEY).is_none() && other["params"]["_meta"].get(LEADER_OWNER_STATE_KEY).is_none());
    // A `params.method` evasion does not change what the leader stamps.
    let evade = stamp("_fuigo/other", json!({ "sessionId": "theirs", "method": "fuigo/toggle_plan_mode" }));
    assert!(evade["params"].get(LEADER_OWNER_STATE_KEY).is_none());
}

// ---------------------------------------------------------------------------------------------------------------------
// End-to-end rig: the real leader server.
// ---------------------------------------------------------------------------------------------------------------------

struct Rig {
    _temp: tempfile::TempDir,
    sock: std::path::PathBuf,
    acp_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
    response_tx: tokio::sync::mpsc::UnboundedSender<String>,
    client_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    board: OwnerBoard,
    cancel: tokio_util::sync::CancellationToken,
}

async fn connect(sock: &Path) -> LeaderClient {
    // Cross-platform readiness: retry the real client handshake instead of probing the socket with a UnixStream.
    for _ in 0..500 {
        if let Ok(c) = LeaderClient::connect(sock.to_path_buf(), "fuigo-pager", ClientMode::Stdio, ClientCapabilities::default()).await {
            return c;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("leader never became ready");
}

impl Rig {
    async fn start(grace: Duration) -> Rig {
        let temp = tempfile::TempDir::new().unwrap();
        let sock = temp.path().join("leader.sock");
        let server = crate::leader::server::spawn_leader_server_with_grace(sock.clone(), grace).await.unwrap();
        Rig {
            _temp: temp,
            sock,
            acp_rx: server.acp_rx,
            response_tx: server.response_tx,
            client_count: server.client_count,
            board: server.control_state.driver_board(),
            cancel: server.cancel,
        }
    }
    async fn client(&self) -> LeaderClient {
        connect(&self.sock).await
    }
    /// The next message the leader forwarded to the agent.
    async fn next(&mut self) -> Value {
        let line = tokio::time::timeout(Duration::from_secs(5), self.acp_rx.recv())
            .await
            .expect("leader forwarded a message")
            .expect("channel open");
        serde_json::from_str(&line).unwrap()
    }
    /// Read `client` until the reply to its request `id` arrives.
    async fn reply(client: &mut LeaderClient, id: u64) -> Value {
        loop {
            let line = tokio::time::timeout(Duration::from_secs(5), client.recv())
                .await
                .expect("reply in time")
                .expect("client open");
            let v: Value = serde_json::from_str(&line).unwrap();
            if v.get("id") == Some(&json!(id)) {
                return v;
            }
        }
    }
    /// The leader tells the agent the sessions their last subscriber left (`fuigo/internal/evict_sessions`).
    async fn evicted(&mut self, sid: &str) {
        let evict = self.next().await;
        assert_eq!(evict["params"]["sessionIds"], json!([sid]), "{evict}");
    }
    /// Everything `client` receives within `window`.
    async fn drain_client(client: &mut LeaderClient, window: Duration) -> Vec<Value> {
        let mut out = Vec::new();
        let end = tokio::time::Instant::now() + window;
        while let Ok(Some(line)) = tokio::time::timeout_at(end, client.recv()).await {
            out.push(serde_json::from_str(&line).unwrap());
        }
        out
    }
    /// `session/new` through the leader; answers it as the agent would. Returns (connection id, the response).
    async fn new_session(&mut self, client: &mut LeaderClient, id: u64, sid: &str) -> (u64, Value) {
        client.send(json!({ "jsonrpc": "2.0", "id": id, "method": "session/new", "params": { "cwd": "/tmp", "mcpServers": [] } }).to_string()).unwrap();
        let fwd = self.next().await;
        let conn = fwd["params"]["_meta"][LEADER_CONNECTION_ID_KEY].as_u64().expect("stamped");
        self.response_tx.send(json!({ "jsonrpc": "2.0", "result": { "sessionId": sid }, "id": fwd["id"] }).to_string()).unwrap();
        (conn, Self::reply(client, id).await)
    }
    /// `session/load` through the leader, not yet answered. Returns the request as the agent would see it.
    async fn send_load(&mut self, client: &LeaderClient, id: u64, sid: &str, meta: Value) -> Value {
        client.send(json!({ "jsonrpc": "2.0", "id": id, "method": "session/load",
            "params": { "sessionId": sid, "cwd": "/tmp", "mcpServers": [], "_meta": meta } }).to_string()).unwrap();
        self.next().await
    }
    /// `session/load` through the leader, answered successfully. Returns (the request as the agent saw it, the client's response).
    async fn load(&mut self, client: &mut LeaderClient, id: u64, sid: &str, meta: Value) -> (Value, Value) {
        let fwd = self.send_load(client, id, sid, meta).await;
        self.response_tx.send(json!({ "jsonrpc": "2.0", "result": {}, "id": fwd["id"] }).to_string()).unwrap();
        let reply = Self::reply(client, id).await;
        (fwd, reply)
    }
    /// An owner-gated request from `client`, forwarded: returns the leader's verdict stamped on it.
    async fn verdict(&mut self, client: &LeaderClient, method: &str, sid: &str) -> String {
        let params = match method {
            "session/set_model" => json!({ "sessionId": sid, "modelId": "grok-3" }),
            "session/set_mode" => json!({ "sessionId": sid, "modeId": "plan" }),
            _ => json!({ "sessionId": sid }),
        };
        client.send(json!({ "jsonrpc": "2.0", "id": 900, "method": method, "params": params }).to_string()).unwrap();
        let fwd = self.next().await;
        let state = if method.starts_with("session/") { &fwd["params"]["_meta"][LEADER_OWNER_STATE_KEY] } else { &fwd["params"][LEADER_OWNER_STATE_KEY] };
        state.as_str().unwrap_or("MISSING").to_string()
    }
    /// Poll until `cond`, for state the leader reaches on its own (a timer, a disconnect).
    async fn until(&self, what: &str, cond: impl Fn() -> bool) {
        for _ in 0..600 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("never happened: {what}");
    }
    async fn wait_for_clients(&self, n: usize) {
        self.until("client count", || self.client_count.load(std::sync::atomic::Ordering::Relaxed) == n).await;
    }
    fn stop(&self) {
        self.cancel.cancel();
    }
}

fn token_of(reply: &Value) -> Option<String> {
    reply["result"]["_meta"][LEADER_RECONNECT_TOKEN_KEY].as_str().map(str::to_owned)
}

fn flagged(fwd: &Value) -> bool {
    fwd["params"]["_meta"].get(LEADER_FOREIGN_DRIVER_KEY) == Some(&json!(true))
}

fn conn_of(fwd: &Value) -> u64 {
    fwd["params"]["_meta"][LEADER_CONNECTION_ID_KEY].as_u64().unwrap()
}

fn attach_request(fwd: &Value) -> acp::LoadSessionRequest {
    serde_json::from_value(fwd["params"].clone()).unwrap()
}

fn state_of(rig: &Rig, sid: &str, conn: u64) -> OwnerState {
    rig.board.owner_state(sid, Claimer::Client(ClientId(conn)))
}

// ---------------------------------------------------------------------------------------------------------------------
// Normal use still works: one window, and two windows.
// ---------------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn e2e_single_and_two_window_use_keep_working() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            let mut a = rig.client().await;
            let (a_conn, reply) = rig.new_session(&mut a, 1, "use").await;
            assert!(token_of(&reply).is_some());
            // Shift+Tab, the model pick, /model and the mode all reach the agent as the owner's.
            for (m, sid) in [
                ("session/set_mode", "use"),
                ("session/set_model", "use"),
                ("session/set_config_option", "use"),
                ("_fuigo/toggle_plan_mode", "use"),
                ("_fuigo/session/update_mcp_servers", "use"),
                ("_fuigo/session/close", "use"),
            ] {
                assert_eq!(rig.verdict(&a, m, sid).await, "self", "{m}");
            }
            // Its own reload keeps it the owner.
            let (fwd, reply) = rig.load(&mut a, 2, "use", json!({ "yoloMode": true })).await;
            assert!(!flagged(&fwd) && token_of(&reply).is_some());
            // A second window views the session: it can attach, but not change it, and its admin calls are refused.
            let mut b = rig.client().await;
            let (fwd, reply) = rig.load(&mut b, 3, "use", json!({})).await;
            assert!(flagged(&fwd) && token_of(&reply).is_none());
            let b_conn = conn_of(&fwd);
            for m in ["session/set_mode", "session/set_model", "_fuigo/toggle_plan_mode", "_fuigo/session/delete", "session/close"] {
                assert_eq!(rig.verdict(&b, m, "use").await, "other", "{m}");
            }
            // The owner's yolo toggle covers its session; the second window's covers nothing of the owner's.
            let yolo = json!({ "jsonrpc": "2.0", "method": "_fuigo/yolo_mode_changed", "params": { "yolo_mode": true } }).to_string();
            a.send(yolo.clone()).unwrap();
            assert_eq!(rig.next().await["params"][LEADER_OWNED_SESSIONS_KEY], json!(["use"]));
            b.send(yolo).unwrap();
            assert_eq!(rig.next().await["params"][LEADER_OWNED_SESSIONS_KEY], json!([]));
            // The session's own owner is untouched throughout.
            assert_eq!(state_of(&rig, "use", a_conn), OwnerState::SelfOwner);
            assert_eq!(state_of(&rig, "use", b_conn), OwnerState::Other);
            a.cancel();
            b.cancel();
            rig.stop();
        })
        .await;
}

/// A session its owner closed (or deleted) has no owner: the next window to load it is not foreign. A refused close by a
/// non-owner releases nothing.
#[tokio::test]
async fn e2e_closing_a_session_releases_its_ownership() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            let mut a = rig.client().await;
            rig.new_session(&mut a, 1, "closed").await;
            let mut b = rig.client().await;
            let (fwd, _) = rig.load(&mut b, 2, "closed", json!({})).await;
            assert!(flagged(&fwd));
            let answer_ok = |rig: &Rig, fwd: &Value| {
                rig.response_tx.send(json!({ "jsonrpc": "2.0", "result": { "success": true }, "id": fwd["id"] }).to_string()).unwrap();
            };
            // The viewer's close is refused by the agent (the verdict is `other`); even if it were answered, nothing is released.
            b.send(json!({ "jsonrpc": "2.0", "id": 20, "method": "_fuigo/session/close", "params": { "sessionId": "closed" } }).to_string()).unwrap();
            let fwd = rig.next().await;
            assert_eq!(fwd["params"][LEADER_OWNER_STATE_KEY], "other");
            answer_ok(&rig, &fwd);
            Rig::reply(&mut b, 20).await;
            let mut c = rig.client().await;
            let (fwd, _) = rig.load(&mut c, 21, "closed", json!({})).await;
            assert!(flagged(&fwd), "a non-owner's close does not release the session");
            // The owner's close does.
            a.send(json!({ "jsonrpc": "2.0", "id": 10, "method": "_fuigo/session/close", "params": { "sessionId": "closed" } }).to_string()).unwrap();
            let fwd = rig.next().await;
            assert_eq!(fwd["params"][LEADER_OWNER_STATE_KEY], "self");
            answer_ok(&rig, &fwd);
            Rig::reply(&mut a, 10).await;
            let (fwd, reply) = rig.load(&mut b, 11, "closed", json!({})).await;
            assert!(!flagged(&fwd), "nobody owns a closed session: the next loader does");
            assert!(token_of(&reply).is_some());
            assert_eq!(rig.verdict(&b, "session/set_model", "closed").await, "self");
            a.cancel();
            b.cancel();
            c.cancel();
            rig.stop();
        })
        .await;
}

// ---------------------------------------------------------------------------------------------------------------------
// The relay and the local clients flag each other's loads.
// ---------------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn e2e_relay_and_local_loads_of_each_others_sessions_are_foreign() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            let agent = leader_agent();

            // --- A local window owns "local-sess"; the relay loads it asking for yolo.
            let mut a = rig.client().await;
            let (a_conn, _) = rig.new_session(&mut a, 1, "local-sess").await;
            let (lsid, mut lrx) = resident(&agent, "local-sess");
            let relay_load = json!({ "jsonrpc": "2.0", "id": 5, "method": "session/load", "params": {
                "sessionId": "local-sess", "cwd": "/tmp", "mcpServers": [],
                "_meta": { "yoloMode": true, "autoMode": true, LEADER_FOREIGN_DRIVER_KEY: false } } }).to_string();
            let stamped: Value = serde_json::from_str(&stamp_relay_connection_identity_with(&relay_load, &rig.board)).unwrap();
            assert_eq!(stamped["params"]["_meta"][LEADER_FOREIGN_DRIVER_KEY], true, "relay load of a locally owned session is foreign");
            assert!(agent.is_foreign_attach(&attach_request(&stamped)));
            agent.refresh_reconnect_session_state(&lsid, false, true, true, true);
            assert!(!super::yolo_of(&agent, &lsid), "the relay cannot raise a locally owned session's mode");
            assert!(lrx.try_recv().is_err());
            assert_eq!(state_of(&rig, "local-sess", a_conn), OwnerState::SelfOwner, "the relay did not take ownership");

            // --- The relay owns "relay-sess" (it created it); a local window loads it asking for yolo.
            let (rsid, mut rrx) = resident(&agent, "relay-sess");
            let new = json!({ "jsonrpc": "2.0", "id": 77, "method": "session/new", "params": { "cwd": "/tmp" } }).to_string();
            stamp_relay_connection_identity_with(&new, &rig.board);
            assert_eq!(rig.board.owner_state("relay-sess", Claimer::Relay), OwnerState::Unowned, "not before the agent answers");
            rig.response_tx.send(json!({ "jsonrpc": "2.0", "id": 77, "result": { "sessionId": "relay-sess" } }).to_string()).unwrap();
            rig.until("relay owns its new session", || rig.board.owner_state("relay-sess", Claimer::Relay) == OwnerState::SelfOwner).await;
            let mut b = rig.client().await;
            let (fwd, reply) = rig
                .load(&mut b, 2, "relay-sess", json!({ "yoloMode": true, "autoMode": true, LEADER_FOREIGN_DRIVER_KEY: false }))
                .await;
            let b_conn = conn_of(&fwd);
            assert!(flagged(&fwd), "local load of a relay-owned session is foreign");
            assert!(token_of(&reply).is_none(), "a foreign load is not issued a reconnect token");
            assert!(agent.is_foreign_attach(&attach_request(&fwd)));
            agent.refresh_reconnect_session_state(&rsid, false, true, true, true);
            assert!(!super::yolo_of(&agent, &rsid));
            assert!(rrx.try_recv().is_err());
            assert_eq!(state_of(&rig, "relay-sess", b_conn), OwnerState::Other);
            assert_eq!(rig.board.owner_state("relay-sess", Claimer::Relay), OwnerState::SelfOwner);

            // The relay's own yolo notification works on its session; B's does not.
            let wire = super::real_wire_ext_notification("fuigo/yolo_mode_changed", json!({ "yolo_mode": true })).await;
            let from_relay: Value = serde_json::from_str(&stamp_relay_connection_identity_with(&wire.to_string(), &rig.board)).unwrap();
            super::deliver_like_the_agent(&agent, &from_relay).await;
            assert!(super::yolo_of(&agent, &rsid), "the relay (owner) changes its own session");
            assert!(!super::yolo_of(&agent, &lsid), "and not the local window's");
            let off = super::real_wire_ext_notification("fuigo/yolo_mode_changed", json!({ "yolo_mode": false })).await;
            b.send(off.to_string()).unwrap();
            let fwd = rig.next().await;
            super::deliver_like_the_agent(&agent, &json!({ "method": "fuigo/yolo_mode_changed", "params": fwd["params"].clone() })).await;
            assert!(super::yolo_of(&agent, &rsid), "B cannot switch the relay's session off");
            a.cancel();
            b.cancel();
            rig.stop();
        })
        .await;
}

// ---------------------------------------------------------------------------------------------------------------------
// A load racing another connection's cold load: the leader claims at request time, so the second loader is foreign.
// ---------------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn e2e_load_during_another_connections_cold_load_is_foreign_and_cannot_own() {
    for a_first in [true, false] {
        tokio::task::LocalSet::new()
            .run_until(async {
                let mut rig = Rig::start(GRACE_LONG).await;
                let mut a = rig.client().await;
                let mut b = rig.client().await;
                let (first, second) = if a_first { (&mut a, &mut b) } else { (&mut b, &mut a) };
                // The first loader's request reaches the agent (its cold load starts) and is not answered yet.
                let fwd1 = rig.send_load(first, 1, "cold-e2e", json!({ "yoloMode": false })).await;
                assert!(!flagged(&fwd1), "the first loader is not flagged");
                let first_conn = conn_of(&fwd1);
                // The second loader arrives before the session is resident.
                let fwd2 = rig.send_load(second, 2, "cold-e2e", json!({ "yoloMode": true, "autoMode": true })).await;
                let second_conn = conn_of(&fwd2);
                assert_ne!(first_conn, second_conn);
                assert!(flagged(&fwd2), "the leader flags the second loader (a_first={a_first})");
                let agent = leader_agent();
                assert!(agent.is_foreign_attach(&attach_request(&fwd2)), "the agent honours the flag although the session is not resident");
                // The first load finishes; then the second.
                rig.response_tx.send(json!({ "jsonrpc": "2.0", "result": {}, "id": fwd1["id"] }).to_string()).unwrap();
                rig.response_tx.send(json!({ "jsonrpc": "2.0", "result": {}, "id": fwd2["id"] }).to_string()).unwrap();
                assert!(token_of(&Rig::reply(first, 1).await).is_some());
                assert!(token_of(&Rig::reply(second, 2).await).is_none());
                assert_eq!(state_of(&rig, "cold-e2e", first_conn), OwnerState::SelfOwner);
                assert_eq!(state_of(&rig, "cold-e2e", second_conn), OwnerState::Other);
                a.cancel();
                b.cancel();
                rig.stop();
            })
            .await;
    }
}

/// A load the leader let claim a session, whose answer is an error, gives the claim back (the next loader is not foreign).
#[tokio::test]
async fn e2e_a_failed_load_does_not_leave_its_loader_the_owner() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            let mut a = rig.client().await;
            let mut b = rig.client().await;
            let fwd = rig.send_load(&a, 1, "missing", json!({})).await;
            assert!(!flagged(&fwd));
            let a_conn = conn_of(&fwd);
            // Pipelined right behind the load, the loader is already the owner (L2).
            assert_eq!(rig.verdict(&a, "session/set_model", "missing").await, "self");
            rig.response_tx.send(json!({ "jsonrpc": "2.0", "error": { "code": -32602, "message": "no such session" }, "id": fwd["id"] }).to_string()).unwrap();
            assert!(Rig::reply(&mut a, 1).await.get("error").is_some());
            assert_eq!(state_of(&rig, "missing", a_conn), OwnerState::Unowned, "a failed load owns nothing");
            let fwd = rig.send_load(&b, 2, "missing", json!({})).await;
            assert!(!flagged(&fwd), "the next loader is the first one");
            rig.response_tx.send(json!({ "jsonrpc": "2.0", "result": {}, "id": fwd["id"] }).to_string()).unwrap();
            assert!(token_of(&Rig::reply(&mut b, 2).await).is_some());
            a.cancel();
            b.cancel();
            rig.stop();
        })
        .await;
}

/// A relay load claims the session when it is sent; its error answer gives the claim back exactly as a failed local load
/// does, without disturbing an owner the claim did not replace.
#[tokio::test]
async fn e2e_a_failed_relay_load_does_not_leave_the_relay_the_owner() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            let mut a = rig.client().await;
            let relay_load = |id: u64, sid: &str| {
                json!({ "jsonrpc": "2.0", "id": id, "method": "session/load", "params": { "sessionId": sid, "cwd": "/tmp", "mcpServers": [], "_meta": {} } })
                    .to_string()
            };
            let fail = |id: u64| json!({ "jsonrpc": "2.0", "error": { "code": -32602, "message": "no such session" }, "id": id }).to_string();

            // A free session: the relay owns it from the moment it loads it, and a failed load gives it up.
            stamp_relay_connection_identity_with(&relay_load(41, "relay-missing"), &rig.board);
            assert_eq!(rig.board.owner_state("relay-missing", Claimer::Relay), OwnerState::SelfOwner, "claimed at request time");
            rig.response_tx.send(fail(41)).unwrap();
            rig.until("the failed relay load gave its claim back", || {
                rig.board.owner_state("relay-missing", Claimer::Relay) == OwnerState::Unowned
            })
            .await;
            let fwd = rig.send_load(&a, 1, "relay-missing", json!({})).await;
            assert!(!flagged(&fwd), "the next loader is the first one");
            let a_conn = conn_of(&fwd);
            rig.response_tx.send(json!({ "jsonrpc": "2.0", "result": {}, "id": fwd["id"] }).to_string()).unwrap();
            assert!(token_of(&Rig::reply(&mut a, 1).await).is_some());
            assert_eq!(state_of(&rig, "relay-missing", a_conn), OwnerState::SelfOwner);

            // A local owner: the relay's load is foreign and claims nothing, so its failure changes nothing.
            let out: Value = serde_json::from_str(&stamp_relay_connection_identity_with(&relay_load(42, "relay-missing"), &rig.board)).unwrap();
            assert_eq!(out["params"]["_meta"][LEADER_FOREIGN_DRIVER_KEY], true);
            rig.response_tx.send(fail(42)).unwrap();
            // The answer is handled in order; this later one proves the failure above has been processed.
            stamp_relay_connection_identity_with(&relay_load(43, "relay-held"), &rig.board);
            rig.response_tx.send(json!({ "jsonrpc": "2.0", "result": {}, "id": 43 }).to_string()).unwrap();
            assert_eq!(state_of(&rig, "relay-missing", a_conn), OwnerState::SelfOwner, "the local owner is undisturbed");
            assert_eq!(rig.board.owner_state("relay-missing", Claimer::Relay), OwnerState::Other);

            // The relay owns "relay-held" (43 succeeded); a failed reload of it keeps the relay the owner.
            rig.until("a successful relay load keeps its claim", || {
                rig.board.owner_state("relay-held", Claimer::Relay) == OwnerState::SelfOwner
            })
            .await;
            stamp_relay_connection_identity_with(&relay_load(44, "relay-held"), &rig.board);
            rig.response_tx.send(fail(44)).unwrap();
            stamp_relay_connection_identity_with(&relay_load(45, "relay-other"), &rig.board);
            rig.response_tx.send(fail(45)).unwrap();
            rig.until("the later failure was processed", || {
                rig.board.owner_state("relay-other", Claimer::Relay) == OwnerState::Unowned
            })
            .await;
            assert_eq!(rig.board.owner_state("relay-held", Claimer::Relay), OwnerState::SelfOwner, "a failed reload does not drop an existing relay claim");
            a.cancel();
            rig.stop();
        })
        .await;
}

// ---------------------------------------------------------------------------------------------------------------------
// Grace window: no handoff, only the token reclaims; then the pending claimant owns (H2a, M3).
// ---------------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn e2e_driver_disconnect_has_no_handoff_and_only_the_token_reclaims_within_grace() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            let agent = leader_agent();
            let mut a = rig.client().await;
            let (a_conn, new_reply) = rig.new_session(&mut a, 1, "grace-sess").await;
            let token_a = token_of(&new_reply).expect("the owning client is issued a reconnect token in session/new");
            assert_eq!(token_a.len(), 32, "128-bit token");
            let (sid, _rx) = resident(&agent, "grace-sess");

            // B attaches as a viewer while A owns: flagged, no token.
            let mut b = rig.client().await;
            let (fwd, reply) = rig.load(&mut b, 2, "grace-sess", json!({})).await;
            assert!(flagged(&fwd));
            assert!(token_of(&reply).is_none());

            // A disconnects. Ownership is NOT handed to B: B's later load asking for yolo is still foreign.
            a.cancel();
            rig.wait_for_clients(1).await;
            let (fwd, reply) = rig.load(&mut b, 3, "grace-sess", json!({ "yoloMode": true, "autoMode": true })).await;
            let b_conn = conn_of(&fwd);
            assert!(flagged(&fwd), "no arbitrary handoff to a remaining subscriber");
            assert!(token_of(&reply).is_none());
            assert!(agent.is_foreign_attach(&attach_request(&fwd)));
            agent.refresh_reconnect_session_state(&sid, false, true, true, true);
            assert!(!super::yolo_of(&agent, &sid));
            assert_eq!(rig.verdict(&b, "session/set_model", "grace-sess").await, "other", "the departed owner's session is reserved");
            assert_eq!(state_of(&rig, "grace-sess", b_conn), OwnerState::Other);
            assert!(
                stamp_relay_connection_identity_with(
                    &json!({ "jsonrpc": "2.0", "id": 1, "method": "session/load", "params": { "sessionId": "grace-sess", "_meta": {} } }).to_string(),
                    &rig.board
                )
                .contains(LEADER_FOREIGN_DRIVER_KEY),
                "a relay load within the grace window is foreign too"
            );

            // A third program with a wrong token is foreign; the token is never forwarded to the agent.
            let mut c = rig.client().await;
            let (fwd, _) = rig.load(&mut c, 4, "grace-sess", json!({ LEADER_RECONNECT_TOKEN_KEY: "0".repeat(32), "yoloMode": true })).await;
            assert!(flagged(&fwd), "a wrong token does not reclaim");
            assert!(fwd["params"]["_meta"].get(LEADER_RECONNECT_TOKEN_KEY).is_none(), "the token never reaches the agent");

            // The reconnecting pager (a NEW connection) presents A's token: it takes ownership back and gets a fresh token.
            let mut a2 = rig.client().await;
            let (fwd, reply) = rig.load(&mut a2, 5, "grace-sess", json!({ LEADER_RECONNECT_TOKEN_KEY: token_a, "yoloMode": true })).await;
            let a2_conn = conn_of(&fwd);
            assert!(!flagged(&fwd), "the token holder is not foreign");
            assert!(fwd["params"]["_meta"].get(LEADER_RECONNECT_TOKEN_KEY).is_none(), "the token never reaches the agent");
            assert!(!agent.is_foreign_attach(&attach_request(&fwd)));
            agent.refresh_reconnect_session_state(&sid, false, true, false, false);
            assert!(super::yolo_of(&agent, &sid), "the token holder's reload applies its mode");
            assert_eq!(state_of(&rig, "grace-sess", a2_conn), OwnerState::SelfOwner);
            assert_eq!(rig.verdict(&a2, "session/set_model", "grace-sess").await, "self");
            let token_a2 = token_of(&reply).expect("a rotated token");
            assert_ne!(token_a2, token_a);

            // The window is closed and A2 is the live owner: the old token buys nothing.
            let (fwd, _) = rig.load(&mut c, 6, "grace-sess", json!({ LEADER_RECONNECT_TOKEN_KEY: token_a })).await;
            assert!(flagged(&fwd));
            a2.cancel();
            b.cancel();
            c.cancel();
            rig.stop();
        })
        .await;
}

/// M3: when the owner was the only subscriber, its token is kept and the grace window opens all the same.
#[tokio::test]
async fn e2e_sole_subscriber_disconnect_keeps_the_token_and_the_window() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            let bystander = rig.client().await;
            let mut a = rig.client().await;
            let (_, new_reply) = rig.new_session(&mut a, 1, "sole").await;
            let token = token_of(&new_reply).unwrap();
            a.cancel();
            rig.wait_for_clients(1).await;
            // The agent is told the (idle) session lost its owner; the leader still reserves it.
            rig.evicted("sole").await;
            // A tokenless window (any program, or a plain `--resume`) is foreign within the window.
            let mut c = rig.client().await;
            let (fwd, reply) = rig.load(&mut c, 2, "sole", json!({ "yoloMode": true })).await;
            assert!(flagged(&fwd), "tokenless within the window: foreign");
            assert!(token_of(&reply).is_none());
            let agent = leader_agent();
            assert!(agent.is_foreign_attach(&attach_request(&fwd)), "flagged although the session is not resident (evicted)");
            // The owner's reconnect (new connection, same token) owns again.
            let mut a2 = rig.client().await;
            let (fwd, reply) = rig.load(&mut a2, 3, "sole", json!({ LEADER_RECONNECT_TOKEN_KEY: token })).await;
            assert!(!flagged(&fwd));
            assert!(token_of(&reply).is_some());
            assert_eq!(rig.verdict(&a2, "session/set_model", "sole").await, "self");
            assert_eq!(rig.verdict(&c, "session/set_model", "sole").await, "other");
            a2.cancel();
            c.cancel();
            bystander.cancel();
            rig.stop();
        })
        .await;
}

/// H2(a): quit and `--resume` within the grace window. The resumed window is foreign inside the window, and owns when the
/// window ends, with no reload; the window that was already viewing the session is first in line.
#[tokio::test]
async fn e2e_a_resumed_window_owns_automatically_when_the_grace_window_ends() {
    tokio::task::LocalSet::new()
        .run_until(async {
            // Sole subscriber: the resumed window is the only claimant.
            let mut rig = Rig::start(GRACE_MED).await;
            let bystander = rig.client().await;
            let mut a = rig.client().await;
            rig.new_session(&mut a, 1, "resume").await;
            a.cancel();
            rig.wait_for_clients(1).await;
            rig.evicted("resume").await;
            let mut c = rig.client().await;
            let (fwd, _) = rig.load(&mut c, 2, "resume", json!({})).await;
            assert!(flagged(&fwd));
            let c_conn = conn_of(&fwd);
            assert_eq!(rig.verdict(&c, "session/set_model", "resume").await, "other", "inside the window");
            rig.until("the window ended", || state_of(&rig, "resume", c_conn) == OwnerState::SelfOwner).await;
            assert_eq!(rig.verdict(&c, "session/set_model", "resume").await, "self", "owns now, with no reload");
            assert_eq!(rig.verdict(&c, "_fuigo/toggle_plan_mode", "resume").await, "self");
            c.cancel();
            bystander.cancel();
            rig.stop();

            // Another window was already viewing it: load order decides, and the resumed window waits its turn.
            let mut rig = Rig::start(GRACE_MED).await;
            let mut a = rig.client().await;
            rig.new_session(&mut a, 1, "resume2").await;
            let mut viewer = rig.client().await;
            let (fwd, _) = rig.load(&mut viewer, 2, "resume2", json!({})).await;
            assert!(flagged(&fwd));
            let viewer_conn = conn_of(&fwd);
            a.cancel();
            rig.wait_for_clients(1).await;
            let mut c = rig.client().await;
            let (fwd, _) = rig.load(&mut c, 3, "resume2", json!({})).await;
            assert!(flagged(&fwd));
            let c_conn = conn_of(&fwd);
            rig.until("the first queued loader owns", || state_of(&rig, "resume2", viewer_conn) == OwnerState::SelfOwner).await;
            assert_eq!(state_of(&rig, "resume2", c_conn), OwnerState::Other);
            assert_eq!(rig.verdict(&viewer, "session/set_model", "resume2").await, "self");
            // And when the new owner goes, the next in line follows.
            viewer.cancel();
            rig.wait_for_clients(1).await;
            rig.until("the next claimant owns after the second window", || state_of(&rig, "resume2", c_conn) == OwnerState::SelfOwner).await;
            c.cancel();
            rig.stop();
        })
        .await;
}

/// A queued claimant that disconnects is skipped; an empty queue leaves the session to its next loader.
#[tokio::test]
async fn e2e_a_departed_claimant_is_skipped_and_with_no_claimant_the_next_loader_owns() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_SHORT).await;
            let mut a = rig.client().await;
            rig.new_session(&mut a, 1, "skip").await;
            let mut b = rig.client().await;
            rig.load(&mut b, 2, "skip", json!({})).await;
            let mut c = rig.client().await;
            let (fwd, _) = rig.load(&mut c, 3, "skip", json!({})).await;
            let c_conn = conn_of(&fwd);
            a.cancel();
            b.cancel();
            rig.wait_for_clients(1).await;
            rig.until("c owns", || state_of(&rig, "skip", c_conn) == OwnerState::SelfOwner).await;
            c.cancel();
            rig.wait_for_clients(0).await;
            rig.stop();

            let mut rig = Rig::start(GRACE_SHORT).await;
            let bystander = rig.client().await;
            let mut a = rig.client().await;
            rig.new_session(&mut a, 1, "empty").await;
            a.cancel();
            rig.wait_for_clients(1).await;
            rig.evicted("empty").await;
            rig.until("the window ended", || !rig.board.in_grace("empty")).await;
            let mut d = rig.client().await;
            let (fwd, reply) = rig.load(&mut d, 2, "empty", json!({})).await;
            assert!(!flagged(&fwd), "after the window, with nobody queued, the first loader owns");
            assert!(token_of(&reply).is_some());
            d.cancel();
            bystander.cancel();
            rig.stop();
        })
        .await;
}

/// The security rule: a connection that merely sends messages naming a session gains no authority, now or later.
#[tokio::test]
async fn e2e_naming_a_session_in_a_message_never_grants_authority() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_SHORT).await;
            let mut a = rig.client().await;
            rig.new_session(&mut a, 1, "target").await;
            let mut mallory = rig.client().await;
            let mut b = rig.client().await;
            // Mallory prompts the session, asks for its mode, cancels, and sends admin calls: all as a non-owner.
            for (i, method) in ["session/prompt", "session/cancel", "session/set_mode", "_fuigo/queue/edit", "_fuigo/interject"].iter().enumerate() {
                mallory.send(json!({ "jsonrpc": "2.0", "id": 100 + i, "method": method, "params": { "sessionId": "target", "modeId": "plan" } }).to_string()).unwrap();
                let fwd = rig.next().await;
                assert_eq!(fwd["method"], *method);
            }
            for m in ["session/set_mode", "session/set_model", "_fuigo/toggle_plan_mode", "_fuigo/session/rename", "session/close"] {
                assert_eq!(rig.verdict(&mallory, m, "target").await, "other", "{m}");
            }
            // The owner leaves and the window ends: Mallory never loaded, so it is not a claimant and owns nothing.
            a.cancel();
            rig.wait_for_clients(2).await;
            rig.until("the window ended", || !rig.board.in_grace("target")).await;
            assert_eq!(rig.verdict(&mallory, "session/set_mode", "target").await, "none", "nobody owns it; Mallory does not");
            assert_eq!(rig.verdict(&mallory, "session/set_model", "ghost").await, "none");
            // B loads after the window: the first LOADER owns, not the first talker.
            let (fwd, _) = rig.load(&mut b, 7, "target", json!({})).await;
            assert!(!flagged(&fwd));
            assert_eq!(rig.verdict(&mallory, "session/set_mode", "target").await, "other");
            assert_eq!(rig.verdict(&b, "session/set_mode", "target").await, "self");
            // The relay is no different: its messages do not claim, only its session/new answer and a free load do.
            let prompt = json!({ "jsonrpc": "2.0", "id": 2, "method": "session/prompt", "params": { "sessionId": "ghost" } }).to_string();
            stamp_relay_connection_identity_with(&prompt, &rig.board);
            assert_eq!(rig.board.owner_state("ghost", Claimer::Relay), OwnerState::Unowned);
            mallory.cancel();
            b.cancel();
            rig.stop();
        })
        .await;
}

// ---------------------------------------------------------------------------------------------------------------------
// The relay as an owner: lease, drop (H2b).
// ---------------------------------------------------------------------------------------------------------------------

fn relay_load(sid: &str, id: u64) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "method": "session/load", "params": { "sessionId": sid, "cwd": "/tmp", "mcpServers": [], "_meta": {} } }).to_string()
}

#[tokio::test]
async fn e2e_an_idle_relay_claim_lapses_after_the_lease_and_the_local_loader_owns() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            rig.board.set_relay_lease(Duration::from_millis(400));
            stamp_relay_connection_identity_with(&relay_load("relay-owned", 1), &rig.board);
            assert_eq!(rig.board.owner_state("relay-owned", Claimer::Relay), OwnerState::SelfOwner);
            // During the claim a local window's load is foreign, and queued.
            let mut w = rig.client().await;
            let (fwd, reply) = rig.load(&mut w, 2, "relay-owned", json!({ "yoloMode": true })).await;
            assert!(flagged(&fwd) && token_of(&reply).is_none());
            let w_conn = conn_of(&fwd);
            assert_eq!(rig.verdict(&w, "session/set_model", "relay-owned").await, "other");
            // A busy relay keeps its claim.
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_millis(200)).await;
                let prompt = json!({ "jsonrpc": "2.0", "id": 3, "method": "session/prompt", "params": { "sessionId": "relay-owned" } }).to_string();
                stamp_relay_connection_identity_with(&prompt, &rig.board);
                // A short turn: the agent answers it (an unanswered prompt means the relay is mid-turn, which never lapses).
                rig.response_tx.send(json!({ "jsonrpc": "2.0", "id": 3, "result": { "stopReason": "end_turn" } }).to_string()).unwrap();
            }
            assert_eq!(state_of(&rig, "relay-owned", w_conn), OwnerState::Other);
            // Idle past the lease: the queued local window owns, without reloading; the relay no longer does.
            rig.until("the lease lapsed", || state_of(&rig, "relay-owned", w_conn) == OwnerState::SelfOwner).await;
            assert_eq!(rig.verdict(&w, "session/set_model", "relay-owned").await, "self");
            let relay_set = json!({ "jsonrpc": "2.0", "id": 4, "method": "session/set_model", "params": { "sessionId": "relay-owned", "modelId": "m" } }).to_string();
            let out: Value = serde_json::from_str(&stamp_relay_connection_identity_with(&relay_set, &rig.board)).unwrap();
            assert_eq!(out["params"]["_meta"][LEADER_OWNER_STATE_KEY], "other");
            // A local load of a session whose relay claim lapsed (nobody queued) takes ownership.
            stamp_relay_connection_identity_with(&relay_load("relay-owned-2", 5), &rig.board);
            tokio::time::sleep(Duration::from_millis(600)).await;
            let mut x = rig.client().await;
            let (fwd, reply) = rig.load(&mut x, 6, "relay-owned-2", json!({})).await;
            assert!(!flagged(&fwd) && token_of(&reply).is_some(), "a lapsed relay claim does not block a local load");
            w.cancel();
            x.cancel();
            rig.stop();
        })
        .await;
}

#[tokio::test]
async fn e2e_all_relay_claims_drop_with_the_relay_connection() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            stamp_relay_connection_identity_with(&relay_load("r1", 1), &rig.board);
            stamp_relay_connection_identity_with(&relay_load("r2", 2), &rig.board);
            let mut w = rig.client().await;
            let (fwd, _) = rig.load(&mut w, 3, "r1", json!({})).await;
            assert!(flagged(&fwd));
            let w_conn = conn_of(&fwd);
            // r1 has a queued local claimant, r2 has none.
            rig.board.relay_dropped();
            rig.until("r1 handed to its claimant", || state_of(&rig, "r1", w_conn) == OwnerState::SelfOwner).await;
            assert_eq!(rig.board.owner_state("r1", Claimer::Relay), OwnerState::Other);
            assert_eq!(rig.board.owner_state("r2", Claimer::Relay), OwnerState::Unowned);
            let (fwd, reply) = rig.load(&mut w, 4, "r2", json!({})).await;
            assert!(!flagged(&fwd) && token_of(&reply).is_some(), "r2 is free for the next local load");
            assert_eq!(rig.verdict(&w, "session/set_model", "r2").await, "self");
            w.cancel();
            rig.stop();
        })
        .await;
}

// ---------------------------------------------------------------------------------------------------------------------
// L1: driver-only messages are held for the owner, not dropped.
// ---------------------------------------------------------------------------------------------------------------------

fn inject(sid: &str, n: u64) -> String {
    json!({ "jsonrpc": "2.0", "method": "fuigo/scheduled_task_inject_prompt", "params": { "sessionId": sid, "prompt": format!("tick {n}") } }).to_string()
}

fn reverse_request(sid: &str, id: &str) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "method": "fs/read_text_file", "params": { "sessionId": sid, "path": "/x" } }).to_string()
}

fn methods(msgs: &[Value]) -> Vec<String> {
    msgs.iter().filter_map(|m| m["method"].as_str().map(str::to_owned)).collect()
}

#[tokio::test]
async fn e2e_driver_only_messages_go_to_the_owner_and_are_held_during_grace() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            let mut a = rig.client().await;
            let (_, new_reply) = rig.new_session(&mut a, 1, "held").await;
            let token = token_of(&new_reply).unwrap();
            let mut b = rig.client().await;
            rig.load(&mut b, 2, "held", json!({})).await;
            // Owner first: only the owner gets a reverse request or a scheduled prompt (the viewer does not).
            rig.response_tx.send(reverse_request("held", "rr1")).unwrap();
            rig.response_tx.send(inject("held", 0)).unwrap();
            let got = Rig::drain_client(&mut a, Duration::from_millis(300)).await;
            assert_eq!(methods(&got), ["fs/read_text_file", "fuigo/scheduled_task_inject_prompt"], "{got:?}");
            assert!(Rig::drain_client(&mut b, Duration::from_millis(100)).await.is_empty());
            // The owner goes. During the window nobody receives them (the viewer is not the owner).
            a.cancel();
            rig.wait_for_clients(1).await;
            rig.response_tx.send(inject("held", 1)).unwrap();
            rig.response_tx.send(reverse_request("held", "rr2")).unwrap();
            assert!(Rig::drain_client(&mut b, Duration::from_millis(300)).await.is_empty(), "held, not handed to the viewer");
            // The owner's reconnect gets what was held, after its load response.
            let mut a2 = rig.client().await;
            let (fwd, _) = rig.load(&mut a2, 3, "held", json!({ LEADER_RECONNECT_TOKEN_KEY: token })).await;
            assert!(!flagged(&fwd));
            let got = Rig::drain_client(&mut a2, Duration::from_millis(400)).await;
            assert_eq!(methods(&got), ["fuigo/scheduled_task_inject_prompt", "fs/read_text_file"], "{got:?}");
            // Live again: straight to the new owner.
            rig.response_tx.send(inject("held", 2)).unwrap();
            assert_eq!(methods(&Rig::drain_client(&mut a2, Duration::from_millis(300)).await), ["fuigo/scheduled_task_inject_prompt"]);
            a2.cancel();
            b.cancel();
            rig.stop();
        })
        .await;
}

#[tokio::test]
async fn e2e_held_messages_reach_the_promoted_claimant_or_are_dropped_when_there_is_none() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_SHORT).await;
            let mut a = rig.client().await;
            rig.new_session(&mut a, 1, "promo").await;
            let mut b = rig.client().await;
            let (fwd, _) = rig.load(&mut b, 2, "promo", json!({})).await;
            let b_conn = conn_of(&fwd);
            a.cancel();
            rig.wait_for_clients(1).await;
            rig.response_tx.send(inject("promo", 1)).unwrap();
            assert!(Rig::drain_client(&mut b, Duration::from_millis(100)).await.is_empty());
            rig.until("b promoted", || state_of(&rig, "promo", b_conn) == OwnerState::SelfOwner).await;
            let got = Rig::drain_client(&mut b, Duration::from_millis(400)).await;
            // The new owner is handed its reconnect token first, then what was held for the owner; nothing else.
            assert_eq!(methods(&got), [LEADER_OWNER_TOKEN_METHOD, "fuigo/scheduled_task_inject_prompt"], "{got:?}");
            assert_eq!(got[0]["params"]["sessionId"], "promo");
            assert!(got[0]["params"]["_meta"][LEADER_RECONNECT_TOKEN_KEY].as_str().is_some_and(|t| t.len() == 32));
            b.cancel();
            rig.wait_for_clients(0).await;
            rig.stop();

            // No owner and no claimant after the window: the held messages are dropped (with a warning), not delivered to a
            // later, unrelated loader.
            let mut rig = Rig::start(GRACE_SHORT).await;
            let bystander = rig.client().await;
            let mut a = rig.client().await;
            rig.new_session(&mut a, 1, "none").await;
            a.cancel();
            rig.wait_for_clients(1).await;
            rig.evicted("none").await;
            rig.response_tx.send(inject("none", 1)).unwrap();
            rig.until("the window ended", || !rig.board.in_grace("none")).await;
            let mut c = rig.client().await;
            let (fwd, _) = rig.load(&mut c, 2, "none", json!({})).await;
            assert!(!flagged(&fwd));
            assert!(Rig::drain_client(&mut c, Duration::from_millis(300)).await.is_empty(), "stale prompts are not replayed to a new owner");
            c.cancel();
            bystander.cancel();
            rig.stop();
        })
        .await;
}

#[test]
fn held_driver_messages_are_bounded_and_drop_the_oldest() {
    let mut held = std::collections::HashMap::new();
    for n in 0..70 {
        crate::leader::server::hold_driver_message(&mut held, "s", std::sync::Arc::from(format!("m{n}")));
    }
    let queue = &held["s"];
    assert_eq!(queue.len(), 64);
    assert_eq!(&*queue[0], "m6", "the oldest were dropped");
    assert_eq!(&*queue[63], "m69");
}

// ---------------------------------------------------------------------------------------------------------------------
// L2 (leader side): a request pipelined behind a reconnect load is already the owner's.
// ---------------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn e2e_set_model_pipelined_behind_a_reconnect_load_carries_the_owners_verdict() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            let bystander = rig.client().await;
            let mut a = rig.client().await;
            let (_, new_reply) = rig.new_session(&mut a, 1, "pipe").await;
            let token = token_of(&new_reply).unwrap();
            a.cancel();
            rig.wait_for_clients(1).await;
            rig.evicted("pipe").await;
            let mut a2 = rig.client().await;
            // The load is on the wire to the agent, unanswered; the set_model right behind it is the owner's already.
            let load = rig.send_load(&a2, 5, "pipe", json!({ LEADER_RECONNECT_TOKEN_KEY: token })).await;
            assert!(!flagged(&load));
            assert_eq!(rig.verdict(&a2, "session/set_model", "pipe").await, "self");
            rig.response_tx.send(json!({ "jsonrpc": "2.0", "result": {}, "id": load["id"] }).to_string()).unwrap();
            assert!(token_of(&Rig::reply(&mut a2, 5).await).is_some());
            a2.cancel();
            bystander.cancel();
            rig.stop();
        })
        .await;
}

// ===================== AUDIT R2 (not part of RC) =====================
/// A promoted owner was never given a reconnect token, so after a brief disconnect it cannot take the session back
/// within the grace window; a claimant queued earlier wins.
#[tokio::test]
async fn audit_r2_promoted_owner_cannot_reclaim_after_disconnect() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_MED).await;
            let mut a = rig.client().await;
            rig.new_session(&mut a, 1, "p").await;
            let mut b = rig.client().await;
            let (fwd_b, _) = rig.load(&mut b, 2, "p", json!({})).await;
            let b_conn = conn_of(&fwd_b);
            let mut c = rig.client().await;
            let (fwd_c, _) = rig.load(&mut c, 3, "p", json!({})).await;
            let c_conn = conn_of(&fwd_c);
            a.cancel();
            rig.until("b promoted", || state_of(&rig, "p", b_conn) == OwnerState::SelfOwner).await;
            let got = Rig::drain_client(&mut b, Duration::from_millis(200)).await;
            // The promotion hands the new owner its token in a notification (the pager keeps it like a load's token).
            let notice = got
                .iter()
                .find(|m| m["method"] == LEADER_OWNER_TOKEN_METHOD)
                .unwrap_or_else(|| panic!("the promoted owner was never given a reconnect token: {got:?}"));
            assert_eq!(notice["params"]["sessionId"], "p");
            let b_token = notice["params"]["_meta"][LEADER_RECONNECT_TOKEN_KEY].as_str().expect("token").to_owned();
            // B blips: disconnects and immediately reconnects (within grace), reloading the session with its token.
            b.cancel();
            rig.until("b gone", || rig.board.in_grace("p")).await;
            let mut b2 = rig.client().await;
            let (fwd_b2, reply_b2) = rig.load(&mut b2, 4, "p", json!({ LEADER_RECONNECT_TOKEN_KEY: b_token })).await;
            assert!(!flagged(&fwd_b2), "a reclaiming load is not foreign");
            assert!(token_of(&reply_b2).is_some(), "the reclaim rotates the token");
            let b2_conn = conn_of(&fwd_b2);
            rig.until("grace ended", || !rig.board.in_grace("p")).await;
            eprintln!("AUDIT: after grace: c={:?} b2={:?}", state_of(&rig, "p", c_conn), state_of(&rig, "p", b2_conn));
            assert_eq!(state_of(&rig, "p", b2_conn), OwnerState::SelfOwner, "the promoted owner, reconnecting within grace, should get its session back");
            b2.cancel(); c.cancel(); rig.stop();
        })
        .await;
}

/// A local window that merely NAMED an unowned session (no load) keeps the routing; once the relay claims the session,
/// permission prompts (reverse requests) for the relay-owned session go to that local non-owner.
#[tokio::test]
async fn audit_r2_relay_owned_session_prompts_leak_to_a_local_non_owner() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            let mut c = rig.client().await;
            let (c_conn, _) = rig.new_session(&mut c, 1, "c-own").await;
            c.send(json!({ "jsonrpc": "2.0", "id": 5, "method": "_fuigo/session/info", "params": { "sessionId": "rs" } }).to_string()).unwrap();
            let fwd = rig.next().await;
            rig.response_tx.send(json!({ "jsonrpc": "2.0", "result": {}, "id": fwd["id"] }).to_string()).unwrap();
            let _ = Rig::reply(&mut c, 5).await;
            stamp_relay_connection_identity_with(&relay_load("rs", 77), &rig.board);
            assert_eq!(rig.board.owner_state("rs", Claimer::Relay), OwnerState::SelfOwner);
            assert_eq!(state_of(&rig, "rs", c_conn), OwnerState::Other);
            rig.response_tx.send(reverse_request("rs", "perm1")).unwrap();
            let got = Rig::drain_client(&mut c, Duration::from_millis(400)).await;
            eprintln!("AUDIT: non-owner c received {:?}", methods(&got));
            assert!(methods(&got).is_empty(), "a non-owner received a driver-only prompt of a relay-owned session: {got:?}");
            c.cancel(); rig.stop();
        })
        .await;
}

/// The owner-elect cold load fails after a concurrent foreign load succeeded: the foreign loader is left queued on an
/// unowned session and is never promoted, so its owner-only changes are refused until it reloads.
#[tokio::test]
async fn audit_r2_foreign_loader_stranded_when_the_owners_load_fails() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_SHORT).await;
            let a = rig.client().await;
            let fwd_a = rig.send_load(&a, 1, "f", json!({})).await;
            let mut b = rig.client().await;
            let fwd_b = rig.send_load(&b, 2, "f", json!({})).await;
            assert!(flagged(&fwd_b));
            let b_conn = conn_of(&fwd_b);
            rig.response_tx.send(json!({ "jsonrpc": "2.0", "result": {}, "id": fwd_b["id"] }).to_string()).unwrap();
            let _ = Rig::reply(&mut b, 2).await;
            rig.response_tx.send(json!({ "jsonrpc": "2.0", "error": { "code": -32603, "message": "boom" }, "id": fwd_a["id"] }).to_string()).unwrap();
            rig.until("a rolled back", || state_of(&rig, "f", b_conn) != OwnerState::Other).await;
            tokio::time::sleep(GRACE_SHORT * 3).await;
            let v = rig.verdict(&b, "session/set_mode", "f").await;
            eprintln!("AUDIT: b state={:?} pending={} set_mode verdict={v}", state_of(&rig, "f", b_conn), rig.board.has_pending("f"));
            assert_eq!(v, "self", "the only loader of the session cannot change its mode");
            a.cancel(); b.cancel(); rig.stop();
        })
        .await;
}

// ===================== AUDIT R2 (not part of RC) =====================
fn spawned(parent: &str, child: &str) -> String {
    json!({ "jsonrpc": "2.0", "method": "session/update", "params": { "sessionId": parent, "update": { "sessionUpdate": "subagent_spawned", "child_session_id": child } } }).to_string()
}
/// A grandchild (subagent of a subagent) permission prompt raised while the root owner is in its grace window must be
/// held for the owner like the child's, not dropped or handed to a non-owner.
#[tokio::test]
async fn audit_r2_grandchild_prompts_are_held_during_grace() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            let mut a = rig.client().await;
            let (_, new_reply) = rig.new_session(&mut a, 1, "par").await;
            let token = token_of(&new_reply).unwrap();
            let mut b = rig.client().await;
            rig.load(&mut b, 2, "par", json!({})).await;
            rig.response_tx.send(spawned("par", "kid")).unwrap();
            rig.response_tx.send(spawned("kid", "gkid")).unwrap();
            rig.response_tx.send(reverse_request("kid", "r1")).unwrap();
            rig.response_tx.send(reverse_request("gkid", "r2")).unwrap();
            let got = Rig::drain_client(&mut a, Duration::from_millis(400)).await;
            eprintln!("AUDIT live owner got ids {:?}", got.iter().filter_map(|m| m["id"].as_str()).collect::<Vec<_>>());
            let _ = Rig::drain_client(&mut b, Duration::from_millis(100)).await;
            a.cancel();
            rig.wait_for_clients(1).await;
            rig.response_tx.send(reverse_request("kid", "r3")).unwrap();
            rig.response_tx.send(reverse_request("gkid", "r4")).unwrap();
            let gb = Rig::drain_client(&mut b, Duration::from_millis(300)).await;
            eprintln!("AUDIT viewer b got during grace ids {:?}", gb.iter().filter_map(|m| m["id"].as_str()).collect::<Vec<_>>());
            let mut a2 = rig.client().await;
            rig.load(&mut a2, 3, "par", json!({ LEADER_RECONNECT_TOKEN_KEY: token })).await;
            let got = Rig::drain_client(&mut a2, Duration::from_millis(400)).await;
            let ids: Vec<_> = got.iter().filter_map(|m| m["id"].as_str().map(str::to_owned)).collect();
            eprintln!("AUDIT reclaimed owner got ids {ids:?}");
            assert!(ids.contains(&"r3".to_string()) && ids.contains(&"r4".to_string()), "held for the owner: {ids:?}");
            a2.cancel(); b.cancel(); rig.stop();
        })
        .await;
}

// ---------------------------------------------------------------------------------------------------------------------
// The relay's own path to the agent's requests (r6): a relay-owned session's driver-only requests reach the relay, never a
// local window, and never get lost when the relay's claim ends.
//
// How the relay is reached: `agent::app` copies EVERY line the agent writes to the relay's outbound channel
// (`agent_to_ws_tx`) before it hands the line to the leader server's IPC path. The relay therefore gets each request
// whatever the server decides about local windows; the server's `relay_owns` rule only keeps a local non-owner out.
// ---------------------------------------------------------------------------------------------------------------------

fn permission_request(sid: &str, id: &str) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "method": "session/request_permission",
        "params": { "sessionId": sid, "toolCall": { "toolCallId": format!("tc-{id}") }, "options": [] } }).to_string()
}

fn relay_answer(id: &str) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "result": { "content": "x" } }).to_string()
}

/// A local window that has the named session in its sights without owning it (what `audit_r2_*` sets up).
async fn bystander_naming(rig: &mut Rig, sid: &str) -> LeaderClient {
    let mut c = rig.client().await;
    c.send(json!({ "jsonrpc": "2.0", "id": 5, "method": "_fuigo/session/info", "params": { "sessionId": sid } }).to_string()).unwrap();
    let fwd = rig.next().await;
    rig.response_tx.send(json!({ "jsonrpc": "2.0", "result": {}, "id": fwd["id"] }).to_string()).unwrap();
    let _ = Rig::reply(&mut c, 5).await;
    c
}

/// Source pin: the relay is sent every agent line on its own path, before and independent of the server's routing, and the
/// relay's lines reach the agent through the leader's stamp. If either changes, the relay-owned rule is unsafe.
#[test]
fn the_relay_gets_every_agent_line_on_its_own_path() {
    let src = include_str!("../../app.rs");
    let flat = src.split_whitespace().collect::<Vec<_>>().join(" ");
    assert_eq!(flat.matches("agent_to_ipc_tx_clone.send(msg)").count(), 1, "one IPC hand-off");
    assert!(
        flat.contains(
            "let maybe_tx = agent_to_ws_tx_clone.lock(); if let Some(ref tx) = *maybe_tx { let _ = tx.send(msg.clone()); } \
             drop(maybe_tx); let _ = agent_to_ipc_tx_clone.send(msg);"
        ),
        "every agent line is copied to the relay (no session or method filter) before the IPC hand-off"
    );
    assert!(
        flat.contains("let msg = crate::leader::server::stamp_relay_connection_identity_with(&msg, &relay_driver_board);"),
        "the relay's lines reach the agent through the leader's stamp"
    );
}

#[test]
fn a_relay_answer_passes_the_stamp_untouched() {
    let board = OwnerBoard::default();
    let line = relay_answer("fs1");
    assert_eq!(stamp_relay_connection_identity_with(&line, &board), line);
}

/// The relay owns S (its socket idle inside the lease). The agent asks for a file read and a permission for S: neither goes
/// to a local window that merely named S as a driver-only message. The permission is a SHARED modal (broadcast to the
/// session's subscribers, first answer wins), unchanged by the relay rule. The relay's answer is a plain response.
#[tokio::test]
async fn e2e_relay_owned_session_requests_stay_off_a_local_non_owner() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            let mut c = bystander_naming(&mut rig, "rs").await;
            stamp_relay_connection_identity_with(&relay_load("rs", 77), &rig.board);
            assert!(rig.board.relay_owns("rs"));
            rig.response_tx.send(reverse_request("rs", "fs1")).unwrap();
            rig.response_tx.send(inject("rs", 1)).unwrap();
            rig.response_tx.send(permission_request("rs", "perm1")).unwrap();
            let got = Rig::drain_client(&mut c, Duration::from_millis(400)).await;
            assert_eq!(methods(&got), ["session/request_permission"], "only the shared modal reaches the window: {got:?}");
            // The relay answers the file read: the stamp lets the answer through to the agent unchanged.
            let answer = relay_answer("fs1");
            assert_eq!(stamp_relay_connection_identity_with(&answer, &rig.board), answer);
            c.cancel();
            rig.stop();
        })
        .await;
}

/// The relay owned S and dropped with requests unanswered; a local window queued behind it is promoted and gets exactly the
/// unanswered ones (after its token), then everything after that straight away.
#[tokio::test]
async fn e2e_relay_drop_hands_unanswered_requests_to_the_promoted_owner() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            stamp_relay_connection_identity_with(&relay_load("rs", 1), &rig.board);
            let mut w = rig.client().await;
            let (fwd, _) = rig.load(&mut w, 2, "rs", json!({})).await;
            assert!(flagged(&fwd));
            let w_conn = conn_of(&fwd);
            rig.response_tx.send(reverse_request("rs", "fs1")).unwrap();
            rig.response_tx.send(reverse_request("rs", "fs2")).unwrap();
            assert!(Rig::drain_client(&mut w, Duration::from_millis(300)).await.is_empty(), "the relay owns: nothing for the queued window");
            // The relay answers fs1 and then drops with fs2 still pending.
            stamp_relay_connection_identity_with(&relay_answer("fs1"), &rig.board);
            rig.board.relay_dropped();
            rig.until("w promoted", || state_of(&rig, "rs", w_conn) == OwnerState::SelfOwner).await;
            let got = Rig::drain_client(&mut w, Duration::from_millis(500)).await;
            assert_eq!(methods(&got), [LEADER_OWNER_TOKEN_METHOD, "fs/read_text_file"], "{got:?}");
            assert_eq!(got[1]["id"], "fs2", "only the unanswered request: {got:?}");
            rig.response_tx.send(reverse_request("rs", "fs3")).unwrap();
            let got = Rig::drain_client(&mut w, Duration::from_millis(300)).await;
            assert_eq!(got.iter().map(|m| m["id"].clone()).collect::<Vec<_>>(), [json!("fs3")], "{got:?}");
            w.cancel();
            rig.stop();
        })
        .await;
}

/// A request that arrives the moment the relay drops (before the server loop has acted on the drop) is the promoted
/// owner's, not dropped.
#[tokio::test]
async fn e2e_a_request_right_after_the_relay_drops_goes_to_the_promoted_owner() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            stamp_relay_connection_identity_with(&relay_load("rs", 1), &rig.board);
            let mut w = rig.client().await;
            let (fwd, _) = rig.load(&mut w, 2, "rs", json!({})).await;
            let w_conn = conn_of(&fwd);
            rig.board.relay_dropped();
            rig.response_tx.send(reverse_request("rs", "fs9")).unwrap();
            rig.until("w promoted", || state_of(&rig, "rs", w_conn) == OwnerState::SelfOwner).await;
            let got = Rig::drain_client(&mut w, Duration::from_millis(500)).await;
            let ids: Vec<Value> = got.iter().filter(|m| m["method"] == "fs/read_text_file").map(|m| m["id"].clone()).collect();
            assert_eq!(ids, [json!("fs9")], "delivered exactly once: {got:?}");
            w.cancel();
            rig.stop();
        })
        .await;
}

/// The relay's claim lapses by idle (the lease) while a local window is queued: requests inside the lease are the relay's
/// alone; the unanswered one and the next one go to the promoted window.
#[tokio::test]
async fn e2e_relay_lease_lapse_hands_unanswered_requests_to_the_promoted_owner() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            rig.board.set_relay_lease(Duration::from_millis(500));
            stamp_relay_connection_identity_with(&relay_load("rs", 1), &rig.board);
            let mut w = rig.client().await;
            let (fwd, _) = rig.load(&mut w, 2, "rs", json!({})).await;
            let w_conn = conn_of(&fwd);
            rig.response_tx.send(reverse_request("rs", "fs1")).unwrap();
            assert!(Rig::drain_client(&mut w, Duration::from_millis(100)).await.is_empty(), "inside the lease it is the relay's");
            rig.until("lease lapsed, w promoted", || state_of(&rig, "rs", w_conn) == OwnerState::SelfOwner).await;
            let got = Rig::drain_client(&mut w, Duration::from_millis(500)).await;
            assert_eq!(methods(&got), [LEADER_OWNER_TOKEN_METHOD, "fs/read_text_file"], "{got:?}");
            rig.response_tx.send(reverse_request("rs", "fs2")).unwrap();
            let got = Rig::drain_client(&mut w, Duration::from_millis(300)).await;
            assert_eq!(got.iter().map(|m| m["id"].clone()).collect::<Vec<_>>(), [json!("fs2")], "{got:?}");
            w.cancel();
            rig.stop();
        })
        .await;
}

/// The relay drops and nobody is queued: the unanswered requests go with it (no later, unrelated loader is handed them).
#[tokio::test]
async fn e2e_relay_drop_with_nobody_queued_does_not_replay_to_a_later_loader() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            stamp_relay_connection_identity_with(&relay_load("rs", 1), &rig.board);
            rig.response_tx.send(reverse_request("rs", "fs1")).unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            rig.board.relay_dropped();
            rig.until("vacated", || rig.board.owner_state("rs", Claimer::Relay) == OwnerState::Unowned).await;
            let mut w = rig.client().await;
            let (fwd, _) = rig.load(&mut w, 2, "rs", json!({})).await;
            assert!(!flagged(&fwd));
            assert!(Rig::drain_client(&mut w, Duration::from_millis(300)).await.is_empty());
            assert!(rig.board.take_relay_inflight("rs").is_empty());
            w.cancel();
            rig.stop();
        })
        .await;
}

// ---------------------------------------------------------------------------------------------------------------------
// r6: the relay's claim does not lapse while the relay is driving (a prompt in flight, or agent output for the session).
// ---------------------------------------------------------------------------------------------------------------------

fn relay_prompt(sid: &str, id: u64) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "method": "session/prompt", "params": { "sessionId": sid, "prompt": [{ "type": "text", "text": "go" }] } }).to_string()
}

fn session_update(sid: &str) -> String {
    json!({ "jsonrpc": "2.0", "method": "session/update", "params": { "sessionId": sid, "update": { "sessionUpdate": "agent_message_chunk", "content": { "type": "text", "text": "." } } } }).to_string()
}

/// A relay turn that outlasts the lease with the agent silent: the relay stays the owner and the queued local loader is not
/// promoted until the turn ends and a whole lease passes after it.
#[tokio::test]
async fn e2e_a_relay_turn_longer_than_the_lease_keeps_the_claim_until_it_ends() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            rig.board.set_relay_lease(Duration::from_millis(400));
            stamp_relay_connection_identity_with(&relay_load("rs", 1), &rig.board);
            let mut w = rig.client().await;
            let (fwd, _) = rig.load(&mut w, 2, "rs", json!({})).await;
            let w_conn = conn_of(&fwd);
            stamp_relay_connection_identity_with(&relay_prompt("rs", 10), &rig.board);
            // Three leases pass with the turn running and no relay message and no agent output.
            tokio::time::sleep(Duration::from_millis(1300)).await;
            assert_eq!(rig.board.owner_state("rs", Claimer::Relay), OwnerState::SelfOwner, "the relay is mid-turn");
            assert_eq!(state_of(&rig, "rs", w_conn), OwnerState::Other, "the queued window is not promoted mid-turn");
            // The turn ends; the lease counts from then.
            rig.response_tx.send(json!({ "jsonrpc": "2.0", "id": 10, "result": { "stopReason": "end_turn" } }).to_string()).unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            assert_eq!(state_of(&rig, "rs", w_conn), OwnerState::Other, "not before a lease has passed after the turn");
            rig.until("lapsed after the turn", || state_of(&rig, "rs", w_conn) == OwnerState::SelfOwner).await;
            w.cancel();
            rig.stop();
        })
        .await;
}

/// Agent output for the session is the relay's turn running: it refreshes the lease, and the claim lapses a lease after the
/// output stops.
#[tokio::test]
async fn e2e_agent_output_for_a_relay_owned_session_refreshes_the_lease() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            rig.board.set_relay_lease(Duration::from_millis(500));
            stamp_relay_connection_identity_with(&relay_load("rs", 1), &rig.board);
            let mut w = rig.client().await;
            let (fwd, _) = rig.load(&mut w, 2, "rs", json!({})).await;
            let w_conn = conn_of(&fwd);
            for _ in 0..8 {
                rig.response_tx.send(session_update("rs")).unwrap();
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            assert_eq!(state_of(&rig, "rs", w_conn), OwnerState::Other, "output kept the claim alive past the lease");
            let _ = Rig::drain_client(&mut w, Duration::from_millis(10)).await;
            rig.until("lapsed once the output stopped", || state_of(&rig, "rs", w_conn) == OwnerState::SelfOwner).await;
            w.cancel();
            rig.stop();
        })
        .await;
}

/// The socket dropping still ends the claim at once, prompt in flight or not.
#[tokio::test]
async fn e2e_a_relay_drop_ends_the_claim_even_with_a_prompt_in_flight() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            rig.board.set_relay_lease(Duration::from_millis(400));
            stamp_relay_connection_identity_with(&relay_load("rs", 1), &rig.board);
            let mut w = rig.client().await;
            let (fwd, _) = rig.load(&mut w, 2, "rs", json!({})).await;
            let w_conn = conn_of(&fwd);
            stamp_relay_connection_identity_with(&relay_prompt("rs", 10), &rig.board);
            rig.board.relay_dropped();
            rig.until("promoted at once", || state_of(&rig, "rs", w_conn) == OwnerState::SelfOwner).await;
            w.cancel();
            rig.stop();
        })
        .await;
}

/// AUDIT R3: the relay path is ahead of the server loop (app.rs sends each agent line to the relay first, then to IPC), so
/// the relay can answer a request before the server loop routes it. The answer is then forgotten (nothing held yet) and the
/// request is held anyway; when the claim ends it is handed to the promoted owner although it was already answered.
#[tokio::test]
async fn audit_r3_a_request_the_relay_answered_before_the_loop_saw_it_is_not_handed_over() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut rig = Rig::start(GRACE_LONG).await;
            stamp_relay_connection_identity_with(&relay_load("rs", 1), &rig.board);
            let mut w = rig.client().await;
            let (fwd, _) = rig.load(&mut w, 2, "rs", json!({})).await;
            assert!(flagged(&fwd));
            let w_conn = conn_of(&fwd);
            // The relay already answered fs1 (it got the line on its own path) ...
            stamp_relay_connection_identity_with(&relay_answer("fs1"), &rig.board);
            // ... then the server loop processes the same agent line.
            rig.response_tx.send(reverse_request("rs", "fs1")).unwrap();
            assert!(Rig::drain_client(&mut w, Duration::from_millis(300)).await.is_empty());
            rig.board.relay_dropped();
            rig.until("w promoted", || state_of(&rig, "rs", w_conn) == OwnerState::SelfOwner).await;
            let got = Rig::drain_client(&mut w, Duration::from_millis(500)).await;
            assert_eq!(methods(&got), [LEADER_OWNER_TOKEN_METHOD], "an answered request must not be handed over again: {got:?}");
            w.cancel();
            rig.stop();
        })
        .await;
}
