//! Packet 13: the ACP surface of peer messaging seen through the real `ext_method` of a minimal agent.

use agent_client_protocol as acp;

use super::p189_park_round3_tests::insert_session;
use super::{build_minimal_agent_for_tests, run_local_for_bridge_test};
use crate::session::peer_message::force_peer_messaging_for_test;

const METHODS: [&str; 4] = ["fuigo/peer/configure", "fuigo/peer/list", "fuigo/peer/list_held", "fuigo/peer/release"];

async fn call(agent: &crate::agent::mvp_agent::MvpAgent, method: &str, params: serde_json::Value) -> Result<acp::ExtResponse, acp::Error> {
    use acp::Agent as _;
    let raw = serde_json::value::to_raw_value(&params).unwrap();
    agent.ext_method(acp::ExtRequest::new(method.to_owned(), std::sync::Arc::from(raw))).await
}

fn params_for(method: &str, sid: &str) -> serde_json::Value {
    match method {
        "fuigo/peer/configure" => serde_json::json!({"sessionId": sid, "optIn": true, "operator": "attended"}),
        "fuigo/peer/release" => serde_json::json!({"sessionId": sid, "heldId": "m1", "token": "t"}),
        _ => serde_json::json!({"sessionId": sid}),
    }
}

fn reason(e: &acp::Error) -> String {
    e.data.as_ref().and_then(|d| d.get("reason")).and_then(|r| r.as_str()).unwrap_or("").to_owned()
}

/// Flag off: the capability object is exactly what it was (no `peerMessaging` key). Flag on: it is there with the contract shape.
#[test]
fn the_capability_is_absent_with_the_flag_off_and_the_rest_is_unchanged_with_it_on() {
    let off = {
        let _g = force_peer_messaging_for_test(false);
        super::super::acp_agent::fuigo_capabilities()
    };
    assert!(off.get("peerMessaging").is_none(), "{off}");
    let on = {
        let _g = force_peer_messaging_for_test(true);
        super::super::acp_agent::fuigo_capabilities()
    };
    let mut on_without = on.clone();
    let entry = on_without.as_object_mut().unwrap().remove("peerMessaging").expect("present with the flag on");
    assert_eq!(serde_json::to_string(&on_without).unwrap(), serde_json::to_string(&off).unwrap(), "the other entries are byte-identical");
    assert_eq!(entry["version"], 1);
    assert_eq!(entry["operatorKinds"], serde_json::json!(["attended", "may_return", "unattended"]));
    assert_eq!(entry["methods"].as_array().unwrap().len(), 4);
    assert!(entry["events"].as_array().unwrap().iter().any(|e| e == "peer_held"));
}

/// Flag off: each new method answers exactly like a method that never existed (same code and message shape).
#[test]
fn flag_off_the_methods_answer_like_any_unknown_method() {
    run_local_for_bridge_test(|| async {
        let _g = force_peer_messaging_for_test(false);
        let agent = build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("p13-off");
        let (_c, _s) = insert_session(&agent, &sid);
        for m in METHODS {
            let got = call(&agent, m, params_for(m, "p13-off")).await.expect_err("unknown");
            let control = call(&agent, &m.replace("peer", "peerzz"), params_for(m, "p13-off")).await.expect_err("unknown");
            assert_eq!(got.code, control.code, "{m}");
            assert_eq!(got.code, acp::Error::method_not_found().code, "{m}");
            assert_eq!(got.message.replace(m, "X"), control.message.replace(&m.replace("peer", "peerzz"), "X"), "{m}");
            assert!(got.data.as_ref().and_then(|d| d.get("reason")).is_none(), "{m}: no peer reason leaks");
        }
    });
}

/// S4.1: while a remote client is attached to the process every method answers `unavailable`, before anything else.
#[test]
fn a_remote_attached_leader_answers_unavailable_for_every_method() {
    run_local_for_bridge_test(|| async {
        let _g = force_peer_messaging_for_test(true);
        let agent = build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("p13-relay");
        let (_c, _s) = insert_session(&agent, &sid);
        let _attached = crate::peer_inbox::driver::attach_remote();
        for m in METHODS {
            let e = call(&agent, m, params_for(m, "p13-relay")).await.expect_err(m);
            assert_eq!(reason(&e), "unavailable", "{m}");
        }
    });
}

/// A session nobody opted in is not served (and an unknown session is an invalid-params error, not a peer error).
#[test]
fn a_session_that_was_not_opted_in_is_refused_and_an_unknown_one_is_invalid_params() {
    run_local_for_bridge_test(|| async {
        let _g = force_peer_messaging_for_test(true);
        let agent = build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("p13-closed");
        let (_c, _s) = insert_session(&agent, &sid);
        for m in ["fuigo/peer/list", "fuigo/peer/list_held", "fuigo/peer/release"] {
            let e = call(&agent, m, params_for(m, "p13-closed")).await.expect_err(m);
            assert_eq!(reason(&e), "not_opted_in", "{m}");
        }
        let e = call(&agent, "fuigo/peer/list", params_for("fuigo/peer/list", "no-such-session")).await.expect_err("unknown");
        assert_eq!(e.code, acp::Error::invalid_params().code);
    });
}
