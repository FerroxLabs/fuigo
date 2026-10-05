//! P15-R. Pins the `x-fuigo-*` split **on the wire**, at a loopback destination.
//!
//! P15 gated the whole namespace on `is_first_party_url` (since P30: `is_fluxrouter_operated_url`), a
//! compiled `https://api.fluxrouter.ai`
//! host check. Every integration harness in this workspace points the sampler at loopback
//! (`fuigo_test_support::leader`, `counting_server`), which that gate correctly refuses — so the
//! blanket refusal silently dropped the five per-session correlation headers the harness
//! correlates on, along with the three identity headers it was chartered to withhold.
//!
//! The split this test pins:
//!
//! * **correlation and routing** — `conv-id`, `req-id`, `session-id`, `turn-idx`,
//!   `transient-retry`, `model-override` — reach EVERY destination. Per-session randoms, per-turn
//!   counters, and (for `model-override`) a verbatim copy of the body's `model` field. None
//!   identifies anyone across two destinations.
//! * **identity** — `agent-id`, `deployment-id`, `user-id`, plus the client-level `client-version`
//!   and `client-identifier` — reach a FluxRouter-operated destination ONLY.
//!
//! A unit test (`client.rs::per_request_namespace_splits_by_disclosure`) covers the FluxRouter-operated
//! half, which no loopback server can stand in for. This binary covers the half that a real
//! socket can prove, and asserts the FULL set of `x-fuigo-*` names on the request, so a header
//! added to either half without a decision fails here rather than shipping.

mod support;

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::HeaderMap;
use axum::routing::post;
use fuigo_sampler::SamplingClient;
use fuigo_sampling_types::{ContentPart, ConversationItem, ConversationRequest, UserItem};
use tokio::net::TcpListener;

/// Reaches a loopback destination. Value asserted, not just presence: a header written with the
/// wrong value correlates nothing and is as broken as a missing one.
const EXPECTED_AT_LOOPBACK: [(&str, &str); 6] = [
    ("x-fuigo-conv-id", "conv-7f3a"),
    ("x-fuigo-req-id", "req-91c2"),
    ("x-fuigo-session-id", "sess-4d0e"),
    ("x-fuigo-turn-idx", "3"),
    ("x-fuigo-transient-retry", "2"),
    ("x-fuigo-model-override", "test-model"),
];

/// Must NOT reach a loopback destination. Three per-request, two client-level.
const WITHHELD_AT_LOOPBACK: [&str; 5] = [
    "x-fuigo-agent-id",
    "x-fuigo-deployment-id",
    "x-fuigo-user-id",
    "x-fuigo-client-version",
    "x-fuigo-client-identifier",
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_loopback_destination_gets_the_correlation_headers_and_none_of_the_identity_headers() {
    let captured: Arc<Mutex<Option<HeaderMap>>> = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&captured);
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |headers: HeaderMap| {
            let sink = Arc::clone(&sink);
            async move {
                *sink.lock().unwrap() = Some(headers);
                "{}"
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // Loopback is what every integration harness in this workspace uses, and it is deliberately
    // NOT FluxRouter-operated: `is_fluxrouter_operated_url` refuses it by host and by scheme both.
    let base_url = format!("http://{addr}/v1");
    assert!(
        !fuigo_extra_ca::fluxrouter::is_fluxrouter_operated_url(&base_url),
        "{base_url} must not be FluxRouter-operated, or this test proves nothing about the gate"
    );

    let mut cfg = support::test_config(&base_url, "test-key");
    // A managed deployment's identity: the values P15 exists to keep off a third-party wire.
    cfg.client_version = Some("1.0.21".to_string());
    cfg.client_identifier = Some("fuigo-cli".to_string());
    cfg.deployment_id = Some("dep-uuid-v5".to_string());
    cfg.user_id = Some("ferrox-account-id".to_string());

    let client = SamplingClient::new(cfg).expect("client builds");
    let request = ConversationRequest {
        items: vec![ConversationItem::User(UserItem {
            content: vec![ContentPart::Text {
                text: Arc::<str>::from("hi"),
            }],
            ..Default::default()
        })],
        x_fuigo_conv_id: Some("conv-7f3a".to_string()),
        x_fuigo_req_id: Some("req-91c2".to_string()),
        x_fuigo_session_id: Some("sess-4d0e".to_string()),
        x_fuigo_turn_idx: Some("3".to_string()),
        x_fuigo_transient_retry: Some("2".to_string()),
        x_fuigo_agent_id: Some("stable-machine-id".to_string()),
        x_fuigo_deployment_id: Some("dep-uuid-v5".to_string()),
        x_fuigo_user_id: Some("ferrox-account-id".to_string()),
        ..Default::default()
    };
    // `{}` is not a valid completion; only the outgoing request matters here.
    let _ = client.conversation(request).await;

    let headers = captured.lock().unwrap().take().expect("request captured");
    let seen: Vec<String> = headers
        .keys()
        .map(|k| k.as_str().to_string())
        .filter(|k| k.starts_with("x-fuigo-"))
        .collect();

    for (name, expected) in EXPECTED_AT_LOOPBACK {
        assert_eq!(
            headers.get(name).and_then(|v| v.to_str().ok()),
            Some(expected),
            "a loopback destination lost {name}; x-fuigo-* seen: {seen:?}"
        );
    }
    for name in WITHHELD_AT_LOOPBACK {
        assert!(
            !headers.contains_key(name),
            "a loopback destination received the identity header {name}; \
             x-fuigo-* seen: {seen:?}"
        );
    }

    // Exhaustive. A new `x-fuigo-*` header has to be classified, not just added: if it lands in
    // neither list this fails and names it.
    let mut unclassified: Vec<&str> = seen
        .iter()
        .map(String::as_str)
        .filter(|name| !EXPECTED_AT_LOOPBACK.iter().any(|(k, _)| k == name))
        .collect();
    unclassified.sort_unstable();
    assert!(
        unclassified.is_empty(),
        "unclassified x-fuigo-* header(s) reached a destination that is not FluxRouter-operated: \
         {unclassified:?}. Put each in the ungated half (correlation/routing: no identity, \
         needed everywhere) or the gated half (identity), in `client.rs`, and list it here."
    );
}
