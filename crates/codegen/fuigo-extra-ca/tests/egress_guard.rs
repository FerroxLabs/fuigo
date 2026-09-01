//! The egress guard, exercised through a real client built by the real
//! chokepoint — not through the predicate alone.
//!
//! `is_blocked_host` having correct unit tests proves nothing about whether the
//! resolver is actually INSTALLED on the clients we ship. That wiring is the
//! part that silently regresses (someone adds a `.dns_resolver()` inside a
//! `configure` closure, or a new builder skips the helper), so it is asserted
//! here against an outbound request.
//!
//! No network is required: a blocked host fails at name resolution, before any
//! socket is opened.

use std::time::Duration;

/// A request to an upstream vendor host must fail, and must fail for OUR
/// reason. Asserting only `is_err()` would pass just as happily if the machine
//  were offline, which would make this test worthless in CI.
#[tokio::test]
async fn blocked_host_is_refused_by_the_guard() {
    let client = fuigo_extra_ca::build_reqwest_client(|b| b.timeout(Duration::from_secs(5)))
        .expect("client builds");

    let err = client
        .get("https://api.x.ai/v1/models")
        .send()
        .await
        .expect_err("request to api.x.ai must not succeed");

    let rendered = format!("{err:?}");
    assert!(
        rendered.contains("refuses to contact upstream vendor host"),
        "expected the egress guard's refusal, got: {rendered}"
    );
}

/// Same for the blocking client, which is a separate builder and so a separate
/// chance to forget the resolver. The boot-time settings prefetch uses this one.
#[test]
fn blocked_host_is_refused_on_the_blocking_client() {
    let client =
        fuigo_extra_ca::build_blocking_reqwest_client(|b| b.timeout(Duration::from_secs(5)))
            .expect("client builds");

    let err = client
        .get("https://cli-chat-proxy.grok.com/v1/settings")
        .send()
        .expect_err("request to cli-chat-proxy.grok.com must not succeed");

    let rendered = format!("{err:?}");
    assert!(
        rendered.contains("refuses to contact upstream vendor host"),
        "expected the egress guard's refusal, got: {rendered}"
    );
}
