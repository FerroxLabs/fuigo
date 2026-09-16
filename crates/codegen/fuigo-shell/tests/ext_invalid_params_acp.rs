//! Malformed or unknown extension requests must not reply with `error.data` a client cannot read.
//!
//! The typed-data guard only sees a literal `.data(..)` call. It cannot see the schema crate's
//! implicit conversions — `impl From<serde_json::Error> for acp::Error` is
//! `Error::invalid_params().data(error.to_string())` — which fire on every `?` inside a handler
//! that returns `Result<_, acp::Error>`. Those replies went out as `data: "invalid type: ..."`,
//! exactly the shape an embedding client drops, leaving the user with "-32602" and nothing else.
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{AutoApproveClient, RPC_TIMEOUT, connect_and_auth, new_session, run_agent_test};
use agent_client_protocol::{self as acp, Agent as _};

/// The JSON-RPC error `method` replies with, serialized exactly as it goes on the wire.
async fn ext_error(
    conn: &acp::ClientSideConnection,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let raw = serde_json::value::to_raw_value(&params).expect("serialize ext params");
    let outcome = tokio::time::timeout(
        RPC_TIMEOUT,
        conn.ext_method(acp::ExtRequest::new(method, raw.into())),
    )
    .await
    .unwrap_or_else(|_| panic!("{method} timed out"));
    match outcome {
        Err(error) => serde_json::to_value(&error).expect("serialize the JSON-RPC error"),
        Ok(resp) => panic!("{method} accepted malformed params: {}", resp.0.get()),
    }
}

/// Every reply's `data` must be an object with a readable `message` and a stable `error_kind`.
fn assert_typed_data(method: &str, wire: &serde_json::Value) {
    let data = &wire["data"];
    assert!(
        data.is_object(),
        "{method}: `error.data` must be an object a JSON client can read, got {wire}"
    );
    assert!(
        data["message"].as_str().is_some_and(|m| !m.is_empty()),
        "{method}: `error.data.message` must say what failed, got {wire}"
    );
    assert!(
        data["error_kind"].as_str().is_some_and(|k| !k.is_empty()),
        "{method}: `error.data.error_kind` must be set, got {wire}"
    );
}

#[test]
fn malformed_ext_params_reply_with_typed_object_data() {
    run_agent_test(|cwd, _mock| async move {
        let (conn, _) = connect_and_auth(AutoApproveClient, "ext-invalid-params").await;
        let _session = new_session(&conn, &cwd).await;

        // Params that are not even an object: every struct-shaped request rejects this the same way,
        // so the assertion does not depend on any one request's field names.
        let malformed = serde_json::json!(5);

        // A `fuigo/git/worktree/*` method: 14 of these `?` sites live in one file.
        let worktree = ext_error(&conn, "fuigo/git/worktree/show", malformed.clone()).await;
        assert_typed_data("fuigo/git/worktree/show", &worktree);

        // Two handlers reached without a workspace, so the -32602 parse path is pinned directly.
        for method in ["fuigo/session_summaries/session_list", "fuigo/skills/list"] {
            let wire = ext_error(&conn, method, malformed.clone()).await;
            assert_eq!(wire["code"], -32602, "{method}: {wire}");
            assert_typed_data(method, &wire);
            assert_eq!(
                wire["data"]["error_kind"], "invalid_request",
                "{method}: {wire}"
            );
        }
    });
}

/// A `fuigo/*` method this build does not implement is the first error class a client hits on version
/// skew, and every namespace router answered it with a bare `acp::Error::method_not_found()` — `data: null`.
/// A client following the agent-mode guide ("never show `message` on its own"; `message` and `error_kind`
/// are present "always") then shows the user a blank. The reply must be typed like every other error.
#[test]
fn unknown_ext_methods_reply_with_typed_object_data() {
    run_agent_test(|cwd, _mock| async move {
        let (conn, _) = connect_and_auth(AutoApproveClient, "ext-unknown-method").await;
        let _session = new_session(&conn, &cwd).await;

        for method in [
            // A namespace this build serves, with a member it does not
            "fuigo/skills/definitely_not_a_method",
            "fuigo/session_summaries/definitely_not_a_method",
            // A namespace that does not exist at all
            "fuigo/not_a_namespace/at_all",
        ] {
            let wire = ext_error(&conn, method, serde_json::json!({})).await;
            assert_eq!(wire["code"], -32601, "{method}: {wire}");
            assert_typed_data(method, &wire);
            assert_eq!(
                wire["data"]["error_kind"], "invalid_request",
                "{method}: {wire}"
            );
            // The client sent `_<method>` (the protocol crate adds the extension prefix and strips it
            // again on the agent side). A client author matching our message against their own request
            // string must find it verbatim, so the reply echoes the `_`-prefixed spelling.
            assert!(
                wire["data"]["message"]
                    .as_str()
                    .is_some_and(|m| m.contains(&format!("_{method}"))),
                "{method}: the message must name the method as the client sent it (`_{method}`), got {wire}"
            );
        }
    });
}
