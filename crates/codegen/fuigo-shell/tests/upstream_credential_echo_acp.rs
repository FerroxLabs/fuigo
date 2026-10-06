//! P70b regression: an upstream that echoes the API key back in its error text must not get that key shown to the
//! ACP client, neither in the `session/prompt` error reply nor in any notification of the failed turn.
//!
//! The agent is the real `MvpAgent`, wired the way the production transports wire it, behind a real `SamplingClient`
//! talking to a mock provider. The key is the one the harness exports as `FUIGO_API_KEY`, so it is what the sampler
//! actually puts on the wire. The mock rejects the request with a 400 whose message quotes that key (OpenAI's
//! "Incorrect API key provided: <key>" shape, which some gateways return verbatim).
//!
//! The text is still classified as it arrived: the scrub happens at the display sinks only.
#[allow(dead_code)]
mod acp_harness;

use std::cell::RefCell;
use std::rc::Rc;

use acp_harness::{RPC_TIMEOUT, allow_once, connect_and_auth, new_session, run_agent_test};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_test_support::scripted::ScriptedResponse;
use fuigo_test_support::{InferenceEndpoint, InferenceRequestMatcher};

/// What `acp_harness::run_agent_test` exports as `FUIGO_API_KEY`.
const SENT_KEY: &str = "test-key-for-ci";

/// Records every notification the agent sends, as wire JSON.
#[derive(Clone, Default)]
struct RecordingClient(Rc<RefCell<Vec<String>>>);

#[async_trait::async_trait(?Send)]
impl acp::Client for RecordingClient {
    async fn request_permission(
        &self,
        args: acp::RequestPermissionRequest,
    ) -> acp::Result<acp::RequestPermissionResponse> {
        Ok(acp::RequestPermissionResponse::new(allow_once(&args)))
    }

    async fn session_notification(&self, args: acp::SessionNotification) -> acp::Result<()> {
        self.0
            .borrow_mut()
            .push(serde_json::to_string(&args).expect("serialize notification"));
        Ok(())
    }

    async fn ext_notification(&self, args: acp::ExtNotification) -> acp::Result<()> {
        self.0
            .borrow_mut()
            .push(format!("{} {}", args.method, args.params.get()));
        Ok(())
    }
}

#[test]
fn an_api_key_echoed_by_the_upstream_is_not_shown_to_the_client() {
    // SAFETY: set before the harness starts any runtime; one #[test] per binary, so nothing reads env concurrently.
    unsafe {
        std::env::set_var("FUIGO_MAX_RETRIES", "0");
    }
    run_agent_test(|cwd, mock| async move {
        let body = serde_json::json!({
            "error": {
                "message": format!(
                    "Incorrect API key provided: {SENT_KEY}. You can find your API key at https://example.invalid/account."
                ),
                "type": "invalid_request_error",
                "code": "invalid_api_key",
            }
        });
        let mut rejected = mock.expect_response(
            "echoes-the-key",
            InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
            ScriptedResponse::json(400, body),
        );

        let client = RecordingClient::default();
        let seen = client.0.clone();
        let (conn, _) = connect_and_auth(client, "p70b-credential-echo").await;
        let session = new_session(&conn, &cwd).await;
        let outcome = tokio::time::timeout(
            RPC_TIMEOUT,
            conn.prompt(acp::PromptRequest::new(
                session.clone(),
                vec![acp::ContentBlock::Text(acp::TextContent::new(
                    "Say hello in one word.".to_owned(),
                ))],
            )),
        )
        .await
        .expect("prompt timed out");
        rejected.wait_satisfied().await;
        // Let notifications sent just before the reply drain.
        tokio::task::yield_now().await;

        let error = match outcome {
            Err(error) => error,
            Ok(resp) => panic!(
                "a 400 with retries off must fail the turn, got {:?}",
                resp.stop_reason
            ),
        };
        let wire = serde_json::to_string(&error).expect("serialize the JSON-RPC error");
        assert!(
            !wire.contains(SENT_KEY),
            "the error reply shows the API key the upstream echoed: {wire}"
        );
        assert!(
            wire.contains("Incorrect API key provided: <redacted>."),
            "the rest of the upstream text is kept, with the key replaced: {wire}"
        );

        let seen = seen.borrow().join("\n");
        assert!(
            !seen.contains(SENT_KEY),
            "a notification of the failed turn shows the API key the upstream echoed:\n{seen}"
        );
        // The failure is still reported on the notification rails (retry state, turn completion), scrubbed.
        assert!(
            seen.contains("Incorrect API key provided: <redacted>."),
            "the failed turn's notifications carry the scrubbed upstream text:\n{seen}"
        );
    });
}
