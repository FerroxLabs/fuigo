//! A turn that fails with no HTTP status must still explain itself to a JSON client.
//! The model answers with nothing visible; with retries off the turn fails at once and `session/prompt` replies with an error.
//! That reply's `error.data` must be an object carrying `message` and `error_kind`: clients that read `data.error_kind` /
//! `data.http_status` (Murage) dropped the old bare-string `data` and showed only "Internal error".
//! The engine's log of that failure must stay one line per record: `acp::Error`'s `Display` pretty-prints an object `data`
//! across several lines, which splits the record for anything that reads the engine's stderr line by line.
#[allow(dead_code)]
mod acp_harness;

use std::sync::{Arc, Mutex};

use acp_harness::{AutoApproveClient, RPC_TIMEOUT, connect_and_auth, new_session, run_agent_test};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_test_support::scripted::ScriptedResponse;
use fuigo_test_support::sse::chat_completion_script_exact;
use fuigo_test_support::{InferenceEndpoint, InferenceRequestMatcher};

/// ERROR-level log capture for the whole test binary.
#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLogs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("log capture lock")
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
    type Writer = CapturedLogs;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl CapturedLogs {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("log capture lock")).into_owned()
    }
}

#[test]
fn a_status_less_terminal_failure_replies_with_typed_object_data() {
    // SAFETY: set before the harness starts any runtime; one #[test] per binary, so nothing reads env concurrently.
    // Zero retries: the sampler fails the empty response immediately instead of resampling it.
    unsafe {
        std::env::set_var("FUIGO_MAX_RETRIES", "0");
    }
    let logs = CapturedLogs::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::ERROR)
            .with_writer(logs.clone())
            .finish(),
    )
    .expect("nothing else installs a global subscriber in this test binary");
    let captured = logs.clone();
    run_agent_test(|cwd, mock| async move {
        // One chunk with empty content and `finish_reason: stop`: a completed stream with nothing visible
        let mut empty = mock.expect_response(
            "empty-answer",
            InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
            ScriptedResponse::sse(chat_completion_script_exact("", "test-model")),
        );

        let (conn, _) = connect_and_auth(AutoApproveClient, "terminal-error-data").await;
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
        empty.wait_satisfied().await;

        let error = match outcome {
            Err(error) => error,
            Ok(resp) => panic!(
                "an empty model response with retries off must fail the turn, got {:?}",
                resp.stop_reason
            ),
        };
        let wire = serde_json::to_value(&error).expect("serialize the JSON-RPC error");
        assert_eq!(wire["code"], -32603, "wire error: {wire}");
        let data = &wire["data"];
        assert!(
            data.is_object(),
            "error.data must be an object a JSON client can read, got: {wire}"
        );
        assert_eq!(data["error_kind"], "empty_response", "wire error: {wire}");
        let message = data["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("empty response from model"),
            "error.data.message must say what failed, got: {wire}"
        );
        assert!(
            data.get("http_status").is_none(),
            "no HTTP status was involved: {wire}"
        );

        // The failure is logged, and every line that names it is a whole ERROR record
        let logs = captured.text();
        let naming: Vec<&str> = logs
            .lines()
            .filter(|line| line.contains("empty response from model"))
            .collect();
        assert!(
            !naming.is_empty(),
            "the terminal failure must be logged at ERROR; captured:\n{logs}"
        );
        for line in naming {
            assert!(
                line.contains("ERROR"),
                "a log line naming the failure is a fragment of a multi-line record: {line:?}\ncaptured:\n{logs}"
            );
        }
    });
}
