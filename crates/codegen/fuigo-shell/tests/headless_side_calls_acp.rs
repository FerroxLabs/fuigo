//! Non-interactive sessions (`fuigo -p`, SDK) must not pay for dashboard-only side calls.
//! One real agent over ACP with the turn summary explicitly enabled, so only the non-interactive gate can suppress them.
//! The non-interactive session completes three turns without a turn-summary, title-refresh or model first-prompt title request.
//! An interactive session on the same agent still issues all three.
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{AutoApproveClient, RPC_TIMEOUT, connect_and_auth, prompt_turn, run_agent_test};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_test_support::mock_server::LogEntry;
use serde_json::json;
use std::time::{Duration, Instant};

const INFERENCE_PATHS: [&str; 3] = ["/v1/chat/completions", "/v1/responses", "/v1/messages"];

async fn open_session(
    conn: &acp::ClientSideConnection,
    cwd: &std::path::Path,
    non_interactive: bool,
) -> acp::SessionId {
    tokio::time::timeout(
        RPC_TIMEOUT,
        conn.new_session(
            acp::NewSessionRequest::new(cwd.to_path_buf()).meta(
                json!({
                    "modelId": "test-model",
                    "startupHints": {
                        "nonInteractive": non_interactive,
                        "skipGitStatus": true,
                        "skipProjectLayout": true,
                    },
                })
                .as_object()
                .cloned(),
            ),
        ),
    )
    .await
    .expect("session/new timed out")
    .expect("session/new failed")
    .session_id
}

fn inference_for<'a>(requests: &'a [LogEntry], session: &acp::SessionId) -> Vec<&'a LogEntry> {
    requests
        .iter()
        .filter(|r| INFERENCE_PATHS.contains(&r.path.as_str()))
        .filter(|r| r.header("x-fuigo-session-id") == Some(&*session.0))
        .collect()
}

fn req_id(request: &LogEntry) -> &str {
    request.header("x-fuigo-req-id").unwrap_or_default()
}

/// The first-prompt title request forces its `session_title` function (Chat Completions or Responses shape).
fn is_model_title(request: &LogEntry) -> bool {
    request
        .body
        .as_ref()
        .and_then(|body| body["tools"].as_array())
        .is_some_and(|tools| {
            tools
                .iter()
                .any(|t| t["function"]["name"] == "session_title" || t["name"] == "session_title")
        })
}

#[test]
fn non_interactive_sessions_skip_dashboard_side_calls() {
    run_agent_test(|cwd, mock| async move {
        // run_agent_test pins the turn summary off; turn it back on before the agent resolves config (title refresh follows it)
        // SAFETY: the only other live threads are the mock's HTTP workers, which never read env.
        unsafe { std::env::set_var("FUIGO_TURN_SUMMARY", "true") };
        let (conn, _) = connect_and_auth(AutoApproveClient, "headless-side-calls").await;
        let headless = open_session(&conn, &cwd, true).await;
        let interactive = open_session(&conn, &cwd, false).await;
        // Three real user turns reach the first title-refresh checkpoint.
        for session in [&headless, &interactive] {
            for round in 0..3 {
                prompt_turn(
                    &conn,
                    session,
                    &format!("Round {round}: reply DONE without using tools."),
                )
                .await;
            }
        }

        // Positive control: the interactive session's calls arrive.
        // The headless session finished its turns first, so a regression there had longer to show up.
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let requests = mock.requests();
            let interactive_requests = inference_for(&requests, &interactive);
            let seen = |prefix: &str| interactive_requests.iter().any(|r| req_id(r).starts_with(prefix));
            if seen("fuigo-turn-summary-")
                && seen("fuigo-title-refresh-")
                && interactive_requests.iter().any(|r| is_model_title(r))
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "interactive session did not issue its dashboard side calls: {:?}",
                interactive_requests
                    .iter()
                    .map(|r| (req_id(r).to_owned(), is_model_title(r)))
                    .collect::<Vec<_>>()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // Grace for a late headless call a regression would spawn at its last completion.
        tokio::time::sleep(Duration::from_millis(500)).await;

        let requests = mock.requests();
        let headless_requests = inference_for(&requests, &headless);
        assert!(
            headless_requests.len() >= 3,
            "headless turns must still reach the model, saw {}",
            headless_requests.len()
        );
        // Report every violation at once, so a regression shows each dashboard call it re-enabled
        let violations: Vec<String> = headless_requests
            .iter()
            .filter_map(|request| {
                let id = req_id(request);
                if id.starts_with("fuigo-turn-summary-") {
                    Some(format!("turn summary ({id})"))
                } else if id.starts_with("fuigo-title-refresh-") {
                    Some(format!("title refresh ({id})"))
                } else if is_model_title(request) {
                    Some(format!("model first-prompt title ({id})"))
                } else if request.header("x-fuigo-turn-idx").is_none() {
                    Some(format!("unexpected side call ({id})"))
                } else {
                    None
                }
            })
            .collect();
        assert!(
            violations.is_empty(),
            "non-interactive session issued dashboard side calls: {violations:?}"
        );
    });
}
