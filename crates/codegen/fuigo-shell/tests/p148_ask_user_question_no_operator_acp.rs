//! P148 item 1 (e2e C1, B19): an app that embeds Fuigo non-interactively over ACP (`startupHints.nonInteractive`)
//! and opts in to `ask_user_question` (`session/new` `_meta.askUserQuestion: true`, the only way such a session is
//! offered the tool) gets the standard "no operator" tool result:
//! - within 30 seconds when it takes the `fuigo/ask_user_question` request and never answers (a silent embedder);
//! - at once when it does not implement the method (`-32601`, a missing embedder).
//! The same holds when such an app loads a session an interactive client started. The turn then continues. C1 drove
//! an interactive session (no `nonInteractive`; `authenticate`'s `headless` only
//! selects a browserless sign-in) and so saw the interactive 30-minute wait.
#![cfg(unix)]

#[allow(dead_code)]
mod acp_harness;

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use acp_harness::{connect_client, run_agent_test, spawn_agent_local_with_config};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_test_support::sse::{
    chat_completion_script_exact, chat_completions_reasoning_then_tool_call_events,
};
use fuigo_test_support::{InferenceEndpoint, InferenceRequestMatcher, ScriptedResponse};
use serde_json::{Value, json};

const NO_OPERATOR: &str = "No user is available to answer questions in this non-interactive session.";

/// The embedder: silent for the questions of `silent_sessions`, method-not-found for every other one.
#[derive(Clone, Default)]
struct Embedder {
    silent_sessions: Rc<RefCell<Vec<String>>>,
    asked: Rc<RefCell<Vec<String>>>,
}

#[async_trait::async_trait(?Send)]
impl acp::Client for Embedder {
    async fn request_permission(
        &self,
        args: acp::RequestPermissionRequest,
    ) -> acp::Result<acp::RequestPermissionResponse> {
        Ok(acp::RequestPermissionResponse::new(acp_harness::allow_once(&args)))
    }
    async fn session_notification(&self, _: acp::SessionNotification) -> acp::Result<()> {
        Ok(())
    }
    async fn ext_method(&self, args: acp::ExtRequest) -> acp::Result<acp::ExtResponse> {
        let params: Value = serde_json::from_str(args.params.get()).unwrap_or_default();
        if args.method.as_ref() == "fuigo/ask_user_question" {
            let sid = params["sessionId"].as_str().unwrap_or_default().to_owned();
            self.asked.borrow_mut().push(sid.clone());
            if self.silent_sessions.borrow().contains(&sid) {
                // A silent embedder: takes the request, never answers.
                futures::future::pending::<()>().await;
            }
        }
        Err(acp::Error::method_not_found())
    }
}

fn ask_call(call_id: &str) -> ScriptedResponse {
    let args = json!({"questions": [{
        "question": "Which option?",
        "header": "pick",
        "options": [{"label": "A", "description": "a"}, {"label": "B", "description": "b"}],
        "multi_select": false
    }]});
    ScriptedResponse::sse(chat_completions_reasoning_then_tool_call_events(
        "ask",
        call_id,
        "ask_user_question",
        &args.to_string(),
        "test-model",
    ))
}

/// Whether some request the mock received carries the no-operator text as `call_id`'s tool result.
fn no_operator_result_for(mock: &fuigo_test_support::MockInferenceServer, call_id: &str) -> bool {
    mock.request_bodies().iter().any(|body| {
        body["messages"].as_array().is_some_and(|messages| {
            messages.iter().any(|m| {
                m["role"] == "tool"
                    && m["tool_call_id"] == call_id
                    && m["content"].to_string().contains(NO_OPERATOR)
            })
        })
    })
}

async fn session_asking(conn: &acp::ClientSideConnection, cwd: &std::path::Path) -> acp::SessionId {
    tokio::time::timeout(
        acp_harness::RPC_TIMEOUT,
        conn.new_session(
            acp::NewSessionRequest::new(cwd.to_path_buf())
                .meta(json!({ "modelId": "test-model", "askUserQuestion": true }).as_object().cloned()),
        ),
    )
    .await
    .expect("session/new timed out")
    .expect("session/new failed")
    .session_id
}

async fn timed_prompt(conn: &acp::ClientSideConnection, session: &acp::SessionId) -> Duration {
    let started = Instant::now();
    let response = tokio::time::timeout(
        Duration::from_secs(90),
        conn.prompt(acp::PromptRequest::new(
            session.clone(),
            vec![acp::ContentBlock::Text(acp::TextContent::new("Ask me."))],
        )),
    )
    .await
    .expect("prompt outlived the 30 s no-operator bound by a wide margin")
    .unwrap_or_else(|e| panic!("prompt failed: {e:?}"));
    assert_eq!(response.stop_reason, acp::StopReason::EndTurn);
    started.elapsed()
}

#[test]
fn a_non_interactive_embedder_that_is_silent_or_missing_gets_the_no_operator_reply() {
    run_agent_test(|cwd, mock| async move {
        let mut config = fuigo_shell::agent::config::Config::default();
        config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
        let embedder = Embedder::default();
        let (conn, _) = connect_client(
            embedder.clone(),
            "p148-ask-user-question",
            spawn_agent_local_with_config(config),
        )
        .await;
        let fg = || InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions);
        let text = |t: &str| ScriptedResponse::sse(chat_completion_script_exact(t, "test-model"));

        // Silent embedder.
        let silent = session_asking(&conn, &cwd).await;
        embedder.silent_sessions.borrow_mut().push(silent.0.to_string());
        let steps = [
            mock.expect_response("silent-ask", fg(), ask_call("call_silent")),
            mock.expect_response("silent-done", fg(), text("silent done")),
        ];
        let silent_elapsed = timed_prompt(&conn, &silent).await;
        for step in &steps {
            step.assert_satisfied();
        }
        assert!(
            embedder.asked.borrow().contains(&silent.0.to_string()),
            "the question must reach the embedder"
        );
        assert!(
            no_operator_result_for(&mock, "call_silent"),
            "a silent embedder must get the no-operator tool result\n{}",
            mock.request_log_summary()
        );
        assert!(
            silent_elapsed >= Duration::from_secs(25) && silent_elapsed <= Duration::from_secs(45),
            "a silent embedder waits about 30 s (B19), took {silent_elapsed:?}"
        );

        // Missing embedder: no handler for the method.
        let missing = session_asking(&conn, &cwd).await;
        let steps = [
            mock.expect_response("missing-ask", fg(), ask_call("call_missing")),
            mock.expect_response("missing-done", fg(), text("missing done")),
        ];
        let missing_elapsed = timed_prompt(&conn, &missing).await;
        for step in &steps {
            step.assert_satisfied();
        }
        assert!(
            embedder.asked.borrow().contains(&missing.0.to_string()),
            "the question must reach the embedder"
        );
        assert!(
            no_operator_result_for(&mock, "call_missing"),
            "an embedder without the method must get the no-operator tool result, not a tool error\n{}",
            mock.request_log_summary()
        );
        assert!(
            missing_elapsed < Duration::from_secs(20),
            "a missing embedder is answered at once, took {missing_elapsed:?}"
        );

        // Astra r1 (P148): a session an interactive client started, then loaded by an app that attaches
        // non-interactively (`startupHints` on `session/load`), follows the attached app: a silent one gets the
        // no-operator reply within 30 seconds, not the interactive 30-minute wait.
        let attached = tokio::time::timeout(
            acp_harness::RPC_TIMEOUT,
            conn.new_session(acp::NewSessionRequest::new(cwd.to_path_buf()).meta(
                json!({
                    "modelId": "test-model",
                    "askUserQuestion": true,
                    "startupHints": { "nonInteractive": false, "skipGitStatus": true, "skipProjectLayout": true }
                })
                .as_object()
                .cloned(),
            )),
        )
        .await
        .expect("session/new timed out")
        .expect("session/new failed")
        .session_id;
        tokio::time::timeout(
            acp_harness::RPC_TIMEOUT,
            conn.load_session(acp::LoadSessionRequest::new(attached.clone(), cwd.to_path_buf()).meta(
                json!({
                    "startupHints": { "nonInteractive": true, "skipGitStatus": true, "skipProjectLayout": true }
                })
                .as_object()
                .cloned(),
            )),
        )
        .await
        .expect("session/load timed out")
        .expect("session/load failed");
        embedder.silent_sessions.borrow_mut().push(attached.0.to_string());
        let steps = [
            mock.expect_response("attached-ask", fg(), ask_call("call_attached")),
            mock.expect_response("attached-done", fg(), text("attached done")),
        ];
        let attached_elapsed = timed_prompt(&conn, &attached).await;
        for step in &steps {
            step.assert_satisfied();
        }
        assert!(
            no_operator_result_for(&mock, "call_attached"),
            "a non-interactive attachment must get the no-operator tool result\n{}",
            mock.request_log_summary()
        );
        assert!(
            attached_elapsed <= Duration::from_secs(45),
            "a non-interactive attachment waits about 30 s (B19), took {attached_elapsed:?}"
        );
    });
}
