//! P148 item 5 (e2e C1, S16/B32): an agent definition's inline `mcpServers` entry that names `FUIGO_API_KEY` loses the
//! reference when the subagent starts, and the session that started it is told so, by a note naming the agent. C1 saw
//! the reference removed but no note at all: the refusal was recorded outside any session's notice scope.
//!
//! Real path: a user agent definition (`$FUIGO_HOME/agents/p148inl.md`) with an inline HTTP server whose header names
//! the key; the scripted parent turn spawns it with `spawn_subagent`.
#![cfg(unix)]

#[allow(dead_code)]
mod acp_harness;
#[allow(dead_code)]
mod p148_support;

use acp_harness::{RPC_TIMEOUT, connect_client, new_session, run_agent_test, spawn_agent_local_with_config};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_test_support::sse::{
    chat_completion_script_exact, chat_completions_reasoning_then_tool_call_events,
};
use fuigo_test_support::{InferenceEndpoint, InferenceRequestMatcher, ScriptedResponse};
use p148_support::Notices;
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct Recorder(Notices);

#[async_trait::async_trait(?Send)]
impl acp::Client for Recorder {
    async fn request_permission(
        &self,
        args: acp::RequestPermissionRequest,
    ) -> acp::Result<acp::RequestPermissionResponse> {
        Ok(acp::RequestPermissionResponse::new(acp_harness::allow_once(&args)))
    }
    async fn session_notification(&self, _: acp::SessionNotification) -> acp::Result<()> {
        Ok(())
    }
    async fn ext_notification(&self, args: acp::ExtNotification) -> acp::Result<()> {
        if let Ok(params) = serde_json::from_str::<Value>(args.params.get()) {
            self.0.record(&params);
        }
        Ok(())
    }
}

const AGENT: &str = "---\nname: p148inl\ndescription: p148 inline mcp probe\nmcpServers:\n  - p148_inl_h:\n      type: http\n      url: http://127.0.0.1:9/mcp\n      headers:\n        - name: X-Ref\n          value: \"${FUIGO_API_KEY}\"\n---\nYou are a test agent. Reply done.\n";

#[test]
fn an_agent_inline_mcp_server_naming_the_key_is_announced_to_the_session() {
    run_agent_test(|cwd, mock| async move {
        let fuigo_home = std::path::PathBuf::from(std::env::var("FUIGO_HOME").expect("FUIGO_HOME"));
        std::fs::create_dir_all(fuigo_home.join("agents")).expect("agents dir");
        std::fs::write(fuigo_home.join("agents").join("p148inl.md"), AGENT).expect("agent definition");

        let mut config = fuigo_shell::agent::config::Config::default();
        config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
        let recorder = Recorder::default();
        let (conn, _) = connect_client(
            recorder.clone(),
            "p148-agent-inline",
            spawn_agent_local_with_config(config),
        )
        .await;
        let session = new_session(&conn, &cwd).await;
        let fg = || InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions);
        let text = |t: &str| ScriptedResponse::sse(chat_completion_script_exact(t, "test-model"));
        let spawn_args = json!({
            "description": "inline mcp probe",
            "prompt": "Reply done (p148 inline child).",
            "subagent_type": "p148inl",
        });
        let steps = [
            mock.expect_response(
                "spawn",
                fg(),
                ScriptedResponse::sse(chat_completions_reasoning_then_tool_call_events(
                    "spawn",
                    "call_spawn",
                    "spawn_subagent",
                    &spawn_args.to_string(),
                    "test-model",
                )),
            ),
            mock.expect_response("child-done", fg(), text("child done")),
            mock.expect_response("parent-done", fg(), text("parent done")),
        ];
        let response = tokio::time::timeout(
            RPC_TIMEOUT,
            conn.prompt(acp::PromptRequest::new(
                session.clone(),
                vec![acp::ContentBlock::Text(acp::TextContent::new("Spawn the probe."))],
            )),
        )
        .await
        .expect("prompt timed out")
        .unwrap_or_else(|e| panic!("prompt failed: {e:?}\n{}", mock.request_log_summary()));
        assert_eq!(response.stop_reason, acp::StopReason::EndTurn);
        for step in &steps {
            step.assert_satisfied();
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let notes: Vec<(String, String)> = recorder
            .0
            .0
            .borrow()
            .iter()
            .filter(|(_, m)| m.contains("p148_inl_h"))
            .cloned()
            .collect();
        assert_eq!(notes.len(), 1, "one note for the refused inline reference: {notes:#?}");
        let (sid, message) = &notes[0];
        assert_eq!(sid, session.0.as_ref(), "the note reaches the session that started the subagent");
        assert!(
            message.contains("p148inl") && message.contains("FUIGO_API_KEY"),
            "the note names the agent and the key: {message}"
        );
    });
}
