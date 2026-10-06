//! P07b: every tool-hook `hook_execution` batch names the ACP tool call it belongs to (`tool_call_id`), so a client can put the
//! runs on that call's row; other events carry none. Before P07b the field did not exist and the pager attached tool-hook
//! runs to whichever tool row came last.
//!
//! A user plugin carries match-all `PreToolUse` and `PostToolUse` hooks; one turn makes one `read_file` call (`call_read`).
//! Green: the `pre_tool_use` and `post_tool_use` batches both carry `tool_call_id == "call_read"`.
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{
    RPC_TIMEOUT, allow_once, connect_client, new_session, run_agent_test,
    spawn_agent_local_with_config,
};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_test_support::sse::{
    chat_completion_script_exact, chat_completions_reasoning_then_tool_call_events,
};
use fuigo_test_support::{InferenceEndpoint, InferenceRequestMatcher, ScriptedResponse};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone, Default)]
struct HookBatches(Rc<RefCell<Vec<Value>>>);

#[async_trait::async_trait(?Send)]
impl acp::Client for HookBatches {
    async fn request_permission(
        &self,
        args: acp::RequestPermissionRequest,
    ) -> acp::Result<acp::RequestPermissionResponse> {
        Ok(acp::RequestPermissionResponse::new(allow_once(&args)))
    }
    async fn session_notification(&self, _: acp::SessionNotification) -> acp::Result<()> {
        Ok(())
    }
    async fn ext_notification(&self, args: acp::ExtNotification) -> acp::Result<()> {
        if let Ok(value) = serde_json::from_str::<Value>(args.params.get())
            && value["update"]["sessionUpdate"] == "hook_execution"
        {
            self.0.borrow_mut().push(value["update"].clone());
        }
        Ok(())
    }
}

#[test]
fn tool_hook_batches_name_their_tool_call() {
    run_agent_test(|cwd, mock| async move {
        let fuigo_home = std::path::PathBuf::from(std::env::var("FUIGO_HOME").expect("FUIGO_HOME"));
        let plugin = fuigo_home.join("plugins").join("idprobe");
        std::fs::create_dir_all(&plugin).expect("plugin dir");
        let hook = json!([{"hooks": [{"type": "command", "command": "true"}]}]);
        std::fs::write(
            plugin.join("plugin.json"),
            json!({"name": "idprobe", "hooks": {"hooks": {"PreToolUse": hook, "PostToolUse": hook}}})
                .to_string(),
        )
        .expect("manifest");
        std::fs::write(
            fuigo_home.join("config.toml"),
            "[plugins]\nenabled = [\"idprobe\"]\n",
        )
        .expect("config.toml");
        let probe = cwd.join("probe.txt");
        std::fs::write(&probe, "probe\n").expect("probe file");

        let mut config = fuigo_shell::agent::config::Config::default();
        config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
        let batches = HookBatches::default();
        let (conn, _) = connect_client(
            batches.clone(),
            "hook-execution-tool-call-id",
            spawn_agent_local_with_config(config),
        )
        .await;
        let session = new_session(&conn, &cwd).await;
        let fg = || InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions);
        let steps = [
            mock.expect_response(
                "read",
                fg(),
                ScriptedResponse::sse(chat_completions_reasoning_then_tool_call_events(
                    "probe",
                    "call_read",
                    "read_file",
                    &json!({"target_file": probe}).to_string(),
                    "test-model",
                )),
            ),
            mock.expect_response(
                "done",
                fg(),
                ScriptedResponse::sse(chat_completion_script_exact("done", "test-model")),
            ),
        ];
        let response = tokio::time::timeout(
            RPC_TIMEOUT,
            conn.prompt(acp::PromptRequest::new(
                session.clone(),
                vec![acp::ContentBlock::Text(acp::TextContent::new(
                    "Read the probe.",
                ))],
            )),
        )
        .await
        .expect("prompt timed out")
        .unwrap_or_else(|e| panic!("prompt failed: {e:?}\n{}", mock.request_log_summary()));
        assert_eq!(response.stop_reason, acp::StopReason::EndTurn);
        for step in &steps {
            step.assert_satisfied();
        }
        let seen = batches.0.borrow().clone();
        for event in ["pre_tool_use", "post_tool_use"] {
            let batch = seen
                .iter()
                .find(|b| b["event_name"] == event)
                .unwrap_or_else(|| panic!("no {event} batch: {seen:#?}"));
            assert_eq!(
                batch["tool_call_id"], "call_read",
                "{event} batch must name its tool call: {batch}"
            );
        }
    });
}
