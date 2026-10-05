//! P07a F1: a subagent whose task text is a typed `/hooks-untrust` (or `/hooks-trust`) reloads its hooks; that reload must
//! not install plugin hooks from the subagent's stored plugin registry, which is the process-wide snapshot rather than its
//! parent's view of the workspace.
//!
//! Setup: a user plugin `userleak` (one `PreToolUse` hook) is enabled process-wide, but the workspace's own config disables
//! it, so the parent session's view has no `userleak`. A global hook file gives the parent (and so its child) a registry, which
//! makes the typed hook commands available in the child. The parent spawns a foreground child whose task text is the slash
//! command; the child's reply ("... Hooks reloaded: N hook(s) loaded.") is read back from the child's own transcript.
//! Green: N == 1 (the global hook only). Red with plugins taken from the child's stored snapshot: N == 2.
#![cfg(unix)]

#[allow(dead_code)]
mod acp_harness;

use acp_harness::{
    AutoApproveClient, RPC_TIMEOUT, connect_client, ext_method, new_session, run_agent_test,
    spawn_agent_local_with_config,
};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_test_support::sse::{
    chat_completion_script_exact, chat_completions_reasoning_then_tool_call_events,
};
use fuigo_test_support::{InferenceEndpoint, InferenceRequestMatcher, ScriptedResponse};
use serde_json::json;

fn spawn_child(call_id: &str, task: &str) -> ScriptedResponse {
    let args = json!({
        "description": "slash child",
        "prompt": task,
        "subagent_type": "general-purpose",
    });
    ScriptedResponse::sse(chat_completions_reasoning_then_tool_call_events(
        "probe",
        call_id,
        "spawn_subagent",
        &args.to_string(),
        "test-model",
    ))
}

/// Every "Hooks reloaded: N hook(s) loaded." reply recorded in a transcript under `dir`.
fn reload_replies(dir: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().is_some_and(|n| n == "updates.jsonl")
                && let Ok(text) = std::fs::read_to_string(&path)
            {
                let mut rest = text.as_str();
                while let Some(at) = rest.find("Hooks reloaded: ") {
                    let tail = &rest[at..];
                    let end = tail
                        .find("loaded.")
                        .map_or(tail.len(), |i| i + "loaded.".len());
                    out.push(tail[..end].to_string());
                    rest = &tail[end..];
                }
            }
        }
    }
    out
}

#[test]
fn a_subagents_typed_hook_command_reloads_no_process_snapshot_plugins() {
    run_agent_test(|cwd, mock| async move {
        let fuigo_home = std::path::PathBuf::from(std::env::var("FUIGO_HOME").expect("FUIGO_HOME"));
        // A global hook file: the parent, and so its child, has a registry and the typed hook commands
        let hooks_dir = fuigo_home.join("hooks");
        std::fs::create_dir_all(&hooks_dir).expect("hooks dir");
        std::fs::write(
            hooks_dir.join("global.json"),
            r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"true"}]}]}}"#,
        )
        .expect("global hook");
        // A user plugin with a hook, enabled for the process, disabled by this workspace's own config
        let plugin = fuigo_home.join("plugins").join("userleak");
        std::fs::create_dir_all(&plugin).expect("plugin dir");
        std::fs::write(
            plugin.join("plugin.json"),
            r#"{"name":"userleak","hooks":{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"true"}]}]}}}"#,
        )
        .expect("plugin manifest");
        std::fs::write(
            fuigo_home.join("config.toml"),
            "[plugins]\nenabled = [\"userleak\"]\n",
        )
        .expect("config.toml");
        git2::Repository::init(&cwd).expect("git init");
        std::fs::create_dir_all(cwd.join(".fuigo")).expect(".fuigo");
        std::fs::write(
            cwd.join(".fuigo").join("config.toml"),
            "[plugins]\ndisabled = [\"userleak\"]\n",
        )
        .expect("workspace config");

        let mut config = fuigo_shell::agent::config::Config::default();
        config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
        config.plugins.enabled = vec!["userleak".to_string()];
        let (conn, _) = connect_client(
            AutoApproveClient,
            "plugin-hooks-child-slash",
            spawn_agent_local_with_config(config),
        )
        .await;
        let session = new_session(&conn, &cwd).await;
        // The process snapshot is rebuilt from the agent's [plugins], which enables userleak; the session's view stays without it
        ext_method(&conn, "fuigo/plugins/reload", json!({})).await;

        let fg = || InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions);
        for (i, task) in ["/hooks-untrust", "/hooks-trust"].into_iter().enumerate() {
            let steps = [
                mock.expect_response(
                    format!("spawn-{i}"),
                    fg(),
                    spawn_child(&format!("call_spawn_{i}"), task),
                ),
                mock.expect_response(
                    format!("done-{i}"),
                    fg(),
                    ScriptedResponse::sse(chat_completion_script_exact("done", "test-model")),
                ),
            ];
            let response = tokio::time::timeout(
                RPC_TIMEOUT,
                conn.prompt(acp::PromptRequest::new(
                    session.clone(),
                    vec![acp::ContentBlock::Text(acp::TextContent::new(format!(
                        "Spawn a child that runs {task}."
                    )))],
                )),
            )
            .await
            .expect("prompt timed out")
            .unwrap_or_else(|e| panic!("prompt failed: {e:?}\n{}", mock.request_log_summary()));
            assert_eq!(response.stop_reason, acp::StopReason::EndTurn);
            for step in &steps {
                step.assert_satisfied();
            }
        }
        // Each child's reply to its slash command is in its own transcript under $FUIGO_HOME/sessions (persisted asynchronously)
        let mut replies = Vec::new();
        for _ in 0..100 {
            replies = reload_replies(&fuigo_home.join("sessions"));
            if replies.len() >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(
            replies.len(),
            2,
            "one reload reply per child (/hooks-untrust, /hooks-trust): {replies:?}"
        );
        for reply in &replies {
            assert_eq!(
                reply, "Hooks reloaded: 1 hook(s) loaded.",
                "a subagent's typed hook command must reload only the global hook, never the process \
                 snapshot's plugin: {replies:?}"
            );
        }
    });
}
