//! A subagent's task text cannot run hook commands, so no hook reload can be triggered from it.
//!
//! History: P07a F1 spawned a child whose task text was a typed `/hooks-untrust` (or `/hooks-trust`) and expected the child to
//! EXECUTE it and reload its hooks (without installing the process-wide snapshot's plugin hooks). The task text is written by the
//! parent MODEL, so executing a slash command from it was itself the escalation: `subagent-task-authority` makes that text
//! model-authored, so it reaches the child's model as plain prompt text and no command runs.
//!
//! Setup is the P07a one: a user plugin `userleak` is enabled process-wide but disabled by the workspace config, and a global hook
//! file gives the parent (and so its child) a hook registry. The parent spawns a foreground child whose task text is the slash
//! command. The child now makes a model turn (scripted below).
//! Asserts, for each of `/hooks-untrust` and `/hooks-trust`: (1) the child made its model request and that request carries the
//! task text as a user message; (2) no "Hooks reloaded: N hook(s) loaded." reply exists in any session transcript; (3)
//! `$FUIGO_HOME/trusted_folders.toml` is byte-for-byte unchanged.
//! Fails on the pre-fix code: there the child runs the command with zero model turns, so the child's scripted model step is never
//! consumed (the scripted "done" lands on the child instead) and two "Hooks reloaded: 1 hook(s) loaded." replies are recorded.
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

/// True when any session transcript under `dir` contains `needle`.
fn transcript_contains(dir: &std::path::Path, needle: &str) -> bool {
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
                && std::fs::read_to_string(&path).is_ok_and(|t| t.contains(needle))
            {
                return true;
            }
        }
    }
    false
}

/// Text of every user-role message in a chat-completions request body.
fn user_texts(body: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    for m in body["messages"].as_array().into_iter().flatten() {
        if m["role"] != "user" {
            continue;
        }
        match &m["content"] {
            serde_json::Value::String(t) => out.push(t.clone()),
            serde_json::Value::Array(parts) => {
                out.extend(parts.iter().filter_map(|p| p["text"].as_str().map(str::to_string)));
            }
            _ => {}
        }
    }
    out
}

#[test]
fn a_subagents_task_text_cannot_run_hook_commands() {
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

        let trust_file = fuigo_home.join("trusted_folders.toml");
        let trust_before = std::fs::read(&trust_file).ok();

        let fg = || InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions);
        for (i, task) in ["/hooks-untrust", "/hooks-trust"].into_iter().enumerate() {
            let steps = [
                mock.expect_response(
                    format!("spawn-{i}"),
                    fg(),
                    spawn_child(&format!("call_spawn_{i}"), task),
                ),
                // The child's own model turn: the task text arrives as a plain prompt, nothing executes it
                mock.expect_response(
                    format!("child-{i}"),
                    fg(),
                    ScriptedResponse::sse(chat_completion_script_exact(
                        &format!("child saw the task {i}"),
                        "test-model",
                    )),
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
        // The child's own turn is persisted asynchronously: wait for the last child's model reply to reach a transcript, so the
        // absence checks below look at a transcript that exists
        let sessions = fuigo_home.join("sessions");
        let mut persisted = false;
        for _ in 0..100 {
            if transcript_contains(&sessions, "child saw the task 1") {
                persisted = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(persisted, "the second child's model reply never reached a transcript");
        let replies = reload_replies(&sessions);
        assert!(
            replies.is_empty(),
            "a subagent's task text must not run /hooks-untrust or /hooks-trust (no reload reply): {replies:?}"
        );
        assert_eq!(
            std::fs::read(&trust_file).ok(),
            trust_before,
            "the hook trust store must be untouched by a subagent's task text"
        );
        // The task text reached the model as plain text, in the child's own request (not only the parent's "Spawn ..." prompt)
        let bodies = mock.request_bodies();
        for task in ["/hooks-untrust", "/hooks-trust"] {
            assert!(
                bodies
                    .iter()
                    .flat_map(user_texts)
                    .any(|t| !t.starts_with("Spawn a child") && t.contains(task)),
                "the child's model request must carry the task text {task:?} as a user message"
            );
        }
    });
}
