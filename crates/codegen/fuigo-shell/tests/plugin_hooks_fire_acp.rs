//! P07a: an enabled plugin's hook fires from a session's FIRST turn, and in the subagents it spawns.
//!
//! Before P07a the session-start hook load (`spawn_session_actor`) built the registry from the
//! config layers and hook files only; plugin hooks were appended solely by the two reload paths
//! (`reload_hooks_impl`, `apply_plugin_registry_snapshot`). A plugin installed to enforce a policy
//! therefore did nothing until something triggered a reload, and a subagent - which copies its
//! parent's registry from the parent's `SessionHandle` - never had it either.
//!
//! The script, all main-turn requests on `/v1/chat/completions`, in the only order a blocking
//! spawn allows:
//!
//! 1. parent: `spawn_subagent` (foreground, so the parent waits);
//! 2. child: `read_file` of a probe file;
//! 3. child: a text answer, ending the child;
//! 4. parent: a text answer, ending the turn.
//!
//! The user plugin `hookprobe` carries a match-all `PreToolUse` hook that appends its stdin (the
//! hook envelope) to a log. Green: the log holds the parent's `spawn_subagent` call under the
//! parent's session id AND the child's `read_file` call under another session id. Red at the
//! parent commit: the log is never written.
//!
//! Two more sessions follow: one whose agent definition carries inline hooks (the other spawn
//! site, `spawn_and_register_session`'s override), which must fire the plugin's hook too; and,
//! after the plugin is deleted and `fuigo/plugins/reload` finds no plugin at all, the same session
//! must stop firing it - an empty (`None`) plugin snapshot strips the plugin's hooks.
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
use serde_json::{Value, json};

const CHILD_PROMPT: &str = "Read one file, then stop (plugin-hook child).";
const CHILD_FILE: &str = "p07-probe-child.txt";
const HOOKED_FILE: &str = "p07-probe-hooked.txt";
const REMOVED_FILE: &str = "p07-probe-after-removal.txt";

fn tool_call(call_id: &str, name: &str, arguments: &str) -> ScriptedResponse {
    ScriptedResponse::sse(chat_completions_reasoning_then_tool_call_events(
        "probe",
        call_id,
        name,
        arguments,
        "test-model",
    ))
}

/// A `read_file` call on `cwd/<file>`; the file name is what marks the call in the hook envelope.
fn read_call(call_id: &str, cwd: &std::path::Path, file: &str) -> ScriptedResponse {
    let path = cwd.join(file);
    std::fs::write(&path, "probe\n").expect("probe file");
    tool_call(
        call_id,
        "read_file",
        &json!({"target_file": path}).to_string(),
    )
}

fn text(answer: &str) -> ScriptedResponse {
    ScriptedResponse::sse(chat_completion_script_exact(answer, "test-model"))
}

/// The hook envelopes in `log`, one JSON object per line.
fn envelopes(log: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad envelope {l:?}: {e}")))
        .collect()
}

fn session_of(envelope: &Value) -> String {
    envelope
        .get("sessionId")
        .or_else(|| envelope.get("session_id"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn an_enabled_plugins_hook_fires_on_the_first_turn_and_in_its_subagents() {
    run_agent_test(|cwd, mock| async move {
        let fuigo_home = std::path::PathBuf::from(std::env::var("FUIGO_HOME").expect("FUIGO_HOME"));
        let log = fuigo_home.join("hookprobe.jsonl");
        // A user plugin with a file-based hooks.json: a match-all PreToolUse logger
        let plugin = fuigo_home.join("plugins").join("hookprobe");
        std::fs::create_dir_all(plugin.join("hooks")).expect("plugin dir");
        std::fs::write(plugin.join("plugin.json"), r#"{"name":"hookprobe"}"#).expect("manifest");
        std::fs::write(
            plugin.join("hooks").join("hooks.json"),
            json!({
                "hooks": {
                    "PreToolUse": [{
                        "hooks": [{
                            "type": "command",
                            "command": format!("cat >> {0}; echo >> {0}", log.display()),
                            "timeout": 30
                        }]
                    }]
                }
            })
            .to_string(),
        )
        .expect("hooks.json");
        // User plugins default to disabled until named in `[plugins].enabled`
        std::fs::write(
            fuigo_home.join("config.toml"),
            "[plugins]\nenabled = [\"hookprobe\"]\n",
        )
        .expect("config.toml");

        let spawn_args = json!({
            "description": "plugin-hook child",
            "prompt": CHILD_PROMPT,
            "subagent_type": "general-purpose",
        });
        let fg = || InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions);
        let steps = [
            mock.expect_response(
                "parent-spawns-child",
                fg(),
                tool_call("call_spawn", "spawn_subagent", &spawn_args.to_string()),
            ),
            mock.expect_response(
                "child-read",
                fg(),
                read_call("call_child", &cwd, CHILD_FILE),
            ),
            mock.expect_response("child-done", fg(), text("child done")),
            mock.expect_response("parent-done", fg(), text("parent done")),
        ];

        let mut config = fuigo_shell::agent::config::Config::default();
        // A model-generated title is one more request to the same mock; keep the stream to the scripted four
        config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
        let (conn, _) = connect_client(
            AutoApproveClient,
            "plugin-hooks-fire",
            spawn_agent_local_with_config(config),
        )
        .await;
        let session = new_session(&conn, &cwd).await;
        let response = tokio::time::timeout(
            RPC_TIMEOUT,
            conn.prompt(acp::PromptRequest::new(
                session.clone(),
                vec![acp::ContentBlock::Text(acp::TextContent::new(
                    "Spawn one foreground child.",
                ))],
            )),
        )
        .await
        .expect("parent prompt timed out")
        .unwrap_or_else(|e| {
            panic!(
                "parent prompt failed: {e:?}\n{}",
                mock.request_log_summary()
            )
        });
        assert_eq!(
            response.stop_reason,
            acp::StopReason::EndTurn,
            "{}",
            mock.request_log_summary()
        );
        for step in &steps {
            step.assert_satisfied();
        }

        let parent = session.0.to_string();
        let runs = envelopes(&log);
        let parent_runs: Vec<&Value> = runs.iter().filter(|e| session_of(e) == parent).collect();
        let child_reads: Vec<&Value> = runs
            .iter()
            .filter(|e| session_of(e) != parent && e.to_string().contains(CHILD_FILE))
            .collect();
        assert!(
            parent_runs
                .iter()
                .any(|e| e.to_string().contains("spawn_subagent")),
            "the plugin's PreToolUse hook must fire for the parent's first tool call, with no reload \
             in between; envelopes logged: {runs:#?}"
        );
        assert_eq!(
            child_reads.len(),
            1,
            "the plugin's PreToolUse hook must fire exactly once for the subagent's read_file; \
             envelopes logged: {runs:#?}"
        );

        tokio::time::timeout(
            RPC_TIMEOUT,
            conn.close_session(acp::CloseSessionRequest::new(session)),
        )
        .await
        .expect("close_session timed out")
        .expect("close_session");

        // A session whose agent definition carries inline hooks takes the other spawn site: `spawn_and_register_session` builds a
        // registry override (disk hooks + the agent's own hooks) instead of the spawn-time load. It must carry the plugin hooks too.
        let hooked_steps = [
            mock.expect_response(
                "hooked-read",
                fg(),
                read_call("call_hooked", &cwd, HOOKED_FILE),
            ),
            mock.expect_response("hooked-done", fg(), text("hooked done")),
        ];
        let meta = json!({
            "modelId": "test-model",
            "agentProfile": {
                "name": "hooked-agent",
                "description": "an agent with inline hooks",
                "hooks": {"SessionEnd": [{"hooks": [{"type": "command", "command": "true"}]}]}
            }
        });
        let hooked = tokio::time::timeout(
            RPC_TIMEOUT,
            conn.new_session(
                acp::NewSessionRequest::new(cwd.clone()).meta(meta.as_object().cloned()),
            ),
        )
        .await
        .expect("session/new timed out")
        .expect("session/new failed")
        .session_id;
        let response = tokio::time::timeout(
            RPC_TIMEOUT,
            conn.prompt(acp::PromptRequest::new(
                hooked.clone(),
                vec![acp::ContentBlock::Text(acp::TextContent::new(
                    "Read one file.",
                ))],
            )),
        )
        .await
        .expect("hooked prompt timed out")
        .unwrap_or_else(|e| {
            panic!(
                "hooked prompt failed: {e:?}\n{}",
                mock.request_log_summary()
            )
        });
        assert_eq!(response.stop_reason, acp::StopReason::EndTurn);
        for step in &hooked_steps {
            step.assert_satisfied();
        }
        let hooked_id = hooked.0.to_string();
        let runs = envelopes(&log);
        assert_eq!(
            runs.iter()
                .filter(|e| session_of(e) == hooked_id && e.to_string().contains(HOOKED_FILE))
                .count(),
            1,
            "a session whose agent has inline hooks must still fire the plugin's hook; envelopes logged: {runs:#?}"
        );

        // Remove the only plugin. The reload finds none, so every session adopts an empty (`None`) plugin snapshot.
        std::fs::remove_dir_all(&plugin).expect("remove the plugin");
        ext_method(&conn, "fuigo/plugins/reload", json!({})).await;
        let removed_steps = [
            mock.expect_response(
                "removed-read",
                fg(),
                read_call("call_removed", &cwd, REMOVED_FILE),
            ),
            mock.expect_response("removed-done", fg(), text("removed done")),
        ];
        let response = tokio::time::timeout(
            RPC_TIMEOUT,
            conn.prompt(acp::PromptRequest::new(
                hooked.clone(),
                vec![acp::ContentBlock::Text(acp::TextContent::new(
                    "Read one file.",
                ))],
            )),
        )
        .await
        .expect("post-removal prompt timed out")
        .unwrap_or_else(|e| {
            panic!(
                "post-removal prompt failed: {e:?}\n{}",
                mock.request_log_summary()
            )
        });
        assert_eq!(response.stop_reason, acp::StopReason::EndTurn);
        for step in &removed_steps {
            step.assert_satisfied();
        }
        let runs = envelopes(&log);
        assert!(
            !runs.iter().any(|e| e.to_string().contains(REMOVED_FILE)),
            "a removed plugin's hook must not fire after the reload found no plugins; envelopes logged: {runs:#?}"
        );
    });
}
