//! P07a: a subagent's plugin hooks come from its PARENT, never from the process-wide plugin snapshot.
//!
//! A subagent copies its parent's live hook registry. When the parent fires no hooks at all there
//! is nothing to copy, and the child builds its own registry at spawn. Its `plugin_registry` there
//! is the process-wide snapshot - built for whichever workspace was resolved last - not the
//! parent's view of its own workspace, so plugin hooks must not be taken from it.
//!
//! Setup: repo A carries a project plugin `leakprobe` with a match-all `PreToolUse` logger. A
//! session in A plus `fuigo/plugins/reload` makes the process snapshot A's (and proves the hook
//! fires in A). A session in B - no hooks, no plugins - then spawns a foreground child that reads a
//! probe file. Green: `leakprobe` never logs the child's read. Red with plugin hooks taken from
//! the child's own snapshot: A's project plugin runs inside a subagent of an unrelated workspace.
#![cfg(unix)]

#[allow(dead_code)]
mod acp_harness;

use std::path::Path;

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

fn tool_call(call_id: &str, name: &str, arguments: &str) -> ScriptedResponse {
    ScriptedResponse::sse(chat_completions_reasoning_then_tool_call_events(
        "probe",
        call_id,
        name,
        arguments,
        "test-model",
    ))
}

/// A `read_file` call on `dir/<file>`; the file name is what marks the call in the hook envelope.
fn read_call(call_id: &str, dir: &Path, file: &str) -> ScriptedResponse {
    let path = dir.join(file);
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

fn logged(log: &Path) -> Vec<Value> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad envelope {l:?}: {e}")))
        .collect()
}

async fn prompt(conn: &acp::ClientSideConnection, session: &acp::SessionId, text: &str) {
    let response = tokio::time::timeout(
        RPC_TIMEOUT,
        conn.prompt(acp::PromptRequest::new(
            session.clone(),
            vec![acp::ContentBlock::Text(acp::TextContent::new(text))],
        )),
    )
    .await
    .expect("prompt timed out")
    .unwrap_or_else(|e| panic!("prompt failed: {e:?}"));
    assert_eq!(response.stop_reason, acp::StopReason::EndTurn);
}

#[test]
fn a_subagent_never_takes_plugin_hooks_from_the_process_snapshot() {
    run_agent_test(|workdir_b, mock| async move {
        let fuigo_home = std::path::PathBuf::from(std::env::var("FUIGO_HOME").expect("FUIGO_HOME"));
        let log = fuigo_home.join("leakprobe.jsonl");
        let repo_a = fuigo_home.join("repo-a");
        git2::Repository::init(&repo_a).expect("git init repo A");
        git2::Repository::init(&workdir_b).expect("git init workdir B");
        let plugin = repo_a.join(".fuigo").join("plugins").join("leakprobe");
        std::fs::create_dir_all(&plugin).expect("plugin dir");
        std::fs::write(
            plugin.join("plugin.json"),
            json!({
                "name": "leakprobe",
                "hooks": {"hooks": {"PreToolUse": [{"hooks": [{
                    "type": "command",
                    "command": format!("cat >> {0}; echo >> {0}", log.display()),
                    "timeout": 30
                }]}]}}
            })
            .to_string(),
        )
        .expect("plugin manifest");
        std::fs::write(
            fuigo_home.join("config.toml"),
            "[plugins]\nenabled = [\"leakprobe\"]\n",
        )
        .expect("config.toml");

        let mut config = fuigo_shell::agent::config::Config::default();
        config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
        // `fuigo/plugins/reload` rebuilds the process snapshot from the agent's in-memory `[plugins]`, not the disk file
        config.plugins.enabled = vec!["leakprobe".to_string()];
        let (conn, _) = connect_client(
            AutoApproveClient,
            "plugin-hooks-child-scope",
            spawn_agent_local_with_config(config),
        )
        .await;
        let fg = || InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions);

        // Session in A; the reload rebuilds the process snapshot for the only resident session's cwd, A.
        let in_a = new_session(&conn, &repo_a).await;
        ext_method(&conn, "fuigo/plugins/reload", json!({})).await;
        let a_steps = [
            mock.expect_response("a-read", fg(), read_call("call_a", &repo_a, "p07-in-a.txt")),
            mock.expect_response("a-done", fg(), text("a done")),
        ];
        prompt(&conn, &in_a, "Read one file.").await;
        for step in &a_steps {
            step.assert_satisfied();
        }
        assert!(
            logged(&log)
                .iter()
                .any(|e| e.to_string().contains("p07-in-a.txt")),
            "fixture: leakprobe must fire in its own workspace, or the leak check below proves nothing"
        );

        // Session in B: no hooks of its own, so its child builds a registry at spawn.
        let in_b = new_session(&conn, &workdir_b).await;
        let spawn_args = json!({
            "description": "child of a hookless parent",
            "prompt": "Read one file, then stop (child of B).",
            "subagent_type": "general-purpose",
        });
        let b_steps = [
            mock.expect_response(
                "b-spawn",
                fg(),
                tool_call("call_b_spawn", "spawn_subagent", &spawn_args.to_string()),
            ),
            mock.expect_response(
                "b-child-read",
                fg(),
                read_call("call_b_child", &workdir_b, "p07-b-child.txt"),
            ),
            mock.expect_response("b-child-done", fg(), text("child done")),
            mock.expect_response("b-done", fg(), text("b done")),
        ];
        prompt(&conn, &in_b, "Spawn one foreground child.").await;
        for step in &b_steps {
            step.assert_satisfied();
        }
        let runs = logged(&log);
        assert!(
            !runs
                .iter()
                .any(|e| e.to_string().contains("p07-b-child.txt")),
            "workspace A's project plugin must not run inside a subagent of workspace B; envelopes: {runs:#?}"
        );
    });
}
