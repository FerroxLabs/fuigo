use super::support::*;
use super::*;

async fn bash_actor() -> SessionActor {
    use fuigo_tools::registry::types::ToolConfig;
    let (gateway_tx, mut gateway_rx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
    let (persistence_tx, _persistence_rx) =
        tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
    let actor = create_test_actor(0, 256_000, 85, gateway_tx, persistence_tx).await;
    let mut bash = ToolConfig::from_id("FuigoBuild:run_terminal_cmd");
    bash.name_override = Some("run_terminal_command".to_owned());
    bash.params = serde_json::json!({ "enabled_background": false })
        .as_object()
        .cloned();
    *actor.agent.borrow_mut() = test_agent_with_tools(vec![bash]).await;
    tokio::task::spawn_local(async move {
        while let Some(msg) = gateway_rx.recv().await {
            if let fuigo_acp_lib::AcpClientMessage::SessionNotification(args) = msg {
                let _ = args.response_tx.send(Ok(()));
            }
        }
    });
    actor
}

fn bash_call(id: &str, command: &str) -> ToolCallResponse {
    ToolCallResponse {
        id: id.to_string(),
        kind: "function".to_string(),
        function: crate::sampling::types::ToolCallFunction::new(
            "run_terminal_command",
            serde_json::json!({ "command": command }).to_string(),
        ),
    }
}

async fn prepare(
    actor: &SessionActor,
    call: ToolCallResponse,
) -> Result<PreparedToolCall, ToolLoop> {
    let mut deferred = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        actor.prepare_tool_call(call, &mut deferred),
    )
    .await
    .expect("prepare_tool_call must not hang")
    .expect("prepare_tool_call must not error")
}

/// RED/GREEN: under an armed `/steward` watch, a wake turn's `gh pr merge` and `git push --force` never run.
#[tokio::test(flavor = "current_thread")]
async fn armed_watch_denies_merge_and_force_push_on_a_wake_turn() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let actor = bash_actor().await;
            actor.ship_guard.on_typed_skill("steward", "");
            actor.ship_guard.begin_turn("wake", false);
            for (id, command) in [("m", "gh pr merge 12 --squash"), ("f", "git push --force")] {
                let result = prepare(&actor, bash_call(id, command)).await;
                assert!(
                    matches!(result, Err(ToolLoop::HookDenied { .. })),
                    "{command} must be denied; got {result:?}"
                );
                let text = tool_result_text(&actor, id).await;
                assert!(text.contains("never-merge rule"), "{text}");
            }
        })
        .await;
}

/// The normal path is untouched: an unarmed session, a typed turn, and ordinary watch commands all pass the gate.
#[tokio::test(flavor = "current_thread")]
async fn normal_path_passes_the_gate() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let actor = bash_actor().await;
            actor.ship_guard.begin_turn("wake", false);
            let unarmed = prepare(&actor, bash_call("u", "gh pr merge 12")).await;
            assert!(unarmed.is_ok(), "unarmed session: {:?}", unarmed.err());

            actor.ship_guard.on_typed_skill("ship", "");
            actor.ship_guard.begin_turn("typed", true);
            let typed = prepare(&actor, bash_call("t", "gh pr merge 12")).await;
            assert!(typed.is_ok(), "typed turn: {:?}", typed.err());

            actor.ship_guard.begin_turn("wake", false);
            let push = prepare(&actor, bash_call("p", "git push origin feature")).await;
            assert!(push.is_ok(), "plain push on a wake turn: {:?}", push.err());
        })
        .await;
}

/// A shell session whose commands run for real, with `use_tool` for MCP dispatch.
#[cfg(unix)]
async fn real_shell_actor() -> SessionActor {
    use fuigo_tools::registry::types::{ToolConfig, ToolServerConfig};
    let (gateway_tx, mut gateway_rx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
    let (persistence_tx, _persistence_rx) =
        tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
    let mut actor = create_test_actor(0, 256_000, 85, gateway_tx, persistence_tx).await;
    let session_id = format!("ship-guard-e2e-{}", uuid::Uuid::new_v4());
    actor.session_info.id = acp::SessionId::new(session_id.as_str());
    let mut bash = ToolConfig::from_id("FuigoBuild:run_terminal_cmd");
    bash.name_override = Some("run_terminal_command".to_owned());
    bash.params = serde_json::json!({ "enabled_background": false })
        .as_object()
        .cloned();
    *actor.agent.borrow_mut() = test_agent_from_config_owned(
        ToolServerConfig {
            tools: vec![
                bash,
                ToolConfig::for_tool::<fuigo_tools::implementations::use_tool::UseTool>(),
            ],
            behavior_preset: None,
        },
        fuigo_agent::AgentDefinition::default_fuigo_build(),
        Arc::new(fuigo_tools::computer::local::LocalTerminalBackend::new()),
        Some(session_id),
    )
    .await;
    actor
        .workspace_ops
        .bind_local_session(
            &actor.session_id_string(),
            actor.tool_context.cwd.as_path().to_path_buf(),
            actor.tool_context.hunk_tracker_handle.clone(),
            actor.agent.borrow().tool_bridge().toolset(),
            None,
            actor.tool_context.peer_influence.clone(),
        )
        .expect("bind_local_session must succeed");
    tokio::task::spawn_local(async move {
        while let Some(msg) = gateway_rx.recv().await {
            if let fuigo_acp_lib::AcpClientMessage::SessionNotification(args) = msg {
                let _ = args.response_tx.send(Ok(()));
            }
        }
    });
    actor
}

#[cfg(unix)]
fn git(args: &[&str]) -> std::process::Output {
    std::process::Command::new("git")
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@localhost",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .expect("git must run")
}

#[cfg(unix)]
fn use_tool_call(id: &str, tool_name: &str, tool_input: serde_json::Value) -> ToolCallResponse {
    ToolCallResponse {
        id: id.to_string(),
        kind: "function".to_string(),
        function: crate::sampling::types::ToolCallFunction::new(
            "use_tool",
            serde_json::json!({ "tool_name": tool_name, "tool_input": tool_input }).to_string(),
        ),
    }
}

/// End to end: `/ship` armed, a wake turn's model output calls `gh pr merge` (a PATH stub that records its argv),
/// `git push --force` (to a local bare repository) and the GitHub MCP `merge_pull_request`. All three are denied and
/// nothing reaches the stub or the repository. The same calls on a typed turn do reach them.
#[cfg(unix)]
#[allow(
    clippy::disallowed_methods,
    reason = "the gh stub and its bin folder live in a test tempdir, not a session folder"
)]
#[tokio::test(flavor = "current_thread")]
async fn e2e_wake_turn_merge_force_push_and_mcp_merge_never_run_but_typed_ones_do() {
    use std::os::unix::fs::PermissionsExt;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let bin = dir.path().join("bin");
            std::fs::create_dir(&bin).unwrap();
            let gh_log = dir.path().join("gh-argv.log");
            let stub = bin.join("gh");
            std::fs::write(
                &stub,
                format!("#!/bin/sh\necho \"$*\" >> '{}'\n", gh_log.display()),
            )
            .unwrap();
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
            let bare = dir.path().join("origin.git");
            let work = dir.path().join("work");
            let (bare_s, work_s) = (bare.display().to_string(), work.display().to_string());
            assert!(git(&["init", "-q", "--bare", &bare_s]).status.success());
            assert!(git(&["init", "-q", &work_s]).status.success());
            assert!(
                git(&["-C", &work_s, "commit", "-q", "--allow-empty", "-m", "init"])
                    .status
                    .success()
            );
            assert!(
                git(&["-C", &work_s, "remote", "add", "origin", &bare_s])
                    .status
                    .success()
            );
            let bare_has_main = || {
                git(&[
                    "-C",
                    &bare_s,
                    "rev-parse",
                    "--verify",
                    "-q",
                    "refs/heads/main",
                ])
                .status
                .success()
            };

            let gh_cmd = format!("PATH=\"{}:$PATH\" gh pr merge 12 --squash", bin.display());
            let push_cmd = format!("git -C {work_s} push --force origin HEAD:main");
            let mcp_args = serde_json::json!({ "owner": "o", "repo": "r", "pullNumber": 12 });
            let calls = |turn: &str| {
                vec![
                    bash_call(&format!("{turn}-gh"), &gh_cmd),
                    bash_call(&format!("{turn}-push"), &push_cmd),
                ]
            };

            let actor = real_shell_actor().await;
            actor.ship_guard.on_typed_skill("ship", "");
            actor.ship_guard.begin_turn("wake-1", false);
            let mut wake_calls = calls("wake");
            wake_calls.push(use_tool_call(
                "wake-mcp",
                "github__merge_pull_request",
                mcp_args.clone(),
            ));
            tokio::time::timeout(
                std::time::Duration::from_secs(60),
                actor.execute_tool_calls(wake_calls),
            )
            .await
            .expect("the wake batch must not hang")
            .expect("the wake batch must not error");
            for id in ["wake-gh", "wake-push", "wake-mcp"] {
                let text = tool_result_text(&actor, id).await;
                assert!(
                    text.contains("never-merge rule"),
                    "{id} must be denied: {text}"
                );
            }
            assert!(
                !gh_log.exists(),
                "a denied `gh pr merge` must never reach the stub"
            );
            assert!(
                !bare_has_main(),
                "a denied force-push must never reach the repository"
            );

            actor.ship_guard.begin_turn("typed-1", true);
            tokio::time::timeout(
                std::time::Duration::from_secs(60),
                actor.execute_tool_calls(calls("typed")),
            )
            .await
            .expect("the typed batch must not hang")
            .expect("the typed batch must not error");
            let argv = std::fs::read_to_string(&gh_log).unwrap_or_default();
            assert_eq!(
                argv.trim(),
                "pr merge 12 --squash",
                "a typed `gh pr merge` reaches the stub"
            );
            assert!(
                bare_has_main(),
                "a typed force-push reaches the repository: {}",
                tool_result_text(&actor, "typed-push").await
            );
            let mcp = prepare(
                &actor,
                use_tool_call("typed-mcp", "github__merge_pull_request", mcp_args),
            )
            .await;
            assert!(
                mcp.is_ok(),
                "a typed MCP merge passes the gate to its server: {:?}",
                mcp.err()
            );
        })
        .await;
}
