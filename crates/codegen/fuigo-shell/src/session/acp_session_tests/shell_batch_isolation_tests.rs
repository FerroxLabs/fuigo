//! Parallel shell commands inside one session, and what an error or a cancel may and may not take down with it.
//!
//! - An ACP error while one call's result is being delivered must not drop its siblings: each one still completes (or is
//!   answered as cancelled), no process is left behind, and the error still surfaces. `bridge_fault` makes
//!   `handle_bridge_tool_success` report that error, because the real one is currently infallible.
//! - A subagent's cancel kills only the foreground commands that subagent owns. The parent's command, on the same
//!   terminal backend, keeps running to its own end.
// The probes are POSIX shell commands ($$, sleep) and ps.
#![cfg(unix)]
use super::support::*;
use super::*;
use fuigo_tools::computer::local::LocalTerminalBackend;
use fuigo_tools::implementations::fuigo_build::enter_plan_mode::EnterPlanModeTool;
use fuigo_tools::implementations::fuigo_build::exit_plan_mode::ExitPlanModeTool;
use fuigo_tools::registry::types::{ToolConfig, ToolServerConfig};
use std::path::Path;

fn shell_toolset() -> Vec<ToolConfig> {
    vec![ToolConfig {
        id: "FuigoBuild:run_terminal_cmd".into(),
        params: Some(
            serde_json::from_value(serde_json::json!({ "enabled_background": false })).unwrap(),
        ),
        name_override: None,
        params_name_overrides: None,
        description_override: None,
        behavior_version: None,
        kind: None,
    }]
}

fn shell_call(id: &str, command: &str) -> ToolCallResponse {
    ToolCallResponse {
        id: id.to_string(),
        kind: "function".to_string(),
        function: crate::sampling::types::ToolCallFunction::new(
            "run_terminal_cmd",
            serde_json::json!({ "command": command, "description": "batch isolation probe" })
                .to_string(),
        ),
    }
}

fn exit_plan_mode_call(id: &str) -> ToolCallResponse {
    ToolCallResponse {
        id: id.to_string(),
        kind: "function".to_string(),
        function: crate::sampling::types::ToolCallFunction::new("exit_plan_mode", "{}"),
    }
}

/// A session whose shell commands run for real on `backend`; two sessions given the same backend share one terminal.
async fn shell_actor(
    backend: &Arc<LocalTerminalBackend>,
    session_id: &str,
    subagent: bool,
    tools: Vec<ToolConfig>,
    gateway_tx: tokio::sync::mpsc::UnboundedSender<fuigo_acp_lib::AcpClientMessage>,
) -> SessionActor {
    let (persistence_tx, _) = tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
    let mut actor = create_test_actor(0, 256_000, 85, gateway_tx, persistence_tx).await;
    actor.session_info.id = acp::SessionId::new(session_id);
    actor.startup_hints.is_subagent = subagent;
    *actor.agent.borrow_mut() = test_agent_from_config_owned(
        ToolServerConfig {
            tools,
            behavior_preset: None,
        },
        fuigo_agent::AgentDefinition::default_fuigo_build(),
        backend.clone(),
        Some(session_id.to_string()),
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
    actor
}

fn read_pid(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn pid_running(pid: u32) -> bool {
    let out = std::process::Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .expect("ps must run");
    let stat = String::from_utf8_lossy(&out.stdout);
    let stat = stat.trim();
    !stat.is_empty() && !stat.starts_with('Z')
}

async fn wait_for_file(path: &Path, secs: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    while std::time::Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    path.exists()
}

async fn results_by_call_id(actor: &SessionActor) -> std::collections::HashMap<String, Vec<String>> {
    let mut by_id: std::collections::HashMap<String, Vec<String>> = Default::default();
    for item in actor.chat_state_handle.get_conversation().await {
        if let fuigo_sampling_types::ConversationItem::ToolResult(tr) = &item {
            by_id
                .entry(tr.tool_call_id.clone())
                .or_default()
                .push(tr.content.to_string());
        }
    }
    by_id
}

/// A command that records its pid, runs for a second and prints `<name>-output`.
fn slow_command(dir: &str, name: &str) -> String {
    format!("echo $$ > {dir}/{name}.pid; sleep 1; echo ran > {dir}/{name}.done; echo {name}-output")
}

#[tokio::test(flavor = "current_thread")]
async fn an_acp_error_on_one_call_neither_loses_nor_orphans_its_siblings() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let d = dir.path().display().to_string();
            let backend = Arc::new(LocalTerminalBackend::new());
            let (gateway_tx, _) = tokio::sync::mpsc::unbounded_channel();
            let actor = shell_actor(&backend, "parent-session", false, shell_toolset(), gateway_tx).await;

            super::tool_calls::bridge_fault::arm("call_fail");
            let outcome = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                actor.execute_tool_calls(vec![
                    shell_call("call_fail", "sleep 0.3; echo fail-output"),
                    shell_call("call_b", &slow_command(&d, "b")),
                    shell_call("call_c", &slow_command(&d, "c")),
                ]),
            )
            .await;

            let hung = outcome.is_err();
            let surfaced = matches!(&outcome, Ok(Err(_)));
            let alive_at_return: Vec<bool> = ["b", "c"]
                .iter()
                .map(|n| {
                    read_pid(&dir.path().join(format!("{n}.pid"))).is_some_and(pid_running)
                })
                .collect();
            // Anything still running now would finish by itself within this window.
            tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
            let finished_unattended: Vec<bool> = ["b", "c"]
                .iter()
                .map(|n| dir.path().join(format!("{n}.done")).exists())
                .collect();
            let results = results_by_call_id(&actor).await;
            eprintln!(
                "SAFE1C-FACTS hung={hung} error_surfaced={surfaced} sibling_alive_at_return={alive_at_return:?} \
                 sibling_ran_to_end={finished_unattended:?} results={results:?}"
            );

            assert!(!hung, "the batch must not hang");
            assert!(surfaced, "the ACP error must still surface to the caller");
            for id in ["call_fail", "call_b", "call_c"] {
                assert_eq!(
                    results.get(id).map(Vec::len),
                    Some(1),
                    "{id} must have exactly one tool result: {results:?}"
                );
            }
            assert_eq!(
                alive_at_return,
                vec![false, false],
                "no sibling process may outlive the batch"
            );
            for (id, name) in [("call_b", "b"), ("call_c", "c")] {
                assert!(
                    results[id][0].contains(&format!("{name}-output")),
                    "a sibling either completes or is answered as cancelled; this one completed, so it must carry its output: {:?}",
                    results[id]
                );
            }
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn an_acp_error_in_the_body_still_answers_the_exit_plan_tail() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let d = dir.path().display().to_string();
            let backend = Arc::new(LocalTerminalBackend::new());
            let (gateway_tx, mut gateway_rx) = tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
            let mut tools = shell_toolset();
            tools.push(ToolConfig::for_tool::<EnterPlanModeTool>());
            tools.push(ToolConfig::for_tool::<ExitPlanModeTool>());
            let actor = shell_actor(&backend, "parent-session", false, tools, gateway_tx).await;
            let plan_path = dir.path().join("plan.md");
            std::fs::write(&plan_path, "# plan").unwrap();
            {
                let mut tracker = actor.plan_mode.lock();
                *tracker = crate::session::plan_mode::PlanModeTracker::new(dir.path().to_path_buf());
                tracker.activate_from_tool();
            }
            actor
                .tool_bridge_handle()
                .update_resource(fuigo_tools::types::resources::PlanFilePath(plan_path))
                .await;

            let exit_fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let exit_fired_task = exit_fired.clone();
            let responder = tokio::task::spawn_local(async move {
                while let Some(msg) = gateway_rx.recv().await {
                    match msg {
                        fuigo_acp_lib::AcpClientMessage::ExtMethod(args) => {
                            if args.request.method.as_ref() == "fuigo/exit_plan_mode" {
                                exit_fired_task.store(true, std::sync::atomic::Ordering::SeqCst);
                            }
                            let raw: Arc<serde_json::value::RawValue> =
                                serde_json::value::to_raw_value(&serde_json::json!({ "outcome": "approved" }))
                                    .unwrap()
                                    .into();
                            let _ = args.response_tx.send(Ok(acp::ExtResponse::new(raw)));
                        }
                        fuigo_acp_lib::AcpClientMessage::SessionNotification(args) => {
                            let _ = args.response_tx.send(Ok(()));
                        }
                        _ => {}
                    }
                }
            });

            super::tool_calls::bridge_fault::arm("call_fail");
            let outcome = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                actor.execute_tool_calls(vec![
                    shell_call("call_fail", "sleep 0.3; echo fail-output"),
                    shell_call("call_b", &slow_command(&d, "b")),
                    exit_plan_mode_call("call_exit"),
                ]),
            )
            .await;
            let results = results_by_call_id(&actor).await;
            eprintln!(
                "SAFE1C-FACTS tail hung={} error_surfaced={} exit_fired={} results={results:?}",
                outcome.is_err(),
                matches!(&outcome, Ok(Err(_))),
                exit_fired.load(std::sync::atomic::Ordering::SeqCst)
            );
            responder.abort();

            assert!(matches!(&outcome, Ok(Err(_))), "the ACP error must still surface");
            for id in ["call_fail", "call_b", "call_exit"] {
                assert_eq!(
                    results.get(id).map(Vec::len),
                    Some(1),
                    "{id} must have exactly one tool result: {results:?}"
                );
            }
            assert!(
                !exit_fired.load(std::sync::atomic::Ordering::SeqCst),
                "the exit tail must not ask for approval after the body failed"
            );
            assert!(
                results["call_exit"][0].contains("cancelled"),
                "the tail is answered as cancelled: {:?}",
                results["call_exit"]
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_subagents_cancel_kills_only_its_own_foreground_commands() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let d = dir.path().display().to_string();
            // One terminal backend, as in a real run where a subagent shares its parent's.
            let backend = Arc::new(LocalTerminalBackend::new());
            let (parent_gateway_tx, _) = tokio::sync::mpsc::unbounded_channel();
            let (child_gateway_tx, _) = tokio::sync::mpsc::unbounded_channel();
            let parent = shell_actor(&backend, "parent-session", false, shell_toolset(), parent_gateway_tx).await;
            let child = shell_actor(&backend, "child-session", true, shell_toolset(), child_gateway_tx).await;

            let parent_run = parent.execute_tool_calls(vec![shell_call(
                "call_parent",
                &format!("echo $$ > {d}/parent.pid; sleep 3; echo ran > {d}/parent.done; echo parent-output"),
            )]);
            let child_run = child.execute_tool_calls(vec![shell_call(
                "call_child",
                &format!("echo $$ > {d}/child.pid; sleep 60; echo ran > {d}/child.done; echo child-output"),
            )]);
            let driver = async {
                assert!(wait_for_file(&dir.path().join("parent.pid"), 20).await, "parent command never started");
                assert!(wait_for_file(&dir.path().join("child.pid"), 20).await, "child command never started");
                let parent_pid = read_pid(&dir.path().join("parent.pid")).expect("parent pid");
                let child_pid = read_pid(&dir.path().join("child.pid")).expect("child pid");
                assert!(pid_running(parent_pid) && pid_running(child_pid), "both commands run before the cancel");

                let _ = child
                    .cancel_running_task(crate::session::CancelOptions {
                        user_initiated: true,
                        ..Default::default()
                    })
                    .await;

                let parent_alive_after_cancel = pid_running(parent_pid);
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while pid_running(child_pid) && std::time::Instant::now() < deadline {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                (pid_running(child_pid), parent_alive_after_cancel)
            };

            let (parent_outcome, child_outcome, (child_alive, parent_alive)) = tokio::time::timeout(
                std::time::Duration::from_secs(40),
                async {
                    tokio::join!(
                        parent_run, child_run, driver
                    )
                },
            )
            .await
            .expect("neither session may hang");
            eprintln!(
                "SAFE1C-FACTS subagent_cancel child_alive={child_alive} parent_alive_right_after_cancel={parent_alive}"
            );

            assert!(!child_alive, "the subagent's cancel must kill the subagent's own command");
            assert!(parent_alive, "the subagent's cancel must not kill the parent's command");
            parent_outcome.expect("the parent's run keeps going");
            child_outcome.expect("the child's turn ends cleanly");
            assert!(
                dir.path().join("parent.done").exists(),
                "the parent's command ran to its own end"
            );
            assert!(
                !dir.path().join("child.done").exists(),
                "the child's command was cut short"
            );
            let parent_results = results_by_call_id(&parent).await;
            assert!(
                parent_results["call_parent"][0].contains("parent-output"),
                "the parent's tool result carries its command's output: {parent_results:?}"
            );
        })
        .await;
}
