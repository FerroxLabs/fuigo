//! A background subagent that needs a shell approval (upstream 1.0.36: "Shell command approvals from background
//! subagents are now shown instead of being silently rejected").
//!
//! The child session inherits its parent's permission manager (`inherited_permission_handle`), so its ask must reach
//! the client over the parent's gateway even though the parent has no turn running, and the user's answer must reach
//! the child: a denial is a tool result the subagent reads, an allow lets the command prepare.
use super::support::*;
use super::*;
use fuigo_acp_lib::AcpAgentGatewaySender;
use fuigo_tools::registry::types::ToolConfig;

/// A command the manager still prompts for (`echo` is safe-listed and auto-allows).
const COMMAND: &str = "./probe-background-subagent-approval.sh";

fn bash_call(id: &str) -> ToolCallResponse {
    ToolCallResponse {
        id: id.to_string(),
        kind: "function".to_string(),
        function: crate::sampling::types::ToolCallFunction::new(
            "run_terminal_cmd",
            serde_json::json!({
                "command": COMMAND,
                "description": "probe a background subagent's shell approval",
            })
            .to_string(),
        ),
    }
}

fn bash_toolset() -> Vec<ToolConfig> {
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

type Asks = std::rc::Rc<std::cell::RefCell<Vec<acp::RequestPermissionRequest>>>;

/// The client end of the parent's gateway: records every permission ask and answers it with `option_id`.
fn client_answering(
    mut gateway_rx: tokio::sync::mpsc::UnboundedReceiver<fuigo_acp_lib::AcpClientMessage>,
    option_id: &'static str,
) -> Asks {
    let asks: Asks = Default::default();
    let asks_in_task = std::rc::Rc::clone(&asks);
    tokio::task::spawn_local(async move {
        while let Some(message) = gateway_rx.recv().await {
            if let fuigo_acp_lib::AcpClientMessage::RequestPermission(args) = message {
                asks_in_task.borrow_mut().push(args.request.clone());
                let _ = args.response_tx.send(Ok(acp::RequestPermissionResponse::new(
                    acp::RequestPermissionOutcome::Selected(acp::SelectedPermissionOutcome::new(
                        acp::PermissionOptionId::new(option_id),
                    )),
                )));
            }
        }
    });
    asks
}

/// A parent that owns the permission manager and has no turn running, and a subagent that inherits that manager.
async fn idle_parent_and_background_child(
    option_id: &'static str,
) -> (SessionActor, SessionActor, Asks) {
    let (parent_gateway_tx, parent_gateway_rx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
    let (parent_persistence_tx, _parent_persistence_rx) =
        tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
    let mut parent = create_test_actor(
        0,
        256_000,
        85,
        parent_gateway_tx.clone(),
        parent_persistence_tx,
    )
    .await;
    install_permission_manager(
        &mut parent,
        false,
        AcpAgentGatewaySender::new(parent_gateway_tx),
    );
    let asks = client_answering(parent_gateway_rx, option_id);

    // The child's own gateway goes nowhere: an ask that went out on it would never be answered.
    let (child_gateway_tx, _child_gateway_rx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
    let (child_persistence_tx, _child_persistence_rx) =
        tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
    let mut child =
        create_test_actor(0, 256_000, 85, child_gateway_tx, child_persistence_tx).await;
    child.startup_hints.is_subagent = true;
    child.permissions = parent.permissions.clone();
    *child.agent.borrow_mut() = test_agent_with_tools(bash_toolset()).await;
    child
        .chat_state_handle
        .push_assistant_response(ConversationItem::assistant_tool_calls(vec![
            fuigo_sampling_types::ToolCall {
                id: "call-bash".into(),
                name: "run_terminal_cmd".into(),
                arguments: "{}".into(),
            },
        ]));
    assert!(
        parent.state.lock().await.running_task.is_none(),
        "the parent has no turn running: this is a background child"
    );
    (parent, child, asks)
}

#[tokio::test(flavor = "current_thread")]
async fn a_background_subagents_shell_ask_reaches_the_client_and_a_denial_reaches_the_subagent() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_parent, child, asks) = idle_parent_and_background_child("reject-once").await;

            let outcome = prepare_call(&child, bash_call("call-bash")).await;

            let asks = asks.borrow().clone();
            assert_eq!(1, asks.len(), "the user is asked exactly once: {asks:?}");
            let shown = format!("{:?}", asks[0].tool_call);
            assert!(
                shown.contains(COMMAND),
                "the ask names the subagent's command: {shown}"
            );
            assert!(
                asks[0]
                    .options
                    .iter()
                    .any(|option| option.option_id.0.as_ref() == "reject-once"),
                "the user is offered a denial: {:?}",
                asks[0].options
            );
            match outcome {
                Err(ToolLoop::PermissionReject { tool_name, .. }) => {
                    assert_eq!("run_terminal_cmd", tool_name)
                }
                Err(other) => {
                    panic!("a denial must reach the subagent as a rejection, got {other:?}")
                }
                Ok(_) => panic!("a denied command must not prepare"),
            }
            let results: Vec<String> = child
                .chat_state_handle
                .get_conversation()
                .await
                .iter()
                .filter_map(|item| match item {
                    ConversationItem::ToolResult(result) if &*result.tool_call_id == "call-bash" => {
                        Some(result.content.to_string())
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(1, results.len(), "{results:?}");
            assert!(
                results[0].contains("run_terminal_cmd"),
                "the subagent reads that its command was refused: {}",
                results[0]
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_background_subagents_shell_ask_lets_the_command_prepare_when_the_user_allows_it() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_parent, child, asks) = idle_parent_and_background_child("allow-once").await;

            let outcome = prepare_call(&child, bash_call("call-bash")).await;

            assert_eq!(1, asks.borrow().len(), "the user is asked exactly once");
            assert!(
                outcome.is_ok(),
                "an approved command prepares; got {:?}",
                outcome.err()
            );
        })
        .await;
}
