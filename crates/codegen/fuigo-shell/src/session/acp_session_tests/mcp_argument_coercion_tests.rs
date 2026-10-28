use super::support::*;
use super::*;
use agent_client_protocol as acp;
use fuigo_tools::types::output::{MCPOutput, ToolOutput, ToolRunResult};
use pretty_assertions::assert_eq;
use std::time::Duration;

const SPLUNK: &str = "splunk__RunSearch";
const COMPACT: &str = r#"{"SPL":"index=main"}"#;
const SPLUNK_BODY: &str = "The requested tool `splunk__RunSearch` for this `use_tool` call required `input` to be a string, yet a JSON object was provided. The system coerced and sent your value as a JSON-encoded string. Please provide the correct schema next call.";
const COULD_NOT: &str = "The requested tool `splunk__RunSearch` for this `use_tool` call required `input` to be an object, yet a string was provided. The system could not coerce this value. Please provide the correct schema next call.";

fn wrapped(body: &str) -> String {
    format!("<system-reminder>\n{body}\n</system-reminder>")
}

fn string_schema() -> serde_json::Value {
    serde_json::json!({"type": "object", "properties": {"input": {"type": "string"}}})
}

async fn open_actor() -> (
    SessionActor,
    tokio::sync::mpsc::UnboundedReceiver<SessionEvent>,
) {
    let (gateway_tx, mut gateway_rx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
    let (persistence_tx, _persistence_rx) =
        tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
    let (actor, event_rx) = create_test_actor_ex(0, 256_000, 85, gateway_tx, persistence_tx).await;
    tokio::task::spawn_local(async move {
        while let Some(msg) = gateway_rx.recv().await {
            if let fuigo_acp_lib::AcpClientMessage::SessionNotification(args) = msg {
                let _ = args.response_tx.send(Ok(()));
            }
        }
    });
    (actor, event_rx)
}

async fn use_tool_actor() -> (
    SessionActor,
    tokio::sync::mpsc::UnboundedReceiver<SessionEvent>,
) {
    let (actor, event_rx) = open_actor().await;
    *actor.agent.borrow_mut() =
        test_agent_with_tools(vec![fuigo_tools::registry::types::ToolConfig::for_tool::<
            fuigo_tools::implementations::use_tool::UseTool,
        >()])
        .await;
    (actor, event_rx)
}

fn seed(actor: &SessionActor, schema: serde_json::Value) {
    actor.tool_metadata_snapshot.lock().unwrap().tools.push(
        crate::session::tool_index::ToolMetadata {
            qualified_name: SPLUNK.to_owned(),
            server_name: "splunk".to_owned(),
            tool_name: "RunSearch".to_owned(),
            description: String::new(),
            parameters: vec!["input".to_owned()],
            input_schema: schema,
        },
    );
}

async fn prepare(actor: &SessionActor, name: &str, arguments: &str) -> PreparedToolCall {
    let call = ToolCallResponse {
        id: "call-1".to_owned(),
        kind: "function".to_owned(),
        function: crate::sampling::types::ToolCallFunction::new(name, arguments),
    };
    let mut deferred = Vec::new();
    match tokio::time::timeout(
        Duration::from_secs(10),
        actor.prepare_tool_call(call, &mut deferred),
    )
    .await
    .expect("prepare_tool_call must not hang (a hang means a permission prompt was issued)")
    .expect("prepare_tool_call must not error")
    {
        Ok(prepared) => prepared,
        Err(blocked) => panic!("prepare must return the call, got {blocked:?}"),
    }
}

fn permission_raw_inputs(
    event_rx: &mut tokio::sync::mpsc::UnboundedReceiver<SessionEvent>,
) -> (Option<serde_json::Value>, Option<serde_json::Value>) {
    let mut early = None;
    let mut later = None;
    while let Ok(event) = event_rx.try_recv() {
        let SessionEvent::Notification(SessionNotification::Acp(notification)) = event else {
            continue;
        };
        match notification.update {
            acp::SessionUpdate::ToolCall(call) => early = call.raw_input,
            acp::SessionUpdate::ToolCallUpdate(update) if update.fields.raw_input.is_some() => {
                later = update.fields.raw_input;
            }
            _ => {}
        }
    }
    (early, later)
}

fn statuses(
    event_rx: &mut tokio::sync::mpsc::UnboundedReceiver<SessionEvent>,
) -> Vec<acp::ToolCallStatus> {
    let mut statuses = Vec::new();
    while let Ok(event) = event_rx.try_recv() {
        let SessionEvent::Notification(SessionNotification::Acp(notification)) = event else {
            continue;
        };
        if let acp::SessionUpdate::ToolCallUpdate(update) = notification.update
            && let Some(status) = update.fields.status
        {
            statuses.push(status);
        }
    }
    statuses
}

async fn chat_history(actor: &SessionActor, call_id: &str) -> String {
    actor
        .chat_state_handle
        .get_conversation()
        .await
        .iter()
        .rev()
        .find_map(|item| match item {
            ConversationItem::ToolResult(result) if result.tool_call_id == call_id => {
                Some(result.content.to_string())
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing chat history tool result {call_id}"))
}

async fn push_mcp(
    actor: &SessionActor,
    call_id: &str,
    note: Option<&str>,
    parsed_args: &serde_json::Value,
    output: ToolOutput,
    prompt_text: &str,
) {
    actor
        .handle_bridge_tool_success(BridgeToolSuccess {
            tool_call_id: &acp::ToolCallId::new(call_id),
            call_id,
            requested_tool_name: "use_tool",
            effective_tool_name: SPLUNK,
            drained: DrainedToolSuccess::new(ToolRunResult {
                output,
                prompt_text: prompt_text.to_owned(),
                effective_tool_name: None,
            }),
            concatenated_json_count: 0,
            coercion_note: note,
            model_id: "test-model",
            tool_parsed_args: parsed_args,
            model_output_override: None,
        })
        .await
        .expect("bridge success");
}

#[tokio::test(flavor = "current_thread")]
async fn use_tool_coerces_before_permission_and_appends_reminder() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (actor, mut event_rx) = use_tool_actor().await;
            seed(&actor, string_schema());
            let arguments =
                r#"{"tool_name":"splunk__RunSearch","tool_input":{"input":{"SPL":"index=main"}}}"#;
            let prepared = prepare(&actor, "use_tool", arguments).await;
            assert_eq!(prepared.raw_arguments, arguments);
            assert_eq!(
                prepared
                    .parsed_args
                    .pointer("/tool_input/input")
                    .and_then(|v| v.as_str()),
                Some(COMPACT)
            );
            assert_eq!(
                prepared.coercion_note.as_deref(),
                Some(wrapped(SPLUNK_BODY).as_str())
            );
            let (early, later) = permission_raw_inputs(&mut event_rx);
            assert!(
                early
                    .as_ref()
                    .and_then(|v| v.pointer("/tool_input/input"))
                    .is_some_and(|v| v.is_object()),
                "early frame may still show the object: {early:?}"
            );
            assert_eq!(
                later
                    .as_ref()
                    .and_then(|v| v.pointer("/tool_input/input"))
                    .and_then(|v| v.as_str()),
                Some(COMPACT)
            );

            let note = prepared
                .coercion_note
                .clone()
                .expect("prepare produces the reminder");
            push_mcp(
                &actor,
                "call-ok",
                Some(note.as_str()),
                &prepared.parsed_args,
                ToolOutput::MCP(MCPOutput::okay_output(
                    SPLUNK.into(),
                    "splunk".into(),
                    "splunk-rows".into(),
                )),
                "splunk-rows",
            )
            .await;
            let ok_history = chat_history(&actor, "call-ok").await;
            assert!(ok_history.contains("splunk-rows"), "{ok_history}");
            assert!(ok_history.contains(&note), "{ok_history}");
            assert_eq!(
                statuses(&mut event_rx).as_slice(),
                &[acp::ToolCallStatus::Completed]
            );

            push_mcp(
                &actor,
                "call-err",
                Some(note.as_str()),
                &prepared.parsed_args,
                ToolOutput::MCP(MCPOutput::errored(
                    SPLUNK.into(),
                    "splunk".into(),
                    "splunk-failed".into(),
                )),
                "splunk-failed",
            )
            .await;
            let err_history = chat_history(&actor, "call-err").await;
            assert!(err_history.contains("splunk-failed"), "{err_history}");
            assert!(err_history.ends_with(note.as_str()), "{err_history}");
            let server_at = err_history.find("splunk-failed").expect("server text");
            let reminder_at = err_history.rfind("<system-reminder>").expect("reminder");
            assert!(server_at < reminder_at, "{err_history}");
            assert_eq!(
                statuses(&mut event_rx).as_slice(),
                &[acp::ToolCallStatus::Failed]
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn could_not_coerce_still_prepares_and_appends_reminder() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (actor, _event_rx) = use_tool_actor().await;
            seed(
                &actor,
                serde_json::json!({"type": "object", "properties": {"input": {"type": "object"}}}),
            );
            let arguments =
                r#"{"tool_name":"splunk__RunSearch","tool_input":{"input":"not json"}}"#;
            let prepared = prepare(&actor, "use_tool", arguments).await;
            assert_eq!(
                prepared
                    .parsed_args
                    .pointer("/tool_input/input")
                    .and_then(|v| v.as_str()),
                Some("not json")
            );
            let note = prepared.coercion_note.expect("could not coerce reminds");
            assert_eq!(note, wrapped(COULD_NOT));
            push_mcp(
                &actor,
                "call-bad",
                Some(note.as_str()),
                &prepared.parsed_args,
                ToolOutput::MCP(MCPOutput::errored(
                    SPLUNK.into(),
                    "splunk".into(),
                    "server said no".into(),
                )),
                "server said no",
            )
            .await;
            let bad_history = chat_history(&actor, "call-bad").await;
            assert!(bad_history.contains("server said no"), "{bad_history}");
            assert!(bad_history.ends_with(note.as_str()), "{bad_history}");
            let server_at = bad_history.find("server said no").expect("server text");
            let reminder_at = bad_history.rfind("<system-reminder>").expect("reminder");
            assert!(server_at < reminder_at, "{bad_history}");
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn missing_schema_row_leaves_arguments_unchanged() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (actor, _event_rx) = use_tool_actor().await;
            let arguments =
                r#"{"tool_name":"splunk__RunSearch","tool_input":{"input":{"SPL":"index=main"}}}"#;
            let prepared = prepare(&actor, "use_tool", arguments).await;
            assert_eq!(
                prepared.parsed_args,
                serde_json::from_str::<serde_json::Value>(arguments).expect("arguments are json")
            );
            assert!(prepared.coercion_note.is_none());
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn string_tool_input_root_is_parsed_before_permission() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (actor, mut event_rx) = use_tool_actor().await;
            seed(&actor, string_schema());
            let arguments = r#"{"tool_name":"splunk__RunSearch","tool_input":"{\"input\":{\"SPL\":\"index=main\"}}"}"#;
            let prepared = prepare(&actor, "use_tool", arguments).await;
            assert!(prepared.parsed_args.pointer("/tool_input").is_some_and(|v| v.is_object()));
            assert_eq!(
                prepared.parsed_args.pointer("/tool_input/input").and_then(|v| v.as_str()),
                Some(COMPACT)
            );
            let (early, later) = permission_raw_inputs(&mut event_rx);
            assert!(early.as_ref().and_then(|v| v.pointer("/tool_input")).is_some_and(|v| v.is_string()));
            assert!(later.as_ref().and_then(|v| v.pointer("/tool_input")).is_some_and(|v| v.is_object()));
            assert_eq!(
                later.as_ref().and_then(|v| v.pointer("/tool_input/input")).and_then(|v| v.as_str()),
                Some(COMPACT)
            );
            let note = prepared.coercion_note.expect("root parse reminds");
            assert!(note.contains("required the arguments to be an object"), "{note}");
            assert!(note.contains("required `input` to be a string"), "{note}");
        })
        .await;
}

/// u35 g10 (Fable r9 Medium): the ACP call carries the permission check's flag to dispatch: a read-only-list
/// approval is judged by the runner, an always-approve one is not.
#[tokio::test(flavor = "current_thread")]
async fn u35_g10_prepared_call_carries_the_permission_flag() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (mut actor, _event_rx) = open_actor().await;
            let cwd = fuigo_paths::AbsPathBuf::new(std::path::PathBuf::from(actor.session_info.cwd.clone()))
                .unwrap_or_else(|_| fuigo_paths::AbsPathBuf::new(crate::test_support::abs_tmp()).unwrap());
            let (gateway_tx, _gateway_rx) = tokio::sync::mpsc::unbounded_channel();
            let (handle, _events) = fuigo_workspace::permission::spawn_permission_manager(
                actor.session_info.id.clone(),
                fuigo_acp_lib::AcpAgentGatewaySender::new(gateway_tx),
                cwd,
                fuigo_workspace::permission::ClientType::Generic,
                None,
                vec![],
                vec![],
                false,
                None,
            );
            actor.permissions = handle;
            let tool = |id: &str| fuigo_tools::registry::types::ToolConfig::from_id(id.to_owned());
            *actor.agent.borrow_mut() = test_agent_with_tools(vec![
                tool("FuigoBuild:run_terminal_cmd"),
                tool("FuigoBuild:get_task_output"),
                tool("FuigoBuild:kill_task"),
            ])
            .await;
            let listed = prepare(&actor, "run_terminal_cmd", r#"{"command":"ls -la","description":"u35"}"#).await;
            assert!(listed.approved_without_grant, "the read-only lists approved it");
            actor.permissions.set_yolo_mode(true);
            let yolo = prepare(&actor, "run_terminal_cmd", r#"{"command":"ls -la","description":"u35"}"#).await;
            assert!(!yolo.approved_without_grant, "always-approve is an override");
        })
        .await;
}

/// u35 g11 (Astra r10 High): an OpenCode bash call runs in its `workdir`, so every repository check runs there too: a
/// nested repository whose config runs a program (`core.fsmonitor`) makes `git status` there ask, though the session
/// directory is clean. u35 g12 (Fable r11 Low): the client answers every ask with allow and records it, so the test
/// proves which call asked (and what about) instead of reading a timeout; both calls are bounded.
#[tokio::test(flavor = "current_thread")]
async fn u35_g11_opencode_workdir_is_judged_where_the_command_runs() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (mut actor, _event_rx) = open_actor().await;
            let session_dir = std::path::PathBuf::from(actor.session_info.cwd.clone());
            let nested = session_dir.join("u35-g11-nested");
            std::fs::create_dir_all(&nested).unwrap();
            let repo = git2::Repository::init(&nested).expect("init the nested repository");
            repo.config().unwrap().set_str("core.fsmonitor", "./payload").unwrap();
            let cwd = fuigo_paths::AbsPathBuf::new(session_dir.clone()).unwrap();
            let (gateway_tx, mut gateway_rx) =
                tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
            let asks: std::rc::Rc<std::cell::RefCell<Vec<acp::RequestPermissionRequest>>> = Default::default();
            let recorded = std::rc::Rc::clone(&asks);
            tokio::task::spawn_local(async move {
                while let Some(message) = gateway_rx.recv().await {
                    if let fuigo_acp_lib::AcpClientMessage::RequestPermission(args) = message {
                        recorded.borrow_mut().push(args.request.clone());
                        let _ = args.response_tx.send(Ok(acp::RequestPermissionResponse::new(
                            acp::RequestPermissionOutcome::Selected(acp::SelectedPermissionOutcome::new(
                                acp::PermissionOptionId::new("allow-once"),
                            )),
                        )));
                    }
                }
            });
            let (handle, _events) = fuigo_workspace::permission::spawn_permission_manager(
                actor.session_info.id.clone(),
                fuigo_acp_lib::AcpAgentGatewaySender::new(gateway_tx),
                cwd,
                fuigo_workspace::permission::ClientType::Generic,
                None,
                vec![],
                vec![],
                false,
                None,
            );
            actor.permissions = handle;
            let tool = |id: &str| fuigo_tools::registry::types::ToolConfig::from_id(id.to_owned());
            *actor.agent.borrow_mut() = test_agent_with_tools(vec![tool("OpenCode:bash")]).await;
            let here = prepare(&actor, "bash", r#"{"command":"git status","description":"u35"}"#).await;
            assert!(here.approved_without_grant, "the session directory is clean: the read-only lists approve it");
            assert!(asks.borrow().is_empty(), "the session-directory call did not ask");
            let call = ToolCallResponse {
                id: "call-2".to_owned(),
                kind: "function".to_owned(),
                function: crate::sampling::types::ToolCallFunction::new(
                    "bash",
                    r#"{"command":"git status","description":"u35","workdir":"u35-g11-nested"}"#,
                ),
            };
            let mut deferred = Vec::new();
            let nested = tokio::time::timeout(Duration::from_secs(10), actor.prepare_tool_call(call, &mut deferred))
                .await
                .expect("the asked call resolves once the client answers")
                .expect("prepare_tool_call must not error")
                .unwrap_or_else(|blocked| panic!("the answered call must be prepared, got {blocked:?}"));
            assert!(!nested.approved_without_grant, "the user's answer approved it");
            let asks = asks.borrow();
            assert_eq!(asks.len(), 1, "the nested repository's config runs a program: the call asks");
            let asked = serde_json::to_string(&asks[0]).unwrap();
            assert!(asked.contains("git status") && asked.contains(r#""toolCallId":"call-2""#), "{asked}");
        })
        .await;
}
