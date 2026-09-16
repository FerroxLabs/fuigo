use super::support::*;
use super::*;
use fuigo_test_support::sse::{
    responses_api_reasoning_then_tool_call_events, responses_api_script_exact,
};
use fuigo_test_support::{MockInferenceServer, ScriptedResponse};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

/// `SessionActor` turn futures overflow the default test thread stack.
pub(super) fn block_on_session(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(f)
        .expect("spawn large-stack test thread")
        .join()
        .expect("test thread");
}

pub(super) fn current_thread_local<F>(f: F)
where
    F: Future<Output = ()> + 'static,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    tokio::task::LocalSet::new().block_on(&rt, f);
}

pub(super) const TODO_ARGS: &str = r#"{"todos":[{"id":"t1","content":"poll","status":"completed"}]}"#;
/// A `search_replace` call: an edit, so a non-yolo permission manager always prompts for it.
const SEARCH_REPLACE_ARGS: &str =
    r#"{"file_path":"/tmp/permission-hook.txt","old_string":"a","new_string":"b"}"#;

/// Acks like [`drain_gateway`] but keeps the hook events for the one test that asserts on them.
fn capture_hook_events(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<fuigo_acp_lib::AcpClientMessage>,
) -> std::rc::Rc<std::cell::RefCell<Vec<serde_json::Value>>> {
    let fired = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let sink = fired.clone();
    tokio::task::spawn_local(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                fuigo_acp_lib::AcpClientMessage::SessionNotification(args) => {
                    let _ = args.response_tx.send(Ok(()));
                }
                fuigo_acp_lib::AcpClientMessage::ExtNotification(args)
                    if args.request.method.as_ref() == "fuigo/hooks/event" =>
                {
                    sink.borrow_mut()
                        .push(serde_json::from_str(args.request.params.get()).unwrap());
                }
                _ => {}
            }
        }
    });
    fired
}

/// Answers **every** `PersistenceMsg` that carries a `respond_to`, so a driven turn can only fail
/// for the reason a test is actually injecting and never because "the persistence actor is gone".
///
/// `flush` decides what the turn-end fsync barrier (`FlushAndAck`) returns; that is the only fault
/// this stub can inject. The variants without a `respond_to` are fire-and-forget writes with no
/// caller waiting on them, so dropping those is not observable.
///
/// `ExecutionState` is the arm that has to do real work: a turn with `max_turns` set opens a
/// durable execution record before the first model call (`SessionActor::handle_turn_input`), reads
/// it once per sampling round and mutates it on every admission, so a stubbed `Ok` would make the
/// bounded-execution state machine meaningless. It is applied against a real temp dir, the same way
/// `execution_state::tests::fixture_actor` and the bounded-compaction fixture do.
pub(super) fn spawn_persistence_stub(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<PersistenceMsg>,
    flush: fn() -> std::io::Result<()>,
) {
    let execution_dir = tempfile::tempdir().expect("execution state dir");
    tokio::task::spawn_local(async move {
        // Held for the lifetime of the drain so the execution record outlives the turn.
        let execution_dir = execution_dir;
        while let Some(msg) = rx.recv().await {
            match msg {
                PersistenceMsg::FlushAndAck { respond_to } => {
                    let _ = respond_to.send(flush());
                }
                PersistenceMsg::ExecutionState {
                    mutation,
                    respond_to,
                } => {
                    let _ = respond_to.send(
                        crate::session::execution_state::apply(execution_dir.path(), mutation)
                            .await,
                    );
                }
                PersistenceMsg::PresentationHints { respond_to, .. }
                | PersistenceMsg::ReplaceChatHistoryForStripAndAck { respond_to, .. }
                | PersistenceMsg::DeleteGoalModeState { respond_to }
                | PersistenceMsg::WorkflowRunStateAndAck { respond_to, .. }
                | PersistenceMsg::ProbeWritable { respond_to } => {
                    let _ = respond_to.send(Ok(()));
                }
                PersistenceMsg::CommitCompactionAndAck { respond_to, .. } => {
                    let _ = respond_to.send(Ok(()));
                }
                PersistenceMsg::AppendUpdateDurablyAndAck { respond_to, .. } => {
                    let _ = respond_to.send(Ok(()));
                }
                PersistenceMsg::AppendCwdSwitchAndAck { respond_to, .. } => {
                    let _ = respond_to.send(Ok(fuigo_chat_state::StrictAppendAck::Appended));
                }
                PersistenceMsg::CopyFile { one_shot } => {
                    let _ = one_shot.send(Ok(
                        crate::session::persistence::SessionStateCopy { files: Vec::new() },
                    ));
                }
                // Fire-and-forget: no `respond_to`, so nothing is waiting on these.
                _ => {}
            }
        }
    });
}

/// Injects ENOSPC on the turn-end flush barrier, and only there.
fn drain_persistence_flush_enospc(rx: tokio::sync::mpsc::UnboundedReceiver<PersistenceMsg>) {
    spawn_persistence_stub(rx, || {
        Err(std::io::Error::from(std::io::ErrorKind::StorageFull))
    });
}

/// `permission_gateway` installs a non-yolo permission manager and the read+edit toolset, so a
/// scripted `search_replace` call prompts the client and the client's answer decides the turn.
pub(super) async fn actor_with_mock_sampler(
    server: &MockInferenceServer,
    persistence_tx: tokio::sync::mpsc::UnboundedSender<PersistenceMsg>,
    gateway_tx: tokio::sync::mpsc::UnboundedSender<fuigo_acp_lib::AcpClientMessage>,
    max_turns: Option<usize>,
    permission_gateway: Option<fuigo_acp_lib::AcpAgentGatewaySender>,
) -> Arc<SessionActor> {
    let sampling_cfg = fuigo_sampler::SamplerConfig {
        api_key: Some("test-key".to_string()),
        base_url: server.url(),
        model: "test".to_string(),
        api_backend: fuigo_sampler::ApiBackend::Responses,
        context_window: 256_000,
        max_retries: Some(0),
        idle_timeout_secs: Some(30),
        ..Default::default()
    };
    let (sampler_event_tx, sampler_event_rx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_sampler::SamplingEvent>();
    let sampler_handle = fuigo_sampler::SamplerActor::spawn(
        sampling_cfg,
        fuigo_sampler::RetryPolicy {
            max_retries: 0,
            rate_limit_retry_threshold: 0,
            ..Default::default()
        },
        sampler_event_tx,
    );

    let mut actor = create_test_actor(0, 256_000, 85, gateway_tx, persistence_tx).await;
    actor.sampler_handle = sampler_handle;
    actor.max_turns = max_turns;
    if let Some(gateway) = permission_gateway {
        *actor.agent.borrow_mut() = test_agent_with_tools(read_and_edit_toolset()).await;
        install_permission_manager(&mut actor, /* yolo */ false, gateway);
    } else {
        *actor.agent.borrow_mut() = test_fuigo_build_agent_with_todo().await;
    }

    let mut cfg = actor
        .chat_state_handle
        .get_sampling_config()
        .await
        .expect("test actor has sampling config");
    cfg.base_url = server.url();
    cfg.api_backend = fuigo_sampling_types::ApiBackend::Responses;
    cfg.model = "test".to_string();
    actor.chat_state_handle.update_sampling_config(cfg);
    let mut creds = actor.chat_state_handle.get_credentials().await;
    creds.api_key = Some("test-key".to_string());
    actor.chat_state_handle.update_credentials(creds);

    actor
        .workspace_ops
        .bind_local_session(
            &actor.session_id_string(),
            actor.tool_context.cwd.as_path().to_path_buf(),
            actor.tool_context.hunk_tracker_handle.clone(),
            actor.agent.borrow().tool_bridge().toolset(),
            None,
        )
        .expect("bind_local_session");

    let actor = Arc::new(actor);
    {
        let drainer = actor.clone();
        let mut sampler_event_rx = sampler_event_rx;
        tokio::task::spawn_local(async move {
            while let Some(event) = sampler_event_rx.recv().await {
                drainer.handle_sampling_event(event).await;
            }
        });
    }
    actor
}

pub(super) async fn run_prompt(
    actor: &Arc<SessionActor>,
    prompt_id: &str,
) -> Result<crate::session::commands::PromptTurnOk, acp::Error> {
    let prompt_blocks = vec![acp::ContentBlock::Text(acp::TextContent::new(
        "hello".to_string(),
    ))];
    tokio::time::timeout(
        Duration::from_secs(60),
        actor.handle_prompt(
            prompt_id,
            prompt_blocks,
            PromptMode::Agent,
            None,
            None,
            None,
            None,
            true,
            /* send_now */ false,
            None,
            None,
            None,
        ),
    )
    .await
    .expect("turn must finish within timeout")
}

/// This is also the one test that drives a real turn into `StopFailure`.
/// Deleting the report in the turn's error arm leaves a host that watched the turn start waiting forever.
#[test]
fn completed_turn_flush_enospc_returns_error_and_reports_stop_failure() {
    block_on_session(|| {
        current_thread_local(async {
            let server = MockInferenceServer::start()
                .await
                .expect("mock inference server");
            server.enqueue_response(
                "/v1/responses",
                ScriptedResponse::sse(responses_api_script_exact("done", "test")),
            );

            let (gateway_tx, gateway_rx) =
                tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
            let fired = capture_hook_events(gateway_rx);
            let (persistence_tx, persistence_rx) =
                tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
            drain_persistence_flush_enospc(persistence_rx);

            let actor =
                actor_with_mock_sampler(&server, persistence_tx, gateway_tx, None, None).await;
            let mut hooks = crate::extensions::hooks::ClientHooks::new();
            hooks.insert(
                fuigo_hooks::event::HookEventName::StopFailure,
                vec![crate::extensions::hooks::ClientHookGroup {
                    matcher: None,
                    callback_ids: vec!["cb".to_string()],
                    timeout: None,
                }],
            );
            *actor.client_hooks.borrow_mut() = hooks;
            let queue = super::turn_end_hooks::TurnEndQueue::spawn(actor.clone());

            let error = run_prompt(&actor, "disk-full-completed")
                .await
                .expect_err("completed turn must fail when flush hits ENOSPC");
            queue.drain().await;

            assert_eq!(error.message, "No space left on device");
            let fired = fired.borrow();
            assert_eq!(fired.len(), 1);
            assert_eq!(fired[0]["hookEventName"], "stop_failure");
        });
    });
}

/// Answers the tool-call permission prompt with `Cancelled`, which is what a user pressing Esc
/// on the prompt sends; the turn then ends `TurnOutcome::Cancelled`.
fn drain_gateway_cancelling_permission(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<fuigo_acp_lib::AcpClientMessage>,
) {
    tokio::task::spawn_local(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                fuigo_acp_lib::AcpClientMessage::SessionNotification(args) => {
                    let _ = args.response_tx.send(Ok(()));
                }
                fuigo_acp_lib::AcpClientMessage::RequestPermission(args) => {
                    let _ = args
                        .response_tx
                        .send(Ok(acp::RequestPermissionResponse::new(
                            acp::RequestPermissionOutcome::Cancelled,
                        )));
                }
                _ => {}
            }
        }
    });
}

/// The turn-end flush barrier is the LAST thing a cancelled turn does, and it fails here with
/// ENOSPC. `handle_turn_input` may only rewrite a `Completed`/`StationarityEnded` outcome into a
/// disk-full error; a cancellation the user asked for must still come back as `Cancelled`, or the
/// host is told its Esc failed with a storage error it cannot act on.
///
/// The cancellation is a real one: the client answers the tool-call permission prompt with
/// `Cancelled`, which is what a user pressing Esc on that prompt sends, and the turn ends
/// `TurnOutcome::Cancelled`. It used to be driven by `max_turns = Some(0)`, which is not a
/// configuration the product can be in - `spawn.rs` refuses it with "max_turns must be greater
/// than 0" - and which under bounded execution failed the prompt outright instead of cancelling
/// it. The flag's own stop is a different outcome with a different completion kind
/// (`MaxTurnsReached`, reported to headless as `error_max_turns`); `max_turns_bound_tests` owns it.
#[test]
fn cancelled_turn_flush_enospc_still_reports_cancellation() {
    block_on_session(|| {
        current_thread_local(async {
            let server = MockInferenceServer::start()
                .await
                .expect("mock inference server");
            server.enqueue_response(
                "/v1/responses",
                ScriptedResponse::sse(responses_api_reasoning_then_tool_call_events(
                    "poll",
                    "disk-full-cancel-call",
                    "search_replace",
                    SEARCH_REPLACE_ARGS,
                    "test",
                )),
            );

            let (gateway_tx, gateway_rx) =
                tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
            let permission_gateway = fuigo_acp_lib::AcpAgentGatewaySender::new(gateway_tx.clone());
            drain_gateway_cancelling_permission(gateway_rx);
            let (persistence_tx, persistence_rx) =
                tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
            drain_persistence_flush_enospc(persistence_rx);

            let actor = actor_with_mock_sampler(
                &server,
                persistence_tx,
                gateway_tx,
                None,
                Some(permission_gateway),
            )
            .await;
            let ok = run_prompt(&actor, "disk-full-cancelled")
                .await
                .expect("a cancelled turn must not become a disk-full error");
            assert_eq!(ok.stop_reason, acp::StopReason::Cancelled);
        });
    });
}
