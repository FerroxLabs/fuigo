use super::*;
use fuigo_tools::implementations::fuigo_build::task::backend::{ChannelBackend, SubagentBackend};
use fuigo_tools::implementations::fuigo_build::task::coordinator::{
    ActiveMessageAdmission, ChildCompletion, ChildControl, ChildRunOutput, ChildRunRequest,
    ChildRunner, CoordinatorConfig, LocalBoxFuture, SendBoxFuture, StartedChild, SubagentProgress,
};
use fuigo_tools::implementations::fuigo_build::task::types::{
    ActiveAgentMessage, ActiveAgentMessageDelivery, ActiveAgentMessageOperation,
    ActiveAgentMessageOutcome,
    ActiveAgentMessageRequest, SubagentDescribeOutcome, SubagentOwner, SubagentRequest,
    SubagentValidateTypeOutcome,
};
use tokio_util::sync::CancellationToken;

const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

async fn await_with_timeout<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(TEST_TIMEOUT, future)
        .await
        .expect("child-runtime test wait timed out")
}

struct SnapshotProbeControl {
    runtime: ShellChildRuntime,
    live_prompt_index: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl ChildControl for SnapshotProbeControl {
    type ProgressFuture = LocalBoxFuture<SubagentProgress>;

    fn progress(&self) -> Self::ProgressFuture {
        self.runtime.progress()
    }

    fn send_active_message(
        &self,
        delivery: ActiveAgentMessageDelivery,
    ) -> SendBoxFuture<ActiveMessageAdmission> {
        let admission = self.runtime.send_active_message(delivery);
        self.live_prompt_index
            .store(8, std::sync::atomic::Ordering::Release);
        admission
    }

    fn cancel(&self) {
        self.runtime.cancel();
    }
}

struct SnapshotProbeRunner {
    child_cmd_tx: mpsc::UnboundedSender<SessionCommand>,
    receipt_sink: mpsc::Sender<PromptTurnReceipt>,
    handle_target_session_id: String,
    force_queue_envelope: bool,
    active_message_parent_session_id: String,
    live_prompt_index: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    started: mpsc::UnboundedSender<()>,
}

impl ChildRunner for SnapshotProbeRunner {
    type Control = SnapshotProbeControl;
    type CompletionData = ();
    type RunFuture = LocalBoxFuture<ChildRunOutput<()>>;
    type ValidateFuture = LocalBoxFuture<SubagentValidateTypeOutcome>;
    type DescribeFuture = LocalBoxFuture<SubagentDescribeOutcome>;

    fn run(&self, run: ChildRunRequest<Self::Control>) -> Self::RunFuture {
        let child_cmd_tx = self.child_cmd_tx.clone();
        let receipt_sink = self.receipt_sink.clone();
        let handle_target_session_id = self.handle_target_session_id.clone();
        let force_queue_envelope = self.force_queue_envelope;
        let active_message_parent_session_id = self.active_message_parent_session_id.clone();
        let live_prompt_index = std::sync::Arc::clone(&self.live_prompt_index);
        let started = self.started.clone();
        Box::pin(async move {
            let was_started = run
                .reporter
                .started(StartedChild {
                    child_session_id: run.request.id.clone(),
                    persona: None,
                    resumed_from: None,
                    child_cwd: String::new(),
                    worktree_path: None,
                    effective_model_id: "test-model".to_owned(),
                    definition_background: false,
                    control: SnapshotProbeControl {
                        runtime: ShellChildRuntime {
                            message_delivery:
                                crate::session::message_delivery::MessageDeliveryHandle::new(
                                    child_cmd_tx.clone(),
                                    handle_target_session_id,
                                ),
                            child_cmd_tx,
                            active_message_target_session_id: run.request.id.clone(),
                            child_signals: crate::session::signals::SessionSignalsHandle::new(),
                            _child_thread: Some(SessionThread::from_handle(std::thread::spawn(
                                || {},
                            ))),
                            receipt_sink,
                            force_queue_envelope,
                            active_message_parent_session_id,
                            active_message_parent_prompt_index: std::sync::Arc::clone(
                                &live_prompt_index,
                            ),
                        },
                        live_prompt_index,
                    },
                })
                .await;
            assert!(was_started, "probe child must become active");
            let _ = started.send(());
            std::future::pending().await
        })
    }

    fn validate_type(&self, _: String, _: String) -> Self::ValidateFuture {
        Box::pin(std::future::pending())
    }

    fn describe_type(&self, _: String, _: Option<String>, _: String) -> Self::DescribeFuture {
        Box::pin(std::future::pending())
    }

    fn on_completed(&self, _: ChildCompletion<()>) {}
}

fn request() -> SubagentRequest {
    SubagentRequest {
        id: "child".to_owned(),
        prompt: String::new(),
        description: String::new(),
        subagent_type: "general-purpose".to_owned(),
        parent_session_id: "parent".to_owned(),
        parent_prompt_id: None,
        resume_from: None,
        cwd: None,
        runtime_overrides: Default::default(),
        run_in_background: true,
        surface_completion: false,
        await_to_completion: false,
        fork_context: false,
        owner: SubagentOwner::Task,
        cancel_token: CancellationToken::new(),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn send_active_message_freezes_parent_turn_before_first_poll() {
    let local = tokio::task::LocalSet::new();
    await_with_timeout(local.run_until(async {
        let (coordinator_sender, receiver) =
            fuigo_tools::implementations::fuigo_build::task::coordinator::SubagentCoordinator::<
                SnapshotProbeRunner,
            >::channel();
        let backend = ChannelBackend::for_coordinator_session(coordinator_sender, "parent");
        let (child_cmd_tx, mut child_cmd_rx) = mpsc::unbounded_channel();
        let (receipt_sink, _receipt_stream) = mpsc::channel(1);
        let live_prompt_index =
            std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(7));
        let (started_tx, mut started_rx) = mpsc::unbounded_channel();
        let runner = SnapshotProbeRunner {
            child_cmd_tx,
            receipt_sink,
            handle_target_session_id: "child".to_owned(),
            force_queue_envelope: false,
            active_message_parent_session_id: "parent".to_owned(),
            live_prompt_index,
            started: started_tx,
        };
        let config = CoordinatorConfig {
            foreground_budget: TEST_TIMEOUT,
            ..Default::default()
        };
        let coordinator =
            fuigo_tools::implementations::fuigo_build::task::coordinator::SubagentCoordinator::from_channel(
                receiver,
                runner,
                config,
            );
        let coordinator_task = tokio::task::spawn_local(coordinator.run());
        let spawn_task = tokio::task::spawn_local({
            let backend = backend.clone();
            async move { backend.spawn(request(), None).await }
        });
        await_with_timeout(started_rx.recv())
            .await
            .expect("probe child started");

        let mut send = Box::pin(backend.send_active_message(
            ActiveAgentMessageRequest::try_new("child", "follow up").expect("valid message"),
        ));
        let command = tokio::select! {
            outcome = &mut send => panic!("message completed before host response: {outcome:?}"),
            command = child_cmd_rx.recv() => command.expect("parent-message command"),
        };
        let SessionCommand::ParentAgentMessage {
            parent_telemetry_ctx,
            respond_to,
            ..
        } = command
        else {
            panic!("expected parent-message command");
        };
        assert_eq!(parent_telemetry_ctx.session_id, "parent");
        assert_eq!(
            *await_with_timeout(parent_telemetry_ctx.prompt_index.lock()).await,
            7,
        );
        respond_to
            .send(ActiveMessageAdmission::Rejected)
            .expect("admission future remains open");
        assert_eq!(
            await_with_timeout(send).await,
            ActiveAgentMessageOutcome::NotActiveOrFinalizing
        );

        coordinator_task.abort();
        spawn_task.abort();
    }))
    .await;
}

async fn rejected_delivery(
    target: &str,
    operation: ActiveAgentMessageOperation,
    force_queue_envelope: bool,
) -> (ActiveAgentMessageOutcome, bool) {
    let (outcome, dispatched) = delivery_probe(target, operation, force_queue_envelope).await;
    (outcome, dispatched.is_some())
}

/// Drive one `send_active_message` through the real backend, coordinator and
/// `MessageDeliveryHandle`, and report both the sender's outcome and the
/// delivery the child host was handed (`None` when nothing was dispatched).
async fn delivery_probe(
    target: &str,
    operation: ActiveAgentMessageOperation,
    force_queue_envelope: bool,
) -> (
    ActiveAgentMessageOutcome,
    Option<(ActiveAgentMessage, ActiveAgentMessageOperation)>,
) {
    let local = tokio::task::LocalSet::new();
    await_with_timeout(local.run_until(async {
        let (coordinator_sender, receiver) =
            fuigo_tools::implementations::fuigo_build::task::coordinator::SubagentCoordinator::<
                SnapshotProbeRunner,
            >::channel();
        let backend = ChannelBackend::for_coordinator_session(coordinator_sender, "parent");
        let (child_cmd_tx, mut child_cmd_rx) = mpsc::unbounded_channel();
        let (receipt_sink, _receipt_stream) = mpsc::channel(1);
        let (started_tx, mut started_rx) = mpsc::unbounded_channel();
        let runner = SnapshotProbeRunner {
            child_cmd_tx,
            receipt_sink,
            handle_target_session_id: target.to_owned(),
            force_queue_envelope,
            active_message_parent_session_id: "parent".to_owned(),
            live_prompt_index: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            started: started_tx,
        };
        let coordinator = fuigo_tools::implementations::fuigo_build::task::coordinator::SubagentCoordinator::from_channel(
            receiver,
            runner,
            CoordinatorConfig {
                foreground_budget: TEST_TIMEOUT,
                ..Default::default()
            },
        );
        let coordinator_task = tokio::task::spawn_local(coordinator.run());
        let spawn_task = tokio::task::spawn_local({
            let backend = backend.clone();
            async move { backend.spawn(request(), None).await }
        });
        await_with_timeout(started_rx.recv())
            .await
            .expect("probe child started");

        // Poll send on the LocalSet while this task waits for the child command.
        // A pinned-but-unpolled future deadlocks Steer dispatch on current_thread.
        let send_task = tokio::task::spawn_local({
            let backend = backend.clone();
            async move {
                backend
                    .send_active_message(
                        ActiveAgentMessageRequest::try_new_with_operation(
                            "child",
                            "follow up",
                            operation,
                        )
                        .expect("valid message"),
                    )
                    .await
            }
        });
        // With a matching target and a well-formed envelope EVERY class is
        // authorized and dispatched, so the probe must await the command for
        // all three: a pinned-but-unpolled future deadlocks dispatch on
        // current_thread. The remaining cases are refused before dispatch.
        let (outcome, dispatched) = if target == "child" && !force_queue_envelope {
            let command = await_with_timeout(child_cmd_rx.recv())
                .await
                .expect("parent-agent message dispatched to the child host");
            let SessionCommand::ParentAgentMessage {
                respond_to,
                delivery,
                ..
            } = command
            else {
                panic!("expected parent-message command");
            };
            let dispatched = Some((delivery.message().clone(), delivery.operation()));
            respond_to
                .send(ActiveMessageAdmission::Rejected)
                .expect("admission future remains open");
            (
                await_with_timeout(send_task).await.expect("send task"),
                dispatched,
            )
        } else {
            let outcome = await_with_timeout(send_task).await.expect("send task");
            let dispatched = match child_cmd_rx.try_recv() {
                Ok(SessionCommand::ParentAgentMessage { delivery, .. }) => {
                    Some((delivery.message().clone(), delivery.operation()))
                }
                Ok(_) => panic!("expected parent-message command"),
                Err(_) => None,
            };
            (outcome, dispatched)
        };
        coordinator_task.abort();
        spawn_task.abort();
        (outcome, dispatched)
    }))
    .await
}

#[tokio::test]
async fn target_mismatch_rejects_without_dispatch() {
    let actual =
        rejected_delivery("different-child", ActiveAgentMessageOperation::Queue, false).await;
    assert_eq!(
        actual,
        (ActiveAgentMessageOutcome::NotActiveOrFinalizing, false)
    );
}

#[tokio::test]
async fn matched_steer_dispatches_to_the_child_host() {
    let actual = rejected_delivery("child", ActiveAgentMessageOperation::Steer, false).await;
    assert_eq!(
        actual,
        (ActiveAgentMessageOutcome::NotActiveOrFinalizing, true)
    );
}

#[tokio::test]
async fn matched_interject_dispatches_to_the_child_host() {
    let actual = rejected_delivery("child", ActiveAgentMessageOperation::Interject, false).await;
    assert_eq!(
        actual,
        (ActiveAgentMessageOutcome::NotActiveOrFinalizing, true)
    );
}

/// The engine half of `send_subagent_message`'s promise. Its description tells
/// the model that `queue`, `steer` and `interject` all land the same way and
/// that the class is only recorded; this proves the class travels no further
/// than the authorization gate. Each class reaches the child host as the SAME
/// `SessionCommand::ParentAgentMessage`, carrying the same message, and the
/// only thing that varies is the recorded label. From there
/// `admit_parent_agent_message` reads `delivery.message()` and commits through
/// `commit_queued_delivery` without ever consulting the operation. If a class
/// is ever given its own delivery, this test and the tool's golden description
/// (`tool_description_promises_only_the_delivery_the_engine_implements`) must
/// change together.
#[tokio::test]
async fn every_delivery_class_reaches_the_child_host_as_the_same_command() {
    let classes = [
        ActiveAgentMessageOperation::Queue,
        ActiveAgentMessageOperation::Steer,
        ActiveAgentMessageOperation::Interject,
    ];
    let mut dispatched = Vec::new();
    for operation in classes {
        let (outcome, delivered) = delivery_probe("child", operation, false).await;
        assert_eq!(outcome, ActiveAgentMessageOutcome::NotActiveOrFinalizing);
        dispatched.push(
            delivered.unwrap_or_else(|| panic!("{operation:?} must reach the child host")),
        );
    }

    // Same command, same message, for every class.
    for (message, _) in &dispatched {
        assert_eq!(message.text.as_ref(), "follow up");
        assert_eq!(message.sender_session_id, "parent");
        assert!(!message.message_id.is_empty());
    }

    // The class survives only as the label the sender chose.
    let labels: Vec<ActiveAgentMessageOperation> =
        dispatched.iter().map(|(_, label)| *label).collect();
    assert_eq!(labels, classes.to_vec());
}

#[tokio::test]
async fn malformed_operation_pair_is_unsupported_and_uncommitted() {
    let actual = rejected_delivery("child", ActiveAgentMessageOperation::Steer, true).await;
    assert_eq!(actual, (ActiveAgentMessageOutcome::Unsupported, false));
}

#[tokio::test]
async fn session_thread_exit_zero_timeout_is_a_single_observation() {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let thread = SessionThread::from_handle(std::thread::spawn(move || {
        let _ = rx.recv();
    }));
    assert!(!await_session_thread_exit(&thread, std::time::Duration::ZERO).await);
    assert_eq!(
        UnpromotedResourceFate::from_thread_exit(false),
        UnpromotedResourceFate::Preserve
    );
    assert!(!UnpromotedResourceFate::Preserve.should_release());
    drop(tx);
}

#[tokio::test]
async fn finished_session_thread_releases_unpromoted_resources() {
    let thread = SessionThread::from_handle(std::thread::spawn(|| {}));
    assert!(await_session_thread_exit(&thread, std::time::Duration::from_secs(1)).await);
    assert!(UnpromotedResourceFate::from_thread_exit(true).should_release());
}
