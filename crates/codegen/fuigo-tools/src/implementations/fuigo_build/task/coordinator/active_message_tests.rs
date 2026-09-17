use std::future::Future;

use futures::StreamExt;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use super::super::*;
use super::*;
use crate::implementations::fuigo_build::task::active_message::SubagentActiveMessageRequest;
use crate::implementations::fuigo_build::task::types::{
    ActiveAgentMessageOperation, ActiveAgentMessageRequest, SubagentResumeLookup,
};

const TEST_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

struct AdmissionCall {
    message_id: String,
    late_delivery: ActiveAgentMessageDelivery,
    release: oneshot::Sender<ActiveMessageAdmission>,
}

struct TestControl {
    admissions: mpsc::UnboundedSender<AdmissionCall>,
}

impl ChildControl for TestControl {
    type ProgressFuture = std::future::Ready<SubagentProgress>;

    fn progress(&self) -> Self::ProgressFuture {
        std::future::ready(SubagentProgress::default())
    }

    fn send_active_message(
        &self,
        delivery: ActiveAgentMessageDelivery,
    ) -> SendBoxFuture<ActiveMessageAdmission> {
        let (release, released) = oneshot::channel();
        let _ = self.admissions.send(AdmissionCall {
            message_id: delivery.message().message_id.clone(),
            late_delivery: delivery.clone(),
            release,
        });
        Box::pin(async move {
            let admission = released
                .await
                .unwrap_or(ActiveMessageAdmission::ChannelClosed);
            if admission == ActiveMessageAdmission::Admitted
                && delivery.commit_admission(|| ()).is_none()
            {
                return ActiveMessageAdmission::Rejected;
            }
            admission
        })
    }

    fn cancel(&self) {}
}

struct TestRunner;

struct PanickingRunner {
    admissions: mpsc::UnboundedSender<AdmissionCall>,
    started: mpsc::UnboundedSender<()>,
    panic: std::sync::Arc<tokio::sync::Notify>,
    completions: mpsc::UnboundedSender<SubagentResult>,
}

impl ChildRunner for PanickingRunner {
    type Control = TestControl;
    type CompletionData = ();
    type RunFuture = SendBoxFuture<ChildRunOutput<()>>;
    type ValidateFuture = SendBoxFuture<SubagentValidateTypeOutcome>;
    type DescribeFuture = SendBoxFuture<SubagentDescribeOutcome>;

    fn run(&self, run: ChildRunRequest<Self::Control>) -> Self::RunFuture {
        let admissions = self.admissions.clone();
        let started = self.started.clone();
        let panic = self.panic.clone();
        Box::pin(async move {
            let request = run.request;
            assert!(
                run.reporter
                    .started(StartedChild {
                        child_session_id: request.id.clone(),
                        persona: None,
                        resumed_from: None,
                        child_cwd: String::new(),
                        worktree_path: None,
                        effective_model_id: "test-model".to_owned(),
                        definition_background: false,
                        control: TestControl { admissions },
                    })
                    .await
            );
            let _ = started.send(());
            panic.notified().await;
            panic!("runner panic after promotion");
        })
    }

    fn validate_type(&self, _: String, _: String) -> Self::ValidateFuture {
        Box::pin(std::future::pending())
    }

    fn describe_type(&self, _: String, _: Option<String>, _: String) -> Self::DescribeFuture {
        Box::pin(std::future::pending())
    }

    fn on_completed(&self, completion: ChildCompletion<()>) {
        let _ = self.completions.send(completion.result);
    }
}

impl ChildRunner for TestRunner {
    type Control = TestControl;
    type CompletionData = ();
    type RunFuture = SendBoxFuture<ChildRunOutput<()>>;
    type ValidateFuture = SendBoxFuture<SubagentValidateTypeOutcome>;
    type DescribeFuture = SendBoxFuture<SubagentDescribeOutcome>;

    fn run(&self, _: ChildRunRequest<Self::Control>) -> Self::RunFuture {
        Box::pin(std::future::pending())
    }

    fn validate_type(&self, _: String, _: String) -> Self::ValidateFuture {
        Box::pin(std::future::pending())
    }

    fn describe_type(&self, _: String, _: Option<String>, _: String) -> Self::DescribeFuture {
        Box::pin(std::future::pending())
    }

    fn on_completed(&self, _: ChildCompletion<()>) {}
}

type TestCoordinator = SubagentCoordinator<TestRunner>;

/// Any runner the shared helpers can drive: the test control and unit completion data.
trait TestChildRunner: ChildRunner<Control = TestControl, CompletionData = ()> {}
impl<R: ChildRunner<Control = TestControl, CompletionData = ()>> TestChildRunner for R {}

/// Runs each spawn: reports it, promotes the child, and finishes on `finish`.
struct WakeRunner {
    admissions: mpsc::UnboundedSender<AdmissionCall>,
    runs: mpsc::UnboundedSender<crate::implementations::fuigo_build::task::types::SubagentRequest>,
    finish: std::sync::Arc<tokio::sync::Notify>,
}

impl ChildRunner for WakeRunner {
    type Control = TestControl;
    type CompletionData = ();
    type RunFuture = SendBoxFuture<ChildRunOutput<()>>;
    type ValidateFuture = SendBoxFuture<SubagentValidateTypeOutcome>;
    type DescribeFuture = SendBoxFuture<SubagentDescribeOutcome>;

    fn run(&self, run: ChildRunRequest<Self::Control>) -> Self::RunFuture {
        let admissions = self.admissions.clone();
        let runs = self.runs.clone();
        let finish = self.finish.clone();
        Box::pin(async move {
            let request = run.request;
            let _ = runs.send(request.clone());
            assert!(
                run.reporter
                    .started(StartedChild {
                        child_session_id: request.id.clone(),
                        persona: None,
                        resumed_from: request.resume_from.clone(),
                        child_cwd: String::new(),
                        worktree_path: None,
                        effective_model_id: "test-model".to_owned(),
                        definition_background: false,
                        control: TestControl { admissions },
                    })
                    .await
            );
            finish.notified().await;
            ChildRunOutput {
                result: SubagentResult {
                    success: true,
                    output: std::sync::Arc::from(request.prompt.as_str()),
                    subagent_id: request.id.clone(),
                    child_session_id: request.id.clone(),
                    ..Default::default()
                },
                completion_data: (),
                snapshot_ref: None,
            }
        })
    }

    fn validate_type(&self, _: String, _: String) -> Self::ValidateFuture {
        Box::pin(std::future::pending())
    }

    fn describe_type(&self, _: String, _: Option<String>, _: String) -> Self::DescribeFuture {
        Box::pin(std::future::pending())
    }

    fn supports_wake(&self) -> bool {
        true
    }

    fn on_completed(&self, _: ChildCompletion<()>) {}
}

type WakeCoordinator = SubagentCoordinator<WakeRunner>;

struct WakeFixture {
    runs:
        mpsc::UnboundedReceiver<crate::implementations::fuigo_build::task::types::SubagentRequest>,
    finish: std::sync::Arc<tokio::sync::Notify>,
}

fn wake_fixture() -> (
    WakeCoordinator,
    crate::implementations::fuigo_build::task::backend::SubagentCoordinatorSender,
    mpsc::UnboundedSender<AdmissionCall>,
    mpsc::UnboundedReceiver<AdmissionCall>,
) {
    let (coordinator, command_tx, admission_tx, admissions, _wake) = wake_fixture_with_runs();
    (coordinator, command_tx, admission_tx, admissions)
}

fn wake_fixture_with_runs() -> (
    WakeCoordinator,
    crate::implementations::fuigo_build::task::backend::SubagentCoordinatorSender,
    mpsc::UnboundedSender<AdmissionCall>,
    mpsc::UnboundedReceiver<AdmissionCall>,
    WakeFixture,
) {
    wake_fixture_with_limits(CoordinatorConfig::default().limits)
}

/// A wake fixture whose spawn admission can be saturated, so the wake's
/// `Enqueue` and `Reject` branches are reachable.
fn wake_fixture_with_limits(
    limits: crate::implementations::fuigo_build::task::admission::SubagentLimits,
) -> (
    WakeCoordinator,
    crate::implementations::fuigo_build::task::backend::SubagentCoordinatorSender,
    mpsc::UnboundedSender<AdmissionCall>,
    mpsc::UnboundedReceiver<AdmissionCall>,
    WakeFixture,
) {
    let config = CoordinatorConfig {
        limits,
        ..CoordinatorConfig::default()
    };
    let (command_tx, command_rx) =
        SubagentCoordinatorReceiver::with_capacity(MAX_ACTIVE_MESSAGE_ADMISSIONS);
    let (admission_tx, admissions) = mpsc::unbounded_channel();
    let (runs_tx, runs) = mpsc::unbounded_channel();
    let finish = std::sync::Arc::new(tokio::sync::Notify::new());
    let coordinator = SubagentCoordinator::from_channel(
        command_rx,
        WakeRunner {
            admissions: admission_tx.clone(),
            runs: runs_tx,
            finish: finish.clone(),
        },
        config,
    );
    (
        coordinator,
        command_tx,
        admission_tx,
        admissions,
        WakeFixture { runs, finish },
    )
}

/// Drive the coordinator's run futures and internal events until `done`.
async fn drive_until<R: ChildRunner>(
    coordinator: &mut SubagentCoordinator<R>,
    done: impl Fn(&InternalEvent<R::Control>) -> bool,
) {
    await_with_timeout(async {
        loop {
            tokio::select! {
                Some((id, output)) = coordinator.runs.next(), if !coordinator.runs.is_empty() => {
                    match output {
                        Ok(output) => coordinator.begin_terminalization(&id, output),
                        Err(_) => coordinator.begin_panicked_terminalization(&id),
                    }
                }
                Some(event) = coordinator.internal_rx.recv() => {
                    let is_done = done(&event);
                    coordinator.handle_internal(event);
                    if is_done {
                        return;
                    }
                }
            }
        }
    })
    .await;
}

/// Drive until the next child reports started.
async fn run_until_started<R: ChildRunner>(coordinator: &mut SubagentCoordinator<R>) {
    drive_until(coordinator, |event| {
        matches!(event, InternalEvent::Started { .. })
    })
    .await;
}

async fn resume_lookup(
    coordinator: &mut WakeCoordinator,
    source_id: &str,
    parent: &str,
) -> SubagentResumeLookup {
    let (respond_to, response) = oneshot::channel();
    coordinator.handle_internal(InternalEvent::ResumeSource {
        source_id: source_id.to_owned(),
        parent_session_id: parent.to_owned(),
        respond_to,
    });
    await_with_timeout(response)
        .await
        .expect("resume lookup response dropped")
}

#[tokio::test]
async fn message_to_completed_owned_child_wakes_same_id_resuming_from_itself() {
    let (mut coordinator, command_tx, admission_tx, mut admissions, mut wake) =
        wake_fixture_with_runs();
    insert_child(&mut coordinator, admission_tx, "child", "parent");
    finish_child(&mut coordinator, "child");
    assert!(coordinator.completed.contains_key("child"));

    let mut response = begin_send(&mut coordinator, &command_tx, "child", "parent");
    // The reply waits for the new incarnation to start; the record moved aside.
    assert!(response.try_recv().is_err());
    assert!(coordinator.pending.contains_key("child"));
    assert!(!coordinator.completed.contains_key("child"));
    assert!(!coordinator.completed_order.contains(&"child".to_owned()));
    assert!(coordinator.woken.contains_key("child"));
    // The runner resolves the wake's own resume source from the displaced record.
    assert!(matches!(
        resume_lookup(&mut coordinator, "child", "parent").await,
        SubagentResumeLookup::Completed(source) if source.child_session_id == "child"
    ));
    assert!(matches!(
        resume_lookup(&mut coordinator, "child", "foreign").await,
        SubagentResumeLookup::Missing
    ));

    run_until_started(&mut coordinator).await;
    let run = wake.runs.try_recv().expect("wake incarnation ran");
    assert_eq!(run.id, "child");
    assert_eq!(run.resume_from.as_deref(), Some("child"));
    assert_eq!(run.prompt, "follow up");
    assert!(!run.fork_context);
    assert!(run.run_in_background);
    assert_eq!(run.parent_prompt_id, None);
    assert_eq!(run.parent_session_id, "parent");
    let outcome = response_outcome(response).await;
    assert!(
        matches!(&outcome, ActiveAgentMessageOutcome::Accepted { message_id } if !message_id.is_empty()),
        "{outcome:?}"
    );
    // The text was the child's prompt: nothing is delivered a second time.
    assert!(admissions.try_recv().is_err());
    let active = coordinator
        .active
        .get("child")
        .expect("woken child is active");
    assert_eq!(active.resumed_from.as_deref(), Some("child"));
    assert!(matches!(
        resume_lookup(&mut coordinator, "child", "parent").await,
        SubagentResumeLookup::Active
    ));

    // A second message while it runs is an ordinary active-message delivery.
    let response = begin_send(&mut coordinator, &command_tx, "child", "parent");
    let call = recv_with_timeout(&mut admissions).await;
    let message_id = call.message_id.clone();
    release_admission(&mut coordinator, call, ActiveMessageAdmission::Admitted).await;
    assert_eq!(
        ActiveAgentMessageOutcome::Accepted { message_id },
        response_outcome(response).await
    );
}

#[tokio::test]
async fn woken_child_completion_replaces_the_displaced_record() {
    let (mut coordinator, command_tx, admission_tx, _admissions, mut wake) =
        wake_fixture_with_runs();
    insert_child(&mut coordinator, admission_tx, "child", "parent");
    finish_child(&mut coordinator, "child");
    let response = begin_send(&mut coordinator, &command_tx, "child", "parent");
    run_until_started(&mut coordinator).await;
    let _ = wake.runs.try_recv().expect("wake incarnation ran");
    assert!(matches!(
        response_outcome(response).await,
        ActiveAgentMessageOutcome::Accepted { .. }
    ));
    wake.finish.notify_one();
    await_with_timeout(async {
        while coordinator.active.contains_key("child") {
            let Some((id, output)) = coordinator.runs.next().await else {
                break;
            };
            match output {
                Ok(output) => coordinator.begin_terminalization(&id, output),
                Err(_) => coordinator.begin_panicked_terminalization(&id),
            }
        }
    })
    .await;
    let completed = coordinator.completed.get("child").expect("completed again");
    assert_eq!(completed.result.output.as_ref(), "follow up");
    assert_eq!(completed.resumed_from.as_deref(), Some("child"));
    assert!(!coordinator.woken.contains_key("child"));
    assert_eq!(
        coordinator
            .completed_order
            .iter()
            .filter(|id| id.as_str() == "child")
            .count(),
        1
    );
}

/// A wake that arrives at a saturated spawn limit under
/// `FUIGO_SUBAGENT_LIMIT_BEHAVIOR=fail` starts nothing, so the terminal record
/// it displaced must go back exactly where it was. Only the ResumeSource
/// lookup falls back to `woken`; if the restore is wrong, `get_task_output`
/// and every completed lookup return not-found for that child forever.
#[tokio::test]
async fn wake_rejected_at_the_spawn_limit_restores_the_displaced_completion() {
    let (mut coordinator, command_tx, admission_tx, _admissions, _wake) =
        wake_fixture_with_limits(
            crate::implementations::fuigo_build::task::admission::SubagentLimits {
                max_concurrent: 1,
                behavior: crate::implementations::fuigo_build::task::admission::LimitBehavior::Fail,
            },
        );
    insert_child(&mut coordinator, admission_tx.clone(), "child", "parent");
    finish_child(&mut coordinator, "child");
    // Saturate the parent's single slot so the wake cannot start.
    insert_child(&mut coordinator, admission_tx, "other", "parent");
    assert!(coordinator.completed.contains_key("child"));

    let response = begin_send(&mut coordinator, &command_tx, "child", "parent");

    assert_eq!(
        ActiveAgentMessageOutcome::NotActiveOrFinalizing,
        response_outcome(response).await
    );
    // Displaced record restored, and restored to the completed ORDER too.
    assert!(coordinator.completed.contains_key("child"));
    assert!(coordinator.completed_order.contains(&"child".to_owned()));
    assert!(!coordinator.woken.contains_key("child"));
    // Nothing was started or left parked.
    assert!(!coordinator.pending.contains_key("child"));
    assert!(!coordinator.queued.contains_id("child"));
    assert!(coordinator.spawn_ready.is_empty());
    // The restored record is reachable again as a resume source.
    assert!(matches!(
        resume_lookup(&mut coordinator, "child", "parent").await,
        SubagentResumeLookup::Completed(source) if source.child_session_id == "child"
    ));
}

/// A wake that arrives at a saturated spawn limit under the default `queue`
/// behaviour is queued, not rejected: the record STAYS in `woken` (the queued
/// incarnation will resume from it), the sender's reply stays outstanding, and
/// the park carries no deadline, so nothing expires it while the wake waits
/// for a slot. `deadline: None` is deliberate and matches upstream
/// (`coordinator/wake.rs`): the message text has already been committed as the
/// woken child's own prompt, so replying `NotAcceptedBeforeDeadline` would tell
/// the sender its text was dropped when the child is still going to run it.
#[tokio::test]
async fn wake_queued_at_the_spawn_limit_holds_the_record_and_never_expires() {
    let (mut coordinator, command_tx, admission_tx, _admissions, _wake) =
        wake_fixture_with_limits(
            crate::implementations::fuigo_build::task::admission::SubagentLimits {
                max_concurrent: 1,
                behavior:
                    crate::implementations::fuigo_build::task::admission::LimitBehavior::Queue,
            },
        );
    insert_child(&mut coordinator, admission_tx.clone(), "child", "parent");
    finish_child(&mut coordinator, "child");
    insert_child(&mut coordinator, admission_tx, "other", "parent");

    let mut response = begin_send(&mut coordinator, &command_tx, "child", "parent");

    // Queued, not started and not rejected.
    assert!(coordinator.queued.contains_id("child"));
    assert!(!coordinator.pending.contains_key("child"));
    // The displaced record stays aside until the queued incarnation finishes.
    assert!(coordinator.woken.contains_key("child"));
    assert!(!coordinator.completed.contains_key("child"));
    assert!(!coordinator.completed_order.contains(&"child".to_owned()));
    // It is still the resume source the queued incarnation will read.
    assert!(matches!(
        resume_lookup(&mut coordinator, "child", "parent").await,
        SubagentResumeLookup::Completed(source) if source.child_session_id == "child"
    ));
    // The sender is still waiting, and no deadline can cut the wait short.
    assert!(response.try_recv().is_err());
    assert!(!coordinator.spawn_ready.is_empty());
    assert!(coordinator.spawn_ready.deadlines().next().is_none());
    coordinator.expire_spawn_ready_messages(
        tokio::time::Instant::now() + std::time::Duration::from_secs(86_400),
    );
    assert!(!coordinator.spawn_ready.is_empty());
    assert!(response.try_recv().is_err());
}

fn fixture_with_capacity(
    active_message_capacity: usize,
) -> (
    TestCoordinator,
    crate::implementations::fuigo_build::task::backend::SubagentCoordinatorSender,
    mpsc::UnboundedSender<AdmissionCall>,
    mpsc::UnboundedReceiver<AdmissionCall>,
) {
    let config = CoordinatorConfig::default();
    let (command_tx, command_rx) =
        SubagentCoordinatorReceiver::with_capacity(active_message_capacity);
    let (admission_tx, admissions) = mpsc::unbounded_channel();
    let coordinator = SubagentCoordinator::from_channel(command_rx, TestRunner, config);
    (coordinator, command_tx, admission_tx, admissions)
}

fn fixture() -> (
    TestCoordinator,
    crate::implementations::fuigo_build::task::backend::SubagentCoordinatorSender,
    mpsc::UnboundedSender<AdmissionCall>,
    mpsc::UnboundedReceiver<AdmissionCall>,
) {
    fixture_with_capacity(MAX_ACTIVE_MESSAGE_ADMISSIONS)
}

fn insert_child<R: TestChildRunner>(
    coordinator: &mut SubagentCoordinator<R>,
    admissions: mpsc::UnboundedSender<AdmissionCall>,
    id: &str,
    parent: &str,
) {
    let mut request =
        crate::implementations::fuigo_build::task::coordinator::tests::request(id, true);
    request.parent_session_id = parent.to_owned();
    request.surface_completion = false;
    coordinator.active.insert(
        id.to_owned(),
        ActiveChild {
            request,
            started_at: std::time::Instant::now(),
            cancellation: CancellationToken::new(),
            spawn_reply: None,
            foreground_deadline: None,
            handle_only: true,
            definition_background: false,
            explicitly_killed: false,
            child_session_id: id.to_owned(),
            persona: None,
            resumed_from: None,
            child_cwd: String::new(),
            worktree_path: None,
            effective_model_id: "test-model".to_owned(),
            generation: ActiveChildGeneration::new(),
            active_messages: ActiveMessageLifecycle::default(),
            control: TestControl { admissions },
        },
    );
}

fn insert_pending<R: TestChildRunner>(
    coordinator: &mut SubagentCoordinator<R>,
    id: &str,
    parent: &str,
) {
    let mut request =
        crate::implementations::fuigo_build::task::coordinator::tests::request(id, true);
    request.parent_session_id = parent.to_owned();
    request.surface_completion = false;
    coordinator.pending.insert(
        id.to_owned(),
        PendingChild {
            request,
            started_at: std::time::Instant::now(),
            cancellation: CancellationToken::new(),
            spawn_reply: None,
            foreground_deadline: None,
            handle_only: true,
            explicitly_killed: false,
            launched: true,
        },
    );
}

fn promote_pending<R: TestChildRunner>(
    coordinator: &mut SubagentCoordinator<R>,
    admissions: mpsc::UnboundedSender<AdmissionCall>,
    id: &str,
) {
    let (respond_to, _response) = oneshot::channel();
    coordinator.handle_internal(InternalEvent::Started {
        subagent_id: id.to_owned(),
        child: StartedChild {
            child_session_id: id.to_owned(),
            persona: None,
            resumed_from: None,
            child_cwd: String::new(),
            worktree_path: None,
            effective_model_id: "test-model".to_owned(),
            definition_background: false,
            control: TestControl { admissions },
        },
        respond_to,
    });
}

fn begin_send<R: TestChildRunner>(
    coordinator: &mut SubagentCoordinator<R>,
    command_tx: &crate::implementations::fuigo_build::task::backend::SubagentCoordinatorSender,
    id: &str,
    parent: &str,
) -> oneshot::Receiver<ActiveAgentMessageOutcome> {
    let (respond_to, response_rx) = oneshot::channel();
    let request = SubagentActiveMessageRequest {
        request: ActiveAgentMessageRequest::try_new(id, "follow up").unwrap(),
        parent_session_id: parent.to_owned(),
        respond_to,
    };
    command_tx
        .try_send_active_message(request)
        .expect("active-message ingress open");
    let ingress = coordinator
        .active_message_ingress
        .as_mut()
        .expect("paired active-message ingress")
        .try_recv()
        .expect("active-message command queued");
    coordinator.handle_send_active_message(ingress);
    response_rx
}

async fn await_with_timeout<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(TEST_WAIT, future)
        .await
        .expect("active-message test wait timed out")
}

async fn recv_with_timeout<T>(receiver: &mut mpsc::UnboundedReceiver<T>) -> T {
    await_with_timeout(receiver.recv())
        .await
        .expect("active-message test channel closed")
}

async fn finish_next_active_message<R: TestChildRunner>(coordinator: &mut SubagentCoordinator<R>) {
    let completion = await_with_timeout(coordinator.active_messages.next())
        .await
        .expect("active-message completion stream ended");
    coordinator.finish_active_message(completion);
}

async fn release_admission<R: TestChildRunner>(
    coordinator: &mut SubagentCoordinator<R>,
    call: AdmissionCall,
    admission: ActiveMessageAdmission,
) {
    call.release
        .send(admission)
        .expect("active-message admission future dropped");
    finish_next_active_message(coordinator).await;
}

async fn response_outcome(
    response: oneshot::Receiver<ActiveAgentMessageOutcome>,
) -> ActiveAgentMessageOutcome {
    await_with_timeout(response)
        .await
        .expect("active-message response dropped")
}

async fn response_outcome_result(response: oneshot::Receiver<SubagentResult>) -> SubagentResult {
    await_with_timeout(response)
        .await
        .expect("spawn result dropped")
}

async fn finalization_outcome(response: oneshot::Receiver<bool>) -> bool {
    await_with_timeout(response)
        .await
        .expect("active-message finalization response dropped")
}

fn finish_child<R: TestChildRunner>(coordinator: &mut SubagentCoordinator<R>, id: &str) {
    coordinator.begin_terminalization(
        id,
        ChildRunOutput {
            result: SubagentResult {
                success: true,
                subagent_id: id.to_owned(),
                child_session_id: id.to_owned(),
                ..Default::default()
            },
            completion_data: (),
            snapshot_ref: None,
        },
    );
}

#[tokio::test]
async fn legacy_public_active_message_event_fails_closed() {
    let (tx, rx) = mpsc::unbounded_channel();
    let coordinator = SubagentCoordinator::new(rx, TestRunner, CoordinatorConfig::default());
    let actor = tokio::spawn(coordinator.run());
    let (respond_to, response) = oneshot::channel();
    tx.send(
        crate::implementations::fuigo_build::task::types::SubagentEvent::SendActiveMessage(
            SubagentActiveMessageRequest {
                request: ActiveAgentMessageRequest::try_new("child", "follow up").unwrap(),
                parent_session_id: "parent".to_owned(),
                respond_to,
            },
        ),
    )
    .unwrap();
    assert_eq!(
        ActiveAgentMessageOutcome::Unsupported,
        response_outcome(response).await
    );
    drop(tx);
    await_with_timeout(actor).await.unwrap();
}

#[tokio::test]
async fn two_sequential_admissions_keep_child_open() {
    let (mut coordinator, command_tx, admission_tx, mut admissions) = fixture();
    insert_child(&mut coordinator, admission_tx, "child", "parent");
    for _ in 0..2 {
        let (respond_to, response) = oneshot::channel();
        let request = SubagentActiveMessageRequest {
            request: ActiveAgentMessageRequest::try_new_with_operation(
                "child",
                "follow up",
                ActiveAgentMessageOperation::Steer,
            )
            .unwrap(),
            parent_session_id: "parent".to_owned(),
            respond_to,
        };
        command_tx
            .try_send_active_message(request)
            .expect("active-message ingress open");
        let ingress = coordinator
            .active_message_ingress
            .as_mut()
            .expect("paired active-message ingress")
            .try_recv()
            .expect("active-message command queued");
        coordinator.handle_send_active_message(ingress);

        let call = recv_with_timeout(&mut admissions).await;
        let message_id = call.message_id.clone();
        assert_eq!(
            call.late_delivery.operation(),
            ActiveAgentMessageOperation::Steer
        );
        release_admission(&mut coordinator, call, ActiveMessageAdmission::Admitted).await;
        assert_eq!(
            ActiveAgentMessageOutcome::Accepted { message_id },
            response_outcome(response).await
        );
    }
}

#[tokio::test]
async fn finalizing_first_and_send_first_are_deterministic() {
    let (mut coordinator, command_tx, admission_tx, mut admissions) = fixture();
    insert_child(&mut coordinator, admission_tx.clone(), "closed", "parent");
    let (closed_tx, closed_rx) = oneshot::channel();
    coordinator.handle_active_message_finalizing("closed".to_owned(), closed_tx);
    assert!(finalization_outcome(closed_rx).await);
    assert_eq!(
        ActiveAgentMessageOutcome::NotActiveOrFinalizing,
        response_outcome(begin_send(
            &mut coordinator,
            &command_tx,
            "closed",
            "parent"
        ))
        .await
    );
    assert!(admissions.try_recv().is_err());

    insert_child(&mut coordinator, admission_tx, "held", "parent");
    let admitted = begin_send(&mut coordinator, &command_tx, "held", "parent");
    let call = recv_with_timeout(&mut admissions).await;
    let (finalize_tx, mut finalize_rx) = oneshot::channel();
    coordinator.handle_active_message_finalizing("held".to_owned(), finalize_tx);
    assert!(finalize_rx.try_recv().is_err());
    assert_eq!(
        ActiveAgentMessageOutcome::NotActiveOrFinalizing,
        response_outcome(begin_send(&mut coordinator, &command_tx, "held", "parent")).await
    );
    assert!(admissions.try_recv().is_err());
    release_admission(&mut coordinator, call, ActiveMessageAdmission::Admitted).await;
    assert!(matches!(
        response_outcome(admitted).await,
        ActiveAgentMessageOutcome::Accepted { .. }
    ));
    assert!(finalization_outcome(finalize_rx).await);
}

#[tokio::test]
async fn finalization_waits_for_both_admissions_on_one_child() {
    let (mut coordinator, command_tx, admission_tx, mut admissions) = fixture();
    insert_child(&mut coordinator, admission_tx, "held", "parent");

    let first_response = begin_send(&mut coordinator, &command_tx, "held", "parent");
    let first_call = recv_with_timeout(&mut admissions).await;
    let second_response = begin_send(&mut coordinator, &command_tx, "held", "parent");
    let second_call = recv_with_timeout(&mut admissions).await;
    let (finalize_tx, mut finalize_rx) = oneshot::channel();
    coordinator.handle_active_message_finalizing("held".to_owned(), finalize_tx);

    release_admission(
        &mut coordinator,
        first_call,
        ActiveMessageAdmission::Rejected,
    )
    .await;
    assert_eq!(
        ActiveAgentMessageOutcome::NotActiveOrFinalizing,
        response_outcome(first_response).await
    );
    assert!(finalize_rx.try_recv().is_err());

    release_admission(
        &mut coordinator,
        second_call,
        ActiveMessageAdmission::Rejected,
    )
    .await;
    assert_eq!(
        ActiveAgentMessageOutcome::NotActiveOrFinalizing,
        response_outcome(second_response).await
    );
    assert!(finalization_outcome(finalize_rx).await);
}

#[tokio::test]
async fn admission_results_release_lifecycle_accounting() {
    let results = [
        (
            ActiveMessageAdmission::Unsupported,
            ActiveAgentMessageOutcome::Unsupported,
        ),
        (
            ActiveMessageAdmission::ChannelClosed,
            ActiveAgentMessageOutcome::ChannelClosed,
        ),
        (
            ActiveMessageAdmission::Rejected,
            ActiveAgentMessageOutcome::NotActiveOrFinalizing,
        ),
    ];
    for (admission, expected) in results {
        let (mut coordinator, command_tx, admission_tx, mut admissions) = fixture();
        insert_child(&mut coordinator, admission_tx, "child", "parent");
        let response = begin_send(&mut coordinator, &command_tx, "child", "parent");
        let call = recv_with_timeout(&mut admissions).await;
        let (finalize_tx, finalize_rx) = oneshot::channel();
        coordinator.handle_active_message_finalizing("child".to_owned(), finalize_tx);

        release_admission(&mut coordinator, call, admission).await;
        assert_eq!(expected, response_outcome(response).await);
        assert!(finalization_outcome(finalize_rx).await);
    }
}

#[tokio::test]
async fn per_child_admission_cap_rejects_before_invoking_host() {
    let (mut coordinator, command_tx, admission_tx, mut admissions) = fixture();
    insert_child(&mut coordinator, admission_tx, "child", "parent");

    let mut responses = Vec::new();
    let mut calls = Vec::new();
    for _ in 0..MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_CHILD {
        responses.push(begin_send(&mut coordinator, &command_tx, "child", "parent"));
        calls.push(recv_with_timeout(&mut admissions).await);
    }

    assert_eq!(
        ActiveAgentMessageOutcome::Saturated {
            max_in_flight: MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_CHILD,
        },
        response_outcome(begin_send(&mut coordinator, &command_tx, "child", "parent")).await
    );
    assert!(admissions.try_recv().is_err());

    for (response, call) in responses.into_iter().zip(calls) {
        release_admission(&mut coordinator, call, ActiveMessageAdmission::Rejected).await;
        assert_eq!(
            ActiveAgentMessageOutcome::NotActiveOrFinalizing,
            response_outcome(response).await
        );
    }
}

#[tokio::test]
async fn global_ingress_cap_rejects_before_enqueue_and_drains() {
    const CAPACITY: usize = 3;
    let (mut coordinator, command_tx, admission_tx, mut admissions) =
        fixture_with_capacity(CAPACITY);
    for id in ["first", "second", "third", "overflow"] {
        insert_child(&mut coordinator, admission_tx.clone(), id, "parent");
    }

    let mut responses = Vec::new();
    let mut calls = Vec::new();
    for id in ["first", "second", "third"] {
        responses.push(begin_send(&mut coordinator, &command_tx, id, "parent"));
        calls.push(recv_with_timeout(&mut admissions).await);
    }
    let (respond_to, overflow_response) = oneshot::channel();
    assert_eq!(
        Err(CAPACITY),
        command_tx.try_send_active_message(SubagentActiveMessageRequest {
            request: ActiveAgentMessageRequest::try_new("overflow", "follow up").unwrap(),
            parent_session_id: "parent".to_owned(),
            respond_to,
        })
    );
    assert!(await_with_timeout(overflow_response).await.is_err());
    assert!(admissions.try_recv().is_err());

    for (response, call) in responses.into_iter().zip(calls) {
        release_admission(&mut coordinator, call, ActiveMessageAdmission::Rejected).await;
        assert_eq!(
            ActiveAgentMessageOutcome::NotActiveOrFinalizing,
            response_outcome(response).await
        );
    }
    let (respond_to, response) = oneshot::channel();
    assert!(
        command_tx
            .try_send_active_message(SubagentActiveMessageRequest {
                request: ActiveAgentMessageRequest::try_new("overflow", "follow up").unwrap(),
                parent_session_id: "parent".to_owned(),
                respond_to,
            })
            .is_ok()
    );
    drop(coordinator);
    assert!(await_with_timeout(response).await.is_err());
}

#[tokio::test(start_paused = true)]
async fn admission_deadline_revocation_is_definite_and_unblocks_finalization() {
    let (mut coordinator, command_tx, admission_tx, mut admissions) = fixture();
    insert_child(&mut coordinator, admission_tx, "child", "parent");
    let response = begin_send(&mut coordinator, &command_tx, "child", "parent");
    let held = recv_with_timeout(&mut admissions).await;
    let (finalize_tx, mut finalize_rx) = oneshot::channel();
    coordinator.handle_active_message_finalizing("child".to_owned(), finalize_tx);
    assert!(finalize_rx.try_recv().is_err());

    tokio::time::advance(ACTIVE_MESSAGE_ADMISSION_TIMEOUT).await;
    finish_next_active_message(&mut coordinator).await;
    assert_eq!(
        ActiveAgentMessageOutcome::NotAcceptedBeforeDeadline,
        response_outcome(response).await
    );
    assert!(finalization_outcome(finalize_rx).await);
    assert!(held.release.send(ActiveMessageAdmission::Admitted).is_err());
    assert!(held.late_delivery.commit_admission(|| ()).is_none());
    assert_eq!(coordinator.active_messages.len(), 0);
}

#[tokio::test]
async fn cancellation_revocation_is_definite_and_settles_finalization() {
    let (mut coordinator, command_tx, admission_tx, mut admissions) = fixture();
    insert_child(&mut coordinator, admission_tx, "child", "parent");
    let response = begin_send(&mut coordinator, &command_tx, "child", "parent");
    let held = recv_with_timeout(&mut admissions).await;
    let (finalize_tx, finalize_rx) = oneshot::channel();
    coordinator.handle_active_message_finalizing("child".to_owned(), finalize_tx);
    coordinator
        .active
        .get("child")
        .expect("active child")
        .cancellation
        .cancel();

    finish_next_active_message(&mut coordinator).await;
    assert_eq!(
        ActiveAgentMessageOutcome::NotAcceptedBeforeDeadline,
        response_outcome(response).await
    );
    assert!(finalization_outcome(finalize_rx).await);
    assert!(held.release.send(ActiveMessageAdmission::Admitted).is_err());
    assert!(held.late_delivery.commit_admission(|| ()).is_none());
    assert_eq!(coordinator.active_messages.len(), 0);
}

#[tokio::test(start_paused = true)]
async fn claimed_deadline_race_remains_uncertain_and_finalization_unclean() {
    let (mut coordinator, command_tx, admission_tx, mut admissions) = fixture();
    insert_child(&mut coordinator, admission_tx, "child", "parent");
    let response = begin_send(&mut coordinator, &command_tx, "child", "parent");
    let held = recv_with_timeout(&mut admissions).await;
    held.late_delivery.mark_admission_uncertain();
    let (finalize_tx, finalize_rx) = oneshot::channel();
    coordinator.handle_active_message_finalizing("child".to_owned(), finalize_tx);

    tokio::time::advance(ACTIVE_MESSAGE_ADMISSION_TIMEOUT).await;
    finish_next_active_message(&mut coordinator).await;

    assert_eq!(
        ActiveAgentMessageOutcome::AdmissionUncertain,
        response_outcome(response).await
    );
    assert!(!finalization_outcome(finalize_rx).await);
}

#[tokio::test]
async fn unsettled_completion_before_runner_output_marks_terminal_result_failed() {
    let (mut coordinator, command_tx, admission_tx, mut admissions) = fixture();
    insert_child(&mut coordinator, admission_tx, "child", "parent");
    let response = begin_send(&mut coordinator, &command_tx, "child", "parent");
    let call = recv_with_timeout(&mut admissions).await;
    call.late_delivery.mark_admission_uncertain();
    coordinator
        .active
        .get("child")
        .expect("active child")
        .cancellation
        .cancel();
    finish_next_active_message(&mut coordinator).await;
    assert_eq!(
        ActiveAgentMessageOutcome::AdmissionUncertain,
        response_outcome(response).await
    );
    finish_child(&mut coordinator, "child");
    let result = &coordinator
        .completed
        .get("child")
        .expect("completed")
        .result;
    assert!(!result.success);
    assert!(result.cancelled);
}

#[tokio::test]
async fn runner_output_parked_before_unsettled_completion_is_failed() {
    let (mut coordinator, command_tx, admission_tx, mut admissions) = fixture();
    insert_child(&mut coordinator, admission_tx, "child", "parent");
    let response = begin_send(&mut coordinator, &command_tx, "child", "parent");
    let call = recv_with_timeout(&mut admissions).await;
    call.late_delivery.mark_admission_uncertain();

    finish_child(&mut coordinator, "child");
    assert!(coordinator.terminal_outputs.contains_key("child"));
    coordinator
        .active
        .get("child")
        .expect("active child")
        .cancellation
        .cancel();
    finish_next_active_message(&mut coordinator).await;
    assert_eq!(
        ActiveAgentMessageOutcome::AdmissionUncertain,
        response_outcome(response).await
    );
    let result = &coordinator
        .completed
        .get("child")
        .expect("completed")
        .result;
    assert!(!result.success);
    assert!(result.cancelled);
}

#[tokio::test]
async fn runner_panic_parks_until_uncertain_admission_terminalizes_failed() {
    let (command_tx, command_rx) = SubagentCoordinatorReceiver::with_capacity(1);
    let (admission_tx, mut admissions) = mpsc::unbounded_channel();
    let (started_tx, mut started) = mpsc::unbounded_channel();
    let panic = std::sync::Arc::new(tokio::sync::Notify::new());
    let (completion_tx, mut completions) = mpsc::unbounded_channel();
    let actor = tokio::spawn(
        SubagentCoordinator::from_channel(
            command_rx,
            PanickingRunner {
                admissions: admission_tx,
                started: started_tx,
                panic: panic.clone(),
                completions: completion_tx,
            },
            CoordinatorConfig::default(),
        )
        .run(),
    );
    let backend =
        crate::implementations::fuigo_build::task::backend::ChannelBackend::for_coordinator_session(
            command_tx, "parent",
        );
    let mut spawn = tokio::spawn({
        let backend = backend.clone();
        async move {
            let mut request =
                crate::implementations::fuigo_build::task::coordinator::tests::request(
                    "panic-child",
                    false,
                );
            request.parent_session_id = "parent".to_owned();
            crate::implementations::fuigo_build::task::backend::SubagentBackend::spawn(
                &backend, request, None,
            )
            .await
        }
    });
    recv_with_timeout(&mut started).await;
    let response = tokio::spawn({
        let backend = backend.clone();
        async move {
            crate::implementations::fuigo_build::task::backend::SubagentBackend::send_active_message(
                &backend,
                ActiveAgentMessageRequest::try_new("panic-child", "follow up").unwrap(),
            )
            .await
        }
    });
    let call = recv_with_timeout(&mut admissions).await;
    call.late_delivery.mark_admission_uncertain();

    panic.notify_one();
    let short_wait = std::time::Duration::from_millis(100);
    assert!(
        tokio::time::timeout(short_wait, completions.recv())
            .await
            .is_err()
    );
    assert!(tokio::time::timeout(short_wait, &mut spawn).await.is_err());

    call.release
        .send(ActiveMessageAdmission::Rejected)
        .expect("selected admission future alive");
    assert_eq!(
        ActiveAgentMessageOutcome::AdmissionUncertain,
        await_with_timeout(response).await.unwrap()
    );
    let result = recv_with_timeout(&mut completions).await;
    assert!(!result.success);
    assert!(result.cancelled);
    assert_eq!(Some("Subagent runtime panicked"), result.error.as_deref());
    let spawned_result = await_with_timeout(&mut spawn).await.unwrap().unwrap();
    assert!(!spawned_result.success);
    assert!(spawned_result.cancelled);
    drop(backend);
    actor.abort();
    let _ = await_with_timeout(actor).await;
}

#[tokio::test]
async fn coordinator_terminalization_parks_output_until_admission_settles() {
    let (mut coordinator, command_tx, admission_tx, mut admissions) = fixture();
    insert_child(&mut coordinator, admission_tx, "child", "parent");
    let response = begin_send(&mut coordinator, &command_tx, "child", "parent");
    let call = recv_with_timeout(&mut admissions).await;

    finish_child(&mut coordinator, "child");
    assert!(coordinator.active.contains_key("child"));
    assert!(coordinator.terminal_outputs.contains_key("child"));
    assert!(!coordinator.completed.contains_key("child"));

    release_admission(&mut coordinator, call, ActiveMessageAdmission::Rejected).await;
    assert_eq!(
        ActiveAgentMessageOutcome::NotActiveOrFinalizing,
        response_outcome(response).await
    );
    assert!(!coordinator.active.contains_key("child"));
    assert!(!coordinator.terminal_outputs.contains_key("child"));
    assert!(coordinator.completed.contains_key("child"));
}

#[tokio::test]
async fn stale_settled_rejection_remains_definite() {
    let (mut coordinator, command_tx, admission_tx, mut admissions) = fixture();
    insert_child(&mut coordinator, admission_tx.clone(), "reused", "parent");
    let response = begin_send(&mut coordinator, &command_tx, "reused", "parent");
    let call = recv_with_timeout(&mut admissions).await;
    finish_child(&mut coordinator, "reused");
    coordinator.completed.remove("reused");
    coordinator.completed_order.clear();
    insert_child(&mut coordinator, admission_tx, "reused", "parent");

    release_admission(&mut coordinator, call, ActiveMessageAdmission::Rejected).await;

    assert_eq!(
        ActiveAgentMessageOutcome::NotActiveOrFinalizing,
        response_outcome(response).await
    );
}

#[tokio::test]
async fn stale_admission_and_completed_lookup_preserve_terminal_authority() {
    let (mut coordinator, command_tx, admission_tx, mut admissions) = fixture();
    insert_child(&mut coordinator, admission_tx.clone(), "reused", "parent");
    let response = begin_send(&mut coordinator, &command_tx, "reused", "parent");
    let call = recv_with_timeout(&mut admissions).await;
    finish_child(&mut coordinator, "reused");
    coordinator.completed.remove("reused");
    coordinator.completed_order.clear();
    insert_child(&mut coordinator, admission_tx.clone(), "reused", "parent");
    let late_delivery = call.late_delivery.clone();
    release_admission(&mut coordinator, call, ActiveMessageAdmission::Admitted).await;
    assert_eq!(
        ActiveAgentMessageOutcome::AdmissionUncertain,
        response_outcome(response).await
    );
    assert!(late_delivery.commit_admission(|| ()).is_none());

    insert_child(&mut coordinator, admission_tx, "completed", "parent");
    finish_child(&mut coordinator, "completed");
    for id in ["completed", "missing"] {
        assert_eq!(
            ActiveAgentMessageOutcome::NotFoundOrNotOwned,
            response_outcome(begin_send(&mut coordinator, &command_tx, id, "foreign")).await
        );
    }
    // `TestRunner` does not support a wake, so the completed child stays down.
    assert!(!coordinator.runner.supports_wake());
    assert_eq!(
        ActiveAgentMessageOutcome::NotActiveOrFinalizing,
        response_outcome(begin_send(
            &mut coordinator,
            &command_tx,
            "completed",
            "parent"
        ))
        .await
    );
    assert!(coordinator.completed.contains_key("completed"));
    assert!(!coordinator.pending.contains_key("completed"));
}

#[tokio::test]
async fn actor_drop_classifies_channel_closure_from_lease_proof() {
    for (is_claimed, expected) in [
        (false, ActiveAgentMessageOutcome::ChannelClosed),
        (true, ActiveAgentMessageOutcome::AdmissionUncertain),
    ] {
        let (mut coordinator, command_tx, admission_tx, mut admissions) = fixture();
        insert_child(&mut coordinator, admission_tx, "child", "parent");
        let response = begin_send(&mut coordinator, &command_tx, "child", "parent");
        let held = recv_with_timeout(&mut admissions).await;
        if is_claimed {
            held.late_delivery.mark_admission_uncertain();
        }

        drop(coordinator);
        assert_eq!(expected, response_outcome(response).await);
        assert!(held.late_delivery.commit_admission(|| ()).is_none());
    }
}

#[tokio::test]
async fn dropped_pre_commit_completion_is_channel_closed() {
    let (mut coordinator, command_tx, admission_tx, mut admissions) = fixture();
    insert_child(&mut coordinator, admission_tx, "child", "parent");
    let response = begin_send(&mut coordinator, &command_tx, "child", "parent");
    let call = recv_with_timeout(&mut admissions).await;
    call.release
        .send(ActiveMessageAdmission::ChannelClosed)
        .expect("admission waiter");
    let completion = await_with_timeout(coordinator.active_messages.next())
        .await
        .expect("completion");
    assert!(completion.is_settled);
    drop(completion);
    assert_eq!(
        ActiveAgentMessageOutcome::ChannelClosed,
        response_outcome(response).await
    );
}

#[tokio::test]
async fn dropped_admitted_completion_is_uncertain_and_finalization_unclean() {
    let (mut coordinator, command_tx, admission_tx, mut admissions) = fixture();
    insert_child(&mut coordinator, admission_tx, "child", "parent");
    let response = begin_send(&mut coordinator, &command_tx, "child", "parent");
    let call = recv_with_timeout(&mut admissions).await;
    call.release
        .send(ActiveMessageAdmission::Admitted)
        .expect("admission waiter");
    let completion = await_with_timeout(coordinator.active_messages.next())
        .await
        .expect("completion");
    assert!(completion.is_settled);
    drop(completion);
    assert_eq!(
        ActiveAgentMessageOutcome::AdmissionUncertain,
        response_outcome(response).await
    );
    let (finalize_tx, mut finalize_rx) = oneshot::channel();
    coordinator.handle_active_message_finalizing("child".to_owned(), finalize_tx);
    assert!(
        finalize_rx.try_recv().is_err(),
        "lost admitted completion must leave finalization in-flight"
    );
    drop(coordinator);
    assert!(!finalization_outcome(finalize_rx).await);
}

#[tokio::test]
async fn held_admission_is_independent_per_child() {
    let (mut coordinator, command_tx, admission_tx, mut admissions) = fixture();
    insert_child(&mut coordinator, admission_tx.clone(), "first", "parent");
    insert_child(&mut coordinator, admission_tx, "second", "parent");
    let first_response = begin_send(&mut coordinator, &command_tx, "first", "parent");
    let first_call = recv_with_timeout(&mut admissions).await;
    let (first_tx, mut first_rx) = oneshot::channel();
    coordinator.handle_active_message_finalizing("first".to_owned(), first_tx);
    let (second_tx, second_rx) = oneshot::channel();
    coordinator.handle_active_message_finalizing("second".to_owned(), second_tx);
    assert!(finalization_outcome(second_rx).await);
    assert!(first_rx.try_recv().is_err());
    release_admission(
        &mut coordinator,
        first_call,
        ActiveMessageAdmission::Rejected,
    )
    .await;
    assert_eq!(
        ActiveAgentMessageOutcome::NotActiveOrFinalizing,
        response_outcome(first_response).await
    );
    assert!(finalization_outcome(first_rx).await);
}

#[tokio::test]
async fn send_to_owned_pending_waits_until_started_then_admits() {
    let (mut coordinator, command_tx, admission_tx, mut admissions) = fixture();
    insert_pending(&mut coordinator, "child", "parent");
    let mut response = begin_send(&mut coordinator, &command_tx, "child", "parent");
    assert!(response.try_recv().is_err());

    promote_pending(&mut coordinator, admission_tx, "child");
    let call = recv_with_timeout(&mut admissions).await;
    let message_id = call.message_id.clone();
    release_admission(&mut coordinator, call, ActiveMessageAdmission::Admitted).await;
    assert_eq!(
        ActiveAgentMessageOutcome::Accepted { message_id },
        response_outcome(response).await
    );
}

#[tokio::test]
async fn send_to_owned_pending_that_fails_is_not_active() {
    let (mut coordinator, command_tx, _admission_tx, mut admissions) = fixture();
    insert_pending(&mut coordinator, "child", "parent");
    let response = begin_send(&mut coordinator, &command_tx, "child", "parent");
    assert!(admissions.try_recv().is_err());

    finish_child(&mut coordinator, "child");
    assert_eq!(
        ActiveAgentMessageOutcome::NotActiveOrFinalizing,
        response_outcome(response).await
    );
    assert!(admissions.try_recv().is_err());
}

#[tokio::test]
async fn send_to_owned_completed_without_wake_support_is_immediate() {
    let (mut coordinator, command_tx, admission_tx, _admissions) = fixture();
    insert_child(&mut coordinator, admission_tx, "child", "parent");
    finish_child(&mut coordinator, "child");
    assert!(!coordinator.runner.supports_wake());
    assert_eq!(
        ActiveAgentMessageOutcome::NotActiveOrFinalizing,
        response_outcome(begin_send(&mut coordinator, &command_tx, "child", "parent")).await
    );
    assert!(coordinator.completed.contains_key("child"));
}

/// The wake-capable fixture: `WakeRunner` runs each spawn, so a completed
/// child's message becomes a new incarnation of the same id.
#[tokio::test]
async fn send_to_completed_workflow_or_cancelled_child_does_not_start_replacement() {
    let (mut coordinator, command_tx, admission_tx, _admissions) = wake_fixture();
    insert_child(&mut coordinator, admission_tx.clone(), "wf", "parent");
    coordinator
        .active
        .get_mut("wf")
        .expect("active")
        .request
        .owner = crate::implementations::fuigo_build::task::types::SubagentOwner::workflow("run-1");
    finish_child(&mut coordinator, "wf");
    insert_child(&mut coordinator, admission_tx, "killed", "parent");
    coordinator.begin_terminalization(
        "killed",
        ChildRunOutput {
            result: SubagentResult {
                success: false,
                cancelled: true,
                subagent_id: "killed".to_owned(),
                child_session_id: "killed".to_owned(),
                ..Default::default()
            },
            completion_data: (),
            snapshot_ref: None,
        },
    );
    for id in ["wf", "killed"] {
        assert_eq!(
            ActiveAgentMessageOutcome::NotActiveOrFinalizing,
            response_outcome(begin_send(&mut coordinator, &command_tx, id, "parent")).await,
            "{id}"
        );
        assert!(!coordinator.pending.contains_key(id), "{id}");
        assert!(coordinator.completed.contains_key(id), "{id}");
    }
    assert_eq!(
        ActiveAgentMessageOutcome::NotFoundOrNotOwned,
        response_outcome(begin_send(&mut coordinator, &command_tx, "wf", "foreign")).await
    );
}

#[tokio::test]
async fn parent_session_cancel_unblocks_parked_send() {
    let (mut coordinator, command_tx, _admission_tx, mut admissions) = fixture();
    let spawn_result = insert_queued(&mut coordinator, "child", "parent");
    let mut response = begin_send(&mut coordinator, &command_tx, "child", "parent");
    assert!(response.try_recv().is_err());

    assert!(matches!(
        coordinator.cancel_parent_session(Some("parent")),
        crate::implementations::fuigo_build::task::types::SubagentCancelOutcome::Cancelled
    ));
    assert_eq!(
        ActiveAgentMessageOutcome::NotActiveOrFinalizing,
        response_outcome(response).await
    );
    let terminal = response_outcome_result(spawn_result).await;
    assert!(
        terminal.cancelled && !terminal.success,
        "session cancel must resolve a terminal result: {terminal:?}"
    );
    assert!(admissions.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn send_to_owned_pending_hits_spawn_ready_backstop() {
    let (mut coordinator, command_tx, _admission_tx, mut admissions) = fixture();
    insert_pending(&mut coordinator, "child", "parent");
    let response = begin_send(&mut coordinator, &command_tx, "child", "parent");
    tokio::time::advance(ACTIVE_MESSAGE_SPAWN_READY_TIMEOUT).await;
    coordinator.expire_spawn_ready_messages(tokio::time::Instant::now());
    assert_eq!(
        ActiveAgentMessageOutcome::NotAcceptedBeforeDeadline,
        response_outcome(response).await
    );
    assert!(admissions.try_recv().is_err());
}

fn insert_queued(
    coordinator: &mut TestCoordinator,
    id: &str,
    parent: &str,
) -> oneshot::Receiver<SubagentResult> {
    let mut request =
        crate::implementations::fuigo_build::task::coordinator::tests::request(id, true);
    request.parent_session_id = parent.to_owned();
    request.surface_completion = false;
    let (result_tx, result_rx) = oneshot::channel();
    coordinator
        .queued
        .push_back(super::super::queue::QueuedSpawn {
            request: Box::new(request),
            queued_at: tokio::time::Instant::now(),
            caller: super::super::queue::QueuedCaller::Awaiting {
                result_tx,
                deadline: None,
            },
        });
    result_rx
}

#[tokio::test]
async fn send_to_owned_queued_child_parks_until_started() {
    let (mut coordinator, command_tx, admission_tx, mut admissions) = fixture();
    let mut spawn_result = insert_queued(&mut coordinator, "child", "parent");
    let mut response = begin_send(&mut coordinator, &command_tx, "child", "parent");
    assert!(response.try_recv().is_err());
    assert!(admissions.try_recv().is_err());

    // Dequeue into pending, then promote — the parked send must admit.
    let queued = coordinator.queued.pop_front().expect("queued child");
    coordinator.start_child(
        *queued.request,
        queued.caller.into_spawn_reply(),
        None,
        super::super::queue::StartOrigin::Dequeued {
            queued_for: std::time::Duration::ZERO,
            deadline: None,
        },
    );
    promote_pending(&mut coordinator, admission_tx, "child");
    let call = recv_with_timeout(&mut admissions).await;
    let message_id = call.message_id.clone();
    release_admission(&mut coordinator, call, ActiveMessageAdmission::Admitted).await;
    assert_eq!(
        ActiveAgentMessageOutcome::Accepted { message_id },
        response_outcome(response).await
    );
    assert!(spawn_result.try_recv().is_err(), "child still running");
}

#[tokio::test]
async fn parked_send_is_saturated_when_admit_cannot_reacquire() {
    let (mut coordinator, command_tx, admission_tx, mut admissions) = fixture_with_capacity(1);
    insert_pending(&mut coordinator, "spawning", "parent");
    let mut parked = begin_send(&mut coordinator, &command_tx, "spawning", "parent");
    assert!(parked.try_recv().is_err());

    insert_child(&mut coordinator, admission_tx, "holder", "parent");
    let _held = begin_send(&mut coordinator, &command_tx, "holder", "parent");
    let _call = recv_with_timeout(&mut admissions).await;

    promote_pending(&mut coordinator, mpsc::unbounded_channel().0, "spawning");
    assert_eq!(
        ActiveAgentMessageOutcome::Saturated { max_in_flight: 1 },
        response_outcome(parked).await
    );
}

#[tokio::test]
async fn send_to_cancelled_or_workflow_spawning_child_fails_fast() {
    let (mut coordinator, command_tx, _admission_tx, mut admissions) = fixture();
    insert_pending(&mut coordinator, "cancelled", "parent");
    coordinator
        .pending
        .get("cancelled")
        .expect("pending")
        .cancellation
        .cancel();
    assert_eq!(
        ActiveAgentMessageOutcome::NotActiveOrFinalizing,
        response_outcome(begin_send(
            &mut coordinator,
            &command_tx,
            "cancelled",
            "parent",
        ))
        .await
    );

    insert_pending(&mut coordinator, "wf", "parent");
    coordinator
        .pending
        .get_mut("wf")
        .expect("pending")
        .request
        .owner = crate::implementations::fuigo_build::task::types::SubagentOwner::workflow("run-1");
    assert_eq!(
        ActiveAgentMessageOutcome::NotActiveOrFinalizing,
        response_outcome(begin_send(&mut coordinator, &command_tx, "wf", "parent")).await
    );
    assert!(admissions.try_recv().is_err());
}

#[tokio::test]
async fn cancel_parent_prompt_rejects_parked_send() {
    let (mut coordinator, command_tx, _admission_tx, mut admissions) = fixture();
    let spawn_result = insert_queued(&mut coordinator, "child", "parent");
    let response = begin_send(&mut coordinator, &command_tx, "child", "parent");
    coordinator.cancel_parent_prompt("prompt", Some("parent"));
    assert_eq!(
        ActiveAgentMessageOutcome::NotActiveOrFinalizing,
        response_outcome(response).await
    );
    let terminal = response_outcome_result(spawn_result).await;
    assert!(
        terminal.cancelled && !terminal.success,
        "queued cancel must resolve a terminal result: {terminal:?}"
    );
    assert!(admissions.try_recv().is_err());
}

#[tokio::test]
async fn cancel_workflow_run_rejects_parked_send() {
    let (mut coordinator, _command_tx, _admission_tx, mut admissions) = fixture();
    insert_pending(&mut coordinator, "child", "parent");
    coordinator
        .pending
        .get_mut("child")
        .expect("pending")
        .request
        .owner = crate::implementations::fuigo_build::task::types::SubagentOwner::workflow("run-1");
    let (tx, rx) = oneshot::channel();
    coordinator
        .spawn_ready
        .push(super::ParkedSpawnReadyMessage {
            subagent_id: "child".to_owned(),
            parent_session_id: "parent".to_owned(),
            request: ActiveAgentMessageRequest::try_new("child", "hello").unwrap(),
            respond_to: Some(tx),
            deadline: Some(tokio::time::Instant::now() + ACTIVE_MESSAGE_SPAWN_READY_TIMEOUT),
            initial_message_id: None,
        });
    coordinator.cancel_workflow_children("run-1", Some("parent"));
    assert_eq!(
        ActiveAgentMessageOutcome::NotActiveOrFinalizing,
        response_outcome(rx).await
    );
    assert!(admissions.try_recv().is_err());
}
