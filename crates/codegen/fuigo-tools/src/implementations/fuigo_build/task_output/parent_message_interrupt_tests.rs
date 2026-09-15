//! A message from the owning parent agent must cut a tool wait short.
//!
//! Without the interrupt the child keeps waiting out `timeout_ms` (up to the
//! 10-minute ceiling) and then the rest of the turn before it ever sees the
//! correction its parent sent.

use super::test_helpers::*;
use super::*;
use crate::computer::types::{
    BackgroundHandle, KillOutcome, TaskSnapshot, TerminalBackend, TerminalRunRequest,
    TerminalRunResult,
};
use crate::implementations::fuigo_build::task::parent_message::ParentMessageSignal;
use crate::types::resources::{Resources, Terminal};
use crate::types::template_renderer::TemplateRenderer;
use crate::types::tool::ToolKind;
use crate::types::tool_metadata::test_ctx;
use std::sync::Arc;

const MESSAGE_ID: &str = "parent-message-abc";

/// A terminal whose task never finishes: `wait_for_completion` honours the
/// whole timeout, exactly as the real actor does for a long-running task.
struct NeverCompletingTerminal(TaskSnapshot);

impl NeverCompletingTerminal {
    fn resource(task_id: &str) -> Arc<dyn TerminalBackend> {
        Arc::new(Self(make_snapshot(task_id, false, None)))
    }
}

#[async_trait::async_trait]
impl TerminalBackend for NeverCompletingTerminal {
    async fn run(
        &self,
        _request: TerminalRunRequest,
    ) -> Result<TerminalRunResult, crate::computer::types::ComputerError> {
        unimplemented!()
    }

    async fn run_background(
        &self,
        _request: TerminalRunRequest,
    ) -> Result<BackgroundHandle, crate::computer::types::ComputerError> {
        unimplemented!()
    }

    async fn kill_task(&self, _task_id: &str) -> KillOutcome {
        unimplemented!()
    }

    async fn get_task(&self, _task_id: &str) -> Option<TaskSnapshot> {
        Some(self.0.clone())
    }

    async fn wait_for_completion(
        &self,
        _task_id: &str,
        timeout: Option<Duration>,
    ) -> Option<TaskSnapshot> {
        tokio::time::sleep(timeout.unwrap_or(Duration::from_secs(3600))).await;
        Some(self.0.clone())
    }

    async fn list_tasks(&self) -> Vec<TaskSnapshot> {
        vec![self.0.clone()]
    }
}

fn resources_with_signal(task_id: &str, signal: &ParentMessageSignal) -> Resources {
    let mut resources = Resources::new();
    resources.insert(Terminal(NeverCompletingTerminal::resource(task_id)));
    resources.insert(TemplateRenderer::new(
        std::collections::HashMap::from([(ToolKind::Read, "read_file".to_string())]),
        std::collections::HashMap::new(),
    ));
    resources.insert(signal.clone());
    resources
}

/// Commit one parent message shortly after the wait has started.
fn commit_after(signal: &ParentMessageSignal, delay: Duration) -> tokio::task::JoinHandle<()> {
    let signal = signal.clone();
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        signal.message_committed(MESSAGE_ID);
    })
}

/// The interrupt must arrive far sooner than the wait's own deadline.
const LONG_WAIT: Duration = Duration::from_secs(30);
const PROMPT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn wait_any_returns_interrupted_when_a_parent_message_arrives() {
    let terminal = NeverCompletingTerminal::resource("bg-1");
    let signal = ParentMessageSignal::new();
    let deadline = tokio::time::Instant::now() + LONG_WAIT;
    let committer = commit_after(&signal, Duration::from_millis(50));
    let started = std::time::Instant::now();

    let outcome = wait_any_event_driven(
        &terminal,
        &None,
        Some(&signal),
        &["bg-1".to_string()],
        &[],
        deadline,
    )
    .await;

    committer.await.expect("committer task");
    assert!(
        started.elapsed() < PROMPT,
        "the wait must return on the message, not at its {LONG_WAIT:?} deadline (took {:?})",
        started.elapsed()
    );
    assert_eq!(
        outcome,
        WaitOutcome::Interrupted {
            messages: Arc::from(vec![MESSAGE_ID.to_string()])
        }
    );
}

#[tokio::test]
async fn wait_all_returns_interrupted_when_a_parent_message_arrives() {
    let terminal = NeverCompletingTerminal::resource("bg-1");
    let signal = ParentMessageSignal::new();
    let deadline = tokio::time::Instant::now() + LONG_WAIT;
    let committer = commit_after(&signal, Duration::from_millis(50));
    let started = std::time::Instant::now();

    let outcome = wait_all_event_driven(
        &terminal,
        &None,
        Some(&signal),
        &["bg-1".to_string()],
        &[],
        deadline,
    )
    .await;

    committer.await.expect("committer task");
    assert!(
        started.elapsed() < PROMPT,
        "the wait must return on the message, not at its {LONG_WAIT:?} deadline (took {:?})",
        started.elapsed()
    );
    assert_eq!(
        outcome,
        WaitOutcome::Interrupted {
            messages: Arc::from(vec![MESSAGE_ID.to_string()])
        }
    );
}

/// Regression guard for the unchanged path: a wait with no pending parent
/// message must still run to its deadline and report `Elapsed`.
#[tokio::test]
async fn wait_without_a_parent_message_still_runs_to_its_deadline() {
    let terminal = NeverCompletingTerminal::resource("bg-1");
    let signal = ParentMessageSignal::new();
    let budget = Duration::from_millis(400);
    let started = std::time::Instant::now();

    let outcome = wait_any_event_driven(
        &terminal,
        &None,
        Some(&signal),
        &["bg-1".to_string()],
        &[],
        tokio::time::Instant::now() + budget,
    )
    .await;

    assert_eq!(outcome, WaitOutcome::DeadlineElapsed);
    assert!(
        started.elapsed() >= Duration::from_millis(350),
        "an uninterrupted wait must not return early (took {:?})",
        started.elapsed()
    );
}

/// A message committed BEFORE the wait started must interrupt it at once.
///
/// The signal is level-triggered, not edge-triggered from the wait's own
/// start: the parent's message is typically committed while the model is
/// sampling, i.e. after the turn loop's drain point and before the tool wait
/// begins. An edge-triggered watch never fires for that timing and the child
/// waits out the whole `timeout_ms` — the very failure this item exists to
/// remove.
#[tokio::test]
async fn a_message_committed_before_the_wait_interrupts_it_immediately() {
    let terminal = NeverCompletingTerminal::resource("bg-1");
    let signal = ParentMessageSignal::new();
    signal.message_committed(MESSAGE_ID);
    let started = std::time::Instant::now();

    let outcome = wait_any_event_driven(
        &terminal,
        &None,
        Some(&signal),
        &["bg-1".to_string()],
        &[],
        tokio::time::Instant::now() + LONG_WAIT,
    )
    .await;

    assert_eq!(
        outcome,
        WaitOutcome::Interrupted {
            messages: Arc::from(vec![MESSAGE_ID.to_string()])
        }
    );
    assert!(
        started.elapsed() < PROMPT,
        "an already-pending message must cut the wait short, not run it to its \
         {LONG_WAIT:?} deadline (took {:?})",
        started.elapsed()
    );
}

/// Level-triggered must not mean "interrupt forever": once the drain has
/// handed the message to the model the pending list is cleared, and the next
/// wait runs to its deadline exactly as before. Without this, one interrupt
/// would become a tool-call loop.
#[tokio::test]
async fn a_delivered_message_no_longer_interrupts_the_next_wait() {
    let terminal = NeverCompletingTerminal::resource("bg-1");
    let signal = ParentMessageSignal::new();
    signal.message_committed(MESSAGE_ID);
    // What `promote_parent_agent_messages` does once the row reaches the model.
    signal.message_delivered(MESSAGE_ID);
    let budget = Duration::from_millis(400);
    let started = std::time::Instant::now();

    let outcome = wait_any_event_driven(
        &terminal,
        &None,
        Some(&signal),
        &["bg-1".to_string()],
        &[],
        tokio::time::Instant::now() + budget,
    )
    .await;

    assert_eq!(outcome, WaitOutcome::DeadlineElapsed);
    assert!(
        started.elapsed() >= Duration::from_millis(350),
        "a delivered message must not re-interrupt (took {:?})",
        started.elapsed()
    );
}

#[tokio::test]
async fn single_task_wait_is_cut_short_and_names_the_parent_message() {
    let signal = ParentMessageSignal::new();
    let resources = resources_with_signal("bg-1", &signal);
    let committer = commit_after(&signal, Duration::from_millis(50));
    let started = std::time::Instant::now();

    let out = fuigo_tool_runtime::Tool::run(
        &TaskOutputTool,
        test_ctx(resources.into_shared()),
        TaskOutputToolInput {
            task_ids: vec!["bg-1".into()],
            timeout_ms: Some(30_000),
        },
    )
    .await
    .expect("get_task_output");

    committer.await.expect("committer task");
    assert!(
        started.elapsed() < PROMPT,
        "the wait must return on the message (took {:?})",
        started.elapsed()
    );
    match out {
        TaskOutputOutput::Result(r) => {
            assert_eq!(r.status, "running", "the task must still be running");
            assert!(
                r.output.contains("Wait interrupted"),
                "output must say the wait was interrupted: {}",
                r.output
            );
            assert!(
                r.output.contains(MESSAGE_ID),
                "output must name the pending message: {}",
                r.output
            );
            assert!(
                r.output.contains("task is still running"),
                "output must say the task is still running: {}",
                r.output
            );
        }
        other => panic!("expected a single Result, got {other:?}"),
    }
}

#[tokio::test]
async fn multi_task_wait_is_cut_short_and_names_the_parent_message() {
    let signal = ParentMessageSignal::new();
    let resources = resources_with_signal("bg-1", &signal);
    let committer = commit_after(&signal, Duration::from_millis(50));
    let started = std::time::Instant::now();

    let out = fuigo_tool_runtime::Tool::run(
        &TaskOutputTool,
        test_ctx(resources.into_shared()),
        TaskOutputToolInput {
            task_ids: vec!["bg-1".into(), "bg-2".into()],
            timeout_ms: Some(30_000),
        },
    )
    .await
    .expect("get_task_output");

    committer.await.expect("committer task");
    assert!(
        started.elapsed() < PROMPT,
        "the wait must return on the message (took {:?})",
        started.elapsed()
    );
    match out {
        TaskOutputOutput::MultiResult(m) => {
            assert!(
                m.results.iter().any(|r| r.status == "running"),
                "a task must still be running: {:?}",
                m.results
            );
            // One interrupt, one notice: it rides the summary, not each result
            // (see `fold_multi_wait_interrupt`).
            assert!(
                m.summary.contains("Wait interrupted") && m.summary.contains(MESSAGE_ID),
                "the summary must name the pending message: {}",
                m.summary
            );
        }
        other => panic!("expected a MultiResult, got {other:?}"),
    }
}

#[test]
fn interrupted_hint_names_the_message_and_keeps_the_auto_wake_promise() {
    let hint = WaitHint::Interrupted {
        requested: Duration::from_secs(120),
        waited: Duration::from_secs(2),
        messages: Arc::from(vec![MESSAGE_ID.to_string()]),
    };
    let rendered = still_running_wait_hint(&hint, WaitSubject::Task);
    assert!(rendered.contains("Wait interrupted after 2s"), "{rendered}");
    assert!(rendered.contains(MESSAGE_ID), "{rendered}");
    assert!(rendered.contains("task is still running"), "{rendered}");
    assert!(
        rendered.contains("You will be notified automatically when the task completes."),
        "{rendered}"
    );
}

/// One interrupt must cost one hint.
///
/// `resolve_tasks` appends the still-running hint to every running result, so
/// a wait over six background tasks used to render six identical copies of the
/// interrupt notice (message ids and all). In a release whose whole subject is
/// wasted input tokens that multiplier is a defect of its own: the notice
/// belongs on the multi-wait summary, once.
#[tokio::test]
async fn multi_task_interrupt_hint_is_rendered_once_not_per_task() {
    let signal = ParentMessageSignal::new();
    let resources = resources_with_signal("bg-1", &signal);
    let committer = commit_after(&signal, Duration::from_millis(50));

    let out = fuigo_tool_runtime::Tool::run(
        &TaskOutputTool,
        test_ctx(resources.into_shared()),
        TaskOutputToolInput {
            task_ids: vec!["bg-1".into(), "bg-2".into(), "bg-3".into()],
            timeout_ms: Some(30_000),
        },
    )
    .await
    .expect("get_task_output");

    committer.await.expect("committer task");
    match out {
        TaskOutputOutput::MultiResult(m) => {
            let running = m.results.iter().filter(|r| r.status == "running").count();
            assert_eq!(running, 3, "all three tasks must still be running");
            let copies = m
                .results
                .iter()
                .filter(|r| r.output.contains("Wait interrupted"))
                .count()
                + usize::from(m.summary.contains("Wait interrupted"));
            assert_eq!(
                copies,
                1,
                "one interrupt must render one hint, got {copies}: results={:#?} summary={}",
                m.results.iter().map(|r| &r.output).collect::<Vec<_>>(),
                m.summary
            );
            assert!(
                m.summary.contains(MESSAGE_ID),
                "the surviving hint must still name the pending message: {}",
                m.summary
            );
        }
        other => panic!("expected a MultiResult, got {other:?}"),
    }
}

/// A terminal that owns no tasks at all: every lookup misses, so
/// `run_single_task` falls through to the subagent backend.
struct EmptyTerminal;

#[async_trait::async_trait]
impl TerminalBackend for EmptyTerminal {
    async fn run(
        &self,
        _request: TerminalRunRequest,
    ) -> Result<TerminalRunResult, crate::computer::types::ComputerError> {
        unimplemented!()
    }

    async fn run_background(
        &self,
        _request: TerminalRunRequest,
    ) -> Result<BackgroundHandle, crate::computer::types::ComputerError> {
        unimplemented!()
    }

    async fn kill_task(&self, _task_id: &str) -> KillOutcome {
        unimplemented!()
    }

    async fn get_task(&self, _task_id: &str) -> Option<TaskSnapshot> {
        None
    }

    async fn wait_for_completion(
        &self,
        _task_id: &str,
        _timeout: Option<Duration>,
    ) -> Option<TaskSnapshot> {
        None
    }

    async fn list_tasks(&self) -> Vec<TaskSnapshot> {
        Vec::new()
    }
}

/// A subagent child that never finishes: a blocking query waits out its whole
/// timeout, a non-blocking one reports it still running.
struct NeverCompletingChild;

impl NeverCompletingChild {
    fn running_snapshot(
        id: &str,
    ) -> crate::implementations::fuigo_build::task::types::SubagentSnapshot {
        use crate::implementations::fuigo_build::task::types::{
            SubagentSnapshot, SubagentSnapshotStatus,
        };
        SubagentSnapshot {
            subagent_id: id.to_string(),
            description: "long child".to_string(),
            subagent_type: "general".to_string(),
            status: SubagentSnapshotStatus::Running {
                turn_count: 1,
                tool_call_count: 2,
                tokens_used: 1_000,
                context_window_tokens: 200_000,
                context_usage_pct: 1,
                tools_used: vec!["bash".to_string()],
                error_count: 0,
            },
            started_at_epoch_ms: 0,
            duration_ms: 1_000,
            persona: None,
        }
    }
}

#[async_trait::async_trait]
impl crate::implementations::fuigo_build::task::backend::SubagentBackend for NeverCompletingChild {
    async fn spawn(
        &self,
        _request: crate::implementations::fuigo_build::task::types::SubagentRequest,
        _registered_tx: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> Result<
        crate::implementations::fuigo_build::task::types::SubagentResult,
        fuigo_tool_runtime::ToolError,
    > {
        unimplemented!()
    }

    async fn query(
        &self,
        id: &str,
        block: bool,
        timeout_ms: Option<u64>,
    ) -> Option<crate::implementations::fuigo_build::task::types::SubagentSnapshot> {
        if block {
            tokio::time::sleep(Duration::from_millis(timeout_ms.unwrap_or(3_600_000))).await;
        }
        Some(Self::running_snapshot(id))
    }

    async fn cancel(
        &self,
        _id: &str,
    ) -> crate::implementations::fuigo_build::task::types::SubagentCancelOutcome {
        unimplemented!()
    }

    async fn validate_type(
        &self,
        _subagent_type: &str,
        _parent_session_id: &str,
    ) -> crate::implementations::fuigo_build::task::types::SubagentValidateTypeOutcome {
        unimplemented!()
    }

    async fn describe_subagent_type(
        &self,
        _subagent_type: &str,
        _harness_agent_type: Option<&str>,
        _parent_session_id: &str,
    ) -> crate::implementations::fuigo_build::task::types::SubagentDescribeOutcome {
        unimplemented!()
    }
}

/// Waiting on a subagent child is this item's headline scenario, and it runs
/// through the backend query arm rather than the terminal one. A parent
/// message must cut that blocking query short too, and the child must still be
/// reported as running.
#[tokio::test]
async fn subagent_backend_wait_is_cut_short_and_names_the_parent_message() {
    use crate::implementations::fuigo_build::task::backend::SubagentBackendResource;

    let signal = ParentMessageSignal::new();
    let mut resources = Resources::new();
    resources.insert(Terminal(Arc::new(EmptyTerminal)));
    resources.insert(TemplateRenderer::new(
        std::collections::HashMap::from([(ToolKind::Read, "read_file".to_string())]),
        std::collections::HashMap::new(),
    ));
    resources.insert(signal.clone());
    resources.insert(SubagentBackendResource(Arc::new(NeverCompletingChild)));
    let committer = commit_after(&signal, Duration::from_millis(50));
    let started = std::time::Instant::now();

    let out = fuigo_tool_runtime::Tool::run(
        &TaskOutputTool,
        test_ctx(resources.into_shared()),
        TaskOutputToolInput {
            task_ids: vec!["child-1".into()],
            timeout_ms: Some(30_000),
        },
    )
    .await
    .expect("get_task_output");

    committer.await.expect("committer task");
    assert!(
        started.elapsed() < PROMPT,
        "the subagent wait must return on the message (took {:?})",
        started.elapsed()
    );
    match out {
        TaskOutputOutput::Result(r) => {
            assert_eq!(r.status, "running", "the child must still be running");
            assert!(
                r.output.contains("Wait interrupted") && r.output.contains(MESSAGE_ID),
                "output must name the pending message: {}",
                r.output
            );
            assert!(
                r.output.contains("subagent is still running"),
                "output must say the subagent is still running: {}",
                r.output
            );
        }
        other => panic!("expected a single Result, got {other:?}"),
    }
}
