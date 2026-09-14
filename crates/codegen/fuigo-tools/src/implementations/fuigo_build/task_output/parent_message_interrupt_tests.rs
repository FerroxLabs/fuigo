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

/// A message committed BEFORE the wait started must not interrupt it: a
/// level-triggered signal would turn one interrupt into a tool-call loop.
#[tokio::test]
async fn a_message_committed_before_the_wait_does_not_interrupt_it() {
    let terminal = NeverCompletingTerminal::resource("bg-1");
    let signal = ParentMessageSignal::new();
    signal.message_committed(MESSAGE_ID);
    let budget = Duration::from_millis(400);

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
            let running = m
                .results
                .iter()
                .find(|r| r.status == "running")
                .expect("a still-running task");
            assert!(
                running.output.contains("Wait interrupted") && running.output.contains(MESSAGE_ID),
                "output must name the pending message: {}",
                running.output
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
