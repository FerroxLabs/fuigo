use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use fuigo_sampling_types::ReasoningEffort;
use fuigo_tools::implementations::fuigo_build::workflow::{WorkflowControl, WorkflowLaunchAck};
use fuigo_workflow::{Journal, WorkflowOutcome, WorkflowRunParams};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use super::host_service::{
    HostDrainOutcome, TelemetryHook, WorkflowHostParams, spawn_workflow_host_service,
};
use super::notify::WorkflowNotifySender;
use super::registry::{ResolvedWorkflow, WorkflowSource};
use super::store::WorkflowRunStore;
use super::tracker::{WorkflowRunState, WorkflowRunStatus, WorkflowTracker};

pub(crate) const WORKFLOW_MAX_ACTIVE_RUNS_PER_SESSION: usize = 4;
pub(crate) const WORKFLOW_DEFAULT_AGENT_BUDGET: u64 = fuigo_workflow::DEFAULT_AGENT_BUDGET;

struct ActiveRun {
    cancel: CancellationToken,
    pause_intent: Arc<AtomicBool>,
    done: oneshot::Receiver<()>,
}

pub(crate) struct LaunchSpec {
    pub objective: String,
    pub args: serde_json::Value,
    pub agent_budget: Option<u64>,
    pub effort: Option<ReasoningEffort>,
    pub resume_run_id: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum LaunchError {
    #[error("workflow run not found: {0}")]
    UnknownRun(String),
    #[error("journal error: {0}")]
    Journal(String),
    #[error("workflow store error: {0}")]
    Store(String),
    #[error("run is not resumable (status: {0})")]
    NotResumable(String),
    #[error(
        "run is budget-limited at {used} of {limit} agents; resume it \
         with an agent_budget above {used}"
    )]
    BudgetNotRaised { used: u64, limit: u64 },
    #[error(
        "session already has the maximum of {WORKFLOW_MAX_ACTIVE_RUNS_PER_SESSION} active workflow runs"
    )]
    TooManyActiveRuns,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ControlError {
    #[error("no workflow run in this session matches '{0}'")]
    UnknownRun(String),
    #[error("run '{name}' is {} and cannot be {}", status.as_str(), match control {
        WorkflowControl::Pause => "paused",
        WorkflowControl::Stop => "stopped",
    })]
    NotApplicable {
        name: String,
        status: WorkflowRunStatus,
        control: WorkflowControl,
    },
}

pub(crate) struct WorkflowManager {
    session_id: String,
    session_dir: Option<PathBuf>,
    cwd: PathBuf,
    tracker: Arc<parking_lot::Mutex<WorkflowTracker>>,
    store: WorkflowRunStore,
    notify: WorkflowNotifySender,
    subagent_event_tx: mpsc::UnboundedSender<
        fuigo_tools::implementations::fuigo_build::task::types::SubagentEvent,
    >,
    telemetry: TelemetryHook,
    session_cmd_tx: mpsc::UnboundedSender<crate::session::commands::SessionCommand>,
    templates: HashMap<String, String>,
    active: HashMap<String, ActiveRun>,
    retiring: Vec<(String, oneshot::Receiver<()>)>,
    max_concurrent_agents: usize,
}

impl WorkflowManager {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        session_id: String,
        session_dir: Option<PathBuf>,
        cwd: PathBuf,
        tracker: Arc<parking_lot::Mutex<WorkflowTracker>>,
        store: WorkflowRunStore,
        notify: WorkflowNotifySender,
        subagent_event_tx: mpsc::UnboundedSender<
            fuigo_tools::implementations::fuigo_build::task::types::SubagentEvent,
        >,
        telemetry: TelemetryHook,
        session_cmd_tx: mpsc::UnboundedSender<crate::session::commands::SessionCommand>,
        templates: HashMap<String, String>,
        max_concurrent_agents: usize,
    ) -> Self {
        Self {
            session_id,
            session_dir,
            cwd,
            tracker,
            store,
            notify,
            subagent_event_tx,
            telemetry,
            session_cmd_tx,
            templates,
            active: HashMap::new(),
            retiring: Vec::new(),
            max_concurrent_agents: super::host_service::workflow_max_concurrent_agents(
                max_concurrent_agents,
            ),
        }
    }

    #[cfg(test)]
    pub(crate) fn test_set_max_concurrent_agents(&mut self, n: usize) {
        self.max_concurrent_agents = n.max(1);
    }

    pub(crate) fn tracker(&self) -> Arc<parking_lot::Mutex<WorkflowTracker>> {
        self.tracker.clone()
    }

    pub(crate) fn launch(
        &mut self,
        resolved: ResolvedWorkflow,
        mut spec: LaunchSpec,
    ) -> Result<(String, oneshot::Receiver<WorkflowOutcome>), LaunchError> {
        self.reap_terminal_runs();
        if self.active.len().saturating_add(self.retiring.len())
            >= WORKFLOW_MAX_ACTIVE_RUNS_PER_SESSION
        {
            return Err(LaunchError::TooManyActiveRuns);
        }

        let allow_fork_context = resolved.source == WorkflowSource::Builtin;
        let mut execution_script = resolved.script;
        let (run_id, journal, state) = match &spec.resume_run_id {
            Some(run_id) => {
                let existing = self
                    .tracker
                    .lock()
                    .get(run_id)
                    .ok_or_else(|| LaunchError::UnknownRun(run_id.clone()))?;
                if !existing.status.is_resumable() {
                    return Err(LaunchError::NotResumable(
                        existing.status.as_str().to_string(),
                    ));
                }
                if existing.status
                    == crate::session::workflow::tracker::WorkflowRunStatus::BudgetLimited
                    && existing.agents_used >= fuigo_workflow::MAX_AGENT_BUDGET
                {
                    return Err(LaunchError::NotResumable(
                        "maximum agent budget reached; start a new run".into(),
                    ));
                }
                let original_args = self.store.args_for(run_id).ok_or_else(|| {
                    LaunchError::Store("immutable launch args are missing".into())
                })?;
                spec.effort = self.store.effort_for(run_id);
                if original_args != spec.args {
                    return Err(LaunchError::Store(
                        "workflow launch args are immutable across resume".into(),
                    ));
                }
                execution_script = self.store.script_for(run_id).ok_or_else(|| {
                    LaunchError::Store("immutable workflow script is missing".into())
                })?;
                let mut journal = match existing
                    .journal_path
                    .as_ref()
                    .and_then(|p| self.session_dir.as_ref().map(|d| (d, p)))
                {
                    Some((session_dir, relative)) => {
                        let expected = format!("workflows/{run_id}/journal.jsonl");
                        if relative != &expected {
                            return Err(LaunchError::Journal(
                                "persisted journal path does not match its workflow run".into(),
                            ));
                        }
                        Journal::load(session_dir.join(relative))
                            .map_err(|e| LaunchError::Journal(e.to_string()))?
                    }
                    None => Journal::new(None),
                };
                if existing.status == crate::session::workflow::tracker::WorkflowRunStatus::Failed {
                    journal
                        .prune_trailing_host_error(existing.pause_message.as_deref().unwrap_or(""))
                        .map_err(|e| LaunchError::Journal(e.to_string()))?;
                }
                let state = {
                    let mut tracker = self.tracker.lock();
                    tracker.reconcile_agents_used(run_id, journal.agent_reservation_count());
                    tracker.resume_run(run_id, spec.agent_budget)
                }
                .ok_or_else(|| {
                    if existing.status
                        == crate::session::workflow::tracker::WorkflowRunStatus::BudgetLimited
                    {
                        LaunchError::BudgetNotRaised {
                            used: existing.agents_used,
                            limit: existing.agent_budget.unwrap_or(0),
                        }
                    } else {
                        LaunchError::NotResumable(existing.status.as_str().into())
                    }
                })?;

                (run_id.clone(), journal, state)
            }
            None => {
                let run_id = format!("wf_{}", uuid::Uuid::now_v7().simple());
                let agent_budget = spec.agent_budget.unwrap_or(WORKFLOW_DEFAULT_AGENT_BUDGET);
                self.store
                    .register(&run_id, &execution_script, &spec.args, spec.effort)
                    .map_err(|error| LaunchError::Store(error.to_string()))?;
                let journal_rel = format!("workflows/{run_id}/journal.jsonl");
                // Write the v2 header now, at creation: it is the positive evidence that lets a run
                // paused or stopped before its first journaled step resume as a fresh start instead
                // of loading as a legacy journal (`Journal::create`).
                let journal = match self.session_dir.as_ref().map(|d| d.join(&journal_rel)) {
                    Some(path) => Journal::create(path).map_err(|error| {
                        self.store.remove(&run_id);
                        LaunchError::Journal(error.to_string())
                    })?,
                    None => Journal::new(None),
                };
                let state = self.tracker.lock().start_run(
                    run_id.clone(),
                    resolved.meta.name,
                    spec.objective.clone(),
                    resolved.meta.phases,
                    Some(agent_budget),
                    self.session_dir.as_ref().map(|_| journal_rel),
                );
                (run_id, journal, state)
            }
        };

        if let Err(error) = self.store.persist_now(&state) {
            if spec.resume_run_id.is_some() {
                if let Some(interrupted) = self.tracker.lock().interrupt(
                    &run_id,
                    "workflow state persistence failed before resume; start a new run",
                ) && let Err(persist_error) = self.store.persist(&interrupted)
                {
                    tracing::warn!(run_id = %run_id, %persist_error, "failed to queue interrupted workflow state");
                }
            } else {
                self.tracker.lock().clear_run(&run_id);
                self.store.remove(&run_id);
            }
            return Err(LaunchError::Store(error.to_string()));
        }
        self.notify
            .emit(&state, self.tracker.lock().elapsed_ms(&run_id), 0);

        let active = fuigo_telemetry::activity::WORKFLOW_RUNS_ACTIVE.enter();
        debug_assert!(
            fuigo_telemetry::activity::WORKFLOW_RUNS_ACTIVE.get() >= 1,
            "WorkflowRunStarted must stamp a self-inclusive count"
        );
        log_run_started(
            &run_id,
            &self.session_id,
            &resolved.source,
            &state,
            self.max_concurrent_agents,
            spec.resume_run_id.is_some(),
        );

        let (host_tx, host_rx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();
        let scratch_dir = self
            .session_dir
            .clone()
            .unwrap_or_else(std::env::temp_dir)
            .join("workflows")
            .join(&run_id)
            .join("scratch");

        let agent_stats = Arc::new(super::host_service::WorkflowAgentStats::default());
        let (host_service, host_drained) = spawn_workflow_host_service(
            WorkflowHostParams {
                run_id: run_id.clone(),
                max_concurrent_agents: self.max_concurrent_agents,
                cwd: self.cwd.clone(),
                scratch_dir,
                tracker: self.tracker.clone(),
                store: self.store.clone(),
                notify: self.notify.clone(),
                subagent_event_tx: self.subagent_event_tx.clone(),
                parent_session_id: self.session_id.clone(),
                allow_fork_context,
                effort: spec.effort,
                templates: self.templates.clone(),
                telemetry: self.telemetry.clone(),
                stats: agent_stats.clone(),
                cancel: cancel.clone(),
            },
            host_rx,
        );

        let script = execution_script;
        let args = spec.args;
        let exec_cancel = cancel.clone();
        let exec = tokio::task::spawn_blocking(move || {
            fuigo_workflow::run_workflow(WorkflowRunParams {
                script,
                args,
                journal,
                host_tx,
                cancel: exec_cancel,
                max_ops: WorkflowRunParams::DEFAULT_MAX_OPS,
            })
        });

        let pause_intent = Arc::new(AtomicBool::new(false));
        let (done_tx, done_rx) = oneshot::channel();
        self.active.insert(
            run_id.clone(),
            ActiveRun {
                cancel: cancel.clone(),
                pause_intent: pause_intent.clone(),
                done: done_rx,
            },
        );

        let (outcome_tx, outcome_rx) = oneshot::channel();
        let tracker = self.tracker.clone();
        let store = self.store.clone();
        let notify = self.notify.clone();
        let session_cmd_tx = self.session_cmd_tx.clone();
        let watcher_run_id = run_id.clone();
        let watcher_cancel = cancel.clone();
        let watcher_session_id = self.session_id.clone();
        let watcher_agent_stats = agent_stats;
        let execution_epoch = self.tracker.lock().execution_epoch(&run_id).unwrap_or(0);
        tokio::spawn(async move {
            let _active = active;
            let mut outcome = exec.await.unwrap_or_else(|e| WorkflowOutcome::Failed {
                error: format!("workflow executor panicked: {e}"),
            });
            if !host_service.is_finished() {
                watcher_cancel.cancel();
            }
            let host_drain =
                tokio::time::timeout(std::time::Duration::from_secs(25), host_drained).await;
            let drain_failed = !matches!(host_drain, Ok(Ok(HostDrainOutcome::Drained)));
            if drain_failed {
                host_service.abort();
            }
            let _ = host_service.await;
            if drain_failed {
                tracing::warn!(run_id = %watcher_run_id, "workflow host/child drain did not complete before lifecycle update");
                outcome = WorkflowOutcome::Failed {
                    error:
                        "workflow cleanup did not complete; run is interrupted and cannot resume"
                            .into(),
                };
            }
            // Epoch check and lifecycle mutation stay under one lock, or a quick resume could let this stale watcher stomp the successor
            let (epoch_matches, state) = {
                let mut tracker = tracker.lock();
                if tracker.execution_epoch(&watcher_run_id) != Some(execution_epoch) {
                    (false, None)
                } else {
                    (
                        true,
                        settle_finished_run(
                            &mut tracker,
                            &watcher_run_id,
                            drain_failed,
                            pause_intent.load(Ordering::Relaxed),
                            &outcome,
                        ),
                    )
                }
            };
            if !epoch_matches {
                // A quick resume took over; close this episode as superseded (cumulative fields may reflect the successor)
                let (elapsed, agents_used, agent_budget) = {
                    let tracker = tracker.lock();
                    let run = tracker.get(&watcher_run_id);
                    (
                        tracker.elapsed_ms(&watcher_run_id),
                        run.as_ref().map(|run| run.agents_used).unwrap_or_default(),
                        run.as_ref().and_then(|run| run.agent_budget),
                    )
                };
                log_run_ended(
                    RunEndMetadata {
                        run_id: &watcher_run_id,
                        parent_session_id: &watcher_session_id,
                        status: fuigo_telemetry::events::WorkflowRunEndStatus::Superseded,
                        duration_ms: elapsed,
                        agents_used,
                        agent_budget,
                    },
                    &watcher_agent_stats,
                );
                let _ = done_tx.send(());
                let _ = outcome_tx.send(outcome);
                return;
            }
            if state.is_none() {
                // The run left the tracker; close the episode so its `workflow_run_started` is not orphaned
                log_run_ended(
                    RunEndMetadata {
                        run_id: &watcher_run_id,
                        parent_session_id: &watcher_session_id,
                        status: fuigo_telemetry::events::WorkflowRunEndStatus::Interrupted,
                        duration_ms: 0,
                        agents_used: 0,
                        agent_budget: None,
                    },
                    &watcher_agent_stats,
                );
            }
            if let Some(mut state) = state {
                let mut persisted = true;
                if let Err(error) = store.persist_ack(&state).await {
                    tracing::warn!(run_id = %watcher_run_id, %error, "workflow terminal manifest was not durably written");
                    outcome = WorkflowOutcome::Failed {
                        error: format!(
                            "workflow terminal state could not be persisted: {error}; run is interrupted"
                        ),
                    };
                    state = tracker
                        .lock()
                        .interrupt(
                            &watcher_run_id,
                            format!(
                                "workflow terminal state could not be persisted: {error}; start a new run"
                            ),
                        )
                        .unwrap_or(state);
                    if let Err(interrupt_error) = store.persist_ack(&state).await {
                        persisted = false;
                        tracing::error!(run_id = %watcher_run_id, %interrupt_error, "failed to persist workflow interruption marker");
                    }
                }
                // Emit before the persist-failure return: every start event gets an end event
                let elapsed = tracker.lock().elapsed_ms(&watcher_run_id);
                log_run_ended(
                    RunEndMetadata {
                        run_id: &watcher_run_id,
                        parent_session_id: &watcher_session_id,
                        status: run_ended_status(state.status),
                        duration_ms: elapsed,
                        agents_used: state.agents_used,
                        agent_budget: state.agent_budget,
                    },
                    &watcher_agent_stats,
                );
                if !persisted {
                    let _ = done_tx.send(());
                    let _ = outcome_tx.send(outcome);
                    return;
                }
                notify.broadcast(&state, elapsed, 0, true);
                if state.status.is_completion_reportable() {
                    let _ = session_cmd_tx.send(
                        crate::session::commands::SessionCommand::WorkflowCompletionTurn {
                            run_id: watcher_run_id.clone(),
                            revision: state.revision,
                        },
                    );
                }
            }
            let _ = done_tx.send(());
            let _ = outcome_tx.send(outcome);
        });

        Ok((run_id, outcome_rx))
    }

    #[cfg(test)]
    pub(crate) fn test_bundle() -> (
        Arc<tokio::sync::Mutex<WorkflowManager>>,
        Arc<parking_lot::Mutex<WorkflowTracker>>,
    ) {
        Self::test_bundle_with_session_dir(None)
    }

    #[cfg(test)]
    pub(crate) fn test_bundle_with_session_dir(
        session_dir: Option<PathBuf>,
    ) -> (
        Arc<tokio::sync::Mutex<WorkflowManager>>,
        Arc<parking_lot::Mutex<WorkflowTracker>>,
    ) {
        let tracker = Arc::new(parking_lot::Mutex::new(WorkflowTracker::default()));
        let (gateway_tx, _gateway_rx) = mpsc::unbounded_channel();
        let (persist_tx, _persist_rx) = mpsc::unbounded_channel();
        let store = WorkflowRunStore::new(session_dir.clone(), persist_tx.clone());
        let notify = super::notify::WorkflowNotifySender::new(
            agent_client_protocol::SessionId::new("test-session"),
            fuigo_acp_lib::AcpAgentGatewaySender::new(gateway_tx),
            persist_tx,
            store.clone(),
        );
        let manager = Arc::new(tokio::sync::Mutex::new(WorkflowManager::new(
            "test-session".into(),
            session_dir,
            std::env::temp_dir(),
            tracker.clone(),
            store,
            notify,
            mpsc::unbounded_channel().0,
            Arc::new(|_, _, _| {}),
            mpsc::unbounded_channel().0,
            std::collections::HashMap::new(),
            super::host_service::DEFAULT_WORKFLOW_MAX_CONCURRENT_AGENTS,
        )));
        (manager, tracker)
    }

    fn reap_terminal_runs(&mut self) {
        let terminal: Vec<String> = self
            .active
            .keys()
            .filter(|run_id| {
                self.tracker
                    .lock()
                    .get(run_id)
                    .is_some_and(|state| state.status.is_terminal())
            })
            .cloned()
            .collect();
        for run_id in terminal {
            if let Some(run) = self.active.remove(&run_id) {
                self.retiring.push((run_id.to_owned(), run.done));
            }
        }

        self.retiring.retain_mut(|(_, done)| match done.try_recv() {
            Ok(()) | Err(oneshot::error::TryRecvError::Closed) => false,
            Err(oneshot::error::TryRecvError::Empty) => true,
        });
    }

    fn reap_if_terminal(&mut self, run_id: &str) -> bool {
        let terminal = self
            .tracker
            .lock()
            .get(run_id)
            .is_some_and(|s| s.status.is_terminal());
        if terminal && let Some(run) = self.active.remove(run_id) {
            self.retiring.push((run_id.to_owned(), run.done));
        }
        terminal
    }

    fn cancel_children_for_run(&self, run_id: &str) -> bool {
        let (respond_to, _response) = oneshot::channel();
        self.subagent_event_tx
            .send(
                fuigo_tools::implementations::fuigo_build::task::types::SubagentEvent::Cancel(
                    fuigo_tools::implementations::fuigo_build::task::types::SubagentCancelRequest {
                        parent_session_id: Some(self.session_id.clone()),
                        target: fuigo_tools::implementations::fuigo_build::task::types::SubagentCancelTarget::WorkflowRunId(
                            run_id.to_owned(),
                        ),
                        respond_to,
                    },
                ),
            )
            .is_ok()
    }

    pub(crate) fn pause(&mut self, run_id: &str) -> bool {
        if self.reap_if_terminal(run_id) {
            return false;
        }
        let Some(run) = self.active.remove(run_id) else {
            return false;
        };
        run.pause_intent.store(true, Ordering::Relaxed);
        run.cancel.cancel();
        let _ = self.cancel_children_for_run(run_id);
        self.retiring.push((run_id.to_owned(), run.done));
        let paused = {
            let mut tracker = self.tracker.lock();
            let active = tracker
                .get(run_id)
                .is_some_and(|state| !state.status.is_terminal());
            if active {
                let state = tracker.pause_user(run_id, None);
                state.map(|state| (state, tracker.elapsed_ms(run_id)))
            } else {
                None
            }
        };
        if let Some((state, elapsed)) = paused {
            self.notify.emit(&state, elapsed, 0);
        }
        true
    }

    pub(crate) fn cancel(&mut self, run_id: &str) -> bool {
        if self.reap_if_terminal(run_id) {
            return false;
        }
        if let Some(run) = self.active.remove(run_id) {
            run.cancel.cancel();
            let _ = self.cancel_children_for_run(run_id);
            self.retiring.push((run_id.to_owned(), run.done));
            let state = {
                let mut tracker = self.tracker.lock();
                match tracker.get(run_id) {
                    Some(state) if !state.status.is_terminal() => {
                        tracker.apply_outcome(run_id, &WorkflowOutcome::Cancelled)
                    }
                    _ => None,
                }
            };
            if state.is_some() {
                let (state, elapsed) = {
                    let tracker = self.tracker.lock();
                    (
                        tracker.get(run_id).expect("run still tracked"),
                        tracker.elapsed_ms(run_id),
                    )
                };
                self.notify.emit(&state, elapsed, 0);
            }
            return true;
        }
        let _ = self.cancel_children_for_run(run_id);
        let state = {
            let mut tracker = self.tracker.lock();
            match tracker.get(run_id) {
                Some(state) if !state.status.is_terminal() => {
                    tracker.apply_outcome(run_id, &WorkflowOutcome::Cancelled)
                }
                _ => None,
            }
        };
        match state {
            Some(_) => {
                let (state, elapsed) = {
                    let tracker = self.tracker.lock();
                    (
                        tracker.get(run_id).expect("run still tracked"),
                        tracker.elapsed_ms(run_id),
                    )
                };
                self.notify.emit(&state, elapsed, 0);
                true
            }
            None => false,
        }
    }

    /// Pause or stop the run whose id or display name is `key`, returning its
    /// state as of before the op.
    pub(crate) fn control_run(
        &mut self,
        key: &str,
        control: WorkflowControl,
    ) -> Result<WorkflowRunState, ControlError> {
        let run = {
            let tracker = self.tracker.lock();
            tracker
                .find_run_id(key)
                .and_then(|run_id| tracker.get(&run_id))
        }
        .ok_or_else(|| ControlError::UnknownRun(key.to_owned()))?;
        let not_applicable = |status: WorkflowRunStatus| ControlError::NotApplicable {
            name: run.name.clone(),
            status,
            control,
        };
        if !run.status.accepts(control) {
            return Err(not_applicable(run.status));
        }
        let applied = match control {
            WorkflowControl::Pause => self.pause(&run.run_id),
            WorkflowControl::Stop => self.cancel(&run.run_id),
        };
        if applied {
            Ok(run)
        } else {
            // The run finished between the gate and the op; report the status it reached.
            let status = self
                .tracker
                .lock()
                .get(&run.run_id)
                .map_or(run.status, |state| state.status);
            Err(not_applicable(status))
        }
    }

    /// The workflow tool's pause/stop: [`Self::control_run`] as a launch ack.
    /// The model gets the outcome from the tool result; a `/workflow stop`
    /// relies on the completion wake to learn about it, so only the tool path
    /// opts out of that wake.
    pub(crate) fn control_ack(&mut self, key: &str, control: WorkflowControl) -> WorkflowLaunchAck {
        match self.control_run(key, control) {
            Ok(run) => {
                if control == WorkflowControl::Stop {
                    self.tracker.lock().mark_completion_reported(&run.run_id);
                }
                WorkflowLaunchAck::Controlled {
                    run_id: run.run_id,
                    name: run.name,
                    control,
                }
            }
            Err(e @ ControlError::UnknownRun(_)) => WorkflowLaunchAck::Rejected {
                code: "workflow_control_unknown_run",
                detail: e.to_string(),
            },
            Err(e @ ControlError::NotApplicable { .. }) => WorkflowLaunchAck::Rejected {
                code: "workflow_control_not_applicable",
                detail: e.to_string(),
            },
        }
    }

    pub(crate) async fn cancel_all_and_drain(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<(), Vec<String>> {
        let active: Vec<(String, ActiveRun)> = self.active.drain().collect();
        for (run_id, run) in &active {
            run.cancel.cancel();
            let _ = self.cancel_children_for_run(run_id);
        }
        let mut pending: Vec<(Option<String>, oneshot::Receiver<()>)> = active
            .into_iter()
            .map(|(run_id, run)| (Some(run_id), run.done))
            .collect();
        pending.extend(
            self.retiring
                .drain(..)
                .map(|(run_id, done)| (Some(run_id), done)),
        );

        let mut timed_out = Vec::new();
        let deadline = tokio::time::Instant::now() + timeout;
        let mut pending = pending.into_iter();
        while let Some((run_id, done)) = pending.next() {
            if tokio::time::timeout_at(deadline, done).await.is_err() {
                if let Some(run_id) = run_id {
                    timed_out.push(run_id);
                }
                timed_out.extend(pending.filter_map(|(run_id, _)| run_id));
                break;
            }
        }
        if timed_out.is_empty() {
            return Ok(());
        }

        tracing::warn!(
            run_ids = ?timed_out,
            "workflow shutdown drain timed out; marking runs interrupted"
        );
        for run_id in &timed_out {
            if self
                .tracker
                .lock()
                .get(run_id)
                .is_some_and(|s| s.status.is_terminal() || s.status.is_paused())
            {
                continue;
            }
            let state = {
                let mut tracker = self.tracker.lock();
                tracker.interrupt(
                    run_id,
                    "session shutdown timed out before workflow cleanup completed; the run cannot resume",
                )
            };
            if let Some(state) = state {
                if let Err(error) = self.store.persist_now(&state) {
                    tracing::error!(%run_id, %error, "failed to persist workflow shutdown interruption");
                }
                let elapsed = self.tracker.lock().elapsed_ms(run_id);
                self.notify.broadcast(&state, elapsed, 0, true);
            }
        }
        Err(timed_out)
    }

    #[cfg(test)]
    pub(crate) fn test_insert_active_run(&mut self, run_id: String, done: oneshot::Receiver<()>) {
        self.active.insert(
            run_id,
            ActiveRun {
                cancel: CancellationToken::new(),
                pause_intent: Arc::new(AtomicBool::new(false)),
                done,
            },
        );
    }

    pub(crate) fn script_copy_for(&self, run_id: &str) -> Option<String> {
        self.store.script_for(run_id)
    }

    pub(crate) fn script_copy_path(&self, run_id: &str) -> Option<std::path::PathBuf> {
        self.store.script_copy_path(run_id)
    }

    pub(crate) fn args_copy_for(&self, run_id: &str) -> serde_json::Value {
        self.store
            .args_for(run_id)
            .unwrap_or(serde_json::Value::Null)
    }
}

/// The lifecycle a finished run settles into, from the engine's outcome and the manager's pause intent.
///
/// A paused run ends `Cancelled` (the pause fires the run's stop signal) or, if the script reached its
/// own pause first, `Paused`; either way the user's pause wins. This relies on the engine reporting a
/// host request lost to the stop's teardown as `Cancelled`, not `Failed` (P38-F): a `Failed` here would
/// overwrite the eager `UserPaused` below.
fn settle_finished_run(
    tracker: &mut WorkflowTracker,
    run_id: &str,
    drain_failed: bool,
    pause_intent: bool,
    outcome: &WorkflowOutcome,
) -> Option<WorkflowRunState> {
    if drain_failed {
        tracker.interrupt(
            run_id,
            "workflow cleanup timed out or could not be acknowledged; start a new run",
        )
    } else if pause_intent
        && matches!(
            outcome,
            WorkflowOutcome::Cancelled | WorkflowOutcome::Paused { .. }
        )
    {
        tracker.pause_user(run_id, None)
    } else {
        tracker.apply_outcome(run_id, outcome)
    }
}

fn log_run_started(
    run_id: &str,
    parent_session_id: &str,
    source: &WorkflowSource,
    state: &crate::session::workflow::tracker::WorkflowRunState,
    max_concurrent_agents: usize,
    resumed: bool,
) {
    use fuigo_telemetry::events::{WorkflowRunStarted, WorkflowSourceKind};
    fuigo_telemetry::session_ctx::log_event(WorkflowRunStarted {
        run_id: run_id.to_owned(),
        parent_session_id: parent_session_id.to_owned(),
        source: match source {
            WorkflowSource::Builtin => WorkflowSourceKind::Builtin,
            WorkflowSource::Inline => WorkflowSourceKind::Inline,
            WorkflowSource::File(_) => WorkflowSourceKind::File,
        },
        // Only built-in workflow names leave the machine; user script names and paths stay local
        workflow_name: (*source == WorkflowSource::Builtin).then(|| state.name.clone()),
        agent_budget: state.agent_budget,
        max_concurrent_agents: u32::try_from(max_concurrent_agents).unwrap_or(u32::MAX),
        resumed,
    });
}

struct RunEndMetadata<'a> {
    run_id: &'a str,
    parent_session_id: &'a str,
    status: fuigo_telemetry::events::WorkflowRunEndStatus,
    duration_ms: u64,
    agents_used: u64,
    agent_budget: Option<u64>,
}

fn log_run_ended(episode: RunEndMetadata<'_>, stats: &super::host_service::WorkflowAgentStats) {
    fuigo_telemetry::session_ctx::log_event(fuigo_telemetry::events::WorkflowRunEnded {
        run_id: episode.run_id.to_owned(),
        parent_session_id: episode.parent_session_id.to_owned(),
        status: episode.status,
        duration_ms: episode.duration_ms,
        agents_used: episode.agents_used,
        agent_budget: episode.agent_budget,
        agents_failed: stats.agents_failed.load(Ordering::Relaxed),
        peak_concurrent_agents: stats.peak_concurrent.load(Ordering::Relaxed),
        slot_waits: stats.slot_waits.load(Ordering::Relaxed),
        slot_wait_ms_total: stats.slot_wait_ms_total.load(Ordering::Relaxed),
        slot_wait_ms_max: stats.slot_wait_ms_max.load(Ordering::Relaxed),
    });
}

/// Exhaustive so a new tracker status forces a decision here.
fn run_ended_status(
    status: crate::session::workflow::tracker::WorkflowRunStatus,
) -> fuigo_telemetry::events::WorkflowRunEndStatus {
    use crate::session::workflow::tracker::WorkflowRunStatus as S;
    use fuigo_telemetry::events::WorkflowRunEndStatus as E;
    match status {
        S::Active => E::Active,
        S::UserPaused => E::UserPaused,
        S::BackOffPaused => E::BackOffPaused,
        S::NoProgressPaused => E::NoProgressPaused,
        S::InfraPaused => E::InfraPaused,
        S::Blocked => E::Blocked,
        S::BudgetLimited => E::BudgetLimited,
        S::Interrupted => E::Interrupted,
        S::Complete => E::Complete,
        S::Failed => E::Failed,
        S::Cancelled => E::Cancelled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::persistence::PersistenceMsg;
    use crate::session::workflow::registry::resolve_inline;

    type SubagentEventRx = mpsc::UnboundedReceiver<
        fuigo_tools::implementations::fuigo_build::task::types::SubagentEvent,
    >;
    type CancelLog = Arc<
        parking_lot::Mutex<
            Vec<fuigo_tools::implementations::fuigo_build::task::types::SubagentCancelTarget>,
        >,
    >;

    /// How long a test waits on a workflow channel before it declares the run wedged.
    ///
    /// Deliberately longer than the watcher's own 25 s host-drain bound, so a slow drain
    /// surfaces as the run's own `Failed { .. }` outcome and only a run that never reports
    /// at all trips this. Every healthy wait in this module completes in milliseconds;
    /// the bound is not a tuning knob, it converts "wedged forever" into a named failure.
    const WORKFLOW_TEST_DEADLINE: std::time::Duration = std::time::Duration::from_secs(40);

    /// Run one workflow test on its own current-thread runtime.
    ///
    /// Not `#[tokio::test]`, for one reason: dropping a runtime WAITS, unboundedly, for its
    /// `spawn_blocking` tasks, and a workflow's engine runs on exactly such a thread. Measured
    /// at the accepted baseline `2eb306e`: `active_run_admission_is_bounded_per_session` had
    /// PASSED its body and then sat in `BlockingPool::shutdown` for half an hour, because the
    /// engine thread it left behind was parked in `release_agent_calls`. A wedged run therefore
    /// turned even a bounded wait into a hang at teardown, with the diagnosis never printed
    /// (libtest holds a test's captured output until the test returns).
    ///
    /// Here teardown is bounded, and a blocking thread that outlives the bound FAILS the test
    /// (naming how many), instead of being waited for or silently leaked.
    fn run_workflow_test<F: std::future::Future<Output = ()>>(test: F) {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // `spawn_blocking` threads are the only threads a current-thread runtime starts, so
        // started-minus-stopped is exactly the number of engine threads still alive.
        let alive = Arc::new(AtomicUsize::new(0));
        let (on_start, on_stop) = (alive.clone(), alive.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .on_thread_start(move || {
                on_start.fetch_add(1, Ordering::SeqCst);
            })
            .on_thread_stop(move || {
                on_stop.fetch_sub(1, Ordering::SeqCst);
            })
            .build()
            .expect("test runtime");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.block_on(test);
        }));
        // Drop the runtime exactly as a `#[tokio::test]` would (scheduler shutdown first, which
        // drops the host service and so releases any engine thread waiting on it, then a wait
        // for the blocking pool), but on a helper thread, so the wait can be bounded.
        // `Runtime::shutdown_timeout` is NOT equivalent: it waits for the blocking pool BEFORE
        // the scheduler has dropped its tasks, so every healthy engine thread would time out.
        let grace = shutdown_grace();
        let (dropped_tx, dropped_rx) = std::sync::mpsc::channel();
        let teardown = std::thread::Builder::new()
            .name("workflow-test-runtime-drop".into())
            .spawn(move || {
                drop(runtime);
                let _ = dropped_tx.send(());
            })
            .expect("spawn runtime teardown thread");
        let torn_down = dropped_rx.recv_timeout(grace).is_ok();
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
        assert!(
            torn_down,
            "workflow test `{}` finished, but its runtime could not be torn down within {}s: \
             {} blocking thread(s) were still running, so a workflow engine thread is wedged \
             (most likely parked in `release_agent_calls`, waiting for a reply the host will \
             never send). Teardown is bounded so this is a named failure and not a hang \
             (R012 section 9b).",
            std::thread::current().name().unwrap_or("<unnamed>"),
            grace.as_secs_f32(),
            alive.load(Ordering::SeqCst),
        );
        teardown.join().expect("runtime teardown thread");
    }

    /// Healthy tests release their blocking threads in milliseconds; this only bounds a wedge.
    const RUNTIME_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(15);

    thread_local! {
        /// Lets the test that proves the bound shorten it; nothing else may.
        static DEADLINE_OVERRIDE: std::cell::Cell<Option<std::time::Duration>> =
            const { std::cell::Cell::new(None) };
        static SHUTDOWN_GRACE_OVERRIDE: std::cell::Cell<Option<std::time::Duration>> =
            const { std::cell::Cell::new(None) };
    }

    fn shutdown_grace() -> std::time::Duration {
        SHUTDOWN_GRACE_OVERRIDE
            .with(std::cell::Cell::get)
            .unwrap_or(RUNTIME_SHUTDOWN_GRACE)
    }

    fn workflow_test_deadline() -> std::time::Duration {
        DEADLINE_OVERRIDE
            .with(std::cell::Cell::get)
            .unwrap_or(WORKFLOW_TEST_DEADLINE)
    }

    /// Everything the manager knows about why a run has not reported, for a failure message.
    fn stall_diagnosis(manager: &WorkflowManager, waiting_for: &str, site: &str) -> String {
        let thread = std::thread::current();
        let mut runs = Vec::new();
        let tracker = manager.tracker.lock();
        for (run_id, active) in &manager.active {
            let state = tracker.get(run_id);
            runs.push(format!(
                "active {run_id}: tracker_status={} agents_used={:?} cancelled={} pause_intent={}",
                state
                    .as_ref()
                    .map(|s| s.status.as_str())
                    .unwrap_or("<absent>"),
                state.as_ref().map(|s| s.agents_used),
                active.cancel.is_cancelled(),
                active.pause_intent.load(Ordering::Relaxed),
            ));
        }
        for (run_id, _) in &manager.retiring {
            runs.push(format!(
                "retiring {run_id}: tracker_status={}",
                tracker
                    .get(run_id)
                    .map(|s| s.status.as_str())
                    .unwrap_or("<absent>"),
            ));
        }
        format!(
            "workflow test wedged: test `{}` at {site} waited {}s for {waiting_for} and it never \
             arrived. The wait is bounded so a wedged workflow fails with this diagnosis rather \
             than hanging the suite (a hang produces no failing set). Manager state: [{}]. Either \
             the workflow executor never finished (blocked in run_workflow), the host service \
             never drained, or the terminal-state persist was never acknowledged.",
            thread.name().unwrap_or("<unnamed>"),
            workflow_test_deadline().as_secs_f32(),
            runs.join("; "),
        )
    }

    async fn await_outcome(
        manager: &WorkflowManager,
        rx: oneshot::Receiver<WorkflowOutcome>,
        site: &str,
    ) -> Result<WorkflowOutcome, oneshot::error::RecvError> {
        match tokio::time::timeout(workflow_test_deadline(), rx).await {
            Ok(result) => result,
            Err(_) => panic!(
                "{}",
                stall_diagnosis(manager, "the run's WorkflowOutcome", site)
            ),
        }
    }

    async fn next_event(
        manager: &WorkflowManager,
        rx: &mut SubagentEventRx,
        what: &str,
        site: &str,
    ) -> fuigo_tools::implementations::fuigo_build::task::types::SubagentEvent {
        match tokio::time::timeout(workflow_test_deadline(), rx.recv()).await {
            Ok(Some(event)) => event,
            Ok(None) => panic!("{what}: subagent event channel closed before it arrived ({site})"),
            Err(_) => panic!(
                "{}",
                stall_diagnosis(manager, &format!("the subagent event `{what}`"), site)
            ),
        }
    }

    /// The run's outcome; a wedged run or a dropped sender is a named failure.
    macro_rules! outcome_of {
        ($manager:expr, $rx:expr) => {
            await_outcome(&$manager, $rx, concat!(file!(), ":", line!()))
                .await
                .expect("workflow watcher dropped its outcome sender without reporting")
        };
    }
    /// Wait for the run to settle and discard how; still bounded.
    macro_rules! settled_of {
        ($manager:expr, $rx:expr) => {
            let _ = await_outcome(&$manager, $rx, concat!(file!(), ":", line!())).await;
        };
    }
    macro_rules! event_of {
        ($manager:expr, $rx:expr, $what:expr) => {
            next_event(&$manager, &mut $rx, $what, concat!(file!(), ":", line!())).await
        };
    }

    fn test_manager(session_dir: Option<PathBuf>) -> (WorkflowManager, SubagentEventRx) {
        let (manager, events, _cancels) = test_manager_with_cancels(session_dir);
        (manager, events)
    }

    fn test_manager_with_cancels(
        session_dir: Option<PathBuf>,
    ) -> (WorkflowManager, SubagentEventRx, CancelLog) {
        use fuigo_tools::implementations::fuigo_build::task::types::{
            SubagentCancelOutcome, SubagentEvent,
        };

        let (subagent_tx, mut raw_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let cancels: CancelLog = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let cancels_stub = cancels.clone();
        tokio::spawn(async move {
            while let Some(event) = raw_rx.recv().await {
                match event {
                    SubagentEvent::Cancel(request) => {
                        cancels_stub.lock().push(request.target.clone());
                        let _ = request.respond_to.send(SubagentCancelOutcome::Cancelled);
                    }
                    other => {
                        if event_tx.send(other).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let (persist_tx, mut persist_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(message) = persist_rx.recv().await {
                if let PersistenceMsg::WorkflowRunStateAndAck { respond_to, .. } = message {
                    let _ = respond_to.send(Ok(()));
                }
            }
        });
        let (gateway_tx, _gateway_rx) = mpsc::unbounded_channel();
        let store = WorkflowRunStore::new(session_dir.clone(), persist_tx.clone());
        let notify = WorkflowNotifySender::new(
            agent_client_protocol::SessionId::new("test-session"),
            fuigo_acp_lib::AcpAgentGatewaySender::new(gateway_tx),
            persist_tx,
            store.clone(),
        );
        let tracker = Arc::new(parking_lot::Mutex::new(WorkflowTracker::default()));
        let manager = WorkflowManager::new(
            "test-session".into(),
            session_dir,
            std::env::temp_dir(),
            tracker,
            store,
            notify,
            subagent_tx,
            Arc::new(|_, _, _| {}),
            mpsc::unbounded_channel().0,
            HashMap::new(),
            crate::session::workflow::host_service::DEFAULT_WORKFLOW_MAX_CONCURRENT_AGENTS,
        );
        (manager, event_rx, cancels)
    }

    fn spec() -> LaunchSpec {
        LaunchSpec {
            objective: "obj".into(),
            args: serde_json::json!({}),
            agent_budget: None,
            effort: None,
            resume_run_id: None,
        }
    }

    fn parallel_n_script(n: usize) -> String {
        format!(
            "let meta = #{{ name: \"t\", description: \"d\" }};\n\
             let jobs = [];\n\
             let i = 0;\n\
             while i < {n} {{\n\
                 jobs.push(#{{ prompt: \"work \" + i.to_string() }});\n\
                 i += 1;\n\
             }}\n\
             let results = parallel(jobs);\n\
             complete(results.len());"
        )
    }

    /// The next subagent event, which must be a spawn. Bounded by the module's wedge deadline like every other must-arrive
    /// wait here. It used to be a fixed 2 s, which a loaded host exceeds before the engine's blocking thread compiles the
    /// script and dispatches its first agent ("expected spawn, timed out").
    async fn recv_spawn(
        manager: &WorkflowManager,
        rx: &mut SubagentEventRx,
        site: &str,
    ) -> fuigo_tools::implementations::fuigo_build::task::types::SubagentSpawnRequest {
        use fuigo_tools::implementations::fuigo_build::task::types::SubagentEvent;
        match next_event(manager, rx, "spawn", site).await {
            SubagentEvent::Spawn(req) => req,
            _ => panic!("expected spawn, got a non-spawn event ({site})"),
        }
    }

    macro_rules! spawn_of {
        ($manager:expr, $rx:expr) => {
            recv_spawn(&$manager, &mut $rx, concat!(file!(), ":", line!())).await
        };
    }

    fn complete_spawn(
        req: fuigo_tools::implementations::fuigo_build::task::types::SubagentSpawnRequest,
    ) {
        use fuigo_tools::implementations::fuigo_build::task::types::SubagentResult;
        let id = req.id.clone();
        let _ = req.result_tx.send(SubagentResult {
            success: true,
            output: std::sync::Arc::from("ok"),
            subagent_id: id.clone(),
            child_session_id: id,
            ..Default::default()
        });
    }

    #[test]
    fn launch_completes_and_updates_tracker() {
        run_workflow_test(async {
            let dir = tempfile::tempdir().unwrap();
            let (mut manager, _rx) = test_manager(Some(dir.path().to_path_buf()));
            let resolved = resolve_inline(
                "let meta = #{ name: \"t\", description: \"d\" };\ncomplete(\"done\");".into(),
            )
            .unwrap();
            let (run_id, outcome_rx) = manager.launch(resolved, spec()).unwrap();

            let outcome = outcome_of!(manager, outcome_rx);
            assert!(matches!(outcome, WorkflowOutcome::Completed { .. }));
            let state = manager.tracker.lock().get(&run_id).unwrap();
            assert_eq!(
                state.status,
                crate::session::workflow::tracker::WorkflowRunStatus::Complete
            );
            assert_eq!(state.result_summary.as_deref(), Some("done"));
            assert!(
                dir.path()
                    .join("workflows")
                    .join(&run_id)
                    .join("script.rhai")
                    .exists()
            );
        });
    }

    #[test]
    fn plain_resume_uses_immutable_script_not_edited_projection() {
        run_workflow_test(async {
            let dir = tempfile::tempdir().unwrap();
            let (mut manager, _rx) = test_manager(Some(dir.path().to_path_buf()));
            let script = "let meta = #{ name: \"t\", description: \"d\" };\nawait_user(\"user\", \"pause\");\ncomplete(\"original\");";
            let (run_id, outcome_rx) = manager
                .launch(resolve_inline(script.into()).unwrap(), spec())
                .unwrap();
            assert!(matches!(
                outcome_of!(manager, outcome_rx),
                WorkflowOutcome::Paused { .. }
            ));
            std::fs::write(
                manager.script_copy_path(&run_id).unwrap(),
                "let meta = #{ name: \"t\", description: \"d\" };\ncomplete(\"edited\");",
            )
            .unwrap();

            let (_same_id, outcome_rx) = manager
            .launch(
                resolve_inline(
                    "let meta = #{ name: \"t\", description: \"d\" };\ncomplete(\"caller copy\");"
                        .into(),
                )
                .unwrap(),
                LaunchSpec {
                    resume_run_id: Some(run_id),
                    ..spec()
                },
            )
            .unwrap();
            match outcome_of!(manager, outcome_rx) {
                WorkflowOutcome::Completed { result } => {
                    assert_eq!(result, serde_json::json!("original"));
                }
                other => panic!("expected Completed, got {other:?}"),
            }
        });
    }

    #[test]
    fn resume_reuses_immutable_launch_effort() {
        run_workflow_test(async {
            use fuigo_tools::implementations::fuigo_build::task::types::SubagentEvent;

            let dir = tempfile::tempdir().unwrap();
            let (mut manager, mut subagent_rx) = test_manager(Some(dir.path().to_path_buf()));
            let script = "let meta = #{ name: \"t\", description: \"d\" };\n\
                      await_user(\"user\", \"pause\");\n\
                      let r = agent(\"after resume\");\n\
                      complete(r.output);";
            let (run_id, first_outcome) = manager
                .launch(
                    resolve_inline(script.into()).unwrap(),
                    LaunchSpec {
                        effort: Some(ReasoningEffort::High),
                        ..spec()
                    },
                )
                .unwrap();
            assert!(matches!(
                outcome_of!(manager, first_outcome),
                WorkflowOutcome::Paused { .. }
            ));

            let (_same_id, resumed_outcome) = manager
                .launch(
                    resolve_inline(script.into()).unwrap(),
                    LaunchSpec {
                        effort: None,
                        resume_run_id: Some(run_id),
                        ..spec()
                    },
                )
                .unwrap();
            let SubagentEvent::Spawn(req) = event_of!(manager, subagent_rx, "resumed spawn") else {
                panic!("expected resumed spawn event");
            };
            assert_eq!(
                req.runtime_overrides.reasoning_effort.as_deref(),
                Some("high")
            );
            complete_spawn(req);
            assert!(matches!(
                outcome_of!(manager, resumed_outcome),
                WorkflowOutcome::Completed { .. }
            ));
        });
    }

    #[test]
    fn pause_eagerly_marks_user_paused() {
        run_workflow_test(async {
            let dir = tempfile::tempdir().unwrap();
            let (mut manager, _rx) = test_manager(Some(dir.path().to_path_buf()));
            let run_id = "wf_pause_eager".to_string();
            manager
                .store
                .register(
                    &run_id,
                    "let meta = #{ name: \"t\", description: \"d\" };",
                    &serde_json::json!({}),
                    None,
                )
                .unwrap();
            manager.tracker.lock().start_run(
                run_id.clone(),
                "t".into(),
                "obj".into(),
                Vec::new(),
                None,
                None,
            );
            let (_done_tx, done_rx) = oneshot::channel();
            manager.test_insert_active_run(run_id.clone(), done_rx);

            assert_eq!(
                manager.tracker.lock().get(&run_id).unwrap().status,
                crate::session::workflow::tracker::WorkflowRunStatus::Active,
            );
            assert!(manager.pause(&run_id));
            let state = manager.tracker.lock().get(&run_id).unwrap();
            assert_eq!(
                state.status,
                crate::session::workflow::tracker::WorkflowRunStatus::UserPaused,
                "pause() must eagerly mark UserPaused so status is not still Active"
            );
            assert!(!manager.active.contains_key(&run_id));
        });
    }

    #[test]
    fn control_ack_stops_by_name_without_a_completion_wake_and_rejects_inapplicable_or_unknown() {
        run_workflow_test(async {
            let dir = tempfile::tempdir().unwrap();
            let (mut manager, _rx) = test_manager(Some(dir.path().to_path_buf()));
            let run_id = "wf_ctrl".to_string();
            manager
                .store
                .register(
                    &run_id,
                    "let meta = #{ name: \"t\", description: \"d\" };",
                    &serde_json::json!({}),
                    None,
                )
                .unwrap();
            manager.tracker.lock().start_run(
                run_id.clone(),
                "review-changes".into(),
                "obj".into(),
                Vec::new(),
                None,
                None,
            );
            let (_done_tx, done_rx) = oneshot::channel();
            manager.test_insert_active_run(run_id.clone(), done_rx);

            let unknown = manager.control_ack("nope", WorkflowControl::Stop);
            assert!(
                matches!(
                    unknown,
                    WorkflowLaunchAck::Rejected {
                        code: "workflow_control_unknown_run",
                        ..
                    }
                ),
                "{unknown:?}"
            );

            let stopped = manager.control_ack("review-changes", WorkflowControl::Stop);
            assert!(
                matches!(
                    &stopped,
                    WorkflowLaunchAck::Controlled { run_id: id, name, control: WorkflowControl::Stop }
                        if id == &run_id && name == "review-changes"
                ),
                "{stopped:?}"
            );
            let stopped_state = manager.tracker.lock().get(&run_id).unwrap();
            assert_eq!(stopped_state.status, WorkflowRunStatus::Cancelled);
            assert!(
                !manager
                    .tracker
                    .lock()
                    .is_unreported_completion(&run_id, stopped_state.revision),
                "a tool-initiated stop must not queue a completion wake turn"
            );
            assert!(!manager.active.contains_key(&run_id));

            let paused = manager.control_ack(&run_id, WorkflowControl::Pause);
            assert!(
                matches!(
                    &paused,
                    WorkflowLaunchAck::Rejected { code: "workflow_control_not_applicable", detail }
                        if detail == "run 'review-changes' is cancelled and cannot be paused"
                ),
                "{paused:?}"
            );
        });
    }

    #[test]
    fn control_ack_pauses_an_active_run_by_run_id_and_keeps_the_completion_wake() {
        run_workflow_test(async {
            let dir = tempfile::tempdir().unwrap();
            let (mut manager, _rx) = test_manager(Some(dir.path().to_path_buf()));
            let run_id = "wf_ctrl_pause".to_string();
            manager
                .store
                .register(
                    &run_id,
                    "let meta = #{ name: \"t\", description: \"d\" };",
                    &serde_json::json!({}),
                    None,
                )
                .unwrap();
            manager.tracker.lock().start_run(
                run_id.clone(),
                "review-changes".into(),
                "obj".into(),
                Vec::new(),
                None,
                None,
            );
            let (_done_tx, done_rx) = oneshot::channel();
            manager.test_insert_active_run(run_id.clone(), done_rx);

            let paused = manager.control_ack(&run_id, WorkflowControl::Pause);
            assert!(
                matches!(
                    &paused,
                    WorkflowLaunchAck::Controlled { run_id: id, name, control: WorkflowControl::Pause }
                        if id == &run_id && name == "review-changes"
                ),
                "{paused:?}"
            );
            let state = manager.tracker.lock().get(&run_id).unwrap();
            assert_eq!(state.status, WorkflowRunStatus::UserPaused);
            assert!(!manager.active.contains_key(&run_id));

            // Only a stop opts out of the completion wake; a pause is not a completion.
            let (_restored, fresh) = manager.tracker.lock().take_unreported_terminal_runs();
            assert!(fresh.is_empty(), "{fresh:?}");
        });
    }

    #[test]
    fn control_run_refuses_to_stop_a_budget_limited_run_so_resume_still_needs_a_raised_cap() {
        run_workflow_test(async {
            let dir = tempfile::tempdir().unwrap();
            let (mut manager, mut subagent_rx) = test_manager(Some(dir.path().to_path_buf()));
            let script = "let meta = #{ name: \"t\", description: \"d\" };\n\
                      let r = agent(\"work\");\ncomplete(r.output);";
            let (run_id, _outcome) = manager
                .launch(resolve_inline(script.into()).unwrap(), spec())
                .unwrap();
            let _child = spawn_of!(manager, subagent_rx);
            manager.tracker.lock().apply_outcome(
                &run_id,
                &WorkflowOutcome::BudgetExceeded {
                    message: "budget".into(),
                },
            );

            assert_eq!(
                manager
                    .control_run(&run_id, WorkflowControl::Stop)
                    .unwrap_err(),
                ControlError::NotApplicable {
                    name: "t".to_owned(),
                    status: WorkflowRunStatus::BudgetLimited,
                    control: WorkflowControl::Stop,
                }
            );
            assert_eq!(
                manager.tracker.lock().get(&run_id).unwrap().status,
                WorkflowRunStatus::BudgetLimited
            );
            let resume = LaunchSpec {
                resume_run_id: Some(run_id.clone()),
                ..spec()
            };
            assert!(matches!(
                manager
                    .launch(resolve_inline(script.into()).unwrap(), resume)
                    .unwrap_err(),
                LaunchError::BudgetNotRaised { .. }
            ));
        });
    }

    #[test]
    fn control_run_refuses_to_pause_an_engine_paused_run() {
        run_workflow_test(async {
            let dir = tempfile::tempdir().unwrap();
            let (mut manager, mut subagent_rx) = test_manager(Some(dir.path().to_path_buf()));
            let script = "let meta = #{ name: \"t\", description: \"d\" };\n\
                      let r = agent(\"work\");\ncomplete(r.output);";
            let (run_id, _outcome) = manager
                .launch(resolve_inline(script.into()).unwrap(), spec())
                .unwrap();
            let _child = spawn_of!(manager, subagent_rx);
            manager.tracker.lock().apply_outcome(
                &run_id,
                &WorkflowOutcome::Paused {
                    kind: fuigo_workflow::PauseKind::BackOff,
                    message: "backing off".into(),
                },
            );

            // The run is still in `active`, so a bare pause() would report success without changing anything.
            assert_eq!(
                manager
                    .control_run(&run_id, WorkflowControl::Pause)
                    .unwrap_err(),
                ControlError::NotApplicable {
                    name: "t".to_owned(),
                    status: WorkflowRunStatus::BackOffPaused,
                    control: WorkflowControl::Pause,
                }
            );
            assert_eq!(
                manager.tracker.lock().get(&run_id).unwrap().status,
                WorkflowRunStatus::BackOffPaused
            );
        });
    }

    #[test]
    fn pause_marks_user_paused_and_resume_rejects_unknown_effect() {
        run_workflow_test(async {
            let dir = tempfile::tempdir().unwrap();
            let (mut manager, mut subagent_rx) = test_manager(Some(dir.path().to_path_buf()));
            let script = "let meta = #{ name: \"t\", description: \"d\" };\nlet r = agent(\"work\");\ncomplete(r.output);";
            let resolved = resolve_inline(script.into()).unwrap();
            let (run_id, outcome_rx) = manager.launch(resolved, spec()).unwrap();

            let _spawn = spawn_of!(manager, subagent_rx);
            assert!(manager.pause(&run_id));
            assert_eq!(
                manager.tracker.lock().get(&run_id).unwrap().status,
                crate::session::workflow::tracker::WorkflowRunStatus::UserPaused,
                "pause() must mark UserPaused immediately"
            );
            let outcome = tokio::time::timeout(std::time::Duration::from_secs(30), outcome_rx)
                .await
                .expect("pause did not drain")
                .unwrap();
            assert!(matches!(outcome, WorkflowOutcome::Cancelled));
            let state = manager.tracker.lock().get(&run_id).unwrap();
            assert_eq!(
                state.status,
                crate::session::workflow::tracker::WorkflowRunStatus::UserPaused,
                "pause intent must map Cancelled → UserPaused"
            );

            let resolved = resolve_inline(script.into()).unwrap();
            let (_run_id2, outcome_rx) = manager
                .launch(
                    resolved,
                    LaunchSpec {
                        resume_run_id: Some(run_id.clone()),
                        ..spec()
                    },
                )
                .unwrap();
            // The first child was dispatched, but its result is unknown. V2 journals
            // must not blindly replay that effect, even after a clean user pause.
            let outcome = tokio::time::timeout(std::time::Duration::from_secs(30), outcome_rx)
                .await
                .expect("resume did not report its outcome")
                .unwrap();
            match outcome {
                WorkflowOutcome::Failed { error } => {
                    assert!(error.contains("unknown outcome"), "{error}");
                }
                other => panic!("expected unknown-outcome failure, got {other:?}"),
            }
            assert!(
                subagent_rx.try_recv().is_err(),
                "unknown effect must not respawn"
            );
        });
    }

    /// The journal of a run that has not journaled a step: the v2 header written at creation and an
    /// empty dispatch sidecar. Asserting it proves the run stopped before its first journaled step.
    fn assert_nothing_journaled(dir: &std::path::Path, run_id: &str) {
        let journal = dir.join("workflows").join(run_id).join("journal.jsonl");
        assert_eq!(
            std::fs::read_to_string(&journal).unwrap(),
            "{\"fuigo_workflow_journal_version\":2}\n",
            "the run must have stopped before its first journaled step"
        );
        assert_eq!(
            std::fs::read_to_string(journal.with_extension("dispatch-v2.jsonl")).unwrap(),
            "",
            "the run must have stopped before dispatching anything"
        );
    }

    /// P45: a run paused before its first journaled step resumes as a fresh start of the same run.
    /// Before the fix its journal file was never written, loaded as legacy, and the resume failed
    /// with `LegacyBoundary` at its first dispatch.
    #[test]
    fn pause_before_the_first_journaled_step_resumes_as_a_fresh_start() {
        run_workflow_test(async {
            use fuigo_tools::implementations::fuigo_build::task::types::SubagentEvent;

            let dir = tempfile::tempdir().unwrap();
            let (mut manager, mut subagent_rx) = test_manager(Some(dir.path().to_path_buf()));
            // A pure-compute prologue (about a second unoptimised): the pause lands in it, before any
            // host call, unless this thread is descheduled for longer than the loop runs. If it ever
            // lands later, `assert_nothing_journaled` fails by name rather than the test passing
            // vacuously. (No hook exists to hold the engine before its first host call.)
            let script = "let meta = #{ name: \"t\", description: \"d\" };\n\
                      let i = 0;\n\
                      while i < 3000000 { i += 1; }\n\
                      let r = agent(\"work\");\n\
                      complete(r.output);";
            let (run_id, outcome_rx) = manager
                .launch(resolve_inline(script.into()).unwrap(), spec())
                .unwrap();
            assert!(manager.pause(&run_id));
            assert!(matches!(
                outcome_of!(manager, outcome_rx),
                WorkflowOutcome::Cancelled
            ));
            assert_eq!(
                manager.tracker.lock().get(&run_id).unwrap().status,
                crate::session::workflow::tracker::WorkflowRunStatus::UserPaused
            );
            assert_nothing_journaled(dir.path(), &run_id);
            assert!(subagent_rx.try_recv().is_err(), "nothing was spawned");

            let (same_id, outcome_rx) = manager
                .launch(
                    resolve_inline(script.into()).unwrap(),
                    LaunchSpec {
                        resume_run_id: Some(run_id.clone()),
                        ..spec()
                    },
                )
                .unwrap();
            assert_eq!(same_id, run_id);
            let SubagentEvent::Spawn(req) = event_of!(manager, subagent_rx, "spawn after resume")
            else {
                panic!("expected the resumed run's first spawn");
            };
            complete_spawn(req);
            match outcome_of!(manager, outcome_rx) {
                WorkflowOutcome::Completed { result } => {
                    assert_eq!(result, serde_json::json!("ok"));
                }
                other => panic!("expected Completed, got {other:?}"),
            }
            assert_eq!(
                manager.tracker.lock().get(&run_id).unwrap().status,
                crate::session::workflow::tracker::WorkflowRunStatus::Complete
            );
            let journal = Journal::load(
                dir.path()
                    .join("workflows")
                    .join(&run_id)
                    .join("journal.jsonl"),
            )
            .unwrap();
            assert_eq!(journal.len(), 1, "the fresh start journals its one spawn");
        });
    }

    /// P45, the stopped variant: a run that hits its agent cap before its first journaled step (the
    /// reservation is refused before any dispatch) resumes with a raised cap as a fresh start.
    #[test]
    fn budget_stop_before_the_first_journaled_step_resumes_as_a_fresh_start() {
        run_workflow_test(async {
            use fuigo_tools::implementations::fuigo_build::task::types::SubagentEvent;

            let dir = tempfile::tempdir().unwrap();
            let (mut manager, mut subagent_rx) = test_manager(Some(dir.path().to_path_buf()));
            let script = "let meta = #{ name: \"t\", description: \"d\" };\n\
                      let r = agent(\"work\");\n\
                      complete(r.output);";
            let (run_id, outcome_rx) = manager
                .launch(
                    resolve_inline(script.into()).unwrap(),
                    LaunchSpec {
                        agent_budget: Some(0),
                        ..spec()
                    },
                )
                .unwrap();
            match outcome_of!(manager, outcome_rx) {
                WorkflowOutcome::BudgetExceeded { .. } => {}
                other => panic!("expected BudgetExceeded, got {other:?}"),
            }
            assert_eq!(
                manager.tracker.lock().get(&run_id).unwrap().status,
                crate::session::workflow::tracker::WorkflowRunStatus::BudgetLimited
            );
            assert_nothing_journaled(dir.path(), &run_id);
            assert!(subagent_rx.try_recv().is_err(), "nothing was spawned");

            let (_same_id, outcome_rx) = manager
                .launch(
                    resolve_inline(script.into()).unwrap(),
                    LaunchSpec {
                        agent_budget: Some(1),
                        resume_run_id: Some(run_id.clone()),
                        ..spec()
                    },
                )
                .unwrap();
            let SubagentEvent::Spawn(req) = event_of!(manager, subagent_rx, "spawn after resume")
            else {
                panic!("expected the resumed run's first spawn");
            };
            complete_spawn(req);
            match outcome_of!(manager, outcome_rx) {
                WorkflowOutcome::Completed { result } => {
                    assert_eq!(result, serde_json::json!("ok"));
                }
                other => panic!("expected Completed, got {other:?}"),
            }
        });
    }

    #[test]
    fn resume_reconciles_agents_used_from_journal_no_double_charge() {
        run_workflow_test(async {
            use fuigo_tools::implementations::fuigo_build::task::types::SubagentEvent;

            let dir = tempfile::tempdir().unwrap();
            let (mut manager, mut subagent_rx) = test_manager(Some(dir.path().to_path_buf()));
            let script = "let meta = #{ name: \"t\", description: \"d\" };\nlet r = agent(\"work\");\ncomplete(r.output);";
            let (run_id, outcome_rx) = manager
                .launch(resolve_inline(script.into()).unwrap(), spec())
                .unwrap();

            let SubagentEvent::Spawn(_first) = event_of!(manager, subagent_rx, "first spawn")
            else {
                panic!("expected spawn event");
            };
            assert_eq!(
                manager.tracker.lock().get(&run_id).unwrap().agents_used,
                1,
                "the live agent reserves one slot before it spawns"
            );

            assert!(manager.pause(&run_id));
            assert!(matches!(
                outcome_of!(manager, outcome_rx),
                WorkflowOutcome::Cancelled
            ));
            assert_eq!(
                manager.tracker.lock().get(&run_id).unwrap().agents_used,
                1,
                "cancel tears the host down before the release lands, so the reserved slot leaks in memory"
            );

            let (_resumed_id, outcome_rx) = manager
                .launch(
                    resolve_inline(script.into()).unwrap(),
                    LaunchSpec {
                        resume_run_id: Some(run_id.clone()),
                        ..spec()
                    },
                )
                .unwrap();
            // The spawn was journaled as dispatched with no recorded result. The bounded
            // engine refuses to replay an effect with an unknown outcome, so resume fails
            // instead of respawning (see pause_marks_user_paused_and_resume_rejects_unknown_effect).
            let outcome = tokio::time::timeout(std::time::Duration::from_secs(30), outcome_rx)
                .await
                .expect("resume did not report its outcome")
                .unwrap();
            match outcome {
                WorkflowOutcome::Failed { error } => {
                    assert!(error.contains("unknown outcome"), "{error}");
                }
                other => panic!("expected unknown-outcome failure, got {other:?}"),
            }
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(200), subagent_rx.recv())
                    .await
                    .is_err(),
                "unknown effect must not respawn"
            );

            assert_eq!(
                manager.tracker.lock().get(&run_id).unwrap().agents_used,
                0,
                "resume reconciles agents_used from the journal (0 recorded reservations) and the \
             refused replay reserves nothing; without the reconcile the slot leaked at pause would \
             stay charged and any later re-reservation would double-charge"
            );
        });
    }

    #[test]
    fn failed_run_resumes_and_reexecutes_failed_host_call_live() {
        run_workflow_test(async {
            let dir = tempfile::tempdir().unwrap();
            let (mut manager, _rx) = test_manager(Some(dir.path().to_path_buf()));
            let script = "let meta = #{ name: \"t\", description: \"d\" };\n\
                      let content = read_scratch_file(\"data.txt\");\n\
                      complete(content);";
            let (run_id, outcome_rx) = manager
                .launch(resolve_inline(script.into()).unwrap(), spec())
                .unwrap();
            match outcome_of!(manager, outcome_rx) {
                WorkflowOutcome::Failed { error } => {
                    assert!(error.contains("scratch"), "{error}");
                }
                other => panic!("expected Failed, got {other:?}"),
            }
            assert_eq!(
                manager.tracker.lock().get(&run_id).unwrap().status,
                crate::session::workflow::tracker::WorkflowRunStatus::Failed
            );
            let journal_path = dir
                .path()
                .join("workflows")
                .join(&run_id)
                .join("journal.jsonl");
            assert!(
                std::fs::read_to_string(&journal_path)
                    .unwrap()
                    .contains("__fuigo_workflow_host_error"),
                "the uncaught host error must be journaled as a trailing sentinel"
            );

            let scratch = dir.path().join("workflows").join(&run_id).join("scratch");
            std::fs::create_dir_all(&scratch).unwrap();
            std::fs::write(scratch.join("data.txt"), "hello").unwrap();

            let (_same_id, outcome_rx) = manager
                .launch(
                    resolve_inline(script.into()).unwrap(),
                    LaunchSpec {
                        resume_run_id: Some(run_id.clone()),
                        ..spec()
                    },
                )
                .unwrap();
            match outcome_of!(manager, outcome_rx) {
                WorkflowOutcome::Completed { result } => {
                    assert_eq!(
                        result,
                        serde_json::json!("hello"),
                        "the failed host call must go live instead of replaying the sentinel"
                    );
                }
                other => panic!("expected Completed, got {other:?}"),
            }
            assert_eq!(
                manager.tracker.lock().get(&run_id).unwrap().status,
                crate::session::workflow::tracker::WorkflowRunStatus::Complete
            );
            assert!(
                !std::fs::read_to_string(&journal_path)
                    .unwrap()
                    .contains("__fuigo_workflow_host_error"),
                "the trailing sentinel must be pruned and replaced by the live result"
            );
        });
    }

    #[test]
    fn completed_and_interrupted_runs_are_not_resumable() {
        run_workflow_test(async {
            use fuigo_tools::implementations::fuigo_build::task::types::{
                SubagentEvent, SubagentResult,
            };

            let dir = tempfile::tempdir().unwrap();
            let (mut manager, mut subagent_rx) = test_manager(Some(dir.path().to_path_buf()));
            let script = "let meta = #{ name: \"t\", description: \"d\" };\nlet a = agent(\"step one\");\ncomplete(a.output);";
            let (run_id, outcome_rx) = manager
                .launch(resolve_inline(script.into()).unwrap(), spec())
                .unwrap();
            let SubagentEvent::Spawn(req) = event_of!(manager, subagent_rx, "first spawn") else {
                panic!("expected spawn event");
            };
            let id = req.id.clone();
            let _ = req.result_tx.send(SubagentResult {
                success: true,
                output: std::sync::Arc::from("one"),
                subagent_id: id,
                ..Default::default()
            });
            assert!(matches!(
                outcome_of!(manager, outcome_rx),
                WorkflowOutcome::Completed { .. }
            ));

            let state = manager.tracker.lock().get(&run_id).unwrap();
            for status in [
                crate::session::workflow::tracker::WorkflowRunStatus::Complete,
                crate::session::workflow::tracker::WorkflowRunStatus::Interrupted,
            ] {
                let mut restored = state.clone();
                restored.status = status;
                let original_tracker = manager.tracker.clone();
                manager.tracker = Arc::new(parking_lot::Mutex::new(
                    WorkflowTracker::from_snapshot(vec![restored]),
                ));
                let err = manager
                    .launch(
                        resolve_inline(script.into()).unwrap(),
                        LaunchSpec {
                            resume_run_id: Some(run_id.clone()),
                            ..spec()
                        },
                    )
                    .unwrap_err();
                manager.tracker = original_tracker;
                assert!(
                    matches!(err, LaunchError::NotResumable(_)),
                    "{status:?}: {err}"
                );
            }

            let mut cancelled = state.clone();
            cancelled.status = crate::session::workflow::tracker::WorkflowRunStatus::Cancelled;
            manager.tracker = Arc::new(parking_lot::Mutex::new(WorkflowTracker::from_snapshot(
                vec![cancelled],
            )));
            manager
                .launch(
                    resolve_inline(script.into()).unwrap(),
                    LaunchSpec {
                        resume_run_id: Some(run_id.clone()),
                        ..spec()
                    },
                )
                .expect("cancelled /workflow stop runs stay resumable from the journal");
        });
    }

    #[test]
    fn shutdown_timeout_marks_active_run_interrupted() {
        run_workflow_test(async {
            let dir = tempfile::tempdir().unwrap();
            let (mut manager, _rx) = test_manager(Some(dir.path().to_path_buf()));
            let run_id = "wf_timeout".to_string();
            manager
                .store
                .register(
                    &run_id,
                    "let meta = #{ name: \"t\", description: \"d\" };",
                    &serde_json::json!({}),
                    None,
                )
                .unwrap();
            manager.tracker.lock().start_run(
                run_id.clone(),
                "t".into(),
                "obj".into(),
                Vec::new(),
                None,
                None,
            );
            let (_done_tx, done_rx) = oneshot::channel();
            manager.test_insert_active_run(run_id.clone(), done_rx);

            let result = manager
                .cancel_all_and_drain(std::time::Duration::from_millis(1))
                .await;
            assert_eq!(result.unwrap_err(), vec![run_id.clone()]);
            let state = manager.tracker.lock().get(&run_id).unwrap();
            assert_eq!(
                state.status,
                crate::session::workflow::tracker::WorkflowRunStatus::Interrupted
            );
            assert!(!state.status.is_paused());
        });
    }

    #[test]
    fn workflow_spawns_await_to_completion() {
        run_workflow_test(async {
            use fuigo_tools::implementations::fuigo_build::task::types::{
                SubagentEvent, SubagentResult,
            };

            let dir = tempfile::tempdir().unwrap();
            let (mut manager, mut subagent_rx) = test_manager(Some(dir.path().to_path_buf()));
            let resolved = resolve_inline(
                "let meta = #{ name: \"t\", description: \"d\" };\n\
             let r = agent(\"work\");\n\
             complete(r.output);"
                    .into(),
            )
            .unwrap();
            let (_run_id, outcome_rx) = manager.launch(resolved, spec()).unwrap();

            let spawn_req = event_of!(manager, subagent_rx, "spawn event");
            let SubagentEvent::Spawn(req) = spawn_req else {
                panic!("expected spawn event");
            };
            assert!(
                req.await_to_completion,
                "workflow agent spawns must disable the ordinary task-tool await budget"
            );
            assert!(
                req.owner.is_workflow(),
                "workflow agent spawns must carry run lifecycle ownership"
            );
            assert_eq!(
            req.runtime_overrides.model_override_provenance,
            fuigo_tools::implementations::fuigo_build::task::types::ModelOverrideProvenance::Tool,
            "script model overrides are untrusted tool provenance"
        );
            assert_eq!(req.runtime_overrides.reasoning_effort, None);
            let id = req.id.clone();
            let _ = req.result_tx.send(SubagentResult {
                success: true,
                output: std::sync::Arc::from("slow but done"),
                subagent_id: id,
                ..Default::default()
            });
            let outcome = outcome_of!(manager, outcome_rx);
            assert!(matches!(outcome, WorkflowOutcome::Completed { .. }));
        });
    }

    #[test]
    fn launch_effort_applies_to_children_and_child_override_wins() {
        run_workflow_test(async {
            use fuigo_tools::implementations::fuigo_build::task::types::SubagentEvent;

            let dir = tempfile::tempdir().unwrap();
            let (mut manager, mut subagent_rx) = test_manager(Some(dir.path().to_path_buf()));
            let resolved = resolve_inline(
                "let meta = #{ name: \"t\", description: \"d\" };\n\
             let results = parallel([\n\
                 #{ prompt: \"inherits\" },\n\
                 #{ prompt: \"overrides\", effort: \"LoW\" },\n\
             ]);\n\
             complete(results.len());"
                    .into(),
            )
            .unwrap();
            let (_run_id, outcome_rx) = manager
                .launch(
                    resolved,
                    LaunchSpec {
                        effort: Some(ReasoningEffort::High),
                        ..spec()
                    },
                )
                .unwrap();

            let mut efforts = HashMap::new();
            for _ in 0..2 {
                let SubagentEvent::Spawn(req) = event_of!(manager, subagent_rx, "spawn") else {
                    panic!("expected spawn event");
                };
                efforts.insert(
                    req.request.prompt.clone(),
                    req.request.runtime_overrides.reasoning_effort.clone(),
                );
                complete_spawn(req);
            }
            assert_eq!(
                efforts.get("inherits").and_then(Option::as_deref),
                Some("high")
            );
            assert_eq!(
                efforts.get("overrides").and_then(Option::as_deref),
                Some("low")
            );
            assert!(matches!(
                outcome_of!(manager, outcome_rx),
                WorkflowOutcome::Completed { .. }
            ));
        });
    }

    #[test]
    fn agent_rejects_invalid_effort_before_spawning() {
        run_workflow_test(async {
            let dir = tempfile::tempdir().unwrap();
            let (mut manager, mut subagent_rx) = test_manager(Some(dir.path().to_path_buf()));
            let resolved = resolve_inline(
                "let meta = #{ name: \"t\", description: \"d\" };\n\
             agent(\"work\", #{ effort: \"turbo\" });"
                    .into(),
            )
            .unwrap();
            let (_run_id, outcome_rx) = manager.launch(resolved, spec()).unwrap();

            match outcome_of!(manager, outcome_rx) {
                WorkflowOutcome::Failed { error } => {
                    assert!(error.contains("invalid workflow agent effort"), "{error}");
                    assert!(error.contains("turbo"), "{error}");
                }
                other => panic!("expected Failed, got {other:?}"),
            }
            assert!(
                subagent_rx.try_recv().is_err(),
                "invalid effort must not reach the coordinator"
            );
        });
    }

    #[test]
    fn parallel_nulls_invalid_child_effort_without_spawning() {
        run_workflow_test(async {
            let dir = tempfile::tempdir().unwrap();
            let (mut manager, mut subagent_rx) = test_manager(Some(dir.path().to_path_buf()));
            let resolved = resolve_inline(
                "let meta = #{ name: \"t\", description: \"d\" };\n\
             let results = parallel([#{ prompt: \"work\", effort: \"turbo\" }]);\n\
             complete(results);"
                    .into(),
            )
            .unwrap();
            let (_run_id, outcome_rx) = manager.launch(resolved, spec()).unwrap();

            match outcome_of!(manager, outcome_rx) {
                WorkflowOutcome::Completed { result } => {
                    assert_eq!(result, serde_json::json!([null]));
                }
                other => panic!("expected Completed, got {other:?}"),
            }
            assert!(
                subagent_rx.try_recv().is_err(),
                "invalid effort must not reach the coordinator"
            );
        });
    }

    #[test]
    fn active_run_admission_is_bounded_per_session() {
        run_workflow_test(async {
            let dir = tempfile::tempdir().unwrap();
            let (mut manager, mut subagent_rx) = test_manager(Some(dir.path().to_path_buf()));
            let script = "let meta = #{ name: \"t\", description: \"d\" };\n\
                      let r = agent(\"work\");\ncomplete(r.output);";
            let mut outcomes = Vec::new();
            let mut spawned = Vec::new();
            for _ in 0..WORKFLOW_MAX_ACTIVE_RUNS_PER_SESSION {
                let (_, outcome) = manager
                    .launch(resolve_inline(script.into()).unwrap(), spec())
                    .unwrap();
                outcomes.push(outcome);
                spawned.push(event_of!(manager, subagent_rx, "spawn event"));
            }
            let error = manager
                .launch(resolve_inline(script.into()).unwrap(), spec())
                .unwrap_err();
            assert!(matches!(error, LaunchError::TooManyActiveRuns));
            drop(spawned);
            let _ = manager
                .cancel_all_and_drain(std::time::Duration::from_secs(1))
                .await;
            drop(outcomes);
        });
    }

    #[test]
    fn retiring_runs_still_consume_session_admission() {
        run_workflow_test(async {
            let dir = tempfile::tempdir().unwrap();
            let (mut manager, _subagent_rx) = test_manager(Some(dir.path().to_path_buf()));
            let mut done_senders = Vec::new();
            for index in 0..WORKFLOW_MAX_ACTIVE_RUNS_PER_SESSION {
                let (done_tx, done_rx) = oneshot::channel();
                manager
                    .retiring
                    .push((format!("retiring-{index}"), done_rx));
                done_senders.push(done_tx);
                assert_eq!(manager.retiring.len(), index + 1);
            }

            let resolved = resolve_inline(
                "let meta = #{ name: \"t\", description: \"d\" };\ncomplete(\"done\");".into(),
            )
            .unwrap();
            assert!(matches!(
                manager.launch(resolved, spec()).unwrap_err(),
                LaunchError::TooManyActiveRuns
            ));

            done_senders.pop().unwrap().send(()).unwrap();
            manager.reap_terminal_runs();
            assert_eq!(
                manager.retiring.len(),
                WORKFLOW_MAX_ACTIVE_RUNS_PER_SESSION - 1
            );
            assert!(
                manager.active.len().saturating_add(manager.retiring.len())
                    < WORKFLOW_MAX_ACTIVE_RUNS_PER_SESSION
            );
            drop(done_senders);
        });
    }

    #[test]
    fn untrusted_workflow_cannot_fork_parent_context() {
        run_workflow_test(async {
            let dir = tempfile::tempdir().unwrap();
            let (mut manager, mut subagent_rx) = test_manager(Some(dir.path().to_path_buf()));
            let resolved = resolve_inline(
                "let meta = #{ name: \"t\", description: \"d\" };\n\
             let r = agent(\"work\", #{ fork_context: true });\n\
             complete(r.output);"
                    .into(),
            )
            .unwrap();
            let (_run_id, outcome_rx) = manager.launch(resolved, spec()).unwrap();

            match outcome_of!(manager, outcome_rx) {
                WorkflowOutcome::Failed { error } => {
                    assert!(error.contains("fork_context is restricted to built-in workflows"));
                }
                other => panic!("expected Failed, got {other:?}"),
            }
            assert!(
                subagent_rx.try_recv().is_err(),
                "rejected fork_context must not reach the coordinator"
            );
        });
    }

    #[test]
    fn output_schema_stays_host_side_with_one_corrective_retry() {
        run_workflow_test(async {
            use fuigo_tools::implementations::fuigo_build::task::types::{
                SubagentEvent, SubagentResult,
            };

            let dir = tempfile::tempdir().unwrap();
            let (mut manager, mut subagent_rx) = test_manager(Some(dir.path().to_path_buf()));
            let resolved = resolve_inline(
            "let meta = #{ name: \"t\", description: \"d\" };\n\
             let r = agent(\"scan\", #{ output_schema: #{ \"type\": \"object\", \
             \"required\": [\"ok\"], \"properties\": #{ \"ok\": #{ \"type\": \"boolean\" } } } });\n\
             complete(r.output.ok);"
                .into(),
        )
        .unwrap();
            let (_run_id, outcome_rx) = manager
                .launch(
                    resolved,
                    LaunchSpec {
                        agent_budget: Some(5),
                        ..spec()
                    },
                )
                .unwrap();

            let SubagentEvent::Spawn(req) = event_of!(manager, subagent_rx, "first spawn") else {
                panic!("expected spawn event");
            };
            assert!(
                req.runtime_overrides.output_schema.is_none(),
                "schema must not be passed to the child runtime"
            );
            assert!(
                req.prompt.contains("<output-contract>"),
                "prompt must carry the schema contract"
            );
            assert!(req.resume_from.is_none());
            assert_eq!(req.runtime_overrides.output_token_budget, None);
            let first_id = req.id.clone();
            let _ = req.result_tx.send(SubagentResult {
                success: true,
                output: std::sync::Arc::from("All files scanned, nothing found."),
                subagent_id: first_id.clone(),
                child_session_id: first_id.clone(),
                tokens_used: 100,
                output_tokens_used: 100,
                total_tokens_used: 100,
                ..Default::default()
            });

            let SubagentEvent::Spawn(retry) = event_of!(manager, subagent_rx, "corrective retry")
            else {
                panic!("expected retry spawn event");
            };
            assert_eq!(retry.resume_from.as_deref(), Some(first_id.as_str()));
            assert!(retry.prompt.contains("did not satisfy the output contract"));
            assert_eq!(retry.runtime_overrides.output_token_budget, None);
            let retry_id = retry.id.clone();
            let _ = retry.result_tx.send(SubagentResult {
                success: true,
                output: std::sync::Arc::from("```json\n{\"ok\": true}\n```"),
                subagent_id: retry_id.clone(),
                child_session_id: retry_id,
                tokens_used: 50,
                output_tokens_used: 50,
                total_tokens_used: 50,
                ..Default::default()
            });

            let outcome = outcome_of!(manager, outcome_rx);
            match outcome {
                WorkflowOutcome::Completed { result } => {
                    assert_eq!(result, serde_json::json!(true));
                }
                other => panic!("expected Completed, got {other:?}"),
            }
            let state = manager.tracker.lock().list().into_iter().next().unwrap();
            assert_eq!(state.agents_used, 1, "schema retry is one logical agent");
            assert_eq!(state.agent_budget, Some(5));
        });
    }

    #[test]
    fn explicit_max_output_tokens_is_ignored_and_run_charges_totals() {
        run_workflow_test(async {
            use fuigo_tools::implementations::fuigo_build::task::types::{
                SubagentEvent, SubagentResult,
            };

            let dir = tempfile::tempdir().unwrap();
            let (mut manager, mut subagent_rx) = test_manager(Some(dir.path().to_path_buf()));
            let resolved = resolve_inline(
                "let meta = #{ name: \"t\", description: \"d\" };\n\
             let r = agent(\"work\", #{ max_output_tokens: 900 });\n\
             complete(r.output);"
                    .into(),
            )
            .unwrap();
            let (run_id, outcome_rx) = manager
                .launch(
                    resolved,
                    LaunchSpec {
                        agent_budget: Some(2),
                        ..spec()
                    },
                )
                .unwrap();
            let SubagentEvent::Spawn(req) = event_of!(manager, subagent_rx, "spawn") else {
                panic!("expected spawn");
            };
            assert_eq!(req.runtime_overrides.output_token_budget, None);
            let id = req.id.clone();
            let _ = req.result_tx.send(SubagentResult {
                success: true,
                output: std::sync::Arc::from("done"),
                subagent_id: id.clone(),
                child_session_id: id,
                output_tokens_used: 120,
                total_tokens_used: 120,
                ..Default::default()
            });
            assert!(matches!(
                outcome_of!(manager, outcome_rx),
                WorkflowOutcome::Completed { .. }
            ));
            let state = manager.tracker.lock().get(&run_id).unwrap();
            assert_eq!(state.agents_used, 1);
            assert_eq!(state.agent_budget, Some(2));
        });
    }

    #[test]
    fn children_spawn_without_output_clamp() {
        run_workflow_test(async {
            use fuigo_tools::implementations::fuigo_build::task::types::{
                SubagentEvent, SubagentResult,
            };

            let dir = tempfile::tempdir().unwrap();
            let (mut manager, mut subagent_rx) = test_manager(Some(dir.path().to_path_buf()));
            let resolved = resolve_inline(
                "let meta = #{ name: \"t\", description: \"d\" };\n\
             let r = agent(\"work\");\ncomplete(r.output);"
                    .into(),
            )
            .unwrap();
            let (_run_id, _outcome_rx) = manager.launch(resolved, spec()).unwrap();
            let SubagentEvent::Spawn(req) = event_of!(manager, subagent_rx, "spawn") else {
                panic!("expected spawn");
            };
            assert_eq!(req.runtime_overrides.output_token_budget, None);
            let id = req.id.clone();
            let _ = req.result_tx.send(SubagentResult {
                success: true,
                output: std::sync::Arc::from("done"),
                subagent_id: id.clone(),
                child_session_id: id,
                output_tokens_used: 1,
                ..Default::default()
            });
        });
    }

    #[test]
    fn cancellation_uses_run_owned_cancel_event_without_parent_detach() {
        run_workflow_test(async {
            use fuigo_tools::implementations::fuigo_build::task::types::{
                SubagentCancelTarget, SubagentEvent,
            };

            let dir = tempfile::tempdir().unwrap();
            let (mut manager, mut subagent_rx, cancels) =
                test_manager_with_cancels(Some(dir.path().to_path_buf()));
            let resolved = resolve_inline(
                "let meta = #{ name: \"t\", description: \"d\" };\n\
             let r = agent(\"work\");\ncomplete(r.output);"
                    .into(),
            )
            .unwrap();
            let (run_id, outcome_rx) = manager
                .launch(
                    resolved,
                    LaunchSpec {
                        agent_budget: Some(100),
                        ..spec()
                    },
                )
                .unwrap();
            let SubagentEvent::Spawn(req) = event_of!(manager, subagent_rx, "spawn") else {
                panic!("expected spawn");
            };
            assert!(req.owner.is_workflow());
            assert!(manager.cancel(&run_id));
            settled_of!(manager, outcome_rx);
            assert!(
                req.cancel_token.is_cancelled(),
                "run cancel must cancel the child token, not silently detach the receiver"
            );
            assert!(
                cancels.lock().iter().any(|target| matches!(
                    target,
                    SubagentCancelTarget::WorkflowRunId(id) if id == &run_id
                )),
                "cancellation must emit an explicit run-owned cancel event"
            );
        });
    }

    #[test]
    fn backgrounded_stub_fails_loudly() {
        run_workflow_test(async {
            use fuigo_tools::implementations::fuigo_build::task::types::{
                SubagentEvent, SubagentResult,
            };

            let dir = tempfile::tempdir().unwrap();
            let (mut manager, mut subagent_rx) = test_manager(Some(dir.path().to_path_buf()));
            let resolved = resolve_inline(
                "let meta = #{ name: \"t\", description: \"d\" };\n\
             let r = agent(\"work\");\n\
             complete(r.output);"
                    .into(),
            )
            .unwrap();
            let (run_id, outcome_rx) = manager.launch(resolved, spec()).unwrap();

            let spawn_req = event_of!(manager, subagent_rx, "spawn event");
            let SubagentEvent::Spawn(req) = spawn_req else {
                panic!("expected spawn event");
            };
            let id = req.id.clone();
            let _ = req.result_tx.send(SubagentResult {
                backgrounded: true,
                subagent_id: id,
                ..Default::default()
            });
            let outcome = outcome_of!(manager, outcome_rx);
            match outcome {
                WorkflowOutcome::Failed { error } => {
                    assert!(
                        error.contains("auto-backgrounded"),
                        "distinct engine-bug message expected, got: {error}"
                    );
                }
                other => panic!("expected Failed, got {other:?}"),
            }
            let state = manager.tracker.lock().get(&run_id).unwrap();
            assert_eq!(
                state.status,
                crate::session::workflow::tracker::WorkflowRunStatus::Failed
            );
        });
    }

    #[test]
    fn parallel_panel_respects_concurrency_cap() {
        run_workflow_test(async {
            const CAP: usize = 2;
            const N: usize = 6;

            let dir = tempfile::tempdir().unwrap();
            let (mut manager, mut subagent_rx) = test_manager(Some(dir.path().to_path_buf()));
            manager.test_set_max_concurrent_agents(CAP);
            let (_run_id, outcome_rx) = manager
                .launch(resolve_inline(parallel_n_script(N)).unwrap(), spec())
                .unwrap();

            let mut live = Vec::new();
            for _ in 0..CAP {
                live.push(spawn_of!(manager, subagent_rx));
            }
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(150), subagent_rx.recv())
                    .await
                    .is_err(),
                "more than {CAP} children were live"
            );

            let mut completed = 0usize;
            while completed + live.len() < N {
                complete_spawn(live.remove(0));
                completed += 1;
                live.push(spawn_of!(manager, subagent_rx));
            }
            for req in live {
                complete_spawn(req);
            }

            match outcome_of!(manager, outcome_rx) {
                WorkflowOutcome::Completed { result } => assert_eq!(result, serde_json::json!(N)),
                other => panic!("expected Completed, got {other:?}"),
            }
        });
    }

    #[test]
    fn cancel_drops_queued_spawns_before_coordinator() {
        run_workflow_test(async {
            let dir = tempfile::tempdir().unwrap();
            let (mut manager, mut subagent_rx) = test_manager(Some(dir.path().to_path_buf()));
            manager.test_set_max_concurrent_agents(1);
            let (run_id, outcome_rx) = manager
                .launch(resolve_inline(parallel_n_script(4)).unwrap(), spec())
                .unwrap();

            let first = spawn_of!(manager, subagent_rx);
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(150), subagent_rx.recv())
                    .await
                    .is_err(),
                "queued agents reached the coordinator before cancel"
            );

            assert!(manager.cancel(&run_id));
            settled_of!(manager, outcome_rx);
            assert!(first.cancel_token.is_cancelled());
            assert!(subagent_rx.try_recv().is_err());
        });
    }

    /// The hang P35 documented (R012 §9b): a workflow that never reports used to park the test
    /// forever on an unbounded `outcome_rx.await`, which produces no failing set at all. The
    /// wait is now bounded and fails with a named diagnosis. Virtual time keeps this instant.
    #[tokio::test(start_paused = true)]
    async fn a_run_that_never_reports_fails_with_a_named_diagnosis_instead_of_hanging() {
        let (mut manager, _events) = test_manager(None);
        let (_done_tx, done_rx) = oneshot::channel();
        manager.test_insert_active_run("wf_wedged".into(), done_rx);
        // `_outcome_tx` stays alive and never sends: exactly a watcher that never finishes.
        let (_outcome_tx, outcome_rx) = oneshot::channel::<WorkflowOutcome>();

        let started = tokio::time::Instant::now();
        let message = {
            let manager = &manager;
            let waited = std::panic::AssertUnwindSafe(async move {
                let _ = await_outcome(manager, outcome_rx, "test-site:1").await;
            });
            let payload = futures::FutureExt::catch_unwind(waited)
                .await
                .expect_err("an unreported outcome must fail, not resolve");
            payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
                .expect("panic payload is a string")
        };

        assert_eq!(
            started.elapsed(),
            WORKFLOW_TEST_DEADLINE,
            "it must give up at the deadline, not earlier and not never"
        );
        for needle in [
            "workflow test wedged",
            "a_run_that_never_reports_fails_with_a_named_diagnosis_instead_of_hanging",
            "test-site:1",
            "the run's WorkflowOutcome",
            "active wf_wedged",
            "run_workflow",
        ] {
            assert!(
                message.contains(needle),
                "diagnosis lacks `{needle}`: {message}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_subagent_event_that_never_arrives_fails_with_a_named_diagnosis() {
        let (manager, mut events) = test_manager(None);
        let message = {
            let manager = &manager;
            let events = &mut events;
            let waited = std::panic::AssertUnwindSafe(async move {
                let _ = next_event(manager, events, "first spawn", "test-site:2").await;
            });
            let payload = futures::FutureExt::catch_unwind(waited)
                .await
                .expect_err("a missing event must fail, not resolve");
            payload
                .downcast_ref::<String>()
                .cloned()
                .expect("panic payload is a String")
        };
        assert!(message.contains("workflow test wedged"), "{message}");
        assert!(
            message.contains("the subagent event `first spawn`"),
            "{message}"
        );
    }

    /// The wedge for real, end to end. A live run that never reports (its child is never
    /// completed, so its engine thread stays parked in `run_workflow`) used to park
    /// `outcome_rx.await` forever. It must now fail, naming the run and its state, and the
    /// runtime teardown must not then hang on the engine's blocking thread.
    #[test]
    fn a_wedged_run_fails_with_its_diagnosis_and_leaves_no_hang_behind() {
        let started = std::time::Instant::now();
        let failure = std::panic::catch_unwind(|| {
            run_workflow_test(async {
                let (mut manager, mut subagent_rx) = test_manager(None);
                let script = "let meta = #{ name: \"t\", description: \"d\" };\n\
                              let r = agent(\"work\");\ncomplete(r.output);";
                let (_run_id, outcome_rx) = manager
                    .launch(resolve_inline(script.into()).unwrap(), spec())
                    .unwrap();
                // The child is dispatched and then left running: nothing will ever complete it.
                let _child = event_of!(manager, subagent_rx, "first spawn");

                DEADLINE_OVERRIDE.with(|d| d.set(Some(std::time::Duration::from_millis(400))));
                let _ = outcome_of!(manager, outcome_rx);
                unreachable!("a run with a live, never-completed child cannot report an outcome");
            });
        })
        .expect_err("a wedged run must fail the test");
        let message = failure
            .downcast_ref::<String>()
            .cloned()
            .expect("the failure is a formatted diagnosis");

        for needle in [
            "workflow test wedged",
            "a_wedged_run_fails_with_its_diagnosis_and_leaves_no_hang_behind",
            "the run's WorkflowOutcome",
            "active wf_",
            "tracker_status=active",
            "cancelled=false",
        ] {
            assert!(
                message.contains(needle),
                "diagnosis lacks `{needle}`: {message}"
            );
        }
        // Detected at the (shortened) bound and torn down within the grace period, not stalled.
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "took {:?}",
            started.elapsed()
        );
    }

    /// `run_workflow_test` exists because a dropped runtime waits for `spawn_blocking` tasks.
    /// Prove the premise and the remedy: a blocking thread nothing will ever release must not
    /// hold the test forever, and must not pass silently either.
    #[test]
    fn a_stuck_blocking_thread_fails_the_test_instead_of_hanging_its_teardown() {
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        SHUTDOWN_GRACE_OVERRIDE.with(|g| g.set(Some(std::time::Duration::from_secs(1))));
        let started = std::time::Instant::now();
        let failure = std::panic::catch_unwind(|| {
            run_workflow_test(async move {
                let (running_tx, running_rx) = oneshot::channel();
                let _stuck = tokio::task::spawn_blocking(move || {
                    let _ = running_tx.send(());
                    // Blocks until `release_tx` is dropped by the test thread, after teardown.
                    let _ = release_rx.recv();
                });
                running_rx.await.unwrap();
            });
        })
        .expect_err("a blocking thread that outlives teardown must fail the test");
        let elapsed = started.elapsed();
        SHUTDOWN_GRACE_OVERRIDE.with(|g| g.set(None));

        let message = failure
            .downcast_ref::<String>()
            .cloned()
            .expect("the failure is a formatted diagnosis");
        assert!(
            message.contains("1 blocking thread(s) were still running"),
            "{message}"
        );
        assert!(message.contains("release_agent_calls"), "{message}");
        assert!(
            elapsed >= std::time::Duration::from_secs(1),
            "gave up early: {elapsed:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(30),
            "teardown was not bounded: {elapsed:?}"
        );
        drop(release_tx);
    }

    // P38-F: a pause or stop that lands while a host request is stranded by the host's teardown (P38).
    // The engine runs for real against the P38 stranding host (see `fuigo-workflow`'s engine tests),
    // the stop goes through the real `pause()` / `cancel()`, and the finished run settles through the
    // watcher's own `settle_finished_run`.

    #[derive(Clone, Copy, Debug)]
    enum Stranded {
        Reservation,
        AgentHostCall,
    }

    #[derive(Clone, Copy, Debug)]
    enum UserStop {
        Pause,
        Stop,
    }

    async fn user_stop_during_stranded_request(
        stop: UserStop,
        stranded: Stranded,
    ) -> (WorkflowOutcome, WorkflowRunStatus) {
        use fuigo_workflow::WorkflowHostRequest as R;

        let (mut manager, _events) = test_manager(None);
        let run_id = format!("wf_p38f_{stop:?}_{stranded:?}").to_lowercase();
        manager.tracker.lock().start_run(
            run_id.clone(),
            run_id.clone(),
            "obj".into(),
            vec![],
            Some(10),
            None,
        );
        let cancel = CancellationToken::new();
        let pause_intent = Arc::new(AtomicBool::new(false));
        let (_done_tx, done_rx) = oneshot::channel();
        manager.active.insert(
            run_id.clone(),
            ActiveRun {
                cancel: cancel.clone(),
                pause_intent: pause_intent.clone(),
                done: done_rx,
            },
        );

        // The P38 stranding host: serve until the selected request arrives, report it held, wait for the
        // user's stop, then stop serving and keep the request (and its reply sender) until the channel's
        // last sender is gone, the lifetime tokio gives a request stranded by a send racing `Rx::drop`.
        let (host_tx, mut host_rx) = mpsc::unbounded_channel::<R>();
        let senders = host_tx.downgrade();
        let (held_tx, held_rx) = oneshot::channel::<()>();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let host = std::thread::spawn(move || {
            let request = loop {
                let Some(request) = host_rx.blocking_recv() else {
                    return;
                };
                match (stranded, request) {
                    (Stranded::Reservation, request @ R::ReserveAgentCalls { .. })
                    | (Stranded::AgentHostCall, request @ R::SpawnAgent { .. }) => break request,
                    (
                        _,
                        R::ReserveAgentCalls { reply, .. } | R::ReleaseAgentCalls { reply, .. },
                    ) => {
                        let _ = reply.send(Ok(()));
                    }
                    _ => {}
                }
            };
            let _ = held_tx.send(());
            let _ = go_rx.recv();
            drop(host_rx);
            while senders.upgrade().is_some() {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            drop(request);
        });

        // A plain thread, not `spawn_blocking`: a wedged engine must fail this test by name, not hold the
        // runtime's shutdown.
        let (outcome_tx, outcome_rx) = oneshot::channel();
        std::thread::spawn(move || {
            let _ = outcome_tx.send(fuigo_workflow::run_workflow(WorkflowRunParams {
                script: "let meta = #{ name: \"t\", description: \"d\" };\n\
                         let r = agent(\"work\");\ncomplete(r.output);"
                    .into(),
                args: serde_json::json!({}),
                journal: Journal::new(None),
                host_tx,
                cancel,
                max_ops: WorkflowRunParams::DEFAULT_MAX_OPS,
            }));
        });

        tokio::time::timeout(std::time::Duration::from_secs(20), held_rx)
            .await
            .expect("the engine never sent the request to strand")
            .expect("stranding host ended early");
        match stop {
            UserStop::Pause => assert!(manager.pause(&run_id)),
            UserStop::Stop => assert!(manager.cancel(&run_id)),
        }
        go_tx.send(()).expect("stranding host gone");
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(20), outcome_rx)
            .await
            .unwrap_or_else(|_| {
                panic!("{stop:?} during a stranded {stranded:?}: the engine wedged (P38)")
            })
            .expect("engine thread panicked");
        host.join().expect("stranding host panicked");
        let status = settle_finished_run(
            &mut manager.tracker.lock(),
            &run_id,
            false,
            pause_intent.load(Ordering::Relaxed),
            &outcome,
        )
        .expect("run is tracked")
        .status;
        (outcome, status)
    }

    #[tokio::test]
    async fn pause_during_a_stranded_reservation_leaves_the_run_user_paused() {
        let (outcome, status) =
            user_stop_during_stranded_request(UserStop::Pause, Stranded::Reservation).await;
        assert!(matches!(outcome, WorkflowOutcome::Cancelled), "{outcome:?}");
        assert_eq!(
            status,
            WorkflowRunStatus::UserPaused,
            "engine outcome {outcome:?}"
        );
    }

    #[tokio::test]
    async fn pause_during_a_stranded_agent_host_call_leaves_the_run_user_paused() {
        let (outcome, status) =
            user_stop_during_stranded_request(UserStop::Pause, Stranded::AgentHostCall).await;
        assert!(matches!(outcome, WorkflowOutcome::Cancelled), "{outcome:?}");
        assert_eq!(
            status,
            WorkflowRunStatus::UserPaused,
            "engine outcome {outcome:?}"
        );
    }

    #[tokio::test]
    async fn stop_during_a_stranded_reservation_leaves_the_run_cancelled() {
        let (outcome, status) =
            user_stop_during_stranded_request(UserStop::Stop, Stranded::Reservation).await;
        // The tracker ignores outcomes once `cancel()` marked it `Cancelled`, so the status alone would
        // not show a `Failed`; the outcome the watcher reports and logs must be `Cancelled` too.
        assert!(matches!(outcome, WorkflowOutcome::Cancelled), "{outcome:?}");
        assert_eq!(
            status,
            WorkflowRunStatus::Cancelled,
            "engine outcome {outcome:?}"
        );
    }

    #[tokio::test]
    async fn stop_during_a_stranded_agent_host_call_leaves_the_run_cancelled() {
        let (outcome, status) =
            user_stop_during_stranded_request(UserStop::Stop, Stranded::AgentHostCall).await;
        assert!(matches!(outcome, WorkflowOutcome::Cancelled), "{outcome:?}");
        assert_eq!(
            status,
            WorkflowRunStatus::Cancelled,
            "engine outcome {outcome:?}"
        );
    }
}
