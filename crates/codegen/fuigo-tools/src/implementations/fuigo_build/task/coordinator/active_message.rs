//! Active-child message admission and finalization linearization.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::sync::{OwnedSemaphorePermit, oneshot};
use tokio_util::sync::WaitForCancellationFutureOwned;

use super::super::admission::{AdmissionDecision, AdmissionError};
use super::queue::{QueuedCaller, QueuedSpawn, StartOrigin};
use super::{SubagentCoordinator, SubagentLimitDecision};
use crate::implementations::fuigo_build::task::active_message::{
    ActiveMessageAdmissionLease, ActiveMessageIngress,
};
use crate::implementations::fuigo_build::task::coordinator_state::{
    ACTIVE_MESSAGE_ADMISSION_TIMEOUT, ACTIVE_MESSAGE_SPAWN_READY_TIMEOUT, ActiveMessageAdmission,
    ChildControl, ChildRunner, MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_CHILD,
};
use crate::implementations::fuigo_build::task::types::{
    ActiveAgentMessage, ActiveAgentMessageDelivery, ActiveAgentMessageOutcome,
    ActiveAgentMessageRequest,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActiveChildGeneration(uuid::Uuid);

impl ActiveChildGeneration {
    pub(super) fn new() -> Self {
        Self(uuid::Uuid::now_v7())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BeginAdmission {
    Started,
    Finalizing,
    Saturated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::implementations::fuigo_build::task) enum TerminalDrainDisposition {
    Clean,
    Uncertain,
}

impl TerminalDrainDisposition {
    fn record(&mut self, is_settled: bool) {
        if !is_settled {
            *self = Self::Uncertain;
        }
    }

    fn is_clean(self) -> bool {
        self == Self::Clean
    }
}

pub(in crate::implementations::fuigo_build::task) enum ActiveMessageLifecycle {
    Open {
        in_flight: usize,
        disposition: TerminalDrainDisposition,
    },
    Finalizing {
        in_flight: usize,
        disposition: TerminalDrainDisposition,
        waiters: Vec<oneshot::Sender<bool>>,
    },
}

impl Default for ActiveMessageLifecycle {
    fn default() -> Self {
        Self::Open {
            in_flight: 0,
            disposition: TerminalDrainDisposition::Clean,
        }
    }
}

impl ActiveMessageLifecycle {
    fn begin_admission(&mut self) -> BeginAdmission {
        let Self::Open { in_flight, .. } = self else {
            return BeginAdmission::Finalizing;
        };
        if *in_flight >= MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_CHILD {
            return BeginAdmission::Saturated;
        }
        *in_flight += 1;
        BeginAdmission::Started
    }

    pub(super) fn begin_finalizing(&mut self, respond_to: oneshot::Sender<bool>) {
        if let Some(is_clean) = self.start_terminalizing() {
            let _ = respond_to.send(is_clean);
        } else if let Self::Finalizing { waiters, .. } = self {
            waiters.push(respond_to);
        }
    }

    pub(super) fn start_terminalizing(&mut self) -> Option<bool> {
        match self {
            Self::Open {
                in_flight,
                disposition,
            } => {
                let in_flight = *in_flight;
                let disposition = *disposition;
                *self = Self::Finalizing {
                    in_flight,
                    disposition,
                    waiters: Vec::new(),
                };
                (in_flight == 0).then(|| disposition.is_clean())
            }
            Self::Finalizing {
                in_flight,
                disposition,
                ..
            } if *in_flight == 0 => Some(disposition.is_clean()),
            Self::Finalizing { .. } => None,
        }
    }

    fn finish_admission(&mut self, is_settled: bool) -> Option<bool> {
        let (in_flight, disposition, waiters) = match self {
            Self::Open {
                in_flight,
                disposition,
            } => (in_flight, disposition, None),
            Self::Finalizing {
                in_flight,
                disposition,
                waiters,
            } => (in_flight, disposition, Some(waiters)),
        };
        disposition.record(is_settled);
        *in_flight = in_flight
            .checked_sub(1)
            .unwrap_or_else(|| unreachable!("active-message completion without admission"));
        if *in_flight == 0
            && let Some(waiters) = waiters
        {
            let is_clean = disposition.is_clean();
            resolve_waiters(waiters, is_clean);
            return Some(is_clean);
        }
        None
    }
}

impl Drop for ActiveMessageLifecycle {
    fn drop(&mut self) {
        if let Self::Finalizing { waiters, .. } = self {
            resolve_waiters(waiters, false);
        }
    }
}
fn resolve_waiters(waiters: &mut Vec<oneshot::Sender<bool>>, outcome: bool) {
    waiters.drain(..).for_each(|waiter| {
        let _ = waiter.send(outcome);
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveMessageCompletionOutcome {
    Admission(ActiveMessageAdmission),
    Cancelled,
    DeadlineElapsed,
}

pub(super) struct ActiveMessageCompletion {
    subagent_id: String,
    generation: ActiveChildGeneration,
    parent_session_id: String,
    message_id: String,
    respond_to: Option<oneshot::Sender<ActiveAgentMessageOutcome>>,
    outcome: ActiveMessageCompletionOutcome,
    is_settled: bool,
    _ingress_permit: OwnedSemaphorePermit,
}

fn protocol_outcome_from_completion(
    outcome: ActiveMessageCompletionOutcome,
    is_settled: bool,
    message_id: &str,
) -> ActiveAgentMessageOutcome {
    if !is_settled {
        return ActiveAgentMessageOutcome::AdmissionUncertain;
    }
    match outcome {
        ActiveMessageCompletionOutcome::Admission(ActiveMessageAdmission::Admitted) => {
            ActiveAgentMessageOutcome::Accepted {
                message_id: message_id.to_owned(),
            }
        }
        ActiveMessageCompletionOutcome::Admission(ActiveMessageAdmission::Unsupported) => {
            ActiveAgentMessageOutcome::Unsupported
        }
        ActiveMessageCompletionOutcome::Admission(ActiveMessageAdmission::ChannelClosed) => {
            ActiveAgentMessageOutcome::ChannelClosed
        }
        ActiveMessageCompletionOutcome::Admission(ActiveMessageAdmission::Rejected) => {
            ActiveAgentMessageOutcome::NotActiveOrFinalizing
        }
        ActiveMessageCompletionOutcome::Cancelled
        | ActiveMessageCompletionOutcome::DeadlineElapsed => {
            ActiveAgentMessageOutcome::NotAcceptedBeforeDeadline
        }
    }
}

/// Reply when the completion is dropped after poll: a committed/claimed
/// admission cannot become a definite rejection.
fn lost_completion_outcome(
    outcome: ActiveMessageCompletionOutcome,
    is_settled: bool,
) -> ActiveAgentMessageOutcome {
    match (outcome, is_settled) {
        (ActiveMessageCompletionOutcome::Admission(ActiveMessageAdmission::Admitted), _)
        | (_, false) => ActiveAgentMessageOutcome::AdmissionUncertain,
        // Admitted is classified above; the dummy id is never used for Accepted.
        (outcome, true) => protocol_outcome_from_completion(outcome, true, ""),
    }
}

impl Drop for ActiveMessageCompletion {
    fn drop(&mut self) {
        if let Some(respond_to) = self.respond_to.take() {
            let _ = respond_to.send(lost_completion_outcome(self.outcome, self.is_settled));
        }
    }
}

pub(super) struct ActiveMessageFuture {
    subagent_id: String,
    generation: ActiveChildGeneration,
    parent_session_id: String,
    message_id: String,
    future: Pin<Box<dyn Future<Output = ActiveMessageAdmission> + Send + 'static>>,
    cancellation: Pin<Box<WaitForCancellationFutureOwned>>,
    deadline: Pin<Box<tokio::time::Sleep>>,
    lease: Arc<ActiveMessageAdmissionLease>,
    ingress_permit: Option<OwnedSemaphorePermit>,
    respond_to: Option<oneshot::Sender<ActiveAgentMessageOutcome>>,
}

impl Future for ActiveMessageFuture {
    type Output = ActiveMessageCompletion;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let outcome = match this.future.as_mut().poll(cx) {
            Poll::Ready(admission) => ActiveMessageCompletionOutcome::Admission(admission),
            Poll::Pending if this.cancellation.as_mut().poll(cx).is_ready() => {
                ActiveMessageCompletionOutcome::Cancelled
            }
            Poll::Pending if this.deadline.as_mut().poll(cx).is_ready() => {
                ActiveMessageCompletionOutcome::DeadlineElapsed
            }
            Poll::Pending => return Poll::Pending,
        };
        let is_settled = match outcome {
            ActiveMessageCompletionOutcome::Admission(admission) => this.lease.settle(admission),
            ActiveMessageCompletionOutcome::Cancelled
            | ActiveMessageCompletionOutcome::DeadlineElapsed => this.lease.revoke(),
        };
        Poll::Ready(ActiveMessageCompletion {
            subagent_id: this.subagent_id.clone(),
            generation: this.generation,
            parent_session_id: this.parent_session_id.clone(),
            message_id: this.message_id.clone(),
            respond_to: Some(
                this.respond_to
                    .take()
                    .unwrap_or_else(|| unreachable!("active-message future polled twice")),
            ),
            outcome,
            is_settled,
            _ingress_permit: this
                .ingress_permit
                .take()
                .unwrap_or_else(|| unreachable!("active-message ingress permit taken twice")),
        })
    }
}

impl Drop for ActiveMessageFuture {
    fn drop(&mut self) {
        let outcome = if self.lease.revoke() {
            ActiveAgentMessageOutcome::ChannelClosed
        } else {
            ActiveAgentMessageOutcome::AdmissionUncertain
        };
        if let Some(respond_to) = self.respond_to.take() {
            let _ = respond_to.send(outcome);
        }
    }
}

struct SpawningChild {
    workflow: bool,
    cancelled: bool,
}

pub(super) struct ParkedSpawnReadyMessage {
    pub(super) subagent_id: String,
    pub(super) parent_session_id: String,
    pub(super) request: ActiveAgentMessageRequest,
    pub(super) respond_to: Option<oneshot::Sender<ActiveAgentMessageOutcome>>,
    /// `None` for a wake: its text is the spawn's own prompt and the reply
    /// waits for the child to start, however long the resume takes.
    pub(super) deadline: Option<tokio::time::Instant>,
    /// Set when the text already went out as the woken child's prompt: on
    /// start the sender is told `Accepted` with this id instead of the text
    /// being delivered a second time.
    pub(super) initial_message_id: Option<String>,
}

impl Drop for ParkedSpawnReadyMessage {
    fn drop(&mut self) {
        if let Some(respond_to) = self.respond_to.take() {
            let _ = respond_to.send(ActiveAgentMessageOutcome::ChannelClosed);
        }
    }
}

/// Parked sends plus the admission semaphore they re-acquire on start.
pub(super) struct SpawnReadyMessages {
    parked: Vec<ParkedSpawnReadyMessage>,
    permits: Option<Arc<tokio::sync::Semaphore>>,
    capacity: usize,
}

impl SpawnReadyMessages {
    pub(super) fn new(permits: Option<Arc<tokio::sync::Semaphore>>, capacity: usize) -> Self {
        Self {
            parked: Vec::new(),
            permits,
            capacity,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.parked.is_empty()
    }

    pub(super) fn clear(&mut self) {
        self.parked.clear();
    }

    pub(super) fn deadlines(&self) -> impl Iterator<Item = tokio::time::Instant> + '_ {
        self.parked.iter().filter_map(|parked| parked.deadline)
    }

    pub(super) fn push(&mut self, parked: ParkedSpawnReadyMessage) {
        self.parked.push(parked);
    }

    pub(super) fn take(&mut self, subagent_id: &str) -> Vec<ParkedSpawnReadyMessage> {
        let (matched, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.parked)
            .into_iter()
            .partition(|parked| parked.subagent_id == subagent_id);
        self.parked = rest;
        matched
    }

    /// Re-acquire ingress permits for parked sends and return those that fit.
    /// Saturated leftovers are replied here so capacity lives in one place.
    pub(super) fn admit(&mut self, subagent_id: &str) -> Vec<ActiveMessageIngress> {
        let mut admitted = Vec::new();
        for mut parked in self.take(subagent_id) {
            if let Some(message_id) = parked.initial_message_id.take() {
                parked.reply(ActiveAgentMessageOutcome::Accepted { message_id });
                continue;
            }
            let Some((request, parent_session_id, respond_to)) = parked.into_request() else {
                continue;
            };
            match self.try_acquire() {
                Ok(permit) => {
                    admitted.push(ActiveMessageIngress {
                        request: crate::implementations::fuigo_build::task::types::SubagentActiveMessageRequest {
                            request,
                            parent_session_id,
                            respond_to,
                        },
                        permit,
                    });
                }
                Err(capacity) => {
                    let _ = respond_to.send(ActiveAgentMessageOutcome::Saturated {
                        max_in_flight: capacity,
                    });
                }
            }
        }
        admitted
    }

    pub(super) fn reject(&mut self, subagent_id: &str, outcome: ActiveAgentMessageOutcome) {
        for parked in self.take(subagent_id) {
            parked.reply(outcome.clone());
        }
    }

    pub(super) fn expire(&mut self, now: tokio::time::Instant) {
        let (due, live): (Vec<_>, Vec<_>) = std::mem::take(&mut self.parked)
            .into_iter()
            .partition(|parked| parked.deadline.is_some_and(|deadline| deadline <= now));
        self.parked = live;
        for parked in due {
            parked.reply(ActiveAgentMessageOutcome::NotAcceptedBeforeDeadline);
        }
    }

    fn try_acquire(&self) -> Result<OwnedSemaphorePermit, usize> {
        let Some(permits) = &self.permits else {
            return Err(self.capacity);
        };
        Arc::clone(permits)
            .try_acquire_owned()
            .map_err(|_| self.capacity)
    }
}

impl ParkedSpawnReadyMessage {
    fn into_request(
        mut self,
    ) -> Option<(
        ActiveAgentMessageRequest,
        String,
        oneshot::Sender<ActiveAgentMessageOutcome>,
    )> {
        let respond_to = self.respond_to.take()?;
        Some((
            self.request.take(),
            std::mem::take(&mut self.parent_session_id),
            respond_to,
        ))
    }

    fn reply(mut self, outcome: ActiveAgentMessageOutcome) {
        if let Some(respond_to) = self.respond_to.take() {
            let _ = respond_to.send(outcome);
        }
    }
}

impl<R: ChildRunner> SubagentCoordinator<R> {
    pub(super) fn handle_send_active_message(&mut self, ingress: ActiveMessageIngress) {
        let ActiveMessageIngress { request, permit } = ingress;
        let crate::implementations::fuigo_build::task::types::SubagentActiveMessageRequest {
            request,
            parent_session_id,
            respond_to,
        } = request;
        if self.active.contains_key(request.subagent_id()) {
            self.admit_active_message(ActiveMessageIngress {
                request:
                    crate::implementations::fuigo_build::task::types::SubagentActiveMessageRequest {
                        request,
                        parent_session_id,
                        respond_to,
                    },
                permit,
            });
            return;
        }

        let subagent_id = request.subagent_id().to_owned();
        let spawning = self.owned_spawning_child(&subagent_id, &parent_session_id);
        if let Some(spawning) = spawning {
            // Cancel and workflow stay fail-fast, matching the active path.
            if spawning.workflow || spawning.cancelled {
                let _ = respond_to.send(ActiveAgentMessageOutcome::NotActiveOrFinalizing);
                return;
            }
            // Release the ingress permit while waiting on spawn so a stuck
            // child cannot pin the global admission budget.
            drop(permit);
            self.spawn_ready.push(ParkedSpawnReadyMessage {
                subagent_id,
                parent_session_id,
                request,
                respond_to: Some(respond_to),
                deadline: Some(tokio::time::Instant::now() + ACTIVE_MESSAGE_SPAWN_READY_TIMEOUT),
                initial_message_id: None,
            });
            return;
        }

        let Some(completed) = self
            .completed
            .get(&subagent_id)
            .filter(|child| child.request.parent_session_id == parent_session_id)
        else {
            let _ = respond_to.send(ActiveAgentMessageOutcome::NotFoundOrNotOwned);
            return;
        };
        // A workflow child belongs to its run; a cancelled or killed child
        // stays down ("do not restart it").
        if completed.request.owner.is_workflow()
            || completed.result.cancelled
            || !self.runner.supports_wake()
            || self
                .spawn_blocked_sessions
                .contains(&completed.request.parent_session_id)
        {
            let _ = respond_to.send(ActiveAgentMessageOutcome::NotActiveOrFinalizing);
            return;
        }
        drop(permit);
        self.wake_completed_child(subagent_id, parent_session_id, request, respond_to);
    }

    /// Continue a completed child as a new incarnation with the same id:
    /// `resume_from` is its own id and the message text is its next prompt.
    /// The sender hears `Accepted` once the child starts, or
    /// `NotActiveOrFinalizing` if the incarnation ends before that.
    fn wake_completed_child(
        &mut self,
        subagent_id: String,
        parent_session_id: String,
        request: ActiveAgentMessageRequest,
        respond_to: oneshot::Sender<ActiveAgentMessageOutcome>,
    ) {
        let Some(completed) = self.completed.remove(&subagent_id) else {
            let _ = respond_to.send(ActiveAgentMessageOutcome::NotFoundOrNotOwned);
            return;
        };
        self.completed_order.retain(|id| id != &subagent_id);
        let mut wake_request = completed.request.clone();
        wake_request.prompt = request.text().to_string();
        wake_request.resume_from = Some(subagent_id.clone());
        wake_request.fork_context = false;
        wake_request.parent_prompt_id = None;
        // No caller awaits a wake: it is background work whose completion
        // reports through the usual background-completion notice.
        wake_request.run_in_background = true;
        // DEVIATION from upstream (`coordinator/wake.rs`), deliberate: upstream
        // clears `surface_completion` here because its `WakeOrigin` gives the
        // wake another way to surface its result. Fuigo has no such path, so
        // the inherited flag is the ONLY thing that lets the parent see the
        // woken child's answer (`coordinator.rs` gates both the buffered
        // completion and `should_surface` on it). Clearing it here would leave
        // the sender with `Accepted` and then silence.
        wake_request.await_to_completion = false;
        wake_request.cancel_token = tokio_util::sync::CancellationToken::new();
        self.woken.insert(subagent_id.clone(), completed);
        let message_id = uuid::Uuid::now_v7().to_string();
        self.spawn_ready.push(ParkedSpawnReadyMessage {
            subagent_id: subagent_id.clone(),
            parent_session_id,
            request,
            respond_to: Some(respond_to),
            // No deadline, matching upstream `wake.rs`. The text is already
            // committed as this incarnation's own prompt, so expiring the park
            // would answer `NotAcceptedBeforeDeadline` to a sender whose
            // message the child is still going to run. On the `Enqueue` branch
            // below the reply therefore stays outstanding until a spawn slot
            // frees (or the coordinator drops the park, which answers
            // `ChannelClosed`); pinned by
            // `wake_queued_at_the_spawn_limit_holds_the_record_and_never_expires`.
            deadline: None,
            initial_message_id: Some(message_id),
        });
        let running = self.session_running_count(&wake_request.parent_session_id);
        match self.admission.admit(&wake_request, running) {
            AdmissionDecision::Start => {
                self.start_child(wake_request, None, None, StartOrigin::Direct);
            }
            AdmissionDecision::Enqueue => {
                self.notify_limit(
                    &wake_request,
                    SubagentLimitDecision::QueuedAtConcurrentLimit {
                        limit: self.admission.max_concurrent(),
                    },
                );
                self.queued.push_back(QueuedSpawn {
                    request: Box::new(wake_request),
                    queued_at: tokio::time::Instant::now(),
                    caller: QueuedCaller::Backgrounded,
                });
            }
            AdmissionDecision::Reject(error) => {
                self.notify_limit(
                    &wake_request,
                    match &error {
                        AdmissionError::ConcurrentLimitReached { limit } => {
                            SubagentLimitDecision::RejectedAtConcurrentLimit { limit: *limit }
                        }
                    },
                );
                // Nothing started: the terminal record goes back where it was.
                if let Some(completed) = self.woken.remove(&subagent_id) {
                    self.completed.insert(subagent_id.clone(), completed);
                    self.completed_order.push_back(subagent_id.clone());
                }
                self.spawn_ready
                    .reject(&subagent_id, ActiveAgentMessageOutcome::NotActiveOrFinalizing);
            }
        }
    }

    fn owned_spawning_child(&self, id: &str, parent_session_id: &str) -> Option<SpawningChild> {
        if let Some(child) = self.pending.get(id)
            && child.request.parent_session_id == parent_session_id
        {
            return Some(SpawningChild {
                workflow: child.request.owner.is_workflow(),
                cancelled: child.cancellation.is_cancelled(),
            });
        }
        self.queued.iter().find_map(|queued| {
            (queued.request.id == id && queued.request.parent_session_id == parent_session_id)
                .then_some(SpawningChild {
                    workflow: queued.request.owner.is_workflow(),
                    cancelled: queued.request.cancel_token.is_cancelled(),
                })
        })
    }

    pub(super) fn admit_spawn_ready_messages(&mut self, subagent_id: &str) {
        for ingress in self.spawn_ready.admit(subagent_id) {
            self.admit_active_message(ingress);
        }
    }

    pub(super) fn reject_spawn_ready_ids(&mut self, ids: &[String]) {
        for id in ids {
            self.spawn_ready
                .reject(id, ActiveAgentMessageOutcome::NotActiveOrFinalizing);
        }
    }

    pub(super) fn reject_spawn_ready_messages(
        &mut self,
        subagent_id: &str,
        outcome: ActiveAgentMessageOutcome,
    ) {
        self.spawn_ready.reject(subagent_id, outcome);
    }

    pub(super) fn expire_spawn_ready_messages(&mut self, now: tokio::time::Instant) {
        self.spawn_ready.expire(now);
    }

    fn admit_active_message(&mut self, ingress: ActiveMessageIngress) {
        let ActiveMessageIngress { request, permit } = ingress;
        let crate::implementations::fuigo_build::task::types::SubagentActiveMessageRequest {
            request,
            parent_session_id,
            respond_to,
        } = request;
        let Some(child) = self.active.get_mut(request.subagent_id()) else {
            let _ = respond_to.send(ActiveAgentMessageOutcome::NotActiveOrFinalizing);
            return;
        };
        if child.request.parent_session_id != parent_session_id {
            let _ = respond_to.send(ActiveAgentMessageOutcome::NotFoundOrNotOwned);
            return;
        }
        if child.request.owner.is_workflow() || child.cancellation.is_cancelled() {
            let _ = respond_to.send(ActiveAgentMessageOutcome::NotActiveOrFinalizing);
            return;
        }
        match child.active_messages.begin_admission() {
            BeginAdmission::Started => {}
            BeginAdmission::Finalizing => {
                let _ = respond_to.send(ActiveAgentMessageOutcome::NotActiveOrFinalizing);
                return;
            }
            BeginAdmission::Saturated => {
                let _ = respond_to.send(ActiveAgentMessageOutcome::Saturated {
                    max_in_flight: MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_CHILD,
                });
                return;
            }
        }

        let message_id = uuid::Uuid::now_v7().to_string();
        let lease = ActiveMessageAdmissionLease::new();
        let admission = child
            .control
            .send_active_message(ActiveAgentMessageDelivery::new(
                ActiveAgentMessage {
                    message_id: message_id.clone(),
                    sender_session_id: parent_session_id.clone(),
                    text: request.text().clone(),
                },
                request.operation(),
                Arc::clone(&lease),
            ));
        self.active_messages.push(ActiveMessageFuture {
            subagent_id: request.subagent_id().to_owned(),
            generation: child.generation,
            parent_session_id,
            message_id,
            future: admission,
            cancellation: Box::pin(child.cancellation.clone().cancelled_owned()),
            deadline: Box::pin(tokio::time::sleep(ACTIVE_MESSAGE_ADMISSION_TIMEOUT)),
            lease,
            ingress_permit: Some(permit),
            respond_to: Some(respond_to),
        });
    }

    pub(super) fn finish_active_message(&mut self, mut completion: ActiveMessageCompletion) {
        let Some(respond_to) = completion.respond_to.take() else {
            return;
        };
        let Some(child) = self
            .active
            .get_mut(&completion.subagent_id)
            .filter(|child| {
                child.generation == completion.generation
                    && child.request.parent_session_id == completion.parent_session_id
            })
        else {
            let _ = respond_to.send(lost_completion_outcome(
                completion.outcome,
                completion.is_settled,
            ));
            return;
        };
        let protocol_outcome = protocol_outcome_from_completion(
            completion.outcome,
            completion.is_settled,
            &completion.message_id,
        );
        let _ = respond_to.send(protocol_outcome);
        let terminal_disposition = child
            .active_messages
            .finish_admission(completion.is_settled);
        if let Some(is_clean) = terminal_disposition
            && let Some(output) = self.terminal_outputs.remove(&completion.subagent_id)
        {
            self.finish_terminalized_child(&completion.subagent_id, output, is_clean);
        }
    }

    pub(super) fn handle_active_message_finalizing(
        &mut self,
        subagent_id: String,
        respond_to: oneshot::Sender<bool>,
    ) {
        let Some(child) = self.active.get_mut(&subagent_id) else {
            let _ = respond_to.send(false);
            return;
        };
        child.active_messages.begin_finalizing(respond_to);
    }
}

#[cfg(test)]
#[path = "active_message_tests.rs"]
mod tests;
