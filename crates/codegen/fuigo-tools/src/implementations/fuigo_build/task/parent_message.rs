//! Wake-up signal for messages sent by an owning parent agent.
//!
//! A subagent that is blocked in a tool wait (`get_task_output`,
//! `wait_tasks`) has no way to notice that its parent just sent it a
//! correction: the message is committed to this session's prompt queue as a
//! protected row and only reaches the model at the next safe point. Without a
//! wake-up, the safe point is the end of the wait — up to the wait ceiling
//! (`FUIGO_MAX_WAIT_BLOCK_MS`, 10 min) — so the child keeps executing a
//! superseded instruction and the correction lands far too late.
//!
//! [`ParentMessageSignal`] is the session-scoped rendezvous between the shell
//! (which commits the queue row) and the tool waits (which race against it).
//! It is injected into the session's `Resources`; sessions without a parent
//! (or hosts that do not admit active-agent messages) simply never signal it,
//! and every wait then behaves exactly as it did before.
//!
//! Waits subscribe with [`ParentMessageSignal::subscribe`] BEFORE they start
//! waiting. A subscription is edge-triggered from the sequence number it
//! captured, so only a message committed after the wait began interrupts it.
//! That is deliberate: a level-triggered signal would make every subsequent
//! wait return instantly until the row drained, turning one interrupt into a
//! tool-call loop.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::register_resource;

#[derive(Default)]
struct ParentMessageState {
    notify: tokio::sync::Notify,
    /// Bumped once per committed message; subscriptions compare against it.
    seq: AtomicU64,
    /// Identifiers of messages committed but not yet handed to the model.
    pending: std::sync::Mutex<Vec<String>>,
}

impl ParentMessageState {
    fn pending_ids(&self) -> Vec<String> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Session-scoped signal raised when the owning parent agent's message is
/// committed to this session's prompt queue.
#[derive(Clone, Default)]
pub struct ParentMessageSignal(Arc<ParentMessageState>);

impl ParentMessageSignal {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one committed parent message and wake every subscription taken
    /// before it arrived.
    pub fn message_committed(&self, message_id: impl Into<String>) {
        self.0
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(message_id.into());
        // Release-store the sequence before waking so a woken subscription
        // observes both the new sequence and the pushed identifier.
        self.0.seq.fetch_add(1, Ordering::Release);
        self.0.notify.notify_waiters();
    }

    /// Identifiers of parent messages committed but not yet delivered.
    pub fn pending_message_ids(&self) -> Vec<String> {
        self.0.pending_ids()
    }

    /// Clear the pending list once the messages have reached the model.
    /// Returns what was cleared.
    pub fn take_pending(&self) -> Vec<String> {
        std::mem::take(
            &mut *self
                .0
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Subscribe from the current sequence. Only messages committed after this
    /// call resolve [`ParentMessageWatch::arrived`].
    pub fn subscribe(&self) -> ParentMessageWatch {
        ParentMessageWatch {
            state: Arc::clone(&self.0),
            baseline: self.0.seq.load(Ordering::Acquire),
        }
    }
}

impl std::fmt::Debug for ParentMessageSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParentMessageSignal")
            .field("seq", &self.0.seq.load(Ordering::Acquire))
            .finish()
    }
}

register_resource!("fuigo_build", "ParentMessageSignal", ParentMessageSignal);

/// One wait's edge-triggered view of [`ParentMessageSignal`].
pub struct ParentMessageWatch {
    state: Arc<ParentMessageState>,
    baseline: u64,
}

impl ParentMessageWatch {
    /// Resolves with every currently pending message identifier as soon as a
    /// message is committed after this watch was taken. Never resolves while
    /// no new message arrives, so it is safe as a `select!` arm.
    pub async fn arrived(&self) -> Arc<[String]> {
        loop {
            // Register before the load: a commit racing the check still wakes us.
            let notified = self.state.notify.notified();
            if self.state.seq.load(Ordering::Acquire) > self.baseline {
                return Arc::from(self.state.pending_ids());
            }
            notified.await;
        }
    }
}

#[cfg(test)]
#[path = "parent_message_tests.rs"]
mod tests;
