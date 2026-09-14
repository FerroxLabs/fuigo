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
//! The signal is LEVEL-triggered: a watch resolves as soon as the pending list
//! is non-empty, whether the message landed during the wait or just before it.
//! Edge-triggering from the wait's own start would miss the common case — the
//! parent's message is usually committed while the model is sampling, i.e.
//! after the turn loop's drain point and before the next tool wait begins — and
//! the child would wait out the whole `timeout_ms` anyway.
//!
//! It does not loop, because [`ParentMessageSignal::message_delivered`] drops
//! the identifier the moment the message reaches the model — at the promoting
//! drain, or, when the session was idle and the row ran as its own turn, as it
//! is promoted to the running turn. Every tool batch is followed by a drain, so
//! at most one wait per batch sees a given message.

use std::sync::Arc;

use crate::register_resource;

#[derive(Default)]
struct ParentMessageState {
    notify: tokio::sync::Notify,
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
        // Push under the lock and release it before waking, so a woken watch
        // reads a list that already contains the identifier.
        self.0
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(message_id.into());
        self.0.notify.notify_waiters();
    }

    /// Identifiers of parent messages committed but not yet delivered.
    pub fn pending_message_ids(&self) -> Vec<String> {
        self.0.pending_ids()
    }

    /// Drop one message from the pending list once it has reached the model.
    ///
    /// Per identifier, never "clear everything": a message committed while the
    /// promoting drain is running belongs to a row that drain did not take, and
    /// must stay pending. Both delivery routes call this — the promoting drain,
    /// and the idle path where the row runs as its own turn and no drain ever
    /// sees it. Left pending, an identifier leaks for the life of the session,
    /// keeps every later wait interruptible, and is named in interrupt hints as
    /// still outstanding.
    pub fn message_delivered(&self, message_id: &str) {
        self.0
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|id| id != message_id);
    }

    /// Take a watch over this signal. Level-triggered: a message already
    /// pending when the wait begins interrupts it just as one that arrives
    /// during it does.
    pub fn subscribe(&self) -> ParentMessageWatch {
        ParentMessageWatch {
            state: Arc::clone(&self.0),
        }
    }
}

impl std::fmt::Debug for ParentMessageSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParentMessageSignal")
            .field("pending", &self.0.pending_ids())
            .finish()
    }
}

register_resource!("fuigo_build", "ParentMessageSignal", ParentMessageSignal);

/// One wait's level-triggered view of [`ParentMessageSignal`].
pub struct ParentMessageWatch {
    state: Arc<ParentMessageState>,
}

impl ParentMessageWatch {
    /// Resolves with every currently pending message identifier, immediately if
    /// one is already pending. Never resolves while the list is empty, so it is
    /// safe as a `select!` arm.
    pub async fn arrived(&self) -> Arc<[String]> {
        loop {
            // Register before the read: a commit racing the check still wakes us.
            let notified = self.state.notify.notified();
            let pending = self.state.pending_ids();
            if !pending.is_empty() {
                return Arc::from(pending);
            }
            notified.await;
        }
    }
}

#[cfg(test)]
#[path = "parent_message_tests.rs"]
mod tests;
