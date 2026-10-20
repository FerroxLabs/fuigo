//! MCP `notifications/progress` forwarding (GitHub issue #20).
//!
//! rmcp attaches a `progressToken` to every `tools/call`. A server that reports progress sends
//! `notifications/progress` carrying that token; the client handler looks the token up in a
//! [`ProgressRegistry`] and hands the update to the [`McpProgressSink`] registered for that call,
//! which the shell turns into an ACP `tool_call_update` for the owning tool call.
//!
//! ## Token ownership across reconnections
//!
//! rmcp numbers progress tokens per connection (a counter that restarts at 0), but one
//! [`ProgressRegistry`] outlives every connection of its client. Entries are therefore keyed by
//! `(connection generation, token)`: each handler built for a new connection carries a fresh
//! generation, and both registration and delivery use it, so an old in-flight call and a new call
//! that happen to share a token number never see each other's updates. Every entry also carries a
//! unique serial; its guard and its timers act only on the entry carrying that serial.
//!
//! ## Throttling
//!
//! Each token delivers at most one update per [`PROGRESS_MIN_INTERVAL`]. Updates arriving inside the
//! interval overwrite one pending slot (latest wins) and a single trailing timer flushes it, so a burst
//! is coalesced but the last update is always delivered.
//!
//! ## Ordering guarantees at both ends of a call
//!
//! rmcp assigns the token while it enqueues the request and runs every notification handler in its
//! own task, so a call cannot know its token before sending and a handler can run late. Two bounded
//! mechanisms close the resulting windows:
//!
//! * **Start.** The call takes a [`ProgressClaim`] *before* the request is sent. While any claim is
//!   outstanding, progress for a token nobody has bound yet is held (latest and highest per token, at
//!   most [`EARLY_STASH_CAP`] tokens) and replayed the moment [`ProgressClaim::bind`] learns the token.
//!   With no claim outstanding, progress for an unknown token is ignored as before.
//! * **End.** When the reply arrives, [`ProgressGuard::complete`] flushes the pending update at once and
//!   leaves the entry in a *settling* state for [`SETTLE_GRACE`]: a handler task that was queued behind
//!   the reply still delivers (throttled as usual, trailing flush included) during that window. After
//!   it the entry is removed and a later notification is ignored. A call that is cancelled, times out or
//!   fails drops its guard instead, which removes the entry immediately.
//!
//! The guarantee is therefore: every notification whose handler runs before the call's reply or within
//! [`SETTLE_GRACE`] after it is delivered, and updates for one call are delivered in increasing-progress
//! order. A handler delayed by more than [`SETTLE_GRACE`] after the reply is dropped. A settling update
//! may reach the sink just after the call's result; it carries progress only, never status or content.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rmcp::model::{ProgressNotificationParam, ProgressToken};
use tokio::time::Instant;

/// Minimum spacing between two delivered updates for one tool call.
pub const PROGRESS_MIN_INTERVAL: Duration = Duration::from_millis(250);

/// How long a completed call's entry keeps accepting updates from notification handlers still queued
/// behind its reply.
pub const SETTLE_GRACE: Duration = Duration::from_millis(100);

/// Most distinct unclaimed tokens whose early progress is held while claims are outstanding.
pub const EARLY_STASH_CAP: usize = 64;

/// Identifies one connection of a client, so tokens (which rmcp numbers per connection) stay unique.
pub type Generation = u64;

/// One progress report for a tool call.
#[derive(Debug, Clone, PartialEq)]
pub struct McpToolProgress {
    /// MCP server the call runs on.
    pub server: String,
    /// Id of the owning tool call (the id the ACP client knows the call by).
    pub tool_call_id: String,
    /// Progress so far.
    pub progress: f64,
    /// Total, when the server knows it.
    pub total: Option<f64>,
    /// Human-readable status from the server.
    pub message: Option<String>,
}

/// Receiver of throttled progress. Called synchronously and must not block.
pub type McpProgressSink = Arc<dyn Fn(McpToolProgress) + Send + Sync>;

type Key = (Generation, ProgressToken);

struct Entry {
    /// Unique per registration; guards and timers act only on the entry they created.
    serial: u64,
    /// The call has its reply and is only draining handlers still queued behind it.
    settling: bool,
    sink: McpProgressSink,
    server: String,
    tool_call_id: String,
    last_sent: Option<Instant>,
    /// Highest progress seen. The MCP spec requires progress to increase; rmcp runs each notification
    /// handler in its own task, so a stale one can arrive late and must not overwrite a newer update.
    high_water: Option<f64>,
    pending: Option<McpToolProgress>,
    timer_armed: bool,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<Key, Entry>,
    /// Progress that arrived for a token no call has bound yet, while a claim was outstanding.
    early: HashMap<Key, ProgressNotificationParam>,
    /// Claims taken before a request was sent and not yet bound or dropped.
    claims: usize,
    next_serial: u64,
}

/// Maps in-flight progress tokens to the tool call that owns them.
#[derive(Default)]
pub struct ProgressRegistry {
    inner: parking_lot::Mutex<Inner>,
}

impl std::fmt::Debug for ProgressRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressRegistry")
            .field("in_flight", &self.len())
            .finish()
    }
}

impl ProgressRegistry {
    /// Number of calls still in flight. Settling entries (reply received, draining queued handlers) are not counted.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .entries
            .values()
            .filter(|e| !e.settling)
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of entries in the settling state.
    pub fn settling_len(&self) -> usize {
        self.inner
            .lock()
            .entries
            .values()
            .filter(|e| e.settling)
            .count()
    }

    /// Reserve ownership for a call that is about to send its request on connection `generation`.
    ///
    /// Take this *before* sending, then [`ProgressClaim::bind`] the token rmcp assigned: progress that
    /// races ahead of the bind is held and replayed instead of dropped.
    pub fn claim(
        self: &Arc<Self>,
        generation: Generation,
        binding: &ProgressBinding,
    ) -> ProgressClaim {
        self.inner.lock().claims += 1;
        ProgressClaim {
            registry: Arc::clone(self),
            generation,
            binding: binding.clone(),
            bound: false,
        }
    }

    /// Claim and bind in one step, for a caller that already knows its token.
    pub fn register(
        self: &Arc<Self>,
        generation: Generation,
        token: ProgressToken,
        binding: &ProgressBinding,
    ) -> ProgressGuard {
        self.claim(generation, binding).bind(token)
    }

    /// Handle one `notifications/progress` that arrived on connection `generation`.
    /// Unknown tokens are ignored, unless a claim is outstanding (see [`ProgressClaim`]).
    pub fn deliver(self: &Arc<Self>, generation: Generation, params: ProgressNotificationParam) {
        let mut inner = self.inner.lock();
        let key = (generation, params.progress_token.clone());
        self.deliver_locked(&mut inner, key, params);
    }

    fn deliver_locked(
        self: &Arc<Self>,
        inner: &mut Inner,
        key: Key,
        params: ProgressNotificationParam,
    ) {
        let Some(entry) = inner.entries.get_mut(&key) else {
            if inner.claims > 0 {
                Self::stash_early(inner, key, params);
            } else {
                tracing::debug!(token = ?params.progress_token, "progress for unknown token ignored");
            }
            return;
        };
        if entry.high_water.is_some_and(|seen| params.progress <= seen) {
            tracing::debug!(token = ?params.progress_token, progress = params.progress, "non-increasing progress ignored");
            return;
        }
        entry.high_water = Some(params.progress);
        let update = McpToolProgress {
            server: entry.server.clone(),
            tool_call_id: entry.tool_call_id.clone(),
            progress: params.progress,
            total: params.total,
            message: params.message,
        };
        let now = Instant::now();
        if entry.timer_armed {
            // A trailing flush is already scheduled: latest wins.
            entry.pending = Some(update);
            return;
        }
        let wait = match entry.last_sent {
            Some(sent) => PROGRESS_MIN_INTERVAL.saturating_sub(now.duration_since(sent)),
            None => Duration::ZERO,
        };
        let runtime = tokio::runtime::Handle::try_current().ok();
        match (wait.is_zero(), runtime) {
            (true, _) | (false, None) => {
                // Due now (or no runtime to time a trailing flush: deliver rather than lose it).
                entry.last_sent = Some(now);
                entry.pending = None;
                (entry.sink)(update);
            }
            (false, Some(runtime)) => {
                entry.pending = Some(update);
                entry.timer_armed = true;
                let registry = Arc::clone(self);
                let serial = entry.serial;
                runtime.spawn(async move {
                    tokio::time::sleep(wait).await;
                    registry.flush(&key, serial);
                });
            }
        }
    }

    /// Hold progress for a token that no call has bound yet: only the highest report per token, bounded.
    fn stash_early(inner: &mut Inner, key: Key, params: ProgressNotificationParam) {
        if let Some(held) = inner.early.get_mut(&key) {
            if params.progress > held.progress {
                *held = params;
            }
        } else if inner.early.len() < EARLY_STASH_CAP {
            inner.early.insert(key, params);
        } else {
            tracing::debug!(token = ?params.progress_token, "early progress stash full; dropped");
        }
    }

    /// Trailing flush: deliver the pending update, if that exact entry is still registered.
    fn flush(&self, key: &Key, serial: u64) {
        let mut inner = self.inner.lock();
        let Some(entry) = inner.entries.get_mut(key) else {
            return;
        };
        if entry.serial != serial {
            return;
        }
        entry.timer_armed = false;
        if let Some(update) = entry.pending.take() {
            entry.last_sent = Some(Instant::now());
            (entry.sink)(update);
        }
    }

    /// Remove the entry `serial` of `key` (and only that one), delivering its pending update first.
    fn remove(&self, key: &Key, serial: u64) {
        let removed = {
            let mut inner = self.inner.lock();
            if inner.entries.get(key).is_some_and(|e| e.serial == serial) {
                inner.entries.remove(key)
            } else {
                None
            }
        };
        if let Some(mut entry) = removed
            && let Some(update) = entry.pending.take()
        {
            (entry.sink)(update);
        }
    }

    /// The reply arrived: flush now, keep accepting for [`SETTLE_GRACE`], then remove.
    fn begin_settling(self: &Arc<Self>, key: &Key, serial: u64) {
        let runtime = tokio::runtime::Handle::try_current().ok();
        {
            let mut inner = self.inner.lock();
            let Some(entry) = inner.entries.get_mut(key).filter(|e| e.serial == serial) else {
                return;
            };
            if let Some(runtime) = &runtime {
                entry.settling = true;
                if let Some(update) = entry.pending.take() {
                    entry.last_sent = Some(Instant::now());
                    (entry.sink)(update);
                }
                let registry = Arc::clone(self);
                let key = key.clone();
                runtime.spawn(async move {
                    tokio::time::sleep(SETTLE_GRACE).await;
                    registry.remove(&key, serial);
                });
                return;
            }
        }
        // No runtime to time the grace window: nothing can be queued either.
        self.remove(key, serial);
    }
}

/// Ownership reserved before a request is sent; becomes a [`ProgressGuard`] once the token is known.
/// Dropping it unbound (the send failed) releases the reservation.
pub struct ProgressClaim {
    registry: Arc<ProgressRegistry>,
    generation: Generation,
    binding: ProgressBinding,
    bound: bool,
}

impl ProgressClaim {
    /// Map `token` to the claiming call until the returned guard drops, replaying any progress that
    /// arrived for it since the claim was taken.
    pub fn bind(mut self, token: ProgressToken) -> ProgressGuard {
        self.bound = true;
        let key = (self.generation, token);
        let registry = Arc::clone(&self.registry);
        let mut inner = registry.inner.lock();
        inner.claims = inner.claims.saturating_sub(1);
        let serial = inner.next_serial;
        inner.next_serial += 1;
        inner.entries.insert(
            key.clone(),
            Entry {
                serial,
                settling: false,
                sink: self.binding.sink.clone(),
                server: self.binding.server.clone(),
                tool_call_id: self.binding.tool_call_id.clone(),
                last_sent: None,
                high_water: None,
                pending: None,
                timer_armed: false,
            },
        );
        if let Some(early) = inner.early.remove(&key) {
            registry.deliver_locked(&mut inner, key.clone(), early);
        }
        if inner.claims == 0 {
            inner.early.clear();
        }
        ProgressGuard {
            registry: Arc::clone(&self.registry),
            key,
            serial,
            completed: false,
        }
    }
}

impl Drop for ProgressClaim {
    fn drop(&mut self) {
        if self.bound {
            return;
        }
        let mut inner = self.registry.inner.lock();
        inner.claims = inner.claims.saturating_sub(1);
        if inner.claims == 0 {
            inner.early.clear();
        }
    }
}

/// Removes its token from the registry on drop (cancellation, timeout or error) and delivers any
/// pending update first. [`Self::complete`] is the normal end: it settles instead of removing at once.
pub struct ProgressGuard {
    registry: Arc<ProgressRegistry>,
    key: Key,
    serial: u64,
    completed: bool,
}

impl ProgressGuard {
    /// The reply arrived. Flush now and keep the entry for [`SETTLE_GRACE`] so handlers still queued
    /// behind the reply can deliver, then remove it.
    pub fn complete(mut self) {
        self.completed = true;
        self.registry.begin_settling(&self.key, self.serial);
    }
}

impl Drop for ProgressGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.registry.remove(&self.key, self.serial);
        }
    }
}

/// Where one tool call's progress goes. Carried to the wire layer through [`CURRENT_PROGRESS`]
/// so the many `try_call_tool` / retry signatures stay unchanged.
#[derive(Clone)]
pub struct ProgressBinding {
    pub registry: Arc<ProgressRegistry>,
    pub sink: McpProgressSink,
    pub server: String,
    pub tool_call_id: String,
}

tokio::task_local! {
    /// Set by the agent's tool path around one `tools/call` dispatch.
    pub static CURRENT_PROGRESS: ProgressBinding;
}
