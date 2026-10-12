//! P189: the session actor's side of `_fuigo/session/park` and `_fuigo/session/unpark`.
//!
//! The registry (`crate::session::quiesce`) carries the park itself, so every gate (turn promotion, the
//! notification drain, model calls) reads it without a round trip through this actor. The actor only does
//! the bookkeeping that needs its own state: deferring a running summary or title refresh, cancelling
//! subagents for a `mode: "stop"` park, reporting what is held, and running the deferred work at unpark.

use super::*;
use crate::session::quiesce::{self, OwedWork, ParkOp, QuiesceReport};

impl SessionActor {
    /// Answer a park probe. Called once when the park starts (with `stop` for a `mode: "stop"` park) and
    /// again while the park waits for a running turn to end.
    pub(super) async fn quiesce_probe(self: &Arc<Self>, park: &ParkOp, stop: bool) -> QuiesceReport {
        let session_id = park.session.clone();
        let session_id: &str = &session_id;
        // Every side effect below runs only while `park` is still the session's park, checked under the same
        // lock that records what it owes (a probe the actor reaches late does nothing).
        if stop {
            quiesce::run_if_current(park, || self.cancel_all_session_subagents());
        }
        // A summary or title refresh still running would call the model, or send its frame, after the ack.
        // Abort it and owe it to unpark, which runs it again.
        let summary_running = self
            .turn_summary_task
            .borrow()
            .as_ref()
            .is_some_and(|task| !task.is_finished());
        if summary_running
            && let Some(prompt_id) = quiesce::last_turn_summary_prompt(session_id)
        {
            quiesce::with_current_owed(park, |owed| {
                self.abort_turn_summary();
                owed.turn_summary = Some(prompt_id);
            });
        }
        let title_running = self
            .title_refresh_task
            .borrow()
            .as_ref()
            .is_some_and(|task| !task.is_finished());
        if title_running {
            quiesce::with_current_owed(park, |owed| {
                self.abort_title_refresh();
                owed.title_refresh = true;
            });
        }
        let mut report = QuiesceReport::default();
        if let Some(entry) = quiesce::entry(session_id) {
            report.turn_summary_deferred = entry.owed.turn_summary.is_some();
            report.title_refresh_deferred = entry.owed.title_refresh;
        }
        let state = self.state.lock().await;
        report.turn_running = state.running_task.is_some() || state.finalization_gate.is_active();
        report.queued_inputs = state.pending_inputs.len();
        report.pending_notifications = state.pending_notifications.len();
        report
    }

    /// Run the side work a park deferred. The caller then promotes the queue and drains notifications.
    pub(super) fn quiesce_release(self: &Arc<Self>, owed: OwedWork, reopen_spawns: bool) {
        if reopen_spawns {
            self.open_subagent_spawn_admission();
        }
        if let Some(prompt_id) = owed.turn_summary {
            self.restart_turn_summary(prompt_id);
        }
        if owed.title_refresh {
            self.maybe_refresh_title();
        }
    }
}
