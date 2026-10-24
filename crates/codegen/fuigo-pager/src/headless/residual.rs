//! What a headless run still has to wait for once its prompt has returned: a goal that is still running,
//! and the follow-up turn the shell starts when a background task finishes.

use std::collections::HashSet;
use std::time::{Duration, Instant};

/// How long after background work finishes the run waits for the follow-up turn the shell starts in response.
pub(super) const FOLLOW_UP_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug, Default)]
pub(crate) struct ResidualWork {
    goals: HashSet<String>,
    prompt_returned: bool,
    wake_armed_at: Option<Instant>,
    follow_up_running: bool,
    /// The status a goal last stopped on when that was not a finish (`user_paused`, `blocked`, ...).
    goal_stop: Option<String>,
}

impl ResidualWork {
    /// The prompt the run sent has returned. Only from here on is anything awaited.
    pub(crate) fn prompt_returned(&mut self) {
        self.prompt_returned = true;
    }

    /// A goal left `active`: remember it when it stopped short of finishing, so the run can say so.
    /// Seeing it become active again (a resume) forgets the earlier stop.
    pub(crate) fn note_goal_stop(&mut self, status: &str) {
        if status == "active" {
            self.goal_stop = None;
        } else if !matches!(status, "complete" | "cleared") {
            self.goal_stop = Some(status.to_owned());
        }
    }

    /// The status the goal stopped on without finishing, if it did.
    pub(crate) fn take_goal_stop(&mut self) -> Option<String> {
        self.goal_stop.take()
    }

    /// A goal changed status: it is tracked while `active` and forgotten once it pauses, completes or is cleared.
    pub(crate) fn goal_status(&mut self, goal_id: &str, active: bool) {
        if active {
            self.goals.insert(goal_id.to_owned());
        } else {
            self.goals.remove(goal_id);
        }
    }

    /// A background task or subagent finished. After the prompt returned, the shell answers that by starting a
    /// follow-up turn on its own, so the run holds on for a moment to see it begin.
    pub(crate) fn background_finished(&mut self, now: Instant) {
        if self.prompt_returned {
            self.wake_armed_at = Some(now);
        }
    }

    /// The model or a tool produced output. That is a follow-up turn only if one was expected.
    pub(crate) fn turn_activity(&mut self) {
        if self.wake_armed_at.is_some() {
            self.follow_up_running = true;
        }
    }

    /// A turn reached its terminal outcome.
    pub(crate) fn turn_completed(&mut self) {
        self.wake_armed_at = None;
        self.follow_up_running = false;
    }

    /// Whether a goal the run saw start is still running.
    pub(crate) fn goal_active(&self) -> bool {
        !self.goals.is_empty()
    }

    /// Whether the run should keep waiting at `now`.
    pub(crate) fn is_waiting(&self, now: Instant) -> bool {
        if !self.prompt_returned {
            return false;
        }
        self.goal_active()
            || self.follow_up_running
            || self
                .wake_armed_at
                .is_some_and(|armed| now.saturating_duration_since(armed) < FOLLOW_UP_GRACE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn returned() -> ResidualWork {
        let mut r = ResidualWork::default();
        r.prompt_returned();
        r
    }

    #[test]
    fn an_active_goal_keeps_the_run_waiting_until_it_stops() {
        let mut r = returned();
        let now = Instant::now();
        assert!(!r.is_waiting(now));
        r.goal_status("g", true);
        assert!(r.goal_active());
        assert!(r.is_waiting(now + Duration::from_secs(3600)));
        r.goal_status("g", false);
        assert!(!r.goal_active());
        assert!(!r.is_waiting(now));
    }

    #[test]
    fn nothing_is_awaited_before_the_prompt_returned() {
        let mut r = ResidualWork::default();
        r.goal_status("g", true);
        assert!(!r.is_waiting(Instant::now()));
        r.prompt_returned();
        assert!(r.is_waiting(Instant::now()));
    }

    #[test]
    fn goals_are_tracked_by_id() {
        let mut r = returned();
        r.goal_status("a", true);
        r.goal_status("b", true);
        r.goal_status("a", false);
        assert!(r.goal_active(), "b is still running");
        r.goal_status("b", false);
        assert!(!r.goal_active());
    }

    #[test]
    fn a_finished_background_task_arms_a_short_wait_for_the_follow_up_turn() {
        let mut r = returned();
        let t0 = Instant::now();
        r.background_finished(t0);
        assert!(r.is_waiting(t0 + Duration::from_millis(500)));
        assert!(!r.is_waiting(t0 + FOLLOW_UP_GRACE + Duration::from_millis(1)));
    }

    #[test]
    fn a_follow_up_turn_that_started_is_awaited_past_the_grace_until_it_completes() {
        let mut r = returned();
        let t0 = Instant::now();
        r.background_finished(t0);
        r.turn_activity();
        let late = t0 + FOLLOW_UP_GRACE * 10;
        assert!(r.is_waiting(late), "the follow-up turn is running");
        r.turn_completed();
        assert!(!r.is_waiting(late));
    }

    #[test]
    fn activity_with_no_finished_task_is_not_a_follow_up() {
        let mut r = returned();
        r.turn_activity();
        assert!(!r.is_waiting(Instant::now()));
    }

    #[test]
    fn a_task_that_finished_during_the_prompt_arms_nothing() {
        let mut r = ResidualWork::default();
        let t0 = Instant::now();
        r.background_finished(t0);
        r.prompt_returned();
        assert!(!r.is_waiting(t0));
    }

    #[test]
    fn a_goal_that_stopped_short_is_remembered_once() {
        let mut r = returned();
        r.note_goal_stop("active");
        r.note_goal_stop("no_progress_paused");
        assert_eq!(r.take_goal_stop().as_deref(), Some("no_progress_paused"));
        assert_eq!(r.take_goal_stop(), None, "reported once");
    }

    #[test]
    fn finishing_or_resuming_forgets_an_earlier_stop() {
        let mut r = returned();
        r.note_goal_stop("blocked");
        r.note_goal_stop("active");
        r.note_goal_stop("complete");
        assert_eq!(r.take_goal_stop(), None);
        r.note_goal_stop("user_paused");
        r.note_goal_stop("cleared");
        assert_eq!(r.take_goal_stop().as_deref(), Some("user_paused"), "clearing is not a stop");
    }

    #[test]
    fn a_completed_turn_clears_the_grace_too() {
        let mut r = returned();
        let t0 = Instant::now();
        r.background_finished(t0);
        r.turn_completed();
        assert!(!r.is_waiting(t0));
    }
}
