//! A goal that keeps getting continued but never calls a tool is not making progress: after three such
//! continuations in a row it pauses (resumable with `/goal resume`) instead of burning more turns.

use super::support::*;
use super::*;
use super::turn_end::GoalTurnActivity;
use crate::session::goal_tracker::GoalStatus;
use crate::session::signals::{SessionSignals, SessionSignalsDelta, TurnDeltaSnapshot};

fn start_goal(actor: &SessionActor) {
    set_goal_harness_for_tests(actor);
    actor.goal_tracker.lock().create_goal(
        "goal".into(),
        "objective".into(),
        None,
        0,
        "2026-01-01T00:00:00Z".into(),
        None,
    );
}

fn snapshot_with_tool_calls(delta_tool_calls: i64, tools: &[&str]) -> TurnDeltaSnapshot {
    TurnDeltaSnapshot {
        current: SessionSignals::default(),
        delta: SessionSignalsDelta {
            delta_tool_calls,
            tools_this_turn: tools.iter().map(|t| (*t).to_owned()).collect(),
            ..Default::default()
        },
        start_prompt_mode: None,
        end_prompt_mode: None,
        turn_input_tokens: 0,
        turn_output_tokens: 0,
        turn_cached_input_tokens: 0,
    }
}

#[test]
fn turn_activity_reads_the_tool_calls_of_the_turn_snapshot() {
    use crate::session::commands::ok_end_turn;
    let idle = ok_end_turn(10, Some(snapshot_with_tool_calls(0, &[])));
    assert_eq!(SessionActor::goal_turn_activity(&idle), GoalTurnActivity::NoToolCalls);
    let counted = ok_end_turn(10, Some(snapshot_with_tool_calls(2, &[])));
    assert_eq!(SessionActor::goal_turn_activity(&counted), GoalTurnActivity::ToolCalls);
    let named = ok_end_turn(10, Some(snapshot_with_tool_calls(0, &["grep"])));
    assert_eq!(SessionActor::goal_turn_activity(&named), GoalTurnActivity::ToolCalls);
    let unknown = ok_end_turn(10, None);
    assert_eq!(SessionActor::goal_turn_activity(&unknown), GoalTurnActivity::Unknown);
    let failed: crate::session::commands::PromptTurnResult = Err(acp::Error::internal_error());
    assert_eq!(SessionActor::goal_turn_activity(&failed), GoalTurnActivity::Unknown);
}

#[tokio::test(flavor = "current_thread")]
async fn three_idle_goal_continuations_pause_the_goal() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = build_actor().await;
            start_goal(&actor);
            for i in 0..2 {
                actor
                    .note_goal_turn_activity(&format!("goal-summary-{i}"), GoalTurnActivity::NoToolCalls)
                    .await;
                assert_eq!(actor.goal_tracker.lock().status(), Some(GoalStatus::Active), "idle turn {i}");
            }
            actor
                .note_goal_turn_activity("goal-summary-2", GoalTurnActivity::NoToolCalls)
                .await;
            assert_eq!(
                actor.goal_tracker.lock().status(),
                Some(GoalStatus::NoProgressPaused),
                "the third idle continuation pauses the goal"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_tool_call_or_a_human_turn_clears_the_idle_streak() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = build_actor().await;
            start_goal(&actor);
            let idle = |n: &'static str| {
                let actor = actor.clone();
                async move { actor.note_goal_turn_activity(n, GoalTurnActivity::NoToolCalls).await }
            };
            idle("goal-summary-a").await;
            idle("goal-summary-b").await;
            actor
                .note_goal_turn_activity("goal-summary-c", GoalTurnActivity::ToolCalls)
                .await;
            idle("goal-summary-d").await;
            idle("goal-summary-e").await;
            // A turn the user typed is not a continuation and clears the streak too
            actor.note_goal_turn_activity("prompt-1", GoalTurnActivity::NoToolCalls).await;
            idle("goal-summary-f").await;
            idle("goal-summary-g").await;
            // An unknown activity moves nothing
            actor.note_goal_turn_activity("goal-summary-h", GoalTurnActivity::Unknown).await;
            assert_eq!(actor.goal_tracker.lock().status(), Some(GoalStatus::Active));
            idle("goal-summary-i").await;
            assert_eq!(actor.goal_tracker.lock().status(), Some(GoalStatus::NoProgressPaused));
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn resume_starts_the_idle_count_over() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = build_actor().await;
            start_goal(&actor);
            for i in 0..3 {
                actor
                    .note_goal_turn_activity(&format!("goal-summary-{i}"), GoalTurnActivity::NoToolCalls)
                    .await;
            }
            assert_eq!(actor.goal_tracker.lock().status(), Some(GoalStatus::NoProgressPaused));
            assert!(actor.goal_tracker.lock().resume());
            for i in 3..5 {
                actor
                    .note_goal_turn_activity(&format!("goal-summary-{i}"), GoalTurnActivity::NoToolCalls)
                    .await;
            }
            assert_eq!(
                actor.goal_tracker.lock().status(),
                Some(GoalStatus::Active),
                "two idle turns after a resume are not three in a row"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_goal_that_is_not_active_does_not_count() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = build_actor().await;
            start_goal(&actor);
            assert!(actor.goal_tracker.lock().pause(crate::session::goal_tracker::GoalPauseReason::User));
            for i in 0..5 {
                actor
                    .note_goal_turn_activity(&format!("goal-summary-{i}"), GoalTurnActivity::NoToolCalls)
                    .await;
            }
            assert_eq!(
                actor.goal_tracker.lock().status(),
                Some(GoalStatus::UserPaused),
                "the pause cause the user chose is kept"
            );
        })
        .await;
}
