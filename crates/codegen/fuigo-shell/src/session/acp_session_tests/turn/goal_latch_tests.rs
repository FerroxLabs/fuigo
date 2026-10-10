//! P89 (audit H-2): one unsuccessful turn must not permanently kill an active `/goal`.
//!
//! A goal's durable execution record is keyed by `blake3(session \0 goal_id)`, and `/goal resume`
//! keeps the goal id, so every turn of a goal reopens the same record. Before P89 any turn that did
//! not end `EndTurn` -- the user's Esc, a provider error, an answer cut at max output tokens, a
//! refusal -- wrote `Terminal` to that record, and every later turn of the goal failed before it
//! reached the model. Only `/goal clear` and a new goal recovered.
//!
//! These tests drive the real prompt path (`handle_prompt`, the entry `session/prompt` takes) with an
//! ACTIVE goal, so the turn opens the goal-keyed record exactly as production does, end the first turn
//! with each cause, resume with `resume_goal` (the `/goal resume` implementation), and run the turn the
//! resume hands to the model. The goal harness (verifier, continuation re-queue) is off in the test
//! actor: what is under test is the execution record a goal's turns share, not the verifier.
//!
//! A genuinely spent budget is the counter-test: it must stay terminal, and both `/goal resume` and
//! the next turn must say which limit stopped it and what to do.

use super::disk_full_tests::{
    actor_with_mock_sampler_configured, block_on_session, current_thread_local, spawn_persistence_stub,
};
use super::support::*;
use super::*;
use crate::acp_error::{EXECUTION_BUDGET_DENIED_CODE, ExecutionBudgetRule};
use crate::session::execution_state::{Execution, TokenLimits};
use crate::session::goal_tracker::GoalStatus;
use fuigo_sampling_types::{ExecutionAdmission, RequestPurpose, TokenUsage};
use fuigo_test_support::sse::{responses_api_reasoning_then_tool_call_events, responses_api_script_exact};
use fuigo_test_support::{MockInferenceServer, ScriptedResponse};
use std::sync::Arc;
use std::time::Duration;

/// What the model says once the goal is running again. It is the mock's DEFAULT reply, so a first
/// turn that consumed more requests than scripted can never steal it from the resumed turn.
const RESUMED: &str = "the resumed goal answered";
/// A `search_replace` call: an edit, so the non-yolo permission manager always prompts for it.
const EDIT_ARGS: &str = r#"{"file_path":"/tmp/p89-goal-latch.txt","old_string":"a","new_string":"b"}"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cause {
    /// The user pressed Esc on the turn's permission prompt: `TurnOutcome::Cancelled`.
    UserCancel,
    /// The provider answered 500 and the turn-level retry is off: the turn fails with a provider
    /// error. (Not 503: the shell classifies 503 as a rate limit and backs off and resends.)
    ProviderError,
    /// The answer was cut at the model's output-token limit (`incomplete`, `max_output_tokens`).
    MaxTokens,
    /// The provider refused (`incomplete`, `content_filter`): `CompletedStop::Refusal`, goal auto-paused.
    Refusal,
}

/// A Responses-API reply that ends `incomplete` for `reason`, with `text` already streamed.
fn incomplete(text: &str, reason: &str) -> ScriptedResponse {
    let mut events = responses_api_script_exact(text, "test");
    for event in &mut events {
        let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&event.data) else {
            continue;
        };
        if value["type"] == "response.completed" {
            value["type"] = "response.incomplete".into();
            value["response"]["status"] = "incomplete".into();
            value["response"]["incomplete_details"] = serde_json::json!({ "reason": reason });
            value["response"]["output"][0]["status"] = "incomplete".into();
            event.data = value.to_string();
        }
    }
    ScriptedResponse::sse(events)
}

/// Acks notifications and answers every permission prompt `Cancelled`: what Esc on the prompt sends.
fn drain_gateway_cancelling_permission(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<fuigo_acp_lib::AcpClientMessage>,
) {
    tokio::task::spawn_local(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                fuigo_acp_lib::AcpClientMessage::SessionNotification(args) => {
                    let _ = args.response_tx.send(Ok(()));
                }
                fuigo_acp_lib::AcpClientMessage::RequestPermission(args) => {
                    let _ = args
                        .response_tx
                        .send(Ok(acp::RequestPermissionResponse::new(
                            acp::RequestPermissionOutcome::Cancelled,
                        )));
                }
                _ => {}
            }
        }
    });
}

async fn run_text(
    actor: &Arc<SessionActor>,
    prompt_id: &str,
    text: &str,
) -> Result<crate::session::commands::PromptTurnOk, acp::Error> {
    tokio::time::timeout(
        Duration::from_secs(120),
        actor.handle_prompt(
            prompt_id,
            vec![acp::ContentBlock::Text(acp::TextContent::new(text.to_string()))],
            PromptMode::Agent,
            None,
            None,
            None,
            None,
            true,
            /* send_now */ false,
            None,
            None,
            None,
        ),
    )
    .await
    .expect("turn must finish within timeout")
}

/// The goal harness (`update_goal`, the verifier) is off in the test actor, and a session without it
/// pauses an active goal at its first turn (`maybe_reconcile_active_goal_without_harness`), so no turn
/// here would run under the goal. That one-shot safety net is marked done, as it is in every session
/// whose toolset has the harness: the turns then open the goal-keyed record exactly as production does.
fn keep_goal_active(actor: &mut SessionActor) {
    actor
        .goal_harness_availability_reconciled
        .store(true, std::sync::atomic::Ordering::Relaxed);
}

/// An ACTIVE goal on `actor`, with a plan already on record so `resume_goal` never re-runs a planner.
fn start_goal(actor: &SessionActor, goal_id: &str, token_budget: Option<i64>) {
    let mut tracker = actor.goal_tracker.lock();
    tracker.create_goal(
        goal_id.to_string(),
        "p89 objective".to_string(),
        token_budget,
        0,
        "2026-10-03T00:00:00Z".to_string(),
        None,
    );
    tracker.snapshot_mut().expect("goal created").plan_file =
        Some(std::path::PathBuf::from("/tmp/p89-goal-latch-plan.md"));
}

struct GoalRun {
    first: Result<crate::session::commands::PromptTurnOk, acp::Error>,
    status_after_first: Option<GoalStatus>,
    resume: Result<String, String>,
    status_after_resume: Option<GoalStatus>,
    second: Option<Result<crate::session::commands::PromptTurnOk, acp::Error>>,
    second_model_requests: u32,
    /// Requests turn 1 sent, and the server's log, for a fixture failure's message.
    first_model_requests: u32,
    request_log: String,
}

/// Turn 1 of an active goal ends by `cause`; then `/goal resume`; then the turn the resume hands to
/// the model.
fn interrupted_goal_then_resume(cause: Cause, run: &'static str) -> GoalRun {
    let cell = Arc::new(std::sync::Mutex::new(None));
    let sink = cell.clone();
    block_on_session(move || {
        current_thread_local(async move {
            let server = MockInferenceServer::start()
                .await
                .expect("mock inference server");
            server.set_response(RESUMED);
            match cause {
                Cause::UserCancel => server.enqueue_response(
                    "/v1/responses",
                    ScriptedResponse::sse(responses_api_reasoning_then_tool_call_events(
                        "edit it",
                        "p89-edit-call",
                        "search_replace",
                        EDIT_ARGS,
                        "test",
                    )),
                ),
                Cause::ProviderError => server.enqueue_response(
                    "/v1/responses",
                    ScriptedResponse::text(500, "upstream failure"),
                ),
                Cause::MaxTokens => server.enqueue_response(
                    "/v1/responses",
                    incomplete("one, two, three,", "max_output_tokens"),
                ),
                Cause::Refusal => server.enqueue_response(
                    "/v1/responses",
                    incomplete("I can't help with that.", "content_filter"),
                ),
            }
            let (gateway_tx, gateway_rx) =
                tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
            let permission_gateway = if cause == Cause::UserCancel {
                drain_gateway_cancelling_permission(gateway_rx);
                Some(fuigo_acp_lib::AcpAgentGatewaySender::new(gateway_tx.clone()))
            } else {
                drain_gateway(gateway_rx);
                None
            };
            let (persistence_tx, persistence_rx) =
                tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
            spawn_persistence_stub(persistence_rx, || Ok(()));
            let actor = actor_with_mock_sampler_configured(
                &server,
                run,
                persistence_tx,
                gateway_tx,
                None,
                permission_gateway,
                |actor| {
                    // A provider error must end THIS turn, not be resent (by the sampler's retry
                    // budget, which the actor's `max_retries` sets per request, or by the turn's
                    // transient resubmit) into the reply meant for the resumed turn.
                    actor.max_retries = 0;
                    actor.transient_retry_enabled = false;
                    keep_goal_active(actor);
                },
            )
            .await;
            start_goal(&actor, &format!("{run}-goal"), None);

            let first = run_text(&actor, &format!("{run}-turn-1"), "work on the goal").await;
            let first_model_requests = server.request_count();
            let request_log = server.request_log_summary();
            let status_after_first = actor.goal_tracker.lock().status();

            let resume = match actor.resume_goal().await {
                GoalResumeOutcome::Inference { reminder, .. } => Ok(reminder),
                GoalResumeOutcome::Message(message) => Err(message),
            };
            let status_after_resume = actor.goal_tracker.lock().status();
            let before = server.request_count();
            let second = match &resume {
                Ok(reminder) => Some(run_text(&actor, &format!("{run}-turn-2"), reminder).await),
                Err(_) => None,
            };
            let second_model_requests = server.request_count() - before;
            if let Some(execution) = Execution::current(run) {
                execution.release(run);
            }
            *sink.lock().unwrap() = Some(GoalRun {
                first,
                status_after_first,
                resume,
                status_after_resume,
                second,
                second_model_requests,
                first_model_requests,
                request_log,
            });
        });
    });
    let taken = cell.lock().unwrap().take();
    taken.expect("the goal run produced a result")
}

fn assert_goal_survives(cause: Cause, run: &'static str) {
    let run_result = interrupted_goal_then_resume(cause, run);
    // Fixture check: turn 1 really did end by `cause`, not normally.
    match (&run_result.first, cause) {
        (Ok(ok), Cause::UserCancel) => assert_eq!(ok.stop_reason, acp::StopReason::Cancelled, "{cause:?}"),
        (Ok(ok), Cause::Refusal) => assert_eq!(ok.stop_reason, acp::StopReason::Refusal, "{cause:?}"),
        (Ok(ok), _) => assert_ne!(
            ok.stop_reason,
            acp::StopReason::EndTurn,
            "{cause:?}: the first turn must not end normally, or this test proves nothing \
             ({} requests: {})",
            run_result.first_model_requests,
            run_result.request_log
        ),
        // A completed-but-not-`EndTurn` turn under a tracked execution is reported as the partial
        // receipt's `execution_incomplete` error (pre-existing, unchanged here); what matters is that
        // no BUDGET ended it.
        (Err(err), Cause::ProviderError | Cause::MaxTokens | Cause::Refusal) => assert!(
            !crate::acp_error::ExecutionBudgetDenial::is_budget_denial(err),
            "{cause:?}: the first turn must fail for the provider's reason, not a budget's: {err:?}"
        ),
        (Err(err), _) => panic!("{cause:?}: unexpected first-turn error {err:?}"),
    }
    if cause == Cause::Refusal {
        assert_eq!(
            run_result.status_after_first,
            Some(GoalStatus::InfraPaused),
            "a refusal auto-pauses the goal, so this case exercises a real pause -> resume"
        );
    }
    let reminder = run_result.resume.as_ref().unwrap_or_else(|message| {
        panic!("{cause:?}: `/goal resume` must hand the goal back to the model, got: {message}")
    });
    assert!(!reminder.is_empty());
    assert_eq!(run_result.status_after_resume, Some(GoalStatus::Active), "{cause:?}");
    let second = run_result.second.expect("the resumed turn ran");
    let ok = second.unwrap_or_else(|err| {
        panic!(
            "{cause:?}: the resumed goal's turn must run, not fail before the model: {}",
            serde_json::to_value(&err).unwrap_or_default()
        )
    });
    assert_eq!(ok.stop_reason, acp::StopReason::EndTurn, "{cause:?}");
    assert!(
        run_result.second_model_requests >= 1,
        "{cause:?}: the resumed turn's answer came from the model"
    );
}

#[test]
fn a_goal_survives_a_user_cancelled_turn() {
    assert_goal_survives(Cause::UserCancel, "p89-goal-cancel");
}

#[test]
fn a_goal_survives_a_provider_error() {
    assert_goal_survives(Cause::ProviderError, "p89-goal-provider-error");
}

#[test]
fn a_goal_survives_a_max_tokens_cut() {
    assert_goal_survives(Cause::MaxTokens, "p89-goal-max-tokens");
}

#[test]
fn a_goal_survives_a_refusal_and_resumes() {
    assert_goal_survives(Cause::Refusal, "p89-goal-refusal");
}

/// Esc over ACP (`session/cancel`) drops the running turn's future, so `handle_turn_input` never
/// issues the receipt: `cancel_running_task` ends the turn through `emit_turn_completed` with
/// `Ok(Cancelled)`, which issues it instead. That path must leave the goal resumable too.
#[test]
fn a_goal_survives_a_cancel_that_dropped_the_turn() {
    const RUN: &str = "p89-goal-cancel-dropped";
    let cell = Arc::new(std::sync::Mutex::new(None));
    let sink = cell.clone();
    block_on_session(move || {
        current_thread_local(async move {
            let server = MockInferenceServer::start()
                .await
                .expect("mock inference server");
            server.set_response(RESUMED);
            let (gateway_tx, gateway_rx) =
                tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
            drain_gateway(gateway_rx);
            let (persistence_tx, persistence_rx) =
                tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
            spawn_persistence_stub(persistence_rx, || Ok(()));
            let actor = actor_with_mock_sampler_configured(
                &server, RUN, persistence_tx, gateway_tx, None, None, keep_goal_active,
            )
            .await;
            let goal_id = format!("{RUN}-goal");
            start_goal(&actor, &goal_id, None);
            // The turn the user cancelled: opened under the goal, its model request admitted and
            // never answered.
            let cancelled = Execution::open(
                &actor.notifications.persistence_tx,
                RUN,
                &goal_id,
                "cancelled-turn",
                u64::MAX,
                None,
                None,
                TokenLimits::default(),
                None,
            )
            .await
            .expect("execution is durable");
            cancelled
                .admit(RequestPurpose::Work, uuid::Uuid::new_v4().to_string())
                .await
                .unwrap();
            drop(cancelled);
            actor
                .emit_turn_completed(
                    "cancelled-turn".to_string(),
                    &Ok(acp::StopReason::Cancelled),
                    None,
                    Some("user"),
                    None,
                    None,
                    None,
                )
                .await;
            assert!(
                Execution::current(RUN).is_none(),
                "the cancel path issued the receipt and released the execution"
            );

            let resume = match actor.resume_goal().await {
                GoalResumeOutcome::Inference { reminder, .. } => Ok(reminder),
                GoalResumeOutcome::Message(message) => Err(message),
            };
            let before = server.request_count();
            let second = match &resume {
                Ok(reminder) => Some(run_text(&actor, &format!("{RUN}-turn-2"), reminder).await),
                Err(_) => None,
            };
            let model_requests = server.request_count() - before;
            if let Some(execution) = Execution::current(RUN) {
                execution.release(RUN);
            }
            *sink.lock().unwrap() = Some((resume, second, model_requests));
        });
    });
    let (resume, second, model_requests) =
        cell.lock().unwrap().take().expect("the cancel run produced a result");
    resume.unwrap_or_else(|message| panic!("`/goal resume` must hand the goal back: {message}"));
    let ok = second
        .expect("the resumed turn ran")
        .unwrap_or_else(|err| {
            panic!(
                "the resumed goal's turn must run, not fail before the model: {}",
                serde_json::to_value(&err).unwrap_or_default()
            )
        });
    assert_eq!(ok.stop_reason, acp::StopReason::EndTurn);
    assert!(model_requests >= 1, "the resumed turn's answer came from the model");
}

/// The counter-test. A goal whose token budget is genuinely spent must STAY stopped -- reopening must
/// never turn a budget into a no-op -- and the user must be told which limit stopped it and how to
/// continue, both by `/goal resume` and by the next turn, with nothing reaching the model.
#[test]
fn a_goal_whose_budget_is_spent_stays_stopped_and_says_how_to_continue() {
    const RUN: &str = "p89-goal-budget-spent";
    let cell = Arc::new(std::sync::Mutex::new(None));
    let sink = cell.clone();
    block_on_session(move || {
        current_thread_local(async move {
            let server = MockInferenceServer::start()
                .await
                .expect("mock inference server");
            server.set_response(RESUMED);
            let (gateway_tx, gateway_rx) =
                tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
            drain_gateway(gateway_rx);
            let (persistence_tx, persistence_rx) =
                tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
            spawn_persistence_stub(persistence_rx, || Ok(()));
            let actor = actor_with_mock_sampler_configured(
                &server, RUN, persistence_tx, gateway_tx, None, None, keep_goal_active,
            )
            .await;
            let goal_id = format!("{RUN}-goal");
            start_goal(&actor, &goal_id, Some(100));
            // Earlier turns of this goal spent 120 of its 100 tokens.
            let execution = Execution::open(
                &actor.notifications.persistence_tx,
                RUN,
                &goal_id,
                "earlier-turn",
                u64::MAX,
                None,
                None,
                TokenLimits { total: Some(100), output: None, initial_total: 0 },
                None,
            )
            .await
            .expect("execution is durable");
            let earlier = uuid::Uuid::new_v4().to_string();
            execution.admit(RequestPurpose::Work, earlier.clone()).await.unwrap();
            execution
                .settle(earlier, Some(TokenUsage { total_tokens: 120, ..Default::default() }))
                .await
                .unwrap();
            drop(execution);

            let before = server.request_count();
            let first = run_text(&actor, &format!("{RUN}-turn-1"), "work on the goal").await;
            let resume = match actor.resume_goal().await {
                GoalResumeOutcome::Inference { reminder, .. } => Ok(reminder),
                GoalResumeOutcome::Message(message) => Err(message),
            };
            let second = run_text(&actor, &format!("{RUN}-turn-2"), "continue the goal").await;
            let model_requests = server.request_count() - before;
            if let Some(execution) = Execution::current(RUN) {
                execution.release(RUN);
            }
            *sink.lock().unwrap() = Some((first, resume, second, model_requests));
        });
    });
    let (first, resume, second, model_requests) =
        cell.lock().unwrap().take().expect("the budget run produced a result");
    assert_eq!(model_requests, 0, "a spent budget lets nothing reach the model");
    for (label, result) in [("first", &first), ("after resume", &second)] {
        let err = result
            .as_ref()
            .err()
            .unwrap_or_else(|| panic!("{label}: a spent budget must refuse the turn"));
        let wire = serde_json::to_value(err).unwrap();
        assert_eq!(
            wire["data"]["code"], EXECUTION_BUDGET_DENIED_CODE,
            "{label}: the turn says a BUDGET stopped it, not a generic receipt: {wire}"
        );
        assert_eq!(
            wire["data"]["rule"],
            ExecutionBudgetRule::TotalTokensExhausted.id(),
            "{label}: {wire}"
        );
        assert_eq!(
            wire["data"]["remedy"],
            ExecutionBudgetRule::TotalTokensExhausted.remedy(),
            "{label}: the remedy tells the user how to continue: {wire}"
        );
    }
    let message = resume.expect_err("`/goal resume` must not hand a spent goal back to the model");
    assert!(
        message.contains("token budget") && message.contains("/goal"),
        "the resume message says which limit stopped the goal and how to continue: {message}"
    );
}

/// P195 (K25): a goal's token budget (`/goal <objective> --budget N`) spent by the answer that completes the turn. In an
/// interactive session the turn is an ordinary success and the goal harness stops the goal budget-limited at the turn's end.
/// A headless run (`fuigo -p`) has no later turn to carry that: the run ended at this answer because the budget did, so the
/// prompt must end as the token budget's typed denial (`fuigo -p` exits 3, B4), not as a success (exit 0). The goal itself is
/// stopped budget-limited either way.
fn goal_answer_spends_budget(
    run: &'static str,
    token_budget: i64,
    headless: bool,
) -> (Result<crate::session::commands::PromptTurnOk, acp::Error>, Option<GoalStatus>) {
    let cell = Arc::new(std::sync::Mutex::new(None));
    let sink = cell.clone();
    block_on_session(move || {
        current_thread_local(async move {
            let server = MockInferenceServer::start()
                .await
                .expect("mock inference server");
            server.set_response(RESUMED);
            let (gateway_tx, gateway_rx) =
                tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
            drain_gateway(gateway_rx);
            let (persistence_tx, persistence_rx) =
                tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
            spawn_persistence_stub(persistence_rx, || Ok(()));
            let actor = actor_with_mock_sampler_configured(
                &server,
                run,
                persistence_tx,
                gateway_tx,
                None,
                None,
                |actor| {
                    keep_goal_active(actor);
                    actor.attach_non_interactive.set(headless);
                },
            )
            .await;
            start_goal(&actor, &format!("{run}-goal"), Some(token_budget));

            let result = run_text(&actor, &format!("{run}-turn"), "work on the goal").await;
            let status = actor.goal_tracker.lock().status();
            if let Some(execution) = Execution::current(run) {
                execution.release(run);
            }
            *sink.lock().unwrap() = Some((result, status));
        });
    });
    let taken = cell.lock().unwrap().take();
    taken.expect("the goal turn produced a result")
}

#[test]
fn a_headless_goal_whose_answer_spends_the_token_budget_ends_as_the_token_denial() {
    let (result, status) = goal_answer_spends_budget("p195-goal-budget-headless", 10, true);
    let err = match result {
        Err(err) => err,
        Ok(ok) => panic!("the budget ended this run, so it is not a success: {:?}", ok.stop_reason),
    };
    let wire = serde_json::to_value(&err).expect("serialize");
    assert_eq!(wire["data"]["code"], EXECUTION_BUDGET_DENIED_CODE, "{wire}");
    assert_eq!(wire["data"]["rule"], ExecutionBudgetRule::TotalTokensExhausted.id(), "{wire}");
    assert_eq!(wire["data"]["total_token_limit"], 10, "{wire}");
    assert!(wire["data"]["total_tokens_used"].as_u64().is_some_and(|used| used >= 10), "{wire}");
    // K25 (Grok r1): the headless run can tell the answer completed and keep it in its one result document
    assert_eq!(wire["data"]["answer_completed"], true, "{wire}");
    assert_eq!(status, Some(GoalStatus::BudgetLimited), "the goal stops budget-limited, not paused");
}

/// Counter-test: the same answer with budget left, headless, is a success and the goal keeps going.
#[test]
fn a_headless_goal_answer_with_budget_left_is_a_success() {
    let (result, status) = goal_answer_spends_budget("p195-goal-budget-left", 1_000_000, true);
    let ok = result.unwrap_or_else(|err| panic!("budget left, so the run succeeds: {err:?}"));
    assert_eq!(ok.stop_reason, acp::StopReason::EndTurn);
    assert_eq!(status, Some(GoalStatus::Active));
}

/// Counter-test: an interactive session is unchanged: the turn that spends the budget is still a success, and the goal
/// harness stops the goal at the turn's end.
#[test]
fn an_interactive_goal_answer_that_spends_the_token_budget_is_still_a_success() {
    let (result, _status) = goal_answer_spends_budget("p195-goal-budget-interactive", 10, false);
    let ok = result.unwrap_or_else(|err| panic!("interactive turns are unchanged: {err:?}"));
    assert_eq!(ok.stop_reason, acp::StopReason::EndTurn);
}

/// P195 (K25): which goals count as "budget spent by this answer": only an ACTIVE goal with a budget the session's spend has
/// reached. A goal that is complete, paused or without a budget, or whose budget has room, is not.
#[test]
fn only_an_active_goal_with_a_spent_token_budget_is_a_headless_denial() {
    block_on_session(|| {
        current_thread_local(async {
            let (gateway_tx, gateway_rx) =
                tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
            drain_gateway(gateway_rx);
            let (persistence_tx, persistence_rx) =
                tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
            spawn_persistence_stub(persistence_rx, || Ok(()));
            // The session has spent 100 tokens.
            let actor = create_test_actor(100, 256_000, 85, gateway_tx, persistence_tx).await;

            // No goal at all.
            assert!(actor.goal_budget_spent_denial().await.is_none(), "no goal");

            // An active goal with no budget, and one whose budget has room.
            start_goal(&actor, "p195-goal-none", None);
            assert!(actor.goal_budget_spent_denial().await.is_none(), "no budget");
            start_goal(&actor, "p195-goal-room", Some(1_000_000));
            assert!(actor.goal_budget_spent_denial().await.is_none(), "budget with room");
            assert_eq!(actor.goal_tracker.lock().status(), Some(GoalStatus::Active), "left active");

            // A goal that finished (the model completed it in this very turn) is not budget-limited.
            start_goal(&actor, "p195-goal-complete", Some(10));
            assert!(actor.goal_tracker.lock().complete(), "fixture: the goal completes");
            assert!(actor.goal_budget_spent_denial().await.is_none(), "complete goal");
            assert_eq!(actor.goal_tracker.lock().status(), Some(GoalStatus::Complete), "left complete");

            // An active goal whose budget the spend reached: the denial, and the goal stops budget-limited.
            start_goal(&actor, "p195-goal-spent", Some(10));
            let denial = actor
                .goal_budget_spent_denial()
                .await
                .expect("an active goal whose budget is spent");
            assert_eq!(denial.rule, ExecutionBudgetRule::TotalTokensExhausted);
            assert_eq!(denial.total_token_limit, Some(10));
            assert!(denial.total_tokens_used >= 10, "{denial:?}");
            assert_eq!(actor.goal_tracker.lock().status(), Some(GoalStatus::BudgetLimited));
            assert!(actor.goal_budget_spent_denial().await.is_none(), "already stopped: not active any more");
        });
    });
}
