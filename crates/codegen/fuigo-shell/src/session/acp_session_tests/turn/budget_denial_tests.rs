//! Contract D.4: a model request the execution's token-budget guard refuses ends the prompt with a
//! DENIAL the ACP client can read as data, not as a provider failure.
//!
//! Before P02e the guard (`execution_state::admit_attempt`) answered with an untyped `io::Error`, the
//! sampler boundary flattened it to `InvalidConfiguration("execution admission denied or could not be
//! persisted")`, and the prompt failed as a status-less `api` error -- indistinguishable from a provider
//! rejecting the request, and from a durable-state write failing. Nothing on the wire said "a budget
//! refused this", which rule, or what to change. The output-token variant of the same guard, caught one
//! step earlier in the turn loop, answered a second, different shape (`execution_incomplete` with a
//! bare sentence).
//!
//! These tests drive the real prompt path (`handle_prompt`, the same entry `session/prompt` takes) under
//! a durable execution whose budget is already spent, and assert the error the client receives.
//!
//! Every test names its own session and prompt id (see `max_turns_bound_tests` for why a shared id
//! silently evicts another test's execution record from the process-global registry).

use super::disk_full_tests::{
    actor_with_mock_sampler, actor_with_mock_sampler_configured, block_on_session, current_thread_local, run_prompt,
    spawn_persistence_stub,
};
use super::support::*;
use super::*;
use crate::acp_error::{EXECUTION_BUDGET_DENIED_CODE, ExecutionBudgetDenial, ExecutionBudgetRule};
use crate::session::execution_state::{Execution, TokenLimits};
use fuigo_sampling_types::{ExecutionAdmission, RequestPurpose, TokenUsage};
use fuigo_test_support::sse::responses_api_script_exact;
use fuigo_test_support::{MockInferenceServer, ScriptedResponse};

const ANSWER: &str = "the answer a budget-free turn would give";

/// How the execution's earlier work left its token budget before this prompt.
#[derive(Clone, Copy)]
enum Spent {
    /// An earlier request reported this usage (`total`, `output`).
    Reported(u32, u32),
    /// An earlier request reported no usage at all.
    Unknown,
}

struct BudgetedRun {
    result: Result<crate::session::commands::PromptTurnOk, acp::Error>,
    /// Requests that reached the model.
    model_requests: u32,
}

/// Open the durable execution the prompt will run under, spend `spent` of it, then run the prompt.
///
/// The turn's own `Execution::open` finds the record already registered under the same key
/// (`session_id`, `root_id` = the prompt id) and adopts it, which is exactly what happens when a
/// goal's next turn runs on an execution an earlier turn spent.
fn run_budgeted_prompt(run_id: &'static str, limits: TokenLimits, spent: Spent) -> BudgetedRun {
    let cell = std::sync::Arc::new(std::sync::Mutex::new(None));
    let sink = cell.clone();
    block_on_session(move || {
        current_thread_local(async move {
            let server = MockInferenceServer::start()
                .await
                .expect("mock inference server");
            // A turn the guard does NOT stop answers with this, so a refused prompt is attributable
            // to the guard and not to a missing script.
            server.enqueue_response(
                "/v1/responses",
                ScriptedResponse::sse(responses_api_script_exact(ANSWER, "test")),
            );
            let (gateway_tx, gateway_rx) =
                tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
            drain_gateway(gateway_rx);
            let (persistence_tx, persistence_rx) =
                tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
            spawn_persistence_stub(persistence_rx, || Ok(()));
            // `--max-turns` is what makes this a tracked execution with no goal and no workflow.
            let actor = actor_with_mock_sampler(
                &server,
                run_id,
                persistence_tx,
                gateway_tx,
                Some(4),
                /* permission_gateway */ None,
            )
            .await;

            let execution = Execution::open(
                &actor.notifications.persistence_tx,
                run_id,
                run_id,
                run_id,
                9,
                None,
                Some(4),
                limits,
                None,
            )
            .await
            .expect("execution is durable");
            let earlier = uuid::Uuid::new_v4().to_string();
            execution
                .admit(RequestPurpose::Work, earlier.clone())
                .await
                .expect("the earlier request was admitted");
            let usage = match spent {
                Spent::Reported(total, output) => Some(TokenUsage {
                    total_tokens: total,
                    completion_tokens: output,
                    ..Default::default()
                }),
                Spent::Unknown => None,
            };
            execution
                .settle(earlier, usage)
                .await
                .expect("the earlier request settled");
            let before = server.request_count();

            let result = run_prompt(&actor, run_id).await;

            let model_requests = server.request_count() - before;
            execution.release(run_id);
            *sink.lock().unwrap() = Some(BudgetedRun {
                result,
                model_requests,
            });
        });
    });
    let taken = cell.lock().unwrap().take();
    taken.expect("budgeted prompt produced a result")
}

/// The client-visible error of a refused prompt, asserted field by field on the wire form.
fn assert_budget_denial(run: &BudgetedRun, rule: ExecutionBudgetRule) -> ExecutionBudgetDenial {
    let err = match &run.result {
        Err(err) => err,
        Ok(ok) => panic!(
            "a spent budget must refuse the prompt, not answer it: {:?}",
            ok.stop_reason
        ),
    };
    let wire = serde_json::to_value(err).expect("serialize the ACP error");
    assert_eq!(wire["code"], -32603, "{wire}");
    let data = &wire["data"];
    assert_eq!(
        data["error_kind"], "execution_incomplete",
        "the kind a client already reads as 'a budget ran out': {wire}"
    );
    assert_eq!(
        data["code"], EXECUTION_BUDGET_DENIED_CODE,
        "the machine-readable mark of a denial: {wire}"
    );
    assert_eq!(data["rule"], rule.id(), "{wire}");
    assert_eq!(data["remedy"], rule.remedy(), "{wire}");
    assert_eq!(
        run.model_requests, 0,
        "a refused request is refused before transport: nothing reaches the model"
    );
    let denial = ExecutionBudgetDenial::from_acp_error(err)
        .unwrap_or_else(|| panic!("a client recovers the denial without reading prose: {wire}"));
    assert_eq!(denial.rule, rule);
    denial
}

/// A goal's total-token budget is spent: the admission guard refuses, and the prompt reports the
/// denial with its rule, its remedy and the figures.
#[test]
fn a_spent_total_token_budget_refuses_the_prompt_as_a_budget_denial() {
    let run = run_budgeted_prompt(
        "p02e-total-budget",
        TokenLimits {
            total: Some(100),
            output: None,
            initial_total: 0,
        },
        Spent::Reported(120, 30),
    );
    let denial = assert_budget_denial(&run, ExecutionBudgetRule::TotalTokensExhausted);
    assert_eq!(
        (denial.total_token_limit, denial.total_tokens_used),
        (Some(100), 120)
    );
}

/// Usage unknown under a token budget FAILS CLOSED (D.4's verified correction) -- with almost all of
/// the budget left -- and says so as its own rule rather than as "exhausted".
#[test]
fn unknown_usage_under_a_token_budget_refuses_the_prompt_as_a_budget_denial() {
    let run = run_budgeted_prompt(
        "p02e-unknown-usage",
        TokenLimits {
            total: Some(1_000_000),
            output: None,
            initial_total: 0,
        },
        Spent::Unknown,
    );
    let denial = assert_budget_denial(&run, ExecutionBudgetRule::TokenUsageUnknown);
    assert!(denial.unknown_usage);
    assert_eq!(denial.total_tokens_used, 0, "nothing reported, nothing counted");
}

/// The output-token budget is caught by the turn loop one step before admission; it reports as the
/// same denial, not as a second shape.
#[test]
fn a_spent_output_token_budget_refuses_the_prompt_as_the_same_denial() {
    let run = run_budgeted_prompt(
        "p02e-output-budget",
        TokenLimits {
            total: None,
            output: Some(40),
            initial_total: 0,
        },
        Spent::Reported(60, 40),
    );
    let denial = assert_budget_denial(&run, ExecutionBudgetRule::OutputTokensExhausted);
    assert_eq!(
        (denial.output_token_limit, denial.output_tokens_used),
        (Some(40), 40)
    );
}

/// The counter-test: the identical setup with room left in the budget answers normally. Without it the
/// denials above could be coming from anything in the fixture.
#[test]
fn the_same_prompt_with_budget_left_answers() {
    let run = run_budgeted_prompt(
        "p02e-budget-left",
        TokenLimits {
            total: Some(1_000_000),
            output: Some(1_000_000),
            initial_total: 0,
        },
        Spent::Reported(120, 30),
    );
    let ok = run
        .result
        .as_ref()
        .unwrap_or_else(|e| panic!("budget left, so the prompt must answer: {e:?}"));
    assert_eq!(ok.stop_reason, acp::StopReason::EndTurn);
    assert!(run.model_requests >= 1, "the answer came from the model");
}

/// `/btw` under the same spent execution: the side question is refused with the same typed denial,
/// and its refusal never lands on the turn's request (where `handle_sampling_failure` would report it
/// as the turn's outcome).
#[test]
fn a_side_question_under_a_spent_budget_is_refused_as_its_own_denial() {
    const RUN: &str = "p02e-btw-budget";
    block_on_session(|| {
        current_thread_local(async {
            let server = MockInferenceServer::start()
                .await
                .expect("mock inference server");
            server.set_response("a side answer");
            let (gateway_tx, gateway_rx) =
                tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
            drain_gateway(gateway_rx);
            let (persistence_tx, persistence_rx) =
                tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
            spawn_persistence_stub(persistence_rx, || Ok(()));
            let actor = actor_with_mock_sampler(
                &server, RUN, persistence_tx, gateway_tx, Some(4), None,
            )
            .await;
            let execution = Execution::open(
                &actor.notifications.persistence_tx, RUN, RUN, RUN, 9, None, Some(4),
                TokenLimits { total: Some(100), output: None, initial_total: 0 }, None,
            )
            .await
            .expect("execution is durable");
            let turn_request = execution.begin_turn_request();
            let earlier = uuid::Uuid::new_v4().to_string();
            execution.admit(RequestPurpose::Work, earlier.clone()).await.unwrap();
            execution
                .settle(earlier, Some(TokenUsage { total_tokens: 120, ..Default::default() }))
                .await
                .unwrap();
            let before = server.request_count();

            let err = actor
                .handle_side_question("what is left?", Vec::new())
                .await
                .expect_err("a spent budget refuses the side question");

            match &err {
                crate::session::SideQuestionError::BudgetDenied(denial) => {
                    assert_eq!(denial.rule, ExecutionBudgetRule::TotalTokensExhausted)
                }
                other => panic!("expected the typed budget denial, got {other:?}"),
            }
            assert_eq!(server.request_count(), before, "refused before transport");
            assert_eq!(
                turn_request.take_budget_denial(),
                None,
                "the side question's refusal is not the turn's request's"
            );
            assert_eq!(execution.take_turn_request_denial(), None);
            execution.release(RUN);
        });
    });
}

/// A workflow child whose real output grant (`task_output_token_budget`) is closed: the grant is checked
/// before the durable execution's mirror of it, and it reports the same typed denial -- not the
/// `internal` "workflow child output-token budget exhausted" it used to. A grant spent by reported
/// usage is `OutputTokensExhausted`; one closed because a request reported NO usage is
/// `TokenUsageUnknown`, whose remedy is about usage, not about raising the grant.
#[test]
fn a_workflow_child_with_its_output_grant_closed_is_refused_as_the_same_denial() {
    for (run, usage_unknown) in [("p02e-child-grant", false), ("p02e-child-grant-unknown", true)] {
        let cell = std::sync::Arc::new(std::sync::Mutex::new(None));
        let sink = cell.clone();
        block_on_session(move || {
            current_thread_local(async move {
                let server = MockInferenceServer::start()
                    .await
                    .expect("mock inference server");
                server.enqueue_response(
                    "/v1/responses",
                    ScriptedResponse::sse(responses_api_script_exact(ANSWER, "test")),
                );
                let (gateway_tx, gateway_rx) =
                    tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
                drain_gateway(gateway_rx);
                let (persistence_tx, persistence_rx) =
                    tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
                spawn_persistence_stub(persistence_rx, || Ok(()));
                let grant = crate::tools::tool_context::TaskOutputTokenBudget::limited(40);
                if usage_unknown {
                    grant.mark_incomplete_and_exhaust();
                } else {
                    grant.record_reported_output(40);
                }
                let actor = actor_with_mock_sampler_configured(
                    &server, run, persistence_tx, gateway_tx, None, None,
                    move |actor| actor.tool_context.task_output_token_budget = Some(grant),
                )
                .await;
                let before = server.request_count();
                let result = run_prompt(&actor, run).await;
                let model_requests = server.request_count() - before;
                if let Some(execution) = Execution::current(run) {
                    execution.release(run);
                }
                *sink.lock().unwrap() = Some(BudgetedRun { result, model_requests });
            });
        });
        let run_result = cell.lock().unwrap().take().expect("a result");
        if usage_unknown {
            let denial = assert_budget_denial(&run_result, ExecutionBudgetRule::TokenUsageUnknown);
            assert!(denial.unknown_usage, "{run}");
        } else {
            let denial = assert_budget_denial(&run_result, ExecutionBudgetRule::OutputTokensExhausted);
            assert_eq!(
                (denial.output_token_limit, denial.output_tokens_used, denial.unknown_usage),
                (Some(40), 40, false),
                "{run}"
            );
        }
    }
}
