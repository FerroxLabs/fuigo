//! P44: a model request refused by the model-call limit (`FUIGO_MAX_MODEL_CALLS`) or the runtime limit
//! (`FUIGO_MAX_RUNTIME_SECS`) ends the prompt with the same typed DENIAL a token budget produces (P02e,
//! Contract D.4), not as a provider failure.
//!
//! Before P44 the durable execution refused these with plain messages ("execution is terminal or
//! expired", "execution completion capacity reserved", "child grant exhausted"), the sampler boundary
//! flattened them to `InvalidConfiguration("execution admission denied or could not be persisted")`,
//! and the prompt failed as a status-less `api` error. The sampler's own process-wide refusals
//! (`execution_budget::CALL_LIMIT` / `WALL_LIMIT`) arrived the same way. A script could not tell any of
//! them from a provider rejecting the request.
//!
//! The durable refusals are driven through the real prompt path (`handle_prompt`) under an execution
//! whose limit is already reached. The sampler's process-wide refusals cannot be: the process budget
//! is a process-global read once from the environment, so this test binary cannot set it without
//! changing every other test in it, and under it the durable mirror refuses first anyway. Those are
//! driven through `handle_sampling_failure` with the exact error the sampler produces; the agent-level
//! and execution-open refusals, which do need the environment, are pinned by their own test binaries
//! (`tests/execution_limit_call_acp.rs`, `tests/execution_limit_runtime_acp.rs`).
//!
//! Every test names its own session and prompt ids (see `max_turns_bound_tests` for why a shared id
//! silently evicts another test's execution record from the process-global registry).

use super::disk_full_tests::{
    actor_with_mock_sampler, block_on_session, current_thread_local, run_prompt, spawn_persistence_stub,
};
use super::support::*;
use super::*;
use crate::acp_error::{EXECUTION_BUDGET_DENIED_CODE, ExecutionBudgetDenial, ExecutionBudgetRule};
use crate::session::execution_state::{Execution, TokenLimits};
use fuigo_sampling_types::{ExecutionAdmission, RequestPurpose, TokenUsage};
use fuigo_test_support::sse::responses_api_script_exact;
use fuigo_test_support::{MockInferenceServer, ScriptedResponse};

const ANSWER: &str = "the answer a turn with room left would give";

struct LimitedRun {
    result: Result<crate::session::commands::PromptTurnOk, acp::Error>,
    /// Requests that reached the model.
    model_requests: u32,
}

/// The client-visible error of a refused prompt, asserted field by field on the wire form.
fn assert_limit_denial(run: &LimitedRun, rule: ExecutionBudgetRule) -> ExecutionBudgetDenial {
    let err = match &run.result {
        Err(err) => err,
        Ok(ok) => panic!(
            "a reached limit must refuse the prompt, not answer it: {:?}",
            ok.stop_reason
        ),
    };
    let denial = assert_denial_wire(err, rule);
    assert_eq!(
        run.model_requests, 0,
        "a refused request is refused before transport: nothing reaches the model"
    );
    denial
}

fn assert_denial_wire(err: &acp::Error, rule: ExecutionBudgetRule) -> ExecutionBudgetDenial {
    let wire = serde_json::to_value(err).expect("serialize the ACP error");
    assert_eq!(wire["code"], -32603, "{wire}");
    let data = &wire["data"];
    assert_eq!(
        data["error_kind"], "execution_incomplete",
        "the kind a client already reads as 'a budget ran out', not `api`: {wire}"
    );
    assert_eq!(
        data["code"], EXECUTION_BUDGET_DENIED_CODE,
        "the machine-readable mark of a denial: {wire}"
    );
    assert_eq!(data["rule"], rule.id(), "{wire}");
    assert_eq!(data["remedy"], rule.remedy(), "{wire}");
    assert!(
        data["message"].as_str().is_some_and(|m| m.contains(rule.id())),
        "the human line names the rule: {wire}"
    );
    let denial = ExecutionBudgetDenial::from_acp_error(err)
        .unwrap_or_else(|| panic!("a client recovers the denial without reading prose: {wire}"));
    assert_eq!(denial.rule, rule);
    denial
}

/// The runtime limit, as the durable execution records it: an execution whose deadline has passed
/// refuses the turn's request, and the prompt reports `execution_runtime_limit`.
#[test]
fn an_expired_execution_deadline_refuses_the_prompt_as_a_runtime_limit_denial() {
    const RUN: &str = "p44-deadline";
    let cell = std::sync::Arc::new(std::sync::Mutex::new(None));
    let sink = cell.clone();
    block_on_session(move || {
        current_thread_local(async move {
            let server = MockInferenceServer::start()
                .await
                .expect("mock inference server");
            // A turn the limit does NOT stop answers with this, so a refused prompt is attributable
            // to the limit and not to a missing script.
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
            let actor =
                actor_with_mock_sampler(&server, RUN, persistence_tx, gateway_tx, Some(4), None)
                    .await;
            // The deadline the execution recorded from `FUIGO_MAX_RUNTIME_SECS` when it opened, now past.
            let past = chrono::Utc::now().timestamp_millis() - 60_000;
            let execution = Execution::open(
                &actor.notifications.persistence_tx,
                RUN,
                RUN,
                RUN,
                9,
                Some(past),
                Some(4),
                TokenLimits::default(),
                None,
            )
            .await
            .expect("execution is durable");
            let before = server.request_count();

            let result = run_prompt(&actor, RUN).await;

            let model_requests = server.request_count() - before;
            execution.release(RUN);
            *sink.lock().unwrap() = Some(LimitedRun {
                result,
                model_requests,
            });
        });
    });
    let run = cell.lock().unwrap().take().expect("a result");
    let denial = assert_limit_denial(&run, ExecutionBudgetRule::RuntimeLimit);
    assert_eq!(
        (denial.total_token_limit, denial.unknown_usage),
        (None, false),
        "no token budget is involved"
    );
}

/// How the parent's call limit was spent before the child's prompt.
#[derive(Clone, Copy)]
enum ParentCalls {
    /// The child spent its whole grant (the child's share of the parent's call limit).
    GrantSpent,
    /// The parent spent its own calls until only the one reserved for its final answer is left; the
    /// child's grant still has room.
    OnlyFinalCallLeft,
    /// Room left everywhere: the counter-test.
    RoomLeft,
}

/// A workflow child (subagent) runs under a durable grant of its parent's model-call limit. Open the
/// parent with `parent_max_calls`, grant the child, spend calls as `spent` says, then run the child's
/// prompt through `handle_prompt`.
fn run_child_prompt(run: &'static str, parent_max_calls: u64, spent: ParentCalls) -> LimitedRun {
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
            let actor =
                actor_with_mock_sampler(&server, run, persistence_tx, gateway_tx, Some(4), None)
                    .await;
            let tx = &actor.notifications.persistence_tx;
            let parent_session = format!("{run}-parent");
            let parent = Execution::open(
                tx,
                &parent_session,
                &parent_session,
                &parent_session,
                parent_max_calls,
                None,
                None,
                TokenLimits::default(),
                None,
            )
            .await
            .expect("parent execution is durable");
            let grant = parent
                .grant_child(run, None, false)
                .await
                .expect("the parent grants the child");
            // The child's own record, under the key the child's turn adopts (session = root = prompt id).
            let child = Execution::open(
                tx,
                run,
                run,
                run,
                9,
                None,
                Some(4),
                TokenLimits::default(),
                Some(grant),
            )
            .await
            .expect("child execution is durable");
            let spend = |admission: std::sync::Arc<Execution>| async move {
                let attempt = uuid::Uuid::new_v4().to_string();
                admission
                    .admit(RequestPurpose::Work, attempt.clone())
                    .await
                    .expect("an earlier request was admitted");
                admission
                    .settle(attempt, Some(TokenUsage::default()))
                    .await
                    .expect("an earlier request settled");
            };
            match spent {
                ParentCalls::GrantSpent => {
                    spend(child.clone()).await;
                    spend(child.clone()).await;
                }
                ParentCalls::OnlyFinalCallLeft => {
                    spend(parent.clone()).await;
                    spend(child.clone()).await;
                }
                ParentCalls::RoomLeft => spend(child.clone()).await,
            }
            let before = server.request_count();

            let result = run_prompt(&actor, run).await;

            let model_requests = server.request_count() - before;
            child.release(run);
            parent.release(&parent_session);
            *sink.lock().unwrap() = Some(LimitedRun {
                result,
                model_requests,
            });
        });
    });
    let taken = cell.lock().unwrap().take();
    taken.expect("child prompt produced a result")
}

/// The child spent its grant (parent limit 3: the grant is 2 calls, one being reserved for the
/// parent's final answer). Its next request is refused by the grant, and the child's prompt reports
/// `execution_model_call_limit`.
#[test]
fn a_childs_spent_call_grant_refuses_its_prompt_as_a_model_call_limit_denial() {
    let run = run_child_prompt("p44-grant-spent", 3, ParentCalls::GrantSpent);
    assert_limit_denial(&run, ExecutionBudgetRule::ModelCallLimit);
}

/// The grant has room, but the parent's own work left it only the call reserved for its final
/// answer: the parent's call limit refuses the child's request, as the same denial.
#[test]
fn a_parent_with_only_its_final_call_left_refuses_the_childs_prompt_as_a_model_call_limit_denial() {
    let run = run_child_prompt("p44-parent-final-call", 3, ParentCalls::OnlyFinalCallLeft);
    assert_limit_denial(&run, ExecutionBudgetRule::ModelCallLimit);
}

/// The counter-test: the identical child setup with calls left answers normally. Without it the
/// denials above could be coming from anything in the fixture.
#[test]
fn the_same_child_prompt_with_calls_left_answers() {
    let run = run_child_prompt("p44-calls-left", 9, ParentCalls::RoomLeft);
    let ok = run
        .result
        .as_ref()
        .unwrap_or_else(|e| panic!("calls left, so the child's prompt must answer: {e:?}"));
    assert_eq!(ok.stop_reason, acp::StopReason::EndTurn);
    assert!(run.model_requests >= 1, "the answer came from the model");
}

/// The sampler's own process-wide limits (`FUIGO_MAX_MODEL_CALLS`, `FUIGO_MAX_RUNTIME_SECS`): the turn's
/// request fails with exactly the error the sampler's process budget produces, and the turn ends with
/// that limit's denial instead of the status-less `api` failure. Any other status-less configuration
/// failure -- the durable admission's own string included -- is still not a denial.
#[tokio::test(flavor = "current_thread")]
async fn a_process_limit_refusal_ends_the_turn_as_that_limits_denial() {
    use fuigo_sampler::execution_budget::{CALL_LIMIT, WALL_LIMIT};
    use fuigo_sampling_types::SamplingError;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (gateway_tx, _) = tokio::sync::mpsc::unbounded_channel();
            let (persistence_tx, _persistence_rx) = tokio::sync::mpsc::unbounded_channel();
            let mut actor = create_test_actor(50_000, 100_000, 85, gateway_tx, persistence_tx).await;
            actor.session_info.id = acp::SessionId::new("p44-process-limit");
            let actor = std::sync::Arc::new(actor);
            let fail = |error: SamplingError| {
                let actor = actor.clone();
                async move {
                    actor
                        .handle_sampling_failure(
                            fuigo_sampler::SamplingErrorInfo::from(&error),
                            0,
                            transient_state(0, true),
                            false,
                            crate::session::acp_session::TurnParkState::Fresh,
                        )
                        .await
                }
            };
            for (limit, rule) in [
                (CALL_LIMIT, ExecutionBudgetRule::ModelCallLimit),
                (WALL_LIMIT, ExecutionBudgetRule::RuntimeLimit),
            ] {
                let err = match fail(SamplingError::InvalidConfiguration(limit)).await {
                    Err(err) => err,
                    Ok(_) => panic!("a process-limit refusal must end the turn: {limit}"),
                };
                let denial = assert_denial_wire(&err, rule);
                assert_eq!(
                    denial,
                    ExecutionBudgetDenial::without_token_figures(rule),
                    "no execution is current, so there are no token figures to report"
                );
            }
            for other in [
                "execution admission denied or could not be persisted",
                "execution budget limits must be positive integers",
            ] {
                if let Err(err) = fail(SamplingError::InvalidConfiguration(other)).await {
                    assert!(
                        !ExecutionBudgetDenial::is_budget_denial(&err),
                        "`{other}` is not a limit refusal: {err:?}"
                    );
                }
            }
        })
        .await;
}

/// P144 (Astra r1): the model-call limit reserved the turn's last call for the final answer, the model
/// answered, and a Stop hook then kept the turn working. The continuation finds the execution already
/// finalized and ends the prompt there. That limit ended the run, so the prompt fails with its typed
/// denial (`fuigo -p` exits 3, B4), the receipt fields kept, not with an untyped receipt (exit 1).
#[test]
fn a_stop_hook_continuation_after_the_reserved_answer_is_the_call_limit_denial() {
    const RUN: &str = "p144-stop-continuation";
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
            let actor = super::disk_full_tests::actor_with_mock_sampler_configured(
                &server,
                RUN,
                persistence_tx,
                gateway_tx,
                Some(4),
                None,
                |actor| {
                    actor.hook_resolved_workspace_root = "/tmp".to_string();
                    *actor.hook_registry.borrow_mut() = Some(std::sync::Arc::new(
                        crate::session::acp_session::client_hooks_tests::file_registry_with_spec(
                            fuigo_hooks::event::HookEventName::Stop,
                            r#"echo '{"decision":"block","reason":"keep going"}'"#,
                        ),
                    ));
                },
            )
            .await;
            // One model call: the turn loop reserves it for the final answer from the start.
            let execution = Execution::open(
                &actor.notifications.persistence_tx,
                RUN,
                RUN,
                RUN,
                1,
                None,
                Some(4),
                TokenLimits::default(),
                None,
            )
            .await
            .expect("execution is durable");
            let before = server.request_count();

            let result = run_prompt(&actor, RUN).await;

            let model_requests = server.request_count() - before;
            execution.release(RUN);
            *sink.lock().unwrap() = Some(LimitedRun {
                result,
                model_requests,
            });
        });
    });
    let run = cell.lock().unwrap().take().expect("a result");
    assert_eq!(run.model_requests, 1, "the reserved call answered; the continuation sent nothing");
    let err = match &run.result {
        Err(err) => err,
        Ok(ok) => panic!("the call limit ended this turn: {:?}", ok.stop_reason),
    };
    let wire = serde_json::to_value(err).expect("serialize");
    assert_eq!(wire["data"]["partial"], true, "the receipt is kept: {wire}");
    assert_denial_wire(err, ExecutionBudgetRule::ModelCallLimit);
}

/// P195 (K25): the model-call limit reserved the turn's last call for the final answer and the model answered, but the
/// agent's completion requirement (a tool that was never called) retries the turn. Each retry finds the execution
/// finalized and ends there. The FIRST such retry was already the call limit's typed denial (P144); a later one found the
/// record already terminal and ended as an untyped receipt, so a `maxRetries` of 2 or more turned `fuigo -p`'s exit 3
/// into exit 1. The turn must end with the typed denial however many retries the requirement allows, and never retry
/// once a budget has ended the run.
fn run_completion_requirement_retries(run: &'static str, max_retries: u32) -> LimitedRun {
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
            let actor =
                actor_with_mock_sampler(&server, run, persistence_tx, gateway_tx, Some(4), None).await;
            *actor.agent.borrow_mut() =
                test_agent_with_completion_requirement("never_called_tool", max_retries).await;
            // One model call: the turn loop reserves it for the final answer from the start.
            let execution = Execution::open(
                &actor.notifications.persistence_tx,
                run,
                run,
                run,
                1,
                None,
                Some(4),
                TokenLimits::default(),
                None,
            )
            .await
            .expect("execution is durable");
            let before = server.request_count();

            let result = run_prompt(&actor, run).await;

            let model_requests = server.request_count() - before;
            execution.release(run);
            *sink.lock().unwrap() = Some(LimitedRun {
                result,
                model_requests,
            });
        });
    });
    let taken = cell.lock().unwrap().take();
    taken.expect("a result")
}

fn assert_call_limit_denial_with_receipt(run: &LimitedRun) {
    assert_eq!(run.model_requests, 1, "the reserved call answered; no retry sent anything");
    let err = match &run.result {
        Err(err) => err,
        Ok(ok) => panic!("the call limit ended this turn: {:?}", ok.stop_reason),
    };
    let wire = serde_json::to_value(err).expect("serialize");
    assert_eq!(wire["data"]["partial"], true, "the receipt is kept: {wire}");
    assert_denial_wire(err, ExecutionBudgetRule::ModelCallLimit);
}

/// Control: one retry was already typed before P195.
#[test]
fn a_completion_requirement_with_one_retry_ends_as_the_call_limit_denial() {
    assert_call_limit_denial_with_receipt(&run_completion_requirement_retries("p195-retry-one", 1));
}

#[test]
fn a_completion_requirement_with_three_retries_ends_as_the_call_limit_denial() {
    assert_call_limit_denial_with_receipt(&run_completion_requirement_retries("p195-retry-three", 3));
}
