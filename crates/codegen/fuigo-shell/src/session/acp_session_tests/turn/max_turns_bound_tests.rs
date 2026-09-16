//! `--max-turns N` against a real turn loop: N tool rounds, then the flag's own stop.
//!
//! `--max-turns` is a documented headless flag (`fuigo-pager/docs/user-guide/14-headless-mode.md`,
//! `fuigo-shell/README.md`: "Maximum number of agentic turns before stopping") whose unit is a
//! tool-use cycle (`fuigo-shell/changelogs/0.2.12.md`: "`--max-turns` now correctly counts tool-use
//! cycles instead of total messages"). `clap` rejects anything below `1` (`app/cli.rs`,
//! `value_parser!(u32).range(1..)`) and `spawn.rs` refuses `max_turns == Some(0)`, so
//! `--max-turns 1` is the smallest run a user can ask for and it must still be able to call a tool.
//!
//! **The stop it produces is not an error.** Reaching the bound returns
//! `TurnOutcome::MaxTurnsReached`, which the prompt response carries as
//! `MAX_TURNS_REACHED_CATEGORY` and headless renders as the `error_max_turns` subtype
//! (`fuigo-pager/src/headless.rs`'s `is_max_turns`). Bounded execution (`a7a17ff`) briefly made
//! that path unreachable by finalizing the turn at `tool_turn_count >= limit`: the last round
//! became a reserved final-answer slot, and *both* ways out of that slot failed the whole prompt
//! with `-32603` - the receipt-carrying "Execution stopped with bounded capacity" error when the
//! model answered, and "Tool call rejected during finalization" when it called a tool (which the
//! OpenAI-Responses profile cannot prevent: it keeps `tools` byte-identical for the prompt cache
//! and steers with `tool_choice`). Every one of these tests fails on that shape.
//!
//! The turn loop and the durable execution record each carry their own copy of the limit
//! (`acp_session_impl/turn.rs`'s `tool_turn_count` versus `execution_state::Snapshot::tool_rounds`)
//! and the two step together, so both halves are pinned: the tests read the model-facing request
//! stream, not just the outcome, because a bound one tighter on either side silently costs the
//! user a round they paid for and a looser one lets the model act past the flag. The durable half
//! is only pinned because every test here runs under its OWN session id (see below): the loop
//! reaches its record through `Execution::for_prompt(session_id, prompt_id)`, and a test whose
//! record was evicted by a concurrent test runs with no record at all - no mirror, no admission -
//! which is the shape the broken product passed.
//!
//! The mock-sampler actor, the prompt driver and the persistence stub are shared with
//! [`super::disk_full_tests`] rather than duplicated, the way `transient_retry_loop_tests` shares
//! `rate_limit_backoff_tests`'s harness.
//!
//! Every test uses its own session id AND prompt id (the same string does for both).
//! `Execution::open` keys a process-global registry (`CURRENT`) by session id and stores the
//! record under `(session_id, root_id)`; `create_test_actor` would hand every test `test-actor`,
//! under which (a) two tests sharing a prompt id have the second adopt the first's already-dropped
//! persistence channel ("Execution state unavailable"), and (b) - worse, because it is silent -
//! two tests running at once have the later `open` evict the earlier test's record from
//! `CURRENT`, so that test's turn loop resolves `execution = None` and its bound is never
//! enforced by the record it thinks it is pinning. Under (b) two of these three tests passed on
//! the pre-fix product in every `--test-threads=16` run; they were only red one at a time.
//! `actor_with_mock_sampler` therefore takes the session id and each test names its own.

use super::disk_full_tests::{
    TODO_ARGS, actor_with_mock_sampler, block_on_session, current_thread_local, run_prompt,
    spawn_persistence_stub,
};
use super::support::*;
use super::*;
use fuigo_test_support::sse::{
    responses_api_reasoning_then_tool_call_events, responses_api_script_exact,
};
use fuigo_test_support::{MockInferenceServer, ScriptedResponse};

fn todo_call_sse(call_id: &str) -> ScriptedResponse {
    ScriptedResponse::sse(responses_api_reasoning_then_tool_call_events(
        "poll",
        call_id,
        "todo_write",
        TODO_ARGS,
        "test",
    ))
}

fn text_sse() -> ScriptedResponse {
    ScriptedResponse::sse(responses_api_script_exact("done", "test"))
}

struct BoundedRun {
    result: Result<crate::session::commands::PromptTurnOk, acp::Error>,
    /// How many tools each `/v1/responses` request advertised, in arrival order.
    advertised_tools: Vec<usize>,
}

/// Drives one turn under `--max-turns limit` against a model scripted reply by reply.
///
/// The replies are served in order. A run that stops where it should never reaches the last one,
/// so a script longer than the bound is how a test proves the bound held.
///
/// `flush` is what the turn-end fsync barrier returns (see `spawn_persistence_stub`); every other
/// persistence message is served for real. `run_id` names both the session and the prompt.
fn run_bounded_turn(
    limit: usize,
    run_id: &'static str,
    replies: Vec<ScriptedResponse>,
    flush: fn() -> std::io::Result<()>,
) -> BoundedRun {
    let cell = std::sync::Arc::new(std::sync::Mutex::new(None));
    let sink = cell.clone();
    block_on_session(move || {
        current_thread_local(async move {
            let server = MockInferenceServer::start()
                .await
                .expect("mock inference server");
            for reply in replies {
                server.enqueue_response("/v1/responses", reply);
            }

            let (gateway_tx, gateway_rx) =
                tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
            drain_gateway(gateway_rx);
            let (persistence_tx, persistence_rx) =
                tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
            spawn_persistence_stub(persistence_rx, flush);

            let actor = actor_with_mock_sampler(
                &server,
                run_id,
                persistence_tx,
                gateway_tx,
                Some(limit),
                /* permission_gateway */ None,
            )
            .await;
            let result = run_prompt(&actor, run_id).await;
            // `Execution::open` leaves the record in the process-global registry keyed by session
            // id. A live session wants that - `side_call.rs` reaches for `Execution::current` to
            // admit recaps and side questions - but a finished test must not leave one behind:
            // the ids here are unique, so nothing else would collide with it, but the registry
            // only prunes entries whose persistence channel is gone at the next `open`, and a
            // test's leftovers are not another test's to clean up.
            let session_id = actor.session_info.id.to_string();
            if let Some(execution) =
                crate::session::execution_state::Execution::current(&session_id)
            {
                execution.release(&session_id);
            }
            let advertised_tools = server
                .requests()
                .iter()
                .filter(|entry| entry.path == "/v1/responses")
                .map(|entry| {
                    entry
                        .body
                        .as_ref()
                        .and_then(|body| body.get("tools"))
                        .and_then(|tools| tools.as_array())
                        .map_or(0, Vec::len)
                })
                .collect();
            *sink.lock().unwrap() = Some(BoundedRun {
                result,
                advertised_tools,
            });
        });
    });
    let taken = cell.lock().unwrap().take();
    taken.expect("bounded turn produced a result")
}

/// A model that keeps calling tools gets exactly `limit` rounds, every one of them able to act,
/// and then the flag's own stop - never a `-32603`.
fn assert_spends_every_round_then_stops_on_the_flag(
    limit: usize,
    run_id: &'static str,
    flush: fn() -> std::io::Result<()>,
) {
    let run = run_bounded_turn(
        limit,
        run_id,
        // One more reply than the bound allows: if the loop took it, the round count below fails.
        (1..=limit + 1)
            .map(|i| todo_call_sse(&format!("bounded-{i}")))
            .collect(),
        flush,
    );
    let ok = run.result.as_ref().unwrap_or_else(|e| {
        panic!("--max-turns {limit} must stop the run, not fail the prompt: {e:?}")
    });
    assert_eq!(
        ok.stop_reason,
        acp::StopReason::Cancelled,
        "hitting the bound stops the run, as `MaxTurnsReached` has always reported it"
    );
    assert!(
        matches!(
            ok.completion_kind,
            crate::session::commands::PromptCompletionKind::MaxTurnsReached { limit: reported }
                if reported == limit
        ),
        "the client is told which bound ended the run, not that the agent failed: {:?}",
        ok.completion_kind
    );
    assert_eq!(
        run.advertised_tools.len(),
        limit,
        "--max-turns {limit} buys {limit} tool rounds, got {:?}",
        run.advertised_tools
    );
    for (round, advertised) in run.advertised_tools.iter().enumerate() {
        assert!(
            *advertised > 0,
            "round {} of {limit} is inside the limit and must still be able to act; \
             advertised {:?}",
            round + 1,
            run.advertised_tools
        );
    }
}

/// The documented minimum. `--max-turns 1` must still buy one tool-use cycle.
#[test]
fn max_turns_one_runs_one_tool_round_then_stops_on_the_flag() {
    assert_spends_every_round_then_stops_on_the_flag(1, "max-turns-one-acts", || Ok(()));
}

/// The same bound one step up, so neither test can pass on a hard-coded round count.
#[test]
fn max_turns_two_runs_two_tool_rounds_then_stops_on_the_flag() {
    assert_spends_every_round_then_stops_on_the_flag(2, "max-turns-two-acts", || Ok(()));
}

/// The flag's stop survives a turn-end flush that fails with ENOSPC. `handle_turn_input` may
/// rewrite only a `Completed`/`StationarityEnded` outcome into "No space left on device"; a
/// `MaxTurnsReached` stop is reported as the stop it is, so a caller that asked for a bound is
/// told the bound was hit, not that the disk is full. This was what
/// `cancelled_turn_flush_enospc_still_reports_cancellation` pinned before its driver became a
/// permission cancel; the max-turns + ENOSPC pair is pinned here.
#[test]
fn max_turns_stop_survives_an_enospc_turn_end_flush() {
    assert_spends_every_round_then_stops_on_the_flag(1, "max-turns-one-acts-enospc", || {
        Err(std::io::Error::from(std::io::ErrorKind::StorageFull))
    });
}

/// A model that finishes inside the bound ends the turn normally. The bound is a ceiling, so
/// nothing about it may colour a run that never reached it - and while the last round was a
/// reserved final-answer slot, answering there was itself reported as a failure: the execution
/// receipt came back `partial`, and `handle_turn_input` turned a completed turn into
/// `-32603 {"reason": "Execution stopped with bounded capacity or unresolved work", ...}`.
#[test]
fn a_model_that_answers_inside_the_bound_completes_normally() {
    let run = run_bounded_turn(
        2,
        "max-turns-two-answers",
        vec![todo_call_sse("inside-1"), text_sse()],
        || Ok(()),
    );
    let ok = run.result.as_ref().unwrap_or_else(|e| {
        panic!("answering inside the bound is a completed turn, not a fault: {e:?}")
    });
    assert_eq!(ok.stop_reason, acp::StopReason::EndTurn);
    assert!(
        matches!(
            ok.completion_kind,
            crate::session::commands::PromptCompletionKind::Completed
        ),
        "the run ended because the model was done, not because a bound cut it off: {:?}",
        ok.completion_kind
    );
    assert_eq!(
        run.advertised_tools.len(),
        2,
        "one tool round and the answer, both inside the bound; advertised {:?}",
        run.advertised_tools
    );
    assert!(
        run.advertised_tools.iter().all(|advertised| *advertised > 0),
        "a run inside the bound never has its tools taken away; advertised {:?}",
        run.advertised_tools
    );
}
