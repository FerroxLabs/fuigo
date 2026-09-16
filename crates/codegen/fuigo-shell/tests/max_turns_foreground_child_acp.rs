//! `--max-turns N` with a FOREGROUND subagent: the parent still gets its N rounds and the flag's
//! own stop; the child inherits N and gets N rounds of its own.
//!
//! `dfd419a` made `--max-turns` stop the run instead of failing it with `-32603`, and pinned
//! that against a real turn loop (`max_turns_bound_tests`) - for a session with no children.
//! The round-3 audit probed the durable state machine and found the parent's mirror
//! (`Snapshot::max_tool_rounds` = N) was still charged for every round a foreground child took:
//! `subagent/spawn.rs` hands the child `Execution::for_prompt(parent…)`, `handle_request.rs`
//! grants it as non-optional (`optional = run_in_background || definition.background`), and
//! `Change::ChildTools` on a non-optional grant ran `Change::Tools` on the PARENT
//! (`execution_state.rs`). With N = 2: the parent's spawn round -> `tool_rounds = 1`; the child's
//! first round -> 2; the child's second round DENIED ("execution actions unavailable", `-32603
//! Tool execution admission not durable or finalizing` on the child prompt); and the parent's
//! next sampling round finalizing (`tool_rounds >= max_tool_rounds`) -> `-32603` for the parent
//! too. The documented flag failed the run whenever a foreground child ran.
//!
//! The semantics pinned here: **a child's rounds do not count against the parent's
//! `--max-turns`.** `docs/user-guide/14-headless-mode.md` says so of the counter family
//! (`num_turns` "counts main-agent model rounds … Subagent sampler calls do not increase it …
//! This is the same counter family as `--max-turns`"), the child inherits the bound for rounds
//! of its own (`resolve_subagent_max_turns`: "may tighten its parent's turn limit, but cannot
//! raise it"), and `prompt_turn_result.rs` already maps a child's own `MaxTurnsReached` to
//! `max turns reached (limit: N)`. A foreground child's actions remain the parent's liabilities
//! (pending on the parent's record until settled, `partial` on a receipt issued while they run);
//! only the round count moved.
//!
//! The script, all on `/v1/chat/completions` and all main-turn requests (they carry
//! `x-fuigo-turn-idx`, which the mock classifies as foreground; side calls do not and fall
//! through to echo mode), in the only order a blocking spawn allows:
//!
//! 1. parent, round 1 of 2: `spawn_subagent` (no `background`, so the parent waits);
//! 2. child, round 1 of 2: `todo_write`;
//! 3. child, round 2 of 2: `todo_write` - then the child reaches ITS bound and stops;
//! 4. parent, round 2 of 2: `todo_write` - then the parent reaches ITS bound and stops.
//!
//! Red on the pre-fix product at step 3 (the child's round is denied) and again at step 4 (the
//! parent is finalizing, so its tool call is rejected): the parent prompt comes back
//! `Err(-32603)`. Green: `StopReason::Cancelled` with `_meta.cancellationCategory =
//! "max_turns_reached"`, exactly four main-turn requests, every one of them with tools
//! advertised, and the child's stop reported to the parent as `max turns reached (limit: 2)`.
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{
    AutoApproveClient, RPC_TIMEOUT, connect_client, new_session, run_agent_test,
    spawn_agent_local_with_config,
};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_test_support::sse::chat_completions_reasoning_then_tool_call_events;
use fuigo_test_support::{
    InferenceEndpoint, InferenceExpectation, InferenceRequestMatcher, MockInferenceServer,
    ScriptedResponse,
};
use serde_json::{Value, json};

const MAX_TURNS: u32 = 2;
const CHILD_PROMPT: &str = "Record two todos, one per round, then stop (child).";
const TODO_ARGS: &str = r#"{"todos":[{"id":"t1","content":"poll","status":"completed"}]}"#;

fn tool_call(call_id: &str, name: &str, arguments: &str) -> ScriptedResponse {
    ScriptedResponse::sse(chat_completions_reasoning_then_tool_call_events(
        "poll",
        call_id,
        name,
        arguments,
        "test-model",
    ))
}

fn spawn_foreground_child() -> ScriptedResponse {
    let args = json!({
        "description": "max-turns foreground child",
        "prompt": CHILD_PROMPT,
        "subagent_type": "general-purpose",
    });
    tool_call("call_spawn", "spawn_subagent", &args.to_string())
}

fn todo_call(call_id: &str) -> ScriptedResponse {
    tool_call(call_id, "todo_write", TODO_ARGS)
}

/// One scripted main-turn reply. Expectations are claimed in registration order by every
/// request the mock classifies as foreground on the endpoint, so registering the four steps in
/// sequence is the whole script.
fn expect_foreground(
    mock: &MockInferenceServer,
    name: &str,
    response: ScriptedResponse,
) -> InferenceExpectation {
    mock.expect_response(
        name,
        InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
        response,
    )
}

fn tool_count(body: &Value) -> usize {
    body["tools"].as_array().map_or(0, Vec::len)
}

/// Every tool-role message in the request, as text, so the child's result can be found in the
/// parent's second request whatever the harness names the role or wraps the content in.
fn tool_results(body: &Value) -> Vec<String> {
    body["messages"]
        .as_array()
        .map(|messages| {
            messages
                .iter()
                .filter(|m| m["role"] == "tool")
                .map(|m| m["content"].to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn max_turns_with_a_foreground_child_stops_on_the_flag_for_both() {
    run_agent_test(|cwd, mock| async move {
        let mut config = fuigo_shell::agent::config::Config::default();
        // A model-generated title is one more request to the same mock; keep the stream to the
        // four main-turn requests the script names.
        config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
        config.cli_agent_overrides.max_turns = Some(MAX_TURNS);

        let steps = [
            expect_foreground(&mock, "parent-round-1-spawns-child", spawn_foreground_child()),
            expect_foreground(&mock, "child-round-1", todo_call("call_child_1")),
            expect_foreground(&mock, "child-round-2", todo_call("call_child_2")),
            expect_foreground(&mock, "parent-round-2", todo_call("call_parent_2")),
        ];

        let (conn, _) = connect_client(
            AutoApproveClient,
            "max-turns-foreground-child",
            spawn_agent_local_with_config(config),
        )
        .await;
        let session = new_session(&conn, &cwd).await;
        let response = tokio::time::timeout(
            RPC_TIMEOUT,
            conn.prompt(acp::PromptRequest::new(
                session.clone(),
                vec![acp::ContentBlock::Text(acp::TextContent::new(
                    "Spawn one foreground child, then record a todo.",
                ))],
            )),
        )
        .await
        .expect("parent prompt timed out");

        let response = response.unwrap_or_else(|error| {
            panic!(
                "--max-turns {MAX_TURNS} with a foreground child must stop the run, not fail \
                 the prompt: {error:?}\n{}",
                mock.request_log_summary()
            )
        });
        assert_eq!(
            response.stop_reason,
            acp::StopReason::Cancelled,
            "reaching the bound is the flag's own stop\n{}",
            mock.request_log_summary()
        );
        let category = response
            .meta
            .as_ref()
            .and_then(|meta| meta.get("cancellationCategory"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        assert_eq!(
            category.as_deref(),
            Some("max_turns_reached"),
            "the client is told which bound ended the run: {:?}",
            response.meta
        );

        for step in &steps {
            step.assert_satisfied();
        }
        let main_turn: Vec<Value> = mock
            .requests()
            .iter()
            .filter(|entry| {
                entry.path == "/v1/chat/completions" && entry.header("x-fuigo-turn-idx").is_some()
            })
            .filter_map(|entry| entry.body.clone())
            .collect();
        assert_eq!(
            main_turn.len(),
            4,
            "two parent rounds and two child rounds, nothing else: {}",
            mock.request_log_summary()
        );
        for (index, body) in main_turn.iter().enumerate() {
            assert!(
                tool_count(body) > 0,
                "main-turn request {} is inside a bound and must be able to act; tools = {}",
                index + 1,
                tool_count(body)
            );
        }
        assert!(
            main_turn
                .iter()
                .any(|body| body.to_string().contains(CHILD_PROMPT)),
            "no main-turn request from the child was observed\n{}",
            mock.request_log_summary()
        );

        // The parent's last request carries the child's result: the child reached ITS bound
        // cleanly, not a session error from a denied round.
        let parent_last = main_turn.last().expect("four requests");
        let results = tool_results(parent_last);
        assert!(
            results
                .iter()
                .any(|text| text.contains(&format!("max turns reached (limit: {MAX_TURNS})"))),
            "the child inheriting --max-turns {MAX_TURNS} stops on its own bound and reports \
             it; tool results seen by the parent: {results:?}"
        );
        assert!(
            !results.iter().any(|text| text.contains("Session error")
                || text.contains("not durable or finalizing")),
            "a child's round inside its bound was denied: {results:?}"
        );

        tokio::time::timeout(RPC_TIMEOUT, conn.close_session(acp::CloseSessionRequest::new(session)))
            .await
            .expect("close_session timed out")
            .expect("close_session");
    });
}
