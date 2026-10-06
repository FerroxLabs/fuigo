//! P44, process-isolated: a prompt the model-call limit (`FUIGO_MAX_MODEL_CALLS`) leaves no call for is
//! refused over real ACP as the typed budget denial `execution_model_call_limit`, not as a storage
//! failure; and (P144) the turn that spent the last call on its final answer reports the same denial on
//! its partial receipt.
//!
//! Before P44 the execution the turn opens for that prompt was refused with the plain "execution budget
//! exhausted", which the turn reported as `-32603` kind `session_storage` "Execution state could not be
//! made durable" -- a client was told its disk failed when a limit it set had simply run out.
//!
//! Its own binary because the limit is read once per process from the environment.
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{AutoApproveClient, RPC_TIMEOUT, connect_client, new_session, run_agent_test, spawn_agent_local_with_config};
use agent_client_protocol::{self as acp, Agent as _};
use serde_json::json;

fn prompt(session: &acp::SessionId, prompt_id: &str) -> acp::PromptRequest {
    acp::PromptRequest::new(session.clone(), vec![acp::ContentBlock::Text(acp::TextContent::new("Say ready."))])
        .meta(json!({ "promptId": prompt_id }).as_object().cloned())
}

#[test]
fn a_prompt_with_no_model_call_left_is_refused_as_the_model_call_limit() {
    // One test in this binary; set before the helper creates any worker threads.
    unsafe { std::env::set_var("FUIGO_MAX_MODEL_CALLS", "1") };
    run_agent_test(|cwd, mock| async move {
        let mut config = fuigo_shell::agent::config::Config::default();
        config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
        let (conn, _) = connect_client(AutoApproveClient, "execution-call-limit", spawn_agent_local_with_config(config)).await;
        let session = new_session(&conn, &cwd).await;

        // The first prompt spends the one call on its final answer: the limit inside a turn finalizes it
        // and ends it with a partial execution receipt. P144: the limit is what ended that turn, so the
        // receipt is also the typed model-call-limit denial (`fuigo -p` exits 3, B4), receipt fields kept.
        let first = tokio::time::timeout(RPC_TIMEOUT, conn.prompt(prompt(&session, "spends-the-call"))).await
            .expect("first prompt timed out");
        let receipt = first.expect_err("the call limit leaves the first turn's receipt partial");
        let receipt_wire = serde_json::to_value(&receipt).expect("serialize");
        assert_eq!(receipt_wire["data"]["error_kind"], "execution_incomplete", "{receipt_wire}");
        assert_eq!(receipt_wire["data"]["partial"], true, "{receipt_wire}");
        let first_denial = fuigo_shell::acp_error::ExecutionBudgetDenial::from_acp_error(&receipt)
            .unwrap_or_else(|| panic!("the finalized turn is the call limit's typed denial: {receipt_wire}"));
        assert_eq!(first_denial.rule, fuigo_shell::acp_error::ExecutionBudgetRule::ModelCallLimit, "{receipt_wire}");
        let budget = fuigo_sampler::execution_budget::process_budget().expect("valid limit").expect("a limit is set");
        assert_eq!(budget.remaining_calls(), Some(0), "precondition: the first prompt spent the only call");

        let requests_before = mock.requests().len();
        let refused = tokio::time::timeout(RPC_TIMEOUT, conn.prompt(prompt(&session, "no-call-left"))).await
            .expect("second prompt timed out")
            .expect_err("no model call is left, so the prompt is refused");
        assert_eq!(mock.requests().len(), requests_before, "refused before anything reached the model");

        let wire = serde_json::to_value(&refused).expect("serialize");
        assert_eq!(wire["code"], -32603, "{wire}");
        assert_eq!(wire["data"]["error_kind"], "execution_incomplete", "not `session_storage`: {wire}");
        assert_eq!(wire["data"]["code"], fuigo_shell::acp_error::EXECUTION_BUDGET_DENIED_CODE, "{wire}");
        assert_eq!(wire["data"]["rule"], "execution_model_call_limit", "{wire}");
        let denial = fuigo_shell::acp_error::ExecutionBudgetDenial::from_acp_error(&refused).expect("typed denial");
        assert_eq!(denial.rule, fuigo_shell::acp_error::ExecutionBudgetRule::ModelCallLimit);
        assert_eq!(wire["data"]["remedy"], denial.rule.remedy(), "{wire}");
    });
}
