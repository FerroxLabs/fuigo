//! P44, process-isolated: a prompt sent after the runtime limit (`FUIGO_MAX_RUNTIME_SECS`) has passed is
//! refused over real ACP as the typed budget denial `execution_runtime_limit`.
//!
//! Before P44 the agent refused it as `-32602` kind `invalid_request` with the sampler's internal string
//! "execution budget: wall deadline exhausted" -- a client was told its request was malformed when a
//! limit it set had simply run out.
//!
//! Its own binary because the limit is read once per process from the environment.
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{AutoApproveClient, RPC_TIMEOUT, connect_client, new_session, run_agent_test, spawn_agent_local_with_config};
use agent_client_protocol::{self as acp, Agent as _};
use std::time::Duration;

#[test]
fn a_prompt_after_the_runtime_limit_is_refused_as_the_runtime_limit() {
    // One test in this binary; set before the helper creates any worker threads.
    unsafe { std::env::set_var("FUIGO_MAX_RUNTIME_SECS", "1") };
    run_agent_test(|cwd, mock| async move {
        let mut config = fuigo_shell::agent::config::Config::default();
        config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
        let (conn, _) = connect_client(AutoApproveClient, "execution-runtime-limit", spawn_agent_local_with_config(config)).await;
        let session = new_session(&conn, &cwd).await;

        // Wait for the limit itself, not for a guessed duration.
        let budget = fuigo_sampler::execution_budget::process_budget().expect("valid limit").expect("a limit is set");
        tokio::time::timeout(RPC_TIMEOUT, async {
            while !budget.expired() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }).await.expect("the runtime limit never passed");

        let requests_before = mock.requests().len();
        let refused = tokio::time::timeout(RPC_TIMEOUT, conn.prompt(acp::PromptRequest::new(
            session.clone(), vec![acp::ContentBlock::Text(acp::TextContent::new("Say ready."))],
        ))).await
            .expect("prompt timed out")
            .expect_err("the runtime limit has passed, so the prompt is refused");
        assert_eq!(mock.requests().len(), requests_before, "refused before anything reached the model");

        let wire = serde_json::to_value(&refused).expect("serialize");
        assert_eq!(wire["code"], -32603, "not `-32602 invalid params`: {wire}");
        assert_eq!(wire["data"]["error_kind"], "execution_incomplete", "{wire}");
        assert_eq!(wire["data"]["code"], fuigo_shell::acp_error::EXECUTION_BUDGET_DENIED_CODE, "{wire}");
        assert_eq!(wire["data"]["rule"], "execution_runtime_limit", "{wire}");
        let denial = fuigo_shell::acp_error::ExecutionBudgetDenial::from_acp_error(&refused).expect("typed denial");
        assert_eq!(denial.rule, fuigo_shell::acp_error::ExecutionBudgetRule::RuntimeLimit);
        assert_eq!(wire["data"]["remedy"], denial.rule.remedy(), "{wire}");
    });
}
