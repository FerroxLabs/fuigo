//! P195 (K25), process-isolated: a `/btw` side question the sampler's process-wide model-call limit
//! (`FUIGO_MAX_MODEL_CALLS`) leaves no call for is refused over real ACP as the typed budget denial
//! `execution_model_call_limit`, the same denial a refused prompt gets, not as an `api` failure.
//!
//! Before P195 the turn path read the sampler's own refusal (`SamplingError::InvalidConfiguration(CALL_LIMIT)`)
//! as the denial (P44) but the side-question path did not: it came back as a status-less `api` error, which a
//! script cannot tell from a provider rejecting the request.
//!
//! Its own binary because the limit is read once per process from the environment.
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{AutoApproveClient, RPC_TIMEOUT, connect_client, new_session, run_agent_test, spawn_agent_local_with_config};
use agent_client_protocol::{self as acp, Agent as _};
use serde_json::json;

#[test]
fn a_side_question_with_no_model_call_left_is_refused_as_the_model_call_limit() {
    // One test in this binary; set before the helper creates any worker threads.
    unsafe { std::env::set_var("FUIGO_MAX_MODEL_CALLS", "1") };
    run_agent_test(|cwd, mock| async move {
        let mut config = fuigo_shell::agent::config::Config::default();
        config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
        let (conn, _) = connect_client(AutoApproveClient, "btw-call-limit", spawn_agent_local_with_config(config)).await;
        let session = new_session(&conn, &cwd).await;
        let budget = fuigo_sampler::execution_budget::process_budget().expect("valid limit").expect("a limit is set");
        assert_eq!(budget.remaining_calls(), Some(1), "precondition: nothing has used the one call");

        let btw = |question: &'static str| {
            let params = json!({"sessionId": session.to_string(), "question": question});
            let raw = serde_json::value::RawValue::from_string(params.to_string()).expect("serialize ext params");
            tokio::time::timeout(RPC_TIMEOUT, conn.ext_method(acp::ExtRequest::new("fuigo/btw", std::sync::Arc::from(raw))))
        };
        // Control: the first side question spends the one call, and is answered.
        btw("What is first?").await.expect("btw timed out").expect("the first side question has a call to spend");
        assert_eq!(budget.remaining_calls(), Some(0), "precondition: the first side question spent the call");

        let requests_before = mock.requests().len();
        let refused = btw("What is left?")
            .await
            .expect("btw timed out")
            .expect_err("no call is left, so the second side question is refused");
        assert_eq!(mock.requests().len(), requests_before, "refused before anything reached the model");

        let wire = serde_json::to_value(&refused).expect("serialize");
        assert_eq!(wire["code"], -32603, "{wire}");
        assert_eq!(wire["data"]["error_kind"], "execution_incomplete", "not `api`: {wire}");
        assert_eq!(wire["data"]["code"], fuigo_shell::acp_error::EXECUTION_BUDGET_DENIED_CODE, "{wire}");
        assert_eq!(wire["data"]["rule"], "execution_model_call_limit", "{wire}");
        let denial = fuigo_shell::acp_error::ExecutionBudgetDenial::from_acp_error(&refused).expect("typed denial");
        assert_eq!(denial.rule, fuigo_shell::acp_error::ExecutionBudgetRule::ModelCallLimit);
        assert_eq!(wire["data"]["remedy"], denial.rule.remedy(), "{wire}");
    });
}
