//! MODELSPERF (E2E-MAC 1.0.32, defect 4): how long `/rewind` and the `/resume` picker take on the real agent path.
//!
//! Fixture: one session of 10 turns plus 49 other one-turn sessions in a home holding 50 sessions, over ACP against the
//! mock model, so no model call sits on any timed path. The steps are exactly what the pager sends: `fuigo/rewind/points`,
//! `fuigo/rewind/execute` (`force`, `conversation_only`), `fuigo/session/list` (cwd, limit 30, `allowRelax`), and
//! `session/load` of the session (the resume itself). Each is printed as `TIMING <name> <ms>` (run with `--nocapture`).
//! The only assertion is a catastrophic bound far above the 1 s target, so a load spike cannot make it flaky while a
//! return of a multi-second scan still fails it. One `#[test]` per binary (the harness env is process-global).
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{
    AutoApproveClient, RPC_TIMEOUT, connect_client, ext_method, new_session, prompt_turn, run_agent_test,
    spawn_agent_local_with_config,
};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_test_support::sse::chat_completion_script_exact;
use fuigo_test_support::{InferenceEndpoint, InferenceRequestMatcher, ScriptedResponse};
use serde_json::json;
use std::time::Instant;

const MODEL: &str = "test-model";
const OTHER_SESSIONS: usize = 49;
const TARGET_TURNS: usize = 10;
const CATASTROPHIC: std::time::Duration = std::time::Duration::from_secs(3);

fn agent_config() -> fuigo_shell::agent::config::Config {
    let mut config = fuigo_shell::agent::config::Config::default();
    config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
    config
}

macro_rules! timed {
    ($name:expr, $fut:expr) => {{
        let wall = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_micros();
        let (w0, t) = (wall(), Instant::now());
        let out = $fut.await;
        let el = t.elapsed();
        eprintln!("TIMING {} {} wall_us {w0} {}", $name, el.as_millis(), wall());
        assert!(el < CATASTROPHIC, "{} took {el:?}", $name);
        out
    }};
}

#[test]
fn rewind_and_resume_picker_timings() {
    run_agent_test(|cwd, mock| async move {
        let conn = connect_client(AutoApproveClient, "modelsperf", spawn_agent_local_with_config(agent_config()))
            .await
            .0;
        let mut turn = 0usize;
        let mut script = |mock: &fuigo_test_support::MockInferenceServer| {
            let step = mock.expect_response(
                format!("answer-{turn}"),
                InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
                ScriptedResponse::sse(chat_completion_script_exact(&format!("Answer {turn}."), MODEL)),
            );
            turn += 1;
            step
        };
        let t = Instant::now();
        for i in 0..OTHER_SESSIONS {
            let other_cwd = cwd.join(format!("proj-{i}"));
            std::fs::create_dir_all(&other_cwd).unwrap();
            let s = new_session(&conn, &other_cwd).await;
            let step = script(&mock);
            prompt_turn(&conn, &s, &format!("Other {i}.")).await;
            step.assert_satisfied();
        }
        eprintln!("TIMING fixture_{OTHER_SESSIONS}_other_sessions {}", t.elapsed().as_millis());
        let session = new_session(&conn, &cwd).await;
        for i in 0..TARGET_TURNS {
            let step = script(&mock);
            prompt_turn(&conn, &session, &format!("Prompt {i}.")).await;
            step.assert_satisfied();
        }

        let sid = session.to_string();
        let points = timed!("rewind_points", ext_method(&conn, "fuigo/rewind/points", json!({ "sessionId": sid })));
        assert!(points.to_string().contains("prompt_index"), "{points}");
        let list_params = json!({ "cwd": cwd.to_string_lossy(), "limit": 30, "headless": "exclude", "allowRelax": true });
        let list = timed!("session_list_cwd_picker", ext_method(&conn, "fuigo/session/list", list_params.clone()));
        assert!(list.to_string().contains(&sid), "the target session is listed: {list}");
        let _ = timed!("session_list_cwd_picker_2nd", ext_method(&conn, "fuigo/session/list", list_params));
        let _ = timed!(
            "session_list_all_workspaces",
            ext_method(&conn, "fuigo/session_summaries/workspace_list_recent", json!({ "limit": 50 }))
        );
        let rewound = timed!(
            "rewind_execute_conversation_only",
            ext_method(
                &conn,
                "fuigo/rewind/execute",
                json!({ "sessionId": sid, "targetPromptIndex": 6, "force": true, "mode": "conversation_only" })
            )
        );
        assert_eq!(rewound["success"], true, "{rewound}");
        let rewound = timed!(
            "rewind_execute_all",
            ext_method(
                &conn,
                "fuigo/rewind/execute",
                json!({ "sessionId": sid, "targetPromptIndex": 3, "force": true, "mode": "all" })
            )
        );
        assert_eq!(rewound["success"], true, "{rewound}");
        let loaded = timed!(
            "session_load_resume",
            tokio::time::timeout(
                RPC_TIMEOUT,
                conn.load_session(acp::LoadSessionRequest::new(session.clone(), cwd.clone()))
            )
        );
        loaded.expect("load_session timed out").expect("load_session failed");
    });
}
