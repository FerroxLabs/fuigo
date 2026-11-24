//! mem3 review M1 (1.0.47): a cold `session/load` of a legacy session whose `chat_history.jsonl` still holds a recorded
//! secret rewrites the history scrubbed. F5 skips a history rewrite whose bytes equal the file; it must compare the
//! at-rest form (S2), or the raw secret round-trips byte-identical, the rewrite is skipped and the secret stays.
//!
//! One `#[test]` per binary (the harness env is process-global).
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{
    RPC_TIMEOUT, connect_client, ext_method, new_session, prompt_turn, run_agent_test,
    spawn_agent_local_with_config,
};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_shell::session::info::Info;
use fuigo_test_support::sse::chat_completion_script_exact;
use fuigo_test_support::{InferenceEndpoint, InferenceRequestMatcher, ScriptedResponse};
use serde_json::json;
use std::path::{Path, PathBuf};

const MODEL: &str = "test-model";
const TOKEN: &str = concat!("legacyTok", "Q7vX2mK9pZ4w");

fn agent_config() -> fuigo_shell::agent::config::Config {
    let mut config = fuigo_shell::agent::config::Config::default();
    config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
    config
}

async fn connect(label: &str) -> acp::ClientSideConnection {
    connect_client(
        acp_harness::AutoApproveClient,
        label,
        spawn_agent_local_with_config(agent_config()),
    )
    .await
    .0
}

fn foreground() -> InferenceRequestMatcher {
    InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions)
}

fn session_dir(session: &acp::SessionId, cwd: &Path) -> PathBuf {
    fuigo_shell::session::persistence::session_dir(&Info {
        id: session.clone(),
        cwd: cwd.to_string_lossy().into_owned(),
    })
}

/// Ends `session` in the agent that built it and waits until its actor released the session.
#[allow(
    clippy::disallowed_methods,
    reason = "test code: fixtures create files in a test FUIGO_HOME; no product session writer runs there"
)]
async fn close_and_release(conn: &acp::ClientSideConnection, session: &acp::SessionId, cwd: &Path) {
    ext_method(
        conn,
        "fuigo/session/close",
        json!({ "sessionId": session.to_string() }),
    )
    .await;
    let lock_path = session_dir(session, cwd).join("turn_owner.lock");
    let deadline = tokio::time::Instant::now() + RPC_TIMEOUT;
    loop {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .expect("open turn owner lock");
        if fs2::FileExt::try_lock_exclusive(&file).is_ok() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the builder's actor never released the session"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

fn holds_token(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read session dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            holds_token(&path, found);
        } else if std::fs::read(&path)
            .is_ok_and(|b| b.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()))
        {
            found.push(path);
        }
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "test code: plants a pre-S2 history in a test FUIGO_HOME while no session writer holds the session"
)]
#[test]
fn resume_scrubs_a_legacy_history_holding_a_recorded_secret() {
    run_agent_test(|cwd, mock| async move {
        let a = connect("m1-build").await;
        let session = new_session(&a, &cwd).await;
        let step = mock.expect_response(
            "m1-0",
            foreground(),
            ScriptedResponse::sse(chat_completion_script_exact("answer zero", MODEL)),
        );
        prompt_turn(&a, &session, "first prompt").await;
        step.assert_satisfied();
        close_and_release(&a, &session, &cwd).await;

        // A history written before S2 (or before the value was recorded): the secret sits raw in chat_history.jsonl.
        let dir = session_dir(&session, &cwd);
        let chat = dir.join("chat_history.jsonl");
        let text = std::fs::read_to_string(&chat).expect("read chat");
        assert!(
            text.contains("first prompt"),
            "the prompt is in the history"
        );
        std::fs::write(
            &chat,
            text.replace("first prompt", &format!("first prompt {TOKEN}")),
        )
        .expect("plant legacy history");
        fuigo_secrets::at_rest::record(TOKEN);

        let b = connect("m1-load").await;
        tokio::time::timeout(
            RPC_TIMEOUT * 3,
            b.load_session(acp::LoadSessionRequest::new(session.clone(), cwd.clone())),
        )
        .await
        .expect("session/load timed out")
        .expect("session/load failed");
        // The load's history rewrites run on the persistence actor; a later turn orders after them.
        let step = mock.expect_response(
            "m1-next",
            foreground(),
            ScriptedResponse::sse(chat_completion_script_exact("next", MODEL)),
        );
        prompt_turn(&b, &session, "and now?").await;
        step.assert_satisfied();
        close_and_release(&b, &session, &cwd).await;

        let mut found = Vec::new();
        holds_token(&dir, &mut found);
        assert!(
            found.is_empty(),
            "a resumed legacy session must leave no recorded secret on disk: {found:?}"
        );
    });
}
