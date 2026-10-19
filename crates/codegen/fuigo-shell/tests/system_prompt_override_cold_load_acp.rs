//! P31 (#19) end to end: a session's `systemPromptOverride` must survive a cold reload that does not resend it.
//!
//! Real ACP path (`session/new` -> `session/load` in a fresh agent -> `session/set_model` -> `session/prompt`) against
//! the mock inference endpoint. The override is checked in the system message of the requests the model received, and
//! in `system_prompt_override.txt` in the session directory. This covers the `spawn_session_actor` load of that file,
//! which the loader and model-switch unit tests do not reach.
#[allow(dead_code)]
mod acp_harness;
use acp_harness::{
    AutoApproveClient, RPC_TIMEOUT, connect_client, prompt_turn, run_agent_test,
    spawn_agent_local_with_config,
};
use agent_client_protocol::{self as acp, Agent as _};
use serde_json::{Value, json};

const SENTINEL: &str = "OVERRIDE-SENTINEL-P31-8841";
const SENTINEL_2: &str = "OVERRIDE-SENTINEL-P31-RESENT-5520";
const MARKER: &str = "<!-- session-rules -->";
const FILE: &str = "system_prompt_override.txt";

fn override_text(sentinel: &str) -> String {
    format!(
        "You are a custom agent. {sentinel}\n\n{MARKER}\n<human_rules>\nclient rule\n</human_rules>"
    )
}

fn agent_config() -> fuigo_shell::agent::config::Config {
    let mut config = fuigo_shell::agent::config::Config::default();
    config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
    config
}

fn meta(v: Value) -> Option<serde_json::Map<String, Value>> {
    v.as_object().cloned()
}

/// `{session dir}/system_prompt_override.txt`, found by session id under the isolated `FUIGO_HOME`.
fn override_file(session: &acp::SessionId) -> Option<std::path::PathBuf> {
    fn walk(dir: &std::path::Path, id: &str, out: &mut Option<std::path::PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n == id) {
                    *out = Some(p.clone());
                }
                walk(&p, id, out);
            }
        }
    }
    let home = std::path::PathBuf::from(std::env::var_os("FUIGO_HOME").expect("FUIGO_HOME"));
    let mut dir = None;
    walk(&home, &session.to_string(), &mut dir);
    let dir = dir.unwrap_or_else(|| panic!("no session dir for {session}"));
    Some(dir.join(FILE)).filter(|p| p.exists())
}

/// The system message(s) of the last chat-completions request after index `before`.
fn last_system(mock: &fuigo_test_support::MockInferenceServer, before: usize) -> (String, String) {
    let bodies: Vec<Value> = mock.requests()[before..]
        .iter()
        .filter(|r| r.path == "/v1/chat/completions")
        .filter_map(|r| {
            r.body
                .as_ref()
                .map(|b| serde_json::from_str(&b.to_string()).unwrap())
        })
        .collect();
    let last = bodies.last().expect("a model request");
    let system = last["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| matches!(m["role"].as_str(), Some("system" | "developer")))
        .map(|m| m["content"].to_string())
        .collect::<Vec<_>>()
        .join("\n");
    (last["model"].as_str().unwrap_or("").to_owned(), system)
}

async fn load(
    conn: &acp::ClientSideConnection,
    s: &acp::SessionId,
    cwd: &std::path::Path,
    m: Option<Value>,
) {
    let mut req = acp::LoadSessionRequest::new(s.clone(), cwd.to_path_buf());
    if let Some(m) = m {
        req = req.meta(meta(m));
    }
    tokio::time::timeout(RPC_TIMEOUT, conn.load_session(req))
        .await
        .expect("session/load timed out")
        .expect("session/load failed");
}

async fn switch(conn: &acp::ClientSideConnection, s: &acp::SessionId, model: &str) {
    tokio::time::timeout(
        RPC_TIMEOUT,
        conn.set_session_model(acp::SetSessionModelRequest::new(
            s.clone(),
            acp::ModelId::new(model),
        )),
    )
    .await
    .expect("set_model timed out")
    .expect("set_model failed");
}

async fn create(
    conn: &acp::ClientSideConnection,
    cwd: &std::path::Path,
    m: Value,
) -> acp::SessionId {
    tokio::time::timeout(
        RPC_TIMEOUT,
        conn.new_session(acp::NewSessionRequest::new(cwd.to_path_buf()).meta(meta(m))),
    )
    .await
    .expect("session/new timed out")
    .expect("session/new failed")
    .session_id
}

#[test]
fn override_survives_cold_load_and_model_switch() {
    run_agent_test(|cwd, mock| async move {
        mock.set_models(vec![
            fuigo_test_support::MockModelEntry::new("test-model"),
            fuigo_test_support::MockModelEntry::new("test-model-alternate"),
        ]);
        let (conn, _) = connect_client(
            AutoApproveClient,
            "override-1",
            spawn_agent_local_with_config(agent_config()),
        )
        .await;
        let with = create(
            &conn,
            &cwd,
            json!({"modelId": "test-model", "systemPromptOverride": override_text(SENTINEL)}),
        )
        .await;
        let without = create(
            &conn,
            &cwd,
            json!({"modelId": "test-model", "rules": "plain session rule"}),
        )
        .await;

        // Written when the override arrives on session/new; never written for a session without one.
        let before = mock.requests().len();
        prompt_turn(&conn, &with, "hello").await;
        let (_, sys) = last_system(&mock, before);
        assert!(
            sys.contains(SENTINEL),
            "new session ignored the override: {sys}"
        );
        let f = override_file(&with).expect("override file written on session/new");
        assert_eq!(std::fs::read_to_string(f).unwrap(), override_text(SENTINEL));

        let before = mock.requests().len();
        prompt_turn(&conn, &without, "hello").await;
        let (_, default_sys) = last_system(&mock, before);
        assert!(!default_sys.contains(SENTINEL));
        assert!(
            override_file(&without).is_none(),
            "no override must write no {FILE}"
        );
        drop(conn);

        // Fresh agent, cold load, override NOT resent, then a model switch.
        let (conn, _) = connect_client(
            AutoApproveClient,
            "override-2",
            spawn_agent_local_with_config(agent_config()),
        )
        .await;
        load(&conn, &with, &cwd, None).await;
        switch(&conn, &with, "test-model-alternate").await;
        let before = mock.requests().len();
        prompt_turn(&conn, &with, "after switch").await;
        let (model, sys) = last_system(&mock, before);
        assert_eq!(model, "test-model-alternate");
        assert!(
            sys.contains(SENTINEL),
            "cold load + switch lost the override: {sys}"
        );
        assert_eq!(
            sys.matches(MARKER).count(),
            1,
            "session-rules block must appear exactly once: {sys}"
        );
        assert_eq!(sys.matches("<human_rules>").count(), 1);

        // Same cold path for the session without an override: default template, one rules block, still no file.
        load(&conn, &without, &cwd, None).await;
        switch(&conn, &without, "test-model-alternate").await;
        let before = mock.requests().len();
        prompt_turn(&conn, &without, "after switch").await;
        let (_, sys) = last_system(&mock, before);
        assert!(!sys.contains(SENTINEL));
        assert_eq!(
            sys.matches(MARKER).count(),
            1,
            "rules block must appear exactly once: {sys}"
        );
        assert!(sys.contains("plain session rule"));
        let prefix: String = default_sys.chars().take(200).collect();
        assert!(
            sys.contains(&prefix),
            "default template changed across the cold load"
        );
        assert!(
            override_file(&without).is_none(),
            "loading must not create {FILE}"
        );

        // Resent on load: the file is rewritten and wins on the next switch.
        load(
            &conn,
            &with,
            &cwd,
            Some(json!({"systemPromptOverride": override_text(SENTINEL_2)})),
        )
        .await;
        prompt_turn(&conn, &with, "after resend").await;
        let f = override_file(&with).expect("override file after resend");
        assert_eq!(
            std::fs::read_to_string(&f).unwrap(),
            override_text(SENTINEL_2)
        );
        switch(&conn, &with, "test-model").await;
        let before = mock.requests().len();
        prompt_turn(&conn, &with, "after resend switch").await;
        let (_, sys) = last_system(&mock, before);
        assert!(sys.contains(SENTINEL_2) && !sys.contains(SENTINEL));

        // A blank override is "no override" by design (it can never blank the prompt): the file is left alone.
        load(
            &conn,
            &with,
            &cwd,
            Some(json!({"systemPromptOverride": "  "})),
        )
        .await;
        prompt_turn(&conn, &with, "after blank").await;
        assert_eq!(
            std::fs::read_to_string(override_file(&with).unwrap()).unwrap(),
            override_text(SENTINEL_2)
        );
    });
}
