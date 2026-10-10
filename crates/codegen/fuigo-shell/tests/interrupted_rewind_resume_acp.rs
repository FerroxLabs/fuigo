//! P164 (K19): a rewind Fuigo is killed in the middle of is reconciled when the session is loaded again.
//!
//! Every scenario builds a real session (three prompts, one rewind point each), runs a real `fuigo/rewind/execute` to
//! prompt #1 that the test seam stops at one step as a kill would (nothing after it runs: no put-back, no cleanup),
//! ends the agent's hold on the session, and loads it cold in a fresh agent (the real `session/load` -> `load_light`
//! path). The session must then be consistent and the next rewind must not be refused:
//! - stopped before the conversation was saved: the rewind did not happen; `rewind_points.jsonl` is back to what it
//!   held, the conversation is as it was;
//! - stopped after: the rewind went through; the copy is gone, the transcript records the rewind once.
//!
//! Before P164 every one of these left `rewind_points.jsonl.pre-rewind` in place and refused the next rewind.
//! One `#[test]` per binary (the harness env and the seam are process-global); failures are reported together.
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{
    RPC_TIMEOUT, connect_client, ext_method, new_session, prompt_turn, run_agent_test,
    spawn_agent_local_with_config,
};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_shell::session::info::Info;
use fuigo_shell::session::storage::rewind_crash_seam::{self, Stage};
use fuigo_test_support::sse::chat_completion_script_exact;
use fuigo_test_support::{InferenceEndpoint, InferenceRequestMatcher, MockInferenceServer, ScriptedResponse};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

const MODEL: &str = "test-model";

/// Records the raw params of every ext notification (the load's notes travel on these).
#[derive(Clone, Default)]
struct Recorder(Rc<RefCell<Vec<String>>>);

#[async_trait::async_trait(?Send)]
impl acp::Client for Recorder {
    async fn request_permission(
        &self,
        args: acp::RequestPermissionRequest,
    ) -> acp::Result<acp::RequestPermissionResponse> {
        Ok(acp::RequestPermissionResponse::new(acp_harness::allow_once(&args)))
    }
    async fn session_notification(&self, _: acp::SessionNotification) -> acp::Result<()> {
        Ok(())
    }
    async fn ext_notification(&self, args: acp::ExtNotification) -> acp::Result<()> {
        self.0.borrow_mut().push(args.params.get().to_owned());
        Ok(())
    }
}

impl Recorder {
    fn notes(&self, session: &acp::SessionId) -> Vec<String> {
        self.0
            .borrow()
            .iter()
            .filter_map(|raw| serde_json::from_str::<Value>(raw).ok())
            .filter(|v| v["sessionId"] == session.0.as_ref())
            .filter(|v| v["update"]["sessionUpdate"] == "history_repaired")
            .filter_map(|v| v["update"]["message"].as_str().map(str::to_owned))
            .collect()
    }
}

fn agent_config() -> fuigo_shell::agent::config::Config {
    let mut config = fuigo_shell::agent::config::Config::default();
    config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
    config
}

async fn connect(label: &str, recorder: Recorder) -> acp::ClientSideConnection {
    connect_client(recorder, label, spawn_agent_local_with_config(agent_config())).await.0
}

fn session_dir(session: &acp::SessionId, cwd: &Path) -> PathBuf {
    fuigo_shell::session::persistence::session_dir(&Info { id: session.clone(), cwd: cwd.to_string_lossy().into_owned() })
}

fn point_indices(path: &Path) -> Vec<u64> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|row| row["prompt_index"].as_u64())
        .collect()
}

/// `RewindMarker`s to `target` in `updates.jsonl`.
fn markers_to(updates: &Path, target: u64) -> usize {
    std::fs::read_to_string(updates)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|v| {
            v["params"]["update"]["sessionUpdate"] == "rewind_marker"
                && v["params"]["update"]["target_prompt_index"].as_u64() == Some(target)
        })
        .count()
}

async fn rewind(conn: &acp::ClientSideConnection, session: &acp::SessionId, target: usize) -> Result<Value, String> {
    let params = json!({ "sessionId": session.to_string(), "targetPromptIndex": target, "force": true, "mode": "all" });
    let raw = serde_json::value::RawValue::from_string(params.to_string()).expect("serialize ext params");
    match tokio::time::timeout(
        RPC_TIMEOUT,
        conn.ext_method(acp::ExtRequest::new("fuigo/rewind/execute", std::sync::Arc::from(raw))),
    )
    .await
    {
        Err(_) => Err("fuigo/rewind/execute timed out".into()),
        Ok(Err(e)) => Err(format!("{e}")),
        Ok(Ok(resp)) => serde_json::from_str(resp.0.get()).map_err(|e| format!("bad response: {e}")),
    }
}

async fn load(conn: &acp::ClientSideConnection, session: &acp::SessionId, cwd: &Path) -> Result<(), String> {
    tokio::time::timeout(RPC_TIMEOUT, conn.load_session(acp::LoadSessionRequest::new(session.clone(), cwd.to_path_buf())))
        .await
        .map_err(|_| "session/load timed out".to_string())?
        .map(|_| ())
        .map_err(|e| format!("session/load failed: {e}"))
}

/// Ends `session` in the agent that ran it and waits until its actor is gone: a killed process holds no lock.
async fn close_and_release(conn: &acp::ClientSideConnection, session: &acp::SessionId, cwd: &Path) {
    ext_method(conn, "fuigo/session/close", json!({ "sessionId": session.to_string() })).await;
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
        assert!(tokio::time::Instant::now() < deadline, "the actor for {} never released the session", session.0);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kill {
    /// Journal and copy written, the swap of `rewind_points.jsonl` not landed.
    BeforeSwap,
    /// The swap landed; the conversation is not saved.
    AfterSwap,
    /// The rewound conversation is saved; nothing after it ran.
    AfterConversationSaved,
    /// Everything ran except the cleanup.
    BeforeCleanup,
    /// The copy was removed, the journal not.
    BetweenRemovals,
}

impl Kill {
    fn stage(self) -> Stage {
        match self {
            Kill::BeforeSwap | Kill::AfterSwap => Stage::AfterPointsRewrite,
            Kill::AfterConversationSaved => Stage::AfterConversationSaved,
            Kill::BeforeCleanup | Kill::BetweenRemovals => Stage::BeforeCleanup,
        }
    }
    fn went_through(self) -> bool {
        !matches!(self, Kill::BeforeSwap | Kill::AfterSwap)
    }
}

/// One scenario; returns what is wrong with it.
async fn scenario(cwd: &Path, mock: &MockInferenceServer, kill: Kill) -> Vec<String> {
    let mut failures = Vec::new();
    let label = format!("{kill:?}");
    let builder = connect(&format!("p164-build-{label}"), Recorder::default()).await;
    let session = new_session(&builder, cwd).await;
    for i in 0..3 {
        let step = mock.expect_response(
            format!("{label}-answer-{i}"),
            InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
            ScriptedResponse::sse(chat_completion_script_exact(&format!("Answer {i}."), MODEL)),
        );
        prompt_turn(&builder, &session, &format!("Prompt {i} of {label}.")).await;
        step.assert_satisfied();
    }
    let dir = session_dir(&session, cwd);
    let points = dir.join("rewind_points.jsonl");
    let chat = dir.join("chat_history.jsonl");
    let updates = dir.join("updates.jsonl");
    let copy = dir.join("rewind_points.jsonl.pre-rewind");
    let journal = dir.join("rewind_points.jsonl.pre-rewind.journal");
    assert_eq!(point_indices(&points), vec![0, 1, 2], "fixture: one rewind point per prompt");
    let points_before = std::fs::read(&points).expect("read rewind points");
    let chat_before = std::fs::read(&chat).expect("read chat history");

    rewind_crash_seam::arm(&session.0, kill.stage());
    let killed = rewind(&builder, &session, 1).await.expect("rewind/execute answers");
    if !killed["error"].as_str().unwrap_or_default().contains("killed by the test seam") {
        failures.push(format!("{label}: the seam did not stop the rewind: {killed}"));
        return failures;
    }
    close_and_release(&builder, &session, cwd).await;
    drop(builder);
    match kill {
        // The rename over rewind_points.jsonl had not landed: the file holds what it held.
        Kill::BeforeSwap => std::fs::write(&points, &points_before).expect("undo the swap"),
        Kill::BetweenRemovals => std::fs::remove_file(&copy).expect("remove the copy"),
        _ => {}
    }
    if kill != Kill::BetweenRemovals && !(copy.is_file() && journal.is_file()) {
        failures.push(format!("{label}: fixture: the killed rewind left no copy and journal"));
    }

    let recorder = Recorder::default();
    let loader = connect(&format!("p164-load-{label}"), recorder.clone()).await;
    if let Err(error) = load(&loader, &session, cwd).await {
        failures.push(format!("{label}: {error}"));
        return failures;
    }
    let notes = recorder.notes(&session);
    // Astra r3: the history the load returns is read after the reconcile. Read before it, it could be the conversation
    // a rewind that went through had already replaced (and startup would write it back).
    if rewind_crash_seam::copy_was_present_at_history_read(&session.0) != Some(false) {
        failures.push(format!("{label}: the load read the history before it reconciled the rewind"));
    }
    let chat_now = String::from_utf8_lossy(&std::fs::read(&chat).unwrap_or_default()).into_owned();
    if copy.symlink_metadata().is_ok() || journal.symlink_metadata().is_ok() {
        failures.push(format!("{label}: the leftover copy or journal is still there after the load"));
    }
    if kill.went_through() {
        if point_indices(&points) != vec![0] {
            failures.push(format!("{label}: rewind_points.jsonl holds {:?}, expected [0]", point_indices(&points)));
        }
        if chat_now.contains(&format!("Prompt 1 of {label}.")) || !chat_now.contains(&format!("Prompt 0 of {label}.")) {
            failures.push(format!("{label}: the conversation is not the rewound one"));
        }
        if markers_to(&updates, 1) != 1 {
            failures.push(format!("{label}: the transcript records the rewind {} times", markers_to(&updates, 1)));
        }
    } else {
        if std::fs::read(&points).unwrap_or_default() != points_before {
            failures.push(format!("{label}: rewind_points.jsonl was not put back: {:?}", point_indices(&points)));
        }
        if std::fs::read(&chat).unwrap_or_default() != chat_before {
            failures.push(format!("{label}: the conversation changed"));
        }
        if markers_to(&updates, 1) != 0 {
            failures.push(format!("{label}: a rewind that did not happen is in the transcript"));
        }
    }
    let expected_note = match kill {
        Kill::BetweenRemovals => None,
        Kill::BeforeSwap | Kill::AfterSwap => Some("did not happen"),
        Kill::AfterConversationSaved | Kill::BeforeCleanup => Some("went through"),
    };
    let rewind_notes: Vec<&String> = notes.iter().filter(|note| note.contains("earlier rewind")).collect();
    match expected_note {
        Some(text) if !rewind_notes.iter().any(|note| note.contains(text) && note.contains("prompt #1")) => {
            failures.push(format!("{label}: the user was not told ({text}): {notes:?}"))
        }
        None if !rewind_notes.is_empty() => failures.push(format!("{label}: unexpected note: {notes:?}")),
        _ => {}
    }
    // The session is usable: the next rewind is not refused over a leftover.
    match rewind(&loader, &session, 0).await {
        Ok(next) if next["success"] == true => {}
        other => failures.push(format!("{label}: the next rewind failed: {other:?}")),
    }
    close_and_release(&loader, &session, cwd).await;
    failures
}

#[test]
fn a_rewind_killed_at_any_step_is_reconciled_when_the_session_is_loaded() {
    run_agent_test(|cwd, mock| async move {
        let mut failures = Vec::new();
        for kill in [Kill::BeforeSwap, Kill::AfterSwap, Kill::AfterConversationSaved, Kill::BeforeCleanup, Kill::BetweenRemovals] {
            failures.extend(scenario(&cwd, &mock, kill).await);
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    });
}
