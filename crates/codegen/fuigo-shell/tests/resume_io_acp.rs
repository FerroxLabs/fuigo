//! F5 (1.0.47): a cold `session/load` reads `updates.jsonl` from disk once and leaves an unchanged
//! `chat_history.jsonl` alone.
//!
//! Builds a real two-turn session, inflates it to `RESUME_IO_TURNS` turns (default 500; the 1.0.47 measurement used
//! 10,000) by repeating the second turn's lines, loads it cold in a fresh agent and checks the read count, that the
//! history file was not replaced, and that the next request carries the whole history.
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
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

const MODEL: &str = "test-model";
const MARKER: &str = "F5-SECOND-PROMPT";

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

/// Appends `extra` copies of the lines from the first one containing `MARKER` to the end of `path`.
#[allow(
    clippy::disallowed_methods,
    reason = "test code: fixtures inflate files in a test FUIGO_HOME; no product session writer runs there"
)]
fn inflate(path: &Path, extra: usize) -> u64 {
    let text = std::fs::read_to_string(path).expect("read fixture");
    let start = text
        .lines()
        .position(|l| l.contains(MARKER))
        .unwrap_or_else(|| panic!("no line of {} contains the marker", path.display()));
    let turn: String = text.lines().skip(start).map(|l| format!("{l}\n")).collect();
    let mut out = text.clone();
    out.reserve(turn.len() * extra);
    for _ in 0..extra {
        out.push_str(&turn);
    }
    std::fs::write(path, &out).expect("write inflated fixture");
    out.len() as u64
}

fn proc_io(key: &str) -> u64 {
    std::fs::read_to_string("/proc/self/io")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| {
                    l.strip_prefix(&format!("{key}: "))
                        .map(|v| v.trim().parse().ok())
                })
                .flatten()
        })
        .unwrap_or(0)
}

#[test]
fn resume_reads_updates_once_and_keeps_an_unchanged_history() {
    let turns: usize = std::env::var("RESUME_IO_TURNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(500)
        .max(2);
    run_agent_test(|cwd, mock| async move {
        let a = connect("f5-build").await;
        let session = new_session(&a, &cwd).await;
        for (i, prompt) in ["first prompt", MARKER].into_iter().enumerate() {
            let step = mock.expect_response(
                format!("f5-{i}"),
                foreground(),
                ScriptedResponse::sse(chat_completion_script_exact(
                    &format!("answer {i} {}", "lorem ipsum ".repeat(40)),
                    MODEL,
                )),
            );
            prompt_turn(&a, &session, prompt).await;
            step.assert_satisfied();
        }
        close_and_release(&a, &session, &cwd).await;

        let dir = session_dir(&session, &cwd);
        let updates_bytes = inflate(&dir.join("updates.jsonl"), turns - 2);
        let chat = dir.join("chat_history.jsonl");
        let chat_bytes = inflate(&chat, turns - 2);
        let chat_before = std::fs::metadata(&chat).expect("chat metadata");
        let history_items = std::fs::read_to_string(&chat)
            .expect("read chat")
            .lines()
            .filter(|l| {
                l.starts_with(r#"{"type":"user""#) || l.starts_with(r#"{"type":"assistant""#)
            })
            .count();

        let b = connect("f5-load").await;
        let reads_before = fuigo_shell::session::storage::updates_cache::disk_reads();
        let (rchar, wchar) = (proc_io("rchar"), proc_io("wchar"));
        let started = std::time::Instant::now();
        tokio::time::timeout(
            RPC_TIMEOUT * 3,
            b.load_session(acp::LoadSessionRequest::new(session.clone(), cwd.clone())),
        )
        .await
        .expect("session/load timed out")
        .expect("session/load failed");
        let elapsed = started.elapsed();
        let reads = fuigo_shell::session::storage::updates_cache::disk_reads() - reads_before;
        eprintln!(
            "F5 resume: turns={turns} updates={updates_bytes}B chat={chat_bytes}B load={elapsed:?} \
             read={}B written={}B updates_disk_reads={reads}",
            proc_io("rchar") - rchar,
            proc_io("wchar") - wchar,
        );

        assert_eq!(
            reads, 1,
            "a resume must read updates.jsonl from disk exactly once"
        );
        let original = std::fs::read(&chat).expect("read chat");

        // The resumed conversation is the history on disk: the next request carries every item of it.
        let step = mock.expect_response(
            "f5-next",
            foreground(),
            ScriptedResponse::sse(chat_completion_script_exact("next", MODEL)),
        );
        let before = mock.requests().len();
        prompt_turn(&b, &session, "and now?").await;
        step.assert_satisfied();
        let messages = mock.requests()[before..]
            .iter()
            .filter(|r| r.path == "/v1/chat/completions" && r.header("x-fuigo-turn-idx").is_some())
            .filter_map(|r| r.body.clone())
            .next()
            .expect("a foreground request")["messages"]
            .as_array()
            .expect("messages array")
            .iter()
            .filter(|m| m["role"] == "user" || m["role"] == "assistant")
            .count();
        // The load's history rewrites ran on the persistence actor, possibly after the load answered: by now the turn
        // has appended to the file, which an append leaves in place and a rewrite would have replaced.
        let chat_after = std::fs::metadata(&chat).expect("chat metadata");
        assert_eq!(
            chat_after.ino(),
            chat_before.ino(),
            "an unchanged chat_history.jsonl must not be rewritten at load"
        );
        assert!(
            std::fs::read(&chat)
                .expect("read chat")
                .starts_with(&original),
            "the turn only appended to the history"
        );
        assert!(
            messages >= history_items,
            "the resumed request carries {messages} user/assistant messages, the history holds {history_items}"
        );
    });
}
