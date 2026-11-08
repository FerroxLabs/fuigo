//! F5-C2 (design F5 §5.5, §6.1, §6.2): a leader session survives its client's disconnect into a working `session/load`.
//!
//! A REAL leader IPC server (`run_leader_server`) fronts a REAL in-process agent (`leader::in_process::spawn_agent`), the
//! production leader topology: one agent, many clients. Client A opens a session, runs a turn and disconnects without
//! closing it. Client B (or A reconnecting) then loads that id. B must get a working session, never `still closing` or
//! `HELD_ELSEWHERE`, and the process never holds two writers for the id (`SessionWriter`'s slot is per id).
//!
//! Cases:
//! - (a1) B loads at once, racing the leader's client-gone detach (`fuigo/internal/evict_sessions`).
//! - (a2) B loads after the detach has unloaded the idle session (its writer released).
//! - (a3) A reconnects on a new connection and loads its own session.
//! - (b1) after A's disconnect, B sends `fuigo/session/close`, then loads.
//! - (b2) A and B both attached; A disconnects; B closes, then loads again.
//!
//! One `#[test]` per binary: the harness env is process-global.
#![cfg(unix)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

#[allow(dead_code)]
mod acp_harness;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::time::{Duration, Instant};

use fuigo_session_writer::SessionWriter;
use fuigo_shell::leader::{
    ClientCapabilities, ClientMode, LeaderClient, LeaderServerControlState, LeaderServerMetadata,
    run_leader_server,
};
use serde_json::{Value, json};

const RPC: Duration = Duration::from_secs(60);
/// §6.1: close is answered within 8.5 s; a free writer follows the actor's end.
const RELEASE_BUDGET: Duration = Duration::from_secs(9);

struct Raw {
    conn: LeaderClient,
    next: u64,
    name: &'static str,
}

impl Raw {
    async fn connect(sock: &Path, name: &'static str) -> Self {
        let conn = tokio::time::timeout(
            RPC,
            LeaderClient::connect(sock.to_path_buf(), name, ClientMode::Stdio, ClientCapabilities::default()),
        )
        .await
        .expect("leader connect timed out")
        .expect("leader connect");
        let mut raw = Self { conn, next: 0, name };
        let init = raw
            .call(
                "initialize",
                json!({
                    "protocolVersion": 1,
                    "clientCapabilities": { "fs": { "readTextFile": false, "writeTextFile": false }, "terminal": false },
                    "_meta": {
                        "startupHints": { "nonInteractive": true, "skipGitStatus": true, "skipProjectLayout": true },
                        "clientType": name,
                        "clientVersion": "0.0-test",
                    },
                }),
            )
            .await;
        assert!(init.get("result").is_some(), "{name}: initialize failed: {init}");
        let auth = raw
            .call("authenticate", json!({ "methodId": "fuigo.api_key", "_meta": { "headless": true } }))
            .await;
        assert!(auth.get("result").is_some(), "{name}: authenticate failed: {auth}");
        raw
    }

    /// Send one request and return its response; agent-to-client requests meanwhile are refused (`-32601`).
    async fn call(&mut self, method: &str, params: Value) -> Value {
        self.next += 1;
        let id = self.next;
        self.conn
            .send(json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string())
            .expect("send to leader");
        let deadline = tokio::time::Instant::now() + RPC;
        loop {
            let line = tokio::time::timeout_at(deadline, self.conn.recv())
                .await
                .unwrap_or_else(|_| panic!("{}: {method} timed out", self.name))
                .unwrap_or_else(|| panic!("{}: leader connection closed during {method}", self.name));
            let Ok(msg) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            let has_method = msg.get("method").is_some();
            match msg.get("id") {
                Some(got) if !has_method && got == &json!(id) => return msg,
                Some(req_id) if has_method => {
                    let _ = self.conn.send(
                        json!({ "jsonrpc": "2.0", "id": req_id, "error": { "code": -32601, "message": "test refuses" } })
                            .to_string(),
                    );
                }
                _ => {}
            }
        }
    }

    async fn new_session(&mut self, cwd: &Path) -> String {
        let r = self
            .call("session/new", json!({ "cwd": cwd, "mcpServers": [], "_meta": { "modelId": "test-model" } }))
            .await;
        r["result"]["sessionId"]
            .as_str()
            .unwrap_or_else(|| panic!("{}: session/new returned no sessionId: {r}", self.name))
            .to_owned()
    }

    async fn prompt(&mut self, sid: &str) {
        let r = self
            .call("session/prompt", json!({ "sessionId": sid, "prompt": [{ "type": "text", "text": "hello" }] }))
            .await;
        assert_eq!(
            r["result"]["stopReason"].as_str(),
            Some("end_turn"),
            "{}: prompt on {sid} did not end its turn: {r}",
            self.name
        );
    }

    /// `session/load` must succeed; a refusal (`still closing`, `HELD_ELSEWHERE`, anything) fails the case.
    async fn load_ok(&mut self, case: &str, sid: &str, cwd: &Path) -> Duration {
        let started = Instant::now();
        let r = self.call("session/load", json!({ "sessionId": sid, "cwd": cwd, "mcpServers": [] })).await;
        let took = started.elapsed();
        assert!(
            r.get("error").is_none() && r.get("result").is_some(),
            "{case}: {} session/load of {sid} was refused after {took:?}: {r}",
            self.name
        );
        took
    }

    async fn close(&mut self, sid: &str) -> Value {
        self.call("_fuigo/session/close", json!({ "sessionId": sid })).await
    }

    fn disconnect(self) {
        self.conn.cancel();
        drop(self);
    }
}

async fn wait_free(sid: &str, within: Duration) -> Option<Duration> {
    let started = Instant::now();
    while started.elapsed() < within {
        if SessionWriter::is_free(sid) {
            return Some(started.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    None
}

fn report(line: String) {
    println!("[f5c2-leader] {line}");
}

/// Open a session on a fresh client, run one turn, and return both.
async fn opened(sock: &Path, cwd: &Path, name: &'static str) -> (Raw, String) {
    let mut a = Raw::connect(sock, name).await;
    let sid = a.new_session(cwd).await;
    a.prompt(&sid).await;
    assert!(!SessionWriter::is_free(&sid), "{name}: a live session holds its writer");
    (a, sid)
}

#[test]
fn f5c2_leader_session_load_after_client_disconnect_never_refuses() {
    acp_harness::run_agent_test(|cwd: PathBuf, _mock| async move {
        let home = std::env::var_os("FUIGO_HOME").expect("harness sets FUIGO_HOME");
        let sock = PathBuf::from(home).join("f5c2-leader.sock");

        let (acp_tx, acp_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let (response_tx, response_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control_state = LeaderServerControlState::new(LeaderServerMetadata {
            pid: std::process::id(),
            socket_path: sock.clone(),
            lock_path: sock.with_extension("lock"),
            ws_url_suffix: String::new(),
            leader_binary_version: env!("CARGO_PKG_VERSION").to_string(),
        });
        let server_sock = sock.clone();
        let server_cancel = cancel.clone();
        let server = tokio::task::spawn_local(async move {
            let _ = run_leader_server(
                server_sock,
                acp_tx,
                response_rx,
                server_cancel,
                true,
                Arc::new(AtomicUsize::new(0)),
                Arc::new(AtomicBool::new(false)),
                fuigo_shell::agent::activity::AgentActivity::default(),
                tokio::sync::watch::channel(true).1,
                tokio::sync::watch::channel(false).0,
                tokio::sync::watch::channel(fuigo_shell::leader::ShutdownReason::Manual).0,
                None,
                control_state,
            )
            .await;
        });
        let agent_tasks = fuigo_shell::leader::in_process::spawn_agent(acp_rx, response_tx);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !sock.exists() {
            assert!(Instant::now() < deadline, "leader socket never bound");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // (a1) B loads at once, racing the client-gone detach.
        let (a, sid) = opened(&sock, &cwd, "a1-owner").await;
        a.disconnect();
        let mut b = Raw::connect(&sock, "a1-other").await;
        let took = b.load_ok("a1", &sid, &cwd).await;
        b.prompt(&sid).await;
        assert!(!SessionWriter::is_free(&sid), "a1: the loaded session holds one writer");
        report(format!("a1 immediate load after disconnect: ok in {took:?}, turn ok"));
        let closed = b.close(&sid).await;
        let freed = wait_free(&sid, RELEASE_BUDGET).await;
        assert!(freed.is_some(), "a1: close never released the writer: {closed}");
        b.disconnect();

        // (a2) B loads after the detach unloaded the idle session.
        let (a, sid) = opened(&sock, &cwd, "a2-owner").await;
        a.disconnect();
        let released = wait_free(&sid, RELEASE_BUDGET).await;
        report(format!("a2 writer after disconnect-detach: released after {released:?}"));
        let mut b = Raw::connect(&sock, "a2-other").await;
        let took = b.load_ok("a2", &sid, &cwd).await;
        b.prompt(&sid).await;
        report(format!("a2 load after detach: ok in {took:?}, turn ok"));
        b.close(&sid).await;
        assert!(wait_free(&sid, RELEASE_BUDGET).await.is_some(), "a2: close never released the writer");
        b.disconnect();

        // (a3) A reconnects and loads its own session.
        let (a, sid) = opened(&sock, &cwd, "a3-owner").await;
        a.disconnect();
        let mut again = Raw::connect(&sock, "a3-owner").await;
        let took = again.load_ok("a3", &sid, &cwd).await;
        again.prompt(&sid).await;
        report(format!("a3 owner reconnect load: ok in {took:?}, turn ok"));
        again.close(&sid).await;
        assert!(wait_free(&sid, RELEASE_BUDGET).await.is_some(), "a3: close never released the writer");
        again.disconnect();

        // (b1) After A's disconnect, B closes the session, then loads it.
        let (a, sid) = opened(&sock, &cwd, "b1-owner").await;
        a.disconnect();
        let mut b = Raw::connect(&sock, "b1-other").await;
        let started = Instant::now();
        let closed = b.close(&sid).await;
        assert!(closed.get("error").is_none(), "b1: close refused: {closed}");
        let freed = wait_free(&sid, RELEASE_BUDGET).await;
        assert!(freed.is_some(), "b1: close never released the writer: {closed}");
        report(format!("b1 close by the other client: {} in {:?}", closed["result"], started.elapsed()));
        let took = b.load_ok("b1", &sid, &cwd).await;
        b.prompt(&sid).await;
        report(format!("b1 load after close: ok in {took:?}, turn ok"));
        b.close(&sid).await;
        assert!(wait_free(&sid, RELEASE_BUDGET).await.is_some(), "b1: final close never released the writer");
        b.disconnect();

        // (b2) A and B both attached; A disconnects; B closes, then loads again.
        let (a, sid) = opened(&sock, &cwd, "b2-owner").await;
        let mut b = Raw::connect(&sock, "b2-other").await;
        let took = b.load_ok("b2 resident", &sid, &cwd).await;
        report(format!("b2 resident load while A attached: ok in {took:?}"));
        a.disconnect();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let closed = b.close(&sid).await;
        assert!(closed.get("error").is_none(), "b2: close refused: {closed}");
        assert!(wait_free(&sid, RELEASE_BUDGET).await.is_some(), "b2: close never released the writer: {closed}");
        let took = b.load_ok("b2", &sid, &cwd).await;
        b.prompt(&sid).await;
        report(format!("b2 load after A gone and B's close: ok in {took:?}, turn ok"));
        b.close(&sid).await;
        assert!(wait_free(&sid, RELEASE_BUDGET).await.is_some(), "b2: final close never released the writer");
        b.disconnect();

        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(10), server).await;
        for task in agent_tasks.iter() {
            task.abort();
        }
    });
}
