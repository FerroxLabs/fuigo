//! Bridge a leader IPC connection into an `AcpClientChannel`.
//!
//! Adapts the leader's raw JSON string channels into the typed ACP channel interface.
//! Reuses `ClientSideConnection` from `agent_client_protocol` for JSON-RPC ser/deser.

use std::sync::Arc;
use std::thread;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, simplex};
use tokio::sync::{Mutex as TokioMutex, mpsc};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use tokio_util::sync::CancellationToken;

use agent_client_protocol as acp;
use fuigo_acp_lib::{
    AcpClientChannel, AcpGatewayReceiver, AcpGatewaySender, LineBufferedRead, acp_channels,
};
pub use fuigo_shell::leader::ConnectionStatus;
use fuigo_shell::leader::{LeaderConnection, LeaderReconnector, ReconnectPolicy};

const MAX_BUF: usize = 8 * 1024 * 1024;

pub struct LeaderBridge {
    pub channel: AcpClientChannel,
    pub cancel: CancellationToken,
    pub thread_handle: thread::JoinHandle<Result<()>>,
}

/// How [`forward_outbound_line`] resolved one outbound line.
#[derive(Debug, PartialEq, Eq)]
enum ForwardOutcome {
    Sent,
    /// The connection the line was composed for died and a new one replaced it; the line was dropped.
    DroppedStale,
    Cancelled,
}

/// Send one outbound line to the (swappable) leader tx.
///
/// A failed send means the connection is dead.
/// The line is held (blocking the lines queued behind it) until the reader task installs a fresh tx, then dropped.
/// Replaying it would be worse: a stale `session/load` re-delivered on the new connection triggers a second full replay into the same reload window.
/// That duplicates the transcript; the reconnect re-init re-establishes state explicitly instead.
///
/// Scoping is by FIRST OBSERVED send failure, a best-effort heuristic.
/// A pre-disconnect line whose first send happens after the swap never fails and goes out on the new connection.
/// Lines queued behind a held one are forwarded post-swap regardless of when they were composed.
#[cfg(test)]
async fn forward_outbound_line(
    leader_tx: &TokioMutex<mpsc::UnboundedSender<String>>,
    cancel: &CancellationToken,
    pending: String,
) -> ForwardOutcome {
    forward_outbound_line_tracked(leader_tx, cancel, pending, None).await
}

/// [`forward_outbound_line`] that also records a sent REQUEST in `inflight` (P152, Astra r2 #2). The record is made
/// while the tx lock is held, so it is atomic with the send: the reader's drain at the connection swap (under the same
/// lock) sees exactly the requests that went to the old connection.
async fn forward_outbound_line_tracked(
    leader_tx: &TokioMutex<mpsc::UnboundedSender<String>>,
    cancel: &CancellationToken,
    mut pending: String,
    inflight: Option<&InflightRequests>,
) -> ForwardOutcome {
    let request_id = inflight.and_then(|_| request_id_of(&pending));
    let mut failed_on: Option<mpsc::UnboundedSender<String>> = None;
    loop {
        {
            let tx = leader_tx.lock().await;
            if let Some(ref dead) = failed_on
                && !tx.same_channel(dead)
            {
                return ForwardOutcome::DroppedStale;
            }
            pending = match tx.send(pending) {
                Ok(()) => {
                    if let (Some(inflight), Some(id)) = (inflight, request_id) {
                        inflight.record(id);
                    }
                    return ForwardOutcome::Sent;
                }
                Err(mpsc::error::SendError(returned)) => returned,
            };
            if failed_on.is_none() {
                failed_on = Some(tx.clone());
            }
        }
        tracing::debug!("Writer send failed; holding line until the reconnect swap");
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return ForwardOutcome::Cancelled,
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
        }
    }
}

/// What a request dropped as stale gets back instead of silence (P152).
pub(crate) const STALE_REQUEST_ERROR_MESSAGE: &str =
    "The Fuigo leader restarted before this request reached it, so nothing was sent. Try again.";

/// The JSON-RPC error response for a REQUEST line the writer dropped as stale, or `None` for a notification or a
/// response (P152, Astra r1 #2). The request never reached any leader; without an answer the caller's `acp_send` would
/// wait forever and a prompt would vanish with no response and no error. The reader injects this line so the pending
/// call fails with a message the user can act on.
fn stale_request_failure_line(line: &str) -> Option<String> {
    let json = serde_json::from_str::<serde_json::Value>(line).ok()?;
    let id = json.get("id").filter(|id| !id.is_null())?;
    json.get("method")?;
    Some(
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32603, "message": STALE_REQUEST_ERROR_MESSAGE },
        })
        .to_string(),
    )
}

/// What a request sent to a leader connection that then died gets back instead of silence (P152, Astra r2 #2).
pub(crate) const LOST_REQUEST_ERROR_MESSAGE: &str = "The connection to the Fuigo leader was lost before this request was answered, \
     so it may not have run. Try again.";

/// Whether a prompt error is one the bridge synthesized for a request the leader connection lost (P152). The pager
/// shows these even for a queued prompt that never became the running turn.
pub(crate) fn is_transport_loss_error(message: &str) -> bool {
    message.contains(STALE_REQUEST_ERROR_MESSAGE) || message.contains(LOST_REQUEST_ERROR_MESSAGE)
}

/// The canonical id (`serde_json` text) of a JSON-RPC REQUEST line, or `None` for a notification or a response.
fn request_id_of(line: &str) -> Option<String> {
    let json = serde_json::from_str::<serde_json::Value>(line).ok()?;
    json.get("method")?;
    json.get("id").filter(|id| !id.is_null()).map(|id| id.to_string())
}

/// The error answer for a request (by canonical id) that the dead connection will never answer.
fn lost_request_failure_line(id: &str) -> Option<String> {
    let id = serde_json::from_str::<serde_json::Value>(id).ok()?;
    Some(
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32603, "message": LOST_REQUEST_ERROR_MESSAGE },
        })
        .to_string(),
    )
}

/// Requests sent to the current leader connection that it has not answered yet (P152, Astra r2 #2). A request the
/// forwarding stage accepted can still die with the connection (the IPC adapter or the socket write fails after the
/// hand-off); when the connection ends, every such request is answered with an error so its caller fails visibly.
#[derive(Default)]
struct InflightRequests(std::sync::Mutex<std::collections::HashSet<String>>);

impl InflightRequests {
    fn record(&self, id: String) {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(id);
    }
    /// Forget the request a leader RESPONSE line answers. Requests and notifications from the leader are ignored.
    fn note_leader_line(&self, line: &str) {
        let mut set = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if set.is_empty() {
            return;
        }
        #[derive(serde::Deserialize)]
        struct Head {
            id: Option<serde_json::Value>,
            method: Option<serde::de::IgnoredAny>,
        }
        if let Ok(Head { id: Some(id), method: None }) = serde_json::from_str::<Head>(line) {
            set.remove(&id.to_string());
        }
    }
    /// The error answers for every unanswered request, which are forgotten.
    fn fail_all(&self) -> Vec<String> {
        let mut set = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        set.drain().filter_map(|id| lost_request_failure_line(&id)).collect()
    }
}

/// Version-mismatch notice as leaders before the `_`-prefix fix sent it.
const LEGACY_VERSION_MISMATCH_METHOD: &str = "fuigo/leader/version_mismatch";
const VERSION_MISMATCH_METHOD: &str = "_fuigo/leader/version_mismatch";

/// Rewrite a legacy leader's bare `fuigo/leader/version_mismatch` notification to the `_`-prefixed ACP ext name.
///
/// `ClientSideConnection` only decodes a custom notification that carries the `_` prefix (it strips it, so handlers see `fuigo/...`)
/// and rejects a bare one as method-not-found.
/// Older leaders sent the bare name, so against them the version-mismatch notice (the one that matters most when the leader is old) never reached a handler.
/// Only a request-less line with exactly that method is touched; every other line passes through byte-for-byte.
fn normalize_legacy_leader_line(line: String) -> String {
    if !line.contains(LEGACY_VERSION_MISMATCH_METHOD) {
        return line;
    }
    let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&line) else {
        return line;
    };
    let is_legacy_notification = json.get("id").is_none()
        && json.get("method").and_then(|m| m.as_str()) == Some(LEGACY_VERSION_MISMATCH_METHOD);
    if !is_legacy_notification {
        return line;
    }
    json["method"] = serde_json::Value::String(VERSION_MISMATCH_METHOD.to_string());
    json.to_string()
}

/// Bridge a `LeaderConnection` into an `AcpClientChannel`.
///
/// When `reconnector` is `Some`, the bridge automatically attempts to reconnect on leader disconnect using the given `policy`.
/// On reconnection failure (or if `reconnector` is `None`), the cancel token fires so the caller can exit.
pub fn bridge_leader_connection(
    conn: LeaderConnection,
    cancel: CancellationToken,
    reconnector: Option<LeaderReconnector>,
    policy: ReconnectPolicy,
) -> Result<LeaderBridge> {
    let (leader_tx, leader_rx) = conn.into_channels();
    bridge_channels(leader_tx, leader_rx, cancel, reconnector, policy)
}

/// Bridge raw IPC channels into an `AcpClientChannel`.
///
/// Spawns a dedicated thread with a `LocalSet` because `ClientSideConnection` uses `spawn_local` internally.
/// On leader disconnect, reconnects via `reconnector` (if provided) or fires the cancel token.
pub(crate) fn bridge_channels(
    leader_tx: mpsc::UnboundedSender<String>,
    leader_rx: mpsc::UnboundedReceiver<String>,
    cancel: CancellationToken,
    reconnector: Option<LeaderReconnector>,
    policy: ReconnectPolicy,
) -> Result<LeaderBridge> {
    let (client_channel, agent_channel) = acp_channels();

    let (incoming_read, incoming_write) = simplex(MAX_BUF);
    let (outgoing_read, outgoing_write) = simplex(MAX_BUF);

    let bridge_cancel = cancel.clone();
    let thread_handle = thread::Builder::new()
        .name("pager-leader-bridge".into())
        .spawn(move || -> Result<()> {
            let mut builder = tokio::runtime::Builder::new_current_thread();
            let rt = fuigo_tty_utils::runtime::apply_blocking_pool(builder.enable_all()).build()?;
            let local = tokio::task::LocalSet::new();
            local.block_on(&rt, async move {
                let leader_tx_shared = Arc::new(TokioMutex::new(leader_tx));
                // P152: answers the writer synthesizes for requests it dropped as stale, delivered by the reader.
                let (inject_tx, mut inject_rx) = mpsc::unbounded_channel::<String>();
                let inflight = std::rc::Rc::new(InflightRequests::default());
                let inflight_r = inflight.clone();

                // Reader: forwards leader IPC lines into the incoming simplex pipe read by ClientSideConnection
                let cancel_r = bridge_cancel.clone();
                let leader_tx_for_reader = leader_tx_shared.clone();
                let inject_tx_r = inject_tx.clone();
                let reader_task = tokio::task::spawn_local(async move {
                    let mut incoming_write = incoming_write;
                    let mut leader_rx = leader_rx;
                    loop {
                        tokio::select! {
                            biased;
                            _ = cancel_r.cancelled() => break,
                            Some(answer) = inject_rx.recv() => {
                                if incoming_write.write_all(answer.as_bytes()).await.is_err()
                                    || incoming_write.write_all(b"\n").await.is_err()
                                {
                                    break;
                                }
                            }
                            msg = leader_rx.recv() => {
                                match msg {
                                    Some(json_line) => {
                                        inflight_r.note_leader_line(&json_line);
                                        let json_line = normalize_legacy_leader_line(json_line);
                                        if incoming_write.write_all(json_line.as_bytes()).await.is_err()
                                            || incoming_write.write_all(b"\n").await.is_err()
                                        {
                                            break;
                                        }
                                    }
                                    None => {
                                        tracing::warn!("Leader connection closed");
                                        // P152 (Astra r2 #2): the dead connection answers nothing more; fail what it
                                        // still owed now, so no caller waits forever on a lost prompt.
                                        let mut write_failed = false;
                                        for answer in inflight_r.fail_all() {
                                            if incoming_write.write_all(answer.as_bytes()).await.is_err()
                                                || incoming_write.write_all(b"\n").await.is_err()
                                            {
                                                write_failed = true;
                                                break;
                                            }
                                        }
                                        if write_failed {
                                            break;
                                        }

                                        if let Some(ref reconnector) = reconnector {
                                            tracing::info!("Attempting to reconnect to leader...");
                                            match reconnector.reconnect(policy, &cancel_r).await {
                                                Ok((new_tx, new_rx, _disconnect_rx)) => {
                                                    tracing::info!("Reconnected to leader IPC");
                                                    leader_rx = new_rx;
                                                    // Swap and drain under one lock: a request recorded before this
                                                    // point went to the old connection (P152).
                                                    let owed = {
                                                        let mut tx = leader_tx_for_reader.lock().await;
                                                        *tx = new_tx;
                                                        inflight_r.fail_all()
                                                    };
                                                    for answer in owed {
                                                        let _ = inject_tx_r.send(answer);
                                                    }
                                                    // Swap first, notify second; see `LeaderReconnector::notify_connected`
                                                    reconnector.notify_connected();
                                                    continue;
                                                }
                                                Err(e) => {
                                                    tracing::error!(error = %e, "Failed to reconnect to leader");
                                                    cancel_r.cancel();
                                                    break;
                                                }
                                            }
                                        } else {
                                            cancel_r.cancel();
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                });

                // Writer: forwards ClientSideConnection output from the outgoing simplex pipe to leader IPC
                let cancel_w = bridge_cancel.clone();
                let leader_tx_for_writer = leader_tx_shared;
                let writer_task = tokio::task::spawn_local(async move {
                    let mut reader = BufReader::new(outgoing_read);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        tokio::select! {
                            biased;
                            _ = cancel_w.cancelled() => break,
                            result = reader.read_line(&mut line) => {
                                match result {
                                    Ok(0) => break,
                                    Ok(_) => {
                                        let pending = line.trim_end();
                                        if pending.is_empty() {
                                            continue;
                                        }
                                        match forward_outbound_line_tracked(
                                            &leader_tx_for_writer,
                                            &cancel_w,
                                            pending.to_string(),
                                            Some(&*inflight),
                                        )
                                        .await
                                        {
                                            ForwardOutcome::Sent => {}
                                            ForwardOutcome::DroppedStale => {
                                                // Unified-log marker: this drop is deliberate
                                                // Replaying a stale `session/load` would double-replay the transcript
                                                // But the drop can eat one-shot notifications like `session/cancel`, a known stuck-cancel failure
                                                // Record WHAT was dropped so the next investigation sees it in the unified log
                                                let method = serde_json::from_str::<serde_json::Value>(pending)
                                                    .ok()
                                                    .and_then(|j| {
                                                        j.get("method").and_then(|m| m.as_str()).map(str::to_owned)
                                                    });
                                                crate::unified_log::warn(
                                                    "leader.ipc.outbound_dropped_stale",
                                                    None,
                                                    Some(serde_json::json!({
                                                        "method": method,
                                                        "len": pending.len(),
                                                    })),
                                                );
                                                tracing::debug!(
                                                    "Dropped outbound line composed for a replaced leader connection"
                                                );
                                                // P152: a dropped REQUEST is answered with an error, never left pending.
                                                if let Some(answer) = stale_request_failure_line(pending) {
                                                    let _ = inject_tx.send(answer);
                                                }
                                            }
                                            ForwardOutcome::Cancelled => break,
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                    }
                });

                // Wire ClientSideConnection for JSON-RPC ser/deser.
                let gw_tx = AcpGatewaySender::new(agent_channel.tx).with_tracing(true);
                let incoming = LineBufferedRead::spawn_local(incoming_read.compat());
                let (conn, handle_io) = acp::ClientSideConnection::new(
                    gw_tx,
                    outgoing_write.compat_write(),
                    incoming,
                    |fut| { tokio::task::spawn_local(fut); },
                );
                let gw_rx = AcpGatewayReceiver::new(agent_channel.rx, conn).with_tracing(true);
                tokio::task::spawn_local(handle_io);
                tokio::task::spawn_local(gw_rx.run());
                tokio::task::yield_now().await;

                bridge_cancel.cancelled().await;
                reader_task.abort();
                writer_task.abort();
                Ok(())
            })
        })?;

    Ok(LeaderBridge {
        channel: client_channel,
        cancel,
        thread_handle,
    })
}

/// Test harness: a REAL leader IPC server plus a REAL client connection bridged through the production [`bridge_channels`] (the real ACP decoder).
/// `leader_version` differs from `client_version`, so the leader itself emits its version-mismatch notice on registration.
#[cfg(all(test, unix))]
pub(crate) mod real_leader_harness {
    use super::*;
    use fuigo_shell::leader::{
        ClientCapabilities, ClientMode, LeaderClient, LeaderServerControlState,
        LeaderServerMetadata, ReconnectPolicy, run_leader_server,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    pub(crate) struct RealLeader {
        pub bridge: LeaderBridge,
        pub server_cancel: CancellationToken,
        _dir: tempfile::TempDir,
    }

    impl Drop for RealLeader {
        fn drop(&mut self) {
            self.bridge.cancel.cancel();
            self.server_cancel.cancel();
        }
    }

    pub(crate) async fn bridge_to_real_leader(
        client_version: &str,
        leader_version: &'static str,
    ) -> RealLeader {
        bridge_to_real_leader_as(
            leader_version,
            ClientCapabilities {
                client_version: Some(client_version.to_string()),
                ..Default::default()
            },
        )
        .await
    }

    /// [`bridge_to_real_leader`] for a client that registers with `capabilities` (P142: the TUI's own).
    pub(crate) async fn bridge_to_real_leader_as(
        leader_version: &'static str,
        capabilities: ClientCapabilities,
    ) -> RealLeader {
        let dir = tempfile::TempDir::new().unwrap();
        let sock = dir.path().join("leader.sock");
        let (acp_tx, _acp_rx) = mpsc::unbounded_channel::<String>();
        let (_response_tx, response_rx) = mpsc::unbounded_channel::<String>();
        let server_cancel = CancellationToken::new();
        let control_state = LeaderServerControlState::new(LeaderServerMetadata {
            pid: std::process::id(),
            socket_path: sock.clone(),
            lock_path: sock.with_extension("lock"),
            ws_url_suffix: String::new(),
            leader_binary_version: leader_version.to_string(),
        });
        let server_sock = sock.clone();
        let server_cancel_task = server_cancel.clone();
        tokio::spawn(async move {
            let _ = run_leader_server(
                server_sock,
                acp_tx,
                response_rx,
                server_cancel_task,
                true,
                Arc::new(AtomicUsize::new(0)),
                Arc::new(AtomicBool::new(false)),
                fuigo_shell::agent::activity::AgentActivity::default(),
                tokio::sync::watch::channel(true).1,
                tokio::sync::watch::channel(false).0,
                tokio::sync::watch::channel(fuigo_shell::leader::ShutdownReason::Manual).0,
                Some(leader_version),
                control_state,
            )
            .await;
        });
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while !sock.exists() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(sock.exists(), "leader socket never bound");
        let conn = LeaderClient::connect(
            sock,
            "p128-client",
            ClientMode::Stdio,
            capabilities,
        )
        .await
        .expect("connect to real leader");
        let (leader_tx, leader_rx) = conn.into_channels();
        let bridge = bridge_channels(
            leader_tx,
            leader_rx,
            CancellationToken::new(),
            None,
            ReconnectPolicy::bounded(),
        )
        .expect("bridge spawn");
        RealLeader {
            bridge,
            server_cancel,
            _dir: dir,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuigo_acp_lib::acp_send;

    const OLD_LEADER_LINE: &str = r#"{"jsonrpc":"2.0","method":"fuigo/leader/version_mismatch","params":{"clientVersion":"0.1.157","leaderVersion":"0.1.150"}}"#;

    /// P152 (Astra r1 #2): a request the writer drops as stale is answered with an error for the same id, so the
    /// caller's `acp_send` fails visibly; notifications and responses get nothing.
    #[test]
    fn stale_request_failure_line_answers_requests_only() {
        let req = r#"{"jsonrpc":"2.0","id":7,"method":"session/prompt","params":{}}"#;
        let answer: serde_json::Value =
            serde_json::from_str(&stale_request_failure_line(req).expect("a request is answered")).unwrap();
        assert_eq!(answer["id"], 7);
        assert_eq!(answer["error"]["code"], -32603);
        assert_eq!(answer["error"]["message"], STALE_REQUEST_ERROR_MESSAGE);
        let str_id = r#"{"jsonrpc":"2.0","id":"a-1","method":"session/load","params":{}}"#;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&stale_request_failure_line(str_id).unwrap()).unwrap()["id"],
            "a-1"
        );
        assert!(stale_request_failure_line(r#"{"jsonrpc":"2.0","method":"session/cancel","params":{}}"#).is_none());
        assert!(stale_request_failure_line(r#"{"jsonrpc":"2.0","id":3,"result":{}}"#).is_none());
        assert!(stale_request_failure_line(r#"{"jsonrpc":"2.0","id":null,"method":"x"}"#).is_none());
        assert!(stale_request_failure_line("not json").is_none());
    }

    #[test]
    fn normalize_rewrites_legacy_version_mismatch_to_prefixed_method() {
        let out = normalize_legacy_leader_line(OLD_LEADER_LINE.to_string());
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(json["method"], "_fuigo/leader/version_mismatch");
        assert_eq!(json["params"]["clientVersion"], "0.1.157");
        assert_eq!(json["params"]["leaderVersion"], "0.1.150");
    }

    #[test]
    fn normalize_leaves_every_other_line_byte_identical() {
        for line in [
            r#"{"jsonrpc":"2.0","method":"_fuigo/leader/version_mismatch","params":{}}"#,
            r#"{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s"}}"#,
            // a request (has an id) is not a notification: never rewritten
            r#"{"jsonrpc":"2.0","id":3,"method":"fuigo/leader/version_mismatch","params":{}}"#,
            // the legacy name only inside a payload string
            r#"{"jsonrpc":"2.0","method":"session/update","params":{"text":"fuigo/leader/version_mismatch"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
            "not json fuigo/leader/version_mismatch",
        ] {
            assert_eq!(normalize_legacy_leader_line(line.to_string()), line);
        }
    }

    /// P152 (Astra r2 #2): a request the forwarding stage accepted is recorded until the leader answers it; when the
    /// connection dies, every unanswered request gets an error for its own id, once.
    #[tokio::test]
    async fn unanswered_requests_are_failed_when_the_connection_dies() {
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let shared = TokioMutex::new(tx);
        let cancel = CancellationToken::new();
        let inflight = InflightRequests::default();
        for line in [
            r#"{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":"b","method":"session/load","params":{}}"#,
            r#"{"jsonrpc":"2.0","method":"session/cancel","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":9,"result":{}}"#,
        ] {
            assert_eq!(
                forward_outbound_line_tracked(&shared, &cancel, line.into(), Some(&inflight)).await,
                ForwardOutcome::Sent
            );
            assert_eq!(rx.recv().await.as_deref(), Some(line));
        }
        // The leader answers request "b"; a leader notification and a leader request change nothing.
        inflight.note_leader_line(r#"{"jsonrpc":"2.0","method":"session/update","params":{"id":1}}"#);
        inflight.note_leader_line(r#"{"jsonrpc":"2.0","id":1,"method":"fs/read","params":{}}"#);
        inflight.note_leader_line(r#"{"jsonrpc":"2.0","id":"b","result":{}}"#);
        let owed = inflight.fail_all();
        assert_eq!(owed.len(), 1, "only the unanswered prompt is owed: {owed:?}");
        let answer: serde_json::Value = serde_json::from_str(&owed[0]).unwrap();
        assert_eq!(answer["id"], 1);
        assert_eq!(answer["error"]["message"], LOST_REQUEST_ERROR_MESSAGE);
        assert!(is_transport_loss_error(answer["error"]["message"].as_str().unwrap()));
        assert!(inflight.fail_all().is_empty(), "each request is failed once");
        // A request whose send never succeeded is not recorded (the stale-drop path answers it instead).
        let (dead_tx, dead_rx) = mpsc::unbounded_channel::<String>();
        drop(dead_rx);
        let dead = TokioMutex::new(dead_tx);
        cancel.cancel();
        let _ = forward_outbound_line_tracked(
            &dead,
            &cancel,
            r#"{"jsonrpc":"2.0","id":2,"method":"session/prompt","params":{}}"#.into(),
            Some(&inflight),
        )
        .await;
        assert!(inflight.fail_all().is_empty());
        assert!(is_transport_loss_error(STALE_REQUEST_ERROR_MESSAGE));
        assert!(!is_transport_loss_error("Server error (500): Something went wrong on our side."));
    }

    #[tokio::test]
    async fn forward_outbound_line_delivers_on_live_channel() {
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let shared = TokioMutex::new(tx);
        let cancel = CancellationToken::new();

        assert_eq!(
            forward_outbound_line(&shared, &cancel, "hello".into()).await,
            ForwardOutcome::Sent
        );
        assert_eq!(rx.recv().await.as_deref(), Some("hello"));
    }

    /// A line whose send failed is HELD (blocking later lines) until the reader swaps in a fresh tx, then DROPPED.
    /// It is neither discarded at first failure (silent outbound loss) nor replayed onto the new connection.
    /// Replaying a stale `session/load` would double-replay the transcript.
    /// Lines queued behind it flow onto the new connection.
    #[tokio::test]
    async fn forward_outbound_line_drops_stale_line_after_swap_and_sends_next() {
        let (dead_tx, dead_rx) = mpsc::unbounded_channel::<String>();
        drop(dead_rx);
        let shared = Arc::new(TokioMutex::new(dead_tx));
        let cancel = CancellationToken::new();

        let (new_tx, mut new_rx) = mpsc::unbounded_channel::<String>();
        let swapped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let swapper_shared = shared.clone();
        let swapper_swapped = swapped.clone();
        let swapper = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            // Flag BEFORE the swap: a `DroppedStale` return implies the new tx was observed, which happens-after this store
            swapper_swapped.store(true, std::sync::atomic::Ordering::SeqCst);
            *swapper_shared.lock().await = new_tx;
        });

        assert_eq!(
            forward_outbound_line(&shared, &cancel, "stale request".into()).await,
            ForwardOutcome::DroppedStale
        );
        assert!(
            swapped.load(std::sync::atomic::Ordering::SeqCst),
            "the line must be HELD until the swap, not dropped on first failure"
        );
        swapper.await.unwrap();

        assert_eq!(
            forward_outbound_line(&shared, &cancel, "fresh request".into()).await,
            ForwardOutcome::Sent
        );
        assert_eq!(
            new_rx.recv().await.as_deref(),
            Some("fresh request"),
            "the first line on the new connection is the post-swap one"
        );
        assert!(
            new_rx.try_recv().is_err(),
            "the stale line must not be re-delivered onto the new connection"
        );
    }

    #[tokio::test]
    async fn forward_outbound_line_cancellation_exits_retry() {
        let (dead_tx, dead_rx) = mpsc::unbounded_channel::<String>();
        drop(dead_rx);
        let shared = TokioMutex::new(dead_tx);
        let cancel = CancellationToken::new();
        cancel.cancel();

        assert_eq!(
            forward_outbound_line(&shared, &cancel, "x".into()).await,
            ForwardOutcome::Cancelled
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bridge_passes_initialize_round_trip() {
        let cancel = CancellationToken::new();

        let (fake_leader_tx, bridge_leader_rx) = mpsc::unbounded_channel::<String>();
        let (bridge_leader_tx, mut fake_leader_rx) = mpsc::unbounded_channel::<String>();

        let bridge = bridge_channels(
            bridge_leader_tx,
            bridge_leader_rx,
            cancel.clone(),
            None,
            ReconnectPolicy::bounded(),
        )
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let fake_leader = tokio::spawn(async move {
            let msg = fake_leader_rx.recv().await.expect("expected a message");
            let req: serde_json::Value =
                serde_json::from_str(&msg).expect("invalid JSON from bridge");
            let id = req.get("id").expect("missing id").clone();

            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "1",
                    "serverCapabilities": {},
                    "authMethods": []
                }
            });
            fake_leader_tx
                .send(serde_json::to_string(&response).unwrap())
                .unwrap();
        });

        let _resp: acp::InitializeResponse = acp_send(
            acp::InitializeRequest::new(acp::ProtocolVersion::V1).client_capabilities(
                acp::ClientCapabilities::new()
                    .fs(acp::FileSystemCapabilities::new())
                    .terminal(false),
            ),
            &bridge.channel.tx,
        )
        .await
        .expect("initialize should succeed through bridge");

        fake_leader.await.unwrap();
        cancel.cancel();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bridge_cancels_on_leader_disconnect_without_reconnector() {
        let cancel = CancellationToken::new();

        let (leader_inbound_tx, bridge_leader_rx) = mpsc::unbounded_channel::<String>();
        let (bridge_leader_tx, _leader_outbound_rx) = mpsc::unbounded_channel::<String>();

        let bridge = bridge_channels(
            bridge_leader_tx,
            bridge_leader_rx,
            cancel.clone(),
            None,
            ReconnectPolicy::bounded(),
        )
        .unwrap();

        drop(leader_inbound_tx);

        tokio::time::timeout(std::time::Duration::from_secs(5), bridge.cancel.cancelled())
            .await
            .expect("bridge should cancel after leader disconnect");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn writer_does_not_break_pipe_on_send_failure() {
        let cancel = CancellationToken::new();

        let (leader_inbound_tx, bridge_leader_rx) = mpsc::unbounded_channel::<String>();
        let (bridge_leader_tx, leader_outbound_rx) = mpsc::unbounded_channel::<String>();

        let bridge = bridge_channels(
            bridge_leader_tx,
            bridge_leader_rx,
            cancel.clone(),
            None,
            ReconnectPolicy::bounded(),
        )
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Drop the outbound receiver so leader_tx.send() will fail in the writer.
        drop(leader_outbound_rx);

        // Spawn a background task that pushes an outbound ACP request.
        // acp_send blocks for a response that will never arrive (the outbound receiver is dropped)
        // The writer task should survive the failed send rather than breaking the simplex pipe
        let tx = bridge.channel.tx.clone();
        tokio::spawn(async move {
            let _ = acp_send(
                acp::InitializeRequest::new(acp::ProtocolVersion::V1).client_capabilities(
                    acp::ClientCapabilities::new()
                        .fs(acp::FileSystemCapabilities::new())
                        .terminal(false),
                ),
                &tx,
            )
            .await;
        });

        // Give the writer time to hit the send failure and sleep/retry.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // The bridge should still be alive; the writer must not have broken the pipe by exiting
        assert!(
            !cancel.is_cancelled(),
            "writer should survive send failures (reader not disconnected yet)"
        );

        // Now disconnect the leader fully so the reader triggers cancel.
        drop(leader_inbound_tx);
        tokio::time::timeout(std::time::Duration::from_secs(5), bridge.cancel.cancelled())
            .await
            .expect("bridge should eventually cancel after full disconnect");
    }
}
