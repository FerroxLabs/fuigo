//! P194 (U16): a tool call that the caller stops waiting for (turn cancel, timeout, server replaced) tells the MCP
//! server with `notifications/cancelled`; a completed call sends none. Red first.

use super::*;
use rmcp::ServiceExt;

/// A scripted MCP server over an in-memory duplex that answers `initialize`, records every
/// message it receives, and answers `tools/call` only when `reply` is set.
async fn recording_service(
    reply: bool,
) -> (McpService, Arc<parking_lot::Mutex<Vec<serde_json::Value>>>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let received: Arc<parking_lot::Mutex<Vec<serde_json::Value>>> = Arc::default();
    let (client_read, server_write) = tokio::io::duplex(64 * 1024);
    let (server_read, client_write) = tokio::io::duplex(64 * 1024);
    let sink = received.clone();
    tokio::spawn(async move {
        let mut reader = BufReader::new(server_read);
        let mut writer = server_write;
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                return;
            }
            let Ok(msg) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
                continue;
            };
            sink.lock().push(msg.clone());
            let id = msg.get("id").cloned().unwrap_or(serde_json::Value::Null);
            let response = match msg.get("method").and_then(|m| m.as_str()) {
                Some("initialize") => {
                    Some(serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {
                        "protocolVersion": msg.pointer("/params/protocolVersion"),
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "recording", "version": "0.0.0" },
                    }}))
                }
                Some("tools/call") if reply => {
                    Some(serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {
                        "content": [{ "type": "text", "text": "done" }],
                        "isError": false,
                    }}))
                }
                _ => None,
            };
            if let Some(response) = response {
                let mut encoded = serde_json::to_string(&response).unwrap();
                encoded.push('\n');
                let _ = writer.write_all(encoded.as_bytes()).await;
                let _ = writer.flush().await;
            }
        }
    });
    let handler = FuigoClientHandler {
        info: McpClient::make_client_info(
            "recording",
            /* advertise_elicitation */ false,
            REQUESTED_PROTOCOL_VERSION,
        ),
        server_name: "recording".to_string(),
        notify_tx: Arc::new(parking_lot::Mutex::new(None)),
        elicitation_tx: Arc::new(parking_lot::Mutex::new(None)),
    };
    let transport = rmcp::transport::async_rw::AsyncRwTransport::<RoleClient, _, _>::new(
        client_read,
        client_write,
    );
    let service: McpService = Arc::new(handler.serve(transport).await.expect("handshake"));
    (service, received)
}

fn cancellations(received: &parking_lot::Mutex<Vec<serde_json::Value>>) -> Vec<serde_json::Value> {
    messages_with_method(received, "notifications/cancelled", "/params/requestId")
}

fn call_ids(received: &parking_lot::Mutex<Vec<serde_json::Value>>) -> Vec<serde_json::Value> {
    messages_with_method(received, "tools/call", "/id")
}

/// The `pointer` field of every recorded message whose `method` is `method`.
fn messages_with_method(
    received: &parking_lot::Mutex<Vec<serde_json::Value>>,
    method: &str,
    pointer: &str,
) -> Vec<serde_json::Value> {
    received
        .lock()
        .iter()
        .filter(|m| m.get("method").and_then(|v| v.as_str()) == Some(method))
        .map(|m| {
            m.pointer(pointer)
                .cloned()
                .unwrap_or(serde_json::Value::Null)
        })
        .collect()
}

/// A `tools/call` the recording server has received and will never answer.
async fn pending_call(
    service: &McpService,
    timeout: Option<std::time::Duration>,
) -> impl std::future::Future<Output = Result<rmcp::model::CallToolResponse, ServiceError>> {
    let mut call = Box::pin(call_tool_cancel_aware(
        service,
        CallToolRequestParams::new("slow"),
        timeout,
    ));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut call)
            .await
            .is_err(),
        "the server never replies, so the call must still be pending"
    );
    call
}

#[tokio::test]
async fn dropped_tool_call_sends_one_cancellation_for_its_request() {
    let (service, received) = recording_service(/* reply */ false).await;
    let call = pending_call(&service, Some(std::time::Duration::from_secs(30))).await;

    // An aborted turn drops its call the same way
    drop(call);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let ids = call_ids(&received);
    assert_eq!(ids.len(), 1, "{ids:?}");
    assert_eq!(
        cancellations(&received),
        ids,
        "one cancel, for the dropped request"
    );
}

#[tokio::test]
async fn dropped_call_still_sends_its_cancellation_when_the_service_is_dropped_too() {
    let (service, received) = recording_service(/* reply */ false).await;
    let call = pending_call(&service, None).await;

    // Stopping or replacing a server mid-call drops the call and then the service.
    // No spawned task runs between the two drops.
    drop(call);
    drop(service);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let ids = call_ids(&received);
    assert_eq!(ids.len(), 1, "{ids:?}");
    assert_eq!(
        cancellations(&received),
        ids,
        "the cancel is written before the service loop shuts down"
    );
}

#[tokio::test]
async fn timed_out_tool_call_is_classified_and_cancelled_once() {
    let (service, received) = recording_service(/* reply */ false).await;
    let round = call_tool_cancel_aware(
        &service,
        CallToolRequestParams::new("slow"),
        Some(std::time::Duration::from_millis(50)),
    )
    .await;
    assert!(matches!(round, Err(ServiceError::Timeout { .. })));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let ids = call_ids(&received);
    assert_eq!(
        cancellations(&received),
        ids,
        "rmcp's timeout cancel, and nothing more"
    );
}

#[tokio::test(start_paused = true)]
async fn tool_call_without_timeout_waits_for_the_reply() {
    let (service, _) = recording_service(/* reply */ false).await;
    let mut call = Box::pin(call_tool_cancel_aware(
        &service,
        CallToolRequestParams::new("slow"),
        None,
    ));

    // With time paused, this day-long timeout fires as soon as every task is idle.
    // Only a timeout inside the call could end it sooner.
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(24 * 60 * 60), &mut call)
            .await
            .is_err(),
        "no timeout was requested, so only the reply may settle the call"
    );
}

#[tokio::test]
async fn completed_tool_call_sends_no_cancellation() {
    let (service, received) = recording_service(/* reply */ true).await;
    let round = call_tool_cancel_aware(
        &service,
        CallToolRequestParams::new("fast"),
        Some(std::time::Duration::from_secs(5)),
    )
    .await;
    assert!(matches!(
        round,
        Ok(rmcp::model::CallToolResponse::Complete(_))
    ));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(cancellations(&received).is_empty());
}

/// The agent's own tool path (`try_call_tool`), not only the helper: a client that is `Ready` on the recording server.
async fn ready_tool_client(
    timeout_sec: Option<u64>,
    reply: bool,
) -> (
    Arc<McpClient>,
    McpErasedTool,
    Arc<parking_lot::Mutex<Vec<serde_json::Value>>>,
) {
    struct NoInvoker;
    #[async_trait::async_trait]
    impl crate::acp_transport::AcpReverseInvoker for NoInvoker {
        async fn invoke(
            &self,
            _server_id: &str,
            _message: serde_json::Value,
            _timeout: std::time::Duration,
        ) -> Result<serde_json::Value, String> {
            Err("never used: the client is already Ready".to_string())
        }
    }
    let (service, received) = recording_service(reply).await;
    let overrides = McpClientTimeoutOverrides {
        tool_timeout_sec: timeout_sec,
        ..Default::default()
    };
    let client = Arc::new(McpClient::new_acp(
        "recording".to_string(),
        "srv_0".to_string(),
        Arc::new(NoInvoker),
        Some(&overrides),
        None,
    ));
    *client.state.lock().await = ClientState::Ready {
        service,
        _connected: fuigo_telemetry::activity::MCP_SERVERS_CONNECTED.enter(),
    };
    let tool = McpErasedTool {
        tool: McpTool::new(
            "slow".to_string(),
            "slow".to_string(),
            "recording".to_string(),
            Arc::new(Mutex::new(McpState::new(vec![]))),
            serde_json::json!({}),
            None,
        ),
    };
    (client, tool, received)
}

#[tokio::test]
async fn a_dropped_agent_tool_call_tells_the_server_it_was_cancelled() {
    let (client, tool, received) = ready_tool_client(None, /* reply */ false).await;
    let ew = fuigo_session_events::EventWriter::noop();
    let raw = serde_json::json!({});
    let (mut reconnect, mut is_timeout) = (false, false);
    {
        let mut call = Box::pin(tool.try_call_tool(&client, &raw, &mut reconnect, &mut is_timeout, &ew));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut call)
                .await
                .is_err(),
            "the server never replies, so the call must still be pending"
        );
        // A turn cancel drops the in-flight call here.
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let ids = call_ids(&received);
    assert_eq!(ids.len(), 1, "{ids:?}");
    assert_eq!(cancellations(&received), ids, "one cancel, for the dropped request");
}

#[tokio::test]
async fn an_agent_tool_call_that_times_out_is_flagged_and_cancelled_once() {
    let (client, tool, received) = ready_tool_client(Some(1), /* reply */ false).await;
    let ew = fuigo_session_events::EventWriter::noop();
    let (mut reconnect, mut is_timeout) = (false, false);
    let err = tool
        .try_call_tool(&client, &serde_json::json!({}), &mut reconnect, &mut is_timeout, &ew)
        .await
        .expect_err("the server never replies");
    assert!(is_timeout, "a timeout must be flagged");
    assert!(err.to_string().contains("timed out after 1 seconds"), "{err}");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let ids = call_ids(&received);
    assert_eq!(ids.len(), 1, "{ids:?}");
    assert_eq!(cancellations(&received), ids, "exactly one cancel for the timed-out request");
}

// ---- Round 2 (Grok r1, U16): a server that stops reading its stdin must not hold the call or the connection ----

/// A scripted server on the production stdio transport (`ResilientRwTransport`). When `stall` is set it stops
/// reading its stdin right after it accepts the first `tools/call`, over a 32-byte pipe: the next write the
/// client makes (a cancel line) cannot complete. Otherwise it keeps reading, like the tests above.
async fn resilient_service(
    stall: bool,
) -> (McpService, Arc<parking_lot::Mutex<Vec<serde_json::Value>>>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let received: Arc<parking_lot::Mutex<Vec<serde_json::Value>>> = Arc::default();
    let (client_read, server_write) = tokio::io::duplex(64 * 1024);
    let (server_read, client_write) = tokio::io::duplex(32);
    let sink = received.clone();
    tokio::spawn(async move {
        let mut reader = BufReader::new(server_read);
        let mut writer = server_write;
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                return;
            }
            let Ok(msg) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
                continue;
            };
            sink.lock().push(msg.clone());
            if msg.get("method").and_then(|m| m.as_str()) == Some("initialize") {
                let response = serde_json::json!({ "jsonrpc": "2.0", "id": msg["id"], "result": {
                    "protocolVersion": msg.pointer("/params/protocolVersion"),
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "stalling", "version": "0.0.0" },
                }});
                let mut encoded = serde_json::to_string(&response).unwrap();
                encoded.push('\n');
                let _ = writer.write_all(encoded.as_bytes()).await;
                let _ = writer.flush().await;
            }
            if stall && msg.get("method").and_then(|m| m.as_str()) == Some("tools/call") {
                // Accepted the call; never read stdin again, and keep the pipe open.
                std::future::pending::<()>().await;
            }
        }
    });
    let handler = FuigoClientHandler {
        info: McpClient::make_client_info("stalling", false, REQUESTED_PROTOCOL_VERSION),
        server_name: "stalling".to_string(),
        notify_tx: Arc::new(parking_lot::Mutex::new(None)),
        elicitation_tx: Arc::new(parking_lot::Mutex::new(None)),
    };
    let transport = ResilientRwTransport::new(
        client_read,
        client_write,
        "stalling".to_string(),
        fuigo_session_events::EventWriter::noop(),
    );
    let service: McpService = Arc::new(handler.serve(transport).await.expect("handshake"));
    (service, received)
}

#[tokio::test]
async fn a_timed_out_call_returns_at_the_deadline_when_the_server_stopped_reading() {
    let (service, _received) = resilient_service(/* stall */ true).await;
    let started = std::time::Instant::now();
    let round = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        call_tool_cancel_aware(
            &service,
            CallToolRequestParams::new("slow"),
            Some(std::time::Duration::from_millis(300)),
        ),
    )
    .await
    .expect("the call must return at its deadline, not wait for the cancel write");
    assert!(matches!(round, Err(ServiceError::Timeout { .. })), "{round:?}");
    assert!(started.elapsed() < std::time::Duration::from_millis(1200));
}

#[tokio::test]
async fn a_later_call_is_not_held_longer_than_the_cancel_bound_by_a_stalled_server() {
    let (service, _received) = resilient_service(/* stall */ true).await;
    let first = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        call_tool_cancel_aware(
            &service,
            CallToolRequestParams::new("slow"),
            Some(std::time::Duration::from_millis(200)),
        ),
    )
    .await
    .expect("first call returns at its deadline");
    assert!(matches!(first, Err(ServiceError::Timeout { .. })));

    // The second call queues behind the stuck cancel write only until the bound; then the
    // connection is closed and the call (and every later one) fails fast. (It starts after the
    // cancel write began; a request that wins the mutex first is itself an unbounded write, as on integration.)
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let started = std::time::Instant::now();
    let second = tokio::time::timeout(
        CANCEL_NOTIFY_TIMEOUT + std::time::Duration::from_secs(2),
        call_tool_cancel_aware(
            &service,
            CallToolRequestParams::new("again"),
            Some(std::time::Duration::from_secs(60)),
        ),
    )
    .await
    .expect("the second call must not wait on the stuck write past the 3 s bound");
    assert!(second.is_err(), "{second:?}");
    assert!(started.elapsed() < CANCEL_NOTIFY_TIMEOUT + std::time::Duration::from_secs(1));

    let third_started = std::time::Instant::now();
    let third = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        call_tool_cancel_aware(&service, CallToolRequestParams::new("later"), None),
    )
    .await
    .expect("a closed connection fails calls at once");
    assert!(third.is_err(), "{third:?}");
    assert!(third_started.elapsed() < std::time::Duration::from_secs(1));
}

#[tokio::test]
async fn a_timed_out_call_to_a_reading_server_sends_exactly_one_cancel_with_the_timeout_reason() {
    let (service, received) = resilient_service(/* stall */ false).await;
    let round = call_tool_cancel_aware(
        &service,
        CallToolRequestParams::new("slow"),
        Some(std::time::Duration::from_millis(50)),
    )
    .await;
    assert!(matches!(round, Err(ServiceError::Timeout { .. })));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let ids = call_ids(&received);
    assert_eq!(ids.len(), 1, "{ids:?}");
    assert_eq!(cancellations(&received), ids, "exactly one cancel");
    let reasons = messages_with_method(&received, "notifications/cancelled", "/params/reason");
    assert_eq!(reasons, vec![serde_json::json!("request timeout")]);
}

#[tokio::test]
async fn dropping_a_call_as_it_times_out_still_sends_one_cancel() {
    // The caller's own deadline races the call's: whichever wins, the request id is cancelled once.
    for outer_ms in [40u64, 50, 60] {
        let (service, received) = resilient_service(/* stall */ false).await;
        let call = call_tool_cancel_aware(
            &service,
            CallToolRequestParams::new("slow"),
            Some(std::time::Duration::from_millis(50)),
        );
        let _ = tokio::time::timeout(std::time::Duration::from_millis(outer_ms), call).await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let ids = call_ids(&received);
        assert_eq!(cancellations(&received), ids, "outer {outer_ms} ms: {ids:?}");
        assert_eq!(ids.len(), 1);
    }
}
