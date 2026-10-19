//! GitHub issue #20: MCP `notifications/progress` reach the owning tool call as throttled updates,
//! before the final result; unknown or late tokens are ignored; token entries are removed when the call ends.

use super::*;
use crate::progress::{
    CURRENT_PROGRESS, EARLY_STASH_CAP, McpProgressSink, McpToolProgress, PROGRESS_MIN_INTERVAL,
    ProgressBinding, ProgressRegistry, SETTLE_GRACE,
};
use rmcp::ServiceExt;
use rmcp::model::{NumberOrString, ProgressToken};

#[derive(Debug, Clone, PartialEq)]
enum Ev {
    Progress(McpToolProgress),
    Result,
}

type Events = Arc<parking_lot::Mutex<Vec<Ev>>>;

fn sink_into(events: &Events) -> McpProgressSink {
    let events = events.clone();
    Arc::new(move |p| events.lock().push(Ev::Progress(p)))
}

fn progress_values(events: &Events) -> Vec<f64> {
    events
        .lock()
        .iter()
        .filter_map(|e| match e {
            Ev::Progress(p) => Some(p.progress),
            Ev::Result => None,
        })
        .collect()
}

/// What the mock server does for a `tools/call`.
#[derive(Clone, Default)]
struct Script {
    /// `(progress, total, message)` sent in a burst right after the call arrives, gap apart.
    before: Vec<(f64, Option<f64>, Option<&'static str>)>,
    gap_ms: u64,
    /// Sent first, with a token nobody registered.
    unknown_token_first: bool,
    /// Pause between the last notification and the result. `None`: never answer.
    result_delay_ms: Option<u64>,
    /// Sent after the result, with the call's own (now settled) token.
    late: Vec<f64>,
    /// Pause before each `late` notification.
    late_gap_ms: u64,
}

fn progress_msg(
    token: &serde_json::Value,
    progress: f64,
    total: Option<f64>,
    message: Option<&str>,
) -> String {
    let mut params = serde_json::json!({ "progressToken": token, "progress": progress });
    if let Some(total) = total {
        params["total"] = total.into();
    }
    if let Some(message) = message {
        params["message"] = message.into();
    }
    format!(
        "{}\n",
        serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/progress", "params": params })
    )
}

async fn progress_service(client: &McpClient, script: Script) -> McpService {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (client_read, server_write) = tokio::io::duplex(64 * 1024);
    let (server_read, client_write) = tokio::io::duplex(64 * 1024);
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
            let id = msg.get("id").cloned().unwrap_or(serde_json::Value::Null);
            match msg.get("method").and_then(|m| m.as_str()) {
                Some("initialize") => {
                    let response = serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {
                        "protocolVersion": msg.pointer("/params/protocolVersion"),
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "progress", "version": "0.0.0" },
                    }});
                    let _ = writer.write_all(format!("{response}\n").as_bytes()).await;
                }
                Some("tools/call") => {
                    let token = msg
                        .pointer("/params/_meta/progressToken")
                        .cloned()
                        .expect("rmcp attaches a progressToken to every tools/call");
                    if script.unknown_token_first {
                        let line =
                            progress_msg(&serde_json::json!(987_654), 99.0, None, Some("stranger"));
                        let _ = writer.write_all(line.as_bytes()).await;
                    }
                    for (progress, total, message) in &script.before {
                        let line = progress_msg(&token, *progress, *total, *message);
                        let _ = writer.write_all(line.as_bytes()).await;
                        let _ = writer.flush().await;
                        if script.gap_ms > 0 {
                            tokio::time::sleep(std::time::Duration::from_millis(script.gap_ms))
                                .await;
                        }
                    }
                    let Some(delay) = script.result_delay_ms else {
                        continue;
                    };
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    let response = serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {
                        "content": [{ "type": "text", "text": "done" }],
                        "isError": false,
                    }});
                    let _ = writer.write_all(format!("{response}\n").as_bytes()).await;
                    let _ = writer.flush().await;
                    for progress in &script.late {
                        tokio::time::sleep(std::time::Duration::from_millis(script.late_gap_ms))
                            .await;
                        let line = progress_msg(&token, *progress, None, Some("late"));
                        let _ = writer.write_all(line.as_bytes()).await;
                        let _ = writer.flush().await;
                    }
                }
                _ => {}
            }
            let _ = writer.flush().await;
        }
    });
    // The client's own handler: it shares the client's progress registry.
    let handler = client.make_client_handler(REQUESTED_PROTOCOL_VERSION);
    let transport = rmcp::transport::async_rw::AsyncRwTransport::<RoleClient, _, _>::new(
        client_read,
        client_write,
    );
    Arc::new(handler.serve(transport).await.expect("handshake"))
}

async fn progress_client(script: Script) -> (Arc<McpClient>, McpErasedTool) {
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
    let client = Arc::new(McpClient::new_acp(
        "recording".to_string(),
        "srv_0".to_string(),
        Arc::new(NoInvoker),
        None,
        None,
    ));
    let service = progress_service(&client, script).await;
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
    (client, tool)
}

fn binding(client: &McpClient, events: &Events) -> ProgressBinding {
    ProgressBinding {
        registry: client.progress_registry().clone(),
        sink: sink_into(events),
        server: "recording".to_string(),
        tool_call_id: "call-42".to_string(),
    }
}

/// One agent-path tool call with progress bound, recording the final result in `events`.
async fn run_call(client: &Arc<McpClient>, tool: &McpErasedTool, events: &Events) {
    let ew = fuigo_session_events::EventWriter::noop();
    let (mut reconnect, mut is_timeout) = (false, false);
    let raw = serde_json::json!({});
    let result = CURRENT_PROGRESS
        .scope(
            binding(client, events),
            tool.try_call_tool(client, &raw, &mut reconnect, &mut is_timeout, &ew),
        )
        .await;
    result.expect("the call succeeds");
    events.lock().push(Ev::Result);
}

#[tokio::test]
async fn a_progress_burst_is_throttled_ordered_and_precedes_the_result() {
    let script = Script {
        before: (1..=5)
            .map(|n| (n as f64, Some(5.0), Some("step")))
            .collect(),
        result_delay_ms: Some(40),
        ..Default::default()
    };
    let (client, tool) = progress_client(script).await;
    let events: Events = Arc::default();
    run_call(&client, &tool, &events).await;

    let got = events.lock().clone();
    // First update goes straight out, the rest of the burst coalesces, the LAST one is always delivered.
    assert_eq!(progress_values(&events), vec![1.0, 5.0], "{got:?}");
    assert_eq!(
        got.last(),
        Some(&Ev::Result),
        "every update precedes the result: {got:?}"
    );
    let Ev::Progress(last) = &got[1] else {
        panic!("{got:?}")
    };
    assert_eq!(last.tool_call_id, "call-42");
    assert_eq!(last.server, "recording");
    assert_eq!(last.total, Some(5.0));
    assert_eq!(last.message.as_deref(), Some("step"));
}

#[tokio::test]
async fn updates_spaced_beyond_the_interval_are_all_delivered_in_order() {
    let script = Script {
        before: vec![
            (1.0, None, Some("a")),
            (2.0, None, Some("b")),
            (3.0, Some(3.0), Some("c")),
        ],
        gap_ms: PROGRESS_MIN_INTERVAL.as_millis() as u64 + 60,
        result_delay_ms: Some(40),
        ..Default::default()
    };
    let (client, tool) = progress_client(script).await;
    let events: Events = Arc::default();
    run_call(&client, &tool, &events).await;

    let got = events.lock().clone();
    assert_eq!(progress_values(&events), vec![1.0, 2.0, 3.0], "{got:?}");
    assert_eq!(got.last(), Some(&Ev::Result), "{got:?}");
}

#[tokio::test]
async fn a_notification_for_an_unknown_token_is_ignored() {
    let script = Script {
        unknown_token_first: true,
        before: vec![(1.0, None, None)],
        result_delay_ms: Some(40),
        ..Default::default()
    };
    let (client, tool) = progress_client(script).await;
    let events: Events = Arc::default();
    run_call(&client, &tool, &events).await;

    assert_eq!(
        progress_values(&events),
        vec![1.0],
        "the stranger's 99.0 must not reach the call"
    );
}

#[tokio::test]
async fn a_late_notification_after_completion_is_ignored_and_the_token_is_removed() {
    let script = Script {
        before: vec![(1.0, None, None)],
        result_delay_ms: Some(40),
        late: vec![2.0, 3.0],
        // Beyond the settling grace: a notification this late is not a handler queued behind the reply.
        late_gap_ms: SETTLE_GRACE.as_millis() as u64 + 150,
        ..Default::default()
    };
    let (client, tool) = progress_client(script).await;
    let events: Events = Arc::default();
    run_call(&client, &tool, &events).await;
    assert!(
        client.progress_registry().is_empty(),
        "no call is in flight once the reply is in"
    );
    tokio::time::sleep(SETTLE_GRACE * 8).await;
    assert_eq!(
        client.progress_registry().settling_len(),
        0,
        "the entry is removed once the grace period ends"
    );

    let got = events.lock().clone();
    assert_eq!(
        got.last(),
        Some(&Ev::Result),
        "nothing is delivered after completion: {got:?}"
    );
    assert_eq!(progress_values(&events), vec![1.0], "{got:?}");
}

#[tokio::test]
async fn a_cancelled_call_removes_its_token() {
    let script = Script {
        before: vec![(1.0, None, None)],
        result_delay_ms: None, // never answers
        ..Default::default()
    };
    let (client, tool) = progress_client(script).await;
    let events: Events = Arc::default();
    let ew = fuigo_session_events::EventWriter::noop();
    let (mut reconnect, mut is_timeout) = (false, false);
    let raw = serde_json::json!({});
    {
        let call = CURRENT_PROGRESS.scope(
            binding(&client, &events),
            tool.try_call_tool(&client, &raw, &mut reconnect, &mut is_timeout, &ew),
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(150), call)
                .await
                .is_err(),
            "the server never replies"
        );
        // The turn cancel drops the in-flight call here.
    }
    assert_eq!(progress_values(&events), vec![1.0]);
    assert!(
        client.progress_registry().is_empty(),
        "a dropped call removes its token"
    );
}

#[tokio::test]
async fn a_timed_out_call_removes_its_token() {
    let script = Script {
        result_delay_ms: None,
        ..Default::default()
    };
    let (client, tool) = progress_client(script).await;
    // Rebuild the tool timeout: 1 s via the client override is not reachable on this fixture,
    // so drive the helper with an explicit deadline.
    let events: Events = Arc::default();
    let service = {
        let state = client.state.lock().await;
        match &*state {
            ClientState::Ready { service, .. } => service.clone(),
            _ => unreachable!(),
        }
    };
    let _ = tool;
    let result = CURRENT_PROGRESS
        .scope(
            binding(&client, &events),
            call_tool_cancel_aware(
                &service,
                CallToolRequestParams::new("slow"),
                Some(std::time::Duration::from_millis(100)),
            ),
        )
        .await;
    assert!(matches!(result, Err(ServiceError::Timeout { .. })));
    assert!(
        client.progress_registry().is_empty(),
        "a timed-out call removes its token"
    );
}

fn token(n: i64) -> ProgressToken {
    ProgressToken(NumberOrString::Number(n))
}

fn param(token: ProgressToken, progress: f64) -> rmcp::model::ProgressNotificationParam {
    rmcp::model::ProgressNotificationParam::new(token, progress)
}

fn registry_binding(registry: &Arc<ProgressRegistry>, events: &Events) -> ProgressBinding {
    ProgressBinding {
        registry: registry.clone(),
        sink: sink_into(events),
        server: "s".to_string(),
        tool_call_id: "t".to_string(),
    }
}

#[tokio::test(start_paused = true)]
async fn a_burst_inside_the_interval_delivers_the_first_and_the_last_after_the_interval() {
    let registry = Arc::new(ProgressRegistry::default());
    let events: Events = Arc::default();
    let _guard = registry.register(0, token(1), &registry_binding(&registry, &events));

    for n in 1..=4 {
        registry.deliver(0, param(token(1), n as f64));
    }
    assert_eq!(
        progress_values(&events),
        vec![1.0],
        "only the first leaves at once"
    );
    tokio::time::sleep(PROGRESS_MIN_INTERVAL + std::time::Duration::from_millis(1)).await;
    assert_eq!(
        progress_values(&events),
        vec![1.0, 4.0],
        "the trailing flush delivers the last"
    );
    tokio::time::sleep(PROGRESS_MIN_INTERVAL * 4).await;
    assert_eq!(
        progress_values(&events),
        vec![1.0, 4.0],
        "nothing is duplicated"
    );
}

#[tokio::test(start_paused = true)]
async fn settling_delivers_the_pending_update_and_later_notifications_are_dropped() {
    let registry = Arc::new(ProgressRegistry::default());
    let events: Events = Arc::default();
    let guard = registry.register(0, token(7), &registry_binding(&registry, &events));
    registry.deliver(0, param(token(7), 1.0));
    registry.deliver(0, param(token(7), 2.0));
    assert_eq!(progress_values(&events), vec![1.0]);

    drop(guard);
    assert_eq!(
        progress_values(&events),
        vec![1.0, 2.0],
        "the pending update flushes on settle"
    );
    assert!(registry.is_empty());

    registry.deliver(0, param(token(7), 3.0));
    registry.deliver(0, param(token(404), 1.0));
    tokio::time::sleep(PROGRESS_MIN_INTERVAL * 2).await;
    assert_eq!(
        progress_values(&events),
        vec![1.0, 2.0],
        "unknown and late tokens are ignored"
    );
}

#[tokio::test(start_paused = true)]
async fn a_stale_non_increasing_update_never_overwrites_a_newer_one() {
    let registry = Arc::new(ProgressRegistry::default());
    let events: Events = Arc::default();
    let _guard = registry.register(0, token(3), &registry_binding(&registry, &events));
    registry.deliver(0, param(token(3), 5.0));
    registry.deliver(0, param(token(3), 3.0));
    registry.deliver(0, param(token(3), 5.0));
    tokio::time::sleep(PROGRESS_MIN_INTERVAL * 2).await;
    assert_eq!(progress_values(&events), vec![5.0]);
}

// ---- finding 1: tokens stay unique across reconnections ----

fn call_binding(client: &McpClient, events: &Events, id: &str) -> ProgressBinding {
    ProgressBinding {
        tool_call_id: id.to_string(),
        ..binding(client, events)
    }
}

async fn ready_service(client: &McpClient) -> McpService {
    match &*client.state.lock().await {
        ClientState::Ready { service, .. } => service.clone(),
        _ => unreachable!(),
    }
}

/// rmcp restarts its token counter on every connection, so two connections of one client hand out the same token
/// number. The old call's updates must reach the old call, the new call must see none of them, and the new call
/// finishing must not remove the old call's registration.
#[tokio::test]
async fn calls_on_reconnected_connections_with_the_same_token_number_do_not_cross() {
    let old_script = Script {
        before: vec![(1.0, None, Some("old-a")), (2.0, None, Some("old-b"))],
        gap_ms: PROGRESS_MIN_INTERVAL.as_millis() as u64 + 50,
        result_delay_ms: Some(50),
        ..Default::default()
    };
    let (client, _tool) = progress_client(old_script).await;
    let old_service = ready_service(&client).await;
    let new_service = progress_service(
        &client,
        Script {
            result_delay_ms: Some(400),
            ..Default::default()
        },
    )
    .await;
    let (old_events, new_events): (Events, Events) = (Arc::default(), Arc::default());

    let old_call = CURRENT_PROGRESS.scope(
        call_binding(&client, &old_events, "call-old"),
        call_tool_cancel_aware(&old_service, CallToolRequestParams::new("slow"), None),
    );
    let new_call = async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        CURRENT_PROGRESS
            .scope(
                call_binding(&client, &new_events, "call-new"),
                call_tool_cancel_aware(&new_service, CallToolRequestParams::new("slow"), None),
            )
            .await
    };
    let (old_result, new_result) = tokio::join!(old_call, new_call);
    old_result.expect("old call succeeds");
    new_result.expect("new call succeeds");

    assert_eq!(
        progress_values(&old_events),
        vec![1.0, 2.0],
        "the old call keeps its updates after the new call registered and finished"
    );
    assert_eq!(
        progress_values(&new_events),
        Vec::<f64>::new(),
        "the new call must not receive the old call's updates"
    );
    for ev in old_events.lock().iter() {
        if let Ev::Progress(p) = ev {
            assert_eq!(p.tool_call_id, "call-old");
        }
    }
}

#[tokio::test(start_paused = true)]
async fn the_same_token_on_two_generations_is_two_calls() {
    let registry = Arc::new(ProgressRegistry::default());
    let (old, new): (Events, Events) = (Arc::default(), Arc::default());
    let old_guard = registry.register(1, token(0), &registry_binding(&registry, &old));
    let new_guard = registry.register(2, token(0), &registry_binding(&registry, &new));

    registry.deliver(1, param(token(0), 1.0));
    registry.deliver(2, param(token(0), 1.0));
    assert_eq!(progress_values(&old), vec![1.0]);
    assert_eq!(progress_values(&new), vec![1.0]);

    drop(new_guard);
    tokio::time::sleep(PROGRESS_MIN_INTERVAL).await;
    registry.deliver(1, param(token(0), 2.0));
    registry.deliver(2, param(token(0), 2.0));
    assert_eq!(
        progress_values(&old),
        vec![1.0, 2.0],
        "the new call's guard must not remove the old registration"
    );
    assert_eq!(progress_values(&new), vec![1.0], "the removed call is deaf");
    drop(old_guard);
    assert!(registry.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_guard_removes_only_its_own_entry() {
    let registry = Arc::new(ProgressRegistry::default());
    let (first, second): (Events, Events) = (Arc::default(), Arc::default());
    let first_guard = registry.register(1, token(9), &registry_binding(&registry, &first));
    // Same key registered again (it must not happen, but the first guard must stay harmless if it does).
    let _second_guard = registry.register(1, token(9), &registry_binding(&registry, &second));
    drop(first_guard);
    registry.deliver(1, param(token(9), 1.0));
    assert_eq!(progress_values(&second), vec![1.0]);
    assert!(progress_values(&first).is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_stale_throttle_timer_never_flushes_a_newer_registration() {
    let registry = Arc::new(ProgressRegistry::default());
    let (old, new): (Events, Events) = (Arc::default(), Arc::default());
    let old_guard = registry.register(1, token(0), &registry_binding(&registry, &old));
    registry.deliver(1, param(token(0), 1.0));
    registry.deliver(1, param(token(0), 2.0)); // arms the old call's trailing timer at +250 ms
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    // The old call is cancelled; a new call takes the same key.
    drop(old_guard);
    let _new_guard = registry.register(1, token(0), &registry_binding(&registry, &new));
    registry.deliver(1, param(token(0), 1.0));
    registry.deliver(1, param(token(0), 2.0)); // the new call's own timer fires at +350 ms

    tokio::time::sleep(std::time::Duration::from_millis(160)).await; // t = 260: the stale timer has fired
    assert_eq!(
        progress_values(&new),
        vec![1.0],
        "the old call's timer must not flush the new call's pending update early"
    );
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(progress_values(&new), vec![1.0, 2.0]);
}

// ---- finding 2: nothing is lost at either end of a call ----

#[tokio::test(start_paused = true)]
async fn progress_that_beats_the_token_bind_is_replayed_highest_first_and_in_order() {
    let registry = Arc::new(ProgressRegistry::default());
    let events: Events = Arc::default();
    let claim = registry.claim(1, &registry_binding(&registry, &events));

    // The request is on the wire; the server answers with progress before rmcp's token reaches the call.
    registry.deliver(1, param(token(5), 1.0));
    registry.deliver(1, param(token(5), 3.0));
    registry.deliver(1, param(token(5), 2.0));
    assert!(
        progress_values(&events).is_empty(),
        "nobody owns token 5 yet"
    );

    let _guard = claim.bind(token(5));
    assert_eq!(
        progress_values(&events),
        vec![3.0],
        "the early report is delivered on bind (the highest one; the stale 2.0 is not)"
    );
    registry.deliver(1, param(token(5), 4.0));
    tokio::time::sleep(PROGRESS_MIN_INTERVAL * 2).await;
    assert_eq!(progress_values(&events), vec![3.0, 4.0]);
}

#[tokio::test(start_paused = true)]
async fn early_progress_is_held_only_for_a_pending_claim_and_only_for_its_generation() {
    let registry = Arc::new(ProgressRegistry::default());
    let events: Events = Arc::default();

    // No claim outstanding: unknown tokens are ignored, not held for a later registration.
    registry.deliver(1, param(token(1), 1.0));
    let guard = registry
        .claim(1, &registry_binding(&registry, &events))
        .bind(token(1));
    assert!(progress_values(&events).is_empty());
    drop(guard);

    // A claim dropped without a bind (the send failed) releases what it held.
    let claim = registry.claim(1, &registry_binding(&registry, &events));
    registry.deliver(1, param(token(2), 1.0));
    drop(claim);
    let _guard = registry
        .claim(1, &registry_binding(&registry, &events))
        .bind(token(2));
    assert!(progress_values(&events).is_empty());

    // Another connection's progress under the same number is not this call's.
    let claim = registry.claim(3, &registry_binding(&registry, &events));
    registry.deliver(4, param(token(7), 1.0));
    let _guard7 = claim.bind(token(7));
    assert!(progress_values(&events).is_empty());
}

#[tokio::test(start_paused = true)]
async fn the_early_stash_is_bounded() {
    let registry = Arc::new(ProgressRegistry::default());
    let events: Events = Arc::default();
    // Two claims, so binding the first leaves one outstanding and the stash alive.
    let first = registry.claim(1, &registry_binding(&registry, &events));
    let second = registry.claim(1, &registry_binding(&registry, &events));
    for n in 0..(EARLY_STASH_CAP as i64 + 10) {
        registry.deliver(1, param(token(n), 1.0));
    }
    let _held = first.bind(token(0));
    assert_eq!(progress_values(&events), vec![1.0], "within the cap: held");
    let _overflow = second.bind(token(EARLY_STASH_CAP as i64 + 5));
    assert_eq!(
        progress_values(&events),
        vec![1.0],
        "beyond the cap: not held"
    );
}

#[tokio::test(start_paused = true)]
async fn a_completed_call_keeps_accepting_for_the_grace_period_then_ignores() {
    let registry = Arc::new(ProgressRegistry::default());
    let events: Events = Arc::default();
    let guard = registry.register(1, token(8), &registry_binding(&registry, &events));
    registry.deliver(1, param(token(8), 1.0));
    registry.deliver(1, param(token(8), 2.0));
    assert_eq!(progress_values(&events), vec![1.0]);

    guard.complete();
    assert_eq!(
        progress_values(&events),
        vec![1.0, 2.0],
        "the pending update flushes as the reply arrives"
    );
    assert!(registry.is_empty(), "no call is in flight");
    assert_eq!(registry.settling_len(), 1);

    // The final report was queued behind the reply: its handler runs now, inside the grace period.
    registry.deliver(1, param(token(8), 3.0));
    tokio::time::sleep(SETTLE_GRACE + std::time::Duration::from_millis(1)).await;
    assert_eq!(
        progress_values(&events),
        vec![1.0, 2.0, 3.0],
        "a handler queued behind the reply still delivers"
    );
    assert_eq!(
        registry.settling_len(),
        0,
        "the entry is gone after the grace"
    );

    registry.deliver(1, param(token(8), 4.0));
    tokio::time::sleep(PROGRESS_MIN_INTERVAL * 2).await;
    assert_eq!(
        progress_values(&events),
        vec![1.0, 2.0, 3.0],
        "later is ignored"
    );
}

#[tokio::test(start_paused = true)]
async fn a_dropped_guard_removes_at_once_without_a_grace_period() {
    let registry = Arc::new(ProgressRegistry::default());
    let events: Events = Arc::default();
    let guard = registry.register(1, token(8), &registry_binding(&registry, &events));
    drop(guard);
    assert_eq!(registry.settling_len(), 0);
    registry.deliver(1, param(token(8), 1.0));
    assert!(progress_values(&events).is_empty());
}
