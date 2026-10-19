use super::*;
use tokio::sync::mpsc;

fn update(progress: f64, total: Option<f64>, message: Option<&str>) -> McpToolProgress {
    McpToolProgress {
        server: "srv".to_owned(),
        tool_call_id: "call-9".to_owned(),
        progress,
        total,
        message: message.map(str::to_owned),
    }
}

/// The progress updates queued on the actor's event queue, as JSON.
fn drain(rx: &mut mpsc::UnboundedReceiver<SessionEvent>) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    while let Ok(event) = rx.try_recv() {
        match event {
            SessionEvent::Transient(notification) => {
                out.push(serde_json::to_value(&*notification).unwrap());
            }
            other => panic!("progress must ride the queue as Transient, got {other:?}"),
        }
    }
    out
}

#[test]
fn progress_becomes_a_tool_call_update_with_meta_progress_and_no_status() {
    let n = progress_notification(
        &acp::SessionId::new("s1"),
        &update(3.0, Some(10.0), Some("symbol 3 of 10")),
    );
    let v = serde_json::to_value(&n).unwrap();
    assert_eq!(v["sessionId"], "s1");
    assert_eq!(v["update"]["sessionUpdate"], "tool_call_update");
    assert_eq!(v["update"]["toolCallId"], "call-9");
    assert!(
        v["update"].get("status").is_none(),
        "status is untouched: {v}"
    );
    assert_eq!(
        v["update"]["_meta"]["progress"],
        serde_json::json!({ "progress": 3.0, "total": 10.0, "message": "symbol 3 of 10" })
    );
}

#[test]
fn unknown_total_and_message_are_omitted() {
    let n = progress_notification(&acp::SessionId::new("s1"), &update(1.0, None, None));
    let v = serde_json::to_value(&n).unwrap();
    assert_eq!(
        v["update"]["_meta"]["progress"],
        serde_json::json!({ "progress": 1.0 })
    );
}

#[test]
fn the_sink_queues_on_the_actor_event_queue_only_while_the_gateway_is_enabled() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let enabled = Arc::new(AtomicBool::new(true));
    let sink = progress_sink(tx, acp::SessionId::new("s1"), enabled.clone());

    sink(update(1.0, None, None));
    enabled.store(false, Ordering::Relaxed);
    sink(update(2.0, None, None));

    let got = drain(&mut rx);
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0]["update"]["_meta"]["progress"]["progress"], 1.0);
}

#[test]
fn the_sink_drops_updates_quietly_once_the_session_loop_is_gone() {
    let (tx, rx) = mpsc::unbounded_channel();
    drop(rx);
    let sink = progress_sink(
        tx,
        acp::SessionId::new("s1"),
        Arc::new(AtomicBool::new(true)),
    );
    sink(update(1.0, None, None));
}
