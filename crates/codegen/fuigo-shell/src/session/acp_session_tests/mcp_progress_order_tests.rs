//! GitHub issue #20 lifecycle ordering: an MCP `tool_call_update` carrying progress never reaches the client
//! before the `tool_call` it refers to, even when the progress arrives while the announcement is still queued.

use super::replay_buffer_send_update_tests::make_replay_send_update_fixture;
use super::*;
use fuigo_mcp::progress::McpToolProgress;

fn kind(n: &acp::SessionNotification) -> (&'static str, String) {
    match &n.update {
        acp::SessionUpdate::ToolCall(tc) => ("tool_call", tc.tool_call_id.0.to_string()),
        acp::SessionUpdate::ToolCallUpdate(tu) => {
            ("tool_call_update", tu.tool_call_id.0.to_string())
        }
        _ => ("other", String::new()),
    }
}

/// The announcement is queued (not yet drained by the loop) when the first progress arrives; what the client
/// sees must still be `tool_call` first, then every progress update, in order.
#[tokio::test(flavor = "current_thread")]
async fn progress_never_overtakes_the_queued_tool_call_announcement() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let mut fixture = make_replay_send_update_fixture().await;
            let actor = fixture.actor;
            let sink = crate::tools::mcp_progress::progress_sink(
                actor.event_tx.clone(),
                actor.session_info.id.clone(),
                actor.notifications.gateway_enabled.clone(),
            );

            // The tool call is announced through the actor's queue, as `prepare_tool_call` does...
            actor
                .send_update(
                    acp::SessionUpdate::ToolCall(
                        acp::ToolCall::new(acp::ToolCallId::new("call-7"), "mcp_tool")
                            .status(acp::ToolCallStatus::Pending),
                    ),
                    None,
                )
                .await;
            // ...and progress arrives before the loop has drained it.
            for progress in [1.0, 2.0] {
                sink(McpToolProgress {
                    server: "srv".to_owned(),
                    tool_call_id: "call-7".to_owned(),
                    progress,
                    total: None,
                    message: None,
                });
            }

            let mut replay_buffer = crate::agent::update_chunk_merge::ReplayBuffer::new(None);
            while let Ok(event) = fixture.event_rx.try_recv() {
                actor.handle_session_event(event, &mut replay_buffer).await;
            }
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }

            let sent = fixture.sent.lock().await;
            let order: Vec<_> = sent.iter().map(kind).collect();
            assert_eq!(
                order,
                vec![
                    ("tool_call", "call-7".to_owned()),
                    ("tool_call_update", "call-7".to_owned()),
                    ("tool_call_update", "call-7".to_owned()),
                ],
                "a tool_call_update must never precede its tool_call"
            );
            let progress: Vec<_> = sent[1..]
                .iter()
                .filter_map(|n| match &n.update {
                    acp::SessionUpdate::ToolCallUpdate(tu) => tu
                        .meta
                        .as_ref()
                        .and_then(|m| m.get("progress"))
                        .and_then(|p| p.get("progress"))
                        .and_then(|v| v.as_f64()),
                    _ => None,
                })
                .collect();
            assert_eq!(progress, vec![1.0, 2.0]);
        })
        .await;
}
