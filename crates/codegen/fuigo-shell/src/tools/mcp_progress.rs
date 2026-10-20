//! Forwards MCP `notifications/progress` for a tool call to the ACP client as a `tool_call_update` (issue #20).
//!
//! `fuigo-mcp` maps each in-flight progress token to its tool call and throttles (see `fuigo_mcp::progress`);
//! this module only renders one throttled update as ACP. The update carries no status or content, only
//! `_meta.progress = { progress, total?, message? }`, so it never changes how the call itself is shown.
//!
//! ## Ordering
//!
//! The tool call's own `tool_call` announcement travels the session actor's FIFO event queue (and its
//! replay buffer), so a `tool_call_update` sent straight to the gateway could overtake it and reach the
//! client before the call it refers to. The sink therefore enqueues each update on the same queue as
//! [`SessionEvent::Transient`]: the loop flushes the replay buffer first, then forwards it live-only
//! (never persisted, no `eventId`), in queue order behind the announcement.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use agent_client_protocol as acp;
use fuigo_mcp::progress::{McpProgressSink, McpToolProgress};
use tokio::sync::mpsc;

use crate::session::replay_events::SessionEvent;

/// `_meta` key on the `tool_call_update`.
pub(crate) const PROGRESS_META_KEY: &str = "progress";

pub(crate) fn progress_notification(
    session_id: &acp::SessionId,
    update: &McpToolProgress,
) -> acp::SessionNotification {
    let mut progress = serde_json::Map::new();
    progress.insert("progress".to_owned(), update.progress.into());
    if let Some(total) = update.total {
        progress.insert("total".to_owned(), total.into());
    }
    if let Some(message) = &update.message {
        progress.insert("message".to_owned(), message.clone().into());
    }
    let mut meta = acp::Meta::new();
    meta.insert(PROGRESS_META_KEY.to_owned(), progress.into());
    acp::SessionNotification::new(
        session_id.clone(),
        acp::SessionUpdate::ToolCallUpdate(
            acp::ToolCallUpdate::new(
                acp::ToolCallId::new(update.tool_call_id.clone()),
                acp::ToolCallUpdateFields::default(),
            )
            .meta(meta),
        ),
    )
}

/// The sink installed on the session's `McpState`. Fire-and-forget: a progress update is never worth blocking a tool on.
///
/// Updates ride the actor's event queue (see the module docs), so a `tool_call_update` never precedes its `tool_call`.
/// If the session loop is gone the update is dropped: nothing is left to show it to.
pub(crate) fn progress_sink(
    event_tx: mpsc::UnboundedSender<SessionEvent>,
    session_id: acp::SessionId,
    gateway_enabled: Arc<AtomicBool>,
) -> McpProgressSink {
    Arc::new(move |update| {
        if !gateway_enabled.load(Ordering::Relaxed) {
            return;
        }
        let _ = event_tx.send(SessionEvent::Transient(Box::new(progress_notification(
            &session_id,
            &update,
        ))));
    })
}

#[cfg(test)]
#[path = "mcp_progress_tests.rs"]
mod tests;
