//! Writeback push: async queue that flushes session updates to the backend.
//!
//! `RemoteSync` runs a background task that buffers ACP notifications and flushes them to the backend via [`BackendClient::save_session_data()`].
//!
//! ## Backpressure
//!
//! When the buffer exceeds [`MAX_PENDING`], the task attempts an emergency flush.
//! If that also fails (network down), the oldest messages are dropped to prevent unbounded memory growth.
//!
//! ## Drop behavior
//!
//! When `RemoteSync` is dropped, the sender half of the channel closes and the background task exits.
//! **Pending buffered messages are lost.**
//! This is acceptable because the local JSONL files are the source of truth: writeback is best-effort.

use crate::remote::BackendClient;
use crate::session::export::{ExportedMessage, ExportedMetadata};
use agent_client_protocol as acp;
use fuigo_telemetry::id::agent_id;
use tokio::sync::mpsc;

/// Max buffered notifications before triggering an emergency flush.
/// Sized to keep memory under ~50MB even with large notifications.
const MAX_PENDING: usize = 512;

/// How many oldest messages to drop when an emergency flush fails.
/// Dropping a batch (not one-by-one) avoids repeated failed flushes.
const DROP_BATCH_SIZE: usize = 64;

enum SyncMsg {
    Queue(Box<acp::SessionNotification>),
    /// An already-serialized upload message (a compaction checkpoint), kept in order with the queued notifications.
    QueueRaw(Box<ExportedMessage>),
    Flush,
    SetTitle {
        title: String,
        is_manual: bool,
    },
    /// Drop the cached title and manual flag so later flushes cannot re-advertise a pin the local summary no longer has.
    ClearTitle,
    SetModelId(String),
}

#[derive(Clone)]
pub struct RemoteSync {
    tx: mpsc::UnboundedSender<SyncMsg>,
}

impl RemoteSync {
    #[cfg(test)]
    pub(crate) fn test_observer() -> (Self, mpsc::UnboundedReceiver<acp::SessionNotification>) {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (observed_tx, observed_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if let SyncMsg::Queue(notification) = message {
                    let _ = observed_tx.send(*notification);
                }
            }
        });
        (Self { tx }, observed_rx)
    }

    #[cfg(test)]
    pub(crate) fn test_raw_observer() -> (Self, mpsc::UnboundedReceiver<ExportedMessage>) {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (observed_tx, observed_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if let SyncMsg::QueueRaw(raw) = message {
                    let _ = observed_tx.send(*raw);
                }
            }
        });
        (Self { tx }, observed_rx)
    }

    /// Metadata is included on every flush to keep the backend session row current.
    pub(crate) fn new(
        session_id: String,
        metadata: ExportedMetadata,
        client: BackendClient,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(sync_task(session_id, metadata, client, rx));
        Self { tx }
    }

    pub fn queue(&self, notification: acp::SessionNotification) {
        let _ = self.tx.send(SyncMsg::Queue(Box::new(notification)));
    }

    /// Queue a compaction checkpoint upload, ordered after everything queued before it.
    pub(crate) fn queue_checkpoint(&self, message: ExportedMessage) {
        let _ = self.tx.send(SyncMsg::QueueRaw(Box::new(message)));
        // A compaction can be the last thing a session does; do not leave its checkpoint buffered until the next flush.
        let _ = self.tx.send(SyncMsg::Flush);
    }

    pub fn flush(&self) {
        let _ = self.tx.send(SyncMsg::Flush);
    }

    pub fn set_title(&self, title: String) {
        let _ = self.tx.send(SyncMsg::SetTitle {
            title,
            is_manual: false,
        });
    }

    pub fn set_manual_title(&self, title: String) {
        let _ = self.tx.send(SyncMsg::SetTitle {
            title,
            is_manual: true,
        });
    }

    pub fn clear_title(&self) {
        let _ = self.tx.send(SyncMsg::ClearTitle);
    }

    pub(crate) fn set_model_id(&self, model_id: String) {
        let _ = self.tx.send(SyncMsg::SetModelId(model_id));
    }
}

async fn do_flush(
    client: &BackendClient,
    session_id: &str,
    metadata: &ExportedMetadata,
    pending: &mut Vec<Pending>,
) -> bool {
    if pending.is_empty() {
        return true;
    }

    let messages: Vec<ExportedMessage> = pending
        .iter()
        .map(|p| match p {
            Pending::Notification(n) => ExportedMessage::from_notification(n),
            Pending::Raw(m) => (**m).clone(),
        })
        .collect();

    match client
        .save_session_data(session_id, &messages, Some(metadata))
        .await
    {
        Ok(()) => {
            tracing::debug!(count = pending.len(), "Writeback: synced");
            pending.clear();

            // Link session to agent so the relay can route requests to it.
            if let Err(e) = client
                .upsert_session(session_id, metadata, &agent_id())
                .await
            {
                tracing::warn!(error = %e, "Writeback: failed to upsert session");
            }

            true
        }
        Err(e) => {
            tracing::warn!(error = %e, pending = pending.len(), "Writeback: flush failed");
            false
        }
    }
}

enum Pending {
    Notification(Box<acp::SessionNotification>),
    Raw(Box<ExportedMessage>),
}

/// Before buffering another message: past [`MAX_PENDING`], try an emergency flush, and drop the oldest batch if it fails.
async fn make_room(
    client: &BackendClient,
    session_id: &str,
    metadata: &mut ExportedMetadata,
    pending: &mut Vec<Pending>,
) {
    if pending.len() < MAX_PENDING {
        return;
    }
    tracing::warn!(pending = pending.len(), "Writeback: buffer full, attempting emergency flush");
    metadata.updated_at = Some(chrono::Utc::now().to_rfc3339());
    if !do_flush(client, session_id, metadata, pending).await {
        let dropped = pending.drain(0..DROP_BATCH_SIZE.min(pending.len())).count();
        tracing::error!(dropped = dropped, "Writeback: emergency flush failed, dropping oldest messages");
    }
}

async fn sync_task(
    session_id: String,
    mut metadata: ExportedMetadata,
    client: BackendClient,
    mut rx: mpsc::UnboundedReceiver<SyncMsg>,
) {
    let mut pending: Vec<Pending> = Vec::new();

    while let Some(msg) = rx.recv().await {
        match msg {
            SyncMsg::Queue(n) => {
                make_room(&client, &session_id, &mut metadata, &mut pending).await;
                pending.push(Pending::Notification(n));
            }
            SyncMsg::QueueRaw(m) => {
                make_room(&client, &session_id, &mut metadata, &mut pending).await;
                pending.push(Pending::Raw(m));
            }
            SyncMsg::Flush => {
                metadata.updated_at = Some(chrono::Utc::now().to_rfc3339());
                do_flush(&client, &session_id, &metadata, &mut pending).await;
            }
            SyncMsg::SetTitle { title, is_manual } => {
                metadata.title = Some(title);
                metadata.title_is_manual = is_manual.then_some(true);
                metadata.updated_at = Some(chrono::Utc::now().to_rfc3339());
                if let Err(e) = client
                    .save_session_data(&session_id, &[], Some(&metadata))
                    .await
                {
                    tracing::warn!(?e, "Writeback: failed to sync title to backend");
                } else if let Err(e) = client
                    .upsert_session(&session_id, &metadata, &agent_id())
                    .await
                {
                    // save_session_data does not write the session-row title (the backend upsert uses `title=None`)
                    // Without this upsert, `list` and `--resume` keep the pre-rename row until the next message flush
                    tracing::warn!(error = %e, "Writeback: failed to upsert session title");
                }
            }
            SyncMsg::ClearTitle => {
                // Empty string, not `None`: an omitted field leaves the backend's prior pin in place
                metadata.title = Some(String::new());
                metadata.title_is_manual = Some(false);
                metadata.updated_at = Some(chrono::Utc::now().to_rfc3339());
                if let Err(e) = client
                    .save_session_data(&session_id, &[], Some(&metadata))
                    .await
                {
                    tracing::warn!(?e, "Writeback: failed to clear title on backend");
                } else if let Err(e) = client
                    .upsert_session(&session_id, &metadata, &agent_id())
                    .await
                {
                    // Same row-title gap as SetTitle: save_session_data does not clear the session-row pin (the backend upsert uses `title=None`)
                    tracing::warn!(error = %e, "Writeback: failed to upsert cleared session title");
                }
            }
            SyncMsg::SetModelId(id) => {
                metadata.model_id = Some(id);
                metadata.updated_at = Some(chrono::Utc::now().to_rfc3339());
                if let Err(e) = client
                    .save_session_data(&session_id, &[], Some(&metadata))
                    .await
                {
                    tracing::warn!(?e, "Writeback: failed to sync model_id to backend");
                }
            }
        }
    }
}

#[cfg(test)]
mod checkpoint_flush_tests {
    use super::*;

    /// A compaction can be the last thing a session does, so queueing its checkpoint must also schedule a flush.
    #[test]
    fn queued_checkpoint_is_followed_by_a_flush() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sync = RemoteSync { tx };
        sync.queue_checkpoint(ExportedMessage { content: "{}".into(), timestamp: None });
        assert!(matches!(rx.try_recv(), Ok(SyncMsg::QueueRaw(_))));
        assert!(matches!(rx.try_recv(), Ok(SyncMsg::Flush)), "checkpoint left buffered without a flush");
    }
}
