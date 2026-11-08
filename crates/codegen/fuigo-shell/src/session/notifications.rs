use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use tokio::sync::{mpsc, watch};

use fuigo_acp_lib::AcpAgentGatewaySender as GatewaySender;

use crate::session::persistence::PersistenceMsg;

/// Session-scoped client gates shared by [`NotificationSender`] and [`crate::session::SessionHandle`].
#[derive(Clone)]
pub(crate) struct SessionClientCaps {
    pub status_line: Arc<AtomicBool>,
    pub user_message_echo: Arc<AtomicBool>,
    /// Where a folder-trust grant the session makes itself (`/trust`, the `/hooks` Trust action) is reported, so the
    /// agent settles it as it settles the modal's grant (design F5 §2 goal 1, §9.4 B2). `None`: nobody settles it.
    pub folder_trust_grants: Option<mpsc::UnboundedSender<SessionGrant>>,
}

impl SessionClientCaps {
    pub(crate) fn new(status_line: bool, user_message_echo: bool) -> Self {
        Self {
            status_line: Arc::new(AtomicBool::new(status_line)),
            user_message_echo: Arc::new(AtomicBool::new(user_message_echo)),
            folder_trust_grants: None,
        }
    }

    /// Report the session's own folder-trust grants to `grants`.
    pub(crate) fn with_folder_trust_grants(mut self, grants: mpsc::UnboundedSender<SessionGrant>) -> Self {
        self.folder_trust_grants = Some(grants);
        self
    }
}

/// A folder-trust grant a session made itself, for the agent's grant settlement (`MvpAgent::settle_session_grant`).
pub(crate) struct SessionGrant {
    pub session_id: agent_client_protocol::SessionId,
    pub cwd: std::path::PathBuf,
    pub outcome: fuigo_workspace::folder_trust::GrantOutcome,
}

pub(crate) struct NotificationSender {
    pub gateway: GatewaySender,
    /// When false, notifications are persisted but NOT forwarded to the client.
    /// Opened by `MvpAgent::load_session` when the client explicitly loads the session.
    pub gateway_enabled: Arc<AtomicBool>,
    pub persistence_tx: mpsc::UnboundedSender<PersistenceMsg>,
    pub disk_full: watch::Receiver<bool>,
    pub client_caps: SessionClientCaps,
}

impl NotificationSender {
    pub(crate) fn is_disk_full(&self) -> bool {
        *self.disk_full.borrow()
    }

    pub(crate) fn live_user_message_echo(&self) -> bool {
        self.client_caps
            .user_message_echo
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
pub(crate) fn idle_disk_full_rx() -> watch::Receiver<bool> {
    watch::channel(false).1
}
