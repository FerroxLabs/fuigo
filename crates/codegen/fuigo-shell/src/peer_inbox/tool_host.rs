//! The session's `PeerHost` (packet 9): what `list_agents`, `send_message` and `/peers` talk to.
//!
//! [`SessionPeerHost`] is the production host (over 8e's process-global inbox); [`UnavailableHost`] answers for a subagent
//! or a double.

use std::sync::Arc;

use fuigo_peer::{Address, DeliveryOutcome, Envelope};
use fuigo_peer::host::{
    HostFuture, PeerHost, PeerHostError, PeerInboxStatus, PeerPage, PeerRow, Relation, SelfInfo, SendRequest, display_escape, render_list,
};

/// The typed reason shown while a remote client is attached to this leader (S4.1).
pub(crate) const REMOTE_ATTACHED: &str = "peer messaging is unavailable: a remote client is connected to this Fuigo";

/// The typed reason shown while no inbox is started.
pub(crate) const NOT_STARTED: &str = "the peer inbox has not been started in this process";

pub(crate) struct UnavailableHost {
    reason: String,
}

impl UnavailableHost {
    pub(crate) fn new(reason: impl Into<String>) -> Self {
        Self { reason: reason.into() }
    }
}

impl PeerHost for UnavailableHost {
    fn status(&self) -> PeerInboxStatus {
        PeerInboxStatus::Unavailable(self.reason.clone())
    }
    fn this_session(&self) -> Option<SelfInfo> {
        None
    }
    fn list(&self, _page: u32) -> HostFuture<'_, Result<PeerPage, PeerHostError>> {
        Box::pin(async move { Err(PeerHostError::Unavailable(self.reason.clone())) })
    }
    fn send(&self, _request: SendRequest) -> HostFuture<'_, Result<DeliveryOutcome, PeerHostError>> {
        Box::pin(async move { Err(PeerHostError::Unavailable(self.reason.clone())) })
    }
}

/// Longest the whole of other-host listing may take, and the longest one remote host or one remote send may take.
const REMOTE_LIST_TOTAL: std::time::Duration = std::time::Duration::from_secs(3);
const REMOTE_ONE: std::time::Duration = std::time::Duration::from_secs(1);
const REMOTE_SEND: std::time::Duration = std::time::Duration::from_secs(5);
/// Other hosts listed per call.
const MAX_REMOTE_HOSTS: usize = 8;

/// The production `PeerHost` of one main session: the process-global inbox ([`super::host::global`]) plus what only this
/// session knows (its denial ring and its live mode). Subagents get [`UnavailableHost`] instead.
pub(crate) struct SessionPeerHost {
    session_id: String,
    denials: fuigo_workspace::permission::DenialLog,
    mode: Arc<dyn Fn() -> fuigo_peer::PeerMode + Send + Sync>,
    /// S5.6: `(conversation id, received hop)` of the peer message in the running turn; `None` in a human-started turn.
    turn_conv: Arc<dyn Fn() -> Option<(String, u32)> + Send + Sync>,
    /// The session's real operator kind (Human / Auto / None), as packet 4 keeps it for this session.
    operator: Arc<dyn Fn() -> fuigo_peer::OperatorKind + Send + Sync>,
    seq: std::sync::atomic::AtomicU64,
}

impl SessionPeerHost {
    pub(crate) fn new(
        session_id: String,
        denials: fuigo_workspace::permission::DenialLog,
        mode: Arc<dyn Fn() -> fuigo_peer::PeerMode + Send + Sync>,
        turn_conv: Arc<dyn Fn() -> Option<(String, u32)> + Send + Sync>,
        operator: Arc<dyn Fn() -> fuigo_peer::OperatorKind + Send + Sync>,
    ) -> Self {
        Self { session_id, denials, mode, turn_conv, operator, seq: std::sync::atomic::AtomicU64::new(0) }
    }
}

impl SessionPeerHost {
    /// The one construction of an outgoing envelope for this session: the host fills sender, mode, the denial stamp and, from the
    /// session's own turn state, the conversation and hop (S5.6): a send from a peer-started turn continues that conversation one
    /// hop further; from a human-started turn it starts a new one at hop 0. Never from the tool input.
    pub(crate) fn build_envelope(&self, from: Address, from_name: String, from_ref: String, message_id: String, seq: u64, body: String) -> Envelope {
        use crate::session::peer_message::{OutgoingParts, build_outgoing_envelope};
        let (conversation_id, hop) = match (self.turn_conv)() {
            Some((conversation, received)) => (conversation, fuigo_peer::next_hop(fuigo_peer::TurnOrigin::Peer, received)),
            None => (message_id.clone(), fuigo_peer::next_hop(fuigo_peer::TurnOrigin::Human, 0)),
        };
        let parts = OutgoingParts {
            message_id,
            seq,
            from,
            from_name,
            from_auto_title: None,
            from_ref,
            from_mode: (self.mode)(),
            // The session's real operator kind: the receiver's admission compares (mode, operator).
            from_operator: (self.operator)(),
            conversation_id,
            hop,
            body,
        };
        build_outgoing_envelope(parts, &self.denials, fuigo_workspace::permission::mono_secs())
    }
}

/// This session's address, name and ref from the directory's listing (the directory keeps its map private).
fn self_info(inbox: &super::PeerInbox, session_id: &str) -> Option<(Address, String, String)> {
    for page in 0..4u32 {
        let (rows, more) = inbox.directory().list_page(page);
        if let Some(r) = rows.into_iter().find(|r| r.address.session_id() == session_id) {
            return Some((r.address, r.name, r.session_ref));
        }
        if !more {
            break;
        }
    }
    None
}

/// A same-host target takes the same path a message from another host takes: the connection host's `send`, which hands the
/// envelope to the session's delivery handle (`deliver_peer_message`) and nothing else.
#[cfg(any(unix, windows))]
async fn deliver_local(inbox: &super::PeerInbox, to: Address, envelope: Envelope, watch: bool) -> DeliveryOutcome {
    use super::conn::InboxHost;
    let host = super::directory::ConnHost::new(inbox.directory().clone());
    host.peer_hello(inbox.host_id());
    host.send_watched(to, envelope, watch).await
}

#[cfg(not(any(unix, windows)))]
async fn deliver_local(_inbox: &super::PeerInbox, _to: Address, _envelope: Envelope, _watch: bool) -> DeliveryOutcome {
    DeliveryOutcome::Rejected { reason: fuigo_peer::RejectReason::Unavailable }
}

fn status_of(s: super::host::PeerInboxStatus) -> PeerInboxStatus {
    use super::host::PeerInboxStatus as S;
    match s {
        S::Available { .. } => PeerInboxStatus::Ready,
        S::NotStarted => PeerInboxStatus::Unavailable(NOT_STARTED.to_owned()),
        S::Unavailable { reason } => PeerInboxStatus::Unavailable(super::host::reason_message(reason)),
    }
}

/// Other hosts' rows from the locator (display data only), minus ours.
#[cfg(unix)]
async fn other_hosts(inbox: &super::PeerInbox) -> Vec<fuigo_peer::HostRow> {
    let dir = inbox.peers_dir().clone();
    let bytes = tokio::task::spawn_blocking(move || super::locator::read_locator(&dir, super::reap::LOCATOR_NAME))
        .await
        .ok()
        .and_then(Result::ok)
        .flatten();
    let mut rows = super::reap::decode_rows(bytes.as_deref());
    rows.retain(|r| &r.host_id != inbox.host_id());
    rows.truncate(MAX_REMOTE_HOSTS);
    rows
}

#[cfg(windows)]
async fn other_hosts(inbox: &super::PeerInbox) -> Vec<fuigo_peer::HostRow> {
    inbox.other_hosts(MAX_REMOTE_HOSTS).await
}

/// One operation against the host a row names: the socket dial on unix, the pipe dial on Windows. A failure is `Err(())`
/// (the callers treat every failure alike: skip the host, or report `unavailable`).
#[cfg(unix)]
async fn dial_row(inbox: &super::PeerInbox, row: &fuigo_peer::HostRow, op: fuigo_peer::Op) -> Result<fuigo_peer::Reply, ()> {
    super::dial::dial(inbox.locations(), inbox.host_id(), &row.host_id, row.dir, op).await.map_err(|_| ())
}

#[cfg(windows)]
async fn dial_row(inbox: &super::PeerInbox, row: &fuigo_peer::HostRow, op: fuigo_peer::Op) -> Result<fuigo_peer::Reply, ()> {
    inbox.dial(&row.host_id, op).await.map_err(|_| ())
}

#[cfg(any(unix, windows))]
async fn remote_rows(inbox: &super::PeerInbox) -> Vec<PeerRow> {
    use fuigo_peer::{Op, Reply};
    let hosts = other_hosts(inbox).await;
    let mut out: Vec<PeerRow> = Vec::new();
    // Bounded in total: on the deadline whatever was gathered stays and the rest is skipped.
    let _ = tokio::time::timeout(REMOTE_LIST_TOTAL, async {
        for h in hosts {
            let one = dial_row(inbox, &h, Op::List { page: 0 });
            // An unreachable or slow host is skipped, never an error for the whole list.
            if let Ok(Ok(Reply::List { rows, .. })) = tokio::time::timeout(REMOTE_ONE, one).await {
                out.extend(rows.into_iter().map(|r| PeerRow {
                    address: r.address,
                    name: r.name,
                    session_ref: r.session_ref,
                    relation: Relation::Peer,
                }));
            }
        }
    })
    .await;
    out
}

#[cfg(not(any(unix, windows)))]
async fn remote_rows(_inbox: &super::PeerInbox) -> Vec<PeerRow> {
    Vec::new()
}

#[cfg(any(unix, windows))]
async fn remote_send(inbox: &super::PeerInbox, to: Address, envelope: Envelope, watch: bool) -> DeliveryOutcome {
    use fuigo_peer::{HostId, Op, Reply, RejectReason};
    let unavailable = DeliveryOutcome::Rejected { reason: RejectReason::Unavailable };
    let target = HostId::of(&to);
    let Some(row) = other_hosts(inbox).await.into_iter().find(|r| r.host_id == target) else {
        return unavailable;
    };
    let call = dial_row(inbox, &row, Op::Send { to, envelope, watch });
    match tokio::time::timeout(REMOTE_SEND, call).await {
        Ok(Ok(Reply::Send { outcome })) => outcome,
        _ => unavailable,
    }
}

#[cfg(not(any(unix, windows)))]
async fn remote_send(_inbox: &super::PeerInbox, _to: Address, _envelope: Envelope, _watch: bool) -> DeliveryOutcome {
    DeliveryOutcome::Rejected { reason: fuigo_peer::RejectReason::Unavailable }
}

/// The local page followed by the other hosts' rows, in all at most `MAX_LIST_ROWS`.
pub(crate) fn merge_rows(mut local: Vec<PeerRow>, remote: Vec<PeerRow>) -> Vec<PeerRow> {
    local.extend(remote);
    local.truncate(fuigo_peer::limits::MAX_LIST_ROWS);
    local
}

impl PeerHost for SessionPeerHost {
    fn status(&self) -> PeerInboxStatus {
        status_of(super::host::peer_inbox_status())
    }

    fn this_session(&self) -> Option<SelfInfo> {
        let inbox = super::host::global().inbox()?;
        let (address, name, session_ref) = self_info(&inbox, &self.session_id)?;
        Some(SelfInfo { address, name, session_ref, is_subagent: false })
    }

    fn list(&self, page: u32) -> HostFuture<'_, Result<PeerPage, PeerHostError>> {
        Box::pin(async move {
            if super::driver::remote_attached() {
                return Err(PeerHostError::Unavailable(REMOTE_ATTACHED.to_owned()));
            }
            let inbox = super::host::global().inbox().ok_or_else(|| PeerHostError::Unavailable(NOT_STARTED.to_owned()))?;
            let me = self_info(&inbox, &self.session_id).map(|(a, _, _)| a);
            let (rows, more) = inbox.directory().list_page(page);
            let mut out: Vec<PeerRow> = rows
                .into_iter()
                .filter(|r| Some(&r.address) != me.as_ref())
                .map(|r| PeerRow {
                    address: r.address,
                    name: r.name,
                    session_ref: r.session_ref,
                    relation: Relation::SameHost,
                })
                .collect();
            if page == 0 {
                out = merge_rows(out, remote_rows(&inbox).await);
            }
            Ok(PeerPage { rows: out, more })
        })
    }

    fn send(&self, request: SendRequest) -> HostFuture<'_, Result<DeliveryOutcome, PeerHostError>> {
        Box::pin(async move {
            // S4.1: a remote party must not use a session of this leader to message peers.
            if super::driver::remote_attached() {
                return Err(PeerHostError::Unavailable(REMOTE_ATTACHED.to_owned()));
            }
            let inbox = super::host::global().inbox().ok_or_else(|| PeerHostError::Unavailable(NOT_STARTED.to_owned()))?;
            let (from, from_name, from_ref) = self_info(&inbox, &self.session_id)
                .ok_or_else(|| PeerHostError::Unavailable("this session has no address yet".to_owned()))?;
            if request.to == from {
                return Ok(DeliveryOutcome::Rejected { reason: fuigo_peer::RejectReason::Unavailable });
            }
            let message_id = uuid::Uuid::new_v4().simple().to_string();
            let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            let envelope = self.build_envelope(from, from_name, from_ref, message_id.clone(), seq, request.message);
            if envelope.validate().is_err() {
                return Err(PeerHostError::Failed);
            }
            // Recorded before the send, so a notice that races the reply still finds this session (and, with a watch, the watch).
            let watch = request.watch;
            inbox.directory().note_sent_to(&self.session_id, &message_id, &request.to, watch);
            let outcome = if request.to.host_id() == inbox.host_id().as_str() {
                deliver_local(&inbox, request.to, envelope, watch).await
            } else {
                remote_send(&inbox, request.to, envelope, watch).await
            };
            // A watch is outstanding only when the receiver armed it (`watching`) or holds the message (it arms at release).
            if watch && !matches!(outcome, DeliveryOutcome::Watching {} | DeliveryOutcome::Held { .. }) {
                inbox.directory().forget_watch(&message_id);
            }
            Ok(outcome)
        })
    }
}

/// `/peers list` and `/peers status` (human). Same data as the tools, escaped the same way.
pub(crate) async fn peers_command(args: &str, host: &dyn PeerHost) -> String {
    match (args, host.status()) {
        ("status", PeerInboxStatus::Ready) => "Peer inbox: ready.".to_owned(),
        ("status", PeerInboxStatus::Unavailable(r)) => format!("Peer inbox: unavailable ({}).", display_escape(&r, 200)),
        ("list", PeerInboxStatus::Unavailable(r)) => format!("Peer messaging is unavailable: {}", display_escape(&r, 200)),
        ("list", PeerInboxStatus::Ready) => {
            let Some(me) = host.this_session() else {
                return "Peer messaging is unavailable: this session has no address yet".to_owned();
            };
            match host.list(0).await {
                Ok(page) => render_list(&me, 0, &page),
                Err(PeerHostError::Unavailable(r)) => format!("Peer messaging is unavailable: {}", display_escape(&r, 200)),
                Err(PeerHostError::Failed) => "The session list could not be read.".to_owned(),
            }
        }
        _ => "Usage: /peers list | status | clear-influence".to_owned(),
    }
}
