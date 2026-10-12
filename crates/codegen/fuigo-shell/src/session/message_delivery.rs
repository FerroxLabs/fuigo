use std::sync::Arc;

use fuigo_message_delivery_core::{
    AgentSource, DeliveryEnvelope, DeliveryIdentity, HumanSource, Operation, OperationSet,
    authorize_operation,
};
use fuigo_tools::implementations::fuigo_build::task::coordinator::ActiveMessageAdmission;
use fuigo_tools::implementations::fuigo_build::task::types::{
    ActiveAgentMessageDelivery, ActiveAgentMessageOperation,
};
use tokio::sync::{mpsc, oneshot};

use super::SessionCommand;

#[cfg(test)]
thread_local! {
    static HUMAN_SENDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn take_human_send_count() -> usize {
    HUMAN_SENDS.with(|count| count.replace(0))
}

pub(crate) struct HumanMessageId(String);
pub(crate) struct HumanPromptId(String);
pub(crate) type HumanDeliveryIdentity = DeliveryIdentity<HumanMessageId, HumanPromptId>;

pub(crate) fn human_delivery_identity(prompt_id: String) -> HumanDeliveryIdentity {
    DeliveryIdentity::new(HumanMessageId(prompt_id.clone()), HumanPromptId(prompt_id))
}

pub(crate) struct HumanPromptContent {
    pub(crate) prompt_blocks: Vec<agent_client_protocol::ContentBlock>,
    pub(crate) prompt_mode: crate::session::plan_mode::PromptMode,
    pub(crate) artifact_upload_ctx: Option<crate::upload::manifest::ArtifactUploadContext>,
    pub(crate) client_identifier: Option<String>,
    pub(crate) screen_mode: Option<String>,
    pub(crate) verbatim: bool,
    pub(crate) traceparent: Option<String>,
    pub(crate) json_schema: Option<serde_json::Value>,
    pub(crate) tool_overrides_update: Option<fuigo_sampling_types::ToolOverridesUpdate>,
    /// `PromptOrigin::User` for a client prompt; `SchedulerFired` only for a ticket-verified cron fire.
    pub(crate) origin: crate::session::PromptOrigin,
    pub(crate) respond_to: oneshot::Sender<crate::session::commands::PromptTurnResult>,
    pub(crate) parsed_prompt_tx:
        Option<oneshot::Sender<crate::session::commands::ParsedPromptInfo>>,
}

impl HumanPromptContent {
    fn into_command(self, prompt_id: String) -> SessionCommand {
        SessionCommand::Prompt {
            prompt_id,
            prompt_blocks: self.prompt_blocks,
            prompt_mode: self.prompt_mode,
            artifact_upload_ctx: self.artifact_upload_ctx,
            client_identifier: self.client_identifier,
            screen_mode: self.screen_mode,
            verbatim: self.verbatim,
            traceparent: self.traceparent,
            json_schema: self.json_schema,
            send_now: false,
            admission: None,
            origin: self.origin,
            tool_overrides_update: self.tool_overrides_update,
            respond_to: self.respond_to,
            prompt_admitted: None,
            persist_ack: None,
            parsed_prompt_tx: self.parsed_prompt_tx,
        }
    }
}

pub(crate) struct ResidentHumanGrant {
    target_session_id: String,
}

impl ResidentHumanGrant {
    pub(crate) fn new(target_session_id: String) -> Self {
        Self { target_session_id }
    }
}

pub(crate) enum HumanDeliveryError {
    Rejected,
    Unsupported,
    ChannelClosed(String),
}

pub(crate) struct AgentMessageId(String);
pub(crate) struct AgentPromptId(String);
pub(crate) type AgentDeliveryIdentity = DeliveryIdentity<AgentMessageId, AgentPromptId>;

pub(crate) fn agent_delivery_identity(message_id: String) -> AgentDeliveryIdentity {
    DeliveryIdentity::new(
        AgentMessageId(message_id.clone()),
        AgentPromptId(format!("parent-message-{message_id}")),
    )
}

pub(crate) fn delivery_operation(operation: ActiveAgentMessageOperation) -> Operation {
    match operation {
        ActiveAgentMessageOperation::Queue => Operation::Queue,
        ActiveAgentMessageOperation::Steer => Operation::Steer,
        ActiveAgentMessageOperation::Interject => Operation::Interject,
    }
}

/// Peer envelopes handed to one session that its actor has not answered yet. Past this the hand-in answers
/// `rate_limited` without queueing, so a stalled actor cannot make the command channel grow without bound.
pub(crate) const MAX_PEER_IN_FLIGHT: usize = 32;

/// What the peer inbox may read about a session without asking its actor: whether it is opted in (set by the admission
/// state when its configuration changes) and how many peer envelopes are in flight. Shared by the session's admission
/// state, its handle and its directory entry.
#[derive(Debug, Default)]
pub(crate) struct PeerGate {
    opted_in: std::sync::atomic::AtomicBool,
    in_flight: std::sync::atomic::AtomicUsize,
    /// Packet 11: idle watches and hold notices for messages this session received (S9).
    pub(crate) watches: super::peer_watch::WatchBook,
}

impl PeerGate {
    pub(crate) fn set_opted_in(&self, value: bool) {
        self.opted_in.store(value, std::sync::atomic::Ordering::SeqCst);
    }

    /// The client's own opt-in, ignoring the remote-attached fact (the event pump's lifetime follows this).
    pub(crate) fn client_opted_in(&self) -> bool {
        self.opted_in.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) fn is_opted_in(&self) -> bool {
        // S4.1: while a remote client is attached to this process no session is addressable, whatever `opted_in` says.
        self.opted_in.load(std::sync::atomic::Ordering::SeqCst) && !crate::peer_inbox::driver::remote_attached()
    }

    pub(crate) fn in_flight(&self) -> usize {
        self.in_flight.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Take one in-flight slot, or `None` at the cap. The slot is returned when the guard drops (also if the caller's
    /// future is dropped).
    fn enter(self: &Arc<Self>) -> Option<PeerSlot> {
        use std::sync::atomic::Ordering::SeqCst;
        let mut cur = self.in_flight.load(SeqCst);
        loop {
            if cur >= MAX_PEER_IN_FLIGHT {
                return None;
            }
            match self.in_flight.compare_exchange(cur, cur + 1, SeqCst, SeqCst) {
                Ok(_) => return Some(PeerSlot(self.clone())),
                Err(now) => cur = now,
            }
        }
    }
}

/// One in-flight slot. It travels inside the session command, so it is freed when the ACTOR is done with the command (or
/// the command is dropped unread), not when the caller gives up waiting: an abandoned send still counts while queued.
#[derive(Debug)]
pub struct PeerSlot(Arc<PeerGate>);

impl Drop for PeerSlot {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Clone)]
pub(crate) struct MessageDeliveryHandle {
    cmd_tx: mpsc::UnboundedSender<SessionCommand>,
    target_session_id: String,
    gate: Arc<PeerGate>,
}

impl MessageDeliveryHandle {
    pub(crate) fn new(
        cmd_tx: mpsc::UnboundedSender<SessionCommand>,
        target_session_id: String,
    ) -> Self {
        Self {
            cmd_tx,
            target_session_id,
            gate: Arc::default(),
        }
    }

    /// Share the session's gate (opt-in state and in-flight count) with this handle.
    pub(crate) fn with_gate(mut self, gate: Arc<PeerGate>) -> Self {
        self.gate = gate;
        self
    }

    pub(crate) fn peer_gate(&self) -> &Arc<PeerGate> {
        &self.gate
    }

    pub(crate) fn send_human(
        &self,
        envelope: DeliveryEnvelope<
            HumanSource,
            ResidentHumanGrant,
            HumanPromptContent,
            HumanDeliveryIdentity,
        >,
    ) -> Result<(), HumanDeliveryError> {
        #[cfg(test)]
        HUMAN_SENDS.with(|count| count.set(count.get() + 1));
        let (operation, content, identity, grant) = envelope.into_parts();
        let (HumanMessageId(message_id), HumanPromptId(prompt_id)) = identity.into_parts();
        if grant.target_session_id != self.target_session_id || message_id != prompt_id {
            return Err(HumanDeliveryError::Rejected);
        }
        if authorize_operation(OperationSet::QUEUE, operation).is_err() {
            return Err(HumanDeliveryError::Unsupported);
        }
        self.cmd_tx
            .send(content.into_command(prompt_id))
            .map_err(|error| HumanDeliveryError::ChannelClosed(error.to_string()))
    }

    /// Deliver a message from a peer session into this session (peer messaging, in-process only).
    ///
    /// Refuses without sending anything when `features.peer_messaging` is off. The session runs the full admission decision
    /// (opt-in, inbound policy, sender and receiver mode, operator) before anything can reach the prompt queue; there is no
    /// path from this call to the queue that skips it. The peer inbox calls it in a later packet.
    pub(crate) async fn deliver_peer_message(
        &self,
        envelope: fuigo_peer::Envelope,
    ) -> super::peer_admission::PeerSubmit {
        self.hand_in_peer(envelope, false).await
    }

    /// Packet 11: a watch-only send (empty body + `watch`) goes through the same bounded hand-in and the same admission gate as a
    /// message, but is only judged: `Outcome(Delivered {})` means "admitted, register the watch"; nothing is stored or queued.
    pub(crate) async fn probe_peer_watch(&self, envelope: fuigo_peer::Envelope) -> super::peer_admission::PeerSubmit {
        self.hand_in_peer(envelope, true).await
    }

    async fn hand_in_peer(&self, envelope: fuigo_peer::Envelope, probe: bool) -> super::peer_admission::PeerSubmit {
        use super::peer_admission::PeerSubmit;
        use super::peer_message::peer_messaging_enabled;
        if !peer_messaging_enabled() {
            return PeerSubmit::Outcome(fuigo_peer::DeliveryOutcome::Rejected {
                reason: fuigo_peer::RejectReason::Unavailable,
            });
        }
        // Bounded hand-in: at the cap nothing is queued (the cap is per session, the counter is returned on drop).
        let Some(slot) = self.gate.enter() else {
            return PeerSubmit::Outcome(fuigo_peer::DeliveryOutcome::Rejected {
                reason: fuigo_peer::RejectReason::RateLimited,
            });
        };
        let (respond_to, response_rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(SessionCommand::PeerMessage {
                envelope: Box::new(envelope),
                respond_to,
                slot,
                probe,
            })
            .is_err()
        {
            return PeerSubmit::SessionClosed;
        }
        response_rx.await.unwrap_or(PeerSubmit::SessionClosed)
    }

    /// Record a typed notice about a message this session sent, in its notice ring. Fire and forget; nothing is stored
    /// with the flag off. The caller passes only an id it matched against its own sends.
    pub(crate) fn record_sent_notice(&self, message_id: &str, kind: fuigo_peer::NoticeKind) {
        if !super::peer_message::peer_messaging_enabled() {
            return;
        }
        let (respond_to, _rx) = oneshot::channel();
        let _ = self.cmd_tx.send(SessionCommand::PeerAdmission {
            cmd: super::peer_admission::PeerAdminCmd::SentNotice { message_id: message_id.to_owned(), kind },
            respond_to,
        });
    }

    /// Packet 11: tell the session a notice about a message it sent (`kind` `None` = `outcome unknown`); the session records it
    /// and wakes the model with fixed text. Fire and forget; nothing happens with the flag off.
    pub(crate) fn record_sent_notice_wake(&self, message_id: &str, kind: Option<fuigo_peer::NoticeKind>, target: String) {
        if !super::peer_message::peer_messaging_enabled() {
            return;
        }
        let (respond_to, _rx) = oneshot::channel();
        let _ = self.cmd_tx.send(SessionCommand::PeerAdmission {
            cmd: super::peer_admission::PeerAdminCmd::SentNoticeWake { message_id: message_id.to_owned(), kind, target },
            respond_to,
        });
    }

    pub(crate) async fn send(
        &self,
        envelope: DeliveryEnvelope<
            AgentSource,
            OwnedActiveDescendantGrant,
            Arc<str>,
            AgentDeliveryIdentity,
        >,
        receipt_sink: mpsc::Sender<crate::agent::subagent::PromptTurnReceipt>,
        parent_telemetry_ctx: fuigo_telemetry::TelemetryCtx,
    ) -> ActiveMessageAdmission {
        let (operation, content, identity, grant) = envelope.into_parts();
        let delivery = grant.delivery;
        if grant.target_session_id != self.target_session_id {
            return ActiveMessageAdmission::Rejected;
        }
        let message = delivery.message();
        let (AgentMessageId(message_id), AgentPromptId(prompt_id)) = identity.into_parts();
        if content != message.text
            || message_id != message.message_id
            || prompt_id != format!("parent-message-{}", message.message_id)
        {
            return ActiveMessageAdmission::Rejected;
        }
        if operation != delivery_operation(delivery.operation())
            || authorize_operation(OperationSet::QUEUE_STEER_AND_INTERJECT, operation).is_err()
        {
            return ActiveMessageAdmission::Unsupported;
        }

        let (respond_to, response_rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(SessionCommand::ParentAgentMessage {
                delivery,
                receipt_sink,
                parent_telemetry_ctx,
                respond_to,
            })
            .is_err()
        {
            return ActiveMessageAdmission::ChannelClosed;
        }
        response_rx
            .await
            .unwrap_or(ActiveMessageAdmission::ChannelClosed)
    }
}

pub(crate) struct OwnedActiveDescendantGrant {
    target_session_id: String,
    delivery: ActiveAgentMessageDelivery,
}

impl OwnedActiveDescendantGrant {
    pub(crate) fn new(target_session_id: String, delivery: ActiveAgentMessageDelivery) -> Self {
        Self {
            target_session_id,
            delivery,
        }
    }
}

/// Test support for the peer inbox (packet 8d): a delivery handle whose "session" reports every peer envelope on the
/// returned channel and answers it with `answer`; `None` never answers (the delivery call then waits forever).
/// Lives here so the `peer_inbox` sources never name the command type (their source-pin test forbids it).
/// Must be called inside a tokio runtime.
#[cfg(test)]
pub(crate) fn peer_test_session(
    session_id: &str,
    answer: Option<super::peer_admission::PeerSubmit>,
) -> (MessageDeliveryHandle, mpsc::UnboundedReceiver<fuigo_peer::Envelope>) {
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<SessionCommand>();
    let (seen_tx, seen_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut parked = Vec::new();
        while let Some(cmd) = cmd_rx.recv().await {
            if let SessionCommand::PeerMessage { envelope, respond_to, .. } = cmd {
                let _ = seen_tx.send(*envelope);
                match &answer {
                    Some(a) => {
                        let _ = respond_to.send(a.clone());
                    }
                    None => parked.push(respond_to),
                }
            }
        }
    });
    (MessageDeliveryHandle::new(cmd_tx, session_id.to_owned()).with_gate(opted_in_gate()), seen_rx)
}

/// A gate for a test session that is opted in (the directory only offers opted-in sessions).
#[cfg(test)]
pub(crate) fn opted_in_gate() -> Arc<PeerGate> {
    let gate = Arc::new(PeerGate::default());
    gate.set_opted_in(true);
    gate
}

/// Test support (packet 8e): a delivery handle whose "session" reports each typed sent-message notice it is given.
#[cfg(test)]
pub(crate) fn peer_test_notice_session(
    session_id: &str,
) -> (MessageDeliveryHandle, mpsc::UnboundedReceiver<(String, fuigo_peer::NoticeKind)>) {
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<SessionCommand>();
    let (seen_tx, seen_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(cmd) = cmd_rx.recv().await {
            if let SessionCommand::PeerAdmission { cmd, .. } = cmd {
                match cmd {
                    super::peer_admission::PeerAdminCmd::SentNotice { message_id, kind } => {
                        let _ = seen_tx.send((message_id, kind));
                    }
                    super::peer_admission::PeerAdminCmd::SentNoticeWake { message_id, kind: Some(kind), .. } => {
                        let _ = seen_tx.send((message_id, kind));
                    }
                    _ => {}
                }
            }
        }
    });
    (MessageDeliveryHandle::new(cmd_tx, session_id.to_owned()).with_gate(opted_in_gate()), seen_rx)
}

#[cfg(test)]
#[path = "message_delivery_tests.rs"]
mod tests;
