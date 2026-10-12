//! Admission of a message from a peer session (peer messaging, packet 3; in-process only).
//!
//! The message is committed to the existing protected prompt queue as its own origin (`PromptOrigin::PeerMessage`, authority
//! `PeerUntrusted`). A busy session promotes it at the next safe point exactly as a parent message is promoted; an idle session
//! starts a turn for it. Nothing here opens a socket or registers a tool, and with `features.peer_messaging` off it refuses.

use super::prompt_queue::PreparedDelivery;
use super::*;
use crate::session::peer_admission::{
    Live, PeerAdminCmd, PeerAdminReply, PeerSubmit, ReleaseOutcome, Submitted, msg_key, now_mono,
};
use crate::session::peer_message::{PeerAdmission, PeerRefusal, peer_messaging_enabled, wrap_peer_message};
use fuigo_peer::{DeliveryOutcome, RejectReason};

impl SessionActor {
    /// The RAW enqueue of an envelope that admission has already decided to admit and tracked. It is private to this module so
    /// the only way in for a peer envelope is [`Self::submit_peer_message`] (and the drain of released messages): there is no
    /// second entry that skips the decision.
    async fn enqueue_admitted_peer_row(
        self: &Arc<Self>,
        envelope: fuigo_peer::Envelope,
        completion_tx: mpsc::UnboundedSender<super::turn_task::TurnCompletionMsg>,
    ) -> PeerAdmission {
        if !peer_messaging_enabled() {
            return PeerAdmission::Refused(PeerRefusal::FeatureOff);
        }
        if envelope.validate().is_err() {
            return PeerAdmission::Refused(PeerRefusal::Invalid);
        }
        self.ensure_prefix_ready().await;
        let wrapped = wrap_peer_message(&envelope);
        let prompt_id = format!("peer-message-{}", envelope.message_id);
        // Decision 35: the blocking prompt hook runs on a real peer message, before anything is queued.
        if self.peer_prompt_hook_refuses(&envelope, &wrapped, &prompt_id).await {
            return PeerAdmission::Refused(PeerRefusal::Policy);
        }
        let input_origin = InputOrigin::new(super::PromptOrigin::PeerMessage {
            message_id: envelope.message_id.clone(),
            from: envelope.from.to_string(),
        });
        let prompt_blocks = vec![acp::ContentBlock::Text(acp::TextContent::new(wrapped))];
        let queue_meta = crate::session::prompt_queue::QueueEntryMeta {
            id: prompt_id.clone(),
            version: 0,
            owner: None,
            last_editor: None,
            kind: "peer_message".to_string(),
            text: Self::queue_text_from_blocks(&prompt_blocks),
            combined_texts: None,
        };
        let (turn_result_tx, _turn_result_rx) = oneshot::channel();
        let item = InputItem {
            prompt_id: prompt_id.clone(),
            prompt_blocks,
            prompt_mode: PromptMode::Agent,
            trace_gcs_config: None,
            artifact_tracker: None,
            client_identifier: None,
            screen_mode: None,
            // Already wrapped: no `<user_query>` envelope, no truncation of the closing tag.
            verbatim: true,
            json_schema: None,
            input_origin,
            task_wake_fallback: None,
            tool_overrides_update: None,
            respond_to: turn_result_tx,
            persist_ack: None,
            parsed_prompt_tx: None,
            initial_child_prompt_ready: None,
            queue_meta: Some(queue_meta),
            // Protected: visible, never editable, reorderable or send-now by the user.
            queue_mutation_policy: QueueMutationPolicy::new(true, false),
            send_now: false,
            traceparent: None,
        };
        // S6.6: the baseline is complete before this text can be visible to the model; no state lock is held across the wait.
        // Normally a no-op (the callers above ran it); if a clear raced in and the read now times out, the row is not queued.
        self.ensure_peer_baseline().await;
        if self.peer_admission.integrity_tripped() {
            return PeerAdmission::Refused(PeerRefusal::Policy);
        }
        {
            let mut state = self.state.lock().await;
            // S6.1: admitting a peer message makes the session peer-influenced (until a typed human command or a fresh
            // context). Set BEFORE the commit and under the same lock, so no state shows a queued row with the flag clear.
            self.mark_peer_influenced();
            // S7.3: a released message's denials are carried by this session until `/peers clear-influence`; S7.4: the model
            // may refuse this message by id.
            self.permissions.peer_influence().denials().carry(&envelope.message_id, &envelope.denied_recently);
            self.peer_admission.mirror_carry(&envelope.message_id, &envelope.denied_recently);
            self.peer_admission.note_delivered(&envelope);
            self.commit_queued_delivery(&mut state, PreparedDelivery(item));
        }
        self.persist_peer_state().await;
        // Idle: starts the turn. Busy: returns early, and the next safe point promotes the row
        // (`promote_parent_agent_messages` takes peer rows too).
        // P189 A2: a held session (parking, parked or unparking) starts nothing here (`maybe_start_running_task`
        // returns at its park gate) and the row runs at unpark; a child of a held root is restarted when the root is
        // released. The decision and the delivery report are exactly the same.
        self.wake_peer_rows_after_hold(completion_tx.clone());
        Self::maybe_start_running_task(self.clone(), completion_tx).await;
        PeerAdmission::Admitted { prompt_id }
    }

    /// A child of a parking or parked root has no park entry of its own, so nothing wakes it at the root's unpark.
    /// When a peer row is queued under such a root, wait (off the actor loop) until the root is released, then
    /// start the queue. No-op for a session that is not under a park.
    ///
    /// Armed at enqueue AND at every blocked start (`maybe_start_running_task`), one waiter per session at a time:
    /// the waiter forgets itself before it restarts the queue, so a restart that blocks again re-arms.
    pub(super) fn wake_peer_rows_after_hold(self: &Arc<Self>, completion_tx: mpsc::UnboundedSender<super::turn_task::TurnCompletionMsg>) {
        static ARMED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> = std::sync::OnceLock::new();
        let armed = ARMED.get_or_init(Default::default);
        let id = self.session_info.id.0.to_string();
        if !crate::session::quiesce::is_ancestor_holding(&id) {
            return;
        }
        if !armed.lock().unwrap_or_else(|e| e.into_inner()).insert(id.clone()) {
            return;
        }
        let session = self.clone();
        tokio::task::spawn_local(async move {
            let mut changes = crate::session::quiesce::subscribe();
            while crate::session::quiesce::is_ancestor_holding(&id) {
                tokio::select! {
                    changed = changes.changed() => {
                        if changed.is_err() {
                            armed.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
                            return;
                        }
                    }
                    () = completion_tx.closed() => {
                        armed.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
                        return;
                    }
                }
            }
            armed.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
            Self::maybe_start_running_task(session, completion_tx).await;
        });
    }

    /// Scheduled-fire rows start nothing while this session or an ancestor has a park entry in ANY phase
    /// (`Unparking` included): only the client prompt that began an un-park finishes it. Wait (off the actor loop)
    /// until no entry is left, then start the queue. One waiter per session; no-op when no entry exists.
    pub(super) fn wake_scheduled_rows_after_park(self: &Arc<Self>, completion_tx: mpsc::UnboundedSender<super::turn_task::TurnCompletionMsg>) {
        static ARMED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> = std::sync::OnceLock::new();
        let armed = ARMED.get_or_init(Default::default);
        let id = self.session_info.id.0.to_string();
        if !crate::session::quiesce::has_park_in_tree(&id) {
            return;
        }
        if !armed.lock().unwrap_or_else(|e| e.into_inner()).insert(id.clone()) {
            return;
        }
        let session = self.clone();
        tokio::task::spawn_local(async move {
            let mut changes = crate::session::quiesce::subscribe();
            while crate::session::quiesce::has_park_in_tree(&id) {
                tokio::select! {
                    changed = changes.changed() => {
                        if changed.is_err() {
                            armed.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
                            return;
                        }
                    }
                    () = completion_tx.closed() => {
                        armed.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
                        return;
                    }
                }
            }
            armed.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
            Self::maybe_start_running_task(session, completion_tx).await;
        });
    }
}

/// S6.1 restore, run once per actor build over the history already loaded for replay (no extra read). A main session whose
/// last state item says influenced is influenced again, with the feature on or off (B2 item 3: with it off the protected-edit
/// guard stays on, and `true` comes back so the caller can say why); a subagent keeps its parent's flag.
pub(super) fn restore_peer_influence(
    flag: &fuigo_workspace::permission::PeerInfluence,
    is_subagent: bool,
    feature_on: bool,
    conversation: &[crate::sampling::ConversationItem],
) -> bool {
    if is_subagent || !fuigo_sampling_types::history_is_peer_influenced(conversation) {
        return false;
    }
    flag.set(true);
    !feature_on
}

/// S7 state read from a stored history (decided by marker item kind only), applied once per actor build before any tool request
/// is decided. A subagent shares the root's log and restores nothing. Read early in `spawn.rs` (the history moves into the chat
/// state afterwards) and applied with [`Self::apply`] where the admission state is built.
#[derive(Default)]
pub(super) struct PeerStoredState {
    carried: fuigo_sampling_types::PeerCarriedState,
    denials: Vec<fuigo_sampling_types::PeerDenialRecord>,
}

impl PeerStoredState {
    pub(super) fn from_history(is_subagent: bool, conversation: &[crate::sampling::ConversationItem]) -> Self {
        if is_subagent {
            return Self::default();
        }
        Self {
            carried: fuigo_sampling_types::history_peer_carried(conversation),
            denials: fuigo_sampling_types::history_peer_denials(conversation),
        }
    }

    /// Receiver side: the carried denials go back into the denial log and the refused senders into admission (with the feature
    /// off too: fail closed, like the influenced flag). Sender side: the ring is rebuilt from the `peer_denial` markers; an
    /// entry stamps until 30 minutes of WALL-CLOCK time after the denial (older entries are not restored; a stored time in the
    /// future counts as now). The ring runs on the monotonic clock, so an entry is re-recorded `age` seconds before `now_mono`.
    /// Limit: `mono_secs()` starts at 0 in each process, so within the first `age` seconds of a process an entry can stamp
    /// somewhat longer than 30 minutes (it errs toward holding the message). Returns (carried restored, ring entries restored).
    pub(super) fn apply(
        &self,
        log: &fuigo_workspace::permission::DenialLog,
        admission: &crate::session::peer_admission::PeerAdmissionState,
        now_wall: u64,
        now_mono: u64,
    ) -> (usize, usize) {
        if !self.carried.is_empty() {
            for (kind, hash, id) in &self.carried.carried {
                log.carry(id, &[fuigo_peer::DenialStamp { tool_kind: kind.clone(), target_hash: hash.clone() }]);
            }
            admission.restore_peer_state(&self.carried);
        }
        let mut n = 0usize;
        for d in &self.denials {
            let age = now_wall.saturating_sub(d.wall_secs);
            if age < fuigo_peer::limits::DENIAL_STAMP_SECS {
                // The whole key set goes back as one denial (S7 round 2: a multi-file read keeps every file's key).
                let keys = d
                    .keys
                    .iter()
                    .map(|(kind, hash)| fuigo_workspace::permission::DenialKey { kind: kind.clone(), hash: hash.clone() })
                    .collect();
                log.record_keys(keys, now_mono.saturating_sub(age));
                n += 1;
            }
        }
        // Written already: the next sync must not write them again.
        admission.set_denials_synced(log.entries());
        (self.carried.carried.len(), n)
    }
}

/// S6.6 restore (item 1): a main session whose stored history ends with the integrity-hold marker (not followed by a cleared
/// marker) comes back with the `integrity` hold up, before any peer message can be decided. Returns whether it was set.
pub(super) fn restore_peer_integrity_hold(
    admission: &crate::session::peer_admission::PeerAdmissionState,
    is_subagent: bool,
    conversation: &[crate::sampling::ConversationItem],
) -> bool {
    if !peer_integrity_hold_from_history(is_subagent, conversation) {
        return false;
    }
    admission.integrity_restore_tripped();
    true
}

/// Whether the stored history of a main session leaves the integrity hold up (decided by item kind).
pub(super) fn peer_integrity_hold_from_history(is_subagent: bool, conversation: &[crate::sampling::ConversationItem]) -> bool {
    !is_subagent && fuigo_sampling_types::history_has_peer_integrity_hold(conversation)
}

/// Result of `/peers clear-influence`.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum PeerClear {
    Cleared,
    Outstanding,
    NotRecorded,
}

impl SessionActor {
    /// S6.1: set the peer-influenced state (idempotent). The flag is shared with the permission handle and the tool context.
    pub(super) fn mark_peer_influenced(&self) {
        // Nothing is written here: the stored peer message (item kind `peer_message`) IS the persisted state.
        self.permissions.set_peer_influenced(true);
        self.tool_context.peer_influence.set(true);
        self.arm_peer_integrity();
    }

    /// Belt and braces (S6.1): a turn started or joined by a peer input keeps the flag set for its whole duration. Called where
    /// such a turn asks for a permission; costs one atomic read when no peer turn is running.
    pub(super) fn remark_if_peer_turn(&self) {
        if self.peer_admission.peer_turn_in_flight() {
            self.mark_peer_influenced();
        }
    }

    /// Whether this session still has peer work outstanding: a peer row queued, held for release, approved and waiting for
    /// the drain, passed to a turn (the in-flight ring) or a turn started or joined by a peer input is running.
    /// The caller holds the state lock, the lock under which every path that sets the flag runs.
    fn peer_work_outstanding_locked(&self, state: &State) -> bool {
        state.pending_inputs.iter().any(|i| i.input_origin.as_prompt_origin().is_peer())
            || self.peer_admission.has_undelivered()
            || self.peer_admission.peer_turn_in_flight()
    }

    /// S6.1 exit: only a typed human command ends the state (the caller has checked the origin). A fresh context is a new session.
    ///
    /// THE RULE: the check and the clear are ONE critical section with every path that can set the flag (admission, safe-point
    /// promotion, turn start all run under `state`), and the cleared marker and the flag never disagree in the unsafe direction.
    /// So under the state lock: (1) verify no peer work is outstanding (including the in-flight ring and a running peer turn),
    /// (2) put the cleared marker on the chat-state queue (the send happens here, under the lock), (3) clear the flag. Then
    /// release the lock and wait for the append ack. A peer row admitted or promoted after the lock is released sets the flag
    /// again and its `peer_message` item is queued behind the marker on the same FIFO, so the stored order is marker, then peer
    /// item. If the append fails the flag is set again (fail closed).
    pub(super) async fn clear_peer_influence(&self) -> PeerClear {
        self.prune_peer_tracking().await;
        let ack = {
            let state = self.state.lock().await;
            if self.peer_work_outstanding_locked(&state) {
                return PeerClear::Outstanding;
            }
            // `push_user_message_and_ack` sends its command before its first await, so polling it once enqueues the marker
            // while the lock is held (ordering); the same future is awaited for the ack after the lock is released.
            let mut append = Box::pin(
                self.chat_state_handle
                    .push_user_message_and_ack(crate::sampling::ConversationItem::peer_influence_marker(false)),
            );
            let first = std::future::poll_fn(|cx| std::task::Poll::Ready(append.as_mut().poll(cx))).await;
            if matches!(first, std::task::Poll::Ready(None)) {
                return PeerClear::NotRecorded;
            }
            self.permissions.set_peer_influenced(false);
            self.tool_context.peer_influence.set(false);
            (first, append)
        };
        #[cfg(test)]
        run_clear_pause_hook().await;
        let (first, append) = ack;
        let acked = match first {
            std::task::Poll::Ready(r) => r,
            std::task::Poll::Pending => append.await,
        };
        #[cfg(test)]
        let acked = if take_clear_append_failure() { None } else { acked };
        if acked.is_none() {
            self.mark_peer_influenced();
            // The cleared marker may or may not be stored: history must agree with the kept lists either way.
            self.rewrite_kept_peer_state().await;
            return PeerClear::NotRecorded;
        }
        // S7.3, S7.4: the carried denials and the refused-sender holds end only now that the cleared marker is stored (on a failed
        // append nothing changed). If a peer message re-flagged the session meanwhile, the carried list stays (fail closed).
        let kept = {
            let _state = self.state.lock().await;
            if !self.tool_context.peer_influence.is_set() {
                self.permissions.peer_influence().denials().clear_carried();
                self.peer_admission.clear_peer_state();
                false
            } else {
                true
            }
        };
        if kept {
            // The cleared marker is stored but memory kept the lists: store them again AFTER it (resume reads the last marker).
            self.rewrite_kept_peer_state().await;
        }
        // S6.6: the human's clear ends the watch and the `integrity` hold.
        self.peer_admission.integrity_reset();
        PeerClear::Cleared
    }

    /// After a cleared marker whose clear did not take effect in memory: append the kept carried list and refused senders as a
    /// fresh `peer_carried_denials` marker, so the stored history never says "empty" while memory holds them. Nothing is
    /// written when the lists are empty. A failed append marks the state dirty (retried at the next persist point).
    async fn rewrite_kept_peer_state(&self) {
        if !peer_messaging_enabled() || self.startup_hints.is_subagent {
            return;
        }
        let Some(state) = self.peer_admission.snapshot_peer_state() else { return };
        let item = crate::sampling::ConversationItem::peer_carried_denials_marker(&state);
        if self.chat_state_handle.push_user_message_and_ack(item).await.is_none() {
            self.peer_admission.mark_state_dirty();
        }
    }

    /// Tell admission how many denial keys the carried list had to drop (`carried_stats()`), for the held row and the release
    /// notice (counts only).
    fn sync_carried_overflow(&self) {
        self.peer_admission.set_carried_overflow(self.permissions.peer_influence().denials().carried_stats().overflow);
    }

    /// S7.3: turn the laundering hits queued by the permission handle into human notices and audit lines. Cheap when none.
    ///
    /// Only the ROOT session flushes: a subagent shares the root's denial log, so a hit made by a subagent's request stays queued
    /// until the root flushes it (after its own request, at a tool-batch end or when notices are taken), into the root's notice
    /// ring and audit line with the real sender.
    pub(super) fn flush_laundering_hits(&self) {
        if self.startup_hints.is_subagent {
            return;
        }
        let hits = self.permissions.peer_influence().denials().take_hits();
        if !hits.is_empty() {
            self.peer_admission.note_laundering(hits);
        }
    }

    /// S7 persistence (root only, feature on): write the sender-side denials recorded since the last call (`peer_denial`, kind,
    /// hash and wall-clock time) and the receiver-side state if it changed (`peer_carried_denials`). Also flushes subagent hits.
    pub(super) async fn persist_peer_state(&self) {
        // Hits are reported with the feature off too (a restored carried list still guards the session).
        self.flush_laundering_hits();
        if !peer_messaging_enabled() || self.startup_hints.is_subagent {
            return;
        }
        let wall = crate::session::peer_admission::now_secs();
        let fresh = self.peer_admission.new_denials(self.permissions.peer_influence().denials().entries());
        let total = fresh.len();
        for (i, keys) in fresh.into_iter().enumerate() {
            let keys: Vec<(String, String)> = keys.into_iter().map(|k| (k.kind, k.hash)).collect();
            // A targetless denial has no marker (and the permission side never records one).
            let Some(item) = crate::sampling::ConversationItem::peer_denial_keys_marker(&keys, wall) else { continue };
            if self.append_denial_marker(item).await.is_none() {
                // Same as the carried marker: this one and the rest are not lost, they are written at the next persist point.
                self.peer_admission.unsync_tail(total - i);
                break;
            }
        }
        if let Some(state) = self.peer_admission.take_state_to_store() {
            let item = crate::sampling::ConversationItem::peer_carried_denials_marker(&state);
            if self.chat_state_handle.push_user_message_and_ack(item).await.is_none() {
                self.peer_admission.mark_state_dirty();
            }
        }
    }

    async fn append_denial_marker(&self, item: crate::sampling::ConversationItem) -> Option<()> {
        #[cfg(test)]
        if take_denial_append_failure() {
            return None;
        }
        self.chat_state_handle.push_user_message_and_ack(item).await.map(|_| ())
    }

    /// The `PeerHost` this session's peer tools and `/peers` talk to. A subagent gets an unavailable one: it reaches its
    /// family only through `send_subagent_message`.
    pub(super) fn peer_host(self: &std::sync::Arc<Self>) -> std::sync::Arc<dyn fuigo_peer::host::PeerHost> {
        use crate::peer_inbox::tool_host::{SessionPeerHost, UnavailableHost};
        if self.startup_hints.is_subagent {
            return std::sync::Arc::new(UnavailableHost::new("a subagent messages its own family with send_subagent_message"));
        }
        let (permissions, plan) = (self.permissions.clone(), self.plan_mode.clone());
        let mode = std::sync::Arc::new(move || fuigo_peer::PeerMode::from(permissions.effective_peer_mode(plan.lock().is_active())));
        // S5.6: the conversation a send continues comes from this session's own turn state (the peer message that started or
        // joined the running turn), never from a tool argument.
        let conv = self.peer_admission.turn_conv_handle();
        let turn_conv = std::sync::Arc::new(move || conv.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone());
        std::sync::Arc::new(SessionPeerHost::new(
            self.session_info.id.0.to_string(),
            self.permissions.peer_influence().denials().clone(),
            mode,
            turn_conv,
            self.peer_admission.operator_kind_handle(),
        ))
    }

    /// `/peers held`, `/peers release <id>`, `/peers refuse <id>` (human-typed only; the caller has already refused a subagent).
    /// Goes through the same admission handler as the handle's release/reject, so the atomic recheck at drain decides delivery.
    /// Every text is built from typed fields; the sender's name is escaped and only shown when it is a valid display name.
    pub(super) async fn peers_human_admin(&self, args: &str) -> String {
        use crate::session::peer_admission::{PeerAdminCmd, PeerAdminReply};
        let mut it = args.split_whitespace();
        let (verb, id, extra) = (it.next().unwrap_or(""), it.next(), it.next());
        let list = || async {
            match self.peer_admission.admin(PeerAdminCmd::ListHeld).await {
                Some(PeerAdminReply::Held(h)) => Some(h),
                _ => None,
            }
        };
        if verb == "held" {
            let Some(rows) = list().await else { return "Held peer messages could not be read.".to_owned() };
            if rows.is_empty() {
                return "No held peer messages.".to_owned();
            }
            let now = crate::session::peer_admission::now_secs();
            let mut out = format!("{} held peer message(s):", rows.len());
            for r in rows {
                let name = if fuigo_peer::is_valid_display_name(&r.from_name) { r.from_name.as_str() } else { "" };
                out.push_str(&format!(
                    "\n  {id}  from \"{name}\" [{from_ref}]  reason: {reasons}{detail}  expires in {left}s",
                    id = crate::session::peer_message::escape_attr(&r.message_id),
                    name = crate::session::peer_message::escape_attr(name),
                    from_ref = crate::session::peer_message::escape_attr(&r.from_ref),
                    reasons = r.reason_names.join(", "),
                    detail = r.detail.as_deref().map(|d| format!(" ({})", crate::session::peer_message::escape_attr(d))).unwrap_or_default(),
                    left = r.expires_at.saturating_sub(now),
                ));
            }
            return out;
        }
        let Some(id) = id.filter(|_| extra.is_none()) else { return format!("Usage: /peers {verb} <message-id>") };
        // Fresh tokens for every call (the old ones die); only an id held in THIS session is found.
        let token = match list().await {
            Some(rows) => rows.into_iter().find(|r| r.message_id == id).map(|r| r.token),
            None => return "Held peer messages could not be read.".to_owned(),
        };
        let Some(token) = token else { return "Unknown or no longer held message id.".to_owned() };
        let shown = crate::session::peer_message::escape_attr(id);
        match verb {
            "release" => match self.peer_admission.admin(PeerAdminCmd::Release { message_id: id.to_owned(), token }).await {
                Some(PeerAdminReply::Release(Ok(outcome))) => format!("Released {shown}: {outcome:?}."),
                Some(PeerAdminReply::Release(Err(e))) => format!("Not released ({e:?})."),
                _ => "The release could not be made.".to_owned(),
            },
            _ => match self.peer_admission.admin(PeerAdminCmd::Reject { message_id: id.to_owned(), token }).await {
                Some(PeerAdminReply::Reject(Ok(()))) => format!("Refused {shown}. The sender is told it was refused."),
                Some(PeerAdminReply::Reject(Err(e))) => format!("Not refused ({e:?})."),
                _ => "The refusal could not be made.".to_owned(),
            },
        }
    }

    /// Feeds `refuse_peer_message` calls (from the tool, through `PeerRefuseHandle`) to [`Self::refuse_peer_message`].
    pub(super) fn spawn_peer_refuse_pump(
        self: &std::sync::Arc<Self>,
    ) -> fuigo_tools::implementations::fuigo_build::peer_tools::PeerRefuseHandle {
        use fuigo_tools::implementations::fuigo_build::peer_tools::RefusePeerMessageInput;
        let (tx, mut rx) = mpsc::unbounded_channel::<(RefusePeerMessageInput, tokio::sync::oneshot::Sender<Result<String, String>>)>();
        let weak = std::sync::Arc::downgrade(self);
        tokio::task::spawn_local(async move {
            while let Some((input, reply)) = rx.recv().await {
                let Some(session) = weak.upgrade() else { break };
                let args = fuigo_peer::tools::RefusePeerMessageArgs { message_id: input.message_id, reason: input.reason };
                let answer = args.validate().map_err(|_| "message_id or reason is too long".to_owned()).and_then(|()| session.refuse_peer_message(&args));
                let _ = reply.send(answer);
            }
        });
        fuigo_tools::implementations::fuigo_build::peer_tools::PeerRefuseHandle(tx)
    }

    /// S7.4: whether the `refuse_peer_message` tool is offered: the feature is on and this session received a peer message.
    pub(super) fn refuse_peer_message_available(&self) -> bool {
        peer_messaging_enabled() && self.peer_admission.has_received()
    }

    /// S7.4: run `refuse_peer_message`. `Err` is an error result for the model (unavailable or unknown id), never a panic.
    pub(super) fn refuse_peer_message(&self, args: &fuigo_peer::tools::RefusePeerMessageArgs) -> Result<String, String> {
        if !self.refuse_peer_message_available() {
            return Err("There is nothing to refuse: no peer message has been delivered to this session.".to_owned());
        }
        match self.peer_admission.refuse_by_model(&args.message_id, &args.reason) {
            Ok(done) => Ok(format!(
                "Refused. The sender was told and is held for the rest of this session (the human can lift this with \
                 `/peers clear-influence`). The human sees the message id and your reason (escaped, cut to 200 characters): {}",
                done.shown_reason
            )),
            Err(_) => Err("no delivered peer message has that message_id".to_owned()),
        }
    }

    /// The live facts admission reads: the flag and this session's current effective mode, read on every call.
    pub(super) fn peer_live(&self) -> Live {
        Live {
            feature_on: peer_messaging_enabled(),
            receiver_mode: self.effective_peer_mode().into(),
        }
    }

    pub(super) async fn handle_peer_admin(
        self: &Arc<Self>,
        cmd: PeerAdminCmd,
        completion_tx: mpsc::UnboundedSender<super::turn_task::TurnCompletionMsg>,
    ) -> PeerAdminReply {
        if !peer_messaging_enabled() && matches!(cmd, PeerAdminCmd::Configure(_) | PeerAdminCmd::TakeNotices) {
            return PeerAdminReply::Done;
        }
        self.prune_peer_tracking().await;
        match cmd {
            PeerAdminCmd::Submit(envelope) => {
                PeerAdminReply::Submit(self.submit_peer_message(*envelope, completion_tx).await)
            }
            PeerAdminCmd::Release { message_id, token } => {
                let (now, live) = (now_mono(), self.peer_live());
                self.sync_carried_overflow();
                match self.peer_admission.release(&message_id, &token, now, &live) {
                    Err(e) => PeerAdminReply::Release(Err(e)),
                    Ok(()) => {
                        let outcomes = self.drain_peer_approved(completion_tx).await;
                        let outcome = outcomes
                            .into_iter()
                            .find(|(id, _)| *id == message_id)
                            .map(|(_, o)| o)
                            .unwrap_or(ReleaseOutcome::Dropped(RejectReason::Unavailable));
                        PeerAdminReply::Release(Ok(outcome))
                    }
                }
            }
            PeerAdminCmd::Reject { message_id, token } => PeerAdminReply::Reject(
                self.peer_admission.reject(&message_id, &token, now_mono()),
            ),
            PeerAdminCmd::ListHeld => {
                self.sync_carried_overflow();
                PeerAdminReply::Held(self.peer_admission.list_held(now_mono()))
            }
            PeerAdminCmd::HeldSnapshot => PeerAdminReply::Held(self.peer_admission.held_snapshot(now_mono())),
            PeerAdminCmd::Configure(config) => {
                self.peer_admission.configure(config);
                PeerAdminReply::Done
            }
            PeerAdminCmd::SentNotice { message_id, kind } => {
                self.peer_admission.record_sent_notice(&message_id, kind);
                PeerAdminReply::Done
            }
            PeerAdminCmd::SentNoticeWake { message_id, kind, target } => {
                self.peer_admission.record_sent_notice_opt(&message_id, kind);
                self.wake_for_peer_notice(&message_id, kind, &target, completion_tx).await;
                PeerAdminReply::Done
            }
            PeerAdminCmd::TakeNotices => {
                self.flush_laundering_hits();
                PeerAdminReply::Notices(self.peer_admission.take_notices(now_mono()))
            }
        }
    }

    /// Packet 11 (S9.4): wake the model for a delivery notice about a message this session sent. The row is HIDDEN runtime control
    /// (the class of a workflow or task completion) with FIXED text built here from the typed kind and the target's address; no
    /// peer-supplied string is in it. It counts against the peer-started-turn budget (nothing is queued once that is used up) and
    /// the turn it starts inherits the session's peer chain (only a human-typed prompt clears it). It never sends a notice.
    async fn wake_for_peer_notice(
        self: &Arc<Self>,
        message_id: &str,
        kind: Option<fuigo_peer::NoticeKind>,
        target: &str,
        completion_tx: mpsc::UnboundedSender<super::turn_task::TurnCompletionMsg>,
    ) {
        if !peer_messaging_enabled() {
            return;
        }
        if self.state.lock().await.notifications_suppressed {
            return;
        }
        if !self.peer_admission.consume_notice_turn() {
            return;
        }
        let text = format!(
            "{} This is a status notice only: it asks you to do nothing. Tell your user if it matters.",
            fuigo_peer::host::notice_text(kind, target)
        );
        let (respond_to, _) = tokio::sync::oneshot::channel();
        {
            let mut state = self.state.lock().await;
            state.pending_inputs.push_back(InputItem {
                prompt_id: format!("peer-notice-{message_id}"),
                prompt_blocks: vec![acp::ContentBlock::Text(acp::TextContent::new(text))],
                prompt_mode: crate::session::plan_mode::PromptMode::Agent,
                trace_gcs_config: None,
                artifact_tracker: None,
                client_identifier: None,
                screen_mode: None,
                verbatim: true,
                json_schema: None,
                input_origin: InputOrigin::new(super::PromptOrigin::PeerNotice { message_id: message_id.to_owned() }),
                task_wake_fallback: None,
                tool_overrides_update: None,
                respond_to,
                persist_ack: None,
                parsed_prompt_tx: None,
                initial_child_prompt_ready: None,
                queue_meta: None,
                queue_mutation_policy: QueueMutationPolicy::hidden(),
                send_now: false,
                traceparent: None,
            });
        }
        Self::maybe_start_running_task(self.clone(), completion_tx).await;
    }

    /// Admission for a message from a peer: decide (S4), then queue, hold or refuse. Flag off: refused `unavailable`, nothing stored.
    pub(super) async fn submit_peer_message(
        self: &Arc<Self>,
        envelope: fuigo_peer::Envelope,
        completion_tx: mpsc::UnboundedSender<super::turn_task::TurnCompletionMsg>,
    ) -> PeerSubmit {
        if !peer_messaging_enabled() {
            return PeerSubmit::Outcome(DeliveryOutcome::Rejected { reason: RejectReason::Unavailable });
        }
        // Not offered (not opted in, or a remote client is attached, S4.1): `unavailable` FIRST, exactly like an unknown
        // session, before any integrity or baseline work, so a send to such a session leaves no marker, warning or task.
        {
            let c = self.peer_admission.config();
            if !c.opted_in || c.relay_driven || crate::peer_inbox::driver::remote_attached() {
                return PeerSubmit::Outcome(DeliveryOutcome::Rejected { reason: RejectReason::Unavailable });
            }
        }
        // S6.6: a write by a background command since the last tool batch is seen before this message is judged.
        self.recheck_peer_integrity().await;
        // S5.1 on the receiving side: an over-size body is `too_large`, before any other check.
        if let Err(reason) = fuigo_peer::check_body(envelope.body.len()) {
            return PeerSubmit::Outcome(DeliveryOutcome::Rejected { reason });
        }
        if envelope.validate().is_err() {
            return PeerSubmit::Invalid;
        }
        // S6.6: the baseline is complete (or the hold is up) before the decision, so a hung read holds this message
        // (`integrity`) instead of parking the actor.
        self.ensure_peer_baseline().await;
        self.prune_peer_tracking().await;
        let (now, live) = (now_mono(), self.peer_live());
        let key = msg_key(&envelope);
        match self.peer_admission.submit(envelope.clone(), now, &live) {
            Submitted::Done(outcome) => PeerSubmit::Outcome(outcome),
            Submitted::Enqueue => match self.enqueue_admitted_peer_row(envelope, completion_tx).await {
                PeerAdmission::Admitted { .. } => PeerSubmit::Outcome(DeliveryOutcome::Delivered {}),
                PeerAdmission::Refused(reason) => {
                    self.peer_admission.untrack(&key);
                    match reason {
                        PeerRefusal::FeatureOff => PeerSubmit::Outcome(DeliveryOutcome::Rejected {
                            reason: RejectReason::Unavailable,
                        }),
                        PeerRefusal::Invalid => PeerSubmit::Invalid,
                        PeerRefusal::SessionClosed => PeerSubmit::SessionClosed,
                        PeerRefusal::Policy => PeerSubmit::Outcome(DeliveryOutcome::Rejected {
                            reason: RejectReason::PolicyRefused,
                        }),
                    }
                }
            },
        }
    }

    /// Packet 11: admission for a watch-only send. The same front door as `submit_peer_message` (not offered, integrity, size,
    /// shape, baseline) and the same ingress and decision (`probe_watch`); `Delivered {}` only when a message would be admitted.
    /// Nothing is stored, queued or started.
    pub(super) async fn probe_peer_watch(self: &Arc<Self>, envelope: fuigo_peer::Envelope) -> PeerSubmit {
        if !peer_messaging_enabled() {
            return PeerSubmit::Outcome(DeliveryOutcome::Rejected { reason: RejectReason::Unavailable });
        }
        {
            let c = self.peer_admission.config();
            if !c.opted_in || c.relay_driven || crate::peer_inbox::driver::remote_attached() {
                return PeerSubmit::Outcome(DeliveryOutcome::Rejected { reason: RejectReason::Unavailable });
            }
        }
        self.recheck_peer_integrity().await;
        if let Err(reason) = fuigo_peer::check_body(envelope.body.len()) {
            return PeerSubmit::Outcome(DeliveryOutcome::Rejected { reason });
        }
        if envelope.validate().is_err() {
            return PeerSubmit::Invalid;
        }
        self.ensure_peer_baseline().await;
        self.prune_peer_tracking().await;
        let (now, live) = (now_mono(), self.peer_live());
        PeerSubmit::Outcome(self.peer_admission.probe_watch(&envelope, now, &live))
    }

    /// The drain step for released messages: re-evaluate against the live state, then queue the ones that still qualify
    /// (S4.7). A mode change between release and here puts the message back on hold.
    pub(super) async fn drain_peer_approved(
        self: &Arc<Self>,
        completion_tx: mpsc::UnboundedSender<super::turn_task::TurnCompletionMsg>,
    ) -> Vec<(String, ReleaseOutcome)> {
        self.recheck_peer_integrity().await;
        self.ensure_peer_baseline().await;
        let (now, live) = (now_mono(), self.peer_live());
        let (enter, mut outcomes) = self.peer_admission.drain(now, &live);
        for envelope in enter {
            let key = msg_key(&envelope);
            let id = envelope.message_id.clone();
            if let PeerAdmission::Refused(why) = self.enqueue_admitted_peer_row(envelope, completion_tx.clone()).await {
                self.peer_admission.untrack(&key);
                let dropped = match why {
                    PeerRefusal::Policy => RejectReason::PolicyRefused,
                    _ => RejectReason::Unavailable,
                };
                for (oid, o) in outcomes.iter_mut() {
                    if *oid == id {
                        *o = ReleaseOutcome::Dropped(dropped);
                    }
                }
            }
        }
        outcomes
    }

    /// Forget tracked admissions whose queue row is gone (cancelled, removed, demoted), so the store cannot fill up with them.
    pub(super) async fn prune_peer_tracking(&self) {
        let state = self.state.lock().await;
        let still_queued: std::collections::HashSet<_> = state
            .pending_inputs
            .iter()
            .filter_map(|i| match i.input_origin.as_prompt_origin() {
                PromptOrigin::PeerMessage { message_id, from } => Some((from.clone(), message_id.clone())),
                _ => None,
            })
            .collect();
        drop(state);
        self.peer_admission.prune_queued(&still_queued);
    }

    /// Start-of-turn check for a turn begun by a peer row: `false` when the hold is up, in which case the row went back to held.
    pub(super) fn peer_turn_row_still_qualifies(&self, request: &super::turn_task::TurnInputRequest) -> bool {
        let PromptOrigin::PeerMessage { message_id, from } = request.input_origin.as_prompt_origin() else { return true };
        self.peer_admission.recheck_queued(&(from.clone(), message_id.clone()), now_mono(), &self.peer_live())
    }

    /// Recheck queued peer rows just before they enter a turn; rows that no longer qualify are taken out of the queue (they are
    /// back in the held store, or dropped with a notice). `front_only`: only the row at the front (about to start). Returns true if
    /// any row was removed. A peer row this state does not track is not qualified and is removed too.
    pub(super) fn demote_unqualified_peer_rows(&self, state: &mut State, front_only: bool) -> bool {
        if !state.pending_inputs.iter().any(|i| i.input_origin.as_prompt_origin().is_peer()) {
            return false;
        }
        let (now, live) = (now_mono(), self.peer_live());
        let running = state.running_prompt_id().map(str::to_string);
        let mut removed = false;
        let mut i = 0;
        while i < state.pending_inputs.len() {
            let item = &state.pending_inputs[i];
            let id = match item.input_origin.as_prompt_origin() {
                PromptOrigin::PeerMessage { message_id, from }
                    if running.as_deref() != Some(item.prompt_id.as_str()) =>
                {
                    (from.clone(), message_id.clone())
                }
                _ => {
                    if front_only {
                        break;
                    }
                    i += 1;
                    continue;
                }
            };
            if self.peer_admission.recheck_queued(&id, now, &live) {
                if front_only {
                    break;
                }
                i += 1;
            } else if let Some(item) = state.pending_inputs.remove(i) {
                Self::respond_removed_prompt(item.respond_to);
                removed = true;
            }
        }
        if removed {
            self.broadcast_queue_changed(state);
        }
        removed
    }
}

#[cfg(test)]
thread_local! {
    static AFTER_RESOURCE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

/// Test seam: run once at the point `maybe_start_running_task` has finished its `update_resource` await.
#[cfg(test)]
pub(super) fn set_after_resource_hook(f: impl FnOnce() + 'static) {
    AFTER_RESOURCE_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(f)));
}

#[cfg(test)]
pub(super) fn run_after_resource_hook() {
    if let Some(f) = AFTER_RESOURCE_HOOK.with(|h| h.borrow_mut().take()) {
        f();
    }
}

#[cfg(test)]
impl SessionActor {
    /// Test only: track `envelope` as a directly admitted message, then run the raw enqueue (for tests of the queued row itself).
    pub(super) async fn admit_peer_message_for_test(
        self: &Arc<Self>,
        envelope: fuigo_peer::Envelope,
        completion_tx: mpsc::UnboundedSender<super::turn_task::TurnCompletionMsg>,
    ) -> PeerAdmission {
        use crate::session::peer_admission::{OperatorPresence, PeerAdmissionConfig};
        // The packet-3 row tests only need a row that qualifies: configure the session (if nobody did) and send the receiver's
        // own mode, so the start and promotion rechecks pass.
        let mut envelope = envelope;
        if !self.peer_admission.config().opted_in {
            self.peer_admission.configure(PeerAdmissionConfig {
                opted_in: true,
                policy: fuigo_config_types::PeerInboundPolicy::Accept,
                operator: OperatorPresence::Present,
                relay_driven: false,
            });
        }
        envelope.from_mode = self.effective_peer_mode().into();
        self.peer_admission.track_direct_for_test(envelope.clone(), now_mono());
        self.enqueue_admitted_peer_row(envelope, completion_tx).await
    }
}

#[cfg(test)]
#[path = "peer_admit_tests.rs"]
mod tests;

#[cfg(test)]
type ClearPauseHook = std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>;

#[cfg(test)]
thread_local! {
    static CLEAR_PAUSE_HOOK: std::cell::RefCell<Option<ClearPauseHook>> = const { std::cell::RefCell::new(None) };
}

/// Test seam: a future run once at the point `/peers clear-influence` is waiting for the marker append (the race window).
#[cfg(test)]
pub(super) fn set_clear_pause_hook(f: impl std::future::Future<Output = ()> + 'static) {
    CLEAR_PAUSE_HOOK.with(|h| *h.borrow_mut() = Some(Box::pin(f)));
}

#[cfg(test)]
async fn run_clear_pause_hook() {
    let hook = CLEAR_PAUSE_HOOK.with(|h| h.borrow_mut().take());
    if let Some(f) = hook {
        f.await;
    }
}

#[cfg(test)]
thread_local! {
    static CLEAR_APPEND_FAILS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test seam: the next `/peers clear-influence` sees its marker append fail.
#[cfg(test)]
pub(super) fn force_clear_append_failure_for_test() {
    CLEAR_APPEND_FAILS.with(|c| c.set(true));
}

#[cfg(test)]
fn take_clear_append_failure() -> bool {
    CLEAR_APPEND_FAILS.with(|c| c.replace(false))
}

#[cfg(test)]
thread_local! {
    static DENIAL_APPEND_FAILS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Test seam: the next `n` sender-side denial marker appends fail.
#[cfg(test)]
pub(super) fn force_denial_append_failures_for_test(n: u32) {
    DENIAL_APPEND_FAILS.with(|c| c.set(n));
}

#[cfg(test)]
fn take_denial_append_failure() -> bool {
    DENIAL_APPEND_FAILS.with(|c| {
        let n = c.get();
        c.set(n.saturating_sub(1));
        n > 0
    })
}
