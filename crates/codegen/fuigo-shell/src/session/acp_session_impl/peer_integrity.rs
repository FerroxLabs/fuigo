//! Actor side of S6.6 change detection (peer messaging, packet 6 part B2). The watch itself is `session/peer_integrity.rs`.
//! With `features.peer_messaging` off nothing here reads or stats a file.

use super::*;
use crate::session::peer_integrity::{Change, Roots};
use crate::session::peer_message::peer_messaging_enabled;

pub(super) use crate::session::peer_integrity::display_path;

/// The warning shown to the human (names the path; never a file body).
pub(super) fn integrity_warning(changes: &[Change]) -> String {
    if changes.iter().any(Change::is_unreadable) {
        return "Warning: the protected files could not be read in time while this session was reading messages from another \
                session, so changes to them cannot be ruled out. Further peer messages are held (reason integrity) until you run \
                `/peers clear-influence`."
            .to_string();
    }
    let paths: Vec<String> = changes.iter().take(8).map(|c| display_path(&c.path)).collect();
    format!(
        "Warning: a protected file changed while this session was reading messages from another session: {}. The change was not \
         undone. Further peer messages are held (reason integrity) until you run `/peers clear-influence`.",
        paths.join(", ")
    )
}

impl SessionActor {
    /// S6.7: the origin and influenced flag for the `PreToolUse` payload; `None` (bytes unchanged) with the feature off.
    pub(super) fn pre_tool_use_peer_note(&self) -> Option<fuigo_workspace::permission::PeerPayloadNote> {
        if !peer_messaging_enabled() {
            return None;
        }
        self.tool_context.peer_influence.payload_note()
    }

    /// The shared `peer_turn` flag belongs to the root session: a subagent shares the parent's flag, so its turn ending must not
    /// clear the parent's. Only a non-subagent actor sets it.
    pub(super) fn set_root_peer_turn(&self, on: bool) {
        if !self.startup_hints.is_subagent {
            self.tool_context.peer_influence.set_peer_turn(on);
        }
    }

    /// Tell the human, once, that a stored peer-influenced session was resumed with peer messaging off and stays guarded.
    pub(super) async fn announce_guard_kept_feature_off(&self) {
        if self.peer_admission.take_guard_kept_feature_off() {
            self.send_host_turn_slash_command_output(
                "Notice: this session was influenced by messages from another session, and peer messaging is off, so the guard on \
                 protected files stays on. Run `/peers clear-influence` to lift it (you type it; the model cannot).",
            )
            .await;
        }
    }

    fn peer_integrity_roots(&self) -> Roots {
        Roots {
            cwd: self.tool_context.cwd.as_path().to_path_buf(),
            home: fuigo_dirs::home_dir(),
            fuigo_home: Some(fuigo_dirs::fuigo_home()),
        }
    }

    /// Take the baseline snapshot once the session is peer-influenced (idempotent).
    pub(super) fn arm_peer_integrity(&self) {
        // A subagent never arms its own watch: the root's watch covers the same files.
        if peer_messaging_enabled() && !self.startup_hints.is_subagent && self.tool_context.peer_influence.is_set() {
            // File work runs on a blocking thread; this may be called with the session state lock held.
            self.peer_admission.integrity_arm_background(self.peer_integrity_roots());
        }
    }

    /// S6.6: the baseline is complete BEFORE the text of an admitted peer message can reach the model. Called by the admit path
    /// before the row is queued (so before it can start a turn or ride into a running one as an interjection): it starts the
    /// baseline read on a blocking thread and awaits it, holding no lock. A tool batch already running was decided before the
    /// model saw this message, so a write of that batch is either inside the baseline (not attributable to the message) or after
    /// it, where the batch-end recheck reports it (a possible false trip, which fails closed).
    pub(super) async fn ensure_peer_baseline(&self) {
        if peer_messaging_enabled() && !self.startup_hints.is_subagent {
            self.peer_admission.integrity_arm_background(self.peer_integrity_roots());
            // Bounded: a read that hangs or panics raises the hold, and the marker and warning are written here.
            let changes = self.peer_admission.integrity_await_baseline().await;
            self.persist_integrity_trip(&changes).await;
        }
    }

    /// Write the persisted hold marker and show the human warning for findings that just tripped the hold (none: nothing).
    async fn persist_integrity_trip(&self, changes: &[Change]) {
        if changes.is_empty() {
            return;
        }
        // S6.6: persist the hold (item kind, hashes nowhere) so a resume brings it back before any message is admitted.
        let _ = self
            .chat_state_handle
            .push_state_marker_and_ack(crate::sampling::ConversationItem::peer_integrity_tripped_marker())
            .await;
        let warning = integrity_warning(changes);
        #[cfg(test)]
        self.peer_admission.hooks.warnings.lock().unwrap_or_else(|p| p.into_inner()).push(warning.clone());
        self.send_host_turn_slash_command_output(&warning).await;
    }

    /// After every tool call of an influenced session: stat the watched files, hash the ones that moved. One warning, once.
    /// Both waits (the baseline and the file work) are bounded; a timeout fails closed the same way as a change.
    pub(super) async fn recheck_peer_integrity(&self) {
        if !peer_messaging_enabled() || self.startup_hints.is_subagent || !self.tool_context.peer_influence.is_set() {
            return;
        }
        self.arm_peer_integrity();
        let changes = self.peer_admission.integrity_check_async().await;
        self.persist_integrity_trip(&changes).await;
    }
}
