//! Packet 12b: dispatch for the peer hold dialog and the answers of the `fuigo/peer/*` requests.

use crate::app::actions::{Effect, PeerUiAction};
use crate::app::agent::AgentId;
use crate::app::app_view::{ActiveView, AppView};
use crate::peer_ui::peer_ui_enabled;
use crate::peer_ui_state::{PeerCall, PeerRpcOutcome, decision_note, startup_call};

fn session_id_of(app: &AppView, id: AgentId) -> Option<String> {
    app.agents.get(&id)?.session.session_id.as_ref().map(|s| s.0.to_string())
}

/// The one opt-in request a new or loaded session sends (empty with the flag off or without a real terminal).
/// At most once per session id per agent view (a create followed by a load, or a repeated load, must not configure twice: a second
/// `configure` voids the tokens of an open dialog). If a different session id must be configured while the dialog is open, the
/// dialog is closed with a one-line notice.
pub(crate) fn startup_effects(agent: &mut crate::app::agent_view::AgentView, agent_id: AgentId, session_id: &str) -> Vec<Effect> {
    let Some(call) = startup_call() else { return vec![] };
    if !agent.owns_peer_ui() {
        return vec![];
    }
    match agent.peer.note_configure(session_id) {
        None => vec![],
        Some(closed_dialog) => {
            if closed_dialog {
                agent.peer_notice_row("The peer hold dialog was closed: the peer connection was set up again.".to_owned());
            }
            vec![Effect::PeerRpc { agent_id, session_id: session_id.to_owned(), call }]
        }
    }
}

pub(super) fn dispatch_peer_ui(action: PeerUiAction, app: &mut AppView) -> Vec<Effect> {
    if !peer_ui_enabled() {
        return vec![];
    }
    let ActiveView::Agent(agent_id) = app.active_view else { return vec![] };
    let Some(session_id) = session_id_of(app, agent_id) else { return vec![] };
    match action {
        // Fresh rows and fresh tokens every time the dialog opens; nothing cached from before.
        PeerUiAction::OpenDialog => vec![Effect::PeerRpc { agent_id, session_id, call: PeerCall::ListHeld { reopen: true } }],
        PeerUiAction::Decide { refuse } => {
            let Some(agent) = app.agents.get_mut(&agent_id) else { return vec![] };
            if !agent.owns_peer_ui() {
                return vec![];
            }
            // Another overlay is up now: no decision goes out; the dialog closes and its token is dropped.
            if agent.other_overlay_active() {
                agent.peer_close_if_overlaid();
                return vec![];
            }
            match agent.peer.take_decision(refuse) {
                Some(call) => vec![Effect::PeerRpc { agent_id, session_id, call }],
                None => vec![],
            }
        }
    }
}

pub(super) fn on_rpc_done(app: &mut AppView, agent_id: AgentId, outcome: PeerRpcOutcome) -> Vec<Effect> {
    let session_id = session_id_of(app, agent_id);
    let Some(agent) = app.agents.get_mut(&agent_id) else { return vec![] };
    if !peer_ui_enabled() || !agent.owns_peer_ui() {
        return vec![];
    }
    match outcome {
        PeerRpcOutcome::Configured(r) => {
            if let Err(e) = r {
                tracing::debug!(reason = %e.reason, "peer opt-in not accepted");
            }
            vec![]
        }
        PeerRpcOutcome::Held { reopen, result } => {
            let line = match result {
                Ok(rows) => {
                    let note = agent.peer.apply_list(rows, reopen);
                    // Another overlay opened while the list was in flight: the dialog does not open over it.
                    agent.peer_close_if_overlaid();
                    note
                }
                Err(e) => Some(e.plain_line()),
            };
            if let Some(line) = line {
                agent.peer_notice_row(line);
            }
            vec![]
        }
        PeerRpcOutcome::Decided { held_id, result, .. } => match result {
            Ok(word) => {
                agent.peer.note_decided(&held_id);
                if let Some(line) = decision_note(&word) {
                    agent.peer_notice_row(line);
                }
                vec![]
            }
            Err(e) => {
                agent.peer_notice_row(e.plain_line());
                // A stale token: refresh the list ONCE (no dialog) and let the user choose again. The release is never re-sent.
                match (e.is_stale(), session_id) {
                    (true, Some(session_id)) => {
                        vec![Effect::PeerRpc { agent_id, session_id, call: PeerCall::ListHeld { reopen: false } }]
                    }
                    _ => vec![],
                }
            }
        },
    }
}
