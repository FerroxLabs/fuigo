//! What the TUI does when its leader IPC connection drops (P152, e2e lane B #2).
//!
//! The event loop's leader-status arm calls [`on_leader_reconnecting`] for every `ConnectionStatus::Reconnecting`.

use super::app_view::AppView;

/// The leader connection dropped and the bridge is reconnecting (attempt `attempt`).
///
/// From here until the reconnect re-init finishes, nothing may be sent: a line written to the dead connection is held
/// and then dropped when the new connection is swapped in (`leader_bridge::forward_outbound_line`), so a prompt sent now
/// would vanish with no response and no error. `reconnect_pending` makes every send path refuse with the reconnect
/// notice and keep the text in the composer (and every drain trigger defer); the event loop clears it and drains the
/// queue once the sessions are reloaded. It used to be raised only at `Connected`, leaving the whole disconnected
/// window, the one a user retrying right after `fuigo leader kill` hits, unguarded.
pub(crate) fn on_leader_reconnecting(app: &mut AppView, attempt: u32) {
    app.reconnect_pending = true;
    // P125: the leader's relay refusal may change while disconnected; it re-sends its current one
    // when this client registers again.
    app.clear_relay_refusal();
    app.show_toast(&format!(
        "Disconnected. Reconnecting... (attempt {attempt})"
    ));
}

/// Close the send window before input is handled (Astra r1 #2). The event loop's `select!` is biased and polls input
/// before the leader-status arm, so a key and a fresh `Reconnecting` that are ready together would let the key send into
/// the dead connection. The loop calls this with the bridge's CURRENT status (peeked, not consumed: the status arm still
/// runs for the notice) before each input batch.
///
/// A `Connected` generation newer than `last_handled_generation` holds sends too (Astra r3 H1): the watch channel keeps
/// only the latest status, so a reconnect can reach `Connected` before the loop has seen it. Until the status arm
/// handles it (and the re-init reloads the sessions), a prompt would reach the fresh leader before `session/load`.
pub(crate) fn hold_sends_if_reconnecting(
    app: &mut AppView,
    status: &crate::acp::leader_bridge::ConnectionStatus,
    last_handled_generation: u64,
) {
    use crate::acp::leader_bridge::ConnectionStatus;
    let unsettled = match status {
        ConnectionStatus::Reconnecting { .. } => true,
        ConnectionStatus::Connected { generation } => *generation > last_handled_generation,
        _ => false,
    };
    if unsettled {
        app.reconnect_pending = true;
    }
}
