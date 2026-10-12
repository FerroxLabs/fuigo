//! Packet 12b: the keyboard of the peer hold row and dialog. Flag off, or nothing held and no dialog: this does nothing.

use super::AgentView;
use crate::app::actions::{Action, PeerUiAction};
use crate::app::app_view::InputOutcome;
use crate::peer_ui::PeerDialogOutcome;
use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};

/// The one-line notice when the peer dialog cannot be (or stay) open because another prompt is.
pub(crate) const OVERLAY_NOTICE: &str = "finish the open prompt first";

impl AgentView {
    /// Whether any OTHER overlay is up: anything that takes keys or paints over the transcript area. The peer hold dialog and these are
    /// never active together. Keep in step with the overlay calls of `AgentView::draw`; `peer_overlay_list_matches_draw` pins it.
    pub(crate) fn other_overlay_active(&self) -> bool {
        self.blocking_card().is_some() // permission card, cancel-turn panel, question, MCP elicitation
            || self.rewind_state.is_some()
            || self.jump_state.is_some()
            || self.btw_state.is_some()
            || self.active_modal.is_some()
            || self.line_viewer.is_some()
            || self.image_viewer.is_some()
            || self.video_viewer.is_some()
            || self.gboom.is_some()
            || self.block_viewer.is_some()
            || self.agents_modal.is_some()
            || self.extensions_modal.is_some()
            || self.persona_detail.is_some()
            || self.show_goal_detail
            || self.show_workflows
            || self.plan_approval_view.is_some()
            || self.active_subagent.is_some()
            || self.prompt.file_search_visible()
            || self.prompt.history_search.is_active()
    }

    /// Only a root agent view owns peer state. A subagent (child) view never does: the shell never opts a subagent session in.
    pub(crate) fn owns_peer_ui(&self) -> bool {
        !self.is_subagent_view
    }

    /// Which view is fullscreen or focused changed: the last paint no longer describes the screen and an open dialog is closed
    /// (token dropped, one-line notice, same text as the exclusivity rule). No-op with no dialog.
    pub(crate) fn peer_view_changed(&mut self) {
        self.peer.note_screen_disturbed();
        if self.peer.close_dialog() {
            self.peer_notice_row(OVERLAY_NOTICE.to_owned());
        }
    }

    /// Close an open peer dialog if another overlay is active (token dropped, one notice). No-op when no dialog is open.
    pub(crate) fn peer_close_if_overlaid(&mut self) {
        if self.peer.dialog_open() && self.other_overlay_active() {
            self.peer.close_dialog();
            self.peer_notice_row(OVERLAY_NOTICE.to_owned());
        }
    }

    /// `Some` when the peer UI owns this event. While the dialog is open it swallows every key (nothing reaches the prompt, so a
    /// stray key can neither type into it nor trigger another binding); closed, only `Alt+h` while something is held.
    pub(super) fn peer_input(&mut self, ev: &Event) -> Option<InputOutcome> {
        // A subagent (child) view never takes part in peer messaging: no dialog, no `Alt+h`, no `a`/`r`.
        if !self.owns_peer_ui() {
            return None;
        }
        // EXCLUSIVITY, before anything else (so before any key): if another overlay took the screen or the keys while the dialog was
        // open, the dialog is gone (token dropped) and the key goes to that overlay exactly as it did before this packet.
        self.peer_close_if_overlaid();
        // A paste while the dialog is open is swallowed whole: nothing reaches the composer.
        if matches!(ev, Event::Paste(_)) && self.peer.dialog_open() {
            return Some(InputOutcome::Unchanged);
        }
        let Event::Key(key) = ev else { return None };
        if self.peer.dialog_open() {
            self.peer.note_key_taken();
            if key.kind == KeyEventKind::Release {
                return Some(InputOutcome::Unchanged);
            }
            return Some(match self.peer.dialog_key(key) {
                PeerDialogOutcome::Release => InputOutcome::Action(Action::PeerUi(PeerUiAction::Decide { refuse: false })),
                PeerDialogOutcome::Refuse => InputOutcome::Action(Action::PeerUi(PeerUiAction::Decide { refuse: true })),
                PeerDialogOutcome::Dismiss | PeerDialogOutcome::Changed => InputOutcome::Changed,
                PeerDialogOutcome::Ignored => InputOutcome::Unchanged,
            });
        }
        if self.peer.row_visible() && key.kind != KeyEventKind::Release && key.modifiers == KeyModifiers::ALT && key.code == KeyCode::Char('h') && self.other_overlay_active()
        {
            self.peer_notice_row(OVERLAY_NOTICE.to_owned());
            return Some(InputOutcome::Changed);
        }
        if self.peer.row_visible()
            && key.kind != KeyEventKind::Release
            && key.modifiers == KeyModifiers::ALT
            && key.code == KeyCode::Char('h')
        {
            return Some(InputOutcome::Action(Action::PeerUi(PeerUiAction::OpenDialog)));
        }
        None
    }

    /// Show one plain line in the transcript (peer notices and errors).
    pub(crate) fn peer_notice_row(&mut self, text: String) {
        self.scrollback.push_block(crate::scrollback::block::RenderBlock::system_single_line(text));
    }
}
