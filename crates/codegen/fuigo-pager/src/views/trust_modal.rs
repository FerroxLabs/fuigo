//! F11: the `/trust` screens (full-screen app only). Two tabs in one [`ModalWindow`](super::modal_window):
//! **This folder** (status, trust or stop trusting it) and **Trusted folders** (the store's list, stop trusting one).
//!
//! The modal never writes the trust store. A grant closes it and sends `/hooks-trust` to the shell, the same text a
//! user types, so it settles through the shell's one grant path (`settle_session_grant`, then the F5 reload). Stopping
//! trust in this folder sends `/hooks-untrust`; stopping trust in another listed folder asks the router for
//! `decline_folder_trust_key`, the writer the startup question's "no" already uses.

use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Widget, Wrap};

use crate::theme::Theme;
use crate::views::modal_window::{
    self, ModalContentArea, ModalSizing, ModalWindowConfig, ModalWindowState, Shortcut,
};

/// The modal title.
pub const TITLE: &str = "Folder trust";
/// Tab labels: index 0 is this folder, 1 the trusted-folder list.
pub const TABS: &[&str] = &["This folder", "Trusted folders"];
/// The text a grant sends: the shell's `/hooks-trust` (alias `/trust` for ACP clients).
pub const GRANT_COMMAND: &str = "/hooks-trust";
/// The text stopping trust in this folder sends: the shell's `/hooks-untrust`.
pub const REVOKE_COMMAND: &str = "/hooks-untrust";

/// What the trust system says about the session folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStatus {
    /// Trusted for its settings and its shell commands.
    Trusted,
    /// Never decided.
    Undecided,
    /// The user said no.
    Declined,
    /// Trusted before 1.0.35 for its settings only.
    SettingsOnly,
    /// Home, `/`, or no trust key: can never be trusted.
    Never,
    /// The trust store or `FUIGO_HOME` could not be read.
    Unreadable,
    /// Folder trust is switched off (config, environment, or a local build).
    Off,
}

impl TrustStatus {
    fn line(self) -> &'static str {
        match self {
            Self::Trusted => "Trusted: its settings load and its shell commands run without asking each time.",
            Self::Undecided => "Not trusted: you have not decided yet. Its settings do not load; shell commands ask.",
            Self::Declined => "Not trusted: you said no. Its settings do not load; shell commands ask.",
            Self::SettingsOnly => {
                "Not trusted: trusted before 1.0.35 for its settings only. Trust it again to cover shell commands."
            }
            Self::Never => "Can never be trusted: home and root folders. Run Fuigo from a project folder.",
            Self::Unreadable => "Not trusted: your trust store could not be read. Check that your Fuigo home is readable.",
            Self::Off => "Folder trust is off (config, FUIGO_FOLDER_TRUST=0, or a local build): every folder is trusted.",
        }
    }

    /// Whether `t` offers a grant (warn, don't refuse: an unreadable store still lets the shell say why).
    pub fn can_grant(self) -> bool {
        !matches!(self, Self::Trusted | Self::Never | Self::Off)
    }
}

/// One trusted folder in the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRow {
    pub folder: PathBuf,
    /// A pre-1.0.35 record: settings only.
    pub settings_only: bool,
    /// The session folder's trust key.
    pub current: bool,
}

/// Everything the screens show, read once when the modal opens (and again after a revoke).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustSnapshot {
    pub cwd: PathBuf,
    /// The folder's trust key (its repository root, or the folder), when it has one.
    pub key: Option<PathBuf>,
    pub status: TrustStatus,
    pub rows: Vec<TrustRow>,
}

impl TrustSnapshot {
    /// Read the trust state for `cwd`. Reads only; never writes.
    pub fn read(cwd: &Path) -> Self {
        use fuigo_workspace::folder_trust::{self as ft, TrustDecision, UntrustedReason};
        let key = fuigo_workspace::trust::trust_key(cwd).ok();
        let status = if ft::folder_trust_inert() || ft::folder_trust_disabled() {
            TrustStatus::Off
        } else {
            match ft::decide(cwd, false) {
                TrustDecision::Trusted => TrustStatus::Trusted,
                TrustDecision::Prompt(_) => TrustStatus::Undecided,
                TrustDecision::Untrusted(reason) => match reason {
                    UntrustedReason::Key(_) => TrustStatus::Never,
                    UntrustedReason::Declined(_) => TrustStatus::Declined,
                    UntrustedReason::Legacy(_) => TrustStatus::SettingsOnly,
                    UntrustedReason::Undecided(_) => TrustStatus::Undecided,
                    UntrustedReason::Inputs => TrustStatus::Unreadable,
                },
            }
        };
        let rows = fuigo_workspace::trust::TrustStore::load()
            .trusted_records()
            .into_iter()
            .map(|(folder, current_consent)| TrustRow {
                current: key.as_deref() == Some(folder.as_path()),
                folder,
                settings_only: !current_consent,
            })
            .collect();
        Self { cwd: cwd.to_path_buf(), key, status, rows }
    }
}

/// A pending one-key confirm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirm {
    /// Trust this folder.
    Grant,
    /// Stop trusting this folder.
    RevokeCurrent,
    /// Stop trusting another listed folder.
    RevokeOther(PathBuf),
}

/// The modal's state.
#[derive(Debug, Clone)]
pub struct TrustModalState {
    pub snapshot: TrustSnapshot,
    /// Selected row on the list tab.
    pub selected: usize,
    pub confirm: Option<Confirm>,
    pub window: ModalWindowState,
}

impl TrustModalState {
    pub fn new(snapshot: TrustSnapshot) -> Self {
        let mut window = ModalWindowState::new();
        window.tab_count = TABS.len();
        Self { snapshot, selected: 0, confirm: None, window }
    }

    /// The tab on screen (0 this folder, 1 trusted folders).
    pub fn tab(&self) -> usize {
        self.window.active_tab.min(TABS.len() - 1)
    }

    /// Replace the snapshot (after a revoke), keeping the tab and clamping the selection.
    pub fn refresh(&mut self, snapshot: TrustSnapshot) {
        self.snapshot = snapshot;
        self.selected = self.selected.min(self.snapshot.rows.len().saturating_sub(1));
        self.confirm = None;
    }
}

/// What a key did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustKeyOutcome {
    Unchanged,
    Changed,
    Close,
    /// Close and send [`GRANT_COMMAND`].
    Grant,
    /// Close and send [`REVOKE_COMMAND`].
    RevokeCurrent,
    /// Stop trusting this folder (another listed folder); the modal stays open.
    RevokeOther(PathBuf),
}

/// Keys: `Tab`/`Shift+Tab` switch tabs; `t` trust this folder; `u` stop trusting (this folder, or the selected row);
/// `Up/Down` or `k/j` select; a confirm takes `y`, any other key (`Enter` included) cancels it; `Esc` closes.
pub fn handle_trust_key(state: &mut TrustModalState, key: &KeyEvent) -> TrustKeyOutcome {
    if key.kind == KeyEventKind::Release {
        return TrustKeyOutcome::Unchanged;
    }
    if let Some(confirm) = state.confirm.take() {
        return match key.code {
            KeyCode::Char('y') => match confirm {
                Confirm::Grant => TrustKeyOutcome::Grant,
                Confirm::RevokeCurrent => TrustKeyOutcome::RevokeCurrent,
                Confirm::RevokeOther(folder) => TrustKeyOutcome::RevokeOther(folder),
            },
            _ => TrustKeyOutcome::Changed,
        };
    }
    let rows = state.snapshot.rows.len();
    match (state.tab(), key.code) {
        (_, KeyCode::Esc) => TrustKeyOutcome::Close,
        (_, KeyCode::Tab | KeyCode::BackTab) => {
            state.window.active_tab = 1 - state.tab();
            TrustKeyOutcome::Changed
        }
        (0, KeyCode::Char('t')) if state.snapshot.status.can_grant() => {
            state.confirm = Some(Confirm::Grant);
            TrustKeyOutcome::Changed
        }
        (0, KeyCode::Char('u')) if state.snapshot.status == TrustStatus::Trusted && state.snapshot.key.is_some() => {
            state.confirm = Some(Confirm::RevokeCurrent);
            TrustKeyOutcome::Changed
        }
        (1, KeyCode::Up | KeyCode::Char('k')) if state.selected > 0 => {
            state.selected -= 1;
            TrustKeyOutcome::Changed
        }
        (1, KeyCode::Down | KeyCode::Char('j')) if state.selected + 1 < rows => {
            state.selected += 1;
            TrustKeyOutcome::Changed
        }
        (1, KeyCode::Char('u') | KeyCode::Delete) => match state.snapshot.rows.get(state.selected) {
            Some(row) if row.current => {
                state.confirm = Some(Confirm::RevokeCurrent);
                TrustKeyOutcome::Changed
            }
            Some(row) => {
                state.confirm = Some(Confirm::RevokeOther(row.folder.clone()));
                TrustKeyOutcome::Changed
            }
            None => TrustKeyOutcome::Unchanged,
        },
        _ => TrustKeyOutcome::Unchanged,
    }
}

fn shown(path: &Path) -> String {
    fuigo_tty_utils::untrusted(path.display()).to_string()
}

fn confirm_text(confirm: &Confirm) -> String {
    match confirm {
        Confirm::Grant => "Trust this folder? Its settings load and its shell commands run without asking. \
                           y yes, any other key no"
            .to_owned(),
        Confirm::RevokeCurrent => "Stop trusting this folder? Shell commands ask again; settings already loaded stay \
                                   until you reopen this session. y yes, any other key no"
            .to_owned(),
        Confirm::RevokeOther(folder) => format!(
            "Stop trusting {}? Sessions already open there keep their settings until reopened. y yes, any other key no",
            shown(folder)
        ),
    }
}

/// The content lines of the tab on screen, without chrome.
pub fn content_lines(state: &TrustModalState, theme: &Theme) -> Vec<Line<'static>> {
    let label = Style::default().fg(theme.gray);
    let text = Style::default().fg(theme.text_primary);
    let mut lines = Vec::new();
    let snap = &state.snapshot;
    if state.tab() == 0 {
        lines.push(Line::from(vec![Span::styled("Folder     ", label), Span::styled(shown(&snap.cwd), text)]));
        if let Some(key) = snap.key.as_deref().filter(|k| *k != snap.cwd.as_path()) {
            lines.push(Line::from(vec![Span::styled("Trust key  ", label), Span::styled(shown(key), text)]));
        }
        let status_style = match snap.status {
            TrustStatus::Trusted | TrustStatus::Off => Style::default().fg(theme.accent_success),
            TrustStatus::Never | TrustStatus::Unreadable => Style::default().fg(theme.accent_error),
            _ => Style::default().fg(theme.warning),
        };
        lines.push(Line::from(vec![Span::styled("Status     ", label), Span::styled(snap.status.line(), status_style)]));
        lines.push(Line::default());
        lines.push(Line::styled(
            "Trust covers the folder's settings (MCP servers, hooks, skills, rules) and its shell commands.",
            label,
        ));
    } else if snap.rows.is_empty() {
        lines.push(Line::styled("No trusted folders yet.", label));
    } else {
        for (i, row) in snap.rows.iter().enumerate() {
            let selected = i == state.selected;
            let mut spans = vec![
                Span::styled(if selected { "> " } else { "  " }, Style::default().fg(theme.accent_user)),
                Span::styled(
                    shown(&row.folder),
                    if selected { text.add_modifier(Modifier::BOLD) } else { text },
                ),
            ];
            if row.current {
                spans.push(Span::styled("  (this folder)", Style::default().fg(theme.accent_user)));
            }
            if row.settings_only {
                spans.push(Span::styled("  (settings only)", Style::default().fg(theme.warning)));
            }
            lines.push(Line::from(spans));
        }
    }
    if state.tab() == 1 {
        lines.push(Line::default());
        lines.push(Line::styled(
            "Folders in your ~/.fuigo/config.toml [folder_trust] trusted_folders are managed there.",
            label,
        ));
    }
    if let Some(confirm) = &state.confirm {
        lines.push(Line::default());
        lines.push(Line::styled(confirm_text(confirm), Style::default().fg(theme.warning).add_modifier(Modifier::BOLD)));
    }
    lines
}

fn shortcuts(state: &TrustModalState) -> Vec<Shortcut<'static>> {
    let hint = |label| Shortcut { label, clickable: false, id: 0 };
    let mut out = Vec::new();
    if state.confirm.is_some() {
        out.push(hint("y confirm"));
        out.push(hint("any key cancel"));
        return out;
    }
    if state.tab() == 0 {
        if state.snapshot.status.can_grant() {
            out.push(hint("t trust this folder"));
        }
        if state.snapshot.status == TrustStatus::Trusted && state.snapshot.key.is_some() {
            out.push(hint("u stop trusting"));
        }
    } else if !state.snapshot.rows.is_empty() {
        out.push(hint("\u{2191}/\u{2193} select"));
        out.push(hint("u stop trusting"));
    }
    out.push(hint("Tab switch"));
    out.push(hint("Esc close"));
    out
}

/// Render the modal.
pub fn render_trust_modal(buf: &mut Buffer, area: Rect, state: &mut TrustModalState, compact: bool) {
    let theme = Theme::current();
    let shortcuts = shortcuts(state);
    let config = ModalWindowConfig {
        title: TITLE,
        tabs: Some(TABS),
        shortcuts: &shortcuts,
        sizing: ModalSizing {
            width_pct: 0.75,
            max_width: 120,
            min_width: 44,
            v_margin: 3,
            h_pad: 2,
            v_pad: 1,
            footer_lines: 2,
        }
        .with_compact(compact),
        fold_info: None,
    };
    let Some(ModalContentArea { content, .. }) =
        modal_window::render_modal_window(buf, area, &mut state.window, &config, &theme)
    else {
        return;
    };
    Paragraph::new(content_lines(state, &theme)).wrap(Wrap { trim: false }).render(content, buf);
}

#[cfg(test)]
#[path = "trust_modal_tests.rs"]
mod tests;
