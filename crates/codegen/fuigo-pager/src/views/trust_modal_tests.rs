//! F11: render and key tests for the `/trust` screens.

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

use super::*;

fn snap(status: TrustStatus, rows: &[(&str, bool, bool)]) -> TrustSnapshot {
    TrustSnapshot {
        cwd: PathBuf::from("/work/app/src"),
        key: Some(PathBuf::from("/work/app")),
        status,
        rows: rows
            .iter()
            .map(|(f, settings_only, current)| TrustRow {
                folder: PathBuf::from(f),
                settings_only: *settings_only,
                current: *current,
            })
            .collect(),
    }
}

fn list() -> TrustSnapshot {
    snap(
        TrustStatus::Trusted,
        &[("/work/app", false, true), ("/work/old", true, false), ("/work/other", false, false)],
    )
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn ch(c: char) -> KeyEvent {
    key(KeyCode::Char(c))
}

/// The modal as text, trailing spaces trimmed, blank edge rows dropped.
fn render(state: &mut TrustModalState) -> String {
    let area = Rect::new(0, 0, 110, 22);
    let mut buf = Buffer::empty(area);
    render_trust_modal(&mut buf, area, state, false);
    let mut rows: Vec<String> = (0..area.height)
        .map(|y| {
            let row: String = (0..area.width).map(|x| buf[(x, y)].symbol().to_string()).collect();
            row.trim_end().to_owned()
        })
        .collect();
    while rows.first().is_some_and(|r| r.is_empty()) {
        rows.remove(0);
    }
    while rows.last().is_some_and(|r| r.is_empty()) {
        rows.pop();
    }
    rows.join("\n")
}

#[test]
fn f11_render_this_folder_trusted() {
    insta::assert_snapshot!(render(&mut TrustModalState::new(list())));
}

#[test]
fn f11_render_this_folder_undecided() {
    insta::assert_snapshot!(render(&mut TrustModalState::new(snap(TrustStatus::Undecided, &[]))));
}

#[test]
fn f11_render_this_folder_never() {
    let mut s = snap(TrustStatus::Never, &[]);
    s.cwd = PathBuf::from("/home/me");
    s.key = None;
    insta::assert_snapshot!(render(&mut TrustModalState::new(s)));
}

#[test]
fn f11_render_this_folder_off() {
    insta::assert_snapshot!(render(&mut TrustModalState::new(snap(TrustStatus::Off, &[]))));
}

#[test]
fn f11_render_trusted_folders_list() {
    let mut state = TrustModalState::new(list());
    state.window.active_tab = 1;
    state.selected = 1;
    insta::assert_snapshot!(render(&mut state));
}

#[test]
fn f11_render_trusted_folders_empty() {
    let mut state = TrustModalState::new(snap(TrustStatus::Undecided, &[]));
    state.window.active_tab = 1;
    insta::assert_snapshot!(render(&mut state));
}

#[test]
fn f11_render_grant_confirm() {
    let mut state = TrustModalState::new(snap(TrustStatus::Declined, &[]));
    assert_eq!(handle_trust_key(&mut state, &ch('t')), TrustKeyOutcome::Changed);
    insta::assert_snapshot!(render(&mut state));
}

#[test]
fn f11_render_revoke_other_confirm() {
    let mut state = TrustModalState::new(list());
    state.window.active_tab = 1;
    state.selected = 2;
    handle_trust_key(&mut state, &ch('u'));
    insta::assert_snapshot!(render(&mut state));
}

#[test]
fn f11_key_grant_needs_confirm_then_sends_grant() {
    let mut state = TrustModalState::new(snap(TrustStatus::Undecided, &[]));
    assert_eq!(handle_trust_key(&mut state, &ch('t')), TrustKeyOutcome::Changed);
    assert_eq!(state.confirm, Some(Confirm::Grant));
    assert_eq!(handle_trust_key(&mut state, &ch('y')), TrustKeyOutcome::Grant);
    assert_eq!(state.confirm, None);
}

#[test]
fn f11_key_confirm_cancels_on_any_other_key() {
    let mut state = TrustModalState::new(snap(TrustStatus::SettingsOnly, &[]));
    handle_trust_key(&mut state, &ch('t'));
    assert_eq!(handle_trust_key(&mut state, &ch('n')), TrustKeyOutcome::Changed);
    assert_eq!(state.confirm, None);
    handle_trust_key(&mut state, &ch('t'));
    assert_eq!(handle_trust_key(&mut state, &key(KeyCode::Esc)), TrustKeyOutcome::Changed, "Esc cancels the confirm only");
    assert_eq!(handle_trust_key(&mut state, &key(KeyCode::Esc)), TrustKeyOutcome::Close);
}

#[test]
fn f11_key_no_grant_when_trusted_never_or_off() {
    for status in [TrustStatus::Trusted, TrustStatus::Never, TrustStatus::Off] {
        let mut state = TrustModalState::new(snap(status, &[]));
        assert_eq!(handle_trust_key(&mut state, &ch('t')), TrustKeyOutcome::Unchanged, "{status:?}");
        assert_eq!(state.confirm, None);
    }
}

#[test]
fn f11_key_revoke_this_folder() {
    let mut state = TrustModalState::new(list());
    assert_eq!(handle_trust_key(&mut state, &ch('u')), TrustKeyOutcome::Changed);
    assert_eq!(handle_trust_key(&mut state, &ch('y')), TrustKeyOutcome::RevokeCurrent);
    let mut untrusted = TrustModalState::new(snap(TrustStatus::Declined, &[]));
    assert_eq!(handle_trust_key(&mut untrusted, &ch('u')), TrustKeyOutcome::Unchanged, "nothing to revoke");
}

#[test]
fn f11_key_tabs_and_selection() {
    let mut state = TrustModalState::new(list());
    assert_eq!(state.tab(), 0);
    handle_trust_key(&mut state, &key(KeyCode::Tab));
    assert_eq!(state.tab(), 1);
    assert_eq!(handle_trust_key(&mut state, &key(KeyCode::Up)), TrustKeyOutcome::Unchanged, "top row");
    handle_trust_key(&mut state, &key(KeyCode::Down));
    handle_trust_key(&mut state, &ch('j'));
    assert_eq!(state.selected, 2);
    assert_eq!(handle_trust_key(&mut state, &key(KeyCode::Down)), TrustKeyOutcome::Unchanged, "last row");
    handle_trust_key(&mut state, &ch('k'));
    assert_eq!(state.selected, 1);
    handle_trust_key(&mut state, &key(KeyCode::BackTab));
    assert_eq!(state.tab(), 0);
}

#[test]
fn f11_key_revoke_rows() {
    let mut state = TrustModalState::new(list());
    state.window.active_tab = 1;
    state.selected = 2;
    handle_trust_key(&mut state, &ch('u'));
    assert_eq!(
        handle_trust_key(&mut state, &ch('y')),
        TrustKeyOutcome::RevokeOther(PathBuf::from("/work/other"))
    );
    // The row of this folder goes through the shell's `/hooks-untrust`, not the direct decline.
    state.selected = 0;
    handle_trust_key(&mut state, &key(KeyCode::Delete));
    // Review r1 M1: only `y` confirms (Enter cancels), see `r1m1_enter_does_not_confirm_a_grant`.
    assert_eq!(handle_trust_key(&mut state, &ch('y')), TrustKeyOutcome::RevokeCurrent);
}

#[test]
fn f11_refresh_clamps_selection() {
    let mut state = TrustModalState::new(list());
    state.selected = 2;
    state.confirm = Some(Confirm::Grant);
    state.refresh(snap(TrustStatus::Trusted, &[("/work/app", false, true)]));
    assert_eq!(state.selected, 0);
    assert_eq!(state.confirm, None);
}
