//! The unauthenticated welcome menu, defined once.
//!
//! The renderer and the click dispatcher previously agreed on this layout by
//! coincidence: `views/welcome/mod.rs` built `[("k", …), ("l", …), ("q", …)]`
//! while `dispatch_pending_menu_action` hardcoded `0 => EnterApiKey,
//! 1 => Login` and derived Quit from the rect count. That held only while the
//! menu had two or three fixed rows. Adding a row silently remapped every
//! click — the kind of defect that produces a wrong action, not a crash.
//!
//! Both sides now build from [`pending_menu_rows`], so the mapping cannot
//! drift.

/// What the menu needs to *display* about a discovered credential.
///
/// Display-only, on purpose: no key material. The secret stays in the process
/// environment where it already was, and is re-read at dispatch time from
/// `key_discovery::discover_appliable()` by matching `env_var`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedKeyRow {
    /// Provider name, e.g. "FluxRouter".
    pub provider_label: String,
    /// The variable it came from, e.g. "FLUX_API_KEY". Safe to display.
    pub env_var: String,
    /// Redacted key, e.g. "sk-B0g...eERw".
    pub masked: String,
}

/// A row of the pending menu, in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingMenuRow {
    /// Apply a credential discovered in the environment. The payload is an
    /// index into `key_discovery::discover_appliable()`, deliberately not the
    /// key itself: `Action` and `Effect` are `#[derive(Debug)]`, so a secret
    /// in a variant is one stray `{:?}` away from a log file.
    UseDetectedKey(usize),
    /// Type a key by hand.
    EnterApiKey,
    /// Interactive login. Only present when an issuer is configured.
    Login,
    Quit,
}

/// How many detected rows may be shown.
///
/// `render_menu` drops rows that do not fit the available height
/// (`views/welcome/menu.rs`), and Quit is identified by position — so a
/// truncated menu would map a credential row onto Quit. Capping keeps the
/// menu inside the smallest sensible terminal.
///
/// Only FluxRouter-family keys are appliable today, and `discover_appliable`
/// yields at most one entry per provider, so this is currently a ceiling
/// rather than a limit that binds.
pub const MAX_DETECTED_ROWS: usize = 3;

/// The rows of the pending menu, in display order.
pub fn pending_menu_rows(detected: usize, has_login: bool) -> Vec<PendingMenuRow> {
    let mut rows: Vec<PendingMenuRow> = (0..detected.min(MAX_DETECTED_ROWS))
        .map(PendingMenuRow::UseDetectedKey)
        .collect();
    rows.push(PendingMenuRow::EnterApiKey);
    if has_login {
        rows.push(PendingMenuRow::Login);
    }
    rows.push(PendingMenuRow::Quit);
    rows
}

/// The keyboard shortcut for a row. Detected rows are numbered from 1.
pub fn row_shortcut(row: PendingMenuRow) -> String {
    match row {
        PendingMenuRow::UseDetectedKey(i) => (i + 1).to_string(),
        PendingMenuRow::EnterApiKey => "k".to_string(),
        PendingMenuRow::Login => "l".to_string(),
        PendingMenuRow::Quit => "q".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_detected_keys_reproduces_the_original_menu() {
        assert_eq!(
            pending_menu_rows(0, true),
            vec![
                PendingMenuRow::EnterApiKey,
                PendingMenuRow::Login,
                PendingMenuRow::Quit
            ]
        );
        assert_eq!(
            pending_menu_rows(0, false),
            vec![PendingMenuRow::EnterApiKey, PendingMenuRow::Quit]
        );
    }

    #[test]
    fn detected_rows_come_first_and_are_numbered_from_one() {
        let rows = pending_menu_rows(2, true);
        assert_eq!(rows[0], PendingMenuRow::UseDetectedKey(0));
        assert_eq!(rows[1], PendingMenuRow::UseDetectedKey(1));
        assert_eq!(row_shortcut(rows[0]), "1");
        assert_eq!(row_shortcut(rows[1]), "2");
        assert_eq!(rows[2], PendingMenuRow::EnterApiKey);
    }

    /// Quit must be last in every shape, because the dispatcher identifies it
    /// by position.
    #[test]
    fn quit_is_always_the_final_row() {
        for detected in 0..6 {
            for has_login in [false, true] {
                let rows = pending_menu_rows(detected, has_login);
                assert_eq!(*rows.last().unwrap(), PendingMenuRow::Quit);
                assert_eq!(
                    rows.iter().filter(|r| **r == PendingMenuRow::Quit).count(),
                    1
                );
            }
        }
    }

    /// Without a cap a long detected list could push the menu past the height
    /// `render_menu` will paint, and the dropped tail would take Quit with it.
    #[test]
    fn detected_rows_are_capped() {
        let rows = pending_menu_rows(9, true);
        let detected = rows
            .iter()
            .filter(|r| matches!(r, PendingMenuRow::UseDetectedKey(_)))
            .count();
        assert_eq!(detected, MAX_DETECTED_ROWS);
        assert!(rows.len() <= MAX_DETECTED_ROWS + 3);
    }

    /// The regression the audit caught: clicking row *i* must invoke the row
    /// the renderer actually painted at *i*, for every menu shape.
    #[test]
    fn click_index_matches_the_painted_row() {
        for detected in 0..5 {
            for has_login in [false, true] {
                let rows = pending_menu_rows(detected, has_login);
                for (i, row) in rows.iter().enumerate() {
                    assert_eq!(
                        rows.get(i).copied(),
                        Some(*row),
                        "index {i} drifted for detected={detected} login={has_login}"
                    );
                }
            }
        }
    }
}
