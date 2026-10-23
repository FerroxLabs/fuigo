//! The sign-in picker on the welcome screen and in `/login`, defined once.
//!
//! The renderer and the click/key dispatcher both build from [`pending_menu_rows`], so the
//! mapping from a painted row to its action cannot drift. The rows and their labels come from
//! [`ProviderStatus::picker_rows`], the same source the CLI picker and `/provider` read.

use fuigo_shell::auth::provider_status::{PickerChoice, ProviderStatus};
use fuigo_shell::auth::subscription::SubscriptionProvider;

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

/// A row of the picker, in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingMenuRow {
    /// Apply the Flux key found in the environment. The dispatcher turns this into the variable
    /// NAME before building an action, so nothing positional survives past the click.
    UseDetectedKey,
    /// Type a Flux key by hand.
    EnterApiKey,
    /// Sign in with a ChatGPT or Grok subscription.
    SignIn(SubscriptionProvider),
    /// The list of provider API keys.
    ProviderKeys,
    /// Single sign-on. Only present when an issuer or external auth command is configured.
    Login,
    /// Remove a signed-in subscription from this machine (`/login` only).
    SignOut(SubscriptionProvider),
    /// "Quit" on first run.
    Quit,
    /// "Cancel" in the `/login` modal.
    Cancel,
    /// A provider API key row on the provider-key page (the provider id).
    KeyProvider(&'static str),
    /// "Other OpenAI-compatible endpoint" on the provider-key page.
    KeyOther,
    /// Back from the provider-key page to the picker.
    Back,
    /// A usable model on the "Pick a model:" page (index into `ModelState::usable_models`).
    UseModel(usize),
    /// Whether the pick is also saved as the default model.
    ToggleMakeDefault,
    /// From the "Pick a model:" page to the connections picker.
    MoreConnections,
}

/// Which list the picker is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PickerPage {
    #[default]
    Main,
    ProviderKeys,
    /// "Pick a model:" shown when the user's own default model cannot be used.
    PickModel,
}

/// One painted row: its action and its label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuEntry {
    pub row: PendingMenuRow,
    pub label: String,
}

/// The rows of a picker page with their labels. The renderer paints these and the dispatcher
/// indexes into them, so a click can never run an action the user was not shown.
pub fn menu_entries(status: &ProviderStatus, modal: bool, page: PickerPage) -> Vec<MenuEntry> {
    match page {
        PickerPage::Main | PickerPage::PickModel => pending_menu_rows(status, modal)
            .into_iter()
            .zip(status.picker_rows(modal))
            .map(|(row, picked)| MenuEntry {
                row,
                label: picked.label,
            })
            .collect(),
        PickerPage::ProviderKeys => {
            use fuigo_shell::auth::provider_status::ConnectionId;
            let mut out: Vec<MenuEntry> = status
                .connections()
                .into_iter()
                .filter_map(|c| match c.id {
                    ConnectionId::Key(id) => Some(MenuEntry {
                        row: PendingMenuRow::KeyProvider(id),
                        label: format!("{}  {}", c.name, c.state),
                    }),
                    _ => None,
                })
                .collect();
            out.push(MenuEntry {
                row: PendingMenuRow::KeyOther,
                label: "Other OpenAI-compatible endpoint".to_string(),
            });
            out.push(MenuEntry {
                row: PendingMenuRow::Back,
                label: "Back".to_string(),
            });
            out
        }
    }
}

/// Most models the "Pick a model:" page lists: each is reachable by its digit.
const MAX_PICK_ROWS: usize = 7;

/// [`menu_entries`] with the model list, for the "Pick a model:" page. Every other page is unchanged.
pub fn menu_entries_for(
    status: &ProviderStatus,
    modal: bool,
    page: PickerPage,
    models: &crate::acp::model_state::ModelState,
    make_default: bool,
) -> Vec<MenuEntry> {
    if page != PickerPage::PickModel {
        return menu_entries(status, modal, page);
    }
    let mut out: Vec<MenuEntry> = models
        .usable_models()
        .into_iter()
        .take(MAX_PICK_ROWS)
        .enumerate()
        .map(|(i, m)| MenuEntry {
            row: PendingMenuRow::UseModel(i),
            label: if m.badge.is_empty() {
                m.name
            } else {
                format!("{} \u{b7} {}", m.name, m.badge)
            },
        })
        .collect();
    out.push(MenuEntry {
        row: PendingMenuRow::ToggleMakeDefault,
        label: format!(
            "Make my pick the default model: {}",
            if make_default { "on" } else { "off" }
        ),
    });
    out.push(MenuEntry {
        row: PendingMenuRow::MoreConnections,
        label: "Connect something else...".to_string(),
    });
    out.push(MenuEntry {
        row: PendingMenuRow::Quit,
        label: "Quit".to_string(),
    });
    out
}

/// The rows of the picker, in display order: exactly the rows of
/// [`ProviderStatus::picker_rows`], so labels and actions are parallel.
pub fn pending_menu_rows(status: &ProviderStatus, modal: bool) -> Vec<PendingMenuRow> {
    status
        .picker_rows(modal)
        .iter()
        .map(|row| match row.choice {
            PickerChoice::Flux if status.flux_env_var().is_some() => PendingMenuRow::UseDetectedKey,
            PickerChoice::Flux => PendingMenuRow::EnterApiKey,
            PickerChoice::Chatgpt => PendingMenuRow::SignIn(SubscriptionProvider::Chatgpt),
            PickerChoice::Xai => PendingMenuRow::SignIn(SubscriptionProvider::Xai),
            PickerChoice::ProviderKey => PendingMenuRow::ProviderKeys,
            PickerChoice::Sso => PendingMenuRow::Login,
            PickerChoice::SignOut(provider) => PendingMenuRow::SignOut(provider),
            PickerChoice::Exit if modal => PendingMenuRow::Cancel,
            PickerChoice::Exit => PendingMenuRow::Quit,
        })
        .collect()
}

/// The keyboard shortcut for the row at `index`: rows are numbered from 1, and the exit row is `q`.
pub fn row_shortcut(rows: &[PendingMenuRow], index: usize) -> String {
    match rows.get(index) {
        Some(PendingMenuRow::Quit | PendingMenuRow::Cancel) => "q".to_string(),
        Some(PendingMenuRow::Back) => "b".to_string(),
        _ => (index + 1).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuigo_shell::auth::provider_status::ProviderStatus;

    fn status(env: &[(&str, &str)], sso: bool) -> ProviderStatus {
        let dir = tempfile::tempdir().unwrap();
        let env: Vec<(String, String)> = env
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        ProviderStatus::collect(
            dir.path(),
            move |name| env.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone()),
            sso,
        )
    }

    #[test]
    fn nothing_configured_offers_flux_first_and_no_sso() {
        let rows = pending_menu_rows(&status(&[], false), false);
        assert_eq!(
            rows,
            vec![
                PendingMenuRow::EnterApiKey,
                PendingMenuRow::SignIn(SubscriptionProvider::Chatgpt),
                PendingMenuRow::SignIn(SubscriptionProvider::Xai),
                PendingMenuRow::ProviderKeys,
                PendingMenuRow::Quit,
            ]
        );
    }

    #[test]
    fn a_flux_key_in_the_environment_becomes_the_first_row() {
        let rows = pending_menu_rows(
            &status(&[("FLUX_API_KEY", "sk-flux-abcdefgh-1234")], false),
            false,
        );
        assert_eq!(rows[0], PendingMenuRow::UseDetectedKey);
        assert_eq!(rows.len(), 5);
    }

    #[test]
    fn the_sso_row_exists_only_when_configured() {
        assert!(!pending_menu_rows(&status(&[], false), false).contains(&PendingMenuRow::Login));
        let with = pending_menu_rows(&status(&[], true), false);
        assert!(with.contains(&PendingMenuRow::Login));
        assert_eq!(*with.last().unwrap(), PendingMenuRow::Quit);
    }

    #[test]
    fn the_modal_ends_in_cancel_not_quit() {
        let rows = pending_menu_rows(&status(&[], false), true);
        assert_eq!(*rows.last().unwrap(), PendingMenuRow::Cancel);
        assert!(!rows.contains(&PendingMenuRow::Quit));
    }

    /// Quit/Cancel must be last in every shape, because clicks identify rows by position.
    #[test]
    fn the_exit_row_is_always_last_and_unique() {
        for env in [vec![], vec![("FLUX_API_KEY", "sk-flux-abcdefgh-1234")]] {
            for sso in [false, true] {
                for modal in [false, true] {
                    let rows = pending_menu_rows(&status(&env, sso), modal);
                    let exits = rows
                        .iter()
                        .filter(|r| matches!(r, PendingMenuRow::Quit | PendingMenuRow::Cancel))
                        .count();
                    assert_eq!(exits, 1);
                    assert!(matches!(
                        rows.last().unwrap(),
                        PendingMenuRow::Quit | PendingMenuRow::Cancel
                    ));
                }
            }
        }
    }

    /// Labels and actions are parallel: the renderer pairs `picker_rows()[i]` with `rows[i]`.
    #[test]
    fn the_modal_has_a_sign_out_row_for_a_signed_in_subscription() {
        use fuigo_shell::auth::provider_status::FluxState;
        use fuigo_shell::auth::subscription::catalog::SignedIn;
        let mut s = status(&[], false);
        s.subscriptions.push(SignedIn {
            provider: SubscriptionProvider::Xai,
            accounts: vec!["acct".into()],
            model_ids: vec![],
        });
        let _ = FluxState::NotSet;
        let rows = pending_menu_rows(&s, true);
        assert!(rows.contains(&PendingMenuRow::SignOut(SubscriptionProvider::Xai)));
        assert_eq!(*rows.last().unwrap(), PendingMenuRow::Cancel);
        assert!(!pending_menu_rows(&s, false).iter().any(|r| matches!(r, PendingMenuRow::SignOut(_))));
    }

    #[test]
    fn rows_and_labels_have_the_same_length() {
        for sso in [false, true] {
            for modal in [false, true] {
                let s = status(&[], sso);
                assert_eq!(
                    pending_menu_rows(&s, modal).len(),
                    s.picker_rows(modal).len()
                );
            }
        }
    }

    #[test]
    fn shortcuts_number_the_rows_and_the_exit_row_is_q() {
        let rows = pending_menu_rows(&status(&[], false), false);
        let shortcuts: Vec<String> = (0..rows.len()).map(|i| row_shortcut(&rows, i)).collect();
        assert_eq!(shortcuts, ["1", "2", "3", "4", "q"]);
    }

    #[test]
    fn the_provider_key_page_lists_each_key_provider_then_other_then_back() {
        let entries = menu_entries(
            &status(&[("OPENAI_API_KEY", "sk-openai-zyxwvuts-9876")], false),
            false,
            PickerPage::ProviderKeys,
        );
        let rows: Vec<PendingMenuRow> = entries.iter().map(|e| e.row).collect();
        assert!(rows.contains(&PendingMenuRow::KeyProvider("openai")));
        assert!(rows.contains(&PendingMenuRow::KeyProvider("anthropic")));
        // Flux is not a "provider API key": it has its own first row.
        assert!(!rows.contains(&PendingMenuRow::KeyProvider("fluxrouter")));
        assert_eq!(rows[rows.len() - 2], PendingMenuRow::KeyOther);
        assert_eq!(*rows.last().unwrap(), PendingMenuRow::Back);
        let openai = entries
            .iter()
            .find(|e| e.row == PendingMenuRow::KeyProvider("openai"))
            .unwrap();
        assert!(openai.label.contains("ready") && openai.label.contains("9876"));
        assert!(!openai.label.contains("zyxwvuts"));
    }
}
