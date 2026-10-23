//! `fuigo login`: the sign-in picker on a terminal, and one command per provider.
//!
//! The same rows the welcome screen and `/login` show come from
//! [`fuigo_shell::auth::provider_status::ProviderStatus`], so the three entry points
//! cannot drift. Subscription sign-in is the existing exact-recipient flow
//! (`subscription::cli_login`); this module only chooses and reports.
//!
//! Third-party API keys are never stored by Fuigo: a key lives in the environment, and
//! `/provider` writes only the variable NAME to config.toml.
#![deny(clippy::print_stdout)]

use crate::app::cli::LoginTarget;
use fuigo_shell::auth::provider_status::{
    CHOOSE_LINE, FLUX_SIGNUP, PickerChoice, ProviderStatus, tail_mask,
};
use fuigo_shell::auth::subscription::{self, SubscriptionProvider};
use std::io::{BufRead, IsTerminal, Write};

/// What the caller does after [`run`].
#[derive(Debug, PartialEq, Eq)]
pub enum Next {
    Done,
    /// Run the deployment's OIDC / external-provider login (the old `fuigo login`).
    Sso,
    /// Exit with this code (the options were already printed).
    Exit(i32),
}

/// What a `fuigo login ...` invocation means. Pure, so the routing is testable without a terminal.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// `--status`: every provider's state (or one subscription's stored accounts).
    Status(Option<LoginTarget>),
    /// Bare `fuigo login` on a terminal.
    Picker,
    /// Bare `fuigo login` without a terminal: print the options, exit 2.
    PrintOptionsAndExit2,
    /// `--provider X`.
    Provider(LoginTarget),
    /// `--provider sso`: the old OIDC path.
    Sso,
}

pub fn plan(target: Option<LoginTarget>, status: bool, tty: bool) -> Plan {
    match (target, status) {
        (t, true) => Plan::Status(t),
        (Some(LoginTarget::Sso), false) => Plan::Sso,
        (Some(t), false) => Plan::Provider(t),
        (None, false) if tty => Plan::Picker,
        (None, false) => Plan::PrintOptionsAndExit2,
    }
}

/// An OIDC issuer or an external auth command is configured: the only case that shows the SSO row.
pub fn sso_configured() -> bool {
    fuigo_shell::config::load_agent_config_disk_only()
        .map(|c| {
            c.fuigo_com_config.oidc.is_some() || c.fuigo_com_config.auth_provider_command.is_some()
        })
        .unwrap_or(false)
}

pub async fn run(target: Option<LoginTarget>, status: bool) -> anyhow::Result<Next> {
    let tty = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    match plan(target, status, tty) {
        Plan::Sso => Ok(Next::Sso),
        Plan::Status(Some(t)) => match subscription_of(t) {
            Some(p) => {
                subscription::cli_status(p).await?;
                Ok(Next::Done)
            }
            None => {
                fuigo_tty_utils::cli_println!("{}", ProviderStatus::current(sso_configured()).status_text());
                Ok(Next::Done)
            }
        },
        Plan::Status(None) => {
            fuigo_tty_utils::cli_println!("{}", ProviderStatus::current(sso_configured()).status_text());
            Ok(Next::Done)
        }
        Plan::PrintOptionsAndExit2 => {
            fuigo_tty_utils::cli_println!("{}", ProviderStatus::current(sso_configured()).picker_text());
            Ok(Next::Exit(2))
        }
        Plan::Provider(t) => sign_in(t).await,
        Plan::Picker => picker().await,
    }
}

fn subscription_of(t: LoginTarget) -> Option<SubscriptionProvider> {
    match t {
        LoginTarget::Chatgpt => Some(SubscriptionProvider::Chatgpt),
        LoginTarget::Xai => Some(SubscriptionProvider::Xai),
        _ => None,
    }
}

async fn sign_in(target: LoginTarget) -> anyhow::Result<Next> {
    match target {
        LoginTarget::Sso => Ok(Next::Sso),
        LoginTarget::Flux => {
            flux().await?;
            Ok(Next::Done)
        }
        LoginTarget::Chatgpt | LoginTarget::Xai => {
            subscription::cli_login(subscription_of(target).expect("subscription target")).await?;
            Ok(Next::Done)
        }
        key => {
            let id = key.key_provider_id().expect("remaining targets are key providers");
            Ok(Next::Exit(provider_key(id).await))
        }
    }
}

/// Flux: use the key already in the environment, or ask for one with echo off.
async fn flux() -> anyhow::Result<()> {
    let home = fuigo_dirs::resolve_fuigo_home()
        .ok_or_else(|| anyhow::anyhow!("cannot locate the Fuigo home directory"))?;
    let status = ProviderStatus::current(false);
    let key = if let Some(var) = status.flux_env_var() {
        fuigo_shell::agent::key_discovery::discover_appliable()
            .into_iter()
            .find(|d| d.env_var == var)
            .map(|d| d.key().to_owned())
            .ok_or_else(|| anyhow::anyhow!("{var} changed while signing in; try again"))?
    } else {
        if std::io::stdin().is_terminal() {
            fuigo_tty_utils::cli_eprintln!(
                "Paste your Flux Router key (one key, every model; get one at {FLUX_SIGNUP}). Input is hidden."
            );
            subscription::prompt_secret()
                .await
                .map_err(|_| anyhow::anyhow!("could not read a key from the terminal"))?
        } else {
            // Piped: `fuigo login --provider flux < keyfile`. One line, never echoed or logged.
            read_key_line(&mut std::io::stdin().lock()).ok_or_else(|| {
                anyhow::anyhow!("could not read a key from standard input (expected one line)")
            })?
        }
    };
    let key = key.trim().to_owned();
    anyhow::ensure!(!key.is_empty(), "no key entered");
    fuigo_shell::auth::store_api_key(&home, &key)?;
    let explicit = fuigo_shell::config::load_agent_config_disk_only()
        .ok()
        .and_then(|c| c.models.default);
    fuigo_tty_utils::cli_eprintln!(
        "{}",
        ProviderStatus::flux_login_summary(&tail_mask(&key), explicit.as_deref())
    );
    Ok(())
}

/// The first line of a piped stdin, as the key: `None` when the stream is empty or unreadable. The caller trims it
/// and applies the same checks as the terminal path.
fn read_key_line(reader: &mut impl BufRead) -> Option<String> {
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line),
    }
}

/// A provider API key stays in the environment. Report whether it can be used now, and what to do if not.
async fn provider_key(id: &str) -> i32 {
    let status = ProviderStatus::current(false);
    let Some(c) = status.connections().into_iter().find(|c| {
        matches!(c.id, fuigo_shell::auth::provider_status::ConnectionId::Key(k) if k == id)
    }) else {
        fuigo_tty_utils::cli_eprintln!("unknown provider {id}");
        return 2;
    };
    fuigo_tty_utils::cli_eprintln!("{}: {}", c.name, c.state);
    if c.ready {
        // The key is set: list that provider's models now (its standard /models endpoint), so /model
        // offers them with no further step.
        if let Some(home) = fuigo_dirs::resolve_fuigo_home() {
            let user_base = fuigo_shell::config::load_agent_config_disk_only()
                .ok()
                .and_then(|c| c.model_providers.get(id).and_then(|p| p.base_url.clone()));
            let results = fuigo_shell::auth::key_models::refresh(
                std::path::Path::new(&home),
                |name| std::env::var(name).ok(),
                Some(id),
                true,
                |p| fuigo_shell::auth::key_models::base_url_for(p, user_base.as_deref()),
            )
            .await;
            for r in results {
                match r.result {
                    Ok(n) => fuigo_tty_utils::cli_eprintln!(
                        "Listed {n} {} models. They appear in /model, ranked after Flux Router and any subscription.",
                        r.label
                    ),
                    Err(_) => fuigo_tty_utils::cli_eprintln!(
                        "Could not list {} models just now; Fuigo retries when it starts.",
                        r.label
                    ),
                }
            }
        }
        fuigo_tty_utils::cli_eprintln!(
            "Fuigo does not store this key. Run `fuigo`, then /model to choose a model, or /provider {id} <model-id> to route one by hand."
        );
        0
    } else {
        fuigo_tty_utils::cli_eprintln!(
            "Fuigo does not store third-party keys: export the variable above in your shell, then run `fuigo login --provider {id}` again."
        );
        2
    }
}

/// Map the user's answer ("2", "", "q") onto a row. Empty means the first row (Flux).
pub fn choice_from_input(
    rows: &[fuigo_shell::auth::provider_status::PickerRow],
    input: &str,
) -> Option<PickerChoice> {
    let t = input.trim();
    if t.is_empty() {
        return rows.first().map(|r| r.choice);
    }
    if t.eq_ignore_ascii_case("q") {
        return Some(PickerChoice::Exit);
    }
    let n: usize = t.parse().ok()?;
    rows.get(n.checked_sub(1)?).map(|r| r.choice)
}

fn read_line() -> Option<String> {
    let mut line = String::new();
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line),
    }
}

async fn picker() -> anyhow::Result<Next> {
    let status = ProviderStatus::current(sso_configured());
    let rows = status.picker_rows(false);
    fuigo_tty_utils::cli_eprintln!("{CHOOSE_LINE}\n");
    for (i, row) in rows.iter().enumerate() {
        fuigo_tty_utils::cli_eprintln!("  {}. {}", i + 1, fuigo_tty_utils::untrusted(&row.label));
    }
    let _ = write!(std::io::stderr(), "\nEnter a number [1]: ");
    let _ = std::io::stderr().flush();
    let Some(answer) = read_line() else {
        return Ok(Next::Exit(1));
    };
    match choice_from_input(&rows, &answer) {
        Some(PickerChoice::Flux) => sign_in(LoginTarget::Flux).await,
        Some(PickerChoice::Chatgpt) => sign_in(LoginTarget::Chatgpt).await,
        Some(PickerChoice::Xai) => sign_in(LoginTarget::Xai).await,
        Some(PickerChoice::Sso) => Ok(Next::Sso),
        Some(PickerChoice::Exit) => Ok(Next::Done),
        Some(PickerChoice::ProviderKey) => provider_key_list(&status).await,
        // The terminal picker has no sign-out rows (`/login` does); `fuigo logout` removes a subscription.
        None | Some(PickerChoice::SignOut(_)) => {
            fuigo_tty_utils::cli_eprintln!("Not an option. Run `fuigo login` again.");
            Ok(Next::Exit(2))
        }
    }
}

async fn provider_key_list(status: &ProviderStatus) -> anyhow::Result<Next> {
    use fuigo_shell::auth::provider_status::ConnectionId;
    let keys: Vec<_> = status
        .connections()
        .into_iter()
        .filter(|c| matches!(c.id, ConnectionId::Key(_)))
        .collect();
    fuigo_tty_utils::cli_eprintln!("\nProvider API key:\n");
    for (i, c) in keys.iter().enumerate() {
        fuigo_tty_utils::cli_eprintln!("  {}. {}  {}", i + 1, c.name, c.state);
    }
    let _ = write!(std::io::stderr(), "\nEnter a number: ");
    let _ = std::io::stderr().flush();
    let Some(answer) = read_line() else {
        return Ok(Next::Exit(1));
    };
    let picked = answer
        .trim()
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
        .and_then(|n| keys.get(n));
    match picked.map(|c| c.id) {
        Some(ConnectionId::Key(id)) => Ok(Next::Exit(provider_key(id).await)),
        _ => Ok(Next::Exit(2)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuigo_shell::auth::provider_status::ProviderStatus;

    #[test]
    fn a_piped_key_is_read_as_one_line() {
        let mut input = std::io::Cursor::new(b"flx-fake-key-123\r\nsecond line\n".to_vec());
        assert_eq!(read_key_line(&mut input).as_deref().map(str::trim), Some("flx-fake-key-123"));
        assert_eq!(read_key_line(&mut std::io::Cursor::new(Vec::new())), None);
    }

    #[test]
    fn bare_login_on_a_terminal_opens_the_picker_and_without_one_prints_options() {
        assert_eq!(plan(None, false, true), Plan::Picker);
        assert_eq!(plan(None, false, false), Plan::PrintOptionsAndExit2);
    }

    #[test]
    fn provider_flags_skip_straight_to_that_sign_in() {
        assert_eq!(plan(Some(LoginTarget::Flux), false, false), Plan::Provider(LoginTarget::Flux));
        assert_eq!(plan(Some(LoginTarget::Xai), false, true), Plan::Provider(LoginTarget::Xai));
        assert_eq!(plan(Some(LoginTarget::Openai), false, false), Plan::Provider(LoginTarget::Openai));
    }

    #[test]
    fn sso_keeps_the_old_path_and_nothing_else_reaches_it() {
        assert_eq!(plan(Some(LoginTarget::Sso), false, false), Plan::Sso);
        for t in [None, Some(LoginTarget::Flux), Some(LoginTarget::Chatgpt)] {
            assert_ne!(plan(t, false, true), Plan::Sso);
            assert_ne!(plan(t, false, false), Plan::Sso);
        }
    }

    #[test]
    fn status_flag_lists_without_signing_in() {
        assert_eq!(plan(None, true, false), Plan::Status(None));
        assert_eq!(plan(Some(LoginTarget::Chatgpt), true, true), Plan::Status(Some(LoginTarget::Chatgpt)));
    }

    #[test]
    fn the_non_tty_text_never_mentions_the_oidc_error() {
        let dir = tempfile::tempdir().unwrap();
        let text = ProviderStatus::collect(dir.path(), |_| None, false).picker_text();
        assert!(!text.contains("OAuth2 issuer"), "{text}");
        assert!(!text.to_lowercase().contains("enterprise"), "{text}");
        assert!(text.contains("fuigo login --provider flux"));
    }

    #[test]
    fn answers_map_onto_rows() {
        let dir = tempfile::tempdir().unwrap();
        let rows = ProviderStatus::collect(dir.path(), |_| None, false).picker_rows(false);
        assert_eq!(choice_from_input(&rows, ""), Some(PickerChoice::Flux));
        assert_eq!(choice_from_input(&rows, "2"), Some(PickerChoice::Chatgpt));
        assert_eq!(choice_from_input(&rows, "3"), Some(PickerChoice::Xai));
        assert_eq!(choice_from_input(&rows, "4"), Some(PickerChoice::ProviderKey));
        assert_eq!(choice_from_input(&rows, "5"), Some(PickerChoice::Exit));
        assert_eq!(choice_from_input(&rows, "q"), Some(PickerChoice::Exit));
        assert_eq!(choice_from_input(&rows, "6"), None);
        assert_eq!(choice_from_input(&rows, "0"), None);
        assert_eq!(choice_from_input(&rows, "x"), None);
    }
}
