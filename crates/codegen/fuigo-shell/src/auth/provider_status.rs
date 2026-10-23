//! ONE provider-status source.
//!
//! The welcome screen, `/login`, `/provider`, `/model` and `fuigo login --status`
//! all read [`ProviderStatus`], so they cannot disagree about what is connected.
//! Everything is discovered with no setup: a Flux key (saved or in the environment),
//! each signed-in subscription, and each environment API key the detector knows.
//!
//! Display only. Nothing here authorises a request, and no secret leaves this module:
//! keys are reduced to their last four characters.

use crate::agent::key_discovery::{self, Provider};
use crate::auth::subscription::SubscriptionProvider;
use crate::auth::subscription::catalog::{self, SignedIn};
use std::path::Path;

/// Where to get a Flux key (already shown on the key-entry screen).
pub const FLUX_SIGNUP: &str = "fluxrouter.ai";
/// The picker's welcome line.
pub const CHOOSE_LINE: &str = "Choose how Fuigo reaches a model.";

/// `••••1234`: the last four characters only; shorter keys show no characters.
pub fn tail_mask(key: &str) -> String {
    let n = key.chars().count();
    if n < 12 {
        return "\u{2022}\u{2022}\u{2022}\u{2022}".to_string();
    }
    let tail: String = key.chars().skip(n - 4).collect();
    format!("\u{2022}\u{2022}\u{2022}\u{2022}{tail}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FluxState {
    /// A key saved by Fuigo in `auth.json`.
    Saved { masked: String },
    /// A key in the environment (`env_var` is the variable NAME).
    Env { env_var: String, masked: String },
    NotSet,
}

/// A non-Flux API key found in the environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvKey {
    pub provider_id: &'static str,
    pub label: &'static str,
    pub env_var: &'static str,
    pub masked: String,
    /// The models this key reaches, from the provider's own `/models` list (cached IDs only).
    /// Empty until the first list is fetched.
    pub model_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderStatus {
    pub flux: FluxState,
    pub subscriptions: Vec<SignedIn>,
    pub env_keys: Vec<EnvKey>,
    /// An OIDC issuer or an external auth command is configured.
    pub sso_configured: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionId {
    Flux,
    Subscription(SubscriptionProvider),
    Key(&'static str),
}

/// One row of the connections view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub id: ConnectionId,
    pub name: String,
    /// "Recommended" on Flux only.
    pub badge: Option<&'static str>,
    /// Usable right now.
    pub ready: bool,
    /// One line: state, and how to fix it when not ready.
    pub state: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickerChoice {
    Flux,
    Chatgpt,
    Xai,
    ProviderKey,
    Sso,
    /// Remove a signed-in subscription from this machine. Offered in the `/login` modal only.
    SignOut(SubscriptionProvider),
    /// "Quit" on first run, "Cancel" in the modal.
    Exit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickerRow {
    pub choice: PickerChoice,
    pub label: String,
}

impl ProviderStatus {
    /// Pure core: every input is explicit, so tests need no real home or environment.
    pub fn collect(
        home: &Path,
        lookup: impl Fn(&str) -> Option<String>,
        sso_configured: bool,
    ) -> Self {
        let found = key_discovery::discover_with(&lookup);
        let saved = crate::auth::read_api_key(home).filter(|k| !k.trim().is_empty());
        let flux_env = found.iter().find(|d| d.provider.applies_to_configured_endpoint);
        let flux = match (saved, flux_env) {
            (Some(key), _) => FluxState::Saved {
                masked: tail_mask(&key),
            },
            (None, Some(d)) => FluxState::Env {
                env_var: d.env_var.to_string(),
                masked: tail_mask(d.key()),
            },
            (None, None) => FluxState::NotSet,
        };
        let env_keys = found
            .iter()
            .filter(|d| !d.provider.applies_to_configured_endpoint)
            .map(|d| EnvKey {
                provider_id: d.provider.id,
                label: d.provider.label,
                env_var: d.env_var,
                masked: tail_mask(d.key()),
                model_ids: crate::auth::key_models::cached_model_ids(home, d.provider.id),
            })
            .collect();
        Self {
            flux,
            subscriptions: catalog::signed_in(home),
            env_keys,
            sso_configured,
        }
    }

    /// The real home and process environment.
    pub fn current(sso_configured: bool) -> Self {
        let home = fuigo_dirs::resolve_fuigo_home().unwrap_or_default();
        Self::collect(&home, |name| std::env::var(name).ok(), sso_configured)
    }

    pub fn flux_ready(&self) -> bool {
        !matches!(self.flux, FluxState::NotSet)
    }

    /// The variable to apply when the Flux row is "Use FLUX_API_KEY from your environment".
    pub fn flux_env_var(&self) -> Option<&str> {
        match &self.flux {
            FluxState::Env { env_var, .. } => Some(env_var),
            _ => None,
        }
    }

    pub fn subscription(&self, provider: SubscriptionProvider) -> Option<&SignedIn> {
        self.subscriptions.iter().find(|s| s.provider == provider)
    }

    /// Flux (when set) plus each signed-in subscription: the connections that make an unset
    /// default unambiguous.
    pub fn primary_connection_count(&self) -> usize {
        usize::from(self.flux_ready()) + self.subscriptions.len()
    }

    /// With the default unset, the model to start on when Flux Router is not set up: the best
    /// model of the first signed-in subscription, else of the first provider key whose models are
    /// listed (ranking: Flux, then a subscription, then a key; ties keep catalogue order, ChatGPT
    /// before Grok). `None` when Flux is ready (its own default stands) or nothing has a model list
    /// yet. An explicit default is the caller's to honour first.
    pub fn implicit_default_key(&self) -> Option<String> {
        if self.flux_ready() {
            return None;
        }
        if let Some(first) = self.subscriptions.iter().find(|s| !s.model_ids.is_empty()) {
            return Some(first.provider.model_key(&first.model_ids[0]));
        }
        let key = self.env_keys.iter().find(|k| !k.model_ids.is_empty())?;
        Some(format!("{}-key/{}", key.provider_id, key.model_ids[0]))
    }

    /// The closing line of a subscription sign-in. `explicit_default` is `[models] default`
    /// when the user set one; it is reported as unchanged, never replaced.
    pub fn login_summary(
        &self,
        provider: SubscriptionProvider,
        explicit_default: Option<&str>,
        catalogue_fetched: bool,
        identity: Option<&str>,
        next: &str,
    ) -> String {
        // Never the opaque account id: a display name when the sign-in carried one, else nothing.
        let who = identity.map_or_else(String::new, |name| format!(" as {name}"));
        let label = provider.label();
        if !catalogue_fetched
            && self.subscription(provider).is_none_or(|s| s.model_ids.is_empty())
        {
            return format!(
                "Signed in to {label}{who}. Its model list could not be fetched just now; \
                 Fuigo retries when it starts. {next}"
            );
        }
        // An existing default from another provider is never overridden; say so plainly.
        let own_prefix = format!("{}/", provider.name());
        if let Some(existing) = explicit_default.filter(|m| !m.starts_with(&own_prefix)) {
            return format!(
                "Signed in to {label}{who}. Your default model stays {existing}; \
                 use /model to pick a {label} model. {next}"
            );
        }
        let default = explicit_default
            .map(str::to_owned)
            .or_else(|| self.implicit_default_key())
            .unwrap_or_else(|| crate::models::default_model().to_string());
        format!("Signed in to {label}{who}. Default model: {default}. {next}")
    }

    /// The closing line of a Flux sign-in.
    pub fn flux_login_summary(masked: &str, explicit_default: Option<&str>) -> String {
        let default = explicit_default
            .map(str::to_owned)
            .unwrap_or_else(|| crate::models::default_model().to_string());
        format!("Signed in to Flux Router with key {masked}. Default model: {default}. Run `fuigo`.")
    }

    /// Every connection, Flux pinned first (and "Recommended") even when not set.
    pub fn connections(&self) -> Vec<Connection> {
        let mut out = Vec::new();
        let (ready, state) = match &self.flux {
            FluxState::Saved { masked } => (true, format!("ready: key {masked}")),
            FluxState::Env { env_var, masked } => {
                (true, format!("ready: {env_var} {masked} in your environment"))
            }
            FluxState::NotSet => (
                false,
                format!("Not set: one key, every model. Get a key at {FLUX_SIGNUP}"),
            ),
        };
        out.push(Connection {
            id: ConnectionId::Flux,
            name: "Flux Router".into(),
            badge: Some("Recommended"),
            ready,
            state,
        });
        for provider in SubscriptionProvider::ALL {
            let (ready, state) = match self.subscription(provider) {
                Some(_) => (true, "signed in".to_string()),
                None => (false, "not signed in: /login".to_string()),
            };
            out.push(Connection {
                id: ConnectionId::Subscription(provider),
                name: provider.label().into(),
                badge: None,
                ready,
                state,
            });
        }
        for p in key_discovery::PROVIDERS
            .iter()
            .filter(|p| !p.applies_to_configured_endpoint)
        {
            let (ready, state) = match self.env_keys.iter().find(|k| k.provider_id == p.id) {
                Some(k) if !k.model_ids.is_empty() => (
                    true,
                    format!("ready: {} {}, {} models listed", k.env_var, k.masked, k.model_ids.len()),
                ),
                Some(k) => (true, format!("ready: {} {}", k.env_var, k.masked)),
                None => (false, format!("not set: export {}", env_var_hint(p))),
            };
            out.push(Connection {
                id: ConnectionId::Key(p.id),
                name: format!("{} API key", p.label),
                badge: None,
                ready,
                state,
            });
        }
        out
    }

    /// The picker. Flux is always row 1; SSO only when configured.
    pub fn picker_rows(&self, modal: bool) -> Vec<PickerRow> {
        let flux_label = match &self.flux {
            FluxState::Env { env_var, masked } => {
                format!("Use {env_var} from your environment {masked}")
            }
            FluxState::Saved { masked } => {
                format!("Flux Router: one key, every model (recommended)  key {masked}")
            }
            FluxState::NotSet => "Flux Router: one key, every model (recommended)".to_string(),
        };
        let sub_label = |provider: SubscriptionProvider, base: &str| match self.subscription(provider) {
            Some(_) => format!("{base}  signed in"),
            None => base.to_string(),
        };
        let mut rows = vec![
            PickerRow {
                choice: PickerChoice::Flux,
                label: flux_label,
            },
            PickerRow {
                choice: PickerChoice::Chatgpt,
                label: sub_label(SubscriptionProvider::Chatgpt, "ChatGPT subscription (Plus/Pro)"),
            },
            PickerRow {
                choice: PickerChoice::Xai,
                label: sub_label(SubscriptionProvider::Xai, "Grok subscription"),
            },
            PickerRow {
                choice: PickerChoice::ProviderKey,
                label: "Provider API key...".to_string(),
            },
        ];
        if self.sso_configured {
            rows.push(PickerRow {
                choice: PickerChoice::Sso,
                label: "Enterprise SSO".to_string(),
            });
        }
        // `/login` doubles as an account switcher, so it can also remove one: a row per signed-in
        // subscription, ahead of Cancel. First run has nothing to sign out of.
        if modal {
            for signed in &self.subscriptions {
                rows.push(PickerRow {
                    choice: PickerChoice::SignOut(signed.provider),
                    label: format!("Sign out of {}", signed.provider.label()),
                });
            }
        }
        rows.push(PickerRow {
            choice: PickerChoice::Exit,
            label: if modal { "Cancel" } else { "Quit" }.to_string(),
        });
        rows
    }

    /// Plain-text picker for a non-TTY `fuigo login`: the options and the command for each.
    pub fn picker_text(&self) -> String {
        let mut out = String::from(CHOOSE_LINE);
        out.push_str("\n\n");
        let mut n = 0;
        for row in self.picker_rows(false) {
            let cmd = match row.choice {
                PickerChoice::Flux => "fuigo login --provider flux",
                PickerChoice::Chatgpt => "fuigo login --provider chatgpt",
                PickerChoice::Xai => "fuigo login --provider xai",
                PickerChoice::ProviderKey => "fuigo login --provider openai|anthropic|google|...",
                PickerChoice::Sso => "fuigo login --provider sso",
                PickerChoice::SignOut(_) | PickerChoice::Exit => continue,
            };
            n += 1;
            out.push_str(&format!("  {n}. {}\n     {cmd}\n", row.label));
        }
        out.push_str("\nRun one of the commands above, or run `fuigo login` in a terminal.\n");
        out
    }

    /// `fuigo login --status` and the connections view: one line per connection.
    pub fn status_text(&self) -> String {
        let mut out = String::new();
        for c in self.connections() {
            let badge = c.badge.map(|b| format!(" [{b}]")).unwrap_or_default();
            out.push_str(&format!("{}{}: {}\n", c.name, badge, c.state));
        }
        if self.sso_configured {
            out.push_str("Enterprise SSO: configured: fuigo login --provider sso\n");
        }
        out
    }

    /// `/provider` with no arguments.
    pub fn provider_list_text(&self) -> String {
        let mut out = String::from("Connections Fuigo can use (Flux Router first):\n\n");
        for c in self.connections() {
            let slug = match c.id {
                ConnectionId::Flux => "fluxrouter".to_string(),
                ConnectionId::Subscription(p) => p.provider_slug().to_string(),
                ConnectionId::Key(id) => id.to_string(),
            };
            let badge = c.badge.map(|b| format!(" [{b}]")).unwrap_or_default();
            out.push_str(&format!("  {:<22} {}{}\n      {}\n", slug, c.name, badge, c.state));
        }
        out
    }
}

/// Route kinds in the fixed ranking order (lower sorts first): Flux Router, then a signed-in
/// subscription, then a direct provider key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RouteKind {
    Flux,
    Subscription,
    Key,
}

/// How Fuigo reaches one model: what ranks it, and the words every surface shows for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub kind: RouteKind,
    /// "Flux Router", "Grok subscription", "OpenAI key from OPENAI_API_KEY".
    pub label: String,
}

impl Route {
    /// "via Flux Router", "included in your ChatGPT subscription", "your OpenAI key".
    pub fn badge(&self) -> String {
        match self.kind {
            RouteKind::Flux => "via Flux Router".to_string(),
            RouteKind::Subscription => format!("included in your {}", self.label),
            RouteKind::Key => {
                let name = self.label.split(" key").next().unwrap_or(&self.label);
                format!("your {name} key")
            }
        }
    }
}

/// The route a model entry uses, from its own credential fields.
pub fn route_of(
    subscription: Option<SubscriptionProvider>,
    env_key: Option<&str>,
    has_api_key: bool,
) -> Route {
    if let Some(p) = subscription {
        return Route {
            kind: RouteKind::Subscription,
            label: p.label().to_string(),
        };
    }
    if let Some(var) = env_key {
        if let Some(p) = key_discovery::PROVIDERS.iter().find(|p| p.env_vars.contains(&var)) {
            if p.applies_to_configured_endpoint {
                return Route {
                    kind: RouteKind::Flux,
                    label: "Flux Router".to_string(),
                };
            }
            return Route {
                kind: RouteKind::Key,
                label: format!("{} key from {var}", p.label),
            };
        }
        return Route {
            kind: RouteKind::Key,
            label: format!("key from {var}"),
        };
    }
    if has_api_key {
        return Route {
            kind: RouteKind::Key,
            label: "key in config.toml".to_string(),
        };
    }
    Route {
        kind: RouteKind::Flux,
        label: "Flux Router".to_string(),
    }
}

impl crate::agent::config::ModelEntry {
    /// The route this entry will use.
    pub fn route(&self) -> Route {
        route_of(
            self.auth_provider
                .as_ref()
                .and_then(|p| p.subscription_provider()),
            self.env_key.as_ref().and_then(|e| e.primary()),
            self.api_key.is_some(),
        )
    }
}

fn env_var_hint(p: &Provider) -> String {
    p.env_vars.first().copied().unwrap_or("the provider key").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::subscription::catalog::test_sign_in;

    const FLUX_KEY: &str = "sk-flux-abcdefgh-1234";
    const OPENAI_KEY: &str = "sk-openai-zyxwvuts-9876";

    fn none(_: &str) -> Option<String> {
        None
    }
    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_string())
        }
    }
    fn choices(status: &ProviderStatus, modal: bool) -> Vec<PickerChoice> {
        status.picker_rows(modal).iter().map(|r| r.choice).collect()
    }

    #[test]
    fn nothing_configured_flux_is_row_one_and_recommended() {
        let dir = tempfile::tempdir().unwrap();
        let status = ProviderStatus::collect(dir.path(), none, false);
        let rows = status.picker_rows(false);
        assert_eq!(rows[0].choice, PickerChoice::Flux);
        assert!(rows[0].label.contains("one key, every model"));
        assert!(rows[0].label.contains("(recommended)"));
        assert_eq!(
            choices(&status, false),
            vec![
                PickerChoice::Flux,
                PickerChoice::Chatgpt,
                PickerChoice::Xai,
                PickerChoice::ProviderKey,
                PickerChoice::Exit
            ]
        );
        assert_eq!(rows.last().unwrap().label, "Quit");
        // Connections view pins Flux first with the badge, even when not set.
        let c = status.connections();
        assert_eq!(c[0].id, ConnectionId::Flux);
        assert_eq!(c[0].badge, Some("Recommended"));
        assert!(!c[0].ready);
        assert!(c[0].state.contains("Not set") && c[0].state.contains(FLUX_SIGNUP));
    }

    #[test]
    fn env_flux_key_row_reads_use_from_your_environment_masked() {
        let dir = tempfile::tempdir().unwrap();
        let status =
            ProviderStatus::collect(dir.path(), env(&[("FLUX_API_KEY", FLUX_KEY)]), false);
        let rows = status.picker_rows(false);
        assert_eq!(
            rows[0].label,
            "Use FLUX_API_KEY from your environment \u{2022}\u{2022}\u{2022}\u{2022}1234"
        );
        assert_eq!(status.flux_env_var(), Some("FLUX_API_KEY"));
        let everything = format!(
            "{}{}{}",
            status.picker_text(),
            status.status_text(),
            status.provider_list_text()
        );
        assert!(!everything.contains(FLUX_KEY), "full key leaked");
        assert!(!everything.contains("abcdefgh"), "key body leaked");
    }

    #[test]
    fn sso_row_only_when_configured_and_exit_label_follows_the_modal() {
        let dir = tempfile::tempdir().unwrap();
        let plain = ProviderStatus::collect(dir.path(), none, false);
        assert!(!choices(&plain, false).contains(&PickerChoice::Sso));
        assert!(!choices(&plain, true).contains(&PickerChoice::Sso));
        let sso = ProviderStatus::collect(dir.path(), none, true);
        let rows = sso.picker_rows(true);
        assert!(rows.iter().any(|r| r.choice == PickerChoice::Sso));
        assert_eq!(rows.last().unwrap().label, "Cancel");
        // "Enterprise" is only ever the SSO row.
        for r in plain.picker_rows(false) {
            assert!(!r.label.to_lowercase().contains("enterprise"), "{}", r.label);
        }
        assert!(!plain.picker_text().to_lowercase().contains("enterprise"));
        assert!(!plain.status_text().to_lowercase().contains("enterprise"));
        assert!(sso.picker_text().contains("fuigo login --provider sso"));
    }

    #[tokio::test]
    async fn the_modal_offers_to_sign_out_of_each_signed_in_subscription_and_first_run_does_not() {
        let dir = tempfile::tempdir().unwrap();
        test_sign_in(dir.path(), SubscriptionProvider::Xai, "grok-acct", &["grok-4.7"]).await;
        let status = ProviderStatus::collect(dir.path(), none, false);
        let modal = status.picker_rows(true);
        let labels: Vec<&str> = modal.iter().map(|r| r.label.as_str()).collect();
        assert!(labels.contains(&"Sign out of Grok subscription"), "{labels:?}");
        assert!(!labels.contains(&"Sign out of ChatGPT subscription"), "{labels:?}");
        assert_eq!(modal.last().unwrap().choice, PickerChoice::Exit, "Cancel stays last");
        assert!(
            !status.picker_rows(false).iter().any(|r| matches!(r.choice, PickerChoice::SignOut(_))),
            "first run has nothing to sign out of"
        );
        assert!(!status.picker_text().contains("Sign out"));
    }

    #[tokio::test]
    async fn signed_in_state_never_shows_the_opaque_account_id_anywhere() {
        let dir = tempfile::tempdir().unwrap();
        test_sign_in(dir.path(), SubscriptionProvider::Xai, "grok-acct-7", &["grok-4.7"]).await;
        let status = ProviderStatus::collect(dir.path(), none, false);
        let rows = status.picker_rows(true);
        assert!(rows[2].label.ends_with("signed in"), "{}", rows[2].label);
        assert!(!rows[2].label.contains("grok-acct-7"), "{}", rows[2].label);
        assert!(!rows[1].label.contains("signed in"));
        for text in [status.status_text(), status.provider_list_text()] {
            assert!(text.contains("signed in"), "{text}");
            assert!(!text.contains("grok-acct-7") && !text.contains("signed in as"), "{text}");
            assert!(text.contains("not signed in: /login"), "ChatGPT row must say how to fix");
        }
        assert!(status.provider_list_text().contains("grok-subscription"));
        assert!(status.provider_list_text().contains("chatgpt-subscription"));
    }

    #[test]
    fn env_key_providers_say_whether_they_can_be_used_now() {
        let dir = tempfile::tempdir().unwrap();
        let status =
            ProviderStatus::collect(dir.path(), env(&[("OPENAI_API_KEY", OPENAI_KEY)]), false);
        let text = status.provider_list_text();
        assert!(text.contains("ready: OPENAI_API_KEY \u{2022}\u{2022}\u{2022}\u{2022}9876"), "{text}");
        assert!(text.contains("not set: export ANTHROPIC_API_KEY"), "{text}");
        assert!(!text.contains(OPENAI_KEY));
    }

    #[tokio::test]
    async fn implicit_default_is_the_best_subscription_model_when_flux_is_not_set_up() {
        let dir = tempfile::tempdir().unwrap();
        test_sign_in(dir.path(), SubscriptionProvider::Xai, "a", &["grok-4.7", "grok-3"]).await;
        let only = ProviderStatus::collect(dir.path(), none, false);
        assert_eq!(only.implicit_default_key().as_deref(), Some("xai/grok-4.7"));
        // Flux outranks a subscription: the built-in (Flux) default stands.
        let with_flux =
            ProviderStatus::collect(dir.path(), env(&[("FLUX_API_KEY", FLUX_KEY)]), false);
        assert_eq!(with_flux.implicit_default_key(), None);
        // Two subscriptions tie: catalogue order (ChatGPT, then Grok) decides.
        test_sign_in(dir.path(), SubscriptionProvider::Chatgpt, "b", &["gpt-5"]).await;
        let two = ProviderStatus::collect(dir.path(), none, false);
        assert_eq!(two.implicit_default_key().as_deref(), Some("chatgpt/gpt-5"));
        // Nothing signed in.
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(ProviderStatus::collect(empty.path(), none, false).implicit_default_key(), None);
    }

    /// With nothing but a provider key whose models are listed, the first of those models is the
    /// start, after any subscription; a key with no list yet offers none.
    #[test]
    fn a_listed_provider_key_gives_the_implicit_default_after_subscriptions() {
        let dir = tempfile::tempdir().unwrap();
        let key = [("OPENAI_API_KEY", "sk-test-openai-key-0123456789")];
        let unlisted = ProviderStatus::collect(dir.path(), env(&key), false);
        assert_eq!(unlisted.implicit_default_key(), None, "no list fetched yet");
        crate::auth::key_models::write_cached_model_ids(dir.path(), "openai", &["gpt-5".into(), "gpt-4o".into()]).unwrap();
        let listed = ProviderStatus::collect(dir.path(), env(&key), false);
        assert_eq!(listed.implicit_default_key().as_deref(), Some("openai-key/gpt-5"));
        let state = listed
            .connections()
            .into_iter()
            .find(|c| c.name == "OpenAI API key")
            .map(|c| c.state)
            .expect("the OpenAI row");
        assert!(state.starts_with("ready: OPENAI_API_KEY") && state.ends_with("2 models listed"), "{state}");
        // A Flux key keeps the built-in default.
        let both = ProviderStatus::collect(
            dir.path(),
            env(&[("OPENAI_API_KEY", "sk-test-openai-key-0123456789"), ("FLUX_API_KEY", FLUX_KEY)]),
            false,
        );
        assert_eq!(both.implicit_default_key(), None);
    }

    #[tokio::test]
    async fn login_summary_shows_a_display_identity_or_none_and_never_the_account_id() {
        let dir = tempfile::tempdir().unwrap();
        test_sign_in(dir.path(), SubscriptionProvider::Xai, "acct-9", &["grok-4.7"]).await;
        let status = ProviderStatus::collect(dir.path(), none, false);
        let none_line = status.login_summary(SubscriptionProvider::Xai, None, true, None, "Run `fuigo`.");
        assert_eq!(
            none_line,
            "Signed in to Grok subscription. Default model: xai/grok-4.7. Run `fuigo`."
        );
        let named = status.login_summary(
            SubscriptionProvider::Xai,
            None,
            true,
            Some("sam@example.com"),
            "Run `fuigo`.",
        );
        assert_eq!(
            named,
            "Signed in to Grok subscription as sam@example.com. Default model: xai/grok-4.7. Run `fuigo`."
        );
        // The model list not fetched: same rule.
        let unfetched = ProviderStatus::collect(dir.path(), none, false);
        let line = unfetched.login_summary(SubscriptionProvider::Chatgpt, None, false, None, "Run `fuigo`.");
        assert!(line.starts_with("Signed in to ChatGPT subscription. Its model list"), "{line}");
        for line in [none_line, named, line] {
            assert!(!line.contains("acct-9") && !line.contains("your account"), "{line}");
        }
    }

    #[tokio::test]
    async fn login_summary_words_a_kept_default_differently_from_a_set_one() {
        let dir = tempfile::tempdir().unwrap();
        test_sign_in(dir.path(), SubscriptionProvider::Xai, "acct-9", &["grok-4.7"]).await;
        let status = ProviderStatus::collect(dir.path(), none, false);
        // A default from another provider stays, and the line says so.
        let kept = status.login_summary(
            SubscriptionProvider::Xai,
            Some("chatgpt/gpt-6.1-sol"),
            true,
            None,
            "Run `fuigo`.",
        );
        assert_eq!(
            kept,
            "Signed in to Grok subscription. Your default model stays chatgpt/gpt-6.1-sol; \
             use /model to pick a Grok subscription model. Run `fuigo`."
        );
        assert!(!kept.contains("Default model:"), "{kept}");
        // A default already on this provider is simply the default.
        let own = status.login_summary(SubscriptionProvider::Xai, Some("xai/grok-4.7"), true, None, "Run `fuigo`.");
        assert!(own.contains("Default model: xai/grok-4.7."), "{own}");
        // No explicit default: the sign-in set it.
        let set = status.login_summary(SubscriptionProvider::Xai, None, true, None, "Run `fuigo`.");
        assert!(set.contains("Default model: xai/grok-4.7."), "{set}");
        assert!(!set.contains("stays") && !kept.contains("models --provider") && !kept.contains("config.toml"));
    }

    #[test]
    fn picker_text_lists_every_option_with_its_command_and_no_oidc_error() {
        let dir = tempfile::tempdir().unwrap();
        let text = ProviderStatus::collect(dir.path(), none, false).picker_text();
        assert!(text.starts_with("Choose how Fuigo reaches a model."), "{text}");
        for cmd in [
            "fuigo login --provider flux",
            "fuigo login --provider chatgpt",
            "fuigo login --provider xai",
        ] {
            assert!(text.contains(cmd), "{text}");
        }
        assert!(!text.contains("OAuth2 issuer"));
        // The upstream product name, built from parts so this guard adds no line naming it to the tree.
        assert!(!text.contains(concat!("Grok", " Build")) && !text.contains("grok.com"));
    }
}
