//! Discover provider credentials already present in the environment.
//!
//! First run should not be a blank prompt when the machine already holds a
//! usable key. Fuigo previously looked only at `FUIGO_API_KEY`, so a developer
//! with `OPENAI_API_KEY` exported for the last two years was still asked to
//! paste something.
//!
//! This module only *reports* what it finds. It never writes config, never
//! sends a key anywhere, and never puts a secret in a log line: [`Discovered`]
//! deliberately has no `Debug` that could leak one, and [`Discovered::masked`]
//! is the only rendering intended for display.

/// A provider Fuigo knows how to reach with a bare API key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provider {
    /// Stable id, also the `[model_providers.<id>]` key we would write.
    pub id: &'static str,
    /// Name to show a human.
    pub label: &'static str,
    /// Environment variables to check, in order of preference.
    pub env_vars: &'static [&'static str],
    /// Expected key prefix, used to avoid offering an obviously wrong value.
    /// `None` means the provider has no stable prefix worth checking.
    pub key_prefix: Option<&'static str>,
    /// OpenAI-compatible base URL, for writing a `[model_providers]` entry.
    pub base_url: &'static str,
    /// Whether this key can be applied through the single-credential path
    /// (`setApiKey` -> `auth.json` + `FUIGO_API_KEY`).
    ///
    /// True ONLY for credentials meant for the configured endpoint. That path
    /// is provider-blind: `extensions/auth.rs:72` stores whatever it is handed
    /// and it is then sent as the bearer to `[endpoints].fuigo_api_base_url`.
    /// Applying a third-party key that way would ship, say, an OpenAI secret
    /// to FluxRouter. Third-party providers need a `[model_providers.<id>]`
    /// entry plus `model_provider` inside a `[model.<key>]` table, which is
    /// what arms the fail-closed guard.
    pub applies_to_configured_endpoint: bool,
    /// `[model_providers.<id>].api_backend` -- the wire protocol, in its TOML
    /// spelling (`chat_completions`, `responses`, `messages`).
    ///
    /// `base_url` alone does not say which protocol a host speaks. Anthropic's
    /// API is not Chat-Completions-shaped, so writing a provider entry with
    /// only a URL produces a config that cannot work.
    pub api_backend: &'static str,
    /// `[model_providers.<id>].auth_scheme` -- how the credential is presented,
    /// in its TOML spelling (`bearer`, `x_api_key`).
    ///
    /// Anthropic wants `x-api-key`, not `Authorization: Bearer`. Until this was
    /// modelled it was unreachable from any user config.
    pub auth_scheme: &'static str,
    /// Headers a request to this provider must carry beyond the credential.
    ///
    /// Anthropic requires `anthropic-version`; the OpenAI-compatible providers
    /// require none, and carry an empty slice rather than a guess.
    pub extra_headers: &'static [(&'static str, &'static str)],
}

/// Providers checked at first run, most preferred first.
///
/// FluxRouter leads because one key reaches every vendor behind it, which is
/// the configuration Fuigo is built around. The rest are direct BYOK.
pub const PROVIDERS: &[Provider] = &[
    Provider {
        id: "fluxrouter",
        label: "FluxRouter",
        env_vars: &["FUIGO_API_KEY", "FUIGO_CODE_API_KEY", "FLUX_API_KEY"],
        key_prefix: Some("sk-"),
        base_url: "https://api.fluxrouter.ai/v1",
        applies_to_configured_endpoint: true,
        api_backend: "chat_completions",
        auth_scheme: "bearer",
        extra_headers: &[],
    },
    Provider {
        id: "anthropic",
        label: "Anthropic",
        env_vars: &["ANTHROPIC_API_KEY"],
        key_prefix: Some("sk-ant-"),
        base_url: "https://api.anthropic.com/v1",
        applies_to_configured_endpoint: false,
        api_backend: "messages",
        auth_scheme: "x_api_key",
        extra_headers: &[("anthropic-version", "2023-06-01")],
    },
    Provider {
        id: "openai",
        label: "OpenAI",
        env_vars: &["OPENAI_API_KEY"],
        key_prefix: Some("sk-"),
        base_url: "https://api.openai.com/v1",
        applies_to_configured_endpoint: false,
        api_backend: "chat_completions",
        auth_scheme: "bearer",
        extra_headers: &[],
    },
    Provider {
        id: "google",
        label: "Google Gemini",
        env_vars: &["GEMINI_API_KEY", "GOOGLE_API_KEY"],
        key_prefix: Some("AIza"),
        base_url: "https://generativelanguage.googleapis.com/v1beta/openai",
        applies_to_configured_endpoint: false,
        api_backend: "chat_completions",
        auth_scheme: "bearer",
        extra_headers: &[],
    },
    Provider {
        id: "xai",
        label: "xAI (Grok)",
        env_vars: &["XAI_API_KEY", "GROK_API_KEY"],
        key_prefix: Some("xai-"),
        // Reachable only when the egress guard is lifted
        // (`FUIGO_ALLOW_UPSTREAM_HOSTS=1`): `fuigo-extra-ca/src/egress.rs`
        // refuses to resolve `x.ai`. Listed so the provider is documented and
        // configurable, never offered as a one-keypress row.
        base_url: "https://api.x.ai/v1",
        applies_to_configured_endpoint: false,
        api_backend: "chat_completions",
        auth_scheme: "bearer",
        extra_headers: &[],
    },
    Provider {
        id: "groq",
        label: "Groq",
        env_vars: &["GROQ_API_KEY"],
        key_prefix: Some("gsk_"),
        base_url: "https://api.groq.com/openai/v1",
        applies_to_configured_endpoint: false,
        api_backend: "chat_completions",
        auth_scheme: "bearer",
        extra_headers: &[],
    },
    Provider {
        id: "openrouter",
        label: "OpenRouter",
        env_vars: &["OPENROUTER_API_KEY"],
        key_prefix: Some("sk-or-"),
        base_url: "https://openrouter.ai/api/v1",
        applies_to_configured_endpoint: false,
        api_backend: "chat_completions",
        auth_scheme: "bearer",
        extra_headers: &[],
    },
    Provider {
        id: "deepseek",
        label: "DeepSeek",
        env_vars: &["DEEPSEEK_API_KEY"],
        key_prefix: None,
        base_url: "https://api.deepseek.com/v1",
        applies_to_configured_endpoint: false,
        api_backend: "chat_completions",
        auth_scheme: "bearer",
        extra_headers: &[],
    },
    Provider {
        id: "mistral",
        label: "Mistral",
        env_vars: &["MISTRAL_API_KEY"],
        key_prefix: None,
        base_url: "https://api.mistral.ai/v1",
        applies_to_configured_endpoint: false,
        api_backend: "chat_completions",
        auth_scheme: "bearer",
        extra_headers: &[],
    },
];

/// A credential found in the environment.
///
/// No `Debug`, on purpose: deriving it would let a stray `{:?}` write an API
/// key into a log or a crash report. Use [`Self::masked`].
#[derive(Clone)]
pub struct Discovered {
    pub provider: &'static Provider,
    /// The variable it came from, which is safe to display.
    pub env_var: &'static str,
    key: String,
}

impl Discovered {
    /// The secret. Only for handing to the credential store.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Display form: enough to recognise which key this is, not enough to use.
    ///
    /// Shows at most the first 6 and last 4 characters. Short keys are masked
    /// entirely rather than partially revealed, since a 12-character secret
    /// with 10 characters shown is not redacted in any useful sense.
    pub fn masked(&self) -> String {
        let k = self.key.as_str();
        let n = k.chars().count();
        if n <= 12 {
            return "*".repeat(n.max(8));
        }
        let head: String = k.chars().take(6).collect();
        let tail: String = k.chars().skip(n - 4).collect();
        format!("{head}...{tail}")
    }
}

/// Whether a value looks like a real key for `provider`.
///
/// Rejects the empty string, obvious placeholders, and values whose prefix
/// disagrees with the provider. Offering a bad key is worse than offering
/// nothing: the user accepts it, the first request 401s, and the error points
/// at Fuigo rather than at their shell profile.
fn looks_usable(provider: &Provider, value: &str) -> bool {
    let v = value.trim();
    if v.len() < 12 {
        return false;
    }
    let lower = v.to_ascii_lowercase();
    if ["changeme", "your-api-key", "todo", "xxx", "none", "null"]
        .iter()
        .any(|p| lower.contains(p))
    {
        return false;
    }
    match provider.key_prefix {
        Some(prefix) => v.starts_with(prefix),
        None => true,
    }
}

/// Read the environment and report every provider credential found.
///
/// Order follows [`PROVIDERS`], so the caller can offer the first as default.
/// One entry per provider: the first matching variable wins.
pub fn discover() -> Vec<Discovered> {
    discover_with(|name| std::env::var(name).ok())
}

/// [`discover`] against an arbitrary lookup, so tests need not mutate the real
/// process environment (which is racy across parallel tests).
pub fn discover_with<F>(lookup: F) -> Vec<Discovered>
where
    F: Fn(&str) -> Option<String>,
{
    let mut found = Vec::new();
    for provider in PROVIDERS {
        for env_var in provider.env_vars {
            let Some(value) = lookup(env_var) else {
                continue;
            };
            if !looks_usable(provider, &value) {
                continue;
            }
            found.push(Discovered {
                provider,
                env_var,
                key: value.trim().to_owned(),
            });
            break;
        }
    }
    found
}

/// Keys that can be applied through the single-credential path right now.
///
/// In practice this yields at most **one** row, and only ever `FLUX_API_KEY`.
/// `FUIGO_API_KEY` and `FUIGO_CODE_API_KEY` are listed first for the
/// FluxRouter provider, but when either is set the shell adopts it
/// automatically (`auth/flow.rs:932,981`), `AuthState` becomes `Done`, and the
/// first-run menu that consumes this never draws. They can therefore appear in
/// `discover()` -- which is a truthful report of the environment -- but never
/// as a row a user is asked to choose.
///
/// This is the ONLY list a first-run menu may offer as one-keypress rows.
/// Everything else needs provider configuration first; offering it would
/// send that vendor's secret to the configured endpoint.
pub fn discover_appliable() -> Vec<Discovered> {
    discover()
        .into_iter()
        .filter(|d| d.provider.applies_to_configured_endpoint)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    #[test]
    fn finds_nothing_in_an_empty_environment() {
        assert!(discover_with(env(&[])).is_empty());
    }

    #[test]
    fn finds_each_provider_by_its_own_variable() {
        let found = discover_with(env(&[
            ("ANTHROPIC_API_KEY", "sk-ant-api03-aaaaaaaaaaaaaaaaaaaa"),
            ("OPENAI_API_KEY", "sk-proj-bbbbbbbbbbbbbbbbbbbb"),
            ("GEMINI_API_KEY", "AIzaSyCcccccccccccccccccc"),
        ]));
        let ids: Vec<_> = found.iter().map(|d| d.provider.id).collect();
        assert_eq!(ids, vec!["anthropic", "openai", "google"]);
    }

    #[test]
    fn fluxrouter_is_offered_first() {
        let found = discover_with(env(&[
            ("OPENAI_API_KEY", "sk-proj-bbbbbbbbbbbbbbbbbbbb"),
            ("FLUX_API_KEY", "sk-flux-aaaaaaaaaaaaaaaaaaaa"),
        ]));
        assert_eq!(found[0].provider.id, "fluxrouter");
    }

    #[test]
    fn first_matching_variable_wins_per_provider() {
        let found = discover_with(env(&[
            ("GEMINI_API_KEY", "AIzaSyCaaaaaaaaaaaaaaaaaaa"),
            ("GOOGLE_API_KEY", "AIzaSyCbbbbbbbbbbbbbbbbbbb"),
        ]));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].env_var, "GEMINI_API_KEY");
    }

    /// A wrong-provider key is worse than none: the user accepts it, the first
    /// request 401s, and the error looks like Fuigo's fault.
    #[test]
    fn rejects_a_key_whose_prefix_belongs_to_another_provider() {
        let found = discover_with(env(&[("ANTHROPIC_API_KEY", "AIzaSyCwrongwrongwrongwrong")]));
        assert!(found.is_empty());
    }

    #[test]
    fn rejects_placeholders_and_stubs() {
        for junk in [
            "",
            "   ",
            "sk-",
            "sk-changeme-please",
            "sk-your-api-key-here",
            "sk-TODO000000000",
        ] {
            assert!(
                discover_with(env(&[("OPENAI_API_KEY", junk)])).is_empty(),
                "accepted junk: {junk:?}"
            );
        }
    }

    /// The security boundary of this module: a third-party key must never be
    /// offered as a one-keypress row, because the path that applies it is
    /// provider-blind and would send that secret to the configured endpoint.
    #[test]
    fn only_configured_endpoint_keys_are_appliable() {
        let appliable: Vec<_> = PROVIDERS
            .iter()
            .filter(|p| p.applies_to_configured_endpoint)
            .map(|p| p.id)
            .collect();
        assert_eq!(
            appliable,
            vec!["fluxrouter"],
            "a provider became one-keypress appliable; that sends its key to \
             [endpoints].fuigo_api_base_url. Confirm that is intended."
        );
    }

    /// The egress guard refuses to resolve `x.ai`, so an xAI row would be a
    /// dead end even before the credential question.
    #[test]
    fn xai_is_never_appliable_because_egress_blocks_it() {
        let xai = PROVIDERS.iter().find(|p| p.id == "xai").expect("listed");
        assert!(!xai.applies_to_configured_endpoint);
        assert!(xai.base_url.contains("x.ai"));
    }

    #[test]
    fn masking_reveals_enough_to_identify_and_not_enough_to_use() {
        let found = discover_with(env(&[(
            "OPENAI_API_KEY",
            "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123",
        )]));
        let masked = found[0].masked();
        assert_eq!(masked, "sk-pro...0123");
        assert!(!masked.contains("MNOPQRSTUVWXYZ"), "leaked the middle");
    }

    /// A short secret with most of it shown is not redacted at all.
    #[test]
    fn short_keys_are_masked_entirely() {
        let found = discover_with(env(&[("DEEPSEEK_API_KEY", "abcdefghijkl")]));
        let masked = found[0].masked();
        assert!(masked.chars().all(|c| c == '*'), "got {masked}");
    }

    #[test]
    fn whitespace_is_trimmed_from_the_stored_key() {
        let found = discover_with(env(&[(
            "OPENAI_API_KEY",
            "  sk-proj-AAAAAAAAAAAAAAAAAAAA\n",
        )]));
        assert_eq!(found[0].key(), "sk-proj-AAAAAAAAAAAAAAAAAAAA");
    }
}

/// Manual check against the real process environment.
/// `cargo test -p fuigo-shell --lib key_discovery::real -- --ignored --nocapture`
#[cfg(test)]
mod real {
    #[test]
    #[ignore = "reads the developer's real environment"]
    fn report_what_is_actually_present() {
        for d in super::discover() {
            println!(
                "  {:<14} {:<20} {}",
                d.provider.label,
                d.env_var,
                d.masked()
            );
        }
    }
}
