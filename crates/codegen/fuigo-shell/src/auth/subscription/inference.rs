// CLI printer: stdout goes through `fuigo_tty_utils::cli_println!` (a raw `println!` aborts the
// process when stdout's reader is gone, R060).
#![deny(clippy::print_stdout)]
use super::*;
use fuigo_sampler::subscription::{SubscriptionBearer, SubscriptionKind, SubscriptionResolver};

impl SubscriptionProvider {
    pub(crate) fn sampling_kind(self) -> SubscriptionKind {
        match self {
            Self::Chatgpt => SubscriptionKind::Chatgpt,
            Self::Xai => SubscriptionKind::Xai,
        }
    }
}
/// Prefix of the auth-provider name [`bind_endpoint_subscription`] gives a model. The
/// space keeps it apart from any `[auth_provider.<name>]` TOML table name a user can write
/// bare; a quoted table of the same name wins (it is then the user's own provider).
const ENDPOINT_BINDING_SUFFIX: &str = " subscription (model endpoint)";

fn endpoint_binding_name(provider: SubscriptionProvider) -> String {
    format!("{}{ENDPOINT_BINDING_SUFFIX}", provider.name())
}

/// Whether `name` is a binding [`bind_endpoint_subscription`] made, rather than a
/// configured `[auth_provider.<name>]` table.
pub(crate) fn is_endpoint_binding_name(name: &str) -> bool {
    [SubscriptionProvider::Chatgpt, SubscriptionProvider::Xai]
        .into_iter()
        .any(|provider| name == endpoint_binding_name(provider))
}

/// P192: a model whose endpoint IS a subscription's own inference endpoint
/// ([`SubscriptionKind::for_endpoint`]) and that carries no credential and no auth
/// provider of its own belongs to that subscription. Bind it, so its requests take the
/// exempt, exact-URL, no-redirect subscription transport. Without this the entry fell
/// through to the ordinary transport: no credential could be attached to a vendor host,
/// and the egress guard refused the request ("fuigo refuses to contact upstream vendor
/// host") on every turn.
///
/// `resolve_model_list` applies this to models from the user's own config only; a remote
/// catalog entry never binds a subscription credential.
/// A model with its own `api_key`/`env_key` (bring-your-own-key, including `/provider
/// xai`), its own auth provider, headers or query parameters, or a different
/// `api_base_url`, is left exactly as configured. No credential store is
/// read here: if the user never signed in, the turn says to run `fuigo login`.
pub(crate) fn bind_endpoint_subscription(entry: &mut crate::agent::config::ModelEntry) {
    // Any credential-bearing or request-shaping input of the user's own is a different
    // transport the user chose (BYOK, a header token, a proxy query): never replaced.
    if entry.auth_provider.is_some()
        || entry.api_key.is_some()
        || entry.env_key.is_some()
        || !entry.info.extra_headers.is_empty()
        || !entry.info.env_http_headers.is_empty()
        || !entry.info.query_params.is_empty()
    {
        return;
    }
    let Some(kind) = SubscriptionKind::for_endpoint(&entry.info.base_url) else {
        return;
    };
    if entry
        .api_base_url
        .as_deref()
        .is_some_and(|url| SubscriptionKind::for_endpoint(url) != Some(kind))
    {
        return;
    }
    let provider = match kind {
        SubscriptionKind::Chatgpt => SubscriptionProvider::Chatgpt,
        SubscriptionKind::Xai => SubscriptionProvider::Xai,
    };
    let mut binding = crate::auth::AuthProviderRef::unresolved(endpoint_binding_name(provider));
    binding.attach_trusted_config(Some(&crate::auth::AuthProviderConfig {
        subscription: Some(provider),
        ..Default::default()
    }));
    entry.auth_provider = Some(binding);
}

#[derive(Debug)]
struct Resolver {
    provider: SubscriptionProvider,
    account: Option<String>,
    valid: bool,
}
impl SubscriptionResolver for Resolver {
    fn resolve(
        &self,
    ) -> futures_util::future::BoxFuture<'_, fuigo_sampling_types::Result<SubscriptionBearer>> {
        Box::pin(async move {
            if !self.valid {
                return Err(fuigo_sampling_types::SamplingError::InvalidConfiguration(
                    "subscription auth conflicts with API-key or command configuration",
                ));
            }
            let access = default_store()
                .map_err(|_| auth_error())?
                .access(self.provider, self.account.as_deref())
                .await
                .map_err(sampling_error)?;
            Ok(SubscriptionBearer::new(
                access.bearer().map_err(|_| auth_error())?.to_owned(),
                access.account,
                access.expires_at,
            ))
        })
    }
}
pub(super) fn sampling_error(error: SubscriptionError) -> fuigo_sampling_types::SamplingError {
    match error {
        // A local TLS fault is not a credential problem; "run fuigo login" would send the
        // user the wrong way. The file path is logged by `flow`.
        SubscriptionError::LocalTls(_) => local_tls_error(),
        _ => auth_error(),
    }
}
fn local_tls_error() -> fuigo_sampling_types::SamplingError {
    fuigo_sampling_types::SamplingError::InvalidConfiguration(
        "subscription local TLS/CA configuration error (the HTTPS client could not be built, or the provider certificate did not verify against the configured CA bundle); check the file named by FUIGO_EXTRA_CA_BUNDLE or SSL_CERT_FILE (the log names it); not a credential or network problem",
    )
}
fn auth_error() -> fuigo_sampling_types::SamplingError {
    fuigo_sampling_types::SamplingError::InvalidConfiguration(
        "subscription credentials unavailable; run fuigo login --provider for the selected provider; no API-key fallback",
    )
}

pub(crate) fn configure(
    sampler: &mut fuigo_sampler::SamplerConfig,
    provider: &crate::auth::AuthProviderRef,
    conflicting_key: bool,
) {
    let Some(kind) = provider.subscription_provider() else {
        return;
    };
    sampler.subscription = Some(kind.sampling_kind());
    // P192: ChatGPT's subscription endpoint speaks only Responses (its transport accepts nothing
    // but `POST …/codex/responses`); any other protocol could only fail closed on every turn.
    if kind == SubscriptionProvider::Chatgpt {
        sampler.api_backend = fuigo_sampling_types::ApiBackend::Responses;
    }
    sampler.subscription_resolver = Some(std::sync::Arc::new(Resolver {
        provider: kind,
        account: provider.config.account.clone(),
        valid: provider.config.is_usable() && !conflicting_key,
    }));
    sampler.api_key = None;
    sampler.bearer_resolver = None;
    sampler.attribution_callback = None;
    sampler.header_injector = None;
    sampler.extra_headers.clear();
    sampler.env_http_headers.clear();
    sampler.supports_backend_search = false;
    sampler.doom_loop_recovery = None;
    sampler.compactions_remaining = None;
    sampler.compaction_at_tokens = None;
}

// Catalogs include per-model instructions/capabilities and are larger than token responses.
const MODEL_CATALOG_MAX_BYTES: usize = 2 * 1024 * 1024;

/// List only model IDs returned for the explicitly authenticated provider.
/// A denial is surfaced; no hard-coded entitlement or fallback catalog.
pub async fn cli_models(provider: SubscriptionProvider) -> Result<()> {
    use fuigo_extra_ca::subscription::Recipient;
    let access = default_store()?.access(provider, None).await?;
    if access.is_unpersisted() {
        fuigo_tty_utils::cli_eprintln!(
            "warning: {} credentials were refreshed but could not be saved, so they are lost when \
             this command exits and the next run will require `fuigo login`. Fix the disk under \
             the Fuigo home first.",
            provider.name()
        );
    }
    let recipient = match provider {
        SubscriptionProvider::Chatgpt => Recipient::ChatGptInference,
        SubscriptionProvider::Xai => Recipient::XaiInference,
    };
    let client = super::flow::subscription_client(recipient)?;
    let request = model_request(&client, provider, &access)?;
    let body = tokio::time::timeout(std::time::Duration::from_secs(25), async {
        let response = client.execute(request).await.map_err(|error| {
            super::flow::transport_error(&error, super::flow::configured_ca_bundle())
        })?;
        super::flow::read_json_response(response, MODEL_CATALOG_MAX_BYTES).await
    })
    .await
    .map_err(|_| SubscriptionError::Timeout)??;
    let models = parse_model_ids(provider, &body)?;
    for model in models {
        fuigo_tty_utils::cli_println!(
            "{}",
            serde_json::to_string(&model).map_err(|_| SubscriptionError::InvalidCredentials)?
        );
    }
    Ok(())
}
fn model_request(
    client: &fuigo_extra_ca::subscription::SubscriptionClient,
    provider: SubscriptionProvider,
    access: &SubscriptionAccess,
) -> Result<reqwest::Request> {
    let url = format!("{}/models", provider.sampling_kind().base_url());
    let mut request = client
        .request(reqwest::Method::GET, &url)
        .bearer_auth(access.bearer()?);
    if provider == SubscriptionProvider::Chatgpt {
        // This is Fuigo's real version, not an impersonated Codex client version.
        let version = fuigo_version::full_version()
            .split_whitespace()
            .next()
            .unwrap_or(fuigo_version::VERSION);
        request = request
            .query(&[("client_version", version)])
            .header("chatgpt-account-id", &access.account)
            .header("originator", "fuigo");
    }
    request
        .build()
        .map_err(|_| SubscriptionError::InvalidCredentials)
}
fn parse_model_ids(
    provider: SubscriptionProvider,
    body: &serde_json::Value,
) -> Result<Vec<String>> {
    let list = body
        .get(match provider {
            SubscriptionProvider::Chatgpt => "models",
            SubscriptionProvider::Xai => "data",
        })
        .and_then(|v| v.as_array())
        .ok_or(SubscriptionError::InvalidCredentials)?;
    list.iter()
        .map(|item| {
            item.get(match provider {
                SubscriptionProvider::Chatgpt => "slug",
                SubscriptionProvider::Xai => "id",
            })
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .ok_or(SubscriptionError::InvalidCredentials)
        })
        .collect()
}

/// Resolve native auth by both wire model and endpoint: the same model slug can
/// exist on Flux and a subscription backend without exchanging their credentials.
pub(crate) fn selected_for_endpoint(
    model: &str,
    endpoint: &str,
) -> Option<crate::auth::AuthProviderRef> {
    let raw = crate::config::load_effective_config().ok()?;
    let config = crate::agent::config::Config::new_from_toml_cfg(&raw).ok()?;
    let models = crate::agent::config::resolve_model_list(&config, None);
    from_models(&models, model, endpoint)
}
/// The auth provider an ACP turn uses, from the (wire model, endpoint) lookup
/// [`selected_for_endpoint`] and the wire-id-only lookup of the session's model facts.
///
/// The endpoint lookup is authoritative for subscriptions (P192): a subscription found only
/// by wire id belongs to ANOTHER entry with the same model id (for example a
/// bring-your-own-key twin on the same host), and attaching it would replace this model's
/// own credential with the subscription. A non-subscription provider is kept.
pub(crate) fn turn_provider(
    by_endpoint: Option<crate::auth::AuthProviderRef>,
    by_wire_id: Option<crate::auth::AuthProviderRef>,
) -> Option<crate::auth::AuthProviderRef> {
    if by_endpoint.is_some() {
        return by_endpoint;
    }
    by_wire_id.filter(|p| p.subscription_provider().is_none())
}
fn subscription_ref(
    entry: &crate::agent::config::ModelEntry,
) -> Option<&crate::auth::AuthProviderRef> {
    entry
        .auth_provider
        .as_ref()
        .filter(|p| p.subscription_provider().is_some())
}
pub(crate) fn from_models(
    models: &indexmap::IndexMap<String, crate::agent::config::ModelEntry>,
    model: &str,
    endpoint: &str,
) -> Option<crate::auth::AuthProviderRef> {
    let matches: Vec<_> = models
        .values()
        .filter(|entry| entry.info.model == model && entry.info.base_url == endpoint)
        .collect();
    let mut provider = matches.iter().find_map(|entry| subscription_ref(entry))?.clone();
    // Ambiguous only when the matching entries would send this request differently: an
    // unbound twin, or a different provider table (subscription, account or anything else).
    // Aliases bound by identical tables (P192 endpoint bindings among them) agree.
    let same_binding = |entry: &&crate::agent::config::ModelEntry| {
        subscription_ref(entry).is_some_and(|p| p.config == provider.config)
    };
    if !matches.iter().all(same_binding) {
        provider.config.command = "ambiguous subscription model/account mapping".into();
    }
    Some(provider)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subscription_child_inheritance_is_bound_to_model_and_recipient() {
        let parent = fuigo_sampler::SamplerConfig {
            model: "same".into(),
            base_url: "https://chatgpt.com/backend-api/codex".into(),
            subscription: Some(SubscriptionKind::Chatgpt),
            ..Default::default()
        };
        let mut child = parent.clone();
        child.subscription = None;
        child.api_key = Some("unrelated-key".into());
        inherit(&mut child, &parent);
        assert_eq!(child.subscription, parent.subscription);
        assert!(child.api_key.is_none());
        let mut other = fuigo_sampler::SamplerConfig {
            model: "same".into(),
            base_url: "https://api.fluxrouter.ai/v1".into(),
            ..Default::default()
        };
        inherit(&mut other, &parent);
        assert!(other.subscription.is_none());
    }
    #[tokio::test]
    async fn subscription_model_catalog_accepts_observed_size_but_remains_bounded() {
        use fuigo_extra_ca::dispatch::AsyncRequestBuilderExt;
        for (size, accepted) in [(421_000, true), (MODEL_CATALOG_MAX_BYTES, false)] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/models", listener.local_addr().unwrap());
            let app=axum::Router::new().route("/models",axum::routing::get(move ||async move {
                axum::Json(serde_json::json!({"models":[{"slug":"fixture-model","base_instructions":"x".repeat(size)}]}))
            }));
            let server = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let client = fuigo_extra_ca::build_reqwest_client(|b| b).unwrap();
            let response = client.get(&url).send_checked().await.unwrap();
            let parsed =
                super::super::flow::read_json_response(response, MODEL_CATALOG_MAX_BYTES).await;
            assert_eq!(parsed.is_ok(), accepted);
            if let Ok(body) = parsed {
                assert_eq!(
                    parse_model_ids(SubscriptionProvider::Chatgpt, &body).unwrap(),
                    vec!["fixture-model"]
                );
            }
            if accepted {
                let response = client.get(&url).send_checked().await.unwrap();
                assert!(
                    super::super::flow::read_response(response).await.is_err(),
                    "token-response cap must remain smaller"
                );
            }
            server.abort();
            let _ = server.await;
        }
    }
    #[test]
    fn subscription_model_request_has_required_query_and_provider_headers() {
        use fuigo_extra_ca::subscription::{Recipient, SubscriptionClient};
        for (provider, recipient) in [
            (SubscriptionProvider::Chatgpt, Recipient::ChatGptInference),
            (SubscriptionProvider::Xai, Recipient::XaiInference),
        ] {
            let access = SubscriptionAccess {
                provider,
                account: "fixture-account".into(),
                expires_at: u64::MAX,
                token: "fake-bearer".into(),
                unpersisted: false,
            };
            let request = model_request(
                &SubscriptionClient::new(recipient).unwrap(),
                provider,
                &access,
            )
            .unwrap();
            assert_eq!(request.headers()["authorization"], "Bearer fake-bearer");
            if provider == SubscriptionProvider::Chatgpt {
                let expected = fuigo_version::full_version()
                    .split_whitespace()
                    .next()
                    .unwrap();
                assert_eq!(
                    request.url().query_pairs().collect::<Vec<_>>(),
                    vec![("client_version".into(), expected.into())]
                );
                assert_eq!(request.headers()["originator"], "fuigo");
                assert_eq!(request.headers()["chatgpt-account-id"], "fixture-account");
            } else {
                assert!(request.url().query().is_none());
                assert!(!request.headers().contains_key("chatgpt-account-id"));
            }
        }
    }
    #[test]
    fn subscription_model_listing_uses_provider_response_only() {
        assert_eq!(
            parse_model_ids(
                SubscriptionProvider::Chatgpt,
                &serde_json::json!({"models":[{"slug":"allowed-model"}]})
            )
            .unwrap(),
            vec!["allowed-model"]
        );
        assert_eq!(
            parse_model_ids(
                SubscriptionProvider::Xai,
                &serde_json::json!({"data":[{"id":"allowed-grok"}]})
            )
            .unwrap(),
            vec!["allowed-grok"]
        );
        assert!(
            parse_model_ids(
                SubscriptionProvider::Xai,
                &serde_json::json!({"error":"no entitlement"})
            )
            .is_err()
        );
    }
}

/// Only an unchanged model/recipient inherits a parent's subscription capability.
pub(crate) fn inherit(
    child: &mut fuigo_sampler::SamplerConfig,
    parent: &fuigo_sampler::SamplerConfig,
) {
    if child.model == parent.model
        && child.base_url == parent.base_url
        && parent.subscription.is_some()
    {
        child.subscription = parent.subscription;
        child.subscription_resolver = parent.subscription_resolver.clone();
        child.api_key = None;
        child.bearer_resolver = None;
        child.attribution_callback = None;
    }
}
