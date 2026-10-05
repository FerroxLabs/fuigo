//! [`SamplerConfig`] is the per-request configuration handed to the sampler.
//! It deliberately does **not** alias `fuigo_sampling_types::SamplingConfig`.
//! Aliasing would pull transitive dependencies on shell-specific types (`fuigo-tools`, etc.) into the sampler crate.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use fuigo_sampling_types::{
    ApiBackend, CompactionAtTokens, CompactionsRemaining, DoomLoopRecoveryPolicy, ReasoningEffort,
    ReasoningSummary,
};

use crate::attribution::SharedAttributionCallback;
use crate::retry::{DEFAULT_MAX_RETRIES, RATE_LIMIT_RETRY_THRESHOLD};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthScheme {
    #[default]
    Bearer,
    XApiKey,
}

/// All knobs that control a single sampling request.
///
/// The session typically owns one `SamplerConfig` per active model and passes it (or a per-request override) to the actor on every submit.
///
/// # Construction in `fuigo-shell`
///
/// `SamplerConfig` is the single source of truth for sampler configuration.
/// The shell builds it directly by composing chat-state's `fuigo_sampling_types::SamplingConfig` with `Credentials` (api key, client version).
/// See `agent::config::resolve_model_to_sampling_config` and `session::acp_session::SessionActor::reconstruct_full_config`.
///
/// URL-derived request headers (e.g. `X-XAI-Token-Auth` for the cli-chat-proxy) land in [`Self::extra_headers`].
/// `agent::config::inject_url_derived_headers` folds them in before the `SamplerConfig` is handed to the actor.
/// Auth is selected separately via `auth_scheme`, while `api_backend` controls only the request/response protocol shape.
#[derive(Clone, Serialize, Deserialize)]
pub struct SamplerConfig {
    /// Persisted discriminator keeps a deserialized subscription config fail-closed.
    #[serde(default)]
    pub subscription: Option<crate::subscription::SubscriptionKind>,
    #[serde(skip)]
    pub subscription_resolver: Option<crate::subscription::SharedSubscriptionResolver>,
    pub api_key: Option<String>,
    pub base_url: String,
    /// Resolved local directory for this model's mTLS client identity.
    #[serde(default)]
    pub mtls_cert_dir: Option<PathBuf>,
    pub model: String,
    pub max_completion_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub api_backend: ApiBackend,
    #[serde(default)]
    pub auth_scheme: AuthScheme,
    /// Extra request headers applied verbatim. The sampler never inspects the URL to derive headers.
    /// Callers (the session) inject proxy auth and other access headers here before constructing the config.
    pub extra_headers: IndexMap<String, String>,
    /// Additional Responses API `include` values not represented by the typed client.
    #[serde(default)]
    pub extra_response_includes: Vec<String>,
    /// Query parameters folded into every request URL (percent-encoded).
    #[serde(default)]
    pub query_params: IndexMap<String, String>,
    /// Header name to environment variable, resolved into request headers at client build and never persisted.
    #[serde(default)]
    pub env_http_headers: IndexMap<String, String>,
    /// Total context window size in tokens.
    /// The sampler does not enforce it; the session uses it for compaction decisions.
    pub context_window: u64,
    pub force_http1: bool,
    pub max_retries: Option<u32>,
    /// Total-attempt ceiling for rate-limited requests.
    /// `None` keeps the actor's [`RetryPolicy::rate_limit_retry_threshold`].
    #[serde(default)]
    pub rate_limit_retry_threshold: Option<u32>,
    pub stream_tool_calls: bool,
    pub idle_timeout_secs: Option<u64>,

    // Reasoning effort
    pub reasoning_effort: Option<ReasoningEffort>,
    /// Overrides the Responses API `reasoning.summary` the request builder sets; `None` leaves it as built.
    #[serde(default)]
    pub reasoning_summary: Option<ReasoningSummary>,

    // Client identity
    pub origin_client: Option<OriginClientInfo>,
    pub client_identifier: Option<String>,
    pub deployment_id: Option<String>,
    pub user_id: Option<String>,
    pub client_version: Option<String>,

    /// Hook invoked on every 401 response with the bearer that was actually sent on the wire.
    /// Implementations typically compare it against a live credential source to tell a stale token from a server-rejected live one.
    /// `None` (default) is a no-op; the 401 arm still returns `SamplingError::Auth`.
    ///
    /// serde skips this field; round-tripping a config drops the callback.
    /// Re-attach it before [`crate::SamplingClient::new`] when deserializing from disk, or 401 attribution is silently disabled.
    #[serde(skip)]
    pub attribution_callback: Option<SharedAttributionCallback>,

    /// Resolves a fresh bearer for each request. `None` uses the construction-time `api_key`.
    #[serde(skip)]
    pub bearer_resolver: Option<SharedBearerResolver>,

    #[serde(default)]
    pub supports_backend_search: bool,

    /// Resolved per-model opt-in for OpenAI Responses programmatic tool calling (already gated on backend and model family).
    #[serde(default)]
    pub programmatic_tool_calling: bool,

    /// Per-model config for the `x-compactions-remaining` header; `None` disables it.
    #[serde(default)]
    pub compactions_remaining: Option<CompactionsRemaining>,

    /// Per-model config for the `x-compaction-at` header; `None` disables it.
    #[serde(default)]
    pub compaction_at_tokens: Option<CompactionAtTokens>,

    /// Server-side doom-loop check policy; `None` disables it.
    /// When set, the client sends both reporting headers on streaming Responses API requests.
    /// Those carry the configured tail window and the default exact-repetition minimum.
    /// It also absorbs the reported trigger events (unlike environment headers in [`Self::extra_headers`], this gates the client's decode behavior).
    #[serde(default)]
    pub doom_loop_recovery: Option<DoomLoopRecoveryPolicy>,

    /// Per-request header injector (e.g. OTel traceparent). Called in `post()`.
    #[serde(skip)]
    pub header_injector: Option<SharedHeaderInjector>,
}

/// Hand-written `Debug` (P70): credential values print as `<redacted>` (headers and query parameters by name only), so a `{:?}` of this type in a log, panic or error cannot disclose them.
/// The destructure is exhaustive, so a new field fails to compile here until its Debug output is decided.
impl std::fmt::Debug for SamplerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            subscription,
            subscription_resolver,
            api_key,
            base_url,
            mtls_cert_dir,
            model,
            max_completion_tokens,
            temperature,
            top_p,
            api_backend,
            auth_scheme,
            extra_headers,
            extra_response_includes,
            query_params,
            env_http_headers,
            context_window,
            force_http1,
            max_retries,
            rate_limit_retry_threshold,
            stream_tool_calls,
            idle_timeout_secs,
            reasoning_effort,
            reasoning_summary,
            origin_client,
            client_identifier,
            deployment_id,
            user_id,
            client_version,
            attribution_callback,
            bearer_resolver,
            supports_backend_search,
            programmatic_tool_calling,
            compactions_remaining,
            compaction_at_tokens,
            doom_loop_recovery,
            header_injector,
        } = self;
        f.debug_struct("SamplerConfig")
            .field("subscription", subscription)
            .field("subscription_resolver", &subscription_resolver.as_ref().map(|_| "<dyn>"))
            .field("api_key", &api_key.as_ref().map(|_| "<redacted>"))
            .field("base_url", &fuigo_auth::redact_url(base_url))
            .field("mtls_cert_dir", mtls_cert_dir)
            .field("model", model)
            .field("max_completion_tokens", max_completion_tokens)
            .field("temperature", temperature)
            .field("top_p", top_p)
            .field("api_backend", api_backend)
            .field("auth_scheme", auth_scheme)
            .field("extra_headers", &extra_headers.iter().map(|(k, _)| (k, "<redacted>")).collect::<Vec<_>>())
            .field("extra_response_includes", extra_response_includes)
            .field("query_params", &query_params.iter().map(|(k, _)| (k, "<redacted>")).collect::<Vec<_>>())
            .field("env_http_headers", env_http_headers)
            .field("context_window", context_window)
            .field("force_http1", force_http1)
            .field("max_retries", max_retries)
            .field("rate_limit_retry_threshold", rate_limit_retry_threshold)
            .field("stream_tool_calls", stream_tool_calls)
            .field("idle_timeout_secs", idle_timeout_secs)
            .field("reasoning_effort", reasoning_effort)
            .field("reasoning_summary", reasoning_summary)
            .field("origin_client", origin_client)
            .field("client_identifier", client_identifier)
            .field("deployment_id", deployment_id)
            .field("user_id", user_id)
            .field("client_version", client_version)
            .field("attribution_callback", &attribution_callback.as_ref().map(|_| "<dyn>"))
            .field("bearer_resolver", &bearer_resolver.as_ref().map(|_| "<dyn>"))
            .field("supports_backend_search", supports_backend_search)
            .field("programmatic_tool_calling", programmatic_tool_calling)
            .field("compactions_remaining", compactions_remaining)
            .field("compaction_at_tokens", compaction_at_tokens)
            .field("doom_loop_recovery", doom_loop_recovery)
            .field("header_injector", &header_injector.as_ref().map(|_| "<dyn>"))
            .finish()
    }
}

impl Default for SamplerConfig {
    /// Empty defaults so callers can use `..Default::default()` and new fields don't ripple through every literal site.
    fn default() -> Self {
        Self {
            subscription: None,
            subscription_resolver: None,
            api_key: None,
            base_url: String::new(),
            mtls_cert_dir: None,
            model: String::new(),
            max_completion_tokens: None,
            temperature: None,
            top_p: None,
            api_backend: ApiBackend::default(),
            auth_scheme: AuthScheme::default(),
            extra_headers: IndexMap::new(),
            extra_response_includes: Vec::new(),
            query_params: IndexMap::new(),
            env_http_headers: IndexMap::new(),
            context_window: 0,
            force_http1: false,
            max_retries: None,
            rate_limit_retry_threshold: None,
            stream_tool_calls: false,
            idle_timeout_secs: None,
            reasoning_effort: None,
            reasoning_summary: None,
            origin_client: None,
            client_identifier: None,
            deployment_id: None,
            user_id: None,
            client_version: None,
            attribution_callback: None,
            bearer_resolver: None,
            supports_backend_search: false,
            programmatic_tool_calling: false,
            compactions_remaining: None,
            compaction_at_tokens: None,
            doom_loop_recovery: None,
            header_injector: None,
        }
    }
}

/// Cheap sync read of the current bearer for [`SamplerConfig::bearer_resolver`].
pub trait BearerResolver: Send + Sync + std::fmt::Debug {
    fn current_bearer(&self) -> Option<String>;
}

pub type SharedBearerResolver = std::sync::Arc<dyn BearerResolver>;

/// Per-request header injection (e.g. OTel `traceparent`).
pub trait HeaderInjector: Send + Sync + std::fmt::Debug {
    fn inject(&self, headers: &mut reqwest::header::HeaderMap);
}

pub type SharedHeaderInjector = std::sync::Arc<dyn HeaderInjector>;

/// Retry knobs for the sampler's internal transport-error retry loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_retries: u32,
    /// After this many rate-limit (429) retries, escalate to the caller.
    /// Lower than `max_retries` because rate-limit waits can be long.
    pub rate_limit_retry_threshold: u32,
    #[serde(default)]
    pub retry_only_before_output: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: DEFAULT_MAX_RETRIES,
            rate_limit_retry_threshold: RATE_LIMIT_RETRY_THRESHOLD,
            retry_only_before_output: false,
        }
    }
}

/// Identity of the client that originated the request, used for User-Agent rendering.
/// The shell layer composes this with platform info into a final UA string.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OriginClientInfo {
    pub product: String,
    pub version: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Configs serialized before the field existed must keep deserializing.
    #[test]
    fn config_without_doom_loop_recovery_deserializes_to_none() {
        let mut stripped = serde_json::to_value(SamplerConfig::default()).unwrap();
        let object = stripped.as_object_mut().unwrap();
        object.remove("doom_loop_recovery");
        object.remove("extra_response_includes");
        object.remove("mtls_cert_dir");
        object.remove("rate_limit_retry_threshold");
        object.remove("reasoning_summary");
        let config: SamplerConfig = serde_json::from_value(stripped).unwrap();
        assert!(config.doom_loop_recovery.is_none());
        assert!(config.extra_response_includes.is_empty());
        assert!(config.mtls_cert_dir.is_none());
        assert!(config.rate_limit_retry_threshold.is_none());
        assert!(config.reasoning_summary.is_none());

        let with_policy = SamplerConfig {
            doom_loop_recovery: Some(DoomLoopRecoveryPolicy {
                max_threshold: 8,
                max_retries: 2,
                ..Default::default()
            }),
            ..Default::default()
        };
        let round_tripped: SamplerConfig =
            serde_json::from_value(serde_json::to_value(&with_policy).unwrap()).unwrap();
        assert_eq!(
            round_tripped.doom_loop_recovery,
            with_policy.doom_loop_recovery
        );
    }
}

#[cfg(test)]
mod p70_redacted_debug {
    use super::*;

    /// `{x:?}` and `{x:#?}` hold `<redacted>` (control) and no fragment of any secret.
    fn assert_redacted(debug: &dyn std::fmt::Debug, secrets: &[&str]) {
        for out in [format!("{debug:?}"), format!("{debug:#?}")] {
            assert!(out.contains("<redacted>"), "control: the secret field is printed as redacted: {out}");
            for secret in secrets {
                let chars: Vec<char> = secret.chars().collect();
                for w in chars.windows(6) {
                    let frag: String = w.iter().collect();
                    assert!(!out.contains(&frag), "Debug output holds {frag:?} of a secret: {out}");
                }
            }
        }
    }

    /// P70: `SamplerConfig`'s Debug used to print `api_key` and every header value.
    #[test]
    fn sampler_config_debug_redacts_key_headers_and_query() {
        let cfg = SamplerConfig {
            api_key: Some("p70sk-FAKE-1b2c3d4e5f".into()),
            extra_headers: [("Authorization".to_owned(), "Bearer p70hd-FAKE-9a8b7c".to_owned())].into_iter().collect(),
            query_params: [("key".to_owned(), "p70qp-FAKE-5e6f7a".to_owned())].into_iter().collect(),
            model: "p70-model".into(),
            base_url: "https://p70.invalid/v1?key=p70bu-FAKE-3c4d5e".into(),
            ..SamplerConfig::default()
        };
        assert_redacted(
            &cfg,
            &["p70sk-FAKE-1b2c3d4e5f", "p70hd-FAKE-9a8b7c", "p70qp-FAKE-5e6f7a", "p70bu-FAKE-3c4d5e"],
        );
        let client = crate::SamplingClient::new(cfg.clone()).expect("client");
        assert_redacted(&client, &["p70bu-FAKE-3c4d5e"]);
        let out = format!("{cfg:?}");
        assert!(out.contains("Authorization") && out.contains("p70-model"), "non-secret fields still print: {out}");
    }
}
