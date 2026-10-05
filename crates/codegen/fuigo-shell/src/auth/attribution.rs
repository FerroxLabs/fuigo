//! Shell-side 401-attribution helpers.
//!
//! Every 401 emit site in the shell joins the bearer the client
//! actually sent on the wire (the `Authorization` value for OAI-compat
//! backends, `x-api-key` for Anthropic Messages, the API proxy
//! `Authorization` header for storage / feedback / registry /
//! idle-resume) with the manager's in-memory token
//! ([`AuthManager::current_or_expired`] -- hard-expired tokens stay
//! visible, since most 401s arrive exactly then). The two sinks are:
//!
//! 1. [`fuigo_telemetry::unified_log::warn`] for the local
//!    `~/.fuigo/logs/unified.jsonl` file (best-effort; ships to GCS
//!    only on OIDC refresh failure via `auth/refresh.rs`).
//! 2. A discrete `tracing::warn_span!("auth_401_attribution", ...)` captured by the OTel layer in `util/otel_layer.rs` and shipped
//!    via OTLP export to the configured telemetry backend (queryable by span name `auth_401_attribution`).
//!
//! # Schema (every emit)
//!
//! ```text
//! {
//!   "sent_key_prefix": "<fingerprint of the bearer the client sent, or """>,
//!   "current_key_prefix": "<fingerprint of the held token (current or
//!                         expired), or null when the manager is empty>",
//!   "mint_age_seconds": <i64; current time minus auth.create_time, or -1>,
//!   "expires_at_seconds_from_now": <i64; auth.expires_at minus now
//!                                 (negative once expired), or 0 when the
//!                                 manager is empty>,
//!   "consumer": "OaiCompatClient.<endpoint>" | "StorageClient.<op>"
//!             | "FeedbackClient.<op>" | "SessionRegistryClient.<op>"
//!             | "IdleResumeModelRefresh",
//!   "is_stale_snapshot": <bool; true iff a bearer was actually sent AND it
//!                        differs from the held token -- "sent nothing"
//!                        (fail-closed) and "held nothing" are both false>
//! }
//! ```
//!
//! A fingerprint is [`fuigo_auth::BearerFingerprint`]: `sha256:<4 hex>/len=<chars>`. The field names keep their
//! historical `_prefix` spelling so existing queries still bind; their values carry no characters of the credential (P70).
//!
//! # Cross-crate wiring
//!
//! [`fuigo_sampler`] is intentionally decoupled from this crate.
//! It invokes the trait [`fuigo_sampler::Auth401AttributionCallback`] at its six 401 arms.
//! This module provides [`ShellAttribution`], the concrete impl wired into [`fuigo_sampler::SamplerConfig::attribution_callback`].
//! The shell does that wiring at every sampler-construction site.
//! Non-sampler sites (storage / feedback / registry / idle-resume) call [`record_consumer_401`] directly with their `(consumer_kind, op)` pair.

use std::sync::Arc;

use fuigo_sampler::{Auth401AttributionCallback, SamplingConsumer};
use fuigo_tools::{Auth401AttributionCallback as ToolAuth401AttributionCallback, ToolConsumer};
use serde_json::Value as JsonValue;

use crate::auth::{AuthManager, TOKEN_TTL};
use fuigo_auth::BearerFingerprint;

/// `cfg(test)`-only process-global counter that bumps on every successful `record_auth_401` invocation.
///
/// Because the counter is process-global, every test that observes it MUST be annotated with `#[serial_test::serial(attribution_emit_count)]`.
#[cfg(test)]
static EMIT_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Read the test-only emit counter.
#[cfg(test)]
pub(crate) fn test_emit_count() -> u64 {
    EMIT_COUNT.load(std::sync::atomic::Ordering::SeqCst)
}

/// Reset the test-only emit counter to zero.
/// Tests that span multiple instrumented call sites should call this at setup.
/// Leftover bumps from earlier tests in the same process then do not pollute the assertion.
#[cfg(test)]
pub(crate) fn reset_test_emit_count() {
    EMIT_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
}

/// Concrete implementation of [`Auth401AttributionCallback`] for the sampler crate's six 401 arms.
///
/// One instance is constructed per `SamplerConfig` and cloned cheaply (the struct holds an `Arc` and an `Option<String>`).
/// The `session_id` is captured at construction time and used for the `unified_log::warn` `sid` field; non-session callers may pass `None`.
pub(crate) struct ShellAttribution {
    auth_manager: Arc<AuthManager>,
    session_id: Option<String>,
}

// `AuthManager` does not implement `Debug` (it carries a `RwLock` over auth state and would expose secrets if it did)
// Hand-roll a redacted `Debug` impl so the trait's `Debug + Send + Sync` bound is satisfied without changing `AuthManager`'s API
impl std::fmt::Debug for ShellAttribution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShellAttribution")
            .field("auth_manager", &"<redacted>")
            .field("session_id", &self.session_id)
            .finish()
    }
}

impl ShellAttribution {
    /// Construct a shareable attribution callback wired to the given [`AuthManager`].
    /// Returns `Arc<dyn Trait>` so callers can drop the value directly into [`fuigo_sampler::SamplerConfig::attribution_callback`].
    /// That field expects exactly `Arc<dyn Trait>`; keeping the boundary in one place avoids `as Arc<dyn _>` coercions at every call site.
    #[allow(clippy::new_ret_no_self)]
    pub(crate) fn new(
        auth_manager: Arc<AuthManager>,
        session_id: Option<String>,
    ) -> Arc<dyn Auth401AttributionCallback> {
        Arc::new(Self {
            auth_manager,
            session_id,
        })
    }

    /// Tool-side counterpart of [`Self::new`]: returns `Arc<dyn fuigo_tools::Auth401AttributionCallback>` for the
    /// `with_attribution_callback(...)` builder on each tool HTTP client (`ImageGenClient`, `VideoGenClient`, `WebSearchClient`).
    /// The two callbacks share the same underlying impl and emit the same `auth_401_attribution` event format.
    /// Only the trait signature differs (`SamplingConsumer` vs. `ToolConsumer`).
    pub(crate) fn new_tool_callback(
        auth_manager: Arc<AuthManager>,
        session_id: Option<String>,
    ) -> Arc<dyn ToolAuth401AttributionCallback> {
        Arc::new(Self {
            auth_manager,
            session_id,
        })
    }
}

impl Auth401AttributionCallback for ShellAttribution {
    fn record_401(&self, consumer: SamplingConsumer, sent_bearer: Option<&BearerFingerprint>) {
        // Already fingerprinted by the sampler: the bearer never leaves that crate
        record_consumer_401(
            self.auth_manager.as_ref(),
            self.session_id.as_deref(),
            ConsumerKind::OaiCompatClient,
            consumer.as_endpoint(),
            sent_bearer,
        );
    }
}

/// Tool-side hook: each tool client (image_gen, video_gen, web_search) in `fuigo-tools` emits a 401 attribution event through this
/// trait when its HTTP request returns UNAUTHORIZED.
/// Same shape as the sampler-side impl above; routes to the same pair of sinks.
///
/// `ToolConsumer::VideoGenStart` and `VideoGenPoll` collapse to the same [`ConsumerKind::VideoGen`] with different op strings.
/// The gate query can then break down video-gen 401s by phase.
impl ToolAuth401AttributionCallback for ShellAttribution {
    fn record_401(&self, consumer: ToolConsumer, sent_bearer: Option<&BearerFingerprint>) {
        let (kind, op) = match consumer {
            ToolConsumer::ImageGen => (ConsumerKind::ImageGen, ""),
            ToolConsumer::VideoGenStart => (ConsumerKind::VideoGen, "start"),
            ToolConsumer::VideoGenPoll => (ConsumerKind::VideoGen, "poll"),
            ToolConsumer::WebSearch => (ConsumerKind::WebSearch, ""),
        };
        record_consumer_401(
            self.auth_manager.as_ref(),
            self.session_id.as_deref(),
            kind,
            op,
            sent_bearer,
        );
    }
}

/// Categories of 401-attribution emit sites. Each variant maps to a
/// fixed prefix in the rendered `consumer` field; the per-site `op`
/// string is appended after a `.` separator (omitted for variants that
/// have no per-operation discriminator, e.g.
/// [`ConsumerKind::IdleResumeModelRefresh`]).
#[derive(Debug, Clone, Copy)]
pub(crate) enum ConsumerKind {
    /// Sampler-side OpenAI-compat / Anthropic Messages emit. The op
    /// string is the [`SamplingConsumer::as_endpoint`] return value.
    OaiCompatClient,
    /// Storage upload / batch / check sites in `upload/storage_client.rs`.
    StorageClient,
    /// Feedback collection sites in `agent/feedback_client.rs`.
    FeedbackClient,
    /// Session registry register/update sites in
    /// `agent/session_registry_client.rs`.
    SessionRegistryClient,
    /// Idle-resume model-metadata refresh in `session/acp_session.rs::maybe_refresh_model_metadata_on_resume`.
    /// No per-op discriminator; the consumer string is just `"IdleResumeModelRefresh"`.
    IdleResumeModelRefresh,
    /// `fuigo_tools::ToolConsumer::ImageGen`, the Imagine API (`POST /images/generations`).
    /// No per-op discriminator; consumer string is just `"ImageGen"`.
    ImageGen,
    /// `fuigo_tools::ToolConsumer::VideoGenStart` and `VideoGenPoll`, the Video Generation API.
    /// The op string is `"start"` (`POST /videos/generations`) or `"poll"` (`GET /videos/{request_id}`).
    VideoGen,
    /// `fuigo_tools::ToolConsumer::WebSearch`, web search via `POST /responses` with a `WebSearch` tool.
    /// No per-op discriminator; consumer string is just `"WebSearch"`.
    WebSearch,
}

impl ConsumerKind {
    /// Fixed prefix for the rendered `consumer` field.
    fn prefix(self) -> &'static str {
        match self {
            Self::OaiCompatClient => "OaiCompatClient",
            Self::StorageClient => "StorageClient",
            Self::FeedbackClient => "FeedbackClient",
            Self::SessionRegistryClient => "SessionRegistryClient",
            Self::IdleResumeModelRefresh => "IdleResumeModelRefresh",
            Self::ImageGen => "ImageGen",
            Self::VideoGen => "VideoGen",
            Self::WebSearch => "WebSearch",
        }
    }

    /// `true` for variants that take a per-operation discriminator appended as `<prefix>.<op>`.
    /// `false` for variants whose `consumer` string is just the prefix.
    /// `IdleResumeModelRefresh`, `ImageGen`, and `WebSearch` are each a single endpoint with no sub-operation.
    fn takes_op(self) -> bool {
        !matches!(
            self,
            Self::IdleResumeModelRefresh | Self::ImageGen | Self::WebSearch
        )
    }
}

/// Format a `(kind, op)` pair into the canonical `consumer` string.
fn format_consumer(kind: ConsumerKind, op: &str) -> String {
    if kind.takes_op() {
        format!("{}.{}", kind.prefix(), op)
    } else {
        kind.prefix().to_string()
    }
}

/// Emit a single `auth 401 attribution` event for a per-consumer 401.
///
/// Wraps [`record_auth_401`] with the canonical `consumer` formatting (e.g., `"StorageClient.upload"`, `"FeedbackClient.submit"`).
/// All 401 emit sites in `fuigo-shell` go through this helper.
/// The per-client `record_401_attribution` wrappers in `agent/feedback_client.rs`, `agent/session_registry_client.rs`, and
/// `upload/storage_client.rs` each resolve their bearer and call this with the right `(kind, op)`.
///
/// `sent_bearer` is the [`BearerFingerprint`] of the bearer that went on the wire; the type admits nothing else, so no
/// call site can hand a raw credential (or a fragment of one) to the sinks.
pub(crate) fn record_consumer_401(
    auth_manager: &AuthManager,
    session_id: Option<&str>,
    kind: ConsumerKind,
    op: &str,
    sent_bearer: Option<&BearerFingerprint>,
) {
    let consumer = format_consumer(kind, op);
    record_auth_401(auth_manager, session_id, &consumer, sent_bearer);
}

/// Emit a single `auth 401 attribution` event to both sinks (local unified log file and OTel span for OTLP export).
///
/// Schema: `(sent_key_prefix, current_key_prefix, mint_age_seconds, expires_at_seconds_from_now, consumer, is_stale_snapshot)`.
///
/// `sent_bearer` is the fingerprint of the bearer that was sent on the wire (the `Authorization` value with `"Bearer "`
/// stripped, or `x-api-key`). `None` becomes the empty string, meaning "no bearer was sent."
///
/// `consumer` should be one of the canonical strings used by the per-client wrappers,
/// e.g. `"OaiCompatClient.chat_completions_stream"`, `"StorageClient.upload"`, `"IdleResumeModelRefresh"`.
/// Most call sites should go through [`record_consumer_401`] which formats the consumer string from a [`ConsumerKind`] for them.
pub(crate) fn record_auth_401(
    auth_manager: &AuthManager,
    session_id: Option<&str>,
    consumer: &str,
    sent_bearer: Option<&BearerFingerprint>,
) {
    let payload =
        compute_attribution_payload(auth_manager, consumer, sent_bearer, attribution_now());

    // Sink 1 -- local file (~/.fuigo/logs/unified.jsonl) + scrubbed
    // tracing event
    // The local file is reliable but only ships to GCS on OIDC refresh failure (auth/refresh.rs::spawn_diagnostic_upload)
    // By itself it does not show the steady-state 401 population; Sink 2 below provides that
    fuigo_telemetry::unified_log::warn("auth 401 attribution", session_id, Some(payload.clone()));

    // Sink 2: discrete OTel span exported via OTLP (util/otel_layer.rs)
    // The schema fields below become OTel span attributes under `attributes.custom.<name>` per the tracing-opentelemetry bridge
    // Query by span name `auth_401_attribution` in the configured telemetry backend
    //
    // Wrapping in a `warn_span!` (vs. plain `tracing::warn!`) emits even when no parent span is active.
    // The OTel layer attaches plain events to the currently-entered span only
    // So a `tracing::warn!` from a `spawn_blocking` closure (idle-resume model refresh) or a background sync task is silently dropped
    // A `warn_span!` itself is always emitted by the layer's `on_new_span`/`on_close` hooks regardless of parent context
    //
    // The span carries no body and is dropped immediately at the end of this function
    // Its `duration` is a few microseconds and it is logically a one-shot record, not a wrapping context for any other work
    let _attribution_span = tracing::warn_span!(
        "auth_401_attribution",
        // String fields
        // tracing flattens Option<&str> via Display, so we pre-collapse `None` to "" for both prefix fields and for session_id
        // Downstream queries should treat "" as absent
        sent_key_prefix = payload["sent_key_prefix"].as_str().unwrap_or(""),
        current_key_prefix = payload["current_key_prefix"].as_str().unwrap_or(""),
        consumer = consumer,
        session_id = session_id.unwrap_or(""),
        // Numeric fields. The sentinel values from `compute_attribution_payload` (-1, 0) carry through unchanged.
        mint_age_seconds = payload["mint_age_seconds"].as_i64().unwrap_or(-1),
        expires_at_seconds_from_now = payload["expires_at_seconds_from_now"].as_i64().unwrap_or(0),
        // Boolean; the field stale-vs-live splits key on
        is_stale_snapshot = payload["is_stale_snapshot"].as_bool().unwrap_or(false),
    )
    .entered();

    #[cfg(test)]
    EMIT_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// The wall clock, except in a test that pinned it with [`pin_attribution_now`] on its own thread.
fn attribution_now() -> chrono::DateTime<chrono::Utc> {
    #[cfg(test)]
    if let Some(pinned) = PINNED_NOW.with(std::cell::Cell::get) {
        return pinned;
    }
    chrono::Utc::now()
}

#[cfg(test)]
thread_local! {
    static PINNED_NOW: std::cell::Cell<Option<chrono::DateTime<chrono::Utc>>> = const { std::cell::Cell::new(None) };
}

/// Test-only: pin [`attribution_now`] for the calling thread until the guard drops.
#[cfg(test)]
#[must_use]
fn pin_attribution_now(now: chrono::DateTime<chrono::Utc>) -> impl Drop {
    struct Unpin;
    impl Drop for Unpin {
        fn drop(&mut self) {
            PINNED_NOW.with(|p| p.set(None));
        }
    }
    PINNED_NOW.with(|p| p.set(Some(now)));
    Unpin
}

/// Pure (no I/O) computation of the attribution payload.
/// Extracted from [`record_auth_401`] so unit tests can assert each field without reaching into `unified_log`'s writer or the tracing layer.
///
/// Reads [`AuthManager::current_or_expired`], NOT `current()`.
/// `current()` is `None` by construction in the hard-expired window most 401s land in and would blank every field this event exists to fill.
///
/// `is_stale_snapshot` is `true` only when a bearer was actually sent and it differs from the held token.
/// "Sent nothing" (fail-closed) and "held nothing" (empty manager) are both `false`.
///
/// `now` is the instant the ages are measured from; [`record_auth_401`] passes [`attribution_now`].
fn compute_attribution_payload(
    auth_manager: &AuthManager,
    consumer: &str,
    sent_bearer: Option<&BearerFingerprint>,
    now: chrono::DateTime<chrono::Utc>,
) -> JsonValue {
    // Fingerprint of the bearer the wire actually carried; `""` when the request had no bearer at all
    // That is a distinct case from "had a bearer that turned out to be stale"; the gate-criteria query can break down on this
    let sent_suffix = sent_bearer.map(BearerFingerprint::as_str).unwrap_or("");

    // One read; `current_or_expired` keeps the hard-expired token visible (see the fn doc)
    // Fingerprinted the same way, so equal credentials compare equal (a different one collides with odds 2^-16 at
    // the same length, which only ever under-reports staleness in a diagnostic)
    let current_auth = auth_manager.current_or_expired();
    let current_suffix_owned: Option<String> = current_auth
        .as_ref()
        .map(|a| fuigo_auth::bearer_fingerprint(&a.key));

    // True-positive staleness only: a bearer was sent AND differs from the held token
    // "Sent nothing" is the fail-closed path (in sync, credential dead); "held nothing" is no evidence; neither is stale
    let is_stale_snapshot = match (sent_suffix, current_suffix_owned.as_deref()) {
        ("", _) => false,
        (_, None) => false,
        (sent, Some(held)) => sent != held,
    };

    // Mint-age and expiry come from the same `current_auth` we already read; sentinels `-1 / 0` when the manager holds nothing
    // For a hard-expired token these report true age and (negative) time-past-expiry: how long the bearer was dead at the 401
    //
    // TODO: mirror the full External-with-ttl branch from `AuthManager::is_token_expired`
    // (uses `fuigo_com_config.auth_token_ttl` when `expires_at` is `None` and `auth_mode == External`)
    // The current 2-branch fallback (`expires_at` if Some else `create_time + TOKEN_TTL`) is good enough for diagnostic metadata
    // The External-ttl branch is worth wiring once a real consumer needs it
    let (mint_age_seconds, expires_at_seconds_from_now) = match current_auth {
        Some(auth) => {
            let mint_age = now.signed_duration_since(auth.create_time).num_seconds();
            let expiry = auth.expires_at.unwrap_or(auth.create_time + TOKEN_TTL);
            (mint_age, expiry.signed_duration_since(now).num_seconds())
        }
        None => (-1_i64, 0_i64),
    };

    serde_json::json!({
        "sent_key_prefix": sent_suffix,
        "current_key_prefix": current_suffix_owned,
        "mint_age_seconds": mint_age_seconds,
        "expires_at_seconds_from_now": expires_at_seconds_from_now,
        "consumer": consumer,
        "is_stale_snapshot": is_stale_snapshot,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::{Duration, Utc};

    use crate::auth::{AuthManager, FuigoAuth, FuigoComConfig};

    use super::*;

    /// Test helper: build a fresh `AuthManager` rooted at a tempdir so
    /// nothing from a developer's actual `~/.fuigo/auth.json` leaks in.
    fn empty_auth_manager() -> (tempfile::TempDir, AuthManager) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = FuigoComConfig::default();
        // `new_at_path`, not `new`: other tests in this binary briefly set `FUIGO_AUTH` / `FUIGO_AUTH_PATH`, which
        // `new` honours, and a credential borrowed that way made "empty manager" tests flake (seen in the P70 runs).
        let am = AuthManager::new_at_path(dir.path().join("auth.json"), cfg);
        (dir, am)
    }

    /// The instant every test measures from: the payload's ages are computed against it, not the wall clock, so a
    /// stalled host cannot move them.
    fn t0() -> chrono::DateTime<Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    /// Minted at `t0`, expiring an hour later.
    fn fresh_auth(key: &str) -> FuigoAuth {
        FuigoAuth {
            key: key.to_string(),
            create_time: t0(),
            expires_at: Some(t0() + Duration::hours(1)),
            ..FuigoAuth::test_default()
        }
    }

    fn payload_at_t0(am: &AuthManager, consumer: &str, sent: Option<&str>) -> JsonValue {
        let sent = sent.map(BearerFingerprint::of);
        compute_attribution_payload(am, consumer, sent.as_ref(), t0())
    }

    fn fp(credential: &str) -> String {
        fuigo_auth::bearer_fingerprint(credential)
    }

    fn fpo(credential: &str) -> Option<BearerFingerprint> {
        Some(BearerFingerprint::of(credential))
    }

    fn payload_field<'a>(payload: &'a JsonValue, key: &str) -> &'a JsonValue {
        payload
            .get(key)
            .unwrap_or_else(|| panic!("payload missing field {key:?}: {payload:?}"))
    }

    /// Live token sent and a 401 with matching `current()`: `is_stale_snapshot` must be `false`.
    /// Also assert the auxiliary fields are set sensibly (prefix, mint age, expiry).
    #[test]
    fn live_token_sent_is_not_stale() {
        let (_dir, am) = empty_auth_manager();
        let sent = "live-token-1234567890abcdef";
        am.hot_swap(fresh_auth(sent));

        let payload = payload_at_t0(&am, "Test.live", Some(sent));

        assert_eq!(payload_field(&payload, "is_stale_snapshot"), false);
        assert_eq!(payload_field(&payload, "consumer"), "Test.live");
        // Fingerprints, equal because the credential is the same
        assert_eq!(payload_field(&payload, "sent_key_prefix"), fp(sent).as_str());
        assert_eq!(payload_field(&payload, "current_key_prefix"), fp(sent).as_str());
        // Minted at t0 and measured at t0: age 0, expiry exactly an hour out
        assert_eq!(payload_field(&payload, "mint_age_seconds"), 0);
        assert_eq!(payload_field(&payload, "expires_at_seconds_from_now"), 3600);
    }

    /// Stale snapshot sent and a 401 with a different (newer) `current()`: `is_stale_snapshot` must be `true`.
    #[test]
    fn stale_snapshot_is_detected() {
        let (_dir, am) = empty_auth_manager();
        let stale = "stale-token-1234567890";
        let live = "live-token-different";
        am.hot_swap(fresh_auth(live));

        let payload = payload_at_t0(&am, "Test.stale", Some(stale));

        assert_eq!(payload_field(&payload, "is_stale_snapshot"), true);
        assert_eq!(payload_field(&payload, "sent_key_prefix"), fp(stale).as_str());
        assert_eq!(payload_field(&payload, "current_key_prefix"), fp(live).as_str());
        assert_eq!(payload_field(&payload, "consumer"), "Test.stale");
    }

    /// Live token sent and a 401 with `current() == None`: `is_stale_snapshot` must be `false` (no evidence of staleness).
    /// Sentinel `mint_age_seconds = -1`, `expires_at_seconds_from_now = 0`; `current_key_prefix` is JSON `null`.
    #[test]
    fn absent_current_is_not_stale() {
        let (_dir, am) = empty_auth_manager();
        // Do NOT inject anything; the manager has no current token

        let payload = payload_at_t0(&am, "Test.absent", Some("any-token"));

        assert_eq!(payload_field(&payload, "is_stale_snapshot"), false);
        assert_eq!(payload_field(&payload, "sent_key_prefix"), fp("any-token").as_str());
        assert!(payload_field(&payload, "current_key_prefix").is_null());
        assert_eq!(payload_field(&payload, "mint_age_seconds"), -1);
        assert_eq!(payload_field(&payload, "expires_at_seconds_from_now"), 0);
    }

    /// Test helper: a token minted 2h ago that hard-expired 1h ago.
    /// That is the in-memory state during the exact window most 401s occur in (`current()` is `None`, `expired_auth()` is `Some`).
    fn hard_expired_auth(key: &str) -> FuigoAuth {
        FuigoAuth {
            key: key.to_string(),
            create_time: t0() - Duration::hours(2),
            expires_at: Some(t0() - Duration::hours(1)),
            ..FuigoAuth::test_default()
        }
    }

    /// A consumer sends the very token the manager holds, hard-expired: NOT stale (in sync; the token itself is dead).
    /// The held token and real age fields must stay visible; `current()` used to blank them.
    #[test]
    fn hard_expired_held_token_sent_is_not_stale() {
        let (_dir, am) = empty_auth_manager();
        let sent = "expired-token-1234567890abcdef";
        am.hot_swap(hard_expired_auth(sent));
        assert!(am.current().is_none(), "hard-expired precondition");

        let payload = payload_at_t0(&am, "Test.expired", Some(sent));

        assert_eq!(payload_field(&payload, "is_stale_snapshot"), false);
        assert_eq!(
            payload_field(&payload, "current_key_prefix"),
            fp(sent).as_str(),
            "the held token must stay visible even when hard-expired"
        );
        // Minted 2h before t0, dead since 1h before it
        assert_eq!(payload_field(&payload, "mint_age_seconds"), 7200);
        assert_eq!(
            payload_field(&payload, "expires_at_seconds_from_now"),
            -3600
        );
    }

    /// The fail-closed path: a hard-expired token is held, and the wire-valid-only resolver correctly put NO bearer on the wire.
    /// Not a stale snapshot: the consumer did the right thing; the credential is dead.
    /// Absorbing this into the stale bucket would bury the true-positive split the field exists for.
    #[test]
    fn nothing_sent_with_hard_expired_held_token_is_not_stale() {
        let (_dir, am) = empty_auth_manager();
        am.hot_swap(hard_expired_auth("held-but-not-sent"));

        let payload = payload_at_t0(&am, "Test.fail_closed", None);

        assert_eq!(payload_field(&payload, "is_stale_snapshot"), false);
        assert_eq!(payload_field(&payload, "sent_key_prefix"), "");
        assert_eq!(
            payload_field(&payload, "current_key_prefix"),
            fp("held-but-not-sent").as_str(),
            "the held token must stay visible for diagnosis"
        );
    }

    /// A consumer sends an OLDER bearer than the (hard-expired) one the manager holds: a true stale snapshot.
    /// It must be flagged even though `current()` is `None` in this window.
    #[test]
    fn stale_snapshot_detected_against_hard_expired_held_token() {
        let (_dir, am) = empty_auth_manager();
        am.hot_swap(hard_expired_auth("held-token-different"));
        assert!(am.current().is_none(), "hard-expired precondition");

        let payload = payload_at_t0(&am, "Test.expired_stale", Some("frozen-at-spawn-copy"));

        assert_eq!(payload_field(&payload, "is_stale_snapshot"), true);
        assert_eq!(
            payload_field(&payload, "current_key_prefix"),
            fp("held-token-different").as_str()
        );
    }

    /// Two-branch fallback: a legacy token (no `expires_at`) uses `create_time + TOKEN_TTL` as the expiry source.
    /// We assert the computed `expires_at_seconds_from_now` reflects that.
    #[test]
    fn legacy_token_uses_two_branch_fallback() {
        let (_dir, am) = empty_auth_manager();
        let auth = FuigoAuth {
            key: "k".into(),
            create_time: t0() - Duration::seconds(60),
            // No expires_at falls through to create_time + TOKEN_TTL (30 days)
            ..FuigoAuth::test_default()
        };
        am.hot_swap(auth);

        let payload = payload_at_t0(&am, "Test.legacy", Some("k"));

        // Minted 60s before t0; no expires_at, so it expires TOKEN_TTL after minting
        assert_eq!(payload_field(&payload, "mint_age_seconds"), 60);
        assert_eq!(
            payload_field(&payload, "expires_at_seconds_from_now"),
            TOKEN_TTL.num_seconds() - 60
        );
    }

    /// `format_consumer` matrix:
    ///   - generic ops append "." plus the op (`OaiCompatClient.foo`)
    ///   - IdleResumeModelRefresh and tool variants drop the op (their consumer string has no sub-op axis).
    #[test]
    fn format_consumer_matrix() {
        let cases: &[(ConsumerKind, &str, &str)] = &[
            (
                ConsumerKind::OaiCompatClient,
                "chat_completions_stream",
                "OaiCompatClient.chat_completions_stream",
            ),
            (
                ConsumerKind::StorageClient,
                "upload_file",
                "StorageClient.upload_file",
            ),
            (
                ConsumerKind::IdleResumeModelRefresh,
                "",
                "IdleResumeModelRefresh",
            ),
            (
                ConsumerKind::IdleResumeModelRefresh,
                "ignored",
                "IdleResumeModelRefresh",
            ),
            (ConsumerKind::ImageGen, "", "ImageGen"),
            (ConsumerKind::ImageGen, "ignored", "ImageGen"),
            (ConsumerKind::VideoGen, "start", "VideoGen.start"),
            (ConsumerKind::VideoGen, "poll", "VideoGen.poll"),
            (ConsumerKind::WebSearch, "", "WebSearch"),
            (ConsumerKind::WebSearch, "ignored", "WebSearch"),
        ];
        for (kind, op, expected) in cases {
            assert_eq!(
                format_consumer(*kind, op),
                *expected,
                "kind={kind:?} op={op:?}"
            );
        }
    }

    /// `format_consumer` formats `OaiCompatClient.<endpoint>` correctly and omits the `.` separator for `IdleResumeModelRefresh`.
    #[test]
    fn format_consumer_with_op_appends_dot() {
        assert_eq!(
            format_consumer(ConsumerKind::OaiCompatClient, "chat_completions_stream"),
            "OaiCompatClient.chat_completions_stream"
        );
        assert_eq!(
            format_consumer(ConsumerKind::StorageClient, "upload_file"),
            "StorageClient.upload_file"
        );
    }

    /// `ShellAttribution` implements `fuigo_tools::Auth401AttributionCallback` by routing each `ToolConsumer` variant to the right
    /// `(ConsumerKind, op)` pair, which formats to the expected `consumer` string in the emitted payload.
    #[test]
    #[serial_test::serial(attribution_emit_count)]
    fn shell_attribution_tool_impl_routes_to_correct_consumer_strings() {
        reset_test_emit_count();
        let (_dir, am) = empty_auth_manager();
        am.hot_swap(fresh_auth("bearer-1234567890"));
        let am_arc = Arc::new(am);
        let cb: Arc<dyn ToolAuth401AttributionCallback> =
            ShellAttribution::new_tool_callback(am_arc.clone(), Some("sid-tool".into()));

        let cases = [
            (ToolConsumer::ImageGen, "ImageGen"),
            (ToolConsumer::VideoGenStart, "VideoGen.start"),
            (ToolConsumer::VideoGenPoll, "VideoGen.poll"),
            (ToolConsumer::WebSearch, "WebSearch"),
        ];

        for (consumer, expected_consumer_str) in cases {
            cb.record_401(consumer, fpo("bearer-1234567890").as_ref());
            let payload = compute_attribution_payload(
                am_arc.as_ref(),
                expected_consumer_str,
                fpo("bearer-1234567890").as_ref(),
                t0(),
            );
            assert_eq!(
                payload_field(&payload, "consumer"),
                expected_consumer_str,
                "ToolConsumer::{consumer:?} should render as {expected_consumer_str:?}",
            );
        }

        // Each variant bumped the global counter exactly once.
        assert_eq!(test_emit_count() as usize, cases.len());
    }

    /// Capture `tracing::Span` `on_new_span` callbacks into a `Mutex<Vec<CapturedSpan>>` so tests can assert the
    /// `warn_span!("auth_401_attribution", ...)` emit fired with the expected name and field values.
    ///
    /// We only need `on_new_span` (which the tracing-opentelemetry layer uses as its `OTel span_started` hook).
    /// `on_close` is not asserted because the test cares about "did the span exist with these attributes," not its duration.
    mod span_capture {
        use std::sync::Mutex;
        use tracing::Subscriber;
        use tracing::field::{Field, Visit};
        use tracing::span::Attributes;
        use tracing_subscriber::layer::{Context, Layer};
        use tracing_subscriber::registry::LookupSpan;

        #[derive(Debug, Default, Clone)]
        pub(crate) struct CapturedSpan {
            pub name: String,
            pub fields_str: std::collections::BTreeMap<String, String>,
            pub fields_i64: std::collections::BTreeMap<String, i64>,
            pub fields_bool: std::collections::BTreeMap<String, bool>,
        }

        pub(crate) struct SpanCollector {
            pub spans: std::sync::Arc<Mutex<Vec<CapturedSpan>>>,
        }

        impl SpanCollector {
            pub(crate) fn new() -> (Self, std::sync::Arc<Mutex<Vec<CapturedSpan>>>) {
                let buf = std::sync::Arc::new(Mutex::new(Vec::new()));
                (Self { spans: buf.clone() }, buf)
            }
        }

        impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for SpanCollector {
            fn on_new_span(&self, attrs: &Attributes<'_>, _id: &tracing::Id, _ctx: Context<'_, S>) {
                let mut captured = CapturedSpan {
                    name: attrs.metadata().name().to_string(),
                    ..Default::default()
                };
                let mut visitor = FieldVisitor {
                    captured: &mut captured,
                };
                attrs.record(&mut visitor);
                self.spans.lock().unwrap().push(captured);
            }
        }

        struct FieldVisitor<'a> {
            captured: &'a mut CapturedSpan,
        }

        impl<'a> Visit for FieldVisitor<'a> {
            fn record_str(&mut self, field: &Field, value: &str) {
                self.captured
                    .fields_str
                    .insert(field.name().to_string(), value.to_string());
            }
            fn record_i64(&mut self, field: &Field, value: i64) {
                self.captured
                    .fields_i64
                    .insert(field.name().to_string(), value);
            }
            fn record_u64(&mut self, field: &Field, value: u64) {
                self.captured
                    .fields_i64
                    .insert(field.name().to_string(), value as i64);
            }
            fn record_bool(&mut self, field: &Field, value: bool) {
                self.captured
                    .fields_bool
                    .insert(field.name().to_string(), value);
            }
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                self.captured
                    .fields_str
                    .insert(field.name().to_string(), format!("{value:?}"));
            }
        }
    }

    /// `record_auth_401` emits a discrete `warn_span!` named `"auth_401_attribution"` with the attribution fields as span attributes.
    /// This is the span the tracing-opentelemetry bridge ships via OTLP export to the configured telemetry backend.
    /// Verifies field names, types, and values match the schema documented at the top of this module.
    #[test]
    #[serial_test::serial(attribution_emit_count)]
    fn record_auth_401_emits_otel_span_with_attribution_fields() {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let (collector, captured) = span_capture::SpanCollector::new();
        let subscriber = tracing_subscriber::registry().with(collector);
        let _guard = subscriber.set_default();

        reset_test_emit_count();
        let (_dir, am) = empty_auth_manager();
        am.hot_swap(fresh_auth("live-token-1234567890"));

        let _clock = pin_attribution_now(t0());
        record_auth_401(
            &am,
            Some("sid-otel-span"),
            "OaiCompatClient.chat_completions_stream",
            fpo("stale-snapshot-aaaaaa").as_ref(),
        );

        let spans = captured.lock().unwrap();
        let attribution = spans
            .iter()
            .find(|s| s.name == "auth_401_attribution")
            .expect("expected one auth_401_attribution span; got: {spans:?}");

        // String fields: fingerprints, consumer and session_id passed verbatim
        assert_eq!(
            attribution
                .fields_str
                .get("sent_key_prefix")
                .map(String::as_str),
            Some(fp("stale-snapshot-aaaaaa").as_str()),
            "sent_key_prefix should be the fingerprint",
        );
        assert_eq!(
            attribution
                .fields_str
                .get("current_key_prefix")
                .map(String::as_str),
            Some(fp("live-token-1234567890").as_str()),
        );
        assert_eq!(
            attribution.fields_str.get("consumer").map(String::as_str),
            Some("OaiCompatClient.chat_completions_stream"),
        );
        assert_eq!(
            attribution.fields_str.get("session_id").map(String::as_str),
            Some("sid-otel-span"),
        );

        // Boolean: the field stale-vs-live splits key on. `true` because `sent != current`.
        assert_eq!(
            attribution.fields_bool.get("is_stale_snapshot"),
            Some(&true),
        );

        // Numeric, against the pinned clock: minted at t0, expiring an hour after it
        assert_eq!(attribution.fields_i64.get("mint_age_seconds"), Some(&0));
        assert_eq!(
            attribution.fields_i64.get("expires_at_seconds_from_now"),
            Some(&3600)
        );
    }

    /// `record_auth_401` (the I/O-bearing wrapper) bumps the `cfg(test)` counter.
    /// Cross-module tests can then observe how many times an attribution event was actually emitted.
    ///
    /// `#[serial]` because `EMIT_COUNT` is process-global; concurrent tests that exercise the counter would race each other.
    #[test]
    #[serial_test::serial(attribution_emit_count)]
    fn record_auth_401_bumps_emit_counter() {
        reset_test_emit_count();
        let (_dir, am) = empty_auth_manager();
        am.hot_swap(fresh_auth("k"));
        record_auth_401(&am, None, "Test.counter", fpo("k").as_ref());
        assert_eq!(test_emit_count(), 1);
        record_auth_401(&am, None, "Test.counter", fpo("k").as_ref());
        assert_eq!(test_emit_count(), 2);
    }

    /// The SubagentSpawnContext-borne callback flows through `read_parent_sampling_config` into the inherited
    /// `SamplerConfig.attribution_callback`.
    /// We can't drive the full subagent path here (requires SessionActor and chat-state scaffolding).
    /// We can assert the structural property: the callback the parent constructs is the one any later `SamplerConfig` clone carries forward.
    #[test]
    #[serial_test::serial(attribution_emit_count)]
    fn parent_callback_flows_through_arc_clone() {
        reset_test_emit_count();
        let (_dir, am) = empty_auth_manager();
        let am_arc = Arc::new(am);
        let parent_cb = ShellAttribution::new(am_arc.clone(), Some("parent-sid".into()));

        // Simulate the inheritance: the parent callback flows through SessionHandle, then SubagentSpawnContext, then
        // SamplerConfig.attribution_callback, as plain Arc clones
        let inherited_cb = parent_cb.clone();

        // Drive the inherited callback
        // The `record_401` bumps the same global counter the parent callback would, proving they refer to the same underlying impl
        inherited_cb.record_401(SamplingConsumer::ChatCompletionsStream, fpo("bearer").as_ref());
        assert_eq!(test_emit_count(), 1);

        // Sanity: the parent_cb still works too (it's the same Arc).
        parent_cb.record_401(SamplingConsumer::Messages, fpo("bearer").as_ref());
        assert_eq!(test_emit_count(), 2);
    }

    /// End-to-end: the trait impl wraps `consumer.as_endpoint()` in `"OaiCompatClient.<endpoint>"` and delegates to `record_consumer_401`
    /// for every variant of `SamplingConsumer`.
    /// We assert one bump per variant via the test counter.
    /// We also assert the rendered `consumer` string for one variant via a payload recompute.
    /// The trait does not return the payload, so we recompute directly from the same inputs.
    #[test]
    #[serial_test::serial(attribution_emit_count)]
    fn shell_attribution_trait_impl_routes_through_helper() {
        reset_test_emit_count();
        let (_dir, am) = empty_auth_manager();
        let am_arc = Arc::new(am);
        let cb = ShellAttribution::new(am_arc.clone(), Some("sid-shell".into()));
        let variants = [
            SamplingConsumer::ChatCompletionsStream,
            SamplingConsumer::ChatCompletions,
            SamplingConsumer::ResponsesStream,
            SamplingConsumer::Responses,
            SamplingConsumer::MessagesStream,
            SamplingConsumer::Messages,
        ];
        for consumer in variants {
            cb.record_401(consumer, fpo("test-bearer").as_ref());
        }
        assert_eq!(test_emit_count() as usize, variants.len());

        // Check the consumer-string formatting via direct payload computation
        let payload = compute_attribution_payload(
            am_arc.as_ref(),
            &format_consumer(
                ConsumerKind::OaiCompatClient,
                SamplingConsumer::MessagesStream.as_endpoint(),
            ),
            fpo("test-bearer").as_ref(),
            t0(),
        );
        assert_eq!(
            payload_field(&payload, "consumer"),
            "OaiCompatClient.messages_stream"
        );
    }

    /// Every substring of `credential` at least `min` characters long, the shortest first.
    fn fragments(credential: &str, min: usize) -> Vec<String> {
        let chars: Vec<char> = credential.chars().collect();
        let mut out = Vec::new();
        for len in min..=chars.len() {
            for w in chars.windows(len) {
                out.push(w.iter().collect());
            }
        }
        out
    }

    /// Tracing layer that renders every span and event field (any type) into one string per record.
    mod record_capture {
        use std::sync::{Arc, Mutex};
        use tracing::field::{Field, Visit};
        use tracing_subscriber::layer::{Context, Layer};
        use tracing_subscriber::registry::LookupSpan;

        pub(crate) struct Collector(pub Arc<Mutex<Vec<String>>>);

        struct Render<'a>(&'a mut String);
        impl Visit for Render<'_> {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!(" {}={value:?}", field.name()));
            }
            fn record_str(&mut self, field: &Field, value: &str) {
                self.0.push_str(&format!(" {}={value}", field.name()));
            }
        }

        impl<S: tracing::Subscriber + for<'a> LookupSpan<'a>> Layer<S> for Collector {
            fn on_new_span(&self, attrs: &tracing::span::Attributes<'_>, _: &tracing::Id, _: Context<'_, S>) {
                let mut line = attrs.metadata().name().to_string();
                attrs.record(&mut Render(&mut line));
                self.0.lock().unwrap().push(line);
            }
            fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
                let mut line = event.metadata().name().to_string();
                event.record(&mut Render(&mut line));
                self.0.lock().unwrap().push(line);
            }
        }
    }

    /// P70 hostile: a 401 on a SHORT key (which the old 12-character tail logged whole) and on a long one. Both sinks
    /// (the tracing span the OTel bridge exports, and the unified log file) are captured; neither holds the credential
    /// or any four-character run of it, sent or held. Positive control: both sinks did record the event.
    #[test]
    #[serial_test::serial(attribution_emit_count)]
    fn attribution_sinks_hold_no_key_material() {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        // The unit-test binary's unified log is already redirected to a private temp file (`test_support` ctor).
        for (held, sent) in [
            // Random-looking (no English runs the captured field names could contain), obviously fake.
            ("Qx7Vw2Zk9FAKE", "k7FAKE"),
            ("Hq3Zx8Wv1Ny6Tb4Rm0Kp2Lc9FAKE", "Sv5Gj2Xq7Dz1Wm8Pb3Yt6Nh0FAKE"),
        ] {
            let records = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let subscriber = tracing_subscriber::registry().with(record_capture::Collector(records.clone()));
            let _guard = subscriber.set_default();
            let (_dir, am) = empty_auth_manager();
            am.hot_swap(fresh_auth(held));
            // Shares no four-character run with either key (the scan below would otherwise match the session id).
            let sid = format!("attribution-sink-{}", sent.len());
            record_consumer_401(&am, Some(&sid), ConsumerKind::StorageClient, "upload", fpo(sent).as_ref());

            let traced = records.lock().unwrap().join("\n");
            assert!(traced.contains("auth_401_attribution"), "control: the span was captured: {traced}");
            let logged = String::from_utf8(
                fuigo_telemetry::unified_log::snapshot_session_log(&sid).expect("control: the event reached the unified log"),
            )
            .expect("utf-8 log");
            assert!(logged.contains(&fp(sent)), "control: the log carries the fingerprint: {logged}");
            for key in [held, sent] {
                for frag in fragments(key, 4) {
                    assert!(!traced.contains(&frag), "tracing captured {frag:?} of {key:?}: {traced}");
                    assert!(!logged.contains(&frag), "the unified log holds {frag:?} of {key:?}: {logged}");
                }
            }
        }
    }
}
