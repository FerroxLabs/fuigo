//! P42: session-token delivery has one predicate.
//!
//! Every path that can put the session bearer on the wire decides the
//! destination with [`session_may_reach`], which is
//! [`AuthBackend::may_receive_session`] for the active backend (for Fuigo:
//! `is_fuigo_api_bearer_url` — a configured `[endpoints]` origin, `https`
//! only, never loopback). `ModelByok::NotByok` / `Unknown` decide only whether
//! the session token is *wanted*; they never decide where it may go.
//!
//! The broad matcher `is_fuigo_api_url` (host only, any scheme or port, every
//! loopback URL) stays a *refusal* matcher — the API-key kill switch uses it to
//! refuse a key — and must not decide delivery.
//!
//! A session token can also sit in a buffer (`fuigo_chat_state::Credentials`,
//! a subagent's inherited seed) after the destination it was resolved for has
//! changed. [`withhold_session_bearer`] re-checks such a buffered key against
//! the destination the request is about to go to.

use crate::auth::backend::{ActiveAuthBackend, AuthBackend};
use crate::auth::manager::AuthManager;

/// The single delivery predicate: may the session bearer be attached to a
/// request for `url`?
pub(crate) fn session_may_reach(url: &str) -> bool {
    AuthBackend::may_receive_session(&ActiveAuthBackend::default(), url)
}

/// Whether `auth` is a session credential (OIDC / external / legacy web login) rather than a static API key
/// held by the `AuthManager` (`AuthMode::ApiKey`, e.g. `fuigo login --api-key` or inline `FUIGO_AUTH`).
/// Only session credentials are subject to [`session_may_reach`]; a static key keeps its own rules.
pub(crate) fn is_session_credential(auth: &crate::auth::FuigoAuth) -> bool {
    !matches!(auth.auth_mode, crate::auth::AuthMode::ApiKey)
}

/// Send-time re-check of a buffered credential against the current
/// destination `url`.
///
/// Returns `key` unchanged unless it is a session bearer of `auth_manager`
/// (recognised by value, see [`AuthManager::is_session_bearer`]) and `url` may
/// not receive the session — then `None`, and the request goes out with no
/// credential (the endpoint answers 401, which is the intended outcome).
///
/// A non-session key (per-model BYOK key, auth-provider token, `FUIGO_API_KEY`,
/// deployment key) is never touched: its own delivery rules were applied when
/// it was resolved.
pub(crate) fn withhold_session_bearer(
    key: Option<String>,
    url: &str,
    auth_manager: Option<&AuthManager>,
    site: &'static str,
) -> Option<String> {
    let k = key?;
    let Some(am) = auth_manager else {
        return Some(k);
    };
    if !am.is_session_bearer(&k) || session_may_reach(url) {
        return Some(k);
    }
    tracing::warn!(
        site,
        base_url = %fuigo_auth::redact_url(url),
        "the session credential was withheld at send time: this destination may not receive \
         the session token. Set `[endpoints].fuigo_api_base_url` to an https origin for it, \
         or give the model its own `api_key`/`env_key`."
    );
    fuigo_telemetry::unified_log::warn(
        "auth: buffered session credential withheld from a destination that may not receive it",
        None,
        Some(serde_json::json!({ "site": site, "base_url": url })),
    );
    None
}

// ── P47: the service-endpoint trust class ────────────────────────────────

/// The service-endpoint trust class's one predicate, as `fuigo-shell` asks it: may the session token go to the
/// auxiliary-service URL `url`? See `fuigo_extra_ca::service_trust` for the rule. The configured-API-origin
/// tier is [`session_may_reach`] (P42), so every origin that may receive the session for inference may receive
/// it for a service call too; `configured_service_base` is the calling client's own configured base.
pub(crate) fn session_may_reach_service(
    url: &str,
    configured_service_base: Option<&str>,
) -> Result<(), fuigo_extra_ca::service_trust::RefusedServiceDestination> {
    fuigo_extra_ca::service_trust::session_may_reach_service(
        url,
        configured_service_base,
        session_may_reach,
    )
}

/// Record a refusal (always-on unified log plus `warn`), naming only the origin and the reason.
pub(crate) fn record_service_refusal(
    site: &'static str,
    refused: &fuigo_extra_ca::service_trust::RefusedServiceDestination,
) {
    tracing::warn!(
        site,
        origin = %refused.origin,
        reason = refused.reason_label(),
        message = %refused,
        "auth: service request not sent: the session credential may not go to this destination"
    );
    fuigo_telemetry::unified_log::warn(
        "auth: service request not sent: the session credential may not go to this destination",
        None,
        Some(serde_json::json!({
            "site": site,
            "origin": refused.origin,
            "reason": refused.reason_label(),
            "message": refused.to_string(),
        })),
    );
}

/// Whether `bearer` is, by value, the static `AuthMode::ApiKey` credential `auth_manager` currently holds (P47's
/// exemption: not a session token). Anything else, including a value the manager no longer holds, is treated as a
/// session token.
pub(crate) fn is_held_static_key(auth_manager: &AuthManager, bearer: &str) -> bool {
    auth_manager
        .current_or_expired()
        .is_some_and(|auth| !is_session_credential(&auth) && auth.key == bearer)
}

/// The gate for a direct service client holding a resolved credential: `Ok(())` when `auth` may be attached to a
/// request for `url`. A static `AuthMode::ApiKey` credential is not a session token and keeps its own rules; every
/// session credential is checked by [`session_may_reach_service`]. On `Err` the caller must not send the request.
pub(crate) fn service_session_gate(
    auth: &crate::auth::FuigoAuth,
    url: &str,
    configured_service_base: Option<&str>,
    site: &'static str,
) -> Result<(), fuigo_extra_ca::service_trust::RefusedServiceDestination> {
    if !is_session_credential(auth) {
        return Ok(());
    }
    service_session_url_gate(url, configured_service_base, site)
}

/// [`service_session_gate`] for a bearer already known to be a session token (or one that must be treated as one:
/// a raw token with no `AuthManager` to classify it).
pub(crate) fn service_session_url_gate(
    url: &str,
    configured_service_base: Option<&str>,
    site: &'static str,
) -> Result<(), fuigo_extra_ca::service_trust::RefusedServiceDestination> {
    session_may_reach_service(url, configured_service_base).inspect_err(|refused| {
        record_service_refusal(site, refused);
    })
}

/// The refusal text when `error` is the auth middleware declining to send a request (P47), so a client can
/// surface it verbatim instead of as a transport failure.
pub(crate) fn bearer_refusal_text(error: &reqwest_middleware::Error) -> Option<String> {
    fuigo_auth::find_bearer_refusal(error).map(|refused| refused.0.clone())
}

/// A `fuigo_auth::BearerDestination` that checks every destination with [`session_may_reach_service`].
pub(crate) fn service_bearer_destination(
    configured_service_base: Option<String>,
    site: &'static str,
) -> fuigo_auth::BearerDestination {
    fuigo_auth::BearerDestination::Checked(std::sync::Arc::new(move |url: &reqwest::Url| {
        service_session_url_gate(url.as_str(), configured_service_base.as_deref(), site)
            .map_err(|refused| fuigo_auth::BearerDestinationRefused(refused.to_string()))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthMode, FuigoAuth, FuigoComConfig};

    fn auth(key: &str, mode: AuthMode) -> FuigoAuth {
        FuigoAuth {
            key: key.into(),
            auth_mode: mode,
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            ..FuigoAuth::test_default()
        }
    }

    /// Audit M3/M4: the registry recognises every session bearer ever held (rotated-out ones too, with no
    /// eviction), and never a static `AuthMode::ApiKey` credential.
    #[test]
    fn the_registry_knows_session_bearers_by_value_and_never_static_keys() {
        let dir = tempfile::tempdir().unwrap();
        let am = AuthManager::new(dir.path(), FuigoComConfig::default());
        am.hot_swap(auth("p42-first-session", AuthMode::Oidc));
        for i in 0..5000 {
            am.hot_swap(auth(&format!("p42-rotation-{i}"), AuthMode::External));
        }
        assert!(am.is_session_bearer("p42-first-session"), "a rotated-out bearer must stay recognised");
        assert!(am.is_session_bearer("p42-rotation-4999"));
        am.hot_swap(auth("p42-static-api-key", AuthMode::ApiKey));
        assert!(!am.is_session_bearer("p42-static-api-key"), "a static API key is not a session token");
        assert!(!am.is_session_bearer("p42-never-held"));
        assert!(!am.is_session_bearer(""));

        crate::agent::config::Config::install_test_trusted_origins();
        let refused = "http://127.0.0.1:9/v1";
        assert_eq!(
            withhold_session_bearer(Some("p42-static-api-key".into()), refused, Some(&am), "test"),
            Some("p42-static-api-key".into())
        );
        assert_eq!(
            withhold_session_bearer(Some("p42-first-session".into()), refused, Some(&am), "test"),
            None
        );
        assert_eq!(
            withhold_session_bearer(
                Some("p42-first-session".into()),
                "https://api.fluxrouter.ai/v1",
                Some(&am),
                "test"
            ),
            Some("p42-first-session".into())
        );
    }
}
