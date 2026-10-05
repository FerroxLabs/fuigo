//! Pure-data OIDC refresh: talks to the IdP and returns [`OidcRefreshResult`] without touching [`AuthManager`].

use super::super::FuigoAuth;
use super::protocol::{OidcError, OidcUserInfo, build_fuigo_auth, discover, refresh_tokens};
use crate::auth::error::RefreshTokenFailedReason;

/// Outcome of a pure OIDC token refresh (no AuthManager mutations).
pub(crate) enum OidcRefreshResult {
    /// Fresh token obtained. Caller must persist.
    Success(Box<FuigoAuth>),
    /// Terminal error from the IdP, already classified into a reason.
    TerminalError { reason: RefreshTokenFailedReason },
    /// Non-terminal failure (discovery failed, network error, etc.)
    ///
    /// `network_unreachable` is `true` when the failure never reached the IdP (DNS resolution, TCP connect, request timeout).
    /// That is the canonical shape of the first seconds after wake-from-sleep.
    /// Such failures prove nothing about the credential, so `OidcRefresher`'s transient-to-permanent escalation budget must not count them.
    Failed { network_unreachable: bool },
    /// The token endpoint was refused by local policy (P99): the discovery document named one the refresh token
    /// must not go to (nothing was sent), or the admitted endpoint answered with a redirect that is not followed
    /// (the token was not sent outside the admitted endpoint's origin). Neither says anything about the
    /// credential: the caller keeps it, does not count the attempt toward escalation, and surfaces `message`.
    Refused { message: String },
}

/// Classify an OAuth2 `error` code as a terminal refresh failure; `None` means non-terminal (retryable).
/// Single source of truth for which codes are fatal; the retry gate (`protocol::is_transient_refresh_error`) defers to this too.
pub(super) fn classify_terminal(error_code: &str) -> Option<RefreshTokenFailedReason> {
    match error_code {
        "invalid_grant" => Some(RefreshTokenFailedReason::RefreshTokenRejected),
        "invalid_client" => Some(RefreshTokenFailedReason::ClientRejected),
        _ => None,
    }
}

/// Conservative client-side bound (ms) on how long an IdP may still accept a refresh token it has already rotated.
/// A clock divergence past this bound means the exchange straddled a suspend too long.
/// A lost response then can no longer be recovered by re-presenting the old RT.
const ROTATION_GRACE_MS: u64 = 60_000;

/// Dual-clock suspend probe around an IdP exchange.
/// The monotonic clock pauses during suspend and the wall clock does not, so their divergence measures time suspended since [`Self::start`].
/// Feeds `suspended_ms` telemetry and stops in-call retries once a straddle exceeds the rotation grace.
/// Re-sending the RT then trips the IdP's reuse detection and revokes a successor a sibling may hold.
pub(super) struct SuspendProbe {
    mono: std::time::Instant,
    wall: chrono::DateTime<chrono::Utc>,
}

impl SuspendProbe {
    pub(super) fn start() -> Self {
        Self {
            mono: std::time::Instant::now(),
            wall: chrono::Utc::now(),
        }
    }

    /// `(monotonic_ms, wall_ms)` elapsed since [`Self::start`].
    fn elapsed_ms(&self) -> (u64, u64) {
        let mono_ms = self.mono.elapsed().as_millis() as u64;
        let wall_ms = (chrono::Utc::now() - self.wall).num_milliseconds().max(0) as u64;
        (mono_ms, wall_ms)
    }

    /// Milliseconds the machine spent suspended since [`Self::start`].
    pub(super) fn suspended_ms(&self) -> u64 {
        let (mono_ms, wall_ms) = self.elapsed_ms();
        wall_ms.saturating_sub(mono_ms)
    }

    /// `true` once the exchange has straddled a suspend past the rotation grace.
    pub(super) fn straddled_past_grace(&self) -> bool {
        self.suspended_ms() > ROTATION_GRACE_MS
    }
}

/// `true` when `err`'s chain shows the request never reached the server: DNS failure, TCP connect failure, or timeout.
/// Used to mark [`OidcRefreshResult::Failed::network_unreachable`].
fn is_network_unreachable(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<reqwest::Error>()
            .is_some_and(|re| re.is_connect() || re.is_timeout())
    })
}

/// Exchange a refresh_token for fresh tokens at the IdP.
/// Pure data return, no `AuthManager` mutations; the caller (`OidcRefresher`) routes the result through `refresh_chain`.
pub(crate) async fn oidc_token_exchange(auth: &FuigoAuth) -> OidcRefreshResult {
    let has_rt = auth.refresh_token.is_some();
    let has_issuer = auth.oidc_issuer.is_some();
    let has_client_id = auth.oidc_client_id.is_some();
    tracing::debug!(
        has_rt,
        has_issuer,
        has_client_id,
        "oidc try_refresh_pure enter"
    );
    if !has_rt || !has_issuer || !has_client_id {
        fuigo_telemetry::unified_log::warn(
            "oidc try_refresh skipped: missing fields",
            None,
            Some(serde_json::json!({
                "has_refresh_token": has_rt,
                "has_issuer": has_issuer,
                "has_client_id": has_client_id,
                "auth_mode": format!("{:?}", auth.auth_mode),
            })),
        );
    }
    let Some(refresh_tok) = auth.refresh_token.as_ref() else {
        return OidcRefreshResult::Failed {
            network_unreachable: false,
        };
    };
    let Some(issuer) = auth.oidc_issuer.as_ref() else {
        return OidcRefreshResult::Failed {
            network_unreachable: false,
        };
    };
    let Some(client_id) = auth.oidc_client_id.as_ref() else {
        return OidcRefreshResult::Failed {
            network_unreachable: false,
        };
    };

    crate::unified_log::info(
        "oidc try_refresh_pure enter",
        None,
        Some(serde_json::json!({ "issuer": issuer, "client_id": client_id })),
    );

    // A large mono/wall divergence around the IdP call means the process was suspended mid-refresh
    // That is the condition that can revoke the refresh token (response lost across sleep). See [`SuspendProbe`].
    let probe = SuspendProbe::start();
    let timing = || {
        let (mono_ms, wall_ms) = probe.elapsed_ms();
        (
            mono_ms,
            wall_ms,
            probe.suspended_ms(),
            probe.straddled_past_grace(),
        )
    };

    let discovery = match discover(issuer).await {
        Ok(d) => d,
        Err(e) => {
            let network_unreachable = is_network_unreachable(&e);
            let (mono_ms, wall_ms, suspended_ms, suspected_suspend) = timing();
            crate::unified_log::error(
                "oidc try_refresh_pure discovery failed",
                None,
                Some(serde_json::json!({
                    "error": format!("{e:#}"),
                    "network_unreachable": network_unreachable,
                    "mono_ms": mono_ms,
                    "wall_ms": wall_ms,
                    "suspended_ms": suspended_ms,
                    "suspected_suspend": suspected_suspend,
                })),
            );
            if suspected_suspend {
                emit_suspend_spanned("discovery_failed", suspended_ms);
            }
            return OidcRefreshResult::Failed {
                network_unreachable,
            };
        }
    };
    let tokens = match refresh_tokens(
        issuer,
        &discovery.token_endpoint,
        refresh_tok,
        client_id,
        auth.principal_type.as_deref(),
        auth.principal_id.as_deref(),
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            if let Some(OidcError::TokenEndpointRefused(reason)) = e.downcast_ref::<OidcError>() {
                crate::unified_log::error(
                    "oidc try_refresh_pure token endpoint refused",
                    None,
                    Some(serde_json::json!({ "reason": reason, "client_id": client_id })),
                );
                tracing::warn!(
                    reason = %reason,
                    client_id = %client_id,
                    issuer = %issuer,
                    "OIDC: token endpoint refused"
                );
                return OidcRefreshResult::Refused {
                    message: format!("{reason}. Your stored sign-in is kept"),
                };
            }
            if let Some(OidcError::TokenRefreshHttp { body, .. }) = e.downcast_ref::<OidcError>()
                && let Some(error_code) = serde_json::from_str::<serde_json::Value>(body)
                    .ok()
                    .and_then(|v| v.get("error")?.as_str().map(str::to_owned))
                && let Some(reason) = classify_terminal(&error_code)
            {
                let (mono_ms, wall_ms, suspended_ms, suspected_suspend) = timing();
                let cred_age_secs = auth.mint_age_seconds();
                crate::unified_log::error(
                    "oidc try_refresh_pure terminal error",
                    None,
                    Some(serde_json::json!({
                        "error_code": error_code,
                        "client_id": client_id,
                        "tried_rt_prefix": auth.refresh_token.as_deref().map(fuigo_auth::bearer_fingerprint),
                        "error_description": serde_json::from_str::<serde_json::Value>(body)
                            .ok()
                            .and_then(|v| v.get("error_description").cloned()),
                        "mono_ms": mono_ms,
                        "wall_ms": wall_ms,
                        "suspended_ms": suspended_ms,
                        "suspected_suspend": suspected_suspend,
                        "cred_age_secs": cred_age_secs,
                    })),
                );
                if suspected_suspend {
                    emit_suspend_spanned(&error_code, suspended_ms);
                }
                return OidcRefreshResult::TerminalError { reason };
            }
            let http_status = e.downcast_ref::<OidcError>().and_then(|oe| match oe {
                OidcError::TokenRefreshHttp { status, .. } => Some(*status),
                _ => None,
            });
            let network_unreachable = is_network_unreachable(&e);
            let (mono_ms, wall_ms, suspended_ms, suspected_suspend) = timing();
            crate::unified_log::error(
                "oidc try_refresh_pure token exchange failed",
                None,
                Some(serde_json::json!({
                    "error": e.to_string(),
                    "client_id": client_id,
                    "http_status": http_status,
                    "network_unreachable": network_unreachable,
                    "mono_ms": mono_ms,
                    "wall_ms": wall_ms,
                    "suspended_ms": suspended_ms,
                    "suspected_suspend": suspected_suspend,
                })),
            );
            tracing::warn!(
                error = %e,
                http_status = ?http_status,
                client_id = %client_id,
                issuer = %issuer,
                "OIDC: token refresh failed"
            );
            if suspected_suspend {
                emit_suspend_spanned("transient_failed", suspended_ms);
            }
            return OidcRefreshResult::Failed {
                network_unreachable,
            };
        }
    };

    // Reuse identity from original login; new id_token from refresh is intentionally skipped.
    let user_info = OidcUserInfo {
        user_id: auth.user_id.clone(),
        email: auth.email.clone(),
        first_name: auth.first_name.clone(),
        last_name: auth.last_name.clone(),
        profile_image_asset_id: auth.profile_image_asset_id.clone(),
        principal_type: auth.principal_type.clone(),
        principal_id: auth.principal_id.clone(),
        team_id: auth.team_id.clone(),
        team_name: auth.team_name.clone(),
        team_role: auth.team_role.clone(),
        organization_id: auth.organization_id.clone(),
        organization_name: auth.organization_name.clone(),
        organization_role: auth.organization_role.clone(),
        user_blocked_reason: auth.user_blocked_reason.clone(),
        team_blocked_reasons: auth.team_blocked_reasons.clone(),
        coding_data_retention_opt_out: auth.coding_data_retention_opt_out,
    };
    let mut new_auth = build_fuigo_auth(tokens, user_info, issuer, client_id);
    let idp_rotated = new_auth.refresh_token.is_some();
    // Keep old refresh token if IdP didn't rotate it
    if new_auth.refresh_token.is_none() {
        new_auth.refresh_token = auth.refresh_token.clone();
    }
    tracing::debug!(
        idp_rotated,
        key_prefix = %fuigo_auth::bearer_fingerprint(&new_auth.key),
        "oidc try_refresh_pure token obtained"
    );
    let (mono_ms, wall_ms, suspended_ms, suspected_suspend) = timing();
    crate::unified_log::info(
        "oidc try_refresh_pure succeeded",
        None,
        Some(serde_json::json!({
            "expires_at": new_auth.expires_at.map(|e| e.to_rfc3339()),
            "mono_ms": mono_ms,
            "wall_ms": wall_ms,
            "suspended_ms": suspended_ms,
            "suspected_suspend": suspected_suspend,
        })),
    );
    if suspected_suspend {
        emit_suspend_spanned("ok", suspended_ms);
    }
    OidcRefreshResult::Success(Box::new(new_auth))
}

/// Alertable event: an OIDC refresh's network call spanned a suspend (wall clock ran far ahead of the monotonic clock).
/// That is the precondition for a refresh-token revocation caused by a lost response.
fn emit_suspend_spanned(outcome: &str, suspended_ms: u64) {
    crate::unified_log::warn(
        "auth.refresh.suspend_spanned",
        None,
        Some(serde_json::json!({
            "outcome": outcome,
            "suspended_ms": suspended_ms,
        })),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthMode;
    use std::sync::Arc;

    type Bodies = Arc<parking_lot::Mutex<Vec<String>>>;

    /// A recipient that is NOT the issuer: records every request body and answers like a
    /// token endpoint, so a refresh that reaches it both succeeds and is recorded.
    async fn spawn_collector() -> (String, Bodies, tokio::task::JoinHandle<()>) {
        let bodies = Bodies::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = axum::Router::new().fallback({
            let bodies = bodies.clone();
            move |body: String| {
                bodies.lock().push(body);
                async {
                    axum::Json(serde_json::json!({
                        "access_token": "collector-access",
                        "refresh_token": "collector-refresh",
                        "expires_in": 3600,
                    }))
                }
            }
        });
        let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (base, bodies, handle)
    }

    fn stored_auth(issuer: &str) -> FuigoAuth {
        FuigoAuth {
            key: "stored-access".into(),
            auth_mode: AuthMode::Oidc,
            oidc_issuer: Some(issuer.into()),
            oidc_client_id: Some("test-client".into()),
            refresh_token: Some("stored-refresh".into()),
            expires_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
            ..FuigoAuth::test_default()
        }
    }

    /// P99, production path (`oidc_token_exchange` over the shared client): a discovery
    /// document naming a token endpoint on another origin gets no refresh token. That
    /// origin is never contacted and no new credential is produced.
    #[tokio::test]
    async fn refresh_token_never_goes_to_a_token_endpoint_off_the_issuer_origin() {
        let (foreign, bodies, collector) = spawn_collector().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let authorize = format!("{issuer}/authorize");
        let app = axum::Router::new().route(
            "/.well-known/openid-configuration",
            axum::routing::get(move || {
                let document = serde_json::json!({
                    "authorization_endpoint": authorize,
                    "token_endpoint": format!("{foreign}/token"),
                });
                async move { axum::Json(document) }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let result = oidc_token_exchange(&stored_auth(&issuer)).await;
        server.abort();
        collector.abort();
        let bodies = bodies.lock().clone();
        assert!(
            bodies.is_empty(),
            "the foreign token endpoint was contacted: {bodies:?}"
        );
        assert!(
            !matches!(result, OidcRefreshResult::Success(_)),
            "a refresh through a foreign token endpoint produced a credential"
        );
        // The refusal is its own outcome, with the reason and what happened to the credential.
        match result {
            OidcRefreshResult::Refused { message } => {
                assert!(message.contains("issuer's origin"), "{message}");
                assert!(message.contains("nothing was sent"), "{message}");
                assert!(message.contains("stored sign-in is kept"), "{message}");
                assert!(
                    !message.contains("127.0.0.1") && !message.contains("stored-refresh"),
                    "the message must not echo the URL or the token: {message}"
                );
            }
            OidcRefreshResult::Success(_) => unreachable!(),
            OidcRefreshResult::TerminalError { reason } => {
                panic!("a refusal is not an IdP verdict: {reason:?}")
            }
            OidcRefreshResult::Failed { .. } => panic!("a refusal must be reported as one"),
        }
    }

    /// P99, production path: a token endpoint on the issuer's origin that answers 307/308
    /// to another origin does not get the refresh-token form replayed there.
    #[tokio::test]
    async fn refresh_token_is_not_replayed_across_a_cross_origin_redirect() {
        for status in [
            axum::http::StatusCode::TEMPORARY_REDIRECT,
            axum::http::StatusCode::PERMANENT_REDIRECT,
        ] {
            let (foreign, bodies, collector) = spawn_collector().await;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let issuer = format!("http://{}", listener.local_addr().unwrap());
            let document = serde_json::json!({
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
            });
            // Proves the issuer's own endpoint WAS reached with the token, so a refresh that
            // failed earlier cannot pass for a refused redirect.
            let posted = Bodies::default();
            let app = axum::Router::new()
                .route(
                    "/.well-known/openid-configuration",
                    axum::routing::get(move || {
                        let document = document.clone();
                        async move { axum::Json(document) }
                    }),
                )
                .route(
                    "/token",
                    axum::routing::post({
                        let posted = posted.clone();
                        move |body: String| {
                            posted.lock().push(body);
                            let location = format!("{foreign}/collect");
                            async move { (status, [(axum::http::header::LOCATION, location)]) }
                        }
                    }),
                );
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let result = oidc_token_exchange(&stored_auth(&issuer)).await;
            server.abort();
            collector.abort();
            let posted = posted.lock().clone();
            assert!(
                !posted.is_empty(),
                "{status}: the token endpoint was never reached"
            );
            assert!(
                posted
                    .iter()
                    .all(|body| body.contains("refresh_token=stored-refresh")),
                "{status}: {posted:?}"
            );
            let bodies = bodies.lock().clone();
            assert!(
                bodies.is_empty(),
                "{status}: the refresh token was replayed to another origin: {bodies:?}"
            );
            assert!(
                !matches!(result, OidcRefreshResult::Success(_)),
                "{status}: a redirect is not a token response"
            );
            // A refused redirect is a refusal: sent once (no retries against the issuer), reported with
            // the reason, and not as a failure that counts against the credential.
            assert_eq!(posted.len(), 1, "{status}: {posted:?}");
            match result {
                OidcRefreshResult::Refused { message } => {
                    assert!(
                        message.contains("a redirect that Fuigo does not follow"),
                        "{status}: {message}"
                    );
                    assert!(
                        message.contains("not sent outside the token endpoint's origin"),
                        "{status}: {message}"
                    );
                    assert!(
                        message.contains("stored sign-in is kept"),
                        "{status}: {message}"
                    );
                    assert!(
                        !message.contains("127.0.0.1") && !message.contains("stored-refresh"),
                        "{status}: the message must not echo a URL or the token: {message}"
                    );
                }
                OidcRefreshResult::Success(_) => unreachable!(),
                OidcRefreshResult::TerminalError { reason } => {
                    panic!("{status}: a refusal is not an IdP verdict: {reason:?}")
                }
                OidcRefreshResult::Failed { .. } => {
                    panic!("{status}: a refused redirect must be reported as a refusal")
                }
            }
        }
    }

    /// P99 (Astra r2): a token endpoint that redirects to itself is followed only on its own origin,
    /// up to the client's hop limit, and then reported as a loop. It is not retried from the start.
    #[tokio::test]
    async fn a_same_origin_redirect_loop_is_reported_as_one() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let document = serde_json::json!({
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
        });
        let posted = Bodies::default();
        let app = axum::Router::new()
            .route(
                "/.well-known/openid-configuration",
                axum::routing::get(move || {
                    let document = document.clone();
                    async move { axum::Json(document) }
                }),
            )
            .route(
                "/token",
                axum::routing::post({
                    let posted = posted.clone();
                    move |body: String| {
                        posted.lock().push(body);
                        async {
                            (
                                axum::http::StatusCode::TEMPORARY_REDIRECT,
                                [(axum::http::header::LOCATION, "/token")],
                            )
                        }
                    }
                }),
            );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let result = oidc_token_exchange(&stored_auth(&issuer)).await;
        server.abort();
        let posted = posted.lock().len();
        // One pass through the hop limit (11 requests in `fuigo_extra_ca`), not three.
        assert!((2..=12).contains(&posted), "{posted} requests");
        match result {
            OidcRefreshResult::Refused { message } => {
                assert!(message.contains("redirected too many times"), "{message}");
                assert!(message.contains("stored sign-in is kept"), "{message}");
            }
            _ => panic!("a redirect loop must be reported as a refusal"),
        }
    }
}
