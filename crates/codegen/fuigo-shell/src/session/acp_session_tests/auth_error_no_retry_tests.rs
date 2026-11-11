use super::support::*;
use super::*;
use crate::auth::{AuthManager, AuthMode, FuigoAuth, FuigoComConfig};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;

/// Test refresher that returns a fresh token and records that it was invoked.
/// Used to drive the auth-arm success path.
struct AlwaysSucceedRefresher {
    called: Arc<AtomicBool>,
}
#[async_trait::async_trait]
impl crate::auth::refresh::TokenRefresher for AlwaysSucceedRefresher {
    async fn refresh(
        &self,
        _reason: crate::auth::refresh::RefreshReason,
    ) -> crate::auth::refresh::RefreshOutcome {
        self.called.store(true, Ordering::SeqCst);
        crate::auth::refresh::RefreshOutcome::Success(Box::new(FuigoAuth {
            key: "refreshed-test-token".to_string(),
            auth_mode: AuthMode::Oidc,
            refresh_token: Some("rt-new".into()),
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            ..FuigoAuth::test_default()
        }))
    }
}

/// Test refresher that always fails transiently — the shape of a sleep-gate
/// deferral ("refresh deferred: system sleep imminent") or a network blip.
struct AlwaysTransientFailRefresher {
    called: Arc<AtomicBool>,
}
#[async_trait::async_trait]
impl crate::auth::refresh::TokenRefresher for AlwaysTransientFailRefresher {
    async fn refresh(
        &self,
        _reason: crate::auth::refresh::RefreshReason,
    ) -> crate::auth::refresh::RefreshOutcome {
        self.called.store(true, Ordering::SeqCst);
        crate::auth::refresh::RefreshOutcome::TransientFailure {
            message: "refresh deferred: system sleep imminent".to_string(),
        }
    }
}

/// `(tempdir, manager)` with an expired OIDC token loaded so `unauthorized_recovery()` actually dispatches to the refresher.
/// Tempdir must outlive the manager (auth.json path).
fn auth_manager_with_refresher(
    refresher: Arc<dyn crate::auth::refresh::TokenRefresher>,
) -> (tempfile::TempDir, Arc<AuthManager>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let am = Arc::new(AuthManager::new(dir.path(), FuigoComConfig::default()));
    am.hot_swap(FuigoAuth {
        key: "initial-test-key".into(),
        auth_mode: AuthMode::Oidc,
        refresh_token: Some("rt".into()),
        expires_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
        ..FuigoAuth::test_default()
    });
    am.set_refresher(refresher);
    (dir, am)
}

/// Build a `SamplingErrorInfo` of kind Auth, the same shape the inner `OaiCompatClient` reports after recording its own attribution.
fn auth_error() -> fuigo_sampler::SamplingErrorInfo {
    fuigo_sampler::SamplingErrorInfo {
        kind: fuigo_sampler::SamplingErrorKind::Auth,
        message: "Unauthorized (401)".to_string(),
        status_code: Some(401),
        is_retryable: false,
        retry_after_secs: None,
        should_retry: None,
        error_code: None,
        upstream_state: None,
        upstream_type: None,
        upstream_details: Default::default(),
        model_metadata: None,
        empty_response_context: None,
        doom_loop_triggers: None,
        doom_loop_aborted_at_chunk: None,
        credential: fuigo_sampling_types::SentCredential::Unknown,
    }
}

/// [`auth_error`] with the wire-credential provenance pinned.
fn auth_error_with_credential(
    credential: fuigo_sampling_types::SentCredential,
) -> fuigo_sampler::SamplingErrorInfo {
    fuigo_sampler::SamplingErrorInfo {
        credential,
        upstream_details: fuigo_sampling_types::error::UpstreamError {
            flux_routed: true, ..Default::default()
        }.with_body(401, br#"{"error":{"message":"Unauthorized"}}"#),
        ..auth_error()
    }
}

/// Construct a test actor with the supplied `auth_manager` and session-token credentials wired in.
/// Wraps the actor in `Arc` ready for `handle_sampling_failure`.
async fn make_actor_with_auth_manager(
    auth_manager: Option<Arc<AuthManager>>,
) -> (Arc<SessionActor>, mpsc::UnboundedReceiver<PersistenceMsg>) {
    make_actor_with_auth_and_credentials(
        auth_manager,
        fuigo_chat_state::AuthType::SessionToken,
        "initial-test-key".to_string(),
    )
    .await
}

/// Variant that pins the credential `auth_type`; the `auth_method_id` is derived from it.
/// Use [`make_actor_with_method_and_credentials`] to pin the two independently.
async fn make_actor_with_auth_and_credentials(
    auth_manager: Option<Arc<AuthManager>>,
    auth_type: fuigo_chat_state::AuthType,
    api_key: String,
) -> (Arc<SessionActor>, mpsc::UnboundedReceiver<PersistenceMsg>) {
    let method_id = match auth_type {
        fuigo_chat_state::AuthType::SessionToken => "cached_token",
        fuigo_chat_state::AuthType::ApiKey => "fuigo.api_key",
    };
    make_actor_with_method_and_credentials(auth_manager, method_id, auth_type, api_key).await
}

/// Pin the ACP `auth_method_id` and credential `auth_type` independently.
/// The gate keys off the stable `auth_method_id`, so this reproduces the regression.
/// In the regression, a session-token cache miss with `FUIGO_API_KEY` set transiently collapsed a session method's `creds.auth_type` to `ApiKey`.
async fn make_actor_with_method_and_credentials(
    auth_manager: Option<Arc<AuthManager>>,
    auth_method_id: &str,
    auth_type: fuigo_chat_state::AuthType,
    api_key: String,
) -> (Arc<SessionActor>, mpsc::UnboundedReceiver<PersistenceMsg>) {
    let (actor, rx) = make_actor_parts_with_method_and_credentials(
        auth_manager,
        auth_method_id,
        auth_type,
        api_key,
    )
    .await;
    (Arc::new(actor), rx)
}

/// [`make_actor_with_method_and_credentials`] before the `Arc` wrap, for tests that pin actor fields (e.g. the park kill switch).
async fn make_actor_parts_with_method_and_credentials(
    auth_manager: Option<Arc<AuthManager>>,
    auth_method_id: &str,
    auth_type: fuigo_chat_state::AuthType,
    api_key: String,
) -> (SessionActor, mpsc::UnboundedReceiver<PersistenceMsg>) {
    let (gateway_tx, _) = mpsc::unbounded_channel();
    let (persistence_tx, persistence_rx) = mpsc::unbounded_channel();
    let mut actor = create_test_actor(50_000, 100_000, 85, gateway_tx, persistence_tx).await;
    actor.auth_manager = auth_manager;
    actor.auth_method_id = test_auth_method_id(auth_method_id);
    // P42: these tests exercise session refresh/recovery mechanics, so the destination must be one that may
    // receive the session token. The shared fixture's `http://localhost` only qualified under the broad matcher.
    crate::agent::config::Config::install_test_trusted_origins();
    if let Some(mut cfg) = actor.chat_state_handle.get_sampling_config().await {
        cfg.base_url = P42_CONFIGURED_ORIGIN.to_string();
        actor.chat_state_handle.update_sampling_config(cfg);
    }
    actor
        .chat_state_handle
        .update_credentials(fuigo_chat_state::Credentials {
            api_key: Some(api_key),
            auth_type,
            ..Default::default()
        });
    (actor, persistence_rx)
}

/// `(tempdir, manager)` holding a valid OIDC token (so `get_valid_token()` is a cache hit).
/// The tempdir must outlive the manager (auth.json path).
fn auth_manager_with_valid_token(key: &str) -> (tempfile::TempDir, Arc<AuthManager>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let am = Arc::new(AuthManager::new(dir.path(), FuigoComConfig::default()));
    am.hot_swap(FuigoAuth {
        key: key.into(),
        auth_mode: AuthMode::Oidc,
        refresh_token: Some("rt".into()),
        expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        ..FuigoAuth::test_default()
    });
    (dir, am)
}

/// Sub-case 1: with no auth_manager the handler falls through and emits no attribution.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(attribution_emit_count)]
async fn no_emit_when_auth_manager_is_none() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = make_actor_with_auth_manager(None).await;
            crate::auth::attribution::reset_test_emit_count();
            let _ = actor
                .handle_sampling_failure(
                    auth_error(),
                    0,
                    transient_state(0, true),
                    false,
                    TurnParkState::Fresh,
                )
                .await;
            assert_eq!(
                crate::auth::attribution::test_emit_count(),
                0,
                "auth arm must not emit attribution when no auth_manager is wired"
            );
        })
        .await;
}

/// Sub-case 2: with no AuthManager, auth recovery is skipped entirely and the 401 falls through to a terminal error.
/// Covers BYOK / API-key users where no OIDC refresh is possible.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(attribution_emit_count)]
async fn no_recovery_without_auth_manager() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = make_actor_with_auth_and_credentials(
                None,
                fuigo_chat_state::AuthType::ApiKey,
                "fuigo-byok-key".to_string(),
            )
            .await;
            crate::auth::attribution::reset_test_emit_count();
            let result = actor
                .handle_sampling_failure(
                    auth_error(),
                    0,
                    transient_state(0, true),
                    false,
                    TurnParkState::Fresh,
                )
                .await;
            assert!(
                result.is_err(),
                "no auth manager must fall through to terminal error"
            );
            assert_eq!(
                crate::auth::attribution::test_emit_count(),
                0,
                "auth arm must not emit attribution without auth manager"
            );
        })
        .await;
}

/// Session-based auth with a working refresher returns RefreshAuthAndResubmit.
#[tokio::test(flavor = "current_thread")]
async fn sampler_401_recovery_returns_refresh_and_retry() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let called = Arc::new(AtomicBool::new(false));
            let refresher: Arc<dyn crate::auth::refresh::TokenRefresher> =
                Arc::new(AlwaysSucceedRefresher {
                    called: called.clone(),
                });
            let (_dir, am) = auth_manager_with_refresher(refresher);
            let (actor, _rx) = make_actor_with_auth_manager(Some(am)).await;
            let result = actor
                .handle_sampling_failure(
                    auth_error(),
                    0,
                    transient_state(0, true),
                    false,
                    TurnParkState::Fresh,
                )
                .await;
            assert!(
                matches!(
                    result,
                    Ok(SamplerFailureRecovery::RefreshAuthAndResubmit {
                        store: RecoveredStore::SessionToken,
                        ..
                    })
                ),
                "session-based auth with a working refresher must return RefreshAuthAndResubmit"
            );
            assert!(called.load(Ordering::SeqCst), "refresher must be invoked");
        })
        .await;
}

/// Rule: a credential-less 401 with transiently-failed recovery parks on the
/// uncharged path instead of failing the turn.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(attribution_emit_count)]
async fn credential_less_401_with_deferred_refresh_parks_on_uncharged_resubmit() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let called = Arc::new(AtomicBool::new(false));
            let refresher: Arc<dyn crate::auth::refresh::TokenRefresher> =
                Arc::new(AlwaysTransientFailRefresher {
                    called: called.clone(),
                });
            let (_dir, am) = auth_manager_with_refresher(refresher);
            let (actor, _rx) = make_actor_with_auth_manager(Some(am)).await;
            let result = actor
                .handle_sampling_failure(
                    auth_error_with_credential(fuigo_sampling_types::SentCredential::Missing),
                    0,
                    transient_state(0, true),
                    false,
                    TurnParkState::Fresh,
                )
                .await;
            assert!(
                matches!(
                    result,
                    Ok(SamplerFailureRecovery::RefreshAuthAndResubmit {
                        credential: fuigo_sampling_types::SentCredential::Missing,
                        store: RecoveredStore::SessionToken,
                    })
                ),
                "credential-less 401 with self-healing deferred refresh must park on \
                 the uncharged resubmit path"
            );
            assert!(called.load(Ordering::SeqCst), "refresher must be consulted");
        })
        .await;
}

/// Rule: an already-parked credential-less 401 re-parks without touching the
/// refresher — parked cycles must not consume the shared escalation budget.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(attribution_emit_count)]
async fn parked_credential_less_401_reparks_without_recovery_dispatch() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let called = Arc::new(AtomicBool::new(false));
            let refresher: Arc<dyn crate::auth::refresh::TokenRefresher> =
                Arc::new(AlwaysTransientFailRefresher {
                    called: called.clone(),
                });
            let (_dir, am) = auth_manager_with_refresher(refresher);
            let (actor, _rx) = make_actor_with_auth_manager(Some(am)).await;
            let result = actor
                .handle_sampling_failure(
                    auth_error_with_credential(fuigo_sampling_types::SentCredential::Missing),
                    0,
                    transient_state(0, true),
                    false,
                    TurnParkState::Parked,
                )
                .await;
            assert!(
                matches!(
                    result,
                    Ok(SamplerFailureRecovery::RefreshAuthAndResubmit {
                        credential: fuigo_sampling_types::SentCredential::Missing,
                        store: RecoveredStore::SessionToken,
                    })
                ),
                "an already-parked credential-less 401 must re-park"
            );
            assert!(
                !called.load(Ordering::SeqCst),
                "a parked cycle must not dispatch a recovery refresh"
            );
        })
        .await;
}

/// Rule: a credential-less 401 on a Length-salvage continuation still parks, fresh or
/// parked — the quiet truncated-complete arm excludes `Auth` kinds, so it neither
/// completes the turn truncated nor goes terminal.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(attribution_emit_count)]
async fn mid_salvage_credential_less_401_still_parks() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            for park in [TurnParkState::Fresh, TurnParkState::Parked] {
                let called = Arc::new(AtomicBool::new(false));
                let refresher: Arc<dyn crate::auth::refresh::TokenRefresher> =
                    Arc::new(AlwaysTransientFailRefresher {
                        called: called.clone(),
                    });
                let (_dir, am) = auth_manager_with_refresher(refresher);
                let (actor, _rx) = make_actor_with_auth_manager(Some(am)).await;
                // A window the seeded estimate exceeds: only the quiet arm's
                // `Auth` exclusion keeps this 401 out of it.
                let error = fuigo_sampler::SamplingErrorInfo {
                    model_metadata: Some(fuigo_sampling_types::ResponseModelMetadata {
                        context_window: Some(1),
                        max_completion_tokens: None,
                        models_etag: None,
                    }),
                    ..auth_error_with_credential(fuigo_sampling_types::SentCredential::Missing)
                };
                let result = actor
                    .handle_sampling_failure(error, 0, transient_state(0, true), true, park)
                    .await;
                assert!(
                    matches!(
                        result,
                        Ok(SamplerFailureRecovery::RefreshAuthAndResubmit {
                            credential: fuigo_sampling_types::SentCredential::Missing,
                            store: RecoveredStore::SessionToken,
                        })
                    ),
                    "a mid-salvage credential-less 401 must park ({park:?})"
                );
                assert_eq!(
                    called.load(Ordering::SeqCst),
                    !park.is_parked(),
                    "one recovery dispatch when fresh, none when already parked ({park:?})"
                );
            }
        })
        .await;
}

/// Rule: a credentialed (or `Unknown` — fails closed) 401 stays terminal when recovery fails.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(attribution_emit_count)]
async fn credentialed_401_with_deferred_refresh_stays_terminal() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            for credential in [
                fuigo_sampling_types::SentCredential::Sent,
                fuigo_sampling_types::SentCredential::Unknown,
            ] {
                let refresher: Arc<dyn crate::auth::refresh::TokenRefresher> =
                    Arc::new(AlwaysTransientFailRefresher {
                        called: Arc::new(AtomicBool::new(false)),
                    });
                let (_dir, am) = auth_manager_with_refresher(refresher);
                let (actor, _rx) = make_actor_with_auth_manager(Some(am)).await;
                let result = actor
                    .handle_sampling_failure(
                        auth_error_with_credential(credential),
                        0,
                        transient_state(0, true),
                        false,
                        TurnParkState::Fresh,
                    )
                    .await;
                assert!(
                    result.is_err(),
                    "{credential:?} 401 with failed recovery must stay terminal"
                );
            }
        })
        .await;
}

/// Rule: kill switch off restores terminal behavior for the exact input that otherwise parks.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(attribution_emit_count)]
async fn credential_less_401_with_park_kill_switch_stays_terminal() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let refresher: Arc<dyn crate::auth::refresh::TokenRefresher> =
                Arc::new(AlwaysTransientFailRefresher {
                    called: Arc::new(AtomicBool::new(false)),
                });
            let (_dir, am) = auth_manager_with_refresher(refresher);
            let (mut actor, _rx) = make_actor_parts_with_method_and_credentials(
                Some(am),
                "cached_token",
                fuigo_chat_state::AuthType::SessionToken,
                "initial-test-key".to_string(),
            )
            .await;
            actor.uncharged_401_park_enabled = false;
            let actor = Arc::new(actor);
            let result = actor
                .handle_sampling_failure(
                    auth_error_with_credential(fuigo_sampling_types::SentCredential::Missing),
                    0,
                    transient_state(0, true),
                    false,
                    TurnParkState::Fresh,
                )
                .await;
            assert!(
                result.is_err(),
                "kill switch off: the otherwise-parking input must stay terminal"
            );
        })
        .await;
}

/// Rule: a credential-less 401 stays terminal under a provider refresh authority —
/// parking would loop on a token only an interactive flow can mint.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(attribution_emit_count)]
async fn credential_less_401_with_provider_authority_stays_terminal() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let dir = tempfile::tempdir().expect("tempdir");
            let am = Arc::new(AuthManager::new(
                dir.path(),
                FuigoComConfig {
                    auth_provider_command: Some("acme-auth".to_owned()),
                    auth_provider_label: Some("Acme SSO".to_owned()),
                    ..FuigoComConfig::default()
                },
            ));
            am.hot_swap(FuigoAuth {
                key: "expired-external".into(),
                auth_mode: AuthMode::External,
                expires_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
                ..FuigoAuth::test_default()
            });
            am.set_refresher(Arc::new(AlwaysTransientFailRefresher {
                called: Arc::new(AtomicBool::new(false)),
            }));
            let (actor, _rx) = make_actor_with_auth_manager(Some(am)).await;
            let result = actor
                .handle_sampling_failure(
                    auth_error_with_credential(fuigo_sampling_types::SentCredential::Missing),
                    0,
                    transient_state(0, true),
                    false,
                    TurnParkState::Fresh,
                )
                .await;
            assert!(
                result.is_err(),
                "credential-less 401 under a provider refresh authority must stay terminal"
            );
        })
        .await;
}

/// Rule: a credential-less 401 stays terminal when the remedy is a manual re-login —
/// resubmits would loop on a credential no refresh can mint.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(attribution_emit_count)]
async fn credential_less_401_with_permanent_failure_stays_terminal() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let refresher: Arc<dyn crate::auth::refresh::TokenRefresher> =
                Arc::new(AlwaysTransientFailRefresher {
                    called: Arc::new(AtomicBool::new(false)),
                });
            let (_dir, am) = auth_manager_with_refresher(refresher);
            am.record_permanent_failure(
                "initial-test-key".to_string(),
                crate::auth::error::RefreshTokenFailedReason::RefreshTokenRejected.into(),
            );
            let (actor, _rx) = make_actor_with_auth_manager(Some(am)).await;
            let result = actor
                .handle_sampling_failure(
                    auth_error_with_credential(fuigo_sampling_types::SentCredential::Missing),
                    0,
                    transient_state(0, true),
                    false,
                    TurnParkState::Fresh,
                )
                .await;
            assert!(
                result.is_err(),
                "credential-less 401 with a permanent refresh failure must stay terminal"
            );
        })
        .await;
}

/// Rule: budgeted workflow children are excluded from the park — the output-budget gate
/// fails the request closed before the auth arms run, so no recovery is dispatched, fresh or parked.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(attribution_emit_count)]
async fn budgeted_workflow_child_credential_less_401_stays_terminal() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            for park in [TurnParkState::Fresh, TurnParkState::Parked] {
                let called = Arc::new(AtomicBool::new(false));
                let refresher: Arc<dyn crate::auth::refresh::TokenRefresher> =
                    Arc::new(AlwaysTransientFailRefresher {
                        called: called.clone(),
                    });
                let (_dir, am) = auth_manager_with_refresher(refresher);
                let (mut actor, _rx) = make_actor_parts_with_method_and_credentials(
                    Some(am),
                    "cached_token",
                    fuigo_chat_state::AuthType::SessionToken,
                    "initial-test-key".to_string(),
                )
                .await;
                actor.tool_context.task_output_token_budget = Some(
                    crate::tools::tool_context::TaskOutputTokenBudget::limited(100_000),
                );
                let actor = Arc::new(actor);
                let result = actor
                    .handle_sampling_failure(
                        auth_error_with_credential(fuigo_sampling_types::SentCredential::Missing),
                        0,
                        transient_state(0, true),
                        false,
                        park,
                    )
                    .await;
                let Err(err) = result else {
                    panic!("a budgeted child's credential-less 401 must be terminal ({park:?})");
                };
                let rendered = serde_json::to_string(&err.data).unwrap_or_default();
                assert!(
                    rendered.contains("budgeted workflow child model request failed"),
                    "failure must classify via the output-budget gate ({park:?}), got: {rendered}"
                );
                assert!(
                    !called.load(Ordering::SeqCst),
                    "the output-budget gate runs before any recovery dispatch ({park:?})"
                );
            }
        })
        .await;
}

/// Regression: sampler 401 with API-key auth (BYOK `env_key` / `FUIGO_API_KEY`) must NOT attempt an OIDC session-token refresh.
/// The bearer on the wire is the static API key, so refreshing the session token reports success but the retry re-sends the same rejected key.
/// That makes an invisible 401 loop that hangs the turn.
/// Recovery is skipped and the 401 surfaces as a terminal error.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(attribution_emit_count)]
async fn sampler_401_with_api_key_auth_skips_refresh_and_surfaces_error() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let called = Arc::new(AtomicBool::new(false));
            let refresher: Arc<dyn crate::auth::refresh::TokenRefresher> =
                Arc::new(AlwaysSucceedRefresher {
                    called: called.clone(),
                });
            let (_dir, am) = auth_manager_with_refresher(refresher);
            let (actor, _rx) = make_actor_with_auth_and_credentials(
                Some(am),
                fuigo_chat_state::AuthType::ApiKey,
                "fuigo-byok-key".to_string(),
            )
            .await;

            let result = actor
                .handle_sampling_failure(
                    auth_error(),
                    0,
                    transient_state(0, true),
                    false,
                    TurnParkState::Fresh,
                )
                .await;

            assert!(
                result.is_err(),
                "API-key 401 must surface a terminal error, not retry"
            );
            assert!(
                !called.load(Ordering::SeqCst),
                "API-key 401 must NOT trigger an OIDC session-token refresh"
            );
        })
        .await;
}

/// Per-turn pre-flight refresh must not fire when `creds.auth_type` is `ApiKey` (a BYOK model).
/// The model's own API key must not be overwritten by the session JWT.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(attribution_emit_count)]
async fn pre_flight_refresh_skips_api_key_auth_type() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let called = Arc::new(AtomicBool::new(false));
            let refresher: Arc<dyn crate::auth::refresh::TokenRefresher> =
                Arc::new(AlwaysSucceedRefresher {
                    called: called.clone(),
                });
            let (_dir, am) = auth_manager_with_refresher(refresher);
            let (actor, _rx) = make_actor_with_auth_and_credentials(
                Some(am),
                fuigo_chat_state::AuthType::ApiKey,
                "byok-api-key".to_string(),
            )
            .await;
            actor.refresh_token_if_expired().await;
            assert!(
                !called.load(Ordering::SeqCst),
                "pre-flight refresh must NOT fire for ApiKey auth_type"
            );
            assert_eq!(
                actor
                    .chat_state_handle
                    .get_credentials()
                    .await
                    .api_key
                    .as_deref(),
                Some("byok-api-key"),
                "BYOK api_key must not be overwritten by session token refresh"
            );
        })
        .await;
}

/// Hard-expired session token: pre-flight must call the refresher and must not leave credentials stuck while pretending the JWT/config path applies.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(attribution_emit_count)]
async fn pre_flight_refreshes_hard_expired_session_token() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let called = Arc::new(AtomicBool::new(false));
            let refresher: Arc<dyn crate::auth::refresh::TokenRefresher> =
                Arc::new(AlwaysSucceedRefresher {
                    called: called.clone(),
                });
            let (_dir, am) = auth_manager_with_refresher(refresher);
            assert!(
                !am.has_usable_token(),
                "precondition: access token is hard-expired"
            );

            let (actor, _rx) = make_actor_with_auth_manager(Some(am.clone())).await;
            actor.refresh_token_if_expired().await;

            assert!(
                called.load(Ordering::SeqCst),
                "pre-flight must invoke the refresher for a hard-expired session token"
            );
            assert_eq!(
                actor
                    .chat_state_handle
                    .get_credentials()
                    .await
                    .api_key
                    .as_deref(),
                Some("refreshed-test-token"),
                "credentials must be updated to the refreshed bearer"
            );
            assert!(am.has_usable_token());
        })
        .await;
}

/// Hard-expired token and a failed refresh: do not fall through to JWT/config.toml.
/// Strip the chat-state seed so default headers cannot carry a dead access token.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(attribution_emit_count)]
async fn pre_flight_hard_expired_refresh_failure_skips_jwt_fallthrough() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
            let refresher: Arc<dyn crate::auth::refresh::TokenRefresher> = Arc::new({
                struct AlwaysFail(Arc<std::sync::atomic::AtomicU32>);
                #[async_trait::async_trait]
                impl crate::auth::refresh::TokenRefresher for AlwaysFail {
                    async fn refresh(
                        &self,
                        _: crate::auth::refresh::RefreshReason,
                    ) -> crate::auth::refresh::RefreshOutcome {
                        self.0.fetch_add(1, Ordering::SeqCst);
                        crate::auth::refresh::RefreshOutcome::transient("refresh failed")
                    }
                }
                AlwaysFail(call_count.clone())
            });
            let (_dir, am) = auth_manager_with_refresher(refresher);
            let (actor, _rx) = make_actor_with_auth_manager(Some(am.clone())).await;

            actor.refresh_token_if_expired().await;

            assert!(
                call_count.load(Ordering::SeqCst) >= 1,
                "pre-flight must attempt refresh"
            );
            assert_eq!(
                actor
                    .chat_state_handle
                    .get_credentials()
                    .await
                    .api_key
                    .as_deref(),
                None,
                "hard-expired pre-flight failure must strip the chat-state seed"
            );
            assert!(
                !am.has_usable_token(),
                "token remains hard-expired after failed refresh"
            );
            assert!(
                am.permanent_failure().is_none(),
                "transient refresh failure must not poison permanent_failure"
            );
        })
        .await;
}

/// Soft-expired (inside the early-invalidation buffer) and a transient refresh failure: retain the seed.
/// The access token on the wire is still accepted, so it can continue until 401 recovery.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(attribution_emit_count)]
async fn pre_flight_soft_expired_transient_fail_retains_seed() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
            let refresher: Arc<dyn crate::auth::refresh::TokenRefresher> = Arc::new({
                struct AlwaysFail(Arc<std::sync::atomic::AtomicU32>);
                #[async_trait::async_trait]
                impl crate::auth::refresh::TokenRefresher for AlwaysFail {
                    async fn refresh(
                        &self,
                        _: crate::auth::refresh::RefreshReason,
                    ) -> crate::auth::refresh::RefreshOutcome {
                        self.0.fetch_add(1, Ordering::SeqCst);
                        crate::auth::refresh::RefreshOutcome::transient("refresh failed")
                    }
                }
                AlwaysFail(call_count.clone())
            });
            let dir = tempfile::tempdir().expect("tempdir");
            let am = Arc::new(AuthManager::new(dir.path(), FuigoComConfig::default()));
            // Inside the early-invalidation buffer but still hard-valid.
            am.hot_swap(FuigoAuth {
                key: "buffered-test-key".into(),
                auth_mode: AuthMode::Oidc,
                refresh_token: Some("rt".into()),
                expires_at: Some(chrono::Utc::now() + chrono::Duration::seconds(30)),
                ..FuigoAuth::test_default()
            });
            am.set_refresher(refresher);
            let (actor, _rx) = make_actor_with_auth_and_credentials(
                Some(am.clone()),
                fuigo_chat_state::AuthType::SessionToken,
                "buffered-test-key".to_string(),
            )
            .await;

            actor.refresh_token_if_expired().await;

            assert!(
                call_count.load(Ordering::SeqCst) >= 1,
                "soft-expired pre-flight must still attempt refresh"
            );
            assert_eq!(
                actor
                    .chat_state_handle
                    .get_credentials()
                    .await
                    .api_key
                    .as_deref(),
                Some("buffered-test-key"),
                "buffer-window soft-expired + transient fail must retain seed"
            );
            assert!(
                am.has_usable_token(),
                "token inside hard-expiry buffer remains usable"
            );
        })
        .await;
}

/// Proactive refresh keeps the cache hot so `refresh_token_if_expired` (per-turn pre-flight) is a cache hit.
/// The refresher fires once (proactive), then the per-turn call sees the fresh token without hitting the identity provider again.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(attribution_emit_count)]
async fn proactive_refresh_makes_per_turn_refresh_a_cache_hit() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
            let refresher: Arc<dyn crate::auth::refresh::TokenRefresher> = Arc::new({
                struct Counting(Arc<std::sync::atomic::AtomicU32>);
                #[async_trait::async_trait]
                impl crate::auth::refresh::TokenRefresher for Counting {
                    async fn refresh(
                        &self,
                        _: crate::auth::refresh::RefreshReason,
                    ) -> crate::auth::refresh::RefreshOutcome {
                        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        crate::auth::refresh::RefreshOutcome::Success(Box::new(FuigoAuth {
                            key: "proactive-fresh".into(),
                            auth_mode: AuthMode::Oidc,
                            refresh_token: Some("rt-new".into()),
                            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
                            ..FuigoAuth::test_default()
                        }))
                    }
                }
                Counting(call_count.clone())
            });

            let (_dir, am) = auth_manager_with_refresher(refresher);
            let cancel = tokio_util::sync::CancellationToken::new();
            am.start_proactive_refresh(cancel.clone());

            // Wait for the proactive task to fire; its first pass runs after PROACTIVE_MIN_SLEEP, so the window must exceed the floor
            tokio::time::sleep(
                crate::auth::manager::PROACTIVE_MIN_SLEEP + std::time::Duration::from_millis(1000),
            )
            .await;
            assert!(
                call_count.load(Ordering::SeqCst) >= 1,
                "proactive task must have fired"
            );
            let count_after_proactive = call_count.load(Ordering::SeqCst);

            // Now run refresh_token_if_expired (the per-turn pre-flight).
            let (actor, _rx) = make_actor_with_auth_manager(Some(am)).await;
            actor.refresh_token_if_expired().await;

            assert_eq!(
                call_count.load(Ordering::SeqCst),
                count_after_proactive,
                "per-turn refresh must NOT call the refresher again (cache hit)"
            );
            assert_eq!(
                actor
                    .chat_state_handle
                    .get_credentials()
                    .await
                    .api_key
                    .as_deref(),
                Some("proactive-fresh"),
                "per-turn refresh must pick up the proactively-refreshed token"
            );

            cancel.cancel();
        })
        .await;
}

fn model_not_found_error() -> fuigo_sampler::SamplingErrorInfo {
    fuigo_sampler::SamplingErrorInfo {
            kind: fuigo_sampler::SamplingErrorKind::Api,
            message: "API error (status 404 Not Found): The model fuigo-build does not exist or your team does not have access".into(),
            status_code: Some(404),
            is_retryable: false,
            retry_after_secs: None,
            should_retry: None,
            error_code: None,
        upstream_state: None,
        upstream_type: None,
        upstream_details: Default::default(),
            model_metadata: None,
            empty_response_context: None,
            doom_loop_triggers: None,
            doom_loop_aborted_at_chunk: None,
            credential: fuigo_sampling_types::SentCredential::Unknown,
        }
}

/// 404 model-not-found with a legacy WebLogin token appends a "Legacy auth detected" hint to the error message.
#[tokio::test(flavor = "current_thread")]
async fn legacy_auth_hint_on_404_model_not_found() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let dir = tempfile::tempdir().expect("tempdir");
            let am = Arc::new(AuthManager::new(dir.path(), FuigoComConfig::default()));
            am.hot_swap(FuigoAuth {
                key: "legacy-token".into(),
                auth_mode: AuthMode::WebLogin,
                ..FuigoAuth::test_default()
            });

            let (actor, _rx) = make_actor_with_auth_manager(Some(am)).await;
            let result = actor
                .handle_sampling_failure(
                    model_not_found_error(),
                    0,
                    transient_state(0, true),
                    false,
                    TurnParkState::Fresh,
                )
                .await;
            let err = match result {
                Err(e) => e,
                Ok(_) => panic!("expected Err from handle_sampling_failure"),
            };
            let data = err.data.unwrap();
            let msg = data
                .get("message")
                .and_then(|v| v.as_str())
                .expect("terminal error data is an object with a message");
            assert!(
                msg.contains("deprecated authentication method"),
                "404 with WebLogin must include deprecation message, got: {msg}"
            );
            assert!(
                msg.contains("fuigo update"),
                "hint must mention `fuigo update` before re-login, got: {msg}"
            );
            assert!(
                msg.contains("fuigo logout"),
                "hint must mention `fuigo logout`, got: {msg}"
            );
            assert!(
                msg.contains("fuigo login"),
                "hint must mention `fuigo login`, got: {msg}"
            );
            let update_at = msg.find("fuigo update").expect("fuigo update");
            let logout_at = msg.find("fuigo logout").expect("fuigo logout");
            assert!(
                update_at < logout_at,
                "update must come before logout, got: {msg}"
            );
            assert!(
                msg.contains("Version:"),
                "must show client version, got: {msg}"
            );
        })
        .await;
}

/// Build a 401-shaped error that bypasses step 4b's auth recovery.
///
/// In production, 401s arrive as `SamplingErrorKind::Auth` with `status_code: None`.
/// Step 4b intercepts `Auth`-kind errors and runs the full recovery chain.
/// On devbox/CI that chain succeeds by minting a service-account token, masking the hint.
///
/// Using `Api` kind with `status_code: Some(401)` exercises the hint condition (`status_code == Some(401)`) without triggering recovery.
/// This makes the test environment-independent.
fn unauthorized_401_error() -> fuigo_sampler::SamplingErrorInfo {
    fuigo_sampler::SamplingErrorInfo {
            kind: fuigo_sampler::SamplingErrorKind::Api,
            message: "Unauthorized (401) from https://cli-chat-proxy.grok.com/v1/responses: {\"error\":\"Invalid or expired credentials (auth_kind=bearer, x_fuigo_token_auth=xai-grok-cli, upstream=Unauthenticated, reason=no auth context)\"}".into(),
            status_code: Some(401),
            is_retryable: false,
            retry_after_secs: None,
            should_retry: None,
            error_code: None,
        upstream_state: None,
        upstream_type: None,
        upstream_details: Default::default(),
            model_metadata: None,
            empty_response_context: None,
            doom_loop_triggers: None,
            doom_loop_aborted_at_chunk: None,
            credential: fuigo_sampling_types::SentCredential::Unknown,
        }
}

/// 401 Unauthorized with a legacy WebLogin token appends a "Legacy auth detected" hint to the error message.
#[tokio::test(flavor = "current_thread")]
async fn legacy_auth_hint_on_401_unauthorized() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let dir = tempfile::tempdir().expect("tempdir");
            let am = Arc::new(AuthManager::new(dir.path(), FuigoComConfig::default()));
            am.hot_swap(FuigoAuth {
                key: "legacy-token".into(),
                auth_mode: AuthMode::WebLogin,
                ..FuigoAuth::test_default()
            });

            let (actor, _rx) = make_actor_with_auth_manager(Some(am)).await;
            let result = actor
                .handle_sampling_failure(
                    unauthorized_401_error(),
                    0,
                    transient_state(0, true),
                    false,
                    TurnParkState::Fresh,
                )
                .await;
            let err = match result {
                Err(e) => e,
                Ok(_) => panic!("expected Err from handle_sampling_failure"),
            };
            let data = err.data.unwrap();
            let msg = data
                .get("message")
                .and_then(|v| v.as_str())
                .expect("terminal error data is an object with a message");
            assert!(
                msg.contains("deprecated authentication method"),
                "401 with WebLogin must include deprecation message, got: {msg}"
            );
            assert!(
                msg.contains("fuigo update"),
                "hint must mention `fuigo update` before re-login, got: {msg}"
            );
            assert!(
                msg.contains("fuigo logout"),
                "hint must mention `fuigo logout`, got: {msg}"
            );
            assert!(
                msg.contains("fuigo login"),
                "hint must mention `fuigo login`, got: {msg}"
            );
            let update_at = msg.find("fuigo update").expect("fuigo update");
            let logout_at = msg.find("fuigo logout").expect("fuigo logout");
            assert!(
                update_at < logout_at,
                "update must come before logout, got: {msg}"
            );
        })
        .await;
}

/// 401 with OIDC auth must NOT append the legacy hint.
#[tokio::test(flavor = "current_thread")]
async fn no_legacy_hint_on_401_for_oidc_auth() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let dir = tempfile::tempdir().expect("tempdir");
            let am = Arc::new(AuthManager::new(dir.path(), FuigoComConfig::default()));
            am.hot_swap(FuigoAuth {
                key: "oidc-token".into(),
                auth_mode: AuthMode::Oidc,
                refresh_token: Some("rt".into()),
                expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
                ..FuigoAuth::test_default()
            });

            let (actor, _rx) = make_actor_with_auth_manager(Some(am)).await;
            let result = actor
                .handle_sampling_failure(
                    unauthorized_401_error(),
                    0,
                    transient_state(0, true),
                    false,
                    TurnParkState::Fresh,
                )
                .await;
            let err = match result {
                Err(e) => e,
                Ok(_) => panic!("expected Err from handle_sampling_failure"),
            };
            let data = err.data.unwrap();
            let msg = data
                .get("message")
                .and_then(|v| v.as_str())
                .or_else(|| data.as_str())
                .unwrap();
            assert!(
                !msg.contains("deprecated authentication method"),
                "OIDC auth must NOT trigger WebLogin deprecation on 401, got: {msg}"
            );
            assert!(
                msg.contains("Auth:      Oidc"),
                "OIDC 401 must show auth mode in enriched message, got: {msg}"
            );
        })
        .await;
}

/// 404 model-not-found with OIDC auth must NOT append the legacy hint.
#[tokio::test(flavor = "current_thread")]
async fn no_legacy_hint_for_oidc_auth() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let dir = tempfile::tempdir().expect("tempdir");
            let am = Arc::new(AuthManager::new(dir.path(), FuigoComConfig::default()));
            am.hot_swap(FuigoAuth {
                key: "oidc-token".into(),
                auth_mode: AuthMode::Oidc,
                refresh_token: Some("rt".into()),
                expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
                ..FuigoAuth::test_default()
            });

            let (actor, _rx) = make_actor_with_auth_manager(Some(am)).await;
            let result = actor
                .handle_sampling_failure(
                    model_not_found_error(),
                    0,
                    transient_state(0, true),
                    false,
                    TurnParkState::Fresh,
                )
                .await;
            let err = match result {
                Err(e) => e,
                Ok(_) => panic!("expected Err from handle_sampling_failure"),
            };
            let data = err.data.unwrap();
            let msg = data
                .get("message")
                .and_then(|v| v.as_str())
                .or_else(|| data.as_str())
                .unwrap();
            assert!(
                !msg.contains("deprecated authentication method"),
                "OIDC auth must NOT trigger WebLogin deprecation, got: {msg}"
            );
            assert!(
                msg.contains("Auth:      Oidc"),
                "OIDC 404 must show auth mode in enriched message, got: {msg}"
            );
            assert!(
                msg.contains("Version:"),
                "OIDC 404 must show version in enriched message, got: {msg}"
            );
        })
        .await;
}

// Regression group: a live session whose `auth_type` transiently reads `ApiKey` must still recover
// The gate keys off the stable `auth_method_id`
#[test]
fn session_token_auth_gate_truth_table() {
    use crate::agent::auth_method::{ModelByok, session_token_auth_gate as gate};
    // Non-session methods never refresh, regardless of BYOK status or endpoint.
    for fp in [false, true] {
        assert!(!gate(false, ModelByok::NotByok, fp));
        assert!(!gate(false, ModelByok::Byok, fp));
        assert!(!gate(false, ModelByok::Unknown, fp));
        // A genuine per-model Byok never uses the session token.
        assert!(!gate(true, ModelByok::Byok, fp));
        // P42: NotByok decides only that the session token is wanted; the destination decides whether it may go.
        // It used to be unconditionally `true`, and a model absent from the catalogue is classed NotByok.
        assert_eq!(gate(true, ModelByok::NotByok, fp), fp);
    }
    // Session method and Unknown BYOK: refresh only where the destination may receive the session
    // That way a transiently-unclassifiable config can't demote a live session (the stale-token 401 regression)
    assert!(gate(true, ModelByok::Unknown, true));
    assert!(!gate(true, ModelByok::Unknown, false));
}

/// Pre-fix, the gate read `auth_type` and skipped recovery here, 401'ing every turn until restart.
#[tokio::test(flavor = "current_thread")]
async fn sampler_401_session_method_with_stale_api_key_auth_type_still_recovers() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let called = Arc::new(AtomicBool::new(false));
            let refresher: Arc<dyn crate::auth::refresh::TokenRefresher> =
                Arc::new(AlwaysSucceedRefresher {
                    called: called.clone(),
                });
            let (_dir, am) = auth_manager_with_refresher(refresher);
            let (actor, _rx) = make_actor_with_method_and_credentials(
                Some(am),
                "cached_token",
                fuigo_chat_state::AuthType::ApiKey,
                "stale-session-jwt".to_string(),
            )
            .await;

            let result = actor
                .handle_sampling_failure(
                    auth_error(),
                    0,
                    transient_state(0, true),
                    false,
                    TurnParkState::Fresh,
                )
                .await;

            assert!(
                matches!(
                    result,
                    Ok(SamplerFailureRecovery::RefreshAuthAndResubmit { .. })
                ),
                "session-based method must recover even when auth_type transiently reads ApiKey"
            );
            assert!(
                called.load(Ordering::SeqCst),
                "the OIDC refresher must be invoked for a session-based method"
            );
        })
        .await;
}

/// Same regression via the `oidc` method id (the other session-based variant).
#[tokio::test(flavor = "current_thread")]
async fn sampler_401_oidc_method_with_stale_api_key_auth_type_still_recovers() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let called = Arc::new(AtomicBool::new(false));
            let refresher: Arc<dyn crate::auth::refresh::TokenRefresher> =
                Arc::new(AlwaysSucceedRefresher {
                    called: called.clone(),
                });
            let (_dir, am) = auth_manager_with_refresher(refresher);
            let (actor, _rx) = make_actor_with_method_and_credentials(
                Some(am),
                "oidc",
                fuigo_chat_state::AuthType::ApiKey,
                "stale-session-jwt".to_string(),
            )
            .await;

            let result = actor
                .handle_sampling_failure(
                    auth_error(),
                    0,
                    transient_state(0, true),
                    false,
                    TurnParkState::Fresh,
                )
                .await;

            assert!(
                matches!(
                    result,
                    Ok(SamplerFailureRecovery::RefreshAuthAndResubmit { .. })
                ),
                "oidc method must recover even when auth_type transiently reads ApiKey"
            );
            assert!(
                called.load(Ordering::SeqCst),
                "the OIDC refresher must be invoked"
            );
        })
        .await;
}

/// Without the live bearer resolver here the sampler would sign requests with the stale buffered token.
#[tokio::test(flavor = "current_thread")]
async fn reconstruct_full_config_wires_bearer_resolver_for_session_method_despite_api_key_auth_type()
 {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_dir, am) = auth_manager_with_valid_token("fresh-session-token");
            let (actor, _rx) = make_actor_with_method_and_credentials(
                Some(am),
                "cached_token",
                fuigo_chat_state::AuthType::ApiKey,
                "stale-session-jwt".to_string(),
            )
            .await;

            let cfg = actor.reconstruct_full_config(crate::session::acp_session::CallRole::Main).await;

            assert!(
                cfg.bearer_resolver.is_some(),
                "session-based method must use the live bearer resolver, not the buffered key"
            );
        })
        .await;
}

/// Negative: a genuine `fuigo.api_key` method keeps its configured key on the wire (no live resolver).
#[tokio::test(flavor = "current_thread")]
async fn reconstruct_full_config_no_bearer_resolver_for_api_key_method() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_dir, am) = auth_manager_with_valid_token("session-token");
            let (actor, _rx) = make_actor_with_method_and_credentials(
                Some(am),
                "fuigo.api_key",
                fuigo_chat_state::AuthType::ApiKey,
                "fuigo-static-key".to_string(),
            )
            .await;

            let cfg = actor.reconstruct_full_config(crate::session::acp_session::CallRole::Main).await;

            assert!(
                cfg.bearer_resolver.is_none(),
                "api-key method must keep its configured bearer (no live resolver)"
            );
        })
        .await;
}

/// The pre-flight refresh heals a transiently-`ApiKey` session by writing the fresh session token back into `creds.api_key`.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(attribution_emit_count)]
async fn pre_flight_refresh_heals_session_method_with_stale_api_key_auth_type() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_dir, am) = auth_manager_with_valid_token("fresh-session-token");
            let (actor, _rx) = make_actor_with_method_and_credentials(
                Some(am),
                "cached_token",
                fuigo_chat_state::AuthType::ApiKey,
                "stale-session-jwt".to_string(),
            )
            .await;

            actor.refresh_token_if_expired().await;

            assert_eq!(
                actor
                    .chat_state_handle
                    .get_credentials()
                    .await
                    .api_key
                    .as_deref(),
                Some("fresh-session-token"),
                "session-based pre-flight refresh must heal a stale api_key with the live token"
            );
        })
        .await;
}

/// End-to-end regression: a session born on `fuigo.api_key` (the gate inactive) must adopt a later OIDC `/login` on the SAME actor.
/// The shared `auth_method_id` handle is flipped in place (no re-spawn), so the next turn wires the live bearer resolver and heals the stale key.
#[tokio::test(flavor = "current_thread")]
async fn session_born_on_api_key_recovers_after_oidc_login_without_restart() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_dir, am) = auth_manager_with_valid_token("fresh-oidc-token");
            let (actor, _rx) = make_actor_with_method_and_credentials(
                Some(am),
                "fuigo.api_key",
                fuigo_chat_state::AuthType::ApiKey,
                "stale-session-jwt".to_string(),
            )
            .await;

            // Born on api_key: the gate is inactive, so no live resolver.
            assert!(
                actor
                    .reconstruct_full_config(crate::session::acp_session::CallRole::Main)
                    .await
                    .bearer_resolver
                    .is_none(),
                "api-key session must not use the live resolver before login"
            );

            // Simulate the agent's `authenticate` publishing an OIDC method into the shared handle this running actor already holds (no re-spawn)
            actor
                .auth_method_id
                .store(Some(std::sync::Arc::new(acp::AuthMethodId::new("oidc"))));

            // The gate is recomputed each turn from the shared handle, so the flip alone activates the live resolver on the very next turn
            // That happens with no re-spawn and before any token refresh runs
            assert!(
                actor
                    .reconstruct_full_config(crate::session::acp_session::CallRole::Main)
                    .await
                    .bearer_resolver
                    .is_some(),
                "flipping the shared handle activates the resolver on the next turn"
            );

            // The pre-flight refresh then heals the stale api_key with the live token.
            actor.refresh_token_if_expired().await;
            assert_eq!(
                actor
                    .chat_state_handle
                    .get_credentials()
                    .await
                    .api_key
                    .as_deref(),
                Some("fresh-oidc-token"),
                "the stale api_key must be healed with the fresh OIDC token"
            );
        })
        .await;
}

// Per-model BYOK memo (`SessionActor::model_auth_memo`): a definite cached status is served without recomputing, and the memo keys on `model_id`

/// The cache-hit branch is what lets a later config parse failure (`Unknown`) fall back to the last-known-good status.
#[tokio::test(flavor = "current_thread")]
async fn model_auth_memo_serves_cached_status_and_keys_on_model() {
    use crate::agent::auth_method::ModelByok;
    use crate::agent::config::ModelAuthFacts;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = make_actor_with_method_and_credentials(
                None,
                "cached_token",
                fuigo_chat_state::AuthType::SessionToken,
                "k".to_string(),
            )
            .await;

            actor
                .model_auth_memo
                .replace(Some(crate::session::acp_session::ModelAuthMemo {
                    model_id: "model-a".to_string(),
                    facts: ModelAuthFacts {
                        byok: ModelByok::Byok,
                        auth_scheme: Default::default(),
                    },
                    provider: None,
                }));

            // Cache hit: served without consulting config.
            assert_eq!(actor.model_auth_facts("model-a").byok, ModelByok::Byok);

            // Different model re-resolves rather than serving the stale `Byok`.
            assert_ne!(actor.model_auth_facts("model-b").byok, ModelByok::Byok);
        })
        .await;
}

/// A session method whose active model is a genuine per-model BYOK model keeps the model's own key on the wire (no live resolver).
#[tokio::test(flavor = "current_thread")]
async fn reconstruct_full_config_no_bearer_resolver_for_byok_model_on_session_method() {
    use crate::agent::auth_method::ModelByok;
    use crate::agent::config::ModelAuthFacts;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_dir, am) = auth_manager_with_valid_token("session-token");
            let (actor, _rx) = make_actor_with_method_and_credentials(
                Some(am),
                "cached_token",
                fuigo_chat_state::AuthType::SessionToken,
                "byok-key".to_string(),
            )
            .await;

            let model = actor
                .chat_state_handle
                .get_sampling_config()
                .await
                .map(|c| c.model)
                .unwrap_or_default();
            actor
                .model_auth_memo
                .replace(Some(crate::session::acp_session::ModelAuthMemo {
                    model_id: model,
                    facts: ModelAuthFacts {
                        byok: ModelByok::Byok,
                        auth_scheme: Default::default(),
                    },
                    provider: None,
                }));

            let cfg = actor.reconstruct_full_config(crate::session::acp_session::CallRole::Main).await;

            assert!(
                cfg.bearer_resolver.is_none(),
                "a per-model BYOK model must keep its own key even on a session method"
            );
        })
        .await;
}

/// Regression: `handle_set_session_model` must invalidate the memo even when `model_id` is unchanged.
/// Otherwise a config edit that turns the current model into a per-model BYOK model on a third-party `base_url` keeps serving the stale `NotByok`.
/// That leaves the gate active and leaks the OIDC token to the third-party host.
#[tokio::test(flavor = "current_thread")]
async fn set_session_model_invalidates_byok_memo_for_same_model_id() {
    use crate::agent::auth_method::ModelByok;
    use crate::agent::config::ModelAuthFacts;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = make_actor_with_method_and_credentials(
                None,
                "cached_token",
                fuigo_chat_state::AuthType::SessionToken,
                "k".to_string(),
            )
            .await;

            let model = actor
                .chat_state_handle
                .get_sampling_config()
                .await
                .map(|c| c.model)
                .unwrap_or_default();

            actor
                .model_auth_memo
                .replace(Some(crate::session::acp_session::ModelAuthMemo {
                    model_id: model.clone(),
                    facts: ModelAuthFacts {
                        byok: ModelByok::NotByok,
                        auth_scheme: Default::default(),
                    },
                    provider: None,
                }));

            // Switch to the same model_id, now a per-model BYOK model on a third-party endpoint
            let cfg = fuigo_sampler::SamplerConfig {
                flux_base_url: None,
                api_key: Some("byok-key".to_string()),
                base_url: "https://third-party.example/v1".to_string(),
                model: model.clone(),
                max_completion_tokens: None,
                temperature: None,
                top_p: None,
                api_backend: crate::sampling::ApiBackend::ChatCompletions,
                auth_scheme: Default::default(),
                extra_headers: Default::default(),
                extra_response_includes: Vec::new(),
                query_params: Default::default(),
                env_http_headers: Default::default(),
                context_window: 256_000,
                max_request_bytes: None,
                client_version: None,
                force_http1: false,
                max_retries: None,
                stream_tool_calls: false,
                idle_timeout_secs: None,
                client_identifier: None,
                reasoning_effort: None,
                deployment_id: None,
                user_id: None,
                origin_client: None,
                attribution_callback: None,
                bearer_resolver: None,
                supports_backend_search: false,
                programmatic_tool_calling: false,
                compactions_remaining: None,
                compaction_at_tokens: None,
                doom_loop_recovery: None,
                subscription: None,
                subscription_resolver: None,
                header_injector: None,
                dispatch_gate: None,
                mtls_cert_dir: None,
                rate_limit_retry_threshold: None,
                reasoning_summary: None,
            };
            let _ = actor
                .handle_set_session_model(cfg, false, false, false, true, 85, Default::default())
                .await;

            assert!(
                actor.model_auth_memo.borrow().is_none(),
                "a model switch must invalidate the per-model BYOK memo so the next \
                 reconstruct recomputes under the current config"
            );
        })
        .await;
}

use crate::auth::test_counting_provider as counting_provider;

/// Seed the per-model memo so `model_auth_provider` resolves without a config load.
async fn seed_provider_memo(actor: &Arc<SessionActor>, provider: crate::auth::AuthProviderRef) {
    let model = actor
        .chat_state_handle
        .get_sampling_config()
        .await
        .map(|c| c.model)
        .unwrap_or_default();
    actor
        .model_auth_memo
        .replace(Some(crate::session::acp_session::ModelAuthMemo {
            model_id: model,
            facts: crate::agent::config::ModelAuthFacts {
                byok: crate::agent::auth_method::ModelByok::Byok,
                auth_scheme: Default::default(),
            },
            provider: Some(provider),
        }));
}

/// Regression: switching from a provider-backed model to a first-party model must drop the minted provider token from the chat credentials.
/// The token must never go out on a later request to `api.x.ai`.
/// Mirrors the forward direction in `set_session_model_invalidates_byok_memo_for_same_model_id`.
#[tokio::test(flavor = "current_thread")]
async fn switch_to_first_party_model_drops_minted_provider_token() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let provider = counting_provider("hall-pass", dir.path());
            let token = provider.ensure_fresh_token(None).await.rotated().unwrap();
            assert_eq!(token, "tok-1");

            let (actor, _rx) = make_actor_with_auth_and_credentials(
                None,
                fuigo_chat_state::AuthType::ApiKey,
                token,
            )
            .await;
            seed_provider_memo(&actor, provider).await;

            let model = actor
                .chat_state_handle
                .get_sampling_config()
                .await
                .map(|c| c.model)
                .unwrap_or_default();

            let cfg = fuigo_sampler::SamplerConfig {
                flux_base_url: None,
                api_key: Some("session-jwt".to_string()),
                base_url: "https://api.x.ai/v1".to_string(),
                model,
                max_completion_tokens: None,
                temperature: None,
                top_p: None,
                api_backend: crate::sampling::ApiBackend::ChatCompletions,
                auth_scheme: Default::default(),
                extra_headers: Default::default(),
                extra_response_includes: Vec::new(),
                query_params: Default::default(),
                env_http_headers: Default::default(),
                context_window: 256_000,
                max_request_bytes: None,
                client_version: None,
                force_http1: false,
                max_retries: None,
                stream_tool_calls: false,
                idle_timeout_secs: None,
                client_identifier: None,
                reasoning_effort: None,
                deployment_id: None,
                user_id: None,
                origin_client: None,
                attribution_callback: None,
                bearer_resolver: None,
                supports_backend_search: false,
                programmatic_tool_calling: false,
                compactions_remaining: None,
                compaction_at_tokens: None,
                doom_loop_recovery: None,
                subscription: None,
                subscription_resolver: None,
                header_injector: None,
                dispatch_gate: None,
                mtls_cert_dir: None,
                rate_limit_retry_threshold: None,
                reasoning_summary: None,
            };
            let _ = actor
                .handle_set_session_model(cfg, false, false, false, true, 85, Default::default())
                .await;

            let creds = actor.chat_state_handle.get_credentials().await;
            assert_eq!(
                creds.api_key.as_deref(),
                Some("session-jwt"),
                "switching to a first-party model must install the session credential, \
                 not the minted provider token"
            );
        })
        .await;
}

/// Arm 4c: a 401 on a provider-backed model re-mints once and resubmits.
#[tokio::test(flavor = "current_thread")]
async fn sampler_401_on_provider_model_remints_and_resubmits() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let provider = counting_provider("test-4c-recover", dir.path());
            let token = provider.ensure_fresh_token(None).await.rotated().unwrap();
            assert_eq!(token, "tok-1");

            let (actor, _rx) = make_actor_with_auth_and_credentials(
                None,
                fuigo_chat_state::AuthType::ApiKey,
                token,
            )
            .await;
            seed_provider_memo(&actor, provider).await;
            crate::auth::test_backdate_provider_mint(
                "test-4c-recover",
                std::time::Duration::from_secs(60),
            );

            let result = actor
                .handle_sampling_failure(
                    auth_error(),
                    0,
                    transient_state(0, true),
                    false,
                    TurnParkState::Fresh,
                )
                .await;
            assert!(
                matches!(
                    result,
                    Ok(SamplerFailureRecovery::RefreshAuthAndResubmit {
                        store: RecoveredStore::AuthProvider,
                        ..
                    })
                ),
                "provider 401 must re-mint and resubmit via the provider store"
            );
            let creds = actor.chat_state_handle.get_credentials().await;
            assert_eq!(
                creds.api_key.as_deref(),
                Some("tok-2"),
                "chat-state credentials must carry the re-minted token"
            );
        })
        .await;
}

/// Arm 4c also fires for a bare 401 that did not classify as `Auth`-kind.
#[tokio::test(flavor = "current_thread")]
async fn sampler_non_auth_kind_401_on_provider_model_still_recovers() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let provider = counting_provider("test-4c-non-auth-kind", dir.path());
            let token = provider.ensure_fresh_token(None).await.rotated().unwrap();

            let (actor, _rx) = make_actor_with_auth_and_credentials(
                None,
                fuigo_chat_state::AuthType::ApiKey,
                token,
            )
            .await;
            seed_provider_memo(&actor, provider).await;
            crate::auth::test_backdate_provider_mint(
                "test-4c-non-auth-kind",
                std::time::Duration::from_secs(60),
            );

            let mut error = auth_error();
            error.kind = fuigo_sampler::SamplingErrorKind::Api;
            let result = actor
                .handle_sampling_failure(
                    error,
                    0,
                    transient_state(0, true),
                    false,
                    TurnParkState::Fresh,
                )
                .await;
            assert!(
                matches!(
                    result,
                    Ok(SamplerFailureRecovery::RefreshAuthAndResubmit { .. })
                ),
                "a non-Auth-kind 401 on a provider model must still recover via 4c"
            );
            let creds = actor.chat_state_handle.get_credentials().await;
            assert_eq!(creds.api_key.as_deref(), Some("tok-2"));
        })
        .await;
}

/// A 401 on a request that went out with no key mints instead of recovering.
#[tokio::test(flavor = "current_thread")]
async fn sampler_401_with_no_key_on_provider_model_mints_and_resubmits() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let provider = counting_provider("test-4c-no-key", dir.path());

            let (actor, _rx) = make_actor_with_auth_and_credentials(
                None,
                fuigo_chat_state::AuthType::ApiKey,
                "placeholder".to_string(),
            )
            .await;
            let mut creds = actor.chat_state_handle.get_credentials().await;
            creds.api_key = None;
            actor.chat_state_handle.update_credentials(creds);
            seed_provider_memo(&actor, provider).await;

            let result = actor
                .handle_sampling_failure(
                    auth_error(),
                    0,
                    transient_state(0, true),
                    false,
                    TurnParkState::Fresh,
                )
                .await;
            assert!(
                matches!(
                    result,
                    Ok(SamplerFailureRecovery::RefreshAuthAndResubmit { .. })
                ),
                "an unauthenticated 401 on a provider model must mint and resubmit"
            );
            let creds = actor.chat_state_handle.get_credentials().await;
            assert_eq!(creds.api_key.as_deref(), Some("tok-1"));
        })
        .await;
}

/// A provider model's 401 goes through the provider, never the session refresher (4a/4b vs 4c exclusivity).
/// The actor uses a session-based method, so the gate would be active for a non-BYOK model.
/// The BYOK memo overrides it; that override is the invariant under test.
#[tokio::test(flavor = "current_thread")]
async fn sampler_401_on_provider_model_never_refreshes_session() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let provider = counting_provider("test-4c-exclusive", dir.path());
            let token = provider.ensure_fresh_token(None).await.rotated().unwrap();

            let called = Arc::new(AtomicBool::new(false));
            let refresher: Arc<dyn crate::auth::refresh::TokenRefresher> =
                Arc::new(AlwaysSucceedRefresher {
                    called: called.clone(),
                });
            let (_dir, am) = auth_manager_with_refresher(refresher);
            let (actor, _rx) = make_actor_with_method_and_credentials(
                Some(am),
                "cached_token",
                fuigo_chat_state::AuthType::SessionToken,
                token,
            )
            .await;
            seed_provider_memo(&actor, provider).await;
            crate::auth::test_backdate_provider_mint(
                "test-4c-exclusive",
                std::time::Duration::from_secs(60),
            );

            let result = actor
                .handle_sampling_failure(
                    auth_error(),
                    0,
                    transient_state(0, true),
                    false,
                    TurnParkState::Fresh,
                )
                .await;
            assert!(
                matches!(
                    result,
                    Ok(SamplerFailureRecovery::RefreshAuthAndResubmit { .. })
                ),
                "the provider arm must recover"
            );
            assert!(
                !called.load(Ordering::SeqCst),
                "session refresh must never fire for a provider-backed model"
            );
            let creds = actor.chat_state_handle.get_credentials().await;
            assert_eq!(creds.api_key.as_deref(), Some("tok-2"));
        })
        .await;
}

/// The pre-turn mirror of the exclusivity test: a cold cache mints the provider token into chat-state, and the session refresher never fires.
/// The actor uses a session-based method, so the gate would be active for a non-BYOK model; the BYOK memo is what keeps the refresher silent.
#[tokio::test(flavor = "current_thread")]
async fn pre_turn_on_provider_model_never_installs_session_token() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let provider = counting_provider("test-preturn-exclusive", dir.path());

            let called = Arc::new(AtomicBool::new(false));
            let refresher: Arc<dyn crate::auth::refresh::TokenRefresher> =
                Arc::new(AlwaysSucceedRefresher {
                    called: called.clone(),
                });
            let (_dir, am) = auth_manager_with_refresher(refresher);
            let (actor, _rx) = make_actor_with_method_and_credentials(
                Some(am),
                "cached_token",
                fuigo_chat_state::AuthType::SessionToken,
                "placeholder".to_string(),
            )
            .await;
            // Cold cache: no key on the wire yet.
            let mut creds = actor.chat_state_handle.get_credentials().await;
            creds.api_key = None;
            actor.chat_state_handle.update_credentials(creds);
            seed_provider_memo(&actor, provider).await;

            actor.refresh_token_if_expired().await;

            let creds = actor.chat_state_handle.get_credentials().await;
            assert_eq!(
                creds.api_key.as_deref(),
                Some("tok-1"),
                "the cold pre-turn hook must mint the provider token"
            );
            assert!(
                !called.load(Ordering::SeqCst),
                "the session refresher must never fire for a provider-backed model"
            );
        })
        .await;
}

/// A token rejected moments after mint surfaces the 401 (fresh-mint guard).
#[tokio::test(flavor = "current_thread")]
async fn sampler_401_on_fresh_provider_token_surfaces_error() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let provider = counting_provider("test-4c-guard", dir.path());
            let token = provider.ensure_fresh_token(None).await.rotated().unwrap();

            let (actor, _rx) = make_actor_with_auth_and_credentials(
                None,
                fuigo_chat_state::AuthType::ApiKey,
                token.clone(),
            )
            .await;
            seed_provider_memo(&actor, provider).await;

            let result = actor
                .handle_sampling_failure(
                    auth_error(),
                    0,
                    transient_state(0, true),
                    false,
                    TurnParkState::Fresh,
                )
                .await;
            assert!(
                result.is_err(),
                "a fresh-minted rejected token must surface the 401, not loop"
            );
            let creds = actor.chat_state_handle.get_credentials().await;
            assert_eq!(
                creds.api_key.as_deref(),
                Some(token.as_str()),
                "credentials must be unchanged when the guard blocks the re-mint"
            );
        })
        .await;
}

/// A subscription model reconstructs onto the native subscription resolver and never carries the session
/// key. P192: the subscription must come from the (wire model, endpoint) lookup of the user's config; the
/// memo's wire-id-only provider alone no longer confers it (it may belong to a same-wire-id twin), so the
/// fixture config binds the session's (model, endpoint) to the ChatGPT subscription.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn subscription_acp_reconstruction_uses_native_resolver_without_session_key() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    const SLUG: &str = "p192-native-slug";
    const SUBSCRIPTION_URL: &str = "https://chatgpt.com/backend-api/codex";
    let home = tempfile::tempdir().expect("fuigo home");
    std::fs::write(
        home.path().join("config.toml"),
        format!(
            "[auth_provider.native-test]\nsubscription = \"chatgpt\"\naccount = \"account-a\"\n\
             [model.native]\nmodel = \"{SLUG}\"\nbase_url = \"{SUBSCRIPTION_URL}\"\nauth_provider = \"native-test\"\n"
        ),
    )
    .expect("write config.toml");
    let _home = fuigo_test_support::EnvGuard::set("FUIGO_HOME", home.path());
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            crate::agent::config::Config::install_test_trusted_origins();
            let (actor, _rx) = make_actor_with_method_and_credentials(
                None,
                "api_key",
                fuigo_chat_state::AuthType::ApiKey,
                "fake-unrelated-key".into(),
            )
            .await;
            let mut config = actor.chat_state_handle.get_sampling_config().await.unwrap();
            config.base_url = SUBSCRIPTION_URL.into();
            config.model = SLUG.into();
            actor.chat_state_handle.update_sampling_config(config);
            let provider = crate::auth::AuthProviderRef::new(
                "native-test".into(),
                crate::auth::AuthProviderConfig {
                    subscription: Some(crate::auth::subscription::SubscriptionProvider::Chatgpt),
                    account: Some("account-a".into()),
                    ..Default::default()
                },
            );
            actor.model_auth_memo.replace(Some(crate::session::acp_session::ModelAuthMemo {
                model_id: SLUG.into(),
                facts: crate::agent::config::ModelAuthFacts {
                    byok: crate::agent::auth_method::ModelByok::Byok,
                    auth_scheme: Default::default(),
                },
                provider: Some(provider),
            }));
            let sampling = actor.reconstruct_full_config(crate::session::acp_session::CallRole::Main).await;
            assert_eq!(
                sampling.subscription,
                Some(fuigo_sampler::subscription::SubscriptionKind::Chatgpt)
            );
            assert!(sampling.subscription_resolver.is_some());
            assert!(sampling.api_key.is_none());
            assert!(sampling.bearer_resolver.is_none());
            assert!(sampling.attribution_callback.is_none());
        })
        .await;
}

/// P192 (R1): a subscription known only from the wire-id memo, with no (model, endpoint) entry in the
/// user's config, is not attached to the turn: it may belong to another entry with the same wire id.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn p192_memo_only_subscription_is_not_attached_to_the_turn() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = tempfile::tempdir().expect("fuigo home");
    let _home = fuigo_test_support::EnvGuard::set("FUIGO_HOME", home.path());
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            crate::agent::config::Config::install_test_trusted_origins();
            let (actor, _rx) = make_actor_with_method_and_credentials(
                None,
                "api_key",
                fuigo_chat_state::AuthType::ApiKey,
                "fake-unrelated-key".into(),
            )
            .await;
            let mut config = actor.chat_state_handle.get_sampling_config().await.unwrap();
            config.base_url = "https://chatgpt.com/backend-api/codex".into();
            config.model = "p192-memo-only-slug".into();
            actor.chat_state_handle.update_sampling_config(config);
            let provider = crate::auth::AuthProviderRef::new(
                "native-test".into(),
                crate::auth::AuthProviderConfig {
                    subscription: Some(crate::auth::subscription::SubscriptionProvider::Chatgpt),
                    account: Some("account-a".into()),
                    ..Default::default()
                },
            );
            actor.model_auth_memo.replace(Some(crate::session::acp_session::ModelAuthMemo {
                model_id: "p192-memo-only-slug".into(),
                facts: crate::agent::config::ModelAuthFacts {
                    byok: crate::agent::auth_method::ModelByok::Byok,
                    auth_scheme: Default::default(),
                },
                provider: Some(provider),
            }));
            let sampling = actor.reconstruct_full_config(crate::session::acp_session::CallRole::Main).await;
            assert_eq!(sampling.subscription, None);
            assert!(sampling.subscription_resolver.is_none());
        })
        .await;
}

/// P42: a 401 on a request the session token was withheld from (its destination may not receive it) is
/// terminal, typed `auth_destination_refused`, and names the `[endpoints]` remedy — not a self-healing blip.
#[tokio::test(flavor = "current_thread")]
async fn p42_withheld_session_401_is_terminal_with_the_endpoints_remedy() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            crate::agent::config::Config::install_test_trusted_origins();
            let (_dir, am) = auth_manager_with_valid_token("p42-terminal-session");
            for (base, withheld) in [
                ("http://127.0.0.1:9/v1", true),
                ("http://api.fluxrouter.ai/v1", true),
                ("https://api.fluxrouter.ai:8443/v1", true),
                (P42_CONFIGURED_ORIGIN, false),
            ] {
                let (actor, _rx) =
                    make_actor_with_method_and_credentials(Some(am.clone()), "cached_token", fuigo_chat_state::AuthType::SessionToken, String::new()).await;
                let mut cfg = actor.chat_state_handle.get_sampling_config().await.unwrap();
                cfg.base_url = base.to_string();
                cfg.model = String::new();
                actor.chat_state_handle.update_sampling_config(cfg);
                let error = auth_error_with_credential(fuigo_sampling_types::SentCredential::Missing);
                assert_eq!(actor.session_withheld_401(&error, "", base), withheld, "{base}");
                if withheld {
                    let result = actor
                        .handle_sampling_failure(error, 0, transient_state(0, true), false, TurnParkState::Fresh)
                        .await;
                    let err = result.err().unwrap_or_else(|| panic!("{base}: must be terminal"));
                    let data = format!("{:?}", err.data);
                    assert!(data.contains("[endpoints]"), "{base}: remedy must name [endpoints]: {data}");
                    assert!(!data.contains("temporarily unavailable"), "{base}: {data}");
                    assert!(
                        data.contains("auth_destination_refused") && !data.contains("\"auth\""),
                        "{base}: the returned error_kind must not invite a sign-in: {data}"
                    );
                    p42_assert_refused_destination_wire(base, err.data.as_ref().expect("typed data"));
                }
            }
            // The pager's banner decision: never a re-auth prompt for a refused destination, even though the
            // message still carries the sampler's "Unauthorized (401)" text.
            assert!(!crate::extensions::notification::is_reauthable_failure(
                Some(crate::extensions::notification::AUTH_DESTINATION_REFUSED_ERROR_TYPE),
                "Unauthorized (401) from http://127.0.0.1:9/v1/responses"
            ));
            // A request that DID carry a credential is a real rejection, not a withheld session.
            let (actor, _rx) = make_actor_with_method_and_credentials(Some(am.clone()), "cached_token", fuigo_chat_state::AuthType::SessionToken, String::new()).await;
            assert!(!actor.session_withheld_401(
                &auth_error_with_credential(fuigo_sampling_types::SentCredential::Sent),
                "",
                "http://127.0.0.1:9/v1"
            ));
        })
        .await;
}

/// P149 (S12, live lane C2 D4): a refused destination whose base URL carries userinfo and a query secret is named by
/// location only in the turn error (`Endpoint:` line): the password and the query value never reach a client,
/// the headless `Error:` line or a log.
#[tokio::test(flavor = "current_thread")]
async fn p149_refused_destination_is_named_by_location_only() {
    const PASS: &str = "fuigo-p149-SYNTH-urlpass";
    const QUERY: &str = "fuigo-p149-SYNTH-urlquery";
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            crate::agent::config::Config::install_test_trusted_origins();
            let (_dir, am) = auth_manager_with_valid_token("p149-userinfo-session");
            let base = format!("https://p149u:{PASS}@gw.p149.invalid/v1?key={QUERY}");
            let (actor, _rx) =
                make_actor_with_method_and_credentials(Some(am.clone()), "cached_token", fuigo_chat_state::AuthType::SessionToken, String::new()).await;
            let mut cfg = actor.chat_state_handle.get_sampling_config().await.unwrap();
            cfg.base_url = base.clone();
            cfg.model = String::new();
            actor.chat_state_handle.update_sampling_config(cfg);
            let error = auth_error_with_credential(fuigo_sampling_types::SentCredential::Missing);
            assert!(actor.session_withheld_401(&error, "", &base), "control: the destination is refused");
            let result = actor
                .handle_sampling_failure(error, 0, transient_state(0, true), false, TurnParkState::Fresh)
                .await;
            let err = result.err().expect("terminal");
            let message = err.data.as_ref().and_then(|d| d["message"].as_str()).expect("message").to_owned();
            assert!(!message.contains(PASS), "the password was shown: {message}");
            assert!(!message.contains(QUERY), "the query secret was shown: {message}");
            assert!(!message.contains("p149u"), "the user name was shown: {message}");
            assert!(
                message.contains("  Endpoint:  https://<redacted>@gw.p149.invalid/v1?key=<redacted>"),
                "control: the location is kept: {message}"
            );
        })
        .await;
}

/// P42 (audit round 6, M1/M2): the shell composes a refused destination's whole message — the `[endpoints]`
/// remedy first, one plain sentence, then the `Model:` diagnostics — and sends no `http_status`. A client cuts
/// its banner at `Model:` (so the remedy survives) and keys its sign-in prompt and post-login resubmit off a 401
/// status or text (so neither may appear).
fn p42_assert_refused_destination_wire(base: &str, data: &serde_json::Value) {
    use crate::extensions::notification::{
        AUTH_DESTINATION_REFUSED_REMEDY, AUTH_DESTINATION_REFUSED_SENTENCE,
    };
    assert!(data.get("http_status").is_none(), "{base}: no http_status may be sent: {data}");
    let message = data["message"].as_str().expect("message");
    assert!(
        message.starts_with(AUTH_DESTINATION_REFUSED_REMEDY),
        "{base}: the remedy must lead the message: {message}"
    );
    let sentence = message.find(AUTH_DESTINATION_REFUSED_SENTENCE).expect("the plain sentence");
    let model = message.find("\n\n  Model:").expect("the diagnostics block");
    assert!(
        AUTH_DESTINATION_REFUSED_REMEDY.len() < sentence && sentence < model,
        "{base}: remedy, sentence, then diagnostics: {message}"
    );
    assert!(message.contains(&format!("  Endpoint:  {base}")), "{base}: {message}");
    for needle in ["(401)", "Unauthorized (", "status 401", "Unauthorized"] {
        assert!(!message.contains(needle), "{base}: {needle:?} must not appear: {message}");
    }
}

/// P42 (audit round 5, M2): a native subscription attaches its own credential at dispatch, after the sampler
/// recorded `Missing`. Its 401 is a real rejection at the subscription endpoint, never a withheld session, even
/// when the catalogue entry for the same wire slug is credential-less (`NotByok`).
#[tokio::test(flavor = "current_thread")]
async fn p42_subscription_401_is_not_classified_as_a_withheld_session() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            crate::agent::config::Config::install_test_trusted_origins();
            let (_dir, am) = auth_manager_with_valid_token("p42-subscription-session");
            let (actor, _rx) = make_actor_with_method_and_credentials(
                Some(am),
                "cached_token",
                fuigo_chat_state::AuthType::SessionToken,
                String::new(),
            )
            .await;
            const SUBSCRIPTION_URL: &str = "https://chatgpt.com/backend-api/codex";
            let provider = crate::auth::AuthProviderRef::new(
                "native-test".into(),
                crate::auth::AuthProviderConfig {
                    subscription: Some(crate::auth::subscription::SubscriptionProvider::Chatgpt),
                    account: Some("account-a".into()),
                    ..Default::default()
                },
            );
            actor.model_auth_memo.replace(Some(crate::session::acp_session::ModelAuthMemo {
                model_id: String::new(),
                facts: crate::agent::config::ModelAuthFacts {
                    byok: crate::agent::auth_method::ModelByok::NotByok,
                    auth_scheme: Default::default(),
                },
                provider: Some(provider),
            }));
            let error = auth_error_with_credential(fuigo_sampling_types::SentCredential::Missing);
            assert!(
                !actor.session_withheld_401(&error, "", SUBSCRIPTION_URL),
                "a subscription 401 must not be reported as a refused session destination"
            );
        })
        .await;
}

/// P42 (audit round 6, LOW): the subscription exclusion must hold when it comes from CONFIGURATION, with
/// no provider in the memo. Two catalogue entries share one wire slug: a credential-less entry and a
/// subscription entry at the ChatGPT backend. The memo says `NotByok` with provider `None`, so only
/// `selected_for_endpoint` (the endpoint-aware lookup `reconstruct_full_config` uses) can tell that the
/// 401 at the subscription endpoint is a real rejection. The same slug at loopback is still a withheld
/// session (positive control: the selection is by endpoint, not by slug).
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn p42_subscription_selected_by_endpoint_is_not_a_withheld_session() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = tempfile::tempdir().expect("fuigo home");
    std::fs::write(
        home.path().join("config.toml"),
        r#"
[auth_provider.chatgpt]
subscription = "chatgpt"
account = "account-a"
[model.chatgpt]
model = "p42-shared-slug"
base_url = "https://chatgpt.com/backend-api/codex"
auth_provider = "chatgpt"
[model.plain]
model = "p42-shared-slug"
base_url = "http://127.0.0.1:9/v1"
"#,
    )
    .expect("write config.toml");
    let _home = fuigo_test_support::EnvGuard::set("FUIGO_HOME", home.path());
    const SUBSCRIPTION_URL: &str = "https://chatgpt.com/backend-api/codex";
    const LOOPBACK_URL: &str = "http://127.0.0.1:9/v1";
    // Precondition: configuration alone selects the subscription for this endpoint, and only for it.
    assert!(
        crate::auth::subscription::inference::selected_for_endpoint("p42-shared-slug", SUBSCRIPTION_URL)
            .and_then(|p| p.subscription_provider())
            .is_some(),
        "the fixture config must select the subscription at its endpoint"
    );
    assert!(
        crate::auth::subscription::inference::selected_for_endpoint("p42-shared-slug", LOOPBACK_URL)
            .is_none()
    );
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            crate::agent::config::Config::install_test_trusted_origins();
            let (_dir, am) = auth_manager_with_valid_token("p42-subscription-by-endpoint");
            let (actor, _rx) = make_actor_with_method_and_credentials(
                Some(am),
                "cached_token",
                fuigo_chat_state::AuthType::SessionToken,
                String::new(),
            )
            .await;
            actor.model_auth_memo.replace(Some(crate::session::acp_session::ModelAuthMemo {
                model_id: "p42-shared-slug".into(),
                facts: crate::agent::config::ModelAuthFacts {
                    byok: crate::agent::auth_method::ModelByok::NotByok,
                    auth_scheme: Default::default(),
                },
                provider: None,
            }));
            let error = auth_error_with_credential(fuigo_sampling_types::SentCredential::Missing);
            assert!(
                !actor.session_withheld_401(&error, "p42-shared-slug", SUBSCRIPTION_URL),
                "a subscription selected by endpoint must not be reported as a refused session destination"
            );
            assert!(
                actor.session_withheld_401(&error, "p42-shared-slug", LOOPBACK_URL),
                "positive control: the same slug at loopback is a withheld session"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn p4_workflow_child_terminal_keeps_upstream_with_no_top_level_status() {
    tokio::task::LocalSet::new().run_until(async {
        for budgeted in [true,false] {
            let (gateway_tx,_)=tokio::sync::mpsc::unbounded_channel();
            let (persistence_tx,_)=tokio::sync::mpsc::unbounded_channel();
            let mut actor=create_test_actor(50_000,100_000,85,gateway_tx,persistence_tx).await;
            if budgeted {
                actor.tool_context.task_output_token_budget=Some(crate::tools::tool_context::TaskOutputTokenBudget::limited(100_000));
            } else {actor.tool_context.sampler_retry_only_before_output=true;}
            let e=fuigo_sampling_types::SamplingError::Api {
                status:reqwest::StatusCode::TOO_MANY_REQUESTS,message:"refusal".into(),model_metadata:None,
                retry_after_secs:None,should_retry:None,error_code:None,
                upstream_state:Some("free_cap_reached".into()),upstream_type:Some("rate_limit_exceeded".into()),upstream_details:Default::default(),
            };
            let actor=Arc::new(actor);
            let result=actor.handle_sampling_failure(fuigo_sampler::SamplingErrorInfo::from(&e),0,transient_state(0,true),false,TurnParkState::Fresh).await;
            let Err(err)=result else {panic!("child must fail closed");};
            let data=err.data.unwrap();
            assert_eq!(data["upstream"]["state"],"free_cap_reached");
            assert_eq!(data["upstream"]["http_status"],429);
            assert!(data.get("http_status").is_none());
            assert!(data["message"].as_str().unwrap().contains("workflow child model request failed"));
        }
    }).await;
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(attribution_emit_count)]
async fn busyloop_terminal_prompt_blocks_expired_token_preflight_for_helpers() {
    tokio::task::LocalSet::new().run_until(async {
        let called=Arc::new(AtomicBool::new(false));
        let (_dir,am)=auth_manager_with_refresher(Arc::new(AlwaysSucceedRefresher {called:called.clone()}));
        let (actor,_rx)=make_actor_with_auth_and_credentials(Some(am),fuigo_chat_state::AuthType::SessionToken,"initial-test-key".into()).await;
        actor.refusal_prompt.lock().unwrap().state=fuigo_sampling_types::refusal::PromptState::Terminal;
        actor.refresh_token_if_expired().await;
        assert!(!called.load(Ordering::SeqCst),"terminal prompt must not refresh for a helper");
    }).await;
}

#[tokio::test(flavor = "current_thread")]
async fn r3_fa6_static_401_flux_minus_32000_non_flux_parent() {
    tokio::task::LocalSet::new().run_until(async {
        for flux in [false, true] {
            let (actor, _rx) = make_actor_with_auth_and_credentials(None, fuigo_chat_state::AuthType::ApiKey, "static-test-key".into()).await;
            let upstream = fuigo_sampling_types::error::UpstreamError { flux_routed: flux, ..Default::default() }.with_body(401, br#"{"error":{"message":"unauthorized","type":"authentication_error"}}"#);
            let error = fuigo_sampling_types::SamplingError::Auth { message: "Unauthorized (401): unauthorized".into(), status: 401, credential: fuigo_sampling_types::SentCredential::Sent, upstream };
            let result = actor.handle_sampling_failure(fuigo_sampler::SamplingErrorInfo::from(&error), 0, transient_state(0, true), false, TurnParkState::Fresh).await.err().expect("static 401 is terminal");
            let data = result.data.unwrap();
            if flux {
                // FA6: a Flux-routed static-key 401 is an auth failure on the wire (-32000), typed in data.upstream.
                assert_eq!(result.code, acp::Error::auth_required().code);
                assert_eq!(data["upstream"]["http_status"], 401);
                assert_eq!(data["upstream"]["type"], "authentication_error");
            } else {
                assert_eq!(result.code, acp::Error::internal_error().code);
            }
            assert!(data.get("http_status").is_none(), "Auth projection must match 1.0.42");
            assert_eq!(result.message, "Internal error");
            let message = data["message"].as_str().unwrap();
            assert!(message.contains("Model:"), "{message}");
            assert!(message.contains("Auth:"), "{message}");
            assert!(message.contains("Version:"), "{message}");
        }
    }).await;
}

#[tokio::test(flavor = "current_thread")]
async fn r4_rebuilt_child_gate_obeys_parent_stop_and_pause() {
    use fuigo_sampling_types::refusal::{PromptSM, PromptState};
    tokio::task::LocalSet::new().run_until(async {
        let (gateway, _) = mpsc::unbounded_channel();
        let (persist, _) = mpsc::unbounded_channel();
        let mut actor = create_test_actor(50_000, 100_000, 85, gateway, persist).await;
        actor.session_info.id = acp::SessionId::new(format!("r4-child-{}", uuid::Uuid::new_v4()));
        let id = actor.session_info.id.to_string();
        let parent_id = format!("parent-{id}");
        let _parent = crate::session::quiesce::SessionGuard::new(&parent_id, None);
        let _child = crate::session::quiesce::SessionGuard::new(&id, Some(&parent_id));
        let prompt = Arc::new(std::sync::Mutex::new(PromptSM::new(false)));
        super::sampler_turn::bind_refusal_prompt(&parent_id, &prompt);
        super::sampler_turn::bind_refusal_prompt(&id, &actor.refusal_prompt);
        let server = fuigo_test_support::MockInferenceServer::start().await.unwrap();
        for status in [402, 429] {
            prompt.lock().unwrap().state = PromptState::Open;
            actor.refusal_prompt.lock().unwrap().state = PromptState::Open;
            let mut config = actor.reconstruct_full_config(crate::session::acp_session::CallRole::Main).await;
            config.base_url = server.url();
            config.flux_base_url = Some(server.url());
            config.api_backend = fuigo_sampler::ApiBackend::Responses;
            let gate = config.dispatch_gate.as_ref().unwrap().clone();
            assert!(gate.check_open().is_ok());
            server.enqueue_response("/v1/responses", fuigo_test_support::ScriptedResponse::json(status, serde_json::json!({"error":{"message":"refused"}})));
            let client = fuigo_sampler::SamplingClient::new(config).unwrap();
            assert!(client.conversation_stream_responses(fuigo_sampling_types::ConversationRequest::new()).await.is_err());
            assert_eq!(prompt.lock().unwrap().state, PromptState::Open, "a child's own refusal must not end the parent");
            assert_eq!(actor.refusal_prompt.lock().unwrap().state, PromptState::Terminal);
            // Rebuild with an open child after the parent's terminal response.
            actor.refusal_prompt.lock().unwrap().state = PromptState::Open;
            prompt.lock().unwrap().state = PromptState::Terminal;
            let before = server.request_count();
            assert!(gate.check_open().is_err(), "rebuilt child dispatched after parent terminal {status}");
            assert!(client.conversation_stream_responses(fuigo_sampling_types::ConversationRequest::new()).await.is_err());
            assert_eq!(server.request_count(), before, "parent STOP/PAUSE must prevent child POSTs");
        }
        assert_eq!(server.request_count(), 2, "only the two child-own refusals were sent");
    }).await;
}

#[tokio::test(flavor = "current_thread")]
async fn r7_terminal_wakes_are_accepted_without_dispatch() {
    tokio::task::LocalSet::new().run_until(async {
        let (actor, mut rx) = make_actor_with_auth_and_credentials(None, fuigo_chat_state::AuthType::ApiKey, "static-test-key".into()).await;
        let server = fuigo_test_support::MockInferenceServer::start().await.unwrap();
        let mut config = actor.chat_state_handle.get_sampling_config().await.unwrap();
        config.base_url = server.url();
        actor.chat_state_handle.update_sampling_config(config);
        actor.sampler_handle.update_config(actor.reconstruct_full_config(crate::session::acp_session::CallRole::Main).await);
        let dir = tempfile::tempdir().unwrap();
        let writer = fuigo_session_writer::SessionWriter::try_claim("wake-actor-test", dir.path()).unwrap();
        let load_writer = writer.clone();
        let persistence = tokio::task::spawn_local(async move {
            while let Some(message) = rx.recv().await {
                match message {
                    PersistenceMsg::HeldWakes { queue, respond_to } => { let _ = respond_to.send(queue.save(&writer)); }
                    PersistenceMsg::FlushAndAck { respond_to } => { let _ = respond_to.send(Ok(())); }
                    _ => (),
                }
            }
        });
        actor.refusal_prompt.lock().unwrap().state = fuigo_sampling_types::refusal::PromptState::Terminal;
        for origin in [
            crate::session::PromptOrigin::TaskCompleted { task_id: "task".into() },
            crate::session::PromptOrigin::SubagentCompleted { subagent_id: "child".into() },
            crate::session::PromptOrigin::ParentAgentMessage { message_id: "message".into(), sender_session_id: "parent".into() },
            crate::session::PromptOrigin::PeerMessage { message_id: "peer-message".into(), from: "peer".into() },
        ] {
            let request = super::turn_task::TurnInputRequest {
                prompt_id: "held-wake".into(), input_origin: InputOrigin::new(origin),
                prompt_blocks: vec![acp::ContentBlock::Text(acp::TextContent::new("completion payload"))],
                prompt_mode: PromptMode::Agent, trace_gcs_config: None, artifact_tracker: None,
                client_identifier: None, screen_mode: None, verbatim: false, send_now: false,
                json_schema: None, persist_ack: None, parsed_prompt_tx: None, traceparent: None,
            };
            assert!(actor.handle_turn_input(request).await.is_ok(), "terminal wakes must be held, not rejected");
            assert_eq!(actor.refusal_prompt.lock().unwrap().state, fuigo_sampling_types::refusal::PromptState::Terminal);
        }
        assert_eq!(actor.held_wakes.lock().unwrap().wakes.len(), 4);
        assert_eq!(server.request_count(), 0, "held wakes cannot dispatch a POST");
        let saved = super::held_wakes::HeldWakes::load(dir.path(), &load_writer).unwrap();
        assert_eq!(saved.wakes.len(), 4);
        // Simulate a restart by replacing the in-memory queue with its durable read.
        *actor.held_wakes.lock().unwrap() = saved;
        actor.deliver_held_wakes().await.unwrap();
        assert!(actor.held_wakes.lock().unwrap().wakes.is_empty());
        assert!(super::held_wakes::HeldWakes::load(dir.path(), &load_writer).unwrap().wakes.is_empty());
        let messages = actor.chat_state_handle.get_conversation().await;
        let text = serde_json::to_string(&messages).unwrap();
        assert_eq!(text.matches("completion payload").count(), 4);
        let expected = serde_json::to_value(fuigo_sampling_types::ConversationItem::peer_message("completion payload")).unwrap();
        assert!(serde_json::to_value(&messages).unwrap().as_array().unwrap().iter().any(|item| item == &expected), "peer framing must survive holding: {text}");
        assert_eq!(server.request_count(), 0);
        persistence.abort();
    }).await;
}

#[tokio::test(flavor = "current_thread")]
async fn r2_side_refusal_leaves_main_open() {
    tokio::task::LocalSet::new().run_until(async {
        let server = fuigo_test_support::MockInferenceServer::start().await.unwrap();
        let (mut actor, _rx) = make_actor_parts_with_method_and_credentials(None, "fuigo.api_key", fuigo_chat_state::AuthType::ApiKey, "test-key".into()).await;
        actor.session_info.id = acp::SessionId::new(uuid::Uuid::new_v4().to_string());
        let dir = tempfile::tempdir().unwrap();
        let am = Arc::new(AuthManager::new(dir.path(), FuigoComConfig::default()));
        let mut cfg = crate::agent::config::Config::default();
        cfg.endpoints.fuigo_api_base_url = server.url();
        actor.models_manager = crate::agent::models::ModelsManager::new(None, Default::default(), acp::ModelId::new("test"), am, cfg);
        let mut cfg = actor.chat_state_handle.get_sampling_config().await.unwrap();
        cfg.base_url = server.url();
        cfg.api_backend = fuigo_sampler::ApiBackend::Responses;
        actor.chat_state_handle.update_sampling_config(cfg);
        super::sampler_turn::bind_refusal_prompt(&actor.session_info.id.to_string(), &actor.refusal_prompt);
        let side = actor.prepare_side_call().await.unwrap();
        server.enqueue_response("/v1/responses", fuigo_test_support::ScriptedResponse::json(402, serde_json::json!({"error":{"message":"refused"}})));
        assert!(side.client.conversation_stream_responses(fuigo_sampling_types::ConversationRequest::new()).await.is_err());
        assert_eq!(actor.refusal_prompt.lock().unwrap().state, fuigo_sampling_types::refusal::PromptState::Open);
        let main = fuigo_sampler::SamplingClient::new(actor.reconstruct_full_config(crate::session::acp_session::CallRole::Main).await).unwrap();
        assert!(main.conversation_stream_responses(fuigo_sampling_types::ConversationRequest::new()).await.is_ok());
        assert_eq!(server.request_count(), 2);
        actor.refusal_prompt.lock().unwrap().state = fuigo_sampling_types::refusal::PromptState::Terminal;
        assert!(side.client.conversation_stream_responses(fuigo_sampling_types::ConversationRequest::new()).await.is_err());
        assert_eq!(server.request_count(), 2);
    }).await;
}

#[tokio::test(flavor = "current_thread")]
async fn r2_terminal_without_wakes_survives_reload() {
    tokio::task::LocalSet::new().run_until(async {
        let (mut actor, mut rx) = make_actor_parts_with_method_and_credentials(None, "fuigo.api_key", fuigo_chat_state::AuthType::ApiKey, "test-key".into()).await;
        let dir = tempfile::tempdir().unwrap();
        let writer = fuigo_session_writer::SessionWriter::try_claim("terminal-reload", dir.path()).unwrap();
        let load_writer = writer.clone();
        Arc::get_mut(&mut actor.rebuild_spec).unwrap().session_writer = Some(writer.clone());
        let actor = Arc::new(actor);
        let persistence = tokio::task::spawn_local(async move {
            while let Some(message) = rx.recv().await {
                match message {
                    PersistenceMsg::HeldWakes { queue, respond_to } => { let _ = respond_to.send(queue.save(&writer)); }
                    PersistenceMsg::FlushAndAck { respond_to } => { let _ = respond_to.send(Ok(())); }
                    _ => (),
                }
            }
        });
        let error = fuigo_sampling_types::SamplingError::Api {
            status: reqwest::StatusCode::PAYMENT_REQUIRED, message: "refused".into(), model_metadata: None,
            retry_after_secs: None, should_retry: None, error_code: None, upstream_state: None, upstream_type: None,
            upstream_details: fuigo_sampling_types::error::UpstreamError { flux_routed: true, ..Default::default() }.with_body(402, b"{}"),
        };
        assert!(actor.handle_sampling_failure(fuigo_sampler::SamplingErrorInfo::from(&error), 0, transient_state(0, true), false, TurnParkState::Fresh).await.is_err());
        let queue = actor.held_wakes.lock().unwrap();
        assert!(queue.wakes.is_empty());
        assert_eq!(serde_json::to_value(&*queue).unwrap()["terminal"], true, "terminal state must be independent of held content");
        drop(queue);
        let restored = super::held_wakes::HeldWakes::load(dir.path(), &load_writer).unwrap();
        assert_eq!(serde_json::to_value(&restored).unwrap()["terminal"], true);
        // Use the exact session/load initializer, then deliver a completion wake.
        *actor.refusal_prompt.lock().unwrap() = restored.refusal_prompt();
        *actor.held_wakes.lock().unwrap() = restored;
        let server = fuigo_test_support::MockInferenceServer::start().await.unwrap();
        let mut cfg = actor.chat_state_handle.get_sampling_config().await.unwrap();
        cfg.base_url = server.url();
        actor.chat_state_handle.update_sampling_config(cfg);
        let request = super::turn_task::TurnInputRequest {
            prompt_id: "reload-wake".into(),
            input_origin: InputOrigin::new(crate::session::PromptOrigin::TaskCompleted { task_id: "task".into() }),
            prompt_blocks: vec![acp::ContentBlock::Text(acp::TextContent::new("completion"))],
            prompt_mode: PromptMode::Agent, trace_gcs_config: None, artifact_tracker: None,
            client_identifier: None, screen_mode: None, verbatim: false, send_now: false,
            json_schema: None, persist_ack: None, parsed_prompt_tx: None, traceparent: None,
        };
        actor.handle_turn_input(request).await.unwrap();
        assert_eq!(actor.held_wakes.lock().unwrap().wakes.len(), 1);
        assert_eq!(server.request_count(), 0);
        persistence.abort();
    }).await;
}

/// Wire expectations transcribed from 413f407d6, with only the documented Flux deltas.
#[tokio::test(flavor = "current_thread")]
async fn r2_wire_golden_terminal_paths() {
    use fuigo_sampling_types::{SamplingError, SentCredential, error::UpstreamError};
    use serde_json::json;
    tokio::task::LocalSet::new().run_until(async {
        let mut mismatches = Vec::new();
        for flux in [false, true] {
            for (status, session_token) in [(401,false),(401,true),(402,false),(403,false),(429,false),(500,false),(503,false),(529,false),(0,false)] {
                for path in ["prompt", "budgeted_child", "child", "setup", "side", "compact", "legacy"] {
                    let body = br#"{"error":{"message":"refused"}}"#;
                    let upstream = UpstreamError { flux_routed: flux, ..Default::default() }.with_body(status, body);
                    let error = if status == 401 {
                        SamplingError::Auth { message: "Unauthorized (401): refused".into(), status, credential: SentCredential::Sent, upstream }
                    } else if status == 0 {
                        fuigo_sampling_types::error::try_parse_stream_error_for_request(r#"{"error":{"type":"server_error","message":"refused"}}"#, flux).expect("SSE error frame")
                    } else {
                        SamplingError::Api { status: reqwest::StatusCode::from_u16(status).unwrap(), message: "refused".into(), model_metadata: None, retry_after_secs: None, should_retry: None, error_code: None, upstream_state: None, upstream_type: None, upstream_details: upstream }
                    };
                    let display = error.to_string();
                    // Parent events.rs:331 Auth -> None; Api -> status; StreamError -> None.
                    let legacy_status = if status == 0 || status == 401 { None } else { Some(status) };
                    let kind = if status == 401 { "auth" } else if status == 429 { "rate_limited" } else { "api" };
                    let (_auth_dir, am) = auth_manager_with_refresher(Arc::new(AlwaysTransientFailRefresher { called: Arc::new(AtomicBool::new(false)) }));
                    if path == "legacy" {
                        am.hot_swap(FuigoAuth { key: "legacy-test-key".into(), auth_mode: AuthMode::WebLogin, ..FuigoAuth::test_default() });
                    }
                    let manager = (session_token || path == "legacy").then_some(am);
                    let (mut actor, _rx) = make_actor_parts_with_method_and_credentials(manager, if session_token && path != "legacy" { "cached_token" } else { "fuigo.api_key" }, if session_token { fuigo_chat_state::AuthType::SessionToken } else { fuigo_chat_state::AuthType::ApiKey }, "test-key".into()).await;
                    if path == "budgeted_child" { actor.tool_context.task_output_token_budget = Some(crate::tools::tool_context::TaskOutputTokenBudget::limited(100_000)); }
                    if path == "child" { actor.tool_context.sampler_retry_only_before_output = true; }
                    let actor = Arc::new(actor);
                    let (actual, code, message, detail, http_status) = if matches!(path, "setup" | "side" | "compact") {
                        // Parent sampling/error.rs:181-288; side surfacing uses this same mapper.
                        let mapped = crate::sampling::error::map_sampling_err_to_acp(error);
                        let (code, msg, detail, http) = match status {
                            401 => (-32000, "Authentication required", "Unauthorized (401): refused".to_string(), None),
                            403 => (-32603, "Internal error", "refused".to_string(), None),
                            429 => (-32003, "Rate limited", "refused".to_string(), None),
                            529 => (-32603, crate::sampling::error::OVERLOADED_USER_MESSAGE, crate::sampling::error::OVERLOADED_USER_MESSAGE.to_string(), Some(status)),
                            0 => (-32603, "Internal error", "server_error: refused".to_string(), None),
                            _ => (-32603, "Internal error", "refused".to_string(), Some(status)),
                        };
                        if path == "compact" && status == 401 {
                            // Parent compaction.rs:846-884: auth compact returns auth_required, status 401.
                            let actual = actor.surface_compact_auth_failure(mapped).await;
                            (actual, code, msg, detail, Some(401))
                        } else { (mapped, code, msg, detail, http) }
                    } else {
                        let result = actor.handle_sampling_failure(fuigo_sampler::SamplingErrorInfo::from(&error), 0, transient_state(0, false), false, TurnParkState::Fresh).await.err().expect("terminal path");
                        // Parent sampler_turn.rs:1540-1563 (child), 1634-1655 (rate), 1902-1953 (diagnostics), 2027-2033 (generic).
                        let (detail, http) = match path {
                            "budgeted_child" => (format!("budgeted workflow child model request failed; output grant exhausted: {display}"), None),
                            "child" => (format!("workflow child model request failed; usage may understate real spend: {display}"), None),
                            // Parent sampler_turn.rs:1878-1897: legacy auth retains its deprecation text.
                            "legacy" if status != 429 => (format!("{display}\n\nYou are using a deprecated authentication method (WebLogin).\nThis auth method is no longer supported and will cause errors.\n\nTo fix: run `fuigo update`, then `fuigo logout`, then `fuigo login` to re-authenticate with OAuth2.\n\nVersion: {}", fuigo_version::VERSION), None),
                            _ if status == 401 => {
                                let model = actor.chat_state_handle.get_sampling_config().await.unwrap().model;
                                let auth_mode = if session_token { "Oidc" } else { "ApiKey" };
                                let mut detail = format!("{display}\n\n  Model:     {model}\n  Auth:      {auth_mode}\n  Version:   {}\n  Available: (none)", fuigo_version::VERSION);
                                // Parent auth/manager/remedy.rs:56-63, for a refreshable token after a transient failure.
                                if session_token { detail.push_str("\n\nAuthentication is temporarily unavailable (often a network blip right after wake). Your session is still signed in and will recover automatically — retry in a few seconds; no need to run /login."); }
                                (detail, None)
                            },
                            _ if status == 429 => (display.clone(), None),
                            _ => (display.clone(), legacy_status),
                        };
                        let rate = status == 429 && matches!(path, "prompt" | "legacy");
                        let code = if flux && status == 401 { -32000 } else if rate { -32003 } else { -32603 };
                        (result, code, if rate { "Rate limited" } else { "Internal error" }, detail, http)
                    };
                    let mut actual = serde_json::to_value(actual).unwrap();
                    assert!(actual["data"].as_object_mut().unwrap().remove("upstream").is_some());
                    let mut data = json!({"message":detail, "error_kind":kind});
                    if let Some(status) = http_status { data["http_status"] = json!(status); }
                    let expected = json!({"code":code,"message":message,"data":data});
                    if actual != expected { mismatches.push(format!("path={path} flux={flux} status={status} session={session_token}: expected={expected} actual={actual}")); }
                }
            }
        }
        // P1 pin (parent behaviour, kept on purpose): a session token withheld from a refused destination is terminal as
        // -32603 with no data.http_status and kind auth_destination_refused on a Flux host and a non-Flux host alike,
        // because signing in again cannot fix a refused destination.
        crate::agent::config::Config::install_test_trusted_origins();
        let (_withheld_dir, withheld_am) = auth_manager_with_valid_token("golden-withheld-session");
        for flux in [false, true] {
            let (actor, _rx) = make_actor_with_method_and_credentials(Some(withheld_am.clone()), "cached_token", fuigo_chat_state::AuthType::SessionToken, String::new()).await;
            let mut cfg = actor.chat_state_handle.get_sampling_config().await.unwrap();
            cfg.base_url = "http://127.0.0.1:9/v1".to_string();
            cfg.model = String::new();
            actor.chat_state_handle.update_sampling_config(cfg);
            let error = SamplingError::Auth {
                message: "Unauthorized (401): refused".into(), status: 401, credential: SentCredential::Missing,
                upstream: UpstreamError { flux_routed: flux, ..Default::default() }.with_body(401, br#"{"error":{"message":"refused"}}"#),
            };
            let result = actor.handle_sampling_failure(fuigo_sampler::SamplingErrorInfo::from(&error), 0, transient_state(0, false), false, TurnParkState::Fresh).await.err().expect("withheld session is terminal");
            let wire = serde_json::to_value(result).unwrap();
            if wire["code"] != json!(-32603) { mismatches.push(format!("session_withheld flux={flux}: code {}", wire["code"])); }
            if !wire["data"].get("http_status").is_none() { mismatches.push(format!("session_withheld flux={flux}: data.http_status present: {wire}")); }
            if wire["data"]["error_kind"] != json!("auth_destination_refused") { mismatches.push(format!("session_withheld flux={flux}: error_kind {}", wire["data"]["error_kind"])); }
        }
        assert!(mismatches.is_empty(), "wire golden mismatches:\n{}", mismatches.join("\n"));
    }).await;
}

#[tokio::test(flavor = "current_thread")]
async fn r2_wire_golden_setup_auth_helper() {
    tokio::task::LocalSet::new().run_until(async {
        for flux in [false, true] {
            for session in [false, true] {
                let (actor, _rx) = make_actor_with_auth_and_credentials(None, if session { fuigo_chat_state::AuthType::SessionToken } else { fuigo_chat_state::AuthType::ApiKey }, "test-key".into()).await;
                let error = fuigo_sampling_types::SamplingError::Auth {
                    message: "unauthorized".into(), status: 401, credential: fuigo_sampling_types::SentCredential::Sent,
                    upstream: fuigo_sampling_types::error::UpstreamError { flux_routed: flux, ..Default::default() }.with_body(401, b"{}"),
                };
                let mut wire = serde_json::to_value(actor.to_acp_error(error)).unwrap();
                let upstream = wire["data"].as_object_mut().unwrap().remove("upstream").expect("setup must preserve upstream too");
                assert_eq!(upstream["http_status"], 401);
                // 413f407d6 session_setup.rs:12-31 and auth_method.rs:647-650.
                let message = if session { "Session expired. Run `fuigo login` to re-authenticate." } else { "Authentication failed. Run `fuigo login`, set FUIGO_API_KEY, or add api_key to ~/.fuigo/config.toml." };
                assert_eq!(wire, serde_json::json!({"code":-32000,"message":"Authentication required","data":{"message":message,"error_kind":"auth"}}));
            }
        }
    }).await;
}

/// F2: a Flux STOP/PAUSE on the auto-compaction call ends the prompt with THAT classified refusal. No main request follows.
#[tokio::test(flavor = "current_thread")]
async fn f2_compaction_refusal_ends_the_prompt_with_the_classified_error() {
    tokio::task::LocalSet::new().run_until(async {
        for flux in [true, false] {
            let server = fuigo_test_support::MockInferenceServer::start().await.unwrap();
            let (mut actor, _rx) = make_actor_parts_with_method_and_credentials(None, "fuigo.api_key", fuigo_chat_state::AuthType::ApiKey, "test-key".into()).await;
            actor.session_info.id = acp::SessionId::new(uuid::Uuid::new_v4().to_string());
            let mut cfg = actor.chat_state_handle.get_sampling_config().await.unwrap();
            cfg.base_url = server.url();
            cfg.api_backend = fuigo_sampler::ApiBackend::Responses;
            actor.chat_state_handle.update_sampling_config(cfg);
            let _models_dir = tempfile::tempdir().unwrap();
            if flux {
                let am = Arc::new(AuthManager::new(_models_dir.path(), FuigoComConfig::default()));
                let mut endpoints_cfg = crate::agent::config::Config::default();
                endpoints_cfg.endpoints.fuigo_api_base_url = server.url();
                actor.models_manager = crate::agent::models::ModelsManager::new(None, Default::default(), acp::ModelId::new("test"), am, endpoints_cfg);
            }
            actor.chat_state_handle.replace_conversation(vec![
                fuigo_sampling_types::ConversationItem::system("sys"),
                fuigo_sampling_types::ConversationItem::user("first request"),
                fuigo_sampling_types::ConversationItem::user("second request"),
            ]);
            let actor = Arc::new(actor);
            let id = actor.session_info.id.to_string();
            super::sampler_turn::bind_refusal_prompt(&id, &actor.refusal_prompt);
            server.enqueue_response("/v1/responses", fuigo_test_support::ScriptedResponse::json(402, serde_json::json!({"error":{"message":"refused"}})));
            let trigger = super::compaction::AutoCompactTriggerInfo { tokens_used: 90_000, context_window: 100_000, percentage: 90 };
            let err = actor.run_compact_only(trigger, false).await.err().expect("a refused compaction fails");
            let wire = serde_json::to_value(&err).unwrap();
            assert_eq!(server.request_count(), 1, "flux={flux}: exactly one compaction POST");
            if flux {
                assert_eq!(wire["code"], serde_json::json!(-32603), "{wire}");
                assert_eq!(wire["message"], serde_json::json!("Internal error"), "{wire}");
                assert_eq!(wire["data"]["upstream"]["http_status"], serde_json::json!(402), "{wire}");
                assert_eq!(wire["data"]["error_kind"], serde_json::json!("api"), "{wire}");
                assert_eq!(wire["data"]["http_status"], serde_json::json!(402), "{wire}");
                assert!(actor.is_terminal_prompt_refusal(&err), "{wire}");
                assert_eq!(actor.refusal_prompt.lock().unwrap().state, fuigo_sampling_types::refusal::PromptState::Terminal);
                let main = actor.reconstruct_full_config(crate::session::acp_session::CallRole::Main).await;
                assert!(main.dispatch_gate.as_ref().unwrap().check_open().is_err(), "the main request is still blocked");
                assert_eq!(server.request_count(), 1, "0 main POSTs");
            } else {
                // Parent behaviour: a compaction failure the caller logs and continues from.
                assert!(!actor.is_terminal_prompt_refusal(&err), "{wire}");
                assert_eq!(wire["data"]["error_kind"], serde_json::json!("compaction"), "{wire}");
                assert_eq!(actor.refusal_prompt.lock().unwrap().state, fuigo_sampling_types::refusal::PromptState::Open);
            }
        }
    }).await;
}

/// F3: a legacy held-wake file keeps every readable entry; only an unreadable ENTRY is dropped.
#[test]
fn f3_legacy_held_wakes_drop_only_the_unreadable_entry() {
    let dir = tempfile::tempdir().unwrap();
    let entry = |id: &str, origin: &str| serde_json::json!({"prompt_id": id, "origin": origin, "blocks": []});
    let file = serde_json::json!({"wakes": [
        entry("a", "SchedulerFired"),
        entry("b", "NotificationDrain"),
        entry("c", "SomethingFromTheFuture { x: 1 }"),
        entry("d", "TaskCompleted { task_id: \"t\" }"),
        entry("e", "GoalSummary"),
    ]});
    std::fs::write(dir.path().join(super::held_wakes::HELD_WAKE_FILE), serde_json::to_vec(&file).unwrap()).unwrap();
    let writer = fuigo_session_writer::SessionWriter::try_claim("f3-legacy", dir.path()).unwrap();
    let loaded = super::held_wakes::HeldWakes::load(dir.path(), &writer).unwrap();
    let ids: Vec<_> = loaded.wakes.iter().map(|w| w.prompt_id.as_str()).collect();
    assert_eq!(ids, ["a", "b", "d", "e"]);
    assert!(loaded.terminal, "a legacy file with wakes keeps the prompt terminal");
    assert!(!dir.path().join("held_wakes.json.bad").exists(), "the file is not quarantined");
}

/// F5: a `terminal` field that is present but not a bool is a file-level error: quarantine, start terminal.
#[test]
fn f5_non_bool_terminal_field_quarantines_the_held_wakes_file() {
    for terminal in [serde_json::json!("false"), serde_json::json!(0), serde_json::json!(null)] {
        let dir = tempfile::tempdir().unwrap();
        let file = serde_json::json!({"terminal": terminal, "wakes": []});
        std::fs::write(dir.path().join(super::held_wakes::HELD_WAKE_FILE), serde_json::to_vec(&file).unwrap()).unwrap();
        let writer = fuigo_session_writer::SessionWriter::try_claim("f5-non-bool", dir.path()).unwrap();
        let loaded = super::held_wakes::HeldWakes::load(dir.path(), &writer).unwrap();
        assert!(loaded.terminal, "terminal={terminal}: must start terminal, not read as false");
        assert!(dir.path().join("held_wakes.json.bad").exists(), "terminal={terminal}: quarantined");
        assert!(!dir.path().join(super::held_wakes::HELD_WAKE_FILE).exists());
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(super::held_wakes::HELD_WAKE_FILE), br#"{"terminal":false,"wakes":[]}"#).unwrap();
    let writer = fuigo_session_writer::SessionWriter::try_claim("f5-real-bool", dir.path()).unwrap();
    let loaded = super::held_wakes::HeldWakes::load(dir.path(), &writer).unwrap();
    assert!(!loaded.terminal && !dir.path().join("held_wakes.json.bad").exists(), "a real bool stays valid");
}

/// A session whose auto-compaction call gets a scripted 401, with the Flux endpoint (or not) pointing at the mock.
async fn compaction_401_actor(flux: bool) -> (Arc<SessionActor>, fuigo_test_support::MockInferenceServer, tempfile::TempDir) {
    let server = fuigo_test_support::MockInferenceServer::start().await.unwrap();
    let (mut actor, _rx) = make_actor_parts_with_method_and_credentials(None, "fuigo.api_key", fuigo_chat_state::AuthType::ApiKey, "test-key".into()).await;
    actor.session_info.id = acp::SessionId::new(uuid::Uuid::new_v4().to_string());
    let mut cfg = actor.chat_state_handle.get_sampling_config().await.unwrap();
    cfg.base_url = server.url();
    cfg.api_backend = fuigo_sampler::ApiBackend::Responses;
    actor.chat_state_handle.update_sampling_config(cfg);
    let dir = tempfile::tempdir().unwrap();
    if flux {
        let am = Arc::new(AuthManager::new(dir.path(), FuigoComConfig::default()));
        let mut endpoints_cfg = crate::agent::config::Config::default();
        endpoints_cfg.endpoints.fuigo_api_base_url = server.url();
        actor.models_manager = crate::agent::models::ModelsManager::new(None, Default::default(), acp::ModelId::new("test"), am, endpoints_cfg);
    }
    actor.chat_state_handle.replace_conversation(vec![
        fuigo_sampling_types::ConversationItem::system("sys"),
        fuigo_sampling_types::ConversationItem::user("first request"),
        fuigo_sampling_types::ConversationItem::user("second request"),
    ]);
    let actor = Arc::new(actor);
    super::sampler_turn::bind_refusal_prompt(&actor.session_info.id.to_string(), &actor.refusal_prompt);
    server.enqueue_response("/v1/responses", fuigo_test_support::ScriptedResponse::json(401, serde_json::json!({"error":{"message":"unauthorized","type":"authentication_error"}})));
    (actor, server, dir)
}

/// The wire error of an inline auto-compaction whose model call got a 401, and the POSTs the server saw.
async fn inline_compaction_401_wire(flux: bool) -> (serde_json::Value, u32) {
    let (actor, server, _dir) = compaction_401_actor(flux).await;
    let trigger = super::compaction::AutoCompactTriggerInfo { tokens_used: 90_000, context_window: 100_000, percentage: 90 };
    let err = actor.run_compact_only(trigger, false).await.err().expect("a refused compaction fails");
    (serde_json::to_value(&err).unwrap(), server.request_count())
}

/// The wire error of a main call that overflowed the context window, whose compaction then got a 401 (F4).
async fn overflow_compaction_401_wire(flux: bool) -> (serde_json::Value, u32, bool) {
    let (actor, server, _dir) = compaction_401_actor(flux).await;
    let overflow = fuigo_sampling_types::SamplingError::Api {
        status: reqwest::StatusCode::BAD_REQUEST,
        message: "This model's maximum context length is 8192 tokens, however you requested 9000 tokens (context length exceeded)".into(),
        model_metadata: None, retry_after_secs: None, should_retry: None, error_code: None, upstream_state: None, upstream_type: None,
        upstream_details: Default::default(),
    };
    let err = actor.handle_sampling_failure(fuigo_sampler::SamplingErrorInfo::from(&overflow), 0, transient_state(0, false), false, TurnParkState::Fresh).await.err().expect("the compaction 401 ends the turn");
    let main = actor.reconstruct_full_config(crate::session::acp_session::CallRole::Main).await;
    let main_blocked = main.dispatch_gate.as_ref().unwrap().check_open().is_err();
    (serde_json::to_value(&err).unwrap(), server.request_count(), main_blocked)
}

/// F4, Flux: a compaction 401 after a context overflow ends the prompt as the classified Flux 401, not a re-auth prompt.
#[tokio::test(flavor = "current_thread")]
async fn f4_overflow_compaction_401_on_flux_is_the_classified_prompt_error() {
    tokio::task::LocalSet::new().run_until(async {
        let (wire, posts, main_blocked) = overflow_compaction_401_wire(true).await;
        assert_eq!(wire["code"], serde_json::json!(-32000), "{wire}");
        assert_eq!(wire["message"], serde_json::json!("Internal error"), "{wire}");
        assert_eq!(wire["data"]["upstream"]["http_status"], serde_json::json!(401), "{wire}");
        assert!(wire["data"].get("http_status").is_none(), "no client re-auth key: {wire}");
        assert_eq!(posts, 1, "the compaction POST only; 0 main POSTs after it");
        assert!(main_blocked, "the main request stays blocked");
    }).await;
}

/// F4, non-Flux: the parent's surface_compact_auth_failure output, unchanged.
#[tokio::test(flavor = "current_thread")]
async fn f4_overflow_compaction_401_off_flux_keeps_the_parent_auth_failure() {
    tokio::task::LocalSet::new().run_until(async {
        let (wire, posts, _) = overflow_compaction_401_wire(false).await;
        assert_eq!(wire["code"], serde_json::json!(-32000), "{wire}");
        assert_eq!(wire["data"]["error_kind"], serde_json::json!("auth"), "{wire}");
        assert_eq!(wire["data"]["http_status"], serde_json::json!(401), "{wire}");
        assert_eq!(posts, 1, "{wire}");
    }).await;
}

/// Wire-golden rows for Flux 401s that end a prompt through compaction, and the sign-in signal's one legitimate source.
#[tokio::test(flavor = "current_thread")]
async fn r3_wire_golden_flux_401_rows_and_signin_signal() {
    tokio::task::LocalSet::new().run_until(async {
        // (a) Flux: -32000 with data.upstream.http_status 401 for the inline and the overflow compaction 401.
        let (inline, _) = inline_compaction_401_wire(true).await;
        let (overflow, _, _) = overflow_compaction_401_wire(true).await;
        for (name, wire) in [("inline_compaction", &inline), ("overflow_compaction", &overflow)] {
            assert_eq!(wire["code"], serde_json::json!(-32000), "{name}: {wire}");
            assert_eq!(wire["data"]["upstream"]["http_status"], serde_json::json!(401), "{name}: {wire}");
            assert!(wire["data"].get("http_status").is_none(), "{name}: {wire}");
        }
        // (b) Off Flux the compaction 401 carries the parent's values: the inline error is a compaction failure the
        // caller remaps; the overflow path surfaces the auth failure with the status a re-auth prompt keys off,
        // because a credential WAS sent and got the 401.
        let (inline_off, _) = inline_compaction_401_wire(false).await;
        assert_eq!(inline_off["data"]["error_kind"], serde_json::json!("compaction"), "{inline_off}");
        let (overflow_off, _, _) = overflow_compaction_401_wire(false).await;
        assert_eq!(overflow_off["data"]["error_kind"], serde_json::json!("auth"), "{overflow_off}");
        assert_eq!(overflow_off["data"]["http_status"], serde_json::json!(401), "{overflow_off}");
        // (c) A withheld session token (nothing sent) never produces the sign-in signal, on either host: the P1 row.
        crate::agent::config::Config::install_test_trusted_origins();
        let (_dir, am) = auth_manager_with_valid_token("golden-signin-withheld");
        for flux in [false, true] {
            let (actor, _rx) = make_actor_with_method_and_credentials(Some(am.clone()), "cached_token", fuigo_chat_state::AuthType::SessionToken, String::new()).await;
            let mut cfg = actor.chat_state_handle.get_sampling_config().await.unwrap();
            cfg.base_url = "http://127.0.0.1:9/v1".to_string();
            cfg.model = String::new();
            actor.chat_state_handle.update_sampling_config(cfg);
            let error = fuigo_sampling_types::SamplingError::Auth {
                message: "Unauthorized (401): refused".into(), status: 401, credential: fuigo_sampling_types::SentCredential::Missing,
                upstream: fuigo_sampling_types::error::UpstreamError { flux_routed: flux, ..Default::default() }.with_body(401, br#"{"error":{"message":"refused"}}"#),
            };
            let err = actor.handle_sampling_failure(fuigo_sampler::SamplingErrorInfo::from(&error), 0, transient_state(0, false), false, TurnParkState::Fresh).await.err().expect("withheld session is terminal");
            let wire = serde_json::to_value(err).unwrap();
            assert_eq!(wire["code"], serde_json::json!(-32603), "flux={flux}: {wire}");
            assert!(wire["data"].get("http_status").is_none(), "flux={flux}: {wire}");
            assert_eq!(wire["data"]["error_kind"], serde_json::json!("auth_destination_refused"), "flux={flux}: {wire}");
        }
    }).await;
}
