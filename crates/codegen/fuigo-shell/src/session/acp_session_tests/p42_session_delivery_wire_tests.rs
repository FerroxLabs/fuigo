//! P42: session-token delivery has one predicate — wire-level proof.
//!
//! Each test re-runs itself in a fresh process (`fresh_process_home`) because the proxy and CA
//! variables the wire harness installs latch when the first HTTP client is built. The child drives a
//! real `SessionActor` (or the real credential functions) and a real `SamplingClient`, and asserts on
//! the `Authorization` header the destination recorded. Every negative test also asserts that the
//! request DID arrive, so "no token" can never be the vacuous result of "no request".
use super::support::*;
use super::*;
use crate::auth::{AuthManager, AuthMode, FuigoAuth, FuigoComConfig};
use crate::test_support::session_wire::{CONFIGURED_HOST, Observed, SessionWire, token_arrived};
use std::sync::Arc;
use tokio::sync::mpsc;

const TOKEN: &str = "p42-session-token-7f3a";
const EXPIRED: &str = "p42-hard-expired-token-91c2";
const CONFIGURED: &str = "https://api.fluxrouter.ai/v1";
const CLEARTEXT: &str = "http://api.fluxrouter.ai/v1";
const OTHER_PORT: &str = "https://api.fluxrouter.ai:8443/v1";
const UNLISTED_MODEL: &str = "p42-model-absent-from-the-catalogue";
/// Empty model id classifies as `ModelByok::Unknown` (`resolve_model_auth_facts_and_provider`).
const UNKNOWN_MODEL: &str = "";
const MODULE: &str = "session::acp_session::p42_session_delivery_wire_tests::";

fn child(test: &str) -> bool {
    fuigo_test_support::env::fresh_process_home(&format!("{MODULE}{test}")).is_some()
}

fn manager(key: &str, valid: bool) -> (tempfile::TempDir, Arc<AuthManager>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let am = Arc::new(AuthManager::new(dir.path(), FuigoComConfig::default()));
    let offset = chrono::Duration::hours(1);
    am.hot_swap(FuigoAuth {
        key: key.into(),
        auth_mode: AuthMode::Oidc,
        refresh_token: Some("rt".into()),
        expires_at: Some(if valid {
            chrono::Utc::now() + offset
        } else {
            chrono::Utc::now() - offset
        }),
        ..FuigoAuth::test_default()
    });
    (dir, am)
}

/// Preconditions every child relies on; a wrong fixture fails loudly instead of passing vacuously.
fn preconditions() {
    crate::agent::config::Config::install_test_trusted_origins();
    use crate::auth::session_delivery::session_may_reach;
    assert!(session_may_reach(CONFIGURED), "fixture: configured origin");
    assert!(!session_may_reach(CLEARTEXT), "fixture: cleartext refused");
    assert!(!session_may_reach(OTHER_PORT), "fixture: other port refused");
    assert!(!session_may_reach("http://127.0.0.1:9/v1"), "fixture: loopback refused");
    assert!(
        crate::util::is_fuigo_api_url(CLEARTEXT)
            && crate::util::is_fuigo_api_url(OTHER_PORT)
            && crate::util::is_fuigo_api_url("http://127.0.0.1:9/v1"),
        "fixture: the broad matcher admits all three (that was the defect)"
    );
}

fn byok(model: &str) -> crate::agent::auth_method::ModelByok {
    crate::agent::config::resolve_model_auth_facts_and_provider(model)
        .0
        .byok
}

fn sampling(base_url: &str, model: &str) -> fuigo_sampling_types::SamplingConfig {
    fuigo_sampling_types::SamplingConfig {
        base_url: base_url.to_string(),
        model: model.to_string(),
        max_completion_tokens: None,
        temperature: None,
        top_p: None,
        max_retries: Some(0),
        api_backend: Default::default(),
        extra_headers: Default::default(),
        query_params: Default::default(),
        env_http_headers: Default::default(),
        context_window: std::num::NonZeroU64::new(256_000).unwrap(),
        reasoning_effort: None,
        stream_tool_calls: None,
        mtls_cert_dir: None,
        rate_limit_retry_threshold: None,
        reasoning_summary: None,
    }
}

async fn session_actor(
    am: Arc<AuthManager>,
    base_url: &str,
    model: &str,
    buffered: Option<&str>,
) -> Arc<SessionActor> {
    let (gateway_tx, _) = mpsc::unbounded_channel();
    let (persistence_tx, _) = mpsc::unbounded_channel();
    let mut actor = create_test_actor(50_000, 100_000, 85, gateway_tx, persistence_tx).await;
    actor.auth_manager = Some(am);
    actor.auth_method_id = test_auth_method_id("cached_token");
    actor.max_retries = 0;
    actor
        .chat_state_handle
        .update_sampling_config(sampling(base_url, model));
    actor
        .chat_state_handle
        .update_credentials(fuigo_chat_state::Credentials {
            api_key: buffered.map(str::to_owned),
            auth_type: fuigo_chat_state::AuthType::SessionToken,
            ..Default::default()
        });
    Arc::new(actor)
}

fn request() -> fuigo_sampling_types::ConversationRequest {
    use fuigo_sampling_types::{ContentPart, ConversationItem, ConversationRequest, UserItem};
    ConversationRequest {
        items: vec![ConversationItem::User(UserItem {
            content: vec![ContentPart::Text {
                text: Arc::<str>::from("p42"),
            }],
            ..Default::default()
        })],
        ..Default::default()
    }
}

/// One turn's sampler, exactly as the turn builds it, sent once.
async fn send_turn(actor: &Arc<SessionActor>) {
    let client = actor
        .prepare_chat_completion(true)
        .await
        .expect("turn sampler builds");
    let _ = client.conversation(request()).await;
}

async fn send_config(cfg: fuigo_sampler::SamplerConfig) {
    let mut cfg = cfg;
    cfg.force_http1 = true;
    cfg.max_retries = Some(0);
    let client = fuigo_sampler::SamplingClient::new(cfg).expect("sampler builds");
    let _ = client.conversation(request()).await;
}

fn assert_withheld(seen: &[Observed], what: &str) {
    assert!(!seen.is_empty(), "{what}: the request must reach the destination (else the test is vacuous)");
    assert!(
        !token_arrived(seen, TOKEN) && !token_arrived(seen, EXPIRED),
        "{what}: the session token reached a destination that may not receive it: {seen:?}"
    );
}

fn assert_delivered(seen: &[Observed], what: &str) {
    assert!(
        seen.iter().any(|o| o.target.starts_with(&format!("https://{CONFIGURED_HOST}"))
            && o.authorization.as_deref() == Some(&format!("Bearer {TOKEN}"))),
        "{what}: the configured origin must receive the session token: {seen:?}"
    );
}

fn run(f: impl std::future::Future<Output = ()>) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tokio::task::LocalSet::new().block_on(&rt, f);
}

/// Positive control: a correctly configured origin still gets the session token.
#[test]
fn p42_wire_session_token_reaches_the_configured_origin() {
    if !child("p42_wire_session_token_reaches_the_configured_origin") {
        return;
    }
    run(async {
        let mut wire = SessionWire::start().await;
        preconditions();
        assert_eq!(byok(UNLISTED_MODEL), crate::agent::auth_method::ModelByok::NotByok);
        let (_d, am) = manager(TOKEN, true);
        let actor = session_actor(am, CONFIGURED, UNLISTED_MODEL, None).await;
        send_turn(&actor).await;
        assert_delivered(&wire.observed().await, "configured origin");
    });
}

/// Unknown BYOK on `http://<configured host>`: the old gate asked the broad matcher and delivered.
#[test]
fn p42_wire_cleartext_url_never_receives_the_session_token() {
    if !child("p42_wire_cleartext_url_never_receives_the_session_token") {
        return;
    }
    run(async {
        let mut wire = SessionWire::start().await;
        preconditions();
        assert_eq!(byok(UNKNOWN_MODEL), crate::agent::auth_method::ModelByok::Unknown);
        let (_d, am) = manager(TOKEN, true);
        let actor = session_actor(am, CLEARTEXT, UNKNOWN_MODEL, None).await;
        send_turn(&actor).await;
        assert_withheld(&wire.observed().await, "cleartext");
    });
}

/// Unknown BYOK on `https://<configured host>:8443`.
#[test]
fn p42_wire_other_port_never_receives_the_session_token() {
    if !child("p42_wire_other_port_never_receives_the_session_token") {
        return;
    }
    run(async {
        let mut wire = SessionWire::start().await;
        preconditions();
        let (_d, am) = manager(TOKEN, true);
        let actor = session_actor(am, OTHER_PORT, UNKNOWN_MODEL, None).await;
        send_turn(&actor).await;
        let seen = wire.observed().await;
        assert!(seen.iter().any(|o| o.target.contains(":8443")), "{seen:?}");
        assert_withheld(&seen, "other port");
    });
}

/// Unknown BYOK on a loopback URL that is not configured.
#[test]
fn p42_wire_unconfigured_loopback_never_receives_the_session_token() {
    if !child("p42_wire_unconfigured_loopback_never_receives_the_session_token") {
        return;
    }
    run(async {
        let mut wire = SessionWire::start().await;
        preconditions();
        let (_d, am) = manager(TOKEN, true);
        let actor = session_actor(am, &wire.loopback_url(), UNKNOWN_MODEL, None).await;
        send_turn(&actor).await;
        assert_withheld(&wire.observed().await, "unconfigured loopback");
    });
}

/// A model absent from the catalogue is classed `NotByok`, which used to deliver with no destination check.
#[test]
fn p42_wire_notbyok_model_absent_from_the_catalogue_never_receives_the_session_token() {
    if !child("p42_wire_notbyok_model_absent_from_the_catalogue_never_receives_the_session_token") {
        return;
    }
    run(async {
        let mut wire = SessionWire::start().await;
        preconditions();
        assert_eq!(byok(UNLISTED_MODEL), crate::agent::auth_method::ModelByok::NotByok);
        let (_d, am) = manager(TOKEN, true);
        let actor = session_actor(am, &wire.loopback_url(), UNLISTED_MODEL, None).await;
        send_turn(&actor).await;
        assert_withheld(&wire.observed().await, "NotByok, absent from catalogue");
    });
}

/// A token buffered by an earlier turn at the configured origin must not follow the session to a new,
/// refused destination (here: the config became unparseable, so BYOK is `Unknown`, and the resolver is withheld).
#[test]
fn p42_wire_buffered_token_is_rechecked_after_the_destination_changes() {
    if !child("p42_wire_buffered_token_is_rechecked_after_the_destination_changes") {
        return;
    }
    run(async {
        let mut wire = SessionWire::start().await;
        preconditions();
        let (_d, am) = manager(TOKEN, true);
        let actor = session_actor(am, CONFIGURED, UNLISTED_MODEL, None).await;
        send_turn(&actor).await;
        assert_delivered(&wire.observed().await, "turn 1");
        assert_eq!(
            actor.chat_state_handle.get_credentials().await.api_key.as_deref(),
            Some(TOKEN),
            "turn 1 must have buffered the session token in chat-state credentials"
        );
        actor
            .chat_state_handle
            .update_sampling_config(sampling(&wire.loopback_url(), UNKNOWN_MODEL));
        send_turn(&actor).await;
        assert_withheld(&wire.observed().await, "turn 2 after the destination changed");
    });
}

/// The P30 regression: withdrawing the resolver must not leave a buffered hard-expired token on the wire.
#[test]
fn p42_wire_buffered_hard_expired_token_is_withheld_from_a_refused_destination() {
    if !child("p42_wire_buffered_hard_expired_token_is_withheld_from_a_refused_destination") {
        return;
    }
    run(async {
        let mut wire = SessionWire::start().await;
        preconditions();
        let (_d, am) = manager(EXPIRED, false);
        let actor = session_actor(am, &wire.loopback_url(), UNKNOWN_MODEL, Some(EXPIRED)).await;
        send_turn(&actor).await;
        assert_withheld(&wire.observed().await, "buffered hard-expired token, refused destination");
    });
}

/// Preserved: at an origin that may receive the session, a hard-expired token is still stripped.
#[test]
fn p42_wire_hard_expired_token_is_still_stripped_at_the_configured_origin() {
    if !child("p42_wire_hard_expired_token_is_still_stripped_at_the_configured_origin") {
        return;
    }
    run(async {
        let mut wire = SessionWire::start().await;
        preconditions();
        let (_d, am) = manager(EXPIRED, false);
        let actor = session_actor(am, CONFIGURED, UNLISTED_MODEL, Some(EXPIRED)).await;
        send_turn(&actor).await;
        assert_withheld(&wire.observed().await, "hard-expired token at the configured origin");
    });
}

/// Kill switch: refusing a key by the broad matcher must not substitute the session where it may not go.
#[test]
fn p42_wire_kill_switch_substitutes_the_session_only_where_it_may_go() {
    if !child("p42_wire_kill_switch_substitutes_the_session_only_where_it_may_go") {
        return;
    }
    run(async {
        let mut wire = SessionWire::start().await;
        preconditions();
        let (_d, _am) = manager(TOKEN, true);
        for base in [wire.loopback_url(), CLEARTEXT.to_string(), OTHER_PORT.to_string(), CONFIGURED.to_string()] {
            let mut creds = crate::agent::config::ResolvedCredentials {
                api_key: Some("p42-own-first-party-key".into()),
                base_url: base.clone(),
                auth_type: fuigo_chat_state::AuthType::ApiKey,
                auth_scheme: Default::default(),
            };
            crate::agent::config::enforce_disable_api_key_auth(&mut creds, true, Some(TOKEN));
            send_config(fuigo_sampler::SamplerConfig {
                api_key: creds.api_key,
                base_url: creds.base_url,
                model: "p42-kill-switch".into(),
                ..Default::default()
            })
            .await;
            let seen = wire.observed().await;
            assert!(!token_arrived(&seen, "p42-own-first-party-key"), "{base}: key must be refused");
            if base == CONFIGURED {
                assert_delivered(&seen, "kill switch at the configured origin");
            } else {
                assert_withheld(&seen, &format!("kill switch at {base}"));
            }
        }
    });
}

/// Aux-model fallback puts the bearer in a synthetic entry's own `api_key`, which bypasses the static check.
#[test]
fn p42_wire_aux_fallback_bearer_respects_the_destination() {
    if !child("p42_wire_aux_fallback_bearer_respects_the_destination") {
        return;
    }
    run(async {
        let mut wire = SessionWire::start().await;
        preconditions();
        let models = indexmap::IndexMap::new();
        for (base, expect) in [(wire.loopback_url(), false), (CONFIGURED.to_string(), true)] {
            let endpoints = crate::agent::config::EndpointsConfig {
                models_base_url: Some(base.clone()),
                deployment_key: None,
                ..Default::default()
            };
            let resolved = crate::agent::config::resolve_aux_model_sampling_config(
                "p42-aux-model", &models, &endpoints, Some(TOKEN), false, None, None, &crate::agent::models::EffectiveAllowlist::Unrestricted,
            );
            match resolved {
                Some(cfg) => send_config(cfg).await,
                None => assert!(!expect, "{base}: the configured origin must resolve a sampler"),
            }
            let seen = wire.observed().await;
            if expect {
                assert_delivered(&seen, "aux fallback at the configured origin");
            } else {
                assert!(!token_arrived(&seen, TOKEN), "aux fallback at {base}: {seen:?}");
            }
        }
    });
}

/// The idle `/models-v2` metadata refresh sends the session to the model's own base URL.
#[test]
fn p42_wire_models_v2_refresh_does_not_send_the_session_to_loopback() {
    if !child("p42_wire_models_v2_refresh_does_not_send_the_session_to_loopback") {
        return;
    }
    run(async {
        let mut wire = SessionWire::start().await;
        preconditions();
        let (_d, am) = manager(TOKEN, true);
        let actor = session_actor(am, &wire.loopback_url(), UNLISTED_MODEL, None).await;
        actor.last_api_request_at.store(
            chrono::Utc::now().timestamp_millis() - 86_400_000,
            std::sync::atomic::Ordering::Relaxed,
        );
        actor.maybe_refresh_model_metadata_on_resume().await;
        let seen = wire.observed().await;
        assert!(!token_arrived(&seen, TOKEN), "/models-v2 at loopback: {seen:?}");
    });
}

/// The model-catalogue fetch's session fallback (custom models endpoint, no `FUIGO_API_KEY`).
#[test]
fn p42_wire_model_catalogue_fetch_does_not_fall_back_to_the_session_at_loopback() {
    if !child("p42_wire_model_catalogue_fetch_does_not_fall_back_to_the_session_at_loopback") {
        return;
    }
    run(async {
        let mut wire = SessionWire::start().await;
        preconditions();
        for (url, ok) in [
            (format!("{}/models", wire.loopback_url()), false),
            ("https://api.fluxrouter.ai/v1/models".to_string(), true),
        ] {
            let endpoints = crate::agent::config::EndpointsConfig {
                models_list_url: Some(url.clone()),
                ..Default::default()
            };
            let auth = FuigoAuth {
                key: TOKEN.into(),
                ..FuigoAuth::test_default()
            };
            let result = tokio::task::spawn_blocking(move || {
                use crate::remote::ModelSource;
                let source = crate::remote::active_model_source(
                    &endpoints,
                    crate::agent::models::ModelFetchAuth::CustomEndpoint,
                );
                source.fetch(Some(&auth)).map(|_| ())
            })
            .await
            .expect("fetch worker completes");
            let seen = wire.observed().await;
            if ok {
                assert_delivered(&seen, "catalogue fetch at the configured origin");
            } else {
                assert!(
                    matches!(result, Err(crate::remote::client::BackendError::Auth(_))),
                    "{url}: the fetch must refuse for want of a credential, got {result:?}"
                );
                assert!(seen.is_empty(), "{url}: nothing may be sent: {seen:?}");
            }
        }
    });
}

/// Image/video/voice credential arm: `credential_recipient_matches` admits a configured https LOOPBACK origin,
/// so the session token also needs the one predicate there (audit H2).
#[test]
fn p42_auxiliary_credential_arm_refuses_the_session_at_configured_https_loopback() {
    if !child("p42_auxiliary_credential_arm_refuses_the_session_at_configured_https_loopback") {
        return;
    }
    run(async {
        let _wire = SessionWire::start().await;
        preconditions();
        let home = std::path::PathBuf::from(std::env::var_os("FUIGO_HOME").expect("child home"));
        let (_d, am) = manager(TOKEN, true);
        for (base, expect) in [
            ("https://localhost:8443/v1", None),
            ("https://127.0.0.1:8443/v1", None),
            ("https://api.fluxrouter.ai/v1", Some(TOKEN)),
        ] {
            std::fs::write(
                home.join("config.toml"),
                format!("[endpoints]\nfuigo_api_base_url = \"{base}\"\n"),
            )
            .unwrap();
            let key = am.voice_api_key_for(&format!("{base}/audio/transcriptions")).await;
            assert_eq!(key.as_deref(), expect, "{base}");
        }
    });
}

/// `/tokenize-text` takes the session token (or the buffered key) to `fuigo_api_base_url`.
#[test]
fn p42_tokenize_key_follows_the_one_predicate() {
    if !child("p42_tokenize_key_follows_the_one_predicate") {
        return;
    }
    run(async {
        let _wire = SessionWire::start().await;
        preconditions();
        let (_d, am) = manager(TOKEN, true);
        let actor = session_actor(am, CONFIGURED, UNLISTED_MODEL, Some(TOKEN)).await;
        assert_eq!(
            actor.p42_tokenize_api_key("https://api.fluxrouter.ai/v1/tokenize-text").await.as_deref(),
            Some(TOKEN)
        );
        for url in [
            "http://api.fluxrouter.ai/v1/tokenize-text",
            "https://api.fluxrouter.ai:8443/v1/tokenize-text",
            "http://127.0.0.1:9/v1/tokenize-text",
        ] {
            assert_eq!(actor.p42_tokenize_api_key(url).await, None, "{url}");
        }
    });
}

/// Memory embeddings seed their static key from the spawn sampler (audit round 2, H1).
#[test]
fn p42_memory_embed_key_is_rechecked_against_the_destination() {
    crate::agent::config::Config::install_test_trusted_origins();
    let (_d, am) = manager(TOKEN, true);
    let cfg = |base: &str, key: &str| fuigo_sampler::SamplerConfig {
        api_key: Some(key.into()),
        base_url: base.into(),
        ..Default::default()
    };
    for refused in [CLEARTEXT, OTHER_PORT, "http://127.0.0.1:9/v1"] {
        assert_eq!(super::spawn::memory_embed_api_key(&cfg(refused, TOKEN), Some(&am)), None, "{refused}");
        assert_eq!(
            super::spawn::memory_embed_api_key(&cfg(refused, "p42-byok"), Some(&am)).as_deref(),
            Some("p42-byok"),
            "{refused}: a non-session key is untouched"
        );
    }
    assert_eq!(
        super::spawn::memory_embed_api_key(&cfg(CONFIGURED, TOKEN), Some(&am)).as_deref(),
        Some(TOKEN)
    );
}

/// A static `AuthMode::ApiKey` credential held by the manager is not a session token: the media arm and the
/// catalogue fallback keep offering it where the session may not go (audit round 2, M2).
#[test]
fn p42_static_manager_api_key_is_not_treated_as_a_session_token() {
    if !child("p42_static_manager_api_key_is_not_treated_as_a_session_token") {
        return;
    }
    run(async {
        let mut wire = SessionWire::start().await;
        preconditions();
        let home = std::path::PathBuf::from(std::env::var_os("FUIGO_HOME").expect("child home"));
        let dir = tempfile::tempdir().unwrap();
        let am = Arc::new(AuthManager::new(dir.path(), FuigoComConfig::default()));
        am.hot_swap(FuigoAuth {
            key: "p42-static-manager-key".into(),
            auth_mode: AuthMode::ApiKey,
            ..FuigoAuth::test_default()
        });
        std::fs::write(
            home.join("config.toml"),
            "[endpoints]\nfuigo_api_base_url = \"https://localhost:8443/v1\"\n",
        )
        .unwrap();
        assert_eq!(
            am.voice_api_key_for("https://localhost:8443/v1/audio/transcriptions").await.as_deref(),
            Some("p42-static-manager-key")
        );
        let endpoints = crate::agent::config::EndpointsConfig {
            models_list_url: Some(format!("{}/models", wire.loopback_url())),
            ..Default::default()
        };
        let auth = am.current_or_expired().expect("held");
        tokio::task::spawn_blocking(move || {
            use crate::remote::ModelSource;
            let source = crate::remote::active_model_source(
                &endpoints,
                crate::agent::models::ModelFetchAuth::CustomEndpoint,
            );
            let _ = source.fetch(Some(&auth));
        })
        .await
        .expect("fetch worker completes");
        let seen = wire.observed().await;
        assert!(token_arrived(&seen, "p42-static-manager-key"), "{seen:?}");

        // Aux-model fallback (audit round 3, M2): the held static key still routes to a refused-for-session URL.
        let held = am.current_or_expired();
        let endpoints = crate::agent::config::EndpointsConfig {
            models_base_url: Some(wire.loopback_url()),
            deployment_key: None,
            ..Default::default()
        };
        let aux = crate::agent::config::resolve_aux_model_sampling_config_for_held(
            "p42-aux-model", &indexmap::IndexMap::new(), &endpoints, held.as_ref(), false, None, None,
            crate::agent::config::HelperModelChoice::Default, &crate::agent::models::EffectiveAllowlist::Unrestricted,
        )
        .expect("the held static key routes the aux fallback");
        assert_eq!(aux.api_key.as_deref(), Some("p42-static-manager-key"));

        // `/tokenize-text` (audit round 3, L3): the held static key wins over a different buffered key.
        let actor = session_actor(am.clone(), CONFIGURED, UNLISTED_MODEL, Some("p42-other-byok")).await;
        assert_eq!(
            actor.p42_tokenize_api_key("https://localhost:8443/v1/tokenize-text").await.as_deref(),
            Some("p42-static-manager-key")
        );
    });
}
