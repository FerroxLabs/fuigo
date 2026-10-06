//! P47: every auxiliary SERVICE client decides session-token delivery through one predicate — wire-level proof.
//!
//! Each test re-runs itself in a fresh process (`fresh_process_home`): the P42 wire harness
//! ([`SessionWire`]) installs proxy and CA variables that latch when the first HTTP client is built.
//! One listener plays every destination: a cleartext proxy (an `http://` request arrives in the clear), a
//! TLS-terminating `CONNECT` tunnel for any `https` authority (presenting a leaf for the configured host), and
//! the loopback origin itself. Every request it sees is recorded with its `Authorization` header.
//!
//! For each client the HOSTILE destinations come first: the harness's own loopback origin, the FluxRouter host
//! over cleartext `http`, and `https` loopback (each configured as the client's own base). P47's failure
//! behaviour is that a refused destination gets NO request at all, so the assertion is the strong one: the
//! harness recorded nothing, and the client's error (where it returns one) carries the refusal text. Then the
//! POSITIVE CONTROL: the same client aimed at the configured origin `https://api.fluxrouter.ai` delivers the
//! token, which also proves the harness would have seen a hostile request had one been sent.
use crate::auth::{AuthManager, AuthMode, FuigoAuth, FuigoComConfig};
use crate::test_support::session_wire::{Observed, SessionWire, token_arrived};
use std::sync::Arc;

pub(crate) const TOKEN: &str = "p47-service-session-token-5d1e";
pub(crate) const TRUSTED: &str = "https://api.fluxrouter.ai/v1";
/// Text every P47 refusal carries (`fuigo_extra_ca::service_trust::RefusedServiceDestination`'s `Display`).
pub(crate) const REFUSED: &str = "The request was not made";
const MODULE: &str = "auth::p47_service_wire_tests::";

fn child(test: &str) -> bool {
    fuigo_test_support::env::fresh_process_home(&format!("{MODULE}{test}")).is_some()
}

/// The hostile destinations, as configured service base URLs (`/v1` path, like a configured proxy base). A client's
/// own configured base is its service-base tier, so the hostile bases are the ones no configuration can admit:
/// cleartext loopback (the harness itself), cleartext to the FluxRouter host (proxied in the clear, so the harness
/// would record it), and `https` loopback. Off-origin destinations for a configured base are covered where a URL
/// can differ from the base (`fuigo_extra_ca::service_trust` unit tests, the leader hub test).
pub(crate) fn hostile_bases(wire: &SessionWire) -> Vec<String> {
    vec![
        wire.loopback_url(),
        "http://api.fluxrouter.ai/v1".to_string(),
        format!("https://127.0.0.1:{}/v1", wire.port),
        "https://localhost/v1".to_string(),
        // Userinfo on the FluxRouter origin itself: refused (a separate credential channel), and if it were sent the
        // harness would record it (reqwest strips the userinfo and proxies the request to the real host name).
        "https://u:p@api.fluxrouter.ai/v1".to_string(),
    ]
}

pub(crate) fn session_auth() -> FuigoAuth {
    FuigoAuth {
        key: TOKEN.into(),
        user_id: "p47-user".into(),
        auth_mode: AuthMode::Oidc,
        oidc_issuer: Some(crate::auth::GROK_OAUTH2_ISSUER.to_string()),
        refresh_token: Some("rt".into()),
        expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        ..FuigoAuth::test_default()
    }
}

pub(crate) fn session_manager() -> (tempfile::TempDir, Arc<AuthManager>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let am = Arc::new(AuthManager::new(dir.path(), FuigoComConfig::default()));
    am.hot_swap(session_auth());
    (dir, am)
}

/// Preconditions every child relies on; a wrong fixture fails loudly instead of passing vacuously.
pub(crate) fn preconditions() {
    crate::auth::set_test_oauth2_issuer(crate::auth::GROK_OAUTH2_ISSUER);
    crate::agent::config::Config::install_test_trusted_origins();
    use crate::auth::session_delivery::session_may_reach_service as reach;
    assert!(reach(TRUSTED, None).is_ok(), "fixture: FluxRouter is admitted");
    assert!(reach("http://api.fluxrouter.ai/v1", None).is_err(), "fixture: cleartext refused");
    assert!(reach("http://127.0.0.1:9/v1", Some("http://127.0.0.1:9/v1")).is_err(), "fixture: loopback refused");
    assert!(reach("https://api.fluxrouter.ai:8443/v1", None).is_err(), "fixture: other port refused");
    assert!(reach("https://unconfigured.example/v1", None).is_err(), "fixture: unconfigured refused");
}

/// Nothing reached the harness while the hostile destinations were tried.
pub(crate) fn assert_nothing_sent(seen: &[Observed], client: &str) {
    assert!(
        seen.is_empty(),
        "{client}: a refused destination received a request: {seen:?}"
    );
    assert!(!token_arrived(seen, TOKEN));
}

/// The positive control: the token reached the configured origin.
pub(crate) fn assert_delivered(seen: &[Observed], client: &str) {
    assert!(
        seen.iter()
            .any(|o| o.target.starts_with("https://api.fluxrouter.ai")
                && o.authorization.as_deref().is_some_and(|a| a.contains(TOKEN))),
        "{client}: the configured origin did not receive the session token: {seen:?}"
    );
}

pub(crate) fn assert_refusal_text(text: &str, client: &str) {
    assert!(text.contains(REFUSED), "{client}: not a P47 refusal: {text}");
    assert!(!text.contains(TOKEN), "{client}: the refusal leaked the token: {text}");
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// `/user?include=subscription` (paywall check).
#[test]
fn p47_wire_subscription_check() {
    if !child("p47_wire_subscription_check") {
        return;
    }
    runtime().block_on(async {
        let mut wire = SessionWire::start().await;
        preconditions();
        let (_dir, am) = session_manager();
        for base in hostile_bases(&wire) {
            let r = crate::agent::subscription_check::single_check(am.clone(), &base, None, "p47-user").await;
            assert!(r.is_none(), "{base}");
        }
        assert_nothing_sent(&wire.observed().await, "subscription_check");
        let _ = crate::agent::subscription_check::single_check(am.clone(), TRUSTED, None, "p47-user").await;
        assert_delivered(&wire.observed().await, "subscription_check");
    });
}

/// `/user` enrichment at login.
#[test]
fn p47_wire_auth_enrichment() {
    if !child("p47_wire_auth_enrichment") {
        return;
    }
    runtime().block_on(async {
        let mut wire = SessionWire::start().await;
        preconditions();
        let dir = tempfile::tempdir().unwrap();
        for base in hostile_bases(&wire) {
            let am = AuthManager::new(dir.path(), FuigoComConfig::default()).with_proxy_base_url(&base);
            let mut auth = session_auth();
            am.enrich_auth_inline(&mut auth).await;
        }
        assert_nothing_sent(&wire.observed().await, "auth_enrichment");
        let am = AuthManager::new(dir.path(), FuigoComConfig::default()).with_proxy_base_url(TRUSTED);
        let mut auth = session_auth();
        am.enrich_auth_inline(&mut auth).await;
        assert_delivered(&wire.observed().await, "auth_enrichment");
    });
}

/// `/settings` (remote settings, blocking client).
#[test]
fn p47_wire_remote_settings() {
    if !child("p47_wire_remote_settings") {
        return;
    }
    runtime().block_on(async {
        let mut wire = SessionWire::start().await;
        preconditions();
        for base in hostile_bases(&wire) {
            let fetched = tokio::task::spawn_blocking(move || {
                crate::remote::fetch_settings_blocking(&base, &session_auth(), None)
            })
            .await
            .unwrap();
            let crate::remote::SettingsFetch::DestinationRefused(text) = fetched else {
                panic!("a refused settings URL must be DestinationRefused, not a 401-shaped Rejected");
            };
            assert_refusal_text(&text, "remote_settings");
        }
        assert_nothing_sent(&wire.observed().await, "remote_settings");
        let _ = tokio::task::spawn_blocking(|| {
            crate::remote::fetch_settings_blocking(TRUSTED, &session_auth(), None)
        })
        .await
        .unwrap();
        assert_delivered(&wire.observed().await, "remote_settings");
    });
}

/// Subagent bundle: the legacy JSON fetch (direct headers) and the archive fetch (auth middleware).
#[test]
fn p47_wire_bundle_fetch() {
    if !child("p47_wire_bundle_fetch") {
        return;
    }
    runtime().block_on(async {
        let mut wire = SessionWire::start().await;
        preconditions();
        let (_dir, am) = session_manager();
        for base in hostile_bases(&wire) {
            let legacy = crate::remote::fetch_subagent_bundle(&base, Some(&am), None, None)
                .await
                .unwrap_err();
            assert_refusal_text(&legacy.to_string(), "bundle_fetch");
            let archive = crate::remote::fetch_bundle(&base, Some(&am), None, None)
                .await
                .unwrap_err();
            assert_refusal_text(&archive.to_string(), "bundle_archive");
        }
        assert_nothing_sent(&wire.observed().await, "bundle");
        let _ = crate::remote::fetch_subagent_bundle(TRUSTED, Some(&am), None, None).await;
        assert_delivered(&wire.observed().await, "bundle_fetch");
        let _ = crate::remote::fetch_bundle(TRUSTED, Some(&am), None, None).await;
        assert_delivered(&wire.observed().await, "bundle_archive");
    });
}

/// `BackendClient` (session history backend; auth middleware).
#[test]
fn p47_wire_backend_client() {
    if !child("p47_wire_backend_client") {
        return;
    }
    runtime().block_on(async {
        let mut wire = SessionWire::start().await;
        preconditions();
        let (_dir, am) = session_manager();
        for base in hostile_bases(&wire) {
            let err = crate::remote::BackendClient::with_base_url(base)
                .with_auth_manager(am.clone())
                .list_sessions()
                .await
                .unwrap_err();
            assert!(matches!(err, crate::remote::BackendError::SessionDestinationRefused(_)), "{err}");
            assert_refusal_text(&err.to_string(), "code_backend");
        }
        assert_nothing_sent(&wire.observed().await, "code_backend");
        let _ = crate::remote::BackendClient::with_base_url(TRUSTED)
            .with_auth_manager(am.clone())
            .list_sessions()
            .await;
        assert_delivered(&wire.observed().await, "code_backend");
    });
}

/// `SandboxClient`.
#[test]
fn p47_wire_sandbox_client() {
    if !child("p47_wire_sandbox_client") {
        return;
    }
    runtime().block_on(async {
        let mut wire = SessionWire::start().await;
        preconditions();
        let (_dir, am) = session_manager();
        let request = crate::remote::SandboxListEnvironmentsRequest::default();
        for base in hostile_bases(&wire) {
            let err = crate::remote::SandboxClient::new(base, am.clone())
                .list_environments(&request)
                .await
                .unwrap_err();
            assert_refusal_text(&format!("{err:#}"), "sandbox");
        }
        assert_nothing_sent(&wire.observed().await, "sandbox");
        let _ = crate::remote::SandboxClient::new(TRUSTED, am.clone())
            .list_environments(&request)
            .await;
        assert_delivered(&wire.observed().await, "sandbox");
    });
}

/// Env-configured REST clients: skills, workspaces, conversations, chat models. Each reads its base from the
/// environment at construction, so the base is set before each client is built (this is a fresh process).
#[test]
fn p47_wire_env_configured_rest_clients() {
    if !child("p47_wire_env_configured_rest_clients") {
        return;
    }
    fn set_bases(base: &str) {
        // SAFETY: fresh single-test process; the clients read these at construction, on this thread.
        unsafe {
            for key in [
                "FUIGO_SKILLS_BASE_URL",
                "FUIGO_WORKSPACES_BASE_URL",
                "FUIGO_CONVERSATIONS_BASE_URL",
                "FUIGO_MODES_BASE_URL",
            ] {
                std::env::set_var(key, base);
            }
        }
    }
    runtime().block_on(async {
        let mut wire = SessionWire::start().await;
        preconditions();
        let (_dir, am) = session_manager();
        for base in hostile_bases(&wire) {
            set_bases(&base);
            let skills = crate::remote::SkillsClient::new(am.clone())
                .try_list_catalog("en")
                .await
                .unwrap_err();
            assert!(matches!(skills, crate::remote::SkillsError::SessionDestinationRefused(_)), "{skills}");
            let ws = crate::remote::WorkspacesClient::new(am.clone())
                .list_workspaces(&crate::remote::WsQuery::default())
                .await
                .unwrap_err();
            assert!(matches!(ws, crate::remote::WsError::SessionDestinationRefused(_)), "{ws}");
            let conv = crate::remote::ConversationsClient::new(am.clone())
                .list_conversations(&crate::remote::ConvQuery::default())
                .await
                .unwrap_err();
            assert!(matches!(conv, crate::remote::ConvError::SessionDestinationRefused(_)), "{conv}");
            let modes = crate::remote::ChatModelsClient::new(am.clone())
                .list_modes("en")
                .await
                .unwrap_err();
            assert!(matches!(modes, crate::remote::ChatModelsError::SessionDestinationRefused(_)), "{modes}");
            for text in [skills.to_string(), ws.to_string(), conv.to_string(), modes.to_string()] {
                assert_refusal_text(&text, "env_rest");
            }
        }
        assert_nothing_sent(&wire.observed().await, "env_rest");
        set_bases(TRUSTED);
        let _ = crate::remote::SkillsClient::new(am.clone()).try_list_catalog("en").await;
        assert_delivered(&wire.observed().await, "skills");
        let _ = crate::remote::WorkspacesClient::new(am.clone())
            .list_workspaces(&crate::remote::WsQuery::default())
            .await;
        assert_delivered(&wire.observed().await, "workspaces");
        let _ = crate::remote::ConversationsClient::new(am.clone())
            .list_conversations(&crate::remote::ConvQuery::default())
            .await;
        assert_delivered(&wire.observed().await, "conversations");
        let _ = crate::remote::ChatModelsClient::new(am.clone()).list_modes("en").await;
        assert_delivered(&wire.observed().await, "chat_models");
    });
}

/// `SessionRegistryClient` (auth middleware).
#[test]
fn p47_wire_session_registry() {
    if !child("p47_wire_session_registry") {
        return;
    }
    runtime().block_on(async {
        let mut wire = SessionWire::start().await;
        preconditions();
        let (_dir, am) = session_manager();
        for base in hostile_bases(&wire) {
            let err = crate::agent::session_registry_client::SessionRegistryClient::new(base, TOKEN)
                .with_auth(am.clone())
                .search(None, 1)
                .await
                .unwrap_err();
            assert_refusal_text(&format!("{err:#}"), "session_registry");
        }
        assert_nothing_sent(&wire.observed().await, "session_registry");
        let _ = crate::agent::session_registry_client::SessionRegistryClient::new(TRUSTED, TOKEN)
            .with_auth(am.clone())
            .search(None, 1)
            .await;
        assert_delivered(&wire.observed().await, "session_registry");
    });
}

/// `FeedbackClient`, live (`AuthManager`) and static (`user_token` only) providers.
#[test]
fn p47_wire_feedback_client() {
    if !child("p47_wire_feedback_client") {
        return;
    }
    runtime().block_on(async {
        use crate::agent::feedback_client::FeedbackClient;
        let mut wire = SessionWire::start().await;
        preconditions();
        let (_dir, am) = session_manager();
        for base in hostile_bases(&wire) {
            let live = FeedbackClient::new(base.clone(), Some(TOKEN.into()))
                .with_auth_manager(am.clone())
                .get_feedback_config()
                .await
                .unwrap_err();
            assert_refusal_text(&format!("{live:#}"), "feedback live");
            let fixed = FeedbackClient::new(base, Some(TOKEN.into()))
                .get_feedback_config()
                .await
                .unwrap_err();
            assert_refusal_text(&format!("{fixed:#}"), "feedback static");
        }
        assert_nothing_sent(&wire.observed().await, "feedback");
        let _ = FeedbackClient::new(TRUSTED, Some(TOKEN.into()))
            .with_auth_manager(am.clone())
            .get_feedback_config()
            .await;
        assert_delivered(&wire.observed().await, "feedback live");
        let _ = FeedbackClient::new(TRUSTED, Some(TOKEN.into())).get_feedback_config().await;
        assert_delivered(&wire.observed().await, "feedback static");
    });
}

/// Proxy storage (trace upload / conversation storage): `build_storage_client_for_proxy` live and static, and the
/// trace-export config's provider (`TraceExportConfigWithAuth`).
#[test]
fn p47_wire_storage_proxy() {
    if !child("p47_wire_storage_proxy") {
        return;
    }
    runtime().block_on(async {
        use crate::auth::credential_provider::build_storage_client_for_proxy;
        use fuigo_file_utils::gcs::StorageConfig as _;
        let mut wire = SessionWire::start().await;
        preconditions();
        let (_dir, am) = session_manager();
        let trace_client = |base: &str| {
            let cfg = crate::upload::gcs::TraceExportConfigWithAuth::new(
                fuigo_file_utils::TraceExportConfig {
                    bucket_url: None,
                    service_account_key: None,
                    upload_method: fuigo_file_utils::UploadMethod::Proxy {
                        proxy_base_url: base.to_string(),
                        user_token: TOKEN.into(),
                        deployment_key: None,
                        alpha_test_key: None,
                    },
                    prefix_dir: None,
                    gcs_prefix: None,
                    absolute_paths: false,
                    archive_name_override: None,
                },
                Some(am.clone()),
            );
            fuigo_file_utils::storage_client::StorageClient::with_provider(
                base,
                crate::http::shared_upload_client(),
                cfg.proxy_credentials().expect("proxy credentials"),
            )
        };
        for base in hostile_bases(&wire) {
            for (label, client) in [
                ("live", build_storage_client_for_proxy(&base, None, None, Some(am.clone()), None, None, "fuigo-shell")),
                ("static", build_storage_client_for_proxy(&base, None, None, None, Some(TOKEN.into()), None, "fuigo-shell")),
                ("trace", trace_client(&base)),
            ] {
                let err = client.get_upload_limits().await.unwrap_err();
                assert_refusal_text(&format!("{err:#}"), label);
            }
        }
        assert_nothing_sent(&wire.observed().await, "storage");
        let _ = build_storage_client_for_proxy(TRUSTED, None, None, Some(am.clone()), None, None, "fuigo-shell")
            .get_upload_limits()
            .await;
        assert_delivered(&wire.observed().await, "storage live");
        let _ = build_storage_client_for_proxy(TRUSTED, None, None, None, Some(TOKEN.into()), None, "fuigo-shell")
            .get_upload_limits()
            .await;
        assert_delivered(&wire.observed().await, "storage static");
        let _ = trace_client(TRUSTED).get_upload_limits().await;
        assert_delivered(&wire.observed().await, "trace upload");
    });
}

/// Agent extensions on the cli-chat-proxy base: billing, auto top-up, consent, privacy.
#[test]
fn p47_wire_agent_extensions() {
    if !child("p47_wire_agent_extensions") {
        return;
    }
    let rt = runtime();
    tokio::task::LocalSet::new().block_on(&rt, async {
        use agent_client_protocol as acp;
        let mut wire = SessionWire::start().await;
        preconditions();
        let (_dir, am) = session_manager();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let agent = crate::agent::MvpAgent::new(
            fuigo_acp_lib::AcpAgentGatewaySender::new(tx),
            &crate::agent::config::Config::default(),
            am,
            None,
        )
        .expect("agent builds");
        let request = |method: &str, params: serde_json::Value| {
            acp::ExtRequest::new(
                method,
                std::sync::Arc::from(serde_json::value::to_raw_value(&params).unwrap()),
            )
        };
        let call_all = |base: String| {
            agent.cfg.borrow_mut().endpoints.cli_chat_proxy_base_url = Some(base);
            let agent = &agent;
            async move {
                vec![
                    crate::extensions::billing::handle(agent, &request("fuigo/billing", serde_json::json!({}))).await,
                    crate::extensions::billing::handle(agent, &request("fuigo/auto-topup-rule", serde_json::json!({}))).await,
                    crate::extensions::consent::handle(
                        agent,
                        &request("fuigo/consent/record", serde_json::json!({ "noticeId": "n1", "version": 1 })),
                    )
                    .await,
                    crate::extensions::privacy::handle(
                        agent,
                        &request(
                            "fuigo/privacy/setCodingDataRetention",
                            serde_json::json!({ "codingDataRetentionOptOut": true }),
                        ),
                    )
                    .await,
                ]
            }
        };
        for base in hostile_bases(&wire) {
            for result in call_all(base).await {
                let err = result.expect_err("refused");
                // `acp_error::internal_error` carries the text in the error's data.
                assert_refusal_text(&format!("{err:?}"), "agent extension");
            }
        }
        assert_nothing_sent(&wire.observed().await, "agent extensions");
        let _ = call_all(TRUSTED.to_string()).await;
        let seen = wire.observed().await;
        for path in ["/billing", "/auto-topup-rule", "/consent/accept", "/privacy/coding-data-retention"] {
            assert!(
                seen.iter().any(|o| o.target.contains(path)
                    && o.authorization.as_deref().is_some_and(|a| a.contains(TOKEN))),
                "{path} did not receive the token at the configured origin: {seen:?}"
            );
        }
    });
}

/// The OTLP exporter's provider: the session token reaches only FluxRouter / configured API origins.
#[test]
fn p47_otel_provider_rule() {
    crate::agent::config::Config::install_test_trusted_origins();
    let (_dir, am) = session_manager();
    let provider = crate::auth::credential_provider::OtelAuthCredentialProvider::for_test(am);
    use fuigo_auth::AuthCredentialProvider as _;
    let reach = |u: &str| provider.bearer_may_reach(&reqwest::Url::parse(u).unwrap(), TOKEN);
    assert!(reach("https://api.fluxrouter.ai/v1/traces").is_ok());
    for refused in [
        "http://127.0.0.1:4318/v1/traces",
        "http://api.fluxrouter.ai/v1/traces",
        "https://collector.example/v1/traces",
    ] {
        let err = reach(refused).expect_err(refused);
        assert_refusal_text(&err.0, "otlp");
    }
}

/// P47 (audit R1 H2): the rule is decided on the exact bearer being stamped, not on a re-read of the manager. A
/// manager that now holds a static API key K still refuses the session token S it handed out a moment earlier (the
/// interleaving: snapshot S, switch to K, then check), while K itself — and the configured deployment key — keep
/// their own rules.
#[test]
fn p47_provider_rule_is_decided_on_the_stamped_value() {
    crate::agent::config::Config::install_test_trusted_origins();
    use fuigo_auth::AuthCredentialProvider as _;
    let (_dir, am) = session_manager();
    let refused = reqwest::Url::parse("http://127.0.0.1:9/v1/consent/accept").unwrap();
    let provider = crate::auth::credential_provider::ShellAuthCredentialProvider::new(
        am.clone(),
        None,
        None,
        Some("http://127.0.0.1:9/v1".into()),
        "test",
    );
    let snapshot = provider.snapshot().token.expect("session snapshot");
    assert_eq!(snapshot, TOKEN);
    am.hot_swap(FuigoAuth {
        key: "p47-static-api-key".into(),
        auth_mode: AuthMode::ApiKey,
        expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        ..FuigoAuth::test_default()
    });
    let err = provider
        .bearer_may_reach(&refused, &snapshot)
        .expect_err("the session value captured before the switch is still a session token");
    assert_refusal_text(&err.0, "interleaving");
    assert!(provider.bearer_may_reach(&refused, "p47-static-api-key").is_ok());
    let otel = crate::auth::credential_provider::OtelAuthCredentialProvider::for_test(am.clone());
    assert!(otel.bearer_may_reach(&refused, &snapshot).is_err());
    assert!(otel.bearer_may_reach(&refused, "p47-static-api-key").is_ok());
    let deployment = crate::auth::credential_provider::ShellAuthCredentialProvider::new(
        am,
        Some("p47-deployment-key".into()),
        None,
        None,
        "test",
    );
    assert!(deployment.bearer_may_reach(&refused, "p47-deployment-key").is_ok());
    assert!(deployment.bearer_may_reach(&refused, &snapshot).is_err());
}

/// P47 (audit R1 M5): the trace-upload static path checks a SESSION credential against the trace-upload URL and
/// leaves a static API key alone.
#[test]
fn p47_upload_method_checks_only_session_credentials() {
    use crate::session::repo_changes::UploadMethod;
    crate::agent::config::Config::install_test_trusted_origins();
    let endpoints = crate::agent::config::EndpointsConfig {
        trace_upload_url: Some("http://127.0.0.1:9/v1".into()),
        trace_upload_bucket: None,
        deployment_key: None,
        ..Default::default()
    };
    let session = session_auth();
    let method = endpoints.resolve_upload_method_for_auth(Some(&session));
    assert!(
        !matches!(&method, Some(UploadMethod::Proxy { user_token, .. }) if user_token == TOKEN),
        "{method:?}"
    );
    let api_key = FuigoAuth {
        key: "p47-static-api-key".into(),
        auth_mode: AuthMode::ApiKey,
        ..FuigoAuth::test_default()
    };
    match endpoints.resolve_upload_method_for_auth(Some(&api_key)) {
        Some(UploadMethod::Proxy { user_token, .. }) => assert_eq!(user_token, "p47-static-api-key"),
        other => panic!("a static API key keeps its own rules: {other:?}"),
    }
}

/// P47 (audit R2): the credential's kind survives a real trace upload (the `fuigo trace` path). At a cleartext
/// loopback proxy a static API key is uploaded (its own rules), and a session token is refused with nothing sent.
#[tokio::test]
async fn p47_classified_trace_upload_keeps_the_credential_kind() {
    crate::agent::config::Config::install_test_trusted_origins();
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = hits.clone();
    let app = axum::Router::new().fallback(move || {
        seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        async { axum::http::StatusCode::OK }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let config = || fuigo_file_utils::TraceExportConfig {
        bucket_url: None,
        service_account_key: None,
        upload_method: fuigo_file_utils::UploadMethod::Proxy {
            proxy_base_url: format!("http://{addr}/v1"),
            user_token: "ignored-by-the-classified-provider".into(),
            deployment_key: None,
            alpha_test_key: None,
        },
        prefix_dir: None,
        gcs_prefix: None,
        absolute_paths: false,
        archive_name_override: None,
    };
    let session = session_auth();
    let refused = crate::upload::gcs::ClassifiedProxyUpload::new(config(), Some(&session));
    let err = fuigo_file_utils::gcs::upload_bytes(&refused, "s/trace.tar.gz", b"x", "application/gzip")
        .await
        .unwrap_err();
    assert!(crate::upload::gcs::is_destination_refusal(&err), "{err:#}");
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0, "the session upload was sent");
    let api_key = FuigoAuth {
        key: "p47-static-api-key".into(),
        auth_mode: AuthMode::ApiKey,
        ..FuigoAuth::test_default()
    };
    let admitted = crate::upload::gcs::ClassifiedProxyUpload::new(config(), Some(&api_key));
    let _ = fuigo_file_utils::gcs::upload_bytes(&admitted, "s/trace.tar.gz", b"x", "application/gzip").await;
    assert!(hits.load(std::sync::atomic::Ordering::SeqCst) >= 1, "the static API key upload must be sent");
}
