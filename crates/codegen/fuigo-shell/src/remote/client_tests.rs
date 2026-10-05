use super::*;
use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::get,
};
use std::sync::{Arc, Mutex};
#[test]
fn login_config_response_parses_tristate() {
    let parse = |s: &str| {
        serde_json::from_str::<LoginConfigResponse>(s)
            .unwrap()
            .device_flow
    };
    assert_eq!(parse(r#"{"device_flow": true}"#), Some(true));
    assert_eq!(parse(r#"{"device_flow": false}"#), Some(false));
    assert_eq!(parse(r#"{"device_flow": null}"#), None);
    assert_eq!(parse("{}"), None, "absent flag must parse as unset");
}
#[test]
fn get_env_keys_parses_strings_and_rejects_non_strings() {
    use crate::agent::config::EnvKeys;
    let parse = |v: serde_json::Value| {
        let obj = serde_json::json!({ "env_key": v });
        get_env_keys(obj.as_object().unwrap(), "env_key")
    };
    assert_eq!(parse(serde_json::json!("A")), Some(EnvKeys::single("A")));
    assert_eq!(
        parse(serde_json::json!(["A", "B"])),
        Some(EnvKeys::new(["A", "B"]))
    );
    assert_eq!(parse(serde_json::json!(["A", 123])), None);
    assert_eq!(parse(serde_json::json!([])), None);
}
fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}
#[derive(Debug, Default, Clone)]
struct LoginConfigHeaders {
    authorization: Option<String>,
    user_id: Option<String>,
    email: Option<String>,
    agent_id: Option<String>,
    client_identifier: Option<String>,
    client_version: Option<String>,
}
#[derive(Clone)]
struct LoginConfigServerState {
    status_code: StatusCode,
    body: String,
    seen: Arc<Mutex<Vec<LoginConfigHeaders>>>,
}
/// Mock cli-chat-proxy serving `GET /v1/login-config` with a fixed status and raw body, recording the request headers it saw.
async fn start_login_config_server(
    status_code: StatusCode,
    body: String,
) -> (
    String,
    Arc<Mutex<Vec<LoginConfigHeaders>>>,
    tokio::task::JoinHandle<()>,
) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let state = LoginConfigServerState {
        status_code,
        body,
        seen: seen.clone(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let app = Router::new()
        .route(
            "/v1/login-config",
            get(
                |State(state): State<LoginConfigServerState>, headers: HeaderMap| async move {
                    state.seen.lock().unwrap().push(LoginConfigHeaders {
                        authorization: header_str(&headers, "authorization"),
                        user_id: header_str(&headers, "x-userid"),
                        email: header_str(&headers, "x-email"),
                        agent_id: header_str(&headers, "x-fuigo-agent-id"),
                        client_identifier: header_str(&headers, "x-fuigo-client-identifier"),
                        client_version: header_str(&headers, "x-fuigo-client-version"),
                    });
                    (state.status_code, state.body)
                },
            ),
        )
        .with_state(state);
    let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("{base}/v1"), seen, handle)
}
#[tokio::test]
async fn fetch_login_device_flow_parses_2xx_bodies() {
    for (body, expected) in [
        (r#"{"device_flow": true}"#, Some(true)),
        (r#"{"device_flow": false}"#, Some(false)),
        (r#"{"device_flow": null}"#, None),
        (r#"{}"#, None),
        (r#"{"other": 1}"#, None),
    ] {
        let (base, _seen, server) =
            start_login_config_server(StatusCode::OK, body.to_string()).await;
        let got = fetch_login_device_flow(&base).await;
        server.abort();
        assert_eq!(got, expected, "body {body:?}");
    }
}
#[tokio::test]
async fn fetch_login_device_flow_errors_return_none() {
    for (status, body) in [
        (StatusCode::NOT_FOUND, r#"{"device_flow": true}"#),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"device_flow": true}"#,
        ),
        (StatusCode::OK, "not json"),
    ] {
        let (base, _seen, server) = start_login_config_server(status, body.to_string()).await;
        let got = fetch_login_device_flow(&base).await;
        server.abort();
        assert_eq!(got, None, "status {status}, body {body:?}");
    }
}
#[tokio::test]
async fn fetch_login_device_flow_sends_only_unauthenticated_headers() {
    let (base, seen, server) =
        start_login_config_server(StatusCode::OK, r#"{"device_flow": true}"#.to_string()).await;
    let got = fetch_login_device_flow(&base).await;
    server.abort();
    assert_eq!(got, Some(true));
    let seen = seen.lock().unwrap();
    let h = seen
        .last()
        .expect("server should have received one request");
    // P43 hostile: the mock is loopback, not FluxRouter-operated, so the persisted machine id
    // and the client labels are withheld. `login_config_request_carries_identity_only_to_fluxrouter`
    // pins that FluxRouter still gets them.
    assert_eq!(h.agent_id, None, "a non-FluxRouter destination got x-fuigo-agent-id");
    assert_eq!(
        h.client_identifier, None,
        "a non-FluxRouter destination got x-fuigo-client-identifier"
    );
    assert_eq!(
        h.client_version, None,
        "a non-FluxRouter destination got x-fuigo-client-version"
    );
    assert_eq!(h.authorization, None, "must not send Authorization");
    assert_eq!(h.user_id, None, "must not send x-userid");
    assert_eq!(h.email, None, "must not send x-email");
}
/// P43. Both sides of the login-config decision on the request this path actually sends.
#[test]
fn login_config_request_carries_identity_only_to_fluxrouter() {
    let client = crate::http::shared_client();
    let fluxrouter = login_config_request(&client, "https://api.fluxrouter.ai/v1/login-config", "agent-7")
        .build()
        .unwrap();
    assert_eq!(fluxrouter.headers()["x-fuigo-agent-id"], "agent-7");
    assert!(fluxrouter.headers().contains_key("x-fuigo-client-version"));
    assert!(fluxrouter.headers().contains_key("x-fuigo-client-identifier"));
    for url in [
        "https://cli-proxy.example/v1/login-config",
        "http://api.fluxrouter.ai/v1/login-config",
        "http://127.0.0.1:9/v1/login-config",
    ] {
        let request = login_config_request(&client, url, "agent-7").build().unwrap();
        for name in fuigo_extra_ca::fluxrouter::IDENTITY_HEADER_NAMES {
            assert!(!request.headers().contains_key(name), "{url} got {name}");
        }
        assert!(request.headers().contains_key(crate::http::CLIENT_MODE_HEADER));
    }
}
/// Mock cli-chat-proxy serving `GET /settings` with a fixed status and body.
/// One settings mock for every case: the reply is swapped between cases, so the session front keeps
/// one backend route and a pooled connection from the previous case never lands on a dead server.
async fn start_settings_server(
    reply: Arc<Mutex<(StatusCode, String)>>,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let app = Router::new().route(
        "/settings",
        get(move || {
            let (status, body) = reply.lock().unwrap().clone();
            async move { (status, body) }
        }),
    );
    let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, handle)
}
/// `fetch_settings_blocking` maps each HTTP outcome to the [`SettingsFetch`] variant the external-OTEL gate relies on.
/// Only 401 yields `Rejected`; every other non-2xx outcome fails closed as `Retry`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settings_fetch_maps_status_to_outcome() {
    let Some(front) = crate::test_support::session_wire::fronted_child(
        "remote::client::tests::settings_fetch_maps_status_to_outcome",
    ) else {
        return;
    };
    let auth = FuigoAuth::test_default();
    let cases: [(StatusCode, &str, &str); 6] = [
        (StatusCode::OK, "{}", "Fetched"),
        (StatusCode::UNAUTHORIZED, "{}", "Rejected"),
        (StatusCode::FORBIDDEN, "{}", "Retry"),
        (StatusCode::TOO_MANY_REQUESTS, "{}", "Retry"),
        (StatusCode::INTERNAL_SERVER_ERROR, "{}", "Retry"),
        (StatusCode::OK, "not json", "Retry"),
    ];
    let reply = Arc::new(Mutex::new((StatusCode::OK, String::new())));
    let (base, server) = start_settings_server(reply.clone()).await;
    let base = front.front(&base);
    for (status, body, expected) in cases {
        *reply.lock().unwrap() = (status, body.to_string());
        let (base, a) = (base.clone(), auth.clone());
        let outcome = tokio::task::spawn_blocking(move || {
            fetch_settings_blocking_with_attempts(&base, &a, None, 1)
        })
        .await
        .unwrap();
        let got = match outcome {
            SettingsFetch::Fetched(_) => "Fetched",
            SettingsFetch::Rejected => "Rejected",
            SettingsFetch::Retry => "Retry",
            SettingsFetch::DestinationRefused(_) => "DestinationRefused",
        };
        assert_eq!(got, expected, "status {status}, body {body:?}");
    }
    server.abort();
}
#[derive(Debug, Default, Clone)]
struct SeenHeaders {
    authorization: Option<String>,
    /// The provider's `X-XAI-Token-Auth` routing hint, a wire value: the mock looks it up under
    /// the provider's spelling so the `None` assertions below are real. (The rebrand had rewritten
    /// this lookup to `x-fuigo-token-auth`, which nothing sends, making them vacuous.)
    token_auth: Option<String>,
    user_id: Option<String>,
    email: Option<String>,
    alpha_test_key: Option<String>,
    client_version: Option<String>,
}
#[derive(Clone)]
struct BundleServerState {
    body: serde_json::Value,
    status_code: StatusCode,
    seen_headers: Arc<Mutex<Vec<SeenHeaders>>>,
}
async fn start_bundle_server(
    status_code: StatusCode,
    body: serde_json::Value,
) -> (
    String,
    Arc<Mutex<Vec<SeenHeaders>>>,
    tokio::task::JoinHandle<()>,
) {
    let seen_headers = Arc::new(Mutex::new(Vec::new()));
    let state = BundleServerState {
        body,
        status_code,
        seen_headers: seen_headers.clone(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let app = Router::new()
        .route(
            "/v1/subagents/bundle",
            get(
                |State(state): State<BundleServerState>, headers: HeaderMap| async move {
                    state.seen_headers.lock().unwrap().push(SeenHeaders {
                        authorization: headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned),
                        token_auth: headers
                            .get("x-xai-token-auth")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned),
                        user_id: headers
                            .get("x-userid")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned),
                        email: headers
                            .get("x-email")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned),
                        alpha_test_key: {
                            let _ = &headers;
                            None
                        },
                        client_version: headers
                            .get("x-fuigo-client-version")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned),
                    });
                    (state.status_code, axum::Json(state.body))
                },
            ),
        )
        .route(
            "/forward/{tail}",
            get(
                |Path(_tail): Path<String>,
                 State(state): State<BundleServerState>,
                 headers: HeaderMap| async move {
                    state.seen_headers.lock().unwrap().push(SeenHeaders {
                        authorization: headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned),
                        token_auth: headers
                            .get("x-xai-token-auth")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned),
                        user_id: headers
                            .get("x-userid")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned),
                        email: headers
                            .get("x-email")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned),
                        alpha_test_key: {
                            let _ = &headers;
                            None
                        },
                        client_version: headers
                            .get("x-fuigo-client-version")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned),
                    });
                    (state.status_code, axum::Json(state.body))
                },
            ),
        )
        .with_state(state);
    let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("{base}/v1"), seen_headers, handle)
}
fn test_auth() -> FuigoAuth {
    FuigoAuth {
        key: "token".to_string(),
        auth_mode: crate::auth::AuthMode::Oidc,
        create_time: chrono::Utc::now(),
        user_id: "user-1".to_string(),
        email: Some("test@example.com".to_string()),
        first_name: None,
        last_name: None,
        profile_image_asset_id: None,
        principal_type: None,
        principal_id: None,
        team_id: None,
        team_name: None,
        team_role: None,
        organization_id: None,
        organization_name: None,
        organization_role: None,
        user_blocked_reason: None,
        team_blocked_reasons: vec![],
        coding_data_retention_opt_out: false,
        has_fuigo_code_access: None,
        refresh_token: None,
        expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        oidc_issuer: None,
        oidc_client_id: None,
    }
}
fn test_auth_manager() -> Arc<crate::auth::AuthManager> {
    let dir = tempfile::tempdir().unwrap();
    let mgr = crate::auth::AuthManager::new(dir.path(), crate::auth::FuigoComConfig::default());
    mgr.hot_swap(test_auth());
    std::mem::forget(dir);
    Arc::new(mgr)
}
#[tokio::test(flavor = "current_thread")]
async fn fetch_subagent_bundle_success() {
    let Some(front) = crate::test_support::session_wire::fronted_child(
        "remote::client::tests::fetch_subagent_bundle_success",
    ) else {
        return;
    };
    let body = serde_json::json!({
        "version": "bundle-v1",
        "personas": {"researcher": "persona"},
        "roles": {"reviewer": "role"},
        "agents": {"default": "agent"}
    });
    let (proxy_base_url, seen_headers, server) =
        start_bundle_server(axum::http::StatusCode::OK, body).await;
    // A non-FluxRouter configured origin: the session token may go (P47), identity may not (P43).
    let proxy_base_url = front.front_service(&proxy_base_url);
    let am = test_auth_manager();
    let bundle = fetch_subagent_bundle(&proxy_base_url, Some(&am), None, None)
        .await
        .unwrap();
    assert_eq!(bundle.version, "bundle-v1");
    assert_eq!(
        bundle.personas.get("researcher"),
        Some(&"persona".to_string())
    );
    assert_eq!(bundle.roles.get("reviewer"), Some(&"role".to_string()));
    assert_eq!(bundle.agents.get("default"), Some(&"agent".to_string()));
    let headers = seen_headers.lock().unwrap();
    let headers = headers.last().unwrap();
    assert_eq!(headers.authorization.as_deref(), Some("Bearer token"));
    // A user-token bundle fetch carries the provider's `X-XAI-Token-Auth: xai-grok-cli`
    // routing hint: `FuigoAuthCredentials::apply` adds it unconditionally with the bearer,
    // exactly as upstream did (there is no trusted-proxy gate in this tree). The proxy is
    // opt-in and empty by default, so nothing is sent anywhere until an operator points
    // `cli_chat_proxy_base_url` at a host that expects this header. An earlier round
    // asserted `None` here on the belief that a gate suppressed it; that only held because
    // the mock looked the header up under a rebranded name nothing sends.
    assert_eq!(headers.token_auth.as_deref(), Some("xai-grok-cli"));
    // P43 hostile: the mock proxy is loopback, not FluxRouter-operated, so the account id,
    // e-mail and client version are withheld while the bearer still authorises the request.
    assert_eq!(headers.user_id, None, "a non-FluxRouter proxy got x-userid");
    assert_eq!(headers.email, None, "a non-FluxRouter proxy got x-email");
    assert_eq!(headers.alpha_test_key, None);
    assert_eq!(
        headers.client_version, None,
        "a non-FluxRouter proxy got x-fuigo-client-version"
    );
    server.abort();
}
/// P43. Both sides of the bundle-fetch decision, on the builder `fetch_subagent_bundle` uses.
#[tokio::test(flavor = "current_thread")]
async fn bundle_fetch_headers_carry_identity_only_to_fluxrouter() {
    let am = test_auth_manager();
    let client = crate::http::shared_client();
    let url = "https://api.fluxrouter.ai/v1/subagents/bundle";
    let request = add_bundle_fetch_headers(client.get(url), Some(&am), None, None, url, url)
        .await
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(request.headers()["x-userid"], "user-1");
    assert_eq!(request.headers()["x-email"], "test@example.com");
    assert!(request.headers().contains_key("x-fuigo-client-version"));
    // P47: the cleartext FluxRouter URL is refused before any header is built (no session token over http).
    assert!(matches!(
        add_bundle_fetch_headers(
            client.get("http://api.fluxrouter.ai/v1/subagents/bundle"),
            Some(&am),
            None,
            None,
            "http://api.fluxrouter.ai/v1/subagents/bundle",
            "http://api.fluxrouter.ai/v1",
        )
        .await,
        Err(BackendError::SessionDestinationRefused(_))
    ));
    for url in ["https://cli-proxy.example/v1/subagents/bundle"] {
        let request = add_bundle_fetch_headers(client.get(url), Some(&am), None, None, url, url)
            .await
            .unwrap()
            .build()
            .unwrap();
        for name in fuigo_extra_ca::fluxrouter::IDENTITY_HEADER_NAMES {
            assert!(!request.headers().contains_key(name), "{url} got {name}");
        }
        assert!(request.headers().contains_key("authorization"));
    }
}
/// P43 hostile: the archive bundle fetch (its own gate) sends no identity to a proxy that is not
/// FluxRouter-operated.
#[tokio::test(flavor = "current_thread")]
async fn archive_bundle_fetch_sends_no_identity_to_a_non_fluxrouter_proxy() {
    let Some(front) = crate::test_support::session_wire::fronted_child(
        "remote::client::tests::archive_bundle_fetch_sends_no_identity_to_a_non_fluxrouter_proxy",
    ) else {
        return;
    };
    // Alone in its process: install the issuer no other test happened to install here.
    crate::auth::set_test_oauth2_issuer(crate::auth::GROK_OAUTH2_ISSUER);
    let (base, seen, handle) = crate::remote::identity_tests::spawn_recording_mock("{}").await;
    let base = front.front_service(&base);
    let am = test_auth_manager();
    let fetched = fetch_bundle(&base, Some(&am), None, None).await;
    handle.abort();
    assert!(matches!(fetched, Ok(FetchedBundle::Archive(_))), "{fetched:?}");
    crate::remote::identity_tests::assert_no_identity_headers(&seen, "bundle_archive");
}
/// P43. The blocking cli-chat-proxy helper (settings fetch): FluxRouter gets identity, a
/// user-configured proxy does not.
#[test]
fn cli_chat_proxy_blocking_headers_carry_identity_only_to_fluxrouter() {
    let auth = test_auth();
    let client = fuigo_extra_ca::build_blocking_reqwest_client(|builder| builder).unwrap();
    let url = "https://api.fluxrouter.ai/v1/settings";
    let request = add_cli_chat_proxy_headers_blocking(client.get(url), &auth, None, url)
        .build()
        .unwrap();
    assert_eq!(request.headers()["x-userid"], "user-1");
    assert_eq!(request.headers()["x-email"], "test@example.com");
    assert!(request.headers().contains_key("x-fuigo-client-identifier"));
    let url = "https://cli-proxy.example/v1/settings";
    let request = add_cli_chat_proxy_headers_blocking(client.get(url), &auth, None, url)
        .build()
        .unwrap();
    for name in fuigo_extra_ca::fluxrouter::IDENTITY_HEADER_NAMES {
        assert!(!request.headers().contains_key(name), "{url} got {name}");
    }
    assert_eq!(request.headers()["authorization"], "Bearer token");
}
#[tokio::test(flavor = "current_thread")]
async fn fetch_subagent_bundle_uses_deployment_key_without_user_headers() {
    let body = serde_json::json!({
        "version": "bundle-v1",
        "personas": {},
        "roles": {},
        "agents": {}
    });
    let (proxy_base_url, seen_headers, server) =
        start_bundle_server(axum::http::StatusCode::OK, body).await;
    let am = test_auth_manager();
    let bundle = fetch_subagent_bundle(&proxy_base_url, Some(&am), Some("deploy-key"), None)
        .await
        .unwrap();
    assert_eq!(bundle.version, "bundle-v1");
    let headers = seen_headers.lock().unwrap();
    let headers = headers.last().unwrap();
    assert_eq!(headers.authorization.as_deref(), Some("Bearer deploy-key"));
    assert_eq!(headers.token_auth, None);
    assert_eq!(headers.user_id, None);
    assert_eq!(headers.email, None);
    server.abort();
}
#[tokio::test(flavor = "current_thread")]
async fn fetch_subagent_bundle_http_failure() {
    let Some(front) = crate::test_support::session_wire::fronted_child(
        "remote::client::tests::fetch_subagent_bundle_http_failure",
    ) else {
        return;
    };
    let (proxy_base_url, _seen_headers, server) = start_bundle_server(
        axum::http::StatusCode::UNAUTHORIZED,
        serde_json::json!({"error": "unauthorized"}),
    )
    .await;
    let proxy_base_url = front.front(&proxy_base_url);
    let am = test_auth_manager();
    let error = fetch_subagent_bundle(&proxy_base_url, Some(&am), None, None)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        BackendError::RequestFailed { status: 401, .. }
    ));
    server.abort();
}
#[tokio::test(flavor = "current_thread")]
async fn fetch_subagent_bundle_parse_failure() {
    let Some(front) = crate::test_support::session_wire::fronted_child(
        "remote::client::tests::fetch_subagent_bundle_parse_failure",
    ) else {
        return;
    };
    let (proxy_base_url, _seen_headers, server) = start_bundle_server(
        axum::http::StatusCode::OK,
        serde_json::json!({"version": 42}),
    )
    .await;
    let proxy_base_url = front.front(&proxy_base_url);
    let am = test_auth_manager();
    let error = fetch_subagent_bundle(&proxy_base_url, Some(&am), None, None)
        .await
        .unwrap_err();
    assert!(matches!(error, BackendError::Serialization(_)));
    server.abort();
}
#[test]
fn parse_openai_format_uses_id_field() {
    let value = serde_json::json!({
        "id": "grok-3",
        "object": "model",
        "owned_by": "fuigo",
        "context_window": 131072
    });
    let result = parse_remote_model_value(&value, "https://api.x.ai/v1").unwrap();
    assert_eq!(result.model, "grok-3");
    assert_eq!(result.base_url, "https://api.x.ai/v1");
    assert_eq!(result.name.as_deref(), Some("grok-3"));
}
#[test]
fn parse_model_field_takes_priority_over_id() {
    let value = serde_json::json!({
        "id": "display-key",
        "model": "actual-model-id",
        "name": "Display Name",
        "context_window": 131072
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    assert_eq!(result.model, "actual-model-id");
    assert_eq!(result.name.as_deref(), Some("Display Name"));
}
#[test]
fn parse_reads_model_family() {
    let value = serde_json::json!({
        "model": "grok-4.5",
        "context_window": 1_000_000,
        "model_family": "xai"
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    // `model_family` is a wire value echoed from the server, not branding: the
    // parser passes it through verbatim. The rebrand rewrote this expectation
    // while leaving the input above -- they disagreed.
    assert_eq!(result.model_family.as_deref(), Some("xai"));
    let value = serde_json::json!({
        "model": "acme-1",
        "contextWindow": 400_000,
        "modelFamily": "acme"
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    assert_eq!(result.model_family.as_deref(), Some("acme"));
    let value = serde_json::json!({"model": "x", "context_window": 256_000});
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    assert!(result.model_family.is_none());
}
#[test]
fn parse_reads_reasoning_effort_fields() {
    use fuigo_sampling_types::ReasoningEffort;
    let value = serde_json::json!({
        "model": "grok-4.5",
        "context_window": 1_000_000,
        "supports_reasoning_effort": true,
        "reasoning_effort": "high"
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    assert!(result.supports_reasoning_effort);
    assert_eq!(result.reasoning_effort, Some(ReasoningEffort::High));
    let value = serde_json::json!({
        "model": "grok-4.5",
        "contextWindow": 1_000_000,
        "supportsReasoningEffort": true,
        "reasoningEffort": "xhigh"
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    assert!(result.supports_reasoning_effort);
    assert_eq!(result.reasoning_effort, Some(ReasoningEffort::Xhigh));
    let value = serde_json::json!({"model": "x", "context_window": 256_000});
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    assert!(!result.supports_reasoning_effort);
    assert!(result.reasoning_effort.is_none());
}
#[test]
fn parse_reads_reasoning_efforts_list() {
    use fuigo_sampling_types::ReasoningEffort;
    let value = serde_json::json!({
        "model": "grok-4.5",
        "context_window": 1_000_000,
        "reasoning_efforts": [
            { "id": "deep", "value": "xhigh", "label": "Deep" },
            { "value": "quantum" },
            "low",
        ]
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    assert_eq!(result.reasoning_efforts.len(), 2);
    assert_eq!(result.reasoning_efforts[0].id, "deep");
    assert_eq!(result.reasoning_efforts[0].value, ReasoningEffort::Xhigh);
    assert_eq!(result.reasoning_efforts[1].value, ReasoningEffort::Low);
    for value in [
        serde_json::json!({
            "model": "m", "context_window": 256_000,
            "reasoningEfforts": [{ "value": "high" }]
        }),
        serde_json::json!({
            "model": "m", "context_window": 256_000,
            "_meta": { "reasoningEfforts": [{ "value": "high" }] }
        }),
    ] {
        let result = parse_remote_model_value(&value, "https://default.url").unwrap();
        assert_eq!(result.reasoning_efforts.len(), 1);
        assert_eq!(result.reasoning_efforts[0].value, ReasoningEffort::High);
    }
    let value = serde_json::json!({"model": "x", "context_window": 256_000});
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    assert!(result.reasoning_efforts.is_empty());
}
#[test]
fn parse_reads_meta_fallback_fields() {
    let value = serde_json::json!({
        "_meta": {
            "model": "meta-model-id",
            "contextWindow": 131072,
            "agentType": "concise"
        }
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    assert_eq!(result.model, "meta-model-id");
    assert_eq!(
        result.context_window,
        std::num::NonZeroU64::new(131072).unwrap()
    );
    assert_eq!(result.agent_type, "concise");
}
#[test]
fn parse_remote_model_value_no_laziness_detector_block_yields_default() {
    let value = serde_json::json!({
        "model": "grok-4",
        "context_window": 256_000,
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    assert_eq!(
        result.laziness_detector,
        crate::agent::config::LazinessDetectorPerModelConfig::default()
    );
}
#[test]
fn parse_remote_model_value_parses_camelcase_key() {
    let value = serde_json::json!({
        "model": "grok-4",
        "context_window": 256_000,
        "lazinessDetector": {
            "enabled": true,
            "max_nudges_per_session": 2,
            "idle_threshold_ms": 12_000,
            "min_confidence": 0.75,
        },
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    let expected = crate::agent::config::LazinessDetectorPerModelConfig {
        enabled: true,
        max_nudges_per_session: 2,
        idle_threshold_ms: Some(12_000),
        min_confidence: Some(0.75),
        include_reasoning: None,
    };
    assert_eq!(result.laziness_detector, expected);
}
#[test]
fn parse_remote_model_value_parses_snake_case_laziness_detector() {
    let value = serde_json::json!({
        "model": "grok-4",
        "context_window": 256_000,
        "laziness_detector": {
            "enabled": true,
            "max_nudges_per_session": 3,
            "idle_threshold_ms": 8_000,
            "min_confidence": 0.6,
        },
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    let expected = crate::agent::config::LazinessDetectorPerModelConfig {
        enabled: true,
        max_nudges_per_session: 3,
        idle_threshold_ms: Some(8_000),
        min_confidence: Some(0.6),
        include_reasoning: None,
    };
    assert_eq!(result.laziness_detector, expected);
}
#[test]
fn parse_remote_model_value_parses_meta_laziness_detector() {
    let value = serde_json::json!({
        "model": "grok-4",
        "context_window": 256_000,
        "_meta": {
            "lazinessDetector": {
                "enabled": true,
                "max_nudges_per_session": 1,
                "idle_threshold_ms": 15_000,
                "min_confidence": 0.9,
            },
        },
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    let expected = crate::agent::config::LazinessDetectorPerModelConfig {
        enabled: true,
        max_nudges_per_session: 1,
        idle_threshold_ms: Some(15_000),
        min_confidence: Some(0.9),
        include_reasoning: None,
    };
    assert_eq!(result.laziness_detector, expected);
}
#[test]
fn parse_remote_model_value_partial_block_uses_field_defaults() {
    let value = serde_json::json!({
        "model": "grok-4",
        "context_window": 256_000,
        "lazinessDetector": {
            "enabled": true,
        },
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    let expected = crate::agent::config::LazinessDetectorPerModelConfig {
        enabled: true,
        max_nudges_per_session: 0,
        idle_threshold_ms: None,
        min_confidence: None,
        include_reasoning: None,
    };
    assert_eq!(result.laziness_detector, expected);
}
#[test]
fn parse_remote_model_value_malformed_block_falls_back_to_default() {
    let value = serde_json::json!({
        "model": "grok-4",
        "context_window": 256_000,
        "lazinessDetector": {
            "enabled": true,
            "max_nudges_per_session": "abc",
        },
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    assert_eq!(
        result.laziness_detector,
        crate::agent::config::LazinessDetectorPerModelConfig::default()
    );
}
#[test]
fn parse_remote_model_value_non_object_value_falls_back_to_default() {
    let value = serde_json::json!({
        "model": "grok-4",
        "context_window": 256_000,
        "lazinessDetector": "not-an-object",
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    assert_eq!(
        result.laziness_detector,
        crate::agent::config::LazinessDetectorPerModelConfig::default()
    );
}
#[test]
fn parse_remote_model_value_top_level_camelcase_wins_over_snake_case() {
    let value = serde_json::json!({
        "model": "grok-4",
        "context_window": 256_000,
        "lazinessDetector": {
            "enabled": true,
            "max_nudges_per_session": 7,
        },
        "laziness_detector": {
            "enabled": false,
            "max_nudges_per_session": 99,
        },
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    let expected = crate::agent::config::LazinessDetectorPerModelConfig {
        enabled: true,
        max_nudges_per_session: 7,
        idle_threshold_ms: None,
        min_confidence: None,
        include_reasoning: None,
    };
    assert_eq!(result.laziness_detector, expected);
}
/// `include_reasoning: false` parses under the camelCase `lazinessDetector` wrapper with a snake_case inner key.
/// That naming matches the sibling fields `min_confidence` and `idle_threshold_ms`.
#[test]
fn parse_remote_model_value_parses_include_reasoning_under_camelcase_wrapper() {
    let value = serde_json::json!({
        "model": "grok-4",
        "context_window": 256_000,
        "lazinessDetector": {
            "enabled": true,
            "include_reasoning": false,
        },
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    assert_eq!(result.laziness_detector.include_reasoning, Some(false));
}
#[test]
fn parse_remote_model_value_parses_include_reasoning_under_snake_case_wrapper() {
    let value = serde_json::json!({
        "model": "grok-4",
        "context_window": 256_000,
        "laziness_detector": {
            "enabled": true,
            "include_reasoning": true,
        },
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    assert_eq!(result.laziness_detector.include_reasoning, Some(true));
}
#[test]
fn parse_remote_model_value_omitted_include_reasoning_defaults_to_none() {
    let value = serde_json::json!({
        "model": "grok-4",
        "context_window": 256_000,
        "lazinessDetector": {
            "enabled": true,
            "max_nudges_per_session": 2,
        },
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    assert_eq!(
        result.laziness_detector.include_reasoning, None,
        "absent include_reasoning defers to harness default via None",
    );
}
#[test]
fn parse_remote_model_value_top_level_wins_over_meta() {
    let value = serde_json::json!({
        "model": "grok-4",
        "context_window": 256_000,
        "lazinessDetector": {
            "enabled": true,
            "max_nudges_per_session": 5,
        },
        "_meta": {
            "lazinessDetector": {
                "enabled": false,
                "max_nudges_per_session": 99,
            },
        },
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    let expected = crate::agent::config::LazinessDetectorPerModelConfig {
        enabled: true,
        max_nudges_per_session: 5,
        idle_threshold_ms: None,
        min_confidence: None,
        include_reasoning: None,
    };
    assert_eq!(result.laziness_detector, expected);
}
#[test]
fn parse_reads_show_model_fingerprint_field() {
    let value = serde_json::json!({
        "model": "fuigo-build",
        "context_window": 256_000,
        "show_model_fingerprint": true
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    assert!(result.show_model_fingerprint);
    let value = serde_json::json!({
        "model": "fuigo-build",
        "contextWindow": 256_000,
        "showModelFingerprint": true
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    assert!(result.show_model_fingerprint);
    let value = serde_json::json!({
        "model": "fuigo-build",
        "context_window": 256_000,
        "_meta": { "showModelFingerprint": true }
    });
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    assert!(result.show_model_fingerprint);
    let value = serde_json::json!({"model": "x", "context_window": 256_000});
    let result = parse_remote_model_value(&value, "https://default.url").unwrap();
    assert!(!result.show_model_fingerprint);
}
#[test]
fn get_object_returns_none_for_non_object_values() {
    let value = serde_json::json!({
        "string": "hello",
        "number": 42,
        "bool": true,
        "array": [1, 2, 3],
        "null": null,
    });
    let obj = value.as_object().unwrap();
    assert!(get_object(obj, "string").is_none());
    assert!(get_object(obj, "number").is_none());
    assert!(get_object(obj, "bool").is_none());
    assert!(get_object(obj, "array").is_none());
    assert!(get_object(obj, "null").is_none());
    assert!(get_object(obj, "missing").is_none());
}
#[test]
fn get_object_returns_some_for_actual_object() {
    let value = serde_json::json!({
        "nested": { "a": 1, "b": "two" },
    });
    let obj = value.as_object().unwrap();
    let nested = get_object(obj, "nested").expect("nested key should resolve to object");
    assert!(nested.is_object());
    assert_eq!(nested["a"], serde_json::json!(1));
    assert_eq!(nested["b"], serde_json::json!("two"));
}
fn endpoints(
    proxy: &str,
    models_base_url: Option<&str>,
    models_list_url: Option<&str>,
) -> crate::agent::config::EndpointsConfig {
    crate::agent::config::EndpointsConfig {
        cli_chat_proxy_base_url: Some(proxy.to_owned()),
        models_base_url: models_base_url.map(|s| s.to_owned()),
        models_list_url: models_list_url.map(|s| s.to_owned()),
        ..Default::default()
    }
}
/// Inference follows `fuigo_api_base_url`, NOT the auxiliary proxy. Upstream
/// routed it through the proxy; that is the inversion this fork depends on.
#[test]
fn inference_url_defaults_to_the_gateway_not_the_proxy() {
    let ep = endpoints("https://proxy.example.com/v1", None, None);
    assert_eq!(
        ep.resolve_inference_base_url(),
        crate::agent::config::FUIGO_API_BASE_URL_DEFAULT
    );
}
#[test]
fn inference_url_uses_models_base_url() {
    let ep = endpoints(
        "https://proxy.grok.com/v1",
        Some("https://enterprise.acme.com/v1"),
        None,
    );
    assert_eq!(
        ep.resolve_inference_base_url(),
        "https://enterprise.acme.com/v1"
    );
}
#[test]
fn inference_url_base_url_wins_over_proxy() {
    let ep = endpoints(
        "https://proxy.grok.com/v1",
        Some("https://inference.acme.com/v1"),
        Some("https://registry.acme.com/api/models"),
    );
    assert_eq!(
        ep.resolve_inference_base_url(),
        "https://inference.acme.com/v1"
    );
}
#[test]
fn list_url_defaults_to_proxy_models() {
    let ep = endpoints("https://proxy.grok.com/v1", None, None);
    assert_eq!(
        ep.resolve_models_list_url(),
        "https://proxy.grok.com/v1/models"
    );
}
#[test]
fn list_url_derived_from_base_url() {
    let ep = endpoints(
        "https://proxy.grok.com/v1",
        Some("https://api.x.ai/v1"),
        None,
    );
    assert_eq!(ep.resolve_models_list_url(), "https://api.x.ai/v1/models");
}
#[test]
fn list_url_explicit_overrides_derivation() {
    let ep = endpoints(
        "https://proxy.grok.com/v1",
        Some("https://inference.acme.com/v1"),
        Some("https://registry.acme.com/api/list-models"),
    );
    assert_eq!(
        ep.resolve_models_list_url(),
        "https://registry.acme.com/api/list-models"
    );
}
/// REGRESSION: `fuigo setup` must send the deployment key to the proxy, never the inference endpoint.
#[test]
#[serial_test::serial]
fn deployment_config_url_uses_cli_chat_proxy_when_not_overridden() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    use crate::agent::config::EndpointsConfig;
    for k in [
        "FUIGO_CLI_CHAT_PROXY_BASE_URL",
        "FUIGO_MANAGED_CONFIG_URL",
        "FUIGO_API_BASE_URL",
    ] {
        unsafe { std::env::remove_var(k) };
    }
    unsafe { std::env::set_var("FUIGO_DEPLOYMENT_KEY", "fuigo-token-ENTERPRISE") };
    let managed: toml::Value = toml::from_str(
        r#"[endpoints]
            deployment_key = "fuigo-token-ENTERPRISE"
            fuigo_api_base_url = "https://inference.acme-corp.example/fuigo/v1""#,
    )
    .unwrap();
    let url = EndpointsConfig::from_config_value(&managed).resolve_managed_config_url();
    // With no auxiliary proxy configured this is a bare path, which reaches
    // nothing -- the point of the assertion is that it does NOT follow the
    // inference endpoint.
    assert_eq!(url, "/deployment/config");
    assert!(
        !url.contains("fluxrouter"),
        "must not follow inference: {url}"
    );
    assert!(
        !url.contains("acme-corp"),
        "deployment key would be sent to the inference host: {url}"
    );
    let pinned: toml::Value = toml::from_str(
        r#"[endpoints]
            fuigo_api_base_url = "https://inference.acme-corp.example/fuigo/v1"
            cli_chat_proxy_base_url = "https://proxy.acme-corp.example/v1""#,
    )
    .unwrap();
    assert_eq!(
        EndpointsConfig::from_config_value(&pinned).resolve_managed_config_url(),
        "https://proxy.acme-corp.example/v1/deployment/config"
    );
    unsafe { std::env::remove_var("FUIGO_DEPLOYMENT_KEY") };
}
#[derive(Clone)]
struct DualBundleServerState {
    archive_status: StatusCode,
    archive_bytes: Vec<u8>,
    legacy_status: StatusCode,
    legacy_body: serde_json::Value,
}
async fn start_dual_bundle_server(
    state: DualBundleServerState,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let app = Router::new()
        .route(
            "/v1/bundle/archive",
            get(|State(state): State<DualBundleServerState>| async move {
                (state.archive_status, state.archive_bytes)
            }),
        )
        .route(
            "/v1/subagents/bundle",
            get(|State(state): State<DualBundleServerState>| async move {
                (state.legacy_status, axum::Json(state.legacy_body))
            }),
        )
        .with_state(state);
    let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("{base}/v1"), handle)
}
#[tokio::test(flavor = "current_thread")]
async fn fetch_bundle_returns_archive_on_success() {
    let Some(front) = crate::test_support::session_wire::fronted_child(
        "remote::client::tests::fetch_bundle_returns_archive_on_success",
    ) else {
        return;
    };
    let archive_bytes = b"fake-tar-gz-bytes".to_vec();
    let (proxy_base_url, server) = start_dual_bundle_server(DualBundleServerState {
        archive_status: StatusCode::OK,
        archive_bytes: archive_bytes.clone(),
        legacy_status: StatusCode::OK,
        legacy_body: serde_json::json!({
            "version": "v1", "personas": {}, "roles": {}, "agents": {}
        }),
    })
    .await;
    let proxy_base_url = front.front(&proxy_base_url);
    let am = test_auth_manager();
    let result = fetch_bundle(&proxy_base_url, Some(&am), None, None)
        .await
        .unwrap();
    match result {
        FetchedBundle::Archive(bytes) => assert_eq!(bytes, archive_bytes),
        FetchedBundle::Legacy(_) => panic!("expected Archive variant"),
    }
    server.abort();
}
#[tokio::test(flavor = "current_thread")]
async fn fetch_bundle_falls_back_on_archive_404() {
    let Some(front) = crate::test_support::session_wire::fronted_child(
        "remote::client::tests::fetch_bundle_falls_back_on_archive_404",
    ) else {
        return;
    };
    let (proxy_base_url, server) = start_dual_bundle_server(DualBundleServerState {
        archive_status: StatusCode::NOT_FOUND,
        archive_bytes: Vec::new(),
        legacy_status: StatusCode::OK,
        legacy_body: serde_json::json!({
            "version": "v1",
            "personas": {"r": "p"},
            "roles": {},
            "agents": {}
        }),
    })
    .await;
    let proxy_base_url = front.front(&proxy_base_url);
    let am = test_auth_manager();
    let result = fetch_bundle(&proxy_base_url, Some(&am), None, None)
        .await
        .unwrap();
    match result {
        FetchedBundle::Legacy(bundle) => {
            assert_eq!(bundle.version, "v1");
            assert_eq!(bundle.personas.get("r"), Some(&"p".to_string()));
        }
        FetchedBundle::Archive(_) => panic!("expected Legacy variant"),
    }
    server.abort();
}
#[tokio::test(flavor = "current_thread")]
async fn fetch_bundle_falls_back_on_archive_503() {
    let Some(front) = crate::test_support::session_wire::fronted_child(
        "remote::client::tests::fetch_bundle_falls_back_on_archive_503",
    ) else {
        return;
    };
    let (proxy_base_url, server) = start_dual_bundle_server(DualBundleServerState {
        archive_status: StatusCode::SERVICE_UNAVAILABLE,
        archive_bytes: Vec::new(),
        legacy_status: StatusCode::OK,
        legacy_body: serde_json::json!({
            "version": "v1", "personas": {}, "roles": {}, "agents": {}
        }),
    })
    .await;
    let proxy_base_url = front.front(&proxy_base_url);
    let am = test_auth_manager();
    let result = fetch_bundle(&proxy_base_url, Some(&am), None, None)
        .await
        .unwrap();
    match &result {
        FetchedBundle::Legacy(bundle) => assert_eq!(bundle.version, "v1"),
        FetchedBundle::Archive(_) => panic!("expected Legacy variant"),
    }
    server.abort();
}
/// `BackendClient::save_session_data` resolves auth from the attached `AuthManager` and sends the token as `Bearer <key>` on the wire.
/// This is the writeback path used on every session flush.
#[tokio::test(flavor = "current_thread")]
async fn backend_client_resolves_auth_from_auth_manager() {
    let Some(front) = crate::test_support::session_wire::fronted_child(
        "remote::client::tests::backend_client_resolves_auth_from_auth_manager",
    ) else {
        return;
    };
    let captured_auth = Arc::new(Mutex::new(None::<String>));
    let captured = captured_auth.clone();
    let app = Router::new().route(
        "/sessions/{id}/data",
        axum::routing::post(move |headers: HeaderMap| async move {
            *captured.lock().unwrap() = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            StatusCode::OK
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let am = test_auth_manager();
    let client = BackendClient::with_base_url(front.front(&format!("http://{addr}"))).with_auth_manager(am);
    client
        .save_session_data("test-session", &[], None)
        .await
        .unwrap();
    let sent = captured_auth
        .lock()
        .unwrap()
        .clone()
        .expect("server must receive Authorization header");
    assert_eq!(sent, "Bearer token", "must use token from AuthManager");
    server.abort();
}
#[tokio::test(flavor = "current_thread")]
async fn fetch_bundle_propagates_legacy_error_after_fallback() {
    let Some(front) = crate::test_support::session_wire::fronted_child(
        "remote::client::tests::fetch_bundle_propagates_legacy_error_after_fallback",
    ) else {
        return;
    };
    let (proxy_base_url, server) = start_dual_bundle_server(DualBundleServerState {
        archive_status: StatusCode::NOT_FOUND,
        archive_bytes: Vec::new(),
        legacy_status: StatusCode::UNAUTHORIZED,
        legacy_body: serde_json::json!({"error": "unauthorized"}),
    })
    .await;
    let proxy_base_url = front.front(&proxy_base_url);
    let am = test_auth_manager();
    let error = fetch_bundle(&proxy_base_url, Some(&am), None, None)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        BackendError::RequestFailed { status: 401, .. }
    ));
    server.abort();
}
/// Regression: reqwest .header() appends, so duplicate or overlapping headers cause Cloudflare to reject the request.
#[tokio::test(flavor = "current_thread")]
#[allow(clippy::disallowed_methods)]
async fn auth_headers_do_not_collide_with_json() {
    let client =
        BackendClient::with_base_url("http://localhost").with_auth_manager(test_auth_manager());
    let auth_headers = client.auth_header_map().await.unwrap();
    assert!(
        !auth_headers.contains_key("content-type"),
        "content-type in auth map would overwrite .json()"
    );
    let request = reqwest::Client::new()
        .put("http://localhost/sessions/test")
        .json(&serde_json::json!({"test": true}))
        .headers(auth_headers)
        .build()
        .unwrap();
    for name in request.headers().keys() {
        let count = request.headers().get_all(name).iter().count();
        assert_eq!(count, 1, "duplicate header {name}");
    }
}
/// P43. The session-history backend (`FUIGO_CODE_BACKEND_URL`, operator-configured): the
/// request `send_with_auth` sends carries identity only to a FluxRouter-operated destination.
#[tokio::test(flavor = "current_thread")]
async fn backend_requests_carry_identity_only_to_fluxrouter() {
    let http = crate::http::shared_client();
    let client = BackendClient::with_base_url("https://api.fluxrouter.ai")
        .with_auth_manager(test_auth_manager());
    let request = client
        .authed_request(http.get("https://api.fluxrouter.ai/sessions"))
        .await
        .unwrap();
    assert_eq!(request.headers()["x-userid"], "user-1");
    assert_eq!(request.headers()["x-email"], "test@example.com");
    assert!(request.headers().contains_key("x-fuigo-client-version"));
    assert!(request.headers().contains_key("x-fuigo-client-identifier"));
    for base in ["https://backend.example", "http://127.0.0.1:9", "http://api.fluxrouter.ai"] {
        let client = BackendClient::with_base_url(base).with_auth_manager(test_auth_manager());
        let request = client
            .authed_request(http.get(format!("{base}/sessions")))
            .await
            .unwrap();
        for name in fuigo_extra_ca::fluxrouter::IDENTITY_HEADER_NAMES {
            assert!(!request.headers().contains_key(name), "{base} got {name}");
        }
        assert!(request.headers().contains_key("x-xai-token-auth"));
    }
}
fn upsert_test_metadata() -> ExportedMetadata {
    ExportedMetadata {
        title: Some("t".into()),
        cwd: "/repo".into(),
        model_id: None,
        created_at: None,
        updated_at: None,
        total_messages: Some(0),
        parent_session_id: None,
        session_kind: None,
        subagent_type: None,
        subagent_persona: None,
        subagent_role: None,
        fork_context_source: None,
        subagent_depth: None,
        title_is_manual: None,
    }
}
/// P54 hostile: the session-history backend upsert (history sync, share, fork and worktree
/// resume all go through it) puts no machine id in the body on the wire to a backend that is not
/// FluxRouter-operated, only the origin-scoped pseudonym; FluxRouter still receives the id.
#[tokio::test(flavor = "current_thread")]
async fn session_upsert_sends_no_machine_id_to_a_non_fluxrouter_backend() {
    // P47: the upsert carries the session, so it goes only to an https service origin; the front
    // gives the plain loopback mock one.
    let Some(front) = crate::test_support::session_wire::fronted_child(
        "remote::client::tests::session_upsert_sends_no_machine_id_to_a_non_fluxrouter_backend",
    ) else {
        return;
    };
    const MACHINE_ID: &str = "5d1f0c2a-7a7a-4b4b-8c8c-0123456789ab";
    let bodies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured = bodies.clone();
    let app = Router::new().route(
        "/sessions/{id}",
        axum::routing::put(move |body: String| {
            let captured = captured.clone();
            async move {
                captured.lock().unwrap().push(body);
                StatusCode::OK
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let base = front.front_service(&base);
    let client = BackendClient::with_base_url(base.clone()).with_auth_manager(test_auth_manager());
    client
        .upsert_session("s1", &upsert_test_metadata(), MACHINE_ID)
        .await
        .unwrap();
    let body = bodies.lock().unwrap().first().cloned().expect("backend saw the upsert");
    assert!(!body.contains(MACHINE_ID), "machine id on the wire: {body}");
    let sent: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        sent["agentId"].as_str(),
        Some(
            fuigo_extra_ca::fluxrouter::destination_pseudonym(&format!("{base}/sessions/s1"), MACHINE_ID)
                .as_str()
        )
    );
    assert_eq!(sent["session"]["cwd"], "/repo");
    let flux = upsert_session_request(
        "https://api.fluxrouter.ai/sessions/s1",
        &upsert_test_metadata(),
        MACHINE_ID,
    );
    assert_eq!(flux.agent_id, MACHINE_ID);
    for other in ["https://backend.example/sessions/s1", "http://api.fluxrouter.ai/sessions/s1"] {
        assert_ne!(upsert_session_request(other, &upsert_test_metadata(), MACHINE_ID).agent_id, MACHINE_ID, "{other}");
    }
    server.abort();
}
// ===== No vendor host as a default (1.0.20, REM-1 / REM-3) =====
//
// Env access is process-global: these run `#[serial_test::serial]` and restore
// the prior value through `EnvGuard`, like the other env-touching tests here.

/// Row 1: with `FUIGO_CODE_BACKEND_URL` unset the backend client resolves NO host.
/// Upstream fell back to its vendor's `code.` origin here.
/// (Inspects `Debug` output only, so it compiles against the pre-fix `&str` too.)
#[test]
#[serial_test::serial]
fn backend_client_without_backend_url_names_no_vendor_host() {
    let _unset = fuigo_test_support::EnvGuard::unset("FUIGO_CODE_BACKEND_URL");
    let client = BackendClient::new();
    let rendered = format!("{:?}", client.base_url());
    assert!(
        !rendered.contains("grok.com"),
        "backend base fell back to a vendor host: {rendered}"
    );
}

/// Row 2: with `FUIGO_CODE_WEB_URL` unset there is no share URL to build.
/// Upstream invented `<vendor>/build/share/<id>` here.
#[test]
#[serial_test::serial]
fn share_url_without_web_origin_names_no_vendor_host() {
    let _unset = fuigo_test_support::EnvGuard::unset("FUIGO_CODE_WEB_URL");
    let rendered = format!("{:?}", share_url("perm-123"));
    assert!(
        !rendered.contains("grok.com"),
        "share URL invented a vendor host: {rendered}"
    );
}

/// Row 1, typed: unset means `None`, and every request fails closed with a message that
/// names the variable rather than a DNS/egress refusal for a host nobody asked for.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn backend_client_without_backend_url_fails_closed_with_a_true_message() {
    let _unset = fuigo_test_support::EnvGuard::unset("FUIGO_CODE_BACKEND_URL");
    let client = BackendClient::new().with_auth_manager(test_auth_manager());
    assert_eq!(client.base_url(), None);
    let err = client.list_sessions().await.expect_err("no backend, no request");
    let shown = err.to_string();
    assert!(matches!(err, BackendError::NotConfigured(_)), "{shown}");
    assert!(shown.contains("FUIGO_CODE_BACKEND_URL"), "{shown}");
    assert!(!shown.contains("grok.com"), "{shown}");
    let err = client
        .delete_session_data("s1")
        .await
        .expect_err("no backend, no request");
    assert!(matches!(err, BackendError::NotConfigured(_)));
}

/// P54-K: a DEFAULT install has no destination that P54 touches. Every body-identity site is
/// behind an auxiliary base that ships empty (the session registry, the storage proxy and the
/// internal OTLP firehose behind `cli_chat_proxy_base_url`; the session backend behind
/// `FUIGO_CODE_BACKEND_URL`) or behind a Mixpanel token no public build bakes. So the behaviour
/// change is confined to operator-configured deployments. If any of those bases ever gains a compiled
/// default host, this test says so and the P54 knock-on analysis must be redone for the default
/// install. For Mixpanel it pins only the mechanism (on ⇔ a build-time token is present); a release
/// that bakes a token passes it, so that half rests on the release pipeline, not on this test.
#[test]
#[serial_test::serial]
fn p54_default_install_has_no_body_identity_destination() {
    // FUIGO_CLI_CHAT_PROXY_BASE_URL is an OWN_PROCESS_KEY: every test in this binary reads it.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _proxy = fuigo_test_support::EnvGuard::unset("FUIGO_CLI_CHAT_PROXY_BASE_URL");
    let _backend = fuigo_test_support::EnvGuard::unset("FUIGO_CODE_BACKEND_URL");
    let _token = fuigo_test_support::EnvGuard::unset("FUIGO_TELEMETRY_MIXPANEL_TOKEN");
    let _enabled = fuigo_test_support::EnvGuard::unset("FUIGO_TELEMETRY_MIXPANEL_ENABLED");
    let _trace = fuigo_test_support::EnvGuard::unset("FUIGO_TRACE_UPLOAD_URL");
    let _otlp = fuigo_test_support::EnvGuard::unset("FUIGO_INTERNAL_OTLP_TRACES_ENDPOINT");
    let _otel = fuigo_test_support::EnvGuard::unset("OTEL_EXPORTER_OTLP_ENDPOINT");
    let _otel_traces = fuigo_test_support::EnvGuard::unset("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT");
    assert!(crate::agent::config::CLI_CHAT_PROXY_BASE_URL_DEFAULT.is_empty());
    let endpoints = crate::agent::config::EndpointsConfig::default();
    assert!(!endpoints.has_proxy(), "registry / storage proxy / internal OTLP have a default host");
    // The storage proxy (feedback archives, review comments) and the internal OTLP firehose resolve
    // through their own settings too; with nothing configured neither names a host.
    assert!(endpoints.resolve_trace_upload_url().is_empty(), "storage proxy has a default host");
    assert_eq!(endpoints.resolve_otlp_traces_endpoint(), "/traces", "internal OTLP has a default host");
    assert_eq!(BackendClient::new().base_url(), None, "session backend has a default host");
    let telemetry = fuigo_telemetry::config::TelemetryConfig::default();
    // This pins the mechanism (Mixpanel is on only with a build-time token), not that no public
    // build bakes one: that is a release-pipeline fact (`fuigo-shell/README.md`, "defaults can be
    // baked ... by setting FUIGO_TELEMETRY_BUILD_MIXPANEL_TOKEN") a unit test cannot see.
    let baked = option_env!("FUIGO_TELEMETRY_BUILD_MIXPANEL_TOKEN").is_some_and(|t| !t.trim().is_empty());
    assert_eq!(telemetry.mixpanel_enabled, baked, "Mixpanel is on without a build-time token");
    assert_eq!(telemetry.mixpanel_token.is_some(), baked);
    // Inference itself is FluxRouter-operated, so identity there is unchanged by P54.
    assert!(fuigo_extra_ca::fluxrouter::is_fluxrouter_operated_url(
        crate::agent::config::FUIGO_API_BASE_URL_DEFAULT
    ));
}

/// Row 1, set: the override is honoured verbatim, as before.
#[test]
#[serial_test::serial]
fn backend_client_with_backend_url_uses_it() {
    let _set =
        fuigo_test_support::EnvGuard::set("FUIGO_CODE_BACKEND_URL", "http://backend.example.test");
    assert_eq!(
        BackendClient::new().base_url(),
        Some("http://backend.example.test")
    );
}

/// Row 1, empty: an empty value counts as unset (the sibling clients' convention).
#[test]
#[serial_test::serial]
fn backend_client_with_empty_backend_url_is_unconfigured() {
    let _set = fuigo_test_support::EnvGuard::set("FUIGO_CODE_BACKEND_URL", "");
    assert_eq!(BackendClient::new().base_url(), None);
}

/// Row 2, typed: unset means `None`; set builds `<origin>/build/share/<id>` exactly as before.
#[test]
#[serial_test::serial]
fn share_url_follows_the_configured_web_origin_only() {
    {
        let _unset = fuigo_test_support::EnvGuard::unset("FUIGO_CODE_WEB_URL");
        assert_eq!(share_url("perm-123"), None);
    }
    {
        let _set =
            fuigo_test_support::EnvGuard::set("FUIGO_CODE_WEB_URL", "https://share.example.test");
        assert_eq!(
            share_url("perm-123").as_deref(),
            Some("https://share.example.test/build/share/perm-123")
        );
    }
    {
        let _set = fuigo_test_support::EnvGuard::set("FUIGO_CODE_WEB_URL", "");
        assert_eq!(share_url("perm-123"), None);
    }
}

/// A share is refused BEFORE any upload when either half is missing, and the refusal
/// names the missing variable. With both set, the origin comes back for the link.
#[test]
#[serial_test::serial]
fn share_link_origin_fails_closed_on_either_missing_half() {
    let _backend = fuigo_test_support::EnvGuard::unset("FUIGO_CODE_BACKEND_URL");
    let _web = fuigo_test_support::EnvGuard::unset("FUIGO_CODE_WEB_URL");
    let err = BackendClient::new()
        .share_link_origin()
        .expect_err("no backend");
    assert!(err.to_string().contains("FUIGO_CODE_BACKEND_URL"), "{err}");
    let _backend = fuigo_test_support::EnvGuard::set("FUIGO_CODE_BACKEND_URL", "http://b.example.test");
    let err = BackendClient::new()
        .share_link_origin()
        .expect_err("backend but no web origin");
    assert!(err.to_string().contains("FUIGO_CODE_WEB_URL"), "{err}");
    assert!(!err.to_string().contains("grok.com"), "{err}");
    let _web = fuigo_test_support::EnvGuard::set("FUIGO_CODE_WEB_URL", "https://w.example.test");
    assert_eq!(
        BackendClient::new().share_link_origin().unwrap(),
        "https://w.example.test"
    );
}

/// Mock backend that rejects any save whose body names the checkpoint method with `reject`, and stores the rest.
async fn start_checkpoint_rejecting_server(
    reject: StatusCode,
) -> (String, Arc<Mutex<Vec<String>>>, Arc<Mutex<u32>>, tokio::task::JoinHandle<()>) {
    let stored = Arc::new(Mutex::new(Vec::<String>::new()));
    let posts = Arc::new(Mutex::new(0u32));
    let (s2, p2) = (stored.clone(), posts.clone());
    let app = Router::new().route(
        "/sessions/{id}/data",
        axum::routing::post(move |body: String| async move {
            *p2.lock().unwrap() += 1;
            if body.contains("_fuigo/compaction_checkpoint") {
                return reject;
            }
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            for m in v["messages"].as_array().unwrap() {
                s2.lock().unwrap().push(m["content"].as_str().unwrap().to_owned());
            }
            StatusCode::OK
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), stored, posts, server)
}
fn checkpoint_upload_batch() -> Vec<ExportedMessage> {
    let (marker, file) = crate::session::export::checkpoint_upload_tests::marker_and_file("cp-1", "SUMMARY");
    vec![
        ExportedMessage { content: "{\"method\":\"session/update\",\"n\":1}".into(), timestamp: None },
        ExportedMessage::compaction_checkpoint(&marker, &file).unwrap(),
        ExportedMessage { content: "{\"method\":\"session/update\",\"n\":2}".into(), timestamp: None },
    ]
}
#[tokio::test(flavor = "current_thread")]
async fn save_retries_without_checkpoints_when_backend_rejects_them() {
    let Some(front) = crate::test_support::session_wire::fronted_child(
        "remote::client::tests::save_retries_without_checkpoints_when_backend_rejects_them",
    ) else {
        return;
    };
    for (i, status) in [StatusCode::BAD_REQUEST, StatusCode::PAYLOAD_TOO_LARGE, StatusCode::UNPROCESSABLE_ENTITY]
        .into_iter()
        .enumerate()
    {
        let (url, stored, posts, server) = start_checkpoint_rejecting_server(status).await;
        super::CHECKPOINTS_REFUSED.store(false, std::sync::atomic::Ordering::Relaxed);
        let client = BackendClient::with_base_url(front.front(&url)).with_auth_manager(test_auth_manager());
        let batch = checkpoint_upload_batch();
        client.save_session_data("s", &batch, None).await.unwrap_or_else(|e| panic!("{status}: {e:?}"));
        assert_eq!(stored.lock().unwrap().len(), 2, "normal messages must be stored ({status})");
        assert_eq!(*posts.lock().unwrap(), 2, "one failed attempt, one retry ({status})");
        // The refusal is remembered: the next save goes out once, without checkpoints.
        client.save_session_data("s", &batch, None).await.unwrap();
        // A 413 may be this one checkpoint being too large, so it is not latched: the next save tries again.
        let expected = if status == StatusCode::PAYLOAD_TOO_LARGE { 4 } else { 3 };
        assert_eq!(*posts.lock().unwrap(), expected, "later saves must not fail twice ({i})");
        assert_eq!(stored.lock().unwrap().len(), 4);
        server.abort();
    }
}
#[tokio::test(flavor = "current_thread")]
async fn save_auth_failure_is_not_treated_as_checkpoint_refusal() {
    let Some(front) = crate::test_support::session_wire::fronted_child(
        "remote::client::tests::save_auth_failure_is_not_treated_as_checkpoint_refusal",
    ) else {
        return;
    };
    for status in [StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN] {
        let (url, stored, posts, server) = start_checkpoint_rejecting_server(status).await;
        super::CHECKPOINTS_REFUSED.store(false, std::sync::atomic::Ordering::Relaxed);
        let client = BackendClient::with_base_url(front.front(&url)).with_auth_manager(test_auth_manager());
        let err = client.save_session_data("s", &checkpoint_upload_batch(), None).await.unwrap_err();
        assert!(matches!(err, BackendError::RequestFailed { status: s, .. } if s == status.as_u16()));
        assert_eq!(*posts.lock().unwrap(), 1, "no retry on {status}");
        assert!(stored.lock().unwrap().is_empty());
        assert!(!super::CHECKPOINTS_REFUSED.load(std::sync::atomic::Ordering::Relaxed));
        server.abort();
    }
}

/// Mock backend that rejects EVERY save (an empty one too) with `reject` and counts the POSTs.
async fn start_always_rejecting_server(reject: StatusCode) -> (String, Arc<Mutex<u32>>, tokio::task::JoinHandle<()>) {
    let posts = Arc::new(Mutex::new(0u32));
    let p2 = posts.clone();
    let app = Router::new().route(
        "/sessions/{id}/data",
        axum::routing::post(move |_body: String| async move {
            *p2.lock().unwrap() += 1;
            reject
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), posts, server)
}
/// P132 (P127 follow-up): a batch holding ONLY a checkpoint that gets a 4xx is a refusal. It is not retried with an empty
/// body (a backend that predates the method may reject that too), the checkpoint is dropped (the save returns Ok, so
/// the pending set is cleared), and the refusal is remembered so later checkpoint-only saves send nothing at all.
#[tokio::test(flavor = "current_thread")]
async fn checkpoint_only_batch_refused_is_dropped_and_remembered() {
    let Some(front) = crate::test_support::session_wire::fronted_child(
        "remote::client::tests::checkpoint_only_batch_refused_is_dropped_and_remembered",
    ) else {
        return;
    };
    let only_checkpoint = || vec![checkpoint_upload_batch().remove(1)];
    for status in [StatusCode::BAD_REQUEST, StatusCode::UNPROCESSABLE_ENTITY] {
        let (url, posts, server) = start_always_rejecting_server(status).await;
        super::CHECKPOINTS_REFUSED.store(false, std::sync::atomic::Ordering::Relaxed);
        let client = BackendClient::with_base_url(front.front(&url)).with_auth_manager(test_auth_manager());
        client.save_session_data("s", &only_checkpoint(), None).await.unwrap_or_else(|e| panic!("{status}: {e:?}"));
        assert_eq!(*posts.lock().unwrap(), 1, "no empty-body retry ({status})");
        assert!(
            super::CHECKPOINTS_REFUSED.load(std::sync::atomic::Ordering::Relaxed),
            "the refusal must be remembered ({status})"
        );
        client.save_session_data("s", &only_checkpoint(), None).await.unwrap();
        assert_eq!(*posts.lock().unwrap(), 1, "a remembered refusal sends nothing for a checkpoint-only batch ({status})");
        server.abort();
    }
}
/// A 413 on a checkpoint-only batch drops that checkpoint but does not disable later (smaller) ones, and does not retry.
#[tokio::test(flavor = "current_thread")]
async fn checkpoint_only_batch_too_large_is_dropped_but_not_latched() {
    let Some(front) = crate::test_support::session_wire::fronted_child(
        "remote::client::tests::checkpoint_only_batch_too_large_is_dropped_but_not_latched",
    ) else {
        return;
    };
    let (url, posts, server) = start_always_rejecting_server(StatusCode::PAYLOAD_TOO_LARGE).await;
    super::CHECKPOINTS_REFUSED.store(false, std::sync::atomic::Ordering::Relaxed);
    let client = BackendClient::with_base_url(front.front(&url)).with_auth_manager(test_auth_manager());
    let batch = vec![checkpoint_upload_batch().remove(1)];
    client.save_session_data("s", &batch, None).await.unwrap();
    assert_eq!(*posts.lock().unwrap(), 1, "no empty-body retry");
    assert!(!super::CHECKPOINTS_REFUSED.load(std::sync::atomic::Ordering::Relaxed), "413 is not latched");
    client.save_session_data("s", &batch, None).await.unwrap();
    assert_eq!(*posts.lock().unwrap(), 2, "the next checkpoint is tried again");
    server.abort();
}
