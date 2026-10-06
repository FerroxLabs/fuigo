use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::{Mutex, oneshot, watch};

use crate::oauth_config::McpOAuthConfig;
use crate::rmcp::transport::auth::{
    AuthError, AuthorizationManager, AuthorizationMetadata, AuthorizationMetadataSource,
    OAuthClientConfig,
};

const MCP_OAUTH_CLIENT_NAME: &str = "Fuigo";

const CREDENTIAL_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

const BROWSER_AUTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

#[cfg(unix)]
const AUTH_LOCK_WAIT: std::time::Duration =
    BROWSER_AUTH_TIMEOUT.saturating_add(std::time::Duration::from_secs(60));

/// rmcp's discovery client has no request timeout; a hung authorization server would otherwise wedge the flow and the manager lock.
pub(crate) const OAUTH_DISCOVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub(crate) async fn discover_metadata_bounded(
    manager: &AuthorizationManager,
) -> Result<AuthorizationMetadata, AuthError> {
    // rmcp 3.x `resolve_metadata` never fails discovery: it degrades to legacy
    // endpoints guessed from the base URL. The probe's auth decision needs the
    // rmcp 2.x "no OAuth support" signal back, so the fallback maps to
    // `NoAuthorizationSupport` instead of guessing endpoints.
    let resolve = async {
        let resolution = manager.resolve_metadata().await?;
        if resolution.source == AuthorizationMetadataSource::LegacyEndpointFallback {
            return Err(AuthError::NoAuthorizationSupport);
        }
        Ok(resolution.metadata)
    };
    tokio::time::timeout(OAUTH_DISCOVERY_TIMEOUT, resolve)
        .await
        .unwrap_or_else(|_| {
            Err(AuthError::InternalError(format!(
                "OAuth metadata discovery timed out after {}s",
                OAUTH_DISCOVERY_TIMEOUT.as_secs()
            )))
        })
}

/// Whether a discovery failure means the authorization server metadata could not be FETCHED (an HTTP error status such
/// as 500, a network failure, the bounded timeout): a passing problem to retry. Every other failure (an issuer or
/// resource mismatch, a missing issuer, no OAuth at all) is a verdict about the metadata itself.
pub(crate) fn metadata_unavailable(error: &AuthError) -> bool {
    match error {
        AuthError::HttpError(_) => true,
        // rmcp's `discovery_failed` wraps every failed GET. Only a retryable status (rmcp raises "unexpected HTTP status"
        // for 5xx/408/425/429 alone) or a transport failure counts; a cross-origin or looping redirect, a refused
        // address or an oversized body is a verdict, not a blip (Astra r1).
        AuthError::MetadataError(message) => {
            message.starts_with("OAuth metadata discovery failed for")
                && ["unexpected HTTP status", "error sending request", "timed out"]
                    .iter()
                    .any(|cause| message.contains(cause))
        }
        // `discover_metadata_bounded`'s own timeout.
        AuthError::InternalError(message) => message.starts_with("OAuth metadata discovery timed out"),
        _ => false,
    }
}

struct InFlightEntry {
    rx: watch::Receiver<Option<Result<(), String>>>,
    generation: u64,
}

#[allow(clippy::type_complexity)]
static IN_FLIGHT_AUTH: std::sync::LazyLock<Mutex<HashMap<String, InFlightEntry>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

static GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(crate) async fn authenticate_mcp_server_dedup(
    server_name: &str,
    server_url: &str,
    auth_manager: &Arc<Mutex<AuthorizationManager>>,
    byo_config: Option<&McpOAuthConfig>,
    force: bool,
) -> Result<(), String> {
    let mut in_flight = IN_FLIGHT_AUTH.lock().await;

    if in_flight
        .get(server_name)
        .is_some_and(|e| e.rx.has_changed().is_err())
    {
        in_flight.remove(server_name);
    }

    if let Some(entry) = in_flight.get(server_name) {
        if force {
            tracing::info!(
                server = server_name,
                "User-initiated auth override; evicting stale in-flight entry"
            );
            in_flight.remove(server_name);
        } else {
            let mut rx = entry.rx.clone();
            drop(in_flight);
            tracing::info!(
                server = server_name,
                "Another task in this process is already authenticating; waiting..."
            );
            loop {
                let snapshot = rx.borrow_and_update().clone();
                if let Some(result) = snapshot {
                    if result.is_ok() {
                        let mut mgr = auth_manager.lock().await;
                        if !ensure_oauth_ready(server_name, &mut mgr).await.hydrated {
                            return Err(format!(
                                "Auth for '{server_name}' completed elsewhere but this manager failed to hydrate the stored credentials"
                            ));
                        }
                    }
                    return result;
                }
                if rx.changed().await.is_err() {
                    return Err("Auth leader dropped".to_string());
                }
            }
        }
    }

    let generation = GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (tx, rx) = watch::channel::<Option<Result<(), String>>>(None);
    in_flight.insert(server_name.to_string(), InFlightEntry { rx, generation });
    drop(in_flight);

    #[cfg(unix)]
    let result = if force {
        run_browser_auth_flow(server_name, server_url, auth_manager, byo_config, None).await
    } else {
        authenticate_with_fs_lock(server_name, server_url, auth_manager, byo_config).await
    };
    #[cfg(not(unix))]
    let result =
        run_browser_auth_flow(server_name, server_url, auth_manager, byo_config, None).await;

    let _ = tx.send(Some(result.clone()));
    let mut in_flight = IN_FLIGHT_AUTH.lock().await;
    if in_flight
        .get(server_name)
        .is_some_and(|e| e.generation == generation)
    {
        in_flight.remove(server_name);
    }

    result
}

#[cfg(unix)]
async fn authenticate_with_fs_lock(
    server_name: &str,
    server_url: &str,
    auth_manager: &Arc<Mutex<AuthorizationManager>>,
    byo_config: Option<&McpOAuthConfig>,
) -> Result<(), String> {
    let lock_path = auth_lock_path(server_name);

    if let Some(parent) = lock_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let token_before = stored_access_token(server_name, server_url).await;

    let lock_file = match std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
    {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(%e, "Failed to create auth lock file; proceeding without cross-process dedup");
            return run_browser_auth_flow(server_name, server_url, auth_manager, byo_config, None)
                .await;
        }
    };

    let lock_file = tokio::task::spawn_blocking(move || {
        use std::os::unix::io::AsRawFd;
        let fd = lock_file.as_raw_fd();
        let deadline = std::time::Instant::now() + AUTH_LOCK_WAIT;
        loop {
            if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Some(lock_file);
            }
            let err = std::io::Error::last_os_error();
            match err.kind() {
                std::io::ErrorKind::Interrupted => continue,
                std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return None;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
                _ => return None,
            }
        }
    })
    .await
    .ok()
    .flatten();

    if lock_file.is_none() {
        tracing::warn!("Timed out waiting for auth lock; re-checking the store before a new flow");
    }
    let _lock_guard = lock_file;

    let readiness = {
        let mut mgr = auth_manager.lock().await;
        let readiness = ensure_oauth_ready(server_name, &mut mgr).await;
        if readiness.hydrated {
            let token_after = stored_access_token(server_name, server_url).await;
            if token_after.is_some() && token_after != token_before {
                tracing::info!(
                    server = server_name,
                    "Another process already authenticated; reusing fresh token"
                );
                return Ok(());
            }
        }
        readiness
    };

    run_browser_auth_flow(
        server_name,
        server_url,
        auth_manager,
        byo_config,
        Some(readiness),
    )
    .await
}

#[cfg(unix)]
fn auth_lock_path(server_name: &str) -> std::path::PathBuf {
    let safe: String = server_name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    fuigo_config::fuigo_home().join(format!("mcp_auth_{safe}.lock"))
}

/// `readiness` carries a caller's fresh [`ensure_oauth_ready`] result so the flow does not re-probe.
async fn run_browser_auth_flow(
    server_name: &str,
    server_url: &str,
    auth_manager: &Arc<Mutex<AuthorizationManager>>,
    byo_config: Option<&McpOAuthConfig>,
    readiness: Option<OauthReadiness>,
) -> Result<(), String> {
    if try_token_refresh(server_name, auth_manager, readiness).await {
        return Ok(());
    }

    let (listener, redirect_uri) = bind_loopback_callback(byo_config).await?;
    let auth_url =
        build_authorization_url(server_name, auth_manager, byo_config, &redirect_uri).await?;
    let token_before_browser = stored_access_token(server_name, server_url).await;

    open_consent_browser(server_name, &auth_url)?;
    await_callback_or_disk_token(
        server_name,
        server_url,
        auth_manager,
        listener,
        token_before_browser,
    )
    .await
}

async fn stored_access_token(server_name: &str, server_url: &str) -> Option<String> {
    let url = url::Url::parse(server_url).ok()?;
    let name = server_name.to_string();
    tokio::task::spawn_blocking(move || {
        use oauth2::TokenResponse as _;
        let store = crate::credentials::McpCredentialStore::load_default().ok()?;
        store
            .get(&name, &url)
            .and_then(|entry| entry.token_response.as_ref())
            .map(|t| t.access_token().secret().to_string())
    })
    .await
    .ok()
    .flatten()
}

async fn try_token_refresh(
    server_name: &str,
    auth_manager: &Arc<Mutex<AuthorizationManager>>,
    readiness: Option<OauthReadiness>,
) -> bool {
    let mut mgr = auth_manager.lock().await;
    let hydrated = match readiness {
        Some(r) => r.hydrated,
        None => ensure_oauth_ready(server_name, &mut mgr).await.hydrated,
    };
    if !hydrated {
        return false;
    }
    let (refreshed, refusal) = crate::http_policy::capture_refusal(mgr.refresh_token()).await;
    match refreshed {
        Ok(_) => {
            tracing::info!(
                server = server_name,
                "Token refreshed successfully (no browser)"
            );
            true
        }
        Err(e) => {
            tracing::info!(
                server = server_name,
                error = %crate::http_policy::explain_token_error(&e, refusal.as_deref()),
                "Token refresh failed, falling through to browser auth"
            );
            false
        }
    }
}

/// What one [`ensure_oauth_ready`] pass learned, for callers to consume instead of re-probing.
pub(crate) struct OauthReadiness {
    /// The bounded discovery outcome; `Ok` means fresh metadata is set on the manager, `Err` kept whatever metadata the manager already held.
    pub(crate) discovery: Result<(), AuthError>,
    /// Whether the oauth client got hydrated from the credential store.
    pub(crate) hydrated: bool,
}

/// The one prelude to `refresh_token`: bounded discovery (degrading to held metadata), then hydrate the oauth client from the store.
/// The sole caller of `initialize_from_store`; discovery runs at most once per flow.
pub(crate) async fn ensure_oauth_ready(
    server_name: &str,
    mgr: &mut AuthorizationManager,
) -> OauthReadiness {
    let discovery = match discover_metadata_bounded(mgr).await {
        Ok(metadata) => {
            mgr.set_metadata(metadata);
            Ok(())
        }
        Err(e) => {
            tracing::warn!(
                server = server_name,
                %e,
                "OAuth metadata discovery failed; continuing with existing metadata"
            );
            Err(e)
        }
    };
    // `initialize_from_store` re-resolves metadata itself when the manager holds none, and rmcp then falls back to
    // endpoints it guesses from the server's base URL (`{base}/token`, no issuer, so its stored-issuer check is
    // skipped). A stored refresh token for another authorization server could then be sent to the resource server.
    // Hydrate only when this pass validated metadata, so every token endpoint rmcp configures came from a document
    // the adapter judged.
    if discovery.is_err() {
        tracing::warn!(
            server = server_name,
            "No validated authorization server metadata; not loading stored OAuth credentials (they would be bound to guessed endpoints)"
        );
        return OauthReadiness {
            discovery,
            hydrated: false,
        };
    }
    let hydrated =
        match tokio::time::timeout(OAUTH_DISCOVERY_TIMEOUT, mgr.initialize_from_store()).await {
            Ok(Ok(hydrated)) => hydrated,
            Ok(Err(e)) => {
                tracing::warn!(server = server_name, %e, "OAuth client hydration failed");
                false
            }
            Err(_) => {
                tracing::warn!(server = server_name, "OAuth client hydration timed out");
                false
            }
        };
    OauthReadiness {
        discovery,
        hydrated,
    }
}

async fn bind_loopback_callback(
    byo_config: Option<&McpOAuthConfig>,
) -> Result<(tokio::net::TcpListener, String), String> {
    let requested_port = byo_config.and_then(|b| b.callback_port).unwrap_or(0);
    let listener =
        tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], requested_port)))
            .await
            .map_err(|e| format!("Failed to bind loopback port {requested_port}: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("Failed to get loopback port: {e}"))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");
    Ok((listener, redirect_uri))
}

async fn build_authorization_url(
    server_name: &str,
    auth_manager: &Arc<Mutex<AuthorizationManager>>,
    byo_config: Option<&McpOAuthConfig>,
    redirect_uri: &str,
) -> Result<String, String> {
    let byo_scopes: Vec<String> = byo_config
        .and_then(|b| b.scopes.as_ref())
        .cloned()
        .unwrap_or_default();

    let mut mgr = auth_manager.lock().await;

    let scopes: Vec<String>;
    if let Some(byo) = byo_config
        && let Some(client_id) = byo.client_id.clone()
    {
        tracing::info!(
            server = server_name,
            "Using BYO client credentials (oauth_client_id from config)"
        );
        scopes = byo_scopes;
        let mut config =
            OAuthClientConfig::new(client_id, redirect_uri.to_string()).with_scopes(scopes.clone());
        config.client_secret = byo.client_secret.clone();
        mgr.configure_client(config)
            .map_err(|e| format!("Failed to configure BYO client: {e}"))?;
    } else {
        scopes = if byo_scopes.is_empty() {
            mgr.select_scopes(None, &[])
        } else {
            byo_scopes
        };
        let scope_refs: Vec<&str> = scopes.iter().map(|s| s.as_str()).collect();
        mgr.register_client(MCP_OAUTH_CLIENT_NAME, redirect_uri, &scope_refs)
            .await
            .map_err(|e| format!("Dynamic client registration failed: {e}"))?;
    }
    let scopes: Vec<&str> = scopes.iter().map(|s| s.as_str()).collect();

    mgr.get_authorization_url(&scopes)
        .await
        .map_err(|e| format!("Failed to get authorization URL: {e}"))
}

fn open_consent_browser(server_name: &str, auth_url: &str) -> Result<(), String> {
    crate::http_policy::check_url(auth_url)?;
    tracing::info!(server = server_name, "Opening browser for OAuth consent");
    if let Err(e) = webbrowser::open(auth_url) {
        // eprintln! corrupts the TUI alternate screen (in-process, fd 2).
        // TODO: show the auth URL via ACP notification instead
        tracing::warn!(%e, url = %auth_url, "Failed to open browser for MCP OAuth; user must visit URL manually");
    }
    Ok(())
}

/// Peeks the file directly: `initialize_from_store` would clobber the freshly registered client with stored values and break the pending exchange.
async fn wait_for_disk_token(
    server_name: String,
    server_url: String,
    token_snapshot: Option<String>,
) {
    if url::Url::parse(&server_url).is_err() {
        tracing::warn!(
            server = server_name,
            url = server_url,
            "could not parse server URL for credential-store poll; falling back to callback-only auth-completion detection"
        );
        std::future::pending::<()>().await;
        return;
    }
    loop {
        tokio::time::sleep(CREDENTIAL_POLL_INTERVAL).await;
        let token_now = stored_access_token(&server_name, &server_url).await;
        if token_now.is_some() && token_now != token_snapshot {
            return;
        }
    }
}

async fn await_callback_or_disk_token(
    server_name: &str,
    server_url: &str,
    auth_manager: &Arc<Mutex<AuthorizationManager>>,
    listener: tokio::net::TcpListener,
    token_before_browser: Option<String>,
) -> Result<(), String> {
    let poll_store = wait_for_disk_token(
        server_name.to_string(),
        server_url.to_string(),
        token_before_browser,
    );
    let (callback_server, callback_rx) = start_oauth_callback_server(listener);

    tokio::select! {
        result = callback_rx => {
            callback_server.abort();
            let callback = result
                .map_err(|_| "Callback channel dropped".to_string())?
                .map_err(|e| format!("OAuth callback failed: {e}"))?;

            let mgr = auth_manager.lock().await;
            exchange_callback(&mgr, &callback).await?;

            tracing::info!(server = server_name, "MCP OAuth authentication successful");
        }
        _ = poll_store => {
            callback_server.abort();
            tracing::info!(
                server = server_name,
                "Fresh tokens detected on disk from another auth flow; skipping callback wait"
            );
        }
        _ = tokio::time::sleep(BROWSER_AUTH_TIMEOUT) => {
            callback_server.abort();
            tracing::warn!(
                server = server_name,
                timeout_secs = BROWSER_AUTH_TIMEOUT.as_secs(),
                "OAuth consent timed out (browser flow abandoned?)"
            );
            return Err(format!(
                "OAuth consent timed out after {}s; re-run authentication to try again",
                BROWSER_AUTH_TIMEOUT.as_secs()
            ));
        }
    }

    Ok(())
}

/// Pass RFC 9207 `iss` when present (required if the AS advertises it). A refused token endpoint is named in the error.
async fn exchange_callback(
    mgr: &AuthorizationManager,
    callback: &OAuthCallbackPayload,
) -> Result<(), String> {
    let (result, refusal) = crate::http_policy::capture_refusal(
        mgr.exchange_code_for_token_with_issuer(
            &callback.code,
            &callback.state,
            callback.issuer.as_deref(),
        ),
    )
    .await;
    result.map(|_| ()).map_err(|e| {
        format!(
            "Token exchange failed: {}",
            crate::http_policy::explain_token_error(&e, refusal.as_deref())
        )
    })
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OAuthCallbackPayload {
    code: String,
    state: String,
    /// RFC 9207 `iss` (optional; required when the AS advertises support).
    issuer: Option<String>,
}

fn parse_oauth_callback_params(
    params: &HashMap<String, String>,
) -> Result<OAuthCallbackPayload, String> {
    if let Some(error) = params.get("error") {
        let desc = params
            .get("error_description")
            .cloned()
            .unwrap_or_else(|| "Unknown error".to_string());
        return Err(format!("OAuth error: {error} - {desc}"));
    }
    let code = params
        .get("code")
        .filter(|s| !s.is_empty())
        .cloned()
        .ok_or_else(|| "Missing authorization code".to_string())?;
    let state = params
        .get("state")
        .filter(|s| !s.is_empty())
        .cloned()
        .ok_or_else(|| "Missing state parameter".to_string())?;
    let issuer = params.get("iss").cloned();
    Ok(OAuthCallbackPayload {
        code,
        state,
        issuer,
    })
}

/// Caller must abort the returned server task.
#[allow(clippy::type_complexity)]
fn start_oauth_callback_server(
    listener: tokio::net::TcpListener,
) -> (
    tokio::task::JoinHandle<()>,
    oneshot::Receiver<Result<OAuthCallbackPayload, String>>,
) {
    use axum::{Router, extract::Query, response::Html, routing::get};

    let (tx, rx) = oneshot::channel::<Result<OAuthCallbackPayload, String>>();
    let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));

    let handler = {
        let tx = tx.clone();
        move |Query(params): Query<HashMap<String, String>>| {
            let tx = tx.clone();
            async move {
                let result = parse_oauth_callback_params(&params);

                let html = match &result {
                    Ok(_) => {
                        r#"<!DOCTYPE html><html><head><title>Authorization Complete</title></head>
                    <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                    <h1>Authorization Complete</h1>
                    <p>You can close this window and return to the terminal.</p>
                    <script>window.close();</script></body></html>"#
                            .to_string()
                    }
                    Err(e) => {
                        let msg = html_escape(e);
                        format!(
                            r#"<!DOCTYPE html><html><head><title>Authorization Failed</title></head>
                            <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                            <h1>Authorization Failed</h1>
                            <p>{msg}</p>
                            <p>You can close this window and return to the terminal.</p>
                            </body></html>"#
                        )
                    }
                };

                if let Some(tx) = tx.lock().await.take() {
                    let _ = tx.send(result);
                }

                Html(html)
            }
        }
    };

    let app = Router::new().route("/callback", get(handler.clone()).post(handler));

    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (server, rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rmcp::transport::auth::{AuthorizationManager, OAuthClientConfig};

    const TEST_ISSUER: &str = "https://auth.example.com";

    fn params(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn callback_parses_code_state_and_rfc9207_iss() {
        let p = params(&[
            ("code", "auth-code"),
            ("state", "csrf"),
            ("iss", TEST_ISSUER),
        ]);
        let got = parse_oauth_callback_params(&p).unwrap();
        assert_eq!(got.code, "auth-code");
        assert_eq!(got.state, "csrf");
        assert_eq!(got.issuer.as_deref(), Some(TEST_ISSUER));
    }

    #[test]
    fn callback_issuer_optional_for_legacy_servers() {
        let p = params(&[("code", "c"), ("state", "s")]);
        let got = parse_oauth_callback_params(&p).unwrap();
        assert!(got.issuer.is_none());
    }

    #[test]
    fn callback_requires_code_and_state() {
        assert!(parse_oauth_callback_params(&params(&[("state", "s")])).is_err());
        assert!(parse_oauth_callback_params(&params(&[("code", "c")])).is_err());
    }

    #[test]
    fn callback_surfaces_oauth_error() {
        let p = params(&[
            ("error", "access_denied"),
            ("error_description", "user said no"),
        ]);
        let err = parse_oauth_callback_params(&p).unwrap_err();
        assert!(err.contains("access_denied"));
        assert!(err.contains("user said no"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn browser_flow_discovers_metadata_on_demand() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use axum::response::IntoResponse as _;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let discovery_hits = Arc::new(AtomicUsize::new(0));
        let handler_hits = Arc::clone(&discovery_hits);
        let poison_prm = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handler_poison = Arc::clone(&poison_prm);
        let metadata = serde_json::json!({
            "issuer": format!("http://{addr}"),
            "authorization_endpoint": format!("http://{addr}/authorize"),
            "token_endpoint": format!("http://{addr}/token"),
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
        });
        let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
            let hits = Arc::clone(&handler_hits);
            let poisoned = Arc::clone(&handler_poison);
            let metadata = metadata.clone();
            async move {
                let path = req.uri().path().to_string();
                if poisoned.load(Ordering::SeqCst) && path.contains("oauth-protected-resource") {
                    return axum::Json(serde_json::json!({
                        "resource": "https://mismatch.example/",
                    }))
                    .into_response();
                }
                if path.contains("oauth-authorization-server") {
                    hits.fetch_add(1, Ordering::SeqCst);
                    return axum::Json(metadata).into_response();
                }
                axum::http::StatusCode::NOT_FOUND.into_response()
            }
        });
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let server_url = format!("http://{addr}/mcp");
        let mgr = Arc::new(Mutex::new(
            crate::http_policy::auth_manager(server_url.as_str())
                .await
                .unwrap(),
        ));

        let err = run_browser_auth_flow("fake", &server_url, &mgr, None, None)
            .await
            .expect_err("no registration endpoint: flow must fail before the browser");
        assert_eq!(
            discovery_hits.load(Ordering::SeqCst),
            1,
            "browser flow must discover metadata on demand, exactly once: {err}"
        );
        assert!(
            err.contains("Dynamic client registration"),
            "must fail at registration, past discovery: {err}"
        );

        poison_prm.store(true, Ordering::SeqCst);
        let err = run_browser_auth_flow("fake", &server_url, &mgr, None, None)
            .await
            .expect_err("registration still fails");
        assert!(
            err.contains("Dynamic client registration"),
            "a discovery failure must degrade to existing metadata, not abort: {err}"
        );
    }

    // ---- P117: the token endpoint must be one the authorization server controls ----

    /// A loopback authorization server (origin A) whose metadata names its own `/token` until `hostile` is set,
    /// then a recorder on a second origin (B). Both token endpoints answer with a valid token response.
    struct TokenBindingRig {
        as_base: String,
        as_token_hits: Arc<std::sync::atomic::AtomicUsize>,
        recorder_hits: Arc<std::sync::atomic::AtomicUsize>,
        recorder_bodies: Arc<std::sync::Mutex<Vec<String>>>,
        hostile: Arc<std::sync::atomic::AtomicBool>,
    }

    impl TokenBindingRig {
        fn issuer(&self) -> String {
            format!("{}/mcp", self.as_base)
        }
    }

    async fn token_binding_rig() -> TokenBindingRig {
        use axum::{Router, body::Body, http::Response, routing::post};
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        fn token_ok() -> Response<Body> {
            Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"access_token":"at-ok","token_type":"Bearer","expires_in":3600,"refresh_token":"rt-ok"}"#,
                ))
                .unwrap()
        }

        let recorder_hits = Arc::new(AtomicUsize::new(0));
        let recorder_bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (hits, bodies) = (recorder_hits.clone(), recorder_bodies.clone());
        let recorder = Router::new().route(
            "/token",
            post(move |body: String| {
                let (hits, bodies) = (hits.clone(), bodies.clone());
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    bodies.lock().unwrap().push(body);
                    token_ok()
                }
            }),
        );
        let recorder_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let recorder_base = format!("http://{}", recorder_listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(recorder_listener, recorder).await.unwrap();
        });

        let as_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let as_base = format!("http://{}", as_listener.local_addr().unwrap());
        let as_token_hits = Arc::new(AtomicUsize::new(0));
        let hostile = Arc::new(AtomicBool::new(false));
        let (own_hits, flag, base, foreign) = (
            as_token_hits.clone(),
            hostile.clone(),
            as_base.clone(),
            recorder_base,
        );
        let app = Router::new()
            .route(
                "/token",
                post(move || {
                    let own_hits = own_hits.clone();
                    async move {
                        own_hits.fetch_add(1, Ordering::SeqCst);
                        token_ok()
                    }
                }),
            )
            .fallback(move |uri: axum::http::Uri| {
                let (flag, base, foreign) = (flag.clone(), base.clone(), foreign.clone());
                async move {
                    use axum::response::IntoResponse as _;
                    if !uri.path().contains("oauth-authorization-server") {
                        return axum::http::StatusCode::NOT_FOUND.into_response();
                    }
                    let token_endpoint = if flag.load(Ordering::SeqCst) {
                        format!("{foreign}/token")
                    } else {
                        format!("{base}/token")
                    };
                    axum::Json(serde_json::json!({
                        // rmcp 3.x requires the issuer to be exactly the one the discovery URL implies for the /mcp resource
                        "issuer": format!("{base}/mcp"),
                        "authorization_endpoint": format!("{base}/authorize"),
                        "token_endpoint": token_endpoint,
                        "response_types_supported": ["code"],
                        "code_challenge_methods_supported": ["S256"],
                        "authorization_response_iss_parameter_supported": true,
                    }))
                    .into_response()
                }
            });
        tokio::spawn(async move {
            axum::serve(as_listener, app).await.unwrap();
        });
        TokenBindingRig {
            as_base,
            as_token_hits,
            recorder_hits,
            recorder_bodies,
            hostile,
        }
    }

    /// Discover and configure the way the real flow does (`ensure_oauth_ready` then `configure_client`).
    async fn configure_from_discovery(mgr: &mut AuthorizationManager) {
        let metadata = discover_metadata_bounded(mgr)
            .await
            .expect("the rig's metadata is discoverable");
        mgr.set_metadata(metadata);
        mgr.configure_client(
            OAuthClientConfig::new("fuigo-test-client", "http://127.0.0.1:0/callback")
                .with_application_type("native"),
        )
        .unwrap();
    }

    /// The real post-callback exchange, as the browser flow runs it.
    async fn exchange(mgr: &AuthorizationManager, issuer: &str) -> Result<(), String> {
        let auth_url = mgr.get_authorization_url(&[]).await.unwrap();
        let state = url::Url::parse(&auth_url)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "state")
            .expect("auth URL must include state")
            .1
            .into_owned();
        exchange_callback(
            mgr,
            &OAuthCallbackPayload {
                code: "auth-code".to_string(),
                state,
                issuer: Some(issuer.to_string()),
            },
        )
        .await
    }

    #[tokio::test]
    async fn legitimate_same_origin_exchange_and_refresh_still_work() {
        use std::sync::atomic::Ordering;
        let rig = token_binding_rig().await;
        let mut mgr = crate::http_policy::auth_manager(&format!("{}/mcp", rig.as_base))
            .await
            .unwrap();
        configure_from_discovery(&mut mgr).await;
        exchange(&mgr, &rig.issuer()).await.expect("same-origin code exchange");
        assert_eq!(rig.as_token_hits.load(Ordering::SeqCst), 1);
        mgr.refresh_token().await.expect("same-origin refresh");
        assert_eq!(rig.as_token_hits.load(Ordering::SeqCst), 2);
        assert_eq!(rig.recorder_hits.load(Ordering::SeqCst), 0);
    }

    /// A resource server R whose protected-resource document carries a stray `token_endpoint` and names no
    /// authorization server; every other discovery URL is 404. Its `/token` records what it receives.
    async fn resource_server_with_stray_token_endpoint() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use axum::{Router, routing::post};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let doc_base = base.clone();
        let app = Router::new()
            .route(
                "/token",
                post(move || {
                    let counter = counter.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        axum::http::StatusCode::BAD_REQUEST
                    }
                }),
            )
            .fallback(move |uri: axum::http::Uri| {
                let doc_base = doc_base.clone();
                async move {
                    use axum::response::IntoResponse as _;
                    if uri.path().contains("oauth-protected-resource") {
                        return axum::Json(serde_json::json!({
                            "resource": format!("{doc_base}/mcp"),
                            "authorization_servers": [],
                            "token_endpoint": format!("{doc_base}/token"),
                        }))
                        .into_response();
                    }
                    axum::http::StatusCode::NOT_FOUND.into_response()
                }
            });
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (base, hits)
    }

    #[tokio::test]
    async fn stored_refresh_token_for_another_issuer_never_reaches_synthesized_fallback_endpoints() {
        // Astra r3 HIGH: with no usable AS metadata rmcp's hydration re-resolves and synthesizes `{base}/token`.
        use crate::rmcp::transport::auth::InMemoryCredentialStore;
        use std::sync::atomic::Ordering;
        let rig = token_binding_rig().await;
        let store = InMemoryCredentialStore::new();
        let mut first = crate::http_policy::auth_manager(&format!("{}/mcp", rig.as_base))
            .await
            .unwrap();
        first.set_credential_store(store.clone());
        configure_from_discovery(&mut first).await;
        exchange(&first, &rig.issuer()).await.expect("legitimate exchange stores credentials for issuer A");

        let (resource_base, resource_hits) = resource_server_with_stray_token_endpoint().await;
        let mut second = crate::http_policy::auth_manager(&format!("{resource_base}/mcp"))
            .await
            .unwrap();
        second.set_credential_store(store);
        let ready = ensure_oauth_ready("fake", &mut second).await;
        let (refreshed, _refusal) = if ready.hydrated {
            crate::http_policy::capture_refusal(second.refresh_token()).await
        } else {
            (Err(crate::rmcp::transport::auth::AuthError::NoAuthorizationSupport), None)
        };
        assert!(refreshed.is_err(), "no refresh may succeed against unvalidated metadata");
        assert_eq!(
            resource_hits.load(Ordering::SeqCst),
            0,
            "issuer A's refresh token reached the resource server (hydrated={})",
            ready.hydrated
        );
        assert!(!ready.hydrated, "hydration must not run on synthesized fallback metadata");
    }

    #[tokio::test]
    async fn code_is_never_sent_to_a_token_endpoint_on_a_foreign_origin() {
        use std::sync::atomic::Ordering;
        let rig = token_binding_rig().await;
        rig.hostile.store(true, Ordering::SeqCst);
        let mut mgr = crate::http_policy::auth_manager(&format!("{}/mcp", rig.as_base))
            .await
            .unwrap();
        configure_from_discovery(&mut mgr).await;
        let err = exchange(&mgr, &rig.issuer())
            .await
            .expect_err("hostile metadata must not receive the authorization code");
        assert_eq!(
            rig.recorder_hits.load(Ordering::SeqCst),
            0,
            "the foreign endpoint received a request: {:?}",
            rig.recorder_bodies.lock().unwrap()
        );
        assert!(err.contains("refus"), "must say it refused: {err}");
        assert!(
            err.contains("origin"),
            "must say why (the endpoint is not on the authorization server's origin): {err}"
        );
        assert!(!err.contains("auth-code"), "no credential in the message: {err}");
    }

    #[tokio::test]
    async fn refresh_token_is_never_sent_to_a_token_endpoint_on_a_foreign_origin() {
        use std::sync::atomic::Ordering;
        let rig = token_binding_rig().await;
        let mut mgr = crate::http_policy::auth_manager(&format!("{}/mcp", rig.as_base))
            .await
            .unwrap();
        configure_from_discovery(&mut mgr).await;
        exchange(&mgr, &rig.issuer()).await.expect("legitimate first exchange");

        // The metadata later turns hostile (a changed or compromised server); the next refresh must not follow it.
        rig.hostile.store(true, Ordering::SeqCst);
        configure_from_discovery(&mut mgr).await;
        let (refreshed, refusal) = crate::http_policy::capture_refusal(mgr.refresh_token()).await;
        let err = crate::http_policy::explain_token_error(
            &refreshed.expect_err("hostile metadata must not receive the refresh token"),
            refusal.as_deref(),
        );
        assert_eq!(
            rig.recorder_hits.load(Ordering::SeqCst),
            0,
            "the foreign endpoint received a request: {:?}",
            rig.recorder_bodies.lock().unwrap()
        );
        assert!(err.contains("refus"), "must say it refused: {err}");
        assert!(err.contains("origin"), "must say why: {err}");
        assert!(!err.contains("rt-ok"), "no credential in the message: {err}");
    }

    #[tokio::test]
    async fn callback_http_server_forwards_iss_query_param() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (server, rx) = start_oauth_callback_server(listener);

        let url = format!(
            "http://{addr}/callback?code=c1&state=s1&iss={}",
            urlencoding_encode(TEST_ISSUER)
        );
        let resp = reqwest::get(&url).await.unwrap();
        assert!(resp.status().is_success());
        let body = resp.text().await.unwrap();
        assert!(body.contains("Authorization Complete"));

        let payload = rx.await.unwrap().unwrap();
        assert_eq!(payload.code, "c1");
        assert_eq!(payload.state, "s1");
        assert_eq!(payload.issuer.as_deref(), Some(TEST_ISSUER));
        server.abort();
    }

    fn urlencoding_encode(s: &str) -> String {
        s.replace(':', "%3A").replace('/', "%2F")
    }
}
