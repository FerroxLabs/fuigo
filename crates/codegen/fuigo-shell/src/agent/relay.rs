//! WebSocket relay connection management.
//!
//! This module provides a shared `RelayConnection` that handles the WebSocket connection to the grok.com relay server with automatic reconnection.
//! It is used by both `run_headless` and `run_leader` modes.
use super::proxy;
use crate::auth::{FuigoAuth, FuigoComConfig};
use crate::{teprintln, tprintln};
use futures_util::{SinkExt as _, StreamExt as _};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tokio_tungstenite::{
    connect_async_tls_with_config,
    tungstenite::{Message, Utf8Bytes, client::IntoClientRequest},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
const KEEPALIVE_INTERVAL_SECS: u64 = 15;
/// Read-side liveness deadline.
/// The write half pings every `KEEPALIVE_INTERVAL_SECS`, and a healthy peer answers each ping with a pong.
/// A live connection thus delivers an inbound frame at least that often.
/// If *nothing* arrives for this long the connection is treated as dead and the session is torn down so the reconnect loop can take over.
///
/// Without it, a half-open TCP connection blocks `ws_inbound.next()` forever and the agent never reconnects.
/// (E.g. the proxy/NAT leg still ACKs our tiny pings while the upstream relay leg is gone.)
/// Sessions stay bricked until the process is killed; the server sees a 1006 close, the client never notices.
const READ_LIVENESS_TIMEOUT_SECS: u64 = 4 * KEEPALIVE_INTERVAL_SECS;
/// Upper bound on a single auth-recovery attempt: a backstop against an indefinitely wedged relay loop, NOT a bound on a healthy refresh.
/// It must stay comfortably above the refresh path's own internal worst case so it only fires when something is truly stuck.
/// `refresh_chain` waits up to 25s for `auth.json.lock` (`REFRESH_LOCK_TIMEOUT`) before IdP IO.
/// Another 25s applies if the suspend-only revalidate re-acquires the lock.
/// The IdP IO has its own timeouts (7s external refresher; 15s per OIDC request with short retries).
/// When this fires the recovery future is dropped (the file lock releases on drop) and the loop falls through to reconnect backoff.
/// Backoff retries recovery on the next 401.
const AUTH_RECOVERY_TIMEOUT_SECS: u64 = 180;
const BASE_DELAY_SECS: u64 = 1;
const MAX_DELAY_SECS: u64 = 60;
const CONNECT_TIMEOUT_SECS: u64 = 30;
/// JSON-RPC auth error code
const AUTH_ERROR_CODE: i64 = -32000;
use crate::auth::AuthManager;
/// Config for the grok.com WebSocket relay.
/// Fields are private so the only constructor is [`RelayConfig::for_session`]: "no relay without a session bearer" is a compile-time guarantee.
#[derive(Clone)]
pub struct RelayConfig {
    ws_url: String,
    ws_origin: String,
    token_header: String,
    auth: FuigoAuth,
    auth_manager: Option<Arc<AuthManager>>,
}
impl RelayConfig {
    /// Session gate: builds only for a grok.com first-party session (`is_fuigo_auth`: x.ai-issuer OIDC or external credential) with a non-empty bearer.
    /// BYOK/ApiKey, non-x.ai issuers (enterprise OIDC, third-party external providers), and deprecated WebLogin get `None`.
    /// With relay off, the leader still serves clients over IPC.
    pub(crate) fn for_session(
        session: &FuigoAuth,
        ctx: &FuigoComConfig,
        alpha_test_key: Option<String>,
        auth_manager: Option<Arc<AuthManager>>,
    ) -> Option<Self> {
        if !session.is_fuigo_auth() || session.key.is_empty() {
            return None;
        }
        let _ = alpha_test_key;
        Some(Self {
            ws_url: ctx.fuigo_ws_url.clone(),
            ws_origin: ctx.fuigo_ws_origin.clone(),
            token_header: ctx.token_header.clone(),
            auth: session.clone(),
            auth_manager,
        })
    }
    /// P77: the identity-disclosure decision for the relay this config connects to, taken on the URL the socket is
    /// opened to and by the same rule as the handshake's identity headers (`build_relay_request`): `wss` to the
    /// FluxRouter API host. Body-carried machine identity sent over the relay (the host name in an `initialize`
    /// response: relay sync's own, and the agent's when the relay is bridged to it) follows it.
    pub(crate) fn identity_disclosure(&self) -> fuigo_extra_ca::fluxrouter::IdentityDisclosure {
        fuigo_extra_ca::fluxrouter::IdentityDisclosure::for_websocket_destination(&self.ws_url)
    }
    /// P81: what the socket writer of this relay decides body-carried identity with: the URL the socket is opened to
    /// (so the decision and the pseudonym's origin are the same URL) and this machine's persisted id.
    pub(crate) fn body_identity(&self) -> RelayBodyIdentity {
        RelayBodyIdentity::for_relay(&self.ws_url, fuigo_telemetry::id::agent_id)
    }
    /// P93: whether the agent may be BRIDGED to this relay (headless-relay and leader mode), decided on the URL the
    /// socket is opened to: a FluxRouter-operated relay, or one whose origin the user opted in to
    /// ([`crate::agent::relay_opt_in`]).
    pub(crate) fn bridge_trust(
        &self,
    ) -> Result<
        crate::agent::relay_opt_in::RelayBridgeTrust,
        crate::agent::relay_opt_in::RelayOptInRefused,
    > {
        crate::agent::relay_opt_in::relay_bridge_gate(&self.ws_url)
    }
    /// P125: whether a TUI session may be SYNCED to this relay (it receives the session transcript): the same rule as
    /// [`Self::bridge_trust`], decided on the URL the socket is opened to.
    pub(crate) fn sync_trust(
        &self,
    ) -> Result<
        crate::agent::relay_opt_in::RelayBridgeTrust,
        crate::agent::relay_opt_in::RelayOptInRefused,
    > {
        crate::agent::relay_opt_in::relay_sync_gate(&self.ws_url)
    }
}
/// P81: the body-identity decision for ONE relay, as the socket writer applies it ([`relay_outbound_frame`]).
///
/// Built from the relay URL alone: the disclosure decision (`wss` to the FluxRouter API host, the handshake's rule)
/// and the origin the machine-id pseudonym is scoped to can therefore never come from two different URLs.
/// `machine_id` is read only when a frame names the field, and only for a relay that is not FluxRouter-operated.
#[derive(Clone, Debug)]
pub(crate) struct RelayBodyIdentity {
    disclosure: fuigo_extra_ca::fluxrouter::IdentityDisclosure,
    relay_url: String,
    machine_id: fn() -> String,
}
impl RelayBodyIdentity {
    pub(crate) fn for_relay(relay_url: &str, machine_id: fn() -> String) -> Self {
        Self {
            disclosure: fuigo_extra_ca::fluxrouter::IdentityDisclosure::for_websocket_destination(relay_url),
            relay_url: relay_url.to_owned(),
            machine_id,
        }
    }
    /// The key this relay receives in place of `machine_id`: P54's published pseudonym, scoped to the relay's origin
    /// (stable across reconnects and restarts for one relay, unrelated at every other relay).
    fn machine_key(&self, machine_id: &str) -> String {
        fuigo_extra_ca::fluxrouter::IdentityDisclosure::body_key_for_websocket(&self.relay_url, machine_id)
    }
}
/// Callback type for first connection event.
pub(crate) type FirstConnectCallback = Box<dyn FnOnce() + Send + 'static>;
/// Handle to a running relay connection.
///
/// The relay maintains a persistent WebSocket connection to grok.com with
/// automatic reconnection on disconnection.
pub struct RelayHandle {
    /// Cancel token to stop the relay connection loop
    cancel: CancellationToken,
}
impl RelayHandle {
    /// Stop the relay connection.
    pub fn stop(&self) {
        self.cancel.cancel();
    }
    /// Check if the relay is still running.
    pub fn is_running(&self) -> bool {
        !self.cancel.is_cancelled()
    }
}
impl Drop for RelayHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
/// Spawn a relay connection task that maintains a WebSocket connection.
///
/// The task runs in the background, automatically reconnecting on disconnection.
/// Messages from the relay are sent to `to_agent_tx`, and messages to send to the relay should be sent via the returned sender.
///
/// # Arguments
/// * `config` - Relay connection configuration
/// * `to_agent_tx` - Channel to send messages received from the relay
/// * `parent_cancel` - Parent cancellation token (relay stops when parent is cancelled)
///
/// # Returns
/// A tuple of (sender for outbound messages, handle to control the relay)
pub fn spawn_relay_connection(
    config: RelayConfig,
    to_agent_tx: mpsc::UnboundedSender<String>,
    parent_cancel: CancellationToken,
) -> (mpsc::UnboundedSender<String>, RelayHandle) {
    spawn_relay_connection_with_callback(config, to_agent_tx, Some(parent_cancel), None)
}
/// Spawn a relay connection with an optional first-connection callback.
///
/// Same as `spawn_relay_connection` but allows providing a callback that will be called once when the first successful connection is established.
pub(crate) fn spawn_relay_connection_with_callback(
    config: RelayConfig,
    to_agent_tx: mpsc::UnboundedSender<String>,
    parent_cancel: Option<CancellationToken>,
    on_first_connect: Option<FirstConnectCallback>,
) -> (mpsc::UnboundedSender<String>, RelayHandle) {
    let cancel = parent_cancel.map_or(CancellationToken::new(), |c| c.child_token());
    let cancel_clone = cancel.clone();
    let (agent_to_ws_tx, agent_to_ws_rx) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        run_relay_loop(
            config,
            to_agent_tx,
            agent_to_ws_rx,
            cancel_clone,
            on_first_connect,
        )
        .await;
    });
    let handle = RelayHandle { cancel };
    (agent_to_ws_tx, handle)
}
/// Check if a connection error is an HTTP 401 from the WebSocket handshake.
fn is_handshake_unauthorized(err: &anyhow::Error) -> bool {
    use tokio_tungstenite::tungstenite::Error as WsError;
    err.downcast_ref::<WsError>()
        .map(|ws_err| {
            matches!(ws_err, WsError::Http(resp) if resp.status() == reqwest::StatusCode::UNAUTHORIZED)
        })
        .unwrap_or(false)
}
/// Attempt auth recovery after a 401.
/// Returns `true` to reconnect immediately, `false` to exit or fall through to backoff.
async fn attempt_auth_recovery(
    config: &mut RelayConfig,
    cancel: &CancellationToken,
    context: &str,
) -> bool {
    let Some(ref am) = config.auth_manager else {
        teprintln!("Authentication required. Run `fuigo login` to re-authenticate.");
        cancel.cancel();
        return false;
    };
    info!("auth recovery: relay {context}, attempting refresh");
    let mut recovery = am.unauthorized_recovery(
        Some(config.auth.clone()),
        crate::auth::recovery::RecoverySource::Relay,
    );
    let recovered = match tokio::time::timeout(
        Duration::from_secs(AUTH_RECOVERY_TIMEOUT_SECS),
        recovery.next(),
    )
    .await
    {
        Ok(res) => res,
        Err(_) => {
            warn!(
                timeout_secs = AUTH_RECOVERY_TIMEOUT_SECS,
                "auth recovery: relay {context}, refresh timed out"
            );
            fuigo_telemetry::unified_log::warn(
                "auth recovery: relay refresh timed out",
                None,
                Some(serde_json::json!({
                    "context": context,
                    "timeout_secs": AUTH_RECOVERY_TIMEOUT_SECS,
                })),
            );
            return false;
        }
    };
    match recovered {
        Ok(new_auth) if new_auth.key == config.auth.key => {
            info!("auth recovery: relay {context}, token unchanged, backing off");
            fuigo_telemetry::unified_log::info(
                "auth recovery: relay token unchanged, backing off",
                None,
                Some(serde_json::json!({
                    "context": context,
                    "key_prefix": fuigo_auth::bearer_fingerprint(&new_auth.key),
                })),
            );
            false
        }
        Ok(new_auth) => {
            info!("auth recovery: relay {context}, recovered, reconnecting");
            fuigo_telemetry::unified_log::info(
                "auth recovery: relay recovered",
                None,
                Some(serde_json::json!({
                    "context": context,
                    "new_key_prefix": fuigo_auth::bearer_fingerprint(&new_auth.key),
                })),
            );
            config.auth = new_auth;
            true
        }
        Err(e) if crate::auth::recovery::relay_should_cancel(&e) => {
            teprintln!("{e}");
            fuigo_telemetry::unified_log::warn(
                "auth recovery: relay giving up (terminal)",
                None,
                Some(serde_json::json!({ "context": context, "error": format!("{e}") })),
            );
            cancel.cancel();
            false
        }
        Err(e) => {
            warn!(error = %e, "auth recovery: relay {context}, refresh failed");
            fuigo_telemetry::unified_log::debug(
                "auth recovery: relay refresh failed",
                None,
                Some(serde_json::json!({ "context": context, "error": format!("{e}") })),
            );
            false
        }
    }
}
/// Internal function that runs the reconnection loop.
/// The HTTP CONNECT proxy for the relay's destination (`resolve` is `proxy::resolve_proxy_for_host` in production),
/// logged once when there is one. P70a (Astra r4): a proxy URL taken from `HTTPS_PROXY` may carry a user name and
/// password (`http://alice:secret@proxy:3128`), so the log line prints only the address the tunnel dials (P113,
/// Astra r1 #5: `redact_url` kept a password holding an unencoded `/` as a path); the URL returned for the
/// connection is unchanged.
pub(super) fn relay_proxy_for(
    ws_url: &str,
    resolve: impl FnOnce(&str) -> Option<String>,
) -> Option<String> {
    let target_host = url::Url::parse(ws_url).ok().and_then(|u| u.host_str().map(str::to_owned));
    let proxy_url = target_host.as_deref().and_then(resolve);
    if let Some(ref url) = proxy_url {
        info!(
            proxy = %proxy::proxy_address_for_log(url),
            target = target_host.as_deref().unwrap_or("unknown"),
            "Using HTTP CONNECT proxy for relay connections"
        );
    }
    proxy_url
}

async fn run_relay_loop(
    mut config: RelayConfig,
    to_agent_tx: mpsc::UnboundedSender<String>,
    mut agent_to_ws_rx: mpsc::UnboundedReceiver<String>,
    cancel: CancellationToken,
    mut on_first_connect: Option<FirstConnectCallback>,
) {
    // P47: a relay URL that may not receive the session token is a configuration fact no reconnect can change, so
    // the relay stops here, once, and says why (the gate also logs the refusal with its remedy).
    if let Err(refused) = relay_destination_gate(&config) {
        tprintln!("Fuigo relay disabled: {refused}");
        return;
    }
    let mut reconnect_attempts = 0u32;
    let mut delay_secs = BASE_DELAY_SECS;
    let mut first_connection = true;
    let proxy_url = relay_proxy_for(&config.ws_url, proxy::resolve_proxy_for_host);
    loop {
        if cancel.is_cancelled() {
            info!("Relay connection cancelled, stopping");
            break;
        }
        tracing::info!(
            target: crate::instrumentation::TARGET,
            event = "relay_connecting",
            ws_url = %fuigo_auth::redact_url(&config.ws_url),
            attempt = reconnect_attempts,
        );
        match connect_to_relay(&config, proxy_url.as_deref(), &cancel).await {
            Ok(ws) => {
                tracing::info!(
                    target: crate::instrumentation::TARGET,
                    event = "relay_connected",
                    ws_url = %fuigo_auth::redact_url(&config.ws_url),
                );
                reconnect_attempts = 0;
                delay_secs = BASE_DELAY_SECS;
                if first_connection {
                    if let Some(callback) = on_first_connect.take() {
                        callback();
                    }
                    first_connection = false;
                }
                let result =
                    run_websocket_session(
                        ws,
                        &to_agent_tx,
                        &mut agent_to_ws_rx,
                        &cancel,
                        &config.body_identity(),
                    )
                    .await;
                match result {
                    Ok(SessionEndReason::Normal) => {
                        info!("WebSocket session ended normally");
                    }
                    Ok(SessionEndReason::AuthError) => {
                        if attempt_auth_recovery(&mut config, &cancel, "Auth error").await {
                            continue;
                        }
                    }
                    Err(e) => {
                        warn!(error = ?e, "WebSocket session ended with error");
                    }
                }
                if cancel.is_cancelled() {
                    break;
                }
                tracing::info!(
                    target: crate::instrumentation::TARGET,
                    event = "relay_disconnected",
                    ws_url = %fuigo_auth::redact_url(&config.ws_url),
                );
                tprintln!("Disconnected from Fuigo WebSocket server");
                info!("WebSocket disconnected, will reconnect");
            }
            Err(e) => {
                let handshake_401 = is_handshake_unauthorized(&e);
                tracing::info!(
                    target: crate::instrumentation::TARGET,
                    event = "relay_connection_failed",
                    ws_url = %fuigo_auth::redact_url(&config.ws_url),
                    error = %e,
                    handshake_401,
                );
                if handshake_401 {
                    if attempt_auth_recovery(&mut config, &cancel, "Handshake 401").await {
                        continue;
                    }
                } else {
                    warn!(error = %e, "Failed to connect to WebSocket server");
                }
            }
        }
        if cancel.is_cancelled() {
            break;
        }
        reconnect_attempts += 1;
        delay_secs = std::cmp::min(delay_secs * 2, MAX_DELAY_SECS);
        info!(delay_secs, attempt = reconnect_attempts, "Reconnecting...");
        tprintln!(
            "Attempting to reconnect in {} seconds... (attempt #{})",
            delay_secs,
            reconnect_attempts
        );
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(Duration::from_secs(delay_secs)) => {}
        }
    }
}
/// Reason why a WebSocket session ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SessionEndReason {
    /// Normal disconnection (server closed, network error, etc.)
    Normal,
    /// Authentication error that may be recoverable with token refresh
    AuthError,
}
/// P47: the relay's session token goes only where the service-endpoint trust class admits `ws_url` (`wss`, not
/// loopback; the configured relay URL from `FuigoComConfig` is the service base).
fn relay_destination_gate(
    config: &RelayConfig,
) -> Result<(), fuigo_extra_ca::service_trust::RefusedServiceDestination> {
    crate::auth::session_delivery::service_session_gate(
        &config.auth,
        &config.ws_url,
        Some(&config.ws_url),
        "relay",
    )
}
/// Build an HTTP request with the relay authentication headers.
fn build_relay_request(config: &RelayConfig) -> anyhow::Result<axum::http::Request<()>> {
    relay_destination_gate(config)?;
    let mut req = config.ws_url.clone().into_client_request()?;
    req.headers_mut().insert(
        "Origin",
        axum::http::header::HeaderValue::from_str(&config.ws_origin)?,
    );
    req.headers_mut().insert(
        "Authorization",
        axum::http::header::HeaderValue::from_str(&format!("Bearer {}", config.auth.key))?,
    );
    req.headers_mut().insert(
        "X-XAI-Token-Auth",
        axum::http::header::HeaderValue::from_str(&config.token_header)?,
    );
    // P43: identity only to a FluxRouter-operated destination (`wss` to the compiled host).
    // The account id was previously required (an invalid one failed the handshake); it still is
    // when it is going to be sent.
    let identity =
        fuigo_extra_ca::fluxrouter::IdentityDisclosure::for_websocket_destination(&config.ws_url);
    if identity.is_permitted() {
        axum::http::header::HeaderValue::from_str(&config.auth.user_id)?;
    }
    req.headers_mut().extend(identity.header_map([
        ("x-userid", config.auth.user_id.as_str()),
        ("x-fuigo-client-version", fuigo_version::VERSION),
    ]));
    req.headers_mut().insert(
        crate::http::CLIENT_MODE_HEADER,
        axum::http::header::HeaderValue::from_static(crate::http::process_client_mode()),
    );
    Ok(req)
}
/// Attempt to connect to the relay WebSocket server.
///
/// If `proxy_url` is `Some`, the connection is established through an HTTP CONNECT tunnel.
/// Otherwise, a direct connection is used.
async fn connect_to_relay(
    config: &RelayConfig,
    proxy_url: Option<&str>,
    cancel: &CancellationToken,
) -> anyhow::Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
> {
    let req = build_relay_request(config)?;
    let connect_timeout = Duration::from_secs(CONNECT_TIMEOUT_SECS);
    tokio::select! {
        _ = cancel.cancelled() => {
            anyhow::bail!("Connection cancelled");
        }
        result = tokio::time::timeout(connect_timeout, async {
            if let Some(proxy_url) = proxy_url {
                // Proxy path: open TCP to proxy, send CONNECT, then WS handshake.
                let target_host = req.uri().host()
                    .ok_or_else(|| anyhow::anyhow!("WebSocket URL has no host"))?;
                let target_port = req.uri().port_u16().unwrap_or(443);
                let tunneled_stream = proxy::connect_via_proxy(
                    proxy_url,
                    target_host,
                    target_port,
                ).await?;
                // Perform the WebSocket handshake over the tunneled stream.
                let (ws, resp) = tokio_tungstenite::client_async(req, tunneled_stream)
                    .await
                    .map_err(|e| anyhow::Error::from(e).context("WebSocket handshake via proxy failed"))?;
                Ok((ws, resp))
            } else {
                // The default connector never sees the shared trust config.
                let connector =
                    tokio_tungstenite::Connector::Rustls(fuigo_extra_ca::rustls_client_config());
                connect_async_tls_with_config(req, None, false, Some(connector))
                    .await
                    .map_err(|e| anyhow::Error::from(e).context("WebSocket connection failed"))
            }
        }) => {
            match result {
                Ok(Ok((ws, resp))) => {
                    if let Some(proto) = resp.headers().get("Sec-WebSocket-Protocol") {
                        info!(subprotocol = ?proto, "WS subprotocol negotiated");
                    }
                    Ok(ws)
                }
                Ok(Err(e)) => Err(e),
                Err(_) => anyhow::bail!("WebSocket connection timed out after {} seconds", CONNECT_TIMEOUT_SECS),
            }
        }
    }
}
/// Run a single WebSocket session, handling messages until disconnection.
pub(crate) async fn run_websocket_session<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    to_agent_tx: &mpsc::UnboundedSender<String>,
    from_agent_rx: &mut mpsc::UnboundedReceiver<String>,
    cancel: &CancellationToken,
    identity: &RelayBodyIdentity,
) -> anyhow::Result<SessionEndReason>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
{
    run_websocket_session_with_liveness(
        ws,
        to_agent_tx,
        from_agent_rx,
        cancel,
        Duration::from_secs(READ_LIVENESS_TIMEOUT_SECS),
        identity,
    )
    .await
}
/// P77, P81: what is written to the relay for one outbound frame (an empty string: nothing).
///
/// Everything the agent emits is forwarded to the relay verbatim when the relay is bridged to it (`agent/app.rs`:
/// headless-relay mode, and leader mode, where the relay also sees the responses to local IPC clients). That includes
/// the agent responses that carry machine identity. They follow the P54 rule for body-carried identity:
///
/// * the OS host name (P77): the ACP `initialize` response (`result._meta.hostname`, this machine) and the
///   `fuigo/session/list` response (the rows' `hostname` under `result.result.sessions[]`, this machine's and the
///   account's other machines' names as the session registry returned them) lose the field;
/// * the persisted machine id (P81): the ACP `initialize` response's `result._meta.agentId`, when it IS this machine's
///   id, becomes the relay-origin pseudonym ([`RelayBodyIdentity::machine_key`]). The relay keys an agent on that
///   field (relay sync supplies one on every connection too), so it is replaced, not removed. Any other value there
///   is left alone: relay sync's own `initialize` carries the session-scoped `"<agent type>-<session id>"`, a
///   correlation id, not identity. `agentInstanceId` is a per-process random and is not identity either (P15-R).
/// * the account (P81): who is signed in, as the agent's auth responses report it. The `authenticate` response
///   (`result._meta`, `auth::AuthMeta`) and `fuigo/auth/check_subscription` (`result.meta`, the same type) lose
///   [`ACCOUNT_META_KEYS`]; `fuigo/auth/info` and `fuigo/auth/logout` (fields directly under `result`) lose
///   [`ACCOUNT_INFO_KEYS`]. Nothing at the relay needs them as a key, so they are omitted, as the handshake's
///   `x-userid` already is (P43). What the account may DO (roles, subscription tier, access gate, data-retention
///   choice, ZDR) is not who it is, and stays. The cloud-environment responses (`fuigo/cloud/env/list`:
///   `result.environments[].environment`; `fuigo/cloud/env/create` and `update`: `result.environment.environment`)
///   carry the owning account and team ids as the backend returned them, and lose [`ENVIRONMENT_OWNER_KEYS`].
///
/// A FluxRouter-operated relay gets every frame untouched, byte for byte. Any other relay gets a RESPONSE (a frame
/// with a `result` and no `method`) with those fields withheld; nothing else is changed (the same key elsewhere is
/// application data: an MCP setup value, the embedder's agent metadata), requests and notifications are never
/// rewritten, and a frame is not read at all unless it contains one of the quoted keys.
///
/// The frame is read one level at a time with every other value kept as raw text, so the rest of it is written back
/// byte for byte and the parser's nesting limit does not apply to it. Fails closed: a frame that contains one of the
/// quoted keys and is not a JSON object is not sent to such a relay, because whether it carries identity cannot be
/// decided.
///
/// P82: before any of that, the credential fields of a frame are withheld from such a relay
/// ([`super::relay_credentials::withhold_credentials`]; an empty string when they cannot be decided).
pub(crate) fn relay_outbound_frame(identity: &RelayBodyIdentity, msg: String) -> String {
    let msg = super::relay_credentials::withhold_credentials(identity.disclosure, msg);
    if identity.disclosure.is_permitted() || !RELAY_IDENTITY_KEYS.iter().any(|key| msg.contains(key)) {
        return msg;
    }
    match withhold_response_identity(identity, &msg) {
        Ok(Some(rewritten)) => rewritten,
        Ok(None) => msg,
        Err(error) => {
            warn!(%error, "relay: an outbound frame that names an identity field could not be read; not sent to this relay");
            String::new()
        }
    }
}
/// The quoted keys [`relay_outbound_frame`] looks for before it reads a frame: every field it can withhold.
const RELAY_IDENTITY_KEYS: [&str; 14] = [
    "\"hostname\"",
    "\"agentId\"",
    "\"email\"",
    "\"team_id\"",
    "\"team_name\"",
    "\"firstName\"",
    "\"lastName\"",
    "\"profileImageUrl\"",
    "\"teamId\"",
    "\"teamName\"",
    "\"organizationId\"",
    "\"organizationName\"",
    "\"principalId\"",
    "\"userId\"",
];
/// Who is signed in, in `auth::AuthMeta` (snake case): the `_meta` of the `authenticate` response and the `meta` of
/// `fuigo/auth/check_subscription`.
const ACCOUNT_META_KEYS: [&str; 3] = ["email", "team_id", "team_name"];
/// Who is signed in, directly under the result of `fuigo/auth/info` (`AuthInfoResponse`, camel case) and of
/// `fuigo/auth/logout` (`email`).
const ACCOUNT_INFO_KEYS: [&str; 9] = [
    "email",
    "firstName",
    "lastName",
    "profileImageUrl",
    "teamId",
    "teamName",
    "organizationId",
    "organizationName",
    "principalId",
];
/// The account and team that own a cloud environment (`SandboxEnvironment`, camel case), in the `environment` object of
/// each `SandboxEnvironmentWithMetadata` the cloud-environment responses return.
const ENVIRONMENT_OWNER_KEYS: [&str; 2] = ["userId", "teamId"];
/// A JSON object read ONE level deep: keys in order, values as raw text.
type RawObject = indexmap::IndexMap<String, Box<serde_json::value::RawValue>>;
/// `frame` with the identity fields of an agent response withheld; `None` when there is nothing to withhold (not a
/// response, or a response without those fields).
fn withhold_response_identity(identity: &RelayBodyIdentity, frame: &str) -> serde_json::Result<Option<String>> {
    let mut frame: RawObject = serde_json::from_str(frame)?;
    if frame.contains_key("method") {
        return Ok(None);
    }
    let Some(mut result) = frame
        .get("result")
        .and_then(|raw| serde_json::from_str::<RawObject>(raw.get()).ok())
    else {
        return Ok(None);
    };
    // ACP `initialize`: `result._meta.hostname` and `result._meta.agentId`. ACP `authenticate`: the account in
    // `result._meta`.
    let mut withheld = withhold_in(&mut result, "_meta", |meta: &mut RawObject| {
        let hostname = meta.shift_remove("hostname").is_some();
        let machine_id = pseudonymise_machine_id(meta, identity)?;
        let account = withhold_keys(meta, &ACCOUNT_META_KEYS);
        Ok(hostname | machine_id | account)
    })?;
    // `fuigo/auth/check_subscription`: the same account metadata under `result.meta`.
    withheld |= withhold_in(&mut result, "meta", |meta: &mut RawObject| Ok(withhold_keys(meta, &ACCOUNT_META_KEYS)))?;
    // `fuigo/session/list`: the rows sit under the extension-method envelope's own `result` (`ExtMethodResult`);
    // rows directly under the response's result are covered too.
    withheld |= withhold_in(&mut result, "result", withhold_session_rows)?;
    withheld |= withhold_session_rows(&mut result)?;
    // `fuigo/auth/info`, `fuigo/auth/logout`: the account directly under the result.
    withheld |= withhold_keys(&mut result, &ACCOUNT_INFO_KEYS);
    // `fuigo/cloud/env/list`: every row of `result.environments`; `fuigo/cloud/env/create` and `update`: the one
    // `result.environment`. Each is a `SandboxEnvironmentWithMetadata`, whose `environment` names its owner.
    withheld |= withhold_environment_rows(&mut result)?;
    withheld |= withhold_in(&mut result, "environment", withhold_environment_owner)?;
    if !withheld {
        return Ok(None);
    }
    frame.insert("result".to_owned(), serde_json::value::to_raw_value(&result)?);
    serde_json::to_string(&frame).map(Some)
}
/// Remove every one of `keys` from `object`, whatever its value.
fn withhold_keys(object: &mut RawObject, keys: &[&str]) -> bool {
    let mut withheld = false;
    for key in keys {
        withheld |= object.shift_remove(*key).is_some();
    }
    withheld
}
/// Replace `meta.agentId` by the relay's pseudonym for it when its value is this machine's persisted id (in place:
/// the key keeps its position). Any other value, of any type, is not the machine id and is left as it is.
fn pseudonymise_machine_id(meta: &mut RawObject, identity: &RelayBodyIdentity) -> serde_json::Result<bool> {
    let Some(sent) = meta
        .get("agentId")
        .and_then(|raw| serde_json::from_str::<String>(raw.get()).ok())
    else {
        return Ok(false);
    };
    if sent != (identity.machine_id)() {
        return Ok(false);
    }
    meta.insert("agentId".to_owned(), serde_json::value::to_raw_value(&identity.machine_key(&sent))?);
    Ok(true)
}
/// Apply `edit` to the object at `parent[key]`, and write it back if `edit` changed it.
fn withhold_in(
    parent: &mut RawObject,
    key: &str,
    edit: impl FnOnce(&mut RawObject) -> serde_json::Result<bool>,
) -> serde_json::Result<bool> {
    let Some(mut child) = parent
        .get(key)
        .and_then(|raw| serde_json::from_str::<RawObject>(raw.get()).ok())
    else {
        return Ok(false);
    };
    if !edit(&mut child)? {
        return Ok(false);
    }
    parent.insert(key.to_owned(), serde_json::value::to_raw_value(&child)?);
    Ok(true)
}
/// Remove `hostname` from every row of `object.sessions`.
fn withhold_session_rows(object: &mut RawObject) -> serde_json::Result<bool> {
    let Some(mut rows) = object
        .get("sessions")
        .and_then(|raw| serde_json::from_str::<Vec<Box<serde_json::value::RawValue>>>(raw.get()).ok())
    else {
        return Ok(false);
    };
    let mut withheld = false;
    for row in &mut rows {
        if let Ok(mut fields) = serde_json::from_str::<RawObject>(row.get())
            && fields.shift_remove("hostname").is_some()
        {
            *row = serde_json::value::to_raw_value(&fields)?;
            withheld = true;
        }
    }
    if withheld {
        object.insert("sessions".to_owned(), serde_json::value::to_raw_value(&rows)?);
    }
    Ok(withheld)
}
/// Remove the owner ids from `with_metadata.environment` (one `SandboxEnvironmentWithMetadata`).
fn withhold_environment_owner(with_metadata: &mut RawObject) -> serde_json::Result<bool> {
    withhold_in(with_metadata, "environment", |environment: &mut RawObject| {
        Ok(withhold_keys(environment, &ENVIRONMENT_OWNER_KEYS))
    })
}
/// Remove the owner ids from every row of `object.environments`.
fn withhold_environment_rows(object: &mut RawObject) -> serde_json::Result<bool> {
    let Some(mut rows) = object
        .get("environments")
        .and_then(|raw| serde_json::from_str::<Vec<Box<serde_json::value::RawValue>>>(raw.get()).ok())
    else {
        return Ok(false);
    };
    let mut withheld = false;
    for row in &mut rows {
        if let Ok(mut with_metadata) = serde_json::from_str::<RawObject>(row.get())
            && withhold_environment_owner(&mut with_metadata)?
        {
            *row = serde_json::value::to_raw_value(&with_metadata)?;
            withheld = true;
        }
    }
    if withheld {
        object.insert("environments".to_owned(), serde_json::value::to_raw_value(&rows)?);
    }
    Ok(withheld)
}
/// [`run_websocket_session`] with an explicit read-liveness window (separate entry point so tests can use a short deadline).
pub(crate) async fn run_websocket_session_with_liveness<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    to_agent_tx: &mpsc::UnboundedSender<String>,
    from_agent_rx: &mut mpsc::UnboundedReceiver<String>,
    cancel: &CancellationToken,
    liveness: Duration,
    identity: &RelayBodyIdentity,
) -> anyhow::Result<SessionEndReason>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
{
    let (mut ws_outbound, mut ws_inbound) = ws.split();
    let (auth_error_tx, mut auth_error_rx) = mpsc::channel::<()>(1);
    // P82: the reader answers a request this relay may not make (`relay_credentials::gate_relay_message`) through the
    // writer, the socket's only writer; the request never reaches the agent.
    let (refusal_tx, mut refusal_rx) = mpsc::unbounded_channel::<String>();
    let relay_is_fluxrouter = identity.disclosure.is_permitted();
    let cancel_read = cancel.clone();
    let read_from_ws = async move {
        loop {
            tokio::select! {
                _ = cancel_read.cancelled() => break,
                msg_res = tokio::time::timeout(liveness, ws_inbound.next()) => {
                    let Ok(msg_opt) = msg_res else {
                        // No frame (not even a pong for our keepalive pings) within the liveness window: the connection is dead or half-open
                        // Break so the session ends and the reconnect loop takes over
                        tprintln!("ws_inbound::liveness_timeout");
                        warn!(
                            timeout_secs = liveness.as_secs(),
                            "no WS traffic within liveness window, treating connection as dead"
                        );
                        fuigo_telemetry::unified_log::warn(
                            "relay: read liveness timeout, reconnecting",
                            None,
                            Some(serde_json::json!({
                                "timeout_secs": liveness.as_secs(),
                            })),
                        );
                        break;
                    };
                    let Some(msg) = msg_opt else { break };
                    match msg {
                        Ok(Message::Text(text)) => {
                            let trimmed_end = text.trim_end_matches(['\r', '\n']);
                            if trimmed_end.is_empty() {
                                debug!("received empty/whitespace WS text frame - skipping");
                                continue;
                            }

                            let json: serde_json::Value = match serde_json::from_str(trimmed_end) {
                                Ok(v) => v,
                                Err(_) => {
                                    debug!("failed to parse WS message as JSON");
                                    continue;
                                }
                            };

                            if let Some(err) = json.get("error") {
                                let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
                                if code == AUTH_ERROR_CODE {
                                    // Signal auth error to the main loop
                                    let _ = auth_error_tx.send(()).await;
                                    return (false, true); // (normal_end, auth_error)
                                }
                                tracing::warn!(error_code = code, "Server error (skipping)");
                                continue;
                            }

                            match json.get("method").and_then(|m| m.as_str()) {
                                Some(method) => tprintln!("acp_inbound::{}", method),
                                None => tprintln!("ws_inbound::text"),
                            }
                            debug!(bytes = trimmed_end.len(), "received WS text -> agent");

                            let mut json = json;
                            let outbound = if relay_is_fluxrouter {
                                if declare_relay_client_capabilities(&mut json) {
                                    json.to_string()
                                } else {
                                    trimmed_end.to_string()
                                }
                            } else {
                                // P82: any other relay is never handed a credential, and the agent reads exactly
                                // the message that was decided on.
                                declare_relay_client_capabilities(&mut json);
                                match super::relay_credentials::gate_relay_message(&json) {
                                    super::relay_credentials::RelayMessage::Forward(line) => line,
                                    super::relay_credentials::RelayMessage::Refuse(answer) => {
                                        let _ = refusal_tx.send(answer);
                                        continue;
                                    }
                                    super::relay_credentials::RelayMessage::Drop => continue,
                                }
                            };
                            if to_agent_tx.send(outbound).is_err() {
                                warn!("Failed to forward message to agent - channel closed");
                                break;
                            }
                        }
                        Ok(Message::Binary(bin)) => {
                            tprintln!("ws_inbound::binary");
                            if let Ok(s) = std::str::from_utf8(&bin) {
                                let s = s.trim_end_matches(['\r', '\n']);
                                if s.is_empty() {
                                    debug!("received empty WS binary frame - skipping");
                                    continue;
                                }
                                if !relay_is_fluxrouter {
                                    // P82: the agent reads this frame line by line; each line is gated as a text
                                    // message is, and one it cannot read is not handed to it.
                                    let mut agent_gone = false;
                                    for line in s.split('\n') {
                                        let Ok(json) = serde_json::from_str::<serde_json::Value>(line) else {
                                            continue;
                                        };
                                        match super::relay_credentials::gate_relay_message(&json) {
                                            super::relay_credentials::RelayMessage::Forward(line) => {
                                                if to_agent_tx.send(line).is_err() {
                                                    agent_gone = true;
                                                    break;
                                                }
                                            }
                                            super::relay_credentials::RelayMessage::Refuse(answer) => {
                                                let _ = refusal_tx.send(answer);
                                            }
                                            super::relay_credentials::RelayMessage::Drop => {}
                                        }
                                    }
                                    if agent_gone {
                                        break;
                                    }
                                    continue;
                                }
                                debug!(bytes = s.len(), "received WS binary(utf8) -> agent");
                                if to_agent_tx.send(s.to_string()).is_err() {
                                    break;
                                }
                            } else {
                                debug!("received non-utf8 WS binary frame - skipping");
                            }
                        }
                        Ok(Message::Close(frame_opt)) => {
                            tprintln!("ws_inbound::close");
                            if let Some(frame) = frame_opt {
                                info!(code = ?frame.code, reason = %frame.reason, "WS close received");
                            } else {
                                info!("WS close received (no frame)");
                            }
                            break;
                        }
                        Ok(Message::Ping(p)) => {
                            tprintln!("ws_inbound::ping");
                            debug!(len = p.len(), "received WS Ping");
                        }
                        Ok(Message::Pong(p)) => {
                            tprintln!("ws_inbound::pong");
                            debug!(len = p.len(), "received WS Pong");
                        }
                        Ok(Message::Frame(_)) => {
                            tprintln!("ws_inbound::frame");
                        }
                        Err(e) => {
                            tprintln!("ws_inbound::error::{:?}", &e);
                            warn!(error = ?e, "WS read error");
                            break;
                        }
                    }
                }
            }
        }
        (true, false)
    };
    let cancel_write = cancel.clone();
    let write_to_ws = async move {
        let mut keepalive = tokio::time::interval(Duration::from_secs(KEEPALIVE_INTERVAL_SECS));
        loop {
            let msg = tokio::select! {
                _ = cancel_write.cancelled() => break,
                // P82: the answer to a request this relay may not make (it never reached the agent).
                Some(refused) = refusal_rx.recv() => refused,
                msg_opt = from_agent_rx.recv() => {
                    match msg_opt {
                        Some(msg) => {
                            // Per-message logging is debug-only: at info level a streaming session mirrors every `session/update` delta here
                            // The full JSON parse and params re-format produced over 100 MB of leader.log churn on dashboard-heavy machines
                            // Skip the parse entirely unless debug logging is enabled
                            if tracing::enabled!(tracing::Level::DEBUG) {
                                if let Ok(json_val) =
                                    serde_json::from_str::<serde_json::Value>(&msg)
                                {
                                    let method = json_val.get("method").and_then(|m| m.as_str());
                                    let line_to_print = match method {
                                        Some("session/update") => {
                                            let params = json_val
                                                .get("params")
                                                .unwrap_or(&serde_json::Value::Null);
                                            format!("acp_outbound::session/update::{params}")
                                        }
                                        Some(m) => format!("acp_outbound::{m}"),
                                        None => "acp_outbound::response".to_string(),
                                    };
                                    debug!("{line_to_print}");
                                } else {
                                    debug!("acp_outbound::response");
                                }
                            }
                            msg
                        }
                        None => {
                            info!("Agent outbound channel closed");
                            break;
                        }
                    }
                }
                _ = keepalive.tick() => {
                    tprintln!("ws::keep_alive_tick");
                    if let Err(e) = ws_outbound.send(Message::Ping(Vec::new().into())).await {
                        tprintln!("ws::keep_alive::error::{:?}", &e);
                        break;
                    }
                    continue;
                }
            };
            let msg = relay_outbound_frame(identity, msg);
            if !msg.is_empty()
                && let Err(e) = ws_outbound.send(Message::Text(Utf8Bytes::from(msg))).await
            {
                warn!(error = ?e, "failed to send to WS");
                break;
            }
        }
        anyhow::Ok(())
    };
    tokio::select! {
        (_, auth_error) = read_from_ws => {
            info!("WebSocket read task completed (connection closed)");
            if auth_error {
                return Ok(SessionEndReason::AuthError);
            }
        }
        res = write_to_ws => {
            info!("WebSocket write task completed");
            res?;
        }
    }
    if auth_error_rx.try_recv().is_ok() {
        return Ok(SessionEndReason::AuthError);
    }
    Ok(SessionEndReason::Normal)
}
/// Capabilities the relay holds as a client regardless of what its `initialize` says.
///
/// The relay is the durable server-side store for every session on this
/// connection and persists `user_message_chunk` solely from the agent's
/// notifications — it never re-derives the prompt from `session/prompt`. Since
/// the live echo became opt-in (`fuigo/userMessageEcho`), a relay whose
/// `initialize` omits the flag silently loses every user prompt from stored
/// history. Declaring it here, where the relay's frames enter the agent, makes
/// persistence independent of the relay build; an explicit value from the relay
/// is left alone. Returns whether the frame was modified.
fn declare_relay_client_capabilities(frame: &mut serde_json::Value) -> bool {
    if frame.get("method").and_then(|m| m.as_str()) != Some("initialize") {
        return false;
    }
    let Some(params) = frame.get_mut("params").and_then(|p| p.as_object_mut()) else {
        return false;
    };
    let caps = params
        .entry("clientCapabilities")
        .or_insert_with(|| serde_json::json!({}));
    let Some(caps) = caps.as_object_mut() else {
        return false;
    };
    let meta = caps.entry("_meta").or_insert_with(|| serde_json::json!({}));
    let Some(meta) = meta.as_object_mut() else {
        return false;
    };
    if meta.contains_key(crate::session::USER_MESSAGE_ECHO_CAPABILITY) {
        return false;
    }
    meta.insert(
        crate::session::USER_MESSAGE_ECHO_CAPABILITY.to_string(),
        serde_json::Value::Bool(true),
    );
    true
}
#[cfg(test)]
mod tests {
    use super::*;
    /// P43 hostile: a relay that is not FluxRouter-operated gets neither the account id nor the
    /// client version on the handshake; `wss` to FluxRouter still does.
    #[test]
    fn relay_handshake_carries_identity_only_to_fluxrouter() {
        let config = |ws_url: &str| RelayConfig {
            ws_url: ws_url.to_string(),
            ws_origin: "https://origin.example".to_string(),
            token_header: "xai-grok-cli".to_string(),
            auth: FuigoAuth {
                key: "tok".into(),
                user_id: "acct-1".into(),
                ..Default::default()
            },
            auth_manager: None,
        };
        let req = build_relay_request(&config("wss://api.fluxrouter.ai/ws/relay")).unwrap();
        assert_eq!(req.headers()["x-userid"], "acct-1");
        assert!(req.headers().contains_key("x-fuigo-client-version"));
        // P47: a `ws://` or loopback relay never gets the session token, so no request is built at all.
        for url in ["ws://api.fluxrouter.ai/ws/relay", "ws://127.0.0.1:9/ws"] {
            assert!(build_relay_request(&config(url)).is_err(), "{url}");
        }
        for url in ["wss://relay.example/ws"] {
            let req = build_relay_request(&config(url)).unwrap();
            for name in fuigo_extra_ca::fluxrouter::IDENTITY_HEADER_NAMES {
                assert!(!req.headers().contains_key(name), "{url} got {name}");
            }
            assert_eq!(req.headers()["authorization"], "Bearer tok");
        }
    }
    use crate::auth::AuthMode;
    use serde_json::json;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio_tungstenite::tungstenite::{Utf8Bytes, protocol::Role};
    /// The machine id the P81 unit tests give the writer (the production one is `fuigo_telemetry::id::agent_id`).
    const P81_MACHINE_ID: &str = "5d1f0c2a-7a7a-4b4b-8c8c-0123456789ab";
    fn p81_machine_id() -> String {
        P81_MACHINE_ID.to_owned()
    }
    /// The decision for a relay that is not FluxRouter-operated (no URL at all: withholding is the default).
    fn p77_withheld() -> RelayBodyIdentity {
        RelayBodyIdentity::for_relay("", p81_machine_id)
    }
    /// Create an in-memory WebSocket pair (no network, no handshake needed).
    async fn ws_pair() -> (
        tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>,
        tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>,
    ) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let client_ws =
            tokio_tungstenite::WebSocketStream::from_raw_socket(client, Role::Client, None).await;
        let server_ws =
            tokio_tungstenite::WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        (client_ws, server_ws)
    }
    #[test]
    fn test_handshake_401_detected_through_anyhow_context() {
        use tokio_tungstenite::tungstenite::Error as WsError;
        let resp = axum::http::Response::builder()
            .status(401)
            .body(None::<Vec<u8>>)
            .unwrap();
        let err = anyhow::Error::from(WsError::Http(Box::new(resp)))
            .context("WebSocket connection failed");
        assert!(is_handshake_unauthorized(&err));
    }
    #[test]
    fn test_handshake_non_401_and_non_ws_errors_rejected() {
        use tokio_tungstenite::tungstenite::Error as WsError;
        let resp = axum::http::Response::builder()
            .status(403)
            .body(None::<Vec<u8>>)
            .unwrap();
        let err = anyhow::Error::from(WsError::Http(Box::new(resp)))
            .context("WebSocket connection failed");
        assert!(!is_handshake_unauthorized(&err));
        let err = anyhow::anyhow!("some random error");
        assert!(!is_handshake_unauthorized(&err));
    }
    #[tokio::test]
    async fn test_ws_session_auth_error_returns_auth_error() {
        let (client_ws, server_ws) = ws_pair().await;
        let (mut server_tx, _server_rx) = server_ws.split();
        let (to_agent_tx, _to_agent_rx) = mpsc::unbounded_channel::<String>();
        let (_agent_out_tx, mut agent_out_rx) = mpsc::unbounded_channel::<String>();
        let cancel = CancellationToken::new();
        tokio::spawn(async move {
            let auth_error = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": { "code": -32000, "message": "Authentication required" }
            });
            let _ = server_tx
                .send(Message::Text(Utf8Bytes::from(auth_error.to_string())))
                .await;
            let _ = server_tx.close().await;
        });
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            run_websocket_session(client_ws, &to_agent_tx, &mut agent_out_rx, &cancel, &p77_withheld()),
        )
        .await
        .expect("test timed out")
        .expect("session should not error");
        assert_eq!(result, SessionEndReason::AuthError);
    }
    #[tokio::test]
    async fn test_ws_session_non_auth_error_skipped() {
        let (client_ws, server_ws) = ws_pair().await;
        let (mut server_tx, _server_rx) = server_ws.split();
        let (to_agent_tx, _to_agent_rx) = mpsc::unbounded_channel::<String>();
        let (_agent_out_tx, mut agent_out_rx) = mpsc::unbounded_channel::<String>();
        let cancel = CancellationToken::new();
        tokio::spawn(async move {
            let other_error = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": { "code": -32600, "message": "Invalid Request" }
            });
            let _ = server_tx
                .send(Message::Text(Utf8Bytes::from(other_error.to_string())))
                .await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = server_tx.close().await;
        });
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            run_websocket_session(client_ws, &to_agent_tx, &mut agent_out_rx, &cancel, &p77_withheld()),
        )
        .await
        .expect("test timed out")
        .expect("session should not error");
        assert_eq!(result, SessionEndReason::Normal);
    }
    #[tokio::test]
    async fn test_ws_session_normal_close_returns_normal() {
        let (client_ws, server_ws) = ws_pair().await;
        let (mut server_tx, _server_rx) = server_ws.split();
        let (to_agent_tx, _to_agent_rx) = mpsc::unbounded_channel::<String>();
        let (_agent_out_tx, mut agent_out_rx) = mpsc::unbounded_channel::<String>();
        let cancel = CancellationToken::new();
        tokio::spawn(async move {
            let _ = server_tx.send(Message::Close(None)).await;
        });
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            run_websocket_session(client_ws, &to_agent_tx, &mut agent_out_rx, &cancel, &p77_withheld()),
        )
        .await
        .expect("test timed out")
        .expect("session should not error");
        assert_eq!(result, SessionEndReason::Normal);
    }
    #[tokio::test]
    async fn test_ws_session_read_liveness_timeout_ends_session() {
        let (client_ws, server_ws) = ws_pair().await;
        let _silent_server = server_ws;
        let (to_agent_tx, _to_agent_rx) = mpsc::unbounded_channel::<String>();
        let (_agent_out_tx, mut agent_out_rx) = mpsc::unbounded_channel::<String>();
        let cancel = CancellationToken::new();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            run_websocket_session_with_liveness(
                client_ws,
                &to_agent_tx,
                &mut agent_out_rx,
                &cancel,
                Duration::from_millis(100),
                &p77_withheld(),
            ),
        )
        .await
        .expect("session must end via read-liveness timeout instead of hanging")
        .expect("session should not error");
        assert_eq!(result, SessionEndReason::Normal);
    }
    #[tokio::test]
    async fn test_ws_session_inbound_traffic_resets_liveness_window() {
        let (client_ws, server_ws) = ws_pair().await;
        let (mut server_tx, _server_rx) = server_ws.split();
        let (to_agent_tx, mut to_agent_rx) = mpsc::unbounded_channel::<String>();
        let (_agent_out_tx, mut agent_out_rx) = mpsc::unbounded_channel::<String>();
        let cancel = CancellationToken::new();
        tokio::spawn(async move {
            for i in 0..12 {
                let msg = json!({ "jsonrpc": "2.0", "method": "ping", "id": i });
                if server_tx
                    .send(Message::Text(Utf8Bytes::from(msg.to_string())))
                    .await
                    .is_err()
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let _ = server_tx.close().await;
        });
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            run_websocket_session_with_liveness(
                client_ws,
                &to_agent_tx,
                &mut agent_out_rx,
                &cancel,
                Duration::from_millis(200),
                &p77_withheld(),
            ),
        )
        .await
        .expect("test timed out")
        .expect("session should not error");
        assert_eq!(result, SessionEndReason::Normal);
        let mut forwarded = 0;
        while to_agent_rx.try_recv().is_ok() {
            forwarded += 1;
        }
        assert_eq!(forwarded, 12);
    }
    #[tokio::test]
    async fn test_ws_session_forwards_text_to_agent() {
        let (client_ws, server_ws) = ws_pair().await;
        let (mut server_tx, _server_rx) = server_ws.split();
        let (to_agent_tx, mut to_agent_rx) = mpsc::unbounded_channel::<String>();
        let (_agent_out_tx, mut agent_out_rx) = mpsc::unbounded_channel::<String>();
        let cancel = CancellationToken::new();
        let test_msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });
        let msg_str = test_msg.to_string();
        tokio::spawn(async move {
            let _ = server_tx
                .send(Message::Text(Utf8Bytes::from(msg_str)))
                .await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = server_tx.close().await;
        });
        let _result = tokio::time::timeout(
            Duration::from_secs(5),
            run_websocket_session(client_ws, &to_agent_tx, &mut agent_out_rx, &cancel, &p77_withheld()),
        )
        .await
        .expect("test timed out");
        let received = to_agent_rx
            .try_recv()
            .expect("should have forwarded message to agent");
        let received_json: serde_json::Value = serde_json::from_str(&received).unwrap();
        assert_eq!(received_json["method"], "initialize");
    }
    /// End to end over the real forwarding path: the frame the AGENT receives carries the echo
    /// capability even though the relay's own `initialize` never mentioned it. Without this, the
    /// agent's opt-in gate suppresses every live `user_message_chunk` and the relay's store — which
    /// is built only from the agent's notifications — keeps sessions with no user prompts in them.
    #[tokio::test]
    async fn test_ws_session_declares_user_message_echo_on_the_forwarded_initialize() {
        let (client_ws, server_ws) = ws_pair().await;
        let (mut server_tx, _server_rx) = server_ws.split();
        let (to_agent_tx, mut to_agent_rx) = mpsc::unbounded_channel::<String>();
        let (_agent_out_tx, mut agent_out_rx) = mpsc::unbounded_channel::<String>();
        let cancel = CancellationToken::new();
        let msg_str = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": 1, "clientCapabilities": { "fs": {} } }
        })
        .to_string();
        tokio::spawn(async move {
            let _ = server_tx
                .send(Message::Text(Utf8Bytes::from(msg_str)))
                .await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = server_tx.close().await;
        });
        let _result = tokio::time::timeout(
            Duration::from_secs(5),
            run_websocket_session(client_ws, &to_agent_tx, &mut agent_out_rx, &cancel, &p77_withheld()),
        )
        .await
        .expect("test timed out");
        let received = to_agent_rx
            .try_recv()
            .expect("should have forwarded message to agent");
        let received_json: serde_json::Value = serde_json::from_str(&received).unwrap();
        assert_eq!(
            received_json.pointer("/params/clientCapabilities/_meta/fuigo~1userMessageEcho"),
            Some(&json!(true)),
            "the relay must declare the live user-message echo on the frame it forwards"
        );
        assert_eq!(received_json["method"], "initialize");
        assert_eq!(received_json["id"], json!(1));
        assert_eq!(
            received_json.pointer("/params/protocolVersion"),
            Some(&json!(1))
        );
    }
    #[tokio::test]
    async fn test_ws_session_cancel_stops_session() {
        let (client_ws, server_ws) = ws_pair().await;
        let _server_ws = server_ws;
        let (to_agent_tx, _to_agent_rx) = mpsc::unbounded_channel::<String>();
        let (_agent_out_tx, mut agent_out_rx) = mpsc::unbounded_channel::<String>();
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            cancel_clone.cancel();
        });
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            run_websocket_session(client_ws, &to_agent_tx, &mut agent_out_rx, &cancel, &p77_withheld()),
        )
        .await
        .expect("test timed out")
        .expect("session should not error");
        assert_eq!(result, SessionEndReason::Normal);
    }
    /// Helper to create a test FuigoAuth with the given key.
    /// P47: a session-token relay reaches its mock only as the configured `wss` origin through the P42 TLS front
    /// (see `agent::app::tests::relay_child`); each such test runs alone in a fresh process.
    fn fronted_child(test: &str) -> Option<crate::test_support::session_wire::SessionFront> {
        fuigo_test_support::env::fresh_process_home(&format!("agent::relay::tests::{test}"))?;
        Some(crate::test_support::session_wire::SessionFront::start())
    }
    fn fronted_ws(
        front: &crate::test_support::session_wire::SessionFront,
        addr: std::net::SocketAddr,
    ) -> (String, String) {
        let https = front.front(&format!("http://{addr}/"));
        (
            format!("{}/", https.replacen("https://", "wss://", 1)),
            "https://api.fluxrouter.ai".to_string(),
        )
    }
    /// P47: the gate itself — `wss` to an admitted origin passes; `ws`, loopback and other origins never do.
    #[test]
    fn p47_relay_destination_gate_follows_the_service_trust_class() {
        crate::agent::config::Config::install_test_trusted_origins();
        let config = |ws_url: &str| RelayConfig {
            ws_url: ws_url.to_string(),
            ws_origin: "https://api.fluxrouter.ai".to_string(),
            token_header: "t".to_string(),
            auth: test_auth("p47-relay-session"),
            auth_manager: None,
        };
        assert!(relay_destination_gate(&config("wss://api.fluxrouter.ai/")).is_ok());
        for refused in [
            "ws://api.fluxrouter.ai/",
            "ws://127.0.0.1:9/",
            "wss://127.0.0.1:9/",
            "wss://localhost/",
            "wss://[::1]:9/",
        ] {
            let err = relay_destination_gate(&config(refused)).expect_err(refused);
            assert!(err.to_string().contains("The request was not made"), "{refused}: {err}");
            let built = build_relay_request(&config(refused));
            assert!(built.is_err(), "{refused}: the request must not even be built");
        }
        // A static API key is not a session token and keeps its own rules.
        let mut api_key = config("ws://127.0.0.1:9/");
        api_key.auth.auth_mode = AuthMode::ApiKey;
        assert!(relay_destination_gate(&api_key).is_ok());
    }
    fn test_auth(key: &str) -> FuigoAuth {
        FuigoAuth {
            key: key.to_string(),
            refresh_token: Some("rt".to_string()),
            ..FuigoAuth::test_default()
        }
    }
    #[test]
    fn for_session_builds_only_for_fuigo_issuer() {
        crate::auth::set_test_oauth2_issuer(crate::auth::GROK_OAUTH2_ISSUER);
        crate::agent::config::Config::install_test_trusted_origins();
        use crate::auth::GROK_OAUTH2_ISSUER;
        let cfg = FuigoComConfig::default();
        let builds = |a: &FuigoAuth| RelayConfig::for_session(a, &cfg, None, None).is_some();
        let fuigo = FuigoAuth {
            auth_mode: AuthMode::Oidc,
            oidc_issuer: Some(GROK_OAUTH2_ISSUER.to_string()),
            ..test_auth("fuigo-bearer")
        };
        assert!(fuigo.is_fuigo_auth(), "precondition: is_fuigo_auth");
        assert!(builds(&fuigo));
        let external_fuigo = FuigoAuth {
            auth_mode: AuthMode::External,
            oidc_issuer: Some(GROK_OAUTH2_ISSUER.to_string()),
            ..test_auth("ext-bearer")
        };
        assert!(
            external_fuigo.is_fuigo_auth(),
            "precondition: is_fuigo_auth"
        );
        assert!(builds(&external_fuigo));
        assert!(!builds(&FuigoAuth {
            key: String::new(),
            ..fuigo.clone()
        }));
        assert!(!builds(&FuigoAuth {
            auth_mode: AuthMode::ApiKey,
            ..test_auth("k")
        }));
        assert!(!builds(&FuigoAuth {
            auth_mode: AuthMode::External,
            ..test_auth("k")
        }));
        assert!(!builds(&FuigoAuth {
            auth_mode: AuthMode::WebLogin,
            ..test_auth("k")
        }));
        assert!(!builds(&FuigoAuth {
            auth_mode: AuthMode::Oidc,
            oidc_issuer: Some("https://login.acme-corp.example/oauth2".to_string()),
            ..test_auth("k")
        }));
        assert!(!builds(&FuigoAuth {
            auth_mode: AuthMode::External,
            oidc_issuer: Some("https://login.acme-corp.example/oauth2".to_string()),
            ..test_auth("k")
        }));
    }
    /// Helper: write a FuigoAuth to disk under the given scope.
    fn write_test_auth_to_disk(dir: &std::path::Path, scope: &str, auth: &FuigoAuth) {
        let path = dir.join("auth.json");
        let mut map = crate::auth::read_auth_json(&path).unwrap_or_default();
        map.insert(scope.to_owned(), auth.clone());
        let json = serde_json::to_string_pretty(&map).unwrap();
        std::fs::write(&path, json).unwrap();
    }
    /// Regression: `auth.json` vanishes (deleted, corrupt, or externally removed).
    /// The process still holds an expired access token and a valid refresh token in `AuthManager` memory.
    /// Relay 401 recovery must drive the full refresh chain (mint a fresh token via the refresher and REWRITE `auth.json`) instead of dead-ending.
    /// A relay holding a private, refresher-less `AuthManager` fails this: it can only adopt sibling disk tokens, and there are none.
    #[tokio::test]
    async fn auth_recovery_refreshes_and_heals_missing_auth_json() {
        crate::auth::set_test_oauth2_issuer(crate::auth::GROK_OAUTH2_ISSUER);
        crate::agent::config::Config::install_test_trusted_origins();
        use crate::auth::GROK_OAUTH2_ISSUER;
        use crate::auth::refresh::{RefreshOutcome, TokenRefresher};
        use std::sync::atomic::AtomicU32;
        struct CountingRefresher {
            calls: Arc<AtomicU32>,
        }
        #[async_trait::async_trait]
        impl TokenRefresher for CountingRefresher {
            async fn refresh(
                &self,
                _reason: crate::auth::manager::RefreshReason,
            ) -> RefreshOutcome {
                self.calls.fetch_add(1, Ordering::SeqCst);
                RefreshOutcome::Success(Box::new(FuigoAuth {
                    key: "fresh-from-authority".into(),
                    auth_mode: AuthMode::Oidc,
                    oidc_issuer: Some(GROK_OAUTH2_ISSUER.to_string()),
                    refresh_token: Some("rt-rotated".into()),
                    expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
                    ..FuigoAuth::test_default()
                }))
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::auth::FuigoComConfig::default();
        let scope = cfg.auth_scope();
        let am = Arc::new(
            AuthManager::new(dir.path(), cfg.clone()).with_proxy_base_url("http://127.0.0.1:1"),
        );
        let expired_session = FuigoAuth {
            auth_mode: AuthMode::Oidc,
            oidc_issuer: Some(GROK_OAUTH2_ISSUER.to_string()),
            refresh_token: Some("rt-valid-unconsumed".into()),
            expires_at: Some(chrono::Utc::now() - chrono::Duration::hours(14)),
            ..test_auth("expired-overnight")
        };
        am.hot_swap(expired_session.clone());
        assert!(
            !dir.path().join("auth.json").exists(),
            "precondition: no auth.json on disk"
        );
        let calls = Arc::new(AtomicU32::new(0));
        am.set_refresher(Arc::new(CountingRefresher {
            calls: calls.clone(),
        }));
        let mut config = RelayConfig::for_session(&expired_session, &cfg, None, Some(am.clone()))
            .expect("x.ai OIDC session is relay-eligible");
        let cancel = CancellationToken::new();
        let recovered = attempt_auth_recovery(&mut config, &cancel, "test 401").await;
        assert!(recovered, "recovery must succeed via the shared refresher");
        assert!(!cancel.is_cancelled(), "relay must keep running");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "exactly one IdP refresh");
        assert_eq!(config.auth.key, "fresh-from-authority");
        let store = crate::auth::read_auth_json(&dir.path().join("auth.json"))
            .expect("auth.json must be recreated");
        let healed = store.get(&scope).expect("scope entry restored");
        assert_eq!(healed.key, "fresh-from-authority");
        assert_eq!(healed.refresh_token.as_deref(), Some("rt-rotated"));
    }
    /// Recovery returning the *unchanged* token (fresh-mint guard) must report no recovery, without cancelling the relay or touching the IdP.
    /// The caller then backs off before reconnecting instead of tight-looping.
    #[tokio::test]
    async fn attempt_auth_recovery_same_key_backs_off_without_cancel() {
        crate::auth::set_test_oauth2_issuer(crate::auth::GROK_OAUTH2_ISSUER);
        crate::agent::config::Config::install_test_trusted_origins();
        use crate::auth::GROK_OAUTH2_ISSUER;
        use crate::auth::refresh::{RefreshOutcome, TokenRefresher};
        struct PanicRefresher;
        #[async_trait::async_trait]
        impl TokenRefresher for PanicRefresher {
            async fn refresh(
                &self,
                _reason: crate::auth::manager::RefreshReason,
            ) -> RefreshOutcome {
                panic!("fresh-mint guard must keep recovery away from the IdP");
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::auth::FuigoComConfig::default();
        let am = Arc::new(AuthManager::new(dir.path(), cfg.clone()));
        let fresh_session = FuigoAuth {
            auth_mode: AuthMode::Oidc,
            oidc_issuer: Some(GROK_OAUTH2_ISSUER.to_string()),
            refresh_token: Some("rt-valid".into()),
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            ..test_auth("fresh-key")
        };
        am.hot_swap(fresh_session.clone());
        am.set_refresher(Arc::new(PanicRefresher));
        let mut config = RelayConfig::for_session(&fresh_session, &cfg, None, Some(am.clone()))
            .expect("x.ai OIDC session is relay-eligible");
        let cancel = CancellationToken::new();
        let recovered = attempt_auth_recovery(&mut config, &cancel, "test 401").await;
        assert!(!recovered, "same-key recovery must take the backoff path");
        assert!(!cancel.is_cancelled(), "relay must keep reconnecting");
        assert_eq!(config.auth.key, "fresh-key", "config auth stays unchanged");
    }
    #[tokio::test]
    async fn test_auth_refresh_via_auth_manager_on_auth_error() {
        let Some(front) = fronted_child("test_auth_refresh_via_auth_manager_on_auth_error") else {
            return;
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connection_count = Arc::new(AtomicU32::new(0));
        let count_clone = connection_count.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let count = count_clone.clone();
                tokio::spawn(async move {
                    let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                        return;
                    };
                    let (mut tx, _rx) = ws.split();
                    let n = count.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        let auth_err = json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "error": { "code": -32000, "message": "Token expired" }
                        });
                        let _ = tx
                            .send(Message::Text(Utf8Bytes::from(auth_err.to_string())))
                            .await;
                    } else {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                });
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::auth::FuigoComConfig::default();
        let scope = cfg.auth_scope();
        let am = Arc::new(AuthManager::new(dir.path(), cfg));
        am.hot_swap(test_auth("old-key"));
        write_test_auth_to_disk(dir.path(), &scope, &test_auth("new-key"));
        let (ws_url, ws_origin) = fronted_ws(&front, addr);
        let config = RelayConfig {
            ws_url,
            ws_origin,
            token_header: "test-token".to_string(),
            auth: test_auth("old-key"),
            auth_manager: Some(am),
        };
        let cancel = CancellationToken::new();
        let (from_relay_tx, _from_relay_rx) = mpsc::unbounded_channel();
        let (_to_relay_tx, _handle) = spawn_relay_connection(config, from_relay_tx, cancel.clone());
        tokio::time::sleep(Duration::from_secs(3)).await;
        cancel.cancel();
        assert!(
            connection_count.load(Ordering::SeqCst) >= 2,
            "should have connected at least twice (original + after refresh), got {}",
            connection_count.load(Ordering::SeqCst)
        );
    }
    #[tokio::test]
    async fn test_auth_refresh_failure_continues_with_backoff() {
        let Some(front) = fronted_child("test_auth_refresh_failure_continues_with_backoff") else {
            return;
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connection_count = Arc::new(AtomicU32::new(0));
        let count_clone = connection_count.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let count = count_clone.clone();
                tokio::spawn(async move {
                    let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                        return;
                    };
                    let (mut tx, _rx) = ws.split();
                    count.fetch_add(1, Ordering::SeqCst);
                    let auth_err = json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "error": { "code": -32000, "message": "Token expired" }
                    });
                    let _ = tx
                        .send(Message::Text(Utf8Bytes::from(auth_err.to_string())))
                        .await;
                });
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::auth::FuigoComConfig::default();
        let scope = cfg.auth_scope();
        let am = Arc::new(AuthManager::new(dir.path(), cfg));
        am.hot_swap(test_auth("old-key"));
        write_test_auth_to_disk(dir.path(), &scope, &test_auth("old-key"));
        let (ws_url, ws_origin) = fronted_ws(&front, addr);
        let config = RelayConfig {
            ws_url,
            ws_origin,
            token_header: "test-token".to_string(),
            auth: test_auth("old-key"),
            auth_manager: Some(am),
        };
        let cancel = CancellationToken::new();
        let (from_relay_tx, _from_relay_rx) = mpsc::unbounded_channel();
        let (_to_relay_tx, _handle) = spawn_relay_connection(config, from_relay_tx, cancel.clone());
        tokio::time::sleep(Duration::from_secs(4)).await;
        cancel.cancel();
        assert!(
            connection_count.load(Ordering::SeqCst) >= 2,
            "should have retried after failed refresh, got {}",
            connection_count.load(Ordering::SeqCst)
        );
    }
    /// U086's relay half. The relay persists `user_message_chunk` only from the agent's
    /// notifications, so once the live echo became opt-in a relay whose `initialize` omits
    /// `fuigo/userMessageEcho` would silently store sessions with no user prompts at all.
    #[test]
    fn relay_initialize_gains_user_message_echo_capability() {
        let mut frame = serde_json::json!({
            "jsonrpc": "2.0", "id": 7, "method": "initialize",
            "params": {
                "protocolVersion": 1,
                "clientCapabilities": { "_meta": { "fuigo/fs_notify": true } }
            }
        });
        assert!(declare_relay_client_capabilities(&mut frame));
        let meta = frame
            .pointer("/params/clientCapabilities/_meta")
            .expect("_meta present");
        assert_eq!(
            meta.get("fuigo/userMessageEcho"),
            Some(&serde_json::json!(true))
        );
        assert_eq!(meta.get("fuigo/fs_notify"), Some(&serde_json::json!(true)));
        assert_eq!(frame.get("id"), Some(&serde_json::json!(7)));
    }
    #[test]
    fn relay_initialize_without_capabilities_block_gets_one() {
        let mut frame = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "protocolVersion": 1 }
        });
        assert!(declare_relay_client_capabilities(&mut frame));
        assert_eq!(
            frame.pointer("/params/clientCapabilities/_meta/fuigo~1userMessageEcho"),
            Some(&serde_json::json!(true))
        );
    }
    #[test]
    fn relay_explicit_user_message_echo_is_respected() {
        let mut frame = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "clientCapabilities": { "_meta": { "fuigo/userMessageEcho": false } } }
        });
        assert!(!declare_relay_client_capabilities(&mut frame));
        assert_eq!(
            frame.pointer("/params/clientCapabilities/_meta/fuigo~1userMessageEcho"),
            Some(&serde_json::json!(false))
        );
    }
    #[test]
    fn non_initialize_frames_are_left_alone() {
        for frame in [
            serde_json::json!({ "jsonrpc": "2.0", "id": 2, "method": "session/new", "params": { "cwd": "/w", "_meta": {} } }),
            serde_json::json!({ "jsonrpc": "2.0", "id": 3, "result": { "ok": true } }),
            serde_json::json!({ "jsonrpc": "2.0", "method": "session/update", "params": { "sessionId": "s" } }),
        ] {
            let original = frame.clone();
            let mut frame = frame;
            assert!(!declare_relay_client_capabilities(&mut frame));
            assert_eq!(frame, original);
        }
    }

    // ===== P77: the host name in an `initialize` response follows the relay's operator =====

    fn p77_identity(relay_url: &str) -> RelayBodyIdentity {
        RelayBodyIdentity::for_relay(relay_url, p81_machine_id)
    }
    /// The agent's ACP `initialize` response, as the bridge hands it to the relay writer.
    fn p77_initialize_response() -> String {
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "result": {
                "protocolVersion": 1,
                "agentCapabilities": { "loadSession": true },
                "_meta": {
                    "fuigoShell": true,
                    "currentWorkingDirectory": "/work/proj",
                    "agentVersion": "1.0.0",
                    "hostname": "My_Laptop.local",
                    "modelState": { "ratio": 0.5 },
                    "metadata": { "hostname": "service.example" },
                }
            }
        })
        .to_string()
    }
    const P77_FLUXROUTER_RELAYS: [&str; 2] = ["wss://api.fluxrouter.ai/ws/relay", "WSS://API.FLUXROUTER.AI./ws"];
    const P77_OTHER_RELAYS: [&str; 6] = [
        "wss://relay.example/ws",
        "ws://api.fluxrouter.ai/ws/relay",
        "https://api.fluxrouter.ai/ws/relay",
        "wss://api.fluxrouter.ai.evil.example/ws",
        "not a url",
        "",
    ];
    /// The agent's `fuigo/session/list` response, produced by the real response types (`ExtMethodResult` around
    /// `ext_list_response`), as the JSON-RPC response ACP writes: the extension response is the `result`. Rows carry
    /// the host names the session registry returned.
    fn p77_real_session_list_response() -> String {
        use crate::session::{merge::MergedSession, result::ExtMethodResult, unified_list};
        let registry = unified_list::facet_registry();
        let rows: Vec<unified_list::UnifiedRow> = [
            ("s1", Some("My_Laptop.local")),
            ("s2", Some("other-box")),
            ("s3", None),
            ("s4", Some("fourth-box")),
        ]
        .into_iter()
        .map(|(id, hostname)| {
            unified_list::merged_session_to_row(
                MergedSession {
                    session_id: id.into(),
                    summary: "a summary".into(),
                    updated_at: "2026-06-18T20:10:00Z".into(),
                    created_at: "2026-01-01T00:00:00Z".into(),
                    cwd: "/work/proj".into(),
                    hostname: hostname.map(Into::into),
                    source: "both".into(),
                    ..Default::default()
                },
                registry,
            )
        })
        .collect();
        let facets = registry.summarize_window(&rows);
        let response = ExtMethodResult::success(unified_list::ext_list_response(unified_list::UnifiedListResult {
            rows,
            next_cursor: None,
            facets,
            conversations_partial: None,
            scope: unified_list::ListScope::Cwd,
        }))
        .to_ext_response()
        .expect("the list response serialises");
        format!(r#"{{"jsonrpc":"2.0","id":9,"result":{}}}"#, response.0.get())
    }
    /// The same rows directly under the response's result (no envelope).
    fn p77_session_list_response() -> String {
        json!({
            "jsonrpc": "2.0",
            "id": 9,
            "result": {
                "sessions": [
                    { "sessionId": "s1", "cwd": "/work/proj", "hostname": "My_Laptop.local", "source": "both", "title": "one" },
                    { "sessionId": "s2", "cwd": "/srv", "source": "local", "title": "two" },
                    { "sessionId": "s3", "cwd": "/srv", "hostname": "other-box", "source": "remote", "title": "three" },
                ],
                "_meta": { "partial": { "conversations": false } }
            }
        })
        .to_string()
    }
    /// P77: a FluxRouter-operated relay gets every frame byte for byte; any other relay gets a RESPONSE without any
    /// `hostname` field (`initialize`: `result._meta.hostname`; `fuigo/session/list`: every row's), everything else in
    /// it unchanged and in the same order; requests, notifications and frames without the field are passed through
    /// untouched whatever they contain.
    #[test]
    fn p77_relay_outbound_frame_withholds_the_hostname_from_a_non_fluxrouter_relay() {
        let response = p77_initialize_response();
        assert!(response.contains("My_Laptop.local"), "positive control");
        for url in P77_FLUXROUTER_RELAYS {
            assert_eq!(relay_outbound_frame(&p77_identity(url), response.clone()), response, "{url}");
        }
        let expected = response.replace(r#""hostname":"My_Laptop.local","#, "");
        assert_ne!(expected, response, "the fixture has the field where the replace looks for it");
        for url in P77_OTHER_RELAYS {
            let sent = relay_outbound_frame(&p77_identity(url), response.clone());
            assert_eq!(sent, expected, "{url}");
            assert!(!sent.to_lowercase().contains("laptop"), "{url}: {sent}");
            let parsed: serde_json::Value = serde_json::from_str(&sent).unwrap();
            assert!(parsed["result"]["_meta"].get("hostname").is_none(), "{url}");
        }
        assert_eq!(relay_outbound_frame(&p77_withheld(), response.clone()), expected, "withholding is the default");
        // The session list: every row's host name, this machine's and the others'.
        let list = p77_session_list_response();
        let list_expected = list
            .replace(r#""hostname":"My_Laptop.local","#, "")
            .replace(r#""hostname":"other-box","#, "");
        assert_eq!(list_expected.len() + 52, list.len(), "the fixture has both fields where the replace looks");
        for url in P77_FLUXROUTER_RELAYS {
            assert_eq!(relay_outbound_frame(&p77_identity(url), list.clone()), list, "{url}");
        }
        for url in P77_OTHER_RELAYS {
            let sent = relay_outbound_frame(&p77_identity(url), list.clone());
            assert_eq!(sent, list_expected, "{url}");
            assert!(!sent.contains("hostname") && !sent.contains("Laptop") && !sent.contains("other-box"), "{sent}");
        }
        // The real response: the rows are under the extension envelope's own `result`.
        let real = p77_real_session_list_response();
        let parsed: serde_json::Value = serde_json::from_str(&real).unwrap();
        for (row, host) in [(0, "My_Laptop.local"), (1, "other-box"), (3, "fourth-box")] {
            assert_eq!(parsed["result"]["result"]["sessions"][row]["hostname"], host, "positive control: {real}");
        }
        assert!(parsed["result"]["result"]["sessions"][2].get("hostname").is_none(), "{real}");
        let real_expected = real
            .replace(r#""hostname":"My_Laptop.local","#, "")
            .replace(r#""hostname":"other-box","#, "")
            .replace(r#""hostname":"fourth-box","#, "");
        assert_eq!(real_expected.len() + 52 + 24, real.len(), "the three fields are where the replace looks");
        for url in P77_FLUXROUTER_RELAYS {
            assert_eq!(relay_outbound_frame(&p77_identity(url), real.clone()), real, "{url}");
        }
        for url in P77_OTHER_RELAYS {
            let sent = relay_outbound_frame(&p77_identity(url), real.clone());
            assert_eq!(sent, real_expected, "{url}");
            for gone in ["Laptop", "other-box", "fourth-box", "\"hostname\""] {
                assert!(!sent.contains(gone), "{url}: {gone} in {sent}");
            }
        }
        // Not one of the two identity fields: untouched, byte for byte. A `hostname` elsewhere in a response is
        // application data (an MCP setup value, the embedder's agent metadata); a session update or a request carries
        // the user's own content; an error has no result.
        for untouched in [
            json!({ "jsonrpc": "2.0", "id": 2, "result": { "servers": [{ "name": "db", "setupValues": { "hostname": "db.example" } }] } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 2, "result": { "result": { "hostname": "x", "_meta": { "hostname": "y" }, "servers": [{ "hostname": "db.example" }] } } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 3, "result": { "hostname": "x", "a": [{ "hostname": "y" }], "sessions": "none", "_meta": [1] } }).to_string(),
            json!({ "jsonrpc": "2.0", "method": "session/update", "params": { "update": { "text": "{\"hostname\": 1}", "hostname": "x" } } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 5, "method": "session/request_permission", "params": { "hostname": "x" }, "result": { "_meta": { "hostname": "y" } } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 6, "error": { "code": -1, "message": "no", "data": { "hostname": "x" } } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 3, "result": { "text": "the \"hostname\" key", "_meta": { "other": 1.50 } } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 4, "result": { "ok": true } }).to_string(),
            String::new(),
        ] {
            assert_eq!(relay_outbound_frame(&p77_withheld(), untouched.clone()), untouched);
        }
        // A non-string value is withheld like any other.
        assert_eq!(
            relay_outbound_frame(&p77_withheld(), r#"{"id":1,"result":{"_meta":{"hostname":null,"a":1},"sessions":[{"hostname":7,"b":2},3]}}"#.to_string()),
            r#"{"id":1,"result":{"_meta":{"a":1},"sessions":[{"b":2},3]}}"#
        );
        // All three places in one response: no removal hides another.
        assert_eq!(
            relay_outbound_frame(&p77_withheld(), r#"{"id":1,"result":{"_meta":{"hostname":"h","a":1},"result":{"sessions":[{"hostname":"h","b":2}]},"sessions":[{"hostname":"h","c":3}]}}"#.to_string()),
            r#"{"id":1,"result":{"_meta":{"a":1},"result":{"sessions":[{"b":2}]},"sessions":[{"c":3}]}}"#
        );
        // Every other value is carried as raw text: written back byte for byte (number spellings, escapes), and
        // however deeply nested. 200 nested arrays exceed the nesting limit of a full parse.
        assert_eq!(
            relay_outbound_frame(&p77_withheld(), r#"{"id":1.0e0,"result":{"_meta":{"a":1.50,"hostname":"h","b":"\u00e9"},"x":[ 1 , 2 ]},"z":18446744073709551616}"#.to_string()),
            r#"{"id":1.0e0,"result":{"_meta":{"a":1.50,"b":"\u00e9"},"x":[ 1 , 2 ]},"z":18446744073709551616}"#
        );
        let deep = format!(
            r#"{{"jsonrpc":"2.0","id":8,"result":{{"_meta":{{"hostname":"My_Laptop.local","metadata":{}0{}}}}}}}"#,
            "[".repeat(200),
            "]".repeat(200)
        );
        assert!(serde_json::from_str::<serde_json::Value>(&deep).is_err(), "positive control: too deep for a full parse");
        assert_eq!(
            relay_outbound_frame(&p77_withheld(), deep.clone()),
            deep.replace(r#""hostname":"My_Laptop.local","#, ""),
            "a valid deep response is delivered, without the host name"
        );
        // Fails closed: a frame that names the field and is not a JSON object is not sent to a non-FluxRouter relay
        // (and is sent, untouched, to a FluxRouter one).
        for unreadable in [
            r#"not json "hostname""#.to_string(),
            r#"[{"result":{"_meta":{"hostname":"h"}}}]"#.to_string(),
            r#"{"result":{"_meta":{"hostname":"h"}}"#.to_string(),
        ] {
            assert_eq!(relay_outbound_frame(&p77_withheld(), unreadable.clone()), "", "{unreadable}");
            for url in P77_FLUXROUTER_RELAYS {
                assert_eq!(relay_outbound_frame(&p77_identity(url), unreadable.clone()), unreadable, "{url}");
            }
        }
    }
    /// P77, through the real socket writer: what the relay receives for the agent's `initialize` response.
    #[tokio::test]
    async fn p77_ws_session_writes_the_initialize_response_by_relay_operator() {
        let response = p77_initialize_response();
        let expected = response.replace(r#""hostname":"My_Laptop.local","#, "");
        for (url, want) in [
            ("wss://api.fluxrouter.ai/ws/relay", &response),
            ("wss://relay.example/ws", &expected),
            ("ws://api.fluxrouter.ai/ws/relay", &expected),
        ] {
            let (client_ws, server_ws) = ws_pair().await;
            let (_server_tx, mut server_rx) = server_ws.split();
            let (to_agent_tx, _to_agent_rx) = mpsc::unbounded_channel::<String>();
            let (agent_out_tx, mut agent_out_rx) = mpsc::unbounded_channel::<String>();
            let cancel = CancellationToken::new();
            let update = json!({ "jsonrpc": "2.0", "method": "session/update", "params": { "hostname": "x" } }).to_string();
            agent_out_tx.send(response.clone()).unwrap();
            agent_out_tx.send(update.clone()).unwrap();
            let identity = p77_identity(url);
            let session = run_websocket_session(client_ws, &to_agent_tx, &mut agent_out_rx, &cancel, &identity);
            let read = async {
                let mut frames = Vec::new();
                while frames.len() < 2 {
                    match server_rx.next().await {
                        Some(Ok(Message::Text(text))) => frames.push(text.to_string()),
                        Some(Ok(_)) => continue,
                        other => panic!("{url}: the relay side saw {other:?} after {frames:?}"),
                    }
                }
                cancel.cancel();
                frames
            };
            let (ended, got) = tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(session, read) })
                .await
                .expect("test timed out");
            assert_eq!(ended.expect("session ends cleanly on cancel"), SessionEndReason::Normal, "{url}");
            // The response as this relay may see it, then the next frame: the writer keeps going, and a notification
            // is never rewritten.
            assert_eq!(got, [want.clone(), update], "{url}");
        }
    }
    /// P77 source pin: the relay socket has one text writer, every frame goes through `relay_outbound_frame` on its
    /// way to it, and the decision it is given is the one for the URL this loop connects to.
    #[test]
    fn p77_relay_writer_is_gated_on_the_connected_relay() {
        let src = include_str!("relay.rs");
        let prod = src.split("\n#[cfg(test)]").next().unwrap();
        let flat = prod.split_whitespace().collect::<Vec<_>>().join(" ");
        assert_eq!(flat.matches("ws_outbound.send(Message::Text(").count(), 1, "one text writer");
        assert_eq!(flat.matches("relay_outbound_frame(").count(), 2, "definition + the one use");
        assert_eq!(flat.matches("run_websocket_session(").count(), 1, "the one caller");
        for pinned in [
            "let msg = relay_outbound_frame(identity, msg); if !msg.is_empty() && let Err(e) = \
             ws_outbound.send(Message::Text(Utf8Bytes::from(msg))).await",
            "run_websocket_session( ws, &to_agent_tx, &mut agent_to_ws_rx, &cancel, &config.body_identity(), ) \
             .await;",
            "Duration::from_secs(READ_LIVENESS_TIMEOUT_SECS), identity, ) .await",
            "if identity.disclosure.is_permitted() || !RELAY_IDENTITY_KEYS.iter().any(|key| msg.contains(key)) { \
             return msg; }",
            "const RELAY_IDENTITY_KEYS: [&str; 14] = [ \"\\\"hostname\\\"\", \"\\\"agentId\\\"\", \"\\\"email\\\"\", \
             \"\\\"team_id\\\"\", \"\\\"team_name\\\"\", \"\\\"firstName\\\"\", \"\\\"lastName\\\"\", \
             \"\\\"profileImageUrl\\\"\", \"\\\"teamId\\\"\", \"\\\"teamName\\\"\", \"\\\"organizationId\\\"\", \
             \"\\\"organizationName\\\"\", \"\\\"principalId\\\"\", \"\\\"userId\\\"\", ];",
            // P81: the writer's decision and the pseudonym's origin are both the URL the loop connects to, and the
            // machine id is the persisted one.
            "pub(crate) fn body_identity(&self) -> RelayBodyIdentity { RelayBodyIdentity::for_relay(&self.ws_url, \
             fuigo_telemetry::id::agent_id) }",
            "disclosure: fuigo_extra_ca::fluxrouter::IdentityDisclosure::for_websocket_destination(relay_url), \
             relay_url: relay_url.to_owned(), machine_id, }",
            "fuigo_extra_ca::fluxrouter::IdentityDisclosure::body_key_for_websocket(&self.relay_url, machine_id)",
            "pub(crate) fn identity_disclosure(&self) -> fuigo_extra_ca::fluxrouter::IdentityDisclosure { \
             fuigo_extra_ca::fluxrouter::IdentityDisclosure::for_websocket_destination(&self.ws_url) }",
            "connect_to_relay(&config",
        ] {
            assert!(flat.contains(pinned), "{pinned}");
        }
    }
    // ===== P81: the persisted machine id in the agent's `initialize` response follows the relay's operator =====

    /// The agent's ACP `initialize` response as the bridge hands it to the relay writer, with the fields
    /// `acp_agent.rs` puts in `_meta` (the machine id, the per-process instance id, the host name).
    fn p81_initialize_response(agent_id: &str) -> String {
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "result": {
                "protocolVersion": 1,
                "agentCapabilities": { "loadSession": true },
                "_meta": {
                    "fuigoShell": true,
                    "currentWorkingDirectory": "/work/proj",
                    "agentVersion": "1.0.0",
                    "agentId": agent_id,
                    "agentInstanceId": "0b5c2d7e-1111-4222-8333-444455556666",
                    "hostname": "My_Laptop.local",
                    "modelState": { "ratio": 0.5 },
                    "metadata": { "agentId": agent_id, "hostname": "service.example" },
                }
            }
        })
        .to_string()
    }
    /// What a relay that is not FluxRouter-operated receives for [`p81_initialize_response`]: no host name, and the
    /// pseudonym in place of the machine id, everything else byte for byte.
    fn p81_withheld_initialize_response(relay_url: &str, agent_id: &str) -> String {
        let response = p81_initialize_response(agent_id);
        let key = fuigo_extra_ca::fluxrouter::destination_pseudonym(relay_url, agent_id);
        // The id as JSON writes it (a configured `FUIGO_AGENT_ID` may need escapes); the key never does.
        let written = serde_json::to_string(agent_id).unwrap();
        let expected = response
            .replace(r#""hostname":"My_Laptop.local","#, "")
            .replacen(&format!(r#""agentId":{written},"agentInstanceId""#), &format!(r#""agentId":"{key}","agentInstanceId""#), 1);
        assert_eq!(expected.len() + 29 + written.len(), response.len() + key.len() + 2, "the host name is where the replace looks");
        assert!(expected.contains(&format!(r#""agentVersion":"1.0.0","agentId":"{key}","agentInstanceId""#)), "so is the machine id");
        expected
    }
    /// P81 hostile: a relay that is not FluxRouter-operated never receives the persisted machine id in the agent's
    /// `initialize` response; it receives P54's pseudonym for its own origin, in the same place. A FluxRouter relay
    /// receives the response byte for byte. Only that field, only when it IS the machine id.
    #[test]
    fn p81_relay_outbound_frame_pseudonymises_the_machine_id_for_a_non_fluxrouter_relay() {
        let response = p81_initialize_response(P81_MACHINE_ID);
        assert_eq!(response.matches(P81_MACHINE_ID).count(), 2, "positive control: `_meta.agentId` and the embedder's metadata");
        for url in P77_FLUXROUTER_RELAYS {
            assert_eq!(relay_outbound_frame(&p77_identity(url), response.clone()), response, "{url}");
        }
        for url in P77_OTHER_RELAYS {
            let sent = relay_outbound_frame(&p77_identity(url), response.clone());
            assert_eq!(sent, p81_withheld_initialize_response(url, P81_MACHINE_ID), "{url}");
            let parsed: serde_json::Value = serde_json::from_str(&sent).unwrap();
            let meta = &parsed["result"]["_meta"];
            let key = fuigo_extra_ca::fluxrouter::destination_pseudonym(url, P81_MACHINE_ID);
            assert_eq!(meta["agentId"], key.as_str(), "{url}");
            assert_ne!(key, P81_MACHINE_ID, "{url}");
            assert_eq!(key.len(), 36, "{url}: UUID-shaped, as the id it stands for");
            // The per-process instance id is a correlation id (P15-R) and the embedder's own metadata is application
            // data: both pass.
            assert_eq!(meta["agentInstanceId"], "0b5c2d7e-1111-4222-8333-444455556666", "{url}");
            assert_eq!(meta["metadata"]["agentId"], P81_MACHINE_ID, "{url}");
            assert!(meta.get("hostname").is_none(), "{url}");
            // The key keeps its position.
            let keys: Vec<&str> = meta.as_object().unwrap().keys().map(String::as_str).collect();
            assert_eq!(
                keys,
                ["fuigoShell", "currentWorkingDirectory", "agentVersion", "agentId", "agentInstanceId", "modelState", "metadata"],
                "{url}"
            );
        }
        // The machine id alone (no host name in the response): still replaced. A removal does not hide it and it does
        // not hide a removal.
        let only_id = format!(r#"{{"id":1,"result":{{"_meta":{{"a":1,"agentId":"{P81_MACHINE_ID}","b":2}}}}}}"#);
        let key = fuigo_extra_ca::fluxrouter::destination_pseudonym("wss://relay.example/ws", P81_MACHINE_ID);
        assert_eq!(
            relay_outbound_frame(&p77_identity("wss://relay.example/ws"), only_id),
            format!(r#"{{"id":1,"result":{{"_meta":{{"a":1,"agentId":"{key}","b":2}}}}}}"#)
        );
        let id_then_host = format!(r#"{{"id":1,"result":{{"_meta":{{"agentId":"{P81_MACHINE_ID}","hostname":"h"}},"sessions":[{{"hostname":"h","c":3}}]}}}}"#);
        assert_eq!(
            relay_outbound_frame(&p77_identity("wss://relay.example/ws"), id_then_host),
            format!(r#"{{"id":1,"result":{{"_meta":{{"agentId":"{key}"}},"sessions":[{{"c":3}}]}}}}"#)
        );
        // Not the machine id: untouched, byte for byte. Relay sync's own `initialize` carries the session-scoped
        // `"<agent type>-<session id>"` there (a correlation id); an id that merely contains or resembles the machine
        // id, or is not a string, is not it; the same key anywhere else is application data; requests and
        // notifications are never rewritten; an error has no result.
        let other_id = P81_MACHINE_ID.replace("5d1f", "5d1e");
        for untouched in [
            json!({ "jsonrpc": "2.0", "id": 0, "result": { "protocolVersion": 1, "_meta": { "agentType": "tui", "agentId": "tui-sess-1", "sessionId": "sess-1", "currentWorkingDirectory": "/w" } } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 0, "result": { "_meta": { "agentId": format!("tui-{P81_MACHINE_ID}") } } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 0, "result": { "_meta": { "agentId": other_id } } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 0, "result": { "_meta": { "agentId": P81_MACHINE_ID.to_uppercase() } } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 0, "result": { "_meta": { "agentId": [P81_MACHINE_ID] } } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 0, "result": { "_meta": { "agentId": null } } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 2, "result": { "agentId": P81_MACHINE_ID, "agents": [{ "agentId": P81_MACHINE_ID }], "_meta": [1] } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 2, "result": { "result": { "agentId": P81_MACHINE_ID, "_meta": { "agentId": P81_MACHINE_ID } } } }).to_string(),
            json!({ "jsonrpc": "2.0", "method": "session/update", "params": { "_meta": { "agentId": P81_MACHINE_ID } } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 5, "method": "session/request_permission", "params": {}, "result": { "_meta": { "agentId": P81_MACHINE_ID } } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 6, "error": { "code": -1, "message": "no", "data": { "_meta": { "agentId": P81_MACHINE_ID } } } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 3, "result": { "text": "the \"agentId\" key", "_meta": { "other": 1.50 } } }).to_string(),
        ] {
            for url in P77_OTHER_RELAYS {
                assert_eq!(relay_outbound_frame(&p77_identity(url), untouched.clone()), untouched, "{url}");
            }
        }
        // Every other value is carried as raw text and written back byte for byte, however deeply nested (200 nested
        // arrays exceed the nesting limit of a full parse): a valid response is delivered, with the pseudonym.
        let deep = format!(
            r#"{{"jsonrpc":"2.0","id":1.0e0,"result":{{"_meta":{{"a":1.50,"agentId":"{P81_MACHINE_ID}","b":"\u00e9","metadata":{}0{}}},"x":[ 1 , 2 ]}},"z":18446744073709551616}}"#,
            "[".repeat(200),
            "]".repeat(200)
        );
        assert!(serde_json::from_str::<serde_json::Value>(&deep).is_err(), "positive control: too deep for a full parse");
        assert_eq!(
            relay_outbound_frame(&p77_identity("wss://relay.example/ws"), deep.clone()),
            deep.replace(P81_MACHINE_ID, &key)
        );
        // Fails closed: a frame that names the field and is not a JSON object is not sent to a relay that is not
        // FluxRouter-operated (and is sent, untouched, to a FluxRouter one).
        for unreadable in [
            format!(r#"not json "agentId" {P81_MACHINE_ID}"#),
            format!(r#"[{{"result":{{"_meta":{{"agentId":"{P81_MACHINE_ID}"}}}}}}]"#),
            format!(r#"{{"result":{{"_meta":{{"agentId":"{P81_MACHINE_ID}"}}}}"#),
        ] {
            for url in P77_OTHER_RELAYS {
                assert_eq!(relay_outbound_frame(&p77_identity(url), unreadable.clone()), "", "{url}: {unreadable}");
            }
            for url in P77_FLUXROUTER_RELAYS {
                assert_eq!(relay_outbound_frame(&p77_identity(url), unreadable.clone()), unreadable, "{url}");
            }
        }
    }
    /// What the relay side of an in-memory socket receives when the agent emits `frames` through the real writer.
    async fn p81_relay_receives(identity: &RelayBodyIdentity, frames: &[String]) -> Vec<String> {
        p81_relay_receives_n(identity, frames, frames.len()).await
    }
    /// The first `delivered` text frames the relay side receives when the agent emits `frames`.
    async fn p81_relay_receives_n(identity: &RelayBodyIdentity, frames: &[String], delivered: usize) -> Vec<String> {
        let (client_ws, server_ws) = ws_pair().await;
        let (_server_tx, mut server_rx) = server_ws.split();
        let (to_agent_tx, _to_agent_rx) = mpsc::unbounded_channel::<String>();
        let (agent_out_tx, mut agent_out_rx) = mpsc::unbounded_channel::<String>();
        let cancel = CancellationToken::new();
        for frame in frames {
            agent_out_tx.send(frame.clone()).unwrap();
        }
        let session = run_websocket_session(client_ws, &to_agent_tx, &mut agent_out_rx, &cancel, identity);
        let read = async {
            let mut got = Vec::new();
            while got.len() < delivered {
                match server_rx.next().await {
                    Some(Ok(Message::Text(text))) => got.push(text.to_string()),
                    Some(Ok(_)) => continue,
                    other => panic!("the relay side saw {other:?} after {got:?}"),
                }
            }
            cancel.cancel();
            got
        };
        let (ended, got) = tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(session, read) })
            .await
            .expect("test timed out");
        assert_eq!(ended.expect("session ends cleanly on cancel"), SessionEndReason::Normal);
        got
    }
    fn p81_relay_config(ws_url: &str) -> RelayConfig {
        RelayConfig {
            ws_url: ws_url.to_string(),
            ws_origin: "https://origin.example".to_string(),
            token_header: "t".to_string(),
            auth: test_auth("p81-relay-session"),
            auth_manager: None,
        }
    }
    /// P81, through the real socket writer and the production decision (`RelayConfig::body_identity`, so the machine
    /// id is the persisted one this process reads): what each relay receives for the agent's `initialize` response,
    /// and that the key is the same on every connection to one relay and after a restart, and different per relay.
    #[tokio::test]
    async fn p81_ws_session_writes_the_machine_id_by_relay_operator_and_keeps_one_key_per_relay() {
        let machine_id = fuigo_telemetry::id::agent_id();
        assert!(!machine_id.is_empty(), "positive control: this process has a machine id");
        let response = p81_initialize_response(&machine_id);
        let update = json!({ "jsonrpc": "2.0", "method": "session/update", "params": { "agentId": "x" } }).to_string();
        let frames = [response.clone(), update.clone()];
        // FluxRouter-operated relay: byte for byte.
        let flux = p81_relay_config("wss://api.fluxrouter.ai/ws/relay").body_identity();
        assert_eq!(p81_relay_receives(&flux, &frames).await, frames);
        // Any other relay: the pseudonym for ITS origin; the next frame follows (the writer keeps going).
        let mut keys = Vec::new();
        for url in ["wss://relay.example/ws", "wss://other-relay.example/ws", "ws://api.fluxrouter.ai/ws/relay"] {
            let expected = p81_withheld_initialize_response(url, &machine_id);
            // The first connection, a reconnect of the same loop (the same `RelayConfig`, as `run_relay_loop` holds
            // it), and a restart (a new `RelayConfig` for the same URL; the machine id is the persisted one).
            let config = p81_relay_config(url);
            for identity in [config.body_identity(), config.body_identity(), p81_relay_config(url).body_identity()] {
                let got = p81_relay_receives(&identity, &frames).await;
                assert_eq!(got, [expected.clone(), update.clone()], "{url}");
                // `_meta.agentId` is not the machine id any more; the embedder's own metadata (application data) still
                // carries its copy.
                let sent: serde_json::Value = serde_json::from_str(&got[0]).unwrap();
                assert_ne!(sent["result"]["_meta"]["agentId"], machine_id.as_str(), "{url}: {got:?}");
                assert_eq!(sent["result"]["_meta"]["metadata"]["agentId"], machine_id.as_str(), "{url}: {got:?}");
            }
            let parsed: serde_json::Value = serde_json::from_str(&expected).unwrap();
            keys.push(parsed["result"]["_meta"]["agentId"].as_str().unwrap().to_owned());
        }
        assert_eq!(keys[0], fuigo_extra_ca::fluxrouter::destination_pseudonym("wss://relay.example", &machine_id));
        assert_eq!(keys[0], fuigo_extra_ca::fluxrouter::IdentityDisclosure::body_key_for_websocket("wss://relay.example/other/path", &machine_id), "one key per relay origin, whatever the path");
        assert!(keys[0] != keys[1] && keys[1] != keys[2] && keys[0] != keys[2], "one key per relay: {keys:?}");
        assert!(keys.iter().all(|key| *key != machine_id), "{keys:?}");
    }
    // ===== P81: who is signed in, in the agent's auth responses, follows the relay's operator =====

    const P81_ACCOUNT_VALUES: [&str; 9] = [
        "ada@corp.example",
        "Ada",
        "Lovelace",
        "asset-77",
        "team-7f3e",
        "Analytical Engines",
        "org-19c2",
        "Corp Example",
        "principal-51aa",
    ];
    /// `auth::AuthMeta` (the real type) as the agent fills it for a team session.
    fn p81_auth_meta() -> serde_json::Value {
        serde_json::to_value(crate::auth::AuthMeta {
            email: Some("ada@corp.example".into()),
            auth_mode: Some("Oidc".into()),
            team_id: Some("team-7f3e".into()),
            team_name: Some("Analytical Engines".into()),
            team_role: Some("admin".into()),
            subscription_tier: Some("Pro".into()),
            gate: Some(crate::auth::GateInfo { message: "upgrade".into() }),
            ..Default::default()
        })
        .unwrap()
    }
    /// The four agent responses that say who is signed in, as ACP writes them, with what a relay that is not
    /// FluxRouter-operated receives for each.
    fn p81_account_responses() -> Vec<(&'static str, String, String)> {
        // `authenticate`: `AuthenticateResponse` with `AuthMeta` as its `_meta`.
        let authenticate = format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{}}}"#,
            serde_json::to_string(&agent_client_protocol::AuthenticateResponse::new().meta(p81_auth_meta().as_object().cloned())).unwrap()
        );
        // `fuigo/auth/check_subscription`: the same metadata under `meta` (`extensions/auth.rs`).
        let check = json!({ "jsonrpc": "2.0", "id": 2, "result": { "authenticated": true, "meta": p81_auth_meta() } }).to_string();
        let meta_removed = |frame: &str| {
            frame
                .replace(r#""email":"ada@corp.example","#, "")
                .replace(r#""team_id":"team-7f3e","team_name":"Analytical Engines","#, "")
        };
        // `fuigo/auth/info`: `AuthInfoResponse`, every field, in its order (`extensions/auth.rs`).
        let info = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "result": {
                "methodId": "fuigo.com",
                "email": "ada@corp.example",
                "firstName": "Ada",
                "lastName": "Lovelace",
                "profileImageUrl": "fuigo-asset:///asset-77",
                "teamId": "team-7f3e",
                "teamName": "Analytical Engines",
                "teamRole": "admin",
                "organizationId": "org-19c2",
                "organizationName": "Corp Example",
                "organizationRole": "member",
                "principalType": "Team",
                "principalId": "principal-51aa",
                "userBlockedReason": null,
                "teamBlockedReasons": ["BLOCKED_REASON_NO_LOGS"],
                "codingDataRetentionOptOut": true,
            }
        })
        .to_string();
        let info_withheld = r#"{"jsonrpc":"2.0","id":3,"result":{"methodId":"fuigo.com","teamRole":"admin","organizationRole":"member","principalType":"Team","userBlockedReason":null,"teamBlockedReasons":["BLOCKED_REASON_NO_LOGS"],"codingDataRetentionOptOut":true}}"#;
        // `fuigo/auth/logout` (`extensions/auth.rs`).
        let logout = json!({ "jsonrpc": "2.0", "id": 4, "result": { "ok": true, "was_logged_in": true, "email": "ada@corp.example", "api_key_still_set": false } }).to_string();
        let logout_withheld = r#"{"jsonrpc":"2.0","id":4,"result":{"ok":true,"was_logged_in":true,"api_key_still_set":false}}"#;
        vec![
            ("authenticate", authenticate.clone(), meta_removed(&authenticate)),
            ("check_subscription", check.clone(), meta_removed(&check)),
            ("info", info, info_withheld.to_owned()),
            ("logout", logout, logout_withheld.to_owned()),
        ]
    }
    /// P81 hostile: a relay that is not FluxRouter-operated does not learn who is signed in from the agent's auth
    /// responses; a FluxRouter relay receives them byte for byte. What the account may do (role, tier, gate,
    /// retention choice) is delivered either way.
    #[test]
    fn p81_relay_outbound_frame_withholds_the_account_from_a_non_fluxrouter_relay() {
        for (name, response, withheld) in p81_account_responses() {
            assert_ne!(response, withheld, "{name}: the fixture has the fields where the replace looks");
            assert!(P81_ACCOUNT_VALUES.iter().any(|value| response.contains(value)), "{name}: positive control");
            for url in P77_FLUXROUTER_RELAYS {
                assert_eq!(relay_outbound_frame(&p77_identity(url), response.clone()), response, "{name} {url}");
            }
            for url in P77_OTHER_RELAYS {
                let sent = relay_outbound_frame(&p77_identity(url), response.clone());
                assert_eq!(sent, withheld, "{name} {url}");
                for value in P81_ACCOUNT_VALUES {
                    assert!(!sent.contains(value), "{name} {url}: {value} in {sent}");
                }
                for key in RELAY_IDENTITY_KEYS {
                    assert!(!sent.contains(key), "{name} {url}: {key} in {sent}");
                }
            }
        }
        // Both metadata frames keep everything that is not who the account is.
        let (_, _, authenticate) = &p81_account_responses()[0];
        assert_eq!(
            authenticate,
            &format!(
                r#"{{"jsonrpc":"2.0","id":1,"result":{{"_meta":{{"auth_mode":"Oidc","is_zdr":false,"team_role":"admin","coding_data_retention_opt_out":{},"show_resolved_model":null,"gate":{{"message":"upgrade"}},"subscription_tier":"Pro","feedback_trace_offer":false}}}}}}"#,
                crate::auth::default_coding_data_retention_opt_out()
            )
        );
        // Each key is withheld on its own, whatever its value, and one removal hides no other: `_meta`, `meta`, the
        // session rows and the result's own fields in one response.
        for key in ACCOUNT_META_KEYS {
            for place in ["_meta", "meta"] {
                assert_eq!(
                    relay_outbound_frame(&p77_withheld(), format!(r#"{{"id":1,"result":{{"{place}":{{"a":1,"{key}":null,"b":2}}}}}}"#)),
                    format!(r#"{{"id":1,"result":{{"{place}":{{"a":1,"b":2}}}}}}"#),
                    "{place}.{key}"
                );
            }
        }
        for key in ACCOUNT_INFO_KEYS {
            assert_eq!(
                relay_outbound_frame(&p77_withheld(), format!(r#"{{"id":1,"result":{{"a":1,"{key}":7,"b":2}}}}"#)),
                r#"{"id":1,"result":{"a":1,"b":2}}"#,
                "{key}"
            );
        }
        assert_eq!(
            relay_outbound_frame(
                &p77_withheld(),
                r#"{"id":1,"result":{"_meta":{"hostname":"h","email":"e","a":1},"meta":{"team_id":"t","b":2},"result":{"sessions":[{"hostname":"h","c":3}]},"sessions":[{"hostname":"h","d":4}],"principalId":"p","e":5}}"#.to_string()
            ),
            r#"{"id":1,"result":{"_meta":{"a":1},"meta":{"b":2},"result":{"sessions":[{"c":3}]},"sessions":[{"d":4}],"e":5}}"#
        );
        // Not one of those places: untouched, byte for byte. The same key elsewhere is application data (a commit's
        // author, an enveloped extension result, a tool's output); camel-case keys are not read in the metadata and
        // snake-case keys are not read under the result; requests, notifications and errors are never rewritten.
        for untouched in [
            json!({ "jsonrpc": "2.0", "id": 2, "result": { "commit": { "author": { "name": "Ada", "email": "ada@corp.example" } } } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 2, "result": { "result": { "email": "ada@corp.example", "teamId": "team-7f3e", "meta": { "email": "x" }, "_meta": { "team_id": "t" } } } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 2, "result": { "_meta": { "teamId": "t", "firstName": "Ada", "principalId": "p" }, "meta": { "organizationId": "o" }, "team_id": "t", "team_name": "n" } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 2, "result": { "users": [{ "email": "ada@corp.example", "teamId": "t" }], "meta": [1], "_meta": "none" } }).to_string(),
            json!({ "jsonrpc": "2.0", "method": "session/update", "params": { "email": "ada@corp.example", "_meta": { "email": "ada@corp.example" } } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 5, "method": "fuigo/ask_user_question", "params": { "email": "x" }, "result": { "email": "y" } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 6, "error": { "code": -1, "message": "no", "data": { "email": "ada@corp.example" } } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 3, "result": { "text": "the \"email\" key", "role": "admin" } }).to_string(),
        ] {
            for url in P77_OTHER_RELAYS {
                assert_eq!(relay_outbound_frame(&p77_identity(url), untouched.clone()), untouched, "{url}");
            }
        }
        // Fails closed, for every key the writer can withhold: a frame that names one and is not a JSON object is not
        // sent to a relay that is not FluxRouter-operated (and is sent, untouched, to a FluxRouter one).
        for key in RELAY_IDENTITY_KEYS {
            for unreadable in [
                format!("not json {key}"),
                format!(r#"[{{"result":{{{key}:"v"}}}}]"#),
                format!(r#"{{"result":{{{key}:"v"}}"#),
            ] {
                assert_eq!(relay_outbound_frame(&p77_withheld(), unreadable.clone()), "", "{unreadable}");
                for url in P77_FLUXROUTER_RELAYS {
                    assert_eq!(relay_outbound_frame(&p77_identity(url), unreadable.clone()), unreadable, "{url}");
                }
            }
        }
        // The keys the writer looks for are exactly the ones it can withhold.
        let mut read: Vec<String> = ["hostname", "agentId"].into_iter().chain(ACCOUNT_META_KEYS).chain(ACCOUNT_INFO_KEYS).chain(ENVIRONMENT_OWNER_KEYS).map(|key| format!("\"{key}\"")).collect();
        read.sort();
        read.dedup();
        let mut looked_for: Vec<String> = RELAY_IDENTITY_KEYS.iter().map(|key| (*key).to_owned()).collect();
        looked_for.sort();
        assert_eq!(read, looked_for);
    }
    /// P81, through the real socket writer: the four auth responses, then the next frame, per relay operator.
    #[tokio::test]
    async fn p81_ws_session_writes_the_account_by_relay_operator() {
        let responses = p81_account_responses();
        let update = json!({ "jsonrpc": "2.0", "method": "session/update", "params": { "email": "x" } }).to_string();
        let mut frames: Vec<String> = responses.iter().map(|(_, response, _)| response.clone()).collect();
        frames.push(update.clone());
        let mut withheld: Vec<String> = responses.iter().map(|(_, _, withheld)| withheld.clone()).collect();
        withheld.push(update);
        for (url, want) in [
            ("wss://api.fluxrouter.ai/ws/relay", &frames),
            ("wss://relay.example/ws", &withheld),
            ("ws://api.fluxrouter.ai/ws/relay", &withheld),
        ] {
            let got = p81_relay_receives(&p81_relay_config(url).body_identity(), &frames).await;
            assert_eq!(&got, want, "{url}");
        }
    }
    // ===== P81 (Astra round 1): cloud-environment owners, value kinds, raw values, the writer after a dropped frame =====

    /// The cloud-environment responses, built from the REAL wire types exactly as `acp_agent.rs` builds them
    /// (`json!({ "environments": resp.environments })`, `json!({ "environment": resp.environment })`), with what a relay
    /// that is not FluxRouter-operated receives.
    fn p81_environment_responses() -> Vec<(&'static str, String, String)> {
        use crate::remote::{SandboxEnvironment, SandboxEnvironmentVariable, SandboxEnvironmentWithMetadata};
        let environment = |id: &str, owner: Option<&str>, team: Option<&str>| SandboxEnvironmentWithMetadata {
            environment: Some(SandboxEnvironment {
                environment_id: Some(id.to_owned()),
                user_id: owner.map(str::to_owned),
                team_id: team.map(str::to_owned),
                name: Some("build box".to_owned()),
                ..Default::default()
            }),
            environment_variables: vec![SandboxEnvironmentVariable { key: Some("CI".to_owned()), value: Some("1".to_owned()) }],
            secrets: Vec::new(),
            user_role: Some("OWNER".to_owned()),
        };
        let rows = vec![
            environment("env-1", Some("acct-7f3e"), Some("team-7f3e")),
            environment("env-2", Some("acct-7f3e"), None),
            SandboxEnvironmentWithMetadata { environment: None, ..environment("env-3", None, None) },
            environment("env-4", Some("acct-other"), Some("team-other")),
        ];
        let list = format!(r#"{{"jsonrpc":"2.0","id":7,"result":{}}}"#, json!({ "environments": rows }));
        let one = format!(r#"{{"jsonrpc":"2.0","id":8,"result":{}}}"#, json!({ "environment": rows[0] }));
        // P82 (stacked on this packet) also withholds the environments' scripts and variable values from such a relay.
        let withheld = |frame: &str| {
            frame
                .replace(r#""userId":"acct-7f3e","teamId":"team-7f3e","#, "")
                .replace(r#""userId":"acct-7f3e","teamId":null,"#, "")
                .replace(r#""userId":"acct-other","teamId":"team-other","#, "")
                .replace(r#""setupScript":null,"maintenanceScript":null,"#, "")
                .replace(r#"{"key":"CI","value":"1"}"#, r#"{"key":"CI"}"#)
        };
        vec![("list", list.clone(), withheld(&list)), ("create / update", one.clone(), withheld(&one))]
    }
    /// P81 hostile (Astra round 1, HIGH): the cloud-environment responses name the owning account and team; a relay
    /// that is not FluxRouter-operated does not receive those ids, in any row, and receives everything else.
    #[test]
    fn p81_relay_outbound_frame_withholds_environment_owners_from_a_non_fluxrouter_relay() {
        for (name, response, withheld) in p81_environment_responses() {
            let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
            let first = if name == "list" { &parsed["result"]["environments"][0] } else { &parsed["result"]["environment"] };
            assert_eq!(first["environment"]["userId"], "acct-7f3e", "{name}: positive control, the real path: {response}");
            assert_eq!(first["environment"]["teamId"], "team-7f3e", "{name}: {response}");
            assert_eq!(first["userRole"], "OWNER", "{name}: {response}");
            assert_ne!(response, withheld, "{name}: the fields are where the replace looks");
            for url in P77_FLUXROUTER_RELAYS {
                assert_eq!(relay_outbound_frame(&p77_identity(url), response.clone()), response, "{name} {url}");
            }
            for url in P77_OTHER_RELAYS {
                let sent = relay_outbound_frame(&p77_identity(url), response.clone());
                assert_eq!(sent, withheld, "{name} {url}");
                for gone in ["acct-7f3e", "team-7f3e", "acct-other", "team-other", "\"userId\"", "\"teamId\""] {
                    assert!(!sent.contains(gone), "{name} {url}: {gone} in {sent}");
                }
                for kept in ["env-1", "build box", "\"userRole\":\"OWNER\"", "\"environmentVariables\""] {
                    assert!(sent.contains(kept), "{name} {url}: {kept} missing from {sent}");
                }
            }
        }
        let (_, list, list_withheld) = &p81_environment_responses()[0];
        assert_eq!(list.matches("\"userId\"").count(), 3, "three rows name an owner (the third has no environment)");
        assert_eq!(list_withheld.matches("\"environmentId\"").count(), 3);
        // Each key on its own, in both places, whatever its value; and next to every other place in one response.
        for key in ENVIRONMENT_OWNER_KEYS {
            assert_eq!(
                relay_outbound_frame(&p77_withheld(), format!(r#"{{"id":1,"result":{{"environments":[{{"environment":{{"a":1,"{key}":null}},"b":2}},3]}}}}"#)),
                r#"{"id":1,"result":{"environments":[{"environment":{"a":1},"b":2},3]}}"#,
                "{key}"
            );
            assert_eq!(
                relay_outbound_frame(&p77_withheld(), format!(r#"{{"id":1,"result":{{"environment":{{"environment":{{"{key}":true,"a":1}},"b":2}}}}}}"#)),
                r#"{"id":1,"result":{"environment":{"environment":{"a":1},"b":2}}}"#,
                "{key}"
            );
        }
        assert_eq!(
            relay_outbound_frame(
                &p77_withheld(),
                r#"{"id":1,"result":{"_meta":{"email":"e","a":1},"environments":[{"environment":{"userId":"u","b":2}},{"environment":{"teamId":"t","c":3}}],"environment":{"environment":{"userId":"u","d":4}},"lastName":"n","e":5}}"#.to_string()
            ),
            r#"{"id":1,"result":{"_meta":{"a":1},"environments":[{"environment":{"b":2}},{"environment":{"c":3}}],"environment":{"environment":{"d":4}},"e":5}}"#
        );
        // Not those places: untouched. `userId` directly under the result, under a row, or under `environment` itself
        // is not a `SandboxEnvironment`'s owner; rows that are not objects and requests are left alone.
        for untouched in [
            json!({ "jsonrpc": "2.0", "id": 2, "result": { "userId": "u", "environments": [{ "userId": "u", "environment": [1] }, 3], "environment": { "userId": "u", "environment": "none" } } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 2, "result": { "environments": { "environment": { "userId": "u" } }, "environment": [{ "environment": { "userId": "u" } }] } }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 2, "result": { "result": { "environments": [{ "environment": { "userId": "u" } }], "environment": { "environment": { "userId": "u" } } } } }).to_string(),
            json!({ "jsonrpc": "2.0", "method": "session/update", "params": { "environment": { "environment": { "userId": "u" } } } }).to_string(),
        ] {
            assert_eq!(relay_outbound_frame(&p77_withheld(), untouched.clone()), untouched);
        }
    }
    /// P81 (Astra round 1): a withheld account field is withheld whatever JSON value it holds, and everything beside it
    /// is written back byte for byte (number spellings, escapes, inner whitespace, nesting deeper than a full parse
    /// allows).
    #[test]
    fn p81_account_fields_are_withheld_for_every_value_kind_and_nothing_else_is_reformatted() {
        for value in ["null", "7", "true", r#""s""#, r#"{"a":[1]}"#, "[1,2]", r#""\u00e9\"""#] {
            for key in ACCOUNT_META_KEYS {
                for place in ["_meta", "meta"] {
                    assert_eq!(
                        relay_outbound_frame(&p77_withheld(), format!(r#"{{"id":1,"result":{{"{place}":{{"a":1,"{key}":{value},"b":2}}}}}}"#)),
                        format!(r#"{{"id":1,"result":{{"{place}":{{"a":1,"b":2}}}}}}"#),
                        "{place}.{key} = {value}"
                    );
                }
            }
            for key in ACCOUNT_INFO_KEYS {
                assert_eq!(
                    relay_outbound_frame(&p77_withheld(), format!(r#"{{"id":1,"result":{{"a":1,"{key}":{value},"b":2}}}}"#)),
                    r#"{"id":1,"result":{"a":1,"b":2}}"#,
                    "{key} = {value}"
                );
            }
            for key in ENVIRONMENT_OWNER_KEYS {
                assert_eq!(
                    relay_outbound_frame(&p77_withheld(), format!(r#"{{"id":1,"result":{{"environment":{{"environment":{{"a":1,"{key}":{value}}}}}}}}}"#)),
                    r#"{"id":1,"result":{"environment":{"environment":{"a":1}}}}"#,
                    "{key} = {value}"
                );
            }
        }
        let deep = format!("{}0{}", "[".repeat(200), "]".repeat(200));
        let frame = |account: &str| {
            format!(
                r#"{{"jsonrpc":"2.0","id":1.0e0,"result":{{"methodId":"m\u00e9",{account}"teamRole":"a\"b","n":1.50,"w":[ 1 , 2 ],"deep":{deep},"meta":{{"x":2.0,"y":{deep}}},"environment":{{"k":[ 3 ],"environment":{{"z":1e2}}}}}},"z":18446744073709551616}}"#
            )
        };
        let sent = relay_outbound_frame(&p77_withheld(), frame(r#""email":"ada@corp.example","principalId":"p","#));
        assert!(serde_json::from_str::<serde_json::Value>(&sent).is_err(), "positive control: too deep for a full parse");
        assert_eq!(sent, frame(""), "only the two account fields are gone");
    }
    /// P81 (Astra round 1): the writer keeps writing after a frame it did not send (fail closed is per frame).
    #[tokio::test]
    async fn p81_ws_session_keeps_writing_after_a_frame_it_withheld() {
        let unreadable = r#"[{"result":{"email":"ada@corp.example"}}]"#.to_string();
        let update = json!({ "jsonrpc": "2.0", "method": "session/update", "params": { "n": 1 } }).to_string();
        let response = json!({ "jsonrpc": "2.0", "id": 4, "result": { "ok": true, "email": "ada@corp.example" } }).to_string();
        let frames = [unreadable.clone(), update.clone(), unreadable.clone(), response.clone()];
        let other = p81_relay_config("wss://relay.example/ws").body_identity();
        assert_eq!(
            p81_relay_receives_n(&other, &frames, 2).await,
            [update.clone(), r#"{"jsonrpc":"2.0","id":4,"result":{"ok":true}}"#.to_string()]
        );
        let fluxrouter = p81_relay_config("wss://api.fluxrouter.ai/ws/relay").body_identity();
        assert_eq!(p81_relay_receives_n(&fluxrouter, &frames, 4).await, frames);
    }
    /// P81 (Astra round 1): a machine id that JSON has to escape (a configured `FUIGO_AGENT_ID`) is recognised by its
    /// value, not by its spelling on the wire.
    #[test]
    fn p81_a_machine_id_that_needs_json_escapes_is_still_replaced() {
        fn escaped_machine_id() -> String {
            "rack\"one\\é".to_owned()
        }
        let identity = RelayBodyIdentity::for_relay("wss://relay.example/ws", escaped_machine_id);
        let key = fuigo_extra_ca::fluxrouter::destination_pseudonym("wss://relay.example/ws", &escaped_machine_id());
        for spelling in [r#""rack\"one\\é""#, r#""rack\u0022one\u005c\u00e9""#] {
            assert_eq!(
                relay_outbound_frame(&identity, format!(r#"{{"id":0,"result":{{"_meta":{{"agentId":{spelling},"a":1}}}}}}"#)),
                format!(r#"{{"id":0,"result":{{"_meta":{{"agentId":"{key}","a":1}}}}}}"#),
                "{spelling}"
            );
        }
        assert_eq!(p81_withheld_initialize_response("wss://relay.example/ws", &escaped_machine_id()), relay_outbound_frame(&identity, p81_initialize_response(&escaped_machine_id())));
    }
    /// P81 (Astra round 2): three combinations no other fixture has. An `agentId` that is NOT the machine id stays as
    /// it is even when the same `_meta` loses another field; the account is withheld from a `_meta` whose machine id
    /// was replaced; and the values kept in an environment that lost its owner are written back byte for byte.
    #[test]
    fn p81_combinations_of_a_machine_id_an_account_and_an_environment_in_one_response() {
        let relay = "wss://relay.example/ws";
        let key = fuigo_extra_ca::fluxrouter::destination_pseudonym(relay, P81_MACHINE_ID);
        // A session-scoped id beside a host name and an account: only those two go.
        assert_eq!(
            relay_outbound_frame(&p77_identity(relay), r#"{"id":1,"result":{"_meta":{"agentId":"tui-sess-1","hostname":"h","email":"e","a":1}}}"#.to_string()),
            r#"{"id":1,"result":{"_meta":{"agentId":"tui-sess-1","a":1}}}"#
        );
        assert_eq!(
            relay_outbound_frame(&p77_identity(relay), r#"{"id":1,"result":{"_meta":{"agentId":"tui-sess-1","a":1},"email":"e"}}"#.to_string()),
            r#"{"id":1,"result":{"_meta":{"agentId":"tui-sess-1","a":1}}}"#
        );
        // The machine id beside an account, without a host name: replaced, and the account goes.
        assert_eq!(
            relay_outbound_frame(&p77_identity(relay), format!(r#"{{"id":1,"result":{{"_meta":{{"agentId":"{P81_MACHINE_ID}","email":"e","team_id":"t","team_name":"n","a":1}}}}}}"#)),
            format!(r#"{{"id":1,"result":{{"_meta":{{"agentId":"{key}","a":1}}}}}}"#)
        );
        // An environment that loses its owner keeps every other value as it was written: number spellings, escapes,
        // inner whitespace and nesting deeper than a full parse allows, in the single environment and in every row.
        let deep = format!("{}0{}", "[".repeat(200), "]".repeat(200));
        let environment = |owner: &str| {
            format!(r#"{{"k":[ 3 ],"environment":{{"n":1.50,{owner}"w":[ 1 , 2 ],"s":"m\u00e9\"x","deep":{deep},"z":1e2}},"userRole":"OWNER"}}"#)
        };
        let frame = |owner: &str| {
            format!(
                r#"{{"jsonrpc":"2.0","id":2,"result":{{"environments":[{},7,{}],"environment":{},"x":2.0}}}}"#,
                environment(owner),
                environment(owner),
                environment(owner)
            )
        };
        let sent = relay_outbound_frame(&p77_identity(relay), frame(r#""userId":"acct-7f3e","teamId":"team-7f3e","#));
        assert!(serde_json::from_str::<serde_json::Value>(&sent).is_err(), "positive control: too deep for a full parse");
        assert_eq!(sent, frame(""), "only the owner ids are gone, three times");
    }
}

#[cfg(test)]
mod p70a_relay_proxy_log {
    /// P70a (Astra r4, r5): the relay's proxy resolution (the function `run_relay_loop` calls, with the proxy lookup
    /// injected) logs the proxy host, never the password in its userinfo, and returns the URL unchanged for the
    /// connection.
    #[test]
    fn relay_proxy_log_redacts_proxy_credentials() {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        struct Capture(std::sync::Arc<std::sync::Mutex<String>>);
        struct Render<'a>(&'a mut String);
        impl tracing::field::Visit for Render<'_> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!(" {}={value:?}", field.name()));
            }
        }
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
            fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
                let mut line = String::new();
                event.record(&mut Render(&mut line));
                self.0.lock().unwrap().push_str(&line);
            }
        }
        let logs = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let _guard = tracing_subscriber::registry().with(Capture(logs.clone())).set_default();
        const PROXY: &str = "http://alice:p70px-FAKE-6c7d8e9f@proxy.p70.invalid:3128";
        let mut asked = None;
        let used = super::relay_proxy_for("wss://relay.p70.invalid/ws", |host| {
            asked = Some(host.to_owned());
            Some(PROXY.to_owned())
        });
        assert_eq!(asked.as_deref(), Some("relay.p70.invalid"), "control: the proxy was looked up for the relay host");
        assert_eq!(used.as_deref(), Some(PROXY), "the connection still uses the configured proxy URL");
        let logged = logs.lock().unwrap().clone();
        assert!(logged.contains("proxy.p70.invalid") && logged.contains("CONNECT proxy"), "control: {logged}");
        assert!(!logged.contains("p70px-FAKE") && !logged.contains("alice"), "the proxy credentials were logged: {logged}");
    }
}
