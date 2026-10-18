use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
/// The release the currently running leader process belongs to.
///
/// Registration compares it against each client's `ClientCapabilities::client_version` to catch mismatches early.
/// A mismatch produces a structured ACP notification.
/// It is the same value every client sends (`fuigo_version::VERSION`) and the leader registers as its binary version.
/// P151 (F17): it was `option_env!("VERSION_WITH_COMMIT")`, which only the pager binary's own build script sets, so in
/// fuigo-shell it was always "unknown" and the notice was never sent.
const LEADER_VERSION: &str = fuigo_version::VERSION;
use super::protocol::{
    ClientCapabilities, ClientId, ClientMessage, ClientMode, ControlCommand, ControlPayload,
    FrameReader, InternalMethod, LEADER_PROTOCOL_VERSION, LeaderCapabilities, ProtocolError,
    ServerMessage, internal_notification, write_message,
};
use super::transport::LeaderStream;
use crate::agent::activity::AgentActivity;
use crate::auth::AuthManager;
use crate::cpu_profile::{
    ControlError, ControlErrorCode, CpuProfileManager, CpuProfileStartOptions, CpuProfileStatus,
    ShutdownStopDisposition,
};
use agent_client_protocol::AGENT_METHOD_NAMES;
use fuigo_computer_hub_sdk::{AuthCredential, AuthIdentity, AuthProvider};
use fuigo_workspace::WorkspaceHandle;
use parking_lot::Mutex;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};
const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(30);
/// Separator for namespacing request IDs.
/// The pipe is valid in JSON strings (no escaping needed) and unlikely to appear in typical JSON-RPC IDs (usually numbers or UUIDs).
const ID_NAMESPACE_SEP: char = '|';
/// Cap on live notifications buffered per in-flight `session/load` (see `load_live_buffer`).
/// A normal load resolves in well under a second, so the buffer is tiny; this bound prevents unbounded growth if a load stalls.
/// On overflow we stop buffering and forward live normally.
/// Correctness of the transcript is preserved by the client's eventId dedup; only the ordering nicety is lost in this degenerate case.
const MAX_BUFFERED_LIVE_PER_LOAD: usize = 4096;
enum ServerEvent {
    Disconnected(ClientId),
    Registered(ClientId, ClientMode, ClientCapabilities, String),
    Message(ClientId, ClientMessage),
}
enum LeaderServerPoll {
    Cancelled,
    Accept(std::io::Result<LeaderStream>),
    Event(ServerEvent),
    Response(String),
    /// P125: the leader's relay refusal changed (`LeaderServerControlState::publish_relay_refusal`).
    RelayRefusalChanged,
    /// P142: this process recorded a one-off user notice (`fuigo_file_utils::destination_gate::subscribe_notices`).
    NoticeRecorded,
    /// The ownership board has something to act on (a grace window or relay lease ended, or the relay dropped).
    OwnerBoardWake,
}
/// A live notification buffered during an in-flight `session/load`: the shared payload plus its `event_seq`.
/// The `event_seq` is computed at buffer time, when the message is already parsed, so the post-load flush never re-parses.
type BufferedLive = (Arc<str>, Option<u64>);
/// Message queued to a client handler task.
///
/// ACP payloads are by far the hot path (every chunk of every session fans out to every subscriber), so they travel as a shared `Arc<str>`.
/// The routing loop pays one refcount bump per recipient instead of a full `String` clone.
/// The live-load buffer and the interaction cache share the same allocation.
/// The handler serializes the wire envelope via [`ServerMessageRef`] without ever building an owned `ServerMessage::Acp`.
#[derive(Debug, Clone)]
enum ClientOutbound {
    /// An ACP payload, shared (refcounted) across fan-out targets.
    Acp(Arc<str>),
    /// Everything else (registration, control results, ping, shutdown, errors).
    Message(ServerMessage),
}
impl From<ServerMessage> for ClientOutbound {
    fn from(msg: ServerMessage) -> Self {
        Self::Message(msg)
    }
}
/// Serialize-only mirror of [`ServerMessage`]'s `Acp` variant that borrows the payload.
/// It lets the per-client writer frame a shared `Arc<str>` without copying it into an owned `ServerMessage`.
/// It must stay wire-identical to `ServerMessage::Acp`; the `server_message_ref_is_wire_identical` test asserts that.
#[derive(serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMessageRef<'a> {
    Acp { payload: &'a str },
}
/// Write one [`ClientOutbound`] to a client connection.
async fn write_outbound<W>(writer: &mut W, msg: &ClientOutbound) -> Result<(), ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    match msg {
        ClientOutbound::Acp(payload) => {
            write_message(writer, &ServerMessageRef::Acp { payload }).await
        }
        ClientOutbound::Message(m) => write_message(writer, m).await,
    }
}
struct ClientState {
    tx: mpsc::UnboundedSender<ClientOutbound>,
    mode: ClientMode,
    capabilities: ClientCapabilities,
    /// The client type string from IPC registration (e.g., "fuigo-tui", "fuigo-code-extension").
    /// Injected into `initialize` requests as `clientIdentifier` so the agent knows the real client type when several clients share one leader.
    client_type: String,
    /// Set to `true` once the client's `initialize` request has been seen and had `clientIdentifier` injected.
    /// Until `initialize` is observed, each ACP message is checked so we never miss a late `initialize`.
    /// After it is seen once, we skip the per-message parse as an optimisation.
    initialize_seen: bool,
    /// The client's own (un-namespaced) JSON-RPC id of its `initialize` request, while the response still needs `modelState.currentModelId` patched to `default_model`.
    /// Set when the `initialize` is forwarded; cleared only by the response carrying that same id, so an unrelated earlier response cannot consume it.
    patch_initialize_request_id: Option<serde_json::Value>,
    /// Whether this client has completed IPC registration.
    /// Only registered clients are counted in `client_count`.
    /// Pre-registration connections (which may time out) must not inflate the count and block auto-updates.
    registered: bool,
    /// P148 (B19): the `startupHints` this client sent on its own `initialize`. The agent keeps only the first
    /// client's `initialize`, so they are carried onto this client's session requests that name none.
    init_startup_hints: Option<serde_json::Value>,
}
#[derive(Debug, Clone)]
pub struct LeaderServerMetadata {
    pub pid: u32,
    pub socket_path: PathBuf,
    pub lock_path: PathBuf,
    pub ws_url_suffix: String,
    pub leader_binary_version: String,
}
#[derive(Debug, Clone)]
pub struct LeaderServerControlState {
    pub metadata: LeaderServerMetadata,
    pub cpu_profile: Arc<Mutex<CpuProfileManager>>,
    pub workspace: Arc<WorkspaceControl>,
    /// P125: the `fuigo/relay/refused` notification line for the relay the leader refused (a relay FluxRouter does
    /// not operate that no opt-in names), or `None` while it has none. The IPC server tells every interactive client
    /// that registers, and every one already attached when it changes, so a TUI user sees the refusal.
    relay_refusal: RelayRefusalBoard,
    /// Who owns each session (see [`super::drivers`]): the one authority for owner-gated session changes; shared with the relay path.
    pub(crate) driver_board: super::drivers::OwnerBoard,
}
impl LeaderServerControlState {
    pub fn new(metadata: LeaderServerMetadata) -> Self {
        let driver_board = super::drivers::OwnerBoard::default();
        Self {
            metadata,
            cpu_profile: Arc::new(Mutex::new(CpuProfileManager::new())),
            workspace: Arc::new(WorkspaceControl::new(None)),
            relay_refusal: RelayRefusalBoard::detached().with_owner_board(driver_board.clone()),
            driver_board,
        }
    }
    /// The ownership board the relay path stamps its verdicts from.
    pub(crate) fn driver_board(&self) -> super::drivers::OwnerBoard {
        self.driver_board.clone()
    }
    /// How long a session whose owner disconnected waits for that owner's reconnect token.
    #[cfg(test)]
    pub(crate) fn with_driver_grace(self, grace: Duration) -> Self {
        self.driver_board.set_grace(grace);
        self
    }
    /// P125: a handle that publishes the leader's relay refusal (what the relay start decides with).
    pub(crate) fn relay_refusal_board(&self) -> RelayRefusalBoard {
        self.relay_refusal.clone()
    }
    pub(crate) fn with_default_hub_url(mut self, default_hub_url: Option<String>) -> Self {
        self.workspace = Arc::new(WorkspaceControl::new(default_hub_url));
        self
    }
    fn leader_capabilities(&self) -> LeaderCapabilities {
        let manager = self.cpu_profile.lock();
        LeaderCapabilities {
            control_v1: true,
            runtime_cpu_profile: manager.runtime_cpu_profile(),
            profile_formats: manager.profile_formats().to_vec(),
            workspace_exposure: true,
            relaunch_v1: true,
            downgrade_stop_v1: true,
        }
    }
}
/// P125: where the leader's relay start publishes whether it refused the relay
/// ([`LeaderServerControlState::publish_relay_refusal`]).
#[derive(Clone, Debug)]
pub struct RelayRefusalBoard {
    refusal: Arc<tokio::sync::watch::Sender<Option<Arc<str>>>>,
    /// The leader's ownership board, so the relay start can tell it when the relay's socket drops.
    owners: Option<super::drivers::OwnerBoard>,
}
impl RelayRefusalBoard {
    /// A board nobody listens to.
    pub fn detached() -> Self {
        Self { refusal: Arc::new(tokio::sync::watch::channel(None).0), owners: None }
    }
    pub(crate) fn with_owner_board(mut self, owners: super::drivers::OwnerBoard) -> Self {
        self.owners = Some(owners);
        self
    }
    /// The leader's ownership board, when this board belongs to a leader.
    pub(crate) fn owner_board(&self) -> Option<super::drivers::OwnerBoard> {
        self.owners.clone()
    }
    /// Publish (or, with `None`, clear) the refusal line; the same line again tells nobody again.
    pub fn publish(&self, payload: Option<String>) {
        self.refusal.send_if_modified(|current| {
            let next: Option<Arc<str>> = payload.map(Arc::from);
            if *current == next {
                return false;
            }
            *current = next;
            true
        });
    }
    /// The refusal line published now, if any.
    pub fn current(&self) -> Option<Arc<str>> {
        self.refusal.borrow().clone()
    }
    fn subscribe(&self) -> tokio::sync::watch::Receiver<Option<Arc<str>>> {
        self.refusal.subscribe()
    }
}
pub struct WorkspaceControl {
    default_hub_url: Option<String>,
    /// Hub credential, wired to the leader's `AuthManager` once auth is ready.
    /// A `watch` so a starting leader (socket up, auth pending) can be awaited instead of failing the command.
    auth: tokio::sync::watch::Sender<Option<Arc<dyn AuthProvider>>>,
    /// Serializes mutating commands (start/pause/resume/stop) so their long awaits (drain, reconnect) never interleave.
    lock: tokio::sync::Mutex<()>,
    /// Current exposure, published for lock-free reads so `status` never blocks behind an in-flight drain/reconnect.
    exposure: arc_swap::ArcSwapOption<WorkspaceExposure>,
    /// P47: the manager behind `auth`, so the hub credential can be classified by value (static API key or session).
    auth_manager: Mutex<Option<Arc<AuthManager>>>,
}
impl WorkspaceControl {
    fn new(default_hub_url: Option<String>) -> Self {
        Self {
            default_hub_url,
            auth: tokio::sync::watch::channel(None).0,
            lock: tokio::sync::Mutex::new(()),
            exposure: arc_swap::ArcSwapOption::empty(),
            auth_manager: Mutex::new(None),
        }
    }
    /// Wire the hub credential to the leader's shared `AuthManager` (sole owner of refresh and persistence).
    pub(crate) fn set_auth_manager(&self, auth_manager: Arc<AuthManager>) {
        *self.auth_manager.lock() = Some(auth_manager.clone());
        self.auth.send_replace(Some(Arc::new(LeaderAuthProvider {
            auth_manager,
            refresh_in_flight: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })));
    }
}
impl std::fmt::Debug for WorkspaceControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkspaceControl")
            .field("default_hub_url", &self.default_hub_url)
            .finish_non_exhaustive()
    }
}
/// Hub [`AuthProvider`] backed by the leader's `AuthManager`: returns the current token at each connect/reconnect; never writes auth.json.
struct LeaderAuthProvider {
    auth_manager: Arc<AuthManager>,
    /// One background refresh at a time.
    /// `current()` is called by a reconnect loop that can spin fast while offline.
    /// A `refresh_lock` would serialize those tasks but not collapse them.
    /// Each queued one would still issue its own IdP call once the previous released.
    refresh_in_flight: Arc<std::sync::atomic::AtomicBool>,
}
impl std::fmt::Debug for LeaderAuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaderAuthProvider").finish_non_exhaustive()
    }
}
impl AuthProvider for LeaderAuthProvider {
    fn current(&self) -> AuthCredential {
        use std::sync::atomic::Ordering;
        let cached = self.auth_manager.current();
        if cached.is_none()
            && self.auth_manager.is_expired()
            && self
                .refresh_in_flight
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            struct ClaimGuard(Arc<std::sync::atomic::AtomicBool>);
            impl Drop for ClaimGuard {
                fn drop(&mut self) {
                    self.0.store(false, std::sync::atomic::Ordering::Release);
                }
            }
            let guard = ClaimGuard(Arc::clone(&self.refresh_in_flight));
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let am = Arc::clone(&self.auth_manager);
                handle.spawn(async move {
                    let _guard = guard;
                    if let Err(e) = am.auth().await {
                        tracing::debug!(error = %e, "leader hub auth: background refresh failed");
                    }
                });
            }
        }
        let token = cached
            .or_else(|| self.auth_manager.current_or_expired())
            .map(|a| a.key)
            .unwrap_or_default();
        AuthCredential::bearer(token)
    }
    /// Owner identity from the leader's `AuthManager`.
    /// The workspace derives `WorkspaceIdentity` from this provider instead of a separate auth.json read.
    /// Mirrors the in-process path (`mvp_agent`).
    /// Prefer `FuigoAuth.team_id` (what shell telemetry/snapshot use) mapped onto a `"Team"` principal so team attribution is derived.
    /// Otherwise pass principal fields through.
    /// `None` when no credential is available (identity resolution never blocks).
    fn identity(&self) -> Option<AuthIdentity> {
        let a = self.auth_manager.current_or_expired()?;
        Some(match a.team_id.filter(|t| !t.is_empty()) {
            Some(team) => AuthIdentity {
                user_id: a.user_id,
                principal_type: Some("Team".to_string()),
                principal_id: Some(team),
            },
            None => AuthIdentity {
                user_id: a.user_id,
                principal_type: a.principal_type,
                principal_id: a.principal_id,
            },
        })
    }
}
/// P47: the hub credential, decided by value against the hub URL before every socket the hub SDK opens.
struct HubDestinationGuard {
    inner: Arc<dyn AuthProvider>,
    auth_manager: Option<Arc<AuthManager>>,
    configured_hub: Option<String>,
}
impl HubDestinationGuard {
    fn check(
        &self,
        hub_url: &url::Url,
        credential: &AuthCredential,
    ) -> Result<(), fuigo_extra_ca::service_trust::RefusedServiceDestination> {
        let AuthCredential::Bearer { token, .. } = credential else {
            return Ok(());
        };
        if token.is_empty()
            || self.auth_manager.as_deref().is_some_and(|am| {
                crate::auth::session_delivery::is_held_static_key(am, token)
            })
        {
            return Ok(());
        }
        crate::auth::session_delivery::service_session_url_gate(
            hub_url.as_str(),
            self.configured_hub.as_deref(),
            "leader_workspace_hub",
        )
    }
}
impl std::fmt::Debug for HubDestinationGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HubDestinationGuard").finish_non_exhaustive()
    }
}
impl AuthProvider for HubDestinationGuard {
    fn current(&self) -> AuthCredential {
        self.inner.current()
    }
    fn principal_key(&self) -> fuigo_computer_hub_sdk::PrincipalKey {
        self.inner.principal_key()
    }
    fn identity(&self) -> Option<AuthIdentity> {
        self.inner.identity()
    }
    fn destination_permits(&self, url: &url::Url, credential: &AuthCredential) -> Result<(), String> {
        self.check(url, credential).map_err(|refused| refused.to_string())
    }
}
struct WorkspaceExposure {
    handle: WorkspaceHandle,
    hub_url: String,
    cwd: PathBuf,
    started_at: Instant,
    paused: std::sync::atomic::AtomicBool,
}
/// Rewrite JSON-RPC request ID **in place** by prefixing with client ID to avoid collisions.
///
/// Only rewrites IDs for **requests** (messages with a "method" field).
/// Responses (messages with "result" or "error" but no "method") are left untouched so the agent can match them to its pending requests.
///
/// Returns `Some((namespaced_id, original_id))` when the message is a request carrying an ID (and `json` was mutated).
/// Returns `None` otherwise (no mutation).
/// The returned `namespaced_id` lets the caller key per-request state (e.g. `pending_load_by_req`) without re-parsing the rewritten payload.
fn rewrite_request_id(
    json: &mut serde_json::Value,
    client_id: ClientId,
) -> Option<(String, serde_json::Value)> {
    json.get("method")?;
    let original_id = json.get("id").cloned()?;
    let original_json = serde_json::to_string(&original_id).unwrap_or_default();
    let namespaced_id = format!("{}{}{}", client_id.0, ID_NAMESPACE_SEP, original_json);
    json["id"] = serde_json::json!(namespaced_id);
    Some((namespaced_id, original_id))
}
/// Parse a namespaced response ID to find the target client, restoring the original ID **in place**.
///
/// Expects format: "client_id|original_id_json" where original_id_json is the JSON-serialized form of the original ID (preserving type information).
///
/// Returns `Some((client_id, namespaced_id))` if successful (`json` now carries the restored original ID).
/// The returned `namespaced_id` is the raw pre-restore ID.
/// It lets the caller match per-request state (e.g. `pending_load_by_req`) without re-parsing the original payload.
/// On `None`, `json` is untouched.
fn parse_response_id(json: &mut serde_json::Value) -> Option<(ClientId, String)> {
    let id = json.get("id")?;
    let id_str = id.as_str()?;
    let (client_part, original_json) = id_str.split_once(ID_NAMESPACE_SEP)?;
    let client_id: u64 = client_part.parse().ok()?;
    let original_id: serde_json::Value = serde_json::from_str(original_json).ok()?;
    let namespaced_id = id_str.to_string();
    json["id"] = original_id;
    Some((ClientId(client_id), namespaced_id))
}
/// Extract session_id from a message's params (for session-based routing).
fn extract_session_id(json: &serde_json::Value) -> Option<String> {
    let params = json.get("params")?;
    params
        .get("sessionId")
        .or_else(|| params.get("session_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            params
                .get("params")
                .and_then(|inner| inner.get("sessionId").or_else(|| inner.get("session_id")))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
}
/// Whether a payload attaches an existing session (`session/load` or `session/resume`).
/// Both need live-broadcast buffering until the response (see `load_live_buffer`) and the pending-modal replay keyed on it.
fn is_session_attach_request(json: &serde_json::Value) -> bool {
    json.get("method")
        .and_then(|m| m.as_str())
        .is_some_and(|m| m == "session/load" || m == "session/resume")
}
/// Extract the leader unicast target `ClientId` from a notification's `params._meta["fuigo/leaderClientId"]`.
///
/// The agent stamps this onto every `session/load` replay notification, echoing the id the leader injected into the load request.
/// The replay then routes back to ONLY the loading client instead of broadcasting to all subscribers.
/// Live (non-replay) turn deltas are never tagged, so they keep broadcasting.
fn extract_target_client_id(json: &serde_json::Value) -> Option<ClientId> {
    let params = json.get("params")?;
    params
        .get("_meta")
        .and_then(|m| m.get("fuigo/leaderClientId"))
        .or_else(|| {
            params
                .get("params")
                .and_then(|inner| inner.get("_meta"))
                .and_then(|m| m.get("fuigo/leaderClientId"))
        })
        .and_then(|v| v.as_u64())
        .map(ClientId)
}
/// Extract the monotonic `event_seq` counter from a notification's `_meta.eventId` (format `"{sessionId}-{counter}"`).
/// Mirrors the `_meta` lookup in [`extract_target_client_id`], which also checks the ExtNotification `params.params` nesting.
/// The suffix parse matches `session::storage` and the client's `acp::meta`.
/// Returns `None` for notifications without an `eventId` (Ferrox Labs one-shots / older shell).
fn event_seq_of(json: &serde_json::Value) -> Option<u64> {
    let params = json.get("params")?;
    let event_id = params
        .get("_meta")
        .and_then(|m| m.get("eventId"))
        .or_else(|| {
            params
                .get("params")
                .and_then(|inner| inner.get("_meta"))
                .and_then(|m| m.get("eventId"))
        })
        .and_then(|v| v.as_str())?;
    event_id.rsplit_once('-')?.1.parse::<u64>().ok()
}
/// Whether a payload is a machine-wide notification (no `sessionId`) that must be **broadcast to every client**.
/// These never fall through to the last-active-client fallback:
///
/// - `fuigo/sessions/changed`: the session roster changed; every open dashboard must stay in sync.
/// - `fuigo/models/update`: the model catalog changed.
///   (Triggers: config.toml `[model.*]`/`[models]` hot-reload, a `models_cache.json` external write, an auth change, a response-header etag refresh.)
///   Every connected client's model picker must refresh, not just the most recently active one.
/// - `fuigo/mcp/servers_updated`: the MCP catalog resolved or changed (managed connectors fetched in the background after `initialize`).
///   It is deliberately session-agnostic on the wire (no `sessionId`, see `extensions::mcp::notify_servers_updated`).
///   The push fires seconds after `initialize` returns.
///   The last-active-client fallback routinely delivered it to the wrong client (or dropped it) in multi-client leaders.
///   Managed connectors then "disappeared" from every other client's `/mcp` view.
///   Broadcast is safe: the pager handler only debounce-refetches `mcp/list` for agents with an open extensions modal.
/// - `fuigo/announcements/update`: the announcements list changed (startup one-shot or the periodic settings refresh).
///   It is session-agnostic; every client renders its own banner, so last-active-client fallback would leave every other client's banner stale.
///   Broadcast is safe: the pager handler is idempotent and drops stale generations via its `gen` gate.
///   (`fuigo/settings/update` stays non-broadcast: it carries auth/gate state.)
///
/// Matched via [`method_of`], NOT the raw top-level `method`.
/// Agent ext notifications arrive `_`-prefixed on the wire (`_fuigo/sessions/changed`), so a raw compare would miss the production form.
fn is_machine_wide_broadcast_notification(json: &serde_json::Value) -> bool {
    matches!(
        method_of(json),
        Some(
            "fuigo/sessions/changed"
                | "fuigo/models/update"
                | "fuigo/mcp/servers_updated"
                | "fuigo/announcements/update"
        )
    )
}
/// The namespaced method a leader payload carries, normalizing the two ext wire forms the gateway produces:
///   - direct:  `{"method":"fuigo/foo", ...}`                                 -> `fuigo/foo`
///   - wrapped: `{"method":"_fuigo/foo","params":{"method":"fuigo/foo",...}}`  -> `fuigo/foo`
///
/// Gateway-forwarded ext methods/notifications (`ext_method` / `ext_notification`) arrive WRAPPED.
/// Examples: `ask_user_question`, `exit_plan_mode`, `scheduled_task_inject_prompt`, `session_notification`.
/// A wrapped payload has a top-level `_`-prefixed method with the real method and params nested one level under `params`.
/// Plain methods (`session/request_permission`, `session/update`, …) arrive direct.
/// Anything that classifies a payload by method name MUST use this: matching the raw top-level `method` misses the wrapped form.
/// See `interaction_inner_params` for the matching params accessor.
fn method_of(json: &serde_json::Value) -> Option<&str> {
    let top = json.get("method")?.as_str()?;
    if let Some(stripped) = top.strip_prefix('_') {
        return Some(
            json.get("params")
                .and_then(|p| p.get("method"))
                .and_then(|m| m.as_str())
                .unwrap_or(stripped),
        );
    }
    Some(top)
}
/// The real params object for a payload, unwrapping the gateway ext wrapper.
/// For a wrapped ext (its `params` carries its own `method` and nested `params`) the real params live at `params.params`.
/// Otherwise `params` is already real.
fn interaction_inner_params(json: &serde_json::Value) -> Option<&serde_json::Value> {
    let params = json.get("params")?;
    if params.get("method").is_some()
        && let Some(inner) = params.get("params")
    {
        Some(inner)
    } else {
        Some(params)
    }
}
/// Whether a payload is the `fuigo/scheduled_task_inject_prompt` notification.
///
/// This notification tells the receiving client to enqueue AND drive a scheduled (`/loop`) cron prompt.
/// Ordinary `sessionId`-bearing notifications fan out to every subscriber so each renders an identical stream.
/// This one must be routed to the SINGLE session driver.
/// If every attached client received it, each would enqueue and try to drive the same cron turn.
/// That duplicates the turn (phantom `#N` queue entries, competing drivers, stuck turns).
/// The other clients render the resulting turn from the broadcast `session/update` deltas, exactly like any other turn the driver runs.
fn is_scheduled_task_inject_prompt(json: &serde_json::Value) -> bool {
    method_of(json) == Some("fuigo/scheduled_task_inject_prompt")
}
/// Whether a payload is a blocking *interaction* reverse-request: a tool permission, `ask_user_question`, plan-approval
/// (`exit_plan_mode`) or an MCP elicitation.
/// Like every reverse-request it decides something for the session, so it is delivered to the session's OWNER only and
/// only the owner's answer counts (1.0.30: it used to be shared with every attached window, first answer wins, so a
/// window in always-approve could approve the owner's tool calls). With no owner (grace window, nobody yet) it waits for
/// the next owner. Unlike other reverse-requests the leader also caches it by `tool_call_id`, so an owner that (re)loads
/// the session or is promoted to owner gets the still-pending modal again.
fn is_interaction_request(json: &serde_json::Value) -> bool {
    matches!(
        method_of(json),
        Some(
            "session/request_permission"
                | "fuigo/ask_user_question"
                | "fuigo/exit_plan_mode"
                | "fuigo/mcp/elicit",
        )
    )
}
/// Extract the `tool_call_id` an interaction reverse-request carries.
/// The leader caches it (keyed by id) for replay-on-attach and evicts it on `InteractionResolved`.
/// The ext-methods (`ask_user_question` / `exit_plan_mode`) carry it directly under (inner) `params`; `request_permission` nests it under `toolCall`.
/// Tolerant of the gateway wrapper (via `interaction_inner_params`) and camel/snake spelling.
fn extract_interaction_tool_call_id(json: &serde_json::Value) -> Option<String> {
    let params = interaction_inner_params(json)?;
    if let Some(id) = params
        .get("toolCallId")
        .or_else(|| params.get("tool_call_id"))
        .and_then(|v| v.as_str())
    {
        return Some(id.to_string());
    }
    let tc = params.get("toolCall").or_else(|| params.get("tool_call"))?;
    tc.get("toolCallId")
        .or_else(|| tc.get("tool_call_id"))
        .or_else(|| tc.get("id"))
        .and_then(|v| v.as_str())
        .map(String::from)
}
/// If a payload is the `InteractionResolved` broadcast, return its `tool_call_id`.
/// That broadcast is an `fuigo/session_notification` whose `update.sessionUpdate == "interaction_resolved"`.
/// The leader evicts the cached interaction request with it (first-answer-wins).
/// Tolerant of the gateway wrapper and camel/snake spelling for the inner field.
fn extract_interaction_resolved_tool_call_id(json: &serde_json::Value) -> Option<String> {
    if method_of(json) != Some("fuigo/session_notification") {
        return None;
    }
    let update = interaction_inner_params(json)?.get("update")?;
    if update.get("sessionUpdate").and_then(|v| v.as_str()) != Some("interaction_resolved") {
        return None;
    }
    update
        .get("tool_call_id")
        .or_else(|| update.get("toolCallId"))
        .and_then(|v| v.as_str())
        .map(String::from)
}
/// Extract session_id from a prompt-complete notification.
fn extract_session_id_from_prompt_complete(json: &serde_json::Value) -> Option<String> {
    let method = json.get("method")?.as_str()?;
    if method != "fuigo/session/prompt_complete" {
        return None;
    }
    json.get("params")?
        .get("sessionId")
        .or_else(|| json.get("params")?.get("session_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}
/// Extract session_id from a response's result (for session/new and session/load responses).
/// This is used to track session ownership when the session is first created.
fn extract_session_id_from_result(json: &serde_json::Value) -> Option<String> {
    let result = json.get("result")?;
    result
        .get("session_id")
        .or_else(|| result.get("sessionId"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}
/// P130: most unsubscribed-session relay notices held at once (oldest dropped first).
const MAX_PENDING_RELAY_NOTICES: usize = 64;

/// P130: is this a session-scoped `fuigo/relay/refused` or `fuigo/relay/refusal_cleared` extension notification?
fn is_relay_refusal_notice(json: &serde_json::Value) -> bool {
    json.get("id").is_none()
        && json.get("method").and_then(|m| m.as_str()).is_some_and(|m| {
            let m = m.strip_prefix('_').unwrap_or(m);
            m == crate::agent::relay_opt_in::RELAY_REFUSED_METHOD
                || m == crate::agent::relay_opt_in::RELAY_REFUSAL_CLEARED_METHOD
        })
}

/// P130: hold a relay refusal notice for a session nobody is subscribed to yet. The agent emits it while handling
/// `session/new`, before the response that tells the leader which client owns the session; it is delivered to that
/// client when it subscribes (see [`take_pending_relay_notices`]).
fn hold_relay_notice(pending: &mut Vec<(String, Arc<str>)>, session_id: &str, payload: Arc<str>) {
    pending.push((session_id.to_string(), payload));
    if pending.len() > MAX_PENDING_RELAY_NOTICES {
        pending.remove(0);
    }
}

/// P130: take (in arrival order) the relay notices held for `session_id`.
fn take_pending_relay_notices(
    pending: &mut Vec<(String, Arc<str>)>,
    session_id: &str,
) -> Vec<Arc<str>> {
    let mut taken = Vec::new();
    pending.retain(|(sid, payload)| {
        if sid == session_id {
            taken.push(payload.clone());
            false
        } else {
            true
        }
    });
    taken
}

#[derive(Debug)]
enum ChildSessionEvent {
    Spawned(String),
    Finished(String),
}
/// Extract child session spawn/finish events from subagent notifications.
fn extract_child_session_event(json: &serde_json::Value) -> Option<ChildSessionEvent> {
    let params = json.get("params")?;
    let update = params
        .get("update")
        .or_else(|| params.get("params")?.get("update"))?;
    let child_sid = update.get("child_session_id").and_then(|v| v.as_str())?;
    match update.get("sessionUpdate")?.as_str()? {
        "subagent_spawned" => Some(ChildSessionEvent::Spawned(child_sid.to_string())),
        "subagent_finished" => Some(ChildSessionEvent::Finished(child_sid.to_string())),
        _ => None,
    }
}
/// Drop a finished child's route and driver and detach it from the child forest.
/// Still-live grandchildren are RE-PARENTED onto the finished child's own parent.
/// Re-parenting (not cascade-prune) keeps a still-running grandchild of a finished intermediate reachable from the root.
/// `backfill_child_routes` only follows forward edges.
/// A subtree left dangling under the removed child would never be reached on a root `session/load`.
/// A genuinely-dead leaf (no surviving children) is removed.
///
/// The current parent is found by searching the forest, not taken from the finish notification's sessionId.
/// That way a grandchild already re-parented by an earlier intermediate finish is still detached from its correct edge.
fn prune_child_route(
    child_sid: &str,
    session_subscribers: &mut HashMap<String, HashSet<ClientId>>,
    session_driver: &mut HashMap<String, ClientId>,
    child_sessions: &mut HashMap<String, HashSet<String>>,
) {
    session_subscribers.remove(child_sid);
    session_driver.remove(child_sid);
    let parent = child_sessions
        .iter()
        .find_map(|(p, kids)| kids.contains(child_sid).then(|| p.clone()));
    if let Some(ref parent) = parent
        && let Some(kids) = child_sessions.get_mut(parent)
    {
        kids.remove(child_sid);
    }
    if let Some(grandchildren) = child_sessions.remove(child_sid)
        && let Some(ref parent) = parent
    {
        child_sessions
            .entry(parent.clone())
            .or_default()
            .extend(grandchildren);
    }
    if let Some(parent) = parent
        && child_sessions.get(&parent).is_some_and(HashSet::is_empty)
    {
        child_sessions.remove(&parent);
    }
}
/// Subscribe `client` to every live descendant of `parent`, walking the parent-to-children index (depth-safe via a visited set).
/// Driverless descendants get the parent's driver.
/// Child routes are otherwise spawn-time snapshots.
/// Without this, a client that attaches to the parent AFTER a subagent spawned (late attach, reconnect) never receives the child's live updates.
fn backfill_child_routes(
    parent: &str,
    client: ClientId,
    child_sessions: &HashMap<String, HashSet<String>>,
    session_subscribers: &mut HashMap<String, HashSet<ClientId>>,
    session_driver: &mut HashMap<String, ClientId>,
) {
    let parent_driver = session_driver.get(parent).copied();
    let mut stack: Vec<&str> = vec![parent];
    let mut visited: HashSet<&str> = HashSet::new();
    while let Some(sid) = stack.pop() {
        let Some(children) = child_sessions.get(sid) else {
            continue;
        };
        for child in children {
            if !visited.insert(child.as_str()) {
                continue;
            }
            session_subscribers
                .entry(child.clone())
                .or_default()
                .insert(client);
            if let Some(driver) = parent_driver {
                session_driver.entry(child.clone()).or_insert(driver);
            }
            stack.push(child);
        }
    }
}
/// Inject the requesting client's context into a `session/new`, `session/load`, or `session/resume` request, **in place**.
/// The agent's own state names whichever client initialized last, which in leader mode is the wrong client.
///
/// For a session/new request:
/// - If the client has yolo_mode enabled, injects `yoloMode: true` into the request's `_meta` object.
/// - If the client has default_model set and the request doesn't already have a modelId, injects `modelId` into the request's `_meta` object.
/// - Injects `clientIdentifier` so the agent can track which client owns each session (scopes `yolo_mode_changed` broadcasts in leader mode).
///
/// Returns `true` when `json` was mutated.
fn inject_session_request_context(
    json: &mut serde_json::Value,
    capabilities: &ClientCapabilities,
    client_type: &str,
    client_id: ClientId,
) -> bool {
    let has_model = capabilities
        .default_model
        .as_ref()
        .is_some_and(|m| !m.is_empty());
    if !capabilities.yolo_mode
        && !capabilities.auto_mode
        && !has_model
        && client_type.is_empty()
        && !capabilities.code_nav_enabled
        && !capabilities.terminal
        && !capabilities.fs_read
        && !capabilities.fs_write
        && !capabilities.status_line
        && !capabilities.user_message_echo
    {
        return false;
    }
    let method = json.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let is_session_new = method == AGENT_METHOD_NAMES.session_new;
    let is_session_load = method == AGENT_METHOD_NAMES.session_load;
    let is_session_resume = method == AGENT_METHOD_NAMES.session_resume;
    if !is_session_new && !is_session_load && !is_session_resume {
        return false;
    }
    let mut mutated = false;
    if let Some(params) = json.get_mut("params").and_then(|p| p.as_object_mut()) {
        let meta = params
            .entry("_meta")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(meta_obj) = meta.as_object_mut() {
            mutated = true;
            if is_session_new && capabilities.yolo_mode && !meta_obj.contains_key("yoloMode") {
                meta_obj.insert("yoloMode".to_string(), serde_json::json!(true));
                debug!("Injected yoloMode=true into session/new request");
            }
            if capabilities.auto_mode
                && !capabilities.yolo_mode
                && !meta_obj.contains_key("autoMode")
            {
                meta_obj.insert("autoMode".to_string(), serde_json::json!(true));
                debug!("Injected autoMode=true into session request");
            }
            if is_session_new
                && let Some(ref model_id) = capabilities.default_model
                && !model_id.is_empty()
                && !meta_obj.contains_key("modelId")
            {
                meta_obj.insert("modelId".to_string(), serde_json::json!(model_id));
                debug!(model_id, "Injected modelId into session/new request");
            }
            if !client_type.is_empty() && !meta_obj.contains_key("clientIdentifier") {
                meta_obj.insert(
                    "clientIdentifier".to_string(),
                    serde_json::json!(client_type),
                );
            }
            if !meta_obj.contains_key("fuigo/leaderClientId") {
                meta_obj.insert(
                    "fuigo/leaderClientId".to_string(),
                    serde_json::json!(client_id.0),
                );
            }
            meta_obj.insert(
                "codeNavEnabled".to_string(),
                serde_json::json!(capabilities.code_nav_enabled),
            );
            debug!(
                code_nav_enabled = capabilities.code_nav_enabled,
                "Injected codeNavEnabled into session request"
            );
            meta_obj.insert(
                "clientTerminal".to_string(),
                serde_json::json!(capabilities.terminal),
            );
            meta_obj.insert(
                "clientFsRead".to_string(),
                serde_json::json!(capabilities.fs_read),
            );
            meta_obj.insert(
                "clientFsWrite".to_string(),
                serde_json::json!(capabilities.fs_write),
            );
            meta_obj.insert(
                fuigo_status_line::CLIENT_STATUS_LINE_META.to_string(),
                serde_json::json!(capabilities.status_line),
            );
            if capabilities.user_message_echo {
                meta_obj.insert(
                    crate::session::CLIENT_USER_MESSAGE_ECHO_META.to_string(),
                    serde_json::json!(true),
                );
            }
        }
    }
    mutated
}
/// The `_meta.startupHints` object of an `initialize` request, if `json` is one that carries it.
fn initialize_startup_hints(json: &serde_json::Value) -> Option<serde_json::Value> {
    if json.get("method").and_then(|m| m.as_str()) != Some(AGENT_METHOD_NAMES.initialize) {
        return None;
    }
    json.pointer("/params/_meta/startupHints")
        .filter(|hints| hints.is_object())
        .cloned()
}
/// P148 (B19): carry the requesting client's own `initialize` `startupHints` onto its `session/new`, `session/load` or
/// `session/resume` that names none. The agent keeps only the first `initialize` it saw, so on a shared leader a later
/// client's initialize-only hints (an app that embeds Fuigo non-interactively) would otherwise be replaced by the first
/// client's: its sessions would run interactive policy (a 30-minute `ask_user_question` wait, progressive MCP init).
/// Hints the request carries itself are kept. Returns `true` when `json` was mutated.
fn inject_client_startup_hints(json: &mut serde_json::Value, hints: Option<&serde_json::Value>) -> bool {
    let Some(hints) = hints else {
        return false;
    };
    let method = json.get("method").and_then(|m| m.as_str()).unwrap_or("");
    if method != AGENT_METHOD_NAMES.session_new
        && method != AGENT_METHOD_NAMES.session_load
        && method != AGENT_METHOD_NAMES.session_resume
    {
        return false;
    }
    let Some(params) = json.get_mut("params").and_then(|p| p.as_object_mut()) else {
        return false;
    };
    let Some(meta) = params
        .entry("_meta")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
    else {
        return false;
    };
    if meta.contains_key("startupHints") {
        return false;
    }
    meta.insert("startupHints".to_string(), hints.clone());
    true
}
/// Inject client identity into an `initialize` request.
///
/// In leader mode, multiple clients (TUI, IDE extension, web) share one agent process.
/// The agent's `client_type` is set during `initialize` from `_meta.clientIdentifier`.
/// The leader injects the IPC registration `client_type` so the agent knows the real client identity.
///
/// Only injects if `clientIdentifier` is not already present in `_meta`, respecting explicit client-provided values.
///
/// Mutates `json` in place. Returns `(mutated, was_initialize)`.
/// The second boolean is `true` only when the message was an `initialize` request, allowing the caller to record that `initialize` has been seen.
fn inject_client_identity_into_initialize(
    json: &mut serde_json::Value,
    client_type: &str,
) -> (bool, bool) {
    if client_type.is_empty() {
        return (false, false);
    }
    let is_initialize = json
        .get("method")
        .and_then(|m| m.as_str())
        .is_some_and(|m| m == AGENT_METHOD_NAMES.initialize);
    if !is_initialize {
        return (false, false);
    }
    let mut mutated = false;
    if let Some(params) = json.get_mut("params").and_then(|p| p.as_object_mut()) {
        let meta = params
            .entry("_meta")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(meta_obj) = meta.as_object_mut()
            && !meta_obj.contains_key("clientIdentifier")
        {
            meta_obj.insert(
                "clientIdentifier".to_string(),
                serde_json::json!(client_type),
            );
            mutated = true;
            debug!(
                client_type,
                "Injected clientIdentifier into initialize request"
            );
        }
    }
    (mutated, true)
}
/// True when the TOP-LEVEL `method` is the yolo-mode notification, in either wire form.
/// The protocol crate prefixes every client ext notification with one `_` on the wire (`_fuigo/yolo_mode_changed`), then the agent strips that one `_` and dispatches on the result.
/// So exactly `fuigo/yolo_mode_changed` and `_fuigo/yolo_mode_changed` match; `__fuigo/...` does not (the agent would see `_fuigo/...`).
/// This deliberately does NOT use `method_of`: it prefers the client-controlled `params.method`, which the agent never looks at.
fn is_yolo_mode_notification(json: &serde_json::Value) -> bool {
    json.get("method")
        .and_then(|m| m.as_str())
        .is_some_and(|m| m.strip_prefix('_').unwrap_or(m) == "fuigo/yolo_mode_changed")
}
/// Remove any client-supplied connection id from `params` and `params._meta` of an inbound client message, whatever its method.
/// Only the leader may write `fuigo/leaderConnectionId`.
fn strip_client_supplied_connection_id(json: &mut serde_json::Value) -> bool {
    let Some(params) = json.get_mut("params").and_then(|p| p.as_object_mut()) else {
        return false;
    };
    let key = crate::leader::protocol::LEADER_CONNECTION_ID_KEY;
    let mut mutated = params.remove(key).is_some();
    if let Some(meta) = params.get_mut("_meta").and_then(|m| m.as_object_mut()) {
        mutated |= meta.remove(key).is_some();
    }
    mutated
}
/// Extract yolo_mode change from fuigo/yolo_mode_changed notification.
fn extract_yolo_mode_change(json: &serde_json::Value) -> Option<bool> {
    if !is_yolo_mode_notification(json) {
        return None;
    }
    let params = json.get("params")?;
    params.get("yolo_mode").and_then(|v| v.as_bool())
}
/// Extract the auto-mode intent from an `fuigo/yolo_mode_changed` notification.
/// The leader keeps `ClientCapabilities.auto_mode` fresh the same way it tracks `yolo_mode`.
/// Without this, a stale connect-time `auto_mode` capability would be injected into later `session/new` requests.
/// That would re-enable Auto after the user opted out.
/// Returns `None` when the notification doesn't change auto state.
fn extract_auto_mode_change(json: &serde_json::Value) -> Option<bool> {
    if !is_yolo_mode_notification(json) {
        return None;
    }
    let params = json.get("params")?;
    if let Some(b) = params.get("auto_mode").and_then(|v| v.as_bool()) {
        return Some(b);
    }
    match params.get("permission_mode").and_then(|v| v.as_str()) {
        Some("auto") => Some(true),
        Some("always-approve" | "ask" | "default") => Some(false),
        _ => None,
    }
}
/// Stamp the leader-minted connection id onto a `yolo_mode_changed` notification's params.
///
/// In leader mode, multiple clients share one agent.
/// The agent scopes the toggle to sessions OWNED BY THE SENDING CONNECTION (the id the leader assigned when it accepted the socket).
/// `clientIdentifier` (the self-declared product string) is not an authority: any same-user process can claim it.
/// So every client-supplied `clientIdentifier` and connection id (in params and in `params._meta`) is stripped first, then the leader's own values are stamped.
/// `clientIdentifier` is stamped only when the registration `client_type` is non-empty.
///
/// Mutates `json` in place; returns `true` when mutated.
fn inject_client_identity_into_yolo_notification(
    json: &mut serde_json::Value,
    client_type: &str,
    client_id: ClientId,
) -> bool {
    if !is_yolo_mode_notification(json) {
        return false;
    }
    let Some(params) = json.get_mut("params").and_then(|p| p.as_object_mut()) else {
        return false;
    };
    params.remove("clientIdentifier");
    params.remove(crate::leader::protocol::LEADER_CONNECTION_ID_KEY);
    if let Some(meta) = params.get_mut("_meta").and_then(|m| m.as_object_mut()) {
        meta.remove("clientIdentifier");
        meta.remove(crate::leader::protocol::LEADER_CONNECTION_ID_KEY);
    }
    if !client_type.is_empty() {
        params.insert(
            "clientIdentifier".to_string(),
            serde_json::json!(client_type),
        );
    }
    params.insert(
        crate::leader::protocol::LEADER_CONNECTION_ID_KEY.to_string(),
        serde_json::json!(client_id.0),
    );
    debug!(
        client_type,
        client_id = client_id.0,
        "Stamped connection identity into yolo_mode_changed notification"
    );
    true
}
/// Everything the leader does to the identity fields of an inbound client message: strip any client-supplied connection id (every method), stamp session requests, and strip + stamp the yolo notification.
pub(crate) fn stamp_inbound_client_identity(
    json: &mut serde_json::Value,
    client_type: &str,
    client_id: ClientId,
) -> bool {
    let mut mutated = strip_client_supplied_connection_id(json);
    mutated |= stamp_connection_id_into_session_request(json, client_id);
    mutated |= stamp_connection_id_into_session_change(json, client_id);
    mutated |= inject_client_identity_into_yolo_notification(json, client_type, client_id);
    mutated
}
/// Connection id the leader reserves for messages arriving over the relay (remote clients). Client ids count up from a small number, so this never collides with one.
pub(crate) const RELAY_CONNECTION_ID: u64 = u64::MAX;
/// Sanitise one relay-delivered JSON-RPC line before the agent sees it: relay messages never pass through a leader client slot, so they get the same treatment.
/// Any client-supplied `fuigo/leaderConnectionId` / `clientIdentifier` is stripped, then `RELAY_CONNECTION_ID` is stamped so the relay client owns the sessions it creates or loads and can change only those.
/// Unparseable lines are returned unchanged (the agent rejects them itself).
pub(crate) fn stamp_relay_connection_identity(line: &str) -> String {
    stamp_relay_connection_identity_with(line, &super::drivers::OwnerBoard::default())
}
/// As [`stamp_relay_connection_identity`], with the relay as a first-class owner on `board`:
/// * a relay `session/load`/`resume` of a session somebody else owns (a live local client, or a departed owner within its
///   reconnect grace) gets the foreign-driver flag; any flag or reconnect token the remote sent is removed first (the
///   relay holds no token);
/// * a relay load of a session nobody else owns makes the relay its owner; every other relay message for a session the
///   relay owns refreshes its lease, and never creates a claim;
/// * every owner-gated request carries the leader's ownership verdict for the relay (see [`stamp_owner_authority`]).
pub(crate) fn stamp_relay_connection_identity_with(
    line: &str,
    board: &super::drivers::OwnerBoard,
) -> String {
    use super::drivers::{Claimer, Verdict};
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(line) else {
        return line.to_string();
    };
    let mut changed = false;
    let mut visit = |json: &mut serde_json::Value| {
        changed |= strip_client_supplied_connection_id(json);
        if take_reconnect_token(json).is_some() {
            changed = true;
        }
        if stamp_connection_id_into_session_request(json, ClientId(RELAY_CONNECTION_ID)) {
            // The replay-unicast target is a leader client slot; a relay has none.
            if let Some(meta) = json
                .get_mut("params")
                .and_then(|p| p.get_mut("_meta"))
                .and_then(|m| m.as_object_mut())
            {
                meta.remove("fuigo/leaderClientId");
            }
            changed = true;
        }
        changed |= stamp_connection_id_into_session_change(json, ClientId(RELAY_CONNECTION_ID));
        changed |= inject_client_identity_into_yolo_notification(
            json,
            "",
            ClientId(RELAY_CONNECTION_ID),
        );
        let session_id = extract_session_id(json);
        if is_session_attach_request(json) {
            let foreign = session_id
                .as_deref()
                .is_some_and(|sid| board.classify(sid, Claimer::Relay, None) == Verdict::Foreign);
            changed |= stamp_foreign_driver_flag(json, foreign);
            if foreign {
                warn!("relay session load of a session another connection owns: flagged foreign");
            } else if let Some(sid) = session_id.as_deref() {
                let claim = board.claim(sid, Claimer::Relay);
                if let Some(id) = json.get("id").filter(|id| !id.is_null()) {
                    // A failed load gives the claim back, as a local one does.
                    board.note_relay_load(&id.to_string(), sid, claim.prev);
                }
            }
        } else if let Some(sid) = session_id.as_deref() {
            board.relay_message(sid);
            if json.get("method").and_then(|m| m.as_str()) == Some("session/prompt")
                && let Some(id) = json.get("id").filter(|id| !id.is_null())
            {
                board.relay_prompt_started(&id.to_string(), sid);
            }
        }
        // The relay's answer to one of the agent's requests (a response has an id and no method).
        if json.get("method").is_none()
            && let Some(id) = json.get("id").filter(|id| !id.is_null())
        {
            board.relay_answered(&id.to_string());
        }
        changed |= stamp_owner_authority(json, super::drivers::Claimer::Relay, board);
    };
    match &mut value {
        serde_json::Value::Array(items) => items.iter_mut().for_each(&mut visit),
        other => visit(other),
    }
    if changed {
        serde_json::to_string(&value).unwrap_or_else(|_| line.to_string())
    } else {
        line.to_string()
    }
}
/// Methods whose effect on a session only its owner may cause (`strict`: an unowned session is refused too).
const OWNER_ONLY_TYPED: [&str; 3] = ["session/set_mode", "session/set_model", "session/set_config_option"];
const OWNER_ONLY_EXT: [&str; 2] = ["fuigo/toggle_plan_mode", crate::leader::protocol::SESSION_OWNER_CHECK_METHOD];
/// Methods anybody may send for a session, carrying the leader's verdict so the agent can tell the owner's apart: a prompt
/// is never refused, but only the owner's may declare the session's mode (`_meta.mode`, which enters or leaves plan mode).
const OWNER_VERDICT_TYPED: [&str; 1] = ["session/prompt"];
/// Admin methods the owner may call, and anybody may call when the session has no owner (`session/close` is typed).
const OWNER_OR_UNOWNED_TYPED: [&str; 1] = ["session/close"];
const OWNER_OR_UNOWNED_EXT: [&str; 6] = [
    "fuigo/session/rename",
    "fuigo/session/delete",
    "fuigo/session/update_mcp_servers",
    "fuigo/session/close",
    "fuigo/session/park",
    "fuigo/session/unpark",
];
/// Remove every ownership key a client may have written, from `params` and `params._meta`, whatever the method.
/// Only the leader writes them.
fn strip_client_supplied_authority(json: &mut serde_json::Value) -> bool {
    use crate::leader::protocol::{LEADER_FOREIGN_SESSIONS_KEY, LEADER_OWNED_SESSIONS_KEY, LEADER_OWNER_STATE_KEY};
    let Some(params) = json.get_mut("params").and_then(|p| p.as_object_mut()) else {
        return false;
    };
    let mut mutated = false;
    for key in [LEADER_OWNER_STATE_KEY, LEADER_OWNED_SESSIONS_KEY, LEADER_FOREIGN_SESSIONS_KEY] {
        mutated |= params.remove(key).is_some();
        if let Some(meta) = params.get_mut("_meta").and_then(|m| m.as_object_mut()) {
            mutated |= meta.remove(key).is_some();
        }
    }
    mutated
}
/// The leader's ownership decision, stamped on the owner-gated requests of `who`. The leader is the only authority on who
/// owns a session ([`super::drivers::OwnerBoard`]); the agent keeps no copy and trusts only what is stamped here:
/// * `session/set_mode`, `set_model`, `set_config_option`, `fuigo/toggle_plan_mode`, `fuigo/session/owner_check`, the
///   session admin methods and `session/close`: `fuigo/leaderOwnerState` = `self` / `other` / `none` (typed requests in `_meta`, extensions in `params`);
/// * `session/prompt`: the same verdict in `_meta` (a prompt is never refused; only the owner's may declare the mode);
/// * `fuigo/yolo_mode_changed`: `fuigo/leaderOwnedSessions`, the sessions `who` owns;
/// * `fuigo/permissions/reset`: `fuigo/leaderForeignSessions`, the sessions somebody else owns.
/// Every client-supplied value of those keys is removed first, on every method. Returns `true` when `json` was mutated.
pub(crate) fn stamp_owner_authority(
    json: &mut serde_json::Value,
    who: super::drivers::Claimer,
    board: &super::drivers::OwnerBoard,
) -> bool {
    use crate::leader::protocol::{LEADER_FOREIGN_SESSIONS_KEY, LEADER_OWNED_SESSIONS_KEY, LEADER_OWNER_STATE_KEY};
    let mut mutated = strip_client_supplied_authority(json);
    let method = json.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
    // Typed ACP methods arrive bare; the protocol crate prefixes client extension methods with one `_`.
    let ext_name = method.strip_prefix('_').unwrap_or(&method);
    let typed_strict = OWNER_ONLY_TYPED.contains(&method.as_str());
    let typed_lenient = OWNER_OR_UNOWNED_TYPED.contains(&method.as_str());
    let typed_verdict = OWNER_VERDICT_TYPED.contains(&method.as_str());
    let ext_strict = OWNER_ONLY_EXT.contains(&ext_name);
    let ext_lenient = OWNER_OR_UNOWNED_EXT.contains(&ext_name);
    let session_scoped = typed_strict || typed_lenient || typed_verdict || ext_strict || ext_lenient;
    let owned_list = ext_name == "fuigo/yolo_mode_changed";
    let foreign_list = ext_name == "fuigo/permissions/reset";
    if !(session_scoped || owned_list || foreign_list) {
        return mutated;
    }
    if (owned_list || foreign_list) && !json.get("params").is_some_and(|p| p.is_object()) {
        json["params"] = serde_json::json!({});
        mutated = true;
    }
    let state = if session_scoped {
        let sid = extract_session_id(json);
        // A request that names no session cannot be shown to be the owner's: fail closed.
        let state = sid
            .as_deref()
            .map(|sid| board.owner_state(sid, who))
            .unwrap_or(super::drivers::OwnerState::Other);
        Some(state)
    } else {
        None
    };
    let Some(params) = json.get_mut("params").and_then(|p| p.as_object_mut()) else {
        return mutated;
    };
    if let Some(state) = state {
        if typed_strict || typed_lenient || typed_verdict {
            let meta = params.entry("_meta").or_insert_with(|| serde_json::json!({}));
            if !meta.is_object() {
                *meta = serde_json::json!({});
            }
            if let Some(meta) = meta.as_object_mut() {
                meta.insert(LEADER_OWNER_STATE_KEY.to_string(), serde_json::json!(state.wire()));
                mutated = true;
            }
        } else {
            params.insert(LEADER_OWNER_STATE_KEY.to_string(), serde_json::json!(state.wire()));
            mutated = true;
        }
    }
    if owned_list {
        params.insert(LEADER_OWNED_SESSIONS_KEY.to_string(), serde_json::json!(board.owned_sessions(who)));
        mutated = true;
    }
    if foreign_list {
        params.insert(LEADER_FOREIGN_SESSIONS_KEY.to_string(), serde_json::json!(board.foreign_owned_sessions(who)));
        mutated = true;
    }
    mutated
}
/// Stamp the leader-minted connection id into a `session/new`, `session/load` or `session/resume` request's `_meta`, **in place**.
/// The agent records it as the session's owner: a load or resume by another connection makes that connection the owner (it is the one now driving the session).
/// Any client-supplied value is overwritten, so a client cannot claim ownership as another connection.
/// Returns `true` when `json` was mutated.
fn stamp_connection_id_into_session_request(
    json: &mut serde_json::Value,
    client_id: ClientId,
) -> bool {
    let method = json.get("method").and_then(|m| m.as_str()).unwrap_or("");
    if method != AGENT_METHOD_NAMES.session_new
        && method != AGENT_METHOD_NAMES.session_load
        && method != AGENT_METHOD_NAMES.session_resume
    {
        return false;
    }
    let Some(params) = json.get_mut("params").and_then(|p| p.as_object_mut()) else {
        return false;
    };
    let meta = params
        .entry("_meta")
        .or_insert_with(|| serde_json::json!({}));
    let Some(meta_obj) = meta.as_object_mut() else {
        return false;
    };
    meta_obj.insert(
        crate::leader::protocol::LEADER_CONNECTION_ID_KEY.to_string(),
        serde_json::json!(client_id.0),
    );
    // `fuigo/leaderClientId` is the replay-unicast target. No flow routes one connection's replay to another (a
    // reconnecting client is a new connection with a new id), so a client-supplied value is always overwritten.
    meta_obj.insert(
        "fuigo/leaderClientId".to_string(),
        serde_json::json!(client_id.0),
    );
    true
}
/// Take the client-supplied reconnect token out of a `session/load`/`session/resume` request (params and `_meta`), returning it.
/// A token is only ever read from an attach request; on any other method it is just removed.
fn take_reconnect_token(json: &mut serde_json::Value) -> Option<String> {
    let key = crate::leader::protocol::LEADER_RECONNECT_TOKEN_KEY;
    let params = json.get_mut("params")?.as_object_mut()?;
    let from_params = params.remove(key);
    let from_meta = params
        .get_mut("_meta")
        .and_then(|m| m.as_object_mut())
        .and_then(|m| m.remove(key));
    from_meta.or(from_params).and_then(|v| v.as_str().map(str::to_owned))
}
/// Stamp the leader-minted connection id into a `session/set_mode`, `session/set_model` or `session/set_config_option`
/// request's `_meta`, in place, overwriting any client-supplied value. The agent lets only the session's owner connection
/// change its mode, model or config. Returns `true` when `json` was mutated.
fn stamp_connection_id_into_session_change(json: &mut serde_json::Value, client_id: ClientId) -> bool {
    let method = json.get("method").and_then(|m| m.as_str()).unwrap_or("");
    if method != AGENT_METHOD_NAMES.session_set_mode
        && method != AGENT_METHOD_NAMES.session_set_model
        && method != AGENT_METHOD_NAMES.session_set_config_option
    {
        return false;
    }
    let Some(params) = json.get_mut("params").and_then(|p| p.as_object_mut()) else {
        return false;
    };
    let meta = params.entry("_meta").or_insert_with(|| serde_json::json!({}));
    let Some(meta_obj) = meta.as_object_mut() else {
        return false;
    };
    meta_obj.insert(
        crate::leader::protocol::LEADER_CONNECTION_ID_KEY.to_string(),
        serde_json::json!(client_id.0),
    );
    true
}
/// Stamp (or strip) the foreign-driver flag on a `session/load`/`session/resume` request; any client-supplied value is removed first.
fn stamp_foreign_driver_flag(json: &mut serde_json::Value, foreign_driver_live: bool) -> bool {
    if !is_session_attach_request(json) {
        return false;
    }
    let key = crate::leader::protocol::LEADER_FOREIGN_DRIVER_KEY;
    let Some(params) = json.get_mut("params").and_then(|p| p.as_object_mut()) else {
        return false;
    };
    let mut mutated = false;
    if let Some(meta) = params.get_mut("_meta").and_then(|m| m.as_object_mut()) {
        mutated |= meta.remove(key).is_some();
        if foreign_driver_live {
            meta.insert(key.to_string(), serde_json::json!(true));
            mutated = true;
        }
    } else if foreign_driver_live {
        params.insert("_meta".to_string(), serde_json::json!({ key: true }));
        mutated = true;
    }
    mutated
}
/// Build a JSON-RPC error response for requests that arrive before the leader is ready.
///
/// Returns `Some(payload)` when the message has an `id` field (i.e. is a request).
/// The client then gets a structured response it can act on instead of hanging.
/// Returns `None` for notifications (no `id`); those are silently dropped.
fn make_leader_starting_error(json: &serde_json::Value) -> Option<String> {
    let id = json.get("id").filter(|v| !v.is_null()).cloned()?;
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32002,
            "message": "leader_starting",
            "data": "Leader is still initializing (auth in progress). Retry shortly."
        }
    });
    Some(response.to_string())
}
/// Choose the bytes forwarded to the agent: the re-serialized `json` when an injection/rewrite mutated it, the original `payload` otherwise.
/// Non-JSON payloads are never parsed or re-serialized.
fn select_outbound_payload(
    json: Option<&serde_json::Value>,
    payload_mutated: bool,
    payload: String,
) -> String {
    match json {
        Some(j) if payload_mutated => j.to_string(),
        _ => payload,
    }
}
/// Patch the `initialize` response so `_meta.modelState.currentModelId` reflects the client's `default_model`.
/// It would otherwise reflect the agent's global `current_model_id`.
///
/// Without this the TUI briefly shows the agent's startup default.
/// It then jumps to the client's preferred model once the first `session/new` response arrives.
///
/// Mutates `json` in place; returns `true` when patched.
fn patch_initialize_response_model(
    json: &mut serde_json::Value,
    default_model: &Option<String>,
) -> bool {
    let Some(model) = default_model.as_ref().filter(|m| !m.is_empty()) else {
        return false;
    };
    // Only switch to a model the agent actually advertises. An unavailable preference would leave the client with a current id absent from its catalog (session/new falls back to the agent default in that case).
    let available = json
        .pointer("/result/_meta/modelState/availableModels")
        .and_then(|v| v.as_array())
        .is_some_and(|models| {
            models
                .iter()
                .any(|m| m.get("modelId").and_then(|v| v.as_str()) == Some(model.as_str()))
        });
    let needs_patch = available
        && json
            .pointer("/result/_meta/modelState/currentModelId")
            .and_then(|v| v.as_str())
            .is_some_and(|current| current != model.as_str());
    if needs_patch {
        json["result"]["_meta"]["modelState"]["currentModelId"] =
            serde_json::Value::String(model.clone());
        debug!(patched_model = %model, "Patched initialize response currentModelId");
        return true;
    }
    false
}
/// Disarm the pending `initialize` patch when `response` answers that exact request.
/// `response["id"]` must already be restored to the client's original id (see `parse_response_id`).
/// Returns `true` once, for the matching response; any other response leaves the patch armed.
fn take_initialize_patch_if_matches(
    pending: &mut Option<serde_json::Value>,
    response: &serde_json::Value,
) -> bool {
    if pending.as_ref().is_some_and(|id| response.get("id") == Some(id)) {
        *pending = None;
        return true;
    }
    false
}
/// Extract model ID from a `session/setModel` request (for keeping `default_model` in sync).
fn extract_model_id_from_set_model(json: &serde_json::Value) -> Option<String> {
    let method = json.get("method")?.as_str()?;
    if method != AGENT_METHOD_NAMES.session_set_model {
        return None;
    }
    let params = json.get("params")?;
    params
        .get("modelId")
        .or_else(|| params.get("model_id"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}
/// A request whose response decides who owns a session.
struct DriverReq {
    client: ClientId,
    kind: DriverReqKind,
}
enum DriverReqKind {
    New,
    /// `foreign`: the leader flagged the load because somebody else owns the session (a live client, the relay within its
    /// lease, or a departed owner within its grace window). A load that is not foreign claimed the session when it was
    /// forwarded (so a request pipelined right behind it already sees the owner); `claim` undoes that if the load fails.
    Attach { session_id: String, foreign: bool, claim: Option<super::drivers::Claim> },
    /// The owner (or anyone, for an unowned session) closed or deleted the session: once that succeeds nobody owns it.
    End { session_id: String },
}
/// `session/close`, `fuigo/session/close` and `fuigo/session/delete` (client extension methods carry one leading `_`).
fn is_session_end_method(method: &str) -> bool {
    matches!(method.strip_prefix('_').unwrap_or(method), "session/close" | "fuigo/session/close" | "fuigo/session/delete")
}
/// Most driver-only messages held per session while it has no owner to take them (oldest dropped first).
const MAX_BUFFERED_DRIVER_MESSAGES: usize = 64;
/// The session whose owner decides for `session_id`: the root of its subagent chain (a subagent's session is owned through
/// its parent, a grandchild's through the root), else itself. Bounded, so a cyclic registry cannot loop.
fn owning_session<'a>(child_sessions: &'a HashMap<String, HashSet<String>>, session_id: &'a str) -> &'a str {
    let mut current = session_id;
    for _ in 0..=child_sessions.len() {
        match child_sessions.iter().find(|(_, children)| children.contains(current)) {
            Some((parent, _)) if parent.as_str() != session_id => current = parent.as_str(),
            _ => break,
        }
    }
    current
}
/// Hold a driver-only message (a reverse request or a scheduled-task prompt) for the session's next owner.
pub(crate) fn hold_driver_message(
    held: &mut HashMap<String, std::collections::VecDeque<Arc<str>>>,
    session_id: &str,
    payload: Arc<str>,
) {
    let queue = held.entry(session_id.to_string()).or_default();
    if queue.len() >= MAX_BUFFERED_DRIVER_MESSAGES {
        queue.pop_front();
        warn!(session_id, "Driver-only message buffer full; dropped the oldest");
    }
    queue.push_back(payload);
}
/// Deliver everything held for `session_id` to its new owner `client`.
fn flush_driver_messages(
    held: &mut HashMap<String, std::collections::VecDeque<Arc<str>>>,
    session_id: &str,
    client: ClientId,
    clients: &HashMap<ClientId, ClientState>,
    board: &super::drivers::OwnerBoard,
) {
    let Some(queue) = held.remove(session_id) else { return };
    let Some(target) = clients.get(&client) else {
        warn!(session_id, dropped = queue.len(), "Owner left before held driver-only messages could be delivered");
        return;
    };
    let count = queue.len();
    for payload in queue {
        let key = request_key_of(&payload);
        if target.tx.send(ClientOutbound::Acp(payload)).is_err() {
            warn!(client_id = client.0, session_id, "Failed to deliver a held driver-only message (channel closed)");
            return;
        }
        if let Some(key) = key {
            board.deliver_request(&key, session_id, super::drivers::Claimer::Client(client));
        }
    }
    debug!(client_id = client.0, session_id, count, "Delivered held driver-only messages to the session's owner");
}
/// The key an answer to this agent request is tracked by (its JSON-RPC id, serialized), when the payload is a request.
fn request_key_of(payload: &str) -> Option<String> {
    let json: serde_json::Value = serde_json::from_str(payload).ok()?;
    request_key(&json)
}
fn request_key(json: &serde_json::Value) -> Option<String> {
    json.get("method")?;
    json.get("id").filter(|id| !id.is_null()).map(|id| id.to_string())
}
/// The agent marks every request it sends for a session as not yet delivered, before the line is fanned out to the relay
/// and the server loop, so no answer counts until the leader has delivered it to the session's owner.
pub(crate) fn note_agent_request(line: &str, board: &super::drivers::OwnerBoard) {
    if !(line.contains("\"method\"") && line.contains("\"id\"")) {
        return;
    }
    let Ok(json) = serde_json::from_str::<serde_json::Value>(line) else { return };
    if let (Some(key), Some(session_id)) = (request_key(&json), extract_session_id(&json)) {
        board.note_request(&key, &session_id);
    }
}
/// What [`drop_unadmitted_answers`] did to a message.
#[derive(Debug, PartialEq, Eq)]
enum AnswerFilter {
    Keep,
    Changed,
    DropAll,
}
/// A JSON-RPC response (an answer to one of the agent's requests).
fn is_answer(json: &serde_json::Value) -> bool {
    json.get("method").is_none()
        && json.get("id").is_some_and(|id| !id.is_null())
        && (json.get("result").is_some() || json.get("error").is_some())
}
/// Remove answers `who` may not give: a request for a session is answered only by the party the leader delivered it to.
fn drop_unadmitted_answers(
    json: &mut serde_json::Value,
    board: &super::drivers::OwnerBoard,
    who: super::drivers::Claimer,
) -> AnswerFilter {
    let refused = |item: &serde_json::Value| {
        if !is_answer(item) {
            return false;
        }
        let id = item.get("id").map(|id| id.to_string()).unwrap_or_default();
        if board.admit_answer(&id, who) {
            return false;
        }
        warn!(request_id = id.as_str(), answerer = ?who, "Dropped an answer to a session request from a connection it was not delivered to (only the session's owner answers)");
        true
    };
    match json {
        serde_json::Value::Array(items) => {
            let before = items.len();
            items.retain(|item| !refused(item));
            match (items.len(), before) {
                (0, b) if b > 0 => AnswerFilter::DropAll,
                (n, b) if n != b => AnswerFilter::Changed,
                _ => AnswerFilter::Keep,
            }
        }
        other if refused(other) => AnswerFilter::DropAll,
        _ => AnswerFilter::Keep,
    }
}
/// The relay's answers follow the same rule as a local window's: `None` when nothing of the line may reach the agent.
pub(crate) fn filter_relay_answers(line: &str, board: &super::drivers::OwnerBoard) -> Option<String> {
    let Ok(mut json) = serde_json::from_str::<serde_json::Value>(line) else {
        return Some(line.to_string());
    };
    match drop_unadmitted_answers(&mut json, board, super::drivers::Claimer::Relay) {
        AnswerFilter::Keep => Some(line.to_string()),
        AnswerFilter::Changed => Some(json.to_string()),
        AnswerFilter::DropAll => None,
    }
}
/// Put the reconnect token into a successful response's `result._meta`.
fn insert_reconnect_token(json: &mut serde_json::Value, token: &str) {
    let Some(result) = json.get_mut("result").and_then(|r| r.as_object_mut()) else {
        return;
    };
    let meta = result.entry("_meta").or_insert_with(|| serde_json::json!({}));
    if let Some(meta) = meta.as_object_mut() {
        meta.insert(
            crate::leader::protocol::LEADER_RECONNECT_TOKEN_KEY.to_string(),
            serde_json::json!(token),
        );
    }
}
/// Act on what the ownership board decided on its own (a grace window or relay lease ended, the relay dropped).
fn apply_board_events(
    board: &super::drivers::OwnerBoard,
    session_driver: &mut HashMap<String, ClientId>,
    held: &mut HashMap<String, std::collections::VecDeque<Arc<str>>>,
    clients: &HashMap<ClientId, ClientState>,
    interactions: &HashMap<String, HashMap<String, Arc<str>>>,
) {
    for event in board.take_events() {
        match event {
            super::drivers::SettleEvent::Promoted { session_id, client, token } => {
                // The first queued claimant owns now: it is handed its reconnect token (so a blip does not cost it the
                // session), then gets what was held for the owner.
                session_driver.insert(session_id.clone(), client);
                debug!(client_id = client.0, session_id = %session_id, "Queued claimant took over the session");
                if let Some(target) = clients.get(&client) {
                    let notice = serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": crate::leader::protocol::LEADER_OWNER_TOKEN_METHOD,
                        "params": {
                            "sessionId": session_id,
                            "_meta": { crate::leader::protocol::LEADER_RECONNECT_TOKEN_KEY: token },
                        },
                    })
                    .to_string();
                    let _ = target.tx.send(ClientOutbound::Acp(notice.into()));
                }
                // What the relay was sent for this session and never answered goes to the new owner first.
                for payload in board.take_relay_inflight(&session_id) {
                    hold_driver_message(held, &session_id, payload);
                }
                // Still-pending interactions (permission, questions, plan approval) are the new owner's to answer now.
                if let Some(cached) = interactions.get(&session_id) {
                    let already: HashSet<String> = held
                        .get(&session_id)
                        .map(|q| q.iter().filter_map(|p| request_key_of(p)).collect())
                        .unwrap_or_default();
                    for payload in cached.values() {
                        if request_key_of(payload).is_none_or(|k| !already.contains(&k)) {
                            hold_driver_message(held, &session_id, payload.clone());
                        }
                    }
                }
                flush_driver_messages(held, &session_id, client, clients, board);
            }
            super::drivers::SettleEvent::Vacated { session_id } => {
                drop(board.take_relay_inflight(&session_id));
                if let Some(queue) = held.remove(&session_id) {
                    warn!(
                        session_id = %session_id,
                        dropped = queue.len(),
                        "Session has no owner and no claimant: dropping held driver-only messages"
                    );
                }
            }
        }
    }
}
fn cpu_profile_status_payload(status: CpuProfileStatus) -> ControlPayload {
    match status {
        CpuProfileStatus::Inactive => ControlPayload::CpuProfileStatus {
            active: false,
            stopping: false,
            started_at: None,
            svg_path: None,
            frequency_hz: None,
        },
        CpuProfileStatus::Active {
            started_at,
            svg_path,
            frequency_hz,
        } => ControlPayload::CpuProfileStatus {
            active: true,
            stopping: false,
            started_at: Some(started_at),
            svg_path: Some(svg_path),
            frequency_hz: Some(frequency_hz),
        },
        CpuProfileStatus::Stopping {
            started_at,
            svg_path,
            frequency_hz,
        } => ControlPayload::CpuProfileStatus {
            active: false,
            stopping: true,
            started_at: Some(started_at),
            svg_path: Some(svg_path),
            frequency_hz: Some(frequency_hz),
        },
    }
}
fn leader_info_payload(control_state: &LeaderServerControlState) -> ControlPayload {
    let manager = control_state.cpu_profile.lock();
    let status = manager.status();
    let (cpu_profile_active, cpu_profile_stopping, profile_started_at) = match status {
        CpuProfileStatus::Inactive => (false, false, None),
        CpuProfileStatus::Active { started_at, .. } => (true, false, Some(started_at)),
        CpuProfileStatus::Stopping { started_at, .. } => (false, true, Some(started_at)),
    };
    ControlPayload::LeaderInfo {
        pid: control_state.metadata.pid,
        socket_path: control_state.metadata.socket_path.clone(),
        lock_path: control_state.metadata.lock_path.clone(),
        ws_url_suffix: control_state.metadata.ws_url_suffix.clone(),
        leader_protocol_version: LEADER_PROTOCOL_VERSION,
        leader_binary_version: control_state.metadata.leader_binary_version.clone(),
        profiling_supported: manager.runtime_cpu_profile(),
        profiling_compiled_in: manager.profiling_compiled_in(),
        cpu_profile_active,
        cpu_profile_stopping,
        profile_started_at,
        profile_formats: manager.profile_formats().to_vec(),
    }
}
use crate::env::PROD_COMPUTER_HUB_WS_URL as PROD_COMPUTER_HUB_URL;
const WORKSPACE_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
fn workspace_err(message: impl Into<String>) -> ControlError {
    ControlError {
        code: ControlErrorCode::InternalError,
        message: message.into(),
        details: None,
    }
}
/// Resolve the hub credential, waiting if the leader is still wiring auth (the IPC socket comes up first).
/// Resolves the instant auth is wired or the leader cancels; event-driven, no timeout.
async fn wait_for_leader_auth(
    ws: &WorkspaceControl,
    cancel: &CancellationToken,
) -> Result<Arc<dyn AuthProvider>, ControlError> {
    let mut rx = ws.auth.subscribe();
    let result = tokio::select! {
        result = rx.wait_for(|v| v.is_some()) => result,
        _ = cancel.cancelled() => {
            return Err(workspace_err(
                "leader is shutting down; cannot expose workspace to the hub",
            ));
        }
    };
    match result {
        Ok(guard) => Ok(guard.clone().expect("waited for Some")),
        Err(_) => Err(workspace_err(
            "leader is shutting down; cannot expose workspace to the hub",
        )),
    }
}
/// The host-derived server id: the sanitised, lower-cased host name. Never sent as is to a hub that is not
/// FluxRouter-operated; see [`hub_registration_identity`].
fn host_derived_server_id(hostname: &str) -> String {
    let raw = hostname.to_ascii_lowercase();
    let sanitized: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let name = sanitized.trim_matches('-');
    if name.is_empty() {
        "fuigo-workspace".to_string()
    } else {
        name.to_string()
    }
}
/// P77: the `server_id` and registration `metadata` sent to the hub at `hub_url` (the exact URL connected to).
///
/// A FluxRouter-operated hub (`IdentityDisclosure::for_websocket_destination`: `wss` to the FluxRouter API host, the
/// P43 rule for a WebSocket handshake; `for_destination` is `https`-only and would never admit a `wss` hub) gets the
/// host-derived id and the `hostname` unchanged. Any other hub, and any hub URL that cannot be classified, gets NO
/// `hostname` and the P54 per-destination pseudonym of the host-derived id: stable per machine at that one origin
/// (reconnects and dedupe keep working), different at every other origin (a keyless hash: a guessed host name can be
/// checked offline), and UUID-shaped so the hub's id parser accepts it.
fn hub_registration_identity(
    hub_url: &str,
    cwd: &Path,
    hostname: &str,
) -> (String, serde_json::Value) {
    let host_id = host_derived_server_id(hostname);
    // `cwd` is the workspace root the user asked to expose to this hub, so it is sent as is; a path that embeds a user
    // or host name is out of this rule's scope (proposal in R082). The object is built in the pre-P77 key order, so a
    // FluxRouter hub receives the registration byte for byte as before.
    let mut metadata = serde_json::json!({
        "source": "fuigo-workspace",
        "hostname": hostname,
        "cwd": cwd.display().to_string(),
    });
    if fuigo_extra_ca::fluxrouter::IdentityDisclosure::for_websocket_destination(hub_url).is_permitted() {
        (host_id, metadata)
    } else {
        if let Some(fields) = metadata.as_object_mut() {
            fields.shift_remove("hostname");
        }
        (
            fuigo_extra_ca::fluxrouter::destination_pseudonym(hub_url, &host_id),
            metadata,
        )
    }
}
async fn drain_and_disconnect(handle: &WorkspaceHandle) {
    let tracker = handle.activity_tracker().clone();
    tracker.set_draining();
    if tokio::time::timeout(WORKSPACE_DRAIN_TIMEOUT, tracker.wait_until_drained())
        .await
        .is_err()
    {
        warn!(
            active = tracker.total_active(),
            "workspace drain timed out; disconnecting hub anyway"
        );
    }
    handle.shutdown_hub().await;
}
fn build_workspace_status(
    metadata: &LeaderServerMetadata,
    exposure: Option<&WorkspaceExposure>,
) -> ControlPayload {
    match exposure {
        None => ControlPayload::WorkspaceStatus {
            state: "none".to_string(),
            hub_url: None,
            cwd: None,
            uptime_ms: 0,
            active_tool_calls: 0,
            sessions: Vec::new(),
            pid: metadata.pid,
        },
        Some(exp) => {
            let snapshot = exp.handle.activity_tracker().snapshot();
            let mut sessions = exp.handle.session_ids();
            sessions.sort();
            ControlPayload::WorkspaceStatus {
                state: if exp.paused.load(std::sync::atomic::Ordering::Relaxed) {
                    "paused"
                } else {
                    "running"
                }
                .to_string(),
                hub_url: Some(exp.hub_url.clone()),
                cwd: Some(exp.cwd.display().to_string()),
                uptime_ms: exp.started_at.elapsed().as_millis() as u64,
                active_tool_calls: snapshot.active_tool_calls,
                sessions,
                pid: metadata.pid,
            }
        }
    }
}
async fn handle_workspace_start(
    control_state: LeaderServerControlState,
    hub_url: Option<String>,
    cwd: String,
    cancel: CancellationToken,
) -> Result<ControlPayload, ControlError> {
    let ws = &control_state.workspace;
    // Cancellation outranks configuration. A caller that is shutting down gets
    // told so; it does not need to hear that the hub is unconfigured.
    //
    // This used to happen by accident: the hub URL defaulted to a real xAI
    // address, so it always parsed, and the first thing that actually noticed
    // the token was the auth wait further down. With no default that ordering
    // reversed and an aborted start reported a config error instead. Making the
    // check explicit keeps the precedence a decision rather than a side effect.
    if cancel.is_cancelled() {
        return Err(workspace_err(
            "leader is shutting down; cannot expose workspace to the hub",
        ));
    }
    // PROD_COMPUTER_HUB_URL is empty by default (Fuigo runs no hub), so this can
    // legitimately resolve to nothing. Say so plainly rather than letting an
    // empty string reach `Url::parse` and surface as "relative URL without a base".
    let url_str = hub_url
        .filter(|u| !u.trim().is_empty())
        .or_else(|| ws.default_hub_url.clone())
        .or_else(|| {
            let fallback = PROD_COMPUTER_HUB_URL.trim();
            (!fallback.is_empty()).then(|| fallback.to_string())
        })
        .ok_or_else(|| {
            workspace_err(
                "no Computer Hub configured: set `hub.url` in the agent config or pass --hub-url"
                    .to_string(),
            )
        })?;
    let url = url::Url::parse(&url_str)
        .map_err(|e| workspace_err(format!("invalid hub url {url_str}: {e}")))?;
    // P47: the configured hub (`[hub].url`, else the compiled default) is the hub's service base.
    let configured_hub = ws.default_hub_url.clone().or_else(|| {
        let fallback = PROD_COMPUTER_HUB_URL.trim();
        (!fallback.is_empty()).then(|| fallback.to_string())
    });
    let cwd_path = PathBuf::from(&cwd);
    let _serialize = ws.lock.lock().await;
    if let Some(existing) = ws.exposure.load_full()
        && !existing.paused.load(Ordering::Relaxed)
        && existing.cwd == cwd_path
        && existing.hub_url == url_str
    {
        return Ok(build_workspace_status(
            &control_state.metadata,
            Some(existing.as_ref()),
        ));
    }
    let allow_insecure_ws = hub_url_allows_insecure_ws(&url);
    let status_config = fuigo_workspace::StatusConfig::from_env();
    let alpha_test_key = None;
    let auth = wait_for_leader_auth(ws, &cancel).await?;
    // P47: the hub is handed the leader's credential on every connect and reconnect, re-resolved each time, so its
    // kind can change between connects. `HubDestinationGuard` decides on the exact value before EVERY socket (the
    // hub SDK asks `AuthProvider::destination_permits`): a session token goes only to a hub the service-endpoint
    // trust class admits (`wss`, not loopback, on the configured hub's origin); a static `AuthMode::ApiKey`
    // credential, matched by value, keeps its own rules. A refusal opens no socket and is terminal. The first
    // connect is checked here too, so the command fails with the remedy instead of a connect error.
    let guard = HubDestinationGuard {
        inner: auth,
        auth_manager: ws.auth_manager.lock().clone(),
        configured_hub,
    };
    guard
        .check(&url, &guard.inner.current())
        .map_err(|refused| workspace_err(refused.to_string()))?;
    let auth: Arc<dyn AuthProvider> = Arc::new(guard);
    let (server_id, metadata) = hub_registration_identity(
        &url_str,
        &cwd_path,
        &gethostname::gethostname().to_string_lossy(),
    );
    let upload_queue_enabled =
        std::env::var("FUIGO_WORKSPACE_UPLOAD_QUEUE_ENABLED").as_deref() != Ok("false");
    crate::agent::folder_trust::resolve_and_record(&cwd_path, None, false);
    let project_lsp_trusted = crate::agent::folder_trust::project_scope_allowed(&cwd_path);
    let handle = fuigo_workspace::connect_local_workspace(
        cwd_path.clone(), url, auth,
        fuigo_workspace::LocalWorkspaceConnectOptions {
            metadata: Some(metadata), server_id: Some(server_id), alpha_test_key,
            allow_insecure_ws, status_config, upload_queue_enabled, project_lsp_trusted,
            ..Default::default()
        },
    )
    .await
    .map_err(|e| workspace_err(format!("failed to connect workspace to hub: {e}")))?;
    let exposure = Arc::new(WorkspaceExposure {
        handle,
        hub_url: url_str,
        cwd: cwd_path,
        started_at: Instant::now(),
        paused: AtomicBool::new(false),
    });
    let payload = build_workspace_status(&control_state.metadata, Some(exposure.as_ref()));
    if let Some(old) = ws.exposure.swap(Some(exposure)) {
        drain_and_disconnect(&old.handle).await;
    }
    Ok(payload)
}
async fn handle_workspace_pause(
    control_state: LeaderServerControlState,
) -> Result<ControlPayload, ControlError> {
    let ws = &control_state.workspace;
    let _serialize = ws.lock.lock().await;
    let Some(exp) = ws.exposure.load_full() else {
        return Err(workspace_err("no workspace exposure is running"));
    };
    if !exp.paused.load(Ordering::Relaxed) {
        drain_and_disconnect(&exp.handle).await;
        exp.paused.store(true, Ordering::Relaxed);
    }
    Ok(build_workspace_status(
        &control_state.metadata,
        Some(exp.as_ref()),
    ))
}
async fn handle_workspace_resume(
    control_state: LeaderServerControlState,
) -> Result<ControlPayload, ControlError> {
    let ws = &control_state.workspace;
    let _serialize = ws.lock.lock().await;
    let Some(exp) = ws.exposure.load_full() else {
        return Err(workspace_err("no workspace exposure is running"));
    };
    if exp.paused.load(Ordering::Relaxed) {
        exp.handle.activity_tracker().set_active();
        if let Err(e) = exp.handle.connect_hub().await {
            exp.handle.activity_tracker().set_draining();
            return Err(workspace_err(format!("failed to reconnect to hub: {e}")));
        }
        exp.paused.store(false, Ordering::Relaxed);
    }
    Ok(build_workspace_status(
        &control_state.metadata,
        Some(exp.as_ref()),
    ))
}
async fn handle_workspace_stop(
    control_state: LeaderServerControlState,
) -> Result<ControlPayload, ControlError> {
    let ws = &control_state.workspace;
    let _serialize = ws.lock.lock().await;
    if let Some(exp) = ws.exposure.swap(None) {
        drain_and_disconnect(&exp.handle).await;
    }
    Ok(build_workspace_status(&control_state.metadata, None))
}
async fn handle_workspace_status(
    control_state: LeaderServerControlState,
) -> Result<ControlPayload, ControlError> {
    let exposure = control_state.workspace.exposure.load_full();
    Ok(build_workspace_status(
        &control_state.metadata,
        exposure.as_deref(),
    ))
}
async fn finalize_workspace_on_shutdown(control_state: LeaderServerControlState) {
    let ws = &control_state.workspace;
    let _serialize = ws.lock.lock().await;
    if let Some(exp) = ws.exposure.swap(None) {
        info!("Draining workspace exposure on leader shutdown");
        drain_and_disconnect(&exp.handle).await;
    }
}
fn handle_control_command(
    control_state: &LeaderServerControlState,
    command: ControlCommand,
) -> Result<ControlPayload, ControlError> {
    match command {
        ControlCommand::GetLeaderInfo => Ok(leader_info_payload(control_state)),
        ControlCommand::CpuProfileStatus => {
            let manager = control_state.cpu_profile.lock();
            Ok(cpu_profile_status_payload(manager.status()))
        }
        ControlCommand::StartCpuProfile {
            output,
            frequency_hz,
        } => {
            let mut manager = control_state.cpu_profile.lock();
            let status = manager.start(CpuProfileStartOptions {
                output: output.map(PathBuf::from),
                frequency_hz,
            })?;
            match status {
                CpuProfileStatus::Active {
                    started_at,
                    svg_path,
                    frequency_hz,
                } => Ok(ControlPayload::CpuProfileStarted {
                    pid: control_state.metadata.pid,
                    svg_path,
                    frequency_hz,
                    started_at,
                }),
                CpuProfileStatus::Inactive => {
                    Ok(cpu_profile_status_payload(CpuProfileStatus::Inactive))
                }
                CpuProfileStatus::Stopping {
                    started_at,
                    svg_path,
                    frequency_hz,
                } => Ok(cpu_profile_status_payload(CpuProfileStatus::Stopping {
                    started_at,
                    svg_path,
                    frequency_hz,
                })),
            }
        }
        ControlCommand::StopCpuProfile => {
            unreachable!("StopCpuProfile must be handled asynchronously")
        }
        ControlCommand::WorkspaceStart { .. }
        | ControlCommand::WorkspacePause
        | ControlCommand::WorkspaceResume
        | ControlCommand::WorkspaceStop
        | ControlCommand::WorkspaceStatus => {
            unreachable!("workspace control commands are handled asynchronously")
        }
        ControlCommand::RelaunchForUpdate { .. } | ControlCommand::StopForDowngrade { .. } => {
            unreachable!("RelaunchForUpdate and StopForDowngrade must be handled asynchronously")
        }
    }
}
async fn handle_stop_cpu_profile(
    control_state: LeaderServerControlState,
) -> Result<ControlPayload, ControlError> {
    let stop_handle = {
        let mut manager = control_state.cpu_profile.lock();
        manager.take_stop_handle()?
    };
    let pid = control_state.metadata.pid;
    let result = tokio::task::spawn_blocking(move || stop_handle.finish()).await;
    control_state.cpu_profile.lock().complete_stop();
    let result = result.map_err(|join_error| ControlError {
        code: ControlErrorCode::InternalError,
        message: "CPU profile stop task failed".to_string(),
        details: Some(serde_json::json!({ "error": join_error.to_string() })),
    })??;
    Ok(ControlPayload::CpuProfileStopped {
        pid,
        svg_path: result.svg_path,
        started_at: result.started_at,
        stopped_at: result.stopped_at,
    })
}
async fn finalize_cpu_profile_on_shutdown(control_state: LeaderServerControlState) {
    let (disposition, stop_handle, mut stop_completion_rx) = {
        let mut manager = control_state.cpu_profile.lock();
        let disposition = manager.shutdown_stop_disposition();
        let stop_completion_rx = manager.subscribe_stop_completion();
        let stop_handle = match manager.take_shutdown_stop_handle() {
            Ok(stop_handle) => stop_handle,
            Err(error) => {
                warn!(error = %error, "Failed to prepare active CPU profile for leader shutdown");
                return;
            }
        };
        (disposition, stop_handle, stop_completion_rx)
    };
    let Some(disposition) = disposition else {
        return;
    };
    let Some(stop_handle) = stop_handle else {
        match disposition {
            ShutdownStopDisposition::AlreadyStopping => {
                debug!(
                    "CPU profile stop already in progress during leader shutdown; waiting for in-flight finalization task"
                );
                if !*stop_completion_rx.borrow() && stop_completion_rx.changed().await.is_err() {
                    warn!("CPU profile stop completion channel closed during leader shutdown wait");
                }
            }
            ShutdownStopDisposition::StartedShutdownStop => {
                warn!("Expected shutdown CPU profile stop handle but none was available");
            }
        }
        return;
    };
    let result = tokio::task::spawn_blocking(move || stop_handle.finish()).await;
    control_state.cpu_profile.lock().complete_stop();
    match result {
        Ok(Ok(result)) => {
            info!(
                path = %result.svg_path.display(),
                started_at = %result.started_at,
                stopped_at = %result.stopped_at,
                "Finalized active CPU profile during leader shutdown"
            );
        }
        Ok(Err(error)) => {
            warn!(error = %error, "Failed to finalize active CPU profile during leader shutdown");
        }
        Err(join_error) => {
            warn!(
                error = %join_error,
                "CPU profile shutdown finalization task failed"
            );
        }
    }
}
/// Bounded grace the leader waits for in-flight turns to finish before a `RelaunchForUpdate` relaunch.
/// If the agent is still busy when this elapses, the leader exits anyway.
/// The in-flight turn ends and the session reloads cleanly (truncated at the last persisted boundary).
const RELAUNCH_GRACE: Duration = Duration::from_secs(5);
/// Bound on the post-drain session flush ([`AgentActivity::flush_all_sessions`]).
const RELAUNCH_FLUSH_GRACE: Duration = Duration::from_secs(5);
/// Total shutdown budget advertised to clients in the `Relaunching` ack: idle-drain plus session flush.
const RELAUNCH_TOTAL_GRACE: Duration =
    Duration::from_millis((RELAUNCH_GRACE.as_millis() + RELAUNCH_FLUSH_GRACE.as_millis()) as u64);
/// Poll cadence while waiting for the agent to go idle during the grace period.
const RELAUNCH_GRACE_POLL: Duration = Duration::from_millis(100);
/// Decide whether a [`ControlCommand::RelaunchForUpdate`] is accepted (the synchronous half).
/// Kept separate from starting the drain so the caller can send the `Relaunching` ack BEFORE the leader begins shutting down.
/// Otherwise an idle leader can race the ack and the client sees a dropped control response.
///
/// Declines unless the target is strictly newer (directional guard) and no relaunch is already in progress (idempotent across multiple clients).
/// On accept it sets `relaunching` so duplicate requests are declined.
fn decide_relaunch_for_update(
    control_state: &LeaderServerControlState,
    to_version: String,
    relaunching: &AtomicBool,
) -> Result<ControlPayload, ControlError> {
    let leader_version = control_state.metadata.leader_binary_version.clone();
    if !super::leader_is_older_than(&leader_version, &to_version) {
        debug!(
            from_version = %leader_version,
            to_version = %to_version,
            "RelaunchForUpdate declined: target is not strictly newer (or unparseable)"
        );
        return Ok(ControlPayload::RelaunchDeclined {
            reason: format!("leader version {leader_version} is not older than {to_version}"),
        });
    }
    if relaunching.swap(true, Ordering::SeqCst) {
        return Ok(ControlPayload::RelaunchDeclined {
            reason: "a relaunch is already in progress".to_string(),
        });
    }
    info!(
        from_version = %leader_version,
        to_version = %to_version,
        grace_ms = RELAUNCH_TOTAL_GRACE.as_millis() as u64,
        "RelaunchForUpdate accepted; draining before relaunch onto new binary"
    );
    Ok(ControlPayload::Relaunching {
        from_version: leader_version,
        to_version,
        grace_ms: RELAUNCH_TOTAL_GRACE.as_millis() as u64,
    })
}
/// Decide whether a [`ControlCommand::StopForDowngrade`] is accepted (P124).
/// The mirror of [`decide_relaunch_for_update`]: accepted only when the leader is strictly NEWER than `to_version` (both parseable)
/// and no relaunch is in progress. Same ack and drain, so connected clients reconnect exactly as for an update.
fn decide_stop_for_downgrade(
    control_state: &LeaderServerControlState,
    to_version: String,
    relaunching: &AtomicBool,
) -> Result<ControlPayload, ControlError> {
    let leader_version = control_state.metadata.leader_binary_version.clone();
    if !super::leader_is_newer_than(&leader_version, &to_version) {
        debug!(
            from_version = %leader_version,
            to_version = %to_version,
            "StopForDowngrade declined: target is not strictly older (or unparseable)"
        );
        return Ok(ControlPayload::RelaunchDeclined {
            reason: format!("leader version {leader_version} is not newer than {to_version}"),
        });
    }
    if relaunching.swap(true, Ordering::SeqCst) {
        return Ok(ControlPayload::RelaunchDeclined {
            reason: "a relaunch is already in progress".to_string(),
        });
    }
    info!(
        from_version = %leader_version,
        to_version = %to_version,
        grace_ms = RELAUNCH_TOTAL_GRACE.as_millis() as u64,
        "StopForDowngrade accepted; draining before the leader stops for an explicit downgrade"
    );
    Ok(ControlPayload::Relaunching {
        from_version: leader_version,
        to_version,
        grace_ms: RELAUNCH_TOTAL_GRACE.as_millis() as u64,
    })
}
/// Start the bounded-grace drain for an accepted relaunch.
/// Wait up to [`RELAUNCH_GRACE`] for the agent to go idle.
/// Idle checks both `agent_busy` (IPC traffic) and [`AgentActivity::is_busy`] (relay-driven turns, subagents).
/// Then flush every session actor, set [`ShutdownReason::AutoUpdate`], and cancel: the same exit path the auto-update checker uses.
/// Must be called *after* the `Relaunching` ack has been sent so the ack is delivered before `ShuttingDown`.
fn spawn_relaunch_drain(
    shutdown_tx: watch::Sender<super::protocol::ShutdownReason>,
    cancel: CancellationToken,
    agent_busy: Arc<AtomicBool>,
    agent_activity: AgentActivity,
) {
    tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + RELAUNCH_GRACE;
        while agent_busy.load(Ordering::Relaxed) || agent_activity.is_busy() {
            if tokio::time::Instant::now() >= deadline {
                warn!(
                    "RelaunchForUpdate grace elapsed while agent busy; relaunching anyway (in-flight turn ends)"
                );
                break;
            }
            tokio::select! {
                // Another path already triggered shutdown; let it own the exit
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(RELAUNCH_GRACE_POLL) => {}
            }
        }
        agent_activity
            .flush_all_sessions(RELAUNCH_FLUSH_GRACE)
            .await;
        let _ = shutdown_tx.send(super::protocol::ShutdownReason::AutoUpdate);
        cancel.cancel();
    });
}
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("Failed to acquire leader lock: {0}")]
    LockFailed(#[from] super::lock::LockError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
/// Wire method of the leader's version-mismatch notice.
/// ACP only decodes a custom notification that carries the extension `_` prefix (the decoder strips it, so the pager handlers see `fuigo/leader/version_mismatch`);
/// a bare `fuigo/...` method is rejected as method-not-found and the notice never reaches the handler.
/// Leaders before this fix sent the bare name; the pager still normalizes it (`leader_bridge`).
pub(crate) const VERSION_MISMATCH_WIRE_METHOD: &str = "_fuigo/leader/version_mismatch";
/// Whether two version strings name the same release.
/// A version may carry a commit stamp (`"1.0.21 (abcdef123456)"`, the pager's `VERSION_WITH_COMMIT`) or semver build
/// metadata; neither makes a different release, so only the semantic version is compared. Strings that are not semver
/// compare as text.
fn same_release(a: &str, b: &str) -> bool {
    fn core(v: &str) -> &str {
        v.split_whitespace().next().unwrap_or("")
    }
    let (a, b) = (core(a), core(b));
    match (semver::Version::parse(a), semver::Version::parse(b)) {
        (Ok(a), Ok(b)) => a.cmp_precedence(&b).is_eq(),
        _ => a == b,
    }
}
/// Build the ACP notification payload for a leader/client version mismatch, or return `None` when versions match or detection is disabled.
///
/// Extracted as a standalone function so the notification shape can be unit-tested without running a full server.
fn make_version_mismatch_notification(
    client_version: &str,
    leader_version: &str,
) -> Option<String> {
    if leader_version == "unknown" || same_release(client_version, leader_version) {
        return None;
    }
    Some(
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": VERSION_MISMATCH_WIRE_METHOD,
            "params": {
                "clientVersion": client_version,
                "leaderVersion": leader_version,
                "message": format!(
                    "Client version {client_version} differs from leader version \
                     {leader_version}. Restart the fuigo binary to use the same version."
                )
            }
        })
        .to_string(),
    )
}
/// P142: send the one-off user notices this process recorded since `*forwarded`
/// (`fuigo_file_utils::destination_gate::announce_notice`, the withheld-upload notices) to every registered client
/// that shows them ([`ClientCapabilities::leader_notices`]). The leader runs the agent and its stderr is
/// `~/.fuigo/leader.log`, so without this the user never sees them. Each notice is sent once overall: to the clients
/// attached when it is recorded, or, when none of them shows notices, to the first such client that registers.
fn forward_process_notices(clients: &HashMap<ClientId, ClientState>, forwarded: &mut usize) {
    let pending = fuigo_file_utils::destination_gate::notices_from(*forwarded);
    // Oldest first, one notice at a time: a notice no client accepted stays (with every later one) for the next client
    // that registers, and a notice a client accepted is never offered again.
    for message in pending {
        let payload: Arc<str> = Arc::from(super::protocol::leader_notice_payload(&message));
        let mut accepted = false;
        for client in clients.values() {
            if client.registered && client.capabilities.leader_notices {
                accepted |= client.tx.send(ClientOutbound::Acp(payload.clone())).is_ok();
            }
        }
        if !accepted {
            return;
        }
        *forwarded += 1;
    }
}
/// Run the leader IPC server.
///
/// The socket_path is where the Unix socket will be created.
/// Caller is responsible for:
/// 1. Cleaning up any stale socket file before calling this
/// 2. Acquiring the leader lock AFTER this function creates the socket
///
/// With this ordering:
/// - Clients waiting for socket can connect as soon as we're ready
/// - The lock acquisition happens after we're actually listening
///
/// # Readiness gating
///
/// The `ready_rx` watch channel controls whether ACP messages are forwarded to the agent.
/// While `*ready_rx.borrow() == false` (leader still initializing):
/// - Client connections and IPC registrations are accepted normally.
/// - ACP requests (messages with an `id`) receive a structured `leader_starting` JSON-RPC error so the client can retry rather than hang.
/// - ACP notifications (no `id`) are dropped with a trace log.
///
/// Once `ready_rx` is signaled `true`, all subsequent ACP traffic is forwarded to the agent as normal.
/// (Ready means the socket is bound and bounded auth completed; the model catalog and remote settings stream in afterward.)
///
/// # Arguments
///
/// * `socket_path` - Path for the Unix domain socket
/// * `acp_tx` - Channel to send ACP messages from clients to the agent
/// * `response_rx` - Channel to receive responses from the agent to route to clients
/// * `cancel` - Cancellation token for graceful shutdown
/// * `no_exit_on_disconnect` - If true, don't exit when all clients disconnect
/// * `client_count` - Atomic counter tracking the number of connected clients
/// * `agent_busy` - Atomic flag set while the agent has in-flight **IPC** requests; relay-driven traffic never sets it
/// * `agent_activity` - Agent-derived activity view (running turns, parked interactions, live subagents).
///   The `RelaunchForUpdate` drain consults it alongside `agent_busy`, plus the pre-shutdown session flush.
/// * `ready_rx` - Watch receiver; ACP forwarding is gated until this is `true`
/// * `relay_demand_tx` - Watch sender flipped to `true` when the first [`ClientMode::Headless`] client registers, and
///   notified again (still `true`) on every later headless registration (P93).
///   `run_leader` defers starting the grok.com WebSocket relay until this fires.
///   A leader serving only interactive clients (TUI dashboard, IDE) thus never duplicates its ACP stream onto the relay.
///   Headless registration is the devbox-flow marker: those clients are driven remotely *through* the relay.
/// * `shutdown_tx` - Watch sender for the shutdown reason.
///   The server subscribes its own receiver and reads it once when `cancel` fires (defaults to [`ShutdownReason::Manual`]).
///   The auto-update checker and the [`ControlCommand::RelaunchForUpdate`] handler send [`ShutdownReason::AutoUpdate`] before cancelling.
///   Clients then see the real reason; senders must write before cancelling.
/// * `leader_version_override` - If `Some`, overrides [`LEADER_VERSION`] for version mismatch detection.
///   Pass `None` in production.
///   Tests use it to pin a leader version independent of the crate's own.
/// * `control_state` - Leader-local control metadata and CPU profiling state
pub async fn run_leader_server(
    socket_path: std::path::PathBuf,
    acp_tx: mpsc::UnboundedSender<String>,
    mut response_rx: mpsc::UnboundedReceiver<String>,
    cancel: CancellationToken,
    no_exit_on_disconnect: bool,
    client_count: Arc<AtomicUsize>,
    agent_busy: Arc<AtomicBool>,
    agent_activity: AgentActivity,
    ready_rx: watch::Receiver<bool>,
    relay_demand_tx: watch::Sender<bool>,
    shutdown_tx: watch::Sender<super::protocol::ShutdownReason>,
    leader_version_override: Option<&'static str>,
    control_state: LeaderServerControlState,
) -> Result<(), ServerError> {
    let _ = std::fs::remove_file(&socket_path);
    let shutdown_reason_rx = shutdown_tx.subscribe();
    let mut relay_refusal_rx = control_state.relay_refusal.subscribe();
    let mut notice_rx = fuigo_file_utils::destination_gate::subscribe_notices();
    // P142: how many of this process's notices a client has been sent (each one is sent once overall).
    let mut notices_forwarded: usize = 0;
    let listener = super::peer_check::bind_private(&socket_path)?;
    info!("Leader server listening");
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<ServerEvent>();
    let mut clients: HashMap<ClientId, ClientState> = HashMap::new();
    let mut session_driver: HashMap<String, ClientId> = HashMap::new();
    // Who owns each session: the one authority for owner-gated changes (see `super::drivers`). `session_driver` below is only
    // where driver-only messages are routed when the session has no live owner; it grants nothing.
    let driver_board = control_state.driver_board();
    // Driver-only messages (reverse requests, scheduled-task prompts) held while a session has no owner to take them.
    let mut held_driver_messages: HashMap<String, std::collections::VecDeque<Arc<str>>> = HashMap::new();
    // Requests whose response decides who drives a session (`session/new`, `session/load`, `session/resume`), by leader request id.
    let mut pending_driver_reqs: HashMap<String, DriverReq> = HashMap::new();
    let mut session_subscribers: HashMap<String, std::collections::HashSet<ClientId>> =
        HashMap::new();
    let mut child_sessions: HashMap<String, HashSet<String>> = HashMap::new();
    let mut pending_load_by_req: HashMap<String, (ClientId, String)> = HashMap::new();
    let mut load_live_buffer: HashMap<(ClientId, String), Vec<BufferedLive>> = HashMap::new();
    let mut orphan_replay_warned: HashSet<ClientId> = HashSet::new();
    let mut load_replay_max_seq: HashMap<(ClientId, String), u64> = HashMap::new();
    let mut interaction_requests: HashMap<String, HashMap<String, Arc<str>>> = HashMap::new();
    let mut pending_relay_notices: Vec<(String, Arc<str>)> = Vec::new();
    let mut last_active_client: Option<ClientId> = None;
    let mut had_clients = false;
    let mut pending_requests: usize = 0;
    let relaunching = Arc::new(AtomicBool::new(false));
    loop {
        apply_board_events(&driver_board, &mut session_driver, &mut held_driver_messages, &clients, &interaction_requests);
        let board_deadline = async {
            match driver_board.next_deadline() {
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                None => std::future::pending::<()>().await,
            }
        };
        let poll = tokio::select! {
            biased;
            _ = cancel.cancelled() => LeaderServerPoll::Cancelled,
            accept_result = listener.accept() => {
                LeaderServerPoll::Accept(accept_result.map(|(stream, _)| stream))
            }
            Some(event) = event_rx.recv() => LeaderServerPoll::Event(event),
            Some(payload) = response_rx.recv() => LeaderServerPoll::Response(payload),
            Ok(()) = relay_refusal_rx.changed() => LeaderServerPoll::RelayRefusalChanged,
            Ok(()) = notice_rx.changed() => LeaderServerPoll::NoticeRecorded,
            _ = driver_board.notified() => LeaderServerPoll::OwnerBoardWake,
            _ = board_deadline => LeaderServerPoll::OwnerBoardWake,
        };
        match poll {
            LeaderServerPoll::Cancelled => {
                let reason = shutdown_reason_rx.borrow().clone();
                info!(?reason, "Leader server shutting down (cancelled)");
                if pending_requests > 0 {
                    debug!(pending_requests, "Resetting agent_busy on shutdown");
                    agent_busy.store(false, Ordering::Relaxed);
                }
                broadcast_shutdown(&clients, reason);
                break;
            }
            LeaderServerPoll::RelayRefusalChanged => {
                // P125: the leader refused a relay: every interactive client attached now is told (headless clients
                // refuse the relay themselves, before they reach the leader).
                let payload = relay_refusal_rx.borrow_and_update().clone();
                // Cleared (the user opted in): tell them so, so no client keeps showing a refusal that is over.
                let payload = payload.unwrap_or_else(|| {
                    Arc::from(crate::agent::relay_opt_in::refusal_cleared_payload())
                });
                for client in clients.values() {
                    if client.registered && client.mode != ClientMode::Headless {
                        let _ = client.tx.send(ClientOutbound::Acp(payload.clone()));
                    }
                }
            }
            LeaderServerPoll::OwnerBoardWake => {}
            LeaderServerPoll::NoticeRecorded => {
                // `changed()` already marked the count seen; the list itself is read from this server's cursor.
                forward_process_notices(&clients, &mut notices_forwarded);
            }
            LeaderServerPoll::Accept(accept_result) => match accept_result {
                // A peer of another user account is dropped unread, before any client state exists.
                Ok(stream) if !super::peer_check::server_accepts(&stream, &socket_path) => drop(stream),
                Ok(stream) => {
                    had_clients = true;
                    let client_id = ClientId::new();
                    let (tx, rx) = mpsc::unbounded_channel();
                    clients.insert(
                        client_id,
                        ClientState {
                            tx,
                            mode: ClientMode::Stdio,
                            capabilities: ClientCapabilities::default(),
                            client_type: String::new(),
                            initialize_seen: false,
                            patch_initialize_request_id: None,
                            registered: false,
                            init_startup_hints: None,
                        },
                    );
                    spawn_client_handler(
                        client_id,
                        stream,
                        rx,
                        event_tx.clone(),
                        cancel.child_token(),
                        ready_rx.clone(),
                        control_state.clone(),
                    );
                }
                Err(e) => error!(error = %e, "Accept failed"),
            },
            LeaderServerPoll::Event(event) => match event {
                ServerEvent::Registered(id, mode, capabilities, client_type) => {
                    if let Some(client) = clients.get_mut(&id) {
                        client.mode = mode;
                        client.capabilities = capabilities;
                        client.client_type = client_type;
                        client.registered = true;
                        client_count.fetch_add(1, Ordering::Relaxed);
                        debug!(client_id = id.0, ?mode, yolo_mode = client.capabilities.yolo_mode, client_type = %client.client_type, "Client registered");
                        fuigo_telemetry::unified_log::info(
                            "leader.client.registered",
                            None,
                            Some(serde_json::json!({
                                "client_id": id.0,
                                "client_type": client.client_type,
                            })),
                        );
                        if mode == ClientMode::Headless {
                            // P93: EVERY headless registration notifies (the value stays `true`), so a leader that
                            // refused a relay nobody had opted in to decides again when the next headless client
                            // attaches (`agent::app::spawn_leader_relay`).
                            let newly_demanded = !*relay_demand_tx.borrow();
                            relay_demand_tx.send_replace(true);
                            if newly_demanded {
                                info!(
                                    client_id = id.0,
                                    "First headless client registered; signalling relay demand"
                                );
                            }
                        }
                        let effective_leader_version =
                            leader_version_override.unwrap_or(LEADER_VERSION);
                        if let Some(ref cv) = client.capabilities.client_version
                            && let Some(payload) = make_version_mismatch_notification(
                                cv.as_str(),
                                effective_leader_version,
                            )
                        {
                            warn!(
                                client_id = id.0,
                                client_version = cv.as_str(),
                                leader_version = effective_leader_version,
                                "Version mismatch: client binary differs from leader binary"
                            );
                            let _ = client.tx.send(ClientOutbound::Acp(payload.into()));
                        }
                        // P125: a client that registers after the leader refused a relay is told at once.
                        if mode != ClientMode::Headless {
                            let refusal = relay_refusal_rx.borrow().clone();
                            let payload = match refusal {
                                Some(payload) => Some(payload),
                                // A client that asked for the state is told "cleared" too, so a reconnect reconciles
                                // a refusal it cached.
                                None if client.capabilities.relay_refusal_state => Some(Arc::from(
                                    crate::agent::relay_opt_in::refusal_cleared_payload(),
                                )),
                                None => None,
                            };
                            if let Some(payload) = payload {
                                let _ = client.tx.send(ClientOutbound::Acp(payload));
                            }
                        }
                    }
                    // P142: a notice recorded while no client that shows them was attached goes to this one.
                    forward_process_notices(&clients, &mut notices_forwarded);
                }
                ServerEvent::Disconnected(id) => {
                    let was_registered = clients.get(&id).is_some_and(|c| c.registered);
                    clients.remove(&id);
                    if was_registered {
                        client_count.fetch_sub(1, Ordering::Relaxed);
                        fuigo_telemetry::unified_log::info(
                            "leader.client.disconnected",
                            None,
                            Some(serde_json::json!({ "client_id": id.0 })),
                        );
                    }
                    pending_load_by_req.retain(|_, (c, _)| *c != id);
                    load_live_buffer.retain(|(c, _), _| *c != id);
                    load_replay_max_seq.retain(|(c, _), _| *c != id);
                    let mut detached_sessions: Vec<String> = Vec::new();
                    let viewed: Vec<String> = session_subscribers
                        .iter()
                        .filter(|(_, subs)| subs.contains(&id))
                        .map(|(sid, _)| sid.clone())
                        .collect();
                    for sid in viewed {
                        let now_empty = if let Some(subs) = session_subscribers.get_mut(&sid) {
                            subs.remove(&id);
                            subs.is_empty()
                        } else {
                            true
                        };
                        if now_empty {
                            session_subscribers.remove(&sid);
                            session_driver.remove(&sid);
                            detached_sessions.push(sid);
                        } else if session_driver.get(&sid) == Some(&id) {
                            // Routing is NOT handed to another subscriber (any local program could be one), and neither
                            // is ownership: see `client_gone` below.
                            session_driver.remove(&sid);
                        }
                    }
                    // Sessions this client owned enter their grace window (its token reclaims them; this holds when it
                    // was the last subscriber too), and it leaves every claimant queue. At the end of the window the
                    // first still-connected claimant owns.
                    driver_board.client_gone(id);
                    pending_driver_reqs.retain(|_, req| req.client != id);
                    if last_active_client == Some(id) {
                        last_active_client = None;
                    }
                    if !detached_sessions.is_empty() {
                        let _ = acp_tx.send(internal_notification(
                            InternalMethod::EvictSessions,
                            serde_json::json!({ "sessionIds": detached_sessions }),
                        ));
                        info!(
                            client_id = id.0,
                            session_count = detached_sessions.len(),
                            "Sent client-disconnect detach notification for disconnected client"
                        );
                    }
                    debug!(client_id = id.0, "Client removed");
                    if clients.is_empty() && had_clients && !no_exit_on_disconnect {
                        info!("Leader server shutting down (all clients disconnected)");
                        break;
                    }
                }
                ServerEvent::Message(
                    id,
                    ClientMessage::Control {
                        request_id,
                        command,
                    },
                ) => {
                    if let Some(client) = clients.get(&id) {
                        let client_tx = client.tx.clone();
                        let control_state = control_state.clone();
                        let cancel = cancel.clone();
                        let shutdown_tx = shutdown_tx.clone();
                        let agent_busy = agent_busy.clone();
                        let agent_activity = agent_activity.clone();
                        let relaunching = relaunching.clone();
                        tokio::spawn(async move {
                            let result = match command {
                                ControlCommand::StopCpuProfile => {
                                    handle_stop_cpu_profile(control_state).await
                                }
                                ControlCommand::WorkspaceStart { hub_url, cwd } => {
                                    handle_workspace_start(
                                        control_state,
                                        hub_url,
                                        cwd,
                                        cancel.clone(),
                                    )
                                    .await
                                }
                                ControlCommand::WorkspacePause => {
                                    handle_workspace_pause(control_state).await
                                }
                                ControlCommand::WorkspaceResume => {
                                    handle_workspace_resume(control_state).await
                                }
                                ControlCommand::WorkspaceStop => {
                                    handle_workspace_stop(control_state).await
                                }
                                ControlCommand::WorkspaceStatus => {
                                    handle_workspace_status(control_state).await
                                }
                                ControlCommand::RelaunchForUpdate { to_version } => {
                                    decide_relaunch_for_update(
                                        &control_state,
                                        to_version,
                                        &relaunching,
                                    )
                                }
                                ControlCommand::StopForDowngrade { to_version } => {
                                    decide_stop_for_downgrade(
                                        &control_state,
                                        to_version,
                                        &relaunching,
                                    )
                                }
                                other => handle_control_command(&control_state, other),
                            };
                            let arm_relaunch =
                                matches!(result, Ok(ControlPayload::Relaunching { .. }));
                            if let Err(e) = client_tx
                                .send(ServerMessage::ControlResult { request_id, result }.into())
                            {
                                warn!(client_id = id.0, error = %e, "Failed to send control response to client");
                            }
                            if arm_relaunch {
                                spawn_relaunch_drain(
                                    shutdown_tx,
                                    cancel,
                                    agent_busy,
                                    agent_activity,
                                );
                            }
                        });
                    }
                }
                ServerEvent::Message(id, ClientMessage::Acp { payload }) => {
                    apply_board_events(&driver_board, &mut session_driver, &mut held_driver_messages, &clients, &interaction_requests);
                    let mut json: Option<serde_json::Value> = serde_json::from_str(&payload).ok();
                    let mut payload_mutated = false;
                    if !*ready_rx.borrow() {
                        if let Some(error_payload) =
                            json.as_ref().and_then(make_leader_starting_error)
                        {
                            if let Some(client) = clients.get(&id) {
                                let _ = client
                                    .tx
                                    .send(ClientOutbound::Acp(error_payload.into()));
                            }
                            trace!(
                                client_id = id.0,
                                "Returned leader_starting error (not yet ready)"
                            );
                        } else {
                            trace!(
                                client_id = id.0,
                                "Dropped pre-ready notification (leader not yet ready)"
                            );
                        }
                        continue;
                    }
                    // An answer to one of the agent's requests for a session counts only from the client the leader delivered
                    // it to (the session's owner). Another window's answer, e.g. an always-approve window's, never reaches the
                    // agent.
                    if let Some(j) = json.as_mut() {
                        match drop_unadmitted_answers(j, &driver_board, super::drivers::Claimer::Client(id)) {
                            AnswerFilter::DropAll => continue,
                            AnswerFilter::Changed => payload_mutated = true,
                            AnswerFilter::Keep => {}
                        }
                    }
                    if let Some(client) = clients.get(&id)
                        && client.mode == ClientMode::Stdio
                    {
                        last_active_client = Some(id);
                    }
                    // Who owns the session this message names. The token is removed from the request here, always, so
                    // it never reaches the agent; it is only honoured on an attach request. Naming a session, by a
                    // prompt or any other message, never changes its owner: only the events listed in `super::drivers` do.
                    let me = super::drivers::Claimer::Client(id);
                    let presented_token = json.as_mut().and_then(take_reconnect_token);
                    payload_mutated |= presented_token.is_some();
                    let msg_session = json.as_ref().and_then(extract_session_id);
                    let msg_is_attach = json.as_ref().is_some_and(is_session_attach_request);
                    let attach_verdict = match (msg_is_attach, msg_session.as_deref()) {
                        (true, Some(sid)) => Some(driver_board.classify(sid, me, presented_token.as_deref())),
                        _ => None,
                    };
                    if let Some(session_id) = msg_session.clone() {
                        session_subscribers
                            .entry(session_id.clone())
                            .or_default()
                            .insert(id);
                        // Routing only: where a driver-only message goes while the session has no live owner.
                        if driver_board.owner_state(&session_id, me) != super::drivers::OwnerState::Other {
                            session_driver.entry(session_id.clone()).or_insert(id);
                        }
                        backfill_child_routes(
                            &session_id,
                            id,
                            &child_sessions,
                            &mut session_subscribers,
                            &mut session_driver,
                        );
                        // A `session/load` re-checks the relay's trust and the agent re-emits a fresh notice if it is
                        // still refused, so a notice held from an earlier (abandoned) `session/new` is stale: drop it.
                        let held = take_pending_relay_notices(&mut pending_relay_notices, &session_id);
                        let is_attach = json.as_ref().is_some_and(is_session_attach_request);
                        if let Some(client) = clients.get(&id)
                            && !is_attach
                        {
                            for notice in held {
                                let _ = client.tx.send(ClientOutbound::Acp(notice));
                            }
                        }
                    }
                    let foreign_driver_live = attach_verdict == Some(super::drivers::Verdict::Foreign);
                    if let (Some(json), Some(client)) = (json.as_ref(), clients.get_mut(&id)) {
                        if let Some(yolo_mode) = extract_yolo_mode_change(json) {
                            client.capabilities.yolo_mode = yolo_mode;
                            debug!(
                                client_id = id.0,
                                yolo_mode, "Updated client yolo_mode from notification"
                            );
                        }
                        if let Some(auto_mode) = extract_auto_mode_change(json) {
                            client.capabilities.auto_mode = auto_mode;
                            debug!(
                                client_id = id.0,
                                auto_mode, "Updated client auto_mode from notification"
                            );
                        }
                        if let Some(new_model) = extract_model_id_from_set_model(json) {
                            debug!(client_id = id.0, model = %new_model, "Updated client default_model from session/setModel");
                            client.capabilities.default_model = Some(new_model);
                        }
                    }
                    if let (Some(json), Some(client)) = (json.as_mut(), clients.get_mut(&id)) {
                        if !client.initialize_seen {
                            let (injected, was_initialize) =
                                inject_client_identity_into_initialize(json, &client.client_type);
                            payload_mutated |= injected;
                            if was_initialize {
                                client.initialize_seen = true;
                                if client
                                    .capabilities
                                    .default_model
                                    .as_ref()
                                    .is_some_and(|m| !m.is_empty())
                                {
                                    // A missing id leaves it unarmed; an explicit `null` id is a valid JSON-RPC id that `rewrite_request_id`/`parse_response_id` round-trip, so it arms as `Some(Null)`.
                                    client.patch_initialize_request_id = json.get("id").cloned();
                                }
                            }
                        }
                        if let Some(hints) = initialize_startup_hints(json) {
                            client.init_startup_hints = Some(hints);
                        }
                        payload_mutated |=
                            stamp_inbound_client_identity(json, &client.client_type, id);
                        payload_mutated |= inject_session_request_context(
                            json,
                            &client.capabilities,
                            &client.client_type,
                            id,
                        );
                        payload_mutated |=
                            inject_client_startup_hints(json, client.init_startup_hints.as_ref());
                        payload_mutated |= stamp_foreign_driver_flag(json, foreign_driver_live);
                        payload_mutated |= stamp_owner_authority(json, me, &driver_board);
                        // A JSON-RPC batch gets the identity and ownership pass per element, so a forged connection id or
                        // verdict hidden in one is removed like any other.
                        if let serde_json::Value::Array(items) = json {
                            for item in items.iter_mut() {
                                payload_mutated |= stamp_inbound_client_identity(item, &client.client_type, id);
                                payload_mutated |= stamp_owner_authority(item, me, &driver_board);
                            }
                        }
                    } else if json.is_some() && !clients.contains_key(&id) {
                        // Fail closed: a message from a client that is no longer registered cannot be stamped with its
                        // connection identity, and forwarding it unstamped would bypass the ownership checks.
                        debug!(client_id = id.0, "Dropped message from unregistered client");
                        continue;
                    }
                    let rewritten = json.as_mut().and_then(|j| rewrite_request_id(j, id));
                    payload_mutated |= rewritten.is_some();
                    if let Some(json) = json.as_ref()
                        && is_session_attach_request(json)
                        && let Some(load_sid) = extract_session_id(json)
                        && let Some((ns_id, _)) = rewritten.as_ref()
                    {
                        pending_load_by_req.insert(ns_id.clone(), (id, load_sid.clone()));
                        load_live_buffer.entry((id, load_sid)).or_default();
                    }
                    if let (Some(json), Some((ns_id, _))) = (json.as_ref(), rewritten.as_ref()) {
                        let method = json.get("method").and_then(|m| m.as_str()).unwrap_or("");
                        if method == AGENT_METHOD_NAMES.session_new {
                            pending_driver_reqs.insert(
                                ns_id.clone(),
                                DriverReq { client: id, kind: DriverReqKind::New },
                            );
                        } else if let (true, Some(sid)) = (is_session_end_method(method), msg_session.as_ref())
                            && driver_board.owner_state(sid, me) != super::drivers::OwnerState::Other
                        {
                            pending_driver_reqs.insert(
                                ns_id.clone(),
                                DriverReq { client: id, kind: DriverReqKind::End { session_id: sid.clone() } },
                            );
                        } else if let (true, Some(sid)) = (msg_is_attach, msg_session.as_ref()) {
                            // A load nobody else owns claims the session now, not at its response: a request pipelined
                            // right behind it must already see its owner. A failed load undoes the claim.
                            let claim = match attach_verdict {
                                Some(super::drivers::Verdict::Owns { .. }) => {
                                    session_driver.insert(sid.clone(), id);
                                    Some(driver_board.claim(sid, me))
                                }
                                _ => None,
                            };
                            pending_driver_reqs.insert(
                                ns_id.clone(),
                                DriverReq {
                                    client: id,
                                    kind: DriverReqKind::Attach {
                                        session_id: sid.clone(),
                                        foreign: foreign_driver_live,
                                        claim,
                                    },
                                },
                            );
                        }
                    }
                    if rewritten.is_some() {
                        pending_requests += 1;
                        agent_busy.store(true, Ordering::Relaxed);
                    }
                    let outbound = select_outbound_payload(json.as_ref(), payload_mutated, payload);
                    let _ = acp_tx.send(outbound);
                }
                ServerEvent::Message(_, _) => {}
            },
            LeaderServerPoll::Response(payload) => {
                apply_board_events(&driver_board, &mut session_driver, &mut held_driver_messages, &clients, &interaction_requests);
                let mut json: Option<serde_json::Value> = serde_json::from_str(&payload).ok();
                let parsed_response = json.as_mut().and_then(parse_response_id);
                let driver_req = parsed_response
                    .as_ref()
                    .and_then(|(_, rid)| pending_driver_reqs.remove(rid));
                if parsed_response.is_some() {
                    pending_requests = pending_requests.saturating_sub(1);
                    agent_busy.store(pending_requests > 0, Ordering::Relaxed);
                }
                if let Some((orphan_client, ref orphan_req_id)) = parsed_response
                    && !clients.contains_key(&orphan_client)
                {
                    warn!(
                        client_id = orphan_client.0,
                        request_id = orphan_req_id.as_str(),
                        "Dropping RPC response: requesting client disconnected (response orphaned)"
                    );
                    fuigo_telemetry::unified_log::warn(
                        "leader.response.orphaned",
                        None,
                        Some(serde_json::json!({
                            "client_id": orphan_client.0,
                            "request_id": orphan_req_id,
                        })),
                    );
                }
                if let Some((client_id, ref raw_response_id)) = parsed_response
                    && let Some(client) = clients.get_mut(&client_id)
                    && let Some(json) = json.as_mut()
                {
                    if let Some(session_id) = extract_session_id_from_result(json) {
                        session_subscribers
                            .entry(session_id.clone())
                            .or_default()
                            .insert(client_id);
                        if driver_board.owner_state(&session_id, super::drivers::Claimer::Client(client_id))
                            != super::drivers::OwnerState::Other
                        {
                            session_driver
                                .entry(session_id.clone())
                                .or_insert(client_id);
                        }
                        backfill_child_routes(
                            &session_id,
                            client_id,
                            &child_sessions,
                            &mut session_subscribers,
                            &mut session_driver,
                        );
                        trace!(
                            client_id = client_id.0,
                            session_id, "Subscribed client to session from response"
                        );
                    }
                    // Ownership follows the response: a new session is owned by its creator, a load that claimed the
                    // session keeps the claim (and its owner gets the token it presents after a leader reconnect), a
                    // failed one gives the claim back, and a foreign one joins the queue to take the session over.
                    let me = super::drivers::Claimer::Client(client_id);
                    let succeeded = json.get("result").is_some_and(|r| r.is_object());
                    let mut now_owned_session: Option<String> = None;
                    if let Some(req) = driver_req {
                        match req.kind {
                            DriverReqKind::New if succeeded => {
                                if let Some(sid) = extract_session_id_from_result(json) {
                                    let claim = driver_board.claim(&sid, me);
                                    session_driver.insert(sid.clone(), client_id);
                                    if let Some(token) = claim.token.as_deref() {
                                        insert_reconnect_token(json, token);
                                    }
                                    now_owned_session = Some(sid);
                                }
                            }
                            DriverReqKind::New => {}
                            DriverReqKind::Attach { session_id, foreign: false, claim: Some(claim) } => {
                                if succeeded {
                                    if let Some(token) = claim.token.as_deref() {
                                        insert_reconnect_token(json, token);
                                    }
                                    now_owned_session = Some(session_id);
                                } else {
                                    driver_board.rollback(&session_id, me, claim.prev);
                                }
                            }
                            DriverReqKind::Attach { session_id, foreign: true, .. } if succeeded => {
                                driver_board.add_pending(&session_id, client_id);
                            }
                            DriverReqKind::Attach { .. } => {}
                            DriverReqKind::End { session_id } => {
                                if succeeded {
                                    // The session is gone: nobody owns it any more, so the next window to load it is the owner.
                                    driver_board.forget(&session_id);
                                    session_driver.remove(&session_id);
                                    held_driver_messages.remove(&session_id);
                                }
                            }
                        }
                    }
                    if take_initialize_patch_if_matches(&mut client.patch_initialize_request_id, json) {
                        patch_initialize_response_model(json, &client.capabilities.default_model);
                    }
                    let restored_payload: Arc<str> = json.to_string().into();
                    match client.tx.send(ClientOutbound::Acp(restored_payload)) {
                        Ok(()) => {
                            trace!(client_id = client_id.0, "Routed response via request ID");
                        }
                        Err(e) => {
                            warn!(client_id = client_id.0, error = %e, "Failed to send response to client (channel closed)");
                            fuigo_telemetry::unified_log::warn(
                                "leader.response.send_failed",
                                None,
                                Some(serde_json::json!({
                                    "client_id": client_id.0,
                                    "reason": "channel_closed",
                                })),
                            );
                        }
                    }
                    // P130: relay refusals the agent emitted while handling this request come after the response.
                    if let Some(session_id) = extract_session_id_from_result(json) {
                        for notice in take_pending_relay_notices(&mut pending_relay_notices, &session_id) {
                            let _ = client.tx.send(ClientOutbound::Acp(notice));
                        }
                    }
                    if let Some((buf_client, buf_sid)) = pending_load_by_req.remove(raw_response_id)
                    {
                        let replay_cutoff: Option<u64> =
                            load_replay_max_seq.remove(&(buf_client, buf_sid.clone()));
                        if let Some(buffered) =
                            load_live_buffer.remove(&(buf_client, buf_sid.clone()))
                            && let Some(target) = clients.get(&buf_client)
                        {
                            let mut count = 0usize;
                            let mut deduped = 0usize;
                            for (buffered_payload, buffered_seq) in buffered {
                                if let Some(cutoff) = replay_cutoff
                                    && buffered_seq.is_some_and(|s| s <= cutoff)
                                {
                                    deduped += 1;
                                    continue;
                                }
                                if let Err(e) =
                                    target.tx.send(ClientOutbound::Acp(buffered_payload))
                                {
                                    warn!(client_id = buf_client.0, error = %e, "Failed to flush buffered live notification after load (channel closed)");
                                    break;
                                }
                                count += 1;
                            }
                            if count > 0 || deduped > 0 {
                                trace!(
                                    client_id = buf_client.0,
                                    count,
                                    deduped,
                                    "Flushed buffered live notifications after load (replay-overlap dropped)"
                                );
                            }
                        }
                        // Pending modals go to the session's owner only: a window that loaded it as a non-owner neither sees
                        // nor answers them.
                        if let Some(cached) = interaction_requests.get(buf_sid.as_str())
                            && let Some(target) = clients.get(&buf_client)
                            && driver_board.owner_client(owning_session(&child_sessions, &buf_sid)) == Some(buf_client)
                        {
                            let count = cached.len();
                            for req in cached.values() {
                                if let Err(e) = target.tx.send(ClientOutbound::Acp(req.clone()))
                                {
                                    warn!(client_id = buf_client.0, error = %e, "Failed to replay interaction request after load (channel closed)");
                                    break;
                                }
                                if let Some(key) = request_key_of(req) {
                                    driver_board.deliver_request(&key, &buf_sid, super::drivers::Claimer::Client(buf_client));
                                }
                            }
                            if count > 0 {
                                trace!(
                                    client_id = buf_client.0,
                                    count,
                                    session_id = buf_sid.as_str(),
                                    "Replayed pending interaction modals to newly-attached client"
                                );
                            }
                        }
                    }
                    if let Some(sid) = now_owned_session {
                        // The owner was missing (grace, or nobody loaded yet): what was held for it arrives after its response.
                        flush_driver_messages(&mut held_driver_messages, &sid, client_id, &clients, &driver_board);
                    }
                    continue;
                }
                // The relay answered a `session/new` (its responses are not leader-routed): it owns the new session.
                if parsed_response.is_none()
                    && json.as_ref().is_some_and(|j| j.get("method").is_none())
                    && let Some(sid) = json.as_ref().and_then(extract_session_id_from_result)
                    && driver_board.claim_new_for_relay(&sid)
                {
                    debug!(session_id = %sid, "Relay created a session: it owns it");
                }
                // The relay's answer to a load that claimed a session: an error gives the claim back.
                if parsed_response.is_none()
                    && let Some(j) = json.as_ref()
                    && j.get("method").is_none()
                    && let Some(id) = j.get("id").filter(|id| !id.is_null())
                {
                    driver_board.relay_response(&id.to_string(), j.get("result").is_some_and(|r| r.is_object()));
                }
                let payload: Arc<str> = payload.into();
                let json = json;
                if json
                    .as_ref()
                    .is_some_and(is_machine_wide_broadcast_notification)
                {
                    for client in clients.values() {
                        let _ = client.tx.send(ClientOutbound::Acp(payload.clone()));
                    }
                    trace!("Broadcast machine-wide notification to all clients");
                    continue;
                }
                if let Some(target) = json.as_ref().and_then(extract_target_client_id) {
                    if let Some(client) = clients.get(&target) {
                        match json.as_ref().and_then(extract_child_session_event) {
                            Some(ChildSessionEvent::Spawned(child_sid)) => {
                                if let Some(parent) = json.as_ref().and_then(extract_session_id) {
                                    driver_board.note_child(&child_sid, &parent);
                                    child_sessions
                                        .entry(parent)
                                        .or_default()
                                        .insert(child_sid.clone());
                                }
                                debug!(client_id = target.0, child_session_id = %child_sid, "Registered child route from replayed SubagentSpawned");
                                session_subscribers
                                    .entry(child_sid)
                                    .or_default()
                                    .insert(target);
                            }
                            Some(ChildSessionEvent::Finished(child_sid)) => {
                                let emptied =
                                    session_subscribers.get_mut(&child_sid).is_some_and(|subs| {
                                        subs.remove(&target);
                                        subs.is_empty()
                                    });
                                if emptied {
                                    prune_child_route(
                                        &child_sid,
                                        &mut session_subscribers,
                                        &mut session_driver,
                                        &mut child_sessions,
                                    );
                                }
                            }
                            None => {}
                        }
                        let replay_seq = json
                            .as_ref()
                            .and_then(extract_session_id)
                            .zip(json.as_ref().and_then(event_seq_of));
                        match client.tx.send(ClientOutbound::Acp(payload)) {
                            Ok(()) => {
                                if let Some((sid, seq)) = replay_seq {
                                    let entry =
                                        load_replay_max_seq.entry((target, sid)).or_insert(0);
                                    *entry = (*entry).max(seq);
                                }
                                trace!(
                                    client_id = target.0,
                                    "Unicast replay notification to loading client"
                                );
                            }
                            Err(e) => {
                                warn!(client_id = target.0, error = %e, "Failed to unicast replay notification to loading client (channel closed)");
                            }
                        }
                    } else {
                        if let Some(ChildSessionEvent::Finished(child_sid)) =
                            json.as_ref().and_then(extract_child_session_event)
                            && session_subscribers
                                .get(&child_sid)
                                .is_none_or(|subs| subs.is_empty())
                        {
                            prune_child_route(
                                &child_sid,
                                &mut session_subscribers,
                                &mut session_driver,
                                &mut child_sessions,
                            );
                        }
                        if orphan_replay_warned.insert(target) {
                            warn!(
                                client_id = target.0,
                                "Dropping targeted replay notification: loading client disconnected mid-replay (rest of burst logged at trace)"
                            );
                        } else {
                            trace!(
                                client_id = target.0,
                                "Dropping targeted replay notification: loading client disconnected mid-replay"
                            );
                        }
                    }
                    continue;
                }
                let session_id = json.as_ref().and_then(extract_session_id).or_else(|| {
                    json.as_ref()
                        .and_then(extract_session_id_from_prompt_complete)
                });
                // Output for a session the relay owns is the relay's turn running: it keeps the claim from lapsing.
                if let Some(ref sid) = session_id {
                    driver_board.relay_message(owning_session(&child_sessions, sid));
                }
                if let Some(ref sid) = session_id
                    && let Some(tcid) = json
                        .as_ref()
                        .and_then(extract_interaction_resolved_tool_call_id)
                    && let Some(map) = interaction_requests.get_mut(sid.as_str())
                {
                    map.remove(&tcid);
                    if map.is_empty() {
                        interaction_requests.remove(sid.as_str());
                    }
                }
                let is_reverse_request = json
                    .as_ref()
                    .is_some_and(|j| j.get("id").is_some() && j.get("method").is_some());
                let is_inject_prompt = json.as_ref().is_some_and(is_scheduled_task_inject_prompt);
                let is_interaction =
                    is_reverse_request && json.as_ref().is_some_and(is_interaction_request);
                let interaction_cached = is_interaction
                    && session_id.is_some()
                    && json.as_ref().and_then(extract_interaction_tool_call_id).is_some();
                if is_interaction
                    && let Some(ref sid) = session_id
                    && let Some(tcid) = json.as_ref().and_then(extract_interaction_tool_call_id)
                {
                    interaction_requests
                        .entry(sid.clone())
                        .or_default()
                        .insert(tcid, payload.clone());
                }
                // Driver-only messages (every reverse request, the interaction modals included, and scheduled-task prompts)
                // go to ONE client: the session's owner when it is connected, else (not for an interaction, and never while
                // the owner's grace window is open: the owner is expected back) the activity-routed fallback. With no one to
                // take it, it is held for the owner (bounded) and delivered when one is (re)established; a cached
                // interaction is not held twice, the cache is replayed to that owner. Only the client a request was
                // delivered to may answer it (`OwnerBoard::admit_answer`).
                let driver_only = is_reverse_request || is_inject_prompt;
                let request_key = if is_reverse_request { json.as_ref().and_then(request_key) } else { None };
                if driver_only && let Some(ref sid) = session_id {
                    // A subagent's session is owned through its parent.
                    let owning = owning_session(&child_sessions, sid);
                    let in_grace = driver_board.in_grace(owning);
                    if let Some(key) = request_key.as_deref() {
                        driver_board.note_request(key, sid);
                    }
                    // Another party (the relay) owns it: the prompt is theirs alone, never a local window's.
                    if driver_board.relay_owns(owning) {
                        trace!(session_id = sid.as_str(), is_inject = is_inject_prompt, "Driver-only message belongs to the relay, which owns the session; not routed to a local client");
                        // The relay is sent every agent message on its own path; keep a request until it answers, in case
                        // the relay's claim ends first and a promoted local owner has to take it over.
                        if let Some(key) = request_key.as_deref() {
                            driver_board.deliver_request(key, sid, super::drivers::Claimer::Relay);
                            driver_board.hold_for_relay(owning, key, payload.clone());
                        }
                        continue;
                    }
                    let target = driver_board
                        .owner_client(owning)
                        .filter(|c| clients.contains_key(c))
                        .or_else(|| {
                            if in_grace || is_interaction {
                                None
                            } else {
                                session_driver.get(sid.as_str()).copied().filter(|c| clients.contains_key(c))
                            }
                        });
                    if let Some(target_id) = target {
                        if let Some(client) = clients.get(&target_id) {
                            if let Err(e) = client.tx.send(ClientOutbound::Acp(payload.clone())) {
                                warn!(client_id = target_id.0, session_id = sid.as_str(), is_inject = is_inject_prompt, error = %e, "Failed to route driver-only message (channel closed)");
                            } else {
                                if let Some(key) = request_key.as_deref() {
                                    driver_board.deliver_request(key, sid, super::drivers::Claimer::Client(target_id));
                                }
                                trace!(
                                    client_id = target_id.0,
                                    session_id = sid.as_str(),
                                    is_inject = is_inject_prompt,
                                    "Routed driver-only message to the session's owner"
                                );
                            }
                        }
                        continue;
                    } else if in_grace || is_interaction {
                        trace!(session_id = sid.as_str(), is_inject = is_inject_prompt, in_grace, "Holding driver-only message for the session's next owner");
                        if !interaction_cached {
                            hold_driver_message(&mut held_driver_messages, owning, payload.clone());
                        }
                        continue;
                    } else if session_subscribers.contains_key(sid.as_str()) {
                        warn!(
                            session_id = sid.as_str(),
                            is_inject = is_inject_prompt,
                            "Dropping driver-only message: session has no owner and no live driver"
                        );
                        continue;
                    }
                }
                if let Some(ref sid) = session_id
                    && session_subscribers.contains_key(sid.as_str())
                {
                    let child_event = json.as_ref().and_then(extract_child_session_event);
                    let event_seq = json.as_ref().and_then(event_seq_of);
                    if driver_only {
                        // Routed above.
                    } else if let Some(subs) = session_subscribers.get(sid.as_str()) {
                        for &cid in subs.iter() {
                            if let Some(buf) = load_live_buffer.get_mut(&(cid, sid.clone())) {
                                if buf.len() < MAX_BUFFERED_LIVE_PER_LOAD {
                                    buf.push((payload.clone(), event_seq));
                                    trace!(
                                        client_id = cid.0,
                                        session_id = sid.as_str(),
                                        "Buffered live notification during in-flight load"
                                    );
                                    continue;
                                }
                                warn!(
                                    client_id = cid.0,
                                    session_id = sid.as_str(),
                                    "Live buffer for in-flight load exceeded cap; forwarding live (ordering not guaranteed)"
                                );
                            }
                            if let Some(client) = clients.get(&cid) {
                                if let Err(e) =
                                    client.tx.send(ClientOutbound::Acp(payload.clone()))
                                {
                                    warn!(client_id = cid.0, session_id = sid.as_str(), error = %e, "Failed to broadcast notification to subscriber (channel closed)");
                                } else {
                                    trace!(
                                        client_id = cid.0,
                                        session_id = sid.as_str(),
                                        "Broadcast notification to subscriber"
                                    );
                                }
                            }
                        }
                    }
                    match child_event {
                        Some(ChildSessionEvent::Spawned(child_sid)) => {
                            let parent_subs = session_subscribers
                                .get(sid.as_str())
                                .cloned()
                                .unwrap_or_default();
                            info!(child_session_id = %child_sid, subscriber_count = parent_subs.len(), "Registered child session from SubagentSpawned");
                            session_subscribers.insert(child_sid.clone(), parent_subs);
                            if let Some(&driver_id) = session_driver.get(sid.as_str()) {
                                session_driver.insert(child_sid.clone(), driver_id);
                            }
                            driver_board.note_child(&child_sid, sid);
                            child_sessions
                                .entry(sid.clone())
                                .or_default()
                                .insert(child_sid);
                        }
                        Some(ChildSessionEvent::Finished(child_sid)) => {
                            debug!(child_session_id = %child_sid, "Deregistered child session from SubagentFinished");
                            prune_child_route(
                                &child_sid,
                                &mut session_subscribers,
                                &mut session_driver,
                                &mut child_sessions,
                            );
                        }
                        None => {}
                    }
                    continue;
                }
                let is_notification = json.as_ref().is_some_and(|j| j.get("id").is_none());
                let is_relay_session_notification = is_notification
                    && session_id
                        .as_ref()
                        .is_some_and(|s| !session_subscribers.contains_key(s.as_str()));
                if !is_notification {
                    trace!("Dropping non-routable response (likely relay-originated)");
                } else if is_relay_session_notification
                    && let Some(ref sid) = session_id
                    && json.as_ref().is_some_and(is_relay_refusal_notice)
                {
                    // P130: not relay-owned: the notice for a session whose `session/new` is still in flight.
                    trace!(session_id = sid.as_str(), "Holding relay refusal notice until the session's client subscribes");
                    hold_relay_notice(&mut pending_relay_notices, sid, payload);
                } else if is_relay_session_notification {
                    if let Some(ChildSessionEvent::Finished(child_sid)) =
                        json.as_ref().and_then(extract_child_session_event)
                        && session_subscribers
                            .get(&child_sid)
                            .is_none_or(|subs| subs.is_empty())
                    {
                        prune_child_route(
                            &child_sid,
                            &mut session_subscribers,
                            &mut session_driver,
                            &mut child_sessions,
                        );
                    }
                    trace!(
                        "Dropping notification for relay-owned session (already delivered via WS)"
                    );
                } else if let Some(client_id) = last_active_client
                    && let Some(client) = clients.get(&client_id)
                {
                    debug!(
                        client_id = client_id.0,
                        "Using fallback routing to last active client"
                    );
                    if let Err(e) = client.tx.send(ClientOutbound::Acp(payload)) {
                        warn!(client_id = client_id.0, error = %e, "Failed to send notification via fallback routing (channel closed)");
                    }
                } else {
                    debug!("No client available for notification routing, message dropped");
                }
            }
        }
    }
    finalize_workspace_on_shutdown(control_state.clone()).await;
    finalize_cpu_profile_on_shutdown(control_state).await;
    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}
fn spawn_client_handler(
    client_id: ClientId,
    stream: LeaderStream,
    server_rx: mpsc::UnboundedReceiver<ClientOutbound>,
    event_tx: mpsc::UnboundedSender<ServerEvent>,
    cancel: CancellationToken,
    ready_rx: watch::Receiver<bool>,
    control_state: LeaderServerControlState,
) {
    tokio::spawn(async move {
        let result = run_client_session(
            client_id,
            stream,
            server_rx,
            event_tx.clone(),
            cancel,
            ready_rx,
            control_state,
        )
        .await;
        if let Err(e) = &result {
            debug!(client_id = client_id.0, error = %e, "Client session ended");
        }
        let _ = event_tx.send(ServerEvent::Disconnected(client_id));
    });
}
async fn run_client_session(
    client_id: ClientId,
    stream: LeaderStream,
    mut server_rx: mpsc::UnboundedReceiver<ClientOutbound>,
    event_tx: mpsc::UnboundedSender<ServerEvent>,
    cancel: CancellationToken,
    mut ready_rx: watch::Receiver<bool>,
    control_state: LeaderServerControlState,
) -> Result<(), ProtocolError> {
    let (reader, mut writer) = tokio::io::split(stream);
    // P161: one cancel-safe reader for the whole session. The loop below reads inside `select!`, where an outbound
    // write can win mid-frame; `FrameReader` keeps the partial frame instead of dropping it.
    let mut reader = FrameReader::new(reader);
    let msg: ClientMessage =
        match tokio::time::timeout(REGISTRATION_TIMEOUT, reader.read_message()).await {
            Ok(Ok(msg)) => msg,
            Ok(Err(e)) => {
                warn!(client_id = client_id.0, error = %e, "Registration failed");
                return Err(e);
            }
            Err(_) => {
                warn!(
                    client_id = client_id.0,
                    "Registration timeout - client did not register within {:?}",
                    REGISTRATION_TIMEOUT
                );
                let _ = write_message(
                    &mut writer,
                    &ServerMessage::Error {
                        code: 3,
                        message: "Registration timeout".into(),
                    },
                )
                .await;
                return Ok(());
            }
        };
    let (client_type, mode, capabilities, was_ready_at_registration) = match msg {
        ClientMessage::Register {
            client_type,
            mode,
            capabilities,
        } => {
            let ready = *ready_rx.borrow();
            write_message(
                &mut writer,
                &ServerMessage::Registered {
                    client_id: client_id.0,
                    ready,
                    leader_protocol_version: Some(LEADER_PROTOCOL_VERSION),
                    leader_binary_version: Some(
                        control_state.metadata.leader_binary_version.clone(),
                    ),
                    leader_capabilities: Some(control_state.leader_capabilities()),
                },
            )
            .await?;
            (client_type, mode, capabilities, ready)
        }
        _ => {
            write_message(
                &mut writer,
                &ServerMessage::Error {
                    code: 1,
                    message: "Expected Register message".into(),
                },
            )
            .await?;
            return Ok(());
        }
    };
    if !was_ready_at_registration {
        debug!(
            client_id = client_id.0,
            "Client registered before leader ready; waiting for readiness"
        );
        while !*ready_rx.borrow() {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    drain_client_outbound_on_cancel(&mut server_rx, &mut writer).await;
                    return Ok(());
                }
                result = ready_rx.changed() => {
                    if result.is_err() {
                        // Watch sender was dropped (leader shutting down without ready).
                        return Ok(());
                    }
                    // Loop re-checks *ready_rx.borrow() at top; no Ref held across await.
                }
            }
        }
        write_message(&mut writer, &ServerMessage::LeaderReady).await?;
        debug!(
            client_id = client_id.0,
            "Leader ready; sent LeaderReady to client"
        );
    }
    let _ = event_tx.send(ServerEvent::Registered(
        client_id,
        mode,
        capabilities.clone(),
        client_type.clone(),
    ));
    info!(client_id = client_id.0, client_type = %client_type, ?mode, yolo_mode = capabilities.yolo_mode, client_version = ?capabilities.client_version, "Client registered");
    loop {
        tokio::select! {
            biased;

            _ = cancel.cancelled() => {
                drain_client_outbound_on_cancel(&mut server_rx, &mut writer).await;
                break;
            }

            Some(msg) = server_rx.recv() => {
                if write_outbound(&mut writer, &msg).await.is_err() {
                    break;
                }
            }

            msg_result = reader.read_message::<ClientMessage>() => {
                match handle_client_inbound_message(
                    msg_result,
                    client_id,
                    &event_tx,
                    &mut writer,
                )
                .await?
                {
                    ClientSessionAction::Continue => {}
                    ClientSessionAction::Break => break,
                }
            }
        }
    }
    Ok(())
}
enum ClientSessionAction {
    Continue,
    Break,
}
async fn drain_client_outbound_on_cancel<W>(
    server_rx: &mut mpsc::UnboundedReceiver<ClientOutbound>,
    writer: &mut W,
) where
    W: tokio::io::AsyncWrite + Unpin,
{
    for _ in 0..10 {
        if !server_rx.is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    while let Ok(msg) = server_rx.try_recv() {
        if write_outbound(writer, &msg).await.is_err() {
            break;
        }
    }
}
async fn handle_client_inbound_message<W>(
    msg_result: Result<ClientMessage, ProtocolError>,
    client_id: ClientId,
    event_tx: &mpsc::UnboundedSender<ServerEvent>,
    writer: &mut W,
) -> Result<ClientSessionAction, ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    match msg_result {
        Ok(msg @ (ClientMessage::Acp { .. } | ClientMessage::Control { .. })) => {
            let _ = event_tx.send(ServerEvent::Message(client_id, msg));
            Ok(ClientSessionAction::Continue)
        }
        Ok(ClientMessage::Ping) => {
            write_message(writer, &ServerMessage::Pong).await?;
            Ok(ClientSessionAction::Continue)
        }
        Ok(ClientMessage::Disconnect) | Err(ProtocolError::ConnectionClosed) => {
            info!(client_id = client_id.0, "Client disconnected");
            Ok(ClientSessionAction::Break)
        }
        Ok(ClientMessage::Register { .. }) => {
            write_message(
                writer,
                &ServerMessage::Error {
                    code: 2,
                    message: "Already registered".into(),
                },
            )
            .await?;
            Ok(ClientSessionAction::Continue)
        }
        Err(e) => {
            warn!(client_id = client_id.0, error = %e, "Protocol error");
            Ok(ClientSessionAction::Break)
        }
    }
}
/// Broadcast a planned shutdown to all connected clients.
///
/// Sends `ShuttingDown` (advance notice with reason and `delay_ms: 0`) followed immediately by `Shutdown`.
/// Both messages are sent before the server exits, so clients that process the channel quickly will see both.
///
/// `delay_ms` is set to 0 because the server sends `Shutdown` immediately after `ShuttingDown`; there is no actual grace period.
/// The cancel token propagates to client session handlers simultaneously.
/// A sleep between the two messages would let session writers exit before `Shutdown` is delivered.
/// Clients should treat `ShuttingDown` as a signal that `Shutdown` is imminent and prepare their reconnection handlers.
fn broadcast_shutdown(
    clients: &HashMap<ClientId, ClientState>,
    reason: super::protocol::ShutdownReason,
) {
    for client in clients.values() {
        let _ = client.tx.send(
            ServerMessage::ShuttingDown {
                reason: reason.clone(),
                delay_ms: 0,
            }
            .into(),
        );
        let _ = client.tx.send(ServerMessage::Shutdown.into());
    }
}
pub struct ServerHandle {
    pub cancel: CancellationToken,
    /// Receive ACP messages from clients (server routes them here)
    pub acp_rx: mpsc::UnboundedReceiver<String>,
    /// Send ACP responses back (server routes to correct client based on request ID)
    pub response_tx: mpsc::UnboundedSender<String>,
    /// Atomic counter tracking the number of connected clients
    pub client_count: Arc<AtomicUsize>,
    /// Atomic flag: `true` while the agent has pending (in-flight) requests
    pub agent_busy: Arc<AtomicBool>,
    /// Signal the IPC server that the leader is fully ready (socket bound and bounded auth; catalog/settings refresh runs in the background).
    ///
    /// Send `true` once the leader has finished initializing.
    /// Until then, ACP requests receive a `leader_starting` error and ACP notifications are dropped.
    ///
    /// `spawn_leader_server` sends `true` immediately.
    /// Callers that do not need staged startup (e.g. tests, in-process use) get a fully-ready server out of the box.
    /// Production leader startup (`run_leader`) holds this back until bounded auth completes.
    /// (Catalog/settings are no longer prefetched; they refresh in the background.)
    pub ready_tx: watch::Sender<bool>,
    /// Set the shutdown reason before cancelling so clients receive the correct `ShuttingDown` reason.
    /// The default value is [`ShutdownReason::Manual`]; send [`ShutdownReason::AutoUpdate`] before cancelling for auto-update shutdowns.
    pub shutdown_tx: watch::Sender<super::protocol::ShutdownReason>,
    /// Observe relay demand: flips to `true` when the first headless client registers (see `relay_demand_tx` on [`run_leader_server`]).
    pub relay_demand_rx: watch::Receiver<bool>,
    /// Leader-local control metadata and CPU profiling state, exposed for tests.
    pub control_state: LeaderServerControlState,
}
fn default_test_control_state(socket_path: &Path) -> LeaderServerControlState {
    LeaderServerControlState::new(LeaderServerMetadata {
        pid: std::process::id(),
        socket_path: socket_path.to_path_buf(),
        lock_path: socket_path.with_extension("lock"),
        ws_url_suffix: String::new(),
        leader_binary_version: env!("CARGO_PKG_VERSION").to_string(),
    })
}
pub async fn spawn_leader_server(socket_path: PathBuf) -> Result<ServerHandle, ServerError> {
    let control_state = default_test_control_state(&socket_path);
    spawn_leader_server_with(socket_path, control_state).await
}
/// As [`spawn_leader_server`], with the reconnect grace window set to `grace` (tests cannot wait the default 30 s).
#[cfg(test)]
pub(crate) async fn spawn_leader_server_with_grace(
    socket_path: PathBuf,
    grace: Duration,
) -> Result<ServerHandle, ServerError> {
    let control_state = default_test_control_state(&socket_path).with_driver_grace(grace);
    spawn_leader_server_with(socket_path, control_state).await
}
/// As [`spawn_leader_server`], with a caller-built control state (tests shorten the driver grace window with it).
async fn spawn_leader_server_with(
    socket_path: PathBuf,
    control_state: LeaderServerControlState,
) -> Result<ServerHandle, ServerError> {
    let (acp_tx, acp_rx) = mpsc::unbounded_channel();
    let (response_tx, response_rx) = mpsc::unbounded_channel();
    let cancel = CancellationToken::new();
    let client_count = Arc::new(AtomicUsize::new(0));
    let agent_busy = Arc::new(AtomicBool::new(false));
    let (ready_tx, ready_rx) = watch::channel(true);
    let (shutdown_tx, _shutdown_reason_rx) =
        watch::channel(super::protocol::ShutdownReason::Manual);
    let (relay_demand_tx, relay_demand_rx) = watch::channel(false);
    let cancel_clone = cancel.clone();
    let socket_path_clone = socket_path.clone();
    let client_count_clone = client_count.clone();
    let agent_busy_clone = agent_busy.clone();
    let control_state_for_server = control_state.clone();
    let shutdown_tx_for_server = shutdown_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = run_leader_server(
            socket_path_clone,
            acp_tx,
            response_rx,
            cancel_clone,
            false,
            client_count_clone,
            agent_busy_clone,
            AgentActivity::default(),
            ready_rx,
            relay_demand_tx,
            shutdown_tx_for_server,
            None,
            control_state_for_server,
        )
        .await
        {
            error!(error = %e, "Leader server error");
        }
    });
    Ok(ServerHandle {
        cancel,
        acp_rx,
        response_tx,
        client_count,
        agent_busy,
        ready_tx,
        shutdown_tx,
        relay_demand_rx,
        control_state,
    })
}
/// Plaintext `ws://` is allowed only to a canonical loopback hub (`localhost`, `127.0.0.1`, `::1`).
/// The parsed host is compared: `host_str()` brackets IPv6 (`[::1]`), so matching it against `"::1"` never fired.
fn hub_url_allows_insecure_ws(url: &url::Url) -> bool {
    url.scheme() == "ws" && crate::util::is_canonical_loopback_host(url)
}
#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "server_p148_tests.rs"]
mod p148_tests;
