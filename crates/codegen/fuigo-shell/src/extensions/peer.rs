//! `_fuigo/peer/{configure,list,list_held,release}` (packet 13): the ACP surface of peer messaging.
//!
//! An ACP client is the session's OPERATOR surface, not a peer. It can configure the session's admission, see the sessions
//! a peer would see, see the held messages and release or refuse one with the single-use token of that row. It can NOT send:
//! there is no `fuigo/peer/send` (the design allows a human-authored send only from the TUI; see `R-xs-p13.md`). Nothing here
//! builds an envelope or enters a message: the only way a peer message enters a session stays
//! `MessageDeliveryHandle::deliver_peer_message`.
//!
//! Everything is behind `features.peer_messaging`: the dispatch arm and the capability exist only with the flag on, so with
//! it off these methods answer exactly like any unknown method. Every peer-supplied string in a reply or event is
//! `display_escape`d and capped.

use std::collections::{HashSet, VecDeque};
use std::sync::{LazyLock, Mutex};

use agent_client_protocol as acp;
use fuigo_config_types::PeerInboundPolicy;
use fuigo_peer::host::{PeerHost, display_escape};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{ExtResult, parse_params, to_raw_response};
use crate::agent::mvp_agent::MvpAgent;
use crate::session::SessionHandle;
use crate::session::peer_admission::{
    HeldSummary, NoticeKind, OperatorPresence, PeerAdmissionConfig, PeerNotice, ReleaseError, ReleaseOutcome,
};

/// JSON-RPC code of every peer failure; `data.reason` says which.
pub const PEER_ERROR_CODE: i32 = -32011;
pub const METHODS: [&str; 4] = ["_fuigo/peer/configure", "_fuigo/peer/list", "_fuigo/peer/list_held", "_fuigo/peer/release"];
pub const OPERATOR_KINDS: [&str; 3] = ["attended", "may_return", "unattended"];
pub const EVENTS: [&str; 6] = ["peer_held", "peer_released", "peer_refused", "peer_expired", "peer_reheld", "peer_warning"];
const NAME_CAP: usize = 64;
const TEXT_CAP: usize = 200;
const PUMP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// `agentCapabilities._meta["fuigo/capabilities"].peerMessaging`; the caller adds it only with the flag on.
pub(crate) fn capability() -> Value {
    json!({
        "version": 1,
        "methods": METHODS,
        "operatorKinds": OPERATOR_KINDS,
        "events": EVENTS,
        "errorCode": PEER_ERROR_CODE,
        "eventMethod": "fuigo/session_notification",
        "defaultOperator": "unattended",
    })
}

// ---- errors ------------------------------------------------------------------------------------------------------------

fn peer_err(reason: &str, message: &str) -> acp::Error {
    acp::Error::new(PEER_ERROR_CODE, "Peer messaging error").data(crate::acp_error::error_data_with_fields(
        crate::acp_error::AcpErrorKind::SessionUnavailable,
        message,
        json!({ "reason": reason }),
    ))
}

fn release_err(e: ReleaseError) -> acp::Error {
    match e {
        ReleaseError::NoOperator => peer_err("no_operator", "this session's operator kind cannot release or refuse"),
        ReleaseError::NotFound => peer_err("not_found", "no such held message"),
        ReleaseError::BadToken => peer_err("bad_token", "the token is not the current token of that held message"),
        ReleaseError::Expired => peer_err("expired", "the hold ran out"),
        ReleaseError::Unavailable => peer_err("unavailable", "peer messaging is unavailable for this session"),
    }
}

// ---- the session as the client surface sees it -------------------------------------------------------------------------

#[async_trait::async_trait]
pub(crate) trait ClientSession: Send + Sync {
    fn opted_in(&self) -> bool;
    /// The session's own opt-in, ignoring whether a remote client is attached.
    fn client_opted_in(&self) -> bool;
    fn actor_gone(&self) -> bool;
    async fn register(&self);
    async fn configure(&self, config: PeerAdmissionConfig);
    /// Held rows with FRESH tokens (every older token dies).
    async fn list_held(&self) -> Vec<HeldSummary>;
    /// Held rows with empty tokens; voids nothing.
    async fn snapshot(&self) -> Vec<HeldSummary>;
    async fn release(&self, id: &str, token: &str) -> Result<ReleaseOutcome, ReleaseError>;
    async fn refuse(&self, id: &str, token: &str) -> Result<(), ReleaseError>;
    async fn notices(&self) -> Vec<PeerNotice>;
    async fn list(&self, page: u32) -> Result<Value, String>;
}

struct LiveSession {
    id: String,
    handle: SessionHandle,
}

#[async_trait::async_trait]
impl ClientSession for LiveSession {
    fn opted_in(&self) -> bool {
        self.handle.peer_gate.is_opted_in()
    }
    fn client_opted_in(&self) -> bool {
        self.handle.peer_gate.client_opted_in()
    }
    fn actor_gone(&self) -> bool {
        self.handle.peer_actor_gone()
    }
    async fn register(&self) {
        crate::peer_inbox::host::ensure_session_registered(&self.id, self.handle.message_delivery());
    }
    async fn configure(&self, config: PeerAdmissionConfig) {
        self.handle.configure_peer_admission(config).await;
    }
    async fn list_held(&self) -> Vec<HeldSummary> {
        self.handle.list_held_peer_messages().await
    }
    async fn snapshot(&self) -> Vec<HeldSummary> {
        self.handle.peer_held_snapshot().await
    }
    async fn release(&self, id: &str, token: &str) -> Result<ReleaseOutcome, ReleaseError> {
        self.handle.release_peer_message(id, token).await
    }
    async fn refuse(&self, id: &str, token: &str) -> Result<(), ReleaseError> {
        self.handle.reject_peer_message(id, token).await
    }
    async fn notices(&self) -> Vec<PeerNotice> {
        self.handle.take_peer_notices().await
    }
    async fn list(&self, page: u32) -> Result<Value, String> {
        use crate::peer_inbox::tool_host::SessionPeerHost;
        // Read-only: the directory listing needs only the session id. The mode, denial and operator closures are the ones a
        // send would use; this surface never sends.
        let host = SessionPeerHost::new(
            self.id.clone(),
            fuigo_workspace::permission::DenialLog::default(),
            std::sync::Arc::new(|| fuigo_peer::PeerMode::Unknown),
            std::sync::Arc::new(|| None),
            std::sync::Arc::new(|| fuigo_peer::OperatorKind::None),
        );
        render_list_reply(&host, page).await
    }
}

async fn render_list_reply(host: &dyn PeerHost, page: u32) -> Result<Value, String> {
    let me = host.this_session().ok_or_else(|| "this session has no address yet".to_owned())?;
    let p = host.list(page).await.map_err(|e| match e {
        fuigo_peer::host::PeerHostError::Unavailable(r) => display_escape(&r, TEXT_CAP),
        fuigo_peer::host::PeerHostError::Failed => "the session list could not be read".to_owned(),
    })?;
    let rows: Vec<Value> = p
        .rows
        .iter()
        .map(|r| {
            json!({
                "address": r.address.to_string(),
                "name": display_escape(&r.name, NAME_CAP),
                "ref": display_escape(&r.session_ref, NAME_CAP),
                "relation": format!("{:?}", r.relation),
            })
        })
        .collect();
    Ok(json!({
        "self": {
            "address": me.address.to_string(),
            "name": display_escape(&me.name, NAME_CAP),
            "ref": display_escape(&me.session_ref, NAME_CAP),
        },
        "page": page,
        "more": p.more,
        "rows": rows,
        "text": fuigo_peer::host::render_list(&me, page, &p),
    }))
}

// ---- request shapes ----------------------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigureReq {
    session_id: String,
    opt_in: bool,
    #[serde(default)]
    operator: Option<String>,
    #[serde(default)]
    policy: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ListReq {
    session_id: String,
    #[serde(default)]
    page: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HeldReq {
    session_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseReq {
    session_id: String,
    held_id: String,
    token: String,
    #[serde(default)]
    action: Option<String>,
}

fn operator_of(kind: &str) -> Option<OperatorPresence> {
    match kind {
        "attended" => Some(OperatorPresence::Present),
        "may_return" => Some(OperatorPresence::MayReturn),
        "unattended" => Some(OperatorPresence::None),
        _ => None,
    }
}

fn policy_of(p: &str) -> Option<PeerInboundPolicy> {
    match p {
        "accept" => Some(PeerInboundPolicy::Accept),
        "hold" => Some(PeerInboundPolicy::Hold),
        "refuse" => Some(PeerInboundPolicy::Refuse),
        _ => None,
    }
}

// ---- the checks every method makes -------------------------------------------------------------------------------------

/// The host is unavailable for a typed reason (including a remote client attached to the leader, which makes the whole
/// leader unavailable). `NotStarted` is not a refusal.
fn inbox_unavailable() -> Option<String> {
    match crate::peer_inbox::host::peer_inbox_status() {
        crate::peer_inbox::host::PeerInboxStatus::Unavailable { reason } => Some(crate::peer_inbox::host::reason_message(reason)),
        _ => None,
    }
}

fn check_inbox(unavailable: Option<String>) -> Result<(), acp::Error> {
    match unavailable {
        Some(text) => Err(peer_err("unavailable", &text)),
        None => Ok(()),
    }
}

fn check_opted_in(s: &dyn ClientSession) -> Result<(), acp::Error> {
    if !s.opted_in() {
        return Err(peer_err("not_opted_in", "call fuigo/peer/configure with optIn: true first"));
    }
    Ok(())
}

// ---- the methods (pure over the trait, so tests drive them with a real admission store) --------------------------------

pub(crate) async fn configure_impl(
    s: &dyn ClientSession,
    req_value: Value,
    unavailable: Option<String>,
) -> Result<(Value, bool), acp::Error> {
    let req: ConfigureReq = serde_json::from_value(req_value).map_err(crate::acp_error::invalid_params_from)?;
    check_inbox(unavailable)?;
    let (operator, policy) = if req.opt_in {
        let kind = req.operator.as_deref().ok_or_else(|| crate::acp_error::invalid_params("operator is required with optIn: true"))?;
        let op = operator_of(kind).ok_or_else(|| {
            crate::acp_error::invalid_params("operator must be one of attended, may_return, unattended")
        })?;
        let policy = match req.policy.as_deref() {
            None => PeerInboundPolicy::default(),
            Some(p) => policy_of(p).ok_or_else(|| crate::acp_error::invalid_params("policy must be one of accept, hold, refuse"))?,
        };
        (op, policy)
    } else {
        (OperatorPresence::None, PeerInboundPolicy::default())
    };
    if req.opt_in {
        s.register().await;
    }
    s.configure(PeerAdmissionConfig { opted_in: req.opt_in, policy, operator, relay_driven: false }).await;
    // A (re)connecting client starts from nothing: every token handed out before this call dies now (S4.6).
    drop(s.list_held().await);
    Ok((
        json!({
            "sessionId": req.session_id,
            "optIn": req.opt_in,
            "operator": req.operator.filter(|_| req.opt_in).unwrap_or_else(|| "unattended".to_owned()),
            "policy": match policy { PeerInboundPolicy::Accept => "accept", PeerInboundPolicy::Hold => "hold", PeerInboundPolicy::Refuse => "refuse" },
        }),
        req.opt_in,
    ))
}

pub(crate) async fn list_impl(s: &dyn ClientSession, req_value: Value, unavailable: Option<String>) -> Result<Value, acp::Error> {
    let req: ListReq = serde_json::from_value(req_value).map_err(crate::acp_error::invalid_params_from)?;
    check_inbox(unavailable)?;
    check_opted_in(s)?;
    let mut v = s.list(req.page.min(3)).await.map_err(|m| peer_err("unavailable", &m))?;
    v["sessionId"] = json!(req.session_id);
    Ok(v)
}

/// The id a client sees for a held message: opaque and local (a hash of the store's key), never the peer-supplied
/// `message_id`. `BoundedId`/`Envelope::validate` only length-cap that id (`fuigo-peer/src/envelope.rs:114`, `wire.rs:106-112`:
/// non-empty, at most `MAX_ID_BYTES`, any characters), so it could carry control or bidi characters.
pub(crate) fn held_ref(from: &str, message_id: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(from.as_bytes());
    hasher.update(&[0u8]);
    hasher.update(message_id.as_bytes());
    let hex = hasher.finalize().to_hex();
    format!("h-{}", &hex.as_str()[..32])
}

fn held_row(h: &HeldSummary, with_token: bool) -> Value {
    let mut row = json!({
        "heldId": held_ref(&h.from, &h.message_id),
        "from": {
            "ref": display_escape(&h.from_ref, NAME_CAP),
            "name": display_escape(&h.from_name, NAME_CAP),
            "mode": display_escape(&h.from_mode, NAME_CAP),
        },
        "reasons": h.reason_names,
        "detail": h.detail.as_deref().map(|d| display_escape(d, TEXT_CAP)),
        "expiresAt": h.expires_at,
    });
    if with_token {
        row["token"] = json!(h.token);
    }
    row
}

pub(crate) async fn list_held_impl(s: &dyn ClientSession, req_value: Value, unavailable: Option<String>) -> Result<Value, acp::Error> {
    let req: HeldReq = serde_json::from_value(req_value).map_err(crate::acp_error::invalid_params_from)?;
    check_inbox(unavailable)?;
    check_opted_in(s)?;
    // Fresh tokens: asking again voids the ones handed out before.
    let rows: Vec<Value> = s.list_held().await.iter().map(|h| held_row(h, true)).collect();
    Ok(json!({ "sessionId": req.session_id, "held": rows }))
}

pub(crate) async fn release_impl(s: &dyn ClientSession, req_value: Value, unavailable: Option<String>) -> Result<Value, acp::Error> {
    let req: ReleaseReq = serde_json::from_value(req_value).map_err(crate::acp_error::invalid_params_from)?;
    check_inbox(unavailable)?;
    check_opted_in(s)?;
    // The client holds the opaque id; the store is keyed by the peer's own id.
    let key = s.snapshot().await.iter().find(|h| held_ref(&h.from, &h.message_id) == req.held_id).map(|h| h.message_id.clone());
    let key = key.unwrap_or_else(|| req.held_id.clone());
    let shown = display_escape(&req.held_id, TEXT_CAP);
    match req.action.as_deref().unwrap_or("release") {
        "release" => {
            let outcome = s.release(&key, &req.token).await.map_err(release_err)?;
            let (result, expires_at, why) = match outcome {
                ReleaseOutcome::Delivered => ("delivered", None, None),
                ReleaseOutcome::Reheld { expires_at } => ("reheld", Some(expires_at), None),
                ReleaseOutcome::Dropped(r) => ("dropped", None, Some(format!("{r:?}"))),
                ReleaseOutcome::Expired => ("expired", None, None),
            };
            Ok(json!({ "sessionId": req.session_id, "heldId": shown, "action": "release", "result": result, "expiresAt": expires_at, "reason": why }))
        }
        "refuse" => {
            s.refuse(&key, &req.token).await.map_err(release_err)?;
            Ok(json!({ "sessionId": req.session_id, "heldId": shown, "action": "refuse", "result": "refused" }))
        }
        _ => Err(crate::acp_error::invalid_params("action must be release or refuse")),
    }
}

// ---- events ------------------------------------------------------------------------------------------------------------

pub(crate) fn held_event(session_id: &str, h: &HeldSummary, total_held: usize) -> Value {
    json!({
        "sessionId": session_id,
        "update": {
            "sessionUpdate": "peer_held",
            "heldId": held_ref(&h.from, &h.message_id),
            "from": {
                "ref": display_escape(&h.from_ref, NAME_CAP),
                "name": display_escape(&h.from_name, NAME_CAP),
                "mode": display_escape(&h.from_mode, NAME_CAP),
            },
            "reasons": h.reason_names,
            "detail": h.detail.as_deref().map(|d| display_escape(d, TEXT_CAP)),
            "expiresAt": h.expires_at,
            "counts": { "held": total_held },
        }
    })
}

/// One event per notice. Fixed text plus escaped, capped fields; the model's refusal reason (`detail`) is already escaped by the
/// session and is escaped again here.
pub(crate) fn notice_event(session_id: &str, n: &PeerNotice) -> Value {
    let escaped_id = display_escape(&n.message_id, TEXT_CAP);
    let held_id = (!n.message_id.is_empty()).then(|| held_ref(&n.from, &n.message_id));
    let detail = n.detail.as_deref().filter(|_| !matches!(n.kind, NoticeKind::PeerTurnNoReply | NoticeKind::PeerTurnDeclined)).map(|d| display_escape(d, TEXT_CAP));
    // 26-4: the sentence names the sender; `detail` is the sender's `name [ref]`, already escaped by the session with `display_escape`.
    let label = n.detail.as_deref().unwrap_or("a peer session");
    let turn_text = match &n.kind {
        NoticeKind::PeerTurnNoReply => Some(format!("The model ended the turn started by a message from {label} without a reply.")),
        NoticeKind::PeerTurnDeclined => Some(format!("The model declined to act on the message from {label}.")),
        _ => None,
    };
    let (kind, text): (&str, Option<&str>) = match &n.kind {
        NoticeKind::Released => ("peer_released", None),
        NoticeKind::Expired => ("peer_expired", None),
        NoticeKind::Refused(_) | NoticeKind::ModelRefused => ("peer_refused", None),
        NoticeKind::Reheld => ("peer_reheld", None),
        NoticeKind::ProtectedFileChanged => (
            "peer_warning",
            Some("a protected file changed while this session was influenced by a peer message"),
        ),
        NoticeKind::GuardKeptFeatureOff => (
            "peer_warning",
            Some("this session was influenced by a peer message earlier; the guard stays on with peer messaging off"),
        ),
        NoticeKind::LaunderingRefused => (
            "peer_warning",
            Some("a tool request matched a denial carried by a peer message and was refused"),
        ),
        NoticeKind::PeerTurnNoReply | NoticeKind::PeerTurnDeclined => ("peer_warning", turn_text.as_deref()),
        #[allow(unreachable_patterns)]
        _ => ("peer_warning", Some("a peer messaging notice")),
    };
    let mut update = json!({ "sessionUpdate": kind, "heldId": held_id, "detail": detail });
    if let Some(t) = text {
        update["text"] = json!(t);
        // The turn notices carry the sender in the sentence; a subject would only repeat the message id.
        update["subject"] = json!(if turn_text.is_some() { String::new() } else { escaped_id });
    }
    if let NoticeKind::Refused(r) = &n.kind {
        update["reason"] = json!(format!("{r:?}"));
    }
    json!({ "sessionId": session_id, "update": update })
}

/// One tick of the event pump. `known` holds the held ids already announced; `pending` holds notices taken from the session but not
/// yet emitted (kept for the next tick).
pub(crate) async fn pump_once(
    s: &dyn ClientSession,
    session_id: &str,
    known: &mut HashSet<String>,
    pending: &mut VecDeque<PeerNotice>,
    emit: &(dyn Fn(Value) + Send + Sync),
) {
    pump_tick(s, session_id, known, pending, emit, &crate::peer_inbox::driver::remote_attached).await;
}

/// Most notices the pump keeps while it may not emit (same size as the session's notice ring).
const PENDING_NOTICES: usize = 64;

/// `attached` is read synchronously immediately before EACH emit (no await between the check and the emit), so an attach during
/// the awaits below never sends a tick to the new subscriber. Nothing is consumed that is not emitted: a held row is only marked
/// announced when emitted, and taken notices stay in `pending` (emitted first on a later tick) until they are emitted.
pub(crate) async fn pump_tick(
    s: &dyn ClientSession,
    session_id: &str,
    known: &mut HashSet<String>,
    pending: &mut VecDeque<PeerNotice>,
    emit: &(dyn Fn(Value) + Send + Sync),
    attached: &(dyn Fn() -> bool + Sync),
) {
    // S4.1: the leader forwards every session notification to every subscriber, a relay client included, and the gateway cannot
    // address one connection. So while a remote client is attached nothing is emitted (and nothing is consumed: the notices and
    // the rows are announced after it detaches).
    if attached() {
        return;
    }
    let held = s.snapshot().await;
    pending.extend(s.notices().await);
    // Bounded like the session's own notice ring: past the cap the oldest waiting notice goes first.
    while pending.len() > PENDING_NOTICES {
        pending.pop_front();
    }
    for h in &held {
        if known.contains(&held_ref(&h.from, &h.message_id)) {
            continue;
        }
        if attached() {
            return;
        }
        known.insert(held_ref(&h.from, &h.message_id));
        emit(held_event(session_id, h, held.len()));
    }
    known.retain(|id| held.iter().any(|h| &held_ref(&h.from, &h.message_id) == id));
    while let Some(n) = pending.front() {
        if attached() {
            return;
        }
        emit(notice_event(session_id, n));
        pending.pop_front();
    }
}

static PUMPS: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(Default::default);

fn pumps() -> std::sync::MutexGuard<'static, HashSet<String>> {
    PUMPS.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Start the event pump of an opted-in session (one per session). It lives as long as the session's OWN opt-in (a remote client
/// attaching does not end it: it stays alive and silent, and announces the pending rows and notices after the client detaches);
/// it ends when the client opts out or the session is closed; a later opt-in starts it again.
fn start_pump(agent: &MvpAgent, session_id: String, s: std::sync::Arc<dyn ClientSession>) {
    if !pumps().insert(session_id.clone()) {
        return;
    }
    let gateway = agent.gateway.clone();
    let emit = move |params: Value| {
        if let Ok(raw) = serde_json::value::to_raw_value(&params) {
            gateway.forward_fire_and_forget(acp::ExtNotification::new("fuigo/session_notification", raw.into()));
        }
    };
    tokio::spawn(run_pump(s, session_id, emit, PUMP_INTERVAL));
}

async fn run_pump(s: std::sync::Arc<dyn ClientSession>, session_id: String, emit: impl Fn(Value) + Send + Sync, interval: std::time::Duration) {
    let mut known = HashSet::new();
    let mut pending = VecDeque::new();
    loop {
        tokio::time::sleep(interval).await;
        {
            // The decision to stop and the removal of the registry entry are ONE step under the registry lock: an opt-in
            // (which sets the gate before `start_pump`) either is seen here, or finds the entry gone and starts a new pump.
            // The client's own opt-in, not `opted_in()`: that one is false while a remote client is attached.
            let mut registry = pumps();
            if s.actor_gone() || !s.client_opted_in() {
                registry.remove(&session_id);
                break;
            }
        }
        pump_once(s.as_ref(), &session_id, &mut known, &mut pending, &emit).await;
    }
}

// ---- dispatch ----------------------------------------------------------------------------------------------------------

/// Called by the agent only with `features.peer_messaging` on (flag off: the method is unknown, see `acp_agent.rs`).
pub async fn handle(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    let params: Value = parse_params(args)?;
    let sid = params
        .get("sessionId")
        .and_then(Value::as_str)
        .ok_or_else(|| crate::acp_error::invalid_params("sessionId is required"))?
        .to_owned();
    let handle = agent
        .session_handle_waiting_for_load(&acp::SessionId::new(sid.clone()))
        .await
        .ok_or_else(|| crate::acp_error::invalid_params(format!("session not found: {sid}")))?;
    let session: std::sync::Arc<dyn ClientSession> = std::sync::Arc::new(LiveSession { id: sid.clone(), handle });
    let unavailable = inbox_unavailable();
    let method = args.method.as_ref().trim_start_matches('_');
    let reply = match method {
        "fuigo/peer/configure" => {
            let (v, opted_in) = configure_impl(session.as_ref(), params, unavailable).await?;
            if opted_in {
                start_pump(agent, sid, session);
            }
            v
        }
        "fuigo/peer/list" => list_impl(session.as_ref(), params, unavailable).await?,
        "fuigo/peer/list_held" => list_held_impl(session.as_ref(), params, unavailable).await?,
        "fuigo/peer/release" => release_impl(session.as_ref(), params, unavailable).await?,
        other => return Err(crate::acp_error::unknown_ext_method(other)),
    };
    to_raw_response(&reply)
}

#[cfg(test)]
#[path = "peer_tests.rs"]
mod tests;
