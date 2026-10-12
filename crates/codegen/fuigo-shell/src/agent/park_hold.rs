//! P189: hold a parked session's frames at the connection (`_fuigo/session/park`).
//!
//! Every agent-to-client message leaves through the gateway receiver, which hands it to an `acp::Client`.
//! [`ParkHoldClient`] wraps that client. While a session is parked (see `crate::session::quiesce`):
//! - its notifications (`session/update`, `_fuigo/session_notification`, other session-scoped
//!   `_fuigo/*` notifications) are queued in order instead of written, except replay frames
//!   (`_meta.isReplay: true`), which answer the client's own `session/load`;
//! - process-wide notifications (no `sessionId`) are queued too while any session on this connection is
//!   parked, because a client that parked the process treats any frame as unexpected;
//! - its requests (`session/request_permission`, session-scoped `_fuigo/*` requests, terminal and fs
//!   requests) wait, unsent, until unpark. The tool or subagent that asked simply blocks. An explicit
//!   unpark sends them (marked released); an implicit one (`session/prompt`) answers them cancelled,
//!   because they belong to the turn before the park.
//!
//! Every frame and request a release writes carries `_meta["fuigo/released"]: true`, and the release ends
//! with one `_fuigo/session_notification` `{"sessionUpdate":"unparked","released":{"frames":N,"droppedFrames":D}}`.
//!
//! [`ParkFrameHold::release`] writes the queued frames in their original order at unpark, and any frame let
//! through first writes the queued frames that are no longer held, so a frame never overtakes an older one.
//! The check and the write happen on the connection's single thread with no await that yields between them
//! (the connection's writes only enqueue), so a frame is either written before the park acknowledgement or
//! held: none can follow the acknowledgement.

use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};
use std::rc::{Rc, Weak};

use agent_client_protocol as acp;

use crate::session::quiesce;

/// Frames held beyond this are dropped (and counted) so a runaway background task cannot grow memory without bound.
pub(crate) const MAX_HELD_FRAMES: usize = 50_000;

/// `_meta` key set to `true` on every frame (and request) written by a release, so a client can attach it
/// to the turn before the park.
pub(crate) const RELEASED_META_KEY: &str = "fuigo/released";
/// `sessionUpdate` of the marker notification (`_fuigo/session_notification`) written after a release.
pub(crate) const UNPARKED_UPDATE: &str = "unparked";

fn mark_meta(meta: &mut Option<acp::Meta>) {
    meta.get_or_insert_with(acp::Meta::new)
        .insert(RELEASED_META_KEY.to_owned(), serde_json::Value::Bool(true));
}

/// Set `params._meta["fuigo/released"] = true` on a JSON-RPC params object (left unchanged if not an object).
fn mark_params(params: &std::sync::Arc<serde_json::value::RawValue>) -> std::sync::Arc<serde_json::value::RawValue> {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(params.get()) else {
        return params.clone();
    };
    let Some(object) = value.as_object_mut() else {
        return params.clone();
    };
    let meta = object
        .entry("_meta")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if let Some(meta) = meta.as_object_mut() {
        meta.insert(RELEASED_META_KEY.to_owned(), serde_json::Value::Bool(true));
    }
    serde_json::value::to_raw_value(&value)
        .map(std::sync::Arc::from)
        .unwrap_or_else(|_| params.clone())
}

/// Take the internal reverse-call ticket out of `params._meta` (`session::reverse_ticket`): the id, and the params
/// without it (an emptied `_meta` goes too). The one strip point: the ticket is never written to the wire.
fn take_ticket(
    params: &std::sync::Arc<serde_json::value::RawValue>,
) -> (Option<u64>, std::sync::Arc<serde_json::value::RawValue>) {
    use crate::session::reverse_ticket::TICKET_META_KEY;
    if !params.get().contains(TICKET_META_KEY) {
        return (None, params.clone());
    }
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(params.get()) else {
        return (None, params.clone());
    };
    let mut id = None;
    if let Some(object) = value.as_object_mut()
        && let Some(meta) = object.get_mut("_meta").and_then(serde_json::Value::as_object_mut)
    {
        id = meta.remove(TICKET_META_KEY).and_then(|v| v.as_u64());
        if meta.is_empty() {
            object.remove("_meta");
        }
    }
    match serde_json::value::to_raw_value(&value) {
        Ok(raw) => (id, std::sync::Arc::from(raw)),
        Err(_) => (id, empty_raw()),
    }
}

/// What a held request does once its session is no longer parked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestGate {
    /// Not held, or released by an explicit unpark: send it (`released` = it was held).
    Send { released: bool },
    /// Its park ended by an implicit unpark (`session/prompt`): it belongs to the old turn, answer it cancelled.
    Cancel,
}

#[allow(clippy::large_enum_variant, reason = "a held frame is queued once and written once; boxing buys nothing")]
enum HeldFrame {
    Session(acp::SessionNotification),
    Ext {
        notification: acp::ExtNotification,
        session_id: Option<String>,
    },
}

impl HeldFrame {
    fn session_id(&self) -> Option<&str> {
        match self {
            Self::Session(n) => Some(n.session_id.0.as_ref()),
            Self::Ext { session_id, .. } => session_id.as_deref(),
        }
    }
}

#[derive(Default)]
struct HoldState {
    /// Sessions parked through this connection; while non-empty, process-wide frames are held too.
    parked_here: HashSet<String>,
    queue: VecDeque<HeldFrame>,
    dropped: usize,
}

/// What a release wrote out.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ReleaseCounts {
    pub(crate) frames: usize,
    pub(crate) dropped: usize,
}

/// Per-connection frame hold, owned by the agent and shared with its [`ParkHoldClient`].
#[derive(Default)]
pub(crate) struct ParkFrameHold {
    state: RefCell<HoldState>,
    sink: RefCell<Option<Weak<dyn acp::Client>>>,
}

/// The `sessionId` of a JSON-RPC params object, when it has one.
fn params_session_id(params: &serde_json::value::RawValue) -> Option<String> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct WithSession {
        session_id: Option<String>,
    }
    serde_json::from_str::<WithSession>(params.get())
        .ok()
        .and_then(|p| p.session_id)
}

impl ParkFrameHold {
    pub(crate) fn new() -> Rc<Self> {
        Rc::new(Self::default())
    }

    fn attach(&self, sink: Weak<dyn acp::Client>) {
        *self.sink.borrow_mut() = Some(sink);
    }

    /// Start holding process-wide frames for `session_id`'s park. Call in the same synchronous step that
    /// completes the park and before the acknowledgement is returned.
    pub(crate) fn mark_parked(&self, session_id: &str) {
        let mut state = self.state.borrow_mut();
        // Forget parks that ended on another path (the session closed).
        state.parked_here.retain(|id| quiesce::is_self_quiesced(id));
        state.parked_here.insert(session_id.to_owned());
    }

    fn still_held(state: &HoldState, session_id: Option<&str>) -> bool {
        match session_id {
            Some(id) => quiesce::is_parked(id),
            // A root that closed (or was unparked elsewhere) no longer holds this connection's frames.
            None => state.parked_here.iter().any(|id| quiesce::is_parked(id)),
        }
    }

    /// Hold this notification? True while its session (or an ancestor) is parked; for a process-wide frame,
    /// while any session on this connection is parked.
    fn should_hold(&self, session_id: Option<&str>) -> bool {
        Self::still_held(&self.state.borrow(), session_id)
    }
}

/// A replay frame (`_meta.isReplay: true`) answers the client's own `session/load`: never held.
fn is_replay(meta: Option<&serde_json::Value>) -> bool {
    meta.and_then(|m| m.get("isReplay")) == Some(&serde_json::Value::Bool(true))
}

fn session_frame_is_replay(n: &acp::SessionNotification) -> bool {
    n.meta.as_ref().and_then(|m| m.get("isReplay")) == Some(&serde_json::Value::Bool(true))
}

fn ext_frame_is_replay(n: &acp::ExtNotification) -> bool {
    serde_json::from_str::<serde_json::Value>(n.params.get())
        .is_ok_and(|v| is_replay(v.get("_meta")))
}

impl ParkFrameHold {

    fn push(&self, frame: HeldFrame) {
        let mut state = self.state.borrow_mut();
        if state.queue.len() >= MAX_HELD_FRAMES {
            state.dropped += 1;
            return;
        }
        state.queue.push_back(frame);
    }

    /// Frames currently held.
    pub(crate) fn held_frames(&self) -> usize {
        self.state.borrow().queue.len()
    }

    fn pop_releasable(&self) -> Option<HeldFrame> {
        let mut state = self.state.borrow_mut();
        let idx = state
            .queue
            .iter()
            .position(|f| !Self::still_held(&state, f.session_id()))?;
        state.queue.remove(idx)
    }

    /// Write every queued frame that is no longer held, oldest first. Called before any frame is let
    /// through, so a frame never overtakes an older held frame of its session, even when the park ended on
    /// another path (another connection's unpark, or the session closing).
    async fn flush_releasable(&self, sink: &dyn acp::Client) -> usize {
        let mut frames = 0;
        if self.state.borrow().queue.is_empty() {
            return frames;
        }
        while let Some(frame) = self.pop_releasable() {
            frames += 1;
            let sent = match frame {
                HeldFrame::Session(mut n) => {
                    mark_meta(&mut n.meta);
                    sink.session_notification(n).await
                }
                HeldFrame::Ext { notification, .. } => {
                    let params = mark_params(&notification.params);
                    sink.ext_notification(acp::ExtNotification::new(notification.method, params))
                        .await
                }
            };
            if let Err(error) = sent {
                tracing::debug!(%error, "park release: a held frame could not be written");
            }
        }
        frames
    }

    /// Unpark bookkeeping for this connection: stop holding process-wide frames for `session_id`'s park,
    /// write every frame that is no longer held in the order it was produced (each marked
    /// `_meta["fuigo/released"]: true`), then the `unparked` marker. Call after `quiesce::unpark`.
    pub(crate) async fn release(&self, session_id: &str) -> ReleaseCounts {
        let dropped = {
            let mut state = self.state.borrow_mut();
            state.parked_here.remove(session_id);
            if state.parked_here.is_empty() {
                std::mem::take(&mut state.dropped)
            } else {
                0
            }
        };
        let sink = self.sink.borrow().as_ref().and_then(Weak::upgrade);
        let Some(sink) = sink else {
            return ReleaseCounts { frames: 0, dropped };
        };
        let frames = self.flush_releasable(sink.as_ref()).await;
        let marker = serde_json::json!({
            "sessionId": session_id,
            "update": {
                "sessionUpdate": UNPARKED_UPDATE,
                "released": { "frames": frames, "droppedFrames": dropped },
            },
        });
        if let Ok(params) = serde_json::value::to_raw_value(&marker)
            && let Err(error) = sink
                .ext_notification(acp::ExtNotification::new(
                    "fuigo/session_notification",
                    std::sync::Arc::from(params),
                ))
                .await
        {
            tracing::debug!(%error, "park release: the unparked marker could not be written");
        }
        ReleaseCounts { frames, dropped }
    }

    /// Wait until a request for `session_id` may be sent (it and its ancestors are not parked), and say
    /// whether to send it or answer it cancelled (see [`RequestGate`]).
    async fn wait_request_allowed(&self, session_id: Option<&str>) -> RequestGate {
        let Some(session_id) = session_id else {
            // Astra r1 #6: a session-less request waits while a live park holds this connection.
            let mut changes = quiesce::subscribe();
            let mut waited = false;
            while Self::still_held(&self.state.borrow(), None) {
                waited = true;
                if changes.changed().await.is_err() {
                    break;
                }
            }
            return RequestGate::Send { released: waited };
        };
        let Some(root) = quiesce::parked_root(session_id) else {
            return RequestGate::Send { released: false };
        };
        // The cancel generation lives in the registry (dropped with the root, Astra r1 #12) so an implicit
        // unpark through any connection cancels what this one holds.
        let generation = quiesce::cancel_generation(&root);
        let mut changes = quiesce::subscribe();
        while quiesce::is_parked(session_id) {
            if changes.changed().await.is_err() {
                break;
            }
        }
        if quiesce::cancel_generation(&root) != generation {
            RequestGate::Cancel
        } else {
            RequestGate::Send { released: true }
        }
    }
}

/// `method` names `name`, with or without the wire's leading `_`.
fn is_method(method: &str, name: &str) -> bool {
    method.strip_prefix('_').unwrap_or(method) == name.strip_prefix('_').unwrap_or(name)
}

fn empty_raw() -> std::sync::Arc<serde_json::value::RawValue> {
    std::sync::Arc::from(
        serde_json::value::RawValue::from_string("{}".to_owned()).expect("valid JSON"),
    )
}

fn cancelled_request_error() -> acp::Error {
    crate::acp_error::session_unavailable(
        "cancelled: the request belonged to a turn before the session was parked, and a new prompt unparked it",
    )
}

/// The connection's `acp::Client`, with parked sessions' frames held (see the module docs).
pub(crate) struct ParkHoldClient<C> {
    inner: Rc<C>,
    hold: Rc<ParkFrameHold>,
}

impl<C: acp::Client + 'static> ParkHoldClient<C> {
    pub(crate) fn new(inner: C, hold: Rc<ParkFrameHold>) -> Self {
        let inner = Rc::new(inner);
        let erased: Rc<dyn acp::Client> = inner.clone();
        hold.attach(Rc::downgrade(&erased));
        Self { inner, hold }
    }
}

#[async_trait::async_trait(?Send)]
impl<C: acp::Client + 'static> acp::Client for ParkHoldClient<C> {
    async fn request_permission(
        &self,
        args: acp::RequestPermissionRequest,
    ) -> acp::Result<acp::RequestPermissionResponse> {
        let mut args = args;
        let session_id = args.session_id.0.to_string();
        match self.hold.wait_request_allowed(Some(&session_id)).await {
            RequestGate::Cancel => {
                return Ok(acp::RequestPermissionResponse::new(
                    acp::RequestPermissionOutcome::Cancelled,
                ));
            }
            RequestGate::Send { released: true } => mark_meta(&mut args.meta),
            RequestGate::Send { released: false } => {}
        }
        self.inner.request_permission(args).await
    }

    async fn write_text_file(
        &self,
        args: acp::WriteTextFileRequest,
    ) -> acp::Result<acp::WriteTextFileResponse> {
        let mut args = args;
        let session_id = args.session_id.0.to_string();
        match self.hold.wait_request_allowed(Some(&session_id)).await {
            RequestGate::Cancel => return Err(cancelled_request_error()),
            RequestGate::Send { released: true } => mark_meta(&mut args.meta),
            RequestGate::Send { released: false } => {}
        }
        self.inner.write_text_file(args).await
    }

    async fn read_text_file(
        &self,
        args: acp::ReadTextFileRequest,
    ) -> acp::Result<acp::ReadTextFileResponse> {
        let mut args = args;
        let session_id = args.session_id.0.to_string();
        match self.hold.wait_request_allowed(Some(&session_id)).await {
            RequestGate::Cancel => return Err(cancelled_request_error()),
            RequestGate::Send { released: true } => mark_meta(&mut args.meta),
            RequestGate::Send { released: false } => {}
        }
        self.inner.read_text_file(args).await
    }

    async fn create_terminal(
        &self,
        args: acp::CreateTerminalRequest,
    ) -> acp::Result<acp::CreateTerminalResponse> {
        let mut args = args;
        let session_id = args.session_id.0.to_string();
        match self.hold.wait_request_allowed(Some(&session_id)).await {
            RequestGate::Cancel => return Err(cancelled_request_error()),
            RequestGate::Send { released: true } => mark_meta(&mut args.meta),
            RequestGate::Send { released: false } => {}
        }
        self.inner.create_terminal(args).await
    }

    async fn terminal_output(
        &self,
        args: acp::TerminalOutputRequest,
    ) -> acp::Result<acp::TerminalOutputResponse> {
        let mut args = args;
        let session_id = args.session_id.0.to_string();
        match self.hold.wait_request_allowed(Some(&session_id)).await {
            RequestGate::Cancel => return Err(cancelled_request_error()),
            RequestGate::Send { released: true } => mark_meta(&mut args.meta),
            RequestGate::Send { released: false } => {}
        }
        self.inner.terminal_output(args).await
    }

    async fn release_terminal(
        &self,
        args: acp::ReleaseTerminalRequest,
    ) -> acp::Result<acp::ReleaseTerminalResponse> {
        let mut args = args;
        let session_id = args.session_id.0.to_string();
        match self.hold.wait_request_allowed(Some(&session_id)).await {
            RequestGate::Cancel => return Err(cancelled_request_error()),
            RequestGate::Send { released: true } => mark_meta(&mut args.meta),
            RequestGate::Send { released: false } => {}
        }
        self.inner.release_terminal(args).await
    }

    async fn wait_for_terminal_exit(
        &self,
        args: acp::WaitForTerminalExitRequest,
    ) -> acp::Result<acp::WaitForTerminalExitResponse> {
        let mut args = args;
        let session_id = args.session_id.0.to_string();
        match self.hold.wait_request_allowed(Some(&session_id)).await {
            RequestGate::Cancel => return Err(cancelled_request_error()),
            RequestGate::Send { released: true } => mark_meta(&mut args.meta),
            RequestGate::Send { released: false } => {}
        }
        self.inner.wait_for_terminal_exit(args).await
    }

    async fn kill_terminal(
        &self,
        args: acp::KillTerminalRequest,
    ) -> acp::Result<acp::KillTerminalResponse> {
        let mut args = args;
        let session_id = args.session_id.0.to_string();
        match self.hold.wait_request_allowed(Some(&session_id)).await {
            RequestGate::Cancel => return Err(cancelled_request_error()),
            RequestGate::Send { released: true } => mark_meta(&mut args.meta),
            RequestGate::Send { released: false } => {}
        }
        self.inner.kill_terminal(args).await
    }

    async fn session_notification(&self, args: acp::SessionNotification) -> acp::Result<()> {
        if !session_frame_is_replay(&args) && self.hold.should_hold(Some(args.session_id.0.as_ref())) {
            self.hold.push(HeldFrame::Session(args));
            return Ok(());
        }
        self.hold.flush_releasable(&*self.inner).await;
        self.inner.session_notification(args).await
    }

    async fn ext_method(&self, args: acp::ExtRequest) -> acp::Result<acp::ExtResponse> {
        // The one strip point of the internal reverse-call ticket (before anything can write the params).
        let (ticket, params) = take_ticket(&args.params);
        let args = if ticket.is_some() { acp::ExtRequest::new(args.method, params) } else { args };
        // The implicit unpark's gateway barrier: everything queued before it has registered with the hold.
        // Internal: answered here, never written.
        if is_method(&args.method, crate::extensions::session_park::PARK_BARRIER_METHOD) {
            tokio::task::yield_now().await;
            return Ok(acp::ExtResponse::new(empty_raw()));
        }
        let session_id = params_session_id(&args.params);
        // P189 r4 (Astra r3 F5): a reverse MCP call waits on its OWN ticket (its session's park, a parked load's
        // window, its cancellation), not on "any park on this connection". Without a ticket it waits like any
        // session-less request (fail closed). A ticket whose call is over (invoker timeout) is cancelled.
        if let Some(id) = ticket
            && is_method(&args.method, crate::session::acp_mcp::MCP_SDK_CALL_METHOD)
        {
            let admitted = match crate::session::reverse_ticket::lookup(id) {
                Some(t) => t.wait_admitted().await.map_err(|_| ()),
                None => Err(()),
            };
            return match admitted {
                Err(()) => Err(cancelled_request_error()),
                Ok(true) => {
                    let params = mark_params(&args.params);
                    self.inner.ext_method(acp::ExtRequest::new(args.method, params)).await
                }
                Ok(false) => self.inner.ext_method(args).await,
            };
        }
        match self.hold.wait_request_allowed(session_id.as_deref()).await {
            RequestGate::Cancel => Err(cancelled_request_error()),
            RequestGate::Send { released: true } => {
                let params = mark_params(&args.params);
                self.inner
                    .ext_method(acp::ExtRequest::new(args.method, params))
                    .await
            }
            RequestGate::Send { released: false } => self.inner.ext_method(args).await,
        }
    }

    async fn ext_notification(&self, args: acp::ExtNotification) -> acp::Result<()> {
        let session_id = params_session_id(&args.params);
        if !ext_frame_is_replay(&args) && self.hold.should_hold(session_id.as_deref()) {
            self.hold.push(HeldFrame::Ext {
                notification: args,
                session_id,
            });
            return Ok(());
        }
        self.hold.flush_releasable(&*self.inner).await;
        self.inner.ext_notification(args).await
    }
}

#[cfg(test)]
#[path = "park_hold_tests.rs"]
mod tests;
