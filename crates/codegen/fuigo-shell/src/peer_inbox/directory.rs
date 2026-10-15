//! The sessions a host offers to peers (packet 8d; DESIGN S1.4, S3.6) and the per-connection [`InboxHost`].
//!
//! The ONLY way a message leaves this module is `MessageDeliveryHandle::deliver_peer_message`, which sends one
//! channel command and awaits the session's own admission decision. Nothing here builds a session command, touches
//! a command channel, submits to admission or reaches the host ingress; a source-pin test enforces it.
// Inert until packet 8e wires a host; only the tests construct these.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

use fuigo_peer::limits::{LIST_PAGE_ROWS, MAX_ID_BYTES, MAX_LIST_ROWS};
use fuigo_peer::{
    Address, BoundedId, DeliveryOutcome, Envelope, HostId, NoticeKind, RejectReason, SessionRow, is_valid_display_name,
};

use super::conn::InboxHost;
use super::watch::{SentWatch, WatchTable};
use crate::session::peer_watch::NoticeOut;
use crate::session::message_delivery::{MessageDeliveryHandle, PeerGate};
use crate::session::peer_admission::PeerSubmit;

/// Why a session could not be registered. Fixed variants only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegisterError {
    BadSessionId,
    BadField,
    Full,
}

/// Called with (peer host id from its hello, message id, kind) for each notice. Set by the host in 8e; none by
/// default, in which case a notice is acknowledged and dropped (there is no notice entry in the session yet).
///
/// The sink carries ONLY the typed kind and the bounded id: no free-text field. The id is peer-supplied and is
/// not checked against any outstanding message. 8e must NEVER render a peer-supplied string from it (not the id,
/// not anything derived from it) to a person or a model; match on the typed kind only.
pub(crate) type NoticeSink = Arc<dyn Fn(&HostId, &BoundedId, NoticeKind) + Send + Sync>;

struct Entry {
    incarnation: u64,
    handle: MessageDeliveryHandle,
    name: String,
    session_ref: String,
    /// Opt-in state kept by the session's admission state. A session that is not opted in (or is relay driven) is not
    /// listed and not addressable (S4.1): the registration stays, only the view of it changes.
    gate: Arc<PeerGate>,
}

#[derive(Default)]
struct Inner {
    /// Highest incarnation ever issued per session id. Survives `unregister`, so an old address is never revived.
    counters: HashMap<String, u64>,
    live: BTreeMap<String, Entry>,
    notice_sink: Option<NoticeSink>,
    /// Message ids each session sent (a bounded ring per session), so a notice reaches only the session that sent it.
    sent: HashMap<String, std::collections::VecDeque<Sent>>,
    /// Packet 11: the sender-side watches (`watch.rs`).
    watches: WatchTable,
    /// Where the sessions' watch books put the notices they produce (set by the inbox; the pump sends them).
    notice_out: Option<NoticeOut>,
}

/// One outstanding record of a message a session sent (S9.3): the id, the target it went to and whether it is watched.
struct Sent {
    id: String,
    /// `None` only for a record made by the test-only `note_sent`: its host is not checked.
    target: Option<Address>,
    watch: bool,
    /// A `released` notice for this watched id was already accepted: a second one is a replay and is dropped.
    released_seen: bool,
}

impl Inner {
    /// The session's own sender-side watches go with it.
    fn watches_of_session_removed(&mut self, session_id: &str) {
        for w in self.watches.snapshot().into_iter().filter(|w| w.session_id == session_id) {
            self.watches.remove(&w.message_id);
        }
    }
}

/// Outstanding message ids kept per session.
const SENT_IDS_PER_SESSION: usize = 64;

/// Session id -> (incarnation, delivery handle, list fields) for one host. The incarnation counter lives in memory:
/// the host id is minted per process, so an address from an earlier process names another host anyway.
pub(crate) struct PeerDirectory {
    host_id: HostId,
    inner: Mutex<Inner>,
    /// Armed watches over all sessions of this host (receiver side, S9.1): the host cap.
    watch_total: Arc<AtomicUsize>,
}

impl PeerDirectory {
    pub(crate) fn new(host_id: HostId) -> Arc<Self> {
        Arc::new(Self { host_id, inner: Mutex::new(Inner::default()), watch_total: Arc::default() })
    }

    pub(crate) fn host_id(&self) -> &HostId {
        &self.host_id
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn set_notice_sink(&self, sink: NoticeSink) {
        self.lock().notice_sink = Some(sink);
    }

    /// Offer a session. Raises the incarnation (a re-registered id gets a NEW one) and returns the address.
    pub(crate) fn register(
        &self,
        session_id: &str,
        handle: MessageDeliveryHandle,
        name: &str,
        session_ref: &str,
    ) -> Result<Address, RegisterError> {
        if !is_valid_display_name(name) || session_ref.len() > MAX_ID_BYTES {
            return Err(RegisterError::BadField);
        }
        let mut g = self.lock();
        if !g.live.contains_key(session_id) && g.live.len() >= MAX_LIST_ROWS {
            return Err(RegisterError::Full);
        }
        let gate = handle.peer_gate().clone();
        let next = g.counters.get(session_id).copied().unwrap_or(0).saturating_add(1);
        let address =
            Address::new(self.host_id.as_str(), session_id, next).map_err(|_| RegisterError::BadSessionId)?;
        g.counters.insert(session_id.to_owned(), next);
        // A new incarnation starts with no sent ids: the previous session's ids are not its own.
        g.sent.remove(session_id);
        g.live.insert(
            session_id.to_owned(),
            Entry { incarnation: next, handle, name: name.to_owned(), session_ref: session_ref.to_owned(), gate },
        );
        Ok(address)
    }

    /// Test only: a record with no target, whose host is not checked.
    #[cfg(test)]
    pub(crate) fn note_sent(&self, session_id: &str, message_id: &str) {
        self.note_sent_inner(session_id, message_id, None, false);
    }

    /// Remember that `session_id` sent `message_id` to `target` (packet 9 calls this before it sends). A notice is accepted only
    /// for a recorded id AND only from the host `target` names (S9.3). `watch` also records the watch (packet 11). Bounded: the
    /// oldest id goes first.
    pub(crate) fn note_sent_to(&self, session_id: &str, message_id: &str, target: &Address, watch: bool) {
        self.note_sent_inner(session_id, message_id, Some(target.clone()), watch);
    }

    fn note_sent_inner(&self, session_id: &str, message_id: &str, target: Option<Address>, watch: bool) {
        let pushed_out = {
            let mut g = self.lock();
            if !g.live.contains_key(session_id) {
                return;
            }
            let ring = g.sent.entry(session_id.to_owned()).or_default();
            // A duplicate id is dropped: it must not push a live id out of the ring.
            if ring.iter().any(|m| m.id == message_id) {
                return;
            }
            if ring.len() >= SENT_IDS_PER_SESSION {
                ring.pop_front();
            }
            ring.push_back(Sent { id: message_id.to_owned(), target: target.clone(), watch, released_seen: false });
            match (watch, target) {
                (true, Some(target)) => g.watches.add(SentWatch {
                    session_id: session_id.to_owned(),
                    message_id: message_id.to_owned(),
                    target,
                    since: std::time::Instant::now(),
                    gone_passes: 0,
                }),
                _ => Vec::new(),
            }
        };
        // Past a cap the oldest watch ends now, locally, as `unavailable` (never unbounded).
        for w in pushed_out {
            self.notify_local(&w.session_id, &w.message_id, Some(NoticeKind::Unavailable));
        }
    }

    /// The send was not accepted (rejected, or answered without a watch): the watch is not outstanding.
    pub(crate) fn forget_watch(&self, message_id: &str) {
        let mut g = self.lock();
        g.watches.remove(message_id);
        for ring in g.sent.values_mut() {
            for s in ring.iter_mut().filter(|s| s.id == message_id) {
                s.watch = false;
            }
        }
    }

    pub(super) fn with_watches<R>(&self, f: impl FnOnce(&mut WatchTable) -> R) -> R {
        f(&mut self.lock().watches)
    }

    /// Whether the session `a` names is registered here under that incarnation.
    pub(super) fn target_alive(&self, a: &Address) -> bool {
        self.lock().live.get(a.session_id()).is_some_and(|e| e.incarnation == a.incarnation())
    }

    pub(crate) fn set_notice_out(&self, tx: NoticeOut) {
        self.lock().notice_out = Some(tx);
    }

    pub(crate) fn take_notice_out(&self) -> Option<NoticeOut> {
        self.lock().notice_out.take()
    }

    fn notice_out(&self) -> Option<NoticeOut> {
        self.lock().notice_out.clone()
    }

    /// The host is shutting down: every outstanding watch or hold record of every session is told `exited` (S9.2).
    pub(crate) fn announce_exit(&self) {
        let books: Vec<_> = self.lock().live.values().map(|e| e.handle.clone()).collect();
        for h in books {
            h.peer_gate().watches.end_all(NoticeKind::Exited);
        }
    }

    /// A local verdict for a session's own record (`None` = `outcome unknown`): the record is consumed and the session told.
    pub(super) fn notify_local(&self, session_id: &str, message_id: &str, kind: Option<NoticeKind>) {
        let (handle, target) = {
            let mut g = self.lock();
            g.watches.remove(message_id);
            let target = g.sent.get_mut(session_id).and_then(|ring| {
                let pos = ring.iter().position(|s| s.id == message_id)?;
                ring.remove(pos).and_then(|s| s.target)
            });
            (g.live.get(session_id).map(|e| e.handle.clone()), target)
        };
        if let Some(h) = handle {
            h.record_sent_notice_wake(message_id, kind, target.map_or_else(|| "(unknown)".to_owned(), |t| t.to_string()));
        }
    }

    /// Deliver a typed notice to the session that sent `message_id`, when the notice comes from the host that message went to
    /// (`peer`); anything else is dropped (acknowledged, no effect).
    pub(super) fn route_notice(&self, message_id: &BoundedId, kind: NoticeKind, peer: Option<&HostId>) {
        // A remote client is attached: acknowledged and dropped, never delivered into a session. The sent id stays, so the
        // notice can still be consumed after detach.
        if crate::peer_inbox::driver::remote_attached() {
            return;
        }
        // Every kind is terminal for its message: the id is consumed, so a second notice for it (a replay, or a flood
        // of one known id) is unknown and dropped instead of filling the session's notice ring. The one exception is
        // `released` for a WATCHED message: the idle notice follows.
        let found = {
            let mut g = self.lock();
            let hit = g.sent.iter().find_map(|(sid, ring)| {
                let s = ring.iter().find(|s| {
                    s.id == message_id.as_str()
                        && s.target.as_ref().is_none_or(|t| peer.is_some_and(|p| *p == HostId::of(t)))
                })?;
                Some((sid.clone(), s.target.clone(), s.watch, s.released_seen))
            });
            hit.and_then(|(sid, target, watch, released_seen)| {
                let keep = watch && kind == NoticeKind::Released;
                if keep {
                    // `released` is accepted at most once per id; the watch stays armed for the final kind.
                    if released_seen {
                        return None;
                    }
                    if let Some(s) = g.sent.get_mut(&sid).and_then(|ring| ring.iter_mut().find(|m| m.id == message_id.as_str())) {
                        s.released_seen = true;
                    }
                } else {
                    if let Some(ring) = g.sent.get_mut(&sid) {
                        ring.retain(|m| m.id != message_id.as_str());
                    }
                    g.watches.remove(message_id.as_str());
                }
                Some((g.live.get(&sid).map(|e| e.handle.clone()), target))
            })
        };
        if let Some((Some(h), target)) = found {
            h.record_sent_notice_wake(
                message_id.as_str(),
                Some(kind),
                target.map_or_else(|| "(unknown)".to_owned(), |t| t.to_string()),
            );
        }
    }

    /// Stop offering a session. Its address is stale from now on, and stays stale if the id registers again.
    pub(crate) fn unregister(&self, session_id: &str) {
        let gone = {
            let mut g = self.lock();
            g.sent.remove(session_id);
            g.watches_of_session_removed(session_id);
            g.live.remove(session_id)
        };
        // Packet 11: a session that ends tells every sender still waiting on it `exited`.
        if let Some(e) = gone {
            e.handle.peer_gate().watches.end_all(NoticeKind::Exited);
        }
    }

    /// Rows `[page * 64, page * 64 + 64)` in session-id order, and whether more follow.
    pub(crate) fn list_page(&self, page: u32) -> (Vec<SessionRow>, bool) {
        let g = self.lock();
        let start = (page as usize).saturating_mul(LIST_PAGE_ROWS);
        // Only opted-in sessions are rows; the page boundaries count those.
        let offered: Vec<SessionRow> = g
            .live
            .iter()
            .filter(|(_, e)| e.gate.is_opted_in())
            .filter_map(|(id, e)| {
                let address = Address::new(self.host_id.as_str(), id, e.incarnation).ok()?;
                Some(SessionRow { address, name: e.name.clone(), session_ref: e.session_ref.clone() })
            })
            .collect();
        let more = offered.len() > start.saturating_add(LIST_PAGE_ROWS);
        (offered.into_iter().skip(start).take(LIST_PAGE_ROWS).collect(), more)
    }

    /// The handle for `to` when it names THIS host and the session's CURRENT incarnation; else `None`.
    fn handle_for(&self, to: &Address) -> Option<MessageDeliveryHandle> {
        if to.host_id() != self.host_id.as_str() {
            return None;
        }
        let g = self.lock();
        let e = g.live.get(to.session_id())?;
        // Not opted in answers exactly like an unknown session: nothing reveals that it exists.
        (e.incarnation == to.incarnation() && e.gate.is_opted_in()).then(|| e.handle.clone())
    }
}

/// The host side of ONE connection. Remembers the host id the peer announced in its hello.
pub(crate) struct ConnHost {
    dir: Arc<PeerDirectory>,
    peer: Mutex<Option<HostId>>,
}

impl ConnHost {
    pub(crate) fn new(dir: Arc<PeerDirectory>) -> Self {
        Self { dir, peer: Mutex::new(None) }
    }

    fn peer(&self) -> Option<HostId> {
        self.peer.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }
}

/// Removes a watch registered by a send that was dropped before it settled (a deadline, a closed connection).
struct UnsettledWatch {
    gate: Arc<crate::session::message_delivery::PeerGate>,
    id: String,
    armed: bool,
}

impl UnsettledWatch {
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for UnsettledWatch {
    fn drop(&mut self) {
        if self.armed {
            self.gate.watches.forget(&self.id);
        }
    }
}

fn rejected(reason: RejectReason) -> DeliveryOutcome {
    DeliveryOutcome::Rejected { reason }
}

impl InboxHost for ConnHost {
    async fn list(&self, page: u32) -> (Vec<SessionRow>, bool) {
        self.dir.list_page(page)
    }

    async fn send(&self, to: Address, envelope: Envelope) -> DeliveryOutcome {
        // Consistency check, NOT a security claim: any same-user process can announce any host id.
        if self.peer().as_ref() != Some(&HostId::of(&envelope.from)) {
            return rejected(RejectReason::Unavailable);
        }
        // Not ours, unknown session or an old incarnation: nothing is delivered.
        let Some(handle) = self.dir.handle_for(&to) else {
            return rejected(RejectReason::Unavailable);
        };
        // The one hand-in point. Delivery is a single unbounded-channel send inside this call; if this future is
        // dropped (deadline, closed connection) before the send it delivers nothing, after the send it has delivered
        // the whole message: there is no partial state.
        match handle.deliver_peer_message(envelope).await {
            PeerSubmit::Outcome(o) => o,
            PeerSubmit::Invalid => rejected(RejectReason::TooLarge),
            PeerSubmit::SessionClosed => rejected(RejectReason::Unavailable),
        }
    }

    async fn send_watched(&self, to: Address, envelope: Envelope, watch: bool) -> DeliveryOutcome {
        // The same consistency check and addressing as `send`; nothing is registered for a message that cannot be addressed.
        if self.peer().as_ref() != Some(&HostId::of(&envelope.from)) {
            return rejected(RejectReason::Unavailable);
        }
        let Some(handle) = self.dir.handle_for(&to) else {
            return rejected(RejectReason::Unavailable);
        };
        let out = self.dir.notice_out();
        let book = &handle.peer_gate().watches;
        let (id, from) = (envelope.message_id.clone(), envelope.from.clone());
        if !watch {
            // A plain record is registered before the send: a held message tells its sender when it is released, expires or is
            // refused (S9.3), and a delivered one lets an explicit refusal (the model's tool) reach the sender while its turn
            // runs. It is dropped silently when that turn ends.
            let Some(out) = out else { return self.send(to, envelope).await };
            book.register_plain(&id, &from, &out);
            let guard = UnsettledWatch { gate: handle.peer_gate().clone(), id: id.clone(), armed: true };
            let outcome = self.send(to, envelope).await;
            let held = matches!(outcome, DeliveryOutcome::Held { .. });
            let rejected_now = !matches!(outcome, DeliveryOutcome::Delivered {} | DeliveryOutcome::Held { .. });
            book.settled(&id, &from, held, rejected_now, &out);
            guard.disarm();
            return outcome;
        }
        // A watch needs a way to send its notice, a free slot (per session: the sender's own oldest ends `unavailable`, else
        // `rate_limited`; per host: refused).
        let Some(out) = out else { return rejected(RejectReason::Unavailable) };
        if envelope.body.is_empty() {
            // Watch-only: the SAME gate as a message (ingress allowance, then the admission decision for this sender). Only an
            // admitted one registers a watch; a would-be hold is refused; nothing is inserted into the conversation.
            return match handle.probe_peer_watch(envelope).await {
                PeerSubmit::Outcome(DeliveryOutcome::Delivered {}) => match book.watch_only(&id, &from, &out, &self.dir.watch_total) {
                    Ok(()) => DeliveryOutcome::Watching {},
                    Err(reason) => rejected(reason),
                },
                PeerSubmit::Outcome(o @ DeliveryOutcome::Rejected { .. }) => o,
                PeerSubmit::Outcome(_) => rejected(RejectReason::PolicyRefused),
                PeerSubmit::Invalid => rejected(RejectReason::TooLarge),
                PeerSubmit::SessionClosed => rejected(RejectReason::Unavailable),
            };
        }
        if let Err(reason) = book.register_watch(&id, &from, &out, &self.dir.watch_total) {
            return rejected(reason);
        }
        // From here until `settled` the record is unbound: if this future is dropped the guard removes it.
        let guard = UnsettledWatch { gate: handle.peer_gate().clone(), id: id.clone(), armed: true };
        let outcome = self.send(to, envelope).await;
        let (held, rejected_now) =
            (matches!(outcome, DeliveryOutcome::Held { .. }), !matches!(outcome, DeliveryOutcome::Delivered {} | DeliveryOutcome::Held { .. }));
        book.settled(&id, &from, held, rejected_now, &out);
        guard.disarm();
        if matches!(outcome, DeliveryOutcome::Delivered {}) { DeliveryOutcome::Watching {} } else { outcome }
    }

    async fn notice(&self, message_id: BoundedId, kind: NoticeKind) {
        self.dir.route_notice(&message_id, kind, self.peer().as_ref());
        let (sink, peer) = (self.dir.lock().notice_sink.clone(), self.peer());
        if let (Some(sink), Some(peer)) = (sink, peer) {
            sink(&peer, &message_id, kind);
        }
    }

    fn peer_hello(&self, host: &HostId) {
        *self.peer.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(host.clone());
    }
}
