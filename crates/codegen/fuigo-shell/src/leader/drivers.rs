//! Who OWNS a leader session: the single authority for "who may change this session's mode, model, config, MCP servers,
//! prompt or hooks".
//!
//! The leader decides, in this one place ([`OwnerBoard`]); the agent keeps no copy. The leader stamps its verdict on every
//! owner-gated request (`fuigo/leaderOwnerState`, see [`OwnerState`]) after stripping any client-supplied value, and the
//! agent trusts only that stamp in leader mode.
//!
//! Ownership moves ONLY on:
//! * `session/new`;
//! * a non-foreign `session/load` / `session/resume` (no live owner, or the owner itself);
//! * a reconnect-token reclaim within the grace window;
//! * the pending-claimant rule: connections that loaded the session while it was foreign are queued in load order; when the
//!   owner is gone and its grace window ends (or the relay's claim lapses), the first still-connected queued loader becomes
//!   owner, with no reload.
//!
//! Sending a prompt or any other message for a session never changes ownership: a program that knows a session id gains
//! nothing by naming it.
//!
//! The relay (remote clients, reserved connection id) is an owner like a local client, with a lease: its claim stands only
//! while its last message for the session is younger than [`RELAY_CLAIM_LEASE`], and all relay claims lapse when the relay
//! connection drops.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::protocol::ClientId;

/// How long a session whose owner disconnected waits for that owner's token before the queued claimants are considered.
pub(crate) const DEFAULT_DRIVER_GRACE: Duration = Duration::from_secs(30);

/// A relay claim is valid only while the relay's last message for that session is younger than this (the relay has no
/// per-session connection state the leader could watch).
pub(crate) const RELAY_CLAIM_LEASE: Duration = Duration::from_secs(60);

/// Whose request this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Claimer {
    Client(ClientId),
    Relay,
}

/// The leader's verdict about a requester and a session, as stamped on owner-gated requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OwnerState {
    /// The requester owns the session.
    SelfOwner,
    /// Someone else owns it (a live client, the relay within its lease, or a departed owner within its grace window).
    Other,
    /// Nobody owns it.
    Unowned,
}

impl OwnerState {
    pub(crate) fn wire(self) -> &'static str {
        match self {
            OwnerState::SelfOwner => "self",
            OwnerState::Other => "other",
            OwnerState::Unowned => "none",
        }
    }
}

/// What an attach (`session/load` / `session/resume`) by some requester amounts to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The requester becomes (or stays) the owner. `reclaimed`: it presented the departed owner's token.
    Owns { reclaimed: bool },
    /// Someone else owns the session: the load attaches but changes nothing.
    Foreign,
}

/// Something the board decided on its own (a timer or the relay dropping), for the server loop to act on.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum SettleEvent {
    /// The first still-connected queued claimant took the session over. `token`: the reconnect token minted for it, which
    /// the server loop hands to the new owner (see `LEADER_OWNER_TOKEN_METHOD`).
    Promoted { session_id: String, client: ClientId, token: String },
    /// The owner is gone, its window ended and nobody was queued.
    Vacated { session_id: String },
}

#[derive(Clone, Debug, PartialEq)]
enum Slot {
    /// A live local client.
    Client(ClientId),
    /// The local owner left; only its token reclaims until the deadline.
    Grace(Instant),
    /// The relay, with the time of its last message for the session. `dropped`: the relay connection went away.
    Relay { last: Instant, dropped: bool },
}

#[derive(Clone, Default)]
struct SessionOwner {
    slot: Option<Slot>,
    /// The owner's reconnect token (local owners only).
    token: Option<String>,
    /// Connections that loaded the session while it was foreign, in load order.
    pending: Vec<ClientId>,
}

/// What a session's ownership was before a provisional claim, so a failed load can undo it.
#[derive(Clone, Debug)]
pub(crate) struct Prev(Option<(Slot, Option<String>)>);

/// A claim just made: the owner's reconnect token (local owners) and how to undo it.
pub(crate) struct Claim {
    pub(crate) token: Option<String>,
    pub(crate) prev: Prev,
}

// Reconnect tokens are bearer secrets: these `Debug`s never print them.
impl std::fmt::Debug for SettleEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Promoted { session_id, client, .. } => f
                .debug_struct("Promoted")
                .field("session_id", session_id)
                .field("client", client)
                .field("token", &"<redacted>")
                .finish(),
            Self::Vacated { session_id } => f.debug_struct("Vacated").field("session_id", session_id).finish(),
        }
    }
}

impl std::fmt::Debug for SessionOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionOwner")
            .field("slot", &self.slot)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("pending", &self.pending)
            .finish()
    }
}

impl std::fmt::Debug for Claim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Claim")
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("prev", &self.prev)
            .finish()
    }
}

#[derive(Debug)]
struct BoardState {
    grace: Duration,
    relay_lease: Duration,
    sessions: HashMap<String, SessionOwner>,
    events: Vec<SettleEvent>,
    /// Relay loads awaiting their answer, by JSON-RPC id: the session and what its claim replaced.
    relay_loads: HashMap<String, (String, Prev)>,
    /// Driver-only requests (`fs/*`, ...) sent for sessions the relay owns that the relay has not answered yet, by session:
    /// (JSON-RPC id, the line). The relay gets them straight off the agent's output; this copy is what a promoted local owner
    /// is given if the relay's claim ends first, so the agent's request is not left unanswered.
    relay_inflight: HashMap<String, Vec<(String, Arc<str>)>>,
    /// Prompts the relay sent that the agent has not answered yet: JSON-RPC id -> session. While one is in flight the relay's
    /// claim on that session does not lapse by idleness (a long turn is the relay driving, not the relay idle).
    relay_prompts: HashMap<String, String>,
    /// Ids the relay answered while nothing was held for them (the relay's path is ahead of the server loop), oldest first,
    /// at most `MAX_RELAY_INFLIGHT`. A request whose id is here is already answered: it is never held. Agent request ids are
    /// unique, so this needs no session key. Bounded, so it needs no clearing.
    relay_answered_early: std::collections::VecDeque<String>,
}

/// Most unanswered relay-bound requests kept per session (oldest dropped first).
const MAX_RELAY_INFLIGHT: usize = 64;

/// Shared between the leader server loop and the relay path; cheap to clone.
#[derive(Clone, Debug)]
pub(crate) struct OwnerBoard {
    state: Arc<std::sync::Mutex<BoardState>>,
    wake: Arc<tokio::sync::Notify>,
}

impl Default for OwnerBoard {
    fn default() -> Self {
        Self::new(DEFAULT_DRIVER_GRACE)
    }
}

/// A fresh 128-bit random token (32 hex digits).
fn mint_token() -> String {
    format!("{:032x}", rand::random::<u128>())
}

/// Compare without an early exit on the first differing byte.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff = (a.len() != b.len()) as u8;
    for i in 0..a.len().max(b.len()) {
        diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

fn slot_of(who: Claimer, now: Instant) -> Slot {
    match who {
        Claimer::Client(id) => Slot::Client(id),
        Claimer::Relay => Slot::Relay { last: now, dropped: false },
    }
}

fn owns(slot: &Slot, who: Claimer) -> bool {
    match (slot, who) {
        (Slot::Client(c), Claimer::Client(id)) => *c == id,
        (Slot::Relay { .. }, Claimer::Relay) => true,
        _ => false,
    }
}

/// Make the first queued claimant of `entry` its owner, with a fresh reconnect token, and queue the event. False (nothing
/// changed) when nobody is queued. Queued claimants are always still connected (`client_gone` removes the others).
fn promote_first(sid: &str, entry: &mut SessionOwner, events: &mut Vec<SettleEvent>) -> bool {
    if entry.pending.is_empty() {
        return false;
    }
    let client = entry.pending.remove(0);
    let token = mint_token();
    entry.slot = Some(Slot::Client(client));
    entry.token = Some(token.clone());
    events.push(SettleEvent::Promoted { session_id: sid.to_string(), client, token });
    true
}

impl BoardState {
    /// Apply every expiry that is due: ends of grace windows and lapsed relay claims. A due expiry promotes the first queued
    /// claimant, or vacates the session. Events for the server loop are queued.
    fn settle(&mut self, now: Instant) -> bool {
        let mut changed = false;
        let mut empty: Vec<String> = Vec::new();
        let relay_lease = self.relay_lease;
        let prompts = &self.relay_prompts;
        for (sid, entry) in self.sessions.iter_mut() {
            let due = match entry.slot {
                Some(Slot::Grace(until)) => now >= until,
                Some(Slot::Relay { last, dropped }) => {
                    dropped || (now.saturating_duration_since(last) >= relay_lease && !prompts.values().any(|s| s == sid))
                }
                _ => false,
            };
            if !due {
                continue;
            }
            changed = true;
            entry.token = None;
            if !promote_first(sid, entry, &mut self.events) {
                entry.slot = None;
                self.events.push(SettleEvent::Vacated { session_id: sid.clone() });
                empty.push(sid.clone());
            }
        }
        for sid in empty {
            self.sessions.remove(&sid);
        }
        changed
    }
}

impl OwnerBoard {
    pub(crate) fn new(grace: Duration) -> Self {
        Self {
            state: Arc::new(std::sync::Mutex::new(BoardState { grace, relay_lease: RELAY_CLAIM_LEASE, sessions: HashMap::new(), events: Vec::new(), relay_loads: HashMap::new(), relay_inflight: HashMap::new(), relay_prompts: HashMap::new(), relay_answered_early: std::collections::VecDeque::new() })),
            wake: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Settled view of the state. Wakes the server loop when settling produced events.
    fn state(&self) -> std::sync::MutexGuard<'_, BoardState> {
        let mut st = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.settle(Instant::now()) {
            self.wake.notify_one();
        }
        st
    }

    pub(crate) fn set_grace(&self, grace: Duration) {
        self.state().grace = grace;
    }

    /// Tests cannot wait the real lease.
    #[cfg(test)]
    pub(crate) fn set_relay_lease(&self, lease: Duration) {
        self.state().relay_lease = lease;
    }

    /// Resolves when the board has something for the server loop (events, or a relay drop to settle).
    pub(crate) async fn notified(&self) {
        self.wake.notified().await;
    }

    /// Events the board produced on its own since the last call.
    pub(crate) fn take_events(&self) -> Vec<SettleEvent> {
        std::mem::take(&mut self.state().events)
    }

    /// The earliest moment an expiry is due, for the server loop's timer.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        let st = self.state();
        let lease = st.relay_lease;
        let prompts = &st.relay_prompts;
        st.sessions
            .iter()
            .filter_map(|(sid, e)| match e.slot {
                Some(Slot::Grace(until)) => Some(until),
                // A claim with a prompt in flight has no idle deadline; answering the prompt wakes the loop to compute one.
                Some(Slot::Relay { last, dropped: false }) if !prompts.values().any(|s| s == sid) => Some(last + lease),
                _ => None,
            })
            .min()
    }

    /// What an attach by `who` of `session_id` amounts to, presenting `token` (only a local requester's token counts).
    pub(crate) fn classify(&self, session_id: &str, who: Claimer, token: Option<&str>) -> Verdict {
        let st = self.state();
        let Some(entry) = st.sessions.get(session_id) else {
            return Verdict::Owns { reclaimed: false };
        };
        match &entry.slot {
            None => Verdict::Owns { reclaimed: false },
            Some(slot) if owns(slot, who) => Verdict::Owns { reclaimed: false },
            Some(Slot::Grace(_)) => {
                let presented = matches!(who, Claimer::Client(_))
                    && token
                        .zip(entry.token.as_deref())
                        .is_some_and(|(presented, held)| constant_time_eq(held, presented));
                if presented { Verdict::Owns { reclaimed: true } } else { Verdict::Foreign }
            }
            Some(_) => Verdict::Foreign,
        }
    }

    /// Make `who` the owner of `session_id`. A local owner is issued a fresh reconnect token (any earlier one stops
    /// working). `who` leaves the claimant queue.
    pub(crate) fn claim(&self, session_id: &str, who: Claimer) -> Claim {
        let mut st = self.state();
        let entry = st.sessions.entry(session_id.to_string()).or_default();
        let prev = Prev(entry.slot.clone().map(|s| (s, entry.token.clone())));
        if let Claimer::Client(id) = who {
            entry.pending.retain(|c| *c != id);
        }
        let token = matches!(who, Claimer::Client(_)).then(mint_token);
        entry.slot = Some(slot_of(who, Instant::now()));
        entry.token = token.clone();
        drop(st);
        if who == Claimer::Relay {
            // The loop's timer has to learn of the new deadline (the lease).
            self.wake.notify_one();
        }
        Claim { token, prev }
    }

    /// Undo a provisional claim whose load failed, if `who` still holds it. A relay claim is refreshed, not undone, by
    /// nothing: only local loads are rolled back.
    pub(crate) fn rollback(&self, session_id: &str, who: Claimer, prev: Prev) {
        let mut st = self.state();
        let Some(entry) = st.sessions.get_mut(session_id) else { return };
        if !entry.slot.as_ref().is_some_and(|s| owns(s, who)) {
            return;
        }
        match prev.0 {
            Some((slot, token)) => {
                entry.slot = Some(slot);
                entry.token = token;
            }
            None => {
                entry.slot = None;
                entry.token = None;
                // A foreign loader that queued behind this claim must not be stranded on an unowned session: the first one
                // takes it over now, exactly as at the end of a grace window.
                let mut events = Vec::new();
                if promote_first(session_id, entry, &mut events) {
                    st.events.extend(events);
                    drop(st);
                    self.wake.notify_one();
                } else {
                    st.sessions.remove(session_id);
                }
            }
        }
    }

    /// `client` loaded `session_id` while it was foreign: queue it to take the session over when the owner is gone.
    pub(crate) fn add_pending(&self, session_id: &str, client: ClientId) {
        let mut st = self.state();
        let entry = st.sessions.entry(session_id.to_string()).or_default();
        if !entry.pending.contains(&client) && !matches!(entry.slot, Some(Slot::Client(c)) if c == client) {
            entry.pending.push(client);
        }
    }

    /// The leader's verdict for `who` about `session_id`.
    pub(crate) fn owner_state(&self, session_id: &str, who: Claimer) -> OwnerState {
        let st = self.state();
        match st.sessions.get(session_id).and_then(|e| e.slot.as_ref()) {
            None => OwnerState::Unowned,
            Some(slot) if owns(slot, who) => OwnerState::SelfOwner,
            Some(_) => OwnerState::Other,
        }
    }

    /// The live local owner of `session_id`, if it has one.
    pub(crate) fn owner_client(&self, session_id: &str) -> Option<ClientId> {
        match self.state().sessions.get(session_id).and_then(|e| e.slot.as_ref()) {
            Some(Slot::Client(c)) => Some(*c),
            _ => None,
        }
    }

    /// True while the departed local owner's grace window is open.
    pub(crate) fn in_grace(&self, session_id: &str) -> bool {
        matches!(self.state().sessions.get(session_id).and_then(|e| e.slot.as_ref()), Some(Slot::Grace(_)))
    }

    /// True when the session has no owner right now but connections are queued to take it over.
    pub(crate) fn has_pending(&self, session_id: &str) -> bool {
        self.state().sessions.get(session_id).is_some_and(|e| !e.pending.is_empty())
    }

    /// True when the relay owns the session within its lease.
    pub(crate) fn relay_owns(&self, session_id: &str) -> bool {
        matches!(self.state().sessions.get(session_id).and_then(|e| e.slot.as_ref()), Some(Slot::Relay { .. }))
    }

    /// Sessions `who` owns.
    pub(crate) fn owned_sessions(&self, who: Claimer) -> Vec<String> {
        let st = self.state();
        let mut out: Vec<String> = st
            .sessions
            .iter()
            .filter(|(_, e)| e.slot.as_ref().is_some_and(|s| owns(s, who)))
            .map(|(sid, _)| sid.clone())
            .collect();
        out.sort();
        out
    }

    /// Sessions somebody other than `who` owns (including a departed owner within its grace window).
    pub(crate) fn foreign_owned_sessions(&self, who: Claimer) -> Vec<String> {
        let st = self.state();
        let mut out: Vec<String> = st
            .sessions
            .iter()
            .filter(|(_, e)| e.slot.as_ref().is_some_and(|s| !owns(s, who)))
            .map(|(sid, _)| sid.clone())
            .collect();
        out.sort();
        out
    }

    /// The local client `client` disconnected: sessions it owned enter their grace window (its token stays valid), and it
    /// leaves every claimant queue.
    pub(crate) fn client_gone(&self, client: ClientId) {
        let mut st = self.state();
        let until = Instant::now() + st.grace;
        let mut empty = Vec::new();
        for (sid, entry) in st.sessions.iter_mut() {
            entry.pending.retain(|c| *c != client);
            if entry.slot == Some(Slot::Client(client)) {
                entry.slot = Some(Slot::Grace(until));
            }
            if entry.slot.is_none() && entry.pending.is_empty() {
                empty.push(sid.clone());
            }
        }
        for sid in empty {
            st.sessions.remove(&sid);
        }
        drop(st);
        self.wake.notify_one();
    }

    /// The relay sent a message for `session_id`: refreshes its claim if it holds one. Never creates a claim.
    pub(crate) fn relay_message(&self, session_id: &str) {
        let mut st = self.state();
        if let Some(Slot::Relay { last, dropped: false }) = st.sessions.get_mut(session_id).and_then(|e| e.slot.as_mut()) {
            *last = Instant::now();
        }
    }

    /// The relay created `session_id` (its `session/new` was answered): it owns the session unless somebody already does.
    pub(crate) fn claim_new_for_relay(&self, session_id: &str) -> bool {
        let mut st = self.state();
        let entry = st.sessions.entry(session_id.to_string()).or_default();
        if entry.slot.is_some() {
            return false;
        }
        entry.slot = Some(slot_of(Claimer::Relay, Instant::now()));
        drop(st);
        self.wake.notify_one();
        true
    }

    /// The relay's load request `request_id` just claimed `session_id` (replacing `prev`): remember how to undo it.
    pub(crate) fn note_relay_load(&self, request_id: &str, session_id: &str, prev: Prev) {
        self.state().relay_loads.insert(request_id.to_string(), (session_id.to_string(), prev));
    }

    /// The agent answered the relay's request `request_id`. If it was a load that claimed a session and failed, the
    /// claim is given back (an owner who took the session meanwhile is left alone). Unknown ids are ignored.
    pub(crate) fn relay_response(&self, request_id: &str, succeeded: bool) {
        {
            // One lock: the prompt leaves flight and the idle lease restarts together, so the claim cannot lapse between.
            let mut st = self.state();
            if let Some(sid) = st.relay_prompts.remove(request_id)
                && let Some(Slot::Relay { last, dropped: false }) = st.sessions.get_mut(&sid).and_then(|e| e.slot.as_mut())
            {
                *last = Instant::now();
                drop(st);
                self.wake.notify_one();
            }
        }
        let pending = self.state().relay_loads.remove(request_id);
        if let (Some((session_id, prev)), false) = (pending, succeeded) {
            self.rollback(&session_id, Claimer::Relay, prev);
        }
    }

    /// The relay sent `session/prompt` `request_id` for `session_id`: while the agent has not answered it and the relay owns
    /// the session, the claim does not lapse by idleness. A prompt for a session the relay does not own is not tracked.
    pub(crate) fn relay_prompt_started(&self, request_id: &str, session_id: &str) {
        let mut st = self.state();
        if matches!(st.sessions.get(session_id).and_then(|e| e.slot.as_ref()), Some(Slot::Relay { dropped: false, .. })) {
            st.relay_prompts.insert(request_id.to_string(), session_id.to_string());
        }
    }

    /// The relay connection dropped: every relay claim lapses now.
    pub(crate) fn relay_dropped(&self) {
        let mut st = self.state();
        st.relay_loads.clear();
        st.relay_prompts.clear();
        for entry in st.sessions.values_mut() {
            if let Some(Slot::Relay { dropped, .. }) = entry.slot.as_mut() {
                *dropped = true;
            }
        }
        drop(st);
        self.wake.notify_one();
    }

    /// Keep a copy of a request the relay (the session's owner) was just sent, until it answers.
    pub(crate) fn hold_for_relay(&self, session_id: &str, request_id: &str, payload: Arc<str>) {
        let mut st = self.state();
        // Already answered by the relay before the loop got here: nothing to hold, so nothing to hand over again.
        if let Some(pos) = st.relay_answered_early.iter().position(|id| id == request_id) {
            st.relay_answered_early.remove(pos);
            return;
        }
        let queue = st.relay_inflight.entry(session_id.to_string()).or_default();
        if queue.len() >= MAX_RELAY_INFLIGHT {
            queue.remove(0);
        }
        queue.push((request_id.to_string(), payload));
    }

    /// The relay answered the agent's request `request_id`: it is no longer in flight.
    pub(crate) fn relay_answered(&self, request_id: &str) {
        let mut st = self.state();
        let mut held = false;
        st.relay_inflight.retain(|_, queue| {
            let before = queue.len();
            queue.retain(|(id, _)| id != request_id);
            held |= queue.len() != before;
            !queue.is_empty()
        });
        if !held && !st.relay_answered_early.iter().any(|id| id == request_id) {
            // Not held (yet): remember the answer so a later hold of this id is skipped.
            if st.relay_answered_early.len() >= MAX_RELAY_INFLIGHT {
                st.relay_answered_early.pop_front();
            }
            st.relay_answered_early.push_back(request_id.to_string());
        }
    }

    /// The requests the relay never answered for `session_id`, in order (the relay's claim ended).
    pub(crate) fn take_relay_inflight(&self, session_id: &str) -> Vec<Arc<str>> {
        let queue = self.state().relay_inflight.remove(session_id).unwrap_or_default();
        queue.into_iter().map(|(_, payload)| payload).collect()
    }

    /// The session ended: forget everything about it.
    pub(crate) fn forget(&self, session_id: &str) {
        let mut st = self.state();
        st.sessions.remove(session_id);
        st.relay_inflight.remove(session_id);
        st.relay_prompts.retain(|_, sid| sid != session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn board(grace_ms: u64) -> OwnerBoard {
        OwnerBoard::new(Duration::from_millis(grace_ms))
    }
    const A: ClientId = ClientId(1);
    const B: ClientId = ClientId(2);
    const C: ClientId = ClientId(3);

    #[test]
    fn token_is_128_bit_hex_and_unique() {
        let a = mint_token();
        let b = mint_token();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn constant_time_eq_matches_equality() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(!constant_time_eq("", "a"));
    }

    #[test]
    fn first_claimer_owns_and_a_live_owner_makes_everyone_else_foreign() {
        let b = board(60_000);
        assert_eq!(b.classify("s", Claimer::Client(A), None), Verdict::Owns { reclaimed: false });
        let claim = b.claim("s", Claimer::Client(A));
        assert_eq!(claim.token.as_deref().map(str::len), Some(32));
        assert_eq!(b.classify("s", Claimer::Client(A), None), Verdict::Owns { reclaimed: false });
        assert_eq!(b.classify("s", Claimer::Client(B), None), Verdict::Foreign);
        assert_eq!(b.classify("s", Claimer::Relay, None), Verdict::Foreign);
        assert_eq!(b.owner_state("s", Claimer::Client(A)), OwnerState::SelfOwner);
        assert_eq!(b.owner_state("s", Claimer::Client(B)), OwnerState::Other);
        assert_eq!(b.owner_state("other", Claimer::Client(B)), OwnerState::Unowned);
    }

    #[test]
    fn grace_opens_for_the_owner_and_only_its_token_reclaims() {
        let b = board(60_000);
        let token = b.claim("s", Claimer::Client(A)).token.unwrap();
        b.client_gone(A);
        assert!(b.in_grace("s"));
        assert_eq!(b.owner_state("s", Claimer::Client(B)), OwnerState::Other, "a departed owner's session is still reserved");
        assert_eq!(b.classify("s", Claimer::Client(B), None), Verdict::Foreign);
        assert_eq!(b.classify("s", Claimer::Client(B), Some("wrong")), Verdict::Foreign);
        assert_eq!(b.classify("s", Claimer::Relay, Some(&token)), Verdict::Foreign, "the relay holds no token");
        assert_eq!(b.classify("s", Claimer::Client(B), Some(&token)), Verdict::Owns { reclaimed: true });
        b.claim("s", Claimer::Client(B));
        assert!(!b.in_grace("s"));
        assert_eq!(b.owner_state("s", Claimer::Client(B)), OwnerState::SelfOwner);
    }

    #[test]
    fn rotating_the_token_invalidates_the_old_one() {
        let b = board(60_000);
        let old = b.claim("s", Claimer::Client(A)).token.unwrap();
        let new = b.claim("s", Claimer::Client(A)).token.unwrap();
        b.client_gone(A);
        assert_eq!(b.classify("s", Claimer::Client(B), Some(&old)), Verdict::Foreign);
        assert_eq!(b.classify("s", Claimer::Client(B), Some(&new)), Verdict::Owns { reclaimed: true });
    }

    #[test]
    fn at_grace_expiry_the_first_queued_claimant_becomes_owner_without_reloading() {
        let b = board(30);
        b.claim("s", Claimer::Client(A));
        b.add_pending("s", B);
        b.add_pending("s", C);
        b.add_pending("s", B);
        b.client_gone(A);
        assert!(b.in_grace("s"));
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(b.owner_state("s", Claimer::Client(B)), OwnerState::SelfOwner);
        assert_eq!(b.owner_state("s", Claimer::Client(C)), OwnerState::Other);
        let events = b.take_events();
        let [SettleEvent::Promoted { session_id, client, token }] = events.as_slice() else { panic!("{events:?}") };
        assert_eq!((session_id.as_str(), *client), ("s", B));
        // The promoted owner holds a token: after a blip it (and only it) reclaims the session.
        b.client_gone(B);
        assert_eq!(b.classify("s", Claimer::Client(B), Some(token)), Verdict::Owns { reclaimed: true });
        assert_eq!(b.classify("s", Claimer::Client(C), None), Verdict::Foreign);
    }

    #[test]
    fn a_failed_claim_leaving_the_session_unowned_promotes_the_first_queued_claimant_with_a_token() {
        let b = board(60_000);
        let claim = b.claim("s", Claimer::Client(A));
        b.add_pending("s", B);
        b.add_pending("s", C);
        b.rollback("s", Claimer::Client(A), claim.prev);
        assert_eq!(b.owner_state("s", Claimer::Client(B)), OwnerState::SelfOwner);
        assert_eq!(b.owner_state("s", Claimer::Client(C)), OwnerState::Other);
        let events = b.take_events();
        let [SettleEvent::Promoted { client, token, .. }] = events.as_slice() else { panic!("{events:?}") };
        assert_eq!(*client, B);
        b.client_gone(B);
        assert_eq!(b.classify("s", Claimer::Client(B), Some(token)), Verdict::Owns { reclaimed: true });
    }

    #[test]
    fn a_failed_claim_with_nobody_queued_just_forgets_the_session() {
        let b = board(60_000);
        let claim = b.claim("s", Claimer::Client(A));
        b.rollback("s", Claimer::Client(A), claim.prev);
        assert_eq!(b.owner_state("s", Claimer::Client(A)), OwnerState::Unowned);
        assert!(b.take_events().is_empty());
    }

    #[test]
    fn a_claimant_that_disconnected_is_skipped_and_an_empty_queue_vacates_the_session() {
        let b = board(30);
        b.claim("s", Claimer::Client(A));
        b.add_pending("s", B);
        b.add_pending("s", C);
        b.client_gone(A);
        b.client_gone(B);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(b.owner_state("s", Claimer::Client(C)), OwnerState::SelfOwner);
        b.client_gone(C);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(b.owner_state("s", Claimer::Client(C)), OwnerState::Unowned);
        assert_eq!(b.classify("s", Claimer::Client(B), None), Verdict::Owns { reclaimed: false });
        assert!(b.take_events().iter().any(|e| matches!(e, SettleEvent::Promoted { client, .. } if *client == C)));
    }

    #[test]
    fn sending_messages_never_creates_ownership() {
        let b = board(60_000);
        // The only way in is a claim; naming a session (relay_message, add_pending-less) changes nothing.
        b.relay_message("s");
        assert_eq!(b.owner_state("s", Claimer::Relay), OwnerState::Unowned);
        assert_eq!(b.owner_state("s", Claimer::Client(A)), OwnerState::Unowned);
        b.claim("s", Claimer::Client(B));
        b.relay_message("s");
        assert_eq!(b.owner_state("s", Claimer::Client(B)), OwnerState::SelfOwner);
        assert_eq!(b.owner_state("s", Claimer::Relay), OwnerState::Other);
    }

    #[test]
    fn a_queued_claimant_that_is_already_the_owner_is_not_queued() {
        let b = board(30);
        b.claim("s", Claimer::Client(A));
        b.add_pending("s", A);
        b.client_gone(A);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(b.owner_state("s", Claimer::Client(A)), OwnerState::Unowned);
    }

    #[test]
    fn relay_claim_lapses_when_the_relay_drops_and_hands_over_to_the_queue() {
        let b = board(60_000);
        assert!(b.claim_new_for_relay("s"));
        assert!(!b.claim_new_for_relay("s"), "an existing owner is never displaced");
        assert_eq!(b.classify("s", Claimer::Client(A), None), Verdict::Foreign);
        assert_eq!(b.classify("s", Claimer::Relay, None), Verdict::Owns { reclaimed: false });
        b.add_pending("s", A);
        b.relay_dropped();
        assert_eq!(b.owner_state("s", Claimer::Client(A)), OwnerState::SelfOwner);
        assert_eq!(b.owner_state("s", Claimer::Relay), OwnerState::Other);
    }

    #[test]
    fn relay_claim_without_a_queue_becomes_unowned_so_a_local_load_owns() {
        let b = board(60_000);
        b.claim("s", Claimer::Relay);
        assert_eq!(b.classify("s", Claimer::Client(A), None), Verdict::Foreign);
        b.relay_dropped();
        assert_eq!(b.classify("s", Claimer::Client(A), None), Verdict::Owns { reclaimed: false });
        assert_eq!(b.owner_state("s", Claimer::Relay), OwnerState::Unowned);
    }

    #[test]
    fn relay_claim_lapses_when_idle_past_the_lease_and_messages_keep_it_alive() {
        let b = board(60_000);
        b.set_relay_lease(Duration::from_millis(80));
        b.claim("s", Claimer::Relay);
        b.add_pending("s", A);
        for _ in 0..4 {
            std::thread::sleep(Duration::from_millis(40));
            b.relay_message("s");
        }
        assert_eq!(b.owner_state("s", Claimer::Relay), OwnerState::SelfOwner, "a busy relay keeps its claim past the lease");
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(b.owner_state("s", Claimer::Client(A)), OwnerState::SelfOwner, "an idle relay's claim lapses to the queue");
        assert_eq!(b.owner_state("s", Claimer::Relay), OwnerState::Other);
    }

    #[test]
    fn owned_and_foreign_session_lists() {
        let b = board(60_000);
        b.claim("a1", Claimer::Client(A));
        b.claim("a2", Claimer::Client(A));
        b.claim("b1", Claimer::Client(B));
        b.claim("r1", Claimer::Relay);
        assert_eq!(b.owned_sessions(Claimer::Client(A)), ["a1", "a2"]);
        assert_eq!(b.foreign_owned_sessions(Claimer::Client(A)), ["b1", "r1"]);
        assert_eq!(b.owned_sessions(Claimer::Relay), ["r1"]);
        b.client_gone(B);
        assert_eq!(b.foreign_owned_sessions(Claimer::Client(A)), ["b1", "r1"], "a session in grace is still somebody's");
    }

    #[test]
    fn rollback_undoes_a_failed_provisional_claim_only_while_it_is_held() {
        let b = board(60_000);
        let claim = b.claim("s", Claimer::Client(A));
        b.rollback("s", Claimer::Client(A), claim.prev);
        assert_eq!(b.owner_state("s", Claimer::Client(A)), OwnerState::Unowned);
        let first = b.claim("s", Claimer::Client(A));
        let second = b.claim("s", Claimer::Client(A));
        b.rollback("s", Claimer::Client(A), second.prev);
        assert_eq!(b.owner_state("s", Claimer::Client(A)), OwnerState::SelfOwner, "back to the first claim");
        b.client_gone(A);
        assert_eq!(b.classify("s", Claimer::Client(B), first.token.as_deref()), Verdict::Owns { reclaimed: true });
        // Somebody else holds it now: A's rollback must not take it away.
        let stale = b.claim("s", Claimer::Client(A)).prev;
        b.client_gone(A);
        b.claim("s", Claimer::Client(B));
        b.rollback("s", Claimer::Client(A), stale);
        assert_eq!(b.owner_state("s", Claimer::Client(B)), OwnerState::SelfOwner);
    }

    fn relay_owned(b: &OwnerBoard) {
        assert!(b.claim_new_for_relay("s"));
    }

    #[test]
    fn answer_before_hold_is_never_handed_over() {
        let b = board(50);
        relay_owned(&b);
        b.relay_answered("7");
        b.hold_for_relay("s", "7", Arc::from("req7"));
        assert!(b.take_relay_inflight("s").is_empty());
        // The early answer was consumed by that hold: a different request is held as usual.
        b.hold_for_relay("s", "8", Arc::from("req8"));
        assert_eq!(b.take_relay_inflight("s").len(), 1);
    }

    #[test]
    fn hold_then_answer_is_never_handed_over() {
        let b = board(50);
        relay_owned(&b);
        b.hold_for_relay("s", "7", Arc::from("req7"));
        b.relay_answered("7");
        assert!(b.take_relay_inflight("s").is_empty());
        // A repeat of the answer, or a re-hold of the same id, is not resurrected.
        b.relay_answered("7");
        b.hold_for_relay("s", "7", Arc::from("req7"));
        assert!(b.take_relay_inflight("s").is_empty());
    }

    #[test]
    fn a_drop_between_answer_and_hold_hands_over_nothing_answered() {
        let b = board(50);
        relay_owned(&b);
        b.hold_for_relay("s", "6", Arc::from("req6"));
        b.relay_answered("7");
        b.relay_dropped();
        // 6 was never answered: still handed over. 7 was answered before the drop and is not held afterwards.
        b.hold_for_relay("s", "7", Arc::from("req7"));
        let got = b.take_relay_inflight("s");
        assert_eq!(got.len(), 1);
        assert_eq!(&*got[0], "req6");
    }

    #[test]
    fn early_answers_are_bounded() {
        let b = board(50);
        relay_owned(&b);
        for i in 0..(MAX_RELAY_INFLIGHT + 10) {
            b.relay_answered(&i.to_string());
        }
        assert_eq!(b.state().relay_answered_early.len(), MAX_RELAY_INFLIGHT);
        // The oldest were evicted; the newest are remembered.
        b.hold_for_relay("s", &(MAX_RELAY_INFLIGHT + 9).to_string(), Arc::from("new"));
        b.hold_for_relay("s", "0", Arc::from("old"));
        assert_eq!(b.take_relay_inflight("s").len(), 1);
    }

    #[test]
    fn next_deadline_tracks_grace_windows_and_relay_leases() {
        let b = board(60_000);
        assert!(b.next_deadline().is_none());
        b.claim("s", Claimer::Client(A));
        assert!(b.next_deadline().is_none());
        b.client_gone(A);
        assert!(b.next_deadline().is_some());
        b.claim("r", Claimer::Relay);
        assert!(b.next_deadline().is_some());
    }
}
