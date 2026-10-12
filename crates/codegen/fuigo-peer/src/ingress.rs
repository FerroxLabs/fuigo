//! Ingress bounds for peer messages (S5.1-S5.6), as pure state machines: no I/O, no clock of their own. Every method that
//! depends on time takes `now` (seconds on a monotonic clock) from the caller, so tests advance time without sleeping.
//!
//! [`PeerIngress::admit`] is the step EVERY envelope passes before the admission decision, so a refused message costs nothing in
//! any held store. The per-host totals live in [`HostLedger`]: a reservation is a [`Ticket`] that frees itself on drop, so a
//! message that is promoted, released, rejected, expired or whose session ends can neither leak nor be freed twice.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};

use crate::envelope::Envelope;
use crate::limits::*;
use crate::outcome::{DeliveryOutcome, RejectReason};

/// Length of the rate window (S5.3): one minute.
pub const RATE_WINDOW_SECS: u64 = 60;
/// Longest a rate-table entry may sit idle (S5.3): 10 minutes. Entries whose whole window is empty are dropped as soon as the
/// table is full, which gives no sender a bigger allowance than it already had.
pub const PAIR_IDLE_SECS: u64 = 10 * 60;

/// S5.1 on the receiving side: is a frame of `len` bytes within the cap? The transport packet calls this before it parses.
pub const fn frame_within_limit(len: usize) -> bool {
    len <= MAX_FRAME_BYTES
}

/// S5.1: the refusal for an over-size frame or body.
pub fn check_frame(len: usize) -> Result<(), RejectReason> {
    if frame_within_limit(len) { Ok(()) } else { Err(RejectReason::TooLarge) }
}

/// S5.1: the refusal for an over-size body.
pub fn check_body(len: usize) -> Result<(), RejectReason> {
    if len <= MAX_BODY_BYTES { Ok(()) } else { Err(RejectReason::TooLarge) }
}

/// What kind of turn a send is made from (S5.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnOrigin {
    /// The turn was started by a human prompt.
    Human,
    /// The turn was started or joined by a peer message or a notice.
    Peer,
}

/// S5.6, the sending side: the `hop` to stamp. A send from a human-started turn is hop 0 (a new conversation); a send from a
/// peer-started turn is the incoming hop plus one (the highest one if several joined). The send tool is a later packet.
pub fn next_hop(current_turn_origin: TurnOrigin, incoming_hop: u32) -> u32 {
    match current_turn_origin {
        TurnOrigin::Human => 0,
        TurnOrigin::Peer => incoming_hop.saturating_add(1),
    }
}

/// S5.6, the receiving side: has this hop used up the hop budget? The receiver holds with `loop_guard`.
pub const fn hop_exhausted(hop: u32) -> bool {
    hop >= HOP_BUDGET
}

/// Peer-started turns since the last human prompt, per session (S5.6). A count of admitted peer messages, which is never lower
/// than the number of turns they start, so it errs on the side of holding.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PeerTurnBudget {
    used: u32,
}

impl PeerTurnBudget {
    /// A human prompt arrived: the budget is full again.
    pub fn human_prompt(&mut self) {
        self.used = 0;
    }
    /// True when the next peer message must be held (`loop_guard`).
    pub fn exhausted(&self) -> bool {
        self.used >= PEER_TURN_BUDGET
    }
    /// A peer message was admitted into the queue.
    pub fn consume(&mut self) {
        self.used = self.used.saturating_add(1);
    }
    pub fn used(&self) -> u32 {
        self.used
    }
}

/// The host-wide count of queued-or-held messages and body bytes (S5.2), shared by every session of this process.
#[derive(Debug)]
pub struct HostLedger {
    max_messages: usize,
    max_bytes: usize,
    used: Mutex<(usize, usize)>,
}

impl Default for HostLedger {
    fn default() -> Self {
        Self::with_caps(MAX_MESSAGES_PER_HOST, MAX_BODY_BYTES_PER_HOST)
    }
}

/// The ledger is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostSaturated;

impl HostLedger {
    pub fn with_caps(max_messages: usize, max_bytes: usize) -> Self {
        Self { max_messages, max_bytes, used: Mutex::new((0, 0)) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, (usize, usize)> {
        self.used.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Reserve room for one message of `bytes`; the reservation frees itself when the [`Ticket`] drops.
    pub fn reserve(self: &Arc<Self>, bytes: usize) -> Result<Ticket, HostSaturated> {
        let mut u = self.lock();
        if u.0 + 1 > self.max_messages || u.1.saturating_add(bytes) > self.max_bytes {
            return Err(HostSaturated);
        }
        u.0 += 1;
        u.1 += bytes;
        Ok(Ticket { ledger: Arc::clone(self), bytes })
    }

    /// Account for a message that is already stored and cannot be refused (a re-hold or a stranded row coming back).
    pub fn force(self: &Arc<Self>, bytes: usize) -> Ticket {
        let mut u = self.lock();
        u.0 += 1;
        u.1 += bytes;
        Ticket { ledger: Arc::clone(self), bytes }
    }

    /// `(messages, bytes)` currently reserved.
    pub fn usage(&self) -> (usize, usize) {
        *self.lock()
    }
}

/// One reservation in a [`HostLedger`]. Dropping it frees exactly what it took. `Clone` takes a second reservation, so a copy
/// can never free the original's share.
pub struct Ticket {
    ledger: Arc<HostLedger>,
    bytes: usize,
}

impl Clone for Ticket {
    fn clone(&self) -> Self {
        self.ledger.force(self.bytes)
    }
}

impl fmt::Debug for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ticket").field("bytes", &self.bytes).finish()
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let mut u = self.ledger.lock();
        u.0 = u.0.saturating_sub(1);
        u.1 = u.1.saturating_sub(self.bytes);
    }
}

/// The numbers `PeerIngress` runs on. Tests lower or raise them; production uses `Default`.
#[derive(Debug, Clone, Copy)]
pub struct IngressConfig {
    pub pair_per_minute: usize,
    pub host_per_minute: usize,
    pub pair_table: usize,
    pub remembered_ids: usize,
    pub id_memory_secs: u64,
}

impl Default for IngressConfig {
    fn default() -> Self {
        Self {
            pair_per_minute: RATE_PER_PAIR_PER_MINUTE as usize,
            host_per_minute: RATE_PER_HOST_PER_MINUTE as usize,
            pair_table: RATE_TABLE_ENTRIES,
            remembered_ids: REMEMBERED_MESSAGE_IDS,
            id_memory_secs: MESSAGE_ID_MEMORY_SECS,
        }
    }
}

/// What ingress says about an envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngressVerdict {
    /// Passed the bounds: go on to the admission decision, then call [`PeerIngress::record`].
    Proceed,
    /// Refused here; nothing was stored.
    Refuse(DeliveryOutcome),
    /// This (sender, id) was seen before with the same body: the original outcome. Nothing is delivered again.
    Replay(DeliveryOutcome),
}

type ReplayKey = (u64, String, String);

struct Remembered {
    body_hash: String,
    outcome: DeliveryOutcome,
    expires: u64,
}

/// Sizes of the internal tables (for tests of boundedness).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressSizes {
    pub pairs: usize,
    pub host_log: usize,
    pub replay: usize,
    pub replay_order: usize,
}

/// The per-host ingress state: rate limits (S5.3) and replay memory (S5.4). `receiver` is a small id for the receiving session,
/// so an outcome can never describe another session's traffic.
pub struct PeerIngress {
    cfg: IngressConfig,
    ledger: Arc<HostLedger>,
    pairs: HashMap<(u64, String), VecDeque<u64>>,
    host_log: VecDeque<u64>,
    replay: HashMap<ReplayKey, Remembered>,
    replay_order: VecDeque<(ReplayKey, u64)>,
}

impl Default for PeerIngress {
    fn default() -> Self {
        Self::new(IngressConfig::default(), Arc::new(HostLedger::default()))
    }
}

fn prune(q: &mut VecDeque<u64>, now: u64) {
    while q.front().is_some_and(|&t| t.saturating_add(RATE_WINDOW_SECS) <= now) {
        q.pop_front();
    }
}

impl PeerIngress {
    pub fn new(cfg: IngressConfig, ledger: Arc<HostLedger>) -> Self {
        Self {
            cfg,
            ledger,
            pairs: HashMap::new(),
            host_log: VecDeque::new(),
            replay: HashMap::new(),
            replay_order: VecDeque::new(),
        }
    }

    pub fn ledger(&self) -> Arc<HostLedger> {
        Arc::clone(&self.ledger)
    }

    pub fn sizes(&self) -> IngressSizes {
        IngressSizes {
            pairs: self.pairs.len(),
            host_log: self.host_log.len(),
            replay: self.replay.len(),
            replay_order: self.replay_order.len(),
        }
    }

    /// S5.1, S5.4, S5.3 in that order. `body_hash` is any stable digest of the body (the caller already has one).
    pub fn admit(&mut self, now: u64, receiver: u64, env: &Envelope, body_hash: &str) -> IngressVerdict {
        if let Err(reason) = check_body(env.body.len()) {
            return IngressVerdict::Refuse(DeliveryOutcome::Rejected { reason });
        }
        self.sweep_replay(now);
        let rkey = (receiver, env.from.to_string(), env.message_id.clone());
        if let Some(r) = self.replay.get(&rkey) {
            // A repeat costs a lookup and no rate allowance. The same id with another body is refused (one rule).
            return if r.body_hash == body_hash {
                IngressVerdict::Replay(r.outcome.clone())
            } else {
                IngressVerdict::Refuse(DeliveryOutcome::Rejected { reason: RejectReason::Ambiguous })
            };
        }
        if self.rate_ok(now, receiver, &rkey.1) {
            IngressVerdict::Proceed
        } else {
            IngressVerdict::Refuse(DeliveryOutcome::Rejected { reason: RejectReason::RateLimited })
        }
    }

    /// Both windows are checked before either is charged, so a refusal costs no allowance.
    fn rate_ok(&mut self, now: u64, receiver: u64, sender: &str) -> bool {
        prune(&mut self.host_log, now);
        if self.host_log.len() >= self.cfg.host_per_minute {
            return false;
        }
        let key = (receiver, sender.to_owned());
        if let Some(q) = self.pairs.get_mut(&key) {
            prune(q, now);
            if q.len() >= self.cfg.pair_per_minute {
                return false;
            }
            q.push_back(now);
            self.host_log.push_back(now);
            return true;
        }
        if self.pairs.len() >= self.cfg.pair_table {
            // Full: forget pairs with nothing in their window (they hold a full allowance anyway, so dropping one hands out
            // nothing). Live pairs are never evicted; an unknown pair is refused if none could go.
            self.pairs.retain(|_, q| {
                prune(q, now);
                !q.is_empty()
            });
            if self.pairs.len() >= self.cfg.pair_table {
                return false;
            }
        }
        self.pairs.insert(key, VecDeque::from([now]));
        self.host_log.push_back(now);
        true
    }

    fn sweep_replay(&mut self, now: u64) {
        while let Some((k, exp)) = self.replay_order.front() {
            if *exp > now {
                break;
            }
            if self.replay.get(k).is_some_and(|r| r.expires == *exp) {
                self.replay.remove(k);
            }
            self.replay_order.pop_front();
        }
    }

    /// Remember the outcome of an envelope that passed [`Self::admit`]. Transient refusals (`rate_limited`, `saturated`) and
    /// size refusals are not remembered: a later send with the same id is judged afresh.
    pub fn record(&mut self, now: u64, receiver: u64, from: &str, message_id: &str, body_hash: &str, outcome: &DeliveryOutcome) {
        if matches!(
            outcome,
            DeliveryOutcome::Rejected { reason: RejectReason::RateLimited | RejectReason::Saturated | RejectReason::TooLarge }
        ) {
            return;
        }
        let key = (receiver, from.to_owned(), message_id.to_owned());
        if self.replay.contains_key(&key) {
            return;
        }
        while self.replay.len() >= self.cfg.remembered_ids {
            let Some((k, exp)) = self.replay_order.pop_front() else { break };
            if self.replay.get(&k).is_some_and(|r| r.expires == exp) {
                self.replay.remove(&k);
            }
        }
        let expires = now.saturating_add(self.cfg.id_memory_secs);
        self.replay.insert(key.clone(), Remembered { body_hash: body_hash.to_owned(), outcome: outcome.clone(), expires });
        self.replay_order.push_back((key, expires));
        self.compact();
    }

    fn compact(&mut self) {
        if self.replay_order.len() > self.cfg.remembered_ids.saturating_mul(4).max(16) {
            let replay = &self.replay;
            self.replay_order.retain(|(k, e)| replay.get(k).is_some_and(|r| r.expires == *e));
        }
    }

    /// Forget one remembered id (the delivery it described failed after all).
    pub fn forget(&mut self, receiver: u64, env_from: &str, message_id: &str) {
        self.replay.remove(&(receiver, env_from.to_owned(), message_id.to_owned()));
    }

    /// A session ended: drop its rate pairs and remembered ids. The host window stays (it is the backstop).
    pub fn forget_session(&mut self, receiver: u64) {
        self.pairs.retain(|(r, _), _| *r != receiver);
        self.replay.retain(|(r, _, _), _| *r != receiver);
        let replay = &self.replay;
        self.replay_order.retain(|(k, e)| replay.get(k).is_some_and(|r| r.expires == *e));
    }
}
