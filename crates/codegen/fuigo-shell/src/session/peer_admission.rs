//! Admission of a peer message (peer messaging, packet 4; in-process only): the one decision made before a message reaches the
//! queue, the held store, release tokens, expiry, and the recheck made again when a message is about to enter a turn.
//!
//! A message is NEVER accepted because of anything inside its body: the decision reads only the feature flag, the session's opt-in,
//! the inbound policy, the operator, and the sender's and receiver's modes. Accepting or releasing approves showing the text to the
//! model and nothing else (S2.1, S2.2, S2.4): this module has no access to permissions, prompts or settings.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use fuigo_config_types::PeerInboundPolicy;
use fuigo_peer::limits::{HOLD_EXPIRY_SECS, MAX_BODY_BYTES_PER_SESSION, MAX_MESSAGES_PER_SESSION};
use fuigo_peer::{
    DeliveryOutcome, Envelope, HoldReason, HostLedger, IngressConfig, IngressVerdict, OperatorKind, PeerIngress, PeerMode,
    PeerTurnBudget, RejectReason, Ticket, hop_exhausted,
};
use sha2::{Digest, Sha256};

use super::peer_audit::{AuditCtx, Event as AuditEvent, Outcome as AuditOutcome};

/// A message is identified by (sender address, message id): two senders may reuse an id.
pub type MsgKey = (String, String);

pub fn msg_key(env: &Envelope) -> MsgKey {
    (env.from.to_string(), env.message_id.clone())
}

/// Rows that passed the start-of-turn recheck are remembered (not counted against the bounds) so a repeat check at the same
/// start stays consistent and a stranded interjection can be tracked again.
// must equal fuigo_peer::limits::MAX_CARRIED_KEYS after the merge
pub(crate) const CARRIED_CAP: usize = fuigo_peer::limits::MAX_CARRIED_KEYS;
// The stored (marker) caps live in `fuigo-sampling-types`, which does not depend on `fuigo-peer`; they must equal the live caps
// or a restore / compaction would silently cut what the session holds.
const _: () = assert!(fuigo_sampling_types::MAX_STORED_CARRIED == fuigo_peer::limits::MAX_CARRIED_KEYS);
const _: () = assert!(fuigo_sampling_types::MAX_STORED_KEYS == fuigo_peer::limits::MAX_KEYS_PER_DENIAL);
const _: () = assert!(fuigo_sampling_types::MAX_STORED_DENIALS == fuigo_peer::limits::DENIAL_RING);
const IN_FLIGHT_RING: usize = 64;

/// Notices kept for the host to collect (no transport yet; a later packet sends them to the sender).
const NOTICE_RING: usize = 64;

/// Who can answer a hold for this session (S4.4). Set by the host through the session handle; the default is `None`, so a
/// session no host has configured fails closed. No in-process signal says "a client that can show prompts is attached":
/// `gateway_enabled` is true from spawn, and the leader keeps no per-session window record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OperatorPresence {
    /// A TUI window is attached, or an ACP client declared `operator: human`.
    Present,
    /// An interactive session resident in a leader with no window attached: a hold waits (5 minutes), the window may return.
    MayReturn,
    /// The host answers permission requests itself (`operator: auto`): never equals a human, never releases (S4.5).
    Auto,
    /// Headless, subagent, or an ACP host without `peerAdmission`.
    #[default]
    None,
}

impl OperatorPresence {
    pub const ALL: [OperatorPresence; 4] = [Self::Present, Self::MayReturn, Self::Auto, Self::None];

    /// The receiver's operator kind, compared with the sender's `from_operator` (S4.2, S4.5).
    pub fn kind(self) -> OperatorKind {
        match self {
            Self::Present | Self::MayReturn => OperatorKind::Human,
            Self::Auto => OperatorKind::Auto,
            Self::None => OperatorKind::None,
        }
    }

    /// True when someone can answer a hold now or soon.
    pub fn can_answer(self) -> bool {
        matches!(self, Self::Present | Self::MayReturn)
    }
}

/// Everything the decision reads. Nothing from the message body.
#[derive(Debug, Clone, Copy)]
pub struct AdmissionInputs {
    pub feature_on: bool,
    pub opted_in: bool,
    pub policy: PeerInboundPolicy,
    pub operator: OperatorPresence,
    pub receiver_mode: PeerMode,
    pub sender_mode: PeerMode,
    pub sender_operator: OperatorKind,
    /// S7.2/S7.4: the message carries a denial stamp, or the receiving model refused an earlier message from this sender.
    pub sender_denied: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Admit,
    Hold(HoldReason),
    Refuse(RejectReason),
}

/// Whether an operator who `MayReturn` (an interactive session resident with no window attached) counts as a present human for
/// auto-admit. Owner decision 38, 2026-10-10: MayReturn counts as attended, so an equal-mode message is admitted and wakes the
/// session (a different mode still holds). Switch this one function to change the ruling.
pub const fn may_return_admits() -> bool {
    true
}

/// The S4 decision. Pure.
///
/// Feature off or not opted in: refuse `unavailable`. Policy `refuse`: refuse. Policy `hold`: hold. Policy `accept`: admit only if
/// the sender's mode equals the receiver's (every dimension; `Unknown` equals nothing) and the operator kinds match; otherwise
/// hold. A would-be hold with nobody who can answer is refused `no_operator`.
pub fn decide(i: &AdmissionInputs) -> Decision {
    if !i.feature_on || !i.opted_in {
        return Decision::Refuse(RejectReason::Unavailable);
    }
    let would_hold = |reason: HoldReason| {
        if i.operator.can_answer() {
            Decision::Hold(reason)
        } else {
            Decision::Refuse(RejectReason::NoOperator)
        }
    };
    match i.policy {
        PeerInboundPolicy::Refuse => Decision::Refuse(RejectReason::PolicyRefused),
        // S4.3, S7.2: a denied sender is held whatever the receiver's mode and its hold/accept policy; `refuse` still refuses.
        _ if i.sender_denied => would_hold(HoldReason::SenderDenied),
        PeerInboundPolicy::Hold => would_hold(HoldReason::PolicyHold),
        PeerInboundPolicy::Accept => {
            let matches = i.sender_mode == i.receiver_mode && i.sender_operator == i.operator.kind();
            if matches && (i.operator != OperatorPresence::MayReturn || may_return_admits()) {
                Decision::Admit
            } else if matches {
                // Same mode and operator kind, but no human is looking right now: hold, do not admit.
                would_hold(HoldReason::PolicyHold)
            } else {
                would_hold(HoldReason::ModeMismatch)
            }
        }
    }
}

/// The live facts the session supplies on every call.
#[derive(Debug, Clone, Copy)]
pub struct Live {
    pub feature_on: bool,
    pub receiver_mode: PeerMode,
}

/// What a release approved: one fixed envelope under the receiver's state at that moment (S4.7).
#[derive(Debug, Clone, Copy)]
pub struct ApprovalSnapshot {
    receiver_mode: PeerMode,
    policy: PeerInboundPolicy,
    operator: OperatorPresence,
}

#[derive(Debug, Clone)]
enum Qualification {
    /// Admitted at arrival: must still decide `Admit` at drain.
    Direct,
    /// Released by an operator: must still match the snapshot (or decide `Admit`) at drain.
    Released(ApprovalSnapshot),
}

#[derive(Clone)]
struct HeldEntry {
    reason: HoldReason,
    envelope: Envelope,
    body_hash: String,
    token: String,
    /// Monotonic deadline (seconds on the [`now_mono`] clock).
    deadline: u64,
    /// The per-host reservation (S5.2): frees itself when this entry goes away, by any path.
    ticket: Option<Ticket>,
    /// Other reasons that applied when a `sender_denied` hold was made (S7.2): the row shows them too.
    also: Vec<HoldReason>,
}

impl std::fmt::Debug for HeldEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldEntry")
            .field("message_id", &self.envelope.message_id)
            .field("deadline", &self.deadline)
            .field("token", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone)]
struct Pending {
    envelope: Envelope,
    body_hash: String,
    deadline: u64,
    qualification: Qualification,
    /// The per-host reservation (S5.2). `None` once the row passed the start-of-turn recheck (not counted from then on).
    ticket: Option<Ticket>,
}

/// One held message as a client sees it.
#[derive(Clone, PartialEq, Eq)]
pub struct HeldSummary {
    pub message_id: String,
    /// The sender's address: with `message_id` the store key.
    pub from: String,
    pub from_ref: String,
    /// The sender's claimed name, RAW: a client must escape it (`peer_message::escape_attr`) before showing it.
    pub from_name: String,
    pub from_mode: String,
    pub reason: HoldReason,
    /// Every reason that applies, primary first (wire names).
    pub reason_names: Vec<&'static str>,
    /// What the held row adds to the reason (S7.2): "the sender was recently denied: <tool kind>" (kinds only).
    pub detail: Option<String>,
    pub expires_at: u64,
    pub token: String,
}

impl std::fmt::Debug for HeldSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldSummary")
            .field("message_id", &self.message_id)
            .field("expires_at", &self.expires_at)
            .field("token", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeKind {
    Released,
    Expired,
    Refused(RejectReason),
    /// Put back on hold at drain (the sender may be told "still held").
    Reheld,
    /// S6.6: a protected file changed while the session was peer-influenced (`message_id` carries the path).
    ProtectedFileChanged,
    /// Resumed with `features.peer_messaging` off from a peer-influenced history: the guard stays on (`message_id` is empty).
    GuardKeptFeatureOff,
    /// S7.3: a tool request matched a denial carried by a released peer message and was denied `laundering_refused`
    /// (`message_id` is the carrying message; the tool kind is in the audit line).
    LaunderingRefused,
    /// S7.4: the model refused this message with `refuse_peer_message`; the sender is held for the rest of the session.
    ModelRefused,
    /// 26-4: a turn started by a peer message ended with an empty model reply (`detail` is the escaped `name [ref]` of the sender).
    PeerTurnNoReply,
    /// 26-4: a turn started by a peer message ended with a provider refusal stop (`detail` as above).
    PeerTurnDeclined,
    /// A notice about a message THIS session sent, from the receiving host (packet 8e). Only the typed kind; the
    /// `message_id` is the one this session sent (never a peer string: the host matched it against its own book).
    SentMessage(fuigo_peer::NoticeKind),
    /// Packet 11: the sending host's own watch ended without any notice (`message_id` is the one this session sent).
    SentOutcomeUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerNotice {
    pub message_id: String,
    /// The sender's address when the notice is about a held message (empty otherwise): with `message_id` the store key.
    pub from: String,
    pub kind: NoticeKind,
    /// Text for the human only (never audited, never sent to the sender): for `Released` the denial counts per kind ("the sender
    /// was recently denied: bash x2, edit x1"), for `ModelRefused` the model's reason (escaped, at most 200 characters).
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseError {
    /// Operator is `Auto` or `None`: nobody human to release (S4.5).
    NoOperator,
    /// Unknown, already released or rejected, or the id never held here.
    NotFound,
    /// The token does not match the current one (replayed, stale, or wrong).
    BadToken,
    /// The hold ran out (at or after `expires_at`).
    Expired,
    /// Feature off, not opted in, or policy `refuse` at release time.
    Unavailable,
}

/// What became of a released message once drained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseOutcome {
    /// It qualified and entered the queue.
    Delivered,
    /// State changed between release and drain: back on hold, expiry not reset.
    Reheld { expires_at: u64 },
    Dropped(RejectReason),
    Expired,
}

/// Result of submitting a message through admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerSubmit {
    Outcome(DeliveryOutcome),
    /// The envelope broke a bound or shape rule.
    Invalid,
    SessionClosed,
}

/// What the store tells the session to do with a submitted message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submitted {
    /// Decided `Admit`: the caller enqueues now (it is already tracked for the drain recheck).
    Enqueue,
    Done(DeliveryOutcome),
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PeerAdmissionConfig {
    pub opted_in: bool,
    pub policy: PeerInboundPolicy,
    pub operator: OperatorPresence,
    /// UNUSED in production (always false since round 3 follow-up: the process-level `remote_attached` fact replaced the
    /// per-session driver); kept only for the tests that exercise the admission field.
    pub relay_driven: bool,
}

struct Inner {
    /// The process-wide ledger (S5.2); tickets are taken from it.
    ledger: Arc<HostLedger>,
    /// Peer messages admitted since the last human prompt (S5.6).
    budget: PeerTurnBudget,
    config: PeerAdmissionConfig,
    held: Vec<HeldEntry>,
    /// Released, waiting for the drain step.
    approved: VecDeque<Pending>,
    /// Admitted into the queue, not yet started or promoted: rechecked right before they enter a turn.
    queued: HashMap<MsgKey, Pending>,
    /// Passed the start-of-turn recheck (bounded ring, not counted).
    in_flight: VecDeque<(MsgKey, Pending)>,
    /// Rows that passed the start-of-turn recheck for a turn that has not ended yet (S6.1: counts as outstanding peer work;
    /// reset when the turn ends). The ring above also serves duplicate detection, so it cannot carry this meaning itself.
    in_flight_live: u32,
    notices: VecDeque<PeerNotice>,
    /// The audit log's queue handle (S8): `emit` only queues, it never does file I/O.
    audit: AuditCtx,
    /// S6.6: the protected-file watch and its `integrity` hold (`peer_integrity.rs`).
    integrity: super::peer_integrity::IntegrityState,
    /// S7.4: senders (address strings) the model refused; every further message from them is held `sender_denied`.
    refused_senders: HashSet<String>,
    /// Delivered messages (id, sender address), newest last and bounded: what `refuse_peer_message` can name.
    received: VecDeque<String>,
    /// Message id -> sender address for the ids in `received` (same bound), plus the ids of messages that carried denials
    /// (`pinned_senders`, at most 64, kept until `/peers clear-influence`): what `refuse_peer_message` can name.
    sender_of: HashMap<String, String>,
    /// Message id -> (conversation id, hop) for the ids in `received` (same bound): what a reply continues (S5.6).
    conv_of: HashMap<String, (String, u32)>,
    /// Message id -> the sender's claimed (name, ref) for the ids in `received` (same bound): RAW, escaped when shown.
    label_of: HashMap<String, (String, String)>,
    /// What the running turn did (26-4, 26-5): read once when a peer-started turn ends.
    turn_obs: TurnObs,
    /// The (conversation id, hop) of the peer message that started or joined the running turn (the highest hop if several);
    /// `None` for a turn no peer message is part of. Set by the session at turn start / join, never from a tool argument.
    turn_conv: Arc<Mutex<Option<(String, u32)>>>,
    /// The PEER CHAIN since the last human-typed prompt: (conversation id, highest hop seen). Raised by every peer message that
    /// starts or joins a turn, cleared ONLY by a turn started by `PromptOrigin::User`. A turn started by anything else (task
    /// wake, scheduled fire, drain, goal turn, plan resume) inherits it, so a runtime wake cannot reset the hop budget. Memory
    /// only: a restart clears it.
    chain: Arc<Mutex<Option<(String, u32)>>>,
    pinned_senders: Vec<(String, String)>,
    /// Keys the carried list could not keep (it was full), as last reported by the denial log (counts only, for the row).
    carried_overflow: usize,
    /// S7 persistence: what the receiver carries, as (kind, hash, message id), mirrored here so it can be written as a marker.
    carried_mirror: Vec<(String, String, String)>,
    /// S7 persistence: the sender-side ring as last written (or restored), to find denials not yet written.
    denial_synced: Vec<Vec<fuigo_workspace::permission::DenialKey>>,
    /// The carried list or the refused set changed since the marker was last written.
    state_dirty: bool,
    /// (message id, tool kind) pairs already reported to the human, so a retried laundering hit gives ONE notice.
    laundering_reported: HashSet<(String, String)>,
    /// The session's gate; its watch book hears the typed notices of held messages (packet 11).
    gate: Arc<super::message_delivery::PeerGate>,
}

/// The per-session admission state. Held in the session actor; the handle reaches it by command.
///
/// Every envelope first passes the host's [`PeerIngress`] (S5.1, S5.3, S5.4), shared by all sessions of the process when the
/// session is built with [`Self::with_host`]; `Default` gives the session a private ingress.
pub struct PeerAdmissionState {
    inner: Mutex<Inner>,
    host: Arc<Mutex<PeerIngress>>,
    /// This session's id inside the ingress tables, so no outcome can describe another session's traffic.
    session: u64,
    /// A turn started or joined by a peer input is running (S6.1: `/peers clear-influence` is refused meanwhile).
    peer_turn: std::sync::atomic::AtomicBool,
    /// Opt-in (and not relay driven) mirrored for the peer inbox, which must not list or address a session that is not
    /// offered (S4.1). Updated by [`Self::configure`] only.
    gate: Arc<super::message_delivery::PeerGate>,
    /// The session's real operator presence (`OperatorPresence` as a discriminant), kept in step with `config.operator`, so an
    /// outgoing envelope states the operator kind the receiver's admission compares (S5.1).
    operator_cell: Arc<std::sync::atomic::AtomicU8>,
    /// This session's own command channel (weak, so it cannot keep the session loop alive): how the human `/peers` commands reach
    /// the actor's admission handler (`held`, `release`, `refuse`) from inside a turn.
    admin_tx: Mutex<Option<tokio::sync::mpsc::WeakUnboundedSender<super::commands::SessionCommand>>>,
    /// Where the baseline snapshot read on a blocking thread is parked (S6.6).
    baseline: Arc<Baseline>,
    /// Test seams for the interleaving and panic tests (per state, so tests cannot affect each other).
    #[cfg(test)]
    pub(crate) hooks: Arc<TestHooks>,
}

/// Test seams (S6.6): a hook run inside the baseline read, and one-shot panics in the baseline and recheck file work.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestHooks {
    pub(crate) in_baseline: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    pub(crate) panic_baseline: std::sync::atomic::AtomicBool,
    pub(crate) panic_recheck: std::sync::atomic::AtomicBool,
    /// Overrides the bound on a baseline or recheck wait, in milliseconds (0 = the production value).
    pub(crate) wait_ms: std::sync::atomic::AtomicU64,
    /// How many baseline reads were started.
    pub(crate) baseline_starts: std::sync::atomic::AtomicUsize,
    /// A hook run inside the recheck's file work (to make it hang).
    pub(crate) in_recheck: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    /// The human warnings written by the actor (a test cannot read the client stream).
    pub(crate) warnings: Mutex<Vec<String>>,
}

/// The longest the actor waits for one read of the protected files (baseline or recheck) before it fails closed.
pub(crate) const INTEGRITY_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

/// The hand-off of a background baseline read: the finished watch (with the generation it began under) and a counter that
/// wakes waiters.
struct Baseline {
    /// The finished watch, the generation it began under, and whether the read panicked (then the watch is empty).
    slot: Mutex<Option<(super::peer_integrity::Watch, u64, bool)>>,
    done: tokio::sync::watch::Sender<u64>,
}

impl Default for PeerAdmissionState {
    fn default() -> Self {
        Self::with_host(Arc::new(Mutex::new(PeerIngress::default())))
    }
}

/// The process-wide ingress: one per host (S5.2, S5.3). Sessions built for real use share it.
pub fn host_ingress() -> Arc<Mutex<PeerIngress>> {
    static HOST: std::sync::OnceLock<Arc<Mutex<PeerIngress>>> = std::sync::OnceLock::new();
    HOST.get_or_init(|| Arc::new(Mutex::new(PeerIngress::default()))).clone()
}

static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

impl Drop for PeerAdmissionState {
    /// Session end: held and queued entries drop with `inner` (their tickets free the host totals); the ingress forgets this
    /// session's rate pairs and remembered ids.
    fn drop(&mut self) {
        let mut h = self.host.lock().unwrap_or_else(|p| p.into_inner());
        h.forget_session(self.session);
    }
}

/// Delivered messages remembered for `refuse_peer_message`.
const RECEIVED_RING: usize = 256;
/// Delivered messages that carried denials stay nameable by `refuse_peer_message` (same bound as the carried list).
const PINNED_SENDERS: usize = 64;
/// Longest `reason` shown to the human on a model refusal, in characters (S7.4). It is never written to the audit log.
const REFUSE_REASON_SHOWN_CHARS: usize = 200;

/// A tool kind from a peer's stamp, made safe to show: the audit alphabet, at most 32 characters, else `other`.
fn shown_kind(k: &str) -> String {
    let ok = !k.is_empty() && k.chars().count() <= 32 && k.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'));
    if ok { k.to_owned() } else { "other".to_owned() }
}

/// The extra line on a held row (S7.2). Kinds only, never a hash, path or command.
fn hold_detail(reason: HoldReason, env: &Envelope, also: &[HoldReason], overflow: usize) -> Option<String> {
    if reason != HoldReason::SenderDenied {
        return None;
    }
    let tail = if also.is_empty() {
        String::new()
    } else {
        format!("; also: {}", also.iter().map(|r| hold_name(*r)).collect::<Vec<_>>().join(", "))
    };
    // Kinds and counts only: releasing one row installs one block per stamp, so the human sees how many ("bash x3").
    let mut kinds: Vec<(String, usize)> = Vec::new();
    for d in &env.denied_recently {
        let k = shown_kind(&d.tool_kind);
        match kinds.iter_mut().find(|(n, _)| *n == k) {
            Some((_, c)) => *c += 1,
            None => kinds.push((k, 1)),
        }
    }
    let kinds: Vec<String> = kinds.into_iter().map(|(k, c)| format!("{k} x{c}")).collect();
    // Counts only: how many keys this session could not keep because its carried list was full.
    let tail = if overflow > 0 { format!("; {overflow} more denial keys were not kept (carried list full){tail}") } else { tail };
    Some(if kinds.is_empty() {
        format!("your session refused an earlier message from this sender{tail}")
    } else {
        format!("the sender was recently denied: {}{tail}", kinds.join(", "))
    })
}

fn hold_name(r: HoldReason) -> &'static str {
    match r {
        HoldReason::ModeMismatch => "mode_mismatch",
        HoldReason::LoopGuard => "loop_guard",
        HoldReason::SenderDenied => "sender_denied",
        HoldReason::Integrity => "integrity",
        HoldReason::PolicyHold => "policy_hold",
    }
}

/// What the running turn did, for the end-of-turn rules of a turn started by a peer message (26-4, 26-5).
#[derive(Debug, Clone, Copy, Default)]
struct TurnObs {
    /// Tool calls the model made in the turn, of any kind (including backend-hosted ones).
    tool_calls: u32,
    /// Some model reply of the turn carried text.
    text_seen: bool,
    /// Some model reply of the turn stopped with the provider's refusal (content filter).
    provider_refused: bool,
    /// The model called `refuse_peer_message` in this turn.
    model_refused: bool,
}

/// Reason recorded for an automatic refusal (a peer-started turn that ended without a tool call).
pub(crate) const AUTO_REFUSE_REASON: &str = "no action taken";

/// What `refuse_peer_message` did, for the tool result and the human row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelRefusal {
    /// The model's reason, cut to 200 characters and escaped for display (never audited).
    pub shown_reason: String,
}

/// `refuse_peer_message` found no such delivered message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownMessage;

fn lock(m: &Mutex<Inner>) -> std::sync::MutexGuard<'_, Inner> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn ingress(m: &Mutex<PeerIngress>) -> std::sync::MutexGuard<'_, PeerIngress> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn body_hash(env: &Envelope) -> String {
    format!("{:x}", Sha256::digest(env.body.as_bytes()))
}

fn new_token() -> String {
    format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple())
}

fn tokens_equal(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Inner {
    fn inputs(&self, live: &Live, env: &Envelope) -> AdmissionInputs {
        AdmissionInputs {
            feature_on: live.feature_on,
            // While a remote client is attached to this process nothing is admitted, released or delivered (owner rule, S4.1).
            opted_in: self.config.opted_in && !self.config.relay_driven && !crate::peer_inbox::driver::remote_attached(),
            policy: self.config.policy,
            operator: self.config.operator,
            receiver_mode: live.receiver_mode,
            sender_mode: env.from_mode,
            sender_operator: env.from_operator,
            sender_denied: !env.denied_recently.is_empty() || self.refused_senders.contains(&env.from.to_string()),
        }
    }

    /// The S4 decision, then S6.6: once a protected file changed, every message that would be admitted or held is held with
    /// reason `integrity` (also when nobody can answer, for a row already accepted). Refusals stand.
    fn decide_live(&self, inputs: &AdmissionInputs) -> Decision {
        let d = decide(inputs);
        if self.integrity.tripped() && matches!(d, Decision::Admit | Decision::Hold(_)) {
            // Always held, even with nobody to answer: the hold waits for a human-typed `/peers clear-influence` or expires.
            // (A NEW message with nobody to answer is refused by `decide_fresh`; a row already accepted is held, not dropped.)
            return Decision::Hold(HoldReason::Integrity);
        }
        d
    }

    /// `decide_live` for a message arriving now: with the integrity hold up and nobody who can answer, a hold could never be
    /// released and would only sit until expiry, so it is refused `no_operator` (as `decide` does for every other would-be hold).
    fn decide_fresh(&self, inputs: &AdmissionInputs) -> Decision {
        match self.decide_live(inputs) {
            Decision::Hold(HoldReason::Integrity) if !inputs.operator.can_answer() => Decision::Refuse(RejectReason::NoOperator),
            d => d,
        }
    }

    /// Audit an outcome for an envelope in hand (S8.1). Queue only; no I/O here.
    fn audit(&mut self, env: &Envelope, outcome: AuditOutcome) {
        let ev = AuditEvent::from_envelope(env, self.audit.to_session(), outcome, None::<&RejectReason>, now_secs());
        self.audit.emit(ev);
    }

    fn audit_hold(&mut self, env: &Envelope, reason: HoldReason) {
        let ev = AuditEvent::from_envelope(env, self.audit.to_session(), AuditOutcome::Held, Some(&reason), now_secs());
        self.audit.emit(ev);
    }

    fn audit_reheld(&mut self, env: &Envelope, reason: HoldReason) {
        let ev = AuditEvent::from_envelope(env, self.audit.to_session(), AuditOutcome::Reheld, Some(&reason), now_secs());
        self.audit.emit(ev);
    }

    /// A refusal; `saturated` has its own outcome name, every other reason is `refused` with the reason.
    fn audit_refused(&mut self, env: &Envelope, reason: RejectReason) {
        let outcome = if reason == RejectReason::Saturated { AuditOutcome::Saturated } else { AuditOutcome::Refused };
        let ev = AuditEvent::from_envelope(env, self.audit.to_session(), outcome, Some(&reason), now_secs());
        self.audit.emit(ev);
    }

    fn audit_integrity(&mut self, c: &super::peer_integrity::Change) {
        let ev = AuditEvent::integrity_changed(self.audit.to_session(), c, now_secs());
        self.audit.emit(ev);
    }

    fn audit_duplicate(&mut self, env: &Envelope) {
        self.audit(env, AuditOutcome::Duplicate);
    }

    fn notice(&mut self, message_id: &str, kind: NoticeKind) {
        self.notice_from("", message_id, kind);
    }

    fn notice_from(&mut self, from: &str, message_id: &str, kind: NoticeKind) {
        if self.notices.len() >= NOTICE_RING {
            self.notices.pop_front();
        }
        self.gate.watches.on_session_notice(message_id, &kind);
        self.notices.push_back(PeerNotice { message_id: message_id.to_owned(), from: from.to_owned(), kind, detail: None });
    }

    fn notice_with(&mut self, from: &str, message_id: &str, kind: NoticeKind, detail: Option<String>) {
        self.notice_from(from, message_id, kind);
        if let Some(n) = self.notices.back_mut() {
            n.detail = detail;
        }
    }

    /// Expire every hold at or past its time.
    fn sweep(&mut self, now: u64) {
        let (live, dead): (Vec<_>, Vec<_>) = std::mem::take(&mut self.held)
            .into_iter()
            .partition(|h| h.deadline > now);
        self.held = live;
        for h in dead {
            self.audit(&h.envelope, AuditOutcome::Expired);
            self.notice_from(&h.envelope.from.to_string(), &h.envelope.message_id, NoticeKind::Expired);
        }
    }

    fn usage(&self) -> (usize, usize) {
        let envs = self
            .held
            .iter()
            .map(|h| &h.envelope)
            .chain(self.approved.iter().map(|p| &p.envelope))
            .chain(self.queued.values().map(|p| &p.envelope));
        envs.fold((0, 0), |(n, b), e| (n + 1, b + e.body.len()))
    }

    fn knows(&self, k: &MsgKey) -> bool {
        self.held.iter().any(|h| msg_key(&h.envelope) == *k)
            || self.approved.iter().any(|p| msg_key(&p.envelope) == *k)
            || self.queued.contains_key(k)
            || self.in_flight.iter().any(|(kk, _)| kk == k)
    }

    /// The body hash recorded for a message already known under this key, if any.
    fn known_hash(&self, k: &MsgKey) -> Option<&str> {
        self.held
            .iter()
            .find(|h| msg_key(&h.envelope) == *k)
            .map(|h| h.body_hash.as_str())
            .or_else(|| self.approved.iter().find(|p| msg_key(&p.envelope) == *k).map(|p| p.body_hash.as_str()))
            .or_else(|| self.queued.get(k).map(|p| p.body_hash.as_str()))
            .or_else(|| self.in_flight.iter().find(|(kk, _)| kk == k).map(|(_, p)| p.body_hash.as_str()))
    }

    /// The held entry for this id whose token matches; ids are not unique across senders, tokens are.
    fn find_held(&mut self, message_id: &str, token: &str, now: u64) -> Result<usize, ReleaseError> {
        let mut any = false;
        let mut expired = false;
        let mut found = None;
        for (i, h) in self.held.iter().enumerate() {
            if h.envelope.message_id != message_id {
                continue;
            }
            any = true;
            if h.deadline <= now {
                expired = true;
            } else if tokens_equal(&h.token, token) {
                found = Some(i);
            }
        }
        if let Some(i) = found {
            return Ok(i);
        }
        if !any {
            self.sweep(now);
            return Err(ReleaseError::NotFound);
        }
        if expired {
            self.sweep(now);
            return Err(ReleaseError::Expired);
        }
        Err(ReleaseError::BadToken)
    }

    /// Put an envelope on hold with the given expiry. Bounds were checked by the caller (or it is a re-hold of a message that
    /// already counted).
    fn hold(&mut self, envelope: Envelope, hash: String, deadline: u64, reason: HoldReason, ticket: Option<Ticket>) {
        let ticket = ticket.unwrap_or_else(|| self.ledger.force(envelope.body.len()));
        self.held.push(HeldEntry { reason, envelope, body_hash: hash, token: new_token(), deadline, ticket: Some(ticket), also: Vec::new() });
    }

    /// Decide whether `p` may enter a turn now; on failure move it back to held or drop it. `true` = enters.
    fn check_at_drain(&mut self, mut p: Pending, live: &Live, now: u64) -> Result<Pending, ReleaseOutcome> {
        // A row that was out of the count (passed a start recheck) is counted again while it is being judged.
        if p.ticket.is_none() {
            p.ticket = Some(self.ledger.force(p.envelope.body.len()));
        }
        let inputs = self.inputs(live, &p.envelope);
        let mut decision = self.decide_live(&inputs);
        // A row already admitted that the integrity hold now stops is HELD even when nobody can answer: it waits for the
        // human-typed `/peers clear-influence` or expires, like any held message (never refused `no_operator` for this reason).
        if self.integrity.tripped() && decision == Decision::Refuse(RejectReason::NoOperator) {
            decision = Decision::Hold(HoldReason::Integrity);
        }
        // A remote client is attached: nothing enters a turn and nothing is lost. The row goes back to held (S4.7).
        if crate::peer_inbox::driver::remote_attached() && !matches!(decision, Decision::Hold(_)) {
            decision = Decision::Hold(HoldReason::PolicyHold);
        }
        let ok = match (&p.qualification, decision) {
            (_, Decision::Admit) => true,
            (Qualification::Direct, _) => false,
            // A release by an operator waives only the hold REASON the human saw (`sender_denied`, `policy hold`, `mode mismatch`,
            // `loop_guard`): a denied sender is held precisely so a human can release it, so a released row is delivered although
            // `decide` still says Hold for it. Everything else is judged again here: flag, opt-in (and a remote client attached),
            // policy, operator, the mode snapshot, the integrity hold, the body hash.
            (Qualification::Released(snap), _) => {
                inputs.feature_on
                    && inputs.opted_in
                    && inputs.policy != PeerInboundPolicy::Refuse
                    && inputs.operator.can_answer()
                    && inputs.policy == snap.policy
                    && inputs.operator == snap.operator
                    && inputs.receiver_mode.known().is_some()
                    && inputs.receiver_mode.known() == snap.receiver_mode.known()
            }
        };
        // S6.6: a message the human already released is held too once a protected file changed (all further peer messages).
        let ok = ok && !self.integrity.tripped();
        // The approved envelope is fixed: the body must still hash to what was approved.
        let intact = body_hash(&p.envelope) == p.body_hash;
        if ok && intact {
            return Ok(p);
        }
        let id = p.envelope.message_id.clone();
        let from = p.envelope.from.to_string();
        if p.deadline <= now {
            self.audit(&p.envelope, AuditOutcome::Expired);
            self.notice_from(&from, &id, NoticeKind::Expired);
            return Err(ReleaseOutcome::Expired);
        }
        match decision {
            Decision::Hold(reason) if intact => {
                let expires_at = wall_expiry(p.deadline, now);
                self.audit_reheld(&p.envelope, reason);
                self.hold(p.envelope, p.body_hash, p.deadline, reason, p.ticket.take());
                self.notice_from(&from, &id, NoticeKind::Reheld);
                Err(ReleaseOutcome::Reheld { expires_at })
            }
            Decision::Refuse(r) => {
                self.audit_refused(&p.envelope, r);
                self.notice_from(&from, &id, NoticeKind::Refused(r));
                Err(ReleaseOutcome::Dropped(r))
            }
            _ => {
                self.audit_refused(&p.envelope, RejectReason::Unavailable);
                self.notice_from(&from, &id, NoticeKind::Refused(RejectReason::Unavailable));
                Err(ReleaseOutcome::Dropped(RejectReason::Unavailable))
            }
        }
    }
}

impl PeerAdmissionState {
    /// A fresh state that names its session in the audit log.
    ///
    /// Outside tests it shares the process-wide host ingress (S5.2, S5.3); tests get a private one so their rate windows do not mix.
    pub fn for_session(session_id: &str) -> Self {
        #[cfg(not(test))]
        let s = Self::with_host(host_ingress());
        #[cfg(test)]
        let s = Self::default();
        s.set_audit_receiver(session_id);
        s
    }

    pub fn configure(&self, config: PeerAdmissionConfig) {
        self.gate.set_opted_in(config.opted_in && !config.relay_driven);
        self.operator_cell.store(config.operator as u8, Ordering::SeqCst);
        lock(&self.inner).config = config;
    }

    /// The shared gate the session's handle and directory entry read.
    pub(crate) fn gate(&self) -> Arc<super::message_delivery::PeerGate> {
        self.gate.clone()
    }

    /// Name the receiving session for the audit log (the `to_session` field).
    pub fn set_audit_receiver(&self, session_id: &str) {
        lock(&self.inner).audit.set_receiver(session_id);
    }

    #[cfg(test)]
    pub(crate) fn with_audit<T>(&self, f: impl FnOnce(&mut AuditCtx) -> T) -> T {
        f(&mut lock(&self.inner).audit)
    }

    /// A live view of this session's operator kind (what an outgoing envelope carries as `from_operator`). Fails closed to
    /// `None` for a session no host configured.
    pub(crate) fn operator_kind_handle(&self) -> Arc<dyn Fn() -> OperatorKind + Send + Sync> {
        let cell = self.operator_cell.clone();
        Arc::new(move || {
            let presence = OperatorPresence::ALL.into_iter().find(|p| *p as u8 == cell.load(Ordering::SeqCst)).unwrap_or_default();
            presence.kind()
        })
    }

    pub fn config(&self) -> PeerAdmissionConfig {
        lock(&self.inner).config
    }

    /// A state that shares `host` (the process-wide ingress) with every other session built on it.
    pub fn with_host(host: Arc<Mutex<PeerIngress>>) -> Self {
        let ledger = ingress(&host).ledger();
        let gate: Arc<super::message_delivery::PeerGate> = Arc::default();
        let inner = Inner {
            ledger,
            budget: PeerTurnBudget::default(),
            config: PeerAdmissionConfig::default(),
            held: Vec::new(),
            approved: VecDeque::new(),
            queued: HashMap::new(),
            in_flight: VecDeque::new(),
            in_flight_live: 0,
            notices: VecDeque::new(),
            audit: AuditCtx::default(),
            integrity: Default::default(),
            refused_senders: HashSet::new(),
            received: VecDeque::new(),
            sender_of: HashMap::new(),
            conv_of: HashMap::new(),
            label_of: HashMap::new(),
            turn_obs: TurnObs::default(),
            turn_conv: Arc::default(),
            chain: Arc::default(),
            pinned_senders: Vec::new(),
            carried_overflow: 0,
            carried_mirror: Vec::new(),
            denial_synced: Vec::new(),
            state_dirty: false,
            laundering_reported: HashSet::new(),
            gate: gate.clone(),
        };
        Self { inner: Mutex::new(inner), host, session: NEXT_SESSION.fetch_add(1, Ordering::Relaxed), peer_turn: std::sync::atomic::AtomicBool::new(false), admin_tx: Mutex::new(None), gate, operator_cell: Arc::new(std::sync::atomic::AtomicU8::new(OperatorPresence::None as u8)), baseline: Arc::new(Baseline { slot: Mutex::new(None), done: tokio::sync::watch::channel(0).0 }), #[cfg(test)] hooks: Arc::default() }
    }

    /// Test only: a private ingress with the rate limits lifted, for tests of the S4 and store bounds.
    #[cfg(test)]
    pub fn unmetered() -> Self {
        Self::metered(IngressConfig { pair_per_minute: usize::MAX, host_per_minute: usize::MAX, ..IngressConfig::default() })
    }

    /// Test only: a private ingress and ledger with the given numbers.
    #[cfg(test)]
    pub fn metered(cfg: IngressConfig) -> Self {
        Self::with_host(Arc::new(Mutex::new(PeerIngress::new(cfg, Arc::new(HostLedger::default())))))
    }

    /// A human-intent prompt started a turn: the peer-turn budget is full again (S5.6).
    pub(crate) fn set_admin_tx(&self, tx: &tokio::sync::mpsc::UnboundedSender<super::commands::SessionCommand>) {
        *self.admin_tx.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(tx.downgrade());
    }

    /// One round trip to this session's own admission handler. `None` when the channel is unset or the session is closing.
    pub(crate) async fn admin(&self, cmd: PeerAdminCmd) -> Option<PeerAdminReply> {
        let tx = self.admin_tx.lock().unwrap_or_else(std::sync::PoisonError::into_inner).as_ref()?.upgrade()?;
        let (respond_to, rx) = tokio::sync::oneshot::channel();
        tx.send(super::commands::SessionCommand::PeerAdmission { cmd, respond_to }).ok()?;
        rx.await.ok()
    }

    pub fn human_prompt(&self) {
        lock(&self.inner).budget.human_prompt();
    }

    /// Peer-started turns counted since the last human prompt.
    pub fn peer_turns_used(&self) -> u32 {
        lock(&self.inner).budget.used()
    }

    /// `(messages, bytes)` reserved on the host by every session sharing this ingress.
    pub fn host_usage(&self) -> (usize, usize) {
        lock(&self.inner).ledger.usage()
    }

    /// Sizes of the host ingress tables.
    pub fn ingress_sizes(&self) -> fuigo_peer::IngressSizes {
        ingress(&self.host).sizes()
    }

    /// Decide on a new message. `Enqueue` means admitted: the caller commits it to the queue. `now` is the monotonic clock.
    ///
    /// Order: the host ingress first (sizes, remembered ids, rate: S5.1, S5.4, S5.3), then the S4 decision, then the loop budget
    /// (S5.6), then the per-session and per-host store bounds (S5.2). A message refused by an earlier step costs nothing in a
    /// later one. With the flag off nothing is tracked.
    pub fn submit(&self, env: Envelope, now: u64, live: &Live) -> Submitted {
        let mut g = lock(&self.inner);
        g.sweep(now);
        let hash = body_hash(&env);
        let (from, id) = msg_key(&env);
        if live.feature_on {
            match ingress(&self.host).admit(now, self.session, &env, &hash) {
                IngressVerdict::Proceed => {}
                IngressVerdict::Refuse(o) => {
                    // too_large, rate_limited (pair or host), or an ambiguous id: one line, aggregated like any refusal.
                    if let DeliveryOutcome::Rejected { reason } = &o {
                        g.audit_refused(&env, *reason);
                    }
                    return Submitted::Done(o);
                }
                // A message still held or queued here is answered from its current state below, as in packet 4.
                IngressVerdict::Replay(o) => {
                    if !g.knows(&(from.clone(), id.clone())) {
                        // Answered from the replay memory: a duplicate, aggregated.
                        g.audit_duplicate(&env);
                        return Submitted::Done(o);
                    }
                }
            }
        }
        let out = Self::store(&mut g, env, hash.clone(), now, live);
        if live.feature_on {
            let recorded = match &out {
                Submitted::Done(o) => o.clone(),
                Submitted::Enqueue => DeliveryOutcome::Delivered {},
            };
            ingress(&self.host).record(now, self.session, &from, &id, &hash, &recorded);
        }
        out
    }

    /// Packet 11 (round 2): the admission gate for a watch-only send (empty body + `watch`). It costs the same ingress allowance
    /// as a message (sizes, remembered ids, pair and host rates) and is judged by the same decision, but stores nothing, records
    /// nothing in the replay memory and starts no turn. Only `Admit` answers `Delivered {}` (the caller then registers the watch).
    /// A decision that would HOLD a message (mode, denied sender, policy hold, integrity, hop or turn budget) is refused
    /// `policy_refused` (`no_operator` when nobody could answer a hold): no held row, no watch, no timing revealed.
    pub fn probe_watch(&self, env: &Envelope, now: u64, live: &Live) -> DeliveryOutcome {
        let mut g = lock(&self.inner);
        g.sweep(now);
        let hash = body_hash(env);
        if live.feature_on {
            match ingress(&self.host).admit(now, self.session, env, &hash) {
                IngressVerdict::Proceed => {}
                IngressVerdict::Refuse(o) => {
                    if let DeliveryOutcome::Rejected { reason } = &o {
                        g.audit_refused(env, *reason);
                    }
                    return o;
                }
                // A probe is never recorded, so a remembered id is a real message sent under it: not a watch-only.
                IngressVerdict::Replay(_) => {
                    g.audit_refused(env, RejectReason::Ambiguous);
                    return DeliveryOutcome::Rejected { reason: RejectReason::Ambiguous };
                }
            }
        }
        let inputs = g.inputs(live, env);
        let refuse = |reason| DeliveryOutcome::Rejected { reason };
        let reason = match g.decide_live(&inputs) {
            Decision::Admit if hop_exhausted(env.hop) || g.budget.exhausted() => {
                if inputs.operator.can_answer() { RejectReason::PolicyRefused } else { RejectReason::NoOperator }
            }
            Decision::Admit => return DeliveryOutcome::Delivered {},
            Decision::Refuse(r) => r,
            Decision::Hold(_) => RejectReason::PolicyRefused,
        };
        g.audit_refused(env, reason);
        refuse(reason)
    }

    fn store(g: &mut Inner, env: Envelope, hash: String, now: u64, live: &Live) -> Submitted {
        let inputs = g.inputs(live, &env);
        let mut decision = g.decide_fresh(&inputs);
        if decision == Decision::Admit && (hop_exhausted(env.hop) || g.budget.exhausted()) {
            // S5.6, S4.3: never auto-admitted once the hop or turn budget is used up; held for the human (or refused if nobody
            // can answer).
            decision = if inputs.operator.can_answer() {
                Decision::Hold(HoldReason::LoopGuard)
            } else {
                Decision::Refuse(RejectReason::NoOperator)
            };
        }
        if let Decision::Refuse(r) = decision {
            g.audit_refused(&env, r);
            return Submitted::Done(DeliveryOutcome::Rejected { reason: r });
        }
        let key = msg_key(&env);
        // Idempotent on (sender, message id): a duplicate returns the state of the first and stores nothing. The same
        // id with a different body is not a duplicate: it is refused.
        if let Some(first) = g.known_hash(&key) {
            if first != hash {
                g.audit_refused(&env, RejectReason::Ambiguous);
                return Submitted::Done(DeliveryOutcome::Rejected { reason: RejectReason::Ambiguous });
            }
            g.audit_duplicate(&env);
            if let Some(h) = g.held.iter().find(|h| msg_key(&h.envelope) == key) {
                return Submitted::Done(DeliveryOutcome::Held { reason: h.reason, expires_at: wall_expiry(h.deadline, now) });
            }
            return Submitted::Done(DeliveryOutcome::Delivered {});
        }
        let (count, bytes) = g.usage();
        if count + 1 > MAX_MESSAGES_PER_SESSION || bytes + env.body.len() > MAX_BODY_BYTES_PER_SESSION {
            // Never evict: the new message is refused.
            g.audit_refused(&env, RejectReason::Saturated);
            return Submitted::Done(DeliveryOutcome::Rejected { reason: RejectReason::Saturated });
        }
        let Ok(ticket) = g.ledger.reserve(env.body.len()) else {
            // The per-host total (S5.2): same answer, and it names nothing about other sessions.
            g.audit_refused(&env, RejectReason::Saturated);
            return Submitted::Done(DeliveryOutcome::Rejected { reason: RejectReason::Saturated });
        };
        let deadline = now + HOLD_EXPIRY_SECS;
        match decision {
            Decision::Hold(reason) => {
                g.audit_hold(&env, reason);
                // S7.2: a `sender_denied` row must not hide a co-occurring mode mismatch, policy hold or used-up budget.
                let mut also = Vec::new();
                if reason == HoldReason::SenderDenied {
                    let mut plain = inputs;
                    plain.sender_denied = false;
                    if let Decision::Hold(other) = decide(&plain) {
                        also.push(other);
                    }
                    if hop_exhausted(env.hop) || g.budget.exhausted() {
                        also.push(HoldReason::LoopGuard);
                    }
                }
                g.hold(env, hash, deadline, reason, Some(ticket));
                if let Some(h) = g.held.last_mut() {
                    h.also = also;
                }
                Submitted::Done(DeliveryOutcome::Held { reason, expires_at: wall_expiry(deadline, now) })
            }
            _ => {
                g.audit(&env, AuditOutcome::Admitted);
                g.budget.consume();
                g.queued.insert(
                    key,
                    Pending {
                        envelope: env,
                        body_hash: hash,
                        deadline,
                        qualification: Qualification::Direct,
                        ticket: Some(ticket),
                    },
                );
                Submitted::Enqueue
            }
        }
    }

    #[cfg(test)]
    pub fn track_direct_for_test(&self, env: Envelope, now: u64) {
        let hash = body_hash(&env);
        let mut g = lock(&self.inner);
        let ticket = g.ledger.force(env.body.len());
        g.queued.insert(
            msg_key(&env),
            Pending {
                envelope: env,
                body_hash: hash,
                deadline: now + HOLD_EXPIRY_SECS,
                qualification: Qualification::Direct,
                ticket: Some(ticket),
            },
        );
    }

    /// Forget a tracked row (the enqueue failed).
    pub fn untrack(&self, key: &MsgKey) {
        let mut g = lock(&self.inner);
        if g.queued.remove(key).is_some() {
            // The enqueue that followed an admit failed: the message was not delivered.
            let ev = AuditEvent::from_key(key, g.audit.to_session(), AuditOutcome::Refused, Some(&RejectReason::Unavailable), now_secs());
            g.audit.emit(ev);
        }
        drop(g);
        ingress(&self.host).forget(self.session, &key.0, &key.1);
    }

    /// A stranded interjection came back as its own queued row: track it again so it is rechecked when it runs. A row this state
    /// never saw stays untracked and is refused at its turn.
    pub fn retrack_stranded(&self, key: &MsgKey) -> bool {
        let mut g = lock(&self.inner);
        let Some(pos) = g.in_flight.iter().position(|(k, _)| k == key) else {
            return false;
        };
        if let Some((k, mut p)) = g.in_flight.remove(pos) {
            // Counted again while it waits in the queue.
            p.ticket = Some(g.ledger.force(p.envelope.body.len()));
            g.queued.insert(k, p);
            g.in_flight_live = g.in_flight_live.saturating_sub(1);
        }
        true
    }

    /// Operator releases one held message. The first valid call wins; the token is single-use. The message moves to the approved
    /// list and enters a turn only through [`Self::drain`], which checks the live state again.
    pub fn release(
        &self,
        message_id: &str,
        token: &str,
        now: u64,
        live: &Live,
    ) -> Result<(), ReleaseError> {
        let mut g = lock(&self.inner);
        if !g.config.operator.can_answer() {
            return Err(ReleaseError::NoOperator);
        }
        let pos = g.find_held(message_id, token, now)?;
        // A remote client is attached: peer messaging is unavailable. The message stays held, nothing is released.
        if crate::peer_inbox::driver::remote_attached() {
            return Err(ReleaseError::Unavailable);
        }
        let held = g.held.remove(pos);
        let inputs = g.inputs(live, &held.envelope);
        if !inputs.feature_on || !inputs.opted_in || inputs.policy == PeerInboundPolicy::Refuse {
            g.audit_refused(&held.envelope, RejectReason::Unavailable);
            g.notice_from(&held.envelope.from.to_string(), message_id, NoticeKind::Refused(RejectReason::Unavailable));
            return Err(ReleaseError::Unavailable);
        }
        let snapshot = ApprovalSnapshot {
            receiver_mode: live.receiver_mode,
            policy: inputs.policy,
            operator: inputs.operator,
        };
        g.audit(&held.envelope, AuditOutcome::Released);
        let detail = hold_detail(HoldReason::SenderDenied, &held.envelope, &[], g.carried_overflow).filter(|_| {
            !held.envelope.denied_recently.is_empty()
        });
        g.notice_with(&held.envelope.from.to_string(), message_id, NoticeKind::Released, detail);
        g.approved.push_back(Pending {
            envelope: held.envelope,
            body_hash: held.body_hash,
            deadline: held.deadline,
            qualification: Qualification::Released(snapshot),
            ticket: held.ticket,
        });
        Ok(())
    }

    /// Operator refuses a held message (same token rules as release).
    pub fn reject(&self, message_id: &str, token: &str, now: u64) -> Result<(), ReleaseError> {
        let mut g = lock(&self.inner);
        if !g.config.operator.can_answer() {
            return Err(ReleaseError::NoOperator);
        }
        let pos = g.find_held(message_id, token, now)?;
        let held = g.held.remove(pos);
        g.audit(&held.envelope, AuditOutcome::RejectedByOperator);
        g.notice_from(&held.envelope.from.to_string(), message_id, NoticeKind::Refused(RejectReason::PolicyRefused));
        Ok(())
    }

    /// Re-evaluate every approved message against the live state. Qualifying ones are returned for the caller to enqueue (and are
    /// tracked for the start-of-turn recheck); the rest go back to held or are dropped. Returns `(message_id, outcome)` for each.
    pub fn drain(&self, now: u64, live: &Live) -> (Vec<Envelope>, Vec<(String, ReleaseOutcome)>) {
        let mut g = lock(&self.inner);
        g.sweep(now);
        let mut enter = Vec::new();
        let mut outcomes = Vec::new();
        while let Some(p) = g.approved.pop_front() {
            let id = p.envelope.message_id.clone();
            match g.check_at_drain(p, live, now) {
                Ok(p) => {
                    g.budget.consume();
                    enter.push(p.envelope.clone());
                    g.queued.insert(msg_key(&p.envelope), p);
                    outcomes.push((id, ReleaseOutcome::Delivered));
                }
                Err(outcome) => outcomes.push((id, outcome)),
            }
        }
        (enter, outcomes)
    }

    /// Right before a queued row starts or is promoted into a turn: `true` = it may enter. `false` = it went back to held or was
    /// dropped, and the caller removes the row. A peer row this state does not know is NOT qualified: it is dropped with a notice
    /// and never runs. Calling again for a row that already passed re-checks it (the answer can change).
    pub fn recheck_queued(&self, key: &MsgKey, now: u64, live: &Live) -> bool {
        let mut g = lock(&self.inner);
        let tracked = match g.queued.remove(key) {
            Some(p) => Some(p),
            None => g
                .in_flight
                .iter()
                .position(|(k, _)| k == key)
                .and_then(|pos| g.in_flight.remove(pos))
                .map(|(_, p)| p),
        };
        let Some(p) = tracked else {
            let ev = AuditEvent::from_key(key, g.audit.to_session(), AuditOutcome::Refused, Some(&RejectReason::Unavailable), now_secs());
            g.audit.emit(ev);
            g.notice_from(&key.0, &key.1, NoticeKind::Refused(RejectReason::Unavailable));
            return false;
        };
        match g.check_at_drain(p, live, now) {
            Ok(mut p) => {
                // Out of the count from here on (a running turn is not a stored message).
                p.ticket = None;
                if g.in_flight.len() >= IN_FLIGHT_RING {
                    g.in_flight.pop_front();
                }
                g.in_flight.push_back((key.clone(), p));
                g.in_flight_live += 1;
                true
            }
            Err(_) => false,
        }
    }

    /// Forget tracked rows whose queue row is gone (cancelled, removed): they no longer count against the bounds.
    pub fn prune_queued(&self, still_queued: &HashSet<MsgKey>) {
        lock(&self.inner).queued.retain(|id, _| still_queued.contains(id));
    }

    /// Any admission not yet delivered: tracked as queued, held for a release, or approved and waiting for the drain.
    pub fn has_undelivered(&self) -> bool {
        let g = lock(&self.inner);
        !g.queued.is_empty() || !g.held.is_empty() || !g.approved.is_empty() || g.in_flight_live > 0
    }

    /// Record that a turn started or joined by a peer input is running (or that the turn ended).
    pub fn set_peer_turn_in_flight(&self, running: bool) {
        if !running {
            let mut g = lock(&self.inner);
            g.in_flight_live = 0;
            *g.turn_conv.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }
        self.peer_turn.store(running, Ordering::SeqCst);
    }

    /// S5.6: the delivered peer message `message_id` started or joined the running turn. The turn's conversation is that of the
    /// message with the highest hop (the chain stays as long as any part of it is in the turn). A message whose conversation is
    /// unknown fails closed: the turn sends at the hop budget, so the receiver's hop check stops the chain.
    pub(crate) fn note_turn_peer_message(&self, message_id: &str) {
        self.gate.watches.bind_turn(message_id);
        let g = lock(&self.inner);
        let c = match g.conv_of.get(message_id).cloned() {
            Some(c) => c,
            None => {
                tracing::debug!(message_id, "peer turn has no recorded conversation: sends from it use the hop budget");
                (message_id.to_owned(), fuigo_peer::limits::HOP_BUDGET.saturating_sub(1))
            }
        };
        let mut ch = g.chain.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if ch.as_ref().is_none_or(|(_, h)| c.1 >= *h) {
            *ch = Some(c);
        }
        // The turn's view follows the chain (which never decreases), so a join cannot lower it either.
        *g.turn_conv.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = ch.clone();
    }

    /// S5.6: a turn is starting. `human_typed` is true only for `PromptOrigin::User`: it clears the peer chain, so the turn sends at
    /// hop 0 in a new conversation. Any other turn INHERITS the chain (its sends continue that conversation at hop + 1), and a
    /// peer message that starts it raises the chain. The returned guard clears only the per-turn view when the turn ends (normal,
    /// cancel, error, panic, abort); the chain itself lives across turns.
    pub(crate) fn begin_turn(&self, human_typed: bool, peer_message_id: Option<&str>) -> TurnConvGuard {
        let handle = self.turn_conv_handle();
        {
            let mut g = lock(&self.inner);
            g.turn_obs = TurnObs::default();
            let mut ch = g.chain.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if human_typed {
                *ch = None;
            }
            *handle.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = ch.clone();
        }
        if let Some(id) = peer_message_id {
            self.note_turn_peer_message(id);
        }
        self.gate.watches.turn_started();
        TurnConvGuard(handle, self.gate.clone())
    }

    /// The peer chain since the last human prompt (see [`Inner::chain`]).
    #[cfg(test)]
    pub(crate) fn peer_chain(&self) -> Option<(String, u32)> {
        lock(&self.inner).chain.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }

    /// S5.6: what a message sent from the running turn continues: `Some((conversation id, received hop))` when a peer message is
    /// part of the turn, `None` for a human-started turn (a new conversation at hop 0).
    pub(crate) fn turn_conversation(&self) -> Option<(String, u32)> {
        self.turn_conv_handle().lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }

    /// A `Send + Sync` handle to the turn's conversation, for closures that must not capture the actor.
    pub(crate) fn turn_conv_handle(&self) -> Arc<Mutex<Option<(String, u32)>>> {
        lock(&self.inner).turn_conv.clone()
    }

    /// Whether a turn started or joined by a peer input is running.
    pub fn peer_turn_in_flight(&self) -> bool {
        self.peer_turn.load(Ordering::SeqCst)
    }

    pub fn has_queued(&self) -> bool {
        !lock(&self.inner).queued.is_empty()
    }

    /// List held messages for a client that attached. Every call issues NEW tokens and kills the old ones (S4.6: a reconnecting
    /// client asks again).
    pub fn list_held(&self, now: u64) -> Vec<HeldSummary> {
        let mut g = lock(&self.inner);
        g.sweep(now);
        let overflow = g.carried_overflow;
        g.held
            .iter_mut()
            .map(|h| {
                h.token = new_token();
                HeldSummary {
                    message_id: h.envelope.message_id.clone(),
                    from: h.envelope.from.to_string(),
                    from_ref: h.envelope.from_ref.clone(),
                    from_name: h.envelope.from_name.clone(),
                    from_mode: h.envelope.from_mode.to_wire(),
                    reason: h.reason,
                    reason_names: std::iter::once(h.reason).chain(h.also.iter().copied()).map(hold_name).collect(),
                    detail: hold_detail(h.reason, &h.envelope, &h.also, overflow),
                    expires_at: wall_expiry(h.deadline, now),
                    token: h.token.clone(),
                }
            })
            .collect()
    }

    /// The held rows WITHOUT touching their tokens (the token field is empty): a read that must not void the tokens a client
    /// already holds (the ACP event pump, packet 13).
    pub fn held_snapshot(&self, now: u64) -> Vec<HeldSummary> {
        let mut g = lock(&self.inner);
        g.sweep(now);
        let overflow = g.carried_overflow;
        g.held
            .iter()
            .map(|h| HeldSummary {
                message_id: h.envelope.message_id.clone(),
                from: h.envelope.from.to_string(),
                from_ref: h.envelope.from_ref.clone(),
                from_name: h.envelope.from_name.clone(),
                from_mode: h.envelope.from_mode.to_wire(),
                reason: h.reason,
                reason_names: std::iter::once(h.reason).chain(h.also.iter().copied()).map(hold_name).collect(),
                detail: hold_detail(h.reason, &h.envelope, &h.also, overflow),
                expires_at: wall_expiry(h.deadline, now),
                token: String::new(),
            })
            .collect()
    }

    pub fn held_count(&self) -> usize {
        lock(&self.inner).held.len()
    }

    /// S6.6: take the baseline snapshot (a no-op once armed or arming), inline. The file reads run outside the lock. Production
    /// uses [`Self::integrity_arm_background`]; this is the same work on the caller's thread.
    #[cfg(test)]
    pub(crate) fn integrity_arm(&self, roots: &super::peer_integrity::Roots) {
        if lock(&self.inner).integrity.armed() {
            return;
        }
        let watch = super::peer_integrity::Watch::snapshot(roots);
        lock(&self.inner).integrity.arm_with(watch);
    }

    /// S6.6: start the baseline snapshot on a blocking thread and return at once (no file work on the caller, which may hold
    /// the session state lock). The result waits in a slot until [`Self::integrity_wait_armed`] adopts it, and every recheck
    /// waits for it first, so the baseline is complete before the first tool call of the influenced turn. Without a runtime
    /// (sync tests) the snapshot is taken inline.
    pub(crate) fn integrity_arm_background(&self, roots: super::peer_integrity::Roots) {
        let generation = {
            let mut g = lock(&self.inner);
            if !g.integrity.begin_arming() {
                return;
            }
            g.integrity.generation()
        };
        let baseline = self.baseline.clone();
        #[cfg(test)]
        let hooks = self.hooks.clone();
        let work = move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                #[cfg(test)]
                {
                    hooks.baseline_starts.fetch_add(1, Ordering::SeqCst);
                    if let Some(h) = hooks.in_baseline.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
                        h();
                    }
                    if hooks.panic_baseline.swap(false, Ordering::SeqCst) {
                        panic!("test: baseline read panics");
                    }
                }
                super::peer_integrity::Watch::snapshot(&roots)
            }));
            // A panicked read leaves no baseline to compare with: it is adopted empty and the hold goes up (fail closed).
            let (watch, panicked) = match result {
                Ok(w) => (w, false),
                Err(_) => (Default::default(), true),
            };
            *baseline.slot.lock().unwrap_or_else(|p| p.into_inner()) = Some((watch, generation, panicked));
            baseline.done.send_modify(|n| *n = n.wrapping_add(1));
        };
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                drop(rt.spawn_blocking(work));
            }
            Err(_) => work(),
        }
    }

    /// Move a finished baseline from its slot into the state.
    /// Returns the generation when the adopted read had panicked (the hold is up; the caller writes marker and warning).
    fn adopt_baseline(&self) -> Option<u64> {
        let ready = self.baseline.slot.lock().unwrap_or_else(|p| p.into_inner()).take();
        let (watch, generation, panicked) = ready?;
        let mut g = lock(&self.inner);
        g.integrity.adopt(watch, generation);
        if panicked && g.integrity.put_back(true, generation) {
            return Some(generation);
        }
        None
    }

    /// The bound on one wait for a protected-file read (baseline or recheck).
    fn integrity_wait_limit(&self) -> std::time::Duration {
        #[cfg(test)]
        {
            let ms = self.hooks.wait_ms.load(Ordering::SeqCst);
            if ms > 0 {
                return std::time::Duration::from_millis(ms);
            }
        }
        INTEGRITY_WAIT
    }

    /// Wait (no lock held, bounded by [`INTEGRITY_WAIT`]) until a started baseline read is finished and adopted. Returns the
    /// findings the caller must persist and show: empty normally; one "unreadable" finding the first time the read panicked or
    /// the wait timed out (fail closed: the hold is up, and a late result never lifts it). The blocking task may stay parked on
    /// a dead read; it holds no lock, and the tripped state starts no second one.
    pub(crate) async fn integrity_await_baseline(&self) -> Vec<super::peer_integrity::Change> {
        let deadline = tokio::time::Instant::now() + self.integrity_wait_limit();
        let mut rx = self.baseline.done.subscribe();
        loop {
            if let Some(generation) = self.adopt_baseline() {
                return self.integrity_apply_changes(vec![super::peer_integrity::Change::unreadable()], generation);
            }
            if !lock(&self.inner).integrity.arming() {
                return Vec::new();
            }
            match tokio::time::timeout_at(deadline, rx.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Vec::new(),
                Err(_) => {
                    if let Some(generation) = self.adopt_baseline() {
                        return self.integrity_apply_changes(vec![super::peer_integrity::Change::unreadable()], generation);
                    }
                    let generation = {
                        let mut g = lock(&self.inner);
                        if !g.integrity.trip_timeout() {
                            return Vec::new();
                        }
                        g.integrity.generation()
                    };
                    return self.integrity_apply_changes(vec![super::peer_integrity::Change::unreadable()], generation);
                }
            }
        }
    }

    /// Test and compatibility wrapper: wait for the baseline, discarding the findings.
    #[cfg(test)]
    pub(crate) async fn integrity_wait_armed(&self) {
        let _ = self.integrity_await_baseline().await;
    }

    /// S6.6: recheck after a tool call. On the first change: set the `integrity` hold, queue one audit line per changed file
    /// (hashes only) and one notice per file, and return the changes so the caller can warn the human. A tripped state
    /// returns nothing and reads nothing (the warning is not repeated).
    #[cfg(test)]
    pub(crate) fn integrity_check(&self) -> Vec<super::peer_integrity::Change> {
        let _ = self.adopt_baseline();
        let Some((watch, generation)) = lock(&self.inner).integrity.take_for_check() else { return Vec::new() };
        super::peer_integrity::recheck_into_pending(&watch);
        self.integrity_apply(&watch, generation)
    }

    /// The production recheck: waits for a started baseline, does the file work on a blocking thread with no lock held, then
    /// applies the result under the (short) lock. Cancel-safe: findings parked in the watch are reported by the next call.
    pub(crate) async fn integrity_check_async(&self) -> Vec<super::peer_integrity::Change> {
        let early = self.integrity_await_baseline().await;
        if !early.is_empty() {
            return early;
        }
        let Some((watch, generation)) = lock(&self.inner).integrity.take_for_check() else { return Vec::new() };
        let w = watch.clone();
        #[cfg(test)]
        let hooks = self.hooks.clone();
        let job = tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            if let Some(h) = hooks.in_recheck.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
                h();
            }
            #[cfg(test)]
            if hooks.panic_recheck.swap(false, Ordering::SeqCst) {
                panic!("test: recheck panics");
            }
            super::peer_integrity::recheck_into_pending(&w)
        });
        // Bounded: a recheck stuck on a dead mount fails closed. The parked task holds only the watch's own mutex; once the hold
        // is up no further recheck starts, so at most one such task exists.
        let done = tokio::time::timeout(self.integrity_wait_limit(), job).await;
        if !matches!(done, Ok(Ok(()))) {
            // The file work died: fail closed. The hold goes up and the caller gets one finding, so it writes the marker and
            // warns the human, exactly as for a real change (the finding names no file; it has no hashes).
            let c = super::peer_integrity::Change::unreadable();
            return self.integrity_apply_changes(vec![c], generation);
        }
        self.integrity_apply(&watch, generation)
    }

    fn integrity_apply(&self, watch: &super::peer_integrity::SharedWatch, generation: u64) -> Vec<super::peer_integrity::Change> {
        let changes = super::peer_integrity::drain_pending(watch);
        self.integrity_apply_changes(changes, generation)
    }

    fn integrity_apply_changes(&self, changes: Vec<super::peer_integrity::Change>, generation: u64) -> Vec<super::peer_integrity::Change> {
        let mut g = lock(&self.inner);
        if !g.integrity.put_back(!changes.is_empty(), generation) {
            // A clear ran while the files were being read: the human's clear stands, the stale result is dropped.
            return Vec::new();
        }
        for c in &changes {
            g.audit_integrity(c);
            g.notice(&super::peer_integrity::display_path(&c.path), NoticeKind::ProtectedFileChanged);
        }
        changes
    }

    /// Restore the `integrity` hold from stored history (a resumed session whose last hold marker says tripped). The hold is
    /// up before any message can be decided.
    pub(crate) fn integrity_restore_tripped(&self) {
        lock(&self.inner).integrity.restore_tripped();
    }

    /// `/peers clear-influence` (typed by the human) ends the watch and the `integrity` hold.
    pub(crate) fn integrity_reset(&self) {
        lock(&self.inner).integrity.reset();
    }

    #[cfg(test)]
    pub(crate) fn integrity_armed(&self) -> bool {
        lock(&self.inner).integrity.armed()
    }

    pub(crate) fn integrity_tripped(&self) -> bool {
        lock(&self.inner).integrity.tripped()
    }

    /// Item 3: record that a stored peer-influenced session was resumed with the feature off and stays guarded.
    /// Remove the pending `GuardKeptFeatureOff` notice; `true` if there was one (the host tells the human directly).
    pub(crate) fn take_guard_kept_feature_off(&self) -> bool {
        let mut g = lock(&self.inner);
        let before = g.notices.len();
        g.notices.retain(|n| n.kind != NoticeKind::GuardKeptFeatureOff);
        g.notices.len() != before
    }

    pub(crate) fn note_guard_kept_feature_off(&self) {
        lock(&self.inner).notice("", NoticeKind::GuardKeptFeatureOff);
    }

    /// S7.4: remember that a peer message was delivered into the session (the model may refuse it by id).
    pub(crate) fn note_delivered(&self, env: &Envelope) {
        let mut g = lock(&self.inner);
        let (id, from) = (env.message_id.clone(), env.from.to_string());
        if g.sender_of.insert(id.clone(), from.clone()).is_none() {
            if g.received.len() >= RECEIVED_RING
                && let Some(old) = g.received.pop_front()
            {
                g.sender_of.remove(&old);
                g.conv_of.remove(&old);
                g.label_of.remove(&old);
            }
            g.received.push_back(id.clone());
        }
        g.conv_of.insert(id.clone(), (env.conversation_id.clone(), env.hop));
        g.label_of.insert(id.clone(), (env.from_name.clone(), env.from_ref.clone()));
        // A message that carried denials stays nameable until the human clears the influence, however many arrive after it.
        if !env.denied_recently.is_empty() && !g.pinned_senders.iter().any(|(i, _)| *i == id) {
            if g.pinned_senders.len() >= PINNED_SENDERS {
                g.pinned_senders.remove(0);
            }
            g.pinned_senders.push((id, from));
        }
    }

    /// S7.4: `refuse_peer_message` is offered only once the session has received a peer message.
    pub(crate) fn has_received(&self) -> bool {
        !lock(&self.inner).received.is_empty()
    }

    /// The sender address of a delivered message still remembered: the last 256 delivered, or any that carried denials (at most
    /// 64, until clear-influence). Beyond that the id is unknown.
    fn sender_for(inner: &Inner, id: &str) -> Option<String> {
        inner
            .sender_of
            .get(id)
            .cloned()
            .or_else(|| inner.pinned_senders.iter().find(|(i, _)| i == id).map(|(_, f)| f.clone()))
    }

    /// The denial log's carried-overflow count, set by the session before it lists held rows or releases one (counts only).
    pub(crate) fn set_carried_overflow(&self, overflow: usize) {
        lock(&self.inner).carried_overflow = overflow;
    }

    /// S7.4: the model refuses a delivered message. The sender is held for the rest of the session (reason `sender_denied`:
    /// the same hold the stamp gives), a `ModelRefused` notice is queued for the human and the sender, and an audit line with
    /// ids only is written. The `reason` text is capped at 200 characters and escaped; it is not audited.
    pub(crate) fn refuse_by_model(&self, message_id: &str, reason: &str) -> Result<ModelRefusal, UnknownMessage> {
        let mut g = lock(&self.inner);
        g.turn_obs.model_refused = true;
        Self::refuse_locked(&mut g, message_id, reason, false)
    }

    /// The refusal itself, shared by the tool and the automatic path. The tool path (`automatic == false`) also holds the sender
    /// for the session; the automatic path refuses that one message only (notice, audit line `automatic`, settled watch).
    fn refuse_locked(g: &mut Inner, message_id: &str, reason: &str, automatic: bool) -> Result<ModelRefusal, UnknownMessage> {
        let Some(from) = Self::sender_for(g, message_id) else {
            return Err(UnknownMessage);
        };
        let id = message_id.to_owned();
        let from_s = from.clone();
        if !automatic {
            // Only the model's own decision holds the sender. The sender is just the envelope's claimed `from`, which any
            // same-user process can forge, so an automatic refusal never writes per-sender state (26-4/26-5 round 2).
            g.refused_senders.insert(from.clone());
            g.state_dirty = true;
        }
        let why = automatic.then_some("automatic");
        let ev = AuditEvent::from_key(&(from, id.clone()), g.audit.to_session(), AuditOutcome::ModelRefused, why.as_ref(), now_secs());
        g.audit.emit(ev);
        let cut: String = reason.chars().take(REFUSE_REASON_SHOWN_CHARS).collect();
        let shown_reason = super::peer_message::escape_attr(&cut);
        // The reason is for the human's row only: not in the audit line above, not forwarded to the sender.
        g.notice_with(&from_s, &id, NoticeKind::ModelRefused, Some(shown_reason.clone()));
        Ok(ModelRefusal { shown_reason })
    }

    /// 26-4/26-5: fold one model reply of the running turn into the turn's record.
    pub(crate) fn note_model_response(&self, tool_calls: usize, has_text: bool, provider_refused: bool) {
        let mut g = lock(&self.inner);
        g.turn_obs.tool_calls = g.turn_obs.tool_calls.saturating_add(u32::try_from(tool_calls).unwrap_or(u32::MAX));
        g.turn_obs.text_seen |= has_text;
        g.turn_obs.provider_refused |= provider_refused;
    }

    #[cfg(test)]
    pub(crate) fn turn_observed_anything(&self) -> bool {
        let o = lock(&self.inner).turn_obs;
        o.tool_calls > 0 || o.text_seen || o.provider_refused || o.model_refused
    }

    /// 26-4/26-5: a turn started by the peer message `message_id` ended normally. When it made no tool call of any kind and the
    /// model did not refuse the message itself, the message is recorded refused automatically (the notice, audit and settled watch of
    /// `refuse_peer_message`, but it does NOT hold the sender), and an empty reply or a refusal stop also puts one notice in the user's transcript.
    /// Returns true when it recorded the refusal.
    pub(crate) fn finish_peer_turn(&self, message_id: &str, refusal_stop: bool) -> bool {
        let mut g = lock(&self.inner);
        let obs = std::mem::take(&mut g.turn_obs);
        if obs.tool_calls > 0 || obs.model_refused {
            return false;
        }
        let Some(from) = Self::sender_for(&g, message_id) else { return false };
        let declined = refusal_stop || obs.provider_refused;
        if declined || !obs.text_seen {
            let (name, sref) = g.label_of.get(message_id).cloned().unwrap_or_default();
            let label = format!("{} [{}]", fuigo_peer::host::display_escape(&name, 64), fuigo_peer::host::display_escape(&sref, 64));
            let kind = if declined { NoticeKind::PeerTurnDeclined } else { NoticeKind::PeerTurnNoReply };
            g.notice_with(&from, message_id, kind, Some(label));
        }
        Self::refuse_locked(&mut g, message_id, AUTO_REFUSE_REASON, true).is_ok()
    }

    /// S7.3: tool requests were denied `laundering_refused`. One human notice and one audit line (message id and tool kind)
    /// each. The notice queue is the only sender-notice path in-process today (no transport yet).
    pub(crate) fn note_laundering(&self, hits: Vec<fuigo_workspace::permission::LaunderingHit>) {
        let mut g = lock(&self.inner);
        for h in hits {
            let from = Self::sender_for(&g, &h.message_id).unwrap_or_default();
            let ev = AuditEvent::from_key(&(from.clone(), h.message_id.clone()), g.audit.to_session(), AuditOutcome::LaunderingRefused, Some(&h.kind), now_secs());
            g.audit.emit(ev);
            // One notice per (message, tool kind): a model retrying the same action cannot push other notices out of the ring.
            if g.laundering_reported.len() >= 256 {
                g.laundering_reported.clear();
            }
            if g.laundering_reported.insert((h.message_id.clone(), h.kind.clone())) {
                g.notice_from(&from, &h.message_id, NoticeKind::LaunderingRefused);
            }
        }
    }

    // ---- S7 persistence helpers (the marker items are written by the session actor) ----

    /// Mirror what `DenialLog::carry` keeps (same dedupe and bound) so the carried list can be written as a marker.
    pub(crate) fn mirror_carry(&self, message_id: &str, stamps: &[fuigo_peer::DenialStamp]) {
        let mut g = lock(&self.inner);
        for s in stamps {
            if g.carried_mirror.iter().any(|(k, h, _)| *k == s.tool_kind && *h == s.target_hash) {
                continue;
            }
            // Same rule as the denial log: never evict, drop the newest and count it.
            if g.carried_mirror.len() >= CARRIED_CAP {
                g.carried_overflow += 1;
                continue;
            }
            g.carried_mirror.push((s.tool_kind.clone(), s.target_hash.clone(), message_id.to_owned()));
            g.state_dirty = true;
        }
    }

    /// The receiver-side state to store, if it changed since the last call (clears the changed flag).
    pub(crate) fn take_state_to_store(&self) -> Option<fuigo_sampling_types::PeerCarriedState> {
        let mut g = lock(&self.inner);
        if !std::mem::take(&mut g.state_dirty) {
            return None;
        }
        let mut refused: Vec<String> = g.refused_senders.iter().cloned().collect();
        refused.sort();
        Some(fuigo_sampling_types::PeerCarriedState { carried: g.carried_mirror.clone(), refused })
    }

    /// The current receiver-side state (regardless of the changed flag), `None` when both lists are empty.
    pub(crate) fn snapshot_peer_state(&self) -> Option<fuigo_sampling_types::PeerCarriedState> {
        let g = lock(&self.inner);
        let mut refused: Vec<String> = g.refused_senders.iter().cloned().collect();
        refused.sort();
        let st = fuigo_sampling_types::PeerCarriedState { carried: g.carried_mirror.clone(), refused };
        (!st.is_empty()).then_some(st)
    }

    /// Marker appends failed for the last `n` entries handed out by `new_denials` (they are the tail of the synced ring):
    /// forget they were written, so the next `new_denials` returns them again.
    pub(crate) fn unsync_tail(&self, n: usize) {
        let mut g = lock(&self.inner);
        let keep = g.denial_synced.len().saturating_sub(n);
        g.denial_synced.truncate(keep);
    }

    /// Put the changed flag back after a failed write.
    pub(crate) fn mark_state_dirty(&self) {
        lock(&self.inner).state_dirty = true;
    }

    /// Resume: the stored carried entries and refused senders (the caller also loads the carried entries into the denial log).
    pub(crate) fn restore_peer_state(&self, st: &fuigo_sampling_types::PeerCarriedState) {
        let mut g = lock(&self.inner);
        g.carried_mirror = st.carried.clone();
        g.refused_senders = st.refused.iter().cloned().collect();
        g.state_dirty = false;
    }

    /// `/peers clear-influence`: forget the carried mirror and the refused-sender holds. Returns how many senders were released.
    pub(crate) fn clear_peer_state(&self) -> usize {
        let mut g = lock(&self.inner);
        g.carried_mirror.clear();
        g.pinned_senders.clear();
        g.carried_overflow = 0;
        g.state_dirty = false;
        let n = g.refused_senders.len();
        g.refused_senders.clear();
        n
    }

    pub(crate) fn refused_sender_count(&self) -> usize {
        lock(&self.inner).refused_senders.len()
    }

    /// The sender-side ring entries not yet written: `snapshot` is the ring now (oldest first). Entries already written form a
    /// prefix overlap (the ring only appends and evicts the front), so only the tail past the longest overlap is new.
    pub(crate) fn new_denials(&self, snapshot: Vec<Vec<fuigo_workspace::permission::DenialKey>>) -> Vec<Vec<fuigo_workspace::permission::DenialKey>> {
        let mut g = lock(&self.inner);
        let old = &g.denial_synced;
        let max = old.len().min(snapshot.len());
        let overlap = (0..=max).rev().find(|k| old[old.len() - k..] == snapshot[..*k]).unwrap_or(0);
        let fresh = snapshot[overlap..].to_vec();
        g.denial_synced = snapshot;
        fresh
    }

    /// Resume: the ring entries rebuilt from storage count as written.
    pub(crate) fn set_denials_synced(&self, keys: Vec<Vec<fuigo_workspace::permission::DenialKey>>) {
        lock(&self.inner).denial_synced = keys;
    }

    /// Record a typed notice about a message this session sent. The caller has already matched `message_id` to one of
    /// this session's sends.
    pub(crate) fn record_sent_notice(&self, message_id: &str, kind: fuigo_peer::NoticeKind) {
        lock(&self.inner).notice(message_id, NoticeKind::SentMessage(kind));
    }

    /// Drop expired holds and report any notices recorded since the last call.
    /// Packet 11: record a notice about a sent message with the kind `None` meaning `outcome unknown`.
    pub(crate) fn record_sent_notice_opt(&self, message_id: &str, kind: Option<fuigo_peer::NoticeKind>) {
        let k = kind.map_or(NoticeKind::SentOutcomeUnknown, NoticeKind::SentMessage);
        lock(&self.inner).notice(message_id, k);
    }

    /// Packet 11 (S5.6, S9.4): a turn started by a delivery notice counts against the peer-started-turn budget. False (nothing
    /// consumed) when the budget is used up: the notice stays in the notice ring but wakes nothing.
    pub(crate) fn consume_notice_turn(&self) -> bool {
        let mut g = lock(&self.inner);
        if g.budget.exhausted() {
            return false;
        }
        g.budget.consume();
        true
    }

    pub fn take_notices(&self, now: u64) -> Vec<PeerNotice> {
        let mut g = lock(&self.inner);
        g.sweep(now);
        g.notices.drain(..).collect()
    }
}

/// The wall-clock second at which a monotonic `deadline` falls, as reported to clients. Only this report reads wall time.
fn wall_expiry(deadline: u64, now_mono: u64) -> u64 {
    // Unit tests that pass explicit times without a test clock treat the supplied times as wall seconds.
    #[cfg(test)]
    if TEST_CLOCK.with(std::cell::Cell::get).is_none() {
        return deadline;
    }
    now_secs().saturating_add(deadline.saturating_sub(now_mono))
}

/// Seconds on a monotonic clock (immune to wall-clock steps): every expiry decision is made on this. Tests override it with
/// [`set_test_clock`], which sets both clocks to the same value.
pub fn now_mono() -> u64 {
    #[cfg(test)]
    if let Some(t) = TEST_CLOCK.with(std::cell::Cell::get) {
        return t;
    }
    static BASE: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    BASE.get_or_init(std::time::Instant::now).elapsed().as_secs()
}

/// Unix seconds, for reporting only. Tests override it with [`set_test_clock`] (no sleeps).
pub fn now_secs() -> u64 {
    #[cfg(test)]
    if let Some(t) = TEST_CLOCK.with(std::cell::Cell::get) {
        return t;
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
thread_local! {
    static TEST_CLOCK: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub fn set_test_clock(t: Option<u64>) {
    TEST_CLOCK.with(|c| c.set(t));
}

/// Commands the session handle sends to the actor for admission.
pub enum PeerAdminCmd {
    Submit(Box<Envelope>),
    Release { message_id: String, token: String },
    Reject { message_id: String, token: String },
    ListHeld,
    /// Held rows with empty tokens; voids nothing (packet 13 event pump).
    HeldSnapshot,
    Configure(PeerAdmissionConfig),
    TakeNotices,
    /// A typed notice about a message this session sent (packet 8e).
    SentNotice { message_id: String, kind: fuigo_peer::NoticeKind },
    /// Packet 11 (S9.4): a notice about a message this session sent, from the receiving host (`kind`) or from this host's own
    /// watch (`None` = `outcome unknown`). `target` is the target's address as the host recorded it. It is recorded like
    /// `SentNotice` and ALSO wakes the model with fixed text, if the peer-turn budget allows.
    SentNoticeWake { message_id: String, kind: Option<fuigo_peer::NoticeKind>, target: String },
}

pub enum PeerAdminReply {
    Submit(PeerSubmit),
    Release(Result<ReleaseOutcome, ReleaseError>),
    Reject(Result<(), ReleaseError>),
    Held(Vec<HeldSummary>),
    Done,
    Notices(Vec<PeerNotice>),
}

#[cfg(test)]
#[path = "peer_admission_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "peer_laundering_tests.rs"]
mod laundering_tests;

#[cfg(test)]
#[path = "peer_ingress_tests.rs"]
mod ingress_tests;

/// Clears the running turn's peer conversation when dropped (see [`PeerAdmissionState::begin_turn`]).
pub(crate) struct TurnConvGuard(Arc<Mutex<Option<(String, u32)>>>, Arc<super::message_delivery::PeerGate>);

impl Drop for TurnConvGuard {
    fn drop(&mut self) {
        *self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        // Packet 11: the watches bound to this turn fire now, once.
        self.1.watches.turn_ended();
    }
}
