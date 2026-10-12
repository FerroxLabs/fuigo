//! Packet 5 part A: ingress bounds, per-host totals, rate limits, replay memory and the loop budget, at the state level.
//! Clock-injected (`now` is a plain number): no sleeps, no real service.

use super::*;
use crate::session::peer_message::test_envelope;
use fuigo_peer::limits::*;
use fuigo_peer::{Address, PeerBase, TurnOrigin, next_hop};

const T0: u64 = 1_000;

fn ae() -> PeerMode {
    PeerMode::new(false, PeerBase::AcceptEdits, false)
}

fn live() -> Live {
    Live { feature_on: true, receiver_mode: ae() }
}

fn cfg() -> PeerAdmissionConfig {
    PeerAdmissionConfig {
        opted_in: true,
        policy: PeerInboundPolicy::Accept,
        operator: OperatorPresence::Present,
        relay_driven: false,
    }
}

/// A host ingress with the rate limits lifted, so the store and loop rules can be exercised alone.
fn open_host() -> Arc<Mutex<PeerIngress>> {
    let c = IngressConfig { pair_per_minute: usize::MAX, host_per_minute: usize::MAX, ..IngressConfig::default() };
    Arc::new(Mutex::new(PeerIngress::new(c, Arc::new(HostLedger::default()))))
}

fn session(host: &Arc<Mutex<PeerIngress>>) -> PeerAdmissionState {
    let s = PeerAdmissionState::with_host(host.clone());
    s.configure(cfg());
    s
}

fn env(sender: usize, id: &str, body: &str, hop: u32) -> Envelope {
    let mut e = test_envelope(id, "lane a", body);
    e.from = Address::new("0123456789abcdef0123456789abcdef", &format!("sender-{sender}"), 1).unwrap();
    e.hop = hop;
    e
}

fn mismatch(mut e: Envelope) -> Envelope {
    e.from_mode = PeerMode::new(false, PeerBase::Default, false);
    e
}

fn outcome(s: Submitted) -> DeliveryOutcome {
    match s {
        Submitted::Enqueue => DeliveryOutcome::Delivered {},
        Submitted::Done(o) => o,
    }
}

fn rejected(r: RejectReason) -> DeliveryOutcome {
    DeliveryOutcome::Rejected { reason: r }
}

/// S5.1: the receiver checks the body again; N passes, N+1 is `too_large` and nothing is stored.
#[test]
fn s5_1_receiver_rechecks_body_size() {
    let h = open_host();
    let s = session(&h);
    let ok = env(1, "a", &"x".repeat(MAX_BODY_BYTES), 0);
    assert!(matches!(s.submit(ok, T0, &live()), Submitted::Enqueue));
    let big = env(1, "b", &"x".repeat(MAX_BODY_BYTES + 1), 0);
    assert_eq!(outcome(s.submit(big, T0, &live())), rejected(RejectReason::TooLarge));
    assert_eq!(s.host_usage(), (1, MAX_BODY_BYTES));
}

/// S5.2: 4 sessions x 64 messages = 256 fill the host; the 257th (a fifth session) is `saturated`, and one freed slot is reusable.
#[test]
fn s5_2_host_total_256_messages_across_sessions() {
    let h = open_host();
    let sessions: Vec<_> = (0..5).map(|_| session(&h)).collect();
    for (si, s) in sessions.iter().take(4).enumerate() {
        for n in 0..MAX_MESSAGES_PER_SESSION {
            let e = mismatch(env(si, &format!("m{n}"), "b", 0));
            assert!(matches!(s.submit(e, T0, &live()), Submitted::Done(DeliveryOutcome::Held { .. })));
        }
    }
    assert_eq!(sessions[0].host_usage().0, MAX_MESSAGES_PER_HOST);
    let e = mismatch(env(9, "over", "b", 0));
    assert_eq!(outcome(sessions[4].submit(e, T0, &live())), rejected(RejectReason::Saturated));
    assert_eq!(sessions[4].held_count(), 0, "a refused message costs nothing in the store");
    // Session 0 ends: its 64 are returned, the fifth session can hold again.
    let mut sessions = sessions;
    let first = sessions.remove(0);
    drop(first);
    assert_eq!(sessions[0].host_usage().0, 3 * MAX_MESSAGES_PER_SESSION);
    let e = mismatch(env(9, "again", "b", 0));
    assert!(matches!(sessions[3].submit(e, T0, &live()), Submitted::Done(DeliveryOutcome::Held { .. })));
}

/// S5.2: 4 MiB across sessions; one byte more is refused.
#[test]
fn s5_2_host_total_4_mib_across_sessions() {
    let h = open_host();
    let per = MAX_BODY_BYTES;
    let sessions: Vec<_> = (0..5).map(|_| session(&h)).collect();
    for (si, s) in sessions.iter().take(4).enumerate() {
        for n in 0..MAX_BODY_BYTES_PER_SESSION / per {
            let e = mismatch(env(si, &format!("m{n}"), &"x".repeat(per), 0));
            assert!(matches!(s.submit(e, T0, &live()), Submitted::Done(DeliveryOutcome::Held { .. })));
        }
    }
    assert_eq!(sessions[0].host_usage().1, MAX_BODY_BYTES_PER_HOST);
    let e = mismatch(env(9, "one", "x", 0));
    assert_eq!(outcome(sessions[4].submit(e, T0, &live())), rejected(RejectReason::Saturated));
}

/// S5.2: the host count returns to zero after every exit path, with no leak and no double free.
#[test]
fn s5_2_accounting_returns_to_zero_on_every_exit_path() {
    let l = live();
    for path in ["promote", "release_then_start", "reject", "expire", "session_end", "untrack", "prune", "rehold_then_expire"] {
        let h = open_host();
        let s = session(&h);
        let probe = session(&h); // a second session reads the shared total
        let held = |id: &str| mismatch(env(1, id, "body", 0));
        match path {
            "promote" => {
                assert!(matches!(s.submit(env(1, "a", "body", 0), T0, &l), Submitted::Enqueue));
                assert_eq!(probe.host_usage(), (1, 4));
                assert!(s.recheck_queued(&msg_key(&env(1, "a", "body", 0)), T0, &l));
            }
            "release_then_start" => {
                s.submit(held("a"), T0, &l);
                assert_eq!(probe.host_usage(), (1, 4));
                let tok = s.list_held(T0)[0].token.clone();
                s.release("a", &tok, T0, &l).unwrap();
                assert_eq!(probe.host_usage(), (1, 4), "approved still counts");
                let (enter, _) = s.drain(T0, &l);
                assert_eq!(enter.len(), 1);
                assert_eq!(probe.host_usage(), (1, 4), "queued still counts");
                assert!(s.recheck_queued(&msg_key(&enter[0]), T0, &l));
            }
            "reject" => {
                s.submit(held("a"), T0, &l);
                let tok = s.list_held(T0)[0].token.clone();
                s.reject("a", &tok, T0).unwrap();
            }
            "expire" => {
                s.submit(held("a"), T0, &l);
                assert_eq!(probe.host_usage(), (1, 4));
                s.take_notices(T0 + HOLD_EXPIRY_SECS);
            }
            "session_end" => {
                s.submit(held("a"), T0, &l);
                s.submit(env(2, "b", "body", 0), T0, &l);
                assert_eq!(probe.host_usage(), (2, 8));
            }
            "untrack" => {
                s.submit(env(1, "a", "body", 0), T0, &l);
                s.untrack(&msg_key(&env(1, "a", "body", 0)));
            }
            "prune" => {
                s.submit(env(1, "a", "body", 0), T0, &l);
                s.prune_queued(&HashSet::new());
            }
            "rehold_then_expire" => {
                s.submit(held("a"), T0, &l);
                let tok = s.list_held(T0)[0].token.clone();
                s.release("a", &tok, T0, &l).unwrap();
                // The receiver's mode changed before the drain: the message goes back on hold (the same reservation).
                let changed = Live { feature_on: true, receiver_mode: PeerMode::new(false, PeerBase::Yolo, false) };
                let (enter, outs) = s.drain(T0, &changed);
                assert!(enter.is_empty());
                assert!(matches!(outs[0].1, ReleaseOutcome::Reheld { .. }));
                assert_eq!(probe.host_usage(), (1, 4));
                s.take_notices(T0 + HOLD_EXPIRY_SECS);
            }
            _ => unreachable!(),
        }
        if path == "session_end" {
            drop(s);
        }
        assert_eq!(probe.host_usage(), (0, 0), "path {path}");
    }
}

/// S5.3 through the state: 10 per minute per pair, a refused message stores nothing, the window slides.
#[test]
fn s5_3_pair_rate_through_state() {
    let h = Arc::new(Mutex::new(PeerIngress::default()));
    let s = session(&h);
    for n in 0..10 {
        assert!(matches!(s.submit(mismatch(env(1, &format!("m{n}"), "b", 0)), T0, &live()), Submitted::Done(DeliveryOutcome::Held { .. })));
    }
    assert_eq!(outcome(s.submit(mismatch(env(1, "m10", "b", 0)), T0, &live())), rejected(RejectReason::RateLimited));
    assert_eq!(s.held_count(), 10);
    assert!(matches!(s.submit(mismatch(env(1, "m11", "b", 0)), T0 + 60, &live()), Submitted::Done(DeliveryOutcome::Held { .. })));
}

/// S5.4 through the state: a rejected (operator-refused) id resent 1,000 times is never held again and memory stays flat.
#[test]
fn s5_4_rejected_id_resent_1000_times_creates_no_hold() {
    let h = Arc::new(Mutex::new(PeerIngress::default()));
    let s = session(&h);
    let e = mismatch(env(1, "r", "body", 0));
    let first = outcome(s.submit(e.clone(), T0, &live()));
    assert!(matches!(first, DeliveryOutcome::Held { .. }));
    let tok = s.list_held(T0)[0].token.clone();
    s.reject("r", &tok, T0).unwrap();
    assert_eq!(s.held_count(), 0);
    let sizes = s.ingress_sizes();
    for k in 0..1000 {
        let o = outcome(s.submit(e.clone(), T0 + 1 + k % 30, &live()));
        assert_eq!(o, first, "answered from memory");
    }
    assert_eq!(s.held_count(), 0, "no hold was created");
    assert_eq!(s.host_usage(), (0, 0));
    assert_eq!(s.ingress_sizes(), sizes, "memory flat");
    // The same id with a different body is refused (one rule).
    let other = mismatch(env(1, "r", "other", 0));
    assert_eq!(outcome(s.submit(other, T0 + 2, &live())), rejected(RejectReason::Ambiguous));
    // After 10 minutes the id is forgotten and judged afresh.
    let again = outcome(s.submit(e, T0 + MESSAGE_ID_MEMORY_SECS, &live()));
    assert!(matches!(again, DeliveryOutcome::Held { .. }));
    assert_eq!(s.held_count(), 1);
}

/// S5.4: an expired hold resent within 10 minutes is answered from memory, not held again.
#[test]
fn s5_4_expired_id_resent_is_answered_from_memory() {
    let h = Arc::new(Mutex::new(PeerIngress::default()));
    let s = session(&h);
    let e = mismatch(env(1, "x", "body", 0));
    let first = outcome(s.submit(e.clone(), T0, &live()));
    s.take_notices(T0 + HOLD_EXPIRY_SECS);
    assert_eq!(s.held_count(), 0);
    assert_eq!(outcome(s.submit(e, T0 + HOLD_EXPIRY_SECS + 1, &live())), first);
    assert_eq!(s.held_count(), 0);
}

/// S5.4: another session never sees this session's remembered ids.
#[test]
fn s5_4_memory_is_per_receiving_session() {
    let h = open_host();
    let (a, b) = (session(&h), session(&h));
    let e = mismatch(env(1, "same", "body", 0));
    assert!(matches!(a.submit(e.clone(), T0, &live()), Submitted::Done(DeliveryOutcome::Held { .. })));
    assert!(matches!(b.submit(e, T0, &live()), Submitted::Done(DeliveryOutcome::Held { .. })));
    assert_eq!((a.held_count(), b.held_count()), (1, 1));
}

/// S5.6: hop 7 admits, hop 8 is held with `loop_guard` (never admitted), also far above 8.
#[test]
fn s5_6_hop_7_admits_hop_8_holds_loop_guard() {
    let h = open_host();
    let s = session(&h);
    assert!(matches!(s.submit(env(1, "h7", "b", HOP_BUDGET - 1), T0, &live()), Submitted::Enqueue));
    let o = outcome(s.submit(env(1, "h8", "b", HOP_BUDGET), T0, &live()));
    assert!(matches!(o, DeliveryOutcome::Held { reason: HoldReason::LoopGuard, .. }), "{o:?}");
    let o = outcome(s.submit(env(1, "h99", "b", 99), T0, &live()));
    assert!(matches!(o, DeliveryOutcome::Held { reason: HoldReason::LoopGuard, .. }));
    assert_eq!(s.held_count(), 2);
    // With nobody who can answer a hold, it is refused rather than admitted.
    let none = PeerAdmissionState::with_host(h.clone());
    none.configure(PeerAdmissionConfig { operator: OperatorPresence::None, ..cfg() });
    let mut e = env(1, "h8n", "b", HOP_BUDGET);
    e.from_operator = OperatorKind::None;
    assert_eq!(outcome(none.submit(e, T0, &live())), rejected(RejectReason::NoOperator));
}

/// S5.6: 20 peer messages admitted, the 21st held `loop_guard`, a human prompt resets, a released hold still counts.
#[test]
fn s5_6_turn_budget_20_admitted_21st_held_human_resets() {
    let h = open_host();
    let s = session(&h);
    for n in 0..PEER_TURN_BUDGET {
        assert!(matches!(s.submit(env(1, &format!("m{n}"), "b", 0), T0, &live()), Submitted::Enqueue), "message {n}");
    }
    assert_eq!(s.peer_turns_used(), 20);
    let o = outcome(s.submit(env(1, "m20", "b", 0), T0, &live()));
    assert!(matches!(o, DeliveryOutcome::Held { reason: HoldReason::LoopGuard, .. }), "{o:?}");
    s.human_prompt();
    assert_eq!(s.peer_turns_used(), 0);
    assert!(matches!(s.submit(env(1, "m21", "b", 0), T0, &live()), Submitted::Enqueue));
}

/// S5.6: two sessions answering each other with unique bodies and honest hops stop at hop 8.
#[test]
fn s5_6_alternating_reply_loop_stops_at_hop_budget() {
    let (a, b) = (session(&open_host()), session(&open_host()));
    let mut hop = 0;
    let mut delivered = 0;
    let mut last = None;
    for n in 0..100 {
        let (to, from_idx) = if n % 2 == 0 { (&b, 1) } else { (&a, 2) };
        let o = outcome(to.submit(env(from_idx, &format!("m{n}"), &format!("reply number {n}"), hop), T0, &live()));
        if o != (DeliveryOutcome::Delivered {}) {
            last = Some((n, o));
            break;
        }
        delivered += 1;
        hop = next_hop(TurnOrigin::Peer, hop);
    }
    assert_eq!(delivered, HOP_BUDGET as usize, "hops 0..=7 are admitted");
    let (n, o) = last.expect("the loop must stop");
    assert_eq!(n, 8);
    assert!(matches!(o, DeliveryOutcome::Held { reason: HoldReason::LoopGuard, .. }));
}

/// S5.6, forged hop: a sender that stamps hop 0 on every reply (claiming a human turn each time) defeats the hop check, because the
/// receiver cannot tell a forged lower hop from a real new conversation; the per-session 20-turn budget stops it anyway.
#[test]
fn s5_6_forged_low_hop_is_bounded_by_the_turn_budget() {
    let (a, b) = (session(&open_host()), session(&open_host()));
    let mut stopped_at = None;
    for n in 0..200 {
        let to = if n % 2 == 0 { &b } else { &a };
        let o = outcome(to.submit(env(1 + n % 2, &format!("m{n}"), &format!("unique {n}"), 0), T0, &live()));
        if o != (DeliveryOutcome::Delivered {}) {
            assert!(matches!(o, DeliveryOutcome::Held { reason: HoldReason::LoopGuard, .. }));
            stopped_at = Some(n);
            break;
        }
    }
    // B receives the even-numbered messages: its 21st (n = 40) is the first one held.
    assert_eq!(stopped_at, Some(40));
    assert_eq!(b.peer_turns_used(), PEER_TURN_BUDGET);
}

/// Flag off: nothing is tracked (no ingress entry, no budget use, no host usage).
#[test]
fn flag_off_tracks_nothing() {
    let h = open_host();
    let s = session(&h);
    let off = Live { feature_on: false, receiver_mode: ae() };
    for n in 0..300 {
        assert_eq!(outcome(s.submit(env(n, &format!("m{n}"), "b", 0), T0, &off)), rejected(RejectReason::Unavailable));
    }
    let z = s.ingress_sizes();
    assert_eq!((z.pairs, z.host_log, z.replay), (0, 0, 0));
    assert_eq!(s.peer_turns_used(), 0);
    assert_eq!(s.host_usage(), (0, 0));
}

/// Flood: 100,000 refused envelopes (not opted in) leave every internal table within its bound.
#[test]
fn flood_100k_refused_envelopes_bounded_tables() {
    let h = Arc::new(Mutex::new(PeerIngress::default()));
    let s = PeerAdmissionState::with_host(h); // not opted in: every message is refused `unavailable`
    let mut max = s.ingress_sizes();
    for n in 0..100_000usize {
        let _ = s.submit(env(n, &format!("m{n}"), "b", 0), T0 + (n / 50) as u64, &live());
        let z = s.ingress_sizes();
        max.pairs = max.pairs.max(z.pairs);
        max.host_log = max.host_log.max(z.host_log);
        max.replay = max.replay.max(z.replay);
        max.replay_order = max.replay_order.max(z.replay_order);
    }
    assert!(max.pairs <= RATE_TABLE_ENTRIES);
    assert!(max.host_log <= RATE_PER_HOST_PER_MINUTE as usize);
    assert!(max.replay <= REMEMBERED_MESSAGE_IDS);
    assert!(max.replay_order <= 4 * REMEMBERED_MESSAGE_IDS);
    assert_eq!(s.held_count(), 0);
    assert_eq!(s.host_usage(), (0, 0));
}

/// S5.7: nothing undelivered is persisted. A restart is a new state; the held messages are gone and nothing was written.
#[test]
fn s5_7_restart_loses_held_messages() {
    let h = open_host();
    let s = session(&h);
    s.submit(mismatch(env(1, "a", "body", 0)), T0, &live());
    assert_eq!(s.held_count(), 1);
    drop(s);
    let restarted = session(&open_host());
    assert_eq!(restarted.held_count(), 0);
    assert!(restarted.list_held(T0).is_empty());
}

/// S5.5: the expiry numbers.
#[test]
fn s5_5_expiry_constants() {
    assert_eq!(HOLD_EXPIRY_SECS, 300);
    assert_eq!(WATCH_EXPIRY_SECS, 12 * 3600);
    assert_eq!(MESSAGE_ID_MEMORY_SECS, 600);
}
