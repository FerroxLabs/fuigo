//! Tests for `PeerIngress`, the host ledger and the loop-budget helpers. Clock-injected: no sleeps.

use std::sync::Arc;

use crate::ingress::*;
use crate::limits::*;
use crate::*;

const HOST: &str = "0123456789abcdef0123456789abcdef";

fn from(n: usize) -> Address {
    Address::new(HOST, &format!("sender-{n}"), 1).unwrap()
}

fn env(sender: usize, id: &str, body: &str) -> Envelope {
    Envelope {
        message_id: id.into(),
        seq: 1,
        from: from(sender),
        from_name: String::new(),
        from_auto_title: None,
        from_ref: "ref".into(),
        from_mode: PeerMode::new(false, PeerBase::AcceptEdits, false),
        from_operator: OperatorKind::Human,
        conversation_id: "c".into(),
        hop: 0,
        denied_recently: Vec::new(),
        body: body.into(),
    }
}

fn admit(i: &mut PeerIngress, now: u64, e: &Envelope) -> IngressVerdict {
    i.admit(now, 1, e, &e.body)
}

fn rate_limited() -> IngressVerdict {
    IngressVerdict::Refuse(DeliveryOutcome::Rejected { reason: RejectReason::RateLimited })
}

fn delivered() -> DeliveryOutcome {
    DeliveryOutcome::Delivered {}
}

/// S5.1: body at N passes, N+1 is `too_large`; frame the same.
#[test]
fn s5_1_body_and_frame_caps_at_n_and_n_plus_1() {
    let mut i = PeerIngress::default();
    let ok = env(1, "a", &"x".repeat(MAX_BODY_BYTES));
    assert_eq!(admit(&mut i, 0, &ok), IngressVerdict::Proceed);
    let big = Envelope { body: "x".repeat(MAX_BODY_BYTES + 1), ..env(1, "b", "") };
    assert_eq!(
        i.admit(0, 1, &big, "h"),
        IngressVerdict::Refuse(DeliveryOutcome::Rejected { reason: RejectReason::TooLarge })
    );
    assert!(frame_within_limit(MAX_FRAME_BYTES));
    assert!(!frame_within_limit(MAX_FRAME_BYTES + 1));
    assert_eq!(check_frame(MAX_FRAME_BYTES + 1), Err(RejectReason::TooLarge));
    assert_eq!(check_frame(MAX_FRAME_BYTES), Ok(()));
    assert_eq!(MAX_BODY_BYTES, 32 * 1024);
    assert_eq!(MAX_FRAME_BYTES, 64 * 1024);
    // An over-size body costs no rate allowance and is not remembered.
    assert_eq!(i.sizes().host_log, 1);
    assert_eq!(i.sizes().replay, 0);
}

/// S5.3: 10 per minute per pair (the 11th is refused), the window slides, another pair is unaffected.
#[test]
fn s5_3_pair_rate_ten_per_minute_with_clock() {
    let mut i = PeerIngress::default();
    for n in 0..10 {
        assert_eq!(admit(&mut i, 100 + n, &env(1, &format!("m{n}"), "b")), IngressVerdict::Proceed, "message {n}");
    }
    assert_eq!(admit(&mut i, 109, &env(1, "m10", "b")), rate_limited());
    // Another sender is a different pair.
    assert_eq!(admit(&mut i, 109, &env(2, "x", "b")), IngressVerdict::Proceed);
    // The first send ages out at t=160: one slot frees, not ten.
    assert_eq!(admit(&mut i, 159, &env(1, "m11", "b")), rate_limited());
    assert_eq!(admit(&mut i, 160, &env(1, "m12", "b")), IngressVerdict::Proceed);
    assert_eq!(admit(&mut i, 160, &env(1, "m13", "b")), rate_limited());
    // After a full minute of quiet the allowance is whole again.
    for n in 0..10 {
        assert_eq!(admit(&mut i, 400, &env(1, &format!("q{n}"), "b")), IngressVerdict::Proceed);
    }
    // A refusal charged nothing: the 11th stays refused only for its own window.
    assert_eq!(admit(&mut i, 400, &env(1, "q10", "b")), rate_limited());
}

/// S5.3: 60 per minute for the host in total, across senders and receivers.
#[test]
fn s5_3_host_rate_sixty_per_minute_across_pairs() {
    let mut i = PeerIngress::default();
    for n in 0..60 {
        // 6 sessions x 10 senders-per-pair: each pair stays under 10.
        let receiver = (n / 10) as u64;
        let e = env(n, &format!("m{n}"), "b");
        assert_eq!(i.admit(5, receiver, &e, "h"), IngressVerdict::Proceed, "message {n}");
    }
    assert_eq!(i.admit(5, 99, &env(500, "late", "b"), "h"), rate_limited());
    assert_eq!(i.admit(64, 99, &env(500, "late", "b"), "h"), rate_limited());
    assert_eq!(i.admit(65, 99, &env(500, "late", "b"), "h"), IngressVerdict::Proceed);
}

/// S5.3: cycling through fresh senders cannot beat the host total, and the pair table stays at its cap.
#[test]
fn s5_3_pair_table_cycling_cannot_exceed_host_total() {
    let mut i = PeerIngress::default();
    let mut passed = 0;
    for n in 0..5_000 {
        if admit(&mut i, 10, &env(n, &format!("m{n}"), "b")) == IngressVerdict::Proceed {
            passed += 1;
        }
        assert!(i.sizes().pairs <= RATE_TABLE_ENTRIES);
    }
    assert_eq!(passed, RATE_PER_HOST_PER_MINUTE);
    // Spread over many minutes the rate is still 60 a minute, not more.
    let mut passed = 0;
    for minute in 0..20u64 {
        for n in 0..200 {
            let e = env(10_000 + (minute as usize) * 200 + n, &format!("z{minute}-{n}"), "b");
            if admit(&mut i, 1_000 + minute * 60, &e) == IngressVerdict::Proceed {
                passed += 1;
            }
        }
    }
    assert_eq!(passed, 20 * RATE_PER_HOST_PER_MINUTE);
}

/// S5.3: when the table is full of LIVE pairs an unknown pair is refused, never given a fresh allowance by evicting one.
#[test]
fn s5_3_full_table_of_live_pairs_refuses_unknown_pair() {
    let cfg = IngressConfig { pair_table: 4, host_per_minute: 1000, ..IngressConfig::default() };
    let mut i = PeerIngress::new(cfg, Arc::new(HostLedger::default()));
    for n in 0..4 {
        assert_eq!(admit(&mut i, 10, &env(n, "m", "b")), IngressVerdict::Proceed);
    }
    assert_eq!(admit(&mut i, 11, &env(4, "m", "b")), rate_limited());
    // Pair 0 is still limited by its own history, not reset.
    for k in 0..9 {
        assert_eq!(admit(&mut i, 12, &env(0, &format!("k{k}"), "b")), IngressVerdict::Proceed);
    }
    assert_eq!(admit(&mut i, 12, &env(0, "k9", "b")), rate_limited());
    // A minute later the old pairs are dead and give way.
    assert_eq!(admit(&mut i, 71, &env(4, "m", "b")), IngressVerdict::Proceed);
    assert!(i.sizes().pairs <= 4);
}

/// S5.4: a repeat gets the original outcome, costs no allowance, and the same id with another body is refused.
#[test]
fn s5_4_repeat_answers_original_outcome_without_rate_cost() {
    let mut i = PeerIngress::default();
    let e = env(1, "id1", "body");
    assert_eq!(admit(&mut i, 0, &e), IngressVerdict::Proceed);
    i.record(0, 1, &e.from.to_string(), "id1", "body", &delivered());
    for t in 1..200 {
        assert_eq!(admit(&mut i, t % 59, &e), IngressVerdict::Replay(delivered()));
    }
    assert_eq!(i.sizes().host_log, 1);
    let other = env(1, "id1", "different");
    assert_eq!(
        admit(&mut i, 5, &other),
        IngressVerdict::Refuse(DeliveryOutcome::Rejected { reason: RejectReason::Ambiguous })
    );
    // Another receiver never sees this session's memory.
    assert_eq!(i.admit(5, 2, &e, "body"), IngressVerdict::Proceed);
}

/// S5.4: a rejected id resent 1,000 times is answered from memory: no growth, nothing held again.
#[test]
fn s5_4_rejected_id_resent_1000_times_memory_flat() {
    let mut i = PeerIngress::default();
    let e = env(1, "rej", "body");
    assert_eq!(admit(&mut i, 0, &e), IngressVerdict::Proceed);
    let out = DeliveryOutcome::Rejected { reason: RejectReason::PolicyRefused };
    i.record(0, 1, &e.from.to_string(), "rej", "body", &out);
    let before = i.sizes();
    for _ in 0..1000 {
        assert_eq!(admit(&mut i, 30, &e), IngressVerdict::Replay(out.clone()));
    }
    assert_eq!(i.sizes(), before);
}

/// S5.4: 1,024 ids; the 1,025th evicts the oldest; and an id is forgotten after 10 minutes.
#[test]
fn s5_4_capacity_1024_and_ten_minute_expiry() {
    let cfg = IngressConfig { host_per_minute: usize::MAX, pair_per_minute: usize::MAX, ..IngressConfig::default() };
    let mut i = PeerIngress::new(cfg, Arc::new(HostLedger::default()));
    for n in 0..REMEMBERED_MESSAGE_IDS + 1 {
        let e = env(1, &format!("m{n}"), "b");
        i.record(0, 1, &e.from.to_string(), &e.message_id, "b", &delivered());
    }
    assert_eq!(i.sizes().replay, REMEMBERED_MESSAGE_IDS);
    assert_eq!(admit(&mut i, 1, &env(1, "m0", "b")), IngressVerdict::Proceed, "oldest evicted");
    assert_eq!(admit(&mut i, 1, &env(1, "m1", "b")), IngressVerdict::Replay(delivered()));
    // Exactly at the lifetime the entry is gone; one second before it is not.
    assert_eq!(admit(&mut i, MESSAGE_ID_MEMORY_SECS - 1, &env(1, "m2", "b")), IngressVerdict::Replay(delivered()));
    assert_eq!(admit(&mut i, MESSAGE_ID_MEMORY_SECS, &env(1, "m2", "b")), IngressVerdict::Proceed);
    assert_eq!(i.sizes().replay, 0);
}

/// S5.4: transient refusals (rate_limited, saturated) are not remembered, so a later send of the same id is judged afresh.
#[test]
fn s5_4_transient_refusals_are_not_remembered() {
    let mut i = PeerIngress::default();
    let e = env(1, "t", "b");
    for r in [RejectReason::RateLimited, RejectReason::Saturated, RejectReason::TooLarge] {
        i.record(0, 1, &e.from.to_string(), "t", "b", &DeliveryOutcome::Rejected { reason: r });
    }
    assert_eq!(i.sizes().replay, 0);
}

/// S5.2 / S5.4: session end drops that session's rate pairs and remembered ids.
#[test]
fn session_end_forgets_pairs_and_ids() {
    let mut i = PeerIngress::default();
    let e = env(1, "m", "b");
    assert_eq!(i.admit(0, 7, &e, "b"), IngressVerdict::Proceed);
    i.record(0, 7, &e.from.to_string(), "m", "b", &delivered());
    i.forget_session(7);
    let s = i.sizes();
    assert_eq!((s.pairs, s.replay, s.replay_order), (0, 0, 0));
}

/// S5.2: the host ledger at N and N+1 messages and at the byte cap; every ticket drop returns it to zero, a clone is its own
/// reservation, and nothing frees twice.
#[test]
fn s5_2_host_ledger_bounds_and_exact_release() {
    let l = Arc::new(HostLedger::default());
    let mut t = Vec::new();
    for _ in 0..MAX_MESSAGES_PER_HOST {
        t.push(l.reserve(1).unwrap());
    }
    assert!(l.reserve(1).is_err(), "message N+1");
    assert_eq!(l.usage(), (MAX_MESSAGES_PER_HOST, MAX_MESSAGES_PER_HOST));
    t.pop();
    assert!(l.reserve(1).is_ok(), "freed slot is reusable (and the temporary frees it again)");
    t.clear();
    assert_eq!(l.usage(), (0, 0));
    let a = l.reserve(MAX_BODY_BYTES_PER_HOST).unwrap();
    assert!(l.reserve(1).is_err(), "byte N+1");
    let b = a.clone();
    assert_eq!(l.usage(), (2, 2 * MAX_BODY_BYTES_PER_HOST), "a clone is a second reservation");
    drop(a);
    assert_eq!(l.usage(), (1, MAX_BODY_BYTES_PER_HOST));
    drop(b);
    assert_eq!(l.usage(), (0, 0));
}

/// S5.6 (sending side): human turn is hop 0; a peer-started turn is incoming + 1.
#[test]
fn s5_6_next_hop_stamps() {
    assert_eq!(next_hop(TurnOrigin::Human, 7), 0);
    assert_eq!(next_hop(TurnOrigin::Peer, 0), 1);
    assert_eq!(next_hop(TurnOrigin::Peer, 6), 7);
    assert_eq!(next_hop(TurnOrigin::Peer, u32::MAX), u32::MAX);
    assert!(!hop_exhausted(HOP_BUDGET - 1));
    assert!(hop_exhausted(HOP_BUDGET));
}

/// S5.6: 20 peer turns fit, the 21st is over, a human prompt resets.
#[test]
fn s5_6_turn_budget_20_then_exhausted_then_reset() {
    let mut b = PeerTurnBudget::default();
    for _ in 0..PEER_TURN_BUDGET {
        assert!(!b.exhausted());
        b.consume();
    }
    assert!(b.exhausted());
    assert_eq!(b.used(), 20);
    b.human_prompt();
    assert!(!b.exhausted());
    assert_eq!(b.used(), 0);
}

/// Flood: 100,000 distinct refused envelopes leave every table bounded.
#[test]
fn flood_100k_envelopes_keep_tables_bounded() {
    let mut i = PeerIngress::default();
    let mut max = i.sizes();
    for n in 0..100_000usize {
        let e = env(n, &format!("m{n}"), "b");
        let now = (n / 50) as u64; // 50 per second: far above both rates
        let out = match admit(&mut i, now, &e) {
            IngressVerdict::Proceed => {
                let o = DeliveryOutcome::Rejected { reason: RejectReason::Unavailable };
                i.record(now, 1, &e.from.to_string(), &e.message_id, "b", &o);
                o
            }
            IngressVerdict::Refuse(o) | IngressVerdict::Replay(o) => o,
        };
        let _ = out;
        let s = i.sizes();
        max.pairs = max.pairs.max(s.pairs);
        max.host_log = max.host_log.max(s.host_log);
        max.replay = max.replay.max(s.replay);
        max.replay_order = max.replay_order.max(s.replay_order);
    }
    assert!(max.pairs <= RATE_TABLE_ENTRIES);
    assert!(max.host_log <= RATE_PER_HOST_PER_MINUTE as usize);
    assert!(max.replay <= REMEMBERED_MESSAGE_IDS);
    assert!(max.replay_order <= 4 * REMEMBERED_MESSAGE_IDS);
}
