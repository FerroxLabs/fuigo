//! Packet 11 tests, session side: the watch book, the hold-notice hook in the admission state, the turn hooks and the budget.

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use fuigo_peer::{Address, DeliveryOutcome, NoticeKind, PeerBase, PeerMode};
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

use super::*;
use crate::session::peer_admission::{Live, PeerAdmissionConfig, PeerAdmissionState, OperatorPresence, Submitted};
use crate::session::peer_message::test_envelope;

fn from(n: u32) -> Address {
    Address::new("0123456789abcdef0123456789abcdef", &format!("s{n}"), 1).unwrap()
}

fn rig() -> (WatchBook, NoticeOut, UnboundedReceiver<Outbound>, Arc<AtomicUsize>) {
    let (tx, rx) = unbounded_channel();
    (WatchBook::default(), tx, rx, Arc::default())
}

fn drain(rx: &mut UnboundedReceiver<Outbound>) -> Vec<(String, NoticeKind)> {
    let mut v = Vec::new();
    while let Ok(o) = rx.try_recv() {
        v.push((o.message_id, o.kind));
    }
    v
}

#[test]
fn p11_one_notice_per_watch() {
    let (b, tx, mut rx, total) = rig();
    b.register_watch("m1", &from(1), &tx, &total).unwrap();
    b.settled("m1", &from(1), false, false, &tx);
    b.turn_started();
    b.bind_turn("m1");
    assert!(drain(&mut rx).is_empty(), "nothing before the turn ends");
    b.turn_ended();
    assert_eq!(drain(&mut rx), vec![("m1".to_owned(), NoticeKind::Idle)]);
    b.turn_started();
    b.turn_ended();
    assert!(drain(&mut rx).is_empty(), "a watch fires once");
    assert_eq!((b.len(), total.load(std::sync::atomic::Ordering::SeqCst)), (0, 0), "the slot is freed");
}

#[test]
fn p11_an_idle_session_answers_a_watch_only_at_once_a_busy_one_at_turn_end() {
    let (b, tx, mut rx, total) = rig();
    b.watch_only("w1", &from(1), &tx, &total).unwrap();
    assert_eq!(drain(&mut rx), vec![("w1".to_owned(), NoticeKind::Idle)]);
    assert_eq!(b.len(), 0);
    b.turn_started();
    b.watch_only("w2", &from(1), &tx, &total).unwrap();
    assert!(drain(&mut rx).is_empty());
    b.turn_ended();
    assert_eq!(drain(&mut rx), vec![("w2".to_owned(), NoticeKind::Idle)]);
}

#[test]
fn p11_held_then_released_arms_at_release_and_sends_released_then_idle() {
    let (b, tx, mut rx, total) = rig();
    b.register_watch("h1", &from(1), &tx, &total).unwrap();
    b.settled("h1", &from(1), true, false, &tx);
    // A turn that ends while the message is still held does not fire the watch.
    b.turn_started();
    b.turn_ended();
    assert!(drain(&mut rx).is_empty());
    b.on_session_notice("h1", &SessionNotice::Released);
    assert_eq!(drain(&mut rx), vec![("h1".to_owned(), NoticeKind::Released)]);
    b.turn_started();
    b.bind_turn("h1");
    b.turn_ended();
    assert_eq!(drain(&mut rx), vec![("h1".to_owned(), NoticeKind::Idle)]);
}

#[test]
fn p11_refused_and_expired_arm_no_watch_and_send_that_notice_instead() {
    for (session, wire) in [
        (SessionNotice::Expired, NoticeKind::Expired),
        (SessionNotice::Refused(fuigo_peer::RejectReason::PolicyRefused), NoticeKind::Refused),
        (SessionNotice::ModelRefused, NoticeKind::Denied),
    ] {
        let (b, tx, mut rx, total) = rig();
        b.register_watch("x", &from(1), &tx, &total).unwrap();
        b.settled("x", &from(1), true, false, &tx);
        b.on_session_notice("x", &session);
        assert_eq!(drain(&mut rx), vec![("x".to_owned(), wire)]);
        b.turn_started();
        b.bind_turn("x");
        b.turn_ended();
        assert!(drain(&mut rx).is_empty(), "no idle after {wire:?}");
        assert_eq!((b.len(), total.load(std::sync::atomic::Ordering::SeqCst)), (0, 0));
    }
    // A rejected send arms nothing and tells nobody (the reply carries the refusal).
    let (b, tx, mut rx, total) = rig();
    b.register_watch("r", &from(1), &tx, &total).unwrap();
    b.settled("r", &from(1), false, true, &tx);
    assert_eq!((b.len(), drain(&mut rx).len()), (0, 0));
}

#[test]
fn p11_a_plain_held_message_still_reports_release_and_expiry_but_never_idle() {
    let (b, tx, mut rx, _t) = rig();
    b.settled("p", &from(1), true, false, &tx);
    b.on_session_notice("p", &SessionNotice::Released);
    assert_eq!(drain(&mut rx), vec![("p".to_owned(), NoticeKind::Released)]);
    b.turn_started();
    b.bind_turn("p");
    b.turn_ended();
    assert!(drain(&mut rx).is_empty());
    assert_eq!(b.len(), 0, "the plain record ended silently with its turn");
}

#[test]
fn p28_a_released_unwatched_message_can_still_be_refused_by_the_model() {
    let (b, tx, mut rx, _t) = rig();
    b.settled("p", &from(1), true, false, &tx);
    b.on_session_notice("p", &SessionNotice::Released);
    b.turn_started();
    b.bind_turn("p");
    assert!(b.on_session_notice("p", &SessionNotice::ModelRefused));
    assert_eq!(drain(&mut rx), vec![("p".to_owned(), NoticeKind::Released), ("p".to_owned(), NoticeKind::Denied)]);
}

#[test]
fn p11_the_65th_watch_ends_the_oldest_with_unavailable_and_the_host_cap_refuses() {
    let (b, tx, mut rx, total) = rig();
    for i in 0..64 {
        b.register_watch(&format!("m{i}"), &from(1), &tx, &total).unwrap();
    }
    assert!(drain(&mut rx).is_empty());
    b.register_watch("m64", &from(1), &tx, &total).unwrap();
    assert_eq!(drain(&mut rx), vec![("m0".to_owned(), NoticeKind::Unavailable)]);
    assert_eq!(b.len(), 64, "still bounded");
    // The host cap: 256 across sessions.
    let total = Arc::new(AtomicUsize::new(0));
    let books: Vec<WatchBook> = (0..5).map(|_| WatchBook::default()).collect();
    let mut ok = 0;
    for (n, book) in books.iter().enumerate() {
        for i in 0..64 {
            if book.register_watch(&format!("b{n}-{i}"), &from(1), &tx, &total).is_ok() {
                ok += 1;
            }
        }
    }
    assert_eq!(ok, 256);
    assert!(books[4].register_watch("one-more", &from(1), &tx, &total).is_err());
}

#[test]
fn p11_an_id_owned_by_another_sender_is_never_merged() {
    let (b, tx, _rx, total) = rig();
    b.register_watch("dup", &from(1), &tx, &total).unwrap();
    assert!(b.register_watch("dup", &from(2), &tx, &total).is_err());
}

#[test]
fn p11_a_session_notice_about_a_sent_message_never_produces_a_notice() {
    let (b, tx, mut rx, total) = rig();
    b.register_watch("n", &from(1), &tx, &total).unwrap();
    for k in [NoticeKind::Released, NoticeKind::Idle, NoticeKind::Exited, NoticeKind::Unavailable, NoticeKind::Refused] {
        b.on_session_notice("n", &SessionNotice::SentMessage(k));
    }
    b.on_session_notice("n", &SessionNotice::SentOutcomeUnknown);
    b.on_session_notice("n", &SessionNotice::Reheld);
    assert!(drain(&mut rx).is_empty(), "receiving a notice emits nothing");
}

#[test]
fn p11_ending_a_session_tells_every_waiting_sender_exited() {
    let (b, tx, mut rx, total) = rig();
    b.register_watch("a", &from(1), &tx, &total).unwrap();
    b.settled("c", &from(2), true, false, &tx);
    b.end_all(NoticeKind::Exited);
    let mut got = drain(&mut rx);
    got.sort_by(|x, y| x.0.cmp(&y.0));
    assert_eq!(got, vec![("a".to_owned(), NoticeKind::Exited), ("c".to_owned(), NoticeKind::Exited)]);
    assert_eq!(b.len(), 0);
}

fn live() -> Live {
    Live { feature_on: true, receiver_mode: PeerMode::new(false, PeerBase::Default, false) }
}

#[test]
fn p11_the_admission_state_feeds_the_book_on_release_and_on_expiry() {
    let s = PeerAdmissionState::unmetered();
    s.configure(PeerAdmissionConfig { opted_in: true, operator: OperatorPresence::Present, ..Default::default() });
    let gate = s.gate();
    let (tx, mut rx) = unbounded_channel();
    let total: Arc<AtomicUsize> = Arc::default();
    for id in ["rel", "exp"] {
        let mut env = test_envelope(id, "lane a", "hi");
        env.from_mode = PeerMode::new(false, PeerBase::AcceptEdits, false);
        gate.watches.register_watch(id, &env.from, &tx, &total).unwrap();
        let out = s.submit(env.clone(), 1_000, &live());
        assert!(matches!(out, Submitted::Done(DeliveryOutcome::Held { .. })), "{out:?}");
        gate.watches.settled(id, &env.from, true, false, &tx);
    }
    let held = s.list_held(1_000);
    let tok = held.iter().find(|h| h.message_id == "rel").unwrap().token.clone();
    s.release("rel", &tok, 1_000, &live()).unwrap();
    assert_eq!(drain(&mut rx), vec![("rel".to_owned(), NoticeKind::Released)]);
    // The other one expires (the next submit sweeps).
    let late = test_envelope("late", "lane a", "hi");
    let _ = s.submit(late, 1_000 + fuigo_peer::limits::HOLD_EXPIRY_SECS + 1, &live());
    assert_eq!(drain(&mut rx), vec![("exp".to_owned(), NoticeKind::Expired)]);
}

#[test]
fn p11_a_notice_woken_turn_counts_against_the_budget_and_keeps_the_peer_chain() {
    let s = PeerAdmissionState::unmetered();
    let mut a = test_envelope("a", "x", "b");
    (a.conversation_id, a.hop) = ("conv-1".into(), 5);
    s.note_delivered(&a);
    // A peer turn at hop 5, then a notice-woken turn (not human typed): it inherits the chain, the hop is not reset.
    drop(s.begin_turn(false, Some("a")));
    let before = s.peer_turns_used();
    assert!(s.consume_notice_turn());
    assert_eq!(s.peer_turns_used(), before + 1, "the notice turn is counted");
    let g = s.begin_turn(false, None);
    assert_eq!(s.turn_conversation(), Some(("conv-1".into(), 5)));
    drop(g);
    // The budget is the same 20 as for peer messages: when used up, no notice wakes.
    while s.peer_turns_used() < fuigo_peer::limits::PEER_TURN_BUDGET {
        assert!(s.consume_notice_turn());
    }
    assert!(!s.consume_notice_turn());
    assert_eq!(s.peer_turns_used(), fuigo_peer::limits::PEER_TURN_BUDGET);
    // A human prompt fills it again.
    s.human_prompt();
    assert!(s.consume_notice_turn());
}

#[test]
fn p11_the_notice_origin_is_runtime_control_with_its_own_hook_tag_and_never_peer() {
    use crate::session::PromptOrigin;
    let o = PromptOrigin::PeerNotice { message_id: "m".into() };
    assert_eq!(o.hook_origin_tag(), Some("peer_notice"));
    assert!(!o.is_peer(), "no peer text in it: not marked peer-influenced");
    assert!(o.is_synthetic() && !o.enforces_prompt_block() && o.hide_user_echo_from_scrollback());
    assert_eq!(PromptOrigin::from_prompt_id("peer-notice-m"), o);
    assert_eq!(o.policy().authority, crate::session::InputAuthority::RuntimeControl);
}

#[test]
fn p11_the_wake_text_is_fixed_and_escapes_the_address() {
    for k in [
        Some(NoticeKind::Released),
        Some(NoticeKind::Expired),
        Some(NoticeKind::Refused),
        Some(NoticeKind::Denied),
        Some(NoticeKind::Idle),
        Some(NoticeKind::Exited),
        Some(NoticeKind::Unavailable),
        None,
    ] {
        let t = fuigo_peer::host::notice_text(k, "fuigo-peer:abc/<b>\u{202e}/1");
        assert!(t.starts_with("Fuigo runtime notice (written by Fuigo, not by a peer): "), "{t}");
        assert!(!t.contains("<b>") && !t.contains('\u{202e}'), "{t}");
    }
    assert!(fuigo_peer::host::notice_text(Some(NoticeKind::Unavailable), "t").contains("target unavailable (not a confirmed exit)"));
    assert!(fuigo_peer::host::notice_text(None, "t").contains("outcome unknown"));
}

#[test]
fn p11_at_the_session_cap_a_sender_evicts_only_its_own_oldest_watch() {
    use fuigo_peer::RejectReason;
    use fuigo_peer::limits::MAX_WATCHES_PER_SESSION as CAP;
    let (b, tx, mut rx, total) = rig();
    // One watch of sender 2 (the oldest of all), then sender 1 fills the rest.
    b.register_watch("other", &from(2), &tx, &total).unwrap();
    for i in 0..CAP - 1 {
        b.register_watch(&format!("a{i}"), &from(1), &tx, &total).unwrap();
    }
    assert_eq!(b.len(), CAP);
    // Sender 1 again: its OWN oldest (a0) ends `unavailable`; sender 2's older watch stays.
    b.register_watch("a-new", &from(1), &tx, &total).unwrap();
    assert_eq!(drain(&mut rx), vec![("a0".to_owned(), NoticeKind::Unavailable)]);
    assert_eq!(b.len(), CAP);
    // A third sender has no watch to replace: refused `rate_limited`, nobody is evicted.
    assert_eq!(b.register_watch("c0", &from(3), &tx, &total), Err(RejectReason::RateLimited));
    assert!(drain(&mut rx).is_empty());
    assert_eq!(b.len(), CAP);
    // Sender 2's watch survived and still fires.
    b.turn_started();
    b.bind_turn("other");
    b.turn_ended();
    assert_eq!(drain(&mut rx), vec![("other".to_owned(), NoticeKind::Idle)]);
}

#[test]
fn p11_forget_removes_an_unsettled_registration() {
    let (b, tx, mut rx, total) = rig();
    b.register_watch("m1", &from(1), &tx, &total).unwrap();
    b.forget("m1");
    assert_eq!((b.len(), total.load(std::sync::atomic::Ordering::SeqCst)), (0, 0));
    b.turn_started();
    b.turn_ended();
    assert!(drain(&mut rx).is_empty());
}

#[test]
fn p28_plain_delivered_records_are_capped_oldest_evicted_and_held_ones_are_kept() {
    let (b, tx, mut rx, _t) = rig();
    b.register_plain("held", &from(1), &tx);
    b.settled("held", &from(1), true, false, &tx);
    for i in 0..(MAX_HELD_RECORDS + 10) {
        let id = format!("d{i}");
        b.register_plain(&id, &from(1), &tx);
        b.settled(&id, &from(1), false, false, &tx);
    }
    assert_eq!(b.len(), MAX_HELD_RECORDS, "bounded");
    // The held one survived and still reports its release; the oldest delivered ones are gone, the newest remain.
    assert!(b.on_session_notice("held", &SessionNotice::Released));
    assert!(!b.on_session_notice("d0", &SessionNotice::ModelRefused));
    assert!(b.on_session_notice(&format!("d{}", MAX_HELD_RECORDS + 9), &SessionNotice::ModelRefused));
    assert_eq!(drain(&mut rx).len(), 2);
}

#[test]
fn p28_all_held_at_the_cap_adds_no_plain_delivered_record() {
    let (b, tx, _rx, _t) = rig();
    for i in 0..MAX_HELD_RECORDS {
        b.settled(&format!("h{i}"), &from(1), true, false, &tx);
    }
    b.register_plain("d", &from(1), &tx);
    assert_eq!(b.len(), MAX_HELD_RECORDS);
    assert!(!b.is_watched("d"));
}

/// Session close: what each kind of record gets, compared with 1.0.27 (which had records only for watches and HELD messages).
#[test]
fn p28_ending_a_session_tells_watches_and_held_senders_but_not_senders_of_delivered_messages() {
    let (b, tx, mut rx, total) = rig();
    b.register_watch("w", &from(1), &tx, &total).unwrap();
    b.register_plain("held", &from(2), &tx);
    b.settled("held", &from(2), true, false, &tx);
    // Delivered and running, delivered and queued, and still unsettled: none of these asked to be told.
    b.register_plain("running", &from(3), &tx);
    b.settled("running", &from(3), false, false, &tx);
    b.bind_turn("running");
    b.register_plain("queued", &from(4), &tx);
    b.settled("queued", &from(4), false, false, &tx);
    b.register_plain("unsettled", &from(5), &tx);
    b.end_all(NoticeKind::Exited);
    let mut got = drain(&mut rx);
    got.sort_by(|x, y| x.0.cmp(&y.0));
    assert_eq!(got, vec![("held".to_owned(), NoticeKind::Exited), ("w".to_owned(), NoticeKind::Exited)]);
    assert_eq!(b.len(), 0);
}
