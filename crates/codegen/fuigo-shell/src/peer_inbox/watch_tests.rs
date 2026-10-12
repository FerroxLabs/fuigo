//! Packet 11 tests, inbox side: watches and notices over real sockets (so every test runs inside `unshare -n`), the sender's
//! probe pass with a fake prober, and the bounds. Each test has its own temp home.

use std::time::{Duration, Instant};

use fuigo_peer::{Address, DeliveryOutcome, HostDir, HostId, NoticeKind, Op, Reply};
use tokio::sync::mpsc::UnboundedReceiver;

use super::dial::dial;
use super::inbox::PeerInbox;
use super::inbox_tests::{envelope, home_in, on, tmp};
use super::watch::{Probe, Prober, probe_pass};
use crate::session::message_delivery::{MessageDeliveryHandle, peer_test_notice_session, peer_test_session};
use crate::session::peer_admission::PeerSubmit;
use crate::session::peer_message::force_peer_messaging_for_test;

type Seen = UnboundedReceiver<(String, NoticeKind)>;

struct Rig {
    a: PeerInbox,
    b: PeerInbox,
    /// A's sending session address and the notices it is woken with.
    from: Address,
    a_seen: Seen,
    /// B's receiving session address and its delivery handle (its watch book plays the session's turns).
    to: Address,
    b_handle: MessageDeliveryHandle,
}

async fn rig(answer: DeliveryOutcome) -> (Rig, tempfile::TempDir) {
    let t = tmp();
    let home = home_in(&t, "home");
    let a = PeerInbox::start_with(&home, on()).await.unwrap();
    let b = PeerInbox::start_with(&home, on()).await.unwrap();
    let (ha, a_seen) = peer_test_notice_session("sa");
    let from = a.directory().register("sa", ha, "", "r1").unwrap();
    let (hb, _env_seen) = peer_test_session("sb", Some(PeerSubmit::Outcome(answer)));
    let to = b.directory().register("sb", hb.clone(), "", "r2").unwrap();
    (Rig { a, b, from, a_seen, to, b_handle: hb }, t)
}

async fn send(r: &Rig, id: &str, body: &str, watch: bool) -> DeliveryOutcome {
    r.a.directory().note_sent_to("sa", id, &r.to, watch);
    let mut env = envelope(&r.from, id);
    env.body = body.to_owned();
    let op = Op::Send { to: r.to.clone(), envelope: env, watch };
    match dial(r.a.locations(), r.a.host_id(), r.b.host_id(), HostDir::Home, op).await.unwrap() {
        Reply::Send { outcome } => outcome,
        other => panic!("{other:?}"),
    }
}

async fn next(seen: &mut Seen) -> (String, NoticeKind) {
    tokio::time::timeout(Duration::from_secs(5), seen.recv()).await.expect("a notice").expect("open")
}

async fn quiet(seen: &mut Seen) {
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(seen.try_recv().is_err(), "no further notice");
}

fn turn(r: &Rig, id: Option<&str>) {
    let book = &r.b_handle.peer_gate().watches;
    book.turn_started();
    if let Some(id) = id {
        book.bind_turn(id);
    }
    book.turn_ended();
}

#[tokio::test]
async fn p11_a_watched_delivery_sends_one_idle_notice_when_the_turn_ends() {
    let _on = force_peer_messaging_for_test(true);
    let (mut r, _t) = rig(DeliveryOutcome::Delivered {}).await;
    assert_eq!(send(&r, "m1", "hello", true).await, DeliveryOutcome::Watching {});
    quiet(&mut r.a_seen).await;
    turn(&r, Some("m1"));
    assert_eq!(next(&mut r.a_seen).await, ("m1".into(), NoticeKind::Idle));
    turn(&r, None);
    quiet(&mut r.a_seen).await;
    assert_eq!(r.a.directory().with_watches(|t| t.len()), 0, "the watch is consumed");
}

#[tokio::test]
async fn p11_a_watch_only_on_an_idle_session_fires_at_once() {
    let _on = force_peer_messaging_for_test(true);
    let (mut r, _t) = rig(DeliveryOutcome::Delivered {}).await;
    assert_eq!(send(&r, "w1", "", true).await, DeliveryOutcome::Watching {});
    assert_eq!(next(&mut r.a_seen).await, ("w1".into(), NoticeKind::Idle));
    // On a busy one it waits for the turn to end.
    let book = &r.b_handle.peer_gate().watches;
    book.turn_started();
    assert_eq!(send(&r, "w2", "", true).await, DeliveryOutcome::Watching {});
    quiet(&mut r.a_seen).await;
    book.turn_ended();
    assert_eq!(next(&mut r.a_seen).await, ("w2".into(), NoticeKind::Idle));
}

#[tokio::test]
async fn p11_a_held_watched_message_arms_at_release_and_sends_released_then_idle() {
    let _on = force_peer_messaging_for_test(true);
    let held = DeliveryOutcome::Held { reason: fuigo_peer::HoldReason::ModeMismatch, expires_at: 1 };
    let (mut r, _t) = rig(held.clone()).await;
    assert_eq!(send(&r, "h1", "hello", true).await, held);
    turn(&r, None);
    quiet(&mut r.a_seen).await;
    let book = &r.b_handle.peer_gate().watches;
    book.on_session_notice("h1", &crate::session::peer_admission::NoticeKind::Released);
    assert_eq!(next(&mut r.a_seen).await, ("h1".into(), NoticeKind::Released));
    turn(&r, Some("h1"));
    assert_eq!(next(&mut r.a_seen).await, ("h1".into(), NoticeKind::Idle));
    quiet(&mut r.a_seen).await;
}

#[tokio::test]
async fn p11_a_held_message_that_expires_sends_expired_and_no_watch_remains() {
    let _on = force_peer_messaging_for_test(true);
    let held = DeliveryOutcome::Held { reason: fuigo_peer::HoldReason::PolicyHold, expires_at: 1 };
    let (mut r, _t) = rig(held).await;
    send(&r, "e1", "hello", true).await;
    r.b_handle.peer_gate().watches.on_session_notice("e1", &crate::session::peer_admission::NoticeKind::Expired);
    assert_eq!(next(&mut r.a_seen).await, ("e1".into(), NoticeKind::Expired));
    turn(&r, Some("e1"));
    quiet(&mut r.a_seen).await;
    assert_eq!(r.a.directory().with_watches(|t| t.len()), 0);
}

#[tokio::test]
async fn p11_a_rejected_watched_send_arms_nothing_and_a_plain_held_one_still_reports_release() {
    let _on = force_peer_messaging_for_test(true);
    let rej = DeliveryOutcome::Rejected { reason: fuigo_peer::RejectReason::PolicyRefused };
    let (mut r, _t) = rig(rej.clone()).await;
    assert_eq!(send(&r, "r1", "hello", true).await, rej);
    r.a.directory().forget_watch("r1");
    turn(&r, Some("r1"));
    quiet(&mut r.a_seen).await;
    let held = DeliveryOutcome::Held { reason: fuigo_peer::HoldReason::LoopGuard, expires_at: 1 };
    let (mut r, _t) = rig(held).await;
    send(&r, "p1", "hello", false).await;
    r.b_handle.peer_gate().watches.on_session_notice("p1", &crate::session::peer_admission::NoticeKind::Released);
    assert_eq!(next(&mut r.a_seen).await, ("p1".into(), NoticeKind::Released));
}

#[tokio::test]
async fn p11_a_notice_for_an_unknown_id_or_from_the_wrong_host_is_dropped() {
    let _on = force_peer_messaging_for_test(true);
    let (mut r, _t) = rig(DeliveryOutcome::Delivered {}).await;
    send(&r, "m1", "hello", true).await;
    // A third host that was not the target tries to end the record, and an unknown id is sent by the real target.
    let home = r.a.locations().home().to_path_buf();
    let c = PeerInbox::start_with(&home, on()).await.unwrap();
    let id = |s: &str| fuigo_peer::BoundedId::new(s).unwrap();
    for (from, mid) in [(&c, "m1"), (&r.b, "never-sent")] {
        let op = Op::Notice { message_id: id(mid), kind: NoticeKind::Idle };
        let rep = dial(from.locations(), from.host_id(), r.a.host_id(), HostDir::Home, op).await.unwrap();
        assert_eq!(rep, Reply::Notice {}, "acknowledged either way");
    }
    quiet(&mut r.a_seen).await;
    // The real target can still end it.
    turn(&r, Some("m1"));
    assert_eq!(next(&mut r.a_seen).await, ("m1".into(), NoticeKind::Idle));
}

#[tokio::test]
async fn p11_a_clean_exit_announces_exited_and_a_killed_host_is_only_unavailable() {
    let _on = force_peer_messaging_for_test(true);
    let (mut r, _t) = rig(DeliveryOutcome::Delivered {}).await;
    send(&r, "m1", "hello", true).await;
    r.b.shutdown().await;
    assert_eq!(next(&mut r.a_seen).await, ("m1".into(), NoticeKind::Exited));
    // The kill case: nothing announced; the sender's pass finds no answer while the row is still there.
    let (mut r2, _t2) = rig(DeliveryOutcome::Delivered {}).await;
    send(&r2, "m2", "hello", true).await;
    probe_pass(r2.a.directory(), &Fake(Probe::Gone { row_present: true }), Instant::now()).await;
    assert_eq!(next(&mut r2.a_seen).await, ("m2".into(), NoticeKind::Unavailable));
    quiet(&mut r2.a_seen).await;
}

struct Fake(Probe);
impl Prober for Fake {
    async fn probe(&self, _host: &HostId) -> Probe {
        self.0
    }
}

#[tokio::test]
async fn p11_a_missing_row_is_exited_only_after_two_passes_a_live_host_is_left_alone() {
    let _on = force_peer_messaging_for_test(true);
    let (mut r, _t) = rig(DeliveryOutcome::Delivered {}).await;
    send(&r, "m1", "hello", true).await;
    let now = Instant::now();
    probe_pass(r.a.directory(), &Fake(Probe::Alive), now).await;
    probe_pass(r.a.directory(), &Fake(Probe::Gone { row_present: false }), now).await;
    quiet(&mut r.a_seen).await;
    probe_pass(r.a.directory(), &Fake(Probe::Alive), now).await;
    probe_pass(r.a.directory(), &Fake(Probe::Gone { row_present: false }), now).await;
    quiet(&mut r.a_seen).await;
    probe_pass(r.a.directory(), &Fake(Probe::Gone { row_present: false }), now).await;
    assert_eq!(next(&mut r.a_seen).await, ("m1".into(), NoticeKind::Exited));
}

#[tokio::test]
async fn p11_the_real_prober_sees_a_live_host_and_a_shut_down_one() {
    let _on = force_peer_messaging_for_test(true);
    let (r, _t) = rig(DeliveryOutcome::Delivered {}).await;
    let p = super::watch::io::SocketProber {
        loc: r.a.locations().clone(),
        home_dir: r.a.peers_dir().clone(),
        own: r.a.host_id().clone(),
    };
    assert_eq!(p.probe(r.b.host_id()).await, Probe::Alive);
    r.b.shutdown().await;
    assert_eq!(p.probe(r.b.host_id()).await, Probe::Gone { row_present: false });
}

#[tokio::test]
async fn p11_a_watch_that_never_resolves_ends_with_outcome_unknown_after_twelve_hours() {
    let _on = force_peer_messaging_for_test(true);
    let (mut r, _t) = rig(DeliveryOutcome::Delivered {}).await;
    send(&r, "m1", "hello", true).await;
    probe_pass(r.a.directory(), &Fake(Probe::Alive), Instant::now() + Duration::from_secs(11 * 3600)).await;
    assert_eq!(r.a.directory().with_watches(|t| t.len()), 1);
    probe_pass(r.a.directory(), &Fake(Probe::Alive), Instant::now() + Duration::from_secs(13 * 3600)).await;
    assert_eq!(r.a.directory().with_watches(|t| t.len()), 0, "the record ended (the session is woken with `outcome unknown`)");
    quiet(&mut r.a_seen).await;
    // A late notice for it is unknown now and dropped.
    turn(&r, Some("m1"));
    quiet(&mut r.a_seen).await;
}

#[tokio::test]
async fn p11_sender_side_watches_are_bounded_64_per_session_256_per_host() {
    let _on = force_peer_messaging_for_test(true);
    let t = tmp();
    let home = home_in(&t, "home");
    let a = PeerInbox::start_with(&home, on()).await.unwrap();
    let target = Address::new(&"b".repeat(32), "sb", 1).unwrap();
    let mut seen = Vec::new();
    for n in 0..5 {
        let sid = format!("s{n}");
        let (h, rx) = peer_test_notice_session(&sid);
        a.directory().register(&sid, h, "", "r").unwrap();
        seen.push(rx);
    }
    for i in 0..65 {
        a.directory().note_sent_to("s0", &format!("m{i}"), &target, true);
    }
    assert_eq!(a.directory().with_watches(|t| t.len()), 64);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(seen[0].try_recv().unwrap(), ("m0".to_owned(), NoticeKind::Unavailable), "the oldest ends unavailable");
    assert!(seen[0].try_recv().is_err());
    for n in 1..5 {
        for i in 0..64 {
            a.directory().note_sent_to(&format!("s{n}"), &format!("n{n}-{i}"), &target, true);
        }
    }
    assert_eq!(a.directory().with_watches(|t| t.len()), 256, "never more than 256 on the host");
}

#[test]
fn p11_the_wire_carries_watch_only_when_true_and_the_tool_input_cannot_set_it_otherwise() {
    let from = Address::new(&"a".repeat(32), "s", 1).unwrap();
    let mk = |watch| Op::Send { to: from.clone(), envelope: envelope(&from, "m"), watch };
    let plain = serde_json::to_value(mk(false)).unwrap();
    assert!(plain.get("watch").is_none(), "flag-off / plain sends have the bytes they always had");
    let watched = serde_json::to_value(mk(true)).unwrap();
    assert_eq!(watched["watch"], serde_json::json!(true));
    assert_eq!(serde_json::from_value::<Op>(watched).unwrap(), mk(true));
    assert_eq!(serde_json::from_value::<Op>(plain.clone()).unwrap(), mk(false));
    // An unknown extra field is still refused (an older peer refuses `watch` the same way).
    let mut bad = plain;
    bad["extra"] = serde_json::json!(1);
    assert!(serde_json::from_value::<Op>(bad).is_err());
}

async fn rig_with(answer: Option<PeerSubmit>) -> (Rig, tempfile::TempDir) {
    let t = tmp();
    let home = home_in(&t, "home");
    let a = PeerInbox::start_with(&home, on()).await.unwrap();
    let b = PeerInbox::start_with(&home, on()).await.unwrap();
    let (ha, a_seen) = peer_test_notice_session("sa");
    let from = a.directory().register("sa", ha, "", "r1").unwrap();
    let (hb, _env_seen) = peer_test_session("sb", answer);
    let to = b.directory().register("sb", hb.clone(), "", "r2").unwrap();
    (Rig { a, b, from, a_seen, to, b_handle: hb }, t)
}

#[tokio::test]
async fn p11_a_watch_only_the_session_refuses_registers_nothing_and_never_notifies() {
    let _on = force_peer_messaging_for_test(true);
    // The session's admission answer (policy refuse, integrity hold, mode mismatch, rate: all arrive as a refusal).
    for reason in [fuigo_peer::RejectReason::PolicyRefused, fuigo_peer::RejectReason::RateLimited] {
        let refusal = DeliveryOutcome::Rejected { reason };
        let (mut r, _t) = rig_with(Some(PeerSubmit::Outcome(refusal.clone()))).await;
        assert_eq!(send(&r, "w1", "", true).await, refusal, "the same refusal comes back");
        assert_eq!(r.b_handle.peer_gate().watches.len(), 0, "no watch registered");
        quiet(&mut r.a_seen).await;
        turn(&r, None);
        quiet(&mut r.a_seen).await;
    }
}

#[tokio::test]
async fn p11_a_dropped_watched_send_leaves_no_unbound_watch() {
    use super::conn::InboxHost;
    let _on = force_peer_messaging_for_test(true);
    // The session never answers, so the send is still waiting when its future is dropped.
    let (r, _t) = rig_with(None).await;
    let host = super::directory::ConnHost::new(r.b.directory().clone());
    host.peer_hello(r.a.host_id());
    let mut env = envelope(&r.from, "d1");
    env.body = "hello".to_owned();
    let mut fut = Box::pin(host.send_watched(r.to.clone(), env, true));
    assert!(tokio::time::timeout(Duration::from_millis(300), &mut fut).await.is_err(), "still waiting");
    assert_eq!(r.b_handle.peer_gate().watches.len(), 1, "registered while the send is pending");
    drop(fut);
    assert_eq!(r.b_handle.peer_gate().watches.len(), 0, "the unsettled registration went with the future");
}

#[tokio::test]
async fn p11_a_replayed_released_notice_is_dropped_and_the_watch_stays_armed() {
    let _on = force_peer_messaging_for_test(true);
    let held = DeliveryOutcome::Held { reason: fuigo_peer::HoldReason::ModeMismatch, expires_at: 1 };
    let (mut r, _t) = rig(held.clone()).await;
    assert_eq!(send(&r, "h1", "hello", true).await, held);
    let id = fuigo_peer::BoundedId::new("h1").unwrap();
    for _ in 0..3 {
        let op = Op::Notice { message_id: id.clone(), kind: NoticeKind::Released };
        let rep = dial(r.b.locations(), r.b.host_id(), r.a.host_id(), HostDir::Home, op).await.unwrap();
        assert_eq!(rep, Reply::Notice {});
    }
    assert_eq!(next(&mut r.a_seen).await, ("h1".into(), NoticeKind::Released));
    quiet(&mut r.a_seen).await;
    // The watch is still armed for the final kind.
    let op = Op::Notice { message_id: id, kind: NoticeKind::Idle };
    dial(r.b.locations(), r.b.host_id(), r.a.host_id(), HostDir::Home, op).await.unwrap();
    assert_eq!(next(&mut r.a_seen).await, ("h1".into(), NoticeKind::Idle));
}
