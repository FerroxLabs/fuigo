use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use super::*;
use crate::session::peer_admission::{
    Live, PeerAdmissionState, Submitted, now_mono, set_test_clock,
};
use crate::session::peer_message::{force_peer_messaging_for_test, test_envelope};
use fuigo_peer::{DeliveryOutcome, PeerBase, PeerMode};

const T0: u64 = 1_000;

/// The real admission store (real tokens, real expiry, real operator rule) behind the client surface. The drain recheck is the
/// actor's (packet 4 tests); here a successful `release` of the store reports `Delivered`.
struct Fake {
    st: PeerAdmissionState,
    delivered: Mutex<Vec<String>>,
    /// Test hook: attach a remote client the moment `notices()` returns (an attach during the pump's awaits).
    attach_after_notices: std::sync::atomic::AtomicBool,
    guard: Mutex<Option<crate::peer_inbox::driver::RemoteAttachGuard>>,
}

impl Fake {
    fn new() -> Self {
        set_test_clock(Some(T0));
        Self { st: PeerAdmissionState::unmetered(), delivered: Mutex::default(), attach_after_notices: Default::default(), guard: Mutex::default() }
    }
    fn live() -> Live {
        Live { feature_on: true, receiver_mode: PeerMode::new(false, PeerBase::Default, false) }
    }
    /// Hold one message (sender mode differs from the receiver's).
    fn hold(&self, id: &str, from_name: &str) {
        self.hold_from(id, from_name, "sender-session");
    }
    fn hold_from(&self, id: &str, from_name: &str, session: &str) {
        let mut e = test_envelope(id, from_name, "hi");
        e.from = fuigo_peer::Address::new("0123456789abcdef0123456789abcdef", session, 1).expect("address");
        e.from_mode = PeerMode::new(false, PeerBase::AcceptEdits, false);
        let out = self.st.submit(e, now_mono(), &Self::live());
        assert!(matches!(out, Submitted::Done(DeliveryOutcome::Held { .. })), "{out:?}");
    }
}

#[async_trait::async_trait]
impl ClientSession for Fake {
    fn opted_in(&self) -> bool {
        self.st.gate().is_opted_in()
    }
    fn client_opted_in(&self) -> bool {
        self.st.gate().client_opted_in()
    }
    fn actor_gone(&self) -> bool {
        false
    }
    async fn register(&self) {}
    async fn configure(&self, config: PeerAdmissionConfig) {
        self.st.configure(config);
    }
    async fn list_held(&self) -> Vec<HeldSummary> {
        self.st.list_held(now_mono())
    }
    async fn snapshot(&self) -> Vec<HeldSummary> {
        self.st.held_snapshot(now_mono())
    }
    async fn release(&self, id: &str, token: &str) -> Result<ReleaseOutcome, ReleaseError> {
        self.st.release(id, token, now_mono(), &Self::live())?;
        self.delivered.lock().unwrap().push(id.to_owned());
        Ok(ReleaseOutcome::Delivered)
    }
    async fn refuse(&self, id: &str, token: &str) -> Result<(), ReleaseError> {
        self.st.reject(id, token, now_mono())
    }
    async fn notices(&self) -> Vec<PeerNotice> {
        let n = self.st.take_notices(now_mono());
        if self.attach_after_notices.load(std::sync::atomic::Ordering::SeqCst) {
            *self.guard.lock().unwrap() = Some(crate::peer_inbox::driver::attach_remote());
        }
        n
    }
    async fn list(&self, _page: u32) -> Result<Value, String> {
        Ok(json!({ "rows": [] }))
    }
}

fn cfg_req(sid: &str, op: &str) -> Value {
    json!({ "sessionId": sid, "optIn": true, "operator": op })
}

async fn opted_in(f: &Fake, op: &str) {
    configure_impl(f, cfg_req("s", op), None).await.expect("configure");
}

fn reason(e: &acp::Error) -> String {
    e.data.as_ref().and_then(|d| d["reason"].as_str()).unwrap_or("").to_owned()
}

fn tokens(v: &Value) -> Vec<(String, String)> {
    v["held"].as_array().unwrap().iter().map(|r| (r["heldId"].as_str().unwrap().to_owned(), r["token"].as_str().unwrap().to_owned())).collect()
}

fn rel(id: &str, token: &str) -> Value {
    json!({ "sessionId": "s", "heldId": id, "token": token })
}

/// The directory lists a session exactly while its gate is opted in (packet 8 tests the listing); configure drives that gate.
#[tokio::test]
async fn configure_opts_the_session_in_and_out_through_the_gate_a_peer_directory_reads() {
    let _on = force_peer_messaging_for_test(true);
    let f = Fake::new();
    assert!(!f.opted_in(), "an ACP session that did not opt in is not listed");
    let (reply, opt) = configure_impl(&f, cfg_req("s", "attended"), None).await.unwrap();
    assert!(opt);
    assert_eq!(reply["operator"], "attended");
    assert!(f.opted_in(), "opted in: a peer lists it");
    let (_, opt) = configure_impl(&f, json!({"sessionId": "s", "optIn": false}), None).await.unwrap();
    assert!(!opt);
    assert!(!f.opted_in(), "opt-out hides it again");
}

#[tokio::test]
async fn configure_validates_operator_and_policy_and_unavailable_is_typed() {
    let _on = force_peer_messaging_for_test(true);
    let f = Fake::new();
    assert!(configure_impl(&f, json!({"sessionId": "s", "optIn": true}), None).await.is_err(), "no operator, no opt-in");
    assert!(configure_impl(&f, cfg_req("s", "root"), None).await.is_err());
    assert!(configure_impl(&f, json!({"sessionId": "s", "optIn": true, "operator": "attended", "policy": "x"}), None).await.is_err());
    assert!(configure_impl(&f, json!({"sessionId": "s", "optIn": true, "operator": "attended", "from": "x"}), None).await.is_err(), "unknown field refused");
    assert!(!f.opted_in(), "nothing was applied");
    let e = configure_impl(&f, cfg_req("s", "attended"), Some("peer messaging is unavailable: a remote client is attached".into())).await.unwrap_err();
    assert_eq!(reason(&e), "unavailable");
    assert!(!f.opted_in());
    for (m, v) in [("list", list_impl(&f, json!({"sessionId": "s"}), Some("x".into())).await), ("held", list_held_impl(&f, json!({"sessionId": "s"}), Some("x".into())).await), ("release", release_impl(&f, rel("a", "b"), Some("x".into())).await)] {
        assert_eq!(reason(&v.unwrap_err()), "unavailable", "{m}");
    }
}

#[tokio::test]
async fn release_with_a_valid_token_delivers_and_the_token_is_single_use() {
    let _on = force_peer_messaging_for_test(true);
    let f = Fake::new();
    opted_in(&f, "attended").await;
    f.hold("m1", "lane a");
    let rows = tokens(&list_held_impl(&f, json!({"sessionId": "s"}), None).await.unwrap());
    let (id, tok) = rows[0].clone();
    let r = release_impl(&f, rel(&id, &tok), None).await.unwrap();
    assert_eq!(r["result"], "delivered");
    assert_eq!(f.delivered.lock().unwrap().as_slice(), ["m1"]);
    // Replay: refused (the hold is gone).
    let e = release_impl(&f, rel(&id, &tok), None).await.unwrap_err();
    assert!(matches!(reason(&e).as_str(), "not_found" | "bad_token"), "{}", reason(&e));
    assert_eq!(f.delivered.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_wrong_stale_replayed_and_foreign_token_is_refused() {
    let _on = force_peer_messaging_for_test(true);
    let f = Fake::new();
    opted_in(&f, "attended").await;
    f.hold("m1", "a");
    let (id, old) = tokens(&list_held_impl(&f, json!({"sessionId": "s"}), None).await.unwrap())[0].clone();
    // Asking again gives new tokens: the old one is dead (a replayed or stale token).
    let (_, fresh) = tokens(&list_held_impl(&f, json!({"sessionId": "s"}), None).await.unwrap())[0].clone();
    assert_ne!(old, fresh);
    assert_eq!(reason(&release_impl(&f, rel(&id, &old), None).await.unwrap_err()), "bad_token");
    assert_eq!(reason(&release_impl(&f, rel(&id, "guess"), None).await.unwrap_err()), "bad_token");
    // A token of another session (same held id there) is refused here.
    let other = Fake::new();
    opted_in(&other, "attended").await;
    other.hold("m1", "a");
    let (_, foreign) = tokens(&list_held_impl(&other, json!({"sessionId": "s"}), None).await.unwrap())[0].clone();
    assert_eq!(reason(&release_impl(&f, rel(&id, &foreign), None).await.unwrap_err()), "bad_token");
    assert!(f.delivered.lock().unwrap().is_empty());
    // The hold expires: the token that was current is refused as expired and nothing is delivered.
    set_test_clock(Some(T0 + 400));
    let e = release_impl(&f, rel(&id, &fresh), None).await.unwrap_err();
    assert!(matches!(reason(&e).as_str(), "expired" | "not_found"), "{}", reason(&e));
    assert!(f.delivered.lock().unwrap().is_empty());
}

#[tokio::test]
async fn tokens_die_when_the_client_disconnects_and_reconnects() {
    let _on = force_peer_messaging_for_test(true);
    let f = Fake::new();
    opted_in(&f, "attended").await;
    f.hold("m1", "a");
    let (id, before) = tokens(&list_held_impl(&f, json!({"sessionId": "s"}), None).await.unwrap())[0].clone();
    // A reconnecting client must configure again: that voids every token handed out before.
    opted_in(&f, "attended").await;
    assert_eq!(reason(&release_impl(&f, rel(&id, &before), None).await.unwrap_err()), "bad_token");
    let (_, after) = tokens(&list_held_impl(&f, json!({"sessionId": "s"}), None).await.unwrap())[0].clone();
    assert_eq!(release_impl(&f, rel(&id, &after), None).await.unwrap()["result"], "delivered");
}

#[tokio::test]
async fn refuse_uses_the_same_token_and_an_unattended_session_cannot_release_or_refuse() {
    let _on = force_peer_messaging_for_test(true);
    let f = Fake::new();
    opted_in(&f, "attended").await;
    f.hold("m1", "a");
    let (id, tok) = tokens(&list_held_impl(&f, json!({"sessionId": "s"}), None).await.unwrap())[0].clone();
    let r = release_impl(&f, json!({"sessionId": "s", "heldId": id, "token": tok, "action": "refuse"}), None).await.unwrap();
    assert_eq!(r["result"], "refused");
    assert!(f.delivered.lock().unwrap().is_empty());
    assert!(release_impl(&f, json!({"sessionId": "s", "heldId": "x", "token": "t", "action": "burn"}), None).await.is_err());

    // Unattended (the default kind): a hold is never released by anyone.
    let u = Fake::new();
    opted_in(&u, "unattended").await;
    u.st.configure(PeerAdmissionConfig { opted_in: true, policy: Default::default(), operator: OperatorPresence::None, relay_driven: false });
    let mut e = test_envelope("m2", "a", "hi");
    e.from_mode = PeerMode::new(false, PeerBase::AcceptEdits, false);
    let out = u.st.submit(e, now_mono(), &Fake::live());
    assert!(
        matches!(out, Submitted::Done(DeliveryOutcome::Rejected { reason: fuigo_peer::RejectReason::NoOperator })),
        "a would-be hold with no operator is rejected, not held: {out:?}"
    );
    assert_eq!(reason(&release_impl(&u, rel("m2", "t"), None).await.unwrap_err()), "no_operator");
}

#[tokio::test]
async fn the_event_pump_announces_holds_once_and_the_notices_with_escaped_text() {
    let _on = force_peer_messaging_for_test(true);
    let f = Fake::new();
    opted_in(&f, "attended").await;
    f.hold("m1", "<b>\u{202e}evil\nname</b>");
    let out: Arc<Mutex<Vec<Value>>> = Arc::default();
    let sink = out.clone();
    let emit = move |v: Value| sink.lock().unwrap().push(v);
    let mut known = HashSet::new();
    let mut pend = VecDeque::new();
    pump_once(&f, "s", &mut known, &mut pend, &emit).await;
    pump_once(&f, "s", &mut known, &mut pend, &emit).await;
    let events = out.lock().unwrap().clone();
    assert_eq!(events.len(), 1, "a hold is announced once: {events:?}");
    let u = &events[0]["update"];
    assert_eq!(u["sessionUpdate"], "peer_held");
    assert_eq!(u["heldId"], held_ref(&f.st.held_snapshot(now_mono())[0].from, "m1"));
    assert_eq!(u["counts"]["held"], 1);
    let name = u["from"]["name"].as_str().unwrap();
    assert!(!name.contains('<') && !name.contains('\n') && !name.contains('\u{202e}'), "{name}");
    assert!(u.get("token").is_none() && events[0].to_string().find("token").is_none(), "an event never carries a token");
    // The pump read the rows without voiding the client's tokens.
    let (id, tok) = tokens(&list_held_impl(&f, json!({"sessionId": "s"}), None).await.unwrap())[0].clone();
    pump_once(&f, "s", &mut known, &mut pend, &emit).await;
    assert_eq!(release_impl(&f, rel(&id, &tok), None).await.unwrap()["result"], "delivered");
    // Notice events: fixed text, escaped subject.
    let n = PeerNotice { message_id: "/etc/<x>\n".into(), from: String::new(), kind: NoticeKind::ProtectedFileChanged, detail: None, told: false };
    let ev = notice_event("s", &n);
    assert_eq!(ev["update"]["sessionUpdate"], "peer_warning");
    assert!(!ev["update"]["subject"].as_str().unwrap().contains('<'));
    assert!(ev["update"]["text"].as_str().unwrap().starts_with("a protected file changed"));
    for kind in [NoticeKind::Released, NoticeKind::Expired, NoticeKind::Reheld, NoticeKind::LaunderingRefused] {
        let ev = notice_event("s", &PeerNotice { message_id: "m".into(), from: String::new(), kind, detail: None, told: false });
        assert!(ev["update"]["sessionUpdate"].as_str().unwrap().starts_with("peer_"));
    }
}

const HOSTILE: &str = "m\u{202e}<b>\n\u{1b}[31m";

/// A peer's `message_id` is only length-capped (`BoundedId`, `Envelope::validate`), so it is never exposed: every row and event
/// carries an opaque local id, and a release through that id still finds the row.
#[tokio::test]
async fn p13r2_a_hostile_peer_message_id_is_never_echoed_and_release_works_through_the_opaque_id() {
    let _on = force_peer_messaging_for_test(true);
    let f = Fake::new();
    opted_in(&f, "attended").await;
    f.hold(HOSTILE, "a");
    let rows = list_held_impl(&f, json!({"sessionId": "s"}), None).await.unwrap();
    let (id, tok) = tokens(&rows)[0].clone();
    assert!(id.starts_with("h-") && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'), "{id}");
    let out: Arc<Mutex<Vec<Value>>> = Arc::default();
    let sink = out.clone();
    pump_once(&f, "s", &mut HashSet::new(), &mut VecDeque::new(), &move |v: Value| sink.lock().unwrap().push(v)).await;
    let all = format!("{rows}{:?}", out.lock().unwrap());
    assert!(!all.contains('\u{202e}') && !all.contains("<b>") && !all.contains("\\u{1b}") && !all.contains("\\u001b"), "{all}");
    assert_eq!(out.lock().unwrap()[0]["update"]["heldId"], id);
    let n = notice_event("s", &PeerNotice { message_id: HOSTILE.into(), from: String::new(), kind: NoticeKind::Released, detail: None, told: false });
    assert_eq!(n["update"]["heldId"], held_ref("", HOSTILE));
    assert!(!n.to_string().contains("<b>"));
    let r = release_impl(&f, rel(&id, &tok), None).await.unwrap();
    assert_eq!((r["result"].as_str(), r["heldId"].as_str()), (Some("delivered"), Some(id.as_str())));
    assert_eq!(f.delivered.lock().unwrap().as_slice(), &[HOSTILE.to_owned()]);
}

/// S4.1: while a remote client is attached the pump emits nothing and consumes nothing; the host answers `unavailable` to the
/// client methods; after it detaches the held row is announced.
#[tokio::test]
async fn p13r2_nothing_is_emitted_and_every_method_is_unavailable_while_a_remote_client_is_attached() {
    let _on = force_peer_messaging_for_test(true);
    let f = Fake::new();
    opted_in(&f, "attended").await;
    f.hold("m1", "a");
    let out: Arc<Mutex<Vec<Value>>> = Arc::default();
    let sink = out.clone();
    let emit = move |v: Value| sink.lock().unwrap().push(v);
    let mut known = HashSet::new();
    let mut pend = VecDeque::new();
    let g = crate::peer_inbox::driver::attach_remote();
    pump_once(&f, "s", &mut known, &mut pend, &emit).await;
    assert!(out.lock().unwrap().is_empty(), "no peer event while a remote client is attached");
    let un = inbox_unavailable();
    assert!(un.is_some(), "the host status is unavailable while attached");
    assert_eq!(reason(&configure_impl(&f, cfg_req("s", "attended"), un.clone()).await.unwrap_err()), "unavailable");
    assert_eq!(reason(&list_impl(&f, json!({"sessionId": "s"}), un.clone()).await.unwrap_err()), "unavailable");
    assert_eq!(reason(&list_held_impl(&f, json!({"sessionId": "s"}), un.clone()).await.unwrap_err()), "unavailable");
    assert_eq!(reason(&release_impl(&f, rel("a", "b"), un).await.unwrap_err()), "unavailable");
    drop(g);
    pump_once(&f, "s", &mut known, &mut pend, &emit).await;
    assert_eq!(out.lock().unwrap().len(), 1, "announced after the client detaches");
}

fn sink() -> (Arc<Mutex<Vec<Value>>>, impl Fn(Value) + Send + Sync) {
    let out: Arc<Mutex<Vec<Value>>> = Arc::default();
    let s = out.clone();
    (out, move |v: Value| s.lock().unwrap().push(v))
}

/// Round 3 fix 1: a remote client that attaches while the pump awaits the snapshot and the notices gets no tick, and nothing the
/// pump took is lost: the held row and the notice are emitted after it detaches.
#[tokio::test]
async fn p13r3_an_attach_during_the_pump_awaits_emits_nothing_and_loses_nothing() {
    let _on = force_peer_messaging_for_test(true);
    let f = Fake::new();
    opted_in(&f, "attended").await;
    f.hold("m1", "a");
    f.st.record_sent_notice("n1", fuigo_peer::NoticeKind::Expired);
    f.attach_after_notices.store(true, std::sync::atomic::Ordering::SeqCst);
    let (out, emit) = sink();
    let (mut known, mut pend) = (HashSet::new(), VecDeque::new());
    pump_once(&f, "s", &mut known, &mut pend, &emit).await;
    assert!(out.lock().unwrap().is_empty(), "attached before the emit: nothing sent: {:?}", out.lock().unwrap());
    assert!(known.is_empty(), "the held row is not marked announced");
    assert_eq!(pend.len(), 1, "the taken notice is kept, not dropped");
    f.attach_after_notices.store(false, std::sync::atomic::Ordering::SeqCst);
    drop(f.guard.lock().unwrap().take());
    pump_once(&f, "s", &mut known, &mut pend, &emit).await;
    let kinds: Vec<String> = out.lock().unwrap().iter().map(|e| e["update"]["sessionUpdate"].as_str().unwrap().to_owned()).collect();
    assert_eq!(kinds.len(), 2, "{kinds:?}");
    assert!(kinds.contains(&"peer_held".to_owned()) && kinds.iter().any(|k| k == "peer_warning" || k.starts_with("peer_")), "{kinds:?}");
    assert!(pend.is_empty());
}

/// Round 3 fix 2: the pump follows the session's own opt-in: a remote client attaching does not end it, and after it detaches the
/// held row is announced without another configure.
#[tokio::test]
async fn p13r3_the_pump_survives_a_remote_attach_and_announces_after_detach() {
    let _on = force_peer_messaging_for_test(true);
    let f = Arc::new(Fake::new());
    opted_in(&f, "attended").await;
    pumps().insert("s-r3".to_owned());
    let (out, emit) = sink();
    let task = tokio::spawn(run_pump(f.clone() as Arc<dyn ClientSession>, "s-r3".into(), emit, std::time::Duration::from_millis(20)));
    // Held, then a client attaches, all before the pump's first tick (current-thread runtime: no await in between).
    f.hold("m1", "a");
    let g = crate::peer_inbox::driver::attach_remote();
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    assert!(!f.opted_in() && f.client_opted_in(), "attached: gate reads false, the client's own opt-in stands");
    assert!(out.lock().unwrap().is_empty(), "silent while attached");
    assert!(!task.is_finished() && pumps().contains("s-r3"), "the pump stays alive");
    drop(g);
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    assert_eq!(out.lock().unwrap().len(), 1, "announced after detach with no new configure");
    // Opting out still ends it.
    f.st.gate().set_opted_in(false);
    tokio::time::timeout(std::time::Duration::from_secs(2), task).await.expect("pump ends on opt-out").unwrap();
    assert!(!pumps().contains("s-r3"));
}

/// Round 3 fix 4: two senders reusing one message id get different `heldId`s and each release resolves its own row.
#[tokio::test]
async fn p13r3_two_senders_reusing_a_message_id_have_distinct_held_ids_and_release_their_own_row() {
    let _on = force_peer_messaging_for_test(true);
    let f = Fake::new();
    opted_in(&f, "attended").await;
    f.hold_from("same", "a", "sender-one");
    f.hold_from("same", "b", "sender-two");
    let rows = tokens(&list_held_impl(&f, json!({"sessionId": "s"}), None).await.unwrap());
    assert_eq!(rows.len(), 2);
    assert_ne!(rows[0].0, rows[1].0, "distinct heldIds");
    for (id, tok) in &rows {
        let r = release_impl(&f, rel(id, tok), None).await.unwrap();
        assert_eq!(r["result"], "delivered");
        assert_eq!(r["heldId"].as_str(), Some(id.as_str()));
    }
    assert_eq!(f.st.held_count(), 0);
}
