use std::sync::{Arc, Mutex};

use fuigo_peer::host::*;
use fuigo_peer::{Address, DeliveryOutcome, HoldReason};

use super::*;

const H: &str = "0123456789abcdef0123456789abcdef";

struct Double {
    status: PeerInboxStatus,
    me: SelfInfo,
    rows: Vec<PeerRow>,
    outcome: DeliveryOutcome,
    sent: Mutex<Vec<SendRequest>>,
}

impl PeerHost for Double {
    fn status(&self) -> PeerInboxStatus {
        self.status.clone()
    }
    fn this_session(&self) -> Option<SelfInfo> {
        Some(self.me.clone())
    }
    fn list(&self, _page: u32) -> HostFuture<'_, Result<PeerPage, PeerHostError>> {
        Box::pin(async move { Ok(PeerPage { rows: self.rows.clone(), more: false }) })
    }
    fn send(&self, request: SendRequest) -> HostFuture<'_, Result<DeliveryOutcome, PeerHostError>> {
        Box::pin(async move {
            self.sent.lock().unwrap().push(request);
            Ok(self.outcome.clone())
        })
    }
}

fn row(sid: &str, name: &str, r: &str, rel: Relation) -> PeerRow {
    PeerRow { address: Address::new(H, sid, 1).unwrap(), name: name.into(), session_ref: r.into(), relation: rel }
}

fn double(subagent: bool, status: PeerInboxStatus) -> (Arc<Double>, PeerHostHandle) {
    let d = Arc::new(Double {
        status,
        me: SelfInfo { address: Address::new(H, "me", 1).unwrap(), name: "me".into(), session_ref: "mmmmmmmm".into(), is_subagent: subagent },
        rows: vec![
            row("s1", "peer-one", "aaaaaaaa", Relation::Peer),
            row("s2", "kid", "bbbbbbbb", Relation::Family),
            row("s3", "<b>evil</b>", "cccccccc", Relation::SameHost),
        ],
        outcome: DeliveryOutcome::Delivered {},
        sent: Mutex::new(Vec::new()),
    });
    let h = PeerHostHandle(d.clone());
    (d, h)
}

fn send(to: &str, msg: &str) -> SendMessageInput {
    serde_json::from_value(serde_json::json!({"to": to, "message": msg})).unwrap()
}

#[tokio::test]
async fn list_agents_has_the_self_line_rows_and_escapes_names() {
    let (_d, h) = double(false, PeerInboxStatus::Ready);
    let out = run_list_agents(&h, &ListAgentsInput { page: None }).await.unwrap().text;
    assert!(out.starts_with("This session is me [mmmmmmmm]"), "{out}");
    assert!(out.contains("peer-one") && out.contains("relation=own-subagent"));
    assert!(!out.contains("<b>"), "{out}");
}

#[tokio::test]
async fn an_unavailable_inbox_gives_one_line_with_the_typed_reason() {
    let (_d, h) = double(false, PeerInboxStatus::Unavailable("the Fuigo home is a symbolic link".into()));
    let out = run_list_agents(&h, &ListAgentsInput { page: None }).await.unwrap().text;
    assert_eq!(out, "Peer messaging is unavailable: the Fuigo home is a symbolic link");
    let e = run_send_message(&h, &send("peer-one", "hi")).await.unwrap_err();
    assert!(format!("{e:?}").contains("symbolic link"), "{e:?}");
}

#[tokio::test]
async fn send_resolves_by_name_and_reports_only_the_receivers_outcome() {
    let (d, h) = double(false, PeerInboxStatus::Ready);
    let out = run_send_message(&h, &send("peer-one", "hello")).await.unwrap().text;
    assert_eq!(out, "Delivered.");
    let sent = d.sent.lock().unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].to, Address::new(H, "s1", 1).unwrap());
    assert_eq!(sent[0].message, "hello");
}

#[tokio::test]
async fn held_names_the_reason() {
    let (mut_d, _h) = double(false, PeerInboxStatus::Ready);
    let d = Arc::new(Double {
        status: PeerInboxStatus::Ready,
        me: mut_d.me.clone(),
        rows: mut_d.rows.clone(),
        outcome: DeliveryOutcome::Held { reason: HoldReason::ModeMismatch, expires_at: 1 },
        sent: Mutex::new(Vec::new()),
    });
    let out = run_send_message(&PeerHostHandle(d), &send("[aaaaaaaa]", "x")).await.unwrap().text;
    assert!(out.starts_with("Held for the receiver's user") && out.contains("permission mode"), "{out}");
}

#[tokio::test]
async fn unknown_and_oversize_are_errors_and_nothing_is_dialed() {
    let (d, h) = double(false, PeerInboxStatus::Ready);
    assert!(run_send_message(&h, &send("nobody", "x")).await.is_err());
    assert!(run_send_message(&h, &send("peer-one", &"x".repeat(32 * 1024 + 1))).await.is_err());
    assert!(d.sent.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_subagent_reaches_only_its_family_never_another_host() {
    let (d, h) = double(true, PeerInboxStatus::Ready);
    let e = run_send_message(&h, &send("peer-one", "x")).await.unwrap_err();
    assert!(format!("{e:?}").contains("parent and sibling"), "{e:?}");
    // a copied address of a peer is refused too
    let a = Address::new(H, "s1", 1).unwrap().to_string();
    assert!(run_send_message(&h, &send(&a, "x")).await.is_err());
    assert!(run_send_message(&h, &send("kid", "x")).await.is_ok());
    assert_eq!(d.sent.lock().unwrap().len(), 1);
    // listing is allowed
    assert!(run_list_agents(&h, &ListAgentsInput { page: None }).await.is_ok());
}

#[test]
fn s2_5_the_input_types_have_no_sender_mode_hop_or_denial_field() {
    for bad in ["from", "mode", "hop", "denied_recently", "from_name", "conversation_id"] {
        let v = serde_json::json!({"to": "x", "message": "y", bad: "z"});
        assert!(serde_json::from_value::<SendMessageInput>(v).is_err(), "{bad}");
    }
    assert!(serde_json::from_value::<ListAgentsInput>(serde_json::json!({"from": "x"})).is_err());
    assert!(serde_json::from_value::<RefusePeerMessageInput>(serde_json::json!({"message_id": "m", "reason": "r", "mode": "yolo"})).is_err());
    let schema = serde_json::to_value(schemars::schema_for!(SendMessageInput)).unwrap();
    let mut keys: Vec<&str> = schema["properties"].as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["message", "notify_when_idle", "summary", "to"]);
    assert_eq!(schema["additionalProperties"], serde_json::json!(false));
}

fn watch_input(v: serde_json::Value) -> SendMessageInput {
    serde_json::from_value(v).unwrap()
}

#[tokio::test]
async fn p11_notify_when_idle_sets_watch_and_a_messageless_call_is_a_watch_only() {
    let (d, h) = double(false, PeerInboxStatus::Ready);
    run_send_message(&h, &watch_input(serde_json::json!({"to": "peer-one", "message": "hi", "notify_when_idle": true}))).await.unwrap();
    run_send_message(&h, &watch_input(serde_json::json!({"to": "peer-one", "notify_when_idle": true}))).await.unwrap();
    run_send_message(&h, &send("peer-one", "plain")).await.unwrap();
    let sent = d.sent.lock().unwrap();
    assert_eq!((sent[0].watch, sent[0].message.as_str()), (true, "hi"));
    assert_eq!((sent[1].watch, sent[1].message.as_str()), (true, ""));
    assert!(!sent[2].watch);
}

#[tokio::test]
async fn p11_a_messageless_call_without_the_watch_flag_is_still_an_error_and_nothing_is_dialed() {
    let (d, h) = double(false, PeerInboxStatus::Ready);
    let e = run_send_message(&h, &watch_input(serde_json::json!({"to": "peer-one"}))).await.unwrap_err();
    assert!(format!("{e:?}").contains("empty_message"), "{e:?}");
    let e = run_send_message(&h, &watch_input(serde_json::json!({"to": "peer-one", "notify_when_idle": false}))).await.unwrap_err();
    assert!(format!("{e:?}").contains("empty_message"), "{e:?}");
    assert!(d.sent.lock().unwrap().is_empty());
}

#[tokio::test]
async fn p11_unavailable_with_a_watch_says_an_older_receiver_cannot_watch() {
    let (mut_d, _h) = double(false, PeerInboxStatus::Ready);
    let mk = |outcome| {
        Arc::new(Double { status: PeerInboxStatus::Ready, me: mut_d.me.clone(), rows: mut_d.rows.clone(), outcome, sent: Mutex::new(Vec::new()) })
    };
    let req = watch_input(serde_json::json!({"to": "peer-one", "message": "x", "notify_when_idle": true}));
    let d = mk(DeliveryOutcome::Rejected { reason: fuigo_peer::RejectReason::Unavailable });
    let out = run_send_message(&PeerHostHandle(d), &req).await.unwrap().text;
    assert!(out.contains("older version"), "{out}");
    let d = mk(DeliveryOutcome::Watching {});
    let out = run_send_message(&PeerHostHandle(d), &req).await.unwrap().text;
    assert!(out.starts_with("Watching"), "{out}");
    // Without a watch the old text is unchanged.
    let d = mk(DeliveryOutcome::Rejected { reason: fuigo_peer::RejectReason::Unavailable });
    let out = run_send_message(&PeerHostHandle(d), &send("peer-one", "x")).await.unwrap().text;
    assert_eq!(out, "Refused by the receiver: unavailable.");
}
