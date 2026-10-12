//! Packet 8c tests: `tokio::io::duplex` only, no socket. Written before `conn.rs`, which is new (red by compilation).

use std::sync::Mutex;
use std::time::Duration;

use fuigo_peer::limits::MAX_FRAME_BYTES;
use fuigo_peer::wire::MAX_LIST_PAGES;
use fuigo_peer::{
    Address, BoundedId, DeliveryOutcome, Envelope, Hello, HostId, NoticeKind, OperatorKind, Op, PeerBase, PeerMode,
    Reply, SessionRow,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

use super::conn::*;

const HOST: &str = "0123456789abcdef0123456789abcdef";
const OTHER: &str = "fedcba9876543210fedcba9876543210";
const MARKER: &str = "ZZPEERMARKERZZ";

fn hid(s: &str) -> HostId {
    HostId::new(s).unwrap()
}
fn addr() -> Address {
    Address::new(HOST, "3f2a9c10-aaaa", 3).unwrap()
}
fn envelope() -> Envelope {
    Envelope {
        message_id: "m-1".into(),
        seq: 7,
        from: addr(),
        from_name: "lane a".into(),
        from_auto_title: None,
        from_ref: "3f2a9c10".into(),
        from_mode: PeerMode::new(false, PeerBase::AcceptEdits, false),
        from_operator: OperatorKind::Human,
        conversation_id: "c-1".into(),
        hop: 2,
        denied_recently: vec![],
        body: "hi".into(),
    }
}

#[derive(Default)]
struct FakeHost {
    calls: Mutex<Vec<String>>,
}
impl FakeHost {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}
impl InboxHost for FakeHost {
    async fn list(&self, page: u32) -> (Vec<SessionRow>, bool) {
        self.calls.lock().unwrap().push(format!("list {page}"));
        (vec![SessionRow { address: addr(), name: "n".into(), session_ref: "r".into() }], true)
    }
    async fn send_watched(&self, to: Address, e: Envelope, _watch: bool) -> DeliveryOutcome {
        self.send(to, e).await
    }
    async fn send(&self, _to: Address, envelope: Envelope) -> DeliveryOutcome {
        envelope.validate().expect("host must only see valid envelopes");
        self.calls.lock().unwrap().push(format!("send {}", envelope.message_id));
        DeliveryOutcome::Delivered {}
    }
    async fn notice(&self, message_id: BoundedId, kind: NoticeKind) {
        self.calls.lock().unwrap().push(format!("notice {} {kind:?}", message_id.as_str()));
    }
}

fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut v = (bytes.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(bytes);
    v
}
fn json_frame<T: serde::Serialize>(v: &T) -> Vec<u8> {
    frame(&serde_json::to_vec(v).unwrap())
}
async fn read_one(s: &mut DuplexStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await.unwrap();
    let mut b = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut b).await.unwrap();
    b
}
fn our() -> Hello {
    Hello::new(hid(HOST))
}

/// Run `serve_one` against a scripted peer that writes `script` (a hello frame then more) and then waits.
async fn serve_script(script: Vec<u8>, host: &FakeHost) -> (Result<(), ConnError>, Vec<u8>) {
    let (mut peer, server) = duplex(1 << 20);
    peer.write_all(&script).await.unwrap();
    let r = serve_one(server, our(), host).await;
    let mut out = Vec::new();
    let _ = peer.read_to_end(&mut out).await;
    (r, out)
}

fn script(ops: &[&Op]) -> Vec<u8> {
    let mut s = json_frame(&Hello::new(hid(OTHER)));
    for o in ops {
        s.extend(json_frame(*o));
    }
    s
}

#[tokio::test]
async fn happy_path_list_send_notice() {
    for (op, check) in [
        (Op::List { page: 2 }, "list 2"),
        (Op::Send { to: addr(), envelope: envelope(), watch: false }, "send m-1"),
        (Op::Notice { message_id: BoundedId::new("m-9").unwrap(), kind: NoticeKind::Idle }, "notice m-9 Idle"),
    ] {
        let host = FakeHost::default();
        let (client, server) = duplex(1 << 16);
        let expect = hid(HOST);
        let (r, reply) = tokio::join!(serve_one(server, our(), &host), exchange(client, Hello::new(hid(OTHER)), &expect, op.clone()));
        r.unwrap();
        let reply = reply.unwrap();
        assert_eq!(host.calls(), vec![check.to_string()]);
        match (&op, reply) {
            (Op::List { .. }, Reply::List { rows, more }) => assert!(more && rows.len() == 1),
            (Op::Send { .. }, Reply::Send { outcome }) => assert_eq!(outcome, DeliveryOutcome::Delivered {}),
            (Op::Notice { .. }, Reply::Notice {}) => {}
            other => panic!("wrong reply {other:?}"),
        }
    }
}

#[tokio::test(start_paused = true)]
async fn oversized_prefix_is_refused_before_any_body() {
    let host = FakeHost::default();
    for prefix in [0xFFFF_FFFFu32, MAX_FRAME_BYTES as u32 + 1] {
        let (mut peer, server) = duplex(1 << 16);
        peer.write_all(&prefix.to_be_bytes()).await.unwrap();
        // Only the prefix is ever sent; a reader that waited for the body would hit the 10 s deadline instead.
        let r = serve_one(server, our(), &host).await;
        assert_eq!(r, Err(ConnError::FrameTooLarge));
        let mut out = Vec::new();
        peer.read_to_end(&mut out).await.unwrap();
        assert!(out.is_empty(), "closed without writing");
    }
    assert!(host.calls().is_empty());
}

#[tokio::test(start_paused = true)]
async fn one_byte_per_second_is_dropped_at_ten_seconds() {
    let host = FakeHost::default();
    let (mut peer, server) = duplex(1 << 16);
    let feeder = tokio::spawn(async move {
        for b in json_frame(&Hello::new(hid(OTHER))) {
            if peer.write_all(&[b]).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    let start = tokio::time::Instant::now();
    let r = serve_one(server, our(), &host).await;
    assert_eq!(r, Err(ConnError::ExchangeTimeout));
    assert_eq!(start.elapsed(), EXCHANGE_DEADLINE);
    feeder.abort();
    assert!(host.calls().is_empty());
}

#[tokio::test(start_paused = true)]
async fn client_one_byte_per_second_server_is_dropped_too() {
    let (mut peer, client) = duplex(1 << 16);
    let feeder = tokio::spawn(async move {
        let _ = read_one(&mut peer).await;
        for b in json_frame(&Hello::new(hid(HOST))) {
            if peer.write_all(&[b]).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    let r = exchange(client, Hello::new(hid(OTHER)), &hid(HOST), Op::List { page: 0 }).await;
    assert_eq!(r, Err(ConnError::ExchangeTimeout));
    feeder.abort();
}

#[tokio::test(start_paused = true)]
async fn a_peer_that_never_reads_hits_the_write_deadline() {
    let host = FakeHost::default();
    let (mut peer, server) = duplex(16);
    let hello = json_frame(&Hello::new(hid(OTHER)));
    let holder = tokio::spawn(async move {
        peer.write_all(&hello).await.unwrap();
        std::future::pending::<()>().await; // never reads
    });
    let start = tokio::time::Instant::now();
    let r = serve_one(server, our(), &host).await;
    assert_eq!(r, Err(ConnError::WriteTimeout));
    assert_eq!(start.elapsed(), WRITE_DEADLINE);
    holder.abort();
}

#[tokio::test]
async fn wrong_version_gets_unavailable_and_never_reaches_the_host() {
    let host = FakeHost::default();
    let mut bad = serde_json::to_value(Hello::new(hid(OTHER))).unwrap();
    bad["version"] = serde_json::json!(2);
    let mut s = json_frame(&bad);
    s.extend(json_frame(&Op::List { page: 0 }));
    let (r, out) = serve_script(s, &host).await;
    assert_eq!(r, Err(ConnError::VersionMismatch));
    assert!(host.calls().is_empty());
    // Our hello, then exactly one unavailable reply.
    let mut cur = &out[..];
    let mut frames = Vec::new();
    while cur.len() >= 4 {
        let n = u32::from_be_bytes(cur[..4].try_into().unwrap()) as usize;
        frames.push(cur[4..4 + n].to_vec());
        cur = &cur[4 + n..];
    }
    assert_eq!(frames.len(), 2);
    assert_eq!(serde_json::from_slice::<Hello>(&frames[0]).unwrap(), our());
    match serde_json::from_slice::<Reply>(&frames[1]).unwrap() {
        Reply::Unavailable { reason } => assert_eq!(reason.as_str(), REASON_VERSION),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn client_sees_host_mismatch_and_sends_no_op() {
    let (mut peer, client) = duplex(1 << 16);
    let t = tokio::spawn(async move {
        let _ = read_one(&mut peer).await;
        peer.write_all(&json_frame(&Hello::new(hid(OTHER)))).await.unwrap();
        let mut rest = Vec::new();
        peer.read_to_end(&mut rest).await.unwrap();
        rest
    });
    let r = exchange(client, Hello::new(hid(OTHER)), &hid(HOST), Op::List { page: 0 }).await;
    assert_eq!(r, Err(ConnError::HostMismatch));
    assert!(t.await.unwrap().is_empty(), "no op is sent to the wrong host");
}

#[tokio::test]
async fn client_sees_version_mismatch_as_its_own_error() {
    let (mut peer, client) = duplex(1 << 16);
    tokio::spawn(async move {
        let _ = read_one(&mut peer).await;
        let mut h = serde_json::to_value(Hello::new(hid(HOST))).unwrap();
        h["version"] = serde_json::json!(9);
        peer.write_all(&json_frame(&h)).await.unwrap();
        let _ = peer.read_to_end(&mut Vec::new()).await;
    });
    let r = exchange(client, Hello::new(hid(OTHER)), &hid(HOST), Op::List { page: 0 }).await;
    assert_eq!(r, Err(ConnError::VersionMismatch));
}

#[tokio::test]
async fn two_pipelined_ops_give_one_reply_and_one_host_call() {
    let host = FakeHost::default();
    let (r, out) = serve_script(script(&[&Op::List { page: 0 }, &Op::List { page: 1 }]), &host).await;
    r.unwrap();
    assert_eq!(host.calls(), vec!["list 0".to_string()]);
    let mut cur = &out[..];
    let mut n_frames = 0;
    while cur.len() >= 4 {
        let n = u32::from_be_bytes(cur[..4].try_into().unwrap()) as usize;
        cur = &cur[4 + n..];
        n_frames += 1;
    }
    assert_eq!(n_frames, 2, "our hello plus exactly one reply");
}

#[tokio::test]
async fn invalid_ops_never_reach_the_host() {
    let host = FakeHost::default();
    // Page out of range: decodes, fails Op::validate.
    let (r, _) = serve_script(script(&[&Op::List { page: MAX_LIST_PAGES }]), &host).await;
    assert_eq!(r, Err(ConnError::Invalid));
    // Oversized body: the envelope refuses to decode.
    let mut v = serde_json::to_value(Op::Send { to: addr(), envelope: envelope(), watch: false }).unwrap();
    v["envelope"]["body"] = serde_json::json!("x".repeat(40 * 1024));
    let mut s = json_frame(&Hello::new(hid(OTHER)));
    s.extend(json_frame(&v));
    let (r, _) = serve_script(s, &host).await;
    assert_eq!(r, Err(ConnError::Decode));
    // Unknown op (`watch`) is a decode error.
    let mut s = json_frame(&Hello::new(hid(OTHER)));
    s.extend(json_frame(&serde_json::json!({"op": "watch"})));
    let (r, _) = serve_script(s, &host).await;
    assert_eq!(r, Err(ConnError::Decode));
    assert!(host.calls().is_empty());
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[tokio::test]
async fn mutation_fuzz_never_panics_and_host_sees_only_valid_input() {
    let host = FakeHost::default();
    let seeds: Vec<Vec<u8>> = vec![
        serde_json::to_vec(&Op::List { page: 0 }).unwrap(),
        serde_json::to_vec(&Op::Send { to: addr(), envelope: envelope(), watch: false }).unwrap(),
        serde_json::to_vec(&Op::Notice { message_id: BoundedId::new("m-1").unwrap(), kind: NoticeKind::Idle }).unwrap(),
    ];
    let hello = serde_json::to_vec(&Hello::new(hid(OTHER))).unwrap();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut served = 0usize;
    for i in 0..1500 {
        let mut h = hello.clone();
        let mut o = seeds[i % seeds.len()].clone();
        for _ in 0..=rng.below(3) {
            let target = if rng.below(4) == 0 { &mut h } else { &mut o };
            if target.is_empty() {
                continue;
            }
            let k = rng.below(target.len());
            match rng.below(3) {
                0 => target[k] = rng.next() as u8,
                1 => target[k] ^= 1 << rng.below(8),
                _ => {
                    target.remove(k);
                }
            }
        }
        let mut s = frame(&h);
        s.extend(frame(&o));
        let (r, _) = serve_script(s, &host).await;
        if r.is_ok() {
            served += 1;
        }
    }
    assert!(served > 0, "some mutations survive, so the loop reaches the host");
    for c in host.calls() {
        assert!(c.starts_with("list ") || c.starts_with("send ") || c.starts_with("notice "));
    }
}

#[tokio::test]
async fn no_error_text_contains_peer_bytes() {
    let host = FakeHost::default();
    let mut cases: Vec<Vec<u8>> = Vec::new();
    // Marker as a host id, as an unknown field, as an op tag, as a body, as raw non-JSON bytes.
    cases.push(json_frame(&serde_json::json!({"version": 1, "host_id": MARKER})));
    cases.push(json_frame(&serde_json::json!({"version": 1, "host_id": OTHER, MARKER: 1})));
    let mut s = json_frame(&Hello::new(hid(OTHER)));
    s.extend(json_frame(&serde_json::json!({"op": MARKER})));
    cases.push(s);
    let mut s = json_frame(&Hello::new(hid(OTHER)));
    s.extend(json_frame(&serde_json::json!({"op": "list", "page": MARKER})));
    cases.push(s);
    let mut s = json_frame(&Hello::new(hid(OTHER)));
    s.extend(frame(MARKER.as_bytes()));
    cases.push(s);
    cases.push(frame(MARKER.as_bytes()));
    let mut v = serde_json::to_value(Op::Send { to: addr(), envelope: envelope(), watch: false }).unwrap();
    v["envelope"]["body"] = serde_json::json!(MARKER.repeat(5000));
    let mut s = json_frame(&Hello::new(hid(OTHER)));
    s.extend(json_frame(&v));
    cases.push(s);
    let mut v = serde_json::to_value(Hello::new(hid(OTHER))).unwrap();
    v["version"] = serde_json::json!(7);
    v[MARKER] = serde_json::json!(MARKER);
    cases.push(json_frame(&v));
    for c in cases {
        let (r, _) = serve_script(c, &host).await;
        let e = r.expect_err("every case is an error");
        assert!(!format!("{e} {e:?}").contains(MARKER));
    }
    // Client side: a server that answers with marker garbage.
    for reply in [frame(MARKER.as_bytes()), json_frame(&serde_json::json!({"reply": MARKER}))] {
        let (mut peer, client) = duplex(1 << 16);
        let t = tokio::spawn(async move {
            let _ = read_one(&mut peer).await;
            peer.write_all(&json_frame(&Hello::new(hid(HOST)))).await.unwrap();
            let _ = read_one(&mut peer).await;
            peer.write_all(&reply).await.unwrap();
        });
        let e = exchange(client, Hello::new(hid(OTHER)), &hid(HOST), Op::List { page: 0 }).await.unwrap_err();
        assert!(!format!("{e} {e:?}").contains(MARKER));
        t.await.unwrap();
    }
    assert!(host.calls().is_empty());
}

#[tokio::test]
async fn client_refuses_a_reply_of_the_wrong_kind_and_an_op_that_fails_validate() {
    let (mut peer, client) = duplex(1 << 16);
    tokio::spawn(async move {
        let _ = read_one(&mut peer).await;
        peer.write_all(&json_frame(&Hello::new(hid(HOST)))).await.unwrap();
        let _ = read_one(&mut peer).await;
        peer.write_all(&json_frame(&Reply::Notice {})).await.unwrap();
    });
    let r = exchange(client, Hello::new(hid(OTHER)), &hid(HOST), Op::List { page: 0 }).await;
    assert_eq!(r, Err(ConnError::UnexpectedReply));
    let (_p, client) = duplex(64);
    let r = exchange(client, Hello::new(hid(OTHER)), &hid(HOST), Op::List { page: MAX_LIST_PAGES }).await;
    assert_eq!(r, Err(ConnError::Invalid));
}


// ---------------------------------------------------------------------------------------------------------------
// Round 2

#[derive(Default)]
struct HelloHost {
    hellos: Mutex<Vec<HostId>>,
}
impl InboxHost for HelloHost {
    async fn list(&self, _page: u32) -> (Vec<SessionRow>, bool) {
        (vec![], false)
    }
    async fn send_watched(&self, to: Address, e: Envelope, _watch: bool) -> DeliveryOutcome {
        self.send(to, e).await
    }
    async fn send(&self, _to: Address, _e: Envelope) -> DeliveryOutcome {
        DeliveryOutcome::Delivered {}
    }
    async fn notice(&self, _m: BoundedId, _k: NoticeKind) {}
    fn peer_hello(&self, host: &HostId) {
        self.hellos.lock().unwrap().push(host.clone());
    }
}

#[tokio::test]
async fn r2_peer_hello_runs_only_after_the_version_matched() {
    let host = HelloHost::default();
    let mut bad = serde_json::to_value(Hello::new(hid(OTHER))).unwrap();
    bad["version"] = serde_json::json!(2);
    let (mut peer, server) = duplex(1 << 20);
    peer.write_all(&json_frame(&bad)).await.unwrap();
    assert_eq!(serve_one(server, our(), &host).await, Err(ConnError::VersionMismatch));
    assert!(host.hellos.lock().unwrap().is_empty());
    let (mut peer, server) = duplex(1 << 20);
    peer.write_all(&script(&[&Op::List { page: 0 }])).await.unwrap();
    assert_eq!(serve_one(server, our(), &host).await, Ok(()));
    assert_eq!(host.hellos.lock().unwrap().len(), 1);
}

/// A stream whose shutdown never completes.
struct StallShutdown(DuplexStream);
impl tokio::io::AsyncRead for StallShutdown {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl tokio::io::AsyncWrite for StallShutdown {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
}

#[tokio::test(start_paused = true)]
async fn r2_a_finished_exchange_does_not_hold_its_permit_for_the_write_deadline() {
    let host = FakeHost::default();
    let (mut peer, server) = duplex(1 << 20);
    peer.write_all(&script(&[&Op::List { page: 0 }])).await.unwrap();
    let t0 = tokio::time::Instant::now();
    assert_eq!(serve_one(StallShutdown(server), our(), &host).await, Ok(()));
    assert!(t0.elapsed() < std::time::Duration::from_secs(1), "{:?}", t0.elapsed());
}
