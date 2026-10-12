//! Packet 8a tests. Written before the code, which is new, so they were red by compilation until the types existed.

use std::path::Path;

use crate::limits::*;
use crate::locator_row::*;
use crate::wire::*;
use crate::*;

const HOST: &str = "0123456789abcdef0123456789abcdef";
const OTHER: &str = "fedcba9876543210fedcba9876543210";

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

fn all_ops() -> Vec<Op> {
    vec![
        Op::List { page: 0 },
        Op::List { page: MAX_LIST_PAGES - 1 },
        Op::Send { to: addr(), envelope: envelope(), watch: false },
        Op::Notice { message_id: BoundedId::new("m-1").unwrap(), kind: NoticeKind::Idle },
    ]
}

fn all_replies() -> Vec<Reply> {
    vec![
        Reply::List { rows: vec![SessionRow { address: addr(), name: "a".into(), session_ref: "3f2a9c10".into() }], more: true },
        Reply::List { rows: vec![], more: false },
        Reply::Send { outcome: DeliveryOutcome::Delivered {} },
        Reply::Send { outcome: DeliveryOutcome::Rejected { reason: RejectReason::StaleAddress } },
        Reply::Notice {},
        Reply::Unavailable { reason: ReasonText::new("version mismatch").unwrap() },
    ]
}

#[test]
fn every_op_and_reply_round_trips() {
    for op in all_ops() {
        let json = serde_json::to_vec(&op).unwrap();
        assert!(check_wire_frame(json.len()).is_ok());
        let back: Op = serde_json::from_slice(&json).unwrap();
        assert_eq!(back, op);
        back.validate().unwrap();
    }
    for r in all_replies() {
        let json = serde_json::to_vec(&r).unwrap();
        let back: Reply = serde_json::from_slice(&json).unwrap();
        assert_eq!(back, r);
        back.validate().unwrap();
    }
    let h = Hello::new(hid(HOST));
    assert_eq!(serde_json::from_slice::<Hello>(&serde_json::to_vec(&h).unwrap()).unwrap(), h);
    assert!(h.version_matches());
}

#[test]
fn unknown_op_unknown_field_and_watch_are_rejected() {
    for bad in [
        r#"{"op":"watch","page":0}"#,
        r#"{"op":"watch","to":"x"}"#,
        r#"{"op":"bogus"}"#,
        r#"{"op":"list","page":0,"origin":"human"}"#,
        r#"{"op":"list","page":0,"mode":"yolo"}"#,
        r#"{"op":"notice","message_id":"m","kind":"idle","approve":true}"#,
        r#"{"page":0}"#,
        r#"{"op":"list"}"#,
        r#"{"op":"notice","message_id":"m","kind":"watch"}"#,
        r#"{"op":"notice","message_id":"","kind":"idle"}"#,
    ] {
        assert!(serde_json::from_str::<Op>(bad).is_err(), "{bad}");
    }
    let mut v = serde_json::to_value(Op::Send { to: addr(), envelope: envelope(), watch: false }).unwrap();
    v["authority"] = "operator".into();
    assert!(serde_json::from_value::<Op>(v).is_err());
    let mut v = serde_json::to_value(Op::Send { to: addr(), envelope: envelope(), watch: false }).unwrap();
    v["envelope"]["origin"] = "human".into();
    assert!(serde_json::from_value::<Op>(v).is_err());
    assert!(serde_json::from_str::<Reply>(r#"{"reply":"watching"}"#).is_err());
    assert!(serde_json::from_str::<Reply>(r#"{"reply":"notice","extra":1}"#).is_err());
    assert!(serde_json::from_str::<Hello>(&format!(r#"{{"version":1,"host_id":"{HOST}","pid":1}}"#)).is_err());
}

#[test]
fn list_page_and_reason_and_rows_are_bounded() {
    assert!(Op::List { page: MAX_LIST_PAGES }.validate().is_err());
    assert!(ReasonText::new(&"x".repeat(MAX_REASON_BYTES + 1)).is_err());
    let row = SessionRow { address: addr(), name: "a".into(), session_ref: "r".into() };
    let r = Reply::List { rows: vec![row.clone(); LIST_PAGE_ROWS + 1], more: false };
    assert!(r.validate().is_err());
    let r = Reply::List { rows: vec![SessionRow { name: "fuigo-peer:x".into(), ..row }], more: false };
    assert!(r.validate().is_err());
    assert!(check_wire_frame(MAX_FRAME_BYTES).is_ok());
    assert!(check_wire_frame(MAX_FRAME_BYTES + 1).is_err());
}

#[test]
fn hello_version_is_exact() {
    for v in [0, 2, u32::MAX] {
        assert!(!Hello { version: v, host_id: hid(HOST) }.version_matches());
    }
}

#[test]
fn host_id_shape_is_enforced() {
    assert!(HostId::new(HOST).is_ok());
    for bad in [
        "0123456789ABCDEF0123456789abcdef",
        &HOST[..31],
        &format!("{HOST}0"),
        "0123456789abcdeg0123456789abcdef",
        "../../etc/passwd00000000000000000",
        "0123456789abcdef/123456789abcdef",
        "0123456789abcdef.123456789abcdef",
        "",
    ] {
        assert!(HostId::new(bad).is_err(), "{bad}");
        assert!(serde_json::from_str::<HostId>(&format!("\"{bad}\"")).is_err());
    }
}

#[test]
fn a_to_address_cannot_change_the_socket_path() {
    for bad in [
        "fuigo-peer:../../tmp/x/s/1",
        "fuigo-peer:0123456789abcdef0123456789abcdef/../../x/1",
        "fuigo-peer:/etc/x/s/1",
        "fuigo-peer:0123456789abcdef0123456789abcdef/a/b/1",
    ] {
        assert!(bad.parse::<Address>().is_err(), "{bad}");
    }
    let dir = Path::new("/home/u/.fuigo/peers");
    let p = socket_path(dir, &HostId::of(&addr()));
    assert_eq!(p, Path::new("/home/u/.fuigo/peers/0123456789abcdef0123456789abcdef.sock"));
    assert_eq!(p.parent(), Some(dir));
    // Whatever session part an address carries, the path depends on the host id alone.
    let a2 = Address::new(HOST, "other-session", 99).unwrap();
    assert_eq!(socket_path(dir, &HostId::of(&a2)), p);
}

#[test]
fn directory_choice_by_length() {
    assert_eq!(choose_dir(20, None), DirChoice::Home);
    assert_eq!(choose_dir(SOCKET_PATH_MAX - HOME_SUFFIX_LEN, None), DirChoice::Home);
    assert_eq!(choose_dir(SOCKET_PATH_MAX - HOME_SUFFIX_LEN + 1, Some(20)), DirChoice::Runtime);
    assert_eq!(choose_dir(120, Some(20)), DirChoice::Runtime);
    assert_eq!(choose_dir(120, None), DirChoice::Unavailable(DirUnavailable::NoRuntimeDir));
    assert_eq!(choose_dir(120, Some(90)), DirChoice::Unavailable(DirUnavailable::RuntimeTooLong));
    assert_eq!(choose_dir(usize::MAX, Some(usize::MAX)), DirChoice::Unavailable(DirUnavailable::RuntimeTooLong));
    // The smaller of 108 (Linux) and 104 (macOS), minus the NUL.
    assert_eq!(SOCKET_PATH_MAX, 103);
    // The limit really is the length of the path we would build.
    let home = "h".repeat(SOCKET_PATH_MAX - HOME_SUFFIX_LEN);
    let built = socket_path(&Path::new(&home).join("peers"), &hid(HOST));
    assert_eq!(built.as_os_str().len(), SOCKET_PATH_MAX);
}

fn row_json(host: &str, dir: &str) -> String {
    format!(r#"{{"host_id":"{host}","pid":42,"started":1700000000,"dir":"{dir}"}}"#)
}

fn host_n(n: usize) -> String {
    format!("{n:032x}")
}

#[test]
fn rows_parse_and_match_serde_output() {
    let rows = vec![
        HostRow { host_id: hid(HOST), pid: 1, started: 2, dir: HostDir::Home },
        HostRow { host_id: hid(OTHER), pid: u32::MAX, started: u64::MAX, dir: HostDir::Runtime },
    ];
    for json in [serde_json::to_vec(&rows).unwrap(), serde_json::to_vec_pretty(&rows).unwrap()] {
        assert_eq!(parse_rows(&json).unwrap(), rows);
        assert_eq!(serde_json::from_slice::<Vec<HostRow>>(&json).unwrap(), rows);
    }
    assert_eq!(parse_rows(b" [ ] ").unwrap(), vec![]);
}

#[test]
fn rows_refuse_bad_input() {
    let ok = row_json(HOST, "home");
    // 64 rows pass, 65 do not.
    let n = |k: usize| format!("[{}]", (0..k).map(|i| row_json(&host_n(i), "home")).collect::<Vec<_>>().join(","));
    assert_eq!(parse_rows(n(64).as_bytes()).unwrap().len(), 64);
    assert_eq!(parse_rows(n(65).as_bytes()), Err(RowsError::TooManyRows));
    // 64 KiB passes the size gate, 64 KiB + 1 does not (even if it is only spaces).
    let mut pad = format!("[{ok}]").into_bytes();
    pad.resize(MAX_ROWS_BYTES, b' ');
    assert!(parse_rows(&pad).is_ok());
    pad.push(b' ');
    assert_eq!(parse_rows(&pad), Err(RowsError::TooLarge));
    assert_eq!(parse_rows(&vec![b'['; MAX_ROWS_BYTES + 1]), Err(RowsError::TooLarge));
    // Duplicate host id.
    assert_eq!(parse_rows(format!("[{ok},{ok}]").as_bytes()), Err(RowsError::DuplicateHost));
    for bad in [
        format!(r#"[{{"host_id":"{HOST}","pid":1,"started":1,"dir":"home","path":"/tmp/x"}}]"#),
        format!(r#"[{{"host_id":"{HOST}","pid":1,"started":1,"dir":"/tmp"}}]"#),
        format!(r#"[{{"host_id":"{HOST}","pid":1,"started":1}}]"#),
        format!(r#"[{{"host_id":"{HOST}","host_id":"{HOST}","pid":1,"started":1,"dir":"home"}}]"#),
        format!(r#"[{{"host_id":"{}","pid":1,"started":1,"dir":"home"}}]"#, HOST.to_uppercase()),
        format!(r#"[{{"host_id":"{HOST}","pid":-1,"started":1,"dir":"home"}}]"#),
        format!(r#"[{{"host_id":"{HOST}","pid":4294967296,"started":1,"dir":"home"}}]"#),
        format!(r#"[{{"host_id":"{HOST}","pid":01,"started":1,"dir":"home"}}]"#),
        format!(r#"[{{"host_id":"{HOST}","pid":1,"started":1,"dir":"ho\u006de"}}]"#),
        format!("[{ok}] x"),
        format!("[{ok},]"),
        format!("{{\"rows\":[{ok}]}}"),
        format!("[{ok}"),
        String::new(),
    ] {
        assert!(parse_rows(bad.as_bytes()).is_err(), "{bad}");
    }
    assert!(serde_json::from_str::<HostRow>(&format!(r#"{{"host_id":"{HOST}","pid":1,"started":1,"dir":"home","path":"x"}}"#)).is_err());
}

#[test]
fn reap_table() {
    use TryResult::*;
    let exp = hid(HOST);
    let x = hid(OTHER);
    let y = hid(&host_n(5));
    let cases: Vec<(TryResult, TryResult, Reap, Reap)> = vec![
        // (first, second, Home row, Runtime row)
        (Refused, Refused, Reap::Reap, Reap::Reap),
        (NoSuchFile, NoSuchFile, Reap::Reap, Reap::Keep),
        (Refused, NoSuchFile, Reap::Reap, Reap::Keep),
        (NoSuchFile, Refused, Reap::Reap, Reap::Keep),
        (Timeout, Timeout, Reap::Keep, Reap::Keep),
        (Refused, Timeout, Reap::Keep, Reap::Keep),
        (Timeout, Refused, Reap::Keep, Reap::Keep),
        (NoSuchFile, Timeout, Reap::Keep, Reap::Keep),
        (VersionMismatch, VersionMismatch, Reap::Keep, Reap::Keep),
        (Refused, VersionMismatch, Reap::Keep, Reap::Keep),
        (VersionMismatch, NoSuchFile, Reap::Keep, Reap::Keep),
        (Other, Other, Reap::Keep, Reap::Keep),
        (Refused, Other, Reap::Keep, Reap::Keep),
        (Hello(exp.clone()), Hello(exp.clone()), Reap::Keep, Reap::Keep),
        (Hello(exp.clone()), Refused, Reap::Keep, Reap::Keep),
        (Refused, Hello(exp.clone()), Reap::Keep, Reap::Keep),
        (Hello(x.clone()), Hello(x.clone()), Reap::Reap, Reap::Reap),
        (Hello(x.clone()), Hello(y.clone()), Reap::Keep, Reap::Keep),
        (Hello(x.clone()), Hello(exp.clone()), Reap::Keep, Reap::Keep),
        (Hello(x.clone()), Refused, Reap::Keep, Reap::Keep),
        (Hello(x.clone()), Timeout, Reap::Keep, Reap::Keep),
        (NoSuchFile, Hello(x.clone()), Reap::Keep, Reap::Keep),
    ];
    for (a, b, home, runtime) in cases {
        assert_eq!(reap_decision(HostDir::Home, &exp, &a, &b, false), home, "home {a:?} {b:?}");
        assert_eq!(reap_decision(HostDir::Runtime, &exp, &a, &b, false), runtime, "runtime {a:?} {b:?}");
        // The runtime directory was verified to be the row's own: absent twice now reaps; nothing else changes.
        let same = if (a == NoSuchFile || a == Refused) && (b == NoSuchFile || b == Refused) { Reap::Reap } else { runtime };
        assert_eq!(reap_decision(HostDir::Runtime, &exp, &a, &b, true), same, "runtime same dir {a:?} {b:?}");
        assert_eq!(reap_decision(HostDir::Home, &exp, &a, &b, true), home, "home same dir {a:?} {b:?}");
    }
}

/// xorshift64*, fixed seed: the fuzz is deterministic.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn mutated_frames_never_panic_and_never_yield_an_invalid_envelope() {
    let mut seeds: Vec<Vec<u8>> = all_ops().iter().map(|o| serde_json::to_vec(o).unwrap()).collect();
    seeds.extend(all_replies().iter().map(|r| serde_json::to_vec(r).unwrap()));
    seeds.push(serde_json::to_vec(&Hello::new(hid(HOST))).unwrap());
    let row_seed = serde_json::to_vec(&[HostRow { host_id: hid(HOST), pid: 1, started: 2, dir: HostDir::Home }]).unwrap();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let (mut decoded_ops, mut decoded_sends) = (0usize, 0usize);
    for i in 0..6000 {
        let mut b = seeds[i % seeds.len()].clone();
        for _ in 0..=rng.below(4) {
            match rng.below(5) {
                0 if !b.is_empty() => {
                    let k = rng.below(b.len());
                    b[k] = rng.next() as u8;
                }
                1 if !b.is_empty() => {
                    let k = rng.below(b.len());
                    b[k] ^= 1 << rng.below(8);
                }
                2 if !b.is_empty() => {
                    let k = rng.below(b.len());
                    b.remove(k);
                }
                3 => {
                    let k = rng.below(b.len() + 1);
                    b.insert(k, rng.next() as u8);
                }
                _ => {
                    let k = rng.below(b.len() + 1);
                    b.truncate(k);
                }
            }
        }
        if let Ok(op) = serde_json::from_slice::<Op>(&b) {
            decoded_ops += 1;
            if let Op::Send { envelope, .. } = &op {
                decoded_sends += 1;
                assert!(envelope.validate().is_ok());
            }
        }
        if let Ok(Reply::List { rows, .. }) = serde_json::from_slice::<Reply>(&b) {
            let _ = rows.len();
        }
        let _ = serde_json::from_slice::<Hello>(&b);
        let _ = parse_rows(&b);
        let mut r = row_seed.clone();
        let k = rng.below(r.len());
        r[k] = rng.next() as u8;
        let _ = parse_rows(&r);
    }
    // The loop is not vacuous: unmutated-enough frames still decode.
    assert!(decoded_ops > 0 && decoded_sends > 0);
}
