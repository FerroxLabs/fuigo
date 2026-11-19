//! Mutation-pass tests (1.0.46, lane `mut`): each test pins behaviour that `cargo mutants` showed no other test pinned.
//! Constants are asserted by value because a changed constant is a changed security bound.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::bounds::{BoundsError, max_bytes};
use crate::host::*;
use crate::ingress::*;
use crate::limits::*;
use crate::locator_row::*;
use crate::tools::*;
use crate::wire::*;
use crate::*;

const HOST: &str = "0123456789abcdef0123456789abcdef";

// ---- address.rs ----

#[test]
fn address_new_refuses_each_bad_session_id() {
    assert_eq!(
        Address::new(HOST, "", 1).unwrap_err(),
        AddressError::BadSessionId
    );
    assert_eq!(
        Address::new(HOST, "a/b", 1).unwrap_err(),
        AddressError::BadSessionId
    );
    assert_eq!(
        Address::new(HOST, "a b", 1).unwrap_err(),
        AddressError::BadSessionId
    );
    let at_cap = "a".repeat(MAX_ADDRESS_SESSION_ID_CHARS);
    assert!(Address::new(HOST, &at_cap, 1).is_ok());
    let over = "a".repeat(MAX_ADDRESS_SESSION_ID_CHARS + 1);
    assert_eq!(
        Address::new(HOST, &over, 1).unwrap_err(),
        AddressError::BadSessionId
    );
    assert!(Address::new(HOST, "Ab-9_z", 1).is_ok());
}

#[test]
fn address_error_display_texts_are_fixed() {
    let all = [
        (
            AddressError::MissingPrefix,
            "address must start with `fuigo-peer:`",
        ),
        (
            AddressError::BadHostId,
            "host id must be 32 lowercase hex characters",
        ),
        (
            AddressError::BadSessionId,
            "session id is empty, too long, or has a disallowed character",
        ),
        (
            AddressError::BadIncarnation,
            "incarnation must be a decimal number",
        ),
        (
            AddressError::WrongPartCount,
            "address must be `fuigo-peer:<host-id>/<session-id>/<incarnation>`",
        ),
        (
            AddressError::InvalidName,
            "name is not a valid display name",
        ),
    ];
    for (e, text) in all {
        assert_eq!(e.to_string(), text);
    }
}

#[test]
fn parse_name_ref_accepts_a_good_ref_and_refuses_a_bad_one() {
    let nr = parse_name_ref("lane a [3f2a9c10]").unwrap();
    assert_eq!((nr.name, nr.reference), ("lane a", "3f2a9c10"));
    assert!(parse_name_ref("n [abcdefghijkl]").is_some());
    assert!(parse_name_ref("n [abcdefg]").is_none());
    assert!(parse_name_ref("n [abcdefghijklm]").is_none());
    assert!(parse_name_ref("n [abcdef!h]").is_none());
    assert!(parse_name_ref("   [3f2a9c10]").is_none());
    assert!(parse_name_ref("[3f2a9c10]").is_none());
}

#[test]
fn target_and_name_ref_debug_print_lengths_only() {
    let secret = "very-secret-name";
    let name = format!("{:?}", Target::Name(secret));
    assert!(name.contains("Name") && name.contains("len") && !name.contains(secret));
    let nr = parse_name_ref("very-secret-name [3f2a9c10]").unwrap();
    let text = format!("{:?}", Target::NameRef(nr));
    assert!(text.contains("NameRef") && text.contains("reference_len") && !text.contains(secret));
    let a = Address::new(HOST, "s1", 4).unwrap();
    let text = format!("{:?}", Target::Address(a));
    assert!(text.contains("Address") && text.contains("s1"));
}

// ---- bounds.rs, tools.rs, envelope.rs ----

#[test]
fn max_bytes_allows_exactly_the_cap() {
    assert!(max_bytes("f", "abc", 3).is_ok());
    assert_eq!(
        max_bytes("f", "abcd", 3).unwrap_err(),
        BoundsError::TooLong {
            field: "f",
            unit: "bytes",
            max: 3,
            got: 4
        }
    );
    assert!(max_bytes("f", "", 0).is_ok());
}

fn send_args(to: usize, message: Option<usize>, summary: Option<usize>) -> SendMessageArgs {
    SendMessageArgs {
        to: "t".repeat(to),
        message: message.map(|n| "m".repeat(n)),
        notify_when_idle: None,
        summary: summary.map(|n| "s".repeat(n)),
    }
}

#[test]
fn send_message_validate_checks_each_field_at_cap_and_cap_plus_one() {
    assert!(
        send_args(MAX_TO_BYTES, Some(MAX_BODY_BYTES), Some(MAX_SUMMARY_BYTES))
            .validate()
            .is_ok()
    );
    let field = |a: SendMessageArgs| match a.validate().unwrap_err() {
        BoundsError::TooLong { field, .. } => field,
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(field(send_args(MAX_TO_BYTES + 1, None, None)), "to");
    assert_eq!(
        field(send_args(1, Some(MAX_BODY_BYTES + 1), None)),
        "message"
    );
    assert_eq!(
        field(send_args(1, None, Some(MAX_SUMMARY_BYTES + 1))),
        "summary"
    );
}

#[test]
fn refuse_peer_message_validate_checks_each_field_at_cap_and_cap_plus_one() {
    let mk = |id: usize, reason: usize| RefusePeerMessageArgs {
        message_id: "i".repeat(id),
        reason: "r".repeat(reason),
    };
    assert!(mk(MAX_ID_BYTES, MAX_REFUSE_REASON_BYTES).validate().is_ok());
    let field = |a: RefusePeerMessageArgs| match a.validate().unwrap_err() {
        BoundsError::TooLong { field, .. } => field,
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(field(mk(MAX_ID_BYTES + 1, 1)), "message_id");
    assert_eq!(field(mk(1, MAX_REFUSE_REASON_BYTES + 1)), "reason");
}

#[test]
fn tool_args_debug_print_lengths_only() {
    let s = SendMessageArgs {
        to: "to-secret".into(),
        message: Some("body-secret".into()),
        notify_when_idle: Some(true),
        summary: Some("sum-secret".into()),
    };
    let text = format!("{s:?}");
    assert!(text.contains("SendMessageArgs") && text.contains("to_len: 9"));
    assert!(text.contains("message_len: Some(11)") && text.contains("summary_len: Some(10)"));
    assert!(!text.contains("secret"));
    let r = RefusePeerMessageArgs {
        message_id: "id-secret".into(),
        reason: "why-secret".into(),
    };
    let text = format!("{r:?}");
    assert!(text.contains("RefusePeerMessageArgs") && text.contains("reason_len: 10"));
    assert!(!text.contains("secret"));
}

#[test]
fn denial_stamp_debug_prints_lengths_only() {
    let d = DenialStamp {
        tool_kind: "bash-secret".into(),
        target_hash: "hash".into(),
    };
    let text = format!("{d:?}");
    assert!(text.contains("DenialStamp") && text.contains("tool_kind_len: 11"));
    assert!(text.contains("target_hash_len: 4") && !text.contains("secret"));
}

// ---- constants ----

#[test]
fn derived_limits_and_windows_have_their_designed_values() {
    assert_eq!(MAX_BODY_BYTES_PER_SESSION, 1_048_576);
    assert_eq!(MAX_BODY_BYTES_PER_HOST, 4_194_304);
    assert_eq!(MESSAGE_ID_MEMORY_SECS, 600);
    assert_eq!(HOLD_EXPIRY_SECS, 300);
    assert_eq!(WATCH_EXPIRY_SECS, 43_200);
    assert_eq!(DENIAL_STAMP_SECS, 1800);
    assert_eq!(MAX_DENIAL_STAMPS, 128);
    assert_eq!(MAX_CARRIED_KEYS, 128);
    assert_eq!(PAIR_IDLE_SECS, 600);
    assert_eq!(RATE_WINDOW_SECS, 60);
    assert_eq!(MAX_LIST_PAGES, 4);
    assert_eq!(MAX_ROWS_BYTES, 65_536);
    assert_eq!(MAX_ROWS, 64);
    assert_eq!(HOME_SUFFIX_LEN, 44);
    assert_eq!(RUNTIME_SUFFIX_LEN, 50);
    assert_eq!(SOCKET_PATH_MAX, 103);
}

// ---- host.rs ----

struct NullHost;
impl PeerHost for NullHost {
    fn status(&self) -> PeerInboxStatus {
        PeerInboxStatus::Ready
    }
    fn this_session(&self) -> Option<SelfInfo> {
        None
    }
    fn list(&self, _page: u32) -> HostFuture<'_, Result<PeerPage, PeerHostError>> {
        Box::pin(async { Ok(PeerPage::default()) })
    }
    fn send(
        &self,
        _request: SendRequest,
    ) -> HostFuture<'_, Result<DeliveryOutcome, PeerHostError>> {
        Box::pin(async { Err(PeerHostError::Failed) })
    }
}

#[test]
fn peer_host_handle_debug_names_the_type() {
    let h = PeerHostHandle(Arc::new(NullHost));
    assert_eq!(format!("{h:?}"), "PeerHostHandle");
}

#[test]
fn relation_labels_are_fixed() {
    assert_eq!(Relation::Family.label(), "own-subagent");
    assert_eq!(Relation::SameHost.label(), "same-host");
    assert_eq!(Relation::Peer.label(), "peer");
}

#[test]
fn display_escape_neutralises_separators_bidi_and_invisibles() {
    assert_eq!(display_escape("a\u{2028}b", 64), "a&#x2028;b");
    assert_eq!(display_escape("a\u{2029}b", 64), "a&#x2029;b");
    assert_eq!(display_escape("a\u{202E}b", 64), "a&#x202E;b");
    assert_eq!(
        display_escape("a\u{200B}b\u{FEFF}", 64),
        "a&#x200B;b&#xFEFF;"
    );
    assert_eq!(display_escape("a\u{2060}b", 64), "a&#x2060;b");
    assert_eq!(display_escape("a\nb\u{7f}", 64), "a&#xA;b&#x7F;");
    assert_eq!(display_escape("&<>\"'", 64), "&amp;&lt;&gt;&quot;&#39;");
    assert_eq!(display_escape("abcdef", 3), "abc…");
    assert_eq!(display_escape("abc", 3), "abc");
}

#[test]
fn notice_text_is_fixed_for_every_kind() {
    use crate::NoticeKind as K;
    let p = "Fuigo runtime notice (written by Fuigo, not by a peer): ";
    let cases = [
        (
            Some(K::Released),
            "your message to T was held and its user released it",
        ),
        (
            Some(K::Expired),
            "your message to T was held and expired before its user released it; it was not delivered",
        ),
        (
            Some(K::Refused),
            "your message to T was held and then refused; it was not delivered",
        ),
        (Some(K::Denied), "the model in T refused your message"),
        (
            Some(K::Idle),
            "T finished the turn that handled your message and is now idle",
        ),
        (Some(K::Exited), "T exited"),
        (
            Some(K::Unavailable),
            "target unavailable (not a confirmed exit): T",
        ),
        (
            None,
            "outcome unknown for your message to T: no notice arrived within 12 hours",
        ),
    ];
    for (kind, what) in cases {
        assert_eq!(notice_text(kind, "T"), format!("{p}{what}."));
    }
    // The target is escaped and capped.
    let long = "x".repeat(300);
    assert!(notice_text(Some(K::Exited), &long).contains(&format!("{}…", "x".repeat(200))));
    assert!(notice_text(Some(K::Exited), "<b>").contains("&lt;b&gt;"));
}

#[test]
fn outcome_text_is_fixed_for_every_outcome() {
    assert_eq!(outcome_text(&DeliveryOutcome::Delivered {}), "Delivered.");
    assert_eq!(
        outcome_text(&DeliveryOutcome::Unknown {}),
        "Unknown: the receiver did not confirm."
    );
    assert!(outcome_text(&DeliveryOutcome::Watching {}).starts_with("Watching: delivered."));
    let held = [
        (
            HoldReason::ModeMismatch,
            "the receiver is in a different permission mode",
        ),
        (
            HoldReason::LoopGuard,
            "the conversation reached its loop guard",
        ),
        (
            HoldReason::SenderDenied,
            "this session was recently denied an action",
        ),
        (
            HoldReason::Integrity,
            "the receiver's integrity check holds new messages",
        ),
        (
            HoldReason::PolicyHold,
            "the receiver's policy holds messages for its user",
        ),
    ];
    for (reason, why) in held {
        assert_eq!(
            outcome_text(&DeliveryOutcome::Held {
                reason,
                expires_at: 1
            }),
            format!(
                "Held for the receiver's user: {why}. It is not delivered unless they release it."
            )
        );
    }
    let rejected = [
        (RejectReason::Unavailable, "unavailable"),
        (RejectReason::NoOperator, "no_operator"),
        (RejectReason::Saturated, "saturated"),
        (RejectReason::RateLimited, "rate_limited"),
        (RejectReason::StaleAddress, "stale_address"),
        (RejectReason::Ambiguous, "ambiguous"),
        (RejectReason::PolicyRefused, "policy_refused"),
        (RejectReason::TooLarge, "too_large"),
    ];
    for (reason, why) in rejected {
        assert_eq!(
            outcome_text(&DeliveryOutcome::Rejected { reason }),
            format!("Refused by the receiver: {why}.")
        );
    }
}

// ---- ingress.rs ----

fn ingress_env(id: &str) -> Envelope {
    Envelope {
        message_id: id.into(),
        seq: 1,
        from: Address::new(HOST, "sender-1", 1).unwrap(),
        from_name: String::new(),
        from_auto_title: None,
        from_ref: "ref".into(),
        from_mode: PeerMode::new(false, PeerBase::AcceptEdits, false),
        from_operator: OperatorKind::Human,
        conversation_id: "c".into(),
        hop: 0,
        denied_recently: Vec::new(),
        body: "b".into(),
    }
}

#[test]
fn ticket_clone_takes_a_second_reservation_and_debug_shows_bytes() {
    let ledger = Arc::new(HostLedger::with_caps(10, 1000));
    let t = ledger.reserve(100).unwrap();
    assert_eq!(ledger.usage(), (1, 100));
    let c = t.clone();
    assert_eq!(ledger.usage(), (2, 200));
    assert_eq!(format!("{c:?}"), "Ticket { bytes: 100 }");
    drop(t);
    assert_eq!(ledger.usage(), (1, 100));
    drop(c);
    assert_eq!(ledger.usage(), (0, 0));
}

fn small_ingress() -> PeerIngress {
    PeerIngress::new(
        IngressConfig {
            remembered_ids: 2,
            ..IngressConfig::default()
        },
        Arc::new(HostLedger::default()),
    )
}

#[test]
fn replay_order_is_compacted_only_past_sixteen_entries() {
    let mut i = small_ingress();
    let e = ingress_env("x");
    let from = e.from.to_string();
    let out = DeliveryOutcome::Delivered {};
    // Each record is followed by a forget, so the order queue keeps one stale entry per round.
    for n in 0..16 {
        let id = format!("id-{n}");
        i.record(0, 1, &from, &id, "h", &out);
        if n < 15 {
            i.forget(1, &from, &id);
        }
    }
    // 16 entries: at the threshold, not past it. Nothing is compacted yet.
    assert_eq!(i.sizes().replay_order, 16);
    assert_eq!(i.sizes().replay, 1);
    i.forget(1, &from, "id-15");
    i.record(0, 1, &from, "id-16", "h", &out);
    // 17 entries: past it. Only the live entry survives the compaction.
    assert_eq!(i.sizes().replay_order, 1);
    assert_eq!(i.sizes().replay, 1);
}

#[test]
fn forget_makes_the_same_id_new_again() {
    let mut i = PeerIngress::default();
    let e = ingress_env("m-1");
    let from = e.from.to_string();
    i.record(0, 1, &from, "m-1", "b", &DeliveryOutcome::Delivered {});
    assert_eq!(
        i.admit(1, 1, &e, "b"),
        IngressVerdict::Replay(DeliveryOutcome::Delivered {})
    );
    i.forget(1, &from, "m-1");
    assert_eq!(i.admit(2, 1, &e, "b"), IngressVerdict::Proceed);
}

// ---- wire.rs ----

#[test]
fn wire_error_display_texts_are_fixed() {
    assert_eq!(
        WireError::FrameTooLarge { len: 70_000 }.to_string(),
        "frame is 70000 bytes, the cap is 65536"
    );
    assert_eq!(
        WireError::OutOfRange { field: "pid" }.to_string(),
        "`pid` is out of range"
    );
    let inner = BoundsError::BadName { field: "n" };
    assert_eq!(
        WireError::Bounds(inner.clone()).to_string(),
        inner.to_string()
    );
}

#[test]
fn bounds_error_display_texts_are_fixed() {
    assert_eq!(
        BoundsError::TooLong {
            field: "f",
            unit: "bytes",
            max: 3,
            got: 4
        }
        .to_string(),
        "`f` is 4 bytes, the cap is 3"
    );
    assert_eq!(
        BoundsError::TooMany {
            field: "l",
            max: 1,
            got: 2
        }
        .to_string(),
        "`l` has 2 entries, the cap is 1"
    );
    assert_eq!(
        BoundsError::BadName { field: "n" }.to_string(),
        "`n` is not a valid display name"
    );
}

#[test]
fn wire_value_accessors_return_the_stored_text() {
    let h = HostId::new(HOST).unwrap();
    assert_eq!(h.as_str(), HOST);
    assert_eq!(h.to_string(), HOST);
    assert_eq!(BoundedId::new("abc").unwrap().as_str(), "abc");
    assert_eq!(ReasonText::new("why").unwrap().as_str(), "why");
}

// ---- locator_row.rs ----

fn row_json(host: &str, pid: &str, started: &str, dir: &str) -> String {
    format!(r#"{{"host_id":"{host}","pid":{pid},"started":{started},"dir":"{dir}"}}"#)
}

const HOST_B: &str = "fedcba9876543210fedcba9876543210";

#[test]
fn rows_error_display_texts_are_fixed() {
    assert_eq!(
        RowsError::TooLarge.to_string(),
        "locator file is over 64 KiB"
    );
    assert_eq!(
        RowsError::TooManyRows.to_string(),
        "locator file has more than 64 rows"
    );
    assert_eq!(
        RowsError::DuplicateHost.to_string(),
        "locator file repeats a host id"
    );
    assert_eq!(
        RowsError::Malformed.to_string(),
        "locator file is not a list of host rows"
    );
}

#[test]
fn parse_rows_reads_rows_in_any_key_order_with_whitespace() {
    let doc = format!(
        " \t\r\n[ \n{} ,\t{{ \"dir\" : \"runtime\" , \"started\":9,\n\"pid\" :  4 , \"host_id\":\"{HOST_B}\" }} \r\n] \n",
        row_json(HOST, "1234", "1700000000", "home")
    );
    let rows = parse_rows(doc.as_bytes()).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].host_id.as_str(), HOST);
    assert_eq!((rows[0].pid, rows[0].started), (1234, 1_700_000_000));
    assert_eq!(rows[0].dir, HostDir::Home);
    assert_eq!(rows[1].host_id.as_str(), HOST_B);
    assert_eq!((rows[1].pid, rows[1].started), (4, 9));
    assert_eq!(rows[1].dir, HostDir::Runtime);
    assert_eq!(parse_rows(b"[]").unwrap(), vec![]);
    assert_eq!(parse_rows(b"  [  ]  ").unwrap(), vec![]);
}

#[test]
fn parse_rows_refuses_every_malformed_shape() {
    let good = row_json(HOST, "1", "2", "home");
    let bad: Vec<(String, RowsError)> = vec![
        (format!("[{good}] x"), RowsError::Malformed),
        (format!("[{good},]"), RowsError::Malformed),
        (format!("[{good}"), RowsError::Malformed),
        (format!("{good}"), RowsError::Malformed),
        // Duplicate keys (each guard).
        (
            format!(
                r#"[{{"host_id":"{HOST}","host_id":"{HOST}","pid":1,"started":2,"dir":"home"}}]"#
            ),
            RowsError::Malformed,
        ),
        (
            format!(r#"[{{"host_id":"{HOST}","pid":1,"pid":1,"started":2,"dir":"home"}}]"#),
            RowsError::Malformed,
        ),
        (
            format!(r#"[{{"host_id":"{HOST}","pid":1,"started":2,"started":2,"dir":"home"}}]"#),
            RowsError::Malformed,
        ),
        (
            format!(r#"[{{"host_id":"{HOST}","pid":1,"started":2,"dir":"home","dir":"home"}}]"#),
            RowsError::Malformed,
        ),
        // Missing each field.
        (
            format!(r#"[{{"pid":1,"started":2,"dir":"home"}}]"#),
            RowsError::Malformed,
        ),
        (
            format!(r#"[{{"host_id":"{HOST}","started":2,"dir":"home"}}]"#),
            RowsError::Malformed,
        ),
        (
            format!(r#"[{{"host_id":"{HOST}","pid":1,"dir":"home"}}]"#),
            RowsError::Malformed,
        ),
        (
            format!(r#"[{{"host_id":"{HOST}","pid":1,"started":2}}]"#),
            RowsError::Malformed,
        ),
        // Unknown key, escapes, controls, bad dir, bad host id.
        (
            format!(r#"[{{"host_id":"{HOST}","pid":1,"started":2,"dir":"home","x":1}}]"#),
            RowsError::Malformed,
        ),
        (
            row_json("ab\\u0063", "1", "2", "home"),
            RowsError::Malformed,
        ),
        (
            format!("[{}]", row_json("ab\tc", "1", "2", "home")),
            RowsError::Malformed,
        ),
        (
            format!("[{}]", row_json(HOST, "1", "2", "elsewhere")),
            RowsError::Malformed,
        ),
        (
            format!("[{}]", row_json("short", "1", "2", "home")),
            RowsError::Malformed,
        ),
        // Unterminated string.
        (format!(r#"[{{"host_id":"{HOST}"#), RowsError::Malformed),
        // Numbers: leading zero, empty, too long, overflow, pid over u32, sign.
        (
            format!("[{}]", row_json(HOST, "01", "2", "home")),
            RowsError::Malformed,
        ),
        (
            format!("[{}]", row_json(HOST, "", "2", "home")),
            RowsError::Malformed,
        ),
        (
            format!("[{}]", row_json(HOST, "1", "-2", "home")),
            RowsError::Malformed,
        ),
        (
            format!("[{}]", row_json(HOST, "1", "000000000000000000002", "home")),
            RowsError::Malformed,
        ),
        (
            format!("[{}]", row_json(HOST, "1", "18446744073709551616", "home")),
            RowsError::Malformed,
        ),
        (
            format!("[{}]", row_json(HOST, "4294967296", "2", "home")),
            RowsError::Malformed,
        ),
        // Duplicate host ids.
        (format!("[{good},{good}]"), RowsError::DuplicateHost),
    ];
    for (doc, want) in bad {
        assert_eq!(parse_rows(doc.as_bytes()).unwrap_err(), want, "{doc}");
    }
    // Numbers at their limits are accepted.
    let max = row_json(HOST, "4294967295", "18446744073709551615", "home");
    let rows = parse_rows(format!("[{max}]").as_bytes()).unwrap();
    assert_eq!((rows[0].pid, rows[0].started), (u32::MAX, u64::MAX));
    let zero = row_json(HOST, "0", "0", "home");
    assert_eq!(
        parse_rows(format!("[{zero}]").as_bytes()).unwrap()[0].pid,
        0
    );
}

fn host_n(n: usize) -> String {
    format!("{n:032x}")
}

#[test]
fn parse_rows_row_cap_is_sixty_four_rows_and_the_size_cap_is_checked_first() {
    let rows = |n: usize| {
        let body: Vec<String> = (0..n)
            .map(|k| row_json(&host_n(k), "1", "2", "home"))
            .collect();
        format!("[{}]", body.join(","))
    };
    assert_eq!(parse_rows(rows(64).as_bytes()).unwrap().len(), 64);
    assert_eq!(
        parse_rows(rows(65).as_bytes()).unwrap_err(),
        RowsError::TooManyRows
    );
    let mut big = b"[".to_vec();
    big.resize(MAX_ROWS_BYTES, b' ');
    assert_eq!(parse_rows(&big).unwrap_err(), RowsError::Malformed);
    big.push(b' ');
    assert_eq!(parse_rows(&big).unwrap_err(), RowsError::TooLarge);
}

#[test]
fn runtime_dirs_use_the_stable_fnv_hash_of_the_home_path() {
    // FNV-1a 64 of the home path bytes, 16 lower-case hex digits.
    assert_eq!(
        runtime_home_dir(Path::new("/run/user/1"), Path::new("/home/x")),
        PathBuf::from("/run/user/1/fuigo/840b5cea7b2afd46")
    );
    assert_eq!(
        runtime_home_dir(Path::new("/r"), Path::new("")),
        PathBuf::from("/r/fuigo/cbf29ce484222325")
    );
    assert_eq!(
        runtime_peers_dir(Path::new("/run/user/1"), Path::new("/home/x")),
        PathBuf::from("/run/user/1/fuigo/840b5cea7b2afd46/peers")
    );
}

// ---- second round (survivors of the first re-run) ----

#[test]
fn address_accessors_return_the_parts() {
    let a = Address::new(HOST, "sess-1", 9).unwrap();
    assert_eq!(a.host_id(), HOST);
    assert_eq!(a.session_id(), "sess-1");
    assert_eq!(a.incarnation(), 9);
}

#[test]
fn ingress_ledger_is_the_one_passed_in() {
    let ledger = Arc::new(HostLedger::with_caps(10, 1000));
    let i = PeerIngress::new(IngressConfig::default(), Arc::clone(&ledger));
    let _t = ledger.reserve(5).unwrap();
    assert_eq!(i.ledger().usage(), (1, 5));
    assert!(Arc::ptr_eq(&i.ledger(), &ledger));
}

#[test]
fn rate_window_is_exactly_sixty_seconds() {
    let mut i = PeerIngress::default();
    let verdict = |i: &mut PeerIngress, now: u64, id: &str| i.admit(now, 1, &ingress_env(id), "b");
    for n in 0..RATE_PER_PAIR_PER_MINUTE {
        assert_eq!(
            verdict(&mut i, 0, &format!("a{n}")),
            IngressVerdict::Proceed
        );
    }
    // 59 s later the window still holds all ten: refused. At 60 s the window has slid past them: admitted.
    assert_eq!(
        verdict(&mut i, RATE_WINDOW_SECS - 1, "late"),
        IngressVerdict::Refuse(DeliveryOutcome::Rejected {
            reason: RejectReason::RateLimited
        })
    );
    assert_eq!(
        verdict(&mut i, RATE_WINDOW_SECS, "later"),
        IngressVerdict::Proceed
    );
}

#[test]
fn forget_session_drops_only_that_receivers_state() {
    let mut i = PeerIngress::default();
    let e = ingress_env("m");
    let from = e.from.to_string();
    let out = DeliveryOutcome::Delivered {};
    for receiver in [1, 2] {
        assert_eq!(i.admit(0, receiver, &e, "b"), IngressVerdict::Proceed);
        i.record(0, receiver, &from, "m", "b", &out);
    }
    assert_eq!(i.sizes().pairs, 2);
    assert_eq!(i.sizes().replay, 2);
    assert_eq!(i.sizes().replay_order, 2);
    i.forget_session(1);
    let s = i.sizes();
    assert_eq!((s.pairs, s.replay, s.replay_order), (1, 1, 1));
    // Receiver 2 still replays; receiver 1 is new again.
    assert_eq!(i.admit(1, 2, &e, "b"), IngressVerdict::Replay(out));
    assert_eq!(i.admit(1, 1, &e, "b"), IngressVerdict::Proceed);
}

fn list_reply(rows: Vec<SessionRow>) -> Reply {
    Reply::List { rows, more: false }
}

fn session_row(name: &str, session_ref: &str) -> SessionRow {
    SessionRow {
        address: Address::new(HOST, "s", 1).unwrap(),
        name: name.into(),
        session_ref: session_ref.into(),
    }
}

#[test]
fn reply_validate_checks_row_count_names_and_refs() {
    let rows = |n: usize| (0..n).map(|_| session_row("ok", "r")).collect::<Vec<_>>();
    assert!(list_reply(rows(LIST_PAGE_ROWS)).validate().is_ok());
    assert_eq!(
        list_reply(rows(LIST_PAGE_ROWS + 1)).validate().unwrap_err(),
        WireError::Bounds(BoundsError::TooMany {
            field: "rows",
            max: LIST_PAGE_ROWS,
            got: LIST_PAGE_ROWS + 1
        })
    );
    // A valid name passes (including the empty one); an invalid one is refused.
    assert!(list_reply(vec![session_row("", "r")]).validate().is_ok());
    assert_eq!(
        list_reply(vec![session_row("bad\u{202E}name", "r")])
            .validate()
            .unwrap_err(),
        WireError::Bounds(BoundsError::BadName { field: "rows.name" })
    );
    assert!(
        list_reply(vec![session_row("ok", &"r".repeat(MAX_ID_BYTES))])
            .validate()
            .is_ok()
    );
    assert!(
        list_reply(vec![session_row("ok", &"r".repeat(MAX_ID_BYTES + 1))])
            .validate()
            .is_err()
    );
    assert!(Reply::Notice {}.validate().is_ok());
}

#[test]
fn op_validate_checks_the_page_and_the_send_envelope() {
    assert!(
        Op::List {
            page: MAX_LIST_PAGES - 1
        }
        .validate()
        .is_ok()
    );
    assert_eq!(
        Op::List {
            page: MAX_LIST_PAGES
        }
        .validate()
        .unwrap_err(),
        WireError::OutOfRange { field: "page" }
    );
    let to = Address::new(HOST, "s", 1).unwrap();
    let good = ingress_env("m");
    let send = |envelope: Envelope| Op::Send {
        to: to.clone(),
        envelope,
        watch: false,
    };
    assert!(send(good.clone()).validate().is_ok());
    let bad = Envelope {
        message_id: "i".repeat(MAX_ID_BYTES + 1),
        ..good
    };
    assert!(matches!(
        send(bad).validate().unwrap_err(),
        WireError::Bounds(BoundsError::TooLong {
            field: "message_id",
            ..
        })
    ));
}
