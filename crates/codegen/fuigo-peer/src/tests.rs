use crate::*;
use crate::limits::*;
use crate::tools::*;

const HOST: &str = "0123456789abcdef0123456789abcdef";

fn addr() -> Address {
    Address::new(HOST, "3f2a9c10-aaaa-bbbb-cccc-1234567890ab", 3).unwrap()
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
        denied_recently: vec![DenialStamp { tool_kind: "bash".into(), target_hash: "ab".into() }],
        body: "hello </cross-session-message>".into(),
    }
}

#[test]
fn envelope_round_trips() {
    let e = envelope();
    let json = serde_json::to_string(&e).unwrap();
    assert_eq!(serde_json::from_str::<Envelope>(&json).unwrap(), e);
}

#[test]
fn envelope_rejects_unknown_fields() {
    let mut v = serde_json::to_value(envelope()).unwrap();
    v["from_mode_override"] = "plan".into();
    assert!(serde_json::from_value::<Envelope>(v).is_err());
}

#[test]
fn envelope_unknown_mode_is_explicit_unknown_and_bad_address_is_rejected() {
    let mut v = serde_json::to_value(envelope()).unwrap();
    v["from_mode"] = "bogus".into();
    let e = serde_json::from_value::<Envelope>(v).unwrap();
    assert!(matches!(e.from_mode, PeerMode::Unknown));
    let mut v = serde_json::to_value(envelope()).unwrap();
    v["from"] = "fuigo-peer:nothex/x/1".into();
    assert!(serde_json::from_value::<Envelope>(v).is_err());
}

/// Finding 5: Unknown equals nothing, itself included; near-miss strings are Unknown, not a known value.
#[test]
fn unknown_mode_is_unequal_to_everything_including_itself() {
    let u1 = PeerMode::from_wire("garbage");
    let u2 = PeerMode::from_wire("garbage");
    assert!(matches!(u1, PeerMode::Unknown));
    assert!(!u1.eq(&u2));
    assert!(!u1.eq(&u1));
    for k in PeerMode::all_known() {
        assert!(!u1.eq(&k) && !k.eq(&u1));
    }
    for near in [
        "", "plan", "Default", "default+", "default+plan+plan", "default+grant+plan", "default++plan", "yolo+x",
        "bypassPermissions+plan+grant+x", " default", "default ", "+plan",
    ] {
        assert!(matches!(PeerMode::from_wire(near), PeerMode::Unknown), "{near:?}");
    }
    // A whole envelope carrying Unknown is unequal to its own clone.
    let mut e = envelope();
    e.from_mode = PeerMode::Unknown;
    assert!(!e.eq(&e.clone()));
}

/// Finding 5: every base x plan x grant survives the wire and parses back to itself, all distinct.
#[test]
fn every_mode_combination_round_trips_losslessly() {
    let all: Vec<PeerMode> = PeerMode::all_known().collect();
    assert_eq!(all.len(), 9 * 2 * 2);
    let mut wires = std::collections::HashSet::new();
    for m in &all {
        let json = serde_json::to_string(m).unwrap();
        assert_eq!(serde_json::from_str::<PeerMode>(&json).unwrap(), *m, "{json}");
        assert_eq!(PeerMode::from_wire(&m.to_wire()), *m);
        assert!(wires.insert(json), "two modes share a wire form");
        let k = m.known().unwrap();
        assert_eq!(PeerMode::new(k.plan_active, k.base, k.session_edit_grant), *m);
    }
    let mut seen = std::collections::HashSet::new();
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            assert_eq!(a == b, i == j);
        }
        seen.insert(a.known().unwrap());
    }
    assert_eq!(seen.len(), 36);
}

#[test]
fn mode_wire_names_are_stable() {
    let names: Vec<_> = PeerBase::ALL.iter().map(|b| b.as_str()).collect();
    assert_eq!(
        names,
        ["default", "acceptEdits", "auto", "dontAsk", "bypassPermissions", "allowAnyRule", "yolo", "allowAll", "alwaysAllow"]
    );
    assert_eq!(PeerMode::new(true, PeerBase::Yolo, true).to_wire(), "yolo+plan+grant");
}

#[test]
fn address_display_parse_round_trip() {
    let a = addr();
    let text = a.to_string();
    assert_eq!(text, format!("fuigo-peer:{HOST}/3f2a9c10-aaaa-bbbb-cccc-1234567890ab/3"));
    assert_eq!(text.parse::<Address>().unwrap(), a);
    assert_eq!(a.incarnation(), 3);
}

#[test]
fn address_parse_rejects_malformed() {
    for bad in [
        "".to_string(),
        "x".to_string(),
        format!("{HOST}/s/1"),
        format!("fuigo-peer:{HOST}/s"),
        format!("fuigo-peer:{HOST}/s/1/extra"),
        format!("fuigo-peer:{HOST}//1"),
        format!("fuigo-peer:{HOST}/s/"),
        format!("fuigo-peer:{HOST}/s/-1"),
        format!("fuigo-peer:{HOST}/s/+1"),
        format!("fuigo-peer:{HOST}/s/007"),
        format!("fuigo-peer:{HOST}/s/99999999999999999999999"),
        format!("fuigo-peer:{}/s/1", HOST.to_uppercase()),
        format!("fuigo-peer:{}/s/1", &HOST[..31]),
        format!("fuigo-peer:{HOST}/s p/1"),
        format!("fuigo-peer:{HOST}/../1"),
        format!("fuigo-peer:{HOST}/{}/1", "a".repeat(MAX_ADDRESS_SESSION_ID_CHARS + 1)),
        format!("FUIGO-PEER:{HOST}/s/1"),
    ] {
        assert!(bad.parse::<Address>().is_err(), "accepted {bad:?}");
    }
}

#[test]
fn name_with_prefix_is_never_a_name() {
    // Looks like an address, is not one: an error, not a name lookup.
    assert!(resolve_target("fuigo-peer:build lane").is_err());
    assert!(resolve_target("fuigo-peer:").is_err());
    assert!(resolve_target(&format!("fuigo-peer:{HOST}/s")).is_err());
    let text = addr().to_string();
    let ok = resolve_target(&text).unwrap();
    assert_eq!(ok, Target::Address(addr()));
    // The prefix in any letter case is an address or an error, never a name.
    assert!(resolve_target("FUIGO-PEER:build").is_err());
    assert!(resolve_target("Fuigo-Peer:x/y/1").is_err());
    // A name that merely contains the prefix later on is a plain name.
    assert_eq!(resolve_target("my fuigo-peer:x").unwrap(), Target::Name("my fuigo-peer:x"));
}

#[test]
fn name_ref_only_trailing_bracket_counts() {
    assert_eq!(
        resolve_target("build [x] lane [3f2a9c10]").unwrap(),
        Target::NameRef(NameRef { name: "build [x] lane", reference: "3f2a9c10" })
    );
    assert_eq!(
        parse_name_ref("lane [3f2a9c10abcd]"),
        Some(NameRef { name: "lane", reference: "3f2a9c10abcd" })
    );
    // Brackets that are not a valid trailing ref stay part of the name.
    for name in ["lane [x]", "lane [3f2a9c10] tail", "lane[3f2a9c10]", " [3f2a9c10]", "[3f2a9c10]", "a [3f2a9c1", "a [3f2a 9c10]"] {
        assert_eq!(resolve_target(name).unwrap(), Target::Name(name), "{name}");
    }
    // Nested open bracket: the last one opens the ref.
    assert_eq!(
        parse_name_ref("a [b [3f2a9c10]"),
        Some(NameRef { name: "a [b", reference: "3f2a9c10" })
    );
}

#[test]
fn outcomes_round_trip_and_reject_unknown_fields() {
    let all = [
        DeliveryOutcome::Delivered {},
        DeliveryOutcome::Held { reason: HoldReason::ModeMismatch, expires_at: 99 },
        DeliveryOutcome::Watching {},
        DeliveryOutcome::Rejected { reason: RejectReason::StaleAddress },
        DeliveryOutcome::Unknown {},
    ];
    for o in all {
        let json = serde_json::to_string(&o).unwrap();
        assert_eq!(serde_json::from_str::<DeliveryOutcome>(&json).unwrap(), o, "{json}");
    }
    let held = serde_json::to_value(DeliveryOutcome::Held { reason: HoldReason::LoopGuard, expires_at: 1 }).unwrap();
    assert_eq!(held, serde_json::json!({"outcome":"held","reason":"loop_guard","expires_at":1}));
    assert!(serde_json::from_str::<DeliveryOutcome>(r#"{"outcome":"delivered","x":1}"#).is_err());
    assert!(serde_json::from_str::<DeliveryOutcome>(r#"{"outcome":"rejected","reason":"nope"}"#).is_err());
}

#[test]
fn tool_args_reject_sender_stamped_fields() {
    let ok: SendMessageArgs = serde_json::from_str(r#"{"to":"a","message":"hi","notify_when_idle":true,"summary":"s"}"#).unwrap();
    assert_eq!(ok.to, "a");
    for field in ["from", "from_mode", "hop", "denied_recently", "from_name"] {
        let v = serde_json::json!({"to":"a","message":"hi", field: "x"});
        assert!(serde_json::from_value::<SendMessageArgs>(v).is_err(), "{field}");
    }
    assert!(serde_json::from_str::<ListAgentsArgs>("{}").is_ok());
    assert!(serde_json::from_str::<ListAgentsArgs>(r#"{"x":1}"#).is_err());
    assert!(serde_json::from_str::<RefusePeerMessageArgs>(r#"{"message_id":"m","reason":"r"}"#).is_ok());
    assert!(serde_json::from_str::<RefusePeerMessageArgs>(r#"{"message_id":"m"}"#).is_err());
}

#[test]
fn limits_match_the_design() {
    assert_eq!(MAX_BODY_BYTES, 32768);
    assert_eq!(MAX_FRAME_BYTES, 65536);
    assert_eq!(HOP_BUDGET, 8);
    assert_eq!(HOLD_EXPIRY_SECS, 300);
    assert_eq!(MAX_TO_BYTES, 512);
    assert_eq!(WATCH_EXPIRY_SECS, 43200);
    assert_eq!(DENIAL_RING, 16);
    const { assert!(MAX_BODY_BYTES < MAX_FRAME_BYTES) };
}

/// Finding 6: each rejection class, and the resolver never routes a failing string as a name.
#[test]
fn display_name_validation_rejects_each_class() {
    let addr_text = addr().to_string();
    let too_long = "a".repeat(MAX_NAME_CHARS + 1);
    let bad: Vec<(&str, String)> = vec![
        ("address", addr_text.clone()),
        ("prefix lower", "fuigo-peer:anything".into()),
        ("prefix upper", "FUIGO-PEER:anything".into()),
        ("prefix mixed", "FuIgO-pEeR:x".into()),
        ("nul", "a\0b".into()),
        ("newline", "a\nb".into()),
        ("tab", "a\tb".into()),
        ("escape", "a\u{1b}[31mb".into()),
        ("del", "a\u{7f}b".into()),
        ("c1", "a\u{85}b".into()),
        ("line sep", "a\u{2028}b".into()),
        ("para sep", "a\u{2029}b".into()),
        ("rlo", "a\u{202E}b".into()),
        ("lre", "a\u{202A}b".into()),
        ("rli", "a\u{2067}b".into()),
        ("pdi", "a\u{2069}b".into()),
        ("lrm", "a\u{200E}b".into()),
        ("alm", "a\u{061C}b".into()),
        ("too long", too_long),
    ];
    for (why, name) in &bad {
        assert!(!is_valid_display_name(name), "accepted ({why})");
        assert!(
            !matches!(resolve_target(name), Ok(Target::Name(_) | Target::NameRef(_))),
            "resolver routed an invalid name ({why})"
        );
        let with_ref = format!("{name} [3f2a9c10]");
        if !name.to_ascii_lowercase().starts_with("fuigo-peer:") {
            assert!(resolve_target(&with_ref).is_err(), "resolver routed `name [ref]` ({why})");
        }
    }
    // At the cap passes; non-ASCII letters pass; the cap counts characters.
    assert!(is_valid_display_name(&"a".repeat(MAX_NAME_CHARS)));
    assert!(is_valid_display_name(&"é".repeat(MAX_NAME_CHARS)));
    assert!(is_valid_display_name("build lane 2 [x]"));
    assert!(is_valid_display_name("my fuigo-peer:x"));
    assert_eq!(resolve_target("build lane").unwrap(), Target::Name("build lane"));
}

/// Finding 7: Debug on every body-holding type prints lengths only.
#[test]
fn debug_never_prints_message_text() {
    let secret = "SECRETTEXT-d41d8cd9";
    let mut e = envelope();
    e.body = format!("body {secret}");
    e.from_name = format!("name {secret}");
    e.from_auto_title = Some(format!("title {secret}"));
    e.message_id = format!("mid {secret}");
    e.denied_recently = vec![DenialStamp { tool_kind: format!("k {secret}"), target_hash: format!("h {secret}") }];
    let s = SendMessageArgs {
        to: format!("to {secret}"),
        message: Some(format!("msg {secret}")),
        notify_when_idle: None,
        summary: Some(format!("sum {secret}")),
    };
    let r = RefusePeerMessageArgs { message_id: format!("m {secret}"), reason: format!("why {secret}") };
    let shown = [
        format!("{e:?}"),
        format!("{:#?}", e),
        format!("{s:?}"),
        format!("{r:?}"),
        format!("{:?}", e.denied_recently[0]),
        format!("{:?}", NameRef { name: secret, reference: "3f2a9c10" }),
        format!("{:?}", Target::Name(secret)),
        format!("{:?}", Target::NameRef(NameRef { name: secret, reference: "3f2a9c10" })),
    ];
    for out in &shown {
        assert!(!out.contains("SECRET") && !out.contains(secret), "leaked: {out}");
    }
    assert!(shown[0].contains("body_len"));
}

fn env_with(f: impl FnOnce(&mut serde_json::Value)) -> serde_json::Result<Envelope> {
    let mut v = serde_json::to_value(envelope()).unwrap();
    f(&mut v);
    serde_json::from_value(v)
}

/// Round 3: a full denial stamp list (128 entries, the longest kind, a real hash) with a maximum body fits one frame.
#[test]
fn p7r3_full_denial_stamp_list_with_maximum_body_fits_a_frame() {
    let mut e = envelope();
    e.body = "a".repeat(MAX_BODY_BYTES);
    e.denied_recently = (0..MAX_DENIAL_STAMPS)
        .map(|i| DenialStamp { tool_kind: "k".repeat(MAX_DENIAL_FIELD_BYTES), target_hash: format!("sha256:{i:016x}") })
        .collect();
    let json = serde_json::to_string(&e).unwrap();
    assert!(json.len() <= MAX_FRAME_BYTES, "{} bytes", json.len());
    assert!(serde_json::from_str::<Envelope>(&json).is_ok());
    assert_eq!(MAX_DENIAL_STAMPS, 128);
    eprintln!("p7r3 full envelope bytes: {}", json.len());
}

/// Finding 8: the caps are enforced on every deserialize, at the cap and one over.
#[test]
fn envelope_caps_hold_at_cap_and_cap_plus_one() {
    let at = |n: usize| "a".repeat(n);
    assert!(env_with(|v| v["body"] = at(MAX_BODY_BYTES).into()).is_ok());
    assert!(env_with(|v| v["body"] = at(MAX_BODY_BYTES + 1).into()).is_err());
    assert!(env_with(|v| v["from_name"] = at(MAX_NAME_CHARS).into()).is_ok());
    assert!(env_with(|v| v["from_name"] = at(MAX_NAME_CHARS + 1).into()).is_err());
    assert!(env_with(|v| v["from_name"] = "".into()).is_ok());
    assert!(env_with(|v| v["from_auto_title"] = at(MAX_NAME_CHARS).into()).is_ok());
    assert!(env_with(|v| v["from_auto_title"] = at(MAX_NAME_CHARS + 1).into()).is_err());
    assert!(env_with(|v| v["from_name"] = addr().to_string().into()).is_err());
    assert!(env_with(|v| v["message_id"] = at(MAX_ID_BYTES).into()).is_ok());
    assert!(env_with(|v| v["message_id"] = at(MAX_ID_BYTES + 1).into()).is_err());
    assert!(env_with(|v| v["conversation_id"] = at(MAX_ID_BYTES + 1).into()).is_err());
    assert!(env_with(|v| v["from_ref"] = at(MAX_ID_BYTES + 1).into()).is_err());
    let stamps = |n: usize| serde_json::json!(vec![serde_json::json!({"tool_kind":"bash","target_hash":"ab"}); n]);
    assert!(env_with(|v| v["denied_recently"] = stamps(MAX_DENIAL_STAMPS)).is_ok());
    assert!(env_with(|v| v["denied_recently"] = stamps(MAX_DENIAL_STAMPS + 1)).is_err());
    let field = |n: usize| serde_json::json!([{"tool_kind": at(n), "target_hash":"ab"}]);
    assert!(env_with(|v| v["denied_recently"] = field(MAX_DENIAL_FIELD_BYTES)).is_ok());
    assert!(env_with(|v| v["denied_recently"] = field(MAX_DENIAL_FIELD_BYTES + 1)).is_err());
    let hash = |n: usize| serde_json::json!([{"tool_kind": "bash", "target_hash": at(n)}]);
    assert!(env_with(|v| v["denied_recently"] = hash(MAX_DENIAL_FIELD_BYTES + 1)).is_err());
    // validate() is what deserialize calls.
    let mut e = envelope();
    assert!(e.validate().is_ok());
    e.body = at(MAX_BODY_BYTES + 1);
    assert!(e.validate().is_err());
}

#[test]
fn tool_arg_caps_hold_at_cap_and_cap_plus_one() {
    let at = |n: usize| "a".repeat(n);
    let send = |msg: usize, sum: usize, to: usize| {
        serde_json::from_value::<SendMessageArgs>(
            serde_json::json!({"to": at(to), "message": at(msg), "summary": at(sum)}),
        )
    };
    assert!(send(MAX_BODY_BYTES, MAX_SUMMARY_BYTES, MAX_TO_BYTES).is_ok());
    assert!(send(MAX_BODY_BYTES + 1, 0, 1).is_err());
    assert!(send(0, MAX_SUMMARY_BYTES + 1, 1).is_err());
    assert!(send(0, 0, MAX_TO_BYTES + 1).is_err());
    let refuse = |reason: usize, id: usize| {
        serde_json::from_value::<RefusePeerMessageArgs>(
            serde_json::json!({"message_id": at(id), "reason": at(reason)}),
        )
    };
    assert!(refuse(MAX_REFUSE_REASON_BYTES, MAX_ID_BYTES).is_ok());
    assert!(refuse(MAX_REFUSE_REASON_BYTES + 1, 1).is_err());
    assert!(refuse(1, MAX_ID_BYTES + 1).is_err());
}

/// Finding 8: unknown fields are rejected on the variants that had no test of their own.
#[test]
fn outcome_variants_and_stamp_reject_unknown_fields() {
    for json in [
        r#"{"outcome":"watching","x":1}"#,
        r#"{"outcome":"unknown","x":1}"#,
        r#"{"outcome":"held","reason":"loop_guard","expires_at":1,"x":1}"#,
        r#"{"outcome":"rejected","reason":"unavailable","x":1}"#,
    ] {
        assert!(serde_json::from_str::<DeliveryOutcome>(json).is_err(), "{json}");
    }
    for json in [
        r#"{"outcome":"watching"}"#,
        r#"{"outcome":"unknown"}"#,
        r#"{"outcome":"held","reason":"loop_guard","expires_at":1}"#,
    ] {
        assert!(serde_json::from_str::<DeliveryOutcome>(json).is_ok(), "{json}");
    }
    assert!(serde_json::from_str::<DenialStamp>(r#"{"tool_kind":"bash","target_hash":"ab","x":1}"#).is_err());
    assert!(serde_json::from_str::<DenialStamp>(r#"{"tool_kind":"bash","target_hash":"ab"}"#).is_ok());
}

/// S7.2: an envelope with no denials has no `denied_recently` key (bytes as before the stamp existed), a stamped one round-trips,
/// and a malformed stamp (unknown key, missing hash, wrong type) is rejected.
#[test]
fn s7_2_stamp_is_absent_when_empty_and_malformed_stamps_are_rejected() {
    let mut e = envelope();
    e.denied_recently.clear();
    let v = serde_json::to_value(&e).unwrap();
    assert!(v.get("denied_recently").is_none());
    let mut e2 = envelope();
    e2.denied_recently = vec![DenialStamp { tool_kind: "bash".into(), target_hash: "sha256:00".into() }];
    let back: Envelope = serde_json::from_value(serde_json::to_value(&e2).unwrap()).unwrap();
    assert_eq!(back.denied_recently, e2.denied_recently);
    let base = serde_json::to_value(&e).unwrap();
    for bad in [
        serde_json::json!([{"tool_kind":"bash"}]),
        serde_json::json!([{"tool_kind":"bash","target_hash":"h","path":"/etc"}]),
        serde_json::json!([{"tool_kind":1,"target_hash":"h"}]),
        serde_json::json!(true),
    ] {
        let mut v = base.clone();
        v["denied_recently"] = bad;
        assert!(serde_json::from_value::<Envelope>(v).is_err());
    }
}
