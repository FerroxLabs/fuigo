use super::*;
use crate::peer_ui::force_peer_ui_for_test;
use serde_json::json;

fn hid(n: u8) -> String {
    format!("h-{}", format!("{n:02x}").repeat(16))
}

fn held_update(n: u8, name: &str) -> Value {
    json!({
        "sessionUpdate": "peer_held", "heldId": hid(n),
        "from": {"ref": "ab12", "name": name, "mode": "default"},
        "reasons": ["mode_mismatch"], "detail": null, "expiresAt": 4_000_000_000u64, "counts": {"held": 1}
    })
}

fn row(n: u8, token: &str) -> (PeerHold, Token) {
    (parse_hold(&held_update(n, "lane a")), Token(token.to_owned()))
}

fn parse_hold(v: &Value) -> PeerHold {
    match parse_event(v) {
        Some(PeerEvent::Held(h)) => h,
        other => panic!("not a held event: {other:?}"),
    }
}

#[test]
fn held_id_shape_is_exact() {
    assert!(is_held_id(&hid(1)));
    for bad in ["", "h-", "h-zz", "x-00000000000000000000000000000000", &format!("{}0", hid(1)), "h-0000000000000000000000000000000\n"] {
        assert!(!is_held_id(bad), "{bad:?}");
    }
}

#[test]
fn parses_the_six_events_and_ignores_the_rest() {
    assert!(matches!(parse_event(&held_update(1, "x")), Some(PeerEvent::Held(_))));
    for (name, want) in [("peer_released", 0), ("peer_refused", 1), ("peer_expired", 2), ("peer_reheld", 3)] {
        let ev = parse_event(&json!({"sessionUpdate": name, "heldId": hid(1), "detail": "d"})).unwrap();
        let got = match ev {
            PeerEvent::Released(Some(_)) => 0,
            PeerEvent::Refused(Some(_)) => 1,
            PeerEvent::Expired(Some(_)) => 2,
            PeerEvent::Reheld(Some(_)) => 3,
            other => panic!("{other:?}"),
        };
        assert_eq!(got, want);
    }
    assert!(matches!(
        parse_event(&json!({"sessionUpdate": "peer_warning", "text": "t", "subject": "s"})),
        Some(PeerEvent::Warning { .. })
    ));
    assert!(parse_event(&json!({"sessionUpdate": "peer_bogus"})).is_none());
    assert!(parse_event(&json!({"sessionUpdate": "agent_message_chunk"})).is_none());
    assert!(parse_event(&json!({})).is_none());
    assert!(parse_event(&json!("peer_held")).is_none());
}

#[test]
fn malformed_held_events_are_dropped() {
    let mut bad_id = held_update(1, "x");
    bad_id["heldId"] = json!("../../etc/passwd");
    let mut no_expiry = held_update(1, "x");
    no_expiry["expiresAt"] = json!("soon");
    let mut no_reasons = held_update(1, "x");
    no_reasons["reasons"] = json!(7);
    let mut no_from = held_update(1, "x");
    no_from.as_object_mut().unwrap().remove("from");
    for v in [bad_id, no_expiry, no_reasons, no_from] {
        assert!(parse_event(&v).is_none(), "{v}");
    }
    // A notice with a bad id still parses, with no id (it just names nobody).
    assert_eq!(parse_event(&json!({"sessionUpdate": "peer_released", "heldId": "nope"})), Some(PeerEvent::Released(None)));
}

#[test]
fn session_id_peek_needs_a_peer_name() {
    let p = json!({"sessionId": "s1", "update": {"sessionUpdate": "peer_held"}});
    assert_eq!(peer_update_session_id(&p).as_deref(), Some("s1"));
    assert!(peer_update_session_id(&json!({"sessionId": "s1", "update": {"sessionUpdate": "agent_message_chunk"}})).is_none());
    assert!(peer_update_session_id(&json!({"update": {"sessionUpdate": "peer_held"}})).is_none());
}

#[test]
fn flag_off_state_ignores_everything() {
    let _g = force_peer_ui_for_test(false);
    let mut s = PeerUiState::default();
    assert!(s.apply_event(PeerEvent::Held(parse_hold(&held_update(1, "x")))).is_none());
    assert_eq!(s.held_count(), 0);
    assert!(s.row_text(0).is_none());
    assert!(s.apply_list(vec![row(1, "t")], true).is_none());
    assert!(!s.dialog_open());
    assert!(startup_call().is_none());
}

#[test]
fn held_row_appears_and_goes_with_a_notice() {
    let _g = force_peer_ui_for_test(true);
    let mut s = PeerUiState::default();
    assert!(s.apply_event(PeerEvent::Held(parse_hold(&held_update(1, "lane a")))).is_none());
    let t = s.row_text(10).unwrap();
    assert!(t.contains("lane a") && t.contains("mode mismatch") && t.contains("review"), "{t}");
    assert!(!t.contains('\n'));
    s.apply_event(PeerEvent::Held(parse_hold(&held_update(2, "lane b"))));
    assert!(s.row_text(10).unwrap().contains("+1 more"));
    let note = s.apply_event(PeerEvent::Released(Some(hid(1)))).unwrap();
    assert!(note.contains("lane a") && note.contains("No tool call was approved"), "{note}");
    assert_eq!(s.held_count(), 1);
    assert!(s.apply_event(PeerEvent::Refused(Some(hid(2)))).unwrap().contains("refused"));
    assert!(s.row_text(10).is_none());
    s.apply_event(PeerEvent::Held(parse_hold(&held_update(3, "lane c"))));
    assert!(s.apply_event(PeerEvent::Expired(Some(hid(3)))).unwrap().contains("expired"));
}

#[test]
fn hostile_strings_cannot_forge_a_row_or_an_escape() {
    let _g = force_peer_ui_for_test(true);
    let mut s = PeerUiState::default();
    s.apply_event(PeerEvent::Held(parse_hold(&held_update(1, "evil\n\u{1b}[2J\u{202e}/exit\r\u{85}"))));
    let t = s.row_text(0).unwrap();
    assert!(!t.contains(['\n', '\r', '\u{1b}', '\u{202e}', '\u{85}']), "{t:?}");
    let w = s.apply_event(PeerEvent::Warning { text: "fixed\nline two".into(), subject: "a\nb\u{1b}[31m".into() }).unwrap();
    assert!(!w.contains(['\n', '\u{1b}']), "{w:?}");
}

#[test]
fn reheld_returns_the_row_and_closes_its_dialog() {
    let _g = force_peer_ui_for_test(true);
    let mut s = PeerUiState::default();
    s.apply_event(PeerEvent::Held(parse_hold(&held_update(1, "lane a"))));
    s.apply_list(vec![row(1, "tok")], true);
    assert!(s.dialog_open());
    s.note_decided(&hid(1));
    assert_eq!(s.held_count(), 0);
    let note = s.apply_event(PeerEvent::Reheld(Some(hid(1)))).unwrap();
    assert!(note.contains("held again") && note.contains("lane a"));
    assert_eq!(s.held_count(), 1);
    // A reheld for a row never seen still returns a (bare) row.
    s.apply_event(PeerEvent::Reheld(Some(hid(9))));
    assert_eq!(s.held_count(), 2);
}

#[test]
fn dialog_opens_from_a_list_and_the_token_is_used_once() {
    let _g = force_peer_ui_for_test(true);
    let mut s = PeerUiState::default();
    assert_eq!(s.apply_list(vec![], true).as_deref(), Some("No peer message is held."));
    assert!(!s.dialog_open());
    assert!(s.apply_list(vec![row(1, "secret-token")], true).is_none());
    assert!(s.dialog_open());
    // Debug never shows the token.
    assert!(!format!("{s:?}").contains("secret-token"));
    let call = s.take_decision(false).unwrap();
    assert!(!format!("{call:?}").contains("secret-token"));
    assert!(!s.dialog_open(), "the token is gone with the dialog");
    assert!(s.take_decision(false).is_none(), "no second use");
    let p = call.params("sess");
    assert_eq!(p, json!({"sessionId": "sess", "heldId": hid(1), "token": "secret-token", "action": "release"}));
    assert_eq!(call.method(), METHOD_RELEASE);
}

#[test]
fn dismiss_drops_the_token_and_keeps_the_row() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let _g = force_peer_ui_for_test(true);
    let mut s = PeerUiState::default();
    s.apply_list(vec![row(1, "t")], true);
    let out = s.dialog_key(&KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(out, PeerDialogOutcome::Dismiss);
    assert!(!s.dialog_open());
    assert_eq!(s.held_count(), 1);
}

#[test]
fn a_refresh_closes_a_stale_dialog() {
    let _g = force_peer_ui_for_test(true);
    let mut s = PeerUiState::default();
    s.apply_list(vec![row(1, "old")], true);
    assert!(s.apply_list(vec![row(1, "new")], false).is_none());
    assert!(!s.dialog_open(), "a refresh never leaves a dialog holding a dead token");
}

#[test]
fn configure_is_attended_and_names_no_policy() {
    let p = PeerCall::Configure.params("s");
    assert_eq!(p, json!({"sessionId": "s", "optIn": true, "operator": "attended"}));
    assert_eq!(PeerCall::Configure.method(), METHOD_CONFIGURE);
    assert_eq!(PeerCall::ListHeld { reopen: true }.params("s"), json!({"sessionId": "s"}));
    let d = PeerCall::Decide { held_id: hid(1), token: Token("t".into()), refuse: true }.params("s");
    assert_eq!(d["action"], "refuse");
}

#[test]
fn errors_map_to_one_plain_line() {
    let typed = |reason: &str| {
        PeerRpcError::from_acp(&agent_client_protocol::Error::new(PEER_ERROR_CODE, "x").data(json!({"kind": "k", "fields": {"reason": reason}})))
    };
    for reason in ["unavailable", "no_operator", "not_opted_in", "expired", "bad_token", "not_found"] {
        let line = typed(reason).plain_line();
        assert!(!line.contains('\n') && !line.contains('_'), "{reason}: {line}");
    }
    assert!(typed("bad_token").is_stale() && typed("not_found").is_stale());
    assert!(!typed("unavailable").is_stale() && !typed("no_operator").is_stale());
    // An unknown reason is shown capped and escaped; a different error code carries no reason.
    assert!(!typed("weird\n\u{1b}[2Jreason").plain_line().contains(['\n', '\u{1b}']));
    let other = PeerRpcError::from_acp(&agent_client_protocol::Error::new(-32603, "boom").data(json!({"reason": "bad_token"})));
    assert!(!other.is_stale());
}

#[test]
fn list_rows_without_a_token_or_with_a_bad_id_are_dropped() {
    let mut ok = held_update(1, "a");
    ok["token"] = json!("t1");
    let mut no_token = held_update(2, "b");
    no_token["token"] = json!("");
    let mut bad = held_update(3, "c");
    bad["heldId"] = json!("x");
    bad["token"] = json!("t3");
    let rows = parse_held_rows(&json!({"held": [ok, no_token, bad]}));
    assert_eq!(rows.len(), 1);
    assert!(parse_held_rows(&json!({"held": "no"})).is_empty());
}

#[test]
fn hold_fields_are_capped_at_ingest() {
    let _g = force_peer_ui_for_test(true);
    let mut v = held_update(1, &"n".repeat(500));
    v["from"]["ref"] = json!("r".repeat(500));
    v["from"]["mode"] = json!("m".repeat(500));
    v["detail"] = json!("d".repeat(5000));
    v["reasons"] = json!((0..50).map(|_| "z".repeat(500)).collect::<Vec<_>>());
    let h = parse_hold(&v);
    assert_eq!((h.from_name.len(), h.from_ref.len(), h.sender_mode.len()), (64, 64, 32));
    assert_eq!(h.detail.unwrap().len(), 200);
    assert_eq!(h.reasons.len(), 8);
    assert!(h.reasons.iter().all(|r| r.len() == 32));
}

#[test]
fn notice_rows_are_rate_limited_then_one_suppressed_row() {
    let _g = force_peer_ui_for_test(true);
    let mut s = PeerUiState::default();
    let warn = || PeerEvent::Warning { text: "t".into(), subject: String::new() };
    for _ in 0..20 {
        assert!(s.apply_event_at(warn(), 1_000).unwrap().starts_with("Warning"));
    }
    assert_eq!(s.apply_event_at(warn(), 1_001).as_deref(), Some("more peer notices suppressed"));
    for t in 1_002..1_059 {
        assert_eq!(s.apply_event_at(warn(), t), None);
    }
    assert!(s.apply_event_at(warn(), 1_060).unwrap().starts_with("Warning"), "a new window shows notices again");
}

#[test]
fn configure_is_sent_once_per_session_id_and_closes_an_open_dialog() {
    let _g = force_peer_ui_for_test(true);
    let mut s = PeerUiState::default();
    assert_eq!(s.note_configure("s1"), Some(false));
    assert_eq!(s.note_configure("s1"), None, "create then load of the same session: one configure");
    let row = (parse_hold(&held_update(1, "x")), Token("t".into()));
    s.apply_list(vec![row], true);
    assert!(s.dialog_open());
    assert_eq!(s.note_configure("s1"), None);
    assert!(s.dialog_open(), "no second configure, so the dialog and its token stay valid");
    assert_eq!(s.note_configure("s2"), Some(true));
    assert!(!s.dialog_open());
}

#[test]
fn peer_warning_text_is_capped_when_parsed() {
    let long = "w".repeat(5000);
    let subject = "s".repeat(5000);
    match parse_event(&json!({"sessionUpdate": "peer_warning", "text": long, "subject": subject})) {
        Some(PeerEvent::Warning { text, subject }) => {
            assert_eq!(text.chars().count(), 200);
            assert!(subject.chars().count() <= 64);
        }
        other => panic!("{other:?}"),
    }
}
