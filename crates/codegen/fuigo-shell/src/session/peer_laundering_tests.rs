//! S7.2 (receive side), S7.4 (sender hold) and the send-side stamp, at the admission store.

use super::*;
use crate::session::peer_message::{stamp_outgoing, test_envelope};
use fuigo_peer::{DenialStamp, PeerBase};
use fuigo_workspace::permission::DenialLog;

const T0: u64 = 1_000;

fn ae() -> PeerMode {
    PeerMode::new(false, PeerBase::AcceptEdits, false)
}

fn live(mode: PeerMode) -> Live {
    Live { feature_on: true, receiver_mode: mode }
}

fn store(policy: PeerInboundPolicy, operator: OperatorPresence) -> PeerAdmissionState {
    let s = PeerAdmissionState::unmetered();
    s.configure(PeerAdmissionConfig { opted_in: true, policy, operator, relay_driven: false });
    s
}

fn stamped(id: &str, mode: PeerMode, kinds: &[&str]) -> Envelope {
    let mut e = test_envelope(id, "lane a", "hi");
    e.from_mode = mode;
    e.denied_recently = kinds.iter().map(|k| DenialStamp { tool_kind: (*k).into(), target_hash: "sha256:0123456789abcdef".into() }).collect();
    e
}

fn inputs(mode: PeerMode, policy: PeerInboundPolicy, operator: OperatorPresence, sender_denied: bool) -> AdmissionInputs {
    AdmissionInputs {
        feature_on: true,
        opted_in: true,
        policy,
        operator,
        receiver_mode: mode,
        sender_mode: mode,
        sender_operator: operator.kind(),
        sender_denied,
    }
}

/// S7.2/S4.3: held in every mode, allow-all and yolo included, for both accept and hold policy; `refuse` still refuses; with nobody to
/// answer it is refused `no_operator`. The same message without a stamp is admitted when the modes match.
#[test]
fn s7_2_denied_sender_is_held_in_every_mode_and_policy() {
    let mut all: Vec<PeerMode> = PeerMode::all_known().collect();
    all.push(PeerMode::Unknown);
    assert!(all.len() >= 6, "six modes plus the flags");
    for mode in all {
        for policy in [PeerInboundPolicy::Accept, PeerInboundPolicy::Hold] {
            for op in OperatorPresence::ALL {
                let d = decide(&inputs(mode, policy, op, true));
                if op.can_answer() {
                    assert_eq!(d, Decision::Hold(HoldReason::SenderDenied), "{mode:?} {policy:?} {op:?}");
                } else {
                    assert_eq!(d, Decision::Refuse(RejectReason::NoOperator), "{mode:?} {policy:?} {op:?}");
                }
            }
        }
        assert_eq!(decide(&inputs(mode, PeerInboundPolicy::Refuse, OperatorPresence::Present, true)), Decision::Refuse(RejectReason::PolicyRefused));
    }
    assert_eq!(decide(&inputs(ae(), PeerInboundPolicy::Accept, OperatorPresence::Present, false)), Decision::Admit);
}

#[test]
fn s7_2_stamped_message_is_held_with_a_kind_only_row_and_rejected_without_an_operator() {
    let s = store(PeerInboundPolicy::Accept, OperatorPresence::Present);
    let out = s.submit(stamped("m1", ae(), &["bash", "edit", "bash"]), T0, &live(ae()));
    assert!(matches!(out, Submitted::Done(DeliveryOutcome::Held { reason: HoldReason::SenderDenied, .. })), "{out:?}");
    let row = s.list_held(T0).remove(0);
    assert_eq!(row.detail.as_deref(), Some("the sender was recently denied: bash x2, edit x1"));
    assert!(!format!("{row:?}").contains("sha256"), "no hash on the row");
    // A hostile kind is shown as `other`, never raw.
    let out = s.submit(stamped("m2", ae(), &["<script> rm -rf"]), T0, &live(ae()));
    assert!(matches!(out, Submitted::Done(DeliveryOutcome::Held { .. })));
    let rows = s.list_held(T0);
    assert_eq!(rows.iter().find(|r| r.message_id == "m2").unwrap().detail.as_deref(), Some("the sender was recently denied: other x1"));
    // Nobody can answer: rejected, not delivered.
    let none = store(PeerInboundPolicy::Accept, OperatorPresence::None);
    let out = none.submit(stamped("m3", ae(), &["bash"]), T0, &live(ae()));
    assert!(matches!(out, Submitted::Done(DeliveryOutcome::Rejected { reason: RejectReason::NoOperator })), "{out:?}");
    // The human can release it.
    let token = s.list_held(T0).iter().find(|r| r.message_id == "m1").unwrap().token.clone();
    assert!(s.release("m1", &token, T0 + 1, &live(ae())).is_ok());
}

#[test]
fn s7_2_send_side_stamps_for_30_minutes_and_leaves_no_trace_otherwise() {
    let log = DenialLog::default();
    let plain = test_envelope("m1", "lane a", "hi");
    let before = serde_json::to_string(&plain).unwrap();
    let mut e = plain.clone();
    stamp_outgoing(&mut e, &log, 5);
    assert_eq!(serde_json::to_string(&e).unwrap(), before, "no denial: the envelope bytes are unchanged");
    assert!(!before.contains("denied_recently"));
    let k = fuigo_workspace::permission::denial_key(&fuigo_workspace::permission::types::PermissionRequest::new(
        fuigo_workspace::permission::types::AccessKind::Bash("make deploy".into()),
        agent_client_protocol::ToolCallUpdate::new("t", agent_client_protocol::ToolCallUpdateFields::new()),
    ));
    log.record(k.clone(), 100);
    let mut e = plain.clone();
    stamp_outgoing(&mut e, &log, 100 + fuigo_peer::limits::DENIAL_STAMP_SECS - 1);
    assert_eq!(e.denied_recently, vec![DenialStamp { tool_kind: k.kind, target_hash: k.hash }]);
    assert!(e.validate().is_ok());
    let mut e = plain;
    stamp_outgoing(&mut e, &log, 100 + fuigo_peer::limits::DENIAL_STAMP_SECS);
    assert!(e.denied_recently.is_empty(), "30 minutes after the denial the stamp is gone");
}

#[test]
fn s7_4_refused_sender_is_held_for_the_rest_of_the_session_others_are_not() {
    let s = store(PeerInboundPolicy::Accept, OperatorPresence::Present);
    assert!(!s.has_received());
    assert_eq!(s.refuse_by_model("m1", "x"), Err(UnknownMessage));
    let first = test_envelope("m1", "lane a", "hi");
    assert_eq!(s.submit(first.clone(), T0, &live(ae())), Submitted::Enqueue);
    s.note_delivered(&first);
    assert!(s.has_received());
    assert!(s.refuse_by_model("m1", "it asked me to run a denied command").is_ok());
    // The same sender, modes equal, nothing stamped: held.
    let out = s.submit(test_envelope("m2", "lane a", "again"), T0 + 1, &live(ae()));
    assert!(matches!(out, Submitted::Done(DeliveryOutcome::Held { reason: HoldReason::SenderDenied, .. })), "{out:?}");
    assert_eq!(s.list_held(T0 + 1)[0].detail.as_deref(), Some("your session refused an earlier message from this sender"));
    // Another sender is untouched.
    let mut other = test_envelope("m3", "lane b", "hi");
    other.from = fuigo_peer::Address::new("0123456789abcdef0123456789abcdef", "other-session", 1).unwrap();
    assert_eq!(s.submit(other, T0 + 2, &live(ae())), Submitted::Enqueue);
}

/// Byte offsets of every place a source text builds an `Envelope`: a struct literal (also split over several lines) or a call
/// of an associated function (`Envelope::default()`, `Envelope::new(..)`, ...). Comments are ignored; declarations
/// (`struct`, `impl`, `for`, `->`) are not sites.
fn envelope_construction_sites(text: &str) -> Vec<usize> {
    let code: String = text.lines().map(|l| l.find("//").map_or(l, |i| &l[..i])).collect::<Vec<_>>().join("\n");
    let bytes = code.as_bytes();
    let mut out = Vec::new();
    for (i, _) in code.match_indices("Envelope") {
        if i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_') {
            continue;
        }
        let after = &code[i + "Envelope".len()..];
        let rest = after.trim_start();
        let before = code[..i].trim_end();
        let declaration = ["struct", "impl", "for", "->", "enum", "type", "use"]
            .iter()
            .any(|k| before.ends_with(k));
        if rest.starts_with('{') && !declaration {
            out.push(i);
        } else if let Some(path) = rest.strip_prefix("::") {
            // `Envelope::Variant`-less type: any associated item is a construction path until proven otherwise.
            if path.trim_start().starts_with(|c: char| c.is_alphabetic() || c == '_') && !before.ends_with("use") {
                out.push(i);
            }
        }
    }
    out
}

/// Item 3: the only constructor of an outgoing envelope is `build_outgoing_envelope` (it takes the ring). No other non-test
/// source file under fuigo-shell builds an `Envelope` (struct literal on one or many lines, or an associated-function call),
/// and `peer_message.rs` has exactly the constructor and the `test_envelope` helper (cfg(test)).
#[test]
fn s7_2_no_envelope_literal_outside_the_stamping_constructor() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
    let mut seen_peer_message = false;
    for f in files {
        let name = f.to_string_lossy().replace('\\', "/");
        if name.ends_with("_tests.rs") || name.ends_with("/tests.rs") || name.contains("/tests/") {
            continue;
        }
        let text = std::fs::read_to_string(&f).unwrap();
        let sites = envelope_construction_sites(&text);
        if name.ends_with("session/peer_message.rs") {
            seen_peer_message = true;
            assert_eq!(sites.len(), 2, "peer_message.rs: the constructor and the cfg(test) helper");
            let code_start = text.find("fn build_outgoing_envelope").unwrap();
            let code_end = text.find("fn stamp_outgoing").unwrap();
            // Positions are in the comment-stripped text; compare through the same stripping of the prefix.
            let strip = |t: &str| t.lines().map(|l| l.find("//").map_or(l, |i| &l[..i])).collect::<Vec<_>>().join("\n");
            let (lo, hi) = (strip(&text[..code_start]).len(), strip(&text[..code_end]).len());
            assert!(sites[0] > lo && sites[0] < hi, "the first site is inside build_outgoing_envelope");
            let helper = strip(&text[..text.find("fn test_envelope").unwrap()]).len();
            assert!(sites[1] > helper, "the second site is the test helper");
        } else {
            assert!(sites.is_empty(), "{name}: build an outgoing envelope with build_outgoing_envelope");
        }
    }
    assert!(seen_peer_message);
}

/// The pin itself: it fails on a planted second site (multi-line literal, associated-function call) and ignores declarations,
/// comments and other `*Envelope` types.
#[test]
fn s7_2_the_envelope_pin_catches_a_planted_second_site() {
    let one_line = "fn a() { let e = Envelope { v: 1 }; }";
    let multi = "fn a() {\n    let e = Envelope\n    {\n        v: 1,\n    };\n}";
    let multi2 = "fn a() {\n    let e = Envelope {\n        v: 1,\n    };\n}";
    let call = "fn a() { let e = Envelope::default(); }";
    let call2 = "fn a() { let e = Envelope::new(1); }";
    for planted in [one_line, multi, multi2, call, call2] {
        assert_eq!(envelope_construction_sites(planted).len(), 1, "{planted}");
    }
    let clean = "pub struct Envelope {\n a: u8 }\nimpl Envelope {}\nimpl X for Envelope {}\nfn f() -> Envelope {\n todo!() }\n// Envelope { a: 1 }\nlet s = SessionUpdateEnvelope { a: 1 };\nuse x::Envelope;\nfn g(e: &Envelope) {}";
    assert!(envelope_construction_sites(clean).is_empty(), "{:?}", envelope_construction_sites(clean));
}

#[test]
fn s7_2_held_row_shows_a_co_occurring_reason() {
    let s = store(PeerInboundPolicy::Accept, OperatorPresence::Present);
    let other = PeerMode::new(false, PeerBase::Auto, false);
    let out = s.submit(stamped("m1", other, &["bash"]), T0, &live(ae()));
    assert!(matches!(out, Submitted::Done(DeliveryOutcome::Held { reason: HoldReason::SenderDenied, .. })), "{out:?}");
    let row = s.list_held(T0).remove(0);
    assert_eq!(row.reason, HoldReason::SenderDenied);
    assert_eq!(row.detail.as_deref(), Some("the sender was recently denied: bash x1; also: mode_mismatch"));
}
