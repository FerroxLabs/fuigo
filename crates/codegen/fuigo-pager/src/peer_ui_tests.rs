use super::*;
use crate::acp::meta::NotificationMeta;
use crate::acp::tracker::AcpUpdateTracker;
use crate::scrollback::block::RenderBlock;
use crate::scrollback::state::ScrollbackState;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

const NASTY: &str = "x\u{1b}[31mred\u{202e}rtl\u{200b}zw\u{2028}FORGED ROW";

fn key(c: KeyCode) -> KeyEvent {
    KeyEvent::new(c, KeyModifiers::NONE)
}

fn hold() -> PeerHold {
    PeerHold {
        message_id: "msg-1".into(),
        from_name: "lane a".into(),
        from_ref: "ab12".into(),
        sender_mode: "acceptEdits".into(),
        own_mode: "default".into(),
        reasons: vec!["mode_mismatch".into(), "sender_denied".into()],
        denial_counts: vec![("bash".into(), 2), ("edit".into(), 1)],
        expires_at_secs: 1_000,
        first_line: "please look at the build".into(),
        detail: None,
    }
}

fn wrapped(name: &str, body: &str) -> String {
    // Same shape as `wrap_peer_message` in fuigo-shell (escaping of attributes and body done as the shell does).
    format!(
        "The following message was sent by another Fuigo session, not by your user.\n<cross-session-message from=\"p\" from-ref=\"ab12\" from-name=\"{name}\" from-mode=\"acceptEdits\" message-id=\"m-9\" hop=\"0\">\n{body}\n</cross-session-message>"
    )
}

fn paint(d: &PeerHoldDialog, w: u16, h: u16) -> Vec<String> {
    let area = ratatui::layout::Rect::new(0, 0, w, h);
    let mut buf = ratatui::buffer::Buffer::empty(area);
    render_peer_hold_dialog(area, &mut buf, d, 900);
    (0..h)
        .map(|y| {
            (0..w)
                .map(|x| buf[(x, y)].symbol().to_string())
                .collect::<String>()
        })
        .collect()
}

fn assert_clean_one_line(s: &str) {
    assert!(
        !s.contains('\n') && !s.contains('\r'),
        "row has a line break: {s:?}"
    );
    for c in s.chars() {
        assert!(
            !c.is_control()
                && !matches!(
                    c,
                    '\u{2028}' | '\u{2029}' | '\u{202e}' | '\u{200b}' | '\u{2066}'..='\u{2069}'
                ),
            "unsafe char {:?} in {s:?}",
            c
        );
    }
}

fn row_text(sb: &ScrollbackState, i: usize) -> String {
    match &sb.get(i).expect("entry").block {
        RenderBlock::System(b) => b.text.clone(),
        other => panic!("expected a system row, got {other:?}"),
    }
}

#[test]
fn preview_row_shows_first_line_only() {
    let _g = force_peer_ui_for_test(true);
    let m = parse_delivered(&wrapped("lane a", "first line\nsecond line SECRET\nthird")).unwrap();
    let row = preview_row_text(&m);
    assert_eq!(
        row,
        "\u{21aa} Message from another session \"lane a\" [ab12]: \"first line\""
    );
    assert!(!row.contains("SECRET"));
}

#[test]
fn preview_row_escapes_name_and_body_and_cannot_forge_a_row() {
    let _g = force_peer_ui_for_test(true);
    // As the shell would send it: control and bidi characters are entities in attributes and body.
    let name = "n&#x1B;&#x202E;&#x2028;ame";
    let body = "hi&#x1B;[2J&#x202E;&#x2028;FORGED&#x200B;\nreal second line";
    let m = parse_delivered(&wrapped(name, body)).unwrap();
    let row = preview_row_text(&m);
    assert_clean_one_line(&row);
    assert!(!row.contains("second line"));
    // And as a raw (hostile) value that bypassed the shell wrapper.
    let raw = DeliveredPeerMessage {
        from_name: NASTY.into(),
        from_ref: NASTY.into(),
        message_id: "m".into(),
        body_first_line: NASTY.into(),
    };
    assert_clean_one_line(&preview_row_text(&raw));
}

#[test]
fn first_line_cuts_at_every_line_break_kind() {
    for sep in ["\n", "\r", "\u{2028}", "\u{2029}", "\u{85}"] {
        let s = first_line_field(&format!("one{sep}two"));
        assert!(s.contains("one") && !s.contains("two"), "{sep:?} -> {s}");
    }
}

#[test]
fn long_text_is_capped() {
    let _g = force_peer_ui_for_test(true);
    let long = "a".repeat(5_000);
    let m = DeliveredPeerMessage {
        from_name: long.clone(),
        from_ref: long.clone(),
        message_id: "m".into(),
        body_first_line: long,
    };
    let row = preview_row_text(&m);
    assert!(
        row.chars().count() < 260,
        "row not capped: {}",
        row.chars().count()
    );
    assert_clean_one_line(&row);
}

#[test]
fn held_row_has_reasons_kinds_counts_and_expiry() {
    let _g = force_peer_ui_for_test(true);
    let row = held_row_text(&hold(), 900);
    assert_eq!(
        row,
        "\u{23f8} A message from \"lane a\" [ab12] is held: mode mismatch, sender denied; the sender was recently denied: \"bash\" x2, \"edit\" x1; expires in 100s"
    );
    assert!(held_row_text(&hold(), 1_000).ends_with("expired"));
    let mut h = hold();
    h.from_name = NASTY.into();
    h.reasons = vec![NASTY.into()];
    h.denial_counts = vec![(NASTY.into(), 3)];
    assert_clean_one_line(&held_row_text(&h, 0));
}

#[test]
fn notices_are_fixed_text_plus_escaped_names() {
    let _g = force_peer_ui_for_test(true);
    for n in [
        PeerNotice::Delivered { name: NASTY.into() },
        PeerNotice::Released { name: NASTY.into() },
        PeerNotice::Refused {
            name: NASTY.into(),
            told: true,
        },
        PeerNotice::Expired { name: NASTY.into() },
        PeerNotice::IntegrityWarning { path: NASTY.into() },
        PeerNotice::LaunderingRefused { name: NASTY.into() },
    ] {
        let t = notice_row_text(&n).unwrap();
        assert_clean_one_line(&t);
        assert!(
            !t.starts_with("x"),
            "a peer string must not be the whole row: {t}"
        );
    }
    assert!(
        notice_row_text(&PeerNotice::Released { name: "a".into() })
            .unwrap()
            .contains("No tool call was approved.")
    );
}

#[test]
fn influence_marker_shows_only_while_influenced() {
    let _g = force_peer_ui_for_test(true);
    assert_eq!(
        influence_marker_text(true).as_deref(),
        Some("peer-influenced  /peers clear-influence")
    );
    assert_eq!(influence_marker_text(false), None);
}

#[test]
fn dialog_lines_snapshot() {
    let _g = force_peer_ui_for_test(true);
    let d = PeerHoldDialog::open(hold()).unwrap();
    assert_eq!(
        d.lines(900, 90).join("\n"),
        "From: \"lane a\" [ab12]\n\
         Sender mode (its claim): \"acceptEdits\"\n\
         This session's mode: \"default\"\n\
         Held because: mode mismatch, sender denied\n\
         Note: the sender was recently denied: \"bash\" x2, \"edit\" x1\n\
         Starts: \"please look at the build\"\n\
         expires in 100s\n\
         Accepting delivers the message to this session.\n\
         It does not approve any tool call.\n\
         [a] accept  [r] refuse  [Esc] dismiss (stays held)"
    );
}

#[test]
fn dialog_escapes_hostile_fields() {
    let _g = force_peer_ui_for_test(true);
    let mut h = hold();
    h.from_name = NASTY.into();
    h.from_ref = NASTY.into();
    h.sender_mode = NASTY.into();
    h.own_mode = NASTY.into();
    h.first_line = NASTY.into();
    h.reasons = vec![NASTY.into()];
    h.denial_counts = vec![(NASTY.into(), 1)];
    let d = PeerHoldDialog::open(h).unwrap();
    let lines = d.lines(0, 90);
    assert_eq!(lines.len(), 10);
    for l in &lines {
        assert_clean_one_line(l);
    }
}

#[test]
fn dialog_keys_choose_release_or_refuse_and_nothing_else() {
    let _g = force_peer_ui_for_test(true);
    let mut d = PeerHoldDialog::open(hold()).unwrap();
    paint(&d, 100, 30);
    assert_eq!(
        d.handle_key(&key(KeyCode::Char('a'))),
        PeerDialogOutcome::Release
    );
    assert_eq!(
        d.handle_key(&key(KeyCode::Char('r'))),
        PeerDialogOutcome::Refuse
    );
    assert_eq!(d.handle_key(&key(KeyCode::Esc)), PeerDialogOutcome::Dismiss);
    assert_eq!(
        d.handle_key(&key(KeyCode::Char('d'))),
        PeerDialogOutcome::Dismiss
    );
    // Anything else (Enter, y, digits, ctrl-a) sends nothing: no stray key releases or approves.
    for k in [
        key(KeyCode::Enter),
        key(KeyCode::Char('y')),
        key(KeyCode::Char('1')),
        KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL),
    ] {
        assert_eq!(d.handle_key(&k), PeerDialogOutcome::Ignored);
    }
}

#[test]
fn dialog_refuses_an_id_that_is_not_a_plain_token() {
    let _g = force_peer_ui_for_test(true);
    for bad in ["", "a b", "x\n/yolo", "id;rm", "a\u{202e}b"] {
        let mut h = hold();
        h.message_id = bad.into();
        assert!(PeerHoldDialog::open(h).is_none(), "{bad:?}");
    }
}

#[test]
fn expiry_closes_the_dialog_to_an_expired_state() {
    let _g = force_peer_ui_for_test(true);
    let mut d = PeerHoldDialog::open(hold()).unwrap();
    assert!(!d.tick(999));
    assert!(d.tick(1_000));
    assert!(d.is_expired());
    assert!(
        d.lines(1_000, 90)
            .contains(&"This hold has expired.".to_owned())
    );
    assert_eq!(
        d.handle_key(&key(KeyCode::Char('a'))),
        PeerDialogOutcome::Ignored
    );
    assert_eq!(
        d.handle_key(&key(KeyCode::Char('r'))),
        PeerDialogOutcome::Ignored
    );
    assert_eq!(d.handle_key(&key(KeyCode::Esc)), PeerDialogOutcome::Dismiss);
}

#[test]
fn dialog_paints_into_a_buffer() {
    let _g = force_peer_ui_for_test(true);
    let d = PeerHoldDialog::open(hold()).unwrap();
    let area = ratatui::layout::Rect::new(0, 0, 100, 24);
    let mut buf = ratatui::buffer::Buffer::empty(area);
    render_peer_hold_dialog(area, &mut buf, &d, 900);
    let text: String = (0..area.height)
        .map(|y| {
            (0..area.width)
                .map(|x| buf[(x, y)].symbol().to_string())
                .collect::<String>()
                + "\n"
        })
        .collect();
    assert!(text.contains("It does not approve any tool call."));
    assert!(text.contains("[a] accept"));
}

#[test]
fn flag_off_no_row_no_notice_no_marker_no_dialog() {
    let _g = force_peer_ui_for_test(false);
    assert_eq!(preview_row_for_wrapped(&wrapped("lane a", "hello")), None);
    assert_eq!(
        notice_row_text(&PeerNotice::Delivered { name: "a".into() }),
        None
    );
    assert_eq!(influence_marker_text(true), None);
    assert!(PeerHoldDialog::open(hold()).is_none());
}

fn user_chunk(text: &str) -> agent_client_protocol::SessionUpdate {
    agent_client_protocol::SessionUpdate::UserMessageChunk(
        agent_client_protocol::ContentChunk::new(agent_client_protocol::ContentBlock::Text(
            agent_client_protocol::TextContent::new(text.to_string()),
        )),
    )
}

#[test]
fn tracker_turns_a_delivered_peer_message_into_one_preview_row() {
    let _g = force_peer_ui_for_test(true);
    let mut sb = ScrollbackState::new();
    let mut tracker = AcpUpdateTracker::new();
    let meta = NotificationMeta {
        prompt_id: Some("peer-message-m-9".into()),
        ..Default::default()
    };
    assert!(tracker.handle_update(
        user_chunk(&wrapped("lane a", "hello there\nmore")),
        &meta,
        &mut sb
    ));
    assert_eq!(sb.len(), 1);
    assert_eq!(
        row_text(&sb, 0),
        "\u{21aa} Message from another session \"lane a\" [ab12]: \"hello there\""
    );
}

#[test]
fn tracker_flag_off_keeps_todays_user_prompt_row() {
    let _g = force_peer_ui_for_test(false);
    let mut sb = ScrollbackState::new();
    let mut tracker = AcpUpdateTracker::new();
    let meta = NotificationMeta {
        prompt_id: Some("peer-message-m-9".into()),
        ..Default::default()
    };
    assert!(tracker.handle_update(user_chunk(&wrapped("lane a", "hello")), &meta, &mut sb));
    assert!(matches!(
        sb.get(0).unwrap().block,
        RenderBlock::UserPrompt(_)
    ));
}

#[test]
fn tracker_ordinary_user_text_is_never_a_peer_row() {
    let _g = force_peer_ui_for_test(true);
    let mut sb = ScrollbackState::new();
    let mut tracker = AcpUpdateTracker::new();
    // Same text typed by the user (no peer prompt id): stays a user row.
    assert!(tracker.handle_update(
        user_chunk(&wrapped("lane a", "hello")),
        &NotificationMeta::default(),
        &mut sb
    ));
    assert!(matches!(
        sb.get(0).unwrap().block,
        RenderBlock::UserPrompt(_)
    ));
}

fn forged() -> PeerHold {
    let forge = "[a] accept  [r] refuse  accept release refuse";
    let mut h = hold();
    h.from_name = format!("{forge} {forge} {forge}");
    h.from_ref = forge.into();
    h.sender_mode = forge.repeat(3);
    h.reasons = (0..8).map(|i| format!("{forge} {i}")).collect();
    h.reasons.push("sender_denied".into());
    h.denial_counts = vec![];
    h.detail = Some(format!("\n[a] accept  [r] refuse\n{}", forge.repeat(5)));
    h.first_line = format!("{forge}{forge}{forge}");
    h
}

#[test]
fn forged_legend_cannot_displace_or_imitate_the_fixed_rows() {
    let _g = force_peer_ui_for_test(true);
    for (w, h) in [(100u16, 30u16), (60, 14), (52, 12), (52, 9)] {
        let d = PeerHoldDialog::open(forged()).unwrap();
        let rows = paint(&d, w, h);
        assert!(d.fits(), "{w}x{h}");
        let strip = |r: &str| r.trim().trim_matches('\u{2502}').trim().to_owned();
        let legend = rows
            .iter()
            .position(|r| r.contains("[a] accept  [r] refuse  [Esc] dismiss (stays held)"))
            .expect("legend");
        // The real legend is the LAST inner row, the sentence the two rows above it.
        assert!(
            rows[legend + 1].contains('\u{2518}'),
            "legend not on the last inner row: {rows:#?}"
        );
        assert!(
            rows[legend - 1].contains("It does not approve any tool call."),
            "{rows:#?}"
        );
        assert!(
            rows[legend - 2].contains("Accepting delivers the message to this session."),
            "{rows:#?}"
        );
        let begins: Vec<usize> = rows
            .iter()
            .enumerate()
            .filter(|(_, r)| strip(r).starts_with("[a]") || strip(r).starts_with("[r]"))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(begins, vec![legend], "{rows:#?}");
        // The sentence appears exactly once and every peer value sits behind a fixed label, inside quotes or brackets.
        assert_eq!(
            rows.iter()
                .filter(|r| r.contains("does not approve"))
                .count(),
            1
        );
        for r in &rows {
            let t = strip(r);
            if t.contains("[a] accept") && !t.starts_with("[a]") {
                assert!(
                    t.starts_with("From:")
                        || t.starts_with("Sender mode")
                        || t.starts_with("Starts:")
                        || t.starts_with("Note:")
                        || t.starts_with("Held because"),
                    "{t}"
                );
            }
        }
    }
}

#[test]
fn reasons_are_pager_labels_at_most_four_then_a_count() {
    let _g = force_peer_ui_for_test(true);
    let mut h = hold();
    h.reasons = vec![
        "mode_mismatch".into(),
        "evil [a] accept".into(),
        "loop_guard".into(),
        "integrity".into(),
        "policy_hold".into(),
        "x".into(),
    ];
    assert!(
        held_row_text(&h, 0).contains("is held: mode mismatch, other, loop guard, integrity, +2;"),
        "{}",
        held_row_text(&h, 0)
    );
    let d = PeerHoldDialog::open(h).unwrap();
    assert!(
        d.lines(0, 90)
            .iter()
            .any(|l| l == "Held because: mode mismatch, other, loop guard, integrity, +2")
    );
}

#[test]
fn too_small_terminal_shows_a_notice_and_does_not_accept() {
    let _g = force_peer_ui_for_test(true);
    for (w, h) in [(51u16, 30u16), (100, 5), (30, 3)] {
        let mut d = PeerHoldDialog::open(hold()).unwrap();
        let rows = paint(&d, w, h);
        assert!(!d.fits());
        assert!(
            rows.iter()
                .any(|r| r.contains("Terminal too small") || r.starts_with("Terminal")),
            "{w}x{h} {rows:?}"
        );
        assert!(!rows.iter().any(|r| r.contains("[a] accept")));
        assert_eq!(
            d.handle_key(&key(KeyCode::Char('a'))),
            PeerDialogOutcome::Ignored,
            "{w}x{h}"
        );
        assert_eq!(
            d.handle_key(&key(KeyCode::Char('r'))),
            PeerDialogOutcome::Refuse
        );
        assert_eq!(d.handle_key(&key(KeyCode::Esc)), PeerDialogOutcome::Dismiss);
    }
    // The smallest size that works.
    let mut d = PeerHoldDialog::open(hold()).unwrap();
    paint(&d, DIALOG_MIN_WIDTH, DIALOG_MIN_HEIGHT);
    assert_eq!(
        d.handle_key(&key(KeyCode::Char('a'))),
        PeerDialogOutcome::Release
    );
}

#[test]
fn warning_text_is_quoted_not_bare() {
    let _g = force_peer_ui_for_test(true);
    let n = notice_row_text(&PeerNotice::Warning {
        text: "[a] accept".into(),
        subject: "s".into(),
    })
    .unwrap();
    assert_eq!(n, "Warning from a peer notice: \"[a] accept\" about \"s\"");
}

// ---- Round 3 ----

#[test]
fn a_waits_for_a_fresh_frame_and_a_resize_clears_it() {
    let _g = force_peer_ui_for_test(true);
    let mut d = PeerHoldDialog::open(hold()).unwrap();
    assert_eq!(
        d.handle_key(&key(KeyCode::Char('a'))),
        PeerDialogOutcome::Ignored,
        "never painted"
    );
    paint(&d, 100, 30);
    assert!(d.fits());
    d.begin_frame();
    assert_eq!(
        d.handle_key(&key(KeyCode::Char('a'))),
        PeerDialogOutcome::Ignored,
        "new frame, nothing painted yet"
    );
    paint(&d, 100, 30);
    d.note_screen_disturbed();
    assert_eq!(
        d.handle_key(&key(KeyCode::Char('a'))),
        PeerDialogOutcome::Ignored,
        "resize since the last paint"
    );
    paint(&d, 100, 30);
    assert_eq!(
        d.handle_key(&key(KeyCode::Char('a'))),
        PeerDialogOutcome::Release
    );
}

/// The fixed rows must fit inside the rect actually used: an area larger than the buffer that is flushed proves nothing.
#[test]
fn a_dialog_that_does_not_fit_the_flushed_buffer_is_not_accepted() {
    let _g = force_peer_ui_for_test(true);
    let mut d = PeerHoldDialog::open(hold()).unwrap();
    let area = ratatui::layout::Rect::new(0, 0, 100, 30);
    let mut buf = ratatui::buffer::Buffer::empty(ratatui::layout::Rect::new(0, 0, 100, 10));
    render_peer_hold_dialog(area, &mut buf, &d, 900);
    assert!(!d.fits());
    assert_eq!(
        d.handle_key(&key(KeyCode::Char('a'))),
        PeerDialogOutcome::Ignored
    );
}

fn assert_cut_is_safe(s: &str, cols: usize) {
    let out = fit_line(s, cols);
    assert!(
        line_width(&out) <= cols,
        "{out:?} is {} wide, limit {cols}",
        line_width(&out)
    );
    // Never splits a cluster: the output (without the ellipsis) is a whole-cluster prefix of the input.
    let body = out.strip_suffix('\u{2026}').unwrap_or(&out);
    assert!(s.starts_with(body), "{out:?} is not a prefix of {s:?}");
    use unicode_segmentation::UnicodeSegmentation;
    let n = body.graphemes(true).count();
    assert_eq!(
        body,
        s.graphemes(true).take(n).collect::<String>(),
        "split a cluster in {s:?} at {cols}"
    );
}

#[test]
fn cut_by_cluster_never_overflows_or_splits() {
    let samples = [
        "\u{2764}\u{fe0f}".repeat(30),
        "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}\u{200d}\u{1f466}".repeat(10),
        "\u{1f1fa}\u{1f1f8}".repeat(20),
        format!("a{}", "\u{301}".repeat(500)),
        format!("x{}", "\u{fe0f}".repeat(50)),
        "e\u{301}\u{1f600}\u{4e2d}".repeat(15),
    ];
    for s in &samples {
        for cols in 1..60 {
            assert_cut_is_safe(s, cols);
        }
    }
}

#[test]
fn dialog_with_emoji_clusters_keeps_rows_in_width_and_fixed_rows_intact() {
    let _g = force_peer_ui_for_test(true);
    let mut h = hold();
    h.from_name = "\u{2764}\u{fe0f}".repeat(40);
    h.first_line = "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}".repeat(30);
    h.sender_mode = "\u{1f1fa}\u{1f1f8}".repeat(20);
    h.reasons = vec![format!("a{}", "\u{301}".repeat(300))];
    let d = PeerHoldDialog::open(h).unwrap();
    for w in [52usize, 60, 98] {
        for line in d.body_lines(0, w - 2) {
            assert!(line_width(&line) <= w - 2, "{line:?}");
        }
    }
    let rows = paint(&d, 60, 14);
    assert!(d.fits());
    assert!(
        rows.iter()
            .any(|r| r.contains("[a] accept  [r] refuse  [Esc] dismiss (stays held)")),
        "{rows:#?}"
    );
    assert!(
        rows.iter()
            .any(|r| r.contains("It does not approve any tool call.")),
        "{rows:#?}"
    );
}

#[test]
fn delivered_preview_is_a_single_line_block() {
    let _g = force_peer_ui_for_test(true);
    let mut sb = ScrollbackState::new();
    let mut tracker = AcpUpdateTracker::new();
    let meta = NotificationMeta {
        prompt_id: Some("peer-message-m-9".into()),
        ..Default::default()
    };
    let body = "long ".repeat(200);
    assert!(tracker.handle_update(user_chunk(&wrapped("lane a", &body)), &meta, &mut sb));
    match &sb.get(0).expect("entry").block {
        RenderBlock::System(b) => assert!(b.single_line, "the preview must not wrap"),
        other => panic!("expected a system row, got {other:?}"),
    }
}

#[test]
fn p28_refused_row_says_the_sender_is_told_only_when_it_is() {
    let _g = force_peer_ui_for_test(true);
    let told = notice_row_text(&PeerNotice::Refused {
        name: "a".into(),
        told: true,
    })
    .unwrap();
    let not = notice_row_text(&PeerNotice::Refused {
        name: "a".into(),
        told: false,
    })
    .unwrap();
    assert_eq!(
        told,
        "Peer message from \"a\" was refused; the sender is told."
    );
    assert_eq!(not, "Peer message from \"a\" was refused.");
    let ev = |t: serde_json::Value| {
        crate::peer_ui_state::parse_event(
            &serde_json::json!({"sessionUpdate": "peer_refused", "senderTold": t}),
        )
    };
    assert!(matches!(
        ev(true.into()),
        Some(crate::peer_ui_state::PeerEvent::Refused(_, true))
    ));
    assert!(matches!(
        ev(serde_json::Value::Null),
        Some(crate::peer_ui_state::PeerEvent::Refused(_, false))
    ));
}
