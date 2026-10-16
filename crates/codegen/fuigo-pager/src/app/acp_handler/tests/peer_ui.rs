//! Packet 12b: the peer UI driven end to end through the app: events in, dialog, `fuigo/peer/*` requests to a fake agent.

use super::*;
use crate::app::actions::{Action, Effect, PeerUiAction, TaskResult};
use crate::app::agent::AgentId;
use crate::app::app_view::InputOutcome;
use crate::peer_ui::force_peer_ui_for_test;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

type Log = Arc<Mutex<Vec<(String, Value)>>>;

fn hid() -> String {
    format!("h-{}", "ab".repeat(16))
}

fn peer_notif(session_id: &str, update: Value) -> AcpClientMessage {
    let (tx, _rx) = tokio::sync::oneshot::channel();
    let raw = serde_json::value::to_raw_value(&json!({"sessionId": session_id, "update": update})).unwrap();
    AcpClientMessage::ExtNotification(fuigo_acp_lib::AcpArgs {
        request: acp::ExtNotification::new("fuigo/session_notification", raw.into()),
        response_tx: tx,
    })
}

fn held_update(name: &str) -> Value {
    json!({
        "sessionUpdate": "peer_held", "heldId": hid(),
        "from": {"ref": "ab12", "name": name, "mode": "default"},
        "reasons": ["mode_mismatch"], "detail": null, "expiresAt": 4_000_000_000u64, "counts": {"held": 1}
    })
}

/// A fake agent: logs every `fuigo/peer/*` request; `release_error` makes `release` answer that typed reason.
fn fake_agent(release_error: Option<&'static str>) -> (fuigo_acp_lib::AcpAgentTx, Log) {
    use fuigo_acp_lib::AcpAgentMessage;
    let log: Log = Arc::default();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<AcpAgentMessage>();
    let l = log.clone();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let AcpAgentMessage::ExtMethod(args) = msg {
                let params: Value = serde_json::from_str(args.request.params.get()).unwrap();
                let method = args.request.method.to_string();
                l.lock().unwrap().push((method.clone(), params));
                let reply: Result<Value, acp::Error> = match method.as_str() {
                    "fuigo/peer/list_held" => {
                        let mut row = held_update("lane a");
                        row["token"] = json!("tok-1");
                        Ok(json!({"held": [row]}))
                    }
                    "fuigo/peer/release" => match release_error {
                        Some(reason) => Err(acp::Error::new(-32011, "Peer messaging error").data(json!({"reason": reason}))),
                        None => Ok(json!({"result": "delivered"})),
                    },
                    _ => Ok(json!({"optIn": true})),
                };
                let _ = args.response_tx.send(reply.map(|v| {
                    acp::ExtResponse::new(Arc::from(serde_json::value::to_raw_value(&v).unwrap()))
                }));
            }
        }
    });
    (tx, log)
}

/// Run effects against the fake agent and feed every answer back through dispatch until nothing is left.
async fn drive(mut effects: Vec<Effect>, app: &mut AppView, tx: &fuigo_acp_lib::AcpAgentTx) {
    let (progress_tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    for _ in 0..4 {
        if effects.is_empty() {
            return;
        }
        let mut tasks = tokio::task::JoinSet::new();
        for e in effects.drain(..) {
            crate::app::effects::execute(e, &mut tasks, tx, std::path::Path::new("."), &Default::default(), &progress_tx);
        }
        while let Some(done) = tasks.join_next().await {
            let result: TaskResult = done.unwrap();
            effects.extend(crate::app::dispatch::dispatch(Action::TaskComplete(result), app));
        }
    }
}

fn press(app: &mut AppView, code: KeyCode, mods: KeyModifiers) -> InputOutcome {
    let registry = crate::actions::ActionRegistry::defaults();
    app.agents.get_mut(&AgentId(0)).unwrap().handle_input(&Event::Key(KeyEvent::new(code, mods)), &registry)
}

/// One frame of the dialog (a real terminal paints before a key can arrive); `a` acts only after a frame showed the fixed rows.
fn paint(app: &AppView) {
    let area = ratatui::layout::Rect::new(0, 0, 100, 30);
    let mut buf = ratatui::buffer::Buffer::empty(area);
    crate::peer_ui::render_peer_hold_dialog(area, &mut buf, peer(app).dialog().expect("dialog open"), 0);
}

fn peer(app: &AppView) -> &crate::peer_ui_state::PeerUiState {
    &app.agents[&AgentId(0)].peer
}

fn act(outcome: InputOutcome, app: &mut AppView) -> Vec<Effect> {
    match outcome {
        InputOutcome::Action(a @ Action::PeerUi(_)) => crate::app::dispatch::dispatch(a, app),
        other => panic!("expected a peer action, got {other:?}"),
    }
}

#[tokio::test]
async fn flag_on_event_row_dialog_release_event() {
    let _g = force_peer_ui_for_test(true);
    let (tx, log) = fake_agent(None);
    let mut app = make_app_with_agent("sess-1");

    // The held event shows the row (escaped, one line).
    assert!(handle(peer_notif("sess-1", held_update("lane\na\u{1b}[2J")), &mut app));
    let row = peer(&app).row_text(0).expect("row");
    assert!(row.contains("review") && !row.contains(['\n', '\u{1b}']), "{row:?}");

    // Alt+h opens the dialog through list_held (fresh token), nothing released yet.
    let effects = act(press(&mut app, KeyCode::Char('h'), KeyModifiers::ALT), &mut app);
    assert!(matches!(effects.as_slice(), [Effect::PeerRpc { .. }]));
    drive(effects, &mut app, &tx).await;
    assert!(peer(&app).dialog_open());
    assert_eq!(log.lock().unwrap().iter().map(|(m, _)| m.as_str()).collect::<Vec<_>>(), ["fuigo/peer/list_held"]);

    // A key the dialog does not own is swallowed (not typed into the prompt) and releases nothing.
    assert!(matches!(press(&mut app, KeyCode::Char('x'), KeyModifiers::NONE), InputOutcome::Unchanged));
    assert!(matches!(press(&mut app, KeyCode::Enter, KeyModifiers::NONE), InputOutcome::Unchanged));
    assert_eq!(log.lock().unwrap().len(), 1);

    // `a` releases with the row's id and token; the token is used once.
    paint(&app);
    let effects = act(press(&mut app, KeyCode::Char('a'), KeyModifiers::NONE), &mut app);
    assert!(!peer(&app).dialog_open());
    drive(effects, &mut app, &tx).await;
    {
        let l = log.lock().unwrap();
        let (m, p) = l.last().unwrap();
        assert_eq!(m, "fuigo/peer/release");
        assert_eq!(p["heldId"], hid());
        assert_eq!(p["token"], "tok-1");
        assert_eq!(p["action"], "release");
        assert_eq!(p["sessionId"], "sess-1");
    }
    assert!(peer(&app).row_text(0).is_none(), "the row goes on success");

    // The shell's own event for it is accepted and changes nothing further.
    let upd = json!({"sessionUpdate": "peer_released", "heldId": hid(), "detail": null});
    let _ = handle(peer_notif("sess-1", upd), &mut app);
    assert_eq!(peer(&app).held_count(), 0);
}

#[tokio::test]
async fn refuse_sends_the_refuse_action() {
    let _g = force_peer_ui_for_test(true);
    let (tx, log) = fake_agent(None);
    let mut app = make_app_with_agent("sess-1");
    handle(peer_notif("sess-1", held_update("a")), &mut app);
    let e = act(press(&mut app, KeyCode::Char('h'), KeyModifiers::ALT), &mut app);
    drive(e, &mut app, &tx).await;
    let e = act(press(&mut app, KeyCode::Char('r'), KeyModifiers::NONE), &mut app);
    drive(e, &mut app, &tx).await;
    assert_eq!(log.lock().unwrap().last().unwrap().1["action"], "refuse");
}

#[tokio::test]
async fn stale_token_refreshes_once_and_never_resends_the_release() {
    let _g = force_peer_ui_for_test(true);
    let (tx, log) = fake_agent(Some("bad_token"));
    let mut app = make_app_with_agent("sess-1");
    handle(peer_notif("sess-1", held_update("a")), &mut app);
    let e = act(press(&mut app, KeyCode::Char('h'), KeyModifiers::ALT), &mut app);
    drive(e, &mut app, &tx).await;
    paint(&app);
    let e = act(press(&mut app, KeyCode::Char('a'), KeyModifiers::NONE), &mut app);
    drive(e, &mut app, &tx).await;
    let methods: Vec<String> = log.lock().unwrap().iter().map(|(m, _)| m.clone()).collect();
    assert_eq!(methods, ["fuigo/peer/list_held", "fuigo/peer/release", "fuigo/peer/list_held"], "one release, one refresh");
    assert!(!peer(&app).dialog_open(), "the user chooses again: the dialog is closed after the refresh");
    assert_eq!(peer(&app).held_count(), 1);
}

#[tokio::test]
async fn no_operator_and_unavailable_are_one_plain_line_and_no_retry() {
    for reason in ["no_operator", "unavailable"] {
        let _g = force_peer_ui_for_test(true);
        let (tx, log) = fake_agent(Some(reason));
        let mut app = make_app_with_agent("sess-1");
        handle(peer_notif("sess-1", held_update("a")), &mut app);
        let e = act(press(&mut app, KeyCode::Char('h'), KeyModifiers::ALT), &mut app);
        drive(e, &mut app, &tx).await;
        paint(&app);
    let e = act(press(&mut app, KeyCode::Char('a'), KeyModifiers::NONE), &mut app);
        drive(e, &mut app, &tx).await;
        assert_eq!(log.lock().unwrap().len(), 2, "{reason}: no refresh, no retry");
    }
}

#[test]
fn flag_off_events_are_ignored_and_no_peer_ui_exists() {
    let _g = force_peer_ui_for_test(false);
    let mut app = make_app_with_agent("sess-1");
    handle(peer_notif("sess-1", held_update("a")), &mut app);
    assert_eq!(peer(&app).held_count(), 0);
    assert!(peer(&app).row_text(0).is_none());
    // Alt+h is not ours: no peer action, no dialog.
    let out = press(&mut app, KeyCode::Char('h'), KeyModifiers::ALT);
    assert!(!matches!(out, InputOutcome::Action(Action::PeerUi(PeerUiAction::OpenDialog))));
    assert!(!peer(&app).dialog_open());
    assert!(crate::peer_ui_state::startup_call().is_none());
}

#[test]
fn unknown_and_malformed_peer_events_are_ignored() {
    let _g = force_peer_ui_for_test(true);
    let mut app = make_app_with_agent("sess-1");
    let mut bad = held_update("a");
    bad["expiresAt"] = json!("never");
    for u in [json!({"sessionUpdate": "peer_bogus"}), bad, json!({"sessionUpdate": "peer_held"}), json!({"sessionUpdate": 5})] {
        handle(peer_notif("sess-1", u), &mut app);
    }
    handle(peer_notif("no-such-session", held_update("a")), &mut app);
    assert_eq!(peer(&app).held_count(), 0);
    assert!(!peer(&app).dialog_open());
    // Nothing from an event reached the prompt.
    assert!(app.agents[&AgentId(0)].prompt.text().is_empty());
}

#[tokio::test]
async fn paste_is_swallowed_while_the_dialog_is_open() {
    let _g = force_peer_ui_for_test(true);
    let (tx, _log) = fake_agent(None);
    let mut app = make_app_with_agent("sess-p");
    assert!(handle(peer_notif("sess-p", held_update("lane")), &mut app));
    let effects = act(press(&mut app, KeyCode::Char('h'), KeyModifiers::ALT), &mut app);
    drive(effects, &mut app, &tx).await;
    assert!(peer(&app).dialog_open());
    let registry = crate::actions::ActionRegistry::defaults();
    let out = app.agents.get_mut(&AgentId(0)).unwrap().handle_input(&Event::Paste("rm -rf /\n".to_owned()), &registry);
    assert!(matches!(out, InputOutcome::Unchanged), "{out:?}");
}

// ---- Round 3: exclusivity, draw order, freshness ----

fn methods(log: &Log) -> Vec<String> {
    log.lock().unwrap().iter().map(|(m, _)| m.clone()).collect()
}

fn app_press(app: &mut AppView, code: KeyCode, mods: KeyModifiers) -> InputOutcome {
    app.handle_input(&Event::Key(KeyEvent::new(code, mods)))
}

fn is_peer_action(o: &InputOutcome) -> bool {
    matches!(o, InputOutcome::Action(Action::PeerUi(_)))
}

async fn open_dialog(app: &mut AppView, tx: &fuigo_acp_lib::AcpAgentTx) {
    let e = act(press(app, KeyCode::Char('h'), KeyModifiers::ALT), app);
    drive(e, app, tx).await;
    assert!(peer(app).dialog_open());
}

fn draw_agent(app: &mut AppView, w: u16, h: u16) -> Vec<String> {
    let reg = crate::actions::ActionRegistry::defaults();
    let area = ratatui::layout::Rect::new(0, 0, w, h);
    let mut buf = ratatui::buffer::Buffer::empty(area);
    let mut scratch = crate::scrollback::render::ScratchBuffer::new();
    app.agents.get_mut(&AgentId(0)).unwrap().draw(
        area,
        &mut buf,
        &reg,
        &mut scratch,
        None,
        false,
        crate::app::agent_view::BannerSlotParams::none(),
        &crate::app::bundle::BundleState::default(),
        false,
        false,
        &mut Vec::new(),
        crate::app::agent_view::AppRenderParams::default(),
    );
    (0..h).map(|y| (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect::<String>()).collect()
}

/// A permission card is up and a message is held: `a` goes to the permission card (exactly as with no peer message at all) and no
/// `release` is ever sent. Both orders: the card arrives while the dialog is open, and the card was there first.
#[tokio::test]
async fn permission_card_gets_a_and_no_release_is_sent() {
    let _g = force_peer_ui_for_test(true);
    let (tx, log) = fake_agent(None);
    let mut app = make_app_with_agent("sess-1");
    handle(peer_notif("sess-1", held_update("lane a")), &mut app);
    open_dialog(&mut app, &tx).await;
    paint(&app);
    let (msg, _rx) = make_permission_message("sess-1");
    handle(msg, &mut app);
    let out = press(&mut app, KeyCode::Char('a'), KeyModifiers::NONE);
    assert!(!is_peer_action(&out), "{out:?}");
    assert!(!peer(&app).dialog_open(), "the dialog is closed before the key is processed");
    assert_eq!(methods(&log), ["fuigo/peer/list_held"], "no release call");

    // Control: the same key on the same card with no peer message anywhere behaves the same.
    let mut control = make_app_with_agent("sess-1");
    let (msg, _rx2) = make_permission_message("sess-1");
    handle(msg, &mut control);
    let want = press(&mut control, KeyCode::Char('a'), KeyModifiers::NONE);
    assert_eq!(format!("{out:?}"), format!("{want:?}"));
}

#[tokio::test]
async fn alt_h_does_not_open_over_another_overlay() {
    let _g = force_peer_ui_for_test(true);
    let mut app = make_app_with_agent("sess-1");
    handle(peer_notif("sess-1", held_update("lane a")), &mut app);
    let (msg, _rx) = make_permission_message("sess-1");
    handle(msg, &mut app);
    let before = app.agents[&AgentId(0)].scrollback.len();
    let out = press(&mut app, KeyCode::Char('h'), KeyModifiers::ALT);
    assert!(!is_peer_action(&out), "{out:?}");
    assert!(!peer(&app).dialog_open());
    assert_eq!(app.agents[&AgentId(0)].scrollback.len(), before + 1, "one notice row");
}

/// A list reply that lands after another overlay opened must not open the dialog.
#[tokio::test]
async fn list_reply_after_an_overlay_opened_does_not_open_the_dialog() {
    let _g = force_peer_ui_for_test(true);
    let (tx, _log) = fake_agent(None);
    let mut app = make_app_with_agent("sess-1");
    handle(peer_notif("sess-1", held_update("lane a")), &mut app);
    let e = act(press(&mut app, KeyCode::Char('h'), KeyModifiers::ALT), &mut app);
    let (msg, _rx) = make_permission_message("sess-1");
    handle(msg, &mut app);
    drive(e, &mut app, &tx).await;
    assert!(!peer(&app).dialog_open());
}

/// Resize to too small, then `a`, in the same batch (no draw between): not accepted. A frame that shows the rows re-arms it.
#[tokio::test]
async fn resize_then_a_before_the_next_draw_is_not_accepted() {
    let _g = force_peer_ui_for_test(true);
    let (tx, log) = fake_agent(None);
    let mut app = make_app_with_agent("sess-1");
    handle(peer_notif("sess-1", held_update("lane a")), &mut app);
    open_dialog(&mut app, &tx).await;
    draw_agent(&mut app, 100, 30);
    assert!(peer(&app).dialog().unwrap().fits(), "a full frame painted the fixed rows");
    let _ = app.handle_input(&Event::Resize(40, 4));
    assert!(!peer(&app).dialog().unwrap().fits(), "the resize cleared the proof at once");
    let out = app_press(&mut app, KeyCode::Char('a'), KeyModifiers::NONE);
    assert!(!is_peer_action(&out), "{out:?}");
    assert_eq!(methods(&log), ["fuigo/peer/list_held"]);
    // A too-small frame never re-arms it; a big one does.
    draw_agent(&mut app, 40, 4);
    assert!(!peer(&app).dialog().unwrap().fits());
    draw_agent(&mut app, 100, 30);
    assert!(peer(&app).dialog().unwrap().fits());
    let out = app_press(&mut app, KeyCode::Char('a'), KeyModifiers::NONE);
    assert!(is_peer_action(&out), "{out:?}");
}

/// Open a dialog and paint it, so `fits` is proven; returns the app and the request log.
async fn painted_dialog() -> (AppView, Log, impl Sized) {
    let g = force_peer_ui_for_test(true);
    let (tx, log) = fake_agent(None);
    let mut app = make_app_with_agent("sess-1");
    handle(peer_notif("sess-1", held_update("lane a")), &mut app);
    open_dialog(&mut app, &tx).await;
    draw_agent(&mut app, 100, 30);
    assert!(peer(&app).dialog().unwrap().fits());
    (app, log, g)
}

#[tokio::test]
async fn focus_gain_then_a_in_the_same_batch_is_not_accepted_until_the_next_draw() {
    let (mut app, log, _g) = painted_dialog().await;
    let _ = app.handle_input(&Event::FocusGained);
    assert!(!peer(&app).dialog().unwrap().fits());
    let out = app_press(&mut app, KeyCode::Char('a'), KeyModifiers::NONE);
    assert!(!is_peer_action(&out), "{out:?}");
    assert!(peer(&app).dialog().is_some(), "dialog still open");
    assert_eq!(methods(&log), ["fuigo/peer/list_held"]);
    draw_agent(&mut app, 100, 30);
    let out = app_press(&mut app, KeyCode::Char('a'), KeyModifiers::NONE);
    assert!(is_peer_action(&out), "{out:?}");
}

#[tokio::test]
async fn focus_lost_then_focus_gained_then_a_is_not_accepted_until_the_next_draw() {
    let (mut app, _log, _g) = painted_dialog().await;
    let _ = app.handle_input(&Event::FocusLost);
    assert!(!peer(&app).dialog().unwrap().fits());
    draw_agent(&mut app, 100, 30);
    let _ = app.handle_input(&Event::FocusLost);
    let _ = app.handle_input(&Event::FocusGained);
    let out = app_press(&mut app, KeyCode::Char('a'), KeyModifiers::NONE);
    assert!(!is_peer_action(&out), "{out:?}");
    assert!(peer(&app).dialog().is_some());
    draw_agent(&mut app, 100, 30);
    let out = app_press(&mut app, KeyCode::Char('a'), KeyModifiers::NONE);
    assert!(is_peer_action(&out), "{out:?}");
}

#[tokio::test]
async fn mouse_then_a_is_not_accepted_and_r_still_refuses() {
    use crossterm::event::{MouseEvent, MouseEventKind};
    let (mut app, _log, _g) = painted_dialog().await;
    let mouse = Event::Mouse(MouseEvent {
        kind: MouseEventKind::Moved,
        column: 3,
        row: 3,
        modifiers: KeyModifiers::NONE,
    });
    let _ = app.handle_input(&mouse);
    let out = app_press(&mut app, KeyCode::Char('a'), KeyModifiers::NONE);
    assert!(!is_peer_action(&out), "{out:?}");
    assert!(peer(&app).dialog().is_some());
    let out = app_press(&mut app, KeyCode::Char('r'), KeyModifiers::NONE);
    assert!(is_peer_action(&out), "refuse is not gated: {out:?}");
}

/// Every non-key event clears the proof; a key does not. The classifier is an exhaustive `match`, so a new `Event`
/// variant fails to compile until it is classified; this test then pins that each variant reaches the hook.
#[tokio::test]
async fn every_non_key_event_reaches_the_screen_disturbed_hook() {
    use crossterm::event::{MouseEvent, MouseEventKind};
    let events = [
        Event::FocusGained,
        Event::FocusLost,
        Event::Resize(100, 30),
        Event::Paste(String::new()),
        Event::Mouse(MouseEvent {
            kind: MouseEventKind::Moved,
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        }),
    ];
    for ev in events {
        assert!(AppView::event_disturbs_screen(&ev), "{ev:?}");
        let (mut app, _log, _g) = painted_dialog().await;
        let _ = app.handle_input(&ev);
        assert!(!peer(&app).dialog().unwrap().fits(), "{ev:?} must clear the painted proof");
    }
    assert!(!AppView::event_disturbs_screen(&Event::Key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE))));
    // The event loop returns early for focus events, so it must call the hook itself, first, before its `match ev`.
    let src = include_str!("../../event_loop.rs");
    let start = src.find("let mut handle_one = |routed: &RoutedInputEvent|").unwrap();
    let body = &src[start..];
    let hook = body.find("app.note_screen_disturbed()").unwrap();
    assert!(hook < body.find("Event::FocusGained =>").unwrap());
}

/// The dialog is painted by the outermost `draw`, after every layer; its fixed rows are on screen and nothing follows it.
#[tokio::test]
async fn dialog_is_painted_last_with_the_fixed_rows_on_screen() {
    let _g = force_peer_ui_for_test(true);
    let (tx, _log) = fake_agent(None);
    let mut app = make_app_with_agent("sess-1");
    handle(peer_notif("sess-1", held_update("lane a")), &mut app);
    open_dialog(&mut app, &tx).await;
    let rows = draw_agent(&mut app, 100, 30);
    let text = rows.join("\n");
    assert!(text.contains("It does not approve any tool call."), "{text}");
    assert!(text.contains("[a] accept  [r] refuse  [Esc] dismiss (stays held)"), "{text}");
    let src = include_str!("../../agent_view/render.rs");
    let wrapper = &src[src.find("pub fn draw(").unwrap()..src.find("fn draw_layers(").unwrap()];
    let layers_end = src.find("fn draw_scroll_arrow(").unwrap();
    let layers = &src[src.find("fn draw_layers(").unwrap()..layers_end];
    assert!(wrapper.contains("self.draw_layers(") && wrapper.contains("render_peer_hold_dialog("));
    assert!(wrapper.find("self.draw_layers(").unwrap() < wrapper.find("render_peer_hold_dialog(").unwrap());
    assert!(!layers.contains("render_peer_hold_dialog"), "the dialog must not be painted inside the layers");
}

/// Pins `other_overlay_active` against the overlay calls of the render function: every overlay the renderer paints is listed in the
/// helper, and a new `render_*_overlay|modal|panel|detail` call that is not in this table fails here.
#[test]
fn other_overlay_list_matches_the_draw_overlays() {
    let render = include_str!("../../agent_view/render.rs");
    let peer_src = include_str!("../../agent_view/peer.rs");
    let layers = &render[render.find("fn draw_layers(").unwrap()..render.find("fn draw_scroll_arrow(").unwrap()];
    let helper = &peer_src[peer_src.find("fn other_overlay_active").unwrap()..peer_src.find("fn peer_close_if_overlaid").unwrap()];
    // (call or condition in the renderer, field the helper must test)
    let table: &[(&str, &str)] = &[
        ("render_permission_view(", "blocking_card()"),
        ("render_question_view(", "blocking_card()"),
        ("render_elicitation_view(", "blocking_card()"),
        ("render_cancel_turn_panel(", "blocking_card()"),
        ("render_rewind_overlay(", "rewind_state"),
        ("render_jump_overlay(", "jump_state"),
        ("render_btw_panel(", "btw_state"),
        ("draw_active_modal(", "active_modal"),
        ("self.line_viewer", "line_viewer"),
        ("self.image_viewer", "image_viewer"),
        ("self.video_viewer", "video_viewer"),
        ("self.gboom", "gboom"),
        ("render_gboom_overlay(", "gboom"),
        ("render_video_overlay(", "video_viewer"),
        ("self.block_viewer", "block_viewer"),
        ("render_agents_modal(", "agents_modal"),
        ("render_extensions_modal(", "extensions_modal"),
        ("render_persona_detail(", "persona_detail"),
        ("render_goal_detail(", "show_goal_detail"),
        ("render_workflows(", "show_workflows"),
        ("self.prompt.file_search_visible()", "file_search_visible()"),
        ("self.prompt.history_search.is_active()", "history_search.is_active()"),
    ];
    for (call, field) in table {
        assert!(layers.contains(call), "renderer no longer has {call}: update the table and other_overlay_active");
        assert!(helper.contains(field), "other_overlay_active does not test {field} (renderer paints {call})");
    }
    assert!(helper.contains("plan_approval_view") && helper.contains("active_subagent"));
    // Any other overlay-shaped render call in the renderer must be listed.
    let mut rest = layers;
    while let Some(i) = rest.find("render_") {
        let ident: String = rest[i..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
        let after = &rest[i + ident.len()..];
        // Selection and drag highlights paint over text but are not prompts and take no keys.
        let overlay_shaped = !ident.contains("_selection_") && !ident.contains("_drag_") && ["_overlay", "_modal", "_panel", "_detail"].iter().any(|s| ident.ends_with(s));
        if overlay_shaped && after.starts_with('(') {
            assert!(table.iter().any(|(c, _)| c.starts_with(&ident)), "overlay call {ident} is not in other_overlay_active's table");
        }
        rest = &rest[i + ident.len().max(1)..];
    }
}

// ---- after the focused audit (decision 60) ----

/// A root view with a held message, an open painted dialog, and a child view `child-1`.
async fn painted_dialog_with_child() -> (AppView, Log, impl Sized) {
    let g = force_peer_ui_for_test(true);
    let (tx, log) = fake_agent(None);
    let mut app = make_app_with_parent_and_child("sess-1", "child-1");
    handle(peer_notif("sess-1", held_update("lane a")), &mut app);
    open_dialog(&mut app, &tx).await;
    draw_agent(&mut app, 100, 30);
    assert!(peer(&app).dialog().unwrap().fits());
    (app, log, g)
}

#[tokio::test]
async fn a_child_view_gets_no_peer_state_row_or_dialog() {
    let _g = force_peer_ui_for_test(true);
    let (_tx, log) = fake_agent(None);
    let mut app = make_app_with_parent_and_child("sess-1", "child-1");
    // The event is addressed to the child's session id: ignored, no state anywhere.
    handle(peer_notif("child-1", held_update("lane a")), &mut app);
    let root = &app.agents[&AgentId(0)];
    assert_eq!(root.peer.held_count(), 0);
    assert_eq!(root.subagent_views["child-1"].peer.held_count(), 0);
    assert!(!root.subagent_views["child-1"].owns_peer_ui() || !root.subagent_views["child-1"].peer.row_visible());
    // Fullscreen child: Alt+h does nothing, `a` sends no release.
    app.agents.get_mut(&AgentId(0)).unwrap().open_subagent_fullscreen("child-1".to_owned());
    let out = app_press(&mut app, KeyCode::Char('h'), KeyModifiers::ALT);
    assert!(!is_peer_action(&out), "{out:?}");
    let out = app_press(&mut app, KeyCode::Char('a'), KeyModifiers::NONE);
    assert!(!is_peer_action(&out), "{out:?}");
    assert!(methods(&log).is_empty());
    let child = &app.agents[&AgentId(0)].subagent_views["child-1"];
    assert!(!child.owns_peer_ui() && !child.peer.dialog_open());
}

#[tokio::test]
async fn tutorial_dismissed_then_a_in_the_same_batch_is_not_accepted_until_the_next_draw() {
    let (mut app, log, _g) = painted_dialog().await;
    app.tutorial = Some(crate::views::tutorial::TutorialState::new());
    for _ in 0..8 {
        if app.tutorial.is_none() {
            break;
        }
        let out = app_press(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert!(!is_peer_action(&out), "{out:?}");
    }
    assert!(app.tutorial.is_none(), "tutorial closed");
    assert!(!peer(&app).dialog().unwrap().fits(), "the key the tutorial handled must clear the painted proof");
    let out = app_press(&mut app, KeyCode::Char('a'), KeyModifiers::NONE);
    assert!(!is_peer_action(&out), "{out:?}");
    assert_eq!(methods(&log), ["fuigo/peer/list_held"]);
    draw_agent(&mut app, 100, 30);
    let out = app_press(&mut app, KeyCode::Char('a'), KeyModifiers::NONE);
    assert!(is_peer_action(&out), "{out:?}");
}

#[tokio::test]
async fn a_key_the_dialog_ignores_keeps_the_painted_proof() {
    let (mut app, _log, _g) = painted_dialog().await;
    let _ = app_press(&mut app, KeyCode::Char('x'), KeyModifiers::NONE);
    assert!(peer(&app).dialog().unwrap().fits());
}

#[tokio::test]
async fn close_then_reopen_fullscreen_then_a_in_one_batch_is_not_accepted() {
    let (mut app, log, _g) = painted_dialog_with_child().await;
    let a = app.agents.get_mut(&AgentId(0)).unwrap();
    a.open_subagent_fullscreen("child-1".to_owned());
    assert!(!a.peer.dialog_open(), "opening a fullscreen subagent closes the dialog");
    a.close_subagent_fullscreen();
    a.open_subagent_fullscreen("child-1".to_owned());
    let out = app_press(&mut app, KeyCode::Char('a'), KeyModifiers::NONE);
    assert!(!is_peer_action(&out), "{out:?}");
    assert_eq!(methods(&log), ["fuigo/peer/list_held"]);
}

#[tokio::test]
async fn the_focused_view_changing_through_dispatch_closes_the_dialog() {
    let (mut app, _log, _g) = painted_dialog_with_child().await;
    let before = app.focus_signature();
    app.agents.get_mut(&AgentId(0)).unwrap().active_subagent = Some("child-1".to_owned());
    app.note_focus_change_since(before);
    assert!(!peer(&app).dialog_open());
}

/// P29-B: a peer message delivered to the hidden home session (the welcome screen is up, no turn has run) used to land in a
/// scrollback nobody could see, and the unused-husk cleanup could later delete the conversation. The delivery now brings that
/// session on screen: the delivered row is visible, and the session is no longer an unused husk.
#[test]
fn a_peer_message_delivered_to_the_hidden_home_session_brings_it_on_screen() {
    let _g = force_peer_ui_for_test(true);
    let mut app = make_app_with_agent("sess-1");
    let home = AgentId(5);
    app.agents.insert(home, make_agent(Some("home-sess")));
    app.home_session_agent = Some(home);
    app.optimistic_home_husk = Some(home);
    app.active_view = ActiveView::Welcome;

    let text = "<cross-session-message from-name=\"lane a\" from-ref=\"ab12\" message-id=\"m-1\">\nhello there\n</cross-session-message>";
    let (tx, _rx) = tokio::sync::oneshot::channel();
    let request = acp::SessionNotification::new(
        acp::SessionId::new("home-sess"),
        acp::SessionUpdate::UserMessageChunk(acp::ContentChunk::new(acp::ContentBlock::Text(acp::TextContent::new(text)))),
    )
    .meta(json!({"promptId": "peer-message-m-1", "isReplay": false}).as_object().cloned());
    let _ = handle(AcpClientMessage::SessionNotification(fuigo_acp_lib::AcpArgs { request, response_tx: tx }), &mut app);

    let sb = &app.agents[&home].scrollback;
    let rows: Vec<String> = (0..sb.len())
        .filter_map(|i| match sb.get(i).map(|e| &e.block) {
            Some(RenderBlock::System(b)) => Some(b.text.clone()),
            _ => None,
        })
        .collect();
    assert!(rows.iter().any(|r| r.contains("lane a") && r.contains("hello there")), "the delivered row is in the session: {rows:?}");
    assert_eq!(app.active_view, ActiveView::Agent(home), "the welcome screen gives way to the session that got the message");
    assert_eq!(app.home_session_agent, None, "no longer the hidden home session");
    assert_eq!(app.optimistic_home_husk, None, "a session that received a peer message is not an unused husk");
}

/// Replay of an old peer message, or any non-peer update, leaves the hidden home session hidden.
#[test]
fn only_a_live_peer_delivery_reveals_the_hidden_home_session() {
    let _g = force_peer_ui_for_test(true);
    let mut app = make_app_with_agent("sess-1");
    let home = AgentId(5);
    app.agents.insert(home, make_agent(Some("home-sess")));
    app.home_session_agent = Some(home);
    app.active_view = ActiveView::Welcome;
    let text = "<cross-session-message from-name=\"lane a\" from-ref=\"ab12\" message-id=\"m-1\">\nhi\n</cross-session-message>";
    for meta in [json!({"promptId": "peer-message-m-1", "isReplay": true}), json!({"promptId": "user-1", "isReplay": false})] {
        let (tx, _rx) = tokio::sync::oneshot::channel();
        let request = acp::SessionNotification::new(
            acp::SessionId::new("home-sess"),
            acp::SessionUpdate::UserMessageChunk(acp::ContentChunk::new(acp::ContentBlock::Text(acp::TextContent::new(text)))),
        )
        .meta(meta.as_object().cloned());
        let _ = handle(AcpClientMessage::SessionNotification(fuigo_acp_lib::AcpArgs { request, response_tx: tx }), &mut app);
        assert_eq!(app.active_view, ActiveView::Welcome, "{meta}");
        assert_eq!(app.home_session_agent, Some(home));
    }
}
