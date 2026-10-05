//! P125: a relay-sync refusal that reaches the TUI before `session/new` returns is shown once the session is bound.

use super::*;
use crate::app::dispatch::session::lifecycle::handle_session_created;
use crate::scrollback::block::RenderBlock;

fn system_texts(app: &AppView, id: AgentId) -> Vec<String> {
    let sb = &app.agents.get(&id).unwrap().scrollback;
    (0..sb.len())
        .filter_map(|i| match sb.get(i).map(|e| &e.block) {
            Some(RenderBlock::System(b)) => Some(b.text.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn a_sync_refusal_that_beat_session_new_is_shown_when_the_session_is_bound() {
    let mut app = test_app();
    let _ = drain_startup_actions(&mut app);
    let home = app.home_session_agent.expect("home session");
    app.note_relay_sync_refusal("home-sid", "relay refused: how to trust it".to_owned());
    assert!(system_texts(&app, home).iter().all(|t| !t.contains("how to trust")), "no session yet");
    let _ = handle_session_created(&mut app, home, acp::SessionId::new("home-sid"), None, None);
    assert!(
        system_texts(&app, home).iter().any(|t| t == "relay refused: how to trust it"),
        "{:?}",
        system_texts(&app, home)
    );
}
