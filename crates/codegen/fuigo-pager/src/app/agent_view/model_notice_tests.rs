//! Agent-view tests for the model notice banner above the prompt: placement, the short-terminal rule, no change without a notice.
use super::{AgentView, AppRenderParams, BannerSlotParams, test_fixtures};
use crate::actions::ActionRegistry;
use crate::app::bundle::BundleState;
use crate::scrollback::render::ScratchBuffer;
use agent_client_protocol as acp;
use pretty_assertions::assert_eq;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

const NOTICE_ID: &str = "example-model-preview";
const PLAIN_ID: &str = "example-model";

fn model(id: &str, notice: Option<serde_json::Value>) -> (acp::ModelId, acp::ModelInfo) {
    let model_id = acp::ModelId::new(id);
    let mut meta = serde_json::Map::new();
    if let Some(notice) = notice {
        meta.insert("notice".to_owned(), notice);
    }
    (
        model_id.clone(),
        acp::ModelInfo::new(model_id, id.to_owned()).meta(meta),
    )
}

fn agent_on(current: &str, notice: serde_json::Value) -> AgentView {
    let mut agent = test_fixtures::make_agent();
    agent.session.models.available = [model(NOTICE_ID, Some(notice)), model(PLAIN_ID, None)]
        .into_iter()
        .collect();
    agent
        .session
        .models
        .set_current(acp::ModelId::new(current), None);
    agent
}

fn draw(agent: &mut AgentView, width: u16, height: u16) -> Vec<String> {
    let area = Rect::new(0, 0, width, height);
    let mut buf = Buffer::empty(area);
    agent.draw(
        area,
        &mut buf,
        &ActionRegistry::defaults(),
        &mut ScratchBuffer::new(),
        None,
        false,
        BannerSlotParams::none(),
        &BundleState::default(),
        false,
        false,
        &mut Vec::new(),
        AppRenderParams::default(),
    );
    (0..height)
        .map(|y| {
            (0..width)
                .filter_map(|x| buf.cell((x, y)).map(|c| c.symbol().to_owned()))
                .collect::<String>()
        })
        .collect()
}

fn warn() -> serde_json::Value {
    serde_json::json!({"severity": "warning", "text": "preview: may change"})
}

#[test]
fn selected_model_notice_shows_above_the_prompt_at_80x24() {
    let mut agent = agent_on(NOTICE_ID, warn());
    let rows = draw(&mut agent, 80, 24);
    let notice_row = rows
        .iter()
        .position(|r| r.contains("! notice: preview: may change"))
        .expect("banner row");
    let prompt_row = rows
        .iter()
        .position(|r| r.contains('>') || r.contains('│'))
        .unwrap_or(usize::MAX);
    assert!(notice_row < prompt_row.min(rows.len()), "{rows:#?}");
}

#[test]
fn model_without_a_notice_renders_byte_identical_to_no_notice_support() {
    let mut plain = agent_on(PLAIN_ID, warn());
    let mut baseline = test_fixtures::make_agent();
    baseline.session.models.available = [model(PLAIN_ID, None)].into_iter().collect();
    baseline
        .session
        .models
        .set_current(acp::ModelId::new(PLAIN_ID), None);
    for (w, h) in [(80, 24), (52, 6)] {
        assert_eq!(draw(&mut baseline, w, h), draw(&mut plain, w, h), "{w}x{h}");
    }
}

#[test]
fn short_terminal_drops_the_banner_and_keeps_the_layout() {
    let mut with = agent_on(NOTICE_ID, warn());
    let mut without = agent_on(PLAIN_ID, warn());
    let rows = draw(&mut with, 52, 6);
    assert!(!rows.iter().any(|r| r.contains("notice:")), "{rows:#?}");
    assert_eq!(draw(&mut without, 52, 6), rows);
}

#[test]
fn banner_is_a_passive_row_painted_in_the_layers_not_an_overlay() {
    let render = include_str!("render.rs");
    let layers = &render
        [render.find("fn draw_layers(").unwrap()..render.find("fn draw_scroll_arrow(").unwrap()];
    assert!(layers.contains("model_notice_banner::render("));
    let peer = include_str!("peer.rs");
    let helper =
        &peer[peer.find("fn other_overlay_active").unwrap()..peer.find("fn owns_peer_ui").unwrap()];
    assert!(
        !helper.contains("notice"),
        "the banner takes no keys and covers nothing"
    );
    // The dialog stays the last thing painted, after the layers that hold the banner.
    let wrapper =
        &render[render.find("pub fn draw(").unwrap()..render.find("fn draw_layers(").unwrap()];
    assert!(
        wrapper.find("self.draw_layers(").unwrap()
            < wrapper.find("render_peer_hold_dialog(").unwrap()
    );
}
