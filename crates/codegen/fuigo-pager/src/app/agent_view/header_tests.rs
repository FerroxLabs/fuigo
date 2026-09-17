//! The session header (status bar) row: `branch worktree path` on the left, and the prompt info line's mode flags.
use super::{AgentView, AppRenderParams, BannerSlotParams, test_fixtures};
use crate::actions::ActionRegistry;
use crate::app::bundle::BundleState;
use crate::scrollback::render::ScratchBuffer;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
const PATH: &str = "/fuigo-header-marker";
fn agent_at(width: u16) -> AgentView {
    let mut agent = test_fixtures::make_agent();
    agent.last_terminal_size = (width, 30);
    agent.session.cwd = std::path::PathBuf::from(PATH);
    agent
}
fn draw(agent: &mut AgentView, registry: &ActionRegistry) -> Buffer {
    let (width, height) = agent.last_terminal_size;
    let area = Rect::new(0, 0, width, height);
    let bundle = BundleState::default();
    let mut buf = Buffer::empty(area);
    let mut scratch = ScratchBuffer::new();
    agent.draw(
        area,
        &mut buf,
        registry,
        &mut scratch,
        None,
        false,
        BannerSlotParams {
            height: 0,
            announcements: &[],
            hidden_ids: &std::collections::BTreeSet::new(),
            privacy_banner: false,
            mouse_pos: None,
            tip: None,
        },
        &bundle,
        false,
        false,
        &mut Vec::new(),
        AppRenderParams::default(),
    );
    buf
}
fn row_text(buf: &Buffer, y: u16) -> String {
    (0..buf.area.width)
        .filter_map(|x| buf.cell((x, y)).map(|c| c.symbol().to_string()))
        .collect()
}
/// The header row's text, from the cwd hit-rect's row.
fn header_row(agent: &AgentView, buf: &Buffer) -> String {
    let y = agent
        .hit_cwd
        .rect
        .map(|r| r.y)
        .expect("the cwd is painted on the status bar");
    row_text(buf, y)
}
/// A worktree session shows the `worktree` badge plus the cwd only; it never appends ` (worktree of <main repo>)`.
#[test]
fn worktree_session_header_keeps_badge_and_omits_main_repo_suffix() {
    let _theme = crate::theme::cache::pin_theme();
    let registry = ActionRegistry::defaults();
    let mut agent = agent_at(120);
    agent.is_worktree = true;
    agent.main_repo = Some("~/x".into());
    let buf = draw(&mut agent, &registry);
    let row = header_row(&agent, &buf);
    assert!(row.contains("worktree"), "row = {row:?}");
    assert!(row.contains(PATH), "row = {row:?}");
    assert!(
        !row.contains("(worktree of"),
        "no leftover main-repo suffix, row = {row:?}"
    );
}
/// Deep cwds are always middle-shortened (last two components stay full), not only when the row is tight.
#[test]
fn session_header_always_shortens_deep_cwd() {
    let _theme = crate::theme::cache::pin_theme();
    let registry = ActionRegistry::defaults();
    let mut agent = agent_at(120);
    agent.session.cwd = std::path::PathBuf::from("/deep/alpha/bravo/charlie/delta");
    let buf = draw(&mut agent, &registry);
    let row = header_row(&agent, &buf);
    assert!(
        row.contains("/d/a/b/charlie/delta"),
        "always last-two shortening, row = {row:?}"
    );
    assert!(
        !row.contains("/deep/alpha"),
        "middle components must not stay full, row = {row:?}"
    );
    assert!(
        !row.contains("(worktree of"),
        "no leftover main-repo suffix, row = {row:?}"
    );
}

/// Plan mode and the permission mode are independent axes: the info line reads `plan · always-approve`
/// (or `plan · auto`) instead of hiding the permission flag while the agent is in plan mode.
#[test]
fn info_line_shows_plan_and_permission_flags_together() {
    let _theme = crate::theme::cache::pin_theme();
    let registry = ActionRegistry::defaults();
    for (yolo, auto, expected) in [(true, false, "always-approve"), (false, true, "auto")] {
        let mut agent = agent_at(120);
        agent.plan_mode_active = true;
        agent.session.set_yolo_mode_for_test(yolo);
        agent.session.set_auto_mode_for_test(auto);
        let buf = draw(&mut agent, &registry);
        let rows: Vec<String> = (0..buf.area.height).map(|y| row_text(&buf, y)).collect();
        let info = rows
            .iter()
            .find(|row| row.contains("plan"))
            .unwrap_or_else(|| panic!("no info line mentions plan: {rows:#?}"));
        assert!(
            info.contains(expected),
            "plan mode must keep the {expected} flag visible, row = {info:?}"
        );
    }
}
