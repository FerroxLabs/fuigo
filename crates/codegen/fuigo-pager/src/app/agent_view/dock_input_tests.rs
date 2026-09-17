//! Regression tests for dock-focused keyboard and mouse input.

use super::test_fixtures::make_agent;
use super::{AgentPane, AgentView};
use crate::actions::ActionRegistry;
use crate::app::actions::Action;
use crate::app::app_view::InputOutcome;
use crate::views::dock::{DockItem, Section};
use crossterm::event::{
    Event, KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::Rect;

fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
    KeyEvent::new(code, modifiers)
}

fn mouse(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind,
        column,
        row,
        modifiers: KeyModifiers::NONE,
    }
}

fn insert_running_task(agent: &mut AgentView, task_id: &str) {
    agent.session.bg_tasks.insert(
        task_id.into(),
        crate::app::agent::BgTaskState {
            task_id: task_id.into(),
            tool_call_id: format!("call-{task_id}"),
            command: "sleep 5".into(),
            description: None,
            cwd: "/tmp".into(),
            output_file: "/tmp/out".into(),
            status: crate::app::agent::BgTaskStatus::Running,
            start_time: std::time::SystemTime::now(),
            end_time: None,
            exit_code: None,
            signal: None,
            stdout: String::new(),
            stdout_line_count: 0,
            truncated: false,
            pending_kill: false,
            kill_requested_at: None,
            scrollback_entry_id: None,
            is_monitor: false,
            restored_from_replay: false,
        },
    );
}

fn insert_running_subagent(agent: &mut AgentView, child_session_id: &str) {
    let info = super::test_fixtures::running_subagent_info(child_session_id);
    agent
        .subagent_sessions
        .insert(child_session_id.to_string(), info);
}

/// A dock that paints a Tasks section with one running command.
fn dock_with_task() -> AgentView {
    let mut agent = make_agent();
    insert_running_task(&mut agent, "bg-1");
    agent.dock_shown = true;
    agent.dock_on = true;
    agent.active_pane = AgentPane::Dock;
    agent
}

fn ctrl_g(agent: &mut AgentView) -> InputOutcome {
    agent.handle_input(
        &Event::Key(key(KeyCode::Char('g'), KeyModifiers::CONTROL)),
        &ActionRegistry::defaults(),
    )
}

// ---------------------------------------------------------------- U024: an on
// but unpainted dock swallows its own keys and opens no legacy pane.

#[test]
fn ctrl_q_while_dock_focused_is_unchanged() {
    let mut agent = dock_with_task();
    let outcome = agent.handle_dock_key(&key(KeyCode::Char('q'), KeyModifiers::CONTROL));
    assert!(
        matches!(outcome, InputOutcome::Unchanged),
        "Ctrl+Q must bubble to global Quit, got {outcome:?}"
    );
    assert_eq!(agent.active_pane, AgentPane::Dock);
}

#[test]
fn ctrl_x_while_dock_focused_is_unchanged() {
    let mut agent = dock_with_task();
    let outcome = agent.handle_dock_key(&key(KeyCode::Char('x'), KeyModifiers::CONTROL));
    assert!(
        matches!(outcome, InputOutcome::Unchanged),
        "Ctrl+X must not take the kill arm, got {outcome:?}"
    );
}

#[test]
fn unmodified_q_unfocuses_dock() {
    let mut agent = dock_with_task();
    let outcome = agent.handle_dock_key(&key(KeyCode::Char('q'), KeyModifiers::NONE));
    assert!(matches!(outcome, InputOutcome::Changed));
    assert_eq!(agent.active_pane, AgentPane::Scrollback);
}

#[test]
fn unmodified_x_kills_selected_task() {
    let mut agent = dock_with_task();
    agent.dock_cursor = agent
        .dock_items()
        .iter()
        .position(|item| matches!(item, DockItem::Row(Section::Tasks, 0)))
        .expect("expanded Tasks section has a row");
    let outcome = agent.handle_dock_key(&key(KeyCode::Char('x'), KeyModifiers::NONE));
    assert!(matches!(
        outcome,
        InputOutcome::Action(Action::KillBgTask(id)) if id == "bg-1"
    ));
}

#[test]
fn hidden_dock_does_not_navigate_or_kill() {
    let mut agent = dock_with_task();
    agent.dock_shown = false;
    let outcome = agent.handle_dock_key(&key(KeyCode::Char('j'), KeyModifiers::NONE));
    assert!(matches!(outcome, InputOutcome::Unchanged));
    assert_eq!(agent.dock_cursor, 0);

    let outcome = agent.handle_dock_key(&key(KeyCode::Char('x'), KeyModifiers::NONE));
    assert!(
        !matches!(outcome, InputOutcome::Action(_)),
        "x on a hidden dock must not kill, got {outcome:?}"
    );
}

#[test]
fn toggle_tasks_does_not_open_hidden_pane_when_dock_on_but_empty() {
    let mut agent = make_agent();
    agent.dock_on = true;
    agent.dock_shown = false;
    agent.tasks.overlay.visible = false;
    let registry = ActionRegistry::defaults();
    let outcome = agent.handle_input(
        &Event::Key(key(KeyCode::Char('g'), KeyModifiers::CONTROL)),
        &registry,
    );
    assert!(matches!(outcome, InputOutcome::Unchanged));
    assert!(!agent.tasks.overlay.visible);
    assert_ne!(agent.active_pane, AgentPane::Tasks);
}

#[test]
fn toggle_tasks_still_toggles_legacy_pane_when_dock_off() {
    let mut agent = make_agent();
    agent.dock_on = false;
    agent.dock_shown = false;
    let registry = ActionRegistry::defaults();
    let outcome = agent.handle_input(
        &Event::Key(key(KeyCode::Char('g'), KeyModifiers::CONTROL)),
        &registry,
    );
    assert!(matches!(outcome, InputOutcome::Changed));
    assert!(agent.tasks.overlay.visible);
    assert_eq!(agent.active_pane, AgentPane::Tasks);
}

#[test]
fn toggle_queue_does_not_open_hidden_pane_when_dock_on_but_empty() {
    let mut agent = make_agent();
    agent.dock_on = true;
    agent.dock_shown = false;
    agent.queue.overlay.visible = false;
    agent
        .session
        .pending_prompts
        .push_back(crate::app::agent::QueuedPrompt::plain(
            1,
            "queued",
            crate::app::agent::QueueEntryKind::Prompt,
        ));
    let registry = ActionRegistry::defaults();
    let outcome = agent.handle_input(
        &Event::Key(key(KeyCode::Char(';'), KeyModifiers::CONTROL)),
        &registry,
    );
    assert!(
        matches!(outcome, InputOutcome::Unchanged),
        "empty dock must not toggle the suppressed queue pane, got {outcome:?}"
    );
    assert!(!agent.queue.overlay.visible);
}

// ---------------------------------------------------------------- U107: Ctrl+G
// hides and shows the dock; hiding returns focus to the scrollback.

#[test]
fn ctrl_g_hides_and_shows_dock_from_prompt() {
    let mut agent = dock_with_task();
    agent.active_pane = AgentPane::Prompt;
    assert!(matches!(ctrl_g(&mut agent), InputOutcome::Changed));
    assert!(agent.dock_hidden);
    assert_eq!(agent.active_pane, AgentPane::Prompt);
    assert!(!agent.tasks.overlay.visible);
    assert!(matches!(ctrl_g(&mut agent), InputOutcome::Changed));
    assert!(!agent.dock_hidden);
    assert_eq!(agent.active_pane, AgentPane::Prompt);
}

#[test]
fn ctrl_g_hides_shown_dock_when_dock_focused() {
    let mut agent = dock_with_task();
    assert_eq!(agent.active_pane, AgentPane::Dock);
    assert!(matches!(ctrl_g(&mut agent), InputOutcome::Changed));
    assert!(agent.dock_hidden);
    assert_eq!(agent.active_pane, AgentPane::Scrollback);
}

// ---------------------------------------------------------------- U106: Tab
// treats the whole dock as one stop.

#[test]
fn tab_cycles_scrollback_to_dock_to_prompt() {
    let mut agent = make_agent();
    insert_running_subagent(&mut agent, "child-1");
    insert_running_task(&mut agent, "bg-1");
    agent.dock_shown = true;
    agent.dock_on = true;
    agent.vim_mode = true;
    agent.active_pane = AgentPane::Scrollback;
    agent.dock_cursor = agent
        .dock_items()
        .iter()
        .position(|item| *item == DockItem::Header(Section::Tasks))
        .expect("tasks header");
    let registry = ActionRegistry::defaults();

    let outcome = agent.handle_scrollback_key(&key(KeyCode::Tab, KeyModifiers::NONE), &registry);
    assert!(matches!(outcome, InputOutcome::Changed));
    assert_eq!(agent.active_pane, AgentPane::Dock);
    assert_eq!(
        agent.dock_items().get(agent.dock_cursor).copied(),
        Some(DockItem::Header(Section::Subagents)),
        "Tab lands on the first dock item, not the section it last walked to"
    );

    let outcome = agent.handle_dock_key(&key(KeyCode::Tab, KeyModifiers::NONE));
    assert!(matches!(outcome, InputOutcome::Action(Action::FocusPrompt)));
}

#[test]
fn tab_from_dock_is_one_stop() {
    let mut agent = dock_with_task();
    insert_running_subagent(&mut agent, "child-1");
    agent.dock_cursor = agent
        .dock_items()
        .iter()
        .position(|item| *item == DockItem::Header(Section::Tasks))
        .expect("tasks header");

    let outcome = agent.handle_dock_key(&key(KeyCode::Tab, KeyModifiers::NONE));
    assert!(
        matches!(outcome, InputOutcome::Action(Action::FocusPrompt)),
        "Tab inside the dock must leave it, not walk to the next header: {outcome:?}"
    );

    let outcome = agent.handle_dock_key(&key(KeyCode::BackTab, KeyModifiers::NONE));
    assert!(matches!(outcome, InputOutcome::Changed));
    assert_eq!(agent.active_pane, AgentPane::Scrollback);
}

#[test]
fn tab_from_scrollback_skips_dock_when_hidden() {
    let mut agent = dock_with_task();
    agent.vim_mode = true;
    agent.dock_hidden = true;
    agent.active_pane = AgentPane::Scrollback;
    let registry = ActionRegistry::defaults();
    let outcome = agent.handle_scrollback_key(&key(KeyCode::Tab, KeyModifiers::NONE), &registry);
    assert!(
        matches!(outcome, InputOutcome::Action(Action::FocusPrompt)),
        "a Ctrl+G-hidden dock stays out of the Tab cycle, got {outcome:?}"
    );
}

// ---------------------------------------------------------------- U113: loop
// rows say when the next run is due.

#[test]
fn dock_loop_meta_includes_cadence_and_next_trigger() {
    let mut agent = make_agent();
    let next = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();
    agent.session.scheduled_tasks.insert(
        "loop-1".into(),
        crate::app::agent::ScheduledTaskInfo {
            task_id: "loop-1".into(),
            prompt: "check CI".into(),
            human_schedule: "every 30 minutes".into(),
            created_at: std::time::Instant::now(),
            next_fire_at: Some(next),
            tag: "loop".into(),
            last_subagent_id: None,
        },
    );
    let rows = agent.dock_watcher_rows();
    let meta = &rows.first().expect("loop row").1.meta;
    assert!(
        meta.starts_with("every 30 minutes (next in ") && !meta.contains("due now"),
        "{meta}"
    );
}

// ---------------------------------------------------------------- U118: a
// click that collapses a section must not leave the header selected.

fn header_row(agent: &AgentView, section: Section) -> u16 {
    agent
        .dock_items()
        .iter()
        .position(|item| *item == DockItem::Header(section))
        .expect("section header") as u16
}

fn painted_header_bg(agent: &AgentView, section: Section) -> Option<ratatui::style::Color> {
    let theme = crate::theme::Theme::tokyonight();
    let data = agent.dock_snapshot();
    let area = Rect::new(0, 0, 80, crate::views::dock::desired_height(&data));
    let mut buf = ratatui::buffer::Buffer::empty(area);
    crate::views::dock::render(&mut buf, area, &theme, &data);
    buf.cell((0, header_row(agent, section))).map(|c| c.bg)
}

#[test]
fn clicking_a_section_header_clears_selection_after_collapse() {
    let mut agent = dock_with_task();
    agent.active_pane = AgentPane::Prompt;
    agent.pane_areas.dock = Rect::new(0, 4, 80, 8);
    let tasks = Section::Tasks;
    let y = agent.pane_areas.dock.y + header_row(&agent, tasks);

    let outcome = agent.handle_mouse(&mouse(MouseEventKind::Down(MouseButton::Left), 5, y));
    assert!(matches!(outcome, InputOutcome::Changed));
    assert!(!agent.dock_tasks_expanded);
    assert_eq!(agent.active_pane, AgentPane::Prompt);
    assert!(!agent.dock_snapshot().focused);

    let _ = agent.handle_mouse(&mouse(MouseEventKind::Moved, 5, 0));
    let theme = crate::theme::Theme::tokyonight();
    assert_ne!(painted_header_bg(&agent, tasks), Some(theme.bg_highlight));

    // Clicking a collapsed header expands it and does focus the dock.
    let y = agent.pane_areas.dock.y + header_row(&agent, tasks);
    let outcome = agent.handle_mouse(&mouse(MouseEventKind::Down(MouseButton::Left), 5, y));
    assert!(matches!(outcome, InputOutcome::Changed));
    assert!(agent.dock_tasks_expanded);
    assert_eq!(agent.active_pane, AgentPane::Dock);
    assert!(agent.dock_snapshot().focused);
}

#[test]
fn clicking_a_focused_section_header_returns_to_prompt() {
    let mut agent = dock_with_task();
    agent.pane_areas.dock = Rect::new(0, 4, 80, 8);
    let tasks = Section::Tasks;
    let y = agent.pane_areas.dock.y + header_row(&agent, tasks);

    assert_eq!(agent.active_pane, AgentPane::Dock);
    let outcome = agent.handle_mouse(&mouse(MouseEventKind::Down(MouseButton::Left), 5, y));
    assert!(matches!(outcome, InputOutcome::Changed));
    assert!(!agent.dock_tasks_expanded);
    assert_eq!(agent.active_pane, AgentPane::Prompt);
    assert!(!agent.dock_snapshot().focused);
    let _ = agent.handle_mouse(&mouse(MouseEventKind::Moved, 5, 0));
    assert_ne!(
        painted_header_bg(&agent, tasks),
        Some(crate::theme::Theme::tokyonight().bg_highlight)
    );
}

#[test]
fn keyboard_collapse_keeps_dock_focus_on_the_header() {
    let mut agent = dock_with_task();
    assert!(agent.dock_tasks_expanded);
    let outcome = agent.handle_dock_key(&key(KeyCode::Left, KeyModifiers::NONE));
    assert!(matches!(outcome, InputOutcome::Changed));
    assert!(!agent.dock_tasks_expanded);
    assert_eq!(agent.active_pane, AgentPane::Dock);
    assert!(agent.dock_snapshot().focused);
    assert_eq!(
        painted_header_bg(&agent, Section::Tasks),
        Some(crate::theme::Theme::tokyonight().bg_highlight)
    );
}

// ---------------------------------------------------------------- U115: the
// running workflow is a clickable dock row.

fn workflow_run(
    run_id: &str,
    name: &str,
    status: &str,
) -> crate::views::workflows::WorkflowRunSnapshot {
    crate::views::workflows::WorkflowRunSnapshot {
        run_id: run_id.to_owned(),
        name: name.to_owned(),
        objective: "obj".to_owned(),
        status: status.to_owned(),
        management_available: true,
        builtin: false,
        phases: Vec::new(),
        current_phase: Some("Verify".to_owned()),
        agents: vec![crate::views::workflows::WorkflowAgentRowView {
            agent_id: "a1".into(),
            label: "one".into(),
            phase: Some("Verify".into()),
            model: None,
            state: "running".into(),
            tokens_used: 0,
            duration_ms: 0,
        }],
        agent_budget: None,
        agents_used: 0,
        agents_reserved: 0,
        agents_remaining: None,
        agent_usage_incomplete: false,
        active_agents: 1,
        elapsed_ms: 5_000,
        received_at: std::time::Instant::now(),
        pause_message: None,
        result_summary: None,
    }
}

fn dock_with_workflow() -> AgentView {
    let mut agent = make_agent();
    agent
        .workflow_runs
        .push(workflow_run("wf-1", "learn-traces-2", "active"));
    agent.session.scheduled_tasks.insert(
        "loop-1".into(),
        crate::app::agent::ScheduledTaskInfo {
            task_id: "loop-1".into(),
            prompt: "check CI".into(),
            human_schedule: "every 5m".into(),
            created_at: std::time::Instant::now(),
            next_fire_at: None,
            tag: "loop".into(),
            last_subagent_id: None,
        },
    );
    agent.dock_shown = true;
    agent.dock_on = true;
    agent.active_pane = AgentPane::Dock;
    agent
}

fn workflow_row_index(agent: &AgentView) -> usize {
    agent
        .dock_items()
        .iter()
        .position(|item| matches!(item, DockItem::Row(Section::Workflows, 0)))
        .expect("workflow row")
}

#[test]
fn hidden_dock_keeps_the_running_workflow_status_cue() {
    let mut agent = dock_with_workflow();
    assert_eq!(agent.watchers().workflows, 1);
    assert!(agent.dock_covers_idle_cues(true));
    agent.dock_hidden = true;
    assert!(!agent.dock_covers_idle_cues(true));
    assert_eq!(agent.watchers().workflows, 1);
}

#[test]
fn running_workflow_is_a_dock_row_above_watchers() {
    let agent = dock_with_workflow();
    let items = agent.dock_items();
    assert_eq!(items.first(), Some(&DockItem::Header(Section::Workflows)));
    assert_eq!(items.get(1), Some(&DockItem::Row(Section::Workflows, 0)));
    assert!(
        items.contains(&DockItem::Header(Section::Watchers)),
        "watchers stay after the workflow row: {items:?}"
    );
    let (run_id, row) = agent
        .dock_workflow_rows()
        .into_iter()
        .next()
        .expect("workflow row");
    assert_eq!(run_id, "wf-1");
    assert_eq!(row.kind, "Workflow");
    assert_eq!(row.description, "learn-traces-2");
    assert_eq!(row.activity.as_deref(), Some("Verify \u{b7} 1 agent"));
    assert!(row.openable && row.killable && row.spinning);
}

#[test]
fn terminal_workflow_is_hidden_from_the_dock() {
    let mut agent = make_agent();
    agent
        .workflow_runs
        .push(workflow_run("wf-done", "old-scan", "complete"));
    agent.dock_shown = true;
    agent.dock_on = true;
    assert!(agent.dock_workflow_rows().is_empty());
    assert!(!agent.dock_items().iter().any(|item| {
        matches!(
            item,
            DockItem::Header(Section::Workflows) | DockItem::Row(Section::Workflows, _)
        )
    }));
}

#[test]
fn enter_on_workflow_row_opens_the_active_run() {
    let mut agent = dock_with_workflow();
    agent.dock_cursor = workflow_row_index(&agent);
    let outcome = agent.handle_dock_key(&key(KeyCode::Enter, KeyModifiers::NONE));
    assert!(matches!(outcome, InputOutcome::Changed));
    assert!(agent.show_workflows);
    assert_eq!(agent.workflows_view.detail_run_id.as_deref(), Some("wf-1"));
    assert_eq!(
        agent.workflows_view.selected_run_id.as_deref(),
        Some("wf-1")
    );
}

#[test]
fn x_on_workflow_row_stops_the_run() {
    let mut agent = dock_with_workflow();
    agent.dock_cursor = workflow_row_index(&agent);
    let outcome = agent.handle_dock_key(&key(KeyCode::Char('x'), KeyModifiers::NONE));
    assert!(matches!(
        outcome,
        InputOutcome::Action(Action::SendSlashCommandPreservingDraft(ref command))
            if command == "/workflow stop learn-traces-2"
    ));
}

#[test]
fn clicking_a_workflow_row_opens_the_run() {
    let mut agent = dock_with_workflow();
    agent.pane_areas.dock = Rect::new(0, 4, 80, 8);
    let y = agent.pane_areas.dock.y + workflow_row_index(&agent) as u16;
    let outcome = agent.handle_mouse(&mouse(MouseEventKind::Down(MouseButton::Left), 5, y));
    assert!(matches!(outcome, InputOutcome::Changed));
    assert!(agent.show_workflows);
    assert_eq!(agent.workflows_view.detail_run_id.as_deref(), Some("wf-1"));
}
