//! Prompt vim (`[keys] vim = "all"`) at the agent-view level: the Esc meanings, key routing, and the NORMAL/INSERT info-line label.
use super::test_fixtures::make_agent;
use super::{AgentPane, AgentView, AppRenderParams, BannerSlotParams};
use crate::actions::ActionRegistry;
use crate::app::actions::Action;
use crate::app::agent::AgentState;
use crate::app::app_view::InputOutcome;
use crate::app::bundle::BundleState;
use crate::scrollback::render::ScratchBuffer;
use crate::views::prompt_widget::VimMode;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

/// Pins the prompt-vim flag for one test and restores it afterwards.
struct PromptVimGuard(bool);

impl PromptVimGuard {
    fn set(enabled: bool) -> Self {
        let previous = crate::appearance::cache::load_vim_prompt();
        crate::appearance::cache::set_vim_prompt(enabled);
        Self(previous)
    }
}

impl Drop for PromptVimGuard {
    fn drop(&mut self) {
        crate::appearance::cache::set_vim_prompt(self.0);
    }
}

fn agent() -> AgentView {
    let mut agent = make_agent();
    agent.active_pane = AgentPane::Prompt;
    agent
}

fn press(agent: &mut AgentView, code: KeyCode, mods: KeyModifiers) -> InputOutcome {
    agent.handle_prompt_key_for_test(&KeyEvent::new(code, mods))
}

fn type_keys(agent: &mut AgentView, keys: &str) {
    for c in keys.chars() {
        let mods = if c.is_uppercase() {
            KeyModifiers::SHIFT
        } else {
            KeyModifiers::NONE
        };
        let _ = press(agent, KeyCode::Char(c), mods);
    }
}

fn esc(agent: &mut AgentView) -> InputOutcome {
    press(agent, KeyCode::Esc, KeyModifiers::NONE)
}

fn render_text(agent: &mut AgentView) -> String {
    let reg = ActionRegistry::defaults();
    let area = Rect::new(0, 0, 100, 40);
    let mut buf = Buffer::empty(area);
    let mut scratch = ScratchBuffer::new();
    let _ = agent.draw(
        area,
        &mut buf,
        &reg,
        &mut scratch,
        None,
        false,
        BannerSlotParams::none(),
        &BundleState::default(),
        false,
        false,
        &mut Vec::new(),
        AppRenderParams::default(),
    );
    (0..area.height)
        .map(|y| {
            (0..area.width)
                .filter_map(|x| buf.cell((x, y)).map(|c| c.symbol().to_string()))
                .collect::<String>()
                + "\n"
        })
        .collect()
}

#[test]
fn esc_in_insert_switches_to_normal_and_normal_esc_stays() {
    let _g = PromptVimGuard::set(true);
    let mut a = agent();
    a.prompt.set_text("draft");
    assert_eq!(a.prompt.vim_mode(), VimMode::Insert);
    assert!(matches!(esc(&mut a), InputOutcome::Changed));
    assert_eq!(a.prompt.vim_mode(), VimMode::Normal);
    // Esc in Normal mode is swallowed: no clear arm, no rewind arm, nothing
    assert!(matches!(esc(&mut a), InputOutcome::Changed));
    assert_eq!(a.prompt.vim_mode(), VimMode::Normal);
    assert_eq!(a.prompt.text(), "draft");
}

#[test]
fn esc_never_cancels_or_hints_mid_turn_with_vim_on() {
    let _g = PromptVimGuard::set(true);
    let mut a = agent();
    a.session.state = AgentState::TurnRunning;
    a.prompt.set_text("draft");
    for _ in 0..3 {
        let outcome = a.handle_input(
            &Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            &ActionRegistry::defaults(),
        );
        assert!(matches!(outcome, InputOutcome::Changed), "{outcome:?}");
    }
    assert_eq!(a.prompt.vim_mode(), VimMode::Normal);
    assert_eq!(a.prompt.text(), "draft", "the draft is kept");
    assert!(
        a.active_toast_message().is_none(),
        "the mid-turn hint belongs to the Esc policy, which vim Esc bypasses"
    );
}

#[test]
fn vim_off_esc_keeps_its_existing_meaning() {
    let _g = PromptVimGuard::set(false);
    let mut a = agent();
    a.session.state = AgentState::TurnRunning;
    a.prompt.set_text("draft");
    let outcome = a.handle_input(
        &Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
        &ActionRegistry::defaults(),
    );
    assert!(matches!(outcome, InputOutcome::Changed), "{outcome:?}");
    // The mid-turn Esc still points at the cancel key, and the mode never leaves Insert
    assert_eq!(
        Some("Press Ctrl+c to cancel the turn"),
        a.active_toast_message()
    );
    assert_eq!(a.prompt.vim_mode(), VimMode::Insert);
}

#[test]
fn vim_off_typing_and_letters_are_unchanged() {
    let _g = PromptVimGuard::set(false);
    let mut a = agent();
    type_keys(&mut a, "dd");
    assert_eq!(a.prompt.text(), "dd", "letters type when prompt vim is off");
    let _ = esc(&mut a);
    type_keys(&mut a, "x");
    assert_eq!(a.prompt.text(), "ddx");
    assert_eq!(a.prompt.vim_mode(), VimMode::Insert);
}

#[test]
fn normal_mode_commands_edit_the_prompt() {
    let _g = PromptVimGuard::set(true);
    let mut a = agent();
    a.prompt.set_text("foo bar baz");
    a.prompt.set_cursor(0);
    let _ = esc(&mut a);
    type_keys(&mut a, "dw");
    assert_eq!(a.prompt.text(), "bar baz");
    type_keys(&mut a, "u");
    assert_eq!(a.prompt.text(), "foo bar baz");
    let _ = press(&mut a, KeyCode::Char('r'), KeyModifiers::CONTROL);
    assert_eq!(a.prompt.text(), "bar baz", "Ctrl+R redoes instead of reaching the action registry");
    type_keys(&mut a, "ihi <");
    let _ = esc(&mut a);
    assert_eq!(a.prompt.text(), "hi <bar baz");
    type_keys(&mut a, "ddix");
    assert_eq!(a.prompt.text(), "x");
}

#[test]
fn normal_mode_letters_never_type_and_bang_does_not_enter_bash_mode() {
    let _g = PromptVimGuard::set(true);
    let mut a = agent();
    let _ = esc(&mut a);
    type_keys(&mut a, "zq!");
    assert_eq!(a.prompt.text(), "");
    assert_eq!(
        a.prompt_input_mode,
        crate::app::agent_view::PromptInputMode::Normal,
        "`!` in Normal mode is not the bash-mode trigger"
    );
    // back in Insert mode it is
    type_keys(&mut a, "i!");
    assert_eq!(
        a.prompt_input_mode,
        crate::app::agent_view::PromptInputMode::Bash
    );
}

#[test]
fn enter_submits_from_normal_mode_and_tab_still_changes_focus() {
    let _g = PromptVimGuard::set(true);
    let mut a = agent();
    a.prompt.set_text("hello");
    let _ = esc(&mut a);
    assert_eq!(a.prompt.vim_mode(), VimMode::Normal);
    let outcome = press(&mut a, KeyCode::Tab, KeyModifiers::NONE);
    assert!(
        matches!(outcome, InputOutcome::Action(Action::FocusScrollback)),
        "{outcome:?}"
    );
    let outcome = press(&mut a, KeyCode::Enter, KeyModifiers::NONE);
    assert!(
        matches!(outcome, InputOutcome::Action(_)),
        "Enter in Normal mode submits as it does today, got {outcome:?}"
    );
}

#[test]
fn queued_prompt_edit_keeps_its_esc_in_normal_mode() {
    let _g = PromptVimGuard::set(true);
    let mut a = agent();
    let _ = esc(&mut a);
    assert_eq!(a.prompt.vim_mode(), VimMode::Normal);
    // Esc ends a queued-prompt edit (it is not a turn cancel), so vim does not swallow it
    a.prompt_mode = crate::app::agent_view::PromptMode::EditingQueued {
        id: 0,
        original: String::new(),
        server_id: None,
        kind: crate::app::agent::QueueEntryKind::Prompt,
    };
    let outcome = esc(&mut a);
    assert!(
        matches!(outcome, InputOutcome::Action(Action::DrainQueue)),
        "{outcome:?}"
    );
    assert!(matches!(
        a.prompt_mode,
        crate::app::agent_view::PromptMode::Normal
    ));
}

#[test]
fn info_line_shows_the_mode_label_only_with_vim_on() {
    let _g = PromptVimGuard::set(true);
    let mut a = agent();
    let text = render_text(&mut a);
    assert!(text.contains("INSERT"), "Insert label missing:\n{text}");
    assert!(!text.contains("NORMAL"));
    let _ = esc(&mut a);
    let text = render_text(&mut a);
    assert!(text.contains("NORMAL"), "Normal label missing:\n{text}");
    assert!(!text.contains("INSERT"));
    type_keys(&mut a, "i");
    assert!(render_text(&mut a).contains("INSERT"));

    crate::appearance::cache::set_vim_prompt(false);
    let text = render_text(&mut a);
    assert!(!text.contains("NORMAL") && !text.contains("INSERT"));
}

#[test]
fn info_line_shows_the_mode_label_in_minimal_mode() {
    let _g = PromptVimGuard::set(true);
    let mut a = agent();
    a.prompt.set_screen_mode(crate::app::ScreenMode::Minimal);
    assert!(render_text(&mut a).contains("INSERT"));
    let outcome = a.handle_minimal_input(
        &Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
        &ActionRegistry::defaults(),
    );
    assert!(matches!(outcome, InputOutcome::Changed), "{outcome:?}");
    assert!(render_text(&mut a).contains("NORMAL"));
}

#[test]
fn bash_mode_info_line_keeps_the_mode_label() {
    let _g = PromptVimGuard::set(true);
    let mut a = agent();
    a.prompt_input_mode = crate::app::agent_view::PromptInputMode::Bash;
    let text = render_text(&mut a);
    assert!(text.contains("INSERT"), "{text}");
}

#[test]
fn turning_vim_off_returns_the_prompt_to_plain_insert() {
    let _g = PromptVimGuard::set(true);
    let mut a = agent();
    let _ = esc(&mut a);
    assert_eq!(a.prompt.vim_mode(), VimMode::Normal);
    crate::appearance::cache::set_vim_prompt(false);
    type_keys(&mut a, "ab");
    assert_eq!(a.prompt.text(), "ab", "keys type again once vim is off");
    assert_eq!(a.prompt.vim_mode(), VimMode::Insert);
}
