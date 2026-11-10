//! `/vim-mode`: choose how much of the interface uses vim keys.
//!
//! - `/vim-mode` (no argument) toggles vim-style scrollback keybindings, as before.
//! - `/vim-mode nav` is scrollback vim only; `/vim-mode off` is none.
//! - `/vim-mode all` adds full Vim editing in the prompt: Insert and Normal modes with motions, operators, counts and undo.
//!
//! When scrollback vim is off (the default), bare-letter and Shift+letter keys in the scrollback jump focus to the prompt so the letter is typed into the textarea.
//! That covers j/k, h/l, g/G, y/Y, o/O, r, x, e/E, L/H, and the `i` insert alternative.
//! Arrow/Tab/Esc/Space/PgUp/PgDn and all Ctrl+letter bindings stay active in every mode.

use crate::app::actions::{Action, VimLevel};
use crate::slash::command::{
    AppCtx, ArgItem, CommandExecCtx, CommandResult, SlashCommand, slash_meta,
};

pub struct VimModeCommand;

const USAGE: &str = "Usage: /vim-mode [all|nav|off]";

impl SlashCommand for VimModeCommand {
    slash_meta! {
        name: "vim-mode",
        description: "Vim keys: all (prompt editing too), nav (scrollback only), off; bare toggles scrollback",
        usage: "/vim-mode [all|nav|off]",
        takes_args: true,
    }

    fn suggest_args(&self, _ctx: &AppCtx, _args_query: &str) -> Option<Vec<ArgItem>> {
        let item = |name: &str, description: &str| ArgItem {
            display: name.to_string(),
            match_text: name.to_string(),
            insert_text: name.to_string(),
            description: description.to_string(),
        };
        Some(vec![
            item("all", "Vim editing in the prompt, plus scrollback keys"),
            item("nav", "Vim keys in the scrollback only"),
            item("off", "No vim keys"),
        ])
    }

    fn run(&self, _ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        let args = args.trim();
        if args.is_empty() {
            return CommandResult::Action(Action::ToggleVimMode);
        }
        match VimLevel::parse(args) {
            Some(level) => CommandResult::Action(Action::SetVimLevel(level)),
            None => CommandResult::Error(USAGE.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_three_levels_case_insensitively() {
        assert_eq!(VimLevel::parse("all"), Some(VimLevel::All));
        assert_eq!(VimLevel::parse(" Nav "), Some(VimLevel::Nav));
        assert_eq!(VimLevel::parse("OFF"), Some(VimLevel::Off));
        assert_eq!(VimLevel::parse("on"), None);
        assert_eq!(VimLevel::parse(""), None);
    }

    #[test]
    fn level_round_trips_through_its_config_value() {
        for level in [VimLevel::Off, VimLevel::Nav, VimLevel::All] {
            assert_eq!(VimLevel::parse(level.as_str()), Some(level));
        }
    }
}
