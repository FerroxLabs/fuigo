//! `/stoke` -- hidden easter egg. Opens a full-screen demoscene fire with the Wind mark.
//!
//! Never listed in `/help` or the slash dropdown (`visible()` is false) but executes when typed exactly as `/stoke`;
//! with any argument it passes through like an unknown command, so only the bare invocation triggers.

use crate::app::actions::Action;
use crate::slash::command::{AppCtx, CommandExecCtx, CommandResult, SlashCommand, slash_meta};

/// Hidden STOKE easter egg.
pub struct StokeCommand;

impl SlashCommand for StokeCommand {
    slash_meta! {
        name: "stoke",
        // Never shown: the command is hidden from the dropdown.
        description: "Hidden easter egg",
        usage: "/stoke",
        // Needs an agent view to render in.
        session_scoped: true,
    }

    /// Easter egg: typeable, never listed.
    fn visible(&self, _ctx: &AppCtx) -> bool {
        false
    }

    fn run(&self, _ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        if !args.trim().is_empty() {
            return CommandResult::PassThrough(format!("/stoke {args}"));
        }
        CommandResult::Action(Action::OpenStoke)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acp::model_state::ModelState;
    use crate::slash::commands::{builtin_commands, tests::make_ctx};
    use crate::slash::registry::CommandRegistry;
    use crate::slash::{SlashController, SlashState};

    #[test]
    fn stoke_is_invisible_but_registered() {
        let models = ModelState::default();
        let ctx = AppCtx {
            models: &models,
            cwd: std::path::Path::new("."),
            has_session_announcements: false,
            billing_surface_visible: true,
            usage_command_visible: true,
            workflows_available: true,
            saved_workflows: &[],
            workflow_runs: &[],
            screen_mode: crate::app::ScreenMode::Fullscreen,
            current_title: None,
        };
        assert!(!StokeCommand.visible(&ctx), "/stoke must never be listed");
        let reg = CommandRegistry::new(builtin_commands());
        assert_eq!(
            reg.get_for_dispatch("stoke").map(|c| c.name()),
            Some("stoke"),
            "/stoke must still resolve for dispatch"
        );
    }

    #[test]
    fn stoke_is_absent_from_autocomplete() {
        let models = ModelState::default();
        for query in ["/", "/s", "/st", "/sto", "/stoke"] {
            let mut ctrl = SlashController::with_builtins(std::path::PathBuf::from("."));
            let state = SlashState::default();
            ctrl.refresh(&state, query, query.len(), &models);
            assert!(
                !state
                    .snapshot()
                    .matches
                    .iter()
                    .any(|row| row.display.contains("stoke")),
                "{query:?} must not suggest /stoke"
            );
        }
    }

    #[test]
    fn bare_stoke_opens_the_fire() {
        let models = ModelState::default();
        let mut ctx = make_ctx(&models);
        assert!(matches!(
            StokeCommand.run(&mut ctx, ""),
            CommandResult::Action(Action::OpenStoke)
        ));
        assert!(matches!(
            StokeCommand.run(&mut ctx, "   "),
            CommandResult::Action(Action::OpenStoke)
        ));
    }

    #[test]
    fn stoke_with_args_passes_through() {
        let models = ModelState::default();
        let mut ctx = make_ctx(&models);
        match StokeCommand.run(&mut ctx, "the fire") {
            CommandResult::PassThrough(text) => assert_eq!(text, "/stoke the fire"),
            other => panic!("expected PassThrough, got {other:?}"),
        }
    }
}
