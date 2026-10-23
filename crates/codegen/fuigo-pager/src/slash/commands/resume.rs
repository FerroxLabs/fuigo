//! `/resume`: open the session picker overlay to resume a previous session.
//! `/resume <id or name>` opens the one session the text names, else the picker filtered by it.

use crate::app::actions::Action;
use crate::slash::command::{CommandExecCtx, CommandResult, SlashCommand, slash_meta};

pub struct ResumeCommand;

impl SlashCommand for ResumeCommand {
    slash_meta! {
        name: "resume",
        description: "Resume a previous session (/resume [id or name])",
        usage: "/resume [id or name]",
        takes_args: true,
        arg_placeholder: "[id or name]",
    }

    fn run(&self, _ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        match args.trim() {
            "" => CommandResult::Action(Action::ShowSessionPicker),
            query => CommandResult::Action(Action::ResumeByQuery(query.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acp::model_state::ModelState;

    static DEFAULT_BUNDLE_STATE: crate::app::bundle::BundleState = crate::app::bundle::BundleState {
        has_cache: false,
        version: String::new(),
        personas: Vec::new(),
        roles: Vec::new(),
        agents: Vec::new(),
        skills: Vec::new(),
        persona_details: Vec::new(),
        role_details: Vec::new(),
    };

    fn run(args: &str) -> CommandResult {
        let models = ModelState::default();
        let mut ctx = CommandExecCtx {
            models: &models,
            session_id: None,
            bundle_state: &DEFAULT_BUNDLE_STATE,
            screen_mode: crate::app::ScreenMode::Inline,
            billing_surface_visible: true,
            usage_command_visible: true,
            pager_state: crate::settings::PagerLocalSnapshot::default(),
        };
        ResumeCommand.run(&mut ctx, args)
    }

    #[test]
    fn bare_resume_opens_the_picker() {
        assert!(matches!(run(""), CommandResult::Action(Action::ShowSessionPicker)));
        assert!(matches!(run("   "), CommandResult::Action(Action::ShowSessionPicker)));
    }

    #[test]
    fn resume_with_text_resumes_by_that_text() {
        match run("  fix login ") {
            CommandResult::Action(Action::ResumeByQuery(q)) => assert_eq!(q, "fix login"),
            other => panic!("expected ResumeByQuery, got {other:?}"),
        }
    }

    #[test]
    fn resume_takes_an_optional_argument() {
        assert!(ResumeCommand.takes_args());
        assert_eq!(ResumeCommand.usage(), "/resume [id or name]");
    }
}
