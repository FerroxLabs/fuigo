//! `/delete`: delete this session's history (welcome, or dashboard when attached).

use crate::app::actions::Action;
use crate::slash::command::{CommandExecCtx, CommandResult, SlashCommand, slash_meta};

pub struct DeleteCommand;

impl SlashCommand for DeleteCommand {
    slash_meta! {
        name: "delete",
        description: "Delete this session",
        usage: "/delete",
        session_scoped: true,
    }

    fn run(&self, ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        // Text after the command is not a confirmation or a target: refusing it beats deleting the session it was not meant for
        if !args.trim().is_empty() {
            return CommandResult::Error("/delete takes no arguments; run /delete on its own to delete this session".into());
        }
        if ctx.session_id.is_none() {
            return CommandResult::Error("No active session to delete".into());
        }
        CommandResult::Action(Action::DeleteCurrentSession)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acp::model_state::ModelState;
    use crate::app::bundle::BundleState;

    fn run_with(args: &str, session: Option<&agent_client_protocol::SessionId>) -> CommandResult {
        let (models, bundle) = (ModelState::default(), BundleState::default());
        let mut ctx = CommandExecCtx {
            models: &models,
            session_id: session,
            bundle_state: &bundle,
            screen_mode: crate::app::ScreenMode::Inline,
            billing_surface_visible: true,
            usage_command_visible: true,
            pager_state: crate::settings::PagerLocalSnapshot {
                multiline_mode: false,
                yolo_mode: false,
                ..crate::settings::PagerLocalSnapshot::default()
            },
        };
        DeleteCommand.run(&mut ctx, args)
    }

    #[test]
    fn bare_delete_deletes_the_session() {
        let sid = agent_client_protocol::SessionId::new("s1");
        assert!(matches!(run_with("", Some(&sid)), CommandResult::Action(Action::DeleteCurrentSession)));
        assert!(matches!(run_with("   ", Some(&sid)), CommandResult::Action(Action::DeleteCurrentSession)));
    }

    #[test]
    fn delete_with_extra_text_is_an_error_not_a_deletion() {
        let sid = agent_client_protocol::SessionId::new("s1");
        for args in ["now", "s1", "--force please"] {
            match run_with(args, Some(&sid)) {
                CommandResult::Error(message) => assert!(message.contains("/delete"), "{message}"),
                other => panic!("`/delete {args}` must not delete anything, got {other:?}"),
            }
        }
    }
}
