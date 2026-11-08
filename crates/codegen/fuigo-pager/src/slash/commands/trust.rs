//! F11 `/trust`: open the folder trust screens (this folder's status, trust or stop trusting it, the trusted-folder
//! list). The full-screen app only: ACP clients and headless runs keep the shell's `/trust` (`/hooks-trust`).

use crate::app::actions::Action;
use crate::slash::command::{CommandExecCtx, CommandResult, SlashCommand, slash_meta};

pub struct TrustCommand;

impl SlashCommand for TrustCommand {
    slash_meta! {
        name: "trust",
        description: "See and manage folder trust: this folder, trust or stop trusting it, and your trusted folders",
        usage: "/trust",
        session_scoped: true,
    }

    fn run(&self, ctx: &mut CommandExecCtx, _args: &str) -> CommandResult {
        if ctx.session_id.is_none() {
            return CommandResult::Error("No active session".to_string());
        }
        CommandResult::Action(Action::OpenFolderTrust)
    }
}
