//! `/density`: choose how much of each tool call the transcript shows.
//!
//! `/density compact` folds every tool call to its header line, `/density detailed` unfolds them, and bare `/density` flips between the two.
//! The choice also applies to tool calls that arrive later in the session.

use crate::app::actions::Action;
use crate::slash::command::{CommandExecCtx, CommandResult, SlashCommand, slash_meta};

/// Set tool-call density via `/density`.
pub struct DensityCommand;

/// Parse the `/density` argument: `None` toggles, `Some(true)` is compact, `Some(false)` is detailed.
fn parse_density(args: &str) -> Result<Option<bool>, ()> {
    match args.trim().to_ascii_lowercase().as_str() {
        "" => Ok(None),
        "compact" | "collapsed" => Ok(Some(true)),
        "detailed" | "expanded" | "full" => Ok(Some(false)),
        _ => Err(()),
    }
}

impl SlashCommand for DensityCommand {
    slash_meta! {
        name: "density",
        description: "Set tool call density (compact or detailed)",
        usage: "/density [compact|detailed]",
    }

    fn run(&self, _ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        match parse_density(args) {
            Ok(compact) => CommandResult::Action(Action::SetToolDensity(compact)),
            Err(()) => CommandResult::Error("Usage: /density [compact|detailed]".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_three_forms() {
        assert_eq!(parse_density(""), Ok(None));
        assert_eq!(parse_density(" Compact "), Ok(Some(true)));
        assert_eq!(parse_density("detailed"), Ok(Some(false)));
        assert_eq!(parse_density("loud"), Err(()));
    }
}
