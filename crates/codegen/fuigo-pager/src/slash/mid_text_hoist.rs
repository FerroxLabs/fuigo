//! Recognizes an opted-in `/command` token that begins a submission once its leading image chips are stripped
//! (`[Image #1] /btw q` arrives as ` /btw q`), and rewrites it to `/command <message-without-token>`.
//! The caller decides what counts as a plain submission (raw text not starting with `/`).
//! A token later in the text is not an invocation: the message goes to the main conversation as typed.

use crate::slash::registry::CommandRegistry;
use crate::slash::scan_inline_slash_tokens;

/// `None` means "not a mid-text invocation"; the caller dispatches `text` unchanged.
#[must_use]
pub(crate) fn hoist_mid_text_command(text: &str, registry: &CommandRegistry) -> Option<String> {
    let (token, command) = scan_inline_slash_tokens(text, 0)
        .into_iter()
        .find_map(|token| {
            // A command starts a side question only when it begins the message; later in the text it is plain text
            if !text.get(..token.range.start)?.trim().is_empty() {
                return None;
            }
            let command = registry.get_for_dispatch(&token.name)?;
            command
                .can_hoist_from_mid_text()
                .then_some((token, command))
        })?;
    // Scanner ranges index this same text; `get` keeps the submit path panic-free regardless.
    let before = text.get(..token.range.start)?;
    // Only the whitespace run after the token goes with it, so a newline before it survives.
    let after = text.get(token.range.end..)?.trim_start();
    let question = format!("{before}{after}");
    let question = question.trim();
    if question.is_empty() {
        return None;
    }
    Some(format!("/{} {question}", command.name()))
}

#[cfg(test)]
#[path = "mid_text_hoist_tests.rs"]
mod tests;
