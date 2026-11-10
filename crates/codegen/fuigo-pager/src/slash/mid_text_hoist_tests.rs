use pretty_assertions::assert_eq;

use super::hoist_mid_text_command;
use crate::slash::commands;
use crate::slash::registry::CommandRegistry;

fn hoist(text: &str) -> Option<String> {
    hoist_mid_text_command(text, &CommandRegistry::new(commands::builtin_commands()))
}

/// A token that does not begin the message is plain text.
#[test]
fn token_later_in_the_text_misses() {
    for text in [
        "explain the controller. /btw what is a WBC",
        "prose /btw",
        "line1\n/btw q\nline2",
        "a /btw b /btw c",
        "/nope hi /btw q",
    ] {
        assert_eq!(None, hoist(text), "{text:?}");
    }
}

/// The caller keeps real leading invocations out; `[Image #1] /btw q` arrives here as ` /btw q`.
#[test]
fn leading_token_after_stripped_chip_hoists_in_place() {
    assert_eq!(Some("/btw q".to_owned()), hoist(" /btw q"));
    assert_eq!(Some("/btw q".to_owned()), hoist("/btw q"));
    assert_eq!(Some("/btw a\nb".to_owned()), hoist("/btw   a\nb"));
}

#[test]
fn empty_question_is_none() {
    for text in ["/btw", " /btw", "/btw   "] {
        assert_eq!(None, hoist(text), "{text:?}");
    }
}

#[test]
fn punctuated_or_uppercase_token_misses() {
    for text in ["hi /btw, q", "hi /btw: q", "hi /BTW q"] {
        assert_eq!(None, hoist(text), "{text:?}");
    }
}

#[test]
fn path_and_url_slashes_miss() {
    for text in ["see docs/btw", "open https://example.com/btw now"] {
        assert_eq!(None, hoist(text), "{text:?}");
    }
}

#[test]
fn non_opted_in_builtin_misses() {
    assert_eq!(None, hoist("great /compact go"));
}

#[test]
fn unknown_command_misses() {
    assert_eq!(None, hoist("hi /nope q"));
}
