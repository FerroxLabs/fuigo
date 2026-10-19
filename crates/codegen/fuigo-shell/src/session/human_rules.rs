//! `<human_rules>` composition shared by session spawn and every later system-prompt rewrite.
//!
//! `_meta.rules` is folded into the system prompt as a trailing `<human_rules>` block.
//! The block lives in the persisted `System` item, so it can be read back from there: a model switch, a harness rebuild
//! or a reload re-applies it to the freshly rendered template instead of silently dropping it.

/// The session block opens with a marker line a custom agent template will not carry, so it is told apart from a
/// `<human_rules>` block the template itself contains: extraction and recomposition stay idempotent across switches.
const OPEN: &str = "\n\n<!-- session-rules -->\n<human_rules>\n";
const CLOSE: &str = "\n</human_rules>";

/// Append the `<human_rules>` block for `rules` to `prompt`.
pub(crate) fn append_human_rules(prompt: &mut String, rules: &str) {
    prompt.push_str(OPEN);
    prompt.push_str(rules);
    prompt.push_str(CLOSE);
}

/// The rules text of the trailing `<human_rules>` block of `system`, if it carries one.
pub(crate) fn extract_human_rules(system: &str) -> Option<&str> {
    let start = system.find(OPEN)?;
    system[start + OPEN.len()..].strip_suffix(CLOSE)
}

/// `template` with the rules carried by `current_system` (the session's existing System item) re-applied.
pub(crate) fn recompose_with_rules(template: &str, current_system: Option<&str>) -> String {
    let mut prompt = template.to_owned();
    if let Some(rules) = current_system.and_then(extract_human_rules) {
        append_human_rules(&mut prompt, rules);
    }
    prompt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_rules() {
        let mut p = "base".to_owned();
        append_human_rules(&mut p, "line1\nline2");
        assert_eq!(extract_human_rules(&p), Some("line1\nline2"));
        assert_eq!(
            recompose_with_rules("other", Some(&p)),
            "other\n\n<!-- session-rules -->\n<human_rules>\nline1\nline2\n</human_rules>"
        );
    }

    #[test]
    fn no_block_means_template_unchanged() {
        assert_eq!(recompose_with_rules("other", Some("base")), "other");
        assert_eq!(recompose_with_rules("other", None), "other");
    }

    #[test]
    fn rules_text_containing_the_marker_survives() {
        let mut p = "base".to_owned();
        append_human_rules(&mut p, "a\n\n<human_rules>\nb");
        assert_eq!(extract_human_rules(&p), Some("a\n\n<human_rules>\nb"));
    }

    const TEMPLATE_WITH_BLOCK: &str =
        "custom agent\n\n<human_rules>\nthe template own rules\n</human_rules>\n\ntail";

    fn count(haystack: &str) -> usize {
        haystack.matches("<human_rules>").count()
    }

    /// Switch `n` times, each time re-rendering `template` and feeding back the previous system item.
    fn switch_n(template: &str, mut system: String, n: usize) -> String {
        for _ in 0..n {
            system = recompose_with_rules(template, Some(&system));
        }
        system
    }

    #[test]
    fn repeated_switches_without_a_template_block_keep_one_block() {
        let mut spawn = "base".to_owned();
        append_human_rules(&mut spawn, "session rules");
        let after = switch_n("other", spawn.clone(), 5);
        assert_eq!(count(&after), 1);
        assert_eq!(extract_human_rules(&after), Some("session rules"));
        assert_eq!(after, switch_n("other", spawn, 1));
    }

    #[test]
    fn repeated_switches_with_a_template_block_do_not_duplicate() {
        let mut spawn = TEMPLATE_WITH_BLOCK.to_owned();
        append_human_rules(&mut spawn, "session rules");
        assert_eq!(count(&spawn), 2, "template block + session block");
        let after = switch_n(TEMPLATE_WITH_BLOCK, spawn.clone(), 5);
        assert_eq!(count(&after), 2, "stable across switches: {after}");
        assert_eq!(extract_human_rules(&after), Some("session rules"));
        assert_eq!(after, spawn, "recomposition is idempotent");
    }

    #[test]
    fn a_template_block_alone_is_not_taken_for_session_rules() {
        assert_eq!(extract_human_rules(TEMPLATE_WITH_BLOCK), None);
        assert_eq!(
            recompose_with_rules(TEMPLATE_WITH_BLOCK, Some(TEMPLATE_WITH_BLOCK)),
            TEMPLATE_WITH_BLOCK
        );
    }
}
