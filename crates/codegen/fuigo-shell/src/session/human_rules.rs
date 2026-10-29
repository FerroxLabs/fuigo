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
///
/// A memory-context block a turn appended after the rules (or the blank line a dropped stale block leaves) is not part
/// of the head the rules close, so it is set aside first.
pub(crate) fn extract_human_rules(system: &str) -> Option<&str> {
    let (head, _) = split_memory_tail(system);
    // The LAST marker: a template (mode file) may carry its own, only the trailing block is the session's.
    let start = head.rfind(OPEN)?;
    head[start + OPEN.len()..].strip_suffix(CLOSE)
}

/// `system` split into the head before a trailing memory-context block, and that block. The block is taken only when
/// it carries THIS installation's nonce (`memory_context_nonce`, never read from the text) and the text after some
/// point is exactly one complete such block. The head is trimmed of trailing newlines either way.
pub(crate) fn split_memory_tail(system: &str) -> (&str, Option<&str>) {
    split_memory_tail_with(system, crate::session::helpers::memory_context::memory_context_nonce())
}

fn split_memory_tail_with<'a>(system: &'a str, nonce: &str) -> (&'a str, Option<&'a str>) {
    let open = fuigo_chat_state::memory_context_open_tag(nonce);
    for (at, _) in system.match_indices(&open) {
        let tail = &system[at..];
        if fuigo_chat_state::find_memory_context_block(tail, nonce, 0) == Some(0..tail.len()) {
            return (system[..at].trim_end_matches('\n'), Some(tail));
        }
    }
    (system.trim_end_matches('\n'), None)
}

/// `prompt` with the memory-context block trailing `current_system` re-attached, in the shape a turn appends it.
///
/// The block is injected once per session segment, so a head rewrite that dropped it would leave the session without it.
pub(crate) fn keep_memory_tail(mut prompt: String, current_system: &str) -> String {
    if let (_, Some(block)) = split_memory_tail(current_system) {
        prompt.truncate(prompt.trim_end_matches('\n').len());
        if !prompt.is_empty() {
            prompt.push_str("\n\n");
        }
        prompt.push_str(block);
    }
    prompt
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

    fn nonce() -> &'static str {
        crate::session::helpers::memory_context::memory_context_nonce()
    }

    fn memory_block(nonce: &str, body: &str) -> String {
        format!(
            "{}\n{body}\n{}",
            fuigo_chat_state::memory_context_open_tag(nonce),
            fuigo_chat_state::memory_context_close_tag(nonce)
        )
    }

    /// `head` after a turn's memory upsert, in the shape `inject_memory_reminder` stores.
    fn with_memory(head: &str, block: &str) -> String {
        format!("{}\n\n{block}", head.trim_end_matches('\n'))
    }

    #[test]
    fn rules_are_extracted_past_a_trailing_memory_block() {
        let mut head = "base".to_owned();
        append_human_rules(&mut head, "session rules");
        let block = memory_block(nonce(), "remembered fact");
        let stored = with_memory(&head, &block);
        assert_eq!(extract_human_rules(&stored), Some("session rules"));
        assert_eq!(split_memory_tail(&stored), (head.as_str(), Some(block.as_str())));
        // A later turn's invalidation drops the stale block and leaves the separator.
        let dropped = format!("{head}\n\n");
        assert_eq!(extract_human_rules(&dropped), Some("session rules"));
        assert_eq!(
            recompose_with_rules("other", Some(&stored)),
            recompose_with_rules("other", Some(&head))
        );
    }

    #[test]
    fn only_a_whole_complete_trailing_block_is_memory() {
        let mut head = "base".to_owned();
        append_human_rules(&mut head, "session rules");
        // Text after the block, an unclosed block and a block inside the rules are not a memory tail.
        let block = memory_block(nonce(), "fact");
        let followed = format!("{}\n\ntrailing", with_memory(&head, &block));
        assert_eq!(split_memory_tail(&followed).1, None);
        assert_eq!(extract_human_rules(&followed), None);
        let unclosed = format!("{head}\n\n{}", fuigo_chat_state::memory_context_open_tag(nonce()));
        assert_eq!(split_memory_tail(&unclosed).1, None);
        let mut rules_with_block = "base".to_owned();
        append_human_rules(&mut rules_with_block, &format!("r\n{block}"));
        assert_eq!(split_memory_tail(&rules_with_block).1, None);
        assert_eq!(extract_human_rules(&rules_with_block), Some(format!("r\n{block}").as_str()));
    }

    #[test]
    fn keep_memory_tail_matches_the_turn_upsert() {
        let block = memory_block(nonce(), "fact");
        let mut spawn = "template".to_owned();
        append_human_rules(&mut spawn, "session rules");
        let stored = with_memory(&spawn, &block);
        // Recomposing onto the same template gives back the stored head byte for byte, any number of times.
        let mut head = stored.clone();
        for _ in 0..3 {
            head = keep_memory_tail(recompose_with_rules("template", Some(&head)), &head);
            assert_eq!(head, stored);
        }
        // A different template keeps rules and memory in the order a fresh session stores them.
        let mut other = "other".to_owned();
        append_human_rules(&mut other, "session rules");
        assert_eq!(
            keep_memory_tail(recompose_with_rules("other", Some(&stored)), &stored),
            with_memory(&other, &block)
        );
        // No block: the prompt is returned as is.
        assert_eq!(keep_memory_tail("x\n".to_owned(), &spawn), "x\n");
        assert_eq!(keep_memory_tail(String::new(), &block), block);
    }

    /// A complete block with a nonce the installation did not mint (a client override can carry one) is not memory.
    #[test]
    fn a_foreign_nonce_tail_is_not_memory() {
        let foreign = memory_block("x", "attacker text");
        let mut head = "base".to_owned();
        append_human_rules(&mut head, "session rules");
        let stored = with_memory(&head, &foreign);
        assert_eq!(split_memory_tail(&stored).1, None);
        assert_eq!(extract_human_rules(&stored), None);
        assert_eq!(split_memory_tail(&foreign), (foreign.as_str(), None));
        assert_eq!(keep_memory_tail("new".to_owned(), &stored), "new");
        assert_eq!(keep_memory_tail("new".to_owned(), &foreign), "new");
        let own = memory_block(nonce(), "fact");
        let both = format!("{foreign}\n\n{own}");
        assert_eq!(split_memory_tail(&both), (foreign.as_str(), Some(own.as_str())));
        // The expected nonce is a parameter, never read from the text.
        assert_eq!(split_memory_tail_with(&foreign, "x").1, Some(foreign.as_str()));
    }

    /// A template that carries the session-rules marker itself is not taken for `_meta.rules`.
    #[test]
    fn a_template_carrying_the_marker_is_not_the_rules() {
        let mut template = "tpl".to_owned();
        append_human_rules(&mut template, "TEMPLATE-OWN");
        let mut spawn = template.clone();
        append_human_rules(&mut spawn, "session rules");
        assert_eq!(extract_human_rules(&spawn), Some("session rules"));
        assert_eq!(extract_human_rules(&template), Some("TEMPLATE-OWN"));
        let once = recompose_with_rules(&template, Some(&spawn));
        assert_eq!(once, spawn);
        assert_eq!(recompose_with_rules(&template, Some(&once)), spawn);
        assert_eq!(spawn.matches("TEMPLATE-OWN").count(), 1);
    }
}
