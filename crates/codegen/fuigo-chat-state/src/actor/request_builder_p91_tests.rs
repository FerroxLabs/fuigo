//! P91 R1: the memory upsert must never cut the system prompt at a
//! `<memory-context>` literal it did not insert.
use super::*;
use fuigo_sampling_types::ConversationItem;

fn system_text(items: &[ConversationItem]) -> String {
    match &items[0] {
        ConversationItem::System(sys) => sys.content.to_string(),
        other => panic!("expected System, got {other:?}"),
    }
}

/// Repo-influenced text (e.g. a repo-defined agent's role text) that mentions the
/// tag must survive, with everything after it, when a reminder is injected.
#[test]
fn stray_tag_in_system_prompt_keeps_the_text_after_it() {
    let prompt = "Role: our plugin emits <memory-context> tags.\nKEEP_CANARY: follow the user's rules.";
    let mut items = vec![ConversationItem::system(prompt), ConversationItem::user("hi")];
    assert!(inject_memory_reminder(
        &mut items,
        "<memory-context>\nRemember: user likes rust\n</memory-context>"
    ));
    let text = system_text(&items);
    assert!(text.starts_with(prompt), "system prompt was cut: {text:?}");
    assert!(text.contains("Remember: user likes rust"));
}

const NONCE: &str = "0123456789abcdef0123456789abcdef";

fn block(nonce: &str, body: &str) -> String {
    format!(
        "{}\n{body}\n{}",
        crate::types::memory_context_open_tag(nonce),
        crate::types::memory_context_close_tag(nonce)
    )
}

/// A re-injected block replaces Fuigo's own earlier block in place and keeps any
/// text after it; a block with a different nonce is not Fuigo's and is kept.
#[test]
fn nonced_reminder_replaces_only_its_own_block() {
    let other = block("ffffffffffffffffffffffffffffffff", "not ours");
    let prompt = format!("Sys.\n\n{}\nTAIL_CANARY\n{other}", block(NONCE, "old fact"));
    let mut items = vec![ConversationItem::system(prompt)];
    assert!(inject_memory_reminder(&mut items, &block(NONCE, "new fact")));
    assert_eq!(
        system_text(&items),
        format!("Sys.\n\n{}\nTAIL_CANARY\n{other}", block(NONCE, "new fact"))
    );
    // Same block again: no change.
    assert!(!inject_memory_reminder(&mut items, &block(NONCE, "new fact")));
}

/// An opening tag with no close is never treated as a block to replace.
#[test]
fn unclosed_own_tag_is_not_replaced_from() {
    let prompt = format!(
        "Sys {} unclosed\nTAIL_CANARY",
        crate::types::memory_context_open_tag(NONCE)
    );
    let mut items = vec![ConversationItem::system(prompt.clone())];
    assert!(inject_memory_reminder(&mut items, &block(NONCE, "fact")));
    let text = system_text(&items);
    assert!(text.starts_with(&prompt), "{text:?}");
}

/// Astra r1 #1: an earlier unclosed own tag must not pair with a later block's
/// close; re-injecting twice keeps the text between them.
#[test]
fn unclosed_own_tag_does_not_pair_with_a_later_block() {
    let prompt = format!(
        "Sys {} unclosed\nTAIL_CANARY",
        crate::types::memory_context_open_tag(NONCE)
    );
    let mut items = vec![ConversationItem::system(prompt.clone())];
    assert!(inject_memory_reminder(&mut items, &block(NONCE, "first")));
    assert!(inject_memory_reminder(&mut items, &block(NONCE, "second")));
    let text = system_text(&items);
    assert!(text.starts_with(&prompt), "{text:?}");
    assert!(text.ends_with(&block(NONCE, "second")) && !text.contains("first"), "{text:?}");
    assert_eq!(
        crate::types::find_memory_context_block(&text, NONCE, 0).map(|r| &text[r]),
        Some(block(NONCE, "second").as_str())
    );
}
