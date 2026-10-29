//! Browser mode (`set_mode("browser_use")`): an overlay on the outgoing request, never stored.
//!
//! The stored System item is always the session's normal head. While the in-memory bit on the plan tracker is on,
//! every request that carries session history gets [`OVERLAY_OPEN`] plus the browsing body appended to its copy of
//! the head, the way the non-persisted memory reminder is added. Leaving browser mode clears the bit and the next
//! request is the session's own prompt again.
//!
//! Sessions saved while browsing by 1.0.35 and earlier stored the bare browsing body as their head. The one-time
//! repair at load and cross-compaction rewind recognises that shape with [`is_legacy_browser_head`].
use std::borrow::Cow;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use fuigo_agent::{AgentDefinition, PromptContext};
use fuigo_sampling_types::ConversationItem;
use fuigo_tools::bridge::ToolBridge;

/// Separates the session's own head from the browsing instructions in the outgoing request.
pub(crate) const OVERLAY_OPEN: &str = "\n\n<!-- session-mode: browser_use -->\n";

/// The browsing instructions: the body of the built-in `browser-use` agent definition.
pub(crate) fn browser_body() -> &'static str {
    static BODY: OnceLock<String> = OnceLock::new();
    BODY.get_or_init(|| AgentDefinition::browser_use().prompt_body.unwrap_or_default())
}

/// The head a request carries: the stored head, plus the browsing overlay while browser mode is on.
/// No parsing and no prefix test: with `browser == false` this is the stored text, borrowed.
pub(crate) fn effective_system_head(stored: &str, browser: bool) -> Cow<'_, str> {
    if !browser {
        return Cow::Borrowed(stored);
    }
    let body = browser_body();
    let mut head = String::with_capacity(stored.len() + OVERLAY_OPEN.len() + body.len());
    head.push_str(stored);
    head.push_str(OVERLAY_OPEN);
    head.push_str(body);
    Cow::Owned(head)
}

/// Apply [`effective_system_head`] to a request's items. Writes only when the head changes (browser mode on); a
/// request with no System item gets one prepended, like the memory reminder.
pub(crate) fn apply_browser_overlay(items: &mut Vec<ConversationItem>, browser: bool) {
    if !browser {
        return;
    }
    match items.first_mut() {
        Some(ConversationItem::System(sys)) => {
            if let Cow::Owned(head) = effective_system_head(&sys.content, true) {
                sys.content = Arc::from(head);
            }
        }
        _ => {
            items.insert(0, ConversationItem::system(effective_system_head("", true).into_owned()));
        }
    }
}

/// Whether text is the browsing body up to trailing whitespace.
fn is_browser_body(text: &str) -> bool {
    text.trim_end() == browser_body()
}

/// A head 1.0.35 stored while browsing: the bare browsing body, optionally followed by `\n\n` and (optionally) one
/// complete memory-context block carrying this installation's nonce ([`crate::session::human_rules::split_memory_tail`]:
/// never a nonce read from the text). Any other non-whitespace text means no match. Used only at load and
/// cross-compaction rewind, never on a request path.
pub(crate) fn is_legacy_browser_head(stored: &str) -> bool {
    is_browser_body(crate::session::human_rules::split_memory_tail(stored).0)
}

/// Collision guard for the legacy repair: `true` when a legacy-shaped head may be replaced.
///
/// `canonical` is the session's own normal head (its client override, else the agent's system prompt), never the
/// replacement text a caller installs: rewind installs the live head, which can differ from the canonical head (a newer
/// memory block). Skipped when the canonical head is itself the browsing body (a `browser-use` profile session, or an
/// override equal to it), or when a `default` or `ask` definition discoverable for `cwd` (the same trust-gated lookup
/// `set_mode` uses) renders, as `set_mode` renders it, to the browsing body; a render that fails also skips it (fail
/// closed: the head stays). Those are the only ways a never-browser session holds that head. `contexts` builds the
/// prompt context for each discovered definition and hands back the tool bridge to render with.
pub(crate) async fn legacy_repair_allowed(
    canonical: &str,
    cwd: &Path,
    contexts: impl FnOnce(&[AgentDefinition]) -> (Vec<PromptContext>, Arc<ToolBridge>),
) -> bool {
    if is_browser_body(canonical) {
        return false;
    }
    let defs: Vec<AgentDefinition> = ["default", "ask"]
        .into_iter()
        .filter_map(|name| fuigo_agent::discovery::by_name_in_cwd(name, cwd))
        .collect();
    if defs.is_empty() {
        return true;
    }
    let (ctxs, bridge) = contexts(&defs);
    for ctx in ctxs {
        if render_blocks_repair(ctx.render(&bridge).await.as_deref()) {
            return false;
        }
    }
    true
}

/// A mode definition's render blocks the repair when it is the browsing body, or when there is none (the render
/// failed): the guard fails closed and the head stays.
fn render_blocks_repair(rendered: Option<&str>) -> bool {
    rendered.is_none_or(is_browser_body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce() -> &'static str {
        crate::session::helpers::memory_context::memory_context_nonce()
    }

    fn block(nonce: &str, body: &str) -> String {
        format!(
            "{}{body}{}",
            fuigo_chat_state::memory_context_open_tag(nonce),
            fuigo_chat_state::memory_context_close_tag(nonce)
        )
    }

    #[test]
    fn unset_head_is_borrowed() {
        let stored = "normal head";
        assert!(matches!(effective_system_head(stored, false), Cow::Borrowed(s) if std::ptr::eq(s, stored)));
    }

    #[test]
    fn overlay_appends_after_the_stored_head() {
        let head = effective_system_head("normal", true);
        assert_eq!(head, format!("normal{OVERLAY_OPEN}{}", browser_body()));
    }

    #[test]
    fn overlay_prepends_a_head_when_there_is_none() {
        let mut items = vec![ConversationItem::user("hi")];
        apply_browser_overlay(&mut items, true);
        match &items[0] {
            ConversationItem::System(sys) => {
                assert_eq!(sys.content.as_ref(), effective_system_head("", true).as_ref(), "inserted unchanged")
            }
            _ => panic!("no System head"),
        }
        let mut unset = vec![ConversationItem::user("hi")];
        apply_browser_overlay(&mut unset, false);
        assert_eq!(unset.len(), 1);
    }

    #[test]
    fn a_failed_render_blocks_the_repair() {
        assert!(render_blocks_repair(None), "no render: leave the head");
        assert!(render_blocks_repair(Some(browser_body())));
        assert!(!render_blocks_repair(Some("a default.md body")));
    }

    #[test]
    fn legacy_shapes_match() {
        let b = browser_body();
        let blk = block(nonce(), "remember this");
        for head in [b.to_owned(), format!("{b}\n\n"), format!("{b}\n\n{blk}"), format!("{b}\n")] {
            assert!(is_legacy_browser_head(&head), "{head:?}");
        }
    }

    #[test]
    fn non_legacy_shapes_do_not_match() {
        let b = browser_body();
        let blk = block(nonce(), "remember this");
        let unclosed = fuigo_chat_state::memory_context_open_tag(nonce());
        let foreign = block("abc123", "remember this");
        for head in [
            format!("{b} more"),
            format!("{b}\n\nrules"),
            format!("{b}\n\n{blk}\ntext"),
            format!("prefix {b}"),
            format!("{b}\n\n{unclosed}remember"),
            format!("{b}\n\n{blk}{blk}"),
            format!("{b}\n\n{foreign}"),
            format!("{b}{OVERLAY_OPEN}{b}"),
            String::new(),
        ] {
            assert!(!is_legacy_browser_head(&head), "{head:?}");
        }
    }
}
