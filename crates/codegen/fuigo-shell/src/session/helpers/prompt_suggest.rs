//! Helpers for next-prompt suggestions.

use crate::config::PromptSuggestModelPin;
use crate::sampling::ConversationItem;
use crate::session::helpers::chat::floor_char_boundary;
use fuigo_sampling_types::ReasoningEffort;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SuggestReasoning {
    pub(crate) effort: Option<ReasoningEffort>,
    pub(crate) reserve_budget: bool,
}

pub(crate) fn resolve_suggest_reasoning(
    configured: Option<ReasoningEffort>,
    model: &str,
    supports_reasoning_effort: bool,
    supports_none: bool,
) -> SuggestReasoning {
    if let Some(effort) = configured
        && !matches!(effort, ReasoningEffort::None)
    {
        return SuggestReasoning {
            effort: supports_reasoning_effort.then_some(effort),
            reserve_budget: supports_reasoning_effort,
        };
    }

    if model != crate::util::config::NON_REASONING_PROMPT_SUGGEST_MODEL && supports_reasoning_effort
    {
        return SuggestReasoning {
            effort: supports_none.then_some(ReasoningEffort::None),
            reserve_budget: !supports_none,
        };
    }

    SuggestReasoning {
        effort: None,
        reserve_budget: false,
    }
}

pub(crate) fn effective_suggest_model(
    pin: &PromptSuggestModelPin,
    client_hint: Option<&str>,
    session_model: Option<&str>,
    reasoning_is_off: bool,
    in_catalog: impl Fn(&str) -> bool,
) -> Option<String> {
    let client_hint = client_hint.map(str::trim).filter(|s| !s.is_empty());
    let session_model = session_model.map(str::trim).filter(|s| !s.is_empty());
    match pin {
        PromptSuggestModelPin::Env(model) | PromptSuggestModelPin::Pinned(model) => {
            in_catalog(model).then(|| model.to_owned())
        }
        PromptSuggestModelPin::Unpinned => match client_hint {
            Some(model) => in_catalog(model).then(|| model.to_owned()),
            None if reasoning_is_off => {
                let alias = crate::util::config::NON_REASONING_PROMPT_SUGGEST_MODEL;
                in_catalog(alias).then(|| alias.to_owned()).or_else(|| {
                    session_model
                        .filter(|model| in_catalog(model))
                        .map(str::to_owned)
                })
            }
            None => session_model
                .filter(|model| in_catalog(model))
                .map(str::to_owned),
        },
    }
}

/// Total character budget for the compact transcript (~6k tokens at the bytes/4 estimate).
/// It keeps the per-turn cost of the feature trivial even on long sessions.
const TRANSCRIPT_BUDGET_CHARS: usize = 24_000;

/// Per-message character cap inside the transcript.
/// Long messages (pasted logs, big diffs) carry little signal for next-prompt prediction.
const MESSAGE_CAP_CHARS: usize = 1_500;

/// Reject suggestions longer than this: a prompt suggestion should be a short, obvious next step.
const SUGGESTION_MAX_CHARS: usize = 120;

/// Reject suggestions with more words than this (mirrors common "2-12 words" guidance with a little slack).
const SUGGESTION_MAX_WORDS: usize = 16;

/// Short replies that are useful suggestions despite being a single word.
const ONE_WORD_ALLOWLIST: &[&str] = &[
    "yes", "yeah", "yep", "no", "ok", "okay", "continue", "proceed", "push", "commit", "deploy",
    "stop", "check", "retry", "undo", "merge",
];

/// The model sees a compact transcript and must reply with ONLY the predicted next user message (or nothing).
pub(crate) const SUGGEST_PROMPT_SYSTEM: &str = "You predict what the USER will type next into their coding agent CLI.\n\
    You are shown a transcript of the conversation so far. The agent's latest reply ends the transcript.\n\n\
    FIRST: look at the user's recent messages and original request.\n\
    Your job is to predict what THEY would type next — not what you think they should do.\n\
    THE TEST: would they think \"I was just about to type that\"?\n\n\
    EXAMPLES:\n\
    - User asked \"fix the bug and run tests\", bug is fixed -> \"run the tests\"\n\
    - After code was written -> \"try it out\"\n\
    - Agent offers options -> the option the user would likely pick, based on the conversation\n\
    - Agent ends by asking a yes/no question (continue? delete it? print it?) -> the user's likely answer: \"yes\" or \"no\"\n\
    - Task complete with an obvious follow-up -> \"commit this\" or \"push it\"\n\
    - After an error or a misunderstanding -> NONE (let them assess)\n\n\
    Be specific: \"run the tests\" beats \"continue\".\n\
    When the agent's reply ends with a question, a suggestion almost always exists — predict the answer.\n\n\
    NEVER SUGGEST:\n\
    - A message the user already sent, or a rephrasing of one — the transcript is history, not a menu. \
Once a request was handled, predict the step AFTER it, never the request again \
(short confirmations like \"yes\" or \"continue\" are the only acceptable repeats)\n\
    - Evaluative filler (\"looks good\", \"thanks\")\n\
    - Questions back to the agent (\"what about...?\")\n\
    - Agent-voice phrasing (\"Let me...\", \"I'll...\", \"Here's...\")\n\
    - New ideas the user never asked about\n\
    - Multiple sentences\n\n\
    Stay silent if the next step is not obvious from what the user said: reply with the single word NONE.\n\n\
    Format: 2-12 words, matching the user's own style and casing.\n\
    Reply with ONLY the suggestion text (or NONE) — no quotes, no markdown, no explanation.";

pub(crate) fn suggestion_size(s: &str) -> (usize, usize) {
    (s.chars().count(), s.split_whitespace().count())
}

/// One transcript line: role label and flattened text content.
fn transcript_line(role: &str, text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let mut text = text;
    if text.len() > MESSAGE_CAP_CHARS {
        let cut = floor_char_boundary(text, MESSAGE_CAP_CHARS);
        text = &text[..cut];
    }
    Some(format!("{role}: {text}"))
}

/// Keeps genuine `User` messages (skipping runtime-synthesized ones) and `Assistant` text, newest-last.
/// Walks backwards until the character budget is exhausted.
/// Tool calls/results, reasoning, and the system prompt are dropped.
/// The user/assistant dialogue carries the signal for "what will the user type next", and dropping the rest keeps the request cheap.
///
/// Returns `None` when the conversation has no assistant reply yet (nothing to predict from).
pub(crate) fn build_transcript(conversation: &[ConversationItem]) -> Option<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut used = 0usize;
    let mut saw_assistant = false;

    for item in conversation.iter().rev() {
        let line = match item {
            ConversationItem::User(u) => {
                if u.synthetic_reason.is_some() {
                    continue;
                }
                transcript_line("User", &item.text_content())
            }
            ConversationItem::Assistant(_) => {
                let line = transcript_line("Agent", &item.text_content());
                if line.is_some() {
                    saw_assistant = true;
                }
                line
            }
            _ => continue,
        };
        let Some(line) = line else { continue };
        if used + line.len() > TRANSCRIPT_BUDGET_CHARS && !lines.is_empty() {
            break;
        }
        used += line.len();
        lines.push(line);
    }

    if !saw_assistant || lines.is_empty() {
        return None;
    }

    lines.reverse();
    Some(lines.join("\n\n"))
}

pub(crate) fn suggest_prompt_user_message(transcript: &str, cwd: &str) -> String {
    format!(
        "CWD: {cwd}\n\nTranscript:\n\n{transcript}\n\n\
         Predict the user's next message. Reply with ONLY the suggestion text."
    )
}

/// Minimum word count for the deterministic repeat filter.
/// Short command-like replies ("yes", "run tests", "try again") legitimately recur across a session.
/// A repeated multi-word task prompt is the "it suggested my old prompt back to me" failure mode.
const REPEAT_MIN_WORDS: usize = 4;

/// Case- and whitespace-insensitive form used for repeat comparison, with trailing sentence punctuation dropped.
fn normalize_for_repeat(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches(['.', '!', '?'])
        .to_ascii_lowercase()
}

/// This is the deterministic backstop behind the system prompt's anti-repeat rule.
/// Prompt guidance reduces repeats; this guarantees an exact (normalized) re-suggestion of a past multi-word prompt never renders as ghost text.
/// Short suggestions (under [`REPEAT_MIN_WORDS`] words) are exempt: repeating "yes" or "run tests" is often exactly what the user is about to type.
pub(crate) fn is_repeat_of_user_message(
    suggestion: &str,
    conversation: &[ConversationItem],
) -> bool {
    if suggestion.split_whitespace().count() < REPEAT_MIN_WORDS {
        return false;
    }
    let needle = normalize_for_repeat(suggestion);
    conversation.iter().any(|item| match item {
        ConversationItem::User(u) if u.synthetic_reason.is_none() => {
            normalize_for_repeat(&item.text_content()) == needle
        }
        _ => false,
    })
}

/// Returns `None` for anything that should not be shown as ghost text.
pub(crate) fn sanitize_suggestion(raw: &str) -> Option<String> {
    // First line only; the prompt asks for a single line but models drift.
    let line = raw.trim().lines().next()?.trim();

    // Strip common wrappers the prompt forbids but models still emit.
    let line = line
        .trim_start_matches(['"', '\'', '`', '“', '‘'])
        .trim_end_matches(['"', '\'', '`', '”', '’'])
        .trim();

    if line.is_empty() || line.len() >= SUGGESTION_MAX_CHARS {
        return None;
    }

    // Meta / "no suggestion" replies.
    let lowered = line.to_ascii_lowercase();
    let meta = [
        "none",
        "n/a",
        "no suggestion",
        "nothing",
        "(silence)",
        "silence",
        "null",
    ];
    if meta
        .iter()
        .any(|m| lowered == *m || lowered.starts_with(&format!("{m}.")))
    {
        return None;
    }

    // Markdown / formatting: ghost text renders on a single styled line
    if line.contains('*') || line.contains("```") || line.starts_with('#') || line.starts_with('-')
    {
        return None;
    }

    // Agent-voice phrasing: the suggestion must be in the USER's voice
    let agent_voice = [
        "i'll ",
        "i will ",
        "let me ",
        "here's ",
        "here is ",
        "i'm going to ",
    ];
    if agent_voice.iter().any(|p| lowered.starts_with(p)) {
        return None;
    }

    // Parenthetical/bracketed meta replies like "(no suggestion)".
    if (line.starts_with('(') && line.ends_with(')'))
        || (line.starts_with('[') && line.ends_with(']'))
    {
        return None;
    }

    // Label prefixes like "Suggestion: ..." / "User: ...".
    if let Some((head, _)) = line.split_once(':')
        && !head.contains(' ')
        && head.chars().all(|c| c.is_ascii_alphabetic())
    {
        return None;
    }

    // Multiple sentences read as agent prose, not a prompt.
    let multi_sentence = line
        .as_bytes()
        .windows(3)
        .any(|w| matches!(w[0], b'.' | b'!' | b'?') && w[1] == b' ' && w[2].is_ascii_uppercase());
    if multi_sentence {
        return None;
    }

    // Word-count bounds: 1 word only from the allowlist, and never a wall of text.
    let words = line.split_whitespace().count();
    if words > SUGGESTION_MAX_WORDS {
        return None;
    }
    if words == 1 {
        let bare = lowered.trim_end_matches(['.', '!']);
        if !ONE_WORD_ALLOWLIST.contains(&bare) && !bare.starts_with('/') {
            return None;
        }
    }

    Some(line.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PromptSuggestModelPin as Pin;

    // -- effective_suggest_model ---------------------------------------------

    #[test]
    fn effective_model_explicit_pin_beats_client_hint_when_reasoning_is_off() {
        assert_eq!(
            effective_suggest_model(
                &Pin::Pinned("pinned".into()),
                Some("hinted"),
                Some("session"),
                true,
                |m| m == "pinned"
            )
            .as_deref(),
            Some("pinned")
        );
    }

    #[test]
    fn effective_model_default_prefers_catalogued_non_reasoning_alias() {
        let alias = crate::util::config::NON_REASONING_PROMPT_SUGGEST_MODEL;
        assert_eq!(
            effective_suggest_model(&Pin::Unpinned, None, Some("session"), true, |m| m == alias)
                .as_deref(),
            Some(alias)
        );
    }

    #[test]
    fn effective_model_default_falls_back_to_catalogued_session_model() {
        assert_eq!(
            effective_suggest_model(&Pin::Unpinned, None, Some("session"), true, |m| m
                == "session")
            .as_deref(),
            Some("session")
        );
        assert_eq!(
            effective_suggest_model(&Pin::Unpinned, None, Some("session"), true, |_| false),
            None
        );
    }

    #[test]
    fn effective_model_default_uses_alias_without_session_catalog_entry() {
        let alias = crate::util::config::NON_REASONING_PROMPT_SUGGEST_MODEL;
        assert_eq!(
            effective_suggest_model(&Pin::Unpinned, None, Some("missing-session"), true, |m| {
                m == alias
            })
            .as_deref(),
            Some(alias)
        );
    }

    #[test]
    fn configured_reasoning_reserves_budget() {
        assert_eq!(
            resolve_suggest_reasoning(Some(ReasoningEffort::Low), "session", true, true),
            SuggestReasoning {
                effort: Some(ReasoningEffort::Low),
                reserve_budget: true,
            }
        );
    }

    #[test]
    fn reasoning_off_uses_none_when_the_fallback_supports_it() {
        assert_eq!(
            resolve_suggest_reasoning(None, "session", true, true),
            SuggestReasoning {
                effort: Some(ReasoningEffort::None),
                reserve_budget: false,
            }
        );
    }

    #[test]
    fn reasoning_off_reserves_budget_when_the_fallback_has_no_none_effort() {
        assert_eq!(
            resolve_suggest_reasoning(None, "session", true, false),
            SuggestReasoning {
                effort: None,
                reserve_budget: true,
            }
        );
    }

    #[test]
    fn alias_keeps_the_small_non_reasoning_budget() {
        assert_eq!(
            resolve_suggest_reasoning(
                None,
                crate::util::config::NON_REASONING_PROMPT_SUGGEST_MODEL,
                true,
                false,
            ),
            SuggestReasoning {
                effort: None,
                reserve_budget: false,
            }
        );
    }

    #[test]
    fn effective_model_client_hint_beats_session_and_is_guarded() {
        assert_eq!(
            effective_suggest_model(
                &Pin::Unpinned,
                Some("hinted"),
                Some("session"),
                false,
                |m| m == "hinted"
            )
            .as_deref(),
            Some("hinted")
        );
    }

    #[test]
    fn effective_model_env_pin_is_catalog_guarded() {
        assert_eq!(
            effective_suggest_model(
                &Pin::Env("custom-model".into()),
                Some("hinted"),
                Some("session"),
                true,
                |_| false
            ),
            None
        );
    }

    // -- sanitize_suggestion ------------------------------------------------

    #[test]
    fn sanitize_accepts_short_imperative() {
        assert_eq!(
            sanitize_suggestion("run the tests").as_deref(),
            Some("run the tests")
        );
    }

    #[test]
    fn sanitize_strips_quotes_and_backticks() {
        assert_eq!(
            sanitize_suggestion("\"commit this\"").as_deref(),
            Some("commit this")
        );
        assert_eq!(sanitize_suggestion("`push it`").as_deref(), Some("push it"));
    }

    #[test]
    fn sanitize_takes_first_line_only() {
        assert_eq!(
            sanitize_suggestion("run the tests\nthen commit").as_deref(),
            Some("run the tests")
        );
    }

    #[test]
    fn sanitize_rejects_none_and_meta() {
        for s in ["NONE", "none", "n/a", "no suggestion", "(silence)", ""] {
            assert_eq!(sanitize_suggestion(s), None, "should reject {s:?}");
        }
    }

    #[test]
    fn sanitize_rejects_agent_voice() {
        for s in [
            "I'll run the tests",
            "Let me check the output",
            "Here's what to do next",
        ] {
            assert_eq!(sanitize_suggestion(s), None, "should reject {s:?}");
        }
    }

    #[test]
    fn sanitize_rejects_markdown_and_labels() {
        for s in [
            "**run tests**",
            "- run tests",
            "# next",
            "Suggestion: run tests",
            "```run```",
        ] {
            assert_eq!(sanitize_suggestion(s), None, "should reject {s:?}");
        }
    }

    #[test]
    fn sanitize_rejects_multi_sentence_and_overlong() {
        assert_eq!(
            sanitize_suggestion("Run the tests. Then commit the changes."),
            None
        );
        let long = "word ".repeat(20);
        assert_eq!(sanitize_suggestion(&long), None);
        let chars = "x".repeat(200);
        assert_eq!(sanitize_suggestion(&chars), None);
    }

    #[test]
    fn sanitize_one_word_allowlist() {
        assert_eq!(sanitize_suggestion("yes").as_deref(), Some("yes"));
        assert_eq!(sanitize_suggestion("commit").as_deref(), Some("commit"));
        // Bare one-word verbs outside the allowlist are too ambiguous.
        assert_eq!(sanitize_suggestion("refactor"), None);
        // Slash commands are fine.
        assert_eq!(sanitize_suggestion("/review").as_deref(), Some("/review"));
    }

    #[test]
    fn sanitize_allows_colon_after_multiword_head() {
        // Only single-word alphabetic label heads are rejected.
        assert_eq!(
            sanitize_suggestion("fix the parse error: line 42").as_deref(),
            Some("fix the parse error: line 42")
        );
    }

    // -- build_transcript ---------------------------------------------------

    fn user(text: &str) -> ConversationItem {
        ConversationItem::user(text.to_owned())
    }

    fn assistant(text: &str) -> ConversationItem {
        ConversationItem::assistant(text.to_owned())
    }

    // -- is_repeat_of_user_message -------------------------------------------

    #[test]
    fn repeat_filter_rejects_verbatim_past_prompt() {
        let conv = vec![user("fix the flaky auth test"), assistant("Fixed it")];
        assert!(is_repeat_of_user_message("fix the flaky auth test", &conv));
    }

    #[test]
    fn repeat_filter_is_case_whitespace_and_punctuation_insensitive() {
        let conv = vec![user("Fix  the flaky\nauth test."), assistant("Fixed it")];
        assert!(is_repeat_of_user_message("fix the flaky auth test!", &conv));
    }

    #[test]
    fn repeat_filter_exempts_short_suggestions() {
        let conv = vec![user("run the tests"), assistant("3 failures")];
        // 3 words, so it legitimately recurs after new changes
        assert!(!is_repeat_of_user_message("run the tests", &conv));
        assert!(!is_repeat_of_user_message("yes", &conv));
    }

    #[test]
    fn repeat_filter_allows_novel_suggestions() {
        let conv = vec![user("fix the flaky auth test"), assistant("Fixed it")];
        assert!(!is_repeat_of_user_message("commit and push the fix", &conv));
    }

    #[test]
    fn repeat_filter_ignores_synthetic_user_messages() {
        let mut synthetic = user("please review the changes now");
        if let ConversationItem::User(u) = &mut synthetic {
            u.synthetic_reason = Some(crate::sampling::SyntheticReason::SystemReminder);
        }
        let conv = vec![synthetic, assistant("done")];
        assert!(!is_repeat_of_user_message(
            "please review the changes now",
            &conv
        ));
    }

    #[test]
    fn transcript_keeps_user_and_assistant_in_order() {
        let conv = vec![
            ConversationItem::system("sys".to_owned()),
            user("fix the bug"),
            assistant("Fixed it in foo.rs"),
        ];
        let t = build_transcript(&conv).unwrap();
        assert_eq!(t, "User: fix the bug\n\nAgent: Fixed it in foo.rs");
    }

    #[test]
    fn transcript_requires_an_assistant_reply() {
        let conv = vec![ConversationItem::system("sys".to_owned()), user("hello")];
        assert!(build_transcript(&conv).is_none());
        assert!(build_transcript(&[]).is_none());
    }

    #[test]
    fn transcript_skips_synthetic_user_messages() {
        let mut synthetic = ConversationItem::user("synthetic reminder".to_owned());
        if let ConversationItem::User(u) = &mut synthetic {
            u.synthetic_reason = Some(crate::sampling::SyntheticReason::SystemReminder);
        }
        let conv = vec![user("real question"), synthetic, assistant("answer")];
        let t = build_transcript(&conv).unwrap();
        assert!(!t.contains("synthetic reminder"));
        assert!(t.contains("User: real question"));
    }

    #[test]
    fn transcript_caps_long_messages() {
        let long = "a".repeat(10_000);
        let conv = vec![user(&long), assistant("ok")];
        let t = build_transcript(&conv).unwrap();
        assert!(
            t.len() < 2_000,
            "long message must be truncated: {}",
            t.len()
        );
    }

    #[test]
    fn transcript_budget_keeps_newest_messages() {
        let filler = "b".repeat(MESSAGE_CAP_CHARS);
        let mut conv = Vec::new();
        for _ in 0..40 {
            conv.push(user(&filler));
            conv.push(assistant(&filler));
        }
        conv.push(user("newest question"));
        conv.push(assistant("newest answer"));
        let t = build_transcript(&conv).unwrap();
        assert!(t.len() <= TRANSCRIPT_BUDGET_CHARS + MESSAGE_CAP_CHARS + 64);
        assert!(t.contains("newest question"));
        assert!(t.ends_with("Agent: newest answer"));
    }
}
