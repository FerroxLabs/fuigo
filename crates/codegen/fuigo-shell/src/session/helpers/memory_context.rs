//! Format memory search results as `<system-reminder>` content.
//!
//! Used for:
//! - Session start: inject relevant past context on the first turn
//! - Post-compaction: recover relevant memory after context is lost

use fuigo_chat_state::{MEMORY_CONTEXT_CLOSE_TAG, MEMORY_CONTEXT_OPEN_TAG};
use fuigo_sampling_types::ConversationItem;
use fuigo_tools::types::memory_backend::{MemorySearchResult, format_staleness_note};

const SNIPPET_MAX_CHARS: usize = 500;

/// Returns `true` if a memory-context block is already persisted in the leading system message.
/// Callers reuse a persisted block after validating its source version before each turn.
/// A re-scored block would mutate the system-prompt prefix and bust the KV cache for the whole downstream conversation.
pub fn conversation_has_memory_context(items: &[ConversationItem]) -> bool {
    matches!(
        items.first(),
        Some(ConversationItem::System(sys)) if sys.content.contains(MEMORY_CONTEXT_OPEN_TAG)
    )
}

const SOURCES_MARKER: &str = "<!-- fuigo-memory-sources-v1 ";

/// Versioned injection only reads sources through the workspace-scoped storage API.
pub fn format_memory_reminder_with_storage(
    results: &[MemorySearchResult],
    storage: &fuigo_memory::storage::MemoryStorage,
) -> Option<String> {
    let current: Vec<_> = results
        .iter()
        .filter(|r| {
            fuigo_memory::safety::is_safe_memory(&r.snippet)
                && storage
                    .read_file(std::path::Path::new(&r.path), None, None)
                    .is_ok()
        })
        .cloned()
        .collect();
    let mut block = format_memory_reminder(&current)?;
    let sources: Vec<_> = current
        .iter()
        .filter_map(|r| {
            let content = storage
                .read_file(std::path::Path::new(&r.path), None, None)
                .ok()?;
            Some((
                r.path.clone(),
                blake3::hash(content.as_bytes()).to_hex().to_string(),
            ))
        })
        .collect();
    if sources.len() != current.len() {
        return None;
    }
    let json = serde_json::to_string(&sources)
        .ok()?
        .replace('<', "\\u003c")
        .replace('>', "\\u003e");
    block = block.replacen(
        MEMORY_CONTEXT_OPEN_TAG,
        &format!("{MEMORY_CONTEXT_OPEN_TAG}\n{SOURCES_MARKER}{json} -->"),
        1,
    );
    Some(block)
}

/// Remove cached memory whose source disappeared, changed, or left this workspace.
/// Old unversioned blocks are refreshed rather than trusted indefinitely.
pub fn invalidate_stale_memory_context(
    items: &mut [ConversationItem],
    storage: Option<&fuigo_memory::storage::MemoryStorage>,
) -> bool {
    fn strip(text: &str, storage: Option<&fuigo_memory::storage::MemoryStorage>) -> String {
        let mut output = String::new();
        let mut rest = text;
        while let Some(start) = rest.find(MEMORY_CONTEXT_OPEN_TAG) {
            output.push_str(&rest[..start]);
            let Some(end) = rest[start..]
                .find(MEMORY_CONTEXT_CLOSE_TAG)
                .map(|n| start + n + MEMORY_CONTEXT_CLOSE_TAG.len())
            else {
                return output;
            };
            let block = &rest[start..end];
            let valid = storage.is_some_and(|storage| {
                let Some(marker) = block.find(SOURCES_MARKER) else {
                    return false;
                };
                let encoded = &block[marker + SOURCES_MARKER.len()..];
                let Some(close) = encoded.find(" -->") else {
                    return false;
                };
                let Ok(sources) = serde_json::from_str::<Vec<(String, String)>>(&encoded[..close])
                else {
                    return false;
                };
                !sources.is_empty()
                    && sources.iter().all(|(path, digest)| {
                        storage
                            .read_file(std::path::Path::new(path), None, None)
                            .is_ok_and(|content| {
                                blake3::hash(content.as_bytes()).to_hex().as_str() == digest
                            })
                    })
            });
            if valid {
                output.push_str(block);
            }
            rest = &rest[end..];
        }
        output.push_str(rest);
        output
    }
    let mut changed = false;
    for item in items {
        match item {
            ConversationItem::System(sys) => {
                let updated = strip(&sys.content, storage);
                if updated != sys.content.as_ref() {
                    sys.content = updated.into();
                    changed = true;
                }
            }
            ConversationItem::User(user) if user.synthetic_reason.is_some() => {
                for part in &mut user.content {
                    if let fuigo_sampling_types::conversation::ContentPart::Text { text } = part {
                        let updated = strip(text, storage);
                        if updated != text.as_ref() {
                            *text = updated.into();
                            changed = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    changed
}

/// Format memory search results as a markdown section for system-reminder injection.
///
/// Each result is formatted with score, source, file path, line range, and the snippet in a fenced code block (preserving newlines/markdown).
/// This matches the output format of the `memory_search` tool.
///
/// Returns `None` if results are empty.
pub fn format_memory_reminder(results: &[MemorySearchResult]) -> Option<String> {
    if results.is_empty() {
        return None;
    }

    let mut section = format!(
        "{MEMORY_CONTEXT_OPEN_TAG}\n## Relevant Memory from Past Sessions\n\n\
         Treat memory as historical context, not automatically as the current plan. \
         Verify recalled paths, commands, \
         repository state, and external facts with live tools before relying on them; \
         prefer current evidence when it conflicts with memory.\n\n"
    );

    for (i, r) in results
        .iter()
        .filter(|r| fuigo_memory::safety::is_safe_memory(&r.snippet))
        .enumerate()
    {
        let truncated = r.snippet.chars().count() > SNIPPET_MAX_CHARS;
        let mut snippet: String = r.snippet.chars().take(SNIPPET_MAX_CHARS).collect();
        if truncated {
            snippet.push_str("...");
        }
        let staleness = format_staleness_note(&r.source, r.created_at);
        section.push_str(&format!(
            "### Result {} (score: {:.2}, source: {})\n\
             **File:** {} (lines {}-{})\n\
             {}```\n{}\n```\n\n",
            i + 1,
            r.score,
            r.source,
            r.path,
            r.start_line,
            r.end_line,
            staleness,
            snippet,
        ));
    }

    section.push_str(MEMORY_CONTEXT_CLOSE_TAG);
    Some(section)
}

/// Check if a message looks like a greeting or generic opener.
///
/// Used to detect vague first messages that won't produce useful memory search results, so we can fall back to a broader project-context query.
pub fn is_greeting(text: &str) -> bool {
    const GREETINGS: &[&str] = &[
        "hi",
        "hey",
        "hello",
        "howdy",
        "continue",
        "start",
        "begin",
        "go",
        "good morning",
        "good afternoon",
        "good evening",
        "what's up",
        "whats up",
        "sup",
    ];
    let lowered = text.to_lowercase();
    let trimmed = lowered.trim().trim_end_matches(['.', '!', '?', ',']);
    GREETINGS.contains(&trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_empty() {
        assert_eq!(format_memory_reminder(&[]), None);
    }

    #[test]
    fn test_format_single_result() {
        let results = vec![MemorySearchResult {
            chunk_id: "test:0".to_string(),
            path: "MEMORY.md".to_string(),
            start_line: 0,
            end_line: 5,
            score: 0.9,
            snippet: "Use tracing for logging, never println!".to_string(),
            source: "workspace".to_string(),
            created_at: None,
        }];
        let output = format_memory_reminder(&results).unwrap();
        assert!(output.contains("<memory-context>"));
        assert!(output.contains("### Result 1"));
        assert!(output.contains("score: 0.90"));
        assert!(output.contains("**File:** MEMORY.md (lines 0-5)"));
        assert!(output.contains("```\nUse tracing for logging"));
    }

    #[test]
    fn test_format_preserves_newlines() {
        let results = vec![MemorySearchResult {
            chunk_id: "test:0".to_string(),
            path: "MEMORY.md".to_string(),
            start_line: 0,
            end_line: 3,
            score: 0.85,
            snippet: "## Conventions\n\n- Use Rust\n- No clones".to_string(),
            source: "workspace".to_string(),
            created_at: None,
        }];
        let output = format_memory_reminder(&results).unwrap();
        assert!(
            output.contains("## Conventions\n\n- Use Rust\n- No clones"),
            "newlines in snippet should be preserved, not collapsed"
        );
    }

    #[test]
    fn test_format_truncates_long_snippets() {
        let results = vec![MemorySearchResult {
            chunk_id: "test:0".to_string(),
            path: "test.md".to_string(),
            start_line: 0,
            end_line: 5,
            score: 0.8,
            snippet: "x".repeat(1000),
            source: "session".to_string(),
            created_at: None,
        }];
        let output = format_memory_reminder(&results).unwrap();
        // The snippet is truncated to SNIPPET_MAX_CHARS (500) with a "..." suffix
        assert!(!output.contains(&"x".repeat(501)));
        assert!(output.contains(&format!("{}...", "x".repeat(500))));
    }

    #[test]
    fn test_format_multiple_results() {
        let results = vec![
            MemorySearchResult {
                chunk_id: "a:0".to_string(),
                path: "MEMORY.md".to_string(),
                start_line: 0,
                end_line: 5,
                score: 0.9,
                snippet: "First result".to_string(),
                source: "workspace".to_string(),
                created_at: None,
            },
            MemorySearchResult {
                chunk_id: "b:0".to_string(),
                path: "session.md".to_string(),
                start_line: 10,
                end_line: 15,
                score: 0.7,
                snippet: "Second result".to_string(),
                source: "session".to_string(),
                created_at: None,
            },
        ];
        let output = format_memory_reminder(&results).unwrap();
        assert!(output.contains("### Result 1"));
        assert!(output.contains("### Result 2"));
        assert!(output.contains("score: 0.90"));
        assert!(output.contains("score: 0.70"));
    }

    // -----------------------------------------------------------------------
    // conversation_has_memory_context (idempotency guard) tests
    // -----------------------------------------------------------------------

    fn sample_result() -> MemorySearchResult {
        MemorySearchResult {
            chunk_id: "test:0".into(),
            path: "MEMORY.md".into(),
            start_line: 0,
            end_line: 5,
            score: 0.9,
            snippet: "Project uses Rust for backend services.".into(),
            source: "workspace".into(),
            created_at: None,
        }
    }

    #[test]
    fn test_detects_persisted_block_in_system_message() {
        let block = format_memory_reminder(&[sample_result()]).unwrap();
        let system_content = format!("You are a helpful assistant.\n\n{block}");
        let conversation = vec![
            ConversationItem::system(system_content),
            ConversationItem::user("help me fix the auth bug"),
        ];
        assert!(
            conversation_has_memory_context(&conversation),
            "an already-injected memory-context block must be detected so it is reused, not re-searched"
        );
    }

    #[test]
    fn test_no_block_when_system_lacks_marker() {
        let conversation = vec![
            ConversationItem::system("You are a helpful assistant."),
            ConversationItem::user("hi"),
        ];
        assert!(!conversation_has_memory_context(&conversation));
    }

    #[test]
    fn test_no_block_when_no_leading_system_message() {
        let conversation = vec![ConversationItem::user("hi")];
        assert!(!conversation_has_memory_context(&conversation));
    }

    #[test]
    fn test_no_block_for_empty_conversation() {
        assert!(!conversation_has_memory_context(&[]));
    }

    // -----------------------------------------------------------------------
    // staleness annotation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_staleness_shown_for_old_session_result() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let results = vec![MemorySearchResult {
            chunk_id: "s:0".into(),
            path: "session.md".into(),
            start_line: 0,
            end_line: 5,
            score: 0.8,
            snippet: "old info".into(),
            source: "session".into(),
            created_at: Some(now - 86400 * 10),
        }];
        let output = format_memory_reminder(&results).unwrap();
        assert!(
            output.contains("**Stale ("),
            "10-day-old session result should show stale warning, got: {output}"
        );
    }

    #[test]
    fn test_no_staleness_for_workspace_result() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let results = vec![MemorySearchResult {
            chunk_id: "w:0".into(),
            path: "MEMORY.md".into(),
            start_line: 0,
            end_line: 5,
            score: 0.9,
            snippet: "workspace data".into(),
            source: "workspace".into(),
            created_at: Some(now - 86400 * 30),
        }];
        let output = format_memory_reminder(&results).unwrap();
        assert!(
            !output.contains("**Stale (") && !output.contains("**Note ("),
            "workspace result must not show staleness, got: {output}"
        );
    }

    // -----------------------------------------------------------------------
    // is_greeting tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_greeting_detection() {
        assert!(is_greeting("hi"));
        assert!(is_greeting("Hey!"));
        assert!(is_greeting("Hello."));
        assert!(is_greeting("good morning"));
        assert!(is_greeting("continue"));
        assert!(is_greeting("  HELLO  "));
    }

    #[test]
    fn test_non_greeting() {
        assert!(!is_greeting("help me fix the auth bug"));
        assert!(!is_greeting("implement feature X"));
        assert!(!is_greeting("what does this function do"));
        assert!(!is_greeting("hi there, can you help me with something"));
    }

    // -----------------------------------------------------------------------
    // Injection counter semantics tests
    // -----------------------------------------------------------------------

    /// Empty results must return `None`: `memory_injection_count` is only incremented when `memory_reminder.is_some()`.
    #[test]
    fn test_format_memory_reminder_empty_results_is_none() {
        use fuigo_tools::types::memory_backend::MemorySearchResult;
        let results: Vec<MemorySearchResult> = vec![];
        let reminder = format_memory_reminder(&results);
        assert!(
            reminder.is_none(),
            "empty results must produce None — injection_count must NOT increment"
        );
    }

    /// Confirms that `memory_injection_count` increments when there are actual results to inject.
    #[test]
    fn test_format_memory_reminder_with_results_is_some() {
        use fuigo_tools::types::memory_backend::MemorySearchResult;
        let results = vec![MemorySearchResult {
            chunk_id: "test:0".into(),
            path: "/mem/MEMORY.md".into(),
            start_line: 0,
            end_line: 3,
            score: 0.85,
            snippet: "Project uses Rust for backend services.".into(),
            source: "workspace".into(),
            created_at: None,
        }];
        let reminder = format_memory_reminder(&results);
        assert!(
            reminder.is_some(),
            "non-empty results must produce Some(_) — injection_count SHOULD increment"
        );
    }
    #[test]
    fn versioned_memory_context_expires_on_edit_delete_and_scope_change() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("memory");
        let storage = fuigo_memory::storage::MemoryStorage::with_paths(
            root.clone(),
            root.join("workspace-a"),
        );
        storage.ensure_initialized().unwrap();
        let source = storage.workspace_dir().join("facts.md");
        std::fs::write(&source, "Decision: color = cobalt").unwrap();
        let mut result = sample_result();
        result.path = source.display().to_string();
        result.snippet = "Decision: color = cobalt".into();
        let block = format_memory_reminder_with_storage(&[result.clone()], &storage).unwrap();
        let mut conversation = vec![ConversationItem::system(format!(
            "Keep this prompt.\n{block}"
        ))];
        assert!(!invalidate_stale_memory_context(
            &mut conversation,
            Some(&storage)
        ));
        std::fs::write(&source, "Correction: color = amber").unwrap();
        assert!(invalidate_stale_memory_context(
            &mut conversation,
            Some(&storage)
        ));
        assert!(!conversation_has_memory_context(&conversation));
        let ConversationItem::System(sys) = &conversation[0] else {
            panic!()
        };
        assert!(sys.content.contains("Keep this prompt."));
        result.snippet = "Correction: color = amber".into();
        let block = format_memory_reminder_with_storage(&[result], &storage).unwrap();
        let mut deleted = vec![ConversationItem::system(block.clone())];
        let other = fuigo_memory::storage::MemoryStorage::with_paths(
            root.clone(),
            root.join("workspace-b"),
        );
        other.ensure_initialized().unwrap();
        let mut scoped = vec![ConversationItem::system(block)];
        assert!(invalidate_stale_memory_context(&mut scoped, Some(&other)));
        std::fs::remove_file(source).unwrap();
        assert!(invalidate_stale_memory_context(
            &mut deleted,
            Some(&storage)
        ));
    }

    #[test]
    fn legacy_memory_context_is_removed_without_source_authority() {
        let mut conversation = vec![ConversationItem::system(
            "Prompt <memory-context>old fact</memory-context> preserved",
        )];
        assert!(invalidate_stale_memory_context(&mut conversation, None));
        let ConversationItem::System(sys) = &conversation[0] else {
            panic!()
        };
        assert_eq!(sys.content.as_ref(), "Prompt  preserved");
    }
}
