//! Format memory search results as `<system-reminder>` content.
//!
//! Used for:
//! - Session start: inject relevant past context on the first turn
//! - Post-compaction: recover relevant memory after context is lost

use fuigo_chat_state::{
    find_memory_context_block, memory_context_close_tag, memory_context_open_tag,
};
use fuigo_sampling_types::ConversationItem;
use fuigo_tools::types::memory_backend::{MemorySearchResult, format_staleness_note};

const SNIPPET_MAX_CHARS: usize = 500;

/// File under the Fuigo home that holds this installation's memory-context nonce.
const NONCE_FILE: &str = ".memory-context-nonce";

static NONCE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn nonce_path() -> std::path::PathBuf {
    fuigo_tools::util::fuigo_home::fuigo_home().join(NONCE_FILE)
}

/// The nonce that marks memory-context blocks Fuigo itself inserted, used to
/// RECOGNISE them (detection and per-turn invalidation).
///
/// Blocks are found and removed only by this nonce, never by the bare
/// `<memory-context>` literal, which any repo file can contain (R098/P91 R1).
/// The value is random, created once per installation by
/// [`memory_context_nonce_for_insert`] (so a resumed or forked session still
/// recognises its own blocks) and is never derived from anything a repository can
/// choose. Recognition never creates the file, so a session with memory off writes
/// nothing: when no nonce exists yet, no block of ours can exist either, and a
/// throwaway value that matches nothing is returned.
pub fn memory_context_nonce() -> &'static str {
    if let Some(nonce) = NONCE.get() {
        return nonce;
    }
    match read_nonce(&nonce_path()) {
        Ok(nonce) => NONCE.get_or_init(|| nonce),
        Err(_) => {
            static UNMATCHABLE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
            UNMATCHABLE.get_or_init(|| uuid::Uuid::new_v4().simple().to_string())
        }
    }
}

/// The nonce to put on a block Fuigo is about to INSERT; creates the installation
/// nonce on first use. `None` when it can neither be read nor created: memory is
/// then not injected at all (fail closed), because a block marked with a
/// throwaway value could not be recognised, validated or removed by a later
/// process (Astra P91 r1 #3).
pub fn memory_context_nonce_for_insert() -> Option<&'static str> {
    if let Some(nonce) = NONCE.get() {
        return Some(nonce);
    }
    let path = nonce_path();
    match load_or_create_nonce(&path) {
        Ok(nonce) => Some(NONCE.get_or_init(|| nonce)),
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "memory-context nonce file unavailable; recalled memory is not injected"
            );
            None
        }
    }
}

fn read_nonce(path: &std::path::Path) -> std::io::Result<String> {
    let text = std::fs::read_to_string(path)?;
    let nonce = text.trim().to_owned();
    if is_valid_nonce(&nonce) {
        Ok(nonce)
    } else {
        Err(std::io::Error::other("malformed memory-context nonce file"))
    }
}

fn is_valid_nonce(nonce: &str) -> bool {
    nonce.len() == 32 && nonce.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Read the installation nonce, creating it atomically (no clobber) when absent.
pub(crate) fn load_or_create_nonce(path: &std::path::Path) -> std::io::Result<String> {
    let read = read_nonce;
    match read(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        other => return other,
    }
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("nonce path has no parent"))?;
    std::fs::create_dir_all(dir)?;
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let mut temp = tempfile::NamedTempFile::new_in(dir)?;
    std::io::Write::write_all(&mut temp, nonce.as_bytes())?;
    temp.as_file().sync_all()?;
    match temp.persist_noclobber(path) {
        Ok(_) => Ok(nonce),
        // Another process created it first: everyone uses the winner's value.
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => read(path),
        Err(error) => Err(error.error),
    }
}

/// Returns `true` if a memory-context block is already persisted in the leading system message.
/// Callers reuse a persisted block after validating its source version before each turn.
/// A re-scored block would mutate the system-prompt prefix and bust the KV cache for the whole downstream conversation.
/// Only a complete block carrying this installation's nonce counts.
/// A pre-P91 block persisted at the end of the system message counts too: it is
/// still validated every turn, and re-injecting after it would push it away from
/// the end, where it could no longer be recognised (Astra P91 r2 #1).
pub fn conversation_has_memory_context(items: &[ConversationItem]) -> bool {
    matches!(
        items.first(),
        Some(ConversationItem::System(sys))
            if find_memory_context_block(&sys.content, memory_context_nonce(), 0).is_some()
                || legacy_tail_block(&sys.content).is_some()
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
                    .is_ok_and(|content| {
                        r.source_revision.as_deref().is_some_and(|revision| {
                            blake3::hash(content.as_bytes()).to_hex().as_str() == revision
                        })
                    })
        })
        .cloned()
        .collect();
    let mut block = format_memory_reminder(&current)?;
    let sources: Vec<_> = current
        .iter()
        .filter_map(|r| {
            Some((
                r.path.clone(),
                r.source_revision.clone()?,
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
    let open = memory_context_open_tag(memory_context_nonce_for_insert()?);
    block = block.replacen(&open, &format!("{open}\n{SOURCES_MARKER}{json} -->"), 1);
    Some(block)
}

/// Whether a block's recorded sources are all still current in this workspace.
fn block_sources_are_current(
    block: &str,
    storage: Option<&fuigo_memory::storage::MemoryStorage>,
) -> bool {
    storage.is_some_and(|storage| {
        let Some(marker) = block.find(SOURCES_MARKER) else {
            return false;
        };
        let encoded = &block[marker + SOURCES_MARKER.len()..];
        let Some(close) = encoded.find(" -->") else {
            return false;
        };
        let Ok(sources) = serde_json::from_str::<Vec<(String, String)>>(&encoded[..close]) else {
            return false;
        };
        !sources.is_empty()
            && sources.iter().all(|(path, digest)| {
                storage
                    .read_file(std::path::Path::new(path), None, None)
                    .is_ok_and(|content| blake3::hash(content.as_bytes()).to_hex().as_str() == digest)
            })
    })
}

/// Bare opening tag + newline that Fuigo emitted before P91.
const LEGACY_OPEN: &str = "<memory-context>\n";
const LEGACY_CLOSE: &str = "</memory-context>";
const LEGACY_HEADER: &str = "## Relevant Memory from Past Sessions\n";

/// A pre-P91 block (bare tags) persisted at the END of an item by a session that
/// predates P91: the first-turn block at the end of the system message, or the
/// post-compaction block that was the last section of a `<system-reminder>`.
///
/// Recognised only in that exact shape, so text that merely mentions the tag is
/// never touched:
/// - the item ends with the bare close tag (optionally followed by the closing
///   `</system-reminder>` of the compaction wrapper);
/// - the block starts at the RIGHTMOST bare opening tag that is followed by the old
///   emitter's sources marker (a JSON list of `[path, digest]` pairs) and its header,
///   with no bare close tag in between. Every pre-P91 block carries that marker
///   (unversioned blocks were already removed by the pre-P91 code every turn), and a
///   recalled snippet that copies an opening tag or header without a marker cannot
///   move the boundary;
/// - an earlier opening tag can never extend the range, so nothing before the
///   block's own opening tag is removed.
///
/// Returns the byte range of the block.
fn legacy_tail_block(text: &str) -> Option<std::ops::Range<usize>> {
    let mut tail = text.trim_end();
    if let Some(inner) = tail.strip_suffix("</system-reminder>") {
        tail = inner.trim_end();
    }
    let body = tail.strip_suffix(LEGACY_CLOSE)?;
    for (start, _) in body.rmatch_indices(LEGACY_OPEN) {
        let inner = &body[start + LEGACY_OPEN.len()..];
        if inner.contains(LEGACY_CLOSE) {
            return None;
        }
        let Some(rest) = inner.strip_prefix(SOURCES_MARKER) else {
            continue;
        };
        let Some(end) = rest.find(" -->\n") else {
            continue;
        };
        if serde_json::from_str::<Vec<(String, String)>>(&rest[..end]).is_ok()
            && rest[end + " -->\n".len()..].starts_with(LEGACY_HEADER)
        {
            return Some(start..tail.len());
        }
    }
    None
}

/// Remove cached memory whose source disappeared, changed, or left this workspace.
/// Blocks without a source marker (or with memory off) are removed rather than trusted indefinitely.
///
/// Only complete blocks that carry this installation's nonce are touched, plus a
/// pre-P91 block persisted at the end of an item (see [`legacy_tail_block`]). Text that contains a bare `<memory-context>` literal
/// elsewhere, an unknown nonce, or an opening tag with no matching close is kept
/// byte for byte: it was not inserted by Fuigo (for example a repo's AGENTS.md)
/// and cutting at it would delete whatever follows, such as the user's own rules.
/// Project-instruction items are never scanned, since Fuigo never puts memory there.
pub fn invalidate_stale_memory_context(
    items: &mut [ConversationItem],
    storage: Option<&fuigo_memory::storage::MemoryStorage>,
) -> bool {
    fn strip(text: &str, storage: Option<&fuigo_memory::storage::MemoryStorage>) -> String {
        let nonce = memory_context_nonce();
        let mut output = String::new();
        let mut rest = text;
        while let Some(range) = find_memory_context_block(rest, nonce, 0) {
            let (start, end) = (range.start, range.end);
            output.push_str(&rest[..start]);
            let block = &rest[start..end];
            if block_sources_are_current(block, storage) {
                output.push_str(block);
            }
            rest = &rest[end..];
        }
        output.push_str(rest);
        output
    }
    fn strip_with_legacy(
        text: &str,
        storage: Option<&fuigo_memory::storage::MemoryStorage>,
    ) -> String {
        let mut output = strip(text, storage);
        if let Some(range) = legacy_tail_block(&output)
            && !block_sources_are_current(&output[range.clone()], storage)
        {
            output.replace_range(range, "");
        }
        output
    }
    let mut changed = false;
    for item in items {
        match item {
            ConversationItem::System(sys) => {
                let updated = strip_with_legacy(&sys.content, storage);
                if updated != sys.content.as_ref() {
                    sys.content = updated.into();
                    changed = true;
                }
            }
            ConversationItem::User(user)
                if user.synthetic_reason.is_some()
                    && user.synthetic_reason
                        != Some(fuigo_sampling_types::conversation::SyntheticReason::ProjectInstructions) =>
            {
                for part in &mut user.content {
                    if let fuigo_sampling_types::conversation::ContentPart::Text { text } = part {
                        let updated = strip_with_legacy(text, storage);
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

    let nonce = memory_context_nonce_for_insert()?;
    let open = memory_context_open_tag(nonce);
    let mut section = format!(
        "{open}\n## Relevant Memory from Past Sessions\n\n\
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
            // A session-log file name is derived from the first user prompt, so it
            // goes through the same content filter as the snippet (P92 Astra MEDIUM).
            if fuigo_memory::safety::is_safe_memory(&r.path) {
                neutralize_memory_tags(&r.path)
            } else {
                "(file name withheld)".to_owned()
            },
            r.start_line,
            r.end_line,
            staleness,
            neutralize_memory_tags(&snippet),
        ));
    }

    section.push_str(&memory_context_close_tag(nonce));
    Some(section)
}

/// Memory text is not ours to frame: escape any memory-context tag inside it so a
/// recalled line can never end (or fake) the block that carries it.
fn neutralize_memory_tags(text: &str) -> String {
    text.replace("</memory-context", "&lt;/memory-context")
        .replace("<memory-context", "&lt;memory-context")
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
            source_revision: None,
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
        assert!(output.starts_with(&memory_context_open_tag(memory_context_nonce())));
        assert!(output.ends_with(&memory_context_close_tag(memory_context_nonce())));
        assert!(output.contains("### Result 1"));
        assert!(output.contains("score: 0.90"));
        assert!(output.contains("**File:** MEMORY.md (lines 0-5)"));
        assert!(output.contains("```\nUse tracing for logging"));
    }

    #[test]
    fn test_format_preserves_newlines() {
        let results = vec![MemorySearchResult {
            source_revision: None,
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
            source_revision: None,
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
                source_revision: None,
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
                source_revision: None,
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
            source_revision: None,
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
            source_revision: None,
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
            source_revision: None,
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
            source_revision: None,
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
        result.source_revision = Some(blake3::hash(result.snippet.as_bytes()).to_hex().to_string());
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
        result.source_revision = Some(blake3::hash(result.snippet.as_bytes()).to_hex().to_string());
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
    fn search_revision_cannot_be_rebound_after_edit() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("memory");
        let storage = fuigo_memory::storage::MemoryStorage::with_paths(root.clone(), root.join("workspace"));
        storage.ensure_initialized().unwrap();
        let source = storage.workspace_dir().join("facts.md");
        let mut result = sample_result();
        result.path = source.display().to_string();
        result.snippet = "Decision: color = cobalt".into();
        std::fs::write(&source, &result.snippet).unwrap();
        result.source_revision = Some(blake3::hash(result.snippet.as_bytes()).to_hex().to_string());
        assert!(format_memory_reminder_with_storage(&[result.clone()], &storage).is_some());
        std::fs::write(&source, "Correction: color = amber").unwrap();
        assert!(format_memory_reminder_with_storage(&[result.clone()], &storage).is_none());
        result.source_revision = None;
        assert!(format_memory_reminder_with_storage(&[result], &storage).is_none());
    }

    #[test]
    fn own_memory_context_is_removed_without_source_authority() {
        let block = format_memory_reminder(&[sample_result()]).unwrap();
        let mut conversation = vec![ConversationItem::system(format!(
            "Prompt {block} preserved"
        ))];
        assert!(invalidate_stale_memory_context(&mut conversation, None));
        let ConversationItem::System(sys) = &conversation[0] else {
            panic!()
        };
        assert_eq!(sys.content.as_ref(), "Prompt  preserved");
    }

    /// Un-nonced blocks are indistinguishable from text a repo wrote, so they are
    /// never cut, even in the system message (a resumed pre-P91 session keeps its
    /// old block as inert text; see receipt R098).
    #[test]
    fn bare_memory_context_pair_is_not_ours_and_is_kept() {
        let text = "Prompt <memory-context>old fact</memory-context> preserved";
        let mut conversation = vec![ConversationItem::system(text)];
        assert!(!invalidate_stale_memory_context(&mut conversation, None));
        let ConversationItem::System(sys) = &conversation[0] else {
            panic!()
        };
        assert_eq!(sys.content.as_ref(), text);
    }
}

#[cfg(test)]
#[path = "memory_context_p91_tests.rs"]
mod p91_tests;
