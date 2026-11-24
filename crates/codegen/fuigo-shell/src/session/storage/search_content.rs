//! Extracting searchable text from session update files.
//!
//! The peek structs are shared with the resume/replay collectors in [`super`], so the indexed text cannot drift from what a resumed session replays.
//! Everything downstream of the extracted string (hashing, dedup, the SQLite index itself) lives in `fuigo-session-search`.

use std::io::{self, BufRead};
use std::path::Path;

use super::{
    ContentPeek, FUIGO_SESSION_UPDATE_METHOD, PromptExtractEvent, RawLinePeek, RawParamsPeek,
    collect_prompts_from_events,
};
use crate::session::wire_tags::{REWIND_MARKER, USER_MESSAGE_CHUNK};

const SEARCH_CONTENT_CHAR_LIMIT: usize = 200_000;

// Zero-copy peek structs
// Text-bearing fields are `Cow`, not `&str`: serde cannot borrow `&str` from JSON strings containing escapes
// Borrowing would error and silently drop the message from the index

/// Peek for assistant text (agent_message_chunk content.text).
#[derive(serde::Deserialize)]
struct AgentContentPeek<'a> {
    #[serde(borrow)]
    update: AgentUpdatePeek<'a>,
}

#[derive(serde::Deserialize)]
struct AgentUpdatePeek<'a> {
    #[serde(borrow, default)]
    content: Option<AgentTextPeek<'a>>,
}

#[derive(serde::Deserialize)]
struct AgentTextPeek<'a> {
    #[serde(rename = "type", default)]
    content_type: Option<&'a str>,
    #[serde(borrow, default)]
    text: Option<std::borrow::Cow<'a, str>>,
}

/// Peek for user message content (user_message_chunk content.text).
/// Reuses [`ContentPeek`] so the peeked fields are defined in one place.
#[derive(serde::Deserialize)]
struct UserContentPeek<'a> {
    #[serde(borrow)]
    update: UserUpdatePeek<'a>,
}

#[derive(serde::Deserialize)]
struct UserUpdatePeek<'a> {
    #[serde(borrow, default)]
    content: Option<ContentPeek<'a>>,
    #[serde(default, rename = "_meta")]
    meta: Option<super::RawChunkMetaPeek>,
}

/// Peek for tool call metadata (tool_call title and locations[].path).
#[derive(serde::Deserialize)]
struct ToolCallPeek<'a> {
    #[serde(borrow)]
    update: ToolUpdatePeek<'a>,
}

#[derive(serde::Deserialize)]
struct ToolUpdatePeek<'a> {
    #[serde(borrow, default)]
    title: Option<std::borrow::Cow<'a, str>>,
    #[serde(borrow, default)]
    locations: Option<Vec<ToolLocationPeek<'a>>>,
}

#[derive(serde::Deserialize)]
struct ToolLocationPeek<'a> {
    #[serde(borrow, default)]
    path: Option<std::borrow::Cow<'a, str>>,
}

const ASSISTANT_MAX_CHARS: usize = 100_000;
const TOOL_MAX_CALLS: usize = 200;
const TOOL_MAX_CHARS: usize = 100_000;

/// Flush the assistant buffer on turn boundary; called in every non-agent_message_chunk branch to match `collect_assistant_text`
fn flush_assistant(current: &mut String, texts: &mut Vec<String>) {
    if !current.is_empty() {
        let t = current.trim().to_string();
        if !t.is_empty() {
            texts.push(t);
        }
        current.clear();
    }
}

/// A repeated boundary is a no-op in `collect_prompts_from_events`, so runs collapse to one and the cached state stays small.
fn push_boundary(events: &mut Vec<PromptExtractEvent>) {
    if events.last() != Some(&PromptExtractEvent::NotUserMessage) {
        events.push(PromptExtractEvent::NotUserMessage);
    }
}

/// Extraction state after some prefix of `updates.jsonl`; feeding the rest of the file and finishing gives the same text as one full pass.
#[derive(Clone, Default)]
struct ContentCollector {
    prompt_events: Vec<PromptExtractEvent>,
    assistant_texts: Vec<String>,
    current_assistant: String,
    tool_meta: Vec<String>,
    assistant_chars: usize,
    tool_call_count: usize,
    tool_chars_emitted: usize,
}

impl ContentCollector {
    /// One line without its newline, or the error a line-by-line read reports for it (invalid UTF-8).
    fn feed(&mut self, line_result: io::Result<&str>) {
        let Self {
            prompt_events,
            assistant_texts,
            current_assistant,
            tool_meta,
            assistant_chars,
            tool_call_count,
            tool_chars_emitted,
        } = self;
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(error = %e, "skipping unreadable line in single-pass content collector");
                // An I/O error is a turn boundary, matching the iterator-based collectors
                flush_assistant(current_assistant, assistant_texts);
                push_boundary(prompt_events);
                return;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return;
        }

        let (raw_params, is_fuigo) =
            if let Ok(env) = serde_json::from_str::<RawLinePeek<'_>>(trimmed) {
                let raw = env.params.map(|p| p.get()).unwrap_or(trimmed);
                let fuigo = env.method == Some(FUIGO_SESSION_UPDATE_METHOD);
                (raw, fuigo)
            } else {
                (trimmed, false)
            };

        let update_peek = serde_json::from_str::<RawParamsPeek<'_>>(raw_params)
            .ok()
            .and_then(|p| p.update);
        let tag = update_peek.as_ref().map(|u| u.session_update);

        // Content events arrive on ACP "session/update"; control events (rewind markers) on the Ferrox Labs "_fuigo/session/update" extension
        if !is_fuigo {
            match tag {
                Some(t) if t == *USER_MESSAGE_CHUNK => {
                    flush_assistant(current_assistant, assistant_texts);
                    if let Ok(peek) = serde_json::from_str::<UserContentPeek<'_>>(raw_params)
                        && let Some(content) = peek.update.content
                        && content.content_type == Some("text")
                        && let Some(text) = content.text
                    {
                        if content
                            .meta
                            .as_ref()
                            .is_some_and(|m| m.bash_command.is_some())
                            || peek
                                .update
                                .meta
                                .as_ref()
                                .is_some_and(|m| m.host_turn == Some(true))
                        {
                            push_boundary(prompt_events);
                        } else {
                            let prompt_index = peek
                                .update
                                .meta
                                .as_ref()
                                .and_then(|m| m.prompt_index.map(|v| v as usize));
                            prompt_events.push(PromptExtractEvent::UserTextChunk {
                                text: text.into_owned(),
                                prompt_index,
                            });
                        }
                    } else {
                        push_boundary(prompt_events);
                    }
                }
                Some("agent_message_chunk") => {
                    // This chunk continues the same assistant turn, so the buffer is not flushed
                    if *assistant_chars < ASSISTANT_MAX_CHARS
                        && let Ok(peek) = serde_json::from_str::<AgentContentPeek<'_>>(raw_params)
                        && let Some(content) = peek.update.content
                        && content.content_type == Some("text")
                        && let Some(text) = content.text
                        && !text.is_empty()
                    {
                        let sep_cost = usize::from(!current_assistant.is_empty());
                        let budget = ASSISTANT_MAX_CHARS
                            .saturating_sub(*assistant_chars)
                            .saturating_sub(sep_cost);
                        if budget > 0 {
                            if sep_cost > 0 {
                                current_assistant.push(' ');
                                *assistant_chars += 1;
                            }
                            let mut take = text.len().min(budget);
                            while take > 0 && !text.is_char_boundary(take) {
                                take -= 1;
                            }
                            current_assistant.push_str(&text[..take]);
                            *assistant_chars += take;
                        }
                    }
                    push_boundary(prompt_events);
                }
                Some("agent_thought_chunk") => {
                    // A thought chunk continues the same assistant turn: it is not indexed, but must not flush the buffer
                    push_boundary(prompt_events);
                }
                Some("tool_call") => {
                    flush_assistant(current_assistant, assistant_texts);
                    if *tool_call_count < TOOL_MAX_CALLS {
                        *tool_call_count += 1;
                        if let Ok(peek) = serde_json::from_str::<ToolCallPeek<'_>>(raw_params) {
                            if let Some(title) = peek.update.title
                                && !title.is_empty()
                            {
                                let budget = TOOL_MAX_CHARS.saturating_sub(*tool_chars_emitted);
                                if budget > 0 {
                                    let mut take = title.len().min(budget);
                                    while take > 0 && !title.is_char_boundary(take) {
                                        take -= 1;
                                    }
                                    tool_meta.push(title[..take].to_string());
                                    *tool_chars_emitted += take;
                                }
                            }
                            if let Some(locs) = peek.update.locations {
                                for loc in locs {
                                    if let Some(p) = loc.path
                                        && !p.is_empty()
                                    {
                                        let budget =
                                            TOOL_MAX_CHARS.saturating_sub(*tool_chars_emitted);
                                        if budget > 0 {
                                            let mut take = p.len().min(budget);
                                            while take > 0 && !p.is_char_boundary(take) {
                                                take -= 1;
                                            }
                                            tool_meta.push(p[..take].to_string());
                                            *tool_chars_emitted += take;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    push_boundary(prompt_events);
                }
                _ => {
                    flush_assistant(current_assistant, assistant_texts);
                    push_boundary(prompt_events);
                }
            }
        } else {
            match tag {
                Some(t) if t == *REWIND_MARKER => {
                    flush_assistant(current_assistant, assistant_texts);
                    if let Some(ref u) = update_peek
                        && let Some(idx) = u.target_prompt_index
                    {
                        prompt_events.push(PromptExtractEvent::RewindTo(idx));
                    } else {
                        push_boundary(prompt_events);
                    }
                }
                _ => {
                    flush_assistant(current_assistant, assistant_texts);
                    push_boundary(prompt_events);
                }
            }
        }
    }

    fn finish(&self) -> String {
        let mut assistant_texts = self.assistant_texts.clone();
        if !self.current_assistant.is_empty() {
            let t = self.current_assistant.trim().to_string();
            if !t.is_empty() {
                assistant_texts.push(t);
            }
        }

        let prompts = collect_prompts_from_events(self.prompt_events.iter().cloned());

        let parts = [
            prompts.join("\n\n"),
            assistant_texts.join("\n"),
            self.tool_meta.join("\n"),
        ];
        let mut joined = parts.join("\n\n");

        if joined.len() > SEARCH_CONTENT_CHAR_LIMIT {
            // Keep the tail: the most recent content is the most relevant.
            let mut start = joined.len().saturating_sub(SEARCH_CONTENT_CHAR_LIMIT);
            while start < joined.len() && !joined.is_char_boundary(start) {
                start += 1;
            }
            joined = joined[start..].to_string();
        }
        joined
    }
}

/// Bytes of the parsed prefix kept to spot a file rewritten in place under the same inode.
const ANCHOR_LEN: usize = 64;

/// Collector state for a transcript up to its last complete line, so the next extraction of a growing file reads only the appended tail.
struct CachedTail {
    path: std::path::PathBuf,
    file_id: Option<(u64, u64)>,
    offset: u64,
    anchor: Vec<u8>,
    collector: ContentCollector,
}

/// Live sessions re-index after every prompt; a handful of entries covers them, and a launch reindex only cycles through.
#[cfg(not(test))]
const TAIL_CACHE_ENTRIES: usize = 4;
// Tests share the process cache; room for all of them keeps a resumption test from being evicted by a sibling
#[cfg(test)]
const TAIL_CACHE_ENTRIES: usize = 256;
static TAIL_CACHE: std::sync::Mutex<Vec<CachedTail>> = std::sync::Mutex::new(Vec::new());

fn file_id(meta: &std::fs::Metadata) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Some((meta.dev(), meta.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        None
    }
}

fn take_cached_tail(path: &Path) -> Option<CachedTail> {
    let mut cache = TAIL_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let at = cache.iter().position(|e| e.path == path)?;
    Some(cache.remove(at))
}

fn store_cached_tail(entry: CachedTail) {
    let mut cache = TAIL_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    cache.retain(|e| e.path != entry.path);
    if cache.len() >= TAIL_CACHE_ENTRIES {
        cache.remove(0);
    }
    cache.push(entry);
}

/// The cached prefix is still the file's prefix: same file, not shorter, and the bytes before the offset unchanged.
fn cached_prefix_holds(
    file: &mut std::fs::File,
    meta: &std::fs::Metadata,
    entry: &CachedTail,
) -> bool {
    use std::io::{Read as _, Seek as _};
    if entry.file_id != file_id(meta) || meta.len() < entry.offset {
        return false;
    }
    let start = entry.offset - entry.anchor.len() as u64;
    let mut buf = vec![0u8; entry.anchor.len()];
    file.seek(io::SeekFrom::Start(start)).is_ok()
        && file.read_exact(&mut buf).is_ok()
        && buf == entry.anchor
}

/// Collect all indexable content from a session's `updates.jsonl` in one pass, without deserializing full `acp::SessionNotification` objects.
/// A file this process extracted before and that has only grown since is resumed from the cached state, reading just the new bytes.
pub(super) fn collect_all_indexable_content_single_pass(
    updates_path: &Path,
) -> io::Result<(String, u64)> {
    use std::io::Seek as _;
    let cached = take_cached_tail(updates_path);
    let mut file = match std::fs::File::open(updates_path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((String::new(), 0)),
        Err(e) => return Err(e),
    };
    let meta = file.metadata();
    let bytes_read = meta.as_ref().map(|m| m.len()).unwrap_or(0);
    let file_id = meta.as_ref().ok().and_then(file_id);
    let (mut collector, mut offset, mut anchor) = match (cached, &meta) {
        (Some(entry), Ok(meta)) if cached_prefix_holds(&mut file, meta, &entry) => {
            (entry.collector, entry.offset, entry.anchor)
        }
        _ => (ContentCollector::default(), 0, Vec::new()),
    };
    file.seek(io::SeekFrom::Start(offset))?;
    let mut reader = io::BufReader::new(file);

    let mut line = Vec::new();
    let mut partial = None;
    loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        let complete = line.last() == Some(&b'\n');
        let text = line.strip_suffix(b"\n").unwrap_or(&line);
        let text = text.strip_suffix(b"\r").unwrap_or(text);
        let text =
            std::str::from_utf8(text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
        if !complete {
            // A record still being written: count it this time, but keep it out of the cached state so the next read sees it whole
            let mut tail = collector.clone();
            tail.feed(text);
            partial = Some(tail);
            break;
        }
        collector.feed(text);
        offset += n as u64;
        anchor.extend_from_slice(&line);
        if anchor.len() > ANCHOR_LEN {
            anchor.drain(..anchor.len() - ANCHOR_LEN);
        }
    }

    let joined = partial.as_ref().unwrap_or(&collector).finish();
    store_cached_tail(CachedTail {
        path: updates_path.to_path_buf(),
        file_id,
        offset,
        anchor,
        collector,
    });
    Ok((joined, bytes_read))
}

/// Drops this process's cached extraction state for `path`.
#[cfg(test)]
pub(super) fn forget_cached_tail(path: &Path) {
    take_cached_tail(path);
}

/// Summary fixture shared by this module's tests and `search.rs`.
#[cfg(test)]
pub(super) fn test_summary(
    session_id: &str,
    cwd: &str,
    title: &str,
) -> crate::session::persistence::Summary {
    use crate::session::info::Info;
    use crate::session::persistence::Summary;
    use agent_client_protocol as acp;

    Summary {
        info: Info {
            id: acp::SessionId::new(session_id),
            cwd: cwd.to_string(),
        },
        cwd_generation: 0,
        previous_cwd: None,
        pending_cwd_switch_reminder: None,
        cwd_switch_bookkeeping_generation: 0,
        session_summary: title.to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        num_messages: 0,
        num_chat_messages: 0,
        current_model_id: acp::ModelId::new("test"),
        parent_session_id: None,
        forked_at: None,
        collection_id: None,
        next_trace_turn: 0,
        chat_format_version: 1,
        prompt_display_cwd: None,
        session_kind: None,
        fork_context_source: None,
        fork_parent_prompt_id: None,
        inherited_prefix_len: None,
        hidden: None,
        source_workspace_dir: None,
        git_root_dir: None,
        git_remotes: Vec::new(),
        head_commit: None,
        head_branch: None,
        request_id: None,
        fuigo_home: None,
        last_active_at: None,
        generated_title: None,
        title_is_manual: false,
        worktree_label: None,
        agent_name: None,
        sandbox_profile: None,
        reasoning_effort: None,
        context_window: None,
        last_turn_summary: None,
        last_turn_summary_prompt_id: None,
        last_recap: None,
        permission_policy: None,
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there"
)]
#[cfg(test)]
#[path = "search_content_tests.rs"]
mod tests;
