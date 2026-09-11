//! Per-session read-dedupe cache: a repeat `read_file` of an unchanged range whose earlier result
//! is still intact in the model's context returns a short note instead of the content.
//!
//! Scope and invalidation (all conservative):
//! - One cache per `SessionActor`; a child subagent has its own actor and never sees the parent's.
//! - Any tool call that is not read-only (execute, edit, patch, write, MCP `use_tool`, a spawned
//!   subagent) clears the whole cache before and after its batch.
//! - A compaction (the last-compaction prompt index changed) clears the cache.
//! - The request-time pruner (`fuigo-chat-state` `prune_conversation`) rewrites old tool results
//!   in the request copy, so the stored conversation cannot be inspected for it; [`PruneMirror`]
//!   replays its rule from the same config, and any result it would trim or clear counts as gone.
//! - The current file bytes are re-hashed on every lookup; a changed hash reads the file again.
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use fuigo_sampling_types::ConversationItem;

/// One cached read range.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ReadKey {
    /// Canonical absolute path.
    pub path: PathBuf,
    pub offset: Option<i64>,
    pub limit: Option<u64>,
    /// `slice` or `indentation` (codex); fuigo_build reads are always `slice`.
    pub mode: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ReadEntry {
    /// blake3 of the file bytes at the time of the read.
    pub hash: [u8; 32],
    /// Prompt index of the turn that produced the result (0-based).
    pub prompt_index: usize,
    /// Model tool-call id of the result that carries the content.
    pub tool_call_id: String,
    /// Lines in the file at the time of the read.
    pub lines: usize,
    /// Size of the whole tool result (chars): the pruner's soft-trim unit.
    pub content_chars: usize,
}

/// The pruner's thresholds, mirrored from the session's `PruningConfig`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PruneMirror {
    pub enabled: bool,
    pub keep_last_n_turns: usize,
    pub soft_trim_threshold: usize,
    pub hard_clear_age_turns: usize,
}

impl PruneMirror {
    pub(crate) fn disabled() -> Self {
        Self {
            enabled: false,
            keep_last_n_turns: 0,
            soft_trim_threshold: usize::MAX,
            hard_clear_age_turns: usize::MAX,
        }
    }
}

impl From<&crate::config::PruningConfig> for PruneMirror {
    fn from(cfg: &crate::config::PruningConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            keep_last_n_turns: cfg.keep_last_n_turns,
            soft_trim_threshold: cfg.soft_trim_threshold,
            hard_clear_age_turns: cfg.hard_clear_age_turns,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ReadDedupeCache {
    entries: HashMap<ReadKey, ReadEntry>,
    prune: PruneMirror,
    compaction_marker: Option<usize>,
}

impl ReadDedupeCache {
    pub(crate) fn new(prune: PruneMirror) -> Self {
        Self {
            entries: HashMap::new(),
            prune,
            compaction_marker: None,
        }
    }

    pub(crate) fn record(&mut self, key: ReadKey, entry: ReadEntry) {
        self.entries.insert(key, entry);
    }

    pub(crate) fn get(&self, key: &ReadKey) -> Option<&ReadEntry> {
        self.entries.get(key)
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn invalidate_all(&mut self, reason: &str) {
        if !self.entries.is_empty() {
            tracing::debug!(entries = self.entries.len(), reason, "read-dedupe cache cleared");
            self.entries.clear();
        }
    }

    /// Sync with the session's last-compaction prompt index; a change means the earlier
    /// results were rewritten, so everything cached is gone.
    pub(crate) fn observe_compaction_marker(&mut self, marker: Option<usize>) {
        if marker != self.compaction_marker {
            if self.compaction_marker.is_some() || marker.is_some() {
                self.invalidate_all("compaction");
            }
            self.compaction_marker = marker;
        }
    }

    /// Whether the earlier result is still intact for the model: present in `conversation`
    /// under its tool-call id and, per the pruner mirror, neither soft-trimmed nor hard-cleared.
    pub(crate) fn result_intact(&self, entry: &ReadEntry, conversation: &[ConversationItem]) -> bool {
        let mut turn_from_end = 0usize;
        let mut seen_first_user = false;
        for item in conversation.iter().rev() {
            match item {
                ConversationItem::User(_) => {
                    if seen_first_user {
                        turn_from_end += 1;
                    }
                    seen_first_user = true;
                }
                ConversationItem::ToolResult(result) if result.tool_call_id == entry.tool_call_id => {
                    if !self.prune.enabled {
                        return true;
                    }
                    if turn_from_end >= self.prune.hard_clear_age_turns {
                        return false;
                    }
                    if turn_from_end >= self.prune.keep_last_n_turns
                        && entry.content_chars > self.prune.soft_trim_threshold
                    {
                        return false;
                    }
                    return true;
                }
                _ => {}
            }
        }
        false
    }
}

pub(crate) fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// Tool calls that may change files, or run code that does, clear the cache: everything that is
/// not read-only, plus subagent spawns and MCP tools regardless of their read-only flag.
pub(crate) fn call_invalidates(tool_name: &str, is_read_only: bool) -> bool {
    !is_read_only
        || matches!(tool_name, "spawn_subagent" | "task" | "use_tool" | "Task" | "Agent")
        || tool_name.contains(crate::session::mcp_servers::MCP_TOOL_NAME_DELIMITER)
}

/// One requested file of a `read_file` call, as the model wrote it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReadRequestEntry {
    pub path: String,
    pub offset: Option<i64>,
    pub limit: Option<u64>,
}

fn int_arg(value: Option<&serde_json::Value>) -> Option<i64> {
    let v = value?;
    v.as_i64()
        .or_else(|| v.as_f64().map(|f| f as i64))
        .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

/// The file entries of a `read_file` call in request order: the single `target_file`/`file_path`
/// first, then every `files[]` entry. Blank paths are skipped.
pub(crate) fn parse_read_entries(args: &serde_json::Value) -> Vec<ReadRequestEntry> {
    let mut out = Vec::new();
    let single = args
        .get("target_file")
        .or_else(|| args.get("file_path"))
        .or_else(|| args.get("path"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|p| !p.is_empty());
    if let Some(path) = single {
        out.push(ReadRequestEntry {
            path: path.to_owned(),
            offset: int_arg(args.get("offset")),
            limit: int_arg(args.get("limit")).and_then(|l| u64::try_from(l).ok()),
        });
    }
    if let Some(files) = args.get("files").and_then(|f| f.as_array()) {
        for file in files {
            let Some(path) = file.get("path").and_then(|v| v.as_str()).map(str::trim) else {
                continue;
            };
            if path.is_empty() {
                continue;
            }
            out.push(ReadRequestEntry {
                path: path.to_owned(),
                offset: int_arg(file.get("offset")),
                limit: int_arg(file.get("limit")).and_then(|l| u64::try_from(l).ok()),
            });
        }
    }
    out
}

pub(crate) fn read_mode(args: &serde_json::Value) -> String {
    match args.get("mode").and_then(|m| m.as_str()) {
        Some("indentation") => "indentation".to_owned(),
        _ => "slice".to_owned(),
    }
}

/// Canonical absolute path for a model-supplied path.
pub(crate) fn canonical_path(cwd: &Path, path: &str) -> PathBuf {
    let joined = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        cwd.join(path)
    };
    dunce::canonicalize(&joined).unwrap_or(joined)
}

/// The note that replaces content on a repeat read.
pub(crate) fn unchanged_note(display_path: &str, lines: usize, prompt_index: usize) -> String {
    format!(
        "{display_path} unchanged since your earlier read ({lines} lines, at turn {}); content omitted — that result is still in your context",
        prompt_index + 1
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuigo_sampling_types::{ContentPart, ConversationItem, Message, Role};

    fn key(path: &str) -> ReadKey {
        ReadKey {
            path: PathBuf::from(path),
            offset: None,
            limit: None,
            mode: "slice".into(),
        }
    }

    fn entry(call: &str, chars: usize) -> ReadEntry {
        ReadEntry {
            hash: hash_bytes(b"hello"),
            prompt_index: 2,
            tool_call_id: call.into(),
            lines: 1,
            content_chars: chars,
        }
    }

    fn user() -> ConversationItem {
        ConversationItem::User(Message::new(Role::User, vec![ContentPart::text("u")]))
    }

    fn tool_result(call: &str) -> ConversationItem {
        ConversationItem::tool_result(call.to_string(), "1→hello".to_string())
    }

    #[test]
    fn repeat_read_hits_when_unchanged_and_intact() {
        let mut cache = ReadDedupeCache::new(PruneMirror::disabled());
        cache.record(key("/w/a.rs"), entry("call_1", 10));
        let hit = cache.get(&key("/w/a.rs")).expect("cached");
        assert_eq!(hit.hash, hash_bytes(b"hello"), "hash compares the current bytes");
        assert_ne!(hit.hash, hash_bytes(b"hello world"), "changed bytes must not hit");
        let conversation = vec![user(), tool_result("call_1"), user()];
        assert!(cache.result_intact(hit, &conversation));
        assert_eq!(
            unchanged_note("a.rs", 1, 2),
            "a.rs unchanged since your earlier read (1 lines, at turn 3); content omitted — that result is still in your context"
        );
    }

    #[test]
    fn edit_and_compaction_clear_the_cache() {
        let mut cache = ReadDedupeCache::new(PruneMirror::disabled());
        cache.record(key("/w/a.rs"), entry("call_1", 10));
        assert!(call_invalidates("search_replace", false));
        assert!(call_invalidates("run_terminal_command", false));
        assert!(call_invalidates("spawn_subagent", true), "a child may edit files");
        assert!(call_invalidates("use_tool", true));
        assert!(call_invalidates("linear__save_issue", true));
        assert!(!call_invalidates("read_file", true));
        assert!(!call_invalidates("grep", true));
        cache.invalidate_all("edit");
        assert!(cache.get(&key("/w/a.rs")).is_none(), "read after an edit returns content");

        cache.record(key("/w/a.rs"), entry("call_2", 10));
        cache.observe_compaction_marker(None);
        assert_eq!(cache.len(), 1, "no compaction yet");
        cache.observe_compaction_marker(Some(4));
        assert!(cache.get(&key("/w/a.rs")).is_none(), "read after compaction returns content");
        cache.record(key("/w/a.rs"), entry("call_3", 10));
        cache.observe_compaction_marker(Some(4));
        assert_eq!(cache.len(), 1, "same marker keeps entries");
        cache.observe_compaction_marker(Some(9));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn pruned_or_missing_results_are_not_intact() {
        let prune = PruneMirror {
            enabled: true,
            keep_last_n_turns: 3,
            soft_trim_threshold: 4000,
            hard_clear_age_turns: 10,
        };
        let cache = ReadDedupeCache::new(prune);
        let recent = vec![user(), tool_result("call_1"), user()];
        assert!(cache.result_intact(&entry("call_1", 10), &recent));
        assert!(!cache.result_intact(&entry("call_9", 10), &recent), "missing (compacted) result");
        // Four user turns after the result: older than keep_last_n_turns.
        let mut aged = vec![user(), tool_result("call_1")];
        aged.extend((0..4).map(|_| user()));
        assert!(cache.result_intact(&entry("call_1", 10), &aged), "small results are never soft-trimmed");
        assert!(!cache.result_intact(&entry("call_1", 5000), &aged), "large result would be soft-trimmed");
        let mut ancient = vec![user(), tool_result("call_1")];
        ancient.extend((0..11).map(|_| user()));
        assert!(!cache.result_intact(&entry("call_1", 10), &ancient), "hard-cleared");
        let off = ReadDedupeCache::new(PruneMirror::disabled());
        assert!(off.result_intact(&entry("call_1", 5000), &ancient), "pruning disabled: intact");
    }

    #[test]
    fn child_session_starts_with_its_own_empty_cache() {
        let mut parent = ReadDedupeCache::new(PruneMirror::disabled());
        parent.record(key("/w/a.rs"), entry("call_1", 10));
        let child = ReadDedupeCache::new(PruneMirror::disabled());
        assert!(child.get(&key("/w/a.rs")).is_none());
        assert_eq!(parent.len(), 1);
    }

    #[test]
    fn parses_single_and_multi_path_reads() {
        let single = parse_read_entries(&serde_json::json!({"target_file": "a.rs", "offset": 5, "limit": "20"}));
        assert_eq!(single, vec![ReadRequestEntry { path: "a.rs".into(), offset: Some(5), limit: Some(20) }]);
        let codex = parse_read_entries(&serde_json::json!({"file_path": "/w/b.rs"}));
        assert_eq!(codex[0].path, "/w/b.rs");
        let multi = parse_read_entries(&serde_json::json!({
            "target_file": "a.rs",
            "files": [{"path": "b.rs", "offset": 1}, {"path": "  "}, {"path": "c.rs", "limit": 3}]
        }));
        assert_eq!(multi.len(), 3);
        assert_eq!(multi[1].path, "b.rs");
        assert_eq!(multi[2].limit, Some(3));
        assert!(parse_read_entries(&serde_json::json!({"target_file": ""})).is_empty());
        assert_eq!(read_mode(&serde_json::json!({"mode": "indentation"})), "indentation");
        assert_eq!(read_mode(&serde_json::json!({})), "slice");
    }
}
