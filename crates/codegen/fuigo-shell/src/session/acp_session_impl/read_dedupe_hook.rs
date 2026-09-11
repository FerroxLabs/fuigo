//! `SessionActor` side of the read-dedupe cache: plans a batch's `read_file` calls against the
//! cache before dispatch and records successful reads after it.
use super::*;
use std::path::PathBuf;
use std::sync::Arc;

use fuigo_sampling_types::ConversationItem;

use crate::session::read_dedupe::{
    ReadEntry, ReadKey, ReadRequestEntry, call_invalidates, canonical_path, hash_bytes,
    parse_read_entries, read_mode, unchanged_note,
};
use fuigo_tools::types::output::{FileContent, ReadFileOutput, ToolOutput, ToolRunResult};

/// Tool names that read files through the dedupe-aware path.
fn is_read_file_tool(name: &str) -> bool {
    matches!(name, "read_file" | "Read" | "read")
}

/// What to do with one `read_file` call: which requested entries are served from the cache.
#[derive(Debug, Default)]
pub(crate) struct DedupePlan {
    /// Notes for the entries served from the cache, in request order.
    pub notes: Vec<String>,
    /// Entries that still need reading (empty when every entry was cached).
    pub remaining: Vec<ReadRequestEntry>,
    /// Canonical paths of the entries served from the cache (never re-recorded this call).
    pub deduped_paths: Vec<PathBuf>,
    /// Display fields for a fully deduped call.
    pub first_path: PathBuf,
    pub first_lines: usize,
}

impl DedupePlan {
    pub(crate) fn serves_everything(&self) -> bool {
        !self.notes.is_empty() && self.remaining.is_empty()
    }

    /// Rewrite the call so only the remaining entries are read.
    pub(crate) fn rewrite_args(&self, args: &mut serde_json::Value) {
        let Some(obj) = args.as_object_mut() else {
            return;
        };
        obj.remove("target_file");
        obj.remove("file_path");
        obj.remove("offset");
        obj.remove("limit");
        let files: Vec<serde_json::Value> = self
            .remaining
            .iter()
            .map(|e| {
                let mut f = serde_json::Map::new();
                f.insert("path".into(), serde_json::Value::String(e.path.clone()));
                if let Some(o) = e.offset {
                    f.insert("offset".into(), serde_json::json!(o));
                }
                if let Some(l) = e.limit {
                    f.insert("limit".into(), serde_json::json!(l));
                }
                serde_json::Value::Object(f)
            })
            .collect();
        obj.insert("files".into(), serde_json::Value::Array(files));
    }

    pub(crate) fn synthesized_result(&self) -> ToolRunResult {
        let note = self.notes.join("\n");
        ToolRunResult {
            output: ToolOutput::ReadFile(ReadFileOutput::FileContent(FileContent {
                content: note.clone(),
                content_concise: None,
                absolute_path: self.first_path.clone(),
                offset: None,
                limit: None,
                raw_output: String::new(),
                total_lines: self.first_lines,
                extracted_images: Vec::new(),
            })),
            prompt_text: note,
            effective_tool_name: None,
        }
    }

    /// Append the cached entries' notes to a partial result.
    pub(crate) fn append_notes(&self, result: &mut ToolRunResult) {
        if self.notes.is_empty() {
            return;
        }
        let suffix = format!("\n\n{}", self.notes.join("\n"));
        result.prompt_text.push_str(&suffix);
        if let ToolOutput::ReadFile(ReadFileOutput::FileContent(fc)) = &mut result.output {
            fc.content.push_str(&suffix);
            if let Some(concise) = fc.content_concise.as_mut() {
                concise.push_str(&suffix);
            }
        }
    }
}

impl SessionActor {
    /// Plan every call of a batch: clears the cache when the batch mutates anything (before the
    /// batch runs; `finish_read_dedupe_batch` clears again after), syncs the compaction marker,
    /// and resolves each `read_file` call against the cache.
    pub(super) async fn plan_read_dedupe_batch(
        &self,
        approved: &[PreparedToolCall],
    ) -> (Vec<Arc<Option<DedupePlan>>>, bool) {
        let marker = self.chat_state_handle.get_last_compaction_prompt_index().await;
        self.read_dedupe.borrow_mut().observe_compaction_marker(marker);
        let mutating = approved
            .iter()
            .any(|p| call_invalidates(&p.tool_name, p.is_read_only));
        if mutating {
            self.read_dedupe.borrow_mut().invalidate_all("mutating tool call in batch");
            return (approved.iter().map(|_| Arc::new(None)).collect(), true);
        }
        let mut plans = Vec::with_capacity(approved.len());
        let mut conversation: Option<Vec<ConversationItem>> = None;
        for prepared in approved {
            if !is_read_file_tool(&prepared.tool_name) || self.read_dedupe.borrow().is_empty() {
                plans.push(Arc::new(None));
                continue;
            }
            let entries = parse_read_entries(&prepared.parsed_args);
            let mode = read_mode(&prepared.parsed_args);
            let mut plan = DedupePlan::default();
            for entry in entries {
                let path = canonical_path(self.tool_context.cwd.as_path(), &entry.path);
                let key = ReadKey {
                    path: path.clone(),
                    offset: entry.offset,
                    limit: entry.limit,
                    mode: mode.clone(),
                };
                let cached = self.read_dedupe.borrow().get(&key).cloned();
                let Some(cached) = cached else {
                    plan.remaining.push(entry);
                    continue;
                };
                let Ok(bytes) = tokio::fs::read(&path).await else {
                    plan.remaining.push(entry);
                    continue;
                };
                if hash_bytes(&bytes) != cached.hash {
                    self.read_dedupe.borrow_mut().invalidate_all("file changed on disk");
                    plan.remaining.push(entry);
                    continue;
                }
                if conversation.is_none() {
                    conversation = Some(self.chat_state_handle.get_conversation().await);
                }
                let intact = self
                    .read_dedupe
                    .borrow()
                    .result_intact(&cached, conversation.as_deref().unwrap_or_default());
                if !intact {
                    plan.remaining.push(entry);
                    continue;
                }
                if plan.notes.is_empty() {
                    plan.first_path = path.clone();
                    plan.first_lines = cached.lines;
                }
                plan.notes.push(unchanged_note(&entry.path, cached.lines, cached.prompt_index));
                plan.deduped_paths.push(path);
            }
            if plan.notes.is_empty() {
                plans.push(Arc::new(None));
            } else {
                tracing::info!(
                    tool = %prepared.tool_name,
                    deduped = plan.notes.len(),
                    remaining = plan.remaining.len(),
                    "read-dedupe: serving unchanged files from the earlier result"
                );
                plans.push(Arc::new(Some(plan)));
            }
        }
        (plans, false)
    }

    /// A batch that mutated anything clears the cache again once it has run.
    pub(super) fn finish_read_dedupe_batch(&self, mutating: bool) {
        if mutating {
            self.read_dedupe.borrow_mut().invalidate_all("mutating batch finished");
        }
    }

    /// Record every file a successful `read_file` returned content for, keyed by the requested
    /// range, with the hash of the bytes now on disk and this result's tool-call id.
    pub(super) async fn record_read_dedupe(
        &self,
        prepared: &PreparedToolCall,
        result: &ToolRunResult,
        plan: Option<&DedupePlan>,
    ) {
        if !is_read_file_tool(&prepared.tool_name) {
            return;
        }
        let ToolOutput::ReadFile(ReadFileOutput::FileContent(fc)) = &result.output else {
            return;
        };
        if fc.content.is_empty() || result.output.is_error() {
            return;
        }
        let entries = parse_read_entries(&prepared.parsed_args);
        let mode = read_mode(&prepared.parsed_args);
        let prompt_index = self.chat_state_handle.get_prompt_index().await;
        let content_chars = result.prompt_text.chars().count();
        for entry in entries {
            let path = canonical_path(self.tool_context.cwd.as_path(), &entry.path);
            if plan.is_some_and(|p| p.deduped_paths.contains(&path)) {
                continue;
            }
            let Ok(bytes) = tokio::fs::read(&path).await else {
                continue;
            };
            let lines = if bytes.is_empty() {
                0
            } else {
                bytes.iter().filter(|b| **b == b'\n').count()
                    + usize::from(bytes.last() != Some(&b'\n'))
            };
            let key = ReadKey {
                path,
                offset: entry.offset,
                limit: entry.limit,
                mode: mode.clone(),
            };
            self.read_dedupe.borrow_mut().record(
                key,
                ReadEntry {
                    hash: hash_bytes(&bytes),
                    prompt_index,
                    tool_call_id: prepared.call_id.clone(),
                    lines,
                    content_chars,
                },
            );
        }
    }
}
