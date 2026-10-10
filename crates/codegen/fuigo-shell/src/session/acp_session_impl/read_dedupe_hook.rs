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

/// The entries of a `read_file` call, each with the file the reader opens for it, or `None` when the call may not
/// be deduped (P174). The raw parser also accepts keys the tool ignores (`target_file` or `path` on the codex form),
/// so dedupe runs only when every parsed entry is a file the permission check judged: the rewrite then reads only
/// judged files, and dedupe hashes the file the reader opens (not its own `cwd.join`, which can name another file).
fn judged_read_entries(prepared: &PreparedToolCall) -> Option<Vec<(ReadRequestEntry, PathBuf)>> {
    let judged = prepared.judged_read_paths.as_ref()?;
    parse_read_entries(&prepared.parsed_args)
        .into_iter()
        .map(|entry| {
            let opened = judged
                .iter()
                .find(|(spelled, _)| *spelled == entry.path)
                .map(|(_, opened)| opened.clone())?;
            Some((entry, opened))
        })
        .collect()
}

impl SessionActor {
    /// Every file a `read_file` call opens (P174), as spelled and as the reader resolves it: the Fuigo reader's own
    /// resolution, or the codex reader's literal path.
    /// `None` (no dedupe for the call) when a file does not exist or the files cannot be resolved within a bound.
    pub(super) async fn judged_read_files(
        &self,
        tool_input: &ToolInput,
    ) -> Option<Vec<(String, PathBuf)>> {
        use fuigo_workspace::permission::ReadResolution;
        let Some(targets) = fuigo_workspace::permission::read_targets_for(tool_input) else {
            return Some(Vec::new());
        };
        let cwd = self.tool_context.cwd.as_path().to_path_buf();
        let display_cwd = self
            .display_cwd
            .get()
            .map(|cwd| PathBuf::from(cwd.as_str()));
        let resolve_all = async move {
            let mut out = Vec::with_capacity(targets.paths.len());
            for path in targets.paths {
                let opened = match targets.resolution {
                    ReadResolution::ModelPath => {
                        // Not `resolve_read_target`: its Unicode-confusable fallback lists the file's whole
                        // directory, and a file that does not exist has nothing to dedupe (the call is then not
                        // deduped). The permission check still judges that fallback file.
                        fuigo_tools::implementations::fuigo_build::read_file::resolve_existing_read_target(
                            &cwd,
                            display_cwd.as_deref(),
                            &path,
                        )
                        .await?
                    }
                    ReadResolution::Literal => {
                        let (cwd, spelled) = (cwd.clone(), path.clone());
                        tokio::task::spawn_blocking(move || canonical_path(&cwd, &spelled))
                            .await
                            .ok()?
                    }
                };
                out.push((path, opened));
            }
            Some(out)
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), resolve_all)
            .await
            .ok()
            .flatten()
    }
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
            let Some(entries) = judged_read_entries(prepared) else {
                plans.push(Arc::new(None));
                continue;
            };
            let mode = read_mode(&prepared.parsed_args);
            let mut plan = DedupePlan::default();
            for (entry, path) in entries {
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
        let Some(entries) = judged_read_entries(prepared) else {
            return;
        };
        let mode = read_mode(&prepared.parsed_args);
        let prompt_index = self.chat_state_handle.get_prompt_index().await;
        let content_chars = result.prompt_text.chars().count();
        for (entry, path) in entries {
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

#[cfg(test)]
mod p174_tests {
    use super::*;

    fn prepared(args: serde_json::Value, judged: Option<Vec<&str>>) -> PreparedToolCall {
        PreparedToolCall {
            call_id: "call_1".to_string(),
            tool_call_id: acp::ToolCallId::new("call_1"),
            tool_name: "read_file".to_string(),
            raw_arguments: args.to_string(),
            parsed_args: args,
            model_id: "test-model".to_string(),
            concatenated_json_count: 0,
            dispatch_target_name: None,
            is_read_only: true,
            rewriting_hook: None,
            additional_context: Vec::new(),
            judged_read_paths: judged.map(|paths| {
                paths
                    .into_iter()
                    .map(|p| (p.to_owned(), PathBuf::from(format!("/opened{p}"))))
                    .collect()
            }),
        }
    }

    /// Astra r1 HIGH: the codex form ignores `target_file`, so only `files` was judged; dedupe must not turn the
    /// ignored key into a `files` entry (which the rewritten call would read unjudged).
    #[test]
    fn dedupe_never_adds_a_path_the_permission_check_did_not_judge() {
        let args = serde_json::json!({ "target_file": "/w/secrets/key", "files": [{ "path": "/w/ok.txt" }] });
        assert!(judged_read_entries(&prepared(args.clone(), Some(vec!["/w/ok.txt"]))).is_none());
        assert!(judged_read_entries(&prepared(args.clone(), None)).is_none());
        let entries = judged_read_entries(&prepared(args, Some(vec!["/w/secrets/key", "/w/ok.txt"])))
            .expect("every entry was judged");
        assert_eq!(
            entries.iter().map(|(e, _)| e.path.as_str()).collect::<Vec<_>>(),
            vec!["/w/secrets/key", "/w/ok.txt"]
        );
        // Astra r2 HIGH: dedupe hashes the file the reader opens, never its own `cwd.join` of the spelling.
        assert_eq!(
            entries.iter().map(|(_, opened)| opened.clone()).collect::<Vec<_>>(),
            vec![PathBuf::from("/opened/w/secrets/key"), PathBuf::from("/opened/w/ok.txt")]
        );
    }

    async fn judged(input: serde_json::Value) -> Option<Vec<(String, PathBuf)>> {
        let (gateway_tx, _gateway_rx) = tokio::sync::mpsc::unbounded_channel();
        let (persistence_tx, _persistence_rx) = tokio::sync::mpsc::unbounded_channel();
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async move {
                let actor = crate::session::acp_session::support::create_test_actor(
                    0, 256_000, 85, gateway_tx, persistence_tx,
                )
                .await;
                let input =
                    ToolInput::ReadFile(serde_json::from_value(input).expect("read_file input"));
                actor.judged_read_files(&input).await
            })
            .await
    }

    /// The prepare path must not scan a directory (P174 perf): a path that does not exist is not deduped, so the
    /// Unicode-confusable sibling scan (`try_resolve_unicode_filename`, which lists the whole parent directory, 1.3 s for
    /// a 500k-entry `/tmp`) never runs on the actor. Deterministic: a confusable sibling exists, and the scan would
    /// find it.
    #[tokio::test(flavor = "current_thread")]
    async fn judged_read_files_does_not_scan_the_directory_for_a_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("shot\u{202F}1.png"), b"x").expect("write sibling");
        let asked = dir.path().join("shot 1.png").to_string_lossy().into_owned();
        let got = judged(serde_json::json!({ "target_file": asked })).await;
        assert!(got.is_none(), "a missing file is not deduped and its directory is not scanned; got {got:?}");
    }

    /// The fix keeps the judged file the one the reader opens: symlinks are followed.
    /// Unix only: it creates the link with `std::os::unix::fs::symlink`.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn judged_read_files_follows_symlinks_for_an_existing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real.txt");
        std::fs::write(&real, b"x").expect("write");
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let asked = link.to_string_lossy().into_owned();
        let got = judged(serde_json::json!({ "target_file": asked.clone() })).await.expect("resolved");
        assert_eq!(got, vec![(asked, dunce::canonicalize(&real).expect("canonical"))]);
    }
}
