use async_trait::async_trait;
use std::io::{self, BufRead, BufReader, Seek, Write};
use std::path::{Path, PathBuf};

use crate::extensions::notification::SessionNotification;
use crate::sampling::ConversationItem;
use crate::session::info::Info;
use crate::session::persistence::Summary;
use crate::session::signals::SessionSignals;
use crate::session::wire_tags::{REWIND_MARKER, USER_MESSAGE_CHUNK};
use crate::tools::todo::TodoState;
use agent_client_protocol as acp;
use fuigo_sampling_types::ReasoningEffort;
use fuigo_workspace::session::file_state::RewindPoint;

pub mod jsonl;
pub(crate) mod owner_only;
pub(crate) mod relocation;
mod replay;
pub(crate) mod snapshot_lock;
#[cfg(test)]
mod replay_tests;
pub mod search;
mod search_content;
pub(crate) mod summary_write;

/// The session search index moved to its own crate; re-exported here so `session::storage::search_fts::…` keeps resolving for its consumers.
pub use fuigo_session_search::fts as search_fts;

/// On-disk file names, relative to a session directory.
/// Single source of truth for the storage adapter and the session/state and session/import extensions.
pub(crate) const SUMMARY_FILE: &str = "summary.json";
pub(crate) const PLAN_FILE: &str = "plan.json";
pub(crate) const PLAN_MODE_FILE: &str = "plan_mode.json";
pub(crate) const SIGNALS_FILE: &str = "signals.json";
pub(crate) const USAGE_FILE: &str = "usage.json";
pub(crate) const GOAL_STATE_FILE: &str = "goal/state.json";
pub(crate) const ANNOUNCEMENT_STATE_FILE: &str = "announcement_state.json";
pub(crate) const CHAT_HISTORY_FILE: &str = "chat_history.jsonl";
pub(crate) const UPDATES_FILE: &str = "updates.jsonl";

/// Write `bytes` to `path` by writing a uniquely named sibling temp file and renaming it over the target.
/// A crash or a concurrent writer never leaves a torn file; the temp is removed on failure.
pub(crate) fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_bytes_atomic_reporting(path, bytes).map_err(AtomicWriteError::into_io)
}

/// How a failed [`write_bytes_atomic`] left the target.
#[derive(Debug)]
pub(crate) enum AtomicWriteError {
    /// The target still holds what it held before (or does not exist, as before).
    NotReplaced(io::Error),
    /// The new bytes were renamed over the target and a later step (the parent directory sync) failed.
    Replaced(io::Error),
}

impl AtomicWriteError {
    pub(crate) fn into_io(self) -> io::Error {
        match self {
            Self::NotReplaced(error) | Self::Replaced(error) => error,
        }
    }
}

/// [`write_bytes_atomic`] that says, when it fails, whether the rename over the target happened.
pub(crate) fn write_bytes_atomic_reporting(path: &Path, bytes: &[u8]) -> Result<(), AtomicWriteError> {
    #[cfg(test)]
    jsonl::load_repair::seams::wait_if_held(path);
    let result = write_bytes_atomic_outcome_with(path, bytes, sync_file_durable, || {
        sync_parent_dir_durable(path)
    });
    if matches!(&result, Ok(()) | Err(AtomicWriteError::Replaced(_)))
        && path.file_name().is_some_and(|name| name == CHAT_HISTORY_FILE)
        && let Some(dir) = path.parent()
    {
        // The whole chat history was rewritten: a compaction rewrite that had not landed is superseded (P111).
        jsonl::compaction_witness::clear_after_chat_rewrite(dir, Some(bytes));
    }
    result
}

fn write_bytes_atomic_with(
    path: &Path,
    bytes: &[u8],
    sync_file: impl Fn(&std::fs::File) -> io::Result<()>,
    sync_parent: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    write_bytes_atomic_outcome_with(path, bytes, sync_file, sync_parent).map_err(AtomicWriteError::into_io)
}

fn write_bytes_atomic_outcome_with(
    path: &Path,
    bytes: &[u8],
    sync_file: impl Fn(&std::fs::File) -> io::Result<()>,
    sync_parent: impl Fn() -> io::Result<()>,
) -> Result<(), AtomicWriteError> {
    let tmp = temp_sibling(path);
    let write_synced = || -> io::Result<()> {
        let mut file = owner_only::create(&tmp)?;
        file.write_all(bytes)?;
        // NTFS/ext4 journal a rename as old-file-or-new-file only when the new file's data is already flushed
        // Without this fsync a power loss can leave the committed rename in place with zero-length content
        sync_file(&file)
    };
    // Old-or-new only covers replacing a file, whose direntry is already durable
    // A first-time create (a session's first summary.json) has no old file
    // Its new entry can vanish on power loss until the parent directory is synced
    // A retry after a rename whose parent sync failed sees the file present and cannot tell create from replace
    // So every successful rename pays the parent sync
    match write_synced().and_then(|()| std::fs::rename(&tmp, path)) {
        Ok(()) => sync_parent().map_err(AtomicWriteError::Replaced),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(AtomicWriteError::NotReplaced(e))
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn sync_file_durable(file: &std::fs::File) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    file.sync_all()?;
    fullfsync_raw(file.as_raw_fd())
}

#[cfg(target_os = "macos")]
pub(crate) fn fullfsync_raw(fd: std::os::fd::RawFd) -> io::Result<()> {
    // macOS fsync may stop at volatile drive caches; F_FULLFSYNC requests stable media.
    if unsafe { libc::fcntl(fd, libc::F_FULLFSYNC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(any(all(unix, not(target_os = "macos")), windows))]
pub(crate) fn sync_file_durable(file: &std::fs::File) -> io::Result<()> {
    file.sync_all()
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn sync_file_durable(_file: &std::fs::File) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "durable file sync is unsupported on this platform",
    ))
}

/// Fsync `dir` so entries just created or renamed into it survive power loss.
#[cfg(target_os = "macos")]
pub(crate) fn sync_dir_durable(dir: &Path) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let file = std::fs::File::open(dir)?;
    file.sync_all()?;
    // Match file durability: macOS fsync may stop at volatile drive caches.
    fullfsync_raw(file.as_raw_fd())
}

#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) fn sync_dir_durable(dir: &Path) -> io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(windows)]
pub(crate) fn sync_dir_durable(_dir: &Path) -> io::Result<()> {
    // Windows has no supported directory-handle fsync
    // NTFS journals directory metadata, which can roll a very recent create back to absent but never to garbage
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn sync_dir_durable(_dir: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "durable directory sync is unsupported on this platform",
    ))
}

/// Fsync `<cwd_dir>/.cwd` if present.
/// Hash-encoded path recovery must not be frozen to a torn marker when a later parent-dir sync makes its direntry durable.
/// Open write-capable: Windows `FlushFileBuffers` on a read-only handle cannot persist the bytes.
pub(crate) fn sync_cwd_marker_if_present(cwd_dir: &Path) -> io::Result<()> {
    sync_cwd_marker_if_present_with(cwd_dir, sync_file_durable)
}

pub(crate) fn sync_cwd_marker_if_present_with(
    cwd_dir: &Path,
    sync_file: impl Fn(&std::fs::File) -> io::Result<()>,
) -> io::Result<()> {
    let cwd_file = cwd_dir.join(".cwd");
    match std::fs::OpenOptions::new().write(true).open(&cwd_file) {
        Ok(file) => sync_file(&file),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

pub(crate) fn sync_parent_dir_durable(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    sync_dir_durable(parent)
}

/// Run `create` (a `create_dir_all`-style creation of `dir`), then [`sync_dir_durable`] every directory that gained a new entry.
/// The created chain itself then survives power loss; fsyncing a file only makes its own direntry durable, not the directories above it.
/// The ancestors are snapshotted before `create` because afterwards the whole chain exists; an already-existing occupied chain pays no sync.
pub(crate) fn create_dir_all_durable(
    dir: &Path,
    create: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    create_dir_all_durable_with(dir, create, sync_dir_durable)
}

pub(crate) fn create_dir_all_durable_with(
    dir: &Path,
    create: impl FnOnce(&Path) -> io::Result<()>,
    sync_dir: impl Fn(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let mut gaining_an_entry = Vec::new();
    let mut cursor = dir;
    while !cursor.exists() {
        let Some(parent) = cursor.parent() else { break };
        gaining_an_entry.push(parent);
        cursor = parent;
    }
    create(dir)?;
    // A retry after a create whose parent sync failed sees the whole chain present and would otherwise sync nothing
    // Re-sync a bounded ancestor list so the new direntry is durable, but only when `dir` is still empty
    // `init_session` calls this on every open
    // A populated resume must not fsync ancestors (permissions, a network home, or macOS F_FULLFSYNC can fail a normal open)
    // Never the filesystem root (fsync("/") can fail or stall)
    let retry_ancestors;
    let to_sync: &[&Path] = if !gaining_an_entry.is_empty() {
        &gaining_an_entry
    } else if std::fs::read_dir(dir)
        .map(|mut entries| entries.next().is_none())
        .unwrap_or(false)
    {
        retry_ancestors = dir
            .ancestors()
            .skip(1)
            .take(4)
            .filter(|parent| !is_fs_root(parent))
            .collect::<Vec<_>>();
        &retry_ancestors
    } else {
        return Ok(());
    };
    // Fresh creates under a new top-level directory include `/` in `gaining_an_entry`; skip it here so both paths honor the root rule
    for parent in to_sync {
        if is_fs_root(parent) {
            continue;
        }
        sync_dir(parent)?;
    }
    Ok(())
}

fn is_fs_root(path: &Path) -> bool {
    path.parent()
        .is_none_or(|parent| parent.as_os_str().is_empty())
}

pub(crate) async fn write_bytes_atomic_async(path: &Path, bytes: Vec<u8>) -> io::Result<()> {
    write_bytes_atomic_reporting_async(path, bytes)
        .await
        .map_err(AtomicWriteError::into_io)
}

pub(crate) async fn write_bytes_atomic_reporting_async(
    path: &Path,
    bytes: Vec<u8>,
) -> Result<(), AtomicWriteError> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || write_bytes_atomic_reporting(&path, &bytes))
        .await
        .map_err(|error| AtomicWriteError::NotReplaced(io::Error::other(error)))?
}

fn to_jsonl_bytes<T: serde::Serialize>(items: &[T]) -> io::Result<Vec<u8>> {
    let mut content = Vec::new();
    for item in items {
        serde_json::to_writer(&mut content, item)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        content.push(b'\n');
    }
    Ok(content)
}

pub(crate) fn write_jsonl_atomic<T: serde::Serialize>(path: &Path, items: &[T]) -> io::Result<()> {
    write_bytes_atomic(path, &to_jsonl_bytes(items)?)
}

pub(crate) async fn write_jsonl_atomic_async<T: serde::Serialize>(
    path: &Path,
    items: &[T],
) -> io::Result<()> {
    write_bytes_atomic_async(path, to_jsonl_bytes(items)?).await
}

/// A unique sibling temp path, e.g. `summary.json` becomes `summary.json.<uuid>.tmp`.
fn temp_sibling(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{}.tmp", uuid::Uuid::now_v7()));
    PathBuf::from(name)
}

/// Rebuild the derived `chat_history.jsonl` cache from `updates.jsonl`, the durable source of truth.
/// A session then restores from its update stream alone.
pub(crate) mod chat_rebuild {
    use std::collections::{HashMap, HashSet};
    use std::io;
    use std::path::Path;

    use agent_client_protocol as acp;

    use super::{CHAT_HISTORY_FILE, SessionUpdate, UPDATES_FILE, UpdatesIterator};
    use crate::sampling::{
        AssistantItem, ContentPart, ConversationItem, SyntheticReason, ToolCall, UserItem,
    };

    /// Rebuild `chat_history.jsonl` from `updates.jsonl` alone. Builds a temp file and renames it over the target.
    /// A failed rebuild leaves the existing cache intact rather than a truncated partial that load would trust.
    pub(crate) fn rebuild_chat_history(dir: &Path) -> io::Result<usize> {
        use std::io::{Seek, Write};

        let updates_path = dir.join(UPDATES_FILE);
        let Some(iter) = UpdatesIterator::open(&updates_path)? else {
            return Ok(0);
        };

        let chat_path = dir.join(CHAT_HISTORY_FILE);
        let tmp_path = dir.join(format!("{CHAT_HISTORY_FILE}.{}.tmp", uuid::Uuid::now_v7()));
        let file = crate::session::storage::owner_only::create(&tmp_path)?;
        let mut writer = std::io::BufWriter::new(file);
        let mut reducer = ChatReducer::new();

        for result in iter {
            let update = match result {
                Ok(u) => u,
                Err(_) => continue,
            };

            for item in reducer.process(&update) {
                if let Ok(line) = serde_json::to_string(&item) {
                    let _ = writer.write_all(line.as_bytes());
                    let _ = writer.write_all(b"\n");
                }
            }

            // CompactionCheckpoint: everything before it is replaced by the checkpoint's compacted projection (the
            // history the model continued from), so truncate and start again from that projection.
            if reducer.should_truncate() {
                reducer.clear_truncate_flag();
                let _ = writer.seek(std::io::SeekFrom::Start(0));
                let _ = writer.get_mut().set_len(0);
                reducer.projection_lines = 0;
                if let Some(file) = reducer.checkpoint_file.take() {
                    for item in compacted_projection(dir, &file) {
                        if let Ok(line) = serde_json::to_string(&item) {
                            let _ = writer.write_all(line.as_bytes());
                            let _ = writer.write_all(b"\n");
                            reducer.item_count += 1;
                            reducer.projection_lines += 1;
                        }
                    }
                }
            }
        }

        for item in reducer.flush() {
            if let Ok(line) = serde_json::to_string(&item) {
                let _ = writer.write_all(line.as_bytes());
                let _ = writer.write_all(b"\n");
            }
        }

        // This reducer keeps tool calls but does not apply rewinds. When a rewind follows the latest compaction, the
        // projection written above may be one the rewind abandoned. If that compaction is still active, use the
        // rewind-aware replay (text only; what 1.0.10-1.0.19 loaded here, under the same rule). Otherwise drop the
        // projection and keep the reducer's tail, which is what this rebuild produced before P88.
        let mut drop_projection = 0;
        if reducer.rewound_after_checkpoint {
            match crate::session::helpers::replay::replay_if_latest_compaction_active(&updates_path, dir) {
                Ok(Some(conversation)) => {
                    let _ = writer.seek(std::io::SeekFrom::Start(0));
                    let _ = writer.get_mut().set_len(0);
                    reducer.item_count = 0;
                    for item in &conversation {
                        if let Ok(line) = serde_json::to_string(item) {
                            let _ = writer.write_all(line.as_bytes());
                            let _ = writer.write_all(b"\n");
                            reducer.item_count += 1;
                        }
                    }
                }
                Ok(None) => drop_projection = reducer.projection_lines,
                Err(error) => {
                    tracing::warn!(dir = %dir.display(), %error,
                        "chat history rebuild: a rewind follows the latest compaction and its checkpoint is unreadable; \
                         rebuilding without the compaction summary");
                    drop_projection = reducer.projection_lines;
                }
            }
        }

        if let Err(e) = writer.flush() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }
        drop(writer);
        if drop_projection > 0 {
            let rebuilt = std::fs::read_to_string(&tmp_path).and_then(|text| {
                let kept: String = text.split_inclusive('\n').skip(drop_projection).collect();
                crate::session::storage::owner_only::write(&tmp_path, kept)
            });
            if let Err(e) = rebuilt {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(e);
            }
            reducer.item_count = reducer.item_count.saturating_sub(drop_projection);
        }
        if let Err(e) = std::fs::rename(&tmp_path, &chat_path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }
        // Rebuilt from the transcript, compactions included: no compaction rewrite is outstanding (P111).
        super::jsonl::compaction_witness::clear_after_chat_rewrite(dir, None);
        Ok(reducer.count())
    }

    /// The compacted projection a checkpoint marker activated. Without it the rebuild after that marker would hold only
    /// the post-compaction tail, losing the summary (P88). An unreadable file degrades to that tail, with a warning.
    fn compacted_projection(dir: &Path, checkpoint_file: &str) -> Vec<ConversationItem> {
        let path = crate::extensions::notification::contained_checkpoint_path(dir, checkpoint_file);
        let parsed = crate::extensions::notification::read_contained_checkpoint(dir, checkpoint_file)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                serde_json::from_slice::<crate::extensions::notification::CompactionCheckpointFile>(&bytes)
                    .map_err(|e| e.to_string())
            });
        match parsed {
            Ok(file) if file.schema_version == 1 => file.compacted_history,
            Ok(file) => {
                tracing::warn!(path = %path.display(), schema_version = file.schema_version,
                    "chat history rebuild: unsupported compaction checkpoint schema; rebuilt history lacks its summary");
                Vec::new()
            }
            Err(error) => {
                tracing::warn!(path = %path.display(), %error,
                    "chat history rebuild: compaction checkpoint unreadable; rebuilt history lacks its summary");
                Vec::new()
            }
        }
    }

    /// Turn boundaries: a switch from user to agent flushes the user item, and a switch from agent to user flushes the agent item.
    /// Tool completion flushes the agent item before emitting the result.
    struct ChatReducer {
        user_parts: Vec<ContentPart>,
        user_is_interjection: bool,
        agent_text: String,
        agent_tool_calls: Vec<ToolCall>,

        in_user_turn: bool,
        has_agent_content: bool,
        needs_truncate: bool,
        /// Checkpoint file of the compaction marker that set `needs_truncate`.
        checkpoint_file: Option<String>,
        checkpoint_seen: bool,
        /// A rewind marker follows the latest compaction marker.
        rewound_after_checkpoint: bool,
        /// Lines of the latest checkpoint's projection at the head of the output.
        projection_lines: usize,
        /// `_meta.promptIndex` of the user run being accumulated.
        user_prompt_index: Option<usize>,

        tool_args: HashMap<String, String>,
        emitted_tool_results: HashSet<String>,
        item_count: usize,
    }

    impl ChatReducer {
        fn new() -> Self {
            Self {
                user_parts: Vec::new(),
                user_is_interjection: false,
                agent_text: String::new(),
                agent_tool_calls: Vec::new(),
                in_user_turn: false,
                has_agent_content: false,
                needs_truncate: false,
                checkpoint_file: None,
                checkpoint_seen: false,
                rewound_after_checkpoint: false,
                projection_lines: 0,
                user_prompt_index: None,
                tool_args: HashMap::new(),
                emitted_tool_results: HashSet::new(),
                item_count: 0,
            }
        }

        fn process(&mut self, update: &SessionUpdate) -> Vec<ConversationItem> {
            match update {
                SessionUpdate::Acp(n) => self.handle_acp(&n.update),
                SessionUpdate::Fuigo(n) => self.handle_fuigo(&n.update),
            }
        }

        fn handle_acp(&mut self, update: &acp::SessionUpdate) -> Vec<ConversationItem> {
            match update {
                acp::SessionUpdate::UserMessageChunk(chunk) => self.on_user_chunk(chunk),
                acp::SessionUpdate::AgentMessageChunk(chunk) => self.on_agent_chunk(chunk),
                acp::SessionUpdate::ToolCall(tc) => self.on_tool_call(tc),
                acp::SessionUpdate::ToolCallUpdate(tc) => self.on_tool_call_update(tc),
                _ => Vec::new(), // AgentThoughtChunk, Retry, Plan not needed
            }
        }

        fn handle_fuigo(
            &mut self,
            update: &crate::extensions::notification::SessionUpdate,
        ) -> Vec<ConversationItem> {
            use crate::extensions::notification::SessionUpdate as FuigoUpdate;

            match update {
                FuigoUpdate::CompactionCheckpoint(info) => {
                    self.reset();
                    self.needs_truncate = true;
                    self.checkpoint_file = Some(info.checkpoint_file.clone());
                    self.checkpoint_seen = true;
                    self.rewound_after_checkpoint = false;
                    Vec::new()
                }
                FuigoUpdate::RewindMarker { .. } => {
                    // This reducer does not apply rewinds; see `rebuild_chat_history`.
                    self.rewound_after_checkpoint |= self.checkpoint_seen;
                    Vec::new()
                }
                _ => Vec::new(), // DiffReview, MemoryFlush, etc. not needed
            }
        }

        fn on_user_chunk(&mut self, chunk: &acp::ContentChunk) -> Vec<ConversationItem> {
            if super::is_host_turn_chunk(chunk) {
                return self.flush_host_turn_boundary();
            }
            let mut out = Vec::new();

            if !self.in_user_turn {
                out.extend(self.flush_agent());
                self.in_user_turn = true;
            }
            // Interjections never merge with an adjacent prompt run (tool-only first response, drain right after the
            // echo), and each interjection's text chunk opens its own item, as the live drain pushed them
            let interjection = super::is_interjection_chunk(chunk);
            let opens_interjection =
                interjection && matches!(chunk.content, acp::ContentBlock::Text(_));
            if interjection != self.user_is_interjection || opens_interjection {
                out.extend(self.flush_user());
            }
            self.user_is_interjection = interjection;
            // A new `_meta.promptIndex` starts a new prompt even with no response in between (a prompt cancelled before
            // any output), and the item keeps its index as the live history does (P88).
            let prompt_index = chunk
                .meta
                .as_ref()
                .and_then(|m| m.get("promptIndex"))
                .and_then(|v| v.as_u64())
                .map(|v| v as usize);
            if prompt_index.is_some() && self.user_prompt_index.is_some() && prompt_index != self.user_prompt_index {
                out.extend(self.flush_user());
            }
            if !interjection && self.user_prompt_index.is_none() {
                self.user_prompt_index = prompt_index;
            }

            match &chunk.content {
                acp::ContentBlock::Text(t) => {
                    self.user_parts.push(ContentPart::Text {
                        text: std::sync::Arc::<str>::from(t.text.clone()),
                    });
                }
                acp::ContentBlock::Image(img) => {
                    if let Some(uri) = &img.uri {
                        self.user_parts.push(ContentPart::Image {
                            url: std::sync::Arc::<str>::from(uri.clone()),
                        });
                    }
                }
                _ => {} // Audio, Resource, etc. not needed for chat replay
            }

            out
        }

        fn on_agent_chunk(&mut self, chunk: &acp::ContentChunk) -> Vec<ConversationItem> {
            if super::is_host_turn_chunk(chunk) {
                return self.flush_host_turn_boundary();
            }
            let mut out = Vec::new();

            if self.in_user_turn {
                out.extend(self.flush_user());
                self.in_user_turn = false;
            }

            if let acp::ContentBlock::Text(t) = &chunk.content {
                self.agent_text.push_str(&t.text);
                self.has_agent_content = true;
            }

            out
        }

        fn flush_host_turn_boundary(&mut self) -> Vec<ConversationItem> {
            let mut out = Vec::new();
            if self.in_user_turn {
                out.extend(self.flush_user());
                self.in_user_turn = false;
            }
            out.extend(self.flush_agent());
            out
        }

        fn on_tool_call(&mut self, tc: &acp::ToolCall) -> Vec<ConversationItem> {
            // A tool call ends the user's run even when the model said nothing first; otherwise the prompt stays
            // buffered and lands after the tool call and result it caused (P88).
            let mut out = Vec::new();
            if self.in_user_turn {
                out.extend(self.flush_user());
                self.in_user_turn = false;
            }
            let id = tc.tool_call_id.0.to_string();
            let args = tc
                .raw_input
                .as_ref()
                .map(|v| v.to_string())
                .unwrap_or_default();

            self.tool_args.insert(id.clone(), args.clone());
            self.agent_tool_calls.push(ToolCall {
                id: std::sync::Arc::<str>::from(id),
                name: tc.title.clone(),
                arguments: std::sync::Arc::<str>::from(args),
            });

            out
        }

        fn on_tool_call_update(&mut self, tc: &acp::ToolCallUpdate) -> Vec<ConversationItem> {
            let id = tc.tool_call_id.0.to_string();
            self.maybe_backfill_args(&id, &tc.fields);

            if Self::is_completed(&tc.fields) && self.emitted_tool_results.insert(id.clone()) {
                return self.emit_tool_result(&id, &tc.fields);
            }
            Vec::new()
        }

        fn maybe_backfill_args(&mut self, id: &str, fields: &acp::ToolCallUpdateFields) {
            let Some(raw) = &fields.raw_input else { return };
            let needs_backfill = self.tool_args.get(id).is_none_or(String::is_empty);
            if !needs_backfill {
                return;
            }

            let args = raw.to_string();
            self.tool_args.insert(id.to_string(), args.clone());

            if let Some(call) = self
                .agent_tool_calls
                .iter_mut()
                .find(|c| c.id.as_ref() == id)
            {
                call.arguments = std::sync::Arc::<str>::from(args);
            }
        }

        fn is_completed(fields: &acp::ToolCallUpdateFields) -> bool {
            matches!(
                fields.status,
                Some(acp::ToolCallStatus::Completed | acp::ToolCallStatus::Failed)
            )
        }

        fn emit_tool_result(
            &mut self,
            id: &str,
            fields: &acp::ToolCallUpdateFields,
        ) -> Vec<ConversationItem> {
            let mut out = Vec::new();
            out.extend(self.flush_agent());

            let content = extract_tool_result_text(fields);
            let item = ConversationItem::tool_result(id.to_string(), content);
            self.item_count += 1;
            out.push(item);
            out
        }

        fn flush_user(&mut self) -> Option<ConversationItem> {
            let interjection = std::mem::take(&mut self.user_is_interjection);
            let prompt_index = self.user_prompt_index.take();
            if self.user_parts.is_empty() {
                return None;
            }
            let content = std::mem::take(&mut self.user_parts);
            let mut item = ConversationItem::User(UserItem {
                content,
                synthetic_reason: interjection.then_some(SyntheticReason::Interjection),
                ..Default::default()
            });
            if let Some(prompt_index) = prompt_index {
                item.set_prompt_index(prompt_index);
            }
            self.item_count += 1;
            Some(item)
        }

        fn flush_agent(&mut self) -> Option<ConversationItem> {
            if !self.has_agent_content && self.agent_tool_calls.is_empty() {
                return None;
            }
            let item = ConversationItem::Assistant(AssistantItem {
                content: std::sync::Arc::<str>::from(std::mem::take(&mut self.agent_text)),
                tool_calls: std::mem::take(&mut self.agent_tool_calls),
                model_id: None,
                model_fingerprint: None,
                reasoning_effort: None,
                output_order: None,
            });
            self.has_agent_content = false;
            self.item_count += 1;
            Some(item)
        }

        fn flush(&mut self) -> Vec<ConversationItem> {
            let mut out = Vec::new();
            out.extend(self.flush_user());
            out.extend(self.flush_agent());
            out
        }

        fn reset(&mut self) {
            self.user_parts.clear();
            self.user_prompt_index = None;
            self.user_is_interjection = false;
            self.agent_text.clear();
            self.agent_tool_calls.clear();
            self.tool_args.clear();
            self.emitted_tool_results.clear();
            self.in_user_turn = false;
            self.has_agent_content = false;
            self.item_count = 0;
        }

        fn should_truncate(&self) -> bool {
            self.needs_truncate
        }

        fn clear_truncate_flag(&mut self) {
            self.needs_truncate = false;
        }

        fn count(&self) -> usize {
            self.item_count
        }
    }

    /// Extract displayable text from a completed ToolCallUpdate.
    fn extract_tool_result_text(fields: &acp::ToolCallUpdateFields) -> String {
        if let Some(content) = &fields.content {
            let text: String = content
                .iter()
                .filter_map(|c| match c {
                    acp::ToolCallContent::Content(acp::Content {
                        content: acp::ContentBlock::Text(t),
                        ..
                    }) => Some(t.text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("");
            if !text.is_empty() {
                return text;
            }
        }
        if let Some(raw) = &fields.raw_output {
            return raw.to_string();
        }
        String::new()
    }

    #[cfg(test)]
    mod contained_checkpoint_tests {
        use super::*;

        /// A cached marker (pulled by an older version) naming a path outside the session dir must not be read.
        #[test]
        fn hostile_marker_path_is_not_read_by_the_rebuild() {
            let tmp = tempfile::TempDir::new().unwrap();
            let dir = tmp.path().join("s");
            std::fs::create_dir_all(&dir).unwrap();
            let file = crate::extensions::notification::CompactionCheckpointFile {
                inherited_prefix_len: None,
                checkpoint_id: "x".into(),
                prompt_index_at_compaction: 1,
                compacted_history: vec![ConversationItem::user("OUTSIDE-SECRET")],
                schema_version: 1,
                created_at: "2026-10-04T00:00:00Z".into(),
                original_user_info: None,
                reread_file_paths: vec![],
            };
            std::fs::write(tmp.path().join("outside.json"), serde_json::to_vec(&file).unwrap()).unwrap();
            let abs = tmp.path().join("outside.json").display().to_string();
            for hostile in ["../outside.json", abs.as_str()] {
                assert!(compacted_projection(&dir, hostile).is_empty(), "{hostile} was read");
            }
        }
    }
}

/// Iterator that streams session updates from a JSONL file without loading all into memory.
pub struct UpdatesIterator {
    reader: BufReader<std::fs::File>,
    line_buffer: String,
}

impl UpdatesIterator {
    /// Returns None if the file doesn't exist.
    pub fn open(path: &Path) -> io::Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let file = std::fs::File::open(path)?;
        Ok(Some(Self {
            reader: BufReader::new(file),
            line_buffer: String::new(),
        }))
    }

    /// After iterating, the position is the offset of the next unread byte (i.e., EOF if all updates were consumed).
    /// Used to record the replay end offset for subsequent delta replay.
    pub fn stream_position(&mut self) -> io::Result<u64> {
        self.reader.stream_position()
    }
}

impl Iterator for UpdatesIterator {
    type Item = io::Result<SessionUpdate>;

    fn next(&mut self) -> Option<Self::Item> {
        self.line_buffer.clear();
        match self.reader.read_line(&mut self.line_buffer) {
            Ok(0) => None, // EOF
            Ok(_) => {
                let line = self.line_buffer.trim();
                if line.is_empty() {
                    return self.next();
                }
                match SessionUpdateEnvelope::from_str(line) {
                    Ok(update) => Some(Ok(update)),
                    Err(e) => Some(Err(io::Error::new(io::ErrorKind::InvalidData, e))),
                }
            }
            Err(e) => Some(Err(e)),
        }
    }
}

const ACP_SESSION_UPDATE_METHOD: &str = "session/update";

pub(crate) const FUIGO_SESSION_UPDATE_METHOD: &str = "_fuigo/session/update";

/// One type for both notification kinds, so all session updates can be stored in chronological order.
/// The `Serialize` implementation produces a format without timestamp (for GCS uploads, etc.).
/// For disk storage with timestamps, use `SessionUpdateEnvelope` via the JSONL adapter methods.
#[derive(Debug, Clone)]
pub enum SessionUpdate {
    /// Standard ACP session/update notification (boxed due to large size)
    Acp(Box<acp::SessionNotification>),
    /// Ferrox Labs extension session notification (e.g., diff_review)
    Fuigo(Box<SessionNotification>),
}

impl serde::Serialize for SessionUpdate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(Some(2))?;
        match self {
            SessionUpdate::Acp(notification) => {
                map.serialize_entry("method", ACP_SESSION_UPDATE_METHOD)?;
                map.serialize_entry("params", notification)?;
            }
            SessionUpdate::Fuigo(notification) => {
                map.serialize_entry("method", FUIGO_SESSION_UPDATE_METHOD)?;
                map.serialize_entry("params", notification)?;
            }
        }
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for SessionUpdate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize to a JSON value first to handle both envelope and legacy formats
        let value = serde_json::Value::deserialize(deserializer)?;
        SessionUpdateEnvelope::from_value(value).map_err(serde::de::Error::custom)
    }
}

/// This is the typed structure that gets written to updates.jsonl (disk storage only).
/// It is separate from `SessionUpdate`'s own serialization so other consumers (e.g., network listeners) don't see the timestamp metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct SessionUpdateEnvelope {
    /// Unix timestamp (seconds since epoch) when this update was written.
    /// Useful for debugging timing issues in the updates.jsonl file.
    #[serde(default)]
    pub timestamp: u64,
    /// Either "session/update" for ACP or "_fuigo/session/update" for Ferrox Labs extensions.
    pub method: String,
    pub params: serde_json::Value,
}

impl SessionUpdateEnvelope {
    /// Create a new envelope with the current timestamp for disk storage.
    pub(crate) fn from_update(update: &SessionUpdate) -> Result<Self, serde_json::Error> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        match update {
            SessionUpdate::Acp(notification) => Ok(Self {
                timestamp,
                method: ACP_SESSION_UPDATE_METHOD.to_string(),
                params: serde_json::to_value(notification)?,
            }),
            SessionUpdate::Fuigo(notification) => Ok(Self {
                timestamp,
                method: FUIGO_SESSION_UPDATE_METHOD.to_string(),
                params: serde_json::to_value(notification)?,
            }),
        }
    }

    pub(crate) fn into_update(self) -> Result<SessionUpdate, serde_json::Error> {
        if self.method == FUIGO_SESSION_UPDATE_METHOD {
            let notification: SessionNotification = serde_json::from_value(self.params)?;
            Ok(SessionUpdate::Fuigo(Box::new(notification)))
        } else {
            // ACP notification (method == "session/update" or unknown)
            let notification: acp::SessionNotification = serde_json::from_value(self.params)?;
            Ok(SessionUpdate::Acp(Box::new(notification)))
        }
    }

    /// Try to parse from a JSON value, handling both envelope format and legacy raw format.
    pub(crate) fn from_value(value: serde_json::Value) -> Result<SessionUpdate, serde_json::Error> {
        if value.get("method").is_some() {
            let envelope: SessionUpdateEnvelope = serde_json::from_value(value)?;
            envelope.into_update()
        } else {
            // Backwards compatibility: old format without envelope wrapper
            let notification: acp::SessionNotification = serde_json::from_value(value)?;
            Ok(SessionUpdate::Acp(Box::new(notification)))
        }
    }

    /// Parse a session update directly from a JSON string, avoiding intermediate `Value` allocation.
    pub(crate) fn from_str(line: &str) -> Result<SessionUpdate, serde_json::Error> {
        #[derive(serde::Deserialize)]
        struct BorrowedEnvelope<'a> {
            #[serde(default)]
            method: Option<&'a str>,
            #[serde(borrow)]
            params: &'a serde_json::value::RawValue,
        }

        if let Ok(envelope) = serde_json::from_str::<BorrowedEnvelope<'_>>(line) {
            let raw_params = envelope.params.get();
            return if envelope.method == Some(FUIGO_SESSION_UPDATE_METHOD) {
                let notification: SessionNotification = serde_json::from_str(raw_params)?;
                Ok(SessionUpdate::Fuigo(Box::new(notification)))
            } else {
                let notification: acp::SessionNotification = serde_json::from_str(raw_params)?;
                Ok(SessionUpdate::Acp(Box::new(notification)))
            };
        }

        // Backwards compatibility: legacy format without envelope
        let notification: acp::SessionNotification = serde_json::from_str(line)?;
        Ok(SessionUpdate::Acp(Box::new(notification)))
    }
}

/// All persisted data for a session
#[derive(Debug, Clone)]
pub struct PersistedData {
    pub summary: Summary,
    pub chat_history: Vec<ConversationItem>,
    /// All session updates (ACP updates and Ferrox Labs extension updates) in chronological order
    pub updates: Vec<SessionUpdate>,
    pub plan_state: Option<TodoState>,
    /// Persisted plan mode lifecycle state (None for sessions created before plan mode)
    pub plan_mode_state: Option<crate::session::plan_mode::PlanModeSnapshot>,
    /// The rewind points that parse, in file order.
    pub rewind_points: Vec<RewindPoint>,
    /// Line numbers of the rows of `rewind_points.jsonl` that did not parse (a torn append). They are left out of
    /// `rewind_points` and kept in the file as they were: they record which prompts' saved files are missing (P114, P123).
    pub damaged_rewind_lines: Vec<usize>,
    /// Persisted session signals (None for sessions created before signals persistence)
    pub signals: Option<SessionSignals>,
    /// Persisted announcement tracking state (None for sessions before this feature)
    pub announcement_state: Option<crate::session::announcement_state::AnnouncementState>,
    /// Persisted goal mode orchestration state (None for sessions without goal mode)
    pub goal_mode_state: Option<crate::session::goal_tracker::GoalOrchestration>,
    pub workflow_runs: Vec<crate::session::workflow::store::RestoredWorkflowRun>,
}

/// Persisted data WITHOUT updates, for memory-efficient session loading
#[derive(Debug, Clone)]
pub struct PersistedDataLight {
    pub summary: Summary,
    pub chat_history: Vec<ConversationItem>,
    /// Lines of `chat_history.jsonl` the reader skipped as unparseable (torn or interleaved appends).
    /// `chat_history` does not contain them.
    pub skipped_chat_lines: usize,
    pub plan_state: Option<TodoState>,
    pub plan_mode_state: Option<crate::session::plan_mode::PlanModeSnapshot>,
    // No `rewind_points` field: the resume path defers them (loaded lazily by `FileStateTracker`)
    // Use `load_session` for the eager set
    /// Persisted session signals (None for sessions created before signals persistence)
    pub signals: Option<SessionSignals>,
    /// Persisted announcement tracking state (None for sessions before this feature)
    pub announcement_state: Option<crate::session::announcement_state::AnnouncementState>,
    /// Persisted goal mode orchestration state (None for sessions without goal mode)
    pub goal_mode_state: Option<crate::session::goal_tracker::GoalOrchestration>,
    pub workflow_runs: Vec<crate::session::workflow::store::RestoredWorkflowRun>,
}

#[derive(Debug, Clone)]
pub struct CopySessionResult {
    pub chat_messages_copied: usize,
    pub updates_copied: usize,
    pub plan_state_copied: bool,
    /// Whether `plan_mode.json` (plan mode lifecycle state) was copied.
    pub plan_mode_state_copied: bool,
    pub signals_copied: bool,
    /// Whether `tool_state.json` (persisted tool state, e.g. TodoState) was copied.
    pub tool_state_copied: bool,
    /// Whether `announcement_state.json` was copied.
    pub announcement_state_copied: bool,
    /// Number of `compaction/segment_*.md` (and `INDEX.md`) files copied from the source session's compaction archive.
    /// `0` when disabled or none exist.
    pub compaction_segments_copied: usize,
    /// Number of `compaction_checkpoints/{uuid}.json` files copied for the checkpoint records retained in the copied updates.
    /// `0` when no records survive the copy or their files are missing from the source.
    pub compaction_checkpoints_copied: usize,
}

/// Options for copying session data during fork
#[derive(Debug, Clone)]
pub struct CopySessionOptions {
    /// Parent session ID to set in the forked session's summary.
    pub parent_session_id: Option<String>,
    /// Model ID override for the forked session (None keeps the source model).
    pub new_model_id: Option<String>,
    /// Truncate copied history to this prompt index (0-based, inclusive).
    pub target_prompt_index: Option<usize>,
    /// When true, skip `transform_conversation_cwd` during copy.
    ///
    /// Set for forks where the child should see the original project path (e.g. worktree forks with a persisted `display_cwd`).
    /// Non-worktree forks should keep this false so conversation paths are rewritten to the new cwd.
    pub skip_cwd_transform: bool,
    /// Stable display path for fork sessions.
    /// Persisted in the forked summary so the prompt-facing cwd survives session restore/reload.
    pub prompt_display_cwd: Option<String>,

    // ── Generic fork extensions (used by subagent + worktree forks) ──
    /// Override `session_kind` in the forked summary. Defaults to `"fork"`.
    /// Subagent resume sets `"subagent_resume"`.
    pub session_kind: Option<String>,
    /// How the fork's initial context was bootstrapped: `"new"` or `"forked"`.
    pub fork_context_source: Option<String>,
    /// Parent prompt/turn ID that triggered this fork.
    pub fork_parent_prompt_id: Option<String>,
    /// Whether to copy the plan state file. Defaults to `true`.
    pub copy_plan_state: bool,
    /// Whether to copy the plan mode state file. Defaults to `true`.
    pub copy_plan_mode_state: bool,
    /// Whether to copy the signals file. Defaults to `true`.
    pub copy_signals: bool,
    /// Whether to copy persisted usage. Defaults to `true`.
    /// Independent of `copy_signals` so a resume can keep billed history without parent telemetry.
    pub copy_usage: bool,
    /// Whether to copy `tool_state.json` (persisted tool state). Defaults to `true`.
    pub copy_tool_state: bool,
    /// Whether to copy `announcement_state.json`. Defaults to `true`.
    pub copy_announcement_state: bool,
    /// Whether to copy the `compaction/` segment archive (`segment_*.md` and `INDEX.md`, the verbose pre-compaction transcripts).
    /// Defaults to `false`: these can be large and most copy paths don't need them.
    /// Forks enable it so the child retains the parent's pre-compaction history.
    pub copy_compaction_segments: bool,
    /// When true, apply fork-safety filtering to copied chat history:
    /// - Strip synthetic user messages (doom loop warnings, compaction metadata)
    /// - Truncate at the last complete turn boundary
    /// - Remove trailing incomplete assistant responses
    pub fork_filter: bool,
    /// Number of inherited parent conversation items.
    /// Stored in the child's summary so compaction can preserve the inherited prefix.
    pub inherited_prefix_len: Option<usize>,
    /// When true, strip `reasoning` (thinking/reasoning_content) from all assistant messages in the copied chat history.
    /// Set for forks so that the new session does not inherit the prior model's chain-of-thought.
    pub strip_reasoning: bool,
    /// The original workspace directory this worktree session was spawned from.
    /// Propagated to the forked session's `Summary::source_workspace_dir`.
    pub source_workspace_dir: Option<String>,
}

impl Default for CopySessionOptions {
    fn default() -> Self {
        Self {
            parent_session_id: None,
            new_model_id: None,
            target_prompt_index: None,
            skip_cwd_transform: false,
            prompt_display_cwd: None,
            session_kind: None,
            fork_context_source: None,
            fork_parent_prompt_id: None,
            copy_plan_state: true,
            copy_plan_mode_state: true,
            copy_signals: true,
            copy_usage: true,
            copy_tool_state: true,
            copy_announcement_state: true,
            copy_compaction_segments: false,
            fork_filter: false,
            inherited_prefix_len: None,
            strip_reasoning: false,
            source_workspace_dir: None,
        }
    }
}

/// Chunk `_meta.promptIndex` on an ACP `UserMessageChunk`, if present.
fn acp_user_chunk_prompt_index(update: &SessionUpdate) -> Option<usize> {
    let SessionUpdate::Acp(n) = update else {
        return None;
    };
    let acp::SessionUpdate::UserMessageChunk(chunk) = &n.update else {
        return None;
    };
    chunk
        .meta
        .as_ref()
        .and_then(|m| m.get("promptIndex"))
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
}

pub(crate) const HOST_TURN_META_KEY: &str = "hostTurn";

pub(crate) fn is_host_turn_chunk(chunk: &acp::ContentChunk) -> bool {
    chunk_meta_flag(chunk, HOST_TURN_META_KEY)
}

/// `ContentChunk._meta` flag on a persisted mid-turn interjection's user chunks. The text block keeps the
/// model-facing frame and carries the typed text in `displayText`; the pager keys on this for replay.
pub const INTERJECTION_META_KEY: &str = "interjection";

pub fn is_interjection_chunk(chunk: &acp::ContentChunk) -> bool {
    chunk_meta_flag(chunk, INTERJECTION_META_KEY)
}

/// Boolean `ContentChunk._meta` flag; anything but a literal `true` reads as `false`.
pub fn chunk_meta_flag(chunk: &acp::ContentChunk, key: &str) -> bool {
    chunk
        .meta
        .as_ref()
        .and_then(|m| m.get(key))
        .and_then(|v| v.as_bool())
        == Some(true)
}

fn is_host_turn_update(update: &SessionUpdate) -> bool {
    let SessionUpdate::Acp(n) = update else {
        return false;
    };
    let acp::SessionUpdate::UserMessageChunk(chunk) = &n.update else {
        return false;
    };
    is_host_turn_chunk(chunk)
}

fn is_acp_user_message_chunk(update: &SessionUpdate) -> bool {
    matches!(
        update,
        SessionUpdate::Acp(n) if matches!(n.update, acp::SessionUpdate::UserMessageChunk(_))
    )
}

/// Tracks user-message runs for turn counting (updates truncate / filter_rewind).
///
/// Progressive: every user run counts until the first `promptIndex` appears; after that only marked runs count (mid-turn phantoms omit the marker).
/// A change of `promptIndex` (including between unmarked and marked) opens a new run.
/// This matches replay's split so back-to-back cancelled prompts stay distinct.
struct UserRunTurnTracker {
    seen_marker: bool,
    in_user: bool,
    /// `promptIndex` of the current user run (`None` means an unmarked phantom run).
    current_run_pi: Option<usize>,
}

impl UserRunTurnTracker {
    fn new() -> Self {
        Self {
            seen_marker: false,
            in_user: false,
            current_run_pi: None,
        }
    }

    /// Returns true if this user chunk opens a **counted** turn.
    fn on_user_chunk(&mut self, prompt_index: Option<usize>) -> bool {
        if prompt_index.is_some() {
            self.seen_marker = true;
        }
        let counts = if self.seen_marker {
            prompt_index.is_some()
        } else {
            true
        };
        let new_run = if !self.in_user {
            true
        } else if self.seen_marker || prompt_index.is_some() {
            prompt_index != self.current_run_pi
        } else {
            false
        };
        if new_run {
            self.current_run_pi = prompt_index;
            self.in_user = true;
            counts
        } else {
            self.in_user = true;
            false
        }
    }

    fn on_non_user(&mut self) {
        self.in_user = false;
        self.current_run_pi = None;
    }
}

/// How many items to keep for `target_prompt_index` (0-based, inclusive): the scan cuts at the opening chunk of the next counted turn.
/// Unmarked user runs count as turns only before the first `_meta.promptIndex`.
fn truncate_for_prompt_by<T>(
    items: &[T],
    target_prompt_index: usize,
    classify: impl Fn(&T) -> RewindStep,
) -> usize {
    let mut user_turn_count = 0;
    let mut tracker = UserRunTurnTracker::new();

    for (i, item) in items.iter().enumerate() {
        match classify(item) {
            RewindStep::UserChunk { prompt_index } => {
                if tracker.on_user_chunk(prompt_index) {
                    user_turn_count += 1;
                    if user_turn_count > target_prompt_index + 1 {
                        return i;
                    }
                }
            }
            RewindStep::Rewind { .. } | RewindStep::Other => tracker.on_non_user(),
        }
    }

    items.len()
}

#[derive(Debug)]
pub enum AppendUpdateError {
    NotCommitted(io::Error),
    Committed(io::Error),
}

#[derive(Debug)]
pub enum AppendChatError {
    NotCommitted(io::Error),
    Committed(io::Error),
}

#[derive(Debug)]
pub enum AppendCwdSwitchError {
    NotCommitted(io::Error),
    Committed {
        acknowledgement: fuigo_chat_state::StrictAppendAck,
        source: io::Error,
    },
}

impl AppendUpdateError {
    pub fn into_io_error(self) -> io::Error {
        match self {
            Self::NotCommitted(error) | Self::Committed(error) => error,
        }
    }
}

impl std::fmt::Display for AppendUpdateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotCommitted(error) | Self::Committed(error) => error.fmt(formatter),
        }
    }
}

impl AppendChatError {
    pub fn into_io_error(self) -> io::Error {
        match self {
            Self::NotCommitted(error) | Self::Committed(error) => error,
        }
    }
}

impl std::fmt::Display for AppendChatError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotCommitted(error) | Self::Committed(error) => error.fmt(formatter),
        }
    }
}

/// Session files a sync barrier flushes.
/// The persistence actor marks the files that took buffered writes since the last successful barrier.
/// Atomic-rename writes are durable at write time and never enter the set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionFileSet {
    pub updates: bool,
    pub chat: bool,
    pub summary: bool,
    pub plan: bool,
    pub rewind_points: bool,
}

impl SessionFileSet {
    pub(crate) const ALL: Self = Self {
        updates: true,
        chat: true,
        summary: true,
        plan: true,
        rewind_points: true,
    };

    pub(crate) fn is_empty(self) -> bool {
        self == Self::default()
    }
}

/// Why [`open_beneath_nofollow`] did not open a file.
#[derive(Debug)]
pub(crate) enum BeneathRefusal {
    /// The path is refused (a symlink, a non-directory folder, a non-regular file, a component leaving `base`).
    Refused(&'static str),
    Io(io::Error),
}

/// Open `base/relative` for reading without following a symlink at any component below `base`, and only when it is
/// a regular file (P146, S17). On Unix every folder is opened with `O_DIRECTORY | O_NOFOLLOW` relative to the one
/// above it and the file with `openat(O_NOFOLLOW | O_NONBLOCK)`, so a component swapped for a symlink after any check
/// cannot redirect the read, and a FIFO cannot block it. On Windows every folder is opened as a handle that refuses
/// rename and delete while it is held, checked from that handle, and kept open until the file is opened, so a folder
/// cannot be swapped for a link in between (P154). On any other platform every folder is checked with
/// `symlink_metadata` and the file is opened without following a link (a folder swapped between the check and the
/// open is not caught there). `base` itself is trusted.
pub(crate) fn open_beneath_nofollow(base: &Path, relative: &Path) -> Result<std::fs::File, BeneathRefusal> {
    const NOT_REGULAR: &str = "it is not a regular file (a symlink is never followed)";
    #[cfg(not(windows))]
    const NOT_DIR: &str = "a folder on its path is not a real directory (a symlink is never followed)";
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(part) => parts.push(part),
            _ => return Err(BeneathRefusal::Refused("its path leaves the session folder")),
        }
    }
    let Some(leaf) = parts.pop() else {
        return Err(BeneathRefusal::Refused("its path is empty"));
    };
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::io::{AsRawFd as _, FromRawFd as _};
        let c = |p: &std::ffi::OsStr| {
            std::ffi::CString::new(p.as_bytes()).map_err(|e| BeneathRefusal::Io(io::Error::other(e)))
        };
        let base_c = c(base.as_os_str())?;
        // SAFETY: open(2) on a NUL-terminated path; the descriptor is owned by the File right after.
        let fd = unsafe { libc::open(base_c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(BeneathRefusal::Io(io::Error::last_os_error()));
        }
        // SAFETY: a fresh descriptor nothing else owns.
        let mut dir = unsafe { std::fs::File::from_raw_fd(fd) };
        for part in parts {
            let part_c = c(part)?;
            // SAFETY: openat(2) relative to a live directory descriptor, on one NUL-terminated component.
            let fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    part_c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                let error = io::Error::last_os_error();
                return Err(match error.raw_os_error() {
                    Some(libc::ELOOP) | Some(libc::ENOTDIR) => BeneathRefusal::Refused(NOT_DIR),
                    _ => BeneathRefusal::Io(error),
                });
            }
            // SAFETY: a fresh descriptor nothing else owns.
            dir = unsafe { std::fs::File::from_raw_fd(fd) };
        }
        let leaf_c = c(leaf)?;
        // SAFETY: as above. O_NONBLOCK: opening a FIFO must not wait for a writer; it is refused just below.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                leaf_c.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = io::Error::last_os_error();
            return Err(match error.raw_os_error() {
                Some(libc::ELOOP) => BeneathRefusal::Refused(NOT_REGULAR),
                _ => BeneathRefusal::Io(error),
            });
        }
        // SAFETY: a fresh descriptor nothing else owns.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        match file.metadata() {
            Ok(meta) if meta.is_file() => Ok(file),
            Ok(_) => Err(BeneathRefusal::Refused(NOT_REGULAR)),
            Err(error) => Err(BeneathRefusal::Io(error)),
        }
    }
    #[cfg(windows)]
    {
        // Every folder stays open (see `hold_folders_beneath_windows`) until the file is opened and checked.
        let (held, dir) = hold_folders_beneath_windows(base, &parts)?;
        open_leaf_beneath_windows(&held, &dir, leaf)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let mut dir = base.to_path_buf();
        for part in parts {
            dir.push(part);
            match std::fs::symlink_metadata(&dir) {
                Ok(meta) if meta.file_type().is_dir() => {}
                Ok(_) => return Err(BeneathRefusal::Refused(NOT_DIR)),
                Err(error) => return Err(BeneathRefusal::Io(error)),
            }
        }
        let file = std::fs::File::open(dir.join(leaf)).map_err(BeneathRefusal::Io)?;
        match file.metadata() {
            Ok(meta) if meta.is_file() => Ok(file),
            Ok(_) => Err(BeneathRefusal::Refused(NOT_REGULAR)),
            Err(error) => Err(BeneathRefusal::Io(error)),
        }
    }
}

/// Windows: `FILE_ATTRIBUTE_REPARSE_POINT` is set (a symlink or junction, never followed here).
#[cfg(windows)]
fn is_reparse_point_windows(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Windows: open the file itself, never the target of a symlink at its path (`FILE_FLAG_OPEN_REPARSE_POINT`); the
/// caller then checks the handle's metadata.
#[cfg(windows)]
fn open_leaf_windows(path: &Path) -> Result<std::fs::File, BeneathRefusal> {
    use std::os::windows::fs::OpenOptionsExt as _;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(BeneathRefusal::Io)
}

/// Windows: the final path of an open handle (`GetFinalPathNameByHandleW`, normalized, DOS volume name) as UTF-16
/// units, where the object really lives, whatever path it was opened through. Never turned into text: a name may hold
/// an isolated surrogate, and a lossy conversion would make two different folders compare equal.
#[cfg(windows)]
fn final_path_windows(file: &std::fs::File) -> io::Result<Vec<u16>> {
    use std::os::windows::io::AsRawHandle as _;
    // kernel32 is linked by std.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFinalPathNameByHandleW(file: *mut std::ffi::c_void, path: *mut u16, len: u32, flags: u32) -> u32;
    }
    let mut buffer = vec![0u16; 1024];
    loop {
        // SAFETY: a live handle and a writable buffer of the length passed.
        let len = unsafe { GetFinalPathNameByHandleW(file.as_raw_handle(), buffer.as_mut_ptr(), buffer.len() as u32, 0) };
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        if (len as usize) < buffer.len() {
            buffer.truncate(len as usize);
            return Ok(buffer);
        }
        buffer.resize(len as usize + 1, 0);
    }
}

/// Windows: `child` (a final path) is `name` directly inside `parent` (a final path). Both come from
/// `GetFinalPathNameByHandleW` as UTF-16 units and the parent part must match unit for unit: a case-sensitive folder
/// can hold `session` and `SESSION` apart, and a name may hold an isolated surrogate that a lossy text conversion
/// would turn into the same U+FFFD as another name. Only the last name is compared without regard to case, as the
/// volume itself may be case-insensitive.
#[cfg(windows)]
fn is_direct_child_windows(parent: &[u16], child: &[u16], name: &std::ffi::OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt as _;
    let backslash = u16::from(b'\\');
    let mut parent = parent;
    while let [rest @ .., last] = parent {
        if *last != backslash {
            break;
        }
        parent = rest;
    }
    let Some(rest) = child.strip_prefix(parent) else {
        return false;
    };
    let Some(last) = rest.strip_prefix(&[backslash]) else {
        return false;
    };
    if last.contains(&backslash) {
        return false;
    }
    let wanted: Vec<u16> = name.encode_wide().collect();
    last == wanted.as_slice() || String::from_utf16_lossy(last).to_lowercase() == String::from_utf16_lossy(&wanted).to_lowercase()
}

/// Windows: open `dir/leaf` (the folders `held` are still open) and refuse anything but a regular file that really
/// lives directly in the last held folder. The location check catches a folder turned into a junction in place (an
/// empty folder can be, through another handle) between the folder checks and this open: the file would then be read
/// from the junction's target, whose final path is not under the folder's own (P154). With no folder held the file
/// is directly in `base`, which is trusted.
#[cfg(windows)]
fn open_leaf_beneath_windows(
    held: &[std::fs::File],
    dir: &Path,
    leaf: &std::ffi::OsStr,
) -> Result<std::fs::File, BeneathRefusal> {
    const NOT_REGULAR: &str = "it is not a regular file (a symlink is never followed)";
    const NOT_DIR: &str = "a folder on its path is not a real directory (a symlink is never followed)";
    let file = open_leaf_windows(&dir.join(leaf))?;
    match file.metadata() {
        Ok(meta) if meta.is_file() && !is_reparse_point_windows(&meta) => {}
        Ok(_) => return Err(BeneathRefusal::Refused(NOT_REGULAR)),
        Err(error) => return Err(BeneathRefusal::Io(error)),
    }
    if let Some(folder) = held.last() {
        let folder_path = final_path_windows(folder).map_err(BeneathRefusal::Io)?;
        let file_path = final_path_windows(&file).map_err(BeneathRefusal::Io)?;
        if !is_direct_child_windows(&folder_path, &file_path, leaf) {
            return Err(BeneathRefusal::Refused(NOT_DIR));
        }
    }
    Ok(file)
}

/// Windows: open every folder of `parts` under `base`, one below the other, and return the open handles with the
/// folder's path. A handle takes `FILE_SHARE_READ` only, so while it is held Windows refuses to rename or delete
/// that folder or any above it, and refuses data-write opens of it; it cannot be swapped for a symlink or junction
/// between this check and the file's open. (An in-place conversion of an empty folder is caught later, by the
/// location check in `open_leaf_beneath_windows`.) Each folder is checked from its own handle: a
/// directory, and not a reparse point. The caller keeps the handles until the file is opened and checked (P154).
#[cfg(windows)]
fn hold_folders_beneath_windows(
    base: &Path,
    parts: &[&std::ffi::OsStr],
) -> Result<(Vec<std::fs::File>, PathBuf), BeneathRefusal> {
    hold_folders_beneath_windows_with(base, parts, &mut |_| {})
}

/// [`hold_folders_beneath_windows`], calling `after_each(index)` once folder `index` is held and checked (a test
/// seam: it lets a test act between two folder opens).
#[cfg(windows)]
fn hold_folders_beneath_windows_with(
    base: &Path,
    parts: &[&std::ffi::OsStr],
    after_each: &mut dyn FnMut(usize),
) -> Result<(Vec<std::fs::File>, PathBuf), BeneathRefusal> {
    use std::os::windows::fs::OpenOptionsExt as _;
    const NOT_DIR: &str = "a folder on its path is not a real directory (a symlink is never followed)";
    // FILE_TRAVERSE too: an open that asks for attribute access alone is not share-checked, so a handle with only
    // FILE_READ_ATTRIBUTES would not stop a rename of its folder (found on a Windows host, P154).
    const FILE_ACCESS: u32 = 0x80 | 0x20; // FILE_READ_ATTRIBUTES | FILE_TRAVERSE
    // No FILE_SHARE_WRITE and no FILE_SHARE_DELETE: nothing else can open the folder for data writes or to rename or
    // delete it. Files created inside it are not affected. An open for FILE_WRITE_ATTRIBUTES alone is not share-checked,
    // and can still turn an EMPTY folder into a junction in place (shown on Windows Server 2022); that case is caught
    // by the location checks (`is_direct_child_windows`).
    const SHARE_READ: u32 = 0x1;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let mut held = Vec::with_capacity(parts.len());
    let mut dir = base.to_path_buf();
    // Where `base` really is (it is trusted, so a link in it is followed). Each folder must really be directly in
    // the one above it: a folder turned into a junction in place between two opens would otherwise lead the walk
    // out, and the file's own location check would then only see the outside folder and the file agree.
    let mut above: Vec<u16> = Vec::new();
    if !parts.is_empty() {
        let base_handle = std::fs::OpenOptions::new()
            .access_mode(FILE_ACCESS)
            .share_mode(0x7)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(base)
            .map_err(BeneathRefusal::Io)?;
        above = final_path_windows(&base_handle).map_err(BeneathRefusal::Io)?;
    }
    for (index, part) in parts.iter().enumerate() {
        dir.push(part);
        let handle = std::fs::OpenOptions::new()
            .access_mode(FILE_ACCESS)
            .share_mode(SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&dir)
            .map_err(BeneathRefusal::Io)?;
        match handle.metadata() {
            Ok(meta) if meta.is_dir() && !is_reparse_point_windows(&meta) => {}
            Ok(_) => return Err(BeneathRefusal::Refused(NOT_DIR)),
            Err(error) => return Err(BeneathRefusal::Io(error)),
        }
        let here = final_path_windows(&handle).map_err(BeneathRefusal::Io)?;
        if !is_direct_child_windows(&above, &here, part) {
            return Err(BeneathRefusal::Refused(NOT_DIR));
        }
        above = here;
        held.push(handle);
        after_each(index);
    }
    Ok((held, dir))
}

/// The durable copy of `rewind_points.jsonl` a rewind keeps while it is in progress (P146), next to it. One left
/// behind means an earlier rewind did not finish; the next rewind is refused until it is dealt with.
pub(crate) fn rewind_points_pre_rewind_copy(rewind_points: &Path) -> PathBuf {
    rewind_points.with_extension("jsonl.pre-rewind")
}

/// The rewind points rewrite lock, held from [`StorageAdapter::lock_rewind_points_rewrite`] until the rewind it was
/// taken for is done (P146). `None` inside: the lock file could not be opened, and the rewrite runs without it, as a
/// rewrite that takes the lock itself does then. Dropping it releases the lock.
#[derive(Debug, Default)]
pub struct RewindPointsRewriteLock {
    /// `rewind_points.jsonl.rewrite.lock`, exclusive.
    pub(crate) rewrite: Option<std::fs::File>,
}

/// What `rewind_points.jsonl` held before a rewind rewrote it (`None`: it did not exist), to put it back when the
/// rewind does not go through (P146).
#[derive(Debug, Default)]
pub struct RewindPointsUndo {
    pub(crate) previous: Option<Vec<u8>>,
    /// What the rewind's rewrite wrote: a put-back keeps whatever was appended after it.
    pub(crate) written: Vec<u8>,
}

/// The rewrite of `rewind_points.jsonl` a rewind makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewindPointsRewrite {
    /// A file rewind (All, FilesOnly): drop the points of prompts `from_index` and later.
    TruncateFrom(usize),
    /// A conversation-only rewind: fold the points of prompts `target_index` and later into the one before.
    MergeFrom(usize),
}

/// Abstracts over different storage backends (JSONL, SQLite, etc.)
#[async_trait]
pub trait StorageAdapter: Send + Sync {
    /// Initialize a new session or load existing one
    async fn init_session(&self, info: &Info, model_id: acp::ModelId) -> io::Result<Summary>;

    /// Set the session title unconditionally (manual `/rename`); last write wins.
    /// Also marks the title manual (`Summary::title_is_manual`) so clients restore the prompt-border title on resume.
    async fn update_session_title(&self, info: &Info, session_title: String) -> io::Result<()>;

    /// Set the session title only if the session has no title yet, used by automatic LLM title generation so it never overwrites a manual `/rename`.
    /// Never marks the title manual.
    /// Returns `true` if the title was written, `false` if an existing title was preserved.
    /// The check and write are atomic under the summary lock, so a concurrent manual rename always wins.
    async fn set_generated_title_if_absent(
        &self,
        info: &Info,
        session_title: String,
    ) -> io::Result<bool>;

    /// Overwrite an existing auto title with a refreshed one (early-session title refresh at turns 3 and 6), but never a manual `/rename`.
    /// The manual check and write are atomic under the summary lock, so a concurrent manual rename always wins.
    /// Returns `true` if the title was written, `false` if a manual pin was preserved.
    async fn regenerate_generated_title(
        &self,
        info: &Info,
        session_title: String,
    ) -> io::Result<bool>;

    /// Stamp `session_kind` only if the session has none yet, atomically under the summary lock.
    /// A kind already on disk (crash-recovered dir, concurrent writer) is preserved.
    async fn set_session_kind_if_absent(&self, info: &Info, kind: String) -> io::Result<()>;

    /// Clear a manual `/rename` pin (`/rename --auto`).
    /// Sets `title_is_manual = false` and, when a pin was present, blanks `generated_title` and `session_summary` so `display_title()` is empty.
    /// Returns `true` iff a manual pin was actually cleared.
    /// Idempotent when the title is not manual.
    async fn reset_title_to_auto(&self, info: &Info) -> io::Result<bool>;

    /// Replace or clear (`None`) the latest session recap preview in `summary.json`; last-writer-wins.
    /// Distinct from `last_turn_summary`.
    async fn set_last_recap(&self, info: &Info, recap: Option<String>) -> io::Result<()>;

    /// Replace or clear (`None`) the per-turn dashboard summary (`(text, prompt_id)`) in `summary.json`; last-writer-wins.
    async fn set_last_turn_summary(
        &self,
        info: &Info,
        summary: Option<(String, String)>,
    ) -> io::Result<()>;

    /// Append a session update (ACP update or Ferrox Labs extension update) and increment counter
    async fn append_update(&self, info: &Info, update: &SessionUpdate) -> io::Result<()>;

    /// Append one update and report whether the replay record was committed before an error.
    async fn append_update_commit_aware(
        &self,
        info: &Info,
        update: &SessionUpdate,
    ) -> Result<(), AppendUpdateError> {
        self.append_update(info, update)
            .await
            .map_err(AppendUpdateError::NotCommitted)
    }

    /// Append one update durably, preserving whether the replay record committed before failure.
    async fn append_update_durable_commit_aware(
        &self,
        _info: &Info,
        _update: &SessionUpdate,
    ) -> Result<(), AppendUpdateError> {
        Err(AppendUpdateError::NotCommitted(io::Error::new(
            io::ErrorKind::Unsupported,
            "durable session update append is unsupported",
        )))
    }

    /// Append a chat message and increment counter.
    async fn append_chat_message(&self, info: &Info, message: &ConversationItem) -> io::Result<()>;

    /// Append one chat message and report whether the JSONL record was committed before an error.
    /// Bookkeeping (summary counters) can fail after the append has already reached the page cache.
    async fn append_chat_message_commit_aware(
        &self,
        info: &Info,
        message: &ConversationItem,
    ) -> Result<(), AppendChatError> {
        self.append_chat_message(info, message)
            .await
            .map_err(AppendChatError::NotCommitted)
    }

    /// Append one working-directory switch generation exactly once.
    async fn append_cwd_switch_commit_aware(
        &self,
        _info: &Info,
        _message: &ConversationItem,
    ) -> Result<fuigo_chat_state::StrictAppendAck, AppendCwdSwitchError> {
        Err(AppendCwdSwitchError::NotCommitted(io::Error::new(
            io::ErrorKind::Unsupported,
            "working-directory switch append is unsupported",
        )))
    }

    /// Update the current model in summary (delegates to `update_current_model_and_agent` with `agent_name = None`).
    async fn update_current_model(&self, info: &Info, model_id: &acp::ModelId) -> io::Result<()> {
        self.update_current_model_and_agent(info, model_id, None, None)
            .await
    }

    /// Update the current model and agent name in summary.
    /// `agent_name` is the resolved agent definition name, persisted so session resume doesn't depend on the mutable model catalog.
    /// `None` leaves the existing `agent_name` unchanged (used by legacy callers that only update the model ID).
    async fn update_current_model_and_agent(
        &self,
        info: &Info,
        model_id: &acp::ModelId,
        agent_name: Option<&str>,
        reasoning_effort: Option<Option<ReasoningEffort>>,
    ) -> io::Result<()>;

    /// Update the collection ID for telemetry tracing
    async fn update_collection_id(&self, info: &Info, collection_id: &str) -> io::Result<()>;

    /// Update the persisted HEAD commit and branch in summary
    async fn update_git_head(
        &self,
        info: &Info,
        commit: Option<String>,
        branch: Option<String>,
    ) -> io::Result<()>;

    /// Update the monotonic telemetry trace turn counter ("next turn" value).
    async fn update_next_trace_turn(
        &self,
        info: &Info,
        next_trace_turn: u64,
        request_id: Option<&str>,
    ) -> io::Result<()>;

    async fn write_plan_state(&self, info: &Info, state: &TodoState) -> io::Result<()>;

    async fn write_plan_mode_state(
        &self,
        info: &Info,
        state: &crate::session::plan_mode::PlanModeSnapshot,
    ) -> io::Result<()>;

    async fn write_signals(&self, info: &Info, signals: &SessionSignals) -> io::Result<()>;

    async fn read_usage(
        &self,
        info: &Info,
    ) -> io::Result<Option<crate::session::usage_file::SessionUsageFile>>;

    async fn write_usage(
        &self,
        info: &Info,
        usage: &crate::session::usage_file::SessionUsageFile,
    ) -> io::Result<()>;

    async fn write_announcement_state(
        &self,
        info: &Info,
        state: &crate::session::announcement_state::AnnouncementState,
    ) -> io::Result<()>;

    async fn write_goal_mode_state(
        &self,
        info: &Info,
        state: &crate::session::goal_tracker::GoalOrchestration,
    ) -> io::Result<()>;

    async fn delete_goal_mode_state(&self, info: &Info) -> io::Result<()>;

    async fn write_workflow_run_state(
        &self,
        info: &Info,
        manifest: &crate::session::workflow::store::WorkflowRunManifest,
    ) -> io::Result<()>;

    async fn delete_workflow_run_state(&self, info: &Info, run_id: &str) -> io::Result<()>;

    async fn load_session(&self, info: &Info) -> io::Result<PersistedData>;

    /// Load session data WITHOUT updates (for memory efficiency when updates will be streamed).
    /// Implementations also do NOT read rewind points here.
    /// Those are deferred and lazily loaded on demand from the path returned by [`rewind_points_file_path`](StorageAdapter::rewind_points_file_path).
    async fn load_session_without_updates(&self, info: &Info) -> io::Result<PersistedDataLight>;

    async fn load_summary(&self, info: &Info) -> io::Result<Summary>;

    /// When `cwd` is `None`, returns summaries for all sessions.
    async fn list_sessions(&self, cwd: Option<&str>) -> io::Result<Vec<Summary>>;

    /// Permanently delete a session's stored data (all files for the session).
    /// Implementations must treat a missing session as success (idempotent delete).
    async fn delete_session(&self, info: &Info) -> io::Result<()>;

    async fn append_rewind_point(&self, info: &Info, point: &RewindPoint) -> io::Result<()>;

    async fn load_rewind_points(&self, info: &Info) -> io::Result<Vec<RewindPoint>>;

    /// Sync the selected session files, plus the session directory entry once, to stable media.
    /// Backs the `FlushAndAck` barrier (dirty files only) and the pre-`CopyFile` flush ([`SessionFileSet::ALL`]).
    /// An error means the barrier must not ack.
    async fn sync_session_files_selected(
        &self,
        info: &Info,
        files: SessionFileSet,
    ) -> io::Result<()>;

    /// Truncate rewind points from a specific prompt index (inclusive)
    /// Used when rewinding to remove future history
    async fn truncate_rewind_points_from(&self, info: &Info, from_index: usize) -> io::Result<()>;

    /// Merge rewind points at indices `>= target_index` into the point at `target_index - 1` and drop the folded points.
    /// Runs as a read-modify-write on disk (used after a ConversationOnly rewind).
    /// Reading the current on-disk set makes this authoritative.
    /// It never relies on a (possibly partially loaded) in-memory tracker, so historical points can't be lost.
    async fn merge_rewind_points_from(&self, info: &Info, target_index: usize) -> io::Result<()>;

    /// Take the rewind points rewrite lock (and check the append lock can be had), waiting as long as a rewrite does.
    /// A rewind takes it before it changes anything and keeps it until it is done (P146): `WouldBlock` when another
    /// process holds either all that time, so the rewind is refused with nothing changed instead of going through and
    /// then dropping its rewrite.
    async fn lock_rewind_points_rewrite(&self, info: &Info) -> io::Result<RewindPointsRewriteLock>;

    /// [`Self::truncate_rewind_points_from`] or [`Self::merge_rewind_points_from`] for a rewind that holds the rewrite
    /// lock (from [`Self::lock_rewind_points_rewrite`]) until it is done. First keeps a durable copy of the file
    /// (`rewind_points.jsonl.pre-rewind`); returns what it held and what was written, for
    /// [`Self::end_rewind_points_rewrite`]. A failed rewrite leaves the file as it was and removes the copy.
    async fn rewrite_rewind_points_holding(&self, info: &Info, rewrite: RewindPointsRewrite) -> io::Result<RewindPointsUndo>;

    /// The rewind [`Self::rewrite_rewind_points_holding`] was made for is done, its rewrite lock still held.
    /// `put_back`: it did not go through, so `rewind_points.jsonl` gets back what it held, followed by any row appended
    /// since. The durable copy is then removed; it stays when the put-back failed.
    async fn end_rewind_points_rewrite(&self, info: &Info, undo: RewindPointsUndo, put_back: bool) -> io::Result<()>;

    /// Replace the entire chat history (used for compaction and rewind)
    async fn replace_chat_history(
        &self,
        info: &Info,
        messages: &[ConversationItem],
    ) -> io::Result<()>;

    /// [`Self::replace_chat_history`] that says, when it fails, whether `chat_history.jsonl` already holds `messages`
    /// (`Committed`: a step after the file replacement failed) or still the previous history (`NotCommitted`).
    async fn replace_chat_history_commit_aware(
        &self,
        info: &Info,
        messages: &[ConversationItem],
    ) -> Result<(), AppendChatError>;

    /// Copy the on-disk chat history before a destructive image-strip rewrite (first backup wins), mirroring the `*.corrupt` quarantine.
    /// Required, not defaulted: a new adapter must choose explicitly how its data stays recoverable.
    async fn backup_chat_history_before_strip(&self, info: &Info) -> io::Result<()>;

    /// Copy session data from source to target, transforming session IDs
    async fn copy_session_data(
        &self,
        source_info: &Info,
        target_info: &Info,
        options: CopySessionOptions,
    ) -> io::Result<CopySessionResult>;

    /// Load only user prompts from a session's updates file.
    /// Returns user prompts in chronological order.
    async fn load_prompts_only(&self, info: &Info) -> io::Result<Vec<String>>;
    /// Load assistant text content from a session's updates file.
    /// Returns assistant responses in chronological order, extracted from ContentChunk text.
    async fn load_assistant_text(&self, info: &Info) -> io::Result<Vec<String>>;

    /// Load tool metadata from a session's updates file.
    /// Per the ACP data model:
    /// - Tool name: from `ToolCall.title` (display name; acp::ToolCall has no .name field)
    /// - File paths: from `ToolCall.locations[].path` (ACP stores locations, not parsed arguments)
    /// - Errors: skipped (no is_error field on acp::SessionUpdate::ToolCallUpdate)
    async fn load_tool_metadata(&self, info: &Info) -> io::Result<Vec<String>>;

    /// Get the path to the updates file for streaming reads.
    /// Returns None if the storage backend doesn't support streaming.
    fn updates_file_path(&self, info: &Info) -> Option<std::path::PathBuf>;

    /// Path to the rewind-points file for lazy/deferred loading, or None if the backend doesn't persist them to a streamable file.
    /// The adapter owns the on-disk layout, so callers must use this rather than recomputing the path.
    /// The path differs for non-default storage modes, e.g. subagent/fork sessions.
    fn rewind_points_file_path(&self, info: &Info) -> Option<std::path::PathBuf>;

    /// Append a feedback entry (user feedback) to feedback.jsonl
    async fn append_feedback(
        &self,
        info: &Info,
        entry: &crate::session::persistence::LocalFeedbackEntry,
    ) -> io::Result<()>;

    /// Append a /btw side question entry to btw_history.jsonl
    async fn append_btw(
        &self,
        info: &Info,
        entry: &crate::session::persistence::BtwEntry,
    ) -> io::Result<()>;

    /// Write a compaction checkpoint file to `compaction_checkpoints/{checkpoint_id}.json`.
    async fn write_compaction_checkpoint(
        &self,
        info: &Info,
        checkpoint: &crate::extensions::notification::CompactionCheckpointFile,
    ) -> io::Result<()>;

    /// Before a compaction's activation marker is appended, record which checkpoint it activates and what
    /// `chat_history.jsonl` holds at that moment, durably (P111). See `jsonl::compaction_witness`.
    async fn write_compaction_witness(
        &self,
        info: &Info,
        checkpoint: &crate::extensions::notification::CompactionCheckpointFile,
    ) -> io::Result<()>;

    /// The compaction `checkpoint_id` activated (its marker is in `updates.jsonl`): earlier witness entries are no
    /// longer needed. Best effort.
    async fn compaction_activated(&self, info: &Info, checkpoint_id: &str);

    /// The compacted history to resume with when the latest compaction committed but its rewrite of
    /// `chat_history.jsonl` never landed; `None` when `chat_history.jsonl` is authoritative (the normal case).
    async fn unapplied_compaction_projection(&self, info: &Info) -> Option<Vec<ConversationItem>>;

    /// Write a compaction request artifact to `compaction_requests/{request_id}.json`.
    /// Captures the exact request sent to the compaction model and the response (or final error) it produced.
    /// Used for offline prompt iteration.
    async fn write_compaction_request(
        &self,
        info: &Info,
        request: &crate::extensions::notification::CompactionRequestFile,
    ) -> io::Result<()>;

    /// Write a recap request artifact to `recap_requests/{request_id}.json`.
    /// Captures the exact request sent for `/recap` or auto recap and the response (or error).
    /// Used for offline recap prompt and garble analysis.
    async fn write_recap_request(
        &self,
        info: &Info,
        request: &crate::extensions::notification::RecapRequestFile,
    ) -> io::Result<()>;

    /// Render and write `compaction/segment_NNN.md` (storage assigns the resume-safe index) and append its `INDEX.md` row.
    async fn write_compaction_segment(
        &self,
        info: &Info,
        segment: &crate::extensions::notification::CompactionSegmentFile,
    ) -> io::Result<()>;

    /// Read a compaction checkpoint file by its relative path within the session directory.
    async fn read_compaction_checkpoint(
        &self,
        info: &Info,
        checkpoint_file: &str,
    ) -> io::Result<crate::extensions::notification::CompactionCheckpointFile>;
}

/// Backup-gated strip rewrite: the destructive rewrite runs only when the backup landed.
/// So recoverability can never be silently forfeited (full disk, read-only volume).
/// Factored out of the persistence actor so the gate ordering is testable against a real adapter.
pub(crate) async fn strip_rewrite_gated(
    storage: &dyn StorageAdapter,
    info: &Info,
    messages: &[ConversationItem],
) -> io::Result<()> {
    storage.backup_chat_history_before_strip(info).await?;
    storage.replace_chat_history(info, messages).await
}

pub use jsonl::JsonlStorageAdapter;
#[cfg(any(test, feature = "test-support"))]
pub use replay::load_updates_for_replay_at;
pub use replay::{
    PreparedReplay, ReplayEmission, ReplayLookupFallback, ReplayPathHint, ReplayedUpdate,
    load_updates_for_replay, prepare_replay_lines, replay_would_emit, stream_replay_updates_at,
    stream_replay_updates_at_hinted,
};
pub(crate) use replay::{ReplayToolCollapser, filter_delta_replay_lines};

/// Extracts `method` and raw `params` from an updates.jsonl envelope without parsing the notification payload.
#[derive(serde::Deserialize)]
pub(crate) struct RawLinePeek<'a> {
    #[serde(default)]
    pub method: Option<&'a str>,
    #[serde(borrow, default)]
    pub params: Option<&'a serde_json::value::RawValue>,
}

/// Peeks at `update.sessionUpdate` tag and `_meta` without full deserialization.
#[derive(serde::Deserialize)]
pub(crate) struct RawParamsPeek<'a> {
    #[serde(borrow, default)]
    pub update: Option<RawUpdatePeek<'a>>,
    #[serde(borrow, default, rename = "_meta")]
    pub meta: Option<&'a serde_json::value::RawValue>,
}

#[derive(serde::Deserialize)]
pub(crate) struct RawUpdatePeek<'a> {
    #[serde(rename = "sessionUpdate")]
    pub session_update: &'a str,
    #[serde(default)]
    pub status: Option<&'a str>,
    #[serde(default)]
    pub target_prompt_index: Option<usize>,
    /// Chunk `_meta.promptIndex` when present (owned; not borrowed).
    #[serde(default, rename = "_meta")]
    pub meta: Option<RawChunkMetaPeek>,
}

#[derive(serde::Deserialize)]
pub(crate) struct RawChunkMetaPeek {
    #[serde(default, rename = "promptIndex")]
    pub prompt_index: Option<u64>,
    #[serde(default, rename = "hostTurn")]
    pub host_turn: Option<bool>,
}

/// Role of one item in the rewind timeline, as seen by [`filter_rewind_by`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RewindStep {
    /// Rewind marker: truncate survivors back to `target`'s prompt boundary.
    Rewind { target: usize },
    /// User-message chunk opening (or continuing) a prompt run.
    UserChunk { prompt_index: Option<usize> },
    /// Anything else: kept, but ends the current user run.
    Other,
}

/// Shared rewind dead-branch filter. `classify` maps each item to its [`RewindStep`].
/// The driver tracks prompt boundaries and, on a marker, truncates survivors back to the target prompt.
/// [`filter_rewind_lines`] and [`filter_rewind_updates`] wrap this over raw JSONL and typed updates so the two paths share one algorithm.
fn filter_rewind_by<T>(items: Vec<T>, classify: impl Fn(&T) -> RewindStep) -> Vec<T> {
    let mut result: Vec<T> = Vec::with_capacity(items.len());
    let mut prompt_starts: Vec<usize> = Vec::new();
    let mut tracker = UserRunTurnTracker::new();

    for item in items {
        match classify(&item) {
            RewindStep::Rewind { target } => {
                // Out-of-range target keeps every survivor: fold to `result.len()`.
                let trunc = prompt_starts.get(target).copied().unwrap_or(result.len());
                result.truncate(trunc);
                prompt_starts.truncate(target);
                tracker.on_non_user();
                continue;
            }
            RewindStep::UserChunk { prompt_index } => {
                if tracker.on_user_chunk(prompt_index) {
                    prompt_starts.push(result.len());
                }
            }
            RewindStep::Other => tracker.on_non_user(),
        }
        result.push(item);
    }
    result
}

/// Classify a raw JSONL line by peeking at its tag and `_meta` without fully deserializing the payload.
fn rewind_step_for_line(line: &str) -> RewindStep {
    let (raw_params, is_fuigo) = if let Ok(env) = serde_json::from_str::<RawLinePeek<'_>>(line) {
        let raw = env.params.map(|p| p.get()).unwrap_or(line);
        (raw, env.method == Some(FUIGO_SESSION_UPDATE_METHOD))
    } else {
        (line, false)
    };

    let Some(u) = serde_json::from_str::<RawParamsPeek<'_>>(raw_params)
        .ok()
        .and_then(|p| p.update)
    else {
        return RewindStep::Other;
    };

    if is_fuigo
        && u.session_update == *REWIND_MARKER
        && let Some(target) = u.target_prompt_index
    {
        return RewindStep::Rewind { target };
    }

    let is_host_turn = u.meta.as_ref().and_then(|m| m.host_turn).unwrap_or(false);
    if !is_fuigo && !is_host_turn && u.session_update == *USER_MESSAGE_CHUNK {
        let prompt_index = u
            .meta
            .as_ref()
            .and_then(|m| m.prompt_index.map(|v| v as usize));
        return RewindStep::UserChunk { prompt_index };
    }

    RewindStep::Other
}

fn rewind_step_for_update(update: &SessionUpdate) -> RewindStep {
    if let SessionUpdate::Fuigo(n) = update
        && let crate::extensions::notification::SessionUpdate::RewindMarker {
            target_prompt_index,
            ..
        } = &n.update
    {
        return RewindStep::Rewind {
            target: *target_prompt_index,
        };
    }
    if is_acp_user_message_chunk(update) && !is_host_turn_update(update) {
        return RewindStep::UserChunk {
            prompt_index: acp_user_chunk_prompt_index(update),
        };
    }
    RewindStep::Other
}

/// Canonical raw-line rewind filter used by the initial and delta replay paths.
/// Skips parsing entirely when no rewind markers are present.
pub(crate) fn filter_rewind_lines(lines: Vec<&str>) -> Vec<&str> {
    if !lines.iter().any(|l| l.contains(&*REWIND_MARKER)) {
        return lines;
    }
    filter_rewind_by(lines, |line| rewind_step_for_line(line))
}

/// Typed equivalent of [`filter_rewind_lines`] over the same [`filter_rewind_by`] driver.
pub fn filter_rewind_updates(updates: Vec<SessionUpdate>) -> Vec<SessionUpdate> {
    let has_rewinds = updates.iter().any(|u| {
        matches!(
            u,
            SessionUpdate::Fuigo(n) if matches!(
                n.update,
                crate::extensions::notification::SessionUpdate::RewindMarker { .. }
            )
        )
    });
    if !has_rewinds {
        return updates;
    }
    filter_rewind_by(updates, rewind_step_for_update)
}

/// Strip `<fork-context>` and `<resume-context>` XML wrappers from user message chunks so replayed/exported prompts show clean text.
/// The tags are injected by the subagent fork/resume logic in `subagent.rs`.
pub fn strip_context_wrappers(update: acp::SessionUpdate) -> acp::SessionUpdate {
    let acp::SessionUpdate::UserMessageChunk(mut chunk) = update else {
        return update;
    };
    if let acp::ContentBlock::Text(ref mut t) = chunk.content {
        for tag in &["fork-context", "resume-context"] {
            let open = format!("<{tag}>");
            let close = format!("</{tag}>");
            if let Some(start) = t.text.find(&open)
                && let Some(rel_end) = t.text[start + open.len()..].find(&close)
            {
                let end = start + open.len() + rel_end;
                let remove_end = end + close.len();
                t.text = format!("{}{}", &t.text[..start], t.text[remove_end..].trim_start());
            }
        }
    }
    acp::SessionUpdate::UserMessageChunk(chunk)
}

/// The session dir's `updates.jsonl` path if it exists, else `None`.
/// Sole owner of the "does this dir have a replayable updates file" gate.
pub(crate) fn replay_updates_path_in_dir(
    session_dir: &std::path::Path,
) -> Option<std::path::PathBuf> {
    let updates_path = session_dir.join(UPDATES_FILE);
    updates_path.exists().then_some(updates_path)
}

// ============================================================================
// Selective prompt-extraction parser
// ============================================================================

/// Each event represents the minimal information extracted from one `updates.jsonl` line without deserializing the full typed notification.
#[derive(Debug, PartialEq)]
pub enum PromptExtractEvent {
    /// A text chunk from a `UserMessageChunk` ACP update.
    ///
    /// Multiple consecutive `UserTextChunk` events belong to the same user message and should be concatenated by the caller.
    /// `prompt_index` is the chunk `_meta.promptIndex` when the turn pipeline stamped one.
    UserTextChunk {
        text: String,
        prompt_index: Option<usize>,
    },

    /// A `RewindMarker` Ferrox Labs update: truncate accumulated prompts to this index.
    ///
    /// Any in-progress user message should be flushed before truncating.
    RewindTo(usize),

    /// Any other update type: the current user message (if any) has ended.
    NotUserMessage,
}

impl PromptExtractEvent {
    pub fn user_text(text: impl Into<String>) -> Self {
        Self::UserTextChunk {
            text: text.into(),
            prompt_index: None,
        }
    }

    pub fn user_text_pi(text: impl Into<String>, prompt_index: usize) -> Self {
        Self::UserTextChunk {
            text: text.into(),
            prompt_index: Some(prompt_index),
        }
    }
}

/// Iterator that streams [`PromptExtractEvent`]s from a `updates.jsonl` file.
///
/// Unlike [`UpdatesIterator`], this never builds a full `acp::SessionNotification` or `SessionNotification`.
/// Instead it uses zero-copy `serde_json` deserialization with `&RawValue` to peek at the discriminant field.
/// It only extracts the one or two fields actually needed for prompt reconstruction:
///
/// - ACP `"user_message_chunk"` → `update.content.text`
/// - Ferrox Labs `"rewind_marker"`      → `update.target_prompt_index`
/// - everything else             → [`PromptExtractEvent::NotUserMessage`]
///
/// Parse errors on individual lines are treated conservatively as `NotUserMessage`.
/// It also safely terminates any in-progress user-message accumulation.
pub struct PromptExtractIterator {
    reader: std::io::BufReader<std::fs::File>,
    line_buffer: String,
}

impl PromptExtractIterator {
    /// Returns `None` if the file does not exist.
    pub fn open(path: &std::path::Path) -> std::io::Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let file = std::fs::File::open(path)?;
        Ok(Some(Self {
            reader: std::io::BufReader::new(file),
            line_buffer: String::new(),
        }))
    }
}

impl Iterator for PromptExtractIterator {
    type Item = PromptExtractEvent;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            self.line_buffer.clear();
            match std::io::BufRead::read_line(&mut self.reader, &mut self.line_buffer) {
                Ok(0) => return None, // EOF
                Err(_) => return Some(PromptExtractEvent::NotUserMessage),
                Ok(_) => {}
            }

            let line = self.line_buffer.trim();
            if line.is_empty() {
                continue;
            }

            return Some(parse_prompt_extract_event(line));
        }
    }
}

/// Assemble accumulated user-prompt strings from a stream of [`PromptExtractEvent`]s.
///
/// Every caller, whether reading from disk or from an in-memory iterator, applies these rules identically:
///
/// - Consecutive `UserTextChunk` events are concatenated into one prompt until a non-user event or a `promptIndex` change opens a new run.
/// - Progressive counting (same as [`UserRunTurnTracker`]): every user run counts until the first `_meta.promptIndex`.
///   After that only marked runs count (mid-turn phantoms are dropped from the list).
/// - `NotUserMessage` flushes any in-progress prompt.
/// - `RewindTo(n)` flushes then truncates the list to `n` **counted** prompts.
///
/// The resulting `Vec` is the index space shared by resume `prompt_texts` and the rewind picker.
/// `prompt_index == prompts.len()` after load, matching live turn stamping (not raw user-message count).
pub fn collect_prompts_from_events(iter: impl Iterator<Item = PromptExtractEvent>) -> Vec<String> {
    let mut prompts: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_user = false;
    let mut current_run_pi: Option<usize> = None;
    let mut current_counts = false;
    let mut seen_marker = false;

    fn flush(
        prompts: &mut Vec<String>,
        current: &mut String,
        in_user: &mut bool,
        current_run_pi: &mut Option<usize>,
        current_counts: &mut bool,
    ) {
        if *in_user {
            if *current_counts {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    prompts.push(trimmed);
                }
            }
            current.clear();
            *in_user = false;
            *current_run_pi = None;
            *current_counts = false;
        }
    }

    for event in iter {
        match event {
            PromptExtractEvent::UserTextChunk { text, prompt_index } => {
                if prompt_index.is_some() {
                    seen_marker = true;
                }
                let counts = if seen_marker {
                    prompt_index.is_some()
                } else {
                    true
                };
                let new_run = if !in_user {
                    true
                } else if seen_marker || prompt_index.is_some() {
                    prompt_index != current_run_pi
                } else {
                    false
                };
                if new_run {
                    flush(
                        &mut prompts,
                        &mut current,
                        &mut in_user,
                        &mut current_run_pi,
                        &mut current_counts,
                    );
                    in_user = true;
                    current_run_pi = prompt_index;
                    current_counts = counts;
                    current.push_str(&text);
                } else {
                    current.push_str(&text);
                    if current_run_pi.is_none() && prompt_index.is_some() {
                        current_run_pi = prompt_index;
                        current_counts = true;
                    }
                }
            }
            PromptExtractEvent::RewindTo(target_index) => {
                // Flush any in-progress user message before truncating.
                // Rewinding TO prompt N keeps prompts[0..N].
                flush(
                    &mut prompts,
                    &mut current,
                    &mut in_user,
                    &mut current_run_pi,
                    &mut current_counts,
                );
                prompts.truncate(target_index);
            }
            PromptExtractEvent::NotUserMessage => {
                flush(
                    &mut prompts,
                    &mut current,
                    &mut in_user,
                    &mut current_run_pi,
                    &mut current_counts,
                );
            }
        }
    }

    flush(
        &mut prompts,
        &mut current,
        &mut in_user,
        &mut current_run_pi,
        &mut current_counts,
    );

    prompts
}
/// Extracts `ContentChunk.text` from `AgentMessageChunk` updates.
/// Capped at 100k chars total.
///
/// This collector does not honor rewind markers (unlike PromptExtractIterator).
/// Rewound-away branches may still contribute to FTS index.
pub fn collect_assistant_text(
    iter: impl Iterator<Item = io::Result<SessionUpdate>>,
) -> Vec<String> {
    const MAX_CHARS: usize = 100_000;
    let mut texts: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut chars_emitted = 0usize;

    for res in iter {
        let update = match res {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!(error = %e, "skipping malformed update in assistant text collector");
                continue;
            }
        };
        match update {
            SessionUpdate::Acp(notification) => {
                match notification.update {
                    acp::SessionUpdate::AgentMessageChunk(chunk) => {
                        if let acp::ContentBlock::Text(text_content) = chunk.content
                            && !text_content.text.is_empty()
                        {
                            // Reserve space for separator before computing budget to avoid overshoot
                            let sep_cost = usize::from(!current.is_empty());
                            let budget = MAX_CHARS
                                .saturating_sub(chars_emitted)
                                .saturating_sub(sep_cost);
                            if budget == 0 {
                                continue;
                            }
                            let text = if text_content.text.len() > budget {
                                // Truncate on a valid UTF-8 char boundary
                                let mut end = budget;
                                while end > 0 && !text_content.text.is_char_boundary(end) {
                                    end -= 1;
                                }
                                &text_content.text[..end]
                            } else {
                                &text_content.text
                            };
                            if !current.is_empty() {
                                current.push(' ');
                                chars_emitted += 1;
                            }
                            current.push_str(text);
                            chars_emitted += text.len();
                        }
                    }
                    _ => {
                        // End of assistant turn
                        if !current.is_empty() {
                            let t = current.trim().to_string();
                            if !t.is_empty() {
                                texts.push(t);
                            }
                            current.clear();
                        }
                    }
                }
            }
            SessionUpdate::Fuigo(_) => {
                if !current.is_empty() {
                    let t = current.trim().to_string();
                    if !t.is_empty() {
                        texts.push(t);
                    }
                    current.clear();
                }
            }
        }
    }
    if !current.is_empty() {
        let t = current.trim().to_string();
        if !t.is_empty() {
            texts.push(t);
        }
    }
    texts
}

/// Per the ACP data model:
/// - Tool name: from `ToolCall.title` (display name; acp::ToolCall has no .name)
/// - File paths: from `ToolCall.locations[].path` (ACP stores locations, not raw arguments)
/// - Errors: skipped (no is_error on acp::ToolCallUpdate)
///
/// Bounds:
/// - Max 200 tool calls per session
/// - Each extraction capped at 100k chars before final join
///
/// This collector does not honor rewind markers (unlike PromptExtractIterator).
/// Rewound-away branches may still contribute to FTS index.
pub fn collect_tool_metadata(iter: impl Iterator<Item = io::Result<SessionUpdate>>) -> Vec<String> {
    let mut meta: Vec<String> = Vec::new();
    let mut tool_call_count = 0usize;
    let mut chars_emitted = 0usize;

    const MAX_TOOL_CALLS: usize = 200;
    const MAX_CHARS: usize = 100_000;

    for res in iter {
        if tool_call_count >= MAX_TOOL_CALLS {
            break;
        }
        let update = match res {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!(error = %e, "skipping malformed update in tool metadata collector");
                continue;
            }
        };
        match update {
            SessionUpdate::Acp(notification) => {
                match notification.update {
                    acp::SessionUpdate::ToolCall(tc) => {
                        tool_call_count += 1;

                        // Tool name from .title (acp::ToolCall has no .name field)
                        if !tc.title.is_empty() {
                            let budget = MAX_CHARS.saturating_sub(chars_emitted);
                            if budget == 0 {
                                continue;
                            }
                            let truncated = &tc.title[..tc.title.len().min(budget)];
                            chars_emitted += truncated.len();
                            meta.push(truncated.to_string());
                        }

                        // File paths from locations[].path
                        for loc in &tc.locations {
                            if let Some(path_str) = loc.path.to_str()
                                && !path_str.is_empty()
                            {
                                let budget = MAX_CHARS.saturating_sub(chars_emitted);
                                if budget == 0 {
                                    continue;
                                }
                                let truncated = &path_str[..path_str.len().min(budget)];
                                meta.push(truncated.to_string());
                                chars_emitted += truncated.len();
                            }
                        }
                    }
                    acp::SessionUpdate::ToolCallUpdate(_) => {
                        // Tool results come as ToolCallUpdate; no is_error field available
                    }
                    _ => {}
                }
            }
            SessionUpdate::Fuigo(_) => {}
        }
    }
    meta
}

// ---------------------------------------------------------------------------
// Selective serde structs: only the fields we care about
// ---------------------------------------------------------------------------

/// Peek inside ACP or Ferrox Labs `params` to read the `update.sessionUpdate` tag and any fields relevant to `user_message_chunk` or `rewind_marker`.
///
/// Works for both method types because both use the same `update.sessionUpdate` discriminant key in the params JSON.
#[derive(serde::Deserialize)]
struct ParamsPeek<'a> {
    #[serde(borrow)]
    update: UpdatePeek<'a>,
}

#[derive(serde::Deserialize)]
struct UpdatePeek<'a> {
    #[serde(rename = "sessionUpdate")]
    session_update: &'a str,
    /// Present only for `user_message_chunk`.
    #[serde(borrow, default)]
    content: Option<ContentPeek<'a>>,
    /// Chunk `_meta` on ACP updates (carries `promptIndex` for real turns).
    #[serde(default, rename = "_meta")]
    meta: Option<RawChunkMetaPeek>,
    /// Present only for `rewind_marker`.
    target_prompt_index: Option<usize>,
}

/// Selective peek at a `user_message_chunk` content object.
///
/// Shared with the search collectors in [`search`].
/// The peeked fields and their escape-tolerance therefore cannot drift between the prompt-extraction and indexing paths.
#[derive(serde::Deserialize)]
pub(crate) struct ContentPeek<'a> {
    #[serde(rename = "type", default)]
    pub content_type: Option<&'a str>,
    // `Cow`, not `&str`: serde cannot borrow from JSON strings containing escapes, and the resulting parse error would drop the whole prompt
    #[serde(borrow, default)]
    pub text: Option<std::borrow::Cow<'a, str>>,
    #[serde(rename = "_meta", default)]
    pub meta: Option<ContentMetaPeek<'a>>,
}

#[derive(serde::Deserialize)]
pub(crate) struct ContentMetaPeek<'a> {
    #[serde(borrow, default)]
    pub bash_command: Option<std::borrow::Cow<'a, str>>,
}

/// Parse one `updates.jsonl` line into a [`PromptExtractEvent`].
///
/// Always returns an event: `NotUserMessage` for every line that is not a user-message chunk or rewind marker (including unparseable ones).
/// So an in-progress prompt is always flushed conservatively.
///
/// Fast path: only those two kinds can produce a non-`NotUserMessage` event, and their discriminant appears verbatim.
/// So a cheap substring pre-check skips the serde peeks for the vast majority of lines.
/// A line merely embedding the discriminant in its content still falls through to the full parse.
pub(crate) fn parse_prompt_extract_event(line: &str) -> PromptExtractEvent {
    if !line.contains(&*USER_MESSAGE_CHUNK) && !line.contains(&*REWIND_MARKER) {
        return PromptExtractEvent::NotUserMessage;
    }

    // Step 1: try to extract the envelope (method and raw params)
    let (raw_params, is_fuigo) = if let Ok(env) = serde_json::from_str::<RawLinePeek<'_>>(line) {
        let raw = env.params.map(|p| p.get()).unwrap_or(line);
        let fuigo = env.method == Some(FUIGO_SESSION_UPDATE_METHOD);
        (raw, fuigo)
    } else {
        // Not a valid envelope, so try legacy format: the line IS the params
        (line, false)
    };

    // Step 2: parse the discriminant and relevant payload fields in one pass.
    let Ok(peek) = serde_json::from_str::<ParamsPeek<'_>>(raw_params) else {
        // Cannot determine update type, so treat conservatively
        return PromptExtractEvent::NotUserMessage;
    };

    let tag = peek.update.session_update;

    if !is_fuigo && tag == *USER_MESSAGE_CHUNK {
        if let Some(content) = peek.update.content
            && content.content_type == Some("text")
            && let Some(text) = content.text
        {
            if content
                .meta
                .as_ref()
                .is_some_and(|m| m.bash_command.is_some())
            {
                return PromptExtractEvent::NotUserMessage;
            }
            if peek
                .update
                .meta
                .as_ref()
                .is_some_and(|m| m.host_turn == Some(true))
            {
                return PromptExtractEvent::NotUserMessage;
            }
            let prompt_index = peek
                .update
                .meta
                .as_ref()
                .and_then(|m| m.prompt_index.map(|v| v as usize));
            return PromptExtractEvent::UserTextChunk {
                text: text.into_owned(),
                prompt_index,
            };
        }
        // user_message_chunk with non-text content (e.g., image) still ends any in-progress user message
        return PromptExtractEvent::NotUserMessage;
    }

    if is_fuigo && tag == *REWIND_MARKER {
        if let Some(idx) = peek.update.target_prompt_index {
            return PromptExtractEvent::RewindTo(idx);
        }
        // Malformed rewind_marker: treat conservatively (flush, no truncate).
        return PromptExtractEvent::NotUserMessage;
    }

    PromptExtractEvent::NotUserMessage
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// P154: the Windows beneath-open holds every folder, so none can be swapped for a link before the file opens.
    #[cfg(windows)]
    mod open_beneath_windows {
        use super::*;

        fn make_dir_link(link: &Path, target: &Path) {
            if std::os::windows::fs::symlink_dir(target, link).is_ok() {
                return;
            }
            // No symlink privilege: a junction needs none.
            let status = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .output()
                .expect("run cmd mklink");
            assert!(status.status.success(), "mklink /J failed: {status:?}");
        }

        // kernel32 is linked by std; these two calls build and run the in-place conversion the audit named.
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn DeviceIoControl(
                device: *mut std::ffi::c_void,
                code: u32,
                input: *const std::ffi::c_void,
                input_len: u32,
                output: *mut std::ffi::c_void,
                output_len: u32,
                returned: *mut u32,
                overlapped: *mut std::ffi::c_void,
            ) -> i32;
        }

        /// Try to turn the EMPTY folder `victim` into a junction to `target` in place, through a second handle
        /// (`FSCTL_SET_REPARSE_POINT`), with each access mask that could allow it. True when one of them worked.
        fn convert_in_place(victim: &Path, target: &Path) -> bool {
            use std::os::windows::fs::OpenOptionsExt as _;
            use std::os::windows::io::AsRawHandle as _;
            use std::os::windows::ffi::OsStrExt as _;
            // A temp dir path is plain `C:\...`; the NT form of it starts `\??\`. Lossless: a name may hold an
            // isolated surrogate.
            let substitute: Vec<u16> = "\\??\\".encode_utf16().chain(target.as_os_str().encode_wide()).collect();
            let sub_bytes = (substitute.len() * 2) as u16;
            let data_len = 8 + sub_bytes + 2 + 2;
            let mut buffer: Vec<u8> = Vec::new();
            buffer.extend_from_slice(&0xA000_0003u32.to_le_bytes()); // IO_REPARSE_TAG_MOUNT_POINT
            buffer.extend_from_slice(&data_len.to_le_bytes());
            buffer.extend_from_slice(&0u16.to_le_bytes());
            buffer.extend_from_slice(&0u16.to_le_bytes()); // substitute offset
            buffer.extend_from_slice(&sub_bytes.to_le_bytes());
            buffer.extend_from_slice(&(sub_bytes + 2).to_le_bytes()); // print offset
            buffer.extend_from_slice(&0u16.to_le_bytes()); // print length
            for unit in &substitute {
                buffer.extend_from_slice(&unit.to_le_bytes());
            }
            buffer.extend_from_slice(&[0, 0, 0, 0]);
            // FILE_WRITE_DATA (= FILE_ADD_FILE on a folder), FILE_WRITE_ATTRIBUTES, and both.
            for access in [0x2u32, 0x100, 0x102] {
                let Ok(handle) = std::fs::OpenOptions::new()
                    .access_mode(access)
                    .share_mode(0x7)
                    .custom_flags(0x0200_0000 | 0x0020_0000)
                    .open(victim)
                else {
                    continue;
                };
                let mut returned = 0u32;
                // SAFETY: a live handle and a fully built REPARSE_DATA_BUFFER; no output buffer is asked for.
                let ok = unsafe {
                    DeviceIoControl(
                        handle.as_raw_handle(),
                        0x0009_00A4, // FSCTL_SET_REPARSE_POINT
                        buffer.as_ptr().cast(),
                        buffer.len() as u32,
                        std::ptr::null_mut(),
                        0,
                        &mut returned,
                        std::ptr::null_mut(),
                    )
                };
                if ok != 0 {
                    return true;
                }
            }
            false
        }

        #[test]
        fn a_held_folder_cannot_be_turned_into_a_junction_before_the_file_opens() {
            let tmp = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            std::fs::write(outside.path().join("f.txt"), b"secret").unwrap();
            std::fs::create_dir_all(tmp.path().join("a").join("b")).unwrap();
            let parts = [std::ffi::OsStr::new("a"), std::ffi::OsStr::new("b")];
            let (held, dir) = hold_folders_beneath_windows(tmp.path(), &parts).expect("holds");
            let converted = convert_in_place(&tmp.path().join("a").join("b"), outside.path());
            eprintln!("P154 in-place conversion succeeded: {converted}");
            // Whether or not the conversion got through, the outside file must not be read.
            if let Ok(mut file) = open_leaf_beneath_windows(&held, &dir, std::ffi::OsStr::new("f.txt")) {
                let mut text = String::new();
                io::Read::read_to_string(&mut file, &mut text).unwrap();
                assert_ne!(text, "secret", "the leaf was read through a junction made after the check");
            }
        }

        #[test]
        fn a_folder_turned_into_a_junction_between_two_folder_opens_is_refused() {
            let tmp = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            std::fs::create_dir(outside.path().join("b")).unwrap();
            std::fs::write(outside.path().join("b").join("f.txt"), b"secret").unwrap();
            std::fs::create_dir(tmp.path().join("a")).unwrap(); // empty, so it can be converted in place
            let parts = [std::ffi::OsStr::new("a"), std::ffi::OsStr::new("b")];
            let mut converted = false;
            let result = hold_folders_beneath_windows_with(tmp.path(), &parts, &mut |index| {
                if index == 0 {
                    converted = convert_in_place(&tmp.path().join("a"), outside.path());
                }
            });
            eprintln!("P154 mid-walk conversion succeeded: {converted}");
            if converted {
                assert!(
                    matches!(result, Err(BeneathRefusal::Refused(_))),
                    "folders below a junction made mid-walk were accepted"
                );
            } else {
                assert!(result.is_err());
            }
        }

        fn wide(text: &str) -> Vec<u16> {
            text.encode_utf16().collect()
        }

        #[test]
        fn a_sibling_that_differs_only_in_case_is_not_the_folder() {
            let name = std::ffi::OsStr::new("f.txt");
            let ok = |parent: &str, child: &str| is_direct_child_windows(&wide(parent), &wide(child), name);
            assert!(ok(r"\\?\C:\s\session\ck", r"\\?\C:\s\session\ck\f.txt"));
            // A case-sensitive folder can hold `session` and `SESSION` apart; a read from the other one is refused.
            assert!(!ok(r"\\?\C:\s\session\ck", r"\\?\C:\s\SESSION\ck\f.txt"));
            // Not nested, and not the name asked for.
            assert!(!ok(r"\\?\C:\s\ck", r"\\?\C:\s\ck\x\f.txt"));
            assert!(!ok(r"\\?\C:\s\ck", r"\\?\C:\s\ck\g.txt"));
        }

        #[test]
        fn folders_whose_names_differ_only_in_an_isolated_surrogate_are_not_the_same() {
            let name = std::ffi::OsStr::new("f.txt");
            let mut with_lone = wide(r"\\?\C:\s\");
            with_lone.push(0xD800);
            with_lone.extend(wide(r"\id\ck"));
            let with_replacement = wide("\\\\?\\C:\\s\\\u{FFFD}\\id\\ck");
            let mut child = with_lone.clone();
            child.extend(wide(r"\f.txt"));
            assert!(is_direct_child_windows(&with_lone, &child, name));
            assert!(!is_direct_child_windows(&with_replacement, &child, name));
        }

        #[test]
        fn a_folder_converted_to_a_junction_onto_a_lookalike_name_is_refused() {
            use std::os::windows::ffi::OsStringExt as _;
            let tmp = tempfile::tempdir().unwrap();
            // `<U+FFFD>/id/ck` is the trusted folder; `<D800>/id/ck` is outside and holds the same-named file.
            let replacement = tmp.path().join("\u{FFFD}").join("id");
            let lone = tmp.path().join(std::ffi::OsString::from_wide(&[0xD800])).join("id");
            std::fs::create_dir_all(replacement.join("ck")).unwrap(); // empty: can be converted in place
            std::fs::create_dir_all(lone.join("ck")).unwrap();
            std::fs::write(lone.join("ck").join("f.txt"), b"secret").unwrap();
            let parts = [std::ffi::OsStr::new("ck")];
            let (held, dir) = hold_folders_beneath_windows(&replacement, &parts).expect("holds");
            let converted = convert_in_place(&replacement.join("ck"), &lone.join("ck"));
            eprintln!("P154 lookalike conversion succeeded: {converted}");
            if let Ok(mut file) = open_leaf_beneath_windows(&held, &dir, std::ffi::OsStr::new("f.txt")) {
                let mut text = String::new();
                io::Read::read_to_string(&mut file, &mut text).unwrap();
                assert_ne!(text, "secret", "the leaf was read from a lookalike folder");
            }
        }

        #[test]
        fn plain_folders_and_a_regular_file_open() {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(tmp.path().join("a").join("b")).unwrap();
            std::fs::write(tmp.path().join("a").join("b").join("f.txt"), b"hello").unwrap();
            let mut file = open_beneath_nofollow(tmp.path(), Path::new("a/b/f.txt")).expect("opens");
            let mut text = String::new();
            io::Read::read_to_string(&mut file, &mut text).unwrap();
            assert_eq!(text, "hello");
        }

        #[test]
        fn a_folder_that_is_a_symlink_or_junction_is_refused() {
            let tmp = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            std::fs::write(outside.path().join("f.txt"), b"secret").unwrap();
            make_dir_link(&tmp.path().join("a"), outside.path());
            assert!(matches!(
                open_beneath_nofollow(tmp.path(), Path::new("a/f.txt")),
                Err(BeneathRefusal::Refused(_))
            ));
            // The same below a real folder.
            std::fs::create_dir(tmp.path().join("real")).unwrap();
            make_dir_link(&tmp.path().join("real").join("b"), outside.path());
            assert!(matches!(
                open_beneath_nofollow(tmp.path(), Path::new("real/b/f.txt")),
                Err(BeneathRefusal::Refused(_))
            ));
        }

        #[test]
        fn a_file_that_is_a_symlink_is_refused() {
            let tmp = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            std::fs::write(outside.path().join("f.txt"), b"secret").unwrap();
            std::os::windows::fs::symlink_file(outside.path().join("f.txt"), tmp.path().join("l.txt"))
                .expect("create a file symlink (needs the symlink privilege)");
            assert!(matches!(
                open_beneath_nofollow(tmp.path(), Path::new("l.txt")),
                Err(BeneathRefusal::Refused(_))
            ));
        }

        #[test]
        fn a_held_folder_cannot_be_renamed_or_swapped_until_released() {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(tmp.path().join("a").join("b")).unwrap();
            let parts = [std::ffi::OsStr::new("a"), std::ffi::OsStr::new("b")];
            let (held, dir) = hold_folders_beneath_windows(tmp.path(), &parts).expect("holds");
            assert_eq!(held.len(), 2);
            assert_eq!(dir, tmp.path().join("a").join("b"));
            assert!(std::fs::rename(tmp.path().join("a"), tmp.path().join("a-moved")).is_err());
            assert!(std::fs::rename(tmp.path().join("a").join("b"), tmp.path().join("a").join("b-moved")).is_err());
            assert!(std::fs::remove_dir(tmp.path().join("a").join("b")).is_err());
            drop(held);
            std::fs::rename(tmp.path().join("a"), tmp.path().join("a-moved")).expect("free after the handles drop");
        }
    }

    mod rebuild_interjections {
        use super::*;
        use crate::sampling::{ContentPart, ConversationItem, SyntheticReason};
        use std::sync::Arc;

        fn text_chunk(text: &str) -> acp::ContentChunk {
            acp::ContentChunk::new(acp::ContentBlock::Text(acp::TextContent::new(text)))
        }

        fn user(text: &str) -> acp::SessionUpdate {
            acp::SessionUpdate::UserMessageChunk(text_chunk(text))
        }

        fn agent(text: &str) -> acp::SessionUpdate {
            acp::SessionUpdate::AgentMessageChunk(text_chunk(text))
        }

        /// A persisted interjection chunk as the shell writes it: framed text plus the `interjection` flag.
        fn interjection(typed: &str) -> acp::SessionUpdate {
            let mut meta = serde_json::Map::new();
            meta.insert(INTERJECTION_META_KEY.into(), serde_json::json!(true));
            acp::SessionUpdate::UserMessageChunk(
                text_chunk(&fuigo_interjection_core::format_interjection(
                    typed.to_string(),
                ))
                .meta(Some(meta)),
            )
        }

        fn tool_call(id: &str) -> acp::SessionUpdate {
            acp::SessionUpdate::ToolCall(acp::ToolCall::new(acp::ToolCallId::new(id), "run"))
        }

        fn tool_done(id: &str) -> acp::SessionUpdate {
            acp::SessionUpdate::ToolCallUpdate(acp::ToolCallUpdate::new(
                acp::ToolCallId::new(id),
                acp::ToolCallUpdateFields::new().status(Some(acp::ToolCallStatus::Completed)),
            ))
        }

        fn rebuild(updates: Vec<acp::SessionUpdate>) -> Vec<ConversationItem> {
            let sid = acp::SessionId::new(Arc::from("s"));
            let dir = tempfile::tempdir().unwrap();
            let envelopes: Vec<SessionUpdateEnvelope> = updates
                .into_iter()
                .map(|update| {
                    SessionUpdate::Acp(Box::new(acp::SessionNotification::new(sid.clone(), update)))
                })
                .map(|u| SessionUpdateEnvelope::from_update(&u).unwrap())
                .collect();
            write_jsonl_atomic(&dir.path().join(UPDATES_FILE), &envelopes).unwrap();
            chat_rebuild::rebuild_chat_history(dir.path()).unwrap();
            std::fs::read_to_string(dir.path().join(CHAT_HISTORY_FILE))
                .unwrap()
                .lines()
                .filter(|l| !l.is_empty())
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        }

        /// `(text, is_interjection)` of every user item, in order.
        fn users(items: &[ConversationItem]) -> Vec<(String, bool)> {
            items
                .iter()
                .filter_map(|item| match item {
                    ConversationItem::User(u) => Some((
                        u.content
                            .iter()
                            .filter_map(|p| match p {
                                ContentPart::Text { text } => Some(text.as_ref()),
                                _ => None,
                            })
                            .collect(),
                        u.synthetic_reason == Some(SyntheticReason::Interjection),
                    )),
                    _ => None,
                })
                .collect()
        }

        fn framed(typed: &str) -> String {
            fuigo_interjection_core::format_interjection(typed.to_string())
        }

        #[test]
        fn interjection_keeps_persisted_frame_and_is_tagged() {
            let items = rebuild(vec![
                user("start the build"),
                agent("building"),
                interjection("ok run the stop for me"),
                agent("stopping"),
            ]);
            assert_eq!(
                users(&items),
                [
                    ("start the build".to_string(), false),
                    (framed("ok run the stop for me"), true),
                ]
            );
        }

        /// Tool-only first response: no agent text closes the prompt run before the interjection lands.
        #[test]
        fn interjection_adjacent_to_prompt_run_is_a_separate_item() {
            let items = rebuild(vec![
                user("start the build"),
                tool_call("c1"),
                tool_done("c1"),
                interjection("ok run the stop for me"),
                agent("stopping"),
            ]);
            assert_eq!(
                users(&items),
                [
                    ("start the build".to_string(), false),
                    (framed("ok run the stop for me"), true),
                ]
            );
        }

        /// A batch drain pushes one item per interjection; a following prompt echo must not join the last one.
        #[test]
        fn consecutive_interjections_stay_distinct_and_next_prompt_is_plain() {
            let items = rebuild(vec![
                user("start"),
                agent("working"),
                interjection("first"),
                interjection("second"),
                user("next prompt"),
                agent("done"),
            ]);
            assert_eq!(
                users(&items),
                [
                    ("start".to_string(), false),
                    (framed("first"), true),
                    (framed("second"), true),
                    ("next prompt".to_string(), false),
                ]
            );
        }
    }

    #[test]
    fn chunk_meta_flag_requires_literal_true() {
        let chunk = |meta: Option<serde_json::Value>| {
            acp::ContentChunk::new(acp::ContentBlock::Text(acp::TextContent::new("x")))
                .meta(meta.map(|m| m.as_object().cloned().unwrap()))
        };
        assert!(chunk_meta_flag(
            &chunk(Some(serde_json::json!({"k": true}))),
            "k"
        ));
        assert!(!chunk_meta_flag(
            &chunk(Some(serde_json::json!({"k": false}))),
            "k"
        ));
        assert!(!chunk_meta_flag(
            &chunk(Some(serde_json::json!({"k": "true"}))),
            "k"
        ));
        assert!(!chunk_meta_flag(
            &chunk(Some(serde_json::json!({"k": 1}))),
            "k"
        ));
        assert!(!chunk_meta_flag(
            &chunk(Some(serde_json::json!({"other": true}))),
            "k"
        ));
        assert!(!chunk_meta_flag(&chunk(None), "k"));
    }

    #[test]
    fn atomic_write_runs_file_sync_barrier_before_rename_replaces_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("summary.json");
        std::fs::write(&target, b"old").unwrap();

        let target_bytes_at_sync = std::cell::RefCell::new(Vec::new());
        write_bytes_atomic_with(
            &target,
            b"new",
            |_| {
                *target_bytes_at_sync.borrow_mut() = std::fs::read(&target).unwrap();
                Ok(())
            },
            || Ok(()),
        )
        .unwrap();

        assert_eq!(
            target_bytes_at_sync.borrow().as_slice(),
            b"old",
            "the sync barrier must run on the temp file before the rename commits"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
    }

    #[test]
    fn atomic_write_syncs_parent_directory_after_the_rename_commits_a_create() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("summary.json");

        let events = std::cell::RefCell::new(Vec::new());
        write_bytes_atomic_with(
            &target,
            b"new",
            |_| {
                events.borrow_mut().push("sync_file");
                Ok(())
            },
            || {
                events.borrow_mut().push(
                    if std::fs::read(&target).is_ok_and(|bytes| bytes == b"new") {
                        "sync_parent_after_rename"
                    } else {
                        "sync_parent_before_rename"
                    },
                );
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(
            events.borrow().as_slice(),
            ["sync_file", "sync_parent_after_rename"],
            "the parent-directory sync must run after the rename commits the new entry"
        );
    }

    #[test]
    fn atomic_write_syncs_parent_directory_after_rename_even_when_replacing() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("summary.json");
        std::fs::write(&target, b"old").unwrap();

        let parent_syncs = std::cell::Cell::new(0);
        write_bytes_atomic_with(
            &target,
            b"new",
            |_| Ok(()),
            || {
                parent_syncs.set(parent_syncs.get() + 1);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(
            parent_syncs.get(),
            1,
            "a retry after a failed create-barrier would otherwise skip the parent sync"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
    }

    #[test]
    fn atomic_write_retries_parent_sync_after_a_failed_create_barrier() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("summary.json");

        let first = write_bytes_atomic_with(
            &target,
            b"new",
            |_| Ok(()),
            || Err(io::Error::other("directory barrier failed")),
        );
        assert_eq!(first.unwrap_err().to_string(), "directory barrier failed");
        assert_eq!(std::fs::read(&target).unwrap(), b"new");

        let parent_syncs = std::cell::Cell::new(0);
        write_bytes_atomic_with(
            &target,
            b"newer",
            |_| Ok(()),
            || {
                parent_syncs.set(parent_syncs.get() + 1);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(parent_syncs.get(), 1);
        assert_eq!(std::fs::read(&target).unwrap(), b"newer");
    }

    #[test]
    fn create_dir_all_durable_syncs_every_directory_gaining_an_entry_on_a_fresh_chain() {
        let root = tempfile::tempdir().unwrap();
        let group = root.path().join("sessions").join("cwd");
        let session = group.join("session-id");

        let synced = std::cell::RefCell::new(Vec::new());
        create_dir_all_durable_with(
            &session,
            |dir| std::fs::create_dir_all(dir),
            |dir| {
                synced.borrow_mut().push(dir.to_path_buf());
                Ok(())
            },
        )
        .unwrap();

        assert!(session.is_dir());
        assert_eq!(
            synced.borrow().as_slice(),
            [
                group.clone(),
                root.path().join("sessions"),
                root.path().to_path_buf()
            ],
            "each directory holding a newly created entry must be synced, up to the first pre-existing ancestor"
        );
    }

    #[cfg(unix)]
    #[test]
    fn create_dir_all_durable_fresh_create_skips_the_filesystem_root() {
        let unique = format!("fuigo-durable-create-{}", uuid::Uuid::now_v7());
        let top = Path::new("/").join(&unique);
        let dir = top.join("sessions").join("id");
        assert!(
            !top.exists(),
            "test unique top-level path must not already exist: {}",
            top.display()
        );

        let synced = std::cell::RefCell::new(Vec::new());
        create_dir_all_durable_with(
            &dir,
            |_dir| Ok(()),
            |path| {
                synced.borrow_mut().push(path.to_path_buf());
                Ok(())
            },
        )
        .unwrap();

        let synced = synced.borrow();
        assert!(
            !synced.iter().any(|path| is_fs_root(path)),
            "a fresh create whose chain reaches a top-level directory must not fsync /, got {synced:?}"
        );
        assert!(
            synced.iter().any(|path| path == &top),
            "the new top-level directory itself must still be synced, got {synced:?}"
        );
        assert!(
            synced.iter().any(|path| path == &top.join("sessions")),
            "intermediate parents that gained an entry must still be synced, got {synced:?}"
        );
    }

    #[test]
    fn create_dir_all_durable_resyncs_ancestors_when_an_empty_chain_already_exists() {
        let root = tempfile::tempdir().unwrap();
        let session = root.path().join("sessions").join("cwd").join("session-id");
        std::fs::create_dir_all(&session).unwrap();

        let synced = std::cell::RefCell::new(Vec::new());
        create_dir_all_durable_with(
            &session,
            |dir| std::fs::create_dir_all(dir),
            |dir| {
                synced.borrow_mut().push(dir.to_path_buf());
                Ok(())
            },
        )
        .unwrap();

        let synced = synced.borrow();
        assert!(
            synced.iter().any(|path| path == session.parent().unwrap()),
            "a retry must re-sync the parent that holds the session direntry, got {synced:?}"
        );
        assert!(
            !synced.iter().any(|path| is_fs_root(path)),
            "must not fsync the filesystem root, got {synced:?}"
        );
    }

    #[test]
    fn create_dir_all_durable_occupied_existing_chain_pays_no_sync() {
        let root = tempfile::tempdir().unwrap();
        let session = root.path().join("sessions").join("cwd").join("session-id");
        std::fs::create_dir_all(&session).unwrap();
        std::fs::write(session.join("summary.json"), b"{}").unwrap();

        let synced = std::cell::RefCell::new(Vec::new());
        create_dir_all_durable_with(
            &session,
            |dir| std::fs::create_dir_all(dir),
            |dir| {
                synced.borrow_mut().push(dir.to_path_buf());
                Ok(())
            },
        )
        .unwrap();

        assert!(
            synced.borrow().is_empty(),
            "resume of a populated session dir must not fsync ancestors, got {:?}",
            synced.borrow()
        );
    }

    #[test]
    fn create_dir_all_durable_retries_ancestor_syncs_after_a_failed_create_barrier() {
        let root = tempfile::tempdir().unwrap();
        let session = root.path().join("sessions").join("cwd").join("session-id");

        let first = create_dir_all_durable_with(
            &session,
            |dir| std::fs::create_dir_all(dir),
            |_| Err(io::Error::other("directory barrier failed")),
        );
        assert_eq!(first.unwrap_err().to_string(), "directory barrier failed");
        assert!(session.is_dir());

        let synced = std::cell::RefCell::new(Vec::new());
        create_dir_all_durable_with(
            &session,
            |dir| std::fs::create_dir_all(dir),
            |dir| {
                synced.borrow_mut().push(dir.to_path_buf());
                Ok(())
            },
        )
        .unwrap();

        assert!(
            synced
                .borrow()
                .iter()
                .any(|path| path == session.parent().unwrap()),
            "a retry after create+failed sync must still durableize the new direntry"
        );
    }

    #[test]
    fn atomic_write_parent_sync_error_propagates_and_keeps_the_committed_rename() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("summary.json");

        let error = write_bytes_atomic_with(
            &target,
            b"new",
            |_| Ok(()),
            || Err(io::Error::other("directory barrier failed")),
        )
        .unwrap_err();

        assert_eq!(error.to_string(), "directory barrier failed");
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"new",
            "a failed directory barrier reports the error but never unwinds the committed rename"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn atomic_write_sync_barrier_error_propagates_keeps_target_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("summary.json");
        std::fs::write(&target, b"old").unwrap();

        let error = write_bytes_atomic_with(
            &target,
            b"new",
            |_| Err(io::Error::other("file barrier failed")),
            || Ok(()),
        )
        .unwrap_err();

        assert_eq!(error.to_string(), "file barrier failed");
        assert_eq!(std::fs::read(&target).unwrap(), b"old");
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "a failed sync must remove its temp file"
        );
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Wrap an ACP notification as the envelope stored in updates.jsonl.
    fn acp_envelope(session_update_json: &str) -> String {
        format!(
            r#"{{"timestamp":1,"method":"session/update","params":{{"sessionId":"s","update":{session_update_json}}}}}"#
        )
    }

    /// Wrap a Ferrox Labs notification as the envelope stored in updates.jsonl.
    fn fuigo_envelope(session_update_json: &str) -> String {
        format!(
            r#"{{"timestamp":1,"method":"_fuigo/session/update","params":{{"sessionId":"s","update":{session_update_json}}}}}"#
        )
    }

    // ── parse_prompt_extract_event unit tests ─────────────────────────────────

    #[test]
    fn acp_user_text_chunk_yields_user_text() {
        let line = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"hello"}}"#,
        );
        assert_eq!(
            parse_prompt_extract_event(&line),
            PromptExtractEvent::user_text("hello")
        );
    }

    #[test]
    fn acp_user_text_chunk_with_json_escapes_yields_user_text() {
        // Escaped JSON strings cannot be borrowed as &str; a regression to a borrowed peek field would drop this prompt from extraction
        let line = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"multi\nline \"quoted\" caf\u00e9"}}"#,
        );
        assert_eq!(
            parse_prompt_extract_event(&line),
            PromptExtractEvent::user_text("multi\nline \"quoted\" caf\u{e9}")
        );
        // An escaped bash command now parses too and must be excluded by the bash_command predicate (it used to be excluded by the parse failure)
        let bash = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"! echo \"hi\"","_meta":{"bash_command":"echo \"hi\""}}}"#,
        );
        assert_eq!(
            parse_prompt_extract_event(&bash),
            PromptExtractEvent::NotUserMessage
        );
    }

    #[test]
    fn acp_agent_message_chunk_yields_not_user() {
        let line = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"reply"}}"#,
        );
        assert_eq!(
            parse_prompt_extract_event(&line),
            PromptExtractEvent::NotUserMessage
        );
    }

    #[test]
    fn acp_tool_result_yields_not_user() {
        let line = acp_envelope(
            r#"{"sessionUpdate":"tool_result","toolCallId":"c1","content":[{"type":"text","text":"big output"}]}"#,
        );
        assert_eq!(
            parse_prompt_extract_event(&line),
            PromptExtractEvent::NotUserMessage
        );
    }

    #[test]
    fn fuigo_rewind_marker_yields_rewind_to() {
        let line = fuigo_envelope(
            r#"{"sessionUpdate":"rewind_marker","target_prompt_index":3,"created_at":"2024-01-01"}"#,
        );
        assert_eq!(
            parse_prompt_extract_event(&line),
            PromptExtractEvent::RewindTo(3)
        );
    }

    #[test]
    fn fuigo_rewind_to_zero_yields_rewind_to_zero() {
        let line = fuigo_envelope(
            r#"{"sessionUpdate":"rewind_marker","target_prompt_index":0,"created_at":"2024-01-01"}"#,
        );
        assert_eq!(
            parse_prompt_extract_event(&line),
            PromptExtractEvent::RewindTo(0)
        );
    }

    #[test]
    fn fuigo_diff_review_yields_not_user() {
        let line = fuigo_envelope(r#"{"sessionUpdate":"diff_review","content":[]}"#);
        assert_eq!(
            parse_prompt_extract_event(&line),
            PromptExtractEvent::NotUserMessage
        );
    }

    #[test]
    fn acp_user_message_chunk_image_yields_not_user() {
        let line = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"image_url","url":"data:image/png;base64,abc"}}"#,
        );
        assert_eq!(
            parse_prompt_extract_event(&line),
            PromptExtractEvent::NotUserMessage
        );
    }

    #[test]
    fn malformed_json_yields_not_user() {
        assert_eq!(
            parse_prompt_extract_event("not json at all!!!"),
            PromptExtractEvent::NotUserMessage
        );
    }

    /// Empty string: the iterator skips blanks, but a direct call must still classify conservatively.
    #[test]
    fn empty_string_yields_not_user() {
        assert_eq!(
            parse_prompt_extract_event(""),
            PromptExtractEvent::NotUserMessage
        );
    }

    #[test]
    fn unknown_json_object_yields_not_user() {
        assert_eq!(
            parse_prompt_extract_event(r#"{"foo":"bar"}"#),
            PromptExtractEvent::NotUserMessage
        );
    }

    /// Old sessions wrote `{"sessionId":"s","update":{"sessionUpdate":"user_message_chunk",...}}` directly without the `method`/`params` envelope.
    #[test]
    fn legacy_format_user_message_chunk() {
        let line = r#"{"sessionId":"s","update":{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"legacy prompt"}}}"#;
        assert_eq!(
            parse_prompt_extract_event(line),
            PromptExtractEvent::user_text("legacy prompt")
        );
    }

    #[test]
    fn legacy_format_non_user_update() {
        let line = r#"{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"hi"}}}"#;
        assert_eq!(
            parse_prompt_extract_event(line),
            PromptExtractEvent::NotUserMessage
        );
    }

    // ── PromptExtractIterator integration tests via tempfile ──────────────────

    fn write_updates_file(lines: &[&str]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for line in lines {
            writeln!(f, "{line}").unwrap();
        }
        f
    }

    fn collect_events(path: &std::path::Path) -> Vec<PromptExtractEvent> {
        PromptExtractIterator::open(path)
            .unwrap()
            .unwrap()
            .collect()
    }

    #[test]
    fn iterator_single_user_prompt() {
        let chunk = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"hello world"}}"#,
        );
        let other = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"reply"}}"#,
        );
        let f = write_updates_file(&[&chunk, &other]);

        let events = collect_events(f.path());
        assert_eq!(events[0], PromptExtractEvent::user_text("hello world"));
        assert_eq!(events[1], PromptExtractEvent::NotUserMessage);
    }

    #[test]
    fn iterator_multi_chunk_user_message() {
        let c1 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"part1 "}}"#,
        );
        let c2 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"part2"}}"#,
        );
        let end = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"hi"}}"#,
        );
        let f = write_updates_file(&[&c1, &c2, &end]);

        let events = collect_events(f.path());
        assert_eq!(events[0], PromptExtractEvent::user_text("part1 "));
        assert_eq!(events[1], PromptExtractEvent::user_text("part2"));
        assert_eq!(events[2], PromptExtractEvent::NotUserMessage);
    }

    #[test]
    fn iterator_rewind_marker_truncates() {
        let chunk = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"p1"}}"#,
        );
        let end = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"a1"}}"#,
        );
        let rewind = fuigo_envelope(
            r#"{"sessionUpdate":"rewind_marker","target_prompt_index":0,"created_at":"2024-01-01"}"#,
        );
        let f = write_updates_file(&[&chunk, &end, &rewind]);

        let events = collect_events(f.path());
        assert_eq!(events[0], PromptExtractEvent::user_text("p1"));
        assert_eq!(events[1], PromptExtractEvent::NotUserMessage);
        assert_eq!(events[2], PromptExtractEvent::RewindTo(0));
    }

    #[test]
    fn iterator_skips_blank_lines() {
        let chunk = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"hello"}}"#,
        );
        let f = write_updates_file(&["", "   ", &chunk, ""]);

        let events = collect_events(f.path());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], PromptExtractEvent::user_text("hello"));
    }

    #[test]
    fn iterator_malformed_line_does_not_panic() {
        let bad = "this is not json !!!";
        let good = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"ok"}}"#,
        );
        let f = write_updates_file(&[bad, &good]);

        let events = collect_events(f.path());
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], PromptExtractEvent::NotUserMessage);
        assert_eq!(events[1], PromptExtractEvent::user_text("ok"));
    }

    #[test]
    fn iterator_nonexistent_file_returns_none() {
        let result =
            PromptExtractIterator::open(std::path::Path::new("/nonexistent/updates.jsonl"));
        assert!(result.unwrap().is_none());
    }

    /// Full round-trip: simulate a session with two user prompts, one rewind, then a new prompt.
    /// Assemble the events into prompts the same way `load_user_prompts_from_updates` does.
    #[test]
    fn full_round_trip_with_rewind() {
        // Turn 1: "first prompt"
        let u1a = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"first "}}"#,
        );
        let u1b = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"prompt"}}"#,
        );
        let a1 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"answer1"}}"#,
        );
        // Turn 2: "second prompt"
        let u2 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"second prompt"}}"#,
        );
        let a2 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"answer2"}}"#,
        );
        // Rewind to before turn 2 (keep 1 prompt)
        let rw = fuigo_envelope(
            r#"{"sessionUpdate":"rewind_marker","target_prompt_index":1,"created_at":"2024-01-01"}"#,
        );
        // Turn 2 (after rewind): "new second prompt"
        let u3 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"new second prompt"}}"#,
        );
        let a3 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"answer3"}}"#,
        );

        let f = write_updates_file(&[&u1a, &u1b, &a1, &u2, &a2, &rw, &u3, &a3]);

        let prompts =
            collect_prompts_from_events(PromptExtractIterator::open(f.path()).unwrap().unwrap());

        assert_eq!(prompts, vec!["first prompt", "new second prompt"]);
    }

    #[test]
    fn collect_prompts_ignores_unmarked_phantoms_when_markers_present() {
        let events = [
            PromptExtractEvent::user_text_pi("hi", 0),
            PromptExtractEvent::NotUserMessage,
            PromptExtractEvent::user_text("!pwd phantom"),
            PromptExtractEvent::NotUserMessage,
            PromptExtractEvent::user_text_pi("echo hello", 1),
            PromptExtractEvent::NotUserMessage,
            PromptExtractEvent::user_text("echo hi instead"),
            PromptExtractEvent::NotUserMessage,
            PromptExtractEvent::user_text_pi("ty ty", 2),
            PromptExtractEvent::NotUserMessage,
        ];
        let prompts = collect_prompts_from_events(events.into_iter());
        assert_eq!(prompts, vec!["hi", "echo hello", "ty ty"]);
    }

    #[test]
    fn collect_prompts_mixed_unmarked_prefix_then_markers() {
        let events = [
            PromptExtractEvent::user_text("old0"),
            PromptExtractEvent::NotUserMessage,
            PromptExtractEvent::user_text("old1"),
            PromptExtractEvent::NotUserMessage,
            PromptExtractEvent::user_text_pi("new2", 2),
            PromptExtractEvent::NotUserMessage,
            PromptExtractEvent::user_text("!pwd"),
            PromptExtractEvent::NotUserMessage,
            PromptExtractEvent::user_text_pi("new3", 3),
            PromptExtractEvent::NotUserMessage,
        ];
        let prompts = collect_prompts_from_events(events.into_iter());
        assert_eq!(prompts, vec!["old0", "old1", "new2", "new3"]);
    }

    #[test]
    fn parse_extracts_prompt_index_from_update_meta() {
        let line = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"hi"},"_meta":{"promptIndex":3}}"#,
        );
        assert_eq!(
            parse_prompt_extract_event(&line),
            PromptExtractEvent::user_text_pi("hi", 3)
        );
    }

    fn user_chunk(text: &str, prompt_index: Option<usize>) -> SessionUpdate {
        let mut chunk = acp::ContentChunk::new(acp::ContentBlock::Text(acp::TextContent::new(
            text.to_string(),
        )));
        if let Some(pi) = prompt_index {
            chunk = chunk.meta(
                serde_json::json!({ "promptIndex": pi })
                    .as_object()
                    .cloned(),
            );
        }
        SessionUpdate::Acp(Box::new(acp::SessionNotification::new(
            acp::SessionId::new("s"),
            acp::SessionUpdate::UserMessageChunk(chunk),
        )))
    }

    fn agent_chunk(text: &str) -> SessionUpdate {
        SessionUpdate::Acp(Box::new(acp::SessionNotification::new(
            acp::SessionId::new("s"),
            acp::SessionUpdate::AgentMessageChunk(acp::ContentChunk::new(acp::ContentBlock::Text(
                acp::TextContent::new(text.to_string()),
            ))),
        )))
    }

    /// The fork copy classifies raw lines while replay parity tests classify typed updates.
    /// A divergence between the two classifiers would silently shift fork truncation boundaries.
    #[test]
    fn rewind_step_classifiers_agree_on_serialized_updates() {
        let rewind = SessionUpdate::Fuigo(Box::new(
            crate::extensions::notification::SessionNotification {
                session_id: acp::SessionId::new("s"),
                update: crate::extensions::notification::SessionUpdate::RewindMarker {
                    target_prompt_index: 2,
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                },
                meta: None,
            },
        ));
        let host_turn_chunk = {
            let chunk = acp::ContentChunk::new(acp::ContentBlock::Text(acp::TextContent::new(
                "host".to_string(),
            )))
            .meta(serde_json::json!({ "hostTurn": true }).as_object().cloned());
            SessionUpdate::Acp(Box::new(acp::SessionNotification::new(
                acp::SessionId::new("s"),
                acp::SessionUpdate::UserMessageChunk(chunk),
            )))
        };
        for update in [
            user_chunk("plain", None),
            user_chunk("marked", Some(4)),
            host_turn_chunk,
            agent_chunk("agent"),
            rewind,
        ] {
            let envelope = SessionUpdateEnvelope::from_update(&update).unwrap();
            let line = serde_json::to_string(&envelope).unwrap();
            assert_eq!(
                rewind_step_for_line(&line),
                rewind_step_for_update(&update),
                "raw and typed classification must agree for {line}"
            );
        }
    }

    #[test]
    fn updates_truncate_ignores_unmarked_phantoms_when_markers_present() {
        let updates = vec![
            user_chunk("P0", Some(0)),
            agent_chunk("A0"),
            user_chunk("!pwd", None),
            agent_chunk("out"),
            user_chunk("P1", Some(1)),
            agent_chunk("A1"),
            user_chunk("P2", Some(2)),
            agent_chunk("A2"),
        ];
        // Keep through P1 (indices 0,1); cut at start of P2 run.
        let cut = truncate_for_prompt_by(&updates, 1, rewind_step_for_update);
        assert_eq!(cut, 6);
        assert!(matches!(
            &updates[cut],
            SessionUpdate::Acp(n) if matches!(
                &n.update,
                acp::SessionUpdate::UserMessageChunk(c)
                    if matches!(&c.content, acp::ContentBlock::Text(t) if t.text == "P2")
            )
        ));
    }

    #[test]
    fn updates_truncate_splits_consecutive_marked_prompts_without_agent() {
        let updates: Vec<_> = (0..6)
            .map(|i| user_chunk(&format!("P{i}"), Some(i)))
            .collect();
        // Target 2 keeps turns 0 and 1; cut at P2 (index 2).
        assert_eq!(
            truncate_for_prompt_by(&updates, 1, rewind_step_for_update),
            2
        );
        assert_eq!(
            truncate_for_prompt_by(&updates, 2, rewind_step_for_update),
            3
        );
        assert_eq!(
            truncate_for_prompt_by(&updates, 5, rewind_step_for_update),
            6
        );
    }

    /// Mixed stream: unmarked runs before the first promptIndex still count.
    #[test]
    fn updates_truncate_mixed_unmarked_prefix_then_markers() {
        let updates = vec![
            user_chunk("old0", None),
            agent_chunk("A0"),
            user_chunk("old1", None),
            agent_chunk("A1"),
            user_chunk("new2", Some(2)),
            agent_chunk("A2"),
            user_chunk("!pwd", None),
            agent_chunk("out"),
            user_chunk("new3", Some(3)),
            agent_chunk("A3"),
        ];
        // Target 1 keeps old0 and old1; cut at new2
        assert_eq!(
            truncate_for_prompt_by(&updates, 1, rewind_step_for_update),
            4
        );
        // Target 2 keeps through A2 (and phantom run does not add a turn); cut at new3.
        assert_eq!(
            truncate_for_prompt_by(&updates, 2, rewind_step_for_update),
            8
        );
        assert_eq!(
            truncate_for_prompt_by(&updates, 0, rewind_step_for_update),
            2
        );
    }

    #[test]
    fn filter_rewind_mixed_unmarked_prefix_then_markers() {
        let o0 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"old0"}}"#,
        );
        let a0 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"A0"}}"#,
        );
        let o1 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"old1"}}"#,
        );
        let a1 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"A1"}}"#,
        );
        let n2 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"new2"},"_meta":{"promptIndex":2}}"#,
        );
        let a2 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"A2"}}"#,
        );
        let n3 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"new3"},"_meta":{"promptIndex":3}}"#,
        );
        // Rewind to target 2: keep turns 0,1 (old0, old1); drop new2 and everything after
        let rw = fuigo_envelope(
            r#"{"sessionUpdate":"rewind_marker","target_prompt_index":2,"created_at":"2024-01-01"}"#,
        );
        let after = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"after"},"_meta":{"promptIndex":2}}"#,
        );
        let lines = vec![
            o0.as_str(),
            a0.as_str(),
            o1.as_str(),
            a1.as_str(),
            n2.as_str(),
            a2.as_str(),
            n3.as_str(),
            rw.as_str(),
            after.as_str(),
        ];
        let kept = filter_rewind_lines(lines);
        let texts: Vec<&str> = kept
            .iter()
            .filter_map(|l| {
                if l.contains("\"text\":\"old0\"") {
                    Some("old0")
                } else if l.contains("\"text\":\"old1\"") {
                    Some("old1")
                } else if l.contains("\"text\":\"new2\"") {
                    Some("new2")
                } else if l.contains("\"text\":\"new3\"") {
                    Some("new3")
                } else if l.contains("\"text\":\"after\"") {
                    Some("after")
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(texts, vec!["old0", "old1", "after"]);
    }

    #[test]
    fn filter_rewind_ignores_unmarked_phantoms_when_markers_present() {
        let p0 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"P0"},"_meta":{"promptIndex":0}}"#,
        );
        let a0 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"A0"}}"#,
        );
        let phantom = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"!pwd"}}"#,
        );
        let p1 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"P1"},"_meta":{"promptIndex":1}}"#,
        );
        let a1 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"A1"}}"#,
        );
        let p2 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"P2"},"_meta":{"promptIndex":2}}"#,
        );
        let rw = fuigo_envelope(
            r#"{"sessionUpdate":"rewind_marker","target_prompt_index":2,"created_at":"2024-01-01"}"#,
        );
        let after = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"after"},"_meta":{"promptIndex":2}}"#,
        );
        let lines = vec![
            p0.as_str(),
            a0.as_str(),
            phantom.as_str(),
            p1.as_str(),
            a1.as_str(),
            p2.as_str(),
            rw.as_str(),
            after.as_str(),
        ];
        let kept = filter_rewind_lines(lines);
        let texts: Vec<&str> = kept
            .iter()
            .filter_map(|l| {
                if l.contains("\"text\":\"P0\"") {
                    Some("P0")
                } else if l.contains("!pwd") {
                    Some("phantom")
                } else if l.contains("\"text\":\"P1\"") {
                    Some("P1")
                } else if l.contains("\"text\":\"P2\"") {
                    Some("P2")
                } else if l.contains("\"text\":\"after\"") {
                    Some("after")
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(texts, vec!["P0", "phantom", "P1", "after"]);
    }

    // ── filter_rewind_lines tests ────────────────────────────────────────────

    #[test]
    fn filter_rewind_removes_dead_branch() {
        let u1 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"first"}}"#,
        );
        let a1 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"resp1"}}"#,
        );
        let u2 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"second"}}"#,
        );
        let a2 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"resp2"}}"#,
        );
        // Rewind to prompt 1 kills u2, a2
        let rw = fuigo_envelope(
            r#"{"sessionUpdate":"rewind_marker","target_prompt_index":1,"created_at":"2024-01-01"}"#,
        );
        let u3 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"replacement"}}"#,
        );
        let a3 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"resp3"}}"#,
        );

        let lines = vec![
            u1.as_str(),
            a1.as_str(),
            u2.as_str(),
            a2.as_str(),
            rw.as_str(),
            u3.as_str(),
            a3.as_str(),
        ];
        let result = filter_rewind_lines(lines);

        assert_eq!(result.len(), 4);
        assert!(result[0].contains("first"));
        assert!(result[1].contains("resp1"));
        assert!(result[2].contains("replacement"));
        assert!(result[3].contains("resp3"));
    }

    #[test]
    fn filter_rewind_ignores_a_malformed_middle_line() {
        let user_message_1 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"first"}}"#,
        );
        let agent_message_1 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"resp1"}}"#,
        );
        let user_message_2 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"second"}}"#,
        );
        let agent_message_2 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"resp2"}}"#,
        );
        let rewind_to_1 = fuigo_envelope(
            r#"{"sessionUpdate":"rewind_marker","target_prompt_index":1,"created_at":"2024-01-01"}"#,
        );
        let torn = "{ torn, unparseable jsonl line";

        // The malformed line is kept but not counted as a prompt boundary, so the rewind still drops prompt 1
        let survivors = filter_rewind_lines(vec![
            user_message_1.as_str(),
            agent_message_1.as_str(),
            torn,
            user_message_2.as_str(),
            agent_message_2.as_str(),
            rewind_to_1.as_str(),
        ]);

        pretty_assertions::assert_eq!(
            survivors,
            vec![user_message_1.as_str(), agent_message_1.as_str(), torn]
        );
    }

    #[test]
    fn filter_rewind_to_zero_clears_all() {
        let u1 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"only"}}"#,
        );
        let a1 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"resp"}}"#,
        );
        let rw = fuigo_envelope(
            r#"{"sessionUpdate":"rewind_marker","target_prompt_index":0,"created_at":"2024-01-01"}"#,
        );
        let u2 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"fresh start"}}"#,
        );

        let lines = vec![u1.as_str(), a1.as_str(), rw.as_str(), u2.as_str()];
        let result = filter_rewind_lines(lines);

        assert_eq!(result.len(), 1);
        assert!(result[0].contains("fresh start"));
    }

    #[test]
    fn filter_rewind_double_rewind() {
        let u1 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"p1"}}"#,
        );
        let a1 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"r1"}}"#,
        );
        let u2 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"p2"}}"#,
        );
        let a2 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"r2"}}"#,
        );
        let u3 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"p3"}}"#,
        );
        let a3 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"r3"}}"#,
        );
        // Rewind to prompt 2 kills p3/r3
        let rw1 = fuigo_envelope(
            r#"{"sessionUpdate":"rewind_marker","target_prompt_index":2,"created_at":"2024-01-01"}"#,
        );
        let u4 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"p4"}}"#,
        );
        let a4 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"r4"}}"#,
        );
        // Rewind to prompt 1 kills p2/r2/p4/r4
        let rw2 = fuigo_envelope(
            r#"{"sessionUpdate":"rewind_marker","target_prompt_index":1,"created_at":"2024-01-01"}"#,
        );
        let u5 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"final"}}"#,
        );

        let lines = vec![
            u1.as_str(),
            a1.as_str(),
            u2.as_str(),
            a2.as_str(),
            u3.as_str(),
            a3.as_str(),
            rw1.as_str(),
            u4.as_str(),
            a4.as_str(),
            rw2.as_str(),
            u5.as_str(),
        ];
        let result = filter_rewind_lines(lines);

        assert_eq!(result.len(), 3);
        assert!(result[0].contains("p1"));
        assert!(result[1].contains("r1"));
        assert!(result[2].contains("final"));
    }

    /// The raw-line filter and the typed filter must truncate an identical rewind timeline to the same surviving updates, in the same order.
    #[test]
    fn filter_rewind_lines_and_updates_agree() {
        let u1 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"p1"}}"#,
        );
        let a1 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"r1"}}"#,
        );
        let u2 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"p2"}}"#,
        );
        let a2 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"r2"}}"#,
        );
        let rw1 = fuigo_envelope(
            r#"{"sessionUpdate":"rewind_marker","target_prompt_index":2,"created_at":"2024-01-01"}"#,
        );
        let u3 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"p3"}}"#,
        );
        let a3 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"r3"}}"#,
        );
        let rw2 = fuigo_envelope(
            r#"{"sessionUpdate":"rewind_marker","target_prompt_index":1,"created_at":"2024-01-01"}"#,
        );
        let u4 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"final"}}"#,
        );

        let lines = vec![
            u1.as_str(),
            a1.as_str(),
            u2.as_str(),
            a2.as_str(),
            rw1.as_str(),
            u3.as_str(),
            a3.as_str(),
            rw2.as_str(),
            u4.as_str(),
        ];

        let ser = |u: &SessionUpdate| serde_json::to_string(u).unwrap();
        let via_lines: Vec<String> = filter_rewind_lines(lines.clone())
            .iter()
            .map(|l| ser(&SessionUpdateEnvelope::from_str(l).unwrap()))
            .collect();
        let typed: Vec<SessionUpdate> = lines
            .iter()
            .map(|l| SessionUpdateEnvelope::from_str(l).unwrap())
            .collect();
        let via_updates: Vec<String> = filter_rewind_updates(typed).iter().map(ser).collect();

        assert_eq!(via_lines, via_updates);
    }

    /// An out-of-range rewind target folds to `result.len()` (the `unwrap_or(result.len())` branch in `filter_rewind_by`).
    /// So truncation is a no-op and every survivor is kept.
    #[test]
    fn filter_rewind_out_of_range_target_keeps_all() {
        let u1 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"p1"}}"#,
        );
        let a1 = acp_envelope(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"r1"}}"#,
        );
        // Only prompt index 0 exists; target 5 is out of range.
        let rw = fuigo_envelope(
            r#"{"sessionUpdate":"rewind_marker","target_prompt_index":5,"created_at":"2024-01-01"}"#,
        );
        let u2 = acp_envelope(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"p2"}}"#,
        );

        let lines = vec![u1.as_str(), a1.as_str(), rw.as_str(), u2.as_str()];
        let result = filter_rewind_lines(lines);

        assert_eq!(result.len(), 3);
        assert!(result[0].contains("p1"));
        assert!(result[1].contains("r1"));
        assert!(result[2].contains("p2"));
    }

    // ── collect_assistant_text / collect_tool_metadata tests ──────────────────

    #[test]
    fn collect_assistant_text_extracts_chunks() {
        let lines = vec![
            acp_envelope(
                r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"hello"}}"#,
            ),
            acp_envelope(
                r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"world"}}"#,
            ),
        ];
        let updates: Vec<_> = lines
            .into_iter()
            .map(|s| Ok(serde_json::from_str(&s).unwrap()))
            .collect();
        let result = collect_assistant_text(updates.into_iter());
        assert_eq!(result, vec!["hello world"]);
    }

    #[test]
    fn collect_assistant_text_caps_at_100k() {
        // Two 60k chunks with non-ASCII, separator, and truncation
        let chunk1 = "x".repeat(60_000) + "café"; // 60k + 5 bytes (café is 5 UTF-8 bytes)
        let chunk2 = "日本語".repeat(20_000); // 60k bytes (3 bytes per char)
        let lines = vec![
            acp_envelope(&format!(
                r#"{{"sessionUpdate":"agent_message_chunk","content":{{"type":"text","text":"{chunk1}"}}}}"#
            )),
            acp_envelope(&format!(
                r#"{{"sessionUpdate":"agent_message_chunk","content":{{"type":"text","text":"{chunk2}"}}}}"#
            )),
        ];
        let updates: Vec<_> = lines
            .into_iter()
            .map(|s| Ok(serde_json::from_str(&s).unwrap()))
            .collect();
        let result = collect_assistant_text(updates.into_iter());
        let total: usize = result.iter().map(|s| s.len()).sum();
        assert!(total <= 100_000, "got {total} chars");
        assert!(
            result.iter().any(|s| s.contains("café")),
            "non-ASCII should be preserved"
        );
    }

    #[test]
    fn collect_tool_metadata_extracts_title_and_paths() {
        let line = acp_envelope(
            r#"{"sessionUpdate":"tool_call","toolCallId":"tc1","title":"Read `/tmp/foo.rs`","kind":"read","locations":[{"path":"/tmp/foo.rs"}]}"#,
        );
        let updates: Vec<_> = vec![Ok(serde_json::from_str(&line).unwrap())];
        let result = collect_tool_metadata(updates.into_iter());
        assert!(result.contains(&"Read `/tmp/foo.rs`".to_string()));
        assert!(result.contains(&"/tmp/foo.rs".to_string()));
    }

    #[test]
    fn collect_tool_metadata_caps_at_200_calls() {
        let mut lines = Vec::new();
        for i in 0..250 {
            lines.push(acp_envelope(&format!(
                r#"{{"sessionUpdate":"tool_call","toolCallId":"tc{i}","title":"tool_{i}","kind":"exec","locations":[]}}"#,
            )));
        }
        let updates: Vec<_> = lines
            .into_iter()
            .map(|s| Ok(serde_json::from_str(&s).unwrap()))
            .collect();
        let result = collect_tool_metadata(updates.into_iter());
        // The calls have empty locations, so every collected entry is a title
        let titles: Vec<_> = result.iter().filter(|s| s.starts_with("tool_")).collect();
        assert_eq!(titles.len(), 200);
    }

    #[test]
    fn from_str_unknown_fuigo_variant_deserializes_via_envelope() {
        // Simulates an updates.jsonl line containing a removed variant (e.g. git_branch_update).
        // SessionUpdateEnvelope::from_str must not error; the Unknown catch-all absorbs it
        let line = fuigo_envelope(r#"{"sessionUpdate":"git_branch_update","branch":"main"}"#);
        let update = SessionUpdateEnvelope::from_str(&line).unwrap();
        match update {
            SessionUpdate::Fuigo(notif) => {
                assert_eq!(
                    notif.update,
                    crate::extensions::notification::SessionUpdate::Unknown
                );
            }
            SessionUpdate::Acp(_) => panic!("expected Fuigo variant"),
        }
    }

    #[test]
    fn from_str_known_fuigo_variant_still_works() {
        let line = fuigo_envelope(r#"{"sessionUpdate":"memory_flush_started"}"#);
        let update = SessionUpdateEnvelope::from_str(&line).unwrap();
        match update {
            SessionUpdate::Fuigo(notif) => {
                assert_eq!(
                    notif.update,
                    crate::extensions::notification::SessionUpdate::MemoryFlushStarted
                );
            }
            SessionUpdate::Acp(_) => panic!("expected Fuigo variant"),
        }
    }
}
