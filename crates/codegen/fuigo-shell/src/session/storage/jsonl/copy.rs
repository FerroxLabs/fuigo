//! Session fork/copy for the JSONL adapter.
//!
//! The `updates.jsonl` transcript is unbounded, so the copy streams it line by line.
//! Peak memory tracks a single capped line, plus one small per-line record when a prompt cut is requested.
//! Chat history stays materialized: its transforms need random access and the compacted history is bounded by the context window.

use std::collections::BTreeSet;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, Write};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use agent_client_protocol as acp;

use crate::sampling::{
    ConversationItem, conversation_truncate_for_prompt, fork_filter_chat,
    transform_conversation_cwd,
};
use crate::session::info::Info;
use crate::session::persistence::{CHAT_FORMAT_VERSION, Summary};
use crate::session::storage::jsonl::{JsonlStorageAdapter, transform_session_id_in_update};
use crate::session::storage::{
    CopySessionOptions, CopySessionResult, RewindStep, SessionUpdate, SessionUpdateEnvelope,
    filter_rewind_by, rewind_step_for_line, truncate_for_prompt_by,
};

#[cfg(test)]
#[path = "copy_tests.rs"]
mod tests;

#[cfg(test)]
thread_local! {
    /// Test seam: runs once on the copying thread right after the source's chat history was read, before the witness
    /// recovery and the transcript staging, so a test can interleave a source write there (P111, Astra r7 #2, r8 #1).
    static AFTER_SOURCE_CHAT_READ: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// Test seam: runs on the copying thread right after the snapshot released its locks, before it reads the chat history.
    static AFTER_SNAPSHOT_LOCKS_RELEASED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn after_source_chat_read() {
    if let Some(hook) = AFTER_SOURCE_CHAT_READ.with(|hook| hook.borrow_mut().take()) {
        hook();
    }
}

fn is_orchestration_projection_update(update: &SessionUpdate) -> bool {
    matches!(
        update,
        SessionUpdate::Fuigo(notification)
            if matches!(
                &notification.update,
                crate::extensions::notification::SessionUpdate::WorkflowUpdated { .. }
                    | crate::extensions::notification::SessionUpdate::GoalUpdated { .. }
            )
    )
}

/// Updates written plus the `compaction_checkpoints/{uuid}.json` files the surviving records reference, collected in the same pass.
#[derive(Default)]
struct CopiedUpdates {
    count: usize,
    checkpoint_files: BTreeSet<String>,
}

/// Anything past this cap is corruption (e.g. a tail that lost its newlines) and is discarded without being buffered.
/// Discarded lines consume no index in either pass, unlike torn lines, which classify as [`RewindStep::Other`] and end a user run.
const MAX_UPDATE_LINE_BYTES: usize = 64 * 1024 * 1024;

/// [`for_each_jsonl_line_capped`] with the production cap.
fn for_each_jsonl_line<R: BufRead>(
    reader: R,
    f: impl FnMut(usize, &[u8]) -> io::Result<ControlFlow<()>>,
) -> io::Result<()> {
    for_each_jsonl_line_capped(reader, MAX_UPDATE_LINE_BYTES, f)
}

/// Invoke `f` with the index and bytes of each non-empty line, reusing one capped line buffer.
/// Lines over `cap` content bytes are discarded without being buffered whole and consume no index.
/// `f` returns `Break` to stop early.
/// `f` gets raw bytes rather than the typed `UpdatesIterator`.
/// Classification must tolerate non-UTF-8 lines, and both copy passes need identical line indexes.
fn for_each_jsonl_line_capped<R: BufRead>(
    mut reader: R,
    cap: usize,
    mut f: impl FnMut(usize, &[u8]) -> io::Result<ControlFlow<()>>,
) -> io::Result<()> {
    let mut buf = Vec::new();
    let mut index = 0;
    let mut discarded = 0usize;
    let result = loop {
        buf.clear();
        let n = reader
            .by_ref()
            .take(cap as u64 + 1)
            .read_until(b'\n', &mut buf)?;
        if n == 0 {
            break Ok(());
        }
        if buf.len() > cap && buf.last() != Some(&b'\n') {
            discarded += 1;
            if discarded == 1 {
                tracing::warn!(
                    max_bytes = cap,
                    "discarding over-long updates.jsonl line during fork copy"
                );
            }
            // Drain the remainder of the line without retaining it.
            loop {
                buf.clear();
                let n = reader
                    .by_ref()
                    .take(cap as u64)
                    .read_until(b'\n', &mut buf)?;
                if n == 0 || buf.last() == Some(&b'\n') {
                    break;
                }
            }
            continue;
        }
        let line = buf.trim_ascii();
        if line.is_empty() {
            continue;
        }
        if f(index, line)?.is_break() {
            break Ok(());
        }
        index += 1;
    };
    if discarded > 1 {
        tracing::warn!(
            discarded,
            max_bytes = cap,
            "discarded over-long updates.jsonl lines during fork copy"
        );
    }
    result
}

/// Indexes (in non-empty-line order) of the source lines that survive rewind filtering and the `target_prompt_index` cut.
/// The scan holds one classification per line instead of the lines.
/// As in replay, an unparseable line classifies as [`RewindStep::Other`] (ending a user run) and is skipped later at parse.
fn surviving_line_indexes<R: BufRead>(
    reader: R,
    target_prompt_index: usize,
) -> io::Result<Vec<usize>> {
    struct LineRecord {
        index: usize,
        step: RewindStep,
    }
    let mut records = Vec::new();
    for_each_jsonl_line(reader, |index, line| {
        let step = std::str::from_utf8(line).map_or(RewindStep::Other, rewind_step_for_line);
        records.push(LineRecord { index, step });
        Ok(ControlFlow::Continue(()))
    })?;
    let mut records = filter_rewind_by(records, |record| record.step);
    let keep = truncate_for_prompt_by(&records, target_prompt_index, |record| record.step);
    records.truncate(keep);
    Ok(records.into_iter().map(|record| record.index).collect())
}

/// Streaming writer for the fork target's `updates.jsonl`.
/// Corruption-tolerant like the load path: a torn or undecodable line is skipped with a warning instead of failing the fork.
struct UpdateLineWriter<'a> {
    writer: BufWriter<std::fs::File>,
    source: &'a Path,
    target_session_id: &'a acp::SessionId,
    copied: CopiedUpdates,
    skipped_lines: usize,
}

impl<'a> UpdateLineWriter<'a> {
    fn try_new(
        target: &Path,
        source: &'a Path,
        target_session_id: &'a acp::SessionId,
    ) -> io::Result<Self> {
        Ok(Self {
            writer: BufWriter::new(super::super::owner_only::create(target)?),
            source,
            target_session_id,
            copied: CopiedUpdates::default(),
            skipped_lines: 0,
        })
    }

    fn copy_line(&mut self, line: &[u8]) -> io::Result<()> {
        let update = match std::str::from_utf8(line).map(SessionUpdateEnvelope::from_str) {
            Ok(Ok(update)) => update,
            Ok(Err(error)) => {
                self.skip_torn_line(&error);
                return Ok(());
            }
            Err(error) => {
                self.skip_torn_line(&error);
                return Ok(());
            }
        };
        if is_orchestration_projection_update(&update) {
            return Ok(());
        }
        if let SessionUpdate::Fuigo(notification) = &update
            && let crate::extensions::notification::SessionUpdate::CompactionCheckpoint(info) =
                &notification.update
        {
            self.copied
                .checkpoint_files
                .insert(info.checkpoint_file.clone());
        }
        let update = transform_session_id_in_update(update, self.target_session_id);
        let envelope = SessionUpdateEnvelope::from_update(&update).map_err(invalid_data)?;
        serde_json::to_writer(&mut self.writer, &envelope).map_err(invalid_data)?;
        self.writer.write_all(b"\n")?;
        self.copied.count += 1;
        Ok(())
    }

    fn skip_torn_line(&mut self, error: &dyn std::fmt::Display) {
        self.skipped_lines += 1;
        if self.skipped_lines == 1 {
            tracing::warn!(
                error = %error,
                path = %self.source.display(),
                "skipping unparseable updates.jsonl line during fork copy (torn append?)"
            );
        }
    }

    fn finish(mut self) -> io::Result<CopiedUpdates> {
        // The first skipped line already warned with its parse error.
        if self.skipped_lines > 1 {
            tracing::warn!(
                skipped = self.skipped_lines,
                copied = self.copied.count,
                path = %self.source.display(),
                "skipped unparseable session update lines during fork copy"
            );
        }
        self.writer.flush()?;
        Ok(self.copied)
    }
}

/// Copy `source` (an `updates.jsonl`) to `target` without materializing it.
/// With a `target_prompt_index`, pass one computes the surviving line set and pass two writes exactly those lines.
/// Without one, every line streams through, preserving rewind markers and dead branches.
/// Both passes read one pinned, rewound file handle, so their line indexes cannot skew under a concurrent rename.
/// Only the first `limit` bytes are read when a limit is given: the length the copy's snapshot took (see
/// [`JsonlStorageAdapter::snapshot_source`]), so lines appended after the snapshot are in neither pass (P123, K17).
fn copy_updates_streaming(
    source: &Path,
    target: &Path,
    target_session_id: &acp::SessionId,
    target_prompt_index: Option<usize>,
    limit: Option<u64>,
) -> io::Result<CopiedUpdates> {
    let limit = limit.unwrap_or(u64::MAX);
    let mut writer = UpdateLineWriter::try_new(target, source, target_session_id)?;
    let mut file = match std::fs::File::open(source) {
        Ok(file) => file,
        // A missing source is an empty transcript; still write the target.
        Err(error) if error.kind() == io::ErrorKind::NotFound => return writer.finish(),
        Err(error) => return Err(error),
    };
    match target_prompt_index {
        None => {
            for_each_jsonl_line(BufReader::new(file.take(limit)), |_, line| {
                writer.copy_line(line)?;
                Ok(ControlFlow::Continue(()))
            })?;
        }
        Some(target_idx) => {
            let survivors = surviving_line_indexes(BufReader::new((&mut file).take(limit)), target_idx)?;
            file.seek(io::SeekFrom::Start(0))?;
            let mut survivors = survivors.into_iter().peekable();
            for_each_jsonl_line(BufReader::new(file.take(limit)), |index, line| {
                if survivors.next_if_eq(&index).is_some() {
                    writer.copy_line(line)?;
                }
                Ok(if survivors.peek().is_none() {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                })
            })?;
        }
    }
    writer.finish()
}

impl JsonlStorageAdapter {
    /// Fully synchronous implementation of `copy_session_data`, for use on a blocking thread; every caller reaches it through `spawn_blocking`.
    pub(crate) fn copy_session_data_sync(
        &self,
        source_info: &Info,
        target_info: &Info,
        options: CopySessionOptions,
    ) -> io::Result<CopySessionResult> {
        let source_summary = self.read_summary_sync(source_info)?;
        let chat_format_version = source_summary.chat_format_version;

        // The source may be live, so the copy takes ONE snapshot of it: the chat history's bytes and the transcript's length
        // are read together with the source's append locks held (both files, so no append lands between the two reads).
        // The transcript is then copied only up to that length, so a turn added while the fork is being made is in the
        // child's transcript and model history, or in neither (P123, K17; before, the transcript was read after the chat
        // history, and a turn appended between the two was in the transcript only).
        // Appends are not the only thing that happens to a live source. A rewrite of the chat history (a rewind, a
        // compaction) replaces the file without those locks, so the chat history is fingerprinted and checked again once the
        // transcript is staged, before the target exists: a history replaced in between refuses the copy instead of
        // pairing one generation's history with another's transcript (P111, Astra r6).
        // The same holds for a compaction that commits after the snapshot: its marker lands in the transcript before its
        // separate rewrite of the chat history runs. A marker in what was appended after the snapshot refuses the copy too,
        // since the compaction witness (read next) may already describe it (P111, Astra r7 #2). A fork_filter copy keeps no
        // transcript and skips the scan (Astra r8 #4).
        let snapshot = self.snapshot_source(source_info, !options.fork_filter)?;
        let source_chat_path = self.chat_file(source_info);
        // The bytes fingerprinted are also the ones the compaction witness is judged against below, so a compaction
        // rewrite that lands in between (and keeps those bytes as its prefix) cannot make them look current (Astra r8 #1).
        let chat_bytes_seen = snapshot.chat_bytes;
        let chat_seen = chat_bytes_seen.as_deref().map(chat_fingerprint_of);
        let (mut chat_to_copy, mut skipped_chat_lines): (Vec<ConversationItem>, usize) = match chat_bytes_seen.as_deref() {
            Some(bytes) => self.read_chat_history_counting_from_bytes(&source_chat_path, bytes, chat_format_version)?,
            None => (Vec::new(), 0),
        };
        #[cfg(test)]
        after_source_chat_read();
        // A source whose latest compaction committed without its chat_history.jsonl rewrite landing is copied with the
        // history it resumes with: the projection and the items written after it (P111, DI-03). Unreadable lines among
        // those are repaired out structurally, as the source's own load would (the child carries no evidence of them).
        if let Some(recovered) = super::compaction_witness::recover_unapplied_compaction_in(
            &self.session_dir(source_info),
            chat_bytes_seen.as_deref(),
        ) {
            chat_to_copy = recovered.history;
            skipped_chat_lines = recovered.skipped_lines;
        }
        // A damaged source (a torn line, or one an earlier load already scrubbed and kept as `.corrupt`) is copied with the
        // history repaired the way its own load repairs it (P96): a tool result whose call was lost would make the provider
        // reject every request of the fork. The source's file is not touched (it stays the evidence), so the child needs no
        // `.pre-repair` backup of its own (P123, K14).
        if skipped_chat_lines > 0 || super::load_repair::quarantine_of_earlier_load(&source_chat_path).is_some() {
            let report = fuigo_chat_state::compaction_utils::repair_history(&mut chat_to_copy);
            if report.changed() {
                tracing::warn!(
                    session_id = %source_info.id.0,
                    skipped_chat_lines,
                    duplicates_removed = report.duplicates_removed,
                    stripped_tool_result_ids = ?report.stripped_tool_result_ids,
                    synthetic_results_inserted = report.synthetic_results_inserted,
                    "fork: the source's saved history was damaged; the copy's history was repaired"
                );
            }
        }

        // A point-in-time copy decides the child's history from the cut (and rewind-filtered) transcript, and that
        // decision can refuse the copy (P111, DI-04). The cut is therefore staged in a private directory under the
        // sessions root (P114: never the system temp dir) and decided BEFORE the target session exists, so a refusal
        // creates nothing and never has to delete anything.
        // A fork_filter copy (subagent context bootstrap) starts the child with an empty transcript and only truncates.
        let staged_cut = match options.target_prompt_index {
            Some(target_idx) if !options.fork_filter => {
                let staging = self.fork_staging_dir(target_info)?;
                let staged_updates = staging.dir.path().join(crate::session::storage::UPDATES_FILE);
                let copied = copy_updates_streaming(
                    &self.updates_file(source_info),
                    &staged_updates,
                    &target_info.id,
                    Some(target_idx),
                    Some(snapshot.updates_len),
                )?;
                match self.chat_for_compacted_cut(
                    source_info,
                    &staged_updates,
                    target_idx,
                    &chat_to_copy,
                    snapshot.updates_len,
                )? {
                    Some(rebuilt) => chat_to_copy = rebuilt,
                    None => {
                        // +1: the cut keeps the target prompt inclusive.
                        let keep = conversation_truncate_for_prompt(&chat_to_copy, target_idx + 1);
                        chat_to_copy.truncate(keep);
                    }
                }
                Some((staging, staged_updates, copied))
            }
            Some(target_idx) => {
                let keep = conversation_truncate_for_prompt(&chat_to_copy, target_idx + 1);
                chat_to_copy.truncate(keep);
                None
            }
            // A whole copy stages the transcript too, so the coherence check below runs before the target exists.
            None if !options.fork_filter => {
                let staging = self.fork_staging_dir(target_info)?;
                let staged_updates = staging.dir.path().join(crate::session::storage::UPDATES_FILE);
                let copied = copy_updates_streaming(
                    &self.updates_file(source_info),
                    &staged_updates,
                    &target_info.id,
                    None,
                    Some(snapshot.updates_len),
                )?;
                Some((staging, staged_updates, copied))
            }
            None => None,
        };
        let compaction_crossed = staged_cut.is_some()
            && !compaction_checkpoint_files(&self.updates_file(source_info), (snapshot.updates_len, None))?.is_empty();
        if compaction_crossed || !chat_file_still_starts_with(&source_chat_path, chat_seen.as_ref())? {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                format!(
                    "Cannot copy session {}: its conversation history was replaced while it was being copied (a \
                     rewind or compaction finished). Nothing was created; try again.",
                    source_info.id.0
                ),
            ));
        }

        // Canonical creator: the fork target chain is born owner-only.
        let target_dir = self.create_session_dir_owner_only(target_info)?;
        // The target id may be the caller's (`newSessionId`). A session already stored under it is never overwritten:
        // the copy claims the target by creating its summary exclusively, so of two copies to one id only one proceeds,
        // and a refused copy has written nothing (P111, Astra r4).
        self.claim_copy_target(target_info)?;

        let copied_updates = if options.fork_filter {
            super::super::owner_only::write(&self.updates_file(target_info), b"")?;
            CopiedUpdates::default()
        } else if let Some((staging, staged_updates, copied)) = staged_cut {
            move_staged_file(&staged_updates, &self.updates_file(target_info))?;
            drop(staging);
            copied
        } else {
            unreachable!("every copy that keeps a transcript staged it")
        };

        if options.fork_filter {
            fork_filter_chat(&mut chat_to_copy);
        }

        for target in [
            self.workflows_dir(target_info),
            self.goal_mode_state_file(target_info)
                .parent()
                .expect("goal state has a parent")
                .to_path_buf(),
        ] {
            match std::fs::remove_dir_all(&target) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }

        // The child inherits everything below this boundary; compaction preserves it
        let inherited_prefix_len = if options.fork_filter {
            Some(chat_to_copy.len())
        } else {
            options.inherited_prefix_len
        };

        // Worktree forks skip the cwd rewrite: their display_cwd already shows the model the original project path
        // Rewritten conversation paths would contradict it
        if !options.skip_cwd_transform && source_info.cwd != target_info.cwd {
            transform_conversation_cwd(&mut chat_to_copy, &source_info.cwd, &target_info.cwd);
        }

        if options.strip_reasoning {
            chat_to_copy = fuigo_chat_state::compaction_utils::strip_reasoning_blocks(chat_to_copy);
        }

        let num_chat_messages = chat_to_copy.len();
        let cwd_switch_bookkeeping_generation = chat_to_copy
            .iter()
            .filter_map(ConversationItem::working_directory_switch_generation)
            .max()
            .unwrap_or(0);

        {
            let mut writer = BufWriter::new(super::super::owner_only::create(&self.chat_file(target_info))?);
            for item in &chat_to_copy {
                serde_json::to_writer(&mut writer, item).map_err(invalid_data)?;
                writer.write_all(b"\n")?;
            }
            writer.flush()?;
        }
        drop(chat_to_copy);
        let checkpoint_files = copied_updates.checkpoint_files;
        let num_messages = copied_updates.count;

        let target_summary = fork_summary(
            source_summary,
            target_info,
            &options,
            ForkCounters {
                num_messages,
                num_chat_messages,
                cwd_switch_bookkeeping_generation,
                inherited_prefix_len,
            },
        );
        let summary_bytes = serde_json::to_vec_pretty(&target_summary).map_err(invalid_data)?;
        super::super::owner_only::write(&self.summary_file(target_info), summary_bytes)?;

        let plan_copied = copy_sidecar_file(
            options.copy_plan_state,
            &self.plan_file(source_info),
            &self.plan_file(target_info),
        )?;
        let signals_copied = copy_sidecar_file(
            options.copy_signals,
            &self.signals_file(source_info),
            &self.signals_file(target_info),
        )?;
        let usage_copied = copy_sidecar_file(
            options.copy_usage,
            &self.usage_file(source_info),
            &self.usage_file(target_info),
        )?;
        if let Some(max_turn) = options.target_prompt_index.map(|i| (i + 1) as u32) {
            if usage_copied {
                restamp_copied_usage(
                    &self.usage_file(target_info),
                    &target_info.id,
                    Some(max_turn),
                )?;
            }
            if usage_copied && signals_copied {
                clip_copied_signals_turns(&self.signals_file(target_info), max_turn)?;
            }
        } else if usage_copied {
            restamp_copied_usage(&self.usage_file(target_info), &target_info.id, None)?;
        }
        if usage_copied && !signals_copied {
            // Resume copies billed history without signals, so the child would start at turn 0 and fold new work into inherited rows
            seed_signals_turn_from_usage(
                &self.usage_file(target_info),
                &self.signals_file(target_info),
            )?;
        }
        let plan_mode_state_copied = copy_sidecar_file(
            options.copy_plan_mode_state,
            &self.plan_mode_state_file(source_info),
            &self.plan_mode_state_file(target_info),
        )?;
        let tool_state_copied = copy_sidecar_file(
            options.copy_tool_state,
            &self.session_dir(source_info).join("tool_state.json"),
            &self.session_dir(target_info).join("tool_state.json"),
        )?;
        let announcement_state_copied = copy_sidecar_file(
            options.copy_announcement_state,
            &self.announcement_state_file(source_info),
            &self.announcement_state_file(target_info),
        )?;
        // A truncating or filtering copy can drop the failure announcement from the child's context
        // The copied state still marks it announced, permanently muting it
        // End the episodes so still-down servers re-announce, the same rule as after rewind or compaction
        // Connected fingerprints stay latched: connected tools remain visible in the tool definitions regardless
        if announcement_state_copied
            && (options.target_prompt_index.is_some() || options.fork_filter)
        {
            clear_announced_failure_episodes(&self.announcement_state_file(target_info))?;
        }

        // Title-refresh watermark: only a managed parent (one with a watermark) passes managed state to the child
        // So a fork of a pre-feature session stays unmanaged (frozen) rather than being adopted
        // A full fork inherits the parent's checkpoint (keeping the inherited title frozen)
        // A partial fork starts fresh at `0` so it can retitle its shorter conversation
        if let Some(parent_idx) =
            crate::session::helpers::session_summary::load_title_refresh_watermark(
                &self.session_dir(source_info),
            )
        {
            let child_idx = if options.target_prompt_index.is_none() {
                parent_idx
            } else {
                0
            };
            crate::session::helpers::session_summary::save_title_refresh_watermark(
                &self.session_dir(target_info),
                child_idx,
            );
        }

        // Copied verbatim: the archive is immutable, so no cwd rewrite.
        let compaction_segments_copied = if options.copy_compaction_segments {
            let src_dir = self
                .session_dir(source_info)
                .join(fuigo_compaction_transcript::COMPACTION_DIR);
            let mut copied = 0usize;
            if src_dir.is_dir() {
                let dst_dir = self
                    .session_dir(target_info)
                    .join(fuigo_compaction_transcript::COMPACTION_DIR);
                std::fs::create_dir_all(&dst_dir)?;
                for entry in std::fs::read_dir(&src_dir)? {
                    let entry = entry?;
                    if entry.file_type()?.is_file() {
                        super::super::owner_only::copy(&entry.path(), &dst_dir.join(entry.file_name()))?;
                        copied += 1;
                    }
                }
            }
            copied
        } else {
            0
        };

        let compaction_checkpoints_copied = copy_referenced_checkpoints(
            &checkpoint_files,
            &self.session_dir(source_info),
            &target_dir,
            &source_info.id,
        )?;

        Ok(CopySessionResult {
            chat_messages_copied: num_chat_messages,
            updates_copied: num_messages,
            plan_state_copied: plan_copied,
            plan_mode_state_copied,
            signals_copied,
            tool_state_copied,
            announcement_state_copied,
            compaction_segments_copied,
            compaction_checkpoints_copied,
        })
    }
}

/// How long a copy waits for the source's append locks before giving up for now (an append is a few milliseconds; this is
/// for a writer that is stuck).
const SNAPSHOT_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// What a copy took from its source at one moment: the chat history's bytes (`None` when it has no file) and the length
/// of the transcript.
struct SourceSnapshot {
    chat_bytes: Option<Vec<u8>>,
    updates_len: u64,
}

impl JsonlStorageAdapter {
    /// One coherent snapshot of the source's chat history and transcript (P123, K17).
    ///
    /// Both files' append locks (`<file>.lock`, taken exclusively by every append) are held while the chat history is
    /// read and the transcript's length is taken, in a fixed order, so no append to either file lands between the two.
    /// The snapshot is the source as it was between two appends: the transcript is later copied only up to the length
    /// taken here, and the chat history is the bytes read here. An append in progress finishes first; one that comes
    /// later waits for the few milliseconds the snapshot takes. A lock that cannot be opened (a source directory that is
    /// not writable) is skipped and the snapshot is then taken without it, as copies were before this; a lock held
    /// longer than [`SNAPSHOT_LOCK_WAIT`] refuses the copy as retryable.
    /// A copy that keeps no transcript (`fork_filter`, a subagent's context) takes the chat history's lock only: it neither
    /// reads nor depends on the transcript, so a stuck transcript writer must not fail it.
    fn snapshot_source(&self, source_info: &Info, with_transcript: bool) -> io::Result<SourceSnapshot> {
        let chat_path = self.chat_file(source_info);
        let updates_path = self.updates_file(source_info);
        let mut held = Vec::new();
        if with_transcript {
            // The turn-start lock first: no prompt is between its transcript echo and its chat item while it is held.
            let pair = crate::session::storage::snapshot_lock::lock_path(&self.session_dir(source_info));
            if let Some(lock) = crate::session::storage::snapshot_lock::acquire_blocking(&pair, &updates_path)? {
                held.push(lock);
            }
        }
        let locked: &[&std::path::PathBuf] = if with_transcript { &[&chat_path, &updates_path] } else { &[&chat_path] };
        for path in locked {
            if let Some(lock) = lock_append_for_snapshot(path)? {
                held.push(lock);
            }
        }
        // Under the locks only the two lengths are taken (a stat each), so a copy that is suspended holds the source's
        // writers for no longer than that. Both files are append-only, so the chat history's first `chat_len` bytes read
        // after the locks are released are the bytes that were there; a rewrite that replaced the file meanwhile is caught
        // by the fingerprint check before the target exists (Astra P123 r3 N3).
        let len_of = |path: &Path| match std::fs::metadata(path) {
            Ok(meta) => Ok(Some(meta.len())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        };
        let chat_len = len_of(&chat_path)?;
        let updates_len = if with_transcript { len_of(&updates_path)?.unwrap_or(0) } else { 0 };
        drop(held);
        #[cfg(test)]
        if let Some(hook) = AFTER_SNAPSHOT_LOCKS_RELEASED.with(|hook| hook.borrow_mut().take()) {
            hook();
        }
        let chat_bytes = match chat_len {
            None => None,
            Some(len) => {
                use std::io::Read as _;
                match std::fs::File::open(&chat_path) {
                    Ok(file) => {
                        let mut bytes = Vec::new();
                        file.take(len).read_to_end(&mut bytes)?;
                        Some(bytes)
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                    Err(error) => return Err(error),
                }
            }
        };
        Ok(SourceSnapshot { chat_bytes, updates_len })
    }
}

/// Take `path`'s append lock exclusively, waiting at most [`SNAPSHOT_LOCK_WAIT`]. `Ok(None)` when the lock file cannot be
/// opened at all.
fn lock_append_for_snapshot(path: &Path) -> io::Result<Option<std::fs::File>> {
    let lock_path = path.with_extension("jsonl.lock");
    let lock = match crate::session::storage::owner_only::open(
        std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false),
        &lock_path,
    ) {
        Ok(lock) => lock,
        Err(error) => {
            tracing::debug!(%error, path = %lock_path.display(), "fork snapshot taken without the append lock");
            return Ok(None);
        }
    };
    let deadline = std::time::Instant::now() + SNAPSHOT_LOCK_WAIT;
    loop {
        match fs2::FileExt::try_lock_exclusive(&lock) {
            Ok(()) => return Ok(Some(lock)),
            Err(error) if error.kind() == fs2::lock_contended_error().kind() => {
                #[cfg(test)]
                crate::session::storage::snapshot_lock::CONTENDED.lock().insert(lock_path.clone());
                if std::time::Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        format!(
                            "Cannot copy the session: {} is being written. Nothing was created; try again.",
                            path.display()
                        ),
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(error) => {
                tracing::debug!(%error, path = %lock_path.display(), "fork snapshot taken without the append lock");
                return Ok(None);
            }
        }
    }
}

impl JsonlStorageAdapter {
    /// Refuse a copy whose target already holds a session, and claim the target for this copy otherwise.
    ///
    /// The claim is the exclusive creation of the target's (still empty) `summary.json`; the copy writes the summary
    /// itself last. Any of the files a session is made of already being there means the id is taken.
    fn claim_copy_target(&self, target_info: &Info) -> io::Result<()> {
        let taken = |path: &Path| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "Cannot create session {}: a session with that id already exists ({} is present). Nothing was \
                     written; use another id.",
                    target_info.id.0,
                    path.display()
                ),
            )
        };
        for existing in [self.updates_file(target_info), self.chat_file(target_info)] {
            if std::fs::symlink_metadata(&existing).is_ok() {
                return Err(taken(&existing));
            }
        }
        let summary = self.summary_file(target_info);
        match crate::session::storage::owner_only::open(
            std::fs::OpenOptions::new().write(true).create_new(true),
            &summary,
        ) {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(taken(&summary)),
            Err(error) => Err(error),
        }
    }

    /// Chat history for a point-in-time copy cut at the target, or `None` when truncating the source's chat history is
    /// right. `cut_updates` is the copied transcript: cut at the target, rewound branches filtered out.
    ///
    /// When the cut ends with an active compaction, the child's model view is that checkpoint's projection plus the
    /// turns after it up to the cut. The source's chat history may instead start from a LATER compaction, whose summary
    /// covers turns after the cut, and no truncation removes those. The cut is replayed instead, as a rewind across a
    /// compaction does (text only: tool calls between that checkpoint and the cut are not carried, the limit a rewind
    /// has). This is the rule 1.0.10-1.0.19 applied at the child's first load; P88 moved it here.
    ///
    /// Otherwise truncating the source's chat history is exact only when that history starts from the same compaction
    /// as the cut (or neither has one). The source's history starts from the latest compaction on its live timeline:
    /// its transcript with every rewound branch filtered out, as the copy filters the cut. When the two differ, the
    /// source's history is a summary made after the cut, and the copy is refused with an error (P111, DI-04): a child
    /// that silently inherits a summary of turns after its fork point would act on work it never did. The same rule
    /// decides when a missing or damaged checkpoint makes the cut unreplayable (1.0.20 failed such a child at its first
    /// load). Only markers are compared, so a damaged checkpoint on an abandoned branch decides nothing.
    fn chat_for_compacted_cut(
        &self,
        source_info: &Info,
        cut_updates: &Path,
        target_prompt_index: usize,
        source_chat: &[ConversationItem],
        source_updates_len: u64,
    ) -> io::Result<Option<Vec<ConversationItem>>> {
        // Checkpoint files are named relative to the session directory; the copy brings them over later, under the
        // same names, so they are read from the source.
        let replay_error = match crate::session::helpers::replay::replay_if_latest_compaction_active(
            cut_updates,
            &self.session_dir(source_info),
        ) {
            Ok(Some(rebuilt)) => return Ok(Some(rebuilt)),
            Ok(None) => None,
            Err(error) => Some(error),
        };
        // The cut holds no rewind markers (the copy drops rewound branches), so its latest marker is its live one.
        let cut_latest = crate::session::helpers::replay::find_latest_compaction_checkpoint(cut_updates)
            .map(|latest| latest.map(|info| info.checkpoint_id));
        let source_latest = latest_live_compaction_id(&self.updates_file(source_info), source_updates_len);
        let same_compaction = matches!((&cut_latest, &source_latest), (Ok(cut), Ok(source)) if cut == source);
        // Truncating a history that starts from a compaction finds its cut by prompt markers, and turns written before
        // prompt markers existed (unmarked) cannot be placed on the transcript's prompt axis. So the truncation is
        // accepted only when the point it cuts at is proven to be the transcript's cut (see `marked_cut_is_exact`).
        let boundary_provable =
            !matches!(&cut_latest, Ok(Some(_))) || marked_cut_is_exact(source_chat, target_prompt_index);
        let exact = same_compaction && boundary_provable;
        if exact {
            if let Some(error) = &replay_error {
                // A damaged checkpoint: like a resume (L-1), the copy degrades instead of failing.
                tracing::warn!(session_id = %source_info.id.0, %error,
                    "fork: cannot rebuild the history at the cut (checkpoint unreadable); truncating the source chat \
                     history, which starts from the same compaction");
            }
            return Ok(None);
        }
        // What the message says depends on why (P114). When the cut and the session's history share their compaction,
        // the summary covers turns BEFORE the cut and the fork is already after the latest compaction: the turns after
        // the summary carry no prompt markers to cut by, and what always works is a whole-session fork.
        const SUMMARY_AFTER_CUT: &str = ", and the session's current history is a compaction summary that covers \
                                         turns after that prompt. Nothing was created. Fork at a prompt after the \
                                         latest compaction, or fork the whole session, instead.";
        let (why, advice) = match (&replay_error, &cut_latest, &source_latest) {
            _ if same_compaction => (
                format!(
                    "{}the saved history has no prompt markers to cut it by",
                    replay_error
                        .as_ref()
                        .map(|error| format!("its compaction checkpoint cannot be replayed ({error}) and "))
                        .unwrap_or_default()
                ),
                ". Nothing was created. Fork the whole session instead.",
            ),
            (Some(error), _, _) => (
                format!("a compaction checkpoint before it is missing or damaged ({error})"),
                SUMMARY_AFTER_CUT,
            ),
            (None, Err(error), _) | (None, _, Err(error)) => (
                format!("the transcript could not be read ({error})"),
                SUMMARY_AFTER_CUT,
            ),
            (None, Ok(_), Ok(_)) => (
                "it lies before the compaction the session's current history starts from".to_string(),
                SUMMARY_AFTER_CUT,
            ),
        };
        tracing::warn!(session_id = %source_info.id.0, target_prompt_index, %why,
            "fork refused: the history at the cut cannot be rebuilt exactly");
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Cannot fork at prompt #{target_prompt_index}: the conversation at that point cannot be rebuilt \
                 exactly, because {why}{advice}"
            ),
        ))
    }
}

/// The checkpoint files every compaction marker in `updates` (a transcript) names, as the copy records them; empty
/// when it does not exist. Streams the file; only lines that mention a compaction checkpoint are parsed. Only the
/// bytes in `range` (from, to) are read: the copy's snapshot is the first `to` bytes, and what was appended after
/// it is the tail the coherence check looks at (P123).
fn compaction_checkpoint_files(updates: &Path, range: (u64, Option<u64>)) -> io::Result<BTreeSet<String>> {
    let mut files = BTreeSet::new();
    let mut file = match std::fs::File::open(updates) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(files),
        Err(error) => return Err(error),
    };
    let (from, to) = range;
    file.seek(io::SeekFrom::Start(from))?;
    let len = to.map_or(u64::MAX, |to| to.saturating_sub(from));
    for_each_jsonl_line(BufReader::new(file.take(len)), |_, line| {
        if let Ok(text) = std::str::from_utf8(line)
            && text.contains("compaction_checkpoint")
            && let Ok(SessionUpdate::Fuigo(notification)) = SessionUpdateEnvelope::from_str(text)
            && let crate::extensions::notification::SessionUpdate::CompactionCheckpoint(info) = notification.update
        {
            files.insert(info.checkpoint_file);
        }
        Ok(ControlFlow::Continue(()))
    })?;
    Ok(files)
}

/// The contents of `path`, or `None` when it does not exist.
fn read_optional(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Length and SHA-256 of `bytes`.
fn chat_fingerprint_of(bytes: &[u8]) -> (u64, String) {
    use sha2::Digest;
    (bytes.len() as u64, format!("{:x}", sha2::Sha256::digest(bytes)))
}

/// Length and SHA-256 of `path`, or `None` when it does not exist.
#[cfg(test)]
fn chat_file_fingerprint(path: &Path) -> io::Result<Option<(u64, String)>> {
    Ok(read_optional(path)?.as_deref().map(chat_fingerprint_of))
}

/// Whether `path` still starts with the bytes `seen` fingerprinted (only appended to since), or `seen` is `None`.
fn chat_file_still_starts_with(path: &Path, seen: Option<&(u64, String)>) -> io::Result<bool> {
    use sha2::Digest;
    let Some((len, sha)) = seen else {
        return Ok(true);
    };
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    Ok(bytes.len() as u64 >= *len && format!("{:x}", sha2::Sha256::digest(&bytes[..*len as usize])) == *sha)
}

/// Whether truncating `chat` (a history that starts from a compaction) for a fork at `target_prompt_index` keeps
/// exactly the turns up to and including that prompt, which is where the transcript copy cuts (P111, DI-04).
///
/// The truncation keeps everything before the first user turn it decides belongs after the target. That point is the
/// transcript's cut, provably, in two cases only:
/// - the item it cuts at is the marked user turn of prompt `target_prompt_index + 1`: the history is chronological, so
///   every turn before it, marked or not, is at or before the target;
/// - the target's own user turn is marked and no unmarked turn follows it before the cut: everything kept after the
///   target's turn is part of that turn.
///
/// Anything else is refused by the caller. In particular a history with unmarked turns after its summary (written
/// before prompt markers) followed by marked ones: the truncation cuts at the first marker past the target, keeping
/// the unmarked turns between the target and that marker (Astra r4).
fn marked_cut_is_exact(chat: &[ConversationItem], target_prompt_index: usize) -> bool {
    let keep = conversation_truncate_for_prompt(chat, target_prompt_index + 1);
    if let Some(ConversationItem::User(user)) = chat.get(keep)
        && user.prompt_index == Some(target_prompt_index + 1)
    {
        return true;
    }
    let Some(target_turn) = chat[..keep].iter().position(
        |item| matches!(item, ConversationItem::User(user) if user.prompt_index == Some(target_prompt_index)),
    ) else {
        return false;
    };
    // An unmarked user item that opens a turn by the pre-marker rules (a typed prompt, or a synthetic that starts a
    // turn) after the target's marked turn is a later prompt the truncation would keep.
    !chat[target_turn + 1..keep].iter().any(|item| {
        matches!(item, ConversationItem::User(user) if user.prompt_index.is_none()
            && user.synthetic_reason.as_ref().is_none_or(|reason| reason.starts_prompt_turn()))
    })
}

/// Id of the latest compaction marker on the live timeline of `updates` (rewound branches filtered out the way a
/// point-in-time copy filters them), or `None` when it has none. Only the first `limit` bytes are read: the copy's
/// snapshot of the transcript.
fn latest_live_compaction_id(updates: &Path, limit: u64) -> io::Result<Option<String>> {
    struct LineRecord {
        step: RewindStep,
        checkpoint_id: Option<String>,
    }
    let file = match std::fs::File::open(updates) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut records = Vec::new();
    for_each_jsonl_line(BufReader::new(file.take(limit)), |_, line| {
        let text = std::str::from_utf8(line).ok();
        let step = text.map_or(RewindStep::Other, rewind_step_for_line);
        let checkpoint_id = text
            .filter(|text| text.contains("compaction_checkpoint"))
            .and_then(|text| SessionUpdateEnvelope::from_str(text).ok())
            .and_then(|update| match update {
                SessionUpdate::Fuigo(notification) => match notification.update {
                    crate::extensions::notification::SessionUpdate::CompactionCheckpoint(info) => {
                        Some(info.checkpoint_id)
                    }
                    _ => None,
                },
                SessionUpdate::Acp(_) => None,
            });
        records.push(LineRecord { step, checkpoint_id });
        Ok(ControlFlow::Continue(()))
    })?;
    Ok(filter_rewind_by(records, |record| record.step)
        .into_iter()
        .rev()
        .find_map(|record| record.checkpoint_id))
}

/// Name prefix of the staging directories copies make next to the target session. The leading dot keeps them out of
/// the session listings and the relocation scan, which skip dot entries at that level.
const FORK_STAGING_PREFIX: &str = ".fuigo-fork-staging-";

/// The lock file inside a staging directory, held exclusively while its copy runs.
const FORK_STAGING_LOCK: &str = ".lock";

/// The name the lock file has until its lock is held.
const FORK_STAGING_LOCK_INIT: &str = ".lock.init";

/// A staging directory older than this whose lock is free was left by a copy whose process died.
const STALE_FORK_STAGING_AGE: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// A copy's staging directory. The lock is released (and closed) before the directory is removed.
struct ForkStaging {
    _lock: std::fs::File,
    dir: tempfile::TempDir,
    /// Declared last, so it runs after the staging directory is gone.
    _created_cwd_dir: CreatedCwdDir,
}

/// The target's `<encoded-cwd>` directory, when THIS fork created it ([`claim_cwd_dir`] makes the claim with an
/// exclusive `create_dir`, so "created" is exact). A refused fork must not leave it behind empty (P132); it is removed
/// on drop with `remove_dir`, which only succeeds on an EMPTY directory, so a session (or anything else) that arrived
/// in the meantime keeps it. A successful fork has put the session in it. Nothing inside is ever deleted: a hash-encoded
/// cwd's `.cwd` marker keeps its directory (a few bytes), because taking the marker away could race with another
/// session that has already checked for it.
struct CreatedCwdDir(Option<PathBuf>);

impl Drop for CreatedCwdDir {
    fn drop(&mut self) {
        if let Some(dir) = self.0.take() {
            let _ = std::fs::remove_dir(&dir);
        }
    }
}

/// Create `dir` and say whether THIS call made `dir`: parents first (owner-only ones for the sessions tree, plain ones
/// for a caller-owned explicit directory, whose ancestors keep their permissions), then one exclusive `create_dir`, so
/// a directory another process makes first is never claimed.
fn claim_cwd_dir(dir: &Path, owner_only_parents: bool) -> io::Result<bool> {
    if let Some(parent) = dir.parent() {
        if owner_only_parents {
            crate::util::fuigo_home::create_dir_all_owner_only(parent)?;
        } else {
            std::fs::create_dir_all(parent)?;
        }
    }
    match std::fs::create_dir(dir) {
        Ok(()) => {
            crate::util::fuigo_home::set_dir_owner_only(dir);
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error),
    }
}

impl JsonlStorageAdapter {
    /// The private directory a copy stages its transcript in (P114): next to the target's session directory, so the
    /// move into the target is a rename on one filesystem and the transcript is written once, with no dependence on the
    /// system temp dir (missing, full, unwritable or RAM-backed). The target's CWD directory is made the way the target
    /// itself is (owner-only, with the sessions root repaired), before anything is staged. The directory is removed
    /// when the returned guard drops, on every path; one left by a process that died is removed by a later copy.
    fn fork_staging_dir(&self, target_info: &Info) -> io::Result<ForkStaging> {
        let (parent, created) = match &self.dir_mode {
            super::SessionDirMode::FromRoot(root) => {
                let cwd_dir = crate::util::fuigo_home::sessions_cwd_dir_in(root, &target_info.cwd);
                let claimed = claim_cwd_dir(&cwd_dir, true)?;
                let created = CreatedCwdDir(claimed.then_some(cwd_dir));
                let parent = crate::util::fuigo_home::ensure_sessions_cwd_dir_in(root, &target_info.cwd)?;
                (parent, created)
            }
            super::SessionDirMode::Explicit(dir) => {
                let parent = dir.parent().map_or_else(|| dir.clone(), Path::to_path_buf);
                let claimed = claim_cwd_dir(&parent, false)?;
                (parent.clone(), CreatedCwdDir(claimed.then(|| parent.clone())))
            }
        };
        remove_stale_fork_staging(&parent);
        match private_staging_dir(&parent) {
            Ok(mut staging) => {
                staging._created_cwd_dir = created;
                Ok(staging)
            }
            // `created` drops here, removing a directory this call made.
            Err(error) => Err(io::Error::new(
                error.kind(),
                format!("cannot create the fork's staging directory in {}: {error}", parent.display()),
            )),
        }
    }
}

/// Best effort: remove staging directories in `parent` left by copies whose process died. A directory is removed only
/// when it is old AND its lock file opens AND its lock is free: a live copy holds its lock for as long as it runs,
/// however long that is (a suspended process included). One without a lock file is kept (its copy may not have made
/// it yet).
fn remove_stale_fork_staging(parent: &Path) {
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let old = entry.file_name().to_string_lossy().starts_with(FORK_STAGING_PREFIX)
            && entry.file_type().is_ok_and(|kind| kind.is_dir())
            && entry
                .metadata()
                .and_then(|meta| meta.modified())
                .is_ok_and(|modified| modified.elapsed().is_ok_and(|age| age > STALE_FORK_STAGING_AGE));
        if !old {
            continue;
        }
        // Only positive evidence that its copy is gone counts: the lock file opens (read-only, so its permissions do not
        // matter) and its lock is free. A directory whose lock cannot be opened or taken is kept (P114 r2 #4).
        let Ok(lock) = std::fs::OpenOptions::new().read(true).open(entry.path().join(FORK_STAGING_LOCK)) else {
            continue;
        };
        if fs2::FileExt::try_lock_exclusive(&lock).is_err() {
            continue;
        }
        drop(lock);
        if let Err(error) = std::fs::remove_dir_all(entry.path()) {
            tracing::warn!(path = %entry.path().display(), %error, "could not remove a stale fork staging directory");
        }
    }
}

/// A private directory in `parent` for a staged cut, locked for as long as the returned guard lives: the transcript is
/// session content, so other local users must not be able to read it while it is staged (owner-only on Unix).
fn private_staging_dir(parent: &Path) -> io::Result<ForkStaging> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(FORK_STAGING_PREFIX);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let dir = builder.tempdir_in(parent)?;
    // The lock is taken under another name and only then renamed to `.lock` (the lock stays with the open file), so a
    // `.lock` a sweep can open is always one its copy has locked at some point: a copy suspended before it holds its
    // lock has no `.lock` yet, and the sweep keeps its directory (P114 r3 #2).
    let initializing = dir.path().join(FORK_STAGING_LOCK_INIT);
    let lock = fuigo_config::owner_only_file_options(
        std::fs::OpenOptions::new().read(true).write(true).create_new(true),
    )
    .open(&initializing)?;
    fs2::FileExt::lock_exclusive(&lock)?;
    std::fs::rename(&initializing, dir.path().join(FORK_STAGING_LOCK))?;
    Ok(ForkStaging { _lock: lock, dir, _created_cwd_dir: CreatedCwdDir(None) })
}

/// Move the staged cut into the new session: a rename (the staging directory is on the target's filesystem), with a
/// copy as the fallback should the rename still fail.
fn move_staged_file(staged: &Path, target: &Path) -> io::Result<()> {
    match std::fs::rename(staged, target) {
        Ok(()) => Ok(()),
        Err(_) => {
            super::super::owner_only::copy(staged, target)?;
            Ok(())
        }
    }
}

/// Counters produced by this copy that feed the fork target's summary, named so the same-typed counts cannot transpose.
struct ForkCounters {
    num_messages: usize,
    num_chat_messages: usize,
    cwd_switch_bookkeeping_generation: u64,
    inherited_prefix_len: Option<usize>,
}

/// Build the fork target's summary: counters from this copy, fork identity from `options`.
/// Every other field is either inherited from the source or reset as for a fresh session.
fn fork_summary(
    source: Summary,
    target_info: &Info,
    options: &CopySessionOptions,
    counters: ForkCounters,
) -> Summary {
    let target_worktree_identity =
        crate::session::worktree::worktree_identity_for_cwd(&target_info.cwd);
    let mut summary = Summary {
        info: target_info.clone(),
        cwd_generation: source.cwd_generation,
        previous_cwd: source.previous_cwd,
        pending_cwd_switch_reminder: None,
        cwd_switch_bookkeeping_generation: counters.cwd_switch_bookkeeping_generation,
        session_summary: source.session_summary,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        num_messages: counters.num_messages,
        num_chat_messages: counters.num_chat_messages,
        current_model_id: options
            .new_model_id
            .clone()
            .map(acp::ModelId::new)
            .unwrap_or(source.current_model_id),
        parent_session_id: options.parent_session_id.clone(),
        forked_at: Some(chrono::Utc::now()),
        collection_id: None,
        next_trace_turn: 0,
        chat_format_version: CHAT_FORMAT_VERSION,
        prompt_display_cwd: options.prompt_display_cwd.clone(),
        session_kind: Some(
            options
                .session_kind
                .clone()
                .unwrap_or_else(|| "fork".to_string()),
        ),
        fork_context_source: options.fork_context_source.clone(),
        fork_parent_prompt_id: options.fork_parent_prompt_id.clone(),
        inherited_prefix_len: counters.inherited_prefix_len,
        hidden: None,
        source_workspace_dir: options.source_workspace_dir.clone(),
        git_root_dir: None,
        git_remotes: Vec::new(),
        head_commit: source.head_commit,
        head_branch: source.head_branch,
        request_id: None,
        // Fresh local fuigo_home, not inherited from source: the fork lives on this machine.
        fuigo_home: crate::session::persistence::fuigo_home_string(),
        last_active_at: source.last_active_at,
        generated_title: source.generated_title,
        // A fork keeps the parent's title, so whether that title was set manually carries over too
        title_is_manual: source.title_is_manual,
        // Re-derived from the target path, never inherited: the source's label describes the parent's worktree, not this one
        worktree_label: target_worktree_identity
            .as_ref()
            .map(|identity| identity.label.clone()),
        agent_name: source.agent_name,
        sandbox_profile: source.sandbox_profile,
        reasoning_effort: source.reasoning_effort,
        // Full forks keep the parent's last turn
        // Partial forks (`target_prompt_index`) may drop that turn, so clear the summary rather than showing work not in the child conversation
        last_turn_summary: if options.target_prompt_index.is_some() {
            None
        } else {
            source.last_turn_summary
        },
        last_turn_summary_prompt_id: if options.target_prompt_index.is_some() {
            None
        } else {
            source.last_turn_summary_prompt_id
        },
        // A recap describes the parent's whole session; a partial fork may not contain that work, so clear it there and keep it for full forks
        last_recap: if options.target_prompt_index.is_some() {
            None
        } else {
            source.last_recap
        },
    };
    if options.session_kind.is_none()
        && let Some(identity) = &target_worktree_identity
    {
        summary.stamp_worktree_identity(identity);
        // An explicitly provided source still wins over the derived one.
        if let Some(source_workspace_dir) = &options.source_workspace_dir {
            summary.source_workspace_dir = Some(source_workspace_dir.clone());
        }
    }
    summary
}

/// Remove `announced_failed_servers` from a copied `announcement_state.json`, preserving every other field (including ones this build doesn't know).
/// A file that doesn't parse is left as copied: the next persist rewrites it.
fn clear_announced_failure_episodes(path: &Path) -> io::Result<()> {
    let bytes = std::fs::read(path)?;
    let Ok(mut state) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Ok(());
    };
    let Some(fields) = state.as_object_mut() else {
        return Ok(());
    };
    if fields.remove("announced_failed_servers").is_none() {
        return Ok(());
    }
    crate::session::storage::write_bytes_atomic(
        path,
        &serde_json::to_vec(&state).map_err(invalid_data)?,
    )
}

fn clip_copied_signals_turns(path: &Path, max_turn: u32) -> io::Result<()> {
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let Ok(mut signals) = serde_json::from_slice::<crate::session::signals::SessionSignals>(&data)
    else {
        return Ok(());
    };
    if signals.turn_count > max_turn {
        signals.turn_count = max_turn;
    }
    if signals.user_message_count > max_turn {
        signals.user_message_count = max_turn;
    }
    if signals.assistant_message_count > max_turn {
        signals.assistant_message_count = max_turn;
    }
    crate::session::storage::write_bytes_atomic(
        path,
        &serde_json::to_vec(&signals).map_err(invalid_data)?,
    )
}

fn seed_signals_turn_from_usage(usage_path: &Path, signals_path: &Path) -> io::Result<()> {
    let data = match std::fs::read(usage_path) {
        Ok(data) => data,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let Ok(file) = serde_json::from_slice::<crate::session::usage_file::SessionUsageFile>(&data)
    else {
        return Ok(());
    };
    let Some(max_turn) = file.turns.iter().map(|turn| turn.turn_number).max() else {
        return Ok(());
    };
    let signals = crate::session::signals::SessionSignals {
        turn_count: max_turn,
        user_message_count: max_turn,
        ..Default::default()
    };
    crate::session::storage::write_bytes_atomic(
        signals_path,
        &serde_json::to_vec(&signals).map_err(invalid_data)?,
    )
}

fn restamp_copied_usage(
    path: &Path,
    session_id: &acp::SessionId,
    max_turn: Option<u32>,
) -> io::Result<()> {
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let Ok(mut file) =
        serde_json::from_slice::<crate::session::usage_file::SessionUsageFile>(&data)
    else {
        return Ok(());
    };
    file.session_id = session_id.to_string();
    if let Some(max_turn) = max_turn {
        file.retain_turns_through(max_turn);
    }
    crate::session::storage::write_bytes_atomic(
        path,
        &serde_json::to_vec_pretty(&file).map_err(invalid_data)?,
    )
}

/// Copy one optional sidecar file (plan, signals, tool state, ...) when enabled and present; reports whether a copy happened.
/// A sidecar that exists but is not a regular file is skipped with a warning rather than failing the fork.
fn copy_sidecar_file(enabled: bool, src: &Path, dst: &Path) -> io::Result<bool> {
    if !enabled {
        return Ok(false);
    }
    if !src.is_file() {
        if src.exists() {
            tracing::warn!(
                path = %src.display(),
                "sidecar is not a regular file; skipping copy",
            );
        }
        return Ok(false);
    }
    super::super::owner_only::copy(src, dst)?;
    Ok(true)
}

/// Copy the `compaction_checkpoints/{uuid}.json` files referenced by the retained records; returns how many copied.
/// Records are user-editable data, so only the exact path shape this feature writes may resolve and symlinks are never followed.
/// Dangling references are skipped rather than failing the fork (otherwise every /rewind in the target session would fail).
fn copy_referenced_checkpoints(
    checkpoint_files: &BTreeSet<String>,
    source_session_dir: &Path,
    target_dir: &Path,
    source_id: &acp::SessionId,
) -> io::Result<usize> {
    if checkpoint_files.is_empty() {
        return Ok(0);
    }
    // The per-file `symlink_metadata` below only vets the final path component
    // So the intermediate `compaction_checkpoints` dir must itself be a real directory
    // A symlinked dir would resolve every matching name outside the session
    match std::fs::symlink_metadata(source_session_dir.join("compaction_checkpoints")) {
        Ok(meta) if meta.file_type().is_dir() => {}
        Ok(meta) => {
            tracing::warn!(
                file_type = ?meta.file_type(),
                session_id = %source_id,
                "compaction_checkpoints is not a real directory; skipping checkpoint copy",
            );
            return Ok(0);
        }
        // Dir gone means every record is dangling; same policy as a missing checkpoint file
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            tracing::warn!(
                session_id = %source_id,
                "compaction_checkpoints directory missing; skipping checkpoint copy",
            );
            return Ok(0);
        }
        Err(error) => return Err(error),
    }
    let mut copied = 0usize;
    for checkpoint_file in checkpoint_files {
        let relative = Path::new(checkpoint_file);
        // A doctored record path must not address other session files (e.g. the fork's rewritten updates.jsonl).
        let well_formed = relative.parent() == Some(Path::new("compaction_checkpoints"))
            && relative.extension() == Some("json".as_ref());
        if !well_formed {
            tracing::warn!(
                checkpoint_file = %checkpoint_file,
                session_id = %source_id,
                "skipping compaction checkpoint with unexpected path during copy",
            );
            continue;
        }
        let src = source_session_dir.join(relative);
        match std::fs::symlink_metadata(&src) {
            Ok(meta) if meta.file_type().is_file() => {}
            Ok(meta) => {
                // This feature only ever writes regular files, so don't follow symlinks planted in the source session
                tracing::warn!(
                    path = %src.display(),
                    file_type = ?meta.file_type(),
                    session_id = %source_id,
                    "compaction checkpoint source is not a regular file; skipping copy",
                );
                continue;
            }
            // Already-dangling record (e.g. a chained fork of a broken session): the copy can't invent the file, so don't fail.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                tracing::warn!(
                    path = %src.display(),
                    session_id = %source_id,
                    "compaction checkpoint file missing from source; skipping copy",
                );
                continue;
            }
            Err(error) => return Err(error),
        }
        // Read through the checkpoint reader, which never follows a symlink even one swapped in after the check
        // above (P146); a file it refuses is skipped like a missing one.
        let bytes = match crate::extensions::notification::read_contained_checkpoint(source_session_dir, checkpoint_file) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                tracing::warn!(path = %src.display(), session_id = %source_id, %error,
                    "compaction checkpoint refused or missing; skipping copy");
                continue;
            }
            Err(error) => return Err(error),
        };
        let dst = target_dir.join(relative);
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        super::super::owner_only::write(&dst, &bytes)?;
        copied += 1;
    }
    Ok(copied)
}

fn invalid_data(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
