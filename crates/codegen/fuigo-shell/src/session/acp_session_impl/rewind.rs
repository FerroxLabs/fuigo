//! Rewind concern for `SessionActor`: rewind points, cross-compaction replay detection, and `handle_rewind`.

use super::*;

/// How long a rewind waits for the persistence actor to start one of its rewind_points requests (P146). Once started,
/// a request is bounded by the storage's own lock wait.
const REWIND_POINTS_QUEUE_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

impl SessionActor {
    pub(super) async fn close_rewind_window(&self) {
        let mut state = self.state.lock().await;
        state.rewindable = false;
    }

    /// Returns the `prompt_index → num_file_snapshots` map from the on-disk snapshot index (independent of the chat-state prompt index).
    /// The bridge joins these onto the server's rewind points.
    pub(super) async fn rewind_file_counts(&self) -> std::collections::HashMap<usize, usize> {
        self.file_state_tracker
            .get_rewind_point_metas()
            .await
            .into_iter()
            .map(|m| (m.prompt_index, m.num_file_snapshots))
            .collect()
    }

    /// Get available rewind points for this session.
    ///
    /// Every prompt is a checkpoint: the list always contains `[0, 1, ..., N-1]` where N is the current prompt_index.
    /// File snapshots may or may not exist for each checkpoint (indicated by `has_file_changes`).
    pub(super) async fn get_rewind_points(&self) -> RewindPointsResponse {
        // Metadata only: don't load the (huge) file-content snapshots just to render the picker
        let file_metas = self.file_state_tracker.get_rewind_point_metas().await;

        // Query prompt state from the chat state actor.
        let snapshot = self.chat_state_handle.snapshot().await;
        let (prompts, current_prompt_index) = match snapshot {
            Some(ref s) => (s.prompt_texts.clone(), s.prompt_index),
            None => (vec![], 0),
        };

        // Build a lookup of which prompt indices have file snapshots.
        let file_meta_map: std::collections::HashMap<
            usize,
            &fuigo_workspace::session::file_state::RewindPointMeta,
        > = file_metas.iter().map(|m| (m.prompt_index, m)).collect();

        // Generate a rewind point for every prompt 0..current_prompt_index.
        let rewind_points = (0..current_prompt_index)
            .map(|idx| {
                let prompt_preview = prompts.get(idx).and_then(|text| {
                    let clean_text = extract_user_query(text);
                    let first_line = clean_text
                        .lines()
                        .map(|l| l.trim())
                        .find(|l| !l.is_empty())
                        .unwrap_or("");

                    if first_line.is_empty() {
                        None
                    } else if first_line.chars().count() > 60 {
                        Some(format!("{}...", crate::util::truncate(first_line, 57)))
                    } else {
                        Some(first_line.to_string())
                    }
                });

                let file_meta = file_meta_map.get(&idx);
                let num_file_snapshots = file_meta.map_or(0, |m| m.num_file_snapshots);
                let created_at = file_meta
                    .map(|m| m.created_at.to_rfc3339())
                    .unwrap_or_default();

                RewindPointInfo {
                    prompt_index: idx,
                    created_at,
                    num_file_snapshots,
                    has_file_changes: num_file_snapshots > 0,
                    prompt_preview,
                }
            })
            .collect();

        RewindPointsResponse { rewind_points }
    }

    /// Load user prompts from `updates.jsonl` in chronological order.
    ///
    /// Each `UserMessageChunk` sequence is merged into a single prompt string.
    /// `RewindMarker` entries truncate the list back to the marker's target so only prompts from the current timeline are returned.
    ///
    /// Uses [`PromptExtractIterator`] which peeks at the `update.sessionUpdate` discriminant field without fully deserialising every notification.
    /// This skips large `acp::SessionNotification` allocations for the many update types (tool calls, assistant chunks) prompt extraction ignores.
    pub(super) fn load_user_prompts_from_updates(
        updates_path: &std::path::Path,
    ) -> std::io::Result<Vec<String>> {
        use crate::session::storage::{PromptExtractIterator, collect_prompts_from_events};

        let Some(iter) = PromptExtractIterator::open(updates_path)? else {
            return Ok(vec![]);
        };

        tracing::debug!(
            path = %updates_path.display(),
            "load_user_prompts_from_updates: starting selective scan"
        );

        let prompts = collect_prompts_from_events(iter);

        tracing::debug!(
            prompt_count = prompts.len(),
            "load_user_prompts_from_updates: done"
        );

        Ok(prompts)
    }

    /// Check whether a rewind must replay `updates.jsonl` to reconstruct the conversation: replay whenever a compaction has occurred.
    ///
    /// Compaction collapses N+1 user messages into ~3, so the conversation in memory no longer has the User count `prompt_index` implies.
    /// `truncate_to_prompt_index` counts User items to find the cut point, so it is wrong for ALL post-compaction targets, not just at the boundary.
    /// `replay_to_prompt` reads `updates.jsonl` from scratch and handles compaction checkpoints correctly, whatever the target position.
    async fn needs_compaction_replay(&self) -> bool {
        let last = self
            .chat_state_handle
            .snapshot()
            .await
            .and_then(|s| s.last_compaction_prompt_index);
        match last {
            Some(compaction_at) => {
                tracing::info!(
                    compaction_at,
                    "Compaction detected — using replay for rewind"
                );
                true
            }
            None => false,
        }
    }

    /// Handle a rewind request with mode support.
    ///
    /// "Rewind to N" restores the state from before prompt N ran; prompts 0..N-1 are kept.
    ///
    /// Modes:
    /// - `All`: roll back both conversation and files
    /// - `ConversationOnly`: roll back conversation, leave files untouched
    /// - `FilesOnly`: roll back files, leave conversation untouched
    pub(super) async fn handle_rewind(
        &self,
        request: RewindRequest,
    ) -> anyhow::Result<RewindResponse> {
        let target_index = request.target_prompt_index;
        let mode = request.mode;
        let wants_file_revert = matches!(mode, RewindMode::All | RewindMode::FilesOnly);
        let wants_conversation_rewind =
            matches!(mode, RewindMode::All | RewindMode::ConversationOnly);
        // A conversation rewind rewrites chat_history.jsonl without an acknowledgement. While a load-time repair still
        // owes its backup that rewrite is refused, and memory and transcript would show the rewind while the file kept
        // the dropped turns (P96). Refuse before anything changes, files included.
        if wants_conversation_rewind
            && let Some(error) = crate::session::storage::jsonl::load_repair::history_rewrite_refusal(
                &self.session_info,
                "rewind the conversation",
            )
        {
            tracing::warn!(session_id = %self.session_info.id, %error, "rewind refused");
            return Ok(RewindResponse {
                success: false,
                target_prompt_index: target_index,
                mode,
                reverted_files: vec![],
                clean_files: vec![],
                conflicts: vec![],
                prompt_text: None,
                error: Some(error),
            });
        }
        self.signals_handle().mark_reverted();

        let _strip_guard = if request.force && wants_conversation_rewind {
            Some(self.prepare_image_strips_for_rewind().await)
        } else {
            None
        };

        // Validate: target must be less than current prompt_index
        // FilesOnly reverts the on-disk snapshot index (bounded by `get_rewind_points`, not the conversation), so it is exempt
        // In bridge mode the conversation lives server-side and the chat-state prompt index is empty
        let current_prompt_index = self.chat_state_handle.get_prompt_index().await;
        if mode != RewindMode::FilesOnly && target_index >= current_prompt_index {
            return Ok(RewindResponse {
                success: false,
                target_prompt_index: target_index,
                mode,
                reverted_files: vec![],
                clean_files: vec![],
                conflicts: vec![],
                prompt_text: None,
                error: Some(format!(
                    "Cannot rewind to prompt #{} — current prompt index is {}. \
                     Valid targets: 0..{}",
                    target_index,
                    current_prompt_index,
                    current_prompt_index.saturating_sub(1)
                )),
            });
        }

        // ── Build file revert preview (for All and FilesOnly modes) ─────
        let mut clean_files = Vec::new();
        let mut conflicts = Vec::new();

        // Collect files that would be reverted and detect conflicts; this is read-only
        let mut files_to_revert: std::collections::HashMap<
            fuigo_workspace::session::file_state::FlexiblePath,
            Option<String>,
        > = std::collections::HashMap::new();

        if wants_file_revert {
            // The saved file contents of a resumed session load lazily. A read that fails must stop the rewind here:
            // planning from the in-memory points alone would skip the unloaded files, rewind the conversation, and a
            // later successful load inside `truncate_from` would then drop those snapshots (P111).
            // A damaged row stops only the rewinds that may need it, and the refusal says which still work (P114).
            let all_points = match self.file_state_tracker.try_get_rewind_points_for(target_index).await {
                Ok(points) => points,
                Err(unavailable) => {
                    // FilesOnly targets are not bounded by the conversation (in bridge mode it is not even here).
                    let valid_targets_below = (mode != RewindMode::FilesOnly).then_some(current_prompt_index);
                    return Ok(RewindResponse {
                        success: false,
                        target_prompt_index: target_index,
                        mode,
                        reverted_files: vec![],
                        clean_files: vec![],
                        conflicts: vec![],
                        prompt_text: None,
                        error: Some(unavailable.refusal_message(target_index, valid_targets_below, true)),
                    });
                }
            };

            for point in all_points.iter().filter(|p| p.prompt_index >= target_index) {
                for (path, before_snapshot) in &point.file_snapshots {
                    // Only keep the earliest snapshot for each file
                    files_to_revert
                        .entry(path.clone())
                        .or_insert_with(|| before_snapshot.content.clone());
                }
            }

            // Build conflict/clean lists for the preview
            for path in files_to_revert.keys() {
                let current_content = self
                    .tool_context
                    .fs
                    .try_read_to_string(path)
                    .await
                    .unwrap_or(None);

                // Find the latest after_snapshot for this file (what the agent most recently left it as) for conflict detection
                let after_content = all_points
                    .iter()
                    .rev()
                    .find_map(|p| p.after_snapshots.get(path))
                    .and_then(|s| s.content.clone());

                let is_clean = current_content == after_content;

                if is_clean {
                    clean_files.push(path.to_string());
                } else {
                    let conflict_type = if current_content.is_none() && after_content.is_some() {
                        "deleted_externally"
                    } else if current_content.is_some() && after_content.is_none() {
                        "created_externally"
                    } else {
                        "modified_externally"
                    };
                    conflicts.push(RewindConflictInfo {
                        path: path.to_string(),
                        conflict_type: conflict_type.to_string(),
                    });
                }
            }
        }

        // ── Preview mode (force=false): pure dry run, no mutations ────
        // Return what WOULD happen so the TUI can show a confirmation modal
        if !request.force {
            let error = if !conflicts.is_empty() {
                Some("External modifications detected. Confirm to revert anyway.".to_string())
            } else {
                None
            };
            return Ok(RewindResponse {
                success: false,
                target_prompt_index: target_index,
                mode,
                reverted_files: vec![],
                clean_files,
                conflicts,
                prompt_text: None,
                error,
            });
        }

        // ── Commit mode (force=true): execute the rewind ─────────────

        // Everything that can fail without touching the project comes first (P111, DI-01). The target conversation is
        // built before any project file is restored or deleted: a rewind across a compaction replays updates.jsonl and
        // reads checkpoint files, and when that fails nothing may have changed on disk.
        let planned_conversation = if wants_conversation_rewind {
            match self.plan_conversation_rewind(target_index).await? {
                Ok(plan) => Some(plan),
                Err(error) => {
                    return Ok(RewindResponse {
                        success: false,
                        target_prompt_index: target_index,
                        mode,
                        reverted_files: vec![],
                        clean_files: vec![],
                        conflicts: vec![],
                        prompt_text: None,
                        error: Some(error),
                    });
                }
            }
        } else {
            None
        };

        // Every forced rewind rewrites rewind_points.jsonl (a file rewind drops the undone prompts' saved file versions,
        // a conversation-only rewind folds them). Its lock is taken now, before anything changes, and held until the
        // rewind is done: another Fuigo process stuck holding it refuses the rewind here with nothing changed, instead
        // of the rewrite being dropped after the rewind was reported done (P146, K19). Every early return below drops
        // the lock.
        let rewind_points_lock = match self.lock_rewind_points_for_rewind().await {
            Ok(lock) => lock,
            Err(error) => {
                tracing::warn!(%error, target_index, "rewind refused: rewind_points.jsonl cannot be rewritten now");
                return Ok(RewindResponse {
                    success: false,
                    target_prompt_index: target_index,
                    mode,
                    reverted_files: vec![],
                    clean_files: vec![],
                    conflicts: vec![],
                    prompt_text: None,
                    error: Some(format!(
                        "Rewind to prompt #{target_index} was not started: this session's saved file history \
                         (rewind_points.jsonl) could not be locked for the rewind ({error}). Another Fuigo process \
                         may be writing it. Nothing was changed; run the same rewind again."
                    )),
                });
            }
        };

        // A durable copy left by an earlier rewind that did not finish (P146): rewind_points.jsonl may have lost rows
        // only that copy still holds. Refused, with what to do, before anything changes.
        let pre_rewind = crate::session::storage::rewind_points_pre_rewind_copy(
            &crate::session::persistence::session_dir(&self.session_info).join("rewind_points.jsonl"),
        );
        // `symlink_metadata`, never `exists()`: a link planted at that path (even a dangling one) is a leftover, and is
        // never followed.
        if pre_rewind.symlink_metadata().is_ok() {
            return Ok(RewindResponse {
                success: false,
                target_prompt_index: target_index,
                mode,
                reverted_files: vec![],
                clean_files: vec![],
                conflicts: vec![],
                prompt_text: None,
                error: Some(format!(
                    "Rewind to prompt #{target_index} was not started: an earlier rewind of this session did not \
                     finish, and {} holds this session's saved file history from before it. Delete it; move it \
                     over rewind_points.jsonl only if the transcript still shows the turns that rewind should have \
                     removed. Then run the rewind again. Nothing was changed.",
                    pre_rewind.display()
                )),
            });
        }

        // The journal the rewrite below writes before its durable copy names the conversation this rewind saves (P164,
        // K19), so that a load after Fuigo is killed in the middle of the rewind can tell whether it went through. The
        // fingerprint is of the bytes the save writes; a conversation that cannot be written that way could not be
        // saved either, so the rewind is refused here with nothing changed.
        // The RewindMarker's timestamp is chosen now and named in the journal too: that marker, and no other, shows
        // this rewind went through.
        let marker_created_at = chrono::Utc::now().to_rfc3339();
        let conversation_commit = match &planned_conversation {
            None => None,
            Some(plan) => match crate::session::storage::ContentFingerprint::of_jsonl(&plan.conversation) {
                Ok(after) => Some(crate::session::storage::RewindConversation {
                    after,
                    marker_created_at: marker_created_at.clone(),
                }),
                Err(error) => {
                    tracing::warn!(%error, target_index, "rewind refused: the rewound conversation cannot be written");
                    return Ok(RewindResponse {
                        success: false,
                        target_prompt_index: target_index,
                        mode,
                        reverted_files: vec![],
                        clean_files: vec![],
                        conflicts: vec![],
                        prompt_text: None,
                        error: Some(format!(
                            "Rewind to prompt #{target_index} was not started: the rewound conversation cannot be \
                             written ({error}). Nothing was changed."
                        )),
                    });
                }
            },
        };

        // Execute file revert. A file that cannot be restored or deleted is reported, never counted as reverted (DI-02).
        let mut reverted_files = Vec::new();
        let mut failed_files: Vec<(String, String)> = Vec::new();
        if wants_file_revert {
            for (rel_path, content) in files_to_revert {
                let outcome = match &content {
                    Some(data) => self
                        .tool_context
                        .fs
                        .write_file(&rel_path, data.as_bytes())
                        .await
                        .map_err(|e| format!("could not restore it: {e}")),
                    None => match self.tool_context.fs.exists(&rel_path).await {
                        Ok(false) => Ok(()),
                        Ok(true) => self
                            .tool_context
                            .fs
                            .delete_file(&rel_path)
                            .await
                            .map_err(|e| format!("could not delete it: {e}")),
                        Err(e) => Err(format!("could not check whether it exists: {e}")),
                    },
                };
                match outcome {
                    Ok(()) => reverted_files.push(rel_path.to_string()),
                    Err(reason) => {
                        tracing::warn!(path = %rel_path, %reason, "rewind: file not reverted");
                        failed_files.push((rel_path.to_string(), reason));
                    }
                }
            }
        }

        // A partial file revert stops here, before the conversation is rewound and before any rewind snapshot is dropped.
        // The conversation stays where it was and every snapshot at or after the target is kept, so the same rewind can be
        // run again once the cause is fixed: it restores the remaining files (rewriting the ones already restored with the
        // same contents) and then rewinds the conversation. Rewinding the conversation now would leave it describing a
        // point in time that some files do not match, and dropping the snapshots would lose the only saved contents of
        // the files that were not restored.
        if !failed_files.is_empty() {
            failed_files.sort();
            reverted_files.sort();
            let failures = failed_files
                .iter()
                .map(|(path, reason)| format!("{path} ({reason})"))
                .collect::<Vec<_>>()
                .join("; ");
            let restored = if reverted_files.is_empty() {
                "No file was reverted.".to_string()
            } else {
                format!("Reverted: {}.", reverted_files.join(", "))
            };
            let conversation_note = if wants_conversation_rewind {
                " The conversation was not rewound."
            } else {
                ""
            };
            return Ok(RewindResponse {
                success: false,
                target_prompt_index: target_index,
                mode,
                reverted_files,
                clean_files: vec![],
                conflicts,
                prompt_text: None,
                error: Some(format!(
                    "Rewind to prompt #{target_index} is incomplete: {} file(s) could not be reverted: {failures}. \
                     {restored}{conversation_note} The saved file contents are kept; fix the cause and run the \
                     same rewind again.",
                    failed_files.len(),
                )),
            });
        }

        // rewind_points.jsonl is rewritten first, under the lock taken above, and the rewind fails here when it cannot
        // be: the conversation stays where it was, every snapshot is kept, and the same rewind can be run again, as
        // when the rewound conversation cannot be saved below (P146, K19). Before P146 this rewrite was sent off last
        // without a reply, and a rewrite that did not land still let the rewind report success.
        let rewrite = if wants_file_revert {
            Some(crate::session::storage::RewindPointsRewrite::TruncateFrom(target_index))
        } else if wants_conversation_rewind {
            Some(crate::session::storage::RewindPointsRewrite::MergeFrom(target_index))
        } else {
            None
        };
        let files_note = |reverted_files: &mut Vec<String>| {
            reverted_files.sort();
            if !wants_file_revert {
                String::new()
            } else if reverted_files.is_empty() {
                " No file needed reverting.".to_string()
            } else {
                format!(" Files reverted: {}.", reverted_files.join(", "))
            }
        };
        let conversation_note = if wants_conversation_rewind { " The conversation was not rewound." } else { "" };
        let mut points_kept = None;
        if let Some(rewrite) = rewrite {
            match self.rewrite_rewind_points_for_rewind(rewrite, conversation_commit).await {
                Ok(kept) => points_kept = Some(kept),
                Err(error) => {
                    tracing::warn!(%error, target_index, "rewind: rewind_points.jsonl could not be rewritten");
                    let restored = files_note(&mut reverted_files);
                    return Ok(RewindResponse {
                        success: false,
                        target_prompt_index: target_index,
                        mode,
                        reverted_files,
                        clean_files: vec![],
                        conflicts,
                        prompt_text: None,
                        error: Some(format!(
                            "Rewind to prompt #{target_index} is incomplete: this session's saved file history \
                             (rewind_points.jsonl) could not be updated ({error}).{conversation_note}{restored} The \
                             saved file contents are kept; fix the cause and run the same rewind again."
                        )),
                    });
                }
            }
        }
        #[cfg(any(test, feature = "test-support"))]
        if let Some(killed) = self.killed_by_seam(crate::session::storage::rewind_crash_seam::Stage::AfterPointsRewrite) {
            return Ok(killed);
        }

        // Execute conversation rewind
        let mut prompt_text: Option<String> = None;
        if let Some(plan) = planned_conversation {
            let PlannedConversationRewind {
                conversation,
                replay_compaction_marker,
                prompt_text: planned_prompt_text,
            } = plan;
            prompt_text = planned_prompt_text;

            self.cancel_active_sampling_requests();
            self.cancel_pending_image_strips_for_rewind();
            // The rewound history must be stored before the rewind can succeed (P111, Astra r4): it is persisted
            // first, with the disk acknowledged, and only then applied in memory. A failure leaves the conversation
            // as it was and keeps every snapshot, like a partial file revert above, so the same rewind can be retried.
            if let Err(error) = self
                .chat_state_handle
                .replace_conversation_persisted(conversation)
                .await
            {
                tracing::warn!(%error, target_index, "rewind: the rewound conversation could not be saved");
                // The rewind did not go through: rewind_points.jsonl gets back what it held (P146).
                let points_note = match points_kept.take() {
                    None => String::new(),
                    Some(undo) => match self.end_rewind_points_for_rewind(undo, true).await {
                        Ok(()) => String::new(),
                        Err(restore_error) => {
                            tracing::warn!(%restore_error, target_index, "rewind: rewind_points.jsonl was not put back");
                            format!(
                                " This session's saved file history (rewind_points.jsonl) could not be put back \
                                 either ({restore_error}); what it held is kept in rewind_points.jsonl.pre-rewind \
                                 in the session folder."
                            )
                        }
                    },
                };
                let restored = files_note(&mut reverted_files);
                return Ok(RewindResponse {
                    success: false,
                    target_prompt_index: target_index,
                    mode,
                    reverted_files,
                    clean_files: vec![],
                    conflicts,
                    prompt_text: None,
                    error: Some(format!(
                        "Rewind to prompt #{target_index} is incomplete: the rewound conversation could not be saved \
                         ({error}), so the conversation was not rewound.{restored} The saved file contents are kept; \
                         fix the cause and run the same rewind again.{points_note}"
                    )),
                });
            }

            #[cfg(any(test, feature = "test-support"))]
            if let Some(killed) =
                self.killed_by_seam(crate::session::storage::rewind_crash_seam::Stage::AfterConversationSaved)
            {
                return Ok(killed);
            }

            // Store for edit-and-retry detection in the next prompt() call
            if let Ok(mut pending) = self.rewind_pending_prompt.lock() {
                *pending = prompt_text.clone();
            }
            // Use a snapshot to set the correct prompt_index and truncated prompt_texts.
            // The actor's TruncateToPromptIndex doesn't apply here because the conversation was already truncated locally
            // Instead, snapshot and restore with the corrected fields
            if let Some(mut snap) = self.chat_state_handle.snapshot().await {
                snap.prompt_index = target_index;
                snap.prompt_texts.truncate(target_index);
                // Cross-compaction rewind recomputes the marker (the rebuilt conversation may have dropped the summary)
                // Standard truncation keeps the existing marker
                let new_marker =
                    replay_compaction_marker.unwrap_or(snap.last_compaction_prompt_index);
                snap.last_compaction_prompt_index = new_marker;
                self.chat_state_handle.restore_snapshot(snap);
            }
            self.finish_conversation_rewind(target_index, marker_created_at).await;
        }

        // The rewind went through: the in-memory snapshots follow what rewind_points.jsonl now holds.
        if wants_file_revert {
            // All/FilesOnly: every file was reverted and the snapshots are now stale, so truncate them
            self.file_state_tracker.truncate_from(target_index).await;
        } else if wants_conversation_rewind {
            // ConversationOnly: files are untouched but the conversation is rewound.
            self.file_state_tracker.merge_and_remove_from(target_index).await;
        }
        #[cfg(any(test, feature = "test-support"))]
        if let Some(killed) = self.killed_by_seam(crate::session::storage::rewind_crash_seam::Stage::BeforeCleanup) {
            return Ok(killed);
        }
        // Done: the durable copy kept during the rewind goes, and the rewind points locks are released. A failure here
        // changes nothing the rewind did (the copy is only left behind).
        // If the End never ran (the persistence queue was stuck behind another process's lock and the request was
        // abandoned), the copy is removed here: the rewrite lock is still held, so nobody else can be using it, and a
        // copy left behind would refuse every later rewind over a rewind that did finish (P153).
        if let Some(undo) = points_kept.take()
            && let Err(error) = self.end_rewind_points_for_rewind(undo, false).await
        {
            tracing::warn!(%error, target_index, "rewind: rewind_points.jsonl.pre-rewind was not removed by the queue");
            let points = crate::session::persistence::session_dir(&self.session_info).join("rewind_points.jsonl");
            // No-follow: a link at that path is removed as a link, a missing path is already done. The journal goes
            // after the copy (P164).
            if let Err(error) = crate::session::storage::jsonl::rewind_reconcile::remove_copy_then_journal(&points) {
                tracing::warn!(%error, target_index, path = %points.display(), "rewind: rewind_points.jsonl.pre-rewind could not be removed");
            }
        }
        drop(rewind_points_lock);

        Ok(RewindResponse {
            success: true,
            target_prompt_index: target_index,
            mode,
            reverted_files,
            clean_files: vec![],
            conflicts,
            prompt_text,
            error: None,
        })
    }

    /// Build the conversation a rewind to `target_index` leaves, without changing anything.
    ///
    /// `Ok(Err(message))` when it cannot be built: a rewind across a compaction whose checkpoint is missing or damaged.
    /// The caller then refuses the whole rewind before any file is touched.
    async fn plan_conversation_rewind(
        &self,
        target_index: usize,
    ) -> anyhow::Result<Result<PlannedConversationRewind, String>> {
        let session_dir = crate::session::persistence::session_dir(&self.session_info);
        let updates_path = session_dir.join("updates.jsonl");

        let prompt_text = self
            .chat_state_handle
            .snapshot()
            .await
            .and_then(|snap| snap.prompt_texts.get(target_index).cloned());

        let needs_replay = self.needs_compaction_replay().await;

        let mut conversation = self.chat_state_handle.get_conversation().await;

        // Cross-compaction replay recomputes whether a compaction summary survives; `None` keeps the existing marker (standard truncation)
        let mut replay_compaction_marker: Option<Option<usize>> = None;

        if needs_replay {
            // Cross-compaction rewind: reconstruct the conversation from updates.jsonl
            // Run on the blocking pool since replay does synchronous file I/O (reading checkpoint files and scanning updates.jsonl)
            let replay_updates = updates_path.clone();
            let replay_session_dir = session_dir.clone();
            let replay_target = target_index;
            let replay_result = tokio::task::spawn_blocking(move || {
                crate::session::helpers::replay::replay_to_prompt(
                    &replay_updates,
                    &replay_session_dir,
                    replay_target,
                )
            })
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking panicked: {e}"))?;
            match replay_result {
                Ok(replay_result) => {
                    tracing::info!(
                        target_index,
                        prompt_index_reached = replay_result.prompt_index_reached,
                        conversation_len = replay_result.conversation.len(),
                        "Cross-compaction rewind: conversation reconstructed via replay"
                    );
                    // The rebuilt conversation drops the summary unless a checkpoint survived
                    // Carry the recomputed marker to the snapshot restore so the stale value isn't reused
                    replay_compaction_marker = Some(replay_result.last_compaction_prompt_index);
                    // The replay result may or may not include the session preamble (System and User(user_info)):
                    // - Checkpoint loaded (target >= compaction_at): compacted_history already has the System and User prefix; use it directly
                    // - Raw updates (target < compaction_at): replay only accumulates user/agent turns from updates.jsonl
                    //   Prepend System and the original User(user_info) so the model sees the same preamble it originally saw
                    if matches!(
                        replay_result.conversation.first(),
                        Some(ConversationItem::System(_))
                    ) {
                        conversation = replay_result.conversation;
                    } else {
                        // Keep System (index 0)
                        // Replace User(user_info) at index 1 with the original from the checkpoint if available, otherwise keep the current one
                        if let Some(ui0) = replay_result.original_user_info {
                            conversation.truncate(1); // keep System only
                            conversation.push(ConversationItem::user(ui0));
                        } else {
                            conversation.truncate(2); // keep System + current user_info
                        }
                        conversation.extend(replay_result.conversation);
                    }
                }
                Err(e) => {
                    tracing::error!(
                        ?e,
                        target_index,
                        "Cross-compaction replay failed; rewind aborted"
                    );
                    // Do NOT fall back to truncation: the post-compaction conversation has wrong user-message counts
                    // Raw replay without a checkpoint produces an oversized conversation that will exceed the context window
                    // Return a clear error so the user can pick a prompt that does not need the unreadable checkpoint
                    // P172: replay fails only when the target's own base checkpoint is unreadable; the error names it,
                    // gives the prompt range it covers and the prompts that still work
                    return Ok(Err(format!(
                        "Cannot rewind to prompt #{target_index}: {e}. Nothing was changed: no file was \
                         reverted and the conversation was not rewound."
                    )));
                }
            }
        } else {
            // Standard rewind: truncate the in-memory conversation
            // "Rewind to N" means restoring the state from before prompt N ran, keeping prompts 0..N-1; target 0 keeps only the session preamble
            let keep_count = conversation_truncate_for_prompt(&conversation, target_index);
            conversation.truncate(keep_count);
        }

        Ok(Ok(PlannedConversationRewind {
            conversation,
            replay_compaction_marker,
            prompt_text,
        }))
    }

    /// The bookkeeping after the conversation was replaced by a rewind to `target_index`: compaction suppression, MCP
    /// failure reminders, the transcript's `RewindMarker`, the turn summary and recap, and the title-refresh watermark.
    async fn finish_conversation_rewind(&self, target_index: usize, marker_created_at: String) {
        // The conversation shrank: clear budget-based (size/schema) and stale per-turn suppression so compaction can run on the smaller context
        // Account-state suppression (credit/auth sets SUPPRESS_UNTIL_SUCCESS) isn't budget-related, so it persists until a successful model call
        if self
            .compaction
            .auto_compact_suppressed
            .load(std::sync::atomic::Ordering::Relaxed)
            != crate::session::compaction_config::SUPPRESS_UNTIL_SUCCESS
        {
            self.compaction.auto_compact_suppressed.store(
                crate::session::compaction_config::SUPPRESS_NONE,
                std::sync::atomic::Ordering::Relaxed,
            );
        }

        // The rewind may have dropped failed-server reminders with the truncated turns, so still-down servers must re-announce
        // See rearm_failed_server_announcements for why connected fingerprints stay latched
        self.rearm_failed_server_announcements().await;

        // Append a RewindMarker to updates.jsonl so replay can handle a branched timeline (updates.jsonl is append-only)
        self.persist_fuigo_update_only(FuigoSessionUpdate::RewindMarker {
            target_prompt_index: target_index,
            created_at: marker_created_at,
        });

        // The turn summary and recap describe turns the rewind just removed
        // Abort in-flight side-calls and clear the persisted copies so session lists don't show stale work
        // Bumping the recap epoch stops an in-flight recap from committing (and re-persisting `last_recap`) after the clear below
        self.recap_epoch.set(self.recap_epoch.get().wrapping_add(1));
        self.abort_turn_summary();
        self.abort_title_refresh();
        let _ = self
            .notifications
            .persistence_tx
            .send(PersistenceMsg::LastTurnSummary(None));
        let _ = self
            .notifications
            .persistence_tx
            .send(PersistenceMsg::LastRecap(None));

        // Re-derive the AUTO title-refresh checkpoint from the shortened conversation
        // A rewind below a checkpoint re-opens refreshing, while one still past the window stays frozen
        // Persist it so the reopened state survives resume (unlike compaction, a rewind genuinely removes the turns those checkpoints described)
        // A manually-titled session stays frozen; reopening would only spawn side-calls the manual-title guard rejects anyway
        let session_dir = crate::session::persistence::session_dir(&self.session_info);
        if !crate::session::persistence::title_is_manual_in_dir(&session_dir) {
            let post_rewind_turns = crate::session::helpers::session_recap::main_turn_count(
                &self.chat_state_handle.get_conversation().await,
            );
            let idx =
                crate::session::helpers::session_summary::checkpoints_reached(post_rewind_turns);
            self.next_title_refresh_idx.set(idx);
            crate::session::helpers::session_summary::save_title_refresh_watermark(
                &session_dir,
                idx,
            );
        }
    }

    /// `ConversationOnly` rewind-tracker bookkeeping: merge the discarded prompts' file effects (`>= target_index`) into the previous rewind point.
    /// That keeps `/rewind 0` able to undo all file changes.
    /// A new prompt at `target_index` then gets a fresh rewind point whose before-snapshots reflect current disk state.
    /// Files and the conversation are left untouched.
    ///
    /// Updates the in-memory tracker, then persists via a disk-authoritative merge.
    /// The merge means a lazily-unloaded or partial tracker can't truncate history off disk.
    /// No normalize_to_relative needed: per-turn persistence already normalized the on-disk points (turn.rs, before PersistenceMsg::RewindPoint).
    ///
    /// Shared by local `handle_rewind` (ConversationOnly) and the bridge-mode ConversationOnly path.
    /// The bridge path's conversation rewind lands server-side (SessionCommand::ReconcileRewindTracker).
    /// One acknowledged rewind_points request to the persistence actor (P146). Waiting is bounded while the request
    /// is still queued (`AckGate`): a request given up on never runs. Once started it runs to its end, which the
    /// storage bounds by the lock wait. A persistence actor that is gone is an error: the session's files are on disk
    /// and could no longer be kept in step.
    async fn rewind_points_request<T>(
        &self,
        what: &str,
        build: impl FnOnce(crate::session::persistence::AckGate, tokio::sync::oneshot::Sender<T>) -> PersistenceMsg,
    ) -> std::io::Result<T> {
        let gate = crate::session::persistence::AckGate::default();
        let (respond_to, mut reply) = tokio::sync::oneshot::channel();
        let stopped = || std::io::Error::other("session persistence has stopped");
        self.notifications
            .persistence_tx
            .send(build(gate.clone(), respond_to))
            .map_err(|_| stopped())?;
        match tokio::time::timeout(REWIND_POINTS_QUEUE_WAIT, &mut reply).await {
            Ok(result) => result.map_err(|_| stopped()),
            Err(_) if gate.abandon() => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "session persistence did not get to {what} within {} s",
                    REWIND_POINTS_QUEUE_WAIT.as_secs()
                ),
            )),
            Err(_) => reply.await.map_err(|_| stopped()),
        }
    }

    /// Take the rewind points rewrite lock through the persistence actor (P146). A lock file that cannot be used at
    /// all gives an empty lock, and the rewrite then runs unlocked, as a rewrite always did then.
    async fn lock_rewind_points_for_rewind(&self) -> std::io::Result<crate::session::storage::RewindPointsRewriteLock> {
        self.rewind_points_request("lock rewind_points.jsonl", |gate, respond_to| {
            PersistenceMsg::LockRewindPointsRewrite { gate, respond_to }
        })
        .await?
    }

    /// The rewind's rewrite of `rewind_points.jsonl`, while it holds the rewrite lock; on success, what the file held
    /// and what was written.
    async fn rewrite_rewind_points_for_rewind(
        &self,
        rewrite: crate::session::storage::RewindPointsRewrite,
        conversation: Option<crate::session::storage::RewindConversation>,
    ) -> std::io::Result<crate::session::storage::RewindPointsUndo> {
        self.rewind_points_request("rewrite rewind_points.jsonl", |gate, respond_to| {
            PersistenceMsg::RewriteRewindPointsAndAck { rewrite, conversation, gate, respond_to }
        })
        .await?
    }

    /// Test seam (P164): the answer of a rewind of this session that the seam stops at `stage`, as if Fuigo were
    /// killed there. Nothing after it runs: no put-back, no cleanup.
    #[cfg(any(test, feature = "test-support"))]
    fn killed_by_seam(&self, stage: crate::session::storage::rewind_crash_seam::Stage) -> Option<RewindResponse> {
        crate::session::storage::rewind_crash_seam::fires(&self.session_info.id.0, stage).then(|| RewindResponse {
            success: false,
            target_prompt_index: 0,
            mode: RewindMode::All,
            reverted_files: vec![],
            clean_files: vec![],
            conflicts: vec![],
            prompt_text: None,
            error: Some(format!("killed by the test seam at {stage:?}")),
        })
    }

    /// The rewind is done; `put_back`: it did not go through, so `rewind_points.jsonl` gets back what it held. The
    /// caller releases the rewrite lock afterwards, also when this gives up waiting.
    async fn end_rewind_points_for_rewind(
        &self,
        undo: crate::session::storage::RewindPointsUndo,
        put_back: bool,
    ) -> std::io::Result<()> {
        self.rewind_points_request("finish the rewind of rewind_points.jsonl", |gate, respond_to| {
            PersistenceMsg::EndRewindPointsAndAck { undo, put_back, gate, respond_to }
        })
        .await?
    }

    pub(super) async fn merge_rewind_tracker_from(&self, target_index: usize) {
        self.file_state_tracker
            .merge_and_remove_from(target_index)
            .await;
        let _ = self
            .notifications
            .persistence_tx
            .send(PersistenceMsg::MergeRewindPointsFrom { target_index });
    }

    /// Out-of-band history repair (`fuigo/session/repair`) for a resident session.
    /// Runs `fuigo_chat_state::compaction_utils::repair_history` inside the chat-state actor, then flushes persistence.
    /// The flush means `chat_history.jsonl` is rewritten on disk before the caller sees success.
    ///
    /// Refused while a turn is in flight (in-flight tool calls legitimately await their results).
    /// The refusal is enforced inside the chat-state actor's command handler; the check below is just a fast path.
    /// See `ChatStateCommand::RepairHistory` for why a caller-side check alone would race turn start.
    pub(super) async fn handle_repair_history(
        &self,
        dry_run: bool,
    ) -> anyhow::Result<fuigo_chat_state::compaction_utils::HistoryRepairReport> {
        // Per-session flag, NOT `tool_context.is_turn_active`, which is the agent-wide coordinator flag shared by all sessions
        // Using it refuses repair of an idle session while any other session runs a turn, and another session's turn end could clear it mid-turn
        let turn_flag = self.session_turn_active.clone();
        if turn_flag.load(std::sync::atomic::Ordering::SeqCst) {
            anyhow::bail!(fuigo_chat_state::commands::RepairHistoryBlocked);
        }

        let report = self
            .chat_state_handle
            .repair_history(dry_run, Some(turn_flag))
            .await
            .ok_or_else(|| anyhow::anyhow!("chat-state actor unavailable"))?
            .map_err(anyhow::Error::new)?;

        if report.changed() && !dry_run {
            // Flush barrier: success must mean the rewrite is on disk.
            let (flush_tx, flush_rx) = tokio::sync::oneshot::channel();
            if self
                .notifications
                .persistence_tx
                .send(PersistenceMsg::FlushAndAck {
                    respond_to: flush_tx,
                })
                .is_err()
                || !matches!(flush_rx.await, Ok(Ok(())))
            {
                anyhow::bail!("history repaired in memory but the persistence flush failed");
            }
            tracing::warn!(
                session_id = %self.session_info.id.0,
                duplicates_removed = report.duplicates_removed,
                stripped_tool_result_ids = ?report.stripped_tool_result_ids,
                synthetic_results_inserted = report.synthetic_results_inserted,
                "session history repaired"
            );
        }

        Ok(report)
    }
}

/// The conversation a rewind leaves, built by [`SessionActor::plan_conversation_rewind`] before anything changes.
struct PlannedConversationRewind {
    conversation: Vec<ConversationItem>,
    /// `Some(marker)` when a cross-compaction replay recomputed the compaction marker; `None` keeps the current one.
    replay_compaction_marker: Option<Option<usize>>,
    /// The text of the prompt at the target, to pre-fill the input.
    prompt_text: Option<String>,
}
