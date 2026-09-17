//! Tool dispatch helpers for `SessionActor`.
//! Covers `dispatch_tool` and its lock and display helpers, direct bash-mode execution, and tool argument parse-error formatting.

use super::*;
use std::path::PathBuf;

/// Number of trailing output lines a bash-mode command keeps in the prompt/history copy.
///
/// The TUI gets the complete output (see [`BashModeOutput`]); only the copy the model sees is bounded, so a
/// long dump in `! cmd` mode does not inflate the next turn.
const BASH_MODE_FINAL_OUTPUT_LINES: usize = 10;
const BASH_MODE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// Hard bound on the bytes a single bash-mode (`! cmd`) command can produce.
///
/// The terminal runner stops accumulating here and reports `TerminalRunResult::truncated = true`, which this module
/// forwards to `BashOutput::truncated`. It is also the bound on the persisted cost of one `! cmd`: since upstream
/// 1.0.25 the FULL output goes out as the final `ToolCallUpdate.raw_output`, and every ACP notification is persisted
/// to `updates.jsonl` (`emit_notification_direct` -> `PersistenceMsg::Update`). `BashOutput::output` is a `Vec<u8>`,
/// so it lands as a JSON array of decimal numbers rather than a string.
///
/// # Measured worst case per `! cmd`
///
/// Measured on hetzner, not estimated, by building the real notification and serialising the real
/// `SessionUpdateEnvelope` (`bash_mode_persisted_cost_of_a_full_size_output_is_measured`, and its base-tree twin in
/// the round-2 red driver):
///
/// | tree | command printed | `updates.jsonl` line |
/// |---|---|---|
/// | `b156799` (10-line tail) | 1,048,576 B | **2,010 B** |
/// | here (full output) | 1,048,575 B | **3,932,916 B** (3.75x the raw bytes) |
///
/// So the worst case is **~3.75 MiB of session file per `! cmd` that saturates this limit**, against ~2 KB before.
/// There is NO per-session cap: N such commands cost N times that, and a session that runs twenty of them adds
/// ~75 MiB to `updates.jsonl`. Ordinary `! cmd` output is a few hundred bytes and costs a few KB — the worst case
/// needs a command that deliberately dumps a megabyte.
///
/// # Why it is not capped here, and what to do if it bites
///
/// Capping the persisted copy below the displayed copy would put the truncated tail straight back into a reloaded
/// session, which is the bug this port fixes: a reopened session would show `... (N lines)` where the command's
/// output had been. Recommendation, in order: (1) leave this as is — the growth only lands on outputs that really
/// are a megabyte; (2) if session files do become a problem, the fix is to stop paying 3.75x for the encoding by
/// giving `BashOutput::output` a base64/string serde representation (~1.37x, a 2.7x saving) rather than by
/// shortening what is stored; (3) only then consider a per-session byte budget for bash-mode `raw_output`, which
/// must degrade by dropping the OLDEST commands' stored output, never by truncating the newest.
const BASH_MODE_OUTPUT_BYTE_LIMIT: usize = 1_048_576; // 1 MiB

/// Phase 2: dispatch a tool call through [`WorkspaceOps::call_tool`].
///
/// Agent sessions always use local workspace ops (in-process toolset).
pub(super) async fn dispatch_tool(
    workspace_ops: &fuigo_workspace::WorkspaceOps,
    prepared: &PreparedToolCall,
    session_id: &str,
) -> Result<ToolRunResult, fuigo_tool_runtime::ToolError> {
    tracing::debug!(
        tool = %prepared.tool_name,
        call_id = %prepared.tool_call_id.0,
        session = %session_id,
        mode = "local",
        "dispatch_tool"
    );
    workspace_ops
        .call_tool(
            &prepared.tool_name,
            prepared.parsed_args.clone(),
            &prepared.tool_call_id.0,
            Some(session_id),
        )
        .await
}

/// First string-valued argument among `keys`, in priority order.
fn str_arg<'a>(args: &'a serde_json::Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|k| args.get(*k)?.as_str())
}

/// Extract the workspace path that a tool call targets, to serialize concurrent same-file edits inside `execute_tool_calls`.
///
/// Different toolsets advertise the path under different JSON keys:
/// - `file_path`: fuigo_build (`search_replace`), opencode (`EditTool`, `WriteTool`, `ReadTool`), codex (`read_file`),
///   fuigo_build_hashline (`hashline_edit`)
/// - `path`: alternate edit/read tools
/// - `target_file`: fuigo_build (`read_file`, via `#[serde(rename)]`)
///
/// Returning the same key for two calls in a batch causes them to share a `tokio::sync::Mutex` and so run sequentially in model-emitted order.
/// Returning `None` lets the call run fully concurrently with everything else.
///
/// `target_directory` is deliberately omitted: a directory listing isn't an edit and must not share a file lock.
pub(super) fn lock_path_for_args(args: &serde_json::Value, cwd: &Path) -> Option<String> {
    let input = Path::new(str_arg(args, &["file_path", "path", "target_file"])?);
    let absolute = if input.is_absolute() {
        input.to_path_buf()
    } else {
        cwd.join(input)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    let lock_path = canonicalize_existing_ancestor(&normalized).unwrap_or(normalized);
    Some(lock_path.to_string_lossy().into_owned())
}

fn canonicalize_existing_ancestor(path: &Path) -> Option<PathBuf> {
    let mut ancestor = path;
    let mut suffix = Vec::new();
    loop {
        if let Ok(mut canonical) = dunce::canonicalize(ancestor) {
            suffix.reverse();
            canonical.extend(suffix);
            return Some(canonical);
        }
        suffix.push(ancestor.file_name()?.to_owned());
        ancestor = ancestor.parent()?;
    }
}

/// Pull the path a read/list tool targets and classify it against the store.
/// Keys span harnesses: `read_file` uses `target_file`, grep uses `path`, `list_dir` uses `target_directory`.
/// The path grammar lives in `fuigo_compaction_transcript`.
pub(super) fn compaction_artifact_read(
    args: &serde_json::Value,
) -> Option<fuigo_compaction_transcript::CompactionArtifact> {
    let path = str_arg(
        args,
        &["target_file", "file_path", "path", "target_directory"],
    )?;
    fuigo_compaction_transcript::classify_compaction_path(path)
}

/// Map a backend-hosted tool name to a user-facing title, ACP ToolKind, and `raw_input` JSON for display in the pager's tool call UI.
///
/// The `raw_input` carries metadata that the pager's `tool_call_to_block()` uses to select the correct renderer.
/// For example, `variant: "WebSearch"` picks the `WebSearchToolCallBlock` instead of the grep `SearchToolCallBlock`.
pub(super) fn backend_tool_display(name: &str) -> (String, acp::ToolKind, serde_json::Value) {
    match name {
        "web_search" => (
            "Web search:".to_string(),
            acp::ToolKind::Search,
            serde_json::json!({"variant": "WebSearch", "backend": true}),
        ),
        "x_search" => (
            "X search:".to_string(),
            acp::ToolKind::Search,
            serde_json::json!({"variant": "XSearch", "backend": true}),
        ),
        n => (
            n.to_string(),
            acp::ToolKind::Other,
            serde_json::json!({"backend": true}),
        ),
    }
}

/// Map a completed backend (server-side) tool call's payload to the ACP terminal status the shell should emit.
/// The backend reports each call's real success or failure in the payload's `status` field (e.g. a `web_search_call`'s `WebSearchToolCallStatus`).
/// A `"failed"` status becomes [`acp::ToolCallStatus::Failed`]; any other or absent status stays `Completed`.
/// Consumers, notably the headless `streaming-messages-json` `web_search_tool_result_error` branch, see the real failure instead of `Completed`.
pub(super) fn backend_tool_call_status(result: Option<&serde_json::Value>) -> acp::ToolCallStatus {
    let failed = result
        .and_then(|r| r.get("status"))
        .and_then(serde_json::Value::as_str)
        == Some("failed");
    if failed {
        acp::ToolCallStatus::Failed
    } else {
        acp::ToolCallStatus::Completed
    }
}

/// Expose the resolved model ID only when the backend actually routed elsewhere AND the catalog opted this model into checkpoint identity.
/// It checks the same `show_model_fingerprint` flag as the fingerprint itself, so one server-side setting governs both.
/// The client keeps no per-slug default.
pub(super) fn should_show_resolved_model(
    requested: &str,
    resolved: &str,
    show_checkpoint_identity: bool,
) -> bool {
    show_checkpoint_identity && requested != resolved
}

/// Resolve the shell name for the system prompt `Shell:` field.
///
/// Unix: basename of `$SHELL` (e.g. "zsh", "bash").
/// Windows: name from the `detect_windows_shell` cascade (pwsh, then powershell.exe, then Git Bash, then cmd.exe), since `$SHELL` is absent.
pub(super) fn resolve_session_shell() -> String {
    #[cfg(unix)]
    {
        std::env::var("SHELL")
            .ok()
            .and_then(|s| {
                std::path::Path::new(&s)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
            })
            .unwrap_or_else(|| "bash".to_string())
    }

    #[cfg(not(unix))]
    {
        fuigo_config::shell::detect_windows_shell()
            .name()
            .to_string()
    }
}

/// Key in `ToolError::details` that carries the HTTP status code.
/// Used by both error producers (image_gen, video_gen, test helpers) and the `is_auth_tool_error` classifier to avoid accidental key mismatch.
pub(crate) const HTTP_STATUS_DETAILS_KEY: &str = "status";

impl SessionActor {
    /// Extract the bash command from the prompt blocks if present in meta.
    /// Returns Some(command) if the prompt is a direct bash command, None otherwise.
    pub(super) fn extract_bash_command(prompt_blocks: &[acp::ContentBlock]) -> Option<String> {
        use crate::extensions::prompt_meta::PromptBlockMeta;
        for block in prompt_blocks {
            if let acp::ContentBlock::Text(text) = block
                && let Some(meta_val) = &text.meta
                && let Some(meta) = PromptBlockMeta::from_value(meta_val)
            {
                return meta.bash_command;
            }
        }
        None
    }

    /// Handle a direct bash command from bash mode.
    /// Runs the command with streaming output and sends updates to the TUI.
    pub(super) async fn handle_direct_bash_command(
        &self,
        _prompt_id: &str,
        command: String,
        prompt_blocks: &[acp::ContentBlock],
    ) -> PromptTurnResult {
        tracing::info!("Handling direct bash command");

        // Send user message chunks to scrollback (so the user sees their command)
        let model_id = self.current_model_id().await;
        let user_chunk_meta = serde_json::json!({ "modelId": model_id })
            .as_object()
            .cloned();
        for block in prompt_blocks.iter() {
            let update = acp::SessionUpdate::UserMessageChunk(
                acp::ContentChunk::new(block.clone()).meta(user_chunk_meta.clone()),
            );
            let notification_meta = self.build_notification_meta();
            let _ = self
                .notifications
                .persistence_tx
                .send(PersistenceMsg::Update(SessionUpdate::Acp(Box::new(
                    acp::SessionNotification::new(self.session_info.id.clone(), update)
                        .meta(notification_meta.as_object().cloned()),
                ))));
        }

        // Persist the user message for session history
        let _ = self
            .notifications
            .persistence_tx
            .send(PersistenceMsg::ContentChunk(PersistenceContentChunk::new(
                prompt_blocks.to_vec(),
            )));
        // Bash turns bypass `handle_prompt`'s commit point; the command is now in the ordered persistence stream, so a send-now may cancel this turn
        self.mark_front_message_committed().await;

        // Run the bash command with streaming enabled
        let tool_call_id = acp::ToolCallId::from(format!("bash-mode-{}", uuid::Uuid::new_v4()));

        // Send initial ToolCall to register with TUI

        use fuigo_tools::types::ToolInput;
        // Use the stripped command as the description so the pager shows the real command (not a generic label) while satisfying the required field
        let title_command = fuigo_tools::util::strip_redundant_session_cd(
            &command,
            self.tool_context.cwd.as_path(),
        );
        let tool_input = ToolInput::Bash(BashToolInput {
            command: command.clone(),
            timeout: None,
            description: title_command.clone().into_owned(),
            is_background: false,
        });
        // Bash mode has no model-issued wire name; resolve the toolset's execute tool by kind so the fuigo/tool identity still stamps
        let bash_marker = serde_json::json!({"bash_mode": true}).as_object().cloned();
        let exec_wire = {
            let agent = self.agent.borrow();
            agent
                .tool_bridge()
                .toolset()
                .tool_name_for_kind(fuigo_tools::types::tool::ToolKind::Execute)
        };
        let bash_meta = match exec_wire {
            Some(wire) => self.stamp_tool_meta(bash_marker.clone(), &wire, Some(&tool_input)),
            None => bash_marker,
        };
        self.send_update(
            acp::SessionUpdate::ToolCall(
                acp::ToolCall::new(tool_call_id.clone(), format!("Execute `{title_command}`"))
                    .kind(acp::ToolKind::Execute)
                    .status(acp::ToolCallStatus::InProgress)
                    .content(Vec::new())
                    .locations(Vec::new())
                    .raw_input(serde_json::to_value(&tool_input).ok())
                    .meta(bash_meta),
            ),
            None,
        )
        .await;

        let request = TerminalRunRequest {
            tool_call_id: tool_call_id.clone(),
            command: command.clone(),
            cwd: self.tool_context.cwd.clone(),
            env: self.tool_context.session_env.as_ref().clone(),
            timeout: BASH_MODE_TIMEOUT,
            output_byte_limit: BASH_MODE_OUTPUT_BYTE_LIMIT,
            stream: true,      // Enable streaming for bash mode
            output_file: None, // No file logging for interactive bash mode
        };

        let result = self.tool_context.terminal.run(request).await;

        // Format the output.
        // `byte_limit_hit` is the runner's own flag: the command produced more than `BASH_MODE_OUTPUT_BYTE_LIMIT`
        // and the tail was dropped before we ever saw it. It is the only truncation left in this path.
        let (output, exit_code, timed_out, signal, byte_limit_hit) = match result {
            Ok(res) => (
                res.combined_output,
                res.exit_code.unwrap_or(-1),
                res.timed_out,
                res.signal,
                res.truncated,
            ),
            Err(e) => (
                format!("Error running command: {}", e),
                -1,
                false,
                None,
                false,
            ),
        };

        // Full output for the TUI; prompt/history keep a last-N tail so dumps do not inflate the next turn
        let BashModeOutput {
            full: full_output,
            history: history_output,
        } = BashModeOutput::split(&output);

        let is_backgrounded = signal.as_deref() == Some("backgrounded");
        // One status line for every copy the model reads: the live chat-history message below and the final
        // update's `content`. Built once so the two cannot drift.
        let status_line = BashModeOutput::status_line(exit_code);

        // Send final tool call update
        // For backgrounded commands, don't mark as completed/failed; let the background task do that
        if !is_backgrounded {
            let final_status = if exit_code == 0 && signal.is_none() {
                acp::ToolCallStatus::Completed
            } else {
                acp::ToolCallStatus::Failed
            };
            let bash_output = BashOutput {
                output_for_prompt: BashOutput::make_output_for_prompt(&history_output),
                output: full_output.as_bytes().to_vec(),
                exit_code,
                command: command.clone(),
                // The runner's 1 MiB cap, not a display bound: before 1.0.25 this field carried
                // "a display tail was applied", which was never what `BashOutput::truncated` means
                // (see its doc: "Use read_file tool to retrieve full output when truncated"), and the
                // runner's own `truncated` was dropped on the floor. The display tail is gone; the byte
                // cap is real, so it is what this field now reports.
                truncated: byte_limit_hit,
                signal: signal.clone(),
                timed_out,
                description: None,
                current_dir: self.tool_context.cwd.to_string(),
                output_file: String::new(),
                total_bytes: full_output.len(),
                output_delta: None,
                was_bare_echo: false,
            };
            self.send_update(
                acp::SessionUpdate::ToolCallUpdate(acp::ToolCallUpdate::new(
                    tool_call_id,
                    acp::ToolCallUpdateFields::new()
                        .status(Some(final_status))
                        // The MODEL's copy of this tool result: the bounded `history` tail plus the same `[exit code: N]`
                        // status line the live chat-history message ends with (`BashModeOutput::model_result`).
                        // `chat_rebuild::extract_tool_result_text` (session/storage/mod.rs) prefers `content` and,
                        // when it is absent, falls back to `raw_output.to_string()` — the whole `BashOutput` JSON,
                        // with `output` rendered as a decimal byte array. Every rebuild of `chat_history.jsonl` from
                        // `updates.jsonl` takes that path (`remote::pull`, `ensure_chat_history` after a crash or
                        // cache loss, and every session import, which drops the chat cache on purpose), so without
                        // this the model's copy of one `! cmd` was the FULL output: 3,933,172 B of rebuilt chat
                        // history for a 1 MiB command, and `line 001` back in the conversation.
                        //
                        // What `content` carries is the live message's tail and status line, not the live message:
                        // live pushes ONE user item, `I executed a terminal command: `<cmd>`` with the tail in a code
                        // fence; a rebuild yields the persisted prompt chunk, an assistant tool call and this tool
                        // result. The tail is bounded by LINES, not bytes, exactly as live: a single very long line
                        // stays long on both paths (pre-existing, upstream-identical). Pinned by
                        // `bash_mode_rebuilt_chat_history_keeps_the_model_copy_bounded` and
                        // `bash_mode_rebuilt_chat_history_carries_the_exit_status`.
                        //
                        // Additive on the wire, verified rather than assumed: the streaming `BashOutputChunk`
                        // updates for this same tool call already carry `content`
                        // (`tools/notification_bridge.rs`), as does every model-issued bash tool result
                        // (`acp_conversion.rs`, `ToolOutput::Bash`), so no client sees a new shape here. The pager
                        // ignores it for a bash-mode block — `tool_call_to_block`'s Execute arm renders
                        // `raw_output`'s `BashOutput::output` and reads `content` only when `raw_output` does not
                        // parse (`fuigo-pager/src/acp/tracker.rs`) — and Murage's `tool_call_update` arm reads only
                        // `status` and `toolCallId` (`server/drivers/acp/core.ts`).
                        .content(Some(vec![acp::ToolCallContent::from(
                            acp::ContentBlock::Text(acp::TextContent::new(
                                BashModeOutput::model_result(&history_output, &status_line),
                            )),
                        )]))
                        .raw_output(serde_json::to_value(ToolsToolOutput::Bash(bash_output)).ok()),
                )),
                None,
            )
            .await;
        }

        // No AgentMessageChunk summary is sent here: the execute block already shows the full output, so an agent copy would duplicate scrollback
        // Old sessions that persisted one still replay fine

        // Build a single user message for chat history that includes command, output, and exit code
        let user_message = format!(
            "I executed a terminal command: `{}`\n\nOutput:\n```\n{}\n```\n\n{}",
            command, history_output, status_line
        );

        // Add to chat history as a user message only
        self.chat_state_handle
            .push_user_message(ConversationItem::user(&user_message));

        self.chat_state_handle.flush();

        let flush_error = self.flush_to_disk().await.err();
        self.disk_full_acp_error(flush_error.as_ref())?;

        let total_tokens = self.chat_state_handle.get_total_tokens().await;
        ok_end_turn(total_tokens, None)
    }
}

// ── Bash-mode output shapes ─────────────────────────────────────────────

/// The two copies of a bash-mode (`! cmd`) command's output.
///
/// `full` is what the pager's execute block shows: the complete output (already bounded to the terminal runner's
/// `output_byte_limit`, 1 MiB), trailing whitespace trimmed. `history` is the copy the model sees — in the next
/// turn's chat history, in `output_for_prompt`, and in the final `ToolCallUpdate`'s `content`, which is what a
/// rebuild of `chat_history.jsonl` from `updates.jsonl` reads: the same text when it is at most
/// [`BASH_MODE_FINAL_OUTPUT_LINES`] lines, otherwise `"... (N lines)\n"` followed by the last
/// [`BASH_MODE_FINAL_OUTPUT_LINES`] lines. Every model-facing path must take `history`; only the pager gets `full`.
///
/// Upstream 1.0.25: "Bash command output shown in the pager is now the complete result instead of a truncated tail."
/// Before that, `full` was also the tail, so anything above the bound was lost to the user with no way to expand it.
///
/// # Which surface this actually fixes: the PERSISTED copy, not the live frame
///
/// While the command is running the shell streams `BashOutputChunk` updates that carry the whole accumulated
/// buffer, and `tools/notification_bridge.rs` sends those **straight to the gateway without persisting them**, so
/// the live execute block already showed every line on the base tree.
///
/// What the live pager does with that block when the final update arrives is NOT established. Measured by the
/// round-3 audit's PTY probe, on a binary that persisted base's `"... (12 lines)\nL03…L12"` tail as a completed update
/// with no `content`: `L01` was still on screen right after `L12`, at turn idle, and 5 s and 8 s after that, and the
/// raw PTY byte stream never once contained `(12 lines)`. So the live pager never painted the final update's output;
/// this is not a sampling race. What IS proven is narrower: `AcpUpdateTracker` on its own replaces the block with
/// the final update's output when it merges a completed update (`fuigo-pager`'s
/// `bash_mode_final_update_output_replaces_the_streamed_block`). Why that replacement never reaches the live screen
/// is unexplained. Consequence: `bash_full_output_double_click_fold_pty` is green on a base-shape binary and on this
/// one, so it guards live rendering (streamed output, fold/expand, failing commands) and cannot detect this port.
///
/// The final `ToolCallUpdate` is the one that IS persisted (`emit_notification_direct` -> `PersistenceMsg::Update`),
/// and it is the only bash-mode output a reloaded session has: replay collapses the initial `ToolCall` and that final
/// update into one completed `ToolCall` (`storage/replay.rs`, `ReplayToolCollapser::push`), and `tool_call_to_block`
/// builds the execute block from its `BashOutput::output`. On the base tree that was the ten-line tail, so reopening a
/// session showed `... (N lines)` where the command's own output had been. That is what this fixes, and it is why the
/// persisted cost changes so much (a 1 MiB command went from ~2 KB to ~3.9 MB of `updates.jsonl`; see
/// `bash_mode_persisted_cost_of_a_full_size_output_is_measured`).
///
/// # The model-facing copy DID change, for one input class
///
/// Trailing blank lines. Before 1.0.25 the line count and the tail were taken from the RAW output and the trim was
/// applied only on the short branch; here (and upstream) the trim happens first and everything is counted on the
/// trimmed text. So for output that ends in blank lines the two disagree, and `history` — the copy the model reads —
/// is not byte-identical to the old one. `"a\nb\n" + "\n" * 10` is the clearest case: the old code counted 12 lines,
/// declared `"... (12 lines)"` and then handed the model ten EMPTY lines, hiding `a` and `b` entirely; this code
/// counts 2 and hands over `"a\nb"`. For output with more than [`BASH_MODE_FINAL_OUTPUT_LINES`] real lines plus a
/// trailing blank run, the old tail spent part of its budget on blanks and the count included them.
///
/// This is kept, not reverted, for three reasons: the old shape lied (the count and the content disagreed with what
/// the command actually printed), it could hide ALL of the real output behind blank padding, and it is what upstream
/// 1.0.25 ships — reverting would fork the wire shape from the client this is being kept in sync with. The change is
/// strictly a superset of information for the model: it never removes a real output line the old shape carried.
/// Pinned by `bash_mode_trailing_blank_lines_change_the_model_copy_and_show_everything_in_the_pager`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BashModeOutput {
    pub(super) full: String,
    pub(super) history: String,
}

impl BashModeOutput {
    /// The status line the model is told a `! cmd` finished with.
    ///
    /// The single source for both model-facing copies — the live chat-history message and the final update's
    /// `content` — so a rebuilt session and a live one cannot disagree on it. It is the exit code only, because that is
    /// all the live message has ever carried: a timed-out, signalled or failed-to-start command reaches it as
    /// `exit_code == -1` (`res.exit_code.unwrap_or(-1)`), and adding a signal/timeout suffix here would change the
    /// live model copy too.
    pub(super) fn status_line(exit_code: i32) -> String {
        format!("[exit code: {exit_code}]")
    }

    /// The final update's `content`: `history` followed by `status_line`, separated the way the live message
    /// separates its code fence from the status.
    pub(super) fn model_result(history: &str, status_line: &str) -> String {
        format!("{history}\n\n{status_line}")
    }

    pub(super) fn split(output: &str) -> Self {
        let full = output.trim_end().to_string();
        let lines: Vec<&str> = full.lines().collect();
        let total_lines = lines.len();
        let history = if total_lines > BASH_MODE_FINAL_OUTPUT_LINES {
            // `start < total_lines` holds: this branch runs only when `total_lines > BASH_MODE_FINAL_OUTPUT_LINES`.
            // Upstream `4827113` rewrites this as `lines.get(start..).unwrap_or(&[])`, but that is part of its
            // repo-wide `indexing_slicing` sweep, not of the 1.0.25 item, and `indexing_slicing` is not enabled in
            // this workspace. Kept as base had it, like the other two unrelated clippy rewrites in the same
            // upstream file that this port deliberately left behind.
            let start = total_lines - BASH_MODE_FINAL_OUTPUT_LINES;
            let last_lines = lines[start..].join("\n");
            format!("... ({} lines)\n{}", total_lines, last_lines)
        } else {
            full.clone()
        };
        Self { full, history }
    }
}

// ── Tool argument error formatting ─────────────────────────────────────

// `truncate_bytes` is the UTF-8-safe truncation helper from fuigo-sampling-types

/// Maximum bytes of `raw_arguments` echoed in a parse-error tool_result.
///
/// The model already holds the full arguments in context, so a prefix plus the JSON error position is enough; echoing more grows every later turn.
/// A syntax error position past this limit points into truncated text, but the model still has the full arguments in context.
pub(crate) const MAX_ARGS_IN_ERROR: usize = 2_000;

/// Build the user-facing error message shown when tool arguments cannot be parsed.
/// The message is stored as a `tool_result` in the conversation history, so the model sees it on the very next turn.
///
/// It carries the error description, the original arguments (capped at [`MAX_ARGS_IN_ERROR`] bytes), and the JSON error position for invalid JSON.
/// Fuigo-shell sanitizes unparseable arguments to `"{}"` before forwarding to the provider (avoiding 400 errors).
/// Without the echoed original, the model would only see that empty object and have to regenerate all its work from scratch.
/// The JSON position (e.g. a missing `"` before a key name) lets the model fix a one-character typo rather than regenerating a thousand-line file.
pub(super) fn build_tool_parse_error_message(
    function_name: &str,
    err: &fuigo_tool_runtime::ToolError,
    raw_arguments: &str,
) -> String {
    let mut msg = format!("Failed to parse arguments for tool `{function_name}`: {err}");

    if raw_arguments.is_empty() {
        return msg;
    }

    // Append the original arguments (capped) so the model knows what it sent.
    // Use truncate_bytes to avoid panicking on a multi-byte UTF-8 boundary.
    msg.push_str("\n\nYour original arguments:\n");
    let prefix = truncate_bytes(raw_arguments, MAX_ARGS_IN_ERROR);
    msg.push_str(prefix);
    if prefix.len() < raw_arguments.len() {
        msg.push_str("\n... (truncated)");
    }

    // If the arguments string is not valid JSON, append the exact position of the syntax error so the model can fix it directly
    // Use `IgnoredAny`: we only need the error, not a DOM
    if let Err(json_err) = serde_json::from_str::<serde::de::IgnoredAny>(raw_arguments) {
        msg.push_str(&format!(
            "\n\nNote: the arguments above contain invalid JSON — {json_err}\n\
             Please fix the syntax and retry."
        ));
    }

    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuigo_sampling_types::rs;

    fn web_search_payload(status: rs::WebSearchToolCallStatus) -> serde_json::Value {
        // The exact serialized `web_search_call` payload the sampler forwards on `BackendToolCallCompleted` (via `serde_json::to_value(ws)`)
        serde_json::to_value(rs::WebSearchToolCall {
            action: rs::WebSearchToolCallAction::Search(rs::WebSearchActionSearch {
                query: "rust async runtime".to_string(),
                sources: None,
            }),
            id: "ws1".to_string(),
            status,
        })
        .expect("serialize web_search_call payload")
    }

    /// A backend web-search failure must map to ACP `Failed` so the headless `web_search_tool_result_error` branch is reachable in production.
    /// A completed call or an absent payload stays `Completed`.
    /// Exercises the real payload shape, not a hand-built status.
    #[test]
    fn backend_failed_web_search_maps_to_failed_status() {
        let failed = web_search_payload(rs::WebSearchToolCallStatus::Failed);
        assert_eq!(failed["status"], "failed", "wire field name is `status`");
        assert_eq!(
            backend_tool_call_status(Some(&failed)),
            acp::ToolCallStatus::Failed
        );

        let completed = web_search_payload(rs::WebSearchToolCallStatus::Completed);
        assert_eq!(
            backend_tool_call_status(Some(&completed)),
            acp::ToolCallStatus::Completed
        );

        assert_eq!(
            backend_tool_call_status(None),
            acp::ToolCallStatus::Completed
        );
    }
}

/// Bash mode (`! cmd`): the pager gets the complete output, the model gets a bounded tail.
///
/// Upstream 1.0.25 fixed the pager showing a 10-line tail: the shell was sending the tail as `BashOutput.output`, so
/// the scrollback block had nothing more to show. These tests pin both halves of the contract: the ACP
/// `ToolCallUpdate.raw_output.output` (what the pager renders) is the full output, and the chat-history user message
/// plus `output_for_prompt` (what the model sees next turn) stay the `... (N lines)` + last-10 tail.
#[cfg(test)]
mod bash_mode_output_tests {
    use super::super::support::*;
    use super::*;
    use fuigo_tools::types::output::ToolOutput;
    use std::sync::Arc;

    /// A terminal runner that returns a scripted result without spawning anything.
    #[derive(Debug)]
    struct ScriptedTerminal {
        combined_output: String,
        /// What the real runner reports when the command blew past `output_byte_limit`.
        truncated: bool,
        /// The command's exit status.
        exit_code: i32,
    }

    #[async_trait::async_trait]
    impl crate::terminal::AsyncTerminalRunner for ScriptedTerminal {
        async fn run(
            &self,
            _request: crate::terminal::runner::TerminalRunRequest,
        ) -> Result<
            crate::terminal::runner::TerminalRunResult,
            crate::terminal::runner::TerminalError,
        > {
            Ok(crate::terminal::runner::TerminalRunResult {
                combined_output: self.combined_output.clone(),
                exit_code: Some(self.exit_code),
                truncated: self.truncated,
                signal: None,
                timed_out: false,
            })
        }
    }

    fn numbered_lines(n: usize) -> String {
        (1..=n)
            .map(|i| format!("line {i:03}"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }

    /// Runs `! <command>` against a terminal whose output is scripted and returns the final Bash `raw_output` the
    /// pager receives plus the chat-history user message the model receives.
    async fn run_bash_mode(output: String) -> (BashOutput, String) {
        run_bash_mode_with(output, false).await
    }

    /// As [`run_bash_mode`], with the runner's `output_byte_limit` truncation flag under test control.
    async fn run_bash_mode_with(output: String, truncated: bool) -> (BashOutput, String) {
        let run = run_bash_mode_capturing(output, truncated, 0).await;
        (run.bash, run.user_message)
    }

    /// One bash-mode turn's observable output: the two copies plus every ACP notification the turn emitted, in
    /// order. The notifications are what `emit_notification_direct` hands the persistence actor, so they are also
    /// exactly what a session's `updates.jsonl` holds.
    struct BashModeRun {
        bash: BashOutput,
        user_message: String,
        notifications: Vec<acp::SessionNotification>,
    }

    async fn run_bash_mode_capturing(
        output: String,
        truncated: bool,
        exit_code: i32,
    ) -> BashModeRun {
        let (gateway_tx, _gateway_rx) =
            tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
        let (persistence_tx, mut persistence_rx) =
            tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
        // `flush_to_disk` waits for the persistence actor's ack; stand in for it. The bash-mode user chunk is sent
        // straight down this channel rather than through `send_update`, so keep the Acp updates it carries: a real
        // `updates.jsonl` holds them ahead of the tool call.
        let persisted: std::rc::Rc<std::cell::RefCell<Vec<acp::SessionNotification>>> =
            std::rc::Rc::default();
        let persisted_sink = std::rc::Rc::clone(&persisted);
        tokio::task::spawn_local(async move {
            while let Some(msg) = persistence_rx.recv().await {
                match msg {
                    PersistenceMsg::FlushAndAck { respond_to } => {
                        let _ = respond_to.send(Ok(()));
                    }
                    PersistenceMsg::Update(crate::session::storage::SessionUpdate::Acp(n)) => {
                        persisted_sink.borrow_mut().push(*n);
                    }
                    _ => {}
                }
            }
        });
        let (actor, mut event_rx) = create_test_actor_with_terminal(
            0,
            256_000,
            85,
            gateway_tx,
            persistence_tx,
            Arc::new(ScriptedTerminal {
                combined_output: output,
                truncated,
                exit_code,
            }),
        )
        .await;
        let actor = Arc::new(actor);

        let bash_actor = Arc::clone(&actor);
        let turn = tokio::task::spawn_local(async move {
            bash_actor
                .handle_direct_bash_command(
                    "bash-1",
                    "seq-dump".to_string(),
                    &[acp::ContentBlock::Text(acp::TextContent::new("!seq-dump"))],
                )
                .await
        });

        // Drain the actor's event channel while the turn runs: ack replay flushes so `flush_to_disk` does not
        // wait out its timeout, and keep every ACP notification (the final Bash ToolCallUpdate among them).
        let mut notifications: Vec<acp::SessionNotification> = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !turn.is_finished() {
            assert!(
                std::time::Instant::now() < deadline,
                "bash-mode turn must finish"
            );
            match tokio::time::timeout(std::time::Duration::from_millis(20), event_rx.recv()).await
            {
                Ok(Some(event)) => note_event(event, &mut notifications),
                Ok(None) => break,
                Err(_) => {}
            }
        }
        while let Ok(event) = event_rx.try_recv() {
            note_event(event, &mut notifications);
        }
        turn.await
            .expect("bash-mode turn task")
            .expect("bash-mode turn ok");
        let bash_output = notifications.iter().rev().find_map(|n| match &n.update {
            acp::SessionUpdate::ToolCallUpdate(upd) => upd
                .fields
                .raw_output
                .clone()
                .and_then(|raw| serde_json::from_value::<ToolOutput>(raw).ok())
                .and_then(|out| match out {
                    ToolOutput::Bash(bash) => Some(bash),
                    _ => None,
                }),
            _ => None,
        });

        let conversation = actor.chat_state_handle.get_conversation().await;
        let user_message = conversation
            .iter()
            .rev()
            .find_map(|item| match item {
                fuigo_sampling_types::ConversationItem::User(_) => Some(item.text_content()),
                _ => None,
            })
            .expect("bash mode pushes one user message into chat history");
        // The session's `updates.jsonl` order: the user chunk this turn persisted directly, then the tool call and
        // its final update, which `emit_notification_direct` forwards to the same persistence stream.
        let mut all = persisted.borrow().clone();
        all.extend(notifications);
        BashModeRun {
            bash: bash_output.expect("bash mode must send a final Bash ToolCallUpdate"),
            user_message,
            notifications: all,
        }
    }

    fn note_event(event: SessionEvent, notifications: &mut Vec<acp::SessionNotification>) {
        match event {
            SessionEvent::FlushReplay {
                respond_to: Some(tx),
            } => {
                let _ = tx.send(());
            }
            SessionEvent::Notification(SessionNotification::Acp(n)) => notifications.push(*n),
            _ => {}
        }
    }

    /// Write `notifications` as a session's `updates.jsonl` and rebuild `chat_history.jsonl` from it, exactly as
    /// `remote::pull`, `ensure_chat_history` and session import do. Returns the rebuilt conversation and the size
    /// of the rebuilt file.
    fn rebuild_chat_history_from(
        notifications: &[acp::SessionNotification],
    ) -> (Vec<fuigo_sampling_types::ConversationItem>, u64) {
        use std::io::Write;

        let dir = tempfile::tempdir().expect("session dir");
        let updates_path = dir.path().join(crate::session::storage::UPDATES_FILE);
        {
            let mut file = std::fs::File::create(&updates_path).expect("updates.jsonl");
            for notification in notifications {
                let envelope = crate::session::storage::SessionUpdateEnvelope::from_update(
                    &crate::session::storage::SessionUpdate::Acp(Box::new(notification.clone())),
                )
                .expect("envelope");
                let line = serde_json::to_string(&envelope).expect("jsonl line");
                writeln!(file, "{line}").expect("write updates.jsonl");
            }
        }
        crate::session::storage::chat_rebuild::rebuild_chat_history(dir.path())
            .expect("rebuild chat_history.jsonl");
        let chat_path = dir.path().join(crate::session::storage::CHAT_HISTORY_FILE);
        let bytes = std::fs::metadata(&chat_path)
            .expect("chat_history.jsonl")
            .len();
        let text = std::fs::read_to_string(&chat_path).expect("read chat_history.jsonl");
        let items = text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                serde_json::from_str::<fuigo_sampling_types::ConversationItem>(l)
                    .expect("rebuilt conversation item")
            })
            .collect();
        (items, bytes)
    }

    // ---- the pure split ----

    #[test]
    fn split_keeps_the_complete_output_for_the_tui_and_a_tail_for_history() {
        let raw = numbered_lines(25);
        let out = BashModeOutput::split(&raw);
        assert_eq!(out.full, raw.trim_end(), "TUI copy is the whole output");
        let expected_tail = format!(
            "... (25 lines)\n{}",
            (16..=25)
                .map(|i| format!("line {i:03}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        assert_eq!(
            out.history, expected_tail,
            "model copy is the last 10 lines"
        );
    }

    #[test]
    fn split_at_or_under_the_bound_is_identical_on_both_sides() {
        for n in [0usize, 1, 9, 10] {
            let raw = numbered_lines(n);
            let out = BashModeOutput::split(&raw);
            assert_eq!(out.full, raw.trim_end(), "n={n}");
            assert_eq!(
                out.history, out.full,
                "n={n}: no tail marker at or under the bound"
            );
            assert!(!out.history.contains("... ("), "n={n}");
        }
        let raw = numbered_lines(11);
        let out = BashModeOutput::split(&raw);
        assert!(
            out.history.starts_with("... (11 lines)\nline 002\n"),
            "{:?}",
            out.history
        );
        assert_eq!(out.full, raw.trim_end());
    }

    // ---- the actor path the pager and the model actually see ----

    /// INVARIANT (upstream 1.0.25): for a bash-mode command whose output exceeds the old 10-line display bound, the
    /// `BashOutput.output` the pager renders is the complete output. RED on the base tree: base sends the
    /// `... (25 lines)` tail as `output`.
    #[tokio::test(flavor = "current_thread")]
    async fn bash_mode_pager_output_is_the_complete_result_not_a_tail() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let raw = numbered_lines(25);
                let (bash, _history) = run_bash_mode(raw.clone()).await;
                let shown = String::from_utf8(bash.output).expect("utf-8 output");
                assert_eq!(
                    shown,
                    raw.trim_end(),
                    "the pager must receive all 25 lines, not a tail"
                );
                assert!(shown.contains("line 001"), "first line reaches the pager");
                assert!(
                    !shown.starts_with("... ("),
                    "no elision marker in the pager copy"
                );
                assert!(!bash.truncated, "the shell did not truncate the pager copy");
                assert_eq!(bash.total_bytes, raw.trim_end().len());
            })
            .await;
    }

    /// The model-facing contract must not grow: the chat-history user message and `output_for_prompt` carry the
    /// `... (N lines)` + last-10 tail exactly as before. GREEN on the base tree and after the fix.
    #[tokio::test(flavor = "current_thread")]
    async fn bash_mode_model_copy_stays_the_bounded_tail() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let raw = numbered_lines(25);
                let (bash, history) = run_bash_mode(raw).await;
                let expected_tail = format!(
                    "... (25 lines)\n{}",
                    (16..=25)
                        .map(|i| format!("line {i:03}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
                assert!(
                    history.contains(&format!("Output:\n```\n{expected_tail}\n```")),
                    "chat history carries the tail, got {history:?}"
                );
                assert!(
                    !history.contains("line 001"),
                    "lines above the bound never reach the model: {history:?}"
                );
                assert!(history.contains("[exit code: 0]"), "{history:?}");
                assert!(
                    bash.output_for_prompt.starts_with("... (25 lines)\n"),
                    "output_for_prompt is derived from the tail: {:?}",
                    bash.output_for_prompt
                );
                assert!(
                    !bash.output_for_prompt.contains("line 001"),
                    "{:?}",
                    bash.output_for_prompt
                );
            })
            .await;
    }

    // ---- trailing blank lines: the one input class whose MODEL copy changed ----

    /// Base counted lines on the RAW output and trimmed only on the short branch; this counts everything on the
    /// trimmed text. For output that ends in blank lines the two disagree, so the model copy is NOT byte-identical
    /// to the base. This pins the new shape and spells out the old one it replaced.
    #[test]
    fn split_trims_before_counting_so_a_blank_run_cannot_eat_the_tail() {
        // Two real lines under twelve raw ones: base declared "... (12 lines)" and then showed the model ten EMPTY
        // lines, hiding `a` and `b` completely. The trimmed split reports the two lines that were actually printed.
        let padded = "a\nb\n\n\n\n\n\n\n\n\n\n\n";
        assert_eq!(padded.lines().count(), 12, "the raw shape base counted");
        let out = BashModeOutput::split(padded);
        assert_eq!(out.full, "a\nb");
        assert_eq!(out.history, "a\nb", "no elision marker: two real lines");
        assert!(!out.history.contains("... ("));

        // Above the bound, base spent part of the ten-line budget on the blanks; the trimmed split does not.
        let raw = numbered_lines(25) + "\n\n\n";
        assert_eq!(raw.lines().count(), 28, "the raw shape base counted");
        let out = BashModeOutput::split(&raw);
        assert_eq!(out.full, numbered_lines(25).trim_end());
        let expected_tail = format!(
            "... (25 lines)\n{}",
            (16..=25)
                .map(|i| format!("line {i:03}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        assert_eq!(out.history, expected_tail);
        // Superset check: every real line the base tail carried (the last 10 of 28 = lines 019..025) is still here.
        for i in 19..=25 {
            assert!(
                out.history.contains(&format!("line {i:03}")),
                "line {i:03} was in the base tail and must survive"
            );
        }
        assert!(
            !out.history.ends_with('\n'),
            "no blank padding at the end of the model copy: {:?}",
            out.history
        );
    }

    /// The MODEL copy alone, for an output that ends in blank lines.
    ///
    /// Split out from the pager assertions so each half's red is its own, unambiguous failure: a single test that
    /// checks the pager first would stop there and never show what base sent the model. RED on `b156799`, which put
    /// `"... (28 lines)\nline 019..line 025\n\n\n"` in the chat-history message — a line count taken from the raw
    /// output and a tail that spent three of its ten slots on blank padding. This is the deliberate model-facing
    /// change recorded on [`BashModeOutput`]; see that doc for why it is kept rather than reverted.
    #[tokio::test(flavor = "current_thread")]
    async fn bash_mode_trailing_blank_lines_model_copy_counts_only_the_lines_the_command_printed() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let raw = numbered_lines(25) + "\n\n\n";
                let (bash, history) = run_bash_mode(raw).await;

                let expected_tail = format!(
                    "... (25 lines)\n{}",
                    (16..=25)
                        .map(|i| format!("line {i:03}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
                assert!(
                    history.contains(&format!("Output:\n```\n{expected_tail}\n```")),
                    "chat history carries the trimmed tail, got {history:?}"
                );
                assert_eq!(
                    bash.output_for_prompt,
                    BashOutput::make_output_for_prompt(&expected_tail),
                    "output_for_prompt is the same trimmed tail"
                );
                assert!(
                    !history.contains("... (28 lines)"),
                    "the raw line count including blank padding is not what the model is told: {history:?}"
                );
                assert!(
                    !history.contains("line 001"),
                    "lines above the bound still never reach the model: {history:?}"
                );
            })
            .await;
    }

    /// Both copies, end to end, for an output that ends in blank lines.
    ///
    /// RED on `b156799` for BOTH halves: base sent `"... (28 lines)\nline 019..line 025\n\n\n"` as the pager copy AND
    /// as the model copy. The pager half is the cluster's fix. The model half is the deliberate, documented change
    /// recorded on [`BashModeOutput`]: base's count and tail disagreed with what the command printed. The model half
    /// also has its own test above, so its red is visible even though this one asserts the pager first.
    #[tokio::test(flavor = "current_thread")]
    async fn bash_mode_trailing_blank_lines_change_the_model_copy_and_show_everything_in_the_pager()
    {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let raw = numbered_lines(25) + "\n\n\n";
                let (bash, history) = run_bash_mode(raw).await;

                // Pager copy: every real line, no elision marker, no trailing blank run.
                let shown = String::from_utf8(bash.output).expect("utf-8 output");
                assert_eq!(
                    shown,
                    numbered_lines(25).trim_end(),
                    "the pager must receive all 25 printed lines with the blank padding trimmed"
                );
                assert!(shown.contains("line 001"), "first line reaches the pager");
                assert!(
                    !shown.starts_with("... ("),
                    "no elision marker in the pager copy"
                );

                // Model copy: the last ten REAL lines, counted after the trim.
                let expected_tail = format!(
                    "... (25 lines)\n{}",
                    (16..=25)
                        .map(|i| format!("line {i:03}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
                assert!(
                    history.contains(&format!("Output:\n```\n{expected_tail}\n```")),
                    "chat history carries the trimmed tail, got {history:?}"
                );
                assert!(
                    !history.contains("... (28 lines)"),
                    "the raw line count is not what the model is told: {history:?}"
                );
                assert!(
                    !history.contains("line 001"),
                    "lines above the bound still never reach the model: {history:?}"
                );
                assert!(
                    bash.output_for_prompt.starts_with("... (25 lines)\n"),
                    "{:?}",
                    bash.output_for_prompt
                );
            })
            .await;
    }

    // ---- the truncation flag ----

    /// `BashOutput::truncated` reports the runner's `output_byte_limit` cut, the only truncation left in this path.
    ///
    /// RED on `b156799`: base computed `truncated = total_lines > 10` from its display tail and threw
    /// `TerminalRunResult::truncated` away, so a three-line output that the runner had capped was reported as
    /// `truncated: false`. (Base did not propagate a truthful flag that this branch dropped — it never propagated
    /// one at all.)
    #[tokio::test(flavor = "current_thread")]
    async fn bash_mode_reports_the_runners_byte_limit_truncation() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let (capped, _) = run_bash_mode_with(numbered_lines(3), true).await;
                assert!(
                    capped.truncated,
                    "the runner hit BASH_MODE_OUTPUT_BYTE_LIMIT; the pager copy is not the whole result"
                );

                let (whole, _) = run_bash_mode_with(numbered_lines(25), false).await;
                assert!(
                    !whole.truncated,
                    "25 lines under the byte limit are complete: a display tail is no longer truncation"
                );
            })
            .await;
    }

    // ---- what one `! cmd` costs on disk ----

    /// Measure the persisted cost of a worst-case bash-mode command.
    ///
    /// Every ACP notification except `AvailableCommandsUpdate` is persisted (`emit_notification_direct` ->
    /// `PersistenceMsg::Update` -> one `SessionUpdateEnvelope` line in `updates.jsonl`). Since upstream 1.0.25 the
    /// final bash-mode update carries the FULL output, and `BashOutput::output` is a `Vec<u8>`, which serde renders
    /// as a JSON array of decimal numbers. This builds exactly that notification for an output at
    /// [`BASH_MODE_OUTPUT_BYTE_LIMIT`] and prints the line length, so the worst case per `! cmd` is a measured
    /// number rather than a guess. Run with `--nocapture` to see it.
    #[test]
    fn bash_mode_persisted_cost_of_a_full_size_output_is_measured() {
        let raw = "line of ordinary command output\n"
            .repeat(BASH_MODE_OUTPUT_BYTE_LIMIT / "line of ordinary command output\n".len());
        let split = BashModeOutput::split(&raw);
        assert!(
            split.full.len() > BASH_MODE_OUTPUT_BYTE_LIMIT - 64,
            "fixture is a full-size output"
        );

        let bash_output = BashOutput {
            output_for_prompt: BashOutput::make_output_for_prompt(&split.history),
            output: split.full.as_bytes().to_vec(),
            exit_code: 0,
            command: "seq-dump".to_string(),
            truncated: false,
            signal: None,
            timed_out: false,
            description: None,
            current_dir: "/work".to_string(),
            output_file: String::new(),
            total_bytes: split.full.len(),
            output_delta: None,
            was_bare_echo: false,
        };
        let notification = acp::SessionNotification::new(
            acp::SessionId::new("cost-measure"),
            acp::SessionUpdate::ToolCallUpdate(acp::ToolCallUpdate::new(
                acp::ToolCallId::from("bash-mode-cost".to_string()),
                acp::ToolCallUpdateFields::new()
                    .status(Some(acp::ToolCallStatus::Completed))
                    .raw_output(serde_json::to_value(ToolsToolOutput::Bash(bash_output)).ok()),
            )),
        );
        let envelope = crate::session::storage::SessionUpdateEnvelope::from_update(
            &crate::session::storage::SessionUpdate::Acp(Box::new(notification)),
        )
        .expect("envelope");
        let line = serde_json::to_string(&envelope).expect("jsonl line");

        let ratio = line.len() as f64 / split.full.len() as f64;
        println!(
            "bash-mode persisted cost: output {} bytes -> updates.jsonl line {} bytes ({:.2}x)",
            split.full.len(),
            line.len(),
            ratio
        );
        // The shape, not a golden number: a JSON array of decimal byte values costs a few bytes per source byte.
        assert!(
            (2.0..8.0).contains(&ratio),
            "persisted-cost ratio moved out of the documented band: {ratio:.2}x \
             ({} bytes of output -> {} bytes of jsonl)",
            split.full.len(),
            line.len()
        );
        // Worst case per command, stated: one `! cmd` at the byte limit costs this much session file. There is no
        // per-session cap — N such commands cost N times it. See BASH_MODE_OUTPUT_BYTE_LIMIT's doc comment.
        assert!(
            line.len() < 8 * 1024 * 1024,
            "one bash-mode command must stay under 8 MiB of persisted session file, got {}",
            line.len()
        );
    }

    // ---- the model's copy after a session rebuild ----

    /// INVARIANT: what the MODEL receives for a `! cmd` turn must stay bounded on EVERY path that produces it,
    /// including the one that does not read chat state at all.
    ///
    /// `chat_history.jsonl` is a cache. It is rebuilt from `updates.jsonl` on every remote/relay session pull
    /// (`remote::pull`), whenever the cache is missing or zero-length (`ensure_chat_history`, i.e. a crash before
    /// the chat flush), and on every session import — `extensions/session_state.rs::write_import` drops the file on
    /// purpose so load rebuilds it. `chat_rebuild::extract_tool_result_text` prefers `ToolCallUpdateFields::content`
    /// and falls back to `raw_output.to_string()`, so with no `content` the model's copy of this turn becomes the
    /// whole `BashOutput` JSON — including the FULL output as a decimal byte array, which is what upstream 1.0.25
    /// started putting there.
    ///
    /// RED on `bd4c152` (the port without `content`): the rebuilt item is that JSON, it contains `line 001`, and it
    /// grows with the command instead of with the bound. GREEN here: the rebuilt item is the same bounded tail the
    /// live turn pushed into chat history.
    #[tokio::test(flavor = "current_thread")]
    async fn bash_mode_rebuilt_chat_history_keeps_the_model_copy_bounded() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let raw = numbered_lines(25);
                let run = run_bash_mode_capturing(raw, false, 0).await;
                let expected_tail = format!(
                    "... (25 lines)\n{}",
                    (16..=25)
                        .map(|i| format!("line {i:03}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                );

                let (items, bytes) = rebuild_chat_history_from(&run.notifications);
                let tool_results: Vec<String> = items
                    .iter()
                    .filter_map(|item| match item {
                        fuigo_sampling_types::ConversationItem::ToolResult(t) => {
                            Some(t.content.as_ref().to_owned())
                        }
                        _ => None,
                    })
                    .collect();
                assert_eq!(
                    tool_results.len(),
                    1,
                    "one bash-mode turn rebuilds to one tool result, got {tool_results:?}"
                );
                assert_eq!(
                    tool_results[0],
                    format!("{expected_tail}\n\n[exit code: 0]"),
                    "the rebuilt model copy is the bounded tail and its status, not the raw BashOutput JSON"
                );

                let rebuilt: String = items.iter().map(|i| i.text_content()).collect();
                assert!(
                    !rebuilt.contains("line 001"),
                    "lines above the bound must not reach the model through a rebuild: {rebuilt:?}"
                );
                assert!(
                    !rebuilt.contains("108,105,110"),
                    "the rebuilt copy must not be `output` rendered as a decimal byte array: {rebuilt:?}"
                );
                assert!(
                    bytes < 4096,
                    "a 25-line `! cmd` must rebuild to a small chat item, got {bytes} bytes"
                );
            })
            .await;
    }

    /// A FAILED `! cmd` must still read as failed after `chat_history.jsonl` is rebuilt.
    ///
    /// The live message ends `[exit code: N]`; `chat_rebuild` ignores the update's `status`, so the rebuilt tool
    /// result is the only place the model can learn the command failed. RED on `47dda32`, whose `content` was the bare
    /// tail: the rebuilt copy of an exit-2 command had no status at all. GREEN here: the rebuilt copy ends with the
    /// same status line as the live message, built by the same `BashModeOutput::status_line`.
    #[tokio::test(flavor = "current_thread")]
    async fn bash_mode_rebuilt_chat_history_carries_the_exit_status() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                for exit_code in [2, 0] {
                    let run = run_bash_mode_capturing(numbered_lines(25), false, exit_code).await;
                    let status = format!("[exit code: {exit_code}]");
                    assert!(
                        run.user_message.ends_with(&status),
                        "exit {exit_code}: the live message is unchanged and ends with the status: {:?}",
                        run.user_message
                    );
                    assert_eq!(run.bash.exit_code, exit_code);

                    let (items, _bytes) = rebuild_chat_history_from(&run.notifications);
                    let rebuilt = items
                        .iter()
                        .find_map(|item| match item {
                            fuigo_sampling_types::ConversationItem::ToolResult(t) => {
                                Some(t.content.as_ref().to_owned())
                            }
                            _ => None,
                        })
                        .expect("one rebuilt tool result");
                    assert!(
                        rebuilt.ends_with(&format!("\n\n{status}")),
                        "exit {exit_code}: the rebuilt model copy must carry the same status line as the live \
                         message, got {rebuilt:?}"
                    );
                    assert!(
                        rebuilt.starts_with("... (25 lines)\nline 016\n"),
                        "exit {exit_code}: still the bounded tail: {rebuilt:?}"
                    );
                    assert!(
                        run.user_message.contains(rebuilt.split("\n\n[exit code:").next().unwrap_or("")),
                        "exit {exit_code}: the rebuilt tail is the live message's tail"
                    );
                }
            })
            .await;
    }

    /// The same rebuild for a command that saturates [`BASH_MODE_OUTPUT_BYTE_LIMIT`]: the model-facing cost of one
    /// `! cmd` must be set by the ten-line bound, not by what the command printed. Run with `--nocapture` to see
    /// the measured size.
    ///
    /// RED on `bd4c152`: ~3.9 MB of `108,105,110,…` in the rebuilt conversation, i.e. context overflow or an
    /// emergency compaction on the next turn.
    #[tokio::test(flavor = "current_thread")]
    async fn bash_mode_rebuilt_chat_history_cost_of_a_full_size_output_is_measured() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let raw = "line of ordinary command output\n".repeat(
                    BASH_MODE_OUTPUT_BYTE_LIMIT / "line of ordinary command output\n".len(),
                );
                let printed = raw.trim_end().len();
                let run = run_bash_mode_capturing(raw, false, 0).await;
                let (_items, bytes) = rebuild_chat_history_from(&run.notifications);
                println!(
                    "bash-mode rebuilt model copy: command printed {printed} bytes -> \
                     chat_history.jsonl {bytes} bytes"
                );
                assert!(
                    bytes < 4096,
                    "the rebuilt model copy must stay bounded by BASH_MODE_FINAL_OUTPUT_LINES, \
                     got {bytes} bytes for {printed} bytes of output"
                );
            })
            .await;
    }

    /// At or under the bound nothing is elided anywhere.
    #[tokio::test(flavor = "current_thread")]
    async fn bash_mode_short_output_is_identical_for_pager_and_model() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let raw = numbered_lines(10);
                let (bash, history) = run_bash_mode(raw.clone()).await;
                let shown = String::from_utf8(bash.output).expect("utf-8 output");
                assert_eq!(shown, raw.trim_end());
                assert!(history.contains(&format!("Output:\n```\n{}\n```", raw.trim_end())));
                assert!(!history.contains("... ("));
                assert!(!bash.truncated);
            })
            .await;
    }
}
