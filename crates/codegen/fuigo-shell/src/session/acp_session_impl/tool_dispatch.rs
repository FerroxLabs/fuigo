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
            output_byte_limit: 1_048_576, // 1 MiB
            stream: true,                 // Enable streaming for bash mode
            output_file: None,            // No file logging for interactive bash mode
        };

        let result = self.tool_context.terminal.run(request).await;

        // Format the output
        let (output, exit_code, timed_out, signal) = match result {
            Ok(res) => (
                res.combined_output,
                res.exit_code.unwrap_or(-1),
                res.timed_out,
                res.signal,
            ),
            Err(e) => (format!("Error running command: {}", e), -1, false, None),
        };

        // Full output for the TUI; prompt/history keep a last-N tail so dumps do not inflate the next turn
        let BashModeOutput {
            full: full_output,
            history: history_output,
        } = BashModeOutput::split(&output);

        let is_backgrounded = signal.as_deref() == Some("backgrounded");

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
                truncated: false,
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
            "I executed a terminal command: `{}`\n\nOutput:\n```\n{}\n```\n\n[exit code: {}]",
            command, history_output, exit_code
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
/// `output_byte_limit`, 1 MiB), trailing whitespace trimmed. `history` is the copy the model sees in the next turn's
/// chat history and in `output_for_prompt`: the same text when it is at most [`BASH_MODE_FINAL_OUTPUT_LINES`] lines,
/// otherwise `"... (N lines)\n"` followed by the last [`BASH_MODE_FINAL_OUTPUT_LINES`] lines.
///
/// Upstream 1.0.25: "Bash command output shown in the pager is now the complete result instead of a truncated tail."
/// Before that, `full` was also the tail, so anything above the bound was lost to the user with no way to expand it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BashModeOutput {
    pub(super) full: String,
    pub(super) history: String,
}

impl BashModeOutput {
    pub(super) fn split(output: &str) -> Self {
        let full = output.trim_end().to_string();
        let lines: Vec<&str> = full.lines().collect();
        let total_lines = lines.len();
        let history = if total_lines > BASH_MODE_FINAL_OUTPUT_LINES {
            let start = total_lines - BASH_MODE_FINAL_OUTPUT_LINES;
            let last_lines = lines.get(start..).unwrap_or(&[]).join("\n");
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
                exit_code: Some(0),
                truncated: false,
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
        let (gateway_tx, _gateway_rx) =
            tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
        let (persistence_tx, mut persistence_rx) =
            tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
        // `flush_to_disk` waits for the persistence actor's ack; stand in for it.
        tokio::task::spawn_local(async move {
            while let Some(msg) = persistence_rx.recv().await {
                if let PersistenceMsg::FlushAndAck { respond_to } = msg {
                    let _ = respond_to.send(Ok(()));
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
        // wait out its timeout, and keep the final Bash ToolCallUpdate.
        let mut bash_output: Option<BashOutput> = None;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !turn.is_finished() {
            assert!(
                std::time::Instant::now() < deadline,
                "bash-mode turn must finish"
            );
            match tokio::time::timeout(std::time::Duration::from_millis(20), event_rx.recv()).await
            {
                Ok(Some(event)) => note_event(event, &mut bash_output),
                Ok(None) => break,
                Err(_) => {}
            }
        }
        while let Ok(event) = event_rx.try_recv() {
            note_event(event, &mut bash_output);
        }
        turn.await
            .expect("bash-mode turn task")
            .expect("bash-mode turn ok");

        let conversation = actor.chat_state_handle.get_conversation().await;
        let user_message = conversation
            .iter()
            .rev()
            .find_map(|item| match item {
                fuigo_sampling_types::ConversationItem::User(_) => Some(item.text_content()),
                _ => None,
            })
            .expect("bash mode pushes one user message into chat history");
        (
            bash_output.expect("bash mode must send a final Bash ToolCallUpdate"),
            user_message,
        )
    }

    fn note_event(event: SessionEvent, bash_output: &mut Option<BashOutput>) {
        match event {
            SessionEvent::FlushReplay {
                respond_to: Some(tx),
            } => {
                let _ = tx.send(());
            }
            SessionEvent::Notification(SessionNotification::Acp(n)) => {
                let n = *n;
                if let acp::SessionUpdate::ToolCallUpdate(upd) = n.update
                    && let Some(raw) = upd.fields.raw_output
                    && let Ok(ToolOutput::Bash(bash)) = serde_json::from_value::<ToolOutput>(raw)
                {
                    *bash_output = Some(bash);
                }
            }
            _ => {}
        }
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
