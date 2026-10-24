use super::*;

pub(super) fn turn_result_to_hook_outcome(
    result: &Result<TurnOutcome, acp::Error>,
) -> fuigo_tool_protocol::turn_hook::TurnHookOutcome {
    use fuigo_tool_protocol::turn_hook::TurnHookOutcome;
    match result {
        Ok(TurnOutcome::Completed { .. }) | Ok(TurnOutcome::StationarityEnded { .. }) => {
            TurnHookOutcome::Completed
        }
        Ok(TurnOutcome::Cancelled { .. }) | Ok(TurnOutcome::MaxTurnsReached { .. }) => {
            TurnHookOutcome::Cancelled
        }
        Err(_) => TurnHookOutcome::Error,
    }
}

/// Encode a [`CancellationCategory`](crate::session::events::CancellationCategory) as its bare snake_case wire string for the `after_turn` payload.
/// Deliberately `serde_json::to_value` then `as_str`, not `to_string`: that yields the quoted form and fails the workspace decode.
pub(super) fn cancellation_category_to_wire_string(
    category: Option<crate::session::events::CancellationCategory>,
) -> Option<String> {
    let category = category?;
    serde_json::to_value(category)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
}

/// The shell's granular `ToolOutcome` variants collapse to the hub protocol's three.
/// `Cancelled` means the tool never ran (permission, doom-loop, hook, followup).
pub(super) fn map_tool_outcome(
    outcome: crate::session::events::ToolOutcome,
) -> fuigo_tool_protocol::session_event::ToolCallOutcome {
    use crate::session::events::ToolOutcome;
    use fuigo_tool_protocol::session_event::ToolCallOutcome;
    match outcome {
        ToolOutcome::Success => ToolCallOutcome::Success,
        ToolOutcome::Error | ToolOutcome::InvalidTool => ToolCallOutcome::Error,
        ToolOutcome::PermissionRejected
        | ToolOutcome::PermissionCancelled
        | ToolOutcome::Followup
        | ToolOutcome::HookDenied
        | ToolOutcome::Cancelled => ToolCallOutcome::Cancelled,
    }
}

/// Returns `(notification_type, message, title, level)` when this update should trigger a vendor-compatible `Notification` hook.
///
/// Internal and high-frequency updates (hook scrollback, retry progress, config changes) are excluded.
/// Migrated hooks fire only on updates that need the user's attention.
/// `DiffReview` always waits on the user, so it is safe to fire `permission_prompt` here.
#[allow(clippy::type_complexity)]
pub(super) fn notification_hook_for_update(
    update: &FuigoSessionUpdate,
) -> Option<(String, Option<String>, Option<String>, Option<String>)> {
    match update {
        FuigoSessionUpdate::DiffReview { .. } => Some((
            "permission_prompt".into(),
            Some("Diff review requested".into()),
            None,
            Some("info".into()),
        )),
        FuigoSessionUpdate::AutoRecoveryExhausted { error, .. } => Some((
            "agent_error".into(),
            Some(error.clone()),
            None,
            Some("error".into()),
        )),
        FuigoSessionUpdate::RetryState(RetryState::Exhausted { reason, .. }) => Some((
            "agent_error".into(),
            Some(reason.clone()),
            None,
            Some("error".into()),
        )),
        FuigoSessionUpdate::RetryState(RetryState::Failed { message, .. }) => Some((
            "agent_error".into(),
            Some(message.clone()),
            None,
            Some("error".into()),
        )),
        _ => None,
    }
}

pub(super) struct DeferredPostToolUseScrollback {
    tool_name: String,
    tool_call_id: String,
    results: Vec<fuigo_hooks::result::HookRunResult>,
}

impl SessionActor {
    pub(super) fn hook_run_ctx(&self) -> fuigo_hooks::runner::RunContext<'_> {
        fuigo_hooks::runner::RunContext {
            session_id: &self.session_info.id.0,
            workspace_root: &self.hook_resolved_workspace_root,
            process_scope: self.tool_context.process_scope.clone(),
        }
    }

    /// The annotation renders inline with the preceding tool call block rather than as a separate agent message.
    pub(super) async fn send_hook_annotation(&self, message: &str) {
        self.send_fuigo_notification(FuigoSessionUpdate::HookAnnotation {
            message: message.to_string(),
        })
        .await;
    }

    /// `prompt_id` is `None` for session-level dispatches (session_start / session-end stop).
    pub(super) async fn send_hook_execution(
        &self,
        event_name: &str,
        tool_name: Option<&str>,
        tool_call_id: Option<&str>,
        prompt_id: Option<&str>,
        results: &[fuigo_hooks::result::HookRunResult],
    ) {
        use crate::extensions::notification::{HookRunEntryDto, HookRunStatusDto};
        use fuigo_hooks::result::HookRunResult;

        // A hook that can never start (CONFIG failure) is not a run: it is told to the user once, as one grouped notice,
        // and the dispatcher skips it silently for the rest of the session. It never reaches the transcript as a failure.
        let mut problems: Vec<fuigo_hooks::health::ConfigProblem> = Vec::new();
        let results: Vec<&HookRunResult> = results
            .iter()
            .filter(|r| match r {
                HookRunResult::Failed { hook_name, error, .. }
                    if fuigo_hooks::health::is_config_failure(error) =>
                {
                    problems.push(fuigo_hooks::health::ConfigProblem {
                        hook_name: hook_name.clone(),
                        source: fuigo_hooks::health::hook_source(hook_name),
                        is_plugin: hook_name.starts_with(fuigo_hooks::config::PLUGIN_HOOK_PREFIX),
                        detail: fuigo_hooks::health::config_failure_detail(error).to_string(),
                    });
                    false
                }
                _ => true,
            })
            .collect();
        if let Some(notice) = fuigo_hooks::health::grouped_notice(&problems) {
            self.send_hook_annotation(&notice).await;
        }
        if results.is_empty()
            || results
                .iter()
                .all(|r| matches!(r, HookRunResult::Skipped { .. }))
        {
            return;
        }

        let runs: Vec<HookRunEntryDto> = results
            .iter()
            .map(|r| {
                let (name, status) = match *r {
                    HookRunResult::Success {
                        hook_name, elapsed, ..
                    } => (
                        hook_name.clone(),
                        HookRunStatusDto::Success {
                            elapsed_ms: elapsed.as_millis() as u64,
                        },
                    ),
                    HookRunResult::Skipped { hook_name } => {
                        (hook_name.clone(), HookRunStatusDto::Skipped)
                    }
                    HookRunResult::Blocked {
                        hook_name,
                        detail,
                        elapsed,
                        ..
                    } => (
                        hook_name.clone(),
                        HookRunStatusDto::Failed {
                            error: detail.clone(),
                            elapsed_ms: elapsed.as_millis() as u64,
                            blocked: true,
                        },
                    ),
                    HookRunResult::Failed {
                        hook_name,
                        error,
                        elapsed,
                        ..
                    } => (
                        hook_name.clone(),
                        HookRunStatusDto::Failed {
                            error: error.clone(),
                            elapsed_ms: elapsed.as_millis() as u64,
                            blocked: false,
                        },
                    ),
                };
                HookRunEntryDto {
                    name,
                    status,
                    output: None,
                }
            })
            .collect();

        self.send_fuigo_notification(FuigoSessionUpdate::HookExecution {
            event_name: event_name.to_string(),
            tool_name: tool_name.map(|s| s.to_string()),
            tool_call_id: tool_call_id.map(|s| s.to_string()),
            prompt_id: prompt_id.map(|s| s.to_string()),
            runs,
        })
        .await;

        for r in results {
            let system_message = match r {
                HookRunResult::Success { system_message, .. }
                | HookRunResult::Blocked { system_message, .. }
                | HookRunResult::Failed { system_message, .. } => system_message.as_deref(),
                HookRunResult::Skipped { .. } => None,
            };
            if let Some(message) = system_message.map(str::trim).filter(|m| !m.is_empty()) {
                self.send_hook_annotation(message).await;
            }
        }
    }

    /// Validate every enabled command hook once, without running anything, and tell the user about the ones that cannot
    /// start as ONE grouped notice. Run at session start and after a hooks reload, so config failures are known before
    /// the first prompt; the dispatcher then skips those hooks silently for the session.
    pub(super) async fn check_hooks_after_load(&self) {
        let Some(registry) = self.hook_registry.borrow().clone() else {
            return;
        };
        let problems = fuigo_hooks::health::validate_registry(
            &registry,
            &self.hook_resolved_workspace_root,
            &self.session_info.id.0,
        );
        if let Some(notice) = fuigo_hooks::health::grouped_notice(&problems) {
            self.send_hook_annotation(&notice).await;
        }
    }

    pub(super) fn hook_workspace_root(&self) -> String {
        self.hook_resolved_workspace_root.clone()
    }

    /// Subagent type for tool-hook attribution, or `None` for the top-level session.
    /// Prefers the task `subagent_type`, falling back to the agent definition name for older spawns.
    pub(super) fn subagent_type_label(&self) -> Option<String> {
        if !self.startup_hints.is_subagent {
            return None;
        }
        Some(
            self.startup_hints
                .subagent_type
                .clone()
                .unwrap_or_else(|| self.agent.borrow().definition().name.clone()),
        )
    }

    /// The three-dimension mode report for peer admission (S4): the plan flag, the base mode and the session edit
    /// grant, each read live on every call. Plan never hides the base: shell, MCP and web still auto-approve under plan.
    /// Not reported (limit): narrower allow rules and saved per-tool grants are not modes; see `EffectivePermissionMode`.
    pub(super) fn effective_peer_mode(&self) -> fuigo_workspace::permission::EffectivePeerMode {
        self.permissions
            .effective_peer_mode(self.plan_mode.lock().is_active())
    }

    pub(super) fn permission_mode_label(&self) -> &'static str {
        if self.plan_mode.lock().is_active() {
            "plan"
        } else if self.permissions.is_yolo_mode() {
            "bypassPermissions"
        } else if self.permissions.is_auto_mode() {
            "auto"
        } else {
            "default"
        }
    }

    /// Dispatch a non-blocking hook event: build the envelope, fire observe-only client hooks, then run the on-disk registry.
    pub(super) async fn dispatch_hook(
        &self,
        event: fuigo_hooks::event::HookEventName,
        payload: fuigo_hooks::event::HookPayload,
        prompt_id: Option<&str>,
        tool_name: Option<&str>,
    ) {
        if !self.may_have_hooks_for(event) {
            return;
        }
        // Fires observe-only client hooks before (and independent of) the on-disk registry guard below.
        let envelope = self.fire_hook(event, prompt_id.map(|s| s.to_string()), payload);
        let Some(registry) = self.hook_registry.borrow().clone() else {
            return;
        };
        let ctx = self.hook_run_ctx();
        // Prompt-gate events go through dispatch_prompt_submit_hook; dispatch_non_blocking debug-asserts observe-only
        let results =
            fuigo_hooks::dispatcher::dispatch_non_blocking(&registry, event, &envelope, &ctx).await;
        self.send_hook_execution(&event.to_string(), tool_name, None, prompt_id, &results)
            .await;
        self.emit_hook_executed_telemetry(&event.to_string(), tool_name, &results)
            .await;
    }

    /// The user's effective `auto_background_on_timeout` for the Bash tool, the same resolved `[toolset.bash]` params
    /// the tool runs with (`BashTool::auto_background_on_timeout_enabled`: the setting and background enabled).
    pub(super) fn bash_auto_background_enabled(&self) -> bool {
        self.rebuild_spec
            .tool_params_json
            .bash
            .as_ref()
            .is_some_and(|m| {
                m.get("auto_background_on_timeout").and_then(|v| v.as_bool()) == Some(true)
                    && m.get("enabled_background").and_then(|v| v.as_bool()) != Some(false)
            })
    }

    pub(super) async fn dispatch_post_tool_use_hook(
        &self,
        prepared: &PreparedToolCall,
        output: &ToolsToolOutput,
        duration_ms: Option<u64>,
    ) -> (PostToolUseDelivery, Option<DeferredPostToolUseScrollback>) {
        use fuigo_hooks::event::{HookEventName, HookPayload, truncate_payload};

        if !self.may_have_hooks_for(HookEventName::PostToolUse) {
            return (PostToolUseDelivery::default(), None);
        }

        let tool_result = serde_json::to_value(output).unwrap_or(serde_json::Value::Null);
        let raw_input: serde_json::Value =
            serde_json::from_str(&prepared.raw_arguments).unwrap_or(serde_json::Value::Null);
        let (tool_input_value, tool_input_truncated) =
            truncate_payload(with_retired_bash_background_field(raw_input, self.bash_auto_background_enabled()));
        let (tool_result_value, tool_result_truncated) = truncate_payload(tool_result);
        let hook_tool_name = prepared.hook_tool_name().to_owned();

        let event = HookEventName::PostToolUse.to_string();
        let envelope = self.make_hook_envelope(
            HookEventName::PostToolUse,
            None,
            HookPayload::PostToolUse {
                tool_name: hook_tool_name.clone(),
                tool_use_id: prepared.call_id.clone(),
                tool_input: tool_input_value,
                tool_result: tool_result_value,
                tool_input_truncated,
                tool_result_truncated,
                duration_ms,
                is_backgrounded: false,
                subagent_type: self.subagent_type_label(),
            },
        );
        let registry = self.hook_registry.borrow().clone();
        let mut dispatch_result = if let Some(registry) = registry {
            let ctx = self.hook_run_ctx();
            fuigo_hooks::dispatcher::dispatch_post_tool_use(&registry, &envelope, &ctx).await
        } else {
            fuigo_hooks::dispatcher::PostToolUseResult::default()
        };
        // Client PostToolUse runs the awaited gate though it is not yet in
        // ADVERTISED_BLOCKING_EVENTS; SDK clients dispatch by callback id and answer.
        dispatch_result.merge(self.run_post_tool_use_client_hooks(&envelope).await);

        let mut results = std::mem::take(&mut dispatch_result.results);
        let delivery = plan_post_tool_use_delivery(
            dispatch_result,
            output,
            self.reminder_wrapper_tag(),
            &mut results,
        );

        self.emit_hook_executed_telemetry(&event, Some(&hook_tool_name), &results)
            .await;
        let deferred = DeferredPostToolUseScrollback {
            tool_name: hook_tool_name,
            tool_call_id: prepared.tool_call_id.0.to_string(),
            results,
        };
        (delivery, Some(deferred))
    }

    pub(super) async fn emit_post_tool_use_scrollback(
        &self,
        deferred: DeferredPostToolUseScrollback,
    ) {
        let event = fuigo_hooks::event::HookEventName::PostToolUse.to_string();
        self.send_hook_execution(
            &event,
            Some(&deferred.tool_name),
            Some(&deferred.tool_call_id),
            None,
            &deferred.results,
        )
        .await;
    }

    /// Build the `PostToolUseFailure` payload from a dispatched call and run the
    /// context-only failure path. Sole hook-presence gate for both failure
    /// sites (MCP error result and hard dispatch error).
    pub(super) async fn dispatch_tool_failure(
        &self,
        prepared: &PreparedToolCall,
        error_text: String,
        duration_ms: u64,
    ) -> Vec<fuigo_hooks::dispatcher::AdditionalContext> {
        if !self.may_have_hooks_for(fuigo_hooks::event::HookEventName::PostToolUseFailure) {
            return Vec::new();
        }
        let raw_input: serde_json::Value =
            serde_json::from_str(&prepared.raw_arguments).unwrap_or(serde_json::Value::Null);
        let (tool_input, tool_input_truncated) =
            fuigo_hooks::event::truncate_payload(with_retired_bash_background_field(raw_input, self.bash_auto_background_enabled()));
        let hook_tool_name = prepared.hook_tool_name();
        self.dispatch_post_tool_use_failure_hook(
            fuigo_hooks::event::HookPayload::PostToolUseFailure {
                tool_name: hook_tool_name.to_owned(),
                tool_use_id: prepared.call_id.clone(),
                tool_input,
                tool_input_truncated,
                error: error_text,
                duration_ms: Some(duration_ms),
                // No clean abort/cancel signal at these dispatch sites; failures
                // here are tool-reported, never interrupts.
                is_interrupt: false,
                subagent_type: self.subagent_type_label(),
            },
            hook_tool_name,
            &prepared.tool_call_id.0,
        )
        .await
    }

    /// Dispatch a `PostToolUseFailure` event: fire observe-only client hooks,
    /// then run the on-disk registry's context-only failure path. Returns the
    /// aggregated `additionalContext` notes for the caller to deliver after the
    /// failed tool result. Context-only — no block or output replacement.
    async fn dispatch_post_tool_use_failure_hook(
        &self,
        payload: fuigo_hooks::event::HookPayload,
        tool_name: &str,
        tool_call_id: &str,
    ) -> Vec<fuigo_hooks::dispatcher::AdditionalContext> {
        let event = fuigo_hooks::event::HookEventName::PostToolUseFailure;
        let envelope = self.fire_hook(event, None, payload);
        let Some(registry) = self.hook_registry.borrow().clone() else {
            return Vec::new();
        };
        let ctx = self.hook_run_ctx();
        let result =
            fuigo_hooks::dispatcher::dispatch_post_tool_use_failure(&registry, &envelope, &ctx)
                .await;
        self.send_hook_execution(
            &event.to_string(),
            Some(tool_name),
            Some(tool_call_id),
            None,
            &result.results,
        )
        .await;
        self.emit_hook_executed_telemetry(&event.to_string(), Some(tool_name), &result.results)
            .await;
        result.additional_context
    }

    /// Enforcement scope for a prompt-gate block: only a real user prompt on a top-level session.
    /// The event fires for every origin, but synthetic wakes and subagent sessions run the gate observe-only.
    pub(super) fn should_enforce_prompt_block(
        &self,
        origin: &crate::session::PromptOrigin,
    ) -> bool {
        origin.enforces_prompt_block() && !self.startup_hints.is_subagent
    }

    /// Run the `UserPromptSubmit` prompt gate: observe client hooks, then the on-disk registry, with shared scrollback and telemetry side effects.
    /// Returns the gate verdict; the caller decides whether to enforce it (`Block` rejects the prompt).
    pub(super) async fn dispatch_prompt_submit_hook(
        &self,
        payload: fuigo_hooks::event::HookPayload,
        prompt_id: Option<&str>,
    ) -> fuigo_hooks::result::PromptDecision {
        let event = fuigo_hooks::event::HookEventName::UserPromptSubmit;
        if !self.may_have_hooks_for(event) {
            return fuigo_hooks::result::PromptDecision::Allow;
        }
        // Fires observe-only client hooks before (and independent of) the on-disk registry guard below.
        let envelope = self.fire_hook(event, prompt_id.map(|s| s.to_string()), payload);
        let Some(registry) = self.hook_registry.borrow().clone() else {
            return fuigo_hooks::result::PromptDecision::Allow;
        };
        let ctx = self.hook_run_ctx();
        let gate = fuigo_hooks::dispatcher::dispatch_prompt_gate(&registry, &envelope, &ctx).await;
        self.send_hook_execution(&event.to_string(), None, None, prompt_id, &gate.results)
            .await;
        self.emit_hook_executed_telemetry(&event.to_string(), None, &gate.results)
            .await;
        gate.decision
    }

    /// Decision 35: run the blocking `UserPromptSubmit` hook on a real peer message. Returns true when the message must be refused.
    /// Only a block counts; a rewrite, extra context or an approval from the hook is ignored (the prompt gate carries none of them).
    /// A hook that FAILS (error or timeout) is fail-open for a human prompt; for a peer message it refuses (fail closed).
    /// With no hook configured nothing runs. The hook text goes to the receiver's UI only, never to the sender.
    pub(super) async fn peer_prompt_hook_refuses(
        &self,
        envelope: &fuigo_peer::Envelope,
        wrapped: &str,
        prompt_id: &str,
    ) -> bool {
        let event = fuigo_hooks::event::HookEventName::UserPromptSubmit;
        if !self.may_have_hooks_for(event) {
            return false;
        }
        let hook_envelope = self.fire_hook(
            event,
            Some(prompt_id.to_owned()),
            fuigo_hooks::event::HookPayload::UserPromptSubmit {
                prompt: Some(wrapped.to_owned()),
                shell_command: None,
                subagent_type: self.subagent_type_label(),
                origin: Some("peer_message".to_owned()),
                peer_sender: Some(envelope.from.to_string()),
                peer_claimed_mode: Some(envelope.from_mode.to_wire()),
            },
        );
        let Some(registry) = self.hook_registry.borrow().clone() else {
            return false;
        };
        let ctx = self.hook_run_ctx();
        let gate = fuigo_hooks::dispatcher::dispatch_prompt_gate(&registry, &hook_envelope, &ctx).await;
        // The hook saw peer text: its block reason, error and output are not shown or logged. Names and outcome only.
        let redacted = redact_peer_hook_results(&gate.results);
        self.send_hook_execution(&event.to_string(), None, None, Some(prompt_id), &redacted)
            .await;
        self.emit_hook_executed_telemetry(&event.to_string(), None, &gate.results)
            .await;
        match gate.decision {
            fuigo_hooks::result::PromptDecision::Block { hook_name, .. } => {
                tracing::info!(%hook_name, "peer message refused by user_prompt_submit hook");
                true
            }
            fuigo_hooks::result::PromptDecision::Allow => {
                let failed = gate
                    .results
                    .iter()
                    .any(|r| matches!(r, fuigo_hooks::result::HookRunResult::Failed { .. }));
                if failed {
                    let names: Vec<&str> = redacted.iter().map(peer_hook_result_name).collect();
                    tracing::info!(hooks = ?names, "peer message refused: user_prompt_submit hook failed (fail closed)");
                }
                failed
            }
        }
    }

    pub(super) async fn emit_hook_executed_telemetry(
        &self,
        event_name: &str,
        tool_name: Option<&str>,
        results: &[fuigo_hooks::result::HookRunResult],
    ) {
        let tool = tool_name.map(|s| s.to_string());
        for r in results {
            let (hook_name, elapsed, outcome) = match r {
                fuigo_hooks::result::HookRunResult::Success {
                    hook_name, elapsed, ..
                } => (
                    hook_name,
                    elapsed,
                    fuigo_telemetry::events::HookOutcome::Success,
                ),
                fuigo_hooks::result::HookRunResult::Blocked {
                    hook_name, elapsed, ..
                } => (
                    hook_name,
                    elapsed,
                    fuigo_telemetry::events::HookOutcome::Blocked,
                ),
                fuigo_hooks::result::HookRunResult::Failed {
                    hook_name, elapsed, ..
                } => (
                    hook_name,
                    elapsed,
                    fuigo_telemetry::events::HookOutcome::Error,
                ),
                fuigo_hooks::result::HookRunResult::Skipped { .. } => continue,
            };
            fuigo_telemetry::session_ctx::log_event(fuigo_telemetry::events::HookExecuted {
                hook_name: hook_name.clone(),
                event: event_name.to_string(),
                tool_name: tool.clone(),
                duration_ms: elapsed.as_millis() as u64,
                outcome,
            });
        }
    }
}

fn peer_hook_result_name(r: &fuigo_hooks::result::HookRunResult) -> &str {
    use fuigo_hooks::result::HookRunResult as R;
    match r {
        R::Success { hook_name, .. }
        | R::Skipped { hook_name }
        | R::Blocked { hook_name, .. }
        | R::Failed { hook_name, .. } => hook_name,
    }
}

/// Hook results for a peer message with the free text removed (block detail, error, system message, HTTP info).
pub(super) fn redact_peer_hook_results(
    results: &[fuigo_hooks::result::HookRunResult],
) -> Vec<fuigo_hooks::result::HookRunResult> {
    use fuigo_hooks::result::HookRunResult as R;
    results
        .iter()
        .map(|r| match r {
            R::Success { hook_name, elapsed, .. } => R::Success {
                hook_name: hook_name.clone(),
                elapsed: *elapsed,
                http_info: None,
                system_message: None,
            },
            R::Skipped { hook_name } => R::Skipped { hook_name: hook_name.clone() },
            R::Blocked { hook_name, elapsed, .. } => R::Blocked {
                hook_name: hook_name.clone(),
                detail: String::new(),
                elapsed: *elapsed,
                http_info: None,
                system_message: None,
            },
            R::Failed { hook_name, elapsed, .. } => R::Failed {
                hook_name: hook_name.clone(),
                error: String::new(),
                elapsed: *elapsed,
                http_info: None,
                system_message: None,
            },
        })
        .collect()
}

#[cfg(test)]
mod notification_hook_filter_tests {
    use super::*;
    use crate::extensions::notification::{
        FeedbackRequestNotification, HookRunEntryDto, HookRunStatusDto, RetryState,
    };

    #[test]
    fn hook_updates_do_not_fire_notification_hook() {
        let execution = FuigoSessionUpdate::HookExecution {
            event_name: "pre_tool_use".into(),
            tool_name: Some("read_file".into()),
            tool_call_id: None,
            prompt_id: None,
            runs: vec![HookRunEntryDto {
                name: "test".into(),
                status: HookRunStatusDto::Success { elapsed_ms: 1 },
                output: None,
            }],
        };
        assert!(notification_hook_for_update(&execution).is_none());

        let annotation = FuigoSessionUpdate::HookAnnotation {
            message: "running hooks".into(),
        };
        assert!(notification_hook_for_update(&annotation).is_none());
    }

    #[test]
    fn retry_in_progress_does_not_fire_notification_hook() {
        let update = FuigoSessionUpdate::RetryState(RetryState::Retrying {
            attempt: 1,
            max_retries: 3,
            reason: "timeout".into(),
            error_type: None,
            verdicts: None,
            discard_emitted: false,
            message_id: None,
            stream_start_ms: None,
        });
        assert!(notification_hook_for_update(&update).is_none());
    }

    #[test]
    fn feedback_request_does_not_fire_notification_hook() {
        let update = FuigoSessionUpdate::FeedbackRequest(FeedbackRequestNotification {
            request_id: "req-1".into(),
            tier: "tier1".into(),
            prompt: "How was this session?".into(),
            dismissible: true,
            trigger_type: "tier1_engagement".into(),
            trigger_condition: "turns >= 10".into(),
            trigger_reason: "long session".into(),
            stars: true,
            thumbs: false,
            text: false,
        });
        assert!(notification_hook_for_update(&update).is_none());
    }

    #[test]
    fn diff_review_fires_permission_prompt() {
        let update = FuigoSessionUpdate::DiffReview { content: vec![] };
        let (ty, message, _, level) = notification_hook_for_update(&update).expect("should fire");
        assert_eq!(ty, "permission_prompt");
        assert_eq!(message.as_deref(), Some("Diff review requested"));
        assert_eq!(level.as_deref(), Some("info"));
    }

    #[test]
    fn task_completed_does_not_fire_via_filter() {
        let update = FuigoSessionUpdate::TaskCompleted {
            task_snapshot: fuigo_tools::types::TaskSnapshot {
                task_id: "task-1".into(),
                command: "echo hi".into(),
                display_command: None,
                cwd: "/tmp".into(),
                start_time: std::time::SystemTime::UNIX_EPOCH,
                end_time: None,
                output: String::new(),
                output_file: std::path::PathBuf::from("/tmp/out"),
                truncated: false,
                exit_code: Some(0),
                signal: None,
                completed: true,
                kind: Default::default(),
                block_waited: false,
                explicitly_killed: false,
                kill_result_delivered: false,
                owner_session_id: None,
                description: None,
                is_backgrounded: false,
                output_total_bytes: 0,
            },
            will_wake: false,
        };
        assert!(notification_hook_for_update(&update).is_none());
    }
}

/// Hook payload for the Bash tool's background fields.
///
/// The tool input carries `block_until_ms` (0 means background) instead of `is_background`, but hooks written against the
/// old shape (some deny background commands) still read `tool_input.is_background`. For a shell-command input (a string
/// `command` plus any of `block_until_ms`, `is_background`, `background`) two fields are therefore set, always overriding
/// whatever the model sent:
///
/// - `is_background`: `true` exactly when the call runs as a background task, computed by the runner's own decision
///   ([`fuigo_tools::implementations::fuigo_build::bash::raw_input_requests_background`], the rule `BashTool::execute`
///   uses): `block_until_ms: 0`, or the retired boolean when there is no `block_until_ms`. A model sending
///   `block_until_ms: 0` with `is_background: false` therefore reaches hooks as `true`.
/// - `may_background_after_wait`: `true` for a foreground call (a positive wait, or none) when the user's
///   `auto_background_on_timeout` setting is on, meaning the command moves to the background if it outlives the wait.
///   With the setting off the command is stopped at the wait and this is `false`. It is `false` for a background task.
///
/// Other inputs are passed through unchanged.
pub(super) fn with_retired_bash_background_field(
    mut input: serde_json::Value,
    auto_background_on_timeout: bool,
) -> serde_json::Value {
    let Some(obj) = input.as_object_mut() else {
        return input;
    };
    let is_bash_shape = obj.get("command").is_some_and(serde_json::Value::is_string)
        && ["block_until_ms", "is_background", "background"]
            .iter()
            .any(|k| obj.contains_key(*k));
    if !is_bash_shape {
        return input;
    }
    let is_background = fuigo_tools::implementations::fuigo_build::bash::raw_input_requests_background(
        &serde_json::Value::Object(obj.clone()),
    );
    obj.insert("is_background".to_string(), serde_json::Value::Bool(is_background));
    obj.insert(
        "may_background_after_wait".to_string(),
        serde_json::Value::Bool(!is_background && auto_background_on_timeout),
    );
    input
}

#[cfg(test)]
mod retired_bash_background_field_tests {
    use super::with_retired_bash_background_field as compat;
    use serde_json::json;

    fn fields(input: serde_json::Value, auto_bg: bool) -> (serde_json::Value, serde_json::Value) {
        let out = compat(input, auto_bg);
        (out["is_background"].clone(), out["may_background_after_wait"].clone())
    }

    /// The hook payload must equal the runner's decision for every combination of the two fields.
    #[test]
    fn is_background_equals_the_runner_decision_in_every_combination() {
        use fuigo_tools::implementations::fuigo_build::bash::BashToolInput;
        let blocks = [None, Some(json!(0)), Some(json!("0")), Some(json!(1)), Some(json!(5000)), Some(json!("5000"))];
        let bools = [None, Some(json!(true)), Some(json!(false)), Some(json!("true")), Some(json!("false")), Some(json!("yes")), Some(json!(1))];
        for block in &blocks {
            for flag in &bools {
                let mut input = json!({"command": "x", "description": "d"});
                if let Some(b) = block {
                    input["block_until_ms"] = b.clone();
                }
                if let Some(f) = flag {
                    input["is_background"] = f.clone();
                }
                let runner = fuigo_tools::implementations::fuigo_build::BashTool::requests_background(
                    &serde_json::from_value::<BashToolInput>(input.clone()).unwrap(),
                );
                for auto_bg in [false, true] {
                    if block.is_none() && flag.is_none() {
                        assert_eq!(compat(input.clone(), auto_bg), input);
                        continue;
                    }
                    let (is_bg, may) = fields(input.clone(), auto_bg);
                    assert_eq!(is_bg, json!(runner), "{input} auto_bg={auto_bg}");
                    assert_eq!(may, json!(!runner && auto_bg), "{input} auto_bg={auto_bg}");
                }
            }
        }
    }

    #[test]
    fn a_hostile_false_cannot_hide_a_background_task() {
        let (is_bg, may) = fields(json!({"command": "x", "block_until_ms": 0, "is_background": false}), true);
        assert_eq!((is_bg, may), (json!(true), json!(false)));
        let (is_bg, _) = fields(json!({"command": "x", "block_until_ms": 0, "background": "false"}), false);
        assert_eq!(is_bg, json!(true));
    }

    #[test]
    fn a_positive_wait_is_foreground_and_may_background_only_under_the_setting() {
        assert_eq!(fields(json!({"command": "x", "block_until_ms": 1}), true), (json!(false), json!(true)));
        assert_eq!(fields(json!({"command": "x", "block_until_ms": 1}), false), (json!(false), json!(false)));
        assert_eq!(fields(json!({"command": "x", "block_until_ms": 1, "is_background": true}), false), (json!(false), json!(false)));
    }

    #[test]
    fn leaves_other_inputs_alone() {
        for input in [
            json!({"command": "x"}),
            json!({"path": "p", "block_until_ms": 0}),
            json!("text"),
        ] {
            assert_eq!(compat(input.clone(), true), input);
        }
    }
}
