use super::*;
use crate::remote::DEFAULT_CONTEXT_WINDOW;
use fuigo_chat_state::conversation_util::replace_or_insert_system_head;
impl SessionActor {
    /// The one place a rewritten system prompt is composed after spawn (model switch, harness rebuild).
    /// A client `systemPromptOverride` wins verbatim, as at spawn.
    /// Otherwise the freshly rendered `template` gets back the `<human_rules>` block (`_meta.rules`) of `current_system`.
    pub(super) fn recompose_system_prompt(
        &self,
        template: &str,
        current_system: Option<&str>,
    ) -> String {
        if let Some(override_prompt) = self.system_prompt_override.borrow().as_ref() {
            return override_prompt.clone();
        }
        crate::session::human_rules::recompose_with_rules(template, current_system)
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn handle_set_session_model(
        self: &std::sync::Arc<Self>,
        mut sampling_config: fuigo_sampler::SamplerConfig,
        use_concise: bool,
        is_family_switch: bool,
        apply_prompt_override: bool,
        skip_prompt_rewrite: bool,
        auto_compact_threshold_percent: u8,
        context_window: crate::session::ContextWindowSwitch,
    ) -> Result<acp::ModelId, acp::Error> {
        let model_id = acp::ModelId::new(sampling_config.model.clone());
        let crate::session::ContextWindowSwitch {
            selection: context_window_selection,
            supported: supported_context_windows,
        } = context_window;
        let supported = |window: &std::num::NonZeroU64| supported_context_windows.contains(window);
        let selection = match context_window_selection {
            crate::session::SwitchContextWindow::Preserve => {
                crate::session::handle::load_context_window_selection(
                    &self.compaction.context_window_selection,
                )
            }
            crate::session::SwitchContextWindow::Set(selection) => {
                let selection = selection.filter(supported);
                self.compaction.context_window_selection.store(
                    selection.map_or(0, std::num::NonZeroU64::get),
                    std::sync::atomic::Ordering::Relaxed,
                );
                selection
            }
        };
        if let Some(window) = selection.filter(supported) {
            sampling_config.context_window = window.get();
        }
        // F8: the family the session is leaving, read before the new config replaces it.
        let old_model = self
            .chat_state_handle
            .get_sampling_config()
            .await
            .map(|config| config.model);
        // The replayed side-call tool list aligned with the old model's cache; the next main turn records a fresh one
        self.last_sent_tool_specs.replace(None);
        let new_context_window = self.compaction.context_window_override.unwrap_or_else(|| {
            std::num::NonZeroU64::new(sampling_config.context_window).unwrap_or_else(|| {
                std::num::NonZeroU64::new(DEFAULT_CONTEXT_WINDOW)
                    .expect("DEFAULT_CONTEXT_WINDOW is non-zero")
            })
        });
        let prev_threshold = self.compaction.threshold_percent.get();
        if prev_threshold != auto_compact_threshold_percent {
            tracing::info!(
                session_id = %self.session_info.id.0,
                new_model = %sampling_config.model,
                old_threshold = prev_threshold,
                new_threshold = auto_compact_threshold_percent,
                "auto_compact_threshold_percent updated for model switch"
            );
        }
        self.compaction
            .threshold_percent
            .set(auto_compact_threshold_percent);
        self.supports_backend_search
            .set(sampling_config.supports_backend_search);
        self.programmatic_tool_calling
            .set(sampling_config.programmatic_tool_calling);
        self.compactions_remaining
            .set(sampling_config.compactions_remaining);
        self.compaction_at_tokens
            .set(sampling_config.compaction_at_tokens);
        fuigo_telemetry::unified_log::info(
            "backend_search: model switch",
            Some(self.session_info.id.0.as_ref()),
            Some(serde_json::json!({
                "new_model": &sampling_config.model,
                "api_backend": format!("{:?}", sampling_config.api_backend),
                "supports_backend_search": sampling_config.supports_backend_search,
            })),
        );
        self.chat_state_handle
            .update_sampling_config(fuigo_sampling_types::SamplingConfig {
                base_url: sampling_config.base_url.clone(),
                model: sampling_config.model.clone(),
                max_completion_tokens: sampling_config.max_completion_tokens,
                temperature: sampling_config.temperature,
                top_p: sampling_config.top_p,
                max_retries: Some(fuigo_sampler::resolve_max_retries(
                    sampling_config.max_retries,
                )),
                api_backend: sampling_config.api_backend.clone(),
                extra_headers: sampling_config.extra_headers.clone(),
                query_params: sampling_config.query_params.clone(),
                env_http_headers: sampling_config.env_http_headers.clone(),
                context_window: new_context_window,
                max_request_bytes: sampling_config.max_request_bytes,
                reasoning_effort: sampling_config.reasoning_effort,
                stream_tool_calls: Some(sampling_config.stream_tool_calls),
                mtls_cert_dir: sampling_config.mtls_cert_dir.clone(),
                rate_limit_retry_threshold: sampling_config.rate_limit_retry_threshold,
                reasoning_summary: sampling_config.reasoning_summary,
            });
        let existing = self.chat_state_handle.get_credentials().await;
        let session_key = self
            .auth_manager
            .as_ref()
            .and_then(|am| am.current_or_expired().map(|a| a.key));
        self.chat_state_handle
            .update_credentials(fuigo_chat_state::Credentials {
                api_key: sampling_config.api_key.clone(),
                auth_type: crate::agent::config::resolve_chat_state_auth_type(
                    sampling_config.model.as_str(),
                    session_key.as_deref(),
                    existing.auth_type,
                ),
                alpha_test_key: existing.alpha_test_key,
                client_version: sampling_config.client_version.clone(),
            });
        self.invalidate_model_auth_memo();
        self.signals_handle()
            .record_model_usage(&sampling_config.model);
        if apply_prompt_override && !skip_prompt_rewrite {
            let mut conversation = self.chat_state_handle.get_conversation().await;
            for item in conversation.iter_mut() {
                if let ConversationItem::System(sys) = item {
                    let template = if use_concise {
                        fuigo_agent::prompt::template::COMPACT_SYSTEM_PROMPT.to_owned()
                    } else {
                        self.agent.borrow().system_prompt().to_owned()
                    };
                    // The memory block is injected once per segment, so the rewrite must carry it over
                    sys.content = std::sync::Arc::<str>::from(
                        crate::session::human_rules::keep_memory_tail(
                            self.recompose_system_prompt(&template, Some(&sys.content)),
                            &sys.content,
                        ),
                    );
                    break;
                }
            }
            self.chat_state_handle.replace_conversation(conversation);
            self.note_history_not_rewritten("the new model's instructions")
                .await;
        } else if !apply_prompt_override {
            tracing::info!(
                session_id = %self.session_info.id.0,
                model_id = %model_id.0,
                "handle_set_session_model: skipping prompt override (apply_prompt_override=false)"
            );
        } else {
            tracing::info!(
                session_id = %self.session_info.id.0,
                model_id = %model_id.0,
                "handle_set_session_model: skipping prompt rewrite (just rebuilt harness)"
            );
        }
        let agent_name = self.agent.borrow().definition().name.clone();
        let _ = self
            .notifications
            .persistence_tx
            .send(PersistenceMsg::CurrentModel {
                model_id: model_id.clone(),
                agent_name: Some(agent_name),
                reasoning_effort: Some(sampling_config.reasoning_effort),
                context_window: Some(selection),
            });
        self.emit_status_snapshot_detached();
        let turn_in_flight = self.state.lock().await.running_task.is_some();
        if turn_in_flight && is_family_switch {
            tracing::warn!("Family-switch compact skipped: turn in flight");
        }
        // A parked (or parking) session makes no model call and its actor must stay free for the unpark: the
        // compaction is owed and runs at the implicit unpark, before the prompt's turn. The debt is tracked
        // against the ORIGIN family, so a switch that returns to it owes nothing.
        let identity_of = |model: &str| {
            let models = self.models_manager.models();
            crate::agent::config::find_model_by_id(&models, model)
                .and_then(|e| e.info.model_family.clone())
                .unwrap_or_else(|| model.to_owned())
        };
        let arriving = identity_of(&sampling_config.model);
        let leaving = old_model.as_deref().map(identity_of);
        let minted =
            is_family_switch && !turn_in_flight && self.history_has_model_minted_items().await;
        let parked = crate::session::quiesce::owe(&self.session_info.id.0, |o| {
            o.note_model_switch(minted, leaving.clone(), &arriving);
        });
        if parked {
            tracing::info!("Family-switch compact: session is parked; owed state updated");
        } else if minted {
            tracing::info!("Family-switch compact: -> {}", sampling_config.model);
            self.run_family_switch_compact(Some(new_context_window.get()))
                .await;
        }
        Ok(model_id)
    }
    /// Compacts the model-minted history after a family switch; a failure is logged and the switch stands.
    /// `context_window` is `None` for an owed compaction: the window is the session's CURRENT one, read here.
    pub(super) async fn run_family_switch_compact(
        self: &std::sync::Arc<Self>,
        context_window: Option<u64>,
    ) {
        let context_window = match (context_window, self.compaction.context_window_override) {
            (Some(window), _) => window,
            (None, Some(window)) => window.get(),
            (None, None) => self
                .chat_state_handle
                .get_sampling_config()
                .await
                .map(|config| config.context_window.get())
                .unwrap_or(DEFAULT_CONTEXT_WINDOW),
        };
        self.abort_and_clear_prefire().await;
        let estimated_total_tokens = self.chat_state_handle.get_estimated_total_tokens().await;
        let trigger_info = compaction::AutoCompactTriggerInfo {
            tokens_used: estimated_total_tokens,
            context_window,
            percentage: fuigo_token_estimation::usage_percentage_u8(
                estimated_total_tokens,
                context_window,
            ),
        };
        if let Err(e) = self.run_compact_only(trigger_info, true).await {
            tracing::error!(error = %crate::sampling::error::acp_error_text(&e), "Family-switch compaction failed; switching anyway");
        }
    }
    /// Set the reasoning effort on the live sampling config, applying the same
    /// support check and per-effort model routing as `apply_supported_effort`.
    pub(super) async fn handle_set_reasoning_effort(
        self: &std::sync::Arc<Self>,
        effort: fuigo_sampling_types::ReasoningEffort,
    ) -> Result<acp::ModelId, acp::Error> {
        let Some(mut cfg) = self.chat_state_handle.get_sampling_config().await else {
            return Err(crate::acp_error::internal_error(
                "session has no sampling config",
            ));
        };
        if !self
            .models_manager
            .model_supports_reasoning_effort(&cfg.model)
        {
            return Err(crate::acp_error::invalid_params(
                "the session's current model does not support reasoning effort",
            ));
        }
        if let Some(routed) = self.models_manager.model_for_effort(&cfg.model, effort) {
            // P169 (Astra r1 #6): the fleet `allowed_models` pin binds the per-effort model id.
            if !self.models_manager.effort_route_allowed(&routed) {
                return Err(crate::acp_error::invalid_params(
                    "This reasoning effort uses a model your organization's policy (requirements.toml allowed_models) does not allow.",
                ));
            }
            cfg.model = routed;
        }
        cfg.reasoning_effort = Some(effort);
        let model_id = acp::ModelId::new(cfg.model.clone());
        self.chat_state_handle.update_sampling_config(cfg);
        let agent_name = self.agent.borrow().definition().name.clone();
        let _ = self
            .notifications
            .persistence_tx
            .send(PersistenceMsg::CurrentModel {
                model_id: model_id.clone(),
                agent_name: Some(agent_name),
                reasoning_effort: Some(Some(effort)),
                context_window: None,
            });
        self.emit_status_snapshot_detached();
        Ok(model_id)
    }
    /// Handle [`SessionCommand::RebuildAgentForDefinition`].
    ///
    /// Builds a fresh [`fuigo_agent::Agent`] from the cached [`crate::session::agent_rebuild::AgentRebuildSpec`] and the supplied definition.
    /// Replaces `self.agent`, rewrites the system message in the conversation, persists the new prompt artifacts, and updates `active_agent_type`.
    ///
    /// Triggered from `MvpAgent::set_session_model` only when the new model's `agent_type` differs from the session's `active_agent_type`.
    /// The trigger also requires `turn_count == 0` (no user message has been sent yet).
    /// Defense-in-depth: rejects if a turn is in flight.
    pub(super) async fn handle_rebuild_agent_for_definition(
        &self,
        definition: fuigo_agent::AgentDefinition,
    ) -> Result<(), acp::Error> {
        {
            let state = self.state.lock().await;
            if state.running_task.is_some() {
                tracing::warn!(
                    session_id = %self.session_info.id.0,
                    new_agent_type = %definition.name,
                    "handle_rebuild_agent_for_definition: turn in flight, rejecting rebuild"
                );
                return Err(crate::acp_error::internal_error(
                    "rebuild_agent: turn in flight, refusing to rebuild harness",
                ));
            }
        }
        let new_agent_name = definition.name.clone();
        let previous_mcp_servers = self.agent.borrow().definition().mcp_servers.clone();
        // A rebuilt harness advertises its own tools; side calls preview them until the next main turn records what it sent
        self.last_sent_tool_specs.replace(None);
        tracing::info!(
            session_id = %self.session_info.id.0,
            new_agent_type = %new_agent_name,
            "handle_rebuild_agent_for_definition: rebuilding harness"
        );
        let new_agent = self
            .rebuild_spec
            .build_agent(definition)
            .await
            .map_err(|e| {
                tracing::error!(
                    session_id = %self.session_info.id.0,
                    new_agent_type = %new_agent_name,
                    error = %e,
                    "handle_rebuild_agent_for_definition: AgentBuilder::build failed"
                );
                crate::acp_error::internal_error(format!(
                    "rebuild_agent: build failed for agent_type={new_agent_name}: {e}"
                ))
            })?;
        let current_system = self
            .chat_state_handle
            .get_conversation_for_model()
            .await
            .into_iter()
            .find_map(|item| match item {
                ConversationItem::System(sys) => Some(sys.content.to_string()),
                _ => None,
            });
        let mut new_system_prompt =
            self.recompose_system_prompt(new_agent.system_prompt(), current_system.as_deref());
        if let Some(current) = current_system.as_deref() {
            new_system_prompt =
                crate::session::human_rules::keep_memory_tail(new_system_prompt, current);
        }
        let mut new_prompt_context = new_agent.prompt_context().clone();
        new_prompt_context.normalize_for_persistence();
        self.abort_and_clear_prefire().await;
        *self.agent.borrow_mut() = new_agent;
        // The agent's own inline hooks belong to the definition: swap them with it, and tell an open hooks view
        self.replace_agent_inline_hooks();
        {
            let hooks = crate::extensions::hooks::current_hook_infos(
                self.hook_registry.borrow().as_deref(),
                &self.session_info.id.0,
                &self.hook_resolved_workspace_root,
            );
            let load_errors = self.hook_load_errors.borrow().clone();
            let project_trusted =
                Self::session_hook_trust(std::path::Path::new(&self.session_info.cwd), None);
            self.send_fuigo_notification(FuigoSessionUpdate::HooksChanged {
                hooks,
                project_trusted,
                load_errors,
            })
            .await;
        }
        *self.active_agent_type.lock() = Some(new_agent_name.clone());
        self.emit_resolved_tool_overrides();
        self.queue_exit_reminder_on_approved_exit.store(
            self.is_cursor_harness(),
            std::sync::atomic::Ordering::Relaxed,
        );
        if let Err(e) = self.workspace_ops.bind_local_session_governed(
            &self.session_id_string(),
            self.tool_context.cwd.as_path().to_path_buf(),
            self.tool_context.hunk_tracker_handle.clone(),
            self.agent.borrow().tool_bridge().toolset(),
            None,
            self.tool_context.peer_influence.clone(),
            self.permissions.has_launch_policy(),
        ) {
            tracing::warn!(error = %e, "failed to rebind local session toolset after agent rebuild");
        }
        {
            let bridge = self.agent.borrow().tool_bridge().clone();
            let snapshot = self.tool_metadata_snapshot.clone();
            let tool_index = crate::session::tool_index::Bm25ToolSearchIndex::new(snapshot);
            bridge
                .update_resource(fuigo_tools::types::tool_index::ToolIndex(
                    std::sync::Arc::new(tool_index),
                ))
                .await;
            if let Some(client) = self.rebuild_spec.managed_gateway_tool_client.clone() {
                bridge.update_resource(client).await;
            }
            let plan_path = self.plan_mode.lock().plan_file_path().to_path_buf();
            bridge
                .update_resource(fuigo_tools::types::resources::PlanFilePath(plan_path))
                .await;
            // P148 (B19): the rebuilt agent's `ask_user_question` follows the attached client, not the spawn hints.
            self.sync_ask_user_question_attachment().await;
            if let Some(display_cwd) = self.display_cwd.get() {
                bridge
                    .set_display_cwd(std::path::PathBuf::from(display_cwd))
                    .await;
            }
            bridge
                .update_resource(
                    fuigo_tools::implementations::fuigo_build::workflow::WorkflowLaunchHandle(
                        self.workflow_launch_tx.clone(),
                    ),
                )
                .await;
            if !self.goal_runs_on_workflow_engine() {
                bridge
                    .update_resource(
                        fuigo_tools::implementations::fuigo_build::update_goal::GoalUpdateHandle(
                            self.goal_update_tx.clone(),
                        ),
                    )
                    .await;
            }
            if let Some(reservations) = self.tool_context.task_completion_reservations.clone() {
                bridge.update_resource(reservations).await;
            }
            if let Some(gate) = self.tool_context.task_wake_suppressed.clone() {
                bridge.update_resource(gate).await;
            }
            self.inject_deny_read_globs().await;
        }
        // The new seat's own `mcpServers` replace the previous seat's before the handshake wait below.
        self.switch_agent_seat_mcp_servers(&previous_mcp_servers)
            .await;
        {
            let notified = self.mcp_handshakes_done.notified();
            tokio::pin!(notified);
            let needs_wait = {
                let s = self.mcp_state.lock().await;
                !s.configs.is_empty() && !s.is_initialized()
            };
            if needs_wait {
                const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
                tokio::select! {
                    () = &mut notified => {}
                    () = tokio::time::sleep(TIMEOUT) => {
                        tracing::warn!(
                            session_id = %self.session_info.id.0,
                            "handle_rebuild_agent_for_definition: timed out waiting for MCP handshakes"
                        );
                    }
                }
            }
        }
        self.re_register_mcp_tools_on_rebuilt_bridge().await;
        if let Some(old_handle) = self.deferred_prefix.take() {
            old_handle.abort();
        }
        let new_user_prefix = self.build_user_message_prefix().await;
        {
            let mut conversation = self.chat_state_handle.get_conversation().await;
            let _ = replace_or_insert_system_head(&mut conversation, &new_system_prompt);
            let drop_startup_skill_reminder = false;
            Self::rewrite_zero_turn_prefix(
                &mut conversation,
                new_user_prefix,
                drop_startup_skill_reminder,
            );
            if !conversation_has_project_instructions(&conversation)
                && let Some(agents_md_reminder) = self.agent.borrow().agents_md_user_reminder()
            {
                let agents_md_at = conversation.len().min(2);
                conversation.insert(
                    agents_md_at,
                    ConversationItem::project_instructions(agents_md_reminder),
                );
            }
            self.inject_baseline_skill_reminder(&mut conversation).await;
            self.chat_state_handle.replace_conversation(conversation);
        }
        save_prompt_context(&self.session_info, &new_prompt_context);
        save_system_prompt(&self.session_info, &new_system_prompt);
        let snapshot = self.chat_state_handle.get_conversation().await;
        persist_chat_history_jsonl_sync(&self.session_info, &snapshot);
        self.note_history_not_rewritten("the new agent's instructions")
            .await;
        self.mcp_reminder_dirty
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.send_available_commands_update().await;
        tracing::info!(
            session_id = %self.session_info.id.0,
            new_agent_type = %new_agent_name,
            "handle_rebuild_agent_for_definition: harness rebuild complete"
        );
        Ok(())
    }
    /// Apply a client-supplied `systemPromptOverride` on attach without wiping user/assistant history: swap only the leading `System` message.
    /// The swap happens atomically inside the `ChatStateActor` (see `ChatStateCommand::ReplaceSystemHead` for the serialization guarantees).
    /// `system_prompt.txt` (not owned by the persistence actor) is saved directly, even on a head no-op, so a diverged secondary artifact self-heals.
    /// Skipped entirely on a verbatim mirror-fork (`preserve_inherited_system`).
    pub(super) async fn handle_replace_system_prompt(&self, system_prompt: String) {
        if self.startup_hints.preserve_inherited_system {
            tracing::debug!(
                session_id = %self.session_info.id.0,
                "handle_replace_system_prompt: skipped (preserve_inherited_system)"
            );
            return;
        }
        *self.system_prompt_override.borrow_mut() = Some(system_prompt.clone());
        save_system_prompt_override(&self.session_info, &system_prompt);
        let Some(changed) = self
            .chat_state_handle
            .replace_system_head(&system_prompt)
            .await
        else {
            tracing::error!(
                session_id = %self.session_info.id.0,
                "handle_replace_system_prompt: chat-state actor unavailable; override not applied"
            );
            return;
        };
        save_system_prompt(&self.session_info, &system_prompt);
        if changed {
            tracing::info!(
                session_id = %self.session_info.id.0,
                prompt_len = system_prompt.len(),
                "handle_replace_system_prompt: client override applied"
            );
            self.note_history_not_rewritten("the client's system prompt override")
                .await;
        } else {
            tracing::debug!(
                session_id = %self.session_info.id.0,
                "handle_replace_system_prompt: head already matches, no-op"
            );
        }
    }
    /// Whether the conversation has anything a family switch must compact away.
    pub(super) async fn history_has_model_minted_items(&self) -> bool {
        self.chat_state_handle
            .get_conversation()
            .await
            .iter()
            .any(|item| {
                matches!(
                    item,
                    fuigo_sampling_types::ConversationItem::Assistant(_)
                        | fuigo_sampling_types::ConversationItem::Reasoning(_)
                        | fuigo_sampling_types::ConversationItem::BackendToolCall(_)
                )
            })
    }
    /// Abort and join an in-flight prefire pass-1 and drop its NOTE1 cache.
    pub(super) async fn abort_and_clear_prefire(&self) {
        if let Some(handle) = self.compaction.prefire.take_handle() {
            handle.abort();
            let _ = handle.await;
            self.compaction.prefire.finish();
        }
        self.compaction.prefire.clear();
    }
}
