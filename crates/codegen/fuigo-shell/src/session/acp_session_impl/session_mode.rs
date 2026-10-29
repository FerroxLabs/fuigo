//! Session/plan-mode concern for `SessionActor` (`handle_session_mode`, plan-mode reminders and persistence, active-template detection).
use super::*;
use fuigo_tools::types::BROWSER_USE_MODE_ID;
pub(super) fn prompt_mode_from_session_mode_id(session_mode_id: &acp::SessionModeId) -> PromptMode {
    use fuigo_tools::types::SessionMode;
    match SessionMode::from_id(session_mode_id.0.as_ref()) {
        SessionMode::Plan => PromptMode::Plan,
        SessionMode::Ask => PromptMode::Ask,
        SessionMode::Default => PromptMode::Agent,
    }
}
/// Inverse of [`prompt_mode_from_session_mode_id`]: the mode id a client displays for a prompt mode.
/// Needed wherever a transition the client did not drive has to be reported back to it.
pub(super) fn session_mode_id_from_prompt_mode(prompt_mode: PromptMode) -> acp::SessionModeId {
    use fuigo_tools::types::SessionMode;
    let mode = match prompt_mode {
        PromptMode::Plan => SessionMode::Plan,
        PromptMode::Ask => SessionMode::Ask,
        PromptMode::Agent => SessionMode::Default,
    };
    acp::SessionModeId::new(mode.as_id())
}
/// The mode id a client is told the session is in (`session/new`, `session/load`, `session/resume` `modes.current`).
///
/// One calculation for every advertiser: `plan` while the plan tracker is on (`Pending` or `Active`); `ExitPending` means
/// the user already switched plan off mid-turn and a non-plan update went out, so it falls through. Then `browser_use`
/// while browser mode is on (the in-memory bit on the plan tracker; cold callers pass `false`), then `ask` for the Ask
/// prompt mode, else `default`.
pub(crate) fn advertised_mode_id(
    plan: crate::session::plan_mode::PlanModeState,
    prompt: PromptMode,
    browser: bool,
) -> &'static str {
    use crate::session::plan_mode::PlanModeState;
    use fuigo_tools::types::SessionMode;
    if matches!(plan, PlanModeState::Pending | PlanModeState::Active) {
        return SessionMode::Plan.as_id();
    }
    if browser {
        return BROWSER_USE_MODE_ID;
    }
    if prompt == PromptMode::Ask {
        return SessionMode::Ask.as_id();
    }
    SessionMode::Default.as_id()
}
/// The id a plan exit reports: `browser_use` while browser mode is on, else the prompt mode's own id.
pub(super) fn plan_exit_mode_id(prompt_mode: PromptMode, browser: bool) -> acp::SessionModeId {
    if browser {
        acp::SessionModeId::new(BROWSER_USE_MODE_ID)
    } else {
        session_mode_id_from_prompt_mode(prompt_mode)
    }
}
/// Pass-through twin: no toolset in this build carries a plan-gated tool.
pub(super) fn filter_cursor_tools_by_plan_mode(
    defs: Vec<ToolDefinition>,
    _plan_active: bool,
) -> Vec<ToolDefinition> {
    defs
}
impl SessionActor {
    pub(super) fn apply_prompt_modes_to_snapshot(&self, snapshot: &mut TurnDeltaSnapshot) {
        snapshot.start_prompt_mode = Some(self.turn_start_prompt_mode.lock().to_string());
        snapshot.end_prompt_mode = Some(self.turn_prompt_mode.lock().to_string());
    }
    /// `false` twin: this agent type is not compiled into this build, so no session runs it.
    /// Keeps ungated call sites compiling in both configurations, like [`Self::is_cursor_harness`].
    pub(super) fn is_cursor_agent(&self) -> bool {
        false
    }
    /// `false` twin: this template integration is not compiled into this build, so no session runs it.
    /// Keeps ungated call sites compiling in both configurations.
    pub(super) fn is_cursor_harness(&self) -> bool {
        false
    }
    /// Whether browser mode is on (the in-memory bit on the plan tracker).
    pub(crate) fn browser_mode_on(&self) -> bool {
        self.plan_mode.lock().browser_use()
    }
    /// Put the browsing overlay on an outgoing request that carries session history (the main turn and parent-cache
    /// side calls). Writes nothing when browser mode is off.
    pub(crate) fn apply_effective_head(&self, items: &mut Vec<ConversationItem>) {
        crate::session::browser_mode::apply_browser_overlay(items, self.browser_mode_on());
    }
    pub(super) async fn handle_session_mode(&self, session_mode_id: acp::SessionModeId) {
        use fuigo_tools::types::SessionMode;
        // The ACP edge refuses these; an id from persisted state or an internal sender is ignored the same way, leaving
        // the prompt mode, the plan tracker and the agent untouched.
        if !fuigo_tools::types::is_supported_mode_id(session_mode_id.0.as_ref()) {
            tracing::warn!(
                session_id = %self.session_info.id.0,
                mode_id = ?session_mode_id.0,
                "ignoring unsupported session mode id"
            );
            return;
        }
        let prompt_mode = prompt_mode_from_session_mode_id(&session_mode_id);
        *self.current_prompt_mode.lock() = prompt_mode;
        let mode = SessionMode::from_id(session_mode_id.0.as_ref());
        let browser = session_mode_id.0.as_ref() == BROWSER_USE_MODE_ID;
        if mode.is_plan() {
            // Picking Plan leaves browser mode, in the same lock scope as the transition.
            let entered = {
                let mut tracker = self.plan_mode.lock();
                tracker.set_browser_use(false);
                tracker.enter_pending()
            };
            if entered {
                self.persist_plan_mode_state();
                self.enqueue_current_mode_update(acp::SessionModeId::new(
                    SessionMode::Plan.as_id(),
                ));
            }
            tracing::info!(
                session_id = %self.session_info.id.0,
                entered,
                "Plan mode toggled ON (Pending)"
            );
            let turn_in_flight = self.state.lock().await.running_task.is_some();
            if entered && turn_in_flight {
                self.activate_plan_mode_mid_turn().await;
            }
            fuigo_telemetry::session_ctx::log_event(fuigo_telemetry::events::PlanModeToggled {
                enabled: true,
                trigger: fuigo_telemetry::events::PlanModeTrigger::User,
                turn_in_flight,
                was_previously_active: !entered,
            });
            if entered {
                tracing::info_span!(
                    "session.permission_mode_changed",
                    from_mode =
                        super::telemetry::permission_mode_label(self.permissions.is_yolo_mode()),
                    to_mode = "plan",
                    trigger = "user",
                    enabled = true,
                )
                .in_scope(|| {});
            }
            return;
        }
        let was_plan = {
            let tracker = self.plan_mode.lock();
            tracker.state() != crate::session::plan_mode::PlanModeState::Inactive
        };
        if was_plan {
            let turn_in_flight = self.state.lock().await.running_task.is_some();
            self.plan_mode.lock().user_exit(turn_in_flight);
            self.persist_plan_mode_state();
            tracing::info!(
                session_id = %self.session_info.id.0,
                new_mode = %session_mode_id.0,
                turn_in_flight,
                "Plan mode toggled OFF"
            );
            fuigo_telemetry::session_ctx::log_event(fuigo_telemetry::events::PlanModeToggled {
                enabled: false,
                trigger: fuigo_telemetry::events::PlanModeTrigger::User,
                turn_in_flight,
                was_previously_active: true,
            });
            tracing::info_span!(
                "session.permission_mode_changed",
                from_mode = "plan",
                to_mode = %session_mode_id.0,
                trigger = "user",
                enabled = false,
            )
            .in_scope(|| {});
        }
        // Every accepted non-plan switch is reported, as the id attach advertises. The bit is set (`browser_use`) or
        // cleared (`default`, `ask`) and the id read in one lock scope.
        let mode_id = {
            let mut tracker = self.plan_mode.lock();
            tracker.set_browser_use(browser);
            advertised_mode_id(
                crate::session::plan_mode::PlanModeState::Inactive,
                prompt_mode,
                tracker.browser_use(),
            )
        };
        self.enqueue_current_mode_update(acp::SessionModeId::new(mode_id));
        // Browser mode writes no head and keeps the session's agent: requests carry the overlay while the bit is on
        // (`crate::session::browser_mode`).
        if browser {
            return;
        }
        let agent_def = {
            let cwd = self.tool_context.cwd.as_path();
            fuigo_agent::discovery::by_name_in_cwd(session_mode_id.0.as_ref(), cwd)
        };
        if let Some(ref def) = agent_def {
            tracing::info!(
                session_id = %self.session_info.id.0,
                agent_name = %def.name,
                agent_scope = %def.scope,
                prompt_mode = ?def.prompt_mode,
                has_completion_req = def.completion_requirement.is_some(),
                tool_configs = def.tool_config.tools.len(),
                "Resolved AgentDefinition for session mode"
            );
            // `Agent::update_policies_from_definition` is a documented no-op (policies live in
            // the registry now); calling it held a `Ref<Agent>` across an await for nothing.
            *self.active_agent_type.lock() = Some(def.name.clone());
        }
        if let Some(ref def) = agent_def {
            // Take the context and a bridge handle in one short borrow, then render: a
            // `Ref<Agent>` parked across the render await would make a harness rebuild's
            // `borrow_mut` panic.
            let (ctx, bridge) = {
                let agent = self.agent.borrow();
                (
                    agent.prompt_context_for_definition(def),
                    std::sync::Arc::clone(agent.tool_bridge()),
                )
            };
            let Some(template) = ctx.render(&bridge).await else {
                tracing::warn!(
                    session_id = %self.session_info.id.0,
                    agent_name = %def.name,
                    "mode definition did not render; system prompt left as is"
                );
                return;
            };
            // The definition supplies only the template: the head is composed as every other rewrite composes it
            // (client override, then `_meta.rules`), and the turn's memory block is kept.
            let mut conversation = self.chat_state_handle.get_conversation().await;
            let mut changed = false;
            for item in conversation.iter_mut() {
                if let ConversationItem::System(sys) = item {
                    let head = crate::session::human_rules::keep_memory_tail(
                        self.recompose_system_prompt(&template, Some(&sys.content)),
                        &sys.content,
                    );
                    if *sys.content != *head {
                        sys.content = std::sync::Arc::<str>::from(head);
                        changed = true;
                    }
                    break;
                }
            }
            if changed {
                self.chat_state_handle.replace_conversation(conversation);
                self.note_history_not_rewritten("the new mode's instructions")
                    .await;
            }
        }
    }
    /// Settle the mode a turn runs in, applying the prompt's declaration when it made one.
    ///
    /// Only a real user turn declares a mode.
    /// Synthetic turns (a background task wake, a goal summary, a notification drain) inherit the session's mode.
    /// Their placeholder `PromptMode::Agent` reads as "the user asked for agent mode".
    /// Reconciling one would end plan mode just by waking the session.
    ///
    /// Returns the resolved mode rather than echoing the argument, so a synthetic turn is also *recorded* under the mode it really ran in.
    pub(super) fn resolve_turn_prompt_mode(
        &self,
        origin: &crate::session::PromptOrigin,
        declared: PromptMode,
    ) -> PromptMode {
        if !origin.is_synthetic() {
            self.reconcile_plan_mode_with_prompt(declared);
        }
        *self.current_prompt_mode.lock()
    }
    /// Bring the plan-mode tracker into agreement with the prompt's mode.
    ///
    /// Mirrors `handle_session_mode` but driven from `_meta.mode` on the prompt, the only signal the client sends.
    /// Both transitions are idempotent, so `set_mode`-driven flows are unaffected.
    ///
    /// Like `handle_session_mode`, a real transition here emits a `CurrentModeUpdate`.
    /// Without it a client that carries its mode on the prompt could enter or leave plan mode with no signal.
    /// The same line is what lands in `updates.jsonl`, so a later replay could not recover the mode either.
    pub(super) fn reconcile_plan_mode_with_prompt(&self, prompt_mode: PromptMode) {
        use crate::session::plan_mode::PlanModeState;
        *self.current_prompt_mode.lock() = prompt_mode;
        match prompt_mode {
            PromptMode::Plan => {
                let entered = self.plan_mode.lock().enter_pending();
                if entered {
                    self.persist_plan_mode_state();
                    self.enqueue_current_mode_update(session_mode_id_from_prompt_mode(prompt_mode));
                }
            }
            PromptMode::Agent | PromptMode::Ask => {
                let was_plan = {
                    let tracker = self.plan_mode.lock();
                    tracker.state() != PlanModeState::Inactive
                };
                if was_plan {
                    let browser = {
                        let mut tracker = self.plan_mode.lock();
                        tracker.user_exit(false);
                        tracker.browser_use()
                    };
                    self.persist_plan_mode_state();
                    self.enqueue_current_mode_update(plan_exit_mode_id(prompt_mode, browser));
                }
            }
        }
    }
    /// Inject plan mode system-reminders into the conversation.
    ///
    /// Called once per turn from `handle_prompt()`, before the user's actual message is pushed.
    /// Handles three cases, in order:
    ///
    /// 1. **Pending to Active**: the first prompt after the user toggles plan mode on injects the full (or reentry) reminder and moves to Active.
    /// 2. **Already Active**: subsequent prompts while plan mode is on inject an alternating full/sparse per-turn reminder.
    /// 3. **Exit reminder**: a one-shot reminder after plan mode was exited, injected once, then the flag is cleared.
    ///
    /// All reminders are pushed as `<system-reminder>`-wrapped user messages so the model sees them in the same turn as the user's prompt.
    /// Tool names are resolved at render time via `TemplateRenderer`.
    pub(super) async fn inject_plan_mode_reminders(&self) {
        use crate::session::plan_mode::{
            PlanModeState, plan_mode_exit_reminder_template, plan_mode_reminder_full_template,
            plan_mode_reminder_sparse_template,
        };
        let use_cursor_reminders = self.is_cursor_harness();
        let push_reminder = |this: &Self, content: &str| {
            this.push_system_reminder_with_tag(content, this.reminder_wrapper_tag());
        };
        let mut injected_this_turn = false;
        let activation = {
            let tracker = self.plan_mode.lock();
            (tracker.state() == PlanModeState::Pending)
                .then(|| (tracker.is_reentry(), tracker.plan_file_path().to_path_buf()))
        };
        if let Some((is_reentry, plan_path)) = activation {
            self.plan_mode.lock().activate();
            self.persist_plan_mode_state();
            let plan_has_content =
                crate::session::plan_mode::plan_file_has_content(&plan_path).await;
            let template = self.plan_activation_template(is_reentry);
            if let Some(rendered) = self
                .render_plan_template(template, &plan_path, plan_has_content)
                .await
            {
                push_reminder(self, &rendered);
                injected_this_turn = true;
                self.plan_mode.lock().record_reminder_injected();
                self.persist_plan_mode_state();
                tracing::info!(
                    session_id = %self.session_info.id.0,
                    is_reentry,
                    uses_template_reminders = use_cursor_reminders,
                    "Plan mode activated: injected system-reminder"
                );
            }
        }
        if !injected_this_turn {
            let per_turn = {
                let tracker = self.plan_mode.lock();
                tracker.is_active().then(|| {
                    (
                        tracker.should_use_full_reminder(),
                        tracker.plan_file_path().to_path_buf(),
                    )
                })
            };
            if let Some((use_full, plan_path)) = per_turn {
                let plan_has_content =
                    crate::session::plan_mode::plan_file_has_content(&plan_path).await;
                let template = if use_full {
                    plan_mode_reminder_full_template()
                } else {
                    plan_mode_reminder_sparse_template()
                };
                if let Some(rendered) = self
                    .render_plan_template(template, &plan_path, plan_has_content)
                    .await
                {
                    push_reminder(self, &rendered);
                    self.plan_mode.lock().record_reminder_injected();
                    self.persist_plan_mode_state();
                }
            }
        }
        if self.plan_mode.lock().has_pending_exit_reminder() {
            let plan_path = self.plan_mode.lock().plan_file_path().to_path_buf();
            let template = plan_mode_exit_reminder_template();
            if let Some(rendered) = self.render_plan_template(template, &plan_path, false).await {
                push_reminder(self, &rendered);
            }
            self.plan_mode.lock().clear_pending_exit_reminder();
            self.persist_plan_mode_state();
        }
    }
    /// Activate plan mode for a turn that is already running.
    ///
    /// Mid-turn counterpart of `inject_plan_mode_reminders` case 1.
    /// The user toggled plan mode ON (Shift+Tab) while the model was thinking, so the tracker sits in `Pending`.
    /// The running turn would otherwise proceed without any plan-mode instruction.
    /// Activate immediately (so `is_active()` tool gating applies to subsequent calls) and buffer the activation reminder on the tracker.
    /// `flush_pending_skill_reminders` delivers it at the running turn's next safe point (loop top, after each tool batch).
    /// If the turn ends first, the cancel/idle flush lands it for the next turn.
    /// Buffering (instead of a direct conversation push) keeps the in-flight batch's tool_result blocks adjacent.
    /// It also lets a toggle-off withdraw an undelivered reminder (`user_exit`).
    ///
    /// No-op unless the tracker is `Pending`.
    /// `enter_pending`'s `ExitPending` to `Active` re-entry needs no reminder.
    /// The model already has plan-mode context and no exit reminder was injected yet.
    ///
    /// A failed template render still activates (without a buffer), keeping gating in lockstep with the turn-start path.
    pub(super) async fn activate_plan_mode_mid_turn(&self) {
        use crate::session::plan_mode::PlanModeState;
        let activation = {
            let tracker = self.plan_mode.lock();
            (tracker.state() == PlanModeState::Pending)
                .then(|| (tracker.is_reentry(), tracker.plan_file_path().to_path_buf()))
        };
        let Some((is_reentry, plan_path)) = activation else {
            return;
        };
        let plan_has_content = crate::session::plan_mode::plan_file_has_content(&plan_path).await;
        let template = self.plan_activation_template(is_reentry);
        let rendered = self
            .render_plan_template(template, &plan_path, plan_has_content)
            .await;
        let tag = self.reminder_wrapper_tag();
        let buffered = rendered.is_some();
        let activated = match rendered {
            Some(rendered) => self
                .plan_mode
                .lock()
                .activate_mid_turn(format!("<{tag}>\n{rendered}\n</{tag}>")),
            None => {
                tracing::warn!(
                    session_id = %self.session_info.id.0,
                    "Mid-turn plan activation: reminder render failed; \
                     activating without a buffered reminder"
                );
                self.plan_mode.lock().activate()
            }
        };
        if !activated {
            return;
        }
        self.persist_plan_mode_state();
        tracing::info!(
            session_id = %self.session_info.id.0,
            is_reentry,
            buffered,
            "Plan mode activated mid-turn"
        );
    }
    /// The activation reminder template for the active template (no
    /// first-entry/reentry distinction), or fuigo's reentry/full variant.
    /// Shared by turn-start injection (`inject_plan_mode_reminders` case 1)
    /// and the mid-turn toggle (`activate_plan_mode_mid_turn`).
    fn plan_activation_template(&self, is_reentry: bool) -> &'static str {
        use crate::session::plan_mode::{
            plan_mode_reentry_reminder_template, plan_mode_reminder_full_template,
        };
        if is_reentry {
            plan_mode_reentry_reminder_template()
        } else {
            plan_mode_reminder_full_template()
        }
    }
    /// Render a plan mode template via the tool bridge's `TemplateRenderer`.
    ///
    /// Passes `plan_path` and `plan_has_content` as extra context alongside the registry's `tools.by_kind.*` mappings.
    pub(super) async fn render_plan_template(
        &self,
        template: &str,
        plan_path: &std::path::Path,
        plan_has_content: bool,
    ) -> Option<String> {
        let extra = serde_json::json!({
            "plan_path": plan_path.display().to_string(),
            "plan_has_content": plan_has_content,
        });
        self.tool_bridge_handle()
            .render_prompt(template, &extra)
            .await
    }
    /// Persist the current plan mode state to disk.
    ///
    /// Called after every state transition so plan mode survives session reload/resume/reconnect.
    pub(super) fn persist_plan_mode_state(&self) {
        let snapshot = self.plan_mode.lock().snapshot();
        let _ = self
            .notifications
            .persistence_tx
            .send(PersistenceMsg::PlanModeState(snapshot));
    }
}
