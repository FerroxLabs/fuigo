//! Delivers project instructions withheld while a folder was untrusted, once a grant makes them available.
//! The conversation records one fact, that its head was built without project files
//! ([`fuigo_sampling_types::UserItem::project_files_withheld`]), so there is no coverage accounting to drift.
//!
//! A session tracks two separate facts: whether the agent's list is current for the verdict, and whether the
//! conversation's head is complete. The invariants:
//! - `withheld_pending` is true whenever the session's list was built untrusted OR the history holds the bit. A loaded
//!   session with no bit and a false cell is still pending, so a grant refreshes its list and delivery then finds nothing.
//! - `instructions_built_trusted` true means a head rendered now from the list needs no bit. It is set, and pending cleared,
//!   only when no bit remains in the conversation. An empty workspace set with a bit leaves the cell false, pending true and
//!   the bit set, so compaction keeps marking the head and the next start rediscovers. A failed history write puts the list
//!   back, so a head rendered from it still matches the cell.
//! - Opening a session with history follows the same rule, and so does a harness rebuild. A rewind sets pending only: its
//!   list has not changed.
//! - A marked head opened under a denial takes the verdict over the build's snapshot: see [`deliver_at_open`].
//! - A zero-turn rebuild of a withheld head from an empty workspace set re-marks the rewritten head, so the obligation
//!   survives and only delivery discharges it.
//!
//! Rediscovery per turn is the cost for a session that started untrusted. A session trusted from the start pays one
//! `Cell::get`.
use super::*;
use fuigo_agent::prompt::user_message::RuleEntry;

/// What [`deliver_withheld_instructions`] needs from a trusted agent.
pub(super) struct WithheldInstructions {
    /// The agent's full reminder. `None` means it keeps its rules in the prefix.
    pub(super) reminder: Option<String>,
    /// The workspace-scope files of the agent's list.
    pub(super) workspace_rules: Vec<RuleEntry>,
}

/// Put the withheld files where this agent keeps its rules, so the head becomes what a trusted session's head would hold
/// and every later route (compaction, fork, load) behaves as on the trusted path. Clears the bit in the same value, so the
/// caller's one history write commits both or neither.
///
/// Returns false and changes nothing when no item has the bit or no workspace file exists: a failed read or a later file
/// loses nothing. The caller has checked that the folder is trusted. Nothing here reads conversation text.
pub(super) fn deliver_withheld_instructions(
    conversation: &mut Vec<ConversationItem>,
    inherited_prefix_len: Option<usize>,
    instructions: &WithheldInstructions,
) -> bool {
    let Some(holder) = conversation
        .iter()
        .position(ConversationItem::project_files_withheld)
    else {
        return false;
    };
    if instructions.workspace_rules.is_empty() {
        return false;
    }
    if let Some(reminder) = &instructions.reminder {
        // By tag alone: an in-place replace keeps a pin complete, and `inherited_prefix_len` never changes.
        let tagged = conversation.iter_mut().find_map(|item| match item {
            ConversationItem::User(user)
                if user.synthetic_reason == Some(SyntheticReason::ProjectInstructions) =>
            {
                Some(user)
            }
            _ => None,
        });
        if let Some(user) = tagged {
            user.content = vec![ContentPart::Text {
                text: std::sync::Arc::<str>::from(reminder.as_str()),
            }];
        } else {
            let at = inherited_prefix_len
                .unwrap_or(holder + 1)
                .min(conversation.len());
            conversation.insert(at, ConversationItem::project_instructions(reminder.clone()));
        }
    } else if let ConversationItem::User(user) = &mut conversation[holder] {
        // The prefix stays at its index, so pins and `inherited_prefix_len` do not move.
        let mut text = user
            .content
            .iter()
            .find_map(|part| match part {
                ContentPart::Text { text } => Some(text.to_string()),
                _ => None,
            })
            .unwrap_or_default();
        let spans = fuigo_agent::prompt::user_message::append_rules_section(
            &mut text,
            &instructions.workspace_rules,
            &[],
        );
        let marks = fuigo_agent::prompt::user_message::fragment_marks(&text, &spans);
        // An in-place rewrite clears the provenance first; after delivery the appended files are a trusted render.
        user.instruction_provenance = None;
        let replaced = user.content.iter_mut().find_map(|part| match part {
            ContentPart::Text { text } => Some(text),
            _ => None,
        });
        match replaced {
            Some(slot) => *slot = std::sync::Arc::<str>::from(text),
            None => user.content.push(ContentPart::Text {
                text: std::sync::Arc::<str>::from(text),
            }),
        }
        if !marks.is_empty() && matches!(user.content.as_slice(), [ContentPart::Text { .. }]) {
            user.instruction_provenance = Some(
                fuigo_sampling_types::InstructionProvenance::HarnessPrefix(marks),
            );
        }
    }
    clear_withheld_bits(conversation);
    true
}

/// Delivery when a session opens, for a marked head and an agent built trusted: the caller has checked both, so a session
/// with no bit reads no verdict. The list is a snapshot from the build. A folder denied since then loses its workspace
/// files from the list, or a head rendered from it would hold them under the bit; the caller leaves the cell false, so a
/// later grant rediscovers once.
pub(super) fn deliver_at_open(
    agent: &mut fuigo_agent::Agent,
    conversation: &mut Vec<ConversationItem>,
    inherited_prefix_len: Option<usize>,
    compat: &CompatConfig,
    session_info: &SessionInfo,
    display_cwd: Option<&str>,
    cwd: &std::path::Path,
) -> bool {
    let files = agent.prompt_context().agents_md_files.clone();
    let (workspace_rules, user_rules) =
        partition_session_rules(files.clone(), compat, &session_info.cwd, display_cwd);
    if !crate::agent::folder_trust::project_scope_allowed(cwd) {
        agent.set_agents_md_files(
            files
                .into_iter()
                .filter(|file| user_rules.iter().any(|rule| rule.path == file.file_path))
                .collect(),
        );
        let mut prompt_context = agent.prompt_context().clone();
        prompt_context.normalize_for_persistence();
        save_prompt_context(session_info, &prompt_context);
        return false;
    }
    deliver_withheld_instructions(
        conversation,
        inherited_prefix_len,
        &WithheldInstructions { reminder: agent.agents_md_user_reminder(), workspace_rules },
    )
}

/// [`deliver_withheld_instructions`] for a new child that has nothing yet to hold the bit: it has no prefix and its first
/// User item has not landed. A prefix agent has no head to append to, and a trusted new child would have none either.
fn deliver_without_holder(
    conversation: &mut Vec<ConversationItem>,
    inherited_prefix_len: Option<usize>,
    instructions: &WithheldInstructions,
) -> bool {
    let Some(reminder) = &instructions.reminder else {
        return false;
    };
    if instructions.workspace_rules.is_empty() {
        return false;
    }
    let at = inherited_prefix_len.unwrap_or(1).min(conversation.len());
    conversation.insert(at, ConversationItem::project_instructions(reminder.clone()));
    clear_withheld_bits(conversation);
    true
}

fn clear_withheld_bits(conversation: &mut [ConversationItem]) {
    for item in conversation.iter_mut() {
        if let ConversationItem::User(user) = item {
            user.project_files_withheld = false;
        }
    }
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct RediscoveryProbe {
    pub(crate) delay: std::cell::Cell<Option<std::time::Duration>>,
    pub(crate) panic: std::cell::Cell<bool>,
    pub(crate) applied: std::cell::Cell<usize>,
}

#[cfg(test)]
thread_local! {
    pub(crate) static REDISCOVERY_PROBE: RediscoveryProbe = RediscoveryProbe::default();
}

impl SessionActor {
    /// The grant check at a turn start. The caller holds the start reservation and has seen `withheld_pending`, so a trusted
    /// session never reaches this. Everything here is best-effort: nothing fails the turn.
    pub(super) async fn apply_folder_trust_grant(&self) {
        let cwd = std::path::Path::new(&self.session_info.cwd);
        if self.trust_reply_wait_armed.replace(false) {
            crate::agent::folder_trust::wait_for_trust_reply(
                cwd,
                crate::agent::folder_trust::TRUST_REPLY_WAIT,
            )
            .await;
        }
        if !crate::agent::folder_trust::project_scope_allowed(cwd) {
            return;
        }
        self.ensure_prefix_ready().await;
        let previous_files = self.agent.borrow().prompt_context().agents_md_files.clone();
        let files = self.rediscover_agents_md_files().await;
        self.agent.borrow_mut().set_agents_md_files(files);
        #[cfg(test)]
        REDISCOVERY_PROBE.with(|probe| probe.applied.set(probe.applied.get() + 1));

        let mut conversation = self.chat_state_handle.get_conversation().await;
        let instructions = self.withheld_instructions();
        let inherited_prefix_len = self.startup_hints.inherited_prefix_len;
        let holder_owed = self.head_holder_owed.get();
        let delivered = if holder_owed {
            deliver_without_holder(&mut conversation, inherited_prefix_len, &instructions)
        } else {
            deliver_withheld_instructions(&mut conversation, inherited_prefix_len, &instructions)
        };
        let still_withheld = (!delivered && holder_owed)
            || conversation.iter().any(ConversationItem::project_files_withheld);
        if delivered
            && let Err(error) = self
                .chat_state_handle
                .replace_conversation_persisted(conversation)
                .await
        {
            // The conversation is unchanged, so the bit stands: the next start or load delivers.
            tracing::warn!(session_id = %self.session_info.id.0, %error, "folder trust: delivery not stored");
            self.agent.borrow_mut().set_agents_md_files(previous_files);
            return;
        }
        if delivered {
            self.head_holder_owed.set(false);
        }
        self.instructions_built_trusted.set(!still_withheld);
        self.withheld_pending.set(still_withheld);
        self.refresh_classifier_project_instructions();
        let mut prompt_context = self.agent.borrow().prompt_context().clone();
        prompt_context.normalize_for_persistence();
        save_prompt_context(&self.session_info, &prompt_context);
    }

    /// The agent's current list, split for delivery.
    pub(super) fn withheld_instructions(&self) -> WithheldInstructions {
        let (workspace_rules, _user_rules) = self.gather_partitioned_rules();
        WithheldInstructions {
            reminder: self.agent.borrow().agents_md_user_reminder(),
            workspace_rules,
        }
    }

    async fn rediscover_agents_md_files(&self) -> Vec<fuigo_agent::prompt::agents_md::AgentConfigFile> {
        #[cfg(test)]
        {
            let (delay, panic) =
                REDISCOVERY_PROBE.with(|probe| (probe.delay.get(), probe.panic.get()));
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            assert!(!panic, "rediscovery panic requested by the test");
        }
        let cwd = &self.session_info.cwd;
        let mut files = fuigo_agent::prompt::agents_md::read_agents_config_with_paths(
            cwd,
            self.rebuild_spec.compat,
            true,
        )
        .await;
        if let Some(display_cwd) = self.display_cwd.get() {
            fuigo_agent::prompt::agents_md::rewrite_display_paths(&mut files, cwd, display_cwd);
        }
        files
    }

    /// As at spawn: the classifier's copy belongs to the session that owns the manager.
    fn refresh_classifier_project_instructions(&self) {
        let section = self.agent.borrow().agents_md_section();
        if let Some(section) = section
            && should_set_classifier_project_instructions(
                self.owns_permission_manager,
                Some(section.as_str()),
            )
        {
            let body = agents_md_classifier_body(&section);
            if !body.is_empty() {
                self.permissions.set_project_instructions(Some(body));
            }
        }
    }
}

/// Holds the start reservation of `maybe_start_running_task` across its await gap. Dropped on every exit, unwinding included.
pub(super) struct StartReservation(std::rc::Rc<std::cell::Cell<bool>>);

impl StartReservation {
    pub(super) fn take(slot: &std::rc::Rc<std::cell::Cell<bool>>) -> Self {
        slot.set(true);
        Self(slot.clone())
    }
}

impl Drop for StartReservation {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

#[cfg(test)]
#[path = "../acp_session_tests/withheld_instructions_tests.rs"]
mod tests;
