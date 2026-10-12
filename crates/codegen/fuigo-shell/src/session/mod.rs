pub mod acp_types;
pub mod announcement_state;
pub mod commands;
pub mod cron_fire_tickets;
pub(crate) mod compaction_config;
pub(crate) mod doom_loop_telemetry;
pub mod handle;
pub(crate) mod memory_state;
pub mod merge;
pub(crate) mod message_delivery;
pub(crate) mod peer_message;
pub mod peer_admission;
pub(crate) mod peer_watch;
pub(crate) mod peer_audit;
pub(crate) mod peer_integrity;
pub mod notifications;
pub mod pending_interaction;
pub mod prompt_queue;
pub(crate) mod quiesce;
pub mod two_pass;
pub mod user_echo;
pub mod visibility;
pub use self::acp_session::*;
pub use self::acp_types::*;
pub use self::commands::*;
pub use self::fork::{ForkSessionRequest, ForkSessionResponse, fork_session};
pub use self::handle::*;
pub use self::persistence::{
    LocalFeedbackEntry, UserFeedbackEntry, find_local_child_for_remote, resolve_local_session,
    resolve_local_session_any_cwd, resolve_local_session_ids_any_cwd, session_exists_for_cwd,
};
pub use self::result::{Empty, ExtMethodResult};
pub use self::share::{ShareSessionRequest, ShareSessionResponse};
pub use self::user_echo::{CLIENT_USER_MESSAGE_ECHO_META, USER_MESSAGE_ECHO_CAPABILITY};
pub use fuigo_fsnotify::{
    FsConfig, FsEvent, FsEventKind, FsEventSource, FsNotifyError, GitMetaKind,
};
pub use prod_mc_cli_chat_proxy_types::feedback_types::{
    ClientType, FeedbackImage, FeedbackTerminalInfo, MAX_FEEDBACK_IMAGE_BYTES,
    MAX_FEEDBACK_IMAGE_TOTAL_BYTES, MAX_FEEDBACK_IMAGES, RatingType, feedback_image_extension,
    validate_feedback_images,
};
/// `false` twin: this template is not compiled into this build, so no template matches.
/// Keeps ungated call sites compiling in both configurations.
pub(crate) fn is_cursor_user_template(
    _template: &fuigo_agent::prompt::user_message::UserMessageTemplate,
) -> bool {
    false
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CompactionPins {
    pub mode: fuigo_chat_state::CompactionMode,
    pub two_pass: bool,
}
pub(crate) fn cursor_compaction_pins(
    resolved_mode: fuigo_chat_state::CompactionMode,
    resolved_two_pass: bool,
    is_cursor: bool,
) -> CompactionPins {
    if is_cursor {
        CompactionPins {
            mode: fuigo_chat_state::CompactionMode::Summary,
            two_pass: false,
        }
    } else {
        CompactionPins {
            mode: resolved_mode,
            two_pass: resolved_two_pass,
        }
    }
}
/// `false` twin of [`is_cursor_system_template`]; see [`is_cursor_user_template`].
pub(crate) fn is_cursor_system_template(
    _template: &fuigo_agent::prompt::context::TemplateOverride,
) -> bool {
    false
}
/// The single spelling of "only Image blocks are carried structurally" (interject parse and queue-interject harvest).
pub(crate) fn image_blocks(
    blocks: impl IntoIterator<Item = agent_client_protocol::ContentBlock>,
) -> Vec<agent_client_protocol::ImageContent> {
    blocks
        .into_iter()
        .filter_map(|block| match block {
            agent_client_protocol::ContentBlock::Image(img) => Some(img),
            _ => None,
        })
        .collect()
}
pub use fuigo_agent_lifecycle::{
    AnalyticsClass, CompactionClass, InputAuthority, InputPolicy, QueuePolicy, ShutdownPolicy,
    TurnBoundary,
};
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptOrigin {
    User,
    /// Auto-wake prompt injected when a background terminal task completed.
    TaskCompleted {
        /// The background task ID (without the `task-completed-` prefix).
        task_id: String,
    },
    /// Auto-wake prompt injected when a background subagent completed.
    SubagentCompleted {
        /// The subagent ID (without the `subagent-completed-` prefix).
        subagent_id: String,
    },
    /// Model-authored context sent by the owning root session.
    ParentAgentMessage {
        message_id: String,
        sender_session_id: String,
    },
    /// Untrusted text from another session (peer messaging). Never human intent: see `InputAuthority::PeerUntrusted`.
    PeerMessage {
        message_id: String,
        /// The sender's address (`fuigo-peer:...`); empty when rebuilt from a prompt id alone.
        from: String,
    },
    WorkflowCompleted {
        completion_id: String,
    },
    /// Packet 11 (S9.4): a delivery notice about a message THIS session sent, written by Fuigo (fixed text from a typed kind
    /// and the target's address). Runtime control, never peer text; the turn it starts counts against the peer-turn budget and
    /// inherits the peer chain. `message_id` is the one this session sent.
    PeerNotice {
        message_id: String,
    },
    /// Server-initiated prompt from the idle-gated notification drain (`maybe_drain_notifications`).
    /// Batches one or more monitor-event or bash-task-completed notifications into a single turn while the user is idle.
    NotificationDrain,
    /// The goal orchestrator injects a system reminder into context and then triggers a model turn so the model can print a visible progress update.
    GoalSummary,
    /// Nudge injected when the verification stage rejects an `update_goal(completed: true)` attempt.
    /// Carries the "not yet achieved — keep working" system-reminder body alongside the path to the persisted details file.
    /// The variant name retains the `Classifier` prefix for wire stability.
    GoalClassifierNudge,
    /// Scheduled task (`/loop`) prompt fired by the scheduler via the pager.
    SchedulerFired,
    /// The shell re-parked `exit_plan_mode` on resume, the user approved/revised, and the shell injects the follow-up turn.
    /// Synthetic: the user never typed it, so it stays out of prompt history, but it still runs a real turn.
    PlanResume,
    /// The initial task prompt of a subagent, written by the parent MODEL. Runs as an ordinary conversational turn for the
    /// child (not synthetic, same queue/compaction treatment as a user prompt) but carries model-authored authority:
    /// no builtin slash command beyond what `ModelAuthoredUntrusted` allows and no `!` shell line.
    SubagentTask,
    /// A client prompt whose id carries the `scheduler-fired-` prefix but did NOT redeem a ticket (unknown, reused,
    /// expired, wrong text or meta, an older pager that sends no ticket, or a human-edited queued scheduled row). Its text
    /// is whatever the model wrote into the schedule (or an edit of it), so it has model-authored authority: no builtin
    /// slash command beyond what `ModelAuthoredUntrusted` allows, no `!` line, no `@file` expansion. Unlike a subagent
    /// task it still goes through the `UserPromptSubmit` gate with a Block enforced. Never derivable from an id by
    /// `from_prompt_id`; only `cron_fire_tickets::client_prompt_origin` produces it.
    UnverifiedScheduled,
}
impl PromptOrigin {
    /// The origin of a prompt whose id arrived from OUTSIDE the shell (an ACP `session/prompt` `meta.promptId`, or any
    /// legacy caller that only has an id). A client-chosen id never carries authority, whatever it says, so this is
    /// always [`Self::User`]. The one verified exception is a cron fire that presents a ticket the shell issued
    /// (`session::cron_fire_tickets`), resolved by the ACP boundary before it builds the command. Internal senders pass
    /// their origin explicitly on `SessionCommand::Prompt::origin`. `PeerMessage` is constructed only by the admission
    /// path (`submit_peer_message` and the release drain) and the stranded-entry rebuild, never from an id.
    pub fn from_client_prompt_id(_prompt_id: &str) -> Self {
        Self::User
    }

    /// Display-level classification of a prompt id (pager rendering, scrollback). NOT an authority decision: never use it to
    /// decide how an incoming prompt is treated; use [`Self::from_client_prompt_id`] or the stored origin.
    /// Whether a `UserPromptSubmit` Block is enforced for this origin (on a top-level session): a typed prompt, and an
    /// unverified scheduled prompt (which has the stricter of both worlds). Every other origin is observe-only.
    pub fn enforces_prompt_block(&self) -> bool {
        match self {
            Self::User | Self::UnverifiedScheduled => true,
            Self::TaskCompleted { .. }
            | Self::SubagentCompleted { .. }
            | Self::ParentAgentMessage { .. }
            | Self::PeerMessage { .. }
            | Self::WorkflowCompleted { .. }
            | Self::PeerNotice { .. }
            | Self::NotificationDrain
            | Self::GoalSummary
            | Self::GoalClassifierNudge
            | Self::SchedulerFired
            | Self::PlanResume
            | Self::SubagentTask => false,
        }
    }

    /// The `origin` tag a `UserPromptSubmit` hook payload carries. `None` ONLY for a prompt the human typed
    /// ([`Self::User`]), whose payload bytes stay unchanged; every other origin has a stable snake_case tag.
    /// Exhaustive on purpose: a new origin cannot be added without choosing its tag.
    pub fn hook_origin_tag(&self) -> Option<&'static str> {
        match self {
            Self::User => None,
            Self::TaskCompleted { .. } => Some("task_completed"),
            Self::SubagentCompleted { .. } => Some("subagent_completed"),
            Self::ParentAgentMessage { .. } => Some("parent_agent_message"),
            Self::PeerMessage { .. } => Some("peer_message"),
            Self::WorkflowCompleted { .. } => Some("workflow_completed"),
            Self::PeerNotice { .. } => Some("peer_notice"),
            Self::NotificationDrain => Some("notification"),
            Self::GoalSummary => Some("goal_summary"),
            Self::GoalClassifierNudge => Some("goal_classifier_nudge"),
            Self::SchedulerFired => Some("scheduled"),
            Self::PlanResume => Some("plan_resume"),
            Self::SubagentTask => Some("subagent_task"),
            Self::UnverifiedScheduled => Some("unverified_scheduled"),
        }
    }

    /// Whether a queued row of this origin may be merged into a RUNNING turn as an interjection (queue promotion, goal
    /// send-now merge). An unverified scheduled prompt must always run as its own turn so `UserPromptSubmit` is
    /// enforced (an interjection never enters that hook, and a stranded one is re-queued as a parent message that
    /// skips it). A subagent task is the child's first row, so no turn is running when it arrives; excluded as well.
    pub fn may_ride_as_interjection(&self) -> bool {
        !matches!(self, Self::UnverifiedScheduled | Self::SubagentTask)
    }

    pub fn from_prompt_id(prompt_id: &str) -> Self {
        if let Some(task_id) = prompt_id.strip_prefix("task-completed-") {
            Self::TaskCompleted {
                task_id: task_id.to_string(),
            }
        } else if let Some(subagent_id) = prompt_id.strip_prefix("subagent-completed-") {
            Self::SubagentCompleted {
                subagent_id: subagent_id.to_string(),
            }
        } else if let Some(parent_message_id) = prompt_id.strip_prefix("parent-message-") {
            Self::ParentAgentMessage {
                message_id: parent_message_id.to_string(),
                sender_session_id: String::new(),
            }
        } else if let Some(peer_message_id) = prompt_id.strip_prefix("peer-message-") {
            Self::PeerMessage {
                message_id: peer_message_id.to_string(),
                from: String::new(),
            }
        } else if let Some(completion_id) = prompt_id.strip_prefix("workflow-completed-") {
            Self::WorkflowCompleted {
                completion_id: completion_id.to_string(),
            }
        } else if let Some(notice_id) = prompt_id.strip_prefix("peer-notice-") {
            Self::PeerNotice {
                message_id: notice_id.to_string(),
            }
        } else if prompt_id.starts_with("notifications-") {
            Self::NotificationDrain
        } else if prompt_id.starts_with("goal-summary-") {
            Self::GoalSummary
        } else if prompt_id.starts_with("goal-classifier-nudge-") {
            Self::GoalClassifierNudge
        } else if prompt_id.starts_with("scheduler-fired-") {
            Self::SchedulerFired
        } else if prompt_id.starts_with("plan-resume-") {
            Self::PlanResume
        } else {
            Self::User
        }
    }
    pub fn policy(&self) -> InputPolicy {
        match self {
            Self::User => InputPolicy {
                authority: InputAuthority::HumanIntent,
                turn_boundary: TurnBoundary::Conversational,
                analytics: AnalyticsClass::HumanPrompt,
                compaction: CompactionClass::HumanAnchor,
                queue: QueuePolicy::VisibleEditable,
                shutdown: ShutdownPolicy::Drain,
            },
            Self::ParentAgentMessage { .. } => InputPolicy {
                authority: InputAuthority::ModelAuthoredUntrusted,
                turn_boundary: TurnBoundary::Conversational,
                analytics: AnalyticsClass::AgentMessage,
                compaction: CompactionClass::ConversationalAgentAnchor,
                queue: QueuePolicy::VisibleProtected,
                shutdown: ShutdownPolicy::Drain,
            },
            // Turn mechanics stay those of a user prompt (queue, compaction anchor, drain); only authority and the
            // human-prompt analytics class are model-authored.
            Self::SubagentTask | Self::UnverifiedScheduled => InputPolicy {
                authority: InputAuthority::ModelAuthoredUntrusted,
                turn_boundary: TurnBoundary::Conversational,
                analytics: AnalyticsClass::AgentMessage,
                compaction: CompactionClass::HumanAnchor,
                queue: QueuePolicy::VisibleEditable,
                shutdown: ShutdownPolicy::Drain,
            },
            Self::PeerMessage { .. } => InputPolicy {
                authority: InputAuthority::PeerUntrusted,
                turn_boundary: TurnBoundary::Conversational,
                analytics: AnalyticsClass::PeerMessage,
                compaction: CompactionClass::ConversationalPeerAnchor,
                queue: QueuePolicy::VisibleProtected,
                shutdown: ShutdownPolicy::Drain,
            },
            Self::TaskCompleted { .. }
            | Self::SubagentCompleted { .. }
            | Self::WorkflowCompleted { .. }
            | Self::PeerNotice { .. }
            | Self::SchedulerFired => InputPolicy {
                authority: InputAuthority::RuntimeControl,
                turn_boundary: TurnBoundary::Conversational,
                analytics: AnalyticsClass::RuntimeWake,
                compaction: CompactionClass::RuntimeEphemera,
                queue: QueuePolicy::Hidden,
                shutdown: ShutdownPolicy::CancelWithProducer,
            },
            Self::NotificationDrain
            | Self::GoalSummary
            | Self::GoalClassifierNudge
            | Self::PlanResume => InputPolicy {
                authority: InputAuthority::RuntimeControl,
                turn_boundary: TurnBoundary::Conversational,
                analytics: AnalyticsClass::RuntimeWake,
                compaction: CompactionClass::RuntimeEphemera,
                queue: QueuePolicy::Hidden,
                shutdown: ShutdownPolicy::DropEphemeral,
            },
        }
    }
    /// Returns `true` for auto-wake (synthetic) prompts.
    pub fn is_synthetic(&self) -> bool {
        !matches!(
            self,
            Self::User | Self::SubagentTask | Self::UnverifiedScheduled
        )
    }
    /// Whether a `UserMessageChunk` echo for this origin must stay out of client scrollback (live and on resume).
    /// The hidden origins carry model-only, side-channel content the UI already shows elsewhere (task pane, monitor gutter, etc.).
    pub fn hide_user_echo_from_scrollback(&self) -> bool {
        match self {
            Self::User
            | Self::ParentAgentMessage { .. }
            | Self::PeerMessage { .. }
            | Self::SchedulerFired
            | Self::SubagentTask
            | Self::UnverifiedScheduled
            | Self::PlanResume => false,
            Self::TaskCompleted { .. }
            | Self::SubagentCompleted { .. }
            | Self::WorkflowCompleted { .. }
            | Self::PeerNotice { .. }
            | Self::NotificationDrain
            | Self::GoalSummary
            | Self::GoalClassifierNudge => true,
        }
    }
    /// Whether this input came from another session. A peer turn is never counted as the user re-engaging.
    pub fn is_peer(&self) -> bool {
        matches!(self, Self::PeerMessage { .. })
    }
    /// Whether this input is the user re-engaging: not a synthetic wake and not the parent model's subagent task text.
    /// Gates the "clear post-cancel suppression / bump user-input generation" bookkeeping.
    pub fn is_user_reengagement(&self) -> bool {
        !self.is_synthetic() && !matches!(self, Self::SubagentTask | Self::UnverifiedScheduled)
    }

    pub fn completion_id(&self) -> Option<&str> {
        match self {
            Self::TaskCompleted { task_id } => Some(task_id),
            Self::SubagentCompleted { subagent_id } => Some(subagent_id),
            Self::WorkflowCompleted { completion_id } => Some(completion_id),
            Self::User
            | Self::ParentAgentMessage { .. }
            | Self::PeerMessage { .. }
            | Self::PeerNotice { .. }
            | Self::NotificationDrain
            | Self::GoalSummary
            | Self::GoalClassifierNudge
            | Self::SchedulerFired
            | Self::SubagentTask
            | Self::UnverifiedScheduled
            | Self::PlanResume => None,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::{InputAuthority, PromptOrigin, QueuePolicy};
    #[test]
    fn hook_origin_tag_is_none_only_for_a_typed_prompt() {
        let all = [
            PromptOrigin::User,
            PromptOrigin::TaskCompleted { task_id: String::new() },
            PromptOrigin::SubagentCompleted { subagent_id: String::new() },
            PromptOrigin::ParentAgentMessage { message_id: String::new(), sender_session_id: String::new() },
            PromptOrigin::PeerMessage { message_id: String::new(), from: String::new() },
            PromptOrigin::WorkflowCompleted { completion_id: String::new() },
            PromptOrigin::PeerNotice { message_id: String::new() },
            PromptOrigin::NotificationDrain,
            PromptOrigin::GoalSummary,
            PromptOrigin::GoalClassifierNudge,
            PromptOrigin::SchedulerFired,
            PromptOrigin::PlanResume,
            PromptOrigin::SubagentTask,
            PromptOrigin::UnverifiedScheduled,
        ];
        let mut seen = std::collections::HashSet::new();
        for origin in &all {
            match origin.hook_origin_tag() {
                None => assert_eq!(origin, &PromptOrigin::User),
                Some(tag) => {
                    assert!(seen.insert(tag), "duplicate tag {tag}");
                    assert!(tag.chars().all(|c| c.is_ascii_lowercase() || c == '_'), "{tag}");
                }
            }
        }
        assert_eq!(seen.len(), all.len() - 1);
        assert_eq!(PromptOrigin::SchedulerFired.hook_origin_tag(), Some("scheduled"));
        assert_eq!(
            PromptOrigin::PeerMessage { message_id: String::new(), from: String::new() }.hook_origin_tag(),
            Some("peer_message")
        );
    }
    #[test]
    fn from_prompt_id_user() {
        assert_eq!(
            PromptOrigin::from_prompt_id("my-prompt"),
            PromptOrigin::User
        );
        assert!(!PromptOrigin::from_prompt_id("my-prompt").is_synthetic());
    }
    #[test]
    fn from_prompt_id_task_completed() {
        let origin = PromptOrigin::from_prompt_id("task-completed-abc-123");
        assert_eq!(
            origin,
            PromptOrigin::TaskCompleted {
                task_id: "abc-123".into()
            }
        );
        assert!(origin.is_synthetic());
        assert_eq!(origin.completion_id(), Some("abc-123"));
    }
    #[test]
    fn from_prompt_id_parent_message() {
        let origin = PromptOrigin::from_prompt_id("parent-message-msg-123");
        assert_eq!(
            origin,
            PromptOrigin::ParentAgentMessage {
                message_id: "msg-123".into(),
                sender_session_id: String::new(),
            }
        );
        assert!(origin.is_synthetic());
    }
    /// A client-supplied id never carries authority: every reserved prefix is an ordinary user prompt, so the
    /// `UserPromptSubmit` hook runs and a Block is enforced (`should_enforce_prompt_block` needs human intent).
    #[test]
    fn client_prompt_id_is_always_a_user_prompt() {
        for prefix in [
            "task-completed-",
            "subagent-completed-",
            "parent-message-",
            "peer-message-",
            "workflow-completed-",
            "notifications-",
            "goal-summary-",
            "goal-classifier-nudge-",
            "scheduler-fired-",
            "plan-resume-",
        ] {
            for id in [format!("{prefix}x-1"), prefix.to_string()] {
                let origin = PromptOrigin::from_client_prompt_id(&id);
                assert_eq!(origin, PromptOrigin::User, "{id}");
                assert!(!origin.is_synthetic(), "{id}");
                assert!(!origin.is_peer(), "{id}");
                assert!(origin.policy().authority.is_human_intent(), "{id}");
            }
        }
        assert_eq!(PromptOrigin::from_client_prompt_id("my-prompt"), PromptOrigin::User);
    }

    #[test]
    fn from_prompt_id_peer_message() {
        let origin = PromptOrigin::from_prompt_id("peer-message-m-1");
        assert_eq!(
            origin,
            PromptOrigin::PeerMessage {
                message_id: "m-1".into(),
                from: String::new(),
            }
        );
        assert!(origin.is_synthetic());
        assert!(origin.is_peer());
        assert_eq!(origin.completion_id(), None);
    }
    #[test]
    fn from_prompt_id_subagent_completed() {
        let origin = PromptOrigin::from_prompt_id("subagent-completed-xyz-789");
        assert_eq!(
            origin,
            PromptOrigin::SubagentCompleted {
                subagent_id: "xyz-789".into()
            }
        );
        assert!(origin.is_synthetic());
        assert_eq!(origin.completion_id(), Some("xyz-789"));
    }
    #[test]
    fn from_prompt_id_notification_drain() {
        let origin =
            PromptOrigin::from_prompt_id("notifications-019e0000-0000-7000-8000-0000000000aa");
        assert_eq!(origin, PromptOrigin::NotificationDrain);
        assert!(origin.is_synthetic());
        assert_eq!(origin.completion_id(), None);
    }
    #[test]
    fn goal_summary_origin_from_prompt_id() {
        let origin = PromptOrigin::from_prompt_id("goal-summary-019e2d3e");
        assert!(matches!(origin, PromptOrigin::GoalSummary));
        assert!(origin.is_synthetic());
        assert_eq!(origin.completion_id(), None);
    }
    #[test]
    fn goal_classifier_nudge_origin_from_prompt_id() {
        let origin = PromptOrigin::from_prompt_id("goal-classifier-nudge-019e2d3e");
        assert!(matches!(origin, PromptOrigin::GoalClassifierNudge));
        assert!(origin.is_synthetic());
        assert_eq!(origin.completion_id(), None);
    }
    #[test]
    fn goal_classifier_nudge_origin_round_trips_through_from_prompt_id() {
        let prompt_id = format!("goal-classifier-nudge-{}", uuid::Uuid::now_v7());
        let origin = PromptOrigin::from_prompt_id(&prompt_id);
        assert!(matches!(origin, PromptOrigin::GoalClassifierNudge));
        assert!(origin.is_synthetic());
    }
    #[test]
    fn scheduler_fired_origin_from_prompt_id() {
        let origin = PromptOrigin::from_prompt_id("scheduler-fired-019e51a3-abcd-1234");
        assert!(matches!(origin, PromptOrigin::SchedulerFired));
        assert!(origin.is_synthetic());
        assert_eq!(origin.completion_id(), None);
    }
    #[test]
    fn plan_resume_origin_from_prompt_id() {
        let origin = PromptOrigin::from_prompt_id("plan-resume-1730000000000");
        assert!(matches!(origin, PromptOrigin::PlanResume));
        assert!(origin.is_synthetic());
        assert_eq!(origin.completion_id(), None);
    }
    #[test]
    fn notification_drain_is_server_initiated() {
        let prompt_id = "notifications-019e0000-0000-7000-8000-0000000000aa";
        assert!(PromptOrigin::from_prompt_id(prompt_id).is_synthetic());
    }
    /// The subagent task is model-authored for authority, but plain turn mechanics (not synthetic, user-like queue and
    /// scrollback treatment) stay those of a user prompt.
    #[test]
    fn subagent_task_is_model_authored_with_user_turn_mechanics() {
        let origin = PromptOrigin::SubagentTask;
        let policy = origin.policy();
        assert_eq!(policy.authority, InputAuthority::ModelAuthoredUntrusted);
        assert!(!policy.authority.is_human_intent());
        assert!(!policy.analytics.is_human_prompt());
        assert_eq!(policy.queue, QueuePolicy::VisibleEditable);
        assert!(!origin.is_synthetic());
        assert!(!origin.is_peer());
        assert!(!origin.is_user_reengagement());
        assert!(PromptOrigin::User.is_user_reengagement());
        assert!(!origin.hide_user_echo_from_scrollback());
        assert_eq!(origin.completion_id(), None);
        // Never derived from an id: a client cannot claim it.
        assert_eq!(PromptOrigin::from_client_prompt_id("subagent-task-x"), PromptOrigin::User);
    }
    /// An unverified scheduled prompt is model-authored for authority but keeps user turn mechanics and an ENFORCED prompt hook.
    #[test]
    fn unverified_scheduled_is_model_authored_with_an_enforced_prompt_hook() {
        let origin = PromptOrigin::UnverifiedScheduled;
        let policy = origin.policy();
        assert_eq!(policy.authority, InputAuthority::ModelAuthoredUntrusted);
        assert!(!policy.authority.is_human_intent());
        assert!(!origin.is_synthetic());
        assert!(!origin.is_user_reengagement());
        assert!(origin.enforces_prompt_block());
        assert!(PromptOrigin::User.enforces_prompt_block());
        assert!(!PromptOrigin::SchedulerFired.enforces_prompt_block());
        assert!(!PromptOrigin::SubagentTask.enforces_prompt_block());
        assert_eq!(PromptOrigin::from_prompt_id("scheduler-fired-x"), PromptOrigin::SchedulerFired);
    }
    #[test]
    fn current_origin_queue_policies_are_preserved() {
        let cases = [
            (PromptOrigin::User, QueuePolicy::VisibleEditable),
            (
                PromptOrigin::TaskCompleted {
                    task_id: "t".into(),
                },
                QueuePolicy::Hidden,
            ),
            (
                PromptOrigin::SubagentCompleted {
                    subagent_id: "s".into(),
                },
                QueuePolicy::Hidden,
            ),
            (
                PromptOrigin::ParentAgentMessage {
                    message_id: "m".into(),
                    sender_session_id: "root".into(),
                },
                QueuePolicy::VisibleProtected,
            ),
            (
                PromptOrigin::WorkflowCompleted {
                    completion_id: "w".into(),
                },
                QueuePolicy::Hidden,
            ),
            (
                PromptOrigin::PeerMessage {
                    message_id: "m".into(),
                    from: "fuigo-peer:x".into(),
                },
                QueuePolicy::VisibleProtected,
            ),
            (PromptOrigin::NotificationDrain, QueuePolicy::Hidden),
            (PromptOrigin::GoalSummary, QueuePolicy::Hidden),
            (PromptOrigin::GoalClassifierNudge, QueuePolicy::Hidden),
            (PromptOrigin::SchedulerFired, QueuePolicy::Hidden),
            (PromptOrigin::PlanResume, QueuePolicy::Hidden),
            (PromptOrigin::UnverifiedScheduled, QueuePolicy::VisibleEditable),
        ];
        for (origin, queue) in cases {
            assert_eq!(origin.policy().queue, queue, "{origin:?}");
        }
    }
    #[test]
    fn hide_user_echo_from_scrollback_by_origin() {
        assert!(!PromptOrigin::User.hide_user_echo_from_scrollback());
        assert!(
            !PromptOrigin::ParentAgentMessage {
                message_id: "m".into(),
                sender_session_id: "root".into(),
            }
            .hide_user_echo_from_scrollback()
        );
        assert!(
            !PromptOrigin::from_prompt_id("scheduler-fired-abc").hide_user_echo_from_scrollback()
        );
        assert!(!PromptOrigin::from_prompt_id("plan-resume-1").hide_user_echo_from_scrollback());
        assert!(PromptOrigin::from_prompt_id("task-completed-t1").hide_user_echo_from_scrollback());
        assert!(
            PromptOrigin::from_prompt_id("subagent-completed-s1").hide_user_echo_from_scrollback()
        );
        assert!(
            PromptOrigin::from_prompt_id("notifications-uuid").hide_user_echo_from_scrollback()
        );
        assert!(
            PromptOrigin::from_prompt_id("workflow-completed-wf-1-9")
                .hide_user_echo_from_scrollback()
        );
        assert!(PromptOrigin::from_prompt_id("goal-summary-1").hide_user_echo_from_scrollback());
        assert!(
            PromptOrigin::from_prompt_id("goal-classifier-nudge-1")
                .hide_user_echo_from_scrollback()
        );
    }
}
/// Determines whether the session sends an initial file index to the client or just streams raw file events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub(crate) enum ClientFsMode {
    #[default]
    Events,
    Index,
}
#[derive(Debug, Clone, Default)]
pub(crate) struct ClientFsConfig {
    pub fs: FsConfig,
    pub mode: ClientFsMode,
}
pub mod share {
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct ShareSessionRequest {
        pub session_id: String,
    }
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct ShareSessionResponse {
        pub share_url: String,
    }
}
/// Proxy config for the session registry client.
/// Shared between `acp_session` (slash commands) and `persistence` (title generation).
#[derive(Clone)]
pub(crate) struct RegistryConfig {
    pub base_url: String,
    pub user_token: String,
    pub deployment_key: Option<String>,
    pub alpha_test_key: Option<String>,
}
pub mod acp_conversion;
pub(crate) mod acp_mcp;
pub(crate) mod reverse_ticket;
pub(crate) mod acp_session;
pub(crate) mod agent_rebuild;
pub(crate) mod chat_persistence;
pub(crate) mod events;
pub mod export;
pub mod feedback;
pub mod feedback_manager;
pub mod file_system;
pub mod fork;
pub(crate) mod fs_watch;
pub(crate) mod goal_classifier;
pub(crate) mod goal_evaluator;
pub(crate) mod goal_next_step;
pub(crate) mod goal_orchestrator;
pub(crate) mod goal_planner;
pub(crate) mod goal_role_tools;
pub(crate) mod goal_stop_detector;
pub(crate) mod goal_strategist;
pub(crate) mod goal_summarizer;
pub mod goal_tracker;
pub mod helpers;
pub(crate) mod image_describe;
pub(crate) mod model_facing_reads;
pub(crate) mod image_normalize;
pub(crate) mod inference_metrics;
pub use fuigo_shared::session::info;
pub mod interrupted_turn;
pub(crate) mod turn_owner_lock;
pub mod admin_policy_watch;
pub mod managed_mcp;
pub(crate) mod mcp_descriptors;
pub(crate) mod mcp_dispatcher;
#[cfg(test)]
mod mcp_dispatcher_e2e_tests;
pub(crate) mod mcp_elicitation;
pub(crate) mod mcp_restart;
pub mod mcp_servers;
pub mod memory;
pub(crate) mod memory_observation;
pub(crate) mod normalize_cache;
pub mod persistence;
pub mod execution_state;
pub(crate) mod read_dedupe;
pub(crate) mod tool_presentation;
#[cfg(test)]
mod compact_tool_catalog_tests;
pub use fuigo_shared::placeholder_images;
pub mod plan_mode;
pub mod prompt_history;
pub mod prompt_parser;
pub(crate) mod prompt_timing;
pub(crate) mod replay_events;
pub mod repo_changes;
#[path = "restore_stub.rs"]
pub mod restore;
pub(crate) mod resume_status;
pub mod result;
pub mod signals;
pub(crate) mod slash_authority;
pub(crate) mod slash_commands;
pub mod usage_file;
pub use slash_commands::PAGER_COMMAND_KEYS;
pub(crate) mod repo_status_prefix;
pub mod storage;
pub(crate) mod streaming_capture;
pub(crate) mod summary;
pub(crate) mod unaccepted_output;
pub(crate) mod telemetry;
#[cfg(feature = "test-support")]
pub mod testkit;
pub mod tool_index;
pub(crate) mod turn_completion;
pub mod unified_list;
pub(crate) mod user_message;
pub(crate) mod wire_tags;
pub(crate) mod workflow;
pub mod worktree;
pub(crate) mod worktree_cleanup;
pub mod worktree_pool;
