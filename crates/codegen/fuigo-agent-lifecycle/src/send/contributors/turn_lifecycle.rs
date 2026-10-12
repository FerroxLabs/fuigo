use async_trait::async_trait;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputAuthority {
    HumanIntent,
    ModelAuthoredUntrusted,
    RuntimeControl,
    /// Text from another session (peer messaging). Stricter than `ModelAuthoredUntrusted`: no slash command of any kind, no
    /// file expansion, no hook gate, never human intent. Data, not instructions.
    PeerUntrusted,
}

impl InputAuthority {
    pub fn is_human_intent(self) -> bool {
        match self {
            Self::HumanIntent => true,
            Self::ModelAuthoredUntrusted | Self::RuntimeControl | Self::PeerUntrusted => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TurnBoundary {
    Conversational,
    MidTurn,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnalyticsClass {
    HumanPrompt,
    AgentMessage,
    /// A message from a peer session; never a human prompt.
    PeerMessage,
    RuntimeWake,
}

impl AnalyticsClass {
    pub fn is_human_prompt(self) -> bool {
        match self {
            Self::HumanPrompt => true,
            Self::AgentMessage | Self::PeerMessage | Self::RuntimeWake => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompactionClass {
    HumanAnchor,
    ConversationalAgentAnchor,
    /// A peer message keeps its own class so it can never be read as a parent-agent anchor.
    ConversationalPeerAnchor,
    RuntimeEphemera,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueuePolicy {
    VisibleProtected,
    VisibleEditable,
    Hidden,
}

impl QueuePolicy {
    pub fn is_visible(self) -> bool {
        match self {
            Self::VisibleProtected | Self::VisibleEditable => true,
            Self::Hidden => false,
        }
    }

    pub fn is_editable(self) -> bool {
        match self {
            Self::VisibleEditable => true,
            Self::VisibleProtected | Self::Hidden => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShutdownPolicy {
    Drain,
    CancelWithProducer,
    DropEphemeral,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputPolicy {
    pub authority: InputAuthority,
    pub turn_boundary: TurnBoundary,
    pub analytics: AnalyticsClass,
    pub compaction: CompactionClass,
    pub queue: QueuePolicy,
    pub shutdown: ShutdownPolicy,
}

#[cfg(test)]
mod policy_tests {
    use super::{AnalyticsClass, InputAuthority};

    #[test]
    fn authority_predicates_cover_every_variant() {
        let cases = [
            (InputAuthority::HumanIntent, true),
            (InputAuthority::ModelAuthoredUntrusted, false),
            (InputAuthority::RuntimeControl, false),
            (InputAuthority::PeerUntrusted, false),
        ];
        for (authority, human_intent) in cases {
            assert_eq!(authority.is_human_intent(), human_intent, "{authority:?}");
        }
    }

    #[test]
    fn analytics_predicate_covers_every_variant() {
        let cases = [
            (AnalyticsClass::HumanPrompt, true),
            (AnalyticsClass::AgentMessage, false),
            (AnalyticsClass::PeerMessage, false),
            (AnalyticsClass::RuntimeWake, false),
        ];
        for (analytics, human_prompt) in cases {
            assert_eq!(analytics.is_human_prompt(), human_prompt, "{analytics:?}");
        }
    }
}

/// Input supplied when the host starts a turn.
pub struct TurnStartInput {
    /// True when the harness produced the turn (auto-wake, drain, cron, continuation), not the user.
    pub synthetic: bool,
}

impl TurnStartInput {
    pub fn new(synthetic: bool) -> Self {
        TurnStartInput { synthetic }
    }
}

/// Input supplied when the host completes a turn.
pub struct TurnDoneInput;

/// Why the host aborted the turn instead of completing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TurnAbortReason {
    /// The client went away mid-turn.
    Disconnected,
    /// The user interrupted the turn before it completed.
    Interrupted,
}

/// Input supplied when the host aborts a turn.
pub struct TurnAbortInput {
    pub reason: TurnAbortReason,
}

impl TurnAbortInput {
    pub fn new(reason: TurnAbortReason) -> Self {
        TurnAbortInput { reason }
    }
}

/// Input supplied when the host observes an error for a turn.
pub struct TurnErrorInput<'a> {
    pub message: &'a str,
}

#[async_trait]
pub trait TurnLifecycleContributor: Send + Sync {
    async fn on_turn_start(&self, _input: &TurnStartInput) {}

    async fn on_turn_start_with_policy(&self, input: &TurnStartInput, _policy: InputPolicy) {
        self.on_turn_start(input).await;
    }

    async fn on_turn_done(&self, _input: &TurnDoneInput) {}

    async fn on_turn_abort(&self, _input: &TurnAbortInput) {}

    async fn on_turn_error(&self, _input: &TurnErrorInput<'_>) {}
}
