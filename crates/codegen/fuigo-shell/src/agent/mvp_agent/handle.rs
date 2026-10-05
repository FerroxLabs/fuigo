//! [`MvpAgentHandle`]: the movable owner of an agent whose state never moves (P84).
//!
//! The agent's background tasks reach it through a [`super::local_ref::LocalRef`], which is the address of the agent's
//! state. Before P84 that state was the value `MvpAgent::new` returned, so moving the value (out of a `Box`, into a
//! `Vec`, `std::mem::swap`) after it had spawned bound work left that work pointing at the old place (R090, open HIGH).
//! Now `MvpAgent::new` / `MvpAgent::with_models` return this handle instead: the state is boxed and pinned at
//! construction and dropped in place, and no `MvpAgent` value ever exists outside such a box, so the address a
//! `LocalRef` holds is the state's address for its whole life. The handle itself may be moved, swapped, put behind an
//! `Rc` and unwrapped again at will. `MvpAgent` is `!Unpin` (its `BoundTasks` field), so safe code cannot get a
//! `&mut MvpAgent` (and with it `std::mem::swap`/`replace`) out of the pin either.
//!
//! Everything else reads the state through `Deref` (`&MvpAgent`), exactly as before; the three construction-time setters
//! that need `&mut` live here and refuse to run once the agent has bound work pending.

use std::ops::Deref;
use std::pin::Pin;

use agent_client_protocol::{self as acp, Agent as _};

use super::MvpAgent;

/// Owns one agent; see the module docs. Dereferences to [`MvpAgent`].
pub struct MvpAgentHandle {
    state: Pin<Box<MvpAgent>>,
}

impl MvpAgentHandle {
    /// Pins a freshly built agent. Called only by the constructor, before the agent can spawn anything.
    pub(super) fn pin(state: MvpAgent) -> Self {
        Self { state: Box::pin(state) }
    }

    /// `&mut` access for the construction-time setters below.
    ///
    /// Panics if the agent has bound work pending: such work may hold a shared borrow of the agent across an `.await`,
    /// and a `&mut` alongside it would be undefined behaviour. Every caller configures the agent right after `new`.
    fn state_mut_while_unshared(&mut self) -> &mut MvpAgent {
        assert!(
            !self.state.bound_tasks.has_pending(),
            "an MvpAgent is configured through `&mut` only before it spawns background work"
        );
        // SAFETY: the returned borrow is used only to assign individual fields (the setters below); the state itself is
        // never moved or replaced through it, so the pinning guarantee the `LocalRef`s rely on holds. No bound future is
        // pending (asserted above), so no other reference into the state exists while this one does.
        unsafe { self.state.as_mut().get_unchecked_mut() }
    }

    /// Set the memory configuration (called from TUI after config resolution).
    pub fn set_memory_config(&mut self, config: crate::config::MemoryConfig) {
        self.state_mut_while_unshared().memory_config = if config.enabled { Some(config) } else { None };
    }

    /// Adopt the leader's [`AgentActivity`](crate::agent::activity::AgentActivity).
    /// The auto-update checker then sees the agent's live view of running turns/subagents and can flush sessions at shutdown.
    ///
    /// Must be called right after construction: entries registered on the constructor-created default instance are NOT migrated.
    pub(crate) fn set_activity(&mut self, activity: crate::agent::activity::AgentActivity) {
        self.state_mut_while_unshared().activity = activity;
    }

    /// Install the channel that fans new session cwds into the leader's `ConfigFileWatcher::watch_path`.
    /// Called once after the watcher is constructed in `agent/app.rs`.
    /// In simple / non-leader mode the channel is never wired and `notify_session_cwd_for_watch` is a no-op.
    pub(crate) fn set_config_watcher_path_tx(&mut self, tx: tokio::sync::mpsc::UnboundedSender<std::path::PathBuf>) {
        self.state_mut_while_unshared().config_watcher_path_tx = Some(tx);
    }

    /// Replaces the gateway (tests that swap the client channel mid-test).
    #[cfg(test)]
    pub(crate) fn set_gateway_for_tests(&mut self, gateway: super::GatewaySender) {
        self.state_mut_while_unshared().gateway = gateway;
    }
}

impl Deref for MvpAgentHandle {
    type Target = MvpAgent;

    fn deref(&self) -> &MvpAgent {
        &self.state
    }
}

/// Forwards every method `MvpAgent` implements; the rest keep the trait's defaults, as on `MvpAgent`.
#[async_trait::async_trait(?Send)]
impl acp::Agent for MvpAgentHandle {
    async fn initialize(&self, args: acp::InitializeRequest) -> Result<acp::InitializeResponse, acp::Error> {
        self.state.initialize(args).await
    }
    async fn authenticate(&self, args: acp::AuthenticateRequest) -> Result<acp::AuthenticateResponse, acp::Error> {
        self.state.authenticate(args).await
    }
    async fn new_session(&self, args: acp::NewSessionRequest) -> Result<acp::NewSessionResponse, acp::Error> {
        self.state.new_session(args).await
    }
    async fn load_session(&self, args: acp::LoadSessionRequest) -> Result<acp::LoadSessionResponse, acp::Error> {
        self.state.load_session(args).await
    }
    async fn list_sessions(&self, args: acp::ListSessionsRequest) -> Result<acp::ListSessionsResponse, acp::Error> {
        self.state.list_sessions(args).await
    }
    async fn resume_session(&self, args: acp::ResumeSessionRequest) -> Result<acp::ResumeSessionResponse, acp::Error> {
        self.state.resume_session(args).await
    }
    async fn close_session(&self, args: acp::CloseSessionRequest) -> Result<acp::CloseSessionResponse, acp::Error> {
        self.state.close_session(args).await
    }
    async fn prompt(&self, args: acp::PromptRequest) -> Result<acp::PromptResponse, acp::Error> {
        self.state.prompt(args).await
    }
    async fn cancel(&self, args: acp::CancelNotification) -> Result<(), acp::Error> {
        self.state.cancel(args).await
    }
    async fn set_session_mode(&self, args: acp::SetSessionModeRequest) -> Result<acp::SetSessionModeResponse, acp::Error> {
        self.state.set_session_mode(args).await
    }
    async fn set_session_model(
        &self,
        args: acp::SetSessionModelRequest,
    ) -> Result<acp::SetSessionModelResponse, acp::Error> {
        self.state.set_session_model(args).await
    }
    async fn set_session_config_option(
        &self,
        args: acp::SetSessionConfigOptionRequest,
    ) -> Result<acp::SetSessionConfigOptionResponse, acp::Error> {
        self.state.set_session_config_option(args).await
    }
    async fn ext_method(&self, args: acp::ExtRequest) -> Result<acp::ExtResponse, acp::Error> {
        self.state.ext_method(args).await
    }
    async fn ext_notification(&self, args: acp::ExtNotification) -> Result<(), acp::Error> {
        self.state.ext_notification(args).await
    }
}
