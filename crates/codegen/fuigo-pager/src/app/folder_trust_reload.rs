//! F5-P (design F5 §4.1, §6.2, §8): the pager's side of the reload a durable folder-trust grant owes a session.
//!
//! The pager advertises `fuigo/folderTrust.reload`. The agent then tells it `folder_trust_reload` once per covered
//! session (only after a grant that reached the trust store, never one that was not saved), or reports the debt as
//! `_meta["fuigo/folderTrustReload"].owed` on a reattach. When the session is idle in this view (R3), the pager holds
//! input and sends `session/close`; only on `closed` does it send `session/load` with the same id, cwd, `mcpServers`
//! and `yoloMode`/`autoMode`. The cold load builds the session trusted, so nested AGENTS.md, project skills, hooks, MCP
//! servers and subagents come from the trusted folder (§8). Any other close answer, or none within
//! [`CLOSE_WAIT`], does not load and says so. A session that is never told about a grant is untouched.

use agent_client_protocol as acp;

use super::actions::{Effect, TaskResult};
use super::agent::AgentId;
use super::agent_view::AgentView;
use super::app_view::AppView;
use crate::scrollback::block::RenderBlock;

/// The client capability key (design F5 §4.1).
pub(crate) const CAPABILITY: &str = "fuigo/folderTrust";
/// The `sessionUpdate` of the reload notification.
pub(crate) const RELOAD_UPDATE: &str = "folder_trust_reload";
/// The load/resume response `_meta` key that says the reload is still owed.
pub(crate) const OWED_META: &str = "fuigo/folderTrustReload";
/// How long the pager waits for `session/close` (its own budget is 8 s, 8.5 s worst case) before it gives up.
pub(crate) const CLOSE_WAIT: std::time::Duration = std::time::Duration::from_secs(12);

/// Shown in place of the transcript while the reload runs.
pub(crate) const RELOADING: &str = "Folder trust is on. Reloading this session to use it...";
/// Added to the transcript when the reload finished.
pub(crate) const RELOADED: &str = "Folder trust is on. This session was reloaded with the folder's settings.";
/// Close answered `timeout`: the session was still saving when its close budget ran out.
pub(crate) const CLOSE_TIMEOUT: &str = "Folder trust is on, but this session was still saving after 8 seconds, so it \
                                        was not reloaded. Reopen this session to use it.";
/// Shown (as a toast) when the user sends while the reload holds input; the draft stays in the composer.
pub(crate) const HOLD_NOTICE: &str = "Reloading this session for folder trust. Your message is kept; send it when the \
                                      reload finishes.";
/// The close error when the agent gave no answer within [`CLOSE_WAIT`].
pub(crate) const CLOSE_NO_ANSWER: &str = "no answer from the agent within 12 seconds";

/// The `fuigo/folderTrust` capability value the pager advertises.
pub(crate) fn capability_value() -> serde_json::Value {
    serde_json::json!({ "reload": true })
}

/// Where a session is in its owed reload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Phase {
    /// A durable grant owes the reload; it starts when the session is idle in this view.
    Owed,
    /// `session/close` is in flight; input is held.
    Closing,
    /// Close answered `closed` and `session/load` is in flight inside the reload window `generation`; input is held.
    /// `untrusted_commands` is the pre-grant command and skill list, dropped from view when the reload starts.
    Loading { generation: u64, untrusted_commands: Vec<acp::AvailableCommand> },
}

/// The session id of a `folder_trust_reload` notification, if `notif` is one.
pub(crate) fn reload_notification_session(notif: &acp::ExtNotification) -> Option<acp::SessionId> {
    if !crate::acp::is_session_update_ext_method(notif.method.as_ref()) {
        return None;
    }
    let params: serde_json::Value = serde_json::from_str(notif.params.get()).ok()?;
    if params.pointer("/update/sessionUpdate").and_then(|v| v.as_str()) != Some(RELOAD_UPDATE) {
        return None;
    }
    params
        .get("sessionId")
        .and_then(|v| v.as_str())
        .map(|sid| acp::SessionId::new(sid.to_owned()))
}

/// Whether a load or resume response says the reload is still owed.
pub(crate) fn owed_in_meta(meta: Option<&acp::Meta>) -> bool {
    meta.and_then(|m| m.get(OWED_META))
        .and_then(|v| v.get("owed"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// The close response's `fuigo/closeOutcome` (an agent that predates it only ever answered a finished close).
pub(crate) fn close_outcome(meta: Option<&acp::Meta>) -> String {
    meta.and_then(|m| m.get("fuigo/closeOutcome"))
        .and_then(|v| v.as_str())
        .unwrap_or("closed")
        .to_owned()
}

/// The agent and session a (wrapped) load result is for.
pub(crate) fn loaded_target(result: &TaskResult) -> Option<(AgentId, acp::SessionId)> {
    match result {
        TaskResult::SessionLoaded { agent_id, session_id, .. } => Some((*agent_id, session_id.clone())),
        _ => None,
    }
}

/// `folder_trust_reload` arrived for `session_id`: owe the reload to the view that shows it.
pub(crate) fn handle_reload_notification(app: &mut AppView, session_id: &acp::SessionId) -> bool {
    let Some(agent_id) = app
        .agents
        .iter()
        .find(|(_, agent)| agent.session.session_id.as_ref() == Some(session_id))
        .map(|(id, _)| *id)
    else {
        tracing::debug!(session_id = %session_id.0, "folder trust: reload for a session this pager does not show");
        return false;
    };
    mark_owed(app, agent_id, session_id)
}

/// Owe the reload to `agent_id` if it still shows `session_id` and is not already reloading.
pub(crate) fn mark_owed(app: &mut AppView, agent_id: AgentId, session_id: &acp::SessionId) -> bool {
    let Some(agent) = app.agents.get_mut(&agent_id) else {
        return false;
    };
    if agent.session.session_id.as_ref() != Some(session_id) || agent.folder_trust_reload.is_some() {
        return false;
    }
    agent.folder_trust_reload = Some(Phase::Owed);
    true
}

/// R3: idle in its own view: no turn, no queued prompt, no background job or terminal, no sub-agent, no live
/// workflow, no card, question or elicitation pending, and no other load or reload in progress.
pub(crate) fn idle_for_reload(agent: &AgentView) -> bool {
    agent.session.state.is_idle()
        && agent.session.session_id.is_some()
        && agent.session_reload.is_none()
        && !agent.session.loading_replay
        && !agent.wake_turn_active()
        && agent.session.pending_prompts.is_empty()
        && agent.shared_queue.is_empty()
        && !agent.session.has_running_bg_tasks()
        && !agent.subagent_sessions.values().any(|s| s.is_running())
        && !agent.workflow_runs.iter().any(|run| run.is_active())
        && agent.permission_queue.is_empty()
        && agent.question_view.is_none()
        && agent.elicitation_view.is_none()
        && agent.pending_elicitation.is_none()
        && agent.queued_elicitations.is_empty()
}

/// Start every owed reload whose session is idle: hold input and close it.
pub(crate) fn poll(app: &mut AppView) -> Vec<Effect> {
    if app.reconnect_pending {
        return Vec::new();
    }
    let mut effects = Vec::new();
    for (agent_id, agent) in app.agents.iter_mut() {
        if agent.folder_trust_reload != Some(Phase::Owed) || !idle_for_reload(agent) {
            continue;
        }
        let Some(session_id) = agent.session.session_id.clone() else {
            continue;
        };
        agent.folder_trust_reload = Some(Phase::Closing);
        effects.push(Effect::FolderTrustClose { agent_id: *agent_id, session_id });
    }
    effects
}

/// Whether the active view's session is mid-reload, so a send must wait (the draft stays in the composer).
pub(crate) fn holds_input(app: &AppView) -> bool {
    let super::app_view::ActiveView::Agent(id) = app.active_view else {
        return false;
    };
    app.agents
        .get(&id)
        .is_some_and(|agent| matches!(agent.folder_trust_reload, Some(Phase::Closing | Phase::Loading { .. })))
}

fn next_generation() -> u64 {
    // Disjoint from reconnect generations (small counters), so a reconnect never finalizes this window.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    (1 << 63) | NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// `session/close` answered (or did not). Only `closed` reloads; anything else releases input and says why.
pub(crate) fn handle_closed(
    app: &mut AppView,
    agent_id: AgentId,
    session_id: &acp::SessionId,
    outcome: Result<String, String>,
) -> Vec<Effect> {
    let fallback_cwd = app.cwd.clone();
    let Some(agent) = app.agents.get_mut(&agent_id) else {
        return Vec::new();
    };
    if agent.folder_trust_reload != Some(Phase::Closing) || agent.session.session_id.as_ref() != Some(session_id) {
        return Vec::new();
    }
    let message = match outcome.as_deref() {
        Ok("closed") => None,
        Ok("timeout") => Some(CLOSE_TIMEOUT.to_owned()),
        Ok(other) => Some(format!(
            "Folder trust is on, but this session could not be reloaded (close answered \"{other}\"). Reopen this \
             session to use it."
        )),
        Err(error) => Some(format!(
            "Folder trust is on, but this session could not be reloaded ({error}). Reopen this session to use it."
        )),
    };
    if let Some(message) = message {
        agent.folder_trust_reload = None;
        agent.scrollback.push_block(RenderBlock::system(message));
        return Vec::new();
    }
    let generation = next_generation();
    let cwd = if agent.session.cwd.as_os_str().is_empty() { fallback_cwd } else { agent.session.cwd.clone() };
    let yolo = agent.session.is_yolo();
    let auto = super::dispatch::effective_auto(yolo, agent.session.is_auto());
    let mut meta = serde_json::json!({ "yoloMode": yolo, "autoMode": auto });
    if let Some(cursor) = agent.last_seen_event_id.as_ref() {
        // Only the tail past the cursor replays, so the transcript, and where the user scrolled to, stay as they are.
        meta["cursor"] = serde_json::Value::String(cursor.clone());
    }
    // §8: the untrusted session's command and skill list goes now; the trusted session sends its own on load.
    let untrusted_commands = std::mem::take(&mut agent.session.available_commands);
    agent.session.available_commands_generation += 1;
    agent.begin_session_reload_labeled(generation, RELOADING);
    agent.folder_trust_reload = Some(Phase::Loading { generation, untrusted_commands });
    vec![Effect::FolderTrustLoad { agent_id, session_id: session_id.clone(), cwd, meta, generation }]
}

/// The reload's `session/load` finished: close the reload window and say how it went.
pub(crate) fn handle_loaded(
    app: &mut AppView,
    agent_id: AgentId,
    session_id: &acp::SessionId,
    generation: u64,
    result: Result<(), String>,
) -> Vec<Effect> {
    let Some(agent) = app.agents.get_mut(&agent_id) else {
        return Vec::new();
    };
    let Some(Phase::Loading { generation: open, .. }) = agent.folder_trust_reload.as_ref() else {
        return Vec::new();
    };
    if *open != generation || agent.session.session_id.as_ref() != Some(session_id) {
        return Vec::new();
    }
    let Some(Phase::Loading { untrusted_commands, .. }) = agent.folder_trust_reload.take() else {
        return Vec::new();
    };
    let ok = result.is_ok();
    if !agent.finish_session_reload(generation, ok) {
        // A reconnect took the view over and reloads it itself.
        return Vec::new();
    }
    match result {
        Ok(()) => agent.scrollback.push_block(RenderBlock::system(RELOADED)),
        Err(error) => {
            if agent.session.available_commands.is_empty() {
                agent.session.available_commands = untrusted_commands;
                agent.session.available_commands_generation += 1;
            }
            agent.scrollback.push_block(RenderBlock::system(format!(
                "Folder trust is on, but reloading this session failed: {error}. Reopen this session to use it."
            )))
        }
    };
    Vec::new()
}
