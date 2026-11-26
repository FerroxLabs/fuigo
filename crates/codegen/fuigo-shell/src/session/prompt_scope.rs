//! Prompt scope (Fuigo 1.0.48, design 1022-grokwarm section A).
//!
//! A client that reuses one Fuigo process for several prompts must be able to tell which prompt caused every frame it
//! receives, including frames from background work that outlives its prompt (a background shell task, a monitor, a
//! subagent, the drain turn a finished task wakes). Reading the session-global `current_prompt_id` at emit time labels
//! such a frame with whatever prompt happens to be running, so the pair is bound when the work STARTS and carried with it:
//!
//! - `promptId`: the turn that produced the frame (a client prompt id, or an internal turn's own minted id);
//! - `originPromptId`: the client prompt at the root of that work. A client prompt is its own root; an internal turn names
//!   the client prompt whose work woke it; work no client prompt caused carries `null`.
//!
//! The pair travels as a tokio task-local ([`PromptScope::scope`]) on the turn task, and as an explicit root recorded in
//! the per-session [`PromptScopeRegistry`] for work that runs on other tasks (keyed by a work id such as a task id).
//!
//! Where the label is written: the agent-side gateway (`fuigo-acp-lib`) stamps EVERY agent-to-client frame, request or
//! notification, with the sending task's pair (keys a frame already carries win). Work handed to another task carries its
//! scope there ([`PromptScope::inherit`], or a scope looked up from the registry by the work's id). Session-level rule: a
//! frame sent outside any bound scope belongs to no prompt and carries `promptId: null, originPromptId: null`. Which
//! frames those are, file by file, is [`SEND_SITES`] (`Session` entries) and `coord-notes/1048-pscope-sites.md`.

use std::collections::HashMap;
use std::sync::Mutex;

/// `initialize` capability key: `agentCapabilities._meta["fuigo/promptScope"] = 1`.
pub(crate) const CAPABILITY_KEY: &str = "fuigo/promptScope";
pub(crate) const META_PROMPT_ID: &str = "promptId";
pub(crate) const META_ORIGIN_PROMPT_ID: &str = "originPromptId";
/// `turn_completed` `_meta` key: live background work at completion (design A8).
pub(crate) const META_BACKGROUND: &str = "background";

/// Whether this build satisfies every prompt-scope rule (A1b-A4, A7, A8) on every agent-to-client route.
/// The capability is advertised only when this is true; a client that sees no key must not reuse the process.
pub(crate) fn capability_advertised() -> bool {
    SEND_SITES
        .iter()
        .all(|(_, _, c)| !matches!(c, Coverage::Unscoped(_)))
}

/// Agent-to-client routes that do not yet carry the origin-bound pair (one entry per source file).
pub(crate) fn uncovered_routes() -> Vec<String> {
    SEND_SITES
        .iter()
        .filter_map(|(file, _, c)| match c {
            Coverage::Scoped(_) | Coverage::Session(_) | Coverage::NotAcp(_) => None,
            Coverage::Unscoped(why) => Some(format!("{file}: {why}")),
        })
        .collect()
}

/// How the send sites of a file are labelled. Every frame is stamped at the gateway; the class says whose pair it gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Coverage {
    /// Prompt work: each send runs in (or is stamped with) the scope of the work that caused it, bound at its start.
    Scoped(&'static str),
    /// Belongs to no prompt: session-level `null`s by rule (why).
    Session(&'static str),
    /// Not an agent-to-client ACP frame (why): below or beside the gateway, client-to-agent, hub, or test code.
    NotAcp(&'static str),
    /// Not labelled correctly yet: holds the capability off.
    Unscoped(&'static str),
}

/// Methods that send a frame or request to the ACP client (or an MCP `tools/call`): every `acp::Client` trait method
/// (agent-client-protocol 0.10, WF-4b) plus the gateway's own senders (`forward_*`, `send_request`, WF-4d), the raw
/// channel round-trip `acp_send` and the hub `send_notification`. WF-4 parses the non-test sources of [`SEND_SITE_CRATES`] (syn, full grammar) and counts every
/// mention of these names as a call or a path in any form: a method call (turbofish and line splits included), a UFCS or
/// qualified path (`acp::Client::session_notification(&gateway, frame)`, `<G as acp::Client>::ext_notification`), the method
/// used as a value, and an identifier inside a macro body. The per-file counts must equal [`SEND_SITES`], so a new route
/// cannot ship without being registered here, and the capability cannot be advertised while any registered file is
/// unscoped. A line text match cannot do this (it misses UFCS calls and macro bodies), so the gate is the parse.
pub(crate) const SEND_METHODS: &[&str] = &[
    "forward_fire_and_forget",
    "forward_with_completion",
    "request_permission",
    "ext_method",
    "read_text_file",
    "write_text_file",
    "create_terminal",
    "terminal_output",
    "release_terminal",
    "wait_for_terminal_exit",
    "kill_terminal",
    "call_tool",
    "session_notification",
    "ext_notification",
    "send_notification",
    "send_request",
    // The raw channel round-trip under the gateway (fuigo-acp-lib channel.rs).
    "acp_send",
];

/// Path segments that build an outgoing MCP `tools/call` (design A7). Each mention in an expression is a counted site, so a
/// new call path cannot ship without being registered (and stamped with `fuigo_mcp::servers::stamp_prompt_scope`).
pub(crate) const MCP_CALL_PATHS: &[&str] = &["CallToolRequestParams"];

/// Source roots scanned, relative to `crates/codegen`.
pub(crate) const SEND_SITE_CRATES: &[&str] = &[
    "fuigo-shell/src",
    "fuigo-workspace/src",
    "fuigo-acp-lib/src",
    "fuigo-shell-terminal/src",
    "fuigo-mcp/src",
];

/// (file relative to `crates/codegen`, send sites in it, coverage).
pub(crate) const SEND_SITES: &[(&str, usize, Coverage)] = &[
    (
        "fuigo-acp-lib/src/channel.rs",
        2,
        Coverage::NotAcp(
            "raw round-trip under the gateway; its one agent-to-client caller (the gateway) stamps first",
        ),
    ),
    (
        "fuigo-acp-lib/src/gateway.rs",
        19,
        Coverage::Scoped(
            "the stamping point: enqueue/forward stamp every agent-to-client frame with the sending task's pair",
        ),
    ),
    (
        "fuigo-acp-lib/src/message.rs",
        14,
        Coverage::NotAcp("receiver-side dispatch of frames the gateway already stamped"),
    ),
    (
        "fuigo-mcp/src/acp_transport.rs",
        2,
        Coverage::NotAcp("test-only rmcp client calls inside #[cfg(test)]"),
    ),
    (
        "fuigo-mcp/src/servers.rs",
        3,
        Coverage::Scoped("tools/call params stamped on the calling task (A7)"),
    ),
    (
        "fuigo-shell-terminal/src/acp_terminal.rs",
        6,
        Coverage::Scoped("terminal/* requests of a foreground command, on the turn's tool task"),
    ),
    (
        "fuigo-shell-terminal/src/adapter.rs",
        14,
        Coverage::Scoped(
            "tool-task terminal/* requests; the exit watcher inherits the starting turn's scope",
        ),
    ),
    (
        "fuigo-shell-terminal/src/exit_watcher.rs",
        5,
        Coverage::Scoped("runs in the watcher spawned with PromptScope::inherit"),
    ),
    (
        "fuigo-shell-terminal/src/pty_session.rs",
        1,
        Coverage::Session("client-opened interactive PTY (_fuigo/terminal), not prompt work"),
    ),
    (
        "fuigo-shell-terminal/src/streaming_local_terminal.rs",
        19,
        Coverage::Scoped(
            "output on the tool task; background completion inherits the starting turn's scope; rest test code",
        ),
    ),
    (
        "fuigo-shell/src/agent/credential_scrub.rs",
        2,
        Coverage::NotAcp("pass-through wrapper below the gateway"),
    ),
    (
        "fuigo-shell/src/agent/handlers/model_switch.rs",
        2,
        Coverage::Session("answers the client's model/config request"),
    ),
    (
        "fuigo-shell/src/agent/models.rs",
        1,
        Coverage::Session("models_updated status"),
    ),
    (
        "fuigo-shell/src/agent/mvp_agent/acp_agent.rs",
        1,
        Coverage::Scoped("prompt_complete is stamped with its own client prompt"),
    ),
    (
        "fuigo-shell/src/agent/mvp_agent/agent_ops.rs",
        6,
        Coverage::Session("session info, workspace ops, announcements, relay refusal notices"),
    ),
    (
        "fuigo-shell/src/agent/mvp_agent/folder_trust_prompt.rs",
        2,
        Coverage::Session("folder-trust prompt at session bring-up"),
    ),
    (
        "fuigo-shell/src/agent/mvp_agent/handle.rs",
        2,
        Coverage::NotAcp("pass-through wrapper below the gateway"),
    ),
    (
        "fuigo-shell/src/agent/mvp_agent/mod.rs",
        2,
        Coverage::Session("session/load task-completion replay and search-index notices"),
    ),
    (
        "fuigo-shell/src/agent/mvp_agent/replay.rs",
        3,
        Coverage::Session("session/load replay: stored frames keep their stored pair"),
    ),
    (
        "fuigo-shell/src/agent/mvp_agent/session_lifecycle.rs",
        1,
        Coverage::Session("session roster delta"),
    ),
    (
        "fuigo-shell/src/agent/park_hold.rs",
        17,
        Coverage::NotAcp(
            "receiver-side hold below the gateway; its unparked marker is stamped session-level in place",
        ),
    ),
    (
        "fuigo-shell/src/agent/subagent/mod.rs",
        1,
        Coverage::Scoped("progress ticks stamped with the scope bound at spawn"),
    ),
    (
        "fuigo-shell/src/agent/subagent/spawn.rs",
        1,
        Coverage::Scoped("subagent frames stamped with the scope bound at spawn"),
    ),
    (
        "fuigo-shell/src/cli_models.rs",
        2,
        Coverage::NotAcp("client-to-agent round trips (models CLI)"),
    ),
    (
        "fuigo-shell/src/extensions/mcp.rs",
        2,
        Coverage::Scoped(
            "servers_updated is MCP status (session-level); the debug call_tool stamps on the calling task",
        ),
    ),
    (
        "fuigo-shell/src/extensions/peer.rs",
        1,
        Coverage::Session("peer messages from other sessions"),
    ),
    (
        "fuigo-shell/src/extensions/routing.rs",
        1,
        Coverage::Scoped("helper: frame takes the calling task's scope at the gateway"),
    ),
    (
        "fuigo-shell/src/extensions/session_admin.rs",
        3,
        Coverage::Session("title notices answering the client's admin request"),
    ),
    (
        "fuigo-shell/src/extensions/session_park.rs",
        1,
        Coverage::NotAcp("internal park barrier answered by the hold, never written"),
    ),
    (
        "fuigo-shell/src/extensions/session_updates.rs",
        1,
        Coverage::Session("answers the client's session-updates request"),
    ),
    (
        "fuigo-shell/src/extensions/terminal.rs",
        4,
        Coverage::Session("client-driven _fuigo/terminal requests"),
    ),
    (
        "fuigo-shell/src/extensions/worktree.rs",
        1,
        Coverage::Session("worktree status at session bring-up"),
    ),
    (
        "fuigo-shell/src/session/acp_mcp.rs",
        1,
        Coverage::Scoped("reverse MCP call carries the inner tools/call pair"),
    ),
    (
        "fuigo-shell/src/session/acp_session/hooks.rs",
        2,
        Coverage::Scoped("hook runs take the calling turn's or tool's scope"),
    ),
    (
        "fuigo-shell/src/session/acp_session_impl/interjection.rs",
        1,
        Coverage::Session("echo of the client's interjection"),
    ),
    (
        "fuigo-shell/src/session/acp_session_impl/mcp.rs",
        7,
        Coverage::Session("MCP server status and tool registration"),
    ),
    (
        "fuigo-shell/src/session/acp_session_impl/prompt_queue.rs",
        1,
        Coverage::Session("prompt-queue changes"),
    ),
    (
        "fuigo-shell/src/session/acp_session_impl/run_loop.rs",
        2,
        Coverage::Session("MCP tools_changed"),
    ),
    (
        "fuigo-shell/src/session/acp_session_impl/spawn.rs",
        1,
        Coverage::Scoped("ask_user_question sent in its tool call's scope"),
    ),
    (
        "fuigo-shell/src/session/acp_session_impl/tool_calls.rs",
        1,
        Coverage::Scoped("exit_plan_mode request on the turn task"),
    ),
    (
        "fuigo-shell/src/session/acp_session_impl/tool_dispatch.rs",
        1,
        Coverage::NotAcp(
            "in-process tool dispatch, not a frame (tools run on the scoped drainer task)",
        ),
    ),
    (
        "fuigo-shell/src/session/acp_session_impl/turn_end.rs",
        1,
        Coverage::Scoped("goal activity at turn end, on the turn task"),
    ),
    (
        "fuigo-shell/src/session/acp_session_impl/updates.rs",
        5,
        Coverage::Scoped(
            "stamped from the bound scope at the call; sampler events take the running turn's start scope",
        ),
    ),
    (
        "fuigo-shell/src/session/fs_watch.rs",
        4,
        Coverage::Session("file-watcher notices"),
    ),
    (
        "fuigo-shell/src/session/goal_orchestrator.rs",
        1,
        Coverage::Scoped("goal updates take the calling turn's scope"),
    ),
    (
        "fuigo-shell/src/session/mcp_dispatcher.rs",
        2,
        Coverage::Session("MCP status and elicitation-complete flush"),
    ),
    (
        "fuigo-shell/src/session/mcp_elicitation.rs",
        1,
        Coverage::Scoped("elicitation card sent in the scope of the call it was raised during"),
    ),
    (
        "fuigo-shell/src/session/mcp_restart.rs",
        1,
        Coverage::Session("MCP server status"),
    ),
    (
        "fuigo-shell/src/session/pending_interaction.rs",
        1,
        Coverage::Scoped("sent within the scope of the request it tracks"),
    ),
    (
        "fuigo-shell/src/session/persistence.rs",
        2,
        Coverage::Session("disk-full notice"),
    ),
    (
        "fuigo-shell/src/session/summary.rs",
        2,
        Coverage::Session("session title and summary"),
    ),
    (
        "fuigo-shell/src/session/workflow/notify.rs",
        1,
        Coverage::Scoped("workflow updates take the calling turn's scope"),
    ),
    (
        "fuigo-shell/src/tools/notification_bridge.rs",
        9,
        Coverage::Scoped(
            "each notification sent in the scope of the work it reports (exhaustive match)",
        ),
    ),
    (
        "fuigo-workspace/src/bin/workspace_server_probe.rs",
        2,
        Coverage::NotAcp("probe binary"),
    ),
    (
        "fuigo-workspace/src/file_system/acp_fs.rs",
        4,
        Coverage::Scoped("fs/* requests on the turn's tool task"),
    ),
    (
        "fuigo-workspace/src/file_system/adapter.rs",
        2,
        Coverage::Scoped("fs/* requests on the turn's tool task"),
    ),
    (
        "fuigo-workspace/src/handle.rs",
        2,
        Coverage::NotAcp("computer-hub notifications, not ACP"),
    ),
    (
        "fuigo-workspace/src/mcp.rs",
        2,
        Coverage::NotAcp("hub-bridged MCP call (stamped when a scope is bound) and test code"),
    ),
    (
        "fuigo-workspace/src/permission/hub_permission.rs",
        1,
        Coverage::NotAcp("computer-hub permission transport, not ACP"),
    ),
    (
        "fuigo-workspace/src/permission/prompter.rs",
        1,
        Coverage::Scoped("the manager actor sends in the scope carried by the request"),
    ),
    (
        "fuigo-workspace/src/permission/sandbox_gate.rs",
        2,
        Coverage::NotAcp("computer-hub permission transport, not ACP"),
    ),
];

/// The (promptId, originPromptId) pair of a piece of work. It lives in `fuigo-acp-lib`, whose agent-side gateway stamps
/// the sending task's pair into every agent-to-client frame (session-level `null`s outside any bound scope).
pub use fuigo_acp_lib::PromptScope;

/// `extra` `_meta` keys plus `scope`'s pair (if any); keys already in `extra` win.
pub(crate) fn with_scope(
    scope: Option<PromptScope>,
    extra: Option<serde_json::Map<String, serde_json::Value>>,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    let Some(scope) = scope else {
        return extra;
    };
    let mut stamped = serde_json::Map::new();
    scope.stamp(&mut stamped);
    if let Some(extra) = extra {
        stamped.extend(extra);
    }
    Some(stamped)
}

/// Per-session record of which client prompt is the root of each piece of background work, and which of it is live.
///
/// A work id is bound once, when the work starts ([`Self::bind`]), with the scope of the turn that started it, and never
/// re-read from the running turn afterwards. [`Self::finish`] marks it no longer live but keeps its scope, because the drain
/// turn that reports a finished task runs after the task ends and must still name the task's root.
#[derive(Debug, Default)]
pub struct PromptScopeRegistry {
    inner: Mutex<RegistryInner>,
}

#[derive(Debug, Default)]
struct RegistryInner {
    bound: HashMap<String, PromptScope>,
    live: std::collections::HashSet<String>,
    internal_origins: HashMap<String, Option<String>>,
    turn_origins: HashMap<String, Option<String>>,
    current: Option<PromptScope>,
}

/// Entries kept per map; bounded so a long session cannot grow the maps without limit.
const MAX_ENTRIES: usize = 4096;

impl PromptScopeRegistry {
    fn lock(&self) -> std::sync::MutexGuard<'_, RegistryInner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Bind `work_id` to `scope` at the moment the work starts. A second bind of the same id keeps the first scope.
    pub fn bind(&self, work_id: &str, scope: PromptScope) {
        let mut inner = self.lock();
        if inner.bound.len() >= MAX_ENTRIES {
            let live = inner.live.clone();
            inner.bound.retain(|k, _| live.contains(k));
        }
        inner.bound.entry(work_id.to_string()).or_insert(scope);
        inner.live.insert(work_id.to_string());
    }

    /// Record `work_id`'s scope without tracking it as live (work whose liveness another registry owns, e.g. subagents).
    pub fn record(&self, work_id: &str, scope: PromptScope) {
        let mut inner = self.lock();
        if inner.bound.len() >= MAX_ENTRIES {
            let live = inner.live.clone();
            inner.bound.retain(|k, _| live.contains(k));
        }
        inner.bound.entry(work_id.to_string()).or_insert(scope);
    }

    /// Bind `work_id` to the scope recorded for the tool call that started it (bound at that call's `ToolCall` frame,
    /// inside its turn). An unknown tool call gives session-level `null`s: never the turn that happens to be current.
    pub fn bind_to_tool_call(&self, work_id: &str, tool_call_id: &str) -> PromptScope {
        let scope = self
            .scope_of(&tool_call_work_id(tool_call_id))
            .unwrap_or_default();
        self.bind(work_id, scope);
        self.scope_of(work_id).unwrap_or_default()
    }

    /// The work ended. Its scope stays readable for the turn that reports it.
    pub fn finish(&self, work_id: &str) {
        self.lock().live.remove(work_id);
    }

    /// The scope bound for `work_id`, `None` if it was never bound.
    pub fn scope_of(&self, work_id: &str) -> Option<PromptScope> {
        self.lock().bound.get(work_id).cloned()
    }

    /// The root bound for `work_id`: `None` if it was never bound, `Some(None)` for work not caused by a client prompt.
    pub fn root_of(&self, work_id: &str) -> Option<Option<String>> {
        self.scope_of(work_id).map(|s| s.origin_prompt_id)
    }

    /// Live bound work items in this session, whatever their root.
    pub fn live_count(&self) -> usize {
        self.lock().live.len()
    }

    /// A turn started with this scope. Work bound outside the turn task while it is the latest turn takes this scope.
    pub fn begin_turn(&self, scope: &PromptScope) {
        let mut inner = self.lock();
        if inner.turn_origins.len() >= MAX_ENTRIES {
            inner.turn_origins.clear();
        }
        if let Some(id) = &scope.prompt_id {
            inner
                .turn_origins
                .insert(id.clone(), scope.origin_prompt_id.clone());
        }
        inner.current = Some(scope.clone());
    }

    /// The origin a turn started with, for frames sent after the turn task ended (its `turn_completed`).
    pub fn turn_origin(&self, prompt_id: &str) -> Option<Option<String>> {
        self.lock().turn_origins.get(prompt_id).cloned()
    }

    /// The scope of the turn that started last.
    pub fn current(&self) -> Option<PromptScope> {
        self.lock().current.clone()
    }

    /// Record the origin of an internal turn when it is queued (its prompt id is minted there).
    pub fn set_internal_origin(&self, prompt_id: &str, origin: Option<String>) {
        let mut inner = self.lock();
        if inner.internal_origins.len() >= MAX_ENTRIES {
            inner.internal_origins.clear();
        }
        inner.internal_origins.insert(prompt_id.to_string(), origin);
    }

    /// Take the origin recorded for an internal turn when it starts.
    pub fn take_internal_origin(&self, prompt_id: &str) -> Option<Option<String>> {
        self.lock().internal_origins.remove(prompt_id)
    }

    /// The single root shared by every work id in `work_ids`; `None` when they disagree, any is unbound, or there are none.
    pub fn common_root<'a>(&self, work_ids: impl IntoIterator<Item = &'a str>) -> Option<String> {
        let inner = self.lock();
        let mut common: Option<String> = None;
        for id in work_ids {
            let root = inner.bound.get(id)?.origin_prompt_id.clone()?;
            match &common {
                None => common = Some(root),
                Some(c) if *c == root => {}
                Some(_) => return None,
            }
        }
        common
    }
}

static SESSION_REGISTRIES: std::sync::LazyLock<
    Mutex<HashMap<String, std::sync::Weak<PromptScopeRegistry>>>,
> = std::sync::LazyLock::new(Default::default);

/// Make a session's registry reachable by session id (subagents are spawned off the parent actor).
pub(crate) fn register_session(session_id: &str, registry: &std::sync::Arc<PromptScopeRegistry>) {
    let mut map = SESSION_REGISTRIES.lock().unwrap_or_else(|p| p.into_inner());
    map.retain(|_, w| w.strong_count() > 0);
    map.insert(session_id.to_string(), std::sync::Arc::downgrade(registry));
}

pub(crate) fn registry_for_session(
    session_id: &str,
) -> Option<std::sync::Arc<PromptScopeRegistry>> {
    SESSION_REGISTRIES
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(session_id)
        .and_then(std::sync::Weak::upgrade)
}

/// Bind a subagent at spawn to its parent prompt (bound by the task tool when the turn spawned it) and that prompt's root.
/// Returns the scope its frames carry. An unknown parent session or prompt gives session-level `null`s.
pub(crate) fn bind_subagent(
    parent_session_id: &str,
    parent_prompt_id: Option<&str>,
    subagent_id: &str,
) -> PromptScope {
    let registry = registry_for_session(parent_session_id);
    let scope = match parent_prompt_id {
        Some(parent) => {
            let origin = registry
                .as_ref()
                .and_then(|r| r.turn_origin(parent))
                .flatten();
            PromptScope::internal(parent, origin)
        }
        None => PromptScope::session(),
    };
    if let Some(registry) = registry {
        registry.record(&subagent_work_id(subagent_id), scope.clone());
    }
    scope
}

/// A8's count: live tasks + live subagents (pending, active, queued) + scheduled drains. `None` when any is unknown.
pub(crate) fn live_background_count(
    live_tasks: Option<usize>,
    subagents: Option<
        &fuigo_tools::implementations::fuigo_build::task::types::SubagentRegistryCounts,
    >,
    scheduled_drains: Option<usize>,
) -> Option<u64> {
    let subagents = subagents?;
    let live =
        live_tasks? + subagents.pending + subagents.active + subagents.queued + scheduled_drains?;
    Some(live as u64)
}

/// Work id of the task a queued notification reports.
pub(crate) fn notification_work_id(
    source: &crate::session::commands::NotificationSource,
) -> String {
    use crate::session::commands::NotificationSource;
    match source {
        NotificationSource::BashTaskCompleted { task_id } => bash_work_id(task_id),
        NotificationSource::MonitorEvent { task_id }
        | NotificationSource::MonitorCompleted { task_id } => monitor_work_id(task_id),
    }
}

/// Work id of a tool call (its scope is recorded when its `ToolCall` frame is sent).
pub fn tool_call_work_id(tool_call_id: &str) -> String {
    format!("tool-call:{tool_call_id}")
}

/// Work id of a background shell task.
pub fn bash_work_id(task_id: &str) -> String {
    format!("bash:{task_id}")
}

/// Work id of a monitor.
pub fn monitor_work_id(task_id: &str) -> String {
    format!("monitor:{task_id}")
}

/// Work id of a subagent.
pub fn subagent_work_id(subagent_id: &str) -> String {
    format!("subagent:{subagent_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_writes_explicit_nulls_for_session_level_work() {
        let mut meta = serde_json::Map::new();
        PromptScope::session().stamp(&mut meta);
        assert_eq!(meta.get(META_PROMPT_ID), Some(&serde_json::Value::Null));
        assert_eq!(
            meta.get(META_ORIGIN_PROMPT_ID),
            Some(&serde_json::Value::Null)
        );
    }

    #[test]
    fn registry_keeps_root_after_finish_and_counts_only_live_work() {
        let reg = PromptScopeRegistry::default();
        reg.bind("bash:t1", PromptScope::client("p1"));
        reg.bind("bash:t1", PromptScope::client("p2"));
        assert_eq!(reg.live_count(), 1);
        reg.finish("bash:t1");
        assert_eq!(reg.live_count(), 0);
        assert_eq!(reg.root_of("bash:t1"), Some(Some("p1".into())));
        assert_eq!(reg.common_root(["bash:t1"]), Some("p1".into()));
        reg.bind("bash:t2", PromptScope::client("p2"));
        assert_eq!(reg.common_root(["bash:t1", "bash:t2"]), None);
    }

    #[tokio::test]
    async fn scope_is_bound_only_inside_the_future() {
        assert_eq!(PromptScope::current(), None);
        let inner = PromptScope::client("p1")
            .scope(async { PromptScope::current() })
            .await;
        assert_eq!(inner, Some(PromptScope::client("p1")));
        assert_eq!(PromptScope::current(), None);
    }
}
