//! MCP extension methods and business logic.
//!
//! - `fuigo/mcp/list`: list available MCP servers (agent-scoped or session-annotated)
//! - `fuigo/mcp/call`: invoke an MCP tool directly, outside the LLM loop
//! - `fuigo/mcp/servers_updated`: the local and plugin catalog after launch-dir discovery or a folder-trust grant (not gateway connectors)
//! - `fuigo/mcp/server_status`: per-server delta pushed by the `StatusDispatcher`.
//!   The triggers: transport-closed pollers, handshake failures, config diffs, and server-pushed list-changed notifications.
//!   See [`crate::session::mcp_dispatcher`] for the coalescing and payload-shaping logic.
//!   Re-exported below so other crates have a single import point.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use agent_client_protocol::{self as acp, Client};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as TokioMutex;
// rmcp is quarantined in fuigo-mcp; see that crate's docs.
use fuigo_mcp::rmcp;
// `wire::MCP_CALL` is the one cross-SDK contract literal; the agent-only siblings live in `mcp_methods` below
use fuigo_mcp::wire;

use super::{ExtResult, parse_params, to_ext_response};

/// Agent-only `fuigo/mcp/*` ACP method/notification names.
///
/// Unlike [`wire::MCP_CALL`] (the cross-SDK contract, which stays in `fuigo_mcp::wire`), these methods are NOT spoken by the SDK.
/// They are private to the channel between the agent and the client.
/// They are centralized here only to avoid scattering the same string literal across dispatch and notification send sites.
pub mod mcp_methods {
    /// Shared prefix that routes every MCP ext method to this module's dispatcher.
    pub const PREFIX: &str = "fuigo/mcp/";

    pub const LIST: &str = "fuigo/mcp/list";
    pub const READ_RESOURCE: &str = "fuigo/mcp/read_resource";
    pub const AUTH_STATUS: &str = "fuigo/mcp/auth_status";
    pub const AUTH_TRIGGER: &str = "fuigo/mcp/auth_trigger";
    pub const SETUP: &str = "fuigo/mcp/setup";
    pub const TOGGLE: &str = "fuigo/mcp/toggle";
    pub const TOGGLE_TOOL: &str = "fuigo/mcp/toggle_tool";
    pub const UPSERT: &str = "fuigo/mcp/upsert";
    pub const DELETE: &str = "fuigo/mcp/delete";

    pub const SERVERS_UPDATED: &str = "fuigo/mcp/servers_updated";
    pub const TOOLS_CHANGED: &str = "fuigo/mcp/tools_changed";
    pub const INIT_PROGRESS: &str = "fuigo/mcp/init_progress";
}
use crate::agent::MvpAgent;
use crate::session::mcp_servers::{MCP_TOOL_NAME_DELIMITER, McpClient, McpState};

// ── Wire types: mcp/list ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpListRequest {
    #[serde(default)]
    pub session_id: Option<String>,
    /// When false, bypass cache and refetch from cli-chat-proxy, then sync into live sessions so `search_tool` sees new tools.
    /// Use after OAuth enrollment or disconnect.
    #[serde(default = "default_true")]
    pub cache: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct McpListResponse {
    pub servers: Vec<McpServerEntry>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpServerEntry {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub icons: Vec<fuigo_mcp::servers::McpIcon>,
    pub source: McpServerSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup: Option<crate::util::config::McpSetupConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup_values: Option<HashMap<String, String>>,
    #[serde(flatten)]
    pub config: McpServerConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<McpServerSessionState>,
}

/// MCP server config for the `mcp/list` catalog response.
///
/// Distinct from `acp::McpServer` (session/new input) because:
/// - HTTP: exposes `scope`, `scope_id`, and `scope_name` for connector selection, NOT headers (auth tokens stay private)
/// - Stdio: same structure but optimized for JSON wire format
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum McpServerConfig {
    #[serde(rename = "http")]
    Http {
        url: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        #[serde(rename = "scopeId", skip_serializing_if = "Option::is_none")]
        scope_id: Option<String>,
        #[serde(rename = "scopeName", skip_serializing_if = "Option::is_none")]
        scope_name: Option<String>,
    },
    #[serde(rename = "stdio")]
    Stdio {
        command: std::path::PathBuf,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        args: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        env: Vec<McpEnvVar>,
    },
    #[serde(rename = "managedGateway")]
    ManagedGateway,
}

#[derive(Debug, Clone, Serialize)]
pub struct McpEnvVar {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum McpServerSource {
    Managed,
    Local,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpServerSessionState {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<McpSessionStatus>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<McpToolEntry>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub auth_required: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub setup_required: bool,
    /// Managed-policy verdict for a server the merge dropped, so `/mcps` can say "blocked by policy"
    /// instead of a generic "unavailable"; old pagers ignore the extra field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum McpSessionStatus {
    Ready,
    Initializing,
    SetupRequired,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct McpToolEntry {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub icons: Vec<fuigo_mcp::servers::McpIcon>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

// ── Wire types: mcp/call ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct McpCallRequest {
    /// When present: session pool. When absent: agent pool (config.toml only).
    #[serde(default)]
    pub session_id: Option<String>,
    pub server: String,
    /// Endpoint URL; disambiguates when multiple servers share a name.
    #[serde(default)]
    pub server_url: Option<String>,
    pub tool: String,
    #[serde(default)]
    pub arguments: serde_json::Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpCallResponse {
    pub content: Vec<McpContentBlock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpContentBlock {
    #[serde(rename = "type")]
    pub kind: String,
    pub text: String,
}

// ── Internal types (not serialized to wire) ─────────────────────────

#[derive(Debug, Clone, Default)]
pub struct McpStatusSnapshot {
    pub configs: Vec<acp::McpServer>,
    pub clients: Vec<McpClientStatus>,
    pub auth_required: std::collections::HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct McpClientStatus {
    pub name: String,
    pub status: McpSessionStatus,
    pub tools: Vec<McpToolEntry>,
    pub icons: Vec<fuigo_mcp::servers::McpIcon>,
}

// ── Notification: mcp/servers_updated ────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpServersUpdated {
    pub mcp_servers: Vec<McpServerEntry>,
}

/// Per-server tool-list change push.
///
/// Emitted by [`crate::session::acp_session::AcpSession`] on the post-handshake, auth-recovery, and toggle-tool paths.
/// The `session_id` field lets the pager route the push to the owning agent via `find_session_match`.
/// Falling back to `app.active_view` was a latent multi-agent bug.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct McpToolsChanged {
    /// Session that owns this push.
    /// The pager routes via `find_session_match` so a background-agent push does not land on the foregrounded agent's modal.
    pub session_id: String,
    /// MCP server whose tool list changed.
    ///
    /// Currently unread by the pager.
    /// The pager treats every `tools_changed` push as a trigger to schedule a debounced `mcp/list` refetch and re-reads the full catalog.
    /// The toggle-tool path therefore leaves this empty for forward-compat.
    /// A future field-aware pager optimization would need to special-case empty as "not scoped to one server"; no consumer reads that today.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server_name: String,
    /// New tool entries for the named server.
    ///
    /// Currently unread by the pager for the same reason as `server_name` above.
    /// Empty on the toggle-tool path.
    /// Populated on the post-handshake and auth-recovery paths so future field-aware consumers can avoid the `mcp/list` round trip.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<McpToolEntry>,
}

// Re-export the `fuigo/mcp/server_status` schema and method constant from the dispatcher module
// External callers then have a single import point alongside the other `fuigo/mcp/*` types
//
// The canonical definitions stay in [`crate::session::mcp_dispatcher`]: their primary consumer is the dispatcher loop and its unit tests
// This import from `session` into `extensions` inverts the typical `extensions` to `session` flow
// Moving the types here would require either making the dispatcher import from `extensions` (the same inversion) or duplicating the schema
// Leaving the re-export here keeps the single import point without duplicating definitions
pub use crate::session::mcp_dispatcher::{
    McpServerStatus, McpServerStatusPayload, McpServerStatusReason, SERVER_STATUS_METHOD,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct McpReadResourceRequest {
    #[serde(default)]
    pub session_id: Option<String>,
    pub server: String,
    pub uri: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpReadResourceResponse {
    pub contents: Vec<McpReadResourceContent>,
}

/// A single resource content block from `resources/read`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpReadResourceContent {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

/// Push the full MCP catalog to the client.
/// Called in the background after launch-dir MCP discovery so `initialize()` isn't blocked by config walks.
pub async fn notify_servers_updated(
    gateway: &fuigo_acp_lib::AcpAgentGatewaySender,
    local_servers: &[acp::McpServer],
) {
    let catalog = build_mcp_catalog(local_servers);
    let payload = McpServersUpdated {
        mcp_servers: catalog,
    };
    if let Ok(params) = serde_json::value::to_raw_value(&payload) {
        let notification = acp::ExtNotification::new(mcp_methods::SERVERS_UPDATED, params.into());
        let _ = gateway.ext_notification(notification).await;
        tracing::info!("Sent fuigo/mcp/servers_updated notification to client");
    }
}

// ── Dispatch ────────────────────────────────────────────────────────

/// Inbound `fuigo/mcp/*` methods this agent services, resolved from the wire string.
///
/// Single source of truth for forward-method routing: [`handle`] maps each variant to its handler.
/// An unknown method yields `None`, which `handle` answers with `method_not_found`.
/// The reverse method [`wire::MCP_SDK_CALL`] is emit-only (agent to client) and has no variant here.
/// A stray inbound reverse call is therefore never misrouted to the forward `handle_call`.
#[derive(Debug, PartialEq, Eq)]
enum McpRoute {
    List,
    Call,
    ReadResource,
    AuthStatus,
    AuthTrigger,
    Setup,
    Toggle,
    ToggleTool,
    Upsert,
    Delete,
}

fn route_mcp_method(method: &str) -> Option<McpRoute> {
    Some(match method {
        mcp_methods::LIST => McpRoute::List,
        wire::MCP_CALL => McpRoute::Call,
        mcp_methods::READ_RESOURCE => McpRoute::ReadResource,
        mcp_methods::AUTH_STATUS => McpRoute::AuthStatus,
        mcp_methods::AUTH_TRIGGER => McpRoute::AuthTrigger,
        mcp_methods::SETUP => McpRoute::Setup,
        mcp_methods::TOGGLE => McpRoute::Toggle,
        mcp_methods::TOGGLE_TOOL => McpRoute::ToggleTool,
        mcp_methods::UPSERT => McpRoute::Upsert,
        mcp_methods::DELETE => McpRoute::Delete,
        _ => return None,
    })
}

#[tracing::instrument(skip_all, fields(method = %args.method))]
pub async fn handle(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    match route_mcp_method(args.method.as_ref()) {
        Some(McpRoute::List) => handle_list(agent, args).await,
        Some(McpRoute::Call) => handle_call(agent, args).await,
        Some(McpRoute::ReadResource) => handle_read_resource(agent, args).await,
        Some(McpRoute::AuthStatus) => handle_auth_status(agent, args).await,
        Some(McpRoute::AuthTrigger) => handle_auth_trigger(agent, args).await,
        Some(McpRoute::Setup) => handle_setup(agent, args).await,
        Some(McpRoute::Toggle) => handle_toggle(agent, args).await,
        Some(McpRoute::ToggleTool) => handle_toggle_tool(agent, args).await,
        Some(McpRoute::Upsert) => handle_upsert(agent, args).await,
        Some(McpRoute::Delete) => handle_delete(agent, args).await,
        None => Err(crate::acp_error::unknown_ext_method(&args.method)),
    }
}

// ── Catalog (shared by mcp/list and InitializeResponse._meta) ───────

/// Extract URL from an MCP server (HTTP and SSE only, None for Stdio).
fn mcp_server_url(server: &acp::McpServer) -> Option<&str> {
    match server {
        acp::McpServer::Http(acp::McpServerHttp { url, .. })
        | acp::McpServer::Sse(acp::McpServerSse { url, .. }) => Some(url.as_str()),
        acp::McpServer::Stdio(acp::McpServerStdio { .. }) => None,
        // TODO(acp-0.10): `McpServer` is #[non_exhaustive].
        _ => None,
    }
}

/// Build the MCP server catalog: gateway rows and local servers, deduplicated by name.
/// Pure function, no I/O. Used by `mcp/list`, `InitializeResponse._meta`, and `mcp/servers_updated`.
pub fn build_mcp_catalog(local_servers: &[acp::McpServer]) -> Vec<McpServerEntry> {
    build_mcp_catalog_with_gateway_tools(local_servers, None, &Default::default())
}

pub(crate) fn build_mcp_catalog_with_gateway_tools(
    local_servers: &[acp::McpServer],
    gateway_catalog: Option<&crate::session::managed_mcp::GatewayToolCatalog>,
    disabled_tools: &HashMap<String, HashSet<String>>,
) -> Vec<McpServerEntry> {
    let mut servers: Vec<McpServerEntry> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    if let Some(catalog) = gateway_catalog {
        let reauth: HashSet<&str> = catalog
            .connectors_needing_reauth
            .iter()
            .map(String::as_str)
            .collect();
        let mut by_connector: BTreeMap<&str, Vec<&crate::session::managed_mcp::GatewayTool>> =
            BTreeMap::new();
        for tool in &catalog.tools {
            by_connector
                .entry(tool.connector_id.as_str())
                .or_default()
                .push(tool);
        }

        for (connector_id, tools) in by_connector {
            let connector_name = tools
                .first()
                .map(|tool| tool.connector_name.as_str())
                .unwrap_or(connector_id);
            let disabled = disabled_tools.get(connector_id);
            let server_disabled = disabled_tools
                .get(crate::util::config::MANAGED_GATEWAY_DISABLED_CONNECTORS_KEY)
                .is_some_and(|set| set.contains(connector_id));
            let auth_required = reauth.contains(connector_id) || reauth.contains(connector_name);
            let name = managed_gateway_entry_name(connector_id);
            seen.insert(name.clone());
            servers.push(McpServerEntry {
                name,
                display_name: Some(connector_name.to_owned()),
                icons: Vec::new(),
                source: McpServerSource::Managed,
                config: McpServerConfig::ManagedGateway,
                source_label: None,
                setup: None,
                setup_values: None,
                session: Some(McpServerSessionState {
                    enabled: !server_disabled,
                    status: (!auth_required && !server_disabled).then_some(McpSessionStatus::Ready),
                    tools: tools
                        .into_iter()
                        .map(|tool| {
                            let qualified_name = tool.qualified_name();
                            McpToolEntry {
                                name: qualified_name.clone(),
                                icons: Vec::new(),
                                display_name: Some(tool.tool_name.clone()),
                                description: Some(tool.description.clone()),
                                meta: None,
                                enabled: disabled.is_none_or(|set| !set.contains(&qualified_name)),
                            }
                        })
                        .collect(),
                    auth_required,
                    setup_required: false,
                    blocked_reason: None,
                }),
            });
        }
    }

    // Local servers (HTTP or Stdio)
    for server in local_servers {
        let name = crate::session::mcp_servers::mcp_server_name(server).to_string();
        if seen.insert(name.clone()) {
            let source = McpServerSource::Local;
            let config = match server {
                acp::McpServer::Http(acp::McpServerHttp { url, .. })
                | acp::McpServer::Sse(acp::McpServerSse { url, .. }) => McpServerConfig::Http {
                    url: url.clone(),
                    scope: None,
                    scope_id: None,
                    scope_name: None,
                },
                acp::McpServer::Stdio(acp::McpServerStdio {
                    command, args, env, ..
                }) => McpServerConfig::Stdio {
                    command: command.clone(),
                    args: args.clone(),
                    env: env
                        .iter()
                        .map(|e| McpEnvVar {
                            name: e.name.clone(),
                            value: e.value.clone(),
                        })
                        .collect(),
                },
                // TODO(acp-0.10): `McpServer` is #[non_exhaustive].
                _ => continue,
            };
            servers.push(McpServerEntry {
                name,
                display_name: None,
                icons: Vec::new(),
                source,
                config,
                source_label: None,
                setup: None,
                setup_values: None,
                session: None,
            });
        }
    }

    servers
}

pub const MANAGED_GATEWAY_ENTRY_PREFIX: &str = "managed_gateway:";

fn managed_gateway_entry_name(connector_id: &str) -> String {
    format!("{MANAGED_GATEWAY_ENTRY_PREFIX}{connector_id}")
}

fn managed_gateway_connector_id(entry_name: &str) -> Option<&str> {
    entry_name.strip_prefix(MANAGED_GATEWAY_ENTRY_PREFIX)
}

fn disabled_server_placeholder_entry(name: &str) -> McpServerEntry {
    let is_managed_gateway = name.starts_with(MANAGED_GATEWAY_ENTRY_PREFIX);
    let source = if is_managed_gateway {
        McpServerSource::Managed
    } else {
        McpServerSource::Local
    };
    let config = if is_managed_gateway {
        McpServerConfig::ManagedGateway
    } else {
        McpServerConfig::Stdio {
            command: std::path::PathBuf::new(),
            args: Vec::new(),
            env: Vec::new(),
        }
    };
    McpServerEntry {
        name: name.to_owned(),
        display_name: name
            .strip_prefix(MANAGED_GATEWAY_ENTRY_PREFIX)
            .map(str::to_owned),
        icons: Vec::new(),
        source,
        source_label: None,
        setup: None,
        setup_values: None,
        config,
        session: Some(McpServerSessionState {
            enabled: false,
            status: None,
            tools: vec![],
            auth_required: false,
            setup_required: false,
            blocked_reason: None,
        }),
    }
}

// ── Session-level operations (called via SessionCommand) ────────────

/// Build session MCP status: which servers are enabled, healthy, and what tools they expose.
/// Clones state under lock then releases; it does not hold the lock across awaits.
pub(crate) async fn build_mcp_status(
    mcp_state: &Arc<TokioMutex<McpState>>,
    tool_bridge: &Arc<fuigo_tools::bridge::ToolBridge>,
    event_writer: Option<&fuigo_session_events::EventWriter>,
) -> McpStatusSnapshot {
    let _build_mcp_status_timer = crate::instrumentation::timer("build_mcp_status");
    let (
        configs,
        clients,
        _is_initializing,
        initializing_servers,
        mcp_tool_meta,
        mcp_tool_icons,
        auth_required,
        init_failed,
        disabled_regs,
    ) = {
        let state = mcp_state.lock().await;
        (
            state.configs.clone(),
            state
                .all_clients()
                .map(|(_, c)| c.clone())
                .collect::<Vec<_>>(),
            state.is_initializing(),
            state.handshaking_servers_cloned(),
            state.mcp_tool_meta.clone(),
            state.mcp_tool_icons.clone(),
            state.auth_required.clone(),
            state.init_failed.clone(),
            // Collect (qualified_name, description) for disabled tools so we can include them in the snapshot without cloning the full registration
            state
                .disabled_tool_registrations
                .iter()
                .map(|(k, v)| (k.clone(), v.description.clone()))
                .collect::<Vec<_>>(),
        )
    };

    let mut client_statuses = Vec::with_capacity(clients.len());
    let _client_loop_timer = crate::instrumentation::timer("mcp_status_client_loop");

    for client in &clients {
        let name = client.server_name().to_string();
        let prefix = format!("{}{}", name, MCP_TOOL_NAME_DELIMITER);

        let healthy = client.is_healthy().await;
        if let Some(ew) = event_writer {
            ew.emit(fuigo_session_events::Event::McpHealthCheck {
                server_name: name.clone(),
                healthy,
                client_state: Some(if healthy { "ready" } else { "unavailable" }.to_string()),
            });
        }
        // A server whose background init failed (a handshake or `tools/list` error, or a timeout) is reported as Unavailable even when the
        // transport is still alive
        // Otherwise a server that connected but hung on `tools/list` (0 tools registered) would misleadingly show as Ready
        let ready = healthy && !init_failed.contains_key(name.as_str());
        let (status, tools) = if ready {
            let _tool_defs_timer = crate::instrumentation::timer("mcp_status_tool_definitions");
            let mut tools: Vec<McpToolEntry> = tool_bridge
                .tool_definitions()
                .await
                .into_iter()
                .filter(|t| t.function.name.starts_with(&prefix))
                .map(|t| {
                    let qualified_name = &t.function.name;
                    let unqualified = qualified_name
                        .strip_prefix(&prefix)
                        .unwrap_or(qualified_name)
                        .to_string();
                    let meta = mcp_tool_meta.get(qualified_name).cloned();
                    let icons = mcp_tool_icons
                        .get(qualified_name)
                        .cloned()
                        .unwrap_or_default();
                    McpToolEntry {
                        name: unqualified,
                        display_name: None,
                        description: t.function.description.clone(),
                        meta,
                        icons,
                        enabled: true,
                    }
                })
                .collect();

            // Include disabled tools from stashed registrations.
            for (qname, desc) in &disabled_regs {
                if qname.starts_with(&prefix) {
                    let unqualified = qname.strip_prefix(&prefix).unwrap_or(qname).to_string();
                    let meta = mcp_tool_meta.get(qname).cloned();
                    let icons = mcp_tool_icons.get(qname).cloned().unwrap_or_default();
                    tools.push(McpToolEntry {
                        name: unqualified,
                        display_name: None,
                        description: Some(desc.clone()),
                        meta,
                        icons,
                        enabled: false,
                    });
                }
            }

            // Stable alphabetical order so tools don't jump around when toggled between enabled and disabled
            tools.sort_by(|a, b| a.name.cmp(&b.name));

            (McpSessionStatus::Ready, tools)
        } else {
            (McpSessionStatus::Unavailable, vec![])
        };

        let icons = client.server_icons().await;
        client_statuses.push(McpClientStatus {
            name,
            status,
            tools,
            icons,
        });
    }

    // A server configured but not yet handshaked (either global init or per-server background init) reports Initializing
    // We use initializing_servers (populated before spawning handshakes) so that slow servers continue showing Initializing after we call
    // finish_init() early
    for config in &configs {
        let cname = crate::session::mcp_servers::mcp_server_name(config);
        if !client_statuses.iter().any(|c| c.name == cname) && initializing_servers.contains(cname)
        {
            client_statuses.push(McpClientStatus {
                name: cname.to_string(),
                status: McpSessionStatus::Initializing,
                tools: vec![],
                icons: Vec::new(),
            });
        }
    }

    McpStatusSnapshot {
        configs,
        clients: client_statuses,
        auth_required,
    }
}

/// Ensure the agent-level MCP pool is initialized, waiting if another caller is already initializing. Safe to call concurrently.
async fn ensure_agent_pool_initialized(mcp_state: &Arc<TokioMutex<McpState>>) {
    loop {
        let state = mcp_state.lock().await;
        if state.is_initialized() {
            return;
        }
        if state.is_initializing() {
            // Another call is initializing; wait and retry
            drop(state);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            continue;
        }
        drop(state);
        let cwd = std::env::current_dir().unwrap_or_default();
        init_agent_mcp_pool(mcp_state, &cwd).await;
        return;
    }
}

/// Spawn config.toml MCP clients into the agent pool. Handshakes happen lazily on first `CallMcpTool`.
pub(crate) async fn init_agent_mcp_pool(
    mcp_state: &Arc<TokioMutex<McpState>>,
    cwd: &std::path::Path,
) {
    use crate::session::mcp_servers::start_mcp_servers;

    let configs = {
        let mut state = mcp_state.lock().await;
        if !state.try_start_init() {
            return;
        }
        state.configs.clone()
    };

    if configs.is_empty() {
        let mut state = mcp_state.lock().await;
        state.finish_init();
        return;
    }

    let noop = fuigo_session_events::EventWriter::noop();
    let ctx = crate::session::mcp_servers::McpSpawnCtx::standalone(&noop)
        .with_oauth_discovery(crate::session::mcp_servers::McpOauthDiscovery::Network);
    let meta = Default::default();
    let oauth = Default::default();
    let results = start_mcp_servers(configs, Some(cwd), &meta, &oauth, &ctx).await;
    let clients: fuigo_mcp::owned_clients::OwnedClients = results
        .into_iter()
        .filter_map(|r| match r {
            Ok(client) => {
                tracing::info!("Agent MCP server '{}' spawned", client.server_name());
                let name = client.server_name().to_string();
                Some((name, Arc::new(client)))
            }
            Err(e) => {
                tracing::warn!("Failed to spawn agent MCP server: {}", e);
                None
            }
        })
        .collect();

    let mut state = mcp_state.lock().await;
    state.owned_clients = clients;
    state.finish_init();
    tracing::info!(
        "Agent MCP pool: {} servers ready",
        state.owned_clients.len()
    );
}

/// Call an MCP tool directly (outside the LLM tool-use loop).
#[tracing::instrument(name = "mcp.call_tool", skip_all, fields(server_name, tool_name))]
pub async fn call_mcp_tool(
    mcp_state: &Arc<TokioMutex<McpState>>,
    server_name: &str,
    server_url: Option<&str>,
    tool_name: &str,
    arguments: serde_json::Value,
) -> Result<McpCallResponse, String> {
    let client = {
        let state = mcp_state.lock().await;

        // Resolve: (name + url) > url-only > name-only.
        let target = if let Some(url) = server_url {
            let config_name =
                |c: &acp::McpServer| crate::session::mcp_servers::mcp_server_name(c).to_string();
            state
                .configs
                .iter()
                .find(|c| {
                    crate::session::mcp_servers::mcp_server_name(c) == server_name
                        && mcp_server_url(c) == Some(url)
                })
                .map(&config_name)
                .or_else(|| {
                    state
                        .configs
                        .iter()
                        .find(|c| mcp_server_url(c) == Some(url))
                        .map(&config_name)
                })
                .unwrap_or_else(|| server_name.to_string())
        } else {
            server_name.to_string()
        };

        Arc::clone(
            state
                .get_client(&target)
                .ok_or_else(|| format!("server '{}' not found", target))?,
        )
    };

    let tool_timeout_sec = client.tool_timeout_for(tool_name);
    let timeout = std::time::Duration::from_secs(tool_timeout_sec);
    let result = tokio::time::timeout(timeout, client.call_tool(tool_name, arguments))
        .await
        .map_err(|_| format!("tool '{}' timed out after {}s", tool_name, tool_timeout_sec))?
        .map_err(|e| format!("tool call failed: {}", e))?;

    let content = result
        .content
        .iter()
        .filter_map(|c| match c {
            rmcp::model::ContentBlock::Text(t) => Some(McpContentBlock {
                kind: "text".to_string(),
                text: t.text.clone(),
            }),
            rmcp::model::ContentBlock::Resource(r) => {
                serde_json::to_string(r).ok().map(|json| McpContentBlock {
                    kind: "resource".to_string(),
                    text: json,
                })
            }
            _ => None,
        })
        .collect();

    Ok(McpCallResponse {
        content,
        is_error: result.is_error,
    })
}

// ── mcp/list handler ────────────────────────────────────────────────

async fn handle_list(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    // The gateway catalog fetch and the session-state branch run concurrently via tokio::join!
    // The session-state branch is a conditional `retry_auth_required_servers` followed by `build_mcp_status`
    // OAuth retries only fire on explicit refresh (cache=false); cached opens skip them so the warm path stays fast
    let req = parse_params::<McpListRequest>(args)?;

    let cwd = req
        .session_id
        .as_ref()
        .and_then(|sid| agent.get_session_cwd(&acp::SessionId::new(sid.clone())))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    // Resolve the session handle synchronously up front so the session-state future can be polled alongside the gateway catalog fetch
    let session_handle = req.session_id.as_ref().and_then(|sid| {
        let acp_id = acp::SessionId::new(sid.clone());
        agent.get_session_handle(&acp_id)
    });
    if let (Some(sid), None) = (req.session_id.as_ref(), session_handle.as_ref()) {
        tracing::debug!(
            session_id = %sid,
            "mcp/list: session not found, returning agent-level catalog only"
        );
    }

    let cache = req.cache;
    let session_state_fut = async {
        let handle = session_handle.as_ref()?;
        // Auth retries belong on explicit refresh: skipping them on cached opens saves ~500ms when multiple OAuth servers are configured
        if !cache {
            handle.retry_auth_required_servers().await;
        }
        Some(handle.get_mcp_status().await)
    };

    let (gateway_catalog, session_snapshot) = tokio::join!(
        agent.fetch_gateway_catalog_for_mcp_list(cache),
        session_state_fut
    );

    let compat = agent.cfg.borrow().compat_resolved;
    let plugin_registry_snapshot = agent.plugin_registry_snapshot();
    let local_servers = crate::util::config::load_mcp_servers(&cwd, &compat);
    let disabled_tools = crate::util::config::get_all_mcp_disabled_tools(&cwd);
    let mut servers = build_mcp_catalog_with_gateway_tools(
        &local_servers,
        gateway_catalog.as_ref(),
        &disabled_tools,
    );
    let disabled_names = crate::util::config::disabled_mcp_server_names(&cwd);
    let setup_entries = crate::util::config::collect_mcp_setup_configs(
        &cwd,
        plugin_registry_snapshot.as_deref(),
        &compat,
    );
    let preferences = crate::util::config::load_mcp_preferences().file();
    for (name, setup_entry) in setup_entries {
        if servers.iter().any(|entry| entry.name == name) {
            continue;
        }
        let enabled = !disabled_names.contains(&name);
        let setup_schema = setup_entry.config.setup.clone();
        let (setup, setup_required, status) = match setup_entry
            .config
            .resolve_setup(preferences.servers.get(&name))
        {
            crate::util::config::McpSetupResolution::Required(setup) => {
                (Some(setup), true, Some(McpSessionStatus::SetupRequired))
            }
            // Surface schema/template breakage instead of dropping the row.
            crate::util::config::McpSetupResolution::Invalid(_) => {
                (setup_schema, true, Some(McpSessionStatus::SetupRequired))
            }
            crate::util::config::McpSetupResolution::Resolved(_) => continue,
        };
        let values = preferences
            .servers
            .get(&name)
            .map(|prefs| prefs.values.clone());
        servers.push(McpServerEntry {
            name: name.clone(),
            icons: Vec::new(),
            display_name: None,
            source: McpServerSource::Local,
            source_label: setup_entry
                .source
                .plugin
                .as_ref()
                .map(|plugin| format!("plugin: {plugin}")),
            setup,
            setup_values: values,
            config: McpServerConfig::Http {
                url: String::new(),
                scope: None,
                scope_id: None,
                scope_name: None,
            },
            session: Some(McpServerSessionState {
                enabled,
                status,
                tools: vec![],
                auth_required: false,
                setup_required,
                blocked_reason: None,
            }),
        });
    }

    // Disabled stubs: only names Space enable can still resolve (see `crate::util::config::mcp_reenable`)
    // Orphans with no definition stay hidden
    let catalog_names: HashSet<String> = servers.iter().map(|s| s.name.clone()).collect();
    let discovery = crate::session::managed_mcp::McpDiscoveryInputs {
        cwd: &cwd,
        plugin_registry: plugin_registry_snapshot.as_deref(),
        compat: &compat,
    };
    // One discovery pass per request: the index serves both the disabled
    // stubs and (for a live session list) the blocked-reason verdicts.
    let needs_stub_scan =
        crate::util::config::needs_definition_scan(&disabled_names, &catalog_names);
    let definition_index = if needs_stub_scan || session_snapshot.is_some() {
        Some(crate::util::config::McpDefinitionIndex::build(&discovery))
    } else {
        None
    };
    let allowlist = &fuigo_workspace::permission::resolution::managed_settings().mcp_allowlist;
    if needs_stub_scan && let Some(index) = &definition_index {
        for name in index.reenableable_for_list(&disabled_names, &catalog_names, allowlist) {
            servers.push(disabled_server_placeholder_entry(&name));
        }
    }

    // Carry the verdict for policy-dropped servers so the pager can say "blocked by policy"
    // instead of a generic "unavailable"; computed only with a session snapshot.
    let blocked_reasons: HashMap<String, String> = match (&session_snapshot, &definition_index) {
        (Some(_), Some(index)) => list_blocked_reasons(index.definitions(), allowlist),
        _ => HashMap::new(),
    };

    if let Some(snapshot) = session_snapshot {
        if gateway_catalog.is_some()
            && let Some(disabled) = match session_handle.as_ref() {
                Some(h) => Some(h.managed_gateway_disabled_tool_names().await),
                None => None,
            }
        {
            for entry in &mut servers {
                if entry.source == McpServerSource::Managed
                    && let Some(session) = entry.session.as_mut()
                {
                    let connector_id =
                        managed_gateway_connector_id(&entry.name).unwrap_or(&entry.name);
                    if let Some(tools) = disabled.get(connector_id) {
                        for tool in &mut session.tools {
                            if tools.contains(&tool.name) {
                                tool.enabled = false;
                            }
                        }
                    }
                }
            }
        }
        // `session_snapshot` is `Some` only when `session_handle` resolved, which requires `req.session_id` to have been `Some`
        // An `expect` would assert that non-local invariant here
        // A future refactor of `session_state_fut` could silently turn that `expect` into a panic in a request handler
        // So use a local `if let` guard around the only consumer, the debug log
        // We emit `%sid` (Display) to match the sibling "session not found" log
        // `?req.session_id` would wrap the bare string as `Some("...")` and diverge from the earlier format
        if let Some(sid) = req.session_id.as_ref() {
            tracing::debug!(session_id = %sid, "Annotating mcp/list with session state");
        }
        let catalog_names: std::collections::HashSet<String> =
            servers.iter().map(|s| s.name.clone()).collect();

        // Annotate catalog entries with session state.
        for entry in &mut servers {
            if entry
                .session
                .as_ref()
                .is_some_and(|session| session.setup_required)
            {
                continue;
            }
            let managed_gateway_session = entry.source == McpServerSource::Managed
                && matches!(&entry.config, McpServerConfig::ManagedGateway);
            if managed_gateway_session {
                if let Some(session) = entry.session.as_mut() {
                    let connector_id =
                        managed_gateway_connector_id(&entry.name).unwrap_or(&entry.name);
                    let managed_disabled = disabled_tools
                        .get(crate::util::config::MANAGED_GATEWAY_DISABLED_CONNECTORS_KEY)
                        .is_some_and(|set| set.contains(connector_id));
                    session.enabled = !disabled_names.contains(&entry.name) && !managed_disabled;
                }
                continue;
            }
            let enabled = snapshot
                .configs
                .iter()
                .any(|c| crate::session::mcp_servers::mcp_server_name(c) == entry.name);
            let (status, tools, icons) = snapshot
                .clients
                .iter()
                .find(|c| c.name == entry.name)
                .map(|c| (Some(c.status.clone()), c.tools.clone(), c.icons.clone()))
                .unwrap_or((None, vec![], Vec::new()));
            entry.icons = icons;
            entry.session = Some(McpServerSessionState {
                enabled,
                status,
                tools,
                auth_required: snapshot.auth_required.contains(&entry.name),
                setup_required: false,
                // Only a server the merge actually dropped is "blocked" — a
                // live one keeps its real status.
                blocked_reason: (!enabled)
                    .then(|| blocked_reasons.get(&entry.name).cloned())
                    .flatten(),
            });
        }

        // Append session-only servers (passed via session/new but not in catalog).
        for client_status in &snapshot.clients {
            if !catalog_names.contains(&client_status.name) {
                servers.push(McpServerEntry {
                    name: client_status.name.clone(),
                    icons: client_status.icons.clone(),
                    display_name: None,
                    source: McpServerSource::Local,
                    source_label: None,
                    setup: None,
                    setup_values: None,
                    config: McpServerConfig::Stdio {
                        command: std::path::PathBuf::new(),
                        args: Vec::new(),
                        env: Vec::new(),
                    },
                    session: Some(McpServerSessionState {
                        enabled: true,
                        status: Some(client_status.status.clone()),
                        tools: client_status.tools.clone(),
                        auth_required: snapshot.auth_required.contains(&client_status.name),
                        setup_required: false,
                        blocked_reason: None,
                    }),
                });
            }
        }
    }

    // Tag servers with the owning plugin
    // This covers both a plugin's .mcp.json and its inline plugin.json mcpServers via the registry's deduped owner map
    if let Some(registry) = plugin_registry_snapshot.as_ref() {
        for entry in &mut servers {
            if entry.source_label.is_none()
                && let Some(plugin_name) = registry.mcp_server_owner(&entry.name)
            {
                entry.source_label = Some(format!("plugin: {plugin_name}"));
            }
        }
    }
    to_ext_response(Ok(McpListResponse { servers }))
}

// ── mcp/call handler ────────────────────────────────────────────────

async fn handle_call(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    let req = parse_params::<McpCallRequest>(args)?;

    let result = match req.session_id {
        Some(sid) => {
            // Session-provided servers: route through the session's MCP pool.
            // Waits for an in-flight `session/load` (a reconnect replay after a leader restart) before failing
            let acp_id = acp::SessionId::new(sid);
            let handle = agent
                .session_handle_waiting_for_load(&acp_id)
                .await
                .ok_or_else(|| crate::acp_error::invalid_params("session not found"))?;
            handle
                .call_mcp_tool(req.server, req.server_url, req.tool, req.arguments)
                .await
        }
        None => {
            // No session: use the agent-level MCP pool (config.toml servers).
            let mcp_state = agent.agent_mcp_state();
            ensure_agent_pool_initialized(&mcp_state).await;
            call_mcp_tool(
                &mcp_state,
                &req.server,
                req.server_url.as_deref(),
                &req.tool,
                req.arguments,
            )
            .await
        }
    }
    .map_err(crate::acp_error::internal_error)?;

    to_ext_response(Ok(result))
}

async fn handle_read_resource(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    let req = parse_params::<McpReadResourceRequest>(args)?;

    let result = if let Some(ref sid) = req.session_id {
        // Waits for an in-flight `session/load`; see `handle_call` above
        let acp_id = acp::SessionId::new(sid.clone());
        let handle = agent
            .session_handle_waiting_for_load(&acp_id)
            .await
            .ok_or_else(|| crate::acp_error::invalid_params("session not found"))?;
        handle
            .read_mcp_resource(req.server.clone(), req.uri.clone())
            .await
    } else {
        let mcp_state = agent.agent_mcp_state();
        ensure_agent_pool_initialized(&mcp_state).await;
        read_mcp_resource(&mcp_state, &req.server, &req.uri).await
    }
    .map_err(crate::acp_error::internal_error)?;

    to_ext_response(Ok(result))
}

pub(crate) async fn read_mcp_resource(
    mcp_state: &Arc<TokioMutex<McpState>>,
    server_name: &str,
    uri: &str,
) -> Result<McpReadResourceResponse, String> {
    let client = {
        let state = mcp_state.lock().await;
        Arc::clone(
            state
                .get_client(server_name)
                .ok_or_else(|| format!("server '{}' not found", server_name))?,
        )
    };

    let mcp_service = client
        .ensure_initialized()
        .await
        .map_err(|e| format!("MCP init failed: {}", e))?;

    let result = mcp_service
        .read_resource(rmcp::model::ReadResourceRequestParams::new(uri))
        .await
        .map_err(|e| format!("resource read failed: {}", e))?;

    if result.contents.is_empty() {
        return Err("empty resource".to_string());
    }

    let contents: Vec<McpReadResourceContent> = result
        .contents
        .into_iter()
        .filter_map(|c| match c {
            rmcp::model::ResourceContents::TextResourceContents {
                uri,
                mime_type,
                text,
                meta,
                ..
            } => Some(McpReadResourceContent {
                uri,
                mime_type,
                text: Some(text),
                blob: None,
                meta: meta.and_then(|m| serde_json::to_value(m).ok()),
            }),
            rmcp::model::ResourceContents::BlobResourceContents {
                uri,
                mime_type,
                blob,
                meta,
                ..
            } => Some(McpReadResourceContent {
                uri,
                mime_type,
                text: None,
                blob: Some(blob),
                meta: meta.and_then(|m| serde_json::to_value(m).ok()),
            }),
            // `ResourceContents` is non_exhaustive; skip unknown variants so the rest of the resource still renders
            // Log the drop so the missing content is diagnosable
            _ => {
                tracing::warn!(
                    server = server_name,
                    uri,
                    "skipping unknown MCP resource content variant"
                );
                None
            }
        })
        .collect();

    if contents.is_empty() {
        return Err("resource contained only unsupported content variants".to_string());
    }

    Ok(McpReadResourceResponse { contents })
}

// ── McpResourceProvider bridge ───────────────────────────────────────
//
// Implements the `McpResourceProvider` trait from fuigo-tools
// The `ListMcpResources` and `FetchMcpResource` tools can then access MCP servers without depending on `fuigo-mcp` directly

/// Bridge from `McpState` to the `McpResourceProvider` trait.
///
/// Injected into the agent's `SharedResources` via `tool_bridge.update_resource()` at session startup.
/// Tools can then enumerate and fetch MCP resources.
pub(crate) struct McpStateResourceProvider(pub Arc<TokioMutex<McpState>>);

#[async_trait::async_trait]
impl fuigo_tools::types::resources::McpResourceProvider for McpStateResourceProvider {
    async fn list_resources(
        &self,
        server: Option<String>,
    ) -> Result<Vec<fuigo_tools::types::resources::McpResourceInfo>, String> {
        let clients: Vec<(String, Arc<McpClient>)> = {
            let state = self.0.lock().await;
            match &server {
                Some(name) => match state.get_client(name) {
                    Some(c) => vec![(name.clone(), Arc::clone(c))],
                    None => return Err(format!("MCP server '{name}' not found")),
                },
                None => state
                    .all_clients()
                    .map(|(name, client)| (name.to_string(), Arc::clone(client)))
                    .collect(),
            }
        };

        let mut resources = Vec::new();
        for (server_name, client) in clients {
            let mcp_service = match client.ensure_initialized().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        server = %server_name,
                        error = %e,
                        "Failed to initialize MCP server for list_resources"
                    );
                    continue;
                }
            };

            match mcp_service.list_all_resources().await {
                Ok(all_resources) => {
                    for r in all_resources {
                        resources.push(fuigo_tools::types::resources::McpResourceInfo {
                            uri: r.uri.clone(),
                            name: Some(r.name.clone()),
                            description: r.description.clone(),
                            mime_type: r.mime_type.clone(),
                            server: server_name.clone(),
                        });
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        server = %server_name,
                        error = %e,
                        "list_resources RPC failed"
                    );
                    if server.is_some() {
                        return Err(format!("list_resources failed for '{server_name}': {e}"));
                    }
                    // For all-servers mode, skip failures and continue.
                }
            }
        }

        Ok(resources)
    }

    async fn read_resource(
        &self,
        server: String,
        uri: String,
    ) -> Result<fuigo_tools::types::resources::McpResourceReadResult, String> {
        let client = {
            let state = self.0.lock().await;
            Arc::clone(
                state
                    .get_client(&server)
                    .ok_or_else(|| format!("MCP server '{server}' not found"))?,
            )
        };

        let mcp_service = client
            .ensure_initialized()
            .await
            .map_err(|e| format!("MCP init failed: {e}"))?;

        // `RunningService::read_resource` (not `Peer::read_resource`) drives SEP-2322
        // `input_required` rounds through the client handler, so elicitation requests on
        // resource reads reach the HITL bridge like tool calls do.
        let result = mcp_service
            .read_resource(rmcp::model::ReadResourceRequestParams::new(uri.clone()))
            .await
            .map_err(|e| format!("resource read failed: {e}"))?;

        if result.contents.is_empty() {
            return Err(format!("Resource not found: {uri}"));
        }

        let first = result
            .contents
            .into_iter()
            .find(|c| {
                let supported = matches!(
                    c,
                    rmcp::model::ResourceContents::TextResourceContents { .. }
                        | rmcp::model::ResourceContents::BlobResourceContents { .. }
                );
                if !supported {
                    tracing::warn!(uri, "skipping unknown MCP resource content variant");
                }
                supported
            })
            .ok_or_else(|| format!("Unsupported resource content type for: {uri}"))?;
        match first {
            rmcp::model::ResourceContents::TextResourceContents {
                uri: content_uri,
                mime_type,
                text,
                ..
            } => Ok(fuigo_tools::types::resources::McpResourceReadResult {
                uri: content_uri,
                name: None,
                description: None,
                mime_type,
                content: Some(fuigo_tools::types::resources::McpResourceContent::Text(
                    text,
                )),
            }),
            rmcp::model::ResourceContents::BlobResourceContents {
                uri: content_uri,
                mime_type,
                blob,
                ..
            } => Ok(fuigo_tools::types::resources::McpResourceReadResult {
                uri: content_uri,
                name: None,
                description: None,
                mime_type,
                content: Some(fuigo_tools::types::resources::McpResourceContent::Blob(
                    blob.into_bytes(),
                )),
            }),
            // Unreachable: `first` is pre-filtered to supported variants, but `ResourceContents` is non_exhaustive so the match must be total
            _ => Err(format!("Unsupported resource content type for: {uri}")),
        }
    }
}

// ── Auth status and trigger ──────────────────────────────────────────

#[derive(serde::Deserialize)]
struct McpAuthStatusRequest {
    session_id: String,
}

#[derive(serde::Serialize)]
pub struct McpAuthStatusEntry {
    pub server_name: String,
    pub status: &'static str,
}

#[derive(serde::Serialize)]
struct McpAuthStatusResponse {
    servers: Vec<McpAuthStatusEntry>,
}

async fn handle_auth_status(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    let req = parse_params::<McpAuthStatusRequest>(args)?;
    let acp_id = acp::SessionId::new(req.session_id);
    let handle = agent
        .get_session_handle(&acp_id)
        .ok_or_else(|| crate::acp_error::invalid_params("session not found"))?;
    let entries = handle.mcp_auth_status().await;
    to_ext_response(Ok(McpAuthStatusResponse { servers: entries }))
}

#[derive(serde::Deserialize)]
struct McpAuthTriggerRequest {
    session_id: String,
    server_name: String,
}

#[derive(serde::Serialize)]
struct McpAuthTriggerResponse {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    setup: Option<crate::util::config::McpSetupConfig>,
    /// Descriptive failure reason from the shell.
    /// `None` on success and on failures with no detail; the TUI shows it verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

async fn handle_auth_trigger(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    let req = parse_params::<McpAuthTriggerRequest>(args)?;
    let acp_id = acp::SessionId::new(req.session_id);
    let handle = agent
        .get_session_handle(&acp_id)
        .ok_or_else(|| crate::acp_error::invalid_params("session not found"))?;
    let cwd = agent
        .get_session_cwd(&acp_id)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let setup_entries = crate::util::config::collect_mcp_setup_configs(
        &cwd,
        agent.plugin_registry_snapshot().as_deref(),
        &agent.cfg.borrow().compat_resolved,
    );
    let preferences = crate::util::config::load_mcp_preferences().file();
    if let Some(entry) = setup_entries.get(&req.server_name) {
        match entry
            .config
            .resolve_setup(preferences.servers.get(&req.server_name))
        {
            crate::util::config::McpSetupResolution::Required(setup) => {
                return to_ext_response(Ok(McpAuthTriggerResponse {
                    status: "setup_required",
                    setup: Some(setup),
                    error: None,
                }));
            }
            crate::util::config::McpSetupResolution::Invalid(reason) => {
                return to_ext_response(Ok(McpAuthTriggerResponse {
                    status: "setup_required",
                    setup: entry.config.setup.clone(),
                    error: Some(reason),
                }));
            }
            crate::util::config::McpSetupResolution::Resolved(_) => {}
        }
    }
    match handle.mcp_auth_trigger(req.server_name).await {
        Ok(()) => to_ext_response(Ok(McpAuthTriggerResponse {
            status: "authenticated",
            setup: None,
            error: None,
        })),
        Err(e) => {
            tracing::warn!(%e, "MCP auth trigger failed");
            to_ext_response(Ok(McpAuthTriggerResponse {
                status: "failed",
                setup: None,
                error: Some(e),
            }))
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct McpSetupRequest {
    session_id: String,
    server_name: String,
    values: HashMap<String, String>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct McpSetupResponse {
    ok: bool,
}

async fn handle_setup(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    let req = parse_params::<McpSetupRequest>(args)?;
    let acp_id = acp::SessionId::new(req.session_id.clone());
    let handle = agent
        .get_session_handle(&acp_id)
        .ok_or_else(|| crate::acp_error::invalid_params("session not found"))?;
    let cwd = agent
        .get_session_cwd(&acp_id)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let setup_entries = crate::util::config::collect_mcp_setup_configs(
        &cwd,
        agent.plugin_registry_snapshot().as_deref(),
        &agent.cfg.borrow().compat_resolved,
    );
    let entry = setup_entries
        .get(&req.server_name)
        .ok_or_else(|| crate::acp_error::invalid_params("server setup not found"))?;
    let setup = entry
        .config
        .setup
        .as_ref()
        .ok_or_else(|| crate::acp_error::invalid_params("server setup not found"))?;

    // Only schema field ids (never arbitrary client keys).
    let filtered_values: HashMap<String, String> = setup
        .fields
        .iter()
        .filter_map(|field| {
            req.values
                .get(&field.id)
                .map(|value| (field.id.clone(), value.clone()))
        })
        .collect();

    let pending_preferences = crate::util::config::McpServerPreferences {
        values: filtered_values,
        source: Some(entry.source.clone()),
        updated_at: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
    };
    match entry.config.resolve_setup(Some(&pending_preferences)) {
        crate::util::config::McpSetupResolution::Resolved(_) => {}
        crate::util::config::McpSetupResolution::Required(_) => {
            return Err(crate::acp_error::invalid_params("setup values incomplete"));
        }
        crate::util::config::McpSetupResolution::Invalid(reason) => {
            return Err(crate::acp_error::invalid_params(reason));
        }
    }

    let load = crate::util::config::load_mcp_preferences();
    if !load.is_writable() {
        return Err(crate::acp_error::internal_error(
            "MCP preferences file is unreadable; fix or remove mcp_preferences.json before saving",
        ));
    }
    let mut prefs = load.file();
    let previous_entry = prefs.servers.get(&req.server_name).cloned();
    prefs
        .servers
        .insert(req.server_name.clone(), pending_preferences);
    crate::util::config::save_mcp_preferences(&prefs)
        .await
        .map_err(|e| crate::acp_error::internal_error(e.to_string()))?;

    let rollback_prefs = || async {
        let _ = crate::util::config::restore_mcp_preference_server(
            &req.server_name,
            previous_entry.clone(),
        )
        .await;
    };

    // Presence check with personal disable ignored (no config write yet).
    let plugin_reg = agent.plugin_registry_snapshot();
    let compat = agent.cfg.borrow().compat_resolved;
    let discovery = crate::session::managed_mcp::McpDiscoveryInputs {
        cwd: &cwd,
        plugin_registry: plugin_reg.as_deref(),
        compat: &compat,
    };
    let discovered =
        crate::session::managed_mcp::discover_mcp_definitions_ignoring_disable(&discovery);
    let Some(probe) = discovered.get(&req.server_name) else {
        rollback_prefs().await;
        return Err(crate::acp_error::internal_error(
            "server did not resolve after setup",
        ));
    };
    let allowlist = &fuigo_workspace::permission::resolution::managed_settings().mcp_allowlist;
    if let Some(message) = policy_enable_error(allowlist, probe) {
        rollback_prefs().await;
        return Err(crate::acp_error::invalid_params(message));
    }

    // Clear disable only after resolve succeeds, then merge for a spawnable transport
    let was_disabled =
        crate::util::config::disabled_mcp_server_names(&cwd).contains(&req.server_name);
    let enable_paths = if was_disabled {
        match crate::util::config::save_mcp_server_enabled_in(&req.server_name, true, &cwd).await {
            Ok(paths) => paths,
            Err(e) => {
                rollback_prefs().await;
                return Err(crate::acp_error::internal_error(format!(
                    "failed to clear disabled MCP server entry after setup resolve: {e}"
                )));
            }
        }
    } else {
        Vec::new()
    };

    let restore_disable = || async {
        if !was_disabled {
            return;
        }
        if let Err(re) = crate::util::config::restore_mcp_server_enabled_after_enable(
            &req.server_name,
            &enable_paths,
        )
        .await
        {
            tracing::warn!(
                server = req.server_name.as_str(),
                error = %re,
                "Failed to restore MCP enable state after setup failure"
            );
        }
    };

    // Restores both the preferences and the enable state for failures after enable wrote config
    let rollback_after_enable = || async {
        rollback_prefs().await;
        restore_disable().await;
    };

    let found = crate::session::managed_mcp::merge_managed_mcp_servers_with_policy(
        vec![],
        &cwd,
        plugin_reg.as_deref(),
        &compat,
    )
    .into_iter()
    .find(|s| crate::session::mcp_servers::mcp_server_name(&s.server) == req.server_name);

    let server = match found {
        Some(s) if s.disabled_reason.is_none() => s.server,
        Some(s) => {
            rollback_after_enable().await;
            return Err(crate::acp_error::invalid_params(
                s.disabled_reason
                    .map(|r| org_policy_message(&req.server_name, &r))
                    .unwrap_or_else(|| "blocked by organization policy".into()),
            ));
        }
        None => {
            rollback_after_enable().await;
            return Err(crate::acp_error::internal_error(
                "server did not resolve after setup",
            ));
        }
    };

    if let Err(e) = handle
        .toggle_mcp_server(req.server_name.clone(), true, Some(server))
        .await
    {
        rollback_after_enable().await;
        return Err(crate::acp_error::internal_error(
            crate::sampling::error::acp_error_text(&e),
        ));
    }

    to_ext_response(Ok(McpSetupResponse { ok: true }))
}

// ── mcp/toggle handler ───────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct McpToggleRequest {
    session_id: String,
    server_name: String,
    enabled: bool,
}

#[derive(serde::Serialize)]
struct McpToggleResponse {
    ok: bool,
}

/// The org-policy refusal for enabling or adding a server (one wording for both).
fn org_policy_message(
    name: &str,
    reason: &crate::session::managed_mcp::McpDisabledReason,
) -> String {
    // The name is a case-sensitive identifier (long ones middle-truncate). The
    // policy file appears by name only (doctor/JSON/logs keep full paths).
    let path = reason.user_facing_source();
    format!(
        "The server {} is blocked by an organization policy ({path}).",
        clamped_server_name(name)
    )
}

/// Server names are unbounded user input; middle-truncate very long ones so the reason clause
/// survives the pager's ~200-char error truncation. Short names print verbatim.
fn clamped_server_name(name: &str) -> std::borrow::Cow<'_, str> {
    const MAX_CHARS: usize = 40;
    if name.chars().count() <= MAX_CHARS {
        return name.into();
    }
    let head: String = name.chars().take(MAX_CHARS / 2).collect();
    let tail_rev: Vec<char> = name.chars().rev().take(MAX_CHARS / 2 - 1).collect();
    let tail: String = tail_rev.into_iter().rev().collect();
    format!("{head}…{tail}").into()
}

/// User-facing refusal for enabling/spawning a policy-blocked server (`None` when it passes) —
/// the one chokepoint for the toggle, setup, and upsert paths.
pub(crate) fn policy_enable_error(
    allowlist: &fuigo_workspace::permission::resolution::McpServerAllowlist,
    server: &acp::McpServer,
) -> Option<String> {
    if allowlist.is_server_allowed(server) {
        return None;
    }
    let reason =
        crate::session::managed_mcp::McpDisabledReason::for_blocked_server(allowlist, server);
    Some(org_policy_message(
        crate::session::mcp_servers::mcp_server_name(server),
        &reason,
    ))
}

/// Verdicts for every discovered definition the policy would drop, keyed by server name;
/// `mcp/list` copies them onto the rows the merge did not spawn.
pub(crate) fn list_blocked_reasons<'a>(
    definitions: impl IntoIterator<Item = (&'a str, &'a acp::McpServer)>,
    allowlist: &fuigo_workspace::permission::resolution::McpServerAllowlist,
) -> HashMap<String, String> {
    definitions
        .into_iter()
        .filter_map(|(name, server)| {
            policy_enable_error(allowlist, server).map(|message| (name.to_string(), message))
        })
        .collect()
}

/// `mcp/upsert`'s gate→persist sequence: the policy refusal comes BEFORE the config write, so a
/// refused upsert leaves no state behind; generic over the persist future (unit-testable).
pub(crate) async fn upsert_gate_then_persist<Fut>(
    allowlist: &fuigo_workspace::permission::resolution::McpServerAllowlist,
    server: &acp::McpServer,
    persist: impl FnOnce() -> Fut,
) -> Result<Fut::Output, String>
where
    Fut: std::future::Future,
{
    if let Some(message) = policy_enable_error(allowlist, server) {
        return Err(message);
    }
    Ok(persist().await)
}

/// Typed failure out of [`enable_mcp_server_gated`]; each caller maps the
/// arms onto its own wire error shape.
#[derive(Debug)]
pub(crate) enum GatedEnableError {
    /// No definition resolves for the name (probe miss, or post-write merge
    /// miss — the latter after rolling back the enable write).
    NotFound,
    /// Policy refused (probe verdict, or the post-write merge tag after
    /// rollback), formatted via [`org_policy_message`].
    PolicyRefused(String),
    /// Persisting the enable failed; `save_mcp_server_enabled_in` rolled back
    /// its own partial writes.
    PersistFailed(String),
    /// The live toggle failed after the enable write; the write has been
    /// rolled back.
    ToggleFailed(String),
    /// A blocking discovery/merge task did not complete (any enable write has
    /// been rolled back).
    TaskFailed(String),
}

/// The gated enable's re-merge leg: any discover/merge divergence fails closed AND rolls back
/// the just-persisted enable, or the write silently resurrects the server next session.
pub(crate) async fn confirm_enabled_or_rollback<Fut>(
    server_name: &str,
    found: Option<crate::session::managed_mcp::McpServerWithPolicy>,
    rollback: impl FnOnce() -> Fut,
) -> Result<acp::McpServer, GatedEnableError>
where
    Fut: std::future::Future<Output = ()>,
{
    match found {
        Some(s) => match s.disabled_reason {
            None => Ok(s.server),
            Some(reason) => {
                rollback().await;
                Err(GatedEnableError::PolicyRefused(org_policy_message(
                    server_name,
                    &reason,
                )))
            }
        },
        None => {
            rollback().await;
            Err(GatedEnableError::NotFound)
        }
    }
}

/// The gated-enable core, generic over its five effects so the ordering (verdict before write,
/// rollback on every failure past it) is unit-testable; [`enable_mcp_server_gated`] wires the real effects.
pub(crate) async fn run_gated_enable<P, ProbeFut, PersistFut, RollFut, MergeFut, ToggleFut>(
    server_name: &str,
    probe: impl FnOnce() -> ProbeFut,
    persist_enable: impl FnOnce() -> PersistFut,
    rollback: impl Fn(P) -> RollFut,
    merge_find: impl FnOnce() -> MergeFut,
    toggle: impl FnOnce(acp::McpServer) -> ToggleFut,
) -> Result<(), GatedEnableError>
where
    P: Clone,
    ProbeFut: std::future::Future<Output = Result<(), GatedEnableError>>,
    PersistFut: std::future::Future<Output = Result<P, String>>,
    RollFut: std::future::Future<Output = ()>,
    MergeFut: std::future::Future<
            Output = Result<Option<crate::session::managed_mcp::McpServerWithPolicy>, String>,
        >,
    ToggleFut: std::future::Future<Output = Result<(), String>>,
{
    probe().await?;

    // Clear the personal disable only after the policy passes. No-op (empty
    // path list) when the server wasn't disabled.
    let enable_paths = persist_enable()
        .await
        .map_err(GatedEnableError::PersistFailed)?;

    let found = match merge_find().await {
        Ok(found) => found,
        Err(detail) => {
            rollback(enable_paths).await;
            return Err(GatedEnableError::TaskFailed(detail));
        }
    };
    let server =
        confirm_enabled_or_rollback(server_name, found, || rollback(enable_paths.clone())).await?;

    if let Err(detail) = toggle(server).await {
        // Without this rollback the persisted enable silently spawns the
        // server in every later session while the client saw only an error.
        rollback(enable_paths).await;
        return Err(GatedEnableError::ToggleFailed(detail));
    }
    Ok(())
}

/// Discovery walks are synchronous disk scans: hop to the blocking pool, never the session
/// actor's LocalSet. `McpDiscoveryInputs` borrows, so the owned inputs are rebuilt inside the task.
async fn spawn_discovery<T: Send + 'static>(
    cwd: std::path::PathBuf,
    plugin_registry: Option<std::sync::Arc<fuigo_agent::plugins::PluginRegistry>>,
    compat: fuigo_tools::types::compat::CompatConfig,
    walk: impl FnOnce(&crate::session::managed_mcp::McpDiscoveryInputs<'_>) -> T + Send + 'static,
) -> Result<T, tokio::task::JoinError> {
    tokio::task::spawn_blocking(move || {
        walk(&crate::session::managed_mcp::McpDiscoveryInputs {
            cwd: &cwd,
            plugin_registry: plugin_registry.as_deref(),
            compat: &compat,
        })
    })
    .await
}

/// The ONE gated enable sequence for `mcp/toggle`: policy verdict BEFORE any
/// config write; every failure past the write rolls the enable back ([`run_gated_enable`]).
async fn enable_mcp_server_gated(
    agent: &MvpAgent,
    handle: &crate::session::SessionHandle,
    cwd: &std::path::Path,
    server_name: &str,
) -> Result<(), GatedEnableError> {
    let plugin_reg = agent.plugin_registry_snapshot();
    let compat = agent.cfg.borrow().compat_resolved;

    let probe_reg = plugin_reg.clone();
    let probe = || async move {
        let discovered = spawn_discovery(
            cwd.to_path_buf(),
            probe_reg,
            compat,
            crate::session::managed_mcp::discover_mcp_definitions_ignoring_disable,
        )
        .await
        .map_err(|e| GatedEnableError::TaskFailed(format!("MCP discovery task failed: {e}")))?;
        let Some(probe) = discovered.get(server_name) else {
            return Err(GatedEnableError::NotFound);
        };
        let allowlist =
            &fuigo_workspace::permission::resolution::managed_settings().mcp_allowlist;
        if let Some(message) = policy_enable_error(allowlist, probe) {
            return Err(GatedEnableError::PolicyRefused(message));
        }
        Ok(())
    };

    let persist_enable = || async move {
        crate::util::config::save_mcp_server_enabled_in(server_name, true, cwd)
            .await
            .map_err(|e| e.to_string())
    };

    let rollback = |paths: Vec<std::path::PathBuf>| async move {
        if let Err(re) =
            crate::util::config::restore_mcp_server_enabled_after_enable(server_name, &paths).await
        {
            tracing::warn!(
                server = server_name,
                error = %re,
                "Failed to restore MCP enable state after enable failure"
            );
        }
    };

    let merge_reg = plugin_reg.clone();
    let merge_find = || async move {
        let cwd = cwd.to_path_buf();
        let server_name = server_name.to_string();
        // Full config walk: blocking pool, never the session actor's LocalSet.
        tokio::task::spawn_blocking(move || {
            crate::session::managed_mcp::merge_managed_mcp_servers_with_policy(
                vec![],
                &cwd,
                merge_reg.as_deref(),
                &compat,
            )
            .into_iter()
            .find(|s| crate::session::mcp_servers::mcp_server_name(&s.server) == server_name)
        })
        .await
        .map_err(|e| format!("MCP merge task failed: {e}"))
    };

    let toggle = |server: acp::McpServer| async move {
        handle
            .toggle_mcp_server(server_name.to_string(), true, Some(server))
            .await
            .map_err(|e| crate::sampling::error::acp_error_text(&e))
    };

    run_gated_enable(
        server_name,
        probe,
        persist_enable,
        rollback,
        merge_find,
        toggle,
    )
    .await
}

async fn handle_toggle(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    let req = parse_params::<McpToggleRequest>(args)?;
    let acp_id = acp::SessionId::new(req.session_id.clone());

    let handle = agent
        .get_session_handle(&acp_id)
        .ok_or_else(|| crate::acp_error::invalid_params("session not found"))?;

    if let Some(connector_id) = managed_gateway_connector_id(&req.server_name) {
        // Managed-gateway connectors are exempt from the MCP server policy by design (server-side
        // curated); only local/plugin/project definitions pass the gated enable below.
        let enable_paths = if req.enabled {
            let cwd = agent
                .get_session_cwd(&acp_id)
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
            // Propagate like the local-server sibling (PersistFailed): `mcp/list` derives gateway
            // enablement from `disabled_mcp_servers`, so an unpersisted enable misreports ok.
            Some(
                crate::util::config::save_mcp_server_enabled_in(&req.server_name, true, &cwd)
                    .await
                    .map_err(|e| {
                        crate::acp_error::internal_error(format!(
                            "failed to clear disabled MCP server entry: {e}"
                        ))
                    })?,
            )
        } else {
            None
        };
        if let Err(e) = handle
            .toggle_managed_gateway_tool(connector_id.to_string(), String::new(), req.enabled)
            .await
        {
            // Roll the persisted enable back like the gated local sibling: without it, `mcp/list` shows
            // enabled while the client only saw an error.
            if let Some(paths) = enable_paths
                && let Err(re) = crate::util::config::restore_mcp_server_enabled_after_enable(
                    &req.server_name,
                    &paths,
                )
                .await
            {
                tracing::warn!(
                    server = req.server_name.as_str(),
                    error = %re,
                    "Failed to restore MCP enable state after gateway toggle failure"
                );
            }
            return Err(crate::acp_error::internal_error(
                crate::sampling::error::acp_error_text(&e),
            ));
        }
        return to_ext_response(Ok(McpToggleResponse { ok: true }));
    }

    if req.enabled {
        let cwd = agent
            .get_session_cwd(&acp_id)
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
        enable_mcp_server_gated(agent, &handle, &cwd, &req.server_name)
            .await
            .map_err(|e| match e {
                GatedEnableError::NotFound => crate::acp_error::invalid_params(format!(
                    "server '{}' not found in config",
                    req.server_name
                )),
                GatedEnableError::PolicyRefused(message) => {
                    crate::acp_error::invalid_params(message)
                }
                GatedEnableError::PersistFailed(detail) => crate::acp_error::internal_error(
                    format!("failed to clear disabled MCP server entry: {detail}"),
                ),
                GatedEnableError::ToggleFailed(detail) | GatedEnableError::TaskFailed(detail) => {
                    crate::acp_error::internal_error(detail)
                }
            })?;
        return to_ext_response(Ok(McpToggleResponse { ok: true }));
    }

    handle
        .toggle_mcp_server(req.server_name, false, None)
        .await
        .map_err(|e| {
            crate::acp_error::internal_error(crate::sampling::error::acp_error_text(&e))
        })?;

    to_ext_response(Ok(McpToggleResponse { ok: true }))
}

// ── mcp/toggle_tool handler ─────────────────────────────────────────

#[derive(serde::Deserialize)]
struct McpToggleToolRequest {
    session_id: String,
    server_name: String,
    tool_name: String,
    enabled: bool,
}

async fn handle_toggle_tool(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    let req = parse_params::<McpToggleToolRequest>(args)?;
    let acp_id = acp::SessionId::new(req.session_id.clone());

    let handle = agent
        .get_session_handle(&acp_id)
        .ok_or_else(|| crate::acp_error::invalid_params("session not found"))?;

    // `managed_gateway:` is reserved, so route by prefix alone
    // Never consult the catalog, or a stale tool toggle would fall back to the local path
    let gateway_connector_id = managed_gateway_connector_id(&req.server_name);
    let is_managed_gateway = gateway_connector_id.is_some();

    if is_managed_gateway {
        handle
            .toggle_managed_gateway_tool(
                gateway_connector_id.unwrap_or(&req.server_name).to_string(),
                req.tool_name,
                req.enabled,
            )
            .await
    } else {
        handle
            .toggle_mcp_tool(req.server_name, req.tool_name, req.enabled)
            .await
    }
    .map_err(|e| crate::acp_error::internal_error(crate::sampling::error::acp_error_text(&e)))?;

    to_ext_response(Ok(McpToggleResponse { ok: true }))
}

// ── mcp/upsert handler ──────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct McpUpsertRequest {
    session_id: String,
    server_name: String,
    #[serde(flatten)]
    config: crate::util::config::McpServerConfig,
}

async fn handle_upsert(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    let req = parse_params::<McpUpsertRequest>(args)?;
    let acp_id = acp::SessionId::new(req.session_id.clone());

    // Resolve the session BEFORE the policy check and persist: a dead session id must fail
    // without a config write.
    let handle = agent
        .get_session_handle(&acp_id)
        .ok_or_else(|| crate::acp_error::invalid_params("session not found"))?;

    // Build the ACP server config before persisting so a refused upsert
    // leaves no state behind.
    let server_config = req
        .config
        .to_acp_mcp_server(&req.server_name)
        .ok_or_else(|| {
            // `to_acp_mcp_server` is `None` for a disabled config or one whose
            // setup is unresolved; name the actual cause.
            let detail = if req.config.enabled {
                "server config requires setup"
            } else {
                "server config is disabled"
            };
            crate::acp_error::invalid_params(detail)
        })?;

    // Policy check BEFORE persist and live spawn: /mcps Add/Edit is a spawn path, so a denied
    // server must fail closed exactly like the setup/toggle siblings.
    let allowlist = &fuigo_workspace::permission::resolution::managed_settings().mcp_allowlist;
    upsert_gate_then_persist(allowlist, &server_config, || {
        crate::util::config::save_mcp_server_config(&req.server_name, &req.config)
    })
    .await
    .map_err(crate::acp_error::invalid_params)?
    .map_err(|e| crate::acp_error::internal_error(e.to_string()))?;

    // Reuse the toggle path: enable=true with the built config.
    handle
        .toggle_mcp_server(req.server_name, true, Some(server_config))
        .await
        .map_err(|e| {
            crate::acp_error::internal_error(crate::sampling::error::acp_error_text(&e))
        })?;

    to_ext_response(Ok(McpToggleResponse { ok: true }))
}

// ── mcp/delete handler ──────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct McpDeleteRequest {
    session_id: String,
    server_name: String,
}

async fn handle_delete(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    let req = parse_params::<McpDeleteRequest>(args)?;
    let acp_id = acp::SessionId::new(req.session_id.clone());

    // Verify the server exists in local config (not managed).
    let existed = crate::util::config::delete_mcp_server_config(&req.server_name)
        .await
        .map_err(|e| crate::acp_error::internal_error(e.to_string()))?;

    if !existed {
        return Err(crate::acp_error::invalid_params(format!(
            "server '{}' not found in config.toml (only locally-configured servers can be deleted)",
            req.server_name
        )));
    }

    // Live teardown: disable the server in the running session.
    let handle = agent
        .get_session_handle(&acp_id)
        .ok_or_else(|| crate::acp_error::invalid_params("session not found"))?;

    handle
        .toggle_mcp_server(req.server_name.clone(), false, None)
        .await
        .map_err(|e| {
            crate::acp_error::internal_error(crate::sampling::error::acp_error_text(&e))
        })?;

    // The toggle path spawns a task that adds the server to `disabled_mcp_servers`
    // Clear the user list only; leave any project-level disable in place
    let _ = crate::util::config::save_user_mcp_server_enabled(&req.server_name, true).await;

    to_ext_response(Ok(McpToggleResponse { ok: true }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The emit-only reverse method (`fuigo/mcp/sdk_call`) shares the `fuigo/mcp/` prefix.
    /// `mvp_agent`'s dispatcher therefore routes an inbound copy of it to this module's `handle`.
    /// It must NOT collide with any forward route, so it has no `McpRoute`.
    /// `handle` then returns `method_not_found` instead of misrouting a stray inbound reverse call to `handle_call`.
    #[test]
    fn inbound_sdk_call_has_no_forward_route() {
        assert!(
            wire::MCP_SDK_CALL.starts_with(mcp_methods::PREFIX),
            "reverse method must share the prefix so it reaches handle()"
        );
        assert_eq!(
            route_mcp_method(wire::MCP_SDK_CALL),
            None,
            "inbound fuigo/mcp/sdk_call must not resolve to a forward handler"
        );
        // Sanity: the forward sibling on the same prefix DOES route.
        assert_eq!(route_mcp_method(wire::MCP_CALL), Some(McpRoute::Call));
    }

    fn gateway_tool(
        connector_id: &str,
        connector_name: &str,
        tool_id: &str,
        tool_name: &str,
        call_id: &str,
        description: &str,
    ) -> crate::session::managed_mcp::GatewayTool {
        crate::session::managed_mcp::GatewayTool {
            connector_id: connector_id.into(),
            connector_name: connector_name.into(),
            tool_id: tool_id.into(),
            tool_name: tool_name.into(),
            call_id: call_id.into(),
            description: description.into(),
            json_schema: serde_json::json!({"type": "object"}),
        }
    }

    /// **Pattern-regression test, not an end-to-end `handle_list` test.**
    ///
    /// `handle_list` takes an `&MvpAgent`, which has no lightweight test constructor.
    /// Spinning up a fake agent here would be a much larger refactor than this test warrants.
    /// Instead this test mirrors the production structure with stand-in futures and asserts the two latency invariants `handle_list` guarantees.
    /// The mirrored structure: resolve the session handle synchronously, then `tokio::join!` a managed-fetch arm with a session-state arm.
    /// The session-state arm conditionally awaits `retry_auth_required_servers` and then `build_mcp_status`.
    ///
    /// 1. The two `tokio::join!` arms, the gateway catalog fetch and the session-state branch, are polled concurrently.
    ///    Total wall-time is therefore about the max of the two arms rather than their sum.
    /// 2. `retry_auth_required_servers` is gated on `cache=false`.
    ///    Cached opens skip it entirely, removing ~500ms of OAuth retry overhead when multiple OAuth servers are configured.
    ///
    /// If a future refactor of `handle_list` awaits the arms sequentially or runs the auth retry on cache=true, this test will *not* fail.
    /// It only guards the pattern; the real behavioural guard is reading the diff against the structure documented here.
    #[tokio::test(start_paused = true)]
    async fn handle_list_parallel_join_pattern_regression() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use tokio::time::{Duration, Instant};

        async fn run(cache: bool) -> (Duration, bool, usize) {
            let auth_retried = Arc::new(AtomicBool::new(false));
            let max_concurrent = Arc::new(AtomicUsize::new(0));
            let in_flight = Arc::new(AtomicUsize::new(0));

            let bump = {
                let max_concurrent = Arc::clone(&max_concurrent);
                let in_flight = Arc::clone(&in_flight);
                move || {
                    let n = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    max_concurrent.fetch_max(n, Ordering::SeqCst);
                }
            };
            let drop_ = {
                let in_flight = Arc::clone(&in_flight);
                move || {
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                }
            };

            // Stand-in for `agent.get_managed_mcp_gateway_tool_catalog()` (~1-2s proxy fetch).
            let managed_fut = {
                let bump = bump.clone();
                let drop_ = drop_.clone();
                async move {
                    bump();
                    tokio::time::sleep(Duration::from_millis(1500)).await;
                    drop_();
                }
            };

            // Stand-in for the session-state branch: conditional auth retry followed by `build_mcp_status`
            // Mirrors the closure in `handle_list`
            let session_fut = {
                let auth_retried = Arc::clone(&auth_retried);
                let bump = bump.clone();
                let drop_ = drop_.clone();
                async move {
                    bump();
                    if !cache {
                        auth_retried.store(true, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    // build_mcp_status is cheap (state-mutex inspect).
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    drop_();
                }
            };

            let start = Instant::now();
            tokio::join!(managed_fut, session_fut);
            (
                start.elapsed(),
                auth_retried.load(Ordering::SeqCst),
                max_concurrent.load(Ordering::SeqCst),
            )
        }

        // cache=true: no auth retry; the total is about the managed fetch alone
        let (cached_elapsed, cached_auth, cached_overlap) = run(true).await;
        assert!(!cached_auth, "auth retry must be skipped on cache=true");
        assert_eq!(cached_overlap, 2, "futures must run concurrently");
        assert!(
            cached_elapsed < Duration::from_millis(1600),
            "cached handle_list should finish in ~1.5s, got {:?}",
            cached_elapsed
        );

        // cache=false: the auth retry runs, but still concurrent with the managed fetch
        // The total is about max(1500, 500+50), roughly 1500ms, not 2050ms
        let (refresh_elapsed, refresh_auth, refresh_overlap) = run(false).await;
        assert!(refresh_auth, "auth retry must run on cache=false");
        assert_eq!(refresh_overlap, 2, "futures must run concurrently");
        assert!(
            refresh_elapsed < Duration::from_millis(1600),
            "refresh handle_list should still finish in ~1.5s (parallel), got {:?}",
            refresh_elapsed
        );
    }

    #[test]
    fn test_mcp_list_response_serialization() {
        let resp = McpListResponse {
            servers: vec![
                McpServerEntry {
                    name: "linear".to_string(),
                    icons: Vec::new(),
                    display_name: None,
                    source: McpServerSource::Local,
                    config: McpServerConfig::Http {
                        url: "https://mcp.linear.app".to_string(),
                        scope: Some("team".to_string()),
                        scope_id: Some("team-uuid-123".to_string()),
                        scope_name: Some("Fuigo CLI".to_string()),
                    },
                    source_label: None,
                    setup: None,
                    setup_values: None,
                    session: None,
                },
                McpServerEntry {
                    name: "filesystem".to_string(),
                    icons: Vec::new(),
                    display_name: None,
                    source: McpServerSource::Local,
                    source_label: None,
                    setup: None,
                    setup_values: None,
                    config: McpServerConfig::Stdio {
                        command: "/usr/bin/mcp-filesystem".into(),
                        args: vec!["--root".to_string(), "/home".to_string()],
                        env: vec![],
                    },
                    session: Some(McpServerSessionState {
                        enabled: true,
                        status: Some(McpSessionStatus::Ready),
                        auth_required: false,
                        setup_required: false,
                        tools: vec![McpToolEntry {
                            name: "read_file".to_string(),
                            icons: Vec::new(),
                            display_name: None,
                            description: Some("Read a file".to_string()),
                            meta: None,
                            enabled: true,
                        }],
                        blocked_reason: None,
                    }),
                },
            ],
        };
        let json = serde_json::to_value(&resp).unwrap();
        // [0] local HTTP
        assert_eq!(json["servers"][0]["source"], "local");
        assert_eq!(json["servers"][0]["type"], "http");
        assert_eq!(json["servers"][0]["url"], "https://mcp.linear.app");
        assert_eq!(json["servers"][0]["scope"], "team");
        assert_eq!(json["servers"][0]["scopeId"], "team-uuid-123");
        assert_eq!(json["servers"][0]["scopeName"], "Fuigo CLI");
        assert!(json["servers"][0].get("session").is_none());
        // Managed gateway connectors are not serialized as local transports.
        let gateway = serde_json::to_value(McpServerEntry {
            name: managed_gateway_entry_name("linear"),
            icons: Vec::new(),
            display_name: Some("linear".to_string()),
            source: McpServerSource::Managed,
            source_label: None,
            setup: None,
            setup_values: None,
            config: McpServerConfig::ManagedGateway,
            session: Some(McpServerSessionState {
                enabled: true,
                status: Some(McpSessionStatus::Ready),
                tools: vec![],
                auth_required: false,
                setup_required: false,
                blocked_reason: None,
            }),
        })
        .unwrap();
        assert_eq!(gateway["name"], "managed_gateway:linear");
        assert_eq!(gateway["displayName"], "linear");
        assert_eq!(gateway["type"], "managedGateway");
        assert!(gateway.get("command").is_none());
        assert!(gateway.get("url").is_none());
        // [1] local Stdio
        assert_eq!(json["servers"][1]["source"], "local");
        assert_eq!(json["servers"][1]["type"], "stdio");
        assert_eq!(json["servers"][1]["command"], "/usr/bin/mcp-filesystem");
        assert_eq!(
            json["servers"][1]["args"],
            serde_json::json!(["--root", "/home"])
        );
        assert!(json["servers"][1].get("url").is_none());
        assert_eq!(json["servers"][1]["session"]["enabled"], true);
        assert_eq!(json["servers"][1]["session"]["status"], "ready");
        assert_eq!(
            json["servers"][1]["session"]["tools"][0]["name"],
            "read_file"
        );
    }

    #[test]
    fn test_mcp_list_icons_serialization() {
        let entry = McpServerEntry {
            name: "custom".to_string(),
            display_name: Some("Custom".to_string()),
            icons: vec![fuigo_mcp::servers::McpIcon {
                src: "https://example.com/icon.png".to_string(),
                mime_type: Some("image/png".to_string()),
                sizes: Some(vec!["48x48".to_string()]),
                theme: Some(fuigo_mcp::servers::McpIconTheme::Dark),
            }],
            source: McpServerSource::Local,
            source_label: None,
            setup: None,
            setup_values: None,
            config: McpServerConfig::Http {
                url: "https://example.com/mcp".to_string(),
                scope: None,
                scope_id: None,
                scope_name: None,
            },
            session: Some(McpServerSessionState {
                enabled: true,
                status: Some(McpSessionStatus::Ready),
                tools: vec![McpToolEntry {
                    name: "ping".to_string(),
                    display_name: None,
                    description: None,
                    meta: None,
                    icons: vec![fuigo_mcp::servers::McpIcon {
                        src: "data:image/png;base64,aaa".to_string(),
                        mime_type: None,
                        sizes: None,
                        theme: None,
                    }],
                    enabled: true,
                }],
                auth_required: false,
                setup_required: false,
                blocked_reason: None,
            }),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["icons"][0]["src"], "https://example.com/icon.png");
        assert_eq!(json["icons"][0]["mimeType"], "image/png");
        assert_eq!(json["icons"][0]["sizes"][0], "48x48");
        assert_eq!(json["icons"][0]["theme"], "dark");
        assert_eq!(
            json["session"]["tools"][0]["icons"][0]["src"],
            "data:image/png;base64,aaa"
        );
    }

    #[test]
    fn gateway_catalog_groups_by_connector_name_and_exact_tool_names() {
        let catalog = crate::session::managed_mcp::GatewayToolCatalog {
            tools: vec![
                gateway_tool(
                    "linear",
                    "Linear",
                    "list_issues",
                    "List issues",
                    "linear.list_issues",
                    "List Linear issues",
                ),
                gateway_tool(
                    "linear",
                    "Linear",
                    "create_issue",
                    "Create issue",
                    "linear.create_issue",
                    "Create a Linear issue",
                ),
                gateway_tool(
                    "slack",
                    "Slack",
                    "search",
                    "Search",
                    "slack.search",
                    "Search Slack",
                ),
            ],
            total_tools: 3,
            connectors_needing_reauth: vec!["slack".into()],
        };
        let servers =
            build_mcp_catalog_with_gateway_tools(&[], Some(&catalog), &Default::default());

        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].name, "managed_gateway:linear");
        assert_eq!(servers[0].display_name.as_deref(), Some("Linear"));
        assert_eq!(servers[0].source, McpServerSource::Managed);
        assert!(matches!(servers[0].config, McpServerConfig::ManagedGateway));
        let linear_session = servers[0].session.as_ref().unwrap();
        assert_eq!(linear_session.status, Some(McpSessionStatus::Ready));
        assert!(!linear_session.auth_required);
        let linear_names: Vec<&str> = linear_session
            .tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect();
        assert_eq!(
            linear_names,
            vec!["linear__list_issues", "linear__create_issue"]
        );

        assert_eq!(servers[1].name, "managed_gateway:slack");
        assert_eq!(servers[1].display_name.as_deref(), Some("Slack"));
        let slack_session = servers[1].session.as_ref().unwrap();
        assert!(slack_session.auth_required);
        assert!(slack_session.status.is_none());
        assert_eq!(slack_session.tools[0].name, "slack__search");
        assert_eq!(
            slack_session.tools[0].display_name.as_deref(),
            Some("Search")
        );
    }

    #[test]
    fn gateway_catalog_preserves_local_name_collision() {
        let catalog = crate::session::managed_mcp::GatewayToolCatalog {
            tools: vec![gateway_tool(
                "linear",
                "Linear",
                "list_issues",
                "List issues",
                "linear.list_issues",
                "List Linear issues",
            )],
            total_tools: 1,
            connectors_needing_reauth: vec![],
        };
        let local = acp::McpServer::Stdio(
            acp::McpServerStdio::new("linear", "/usr/bin/local-linear")
                .args(vec![])
                .env(vec![]),
        );

        let servers =
            build_mcp_catalog_with_gateway_tools(&[local], Some(&catalog), &Default::default());

        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].name, "managed_gateway:linear");
        assert_eq!(servers[0].display_name.as_deref(), Some("Linear"));
        assert_eq!(servers[0].source, McpServerSource::Managed);
        assert_eq!(servers[1].name, "linear");
        assert_eq!(servers[1].display_name, None);
        assert_eq!(servers[1].source, McpServerSource::Local);
        assert!(matches!(servers[1].config, McpServerConfig::Stdio { .. }));
    }

    #[test]
    fn gateway_toggle_classification_requires_managed_gateway_entry_id() {
        assert_eq!(
            managed_gateway_connector_id("managed_gateway:linear"),
            Some("linear")
        );
        assert_eq!(managed_gateway_connector_id("linear"), None);
    }

    #[test]
    fn disabled_local_rows_keep_non_gateway_placeholder_config() {
        let entry = disabled_server_placeholder_entry("local_slack");
        assert_eq!(entry.source, McpServerSource::Local);
        assert!(matches!(entry.config, McpServerConfig::Stdio { .. }));
    }

    #[test]
    fn fuigo_com_local_name_is_not_managed_in_catalog() {
        let local = acp::McpServer::Http(
            acp::McpServerHttp::new("fuigo_com_slack", "https://mcp.example.test/sse")
                .headers(vec![]),
        );
        let servers = build_mcp_catalog_with_gateway_tools(&[local], None, &Default::default());
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "fuigo_com_slack");
        assert_eq!(servers[0].source, McpServerSource::Local);
        assert!(matches!(servers[0].config, McpServerConfig::Http { .. }));

        let placeholder = disabled_server_placeholder_entry("fuigo_com_slack");
        assert_eq!(placeholder.source, McpServerSource::Local);
        assert!(matches!(placeholder.config, McpServerConfig::Stdio { .. }));
    }

    #[test]
    fn gateway_catalog_honors_disabled_connectors_and_tools() {
        let catalog = crate::session::managed_mcp::GatewayToolCatalog {
            tools: vec![
                gateway_tool(
                    "linear",
                    "Linear",
                    "list_issues",
                    "List issues",
                    "linear.list_issues",
                    "List Linear issues",
                ),
                gateway_tool(
                    "linear",
                    "Linear",
                    "create_issue",
                    "Create issue",
                    "linear.create_issue",
                    "Create a Linear issue",
                ),
            ],
            total_tools: 2,
            connectors_needing_reauth: vec![],
        };
        let disabled: HashMap<String, HashSet<String>> = HashMap::from([
            (
                crate::util::config::MANAGED_GATEWAY_DISABLED_CONNECTORS_KEY.to_string(),
                HashSet::from(["linear".to_string()]),
            ),
            (
                "linear".to_string(),
                HashSet::from(["linear__create_issue".to_string()]),
            ),
        ]);
        let servers = build_mcp_catalog_with_gateway_tools(&[], Some(&catalog), &disabled);
        let session = servers[0].session.as_ref().unwrap();
        assert!(!session.enabled);
        assert!(session.status.is_none());
        assert!(session.tools[0].enabled);
        assert!(!session.tools[1].enabled);
    }

    #[test]
    fn test_mcp_call_response_serialization() {
        let resp = McpCallResponse {
            content: vec![McpContentBlock {
                kind: "text".to_string(),
                text: "Created issue LIN-123".to_string(),
            }],
            is_error: Some(false),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["content"][0]["type"], "text");
        assert_eq!(json["content"][0]["text"], "Created issue LIN-123");
        assert_eq!(json["isError"], false);
    }

    #[test]
    fn test_mcp_list_setup_required_serialization() {
        let entry = McpServerEntry {
            name: "acme".to_string(),
            icons: Vec::new(),
            display_name: None,
            source: McpServerSource::Local,
            source_label: Some("plugin: acme".to_string()),
            setup: Some(crate::util::config::McpSetupConfig {
                fields: vec![crate::util::config::McpSetupField {
                    id: "site".to_string(),
                    label: "Site".to_string(),
                    field_type: crate::util::config::McpSetupFieldType::Select,
                    required: true,
                    default: Some("us1".to_string()),
                    options: vec![crate::util::config::McpSetupOption {
                        label: "US5".to_string(),
                        value: "us5".to_string(),
                    }],
                }],
                variables: HashMap::new(),
            }),
            setup_values: Some(HashMap::from([("site".to_string(), "us5".to_string())])),
            config: McpServerConfig::Http {
                url: String::new(),
                scope: None,
                scope_id: None,
                scope_name: None,
            },
            session: Some(McpServerSessionState {
                enabled: true,
                status: Some(McpSessionStatus::SetupRequired),
                tools: vec![],
                auth_required: false,
                setup_required: true,
                blocked_reason: None,
            }),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["session"]["status"], "setuprequired");
        assert_eq!(json["session"]["setupRequired"], true);
        assert_eq!(json["setup"]["fields"][0]["id"], "site");
        assert_eq!(json["setupValues"]["site"], "us5");
    }

    #[test]
    fn test_mcp_auth_trigger_response_success_no_error_field() {
        let resp = McpAuthTriggerResponse {
            status: "authenticated",
            setup: None,
            error: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "authenticated");
        assert!(
            json.get("error").is_none(),
            "error field must be omitted on success: {json}"
        );
    }

    #[test]
    fn test_mcp_auth_trigger_response_failure_carries_error() {
        let resp = McpAuthTriggerResponse {
            status: "failed",
            setup: None,
            error: Some("MCP server 'linear' does not use OAuth".to_string()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "failed");
        assert_eq!(
            json["error"], "MCP server 'linear' does not use OAuth",
            "failure must carry the descriptive error verbatim: {json}"
        );
    }

    #[test]
    fn test_mcp_auth_trigger_response_failure_omits_error_when_none() {
        let resp = McpAuthTriggerResponse {
            status: "failed",
            setup: None,
            error: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "failed");
        assert!(json.get("error").is_none());
    }

    #[test]
    fn test_disabled_session_state_serialization() {
        let entry = McpServerEntry {
            name: "slack".to_string(),
            icons: Vec::new(),
            display_name: None,
            source: McpServerSource::Local,
            source_label: None,
            setup: None,
            setup_values: None,
            config: McpServerConfig::Http {
                url: "https://mcp.slack.com".to_string(),
                scope: Some("user".to_string()),
                scope_id: Some("user-uuid-456".to_string()),
                scope_name: None,
            },
            session: Some(McpServerSessionState {
                enabled: false,
                status: None,
                tools: vec![],
                auth_required: false,
                setup_required: false,
                blocked_reason: None,
            }),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["type"], "http");
        assert_eq!(json["scope"], "user");
        assert_eq!(json["scopeId"], "user-uuid-456");
        assert_eq!(json["session"]["enabled"], false);
        assert!(json["session"].get("status").is_none());
        assert!(json["session"].get("tools").is_none());
    }

    /// Deny policy for `https://evil.corp/*` pinned by a full-path source.
    fn deny_evil_corp() -> fuigo_workspace::permission::resolution::McpServerAllowlist {
        use fuigo_workspace::permission::resolution::{AllowedMcpServer, McpServerAllowlist};
        McpServerAllowlist::new(
            vec![],
            vec![AllowedMcpServer::Http {
                url_pattern: "https://evil.corp/*".into(),
            }],
            Some(std::path::PathBuf::from("/etc/fuigo/managed_config.toml")),
        )
    }

    /// The shared enable/upsert gate refuses a policy-blocked server with the org-policy message and passes an allowed one.
    #[test]
    fn policy_enable_error_fails_closed_for_blocked_server() {
        let allowlist = deny_evil_corp();
        let denied = acp::McpServer::Http(
            acp::McpServerHttp::new("exfil", "https://evil.corp/mcp").headers(vec![]),
        );
        let message = policy_enable_error(&allowlist, &denied)
            .expect("denied server must fail closed before spawn");
        assert_eq!(
            message,
            "The server exfil is blocked by an organization policy (managed_config.toml)."
        );
        assert!(
            !message.contains("/etc/fuigo/"),
            "user-facing refusal must name the policy file only, got: {message}"
        );

        let allowed = acp::McpServer::Http(
            acp::McpServerHttp::new("ok", "https://ok.example.com/mcp").headers(vec![]),
        );
        assert_eq!(policy_enable_error(&allowlist, &allowed), None);
    }

    /// `mcp/list` carries the verdict only for the definitions the policy drops.
    #[test]
    fn list_blocked_reasons_annotates_only_policy_dropped_definitions() {
        let allowlist = deny_evil_corp();
        let denied = acp::McpServer::Http(
            acp::McpServerHttp::new("exfil", "https://evil.corp/mcp").headers(vec![]),
        );
        let allowed = acp::McpServer::Http(
            acp::McpServerHttp::new("ok", "https://ok.example.com/mcp").headers(vec![]),
        );
        let blocked = list_blocked_reasons([("exfil", &denied), ("ok", &allowed)], &allowlist);
        assert_eq!(
            blocked.get("exfil").map(String::as_str),
            Some("The server exfil is blocked by an organization policy (managed_config.toml).")
        );
        assert!(!blocked.contains_key("ok"));
    }

    /// The upsert seam: the policy gate runs BEFORE persist — a refused upsert leaves no config write behind.
    #[tokio::test]
    async fn upsert_gate_refuses_before_persist() {
        let allowlist = deny_evil_corp();
        let persisted = std::cell::Cell::new(false);

        let denied = acp::McpServer::Http(
            acp::McpServerHttp::new("exfil", "https://evil.corp/mcp").headers(vec![]),
        );
        let err = upsert_gate_then_persist(&allowlist, &denied, || {
            persisted.set(true);
            std::future::ready(())
        })
        .await
        .expect_err("denied upsert must be refused");
        assert!(
            err.contains("blocked by an organization policy") && err.contains("managed_config.toml"),
            "got: {err}"
        );
        assert!(
            !persisted.get(),
            "refused upsert must not reach the config write"
        );

        let allowed = acp::McpServer::Http(
            acp::McpServerHttp::new("ok", "https://ok.example.com/mcp").headers(vec![]),
        );
        upsert_gate_then_persist(&allowlist, &allowed, || {
            persisted.set(true);
            std::future::ready(())
        })
        .await
        .expect("allowed upsert persists");
        assert!(persisted.get());
    }

    /// The toggle seam: a merge refusal rolls back the just-persisted enable; an allowed outcome keeps the write.
    #[tokio::test]
    async fn toggle_merge_refusal_rolls_back_enable() {
        use crate::session::managed_mcp::{McpDisabledReason, McpServerWithPolicy};

        let server = || {
            acp::McpServer::Http(
                acp::McpServerHttp::new("corp", "https://denied.corp.com/mcp").headers(vec![]),
            )
        };
        let rolled_back = std::cell::Cell::new(false);
        let rollback = || {
            rolled_back.set(true);
            std::future::ready(())
        };

        // Blocked verdict: rollback, org-policy message (file name only).
        let blocked = McpServerWithPolicy {
            server: server(),
            disabled_reason: Some(McpDisabledReason::Denylist {
                source: std::path::PathBuf::from("/etc/fuigo/managed_config.toml"),
            }),
        };
        let err = confirm_enabled_or_rollback("corp", Some(blocked), rollback)
            .await
            .expect_err("blocked merge outcome must refuse");
        let GatedEnableError::PolicyRefused(message) = err else {
            panic!("blocked merge outcome must refuse as PolicyRefused, got {err:?}");
        };
        assert!(
            message.contains("blocked by an organization policy")
                && message.contains("managed_config.toml")
                && !message.contains("/etc/fuigo/"),
            "got: {message}"
        );
        assert!(rolled_back.get(), "refusal must roll back the enable write");

        // Vanished from the merge: also rolls back.
        rolled_back.set(false);
        let err = confirm_enabled_or_rollback("corp", None, rollback)
            .await
            .expect_err("vanished server must refuse");
        assert!(
            matches!(err, GatedEnableError::NotFound),
            "vanished server must refuse as NotFound, got {err:?}"
        );
        assert!(rolled_back.get());

        // Allowed: the write stands and the live config comes back.
        rolled_back.set(false);
        let confirmed = confirm_enabled_or_rollback(
            "corp",
            Some(McpServerWithPolicy {
                server: server(),
                disabled_reason: None,
            }),
            rollback,
        )
        .await
        .expect("allowed server enables");
        assert_eq!(
            crate::session::mcp_servers::mcp_server_name(&confirmed),
            "corp"
        );
        assert!(!rolled_back.get(), "allowed enable must keep the write");
    }

    /// What the [`run_gated_enable`] harness recorded, in call order.
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum GatedStep {
        Persist,
        Rollback,
        Toggle,
    }

    /// Drive the gated-enable seam with scripted outcomes, recording the persist/rollback/toggle order.
    async fn drive_gated_enable(
        probe_result: Result<(), GatedEnableError>,
        merge_result: Result<Option<crate::session::managed_mcp::McpServerWithPolicy>, String>,
        toggle_result: Result<(), String>,
    ) -> (Result<(), GatedEnableError>, Vec<GatedStep>) {
        let steps = std::cell::RefCell::new(Vec::new());
        let result = run_gated_enable(
            "corp",
            || std::future::ready(probe_result),
            || {
                steps.borrow_mut().push(GatedStep::Persist);
                std::future::ready(Ok::<u8, String>(7))
            },
            |_paths: u8| {
                steps.borrow_mut().push(GatedStep::Rollback);
                std::future::ready(())
            },
            || std::future::ready(merge_result),
            |_server| {
                steps.borrow_mut().push(GatedStep::Toggle);
                std::future::ready(toggle_result)
            },
        )
        .await;
        (result, steps.into_inner())
    }

    fn merged_allowed() -> Option<crate::session::managed_mcp::McpServerWithPolicy> {
        Some(crate::session::managed_mcp::McpServerWithPolicy {
            server: acp::McpServer::Http(
                acp::McpServerHttp::new("corp", "https://ok.example.com/mcp").headers(vec![]),
            ),
            disabled_reason: None,
        })
    }

    /// Probe leg: a probe refusal returns before the enable write; a clean run persists then toggles.
    #[tokio::test]
    async fn gated_enable_seam_gates_before_the_write() {
        let (result, steps) = drive_gated_enable(
            Err(GatedEnableError::PolicyRefused("blocked".into())),
            Ok(merged_allowed()),
            Ok(()),
        )
        .await;
        assert!(matches!(result, Err(GatedEnableError::PolicyRefused(_))));
        assert!(
            steps.is_empty(),
            "a probe refusal must precede any write, got {steps:?}"
        );

        let (result, steps) = drive_gated_enable(Ok(()), Ok(merged_allowed()), Ok(())).await;
        assert!(result.is_ok());
        assert_eq!(
            steps,
            vec![GatedStep::Persist, GatedStep::Toggle],
            "a clean enable must keep the write"
        );
    }

    /// Rollback legs: every failure past the enable write must roll it back (dropping `rollback` fails here).
    #[tokio::test]
    async fn gated_enable_seam_rolls_back_every_failure_past_the_write() {
        let (result, steps) =
            drive_gated_enable(Ok(()), Err("merge task failed".into()), Ok(())).await;
        assert!(matches!(result, Err(GatedEnableError::TaskFailed(_))));
        assert_eq!(steps, vec![GatedStep::Persist, GatedStep::Rollback]);

        let (result, steps) = drive_gated_enable(Ok(()), Ok(None), Ok(())).await;
        assert!(matches!(result, Err(GatedEnableError::NotFound)));
        assert_eq!(steps, vec![GatedStep::Persist, GatedStep::Rollback]);

        let (result, steps) =
            drive_gated_enable(Ok(()), Ok(merged_allowed()), Err("spawn failed".into())).await;
        assert!(matches!(result, Err(GatedEnableError::ToggleFailed(_))));
        assert_eq!(
            steps,
            vec![GatedStep::Persist, GatedStep::Toggle, GatedStep::Rollback]
        );
    }

    /// The `mcp/list` wire shape: `session.blockedReason` is additive and absent when there is no verdict.
    #[test]
    fn session_state_serializes_blocked_reason_only_when_present() {
        let state = McpServerSessionState {
            enabled: false,
            status: None,
            tools: vec![],
            auth_required: false,
            setup_required: false,
            blocked_reason: Some("The server x is blocked by an organization policy (managed_config.toml).".into()),
        };
        let json = serde_json::to_value(&state).unwrap();
        assert_eq!(
            json["blockedReason"].as_str(),
            Some("The server x is blocked by an organization policy (managed_config.toml).")
        );
        let clean = McpServerSessionState {
            blocked_reason: None,
            ..state
        };
        assert!(serde_json::to_value(&clean).unwrap().get("blockedReason").is_none());
    }
}
