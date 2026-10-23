//! Materialize `AgentDefinition.mcp_servers` and overlay them onto a disk/client merge.
//!
//! The servers an agent definition declares (`mcpServers` in agent.md) win over the disk/client merge by name,
//! for the session's main seat as well as for a child. A hot reload (project config, plugin reload) re-merges disk
//! and client servers, so the overlay is applied again on top of every re-merge instead of being lost to it.

use std::collections::HashSet;
use std::path::Path;

use agent_client_protocol as acp;
use fuigo_agent::config::{AgentDefinition, McpServerRef};
use fuigo_config::key_naming::NoticeScope;
use fuigo_tools::types::compat::CompatConfig;

use crate::session::mcp_servers::mcp_server_name;

/// Inputs of a disk rematerialize: the merge a reload would build, with the seat's overlay on top.
pub(crate) struct RematerializeParams<'a> {
    pub initial_client_mcp_servers: crate::session::managed_mcp::ClientMcpSeed,
    /// The seat's cwd: where project config and folder trust are read.
    pub cwd: &'a Path,
    /// The parent project's cwd for the kill switch and managed policy when the seat is a child worktree.
    /// `None` uses `cwd`.
    pub parent_cwd: Option<&'a Path>,
    pub plugin_registry: Option<&'a fuigo_agent::plugins::PluginRegistry>,
    pub compat: &'a CompatConfig,
    pub definition: &'a AgentDefinition,
}

/// The servers `definition` declares, after plugin-agent ignore, folder trust, the inline/named parse, and then the
/// `enabled = false` kill switch and managed policy.
///
/// `named_lookup` is the merge a named reference is resolved against (the parent's, for a child).
/// Servers the kill switch or policy drops never leave this function, so an overlay cannot append them again.
/// Refusals of `FUIGO_API_KEY` references inside an inline definition are recorded in `notices`.
pub(crate) fn materialize_agent_mcp_servers(
    definition: &AgentDefinition,
    named_lookup: &[acp::McpServer],
    cwd: &Path,
    notices: NoticeScope,
) -> Vec<acp::McpServer> {
    let servers = if definition.mcp_servers.is_empty() {
        Vec::new()
    } else if definition.plugin_name.is_some() {
        tracing::warn!(
            agent = %definition.name,
            plugin = ?definition.plugin_name,
            "ignoring mcpServers on plugin agent (not supported for security)"
        );
        Vec::new()
    } else if !crate::agent::folder_trust::agent_inline_hooks_allowed(definition.scope, || {
        crate::agent::folder_trust::project_scope_allowed(cwd)
    }) {
        tracing::warn!(
            agent = %definition.name,
            "ignoring mcpServers on untrusted project agent (folder not trusted; re-run with --trust)"
        );
        Vec::new()
    } else {
        definition
            .mcp_servers
            .iter()
            .filter_map(|entry| match entry {
                McpServerRef::Named(name) => named_lookup
                    .iter()
                    .find(|s| mcp_server_name(s) == name)
                    .cloned()
                    .or_else(|| {
                        tracing::warn!(agent = %definition.name, server = name, "mcpServers: named ref not found in parent");
                        None
                    }),
                McpServerRef::Inline { name, config } => {
                    notices.run(|| inline_agent_mcp_server(&definition.name, name, config))
                }
            })
            .collect()
    };
    crate::session::managed_mcp::filter_policy_blocked_agent_mcp(servers, cwd)
}

/// An MCP server an agent definition declares inline (`mcpServers: {name: {...}}`), as the session would spawn it.
///
/// Two shapes parse: the ACP wire form (`headers` / `env` as lists of `{name, value}`), and the `config.toml` map form
/// (`headers = { K = "v" }`, `env = { K = "v" }`) that agent.md YAML usually carries. A definition is a file a
/// repository (or any user) wrote, not a source that may name the saved API key, so every reference to the key is
/// removed from the server (P133); `None` when it cannot be parsed.
pub(crate) fn inline_agent_mcp_server(
    agent: &str,
    name: &str,
    config: &serde_json::Value,
) -> Option<acp::McpServer> {
    use serde::Deserialize;
    let origin = format!("defined inline by agent `{agent}`");
    let Some(obj) = config.as_object() else {
        tracing::warn!(agent = %agent, server = name, "mcpServers: inline config is not an object");
        return None;
    };
    let server = match parse_acp_mcp_object(name, obj) {
        Ok(server) => server,
        Err(acp_err) => {
            tracing::debug!(agent = %agent, server = name, error = %acp_err, "ACP wire format parse failed, trying map-keyed");
            match fuigo_config_types::McpServerConfig::deserialize(config) {
                Ok(cfg) => server_from_config(agent, name, &cfg)?,
                Err(e) => {
                    tracing::warn!(agent = %agent, server = name, error = %e, "mcpServers: inline config could not be parsed");
                    return None;
                }
            }
        }
    };
    crate::session::managed_mcp::refuse_saved_key_in_server(server, &origin)
}

fn parse_acp_mcp_object(
    name: &str,
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<acp::McpServer, serde_json::Error> {
    let mut flat = obj.clone();
    flat.insert(
        "name".to_owned(),
        serde_json::Value::String(name.to_owned()),
    );
    serde_json::from_value(serde_json::Value::Object(flat))
}

fn server_from_config(
    agent: &str,
    name: &str,
    cfg: &fuigo_config_types::McpServerConfig,
) -> Option<acp::McpServer> {
    let Some(mut server) = cfg.to_acp_mcp_server(name) else {
        if cfg.enabled {
            tracing::warn!(agent = %agent, server = name, "mcpServers: inline config dropped (setup block or empty url)");
        } else {
            tracing::debug!(agent = %agent, server = name, "mcpServers: skipping disabled inline server");
        }
        return None;
    };
    canonicalize_mcp_maps(&mut server);
    Some(server)
}

/// `env` and `headers` come from map iteration, so their order is fixed here; `args` order is not touched.
fn canonicalize_mcp_maps(server: &mut acp::McpServer) {
    match server {
        acp::McpServer::Stdio(stdio) => stdio
            .env
            .sort_by(|a, b| (&a.name, &a.value).cmp(&(&b.name, &b.value))),
        acp::McpServer::Http(acp::McpServerHttp { headers, .. })
        | acp::McpServer::Sse(acp::McpServerSse { headers, .. }) => {
            headers.sort_by(|a, b| (&a.name, &a.value).cmp(&(&b.name, &b.value)))
        }
        _ => {}
    }
}

/// Insert materialized agent.md servers by name so they win over the disk/client merge.
pub(crate) fn overlay_agent_mcp_servers(
    merged: &mut Vec<acp::McpServer>,
    overlay: Vec<acp::McpServer>,
) {
    for server in overlay {
        let name = mcp_server_name(&server);
        if let Some(slot) = merged
            .iter_mut()
            .find(|existing| mcp_server_name(existing) == name)
        {
            *slot = server;
        } else {
            merged.push(server);
        }
    }
}

/// Materialize against the current merge, then insert-wins by name. Returns the notices the materialize recorded.
pub(crate) fn apply_agent_mcp_overlay(
    merged: &mut Vec<acp::McpServer>,
    definition: &AgentDefinition,
    cwd: &Path,
) -> Vec<String> {
    let notices = NoticeScope::new();
    let overlay = materialize_agent_mcp_servers(definition, merged, cwd, notices);
    overlay_agent_mcp_servers(merged, overlay);
    notices.notes()
}

/// What a fork copies from the parent handle. A snapshot: a later seat switch on the parent does not rewrite a child
/// that already inherited.
pub(crate) fn mcp_servers_for_fork(
    parent: &crate::session::mcp_servers::AdmittedMcpServers,
) -> Vec<acp::McpServer> {
    parent.snapshot()
}

/// The merge a reload builds (disk, plugins and the client seed) with the seat's overlay on top.
/// Disk merge uses the seat `cwd`; the kill switch uses `parent_cwd` when the seat is a child.
pub(crate) fn rematerialize_with_agent_overlay(
    params: RematerializeParams<'_>,
) -> (Vec<acp::McpServer>, Vec<String>) {
    let policy_cwd = params.parent_cwd.unwrap_or(params.cwd);
    let mut merged = crate::session::managed_mcp::merge_managed_mcp_servers(
        params.initial_client_mcp_servers,
        params.cwd,
        params.plugin_registry,
        params.compat,
    );
    let notices = apply_agent_mcp_overlay(&mut merged, params.definition, policy_cwd);
    (merged, notices)
}

/// Rebuild: rematerialize disk/client + the new seat, then keep live names outside the previous overlay.
/// The disk/client layer is the actor's admitted seed, not the spawn-time list.
pub(crate) fn rematerialize_live_for_agent_seat(
    live: &[acp::McpServer],
    previous_mcp_servers: &[McpServerRef],
    params: RematerializeParams<'_>,
) -> (Vec<acp::McpServer>, Vec<String>) {
    let previous_names = agent_overlay_names(previous_mcp_servers);
    let (mut desired, notices) = rematerialize_with_agent_overlay(params);
    let mut desired_names: HashSet<String> = desired
        .iter()
        .map(|server| mcp_server_name(server).to_owned())
        .collect();
    for server in live {
        let name = mcp_server_name(server).to_owned();
        if desired_names.contains(&name) || previous_names.contains(&name) {
            continue;
        }
        desired.push(server.clone());
        desired_names.insert(name);
    }
    (desired, notices)
}

fn agent_overlay_names(mcp_servers: &[McpServerRef]) -> HashSet<String> {
    mcp_servers
        .iter()
        .map(mcp_server_ref_name)
        .map(str::to_owned)
        .collect()
}

fn mcp_server_ref_name(entry: &McpServerRef) -> &str {
    match entry {
        McpServerRef::Named(name) | McpServerRef::Inline { name, .. } => name,
    }
}

#[cfg(test)]
#[path = "agent_mcp_tests.rs"]
mod tests;
