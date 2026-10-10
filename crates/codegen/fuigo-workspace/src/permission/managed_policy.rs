//! Managed MCP + marketplace policy engine (P169; upstream 72a61251, 1.0.18/1.0.19).
//!
//! Policy comes from every layer [`fuigo_config::policy_sources`] reads: the `managed_config.toml` layers (Fuigo's own
//! managed-config endpoint writes the user one, P47), the `requirements.toml` layers and the Claude
//! `managed-settings.json`. Strictest wins: any deny wins, every restricted source must allow, a managed-only lockdown
//! needs a positive grant from a layer its owner accepts, and a source that could not be read locks everything down.
//!
//! Fuigo way (differs from upstream): every source binds every server and marketplace. Upstream later made the Claude
//! file "advisory" for natively defined servers; Fuigo has always enforced that file on everything (1.0.21) and keeps
//! doing so, which is the stricter reading.

use std::path::{Path, PathBuf};

use fuigo_config::policy_sources::{
    BoolPin, PolicyKey, PolicyLayerOwnership, PolicyPin, PolicySource, policy_array, policy_bool,
    policy_field, resolve_bool_pin,
};
use tracing::{info, warn};

use super::{
    AllowedMcpServer, ManagedSettings, MarketplaceAllowlist, McpServerAllowlist,
    locked_down_base, parse_managed_settings_base, warn_on_unmatchable_allow_url, warn_on_unmatchable_deny_url,
};

// ── MCP ────────────────────────────────────────────────────────────────────────────────────────

/// MCP policy across all sources: any deny wins; every restricted source must allow; managed-only requires a grant.
#[derive(Debug, Clone, Default)]
pub struct McpServerPolicy {
    pub sources: Vec<McpServerAllowlist>,
}

impl From<McpServerAllowlist> for McpServerPolicy {
    fn from(allowlist: McpServerAllowlist) -> Self {
        Self::single(allowlist)
    }
}

impl McpServerPolicy {
    /// A single-source policy (tests and callers that build one by hand).
    pub fn single(allowlist: McpServerAllowlist) -> Self {
        Self {
            sources: vec![allowlist],
        }
    }

    pub fn is_restricted(&self) -> bool {
        self.sources.iter().any(McpServerAllowlist::is_restricted)
    }

    /// Any source requires a positive grant (`allow_managed_mcp_servers_only`).
    pub fn managed_only(&self) -> bool {
        self.sources.iter().any(McpServerAllowlist::managed_only)
    }

    /// Any source is a full lockdown.
    pub fn is_lockdown(&self) -> bool {
        self.sources.iter().any(McpServerAllowlist::is_lockdown)
    }

    pub fn is_server_denied(&self, server: &agent_client_protocol::McpServer) -> bool {
        self.denying_source(server).is_some()
    }

    /// The source whose deny list matches `server`, if any.
    pub fn denying_source(
        &self,
        server: &agent_client_protocol::McpServer,
    ) -> Option<&McpServerAllowlist> {
        self.sources.iter().find(|s| s.is_server_denied(server))
    }

    /// An allow entry grants `server` from a layer a restriction owned by `restriction_ownership` accepts grants from.
    pub fn grants_exception(
        &self,
        server: &agent_client_protocol::McpServer,
        restriction_ownership: PolicyLayerOwnership,
    ) -> bool {
        self.sources.iter().any(|s| {
            restriction_ownership.accepts_grant_from(s.ownership()) && s.matches_allow_entry(server)
        })
    }

    /// The source blocking a non-denied server: an unsatisfied managed-only source first, else a restricted source
    /// that excludes the server (a lockdown excludes everything).
    pub fn blocking_allow_source(
        &self,
        server: &agent_client_protocol::McpServer,
    ) -> Option<&McpServerAllowlist> {
        self.sources
            .iter()
            .find(|s| s.managed_only() && !self.grants_exception(server, s.ownership()))
            .or_else(|| {
                self.sources
                    .iter()
                    .find(|s| !s.allows_ignoring_managed_only(server))
            })
    }

    /// Denied by no source and blocked by none.
    pub fn is_server_allowed(&self, server: &agent_client_protocol::McpServer) -> bool {
        matches!(self.verdict(server), McpVerdict::Allowed)
    }

    /// The verdict for `server`, attributed to the blocking source: deny first, then lockdown or missing grant.
    pub fn verdict(&self, server: &agent_client_protocol::McpServer) -> McpVerdict {
        if let Some(denying) = self.denying_source(server) {
            return McpVerdict::Blocked(McpBlockReason::Deny {
                source: denying.source_path.clone().unwrap_or_default(),
            });
        }
        if let Some(blocking) = self.blocking_allow_source(server) {
            let source = blocking.source_path.clone().unwrap_or_default();
            return McpVerdict::Blocked(if blocking.is_lockdown() {
                McpBlockReason::Lockdown { source }
            } else {
                McpBlockReason::NotGranted { source }
            });
        }
        McpVerdict::Allowed
    }

    /// The verdict for a server known only by its name: an in-process ACP SDK server (`_meta["fuigo/mcp/servers"]`,
    /// P169 Grok 4.7 #4) has no URL or command to judge. It is denied by a `serverName` deny entry, granted only by a
    /// `serverName` allow entry (from a layer a managed-only lock's owner accepts), and blocked by any lockdown.
    pub fn name_only_verdict(&self, name: &str) -> McpVerdict {
        if let Some(denying) = self.sources.iter().find(|s| s.is_name_denied(name)) {
            return McpVerdict::Blocked(McpBlockReason::Deny {
                source: denying.source_path.clone().unwrap_or_default(),
            });
        }
        let blocking = self
            .sources
            .iter()
            .find(|s| {
                s.managed_only()
                    && !self.sources.iter().any(|g| {
                        s.ownership().accepts_grant_from(g.ownership())
                            && g.matches_name_allow_entry(name)
                    })
            })
            .or_else(|| {
                self.sources
                    .iter()
                    .find(|s| !s.allows_name_ignoring_managed_only(name))
            });
        match blocking {
            Some(source) => {
                let path = source.source_path.clone().unwrap_or_default();
                McpVerdict::Blocked(if source.is_lockdown() {
                    McpBlockReason::Lockdown { source: path }
                } else {
                    McpBlockReason::NotGranted { source: path }
                })
            }
            None => McpVerdict::Allowed,
        }
    }

    /// Total allow + deny entry count across sources (doctor summary).
    pub fn entry_count(&self) -> usize {
        self.sources
            .iter()
            .map(|s| s.entries.len() + s.deny_entries.len())
            .sum()
    }

    /// Paths of the sources that restrict anything (diagnostics).
    pub fn source_paths(&self) -> Vec<&Path> {
        self.sources
            .iter()
            .filter(|s| s.is_restricted())
            .filter_map(|s| s.source_path.as_deref())
            .collect()
    }

    /// Every allow entry across sources (display only; matching intersects).
    pub fn allow_entries(&self) -> impl Iterator<Item = &AllowedMcpServer> {
        self.sources.iter().flat_map(|s| s.entries.iter())
    }

    /// Every deny entry across sources (display only).
    pub fn deny_entries(&self) -> impl Iterator<Item = &AllowedMcpServer> {
        self.sources.iter().flat_map(|s| s.deny_entries.iter())
    }

    #[cfg(test)]
    pub(super) fn is_http_allowed(&self, url: &str) -> bool {
        self.sources.iter().all(|s| s.is_http_allowed(url))
    }

    #[cfg(test)]
    pub(super) fn is_stdio_allowed(&self, command: &str) -> bool {
        self.sources.iter().all(|s| s.is_stdio_allowed(command))
    }
}

/// Policy verdict for one MCP server definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpVerdict {
    Allowed,
    Blocked(McpBlockReason),
}

/// Why policy blocks an MCP server, attributed to the blocking source. `Display` (full path) is for doctor, JSON and
/// logs; [`Self::user_facing_reason`] names the policy file only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpBlockReason {
    /// Matches a `deniedMcpServers` entry.
    Deny { source: PathBuf },
    /// Missing from `allowedMcpServers` (or a managed-only source's grants).
    NotGranted { source: PathBuf },
    /// The source blocks everything (an empty allow list, a malformed key, or an unreadable policy file).
    Lockdown { source: PathBuf },
    /// Project-declared and not granted under `enable_all_project_mcp_servers = false`.
    ProjectPin { source: PathBuf },
}

impl McpBlockReason {
    pub fn source(&self) -> &Path {
        match self {
            Self::Deny { source }
            | Self::NotGranted { source }
            | Self::Lockdown { source }
            | Self::ProjectPin { source } => source,
        }
    }

    /// The matched rule without its source.
    pub fn rule(&self) -> &'static str {
        match self {
            Self::Deny { .. } => "matches deniedMcpServers",
            Self::NotGranted { .. } => "not in allowedMcpServers",
            Self::Lockdown { .. } => "locked down by policy",
            Self::ProjectPin { .. } => {
                "project MCP disabled by enable_all_project_mcp_servers = false"
            }
        }
    }

    /// The blocking policy file by name only, for user-facing refusals.
    pub fn user_facing_source(&self) -> String {
        user_facing_policy_source(self.source())
    }

    /// The refusal form: the rule plus the policy file's name.
    pub fn user_facing_reason(&self) -> String {
        format!("{} ({})", self.rule(), self.user_facing_source())
    }
}

impl std::fmt::Display for McpBlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.rule(), self.source().display())
    }
}

/// The policy file's name (never the full path) for user-facing text; the full path when it has no name.
pub fn user_facing_policy_source(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| path.display().to_string())
}

impl ManagedSettings {
    /// Project-pin leg: blocks a project-scoped server no allow entry (from a layer the pin's owner accepts) grants.
    pub fn mcp_project_pin_block(
        &self,
        server: &agent_client_protocol::McpServer,
    ) -> Option<McpBlockReason> {
        let PolicyPin::Disabled { source, ownership } = &self.project_mcp else {
            return None;
        };
        if self.mcp_allowlist.grants_exception(server, *ownership) {
            return None;
        }
        Some(McpBlockReason::ProjectPin {
            source: source.clone(),
        })
    }
}

// ── Marketplaces ───────────────────────────────────────────────────────────────────────────────

/// Marketplace policy across all sources: a URL must pass every source (strictest wins). A source exists only when its
/// strict key was present, so a source with no URLs is a lockdown.
#[derive(Debug, Clone, Default)]
pub struct MarketplacePolicy {
    pub sources: Vec<MarketplaceAllowlist>,
}

impl MarketplacePolicy {
    pub fn single(allowlist: MarketplaceAllowlist) -> Self {
        Self {
            sources: vec![allowlist],
        }
    }

    pub fn is_restricted(&self) -> bool {
        !self.sources.is_empty()
    }

    pub fn is_url_allowed(&self, url: &str) -> bool {
        self.sources.iter().all(|s| s.is_url_allowed(url))
    }

    fn blocking_source(&self, url: &str) -> Option<&MarketplaceAllowlist> {
        self.sources
            .iter()
            .find(|s| !s.is_url_allowed(url))
            .or_else(|| self.sources.first())
    }

    /// Why `url` is blocked, full-path form (logs).
    pub fn block_reason(&self, url: &str) -> String {
        self.blocking_source(url)
            .map(MarketplaceAllowlist::block_reason)
            .unwrap_or_else(|| "source not in strictKnownMarketplaces".to_string())
    }

    /// Fail-closed add/install/enable gate: `Some(reason)` when restricted and `identity` is not allowed (local paths
    /// never match). The reason names the policy file only.
    pub fn add_block_reason(&self, identity: &str) -> Option<String> {
        (self.is_restricted() && !self.is_url_allowed(identity)).then(|| {
            match self
                .blocking_source(identity)
                .and_then(|s| s.source_path.as_deref())
            {
                Some(p) => format!(
                    "source not in strictKnownMarketplaces ({})",
                    user_facing_policy_source(p)
                ),
                None => "source not in strictKnownMarketplaces".to_string(),
            }
        })
    }

    /// Union across sources, display only (matching intersects).
    pub fn allowed_urls(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for url in self.sources.iter().flat_map(|s| s.allowed_urls.iter()) {
            if !out.contains(url) {
                out.push(url.clone());
            }
        }
        out
    }

    /// Any source is a lockdown (no URL allowed).
    pub fn is_lockdown(&self) -> bool {
        self.sources.iter().any(|s| s.allowed_urls.is_empty())
    }

    /// The plugins that may load under this policy (P169, Grok 4.7 #1): `None` when marketplaces are unrestricted;
    /// otherwise the full ids of the plugins of every install whose recorded source this policy allows. Discovery drops
    /// every other plugin, so plugin hooks and MCP servers are bound at load, not only at enable/install.
    pub fn plugin_load_restriction(
        &self,
        registry: &fuigo_agent::plugins::InstallRegistry,
    ) -> Option<fuigo_agent::plugins::PluginSourceRestriction> {
        if !self.is_restricted() {
            return None;
        }
        let mut allowed_ids: Vec<String> = registry
            .list()
            .into_iter()
            .filter(|(_, repo)| {
                registry
                    .verified_source_identity(repo)
                    .is_some_and(|identity| self.add_block_reason(&identity).is_none())
            })
            .flat_map(|(_, repo)| {
                repo.plugins
                    .keys()
                    .filter_map(|name| repo.plugin_id(name))
                    .collect::<Vec<_>>()
            })
            .collect();
        allowed_ids.sort();
        allowed_ids.dedup();
        Some(fuigo_agent::plugins::PluginSourceRestriction { allowed_ids })
    }
}

// ── Loading ────────────────────────────────────────────────────────────────────────────────────

/// The managed settings from every policy layer on disk.
pub(super) fn load_managed_settings_from(sources: Vec<PolicySource>) -> ManagedSettings {
    resolve_managed_settings_with(sources, |source| {
        use fuigo_config::policy_sources::PolicyLayerTier as T;
        match source.tier {
            T::Vendor => match fuigo_config::managed_settings_json(&source.path) {
                fuigo_config::ManagedSettingsJson::Loaded(json) => Some(json),
                _ => None,
            },
            // A validated copy of an admin TOML file is enforced by the requirements path; Null only says "a copy exists"
            T::SystemRequirements | T::SystemManaged
                if fuigo_config::admin_requirements_copy_exists(&source.path) =>
            {
                Some(serde_json::Value::Null)
            }
            _ => None,
        }
    })
}

/// Pure form of [`load_managed_settings`] over pre-read sources (in tier order). The Claude file's non-policy settings
/// (features, permission rules, `defaultMode`) come from its JSON when it parsed.
pub(super) fn resolve_managed_settings(sources: Vec<PolicySource>) -> ManagedSettings {
    resolve_managed_settings_with(sources, |_| None)
}

/// [`resolve_managed_settings`] with the Claude file's last validated copy (`vendor_copy`, by path). P183 round 9 (Grok r5
/// H2): a Claude file that is `Err` now contributes that copy's permission rules and `defaultMode` when one exists, and the
/// deny-every-tool rule when none does; its MCP, marketplace, hooks and project-MCP lock-down applies either way.
pub(super) fn resolve_managed_settings_with(
    sources: Vec<PolicySource>,
    copy_of: impl Fn(&PolicySource) -> Option<serde_json::Value>,
) -> ManagedSettings {
    let mut ms = sources
        .iter()
        .find(|s| s.tier == fuigo_config::policy_sources::PolicyLayerTier::Vendor)
        .map(|s| match &s.policy {
            Ok(json) => parse_managed_settings_base(json, &s.path),
            Err(_) => match copy_of(s) {
                Some(json) => parse_managed_settings_base(&json, &s.path),
                None => locked_down_base(&s.path),
            },
        })
        .unwrap_or_default();
    for pin in BoolPin::ALL {
        let resolved = resolve_bool_pin(pin, &sources);
        match pin {
            BoolPin::ProjectMcp => ms.project_mcp = resolved,
            BoolPin::NonManagedHooks => ms.non_managed_hooks = resolved,
        }
    }
    for source in &sources {
        let ownership = source.ownership;
        match &source.policy {
            Ok(json) => apply_policy_source(&mut ms, json, &source.path, ownership),
            Err(_) => {
                apply_unreadable_policy_source(&mut ms, &source.path, ownership);
                // P183 round 9 (H2): an ADMIN layer that cannot be trusted and has no validated copy denies every tool
                // (the Claude file did it above; the TOML files' copies are enforced by the requirements path)
                if ownership == PolicyLayerOwnership::Admin
                    && source.tier != fuigo_config::policy_sources::PolicyLayerTier::Vendor
                    && copy_of(source).is_none()
                {
                    ms.permissions.extend(locked_down_base(&source.path).permissions);
                }
            }
        }
    }
    ms
}

/// Fail-closed stand-in for a layer that could not be read: MCP and marketplace lockdown (the pins were engaged by
/// [`resolve_bool_pin`]).
fn apply_unreadable_policy_source(
    ms: &mut ManagedSettings,
    path: &Path,
    ownership: PolicyLayerOwnership,
) {
    ms.mcp_allowlist.sources.push(
        McpServerAllowlist::new(Vec::new(), Vec::new(), Some(path.to_path_buf()))
            .with_ownership(ownership)
            .with_lockdown(),
    );
    ms.marketplace_allowlist.sources.push(MarketplaceAllowlist {
        allowed_urls: Vec::new(),
        source_path: Some(path.to_path_buf()),
    });
}

/// Fold one source's MCP and marketplace keys into `ms`; layers only accumulate, so a later layer can add restrictions
/// but never remove another's.
pub(super) fn apply_policy_source(
    ms: &mut ManagedSettings,
    json: &serde_json::Value,
    path: &Path,
    ownership: PolicyLayerOwnership,
) {
    let allow = parse_mcp_entry_list(json, McpPolicyList::Allow, path);
    let deny = parse_mcp_entry_list(json, McpPolicyList::Deny, path);
    let managed_only = policy_bool(
        json,
        &[
            "allowManagedMcpServersOnly",
            "allow_managed_mcp_servers_only",
        ],
        true,
        path,
    ) == Some(true);
    // An explicit empty deny list is harmless; an empty allow list or any malformed list is a lockdown.
    let lockdown = allow.locks_down() || deny.is_malformed();
    if lockdown {
        warn!(
            path = %path.display(),
            "MCP lockdown: the allow list has no usable entries or the deny list is unenforceable; every MCP server is blocked"
        );
    }
    let allow_entries = allow.entries();
    let deny_entries = deny.entries();
    if lockdown || managed_only || !allow_entries.is_empty() || !deny_entries.is_empty() {
        info!(
            path = %path.display(),
            allow = allow_entries.len(),
            deny = deny_entries.len(),
            managed_only,
            lockdown,
            "Loaded MCP server policy"
        );
        let mut allowlist =
            McpServerAllowlist::new(allow_entries, deny_entries, Some(path.to_path_buf()))
                .with_ownership(ownership);
        if managed_only {
            allowlist = allowlist.with_managed_only();
        }
        if lockdown {
            allowlist = allowlist.with_lockdown();
        }
        ms.mcp_allowlist.sources.push(allowlist);
    }

    let strict = parse_strict_marketplaces(json, path);
    if !strict.is_absent() {
        let allowed_urls = strict.entries();
        if allowed_urls.is_empty() {
            warn!(
                path = %path.display(),
                "marketplace lockdown: the strict list has no usable entries; every marketplace is blocked"
            );
        }
        info!(path = %path.display(), count = allowed_urls.len(), "Loaded marketplace allowlist");
        ms.marketplace_allowlist.sources.push(MarketplaceAllowlist {
            allowed_urls,
            source_path: Some(path.to_path_buf()),
        });
    }
}

/// `strictKnownMarketplaces` → allowed clone URLs (`git`+`url`, `github`+`repo`). Unsupported entries grant nothing.
fn parse_strict_marketplaces(json: &serde_json::Value, path: &Path) -> PolicyKey<Vec<String>> {
    policy_array(
        json,
        &["strictKnownMarketplaces", "strict_known_marketplaces"],
        path,
    )
    .map(|arr| {
        arr.iter()
            .filter_map(|entry| {
                let url = marketplace_git_url(entry);
                if url.is_none() {
                    warn!(
                        path = %path.display(),
                        "ignoring unsupported strictKnownMarketplaces entry; only git+url and github+repo sources are honored"
                    );
                }
                url
            })
            .collect()
    })
}

fn marketplace_git_url(entry: &serde_json::Value) -> Option<String> {
    match entry.get("source")?.as_str()? {
        "git" => Some(entry.get("url")?.as_str()?.to_string()),
        "github" => Some(format!(
            "https://github.com/{}.git",
            entry.get("repo")?.as_str()?
        )),
        _ => None,
    }
}

/// Which MCP policy list a key names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum McpPolicyList {
    Allow,
    Deny,
}

impl McpPolicyList {
    fn keys(self) -> &'static [&'static str] {
        match self {
            Self::Allow => &["allowedMcpServers", "allowed_mcp_servers"],
            Self::Deny => &["deniedMcpServers", "denied_mcp_servers"],
        }
    }
}

/// One list by either spelling (`allowedMcpServers` / `deniedMcpServers`); tests.
#[cfg(test)]
pub(super) fn parse_mcp_entries_for_key(
    json: &serde_json::Value,
    key: &str,
) -> PolicyKey<Vec<AllowedMcpServer>> {
    let list = if key.starts_with("denied") {
        McpPolicyList::Deny
    } else {
        McpPolicyList::Allow
    };
    parse_mcp_entry_list(json, list, Path::new("<test>"))
}

fn parse_mcp_entry_list(
    json: &serde_json::Value,
    list: McpPolicyList,
    path: &Path,
) -> PolicyKey<Vec<AllowedMcpServer>> {
    policy_array(json, list.keys(), path).and_then(|arr| {
        parse_mcp_entries(arr, list, path).map_or(PolicyKey::Malformed, PolicyKey::Present)
    })
}

/// Unusable allow entries drop (they grant nothing); an unusable deny entry would block nothing, so the whole deny key
/// fails closed (`None`).
fn parse_mcp_entries(
    arr: &[serde_json::Value],
    list: McpPolicyList,
    path: &Path,
) -> Option<Vec<AllowedMcpServer>> {
    let mut entries = Vec::new();
    let mut enforceable = true;
    for entry in arr {
        match (parse_mcp_entry(entry, list), list) {
            (Some(parsed), _) => entries.push(parsed),
            (None, McpPolicyList::Deny) => {
                warn!(
                    path = %path.display(),
                    "unenforceable deniedMcpServers entry; failing closed (honored fields: serverUrl, command, serverCommand, serverName)"
                );
                enforceable = false;
            }
            (None, McpPolicyList::Allow) => warn!(
                path = %path.display(),
                "ignoring unusable allowedMcpServers entry; it grants nothing (honored fields: serverUrl, command, serverCommand, serverName)"
            ),
        }
    }
    enforceable.then_some(entries)
}

const SERVER_URL: &[&str] = &["serverUrl", "server_url"];
const SERVER_COMMAND: &[&str] = &["serverCommand", "server_command"];
const SERVER_NAME: &[&str] = &["serverName", "server_name"];

/// `serverUrl` → Http, `serverCommand` → StdioArgv, `command` → Stdio, `serverName` → Name. `None`: unknown shape, a
/// field spelled both ways with different values, or an unmatchable deny URL.
fn parse_mcp_entry(entry: &serde_json::Value, list: McpPolicyList) -> Option<AllowedMcpServer> {
    if [SERVER_URL, SERVER_COMMAND, SERVER_NAME]
        .iter()
        .any(|keys| policy_field(entry, keys).is_malformed())
    {
        return None;
    }
    let field = |keys: &[&str]| keys.iter().find_map(|key| entry.get(*key));
    if let Some(url) = field(SERVER_URL).and_then(|u| u.as_str()) {
        let unmatchable = match list {
            McpPolicyList::Deny => warn_on_unmatchable_deny_url(url),
            McpPolicyList::Allow => {
                warn_on_unmatchable_allow_url(url);
                false
            }
        };
        return (!unmatchable).then(|| AllowedMcpServer::Http {
            url_pattern: url.to_string(),
        });
    }
    if let Some(argv) = field(SERVER_COMMAND)
        .and_then(|c| c.as_array())
        // All or nothing: a partial argv would match the wrong command.
        .and_then(|a| {
            a.iter()
                .map(|v| v.as_str().map(String::from))
                .collect::<Option<Vec<_>>>()
        })
        .filter(|argv| !argv.is_empty())
    {
        return Some(AllowedMcpServer::StdioArgv { argv });
    }
    if let Some(cmd) = entry.get("command").and_then(|c| c.as_str()) {
        return Some(AllowedMcpServer::Stdio {
            command: cmd.to_string(),
        });
    }
    field(SERVER_NAME)
        .and_then(|n| n.as_str())
        .map(|name| AllowedMcpServer::Name {
            name: name.to_string(),
        })
}

#[cfg(test)]
#[path = "managed_policy_tests.rs"]
mod tests;
