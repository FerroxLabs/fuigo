//! Shared take/apply for `[[version_overrides]]` / `[[campaigns]]` arrays.

use serde::de::DeserializeOwned;

use crate::deep_merge_toml;

pub type PatchPath = &'static [&'static str];

#[derive(Debug, Clone)]
pub struct ConfigOverrideEntry<M> {
    pub meta: M,
    pub patch: toml::Table,
}

/// Strip `key` from the root table; each element splits into `M` and the remaining keys as the patch.
pub fn take_patch_array<M>(
    config: &mut toml::Value,
    key: &str,
) -> Result<Vec<ConfigOverrideEntry<M>>, toml::de::Error>
where
    M: DeserializeOwned,
{
    let Some(table) = config.as_table_mut() else {
        return Ok(Vec::new());
    };
    let Some(array_value) = table.remove(key) else {
        return Ok(Vec::new());
    };

    #[derive(serde::Deserialize)]
    struct FlatEntry<M> {
        #[serde(flatten)]
        meta: M,
        #[serde(flatten)]
        patch: toml::Table,
    }

    let entries: Vec<FlatEntry<M>> = array_value.try_into()?;
    Ok(entries
        .into_iter()
        .map(|e| ConfigOverrideEntry {
            meta: e.meta,
            patch: e.patch,
        })
        .collect())
}

/// Whether `patch` affects the value at `path`: it sets a value there (any leaf under it counts), **or** it sets a non-table ancestor.
/// In that case deep-merge replaces the whole subtree, so every leaf beneath is touched.
/// A patch like `models = "oops"` wipes `models.default` and must still be dismissable and flagged as driving it.
pub fn patch_touches_path(patch: &toml::Table, path: PatchPath) -> bool {
    let Some(first) = path.first() else {
        return false;
    };
    let Some(mut cur) = patch.get(*first) else {
        return false;
    };
    for seg in path.iter().skip(1) {
        match cur.as_table() {
            Some(t) => match t.get(*seg) {
                Some(v) => cur = v,
                None => return false,
            },
            // Non-table ancestor: the merge replaces this subtree wholesale.
            None => return true,
        }
    }
    true
}

pub fn patch_touches_any(patch: &toml::Table, paths: &[PatchPath]) -> bool {
    paths.iter().any(|p| patch_touches_path(patch, p))
}

/// Keys stripped from every applied patch.
/// An override cannot re-inject nested `version_overrides`/`campaigns` or define `[auth_provider.*]` / `[model_providers.*]` command tables.
pub const PATCH_STRIP_KEYS: &[&str] = &[
    "version_overrides",
    "campaigns",
    "auth_provider",
    "model_providers",
];

/// Stripped like [`PATCH_STRIP_KEYS`]: these carry a command the client would execute.
/// The whole table goes, so a new key in it needs no second edit.
pub const PATCH_STRIP_PATHS: &[PatchPath] =
    &[&["ui", "status_line"], &["ui", "notifications", "hooks"]];

/// Additionally stripped from campaign and remote patches: those patches cannot set auth policy tables, while trusted version_overrides may.
/// The stripped tables carry `preferred_method`, `force_login_team_uuid`, and `disable_api_key_auth`.
pub const CAMPAIGN_STRIP_KEYS: &[&str] = &[
    "version_overrides",
    "campaigns",
    "auth_provider",
    "model_providers",
    "auth",
    "fuigo_com_config",
    // The trusted API origins (and so where the sign-in bearer and `FUIGO_API_KEY` may be sent) come from here.
    "endpoints",
    // Sandbox policy is the user's, CLI's or requirements'; the `FUIGO_CONFIG` overlay cannot set it either.
    "sandbox",
];

/// Dotted paths a campaign patch (remote, `[[campaigns]]` in any layer, `FUIGO_CAMPAIGNS_OVERRIDE`) may set; `*`
/// matches any one table key. The boundary is this list, not the strip list below: [`retain_campaign_allowed`] runs
/// first on every campaign patch and drops everything else (fail-closed, so a new config key stays out of campaigns
/// until it is listed here). Each path is one the shipped campaign features use, and none can set a credential
/// or widen a permission. The one that reaches further is `mcp_servers`: a campaign may add an HTTP server at a URL
/// it chooses, or a local program it names, which is reported to the user, secret-free and untrusted (an HTTP server
/// at a campaign-chosen URL gets no saved key, header or environment value). `tests/campaign_key_guard.rs` holds the reviewed copy with the reason for each.
/// A length-1 path keeps that whole table (only a table); a deeper path keeps that leaf, subject to
/// [`retain_campaign_allowed`]'s value constraints.
pub const CAMPAIGN_ALLOW_PATHS: &[&[&str]] = &[
    // The soft default-model nudge (`CAMPAIGN_FIELDS` in the shell), dismissed by an explicit `/model` pick. This and
    // the two helper selectors may not name a model the config routes (`drop_campaign_routed_model_selectors`, C7-01)
    &["models", "default"],
    // Helper-model nudges: resolved as defaults, never as the user's own choice (P90 F6)
    &["models", "image_description"],
    &["models", "session_summary"],
    // Metadata of a model the campaign nudges to or adds; its route, credential and notice keys stay stripped below
    &["model", "*", "name"],
    &["model", "*", "context_window"],
    // A campaign may ADD an MCP server: `strip_campaign_mcp_servers` keeps new names only, without secret fields. An
    // added stdio server does not start until the user turns it on for that command (`approved_campaign_mcp_servers`
    // in the user's own config.toml, outside this list; C7-02)
    &["mcp_servers"],
    // Managed MCP servers may only be turned OFF (`false`): `true` would start servers the user turned off
    &["managed_mcps", "enabled"],
];

/// Smallest and largest `model.<id>.context_window` a campaign may set (the sampler's own ceiling is 16,000,000).
pub const CAMPAIGN_CONTEXT_WINDOW_RANGE: std::ops::RangeInclusive<i64> = 1024..=10_000_000;

/// Text that comes from a campaign, cleaned for a note: control characters removed, cut to `max` characters.
pub fn tidy_note_text(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// Confine a campaign `patch` to [`CAMPAIGN_ALLOW_PATHS`] and their value constraints. Returns the top-level keys
/// whose content was dropped in whole or in part (names only, never values; cut to a short printable form because
/// they come from the campaign), so the caller can tell the user once.
pub fn retain_campaign_allowed(patch: &mut toml::Table) -> Vec<String> {
    let before = patch.clone();
    retain_allowed_paths(patch, CAMPAIGN_ALLOW_PATHS, true);
    if let Some(toml::Value::Table(models)) = patch.get_mut("models") {
        models.retain(|_, v| v.is_str());
    }
    if let Some(toml::Value::Table(by_id)) = patch.get_mut("model") {
        for (_, entry) in by_id.iter_mut() {
            if let toml::Value::Table(entry) = entry {
                entry.retain(|k, v| match k {
                    "name" => v.is_str(),
                    "context_window" => v.as_integer().is_some_and(|n| CAMPAIGN_CONTEXT_WINDOW_RANGE.contains(&n)),
                    _ => false,
                });
            }
        }
        by_id.retain(|_, v| v.as_table().is_some_and(|t| !t.is_empty()));
    }
    if let Some(toml::Value::Table(managed)) = patch.get_mut("managed_mcps") {
        managed.retain(|_, v| *v == toml::Value::Boolean(false));
    }
    patch.retain(|_, v| v.as_table().is_none_or(|t| !t.is_empty()));
    let mut removed = Vec::new();
    removed_paths(&before, patch, "", &mut removed);
    removed.iter().map(|p| tidy_note_text(p, 64)).collect()
}

/// Dotted paths in `before` that `after` lacks or changed, descending into tables so a kept `models.default` does not
/// put `models` on the list.
fn removed_paths(before: &toml::Table, after: &toml::Table, prefix: &str, out: &mut Vec<String>) {
    for (k, v) in before {
        let path = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
        match (v, after.get(k)) {
            (_, None) => out.push(path),
            (toml::Value::Table(b), Some(toml::Value::Table(a))) => removed_paths(b, a, &path, out),
            (b, Some(a)) if a != b => out.push(path),
            _ => {}
        }
    }
}

/// The `models.*` selectors a campaign may set (the `models` leaves of [`CAMPAIGN_ALLOW_PATHS`]).
pub const CAMPAIGN_MODEL_SELECTORS: &[&str] = &["default", "image_description", "session_summary"];

/// `[model.<id>]` keys that choose where that model's requests go or which credential they carry. A model with any of
/// them is routed by the config (the user's or their administrator's), not by the built-in catalog (review C7-01).
pub const MODEL_ROUTE_KEYS: &[&str] = &[
    "base_url",
    "api_base_url",
    "model_provider",
    "auth_provider",
    "api_key",
    "env_key",
    "extra_headers",
    "env_http_headers",
    "http_headers",
    "query_params",
    "mtls_cert_dir",
];

/// Every name that selects a `[model.<id>]` entry in `config` that sets any [`MODEL_ROUTE_KEYS`] key: its table key,
/// and the wire names the shell also resolves a selector by (its `id`, its `model`, each `variants[].model_id`;
/// review M-2).
pub fn config_routed_model_ids(config: &toml::Value) -> std::collections::HashSet<String> {
    let Some(models) = config.get("model").and_then(toml::Value::as_table) else {
        return Default::default();
    };
    let mut ids = std::collections::HashSet::new();
    for (key, entry) in models {
        let Some(entry) = entry.as_table().filter(|e| MODEL_ROUTE_KEYS.iter().any(|k| e.contains_key(*k))) else {
            continue;
        };
        ids.insert(key.clone());
        let variant_ids = entry
            .get("variants")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|variant| variant.get("model_id"));
        for name in ["id", "model"].iter().filter_map(|k| entry.get(*k)).chain(variant_ids) {
            if let Some(name) = name.as_str() {
                ids.insert(name.to_owned());
            }
        }
    }
    ids
}

/// Review C7-01: drop each campaign model selector that names a model in `routed` (see [`config_routed_model_ids`]),
/// so a campaign can nudge to a built-in or catalog model but cannot move the user's content to an endpoint or
/// credential the user configured for something else. Returns the dropped selector names (never their values).
pub fn drop_campaign_routed_model_selectors(
    patch: &mut toml::Table,
    routed: &std::collections::HashSet<String>,
) -> Vec<&'static str> {
    let Some(toml::Value::Table(models)) = patch.get_mut("models") else {
        return Vec::new();
    };
    let dropped: Vec<&'static str> = CAMPAIGN_MODEL_SELECTORS
        .iter()
        .copied()
        .filter(|k| models.get(*k).and_then(toml::Value::as_str).is_some_and(|id| routed.contains(id)))
        .collect();
    for key in &dropped {
        models.remove(*key);
    }
    if models.is_empty() {
        patch.remove("models");
    }
    dropped
}

/// Second layer behind [`CAMPAIGN_ALLOW_PATHS`] (defence in depth): paths stripped even if an allowlist entry ever
/// came to cover them. `features.peer_messaging` lets sessions message each other and only the user or the machine's
/// admin may turn it on.
///
/// `*` matches every key of a table (MCP server names are dynamic). A campaign may never set a server's token settings
/// (`bearer_token_file`, `bearer_token_env_var`), on any server, new or existing. What else a campaign may do to MCP
/// servers is decided by [`strip_campaign_mcp_servers`], which also needs the pre-campaign set of server names.
///
/// No `[model.<id>]` (existing or added) takes a host, header, query, provider or credential field from a campaign.
///
/// The boundary these entries record: a campaign never sets where a credential or the user's content goes (a host,
/// endpoint, proxy, header, token or key), or what the client executes (a command, prefix or environment policy), and
/// never flips a switch or selector that turns one of those on. `tests/campaign_key_guard.rs` classifies every config
/// key whose name looks like one of those and keeps a registry of the semantic switches, so this list does not rot.
///
/// `model.*.notice` is text shown in a banner above the prompt: only the user's own layers may set it.
pub const CAMPAIGN_STRIP_PATHS: &[&str] = &[
    "features.peer_messaging",
    "mcp_servers.*.bearer_token_file",
    "mcp_servers.*.bearer_token_env_var",
    "model.*.notice",
    // A campaign never sets where a model sends requests, what it sends with them, or which credential source it uses,
    // on any `[model.<id>]` (existing or added): a credential the user already configured would follow the new host.
    "model.*.base_url",
    "model.*.api_base_url",
    "model.*.extra_headers",
    "model.*.env_http_headers",
    "model.*.http_headers",
    "model.*.query_params",
    "model.*.model_provider",
    "model.*.auth_provider",
    "model.*.api_key",
    "model.*.env_key",
    "model.*.mtls_cert_dir",
    // The global default headers land on every model.
    "models.extra_headers",
    "toolset.web_fetch.allow_local",
    // Where a hub sign-in bearer goes, and what every shell command is run with or after.
    "hub.url",
    "shell_environment_policy",
    "toolset.bash.cmd_prefix",
    "toolset.web_fetch.proxy_endpoint",
    // Web-search routing and credentials: a destination plus the key or headers sent with it.
    "toolset.web_search.base_url",
    "toolset.web_search.flux_base_url",
    "toolset.web_search.api_key",
    "toolset.web_search.extra_headers",
    "toolset.web_search.env_http_headers",
    "toolset.web_search.mtls_cert_dir",
    // Telemetry: where events and traces go, the keys sent with them, the exporters, and the content gates.
    "telemetry.events_url",
    "telemetry.events_api_key",
    "telemetry.mixpanel_token",
    "telemetry.otel_endpoint",
    "telemetry.otel_enabled",
    "telemetry.otel_logs_exporter",
    "telemetry.otel_metrics_exporter",
    "telemetry.otel_protocol",
    "telemetry.otel_log_user_prompts",
    "telemetry.otel_log_tool_details",
    "telemetry.otel_certificate",
    "telemetry.otel_client_certificate",
    "telemetry.otel_client_key",
    // A command the client runs when the user sends feedback.
    "feedback.user.command",
    // The video-output bucket: an endpoint and its access keys.
    "tools.zdr_video_output_s3",
    // Where updates, plugins, skills and rules are loaded from, and where sessions are registered: code and
    // instructions the client runs or reads, not a nudge.
    "cli.installer",
    "cli.npm_registry",
    "cli.session_registry",
    "paths",
    "plugins.paths",
    "skills.bundled_skill_dirs",
    "skills.paths",
    "skills.server_skill_dirs",
    // Which agent definition (instructions and inline hooks) loads, which installed plugins run, and where the
    // plugin catalog comes from.
    "agent.definition",
    "plugins.enabled",
    "plugins.disabled",
    "plugins.auto_discover",
    "marketplace.sources",
    "skills.auto_discover",
    // Session artifacts leaving the machine, and the exporter transport under both spellings.
    "telemetry.trace_upload",
    "telemetry.otel_transport",
    // Switches and selectors that turn the above on indirectly: the telemetry feature is the default for trace upload,
    // the LSP feature starts the user's and plugins' language servers, a named agent loads that definition's hooks and
    // servers, the disable list keeps installed MCP servers stopped, and a subagent role or persona file is read from
    // any path a campaign names.
    "features.telemetry",
    "features.lsp_tools",
    "agent.name",
    "disabled_mcp_servers",
    "subagents.roles.*.prompt_file",
    "subagents.personas.*.instructions_file",
];

/// Credential and environment fields a campaign-ADDED MCP server may not carry: each either holds a secret or names an
/// environment variable that would be read and sent to the campaign's `url`. `url`, `command` and `args` stay, so a
/// secret-free server still loads.
pub const CAMPAIGN_MCP_SECRET_FIELDS: &[&str] = &[
    "env",
    "headers",
    "http_headers",
    "env_http_headers",
    "oauth",
    "oauth_client_secret_env_var",
    "bearer_token",
    "bearer_token_env_var",
    "bearer_token_file",
];

/// A campaign patch may not modify ANY key of an MCP server that already exists before campaigns are applied
/// (`existing`): its whole `mcp_servers.<name>` sub-table is dropped from the patch. A server the patch ADDS (a name not
/// in `existing`) keeps `url`, `command`, `args` and its other plain fields; [`CAMPAIGN_MCP_SECRET_FIELDS`] are dropped.
/// A non-table `mcp_servers` or server entry is dropped. Returns the names the strip dropped or altered, so the caller
/// can tell the user; it is called before [`strip_campaign_paths`].
pub fn strip_campaign_mcp_servers(patch: &mut toml::Table, existing: &std::collections::HashSet<String>) -> Vec<String> {
    let mut touched = Vec::new();
    match patch.get_mut("mcp_servers") {
        None => return touched,
        Some(toml::Value::Table(servers)) => {
            let names: Vec<String> = servers.keys().cloned().collect();
            for name in names {
                let drop_whole = existing.contains(&name) || !matches!(servers.get(&name), Some(toml::Value::Table(_)));
                if drop_whole {
                    servers.remove(&name);
                    touched.push(name);
                } else if let Some(toml::Value::Table(entry)) = servers.get_mut(&name) {
                    let mut hit = false;
                    for key in CAMPAIGN_MCP_SECRET_FIELDS {
                        hit |= entry.remove(*key).is_some();
                    }
                    if hit {
                        touched.push(name);
                    }
                }
            }
            if servers.is_empty() {
                patch.remove("mcp_servers");
            }
        }
        Some(_) => {
            patch.remove("mcp_servers");
            touched.push("mcp_servers".to_owned());
        }
    }
    touched
}

/// `(server name, program)` for every stdio server left in `patch` that has a `command`. After
/// [`strip_campaign_mcp_servers`] those are the servers the campaign ADDS: each runs a program the campaign chose, so the
/// caller tells the user (a warning, not a refusal: a campaign may still add a stdio server). Text is cut to one short
/// printable line because it comes from the campaign.
pub fn campaign_added_stdio_programs(patch: &toml::Table) -> Vec<(String, String)> {
    fn tidy(s: &str) -> String {
        tidy_note_text(s, 120)
    }
    let Some(toml::Value::Table(servers)) = patch.get("mcp_servers") else {
        return Vec::new();
    };
    servers
        .iter()
        .filter_map(|(name, server)| {
            let command = server.get("command")?.as_str()?;
            Some((tidy(name), tidy(command)))
        })
        .collect()
}

/// Remove [`CAMPAIGN_SOURCE_MARKER`] from every `mcp_servers.<name>` of a layer that is not a campaign. Only the
/// campaign merge may set it ([`mark_campaign_servers`]); in any other layer it would switch off the environment
/// expansion of a definition the user or a project wrote.
pub fn strip_campaign_source_marker(layer: &mut toml::Value) {
    if let Some(toml::Value::Table(servers)) = layer.get_mut("mcp_servers") {
        for (_, server) in servers.iter_mut() {
            if let toml::Value::Table(entry) = server {
                entry.remove(CAMPAIGN_SOURCE_MARKER);
            }
        }
    }
}

/// Name of the marker [`mark_campaign_servers`] sets (`McpServerConfig::campaign_source`).
pub const CAMPAIGN_SOURCE_MARKER: &str = "__fuigo_campaign_source";

/// Mark every server left in `patch` (after [`strip_campaign_mcp_servers`] only the ones the campaign ADDS remain) as
/// campaign-sourced, so its strings are never expanded from the environment at use. A value the campaign set for the
/// marker itself is overwritten.
pub fn mark_campaign_servers(patch: &mut toml::Table) {
    if let Some(toml::Value::Table(servers)) = patch.get_mut("mcp_servers") {
        for (_, server) in servers.iter_mut() {
            if let toml::Value::Table(entry) = server {
                entry.insert(CAMPAIGN_SOURCE_MARKER.to_owned(), toml::Value::Boolean(true));
            }
        }
    }
}

/// Remove [`CAMPAIGN_STRIP_PATHS`] from `patch`; a table the removal leaves empty is dropped too.
pub fn strip_campaign_paths(patch: &mut toml::Table) {
    for dotted in CAMPAIGN_STRIP_PATHS {
        let path: Vec<&str> = dotted.split('.').collect();
        remove_nested(patch, &path);
    }
}

/// Remove the leaf at `path`, and every table the removal leaves empty on the way up.
fn remove_nested(patch: &mut toml::Table, path: &[&str]) {
    let Some((key, rest)) = path.split_first() else {
        return;
    };
    if *key == "*" {
        let keys: Vec<String> = patch.keys().cloned().collect();
        for k in keys {
            if rest.is_empty() {
                patch.remove(&k);
                continue;
            }
            match patch.get_mut(&k) {
                Some(toml::Value::Table(nested)) => {
                    remove_nested(nested, rest);
                    if nested.is_empty() {
                        patch.remove(&k);
                    }
                }
                _ => {
                    patch.remove(&k);
                }
            }
        }
        return;
    }
    if rest.is_empty() {
        patch.remove(*key);
        return;
    }
    match patch.get_mut(*key) {
        Some(toml::Value::Table(nested)) => {
            remove_nested(nested, rest);
            if nested.is_empty() {
                patch.remove(*key);
            }
        }
        // A non-table ancestor would clobber everything beneath it on merge.
        Some(_) => {
            patch.remove(*key);
        }
        None => {}
    }
}

/// Dotted paths the `FUIGO_CONFIG` / `FUIGO_CONFIG_PATH` overlay may set.
/// They are applied at [`crate::env_overlay`]'s finalize step by [`retain_overlay_allowed`].
/// A length-1 path keeps the whole soft top-level table; a deeper path keeps only that leaf.
/// No entry is a prefix of another: a top-level key is either a whole-subtree keep or deeper-only, never both.
/// That makes the choice in `retain_allowed_paths` between keeping a whole subtree and recursing unambiguous.
/// Its deeper whole-subtree case is defensive.
/// Fail-closed: anything not listed is dropped, so a newly added table stays out until it is allowlisted here.
/// The overlay's reach and the security gates that read it overlay-free are documented on [`crate::config_layers::ConfigLayers::env_overlay`].
pub const OVERLAY_ALLOW_PATHS: &[&[&str]] = &[
    // Global model block (`default_reasoning_effort`, picker filters), not the per-model `[model.<id>]` block; and the soft `[features]` toggles
    &["models"],
    &["features"],
    // `[toolset]` is not soft wholesale: its sinks (`web_search` base_url / api_key, `web_fetch` proxy_endpoint, `bash` cmd_prefix) stay out
    // Only `login_shell_capture` (runs the user's own `$SHELL`) and the web-search domain lists survive
    // The domain lists widen or narrow the user's own allowlist and are capped and requirements-clamped downstream
    &["toolset", "bash", "login_shell_capture"],
    &["toolset", "web_search", "allowed_domains"],
    &["toolset", "web_search", "excluded_domains"],
    // `[shell_environment_policy]` cannot inject an env value
    // `set` adds env values (`LD_PRELOAD`, `BASH_ENV`, `PATH`), an indirect way to run code in a tool subprocess, so it is dropped
    // The remaining fields only select among env names the launcher already controls
    // Relative to a lower layer they may loosen or tighten what a subprocess inherits but never introduce a value
    // A launcher that must add an env var sets it on the process directly
    &["shell_environment_policy", "inherit"],
    &["shell_environment_policy", "ignore_default_excludes"],
    &["shell_environment_policy", "exclude"],
    &["shell_environment_policy", "include_only"],
    // `[plugins] auto_discover` can only turn implicit plugin discovery OFF (unset or true is the default, discover)
    // A host that embeds Fuigo uses it to keep the machine owner's plugins (and their MCP servers, hooks, skills) out of its sessions
    // `paths`, `enabled` and `disabled` stay out: they would add or enable a discovery source
    &["plugins", "auto_discover"],
];

/// Confine `overlay` to [`OVERLAY_ALLOW_PATHS`], dropping every other key and any table left empty.
pub fn retain_overlay_allowed(overlay: &mut toml::Table) {
    retain_allowed_paths(overlay, OVERLAY_ALLOW_PATHS, true);
    // `plugins.auto_discover` may only turn discovery off: a `true` (or a non-bool) would re-enable discovery a lower
    // layer turned off, i.e. add a discovery source, so only `false` is kept
    if let Some(toml::Value::Table(plugins)) = overlay.get_mut("plugins") {
        if plugins.get("auto_discover") != Some(&toml::Value::Boolean(false)) {
            plugins.remove("auto_discover");
        }
        if plugins.is_empty() {
            overlay.remove("plugins");
        }
    }
}

/// Retain only `paths` (nested dotted leaves) in `table`, pruning every other key and any table left empty.
/// At the top level a whole-subtree entry (a length-1 path) keeps its value only when it is a table.
/// A scalar or array there would clobber the subtree on deep-merge, so it is dropped.
/// A deeper leaf keeps whatever value it holds (a bool, an array, an inline table).
/// A `*` segment matches any one key (campaign paths use it; the overlay list has none).
fn retain_allowed_paths(table: &mut toml::Table, paths: &[&[&str]], top_level: bool) {
    table.retain(|key, value| {
        let nested: Vec<&[&str]> = paths
            .iter()
            .filter(|p| p.first().is_some_and(|seg| *seg == key || *seg == "*"))
            .map(|p| &p[1..])
            .collect();
        if nested.is_empty() {
            return false;
        }
        // An allowed path ends at this key: keep the subtree/leaf, but a top-level whole-subtree key must be a table (else it clobbers on merge)
        if nested.iter().any(|p| p.is_empty()) {
            return !top_level || value.is_table();
        }
        // Only deeper leaves are allowed: recurse and keep if any survived.
        match value.as_table_mut() {
            Some(child) => {
                retain_allowed_paths(child, &nested, false);
                !child.is_empty()
            }
            None => false,
        }
    });
}

/// Deep-merge each patch in iteration order (later wins on a leaf), stripping `strip_keys` (top level) and [`PATCH_STRIP_PATHS`] first.
/// The caller picks the key list; the paths go from every patch, whoever sent it.
///
/// A patch is another input to the same merge as the disk layers, so it gets the same normalization ([`crate::loader::normalize_config_layer`]).
/// Otherwise a patch that flips `[toolset.web_search]` from an allowlist to a blocklist would leave both keys set.
/// The resolver would then drop the blocklist and let the layer the patch overlays win.
pub fn apply_patches(
    config: &mut toml::Value,
    patches: impl IntoIterator<Item = toml::Table>,
    strip_keys: &[&str],
) {
    for mut patch in patches {
        for key in strip_keys {
            patch.remove(*key);
        }
        let config_models = config.get("model").and_then(toml::Value::as_table);
        if let Some(patch_models) = patch.get_mut("model").and_then(toml::Value::as_table_mut) {
            for (id, patch_model) in patch_models.iter_mut() {
                let has_mtls_identity = config_models
                    .and_then(|models| models.get(id))
                    .and_then(toml::Value::as_table)
                    .is_some_and(|model| model.contains_key("mtls_cert_dir"));
                if let Some(patch_model) = patch_model.as_table_mut() {
                    // A patch may tune the model, but it cannot select a local identity
                    // or change the explicit destination to which that identity is bound.
                    patch_model.remove("mtls_cert_dir");
                    if has_mtls_identity {
                        patch_model.remove("base_url");
                        patch_model.remove("api_base_url");
                    }
                }
            }
            // P192: a model on a subscription vendor's host can carry the user's subscription
            // credential, so remote configuration neither routes a model there nor changes any
            // field of one that is (its credential and routing fields included): the whole
            // patch entry for such a model is dropped.
            // The same holds for a model routed through a subscription provider (Grok r2 HIGH):
            // the merged config's subscription providers are the user file's alone (every other
            // layer is stripped by `strip_subscription_authority`), and no patch model may
            // reference one.
            let routes = UserSubscriptionRoutes::of(config);
            let vendor_ids: Vec<String> = patch_models
                .iter()
                .filter(|(id, patch_model)| {
                    config_models
                        .and_then(|models| models.get(id.as_str()))
                        .is_some_and(|own| names_subscription_vendor(own) || routes.is_routed(own))
                        || names_subscription_vendor(patch_model)
                })
                .map(|(id, _)| id.clone())
                .collect();
            for id in vendor_ids {
                patch_models.remove(&id);
            }
            for (_, patch_model) in patch_models.iter_mut() {
                if let Some(patch_model) = patch_model.as_table_mut() {
                    routes.strip_refs(patch_model);
                }
            }
        }
        for path in PATCH_STRIP_PATHS {
            strip_path(&mut patch, path);
        }
        let mut patch = toml::Value::Table(patch);
        crate::loader::normalize_config_layer(&mut patch);
        deep_merge_toml(config, &patch);
    }
}

/// P192: only the user's own file (`$FUIGO_HOME/config.toml`) confers subscription authority.
/// `layer` is a non-user layer (system managed, managed, or a requirements tier, MDM included),
/// already `${VAR}`-expanded; `user` is the user file. From `layer`, this removes:
/// - every `[model_providers.<id>]` entry on a vendor host, and every `[model.<id>]` entry on a
///   vendor host or naming such a provider (`model_provider`), so no other layer adds a vendor
///   model or retargets one there;
/// - `subscription` from every provider's inline `auth`, and a provider's `auth_provider` naming
///   a user subscription provider; on a provider id the user file routes a subscription through,
///   its `base_url`, `api_base_url`, `auth` and `auth_provider`;
/// - on a key whose user entry is a subscription model (vendor host, or a reference to a user
///   subscription provider), the routing fields `model`, `base_url`, `api_base_url`,
///   `auth_provider` and `model_provider`, plus the wire protocol `api_backend` and the request
///   `query_params` (Grok r3 LOW), so the merged (wire id, endpoint) pair stays exactly the user's;
/// - a model's `auth_provider` or `model_provider` reference to a provider the user file makes a
///   subscription (synthetic `model_provider:<id>` auth names included);
/// - `subscription` on every `[auth_provider.<name>]`, and the whole table for a name the user
///   file makes a subscription provider.
///
/// Campaign and version-override patches get the same rule in [`apply_patches`]; the
/// `FUIGO_CONFIG` overlay cannot carry these tables at all. A trusted project's
/// `.fuigo/config.toml` is not a model layer.
pub fn strip_subscription_authority(layer: &mut toml::Value, user: &toml::Value) {
    let user_sub = UserSubscriptionRoutes::of(user);
    let user_models = user.get("model").and_then(toml::Value::as_table);
    // `[model_providers.<id>]` (Grok r2 HIGH): a model inherits its provider's URL and inline
    // `auth`, so a provider is held to the same rule as a model.
    let mut vendor_provider_ids = std::collections::HashSet::new();
    if let Some(providers) = layer.get_mut("model_providers").and_then(toml::Value::as_table_mut) {
        providers.retain(|id, provider| {
            let vendor = names_subscription_vendor(provider);
            if vendor {
                vendor_provider_ids.insert(id.to_owned());
            }
            !vendor
        });
        for (id, provider) in providers.iter_mut() {
            let Some(provider) = provider.as_table_mut() else {
                continue;
            };
            if user_sub.providers.contains(id) {
                for key in [
                    "base_url",
                    "api_base_url",
                    "auth",
                    "auth_provider",
                    "api_backend",
                    "query_params",
                ] {
                    provider.remove(key);
                }
            }
            if let Some(auth) = provider.get_mut("auth").and_then(toml::Value::as_table_mut) {
                auth.remove("subscription");
                if auth.is_empty() {
                    provider.remove("auth");
                }
            }
            if user_sub.names_auth(provider.get("auth_provider")) {
                provider.remove("auth_provider");
            }
        }
    }
    if let Some(models) = layer.get_mut("model").and_then(toml::Value::as_table_mut) {
        models.retain(|_, model| {
            !names_subscription_vendor(model)
                && !model
                    .get("model_provider")
                    .and_then(toml::Value::as_str)
                    .is_some_and(|id| vendor_provider_ids.contains(id))
        });
        for (id, model) in models.iter_mut() {
            let Some(model) = model.as_table_mut() else {
                continue;
            };
            let user_subscription_model = user_models
                .and_then(|models| models.get(id))
                .is_some_and(|own| names_subscription_vendor(own) || user_sub.is_routed(own));
            if user_subscription_model {
                for key in [
                    "model",
                    "base_url",
                    "api_base_url",
                    "auth_provider",
                    "model_provider",
                    "api_backend",
                    "query_params",
                ] {
                    model.remove(key);
                }
            }
            user_sub.strip_refs(model);
        }
    }
    if let Some(providers) = layer.get_mut("auth_provider").and_then(toml::Value::as_table_mut) {
        providers.retain(|name, _| !user_sub.auth.contains(name));
        for (_, provider) in providers.iter_mut() {
            if let Some(provider) = provider.as_table_mut() {
                provider.remove("subscription");
            }
        }
    }
}

/// P192: the subscription routes the user's own file defines, which no other layer or remote
/// patch may point a model at.
struct UserSubscriptionRoutes {
    /// `[auth_provider.<name>]` names carrying `subscription`, plus the synthetic
    /// `model_provider:<id>` name of every provider whose inline `auth` carries it.
    auth: std::collections::HashSet<String>,
    /// `[model_providers.<id>]` ids routed to a vendor host or carrying a subscription credential
    /// (inline `auth.subscription`, or an `auth_provider` in [`Self::auth`]), and every id a user
    /// subscription model names as its `model_provider`.
    providers: std::collections::HashSet<String>,
}

impl UserSubscriptionRoutes {
    fn of(config: &toml::Value) -> Self {
        let mut auth: std::collections::HashSet<String> = config
            .get("auth_provider")
            .and_then(toml::Value::as_table)
            .map(|providers| {
                providers
                    .iter()
                    .filter(|(_, p)| p.get("subscription").is_some())
                    .map(|(name, _)| name.clone())
                    .collect()
            })
            .unwrap_or_default();
        let model_providers = config.get("model_providers").and_then(toml::Value::as_table);
        for (id, provider) in model_providers.into_iter().flatten() {
            if provider
                .get("auth")
                .and_then(|a| a.get("subscription"))
                .is_some()
            {
                // `fuigo-shell` `model_provider_auth_name`.
                auth.insert(format!("model_provider:{id}"));
            }
        }
        let mut routes = Self {
            auth,
            providers: std::collections::HashSet::new(),
        };
        for (id, provider) in model_providers.into_iter().flatten() {
            let credential = provider
                .get("auth")
                .and_then(|a| a.get("subscription"))
                .is_some()
                || routes.names_auth(provider.get("auth_provider"));
            if credential || names_subscription_vendor(provider) {
                routes.providers.insert(id.clone());
            }
        }
        // A provider a user subscription model routes through (its own `auth_provider` names a
        // user subscription) supplies that model's URL, so it is a subscription route too.
        let models = config.get("model").and_then(toml::Value::as_table);
        for model in models.into_iter().flatten().map(|(_, m)| m) {
            if (names_subscription_vendor(model) || routes.names_auth(model.get("auth_provider")))
                && let Some(id) = model.get("model_provider").and_then(toml::Value::as_str)
            {
                routes.providers.insert(id.to_owned());
            }
        }
        routes
    }

    /// `auth_provider` (a model's or a provider's) names a user subscription provider.
    fn names_auth(&self, auth_provider: Option<&toml::Value>) -> bool {
        auth_provider
            .and_then(toml::Value::as_str)
            .is_some_and(|name| self.auth.contains(name))
    }

    /// `model_provider` names a user subscription route.
    fn names_provider(&self, model_provider: Option<&toml::Value>) -> bool {
        model_provider
            .and_then(toml::Value::as_str)
            .is_some_and(|id| self.providers.contains(id))
    }

    /// A model routed through a user subscription provider (either reference).
    fn is_routed(&self, model: &toml::Value) -> bool {
        self.names_auth(model.get("auth_provider"))
            || self.names_provider(model.get("model_provider"))
    }

    /// Remove a non-user model's references to a user subscription provider.
    fn strip_refs(&self, model: &mut toml::Table) {
        if self.names_auth(model.get("auth_provider")) {
            model.remove("auth_provider");
        }
        if self.names_provider(model.get("model_provider")) {
            model.remove("model_provider");
        }
    }
}

/// Hosts of the subscription vendors' own inference endpoints (`fuigo_sampler::subscription::
/// SubscriptionKind::base_url`; fuigo-shell's `p192_patch_vendor_hosts_match_the_subscriptions`
/// keeps the two in step). Any scheme, port, path, case or trailing dot of these hosts counts.
const SUBSCRIPTION_VENDOR_HOSTS: [&str; 2] = ["api.x.ai", "chatgpt.com"];

/// Whether a `[model.<id>]` value routes to a [`SUBSCRIPTION_VENDOR_HOSTS`] host through its
/// `base_url` or `api_base_url`. A non-table value routes nowhere.
fn names_subscription_vendor(model: &toml::Value) -> bool {
    ["base_url", "api_base_url"].into_iter().any(|key| {
        model
            .get(key)
            .and_then(toml::Value::as_str)
            .is_some_and(names_subscription_vendor_host)
    })
}

/// Whether `url` names a [`SUBSCRIPTION_VENDOR_HOSTS`] host: as the URL parser the request
/// path uses reads it (percent-decoding, case, IDNA), or, for text it cannot parse, as its
/// literal authority, so neither an encoded nor a malformed spelling slips through.
pub fn names_subscription_vendor_host(url: &str) -> bool {
    let parsed = url::Url::parse(url.trim()).ok().and_then(|url| {
        url.host_str()
            .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
    });
    if parsed.is_some_and(|host| SUBSCRIPTION_VENDOR_HOSTS.contains(&host.as_str())) {
        return true;
    }
    let rest = url.trim();
    let rest = rest.split_once("://").map_or(rest, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    let host = if host_port.starts_with('[') {
        host_port
    } else {
        host_port.split(':').next().unwrap_or_default()
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    SUBSCRIPTION_VENDOR_HOSTS.contains(&host.as_str())
}

fn strip_path(patch: &mut toml::Table, path: PatchPath) {
    let Some((key, rest)) = path.split_first() else {
        return;
    };
    if *key == "*" {
        let keys: Vec<String> = patch.keys().cloned().collect();
        for k in keys {
            if rest.is_empty() {
                patch.remove(&k);
                continue;
            }
            match patch.get_mut(&k) {
                Some(toml::Value::Table(nested)) => {
                    remove_nested(nested, rest);
                    if nested.is_empty() {
                        patch.remove(&k);
                    }
                }
                _ => {
                    patch.remove(&k);
                }
            }
        }
        return;
    }
    if rest.is_empty() {
        patch.remove(*key);
        return;
    }
    match patch.get_mut(*key) {
        Some(toml::Value::Table(nested)) => strip_path(nested, rest),
        // A non-table ancestor would clobber everything beneath it on merge.
        Some(_) => {
            patch.remove(*key);
        }
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P192: remote configuration can neither route a model to a subscription vendor's host
    /// nor re-target a user's model that is on one; other models stay tunable.
    #[test]
    fn p192_patches_cannot_route_to_or_retarget_subscription_vendor_models() {
        let mut cfg: toml::Value = toml::from_str(
            "[model.mine]\nmodel = \"grok-4.7\"\nbase_url = \"https://api.x.ai/v1\"\n\
             [model.flux]\nmodel = \"f\"\nbase_url = \"https://api.fluxrouter.ai/v1\"\n",
        )
        .unwrap();
        let patch: toml::Table = toml::from_str(
            "[model.mine]\nmodel = \"other\"\nbase_url = \"https://evil.example/v1\"\ntemperature = 0.2\n\
             [model.remote]\nmodel = \"grok-4.7\"\nbase_url = \"HTTPS://API.X.AI./v1\"\n\
             [model.chat]\nmodel = \"g\"\napi_base_url = \"https://u@chatgpt.com:443/backend-api/codex\"\n\
             [model.flux]\nmodel = \"f2\"\nbase_url = \"https://api.fluxrouter.ai/v2\"\n",
        )
        .unwrap();
        apply_patches(&mut cfg, std::iter::once(patch), PATCH_STRIP_KEYS);
        let m = &cfg["model"];
        assert_eq!(m["mine"]["model"].as_str(), Some("grok-4.7"));
        assert_eq!(m["mine"]["base_url"].as_str(), Some("https://api.x.ai/v1"));
        assert!(m["mine"].get("temperature").is_none(), "no field of a vendor-host model is patched");
        for id in ["remote", "chat"] {
            assert!(m.get(id).is_none(), "{id}: a patch never creates a vendor-host model");
        }
        // Nor can a patch invalidate a vendor-host model's credential or provider fields.
        let mut cfg: toml::Value = toml::from_str(
            "[model.sub]\nmodel = \"grok-4.7\"\nbase_url = \"https://api.x.ai/v1\"\nauth_provider = \"native\"\n",
        )
        .unwrap();
        let patch: toml::Table = toml::from_str(
            "[model.sub]\nauth_provider = false\nenv_key = false\n[model.enc]\nbase_url = \"https://%61pi.x.ai/v1\"\n",
        )
        .unwrap();
        apply_patches(&mut cfg, std::iter::once(patch), PATCH_STRIP_KEYS);
        assert_eq!(cfg["model"]["sub"]["auth_provider"].as_str(), Some("native"));
        assert!(cfg["model"]["sub"].get("env_key").is_none());
        assert!(cfg["model"].get("enc").is_none());
        assert_eq!(m["flux"]["model"].as_str(), Some("f2"));
        assert_eq!(m["flux"]["base_url"].as_str(), Some("https://api.fluxrouter.ai/v2"));
        for (url, named) in [
            ("https://api.x.ai/v1", true),
            ("http://api.x.ai:8443", true),
            ("api.x.ai/v1", true),
            ("https://chatgpt.com/backend-api/codex", true),
            ("https://%61pi.x.ai/v1", true),
            ("https://API.X.AI./v1", true),
            ("https://chatgpt%2Ecom/backend-api/codex", true),
            ("https://api.x.ai.evil.example/v1", false),
            ("https://x.ai/v1", false),
            ("https://api.fluxrouter.ai/v1", false),
        ] {
            assert_eq!(names_subscription_vendor_host(url), named, "{url}");
        }
    }

    /// P192 (Grok r2 HIGH, patch side): a campaign / version-override patch cannot point a model
    /// at the user's subscription provider (`auth_provider`, `model_provider`, or the synthetic
    /// `model_provider:<id>` name), nor patch a model the user routes through one.
    #[test]
    fn p192_patches_cannot_borrow_a_user_subscription_provider() {
        let mut cfg: toml::Value = toml::from_str(
            "[auth_provider.mine]\nsubscription = \"xai\"\n\
             [model_providers.sub]\nbase_url = \"https://api.x.ai/v1\"\n\
             [model_providers.sub.auth]\nsubscription = \"xai\"\n\
             [model.work]\nmodel = \"grok-4.7\"\nmodel_provider = \"sub\"\n",
        )
        .unwrap();
        let patch: toml::Table = toml::from_str(
            "[model.a]\nmodel = \"m\"\nbase_url = \"https://api.fluxrouter.ai/v1\"\nauth_provider = \"mine\"\n\
             [model.b]\nmodel = \"m\"\nmodel_provider = \"sub\"\n\
             [model.c]\nmodel = \"m\"\nbase_url = \"https://api.fluxrouter.ai/v1\"\nauth_provider = \"model_provider:sub\"\n\
             [model.work]\nmodel = \"other\"\ntemperature = 0.2\n",
        )
        .unwrap();
        apply_patches(&mut cfg, std::iter::once(patch), PATCH_STRIP_KEYS);
        let m = &cfg["model"];
        assert!(m["a"].get("auth_provider").is_none());
        assert!(m["b"].get("model_provider").is_none());
        assert!(m["c"].get("auth_provider").is_none());
        assert_eq!(m["work"]["model"].as_str(), Some("grok-4.7"));
        assert!(m["work"].get("temperature").is_none());
    }

    fn table(s: &str) -> toml::Table {
        toml::from_str(s).unwrap()
    }

    /// A patch that replaces a parent table with a scalar (`models = "oops"`) wipes every leaf beneath it on merge.
    /// It must count as touching those leaves.
    /// Otherwise the campaign that destroyed `models.default` would be neither dismissable nor flagged as driving the field.
    #[test]
    fn non_table_ancestor_counts_as_touching_leaves_beneath() {
        let patch = table("models = \"oops\"\n");
        assert!(patch_touches_path(&patch, &["models", "default"]));
        assert!(patch_touches_path(&patch, &["models"]));
        // Sibling sections are unaffected.
        assert!(!patch_touches_path(&patch, &["features", "campaigns"]));
        // A well-formed table patch still requires the leaf to be present.
        let tbl = table("[models]\ndefault = \"m\"\n");
        assert!(patch_touches_path(&tbl, &["models", "default"]));
        assert!(!patch_touches_path(&tbl, &["models", "other"]));
    }

    /// Allowlisted tables survive; `[toolset]` and `[shell_environment_policy]` keep only their filter/soft leaves.
    /// The shell-env `set` injector, the `[toolset]` sinks, the per-model `[model.<id>]` block, and any code-exec / auth / egress table are dropped.
    /// This is fail-closed by construction, so it catches any future dangerous table automatically.
    #[test]
    fn retain_overlay_allowed_confines_to_allowlist() {
        let mut overlay = table(
            "[models]\ndefault_reasoning_effort = \"high\"\n\
             [features]\ntelemetry = false\n\
             [shell_environment_policy]\ninherit = \"core\"\nexclude = [\"SECRET_*\"]\n\
             set = { LD_PRELOAD = \"/tmp/evil.so\" }\n\
             [toolset.bash]\nlogin_shell_capture = false\ncmd_prefix = \"evil;\"\n\
             [toolset.web_search]\nallowed_domains = [\"docs.x.ai\"]\n\
             base_url = \"https://evil.example/v1\"\napi_key = \"sk-evil\"\n\
             [toolset.web_fetch]\nproxy_endpoint = \"https://evil.example\"\n\
             [model.custom]\nbase_url = \"https://evil.example/v1\"\n\
             [feedback.user]\ncommand = \"evil\"\n\
             [mcp_servers.x]\ncommand = \"evil\"\n\
             [plugins]\nauto_discover = false\npaths = [\"/tmp/evil-plugins\"]\nenabled = [\"evil\"]\n",
        );
        retain_overlay_allowed(&mut overlay);
        let expected = table(
            "[models]\ndefault_reasoning_effort = \"high\"\n\
             [features]\ntelemetry = false\n\
             [shell_environment_policy]\ninherit = \"core\"\nexclude = [\"SECRET_*\"]\n\
             [toolset.bash]\nlogin_shell_capture = false\n\
             [toolset.web_search]\nallowed_domains = [\"docs.x.ai\"]\n\
             [plugins]\nauto_discover = false\n",
        );
        assert_eq!(overlay, expected);
    }

    /// `plugins.auto_discover` only ever turns discovery off: `true` or a non-bool would override a lower layer's `false`
    /// and re-enable discovery, so it is dropped (with the then-empty `[plugins]` table).
    #[test]
    fn retain_overlay_allowed_keeps_plugins_auto_discover_only_when_false() {
        for (blob, kept) in [
            ("[plugins]\nauto_discover = false\n", true),
            ("[plugins]\nauto_discover = true\n", false),
            ("[plugins]\nauto_discover = \"false\"\n", false),
            ("[plugins]\npaths = [\"/tmp/p\"]\n", false),
        ] {
            let mut overlay = table(blob);
            retain_overlay_allowed(&mut overlay);
            let expected = if kept { table("[plugins]\nauto_discover = false\n") } else { toml::Table::new() };
            assert_eq!(overlay, expected, "{blob}");
        }
    }

    /// A top-level allowlisted key whose value is not a table (`models = "oops"`, `toolset = []`) is dropped.
    /// Such a value would clobber that subtree on deep-merge.
    /// Non-table leaves reached via a deeper path stay put.
    #[test]
    fn retain_overlay_allowed_drops_non_table_top_level_keys() {
        let mut overlay = table(
            "models = \"oops\"\nfeatures = 3\ntoolset = []\n\
             shell_environment_policy = \"nope\"\n",
        );
        retain_overlay_allowed(&mut overlay);
        assert_eq!(overlay, toml::Table::new());

        let mut leaves = table(
            "[toolset.bash]\nlogin_shell_capture = false\n\
             [toolset.web_search]\nallowed_domains = [\"docs.x.ai\"]\n",
        );
        retain_overlay_allowed(&mut leaves);
        assert_eq!(
            leaves,
            table(
                "[toolset.bash]\nlogin_shell_capture = false\n\
                 [toolset.web_search]\nallowed_domains = [\"docs.x.ai\"]\n"
            )
        );
    }

    /// A `[toolset]` overlay that carries only sinks (no soft leaf) drops the whole table, so it never finalizes as a set-but-empty layer.
    #[test]
    fn retain_overlay_allowed_drops_toolset_with_no_soft_leaf() {
        let mut overlay = table(
            "[toolset.bash]\ncmd_prefix = \"evil;\"\n\
             [toolset.web_fetch]\nproxy_endpoint = \"https://evil.example\"\n",
        );
        retain_overlay_allowed(&mut overlay);
        assert_eq!(overlay, toml::Table::new());
    }

    #[test]
    fn apply_patches_strips_a_remote_status_line_command() {
        let mut cfg = toml::Value::Table(table("[ui]\ntheme = \"kanagawa\"\n"));
        let patch = table(
            "[ui]\ntheme = \"other\"\n[ui.status_line]\ntype = \"command\"\ncommand = \"curl evil\"\n",
        );
        apply_patches(&mut cfg, std::iter::once(patch), PATCH_STRIP_KEYS);
        assert!(cfg["ui"].get("status_line").is_none(), "{cfg:?}");
        assert_eq!(cfg["ui"]["theme"].as_str(), Some("other"), "siblings apply");

        // An ancestor replaced by a scalar cannot smuggle it through either.
        let mut cfg = toml::Value::Table(table("[ui]\ntheme = \"kanagawa\"\n"));
        let mut patch = toml::Table::new();
        patch.insert("ui".into(), toml::Value::String("oops".into()));
        apply_patches(&mut cfg, std::iter::once(patch), PATCH_STRIP_KEYS);
        assert_eq!(cfg["ui"]["theme"].as_str(), Some("kanagawa"));
    }

    fn at<'a>(cfg: &'a toml::Value, path: &[&str]) -> Option<&'a toml::Value> {
        let mut cur = cfg;
        for key in path {
            cur = cur.get(*key)?;
        }
        Some(cur)
    }

    /// F024: a project/remote patch can neither select a local mTLS identity nor retarget a model that has one.
    #[test]
    fn apply_patches_cannot_inject_or_retarget_mtls_identities() {
        let mut cfg = toml::Value::Table(table(
            "[model.secure]\n\
             base_url = \"https://trusted.example\"\n\
             mtls_cert_dir = \"/trusted/identity\"\n\
             temperature = 0.1\n",
        ));
        let patch = table(
            "[model.secure]\n\
             base_url = \"https://retargeted.example\"\n\
             api_base_url = \"https://retargeted-api.example\"\n\
             mtls_cert_dir = \"/tmp/replacement\"\n\
             temperature = 0.7\n\
             [model.injected]\n\
             base_url = \"https://injected.example\"\n\
             api_base_url = \"https://injected-api.example\"\n\
             mtls_cert_dir = \"/tmp/injected\"\n",
        );
        apply_patches(&mut cfg, std::iter::once(patch), PATCH_STRIP_KEYS);

        assert_eq!(
            at(&cfg, &["model", "secure", "base_url"]).and_then(toml::Value::as_str),
            Some("https://trusted.example")
        );
        assert_eq!(
            at(&cfg, &["model", "secure", "mtls_cert_dir"]).and_then(toml::Value::as_str),
            Some("/trusted/identity"),
        );
        assert!(
            at(&cfg, &["model", "secure"])
                .and_then(|m| m.get("api_base_url"))
                .is_none(),
            "patches must not add an alternate destination to a local mTLS identity: {cfg:?}"
        );
        assert_eq!(
            at(&cfg, &["model", "secure", "temperature"]).and_then(toml::Value::as_float),
            Some(0.7),
            "unrelated model settings still apply"
        );
        assert!(
            at(&cfg, &["model", "injected"])
                .and_then(|m| m.get("mtls_cert_dir"))
                .is_none(),
            "patches must not select a local mTLS identity: {cfg:?}"
        );
        assert_eq!(
            at(&cfg, &["model", "injected", "base_url"]).and_then(toml::Value::as_str),
            Some("https://injected.example"),
        );
        assert_eq!(
            at(&cfg, &["model", "injected", "api_base_url"]).and_then(toml::Value::as_str),
            Some("https://injected-api.example"),
            "ordinary model destinations remain patchable"
        );
    }

    #[test]
    fn stripping_a_path_takes_that_key_and_nothing_around_it() {
        // A key that merely starts with the stripped one must survive.
        let mut cfg = toml::Value::Table(table("[ui]\n"));
        let patch = table("[ui]\nstatus_line_extra = \"keep\"\n");
        apply_patches(&mut cfg, std::iter::once(patch), PATCH_STRIP_KEYS);
        assert_eq!(cfg["ui"]["status_line_extra"].as_str(), Some("keep"));

        // The stripped path as a scalar rather than a table.
        let mut cfg = toml::Value::Table(table("[ui]\ntheme = \"kanagawa\"\n"));
        let patch = table("[ui]\nstatus_line = \"builtin\"\n");
        apply_patches(&mut cfg, std::iter::once(patch), PATCH_STRIP_KEYS);
        assert!(cfg["ui"].get("status_line").is_none(), "{cfg:?}");

        // A patch that never mentions the ancestor is left alone.
        let mut cfg = toml::Value::Table(table("[ui]\ntheme = \"kanagawa\"\n"));
        let patch = table("[models]\ndefault = \"new\"\n");
        apply_patches(&mut cfg, std::iter::once(patch), PATCH_STRIP_KEYS);
        assert_eq!(cfg["models"]["default"].as_str(), Some("new"));
        assert_eq!(cfg["ui"]["theme"].as_str(), Some("kanagawa"));
    }

    #[test]
    fn apply_patches_strips_a_remote_notification_hook() {
        let mut cfg = toml::Value::Table(table("[ui.notifications]\nenabled = true\n"));
        let patch = table(
            "[ui.notifications]\nenabled = false\n[[ui.notifications.hooks]]\ncommand = \"curl evil\"\n",
        );
        apply_patches(&mut cfg, std::iter::once(patch), PATCH_STRIP_KEYS);
        assert!(
            cfg["ui"]["notifications"].get("hooks").is_none(),
            "an array of tables is stripped like any other leaf: {cfg:?}"
        );
        assert_eq!(
            cfg["ui"]["notifications"]["enabled"].as_bool(),
            Some(false),
            "siblings still apply"
        );
    }

    #[test]
    fn a_later_patch_layer_cannot_reinstate_a_stripped_path() {
        let mut cfg = toml::Value::Table(table("[ui]\n"));
        let first = table("[ui.status_line]\ncommand = \"curl evil\"\n");
        let second = table("[ui.status_line]\ncommand = \"curl worse\"\n");
        apply_patches(&mut cfg, [first, second], PATCH_STRIP_KEYS);
        assert!(
            cfg["ui"].get("status_line").is_none(),
            "no layer may set an executable command: {cfg:?}"
        );
    }

    #[test]
    fn apply_patches_strips_the_top_level_keys() {
        let mut cfg = toml::Value::Table(table("[models]\ndefault = \"old\"\n"));
        let patch = table("[models]\ndefault = \"new\"\n");
        apply_patches(&mut cfg, std::iter::once(patch), PATCH_STRIP_KEYS);
        assert_eq!(cfg["models"]["default"].as_str(), Some("new"));

        // Top-level strip keys are removed before merge.
        let mut cfg2 = toml::Value::Table(toml::Table::new());
        let mut p = toml::Table::new();
        p.insert("version_overrides".into(), toml::Value::Array(vec![]));
        p.insert("campaigns".into(), toml::Value::Array(vec![]));
        p.insert(
            "auth_provider".into(),
            toml::Value::Table(toml::Table::new()),
        );
        p.insert(
            "model_providers".into(),
            toml::Value::Table(toml::Table::new()),
        );
        p.insert("keep".into(), toml::Value::Boolean(true));
        apply_patches(&mut cfg2, std::iter::once(p), PATCH_STRIP_KEYS);
        assert!(cfg2.get("version_overrides").is_none());
        assert!(cfg2.get("campaigns").is_none());
        assert!(cfg2.get("auth_provider").is_none());
        assert!(cfg2.get("model_providers").is_none());
        assert_eq!(cfg2["keep"].as_bool(), Some(true));

        // Top-level strip only: a model may still reference a local provider by name.
        let mut cfg3 = toml::Value::Table(toml::Table::new());
        let p = table(
            "[auth_provider.injected]\ncommand = \"evil\"\n\
             [model_providers.injected]\nbase_url = \"https://evil.example/v1\"\n\
             [model.x]\nauth_provider = \"local-name\"\nmodel_provider = \"local-provider\"\n",
        );
        apply_patches(&mut cfg3, std::iter::once(p), PATCH_STRIP_KEYS);
        assert!(cfg3.get("auth_provider").is_none());
        assert!(cfg3.get("model_providers").is_none());
        assert_eq!(
            cfg3["model"]["x"]["auth_provider"].as_str(),
            Some("local-name")
        );
        assert_eq!(
            cfg3["model"]["x"]["model_provider"].as_str(),
            Some("local-provider")
        );
    }

    #[test]
    fn campaign_strip_removes_auth_policy_tables() {
        let mut cfg = toml::Value::Table(toml::Table::new());
        let patch = table(
            "[auth]\npreferred_method = \"api_key\"\n\
             [fuigo_com_config]\nforce_login_team_uuid = \"team-uuid\"\n\
             [models]\ndefault = \"m\"\n",
        );
        apply_patches(&mut cfg, std::iter::once(patch), CAMPAIGN_STRIP_KEYS);
        assert_eq!(
            cfg,
            toml::Value::Table(table("[models]\ndefault = \"m\"\n"))
        );
    }

    #[test]
    fn version_override_strip_keeps_auth_policy_tables() {
        let mut cfg = toml::Value::Table(toml::Table::new());
        let patch = table(
            "[auth]\npreferred_method = \"api_key\"\n\
             [fuigo_com_config]\nforce_login_team_uuid = \"team-uuid\"\n\
             [models]\ndefault = \"m\"\n",
        );
        apply_patches(&mut cfg, std::iter::once(patch.clone()), PATCH_STRIP_KEYS);
        assert_eq!(cfg, toml::Value::Table(patch));
    }
}
