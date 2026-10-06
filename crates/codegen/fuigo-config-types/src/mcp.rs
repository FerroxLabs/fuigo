//! MCP server configuration value types, extracted from fuigo-shell so crates the shell depends on can use them.

use agent_client_protocol as acp;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use fuigo_mcp::oauth_config::McpOAuthConfig;

/// serde default helper.
fn default_true() -> bool {
    true
}

/// A credential an MCP server's config names by environment variable (P70a): an HTTP server's
/// `bearer_token_env_var`, and the OAuth `oauth_client_secret_env_var` / `[oauth] client_secret_env_var`. Resolved
/// through `fuigo_config`'s installable resolver, which the shell installs when it holds the user's saved first-party
/// key in memory: `FUIGO_API_KEY` then resolves to that key exactly where it used to be found in the agent's
/// environment (the agent no longer copies it there), and any other name reads the environment. Uninstalled, names
/// resolve via `std::env::var`. The same resolver serves explicit `${FUIGO_API_KEY}` references in config strings.
pub use fuigo_config::install_credential_env_resolver;

/// Read a credential variable an MCP server's config names. The name is denied to every child process from here on
/// (P113, E2), as P86 does for a model's `env_key`: the token belongs to the destination it is written for, not to the
/// model's shell, another server, a hook or a language server.
fn resolve_credential_env_var(var: &str) -> Option<String> {
    fuigo_tools::util::shell_env_policy::register_credential_env_names([var]);
    fuigo_config::resolve_credential_env_var(var)
}

/// Read an MCP OAuth client secret from the named env var. `McpServerConfig` is its only caller.
fn resolve_oauth_client_secret(env_var: Option<&String>) -> Option<String> {
    let env_var = env_var?;
    match resolve_credential_env_var(env_var) {
        Some(secret) => Some(secret),
        None => {
            tracing::warn!(
                env_var = env_var.as_str(),
                "MCP OAuth client_secret env var is configured but not set in the environment; \
                 proceeding without a client secret"
            );
            None
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum McpServerTransportConfig {
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        env: Option<HashMap<String, String>>,
        /// Standard MCP JSON supports `cwd`, but ACP stdio server config does not yet expose it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
    },
    StreamableHttp {
        // Not `default`: a missing url must fail to deserialize, not become a fake HTTP server with an empty url
        #[serde(alias = "urlTemplate", alias = "url_template")]
        url: String,
        #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
        transport_type: Option<String>,
        /// Name of the environment variable to read and set for `Authorization: Bearer <token>`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bearer_token_env_var: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        headers: Option<HashMap<String, String>>,
        /// OAuth client ID for providers that don't support Dynamic Client Registration.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        oauth_client_id: Option<String>,
        /// Name of the env var holding the OAuth client secret (for BYO credentials).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        oauth_client_secret_env_var: Option<String>,
        /// OAuth scopes to request during authorization.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        oauth_scopes: Option<Vec<String>>,
    },
}

/// `url` with userinfo, query and fragment replaced by `<redacted>` (P70): an MCP server URL may carry a key. A leaf-crate
/// copy of `fuigo_auth::redact_url`'s rule for the parts that matter here.
fn url_without_credentials(url: &str) -> String {
    // Fail closed on anything carrying userinfo or a backslash: transport parsers normalize odd spellings
    // (`https:/user:pw@host`, `\\`) that a string scan here could misread.
    if url.contains(['@', '\\']) {
        return "<redacted url>".to_owned();
    }
    match url.find(['?', '#']) {
        Some(i) => format!("{}{}<redacted>", &url[..i], &url[i..=i]),
        None => url.to_owned(),
    }
}

/// Hand-written `Debug` (P70): credential values print as `<redacted>` (headers and query parameters by name only), so a `{:?}` of this type in a log, panic or error cannot disclose them. MCP server `env` values and `args` often carry API keys, so they print by name / count only.
/// The destructures are exhaustive, so a new field fails to compile here until its Debug output is decided.
impl std::fmt::Debug for McpServerTransportConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stdio { command, args, env, cwd } => f
                .debug_struct("Stdio")
                .field("command", command)
                .field("args", &format_args!("<{} args redacted>", args.len()))
                .field("env", &env.as_ref().map(|m| m.keys().map(|k| (k, "<redacted>")).collect::<Vec<_>>()))
                .field("cwd", cwd)
                .finish(),
            Self::StreamableHttp { url, transport_type, bearer_token_env_var, headers, oauth_client_id, oauth_client_secret_env_var, oauth_scopes } => f
                .debug_struct("StreamableHttp")
                .field("url", &url_without_credentials(url))
                .field("transport_type", transport_type)
                .field("bearer_token_env_var", bearer_token_env_var)
                .field("headers", &headers.as_ref().map(|m| m.keys().map(|k| (k, "<redacted>")).collect::<Vec<_>>()))
                .field("oauth_client_id", oauth_client_id)
                .field("oauth_client_secret_env_var", oauth_client_secret_env_var)
                .field("oauth_scopes", oauth_scopes)
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum McpServerProblemSeverity {
    Error,
    Warning,
}

/// A problem found loading an `[mcp_servers.*]` entry. It is reported (never fatal) and shown by `fuigo inspect`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct McpServerConfigProblem {
    pub server: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub severity: McpServerProblemSeverity,
    pub message: String,
}

/// Recognized wire keys for an `[mcp_servers.*]` entry.
/// It exists because the flattened untagged transport enum bypasses `serde_ignored`.
/// `known_mcp_server_fields_cover_serialized_keys` keeps it in sync.
pub const KNOWN_MCP_SERVER_FIELDS: &[&str] = &[
    "args",
    "bearer_token_env_var",
    "command",
    "cwd",
    "enabled",
    "env",
    "expose_image_base64",
    "headers",
    "oauth",
    "oauth_client_id",
    "oauth_client_secret_env_var",
    "oauth_scopes",
    "setup",
    "startup_timeout_sec",
    "tool_timeout_sec",
    "tool_timeouts",
    "type",
    "url",
    // Deserialize-only aliases for `url`.
    "urlTemplate",
    "url_template",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpJsonOAuthBlock {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret_env_var: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpSetupConfig {
    #[serde(default)]
    pub fields: Vec<McpSetupField>,
    #[serde(default, alias = "values")]
    pub variables: HashMap<String, McpSetupDerivedValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpSetupField {
    pub id: String,
    pub label: String,
    #[serde(rename = "type")]
    pub field_type: McpSetupFieldType,
    #[serde(default)]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    #[serde(default)]
    pub options: Vec<McpSetupOption>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum McpSetupFieldType {
    Select,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpSetupOption {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpSetupDerivedValue {
    pub from: String,
    pub map: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct McpPreferenceSource {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct McpServerPreferences {
    #[serde(default)]
    pub values: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<McpPreferenceSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpPreferencesFile {
    pub version: u32,
    #[serde(default)]
    pub servers: HashMap<String, McpServerPreferences>,
}

impl Default for McpPreferencesFile {
    fn default() -> Self {
        Self {
            version: 1,
            servers: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum McpSetupResolution {
    Resolved(Box<McpServerConfig>),
    Required(McpSetupConfig),
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerConfig {
    #[serde(flatten)]
    pub transport: McpServerTransportConfig,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<McpJsonOAuthBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup: Option<McpSetupConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup_timeout_sec: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_timeout_sec: Option<u64>,
    /// Per-tool timeout overrides in seconds: `{ "create_issue" = 120, "search" = 30 }`.
    /// Tools not listed here fall back to `tool_timeout_sec`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_timeouts: Option<HashMap<String, u64>>,
    /// Also keep the raw base64 in tool-result text so agents can forward bytes via path-based tools (`base64 -d > /tmp/x.png && send_file ...`).
    /// It roughly doubles the tokens per image. `_meta.mcpConfig.<server>.exposeImageBase64` overrides it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expose_image_base64: Option<bool>,
    /// P118: this definition came from a source that may not name the saved API key (a project config, a plugin, a
    /// project `.mcp.json`). Set by the loader of such a source; it travels with the definition, and
    /// [`McpServerConfig::to_acp_mcp_server`] refuses every reference to the key in the final strings.
    /// Written only when set (P133): a definition an ACP client upserted is saved to the user's config, which may
    /// name the key, so the mark must survive the save or a value that composes a reference only under a different
    /// environment would be bound the key after a restart.
    #[serde(default, rename = "__fuigo_untrusted_source", skip_serializing_if = "std::ops::Not::not")]
    pub untrusted_source: bool,
}

impl McpServerConfig {
    /// The environment variables this config names as holding a credential: `bearer_token_env_var`,
    /// `oauth_client_secret_env_var` and `[oauth] client_secret_env_var`.
    pub fn credential_env_var_names(&self) -> Vec<&str> {
        let mut names = Vec::new();
        if let McpServerTransportConfig::StreamableHttp {
            bearer_token_env_var,
            oauth_client_secret_env_var,
            ..
        } = &self.transport
        {
            names.extend(bearer_token_env_var.as_deref());
            names.extend(oauth_client_secret_env_var.as_deref());
        }
        if let Some(block) = &self.oauth {
            names.extend(block.client_secret_env_var.as_deref());
        }
        names
    }

    /// Deny [`Self::credential_env_var_names`] to every child process spawned from now on (P113, E2). Called by the
    /// config loaders when they parse a server and before a server is built from this config, whether or not it is
    /// enabled: a stdio server started before the HTTP server that names a token must not inherit it either.
    pub fn deny_credential_env_vars_to_children(&self) {
        fuigo_tools::util::shell_env_policy::register_credential_env_names(
            self.credential_env_var_names(),
        );
    }

    /// The transport field (`command` or `url`) that is present but blank, if
    /// any. Such a server can never connect, so the loader drops it.
    pub fn blank_transport_field(&self) -> Option<&'static str> {
        match &self.transport {
            McpServerTransportConfig::Stdio { command, .. } if command.trim().is_empty() => {
                Some("command")
            }
            McpServerTransportConfig::StreamableHttp { url, .. } if url.trim().is_empty() => {
                Some("url")
            }
            _ => None,
        }
    }
}

fn render_setup_template(
    input: &str,
    variables: &HashMap<String, String>,
) -> Result<String, String> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("{{") {
        let (prefix, after_start) = rest.split_at(start);
        out.push_str(prefix);
        let after_start = &after_start[2..];
        let Some(end) = after_start.find("}}") else {
            return Err("unterminated setup variable template".to_string());
        };
        let key = after_start[..end].trim();
        let Some(value) = variables.get(key) else {
            return Err(format!("unresolved setup variable '{key}'"));
        };
        out.push_str(value);
        rest = &after_start[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

fn render_setup_templates(
    config: &mut McpServerConfig,
    variables: &HashMap<String, String>,
) -> Result<(), String> {
    let sub = |s: &str| render_setup_template(s, variables);
    match &mut config.transport {
        McpServerTransportConfig::Stdio {
            command,
            args,
            env,
            cwd,
        } => {
            *command = sub(command)?;
            for arg in args.iter_mut() {
                *arg = sub(arg)?;
            }
            if let Some(env) = env.as_mut() {
                for value in env.values_mut() {
                    *value = sub(value)?;
                }
            }
            if let Some(cwd) = cwd.as_mut() {
                *cwd = sub(cwd)?;
            }
        }
        McpServerTransportConfig::StreamableHttp { url, headers, .. } => {
            *url = sub(url)?;
            if let Some(headers) = headers.as_mut() {
                for value in headers.values_mut() {
                    *value = sub(value)?;
                }
            }
        }
    }
    Ok(())
}

impl McpServerConfig {
    /// Resolve `setup` templates using stored preferences.
    ///
    /// v0 supports exactly one select field with options. Multi-field schemas are Invalid until the TUI can collect them.
    pub fn resolve_setup(&self, preferences: Option<&McpServerPreferences>) -> McpSetupResolution {
        let Some(setup) = self.setup.as_ref() else {
            return McpSetupResolution::Resolved(Box::new(self.clone()));
        };

        if setup.fields.len() != 1 {
            return McpSetupResolution::Invalid(
                "setup schema must declare exactly one select field (v0)".to_string(),
            );
        }
        let field = &setup.fields[0];
        if !matches!(field.field_type, McpSetupFieldType::Select) || field.options.is_empty() {
            return McpSetupResolution::Invalid(
                "setup field must be a non-empty select (v0)".to_string(),
            );
        }

        let Some(preferences) = preferences else {
            return McpSetupResolution::Required(setup.clone());
        };

        let Some(value) = preferences.values.get(&field.id) else {
            return McpSetupResolution::Required(setup.clone());
        };
        if !field.options.iter().any(|option| option.value == *value) {
            return McpSetupResolution::Required(setup.clone());
        }

        let mut variables = HashMap::new();
        for (name, derived) in &setup.variables {
            if derived.from != field.id {
                return McpSetupResolution::Invalid(format!(
                    "setup variable '{name}' references unknown field '{}'",
                    derived.from
                ));
            }
            let Some(mapped) = derived.map.get(value) else {
                return McpSetupResolution::Required(setup.clone());
            };
            variables.insert(name.clone(), mapped.clone());
        }

        let mut resolved = self.clone();
        resolved.setup = None;
        match render_setup_templates(&mut resolved, &variables) {
            Ok(()) => McpSetupResolution::Resolved(Box::new(resolved)),
            Err(e) => McpSetupResolution::Invalid(e),
        }
    }

    pub fn expand_strings(&mut self, sub: &dyn Fn(&str) -> String) {
        match &mut self.transport {
            McpServerTransportConfig::Stdio {
                command,
                args,
                env,
                cwd,
            } => {
                // P147: `command` and `cwd` never receive the saved key, so a `${FUIGO_API_KEY:-default}` there is its
                // default (as without a key in 1.0.20); `args` and `env` keep it for the spawn to resolve.
                *command = fuigo_config::apply_first_party_key_defaults(&sub(command)).into_owned();
                for arg in args.iter_mut() {
                    *arg = sub(arg);
                }
                if let Some(env) = env.as_mut() {
                    for value in env.values_mut() {
                        *value = sub(value);
                    }
                }
                if let Some(cwd) = cwd.as_mut() {
                    *cwd = fuigo_config::apply_first_party_key_defaults(&sub(cwd)).into_owned();
                }
            }
            McpServerTransportConfig::StreamableHttp { url, headers, .. } => {
                *url = fuigo_config::apply_first_party_key_defaults(&sub(url)).into_owned();
                if let Some(headers) = headers.as_mut() {
                    for value in headers.values_mut() {
                        *value = sub(value);
                    }
                }
            }
        }
    }

    /// This definition with every reference to the saved API key removed, when it came from an untrusted source. It
    /// runs on the FINAL strings (after setup, version overrides and `$VAR` expansion), the last point before a spawn.
    /// `None` when the cleaned definition cannot be rebuilt: fail closed.
    fn refused_for_untrusted_source(&self, name: &str) -> Option<McpServerConfig> {
        self.refused_for_untrusted_source_reported(name, fuigo_config::key_naming::report_refusals)
    }

    /// [`Self::refused_for_untrusted_source`], recording the refusals with `report` (the note wording depends on the source).
    fn refused_for_untrusted_source_reported(
        &self,
        name: &str,
        report: fn(&[fuigo_config::key_naming::RefusedKeyReference]),
    ) -> Option<McpServerConfig> {
        let mut json = serde_json::to_value(self).ok()?;
        let label = format!("MCP server `{name}`");
        let mut refused = fuigo_config::key_naming::refuse_key_references_in_server_json(&mut json, &label);
        // P136 (Astra r1 #3): text that only became the key's VALUE on expansion (a persisted `${SWITCH:-$}{FUIGO_API_KEY}`
        // loaded while the key is exported) holds no reference: remove the value too.
        refused.extend(fuigo_config::key_naming::refuse_key_values_in_server_json(&mut json, &label));
        if refused.is_empty() {
            return Some(self.clone());
        }
        report(&refused);
        let mut cleaned: McpServerConfig = serde_json::from_value(json).ok()?;
        cleaned.untrusted_source = true;
        Some(cleaned)
    }

    /// This definition as a source that may not name the saved key would have it: marked untrusted, every reference to
    /// the saved key removed (with a recorded note). For a server an ACP client hands over (`mcp/upsert`), whose origin
    /// is not the user's own config file. `None` when the cleaned definition cannot be rebuilt: fail closed.
    pub fn without_saved_key_references(&self, name: &str) -> Option<McpServerConfig> {
        let mut marked = self.clone();
        marked.untrusted_source = true;
        // P152: the notes name this source (`/mcps` Add or an editor) and give the remedy that fits it.
        let mut cleaned = marked.refused_for_untrusted_source_reported(
            name,
            fuigo_config::key_naming::report_added_server_refusals,
        )?;
        // The cleaned definition may be written to the user's own config, which is loaded with `$VAR` expansion and may
        // name the key: a value that composes a reference only when expanded must not get there.
        let mut json = serde_json::to_value(&cleaned).ok()?;
        let refused = fuigo_config::key_naming::refuse_composed_key_references_in_server_json(
            &mut json,
            &format!("MCP server `{name}`"),
            &fuigo_config::expand_env_vars_in_string,
        );
        if !refused.is_empty() {
            fuigo_config::key_naming::report_added_server_refusals(&refused);
            cleaned = serde_json::from_value(json).ok()?;
            cleaned.untrusted_source = true;
        }
        Some(cleaned)
    }

    pub fn to_acp_mcp_server(&self, name: impl Into<String>) -> Option<acp::McpServer> {
        if self.untrusted_source {
            let name: String = name.into();
            let cleaned = self.refused_for_untrusted_source(&name)?;
            return cleaned.to_acp_mcp_server_inner(name);
        }
        self.to_acp_mcp_server_inner(name)
    }

    fn to_acp_mcp_server_inner(&self, name: impl Into<String>) -> Option<acp::McpServer> {
        self.deny_credential_env_vars_to_children();
        if !self.enabled || self.setup.is_some() {
            return None;
        }
        let name = name.into();
        match &self.transport {
            McpServerTransportConfig::Stdio {
                command,
                args,
                env,
                cwd: _,
            } => {
                let env_variables: Vec<acp::EnvVariable> = env
                    .as_ref()
                    .map(|e| {
                        e.iter()
                            .map(|(k, v)| acp::EnvVariable::new(k.clone(), v.clone()))
                            .collect()
                    })
                    .unwrap_or_default();

                Some(acp::McpServer::Stdio(
                    acp::McpServerStdio::new(name, PathBuf::from(command))
                        .args(args.clone())
                        .env(env_variables),
                ))
            }
            McpServerTransportConfig::StreamableHttp {
                url,
                transport_type,
                bearer_token_env_var,
                headers,
                ..
            } => {
                if url.is_empty() {
                    return None;
                }
                let mut http_headers: Vec<acp::HttpHeader> = headers
                    .as_ref()
                    .map(|h| {
                        h.iter()
                            .map(|(k, v)| acp::HttpHeader::new(k.clone(), v.clone()))
                            .collect()
                    })
                    .unwrap_or_default();

                // Add bearer token from environment variable if specified
                if let Some(env_var) = bearer_token_env_var {
                    match self.credential_from_env_var(env_var) {
                        Some(token) => {
                            http_headers.push(acp::HttpHeader::new(
                                "Authorization",
                                format!("Bearer {}", token),
                            ));
                        }
                        None => {
                            tracing::warn!(
                                "MCP server '{}': bearer_token_env_var '{}' not set in environment",
                                name,
                                env_var
                            );
                        }
                    }
                }

                let is_sse = transport_type
                    .as_deref()
                    .is_some_and(|transport| transport.eq_ignore_ascii_case("sse"))
                    || url.ends_with("/sse");

                Some(if is_sse {
                    acp::McpServer::Sse(
                        acp::McpServerSse::new(name, url.clone()).headers(http_headers),
                    )
                } else {
                    acp::McpServer::Http(
                        acp::McpServerHttp::new(name, url.clone()).headers(http_headers),
                    )
                })
            }
        }
    }

    /// The credential the variable `var` names, as this definition may have it (P136, Astra r3 #1). Every place a
    /// definition's own field becomes a credential (`bearer_token_env_var`, both OAuth client-secret variables) reads
    /// it through here. A definition from a source that may not name the saved API key (`untrusted_source`) never
    /// gets the key: not by its name (also after any later `$VAR` expansion of the selector, which ran before this
    /// point), and not by another variable that holds the same value.
    fn credential_from_env_var(&self, var: &str) -> Option<String> {
        if self.untrusted_source && fuigo_config::key_naming::names_saved_key(var) {
            tracing::warn!(env_var = var, "an untrusted MCP server definition names the saved API key as a credential; ignored");
            return None;
        }
        let value = resolve_credential_env_var(var)?;
        // The value may hold the key, or a reference a destination would still resolve to it (`${FUIGO_API_KEY}` as the
        // text of another variable, Astra P136 r1 #2): either is the key.
        if self.untrusted_source && fuigo_config::key_naming::holds_saved_key(&value) {
            tracing::warn!(env_var = var, "an untrusted MCP server definition's credential holds the saved API key; ignored");
            return None;
        }
        Some(value)
    }

    /// [`resolve_oauth_client_secret`] through [`Self::credential_from_env_var`].
    fn oauth_client_secret(&self, env_var: Option<&String>) -> Option<String> {
        let env_var = env_var?;
        if self.untrusted_source {
            return self.credential_from_env_var(env_var);
        }
        resolve_oauth_client_secret(Some(env_var))
    }

    /// Extract OAuth configuration for this server, if any OAuth fields are set. The client secret honours the
    /// definition's provenance (P136): see [`Self::credential_from_env_var`].
    pub fn oauth_config(&self) -> Option<McpOAuthConfig> {
        self.deny_credential_env_vars_to_children();
        if let McpServerTransportConfig::StreamableHttp {
            oauth_client_id,
            oauth_client_secret_env_var,
            oauth_scopes,
            ..
        } = &self.transport
            && oauth_client_id.is_some()
        {
            return Some(McpOAuthConfig {
                client_id: oauth_client_id.clone(),
                client_secret: self.oauth_client_secret(oauth_client_secret_env_var.as_ref()),
                scopes: oauth_scopes.clone(),
                callback_port: None,
            });
        }

        if let Some(block) = &self.oauth
            && block.client_id.is_some()
        {
            return Some(McpOAuthConfig {
                client_id: block.client_id.clone(),
                client_secret: self.oauth_client_secret(block.client_secret_env_var.as_ref()),
                scopes: block.scopes.clone(),
                callback_port: block.callback_port,
            });
        }

        None
    }
}

/// Configuration for relay session sharing, set in config.toml under the `[relay]` section.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelaySyncConfig {
    pub enabled: Option<bool>,
}

impl RelaySyncConfig {
    /// Check if relay sync is enabled. `FUIGO_RELAY_SYNC_ENABLED` takes precedence over config.
    pub fn is_enabled(&self) -> bool {
        if let Ok(env_val) = std::env::var("FUIGO_RELAY_SYNC_ENABLED") {
            return env_val.eq_ignore_ascii_case("true") || env_val == "1";
        }
        self.enabled.unwrap_or(false)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct McpConfig {
    #[serde(default, rename = "mcpServers")]
    pub mcp_servers: IndexMap<String, McpServerConfig>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site_select_setup_json() -> &'static str {
        r#"{
            "mcpServers": {
                "acme": {
                    "type": "http",
                    "urlTemplate": "{{url}}",
                    "setup": {
                        "fields": [{
                            "id": "site",
                            "label": "Site",
                            "type": "select",
                            "required": true,
                            "default": "us1",
                            "options": [
                                {"label": "US1", "value": "us1"},
                                {"label": "US5", "value": "us5"}
                            ]
                        }],
                        "values": {
                            "url": {
                                "from": "site",
                                "map": {
                                    "us1": "https://mcp.example.com/v1/mcp",
                                    "us5": "https://mcp.us5.example.com/v1/mcp"
                                }
                            }
                        }
                    }
                }
            }
        }"#
    }

    #[test]
    fn transport_less_entry_fails_to_deserialize() {
        for value in [
            serde_json::json!({ "enabled": false }),
            serde_json::json!({ "enabled": true }),
            serde_json::json!({}),
        ] {
            assert!(
                serde_json::from_value::<McpServerConfig>(value.clone()).is_err(),
                "transport-less entry must not deserialize: {value}"
            );
        }
    }

    #[test]
    fn blank_transport_field_is_detected_symmetrically() {
        let blank_url: McpServerConfig =
            serde_json::from_value(serde_json::json!({ "url": "  " })).unwrap();
        assert_eq!(blank_url.blank_transport_field(), Some("url"));

        let blank_command: McpServerConfig =
            serde_json::from_value(serde_json::json!({ "command": "\t" })).unwrap();
        assert_eq!(blank_command.blank_transport_field(), Some("command"));

        let ok: McpServerConfig =
            serde_json::from_value(serde_json::json!({ "command": "npx" })).unwrap();
        assert_eq!(ok.blank_transport_field(), None);
    }

    /// A newly added field cannot silently escape `KNOWN_MCP_SERVER_FIELDS`.
    #[test]
    fn known_mcp_server_fields_cover_serialized_keys() {
        let stdio = McpServerConfig {
            transport: McpServerTransportConfig::Stdio {
                command: "npx".into(),
                args: vec!["-y".into()],
                env: Some(HashMap::from([("A".into(), "b".into())])),
                cwd: Some("/tmp".into()),
            },
            enabled: true,
            oauth: Some(McpJsonOAuthBlock::default()),
            setup: None,
            startup_timeout_sec: Some(10),
            tool_timeout_sec: Some(20),
            tool_timeouts: Some(HashMap::from([("t".into(), 1)])),
            expose_image_base64: Some(true),
            untrusted_source: false,
        };
        let http = McpServerConfig {
            transport: McpServerTransportConfig::StreamableHttp {
                url: "https://x/mcp".into(),
                transport_type: Some("http".into()),
                bearer_token_env_var: Some("TOK".into()),
                headers: Some(HashMap::from([("H".into(), "v".into())])),
                oauth_client_id: Some("id".into()),
                oauth_client_secret_env_var: Some("SEC".into()),
                oauth_scopes: Some(vec!["s".into()]),
            },
            enabled: true,
            oauth: None,
            setup: None,
            startup_timeout_sec: None,
            tool_timeout_sec: None,
            tool_timeouts: None,
            expose_image_base64: None,
            untrusted_source: false,
        };
        for config in [stdio, http] {
            let value = serde_json::to_value(&config).unwrap();
            for key in value.as_object().unwrap().keys() {
                assert!(
                    KNOWN_MCP_SERVER_FIELDS.contains(&key.as_str()),
                    "field `{key}` is serialized but missing from KNOWN_MCP_SERVER_FIELDS"
                );
            }
        }
    }

    #[test]
    fn stdio_and_http_still_parse() {
        let stdio: McpServerConfig = serde_json::from_value(serde_json::json!({
            "command": "npx",
            "args": ["-y", "pkg"]
        }))
        .unwrap();
        assert!(stdio.enabled);
        assert!(matches!(
            stdio.transport,
            McpServerTransportConfig::Stdio { .. }
        ));

        let http: McpServerConfig = serde_json::from_value(serde_json::json!({
            "url": "https://mcp.example.com/mcp"
        }))
        .unwrap();
        assert!(matches!(
            http.transport,
            McpServerTransportConfig::StreamableHttp { .. }
        ));
        assert!(http.to_acp_mcp_server("x").is_some());
    }

    #[test]
    fn mcp_setup_schema_parses_and_missing_preference_requires_setup() {
        let config: McpConfig = serde_json::from_str(site_select_setup_json()).unwrap();
        let server = config.mcp_servers.get("acme").unwrap();
        let setup = server.setup.as_ref().unwrap();
        assert_eq!(setup.fields[0].id, "site");
        assert_eq!(setup.fields[0].default.as_deref(), Some("us1"));
        assert!(setup.variables.contains_key("url"));
        assert!(matches!(
            server.resolve_setup(None),
            McpSetupResolution::Required(_)
        ));
        assert!(server.to_acp_mcp_server("acme").is_none());
    }

    #[test]
    fn mcp_setup_valid_preference_resolves_mapped_url() {
        let config: McpConfig = serde_json::from_str(site_select_setup_json()).unwrap();
        let server = config.mcp_servers.get("acme").unwrap();
        let prefs = McpServerPreferences {
            values: HashMap::from([("site".to_string(), "us5".to_string())]),
            source: None,
            updated_at: None,
        };
        let resolved = match server.resolve_setup(Some(&prefs)) {
            McpSetupResolution::Resolved(config) => config,
            other => panic!("expected resolved config, got {other:?}"),
        };
        assert!(resolved.setup.is_none());
        assert!(resolved.to_acp_mcp_server("acme").is_some());
        match &resolved.transport {
            McpServerTransportConfig::StreamableHttp { url, .. } => {
                assert_eq!(url, "https://mcp.us5.example.com/v1/mcp");
            }
            _ => panic!("expected http config"),
        }
    }

    #[test]
    fn mcp_setup_invalid_preference_value_requires_setup() {
        let setup = McpSetupConfig {
            fields: vec![McpSetupField {
                id: "site".into(),
                label: "Site".into(),
                field_type: McpSetupFieldType::Select,
                required: true,
                default: Some("us1".into()),
                options: vec![McpSetupOption {
                    label: "US1".into(),
                    value: "us1".into(),
                }],
            }],
            variables: HashMap::new(),
        };
        let config = McpServerConfig {
            transport: McpServerTransportConfig::StreamableHttp {
                url: "{{url}}".into(),
                transport_type: None,
                bearer_token_env_var: None,
                headers: None,
                oauth_client_id: None,
                oauth_client_secret_env_var: None,
                oauth_scopes: None,
            },
            enabled: true,
            oauth: None,
            setup: Some(setup),
            startup_timeout_sec: None,
            tool_timeout_sec: None,
            tool_timeouts: None,
            expose_image_base64: None,
            untrusted_source: false,
        };
        let prefs = McpServerPreferences {
            values: HashMap::from([("site".to_string(), "us5".to_string())]),
            source: None,
            updated_at: None,
        };
        assert!(matches!(
            config.resolve_setup(Some(&prefs)),
            McpSetupResolution::Required(_)
        ));
    }

    #[test]
    fn mcp_setup_multi_field_schema_is_invalid() {
        let setup = McpSetupConfig {
            fields: vec![
                McpSetupField {
                    id: "a".into(),
                    label: "A".into(),
                    field_type: McpSetupFieldType::Select,
                    required: true,
                    default: None,
                    options: vec![McpSetupOption {
                        label: "1".into(),
                        value: "1".into(),
                    }],
                },
                McpSetupField {
                    id: "b".into(),
                    label: "B".into(),
                    field_type: McpSetupFieldType::Select,
                    required: true,
                    default: None,
                    options: vec![McpSetupOption {
                        label: "2".into(),
                        value: "2".into(),
                    }],
                },
            ],
            variables: HashMap::new(),
        };
        let config = McpServerConfig {
            transport: McpServerTransportConfig::StreamableHttp {
                url: "https://example.com".into(),
                transport_type: None,
                bearer_token_env_var: None,
                headers: None,
                oauth_client_id: None,
                oauth_client_secret_env_var: None,
                oauth_scopes: None,
            },
            enabled: true,
            oauth: None,
            setup: Some(setup),
            startup_timeout_sec: None,
            tool_timeout_sec: None,
            tool_timeouts: None,
            expose_image_base64: None,
            untrusted_source: false,
        };
        assert!(matches!(
            config.resolve_setup(None),
            McpSetupResolution::Invalid(_)
        ));
        assert!(config.to_acp_mcp_server("x").is_none());
    }
}

#[cfg(test)]
mod p70_redacted_debug {
    use super::*;

    /// `{x:?}` and `{x:#?}` hold `<redacted>` (control) and no fragment of any secret.
    fn assert_redacted(debug: &dyn std::fmt::Debug, secrets: &[&str]) {
        for out in [format!("{debug:?}"), format!("{debug:#?}")] {
            assert!(out.contains("<redacted>"), "control: the secret field is printed as redacted: {out}");
            for secret in secrets {
                let chars: Vec<char> = secret.chars().collect();
                for w in chars.windows(6) {
                    let frag: String = w.iter().collect();
                    assert!(!out.contains(&frag), "Debug output holds {frag:?} of a secret: {out}");
                }
            }
        }
    }

    /// The resolver this test installs: one variable answers from "memory", every other name reads the environment.
    /// It also answers the saved key (`FUIGO_API_KEY`) and an alias holding the same value, for the P136 tests: the
    /// resolver is installed once per process, so every test of this binary installs this one.
    pub(super) fn p70a_resolver(var: &str) -> Option<String> {
        match var {
            "P70A_MCP_BEARER_TEST_VAR" => Some("p70a-FAKE-resolved-bearer".to_owned()),
            "FUIGO_API_KEY" | "P136_ALIAS_OF_THE_KEY" => Some(super::p136_tests::SAVED_KEY.to_owned()),
            "P136_HOLDS_THE_KEY" => Some(format!("prefix-{}", super::p136_tests::SAVED_KEY)),
            "P136_LITERAL_REFERENCE" => Some("${FUIGO_API_KEY}".to_owned()),
            _ => std::env::var(var).ok(),
        }
    }

    /// P70a (Astra r3, r4): `bearer_token_env_var` and both OAuth client-secret variables resolve through the
    /// installed resolver, so the shell can answer `FUIGO_API_KEY` from the key it holds in memory (it is no longer
    /// copied into the environment). The variable is set nowhere in the environment, so only the resolver can supply
    /// the value.
    #[test]
    fn credential_env_vars_resolve_through_the_installed_resolver() {
        assert!(std::env::var_os("P70A_MCP_BEARER_TEST_VAR").is_none(), "precondition: not in the environment");
        install_credential_env_resolver(p70a_resolver);
        let server = McpServerConfig {
            transport: McpServerTransportConfig::StreamableHttp {
                url: "https://mcp.p70.invalid/mcp".into(),
                transport_type: None,
                bearer_token_env_var: Some("P70A_MCP_BEARER_TEST_VAR".into()),
                headers: None,
                oauth_client_id: None,
                oauth_client_secret_env_var: None,
                oauth_scopes: None,
            },
            enabled: true,
            oauth: None,
            setup: None,
            startup_timeout_sec: None,
            tool_timeout_sec: None,
            tool_timeouts: None,
            expose_image_base64: None,
            untrusted_source: false,
        };
        let Some(acp::McpServer::Http(http)) = server.to_acp_mcp_server("p70a") else {
            panic!("an HTTP MCP server");
        };
        let auth: Vec<&acp::HttpHeader> = http.headers.iter().filter(|h| h.name == "Authorization").collect();
        assert_eq!(auth.len(), 1, "one Authorization header: {:?}", http.headers.len());
        assert_eq!(auth[0].value, "Bearer p70a-FAKE-resolved-bearer");
        // The OAuth client secret, flat and in the `[oauth]` block.
        let flat = McpServerConfig {
            transport: McpServerTransportConfig::StreamableHttp {
                url: "https://mcp.p70.invalid/mcp".into(),
                transport_type: None,
                bearer_token_env_var: None,
                headers: None,
                oauth_client_id: Some("p70a-client".into()),
                oauth_client_secret_env_var: Some("P70A_MCP_BEARER_TEST_VAR".into()),
                oauth_scopes: None,
            },
            ..server.clone()
        };
        let secret = flat.oauth_config().and_then(|c| c.client_secret);
        assert_eq!(secret.as_deref(), Some("p70a-FAKE-resolved-bearer"), "oauth_client_secret_env_var");
        let block: McpServerConfig = serde_json::from_value(serde_json::json!({
            "url": "https://mcp.p70.invalid/mcp",
            "oauth": { "clientId": "p70a-client", "clientSecretEnvVar": "P70A_MCP_BEARER_TEST_VAR" }
        }))
        .expect("an [oauth] block");
        let secret = block.oauth_config().and_then(|c| c.client_secret);
        assert_eq!(secret.as_deref(), Some("p70a-FAKE-resolved-bearer"), "[oauth] client_secret_env_var");
    }

    /// P70 (Astra r1): MCP server env values, args and headers routinely carry API keys.
    #[test]
    fn mcp_transport_debug_redacts_env_args_and_headers() {
        let stdio = McpServerTransportConfig::Stdio {
            command: "p70-server".into(),
            args: vec!["--token".into(), "p70ma-FAKE-3e4f5a6b".into()],
            env: Some([("P70_TOKEN".to_owned(), "p70me-FAKE-7c8d9e0f".to_owned())].into_iter().collect()),
            cwd: None,
        };
        assert_redacted(&stdio, &["p70ma-FAKE-3e4f5a6b", "p70me-FAKE-7c8d9e0f"]);
        let http = McpServerTransportConfig::StreamableHttp {
            url: "https://p70u:p70mu-FAKE-5b6c7d8e@p70.invalid/mcp/@team?key=p70mq-FAKE-9f0a1b2c".into(),
            transport_type: None,
            bearer_token_env_var: Some("P70_ENV_NAME".into()),
            headers: Some([("Authorization".to_owned(), "Bearer p70mh-FAKE-1a2b3c4d".to_owned())].into_iter().collect()),
            oauth_client_id: None,
            oauth_client_secret_env_var: None,
            oauth_scopes: None,
        };
        assert_redacted(&http, &["p70mh-FAKE-1a2b3c4d", "p70mu-FAKE-5b6c7d8e", "p70mq-FAKE-9f0a1b2c"]);
    }
}

#[cfg(test)]
#[path = "mcp_p136_tests.rs"]
mod p136_tests;
