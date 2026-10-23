use fuigo_config_types::McpServerConfig;

/// Which `[paths]` field a [`ImportableItem::PathEntry`] populates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// `[paths] extra_skill_dirs`.
    Skill,
    /// `[paths] extra_rule_dirs`.
    Rule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportRuleAction {
    Allow,
    Deny,
    Ask,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportTool {
    Any,
    Bash,
    Edit,
    Read,
    Grep,
    Mcp,
    WebFetch,
    WebSearch,
    AgentMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportPatternMode {
    Glob,
    Domain,
}

/// One permission rule, in the shape the compact `[permission]` lists store it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportPermission {
    pub action: ImportRuleAction,
    pub tool: ImportTool,
    pub pattern: Option<String>,
    pub pattern_mode: ImportPatternMode,
}

/// What the caller read from one source settings file: its permission rules (already parsed; the caller owns the
/// rule grammar) and its environment variables.
#[derive(Clone, Default)]
pub struct ClaudeSettingsSnapshot {
    pub permissions: Vec<ImportPermission>,
    /// In the order they should be imported.
    pub env: Vec<(String, String)>,
}

/// `Debug` prints the variable NAMES only: the values are often API keys.
impl std::fmt::Debug for ClaudeSettingsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.env.iter().map(|(name, _)| name.as_str()).collect();
        f.debug_struct("ClaudeSettingsSnapshot")
            .field("permissions", &self.permissions)
            .field("env_names", &names)
            .finish()
    }
}

/// How an imported environment variable value is shown in any user-facing surface (CLI summary, TUI modal):
/// its length only, since values are often API keys. The one definition; do not format a value elsewhere.
#[must_use]
pub fn redacted_env_value(value: &str) -> String {
    format!("<redacted, {} chars>", value.len())
}

/// A single item that can be imported.
#[derive(Clone)]
pub enum ImportableItem {
    /// A permission rule (allow/deny/ask).
    Permission(ImportPermission),
    /// An environment variable.
    EnvVar { key: String, value: String },
    /// An MCP server configuration.
    McpServer {
        name: String,
        config: Box<McpServerConfig>,
    },
    /// A single hook (one event, matcher and command, derived from a source `hooks` entry).
    Hook {
        event: String,
        matcher: Option<String>,
        command: String,
        timeout: Option<u64>,
    },
    /// A directory to add to `[paths] extra_skill_dirs` or `extra_rule_dirs`.
    PathEntry { kind: PathKind, path: String },
}

/// Hand-written `Debug`: an imported environment variable's value and a hook's command print as `<redacted>`
/// (users keep API keys there). The destructures are exhaustive, so a new field fails to compile here until its
/// Debug output is decided.
impl std::fmt::Debug for ImportableItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Permission(rule) => f.debug_tuple("Permission").field(rule).finish(),
            Self::EnvVar { key, value: _ } => f
                .debug_struct("EnvVar")
                .field("key", key)
                .field("value", &"<redacted>")
                .finish(),
            Self::McpServer { name, config } => f
                .debug_struct("McpServer")
                .field("name", name)
                .field("config", config)
                .finish(),
            Self::Hook {
                event,
                matcher,
                command,
                timeout,
            } => f
                .debug_struct("Hook")
                .field("event", event)
                .field("matcher", matcher)
                // A hook command may embed a credential (`curl -H 'Authorization: Bearer ...'`).
                .field("command", &if command.is_empty() { "" } else { "<redacted>" })
                .field("timeout", timeout)
                .finish(),
            Self::PathEntry { kind, path } => f
                .debug_struct("PathEntry")
                .field("kind", kind)
                .field("path", path)
                .finish(),
        }
    }
}

/// What would be imported and where.
#[derive(Debug, Clone, Default)]
pub struct ImportPlan {
    /// Items for `~/.fuigo/config.toml` (and `~/.fuigo/hooks`).
    pub global_items: Vec<ImportableItem>,
    /// Items for `<repo>/.fuigo/config.toml` (and `<repo>/.fuigo/hooks`).
    pub project_items: Vec<ImportableItem>,
}

impl ImportPlan {
    /// Total number of items across both scopes.
    #[must_use]
    pub fn total_items(&self) -> usize {
        self.global_items.len() + self.project_items.len()
    }

    /// Whether there is nothing to import.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.global_items.is_empty() && self.project_items.is_empty()
    }
}

/// Result of applying an import.
#[derive(Debug, Default)]
pub struct ImportResult {
    /// Number of items written to global config.
    pub global_count: usize,
    /// Number of items written to project config.
    pub project_count: usize,
    /// Paths of config files that were modified.
    pub modified_files: Vec<String>,
}

impl ImportResult {
    #[must_use]
    pub fn total(&self) -> usize {
        self.global_count + self.project_count
    }
}

fn tool_label(tool: ImportTool) -> &'static str {
    match tool {
        ImportTool::Any => "",
        ImportTool::Bash => "Bash",
        ImportTool::Edit => "Edit",
        ImportTool::Read => "Read",
        ImportTool::Grep => "Grep",
        ImportTool::Mcp => "MCPTool",
        ImportTool::WebFetch => "WebFetch",
        ImportTool::WebSearch => "WebSearch",
        ImportTool::AgentMessage => "AgentMessage",
    }
}

/// A rule back in the compact string form.
///
/// - `Bash(npm run build)` for `{ Bash, "npm run build" }`
/// - `Read(src/*.rs)` for `{ Read, "src/*.rs" }`
/// - `WebFetch(domain:example.com)` for a domain pattern
/// - `Bash` for `{ Bash, None }` (bare tool name, any pattern)
/// - `*` for `{ Any, None }` (the catch-all rule)
#[must_use]
pub fn format_rule_string(rule: &ImportPermission) -> String {
    let tool_name = tool_label(rule.tool);
    match (rule.pattern.as_deref(), rule.tool) {
        (None, ImportTool::Any) => "*".to_string(),
        (Some(pattern), ImportTool::Any) => pattern.to_string(),
        (None, _) => tool_name.to_string(),
        (Some(pattern), _) => {
            let pattern = match rule.pattern_mode {
                ImportPatternMode::Domain => format!("domain:{pattern}"),
                ImportPatternMode::Glob => pattern.to_string(),
            };
            format!("{tool_name}({pattern})")
        }
    }
}
