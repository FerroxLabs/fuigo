//! Headless CLI parsing: output format, prompt sources, permission rules, and agent args.

use std::path::{Path, PathBuf};

use agent_client_protocol as acp;
use clap::ValueEnum;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Plain,
    Json,
    /// NDJSON: one ACP session update per line, the agent's native format.
    #[value(name = "streaming-json")]
    StreamingJson,
    /// NDJSON in the Anthropic Messages API wire format.
    #[value(name = "streaming-messages-json")]
    StreamingMessagesJson,
}

pub fn parse_json_schema(input: &str) -> anyhow::Result<serde_json::Value> {
    let schema: serde_json::Value = serde_json::from_str(input)
        .map_err(|e| anyhow::anyhow!("--json-schema: invalid JSON: {e}"))?;
    if !schema.is_object() {
        anyhow::bail!("--json-schema: must be a JSON object describing a JSON Schema");
    }
    Ok(schema)
}

#[derive(Debug, Clone)]
pub enum HeadlessPrompt {
    Text(String),
    Blocks(Vec<acp::ContentBlock>),
}

impl HeadlessPrompt {
    /// Build from mutually-exclusive CLI prompt args. `None` means interactive mode.
    pub fn from_args(
        single: Option<&str>,
        prompt_json: Option<&str>,
        prompt_file: Option<&Path>,
    ) -> anyhow::Result<Option<Self>> {
        if let Some(text) = single {
            Self::from_text(text)
                .map(Some)
                .map_err(|e| anyhow::anyhow!("--single: {e}"))
        } else if let Some(json_str) = prompt_json {
            Self::from_json(json_str)
                .map(Some)
                .map_err(|e| anyhow::anyhow!("--prompt-json: {e}"))
        } else if let Some(path) = prompt_file {
            Self::from_file(path).map(Some)
        } else {
            Ok(None)
        }
    }

    /// `.json` files are parsed as content blocks, everything else as text.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read '{}': {e}", path.display()))?;

        let context = |e| anyhow::anyhow!("'{}': {e}", path.display());
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            Self::from_json(&content).map_err(context)
        } else {
            Self::from_text(&content).map_err(context)
        }
    }

    fn from_text(text: &str) -> anyhow::Result<Self> {
        // A byte order mark (editors and shells on Windows add one) is not part of the prompt
        let trimmed = text
            .trim_start_matches(|c: char| c == '\u{feff}' || c.is_whitespace())
            .trim_end();
        if trimmed.is_empty() {
            anyhow::bail!("prompt is empty");
        }
        Ok(Self::Text(trimmed.to_string()))
    }

    fn from_json(json_str: &str) -> anyhow::Result<Self> {
        let blocks = parse_prompt_json(json_str)?;
        Ok(Self::Blocks(blocks))
    }

    pub fn into_content_blocks(self) -> Vec<acp::ContentBlock> {
        match self {
            Self::Text(text) => vec![acp::ContentBlock::Text(acp::TextContent::new(text))],
            Self::Blocks(blocks) => blocks,
        }
    }
}

/// Parse ACP content blocks from an array (`[...]`) or typed wrapper (`{"type":"acp","content":[...]}`).
fn parse_prompt_json(json_str: &str) -> anyhow::Result<Vec<acp::ContentBlock>> {
    let json_str = json_str.trim_start_matches('\u{feff}');
    let value: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| anyhow::anyhow!("Invalid JSON: {e}"))?;

    let blocks: Vec<acp::ContentBlock> = match value {
        serde_json::Value::Array(_) => serde_json::from_value(value)
            .map_err(|e| anyhow::anyhow!("Invalid ACP content blocks: {e}"))?,

        serde_json::Value::Object(ref map) => {
            let format_type = map.get("type").and_then(|v| v.as_str()).ok_or_else(|| {
                anyhow::anyhow!(
                    "JSON object must have a \"type\" field \
                         (e.g., {{\"type\": \"acp\", \"content\": [...]}})"
                )
            })?;
            let content = map
                .get("content")
                .ok_or_else(|| anyhow::anyhow!("JSON object must have a \"content\" field"))?;

            match format_type {
                "acp" => serde_json::from_value(content.clone()).map_err(|e| {
                    anyhow::anyhow!("Invalid ACP content blocks in \"content\": {e}")
                })?,
                other => anyhow::bail!(
                    "Unsupported prompt format type: \"{other}\". Supported types: \"acp\""
                ),
            }
        }

        _ => {
            anyhow::bail!("Expected JSON array or {{\"type\": \"...\", \"content\": [...]}} object")
        }
    };

    if blocks.is_empty() {
        anyhow::bail!("content blocks array is empty");
    }
    Ok(blocks)
}

/// Parse a comma-separated list into a vec, or None if empty.
pub(crate) fn parse_comma_list(s: Option<&str>) -> Option<Vec<String>> {
    s.and_then(|s| {
        let v: Vec<String> = s
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        if v.is_empty() { None } else { Some(v) }
    })
}

pub fn parse_permission_rules_strict(
    allow: &[String],
    deny: &[String],
) -> anyhow::Result<Vec<fuigo_workspace::permission::types::PermissionRule>> {
    let (rules, errors) = parse_permission_rules_inner(allow, deny);
    if !errors.is_empty() {
        let msgs: Vec<String> = errors
            .into_iter()
            .map(|(flag, rule, err)| format!("{flag} \"{rule}\": {err}"))
            .collect();
        anyhow::bail!("{}", msgs.join("; "));
    }
    Ok(rules)
}

pub fn parse_permission_rules_lenient(
    allow: &[String],
    deny: &[String],
) -> Vec<fuigo_workspace::permission::types::PermissionRule> {
    let (rules, errors) = parse_permission_rules_inner(allow, deny);
    for (flag, rule, err) in errors {
        fuigo_tty_utils::cli_eprintln!(
            "warning: {} \"{}\": {}, skipping",
            fuigo_tty_utils::untrusted(flag),
            fuigo_tty_utils::untrusted(rule),
            fuigo_tty_utils::untrusted(err)
        );
    }
    rules
}

// Deny before allow is cosmetic: the policy evaluator is order-independent (deny beats ask, ask beats allow)
pub(crate) fn parse_permission_rules_inner(
    allow: &[String],
    deny: &[String],
) -> (
    Vec<fuigo_workspace::permission::types::PermissionRule>,
    Vec<(&'static str, String, String)>,
) {
    use fuigo_workspace::permission::rules::parse_permission_rule;
    use fuigo_workspace::permission::types::RuleAction;

    let mut rules = Vec::new();
    let mut errors = Vec::new();
    for rule_str in deny {
        match parse_permission_rule(rule_str, RuleAction::Deny) {
            Ok(rule) => rules.push(rule),
            Err(e) => errors.push(("--deny", rule_str.clone(), e.to_string())),
        }
    }
    for rule_str in allow {
        match parse_permission_rule(rule_str, RuleAction::Allow) {
            Ok(rule) => rules.push(rule),
            Err(e) => errors.push(("--allow", rule_str.clone(), e.to_string())),
        }
    }
    (rules, errors)
}

pub(crate) enum ResolvedAgent {
    FilePath(PathBuf),
    Name(String),
}

/// `--agent <arg>`: a definition file only when the argument reads as a path (a separator, or a `.md` name) and is a
/// file; a plain agent name is always a name, so a repo file called `explore` or `codex` never becomes the profile.
pub(crate) fn resolve_agent_arg(agent: &str) -> ResolvedAgent {
    resolve_agent_arg_with(agent, |p| p.is_file())
}

fn resolve_agent_arg_with(agent: &str, is_file: impl Fn(&std::path::Path) -> bool) -> ResolvedAgent {
    let path = std::path::Path::new(agent);
    // A separator or a `.md` suffix, nothing else: a qualified plugin name (`plug:reviewer`) is not a valid bare
    // name but is still a name, so a repo file literally called `plug:reviewer` never becomes the profile.
    let reads_as_path = agent.contains(['/', '\\']) || agent.ends_with(".md");
    if reads_as_path && is_file(path) {
        ResolvedAgent::FilePath(dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()))
    } else {
        ResolvedAgent::Name(agent.to_string())
    }
}

pub(crate) fn parse_cli_agents(
    json: &str,
) -> anyhow::Result<Vec<fuigo_shell::agent::config::AgentDefinition>> {
    let map: std::collections::HashMap<String, serde_json::Value> =
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("--agents: invalid JSON: {e}"))?;
    let mut agents = Vec::with_capacity(map.len());
    for (name, mut value) in map {
        if let serde_json::Value::Object(ref mut obj) = value {
            if !obj.contains_key("promptBody")
                && let Some(prompt) = obj.remove("prompt")
            {
                obj.insert("promptBody".to_string(), prompt);
            }
            obj.entry("name".to_string())
                .or_insert_with(|| serde_json::Value::String(name.clone()));
            obj.entry("description".to_string())
                .or_insert_with(|| serde_json::Value::String(name.clone()));
        }
        let mut def = fuigo_shell::agent::config::AgentDefinition::from_json(&value)
            .map_err(|e| anyhow::anyhow!("--agents: failed to parse '{name}': {e}"))?;
        def.name = name;
        agents.push(def);
    }
    Ok(agents)
}

pub(crate) fn apply_agent_flag(
    agent: &Option<String>,
    config: &mut fuigo_shell::agent::config::Config,
) {
    if let Some(agent) = agent {
        match resolve_agent_arg(agent) {
            ResolvedAgent::FilePath(path) => config.agent_profile_path = Some(path),
            ResolvedAgent::Name(name) => config.agent.name = Some(name),
        }
    }
}

#[cfg(test)]
mod bom_tests {
    use super::*;

    const BOM: &str = "\u{feff}";

    #[test]
    fn a_leading_byte_order_mark_is_dropped_from_a_text_prompt() {
        for raw in [format!("{BOM}hello"), format!("{BOM}{BOM}  hello  \n"), format!("  {BOM}hello")] {
            match HeadlessPrompt::from_args(Some(&raw), None, None).unwrap() {
                Some(HeadlessPrompt::Text(t)) => assert_eq!(t, "hello", "{raw:?}"),
                other => panic!("expected text, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_prompt_that_is_only_a_byte_order_mark_is_empty() {
        let err = HeadlessPrompt::from_args(Some(BOM), None, None).unwrap_err();
        assert!(err.to_string().contains("empty"), "{err}");
    }

    #[test]
    fn a_byte_order_mark_inside_the_text_is_kept() {
        match HeadlessPrompt::from_args(Some(&format!("a{BOM}b")), None, None).unwrap() {
            Some(HeadlessPrompt::Text(t)) => assert_eq!(t, format!("a{BOM}b")),
            other => panic!("expected text, got {other:?}"),
        }
    }

    #[test]
    fn prompt_json_with_a_leading_byte_order_mark_parses() {
        let json = format!("{BOM}[{{\"type\":\"text\",\"text\":\"hi\"}}]");
        match HeadlessPrompt::from_args(None, Some(&json), None).unwrap() {
            Some(HeadlessPrompt::Blocks(blocks)) => assert_eq!(blocks.len(), 1),
            other => panic!("expected blocks, got {other:?}"),
        }
    }

    #[test]
    fn prompt_files_written_with_a_byte_order_mark_load() {
        let dir = tempfile::tempdir().unwrap();
        let text = dir.path().join("p.txt");
        std::fs::write(&text, format!("{BOM}from a file\n")).unwrap();
        match HeadlessPrompt::from_file(&text).unwrap() {
            HeadlessPrompt::Text(t) => assert_eq!(t, "from a file"),
            other => panic!("expected text, got {other:?}"),
        }
        let json = dir.path().join("p.json");
        std::fs::write(&json, format!("{BOM}[{{\"type\":\"text\",\"text\":\"x\"}}]")).unwrap();
        assert!(matches!(
            HeadlessPrompt::from_file(&json).unwrap(),
            HeadlessPrompt::Blocks(_)
        ));
    }
}

#[cfg(test)]
mod u35_agent_arg_tests {
    use super::*;

    /// u35 r1 (Grok M): a file in the working directory named like an agent is not a profile file.
    #[test]
    fn plain_agent_names_never_resolve_to_a_file() {
        // Every path "exists" as a file: only the argument's shape decides.
        let every_path_is_a_file = |_: &std::path::Path| true;
        for name in ["explore", "codex", "fuigo-build", "custom", "plug:reviewer"] {
            assert!(
                matches!(resolve_agent_arg_with(name, every_path_is_a_file), ResolvedAgent::Name(n) if n == name),
                "{name} must stay a name"
            );
        }
        for path in ["mine.md", "./explore", "agents/codex", "/abs/fuigo-build"] {
            assert!(
                matches!(resolve_agent_arg_with(path, every_path_is_a_file), ResolvedAgent::FilePath(_)),
                "{path} reads as a file"
            );
        }
        assert!(matches!(
            resolve_agent_arg_with("./missing.md", |_| false),
            ResolvedAgent::Name(_)
        ));
    }
}
