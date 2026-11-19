//! `fuigo doctor --report`: one Markdown summary a user can paste into a bug report.
//!
//! Nothing is sent anywhere: the report is printed to stdout and that is all. Two rules keep it safe to paste:
//! - It collects names and states, never values: providers and models by name, MCP servers by name, transport and
//!   enabled state (no URL, no header, no argument, no environment value), plugins by count.
//! - Every value that is printed goes through [`Sanitizer::clean`]: the secret sanitizer, the home directory shown as
//!   `~`, control characters removed, one line, capped. A field that was not collected cannot leak, and one that was
//!   collected is scrubbed on the way out.
//!
//! [`collect`] reads the machine; [`render`] is pure, so the format is tested against a fake environment.

use std::fmt::Write as _;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};

use fuigo_shell::util::config::McpServerTransportConfig;

/// Longest value printed, in characters.
const MAX_VALUE_CHARS: usize = 300;
/// Most recent error lines shown.
const MAX_ERROR_LINES: usize = 10;
/// How much of the end of the log is read. The log is capped at a few MB; the report needs only its tail.
const LOG_TAIL_BYTES: u64 = 256 * 1024;

/// Cleans every printed value. `home` is the user's home directory, shown as `~`.
pub(super) struct Sanitizer {
    home: Option<String>,
}

impl Sanitizer {
    pub(super) fn from_env() -> Self {
        Self::with_home(fuigo_dirs::home_dir().map(|p| p.display().to_string()))
    }

    pub(super) fn with_home(home: Option<String>) -> Self {
        // A home of `/` or empty would turn every slash into `~`.
        Self {
            home: home.filter(|h| h.len() > 1),
        }
    }

    /// The secret sanitizer first (on the raw text, so a token shape is intact), then the home directory as `~` and
    /// other users' names out of paths, then one line of printable text, capped, with no backtick to break the Markdown.
    pub(super) fn clean(&self, raw: &str) -> String {
        let redacted = fuigo_secrets::redact_secrets(raw);
        let mut text = redacted.into_owned();
        if let Some(home) = &self.home {
            text = text.replace(home.as_str(), "~");
        }
        let text = fuigo_secrets::redact_user_paths(&text).into_owned();
        let one_line: String = text
            .chars()
            .map(|c| match c {
                '`' => '\'',
                c if c.is_control() => ' ',
                c => c,
            })
            .collect();
        let one_line = one_line.trim();
        let capped: String = if one_line.chars().count() > MAX_VALUE_CHARS {
            let head: String = one_line.chars().take(MAX_VALUE_CHARS).collect();
            format!("{head}...")
        } else {
            one_line.to_owned()
        };
        // The terminal-safety pass the other doctor output uses.
        fuigo_tty_utils::untrusted(capped).to_string()
    }

    /// [`Sanitizer::clean`] for a table cell: no `|`.
    fn cell(&self, raw: &str) -> String {
        self.clean(raw).replace('|', "/")
    }
}

/// One MCP server: name, transport kind, state. Never a URL, header, argument or environment value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct McpRow {
    pub name: String,
    pub transport: String,
    pub enabled: bool,
    pub scope: String,
}

/// The row for one configured server. A stdio server shows its program's file name only (its arguments often carry a
/// key); an HTTP server shows `http` or `sse` only (its URL may carry one).
pub(super) fn mcp_row(
    name: &str,
    transport: &McpServerTransportConfig,
    enabled: bool,
    scope: &str,
) -> McpRow {
    let transport = match transport {
        McpServerTransportConfig::Stdio { command, .. } => {
            let program = Path::new(command)
                .file_name()
                .map_or_else(|| command.clone(), |n| n.to_string_lossy().into_owned());
            format!("stdio ({program})")
        }
        McpServerTransportConfig::StreamableHttp { transport_type, .. } => {
            match transport_type.as_deref() {
                Some("sse") => "sse".to_owned(),
                _ => "http".to_owned(),
            }
        }
    };
    McpRow {
        name: name.to_owned(),
        transport,
        enabled,
        scope: scope.to_owned(),
    }
}

/// Names from the effective config: never a key, URL or header.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ConfigSummary {
    pub default_model: Option<String>,
    pub models: Vec<String>,
    pub providers: Vec<String>,
    pub use_leader: Option<bool>,
}

pub(super) fn config_summary(config: &toml::Value) -> ConfigSummary {
    let keys = |table: &str| -> Vec<String> {
        config
            .get(table)
            .and_then(toml::Value::as_table)
            .map(|t| t.keys().cloned().collect())
            .unwrap_or_default()
    };
    ConfigSummary {
        default_model: config
            .get("models")
            .and_then(|m| m.get("default"))
            .and_then(toml::Value::as_str)
            .map(str::to_owned),
        models: keys("model"),
        providers: keys("model_providers"),
        use_leader: fuigo_shell::util::config::use_leader_from_toml_opt(config),
    }
}

/// The `error` entries at the end of a `unified.jsonl` log, oldest first, as `<timestamp> <message>`.
pub(super) fn error_lines_from_jsonl(text: &str, max: usize) -> Vec<String> {
    let mut found: Vec<String> = text
        .lines()
        .filter_map(|line| {
            let value: serde_json::Value = serde_json::from_str(line).ok()?;
            if value.get("lvl")?.as_str()? != "error" {
                return None;
            }
            let msg = value.get("msg")?.as_str()?;
            let ts = value.get("ts").and_then(|t| t.as_str()).unwrap_or("-");
            Some(format!("{ts} {msg}"))
        })
        .collect();
    let skip = found.len().saturating_sub(max);
    found.drain(..skip);
    found
}

/// The last [`LOG_TAIL_BYTES`] of the log at `path`, or `None` when it cannot be read.
fn read_log_tail(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    let start = len.saturating_sub(LOG_TAIL_BYTES);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut bytes = Vec::new();
    file.take(LOG_TAIL_BYTES).read_to_end(&mut bytes).ok()?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    // A tail that starts mid-file starts mid-line: drop that partial line.
    if start > 0 {
        return Some(
            text.split_once('\n')
                .map_or(String::new(), |(_, r)| r.to_owned()),
        );
    }
    Some(text)
}

/// Sandbox facts. Raw text; [`render`] cleans it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct SandboxFacts {
    pub mode: String,
    pub source: String,
    pub degraded: Option<String>,
    pub backend: String,
    pub bwrap: Option<String>,
}

/// Everything the report prints, raw. [`render`] cleans each value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ReportInputs {
    pub version: String,
    pub os: String,
    pub kernel: Option<String>,
    pub shell: Option<String>,
    pub terminal: String,
    pub install_method: String,
    pub sandbox: SandboxFacts,
    pub cwd: String,
    pub trust: String,
    pub config: ConfigSummary,
    pub peer_messaging: bool,
    pub mcp: Vec<McpRow>,
    pub plugin_count: usize,
    pub errors: Vec<String>,
    /// `(label, path, exists)`.
    pub paths: Vec<(String, String, bool)>,
}

fn field(out: &mut String, label: &str, value: &str) {
    let _ = writeln!(out, "- **{label}**: `{value}`");
}

fn names(san: &Sanitizer, list: &[String]) -> String {
    if list.is_empty() {
        "none".to_owned()
    } else {
        list.iter()
            .map(|n| san.clean(n))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

pub(super) fn render(inputs: &ReportInputs, san: &Sanitizer) -> String {
    let c = |s: &str| san.clean(s);
    let mut out = String::from("# Fuigo doctor report\n\n");
    out.push_str(
        "Made on this machine by `fuigo doctor --report`. Nothing was sent anywhere. Secrets, URLs, headers and \
         environment values are left out; read it once before you paste it.\n",
    );

    out.push_str("\n## Environment\n\n");
    field(&mut out, "Fuigo", &c(&inputs.version));
    field(&mut out, "OS", &c(&inputs.os));
    if let Some(kernel) = &inputs.kernel {
        field(&mut out, "Kernel", &c(kernel));
    }
    field(
        &mut out,
        "Shell",
        &inputs.shell.as_deref().map_or("unknown".to_owned(), c),
    );
    field(&mut out, "Terminal", &c(&inputs.terminal));
    field(&mut out, "Install method", &c(&inputs.install_method));

    out.push_str("\n## Sandbox and trust\n\n");
    let s = &inputs.sandbox;
    field(&mut out, "Sandbox mode", &c(&s.mode));
    field(&mut out, "Mode set by", &c(&s.source));
    if let Some(degraded) = &s.degraded {
        field(&mut out, "Mode degraded", &c(degraded));
    }
    field(&mut out, "Sandbox backend", &c(&s.backend));
    field(
        &mut out,
        "bwrap",
        &s.bwrap.as_deref().map_or("not found".to_owned(), c),
    );
    field(&mut out, "Folder", &c(&inputs.cwd));
    field(&mut out, "Folder trust", &c(&inputs.trust));

    out.push_str("\n## Models and providers (names only)\n\n");
    field(
        &mut out,
        "Default model",
        &inputs
            .config
            .default_model
            .as_deref()
            .map_or("not set".to_owned(), c),
    );
    field(
        &mut out,
        "Configured models",
        &names(san, &inputs.config.models),
    );
    field(
        &mut out,
        "Configured providers",
        &names(san, &inputs.config.providers),
    );

    out.push_str("\n## Leader and peers\n\n");
    let leader = match inputs.config.use_leader {
        Some(true) => "on (cli.use_leader = true)",
        Some(false) => "off (cli.use_leader = false)",
        None => "not set in config (off unless started with --leader)",
    };
    field(&mut out, "Leader", leader);
    field(
        &mut out,
        "Peer messaging",
        if inputs.peer_messaging { "on" } else { "off" },
    );

    out.push_str("\n## MCP servers\n\n");
    if inputs.mcp.is_empty() {
        out.push_str("None configured.\n");
    } else {
        out.push_str("| Name | Transport | Enabled | Scope |\n| --- | --- | --- | --- |\n");
        for row in &inputs.mcp {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} |",
                san.cell(&row.name),
                san.cell(&row.transport),
                if row.enabled { "yes" } else { "no" },
                san.cell(&row.scope)
            );
        }
    }

    out.push_str("\n## Plugins\n\n");
    field(&mut out, "Installed", &inputs.plugin_count.to_string());

    out.push_str("\n## Config files\n\n");
    for (label, path, exists) in &inputs.paths {
        let _ = writeln!(
            out,
            "- **{}**: `{}` ({})",
            san.cell(label),
            c(path),
            if *exists { "present" } else { "missing" }
        );
    }

    out.push_str("\n## Recent errors\n\n");
    if inputs.errors.is_empty() {
        out.push_str("None in the log.\n");
    } else {
        out.push_str("```text\n");
        for line in &inputs.errors {
            // `clean` leaves no backtick, so a log line cannot close this fence.
            let _ = writeln!(out, "{}", c(line));
        }
        out.push_str("```\n");
    }
    out
}

/// Read this machine into [`ReportInputs`]. Each probe is best effort: one that fails prints as unknown, never an error.
pub(super) fn collect() -> ReportInputs {
    let cwd = std::env::current_dir().ok();
    let cwd_for_probes = cwd.clone().unwrap_or_else(|| PathBuf::from("."));
    let terminal_ctx = crate::terminal::standalone_terminal_context();
    let terminal = format!(
        "{} (multiplexer: {}, ssh: {}, TERM={})",
        terminal_ctx.brand,
        terminal_ctx.multiplexer,
        if terminal_ctx.is_ssh { "yes" } else { "no" },
        terminal_ctx.term_var.as_deref().unwrap_or("unset"),
    );
    let effective = fuigo_shell::config::load_effective_config().ok();
    let config = effective.as_ref().map(config_summary).unwrap_or_default();

    let mcp = {
        let servers =
            fuigo_shell::util::config::load_mcp_server_configs_with_project(&cwd_for_probes);
        let disabled = fuigo_shell::util::config::disabled_mcp_server_names(&cwd_for_probes);
        servers
            .iter()
            .map(|(name, (cfg, scope))| {
                mcp_row(name, &cfg.transport, !disabled.contains(name), scope)
            })
            .collect()
    };

    let plugin_count = fuigo_agent::plugins::install_registry::InstallRegistry::load()
        .list()
        .iter()
        .map(|(_, repo)| repo.plugins.len())
        .sum();

    let home = fuigo_dirs::fuigo_home();
    let log = home.join("logs").join("unified.jsonl");
    let errors = read_log_tail(&log)
        .map(|t| error_lines_from_jsonl(&t, MAX_ERROR_LINES))
        .unwrap_or_default();
    let mut paths = vec![
        (
            "Fuigo home".to_owned(),
            home.display().to_string(),
            home.exists(),
        ),
        file_entry("User config", home.join("config.toml")),
        file_entry("Managed config", home.join("managed_config.toml")),
        file_entry("User sandbox config", home.join("workspaced.toml")),
        file_entry("Log", log),
    ];
    if let Some(cwd) = &cwd {
        paths.push(file_entry(
            "Project config",
            cwd.join(".fuigo").join("config.toml"),
        ));
    }

    ReportInputs {
        version: fuigo_version::full_version().to_owned(),
        os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        kernel: kernel_release(),
        shell: std::env::var("SHELL").ok().filter(|s| !s.is_empty()),
        terminal,
        install_method: install_method(),
        sandbox: collect_sandbox(&cwd_for_probes),
        cwd: cwd.map_or_else(|| "unknown".to_owned(), |c| c.display().to_string()),
        trust: trust_text(&cwd_for_probes),
        config,
        peer_messaging: crate::peer_ui::peer_ui_enabled(),
        mcp,
        plugin_count,
        errors,
        paths,
    }
}

fn file_entry(label: &str, path: PathBuf) -> (String, String, bool) {
    let exists = path.exists();
    (label.to_owned(), path.display().to_string(), exists)
}

#[cfg(unix)]
fn kernel_release() -> Option<String> {
    let out = std::process::Command::new("uname")
        .arg("-sr")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .filter(|s| !s.is_empty())
}

#[cfg(not(unix))]
fn kernel_release() -> Option<String> {
    None
}

/// How this copy was installed, from the markers the npm launcher sets and the path it runs from.
fn install_method() -> String {
    if let Some(installer) = std::env::var("FUIGO_INSTALLER")
        .ok()
        .filter(|s| !s.is_empty())
    {
        return format!("set by FUIGO_INSTALLER ({installer})");
    }
    if fuigo_update::auto_update::is_npm_local_copy() {
        return "npm (local or npx copy)".to_owned();
    }
    if std::env::var_os("FUIGO_MANAGED_BY_NPM").is_some() {
        return "npm (global)".to_owned();
    }
    let under_node_modules = std::env::current_exe()
        .and_then(|exe| dunce::canonicalize(&exe))
        .is_ok_and(|exe| exe.components().any(|c| c.as_os_str() == "node_modules"));
    if under_node_modules {
        "npm".to_owned()
    } else {
        "standalone".to_owned()
    }
}

fn collect_sandbox(cwd: &Path) -> SandboxFacts {
    use fuigo_sandbox::command::detect::{BackendChoice, HostProbe};
    let (backend, available) = match HostProbe::run().preferred_backend() {
        BackendChoice::Selected(name) => (<&str>::from(name).to_owned(), true),
        BackendChoice::Unavailable { reason } => (format!("none ({reason})"), false),
    };
    let resolved = fuigo_workspace::sandbox_mode::resolve_sandbox_mode(cwd, available);
    SandboxFacts {
        mode: <&str>::from(resolved.mode).to_owned(),
        source: <&str>::from(resolved.source).to_owned(),
        degraded: resolved.degraded.map(|d| <&str>::from(d).to_owned()),
        backend,
        bwrap: find_in_path("bwrap").map(|p| p.display().to_string()),
    }
}

/// `name` on an absolute `PATH` entry (a relative entry is never trusted to name a program).
fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

fn trust_text(cwd: &Path) -> String {
    if fuigo_workspace::folder_trust::folder_trust_inert() {
        return "not enforced (this is a local build without a release stamp)".to_owned();
    }
    if fuigo_workspace::folder_trust::folder_trust_disabled() {
        return "off (switched off in your settings or by FUIGO_FOLDER_TRUST=0)".to_owned();
    }
    if fuigo_workspace::folder_trust::decide(cwd, false).is_trusted() {
        "trusted".to_owned()
    } else {
        "not trusted".to_owned()
    }
}

#[cfg(test)]
mod tests;
