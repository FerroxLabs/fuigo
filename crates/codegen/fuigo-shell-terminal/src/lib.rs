//! Local, ACP, and PTY terminal runners for the fuigo shell.
//!
//! `fuigo-shell` re-exports this crate as `fuigo_shell::terminal`.

use std::sync::Arc;

pub mod runner;
pub use runner::{AsyncTerminalRunner, TerminalError, TerminalRunRequest, TerminalRunResult};

mod background_task;
pub use background_task::{
    BackgroundTaskManifestEntry, BackgroundTaskRegistry, TaskId, TaskSnapshot,
    format_resumed_tasks_reminder, load_and_clear_manifest, persist_manifest,
};

mod local_terminal;
pub use local_terminal::LocalTerminalRunner;

mod acp_terminal;
pub use acp_terminal::AcpTerminalRunner;

pub mod adapter;
pub use adapter::AcpTerminalAdapter;

mod exit_watcher;
mod output_recorder;

pub mod pty_session;

mod streaming_local_terminal;
pub use streaming_local_terminal::{
    ExitStatus, GatedNotifier, KillOutcome, OutputSnapshot, SessionNotificationSender,
    StreamingLocalTerminalRunner, background_terminal, create_terminal, find_terminal_session_id,
    get_terminal_output, kill_and_release_all_for_session, kill_terminal, release_terminal,
    wait_for_terminal_exit,
};

/// P113 r3: remove Fuigo's own secrets ([`fuigo_tools::util::shell_env_policy::is_fuigo_secret`]: its first-party
/// keys, internal secrets such as `FUIGO_AGENT_SECRET`, and every credential name a config registered) from a child
/// that otherwise keeps the user's whole environment (a `!` command, a client terminal). Call it before setting any
/// explicit variable, so an explicit entry still arrives.
pub(crate) fn remove_fuigo_secrets(cmd: &mut tokio::process::Command) {
    for name in fuigo_tools::util::shell_env_policy::inherited_fuigo_secret_names() {
        cmd.env_remove(name);
    }
}

/// P113 r3 probes: `!` commands, client terminals and PTYs keep the user's environment but never Fuigo's own secrets.
#[cfg(all(test, unix))]
pub(crate) mod p113_probe {
    /// Fuigo's own secret variables, planted in the PARENT. Literal on purpose (a probe that read the denylist would
    /// plant nothing once it was emptied).
    pub(crate) const SECRETS: &[&str] = &[
        "FUIGO_API_KEY",
        "FUIGO_CODE_API_KEY",
        "FUIGO_AGENT_SECRET",
        "FUIGO_AUTH",
        "FUIGO_AUTH_PATH",
        "FUIGO_DEPLOYMENT_KEY",
        "FUIGO_EXTRA_AUTH_KEY",
        "FUIGO_TRACE_UPLOAD_CREDENTIALS_FILE",
        "FUIGO_INTERNAL_OTLP_HEADERS",
        "OTEL_EXPORTER_OTLP_HEADERS",
        "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
        "OTEL_EXPORTER_OTLP_METRICS_HEADERS",
        "FUIGO_TELEMETRY_EVENTS_API_KEY",
        "FUIGO_TELEMETRY_MIXPANEL_TOKEN",
        // A name a config registered (an MCP `bearer_token_env_var`); the child registers it before spawning.
        "P113_MCP_BEARER",
        // Astra r3 #1: a built-in provider name a config registered the same way is Fuigo's too.
        "GROQ_API_KEY",
    ];

    /// The shell test the probe runs: the benign variable and the user's own provider key arrived, the explicit
    /// `FUIGO_AGENT_SECRET` arrived when `explicit`, and none of [`SECRETS`] otherwise did.
    pub(crate) fn check(explicit: bool) -> String {
        let absent: String = SECRETS
            .iter()
            .filter(|name| !(explicit && **name == "FUIGO_AGENT_SECRET"))
            .map(|name| format!("${{{name}+x}}"))
            .collect();
        let agent = if explicit {
            " && test \"$FUIGO_AGENT_SECRET\" = fake-p113-explicit"
        } else {
            ""
        };
        format!(
            "test \"$P113_BENIGN\" = kept && test \"$OPENAI_API_KEY\" = fake-p113-user{agent} && test -z \"{absent}\""
        )
    }

    /// Re-run `test_name` in a fresh test process whose own environment holds every [`SECRETS`] entry, the user's
    /// `OPENAI_API_KEY` and `P113_BENIGN=kept`. `true` in the parent (which then returns), `false` in the child
    /// (which registers `P113_MCP_BEARER` and `GROQ_API_KEY` as configured credentials and runs the body).
    pub(crate) fn parent_env(test_name: &str) -> bool {
        if std::env::var("P113_CHILD_TEST").as_deref() == Ok(test_name) {
            fuigo_tools::util::shell_env_policy::register_credential_env_names(["P113_MCP_BEARER", "GROQ_API_KEY"]);
            return false;
        }
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.arg(test_name)
            .args(["--test-threads=1", "--nocapture"])
            .env("P113_CHILD_TEST", test_name)
            .env("P113_BENIGN", "kept")
            .env("OPENAI_API_KEY", "fake-p113-user");
        for name in SECRETS {
            cmd.env(name, "fake-p113-ambient");
        }
        let output = cmd.output().unwrap();
        let diagnostics = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .replace("fake-p113-", "[redacted]-");
        assert!(output.status.success(), "isolated P113 probe failed: {diagnostics}");
        assert!(
            diagnostics.contains("test result: ok. 1 passed"),
            "the P113 child must run exactly one test: {diagnostics}"
        );
        true
    }
}

pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
pub const DEFAULT_OUTPUT_BYTE_LIMIT: usize = 30_000;

/// Resolved absolute path to bash.
/// On Unix uses the `fuigo_config` cascade (`$FUIGO_SHELL` > `$SHELL` > `which` > common dirs > `/bin/bash`), cached process-wide.
/// On non-Unix returns `"/bin/bash"`.
/// Every caller in this crate is gated behind `#[cfg(unix)]`, so the non-Unix value should not be observed in practice.
pub(crate) fn default_shell_path() -> &'static str {
    #[cfg(unix)]
    {
        fuigo_config::shell::unix_shell_path(fuigo_config::shell::UnixShellKind::Bash)
    }
    #[cfg(not(unix))]
    {
        "/bin/bash"
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TerminalStatus {
    Connecting,
    Connected,
    Exited,
    Error,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalInfo {
    pub terminal_id: String,
    pub status: TerminalStatus,
    pub interactive: bool,
    pub name: Option<String>,
    pub exit_code: Option<i32>,
    pub cwd: Option<String>,
    pub output_offset: u64,
    pub created_at: u64,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum TerminalExtError {
    #[error("terminal '{terminal_id}' not found")]
    NotFound { terminal_id: String },
    #[error("terminal '{terminal_id}' is not an interactive PTY")]
    NotInteractive { terminal_id: String },
    #[error("terminal '{terminal_id}' exited")]
    Exited { terminal_id: String },
    #[error("terminal '{terminal_id}' input channel closed")]
    InputClosed { terminal_id: String },
    #[error("{0}")]
    Internal(String),
}

impl TerminalExtError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "TERMINAL_NOT_FOUND",
            Self::NotInteractive { .. } => "TERMINAL_NOT_INTERACTIVE",
            Self::Exited { .. } => "TERMINAL_EXITED",
            Self::InputClosed { .. } => "TERMINAL_INPUT_CLOSED",
            Self::Internal(_) => "TERMINAL_INTERNAL_ERROR",
        }
    }

    pub fn terminal_id(&self) -> Option<&str> {
        match self {
            Self::NotFound { terminal_id }
            | Self::NotInteractive { terminal_id }
            | Self::Exited { terminal_id }
            | Self::InputClosed { terminal_id } => Some(terminal_id),
            Self::Internal(_) => None,
        }
    }
}

pub async fn list_terminals() -> Vec<TerminalInfo> {
    let mut terminals = pty_session::list_ptys().await;
    let mut piped = streaming_local_terminal::list_piped_terminals().await;
    terminals.append(&mut piped);
    terminals
}

/// Returns environment variables that prevent CLI tools from launching any blocking/waiting programs.
pub use fuigo_tools::util::pager_env;

/// Returns environment variables that encourage CLI tools to emit color and progress bars/spinners even when running through pipes (non-TTY).
pub fn color_env() -> std::collections::HashMap<String, String> {
    std::collections::HashMap::from([
        ("TERM".to_string(), "xterm-256color".to_string()),
        ("COLORTERM".to_string(), "truecolor".to_string()),
        ("FORCE_COLOR".to_string(), "1".to_string()),
        ("CLICOLOR_FORCE".to_string(), "1".to_string()),
        ("CLICOLOR".to_string(), "1".to_string()),
        // Cargo: always show progress bar
        ("CARGO_TERM_PROGRESS_WHEN".to_string(), "always".to_string()),
        ("CARGO_TERM_PROGRESS_WIDTH".to_string(), "80".to_string()),
        // CI mode: many tools show progress in CI
        ("CI".to_string(), "true".to_string()),
        // npm/yarn progress
        ("NPM_CONFIG_PROGRESS".to_string(), "true".to_string()),
        // pip progress
        ("PIP_PROGRESS_BAR".to_string(), "on".to_string()),
        // gradle
        (
            "GRADLE_OPTS".to_string(),
            "-Dorg.gradle.console=rich".to_string(),
        ),
        // Maven
        ("MAVEN_OPTS".to_string(), "-Dstyle.color=always".to_string()),
    ])
}

/// Returns environment variables that disable colors and ANSI escape codes in CLI tool output.
/// Used when the client sets `fuigo/bashOutputNoColor: true` (e.g. fuigo-pager which renders its own UI and doesn't need raw ANSI codes).
/// Follows the <https://no-color.org/> convention plus tool-specific overrides.
pub fn no_color_env() -> std::collections::HashMap<String, String> {
    std::collections::HashMap::from([
        // https://no-color.org/: respected by many CLI tools
        ("NO_COLOR".to_string(), "1".to_string()),
        // Override TERM to dumb: prevents cursor movement, color codes
        ("TERM".to_string(), "dumb".to_string()),
        // Disable forced color in tools that check these
        ("FORCE_COLOR".to_string(), "0".to_string()),
        ("CLICOLOR_FORCE".to_string(), "0".to_string()),
        ("CLICOLOR".to_string(), "0".to_string()),
        // Cargo: disable color and progress bar
        ("CARGO_TERM_COLOR".to_string(), "never".to_string()),
        // npm/yarn: disable color
        ("NPM_CONFIG_COLOR".to_string(), "false".to_string()),
        // pip: disable color and progress
        ("PIP_NO_COLOR".to_string(), "1".to_string()),
        ("PIP_PROGRESS_BAR".to_string(), "off".to_string()),
        // gradle
        (
            "GRADLE_OPTS".to_string(),
            "-Dorg.gradle.console=plain".to_string(),
        ),
        // Maven
        ("MAVEN_OPTS".to_string(), "-Dstyle.color=never".to_string()),
    ])
}

/// `stream: true` uses StreamingLocalTerminalRunner (updates, killable).
/// `stream: false` uses LocalTerminalRunner (silent, fire and forget).
pub struct TerminalRunner {
    notifier: Arc<dyn SessionNotificationSender>,
    session_id: agent_client_protocol::SessionId,
}

impl TerminalRunner {
    pub fn new(
        notifier: Arc<dyn SessionNotificationSender>,
        session_id: agent_client_protocol::SessionId,
    ) -> Self {
        Self {
            notifier,
            session_id,
        }
    }
}

#[async_trait::async_trait]
impl AsyncTerminalRunner for TerminalRunner {
    async fn run(&self, request: TerminalRunRequest) -> Result<TerminalRunResult, TerminalError> {
        if request.stream {
            StreamingLocalTerminalRunner {
                notifier: self.notifier.clone(),
                session_id: self.session_id.clone(),
            }
            .run(request)
            .await
        } else {
            LocalTerminalRunner.run(request).await
        }
    }
}
