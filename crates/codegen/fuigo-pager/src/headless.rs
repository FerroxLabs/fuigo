//! Headless single-turn mode (`fuigo -p "prompt"`).
//!
//! Runs the agent in-process via `spawn_fuigo_shell` and drives the ACP lifecycle (init, auth, session, prompt).
//! Streams to stdout and exits via `CancellationToken`.

use fuigo_shell::sampling::error::acp_error_text;
use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use agent_client_protocol as acp;
use fuigo_acp_lib::{AcpAgentTx, AcpClientMessageBox, AcpClientRx, acp_send};
use fuigo_shell::agent::auth_method::AuthMethodKind;
use fuigo_shell::agent::config::Config as AgentConfig;
use fuigo_shell::extensions::notification::is_retry_status_update;
use fuigo_shell::extensions::task::{CancelSubagentRequest, KillTaskRequest};
use fuigo_shell::sampling::error::{
    RATE_LIMITED_ERROR_CODE, error_detail_from_data, format_rate_limited_user_message_with,
};
use fuigo_shell::sampling::types::{
    REASONING_EFFORT_META_KEY, parse_canonical_effort_token, reasoning_effort_meta_value,
};
use fuigo_shell::util::config as cli_config;
use fuigo_telemetry::startup::PendingStartup;

use crate::acp::model_state::{EffortTokenError, ModelState};
use crate::app::worktree_session::{
    CREATE_METHOD, RESUME_METHOD, WorktreeRpcError, WorktreeSpec, create_worktree,
    new_worktree_id, note_orphaned_worktree, resume_session_into_worktree,
};
use crate::acp::spawn::{AgentShutdownGuard, spawn_fuigo_shell};
use crate::client_identity::{HEADLESS_CLIENT_TYPE, PAGER_CLIENT_VERSION};
use crate::headless::reducer::{
    Lifecycle, McpServer, Reducer, SessionContext, StreamEvent, TurnEnd, map_session_update,
    reducer_for,
};

mod ext_protocol;
mod prompt_ack;
mod reducer;
use crate::app::prompt_ack::{PromptAckDeadlines, PromptAckWatch};
use ext_protocol::{ExtEvent, handle_ext_notification, reply_headless_ext_method};
use prompt_ack::{abort_unacknowledged_prompt, headless_ack_signal};

mod cli;
pub use cli::{HeadlessPrompt, OutputFormat, parse_json_schema, parse_permission_rules_lenient};
pub(crate) use cli::{ResolvedAgent, resolve_agent_arg};
use cli::{apply_agent_flag, parse_cli_agents, parse_comma_list, parse_permission_rules_strict};

#[derive(Debug, Clone)]
pub struct HeadlessOptions {
    pub session_id: Option<String>,
    pub resume: Option<String>,
    /// Resume was pinned pre-sandbox; materialization must not re-run title selection.
    pub resume_title_pinned: bool,
    pub cwd: Option<PathBuf>,
    pub yolo: bool,
    pub trust: bool,
    pub output_format: OutputFormat,
    /// Emit `stream_event` deltas for `streaming-messages-json`.
    pub include_partial_messages: bool,
    pub json_schema: Option<serde_json::Value>,
    pub model: Option<String>,
    pub rules: Option<String>,
    pub system_prompt_override: Option<String>,
    pub continue_last_session: bool,
    /// Fork on resume/continue (`--fork-session`).
    pub fork_session: bool,
    pub worktree: Option<String>,
    /// `--worktree-ref`: branch, tag, or commit the new worktree is based on.
    pub worktree_ref: Option<String>,
    pub restore_code: bool,
    pub agent: Option<String>,
    pub agents_json: Option<String>,
    pub cli_tools: Option<String>,
    pub cli_disallowed_tools: Option<String>,
    pub disable_web_search: bool,
    pub allow_rules: Vec<String>,
    pub deny_rules: Vec<String>,
    pub max_turns: Option<u32>,
    pub permission_mode_flag: Option<String>,
    /// Effort token (`--reasoning-effort` / `--effort`); resolved like `/effort` after models load.
    pub reasoning_effort: Option<String>,
    /// Wait for background tasks to report `task_completed` before exiting (default true).
    pub wait_for_background: bool,
    /// Max time to wait for background work to finish after the first turn ends.
    pub background_wait_timeout: Duration,
    /// Hard cap on the whole turn (`--timeout` / `FUIGO_HEADLESS_TIMEOUT_SECS`).
    /// `None` (the default) keeps the historical behaviour: wait indefinitely for the agent.
    pub total_timeout: Option<Duration>,
    /// After the prompt (or instead of one when resuming), run `fuigo/memory/flush`.
    pub memory_flush: bool,
    /// CLI `--experimental-memory` / `--no-memory` override for the headless agent.
    pub memory_enabled_override: Option<bool>,
}

/// Process exit code for a run that ended because a permission was denied.
///
/// Contract D.2.1: a dedicated, documented and **stable** code — downstream scripts branch on it,
/// so it may not be renumbered. The space around it is already allocated: `0` success, `1` generic
/// error, `2` a managed-policy requirement failure (`fuigo-pager-bin/src/main.rs`), `130`/`143`
/// SIGINT/SIGTERM. `3` is the lowest free code; it avoids the shell's `126`/`127` ("cannot
/// execute") and stays clear of the `128+n` signal range.
pub const PERMISSION_DENIED_EXIT_CODE: i32 = 3;

/// Which rule refused a headless permission request.
///
/// Closed over the denial sites in [`handle_headless_acp_message`]: a new denial site adds a
/// variant rather than reusing one, so a consumer can always tell what refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadlessDenialRule {
    /// Headless mode has no operator to ask, so it never approves a permission request.
    HeadlessNeverApproves,
    /// `--yolo` auto-approves, but this request offered no allow option to select.
    YoloHadNoAllowOption,
    /// A budget refused the next model request: the execution's token-budget guard (Contract D.4), or
    /// the model-call or runtime limit (P44). The shell
    /// reports it as the turn's ACP error with `data.code = "execution_budget_denied"`
    /// ([`fuigo_shell::acp_error::ExecutionBudgetDenial`]); the inner rule is the shell's own.
    ExecutionBudget(fuigo_shell::acp_error::ExecutionBudgetRule),
    /// A budget denial whose rule this build does not know (a newer agent). Still a denial —
    /// the shell's stable `data.code` says so — so it still exits with the denial code.
    ExecutionBudgetUnrecognized,
}

impl HeadlessDenialRule {
    /// Stable wire id, part of the machine-readable record (D.2.2). Never localize it.
    pub fn id(self) -> &'static str {
        match self {
            Self::HeadlessNeverApproves => "headless_never_approves",
            Self::YoloHadNoAllowOption => "yolo_had_no_allow_option",
            Self::ExecutionBudget(rule) => rule.id(),
            Self::ExecutionBudgetUnrecognized => {
                fuigo_shell::acp_error::EXECUTION_BUDGET_DENIED_CODE
            }
        }
    }

    /// What the operator would have to change (D.2.2): a permission mode, a config key, a grant.
    pub fn remedy(self) -> &'static str {
        match self {
            Self::HeadlessNeverApproves => {
                "pre-approve it before the run — pass --allow, raise --permission-mode, or trust a \
                 folder whose project config allows it; headless mode has nobody to ask. No --allow \
                 rule covers a shell command that writes a file by redirect (`> file`); \
                 --always-approve runs one (--permission-mode auto runs it only if its classifier \
                 approves), and deny rules still apply"
            }
            Self::YoloHadNoAllowOption => {
                "a deny rule or protected path left the request with no allow option — remove the \
                 matching entry from --deny or the permissions config"
            }
            Self::ExecutionBudget(rule) => rule.remedy(),
            Self::ExecutionBudgetUnrecognized => {
                "an agent budget refused the request under a rule this build does not \
                 know; the agent's error message names it and its remedy"
            }
        }
    }
}

/// A headless permission denial, as data.
///
/// Contract D.2.2 wants three things recoverable without parsing English: what was requested, which
/// rule denied it, and the remedy. This is that record. It is carried **by value** from the ACP
/// message loop out to `main`, never collapsed to a bool, so the exit path still knows all three.
/// P02b renders it into each [`OutputFormat`]; nothing here formats for a wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadlessDenial {
    /// The rule that refused.
    pub rule: HeadlessDenialRule,
    /// Title of the tool call that asked, when the agent supplied one.
    pub tool_title: Option<String>,
    /// ACP tool-call id, so the denial ties to the tool call already on the stream.
    pub tool_call_id: String,
    /// The option kinds offered, in the order offered: the evidence that no allow option existed.
    pub offered_option_kinds: Vec<String>,
    /// The agent's own message for a budget rule this build does not know. It names the rule and its
    /// remedy, which [`HeadlessDenialRule::ExecutionBudgetUnrecognized`] cannot, so [`Self::human_line`]
    /// carries it: the denial is then reported by that one line and nowhere else (P51).
    pub agent_message: Option<String>,
}

impl HeadlessDenial {
    /// Record the denial of `request` by `rule`.
    fn from_request(request: &acp::RequestPermissionRequest, rule: HeadlessDenialRule) -> Self {
        Self {
            rule,
            // P149 (S8): the title is printed on stderr (`human_line`/`notice_line`) and in the denial record, so
            // a credential this process sent is replaced in it, as on every other error output.
            tool_title: request
                .tool_call
                .fields
                .title
                .clone()
                .map(fuigo_telemetry::sent_credentials::scrub_owned),
            tool_call_id: request.tool_call.tool_call_id.0.to_string(),
            offered_option_kinds: request
                .options
                .iter()
                .map(|option| permission_option_kind_wire(option.kind))
                .collect(),
            agent_message: None,
        }
    }

    /// A model request refused by the execution's token-budget guard (Contract D.4): no tool call
    /// asked, so there is no title, id or option list.
    pub fn from_budget_rule(rule: HeadlessDenialRule) -> Self {
        debug_assert!(matches!(
            rule,
            HeadlessDenialRule::ExecutionBudget(_)
                | HeadlessDenialRule::ExecutionBudgetUnrecognized
        ));
        Self {
            rule,
            tool_title: None,
            tool_call_id: String::new(),
            offered_option_kinds: Vec::new(),
            agent_message: None,
        }
    }

    /// Whether the token-budget guard refused a model request (D.4), rather than a tool permission.
    pub(crate) fn is_budget(&self) -> bool {
        matches!(
            self.rule,
            HeadlessDenialRule::ExecutionBudget(_)
                | HeadlessDenialRule::ExecutionBudgetUnrecognized
        )
    }

    /// The exit code a run blocked by this denial must produce (D.2.1).
    pub fn exit_code(&self) -> i32 {
        PERMISSION_DENIED_EXIT_CODE
    }

    /// What was requested, for the human line. The title is the agent's own wording; the tool-call
    /// id is the join key a reader needs when several calls are in flight.
    pub fn requested(&self) -> String {
        if self.is_budget() {
            return "the next model request".to_string();
        }
        match self.tool_title.as_deref() {
            Some(title) if !title.is_empty() => format!("{title} (tool call {})", self.tool_call_id),
            _ => format!("tool call {}", self.tool_call_id),
        }
    }

    /// The single English line required by D.2.3, remedy included.
    ///
    /// Written by the process exit path to stderr for every `--output-format`, and **never** gated
    /// on a TTY: headless is a mode, not an inference (D.3).
    pub fn human_line(&self) -> String {
        if self.is_budget() {
            let detail = self
                .agent_message
                .as_deref()
                .map(|m| format!(" Agent message: {}", m.split_whitespace().collect::<Vec<_>>().join(" ")))
                .unwrap_or_default();
            return format!(
                "fuigo: blocked — an execution budget refused {}. \
                 Denied by rule `{}`. Remedy: {}. Exiting {}.{detail}",
                self.requested(),
                self.rule.id(),
                self.rule.remedy(),
                self.exit_code(),
            );
        }
        format!(
            "fuigo: blocked — permission denied in headless mode: {}. \
             Denied by rule `{}`. Remedy: {}. Exiting {}.",
            self.requested(),
            self.rule.id(),
            self.rule.remedy(),
            self.exit_code(),
        )
    }

    /// The English line for a denial the run then carried on past.
    ///
    /// D.3 forbids a denial that is indistinguishable from success, and a run that was refused
    /// something and still finished is exactly that case: the exit code is `0` because the prompt
    /// completed, so the only thing left to say it is one line on stderr. Written for every
    /// `--output-format` and never gated on a TTY, like [`Self::human_line`]. It deliberately omits
    /// an exit code — there is no dedicated code for a run that recovered.
    pub fn notice_line(&self) -> String {
        format!(
            "fuigo: a permission was denied in headless mode and the run continued: {}. \
             Denied by rule `{}`. Remedy: {}.",
            self.requested(),
            self.rule.id(),
            self.rule.remedy(),
        )
    }

    /// The machine-readable denial record (Contract D.2.2): what was requested, which rule refused
    /// it, and the remedy — as data, so a consumer never parses [`Self::human_line`].
    ///
    /// Rides on the terminal line of `json` (the document) and `streaming-json` (the `end` or
    /// `error` line) as `permissionDenied`, rather than as a record of its own: `json` is a single
    /// JSON value, and every consumer of either format reads exactly one terminal record.
    /// `streaming-messages-json` renders the same denial in its own schema's `permission_denials`
    /// shape instead (`headless::reducer::messages`).
    ///
    /// `ended_run` says whether the turn ended at this refusal — the condition for the dedicated exit
    /// code (see `headless_run_outcome`). `exitCode` is present **only** then: a refusal the run
    /// carried past, or one followed by a failure, does not exit `3`, and a record that said it would
    /// would contradict `$?` in the one place a script is told not to read prose.
    pub fn wire_record(&self, ended_run: bool) -> serde_json::Value {
        let mut record = serde_json::json!({
            "rule": self.rule.id(),
            // A budget denial (D.4) refused a model request, not a tool call: no id to join on.
            "toolCallId": (!self.is_budget()).then_some(self.tool_call_id.as_str()),
            "toolTitle": self.tool_title,
            "offeredOptionKinds": self.offered_option_kinds,
            "remedy": self.rule.remedy(),
            "endedRun": ended_run,
        });
        if ended_run {
            record["exitCode"] = serde_json::json!(self.exit_code());
        }
        record
    }
}

/// The ACP wire spelling of a permission option kind.
///
/// Goes through serde rather than a hand-written match so a kind added to the schema is reported as
/// itself instead of silently folding into a catch-all.
fn permission_option_kind_wire(kind: acp::PermissionOptionKind) -> String {
    match serde_json::to_value(kind) {
        Ok(serde_json::Value::String(s)) => s,
        other => {
            tracing::debug!(?other, "headless: unexpected permission option kind encoding");
            format!("{kind:?}")
        }
    }
}

/// How a run ended, as a value the process exit path can map to an exit code.
///
/// Contract D.2.1 and D.3: a permission denial is a first-class outcome, so it travels the
/// **success** channel with its record attached. Putting it in `Err` would hand it to `main`'s
/// generic error handler, which reports every error as `exit(1)` — precisely the
/// "indistinguishable from a crash" collapse the contract forbids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadlessOutcome {
    /// The command ran to its own end. `main` exits as it always did.
    Finished,
    /// A permission request was denied: the run was blocked, not completed.
    PermissionDenied(HeadlessDenial),
}

impl HeadlessOutcome {
    /// The denial record, when this outcome is one.
    pub fn denial(&self) -> Option<&HeadlessDenial> {
        match self {
            Self::Finished => None,
            Self::PermissionDenied(denial) => Some(denial),
        }
    }
}

/// Why a turn that did not error stopped, as far as the exit path cares.
///
/// The discriminator the denial code hangs on. A latched denial says only that *something* was
/// refused somewhere in the run — a subagent, a background task, the memory flush — not that the
/// run ended there. This says whether it did, and it reads the shell's own answer rather than
/// guessing: a permission request answered `Cancelled` ends the turn through
/// `ToolLoop::Cancelled` -> `TurnOutcome::Cancelled { PermissionCancelled }`
/// (`fuigo-shell/src/session/acp_session_impl/tool_calls.rs`, `.../turn.rs`), which stamps
/// `_meta.cancellationCategory = "PermissionCancelled"` on the prompt response
/// (`fuigo_shell::session::commands::PERMISSION_CANCELLED_CATEGORY`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TurnStop {
    /// The turn reached its own end, or there was no turn to run.
    Ended,
    /// `--max-turns` stopped it; the caller turns this into the error it always was.
    MaxTurns,
    /// The turn stopped because a permission request was dismissed.
    PermissionCancelled,
    /// The turn ended because the execution's token-budget guard refused a model request (D.4),
    /// read from the shell's `data.code = "execution_budget_denied"` on the prompt error.
    BudgetDenied(HeadlessDenialRule),
}

/// Every non-headless command path finishes with `()`; this is the one conversion to the outcome
/// type so those call sites stay one line each.
impl From<()> for HeadlessOutcome {
    fn from((): ()) -> Self {
        Self::Finished
    }
}

struct HeadlessEmitter {
    format: OutputFormat,
    parse_structured_output: bool,
    text_buffer: String,
    thought_buffer: String,
    /// P188: the lengths of `text_buffer` / `thought_buffer` that completed responses own. A discarded attempt's
    /// text (everything after them) is cut off when `retry_state` says the request is being resent.
    text_mark: usize,
    thought_mark: usize,
    /// P188: where each model attempt's text / thinking begins in `text_buffer` / `thought_buffer`, by the
    /// `_meta.streamStartMs` its chunks carried. A discard naming a stream cuts exactly that attempt.
    text_streams: Vec<(i64, usize)>,
    thought_streams: Vec<(i64, usize)>,
    /// P188: the attempt whose text `plain_pending` holds.
    plain_stream: Option<i64>,
    /// P188: `plain` holds the current response's text until the response completes (or a tool call or the end of
    /// the run closes it): stdout cannot take text back, and a resent request streams the reply again.
    plain_pending: String,
    /// Schema-validated output read from the prompt-response `_meta`.
    structured_output: Option<Result<serde_json::Value, String>>,
    usage: Option<serde_json::Value>,
    /// Reducer for the streaming formats; `None` for `plain`/`json`.
    reducer: Option<Box<dyn Reducer>>,
    /// Set when the prompt is sent; `result.duration_ms` on the terminal line is measured from it.
    prompt_started: Option<Instant>,
    /// Where the wire output goes. Production is stdout; tests capture the bytes so the terminal
    /// document a machine consumer actually reads can be asserted on.
    out: Box<dyn std::io::Write + Send>,
    /// Latched once stdout is unwritable so later writes are dropped instead of panicking.
    output_closed: bool,
    /// First hard stdout IO error (not a broken pipe), surfaced so the process exits non-zero.
    write_error: Option<std::io::Error>,
    /// First permission denial of the run, surfaced so the process exits with the dedicated code.
    ///
    /// Same idiom as `write_error`: the condition is latched wherever in the ACP loop it happens and
    /// read once at the exit path, because the loop has no way to return anything. The first denial
    /// wins — it is the one that blocked the run; later ones are its consequences.
    permission_denial: Option<HeadlessDenial>,
    /// Whether the turn ended at the latched denial, as the terminal response said
    /// (`TurnStop::PermissionCancelled` with no run-level error on top). Set by
    /// `emit_completed_response` just before the terminal line is written, and read only there: it
    /// is what the record's `endedRun`/`exitCode` report. `false` everywhere else, including every
    /// `on_error` path, which exits `1` whatever was refused on the way.
    denial_ended_run: bool,
    /// Whether the run's terminal document (`on_end` / `on_error`) has been written. An interrupt
    /// that lands after it must not write a second one.
    terminal_emitted: bool,
    /// Usage of the responses that completed so far (see [`Self::terminal_usage`]).
    observed_usage: fuigo_shell::extensions::notification::PromptUsageModel,
}

impl HeadlessEmitter {
    fn new(format: OutputFormat, parse_structured_output: bool) -> Self {
        Self::with_writer(format, parse_structured_output, Box::new(std::io::stdout()))
    }

    fn with_writer(
        format: OutputFormat,
        parse_structured_output: bool,
        out: Box<dyn std::io::Write + Send>,
    ) -> Self {
        Self {
            format,
            parse_structured_output,
            text_buffer: String::new(),
            thought_buffer: String::new(),
            text_mark: 0,
            thought_mark: 0,
            text_streams: Vec::new(),
            thought_streams: Vec::new(),
            plain_stream: None,
            plain_pending: String::new(),
            structured_output: None,
            usage: None,
            reducer: reducer_for(format),
            prompt_started: None,
            out,
            output_closed: false,
            write_error: None,
            permission_denial: None,
            denial_ended_run: false,
            terminal_emitted: false,
            observed_usage: Default::default(),
        }
    }

    /// Checked write to stdout: broken pipe latches a clean stop, any other error is latched and returned.
    fn write_out(&mut self, bytes: &[u8], flush: bool) -> std::io::Result<()> {
        if self.output_closed {
            return Ok(());
        }
        use std::io::Write as _;
        let mut result = self.out.write_all(bytes);
        if flush && result.is_ok() {
            result = self.out.flush();
        }
        self.record_write_result(result)
    }

    /// Fold a write result into the latches: broken pipe is a clean stop, any other error is surfaced.
    fn record_write_result(&mut self, result: std::io::Result<()>) -> std::io::Result<()> {
        let Err(e) = result else {
            return Ok(());
        };
        self.output_closed = true;
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            tracing::debug!("headless: stdout closed (broken pipe); halting output");
            return Ok(());
        }
        tracing::error!(error = %e, "headless: stdout write failed; halting output");
        if self.write_error.is_none() {
            self.write_error = Some(std::io::Error::new(e.kind(), e.to_string()));
        }
        Err(e)
    }

    /// Take the latched hard stdout error, if any.
    fn take_output_error(&mut self) -> Option<std::io::Error> {
        self.write_error.take()
    }

    /// Latch a permission denial (Contract D.2). The first one wins; it is what blocked the run.
    ///
    /// The structured record is rendered from this latch onto each format's terminal line
    /// (`build_json_result`, `on_end`, `on_error`), so only a denial latched **before** the terminal
    /// line reaches stdout. One latched after it — the post-turn memory flush — is reported on stderr
    /// by `headless_run_outcome` and nowhere else, because the terminal record has already gone.
    fn record_permission_denial(&mut self, denial: HeadlessDenial) {
        tracing::warn!(
            rule = denial.rule.id(),
            tool_call_id = %denial.tool_call_id,
            "headless: permission denied; the run is blocked"
        );
        if self.permission_denial.is_none() {
            self.permission_denial = Some(denial);
        }
    }

    /// Take the latched permission denial, if any.
    fn take_permission_denial(&mut self) -> Option<HeadlessDenial> {
        self.permission_denial.take()
    }

    /// Emit one compact NDJSON wire line plus newline.
    fn emit_line(&mut self, line: &serde_json::Value) {
        let mut buf = line.to_string();
        buf.push('\n');
        let _ = self.write_out(buf.as_bytes(), false);
    }

    /// Mark the wall-clock start of the run for `result.duration_ms`.
    fn mark_prompt_started(&mut self) {
        self.prompt_started = Some(Instant::now());
    }

    fn duration_ms(&self) -> u64 {
        self.prompt_started
            .map_or(0, |t| t.elapsed().as_millis() as u64)
    }

    /// Emit the reducer preamble once the session context is known.
    fn begin_session(&mut self, ctx: SessionContext) {
        let Some(reducer) = self.reducer.as_mut() else {
            return;
        };
        let lines = reducer.begin(ctx);
        self.emit_lines(lines);
    }

    /// Emit a batch of NDJSON wire lines produced by the reducer.
    fn emit_lines(&mut self, lines: Vec<serde_json::Value>) {
        for line in lines {
            self.emit_line(&line);
        }
    }

    /// Render an `fuigo/*` lifecycle notification for the active format.
    fn on_lifecycle(&mut self, event: Lifecycle) {
        match self.format {
            OutputFormat::Plain => {
                crate::best_effort_stderr::eprint_line(&event.plain_message());
            }
            // stdout stays one JSON document; a refused reference to the saved key is a warning for the person at the
            // terminal, so it goes to stderr (the other lifecycle events have no stderr line in these formats).
            OutputFormat::Json => {
                if matches!(event, Lifecycle::ConfigNotice { .. }) {
                    crate::best_effort_stderr::eprint_line(&event.plain_message());
                }
            }
            OutputFormat::StreamingJson => {
                self.reduce_and_emit(StreamEvent::Lifecycle(event));
            }
            OutputFormat::StreamingMessagesJson => {
                if matches!(event, Lifecycle::ConfigNotice { .. }) {
                    crate::best_effort_stderr::eprint_line(&event.plain_message());
                }
                self.reduce_and_emit(StreamEvent::Lifecycle(event));
            }
        }
    }

    /// P188: response boundaries for the formats that hold text themselves (`plain` writes, `json`/`stream-json`
    /// buffer). A completed response, or a tool call (dispatched only for a committed response), makes the text so
    /// far final; a discard drops what came after the last boundary.
    fn observe_response_boundary(&mut self, event: &StreamEvent) {
        match event {
            // A completed response is final. Tool events are not boundaries: a hosted tool (web/x search) reports
            // while its response is still streaming and can still fail.
            StreamEvent::ResponseCompleted { .. } => {
                self.text_mark = self.text_buffer.len();
                self.thought_mark = self.thought_buffer.len();
                self.flush_plain_pending();
            }
            StreamEvent::ResponseDiscarded {
                stream_start_ms: Some(stream),
                ..
            } => {
                cut_stream(&mut self.text_buffer, &mut self.text_streams, *stream);
                cut_stream(&mut self.thought_buffer, &mut self.thought_streams, *stream);
                if self.plain_stream == Some(*stream) {
                    self.plain_pending.clear();
                }
            }
            // An older notice without the stream: everything since the last completed response
            StreamEvent::ResponseDiscarded {
                stream_start_ms: None,
                ..
            } => {
                self.text_buffer.truncate(self.text_mark);
                self.thought_buffer.truncate(self.thought_mark);
                self.plain_pending.clear();
            }
            _ => {}
        }
    }

    /// Write the `plain` text held for the current response.
    fn flush_plain_pending(&mut self) {
        if self.plain_pending.is_empty() {
            return;
        }
        let pending = std::mem::take(&mut self.plain_pending);
        let _ = self.write_out(pending.as_bytes(), true);
    }

    /// Fold one event through the reducer and emit its lines; a no-op for `plain`/`json`.
    fn reduce_and_emit(&mut self, event: StreamEvent) {
        self.observe_response_usage(&event);
        self.observe_response_boundary(&event);
        let Some(reducer) = self.reducer.as_mut() else {
            return;
        };
        let lines = reducer.reduce(event);
        self.emit_lines(lines);
    }

    /// Add one completed response's usage to the running ledger of what this run has been billed so
    /// far. The terminal record of a run that never got a final prompt-level ledger (interrupt,
    /// timeout, connection error) reports this instead of nothing or zeros.
    fn observe_response_usage(&mut self, event: &StreamEvent) {
        let StreamEvent::ResponseCompleted { usage: Some(u), .. } = event else {
            return;
        };
        let t = &mut self.observed_usage;
        // ACP identity: `input_tokens` is the whole prompt, cache reads and creation included.
        t.input_tokens += u.input_tokens + u.cache_read_input_tokens + u.cache_creation_input_tokens;
        t.output_tokens += u.output_tokens;
        t.cached_read_tokens += u.cache_read_input_tokens;
        t.cache_creation_tokens += u.cache_creation_input_tokens;
        t.reasoning_tokens += u.reasoning_tokens;
        t.total_tokens = t.input_tokens + t.output_tokens;
        t.model_calls += 1;
    }

    /// The usage a failed/interrupted run reports: the prompt-level ledger when the shell sent one,
    /// else what completed responses were observed to cost, marked incomplete (the in-flight
    /// response, if any, is not in it). `None` when nothing was billed yet.
    fn terminal_usage(&self) -> Option<serde_json::Value> {
        if let Some(u) = &self.usage {
            return Some(u.clone());
        }
        if self.observed_usage.model_calls == 0 {
            return None;
        }
        let ledger = fuigo_shell::extensions::notification::PromptUsage {
            totals: self.observed_usage.clone(),
            num_turns: self.observed_usage.model_calls,
            usage_is_incomplete: true,
            ..Default::default()
        };
        serde_json::to_value(&ledger).ok()
    }

    /// Schema output for a terminal line: `Ok`, `Err`, or `None` when not requested.
    fn resolved_structured_output(&self) -> Option<Result<serde_json::Value, String>> {
        if !self.parse_structured_output {
            return None;
        }
        Some(
            self.structured_output
                .clone()
                .unwrap_or_else(|| Err("model did not produce structured output".to_string())),
        )
    }

    /// Read structured output (or its error) from the prompt-response `_meta`.
    fn set_structured_output_from_meta(&mut self, meta: Option<&acp::Meta>) {
        if !self.parse_structured_output {
            return;
        }
        let Some(meta) = meta else { return };
        if let Some(err) = meta.get("structuredOutputError").and_then(|v| v.as_str()) {
            // P149 (S8, Astra r3 #1): a schema-validation error quotes the rejected value, and it rides an `Ok`
            // reply the ACP reply-rail scrub never sees; it is printed on the terminal document, so scrub it here.
            self.structured_output =
                Some(Err(fuigo_telemetry::sent_credentials::scrub_owned(err.to_string())));
        } else if let Some(value) = meta.get("structuredOutput") {
            self.structured_output = Some(Ok(value.clone()));
        }
    }

    fn set_usage_from_meta(&mut self, meta: Option<&acp::Meta>) {
        let Some(meta) = meta else { return };
        self.usage = meta.get("usage").cloned();
    }

    fn on_text_chunk(&mut self, text: &str, stream: Option<i64>) {
        note_stream(&mut self.text_streams, stream, self.text_buffer.len());
        match self.format {
            OutputFormat::Plain => {
                // A new attempt began with no discard of the one held: that one was accepted
                if stream.is_some() && stream != self.plain_stream {
                    self.flush_plain_pending();
                    self.plain_stream = stream;
                }
                self.plain_pending.push_str(text);
            }
            OutputFormat::Json => {
                self.text_buffer.push_str(text);
            }
            OutputFormat::StreamingMessagesJson => {
                self.text_buffer.push_str(text);
                self.reduce_and_emit(StreamEvent::AgentMessage(text.to_string()));
            }
            OutputFormat::StreamingJson => {
                self.reduce_and_emit(StreamEvent::AgentMessage(text.to_string()));
            }
        }
    }

    fn on_thought_chunk(&mut self, text: &str, stream: Option<i64>) {
        note_stream(&mut self.thought_streams, stream, self.thought_buffer.len());
        match self.format {
            OutputFormat::Plain => { /* no-op */ }
            OutputFormat::Json => {
                self.thought_buffer.push_str(text);
            }
            OutputFormat::StreamingJson | OutputFormat::StreamingMessagesJson => {
                self.reduce_and_emit(StreamEvent::AgentThought(text.to_string()));
            }
        }
    }

    fn attach_structured_output(&self, target: &mut serde_json::Value) {
        if !self.parse_structured_output {
            return;
        }
        // Only the agent's validated `_meta` output is trusted; never parse the raw text buffer.
        let result = self
            .structured_output
            .clone()
            .unwrap_or_else(|| Err("model did not produce structured output".to_string()));
        crate::headless::reducer::attach_structured_output(target, Some(result));
    }

    /// Final object for `--output-format json`, including spend fields when present.
    fn build_json_result(
        &self,
        stop_reason: &str,
        session_id: &str,
        request_id: &str,
    ) -> serde_json::Value {
        let mut result = serde_json::json!({
            "text": self.text_buffer,
            "stopReason": stop_reason,
            "sessionId": session_id,
            "requestId": request_id
        });
        if !self.thought_buffer.is_empty() {
            result["thought"] = serde_json::Value::String(self.thought_buffer.clone());
        }
        if let Some(usage) = &self.usage {
            attach_result_usage(&mut result, usage);
        }
        // Contract D.2.2: the denial as data on the document a machine consumer reads, so the reason
        // never has to be recovered from the stderr prose. Additive and conditional, like `thought`,
        // `usage` and `error` — the document stays exactly one JSON value.
        if let Some(denial) = &self.permission_denial {
            result["permissionDenied"] = denial.wire_record(self.denial_ended_run);
        }
        self.attach_structured_output(&mut result);
        result
    }

    /// Emit the terminal document for a turn that produced a response.
    ///
    /// `error` folds a run-level failure that arrived *after* the turn answered (today: the
    /// `--timeout` hard cap) into that same document. It must never be emitted as a second
    /// terminal record: every machine consumer of `json`/`stream-json` reads exactly one.
    fn on_end(
        &mut self,
        stop_reason: &str,
        session_id: &str,
        request_id: &str,
        error: Option<&str>,
    ) {
        // P149 (S8, Astra r2): the run-level error folded into the terminal document is an error output too.
        let scrubbed = error.map(fuigo_telemetry::sent_credentials::scrub);
        let error = scrubbed.as_deref();
        self.terminal_emitted = true;
        self.flush_plain_pending();
        match self.format {
            OutputFormat::Plain => {
                let _ = self.write_out(b"\n", false);
                // Plain has no terminal document, and the run-level failure it would carry is
                // written to stderr exactly once, by `main`'s `Error: ...` line: every caller that
                // passes `error` also returns it as `Err`. Printing it here too is the P51 double.
                let _ = error;
            }
            OutputFormat::Json => {
                let mut result = self.build_json_result(stop_reason, session_id, request_id);
                if let Some(error) = error
                    && let Some(obj) = result.as_object_mut()
                {
                    obj.insert(
                        "error".to_string(),
                        serde_json::Value::String(error.to_string()),
                    );
                }
                let mut rendered =
                    serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string());
                rendered.push('\n');
                let _ = self.write_out(rendered.as_bytes(), false);
            }
            OutputFormat::StreamingJson | OutputFormat::StreamingMessagesJson => {
                let usage = self.usage.clone();
                let structured_output = self.resolved_structured_output();
                let result_text = self.text_buffer.clone();
                let duration_ms = self.duration_ms();
                let denial = self.permission_denial.clone();
                let ended_run = self.denial_ended_run;
                let lines = self.reducer.as_mut().map(|reducer| {
                    // D.2.2 on the streaming formats: the reducer renders the record onto the
                    // terminal line it is about to build, in its own wire shape.
                    if let Some(denial) = &denial {
                        reducer.permission_denied(denial, ended_run);
                    }
                    let end = TurnEnd {
                        stop_reason,
                        session_id,
                        request_id,
                        usage: usage.as_ref(),
                        structured_output,
                        result_text: result_text.as_str(),
                        duration_ms,
                        error,
                    };
                    reducer.finish(&end)
                });
                if let Some(lines) = lines {
                    self.emit_lines(lines);
                }
            }
        }
    }

    /// Emit the max turns marker for the active format.
    fn on_max_turns(&mut self) {
        self.flush_plain_pending();
        match self.format {
            // Plain's stderr line is `main`'s `Error: max turns reached` (the run returns `Err`);
            // a second "Max turns reached" here would be the same condition printed twice.
            OutputFormat::Plain => {}
            // Conveyed by `stopReason` in the terminal JSON and result.
            OutputFormat::Json => {}
            OutputFormat::StreamingJson | OutputFormat::StreamingMessagesJson => {
                let lines = self.reducer.as_mut().map(|reducer| reducer.max_turns());
                if let Some(lines) = lines {
                    self.emit_lines(lines);
                }
            }
        }
    }

    /// Emit the terminal error; `stop_reason_override` stamps a Messages stop reason (e.g. `max_tokens`).
    fn on_error(&mut self, message: &str, stop_reason_override: Option<&str>) {
        // P149 (S8): the error line is a display sink, so every format writes the text with the credentials this
        // process sent replaced, as the ACP reply rail and the TUI do (`main`'s `Error:` line does the same).
        let message = fuigo_telemetry::sent_credentials::scrub(message);
        let message = message.as_ref();
        self.terminal_emitted = true;
        // The text a failed run already produced is still printed, as it was when `plain` streamed it
        self.flush_plain_pending();
        match self.format {
            // Plain writes nothing: every `on_error` caller but one returns the same message as
            // `Err`, and `main` is the single authoritative stderr print (`Error: ...`) for it.
            // The one exception (an unrecognized budget rule, which returns `Ok`) prints itself in
            // `finish_turn`. P51: this used to print as well, so each failure appeared twice.
            OutputFormat::Plain => {}
            OutputFormat::Json => {
                let mut err = serde_json::json!({"type":"error","message": message});
                if let Some(usage) = &self.terminal_usage() {
                    attach_result_usage(&mut err, usage);
                }
                // The error line is this run's whole document, so D.2.2's record belongs on it too.
                // An error exits `1`, so the record never claims the run ended at the refusal — except
                // a token-budget denial (D.4), which reports through this line and sets the flag.
                if let Some(denial) = &self.permission_denial {
                    err["permissionDenied"] = denial.wire_record(self.denial_ended_run);
                }
                self.emit_line(&err);
            }
            OutputFormat::StreamingJson | OutputFormat::StreamingMessagesJson => {
                let usage = self.terminal_usage();
                let duration_ms = self.duration_ms();
                let denial = self.permission_denial.clone();
                let ended_run = self.denial_ended_run;
                let lines = self.reducer.as_mut().map(|reducer| {
                    if let Some(denial) = &denial {
                        reducer.permission_denied(denial, ended_run);
                    }
                    reducer.error(message, usage.as_ref(), duration_ms, stop_reason_override)
                });
                if let Some(lines) = lines {
                    self.emit_lines(lines);
                }
            }
        }
    }
}

/// P188: remember where a model attempt's text begins (`stream` is its `_meta.streamStartMs`).
fn note_stream(streams: &mut Vec<(i64, usize)>, stream: Option<i64>, at: usize) {
    if let Some(stream) = stream
        && streams.last().is_none_or(|(last, _)| *last != stream)
    {
        streams.push((stream, at));
    }
}

/// P188: cut an attempt's text out of `buffer` (it is always the tail: the attempt being resent is the latest).
fn cut_stream(buffer: &mut String, streams: &mut Vec<(i64, usize)>, stream: i64) {
    if let Some(i) = streams.iter().position(|(s, _)| *s == stream) {
        buffer.truncate(streams[i].1);
        streams.truncate(i);
    }
}

/// `_meta.streamStartMs` of a session update: the model attempt it came from.
fn update_stream_start_ms(meta: Option<&acp::Meta>) -> Option<i64> {
    meta.and_then(|m| m.get("streamStartMs"))
        .and_then(serde_json::Value::as_i64)
}

pub(crate) fn attach_result_usage(result: &mut serde_json::Value, usage: &serde_json::Value) {
    fuigo_shell::extensions::notification::attach_result_usage_fail_closed(result, usage);
}

/// Snake_case wire token for an ACP stop reason.
fn stop_reason_wire(reason: acp::StopReason) -> String {
    match reason {
        acp::StopReason::EndTurn => "end_turn",
        acp::StopReason::MaxTokens => "max_tokens",
        acp::StopReason::MaxTurnRequests => "max_turn_requests",
        acp::StopReason::Refusal => "refusal",
        acp::StopReason::Cancelled => "cancelled",
        // Fail loud on an unknown future variant, then degrade to `end_turn`.
        other => {
            tracing::warn!(
                stop_reason = ?other,
                "headless: unknown ACP StopReason; defaulting wire token to end_turn"
            );
            "end_turn"
        }
    }
    .to_string()
}

/// Configured MCP servers for the `init` line; all report `"connected"` (status is not resolved here).
fn mcp_server_names(cwd: &Path) -> Vec<McpServer> {
    let servers =
        cli_config::load_mcp_servers(cwd, &fuigo_tools::types::compat::CompatConfig::default());
    servers
        .iter()
        .filter_map(|s| {
            let name = match s {
                acp::McpServer::Http(h) => h.name.clone(),
                acp::McpServer::Sse(h) => h.name.clone(),
                acp::McpServer::Stdio(h) => h.name.clone(),
                _ => return None,
            };
            Some(McpServer {
                name,
                status: "connected".to_string(),
            })
        })
        .collect()
}

fn auto_respond_to_permissions(
    args: &acp::RequestPermissionRequest,
    option_kinds: &[acp::PermissionOptionKind],
) -> Option<acp::RequestPermissionResponse> {
    for &option_kind in option_kinds {
        for option in &args.options {
            if option.kind == option_kind {
                return Some(acp::RequestPermissionResponse::new(
                    acp::RequestPermissionOutcome::Selected(acp::SelectedPermissionOutcome::new(
                        option.option_id.clone(),
                    )),
                ));
            }
        }
    }
    None
}

/// "Not signed in" error message, tailored to the session type.
fn auth_required_message(interactive: bool) -> String {
    if interactive {
        "Not signed in. Run `fuigo login` to authenticate \
         (or `fuigo login --device-code` if no browser is available)."
            .to_string()
    } else {
        "Not signed in. To authenticate without a browser, run:\n  \
         fuigo login --device-code\n\n\
         Alternatively, set the FUIGO_API_KEY environment variable \
         or run `fuigo login` on a machine with a browser."
            .to_string()
    }
}

/// Authenticate via the agent's `defaultAuthMethodId`, failing closed when none is available.
/// Returns whether the selected method is API-key auth.
async fn authenticate(
    acp_tx: &AcpAgentTx,
    auths: &[acp::AuthMethod],
    default_auth_method_id: Option<&acp::AuthMethodId>,
) -> anyhow::Result<bool> {
    let method_id = crate::acp::select_eager_auth_method(auths, default_auth_method_id)
        .ok_or_else(|| {
            use std::io::IsTerminal;
            let interactive = std::io::stdin().is_terminal()
                && !fuigo_shell::util::clipboard::is_remote_session();
            anyhow::anyhow!("{}", auth_required_message(interactive))
        })?;
    let kind = AuthMethodKind::from_id(&method_id);
    // Prefer non-interactive methods only; interactive login is not usable headless.
    if kind.needs_interactive_login() {
        use std::io::IsTerminal;
        let interactive =
            std::io::stdin().is_terminal() && !fuigo_shell::util::clipboard::is_remote_session();
        anyhow::bail!("{}", auth_required_message(interactive));
    }
    let is_api_key_auth = kind.is_api_key();
    let _resp: acp::AuthenticateResponse = acp_send(
        acp::AuthenticateRequest::new(method_id)
            .meta(serde_json::json!({"headless": true}).as_object().cloned()),
        acp_tx,
    )
    .await
    .map_err(|e| anyhow::anyhow!(acp_error_text(&e)))?;
    Ok(is_api_key_auth)
}

fn build_headless_init_request(
    rules: Option<&str>,
    system_prompt_override: Option<&str>,
) -> acp::InitializeRequest {
    let mut meta = serde_json::json!({
        "clientType": HEADLESS_CLIENT_TYPE,
        "clientVersion": PAGER_CLIENT_VERSION,
    });
    if let Some(rules) = rules {
        meta["rules"] = serde_json::json!(rules);
    }
    if let Some(system_prompt_override) = system_prompt_override {
        meta["systemPromptOverride"] = serde_json::json!(system_prompt_override);
    }
    meta["startupHints"] = serde_json::json!({
        "nonInteractive": true,
        "skipGitStatus": true,
        "skipProjectLayout": true,
    });

    acp::InitializeRequest::new(acp::ProtocolVersion::V1)
        .client_capabilities(
            acp::ClientCapabilities::new()
                .fs(acp::FileSystemCapabilities::new())
                .terminal(false),
        )
        .meta(meta.as_object().cloned())
}

#[derive(Debug)]
struct OpenedSession {
    session_id: acp::SessionId,
    models: ModelState,
    /// Directory the session is anchored to (launch cwd, resume `original_cwd`, or fork `write_cwd`).
    cwd: PathBuf,
}

async fn open_session(
    acp_tx: &AcpAgentTx,
    cwd: &Path,
    session_id_flag: Option<&str>,
    restore_code: Option<bool>,
    deadline: RunDeadline,
) -> anyhow::Result<OpenedSession> {
    // Sessions open before the agent resolves per-vendor compat; default all-on until it does.
    let mcp_servers =
        cli_config::load_mcp_servers(cwd, &fuigo_tools::types::compat::CompatConfig::default());

    if let Some(sid) = session_id_flag {
        // A load the agent refused because the session is held elsewhere (B23: another process is recovering it)
        // keeps the agent's own words: "Session does not exist" would send the operator to the wrong remedy.
        let mut unavailable: Option<String> = None;
        let request =
            acp::LoadSessionRequest::new(acp::SessionId::new(sid.to_string()), cwd.to_path_buf())
                .mcp_servers(mcp_servers.clone())
                .meta({
                    let mut m = acp::Meta::new();
                    m.insert("noReplay".into(), serde_json::Value::Bool(true));
                    if let Some(rc) = restore_code {
                        m.insert("fuigo/restore_code".into(), serde_json::Value::Bool(rc));
                    }
                    Some(m)
                });
        let try_load: Result<acp::LoadSessionResponse, _> = with_send_deadline(
            "session/load",
            deadline.budget(None),
            async {
                let result = acp_send(request, acp_tx).await;
                if let Err(error) = &result
                    && is_session_unavailable(error)
                {
                    unavailable = Some(acp_error_text(error));
                }
                result
            },
        )
        .await;
        match try_load {
            Ok(resp) => {
                return Ok(OpenedSession {
                    session_id: acp::SessionId::new(sid.to_string()),
                    models: ModelState::from(resp.models),
                    cwd: cwd.to_path_buf(),
                });
            }
            // A run cap that elapsed mid-load is not a missing session: telling the operator their
            // session is gone sends them to the wrong remedy (re-running without `--resume`, which
            // loses the conversation). Report the timeout the wrapper already named.
            Err(e) if e.is::<SendDeadlineElapsed>() => return Err(e),
            Err(e) => {
                tracing::debug!(error = %e, session = sid, "headless: session/load failed");
                if let Some(message) = unavailable {
                    anyhow::bail!(message);
                }
                anyhow::bail!("Session does not exist");
            }
        }
    }

    let new_resp: acp::NewSessionResponse = with_send_deadline(
        "session/new",
        deadline.budget(None),
        acp_send(
            acp::NewSessionRequest::new(cwd.to_path_buf())
                .mcp_servers(mcp_servers)
                // Fresh `-p` sessions persist as headless so `/resume` keeps them off its default pages; the load path above never restamps
                .meta(
                    serde_json::json!({ "sessionKind": "headless" })
                        .as_object()
                        .cloned(),
                ),
            acp_tx,
        ),
    )
    .await?;
    Ok(OpenedSession {
        session_id: new_resp.session_id,
        models: ModelState::from(new_resp.models),
        cwd: cwd.to_path_buf(),
    })
}

async fn open_session_with_id(
    acp_tx: &AcpAgentTx,
    cwd: &Path,
    session_id: &str,
    deadline: RunDeadline,
) -> anyhow::Result<OpenedSession> {
    let cwd_str = cwd.to_string_lossy();
    crate::app::session_startup::ensure_session_id_available(session_id, &cwd_str)?;
    let mcp_servers =
        cli_config::load_mcp_servers(cwd, &fuigo_tools::types::compat::CompatConfig::default());
    let new_resp: acp::NewSessionResponse = with_send_deadline(
        "session/new",
        deadline.budget(None),
        acp_send(
            acp::NewSessionRequest::new(cwd.to_path_buf())
                .mcp_servers(mcp_servers)
                .meta(
                    serde_json::json!({ "sessionId": session_id, "sessionKind": "headless" })
                        .as_object()
                        .cloned(),
                ),
            acp_tx,
        ),
    )
    .await?;
    Ok(OpenedSession {
        session_id: new_resp.session_id,
        models: ModelState::from(new_resp.models),
        cwd: cwd.to_path_buf(),
    })
}

async fn fork_then_open(
    acp_tx: &AcpAgentTx,
    launch_cwd: &Path,
    parent_id: &str,
    parent_cwd: Option<&Path>,
    new_id: Option<&str>,
    restore_code: Option<bool>,
    deadline: RunDeadline,
) -> anyhow::Result<OpenedSession> {
    use crate::app::session_startup::{
        effective_fork_new_cwd, ensure_session_id_available, fork_response_error,
        fork_response_new_session_id, fork_session_params, parent_session_is_worktree,
    };
    let launch_cwd_str = launch_cwd.to_string_lossy().into_owned();
    // Match interactive: child lands under the parent session cwd, not the launch cwd.
    let new_cwd_str = effective_fork_new_cwd(&launch_cwd_str, parent_cwd);
    let write_cwd = PathBuf::from(&new_cwd_str);
    if let Some(nid) = new_id {
        ensure_session_id_available(nid, &new_cwd_str)?;
    }
    let parent_is_worktree = parent_session_is_worktree(parent_id, &write_cwd);
    let mut payload = fork_session_params(parent_id, &write_cwd, new_id, parent_is_worktree);
    // Shared helper stamps `fork` for interactive `/fork`
    // `-p` children must stay headless: the load path below never restamps
    payload["sessionKind"] = serde_json::Value::String("headless".into());
    let fork_params = serde_json::value::to_raw_value(&payload)
        .map_err(|e| anyhow::anyhow!("serialize fork params: {e}"))?;
    let req = acp::ExtRequest::new("fuigo/session/fork", fork_params.into());
    let resp = with_send_deadline(
        "fuigo/session/fork",
        deadline.budget(None),
        acp_send(req, acp_tx),
    )
    .await?;
    if let Some(err) = fork_response_error(resp.0.get()) {
        anyhow::bail!("fork failed: {err}");
    }
    let child = fork_response_new_session_id(resp.0.get())
        .ok_or_else(|| anyhow::anyhow!("fork response missing newSessionId"))?;
    match open_session(acp_tx, &write_cwd, Some(&child), restore_code, deadline).await {
        Ok(opened) => Ok(opened),
        Err(e) => Err(anyhow::anyhow!(
            "fork succeeded as {child} but load failed: {e}"
        )),
    }
}

/// Mirrors `Effect::CreateWorktreeSession`. A `-s` UUID also names the worktree, and
/// `open_session_with_id` checks its availability under the worktree cwd, which is why
/// `materialize_startup_for_cwd` skipped that check when `has_worktree` is set.
async fn open_session_in_new_worktree(
    acp_tx: &AcpAgentTx,
    cwd: &Path,
    spec: &WorktreeSpec,
    session_id: Option<&str>,
    deadline: RunDeadline,
) -> anyhow::Result<OpenedSession> {
    let created = with_send_deadline(
        CREATE_METHOD,
        deadline.budget(None),
        create_worktree(acp_tx, cwd, spec, &new_worktree_id(session_id)),
    )
    .await?;
    tracing::info!(
        worktree = %created.worktree_root.display(),
        session_cwd = %created.session_cwd.display(),
        copy_mode = ?spec.copy_mode(),
        "headless: worktree created"
    );
    let opened = match session_id {
        Some(sid) => open_session_with_id(acp_tx, &created.session_cwd, sid, deadline).await,
        None => open_session(acp_tx, &created.session_cwd, None, None, deadline).await,
    };
    opened.map_err(|e| {
        anyhow::anyhow!(
            "{}",
            note_orphaned_worktree(&e.to_string(), &created.worktree_root)
        )
    })
}

/// Mirrors the `load_session_id` branch of `Effect::CreateWorktreeSession`: the agent creates the
/// worktree and restores into it, then the session is loaded at the cwd it reports.
async fn resume_session_in_new_worktree(
    acp_tx: &AcpAgentTx,
    cwd: &Path,
    spec: &WorktreeSpec,
    session_id: &str,
    restore_code: Option<bool>,
    local_miss: bool,
    deadline: RunDeadline,
) -> anyhow::Result<OpenedSession> {
    let resumed = with_send_deadline(
        RESUME_METHOD,
        deadline.budget(None),
        resume_session_into_worktree(
            acp_tx,
            cwd,
            spec,
            session_id,
            restore_code,
            local_miss.then_some(session_id),
        ),
    )
    .await?;
    tracing::info!(
        session_id = %resumed.session_id,
        worktree = %resumed.worktree_root.display(),
        session_cwd = %resumed.session_cwd.display(),
        code_restored = resumed.code_restored,
        "headless: session resumed into worktree"
    );
    // resume_session already restored code; asking again on load would redo it.
    open_session(
        acp_tx,
        &resumed.session_cwd,
        Some(&resumed.session_id),
        None,
        deadline,
    )
    .await
    .map_err(|e| {
        anyhow::anyhow!(
            "{}",
            note_orphaned_worktree(&e.to_string(), &resumed.worktree_root)
        )
    })
}

/// Apply `-m` / effort after session open.
/// Effort is soft-ignored on a non-supporting model (still applying `-m`) but hard-fails on a genuinely unknown token.
async fn apply_headless_model_and_effort(
    acp_tx: &AcpAgentTx,
    session_id: &acp::SessionId,
    models: &ModelState,
    model_name: Option<&str>,
    effort_token: Option<&str>,
    deadline: RunDeadline,
) -> anyhow::Result<()> {
    if model_name.is_none() && effort_token.is_none() {
        return Ok(());
    }

    let model_id = if let Some(name) = model_name {
        models
            .resolve_by_name_or_id(name)
            .unwrap_or_else(|| acp::ModelId::new(name))
    } else {
        models.current.clone().ok_or_else(|| {
            anyhow::anyhow!("--effort/--reasoning-effort: no active model to apply effort to")
        })?
    };

    let effort = match effort_token {
        None => None,
        // Pre-catalog: canonical tokens are already stamped; remapped menu ids can't resolve yet.
        Some(token) if models.available.is_empty() => {
            if parse_canonical_effort_token(token).is_none() {
                anyhow::bail!(
                    "--effort/--reasoning-effort: unknown effort level '{token}' \
                     (model catalog unavailable; remapped menu ids require a loaded catalog)"
                );
            }
            None
        }
        Some(token) => match models.resolve_effort_for_model(&model_id, token) {
            Ok(effort) => Some(effort),
            Err(EffortTokenError::Unsupported) => {
                tracing::warn!(
                    model = %model_id.0,
                    token,
                    "--effort/--reasoning-effort: model does not support reasoning effort; ignoring"
                );
                None
            }
            Err(err) => anyhow::bail!("--effort/--reasoning-effort: {}", err.message()),
        },
    };

    if model_name.is_none() && effort.is_none() {
        return Ok(());
    }

    let meta = effort.map(|eff| {
        let mut m = acp::Meta::new();
        m.insert(
            REASONING_EFFORT_META_KEY.to_string(),
            reasoning_effort_meta_value(eff),
        );
        m
    });

    with_send_deadline(
        "session/set_model",
        deadline.budget(None),
        acp_send(
            acp::SetSessionModelRequest::new(session_id.clone(), model_id.clone()).meta(meta),
            acp_tx,
        ),
    )
    .await
    .map_err(|e| {
        if let Some(name) = model_name {
            anyhow::anyhow!(
                "Couldn't set model '{}': {}. Run 'fuigo models' to see available models.",
                name,
                e
            )
        } else {
            anyhow::anyhow!("Couldn't apply reasoning effort: {e}")
        }
    })?;
    tracing::debug!(
        model_id = %model_id.0,
        effort = ?effort,
        "headless: model/effort set"
    );
    Ok(())
}

/// Startup-materialization context for headless (`-p`) runs; never chat mode.
/// Default cap on the pre-turn ACP lifecycle sends (`initialize`, `authenticate`).
///
/// `acp_send` awaits a bare oneshot, so an agent that wedges before answering leaves `fuigo -p`
/// blocked with no deadline at all. The exit reaper already bounds its own sends; these are bounded
/// the same way so startup fails loudly instead of hanging.
const DEFAULT_LIFECYCLE_SEND_TIMEOUT: Duration = Duration::from_secs(120);

/// Escape hatch for the lifecycle cap, in whole seconds. `0` disables it (1.0.16 behaviour).
const LIFECYCLE_TIMEOUT_ENV: &str = "FUIGO_HEADLESS_LIFECYCLE_TIMEOUT_SECS";

/// The lifecycle cap for this run: `FUIGO_HEADLESS_LIFECYCLE_TIMEOUT_SECS` if usable, else 120s.
///
/// Unlike `--timeout` this one applies even to runs that asked for no cap, so it needs a way out: a
/// cold `FUIGO_HOME` on a network mount can legitimately take longer than the default to answer
/// `initialize`, and that run worked in 1.0.16. Read only on the headless path, and leniently, so a
/// malformed value can never break an unrelated mode.
fn lifecycle_send_timeout() -> Option<Duration> {
    parse_lifecycle_timeout_env(std::env::var(LIFECYCLE_TIMEOUT_ENV).ok().as_deref())
}

/// Lenient parse: unset/empty/garbage keep the default, `0` means "no lifecycle cap at all".
fn parse_lifecycle_timeout_env(raw: Option<&str>) -> Option<Duration> {
    let Some(raw) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return Some(DEFAULT_LIFECYCLE_SEND_TIMEOUT);
    };
    match raw.parse::<u64>() {
        Ok(0) => {
            tracing::warn!("{LIFECYCLE_TIMEOUT_ENV}=0: the startup sends run unbounded");
            None
        }
        Ok(secs) => Some(Duration::from_secs(secs)),
        Err(_) => {
            tracing::warn!(
                value = raw,
                "{LIFECYCLE_TIMEOUT_ENV} is not a number of seconds; keeping the default"
            );
            Some(DEFAULT_LIFECYCLE_SEND_TIMEOUT)
        }
    }
}

/// The `--timeout` budget for one headless run.
///
/// `--timeout` is documented as a hard cap on the **whole run**, so every ACP send on the run path
/// draws its deadline from here — not just the prompt turn. `acp_send` awaits a bare oneshot, so an
/// agent that answers `initialize` and then goes silent on `session/new` (the slow-skills-scan
/// shape) would otherwise hang forever with the flag set.
#[derive(Clone, Copy, Debug, Default)]
struct RunDeadline(Option<Instant>);

impl RunDeadline {
    /// Start the clock. `None` keeps the historical behaviour: no cap anywhere.
    fn start(total: Option<Duration>) -> Self {
        Self(total.map(|d| Instant::now() + d))
    }
    /// Time left before the cap, or `None` when uncapped. Saturates at zero once it has passed.
    fn remaining(self) -> Option<Duration> {
        self.0
            .map(|at| at.saturating_duration_since(Instant::now()))
    }
    /// Budget for one send: whichever of the run cap and `cap` comes first.
    fn budget(self, cap: Option<Duration>) -> Option<Duration> {
        match (self.remaining(), cap) {
            (Some(left), Some(cap)) => Some(left.min(cap)),
            (Some(left), None) => Some(left),
            (None, cap) => cap,
        }
    }
}

/// A bounded ACP send ran out of budget. Typed so callers can tell a run-cap timeout apart from a
/// genuine failure of the step (`session/load` reporting "Session does not exist", say).
#[derive(Debug)]
struct SendDeadlineElapsed {
    what: String,
    limit: Duration,
}

impl std::fmt::Display for SendDeadlineElapsed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "timed out after {}s waiting for {}",
            self.limit.as_secs(),
            self.what
        )
    }
}

impl std::error::Error for SendDeadlineElapsed {}

/// Await an ACP send under `limit`, failing with a named error instead of blocking forever.
/// `None` means unbounded — the shape every send on this path had before `--timeout` existed.
/// Text of an error a deadline-bounded send failed with.
/// An `acp::Error` goes through `acp_error_text`: its `Display` would print an object `data` as multi-line JSON.
trait SendErrorText {
    fn send_error_text(&self) -> String;
}

impl SendErrorText for acp::Error {
    fn send_error_text(&self) -> String {
        acp_error_text(self)
    }
}

impl SendErrorText for anyhow::Error {
    fn send_error_text(&self) -> String {
        self.to_string()
    }
}

impl SendErrorText for WorktreeRpcError {
    fn send_error_text(&self) -> String {
        self.0.clone()
    }
}

impl SendErrorText for String {
    fn send_error_text(&self) -> String {
        self.clone()
    }
}

/// The agent's typed `session_unavailable` refusal: the session exists but cannot be opened right now.
fn is_session_unavailable(error: &acp::Error) -> bool {
    error
        .data
        .as_ref()
        .and_then(|data| data.get(fuigo_shell::acp_error::ERROR_KIND_DATA_KEY))
        .and_then(serde_json::Value::as_str)
        == Some(fuigo_shell::acp_error::ERROR_KIND_SESSION_UNAVAILABLE)
}

async fn with_send_deadline<T, E, F>(what: &str, limit: Option<Duration>, fut: F) -> Result<T>
where
    F: Future<Output = std::result::Result<T, E>>,
    E: SendErrorText,
{
    let Some(limit) = limit else {
        return fut.await.map_err(|e| anyhow::anyhow!(e.send_error_text()));
    };
    match tokio::time::timeout(limit, fut).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(anyhow::anyhow!(e.send_error_text())),
        Err(_) => Err(anyhow::Error::new(SendDeadlineElapsed {
            what: what.to_string(),
            limit,
        })),
    }
}

/// With `-w`, a remote miss defers to the worktree resume path like the TUI; without it headless restores in place.
fn headless_materialize_ctx(
    resume_title_pinned: bool,
    restore_code: bool,
    has_worktree: bool,
) -> crate::app::session_startup::MaterializeCtx {
    crate::app::session_startup::MaterializeCtx {
        has_worktree,
        allow_remote_restore:
            crate::app::session_startup::MaterializeCtx::default_allow_remote_restore(),
        chat_mode: false,
        title_resolution: if resume_title_pinned {
            crate::app::session_startup::TitleResolution::PinnedPreSandbox
        } else {
            crate::app::session_startup::TitleResolution::Allowed
        },
        restore_code,
        recent_session_selection: crate::app::session_startup::RecentSessionSelection::Any,
        restore_progress_on_stdout: false,
    }
}

/// Run a headless single-turn prompt: spawn the agent, drive the ACP lifecycle, stream to stdout.
///
/// Returns [`HeadlessOutcome`], not `()`: a permission denial ends the run as a distinct,
/// non-error outcome that the caller maps to [`PERMISSION_DENIED_EXIT_CODE`] (Contract D.2.1).
/// `Err` still means what it always meant — the run failed — and stays on the generic `exit(1)`
/// path, so a blocked run and a crashed run are never the same thing to a script (D.3).
pub async fn run_single_turn(
    prompt: Option<HeadlessPrompt>,
    verbatim: bool,
    options: HeadlessOptions,
) -> Result<HeadlessOutcome> {
    // The emitter lives out here so an interrupt that drops the run mid-flight can still write the
    // format's terminal event through it (a machine consumer reads exactly one).
    let mut emitter = HeadlessEmitter::new(options.output_format, options.json_schema.is_some());
    let interrupt = InterruptWatch::global();
    let outcome = {
        let run = run_single_turn_inner(prompt, verbatim, options, &mut emitter, interrupt.clone());
        tokio::pin!(run);
        tokio::select! {
            biased;
            result = &mut run => Ok(result),
            code = interrupt.fired_outside_turn() => Err(code),
        }
    };
    match outcome {
        Ok(result) => result,
        Err(code) => Err(interrupted(&mut emitter, code)),
    }
}

/// SIGINT/SIGTERM/SIGHUP, latched. The listeners are registered when this is built (before the agent
/// spawns), and the latch is sticky, so a signal is never lost between two polls.
///
/// Two consumers, one at a time: while the turn is being driven (`driving`), [`drive_prompt_turn`]
/// owns the interrupt so a response that already completed is folded into the one terminal document
/// exactly as the `--timeout` cap does; before and after the turn this wrapper handles it.
#[derive(Clone)]
struct InterruptWatch {
    rx: tokio::sync::watch::Receiver<Option<i32>>,
    /// Who owns an interrupt right now: [`PHASE_OUTER`] (before the turn and after its terminal
    /// document: the wrapper reports it) or [`PHASE_TURN`] (the turn driver folds it into the
    /// document, and the wrapper stands down until the turn is finalized).
    phase: std::sync::Arc<std::sync::atomic::AtomicU8>,
}

const PHASE_OUTER: u8 = 0;
const PHASE_TURN: u8 = 1;

static GLOBAL_INTERRUPT_WATCH: std::sync::OnceLock<InterruptWatch> = std::sync::OnceLock::new();

/// Register the headless signal listeners now. `main` calls this before the pre-run startup work
/// (managed-policy heal) so a signal in that window is latched and reported by the run that follows,
/// instead of killing the process with nothing said. Idempotent; must run inside the runtime.
pub fn arm_interrupt_watch() {
    let _ = InterruptWatch::global();
}

impl InterruptWatch {
    fn global() -> Self {
        GLOBAL_INTERRUPT_WATCH.get_or_init(Self::install).clone()
    }

    fn install() -> Self {
        let (tx, rx) = tokio::sync::watch::channel(None);
        let listener = interrupt_listener();
        tokio::spawn(async move {
            let code = listener.await;
            let _ = tx.send(Some(code));
        });
        Self {
            rx,
            phase: std::sync::Arc::default(),
        }
    }

    /// A watch no signal can reach (its sender is gone), for tests that drive the turn directly.
    #[cfg(test)]
    fn inert() -> Self {
        Self::fixed(None)
    }

    /// A watch already latched with `code`, for tests of the interrupt path.
    #[cfg(test)]
    fn fixed(code: Option<i32>) -> Self {
        let (tx, rx) = tokio::sync::watch::channel(code);
        if code.is_none() {
            drop(tx);
        } else {
            std::mem::forget(tx);
        }
        Self {
            rx,
            phase: std::sync::Arc::default(),
        }
    }

    fn set_phase(&self, phase: u8) {
        self.phase.store(phase, std::sync::atomic::Ordering::SeqCst);
    }

    /// Resolves with the exit code once a signal has arrived; pends forever if the listener died.
    async fn fired(&self) -> i32 {
        let mut rx = self.rx.clone();
        match rx.wait_for(Option::is_some).await {
            Ok(code) => code.unwrap_or(130),
            Err(_) => std::future::pending().await,
        }
    }

    /// [`Self::fired`], but only while the turn is not being driven (see the type docs).
    async fn fired_outside_turn(&self) -> i32 {
        loop {
            let code = self.fired().await;
            if self.phase.load(std::sync::atomic::Ordering::SeqCst) != PHASE_TURN {
                return code;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// A headless run ended by SIGINT/SIGTERM/SIGHUP. Carried in `Err` so the process exit path reports
/// it once and exits `128 + signal` (130/143/129) rather than the generic `1`.
#[derive(Debug)]
pub struct HeadlessInterrupted {
    code: i32,
}

impl HeadlessInterrupted {
    pub fn exit_code(&self) -> i32 {
        self.code
    }
}

impl std::fmt::Display for HeadlessInterrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self.code {
            143 => "SIGTERM",
            129 => "SIGHUP",
            _ => "SIGINT",
        };
        write!(f, "Interrupted by {name}; exiting {}", self.code)
    }
}

impl std::error::Error for HeadlessInterrupted {}

/// Terminal event for a run interrupted outside the driven turn: the structured error on the
/// machine formats (plain writes nothing here; `main` prints the one `Error:` line for the returned
/// `Err`). Nothing is written if the run had already emitted its terminal document (an interrupt
/// during the post-turn memory flush): a machine consumer reads exactly one.
fn interrupted(emitter: &mut HeadlessEmitter, code: i32) -> anyhow::Error {
    let error = HeadlessInterrupted { code };
    if !emitter.terminal_emitted {
        emitter.on_error(&error.to_string(), Some("cancelled"));
    }
    anyhow::Error::new(error)
}

/// An interrupt that landed while the turn was being driven. Mirrors the `--timeout` cap: a response
/// that already completed is reported, with the interrupt, in ONE terminal document; otherwise the
/// error line is the document.
fn finish_interrupt(
    emitter: &mut HeadlessEmitter,
    prompt_result: Option<Result<acp::PromptResponse, acp::Error>>,
    code: i32,
    session_id: &acp::SessionId,
) -> anyhow::Error {
    let error = HeadlessInterrupted { code };
    let msg = error.to_string();
    match prompt_result {
        Some(Ok(resp)) => {
            emit_completed_response(emitter, resp, session_id, Some(&msg));
        }
        _ => emitter.on_error(&msg, Some("cancelled")),
    }
    anyhow::Error::new(error)
}

/// Registers the process-signal listeners now (not on first poll) and returns the future that
/// resolves with the `128 + signal` exit code.
#[cfg(unix)]
fn interrupt_listener() -> impl std::future::Future<Output = i32> + Send + 'static {
    use crate::app::signal_handler::recv_optional_unix_signal;
    use tokio::signal::unix::{SignalKind, signal};
    let mut int = signal(SignalKind::interrupt()).ok();
    let mut term = signal(SignalKind::terminate()).ok();
    let mut hup = signal(SignalKind::hangup()).ok();
    async move {
        tokio::select! {
            _ = recv_optional_unix_signal(&mut int) => 130,
            _ = recv_optional_unix_signal(&mut term) => 143,
            _ = recv_optional_unix_signal(&mut hup) => 129,
        }
    }
}

#[cfg(not(unix))]
fn interrupt_listener() -> impl std::future::Future<Output = i32> + Send + 'static {
    async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => 130,
            Err(_) => std::future::pending().await,
        }
    }
}

async fn run_single_turn_inner(
    prompt: Option<HeadlessPrompt>,
    verbatim: bool,
    options: HeadlessOptions,
    emitter: &mut HeadlessEmitter,
    interrupt: InterruptWatch,
) -> Result<HeadlessOutcome> {
    // Stamp proxy requests as headless before the agent issues its first request.
    fuigo_shell::http::set_process_client_mode_headless();

    // `--timeout` is a cap on the whole run, not just the turn: start the clock before the agent
    // spawns so a wedge anywhere on the path (initialize, session/new, the turn, the memory flush)
    // is bounded by it.
    let deadline = RunDeadline::start(options.total_timeout);

    let cwd = match options.cwd {
        None => std::env::current_dir()?,
        Some(ref p) => dunce::canonicalize(p)?,
    };

    if options.include_partial_messages
        && options.output_format != OutputFormat::StreamingMessagesJson
    {
        crate::best_effort_stderr::eprint_line(
            "warning: --include-partial-messages only affects --output-format streaming-messages-json; ignoring it",
        );
    }

    let t_spawn = Instant::now();
    let (raw_config, campaign_free_config) =
        fuigo_shell::config::load_effective_config_with_campaign_free()
            .map_err(|e| anyhow::anyhow!("Failed to load config: {e}"))?;
    let mut agent_config = AgentConfig::new_from_toml_cfg(&raw_config)
        .map_err(|e| anyhow::anyhow!("Failed to create agent config: {e}"))?;

    // Only canonical tokens are stamped early; remapped menu ids need the post-session catalog resolve below
    if let Some(ref token) = options.reasoning_effort
        && let Some(effort) = parse_canonical_effort_token(token)
    {
        agent_config.reasoning_effort_override = Some(effort);
    }
    // Stamp `-m` early so the initial system prompt uses it, not a later SetSessionModel.
    if let Some(ref model) = options.model {
        agent_config.default_model_override = Some(model.clone());
    }

    agent_config.resolve_runtime_fields(&fuigo_shell::agent::config::RuntimeResolutionContext {
        raw_config: &raw_config,
        remote_settings: None,
        is_headless: true,
        cli_subagents: None,
        cli_web_search_model: None,
        cli_session_summary_model: None,
        memory_enabled_override: options.memory_enabled_override,
        disable_web_search: options.disable_web_search,
        todo_gate: false,
        laziness_debug_log: None,
        storage_mode: None,
        campaign_free_config: Some(&campaign_free_config),
    });

    agent_config.mode = fuigo_shell::agent::config::AgentMode::Headless;
    agent_config.default_yolo_mode = options.yolo;
    agent_config.default_auto_mode = fuigo_shell::util::config::effective_auto_for_launch(
        options.yolo,
        options.permission_mode_flag.as_deref(),
        None,
        fuigo_shell::util::config::PermissionMode::Ask,
    );

    apply_agent_flag(&options.agent, &mut agent_config);

    if let Some(ref json) = options.agents_json {
        agent_config.cli_agents = parse_cli_agents(json)?;
    }

    agent_config.cli_agent_overrides = fuigo_shell::agent::config::CliAgentOverrides {
        tools: parse_comma_list(options.cli_tools.as_deref()),
        disallowed_tools: parse_comma_list(options.cli_disallowed_tools.as_deref()),
        permission_rules: parse_permission_rules_strict(&options.allow_rules, &options.deny_rules)?,
        max_turns: options.max_turns,
        permission_mode: options
            .permission_mode_flag
            .as_deref()
            .map(|s| {
                serde_json::from_value(serde_json::Value::String(s.to_string()))
                    .map_err(|e| anyhow::anyhow!("--permission-mode: invalid value: {e}"))
            })
            .transpose()?,
    };

    if options.trust {
        fuigo_workspace::folder_trust::grant_folder_trust(&cwd);
    }

    let cancel = CancellationToken::new();
    let memory_config = agent_config.memory_config.clone();
    let mut pending_startup = Some(PendingStartup::new());
    let timer = fuigo_telemetry::startup::begin(crate::acp::Owner::Client);
    let mut report_startup_failure = |timer: &crate::acp::StartupTimer| {
        timer.emit_telemetry(
            crate::acp::AgentKind::Embedded,
            crate::acp::StartupOutcome::Error,
            None,
            false,
        );
        PendingStartup::finish_held(&mut pending_startup, crate::acp::StartupOutcome::Error);
    };
    let spawned = match spawn_fuigo_shell(agent_config, &cancel, memory_config).await {
        Ok(s) => s,
        Err(e) => {
            report_startup_failure(&timer);
            let msg = format!("Couldn't start session: {e}");
            emitter.on_error(&msg, None);
            anyhow::bail!("{msg}");
        }
    };
    let _agent_guard = AgentShutdownGuard::new(cancel.clone(), Some(spawned.thread_handle));
    let (acp_tx, mut acp_rx) = (spawned.channel.tx, spawned.channel.rx);
    crate::unified_log::init(acp_tx.clone());
    crate::unified_log::info(
        "pager started",
        None,
        Some(serde_json::json!({"mode": "headless"})),
    );
    crate::unified_log::flush();

    let init_req = build_headless_init_request(
        options.rules.as_deref(),
        options.system_prompt_override.as_deref(),
    );
    fuigo_telemetry::startup::enter(crate::acp::StartupPhase::AcpInitialize);
    let init_resp: acp::InitializeResponse = match with_send_deadline(
        "initialize",
        deadline.budget(lifecycle_send_timeout()),
        acp_send(init_req, &acp_tx),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            report_startup_failure(&timer);
            let msg = format!("Couldn't initialize: {e}");
            emitter.on_error(&msg, None);
            anyhow::bail!("{msg}");
        }
    };
    tracing::debug!(
        elapsed_ms = t_spawn.elapsed().as_millis() as u64,
        "headless: spawn + initialize complete"
    );

    let t_auth = Instant::now();
    fuigo_telemetry::startup::enter(crate::acp::StartupPhase::EagerAuth);
    let default_auth_method_id = crate::acp::parse_default_auth_method_id(init_resp.meta.as_ref());
    let is_api_key_auth = match with_send_deadline(
        "authenticate",
        deadline.budget(lifecycle_send_timeout()),
        authenticate(
            &acp_tx,
            &init_resp.auth_methods,
            default_auth_method_id.as_ref(),
        ),
    )
    .await
    {
        Ok(is_api_key) => is_api_key,
        Err(e) => {
            report_startup_failure(&timer);
            emitter.on_error(&e.to_string(), None);
            return Err(e);
        }
    };
    tracing::debug!(
        elapsed_ms = t_auth.elapsed().as_millis() as u64,
        "headless: authenticate complete"
    );
    // Connect ends here; session phases stay out of the phase histogram.
    timer.emit_telemetry(
        crate::acp::AgentKind::Embedded,
        crate::acp::StartupOutcome::Ok,
        None,
        false,
    );

    use crate::app::session_startup::{self, MaterializedStartup, SessionStartupFlags};
    let has_resume_id = options.resume.as_deref().filter(|s| !s.is_empty());
    let resume_most_recent = options.resume.as_deref() == Some("");
    let worktree =
        WorktreeSpec::from_cli(options.worktree.as_deref(), options.worktree_ref.as_deref());
    let intent = session_startup::session_startup_intent_from_flags(SessionStartupFlags {
        session_id: options.session_id.as_deref(),
        resume_session_id: has_resume_id,
        resume_most_recent,
        continue_last_session: options.continue_last_session,
        fork_session: options.fork_session,
        has_worktree: worktree.is_some(),
    })
    .map_err(|e| anyhow::anyhow!("{e}"))
    .inspect_err(|_| {
        PendingStartup::finish_held(&mut pending_startup, crate::acp::StartupOutcome::Error);
    })?;

    let cwd_str = cwd.to_string_lossy().to_string();
    let materialized = session_startup::materialize_startup_for_cwd(
        headless_materialize_ctx(
            options.resume_title_pinned,
            options.restore_code,
            worktree.is_some(),
        ),
        intent,
        &cwd_str,
    )
    .await
    .inspect_err(|_| {
        PendingStartup::finish_held(&mut pending_startup, crate::acp::StartupOutcome::Error);
    })?;

    let restore_code = match &materialized {
        MaterializedStartup::Resume {
            suppress_code_restore: true,
            ..
        }
        | MaterializedStartup::Fork {
            suppress_code_restore: true,
            ..
        } => Some(false),
        _ => options.restore_code.then_some(true),
    };
    let t_session = Instant::now();
    fuigo_telemetry::startup::enter(crate::acp::StartupPhase::SessionCreate);
    let opened = match (materialized, worktree.as_ref()) {
        (MaterializedStartup::NewAuto, Some(spec)) => {
            open_session_in_new_worktree(&acp_tx, &cwd, spec, None, deadline).await
        }
        (MaterializedStartup::NewWithId { session_id }, Some(spec)) => {
            open_session_in_new_worktree(&acp_tx, &cwd, spec, Some(&session_id), deadline).await
        }
        (
            MaterializedStartup::Resume {
                session_id,
                deferred_local_miss,
                ..
            },
            Some(spec),
        ) => {
            resume_session_in_new_worktree(
                &acp_tx,
                &cwd,
                spec,
                &session_id,
                restore_code,
                deferred_local_miss,
                deadline,
            )
            .await
        }
        (MaterializedStartup::NewAuto, None) => {
            open_session(&acp_tx, &cwd, None, None, deadline).await
        }
        (MaterializedStartup::NewWithId { session_id }, None) => {
            open_session_with_id(&acp_tx, &cwd, &session_id, deadline).await
        }
        (
            MaterializedStartup::Resume {
                session_id,
                original_cwd,
                ..
            },
            None,
        ) => {
            let load_cwd = original_cwd.as_deref().unwrap_or(cwd.as_path());
            open_session(
                &acp_tx,
                load_cwd,
                Some(session_id.as_str()),
                restore_code,
                deadline,
            )
            .await
        }
        // Fork with `-w` never reaches here; the intent check above refuses it.
        (
            MaterializedStartup::Fork {
                parent_session_id,
                parent_cwd,
                new_session_id,
                ..
            },
            _,
        ) => {
            fork_then_open(
                &acp_tx,
                &cwd,
                &parent_session_id,
                parent_cwd.as_deref(),
                new_session_id.as_deref(),
                restore_code,
                deadline,
            )
            .await
        }
    };
    let OpenedSession {
        session_id,
        models: session_models,
        cwd: session_cwd,
    } = match opened {
        Ok(v) => v,
        Err(e) => {
            PendingStartup::finish_held(&mut pending_startup, crate::acp::StartupOutcome::Error);
            let msg = format!("Couldn't create session: {e}");
            emitter.on_error(&msg, None);
            anyhow::bail!("{msg}");
        }
    };
    PendingStartup::finish_held(&mut pending_startup, crate::acp::StartupOutcome::Ok);
    tracing::debug!(
        elapsed_ms = t_session.elapsed().as_millis() as u64,
        session_id = %session_id.0,
        "headless: open_session complete"
    );

    let track_active = std::env::var("FUIGO_TRACK_HEADLESS").is_ok();
    if track_active {
        let _ = fuigo_active_sessions::register(fuigo_active_sessions::ActiveSession {
            session_id: session_id.clone(),
            pid: std::process::id(),
            cwd: cwd.display().to_string(),
            opened_at: chrono::Utc::now(),
        });
    }

    // Seed the reducer's session context BEFORE applying model/effort so a later failure carries it.
    {
        let model = options
            .model
            .clone()
            .or_else(|| session_models.current_model_id_str().map(str::to_string));
        let permission_mode = options
            .permission_mode_flag
            .clone()
            .or_else(|| options.yolo.then(|| "bypassPermissions".to_string()));
        emitter.begin_session(SessionContext {
            session_id: session_id.0.to_string(),
            model,
            cwd: session_cwd.to_string_lossy().to_string(),
            permission_mode,
            mcp_servers: mcp_server_names(&session_cwd),
            include_partial_messages: options.include_partial_messages,
            api_key_auth: is_api_key_auth,
            context_window: session_models.get_context_window(),
        });
    }

    // One bounded catalog read covers what the session catalog cannot resolve.
    let effort_unresolved = |token: &str| {
        if parse_canonical_effort_token(token).is_some() {
            return false;
        }
        let target = options
            .model
            .as_deref()
            .and_then(|m| session_models.resolve_by_name_or_id(m))
            .or_else(|| session_models.current.clone());
        match target {
            Some(model_id) => matches!(
                session_models.resolve_effort_for_model(&model_id, token),
                Err(EffortTokenError::UnknownToken { .. } | EffortTokenError::NoActiveModel)
            ),
            None => true,
        }
    };
    let needs_fresh_catalog = options
        .model
        .as_deref()
        .is_some_and(|m| session_models.resolve_by_name_or_id(m).is_none())
        || options
            .reasoning_effort
            .as_deref()
            .is_some_and(effort_unresolved);
    let session_models = if needs_fresh_catalog {
        match with_send_deadline(
            "the model catalog",
            deadline.budget(None),
            fuigo_shell::cli_models::fetch_model_state(&acp_tx),
        )
        .await
        {
            Ok(state) => ModelState::from(Some(state)),
            Err(e) => {
                tracing::warn!(error = %e, "headless: model catalog refresh failed; using session state");
                session_models
            }
        }
    } else {
        session_models
    };

    if let Err(e) = apply_headless_model_and_effort(
        &acp_tx,
        &session_id,
        &session_models,
        options.model.as_deref(),
        options.reasoning_effort.as_deref(),
        deadline,
    )
    .await
    {
        let msg = e.to_string();
        emitter.on_error(&msg, None);
        anyhow::bail!("{msg}");
    }

    let t_prompt = Instant::now();
    emitter.mark_prompt_started();
    let mut ttf_logged = false;
    let ack_deadlines = PromptAckDeadlines::from_process_env();
    let (prompt_fut, prompt_ack) = match prompt {
        Some(prompt) => {
            let prompt_blocks = prompt.into_content_blocks();
            let mut meta = serde_json::Map::new();
            if verbatim {
                meta.insert("verbatim".to_string(), serde_json::Value::Bool(true));
            }
            if let Some(ref schema) = options.json_schema {
                meta.insert("outputSchema".to_string(), schema.clone());
            }
            meta.insert(
                "screenMode".to_string(),
                serde_json::Value::String("headless".to_string()),
            );
            // The shell echoes this id on every notification for the prompt; the acknowledgment watch keys on it
            let prompt_id = uuid::Uuid::new_v4().to_string();
            meta.insert(
                "promptId".to_string(),
                serde_json::Value::String(prompt_id.clone()),
            );
            let request =
                acp::PromptRequest::new(session_id.clone(), prompt_blocks).meta(Some(meta));
            (
                Some(Box::pin(acp_send(request, &acp_tx))),
                Some(PromptAckWatch::new(prompt_id, Instant::now())),
            )
        }
        None => (None, None),
    };
    // From here until the turn is finalized the driver owns an interrupt (see `InterruptWatch`).
    interrupt.set_phase(PHASE_TURN);
    let TurnDriveOutcome {
        prompt_result,
        connection_closed,
        timed_out,
        interrupted: interrupted_by,
        prompt_unacknowledged,
    } = match prompt_fut {
        Some(prompt_fut) => {
            drive_prompt_turn(
                prompt_fut,
                &mut acp_rx,
                &acp_tx,
                &session_id,
                emitter,
                &options,
                deadline,
                t_prompt,
                &mut ttf_logged,
                prompt_ack,
                &ack_deadlines,
                &interrupt,
            )
            .await
        }
        None => TurnDriveOutcome::default(),
    };

    // Bounded when the shell never took the prompt (it may never answer the log notification either)
    // and when a signal ended the turn (the operator is waiting on the exit; the interrupt owner
    // stands down until the terminal document is out, so an unbounded await here could never be
    // released by another signal).
    let flush_bounded = prompt_unacknowledged || interrupted_by.is_some();
    // A signal that arrives while the flush is stalled must not wait behind it: the interrupt owner
    // stands down until the turn is finalized, so the flush itself has to notice the signal.
    let interrupted_by = flush_or_interrupt(
        flush_bounded,
        prompt_ack::HEADLESS_ABORT_SEND_TIMEOUT,
        crate::unified_log::flush_blocking(),
        &interrupt,
        interrupted_by,
    )
    .await;

    if track_active {
        // Non-blocking flock so a slow/network ~/.fuigo can't hang exit.
        let _ = fuigo_active_sessions::try_unregister(&session_id);
    }
    // A mid-turn ACP close already reaped above; return that error before the normal outcome.
    //
    // This is NOT suppressed when a permission was denied. P02a suppressed it on the theory that a
    // shell shutting down after being told no is the consequence of the block, but a denial can be
    // latched by a subagent or a background task while the crash has nothing to do with it, and
    // then a genuine crash exits with the denial code and tells the operator to pre-approve
    // something. Contract D.2.1 wants a code distinct from a crash, which cuts both ways: the crash
    // keeps its own code. The denial is not lost — it is on the terminal document and, for
    // `--output-format json`, in the `permissionDenied` record.
    if let Some(code) = interrupted_by {
        return Err(finish_interrupt(emitter, prompt_result, code, &session_id));
    }
    // A signal that lands while the awaits below run is reported by the wrapper once the turn is
    // finalized; one that landed after the race is left latched and the run finishes (completion wins).
    if connection_closed {
        return Err(connection_closed_error(
            emitter,
            &mut std::io::stderr(),
        ));
    }
    let outcome = finish_turn(
        emitter,
        prompt_result,
        timed_out,
        options.total_timeout,
        &session_id,
        is_api_key_auth,
    );
    interrupt.set_phase(PHASE_OUTER);

    // Held rather than returned immediately so the denial latch below is still consulted: the flush
    // drives the same ACP handler and can be the thing that hits a permission denial.
    let flush_error = if should_run_memory_flush(options.memory_flush, &outcome) {
        run_headless_memory_flush(
            &acp_tx,
            &mut acp_rx,
            &session_id,
            emitter,
            options.yolo,
            deadline,
        )
        .await
        .err()
    } else {
        None
    };

    headless_run_outcome(
        outcome,
        flush_error,
        emitter.take_output_error(),
        emitter.take_permission_denial(),
    )
}

/// Await `fut`, capped at `limit` when `bounded`. `false` only when the cap fired.
async fn await_bounded_if<F: Future>(bounded: bool, limit: Duration, fut: F) -> bool {
    if bounded {
        tokio::time::timeout(limit, fut).await.is_ok()
    } else {
        fut.await;
        true
    }
}

/// The final log flush, ended early by a signal. Returns the interrupt code the run now carries:
/// the one it already had, else one that landed during the flush.
async fn flush_or_interrupt<F: Future>(
    bounded: bool,
    limit: Duration,
    flush: F,
    interrupt: &InterruptWatch,
    already: Option<i32>,
) -> Option<i32> {
    let flush = await_bounded_if(bounded, limit, flush);
    if already.is_some() {
        if !flush.await {
            tracing::warn!("headless: unified log flush timed out on an aborted run");
        }
        return already;
    }
    tokio::select! {
        biased;
        finished = flush => {
            if !finished {
                tracing::warn!("headless: unified log flush timed out on an aborted run");
            }
            None
        }
        code = interrupt.fired() => Some(code),
    }
}

/// The error for a mid-turn ACP close, after saying out loud any denial latched before it.
///
/// The exit stays `1` (a crash is a crash), but D.3 forbids a denial that goes unreported: without
/// this the bail returned before `headless_run_outcome` could write the notice. Taking the latch
/// makes the line appear exactly once. `w` is stderr in production and a buffer in tests.
fn connection_closed_error(
    emitter: &mut HeadlessEmitter,
    w: &mut impl std::io::Write,
) -> anyhow::Error {
    if let Some(denial) = emitter.take_permission_denial() {
        crate::best_effort_stderr::write_line(w, &denial.notice_line());
    }
    anyhow::anyhow!("Connection closed unexpectedly")
}

/// Whether the post-turn memory flush runs: only after a turn that did not error, and never after a
/// token-budget denial (D.4) — the flush's own model request has no budget left, would be refused
/// too, and would turn the denial's exit `3` into a failed run's `1`.
fn should_run_memory_flush(memory_flush: bool, outcome: &Result<TurnStop>) -> bool {
    memory_flush
        && outcome
            .as_ref()
            .is_ok_and(|stop| !matches!(stop, TurnStop::BudgetDenied(_)))
}

/// Fold everything the run latched into the one outcome the process exits on.
///
/// Split out of [`run_single_turn`] so the precedence is testable rather than asserted in prose:
///
/// 1. **A hard stdout write error wins.** Output is dead, so nothing can report anything and the
///    only honest report left is a non-zero exit.
/// 2. **Then the memory-flush error, then the turn's own error.** An error keeps `exit(1)`. Contract
///    D.2.1 asks for a denial code distinct from a crash, and that is symmetric: a denial latched
///    somewhere in the run must not downgrade a crash, a timeout or a `--max-turns` stop to
///    "permission denied", which would tell the operator to pre-approve something that was never
///    the problem.
/// 3. **Then a denial, but only if the run actually ended at one** ([`TurnStop::PermissionCancelled`],
///    read from the shell's own `_meta.cancellationCategory`). D.2.1 scopes the code to "a run that
///    ended because a permission was denied"; a run that was refused something, carried on and
///    finished produced its answer on stdout, and exiting non-zero there would make every recovered
///    run look blocked. Such a denial still gets its stderr line, because D.3 forbids a denial that
///    is indistinguishable from success.
fn headless_run_outcome(
    turn: Result<TurnStop>,
    flush_error: Option<anyhow::Error>,
    output_error: Option<std::io::Error>,
    denial: Option<HeadlessDenial>,
) -> Result<HeadlessOutcome> {
    if let Some(err) = output_error {
        // Output is dead. A stderr line is all that could still be said, but the write error is the
        // louder fact and it is what `main` reports.
        return Err(anyhow::Error::new(err).context("headless: stdout write failed"));
    }
    let stop = match (flush_error, turn) {
        // An error is the run's outcome and keeps `exit(1)`. A denial latched on the way is still
        // said out loud, or an unrelated failure would bury it (D.3).
        (Some(e), _) | (None, Err(e)) => {
            if let Some(denial) = &denial {
                crate::best_effort_stderr::eprint_line(&denial.notice_line());
            }
            return Err(e);
        }
        (None, Ok(stop)) => stop,
    };
    // Invariant, and the one thing that makes the narrow gate safe: a latched denial always produces
    // exactly one line on stderr. `main` writes the fuller one (remedy plus exit code) on the
    // `PermissionDenied` arm; every other path writes the notice here.
    match (denial, stop) {
        // `finish_turn` latched the budget denial itself, so a latched one here IS it.
        (Some(denial), TurnStop::PermissionCancelled | TurnStop::BudgetDenied(_)) => {
            Ok(HeadlessOutcome::PermissionDenied(denial))
        }
        (None, TurnStop::BudgetDenied(rule)) => Ok(HeadlessOutcome::PermissionDenied(
            HeadlessDenial::from_budget_rule(rule),
        )),
        (Some(denial), TurnStop::Ended | TurnStop::MaxTurns) => {
            crate::best_effort_stderr::eprint_line(&denial.notice_line());
            Ok(HeadlessOutcome::Finished)
        }
        (None, _) => Ok(HeadlessOutcome::Finished),
    }
}

/// Emit the terminal outcome of a finished turn and decide the process exit status.
///
/// Split out of `run_single_turn` so the hard-cap path is testable: the cap can fire while a turn
/// that already produced its answer, usage and structured output is still waiting on background
/// work, and that work must not be thrown away just because the run ran out of time.
fn finish_turn(
    emitter: &mut HeadlessEmitter,
    prompt_result: Option<Result<acp::PromptResponse, acp::Error>>,
    timed_out: bool,
    total_timeout: Option<Duration>,
    session_id: &acp::SessionId,
    is_api_key_auth: bool,
) -> Result<TurnStop> {
    // P188: the turn is over, nothing can be resent: the text held for the last response is final
    emitter.flush_plain_pending();
    // The hard run cap fired: background work is already reaped, so report it and exit non-zero.
    if timed_out {
        let msg = match total_timeout {
            Some(limit) => format!(
                "Timed out after {}s waiting for the turn to end",
                limit.as_secs()
            ),
            None => "Timed out waiting for the turn to end".to_string(),
        };
        // The cap commonly lands while a turn that already answered is waiting on background work
        // (a persistent monitor never completes and always waits out `--background-wait-timeout`).
        // That answer, its usage and its structured output are work that was done and paid for:
        // report them, and the cap, in ONE terminal document. Dropping them loses both the result
        // and the spend record of a turn that finished; emitting them as a second document breaks
        // every machine consumer of `json`/`stream-json`, which reads exactly one terminal record.
        match prompt_result {
            // The cap is the outcome, so how the turn itself stopped is not consulted.
            Some(Ok(resp)) => {
                emit_completed_response(emitter, resp, session_id, Some(&msg));
            }
            // Nothing completed, so the error line IS the terminal document.
            _ => emitter.on_error(&msg, Some("cancelled")),
        }
        anyhow::bail!("{msg}");
    }
    match prompt_result {
        Some(Ok(resp)) => match emit_completed_response(emitter, resp, session_id, None) {
            TurnStop::MaxTurns => Err(anyhow::anyhow!("max turns reached")),
            stop => Ok(stop),
        },
        Some(Err(err)) => {
            if fuigo_shell::acp_error::ExecutionBudgetDenial::is_budget_denial(&err) {
                // Contract D.4: the shell's token-budget guard refused a model request. That is a
                // denial with the same reporting contract as a permission denial — exit 3, the record
                // on the terminal document, one English line — not a failed run. Keyed on the stable
                // `data.code`, so a rule this build does not know is still a denial.
                let rule = fuigo_shell::acp_error::ExecutionBudgetDenial::from_acp_error(&err)
                    .map_or(HeadlessDenialRule::ExecutionBudgetUnrecognized, |budget| {
                        HeadlessDenialRule::ExecutionBudget(budget.rule)
                    });
                let mut denial = HeadlessDenial::from_budget_rule(rule);
                if rule == HeadlessDenialRule::ExecutionBudgetUnrecognized {
                    denial.agent_message = Some(fuigo_telemetry::sent_credentials::scrub_owned(
                        fuigo_shell::sampling::error::acp_error_text(&err),
                    ));
                }
                if let Some(earlier) = emitter.permission_denial.replace(denial)
                {
                    crate::best_effort_stderr::eprint_line(&earlier.notice_line());
                }
                // The run ends here with exit 3, so the record on the error line says so.
                emitter.denial_ended_run = true;
                if let Some(usage) = fuigo_shell::sampling::error::prompt_usage_from_error(&err)
                    && let Ok(v) = serde_json::to_value(&usage)
                {
                    emitter.usage = Some(v);
                }
                // Plain writes nothing to stdout and its error goes to stderr, where `main` writes
                // the denial's one line (D.2.3): a second line here would be two. A rule this build
                // does not know has no remedy of its own, so the agent's message — which names the
                // rule and its remedy — rides on that same line (`HeadlessDenial::agent_message`).
                if emitter.format != OutputFormat::Plain {
                    emitter.on_error(&fuigo_shell::sampling::error::acp_error_text(&err), None);
                } else {
                    // P188 (Astra r1): the reply text held for the response still reaches stdout
                    emitter.flush_plain_pending();
                }
                return Ok(TurnStop::BudgetDenied(rule));
            }
            let msg = if i32::from(err.code) == RATE_LIMITED_ERROR_CODE {
                let detail = err.data.as_ref().and_then(error_detail_from_data);
                crate::app::sanitize_user_error(&format_rate_limited_user_message_with(
                    detail.as_deref(),
                    is_api_key_auth,
                    fuigo_shell::sampling::error_verdicts::error_verdicts_from_error(&err)
                        .as_ref(),
                ))
            } else {
                // `Display` would print an object `data` as raw JSON; people read its `message`
                fuigo_shell::sampling::error::acp_error_text(&err)
            };
            if let Some(usage) = fuigo_shell::sampling::error::prompt_usage_from_error(&err) {
                match serde_json::to_value(&usage) {
                    Ok(v) => emitter.usage = Some(v),
                    // Log rather than swallow: a serialize failure would drop the frozen spend fields.
                    Err(e) => tracing::warn!(
                        error = %e,
                        "headless: failed to serialize prompt-error usage; spend fields dropped"
                    ),
                }
            }
            let stop_reason_override =
                (fuigo_shell::sampling::error::stop_reason_for_turn_error(&err) == "MaxTokens")
                    .then_some("max_tokens");
            emitter.on_error(&msg, stop_reason_override);
            Err(anyhow::anyhow!("{msg}"))
        }
        None => Ok(TurnStop::Ended),
    }
}

/// Emit a completed prompt response: structured output, usage, and the terminal result line.
///
/// `run_error` folds a run-level failure that arrived after the turn answered (the `--timeout` hard
/// cap) into that same terminal document, stamping `cancelled` as the stop reason. Returns how the
/// turn stopped, read from the shell's own `_meta.cancellationCategory`.
fn emit_completed_response(
    emitter: &mut HeadlessEmitter,
    resp: acp::PromptResponse,
    session_id: &acp::SessionId,
    run_error: Option<&str>,
) -> TurnStop {
    let stop_reason = if run_error.is_some() {
        "cancelled".to_string()
    } else {
        stop_reason_wire(resp.stop_reason)
    };
    emitter.set_structured_output_from_meta(resp.meta.as_ref());
    emitter.set_usage_from_meta(resp.meta.as_ref());
    // Prefer the response `_meta` ids, falling back to the typed session id rather than "".
    let sid = resp
        .meta
        .as_ref()
        .and_then(|m| m.get("sessionId"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| session_id.0.as_ref());
    let rid = match resp
        .meta
        .as_ref()
        .and_then(|m| m.get("requestId"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        Some(r) => r,
        None => {
            tracing::warn!(
                "headless: prompt response carried no requestId; emitting an empty requestId"
            );
            ""
        }
    };
    // The shell stamps exactly one category per terminal response, so this is a match, not a set of
    // independent flags. `PermissionCancelled` is the answer to "did the run end at the denial?" —
    // the stop reason alone cannot say, because `cancelled` also covers `--max-turns`, a hook deny,
    // a permission *reject* and a mid-turn abort.
    let stop = match resp
        .meta
        .as_ref()
        .and_then(|m| m.get(crate::app::CANCELLATION_CATEGORY_KEY))
        .and_then(|v| v.as_str())
    {
        Some(fuigo_shell::session::commands::MAX_TURNS_REACHED_CATEGORY) => TurnStop::MaxTurns,
        Some(fuigo_shell::session::commands::PERMISSION_CANCELLED_CATEGORY) => {
            TurnStop::PermissionCancelled
        }
        _ => TurnStop::Ended,
    };
    if stop == TurnStop::MaxTurns {
        emitter.on_max_turns();
    }
    // The same condition `headless_run_outcome` exits `3` on, decided here because the terminal
    // record is written here: a run-level error on top (the `--timeout` cap) exits `1` instead.
    emitter.denial_ended_run = stop == TurnStop::PermissionCancelled && run_error.is_none();
    emitter.on_end(&stop_reason, sid, rid, run_error);
    stop
}

/// What one headless prompt turn produced, once its stream loop has stopped.
#[derive(Default)]
struct TurnDriveOutcome {
    prompt_result: Option<Result<acp::PromptResponse, acp::Error>>,
    /// The ACP channel closed mid-turn; background work was still reaped.
    connection_closed: bool,
    /// `options.total_timeout` elapsed before the turn ended.
    timed_out: bool,
    /// A signal ended the turn: the `128 + signal` exit code.
    interrupted: Option<i32>,
    /// The shell never acknowledged the prompt; exit-path awaits must stay bounded.
    prompt_unacknowledged: bool,
}

/// Drive the prompt future and the ACP stream until the turn ends.
///
/// When `options.total_timeout` is set it is a hard cap on the whole turn: on elapse the stream
/// loop is dropped and the caller leaves through the normal drain/reap path. Without it, an agent
/// that never produces an end event leaves every `select!` arm pending (the background-wait sleep
/// arm is gated off until there is pending background work), so the turn waits forever.
async fn drive_prompt_turn<F>(
    prompt_fut: F,
    acp_rx: &mut AcpClientRx,
    acp_tx: &AcpAgentTx,
    session_id: &acp::SessionId,
    emitter: &mut HeadlessEmitter,
    options: &HeadlessOptions,
    deadline: RunDeadline,
    t_prompt: Instant,
    ttf_logged: &mut bool,
    prompt_ack: Option<PromptAckWatch>,
    ack_deadlines: &PromptAckDeadlines,
    interrupt: &InterruptWatch,
) -> TurnDriveOutcome
where
    F: Future<Output = Result<acp::PromptResponse, acp::Error>>,
{
    tokio::pin!(prompt_fut);
    let mut prompt_ack = prompt_ack;
    // Set when the ack watch expires: the exit path must then stay bounded.
    let mut prompt_unacknowledged = false;
    let mut prompt_result = None;
    // Tracked regardless of wait_for_background so the exit reaper always sees running work.
    let mut pending_bg: HashSet<BackgroundWork> = HashSet::new();
    // Tombstone of completed ids so an out-of-order task_backgrounded or subagent_spawned never re-adds them to pending
    let mut completed_bg: HashSet<BackgroundWork> = HashSet::new();
    let mut prompt_done_at: Option<Instant> = None;
    // On mid-turn channel close, break (not bail) so the exit path still drains and reaps.
    let mut connection_closed = false;

    let stream = async {
        loop {
            if emitter.write_error.is_some() {
                tracing::warn!("headless: stdout write failed; stopping the stream loop");
                break;
            }
            // Drain buffered ACP first: PromptResponse can complete while task_backgrounded is still queued.
            if options.wait_for_background && prompt_result.is_some() && pending_bg.is_empty() {
                drain_pending_acp_messages(
                    &mut *acp_rx,
                    &mut *emitter,
                    t_prompt,
                    &mut *ttf_logged,
                    options.yolo,
                    &mut pending_bg,
                    &mut completed_bg,
                );
                if pending_bg.is_empty() {
                    tracing::debug!("headless: no pending background tasks, exiting");
                    break;
                }
            }

            if options.wait_for_background
                && let Some(done_at) = prompt_done_at
                && done_at.elapsed() >= options.background_wait_timeout
            {
                tracing::warn!(
                    pending_bg = pending_bg.len(),
                    timeout_secs = options.background_wait_timeout.as_secs(),
                    "headless: background wait timed out, exiting"
                );
                break;
            }

            let timeout_deadline = if options.wait_for_background
                && prompt_result.is_some()
                && !pending_bg.is_empty()
                && let Some(done_at) = prompt_done_at
            {
                let remaining = options
                    .background_wait_timeout
                    .saturating_sub(done_at.elapsed());
                if remaining.is_zero() {
                    Duration::from_millis(50)
                } else {
                    remaining
                }
            } else {
                Duration::from_secs(3600)
            };
            // The branch is disabled once acknowledged; the far-future sleep is built but never polled
            let ack_deadline = match prompt_ack.as_ref() {
                Some(watch) => tokio::time::Instant::from_std(watch.hard_deadline(ack_deadlines)),
                None => tokio::time::Instant::now() + Duration::from_secs(3600),
            };

            tokio::select! {
                biased;
                msg = acp_rx.recv() => {
                    let Some(msg) = msg else {
                        emitter.on_error("Connection closed unexpectedly", None);
                        connection_closed = true;
                        break;
                    };
                    let msg = msg.boxed();
                    if let Some(watch) = prompt_ack.as_ref()
                        && headless_ack_signal(&msg, session_id, watch.prompt_id()).is_some()
                    {
                        prompt_ack = None;
                    }
                    handle_headless_acp_message(
                        msg,
                        &mut *emitter,
                        t_prompt,
                        &mut *ttf_logged,
                        options.yolo,
                        &mut pending_bg,
                        &mut completed_bg,
                    );
                }
                res = &mut prompt_fut, if prompt_result.is_none() => {
                    // The turn ended: nothing left to acknowledge
                    prompt_ack = None;
                    prompt_result = Some(res);
                    prompt_done_at = Some(Instant::now());
                    if !options.wait_for_background {
                        drain_acp_with_grace(
                            &mut *acp_rx,
                            Duration::from_millis(750),
                            &mut *emitter,
                            t_prompt,
                            &mut *ttf_logged,
                            options.yolo,
                            &mut pending_bg,
                            &mut completed_bg,
                        )
                        .await;
                        break;
                    }
                    // Drain now so a task_backgrounded around completion is recorded before the empty-check.
                    drain_pending_acp_messages(
                        &mut *acp_rx,
                        &mut *emitter,
                        t_prompt,
                        &mut *ttf_logged,
                        options.yolo,
                        &mut pending_bg,
                        &mut completed_bg,
                    );
                }
                _ = tokio::time::sleep(timeout_deadline), if options.wait_for_background
                    && prompt_result.is_some()
                    && !pending_bg.is_empty() =>
                {
                    // Wake to re-check the timeout at the top of the loop.
                }
                _ = tokio::time::sleep_until(ack_deadline), if prompt_ack.is_some() => {
                    let Some(watch) = prompt_ack.take() else {
                        unreachable!("branch precondition is `prompt_ack.is_some()`")
                    };
                    let err = abort_unacknowledged_prompt(
                        acp_tx,
                        session_id,
                        watch.prompt_id(),
                        watch.waited(Instant::now()),
                        ack_deadlines,
                    )
                    .await;
                    prompt_result = Some(Err(err));
                    prompt_unacknowledged = true;
                    break;
                }
            }
        }
    };
    let run = async {
        if let Some(limit) = deadline.remaining() {
            let elapsed = tokio::time::timeout(limit, stream).await.is_err();
            if elapsed {
                tracing::warn!(
                    timeout_secs = limit.as_secs(),
                    "headless: turn timed out; tearing down"
                );
            }
            elapsed
        } else {
            stream.await;
            false
        }
    };
    // Completion wins a tie with a signal; an interrupt leaves through the same drain/reap path as
    // the timeout, keeping whatever the turn had already produced.
    let (timed_out, interrupted) = tokio::select! {
        biased;
        timed_out = run => (timed_out, None),
        code = interrupt.fired() => (false, Some(code)),
    };

    // Final drain-to-empty so the reaper sees work buffered right at exit (the timeout path skips draining).
    drain_pending_acp_messages(
        &mut *acp_rx,
        &mut *emitter,
        t_prompt,
        &mut *ttf_logged,
        options.yolo,
        &mut pending_bg,
        &mut completed_bg,
    );

    if !pending_bg.is_empty() {
        tracing::warn!(
            pending_bg = pending_bg.len(),
            "headless: killing background work still pending at exit"
        );
        reap_pending_background_tasks(&pending_bg, session_id, acp_tx).await;
    }

    TurnDriveOutcome {
        prompt_result,
        connection_closed,
        timed_out,
        interrupted,
        prompt_unacknowledged,
    }
}

/// Invoke `fuigo/memory/flush` and wait for the flush LLM to finish.
async fn run_headless_memory_flush(
    acp_tx: &AcpAgentTx,
    acp_rx: &mut AcpClientRx,
    session_id: &acp::SessionId,
    emitter: &mut HeadlessEmitter,
    yolo: bool,
    deadline: RunDeadline,
) -> Result<()> {
    let params = serde_json::json!({ "session_id": session_id.0.to_string() });
    let raw = serde_json::value::to_raw_value(&params)
        .map_err(|e| anyhow::anyhow!("serialize memory flush params: {e}"))?;
    let request = acp::ExtRequest::new("fuigo/memory/flush", raw.into());
    let mut flush_fut = Box::pin(acp_send(request, acp_tx));
    let t0 = Instant::now();
    let mut ttf_logged = true;
    let mut pending_bg = HashSet::new();
    let mut completed_bg = HashSet::new();
    // The flush is part of the run, so it draws on the same `--timeout` budget as everything else:
    // `flush_fut` is a bare `acp_send`, and the ACP arm alone never ends a wedged flush.
    let drain = async {
        loop {
            tokio::select! {
                biased;
                msg = acp_rx.recv() => {
                    let Some(msg) = msg else {
                        anyhow::bail!("connection closed while waiting for memory flush");
                    };
                    handle_headless_acp_message(
                        msg.boxed(),
                        emitter,
                        t0,
                        &mut ttf_logged,
                        yolo,
                        &mut pending_bg,
                        &mut completed_bg,
                    );
                }
                res = &mut flush_fut => break Ok(res),
            }
        }
    };
    let response = match deadline.remaining() {
        Some(limit) => tokio::time::timeout(limit, drain).await.map_err(|_| {
            anyhow::anyhow!(
                "timed out after {}s waiting for memory flush",
                limit.as_secs()
            )
        })??,
        None => drain.await?,
    };
    drain_pending_acp_messages(
        acp_rx,
        emitter,
        t0,
        &mut ttf_logged,
        yolo,
        &mut pending_bg,
        &mut completed_bg,
    );
    let response =
        response.map_err(|e| anyhow::anyhow!("memory flush failed: {}", acp_error_text(&e)))?;
    let flushed = serde_json::from_str::<serde_json::Value>(response.0.get())
        .ok()
        .and_then(|v| v.get("flushed")?.as_bool())
        .unwrap_or(false);
    if !flushed {
        anyhow::bail!("memory flush skipped (already in progress or not started)");
    }
    Ok(())
}

/// Background work tracked for exit: bash/monitor tasks and background subagents, keyed by id.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum BackgroundWork {
    Task(String),
    Subagent(String),
}

/// Ext request that kills one unit of background work (subagent cancel or task kill).
fn reap_request_for_work(
    work: &BackgroundWork,
    session_id: &acp::SessionId,
) -> serde_json::Result<acp::ExtRequest> {
    let (method, params) = match work {
        BackgroundWork::Subagent(id) => (
            "fuigo/subagent/cancel",
            serde_json::value::to_raw_value(&CancelSubagentRequest {
                subagent_id: id.clone(),
            })?,
        ),
        BackgroundWork::Task(id) => (
            "fuigo/task/kill",
            serde_json::value::to_raw_value(&KillTaskRequest {
                session_id: session_id.0.to_string(),
                task_id: id.clone(),
                source: fuigo_shell::extensions::task::TaskKillSource::Teardown,
            })?,
        ),
    };
    Ok(acp::ExtRequest::new(method, params.into()))
}

/// Best-effort kill of background work still pending at exit so it never outlives the process.
async fn reap_pending_background_tasks(
    pending_bg: &HashSet<BackgroundWork>,
    session_id: &acp::SessionId,
    acp_tx: &AcpAgentTx,
) {
    for work in pending_bg {
        let request = match reap_request_for_work(work, session_id) {
            Ok(request) => request,
            Err(e) => {
                tracing::warn!(?work, error = %e, "headless: failed to build reap request");
                continue;
            }
        };
        let method = request.method.clone();
        match tokio::time::timeout(Duration::from_secs(10), acp_send(request, acp_tx)).await {
            Ok(Ok(_)) => {
                tracing::debug!(?work, %method, "headless: reaped pending background work")
            }
            Ok(Err(e)) => {
                tracing::warn!(?work, %method, error = %acp_error_text(&e), "headless: failed to reap background work")
            }
            Err(_) => {
                tracing::warn!(?work, %method, "headless: timed out reaping background work")
            }
        }
    }
}

/// `completed_bg` tombstones finished ids so a late or out-of-order task_backgrounded/subagent_spawned cannot resurrect them into `pending_bg`.
fn track_background_lifecycle(
    event: ExtEvent,
    pending_bg: &mut HashSet<BackgroundWork>,
    completed_bg: &mut HashSet<BackgroundWork>,
) {
    match event {
        ExtEvent::TaskBackgrounded {
            task_id,
            is_monitor,
        } => {
            let work = BackgroundWork::Task(task_id);
            if completed_bg.contains(&work) {
                tracing::debug!(
                    is_monitor,
                    "headless: ignoring task_backgrounded for already-completed task"
                );
            } else {
                pending_bg.insert(work);
                tracing::debug!(
                    pending = pending_bg.len(),
                    is_monitor,
                    "headless: tracking background task"
                );
            }
        }
        ExtEvent::TaskCompleted { task_id } => {
            let work = BackgroundWork::Task(task_id);
            let was_pending = pending_bg.remove(&work);
            completed_bg.insert(work);
            if was_pending {
                tracing::debug!(
                    pending = pending_bg.len(),
                    "headless: background task completed"
                );
            }
        }
        ExtEvent::SubagentSpawned { subagent_id } => {
            let work = BackgroundWork::Subagent(subagent_id);
            if completed_bg.contains(&work) {
                tracing::debug!(
                    "headless: ignoring subagent_spawned for already-finished subagent"
                );
            } else {
                pending_bg.insert(work);
                tracing::debug!(
                    pending = pending_bg.len(),
                    "headless: tracking background subagent"
                );
            }
        }
        ExtEvent::SubagentFinished { subagent_id } => {
            let work = BackgroundWork::Subagent(subagent_id);
            let was_pending = pending_bg.remove(&work);
            completed_bg.insert(work);
            if was_pending {
                tracing::debug!(
                    pending = pending_bg.len(),
                    "headless: background subagent finished"
                );
            }
        }
        // Routed to the emitter by the caller, never tracked.
        ExtEvent::MonitorEvent | ExtEvent::None | ExtEvent::Lifecycle(_) | ExtEvent::Stream(_) => {}
    }
}

/// Non-blocking drain-to-empty of `acp_rx`.
/// Background work buffered around prompt completion is recorded in `pending_bg` before the empty-check decides whether to exit.
#[allow(clippy::too_many_arguments)]
fn drain_pending_acp_messages(
    acp_rx: &mut AcpClientRx,
    emitter: &mut HeadlessEmitter,
    t_prompt: Instant,
    ttf_logged: &mut bool,
    yolo: bool,
    pending_bg: &mut HashSet<BackgroundWork>,
    completed_bg: &mut HashSet<BackgroundWork>,
) {
    while let Ok(msg) = acp_rx.try_recv() {
        handle_headless_acp_message(
            msg.boxed(),
            emitter,
            t_prompt,
            ttf_logged,
            yolo,
            pending_bg,
            completed_bg,
        );
    }
}

#[allow(clippy::too_many_arguments)]
async fn drain_acp_with_grace(
    acp_rx: &mut AcpClientRx,
    grace: Duration,
    emitter: &mut HeadlessEmitter,
    t_prompt: Instant,
    ttf_logged: &mut bool,
    yolo: bool,
    pending_bg: &mut HashSet<BackgroundWork>,
    completed_bg: &mut HashSet<BackgroundWork>,
) {
    let deadline = Instant::now() + grace;
    loop {
        while let Ok(msg) = acp_rx.try_recv() {
            handle_headless_acp_message(
                msg.boxed(),
                emitter,
                t_prompt,
                ttf_logged,
                yolo,
                pending_bg,
                completed_bg,
            );
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        tokio::select! {
            biased;
            msg = acp_rx.recv() => {
                let Some(msg) = msg else { break; };
                handle_headless_acp_message(
                    msg.boxed(),
                    emitter,
                    t_prompt,
                    ttf_logged,
                    yolo,
                    pending_bg,
                    completed_bg,
                );
            }
            _ = tokio::time::sleep(remaining) => {
                break;
            }
        }
    }
}

/// Process one inbound ACP client message; shared by `recv()` and `try_recv()`.
#[allow(clippy::too_many_arguments)]
fn handle_headless_acp_message(
    msg: AcpClientMessageBox,
    emitter: &mut HeadlessEmitter,
    t_prompt: Instant,
    ttf_logged: &mut bool,
    yolo: bool,
    pending_bg: &mut HashSet<BackgroundWork>,
    completed_bg: &mut HashSet<BackgroundWork>,
) {
    match msg {
        AcpClientMessageBox::SessionNotification(boxed) => {
            match &boxed.request.update {
                // Retry progress for stock ACP clients, never part of the answer
                update if is_retry_status_update(update) => {}
                acp::SessionUpdate::AgentMessageChunk(chunk) => {
                    if let acp::ContentBlock::Text(text) = &chunk.content
                        && !text.text.is_empty()
                    {
                        if !*ttf_logged {
                            *ttf_logged = true;
                            tracing::debug!(
                                elapsed_ms = t_prompt.elapsed().as_millis() as u64,
                                "headless: time-to-first-chunk"
                            );
                        }
                        emitter.on_text_chunk(
                            &text.text,
                            update_stream_start_ms(boxed.request.meta.as_ref()),
                        );
                    }
                }
                acp::SessionUpdate::AgentThoughtChunk(chunk) => {
                    if let acp::ContentBlock::Text(text) = &chunk.content
                        && !text.text.is_empty()
                    {
                        if !*ttf_logged {
                            *ttf_logged = true;
                            tracing::debug!(
                                elapsed_ms = t_prompt.elapsed().as_millis() as u64,
                                "headless: time-to-first-thought"
                            );
                        }
                        emitter.on_thought_chunk(
                            &text.text,
                            update_stream_start_ms(boxed.request.meta.as_ref()),
                        );
                    }
                }
                acp::SessionUpdate::ToolCall(_)
                | acp::SessionUpdate::ToolCallUpdate(_)
                | acp::SessionUpdate::Plan(_)
                | acp::SessionUpdate::AvailableCommandsUpdate(_) => {
                    if let Some(event) = map_session_update(&boxed.request.update) {
                        emitter.reduce_and_emit(event);
                    }
                }
                _ => {}
            }
            let _ = boxed.response_tx.send(Ok(()));
        }
        AcpClientMessageBox::RequestPermission(req) => {
            // Both no-approval paths are denials, and a denial is a first-class outcome (Contract
            // D.2), not a log line: latch it on the emitter so the exit path can report it and exit
            // with the dedicated code. The ACP outcome stays `Cancelled` on purpose — changing the
            // wire outcome is a Contract E question Murage reads, deferred to P00 (packet §3.2).
            let approval = if yolo {
                auto_respond_to_permissions(
                    &req.request,
                    &[
                        acp::PermissionOptionKind::AllowOnce,
                        acp::PermissionOptionKind::AllowAlways,
                    ],
                )
            } else {
                None
            };
            let response = match approval {
                Some(resp) => resp,
                None => {
                    let rule = if yolo {
                        // Yolo auto-approves, so reaching here means no allow option was offered.
                        HeadlessDenialRule::YoloHadNoAllowOption
                    } else {
                        HeadlessDenialRule::HeadlessNeverApproves
                    };
                    emitter
                        .record_permission_denial(HeadlessDenial::from_request(&req.request, rule));
                    acp::RequestPermissionResponse::new(acp::RequestPermissionOutcome::Cancelled)
                }
            };
            // A dropped send used to be discarded silently; report it, because an unanswered
            // permission request wedges the agent on a reply that is never coming.
            if req.response_tx.send(Ok(response)).is_err() {
                tracing::warn!(
                    "headless: permission response could not be delivered; the requester is gone"
                );
            }
        }
        AcpClientMessageBox::ExtNotification(notif) => {
            let event = handle_ext_notification(&notif);
            let _ = notif.response_tx.send(Ok(()));
            match event {
                ExtEvent::Lifecycle(l) => emitter.on_lifecycle(l),
                ExtEvent::Stream(event) => emitter.reduce_and_emit(*event),
                other => track_background_lifecycle(other, pending_bg, completed_bg),
            }
        }
        AcpClientMessageBox::WaitForTerminalExit(args) => {
            args.response_tx
                .send(Err(crate::acp::wait_for_exit_not_supported(
                    "headless mode",
                )))
                .ok();
        }
        AcpClientMessageBox::ExtMethod(args) => reply_headless_ext_method(args),
        _ => {}
    }
}

#[cfg(test)]
#[path = "headless_tests.rs"]
mod tests;
