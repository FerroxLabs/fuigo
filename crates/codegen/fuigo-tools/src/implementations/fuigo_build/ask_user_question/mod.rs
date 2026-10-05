//! `AskUserQuestion` tool — new architecture (`Tool` trait).
//!
//! Interactive Q&A tool that presents the user with structured questions and
//! option sets. In plan mode it serves as the **interview mechanism** — the
//! agent clarifies requirements, disambiguates approaches, and gets user input
//! on design decisions before finalizing the plan. Outside plan mode it is a
//! general-purpose tool for gathering user preferences during implementation.
//!
//! ## How It Works
//!
//! 1. The agent calls `AskUserQuestion` with an array of structured questions
//!    (each with options, optional preview, optional multi_select).
//! 2. The tool sends a `UserQuestionRequest` to the session's question
//!    coordinator (in fuigo-shell), which makes the `fuigo/ask_user_question`
//!    ACP round trip, and emits a `UserQuestionAsked` notification.
//! 3. The tool blocks until the client answers, cancels, or the wait budget
//!    elapses, and returns the formatted result as
//!    `AskUserQuestionOutput::UserAnswered`.
//!
//! ## Outcomes
//!
//! - Answered → the formatted answers.
//! - Unanswered (cancel or timeout) → [`format::CANCEL_TEXT`] interactively,
//!   [`format::NO_OPERATOR_TEXT`] in a non-interactive session.
//! - Non-interactive only: an unreachable client (transport error, e.g. an
//!   embedder without a `fuigo/ask_user_question` handler) or an already-closed
//!   coordinator → [`format::NO_OPERATOR_TEXT`], and the wait is capped at
//!   [`NON_INTERACTIVE_RESPONSE_TIMEOUT`].
//! - Interactive transport break, malformed reply, or a session with no
//!   coordinator wired → a hard `ToolError`.
//!
//! ## Plan-Mode Interview Actions
//!
//! When called during plan mode, the client can present two extra buttons:
//! - **"Respond to agent"** — partial answers, agent reformulates questions
//! - **"Finish plan interview"** — agent stops asking, proceeds with what it has
//!
//! These are client-side behaviors that produce different tool-result strings;
//! the tool itself is identical in and out of plan mode.

pub mod format;
pub mod types;

pub use types::{
    AskUserQuestionExtRequest, AskUserQuestionExtResponse, AskUserQuestionMode, QuestionAnnotation,
    UserQuestionError, UserQuestionRequest, UserQuestionResponse, UserQuestionResult,
    UserQuestionSender,
};

use crate::notification::types::UserQuestionAsked;
use crate::types::output::AskUserQuestionOutput;
use crate::types::requirements::{Expr, ToolRequirement};
use crate::types::resources::NotificationHandle;
use crate::types::tool::{ToolKind, ToolNamespace};

/// Default max time to wait for the user to answer the questionnaire (all
/// questions in this tool call share one timer): 30 minutes. On expiry the
/// tool returns the same skipped/cancel text as a user dismiss
/// (`format::unanswered_text`), not a tool failure.
///
/// The shell resolves `[toolset.ask_user_question]` across its config tiers
/// and injects the result as [`AskUserQuestionParams`]; when no resolved
/// params are injected, `FUIGO_ASK_USER_QUESTION_TIMEOUT_SECS` (positive
/// integer seconds) still overrides this default directly —
/// e.g. `FUIGO_ASK_USER_QUESTION_TIMEOUT_SECS=8` for tests / TUI repro.
pub const RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// Ceiling on the wait budget in a non-interactive session (headless `-p`,
/// SDK, a third-party ACP embedder that set `nonInteractive`): 30 seconds.
///
/// Nobody is at a keyboard, so the 30-minute interactive budget only turns an
/// embedder that acks `fuigo/ask_user_question` but never replies into a
/// 30-minute stall (the coordinator's `ext_method` has no deadline of its own).
/// Not zero: the question still makes its one ACP round trip, and an
/// embedder-supplied UI can still answer with a real `Accepted`/`Cancelled`.
/// A shorter configured budget is honoured; `timeout_enabled = false` does not
/// lift this ceiling.
pub const NON_INTERACTIVE_RESPONSE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(30);

/// Default for `timeout_enabled` across every resolver tier and settings
/// surface: the questionnaire timer is armed unless something disarms it.
/// Single source — the shell resolver's `.default(...)` and the pager's
/// settings registry both anchor on this const.
pub const DEFAULT_ASK_USER_QUESTION_TIMEOUT_ENABLED: bool = true;

/// Env var: override [`RESPONSE_TIMEOUT`] with a duration in **seconds**.
pub const RESPONSE_TIMEOUT_ENV: &str = "FUIGO_ASK_USER_QUESTION_TIMEOUT_SECS";

/// Parse the [`RESPONSE_TIMEOUT_ENV`] override (positive integer seconds).
/// Invalid or non-positive values are warned and treated as unset. Single
/// source for this parse — the shell's env tier calls it too, so the two
/// resolutions can't drift.
pub fn response_timeout_env_secs() -> Option<u64> {
    let raw = std::env::var(RESPONSE_TIMEOUT_ENV).ok()?;
    match raw.trim().parse::<u64>() {
        Ok(secs) if secs > 0 => Some(secs),
        _ => {
            tracing::warn!(
                env = RESPONSE_TIMEOUT_ENV,
                value = %raw,
                "invalid timeout override; ignoring"
            );
            None
        }
    }
}

/// Effective wait budget for one questionnaire (env override or default).
pub fn response_timeout() -> std::time::Duration {
    response_timeout_env_secs()
        .map(std::time::Duration::from_secs)
        .unwrap_or(RESPONSE_TIMEOUT)
}

/// Runtime-configurable parameters for the `ask_user_question` tool,
/// injected via `Params<AskUserQuestionParams>` in `SharedResources`.
///
/// The shell resolves `[toolset.ask_user_question]` across requirements >
/// env > user `config.toml` > managed > remote feature config and injects the
/// concrete result. All fields are optional — `None` means "unset", which
/// preserves the legacy env→default budget, so registry consumers that never
/// resolve config (workspace toolset) keep today's behavior.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AskUserQuestionParams {
    /// `Some(false)` disarms the questionnaire timer entirely (wait forever
    /// for an answer). `None`/`Some(true)` keep the timer armed.
    #[serde(default)]
    pub timeout_enabled: Option<bool>,
    /// Wait budget in seconds when the timer is armed (positive integer).
    /// `None` falls back to the env override / [`RESPONSE_TIMEOUT`].
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Session state stamped by the agent builder for non-interactive
    /// sessions (headless `-p`, SDK) — NOT a user config key. `Some(true)`
    /// switches every unanswered result (cancel, timeout, unreachable client)
    /// to [`format::NO_OPERATOR_TEXT`] and caps the wait at
    /// [`NON_INTERACTIVE_RESPONSE_TIMEOUT`].
    #[serde(default)]
    pub non_interactive: Option<bool>,
}

crate::register_resource!("fuigo_build", "AskUserQuestion", AskUserQuestionParams);

impl AskUserQuestionParams {
    /// Whether the agent builder stamped this session non-interactive.
    pub fn is_non_interactive(&self) -> bool {
        self.non_interactive.unwrap_or(false)
    }

    /// Effective wait budget: `Some(duration)` = bounded, `None` = wait forever.
    ///
    /// A non-interactive session is always bounded, by at most
    /// [`NON_INTERACTIVE_RESPONSE_TIMEOUT`]; an interactive one gets the
    /// configured budget unchanged.
    pub fn wait_budget(&self) -> Option<std::time::Duration> {
        let configured = self.configured_wait_budget();
        if self.is_non_interactive() {
            return Some(configured.map_or(NON_INTERACTIVE_RESPONSE_TIMEOUT, |d| {
                d.min(NON_INTERACTIVE_RESPONSE_TIMEOUT)
            }));
        }
        configured
    }

    /// The budget the timeout settings alone ask for, before the
    /// non-interactive ceiling.
    fn configured_wait_budget(&self) -> Option<std::time::Duration> {
        if !self
            .timeout_enabled
            .unwrap_or(DEFAULT_ASK_USER_QUESTION_TIMEOUT_ENABLED)
        {
            return None;
        }
        match self.timeout_secs {
            Some(secs) if secs > 0 => Some(std::time::Duration::from_secs(secs)),
            Some(secs) => {
                // 0 must never mean "wait forever" — that is `timeout_enabled`'s job.
                tracing::warn!(
                    value = secs,
                    "ask_user_question timeout_secs must be > 0; using default budget"
                );
                Some(response_timeout())
            }
            None => Some(response_timeout()),
        }
    }
}

/// A single option within a question.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct QuestionOption {
    /// Option text shown to the user; a few words at most.
    #[schemars(description = "Option text shown to the user. A few words at most.")]
    pub label: String,

    /// What picking this option means or implies.
    #[schemars(description = "What picking this option means or implies.")]
    pub description: String,

    /// Optional content shown while the option is focused — mockups, code
    /// snippets, anything the user should compare. Single-select only.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Optional content shown while the option is focused — mockups, code snippets, anything the user should compare. Single-select questions only."
    )]
    pub preview: Option<String>,

    /// Opaque id; hidden from the model. Fuigo callers leave it `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(skip)]
    pub id: Option<String>,
}

/// A single question with its options.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Question {
    /// The question to ask, phrased as a full question.
    #[schemars(description = "The question to ask, phrased as a full question.")]
    pub question: String,

    /// The choices for this question.
    #[schemars(description = "The choices for this question.")]
    pub options: Vec<QuestionOption>,

    /// Let the user pick more than one option (default false).
    // Model-facing schema name is snake_case (`multi_select`); deserialize also
    // accepts the legacy/ACP `multiSelect` so the shared `Question` type stays
    // wire-compatible with the camelCase ACP ext_method.
    #[serde(
        default,
        alias = "multi_select",
        deserialize_with = "crate::types::schema::deserialize_lenient_option_bool"
    )]
    #[schemars(
        rename = "multi_select",
        description = "Let the user pick more than one option (default false)."
    )]
    pub multi_select: Option<bool>,

    /// See `QuestionOption.id`. Hidden from the JSON schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(skip)]
    pub id: Option<String>,
}

/// Input for the `AskUserQuestion` tool.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct AskUserQuestionInput {
    /// The questions to ask, each with its own options. At least one question
    /// is required.
    #[schemars(description = "The questions to ask, each with its own options.")]
    pub questions: Vec<Question>,

    /// Internal flag: when `true`, the tool result is formatted in the
    /// alternate shape (referenced by id, not label).
    /// Skipped on the wire and from the JSON schema so the model never
    /// sees or controls this field.
    #[serde(default, skip)]
    #[schemars(skip)]
    pub use_id_keyed_format: bool,
}

/// `AskUserQuestion` tool.
///
/// Blocks inside `run()` until the user responds or the configured wait
/// budget elapses for the whole questionnaire (default [`RESPONSE_TIMEOUT`],
/// 30 minutes; at most [`NON_INTERACTIVE_RESPONSE_TIMEOUT`] when
/// non-interactive). Sends a request over an in-process mpsc channel to a
/// session-owned coordinator (in fuigo-shell), which performs an ACP
/// `ext_method` round-trip to the client/pager. The response is sent back
/// over a oneshot channel and formatted into the model-visible tool result.
///
/// Params: [`AskUserQuestionParams`] — timeout policy resolved by the shell
/// across its config tiers; unset fields keep the legacy env→default budget.
#[derive(Debug, Default)]
pub struct AskUserQuestionTool;

impl crate::types::tool_metadata::ToolMetadata for AskUserQuestionTool {
    fn kind(&self) -> ToolKind {
        ToolKind::AskUser
    }

    fn tool_namespace(&self) -> ToolNamespace {
        ToolNamespace::FuigoBuild
    }

    fn emitted_notifications(&self) -> &'static [&'static str] {
        &["UserQuestionAsked"]
    }

    fn description_template(&self) -> &str {
        r#"Ask the user one or more multiple-choice questions.

- Every question automatically gets an "Other" choice where the user can type their own answer.
- Put your recommended option first and append "(Recommended)" to its label."#
    }

    fn requires_expr(&self) -> Expr<ToolRequirement> {
        // Standalone. The plan-mode prompt note is
        // `${% if tools.by_kind.exit_plan %}`-guarded, so it renders
        // fine without the plan tools.
        Expr::True
    }
}

impl fuigo_tool_runtime::Tool for AskUserQuestionTool {
    type Args = AskUserQuestionInput;
    type Output = AskUserQuestionOutput;

    fn id(&self) -> fuigo_tool_protocol::ToolId {
        fuigo_tool_protocol::ToolId::new("ask_user_question").expect("valid tool id")
    }

    fn description(
        &self,
        _ctx: &::fuigo_tool_runtime::ListToolsContext,
    ) -> fuigo_tool_types::ToolDescription {
        fuigo_tool_types::ToolDescription::new(
            "ask_user_question",
            crate::types::tool_metadata::ToolMetadata::sanitized_description_template(self),
        )
    }

    fn capabilities(&self) -> fuigo_tool_protocol::ToolCapabilities {
        fuigo_tool_protocol::ToolCapabilities {
            is_read_only: true,
            tool_scope: Some(fuigo_tool_protocol::ToolScope::Read),
            ..Default::default()
        }
    }

    #[tracing::instrument(
        name = "tool.ask_user_question",
        skip_all,
        fields(question_count = input.questions.len()),
    )]
    async fn run(
        &self,
        ctx: fuigo_tool_runtime::ToolCallContext,
        input: AskUserQuestionInput,
    ) -> Result<AskUserQuestionOutput, fuigo_tool_runtime::ToolError> {
        use crate::types::tool_metadata::shared_resources;
        let resources = shared_resources(&ctx)?;

        let question_count = input.questions.len();

        if question_count == 0 {
            return Ok(AskUserQuestionOutput::QuestionsSent {
                message: "No questions provided. Continue with the task.".to_string(),
                question_count: 0,
            });
        }

        // ── Step 1: Validate unique question text ───────────────────────
        {
            let mut seen = std::collections::HashSet::new();
            for q in &input.questions {
                if !seen.insert(&q.question) {
                    return Err(fuigo_tool_runtime::ToolError::invalid_arguments(format!(
                        "Duplicate question text: \"{}\"",
                        q.question
                    )));
                }
            }
        }

        // ── Step 2: Read the session wiring and the wait policy ─────────
        // Both are read before any channel exists or any UI is notified, so the
        // no-operator short-circuit below cannot race a client that is already
        // rendering the question.
        let (sender, params) = {
            let res = resources.lock().await;
            (
                res.get::<UserQuestionSender>().cloned(),
                // Shell-injected params win; absent or unset fields keep the
                // legacy env→default budget so non-shell registry consumers are
                // unchanged.
                res.get::<crate::types::resources::Params<AskUserQuestionParams>>()
                    .map(|p| p.0)
                    .unwrap_or_default(),
            )
        };
        let non_interactive = params.is_non_interactive();
        // One wording for every unanswered path (cancel, timeout, and — in a
        // non-interactive session — an unreachable client).
        let unanswered = format::unanswered_text(non_interactive);

        // The shell spawns the question coordinator for every session and
        // injects its sender at agent build, so a missing sender is a wiring
        // fault. It is reported as one, never papered over as "questions sent".
        let Some(sender) = sender else {
            tracing::error!(
                "ask_user_question invoked without a UserQuestionSender; the session's \
                 question coordinator is not wired"
            );
            return Err(missing_user_question_sender_error());
        };

        // ── Step 3: No operator can exist → answer now ──────────────────
        // In a non-interactive session the coordinator is the only route to an
        // embedder that might render the question. If it is already gone, no
        // one can answer: return the no-operator result without creating a
        // channel or emitting `UserQuestionAsked`. Interactive sessions fall
        // through and report the closed channel as the fault it is.
        if non_interactive && sender.0.is_closed() {
            tracing::info!(
                question_count,
                "Non-interactive session has no question coordinator; continuing without answers"
            );
            return Ok(AskUserQuestionOutput::UserAnswered {
                message: unanswered.to_string(),
            });
        }

        // ── Step 4: Create oneshot + send UserQuestionRequest ───────────
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let request = types::UserQuestionRequest {
            tool_call_id: ctx.call_id.as_str().to_owned(),
            questions: input.questions.clone(),
            result_tx,
        };

        if sender.0.send(request).is_err() {
            // The coordinator closed between the check above and this send.
            if non_interactive {
                return Ok(AskUserQuestionOutput::UserAnswered {
                    message: unanswered.to_string(),
                });
            }
            return Err(fuigo_tool_runtime::ToolError::execution(
                fuigo_tool_protocol::ToolId::new("ask_user_question").expect("valid"),
                "User question session ended unexpectedly (coordinator channel closed)",
            ));
        }

        // ── Step 5: Emit UserQuestionAsked ──────────────────────────────
        {
            let questions_json = serde_json::to_value(&input.questions)
                .unwrap_or_else(|_| serde_json::Value::Array(vec![]));
            let res = resources.lock().await;
            if let Some(handle) = res.get::<NotificationHandle>() {
                handle.0.send_user_question_asked(UserQuestionAsked {
                    tool_call_id: ctx.call_id.as_str().to_owned(),
                    questions_json,
                });
            }
        }
        let wait = params.wait_budget();
        tracing::info!(
            question_count,
            non_interactive,
            timeout_secs = ?wait.map(|d| d.as_secs()),
            "Asked user questions, blocking for response"
        );

        // ── Step 6: Block on the oneshot result (whole batch, one timer) ─
        // A single pending-decision timeout covers the questionnaire, not per
        // question: N questions in one call share one wait.
        // A `None` budget (`timeout_enabled = false`) runs the same await with
        // no timer, normalized into the timed shape so one match handles both.
        let outcome = match wait {
            Some(dur) => tokio::time::timeout(dur, result_rx).await,
            None => Ok(result_rx.await),
        };
        let result = match outcome {
            Ok(Ok(r)) => r,
            Ok(Err(_recv_error)) => {
                return Err(fuigo_tool_runtime::ToolError::execution(
                    fuigo_tool_protocol::ToolId::new("ask_user_question").expect("valid"),
                    "User question session ended unexpectedly (client may have disconnected)",
                ));
            }
            Err(_elapsed) => {
                tracing::info!(
                    question_count,
                    timeout_secs = ?wait.map(|d| d.as_secs()),
                    "User question timed out; continuing without answers"
                );
                // Drop the oneshot receiver on return. The shell coordinator
                // races `result_tx.closed()` against ACP so it unblocks and
                // can open the next questionnaire (stale UI is cancelled when
                // a new ext_method arrives). Same model text as cancel.
                return Ok(AskUserQuestionOutput::UserAnswered {
                    message: unanswered.to_string(),
                });
            }
        };

        // ── Step 7: Map result to formatter or error ────────────────────
        match result {
            Ok(UserQuestionResponse::Accepted {
                answers,
                annotations,
            }) => {
                let message = if input.use_id_keyed_format {
                    format::format_id_keyed_accepted_tool_result(
                        &input.questions,
                        &answers,
                        &annotations,
                    )
                } else {
                    format::format_accepted_tool_result(&answers, &annotations)
                };
                Ok(AskUserQuestionOutput::UserAnswered { message })
            }
            Ok(UserQuestionResponse::ChatAboutThis {
                questions,
                partial_answers,
            }) => {
                let message = format::format_chat_about_this(&questions, &partial_answers);
                Ok(AskUserQuestionOutput::UserAnswered { message })
            }
            Ok(UserQuestionResponse::SkipInterview {
                questions,
                partial_answers,
            }) => {
                let message = format::format_skip_interview(&questions, &partial_answers);
                Ok(AskUserQuestionOutput::UserAnswered { message })
            }
            Ok(UserQuestionResponse::Cancelled) => Ok(AskUserQuestionOutput::UserAnswered {
                message: unanswered.to_string(),
            }),
            // Non-interactive: an embedder that enabled the tool but does not
            // implement `fuigo/ask_user_question` (JSON-RPC -32601), or is
            // otherwise unreachable, means no one can answer. That is the
            // no-operator outcome, not an infrastructure error for the model to
            // retry against.
            Err(UserQuestionError::TransportError(msg)) if non_interactive => {
                tracing::info!(
                    question_count,
                    error = %msg,
                    "Non-interactive client did not take the question; continuing without answers"
                );
                Ok(AskUserQuestionOutput::UserAnswered {
                    message: unanswered.to_string(),
                })
            }
            // Interactive: a transport break is a genuine fault.
            Err(UserQuestionError::TransportError(msg)) => {
                Err(fuigo_tool_runtime::ToolError::execution(
                    fuigo_tool_protocol::ToolId::new("ask_user_question").expect("valid"),
                    format!("Failed to reach the client for user question: {msg}"),
                ))
            }
            Err(UserQuestionError::MalformedResponse(msg)) => {
                Err(fuigo_tool_runtime::ToolError::execution(
                    fuigo_tool_protocol::ToolId::new("ask_user_question").expect("valid"),
                    format!("Client returned an invalid response to user question: {msg}"),
                ))
            }
        }
    }
}

/// Error code of the hard failure for a session with no question coordinator.
pub const MISSING_USER_QUESTION_SENDER_CODE: &str = "missing_resource";

/// The hard, named failure returned when `UserQuestionSender` was never
/// injected (formerly a warning plus a fire-and-forget "questions sent" lie).
fn missing_user_question_sender_error() -> fuigo_tool_runtime::ToolError {
    fuigo_tool_runtime::ToolError::custom(
        MISSING_USER_QUESTION_SENDER_CODE,
        "UserQuestionSender is not wired into this session: ask_user_question cannot reach a \
         question coordinator, so no question was shown to anyone",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::resources::{Resources, SharedResources};
    use crate::types::tool_metadata::test_ctx_with_call_id;
    use indexmap::IndexMap;
    use tokio::sync::mpsc;

    fn make_question(question: &str, labels: &[&str]) -> Question {
        Question {
            question: question.to_string(),
            options: labels
                .iter()
                .map(|l| QuestionOption {
                    label: l.to_string(),
                    description: format!("Description for {l}"),
                    preview: None,
                    id: None,
                })
                .collect(),
            multi_select: None,
            id: None,
        }
    }

    /// Create resources with a UserQuestionSender injected.
    /// Returns (shared_resources, rx) where rx receives UserQuestionRequests.
    fn resources_with_sender() -> (
        SharedResources,
        mpsc::UnboundedReceiver<types::UserQuestionRequest>,
    ) {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut resources = Resources::new();
        resources.insert(UserQuestionSender(tx));
        (resources.into_shared(), rx)
    }

    /// Like [`resources_with_sender`], with shell-resolved params injected.
    fn resources_with_sender_and_params(
        params: AskUserQuestionParams,
    ) -> (
        SharedResources,
        mpsc::UnboundedReceiver<types::UserQuestionRequest>,
    ) {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut resources = Resources::new();
        resources.insert(UserQuestionSender(tx));
        resources.insert(crate::types::resources::Params(params));
        (resources.into_shared(), rx)
    }

    // ── Basic tool metadata tests ────────────────────────────────────────

    #[test]
    fn tool_name_and_description() {
        let tool = AskUserQuestionTool;
        assert_eq!(
            fuigo_tool_runtime::Tool::id(&tool).as_str(),
            "ask_user_question"
        );
    }

    #[test]
    fn tool_is_read_only() {
        assert!(fuigo_tool_runtime::Tool::capabilities(&AskUserQuestionTool).is_read_only);
    }

    #[test]
    fn tool_kind_is_ask_user() {
        assert_eq!(
            crate::types::tool_metadata::ToolMetadata::kind(&AskUserQuestionTool),
            ToolKind::AskUser
        );
    }

    #[test]
    fn input_deserializes_from_json() {
        let json = serde_json::json!({
            "questions": [{
                "question": "Pick DB?",
                "options": [
                    {"label": "Postgres", "description": "Relational DB"},
                    {"label": "SQLite", "description": "Embedded SQL database", "preview": "```\nSELECT 1;\n```"}
                ],
                "multiSelect": false
            }]
        });

        let input: AskUserQuestionInput = serde_json::from_value(json).unwrap();
        assert_eq!(input.questions.len(), 1);
        assert_eq!(input.questions[0].question, "Pick DB?");
        assert_eq!(input.questions[0].options.len(), 2);
        assert_eq!(input.questions[0].options[0].label, "Postgres");
        assert!(input.questions[0].options[0].preview.is_none());
        assert_eq!(input.questions[0].options[1].label, "SQLite");
        assert!(input.questions[0].options[1].preview.is_some());
        assert_eq!(input.questions[0].multi_select, Some(false));
    }

    #[test]
    fn model_schema_advertises_snake_case_multi_select() {
        let schema = schemars::schema_for!(AskUserQuestionInput);
        let json = serde_json::to_string(&schema).unwrap();
        assert!(
            json.contains("multi_select"),
            "model schema should advertise multi_select: {json}"
        );
        assert!(
            !json.contains("multiSelect"),
            "model schema should not advertise camelCase multiSelect: {json}"
        );
    }

    #[test]
    fn input_accepts_snake_case_multi_select() {
        let json = serde_json::json!({
            "questions": [{
                "question": "Pick DB?",
                "options": [{"label": "Postgres", "description": "Relational DB"}],
                "multi_select": true
            }]
        });
        let input: AskUserQuestionInput = serde_json::from_value(json).unwrap();
        assert_eq!(input.questions[0].multi_select, Some(true));
    }

    // ── Missing UserQuestionSender (MIGRATION_FALLBACK removed) ─────────

    /// A session without a `UserQuestionSender` is a wiring fault. It must be a
    /// hard, named failure — never the old warning plus a fire-and-forget
    /// "your questions have been presented" lie — and no UI notification may
    /// go out, in either session kind.
    #[tokio::test]
    async fn missing_sender_is_a_hard_named_failure() {
        use crate::notification::types::ToolNotificationHandle;

        for non_interactive in [None, Some(false), Some(true)] {
            let (handle, mut notifications) = ToolNotificationHandle::channel();
            let mut resources = Resources::new();
            resources.insert(NotificationHandle(handle));
            resources.insert(crate::types::resources::Params(AskUserQuestionParams {
                non_interactive,
                ..Default::default()
            }));
            let input = AskUserQuestionInput {
                questions: vec![make_question(
                    "Which database?",
                    &["Redis (Recommended)", "Memcached"],
                )],
                use_id_keyed_format: false,
            };

            let err = fuigo_tool_runtime::Tool::run(
                &AskUserQuestionTool,
                test_ctx_with_call_id(resources.into_shared(), "test-call"),
                input,
            )
            .await
            .expect_err("a missing UserQuestionSender must fail the tool call");

            assert_eq!(
                err.kind,
                fuigo_tool_runtime::ToolErrorKind::Custom,
                "{non_interactive:?}"
            );
            assert_eq!(
                err.details,
                Some(serde_json::json!({ "code": MISSING_USER_QUESTION_SENDER_CODE })),
                "{non_interactive:?}"
            );
            assert_eq!(MISSING_USER_QUESTION_SENDER_CODE, "missing_resource");
            let msg = err.to_string();
            assert!(msg.contains("UserQuestionSender"), "{non_interactive:?}: {msg}");
            assert!(msg.contains("not wired"), "{non_interactive:?}: {msg}");
            assert!(
                !msg.contains("presented to the user"),
                "{non_interactive:?}: {msg}"
            );
            assert!(
                notifications.try_recv().is_err(),
                "{non_interactive:?}: no UserQuestionAsked may be emitted without a coordinator"
            );
        }
    }

    #[tokio::test]
    async fn empty_questions_handled() {
        let resources = Resources::new();
        let shared = resources.into_shared();
        let tool = AskUserQuestionTool;

        let input = AskUserQuestionInput {
            questions: vec![],
            use_id_keyed_format: false,
        };

        let result =
            fuigo_tool_runtime::Tool::run(&tool, test_ctx_with_call_id(shared, "test-call"), input)
                .await
                .unwrap();

        match result {
            AskUserQuestionOutput::QuestionsSent {
                ref message,
                question_count,
            } => {
                assert_eq!(question_count, 0);
                assert!(message.contains("No questions provided"));
            }
            _ => panic!("Expected QuestionsSent for empty"),
        }
    }

    // ── Validation tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn validate_duplicate_question_text() {
        let resources = Resources::new();
        let shared = resources.into_shared();
        let tool = AskUserQuestionTool;

        let input = AskUserQuestionInput {
            questions: vec![
                make_question("Same question?", &["A"]),
                make_question("Same question?", &["B"]),
            ],
            use_id_keyed_format: false,
        };

        let err =
            fuigo_tool_runtime::Tool::run(&tool, test_ctx_with_call_id(shared, "test-call"), input)
                .await
                .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("Duplicate question text"), "got: {msg}");
        assert!(msg.contains("Same question?"), "got: {msg}");
    }

    // ── Blocking round-trip tests ────────────────────────────────────────

    #[tokio::test]
    async fn blocking_round_trip_accepted() {
        let (shared, mut rx) = resources_with_sender();
        let tool = AskUserQuestionTool;

        let input = AskUserQuestionInput {
            questions: vec![make_question("Which database?", &["Redis", "Postgres"])],
            use_id_keyed_format: false,
        };

        let handle = tokio::spawn({
            let shared = shared.clone();
            async move {
                fuigo_tool_runtime::Tool::run(&tool, test_ctx_with_call_id(shared, "tc-1"), input)
                    .await
            }
        });

        let request = rx.recv().await.expect("should receive request");
        assert_eq!(request.tool_call_id, "tc-1");
        assert_eq!(request.questions.len(), 1);

        let mut answers = IndexMap::new();
        answers.insert("Which database?".to_string(), vec!["Redis".to_string()]);

        request
            .result_tx
            .send(Ok(UserQuestionResponse::Accepted {
                answers,
                annotations: None,
            }))
            .unwrap();

        let result = handle.await.unwrap().unwrap();
        match result {
            AskUserQuestionOutput::UserAnswered { message } => {
                assert!(message.contains("Which database?"));
                assert!(message.contains("Redis"));
            }
            other => panic!("Expected UserAnswered, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn blocking_round_trip_cancelled() {
        let (shared, mut rx) = resources_with_sender();
        let tool = AskUserQuestionTool;

        let input = AskUserQuestionInput {
            questions: vec![make_question("Q?", &["A"])],
            use_id_keyed_format: false,
        };

        let handle = tokio::spawn({
            let shared = shared.clone();
            async move {
                fuigo_tool_runtime::Tool::run(&tool, test_ctx_with_call_id(shared, "tc-4"), input)
                    .await
            }
        });

        let request = rx.recv().await.unwrap();
        request
            .result_tx
            .send(Ok(UserQuestionResponse::Cancelled))
            .unwrap();

        let result = handle.await.unwrap().unwrap();
        match result {
            AskUserQuestionOutput::UserAnswered { message } => {
                assert_eq!(message, format::CANCEL_TEXT);
            }
            other => panic!("Expected UserAnswered with cancel text, got {:?}", other),
        }
    }

    /// A cancel in a non-interactive session (builder-stamped params) must
    /// return the honest no-operator text, not "user declined".
    #[tokio::test]
    async fn non_interactive_cancel_returns_no_operator_text() {
        let (shared, mut rx) = resources_with_sender_and_params(AskUserQuestionParams {
            non_interactive: Some(true),
            ..Default::default()
        });
        let tool = AskUserQuestionTool;

        let input = AskUserQuestionInput {
            questions: vec![make_question("Q?", &["A"])],
            use_id_keyed_format: false,
        };

        let handle = tokio::spawn({
            let shared = shared.clone();
            async move {
                fuigo_tool_runtime::Tool::run(&tool, test_ctx_with_call_id(shared, "tc-ni"), input)
                    .await
            }
        });

        let request = rx.recv().await.unwrap();
        request
            .result_tx
            .send(Ok(UserQuestionResponse::Cancelled))
            .unwrap();

        let result = handle.await.unwrap().unwrap();
        match result {
            AskUserQuestionOutput::UserAnswered { message } => {
                assert_eq!(message, format::NO_OPERATOR_TEXT);
                // Headless (`headless/ext_protocol.rs` answers `Cancelled` at
                // once) is the shipped path; pin its model-visible bytes.
                assert_eq!(
                    message,
                    "No user is available to answer questions in this non-interactive session. \
                     Continue with your best judgment; do not wait for clarification."
                );
            }
            other => panic!(
                "Expected UserAnswered with no-operator text, got {:?}",
                other
            ),
        }
    }

    /// A timeout in a non-interactive session also returns the no-operator
    /// text — both unanswered paths share one wording source.
    #[tokio::test(start_paused = true)]
    async fn non_interactive_timeout_returns_no_operator_text() {
        let (shared, mut rx) = resources_with_sender_and_params(AskUserQuestionParams {
            timeout_enabled: Some(true),
            timeout_secs: Some(5),
            non_interactive: Some(true),
        });
        let tool = AskUserQuestionTool;

        let input = AskUserQuestionInput {
            questions: vec![make_question("Q?", &["A", "B"])],
            use_id_keyed_format: false,
        };

        let handle = tokio::spawn({
            let shared = shared.clone();
            async move {
                fuigo_tool_runtime::Tool::run(
                    &tool,
                    test_ctx_with_call_id(shared, "tc-ni-timeout"),
                    input,
                )
                .await
            }
        });

        let _request = rx.recv().await.expect("should receive request");
        tokio::time::advance(std::time::Duration::from_secs(6)).await;

        let result = handle.await.unwrap().unwrap();
        match result {
            AskUserQuestionOutput::UserAnswered { message } => {
                assert_eq!(message, format::NO_OPERATOR_TEXT);
            }
            other => panic!(
                "Expected UserAnswered with no-operator text, got {:?}",
                other
            ),
        }
    }

    /// Whole questionnaire (multi-question batch) shares one 6-minute timer.
    /// No `Params` injected — pins the legacy env→default budget for
    /// consumers that never resolve `[toolset.ask_user_question]`.
    #[tokio::test(start_paused = true)]
    async fn blocking_times_out_after_default_budget_for_batch() {
        let (shared, mut rx) = resources_with_sender();
        let tool = AskUserQuestionTool;

        let input = AskUserQuestionInput {
            questions: vec![
                make_question("Q1?", &["A", "B"]),
                make_question("Q2?", &["C", "D"]),
            ],
            use_id_keyed_format: false,
        };

        let handle = tokio::spawn({
            let shared = shared.clone();
            async move {
                fuigo_tool_runtime::Tool::run(
                    &tool,
                    test_ctx_with_call_id(shared, "tc-timeout"),
                    input,
                )
                .await
            }
        });

        let request = rx.recv().await.expect("should receive request");
        assert_eq!(request.questions.len(), 2);
        // Advance past the *effective* budget (honors env override if set).
        let wait = response_timeout();
        tokio::time::advance(wait + std::time::Duration::from_secs(1)).await;

        let result = handle.await.unwrap().unwrap();
        match result {
            AskUserQuestionOutput::UserAnswered { message } => {
                assert_eq!(message, format::CANCEL_TEXT);
            }
            other => panic!(
                "Expected UserAnswered with skip/cancel text, got {:?}",
                other
            ),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn answer_before_timeout_still_succeeds() {
        let (shared, mut rx) = resources_with_sender();
        let tool = AskUserQuestionTool;

        let input = AskUserQuestionInput {
            questions: vec![make_question("Which database?", &["Redis", "Postgres"])],
            use_id_keyed_format: false,
        };

        let handle = tokio::spawn({
            let shared = shared.clone();
            async move {
                fuigo_tool_runtime::Tool::run(&tool, test_ctx_with_call_id(shared, "tc-ok"), input)
                    .await
            }
        });

        let request = rx.recv().await.expect("should receive request");
        // Stay well under the effective timeout (env override or default budget).
        let advance = response_timeout()
            .checked_div(6)
            .unwrap_or(std::time::Duration::from_secs(1))
            .max(std::time::Duration::from_secs(1));
        tokio::time::advance(advance).await;

        let mut answers = IndexMap::new();
        answers.insert("Which database?".to_string(), vec!["Redis".to_string()]);
        request
            .result_tx
            .send(Ok(UserQuestionResponse::Accepted {
                answers,
                annotations: None,
            }))
            .unwrap();

        let result = handle.await.unwrap().unwrap();
        match result {
            AskUserQuestionOutput::UserAnswered { message } => {
                assert!(message.contains("\"Which database?\"=\"Redis\""));
            }
            other => panic!("Expected UserAnswered, got {:?}", other),
        }
    }

    // ── Configured timeout params tests ──────────────────────────────────

    /// Unset params reproduce the legacy env→default budget; `timeout_enabled
    /// = false` disarms the timer; `0` never means "wait forever".
    #[test]
    fn wait_budget_mapping() {
        // Compared against `response_timeout()` rather than the raw constant so
        // the assertions pin the legacy delegation and hold under a dev's env override.
        assert_eq!(
            AskUserQuestionParams::default().wait_budget(),
            Some(response_timeout()),
            "registry-default (all-None) params must keep the legacy budget"
        );
        assert_eq!(
            RESPONSE_TIMEOUT,
            std::time::Duration::from_secs(30 * 60),
            "default ask_user_question budget is 30 minutes"
        );
        let disabled = AskUserQuestionParams {
            timeout_enabled: Some(false),
            timeout_secs: Some(30),
            non_interactive: None,
        };
        assert_eq!(disabled.wait_budget(), None, "disabled timer waits forever");
        let zero = AskUserQuestionParams {
            timeout_enabled: Some(true),
            timeout_secs: Some(0),
            non_interactive: None,
        };
        assert_eq!(
            zero.wait_budget(),
            Some(response_timeout()),
            "0 secs must fall back to the default, never wait forever"
        );
    }

    /// A short shell-resolved budget fires with the same silent-skip text as
    /// a user dismiss.
    #[tokio::test(start_paused = true)]
    async fn short_params_timeout_fires_with_cancel_text() {
        let (shared, mut rx) = resources_with_sender_and_params(AskUserQuestionParams {
            timeout_enabled: Some(true),
            timeout_secs: Some(5),
            non_interactive: None,
        });
        let tool = AskUserQuestionTool;

        let input = AskUserQuestionInput {
            questions: vec![make_question("Q?", &["A", "B"])],
            use_id_keyed_format: false,
        };

        let handle = tokio::spawn({
            let shared = shared.clone();
            async move {
                fuigo_tool_runtime::Tool::run(&tool, test_ctx_with_call_id(shared, "tc-short"), input)
                    .await
            }
        });

        let _request = rx.recv().await.expect("should receive request");
        tokio::time::advance(std::time::Duration::from_secs(6)).await;

        let result = handle.await.unwrap().unwrap();
        match result {
            AskUserQuestionOutput::UserAnswered { message } => {
                assert_eq!(message, format::CANCEL_TEXT);
            }
            other => panic!("Expected UserAnswered with cancel text, got {:?}", other),
        }
    }

    /// `timeout_enabled = false` waits arbitrarily long — an answer far past
    /// the default budget still succeeds instead of timing out.
    #[tokio::test(start_paused = true)]
    async fn timeout_disabled_waits_beyond_default_budget() {
        let (shared, mut rx) = resources_with_sender_and_params(AskUserQuestionParams {
            timeout_enabled: Some(false),
            timeout_secs: Some(1),
            non_interactive: None,
        });
        let tool = AskUserQuestionTool;

        let input = AskUserQuestionInput {
            questions: vec![make_question("Which database?", &["Redis", "Postgres"])],
            use_id_keyed_format: false,
        };

        let handle = tokio::spawn({
            let shared = shared.clone();
            async move {
                fuigo_tool_runtime::Tool::run(
                    &tool,
                    test_ctx_with_call_id(shared, "tc-forever"),
                    input,
                )
                .await
            }
        });

        let request = rx.recv().await.expect("should receive request");
        // Far past both the default and any env-overridden budget.
        tokio::time::advance(RESPONSE_TIMEOUT.max(response_timeout()) * 4).await;

        let mut answers = IndexMap::new();
        answers.insert("Which database?".to_string(), vec!["Redis".to_string()]);
        request
            .result_tx
            .send(Ok(UserQuestionResponse::Accepted {
                answers,
                annotations: None,
            }))
            .unwrap();

        let result = handle.await.unwrap().unwrap();
        match result {
            AskUserQuestionOutput::UserAnswered { message } => {
                assert!(message.contains("\"Which database?\"=\"Redis\""));
            }
            other => panic!("Expected UserAnswered, got {:?}", other),
        }
    }

    // ── Failure path tests ───────────────────────────────────────────────

    #[tokio::test]
    async fn channel_drop_returns_error() {
        let (shared, mut rx) = resources_with_sender();
        let tool = AskUserQuestionTool;

        let input = AskUserQuestionInput {
            questions: vec![make_question("Q?", &["A"])],
            use_id_keyed_format: false,
        };

        let handle = tokio::spawn({
            let shared = shared.clone();
            async move {
                fuigo_tool_runtime::Tool::run(&tool, test_ctx_with_call_id(shared, "tc-5"), input)
                    .await
            }
        });

        let request = rx.recv().await.unwrap();
        drop(request.result_tx);

        let err = handle.await.unwrap().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unexpectedly"), "msg: {msg}");
    }

    #[tokio::test]
    async fn transport_error_not_cancel() {
        let (shared, mut rx) = resources_with_sender();
        let tool = AskUserQuestionTool;

        let input = AskUserQuestionInput {
            questions: vec![make_question("Q?", &["A"])],
            use_id_keyed_format: false,
        };

        let handle = tokio::spawn({
            let shared = shared.clone();
            async move {
                fuigo_tool_runtime::Tool::run(&tool, test_ctx_with_call_id(shared, "tc-6"), input)
                    .await
            }
        });

        let request = rx.recv().await.unwrap();
        request
            .result_tx
            .send(Err(UserQuestionError::TransportError(
                "connection reset".to_string(),
            )))
            .unwrap();

        let err = handle.await.unwrap().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Failed to reach the client"), "msg: {msg}");
        assert!(msg.contains("connection reset"), "msg: {msg}");
    }

    // ── Non-interactive embedder path (P04) ──────────────────────────────

    /// Spawns the tool with `params` and returns (join handle, coordinator rx).
    fn spawn_tool(
        params: AskUserQuestionParams,
        call_id: &'static str,
    ) -> (
        tokio::task::JoinHandle<
            Result<AskUserQuestionOutput, fuigo_tool_runtime::ToolError>,
        >,
        mpsc::UnboundedReceiver<types::UserQuestionRequest>,
    ) {
        let (shared, rx) = resources_with_sender_and_params(params);
        let input = AskUserQuestionInput {
            questions: vec![make_question("Q?", &["A", "B"])],
            use_id_keyed_format: false,
        };
        let handle = tokio::spawn(async move {
            fuigo_tool_runtime::Tool::run(
                &AskUserQuestionTool,
                test_ctx_with_call_id(shared, call_id),
                input,
            )
            .await
        });
        (handle, rx)
    }

    fn non_interactive() -> AskUserQuestionParams {
        AskUserQuestionParams {
            non_interactive: Some(true),
            ..Default::default()
        }
    }

    /// Non-interactive budget is seconds, never 30 minutes and never unbounded;
    /// a shorter configured budget is still honoured. Interactive is unchanged.
    #[test]
    fn non_interactive_wait_budget_is_capped_in_seconds() {
        let cap = NON_INTERACTIVE_RESPONSE_TIMEOUT;
        assert!(
            cap > std::time::Duration::ZERO && cap <= std::time::Duration::from_secs(60),
            "the non-interactive cap must be seconds, not zero and not minutes: {cap:?}"
        );
        assert_eq!(
            non_interactive().wait_budget(),
            Some(response_timeout().min(cap)),
            "default non-interactive budget must be the cap, not the 30-minute default"
        );
        let disabled = AskUserQuestionParams {
            timeout_enabled: Some(false),
            ..non_interactive()
        };
        assert_eq!(
            disabled.wait_budget(),
            Some(cap),
            "timeout_enabled = false must not make a non-interactive session wait forever"
        );
        let long = AskUserQuestionParams {
            timeout_enabled: Some(true),
            timeout_secs: Some(3600),
            non_interactive: Some(true),
        };
        assert_eq!(long.wait_budget(), Some(cap));
        let short = AskUserQuestionParams {
            timeout_enabled: Some(true),
            timeout_secs: Some(5),
            non_interactive: Some(true),
        };
        assert_eq!(short.wait_budget(), Some(std::time::Duration::from_secs(5)));
        // Interactive keeps the configured budget, including "wait forever".
        let interactive_long = AskUserQuestionParams {
            non_interactive: Some(false),
            ..long
        };
        assert_eq!(
            interactive_long.wait_budget(),
            Some(std::time::Duration::from_secs(3600))
        );
        let interactive_disabled = AskUserQuestionParams {
            non_interactive: Some(false),
            ..disabled
        };
        assert_eq!(interactive_disabled.wait_budget(), None);
    }

    /// An embedder that acks the question but never replies resolves within the
    /// non-interactive cap, with the no-operator text — not after 30 minutes.
    #[tokio::test(start_paused = true)]
    async fn non_interactive_silent_embedder_resolves_within_cap() {
        let started = tokio::time::Instant::now();
        let (handle, mut rx) = spawn_tool(non_interactive(), "tc-ni-silent");
        // Keep the request (and so its result_tx) alive: the embedder is silent.
        let _request = rx.recv().await.expect("the question must still be sent");

        let result = handle.await.unwrap().unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed <= NON_INTERACTIVE_RESPONSE_TIMEOUT + std::time::Duration::from_secs(1),
            "a silent non-interactive embedder stalled the tool for {elapsed:?}"
        );
        match result {
            AskUserQuestionOutput::UserAnswered { message } => {
                assert_eq!(message, format::NO_OPERATOR_TEXT);
            }
            other => panic!("Expected UserAnswered with no-operator text, got {other:?}"),
        }
    }

    /// An embedder-supplied UI can still answer a non-interactive question.
    #[tokio::test(start_paused = true)]
    async fn non_interactive_embedder_can_still_answer() {
        let (handle, mut rx) = spawn_tool(non_interactive(), "tc-ni-answer");
        let request = rx.recv().await.expect("should receive request");
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        let mut answers = IndexMap::new();
        answers.insert("Q?".to_string(), vec!["B".to_string()]);
        request
            .result_tx
            .send(Ok(UserQuestionResponse::Accepted {
                answers,
                annotations: None,
            }))
            .unwrap();
        match handle.await.unwrap().unwrap() {
            AskUserQuestionOutput::UserAnswered { message } => {
                assert!(message.contains("\"Q?\"=\"B\""), "{message}");
            }
            other => panic!("Expected UserAnswered, got {other:?}"),
        }
    }

    /// An embedder that enabled the tool but does not implement
    /// `fuigo/ask_user_question` (JSON-RPC -32601 → TransportError) yields the
    /// no-operator text in a non-interactive session, not a retryable ToolError.
    #[tokio::test]
    async fn non_interactive_missing_handler_returns_no_operator_text() {
        let (handle, mut rx) = spawn_tool(non_interactive(), "tc-ni-32601");
        let request = rx.recv().await.unwrap();
        request
            .result_tx
            .send(Err(UserQuestionError::TransportError(
                "Method not found: fuigo/ask_user_question (-32601)".to_string(),
            )))
            .unwrap();
        match handle.await.unwrap() {
            Ok(AskUserQuestionOutput::UserAnswered { message }) => {
                assert_eq!(message, format::NO_OPERATOR_TEXT);
            }
            other => panic!("Expected the no-operator text, got {other:?}"),
        }
    }

    /// The interactive transport break stays a hard error even when the params
    /// are present and explicitly interactive.
    #[tokio::test]
    async fn interactive_transport_error_still_errors_with_params() {
        let (handle, mut rx) = spawn_tool(
            AskUserQuestionParams {
                non_interactive: Some(false),
                ..Default::default()
            },
            "tc-i-transport",
        );
        let request = rx.recv().await.unwrap();
        request
            .result_tx
            .send(Err(UserQuestionError::TransportError(
                "connection reset".to_string(),
            )))
            .unwrap();
        let msg = handle.await.unwrap().unwrap_err().to_string();
        assert!(msg.contains("Failed to reach the client"), "msg: {msg}");
    }

    /// A malformed reply is a client bug, not "no operator": it still errors in
    /// a non-interactive session.
    #[tokio::test]
    async fn non_interactive_malformed_response_still_errors() {
        let (handle, mut rx) = spawn_tool(non_interactive(), "tc-ni-malformed");
        let request = rx.recv().await.unwrap();
        request
            .result_tx
            .send(Err(UserQuestionError::MalformedResponse("bad json".to_string())))
            .unwrap();
        let msg = handle.await.unwrap().unwrap_err().to_string();
        assert!(msg.contains("invalid response"), "msg: {msg}");
    }

    /// No coordinator can be reached in a non-interactive session: answer with
    /// the no-operator text before any channel or UI notification exists.
    /// Interactive keeps the hard "coordinator channel closed" error.
    #[tokio::test]
    async fn closed_coordinator_non_interactive_returns_no_operator_before_ui() {
        use crate::notification::types::ToolNotificationHandle;

        for (params, expect_no_operator) in [
            (non_interactive(), true),
            (AskUserQuestionParams::default(), false),
        ] {
            let (tx, rx) = mpsc::unbounded_channel::<types::UserQuestionRequest>();
            drop(rx);
            let (handle, mut notifications) = ToolNotificationHandle::channel();
            let mut resources = Resources::new();
            resources.insert(UserQuestionSender(tx));
            resources.insert(NotificationHandle(handle));
            resources.insert(crate::types::resources::Params(params));
            let input = AskUserQuestionInput {
                questions: vec![make_question("Q?", &["A"])],
                use_id_keyed_format: false,
            };
            let result = fuigo_tool_runtime::Tool::run(
                &AskUserQuestionTool,
                test_ctx_with_call_id(resources.into_shared(), "tc-closed"),
                input,
            )
            .await;
            if expect_no_operator {
                match result {
                    Ok(AskUserQuestionOutput::UserAnswered { message }) => {
                        assert_eq!(message, format::NO_OPERATOR_TEXT);
                    }
                    other => panic!("Expected the no-operator text, got {other:?}"),
                }
            } else {
                let msg = result.unwrap_err().to_string();
                assert!(msg.contains("coordinator channel closed"), "msg: {msg}");
            }
            assert!(
                notifications.try_recv().is_err(),
                "no UserQuestionAsked may be emitted when no coordinator exists"
            );
        }
    }

    /// The coordinator dropping `result_tx` without replying is a coordinator
    /// fault, not "no operator": it stays a hard error in a non-interactive
    /// session too (deliberately outside P04's TransportError mapping).
    #[tokio::test]
    async fn non_interactive_coordinator_drop_still_errors() {
        let (handle, mut rx) = spawn_tool(non_interactive(), "tc-ni-drop");
        let request = rx.recv().await.unwrap();
        drop(request.result_tx);
        let msg = handle.await.unwrap().unwrap_err().to_string();
        assert!(msg.contains("ended unexpectedly"), "msg: {msg}");
    }
}
