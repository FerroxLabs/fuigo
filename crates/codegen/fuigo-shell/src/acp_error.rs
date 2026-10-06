//! Typed `acp::Error` construction.
//!
//! Every error the shell answers a request with carries object `data`: `{"message": <text>, "error_kind": <tag>}`, plus any structured fields.
//! JSON clients read `data.message` and `data.error_kind`; a bare string in `data` is dropped, and the user sees only the JSON-RPC class name.
//! Build errors with the constructors here, or put [`error_data`] / [`error_data_with_fields`] in `data` when the code is custom.
//! `sampling::error::error_data_guard_tests` rejects any other `data` in shell source.
//! People never see the object itself: text readers take `data.message` (`sampling::error::acp_error_text`).

use agent_client_protocol as acp;
use fuigo_sampler::SamplingErrorKind;

/// `acp::Error.data` key of the typed kind marker.
/// Snake_case like its shipped `data` sibling `http_status`; frozen wire format.
/// Clients must treat an unknown value as a generic failure.
pub const ERROR_KIND_DATA_KEY: &str = "error_kind";

/// A request the agent could not hand to its session actor, or that the actor never answered.
pub const ERROR_KIND_SESSION_UNAVAILABLE: &str = "session_unavailable";
/// A failure inside the agent that is none of the more specific kinds.
pub const ERROR_KIND_INTERNAL: &str = "internal";
/// The request itself is wrong: bad or missing parameters, an unknown session or method, an unsupported operation.
pub const ERROR_KIND_INVALID_REQUEST: &str = "invalid_request";
/// The named resource (a session, a file) does not exist.
pub const ERROR_KIND_NOT_FOUND: &str = "not_found";
/// Reading or writing the session's on-disk state failed (session directory, history, durable execution state).
pub const ERROR_KIND_SESSION_STORAGE: &str = "session_storage";
/// Context compaction failed.
pub const ERROR_KIND_COMPACTION: &str = "compaction";
/// A budgeted execution (a workflow child, a goal) stopped before its work finished: a budget ran out, or it ended with a partial receipt.
pub const ERROR_KIND_EXECUTION_INCOMPLETE: &str = "execution_incomplete";

/// The `error_kind` of an `acp::Error`: a model-request failure kind, or one of the agent-side kinds above.
/// The strings are frozen wire format and documented in the agent-mode guide ("Errors").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpErrorKind {
    /// A model-request failure; the tag is [`SamplingErrorKind::as_str`].
    Sampling(SamplingErrorKind),
    SessionUnavailable,
    Internal,
    InvalidRequest,
    NotFound,
    SessionStorage,
    Compaction,
    ExecutionIncomplete,
}

impl AcpErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AcpErrorKind::Sampling(kind) => kind.as_str(),
            AcpErrorKind::SessionUnavailable => ERROR_KIND_SESSION_UNAVAILABLE,
            AcpErrorKind::Internal => ERROR_KIND_INTERNAL,
            AcpErrorKind::InvalidRequest => ERROR_KIND_INVALID_REQUEST,
            AcpErrorKind::NotFound => ERROR_KIND_NOT_FOUND,
            AcpErrorKind::SessionStorage => ERROR_KIND_SESSION_STORAGE,
            AcpErrorKind::Compaction => ERROR_KIND_COMPACTION,
            AcpErrorKind::ExecutionIncomplete => ERROR_KIND_EXECUTION_INCOMPLETE,
        }
    }
}

impl From<SamplingErrorKind> for AcpErrorKind {
    fn from(kind: SamplingErrorKind) -> Self {
        AcpErrorKind::Sampling(kind)
    }
}

/// Typed `data`: `{"message", "error_kind"}`.
pub fn error_data(kind: AcpErrorKind, message: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "message": message.into(), ERROR_KIND_DATA_KEY: kind.as_str() })
}

/// Typed `data` that also carries structured fields (a `code` a client matches on, a receipt).
/// `fields` must be an object; any other value is kept under `detail`. `message` and `error_kind` always win over same-named fields.
pub fn error_data_with_fields(
    kind: AcpErrorKind,
    message: impl Into<String>,
    fields: serde_json::Value,
) -> serde_json::Value {
    let mut map = match fields {
        serde_json::Value::Object(map) => map,
        serde_json::Value::Null => serde_json::Map::new(),
        other => serde_json::Map::from_iter([("detail".to_string(), other)]),
    };
    map.insert("message".into(), serde_json::Value::String(message.into()));
    map.insert(ERROR_KIND_DATA_KEY.into(), kind.as_str().into());
    serde_json::Value::Object(map)
}

/// Bring existing `data` to the typed shape without losing anything.
/// An object keeps its fields; a bare string (or any other value) becomes `message`; a missing `message` is `fallback_message`; a missing kind is `internal`.
pub fn typed_error_data(
    data: Option<serde_json::Value>,
    fallback_message: &str,
) -> serde_json::Value {
    let mut map = match data {
        Some(serde_json::Value::Object(map)) => map,
        Some(serde_json::Value::String(message)) => serde_json::Map::from_iter([(
            "message".to_string(),
            serde_json::Value::String(message),
        )]),
        Some(serde_json::Value::Null) | None => serde_json::Map::new(),
        Some(other) => serde_json::Map::from_iter([("message".to_string(), other)]),
    };
    if !map.get("message").is_some_and(serde_json::Value::is_string) {
        let message = match map.remove("message") {
            Some(serde_json::Value::Null) | None => fallback_message.to_string(),
            Some(other) => other.to_string(),
        };
        map.insert("message".into(), serde_json::Value::String(message));
    }
    if !map
        .get(ERROR_KIND_DATA_KEY)
        .is_some_and(serde_json::Value::is_string)
    {
        map.insert(ERROR_KIND_DATA_KEY.into(), ERROR_KIND_INTERNAL.into());
    }
    serde_json::Value::Object(map)
}

/// `err` (any JSON-RPC code) with typed `data`.
pub fn typed(err: acp::Error, kind: AcpErrorKind, message: impl Into<String>) -> acp::Error {
    err.data(error_data(kind, message))
}

/// `-32602` invalid params, kind `invalid_request`.
pub fn invalid_params(message: impl Into<String>) -> acp::Error {
    typed(
        acp::Error::invalid_params(),
        AcpErrorKind::InvalidRequest,
        message,
    )
}

/// `?`-boundary for malformed request parameters: `-32602`, kind `invalid_request`.
/// Hand it to `map_err`; letting `?` convert a `serde_json::Error` on its own runs the schema crate's
/// `From` impl, which puts a BARE STRING in `data` — the shape a JSON client drops.
pub fn invalid_params_from(err: impl std::fmt::Display) -> acp::Error {
    invalid_params(err.to_string())
}

/// `?`-boundary for a failure that is not itself an `acp::Error` (serde, anyhow, io): `-32603`, kind `internal`.
/// Same reason as [`invalid_params_from`]: the schema crate's implicit conversions build untyped `data`.
pub fn internal_from(err: impl std::fmt::Display) -> acp::Error {
    internal_error(err.to_string())
}

/// `-32602` invalid params, kind `invalid_request`, plus the stable `data.code` a client matches on.
pub fn invalid_params_with_code(code: &str, message: impl Into<String>) -> acp::Error {
    acp::Error::invalid_params().data(error_data_with_fields(
        AcpErrorKind::InvalidRequest,
        message,
        serde_json::json!({ "code": code }),
    ))
}

/// `-32600` invalid request, kind `invalid_request`.
pub fn invalid_request(message: impl Into<String>) -> acp::Error {
    typed(
        acp::Error::invalid_request(),
        AcpErrorKind::InvalidRequest,
        message,
    )
}

/// `-32601` method not found, kind `invalid_request`.
pub fn method_not_found(message: impl Into<String>) -> acp::Error {
    typed(
        acp::Error::method_not_found(),
        AcpErrorKind::InvalidRequest,
        message,
    )
}

/// `-32601` for a `fuigo/*` extension method this build does not implement: an unknown name, or a member
/// of a namespace it does serve. Version skew makes this the first error class a third-party client meets,
/// so it carries the same typed `data` as everything else instead of `data: null`.
///
/// `method` is what the routers match on, which is the wire name with its ACP `_` prefix already stripped
/// (`agent-client-protocol` strips it when it decodes an `ExtRequest`). The message echoes the name the
/// CLIENT sent -- `_`-prefixed -- so a client author matching our text against their own request string finds it.
pub fn unknown_ext_method(method: &str) -> acp::Error {
    method_not_found(format!(
        "unknown ACP extension method: {}",
        ext_method_as_sent(method)
    ))
}

/// The wire spelling of an extension method name the routers hold in its stripped form.
/// Idempotent: a name that still carries the `_` is returned untouched.
fn ext_method_as_sent(method: &str) -> std::borrow::Cow<'_, str> {
    if method.starts_with('_') {
        std::borrow::Cow::Borrowed(method)
    } else {
        std::borrow::Cow::Owned(format!("_{method}"))
    }
}

/// `-32603` internal error, kind `internal`.
pub fn internal_error(message: impl Into<String>) -> acp::Error {
    typed(
        acp::Error::internal_error(),
        AcpErrorKind::Internal,
        message,
    )
}

/// `-32000` authentication required, kind `auth`.
pub fn auth_required(message: impl Into<String>) -> acp::Error {
    typed(
        acp::Error::auth_required(),
        AcpErrorKind::Sampling(SamplingErrorKind::Auth),
        message,
    )
}

/// `-32002` resource not found, kind `not_found`.
pub fn resource_not_found(message: impl Into<String>) -> acp::Error {
    typed(
        acp::Error::resource_not_found(None),
        AcpErrorKind::NotFound,
        message,
    )
}

/// `-32603` internal error, kind `session_unavailable`.
pub fn session_unavailable(message: impl Into<String>) -> acp::Error {
    typed(
        acp::Error::internal_error(),
        AcpErrorKind::SessionUnavailable,
        message,
    )
}

/// `-32603` internal error, kind `session_storage`.
pub fn session_storage(message: impl Into<String>) -> acp::Error {
    typed(
        acp::Error::internal_error(),
        AcpErrorKind::SessionStorage,
        message,
    )
}

/// `-32603` internal error, kind `compaction`.
pub fn compaction(message: impl Into<String>) -> acp::Error {
    typed(
        acp::Error::internal_error(),
        AcpErrorKind::Compaction,
        message,
    )
}

/// `-32603` internal error, kind `execution_incomplete`.
pub fn execution_incomplete(message: impl Into<String>) -> acp::Error {
    typed(
        acp::Error::internal_error(),
        AcpErrorKind::ExecutionIncomplete,
        message,
    )
}

/// The error a budgeted execution ends with when its terminal receipt is partial: kind `execution_incomplete`, the receipt's `reason` as
/// `message`, and every receipt field (`partial`, `pending_tool_calls`, ...) kept alongside for clients that act on them.
pub(crate) fn execution_receipt_error(
    receipt: &crate::session::execution_state::TerminalReceipt,
) -> acp::Error {
    acp::Error::internal_error().data(error_data_with_fields(
        AcpErrorKind::ExecutionIncomplete,
        receipt.reason.clone(),
        serde_json::to_value(receipt).unwrap_or_default(),
    ))
}

/// P144: the partial receipt of an execution a budget FINALIZED (the turn loop reserved the last model
/// call for the final answer, or a token budget ran out mid-turn), typed as that budget's denial. The
/// receipt's own fields (`partial`, `reason`, `pending_tool_calls`, ...) are kept, so a client that reads
/// the receipt still finds it; `code`, `rule`, `remedy` and the token figures are added, so a client that
/// matches `data.code` (the pager's headless mode: exit 3) sees which limit ended the run.
pub(crate) fn execution_receipt_denial_error(
    receipt: &crate::session::execution_state::TerminalReceipt,
    denial: &ExecutionBudgetDenial,
) -> acp::Error {
    let mut fields = serde_json::to_value(receipt).unwrap_or_default();
    if let (Some(map), Some(serde_json::Value::Object(denial_data))) =
        (fields.as_object_mut(), denial.to_acp_error().data)
    {
        for (key, value) in denial_data {
            if key != "message" && key != ERROR_KIND_DATA_KEY {
                map.insert(key, value);
            }
        }
    }
    acp::Error::internal_error().data(error_data_with_fields(
        AcpErrorKind::ExecutionIncomplete,
        denial.message(),
        fields,
    ))
}

/// `data.code` of the error a turn ends with when a budget refused a model request: the durable
/// execution's token-budget guard (Contract D.4), or the model-call or runtime limit (P44; the agent
/// also answers a prompt refused by the runtime limit with it). Frozen wire format: a client branches on it.
///
/// The error is `-32603` with kind `execution_incomplete`, the kind already documented for "a budgeted
/// execution stopped before its work finished", so a client that only knows the kind still reads it
/// correctly. The `code` and the fields of [`ExecutionBudgetDenial`] are what make it a *denial* -- the
/// same three facts a headless permission denial carries: what was refused, which rule refused it, and
/// the remedy.
pub const EXECUTION_BUDGET_DENIED_CODE: &str = "execution_budget_denied";

/// Which budget refused the request. The wire ids are frozen; never localize them.
///
/// The three token rules are one variant per clause of the token guard in
/// `session::execution_state::admit_attempt`, checked in the same order. The two limit rules (P44) are
/// the process limits a private agent runs under, `FUIGO_MAX_MODEL_CALLS` and `FUIGO_MAX_RUNTIME_SECS`,
/// whichever layer enforces them: the durable execution that mirrors them when it opens (its call cap,
/// a child's share of it, its deadline) or the sampler's process-wide counter and clock. One rule per
/// limit, so a consumer can always tell which limit stopped the run and what to raise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionBudgetRule {
    /// The execution's total-token budget (a goal's `--budget`) is spent.
    TotalTokensExhausted,
    /// The execution's output-token budget (a workflow child's output grant) is spent.
    OutputTokensExhausted,
    /// A token budget is set but an earlier request reported no usage, so the guard cannot tell how
    /// much is left and fails closed.
    TokenUsageUnknown,
    /// The model-call limit (`FUIGO_MAX_MODEL_CALLS`) has no call left for this request: the calls are
    /// spent, or the one left is reserved for the execution's final answer.
    ModelCallLimit,
    /// The runtime limit (`FUIGO_MAX_RUNTIME_SECS`) has passed: the process's wall clock, or the
    /// deadline the execution recorded from it when it opened.
    RuntimeLimit,
}

impl ExecutionBudgetRule {
    pub const ALL: [Self; 5] = [
        Self::TotalTokensExhausted,
        Self::OutputTokensExhausted,
        Self::TokenUsageUnknown,
        Self::ModelCallLimit,
        Self::RuntimeLimit,
    ];

    /// Stable wire id (`data.rule`).
    pub fn id(self) -> &'static str {
        match self {
            Self::TotalTokensExhausted => "execution_token_budget_exhausted",
            Self::OutputTokensExhausted => "execution_output_token_budget_exhausted",
            Self::TokenUsageUnknown => "execution_token_usage_unknown",
            Self::ModelCallLimit => "execution_model_call_limit",
            Self::RuntimeLimit => "execution_runtime_limit",
        }
    }

    /// Inverse of [`Self::id`]; `None` for an id this build does not know (a newer agent's rule).
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|rule| rule.id() == id)
    }

    /// What the operator would have to change for the run to proceed (`data.remedy`).
    pub fn remedy(self) -> &'static str {
        match self {
            Self::TotalTokensExhausted => {
                "raise the goal's token budget (`/goal <objective> --budget <tokens>`) or clear the \
                 goal (`/goal clear`); tokens already spent are not refunded"
            }
            Self::OutputTokensExhausted => {
                "raise the output-token budget granted to this workflow child \
                 (`output_token_budget`); output tokens already spent are not refunded"
            }
            Self::TokenUsageUnknown => {
                "the provider did not report token usage for an earlier request, so the token \
                 budget cannot be enforced and fails closed; use a model that reports usage, or run \
                 without a token budget"
            }
            Self::ModelCallLimit => {
                "raise `FUIGO_MAX_MODEL_CALLS` for the next run; calls already made are not \
                 refunded, and a goal keeps the call limit its execution opened with, so clear the \
                 goal (`/goal clear`) to start a new one"
            }
            Self::RuntimeLimit => {
                "raise `FUIGO_MAX_RUNTIME_SECS` for the next run; the limit counts from agent start \
                 and cannot be extended in a running agent, and a goal keeps the deadline its \
                 execution opened with, so clear the goal (`/goal clear`) to start a new one"
            }
        }
    }
}

/// A model request refused by a budget, as data: the durable execution's token-budget guard (Contract
/// D.4), or since P44 the model-call and runtime limits (`FUIGO_MAX_MODEL_CALLS`,
/// `FUIGO_MAX_RUNTIME_SECS`). The token figures are the refusing execution's counters whatever the
/// rule; [`Self::without_token_figures`] when no execution is at hand.
///
/// Built where the guard fires (`session::execution_state`), carried through the persistence actor as
/// the payload of the `io::Error` the guard returns, latched on the execution, and turned into the
/// turn's ACP error by [`Self::to_acp_error`]. [`Self::from_acp_error`] is the inverse for a client
/// (the pager's headless mode) so nobody has to parse `data.message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionBudgetDenial {
    pub rule: ExecutionBudgetRule,
    pub total_token_limit: Option<u64>,
    pub total_tokens_used: u64,
    pub output_token_limit: Option<u64>,
    pub output_tokens_used: u64,
    pub unknown_usage: bool,
}

impl ExecutionBudgetDenial {
    /// A denial by `rule` where no execution's token counters are at hand (the agent refusing a prompt
    /// before any session runs it): no token limit, nothing counted as used.
    pub fn without_token_figures(rule: ExecutionBudgetRule) -> Self {
        Self {
            rule,
            total_token_limit: None,
            total_tokens_used: 0,
            output_token_limit: None,
            output_tokens_used: 0,
            unknown_usage: false,
        }
    }

    /// The English line: what stopped the run, then the remedy.
    pub fn message(&self) -> String {
        let what = match self.rule {
            ExecutionBudgetRule::TotalTokensExhausted => format!(
                "Execution token budget exhausted: {} of {} tokens used",
                self.total_tokens_used,
                self.total_token_limit.unwrap_or_default()
            ),
            ExecutionBudgetRule::OutputTokensExhausted => format!(
                "Execution output-token budget exhausted: {} of {} output tokens used",
                self.output_tokens_used,
                self.output_token_limit.unwrap_or_default()
            ),
            ExecutionBudgetRule::TokenUsageUnknown => {
                "Execution token usage is unknown, so the token budget refused the request".to_string()
            }
            ExecutionBudgetRule::ModelCallLimit => {
                "Execution model-call limit reached: no model call is left for this request".to_string()
            }
            ExecutionBudgetRule::RuntimeLimit => {
                "Execution runtime limit reached: the run's time is up".to_string()
            }
        };
        format!(
            "{what}. Denied by rule `{}`. Remedy: {}.",
            self.rule.id(),
            self.rule.remedy()
        )
    }

    /// The turn's ACP error: `-32603`, kind `execution_incomplete`, `code`
    /// [`EXECUTION_BUDGET_DENIED_CODE`], plus the rule, the remedy and the budget figures.
    pub fn to_acp_error(&self) -> acp::Error {
        acp::Error::internal_error().data(error_data_with_fields(
            AcpErrorKind::ExecutionIncomplete,
            self.message(),
            serde_json::json!({
                "code": EXECUTION_BUDGET_DENIED_CODE,
                "rule": self.rule.id(),
                "remedy": self.rule.remedy(),
                "total_token_limit": self.total_token_limit,
                "total_tokens_used": self.total_tokens_used,
                "output_token_limit": self.output_token_limit,
                "output_tokens_used": self.output_tokens_used,
                "unknown_usage": self.unknown_usage,
            }),
        ))
    }

    /// Recover the denial from an ACP error, or `None` when the error is not one.
    ///
    /// Keyed on `data.code` alone: the kind, the JSON-RPC code and the message may all be reworded
    /// without this changing. An unknown `data.rule` (a newer agent) is still a denial -- it is reported
    /// as `None` here so the caller can fall back to the generic budget wording rather than guess.
    pub fn from_acp_error(err: &acp::Error) -> Option<Self> {
        let data = err.data.as_ref()?;
        if data.get("code").and_then(serde_json::Value::as_str) != Some(EXECUTION_BUDGET_DENIED_CODE) {
            return None;
        }
        let rule = ExecutionBudgetRule::from_id(data.get("rule")?.as_str()?)?;
        let u64_at = |key: &str| data.get(key).and_then(serde_json::Value::as_u64);
        Some(Self {
            rule,
            total_token_limit: u64_at("total_token_limit"),
            total_tokens_used: u64_at("total_tokens_used").unwrap_or_default(),
            output_token_limit: u64_at("output_token_limit"),
            output_tokens_used: u64_at("output_tokens_used").unwrap_or_default(),
            unknown_usage: data
                .get("unknown_usage")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or_default(),
        })
    }

    /// Whether `err` carries [`EXECUTION_BUDGET_DENIED_CODE`], whatever its rule.
    pub fn is_budget_denial(err: &acp::Error) -> bool {
        err.data
            .as_ref()
            .and_then(|data| data.get("code"))
            .and_then(serde_json::Value::as_str)
            == Some(EXECUTION_BUDGET_DENIED_CODE)
    }
}

impl std::fmt::Display for ExecutionBudgetDenial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for ExecutionBudgetDenial {}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind_and_message(err: &acp::Error) -> (&str, &str) {
        let data = err.data.as_ref().expect("typed data");
        (
            data[ERROR_KIND_DATA_KEY].as_str().expect("kind"),
            data["message"].as_str().expect("message"),
        )
    }

    #[test]
    fn constructors_pair_the_json_rpc_code_with_a_typed_kind() {
        let cases: [(acp::Error, i32, &str); 11] = [
            (invalid_params("m"), -32602, "invalid_request"),
            (invalid_request("m"), -32600, "invalid_request"),
            (method_not_found("m"), -32601, "invalid_request"),
            (internal_error("m"), -32603, "internal"),
            (auth_required("m"), -32000, "auth"),
            (resource_not_found("m"), -32002, "not_found"),
            (session_unavailable("m"), -32603, "session_unavailable"),
            (session_storage("m"), -32603, "session_storage"),
            (compaction("m"), -32603, "compaction"),
            (execution_incomplete("m"), -32603, "execution_incomplete"),
            (
                invalid_params_with_code("some_code", "m"),
                -32602,
                "invalid_request",
            ),
        ];
        for (err, code, kind) in cases {
            assert_eq!(i32::from(err.code), code, "{err:?}");
            assert_eq!(kind_and_message(&err), (kind, "m"), "{err:?}");
        }
        assert_eq!(
            invalid_params_with_code("some_code", "m")
                .data
                .expect("data")["code"],
            "some_code"
        );
    }

    /// Every namespace router answers an unimplemented `fuigo/*` method with this, so the reply names
    /// what the client asked for instead of arriving as `-32601` with `data: null`.
    #[test]
    fn unknown_ext_method_names_the_method_the_client_asked_for() {
        let err = unknown_ext_method("fuigo/skills/definitely_not_a_method");
        assert_eq!(i32::from(err.code), -32601);
        assert_eq!(
            kind_and_message(&err),
            (
                "invalid_request",
                "unknown ACP extension method: _fuigo/skills/definitely_not_a_method"
            ),
            "the message must echo the method as the client sent it, `_` prefix included"
        );
    }

    /// The routers are handed `ExtRequest::method`, which the protocol crate already stripped of its
    /// `_`. Echoing that back told a client that sent `_fuigo/skills/x` about `fuigo/skills/x`, which
    /// its own request string never contained. Restoring the prefix is idempotent, so a caller that
    /// somehow holds the wire spelling does not get `__`.
    #[test]
    fn unknown_ext_method_restores_the_wire_prefix_exactly_once() {
        for name in [
            "fuigo/not_a_namespace/at_all",
            "_fuigo/not_a_namespace/at_all",
        ] {
            assert_eq!(
                kind_and_message(&unknown_ext_method(name)).1,
                "unknown ACP extension method: _fuigo/not_a_namespace/at_all",
                "{name}"
            );
        }
    }

    /// `send_tool_call_start` used to let `?` convert a `serde_json::Error` through the schema crate:
    /// `-32602 invalid_params`, with a bare string in `data`. Failing to serialize the AGENT's own tool
    /// input is not the client's bad parameters, so it goes out as `internal_from` instead. The JSON-RPC
    /// code changed with it, deliberately; this pins both halves and 15-agent-mode.md records the change.
    #[test]
    fn internal_from_answers_a_serialization_failure_as_internal_not_invalid_params() {
        let schema_conversion: acp::Error = serde_json::from_str::<u8>("{}")
            .expect_err("not a u8")
            .into();
        assert_eq!(i32::from(schema_conversion.code), -32602);
        assert!(
            schema_conversion
                .data
                .as_ref()
                .is_some_and(serde_json::Value::is_string),
            "the schema crate's `From` is what put a bare string on the wire"
        );

        let typed = internal_from(serde_json::from_str::<u8>("{}").expect_err("not a u8"));
        assert_eq!(i32::from(typed.code), -32603);
        assert_eq!(kind_and_message(&typed).0, "internal");
    }

    #[test]
    fn error_data_with_fields_keeps_structured_fields_and_the_typed_keys_win() {
        let data = error_data_with_fields(
            AcpErrorKind::InvalidRequest,
            "only on chat sessions",
            serde_json::json!({ "code": "local_workspace_chat_only", "message": "stale", "error_kind": "stale" }),
        );
        assert_eq!(
            data,
            serde_json::json!({
                "code": "local_workspace_chat_only",
                "message": "only on chat sessions",
                "error_kind": "invalid_request",
            })
        );
        assert_eq!(
            error_data_with_fields(AcpErrorKind::Internal, "m", serde_json::json!([1])),
            serde_json::json!({ "detail": [1], "message": "m", "error_kind": "internal" })
        );
    }

    #[test]
    fn typed_error_data_normalizes_any_existing_data() {
        assert_eq!(
            typed_error_data(Some(serde_json::json!("bare")), "fallback"),
            serde_json::json!({ "message": "bare", "error_kind": "internal" })
        );
        assert_eq!(
            typed_error_data(None, "Internal error"),
            serde_json::json!({ "message": "Internal error", "error_kind": "internal" })
        );
        let kept = serde_json::json!({ "message": "m", "error_kind": "empty_response", "http_status": 502 });
        assert_eq!(typed_error_data(Some(kept.clone()), "x"), kept);
        assert_eq!(
            typed_error_data(
                Some(serde_json::json!({ "code": "FS_OTHER" })),
                "An I/O error"
            ),
            serde_json::json!({ "code": "FS_OTHER", "message": "An I/O error", "error_kind": "internal" })
        );
    }

    /// Contract D.4: a budget denial reaches the client as data, not prose. Pins the frozen wire
    /// shape -- class, kind, `code`, `rule`, `remedy` and the figures -- for every rule, and that a
    /// client recovers exactly the denial that was sent without reading `message`.
    #[test]
    fn a_budget_denial_round_trips_through_its_acp_error_for_every_rule() {
        for rule in ExecutionBudgetRule::ALL {
            let denial = ExecutionBudgetDenial {
                rule,
                total_token_limit: Some(100),
                total_tokens_used: 120,
                output_token_limit: Some(40),
                output_tokens_used: 41,
                unknown_usage: rule == ExecutionBudgetRule::TokenUsageUnknown,
            };
            let err = denial.to_acp_error();
            assert_eq!(i32::from(err.code), -32603, "{rule:?}");
            let wire = serde_json::to_value(&err).expect("serialize");
            let data = &wire["data"];
            assert_eq!(data["error_kind"], "execution_incomplete", "{wire}");
            assert_eq!(data["code"], EXECUTION_BUDGET_DENIED_CODE, "{wire}");
            assert_eq!(data["rule"], rule.id(), "{wire}");
            assert_eq!(data["remedy"], rule.remedy(), "{wire}");
            assert_eq!(data["total_token_limit"], 100, "{wire}");
            assert_eq!(data["output_tokens_used"], 41, "{wire}");
            assert!(
                data["message"].as_str().is_some_and(|m| m.contains(rule.id())),
                "the human line names the rule: {wire}"
            );
            assert_eq!(ExecutionBudgetRule::from_id(rule.id()), Some(rule));
            let back: acp::Error = serde_json::from_value(wire.clone()).expect("deserialize");
            assert!(ExecutionBudgetDenial::is_budget_denial(&back));
            assert_eq!(ExecutionBudgetDenial::from_acp_error(&back), Some(denial), "{wire}");
        }
        let ids: std::collections::BTreeSet<_> =
            ExecutionBudgetRule::ALL.iter().map(|rule| rule.id()).collect();
        assert_eq!(ids.len(), ExecutionBudgetRule::ALL.len(), "rule ids are distinct");
    }

    /// Nothing else is mistaken for a denial: not the kind it shares, not another `code`.
    #[test]
    fn only_the_budget_denial_code_reads_as_a_budget_denial() {
        for err in [
            execution_incomplete("Execution output-token budget exhausted"),
            invalid_params_with_code("local_workspace_chat_only", "m"),
            internal_error("execution admission denied or could not be persisted"),
            acp::Error::internal_error(),
        ] {
            assert!(!ExecutionBudgetDenial::is_budget_denial(&err), "{err:?}");
            assert_eq!(ExecutionBudgetDenial::from_acp_error(&err), None, "{err:?}");
        }
    }

    #[test]
    fn every_agent_side_kind_has_its_frozen_tag() {
        use AcpErrorKind as K;
        for (kind, tag) in [
            (K::SessionUnavailable, "session_unavailable"),
            (K::Internal, "internal"),
            (K::InvalidRequest, "invalid_request"),
            (K::NotFound, "not_found"),
            (K::SessionStorage, "session_storage"),
            (K::Compaction, "compaction"),
            (K::ExecutionIncomplete, "execution_incomplete"),
            (K::Sampling(SamplingErrorKind::Cancelled), "cancelled"),
        ] {
            // Exhaustive: a new kind refuses to compile until it is listed (and documented)
            match kind {
                K::Sampling(_)
                | K::SessionUnavailable
                | K::Internal
                | K::InvalidRequest
                | K::NotFound
                | K::SessionStorage
                | K::Compaction
                | K::ExecutionIncomplete => {}
            }
            assert_eq!(kind.as_str(), tag);
            assert!(
                matches!(kind, K::Sampling(_)) || tag.parse::<SamplingErrorKind>().is_err(),
                "{tag} collides with a sampling kind"
            );
        }
    }
}
