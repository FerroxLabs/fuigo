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
        for name in ["fuigo/not_a_namespace/at_all", "_fuigo/not_a_namespace/at_all"] {
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
