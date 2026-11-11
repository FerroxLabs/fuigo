//! Fixed vocabulary at the error wire and persistence boundaries.
use serde::{Serialize, Serializer};
use serde_json::Value;

/// Provider types used by the supported envelopes, tests and agent-mode contract.
pub const PROVIDER_TYPES: &[&str] = &[
    "error",
    "hold",
    "rate_limit_exceeded",
    "rate_limit_error",
    "authentication_error",
    "permission_error",
    "invalid_request_error",
    "insufficient_quota",
    "overloaded_error",
    "api_error",
    "provider_error",
    "BAD_REQUEST",
    "server_error",
    "not_found_error",
    "request_too_large",
    "billing_error",
    "auth_error",
    "token_expired",
    "service_unavailable_error",
    "context_length_exceeded",
    "transient",
    "invalid_image",
    "unknown",
    "other",
];
/// Exact names from https://docs.litellm.ai/docs/exception_mapping (2026-11-10).
pub const LITELLM_EXCEPTIONS: &[&str] = &[
    "RateLimitError",
    "AuthenticationError",
    "BadRequestError",
    "NotFoundError",
    "ServiceUnavailableError",
    "APIConnectionError",
    "Timeout",
    "ContextWindowExceededError",
    "ContentPolicyViolationError",
    "InternalServerError",
    "APIError",
    "UnsupportedParamsError",
    "ImageFetchError",
    "InvalidRequestError",
    "PaymentRequiredError",
    "PermissionDeniedError",
    "UnprocessableEntityError",
    "APIResponseValidationError",
    "BudgetExceededError",
    "JSONSchemaValidationError",
    "MockException",
    "OpenAIError",
];

pub fn vocab(value: &str) -> &str {
    if crate::refusal::FINAL_ORDER
        .iter()
        .any(|(code, _)| *code == value)
        || crate::refusal::TRANSIENT.contains(&value)
        || value == "concurrency"
        || PROVIDER_TYPES.contains(&value)
        || LITELLM_EXCEPTIONS.contains(&value)
        || [
            "bot_monthly_spend",
            "monthly_spend",
            "monthly_tokens",
            "rpm",
        ]
        .contains(&value)
    {
        value
    } else {
        "other"
    }
}
pub fn serialize_optional<S: Serializer>(
    value: &Option<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    value.as_deref().map(vocab).serialize(serializer)
}
pub fn serialize_codes<S: Serializer>(value: &[String], serializer: S) -> Result<S::Ok, S::Error> {
    value
        .iter()
        .map(|s| vocab(s))
        .collect::<Vec<_>>()
        .serialize(serializer)
}
pub fn deserialize_optional<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<String>, D::Error> {
    let v = crate::error::lenient_code(d)?;
    Ok(v.map(|s| vocab(&s).to_owned()))
}
/// Handles manually constructed ACP data too, before credential-text scrubbing.
pub fn project_json(upstream: &mut Value) {
    if let Some(map) = upstream.as_object_mut() {
        for field in ["state", "type", "code", "hold_reason", "limit"] {
            if let Some(value) = map.get_mut(field) {
                *value = value
                    .as_str()
                    .map(|s| Value::String(vocab(s).into()))
                    .unwrap_or(Value::Null);
            }
        }
        if let Some(Value::Array(codes)) = map.get_mut("codes") {
            for value in codes {
                *value = value
                    .as_str()
                    .map(|s| Value::String(vocab(s).into()))
                    .unwrap_or(Value::Null);
            }
        }
    }
}

// The sampler actor's persisted mirror retains request provenance. ACP upstream
// objects use UpstreamError's ordinary serializer and never expose this flag.
pub fn serialize_internal<S: Serializer>(
    upstream: &crate::error::UpstreamError,
    s: S,
) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Stored<'a> {
        #[serde(flatten)]
        upstream: &'a crate::error::UpstreamError,
        flux_routed: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        classification: Option<crate::refusal::Classification>,
    }
    Stored {
        upstream,
        flux_routed: upstream.flux_routed,
        classification: upstream.classification.clone(),
    }
    .serialize(s)
}
pub fn deserialize_internal<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<crate::error::UpstreamError, D::Error> {
    #[derive(serde::Deserialize)]
    struct Stored {
        #[serde(flatten)]
        upstream: crate::error::UpstreamError,
        #[serde(default)]
        flux_routed: bool,
        #[serde(default)]
        classification: Option<crate::refusal::Classification>,
    }
    let mut stored = <Stored as serde::Deserialize>::deserialize(d)?;
    stored.upstream.flux_routed = stored.flux_routed;
    stored.upstream.classification = stored.classification;
    Ok(stored.upstream)
}
