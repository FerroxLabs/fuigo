//! Sampling error types.
//!
//! The canonical error types live in `fuigo_sampling_types::error`.
//! This module re-exports them and adds `map_sampling_err_to_acp`, which depends on `agent_client_protocol::Error` (a fuigo-shell dependency).

pub use fuigo_sampling_types::error::*;

// Clients carry this typed kind from parsing the wire error to choosing the user-facing copy; re-exported so the pager shares the exact type
pub use fuigo_sampler::SamplingErrorKind;

use crate::acp_error::ERROR_KIND_DATA_KEY;
use agent_client_protocol as acp;

/// ACP error code for rate-limited requests (HTTP 429).
/// Uses the JSON-RPC implementation-defined server error range (-32000 to -32099).
///
/// Contract: set only for actual HTTP 429 responses from the sampling client.
/// Clients derive user-facing text via [`format_rate_limited_user_message`].
/// The desktop path (`prompt_complete_fields`) reports the stop reason with no detail.
pub const RATE_LIMITED_ERROR_CODE: i32 = -32003;

/// OAuth / session rate-limit copy (personal plan upgrade path).
pub const RATE_LIMITED_USER_MESSAGE_OAUTH: &str =
    "You\u{2019}ve hit the rate limit for your plan. Upgrade your account or try again later.";

/// API key rate-limit copy.
///
/// Previously described xAI's team-credit model and linked docs.x.ai. Fuigo
/// keys are FluxRouter or direct-provider keys, whose limits are set by
/// whoever issued them, so the copy no longer asserts a billing model it
/// cannot know.
pub const RATE_LIMITED_USER_MESSAGE_API_KEY: &str = "You\u{2019}ve hit the rate limit for this API key. Check the limits set by your key\u{2019}s provider, or try again later.";

/// Well-known free-usage exhaustion code CCP returns on HTTP 429.
/// Matches `prod_util_well_known_errors::SUBSCRIPTION_FREE_USAGE_EXHAUSTED`.
/// sampling-types' `parse_error_bytes` prepends the flat `code` to the flattened message, so this reaches clients embedded in error detail.
pub const FREE_USAGE_EXHAUSTED_ERROR_CODE: &str = "subscription:free-usage-exhausted";

/// User-facing free-usage exhaustion copy.
/// Promises no reset duration; the provider's config drives the quota window.
///
/// This was the most incoherent string in the tree: it named Fuigo's usage
/// limit in one clause and sold SuperGrok in the next, with a referral tag.
/// Fuigo has no free tier and no subscription to upsell.
pub const FREE_USAGE_USER_MESSAGE: &str = "You\u{2019}ve reached the usage limit for this key. Add credit with your provider, use a different key, or try again later.";

/// Whether flattened server detail is free-usage-quota exhaustion (paywall), not transient throttling.
/// Sniffs the well-known code embedded by `parse_error_bytes`.
pub fn is_free_usage_exhausted_error(detail: &str) -> bool {
    detail.contains(FREE_USAGE_EXHAUSTED_ERROR_CODE)
}

/// User-facing text for an ACP -32003 rate-limit error.
///
/// The free-usage code wins first (consumer-only; checked before the upsell rewrite).
/// A detail that pushes the upstream provider's consumer-subscription plan is replaced with our own
/// rate-limit copy for EVERY auth mode — see [`consumer_subscription_upsell_replacement`].
/// Otherwise the body is shown after stripping the `API error (status …):` prefix (SamplingError Display).
/// An empty detail falls back to the OAuth or API-key message.
/// Callers that show this in UI should still run their usual sanitizer (scrub/cap).
pub fn format_rate_limited_user_message(
    server_detail: Option<&str>,
    is_api_key_auth: bool,
) -> String {
    // Free-usage sniff works on the prefixed wire string (`contains` the code).
    if server_detail.is_some_and(is_free_usage_exhausted_error) {
        return FREE_USAGE_USER_MESSAGE.to_string();
    }
    if let Some(detail) = server_detail.map(str::trim).filter(|s| !s.is_empty()) {
        let detail = strip_sampling_api_error_prefix(detail);
        if let Some(replacement) =
            consumer_subscription_upsell_replacement(detail, is_api_key_auth)
        {
            return replacement.to_string();
        }
        return detail.to_string();
    }
    if is_api_key_auth {
        RATE_LIMITED_USER_MESSAGE_API_KEY
    } else {
        RATE_LIMITED_USER_MESSAGE_OAUTH
    }
    .to_string()
}

/// Drop `SamplingError::Api`'s Display prefix so users see the IC body, not `API error (status 429 Too Many Requests): …`.
fn strip_sampling_api_error_prefix(detail: &str) -> &str {
    const PREFIX: &str = "API error (status ";
    const SEP: &str = "): ";
    if let Some(rest) = detail.strip_prefix(PREFIX)
        && let Some(idx) = rest.find(SEP)
    {
        return rest[idx + SEP.len()..].trim();
    }
    detail.trim()
}

/// The upstream provider reuses its own consumer-plan upsell copy on 429s ("upgrade to a SuperGrok
/// subscription for higher limits: https://grok.com/supergrok").
///
/// Fuigo does not sell that plan and does not market anybody else's subscription, so this copy is
/// never shown to any user, in any auth mode. It is wrong twice over: for an API key the limits come
/// from whoever issued the key, and for a session account the provider's consumer plan is not the
/// thing the user is even on.
///
/// The needle list carries the provider's own spelling on purpose. The `b5e43b9` rebrand rewrote
/// "SuperGrok" to "Fuigo" in this matcher, which is the one place the rebrand must NOT reach: the
/// string being matched comes off the wire from the provider, so it still says "SuperGrok".
fn pushes_consumer_subscription_upsell(detail: &str) -> bool {
    let d = detail.to_ascii_lowercase();
    d.contains("grok.com/supergrok")
        || d.contains("supergrok subscription")
        || d.contains("upgrade to a fuigo subscription")
        // Generic shape of the same pitch, whatever the plan is called this quarter.
        || (d.contains("upgrade to a") && d.contains("subscription"))
}

/// Our replacement copy for a 429 body that markets a consumer subscription, or `None` to show the
/// provider's body unchanged.
///
/// Callers may pass either the raw `SamplingError::Api` Display string or an already-stripped body.
/// The replacement still tells the user they hit a rate limit — only the upsell clause is dropped —
/// and it is auth-appropriate: the API-key copy talks about the key issuer's limits, which is not
/// true for a session account, so a session account gets the plan copy instead.
pub fn consumer_subscription_upsell_replacement(
    detail: &str,
    is_api_key_auth: bool,
) -> Option<&'static str> {
    if !pushes_consumer_subscription_upsell(strip_sampling_api_error_prefix(detail)) {
        return None;
    }
    Some(if is_api_key_auth {
        RATE_LIMITED_USER_MESSAGE_API_KEY
    } else {
        RATE_LIMITED_USER_MESSAGE_OAUTH
    })
}

/// User-facing copy for capacity/overload failures (stream `overloaded_error`, HTTP 529, proxy-wrapped 5xx).
/// See [`SamplingError::is_overloaded`].
pub const OVERLOADED_USER_MESSAGE: &str = "Model is temporarily overloaded. Try again in a moment.";

/// Map a `SamplingError` to an ACP `Error` for client-facing responses.
/// This stays in fuigo-shell because it depends on `agent_client_protocol::Error`.
pub(crate) fn map_sampling_err_to_acp(err: SamplingError) -> acp::Error {
    use reqwest::StatusCode;
    let info = fuigo_sampler::SamplingErrorInfo::from(&err);
    // Capacity/overload gets the same short copy everywhere, as the message and as the typed `data.message`
    if err.is_overloaded() {
        return acp::Error::new(
            acp::ErrorCode::InternalError.into(),
            OVERLOADED_USER_MESSAGE,
        )
        .data(terminal_error_data(
            OVERLOADED_USER_MESSAGE.to_string(),
            info.status_code,
            info.kind,
        ));
    }
    // Every arm below carries object `data` with this kind (see `terminal_error_data`); `http_status` only where a status was always sent
    let kind = info.kind;
    match err {
        SamplingError::Auth { message, .. } => {
            acp::Error::auth_required().data(terminal_error_data(message, None, kind))
        }
        SamplingError::InvalidConfiguration(msg) => {
            acp::Error::invalid_params().data(terminal_error_data(msg.to_owned(), None, kind))
        }
        SamplingError::Http(e) => acp::Error::internal_error().data(terminal_error_data(
            format!("http client init failed: {e}"),
            None,
            kind,
        )),
        SamplingError::Serialization(_) => {
            acp::Error::invalid_params().data(terminal_error_data(err.to_string(), None, kind))
        }
        SamplingError::Api {
            status, message, ..
        } => match status {
            StatusCode::UNAUTHORIZED => {
                acp::Error::auth_required().data(terminal_error_data(message, None, kind))
            }
            // 403 Forbidden is not an auth error: the request was authenticated, but the action is not permitted
            // Examples: content-safety blocks, ZDR-gated operations, remote-settings-blocked users
            // Passing the proxy's message via internal_error keeps the explanation visible without triggering the client's re-auth flow on -32000
            StatusCode::FORBIDDEN => {
                let message = if message.contains("requires a Fuigo subscription")
                    && crate::agent::auth_method::has_fuigo_api_key_env()
                {
                    format!(
                        "{message}\n\nYou have an API key set (FUIGO_API_KEY). \
                         Your cached OAuth session is being used instead. \
                         To use your API key, run `fuigo logout` or type /logout in the TUI."
                    )
                } else {
                    message
                };
                // 403 is content-safety, never auth: on this setup path it stays `internal_error`, which maps to `server_error`
                acp::Error::internal_error().data(terminal_error_data(message, None, kind))
            }
            StatusCode::BAD_REQUEST => {
                acp::Error::invalid_params().data(terminal_error_data(message, None, kind))
            }
            StatusCode::NOT_FOUND => {
                acp::Error::resource_not_found(None).data(terminal_error_data(message, None, kind))
            }
            StatusCode::PAYLOAD_TOO_LARGE => {
                acp::Error::invalid_params().data(terminal_error_data(message, None, kind))
            }
            StatusCode::TOO_MANY_REQUESTS => {
                acp::Error::new(RATE_LIMITED_ERROR_CODE, "Rate limited".to_string())
                    .data(terminal_error_data(message, None, kind))
            }
            // Preserve the HTTP status in data so the classifier folds capacity errors (503/529) into `rate_limit`
            _ => acp::Error::internal_error().data(terminal_error_data(
                message,
                Some(status.as_u16()),
                kind,
            )),
        },
        SamplingError::EventStreamError(message) => {
            acp::Error::internal_error().data(terminal_error_data(message, None, kind))
        }
        SamplingError::StreamError {
            error_type,
            message,
            ..
        } => acp::Error::internal_error().data(terminal_error_data(
            format!("{error_type}: {message}"),
            None,
            kind,
        )),
        SamplingError::EmptyResponse { context } => {
            acp::Error::internal_error().data(terminal_error_data(
                format!(
                    "empty response from model ({}): model={}, had_reasoning={}, finish_reason={}",
                    context.reason,
                    context.model,
                    context.had_reasoning,
                    context.finish_reason_str(),
                ),
                None,
                kind,
            ))
        }
        SamplingError::MaxTokensTruncation => {
            acp::Error::internal_error().data(terminal_error_data(err.to_string(), None, kind))
        }
        SamplingError::IdleTimeout { elapsed_secs } => {
            acp::Error::internal_error().data(terminal_error_data(
                format!("No response from model for {elapsed_secs}s — the model may be stuck"),
                None,
                kind,
            ))
        }
        // Recovery consumes these inside the sampler's retry loop; a stray terminal one still renders its labels
        SamplingError::DoomLoopDetected { .. } => {
            acp::Error::internal_error().data(terminal_error_data(err.to_string(), None, kind))
        }
        // A cancel is not a failure of the request: JSON-RPC request-cancelled (-32800), never auth (-32000)
        SamplingError::Cancelled => {
            acp::Error::request_cancelled().data(terminal_error_data(err.to_string(), None, kind))
        }
    }
}

/// Building block of [`terminal_error_data`]: `{"message"}` plus `"http_status"` when known.
/// Never put its result in `acp::Error.data` directly; every error carries a kind (see `crate::acp_error`).
pub(crate) fn error_data_with_status(
    message: String,
    http_status: Option<u16>,
) -> serde_json::Value {
    let mut data = serde_json::json!({ "message": message });
    if let Some(sc) = http_status {
        data["http_status"] = serde_json::json!(sc);
    }
    data
}

/// `error_kind` of a request whose session actor could not be reached or never replied (defined with the other agent-side kinds in `crate::acp_error`).
pub use crate::acp_error::ERROR_KIND_SESSION_UNAVAILABLE;

/// `acp::Error` for a prompt whose session actor could not be reached or never replied.
pub fn session_unavailable_error(message: impl Into<String>) -> acp::Error {
    crate::acp_error::session_unavailable(message)
}

/// Human text for an `acp::Error`: the JSON-RPC message plus the `data` detail ([`error_detail_from_data`]: `data.message` or a bare string).
/// `acp::Error`'s `Display` pretty-prints `data` as JSON, which is wrong for a person once `data` is an object, so this NEVER calls it.
/// A detail that repeats the message is printed once (the overload copy is both).
/// `data` with no readable detail (a foreign or purely machine-readable payload) degrades to the JSON-RPC message, never to the object.
pub fn acp_error_text(err: &acp::Error) -> String {
    let headline = || {
        if err.message.is_empty() {
            i32::from(err.code).to_string()
        } else {
            err.message.clone()
        }
    };
    let Some(data) = err.data.as_ref() else {
        return headline();
    };
    match error_detail_from_data(data) {
        Some(detail) if detail.is_empty() => headline(),
        Some(detail) if err.message.is_empty() => detail,
        // Overload copy (and any future error whose own message is the user-facing text) says it once, not twice
        Some(detail) if detail == err.message => detail,
        Some(detail) => format!("{}: {detail}", err.message),
        None => headline(),
    }
}

/// `salvage_cause` values stamped on mid-salvage terminal errors and forwarded onto the `shell.turn.length_empty_continuation` event.
/// EMPTY covers every continuation that cannot be salvaged at the cap: nothing visible, or a truncated tool-call tail.
/// The sampler folds both into `MaxTokensTruncation`; OVERFLOW means the request no longer fit.
pub(crate) const SALVAGE_CAUSE_KEY: &str = "salvage_cause";
pub(crate) const SALVAGE_CAUSE_EMPTY: &str = "empty_continuation";
pub(crate) const SALVAGE_CAUSE_OVERFLOW: &str = "context_overflow";

/// Terminal-failure `acp::Error.data`: always the object `{"message", "error_kind", "http_status"?}`.
/// Until 1.0.18 only max-tokens truncation got this shape and every status-less kind went out as a bare string.
/// JSON clients read `data.error_kind` / `data.http_status` and drop a string, so a turn that died on an empty response showed only "Internal error".
/// People must never see the object itself: text readers take `data.message` ([`error_detail_from_data`], [`acp_error_text`]).
pub(crate) fn terminal_error_data(
    message: String,
    http_status: Option<u16>,
    kind: SamplingErrorKind,
) -> serde_json::Value {
    let mut data = error_data_with_status(message, http_status);
    data[ERROR_KIND_DATA_KEY] = serde_json::json!(kind.as_str());
    data
}

/// Log a failed turn as exactly one ERROR record: the human text ([`acp_error_text`]), the typed kind, and the JSON-RPC code.
/// The text is recorded with Display so a JSON log layer stores the words, not a Debug-quoted copy with escaped quotes.
/// Newlines are escaped explicitly (the legacy-auth hint has several), so the record cannot split in a line-based reader.
/// This replaces `#[instrument(err)]` on the turn functions, whose `Display` rendering printed an object `data` as multi-line JSON.
pub(crate) fn log_turn_error(err: &acp::Error) {
    let text = one_line_log_text(&acp_error_text(err));
    tracing::error!(
        error = %text,
        error_kind = error_kind_str_from_error(err).unwrap_or("none"),
        code = i32::from(err.code),
        "turn failed"
    );
}

/// `text` with CR and LF written as the two-character escapes `\r` / `\n`, so it stays on one log line.
fn one_line_log_text(text: &str) -> String {
    text.replace('\r', "\\r").replace('\n', "\\n")
}

/// The raw `error_kind` marker string from `acp::Error.data`, unparsed, for readers with their own vocabulary.
/// The pager maps an unknown kind to its `Other`, keeping it immune to text recovery.
pub fn error_kind_str_from_error(err: &acp::Error) -> Option<&str> {
    err.data.as_ref()?.get(ERROR_KIND_DATA_KEY)?.as_str()
}

/// Typed view of [`error_kind_str_from_error`] for the shell's own classification, where an unknown kind degrading to `None` (generic) is correct.
pub fn error_kind_from_error(err: &acp::Error) -> Option<SamplingErrorKind> {
    error_kind_str_from_error(err)?.parse().ok()
}

/// Whether a mapped turn error carries the max-tokens truncation marker.
pub(crate) fn is_max_tokens_turn_error(err: &acp::Error) -> bool {
    error_kind_from_error(err) == Some(SamplingErrorKind::MaxTokensTruncation)
}

/// `turn_result.json` stop_reason for a failed turn: "MaxTokens" when the marker is present, else "Error".
/// Matches the success path's `acp::StopReason` names.
pub fn stop_reason_for_turn_error(err: &acp::Error) -> &'static str {
    if is_max_tokens_turn_error(err) {
        "MaxTokens"
    } else {
        "Error"
    }
}

fn error_message_from_data(data: &serde_json::Value) -> serde_json::Value {
    data.get("message").cloned().unwrap_or_else(|| data.clone())
}

/// Internal service names that upstream error bodies echo, rewritten to distinct sentence-friendly backend labels before display.
/// The labels stay distinct so a user paste keeps the failing hop.
/// Shared by shell and pager so the redaction cannot drift; apply via [`rewrite_service_names`] (case-insensitive, no cased variants here).
/// No replacement value may re-match a pattern (pinned by test).
pub const SERVICE_NAME_REWRITES: &[(&str, &str)] = &[
    ("cli-chat-proxy", "build backend"),
    ("cli_chat_proxy", "build backend"),
    ("inference-api", "inference backend"),
    ("inference_api", "inference backend"),
    ("research-api", "research backend"),
    ("research_api", "research backend"),
    ("fuigo-code-backend", "code backend"),
    ("fuigo_code_backend", "code backend"),
];

/// Scrub every [`SERVICE_NAME_REWRITES`] entry out of `text`, ASCII-case-insensitively (upstream bodies title-case service names).
/// Each replacement keeps its own casing.
pub fn rewrite_service_names(text: &str) -> String {
    let mut result = text.to_owned();
    for (pattern, replacement) in SERVICE_NAME_REWRITES {
        result = replace_ascii_case_insensitive(&result, pattern, replacement);
    }
    result
}

/// ASCII-case-insensitive `replace`.
/// Indices found on the lowercased copy map 1:1 onto `text`: `to_ascii_lowercase` never changes byte lengths.
fn replace_ascii_case_insensitive(text: &str, pattern: &str, replacement: &str) -> String {
    // An empty pattern would never advance `idx`; fail safe in release too.
    if pattern.is_empty() {
        return text.to_owned();
    }
    let lower_text = text.to_ascii_lowercase();
    let lower_pattern = pattern.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut idx = 0;
    while let Some(pos) = lower_text[idx..].find(&lower_pattern) {
        let start = idx + pos;
        out.push_str(&text[idx..start]);
        out.push_str(replacement);
        idx = start + pattern.len();
    }
    out.push_str(&text[idx..]);
    out
}

pub fn error_detail_from_data(data: &serde_json::Value) -> Option<String> {
    if let Some(m) = data.get("message").and_then(|v| v.as_str()) {
        return Some(m.to_owned());
    }
    if let Some(s) = data.as_str() {
        return Some(s.to_owned());
    }
    data.get("detail")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
}

/// Detail an ACP error carries: `data` via [`error_detail_from_data`], else the JSON-RPC `message`, so foreign shapes classify as the safe `Other`.
pub(crate) fn acp_error_message(err: &acp::Error) -> String {
    err.data
        .as_ref()
        .and_then(error_detail_from_data)
        .unwrap_or_else(|| err.message.clone())
}

pub fn http_status_from_error(err: &acp::Error) -> Option<u16> {
    err.data
        .as_ref()?
        .get("http_status")?
        .as_u64()
        .map(|s| s as u16)
}

const PROMPT_USAGE_DATA_KEY: &str = "promptUsage";

pub fn attach_prompt_usage(
    err: acp::Error,
    usage: Option<crate::extensions::notification::PromptUsage>,
) -> acp::Error {
    let Some(usage) = usage else {
        return err;
    };
    let Ok(usage_val) = serde_json::to_value(&usage) else {
        tracing::warn!(
            "attach_prompt_usage: failed to serialize PromptUsage; leaving error unchanged"
        );
        return err;
    };
    // Normalize first so the usage rides typed data even when the incoming error had a bare string or none
    let mut data = crate::acp_error::typed_error_data(err.data.clone(), &err.message);
    if let Some(map) = data.as_object_mut() {
        map.insert(PROMPT_USAGE_DATA_KEY.into(), usage_val);
    }
    err.data(crate::acp_error::typed_error_data(Some(data), ""))
}

pub fn prompt_usage_from_error(
    err: &acp::Error,
) -> Option<crate::extensions::notification::PromptUsage> {
    let data = err.data.as_ref()?;
    let raw = data.get(PROMPT_USAGE_DATA_KEY)?;
    serde_json::from_value(raw.clone()).ok()
}

/// Derive `(stop reason, agent result, error kind)` for the turn-end payloads (`prompt_complete`, durable `TurnCompleted`) from a prompt result.
/// Rate-limit errors produce `("rate_limit", null)` so the client shows its own upgrade message; other errors produce `("error", <detail>)`.
/// The error kind ([`error_kind_from_error`]) is `Some` for every model-request failure kind, not only truncation.
/// It is `None` for successes and for agent-side kinds outside the `SamplingErrorKind` vocabulary (`session_unavailable`, `internal`, ...).
pub(crate) fn prompt_complete_fields(
    result: &std::result::Result<acp::StopReason, acp::Error>,
) -> (
    serde_json::Value,
    serde_json::Value,
    Option<SamplingErrorKind>,
) {
    match result {
        Ok(reason) => (serde_json::json!(*reason), serde_json::Value::Null, None),
        Err(err) => {
            let is_rate_limit = i32::from(err.code) == RATE_LIMITED_ERROR_CODE;
            let stop = if is_rate_limit { "rate_limit" } else { "error" };
            let result = if is_rate_limit {
                serde_json::Value::Null
            } else {
                err.data
                    .as_ref()
                    .map(error_message_from_data)
                    .unwrap_or_else(|| serde_json::Value::String(err.message.clone()))
            };
            (serde_json::json!(stop), result, error_kind_from_error(err))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;

    #[test]
    fn rewrite_service_names_is_ascii_case_insensitive() {
        // Idempotency: no replacement value may re-match any pattern.
        for (_, replacement) in SERVICE_NAME_REWRITES {
            for (pattern, _) in SERVICE_NAME_REWRITES {
                assert!(
                    !replacement
                        .to_ascii_lowercase()
                        .contains(&pattern.to_ascii_lowercase()),
                    "value {replacement:?} re-matches pattern {pattern:?}"
                );
            }
        }
        // Derive cased variants from the table so fixtures never respell a name.
        for (pattern, replacement) in SERVICE_NAME_REWRITES {
            let upper = pattern.to_ascii_uppercase();
            let title: String = pattern
                .split_inclusive(['-', '_'])
                .map(|seg| {
                    let mut chars = seg.chars();
                    chars
                        .next()
                        .map(|f| f.to_ascii_uppercase().to_string() + chars.as_str())
                        .unwrap_or_default()
                })
                .collect();
            for variant in [pattern.to_string(), upper, title] {
                let out = rewrite_service_names(&format!("error from {variant} upstream"));
                assert_eq!(
                    out,
                    format!("error from {replacement} upstream"),
                    "variant {variant:?} must scrub to the replacement's own casing"
                );
            }
        }
    }

    #[test]
    fn attach_prompt_usage_preserves_error_kind_and_round_trips() {
        let mut ledger = fuigo_chat_state::UsageLedger::default();
        ledger.record_main_loop_call(
            "m",
            &fuigo_sampling_types::TokenUsage {
                prompt_tokens: 3,
                completion_tokens: 1,
                total_tokens: 4,
                reasoning_tokens: 0,
                cached_prompt_tokens: 0,
                cache_creation_prompt_tokens: 0,
            },
            None,
            Some(10),
        );
        let usage = crate::extensions::notification::PromptUsage::from(&ledger);
        let err = attach_prompt_usage(
            acp::Error::internal_error().data(terminal_error_data(
                "truncated".into(),
                None,
                fuigo_sampler::SamplingErrorKind::MaxTokensTruncation,
            )),
            Some(usage.clone()),
        );
        assert_eq!(stop_reason_for_turn_error(&err), "MaxTokens");
        let back = prompt_usage_from_error(&err).expect("usage attached");
        assert_eq!(back.totals.input_tokens, 3);
        assert_eq!(back.num_turns, 1);
    }

    #[test]
    fn attach_prompt_usage_keeps_string_message_readable() {
        let usage = crate::extensions::notification::PromptUsage {
            totals: Default::default(),
            model_usage: Default::default(),
            num_turns: 1,
            usage_is_incomplete: false,
        };
        let free = "subscription:free-usage-exhausted quota hit";
        let err = attach_prompt_usage(
            acp::Error::new(RATE_LIMITED_ERROR_CODE, "Rate limited").data(free),
            Some(usage),
        );
        let msg = err
            .data
            .as_ref()
            .and_then(|d| {
                d.as_str()
                    .or_else(|| d.get("message").and_then(|m| m.as_str()))
            })
            .unwrap_or("");
        assert!(msg.contains("subscription:free-usage-exhausted"));
        assert!(prompt_usage_from_error(&err).is_some());
        assert!(!err.data.as_ref().unwrap().is_string());
    }

    /// Every terminal kind reaches the client as an object: `message` and `error_kind` always, `http_status` when known.
    /// A string `data` is dropped by JSON clients that read `data.error_kind` / `data.http_status`, leaving a bare "Internal error".
    #[test]
    fn terminal_error_data_is_an_object_for_every_kind() {
        use SamplingErrorKind as K;
        let all = [
            K::Auth,
            K::Http,
            K::Api,
            K::Serialization,
            K::IdleTimeout,
            K::RateLimited,
            K::EmptyResponse,
            K::MaxTokensTruncation,
            K::DoomLoopDetected,
            K::Cancelled,
        ];
        for kind in all {
            // Exhaustive: a new kind refuses to compile until it is listed above
            match kind {
                K::Auth
                | K::Http
                | K::Api
                | K::Serialization
                | K::IdleTimeout
                | K::RateLimited
                | K::EmptyResponse
                | K::MaxTokensTruncation
                | K::DoomLoopDetected
                | K::Cancelled => {}
            }
            for status in [None, Some(503u16)] {
                let data = terminal_error_data("boom detail".into(), status, kind);
                let obj = data
                    .as_object()
                    .unwrap_or_else(|| panic!("{kind:?}/{status:?} must be an object, got {data}"));
                assert_eq!(obj.get("message"), Some(&serde_json::json!("boom detail")));
                assert_eq!(
                    obj.get("error_kind"),
                    Some(&serde_json::json!(kind.as_str())),
                    "{kind:?}/{status:?}"
                );
                assert_eq!(
                    obj.get("http_status").and_then(|v| v.as_u64()),
                    status.map(u64::from),
                    "{kind:?}/{status:?}"
                );
                let err = acp::Error::internal_error().data(data.clone());
                assert_eq!(error_kind_str_from_error(&err), Some(kind.as_str()));
                assert_eq!(acp_error_message(&err), "boom detail");
            }
        }
    }

    #[test]
    fn error_data_with_status_is_an_object_even_without_a_status() {
        assert_eq!(
            error_data_with_status("no status".into(), None),
            serde_json::json!({ "message": "no status" })
        );
        assert_eq!(
            error_data_with_status("with status".into(), Some(502)),
            serde_json::json!({ "message": "with status", "http_status": 502 })
        );
    }

    /// The status-less sampling errors are exactly the ones that used to go out as a bare string: they must carry their kind.
    #[test]
    fn status_less_sampling_errors_map_to_object_data_with_their_kind() {
        let empty = SamplingError::EmptyResponse {
            context: fuigo_sampling_types::EmptyResponseContext {
                reason: fuigo_sampling_types::EmptyReason::ReasoningOnly,
                had_reasoning: true,
                content_len: 0,
                tool_call_count: 0,
                finish_reason: Some("stop".into()),
                completion_tokens: Some(40),
                reasoning_tokens: Some(40),
                prompt_tokens: Some(5000),
                model: "m".into(),
                first_choice_seen: true,
                // Cluster B added this field to EmptyResponseContext; cluster A added this
                // construction site. Neither branch is wrong alone and they are in different
                // files, so the merge was clean and did not compile. `None` is what B's own
                // doc specifies for a per-attempt context (it is stamped only on the terminal
                // error), and it is `skip_serializing_if = "Option::is_none"`, so the data
                // shape this test asserts is unchanged.
                attempts: None,
            },
        };
        let cases: Vec<(SamplingError, &str, &str)> = vec![
            (
                empty,
                "empty_response",
                "empty response from model (reasoning_only)",
            ),
            (
                SamplingError::IdleTimeout { elapsed_secs: 90 },
                "idle_timeout",
                "No response from model for 90s",
            ),
            (
                SamplingError::EventStreamError("connection reset".into()),
                "http",
                "connection reset",
            ),
            (
                SamplingError::StreamError {
                    error_type: "server_error".into(),
                    message: "boom".into(),
                    code: None,
                },
                "api",
                "server_error: boom",
            ),
            (
                SamplingError::DoomLoopDetected {
                    triggers: vec!["repeat".into()],
                    aborted_at_chunk: None,
                },
                "doom_loop_detected",
                "doom loop detected",
            ),
            (
                crate::sampling::error::SamplingError::auth_unknown("token expired"),
                "auth",
                "token expired",
            ),
            (
                fuigo_sampler::events::request_cancelled_error(),
                "cancelled",
                "request cancelled",
            ),
            (
                SamplingError::InvalidConfiguration("bad base url"),
                "api",
                "bad base url",
            ),
            (
                SamplingError::Api {
                    status: StatusCode::FORBIDDEN,
                    message: "Content violates usage guidelines.".into(),
                    model_metadata: None,
                    retry_after_secs: None,
                    should_retry: None,
                    error_code: None,
                },
                "api",
                "Content violates usage guidelines.",
            ),
            (
                SamplingError::Api {
                    status: StatusCode::TOO_MANY_REQUESTS,
                    message: "Rate limit exceeded".into(),
                    model_metadata: None,
                    retry_after_secs: None,
                    should_retry: None,
                    error_code: None,
                },
                "rate_limited",
                "Rate limit exceeded",
            ),
        ];
        for (err, kind, text) in cases {
            let acp_err = map_sampling_err_to_acp(err);
            let data = acp_err.data.clone().expect("terminal errors carry data");
            assert!(
                data.is_object(),
                "{kind}: data must be an object, got {data}"
            );
            assert_eq!(
                error_kind_str_from_error(&acp_err),
                Some(kind),
                "{kind}: wrong error_kind in {data}"
            );
            let message = data["message"].as_str().unwrap_or_default();
            assert!(
                message.contains(text),
                "{kind}: message {message:?} lacks {text:?}"
            );
            // The JSON-RPC frame a client reads
            let wire = serde_json::to_value(&acp_err).expect("serialize acp error");
            assert_eq!(wire["data"]["error_kind"], kind, "{kind}: wire {wire}");
        }
    }

    #[test]
    fn session_unavailable_error_carries_a_typed_object() {
        let err = session_unavailable_error("session failed to respond");
        assert_eq!(err.code, acp::ErrorCode::InternalError);
        assert_eq!(
            err.data,
            Some(serde_json::json!({
                "message": "session failed to respond",
                "error_kind": ERROR_KIND_SESSION_UNAVAILABLE,
            }))
        );
        assert_eq!(ERROR_KIND_SESSION_UNAVAILABLE, "session_unavailable");
        // Outside the sampling vocabulary: the shell's typed view degrades to generic
        assert_eq!(error_kind_from_error(&err), None);
    }

    /// People read `data.message`, never the JSON object `Display` would print.
    #[test]
    fn acp_error_text_renders_the_message_never_raw_json() {
        let err = acp::Error::internal_error().data(terminal_error_data(
            "empty response from model (reasoning_only)".into(),
            None,
            SamplingErrorKind::EmptyResponse,
        ));
        assert_eq!(
            acp_error_text(&err),
            "Internal error: empty response from model (reasoning_only)"
        );
        assert_eq!(
            acp_error_text(&acp::Error::internal_error().data("bare string")),
            "Internal error: bare string"
        );
        assert_eq!(
            acp_error_text(&acp::Error::internal_error()),
            "Internal error"
        );
    }

    /// `data` that carries no readable message must NEVER fall back to `Display`, which
    /// pretty-prints the object across lines. `fuigo_acp_lib`'s channel-failure errors are
    /// exactly this shape, and they are the first failure most users see (the agent dying
    /// mid-prompt), rendered straight into the TUI by `acp_error_user_text`.
    #[test]
    fn acp_error_text_never_falls_back_to_display_for_an_object_without_a_message() {
        let err = acp::Error::internal_error()
            .data(serde_json::json!({ "fuigoAcpChannelFailure": "recv_failed" }));
        let text = acp_error_text(&err);
        assert!(
            !text.contains('{') && !text.contains('\n'),
            "raw JSON reached a person: {text:?}"
        );
        assert_eq!(text, "Internal error");
        // A codeless-message error still says something a person can read.
        let anonymous =
            acp::Error::new(-32099, String::new()).data(serde_json::json!({ "some_tag": "x" }));
        assert_eq!(acp_error_text(&anonymous), "-32099");
    }

    /// A turn failure is one log record on one line, even when its message spans lines.
    #[test]
    fn log_turn_error_writes_one_line_per_record() {
        let capture = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::ERROR)
            .with_writer(capture.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, log_two_failed_turns);
        let out = capture.text();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "one line per failed turn, got:\n{out}");
        assert!(
            lines[0].contains("ERROR")
                && lines[0].contains("turn failed")
                && lines[0]
                    .contains("error=Internal error: empty response from model (reasoning_only)")
                && lines[0].contains("error_kind=\"empty_response\"")
                && lines[0].contains("code=-32603"),
            "{}",
            lines[0]
        );
        assert!(
            lines[1].contains("deprecated authentication method")
                && lines[1].contains("error_kind=\"auth\""),
            "{}",
            lines[1]
        );
        assert!(!out.contains('{'), "no JSON object in the log: {out}");
    }

    #[test]
    fn error_detail_from_data_reads_message_field() {
        let data = error_data_with_status("upstream unavailable".into(), Some(503));
        assert_eq!(
            error_detail_from_data(&data).as_deref(),
            Some("upstream unavailable")
        );
    }

    #[test]
    fn rate_limited_fallback_oauth_vs_api_key() {
        assert_eq!(
            format_rate_limited_user_message(None, false),
            RATE_LIMITED_USER_MESSAGE_OAUTH
        );
        assert_eq!(
            format_rate_limited_user_message(None, true),
            RATE_LIMITED_USER_MESSAGE_API_KEY
        );
        assert!(RATE_LIMITED_USER_MESSAGE_OAUTH.contains("Upgrade your account"));
        // The API-key copy must not describe a billing model it cannot know:
        // these keys are FluxRouter or direct-provider keys, and their limits
        // are set by whoever issued them. The assertions below replace three
        // that still pinned the old xAI wording ("team", "credits", and a
        // docs.x.ai rate-limit link) after the copy had deliberately dropped it.
        assert!(RATE_LIMITED_USER_MESSAGE_API_KEY.contains("this API key"));
        assert!(RATE_LIMITED_USER_MESSAGE_API_KEY.contains("provider"));
        assert!(!RATE_LIMITED_USER_MESSAGE_API_KEY.contains("docs.x.ai"));
        assert!(!RATE_LIMITED_USER_MESSAGE_API_KEY.contains("Upgrade your account"));
    }

    #[test]
    fn format_rate_limited_surfaces_nonempty_server_detail() {
        let body = "The service is temporarily at capacity. Please retry your request shortly.";
        // Production detail is SamplingError::Api Display (prefixed).
        let wire = format!("API error (status 429 Too Many Requests): {body}");
        assert_eq!(format_rate_limited_user_message(Some(&wire), false), body);
        assert_eq!(format_rate_limited_user_message(Some(&wire), true), body);

        // Team console rate-limit copy has no personal SuperGrok upsell; it passes through as-is
        let team = "resource-exhausted: Too many requests for team abc. See https://console.x.ai/team/default/rate-limits.";
        let team_wire = format!("API error (status 429 Too Many Requests): {team}");
        assert_eq!(
            format_rate_limited_user_message(Some(&team_wire), true),
            team
        );
        assert_eq!(
            format_rate_limited_user_message(Some("slow down"), false),
            "slow down"
        );
    }

    /// The provider's consumer-subscription pitch is suppressed for EVERY auth mode.
    ///
    /// This used to assert the opposite for `is_api_key_auth = false` ("OAuth keeps the IC body"),
    /// which made the default user — `AppView::is_api_key_auth` starts `false` — the one person who
    /// still saw the competitor's upsell on a 429.
    #[test]
    fn format_rate_limited_rewrites_consumer_subscription_upsell_for_every_auth_mode() {
        let body = "Some resource has been exhausted: You are sending requests too quickly. \
             Please slow down, or upgrade to a Fuigo subscription for higher limits: \
             https://grok.com/supergrok";
        let wire = format!("API error (status 429 Too Many Requests): {body}");
        assert_eq!(
            format_rate_limited_user_message(Some(&wire), false),
            RATE_LIMITED_USER_MESSAGE_OAUTH
        );
        assert_eq!(
            format_rate_limited_user_message(Some(&wire), true),
            RATE_LIMITED_USER_MESSAGE_API_KEY
        );
        for is_api_key_auth in [false, true] {
            let shown = format_rate_limited_user_message(Some(&wire), is_api_key_auth);
            assert!(!shown.to_ascii_lowercase().contains("supergrok"), "{shown}");
            assert!(!shown.contains("grok.com"), "{shown}");
            assert!(shown.contains("rate limit"), "{shown}");
        }
    }

    /// The needle the mechanical rebrand (`b5e43b9`) mangled: the provider sends its own plan name,
    /// never "Fuigo", so matching only the rebranded spelling left the live wording undetected.
    #[test]
    fn format_rate_limited_rewrites_the_providers_own_upsell_wording() {
        let body = "You are sending requests too quickly. Please slow down, or \
             upgrade to a SuperGrok subscription for higher limits.";
        let wire = format!("API error (status 429 Too Many Requests): {body}");
        assert_eq!(
            format_rate_limited_user_message(Some(&wire), false),
            RATE_LIMITED_USER_MESSAGE_OAUTH
        );
        assert_eq!(
            format_rate_limited_user_message(Some(&wire), true),
            RATE_LIMITED_USER_MESSAGE_API_KEY
        );
    }

    #[test]
    fn format_rate_limited_strips_api_error_display_prefix() {
        let body = "The service is temporarily at capacity.";
        let wire = format!("API error (status 429 Too Many Requests): {body}");
        assert_eq!(format_rate_limited_user_message(Some(&wire), false), body);
        assert!(!format_rate_limited_user_message(Some(&wire), false).contains("API error"));
    }

    #[test]
    fn is_free_usage_exhausted_error_sniffs_well_known_code() {
        assert!(is_free_usage_exhausted_error(
            "subscription:free-usage-exhausted: You have used all your free usage."
        ));
        assert!(is_free_usage_exhausted_error(
            "API error (status 429): subscription:free-usage-exhausted quota hit"
        ));
        assert!(!is_free_usage_exhausted_error("throttled"));
        assert!(!is_free_usage_exhausted_error(
            "The service is temporarily at capacity."
        ));
    }

    #[test]
    fn format_rate_limited_free_usage_uses_paywall_copy() {
        let wire = "API error (status 429 Too Many Requests): \
            subscription:free-usage-exhausted: You have used all your free usage.";
        assert_eq!(
            format_rate_limited_user_message(Some(wire), false),
            FREE_USAGE_USER_MESSAGE
        );
        // Free-usage code is consumer-only; still wins for API-key callers.
        assert_eq!(
            format_rate_limited_user_message(Some(wire), true),
            FREE_USAGE_USER_MESSAGE
        );
    }

    #[test]
    fn format_rate_limited_empty_detail_uses_auth_aware_fallback() {
        assert_eq!(
            format_rate_limited_user_message(None, false),
            RATE_LIMITED_USER_MESSAGE_OAUTH
        );
        assert_eq!(
            format_rate_limited_user_message(Some(""), false),
            RATE_LIMITED_USER_MESSAGE_OAUTH
        );
        assert_eq!(
            format_rate_limited_user_message(None, true),
            RATE_LIMITED_USER_MESSAGE_API_KEY
        );
        assert_eq!(
            format_rate_limited_user_message(Some("   "), true),
            RATE_LIMITED_USER_MESSAGE_API_KEY
        );
    }

    #[test]
    fn overload_maps_to_display_message_with_typed_data() {
        let err = SamplingError::StreamError {
            error_type: "overloaded_error".into(),
            message: "Overloaded".into(),
            code: None,
        };
        let acp_err = map_sampling_err_to_acp(err);
        assert_eq!(acp_err.code, acp::ErrorCode::InternalError);
        assert_eq!(acp_err.message, OVERLOADED_USER_MESSAGE);
        // The same copy rides `data.message`, with the typed kind every terminal error carries
        let data = acp_err.data.clone().expect("typed data");
        assert_eq!(data["message"], OVERLOADED_USER_MESSAGE);
        assert_eq!(data["error_kind"], "api");
        assert_eq!(acp_error_text(&acp_err), OVERLOADED_USER_MESSAGE);

        let err_529 = SamplingError::Api {
            status: StatusCode::from_u16(529).expect("valid status"),
            message: "capacity".into(),
            model_metadata: None,
            retry_after_secs: None,
            should_retry: None,
            error_code: None,
        };
        let acp_529 = map_sampling_err_to_acp(err_529);
        assert_eq!(acp_529.message, OVERLOADED_USER_MESSAGE);
        let data_529 = acp_529.data.clone().expect("typed data");
        assert_eq!(data_529["message"], OVERLOADED_USER_MESSAGE);
        // The capacity status stays readable for the classifier that folds 503/529 into rate-limit copy
        assert_eq!(data_529["http_status"], 529);
        assert!(
            error_kind_str_from_error(&acp_529).is_some(),
            "every terminal error carries a kind: {acp_529:?}"
        );
    }

    #[test]
    fn rate_limit_error_uses_dedicated_code() {
        let err = SamplingError::Api {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: "Rate limit exceeded".into(),
            model_metadata: None,
            retry_after_secs: None,
            should_retry: None,
            error_code: None,
        };
        let acp_err = map_sampling_err_to_acp(err);
        assert_eq!(acp_err.code, acp::ErrorCode::from(RATE_LIMITED_ERROR_CODE));
        assert_eq!(acp_err.message, "Rate limited");
        assert_eq!(
            acp_err.data,
            Some(serde_json::json!({
                "message": "Rate limit exceeded",
                "error_kind": "rate_limited",
            }))
        );
    }

    #[test]
    fn rate_limit_mapping_is_stable_with_retry_after() {
        let err = SamplingError::Api {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: "Rate limit exceeded".into(),
            model_metadata: None,
            retry_after_secs: Some(60),
            should_retry: None,
            error_code: None,
        };
        assert_eq!(err.retry_after(), Some(60));
        let acp_err = map_sampling_err_to_acp(err);
        assert_eq!(acp_err.code, acp::ErrorCode::from(RATE_LIMITED_ERROR_CODE));
        assert_eq!(acp_err.message, "Rate limited");
    }

    #[test]
    fn rate_limit_code_differs_from_internal_error() {
        let rate_err = SamplingError::Api {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: "limited".into(),
            model_metadata: None,
            retry_after_secs: None,
            should_retry: None,
            error_code: None,
        };
        let server_err = SamplingError::Api {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "oops".into(),
            model_metadata: None,
            retry_after_secs: None,
            should_retry: None,
            error_code: None,
        };
        let rate_acp = map_sampling_err_to_acp(rate_err);
        let server_acp = map_sampling_err_to_acp(server_err);

        assert_eq!(rate_acp.code, acp::ErrorCode::from(RATE_LIMITED_ERROR_CODE));
        assert_ne!(rate_acp.code, server_acp.code);
        assert_eq!(server_acp.code, acp::Error::internal_error().code);
    }

    #[test]
    fn service_unavailable_retains_http_status_for_classification() {
        let err = SamplingError::Api {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "at capacity".into(),
            model_metadata: None,
            retry_after_secs: None,
            should_retry: None,
            error_code: None,
        };
        let acp_err = map_sampling_err_to_acp(err);
        assert_eq!(acp_err.code, acp::Error::internal_error().code);
        assert_eq!(http_status_from_error(&acp_err), Some(503));
    }

    #[test]
    fn auth_errors_map_to_auth_required() {
        let err = SamplingError::Api {
            status: StatusCode::UNAUTHORIZED,
            message: "bad token".into(),
            model_metadata: None,
            retry_after_secs: None,
            should_retry: None,
            error_code: None,
        };
        let acp_err = map_sampling_err_to_acp(err);
        assert_eq!(acp_err.code, acp::Error::auth_required().code);
    }

    /// Regression test: 403 Forbidden must not map to auth_required.
    /// The cli-chat-proxy returns 403 for policy denials unrelated to the caller's credentials.
    /// Examples: content-safety blocks like SAFETY_CHECK_TYPE_DATA_LEAKAGE, ZDR-gated operations, remote settings blocks.
    /// Mapping these to auth_required makes the desktop app tear down the session and start silent re-auth on -32000.
    /// That can race with invalid_grant_threshold to wipe auth.json.
    #[test]
    fn forbidden_does_not_map_to_auth_required() {
        let err = SamplingError::Api {
            status: StatusCode::FORBIDDEN,
            message:
                "Content violates usage guidelines. Failed check: SAFETY_CHECK_TYPE_DATA_LEAKAGE"
                    .into(),
            model_metadata: None,
            retry_after_secs: None,
            should_retry: None,
            error_code: None,
        };
        let acp_err = map_sampling_err_to_acp(err);
        assert_ne!(
            acp_err.code,
            acp::Error::auth_required().code,
            "403 Forbidden must not be surfaced as auth_required"
        );
        assert_eq!(
            acp_err.data,
            Some(serde_json::json!({
                "message": "Content violates usage guidelines. Failed check: SAFETY_CHECK_TYPE_DATA_LEAKAGE",
                "error_kind": "api",
            }))
        );
    }

    /// Helper: run a closure with FUIGO_API_KEY temporarily set (or cleared).
    /// Cleans up even if the closure panics.
    fn with_api_key_env<F: FnOnce()>(key: Option<&str>, f: F) {
        let prev = std::env::var("FUIGO_API_KEY").ok();
        let prev_legacy = std::env::var("FUIGO_CODE_API_KEY").ok();
        // SAFETY: serial_test ensures no concurrent env mutation.
        unsafe {
            std::env::remove_var("FUIGO_API_KEY");
            std::env::remove_var("FUIGO_CODE_API_KEY");
            if let Some(k) = key {
                std::env::set_var("FUIGO_API_KEY", k);
            }
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        // Restore original state.
        unsafe {
            std::env::remove_var("FUIGO_API_KEY");
            std::env::remove_var("FUIGO_CODE_API_KEY");
            if let Some(v) = prev {
                std::env::set_var("FUIGO_API_KEY", v);
            }
            if let Some(v) = prev_legacy {
                std::env::set_var("FUIGO_CODE_API_KEY", v);
            }
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    #[test]
    #[serial_test::serial]
    fn forbidden_subscription_error_includes_api_key_hint_when_env_set() {
        with_api_key_env(Some("fuigo-test"), || {
            let err = SamplingError::Api {
                status: StatusCode::FORBIDDEN,
                message: "The model 'fuigo-build' requires a Fuigo subscription.".into(),
                model_metadata: None,
                retry_after_secs: None,
                should_retry: None,
                error_code: None,
            };
            let acp_err = map_sampling_err_to_acp(err);
            let data = acp_err.data.unwrap();
            let msg = error_detail_from_data(&data).expect("data.message");
            assert!(
                msg.contains("fuigo logout"),
                "should suggest fuigo logout when API key is available: {msg}"
            );
            assert!(
                msg.contains("/logout"),
                "should mention /logout TUI command: {msg}"
            );
        });
    }

    #[test]
    #[serial_test::serial]
    fn forbidden_subscription_error_no_hint_without_api_key() {
        with_api_key_env(None, || {
            let err = SamplingError::Api {
                status: StatusCode::FORBIDDEN,
                message: "The model 'fuigo-build' requires a Fuigo subscription.".into(),
                model_metadata: None,
                retry_after_secs: None,
                should_retry: None,
                error_code: None,
            };
            let acp_err = map_sampling_err_to_acp(err);
            let data = acp_err.data.unwrap();
            let msg = error_detail_from_data(&data).expect("data.message");
            assert!(
                !msg.contains("fuigo logout"),
                "should NOT suggest logout when no API key is available: {msg}"
            );
        });
    }

    #[test]
    #[serial_test::serial]
    fn forbidden_non_subscription_error_no_hint() {
        with_api_key_env(Some("fuigo-test"), || {
            let err = SamplingError::Api {
                status: StatusCode::FORBIDDEN,
                message: "Content violates usage guidelines.".into(),
                model_metadata: None,
                retry_after_secs: None,
                should_retry: None,
                error_code: None,
            };
            let acp_err = map_sampling_err_to_acp(err);
            let data = acp_err.data.unwrap();
            let msg = error_detail_from_data(&data).expect("data.message");
            assert!(
                !msg.contains("fuigo logout"),
                "should NOT suggest logout for non-subscription 403: {msg}"
            );
        });
    }

    #[test]
    fn prompt_complete_fields_ok_passes_through_stop_reason() {
        let result: std::result::Result<acp::StopReason, acp::Error> = Ok(acp::StopReason::EndTurn);
        let (stop, agent_result, error_kind) = prompt_complete_fields(&result);
        assert_eq!(stop, serde_json::json!("end_turn"));
        assert_eq!(agent_result, serde_json::Value::Null);
        assert_eq!(error_kind, None);
    }

    #[test]
    fn prompt_complete_fields_rate_limit_omits_detail() {
        let err = acp::Error::new(RATE_LIMITED_ERROR_CODE, "Rate limited".to_string())
            .data("Rate limit exceeded");
        let result = Err(err);
        let (stop, agent_result, error_kind) = prompt_complete_fields(&result);
        assert_eq!(stop, serde_json::json!("rate_limit"));
        assert_eq!(agent_result, serde_json::Value::Null);
        assert_eq!(error_kind, None);
    }

    #[test]
    fn prompt_complete_fields_generic_error_includes_detail() {
        let err = acp::Error::internal_error().data("connection reset");
        let result = Err(err);
        let (stop, agent_result, error_kind) = prompt_complete_fields(&result);
        assert_eq!(stop, serde_json::json!("error"));
        assert_eq!(
            agent_result,
            serde_json::Value::String("connection reset".into())
        );
        assert_eq!(
            error_kind, None,
            "errors without a kind marker carry no errorKind"
        );
    }

    #[test]
    fn prompt_complete_fields_error_without_data_falls_back_to_message() {
        let err = acp::Error::new(-32000, "something broke".to_string());
        assert!(err.data.is_none());
        let result = Err(err);
        let (stop, agent_result, error_kind) = prompt_complete_fields(&result);
        assert_eq!(stop, serde_json::json!("error"));
        assert_eq!(
            agent_result,
            serde_json::Value::String("something broke".into())
        );
        assert_eq!(error_kind, None);
    }

    #[test]
    fn error_kind_from_error_reads_typed_marker_only() {
        let truncation = map_sampling_err_to_acp(SamplingError::MaxTokensTruncation);
        assert_eq!(
            error_kind_from_error(&truncation),
            Some(SamplingErrorKind::MaxTokensTruncation)
        );
        // No data, string data, and object data without the marker all yield None.
        assert_eq!(error_kind_from_error(&acp::Error::internal_error()), None);
        assert_eq!(
            error_kind_from_error(&acp::Error::internal_error().data("boom")),
            None
        );
        let with_status = acp::Error::internal_error()
            .data(error_data_with_status("bad gateway".into(), Some(502)));
        assert_eq!(error_kind_from_error(&with_status), None);
    }

    #[test]
    fn http_status_from_error_extracts_status() {
        let err = acp::Error::internal_error()
            .data(error_data_with_status("bad token".into(), Some(401)));
        assert_eq!(http_status_from_error(&err), Some(401));
    }

    /// The typed max-tokens kind round-trips through `acp::Error.data` to the uploaded stop_reason.
    #[test]
    fn stop_reason_for_turn_error_distinguishes_max_tokens() {
        let err = map_sampling_err_to_acp(SamplingError::MaxTokensTruncation);
        assert_eq!(stop_reason_for_turn_error(&err), "MaxTokens");
        assert_eq!(
            stop_reason_for_turn_error(&acp::Error::internal_error()),
            "Error"
        );
    }

    /// Captures formatted log output for the `log_turn_error` tests.
    #[derive(Clone, Default)]
    struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for LogCapture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("capture lock").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
        type Writer = LogCapture;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }
    impl LogCapture {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().expect("capture lock").clone())
                .expect("utf8 log output")
        }
    }

    fn log_two_failed_turns() {
        log_turn_error(&acp::Error::internal_error().data(terminal_error_data(
            "empty response from model (reasoning_only)".into(),
            None,
            SamplingErrorKind::EmptyResponse,
        )));
        log_turn_error(&acp::Error::internal_error().data(terminal_error_data(
            "401 Unauthorized\n\nYou are using a deprecated authentication method".into(),
            Some(401),
            SamplingErrorKind::Auth,
        )));
    }

    /// The failed-turn record stores the human text itself (Display), not a Debug-quoted copy.
    /// A JSON log layer keeps whatever the field formats to, so Debug put literal quotes and backslashes inside the value.
    /// Newlines are escaped explicitly, so each record is still one line in the plain and the JSON formatter.
    #[test]
    fn log_turn_error_records_display_text_with_escaped_newlines() {
        let plain = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::ERROR)
            .with_writer(plain.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, log_two_failed_turns);
        let out = plain.text();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "one line per failed turn, got:\n{out}");
        assert!(
            lines[0].contains("error=Internal error: empty response from model (reasoning_only) "),
            "{}",
            lines[0]
        );
        assert!(
            lines[1].contains(
                r"error=Internal error: 401 Unauthorized\n\nYou are using a deprecated authentication method "
            ),
            "{}",
            lines[1]
        );

        let json = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::ERROR)
            .with_writer(json.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, log_two_failed_turns);
        let out = json.text();
        let records: Vec<serde_json::Value> = out
            .lines()
            .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}")))
            .collect();
        assert_eq!(
            records.len(),
            2,
            "one JSON record per failed turn, got:\n{out}"
        );
        assert_eq!(
            records[0]["fields"]["error"],
            "Internal error: empty response from model (reasoning_only)"
        );
        assert_eq!(records[0]["fields"]["error_kind"], "empty_response");
        assert_eq!(
            records[1]["fields"]["error"],
            r"Internal error: 401 Unauthorized\n\nYou are using a deprecated authentication method"
        );
    }

    /// A message that is already the user-facing sentence is not repeated after itself.
    #[test]
    fn acp_error_text_says_a_repeated_message_once() {
        let err = acp::Error::new(
            acp::ErrorCode::InternalError.into(),
            OVERLOADED_USER_MESSAGE,
        )
        .data(terminal_error_data(
            OVERLOADED_USER_MESSAGE.to_string(),
            None,
            SamplingErrorKind::Api,
        ));
        assert_eq!(acp_error_text(&err), OVERLOADED_USER_MESSAGE);
        // A distinct detail still reads "<class>: <detail>"
        let distinct = acp::Error::internal_error().data(terminal_error_data(
            "boom".into(),
            None,
            SamplingErrorKind::Api,
        ));
        assert_eq!(acp_error_text(&distinct), "Internal error: boom");
    }

    /// A cancelled request is not an auth rejection: JSON-RPC `-32800` (request cancelled), never `-32000`, with `error_kind: cancelled`.
    #[test]
    fn cancelled_sampling_error_maps_to_request_cancelled_not_auth_required() {
        let err = map_sampling_err_to_acp(fuigo_sampler::events::request_cancelled_error());
        assert_eq!(i32::from(err.code), -32800, "{err:?}");
        assert_eq!(error_kind_str_from_error(&err), Some("cancelled"));
        assert_eq!(acp_error_message(&err), "request cancelled");
    }

    /// Cancellation is never inferred from text: an auth rejection whose body reads "request cancelled" stays `auth` / `-32000`.
    #[test]
    fn auth_error_saying_request_cancelled_stays_auth() {
        let err = map_sampling_err_to_acp(SamplingError::auth_unknown("request cancelled"));
        assert_eq!(i32::from(err.code), -32000, "{err:?}");
        assert_eq!(error_kind_str_from_error(&err), Some("auth"));
    }

    #[test]
    fn prompt_complete_fields_extracts_message_from_status_data() {
        let err = acp::Error::internal_error()
            .data(error_data_with_status("model not found".into(), Some(404)));
        let result = Err(err);
        let (stop, agent_result, error_kind) = prompt_complete_fields(&result);
        assert_eq!(stop, serde_json::json!("error"));
        assert_eq!(
            agent_result,
            serde_json::Value::String("model not found".into())
        );
        assert_eq!(error_kind, None);
    }
}

#[cfg(test)]
#[path = "error_data_guard_tests.rs"]
mod error_data_guard_tests;
