//! HTTP client for the Ferrox Labs sampling APIs.
//!
//! Owns the `reqwest::Client`, default request headers, and per-method defaults.
//! Talks to three backend shapes:
//!
//! * Chat Completions (`/chat/completions`)
//! * Responses API (`/responses`)
//! * Anthropic Messages API (`/messages`)
//!
//! All trace-upload and URL-based header injection is intentionally *not* here.
//! The session puts per-request headers (proxy auth, OTel context, etc.) into [`SamplerConfig::extra_headers`] before constructing the client.

use eventsource_stream::Eventsource;
use futures_util::StreamExt;
use futures_util::stream::BoxStream;
use indexmap::IndexMap;
use reqwest::header::{
    ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, USER_AGENT,
};
use serde::Serialize;

use fuigo_sampling_types::error::{
    parse_error_code, try_parse_stream_error, user_facing_api_error_message,
};
use fuigo_sampling_types::serde_helpers::parse_sse_event;
use fuigo_sampling_types::{
    ChatCompletionChunk, ChatCompletionRequest, ChatCompletionResponse, ConversationRequest,
    ConversationResponse, CreateResponseWrapper, DEFAULT_EXACT_REPETITION_MIN_TOKENS,
    DOOM_LOOP_CHECK_HEADER, EXACT_REPETITION_CHECK_HEADER, MessagesRequestWrapper,
    ResponseModelMetadata, Result, SamplingError, SentCredential, build_messages_request,
    is_check_event, messages, rs,
};

use crate::config::{AuthScheme, OriginClientInfo, SamplerConfig};
use crate::events::SamplingErrorInfo;
use fuigo_auth::BearerFingerprint;
use fuigo_extra_ca::fluxrouter::IdentityDisclosure;

pub use fuigo_sampling_types::ApiBackend;

/// Process-level fallback for the `x-fuigo-client-identifier` header.
const DEFAULT_CLIENT_IDENTIFIER: &str = "fuigo-shell";

/// Product identifier baked into User-Agent strings.
const AGENT_PRODUCT: &str = "fuigo-shell";
/// Header the Anthropic Messages API requires on every request.
///
/// Choosing `api_backend = "messages"` chooses this header with it: the wire
/// protocol is not selectable separately from its own preconditions.
/// `key_discovery`'s `anthropic` entry writes the same pair into a
/// `/provider`-generated config; this constant is what a HAND-WRITTEN
/// `[model_providers.x] api_backend = "messages"` gets, which previously got
/// nothing and produced a request Anthropic rejects.
pub const ANTHROPIC_VERSION_HEADER: &str = "anthropic-version";

/// Value sent for [`ANTHROPIC_VERSION_HEADER`] when the config names none.
/// `2023-06-01` is the only Messages API version Anthropic has published; a
/// config that needs another one sets `extra_headers` and wins over this.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// `max_tokens` for a Messages request that carries none and whose config sets
/// no `max_completion_tokens` at any layer.
///
/// This is a FLOOR, not a target. `max_tokens` is a hard per-model ceiling on
/// api.anthropic.com, and Fuigo cannot know which model a BYOK `[model.<id>]`
/// names: the built-in catalogue (`fuigo-models/default_models.json`) carries
/// no `messages`-backend model at all, and the remote catalogue that supplies
/// `max_completion_tokens` (`extract_model_metadata`) speaks only for the
/// configured endpoint, not for a third-party host. So the default has to be a
/// value every model the backend can reach accepts.
///
/// 32_000 is the smallest published `max_output_tokens` across Anthropic's
/// non-retired models as of 2026-09 (Claude Opus 4 / 4.1 = 32K; Sonnet 4 / 4.5,
/// Opus 4.5, Haiku 4.5 = 64K; the Opus 4.6+, Sonnet 4.6+ and Fable 5 families =
/// 128K). The previous value, 128_000, is the CURRENT family's ceiling and was
/// inherited from upstream, where the Messages shape pointed at a route
/// upstream controlled; against api.anthropic.com it 400s on every older model,
/// and the `/provider` flow that writes the config had no key to fix it with.
///
/// Direction of failure decides the number: too small truncates one response,
/// which the caller sees as a `Length` stop and can raise; too large rejects
/// every turn with no in-product remedy. Three layers raise it —
/// `[model.<id>].max_completion_tokens`, `[model_providers.<id>].max_completion_tokens`
/// (which `/provider` now writes), and the global `[models].max_completion_tokens`.
///
/// Deliberately NOT derived from `context_window`: an output cap and a context
/// window are different quantities, and conflating them is the bug a separate
/// packet exists to remove. `ClientDefaults` holds no context window, so this
/// function structurally cannot read one.
const ANTHROPIC_DEFAULT_MAX_TOKENS: u32 = 32_000;

/// Per-request correlation header: the conversation id.
pub(crate) const H_CONV_ID: &str = "x-fuigo-conv-id";
/// Per-request correlation header: the request id.
pub(crate) const H_REQ_ID: &str = "x-fuigo-req-id";
/// Per-request correlation header: the session id.
pub(crate) const H_SESSION_ID: &str = "x-fuigo-session-id";
/// Per-request correlation header: the 0-based turn index within the session.
pub(crate) const H_TURN_IDX: &str = "x-fuigo-turn-idx";
/// Per-request correlation header: the turn-level resubmit attempt.
pub(crate) const H_TRANSIENT_RETRY: &str = "x-fuigo-transient-retry";
/// Per-request routing hint: a copy of the request body's `model` field.
pub(crate) const H_MODEL_OVERRIDE: &str = "x-fuigo-model-override";
/// Per-request IDENTITY header: a persisted machine id that survives logout.
pub(crate) const H_AGENT_ID: &str = "x-fuigo-agent-id";
/// IDENTITY header: the tenant deployment UUID.
pub(crate) const H_DEPLOYMENT_ID: &str = "x-fuigo-deployment-id";
/// IDENTITY header: the Ferrox account id.
pub(crate) const H_USER_ID: &str = "x-fuigo-user-id";
/// Client-level IDENTITY header: the Fuigo version, for version gating at the proxy.
pub(crate) const H_CLIENT_VERSION: &str = "x-fuigo-client-version";
/// Client-level IDENTITY header: which Ferrox client is calling.
pub(crate) const H_CLIENT_IDENTIFIER: &str = "x-fuigo-client-identifier";

/// The per-request `x-fuigo-*` names that go to **every** destination.
///
/// `cfg(test)` because the product reads the individual `H_*` consts directly; this array is
/// the enumeration that `per_request_namespace_splits_by_disclosure` asserts `apply` against,
/// so a header added to `apply` without being classified fails the test by name.
///
/// P15-R. Each is either a per-session random or a per-turn counter, or (in
/// [`H_MODEL_OVERRIDE`]'s case) a verbatim copy of a field already in the request body.
/// None of them identifies anybody across two destinations, so withholding them buys no
/// privacy — and all of them are load-bearing off the FluxRouter-operated route:
/// [`H_TRANSIENT_RETRY`] is how a self-hosted gateway tells a resubmit from a new turn when
/// it accounts for retry traffic, and the integration harness classifies foreground against
/// auxiliary calls on [`H_TURN_IDX`]/[`H_REQ_ID`] (`fuigo_test_support::inference_override`),
/// falling through to a body heuristic when they are absent rather than erroring.
///
/// [`H_MODEL_OVERRIDE`] is here on purpose and the reasoning is worth stating, because it is
/// the only member that is neither random nor a counter: its value is `payload.model`, which
/// `body()` serializes into the same request. Withholding the header could not hide the model
/// id from a destination that is already being told it, so the header discloses exactly
/// nothing extra — and its documented job (`session/commands.rs`, `OverrideModelName`) is to
/// carry an *opaque third-party routing name* alongside BYOK headers such as
/// `x-openrouter-api-key`. Gating it would break the one case it exists for.
#[cfg(test)]
const PER_REQUEST_UNGATED_HEADERS: [&str; 6] = [
    H_CONV_ID,
    H_REQ_ID,
    H_SESSION_ID,
    H_TURN_IDX,
    H_TRANSIENT_RETRY,
    H_MODEL_OVERRIDE,
];

/// The per-request `x-fuigo-*` names withheld from a destination that is not FluxRouter-operated.
///
/// `cfg(test)`, for the reason given on `PER_REQUEST_UNGATED_HEADERS`.
///
/// [`H_AGENT_ID`] is the one P15 was most right about: it is a persisted machine id that
/// survives logout, so it correlates a user across providers even when nobody is signed in.
#[cfg(test)]
const PER_REQUEST_IDENTITY_HEADERS: [&str; 3] = [H_AGENT_ID, H_DEPLOYMENT_ID, H_USER_ID];

/// The client-level `x-fuigo-*` names withheld from a destination that is not FluxRouter-operated, i.e.
/// exactly what [`apply_identity_headers`] writes, and what its M10 refusal log names.
const CLIENT_IDENTITY_HEADERS: [&str; 4] = [
    H_CLIENT_VERSION,
    H_DEPLOYMENT_ID,
    H_USER_ID,
    H_CLIENT_IDENTIFIER,
];

/// Per-request `x-fuigo-*` headers. Optional fields are skipped when empty/`None`.
struct FuigoRequestHeaders<'a> {
    conv_id: &'a str,
    req_id: &'a str,
    model_id: &'a str,
    session_id: &'a str,
    turn_idx: Option<&'a str>,
    /// Turn-level resubmit attempt; the proxy counts retry traffic by it.
    transient_retry: Option<&'a str>,
    agent_id: &'a str,
    deployment_id: Option<&'a str>,
    user_id: Option<&'a str>,
    /// Whether the destination may receive the identity half
    /// ([`fuigo_extra_ca::fluxrouter::IdentityDisclosure`], decided by the compiled
    /// FluxRouter-operated host check).
    ///
    /// A field rather than an argument on purpose: the compiler then forces every
    /// construction site to state the destination's trust, so a new call site cannot
    /// silently inherit "send everything". P15. A type rather than a `bool` since P30, so
    /// a user-configured-origin answer (`fuigo_shell_base::util::is_fuigo_api_bearer_url`,
    /// which decides credential delivery) cannot be passed here by mistake.
    identity: IdentityDisclosure,
}

impl FuigoRequestHeaders<'_> {
    /// Writes the per-request `x-fuigo-*` namespace, **split by what each header discloses**.
    ///
    /// `PER_REQUEST_UNGATED_HEADERS` go to every destination;
    /// `PER_REQUEST_IDENTITY_HEADERS` only to a FluxRouter-operated one. Those two arrays are the
    /// enumeration of this namespace and `per_request_namespace_splits_by_disclosure` pins
    /// this function against them, so a header added here must land in one list or the other
    /// and the test names which.
    ///
    /// P15 returned `builder` untouched for every other destination, withholding all
    /// nine. That was wrong in both directions. It over-withheld: five of the nine are
    /// per-session randoms or per-turn counters that identify nobody across destinations, so
    /// withholding them bought no privacy. And it broke two live behaviours —
    /// `x-fuigo-transient-retry` is retry accounting at every self-hosted gateway, and the
    /// integration harness routes scripted responses off `-turn-idx`/`-req-id`, silently
    /// misrouting them (not erroring) once they vanished. Every integration test points the
    /// sampler at loopback, which the gate correctly refuses, so the blanket return dropped
    /// the headers the harness correlates on. See `PER_REQUEST_UNGATED_HEADERS` for why
    /// `x-fuigo-model-override` is in the ungated half.
    fn apply(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        // Ungated: correlation and routing. No identity, and load-bearing everywhere.
        let mut b = builder
            .header(H_CONV_ID, self.conv_id)
            .header(H_REQ_ID, self.req_id)
            .header(H_SESSION_ID, self.session_id)
            .header(H_MODEL_OVERRIDE, self.model_id);
        if let Some(idx) = self.turn_idx {
            b = b.header(H_TURN_IDX, idx);
        }
        if let Some(attempt) = self.transient_retry {
            b = b.header(H_TRANSIENT_RETRY, attempt);
        }
        // Gated: identity. `agent_id` is a persisted machine id that survives logout,
        // `deployment_id` the tenant UUID, `user_id` the Ferrox account id — all three are
        // stable and identical across every provider a user configures, which is exactly
        // what makes them a cross-provider correlator.
        if !self.identity.is_permitted() {
            return b;
        }
        b = b.header(H_AGENT_ID, self.agent_id);
        if let Some(id) = self.deployment_id.filter(|s| !s.is_empty()) {
            b = b.header(H_DEPLOYMENT_ID, id);
        }
        if let Some(id) = self.user_id.filter(|s| !s.is_empty()) {
            b = b.header(H_USER_ID, id);
        }
        b
    }
}

/// Parse the `Retry-After` response header as delta-seconds.
/// Our inference backends only emit integer seconds (never HTTP-date), so we only handle that form.
/// HTTP-dates silently return `None` and the caller falls back to exponential backoff.
/// Capped at 120s to prevent absurdly long sleeps from a misbehaving upstream.
/// Deserialize a Responses API SSE event, with a fallback for Ferrox Labs-specific tool types (e.g., `x_search`) that `async_openai` can't parse.
/// The API echoes the request's `tools` array in `ResponseCreated` and `ResponseCompleted` events.
/// If we sent `{"type": "x_search"}`, `rs::Tool` deserialization fails, so we strip unrecognized tools from the raw JSON and retry.
/// `Ok(None)` means "a well-formed event whose `type` this client does not model": skip it.
fn deserialize_response_event(data: &str) -> Result<Option<rs::ResponseStreamEvent>> {
    // Programmatic-tool-calling items (`program`, `program_output`) have no typed variant; rewrite them into carriers first
    let transcoded = crate::stream::responses_ptc::transcode_sse(data);
    let data = transcoded.as_deref().unwrap_or(data);
    // An SSE event stream is forward-compatible: the server may introduce event types at any
    // time, and OpenAI now emits `keepalive` during long reasoning turns. An unknown `type` is
    // benign and MUST be skipped -- failing here aborts the entire turn, which selects precisely
    // for the longest turns, the ones most expensive to lose. `parse_sse_event` is the one place
    // that decision is made, shared with the Messages backend, and it still fails closed on a
    // MODELLED `type` whose body is malformed.
    let mut event = match parse_sse_event::<rs::ResponseStreamEvent>("responses", data) {
        Ok(Some(event)) => event,
        Ok(None) => return Ok(None),
        Err(first_err) => {
            // Try sanitizing: parse as Value, strip unknown tools, retry.
            if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(data) {
                // Strip tools that async_openai's rs::Tool can't deserialize (e.g., Ferrox Labs-specific "x_search")
                // Instead of maintaining a hardcoded allowlist, try deserializing each tool entry; if it fails, drop it
                if let Some(tools) = value
                    .pointer_mut("/response/tools")
                    .and_then(|v| v.as_array_mut())
                {
                    tools.retain(|t| serde_json::from_value::<rs::Tool>(t.clone()).is_ok());
                }
                if let Ok(mut event) = serde_json::from_value::<rs::ResponseStreamEvent>(value) {
                    apply_terminal_event_overrides(&mut event, data);
                    return Ok(Some(event));
                }
            }
            return Err(serde_failure("ResponseStreamEvent from stream", &first_err, data.len()));
        }
    };
    apply_terminal_event_overrides(&mut event, data);
    Ok(Some(event))
}

/// On `response.completed` / `response.incomplete`, rewrite `usage.total_tokens` to the live context length from `context_details`.
/// `total_tokens` drives the CLI's `/context` bar, the auto-compact threshold, and `meta.totalTokens` on persisted sessions.
/// Under server-side loops (`web_search`, `x_search`) the cumulative total inflates; `context_details` holds the final turn's real context.
/// Billing fields stay on the cumulative wire values, so telemetry is unaffected.
fn apply_terminal_event_overrides(event: &mut rs::ResponseStreamEvent, data: &str) {
    let response = match event {
        rs::ResponseStreamEvent::ResponseCompleted(e) => &mut e.response,
        rs::ResponseStreamEvent::ResponseIncomplete(e) => &mut e.response,
        _ => return,
    };
    // Re-parse for fields async_openai's types omit (context total, cost ticks).
    let Ok(value) = serde_json::from_str::<serde_json::Value>(data) else {
        return;
    };
    // Stash cost ticks in metadata for stream_responses.
    if let Some(ticks) = fuigo_sampling_types::reported_cost_ticks(
        value
            .pointer("/response/usage/cost_in_usd_ticks")
            .and_then(|v| v.as_i64()),
    ) {
        response
            .metadata
            .get_or_insert_with(Default::default)
            .insert(COST_USD_TICKS_METADATA_KEY.to_owned(), ticks.to_string());
    }
    let Some(usage) = response.usage.as_mut() else {
        return;
    };
    let Some(total) = extract_context_total(&value) else {
        return;
    };
    usage.total_tokens = total;
}

/// Metadata key that carries cost ticks through the typed Response events, which have no field for them.
pub(crate) const COST_USD_TICKS_METADATA_KEY: &str = "fuigo.cost_usd_ticks";

/// Read `response.usage.context_details.{input_tokens, output_tokens}` from the parsed terminal-event JSON and return their sum.
/// Returns `None` if either field is missing or out of `u32` range.
fn extract_context_total(value: &serde_json::Value) -> Option<u32> {
    let cd = value.pointer("/response/usage/context_details")?;
    let i = u32::try_from(cd.get("input_tokens")?.as_u64()?).ok()?;
    let o = u32::try_from(cd.get("output_tokens")?.as_u64()?).ok()?;
    Some(i.saturating_add(o))
}

/// Record `success=false` and `error` on the active inference span when a stream request fails before any response (transport/connect/TLS errors).
/// Otherwise the `#[instrument]` span closes with both fields Empty, an outage shows zero `success=false`, and error-rate alerts never fire.
fn record_stream_request_failure(err: &reqwest::Error) {
    let span = tracing::Span::current();
    span.record("success", false);
    span.record("error", transport_error_for_log(err).as_str());
}

/// A parser error as category and position only (P70a): `Data error at line 1 column 347`. serde's own text quotes
/// the offending value out of the body it was parsing, so neither the log line nor the returned error may carry it.
/// An error serde raised without a position (the body of an internally tagged enum is parsed from a buffered copy)
/// is the category alone: `Data error`.
fn serde_error_summary(error: &serde_json::Error) -> String {
    if error.line() == 0 {
        return format!("{:?} error", error.classify());
    }
    format!("{:?} error at line {} column {}", error.classify(), error.line(), error.column())
}

/// A response body or stream chunk that failed to deserialize (P70a): logged as its length and the parser error's
/// category and position, never the body or serde's own message, and returned as a `Serialization` error holding
/// the same summary. The variant is unchanged, so the error is handled exactly as before; only its text differs.
fn serde_failure(what: &str, error: &serde_json::Error, body_len: usize) -> SamplingError {
    let message = serde_error_summary(error);
    tracing::error!(error = %message, body_len, "Failed to deserialize {what}");
    SamplingError::Serialization(<serde_json::Error as serde::de::Error>::custom(message))
}

/// `error`'s text for a log line or span field (P70a): reqwest prints the request URL in its `Display`, and a base
/// URL or a configured query parameter may carry a key. Only the logged text is redacted; the error value that is
/// returned to the caller is left as it is.
fn transport_error_for_log(error: &reqwest::Error) -> String {
    request_url_redacted(error.to_string(), error)
}

/// `text` (which embeds `error`'s rendering) with the request URL redacted. The URL is the one the error itself
/// reports, replaced as an exact string, so no guess about where a URL ends in running text is involved; text from
/// an error that reports no URL is scanned for URLs instead.
fn request_url_redacted(text: String, error: &reqwest::Error) -> String {
    match error.url() {
        Some(url) => text.replace(url.as_str(), &fuigo_auth::redact_url(url.as_str())),
        None => fuigo_auth::redact_urls_in_text(&text),
    }
}

/// A dispatch failure's text for the debug log (P70a): see [`transport_error_for_log`].
fn dispatch_error_for_log(error: &fuigo_extra_ca::dispatch::DispatchError) -> String {
    let text = error.to_string();
    match error {
        fuigo_extra_ca::dispatch::DispatchError::Transport(transport) => request_url_redacted(text, transport),
        fuigo_extra_ca::dispatch::DispatchError::Denied(_) => fuigo_auth::redact_urls_in_text(&text),
    }
}

/// Local egress denial is configuration policy, not a retryable network outage.
fn dispatch_error(
    error: fuigo_extra_ca::dispatch::DispatchError,
    streaming: bool,
) -> SamplingError {
    tracing::debug!("HTTP dispatch failed: {}", dispatch_error_for_log(&error));
    match error {
        fuigo_extra_ca::dispatch::DispatchError::Denied(reason) => {
            SamplingError::InvalidConfiguration(reason)
        }
        fuigo_extra_ca::dispatch::DispatchError::Transport(error) => {
            if streaming {
                record_stream_request_failure(&error);
            }
            SamplingError::Http(error)
        }
    }
}

/// Splice the raw-JSON hosted-tool entries for `web_search` and `x_search` into a serialized Responses request body's `tools` array.
/// `x_search` has no `rs::Tool` variant, and `web_search`'s typed filters cannot carry `excluded_domains`, so both travel as raw JSON.
/// Neither may also be emitted as a typed `rs::Tool`; the API rejects the duplicate.
/// Shared by the streaming (`create_response_stream`) and non-streaming (`create_response`) paths so neither can silently drop these tools.
fn splice_extra_tool_entries(
    request_body: &mut serde_json::Value,
    entries: Vec<serde_json::Value>,
) {
    if entries.is_empty() {
        return;
    }
    if let Some(tools) = request_body.get_mut("tools").and_then(|v| v.as_array_mut()) {
        tools.extend(entries);
    } else {
        request_body["tools"] = serde_json::Value::Array(entries);
    }
}

/// Whole seconds to back off for, from the backoff headers a response may carry.
///
/// `Retry-After` (integer seconds) is the standard spelling, is defined for any
/// status, and wins when it parses.
///
/// The two fallbacks are scoped to `status`, not applied everywhere. OpenAI/Azure
/// tokens-per-minute 429s commonly send no usable `Retry-After` at all and answer
/// with `retry-after-ms` or `x-ratelimit-reset-tokens` instead; without those the
/// sampling envelope carries `retry_after_secs: None`, which is the one signal the
/// compaction classifier reads to tell "capacity is coming back" from "this payload
/// is too big". But `x-ratelimit-reset-tokens` is a token-bucket refill time that
/// those providers attach to essentially EVERY response, 5xx included: honouring it
/// on an unrelated 502 or 529 would turn a ~2s first backoff into the 30s
/// `MAX_RETRY_BACKOFF` (`retry::retry_after_or_backoff`) for no reason. So both
/// fallbacks apply only where they mean what they say: 429, and the 408 the retry
/// loop treats the same way.
///
/// A zero-valued fallback is dropped rather than honoured. Both headers report a
/// bucket refill time that providers attach per bucket, so an RPM-triggered 429
/// routinely reads `x-ratelimit-reset-tokens: 0s` while the limit that actually
/// fired is elsewhere; `Some(0)` there would mean "retry immediately" and hot-loop
/// against a provider that just rate-limited us. `None` instead falls through to
/// the retry ladder's own backoff.
///
/// Capped at 120s, the same cap the standard header gets.
pub(crate) fn extract_retry_after(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> Option<u64> {
    let header = |name: &'static str| {
        headers
            .get(reqwest::header::HeaderName::from_static(name))
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
    };
    let rate_limited = status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status == reqwest::StatusCode::REQUEST_TIMEOUT;
    let seconds = header("retry-after")
        .and_then(|s| s.parse::<u64>().ok())
        // `retry-after-ms` is a bare count of milliseconds, never a duration string.
        .or_else(|| {
            rate_limited
                .then(|| {
                    header("retry-after-ms")
                        .and_then(|s| s.parse::<f64>().ok())
                        .filter(|ms| ms.is_finite() && *ms >= 0.0)
                        .map(millis_to_whole_seconds)
                        .filter(|secs| *secs > 0)
                })
                .flatten()
        })
        // `x-ratelimit-reset-tokens` is a Go-style duration ("1s", "88ms", "6m0s").
        .or_else(|| {
            rate_limited
                .then(|| {
                    header("x-ratelimit-reset-tokens")
                        .and_then(parse_reset_duration_millis)
                        .map(millis_to_whole_seconds)
                        .filter(|secs| *secs > 0)
                })
                .flatten()
        })?;
    Some(seconds.min(120))
}

/// Round a backoff up to whole seconds, so a sub-second wait still waits.
/// Truncating 500ms to 0 would turn a promised backoff into a hot retry.
fn millis_to_whole_seconds(millis: f64) -> u64 {
    (millis / 1000.0).ceil().max(0.0) as u64
}

/// Parse an `x-ratelimit-reset-*` value into milliseconds.
///
/// Accepts Go-style duration strings with concatenated units — `88ms`, `1s`,
/// `1.5s`, `6m0s`, `1h2m3s` — which is what OpenAI and Azure send, plus a bare
/// number, which those headers also emit and which means seconds. Returns
/// `None` for anything it does not fully understand, including negatives and
/// unknown units, so an unparsed value stays "no backoff signal" rather than
/// becoming a wrong one.
fn parse_reset_duration_millis(raw: &str) -> Option<f64> {
    let text = raw.trim();
    if text.is_empty() || text.starts_with('-') {
        return None;
    }
    let mut rest = text;
    let mut total_ms = 0.0f64;
    let mut saw_component = false;
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(rest.len());
        if digits == 0 {
            return None;
        }
        let value: f64 = rest[..digits].parse().ok()?;
        if !value.is_finite() {
            return None;
        }
        rest = &rest[digits..];
        let unit_len = rest
            .find(|c: char| c.is_ascii_digit())
            .unwrap_or(rest.len());
        let (unit, remainder) = rest.split_at(unit_len);
        rest = remainder;
        let multiplier = match unit {
            "" | "s" => 1_000.0,
            "ms" => 1.0,
            "m" => 60_000.0,
            "h" => 3_600_000.0,
            _ => return None,
        };
        total_ms += value * multiplier;
        saw_component = true;
    }
    saw_component.then_some(total_ms)
}

pub(crate) fn extract_should_retry(headers: &reqwest::header::HeaderMap) -> Option<bool> {
    headers
        .get("x-should-retry")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            if s.eq_ignore_ascii_case("true") {
                Some(true)
            } else if s.eq_ignore_ascii_case("false") {
                Some(false)
            } else {
                None // unknown value, treat as absent
            }
        })
}

/// Per-model limits the upstream inference proxy reports on every completion response.
///
/// These are RESPONSE header names, i.e. the provider's spelling: the 1.0.1 mechanical rebrand
/// rewrote them to `x-fuigo-*`, names no provider sends, so the limits were silently never read.
/// FluxRouter sends neither spelling today; a proxy that does sends the `x-grok-*` ones.
const CONTEXT_WINDOW_HEADER: &str = "x-grok-context-window";
const MAX_COMPLETION_TOKENS_HEADER: &str = "x-grok-max-completion-tokens";

pub(crate) fn extract_model_metadata(headers: &reqwest::header::HeaderMap) -> Option<ResponseModelMetadata> {
    let context_window = headers
        .get(CONTEXT_WINDOW_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    let max_completion_tokens = headers
        .get(MAX_COMPLETION_TOKENS_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u32>().ok());

    let models_etag = headers
        .get("x-models-etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if context_window.is_some() || max_completion_tokens.is_some() || models_etag.is_some() {
        Some(ResponseModelMetadata {
            context_window,
            max_completion_tokens,
            models_etag,
        })
    } else {
        None
    }
}

/// Wrapper for streaming chat completion requests that adds `stream` and `stream_options` without modifying the original `ChatCompletionRequest`.
#[derive(Serialize)]
struct StreamingChatRequest<'a> {
    #[serde(flatten)]
    inner: &'a ChatCompletionRequest,
    stream: bool,
    stream_options: StreamOptions,
}

#[derive(Serialize)]
struct StreamOptions {
    include_usage: bool,
}

/// FluxRouter's request-body opt-out of its response cache, sent as `"cache": {"no-cache": true, "no-store": true}`.
/// FluxRouter answers byte-identical requests from an exact-match cache, which replayed one empty model reply to every retry of an agent turn.
/// Agent turns are never safely replayable, and a header (`Cache-Control`) does not bypass that cache; this body field does.
#[derive(Serialize)]
struct CacheBypass {
    #[serde(rename = "no-cache")]
    no_cache: bool,
    #[serde(rename = "no-store")]
    no_store: bool,
}

/// A request body as sent: the wire payload, plus [`CacheBypass`] under `cache` for FluxRouter only.
/// Strict providers reject the unknown field with a 400, so it is absent everywhere else.
#[derive(Serialize)]
struct RequestBody<'a, T: Serialize> {
    #[serde(flatten)]
    inner: &'a T,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache: Option<CacheBypass>,
}

fn append_response_includes(body: &mut serde_json::Value, extra_includes: &[String]) {
    if extra_includes.is_empty() {
        return;
    }
    let Some(body) = body.as_object_mut() else {
        return;
    };
    let include = body.entry("include").or_insert(serde_json::Value::Null);
    if include.is_null() {
        *include = serde_json::Value::Array(Vec::new());
    }
    let Some(include) = include.as_array_mut() else {
        return;
    };
    for value in extra_includes {
        if !include
            .iter()
            .any(|existing| existing.as_str() == Some(value.as_str()))
        {
            include.push(serde_json::Value::String(value.clone()));
        }
    }
}

/// Process-wide resolver for `env_http_headers` variable names (P08). The shell installs one that answers the
/// first-party key names (`FUIGO_API_KEY`, legacy) from the key an ACP client supplied in memory, so a header mapped
/// to them follows the same precedence as the rest of credential resolution. Unset, names resolve via `std::env::var`.
static ENV_HEADER_RESOLVER: std::sync::OnceLock<fn(&str) -> Option<String>> = std::sync::OnceLock::new();

/// Install the [`ENV_HEADER_RESOLVER`]. The first install wins; later calls are no-ops.
pub fn install_env_header_resolver(resolver: fn(&str) -> Option<String>) {
    let _ = ENV_HEADER_RESOLVER.set(resolver);
}

fn resolve_env_header_var(var: &str) -> Option<String> {
    match ENV_HEADER_RESOLVER.get() {
        Some(resolver) => resolver(var),
        None => std::env::var(var).ok(),
    }
}

/// Resolve `env_http_headers` (`header -> env var`) into `headers` via `getenv`, skipping unset/blank/invalid entries and trimming values.
fn apply_env_http_headers(
    env_http_headers: &IndexMap<String, String>,
    getenv: impl Fn(&str) -> Option<String>,
    headers: &mut HeaderMap,
) {
    for (key, env_var) in env_http_headers {
        let Some(value) = getenv(env_var) else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let (Ok(name), Ok(header_value)) = (
            HeaderName::try_from(key.as_str()),
            HeaderValue::from_str(value),
        ) else {
            tracing::warn!(
                header = %key,
                env_var = %env_var,
                "skipping env_http_header with an invalid header name or value"
            );
            continue;
        };
        headers.insert(name, header_value);
    }
}

/// HTTP client for sampling. Cheap to clone.
/// Carries an `Arc`-backed `reqwest::Client` and the default headers/request-defaults computed from a [`SamplerConfig`] at construction time.
#[derive(Clone)]
pub struct SamplingClient {
    subscription: Option<crate::subscription::SubscriptionKind>,
    subscription_resolver: Option<crate::subscription::SharedSubscriptionResolver>,
    http: reqwest::Client,
    default_headers: HeaderMap,
    base_url: String,
    defaults: ClientDefaults,
    /// Optional 401-attribution hook.
    /// The shell wires this to emit a structured event at every UNAUTHORIZED arm so 401s can be bucketed by stale-snapshot vs. live-token-rejected.
    /// `None` for sampler-only callers and tests.
    attribution_callback: Option<crate::attribution::SharedAttributionCallback>,
    /// Per-request bearer override. See `SamplerConfig::bearer_resolver`.
    bearer_resolver: Option<crate::config::SharedBearerResolver>,
    /// Per-request header injection (OTel traceparent).
    header_injector: Option<crate::config::SharedHeaderInjector>,
    /// Endpoint URL builder, resolved once from `base_url` and `query_params`.
    endpoint: EndpointTemplate,
    /// Whether every request body carries [`CacheBypass`]: only for FluxRouter's API host, and never on a subscription transport.
    fluxrouter_cache_bypass: bool,
    /// Whether this client's destination may receive `x-fuigo-*` identity headers. P15, P30.
    identity_disclosure: IdentityDisclosure,
    first_use_noted: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// P70b: the values of configured headers (`extra_headers`, `env_http_headers`) that are really in
    /// `default_headers`, i.e. that no client-composed header replaced. Recorded as sent credentials on every
    /// request, whatever name they were configured under. Never logged (`Debug` is hand-written above).
    configured_header_values: Vec<String>,
}

impl std::fmt::Debug for SamplingClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SamplingClient")
            .field("base_url", &fuigo_auth::redact_url(&self.base_url))
            .field("defaults", &self.defaults)
            .field(
                "has_attribution_callback",
                &self.attribution_callback.is_some(),
            )
            .field("has_bearer_resolver", &self.bearer_resolver.is_some())
            .finish()
    }
}

#[derive(Clone, Debug, Default)]
struct ClientDefaults {
    model: String,
    max_completion_tokens: Option<u32>,
    temperature: Option<f32>,
    top_p: Option<f32>,
    api_backend: ApiBackend,
    auth_scheme: AuthScheme,
    stream_tool_calls: bool,
    reasoning_summary: Option<fuigo_sampling_types::ReasoningSummary>,
    extra_response_includes: Vec<String>,
    doom_loop_recovery: Option<fuigo_sampling_types::DoomLoopRecoveryPolicy>,
}

/// Endpoint URL builder, resolved once at client construction so each request only appends its path.
#[derive(Clone)]
enum EndpointTemplate {
    /// No query params and no query on the base URL (or an unparseable base): append the path to the base verbatim.
    Plain(String),
    /// Query params configured: `{prefix}/{path}{suffix}`.
    /// `suffix` starts with `?` and folds any base-URL params; a configured key wins over the same key in `base_url`.
    /// Pairs are percent-encoded with no duplicates.
    WithQuery { prefix: String, suffix: String },
}

/// Hand-written `Debug` (P70): the base URL and its folded query may carry a key, so both print through `redact_url`.
impl std::fmt::Debug for EndpointTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plain(base) => f.debug_tuple("Plain").field(&fuigo_auth::redact_url(base)).finish(),
            Self::WithQuery { prefix, suffix } => f
                .debug_struct("WithQuery")
                .field("prefix", &fuigo_auth::redact_url(prefix))
                .field("suffix", &fuigo_auth::redact_url(&format!("x:{suffix}")).trim_start_matches("x:"))
                .finish(),
        }
    }
}

impl EndpointTemplate {
    fn new(base_url: &str, query_params: &IndexMap<String, String>) -> Self {
        let base = base_url.trim_end_matches('/').to_string();
        // The fast path is safe only when there is nothing to fold: no configured params and no query already on the base
        // A base query would otherwise land before the appended path
        if query_params.is_empty() && !base.contains('?') {
            return Self::Plain(base);
        }
        let mut url = match reqwest::Url::parse(&base) {
            Ok(url) => url,
            Err(error) => {
                tracing::warn!(
                    url = %fuigo_auth::redact_url(&base),
                    %error,
                    "failed to parse base URL for endpoint; sending without folded query"
                );
                return Self::Plain(base);
            }
        };
        let overridden: std::collections::HashSet<&str> =
            query_params.keys().map(String::as_str).collect();
        let kept: Vec<(String, String)> = url
            .query_pairs()
            .filter(|(k, _)| !overridden.contains(k.as_ref()))
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let prefix = {
            let mut prefix_url = url.clone();
            prefix_url.set_query(None);
            prefix_url.as_str().trim_end_matches('/').to_string()
        };
        {
            let mut pairs = url.query_pairs_mut();
            pairs.clear();
            for (key, value) in &kept {
                pairs.append_pair(key, value);
            }
            for (key, value) in query_params {
                pairs.append_pair(key, value);
            }
        }
        let suffix = url.query().map(|q| format!("?{q}")).unwrap_or_default();
        Self::WithQuery { prefix, suffix }
    }

    fn url_for_path(&self, path: &str) -> String {
        let path = path.trim_start_matches('/');
        match self {
            Self::Plain(base) => format!("{base}/{path}"),
            Self::WithQuery { prefix, suffix } => format!("{prefix}/{path}{suffix}"),
        }
    }
}

// =============================================================================
// User-Agent helpers
// =============================================================================

#[derive(Clone, Debug, Eq, PartialEq)]
struct PlatformInfo {
    os: String,
    arch: String,
}

impl PlatformInfo {
    fn current() -> Self {
        let os = match std::env::consts::OS {
            "macos" => "macos",
            "windows" => "windows",
            other => other,
        }
        .to_string();

        let arch = match std::env::consts::ARCH {
            "arm64" => "aarch64",
            "x86_64" => "x86_64",
            other => other,
        }
        .to_string();

        Self { os, arch }
    }
}

fn agent_version() -> String {
    fuigo_version::VERSION.to_string()
}

/// Render a User-Agent string for the given origin client.
///
/// Mirrors the shell's `user_agent_string_for` but uses sampler-local constants.
/// The session typically owns the canonical User-Agent rendering for process-wide HTTP clients.
/// This helper is for per-session sampling clients that want to override it.
pub fn user_agent_string_for(origin: &OriginClientInfo) -> String {
    let agent_version = agent_version();
    let platform = PlatformInfo::current();

    if origin.product == AGENT_PRODUCT && origin.version.as_deref() == Some(agent_version.as_str())
    {
        return format!(
            "{}/{} ({}; {})",
            AGENT_PRODUCT, agent_version, platform.os, platform.arch
        );
    }

    match origin.version.as_deref() {
        Some(origin_version) => format!(
            "{}/{} {}/{} ({}; {})",
            origin.product,
            origin_version,
            AGENT_PRODUCT,
            agent_version,
            platform.os,
            platform.arch
        ),
        None => format!(
            "{} {}/{} ({}; {})",
            origin.product, AGENT_PRODUCT, agent_version, platform.os, platform.arch
        ),
    }
}

/// A request builder coupled to the credential state it was built with, so a 401 arm cannot classify from anything but the build-time capture.
/// The wire default (`SentCredential::Unknown`, which charges the retry budget) stays the fail-closed one.
/// Only an explicit `sent_bearer: None` (a send the builder provably stamped no credential onto) reaches the uncharged lane via [`auth_rejected`].
struct SentRequest {
    builder: reqwest::RequestBuilder,
    /// Fingerprint of the credential in the built headers (`None` means no credential header).
    sent_bearer: Option<BearerFingerprint>,
}

/// The one way a 401 becomes a `SamplingError::Auth` with a wire-derived credential classification: from the fragment its [`SentRequest`] captured.
fn auth_rejected(message: String, sent_bearer: Option<&BearerFingerprint>) -> SamplingError {
    SamplingError::Auth {
        message,
        credential: SentCredential::from_sent_fragment(sent_bearer.map(BearerFingerprint::as_str)),
    }
}

// =============================================================================
// SamplingClient
// =============================================================================

/// The client-level `x-fuigo-*` identity headers, applied only to a FluxRouter-operated destination.
///
/// Enumerated by [`CLIENT_IDENTITY_HEADERS`]. Every name this writes is identity: there is no
/// ungated half here, unlike [`FuigoRequestHeaders::apply`], because none of these is a
/// per-session value.
///
/// P15. These were previously written unconditionally, so a BYOK request to
/// `api.openai.com`, `api.anthropic.com` or `openrouter.ai` carried the Ferrox account id
/// and the tenant deployment UUID. Both are stable and identical across every provider a
/// user configures, which made them a cross-provider correlator letting unrelated third
/// parties link one user's traffic — and disclosed Ferrox tenancy to vendors with no
/// business holding it.
///
/// The comment this block used to carry, *"for version gating at the proxy"*, stated the
/// single-destination assumption outright. It was true of the CLI this was forked from and
/// stopped being true when BYOK providers became a first-class feature.
///
/// A free function, not a method, so it is directly testable for both destination classes
/// without building a client or a network.
fn apply_identity_headers(
    headers: &mut HeaderMap,
    config: &SamplerConfig,
    identity: IdentityDisclosure,
) {
    if !identity.is_permitted() {
        // M10. The gate used to refuse in total silence, which contradicted the
        // justification it carries: "the cost is telemetry going dark, which is VISIBLE and
        // recoverable". Nothing made it visible. The sibling destination refusals in
        // `fuigo-shell`'s `session_may_be_sent_to` each `warn` and name the remedy, for the
        // same reason — a legitimate setup that silently loses a feature is undiagnosable.
        //
        // Severity is split on whether there was anything to withhold, so the log says
        // something in the case that matters and stays quiet in the case that does not. A
        // plain BYOK user has no `deployment_id` or `user_id`; warning on every client they
        // build would be noise, and noise is how a real warning gets missed. A MANAGED
        // deployment does have them, and it is precisely the case the doc calls recoverable.
        let downgraded = fuigo_extra_ca::fluxrouter::is_fluxrouter_url(&config.base_url);
        if config.deployment_id.is_some() || config.user_id.is_some() {
            tracing::warn!(
                base_url = %fuigo_auth::redact_url(&config.base_url),
                scheme_downgrade = downgraded,
                withheld = ?CLIENT_IDENTITY_HEADERS,
                "x-fuigo-* identity headers were withheld: this inference base URL is not \
                 https://api.fluxrouter.ai. Proxy-side version gating and telemetry go dark \
                 for this client. Point the inference base URL at \
                 `https://api.fluxrouter.ai` to restore them."
            );
        } else {
            tracing::debug!(
                base_url = %fuigo_auth::redact_url(&config.base_url),
                scheme_downgrade = downgraded,
                withheld = ?CLIENT_IDENTITY_HEADERS,
                "x-fuigo-* identity headers withheld: destination is not FluxRouter-operated"
            );
        }
        return;
    }
    // Version gating at the proxy — the proxy being the FluxRouter-operated route alone.
    if let Some(client_version) = config.client_version.as_ref()
        && let Ok(header_value) = HeaderValue::from_str(client_version)
    {
        headers.insert(HeaderName::from_static(H_CLIENT_VERSION), header_value);
    }

    if let Some(deployment_id) = config.deployment_id.as_ref()
        && let Ok(header_value) = HeaderValue::from_str(deployment_id)
    {
        headers.insert(HeaderName::from_static(H_DEPLOYMENT_ID), header_value);
    }

    if let Some(user_id) = config.user_id.as_ref()
        && let Ok(header_value) = HeaderValue::from_str(user_id)
    {
        headers.insert(HeaderName::from_static(H_USER_ID), header_value);
    }

    let client_id = config
        .client_identifier
        .clone()
        .unwrap_or_else(|| DEFAULT_CLIENT_IDENTIFIER.to_string());
    if let Ok(header_value) = HeaderValue::from_str(&client_id) {
        headers.insert(HeaderName::from_static(H_CLIENT_IDENTIFIER), header_value);
    }
}

impl SamplingClient {
    /// Grabs the process-wide shared `reqwest::Client` (HTTP/2 by default, HTTP/1.1 when `config.force_http1` is set).
    /// Pre-computes the default request headers.
    /// This does not perform any network I/O.
    pub fn new(mut config: SamplerConfig) -> Result<Self> {
        if config.subscription.is_some() {
            config.api_key = None;
            config.bearer_resolver = None;
            config.attribution_callback = None;
            config.header_injector = None;
            config.extra_headers.clear();
            config.env_http_headers.clear();
        }
        // P15: decided once, from the destination host, before any header is assembled.
        // P30: by the compiled FluxRouter-operated check, never by configured trust.
        let identity = IdentityDisclosure::for_destination(&config.base_url);
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(ref api_key) = config.api_key {
            match config.auth_scheme {
                AuthScheme::XApiKey => {
                    let header_value = HeaderValue::from_str(api_key).map_err(|_| {
                        // Length and nothing else. The key is invalid, not
                        // secret-by-accident: a malformed credential is still a
                        // credential, and a debug log is a file on disk.
                        tracing::debug!(
                            api_key_len = api_key.len(),
                            "Invalid api_key: cannot be converted to a valid HTTP header"
                        );
                        SamplingError::auth_unknown(
                            "Invalid api_key: cannot be converted to a valid HTTP header",
                        )
                    })?;
                    headers.insert(HeaderName::from_static("x-api-key"), header_value);
                }
                AuthScheme::Bearer => {
                    let bearer = format!("Bearer {}", api_key);
                    let header_value = HeaderValue::from_str(&bearer).map_err(|_| {
                        // See the `XApiKey` arm: length only, never the value.
                        tracing::debug!(
                            api_key_len = api_key.len(),
                            "Invalid api_key: cannot be converted to a valid HTTP Authorization header"
                        );
                        SamplingError::auth_unknown(
                            "Invalid api_key: cannot be converted to a valid HTTP Authorization header",
                        )
                    })?;
                    headers.insert(AUTHORIZATION, header_value);
                }
            }
        }

        // Apply all extra headers verbatim
        // This is the single injection point for proxy-auth headers and any other URL- or environment-specific headers the session decides to set
        for (key, value) in &config.extra_headers {
            let header_name = HeaderName::try_from(key.as_str())
                .map_err(|_| SamplingError::InvalidConfiguration("Invalid extra header name"))?;
            let header_value = HeaderValue::from_str(value)
                .map_err(|_| SamplingError::InvalidConfiguration("Invalid extra header value"))?;
            headers.insert(header_name, header_value);
        }

        // Resolve here, not into `extra_headers`, so an env-sourced secret stays out of persisted state
        apply_env_http_headers(&config.env_http_headers, resolve_env_header_var, &mut headers);
        // P70b: a configured header may carry a credential under ANY name, including one the per-request recorder
        // treats as client-composed (`user-agent`, an `x-fuigo-*` name). Snapshot what configuration put under each
        // configured name; whatever of it survives the client-composed headers below is recorded on every request.
        let configured = crate::sent_credentials::configured_snapshot(
            &headers,
            config.extra_headers.keys().chain(config.env_http_headers.keys()),
        );

        // The Messages wire protocol requires `anthropic-version`. Supplied
        // here rather than only in the `/provider` discovery table so a
        // hand-written `[model_providers.x] api_backend = "messages"` produces
        // a well-formed request instead of one the server rejects. Inserted
        // only when absent, so `extra_headers` / `env_http_headers` above still
        // decide the value when the config names one.
        if config.api_backend == ApiBackend::Messages
            && !headers.contains_key(HeaderName::from_static(ANTHROPIC_VERSION_HEADER))
        {
            headers.insert(
                HeaderName::from_static(ANTHROPIC_VERSION_HEADER),
                HeaderValue::from_static(ANTHROPIC_VERSION),
            );
        }

        apply_identity_headers(&mut headers, &config, identity);

        // Always set User-Agent: per-session origin if available, else fallback.
        {
            let ua_string = match config.origin_client.as_ref() {
                Some(origin) => user_agent_string_for(origin),
                None => user_agent_string_for(&OriginClientInfo {
                    product: AGENT_PRODUCT.to_string(),
                    version: Some(agent_version()),
                }),
            };
            // P70: the `User-Agent` this client sends is always its own. An origin that does not form a header value
            // (a control character in the product name) falls back to the agent's own string, so a `user-agent`
            // configured in `extra_headers` (which may hold anything, a credential included) never survives here.
            let own = || {
                HeaderValue::from_str(&user_agent_string_for(&OriginClientInfo {
                    product: AGENT_PRODUCT.to_string(),
                    version: Some(agent_version()),
                }))
            };
            match HeaderValue::from_str(&ua_string).or_else(|_| own()) {
                Ok(v) => {
                    headers.insert(USER_AGENT, v);
                }
                Err(_) => {
                    headers.remove(USER_AGENT);
                }
            }
        }

        if config.force_http1 {
            tracing::info!("Using HTTP/1.1 for sampling client (force_http1=true)");
        }
        // A per-model mTLS identity gets its own HTTPS-only, no-redirect client; it is still built through
        // `fuigo_extra_ca::build_reqwest_client`, so the egress blocklist applies to it as well.
        let http = if let Some(cert_dir) = config.mtls_cert_dir.as_deref() {
            crate::shared_http::mtls_client(cert_dir, config.force_http1)?
        } else if config.force_http1 {
            crate::shared_http::client_http1().map_err(SamplingError::Http)?
        } else {
            crate::shared_http::client().map_err(SamplingError::Http)?
        };

        tracing::info!(
            target: crate::sampling_log::TARGET,
            event = "client_new",
            base_url = %fuigo_auth::redact_url(&config.base_url),
            model = %config.model,
            api_backend = ?config.api_backend,
            auth_scheme = ?config.auth_scheme,
            // "unset" (not "none"): `ReasoningEffort::None` is a real wire value; logging the absent Option as "none" looked like we were sending it
            reasoning_effort = config.reasoning_effort.map_or("unset", |e| e.as_str()),
            has_api_key = config.api_key.is_some(),
            has_bearer_resolver = config.bearer_resolver.is_some(),
            has_authorization_header = headers.get(AUTHORIZATION).is_some(),
            has_x_api_key_header = headers.get(HeaderName::from_static("x-api-key")).is_some(),
        );

        let defaults = ClientDefaults {
            model: config.model,
            max_completion_tokens: config.max_completion_tokens,
            temperature: config.temperature,
            top_p: config.top_p,
            api_backend: config.api_backend,
            auth_scheme: config.auth_scheme,
            stream_tool_calls: config.stream_tool_calls,
            reasoning_summary: config.reasoning_summary,
            extra_response_includes: config.extra_response_includes,
            doom_loop_recovery: config.doom_loop_recovery,
        };

        let endpoint = EndpointTemplate::new(&config.base_url, &config.query_params);
        let fluxrouter_cache_bypass = config.subscription.is_none()
            && fuigo_extra_ca::fluxrouter::is_fluxrouter_url(&config.base_url);

        let configured_header_values =
            crate::sent_credentials::surviving_configured_values(configured, &headers);

        Ok(Self {
            subscription: config.subscription,
            subscription_resolver: config.subscription_resolver,
            http,
            default_headers: headers,
            base_url: config.base_url,
            defaults,
            attribution_callback: config.attribution_callback,
            bearer_resolver: config.bearer_resolver,
            header_injector: config.header_injector,
            endpoint,
            fluxrouter_cache_bypass,
            identity_disclosure: identity,
            first_use_noted: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            configured_header_values,
        })
    }

    async fn dispatch_request(&self, mut request: reqwest::Request, streaming: bool) -> Result<reqwest::Response> {
        use crate::request_accounting::{Attempt, Outcome};
        // Low-level callers still receive a receipt, but without guessing purpose
        // or claiming that receiving response headers settled streaming usage.
        let fallback = (!crate::request_accounting::is_scoped()).then(||
            Attempt::new(&ConversationRequest::new(), &uuid::Uuid::new_v4().to_string(), 1));
        let dispatch = async {
        crate::request_accounting::admit_current().await.map_err(|_|
            SamplingError::InvalidConfiguration("execution admission denied or could not be persisted"))?;
        if let Some(budget) = crate::execution_budget::process_budget().map_err(SamplingError::InvalidConfiguration)? {
            let (purpose, scope) = crate::request_accounting::current_policy();
            budget.admit_for_scope(purpose, scope.as_deref()).map_err(SamplingError::InvalidConfiguration)?;
            if let Some(remaining) = budget.remaining() {
                let timeout = request.timeout().copied().map_or(remaining, |timeout| timeout.min(remaining));
                *request.timeout_mut() = Some(timeout);
            }
        }
        if let Some(kind) = self.subscription {
            return crate::subscription::dispatch(kind, self.subscription_resolver.as_ref(), request).await;
        }
        crate::request_accounting::clamp_deadline(&mut request)?;
        crate::sent_credentials::record_request(&request, &self.configured_header_values);
        crate::request_accounting::dispatched();
        fuigo_extra_ca::dispatch::execute(&self.http, request).await.map_err(|error| dispatch_error(error, streaming))
        };
        if let Some(receipt) = fallback {
            let result = receipt.scope(dispatch).await;
            receipt.finish(if result.is_ok() { Outcome::Unknown } else { Outcome::Failed }, None, None);
            result
        } else {
            dispatch.await
        }
    }

    pub fn api_backend(&self) -> ApiBackend {
        self.defaults.api_backend.clone()
    }

    /// POST with default headers, returning the builder coupled to the tail fragment of the credential placed in its headers.
    /// `None` means no credential; the capture happens at build time because a record-time re-read races with the recovery a 401 triggers.
    ///
    /// A wired bearer_resolver is the sole auth source.
    /// A missing live bearer strips default Authorization / x-api-key so a hard-expired seed key cannot ride on the wire.
    fn post(&self, url: impl reqwest::IntoUrl) -> SentRequest {
        if !self
            .first_use_noted
            .load(std::sync::atomic::Ordering::Relaxed)
            && !self
                .first_use_noted
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            crate::prewarm::note_first_sampling_use(&self.base_url);
        }
        let mut headers = self.default_headers.clone();
        if let Some(resolver) = &self.bearer_resolver {
            headers.remove(AUTHORIZATION);
            headers.remove(HeaderName::from_static("x-api-key"));
            if let Some(fresh) = resolver.current_bearer() {
                match self.defaults.auth_scheme {
                    AuthScheme::XApiKey => {
                        if let Ok(v) = HeaderValue::from_str(&fresh) {
                            headers.insert(HeaderName::from_static("x-api-key"), v);
                        }
                    }
                    AuthScheme::Bearer => {
                        if let Ok(v) = HeaderValue::from_str(&format!("Bearer {fresh}")) {
                            headers.insert(AUTHORIZATION, v);
                        }
                    }
                }
            }
        }
        {
            // A fixed label for the `Authorization` scheme, never text taken from the header (P08): a value with no
            // recognised scheme may be the credential itself, or start with part of it.
            let auth_header_scheme = headers.get(AUTHORIZATION).map(|v| {
                let scheme = v.to_str().ok().and_then(|s| s.split_once(' ')).map(|(scheme, _)| scheme);
                match scheme {
                    Some(s) if s.eq_ignore_ascii_case("bearer") => "bearer",
                    Some(s) if s.eq_ignore_ascii_case("basic") => "basic",
                    _ => "other",
                }
            });
            tracing::info!(
                target: crate::sampling_log::TARGET,
                event = "client_post",
                base_url = %fuigo_auth::redact_url(&self.base_url),
                model = %self.defaults.model,
                api_backend = ?self.defaults.api_backend,
                auth_scheme = ?self.defaults.auth_scheme,
                has_bearer_resolver = self.bearer_resolver.is_some(),
                has_authorization_header = headers.get(AUTHORIZATION).is_some(),
                has_x_api_key_header = headers.get(HeaderName::from_static("x-api-key")).is_some(),
                auth_header_scheme = auth_header_scheme.unwrap_or("none"),
            );
        }
        let sent_bearer = Self::sent_fragment_from_headers(&headers, &self.defaults.auth_scheme);
        if let Some(injector) = &self.header_injector {
            injector.inject(&mut headers);
        }
        SentRequest {
            builder: self.http.post(url).headers(headers),
            sent_bearer,
        }
    }

    /// [`BearerFingerprint`] of the credential in `headers`: `x-api-key` (Messages-API scheme) or `Authorization`.
    fn sent_fragment_from_headers(headers: &HeaderMap, scheme: &AuthScheme) -> Option<BearerFingerprint> {
        let raw = match scheme {
            AuthScheme::XApiKey => headers
                .get(HeaderName::from_static("x-api-key"))
                .and_then(|v| v.to_str().ok()),
            AuthScheme::Bearer => headers
                .get(AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer ")),
        };
        raw.map(BearerFingerprint::of)
    }

    /// Best-effort *build-time* view of what the next request would carry (resolver-authoritative).
    /// For request-start diagnostics ([`Self::auth_info`]) only.
    /// 401 attribution must use the fragment captured by [`Self::post`], which cannot race a recovery.
    fn current_sent_bearer_fingerprint(&self) -> Option<BearerFingerprint> {
        if self.bearer_resolver.is_some() {
            return self
                .bearer_resolver
                .as_ref()
                .and_then(|r| r.current_bearer())
                .map(|s| BearerFingerprint::of(&s));
        }
        Self::sent_fragment_from_headers(&self.default_headers, &self.defaults.auth_scheme)
    }

    /// Invoke the optional 401 attribution callback for one logical 401 response.
    /// Each of the six UNAUTHORIZED arms in this file calls this helper immediately before returning `SamplingError::Auth(...)`.
    /// The emit happens at the lowest layer that saw the status, so higher layers that react to a 401 must not emit a duplicate event.
    ///
    /// `sent` is the fingerprint [`Self::post`] captured for the rejected request.
    /// Neither the bearer nor any fragment of it crosses this boundary.
    fn record_401_attribution(
        &self,
        consumer: crate::attribution::SamplingConsumer,
        sent: Option<&BearerFingerprint>,
    ) {
        if let Some(cb) = self.attribution_callback.as_ref() {
            cb.record_401(consumer, sent);
        }
    }

    pub fn auth_info(&self) -> crate::sampling_log::AuthInfo {
        let auth_type = match (&self.defaults.auth_scheme, self.current_sent_bearer_fingerprint()) {
            (AuthScheme::XApiKey, Some(_)) => "x-api-key",
            (AuthScheme::Bearer, Some(_)) => "bearer",
            (_, None) => "none",
        };
        crate::sampling_log::AuthInfo { auth_type }
    }

    /// Short lossy body snippet for error logs (never user-facing).
    /// P70b: the 500-char cap never cuts through a credential this process sent, so the log writer's exact-match
    /// scrub still finds an echoed key whole.
    fn body_preview(bytes: &[u8]) -> String {
        let text = String::from_utf8_lossy(bytes);
        fuigo_secrets::sent_credentials::truncate_chars(&text, 500)
            .0
            .to_owned()
    }

    /// Log the NAMES of a request's headers at debug level (P70). No value is logged: any header, whatever its name,
    /// may have been mapped to a credential by `extra_headers` / `env_http_headers`, and a name-based denylist
    /// (`authorization`, `api-key`, `token`, `secret`) misses `Cookie`, `x-credential` and the like.
    fn log_request_headers(request: &reqwest::Request, endpoint_name: &str) {
        for name in request.headers().keys() {
            tracing::debug!(header_name = %name, "Request header ({})", endpoint_name);
        }
    }

    fn endpoint(&self, path: &str) -> String {
        self.endpoint.url_for_path(path)
    }

    /// The body to send for `inner`: every dispatch serializes through here so FluxRouter's cache bypass cannot miss a wire format.
    fn body<'a, T: Serialize>(&self, inner: &'a T) -> RequestBody<'a, T> {
        RequestBody {
            inner,
            cache: self.fluxrouter_cache_bypass.then_some(CacheBypass {
                no_cache: true,
                no_store: true,
            }),
        }
    }

    fn apply_defaults(&self, mut request: ChatCompletionRequest) -> Result<ChatCompletionRequest> {
        if request.model.is_none() {
            request.model = Some(self.defaults.model.clone());
        }

        if request.max_tokens.is_none() {
            request.max_tokens = self.defaults.max_completion_tokens;
        }

        if request.temperature.is_none() {
            request.temperature = self.defaults.temperature;
        }

        if request.top_p.is_none() {
            request.top_p = self.defaults.top_p;
        }

        Ok(request)
    }

    /// `sent_bearer` is the fragment [`Self::post`] captured for the request that produced `response` (401 attribution).
    async fn handle_response(
        &self,
        response: reqwest::Response,
        sent_bearer: Option<&BearerFingerprint>,
    ) -> Result<ChatCompletionResponse> {
        let status = response.status();
        let model_metadata = extract_model_metadata(response.headers());
        let retry_after_secs = extract_retry_after(status, response.headers());
        let should_retry = extract_should_retry(response.headers());
        let bytes = response.bytes().await?;

        if !status.is_success() {
            if status == reqwest::StatusCode::UNAUTHORIZED {
                self.record_401_attribution(
                    crate::attribution::SamplingConsumer::ChatCompletions,
                    sent_bearer,
                );
                let server_message = user_facing_api_error_message(status, bytes.as_ref());
                return Err(auth_rejected(
                    format!("Unauthorized (401): {server_message}"),
                    sent_bearer,
                ));
            }
            let message = user_facing_api_error_message(status, bytes.as_ref());
            return Err(SamplingError::Api {
                status,
                message,
                model_metadata,
                retry_after_secs,
                should_retry,
                error_code: parse_error_code(bytes.as_ref()),
            });
        }

        let completion = serde_json::from_slice::<ChatCompletionResponse>(&bytes)
            .map_err(|e| serde_failure("ChatCompletionResponse", &e, bytes.len()))?;
        Ok(completion)
    }

    // =========================================================================
    // Chat Completions API
    // =========================================================================

    pub async fn chat_completion(
        &self,
        request: ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse> {
        let payload = self.apply_defaults(request)?;
        let x_fuigo_conv_id = &payload.x_fuigo_conv_id.clone().unwrap_or_default();
        let x_fuigo_req_id = &payload.x_fuigo_req_id.clone().unwrap_or_default();
        let model_id = payload.model.clone().unwrap_or_default();

        tracing::debug!(
            base_url = %fuigo_auth::redact_url(&self.base_url),
            model_id = %model_id,
            "Sending chat completion request"
        );

        let fuigo_headers = FuigoRequestHeaders {
            conv_id: x_fuigo_conv_id,
            req_id: x_fuigo_req_id,
            model_id: &model_id,
            session_id: payload.x_fuigo_session_id.as_deref().unwrap_or_default(),
            turn_idx: payload.x_fuigo_turn_idx.as_deref(),
            transient_retry: payload.x_fuigo_transient_retry.as_deref(),
            agent_id: payload.x_fuigo_agent_id.as_deref().unwrap_or_default(),
            deployment_id: payload.x_fuigo_deployment_id.as_deref(),
            user_id: payload.x_fuigo_user_id.as_deref(),
            identity: self.identity_disclosure,
        };
        let SentRequest {
            builder,
            sent_bearer,
        } = self.post(self.endpoint("chat/completions"));
        let http_request = fuigo_headers.apply(builder).json(&self.body(&payload));

        let response = self.dispatch_request(http_request.build().map_err(SamplingError::Http)?, false).await?;

        self.handle_response(response, sent_bearer.as_ref()).await
    }

    /// Start a streaming chat completion request. Returns a stream of typed chunks.
    #[tracing::instrument(
        name = "http.chat_completion_stream",
        skip_all,
        fields(
            endpoint = %fuigo_auth::redact_url(&self.endpoint("chat/completions")),
            model_id = request.model.as_deref().unwrap_or(""),
            status_code = tracing::field::Empty,
            success = tracing::field::Empty,
            error = tracing::field::Empty,
        )
    )]
    pub async fn chat_completion_stream(
        &self,
        request: ChatCompletionRequest,
    ) -> Result<(
        BoxStream<'static, Result<ChatCompletionChunk>>,
        Option<ResponseModelMetadata>,
    )> {
        let payload = self.apply_defaults(request)?;
        let x_fuigo_conv_id = &payload.x_fuigo_conv_id.clone().unwrap_or_default();
        let x_fuigo_req_id = &payload.x_fuigo_req_id.clone().unwrap_or_default();
        let model_id = payload.model.clone().unwrap_or_default();

        // Wrap the request with streaming fields and serialize once.
        let streaming_request = StreamingChatRequest {
            inner: &payload,
            stream: true,
            stream_options: StreamOptions {
                include_usage: true,
            },
        };

        let fuigo_headers = FuigoRequestHeaders {
            conv_id: x_fuigo_conv_id,
            req_id: x_fuigo_req_id,
            model_id: &model_id,
            session_id: payload.x_fuigo_session_id.as_deref().unwrap_or_default(),
            turn_idx: payload.x_fuigo_turn_idx.as_deref(),
            transient_retry: payload.x_fuigo_transient_retry.as_deref(),
            agent_id: payload.x_fuigo_agent_id.as_deref().unwrap_or_default(),
            deployment_id: payload.x_fuigo_deployment_id.as_deref(),
            user_id: payload.x_fuigo_user_id.as_deref(),
            identity: self.identity_disclosure,
        };
        let SentRequest {
            builder,
            sent_bearer,
        } = self.post(self.endpoint("chat/completions"));
        let http_request = fuigo_headers
            .apply(builder)
            .header(ACCEPT, HeaderValue::from_static("text/event-stream"))
            .json(&self.body(&streaming_request));

        let built_request = http_request.build().map_err(|e| {
            tracing::error!("Failed to build HTTP request: {}", transport_error_for_log(&e));
            SamplingError::Http(e)
        })?;

        tracing::debug!(
            url = %fuigo_auth::redact_url(built_request.url().as_str()),
            method = %built_request.method(),
            "Sending chat/completions request"
        );
        Self::log_request_headers(&built_request, "chat/completions");

        let response = self.dispatch_request(built_request, true).await?;

        let status = response.status();
        let span = tracing::Span::current();
        span.record("status_code", status.as_u16() as i64);
        span.record("success", status.is_success());
        let model_metadata = extract_model_metadata(response.headers());
        let retry_after_secs = extract_retry_after(status, response.headers());
        let should_retry = extract_should_retry(response.headers());
        if !status.is_success() {
            if status == reqwest::StatusCode::UNAUTHORIZED {
                span.record("error", "unauthorized (401)");
                self.record_401_attribution(
                    crate::attribution::SamplingConsumer::ChatCompletionsStream,
                    sent_bearer.as_ref(),
                );
                let endpoint = self.endpoint("chat/completions");
                let body = response.bytes().await.unwrap_or_default();
                let server_message = user_facing_api_error_message(status, body.as_ref());
                return Err(auth_rejected(
                    format!("Unauthorized (401) from {endpoint}: {server_message}"),
                    sent_bearer.as_ref(),
                ));
            }

            let bytes = response.bytes().await?;
            let message = user_facing_api_error_message(status, bytes.as_ref());
            span.record("error", message.as_str());
            tracing::error!(
                status = %status,
                error_message = %message,
                body_preview = %Self::body_preview(bytes.as_ref()),
                model_id = %model_id,
                "chat/completions API error"
            );
            return Err(SamplingError::Api {
                status,
                message,
                model_metadata,
                retry_after_secs,
                should_retry,
                error_code: parse_error_code(bytes.as_ref()),
            });
        }

        // Strip UTF-8 BOM if present: eventsource-stream 0.2.3 incorrectly slices BOM at byte 1 instead of 3.
        const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];
        let mut is_first = true;
        let byte_stream = response.bytes_stream().map(move |result| {
            result.map(|bytes| {
                if is_first {
                    is_first = false;
                    if bytes.starts_with(UTF8_BOM) {
                        return bytes.slice(UTF8_BOM.len()..);
                    }
                }
                bytes
            })
        });

        let event_stream = byte_stream.eventsource();

        // Map SSE events into ChatCompletionChunk.
        // Uses `scan` so that `[DONE]` and transport errors both terminate the stream (`None`)
        // The first transport error is emitted to the consumer, then subsequent polls return `None`
        // This prevents an infinite busy-loop when the HTTP/2 connection drops and h2 keeps producing errors
        let chunks = event_stream
            .scan(false, |had_transport_error, event_res| {
                if *had_transport_error {
                    return std::future::ready(None);
                }
                let item = match event_res {
                    Ok(event) => {
                        let data = &event.data;
                        if data == "[DONE]" {
                            return std::future::ready(None);
                        }

                        tracing::info!(
                            target: crate::sampling_log::TARGET,
                            event = "sse_chunk",
                            backend = "chat_completions",
                            data = %data,
                        );

                        if let Some(stream_error) = try_parse_stream_error(data) {
                            Some(Err(stream_error))
                        } else {
                            Some(
                                serde_json::from_str::<ChatCompletionChunk>(data).map_err(|e| {
                                    serde_failure("ChatCompletionChunk from stream", &e, data.len())
                                }),
                            )
                        }
                    }
                    Err(e) => {
                        *had_transport_error = true;
                        Some(Err(SamplingError::EventStreamError(e.to_string())))
                    }
                };
                std::future::ready(item)
            })
            .boxed();

        Ok((chunks, model_metadata))
    }

    // =========================================================================
    // Responses API
    // =========================================================================

    fn apply_response_defaults(&self, request: &mut CreateResponseWrapper) -> Result<()> {
        if request.inner.model.is_none() {
            request.inner.model = Some(self.defaults.model.clone());
        }

        if request.inner.temperature.is_none() {
            request.inner.temperature = self.defaults.temperature;
        }

        if request.inner.top_p.is_none() {
            request.inner.top_p = self.defaults.top_p;
        }

        if request.inner.max_output_tokens.is_none() {
            request.inner.max_output_tokens = self.defaults.max_completion_tokens;
        }

        // The API defaults `store` to true, which breaks ZDR compliance
        if request.inner.store.is_none() {
            request.inner.store = Some(false);
        }

        // Per-model `reasoning_summary` override: `none` omits the field (BYOK gateways that reject it), any other
        // value replaces the built one. A non-interactive session's suppression still wins: nothing displays the
        // summary there, so it is forced to `none` regardless of the model's setting.
        let summary_override = if request.suppress_reasoning_summary {
            Some(fuigo_sampling_types::ReasoningSummary::None)
        } else {
            self.defaults.reasoning_summary
        };
        if let Some(summary) = summary_override {
            let summary = summary.to_responses_api();
            match request.inner.reasoning.as_mut() {
                Some(reasoning) => reasoning.summary = summary,
                None if summary.is_some() => {
                    request.inner.reasoning = Some(rs::Reasoning {
                        effort: None,
                        summary,
                    });
                }
                None => {}
            }
        }

        // Include encrypted reasoning content if not specified
        let includes = request.inner.include.get_or_insert_with(Vec::new);
        if !includes.contains(&rs::IncludeEnum::ReasoningEncryptedContent) {
            includes.push(rs::IncludeEnum::ReasoningEncryptedContent);
        }

        Ok(())
    }

    /// Create a response using the Responses API (non-streaming).
    pub async fn create_response(
        &self,
        mut request: CreateResponseWrapper,
    ) -> Result<rs::Response> {
        if self.subscription == Some(crate::subscription::SubscriptionKind::Chatgpt) {
            let (mut events, _, _) = self.create_response_stream(request).await?;
            while let Some(event) = events.next().await {
                match event? {
                    rs::ResponseStreamEvent::ResponseCompleted(event) => return Ok(event.response),
                    rs::ResponseStreamEvent::ResponseFailed(_) | rs::ResponseStreamEvent::ResponseIncomplete(_) => return Err(SamplingError::InvalidConfiguration("subscription response did not complete")),
                    _ => {},
                }
            }
            return Err(SamplingError::InvalidConfiguration("subscription stream ended without completion"));
        }
        self.apply_response_defaults(&mut request)?;

        let x_fuigo_conv_id = request.x_fuigo_conv_id.as_deref().unwrap_or_default();
        let x_fuigo_req_id = request.x_fuigo_req_id.as_deref().unwrap_or_default();
        let model_id = request.inner.model.clone().unwrap_or_default();

        // The trace field is process-local: upstream session code consumes it (and may upload a payload artifact); the sampler never forwards it
        // Drop it before we send
        request.trace.take();

        tracing::debug!("create_response: {:?}", &request);
        tracing::debug!("endpoint: {:?}", fuigo_auth::redact_url(&self.endpoint("responses")));

        let fuigo_headers = FuigoRequestHeaders {
            conv_id: x_fuigo_conv_id,
            req_id: x_fuigo_req_id,
            model_id: &model_id,
            session_id: request.x_fuigo_session_id.as_deref().unwrap_or_default(),
            turn_idx: request.x_fuigo_turn_idx.as_deref(),
            transient_retry: request.x_fuigo_transient_retry.as_deref(),
            agent_id: request.x_fuigo_agent_id.as_deref().unwrap_or_default(),
            deployment_id: request.x_fuigo_deployment_id.as_deref(),
            user_id: request.x_fuigo_user_id.as_deref(),
            identity: self.identity_disclosure,
        };
        let extra_tool_entries = std::mem::take(&mut request.extra_tool_entries);
        let mut request_body = serde_json::to_value(&request.inner).map_err(|e| {
            tracing::error!("Failed to serialize responses request: {}", e);
            SamplingError::Serialization(e)
        })?;
        splice_extra_tool_entries(&mut request_body, extra_tool_entries);
        append_response_includes(&mut request_body, &self.defaults.extra_response_includes);
        // async-openai's ReasoningTextContent struct omits the `type` discriminator that the Responses API requires on input
        // Patch it in after serializing
        fuigo_sampling_types::patch_reasoning_text_types(&mut request_body);
        // Programmatic tool calling: carriers -> wire items, `caller` on program calls, `allowed_callers` on tools (no-op when off)
        fuigo_sampling_types::patch_request_body(&mut request_body);
        let SentRequest {
            builder,
            sent_bearer,
        } = self.post(self.endpoint("responses"));
        let http_request = fuigo_headers.apply(builder).json(&self.body(&request_body));

        let response = self.dispatch_request(http_request.build().map_err(SamplingError::Http)?, false).await?;

        let status = response.status();
        let model_metadata = extract_model_metadata(response.headers());
        let retry_after_secs = extract_retry_after(status, response.headers());
        let should_retry = extract_should_retry(response.headers());
        let bytes = response.bytes().await?;

        if !status.is_success() {
            if status == reqwest::StatusCode::UNAUTHORIZED {
                self.record_401_attribution(
                    crate::attribution::SamplingConsumer::Responses,
                    sent_bearer.as_ref(),
                );
                let endpoint = self.endpoint("responses");
                let server_message = user_facing_api_error_message(status, bytes.as_ref());
                return Err(auth_rejected(
                    format!("Unauthorized (401) from {endpoint}: {server_message}"),
                    sent_bearer.as_ref(),
                ));
            }

            let message = user_facing_api_error_message(status, bytes.as_ref());
            tracing::warn!(
                status = %status,
                error_message = %message,
                body_preview = %Self::body_preview(bytes.as_ref()),
                model_id = %model_id,
                "responses API error"
            );
            return Err(SamplingError::Api {
                status,
                message,
                model_metadata,
                retry_after_secs,
                should_retry,
                error_code: parse_error_code(bytes.as_ref()),
            });
        }

        let response_obj = serde_json::from_slice::<rs::Response>(&bytes)
            .map_err(|e| serde_failure("rs::Response", &e, bytes.len()))?;
        Ok(response_obj)
    }

    /// Create a streaming response using the Responses API.
    ///
    /// The third tuple element is a per-request doom-loop signal collector, `Some` only when `SamplerConfig::doom_loop_recovery` is set.
    /// That same gate adds the opt-in `x-fuigo-doom-loop-check` request header, so header and parse protection cannot drift apart.
    /// The SSE decoder fills it as the server reports triggers.
    /// Hand it to `stream_responses` so the signals land on the final `ConversationResponse`.
    #[tracing::instrument(
        name = "http.create_response_stream",
        skip_all,
        fields(
            endpoint = %fuigo_auth::redact_url(&self.endpoint("responses")),
            model_id = request.inner.model.as_deref().unwrap_or(""),
            status_code = tracing::field::Empty,
            success = tracing::field::Empty,
            error = tracing::field::Empty,
        )
    )]
    #[allow(clippy::type_complexity)]
    pub async fn create_response_stream(
        &self,
        mut request: CreateResponseWrapper,
    ) -> Result<(
        BoxStream<'static, Result<rs::ResponseStreamEvent>>,
        Option<ResponseModelMetadata>,
        Option<crate::doom_loop::DoomLoopSignalCollector>,
    )> {
        self.apply_response_defaults(&mut request)?;

        request.inner.stream = Some(true);

        let x_fuigo_conv_id = request.x_fuigo_conv_id.as_deref().unwrap_or_default();
        let x_fuigo_req_id = request.x_fuigo_req_id.as_deref().unwrap_or_default();
        let model_id = request.inner.model.clone().unwrap_or_default();

        // Drop process-local trace data (see note in `create_response`).
        request.trace.take();

        tracing::debug!(
            base_url = %fuigo_auth::redact_url(&self.base_url),
            model_id = model_id.as_str(),
            "Sending responses API stream request"
        );

        let fuigo_headers = FuigoRequestHeaders {
            conv_id: x_fuigo_conv_id,
            req_id: x_fuigo_req_id,
            model_id: &model_id,
            session_id: request.x_fuigo_session_id.as_deref().unwrap_or_default(),
            turn_idx: request.x_fuigo_turn_idx.as_deref(),
            transient_retry: request.x_fuigo_transient_retry.as_deref(),
            agent_id: request.x_fuigo_agent_id.as_deref().unwrap_or_default(),
            deployment_id: request.x_fuigo_deployment_id.as_deref(),
            user_id: request.x_fuigo_user_id.as_deref(),
            identity: self.identity_disclosure,
        };
        let extra_tool_entries = std::mem::take(&mut request.extra_tool_entries);
        let mut request_body = serde_json::to_value(&request.inner).map_err(|e| {
            tracing::error!("Failed to serialize responses request: {}", e);
            SamplingError::Serialization(e)
        })?;
        // Inject Ferrox Labs-specific fields not in async-openai's CreateResponse type.
        if self.defaults.stream_tool_calls {
            request_body["stream_tool_calls"] = serde_json::json!(true);
        }
        splice_extra_tool_entries(&mut request_body, extra_tool_entries);
        append_response_includes(&mut request_body, &self.defaults.extra_response_includes);
        fuigo_sampling_types::patch_reasoning_text_types(&mut request_body);
        // Programmatic tool calling: carriers -> wire items, `caller` on program calls, `allowed_callers` on tools (no-op when off)
        fuigo_sampling_types::patch_request_body(&mut request_body);
        // Fresh per attempt so signals never leak across retries; `None` (check disabled) sends no header and does no peek work per event
        let doom_loop = self
            .defaults
            .doom_loop_recovery
            .map(crate::doom_loop::DoomLoopSignalCollector::new);
        let SentRequest {
            builder,
            sent_bearer,
        } = self.post(self.endpoint("responses"));
        let mut http_request = fuigo_headers
            .apply(builder)
            .header(ACCEPT, HeaderValue::from_static("text/event-stream"));
        if let Some(policy) = self.defaults.doom_loop_recovery {
            http_request = http_request
                .header(DOOM_LOOP_CHECK_HEADER, policy.window_tokens.to_string())
                .header(
                    EXACT_REPETITION_CHECK_HEADER,
                    DEFAULT_EXACT_REPETITION_MIN_TOKENS.to_string(),
                );
        }
        let http_request = http_request.json(&self.body(&request_body));

        let built_request = http_request.build().map_err(|e| {
            tracing::error!("Failed to build HTTP request: {}", transport_error_for_log(&e));
            SamplingError::Http(e)
        })?;

        tracing::debug!(
            url = %fuigo_auth::redact_url(built_request.url().as_str()),
            method = %built_request.method(),
            "Sending responses API stream request"
        );
        Self::log_request_headers(&built_request, "responses");

        let response = self.dispatch_request(built_request, true).await?;

        let status = response.status();
        let span = tracing::Span::current();
        span.record("status_code", status.as_u16() as i64);
        span.record("success", status.is_success());
        if !status.is_success() {
            if status == reqwest::StatusCode::UNAUTHORIZED {
                span.record("error", "unauthorized (401)");
                self.record_401_attribution(
                    crate::attribution::SamplingConsumer::ResponsesStream,
                    sent_bearer.as_ref(),
                );
                let endpoint = self.endpoint("responses");
                let body = response.bytes().await.unwrap_or_default();
                let server_message = user_facing_api_error_message(status, body.as_ref());
                return Err(auth_rejected(
                    format!("Unauthorized (401) from {endpoint}: {server_message}"),
                    sent_bearer.as_ref(),
                ));
            }
            let model_metadata = extract_model_metadata(response.headers());
            let retry_after_secs = extract_retry_after(status, response.headers());
            let should_retry = extract_should_retry(response.headers());
            let bytes = response.bytes().await?;
            let message = user_facing_api_error_message(status, bytes.as_ref());
            span.record("error", message.as_str());
            tracing::error!(
                status = %status,
                error_message = %message,
                body_preview = %Self::body_preview(bytes.as_ref()),
                model_id = %model_id,
                "responses API error"
            );
            return Err(SamplingError::Api {
                status,
                message,
                model_metadata,
                retry_after_secs,
                should_retry,
                error_code: parse_error_code(bytes.as_ref()),
            });
        }

        let model_metadata = extract_model_metadata(response.headers());

        // Strip UTF-8 BOM if present
        const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];
        let mut is_first = true;
        let byte_stream = response.bytes_stream().map(move |result| {
            result.map(|bytes| {
                if is_first {
                    is_first = false;
                    if bytes.starts_with(UTF8_BOM) {
                        return bytes.slice(UTF8_BOM.len()..);
                    }
                }
                bytes
            })
        });

        let event_stream = byte_stream.eventsource();

        let doom_loop_for_stream = doom_loop.clone();
        let mut codex_output = (self.subscription == Some(crate::subscription::SubscriptionKind::Chatgpt))
            .then(crate::subscription::CodexOutput::default);

        // The scan item is an `Option`: `Some(None)` skips an absorbed doom-loop event without terminating the stream (`filter_map` below)
        // An outer `None` still ends the stream
        let events = event_stream
            .scan(false, move |had_transport_error, event_res| {
                if *had_transport_error {
                    return std::future::ready(None);
                }
                let item = match event_res {
                    Ok(event) => {
                        let data = &event.data;
                        if data == "[DONE]" {
                            return std::future::ready(None);
                        }

                        tracing::info!(
                            target: crate::sampling_log::TARGET,
                            event = "sse_chunk",
                            backend = "responses",
                            data = %data,
                        );

                        // Intercept the non-standard doom-loop event before typed deserialization
                        // async-openai's event enum does not know it and would fail to parse it
                        // With the check disabled, `is_check_event` still guards against a server emitting it without opt-in (rollout skew)
                        let swallow = match &doom_loop_for_stream {
                            Some(collector) => collector.absorb(&event.event, data),
                            None => is_check_event(&event.event, data),
                        };
                        if swallow {
                            Some(None)
                        } else if let Some(stream_error) = try_parse_stream_error(data) {
                            Some(Some(Err(stream_error)))
                        } else {
                            match deserialize_response_event(data) {
                                // A well-formed event whose `type` we do not model: swallow it and
                                // keep the stream alive, exactly as the doom-loop event above does.
                                Ok(None) => Some(None),
                                Ok(Some(mut event)) => {
                                    if let Some(output) = &mut codex_output {
                                        output.observe(&mut event);
                                    }
                                    Some(Some(Ok(event)))
                                }
                                Err(e) => Some(Some(Err(e))),
                            }
                        }
                    }
                    Err(e) => {
                        *had_transport_error = true;
                        Some(Some(Err(SamplingError::EventStreamError(e.to_string()))))
                    }
                };
                std::future::ready(item)
            })
            .filter_map(std::future::ready)
            .boxed();

        Ok((events, model_metadata, doom_loop))
    }

    // =========================================================================
    // Anthropic Messages API
    // =========================================================================

    fn apply_message_defaults(&self, request: &mut MessagesRequestWrapper) -> Result<()> {
        if request.inner.model.is_empty() {
            request.inner.model = self.defaults.model.clone();
        }

        if request.inner.max_tokens == 0 {
            request.inner.max_tokens = self
                .defaults
                .max_completion_tokens
                .unwrap_or(ANTHROPIC_DEFAULT_MAX_TOKENS);
        }

        if request.inner.temperature.is_none() {
            request.inner.temperature = self.defaults.temperature;
        }

        if request.inner.top_p.is_none() {
            request.inner.top_p = self.defaults.top_p;
        }

        Ok(())
    }

    /// Create a message using the Anthropic Messages API (non-streaming).
    pub async fn create_message(
        &self,
        mut request: MessagesRequestWrapper,
    ) -> Result<messages::MessagesResponse> {
        self.apply_message_defaults(&mut request)?;

        let x_fuigo_conv_id = request.x_fuigo_conv_id.as_deref().unwrap_or_default();
        let x_fuigo_req_id = request.x_fuigo_req_id.as_deref().unwrap_or_default();
        let model_id = request.inner.model.clone();

        // Drop process-local trace data.
        request.trace.take();

        tracing::debug!("create_message: {:?}", &request.inner);
        tracing::debug!("endpoint: {:?}", fuigo_auth::redact_url(&self.endpoint("messages")));

        let fuigo_headers = FuigoRequestHeaders {
            conv_id: x_fuigo_conv_id,
            req_id: x_fuigo_req_id,
            model_id: &model_id,
            session_id: request.x_fuigo_session_id.as_deref().unwrap_or_default(),
            turn_idx: request.x_fuigo_turn_idx.as_deref(),
            transient_retry: request.x_fuigo_transient_retry.as_deref(),
            agent_id: request.x_fuigo_agent_id.as_deref().unwrap_or_default(),
            deployment_id: request.x_fuigo_deployment_id.as_deref(),
            user_id: request.x_fuigo_user_id.as_deref(),
            identity: self.identity_disclosure,
        };
        let SentRequest {
            builder,
            sent_bearer,
        } = self.post(self.endpoint("messages"));
        let http_request = fuigo_headers
            .apply(builder)
            .json(&self.body(&request.inner));

        let response = self.dispatch_request(http_request.build().map_err(SamplingError::Http)?, false).await?;

        let status = response.status();
        let model_metadata = extract_model_metadata(response.headers());
        let retry_after_secs = extract_retry_after(status, response.headers());
        let should_retry = extract_should_retry(response.headers());
        let bytes = response.bytes().await?;

        if !status.is_success() {
            if status == reqwest::StatusCode::UNAUTHORIZED {
                self.record_401_attribution(
                    crate::attribution::SamplingConsumer::Messages,
                    sent_bearer.as_ref(),
                );
                let endpoint = self.endpoint("messages");
                let server_message = user_facing_api_error_message(status, bytes.as_ref());
                return Err(auth_rejected(
                    format!("Unauthorized (401) from {endpoint}: {server_message}"),
                    sent_bearer.as_ref(),
                ));
            }

            let message = user_facing_api_error_message(status, bytes.as_ref());
            tracing::warn!(
                status = %status,
                error_message = %message,
                body_preview = %Self::body_preview(bytes.as_ref()),
                model_id = %model_id,
                "messages API error"
            );
            return Err(SamplingError::Api {
                status,
                message,
                model_metadata,
                retry_after_secs,
                should_retry,
                error_code: parse_error_code(bytes.as_ref()),
            });
        }

        let response_obj =
            serde_json::from_slice::<messages::MessagesResponse>(&bytes)
                .map_err(|e| serde_failure("MessagesResponse", &e, bytes.len()))?;
        Ok(response_obj)
    }

    /// Create a streaming message using the Anthropic Messages API.
    #[tracing::instrument(
        name = "http.create_message_stream",
        skip_all,
        fields(
            endpoint = %fuigo_auth::redact_url(&self.endpoint("messages")),
            model_id = request.inner.model.as_str(),
            status_code = tracing::field::Empty,
            success = tracing::field::Empty,
            error = tracing::field::Empty,
        )
    )]
    pub async fn create_message_stream(
        &self,
        mut request: MessagesRequestWrapper,
    ) -> Result<(
        BoxStream<'static, Result<messages::MessageStreamEvent>>,
        Option<ResponseModelMetadata>,
    )> {
        self.apply_message_defaults(&mut request)?;

        request.inner.stream = Some(true);

        let x_fuigo_conv_id = request.x_fuigo_conv_id.as_deref().unwrap_or_default();
        let x_fuigo_req_id = request.x_fuigo_req_id.as_deref().unwrap_or_default();
        let model_id = request.inner.model.clone();

        // Drop process-local trace data.
        request.trace.take();

        tracing::debug!(
            base_url = %fuigo_auth::redact_url(&self.base_url),
            model_id = model_id.as_str(),
            "Sending Messages API stream request"
        );

        let fuigo_headers = FuigoRequestHeaders {
            conv_id: x_fuigo_conv_id,
            req_id: x_fuigo_req_id,
            model_id: &model_id,
            session_id: request.x_fuigo_session_id.as_deref().unwrap_or_default(),
            turn_idx: request.x_fuigo_turn_idx.as_deref(),
            transient_retry: request.x_fuigo_transient_retry.as_deref(),
            agent_id: request.x_fuigo_agent_id.as_deref().unwrap_or_default(),
            deployment_id: request.x_fuigo_deployment_id.as_deref(),
            user_id: request.x_fuigo_user_id.as_deref(),
            identity: self.identity_disclosure,
        };
        let SentRequest {
            builder,
            sent_bearer,
        } = self.post(self.endpoint("messages"));
        let http_request = fuigo_headers
            .apply(builder)
            .header(ACCEPT, HeaderValue::from_static("text/event-stream"))
            .json(&self.body(&request.inner));

        let built_request = http_request.build().map_err(|e| {
            tracing::error!("Failed to build HTTP request: {}", transport_error_for_log(&e));
            SamplingError::Http(e)
        })?;

        tracing::debug!(
            url = %fuigo_auth::redact_url(built_request.url().as_str()),
            method = %built_request.method(),
            "Sending messages API stream request"
        );
        Self::log_request_headers(&built_request, "messages");

        let response = self.dispatch_request(built_request, true).await?;

        let status = response.status();
        let span = tracing::Span::current();
        span.record("status_code", status.as_u16() as i64);
        span.record("success", status.is_success());
        if !status.is_success() {
            if status == reqwest::StatusCode::UNAUTHORIZED {
                span.record("error", "unauthorized (401)");
                self.record_401_attribution(
                    crate::attribution::SamplingConsumer::MessagesStream,
                    sent_bearer.as_ref(),
                );
                let endpoint = self.endpoint("messages");
                let body = response.bytes().await.unwrap_or_default();
                let server_message = user_facing_api_error_message(status, body.as_ref());
                return Err(auth_rejected(
                    format!("Unauthorized (401) from {endpoint}: {server_message}"),
                    sent_bearer.as_ref(),
                ));
            }
            let model_metadata = extract_model_metadata(response.headers());
            let retry_after_secs = extract_retry_after(status, response.headers());
            let should_retry = extract_should_retry(response.headers());
            let bytes = response.bytes().await?;
            let message = user_facing_api_error_message(status, bytes.as_ref());
            span.record("error", message.as_str());
            tracing::error!(
                status = %status,
                error_message = %message,
                body_preview = %Self::body_preview(bytes.as_ref()),
                model_id = %model_id,
                "messages API error"
            );
            return Err(SamplingError::Api {
                status,
                message,
                model_metadata,
                retry_after_secs,
                should_retry,
                error_code: parse_error_code(bytes.as_ref()),
            });
        }

        let model_metadata = extract_model_metadata(response.headers());

        // Strip UTF-8 BOM if present
        const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];
        let mut is_first = true;
        let byte_stream = response.bytes_stream().map(move |result| {
            result.map(|bytes| {
                if is_first {
                    is_first = false;
                    if bytes.starts_with(UTF8_BOM) {
                        return bytes.slice(UTF8_BOM.len()..);
                    }
                }
                bytes
            })
        });

        let event_stream = byte_stream.eventsource();

        // Map SSE events into MessageStreamEvent.
        // Uses `scan` so transport errors terminate the stream after the first error (same pattern as `chat_completion_stream`)
        // The scan item is an `Option`: `Some(None)` skips an event type this client does not model
        // without terminating the stream (`filter_map` below), exactly as the Responses backend does
        // An outer `None` still ends the stream
        let events = event_stream
            .scan(false, |had_transport_error, event_res| {
                if *had_transport_error {
                    return std::future::ready(None);
                }
                let item = match event_res {
                    Ok(event) => {
                        let data = &event.data;
                        if data == "[DONE]" {
                            return std::future::ready(None);
                        }

                        tracing::info!(
                            target: crate::sampling_log::TARGET,
                            event = "sse_chunk",
                            backend = "messages",
                            data = %data,
                        );

                        if let Some(stream_error) = try_parse_stream_error(data) {
                            Some(Some(Err(stream_error)))
                        } else {
                            // Anthropic adds SSE event types without a version bump. An unmodelled
                            // `type` is skipped so the turn survives; a MODELLED `type` carrying a
                            // malformed body still fails closed, because silently dropping a
                            // corrupt `message_stop` would hang the turn instead of erroring.
                            match parse_sse_event::<messages::MessageStreamEvent>("messages", data)
                            {
                                Ok(Some(event)) => Some(Some(Ok(event))),
                                Ok(None) => Some(None),
                                Err(e) => Some(Some(Err(serde_failure(
                                    "MessageStreamEvent from stream",
                                    &e,
                                    data.len(),
                                )))),
                            }
                        }
                    }
                    Err(e) => {
                        *had_transport_error = true;
                        Some(Some(Err(SamplingError::EventStreamError(e.to_string()))))
                    }
                };
                std::future::ready(item)
            })
            .filter_map(std::future::ready)
            .boxed();

        Ok((events, model_metadata))
    }

    // =========================================================================
    // Unified Conversation API
    // =========================================================================

    fn apply_conversation_defaults(&self, request: &mut ConversationRequest) -> Result<()> {
        if request.model.is_none() {
            request.model = Some(self.defaults.model.clone());
        }

        if request.temperature.is_none() {
            request.temperature = self.defaults.temperature;
        }

        if request.top_p.is_none() {
            request.top_p = self.defaults.top_p;
        }

        if request.max_output_tokens.is_none() {
            request.max_output_tokens = self.defaults.max_completion_tokens;
        }

        if self.subscription.is_some() {
            crate::subscription::retain_reasoning_for_model(&mut request.items, request.model.as_deref().unwrap_or(&self.defaults.model));
        }
        Ok(())
    }

    /// Send a conversation request using the Chat Completions API (streaming).
    pub async fn conversation_stream(
        &self,
        mut request: ConversationRequest,
    ) -> Result<(
        BoxStream<'static, Result<ChatCompletionChunk>>,
        Option<ResponseModelMetadata>,
    )> {
        self.apply_conversation_defaults(&mut request)?;

        let trace = request.trace.take();
        let mut chat_request: ChatCompletionRequest = request.into();
        if let Some(trace) = trace {
            chat_request.trace = Some(trace);
        }

        self.chat_completion_stream(chat_request).await
    }

    /// Send a conversation request using the Chat Completions API (non-streaming).
    pub async fn conversation(
        &self,
        mut request: ConversationRequest,
    ) -> Result<ChatCompletionResponse> {
        self.apply_conversation_defaults(&mut request)?;

        let trace = request.trace.take();
        let mut chat_request: ChatCompletionRequest = request.into();
        if let Some(trace) = trace {
            chat_request.trace = Some(trace);
        }

        self.chat_completion(chat_request).await
    }

    /// Send a conversation request using the Responses API (streaming).
    ///
    /// The third tuple element is the per-request doom-loop signal collector (see [`Self::create_response_stream`]).
    /// Callers that don't consume the signals can ignore it.
    #[allow(clippy::type_complexity)]
    pub async fn conversation_stream_responses(
        &self,
        mut request: ConversationRequest,
    ) -> Result<(
        BoxStream<'static, Result<rs::ResponseStreamEvent>>,
        Option<ResponseModelMetadata>,
        Option<crate::doom_loop::DoomLoopSignalCollector>,
    )> {
        self.apply_conversation_defaults(&mut request)?;

        let trace = request.trace.take();
        let x_fuigo_conv_id = request.x_fuigo_conv_id.clone();
        let x_fuigo_req_id = request.x_fuigo_req_id.clone();
        let x_fuigo_session_id = request.x_fuigo_session_id.clone();
        let x_fuigo_turn_idx = request.x_fuigo_turn_idx.clone();
        let x_fuigo_transient_retry = request.x_fuigo_transient_retry.clone();
        let x_fuigo_agent_id = request.x_fuigo_agent_id.clone();

        // The hosted tools travel as raw JSON, spliced in after serialization by `splice_extra_tool_entries`, whose doc explains why each one does
        let extra_tools = fuigo_sampling_types::extra_tool_entries(&request.hosted_tools);

        let responses_request: rs::CreateResponse = (&request).into();

        let mut wrapper = CreateResponseWrapper::new(responses_request);
        wrapper.x_fuigo_conv_id = x_fuigo_conv_id;
        wrapper.x_fuigo_req_id = x_fuigo_req_id;
        wrapper.x_fuigo_session_id = x_fuigo_session_id;
        wrapper.x_fuigo_turn_idx = x_fuigo_turn_idx;
        wrapper.x_fuigo_transient_retry = x_fuigo_transient_retry;
        wrapper.x_fuigo_agent_id = x_fuigo_agent_id;
        wrapper.extra_tool_entries = extra_tools;
        wrapper.suppress_reasoning_summary = request.suppress_reasoning_summary;

        if let Some(trace) = trace {
            wrapper.trace = Some(trace);
        }

        self.create_response_stream(wrapper).await
    }

    /// Send a conversation request using the Responses API (non-streaming).
    pub async fn conversation_responses(
        &self,
        mut request: ConversationRequest,
    ) -> Result<rs::Response> {
        self.apply_conversation_defaults(&mut request)?;

        let trace = request.trace.take();
        let x_fuigo_conv_id = request.x_fuigo_conv_id.clone();
        let x_fuigo_req_id = request.x_fuigo_req_id.clone();
        let x_fuigo_session_id = request.x_fuigo_session_id.clone();
        let x_fuigo_turn_idx = request.x_fuigo_turn_idx.clone();
        let x_fuigo_transient_retry = request.x_fuigo_transient_retry.clone();
        let x_fuigo_agent_id = request.x_fuigo_agent_id.clone();

        // The hosted tools travel as raw JSON, spliced in by `create_response` via `splice_extra_tool_entries`, whose doc explains why
        let extra_tools = fuigo_sampling_types::extra_tool_entries(&request.hosted_tools);

        let responses_request: rs::CreateResponse = (&request).into();

        let mut wrapper = CreateResponseWrapper::new(responses_request);
        wrapper.x_fuigo_conv_id = x_fuigo_conv_id;
        wrapper.x_fuigo_req_id = x_fuigo_req_id;
        wrapper.x_fuigo_session_id = x_fuigo_session_id;
        wrapper.x_fuigo_turn_idx = x_fuigo_turn_idx;
        wrapper.x_fuigo_transient_retry = x_fuigo_transient_retry;
        wrapper.x_fuigo_agent_id = x_fuigo_agent_id;
        wrapper.extra_tool_entries = extra_tools;
        wrapper.suppress_reasoning_summary = request.suppress_reasoning_summary;

        if let Some(trace) = trace {
            wrapper.trace = Some(trace);
        }

        self.create_response(wrapper).await
    }

    /// Send a conversation request using the Anthropic Messages API (streaming).
    pub async fn conversation_stream_messages(
        &self,
        mut request: ConversationRequest,
    ) -> Result<(
        BoxStream<'static, Result<messages::MessageStreamEvent>>,
        Option<ResponseModelMetadata>,
    )> {
        self.apply_conversation_defaults(&mut request)?;

        let trace = request.trace.take();
        let x_fuigo_conv_id = request.x_fuigo_conv_id.clone();
        let x_fuigo_req_id = request.x_fuigo_req_id.clone();
        let x_fuigo_session_id = request.x_fuigo_session_id.clone();
        let x_fuigo_turn_idx = request.x_fuigo_turn_idx.clone();
        let x_fuigo_transient_retry = request.x_fuigo_transient_retry.clone();
        let x_fuigo_agent_id = request.x_fuigo_agent_id.clone();

        let messages_request = build_messages_request(&request);

        let mut wrapper = MessagesRequestWrapper::new(messages_request);
        wrapper.x_fuigo_conv_id = x_fuigo_conv_id;
        wrapper.x_fuigo_req_id = x_fuigo_req_id;
        wrapper.x_fuigo_session_id = x_fuigo_session_id;
        wrapper.x_fuigo_turn_idx = x_fuigo_turn_idx;
        wrapper.x_fuigo_transient_retry = x_fuigo_transient_retry;
        wrapper.x_fuigo_agent_id = x_fuigo_agent_id;

        if let Some(trace) = trace {
            wrapper.trace = Some(trace);
        }

        self.create_message_stream(wrapper).await
    }

    /// Send a conversation request using the Anthropic Messages API (non-streaming).
    pub async fn conversation_messages(
        &self,
        mut request: ConversationRequest,
    ) -> Result<messages::MessagesResponse> {
        self.apply_conversation_defaults(&mut request)?;

        let trace = request.trace.take();
        let x_fuigo_conv_id = request.x_fuigo_conv_id.clone();
        let x_fuigo_req_id = request.x_fuigo_req_id.clone();
        let x_fuigo_session_id = request.x_fuigo_session_id.clone();
        let x_fuigo_turn_idx = request.x_fuigo_turn_idx.clone();
        let x_fuigo_transient_retry = request.x_fuigo_transient_retry.clone();
        let x_fuigo_agent_id = request.x_fuigo_agent_id.clone();

        let messages_request = build_messages_request(&request);

        let mut wrapper = MessagesRequestWrapper::new(messages_request);
        wrapper.x_fuigo_conv_id = x_fuigo_conv_id;
        wrapper.x_fuigo_req_id = x_fuigo_req_id;
        wrapper.x_fuigo_session_id = x_fuigo_session_id;
        wrapper.x_fuigo_turn_idx = x_fuigo_turn_idx;
        wrapper.x_fuigo_transient_retry = x_fuigo_transient_retry;
        wrapper.x_fuigo_agent_id = x_fuigo_agent_id;

        if let Some(trace) = trace {
            wrapper.trace = Some(trace);
        }

        self.create_message(wrapper).await
    }

    /// Backend-aware streaming call that collects the full response.
    ///
    /// Honors the request's [`LengthPolicy`](fuigo_sampling_types::LengthPolicy) like the actor path.
    /// The default still fails a text-only or empty `Length` stop, so side callers never persist a silently truncated result.
    pub async fn conversation_collect(
        &self,
        request: ConversationRequest,
    ) -> Result<ConversationResponse> {
        self.conversation_collect_with_idle_timeout(request, std::time::Duration::from_secs(300))
            .await
    }

    /// [`Self::conversation_collect`] with a caller-chosen idle timeout, for short side calls (autocomplete, memory notes) that must give up fast.
    pub async fn conversation_collect_with_idle_timeout(
        &self,
        request: ConversationRequest,
        idle_timeout: std::time::Duration,
    ) -> Result<ConversationResponse> {
        let request_id = crate::types::RequestId::random();
        let receipt = crate::request_accounting::Attempt::new(&request, request_id.as_str(), 1);
        let collect = async {
        let length_policy = request.length_policy;
        let result = match self.api_backend() {
            ApiBackend::ChatCompletions => {
                let (raw, meta) = self.conversation_stream(request).await?;
                let events =
                    crate::stream::stream_chat_completions(raw, meta, request_id, idle_timeout);
                crate::stream::collect_response(events).await
            }
            ApiBackend::Responses => {
                let client_tools: std::collections::HashSet<String> =
                    request.tools.iter().map(|t| t.name.clone()).collect();
                let (raw, meta, doom_loop) = self.conversation_stream_responses(request).await?;
                let events = crate::stream::stream_responses(
                    raw,
                    meta,
                    request_id,
                    idle_timeout,
                    doom_loop,
                    client_tools,
                );
                crate::stream::collect_response(events).await
            }
            ApiBackend::Messages => {
                let (raw, meta) = self.conversation_stream_messages(request).await?;
                let events = crate::stream::stream_messages(raw, meta, request_id, idle_timeout);
                crate::stream::collect_response(events).await
            }
        };
        let response = result
            .map(|(response, _metrics)| response)
            .map_err(stream_collect_error)?;
        apply_length_policy(length_policy, response)
        };
        let result = receipt.scope(collect).await;
        match &result {
            Ok(response) => receipt.finish(crate::request_accounting::Outcome::Completed,
                response.usage.clone(), response.cost_usd_ticks),
            Err(_) => receipt.finish(crate::request_accounting::Outcome::Failed, None, None),
        }
        if result.is_ok() {
            receipt.settle_execution().await.map_err(|_|
                SamplingError::InvalidConfiguration("execution receipt settlement could not be persisted"))?;
        }
        result
    }
}

/// Applies the request's [`fuigo_sampling_types::LengthPolicy`] to a collected response.
/// Fails a `Length` stop the policy rejects, logs the salvage breadcrumb otherwise.
/// The single gate shared by `drive_l2` and the direct-collect path so the two cannot drift.
pub(crate) fn apply_length_policy(
    policy: fuigo_sampling_types::LengthPolicy,
    response: fuigo_sampling_types::ConversationResponse,
) -> Result<fuigo_sampling_types::ConversationResponse> {
    use fuigo_sampling_types::LengthVerdict;
    match policy.verdict(&response) {
        LengthVerdict::Pass => Ok(response),
        LengthVerdict::Fail => Err(SamplingError::MaxTokensTruncation),
        LengthVerdict::Salvage => {
            // Breadcrumb for "why did the user get half an answer".
            tracing::info!(
                content_len = response.assistant().map_or(0, |a| a.content.len()),
                completion_tokens = response.usage.as_ref().map(|u| u.completion_tokens),
                "salvaging Length-truncated response per LengthPolicy::CompletePartial"
            );
            Ok(response)
        }
        LengthVerdict::SalvageToolCalls => {
            // Breadcrumb for counting turns rescued from max_tokens_truncation.
            tracing::info!(
                tool_calls = response.tool_calls().len(),
                content_len = response.assistant().map_or(0, |a| a.content.len()),
                completion_tokens = response.usage.as_ref().map(|u| u.completion_tokens),
                "completing Length-truncated response with completed tool calls"
            );
            Ok(response)
        }
    }
}

/// Rebuild `Api` from stream-collected info, preserving status, `Retry-After`, and `x-should-retry` (kind is lost on this path).
fn stream_collect_error(info: SamplingErrorInfo) -> SamplingError {
    SamplingError::Api {
        status: info
            .status_code
            .and_then(|c| reqwest::StatusCode::from_u16(c).ok())
            .unwrap_or(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
        message: info.message,
        model_metadata: info.model_metadata,
        retry_after_secs: info.retry_after_secs,
        should_retry: info.should_retry,
        error_code: info.error_code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Bytes, routing::post};
    use fuigo_sampling_types::ApiErrorCode;
    use fuigo_sampling_types::types::ChatRequestMessage;
    use indexmap::IndexMap;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    /// The model-limit headers are read off the PROVIDER's response, so their names are the
    /// provider's spelling. The 1.0.1 mechanical rebrand rewrote them to `x-fuigo-*`, which no
    /// provider sends, so a proxy that reports limits was silently ignored.
    #[test]
    fn model_metadata_is_read_from_the_providers_header_spelling() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-grok-context-window", "131072".parse().unwrap());
        headers.insert("x-grok-max-completion-tokens", "8192".parse().unwrap());
        let meta = extract_model_metadata(&headers)
            .expect("the provider's x-grok-* limit headers must populate the metadata");
        assert_eq!(meta.context_window, Some(131072));
        assert_eq!(meta.max_completion_tokens, Some(8192));

        let mut rebranded = reqwest::header::HeaderMap::new();
        rebranded.insert("x-fuigo-context-window", "131072".parse().unwrap());
        rebranded.insert("x-fuigo-max-completion-tokens", "8192".parse().unwrap());
        assert!(
            extract_model_metadata(&rebranded).is_none(),
            "`x-fuigo-*` is a rebrand artefact no provider sends; it must not be honoured"
        );
    }

    #[test]
    fn splice_extra_tool_entries_extends_existing_tools_array() {
        let mut body = serde_json::json!({ "tools": [{ "type": "function" }] });
        splice_extra_tool_entries(&mut body, vec![serde_json::json!({ "type": "web_search" })]);
        assert_eq!(
            body["tools"],
            serde_json::json!([{ "type": "function" }, { "type": "web_search" }])
        );
    }

    #[test]
    fn splice_extra_tool_entries_creates_tools_array_when_absent() {
        let mut body = serde_json::json!({});
        splice_extra_tool_entries(&mut body, vec![serde_json::json!({ "type": "web_search" })]);
        assert_eq!(body["tools"], serde_json::json!([{ "type": "web_search" }]));
    }

    #[test]
    fn splice_extra_tool_entries_noop_when_empty() {
        let mut body = serde_json::json!({ "tools": [{ "type": "function" }] });
        splice_extra_tool_entries(&mut body, vec![]);
        assert_eq!(body["tools"], serde_json::json!([{ "type": "function" }]));
    }

    #[test]
    fn stream_collect_error_preserves_should_retry() {
        let info = SamplingErrorInfo {
            kind: crate::events::SamplingErrorKind::Api,
            status_code: Some(529),
            message: "Overloaded".into(),
            is_retryable: true,
            retry_after_secs: Some(3),
            should_retry: Some(false),
            error_code: Some(ApiErrorCode::InvalidImage),
            model_metadata: None,
            empty_response_context: None,
            doom_loop_triggers: None,
            doom_loop_aborted_at_chunk: None,
            credential: fuigo_sampling_types::SentCredential::Unknown,
        };
        // SamplingError is not PartialEq (it carries reqwest/serde errors), so destructure once and compare all fields in a single assert
        let SamplingError::Api {
            status,
            message,
            model_metadata,
            retry_after_secs,
            should_retry,
            error_code,
        } = stream_collect_error(info)
        else {
            panic!("expected Api");
        };
        assert_eq!(
            (
                status.as_u16(),
                message.as_str(),
                model_metadata.is_none(),
                retry_after_secs,
                should_retry,
                error_code,
            ),
            (
                529,
                "Overloaded",
                true,
                Some(3),
                Some(false),
                Some(ApiErrorCode::InvalidImage)
            ),
        );
    }

    // ── P15: x-fuigo-* identity headers are FluxRouter-operated only ──────

    /// The identity headers a FluxRouter-operated route legitimately needs.
    fn identity_config(base_url: &str) -> SamplerConfig {
        SamplerConfig {
            base_url: base_url.to_string(),
            client_version: Some("1.0.21".to_string()),
            deployment_id: Some("dep-uuid-v5".to_string()),
            user_id: Some("ferrox-account-id".to_string()),
            client_identifier: Some("fuigo-cli".to_string()),
            ..minimal_config()
        }
    }

    fn built_identity_headers(base_url: &str) -> HeaderMap {
        let config = identity_config(base_url);
        let identity = IdentityDisclosure::for_destination(&config.base_url);
        let mut headers = HeaderMap::new();
        apply_identity_headers(&mut headers, &config, identity);
        headers
    }

    /// THE LEAK. Fails on the baseline, where these were written unconditionally.
    ///
    /// `x-fuigo-user-id` is the Ferrox account id and `x-fuigo-deployment-id` the tenant
    /// UUID. Both are stable and identical across every provider a user configures, so
    /// sending them to third parties lets unrelated vendors correlate one user's traffic.
    #[test]
    fn third_party_destinations_receive_no_fuigo_identity_headers() {
        for base_url in [
            "https://api.openai.com/v1",
            "https://api.anthropic.com/v1",
            "https://api.x.ai/v1",
            "https://openrouter.ai/api/v1",
            "http://127.0.0.1:8080/v1",
            "https://api.fluxrouter.ai.evil.example/v1",
            "https://api.fluxrouter.ai@evil.example/v1",
            // M11. The right host over cleartext: an observer on the path reads the
            // account id, so the host being correct does not make it FluxRouter-operated.
            "http://api.fluxrouter.ai/v1",
        ] {
            let headers = built_identity_headers(base_url);
            assert!(
                headers.is_empty(),
                "{base_url} received x-fuigo-* identity headers: {headers:?}"
            );
            for name in [
                "x-fuigo-user-id",
                "x-fuigo-deployment-id",
                "x-fuigo-client-version",
                "x-fuigo-client-identifier",
            ] {
                assert!(
                    !headers.contains_key(name),
                    "{base_url} must not receive {name}"
                );
            }
        }
    }

    /// The other half: gating must not break proxy version gating, which is a real feature.
    #[test]
    fn fluxrouter_operated_destination_still_receives_every_identity_header() {
        let headers = built_identity_headers("https://api.fluxrouter.ai/v1");
        for (name, expected) in [
            ("x-fuigo-user-id", "ferrox-account-id"),
            ("x-fuigo-deployment-id", "dep-uuid-v5"),
            ("x-fuigo-client-version", "1.0.21"),
            ("x-fuigo-client-identifier", "fuigo-cli"),
        ] {
            assert_eq!(
                headers.get(name).and_then(|v| v.to_str().ok()),
                Some(expected),
                "FluxRouter-operated route lost {name}"
            );
        }
    }

    /// One `reqwest::Client` for every header probe in this module. A shared constructor
    /// rather than one per test: `reqwest::Client::new` is a `clippy::disallowed_method` here
    /// (the workspace routes real traffic through `fuigo_extra_ca::dispatch`), and these probes
    /// never dispatch — they build a request and read its headers.
    fn probe_builder(url: &str) -> reqwest::RequestBuilder {
        reqwest::Client::new().post(url)
    }

    /// THE P15-R PIN. The per-request namespace splits by **what each header discloses**, not
    /// by "is this `x-fuigo-*`".
    ///
    /// P15 returned the builder untouched for every other destination, so all nine went.
    /// Five of them are per-session randoms or per-turn counters that identify nobody across
    /// two destinations, and two live behaviours read them off the FluxRouter-operated route: a
    /// self-hosted gateway counts retry traffic by `x-fuigo-transient-retry`, and
    /// `fuigo_test_support::inference_override` classifies foreground against auxiliary calls
    /// on `-turn-idx`/`-req-id` (falling through to a body heuristic when absent, so it
    /// MISROUTES rather than failing). `x-fuigo-agent-id` is the one P15 was most right about:
    /// a persisted machine id that survives logout.
    ///
    /// Asserted as set equality against [`PER_REQUEST_UNGATED_HEADERS`] and
    /// [`PER_REQUEST_IDENTITY_HEADERS`], so a header added to `apply` without being classified
    /// fails here and is named — this is the namespace enumeration, executable.
    #[test]
    fn per_request_namespace_splits_by_disclosure() {
        fn header_names(identity: IdentityDisclosure) -> Vec<String> {
            let h = FuigoRequestHeaders {
                conv_id: "conv",
                req_id: "req",
                model_id: "model",
                session_id: "session",
                turn_idx: Some("1"),
                transient_retry: Some("2"),
                agent_id: "stable-machine-id",
                deployment_id: Some("dep-uuid-v5"),
                user_id: Some("ferrox-account-id"),
                identity,
            };
            let request = h
                .apply(probe_builder("https://example.test/v1"))
                .build()
                .expect("request builds");
            let mut names: Vec<String> = request
                .headers()
                .keys()
                .map(|k| k.as_str().to_string())
                .filter(|k| k.starts_with("x-fuigo-"))
                .collect();
            names.sort();
            names
        }

        let sorted = |names: &[&str]| {
            let mut v: Vec<String> = names.iter().map(|s| (*s).to_string()).collect();
            v.sort();
            v
        };

        // Third party / loopback: the ungated half, exactly, nothing more and nothing less.
        assert_eq!(
            header_names(IdentityDisclosure::WITHHELD),
            sorted(&PER_REQUEST_UNGATED_HEADERS),
            "a withheld-identity request does not carry exactly the ungated half"
        );
        for name in PER_REQUEST_IDENTITY_HEADERS {
            assert!(
                !header_names(IdentityDisclosure::WITHHELD).contains(&name.to_string()),
                "a withheld-identity request carried the identity header {name}"
            );
        }

        // FluxRouter-operated: both halves, so the gate cannot be "fixed" by simply turning it off in
        // the other direction either.
        let mut both: Vec<&str> = PER_REQUEST_UNGATED_HEADERS.to_vec();
        both.extend(PER_REQUEST_IDENTITY_HEADERS);
        assert_eq!(
            header_names(IdentityDisclosure::for_destination("https://api.fluxrouter.ai/v1")),
            sorted(&both),
            "a FluxRouter-operated request does not carry the whole namespace"
        );

        // The two halves are disjoint, and every name is spelled inside the namespace.
        for name in both {
            assert!(
                name.starts_with("x-fuigo-"),
                "{name} is not an x-fuigo-* name"
            );
            assert!(
                PER_REQUEST_UNGATED_HEADERS.contains(&name)
                    != PER_REQUEST_IDENTITY_HEADERS.contains(&name),
                "{name} is in both halves or neither"
            );
        }
    }

    /// The values must be the ones asked for, not just the names. A header written with the
    /// wrong value correlates nothing and is as broken as a missing one.
    #[test]
    fn the_ungated_half_carries_its_values_to_a_third_party() {
        let h = FuigoRequestHeaders {
            conv_id: "conv-7f3a",
            req_id: "req-91c2",
            model_id: "an-opaque-third-party-routing-name",
            session_id: "sess-4d0e",
            turn_idx: Some("3"),
            transient_retry: Some("2"),
            agent_id: "stable-machine-id",
            deployment_id: Some("dep-uuid-v5"),
            user_id: Some("ferrox-account-id"),
            identity: IdentityDisclosure::WITHHELD,
        };
        let request = h
            .apply(probe_builder("https://api.openai.com/v1"))
            .build()
            .expect("request builds");
        for (name, expected) in [
            (H_CONV_ID, "conv-7f3a"),
            (H_REQ_ID, "req-91c2"),
            (H_SESSION_ID, "sess-4d0e"),
            (H_TURN_IDX, "3"),
            (H_TRANSIENT_RETRY, "2"),
            (H_MODEL_OVERRIDE, "an-opaque-third-party-routing-name"),
        ] {
            assert_eq!(
                request.headers().get(name).and_then(|v| v.to_str().ok()),
                Some(expected),
                "{name} did not reach a third-party destination with its value"
            );
        }
    }

    /// `turn_idx` and `transient_retry` are `Option`, and a first turn with no resubmit has
    /// neither. Pinned so the "absent" case stays absent rather than becoming an empty header,
    /// which `inference_override::classify` treats as not-present anyway (`nonempty_header`).
    #[test]
    fn absent_optional_correlators_are_omitted_not_empty() {
        let h = FuigoRequestHeaders {
            conv_id: "conv",
            req_id: "req",
            model_id: "model",
            session_id: "session",
            turn_idx: None,
            transient_retry: None,
            agent_id: "agent",
            deployment_id: None,
            user_id: None,
            identity: IdentityDisclosure::WITHHELD,
        };
        let request = h
            .apply(probe_builder("https://api.openai.com/v1"))
            .build()
            .expect("request builds");
        assert!(request.headers().get(H_TURN_IDX).is_none());
        assert!(request.headers().get(H_TRANSIENT_RETRY).is_none());
        assert!(request.headers().get(H_CONV_ID).is_some());
    }

    /// The client-level half is enumerated too, so `CLIENT_IDENTITY_HEADERS` cannot drift from
    /// what `apply_identity_headers` actually writes.
    #[test]
    fn client_identity_headers_enumerate_what_the_fluxrouter_operated_client_writes() {
        let headers = built_identity_headers("https://api.fluxrouter.ai/v1");
        let mut written: Vec<String> = headers.keys().map(|k| k.as_str().to_string()).collect();
        written.sort();
        let mut expected: Vec<String> = CLIENT_IDENTITY_HEADERS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        expected.sort();
        expected.dedup();
        assert_eq!(
            written, expected,
            "CLIENT_IDENTITY_HEADERS does not enumerate apply_identity_headers"
        );
    }

    fn minimal_config() -> SamplerConfig {
        SamplerConfig {
            api_key: Some("test-key".to_string()),
            base_url: "https://example.test".to_string(),
            model: "test-model".to_string(),
            max_completion_tokens: None,
            temperature: None,
            top_p: None,
            api_backend: ApiBackend::ChatCompletions,
            auth_scheme: AuthScheme::Bearer,
            extra_headers: IndexMap::new(),
            extra_response_includes: Vec::new(),
            query_params: IndexMap::new(),
            env_http_headers: IndexMap::new(),
            context_window: 8192,
            force_http1: false,
            max_retries: None,
            stream_tool_calls: false,
            idle_timeout_secs: None,
            reasoning_effort: None,
            origin_client: None,
            client_identifier: None,
            deployment_id: None,
            user_id: None,
            client_version: None,
            attribution_callback: None,
            bearer_resolver: None,
            supports_backend_search: false,
            programmatic_tool_calling: false,
            compactions_remaining: None,
            compaction_at_tokens: None,
            doom_loop_recovery: None,
            subscription: None,
            subscription_resolver: None,
            header_injector: None,
            mtls_cert_dir: None,
            rate_limit_retry_threshold: None,
            reasoning_summary: None,
        }
    }

    /// The serialized StreamingChatRequest flattens all ChatCompletionRequest fields at top level.
    /// The wrapper adds `stream: true` and `stream_options.include_usage: true`.
    #[test]
    fn streaming_chat_request_serializes_correctly() {
        let request = ChatCompletionRequest {
            model: Some("test-model".into()),
            messages: vec![ChatRequestMessage::user("hello")],
            temperature: Some(0.7),
            max_tokens: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
            user: None,
            tools: None,
            tool_choice: None,
            search_parameters: None,
            response_format: None,
            reasoning_effort: None,
            x_fuigo_conv_id: None,
            x_fuigo_req_id: None,
            x_fuigo_session_id: None,
            x_fuigo_turn_idx: None,
            x_fuigo_transient_retry: None,
            x_fuigo_agent_id: None,
            x_fuigo_deployment_id: None,
            x_fuigo_user_id: None,
            trace: None,
        };

        let wrapper = StreamingChatRequest {
            inner: &request,
            stream: true,
            stream_options: StreamOptions {
                include_usage: true,
            },
        };

        let json: serde_json::Value = serde_json::to_value(&wrapper).unwrap();
        let obj = json.as_object().unwrap();

        assert_eq!(obj.get("stream").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            obj.get("stream_options")
                .and_then(|v| v.get("include_usage"))
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        assert!(
            !obj.keys().any(|k| k.starts_with("x_fuigo_")),
            "x_fuigo_* are header fields and must never serialize into the body: {:?}",
            obj.keys().collect::<Vec<_>>()
        );

        assert!(
            obj.get("inner").is_none(),
            "inner field should be flattened"
        );
        assert_eq!(
            obj.get("model").and_then(|v| v.as_str()),
            Some("test-model")
        );
        assert!(obj.get("messages").is_some());
        let temp = obj.get("temperature").and_then(|v| v.as_f64()).unwrap();
        assert!((temp - 0.7).abs() < 0.001, "temperature should be ~0.7");

        assert!(obj.get("max_tokens").is_none());
        assert!(obj.get("tools").is_none());
    }

    /// The body wrapper is inert without the bypass: every wire payload leaves byte-for-byte as before, so a non-FluxRouter provider sees no change at all.
    /// With it, the payload's own bytes still lead and only `cache` is appended.
    #[test]
    fn request_body_wrapper_changes_no_payload_byte_and_appends_only_cache() {
        let chat =
            ChatCompletionRequest::new("test-model", vec![ChatRequestMessage::user("hello")]);
        let streaming = StreamingChatRequest {
            inner: &chat,
            stream: true,
            stream_options: StreamOptions {
                include_usage: true,
            },
        };
        let responses = serde_json::json!({"model": "test-model", "input": "hello", "include": ["reasoning.encrypted_content"], "stream": true});
        let messages = messages::MessagesRequest {
            model: "test-model".into(),
            messages: vec![messages::Message {
                role: messages::MessageRole::User,
                content: messages::MessageContent::Text("hello".into()),
            }],
            max_tokens: 1024,
            stream: Some(true),
            ..Default::default()
        };
        let other = SamplingClient::new(SamplerConfig {
            base_url: "https://api.openai.com/v1".into(),
            ..minimal_config()
        })
        .unwrap();
        let flux = SamplingClient::new(SamplerConfig {
            base_url: "https://api.fluxrouter.ai/v1".into(),
            ..minimal_config()
        })
        .unwrap();
        fn check<T: Serialize>(other: &SamplingClient, flux: &SamplingClient, payload: &T) {
            let plain = serde_json::to_string(payload).unwrap();
            assert_eq!(plain, serde_json::to_string(&other.body(payload)).unwrap());
            let bypassed = serde_json::to_string(&flux.body(payload)).unwrap();
            assert_eq!(
                bypassed,
                format!(
                    "{},\"cache\":{{\"no-cache\":true,\"no-store\":true}}}}",
                    plain.strip_suffix('}').unwrap()
                )
            );
        }
        check(&other, &flux, &chat);
        check(&other, &flux, &streaming);
        check(&other, &flux, &responses);
        check(&other, &flux, &messages);
    }

    async fn capture_response_body(streaming: bool) -> serde_json::Value {
        let (body_tx, body_rx) = oneshot::channel();
        let body_tx = std::sync::Arc::new(std::sync::Mutex::new(Some(body_tx)));
        let app = Router::new().route(
            "/v1/responses",
            post(move |body: Bytes| {
                let body_tx = body_tx.clone();
                async move {
                    let _ = body_tx.lock().unwrap().take().unwrap().send(body);
                    if streaming {
                        axum::response::Response::builder()
                            .header("content-type", "text/event-stream")
                            .body(axum::body::Body::from("data: [DONE]\n\n"))
                            .unwrap()
                    } else {
                        axum::response::Response::builder()
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(r#"{"id":"resp","object":"response","created_at":0,"model":"test-model","status":"completed","output":[],"usage":{"input_tokens":0,"input_tokens_details":{"cached_tokens":0},"output_tokens":0,"output_tokens_details":{"reasoning_tokens":0},"total_tokens":0}}"#))
                            .unwrap()
                    }
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = SamplingClient::new(SamplerConfig {
            base_url: format!("http://{addr}/v1"),
            api_backend: ApiBackend::Responses,
            extra_response_includes: vec!["no_inline_citations".to_owned()],
            ..minimal_config()
        })
        .unwrap();
        let mut request = rs::CreateResponse {
            input: rs::InputParam::Text("hi".to_owned()),
            include: Some(vec![rs::IncludeEnum::ReasoningEncryptedContent]),
            tools: Some(vec![rs::Tool::WebSearch(rs::WebSearchTool::default())]),
            ..Default::default()
        };
        let mut wrapper = CreateResponseWrapper::new(request.clone());
        wrapper.extra_tool_entries = vec![serde_json::json!({"type": "x_search"})];
        if streaming {
            let (_stream, _model_metadata, _doom_loop_collector) = client
                .create_response_stream(wrapper)
                .await
                .expect("streaming request should succeed");
        } else {
            request.tools = None;
            client
                .create_response(CreateResponseWrapper::new(request))
                .await
                .expect("unary request should succeed");
        }
        let body = body_rx.await.unwrap();
        server.abort();
        serde_json::from_slice(&body).unwrap()
    }

    /// P70a: what the sampler LOGS holds no credential the request carried, and a body that fails to deserialize
    /// is neither logged nor quoted in the error.
    ///
    /// The request's URL carries keys (base-URL query and configured `query_params`) and its headers carry
    /// credentials under names a denylist misses (`Cookie`, `x-credential`, a well-known name mapped to a key).
    /// Every span and event the client emits, at every level, is captured across: a 401, a 500, a 2xx body that does
    /// not deserialize, malformed stream chunks on the Responses and Chat Completions backends, and a refused
    /// connection. No eight-character run of any credential is in any record. Controls: the endpoint path and the
    /// header NAMES were logged, and each failure was logged.
    ///
    /// Scope: logs only. The text of the errors RETURNED for a 401 or a transport failure still names the request
    /// URL exactly as before (P70b decides what happens to error text); this test does not look at it.
    #[tokio::test(flavor = "current_thread")]
    async fn request_logs_hold_no_url_or_header_credentials_and_serde_errors_hold_no_body() {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        struct Capture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);
        struct Render<'a>(&'a mut String);
        impl tracing::field::Visit for Render<'_> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!(" {}={value:?}", field.name()));
            }
        }
        impl<S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>> tracing_subscriber::Layer<S>
            for Capture
        {
            fn on_new_span(
                &self,
                attrs: &tracing::span::Attributes<'_>,
                _: &tracing::Id,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                let mut line = attrs.metadata().name().to_owned();
                attrs.record(&mut Render(&mut line));
                self.0.lock().unwrap().push(line);
            }
            fn on_record(
                &self,
                _: &tracing::Id,
                values: &tracing::span::Record<'_>,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                let mut line = "record".to_owned();
                values.record(&mut Render(&mut line));
                self.0.lock().unwrap().push(line);
            }
            fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
                let mut line = event.metadata().name().to_owned();
                event.record(&mut Render(&mut line));
                self.0.lock().unwrap().push(line);
            }
        }

        const SECRETS: [&str; 6] = [
            "p70uq-FAKE-1a2b3c4d",
            "p70qp-FAKE-5e6f7a8b",
            "p70ck-FAKE-9c0d1e2f",
            "p70xc-FAKE-3a4b5c6d",
            "p70ak-FAKE-7e8f9a0b",
            "p70ae-FAKE-Kq4ZtW8x",
        ];
        // Values a response body carries; serde's own error text would quote them.
        const BODY_MARK: &str = "p70body-MARK-k3Vb9x";
        const STREAM_MARK: &str = "p70strm-MARK-9ZqT4h";
        const CHAT_MARK: &str = "p70chat-MARK-7HxN2c";
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let status = std::sync::Arc::new(std::sync::atomic::AtomicU16::new(401));
        let (seen, status_now) = (hits.clone(), status.clone());
        let app = axum::Router::new().fallback(move || {
            let (seen, status_now) = (seen.clone(), status_now.clone());
            async move {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let code = status_now.load(std::sync::atomic::Ordering::SeqCst);
                let (content_type, body) = match code {
                    // A modelled Responses event with a malformed body, then (201) a malformed chat chunk.
                    200 => (
                        "text/event-stream",
                        format!("data: {}\n\n", serde_json::json!({ "type": "response.created", "sequence_number": 0, "response": STREAM_MARK })),
                    ),
                    201 => ("text/event-stream", format!("data: {}\n\n", serde_json::json!({ "choices": CHAT_MARK }))),
                    // A 2xx body that fails to deserialize.
                    299 => (
                        "application/json",
                        serde_json::json!({ "id": "r", "object": "response", "created_at": BODY_MARK }).to_string(),
                    ),
                    _ => ("application/json", serde_json::json!({ "error": { "message": "denied" } }).to_string()),
                };
                let code = if code == 201 { 200 } else { code };
                (axum::http::StatusCode::from_u16(code).unwrap(), [("content-type", content_type)], body)
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(Capture(captured.clone()));
        let _guard = subscriber.set_default();
        // The callsite interest cache is process-wide: a callsite first hit under another subscriber can be cached
        // as disabled and hide this test's own records.
        tracing::callsite::rebuild_interest_cache();
        let client_config = SamplerConfig {
            base_url: format!("http://{addr}/v1?key={}", SECRETS[0]),
            api_backend: ApiBackend::Responses,
            api_key: Some(SECRETS[4].to_owned()),
            query_params: [("sig".to_owned(), SECRETS[1].to_owned())].into_iter().collect(),
            extra_headers: [
                ("Cookie".to_owned(), format!("session={}", SECRETS[2])),
                ("x-credential".to_owned(), SECRETS[3].to_owned()),
                // A well-known header NAME mapped to a credential: the old name-based denylist logged its value.
                ("accept-encoding".to_owned(), SECRETS[5].to_owned()),
            ]
            .into_iter()
            .collect(),
            ..minimal_config()
        };
        let client = SamplingClient::new(client_config.clone()).unwrap();
        let request = rs::CreateResponse { input: rs::InputParam::Text("hi".to_owned()), ..Default::default() };

        // 401 on the stream call (the path that logs the request URL and headers).
        let err = client
            .create_response_stream(CreateResponseWrapper::new(request.clone()))
            .await
            .err()
            .expect("the 401 is an error");
        assert!(hits.load(std::sync::atomic::Ordering::SeqCst) >= 1, "control: the request reached the server");
        assert!(matches!(err, SamplingError::Auth { .. }), "control: a 401, not a pre-dispatch failure: {err:?}");
        // 500 on the unary call.
        status.store(500, std::sync::atomic::Ordering::SeqCst);
        let e = client.create_response(CreateResponseWrapper::new(request.clone())).await.expect_err("a 500 is an error");
        assert!(matches!(e, SamplingError::Api { .. }), "control: {e:?}");
        // A malformed 2xx body.
        status.store(299, std::sync::atomic::Ordering::SeqCst);
        let malformed = client
            .create_response(CreateResponseWrapper::new(request.clone()))
            .await
            .expect_err("a malformed body is an error");
        // A malformed modelled event in a Responses stream.
        status.store(200, std::sync::atomic::Ordering::SeqCst);
        let (mut stream, _, _) = client
            .create_response_stream(CreateResponseWrapper::new(request.clone()))
            .await
            .expect("a 200 stream opens");
        let stream_err = futures_util::StreamExt::next(&mut stream).await.expect("an item").expect_err("a malformed event");
        // A malformed chunk in a Chat Completions stream.
        status.store(201, std::sync::atomic::Ordering::SeqCst);
        let chat_client =
            SamplingClient::new(SamplerConfig { api_backend: ApiBackend::ChatCompletions, ..client_config.clone() }).unwrap();
        let chat_request: ChatCompletionRequest =
            serde_json::from_value(serde_json::json!({ "model": "m", "messages": [{ "role": "user", "content": "hi" }] }))
                .expect("chat request");
        let (mut chunks, _) = chat_client.chat_completion_stream(chat_request).await.expect("a 200 stream opens");
        let chat_err = futures_util::StreamExt::next(&mut chunks).await.expect("an item").expect_err("a malformed chunk");
        server.abort();
        // A transport failure: reqwest's error text names the request URL, and the client logs that text.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_addr = closed.local_addr().unwrap();
        drop(closed);
        // The path holds parentheses: text scanning that stops a URL at `)` would log the query after them.
        let offline = SamplingClient::new(SamplerConfig {
            base_url: format!("http://{closed_addr}/tenant(p70)/v1?key={}", SECRETS[0]),
            api_backend: ApiBackend::Responses,
            query_params: [("sig".to_owned(), SECRETS[1].to_owned())].into_iter().collect(),
            ..minimal_config()
        })
        .unwrap();
        let transport = offline
            .create_response_stream(CreateResponseWrapper::new(request))
            .await
            .err()
            .expect("a refused connection is an error");
        assert!(matches!(transport, SamplingError::Http(_)), "control: a transport failure: {transport:?}");

        // serde errors: category and position only, in the error and in its log line.
        // (the body of a Responses event is an internally tagged enum: serde reports no position for it)
        for (what, error, mark, positioned) in [
            ("unary body", &malformed, BODY_MARK, true),
            ("responses event", &stream_err, STREAM_MARK, false),
            ("chat chunk", &chat_err, CHAT_MARK, true),
        ] {
            assert!(matches!(error, SamplingError::Serialization(_)), "control ({what}): {error:?}");
            let shown = error.to_string();
            let summary = shown.strip_prefix("serialization error: ").unwrap_or_else(|| panic!("{what}: {shown}"));
            let (category, position) = summary.split_once(" error").unwrap_or_else(|| panic!("{what}: {shown}"));
            assert!(["Data", "Syntax", "Eof", "Io"].contains(&category), "{what}: a category is shown: {shown}");
            if positioned {
                let column = position.strip_prefix(" at line 1 column ").unwrap_or_else(|| panic!("{what}: {shown}"));
                assert!(column.parse::<u32>().is_ok_and(|c| c > 0), "{what}: a position is shown: {shown}");
            } else {
                assert_eq!(position, "", "{what}: nothing but the category: {shown}");
            }
            assert!(!format!("{shown} {error:?}").contains("MARK"), "{what}: the error quotes the body ({mark})");
        }
        let records = captured.lock().unwrap().clone();
        let logs = records.join("\n");
        let failures: Vec<&String> = records.iter().filter(|r| r.contains("Failed to deserialize")).collect();
        assert_eq!(failures.len(), 3, "control: each deserialization failure was logged once: {failures:?}");
        for record in failures {
            assert!(record.contains(" error") && record.contains("body_len="), "{record}");
            assert!(!record.contains("MARK"), "a deserialization failure logged the body: {record}");
        }
        // Nothing else logs a unary response body either. (Stream chunks are logged by the `sse_chunk` event, which
        // P70a does not change.)
        assert!(!logs.contains(BODY_MARK), "the malformed 2xx body was logged: {logs}");

        assert!(logs.contains("/v1/responses"), "control: the endpoint was logged: {logs}");
        for name in ["cookie", "x-credential", "accept-encoding", "authorization"] {
            assert!(logs.contains(&format!("header_name={name}")), "control: the header name {name} was logged: {logs}");
        }
        assert!(!logs.contains("header_value"), "a header value field was logged: {logs}");
        let dispatch_failure = records
            .iter()
            .find(|r| r.contains("HTTP dispatch failed"))
            .unwrap_or_else(|| panic!("control: the transport failure was logged: {logs}"));
        assert!(
            dispatch_failure.contains("/tenant(p70)/v1/responses?key=<redacted>&sig=<redacted>"),
            "control: the failed request's URL is in that line, redacted: {dispatch_failure}"
        );
        for secret in SECRETS {
            let chars: Vec<char> = secret.chars().collect();
            for w in chars.windows(8) {
                let frag: String = w.iter().collect();
                assert!(!logs.contains(&frag), "the sampler logged {frag:?} of a credential: {logs}");
            }
        }
    }

    /// P70 (Astra r11): a `User-Agent` configured in `extra_headers` never survives construction, even when the
    /// session origin does not form a header value: the agent's own string is sent instead.
    #[test]
    fn configured_user_agent_never_survives_an_invalid_origin() {
        let client = SamplingClient::new(SamplerConfig {
            extra_headers: [("user-agent".to_owned(), "Ua7kQ9".to_owned())].into_iter().collect(),
            origin_client: Some(OriginClientInfo { product: "bad\nclient".to_owned(), version: None }),
            ..minimal_config()
        })
        .expect("build");
        let sent = client.default_headers.get(USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
        assert!(sent.starts_with(AGENT_PRODUCT), "the agent's own User-Agent is sent: {sent:?}");
        assert!(!sent.contains("Ua7kQ9"), "the configured value survived: {sent:?}");
    }

    #[tokio::test]
    async fn response_call_sites_emit_final_includes_and_stream_fields() {
        let unary = capture_response_body(false).await;
        assert_eq!(
            serde_json::json!(["reasoning.encrypted_content", "no_inline_citations"]),
            unary["include"],
        );

        let stream = capture_response_body(true).await;
        assert_eq!(
            serde_json::json!(["reasoning.encrypted_content", "no_inline_citations"]),
            stream["include"],
        );
        assert_eq!(Some(true), stream["stream"].as_bool());
        assert!(
            stream["tools"]
                .as_array()
                .unwrap()
                .iter()
                .any(|tool| tool["type"] == "x_search")
        );
    }

    #[test]
    fn append_response_includes_preserves_typed_values_and_deduplicates() {
        let typed = [
            "reasoning.encrypted_content",
            "web_search_call.action.sources",
        ];
        let mut body = serde_json::json!({ "include": typed });
        append_response_includes(
            &mut body,
            &[
                "no_inline_citations".to_owned(),
                "no_inline_citations".to_owned(),
            ],
        );
        assert_eq!(
            serde_json::json!([
                "reasoning.encrypted_content",
                "web_search_call.action.sources",
                "no_inline_citations",
            ]),
            body["include"],
        );

        let mut unchanged = serde_json::json!({ "include": typed });
        let expected = unchanged.clone();
        append_response_includes(&mut unchanged, &[]);
        assert_eq!(expected, unchanged);

        for mut body in [
            serde_json::json!({}),
            serde_json::json!({ "include": null }),
        ] {
            append_response_includes(&mut body, &["no_inline_citations".to_owned()]);
            assert_eq!(serde_json::json!(["no_inline_citations"]), body["include"]);
        }
    }

    /// The status the `retry-after-ms` / `x-ratelimit-reset-tokens` fallbacks are scoped to.
    const RATE_LIMITED: reqwest::StatusCode = reqwest::StatusCode::TOO_MANY_REQUESTS;

    #[test]
    fn extract_retry_after_parses_seconds() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::RETRY_AFTER, "30".parse().unwrap());
        assert_eq!(extract_retry_after(RATE_LIMITED, &headers), Some(30));
    }

    #[test]
    fn extract_retry_after_caps_at_120() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::RETRY_AFTER, "3600".parse().unwrap());
        assert_eq!(extract_retry_after(RATE_LIMITED, &headers), Some(120));
    }

    #[test]
    fn extract_retry_after_zero_is_valid() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::RETRY_AFTER, "0".parse().unwrap());
        assert_eq!(extract_retry_after(RATE_LIMITED, &headers), Some(0));
    }

    #[test]
    fn extract_retry_after_ignores_http_date() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::RETRY_AFTER,
            "Fri, 31 Dec 2025 23:59:59 GMT".parse().unwrap(),
        );
        assert_eq!(extract_retry_after(RATE_LIMITED, &headers), None);
    }

    #[test]
    fn extract_retry_after_none_when_missing() {
        let headers = reqwest::header::HeaderMap::new();
        assert_eq!(extract_retry_after(RATE_LIMITED, &headers), None);
    }

    // ── TPM 429 backoff headers (upstream 1.0.26) ──────────────────────────
    // OpenAI/Azure tokens-per-minute 429s commonly answer with `retry-after-ms`
    // or `x-ratelimit-reset-tokens` and NO integer `Retry-After`. Without these
    // fallbacks the envelope carries `retry_after_secs: None`, so the compaction
    // classifier loses the one signal that says "capacity is coming back".

    #[test]
    fn extract_retry_after_falls_back_to_retry_after_ms() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("retry-after-ms", "1500".parse().unwrap());
        assert_eq!(extract_retry_after(RATE_LIMITED, &headers), Some(2));
    }

    #[test]
    fn extract_retry_after_ms_below_a_second_still_backs_off() {
        // Rounding 500ms down to 0 would turn a backoff into a hot retry.
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("retry-after-ms", "500".parse().unwrap());
        assert_eq!(extract_retry_after(RATE_LIMITED, &headers), Some(1));
    }

    #[test]
    fn extract_retry_after_falls_back_to_ratelimit_reset_tokens() {
        for (raw, expected) in [
            ("1s", 1u64),
            ("88ms", 1),
            ("1.5s", 2),
            ("6m0s", 120), // 360s, capped
            ("2m30s", 120),
            ("7", 7), // bare seconds
        ] {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert("x-ratelimit-reset-tokens", raw.parse().unwrap());
            assert_eq!(
                extract_retry_after(RATE_LIMITED, &headers),
                Some(expected),
                "x-ratelimit-reset-tokens: {raw}"
            );
        }
    }

    #[test]
    fn extract_retry_after_ignores_unparseable_reset_tokens() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-ratelimit-reset-tokens", "soon".parse().unwrap());
        assert_eq!(extract_retry_after(RATE_LIMITED, &headers), None);
    }

    #[test]
    fn extract_retry_after_prefers_the_standard_header() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::RETRY_AFTER, "9".parse().unwrap());
        headers.insert("retry-after-ms", "60000".parse().unwrap());
        headers.insert("x-ratelimit-reset-tokens", "6m0s".parse().unwrap());
        assert_eq!(extract_retry_after(RATE_LIMITED, &headers), Some(9));
    }

    #[test]
    fn extract_retry_after_http_date_still_falls_through_to_ms() {
        // An HTTP-date `Retry-After` is unparseable here; the ms header beside
        // it is the usable signal and must not be shadowed.
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::RETRY_AFTER,
            "Fri, 31 Dec 2025 23:59:59 GMT".parse().unwrap(),
        );
        headers.insert("retry-after-ms", "3000".parse().unwrap());
        assert_eq!(extract_retry_after(RATE_LIMITED, &headers), Some(3));
    }

    #[test]
    fn retry_after_fallbacks_are_scoped_to_rate_limit_statuses() {
        // `x-ratelimit-reset-tokens` is a token-bucket refill time OpenAI/Azure
        // attach to essentially every response, 5xx included. Read as a backoff on
        // an unrelated 502/529 it replaces the ~2s first backoff with the 30s
        // `MAX_RETRY_BACKOFF` (`retry::retry_after_or_backoff`), and on the
        // rate-limited branch (`retry.rs`, unclamped) it can park the sampler for
        // the full 120s cap. Neither header means "retry later" outside a 429.
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("retry-after-ms", "2000".parse().unwrap());
        headers.insert("x-ratelimit-reset-tokens", "6m0s".parse().unwrap());
        for status in [
            reqwest::StatusCode::BAD_GATEWAY,
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            reqwest::StatusCode::BAD_REQUEST,
            reqwest::StatusCode::from_u16(529).unwrap(),
        ] {
            assert_eq!(
                extract_retry_after(status, &headers),
                None,
                "{status} must not inherit a token-bucket reset as its backoff",
            );
        }
        // The statuses the retry loop actually treats as rate limits keep them.
        assert_eq!(
            extract_retry_after(reqwest::StatusCode::TOO_MANY_REQUESTS, &headers),
            Some(2),
        );
        assert_eq!(
            extract_retry_after(reqwest::StatusCode::REQUEST_TIMEOUT, &headers),
            Some(2),
        );
    }

    #[test]
    fn a_zero_valued_fallback_bucket_is_not_a_backoff() {
        // OpenAI/Azure send a reset time per bucket, so an RPM-triggered 429
        // routinely reports the TOKENS bucket as already refilled. Reading that
        // as `Some(0)` makes the rate-limited retry branch re-dispatch with no
        // wait at all, up to `rate_limit_threshold` times, against a provider
        // that just rate-limited us. Dropping the zero falls back to the retry
        // ladder's own backoff instead.
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-ratelimit-reset-tokens", "0s".parse().unwrap());
        assert_eq!(extract_retry_after(RATE_LIMITED, &headers), None);

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("retry-after-ms", "0".parse().unwrap());
        assert_eq!(extract_retry_after(RATE_LIMITED, &headers), None);

        // A sub-second value still rounds up to a real wait; only zero is dropped.
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-ratelimit-reset-tokens", "0s".parse().unwrap());
        headers.insert("retry-after-ms", "120".parse().unwrap());
        assert_eq!(extract_retry_after(RATE_LIMITED, &headers), Some(1));
    }

    #[test]
    fn the_standard_retry_after_header_is_honoured_at_any_status() {
        // `Retry-After` is defined for 503 and 3xx as well as 429; only the two
        // provider-specific fallbacks are scoped.
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::RETRY_AFTER, "5".parse().unwrap());
        assert_eq!(
            extract_retry_after(reqwest::StatusCode::SERVICE_UNAVAILABLE, &headers),
            Some(5),
        );
    }

    #[test]
    fn extract_should_retry_true() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-should-retry", "true".parse().unwrap());
        assert_eq!(extract_should_retry(&headers), Some(true));
    }

    #[test]
    fn extract_should_retry_true_case_insensitive() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-should-retry", "TRUE".parse().unwrap());
        assert_eq!(extract_should_retry(&headers), Some(true));
    }

    #[test]
    fn extract_should_retry_false() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-should-retry", "false".parse().unwrap());
        assert_eq!(extract_should_retry(&headers), Some(false));
    }

    #[test]
    fn extract_should_retry_unknown_value_is_none() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-should-retry", "banana".parse().unwrap());
        assert_eq!(extract_should_retry(&headers), None);
    }

    #[test]
    fn extract_should_retry_absent_is_none() {
        let headers = reqwest::header::HeaderMap::new();
        assert_eq!(extract_should_retry(&headers), None);
    }

    #[test]
    fn new_with_minimal_config_succeeds() {
        let client = SamplingClient::new(minimal_config()).expect("client should construct");
        assert_eq!(client.api_backend(), ApiBackend::ChatCompletions);
    }

    #[test]
    fn apply_env_http_headers_resolves_trims_skips_and_overrides() {
        let mut map = IndexMap::new();
        map.insert("x-tenant-token".to_string(), "TENANT".to_string());
        map.insert("x-blank".to_string(), "BLANK".to_string());
        map.insert("x-missing".to_string(), "MISSING".to_string());
        map.insert("x-override".to_string(), "OVERRIDE".to_string());
        map.insert("x invalid".to_string(), "INVALID".to_string());

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-override"),
            HeaderValue::from_static("static"),
        );

        apply_env_http_headers(
            &map,
            |var| match var {
                // Leading space and trailing newline exercise trimming
                "TENANT" => Some(" tenant-secret\n".to_string()),
                "BLANK" => Some("   ".to_string()),
                "OVERRIDE" => Some("from-env".to_string()),
                "INVALID" => Some("value".to_string()),
                _ => None,
            },
            &mut headers,
        );

        assert_eq!(headers.get("x-tenant-token").unwrap(), "tenant-secret");
        assert!(headers.get("x-blank").is_none());
        assert!(headers.get("x-missing").is_none());
        // A resolved env value overrides an existing header of the same name.
        assert_eq!(headers.get("x-override").unwrap(), "from-env");
        // An invalid header name is skipped rather than panicking.
        assert!(headers.get("x invalid").is_none());
    }

    #[test]
    fn endpoint_appends_path_before_a_base_url_query_without_configured_params() {
        let template =
            EndpointTemplate::new("https://gateway.example/v1?api-version=x", &IndexMap::new());
        let url = template.url_for_path("responses");
        assert!(
            url.starts_with("https://gateway.example/v1/responses?"),
            "url: {url}"
        );
        assert!(url.contains("api-version=x"), "url: {url}");
        assert!(!url.contains("x/responses"), "url: {url}");
    }

    /// P13: the Messages default was 128_000 -- the CURRENT Anthropic family's
    /// ceiling, inherited from upstream where `messages` pointed at a route
    /// upstream controlled. Against api.anthropic.com it exceeds the real
    /// `max_output_tokens` of every model below Opus 4.6 / Sonnet 4.6, so a
    /// `/provider`-written Anthropic entry 400'd on every turn and nothing the
    /// flow wrote could correct it. The default must be a value every
    /// non-retired Anthropic model accepts.
    #[test]
    fn messages_default_max_tokens_is_within_every_anthropic_models_output_cap() {
        let client = SamplingClient::new(SamplerConfig {
            api_backend: ApiBackend::Messages,
            auth_scheme: AuthScheme::XApiKey,
            max_completion_tokens: None,
            ..minimal_config()
        })
        .expect("client should build");

        let mut request =
            MessagesRequestWrapper::new(fuigo_sampling_types::messages::MessagesRequest::default());
        client
            .apply_message_defaults(&mut request)
            .expect("defaults apply");

        // The smallest published `max_output_tokens` across Anthropic's
        // non-retired models as of 2026-09 (Opus 4 / 4.1 = 32K).
        const SMALLEST_ANTHROPIC_OUTPUT_CAP: u32 = 32_000;
        assert_eq!(
            request.inner.max_tokens, SMALLEST_ANTHROPIC_OUTPUT_CAP,
            "a Messages request with no max_tokens must default to a value every \
             non-retired Anthropic model accepts"
        );
        assert!(
            request.inner.max_tokens <= SMALLEST_ANTHROPIC_OUTPUT_CAP,
            "max_tokens {} exceeds the smallest per-model output cap and would 400",
            request.inner.max_tokens
        );
    }

    /// The default is a floor, not a ceiling: a config that states a budget
    /// still decides. This is the key `[model_providers.<id>].max_completion_tokens`
    /// now reaches, so `/provider` output is correctable without hand-editing
    /// a `[model.<id>]` table the flow never mentioned.
    #[test]
    fn configured_max_completion_tokens_beats_the_messages_default() {
        let client = SamplingClient::new(SamplerConfig {
            api_backend: ApiBackend::Messages,
            auth_scheme: AuthScheme::XApiKey,
            max_completion_tokens: Some(64_000),
            ..minimal_config()
        })
        .expect("client should build");

        let mut request =
            MessagesRequestWrapper::new(fuigo_sampling_types::messages::MessagesRequest::default());
        client
            .apply_message_defaults(&mut request)
            .expect("defaults apply");
        assert_eq!(request.inner.max_tokens, 64_000);
    }

    /// A request that already states `max_tokens` is untouched.
    #[test]
    fn an_explicit_max_tokens_survives_the_messages_defaults() {
        let client = SamplingClient::new(SamplerConfig {
            api_backend: ApiBackend::Messages,
            auth_scheme: AuthScheme::XApiKey,
            ..minimal_config()
        })
        .expect("client should build");

        let mut request = MessagesRequestWrapper::new(
            fuigo_sampling_types::messages::MessagesRequest {
                max_tokens: 1_234,
                ..Default::default()
            },
        );
        client
            .apply_message_defaults(&mut request)
            .expect("defaults apply");
        assert_eq!(request.inner.max_tokens, 1_234);
    }

    /// P13 / packet §3.1: the output ceiling must NOT be derived from the
    /// context window. They are different quantities, and a derivation would
    /// couple this default to a type change owned by another packet. Two
    /// clients whose context windows differ by two orders of magnitude must
    /// produce the same `max_tokens`.
    #[test]
    fn the_messages_default_is_not_derived_from_the_context_window() {
        let max_tokens_for = |context_window: u64| {
            let client = SamplingClient::new(SamplerConfig {
                api_backend: ApiBackend::Messages,
                auth_scheme: AuthScheme::XApiKey,
                max_completion_tokens: None,
                context_window,
                ..minimal_config()
            })
            .expect("client should build");
            let mut request = MessagesRequestWrapper::new(
                fuigo_sampling_types::messages::MessagesRequest::default(),
            );
            client
                .apply_message_defaults(&mut request)
                .expect("defaults apply");
            request.inner.max_tokens
        };
        assert_eq!(
            max_tokens_for(8_192),
            max_tokens_for(1_000_000),
            "max_tokens must not be a function of context_window"
        );
    }

    /// P13 / divergence finding 6: `api_backend = "messages"` implies
    /// `anthropic-version`. The `/provider` discovery table knew that; the
    /// backend did not, so a HAND-WRITTEN `[model_providers.x] api_backend =
    /// "messages"` with no `extra_headers` built a request with no version
    /// header at all -- silently malformed, which is the defect.
    #[test]
    fn a_messages_client_sends_anthropic_version_without_any_configured_header() {
        let client = SamplingClient::new(SamplerConfig {
            api_backend: ApiBackend::Messages,
            auth_scheme: AuthScheme::XApiKey,
            extra_headers: IndexMap::new(),
            ..minimal_config()
        })
        .expect("client should build");
        assert_eq!(
            client
                .default_headers
                .get(HeaderName::from_static(ANTHROPIC_VERSION_HEADER))
                .expect("a messages client must carry anthropic-version"),
            ANTHROPIC_VERSION,
        );
    }

    /// Supplied, not imposed: a config that names a version keeps it.
    #[test]
    fn a_configured_anthropic_version_is_not_overwritten() {
        let mut extra_headers = IndexMap::new();
        extra_headers.insert(
            ANTHROPIC_VERSION_HEADER.to_string(),
            "2099-01-01".to_string(),
        );
        let client = SamplingClient::new(SamplerConfig {
            api_backend: ApiBackend::Messages,
            auth_scheme: AuthScheme::XApiKey,
            extra_headers,
            ..minimal_config()
        })
        .expect("client should build");
        assert_eq!(
            client
                .default_headers
                .get(HeaderName::from_static(ANTHROPIC_VERSION_HEADER))
                .expect("header present"),
            "2099-01-01",
        );
    }

    /// The header belongs to the Messages wire protocol, so the other two
    /// backends must not acquire it.
    #[test]
    fn non_messages_backends_do_not_send_anthropic_version() {
        for backend in [ApiBackend::ChatCompletions, ApiBackend::Responses] {
            let client = SamplingClient::new(SamplerConfig {
                api_backend: backend.clone(),
                ..minimal_config()
            })
            .expect("client should build");
            assert!(
                client
                    .default_headers
                    .get(HeaderName::from_static(ANTHROPIC_VERSION_HEADER))
                    .is_none(),
                "{backend:?} must not carry anthropic-version"
            );
        }
    }

    #[test]
    fn messages_plus_anthropic_api_key_uses_x_api_key_and_not_authorization() {
        let cfg = SamplerConfig {
            api_key: Some("anthropic-key-abc123".to_string()),
            api_backend: ApiBackend::Messages,
            auth_scheme: AuthScheme::XApiKey,
            ..minimal_config()
        };
        let client = SamplingClient::new(cfg).expect("client should build");
        assert!(
            client
                .default_headers
                .get(HeaderName::from_static("x-api-key"))
                .is_some()
        );
        assert!(client.default_headers.get(AUTHORIZATION).is_none());
    }

    #[test]
    fn messages_plus_bearer_uses_authorization_and_not_x_api_key() {
        let cfg = SamplerConfig {
            api_key: Some("bearer-key-abc123".to_string()),
            api_backend: ApiBackend::Messages,
            auth_scheme: AuthScheme::Bearer,
            ..minimal_config()
        };
        let client = SamplingClient::new(cfg).expect("client should build");
        assert!(client.default_headers.get(AUTHORIZATION).is_some());
        assert!(
            client
                .default_headers
                .get(HeaderName::from_static("x-api-key"))
                .is_none()
        );
    }

    // Regression: a past change dropped User-Agent from sampling requests.
    #[test]
    fn sampling_client_always_has_user_agent() {
        let client = SamplingClient::new(minimal_config()).expect("build");
        assert!(client.default_headers.contains_key(USER_AGENT));
    }

    // Regression: a past change dropped HeaderInjector (traceparent) from sampling requests.
    #[test]
    fn header_injector_is_called_in_post() {
        #[derive(Debug)]
        struct TestInjector;
        impl crate::config::HeaderInjector for TestInjector {
            fn inject(&self, headers: &mut HeaderMap) {
                headers.insert(
                    HeaderName::from_static("traceparent"),
                    HeaderValue::from_static("00-test-trace-id-00"),
                );
            }
        }

        let mut config = minimal_config();
        config.header_injector = Some(std::sync::Arc::new(TestInjector));
        let client = SamplingClient::new(config).expect("build");
        let SentRequest { builder, .. } = client.post("http://localhost/test");
        let req = builder.build().expect("build request");
        assert!(
            req.headers().contains_key("traceparent"),
            "HeaderInjector should inject traceparent into post() requests"
        );
    }

    #[test]
    fn user_agent_includes_origin_and_agent_product() {
        let origin = OriginClientInfo {
            product: "my-client".to_string(),
            version: Some("1.2.3".to_string()),
        };
        let ua = user_agent_string_for(&origin);
        assert!(ua.contains("my-client/1.2.3"));
        assert!(ua.contains(AGENT_PRODUCT));
    }

    #[test]
    fn user_agent_omits_origin_version_when_absent() {
        let origin = OriginClientInfo {
            product: "my-client".to_string(),
            version: None,
        };
        let ua = user_agent_string_for(&origin);
        // No slash between product and the fuigo-shell agent product.
        assert!(ua.starts_with("my-client fuigo-shell/"));
    }

    #[test]
    fn user_agent_collapses_when_origin_matches_agent() {
        let agent_version = fuigo_version::VERSION.to_string();
        let origin = OriginClientInfo {
            product: AGENT_PRODUCT.to_string(),
            version: Some(agent_version.clone()),
        };
        let ua = user_agent_string_for(&origin);
        // Single product/version slot when the origin and agent match.
        assert!(ua.starts_with(&format!("{}/{}", AGENT_PRODUCT, agent_version)));
    }

    /// Counts callbacks for assertions in the tests below.
    #[derive(Default, Debug)]
    struct CountingCallback {
        invocations: std::sync::Mutex<Vec<(crate::attribution::SamplingConsumer, Option<String>)>>,
    }

    #[derive(Debug)]
    struct StaticBearerResolver(&'static str);

    impl crate::config::BearerResolver for StaticBearerResolver {
        fn current_bearer(&self) -> Option<String> {
            Some(self.0.to_string())
        }
    }

    impl crate::attribution::Auth401AttributionCallback for CountingCallback {
        fn record_401(
            &self,
            consumer: crate::attribution::SamplingConsumer,
            sent_bearer: Option<&BearerFingerprint>,
        ) {
            self.invocations
                .lock()
                .unwrap()
                .push((consumer, sent_bearer.map(|s| s.as_str().to_string())));
        }
    }

    /// `post()` strips the `"Bearer "` scheme prefix off `Authorization` and captures the bearer's fingerprint.
    #[test]
    fn post_captures_bearer_tail_for_openai_compat() {
        let cfg = SamplerConfig {
            api_key: Some("test-bearer-1234567890".to_string()),
            api_backend: ApiBackend::ChatCompletions,
            ..minimal_config()
        };
        let client = SamplingClient::new(cfg).expect("client should build");
        let SentRequest {
            sent_bearer: bearer,
            ..
        } = client.post("https://example.test/v1/chat/completions");
        assert_eq!(bearer, Some(BearerFingerprint::of("test-bearer-1234567890")));
        assert!(!bearer.expect("captured").as_str().contains("7890"), "no fragment of the bearer");
    }

    /// `post()` captures `x-api-key` for Messages-API backends and keeps the value's fingerprint.
    #[test]
    fn post_captures_x_api_key_tail_for_messages() {
        let cfg = SamplerConfig {
            api_key: Some("anthropic-key-abc123".to_string()),
            api_backend: ApiBackend::Messages,
            auth_scheme: AuthScheme::XApiKey,
            ..minimal_config()
        };
        let client = SamplingClient::new(cfg).expect("client should build");
        let SentRequest {
            sent_bearer: bearer,
            ..
        } = client.post("https://example.test/v1/messages");
        assert_eq!(bearer, Some(BearerFingerprint::of("anthropic-key-abc123")));
    }

    /// `post()` captures `None` when the request carries no auth header.
    #[test]
    fn post_captures_none_when_no_header() {
        let cfg = SamplerConfig {
            api_key: None,
            api_backend: ApiBackend::ChatCompletions,
            ..minimal_config()
        };
        let client = SamplingClient::new(cfg).expect("client should build");
        let SentRequest {
            sent_bearer: bearer,
            ..
        } = client.post("https://example.test/v1/chat/completions");
        assert!(bearer.is_none());
    }

    /// The race this design closes: a 401 triggers a recovery that rotates the resolver.
    /// A record-time re-read would then attribute a bearer the rejected request never carried.
    /// The attributed fragment must be the one captured when the request was built.
    #[test]
    fn post_capture_is_immune_to_resolver_rotation_after_build() {
        #[derive(Debug)]
        struct RotatingResolver(std::sync::Mutex<String>);
        impl crate::config::BearerResolver for RotatingResolver {
            fn current_bearer(&self) -> Option<String> {
                Some(self.0.lock().unwrap().clone())
            }
        }

        let resolver = std::sync::Arc::new(RotatingResolver(std::sync::Mutex::new(
            "rejected-token-oldtail1".to_string(),
        )));
        let cfg = SamplerConfig {
            api_key: None,
            api_backend: ApiBackend::Responses,
            bearer_resolver: Some(resolver.clone()),
            ..minimal_config()
        };
        let client = SamplingClient::new(cfg).expect("client should build");

        let SentRequest {
            sent_bearer: sent_at_build,
            ..
        } = client.post("https://example.test/v1/responses");
        // The 401 kicks recovery; the resolver rotates before the callback runs.
        *resolver.0.lock().unwrap() = "fresh-token-newtail99".to_string();

        assert_eq!(
            sent_at_build,
            Some(BearerFingerprint::of("rejected-token-oldtail1")),
            "attribution must describe the bearer the rejected request carried"
        );
        // A record-time re-read would report the rotated token instead:
        assert_eq!(
            client.current_sent_bearer_fingerprint(),
            Some(BearerFingerprint::of("fresh-token-newtail99")),
            "sanity: the build-time capture and a live re-read now differ"
        );
    }

    #[test]
    fn live_bearer_resolver_uses_authorization_for_messages_plus_bearer() {
        let cfg = SamplerConfig {
            api_key: Some("stale-bearer".to_string()),
            api_backend: ApiBackend::Messages,
            auth_scheme: AuthScheme::Bearer,
            bearer_resolver: Some(std::sync::Arc::new(StaticBearerResolver("fresh-bearer"))),
            ..minimal_config()
        };
        let client = SamplingClient::new(cfg).expect("client should build");
        let SentRequest { builder, .. } = client.post("https://example.test/v1/messages");
        let request = builder.build().expect("request should build");
        let auth = request
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        assert_eq!(auth, Some("Bearer fresh-bearer"));
        assert!(request.headers().get("x-api-key").is_none());
    }

    /// Regression: `api_key` seeds `default_headers` with `Authorization: Bearer ...`.
    /// With a `bearer_resolver` also set, `post()` must produce exactly one `Authorization` header on the wire.
    /// `RequestBuilder::header(AUTHORIZATION, ...)` appends rather than replaces, causing two identical headers and a 400 from cli-chat-proxy.
    #[test]
    fn post_emits_single_authorization_with_api_key_and_bearer_resolver() {
        let cfg = SamplerConfig {
            api_key: Some("stale-bearer".to_string()),
            api_backend: ApiBackend::Responses,
            auth_scheme: AuthScheme::Bearer,
            bearer_resolver: Some(std::sync::Arc::new(StaticBearerResolver("fresh-bearer"))),
            ..minimal_config()
        };
        let client = SamplingClient::new(cfg).expect("client should build");
        let SentRequest { builder, .. } = client.post("https://example.test/v1/responses");
        let request = builder.build().expect("request should build");
        let auth_count = request.headers().get_all(AUTHORIZATION).iter().count();
        assert_eq!(
            auth_count, 1,
            "expected exactly one Authorization header, got {auth_count}"
        );
        assert_eq!(
            request
                .headers()
                .get(AUTHORIZATION)
                .and_then(|v| v.to_str().ok()),
            Some("Bearer fresh-bearer"),
        );
    }

    #[test]
    fn live_bearer_resolver_uses_x_api_key_for_messages_plus_anthropic_api_key() {
        let cfg = SamplerConfig {
            api_key: Some("stale-anthropic".to_string()),
            api_backend: ApiBackend::Messages,
            auth_scheme: AuthScheme::XApiKey,
            bearer_resolver: Some(std::sync::Arc::new(StaticBearerResolver("fresh-anthropic"))),
            ..minimal_config()
        };
        let client = SamplingClient::new(cfg).expect("client should build");
        let SentRequest { builder, .. } = client.post("https://example.test/v1/messages");
        let request = builder.build().expect("request should build");
        let api_key = request
            .headers()
            .get("x-api-key")
            .and_then(|v| v.to_str().ok());
        assert_eq!(api_key, Some("fresh-anthropic"));
        assert!(request.headers().get(AUTHORIZATION).is_none());
    }

    /// The callback receives the `post()`-captured fingerprint only; neither the bearer nor a fragment crosses the crate boundary.
    #[test]
    fn record_401_attribution_invokes_callback_with_captured_bearer() {
        let cb = std::sync::Arc::new(CountingCallback::default());
        let cb_dyn: crate::attribution::SharedAttributionCallback = cb.clone();
        let cfg = SamplerConfig {
            api_key: Some("the-bearer-1234567890-extra-tail".to_string()),
            api_backend: ApiBackend::ChatCompletions,
            attribution_callback: Some(cb_dyn),
            bearer_resolver: None,
            ..minimal_config()
        };
        let client = SamplingClient::new(cfg).expect("client should build");
        let SentRequest { sent_bearer, .. } =
            client.post("https://example.test/v1/chat/completions");
        client.record_401_attribution(
            crate::attribution::SamplingConsumer::ChatCompletionsStream,
            sent_bearer.as_ref(),
        );
        let calls = cb.invocations.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].0,
            crate::attribution::SamplingConsumer::ChatCompletionsStream
        );
        assert_eq!(
            calls[0].1.as_deref(),
            Some(fuigo_auth::bearer_fingerprint("the-bearer-1234567890-extra-tail").as_str())
        );
        assert!(!calls[0].1.as_deref().unwrap_or_default().contains("tail"), "no fragment of the bearer");
    }

    /// When a bearer_resolver is wired but returns `None`, attribution must report no sent bearer (not the construction-time default header seed).
    #[test]
    fn bearer_resolver_none_attribution_ignores_default_headers() {
        #[derive(Debug)]
        struct EmptyResolver;
        impl crate::config::BearerResolver for EmptyResolver {
            fn current_bearer(&self) -> Option<String> {
                None
            }
        }

        let cfg = SamplerConfig {
            api_key: Some("stale-seed-token".to_string()),
            api_backend: ApiBackend::Responses,
            bearer_resolver: Some(std::sync::Arc::new(EmptyResolver)),
            ..minimal_config()
        };
        let client = SamplingClient::new(cfg).expect("client should build");
        assert_eq!(
            client.current_sent_bearer_fingerprint(),
            None,
            "resolver None must not attribute a stripped default seed"
        );
    }

    /// A wired bearer_resolver that returns `None` means a hard-expired session with no live access token.
    /// Default Authorization / x-api-key must be stripped so a stale seed key cannot ride the wire.
    #[test]
    fn bearer_resolver_none_strips_default_authorization() {
        #[derive(Debug)]
        struct EmptyResolver;
        impl crate::config::BearerResolver for EmptyResolver {
            fn current_bearer(&self) -> Option<String> {
                None
            }
        }

        let cfg = SamplerConfig {
            api_key: Some("stale-token".to_string()),
            api_backend: ApiBackend::Responses,
            bearer_resolver: Some(std::sync::Arc::new(EmptyResolver)),
            ..minimal_config()
        };
        let client = SamplingClient::new(cfg).expect("client should build");
        let SentRequest {
            builder,
            sent_bearer: sent,
        } = client.post("https://example.test/v1/responses");
        let request = builder.body("").build().expect("request should build");
        assert_eq!(sent, None, "capture must agree: nothing was sent");
        assert!(
            request.headers().get(AUTHORIZATION).is_none(),
            "stale default Authorization must not be sent when resolver is empty"
        );
    }

    /// An unknown top-level `type` is benign and must be SKIPPED, not fatal.
    /// OpenAI emits `keepalive` during long reasoning turns; before this, one such frame
    /// aborted the whole turn with `unknown variant `keepalive``, so the failure selected
    /// for the longest and most expensive turns.
    #[test]
    fn unknown_stream_event_type_is_skipped_not_fatal() {
        for raw in [
            r#"{"type":"keepalive"}"#,
            r#"{"type":"keepalive","sequence_number":7}"#,
            r#"{"type":"response.some_future_event","whatever":{"nested":true}}"#,
        ] {
            let parsed = deserialize_response_event(raw);
            assert!(
                matches!(parsed, Ok(None)),
                "expected {raw} to be skipped, got {:?}",
                parsed.map(|e| e.is_some())
            );
        }
    }

    /// The converse, and the reason the check probes the tag alone: a KNOWN event type whose
    /// body is malformed must still fail closed. Silently dropping a corrupt terminal event
    /// would strand the stream with no `response.completed`, which
    /// `stream::responses`'s `missing_completed_event_yields_failed` shows surfaces as an
    /// opaque `Failed { status: 500 }` -- the real parse error, which names the offending
    /// field, is strictly more useful than that.
    #[test]
    fn known_stream_event_type_with_bad_body_still_errors() {
        let raw = r#"{"type":"response.completed","response":"not-an-object"}"#;
        assert!(
            deserialize_response_event(raw).is_err(),
            "a known event type with a malformed body must not be silently skipped"
        );
    }

    /// The Messages backend has the same open vocabulary as the Responses backend: Anthropic ships
    /// new SSE event types without a version bump, and modelling them as a closed enum turns the
    /// next such release into a dead turn. This exercises the REAL parse the stream performs.
    #[test]
    fn unknown_messages_stream_event_type_is_skipped_not_fatal() {
        for raw in [
            r#"{"type":"keepalive"}"#,
            r#"{"type":"message_heartbeat","sequence":3}"#,
            r#"{"type":"container_start","container":{"id":"c_1"}}"#,
            r#"{"type":"some_future_event","whatever":{"nested":true}}"#,
        ] {
            let parsed = parse_sse_event::<messages::MessageStreamEvent>("messages", raw);
            assert!(
                matches!(parsed, Ok(None)),
                "expected {raw} to be skipped, got {:?}",
                parsed.map(|e| e.is_some())
            );
        }
    }

    /// The converse for the Messages backend: a MODELLED event type whose body is malformed must
    /// still fail closed. Skipping it would strand the stream with no terminal event, which
    /// surfaces later as an opaque failure instead of the parse error that names the bad field.
    #[test]
    fn known_messages_stream_event_type_with_bad_body_still_errors() {
        for raw in [
            // `message_start` requires a `message` object
            r#"{"type":"message_start","message":"not-an-object"}"#,
            // `content_block_delta` requires `index` and `delta`
            r#"{"type":"content_block_delta","index":"zero","delta":{"type":"text_delta","text":"hi"}}"#,
            // `message_delta` is missing `usage` entirely
            r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"}}"#,
        ] {
            assert!(
                parse_sse_event::<messages::MessageStreamEvent>("messages", raw).is_err(),
                "a modelled event type with a malformed body must not be silently skipped: {raw}"
            );
        }
    }

    /// Level two of the same policy: the `content_block` discriminator nested inside a MODELLED
    /// `content_block_start` is its own open vocabulary (`server_tool_use`,
    /// `web_search_tool_result`, `mcp_tool_use`, …). An unmodelled block is preserved verbatim
    /// instead of killing the turn, and re-serializes faithfully so logs stay true to the wire.
    #[test]
    fn unknown_messages_content_block_type_is_preserved_not_fatal() {
        for (raw, tag) in [
            (
                r#"{"type":"content_block_start","index":0,"content_block":{"type":"server_tool_use","id":"srvtoolu_1","name":"web_search","input":{}}}"#,
                "server_tool_use",
            ),
            (
                r#"{"type":"content_block_start","index":1,"content_block":{"type":"web_search_tool_result","tool_use_id":"srvtoolu_1","content":[]}}"#,
                "web_search_tool_result",
            ),
        ] {
            let event = parse_sse_event::<messages::MessageStreamEvent>("messages", raw)
                .expect("an unmodelled content block must not fail the event parse")
                .expect("an unmodelled content block is not an unmodelled EVENT type");
            let messages::MessageStreamEvent::ContentBlockStart { content_block, .. } = event
            else {
                panic!("expected ContentBlockStart for {raw}");
            };
            assert_eq!(
                content_block.unknown_tag(),
                Some(tag),
                "the wire tag must be preserved, not discarded"
            );
            // Faithful re-serialization: the raw payload round-trips unchanged.
            let reserialized = serde_json::to_value(&content_block).expect("re-serialize");
            let expected: serde_json::Value = serde_json::from_str(raw).expect("raw json");
            assert_eq!(reserialized, expected["content_block"]);
        }
    }

    /// The line between "unknown variant" and "corrupt payload", at the NESTED level. A
    /// `tool_use` block that is missing its `id` is not a new block type; it is a broken one, and
    /// tolerating it would make a tool call vanish with no error at all -- strictly worse than
    /// today's abort, which is at least loud.
    #[test]
    fn known_messages_content_block_with_bad_body_still_errors() {
        for raw in [
            // modelled `tool_use`, missing the required `id`
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","name":"do_thing","input":{}}}"#,
            // modelled `text`, `text` is the wrong JSON type
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":42}}"#,
            // modelled `text_delta`, missing the required `text`
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta"}}"#,
        ] {
            assert!(
                parse_sse_event::<messages::MessageStreamEvent>("messages", raw).is_err(),
                "a modelled content block with a malformed body must still fail closed: {raw}"
            );
        }
    }

    /// The Chat Completions payload has no top-level `type` tag, so its open vocabularies are the
    /// nested string enums: `finish_reason` and the response-side `role`. Either one aborting the
    /// terminal chunk discards a response that has already streamed and already been billed.
    #[test]
    fn unknown_chat_completion_vocabularies_are_tolerated() {
        for (raw, expected_finish) in [
            (
                r#"{"id":"c1","object":"chat.completion.chunk","created":0,"model":"m","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"},"finish_reason":"guardrail_intervened"}]}"#,
                "guardrail_intervened",
            ),
            (
                r#"{"id":"c2","object":"chat.completion.chunk","created":0,"model":"m","choices":[{"index":0,"delta":{"role":"model","content":"hi"},"finish_reason":"eos"}]}"#,
                "eos",
            ),
        ] {
            let chunk = serde_json::from_str::<ChatCompletionChunk>(raw)
                .unwrap_or_else(|e| panic!("chunk must parse: {e}\n{raw}"));
            let finish = chunk.choices[0]
                .finish_reason
                .as_ref()
                .expect("finish_reason present");
            assert_eq!(
                finish.wire_str(),
                expected_finish,
                "the wire finish_reason must be preserved verbatim"
            );
            // An unmodelled response role normalizes to the only role a response can carry.
            assert_eq!(
                chunk.choices[0].delta.role,
                Some(fuigo_sampling_types::Role::Assistant)
            );
        }
    }

    /// SSE *comment* lines are the next instance of this class in the wild: OpenRouter's keepalive
    /// is a literal `: OPENROUTER PROCESSING`, which is a comment, not a payload. This asserts the
    /// transport already drops them (and `id:` / `retry:` / unknown fields with it), so no guard is
    /// needed at the JSON boundary -- and pins that property against a future transport swap.
    #[tokio::test]
    async fn sse_comments_and_unknown_fields_never_reach_the_json_parser() {
        let raw: &[&str] = &[
            ": OPENROUTER PROCESSING\n\n",
            "id: 1\nretry: 5000\nx-trace: abc\n\n",
            ":\n\n",
            "event: message\ndata: {\"type\":\"ping\"}\n\n",
            "data: [DONE]\n\n",
        ];
        // `Vec<u8>` rather than `bytes::Bytes` so this test adds no dependency.
        let byte_stream = futures_util::stream::iter(
            raw.iter()
                .map(|s| Ok::<Vec<u8>, std::io::Error>(s.as_bytes().to_vec())),
        );
        let payloads: Vec<String> = byte_stream
            .eventsource()
            .map(|e| e.expect("no transport error").data)
            .collect()
            .await;
        assert_eq!(
            payloads,
            vec!["{\"type\":\"ping\"}".to_owned(), "[DONE]".to_owned()],
            "only `data:` payloads may reach the JSON parser"
        );
    }

    /// The converse for Chat Completions: a structurally broken chunk must still fail. Tolerating
    /// open string vocabularies must not turn into tolerating a corrupt envelope.
    #[test]
    fn malformed_chat_completion_chunk_still_errors() {
        for raw in [
            // `choices` is not an array
            r#"{"id":"c1","object":"chat.completion.chunk","created":0,"model":"m","choices":"none"}"#,
            // required `model` missing
            r#"{"id":"c1","object":"chat.completion.chunk","created":0,"choices":[]}"#,
            // `delta.tool_calls` is the wrong shape
            r#"{"id":"c1","object":"chat.completion.chunk","created":0,"model":"m","choices":[{"index":0,"delta":{"tool_calls":"nope"}}]}"#,
        ] {
            assert!(
                serde_json::from_str::<ChatCompletionChunk>(raw).is_err(),
                "a structurally broken chunk must still fail: {raw}"
            );
        }
    }

    /// `response.completed` carrying `usage.context_details.{input_tokens, output_tokens}` rewrites `usage.total_tokens` in place.
    /// The new value is the live context length (`ctx.input + ctx.output`).
    /// Billing fields stay on the wire's cumulative values.
    #[test]
    fn deserialize_response_event_overrides_total_tokens_from_context_details() {
        let sse = r#"{
            "type": "response.completed",
            "sequence_number": 0,
            "response": {
                "id": "resp_1",
                "object": "response",
                "created_at": 0,
                "model": "fuigo-build",
                "status": "completed",
                "output": [],
                "usage": {
                    "input_tokens": 6003,
                    "input_tokens_details": { "cached_tokens": 1984 },
                    "output_tokens": 711,
                    "output_tokens_details": { "reasoning_tokens": 388 },
                    "total_tokens": 6714,
                    "context_details": {
                        "input_tokens": 5022,
                        "output_tokens": 571
                    }
                }
            }
        }"#;
        let event = deserialize_response_event(sse).expect("parse").expect("event");
        let rs::ResponseStreamEvent::ResponseCompleted(e) = event else {
            panic!("expected ResponseCompleted");
        };
        let usage = e.response.usage.expect("usage present");
        // Billing fields stay cumulative, unchanged by context_details
        assert_eq!(usage.input_tokens, 6003);
        assert_eq!(usage.output_tokens, 711);
        assert_eq!(usage.input_tokens_details.cached_tokens, 1984);
        assert_eq!(usage.output_tokens_details.reasoning_tokens, 388);
        // total_tokens is rewritten to ctx.input + ctx.output (5022 + 571), not the wire's cumulative total (6714)
        assert_eq!(usage.total_tokens, 5_593);
    }

    #[test]
    fn deserialize_response_event_stashes_cost_in_metadata() {
        let make = |ticks: i64| {
            format!(
                r#"{{
                "type": "response.completed",
                "sequence_number": 0,
                "response": {{
                    "id": "resp_1", "object": "response", "created_at": 0,
                    "model": "fuigo-build", "status": "completed", "output": [],
                    "usage": {{
                        "input_tokens": 10,
                        "input_tokens_details": {{ "cached_tokens": 0 }},
                        "output_tokens": 5,
                        "output_tokens_details": {{ "reasoning_tokens": 0 }},
                        "total_tokens": 15,
                        "cost_in_usd_ticks": {ticks}
                    }}
                }}
            }}"#
            )
        };

        let event = deserialize_response_event(&make(78)).expect("parse").expect("event");
        let rs::ResponseStreamEvent::ResponseCompleted(e) = event else {
            panic!("expected ResponseCompleted");
        };
        assert_eq!(
            e.response
                .metadata
                .as_ref()
                .and_then(|m| m.get(COST_USD_TICKS_METADATA_KEY))
                .map(String::as_str),
            Some("78")
        );

        // The REST mapper backfills 0 for unbilled requests: no stash.
        let event = deserialize_response_event(&make(0)).expect("parse").expect("event");
        let rs::ResponseStreamEvent::ResponseCompleted(e) = event else {
            panic!("expected ResponseCompleted");
        };
        assert!(e.response.metadata.is_none());
    }

    #[test]
    fn deserialize_response_event_total_tokens_unchanged_when_context_details_absent() {
        // Older / non-Responses backends omit `context_details`.
        // `total_tokens` passes through from the wire unchanged.
        let sse = r#"{
            "type": "response.completed",
            "sequence_number": 0,
            "response": {
                "id": "resp_1",
                "object": "response",
                "created_at": 0,
                "model": "fuigo-build",
                "status": "completed",
                "output": [],
                "usage": {
                    "input_tokens": 10000,
                    "input_tokens_details": { "cached_tokens": 0 },
                    "output_tokens": 100,
                    "output_tokens_details": { "reasoning_tokens": 0 },
                    "total_tokens": 10100
                }
            }
        }"#;
        let event = deserialize_response_event(sse).expect("parse").expect("event");
        let rs::ResponseStreamEvent::ResponseCompleted(e) = event else {
            panic!("expected ResponseCompleted");
        };
        let usage = e.response.usage.expect("usage present");
        assert_eq!(usage.total_tokens, 10_100);
    }

    #[test]
    fn deserialize_response_event_total_tokens_unchanged_when_context_details_partial() {
        // Defensive: if the backend ever ships only one of the two context_details fields, we can't know the live context size
        // Leave `total_tokens` on the wire's cumulative value instead of guessing; treating the missing half as 0 would silently under-report
        let sse = r#"{
            "type": "response.completed",
            "sequence_number": 0,
            "response": {
                "id": "resp_1",
                "object": "response",
                "created_at": 0,
                "model": "fuigo-build",
                "status": "completed",
                "output": [],
                "usage": {
                    "input_tokens": 6003,
                    "input_tokens_details": { "cached_tokens": 1984 },
                    "output_tokens": 711,
                    "output_tokens_details": { "reasoning_tokens": 388 },
                    "total_tokens": 6714,
                    "context_details": {
                        "input_tokens": 5022
                    }
                }
            }
        }"#;
        let event = deserialize_response_event(sse).expect("parse").expect("event");
        let rs::ResponseStreamEvent::ResponseCompleted(e) = event else {
            panic!("expected ResponseCompleted");
        };
        let usage = e.response.usage.expect("usage present");
        assert_eq!(usage.total_tokens, 6_714);
    }

    #[test]
    fn deserialize_response_event_ignores_context_details_on_non_terminal_events() {
        // Non-terminal events don't carry final usage; even if the backend ever echoed `context_details` on one, we don't touch it
        let sse = r#"{
            "type": "response.output_text.delta",
            "sequence_number": 0,
            "item_id": "item-1",
            "output_index": 0,
            "content_index": 0,
            "delta": "hello",
            "logprobs": []
        }"#;
        let event = deserialize_response_event(sse)
            .expect("non-terminal event parses")
            .expect("event");
        assert!(matches!(
            event,
            rs::ResponseStreamEvent::ResponseOutputTextDelta(_)
        ));
    }

    /// A request as the builder emits it: `reasoning.summary` already set to the built-in default.
    fn built_response_request() -> CreateResponseWrapper {
        CreateResponseWrapper::new(rs::CreateResponse {
            reasoning: Some(rs::Reasoning {
                effort: Some(rs::ReasoningEffort::High),
                summary: Some(rs::ReasoningSummary::Concise),
            }),
            ..Default::default()
        })
    }

    fn client_with_summary(
        summary: Option<fuigo_sampling_types::ReasoningSummary>,
    ) -> SamplingClient {
        SamplingClient::new(SamplerConfig {
            reasoning_summary: summary,
            ..minimal_config()
        })
        .expect("client should construct")
    }

    #[test]
    fn reasoning_summary_unset_keeps_the_built_request() {
        let client = client_with_summary(None);
        let mut request = built_response_request();
        client.apply_response_defaults(&mut request).unwrap();
        let reasoning = request.inner.reasoning.expect("reasoning block kept");
        assert_eq!(reasoning.effort, Some(rs::ReasoningEffort::High));
        assert_eq!(reasoning.summary, Some(rs::ReasoningSummary::Concise));
    }

    #[test]
    fn reasoning_summary_none_omits_the_field_but_keeps_effort() {
        let client = client_with_summary(Some(fuigo_sampling_types::ReasoningSummary::None));
        let mut request = built_response_request();
        client.apply_response_defaults(&mut request).unwrap();
        let body = serde_json::to_value(&request.inner).unwrap();
        assert_eq!(
            body.get("reasoning"),
            Some(&serde_json::json!({ "effort": "high" }))
        );
        let reasoning = request
            .inner
            .reasoning
            .expect("reasoning block kept for effort");
        assert_eq!(reasoning.effort, Some(rs::ReasoningEffort::High));
        assert_eq!(reasoning.summary, None);
    }

    #[test]
    fn reasoning_summary_override_replaces_the_built_value() {
        let client = client_with_summary(Some(fuigo_sampling_types::ReasoningSummary::Detailed));
        let mut request = built_response_request();
        client.apply_response_defaults(&mut request).unwrap();
        assert_eq!(
            request.inner.reasoning.unwrap().summary,
            Some(rs::ReasoningSummary::Detailed)
        );
    }

    #[test]
    fn reasoning_summary_adds_a_reasoning_block_only_when_there_is_something_to_send() {
        let with_summary =
            client_with_summary(Some(fuigo_sampling_types::ReasoningSummary::Auto));
        let mut request = CreateResponseWrapper::new(rs::CreateResponse::default());
        with_summary.apply_response_defaults(&mut request).unwrap();
        assert_eq!(
            request.inner.reasoning,
            Some(rs::Reasoning {
                effort: None,
                summary: Some(rs::ReasoningSummary::Auto),
            })
        );

        let without = client_with_summary(Some(fuigo_sampling_types::ReasoningSummary::None));
        let mut request = CreateResponseWrapper::new(rs::CreateResponse::default());
        without.apply_response_defaults(&mut request).unwrap();
        assert_eq!(request.inner.reasoning, None);
    }

    /// Fuigo divergence (1.0.11 token work): a non-interactive session suppresses the summary at build time,
    /// and a per-model `reasoning_summary` must not put it back.
    #[test]
    fn reasoning_summary_override_never_reinstates_a_suppressed_summary() {
        let client = client_with_summary(Some(fuigo_sampling_types::ReasoningSummary::Detailed));
        let mut request = CreateResponseWrapper::new(rs::CreateResponse {
            reasoning: Some(rs::Reasoning {
                effort: Some(rs::ReasoningEffort::High),
                summary: None,
            }),
            ..Default::default()
        });
        request.suppress_reasoning_summary = true;
        client.apply_response_defaults(&mut request).unwrap();
        let reasoning = request.inner.reasoning.expect("reasoning block kept for effort");
        assert_eq!(reasoning.effort, Some(rs::ReasoningEffort::High));
        assert_eq!(reasoning.summary, None, "suppression wins over the per-model summary");

        let mut request = CreateResponseWrapper::new(rs::CreateResponse::default());
        request.suppress_reasoning_summary = true;
        client.apply_response_defaults(&mut request).unwrap();
        assert_eq!(request.inner.reasoning, None);
    }
}

#[cfg(test)]
mod env_header_resolver_tests {
    use super::*;

    /// Stands in for the shell's resolver: one name answered from memory, every other name from the environment.
    fn in_memory_first(var: &str) -> Option<String> {
        if var == "P08_SAMPLER_KEY_VAR" {
            Some("p08-sampler-runtime-FAKE".to_owned())
        } else {
            std::env::var(var).ok()
        }
    }

    /// P08 (Astra r3): `env_http_headers` resolves through the installed resolver, so a header mapped to a
    /// first-party key name carries the in-memory runtime key rather than an ambient env value.
    #[test]
    fn env_http_headers_resolve_through_the_installed_resolver() {
        install_env_header_resolver(in_memory_first);
        let mut mapping = IndexMap::new();
        mapping.insert("x-api-key".to_owned(), "P08_SAMPLER_KEY_VAR".to_owned());
        let mut headers = HeaderMap::new();
        apply_env_http_headers(&mapping, resolve_env_header_var, &mut headers);
        assert_eq!(
            headers.get("x-api-key").and_then(|v| v.to_str().ok()),
            Some("p08-sampler-runtime-FAKE")
        );
        assert_eq!(resolve_env_header_var("P08_SAMPLER_UNSET_VAR_FOR_TEST"), None);
    }
}

#[cfg(test)]
mod p70b_body_preview_tests {
    use super::*;

    /// P70b: the 500-char error-log preview never cuts through a credential this client sent, so the log writer's
    /// exact-match scrub finds it whole instead of logging a prefix of it.
    #[test]
    fn the_error_log_preview_never_cuts_through_a_sent_credential() {
        let _g = crate::sent_credentials::TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let cred = "p70b-preview-cred-0123456789";
        fuigo_secrets::sent_credentials::record(cred);
        let body = format!("{}{cred} trailing text", "y".repeat(495));
        let preview = SamplingClient::body_preview(body.as_bytes());
        assert!(preview.ends_with(cred), "{preview}");
        assert_eq!(
            fuigo_secrets::sent_credentials::scrub(&preview),
            format!("{}<redacted>", "y".repeat(495))
        );
        // Text with no credential at the cut is capped exactly as before.
        let plain = "z".repeat(800);
        assert_eq!(
            SamplingClient::body_preview(plain.as_bytes())
                .chars()
                .count(),
            500
        );
    }

    /// Through the production constructor and the dispatch recorder: a header configured under a client-written
    /// name that the client does NOT replace is recorded on every request; one the client replaces is never sent
    /// and never recorded; nothing is recorded before a request exists.
    #[test]
    fn configured_headers_are_recorded_iff_they_are_really_sent() {
        use fuigo_secrets::sent_credentials::{clear_for_tests, scrub};
        let _g = crate::sent_credentials::TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        clear_for_tests();
        let mut cfg = SamplerConfig {
            base_url: "https://example.invalid/v1".to_string(),
            model: "test-model".to_string(),
            ..SamplerConfig::default()
        };
        // `traceparent` is a client-written name (the injector stamps it), but this client has no injector, so
        // the configured value is what goes on the wire.
        cfg.extra_headers.insert(
            "traceparent".to_owned(),
            "p70b-configured-agent-id".to_owned(),
        );
        // The client always replaces a configured User-Agent: this value never reaches the wire.
        cfg.extra_headers.insert(
            "user-agent".to_owned(),
            "p70b-never-sent-user-agent".to_owned(),
        );
        // A configured protocol constant under its own header is not a credential.
        cfg.extra_headers.insert(
            ANTHROPIC_VERSION_HEADER.to_owned(),
            ANTHROPIC_VERSION.to_owned(),
        );
        let client = SamplingClient::new(cfg).expect("client");
        assert_eq!(
            client.configured_header_values,
            vec!["p70b-configured-agent-id".to_owned()]
        );
        assert_eq!(
            scrub("p70b-configured-agent-id"),
            "p70b-configured-agent-id"
        );
        let request = client
            .post("https://example.invalid/v1/chat/completions")
            .builder
            .build()
            .expect("request");
        crate::sent_credentials::record_request(&request, &client.configured_header_values);
        assert_eq!(scrub("p70b-configured-agent-id"), "<redacted>");
        assert_eq!(
            scrub("p70b-never-sent-user-agent"),
            "p70b-never-sent-user-agent"
        );
        clear_for_tests();
    }
}
