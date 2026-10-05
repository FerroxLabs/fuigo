//! Typed error verdicts (P119 / P70c, closes the open HIGH of P70b R088).
//!
//! The shell hides every credential it sent upstream in the human text of an error, at the sinks where text leaves
//! the agent ([`crate::agent::credential_scrub`], `SessionUpdate::scrub_sent_credentials`). A client that decides
//! something (a credit-limit upsell, a re-auth prompt, the free-usage paywall, the status in a headline) by matching
//! the words of that text would then decide on text a credential had been cut out of: a sent value that overlaps a
//! marker phrase would change the decision.
//!
//! So the decisions travel as data. The shell computes them from the error text as it arrived, before anything is
//! replaced, and sends them next to the text: as `verdicts` on a [`crate::extensions::notification::RetryState`],
//! and as `data.verdicts` on an error reply. A client decides on [`ErrorVerdicts`] and only DISPLAYS the text. A
//! client that receives no verdicts (an older shell, whose text was never scrubbed) falls back to reading the text
//! with the same functions this module exports, so both ends share one definition of every marker.
//!
//! Nothing in this module reads scrubbed text: it is called from the places that still hold the original.

use serde::{Deserialize, Serialize};

/// Key of the verdicts object inside an error reply's `data`.
pub const ERROR_VERDICTS_DATA_KEY: &str = "verdicts";

/// What a client needs to decide about an upstream failure, read from its text before any credential is replaced.
///
/// Every field has the exact meaning of the text check the pager used to run itself (see the constructors), so a
/// client that switches from the text to the verdicts changes nothing but the input.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorVerdicts {
    /// A credit-limit or spend-block denial (HTTP 402, or 403 with the legacy "run out of credits" wording).
    #[serde(default)]
    pub credit_limit: bool,
    /// The well-known free-usage-exhausted code is in the text.
    #[serde(default)]
    pub free_usage: bool,
    /// A recoverable authentication failure: the user can fix it by signing in again.
    #[serde(default)]
    pub reauth: bool,
    /// The HTTP status the text names (4xx/5xx), when it names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    /// The text is, or quotes, the max-tokens truncation message.
    #[serde(default)]
    pub max_tokens_truncation: bool,
    /// The text is a transport dump (`request error: ...`).
    #[serde(default)]
    pub http_dump: bool,
    /// The text is, or wraps, a disk-full (ENOSPC / quota) failure.
    #[serde(default)]
    pub disk_full: bool,
    /// A 429 body that markets a consumer subscription (replaced by our own copy for display).
    #[serde(default)]
    pub consumer_upsell: bool,
}

impl ErrorVerdicts {
    /// Verdicts for a retry notification's text. A retry state carries no HTTP status, so the credit-limit check
    /// reads the text alone. `error_type` is the state's own kind (`None` for an exhaustion, which the pager has
    /// always judged without one).
    pub fn for_retry(error_type: Option<&str>, text: &str) -> Self {
        Self {
            credit_limit: is_credit_limit_error(None, text),
            free_usage: crate::sampling::error::is_free_usage_exhausted_error(text),
            reauth: crate::extensions::notification::is_reauthable_failure(error_type, text),
            ..Self::sniffed_from(text)
        }
    }

    /// Verdicts for an error reply: `http_status` and `error_kind` as the reply carries them, `text` its human
    /// detail. A status the reply does not carry is recovered from the text.
    pub fn for_error(http_status: Option<u16>, error_kind: Option<&str>, text: &str) -> Self {
        let sniffed = Self::sniffed_from(text);
        Self {
            credit_limit: is_credit_limit_error(http_status.or(sniffed.http_status), text),
            free_usage: crate::sampling::error::is_free_usage_exhausted_error(text),
            reauth: crate::extensions::notification::is_reauthable_failure(error_kind, text),
            ..sniffed
        }
    }

    /// The text-derived fields only (status, truncation, transport dump, upsell); the decision fields stay false.
    /// This is what a client without verdicts computes from the text it received.
    pub fn sniffed_from(text: &str) -> Self {
        Self {
            http_status: parse_http_status(text),
            max_tokens_truncation: text
                .contains(fuigo_sampling_types::error::MAX_TOKENS_TRUNCATION_MESSAGE),
            http_dump: text.trim().starts_with(HTTP_DUMP_PREFIX),
            disk_full: is_disk_full_text(text),
            consumer_upsell: crate::sampling::error::pushes_consumer_subscription_upsell(
                crate::sampling::error::strip_sampling_api_error_prefix(text),
            ),
            ..Self::default()
        }
    }
}

/// Whether `raw` is (or wraps) a disk-full / ENOSPC failure (the one definition; the pager's display helper calls it).
pub fn is_disk_full_text(raw: &str) -> bool {
    raw.contains(fuigo_fast_worktree::OUT_OF_DISK_CONTEXT)
        || raw.contains(fuigo_fast_worktree::ENOSPC_OS_MESSAGE)
        || raw.contains("Disk quota exceeded")
        || raw.contains("Out of disk space")
}

/// `SamplingError::Http`'s Display prefix.
const HTTP_DUMP_PREFIX: &str = "request error:";

/// Verdicts of an error reply, as the shell stamped them into `data.verdicts`; `None` for a reply without them.
pub fn error_verdicts_from_error(
    err: &agent_client_protocol::Error,
) -> Option<ErrorVerdicts> {
    serde_json::from_value(err.data.as_ref()?.get(ERROR_VERDICTS_DATA_KEY)?.clone()).ok()
}

/// Verdicts for the persisted `TurnCompleted` of a failed turn (P119 / P70c): what a client decides on, read from the
/// error as the session holds it, BEFORE `prompt_complete_fields` replaces sent credentials in the text it reports.
///
/// `None` when this process has sent no credential (nothing in the text can have been replaced, so the wire stays what
/// it was and a client reads the text) and for a turn that did not fail. An error that already carries stamped
/// `data.verdicts` hands those on. Otherwise they are computed from the same text the error reply is stamped from.
pub fn verdicts_for_turn_error(err: &agent_client_protocol::Error) -> Option<ErrorVerdicts> {
    if fuigo_telemetry::sent_credentials::is_empty() {
        return None;
    }
    if let Some(stamped) = error_verdicts_from_error(err) {
        return Some(stamped);
    }
    let data = err.data.as_ref();
    let text = match data {
        Some(serde_json::Value::String(text)) => text.as_str(),
        Some(serde_json::Value::Object(map)) => map
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(err.message.as_str()),
        _ => err.message.as_str(),
    };
    let status = data
        .and_then(|d| d.get("http_status"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|status| u16::try_from(status).ok());
    let kind = data
        .and_then(|d| d.get(crate::acp_error::ERROR_KIND_DATA_KEY))
        .and_then(serde_json::Value::as_str);
    Some(ErrorVerdicts::for_error(status, kind, text))
}

/// Whether an API or retry error is a credit-limit or spend-block denial.
///
/// - 402 Payment Required always means a credit or spend block here (Build pool and IC spend blocks); no message filter.
/// - 403 counts only when the body contains "run out of credits" (legacy IC spend wording); other 403s (content-safety, ZDR, ...) are excluded.
pub fn is_credit_limit_error(http_status: Option<u16>, message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    let legacy = m.contains("run out of credits");
    match http_status {
        Some(402) => true,
        Some(403) if legacy => true,
        // Retry notifications embed "status 402" / "status 403" in the body without a separate status field
        None | Some(_) => m.contains("status 402") || (m.contains("status 403") && legacy),
    }
}

/// Pull an HTTP error status out of a raw dump: `API error (status 500): ...`, `Unauthorized (401)`, or our own formatted `Server error (500): ...`.
/// 4xx/5xx only: prose like "status 200" or a year must never classify a failure.
pub fn parse_http_status(raw: &str) -> Option<u16> {
    // Every "status " occurrence, so "status unknown; ... status 503" still finds the code
    let mut from = 0;
    while let Some(i) = find_ignore_ascii_case(&raw[from..], "status ") {
        let after = from + i + "status ".len();
        if let Some(code) = parse_status_digits(&raw[after..], false) {
            return Some(code);
        }
        from = after;
    }
    const MARKERS: &[&str] = &[
        "Unauthorized (",
        "Forbidden (",
        "Not Found (",
        "Bad Request (",
        "Payment Required (",
        "Too Many Requests (",
        "Internal Server Error (",
        "Bad Gateway (",
        "Service Unavailable (",
        "Gateway Timeout (",
        "Payload Too Large (",
        "Request Entity Too Large (",
        "Server error (",
        "Request denied (",
        "Request failed (",
        "Not found (",
        "Bad request (",
        "Request too large (",
        "Service unavailable (",
        "Rate limited (",
        "Request timed out (",
        "Conflict (",
    ];
    for marker in MARKERS {
        if let Some(i) = find_ignore_ascii_case(raw, marker)
            && let Some(code) = parse_status_digits(&raw[i + marker.len()..], true)
        {
            return Some(code);
        }
    }
    None
}

fn find_ignore_ascii_case(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .as_bytes()
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
}

/// Exactly three digits in 400..600. `require_close_paren` for the `"... ("` markers, so prose like "merge conflict (300 files" can't match.
fn parse_status_digits(s: &str, require_close_paren: bool) -> Option<u16> {
    let bytes = s.as_bytes();
    if bytes.len() < 3 || !bytes[..3].iter().all(u8::is_ascii_digit) {
        return None;
    }
    if bytes.get(3).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    if require_close_paren && bytes.get(3) != Some(&b')') {
        return None;
    }
    let code: u16 = s[..3].parse().ok()?;
    (400..600).contains(&code).then_some(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_verdicts_read_the_markers_of_the_original_text() {
        let credit = ErrorVerdicts::for_retry(
            Some("api"),
            "API error (status 402 Payment Required): out of balance",
        );
        assert!(credit.credit_limit);
        assert_eq!(credit.http_status, Some(402));
        assert!(!credit.free_usage && !credit.reauth);

        let free = ErrorVerdicts::for_retry(
            None,
            "API error (status 429 Too Many Requests): subscription:free-usage-exhausted",
        );
        assert!(free.free_usage && !free.credit_limit);

        assert!(ErrorVerdicts::for_retry(Some("auth"), "bad key").reauth);
        assert!(ErrorVerdicts::for_retry(None, "Unauthorized (401): expired").reauth);
        assert!(!ErrorVerdicts::for_retry(Some("legacy_auth"), "Unauthorized (401)").reauth);
    }

    #[test]
    fn error_verdicts_prefer_the_replys_own_status() {
        let v = ErrorVerdicts::for_error(Some(402), Some("api"), "spend block");
        assert!(v.credit_limit);
        let v = ErrorVerdicts::for_error(Some(403), Some("api"), "content policy");
        assert!(!v.credit_limit);
        let v = ErrorVerdicts::for_error(Some(403), Some("api"), "You have run out of credits");
        assert!(v.credit_limit);
        let v = ErrorVerdicts::for_error(None, None, "request error: connection reset");
        assert!(v.http_dump && v.http_status.is_none());
        let v = ErrorVerdicts::for_error(
            None,
            Some("max_tokens_truncation"),
            fuigo_sampling_types::error::MAX_TOKENS_TRUNCATION_MESSAGE,
        );
        assert!(v.max_tokens_truncation);
        assert!(ErrorVerdicts::for_error(None, None, "write failed: No space left on device").disk_full);
        assert!(!ErrorVerdicts::for_error(None, None, "all fine").disk_full);
    }

    #[test]
    fn verdicts_round_trip_and_a_missing_field_reads_false() {
        let v = ErrorVerdicts {
            credit_limit: true,
            http_status: Some(402),
            ..ErrorVerdicts::default()
        };
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(json["creditLimit"], true);
        assert_eq!(json["httpStatus"], 402);
        assert_eq!(serde_json::from_value::<ErrorVerdicts>(json).unwrap(), v);
        let sparse: ErrorVerdicts = serde_json::from_str(r#"{"reauth":true}"#).unwrap();
        assert!(sparse.reauth && !sparse.credit_limit);
    }

    #[test]
    fn parse_http_status_rejects_non_status_numbers() {
        assert_eq!(parse_http_status("expected status 200 but got EOF"), None);
        assert_eq!(parse_http_status("status 2024 items processed"), None);
        assert_eq!(parse_http_status("merge conflict (300 files changed)"), None);
        assert_eq!(
            parse_http_status("status unknown; API error (status 503): overloaded"),
            Some(503)
        );
        assert_eq!(parse_http_status("Unauthorized (401) from https://x"), Some(401));
    }

    /// The rate-limit copy reads the verdicts, not the (possibly scrubbed) detail.
    #[test]
    fn the_rate_limit_message_decides_on_verdicts_when_present() {
        use crate::sampling::error::{
            FREE_USAGE_USER_MESSAGE, RATE_LIMITED_USER_MESSAGE_API_KEY,
            format_rate_limited_user_message_with,
        };
        let free = ErrorVerdicts {
            free_usage: true,
            ..ErrorVerdicts::default()
        };
        assert_eq!(
            format_rate_limited_user_message_with(Some("<redacted>"), false, Some(&free)),
            FREE_USAGE_USER_MESSAGE
        );
        let upsell = ErrorVerdicts {
            consumer_upsell: true,
            ..ErrorVerdicts::default()
        };
        assert_eq!(
            format_rate_limited_user_message_with(Some("<redacted>"), true, Some(&upsell)),
            RATE_LIMITED_USER_MESSAGE_API_KEY
        );
        // No verdicts: the text decides, as before.
        assert_eq!(
            format_rate_limited_user_message_with(Some("slow down"), false, None),
            "slow down"
        );
    }
}
