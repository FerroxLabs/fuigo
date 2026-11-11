//! S3 supplements; binding TSV rows are never changed.
use fuigo_sampling_types::{
    SamplingError,
    error::UpstreamError,
    refusal::{Action, is_flux_routed},
};
use serde_json::json;

fn error(
    url: &str,
    configured: Option<&str>,
    body: serde_json::Value,
    wait: Option<u64>,
    hold: Option<&str>,
) -> SamplingError {
    let mut u = UpstreamError {
        flux_routed: is_flux_routed(&reqwest::Url::parse(url).unwrap(), configured),
        retry_after_s: wait,
        hold_reason: hold.map(str::to_owned),
        ..Default::default()
    }
    .with_body(429, &serde_json::to_vec(&body).unwrap());
    u.http_status = Some(429);
    SamplingError::Api {
        status: reqwest::StatusCode::TOO_MANY_REQUESTS,
        message: fuigo_sampling_types::error::user_facing_api_error_message(
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            &serde_json::to_vec(&body).unwrap(),
        ),
        model_metadata: None,
        retry_after_secs: wait,
        should_retry: None,
        error_code: None,
        upstream_state: None,
        upstream_type: None,
        upstream_details: u,
    }
}
#[test]
fn s3a_non_flux_gemini_resource_exhausted_keeps_retry() {
    let e = error(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini:generateContent",
        None,
        json!({"error":{"code":429,"message":"Resource has been exhausted (e.g. check quota).","status":"RESOURCE_EXHAUSTED"}}),
        None,
        None,
    );
    assert!(e.is_retryable());
    assert!(!e.is_terminal_refusal());
    assert!(!e.is_retry_vetoed());
    assert_eq!(
        e.upstream().classify(&e.to_string()).action,
        Action::Pass
    );
}
#[test]
fn s3b_non_flux_anthropic_lowercase_rate_limit_honors_wait() {
    let e = error(
        "https://api.anthropic.com/v1/messages",
        None,
        json!({"error":{"type":"rate_limit_error","message":"rate limit exceeded"}}),
        Some(7),
        None,
    );
    assert!(e.is_retryable());
    assert!(!e.is_terminal_refusal());
    assert_eq!(e.retry_after(), Some(7));
    assert_eq!(e.upstream().classify(&e.to_string()).action, Action::Pass);
}
#[test]
fn s3c_flux_unknown_429_pauses() {
    for url in [
        "https://fluxrouter.ai/v1/responses",
        "https://api.fluxrouter.ai/v1/responses",
        "https://staging.api.fluxrouter.ai/v1/responses",
    ] {
        let e = error(
            url,
            None,
            json!({"error":{"message":"opaque refusal"}}),
            None,
            None,
        );
        assert!(!e.is_retryable());
        assert!(e.is_terminal_refusal());
        assert_eq!(e.upstream().classify(&e.to_string()).action, Action::Pause);
    }
}
#[test]
fn non_flux_text_or_transient_header_cannot_change_bare_429() {
    for message in [
        "opaque refusal",
        "Your $1 free credit is used up",
        "API key has been revoked",
        "temporarily reserved",
    ] {
        for hold in [None, Some("concurrency"), Some("provider_rate_limited")] {
            let e = error(
                "https://api.anthropic.com/v1/messages",
                None,
                json!({"error":{"message":message}}),
                None,
                hold,
            );
            assert!(e.is_retryable(), "{message} {hold:?}");
            assert!(!e.is_terminal_refusal());
        }
    }
    let e = error(
        "https://api.anthropic.com/v1/messages",
        None,
        json!({"error":{"code":"key_revoked"}}),
        None,
        None,
    );
    assert!(!e.is_terminal_refusal());
}
#[test]
fn host_comparison_is_request_based_and_exact() {
    for (url, configured, want) in [
        ("https://api.fluxrouter.ai.evil.example/v1", None, false),
        ("https://api.fluxrouter.ai@evil.example/v1", None, false),
        ("https://notfluxrouter.ai/v1", None, false),
        ("https://API.FLUXROUTER.AI./v1", None, true),
        (
            "http://custom.example:8888/v1",
            Some("https://custom.example/flux"),
            true,
        ),
        (
            "https://different.example/v1",
            Some("https://custom.example/v1"),
            false,
        ),
    ] {
        assert_eq!(
            is_flux_routed(&reqwest::Url::parse(url).unwrap(), configured),
            want,
            "{url}"
        );
    }
}
