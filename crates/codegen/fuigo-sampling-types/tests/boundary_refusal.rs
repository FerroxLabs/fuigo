use fuigo_sampling_types::{
    SamplingError,
    error::UpstreamError,
    refusal::{self, Action},
};
use serde_json::json;

#[test]
fn h5_raw_provider_message_survives_display_selection() {
    let body = json!({"error":{"message":"busy", "provider_specific_fields":{"message":"API key has been revoked"}}});
    let upstream = UpstreamError {
        flux_routed: true,
        ..Default::default()
    }
    .with_body(503, &serde_json::to_vec(&body).unwrap());
    let error = SamplingError::Api {
        status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
        message: "busy".into(),
        model_metadata: None,
        retry_after_secs: None,
        should_retry: None,
        error_code: None,
        upstream_state: None,
        upstream_type: None,
        upstream_details: upstream,
    };
    assert!(error.is_terminal_refusal());
    assert!(!error.is_retryable());
    assert_eq!(
        error
            .upstream()
            .classify("display text deliberately has no refusal")
            .reason,
        "keyRevoked"
    );
}

#[test]
fn r2_non_flux_always_passes_every_status_and_body() {
    for status in [0, 200, 400, 401, 402, 403, 429, 500, 503, 529] {
        for body in [
            json!({}),
            json!({"error":{"code":"key_revoked","message":"API key has been revoked"}}),
        ] {
            let signals = refusal::extract("resp", status, &json!({}), &body, chrono::Utc::now());
            assert_eq!(
                refusal::decide_for_request(&signals, false).action,
                Action::Pass,
                "{status} {body}"
            );
        }
    }
}

#[test]
fn r6_error_and_hold_preserve_existing_wire_vocabulary() {
    let upstream =
        UpstreamError::default().with_body(429, br#"{"error":{"type":"error","state":"hold"}}"#);
    let wire = serde_json::to_value(upstream).unwrap();
    assert_eq!(wire["type"], "error");
    assert_eq!(wire["state"], "hold");
}

#[test]
fn r8_refusal_regexes_are_compiled_once() {
    for source in [
        include_str!("../src/refusal.rs"),
        include_str!("../src/error.rs"),
    ] {
        assert!(
            source.contains("LazyLock"),
            "error-path regexes must be cached"
        );
    }
}

#[test]
fn r1_boundary_guard_rejects_unclassified_errors() {
    let error = SamplingError::Auth {
        message: "unclassified network error".into(),
        status: 401,
        credential: fuigo_sampling_types::SentCredential::Unknown,
        upstream: Default::default(),
    };
    let guarded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        error.assert_boundary_classified()
    }));
    assert_eq!(guarded.is_err(), cfg!(debug_assertions));
    let classified = SamplingError::Auth {
        message: "classified network error".into(),
        status: 401,
        credential: fuigo_sampling_types::SentCredential::Unknown,
        upstream: UpstreamError::default().with_body(401, br#"{}"#),
    };
    classified.assert_boundary_classified();
}

#[test]
fn r2_a4_flux_401_type_fallback() {
    for body in [
        b"{}".as_slice(),
        b"not JSON",
        b"",
        br#"{"error":{"message":"unauthorized"}}"#,
    ] {
        for flux in [false, true] {
            let u = UpstreamError {
                flux_routed: flux,
                ..Default::default()
            }
            .with_body(401, body);
            assert_eq!(
                u.error_type.as_deref(),
                flux.then_some("authentication_error"),
                "{flux} {body:?}"
            );
        }
    }
}

#[test]
fn r2_release_unclassified_flux_fails_closed() {
    let u = UpstreamError {
        flux_routed: true,
        http_status: Some(402),
        ..Default::default()
    };
    assert_eq!(u.classification().action, Action::Stop);
    let u = UpstreamError {
        flux_routed: false,
        ..u
    };
    assert_eq!(u.classification().action, Action::Pass);
}
