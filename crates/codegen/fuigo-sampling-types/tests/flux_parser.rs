use fuigo_sampling_types::error::{UpstreamError, parse_upstream_code, parse_upstream_retry_after};
use serde_json::json;

#[test]
fn upstream_code_precedence_and_wrappers() {
    let inner = json!({"error":{"error":"key_budget_reached","provider_specific_fields":{"error":{"state":"key_revoked","type":"cap_reached"}},"code":"credit_exhausted","retry_after":60}});
    for payload in [
        inner.to_string(),
        serde_json::to_string(&inner.to_string()).unwrap(),
    ] {
        for text in [payload.clone(),json!({"error":{"message":format!("litellm model=\"name\": {}{payload} suffix", "prefix ".repeat(50)),"code":"429"}}).to_string()] {
            assert_eq!(parse_upstream_code(text.as_bytes()).as_deref(),Some("key_budget_reached"));
            assert_eq!(parse_upstream_retry_after(text.as_bytes()),Some(60));
        }
    }
    for (body, want) in [
        (
            json!({"error":{"error":"Bad Code","provider_specific_fields":{"error":{"state":"key_revoked","type":"cap_reached"}},"code":"credit_exhausted"}}),
            Some("key_revoked"),
        ),
        (
            json!({"error":{"provider_specific_fields":{"error":{"state":42,"type":"cap_reached"}}}}),
            Some("cap_reached"),
        ),
        (json!({"error":{"code":"429"}}), None),
        (
            json!({"error":{"message":"{'error': 'free_tier_exhausted'}"}}),
            None,
        ),
    ] {
        assert_eq!(
            parse_upstream_code(body.to_string().as_bytes()).as_deref(),
            want
        );
    }
}

#[test]
fn nested_wait_is_integer_bounded_and_header_wins() {
    for error in [
        json!({"retry_after":60}),
        json!({"provider_specific_fields":{"retry_after":60}}),
        json!({"provider_specific_fields":{"error":{"retry_after":60}}}),
    ] {
        let bytes = json!({"error":error}).to_string();
        assert_eq!(parse_upstream_retry_after(bytes.as_bytes()), Some(60));
        assert_eq!(
            UpstreamError {
                retry_after_s: Some(2),
                ..Default::default()
            }
            .with_body(429, bytes.as_bytes())
            .retry_after_s,
            Some(2)
        );
    }
    for n in [0, 7200] {
        assert_eq!(
            parse_upstream_retry_after(json!({"error":{"retry_after":n}}).to_string().as_bytes()),
            Some(n)
        );
    }
}
