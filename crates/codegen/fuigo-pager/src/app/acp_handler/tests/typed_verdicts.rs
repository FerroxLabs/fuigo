//! P119 (P70c): the pager decides on the shell's typed verdicts, never on text the shell has scrubbed.
//!
//! Each test sends a retry state through the shell's own sink (`scrub_sent_credentials`, which stamps the verdicts
//! and then replaces every sent credential in the text), with a sent value that overlaps the very phrase the pager
//! used to match, and applies the result as the pager does.

use super::*;
use fuigo_telemetry::sent_credentials;


/// The state as the pager receives it after the shell's sink ran, with `credential` recorded as a sent value.
fn through_the_shell_sink(credential: &str, state: serde_json::Value) -> RetryState {
    sent_credentials::record(credential);
    let mut update = FuigoSessionUpdate::RetryState(serde_json::from_value(state).unwrap());
    update.scrub_sent_credentials();
    let FuigoSessionUpdate::RetryState(state) = update else {
        unreachable!()
    };
    state
}

#[test]
fn a_credit_limit_denial_is_recognised_although_a_sent_value_overlaps_its_marker() {
    let _g = crate::test_util::sent_credentials_lock();
    let state = through_the_shell_sink(
        "status 402",
        serde_json::json!({
            "type": "failed",
            "error_type": "api",
            "message": "API error (status 402 Payment Required): out of balance",
        }),
    );
    let text = format!("{state:?}");
    assert!(!text.contains("status 402"), "the text was scrubbed: {text}");
    let mut session = make_session(Some("s1"));
    let mut scrollback = ScrollbackState::new();
    apply_retry_state(&state, &mut session, &mut scrollback, false);
    assert!(session.credit_limit_blocked);
    sent_credentials::clear_for_tests();
}

#[test]
fn the_free_usage_paywall_is_recognised_although_a_sent_value_overlaps_its_code() {
    let _g = crate::test_util::sent_credentials_lock();
    let state = through_the_shell_sink(
        "subscription:free-usage-exhausted",
        serde_json::json!({
            "type": "exhausted",
            "attempts": 3,
            "reason": "API error (status 429 Too Many Requests): subscription:free-usage-exhausted",
            "is_rate_limited": true,
        }),
    );
    let text = format!("{state:?}");
    assert!(!text.contains("free-usage-exhausted"), "{text}");
    let mut session = make_session(Some("s1"));
    let mut scrollback = ScrollbackState::new();
    apply_retry_state(&state, &mut session, &mut scrollback, false);
    assert!(session.free_usage_blocked);
    sent_credentials::clear_for_tests();
}

#[test]
fn a_reauth_failure_is_recognised_although_a_sent_value_overlaps_its_marker() {
    let _g = crate::test_util::sent_credentials_lock();
    let state = through_the_shell_sink(
        "Unauthorized (401)",
        serde_json::json!({
            "type": "failed",
            "error_type": "api",
            "message": "Unauthorized (401): the token has expired",
        }),
    );
    let text = format!("{state:?}");
    assert!(!text.contains("Unauthorized (401)"), "{text}");
    let mut session = make_session(Some("s1"));
    let mut scrollback = ScrollbackState::new();
    apply_retry_state(&state, &mut session, &mut scrollback, false);
    assert!(matches!(
        last_session_event(&scrollback),
        Some(SessionEvent::ReAuthRequired)
    ));
    sent_credentials::clear_for_tests();
}

/// A state from an older shell has no verdicts and an unscrubbed text: it is still read by its words.
#[test]
fn a_state_without_verdicts_is_still_judged_by_its_text() {
    let state: RetryState = serde_json::from_value(serde_json::json!({
        "type": "failed",
        "error_type": "api",
        "message": "API error (status 402 Payment Required): out of balance",
    }))
    .unwrap();
    assert!(state.verdicts().is_none());
    let mut session = make_session(Some("s1"));
    let mut scrollback = ScrollbackState::new();
    apply_retry_state(&state, &mut session, &mut scrollback, false);
    assert!(session.credit_limit_blocked);
}
