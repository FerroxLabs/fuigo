//! P119 (P70c): the shell decides from the text as it arrived and sends the decision as data, so a client never has
//! to read words that a credential was cut out of. Public API only, so this compiles against the parent too.

use agent_client_protocol as acp;
use fuigo_shell::agent::credential_scrub::scrub_acp_error;
use fuigo_shell::extensions::notification::SessionUpdate;
use fuigo_telemetry::sent_credentials;

/// A sent value that overlaps the marker phrase of a credit-limit denial (a header the user configured).
const MARKER_CREDENTIAL: &str = "status 402";

#[test]
fn a_retry_state_carries_the_verdicts_read_before_the_credential_was_replaced() {
    sent_credentials::record(MARKER_CREDENTIAL);
    let state = serde_json::json!({
        "type": "failed",
        "error_type": "api",
        "message": "API error (status 402 Payment Required): out of balance",
    });
    let mut update = SessionUpdate::RetryState(serde_json::from_value(state).unwrap());
    update.scrub_sent_credentials();
    let wire = serde_json::to_value(&update).unwrap();
    let state = &wire["retryState"]
        .as_object()
        .map_or(&wire, |_| &wire["retryState"]);
    let text = state["message"].as_str().unwrap();
    assert!(!text.contains(MARKER_CREDENTIAL), "{wire}");
    assert_eq!(state["verdicts"]["creditLimit"], true, "{wire}");
    assert_eq!(state["verdicts"]["httpStatus"], 402, "{wire}");
}

#[test]
fn an_error_reply_carries_the_verdicts_read_before_the_credential_was_replaced() {
    sent_credentials::record(MARKER_CREDENTIAL);
    let err = acp::Error::internal_error().data(serde_json::json!({
        "message": "API error (status 402 Payment Required): out of balance",
        "error_kind": "api",
        "http_status": 402,
    }));
    let data = scrub_acp_error(err).data.expect("data kept");
    assert!(
        !data["message"].as_str().unwrap().contains(MARKER_CREDENTIAL),
        "{data}"
    );
    assert_eq!(data["verdicts"]["creditLimit"], true, "{data}");
    // Discriminators stay as the agent wrote them.
    assert_eq!(data["error_kind"], "api");
    assert_eq!(data["http_status"], 402);
}

/// A persistence failure is not a model failure but a client decides on it too (disk full).
#[test]
fn a_disk_full_reply_carries_its_verdict_although_the_text_was_scrubbed() {
    sent_credentials::record("No space left on device");
    let err = acp::Error::internal_error().data(serde_json::json!({
        "message": "write failed: No space left on device",
        "error_kind": "session_storage",
    }));
    let data = scrub_acp_error(err).data.expect("data kept");
    assert!(!data["message"].as_str().unwrap().contains("No space left"), "{data}");
    assert_eq!(data["verdicts"]["diskFull"], true, "{data}");
}

/// The same verdict reaches every display that renders the error (a memory-note save, a list toast).
#[test]
fn a_disk_full_error_reads_as_disk_full_on_every_display_path() {
    sent_credentials::record("No space left on device");
    let err = acp::Error::internal_error().data(serde_json::json!({
        "message": "memory note write failed: No space left on device (os error 28)",
        "error_kind": "session_storage",
    }));
    let err = scrub_acp_error(err);
    assert_eq!(
        fuigo_shell::sampling::error::acp_error_text(&err),
        "No space left on device"
    );
}
