//! P71 wire-level tests: every shell upload path sends no byte to a storage proxy that is neither
//! FluxRouter-operated nor the operator's own bucket, and still delivers to a FluxRouter-class one.
//!
//! Each test binds two recording mocks (`fuigo_file_utils::gate_testkit`): one addressed as `127.0.0.1`,
//! classified FluxRouter-operated by the test seam (class 1), and one addressed as `localhost`, classified
//! by the production rule as a third-party proxy (class 3). Assertions are on what the mocks RECEIVED.

use std::sync::Arc;

use fuigo_file_utils::UploadMethod;
use fuigo_file_utils::gate_testkit::RecordingEndpoint;

use crate::auth::{AuthManager, AuthMode, FuigoAuth, FuigoComConfig};
use crate::session::repo_changes::TraceExportConfig;

const SETTLE: std::time::Duration = std::time::Duration::from_millis(400);

fn method_for(base: &str) -> UploadMethod {
    UploadMethod::Proxy {
        proxy_base_url: base.to_string(),
        user_token: String::new(),
        deployment_key: Some("p71-deployment-key".to_string()),
        alpha_test_key: None,
    }
}

fn config_for(base: &str) -> TraceExportConfig {
    TraceExportConfig {
        bucket_url: None,
        service_account_key: None,
        upload_method: method_for(base),
        prefix_dir: None,
        gcs_prefix: Some("sess-1".to_string()),
        absolute_paths: false,
        archive_name_override: None,
    }
}

/// A manager holding a static API key: not a session token, so no destination rule stands between
/// the upload and a loopback mock except the P71 gate.
fn api_key_manager() -> Arc<AuthManager> {
    let dir = tempfile::tempdir().unwrap();
    let mgr = AuthManager::new(dir.path(), FuigoComConfig::default());
    mgr.hot_swap(FuigoAuth {
        key: "p71-static-api-key".into(),
        auth_mode: AuthMode::ApiKey,
        ..FuigoAuth::test_default()
    });
    std::mem::forget(dir);
    Arc::new(mgr)
}

/// Assert `path` sent nothing to the third-party mock and reached the FluxRouter-class mock.
/// `run(base_url)` performs the upload under test against `base_url`.
async fn assert_gated<F, Fut>(path: &str, needle: &[u8], run: F)
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let third_party = RecordingEndpoint::third_party().await;
    run(third_party.proxy_base_url()).await;
    third_party.settle(SETTLE).await;
    assert_eq!(third_party.connections(), 0, "{path}: a connection reached the third-party proxy");
    assert!(third_party.received().is_empty(), "{path}: bytes reached the third-party proxy");

    let fluxrouter_class = RecordingEndpoint::fluxrouter_class().await;
    run(fluxrouter_class.proxy_base_url()).await;
    assert!(
        fluxrouter_class.wait_for_request(std::time::Duration::from_secs(5)).await,
        "{path}: nothing reached the FluxRouter-class proxy (positive control)"
    );
    assert!(
        fluxrouter_class.received_contains(needle),
        "{path}: the FluxRouter-class proxy did not receive {:?}",
        String::from_utf8_lossy(needle)
    );
}

#[tokio::test]
async fn tool_definitions_trace_is_gated() {
    // The needle is in the BODY (a tool's description), not in the object path.
    let tools = [crate::sampling::types::ToolDefinition::function(
        "p71_tool",
        Some("P71-TOOLDEF-MARKER reads /home/rowan/work"),
        serde_json::json!({"type": "object"}),
    )];
    let tools = &tools;
    assert_gated("tool_definitions.json", b"P71-TOOLDEF-MARKER reads /home/rowan/work", |base| async move {
        super::trace::upload_tool_definitions(config_for(&base), None, tools, None).await;
    })
    .await;
}

/// The share bundle goes by signed URL: the proxy is asked for a URL, then the bundle is PUT to it. A
/// third-party proxy is not even asked; a FluxRouter-class one is asked AND receives the bundle (the mock's
/// answer points the PUT at itself). The bundle of no messages is the JSON `[]`.
#[tokio::test]
async fn share_bundle_is_gated() {
    let put = format!("PUT {}", fuigo_file_utils::gate_testkit::SIGNED_PUT_PATH);
    assert_gated("share bundle", put.as_bytes(), |base| async move {
        crate::extensions::share::upload_share_data_to_gcs("sess-1", &[], &config_for(&base), None).await;
    })
    .await;
    let fluxrouter_class = RecordingEndpoint::fluxrouter_class().await;
    crate::extensions::share::upload_share_data_to_gcs(
        "sess-1",
        &[],
        &config_for(&fluxrouter_class.proxy_base_url()),
        None,
    )
    .await;
    assert!(fluxrouter_class.received_contains(b"share/sess-1_"), "the object path names the share bundle");
    assert!(fluxrouter_class.received_contains(b"\r\n\r\n[]"), "the bundle body was not PUT");
}

#[tokio::test]
async fn auth_diagnostics_body_and_object_path_are_gated() {
    assert_gated("auth-diagnostics", b"P71-DIAG-MARKER user-123", |base| async move {
        super::gcs::upload_to_auth_diagnostics(
            b"P71-DIAG-MARKER user-123",
            "user-123",
            &method_for(&base),
            api_key_manager(),
        )
        .await;
    })
    .await;
    // The object path names the account; the class 3 mock above received no connection at all, so
    // neither the body nor the path (an `X-Storage-Path` header) left the machine.
}

#[tokio::test]
async fn subagent_metadata_is_gated() {
    let metadata = crate::agent::subagent::SubagentSessionMetadata {
        schema_version: 1,
        session_id: "child-1".into(),
        session_kind: "subagent".into(),
        subagent_id: "sa-1".into(),
        child_session_id: "child-1".into(),
        parent_session_id: "parent-1".into(),
        parent_prompt_id: None,
        subagent_type: "general-purpose".into(),
        description: "P71-SUBAGENT-MARKER".into(),
        role: None,
        persona: None,
        context_normalized: false,
        capability_mode: None,
        reasoning_effort: None,
        model_id: None,
        cwd: Some("/home/rowan/work".into()),
        worktree_path: None,
        isolation_mode: None,
        depth: 0,
        started_at: "2026-01-01T00:00:00Z".into(),
        completed_at: None,
        status: "running".into(),
        duration_ms: None,
        tool_calls: None,
        turns: None,
        error: None,
        fork_copy_error: None,
        resumed_from: None,
    };
    let metadata = Arc::new(metadata);
    assert_gated("subagent.json", b"P71-SUBAGENT-MARKER", |base| {
        let metadata = metadata.clone();
        async move {
            super::trace::upload_subagent_metadata(&metadata, "gs://unused", method_for(&base), api_key_manager())
                .await;
        }
    })
    .await;
}

/// `fuigo/review/comment` and `fuigo/review/comment/delete`: both handlers upload their record through
/// `upload_review_record`. P54 already kept the machine id out of a record bound for a third-party proxy; under
/// P71 that proxy receives no record at all.
#[tokio::test]
async fn review_comment_records_are_gated() {
    for event in ["create", "delete"] {
        assert_gated("review comment record", b"P71-REVIEW-MARKER", move |base| async move {
            crate::extensions::feedback::upload_review_record(
                config_for(&base),
                None,
                "sess-1/comments/c-1.json".to_string(),
                br#"{"event":"x","citation":"P71-REVIEW-MARKER /home/rowan/work/src/lib.rs"}"#.to_vec(),
                event,
            )
            .await;
        })
        .await;
    }
}

/// The one-shot feedback archive: a third-party proxy gets nothing (and the user is told so without
/// being promised a bucket); a FluxRouter-class proxy gets the gzip archive.
#[tokio::test]
async fn feedback_archive_is_gated_and_its_notice_promises_no_bucket() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("events.jsonl"), b"P71-FEEDBACK-MARKER user-123\n").unwrap();

    let third_party = RecordingEndpoint::third_party().await;
    let err = crate::extensions::feedback::send_feedback_archive(
        dir.path().to_path_buf(),
        "sess-1".to_string(),
        config_for(&third_party.proxy_base_url()),
        None,
    )
    .await
    .expect_err("a third-party proxy must not receive the feedback archive");
    assert!(format!("{err:?}").contains("withheld"), "{err:?}");
    third_party.settle(SETTLE).await;
    assert_eq!(third_party.connections(), 0, "the feedback archive reached a third-party proxy");
    let notices = fuigo_file_utils::destination_gate::withheld_notices();
    assert!(notices.iter().any(|n| n == fuigo_file_utils::destination_gate::FEEDBACK_WITHHELD_NOTICE));
    assert!(
        !fuigo_file_utils::destination_gate::FEEDBACK_WITHHELD_NOTICE.to_lowercase().contains("bucket"),
        "the feedback archive has no bucket alternative"
    );

    let fluxrouter_class = RecordingEndpoint::fluxrouter_class().await;
    crate::extensions::feedback::send_feedback_archive(
        dir.path().to_path_buf(),
        "sess-1".to_string(),
        config_for(&fluxrouter_class.proxy_base_url()),
        None,
    )
    .await
    .expect("the feedback archive upload to a FluxRouter-class proxy succeeds");
    assert!(fluxrouter_class.received_contains(b"sess-1/feedback_trace.tar.gz"));
    // The request body is the gzip archive of the session directory: unpack what the mock received and find
    // the session file's own bytes in it.
    let received = fluxrouter_class.received();
    let body = received
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|at| &received[at + 4..])
        .expect("a request with a body");
    assert_eq!(&body[..2], &[0x1f, 0x8b], "the body is not a gzip archive");
    let mut unpacked = Vec::new();
    std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(body), &mut unpacked).expect("gunzip the received body");
    assert!(
        unpacked.windows(28).any(|w| w == b"P71-FEEDBACK-MARKER user-123"),
        "the received archive does not hold the session's events.jsonl"
    );
}

/// `is_destination_refusal` (the pager's retry predicate) recognises a withheld upload, so
/// `fuigo trace` does not back off and retry a destination that cannot change.
#[test]
fn a_withheld_upload_is_a_destination_refusal() {
    let err = fuigo_file_utils::destination_gate::gate_proxy_url("https://third.example/v1", "x").unwrap_err();
    assert!(super::gcs::is_destination_refusal(&err));
    assert!(super::gcs::is_destination_refusal(&err.context("Upload failed")));
    assert!(!super::gcs::is_destination_refusal(&anyhow::anyhow!("network down")));
}
