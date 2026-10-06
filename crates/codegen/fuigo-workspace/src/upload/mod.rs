pub(crate) mod environment;
use crate::telemetry::dc_log;
use environment::WorkspaceIdentity;
use prometheus::{IntCounterVec, IntGauge, register_int_counter_vec, register_int_gauge};
use std::sync::Arc;
use std::sync::LazyLock;
use fuigo_computer_hub_sdk::auth::{AuthCredential, AuthProvider};
use fuigo_file_utils::gcs::StorageConfig;
use fuigo_file_utils::queue::{EnqueueOutcome, TraceExportSource, UploadQueue};
use fuigo_file_utils::storage_client::Auth401AttributionCallback;
use fuigo_file_utils::{TraceExportConfig, UploadMethod};
use fuigo_auth::{AuthCredentialProvider, CredentialSnapshot};
/// `…_pending_bytes` is the series the mandatory queue-memory alert fires on.
static UPLOAD_QUEUE_PENDING_BYTES: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "fuigo_workspace_upload_queue_pending_bytes",
        "Bytes spilled to the upload queue and not yet uploaded"
    )
    .unwrap()
});
static UPLOAD_QUEUE_PENDING: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "fuigo_workspace_upload_queue_pending",
        "Items in the upload queue not yet uploaded"
    )
    .unwrap()
});
/// Per-phase terminal upload outcome: `succeeded` (bytes accepted, not GCS-confirmed) / `failed` / `skipped`.
static UPLOAD_OUTCOME_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "fuigo_workspace_upload_outcome_total",
        "Workspace upload terminal outcomes, by phase and outcome",
        &["phase", "outcome"]
    )
    .unwrap()
});
/// Per-phase upload failures, by error category (`archive_failed` / `enqueue_failed` / `upload_failed`).
static UPLOAD_FAILED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "fuigo_workspace_upload_failed_total",
        "Workspace upload failures, by phase and error category",
        &["phase", "error_category"]
    )
    .unwrap()
});
/// Per-phase deliberate upload skips (policy / missing-config only).
/// Failure declines are counted as failures, not here.
static UPLOAD_SKIPPED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "fuigo_workspace_upload_skipped_total",
        "Workspace uploads deliberately skipped, by phase and skip reason",
        &["phase", "skip_reason"]
    )
    .unwrap()
});
/// Record a terminal upload outcome; call sites pair it with the matching [`record_upload_failed`] / [`record_upload_skipped`] when one applies.
pub(crate) fn record_upload_outcome(phase: &str, outcome: &str) {
    UPLOAD_OUTCOME_TOTAL
        .with_label_values(&[phase, outcome])
        .inc();
}
pub(crate) fn record_upload_failed(phase: &str, error_category: &str) {
    UPLOAD_FAILED_TOTAL
        .with_label_values(&[phase, error_category])
        .inc();
}
pub(crate) fn record_upload_skipped(phase: &str, skip_reason: &str) {
    UPLOAD_SKIPPED_TOTAL
        .with_label_values(&[phase, skip_reason])
        .inc();
}
/// Zero-init this module's metric families. See [`crate::init_metrics`].
pub(crate) fn init_metrics() {
    UPLOAD_QUEUE_PENDING_BYTES.set(UPLOAD_QUEUE_PENDING_BYTES.get());
    UPLOAD_QUEUE_PENDING.set(UPLOAD_QUEUE_PENDING.get());
    for outcome in ["succeeded", "failed", "skipped"] {
        UPLOAD_OUTCOME_TOTAL
            .with_label_values(&["tool_state", outcome])
            .inc_by(0);
    }
    UPLOAD_FAILED_TOTAL
        .with_label_values(&["tool_state", "enqueue_failed"])
        .inc_by(0);
    for reason in ["no_upload_queue", "no_session"] {
        UPLOAD_SKIPPED_TOTAL
            .with_label_values(&["tool_state", reason])
            .inc_by(0);
    }
    for outcome in ["succeeded", "failed"] {
        UPLOAD_OUTCOME_TOTAL
            .with_label_values(&["workspace_environment", outcome])
            .inc_by(0);
    }
    UPLOAD_FAILED_TOTAL
        .with_label_values(&["workspace_environment", "enqueue_failed"])
        .inc_by(0);
}
/// Spawn a detached sampler that mirrors the queue's pending/pending-bytes stats into the Prometheus gauges every `interval`.
/// It also emits a matching queue-aggregate telemetry snapshot so queue pressure is visible in the same log stream as upload outcomes.
pub(crate) fn spawn_queue_stats_sampler(
    queue: Arc<UploadQueue>,
    interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    let stats = queue.stats_arc();
    let sample_period_secs = interval.as_secs();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let pending_bytes = stats
                .pending_bytes
                .load(std::sync::atomic::Ordering::Relaxed);
            let pending = stats.pending.load(std::sync::atomic::Ordering::Relaxed);
            UPLOAD_QUEUE_PENDING_BYTES.set(pending_bytes as i64);
            UPLOAD_QUEUE_PENDING.set(pending as i64);
            dc_log!(
                info,
                pending,
                pending_bytes,
                sample_period_secs,
                "workspace: upload queue pending stats"
            );
        }
    })
}
/// Wraps the server [`AuthProvider`] as an [`AuthCredentialProvider`] and [`HttpAuth`] so the `StorageClient` can authenticate requests.
struct HubAuthCredentialProvider {
    auth: Arc<dyn AuthProvider>,
    /// Resolved workspace owner so `snapshot` can attribute uploads (and 401s) to the real `user_id`/`team_id`.
    identity: WorkspaceIdentity,
    /// P47: the configured auxiliary-service base (`FUIGO_CLI_CHAT_PROXY_BASE_URL`) uploads go to.
    proxy_base_url: String,
}
impl fuigo_auth::visibility::HttpAuth for HubAuthCredentialProvider {
    fn apply(&self, builder: reqwest::RequestBuilder, _base_url: &str) -> reqwest::RequestBuilder {
        let cred = self.auth.current();
        match &cred {
            AuthCredential::Bearer { token, .. } => {
                builder.header("Authorization", format!("Bearer {token}"))
            }
            AuthCredential::Headers { headers, .. } => {
                let mut b = builder;
                for (name, value) in headers {
                    b = b.header(name.as_str(), value.as_str());
                }
                b
            }
        }
    }
}
#[async_trait::async_trait]
impl AuthCredentialProvider for HubAuthCredentialProvider {
    fn snapshot(&self) -> CredentialSnapshot {
        let user_id = self.identity.user_id_opt();
        let team_id = self.identity.team_id();
        let cred = self.auth.current();
        match &cred {
            AuthCredential::Bearer { token } => CredentialSnapshot {
                token: Some(token.clone()),
                user_id,
                team_id,
                ..Default::default()
            },
            AuthCredential::Headers { .. } => CredentialSnapshot {
                user_id,
                team_id,
                ..Default::default()
            },
        }
    }
    async fn refresh_after_unauthorized(&self) -> bool {
        false
    }
    /// P47: the hub credential is the session token (from the leader's `AuthManager` or auth.json), so every upload
    /// destination must be admitted by the service-endpoint trust class with the configured proxy base.
    fn bearer_may_reach(
        &self,
        url: &reqwest::Url,
        _bearer: &str,
    ) -> Result<(), fuigo_auth::BearerDestinationRefused> {
        fuigo_extra_ca::service_trust::session_may_reach_service(
            url.as_str(),
            Some(&self.proxy_base_url),
            |_| false,
        )
        .map_err(|refused| {
            tracing::warn!(origin = %refused.origin, reason = refused.reason_label(), "workspace upload not sent: the session credential may not go to this destination");
            fuigo_auth::BearerDestinationRefused(refused.to_string())
        })
    }
}
/// [`StorageConfig`] implementation that proxies uploads through the configured proxy endpoint using the connection's auth credentials.
pub(crate) struct ProxyStorageConfig {
    method: UploadMethod,
    credentials: Arc<dyn AuthCredentialProvider>,
}
impl ProxyStorageConfig {
    pub(crate) fn new(
        auth: Arc<dyn AuthProvider>,
        api_base_url: String,
        identity: WorkspaceIdentity,
    ) -> Self {
        let credentials: Arc<dyn AuthCredentialProvider> = Arc::new(HubAuthCredentialProvider {
            auth,
            identity,
            proxy_base_url: api_base_url.clone(),
        });
        let method = UploadMethod::Proxy {
            proxy_base_url: api_base_url,
            user_token: "workspace-upload".to_string(),
            deployment_key: None,
            alpha_test_key: None,
        };
        Self {
            method,
            credentials,
        }
    }
}
impl StorageConfig for ProxyStorageConfig {
    fn bucket_url(&self) -> &str {
        "gs://placeholder"
    }
    fn upload_method(&self) -> &UploadMethod {
        &self.method
    }
    fn proxy_credentials(&self) -> Option<Arc<dyn AuthCredentialProvider>> {
        Some(self.credentials.clone())
    }
}
/// Adapts the workspace's [`ProxyStorageConfig`] to the upload queue's [`TraceExportSource`] contract.
/// [`UploadQueue`] resolves fresh proxy credentials through it on every upload attempt.
pub(crate) struct WorkspaceTraceExportSource {
    proxy_storage_config: Arc<ProxyStorageConfig>,
}
impl WorkspaceTraceExportSource {
    pub(crate) fn new(proxy_storage_config: Arc<ProxyStorageConfig>) -> Self {
        Self {
            proxy_storage_config,
        }
    }
}
impl TraceExportSource for WorkspaceTraceExportSource {
    fn resolve(&self) -> TraceExportConfig {
        TraceExportConfig {
            bucket_url: Some(self.proxy_storage_config.bucket_url().to_string()),
            service_account_key: None,
            upload_method: self.proxy_storage_config.upload_method().clone(),
            prefix_dir: None,
            gcs_prefix: None,
            absolute_paths: false,
            archive_name_override: None,
        }
    }
    fn proxy_attribution(&self) -> Option<Arc<dyn Auth401AttributionCallback>> {
        self.proxy_storage_config.proxy_attribution()
    }
    fn proxy_credentials(&self) -> Option<Arc<dyn AuthCredentialProvider>> {
        self.proxy_storage_config.proxy_credentials()
    }
    fn proxy_http_client(&self) -> Option<reqwest::Client> {
        self.proxy_storage_config.proxy_http_client()
    }
}
/// Enqueue the flushed tool-state bytes at `"{session_id}/turn_{turn_number}/tool_state.json"`.
/// The local spill file is named `resources_state.json`, but the durable artifact is `tool_state.json` to match the environment naming scheme.
/// `Enqueued`/`FellBackToInline` are success; `Failed` is an error.
pub(crate) async fn upload_tool_state_queued(
    state_bytes: Vec<u8>,
    session_id: String,
    turn_number: u64,
    upload_queue: Arc<UploadQueue>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let object_path = format!("{session_id}/turn_{turn_number}/tool_state.json");
    let bytes_len = state_bytes.len();
    match upload_queue
        .enqueue_bytes_blocking(
            &state_bytes,
            &object_path,
            "application/json",
            "tool_state",
            &session_id,
            turn_number,
        )
        .await
    {
        EnqueueOutcome::Enqueued => {
            dc_log!(
                info,
                session_id = %session_id,
                turn_number,
                bytes = bytes_len,
                "workspace: tool_state upload enqueued"
            );
            record_upload_outcome("tool_state", "succeeded");
            Ok(())
        }
        EnqueueOutcome::FellBackToInline => {
            dc_log!(
                info,
                session_id = %session_id,
                turn_number,
                bytes = bytes_len,
                "workspace: tool_state upload fell back to inline"
            );
            record_upload_outcome("tool_state", "succeeded");
            Ok(())
        }
        EnqueueOutcome::Deduplicated => {
            dc_log!(
                info,
                session_id = %session_id,
                turn_number,
                "workspace: tool_state upload deduplicated, identical upload already in flight"
            );
            record_upload_outcome("tool_state", "succeeded");
            Ok(())
        }
        EnqueueOutcome::Skipped { reason } => {
            dc_log!(
                info,
                session_id = %session_id,
                turn_number,
                skip_reason = reason.as_str(),
                "workspace: tool_state upload skipped"
            );
            record_upload_skipped("tool_state", &reason);
            record_upload_outcome("tool_state", "skipped");
            Ok(())
        }
        EnqueueOutcome::Failed { reason } => Err(reason.into()),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use fuigo_computer_hub_sdk::auth::AuthCredential;
    fn proxy_config() -> Arc<ProxyStorageConfig> {
        proxy_config_with_identity(WorkspaceIdentity::default())
    }
    fn proxy_config_with_identity(identity: WorkspaceIdentity) -> Arc<ProxyStorageConfig> {
        let auth: Arc<dyn AuthProvider> = Arc::new(AuthCredential::bearer("test-token"));
        Arc::new(ProxyStorageConfig::new(
            auth,
            "https://proxy.example/v1".to_string(),
            identity,
        ))
    }
    /// A Team principal's snapshot must carry the real `user_id` and the `team_id` (from `principal_id`).
    #[test]
    fn snapshot_carries_team_identity() {
        let identity = WorkspaceIdentity::new(
            "user-team-1",
            Some("Team".to_string()),
            Some("team-9".to_string()),
        );
        let cfg = proxy_config_with_identity(identity);
        let snap = cfg
            .proxy_credentials()
            .expect("proxy_credentials must be Some")
            .snapshot();
        assert_eq!(snap.token.as_deref(), Some("test-token"));
        assert_eq!(snap.user_id.as_deref(), Some("user-team-1"));
        assert_eq!(snap.team_id.as_deref(), Some("team-9"));
    }
    /// A User principal's snapshot carries `user_id` but never a `team_id`, even though the same code path runs.
    #[test]
    fn snapshot_user_identity_has_no_team_id() {
        let identity = WorkspaceIdentity::new("user-solo", Some("User".to_string()), None);
        let cfg = proxy_config_with_identity(identity);
        let snap = cfg
            .proxy_credentials()
            .expect("proxy_credentials must be Some")
            .snapshot();
        assert_eq!(snap.user_id.as_deref(), Some("user-solo"));
        assert_eq!(snap.team_id, None);
    }
    /// With no resolved identity (headless / local-dev), `user_id` and `team_id` are `None` but the live bearer token still flows.
    #[test]
    fn snapshot_default_identity_omits_user_and_team() {
        let snap = proxy_config()
            .proxy_credentials()
            .expect("proxy_credentials must be Some")
            .snapshot();
        assert_eq!(snap.token.as_deref(), Some("test-token"));
        assert_eq!(snap.user_id, None);
        assert_eq!(snap.team_id, None);
    }
    /// The `Headers` credential arm must carry the real `user_id` / `team_id` too.
    /// It has no bearer token, so `token` stays `None`.
    #[test]
    fn snapshot_headers_credential_carries_identity() {
        let identity = WorkspaceIdentity::new(
            "user-headers",
            Some("Team".to_string()),
            Some("team-h".to_string()),
        );
        let auth: Arc<dyn AuthProvider> =
            Arc::new(AuthCredential::headers([("x-api-key", "secret")]).expect("headers cred"));
        let provider = HubAuthCredentialProvider {
            auth,
            identity,
            proxy_base_url: "https://proxy.example/v1".into(),
        };
        let snap = provider.snapshot();
        assert_eq!(snap.token, None, "Headers arm carries no bearer token");
        assert_eq!(snap.user_id.as_deref(), Some("user-headers"));
        assert_eq!(snap.team_id.as_deref(), Some("team-h"));
    }
    /// P47: the upload credential follows the service-endpoint trust class: the configured https proxy origin is
    /// admitted; cleartext, loopback and any other origin are refused with the remedy.
    #[test]
    fn p47_upload_bearer_follows_the_service_trust_class() {
        let provider = proxy_config()
            .proxy_credentials()
            .expect("proxy_credentials must be Some");
        let reach = |u: &str| provider.bearer_may_reach(&reqwest::Url::parse(u).unwrap(), "test-token");
        assert!(reach("https://proxy.example/v1/storage/upload").is_ok());
        for refused in [
            "http://proxy.example/v1/storage/upload",
            "https://127.0.0.1/v1/storage/upload",
            "https://proxy.example:8443/v1/storage/upload",
            "https://evil.example/v1/storage/upload",
        ] {
            let err = reach(refused).expect_err(refused);
            assert!(err.0.contains("The request was not made"), "{refused}: {}", err.0);
        }
    }
    /// `WorkspaceTraceExportSource` must delegate all four `TraceExportSource` hooks to the wrapped `ProxyStorageConfig`.
    #[tokio::test]
    async fn workspace_trace_export_source_delegates_all_methods() {
        let source = WorkspaceTraceExportSource::new(proxy_config());
        let cfg = source.resolve();
        assert_eq!(cfg.bucket_url.as_deref(), Some("gs://placeholder"));
        assert!(
            matches!(
                &cfg.upload_method,
                UploadMethod::Proxy { proxy_base_url, .. } if proxy_base_url == "https://proxy.example/v1"
            ),
            "resolve() must carry the proxy upload method + base url"
        );
        let cfg_async = source.resolve_async().await;
        assert_eq!(cfg_async.bucket_url.as_deref(), Some("gs://placeholder"));
        assert!(
            source.proxy_credentials().is_some(),
            "proxy_credentials() must delegate the server credential provider"
        );
        assert!(source.proxy_attribution().is_none());
        assert!(source.proxy_http_client().is_none());
    }
    /// The credential the queue resolves must be the server-backed provider.
    /// Its snapshot carries the live bearer token, not the placeholder baked into `UploadMethod::Proxy`.
    #[test]
    fn workspace_trace_export_source_credentials_snapshot_live_token() {
        let source = WorkspaceTraceExportSource::new(proxy_config());
        let creds = source
            .proxy_credentials()
            .expect("proxy_credentials must be Some");
        assert_eq!(creds.snapshot().token.as_deref(), Some("test-token"));
    }
    use std::path::Path;
    use tempfile::TempDir;
    /// Spawn a real [`UploadQueue`] spilling under `home`.
    /// The proxy points at a dead local port so any background cloud upload fails fast without DNS.
    /// The tests only assert the *enqueue* side (`stats().enqueued`), never the upload itself.
    fn test_queue(home: &Path) -> Arc<UploadQueue> {
        let auth: Arc<dyn AuthProvider> = Arc::new(AuthCredential::bearer("test-token"));
        let proxy = Arc::new(ProxyStorageConfig::new(
            auth,
            "http://127.0.0.1:1/v1".to_string(),
            WorkspaceIdentity::default(),
        ));
        let source: Arc<dyn TraceExportSource> = Arc::new(WorkspaceTraceExportSource::new(proxy));
        Arc::new(UploadQueue::spawn(
            home,
            source,
            fuigo_file_utils::queue::UploadRetryPolicy::default(),
        ))
    }
    /// Pins the tool-state path contract: bytes enqueued at exactly `{session_id}/turn_{N}/tool_state.json`.
    /// The content-type is JSON and the artifact name is `tool_state` (asserted via queue stat and sidecar manifest).
    #[tokio::test]
    async fn tool_state_enqueues_at_session_turn_gcs_path() {
        use fuigo_file_utils::queue::{
            QueueItemSidecar, SIDECAR_SUFFIX, UploadQueue, UploadRetryPolicy,
        };
        let home = tempfile::TempDir::new().unwrap();
        let source: Arc<dyn TraceExportSource> =
            Arc::new(WorkspaceTraceExportSource::new(proxy_config()));
        let policy = UploadRetryPolicy {
            initial_delay: std::time::Duration::from_secs(3600),
            ..UploadRetryPolicy::default()
        };
        let queue = Arc::new(UploadQueue::spawn(home.path(), source, policy));
        let enqueued_before = queue
            .stats()
            .enqueued
            .load(std::sync::atomic::Ordering::Relaxed);
        upload_tool_state_queued(
            br#"{"state":{}}"#.to_vec(),
            "sess-XYZ".to_string(),
            7,
            queue.clone(),
        )
        .await
        .expect("tool_state enqueue should succeed");
        assert_eq!(
            queue
                .stats()
                .enqueued
                .load(std::sync::atomic::Ordering::Relaxed),
            enqueued_before + 1,
            "the tool_state item must enter the queue"
        );
        let queue_dir = home.path().join("upload_queue");
        let sidecar_path = std::fs::read_dir(&queue_dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(SIDECAR_SUFFIX))
            })
            .expect("a sidecar manifest must exist after enqueue");
        let sidecar: QueueItemSidecar =
            serde_json::from_slice(&std::fs::read(&sidecar_path).unwrap()).unwrap();
        assert_eq!(sidecar.gcs_path, "sess-XYZ/turn_7/tool_state.json");
        assert_eq!(sidecar.artifact_name, "tool_state");
        assert_eq!(sidecar.content_type, "application/json");
        assert_eq!(sidecar.session_id, "sess-XYZ");
        assert_eq!(sidecar.turn_number, 7);
    }
    /// The closed field vocabulary; only fields in this set are emitted (never the free-form `reason`/`error`/`*_path`).
    const APPROVED_DC_FIELDS: &[&str] = &[
        "session_id",
        "turn_number",
        "phase",
        "bytes",
        "file_count",
        "pending",
        "pending_bytes",
        "sample_period_secs",
        "error_category",
        "outcome",
        "skip_reason",
        "drain_reason",
        "grace_ms",
        "active_at_start",
        "pending_at_start",
        "producers_at_start",
    ];
    #[derive(Clone)]
    struct CapturedEvent {
        level: tracing::Level,
        target: String,
        message: String,
        fields: Vec<String>,
    }
    #[derive(Default)]
    struct FieldVisitor {
        message: String,
        fields: Vec<String>,
    }
    impl tracing::field::Visit for FieldVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.message = format!("{value:?}");
            } else {
                self.fields.push(field.name().to_string());
            }
        }
    }
    #[derive(Clone)]
    struct CaptureLayer {
        events: Arc<std::sync::Mutex<Vec<CapturedEvent>>>,
    }
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut v = FieldVisitor::default();
            event.record(&mut v);
            let meta = event.metadata();
            self.events.lock().unwrap().push(CapturedEvent {
                level: *meta.level(),
                target: meta.target().to_string(),
                message: v.message,
                fields: v.fields,
            });
        }
    }
    /// Run `f` with a thread-local capturing subscriber; returns only the events on the `workspace::telemetry` target.
    fn capture_dc(f: impl FnOnce()) -> Vec<CapturedEvent> {
        use tracing_subscriber::layer::SubscriberExt;
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let layer = CaptureLayer {
            events: events.clone(),
        };
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, f);
        let out = events.lock().unwrap().clone();
        out.into_iter()
            .filter(|e| e.target == crate::telemetry::TELEMETRY_TARGET)
            .collect()
    }
    /// `dc_log!` pins the target, honors the level, keeps the message a verbatim literal, and only ever carries the approved field vocabulary.
    #[test]
    fn dc_log_pins_target_level_and_vocabulary() {
        let events = capture_dc(|| {
            dc_log!(
                info,
                session_id = %"s",
                turn_number = 1u64,
                bytes = 5usize,
                "constant info message"
            );
            dc_log!(
                warn,
                session_id = %"s",
                outcome = "skipped",
                skip_reason = "no_upload_queue",
                "constant warn message"
            );
        });
        assert_eq!(events.len(), 2, "both events land on the target");
        assert!(
            events
                .iter()
                .all(|e| e.target == crate::telemetry::TELEMETRY_TARGET)
        );
        assert_eq!(events[0].level, tracing::Level::INFO);
        assert_eq!(events[0].message, "constant info message");
        assert_eq!(events[1].level, tracing::Level::WARN);
        for e in &events {
            for f in &e.fields {
                assert!(
                    APPROVED_DC_FIELDS.contains(&f.as_str()),
                    "field {f:?} is not in the approved field vocabulary"
                );
            }
        }
    }
    /// The queue-stats snapshot is INFO, queue-aggregate (no `session_id`), and carries exactly the queue counters.
    #[tokio::test]
    async fn queue_stats_sampler_emits_info_snapshot() {
        let home = TempDir::new().unwrap();
        let queue = test_queue(home.path());
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        {
            use tracing_subscriber::layer::SubscriberExt;
            let layer = CaptureLayer {
                events: events.clone(),
            };
            let subscriber = tracing_subscriber::registry().with(layer);
            let _guard = tracing::subscriber::set_default(subscriber);
            let handle = spawn_queue_stats_sampler(queue, std::time::Duration::from_millis(20));
            // Wait for the first snapshot rather than a fixed 60 ms: a starved host may not run the sampler's task inside that window.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while std::time::Instant::now() < deadline
                && !events
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|e| e.message.contains("upload queue pending stats"))
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            handle.abort();
        }
        let snaps: Vec<_> = events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| {
                e.target == crate::telemetry::TELEMETRY_TARGET
                    && e.message.contains("upload queue pending stats")
            })
            .cloned()
            .collect();
        assert!(
            !snaps.is_empty(),
            "the sampler must emit at least one snapshot"
        );
        let e = &snaps[0];
        assert_eq!(e.level, tracing::Level::INFO);
        let mut fields = e.fields.clone();
        fields.sort();
        assert_eq!(
            fields,
            vec!["pending", "pending_bytes", "sample_period_secs"],
            "queue-aggregate snapshot carries only the queue counters (no session_id)"
        );
    }
}

/// P149 (S14/K16, Astra r2 #1): the upload filter a standalone workspace server installs
/// (`fuigo_file_utils::payload_filter`), since the shell's `/feedback` scrub is not in this process. It applies the same
/// detectors from `fuigo_secrets`: credential shapes and private-key blocks, then the credentials this process sent. A
/// JSON document is scrubbed string by string and re-serialised (so it stays valid JSON); other text as text; bytes
/// that are not UTF-8 are returned as they are.
pub fn workspace_upload_scrub(buf: Vec<u8>) -> Vec<u8> {
    use std::borrow::Cow;
    let text = match String::from_utf8(buf) {
        Ok(text) => text,
        Err(e) => return e.into_bytes(),
    };
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&text) {
        let mut scrub = JsonScrub { recorded: !fuigo_secrets::sent_credentials::is_empty(), pem: Default::default() };
        if !scrub.value(&mut value, None) {
            return text.into_bytes();
        }
        let pretty = text.trim().lines().count() > 1;
        let out = if pretty { serde_json::to_vec_pretty(&value) } else { serde_json::to_vec(&value) };
        return out.unwrap_or_else(|_| b"<redacted>".to_vec());
    }
    let exact = fuigo_secrets::sent_credentials::scrub_owned(text);
    fuigo_secrets::redact_credential_shapes(&exact).into_owned().into_bytes()
}

/// The structural scrub `/feedback` applies (Astra r3 #2), for a process without the shell: string values and property
/// names by credential shape, arrays of byte values decoded and scrubbed whole, and a PEM block whose markers and body
/// sit in separate strings ([`fuigo_secrets::PrivateKeyJoin`]). Recorded credentials run first, then shapes.
struct JsonScrub {
    recorded: bool,
    pem: fuigo_secrets::PrivateKeyJoin,
}

impl JsonScrub {
    fn text(&self, s: &str) -> Option<String> {
        use std::borrow::Cow;
        let exact = self.recorded.then(|| fuigo_secrets::sent_credentials::scrub(s)).and_then(|c| match c {
            Cow::Owned(o) => Some(o),
            Cow::Borrowed(_) => None,
        });
        let base = exact.as_deref().unwrap_or(s);
        match fuigo_secrets::redact_credential_shapes(base) {
            Cow::Owned(o) => Some(o),
            Cow::Borrowed(_) => exact,
        }
    }

    fn value(&mut self, value: &mut serde_json::Value, property: Option<&str>) -> bool {
        use serde_json::Value;
        match value {
            Value::String(s) => {
                let mut changed = false;
                if self.recorded {
                    changed |= fuigo_secrets::sent_credentials::scrub_in_place(s);
                }
                changed |= self.pem.feed(property, s);
                if let std::borrow::Cow::Owned(o) = fuigo_secrets::redact_credential_shapes(s) {
                    *s = o;
                    changed = true;
                }
                changed
            }
            Value::Array(items) => {
                let bytes: Option<Vec<u8>> = (!items.is_empty())
                    .then(|| items.iter().map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok())).collect())
                    .flatten();
                if let Some(bytes) = bytes {
                    // Decode the run, scrub each valid UTF-8 stretch, keep invalid bytes as they are.
                    let exact = self.recorded.then(|| fuigo_secrets::sent_credentials::scrub_bytes(&bytes)).flatten();
                    let current = exact.as_deref().unwrap_or(&bytes);
                    let mut out = Vec::with_capacity(current.len());
                    let mut changed = exact.is_some();
                    for chunk in current.utf8_chunks() {
                        match fuigo_secrets::redact_credential_shapes(chunk.valid()) {
                            std::borrow::Cow::Owned(o) => {
                                changed = true;
                                out.extend_from_slice(o.as_bytes());
                            }
                            std::borrow::Cow::Borrowed(v) => out.extend_from_slice(v.as_bytes()),
                        }
                        out.extend_from_slice(chunk.invalid());
                    }
                    if changed {
                        *items = out.into_iter().map(Value::from).collect();
                    }
                    return changed;
                }
                items.iter_mut().fold(false, |changed, item| self.value(item, property) | changed)
            }
            Value::Object(map) => {
                let mut changed = false;
                for (name, mut item) in std::mem::take(map) {
                    changed |= self.value(&mut item, Some(&name));
                    let mut name = match self.text(&name) {
                        Some(scrubbed) => {
                            changed = true;
                            scrubbed
                        }
                        None => name,
                    };
                    // Two names redacted alike must not overwrite each other's data.
                    let base = name.clone();
                    let mut n = 2;
                    while map.contains_key(&name) {
                        name = format!("{base}#{n}");
                        n += 1;
                    }
                    map.insert(name, item);
                }
                changed
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod p149_upload_scrub_tests {
    /// P149 (Astra r2 #1): a standalone workspace server's `tool_state.json` (scheduler prompts) leaves the machine
    /// with credential shapes, private keys and sent credentials replaced, and stays valid JSON.
    #[test]
    fn workspace_upload_scrub_redacts_tool_state() {
        // Not credential-shaped, so only the sent-credential registry can catch it.
        const SENT: &str = "p149-SYNTH-workspace-sent-0001";
        const GHP: &str = "ghp_p149SYNTHp149SYNTHp149SYNTHp149SYNTH";
        const PEM_BODY: &str = "MIIEp149SYNTHPEMBODYp149SYNTHPEMBODYp149SYNTHPEMBODYp149SYNTHAA";
        fuigo_secrets::sent_credentials::record(SENT);
        let state = serde_json::json!({"scheduler": [{"prompt": format!(
            "run with {SENT} and {GHP}\n-----BEGIN PRIVATE KEY-----\n{PEM_BODY}\n-----END PRIVATE KEY-----\n")}]});
        let out = super::workspace_upload_scrub(serde_json::to_vec(&state).unwrap());
        let text = String::from_utf8(out).unwrap();
        for secret in [SENT, GHP, PEM_BODY] {
            assert!(!text.contains(secret), "{secret}: {text}");
        }
        serde_json::from_str::<serde_json::Value>(&text).expect("still JSON");
        assert!(text.contains("run with <redacted>"), "control: {text}");
        let log = format!("line {GHP}\n");
        assert!(!String::from_utf8(super::workspace_upload_scrub(log.into_bytes())).unwrap().contains(GHP));
        let binary = vec![0x89u8, b'P', b'N', b'G', 0xff];
        assert_eq!(super::workspace_upload_scrub(binary.clone()), binary);
    }

    /// P149 (Astra r3 #2): the structural cases `/feedback` covers: a PEM block split over separate strings, a credential
    /// in a property NAME, and a credential or key held as an array of byte values.
    #[test]
    fn workspace_upload_scrub_matches_feedback_structure() {
        const SENT: &str = "p149-SYNTH-workspace-sent-0002";
        const GHP: &str = "ghp_p149SYNTHp149SYNTHp149SYNTHp149SYNTH";
        const PEM_BODY: &str = "MIIEp149SYNTHPEMBODYp149SYNTHPEMBODYp149SYNTHPEMBODYp149SYNTHAA";
        fuigo_secrets::sent_credentials::record(SENT);
        let bytes = |s: &str| s.bytes().map(serde_json::Value::from).collect::<Vec<_>>();
        let state = serde_json::json!({
            "pem": ["-----BEGIN PRIVATE KEY-----", PEM_BODY, "-----END PRIVATE KEY-----"],
            (GHP): "named by a credential",
            "raw": bytes(&format!("out {GHP} and {SENT}\n")),
        });
        let text = String::from_utf8(super::workspace_upload_scrub(serde_json::to_vec(&state).unwrap())).unwrap();
        for secret in [SENT, GHP, PEM_BODY] {
            assert!(!text.contains(secret), "{secret}: {text}");
        }
        let decoded: serde_json::Value = serde_json::from_str(&text).unwrap();
        let raw: Vec<u8> = decoded["raw"].as_array().unwrap().iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect();
        let raw = String::from_utf8_lossy(&raw).into_owned();
        assert!(!raw.contains(GHP) && !raw.contains(SENT), "byte array: {raw}");
        assert!(raw.starts_with("out "), "control: {raw}");
    }
}
