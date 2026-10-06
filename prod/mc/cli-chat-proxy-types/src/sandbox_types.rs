//! Sandbox API request and response types.
//!
//! These types are shared between the server and clients that use the sandbox API.
//! All types use `camelCase` serialization to match the proto3 canonical JSON encoding
//! used on the wire.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Request body for forking a sandbox session.
/// POST /v1/sandbox/sessions/fork
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxForkRequest {
    /// The source sandbox ID to fork from
    pub source_sandbox_id: String,
    /// Number of copies to create (defaults to 1)
    #[serde(default)]
    pub copies: Option<u32>,
    /// Snapshot bucket to use.
    ///
    /// SECURITY (CWE-284): This field is accepted for backwards compatibility
    /// but MUST NOT be forwarded to backend services. The server always uses the
    /// configured default bucket and enforces this server-side.
    #[serde(default)]
    pub snapshot_bucket: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that a user-supplied snapshotBucket is deserialized but
    /// the handler is expected to ignore it. This test documents the security
    /// invariant: snapshot_bucket from user input must never control GCS access.
    #[test]
    fn test_fork_request_snapshot_bucket_is_ignored_by_convention() {
        // User sends a malicious bucket name
        let json = r#"{
            "sourceSandboxId": "session-123",
            "copies": 2,
            "snapshotBucket": "attacker-controlled-bucket"
        }"#;

        let req: SandboxForkRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.source_sandbox_id, "session-123");
        assert_eq!(req.copies, Some(2));
        // Field is deserialized for backwards compat, but the handler MUST NOT use it.
        assert_eq!(
            req.snapshot_bucket,
            Some("attacker-controlled-bucket".to_string())
        );
    }

    /// Verify fork request works without snapshot_bucket (the expected path).
    #[test]
    fn test_fork_request_without_snapshot_bucket() {
        let json = r#"{"sourceSandboxId": "session-456"}"#;

        let req: SandboxForkRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.source_sandbox_id, "session-456");
        assert_eq!(req.copies, None);
        assert_eq!(req.snapshot_bucket, None);
    }

    // ====================================================================
    // SandboxMode enum serde
    // ====================================================================

    #[test]
    fn test_sandbox_mode_serializes_as_proto3_string() {
        assert_eq!(
            serde_json::to_string(&SandboxMode::WorkspaceServer).unwrap(),
            r#""SANDBOX_MODE_WORKSPACE_SERVER""#
        );
        assert_eq!(
            serde_json::to_string(&SandboxMode::Bare).unwrap(),
            r#""SANDBOX_MODE_BARE""#
        );
        assert_eq!(
            serde_json::to_string(&SandboxMode::Invalid).unwrap(),
            r#""SANDBOX_MODE_INVALID""#
        );
    }

    #[test]
    fn test_sandbox_mode_roundtrip() {
        for mode in [
            SandboxMode::Invalid,
            SandboxMode::WorkspaceServer,
            SandboxMode::Bare,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: SandboxMode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, mode);
        }
    }

    #[test]
    fn test_sandbox_mode_default_is_invalid() {
        assert_eq!(SandboxMode::default(), SandboxMode::Invalid);
    }

    // ====================================================================
    // SandboxStartResponse deserialization from realistic proto3 JSON
    // ====================================================================

    #[test]
    fn test_start_response_from_proto3_json() {
        // Realistic JSON using proto3 canonical JSON encoding.
        // uint64 values like memoryLimitBytes are encoded as strings.
        let json = r#"{
            "sandboxId": "sb-abc123",
            "sessionId": "sess-xyz789",
            "websocketUrl": "wss://sandbox.example.com/ws",
            "environment": {
                "environment": {
                    "environmentId": "env-001",
                    "name": "test-env",
                    "repository": "org/repo",
                    "requestedMemoryBytes": "17179869184",
                    "requestedCpus": 4,
                    "cachingEnabled": true,
                    "preinstalledPackages": {"python": "3.11"}
                },
                "environmentVariables": [
                    {"key": "FOO", "value": "bar"}
                ],
                "secrets": [],
                "userRole": "ROLE_OWNER"
            },
            "directUrls": {"6013": "http://direct.example.com:6013"},
            "cloudflareUrls": {"443": "https://cf.example.com"},
            "mode": "SANDBOX_MODE_BARE"
        }"#;

        let resp: SandboxStartResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.sandbox_id, "sb-abc123");
        assert_eq!(resp.session_id, "sess-xyz789");
        assert_eq!(resp.websocket_url, "wss://sandbox.example.com/ws");
        assert_eq!(resp.mode, Some(SandboxMode::Bare));

        // Verify direct_urls / cloudflare_urls maps
        assert_eq!(
            resp.direct_urls.get("6013").map(|s| s.as_str()),
            Some("http://direct.example.com:6013")
        );
        assert_eq!(
            resp.cloudflare_urls.get("443").map(|s| s.as_str()),
            Some("https://cf.example.com")
        );

        // Verify nested environment
        let env_meta = resp.environment.as_ref().unwrap();
        let env = env_meta.environment.as_ref().unwrap();
        assert_eq!(env.environment_id.as_deref(), Some("env-001"));
        assert_eq!(env.name.as_deref(), Some("test-env"));
        assert_eq!(env.requested_memory_bytes.as_deref(), Some("17179869184"));
        assert_eq!(env.requested_cpus, Some(4));
        assert_eq!(env.caching_enabled, Some(true));
        assert_eq!(
            env.preinstalled_packages.get("python").map(|s| s.as_str()),
            Some("3.11")
        );

        // Verify environment variables
        assert_eq!(env_meta.environment_variables.len(), 1);
        assert_eq!(
            env_meta.environment_variables[0].key.as_deref(),
            Some("FOO")
        );
        assert_eq!(env_meta.user_role.as_deref(), Some("ROLE_OWNER"));
    }

    /// Verify SandboxStartResponse handles missing optional fields gracefully.
    #[test]
    fn test_start_response_minimal_json() {
        let json = r#"{
            "sandboxId": "sb-min",
            "sessionId": "sess-min",
            "websocketUrl": "wss://example.com"
        }"#;

        let resp: SandboxStartResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.sandbox_id, "sb-min");
        assert!(resp.environment.is_none());
        assert!(resp.direct_urls.is_empty());
        assert!(resp.cloudflare_urls.is_empty());
        assert!(resp.mode.is_none());
    }

    // ====================================================================
    // SandboxEnvironmentResponse roundtrip
    // ====================================================================

    #[test]
    fn test_environment_response_roundtrip() {
        let resp = SandboxEnvironmentResponse {
            environment: Some(SandboxEnvironmentWithMetadata {
                environment: Some(SandboxEnvironment {
                    environment_id: Some("env-rt".into()),
                    name: Some("roundtrip".into()),
                    caching_enabled: Some(false),
                    preinstalled_packages: HashMap::from([("node".into(), "20".into())]),
                    ..Default::default()
                }),
                environment_variables: vec![SandboxEnvironmentVariable {
                    key: Some("KEY".into()),
                    value: Some("VAL".into()),
                }],
                secrets: vec![],
                user_role: Some("ROLE_EDITOR".into()),
            }),
        };

        let json = serde_json::to_string(&resp).unwrap();
        let back: SandboxEnvironmentResponse = serde_json::from_str(&json).unwrap();

        let env = back
            .environment
            .as_ref()
            .unwrap()
            .environment
            .as_ref()
            .unwrap();
        assert_eq!(env.environment_id.as_deref(), Some("env-rt"));
        assert_eq!(env.name.as_deref(), Some("roundtrip"));
        assert_eq!(
            env.preinstalled_packages.get("node").map(|s| s.as_str()),
            Some("20")
        );
    }
}

/// Information about a single forked session.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxForkedSession {
    /// The provider sandbox ID
    pub sandbox_id: String,
    /// WebSocket URL for connecting to the sandbox
    pub websocket_url: String,
    /// JWT token for authenticating the WebSocket connection
    pub jwt_token: String,
}

/// `url` with userinfo, query and fragment replaced by `<redacted>` (P70): a connect URL may carry a token.
fn url_without_query(url: &str) -> String {
    // Fail closed on anything carrying userinfo or a backslash: transport parsers normalize odd spellings
    // (`https:/user:pw@host`, `\\`) that a string scan here could misread.
    if url.contains(['@', '\\']) {
        return "<redacted url>".to_owned();
    }
    match url.find(['?', '#']) {
        Some(i) => format!("{}{}<redacted>", &url[..i], &url[i..=i]),
        None => url.to_owned(),
    }
}

/// Hand-written `Debug` (P70): credential values print as `<redacted>` (headers and query parameters by name only), so a `{:?}` of this type in a log, panic or error cannot disclose them.
/// The destructure is exhaustive, so a new field fails to compile here until its Debug output is decided.
impl std::fmt::Debug for SandboxForkedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            sandbox_id,
            websocket_url,
            jwt_token: _,
        } = self;
        f.debug_struct("SandboxForkedSession")
            .field("sandbox_id", sandbox_id)
            .field("websocket_url", &url_without_query(websocket_url))
            .field("jwt_token", &"<redacted>")
            .finish()
    }
}

/// Response from forking a sandbox session.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxForkResponse {
    /// List of created sandbox IDs
    pub sandbox_ids: Vec<String>,
    /// Detailed information about each forked session
    pub sessions: Vec<SandboxForkedSession>,
}

/// Request body/query for terminating a sandbox session.
/// DELETE /v1/sandbox/sessions/{sandbox_id}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxTerminateRequest {
    /// Environment ID (defaults to "universal")
    #[serde(default)]
    pub environment_id: Option<String>,
}

// ============================================================================
// Session Lifecycle Types
// ============================================================================

/// Sandbox operating mode.
///
/// Proto3 enum serialized as its string name on the wire
/// (e.g. `"SANDBOX_MODE_BARE"`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxMode {
    #[default]
    #[serde(rename = "SANDBOX_MODE_INVALID")]
    Invalid,
    #[serde(rename = "SANDBOX_MODE_WORKSPACE_SERVER")]
    WorkspaceServer,
    #[serde(rename = "SANDBOX_MODE_BARE")]
    Bare,
}

/// Request body for starting a sandbox session (non-TUI).
/// POST /v1/sandbox/sessions/start
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxStartRequest {
    /// Environment ID to use (defaults to "universal").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_id: Option<String>,
    /// Optional session ID to resume or associate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Repository to clone (e.g. "owner/repo" or full git URL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// Branch to checkout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Memory limit in bytes. Proto3 uint64, serialized as a JSON string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_limit_bytes: Option<String>,
    /// Number of CPUs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<u32>,
    /// Session timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_timeout_seconds: Option<u32>,
    /// Additional environment variables.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub env_vars: HashMap<String, String>,
    /// Disk size in bytes. Proto3 uint64, serialized as a JSON string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_bytes: Option<String>,
    /// Number of GPUs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpus: Option<u32>,
    /// GPU type (e.g. "A100", "H100").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_type: Option<String>,
    /// Sandbox operating mode.
    pub mode: SandboxMode,
}

/// Response from starting a sandbox session.
/// Returned by POST /v1/sandbox/sessions/start.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxStartResponse {
    /// Provider sandbox ID.
    #[serde(default)]
    pub sandbox_id: String,
    /// Session ID for persistence and reconnection.
    #[serde(default)]
    pub session_id: String,
    /// WebSocket URL for connecting to the sandbox.
    #[serde(default)]
    pub websocket_url: String,
    /// Environment configuration returned by the sandbox service.
    #[serde(default)]
    pub environment: Option<SandboxEnvironmentWithMetadata>,
    /// Port-to-URL mapping for direct access.
    #[serde(default)]
    pub direct_urls: HashMap<String, String>,
    /// Port-to-URL mapping for Cloudflare-proxied access.
    #[serde(default)]
    pub cloudflare_urls: HashMap<String, String>,
    /// Which mode was actually started.
    #[serde(default)]
    pub mode: Option<SandboxMode>,
}

/// Response from getting sandbox session status.
/// GET /v1/sandbox/sessions/{id}/status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxStatusResponse {
    /// Status string (e.g. "STARTING", "SETUP", "READY", "ERROR").
    #[serde(default)]
    pub status: String,
    /// Human-readable status message.
    #[serde(default)]
    pub message: String,
    /// Additional metadata (e.g. repository size).
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    /// ISO 8601 timestamp.
    #[serde(default)]
    pub timestamp: Option<String>,
}

/// Exit codes for sandbox log commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxLogsExitCodes {
    /// Exit code of environment variables echo command.
    #[serde(default)]
    pub env: Option<i32>,
    /// Exit code of direct mode logs.
    #[serde(default)]
    pub direct_mode: Option<i32>,
    /// Exit code of git fetch logs.
    #[serde(default)]
    pub fetch: Option<i32>,
}

/// Response from getting sandbox session logs.
/// GET /v1/sandbox/sessions/{id}/logs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxLogsResponse {
    /// Combined environment variables echo stdout/stderr.
    #[serde(default)]
    pub env_vars: String,
    /// Combined direct mode logs stdout/stderr.
    #[serde(default)]
    pub direct_mode_logs: String,
    /// Combined fetch/clone logs stdout/stderr.
    #[serde(default)]
    pub fetch_logs: String,
    /// Exit codes for each command.
    #[serde(default)]
    pub exit_codes: Option<SandboxLogsExitCodes>,
}

/// Response from hibernating a sandbox session.
/// POST /v1/sandbox/sessions/{id}/hibernate
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxHibernateResponse {
    /// GCS path where the snapshot was stored.
    #[serde(default)]
    pub snapshot_path: String,
}

/// Request body for restoring a hibernated sandbox session.
/// POST /v1/sandbox/sessions/{id}/restore
///
/// The `session_id` is provided as a path parameter, not in the body.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxRestoreRequest {
    /// Server key for the restored session's direct-mode agent.
    pub server_key: String,
}

/// Hand-written `Debug` (P70): credential values print as `<redacted>` (headers and query parameters by name only), so a `{:?}` of this type in a log, panic or error cannot disclose them.
/// The destructure is exhaustive, so a new field fails to compile here until its Debug output is decided.
impl std::fmt::Debug for SandboxRestoreRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            server_key: _,
        } = self;
        f.debug_struct("SandboxRestoreRequest")
            .field("server_key", &"<redacted>")
            .finish()
    }
}

/// Response from restoring a hibernated sandbox session.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxRestoreResponse {
    /// Provider sandbox ID of the newly created restored sandbox.
    #[serde(default)]
    pub sandbox_id: String,
    /// GCS path of the snapshot that was restored.
    #[serde(default)]
    pub snapshot_path: String,
    /// WebSocket URL for the restored session.
    #[serde(default)]
    pub websocket_url: String,
}

// ============================================================================
// Environment Types
// ============================================================================

/// A sandbox environment configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxEnvironment {
    #[serde(default)]
    pub environment_id: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub team_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub repository: Option<String>,
    #[serde(default)]
    pub default_branch: Option<String>,
    #[serde(default)]
    pub workspace_directory: Option<String>,
    #[serde(default)]
    pub container_image: Option<String>,
    #[serde(default)]
    pub setup_script: Option<String>,
    #[serde(default)]
    pub maintenance_script: Option<String>,
    #[serde(default)]
    pub caching_enabled: Option<bool>,
    #[serde(default)]
    pub internet_enabled: Option<bool>,
    #[serde(default)]
    pub domain_allowlist_preset: Option<String>,
    #[serde(default)]
    pub additional_domains: Option<String>,
    #[serde(default)]
    pub allowed_http_methods: Option<String>,
    #[serde(default)]
    pub preinstalled_packages: HashMap<String, String>,
    /// ISO 8601 timestamp.
    #[serde(default)]
    pub create_time: Option<String>,
    /// ISO 8601 timestamp.
    #[serde(default)]
    pub modify_time: Option<String>,
    #[serde(default)]
    pub cached_commit_sha: Option<String>,
    #[serde(default)]
    pub provider_id: Option<String>,
    #[serde(default)]
    pub requested_cpus: Option<u32>,
    /// Proto3 uint64, serialized as a JSON string.
    #[serde(default)]
    pub requested_memory_bytes: Option<String>,
    /// Proto3 uint64, serialized as a JSON string.
    #[serde(default)]
    pub requested_disk_bytes: Option<String>,
    #[serde(default)]
    pub requested_gpus: Option<u32>,
}

/// An environment variable key-value pair.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxEnvironmentVariable {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
}

/// Hand-written `Debug` (P70): credential values print as `<redacted>` (headers and query parameters by name only), so a `{:?}` of this type in a log, panic or error cannot disclose them. It carries the elements of `SandboxEnvironmentWithMetadata.secrets`.
/// The destructure is exhaustive, so a new field fails to compile here until its Debug output is decided.
impl std::fmt::Debug for SandboxEnvironmentVariable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            key,
            value,
        } = self;
        f.debug_struct("SandboxEnvironmentVariable")
            .field("key", key)
            .field("value", &value.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// A secret input key-value pair for environment creation/update.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxSecretInput {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
}

/// Hand-written `Debug` (P70): credential values print as `<redacted>` (headers and query parameters by name only), so a `{:?}` of this type in a log, panic or error cannot disclose them.
/// The destructure is exhaustive, so a new field fails to compile here until its Debug output is decided.
impl std::fmt::Debug for SandboxSecretInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            key,
            value,
        } = self;
        f.debug_struct("SandboxSecretInput")
            .field("key", key)
            .field("value", &value.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// A sandbox environment with its associated metadata.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxEnvironmentWithMetadata {
    /// The environment configuration.
    #[serde(default)]
    pub environment: Option<SandboxEnvironment>,
    /// Non-secret environment variables.
    #[serde(default)]
    pub environment_variables: Vec<SandboxEnvironmentVariable>,
    /// Secret environment variables (values may be redacted).
    #[serde(default)]
    pub secrets: Vec<SandboxEnvironmentVariable>,
    /// The requesting user's role for this environment (proto enum as string).
    #[serde(default)]
    pub user_role: Option<String>,
}

/// Hand-written `Debug` (P70): credential values print as `<redacted>` (headers and query parameters by name only), so a `{:?}` of this type in a log, panic or error cannot disclose them.
/// The destructure is exhaustive, so a new field fails to compile here until its Debug output is decided.
impl std::fmt::Debug for SandboxEnvironmentWithMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            environment,
            environment_variables,
            secrets,
            user_role,
        } = self;
        f.debug_struct("SandboxEnvironmentWithMetadata")
            .field("environment", environment)
            .field("environment_variables", environment_variables)
            .field("secrets", &secrets.iter().map(|v| (&v.key, "<redacted>")).collect::<Vec<_>>())
            .field("user_role", user_role)
            .finish()
    }
}

/// Query parameters for listing sandbox environments.
/// Used with GET /v1/sandbox/environments.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxListEnvironmentsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<i32>,
}

/// Response from listing sandbox environments.
/// GET /v1/sandbox/environments
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxListEnvironmentsResponse {
    #[serde(default)]
    pub environments: Vec<SandboxEnvironmentWithMetadata>,
    #[serde(default)]
    pub page: Option<i32>,
    #[serde(default)]
    pub page_size: Option<i32>,
    #[serde(default)]
    pub has_more: Option<bool>,
}

/// Request body for creating a sandbox environment.
/// POST /v1/sandbox/environments
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxCreateEnvironmentRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_directory: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_script: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintenance_script: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caching_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internet_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_allowlist_preset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_domains: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_http_methods: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_variables: Option<Vec<SandboxEnvironmentVariable>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<SandboxSecretInput>>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub preinstalled_packages: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_cpus: Option<u32>,
    /// Proto3 uint64, serialized as a JSON string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_memory_bytes: Option<String>,
    /// Proto3 uint64, serialized as a JSON string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_disk_bytes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_gpus: Option<u32>,
}

/// Response wrapping a single environment with metadata.
///
/// Shared by the create, get, and update environment endpoints since they all
/// return the same shape: `{ "environment": SandboxEnvironmentWithMetadata }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxEnvironmentResponse {
    #[serde(default)]
    pub environment: Option<SandboxEnvironmentWithMetadata>,
}

/// Request body for updating a sandbox environment.
/// PUT /v1/sandbox/environments/{environment_id}
///
/// The `environment_id` is provided as a path parameter, not in the body.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxUpdateEnvironmentRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_directory: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_script: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintenance_script: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caching_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internet_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_allowlist_preset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_domains: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_http_methods: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_variables: Option<Vec<SandboxEnvironmentVariable>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<SandboxSecretInput>>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub preinstalled_packages: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_cpus: Option<u32>,
    /// Proto3 uint64, serialized as a JSON string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_memory_bytes: Option<String>,
    /// Proto3 uint64, serialized as a JSON string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_disk_bytes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_gpus: Option<u32>,
}

/// A preinstalled package available for sandbox environments.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxPreinstalledPackage {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub versions: Vec<String>,
    #[serde(default)]
    pub default_version: Option<String>,
}

/// Response from listing preinstalled packages.
/// GET /v1/sandbox/environments/preinstalled-packages
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxListPreinstalledPackagesResponse {
    #[serde(default)]
    pub packages: Vec<SandboxPreinstalledPackage>,
}

#[cfg(test)]
mod p70_redacted_debug {
    use super::*;

    /// `{x:?}` and `{x:#?}` hold `<redacted>` (control) and no fragment of any secret.
    fn assert_redacted(debug: &dyn std::fmt::Debug, secrets: &[&str]) {
        for out in [format!("{debug:?}"), format!("{debug:#?}")] {
            assert!(out.contains("<redacted>"), "control: the secret field is printed as redacted: {out}");
            for secret in secrets {
                let chars: Vec<char> = secret.chars().collect();
                for w in chars.windows(6) {
                    let frag: String = w.iter().collect();
                    assert!(!out.contains(&frag), "Debug output holds {frag:?} of a secret: {out}");
                }
            }
        }
    }

    #[test]
    fn sandbox_secret_types_debug_redact() {
        let forked = SandboxForkedSession {
            sandbox_id: "p70-sbx".into(),
            websocket_url: "wss://p70user:p70pw-FAKE-4d5e6f7a@p70.invalid/ws/@x?token=p70wq-FAKE-0b1c2d3e".into(),
            jwt_token: "p70jw-FAKE-8f9a0b1c".into(),
        };
        assert_redacted(&forked, &["p70jw-FAKE-8f9a0b1c", "p70pw-FAKE-4d5e6f7a", "p70wq-FAKE-0b1c2d3e"]);
        let restore = SandboxRestoreRequest { server_key: "p70rk-FAKE-8e9f0a1b".into() };
        assert_redacted(&restore, &["p70rk-FAKE-8e9f0a1b"]);
        let secret = SandboxSecretInput { key: Some("P70_NAME".into()), value: Some("p70sv-FAKE-2d3e4f5a".into()) };
        assert_redacted(&secret, &["p70sv-FAKE-2d3e4f5a"]);
        let with_meta = SandboxEnvironmentWithMetadata {
            environment: None,
            environment_variables: Vec::new(),
            secrets: vec![SandboxEnvironmentVariable { key: Some("P70_NAME".into()), value: Some("p70se-FAKE-6b7c8d9e".into()) }],
            user_role: None,
        };
        assert_redacted(&with_meta, &["p70se-FAKE-6b7c8d9e"]);
        let element = SandboxEnvironmentVariable { key: Some("P70_NAME".into()), value: Some("p70ev-FAKE-0f1a2b3c".into()) };
        assert_redacted(&vec![element], &["p70ev-FAKE-0f1a2b3c"]);
    }
}
