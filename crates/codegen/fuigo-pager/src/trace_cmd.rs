use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use fuigo_shell::agent::config::Config as AgentConfig;
use fuigo_shell::session::repo_changes::UploadMethod;
use fuigo_shell::util::fuigo_home::fuigo_home;

#[derive(Debug, clap::Args, Clone)]
pub struct TraceArgs {
    /// Session ID to export/upload
    pub session_id: String,
    /// Save locally only, skip remote upload
    #[arg(long)]
    pub local: bool,
    /// Output path (default: $FUIGO_HOME/trace-exports/<session-id>.tar.gz)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Emit machine-readable JSON output
    #[arg(long)]
    pub json: bool,
}

#[derive(serde::Serialize)]
struct TraceResult {
    session_id: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub async fn run(args: TraceArgs, agent_config: &AgentConfig) -> Result<()> {
    // P149 (S14/K16): what this command uploads goes through the trace-upload scrub.
    fuigo_shell::upload::install_upload_scrub();
    if args.local {
        return run_export(
            &args.session_id,
            args.output.as_deref(),
            args.json,
            agent_config,
        )
        .await;
    }

    if !agent_config.is_trace_upload_enabled() {
        tracing::warn!(
            session_id = %args.session_id,
            "trace_cmd: trace uploads disabled in config"
        );
        if !args.json {
            fuigo_tty_utils::cli_eprintln!(
                "Trace uploads disabled. Set [telemetry] trace_upload = true in {}",
                crate::util::display_user_fuigo_path(fuigo_config::USER_CONFIG_FILENAME)
            );
            fuigo_tty_utils::cli_eprintln!("Falling back to local export.");
        }
        return run_export(
            &args.session_id,
            args.output.as_deref(),
            args.json,
            agent_config,
        )
        .await;
    }

    run_upload(
        &args.session_id,
        args.output.as_deref(),
        args.json,
        agent_config,
    )
    .await
}

// ---------------------------------------------------------------------------
// Archive construction
// ---------------------------------------------------------------------------

pub fn build_session_tar(
    session_dir: &Path,
    session_id: &str,
    agent_config: &AgentConfig,
) -> Result<Vec<u8>> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    tracing::info!(
        session_id = %session_id,
        session_dir = %session_dir.display(),
        "trace_cmd: building session tar.gz archive"
    );

    let mut archive_data = Vec::new();
    let mut file_count: u32 = 0;
    {
        let encoder = GzEncoder::new(&mut archive_data, Compression::default());
        let mut archive = tar::Builder::new(encoder);

        file_count += add_directory_to_tar(&mut archive, session_dir, session_id)?;

        let memtrace = crate::memory_trace::collect_for_export(
            &crate::memory_trace::default_dir(),
            crate::memory_trace::ExportLimits::default(),
        );
        for trace in &memtrace {
            append_bytes(
                &mut archive,
                &format!("{session_id}/memtrace/{}", trace.name),
                &trace.data,
            );
        }
        file_count += memtrace.len() as u32;

        let trace_config = build_trace_config_snapshot(agent_config);
        let config_bytes = serde_json::to_vec_pretty(&trace_config)?;
        append_bytes(
            &mut archive,
            &format!("{session_id}/trace_config.json"),
            &config_bytes,
        );
        file_count += 1;

        let metadata = ExportMetadata {
            session_id: session_id.to_owned(),
            fuigo_version: fuigo_version::full_version().to_owned(),
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            exported_at: chrono::Utc::now().to_rfc3339(),
            memtrace_files: memtrace.len(),
        };
        let meta_bytes = serde_json::to_vec_pretty(&metadata)?;
        append_bytes(
            &mut archive,
            &format!("{session_id}/export_metadata.json"),
            &meta_bytes,
        );
        file_count += 1;

        archive
            .into_inner()
            .and_then(|encoder| encoder.finish())
            .context("Failed to finalize tar.gz archive")?;
    }

    tracing::info!(
        session_id = %session_id,
        file_count,
        archive_bytes = archive_data.len(),
        "trace_cmd: archive built"
    );

    Ok(archive_data)
}

#[derive(serde::Serialize)]
struct ExportMetadata {
    session_id: String,
    fuigo_version: String,
    os: String,
    arch: String,
    exported_at: String,
    memtrace_files: usize,
}

/// No URLs, paths, or bucket names, only booleans and config source indicators.
#[derive(serde::Serialize)]
struct TraceConfigSnapshot {
    trace_upload_enabled: bool,
    telemetry_trace_upload: Option<bool>,
    custom_upload_url: bool,
    bucket_url_source: String,
    direct_upload_configured: bool,
    has_bucket_configured: bool,
    has_region_configured: bool,
    has_custom_endpoint: bool,
    has_credentials_file: bool,
    has_inline_credentials: bool,
    has_deployment_key: bool,
}

fn build_trace_config_snapshot(agent_config: &AgentConfig) -> TraceConfigSnapshot {
    TraceConfigSnapshot {
        trace_upload_enabled: agent_config.is_trace_upload_enabled(),
        telemetry_trace_upload: agent_config.telemetry.trace_upload,
        custom_upload_url: agent_config.endpoints.trace_upload_url.is_some(),
        bucket_url_source: match agent_config.endpoints.resolve_trace_bucket_url() {
            Some(resolved) => format!("{}", resolved.source),
            None => "unconfigured".to_owned(),
        },
        direct_upload_configured: agent_config
            .endpoints
            .resolve_direct_upload_method()
            .is_some(),
        has_bucket_configured: agent_config.endpoints.trace_upload_bucket.is_some(),
        has_region_configured: agent_config.endpoints.trace_upload_region.is_some(),
        has_custom_endpoint: agent_config.endpoints.trace_upload_endpoint_url.is_some(),
        has_credentials_file: agent_config
            .endpoints
            .trace_upload_credentials_file
            .is_some(),
        has_inline_credentials: agent_config.endpoints.trace_upload_credentials.is_some(),
        has_deployment_key: agent_config.endpoints.deployment_key.is_some(),
    }
}

fn append_bytes<W: std::io::Write>(archive: &mut tar::Builder<W>, path: &str, data: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    set_mtime(&mut header);
    if let Err(e) = archive.append_data(&mut header, path, data) {
        tracing::warn!(error = %e, "trace_cmd: failed to add file to archive");
        fuigo_tty_utils::cli_eprintln!("  Warning: failed to add {path}: {e}");
    }
}

fn set_mtime(header: &mut tar::Header) {
    header.set_mtime(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );
}

/// P149 (S14/K16, live lane C2 D2): a session file as the trace export packs it. The export is built to leave the
/// machine (`fuigo trace` uploads it; a local bundle is made to be handed on), so every TEXT file gets the `/feedback`
/// archive's scrub (`fuigo_shell::upload::scrub_upload_text`: the credentials this process holds or sent, credential
/// shapes, private-key blocks). A file is text when its extension says so (`.jsonl`, `.log` for terminal output, ...),
/// or when it has no extension and is UTF-8 that is not a PDF. Everything else (an image, a video, a PDF, an archive,
/// any unknown format) is packed byte for byte: replacing bytes inside a format with lengths and offsets would
/// corrupt it (Astra r1, r2). The session directory itself is not changed (K16: local history keeps it).
fn scrub_export_file(path: &Path, data: Vec<u8>) -> Vec<u8> {
    const TEXT: &[&str] = &[
        "json", "jsonl", "ndjson", "txt", "log", "md", "toml", "yaml", "yml", "csv", "tsv", "xml", "html", "htm",
        "sh", "patch", "diff", "lock", "pem", "key", "crt", "cer", "csr", "pub", "env", "cfg", "conf", "ini",
        "properties", "netrc", "npmrc", "pypirc", "gitconfig", "py", "js", "ts", "rs", "go", "rb",
    ];
    let text = match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => TEXT.iter().any(|t| t.eq_ignore_ascii_case(ext)),
        None => std::str::from_utf8(&data).is_ok() && !data.starts_with(b"%PDF"),
    };
    if !text {
        return data;
    }
    fuigo_shell::upload::scrub_upload_text(data)
}

/// Returns the number of files added.
fn add_directory_to_tar<W: std::io::Write>(
    archive: &mut tar::Builder<W>,
    dir: &Path,
    prefix: &str,
) -> Result<u32> {
    let entries =
        std::fs::read_dir(dir).with_context(|| format!("Failed to read {}", dir.display()))?;

    let mut count: u32 = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let archive_path = format!("{prefix}/{name_str}");

        if path.is_dir() {
            count += add_directory_to_tar(archive, &path, &archive_path)?;
        } else if path.is_file() {
            match std::fs::read(&path) {
                Ok(data) => {
                    let data = scrub_export_file(&path, data);
                    append_bytes(archive, &archive_path, &data);
                    count += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "trace_cmd: failed to read file for archive"
                    );
                    fuigo_tty_utils::cli_eprintln!(
                        "  Warning: failed to read {}: {}",
                        path.display(),
                        e
                    );
                }
            }
        }
    }

    Ok(count)
}

// ---------------------------------------------------------------------------
// Upload method diagnostics
// ---------------------------------------------------------------------------

pub struct UploadMethodDisplay<'a> {
    pub method: &'a UploadMethod,
    pub bucket_url: &'a str,
}

impl std::fmt::Display for UploadMethodDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.method {
            UploadMethod::Direct {
                service_account_key,
            } => {
                let auth = if service_account_key.is_some() {
                    "service account key"
                } else {
                    "ambient credentials"
                };
                writeln!(f, "  Method:   Direct GCS")?;
                writeln!(f, "  Bucket:   {}", self.bucket_url)?;
                write!(f, "  Auth:     {auth}")
            }
            UploadMethod::Proxy {
                proxy_base_url,
                deployment_key,
                ..
            } => {
                // P70: no characters of the key (the old head/tail print showed eight, or all of a short key).
                let deploy = if deployment_key.is_some() { "configured" } else { "none" };
                writeln!(f, "  Method:   Proxy")?;
                // P149 (S12): location only (a base URL can carry a password or a query secret).
                writeln!(f, "  Proxy:    {}", fuigo_auth::redact_url(proxy_base_url))?;
                write!(f, "  Deploy:   {deploy}")
            }
            UploadMethod::S3 {
                bucket,
                region,
                endpoint_url,
                credentials_content,
                credentials_file,
                ..
            } => {
                let endpoint = endpoint_url
                    .as_deref()
                    .map_or_else(|| "(default AWS)".to_owned(), fuigo_auth::redact_url);
                let creds = if credentials_content.is_some() {
                    "inline credentials"
                } else if credentials_file.is_some() {
                    "credentials file"
                } else {
                    "ambient credentials"
                };
                writeln!(f, "  Method:   S3")?;
                writeln!(f, "  Bucket:   {bucket}")?;
                writeln!(f, "  Region:   {region}")?;
                writeln!(f, "  Endpoint: {endpoint}")?;
                write!(f, "  Auth:     {creds}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Local export
// ---------------------------------------------------------------------------

pub(crate) fn find_session_dir(session_id: &str) -> Result<PathBuf> {
    fuigo_shell::session::persistence::find_session_dir_by_id(session_id).with_context(|| {
        format!(
            "Session '{session_id}' not found under {}",
            crate::util::display_user_fuigo_path("sessions")
        )
    })
}

pub fn trace_exports_dir() -> PathBuf {
    fuigo_home().join("trace-exports")
}

/// Creates parent directory if needed.
pub fn save_local_bundle(
    archive: &[u8],
    session_id: &str,
    output: Option<&Path>,
) -> Result<PathBuf> {
    let output_path = match output {
        Some(p) => p.to_path_buf(),
        None => trace_exports_dir().join(format!("{session_id}.tar.gz")),
    };

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }

    std::fs::write(&output_path, archive)
        .with_context(|| format!("Failed to write {}", output_path.display()))?;

    tracing::info!(
        session_id = %session_id,
        path = %output_path.display(),
        size_bytes = archive.len(),
        "trace_cmd: local bundle saved"
    );

    Ok(output_path)
}

async fn run_export(
    session_id: &str,
    output: Option<&Path>,
    json: bool,
    agent_config: &AgentConfig,
) -> Result<()> {
    let session_dir = find_session_dir(session_id)?;
    if !json {
        fuigo_tty_utils::cli_eprintln!("Found session at: {}", session_dir.display());
        fuigo_tty_utils::cli_eprintln!("Building session trace archive...");
    }

    let archive = build_session_tar(&session_dir, session_id, agent_config)?;
    let output_path = save_local_bundle(&archive, session_id, output)?;

    if json {
        let result = TraceResult {
            session_id: session_id.to_owned(),
            status: "exported",
            url: None,
            local_path: Some(output_path.display().to_string()),
            error: None,
        };
        fuigo_tty_utils::cli_println!("{}", serde_json::to_string(&result)?);
    } else {
        let size_kb = archive.len() / 1024;
        fuigo_tty_utils::cli_eprintln!("Session trace exported ({size_kb} KB):");
        fuigo_tty_utils::cli_eprintln!("  {}", output_path.display());
        fuigo_tty_utils::cli_println!("{}", output_path.display());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Upload with fallback
// ---------------------------------------------------------------------------

/// Prints upload URL to stdout on success; saves local bundle and returns Err on failure.
async fn run_upload(
    session_id: &str,
    output: Option<&Path>,
    json: bool,
    agent_config: &AgentConfig,
) -> Result<()> {
    let session_dir = find_session_dir(session_id)?;
    if !json {
        fuigo_tty_utils::cli_eprintln!("Found session at: {}", session_dir.display());
    }

    let (upload_method, upload_auth) = resolve_upload_method(agent_config).await;
    let upload_method = match upload_method {
        Some(method) => method,
        None => {
            tracing::warn!(
                session_id = %session_id,
                "trace_cmd: no upload credentials available"
            );
            anyhow::bail!(
                "No upload credentials. Run `fuigo login` or set a deployment key. \
                 See {} for upload overrides.",
                crate::util::display_user_fuigo_path("docs/user-guide")
            );
        }
    };

    if !json {
        fuigo_tty_utils::cli_eprintln!("Building session trace archive...");
    }
    let archive = build_session_tar(&session_dir, session_id, agent_config)?;
    let archive_size = archive.len();

    // Proxy-mode uploads don't need a bucket (the proxy owns the destination); direct GCS uploads do
    let bucket_url = agent_config
        .endpoints
        .resolve_trace_bucket_url()
        .map(|r| r.value);
    if bucket_url.is_none()
        && matches!(
            upload_method,
            fuigo_shell::session::repo_changes::UploadMethod::Direct { .. }
        )
    {
        anyhow::bail!(
            "No trace upload bucket configured. Set `FUIGO_TELEMETRY_GCS_BUCKET`, \
             `FUIGO_TRACE_UPLOAD_BUCKET`, or `endpoints.trace_upload_bucket` in \
             config for direct GCS uploads."
        );
    }
    let bucket_display = bucket_url.as_deref().unwrap_or("proxy-managed");
    let object_path = format!("{session_id}/trace_export.tar.gz");
    let method_desc = UploadMethodDisplay {
        method: &upload_method,
        bucket_url: bucket_display,
    }
    .to_string();

    let upload_config = fuigo_shell::session::repo_changes::TraceExportConfig {
        bucket_url: bucket_url.clone(),
        service_account_key: None,
        prefix_dir: None,
        gcs_prefix: Some(session_id.to_string()),
        absolute_paths: false,
        archive_name_override: None,
        upload_method,
    };

    tracing::info!(
        session_id = %session_id,
        object_path = %object_path,
        archive_bytes = archive_size,
        bucket_url = bucket_display,
        "trace_cmd: starting upload"
    );
    if !json {
        let size_kb = archive_size / 1024;
        fuigo_tty_utils::cli_eprintln!("Uploading session trace ({size_kb} KB)...");
        fuigo_tty_utils::cli_eprintln!("{method_desc}");
    }

    // P47: the credential's kind travels with the upload, so a static API key keeps its own rules and a session
    // token is checked against the proxy base.
    let upload_config =
        fuigo_shell::upload::gcs::ClassifiedProxyUpload::new(upload_config, upload_auth.as_ref());
    match upload_with_retries(&upload_config, &object_path, &archive).await {
        Ok(url) => {
            tracing::info!(session_id = %session_id, url = %url, "trace_cmd: upload succeeded");
            if json {
                let result = TraceResult {
                    session_id: session_id.to_owned(),
                    status: "uploaded",
                    url: Some(url),
                    local_path: None,
                    error: None,
                };
                fuigo_tty_utils::cli_println!("{}", serde_json::to_string(&result)?);
            } else {
                fuigo_tty_utils::cli_eprintln!();
                fuigo_tty_utils::cli_eprintln!("Session trace uploaded successfully.");
                fuigo_tty_utils::cli_eprintln!("  {url}");
                fuigo_tty_utils::cli_println!("{url}");
            }
            Ok(())
        }
        Err(e) => {
            let attempt = UploadAttempt {
                session_id,
                archive: &archive,
                output,
                method_desc: &method_desc,
                object_path: &object_path,
                bucket_url: bucket_display,
                json,
            };
            Err(attempt.handle_failure(&e))
        }
    }
}

pub struct UploadAttempt<'a> {
    pub session_id: &'a str,
    pub archive: &'a [u8],
    pub output: Option<&'a Path>,
    pub method_desc: &'a str,
    pub object_path: &'a str,
    pub bucket_url: &'a str,
    pub json: bool,
}

impl UploadAttempt<'_> {
    /// Saves local bundle and debug log, prints diagnostics.
    pub fn handle_failure(&self, error: &anyhow::Error) -> anyhow::Error {
        let export_dir = trace_exports_dir();
        std::fs::create_dir_all(&export_dir).ok();

        let export_path = save_local_bundle(self.archive, self.session_id, self.output)
            .unwrap_or_else(|write_err| {
                fuigo_tty_utils::cli_eprintln!("Failed to save local bundle: {write_err}");
                export_dir.join(format!("{}.tar.gz", self.session_id))
            });

        let log_path = self.write_debug_log(error, &export_dir);

        if self.json {
            let result = TraceResult {
                session_id: self.session_id.to_owned(),
                status: "failed",
                url: None,
                local_path: Some(export_path.display().to_string()),
                error: Some(format!("{error}")),
            };
            fuigo_tty_utils::cli_println!("{}", serde_json::to_string(&result).unwrap_or_default());
        } else {
            fuigo_tty_utils::cli_eprintln!();
            fuigo_tty_utils::cli_eprintln!("Trace upload failed: {error}");
            fuigo_tty_utils::cli_eprintln!("  Bundle: {}", export_path.display());
            fuigo_tty_utils::cli_eprintln!("  Log:    {}", log_path.display());
            fuigo_tty_utils::cli_eprintln!("  Retry:  fuigo trace {}", self.session_id);
            fuigo_tty_utils::cli_println!("{}", export_path.display());
        }

        anyhow::anyhow!("Trace upload failed for session {}", self.session_id)
    }

    fn write_debug_log(&self, error: &anyhow::Error, output_dir: &Path) -> PathBuf {
        use std::fmt::Write;

        let log_path = output_dir.join(format!("{}.upload.log", self.session_id));
        let mut log = String::new();
        let _ = writeln!(log, "Trace upload debug log");
        let _ = writeln!(log, "======================");
        let _ = writeln!(log, "Timestamp:    {}", chrono::Utc::now().to_rfc3339());
        let _ = writeln!(log, "Fuigo version: {}", fuigo_version::full_version());
        let _ = writeln!(
            log,
            "OS:           {} {}",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        let _ = writeln!(log, "Session ID:   {}", self.session_id);
        let _ = writeln!(log, "Archive size: {} bytes", self.archive.len());
        let _ = writeln!(log, "Object path:  {}", self.object_path);
        let _ = writeln!(log);
        let _ = writeln!(log, "Upload configuration:");
        let _ = writeln!(log, "{}", self.method_desc);
        let _ = writeln!(log);
        // P149 (S12, Astra r3 #5): a transport error quotes its request URL; location only.
        let _ = writeln!(log, "Error:\n  {}", fuigo_auth::redact_urls_in_text(&error.to_string()));
        let _ = writeln!(log);
        let _ = writeln!(
            log,
            "Full error chain:\n  {}",
            fuigo_auth::redact_urls_in_text(&format!("{error:?}"))
        );

        if let Err(e) = std::fs::write(&log_path, &log) {
            fuigo_tty_utils::cli_eprintln!("  Warning: failed to write debug log: {e}");
        }
        log_path
    }
}

// ---------------------------------------------------------------------------
// Upload with retries
// ---------------------------------------------------------------------------

const UPLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

async fn upload_with_retries<C: fuigo_file_utils::gcs::StorageConfig + Sync>(
    config: &C,
    object_path: &str,
    archive: &[u8],
) -> anyhow::Result<String> {
    use backon::{ExponentialBuilder, Retryable};

    let backoff = ExponentialBuilder::default()
        .with_min_delay(std::time::Duration::from_secs(2))
        .with_max_delay(std::time::Duration::from_secs(8))
        .with_max_times(3);

    (|| async {
        tokio::time::timeout(
            UPLOAD_TIMEOUT,
            fuigo_file_utils::gcs::upload_bytes(config, object_path, archive, "application/gzip"),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Upload timed out after {}s", UPLOAD_TIMEOUT.as_secs()))?
    })
    .retry(backoff)
    // P47 / P71: a refused destination sent nothing and cannot change on retry.
    .when(|err| !fuigo_shell::upload::gcs::is_destination_refusal(err))
    .notify(|err, dur| {
        tracing::warn!(error = %err, retry_in = ?dur, "trace_cmd: upload attempt failed, retrying");
        fuigo_tty_utils::cli_eprintln!("  Upload failed, retrying in {}s...", dur.as_secs());
    })
    .await
}

// ---------------------------------------------------------------------------
// Upload method resolution
// ---------------------------------------------------------------------------

/// The upload method, and the credential it was resolved from (P47: its kind decides the destination rule).
pub async fn resolve_upload_method(
    agent_config: &AgentConfig,
) -> (Option<UploadMethod>, Option<fuigo_shell::auth::FuigoAuth>) {
    // On login failure, fall back to ambient creds rather than erroring.
    let auth_token = fuigo_shell::auth::ensure_authenticated_or_noninteractive(
        &agent_config.fuigo_com_config,
        agent_config.endpoints.has_noninteractive_upload_auth(),
        Some("Authentication required for trace upload."),
    )
    .await
    .inspect_err(
        |e| tracing::info!(error = %e, "trace_cmd: auth failed, trying ambient credentials"),
    )
    .ok()
    .flatten();

    // P47: the credential's kind decides whether the trace-upload URL is checked (a session token is; a static API
    // key keeps its own rules).
    let method = agent_config
        .endpoints
        .resolve_upload_method_for_auth(auth_token.as_ref());
    if method.is_none() {
        tracing::warn!("trace_cmd: no upload method available");
    }
    (method, auth_token)
}

#[cfg(test)]
mod p71_gate_tests {
    use super::*;
    use fuigo_file_utils::gate_testkit::RecordingEndpoint;

    const ARCHIVE: &[u8] = b"P71-PAGER-TRACE-ARCHIVE account user-123 /home/rowan/work";

    fn config_for(base: &str) -> fuigo_file_utils::TraceExportConfig {
        fuigo_file_utils::TraceExportConfig {
            bucket_url: None,
            service_account_key: None,
            upload_method: fuigo_file_utils::UploadMethod::Proxy {
                proxy_base_url: base.to_string(),
                user_token: String::new(),
                deployment_key: Some("p71-deployment-key".to_string()),
                alpha_test_key: None,
            },
            prefix_dir: None,
            gcs_prefix: None,
            absolute_paths: false,
            archive_name_override: None,
        }
    }

    /// A config that counts how often an upload attempt asks it for its destination. A refused attempt
    /// asks exactly once (the gate, then it returns), so the count is the number of attempts.
    struct CountingConfig {
        inner: fuigo_file_utils::TraceExportConfig,
        asked: std::sync::atomic::AtomicUsize,
    }
    impl fuigo_file_utils::gcs::StorageConfig for CountingConfig {
        fn bucket_url(&self) -> &str {
            fuigo_file_utils::gcs::StorageConfig::bucket_url(&self.inner)
        }
        fn upload_method(&self) -> &fuigo_file_utils::UploadMethod {
            self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            &self.inner.upload_method
        }
    }

    /// `fuigo trace`: a third-party storage proxy receives no byte, and the refusal is attempted once, never
    /// retried (counted, not timed); a FluxRouter-class proxy receives the archive unchanged.
    #[tokio::test]
    async fn trace_archive_goes_only_to_fluxrouter_class_or_operator_destinations() {
        let third_party = RecordingEndpoint::third_party().await;
        let config = CountingConfig {
            inner: config_for(&third_party.proxy_base_url()),
            asked: std::sync::atomic::AtomicUsize::new(0),
        };
        let err = upload_with_retries(&config, "sess-1/trace_export.tar.gz", ARCHIVE)
            .await
            .expect_err("a third-party proxy must not receive the archive");
        assert!(fuigo_shell::upload::gcs::is_destination_refusal(&err), "{err:#}");
        assert_eq!(
            config.asked.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a withheld upload was retried"
        );
        third_party.settle(std::time::Duration::from_millis(300)).await;
        assert_eq!(third_party.connections(), 0, "the trace archive reached a third-party proxy");

        let fluxrouter_class = RecordingEndpoint::fluxrouter_class().await;
        let _ = upload_with_retries(&config_for(&fluxrouter_class.proxy_base_url()), "sess-1/trace_export.tar.gz", ARCHIVE).await;
        assert!(fluxrouter_class.received_contains(ARCHIVE), "FluxRouter-class proxy did not receive the archive unchanged");
        assert!(fluxrouter_class.received_contains(b"sess-1/trace_export.tar.gz"));
    }
}

#[cfg(test)]
mod p70_deploy_key_display {
    use super::*;

    /// P70: the trace-upload method summary (printed to stderr) holds no run of four characters of the deployment key,
    /// short or long (the old `redact_middle` printed eight of them, or all of a key of 11 characters or fewer).
    #[test]
    fn upload_method_display_shows_no_deployment_key_material() {
        for key in ["dkFAKE7", "p70dk-FAKE-9b8c7d6e5f4a3b2c"] {
            let method = UploadMethod::Proxy {
                proxy_base_url: "https://proxy.p70.invalid".into(),
                user_token: "p70ut-FAKE-1a2b3c4d".into(),
                deployment_key: Some(key.into()),
                alpha_test_key: None,
            };
            let shown = UploadMethodDisplay { method: &method, bucket_url: "gs://p70" }.to_string();
            assert!(shown.contains("Deploy:   configured"), "control: {shown}");
            let chars: Vec<char> = key.chars().collect();
            for w in chars.windows(4) {
                let frag: String = w.iter().collect();
                assert!(!shown.contains(&frag), "the summary holds {frag:?} of the deployment key: {shown}");
            }
            assert!(!format!("{method:?}").contains(key), "Debug holds the deployment key");
        }
    }

    /// P70 (Astra r7): `fuigo serve` arguments: the secret, and credentials in the remote / headless URLs.
    #[test]
    fn serve_args_debug_redacts_secret_and_url_credentials() {
        let args = crate::app::cli::ServeArgs {
            bind: "127.0.0.1:0".parse().unwrap(),
            secret: Some("p70sv-FAKE-1d2e3f4a".into()),
            remote: Some("wss://u:p70rp-FAKE-5b6c7d8e@host/ws?token=p70rq-FAKE-9f0a1b2c".into()),
            headless: crate::app::cli::HeadlessArgs {
                fuigo_ws_url: Some("wss://host/ws?token=p70hw-FAKE-3d4e5f6a".into()),
                ..Default::default()
            },
        };
        for out in [format!("{args:?}"), format!("{args:#?}")] {
            assert!(out.contains("<redacted>"), "control: {out}");
            for secret in ["p70sv-FAKE-1d2e3f4a", "p70rp-FAKE-5b6c7d8e", "p70rq-FAKE-9f0a1b2c", "p70hw-FAKE-3d4e5f6a"] {
                assert!(!out.contains(secret), "Debug holds {secret}: {out}");
            }
        }
    }

    /// P70a (Astra r1): `fuigo agent` arguments: credentials in the two base-URL overrides.
    #[test]
    fn agent_args_debug_redacts_url_credentials() {
        let args = crate::app::cli::AgentArgs {
            reauthenticate: false,
            model: Some("p70-model".into()),
            reasoning_effort: None,
            yolo: false,
            agent_profile: None,
            plugin_dirs: Vec::new(),
            leader: false,
            no_leader: false,
            headless: crate::app::cli::HeadlessArgs::default(),
            cli_chat_proxy_base_url: Some("https://proxy.p70.invalid/v1?key=p70cq-FAKE-7a8b9c0d".into()),
            fuigo_api_base_url: Some("https://u:p70ap-FAKE-1e2f3a4b@api.p70.invalid/v1".into()),
            mode: None,
        };
        for out in [format!("{args:?}"), format!("{args:#?}")] {
            assert!(out.contains("<redacted>") && out.contains("p70-model"), "control: {out}");
            assert!(out.contains("proxy.p70.invalid") && out.contains("api.p70.invalid"), "control: hosts print: {out}");
            for secret in ["p70cq-FAKE-7a8b9c0d", "p70ap-FAKE-1e2f3a4b"] {
                assert!(!out.contains(secret), "Debug holds {secret}: {out}");
            }
        }
    }
}

#[cfg(test)]
mod p149_export_scrub {
    use super::*;

    const SENT: &str = "fuigo-p149-SYNTH-trace-export-key-01";
    const GHP: &str = "ghp_p149SYNTHp149SYNTHp149SYNTHp149SYNTH";
    const PEM_BODY: &str = "MIIEp149SYNTHPEMBODYp149SYNTHPEMBODYp149SYNTHPEMBODYp149SYNTHAA";

    fn unpacked(archive: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
        for entry in tar.entries().unwrap() {
            let mut entry = entry.unwrap();
            let name = entry.path().unwrap().to_string_lossy().into_owned();
            let mut data = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut data).unwrap();
            out.push((name, data));
        }
        out
    }

    /// P149 (S14/K16, live lane C2 D2): `fuigo trace <sid>` packed the session's files as written, so the uploaded
    /// `trace_export.tar.gz` held the sent FUIGO_API_KEY ten times and a PEM private key. The export now carries
    /// `<redacted>` for every credential the process sent or holds, every credential shape and every private-key
    /// block, in JSON-lines records and in plain terminal logs alike; an image is packed byte for byte; the session
    /// directory on disk is unchanged.
    #[test]
    fn the_trace_export_archive_is_scrubbed_and_the_session_dir_is_not() {
        let _registry = crate::test_util::sent_credentials_lock();
        fuigo_telemetry::sent_credentials::record(SENT);
        let dir = tempfile::tempdir().unwrap();
        let session = dir.path().join("sess-p149");
        std::fs::create_dir_all(session.join("terminal")).unwrap();
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{PEM_BODY}\n{PEM_BODY}\n-----END PRIVATE KEY-----\n");
        let updates = format!(
            "{}\n",
            serde_json::json!({"tool": "run_terminal_command", "command": format!("echo {SENT}; echo {GHP}"),
                "output": format!("{SENT}\n{pem}")})
        );
        std::fs::write(session.join("updates.jsonl"), &updates).unwrap();
        let terminal = format!("$ echo $FUIGO_API_KEY\n{SENT}\n$ cat key.pem\n{pem}$ echo {GHP}\n{GHP}\n");
        std::fs::write(session.join("terminal").join("cmd-1.log"), &terminal).unwrap();
        let image: Vec<u8> = [&[0x89u8, b'P', b'N', b'G'][..], SENT.as_bytes()].concat();
        std::fs::write(session.join("shot.png"), &image).unwrap();
        let pdf = format!("%PDF-1.4\n1 0 obj << /Length 60 >> stream\n{SENT}\nendstream\nstartxref\n420\n%%EOF\n");
        std::fs::write(session.join("report.pdf"), &pdf).unwrap();
        // Astra r3 #3: a key file is text and must be scrubbed.
        std::fs::write(session.join("deploy.pem"), &pem).unwrap();

        let archive = build_session_tar(&session, "sess-p149", &AgentConfig::default()).unwrap();
        let files = unpacked(&archive);
        let mut seen = 0;
        for (name, data) in &files {
            let text = String::from_utf8_lossy(data);
            if name.ends_with("deploy.pem") {
                seen += 1;
                assert!(!text.contains(PEM_BODY), "{name} carries the private key: {text}");
            }
            if name.ends_with("updates.jsonl") || name.ends_with("cmd-1.log") {
                seen += 1;
                for secret in [SENT, GHP, PEM_BODY] {
                    assert!(!text.contains(secret), "{name} carries {secret}: {text}");
                }
                assert!(text.contains("<redacted>"), "control: {name}: {text}");
            }
            if name.ends_with("updates.jsonl") {
                serde_json::from_str::<serde_json::Value>(text.trim()).expect("still one JSON record");
            }
            if name.ends_with("shot.png") {
                seen += 1;
                assert_eq!(data, &image, "an image is packed as it is");
            }
            if name.ends_with("report.pdf") {
                seen += 1;
                assert_eq!(data, pdf.as_bytes(), "an ASCII PDF is packed as it is (offsets must stay valid)");
            }
        }
        assert_eq!(seen, 5, "control: the five files were packed: {:?}", files.iter().map(|f| &f.0).collect::<Vec<_>>());
        assert_eq!(std::fs::read_to_string(session.join("updates.jsonl")).unwrap(), updates, "local file changed");
        assert_eq!(std::fs::read_to_string(session.join("terminal").join("cmd-1.log")).unwrap(), terminal);
    }

    /// P149 (S12, Astra r1 #4): the upload-method summary `fuigo trace` prints (and writes into its failure log)
    /// names a proxy or S3 endpoint by location only.
    #[test]
    fn the_upload_method_summary_names_endpoints_by_location_only() {
        const PASS: &str = "fuigo-p149-SYNTH-proxypass";
        const QUERY: &str = "fuigo-p149-SYNTH-proxyquery";
        let url = format!("https://p149u:{PASS}@proxy.p149.invalid/v1?key={QUERY}");
        let proxy = UploadMethod::Proxy {
            proxy_base_url: url.clone(),
            user_token: String::new(),
            deployment_key: None,
            alpha_test_key: None,
        };
        let shown = UploadMethodDisplay { method: &proxy, bucket_url: "gs://p149" }.to_string();
        assert!(shown.contains("proxy.p149.invalid/v1"), "control: {shown}");
        for secret in [PASS, QUERY] {
            assert!(!shown.contains(secret), "{secret} shown: {shown}");
        }
    }
}
