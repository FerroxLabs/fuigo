//! Hub [`AuthProvider`] from `~/.fuigo/auth.json` for the standalone
//! `workspace_server` binary: an auto-refreshing OIDC provider that persists rotated tokens. P47: only a hub the
//! service-endpoint trust class admits (`wss`, not loopback) is given the session token.
//!
//! The in-leader `fuigo workspace` exposure does NOT use this path.
//! It gets an in-memory provider from the leader's `AuthManager` (see `LeaderAuthProvider`) so it never races the leader's own auth.json writer.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fuigo_computer_hub_sdk::{
    AuthCredential, AuthIdentity, AuthProvider, OidcAuthProviderBuilder, OnRefreshCallback,
    RefreshEvent,
};
use url::Url;

use crate::status_config::ProactiveRefreshConfig;

mod proactive;

pub use proactive::{ProactiveOidcAuthProvider, ProactiveOidcParams};

pub(crate) fn init_metrics() {
    proactive::init_metrics();
}

/// Owner identity parsed from an auth.json entry, which the [`AuthProvider`]s built here return from [`AuthProvider::identity`].
fn identity_from_entry(entry: &AuthEntry) -> AuthIdentity {
    AuthIdentity {
        user_id: entry.user_id.clone(),
        principal_type: entry.principal_type.clone(),
        principal_id: entry.principal_id.clone(),
    }
}

#[derive(serde::Deserialize)]
struct AuthEntry {
    key: String,
    #[serde(default)]
    user_id: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    oidc_issuer: Option<String>,
    #[serde(default)]
    oidc_client_id: Option<String>,
    #[serde(default)]
    principal_type: Option<String>,
    #[serde(default)]
    principal_id: Option<String>,
    #[serde(default)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Hand-written `Debug` (P70): credential values print as `<redacted>` (headers and query parameters by name only), so a `{:?}` of this type in a log, panic or error cannot disclose them.
/// The destructure is exhaustive, so a new field fails to compile here until its Debug output is decided.
impl std::fmt::Debug for AuthEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            key: _,
            user_id,
            refresh_token,
            oidc_issuer,
            oidc_client_id,
            principal_type,
            principal_id,
            expires_at,
        } = self;
        f.debug_struct("AuthEntry")
            .field("key", &"<redacted>")
            .field("user_id", user_id)
            .field("refresh_token", &refresh_token.as_ref().map(|_| "<redacted>"))
            .field("oidc_issuer", oidc_issuer)
            .field("oidc_client_id", oidc_client_id)
            .field("principal_type", principal_type)
            .field("principal_id", principal_id)
            .field("expires_at", expires_at)
            .finish()
    }
}

pub fn default_auth_path() -> anyhow::Result<PathBuf> {
    let fuigo = fuigo_config::user_fuigo_home()
        .ok_or_else(|| anyhow::anyhow!("no user fuigo home (set $FUIGO_HOME or $HOME)"))?;
    Ok(fuigo.join("auth.json"))
}

/// Read the active OIDC entry and its scope key.
/// The key is threaded to the refresh write so rotation updates exactly the entry that was read.
///
/// When several OIDC entries qualify, the latest `expires_at` wins: that is the entry the shell is actively refreshing.
/// Picking any other entry could rotate a different principal's refresh-token chain out from under the user's sessions.
fn read_auth_entry(path: &Path) -> anyhow::Result<(String, AuthEntry)> {
    if !path.exists() {
        anyhow::bail!(
            "No auth credentials found at {}. Run `fuigo login` first.",
            path.display()
        );
    }

    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;
    let entries: BTreeMap<String, AuthEntry> = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("failed to parse {}: {e}", path.display()))?;

    entries
        .into_iter()
        .filter(|(_, e)| e.refresh_token.is_some() && e.oidc_issuer.is_some())
        // Strictly-greater comparison: ties (including all-`None`) keep the first candidate in BTreeMap (alphabetical) order
        .fold(None::<(String, AuthEntry)>, |best, cand| match best {
            Some(b) if cand.1.expires_at <= b.1.expires_at => Some(b),
            _ => Some(cand),
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no OIDC auth entry found in {}. Run `fuigo login` first.",
                path.display()
            )
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OidcProviderKind {
    Sdk,
    Proactive,
}

/// Refreshed tokens that could not be written to `auth.json` (lock timeout or I/O error): the newest unsaved event, if any.
/// The same shape as the shell's unsaved subscription credential: the rotated tokens stay usable from memory, the failure is
/// reported loudly, and the write is retried until it lands or a newer refresh supersedes it.
type UnsavedSlot = Arc<parking_lot::Mutex<Option<RefreshEvent>>>;

/// Attempts after the first for an unsaved write, and the pause before each.
const UNSAVED_RETRIES: u32 = 6;
const UNSAVED_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(15);

/// Writes `auth.json` on the calling thread.
/// The proactive provider already offloads this onto its persist worker, whose seq check drops stale writes.
/// A nested spawn here would run `write_refreshed_token` after that check and let a stale write land over a newer one.
/// A failed write is not just logged: the event is kept as unsaved and retried on a detached thread (see [`persist_event`]).
pub(crate) fn persist_on_refresh(auth_path: PathBuf, scope_key: String) -> OnRefreshCallback {
    let unsaved: UnsavedSlot = Arc::new(parking_lot::Mutex::new(None));
    Arc::new(move |event: &RefreshEvent| {
        let _ = persist_event(
            &auth_path,
            &scope_key,
            event,
            &unsaved,
            AUTH_LOCK_TIMEOUT,
            UNSAVED_RETRY_DELAY,
            UNSAVED_RETRIES,
        );
    })
}

/// Writes `event`; on failure records it in `unsaved`, warns that disk trails the IdP by one rotation, and returns the
/// retry thread's handle. A newer event (a later refresh) replaces the unsaved one, and the retry then stands down.
fn persist_event(
    path: &Path,
    scope_key: &str,
    event: &RefreshEvent,
    unsaved: &UnsavedSlot,
    lock_timeout: std::time::Duration,
    retry_delay: std::time::Duration,
    retries: u32,
) -> Option<std::thread::JoinHandle<()>> {
    match write_refreshed_token_within(path, scope_key, event, lock_timeout) {
        Ok(()) => {
            *unsaved.lock() = None;
            None
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "refreshed token could not be saved to auth.json; using it from memory and retrying. \
                 A new session started before it is saved will present a spent refresh token; \
                 close other fuigo processes holding auth.json.lock, or run `fuigo login`"
            );
            *unsaved.lock() = Some(event.clone());
            let (path, scope_key, event, unsaved) =
                (path.to_owned(), scope_key.to_owned(), event.clone(), unsaved.clone());
            Some(std::thread::spawn(move || {
                for _ in 0..retries {
                    std::thread::sleep(retry_delay);
                    let still_ours = unsaved
                        .lock()
                        .as_ref()
                        .is_some_and(|u| u.access_token == event.access_token);
                    if !still_ours {
                        return;
                    }
                    if write_refreshed_token_within(&path, &scope_key, &event, lock_timeout).is_ok() {
                        let mut slot = unsaved.lock();
                        if slot.as_ref().is_some_and(|u| u.access_token == event.access_token) {
                            *slot = None;
                        }
                        tracing::info!(path = %path.display(), "refreshed token saved to auth.json after an earlier failure");
                        return;
                    }
                }
                tracing::warn!(
                    path = %path.display(),
                    "refreshed token is still not saved to auth.json; giving up retries (the next refresh will try again)"
                );
            }))
        }
    }
}

/// SDK `on_refresh` is invoked from the async refresh path, which has no PersistGate.
/// Offload the same write so a contended flock cannot stall the runtime.
fn persist_on_refresh_off_thread(auth_path: PathBuf, scope_key: String) -> OnRefreshCallback {
    let persist = persist_on_refresh(auth_path, scope_key);
    Arc::new(move |event: &RefreshEvent| {
        let persist = persist.clone();
        let event = event.clone();
        std::thread::spawn(move || persist(&event));
    })
}

fn build_oidc_provider(
    scope_key: String,
    entry: &AuthEntry,
    auth_path: PathBuf,
    refresh_cfg: &ProactiveRefreshConfig,
) -> anyhow::Result<(Arc<dyn AuthProvider>, OidcProviderKind)> {
    let refresh_token = entry.refresh_token.as_ref().ok_or_else(|| {
        anyhow::anyhow!("auth entry has no refresh_token — cannot refresh expired tokens")
    })?;
    let issuer = entry.oidc_issuer.as_ref().ok_or_else(|| {
        anyhow::anyhow!("auth entry has no oidc_issuer — cannot refresh expired tokens")
    })?;
    let client_id = entry.oidc_client_id.as_ref().ok_or_else(|| {
        anyhow::anyhow!("auth entry has no oidc_client_id — cannot refresh expired tokens")
    })?;

    if refresh_cfg.enabled {
        return Ok((
            Arc::new(ProactiveOidcAuthProvider::new(ProactiveOidcParams {
                access_token: entry.key.clone(),
                refresh_token: refresh_token.clone(),
                issuer: issuer.clone(),
                client_id: client_id.clone(),
                identity: identity_from_entry(entry),
                expires_at: entry.expires_at,
                refresh: refresh_cfg.clone(),
                on_refresh: Some(persist_on_refresh(auth_path, scope_key)),
            })),
            OidcProviderKind::Proactive,
        ));
    }

    let client = fuigo_extra_ca::build_reqwest_client(|builder| builder)?;
    let mut builder = OidcAuthProviderBuilder::new(&entry.key, refresh_token, issuer, client_id)
        .http_transport(client, |url| {
            fuigo_extra_ca::dispatch::check_url(url).map_err(|error| error.to_string())
        });

    // The workspace derives `WorkspaceIdentity` from `AuthProvider::identity()`, so pass the owner identity along (no separate auth.json read)
    builder = builder.user_id(&entry.user_id);
    if let Some(ref pt) = entry.principal_type {
        builder = builder.principal_type(pt);
    }
    if let Some(ref pid) = entry.principal_id {
        builder = builder.principal_id(pid);
    }
    if let Some(exp) = entry.expires_at {
        builder = builder.expires_at(exp);
    }
    builder = builder.on_refresh(persist_on_refresh_off_thread(auth_path, scope_key));

    Ok((Arc::new(builder.build()), OidcProviderKind::Sdk))
}

/// How long [`lock_auth_file`] polls for the shared `auth.json.lock` before the persist fails.
/// Equal to the shell's `AUTH_LOCK_TIMEOUT` (10 s), which bounds every `auth.json` writer there; keep the two in step.
/// A timeout is an error, not a silent skip: nothing is written, and the caller logs that disk trails the IdP by one rotation.
const AUTH_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// RAII flock on the sibling `auth.json.lock`, the same advisory lock every fuigo-shell `auth.json` writer takes.
/// Polls `try_lock` rather than a blocking `flock` to bound the wait.
/// Never breaks a held lock and never unlinks the lock file: a holder here would be the shell mid-refresh, exactly the writer we must not race.
/// The shell no longer recovers by unlinking, but older shells still in the fleet do, so the live-inode check below stays.
struct AuthFileLockGuard {
    _file: std::fs::File,
}

fn lock_auth_file(auth_json_path: &Path, timeout: std::time::Duration) -> Option<AuthFileLockGuard> {
    use fs2::FileExt;
    use std::io::Write;
    let lock_path = auth_json_path.with_file_name("auth.json.lock");
    let deadline = std::time::Instant::now() + timeout;
    loop {
        // Older shells recover a stale lock by unlinking and recreating the file, so only a flock on the live inode counts
        // The current shell's acquire path does the same inode check
        // A dead inode falls through to the same deadline and sleep as a busy lock; retrying immediately would spin while the check keeps failing
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            && file.try_lock_exclusive().is_ok()
            && lock_inode_is_live(&file, &lock_path)
        {
            // Write holder info (`PID:TS`) through the locked fd so a holder can be identified from the lock file (diagnostics only; the flock itself is released by the kernel when this process dies)
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let _ = file.set_len(0);
            let _ = write!(file, "{}:{ts}", std::process::id());
            let _ = file.sync_all();
            return Some(AuthFileLockGuard { _file: file });
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// `fstat(fd)` vs `stat(path)`: `false` when the locked file was concurrently unlinked and recreated (our flock would be on the dead inode).
#[cfg(unix)]
fn lock_inode_is_live(file: &std::fs::File, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (file.metadata(), std::fs::metadata(path)) {
        (Ok(fd), Ok(p)) => fd.ino() == p.ino() && fd.dev() == p.dev(),
        _ => false,
    }
}

#[cfg(not(unix))]
fn lock_inode_is_live(_file: &std::fs::File, _path: &Path) -> bool {
    true
}

pub(crate) fn write_refreshed_token(
    path: &Path,
    scope_key: &str,
    event: &RefreshEvent,
) -> anyhow::Result<()> {
    write_refreshed_token_within(path, scope_key, event, AUTH_LOCK_TIMEOUT)
}

/// [`write_refreshed_token`] with the lock wait as a parameter, so a test can exercise the timeout without waiting 10 s.
fn write_refreshed_token_within(
    path: &Path,
    scope_key: &str,
    event: &RefreshEvent,
    lock_timeout: std::time::Duration,
) -> anyhow::Result<()> {
    // Read-modify-write under the shared advisory lock
    // An unlocked write races the shell's own refresh writer: whichever writes second rolls back the other's freshly rotated refresh token on disk
    // That guarantees a future `invalid_grant` for every session sharing the file
    let Some(_lock) = lock_auth_file(path, lock_timeout) else {
        // The rotated token still serves this process from memory, but disk now trails the IdP by one rotation:
        // a fresh process that picks it up will present a spent token. Fail without writing, as the shell's writers do.
        anyhow::bail!(
            "auth.json.lock still held by another writer after {lock_timeout:?}; auth.json left unchanged"
        );
    };

    let content = std::fs::read_to_string(path)?;
    let mut raw: serde_json::Value = serde_json::from_str(&content)?;

    let Some(obj) = raw.get_mut(scope_key).and_then(|e| e.as_object_mut()) else {
        anyhow::bail!("auth entry '{scope_key}' not found while persisting refreshed token");
    };

    // Never roll disk back to an older token
    // Each refresh persists on its own thread and a sibling shell writes the same file, so writes can arrive out of order
    // The loser would replace a live refresh token with a spent one and guarantee a future `invalid_grant`
    if let Some(new_expiry) = event.expires_at
        && let Some(disk_expiry) = obj
            .get("expires_at")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        && disk_expiry.with_timezone(&chrono::Utc) >= new_expiry
    {
        tracing::debug!("auth.json already holds a same-or-newer token; skipping persist");
        return Ok(());
    }

    obj.insert(
        "key".to_owned(),
        serde_json::Value::String(event.access_token.clone()),
    );
    if let Some(ref rt) = event.new_refresh_token {
        obj.insert(
            "refresh_token".to_owned(),
            serde_json::Value::String(rt.clone()),
        );
    }
    if let Some(exp) = event.expires_at {
        obj.insert(
            "expires_at".to_owned(),
            serde_json::Value::String(exp.to_rfc3339()),
        );
    }

    write_json_atomic(path, &raw)?;
    tracing::info!(path = %path.display(), "persisted refreshed token to auth.json");
    Ok(())
}

/// Atomically replace `path`: temp file (0600 on Unix), fsync, then rename.
/// Avoids the window where a truncate-in-place rewrite would leave auth.json partially written.
fn write_json_atomic(path: &Path, value: &serde_json::Value) -> anyhow::Result<()> {
    use std::io::Write;

    let json = serde_json::to_string_pretty(value)?;
    let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut file = opts
        .open(&tmp)
        .map_err(|e| anyhow::anyhow!("failed to open {}: {e}", tmp.display()))?;
    file.write_all(json.as_bytes())?;
    file.sync_all()?;
    drop(file);

    #[cfg(windows)]
    let _ = std::fs::remove_file(path);

    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow::anyhow!("failed to replace {}: {e}", path.display()));
    }
    Ok(())
}

/// Build a hub auth provider for `hub_url`. `auth_config` overrides
/// the default credential path (`~/.fuigo/auth.json`).
///
/// `refresh_cfg.enabled` selects the workspace-owned proactive refresher (the default).
/// The SDK `OidcAuthProvider` is the explicit kill-switch path (`FUIGO_WORKSPACE_OIDC_PROACTIVE_REFRESH_ENABLED=false`).
/// P47: a `ws://`, loopback or otherwise refused hub URL is an error naming the remedy; no credential is read.
pub fn provider(
    hub_url: &Url,
    auth_config: Option<&Path>,
    refresh_cfg: &ProactiveRefreshConfig,
) -> anyhow::Result<Arc<dyn AuthProvider>> {
    let auth_path = match auth_config {
        Some(p) => p.to_path_buf(),
        None => default_auth_path()?,
    };
    // P47: the hub receives the session token from auth.json on every connect, so `hub_url` must be admitted by the
    // service-endpoint trust class (`wss`, not loopback; the operator's hub URL is the configured service base).
    // The old local-dev path that handed a plain bearer to a `ws://` loopback hub is gone: a co-located process
    // could read it. Checked before auth.json is read, so a refused hub never touches the credential.
    fuigo_extra_ca::service_trust::session_may_reach_service(
        hub_url.as_str(),
        Some(hub_url.as_str()),
        |_| false,
    )
    .map_err(|refused| anyhow::anyhow!("{refused}"))?;
    let (scope_key, entry) = read_auth_entry(&auth_path)?;
    build_oidc_provider(scope_key, &entry, auth_path, refresh_cfg).map(|(provider, _)| provider)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_auth_json(dir: &std::path::Path, json: &str) -> PathBuf {
        let path = dir.join("auth.json");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
        path
    }

    #[test]
    fn read_auth_entry_picks_oidc_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_auth_json(
            dir.path(),
            r#"{
            "legacy": { "key": "fuigo-plainkey", "user_id": "u1" },
            "oidc": {
                "key": "eyJhbGciOiJFUzI1NiJ9.test",
                "user_id": "u2",
                "refresh_token": "rt",
                "oidc_issuer": "https://auth.example.com",
                "oidc_client_id": "client1"
            }
        }"#,
        );

        let (key, entry) = read_auth_entry(&path).unwrap();
        assert_eq!(key, "oidc");
        assert_eq!(entry.refresh_token.as_deref(), Some("rt"));
        assert_eq!(
            entry.oidc_issuer.as_deref(),
            Some("https://auth.example.com")
        );
    }

    #[test]
    fn read_auth_entry_rejects_non_oidc() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_auth_json(
            dir.path(),
            r#"{
            "api_key": { "key": "fuigo-plainkey", "user_id": "u1" }
        }"#,
        );

        let err = read_auth_entry(&path).unwrap_err();
        assert!(err.to_string().contains("no OIDC auth entry"));
    }

    #[test]
    fn read_auth_entry_missing_file() {
        let path = PathBuf::from("/nonexistent/auth.json");
        let err = read_auth_entry(&path).unwrap_err();
        assert!(err.to_string().contains("No auth credentials"));
    }

    #[test]
    fn read_auth_entry_tolerates_extra_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_auth_json(
            dir.path(),
            r#"{
            "scope": {
                "key": "eyJhbGciOiJFUzI1NiJ9.tok",
                "user_id": "u1",
                "auth_mode": "oidc",
                "create_time": "2026-01-01T00:00:00Z",
                "email": "test@example.com",
                "first_name": "Test",
                "refresh_token": "rt1",
                "oidc_issuer": "https://auth.x.ai",
                "oidc_client_id": "c1",
                "some_future_field": true
            }
        }"#,
        );

        let (_key, entry) = read_auth_entry(&path).unwrap();
        assert_eq!(entry.refresh_token.as_deref(), Some("rt1"));
    }

    #[test]
    fn build_oidc_provider_requires_refresh_token() {
        let entry = AuthEntry {
            key: "eyJ.tok".into(),
            user_id: "u1".into(),
            refresh_token: None,
            oidc_issuer: Some("https://auth.x.ai".into()),
            oidc_client_id: Some("c1".into()),
            principal_type: None,
            principal_id: None,
            expires_at: None,
        };
        let err = build_oidc_provider(
            "oidc".into(),
            &entry,
            PathBuf::from("/tmp/x"),
            &ProactiveRefreshConfig::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("refresh_token"));
    }

    #[test]
    fn build_oidc_provider_requires_issuer() {
        let entry = AuthEntry {
            key: "eyJ.tok".into(),
            user_id: "u1".into(),
            refresh_token: Some("rt".into()),
            oidc_issuer: None,
            oidc_client_id: Some("c1".into()),
            principal_type: None,
            principal_id: None,
            expires_at: None,
        };
        let err = build_oidc_provider(
            "oidc".into(),
            &entry,
            PathBuf::from("/tmp/x"),
            &ProactiveRefreshConfig::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("oidc_issuer"));
    }

    #[test]
    fn build_oidc_provider_requires_client_id() {
        let entry = AuthEntry {
            key: "eyJ.tok".into(),
            user_id: "u1".into(),
            refresh_token: Some("rt".into()),
            oidc_issuer: Some("https://auth.x.ai".into()),
            oidc_client_id: None,
            principal_type: None,
            principal_id: None,
            expires_at: None,
        };
        let err = build_oidc_provider(
            "oidc".into(),
            &entry,
            PathBuf::from("/tmp/x"),
            &ProactiveRefreshConfig::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("oidc_client_id"));
    }

    #[test]
    fn build_oidc_provider_succeeds_with_all_fields() {
        let entry = AuthEntry {
            key: "eyJ.tok".into(),
            user_id: "u1".into(),
            refresh_token: Some("rt".into()),
            oidc_issuer: Some("https://auth.x.ai".into()),
            oidc_client_id: Some("c1".into()),
            principal_type: Some("Team".into()),
            principal_id: Some("t1".into()),
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        };
        let (provider, kind) = build_oidc_provider(
            "oidc".into(),
            &entry,
            PathBuf::from("/tmp/x"),
            &ProactiveRefreshConfig {
                enabled: false,
                ..ProactiveRefreshConfig::default()
            },
        )
        .unwrap();
        assert_eq!(kind, OidcProviderKind::Sdk);
        let cred = provider.current();
        match cred {
            fuigo_computer_hub_sdk::AuthCredential::Bearer { token } => {
                assert_eq!(token, "eyJ.tok");
            }
            _ => panic!("expected Bearer"),
        }
        // Identity comes from the parsed entry (no second auth.json read)
        let id = provider.identity().expect("identity present");
        assert_eq!(id.user_id, "u1");
        assert_eq!(id.principal_type.as_deref(), Some("Team"));
        assert_eq!(id.principal_id.as_deref(), Some("t1"));
    }

    #[test]
    fn write_refreshed_token_updates_jwt_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_auth_json(
            dir.path(),
            r#"{
            "legacy": { "key": "fuigo-old", "user_id": "u1" },
            "oidc": { "key": "eyJ.old", "user_id": "u2", "refresh_token": "rt-old", "oidc_issuer": "https://auth.x.ai" }
        }"#,
        );

        let event = RefreshEvent {
            access_token: "eyJ.new".into(),
            new_refresh_token: Some("rt-new".into()),
            expires_at: None,
        };
        write_refreshed_token(&path, "oidc", &event).unwrap();

        let updated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(updated["oidc"]["key"], "eyJ.new");
        assert_eq!(updated["oidc"]["refresh_token"], "rt-new");
        assert_eq!(updated["legacy"]["key"], "fuigo-old");
    }

    /// With several OIDC entries (personal and enterprise login), the latest `expires_at` wins; the user's fuigo sessions refresh that entry.
    /// Alphabetical selection could adopt a different principal's refresh token and rotate it out from under the shell.
    #[test]
    fn read_auth_entry_prefers_latest_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_auth_json(
            dir.path(),
            r#"{
            "aaa-stale": { "key": "eyJ.a", "refresh_token": "rt-a", "oidc_issuer": "https://auth.x.ai", "expires_at": "2026-01-01T00:00:00Z" },
            "zzz-active": { "key": "eyJ.z", "refresh_token": "rt-z", "oidc_issuer": "https://auth.x.ai", "expires_at": "2026-06-01T00:00:00Z" }
        }"#,
        );

        let (key, entry) = read_auth_entry(&path).unwrap();
        assert_eq!(key, "zzz-active", "latest expires_at must win");
        assert_eq!(entry.refresh_token.as_deref(), Some("rt-z"));

        // An entry with no expires_at never beats one with a timestamp.
        let path = write_auth_json(
            dir.path(),
            r#"{
            "aaa-with-expiry": { "key": "eyJ.a", "refresh_token": "rt-a", "oidc_issuer": "https://auth.x.ai", "expires_at": "2026-01-01T00:00:00Z" },
            "zzz-no-expiry": { "key": "eyJ.z", "refresh_token": "rt-z", "oidc_issuer": "https://auth.x.ai" }
        }"#,
        );
        let (key, _) = read_auth_entry(&path).unwrap();
        assert_eq!(key, "aaa-with-expiry");
    }

    #[test]
    fn write_refreshed_token_targets_exact_scope_key() {
        // Non-sorted order: refresh must update the read-selected key ("aaa"), not the first in file order ("zzz")
        let dir = tempfile::tempdir().unwrap();
        let path = write_auth_json(
            dir.path(),
            r#"{
            "zzz": { "key": "eyJ.z", "refresh_token": "rt-z", "oidc_issuer": "https://auth.x.ai" },
            "aaa": { "key": "eyJ.a", "refresh_token": "rt-a", "oidc_issuer": "https://auth.x.ai" }
        }"#,
        );

        let (key, _entry) = read_auth_entry(&path).unwrap();
        assert_eq!(key, "aaa");

        let event = RefreshEvent {
            access_token: "eyJ.a-new".into(),
            new_refresh_token: Some("rt-a-new".into()),
            expires_at: None,
        };
        write_refreshed_token(&path, &key, &event).unwrap();

        let updated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(updated["aaa"]["key"], "eyJ.a-new");
        assert_eq!(updated["aaa"]["refresh_token"], "rt-a-new");
        assert_eq!(updated["zzz"]["key"], "eyJ.z");
        assert_eq!(updated["zzz"]["refresh_token"], "rt-z");
    }

    /// Persists run on detached threads and race a sibling shell writing the same file.
    /// A late write must not replace a live refresh token with the one it already rotated away.
    #[test]
    fn write_refreshed_token_does_not_roll_back_a_newer_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_auth_json(
            dir.path(),
            r#"{
            "oidc": { "key": "eyJ.newer", "refresh_token": "rt-newer", "oidc_issuer": "https://auth.x.ai", "expires_at": "2026-06-01T00:00:00Z" }
        }"#,
        );

        let stale = RefreshEvent {
            access_token: "eyJ.older".into(),
            new_refresh_token: Some("rt-older".into()),
            expires_at: Some("2026-05-01T00:00:00Z".parse().unwrap()),
        };
        write_refreshed_token(&path, "oidc", &stale).unwrap();

        let updated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(updated["oidc"]["refresh_token"], "rt-newer");
        assert_eq!(updated["oidc"]["key"], "eyJ.newer");
    }

    #[test]
    fn write_refreshed_token_preserves_existing_rt_when_not_rotated() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_auth_json(
            dir.path(),
            r#"{
            "oidc": { "key": "eyJ.old", "user_id": "u1", "refresh_token": "rt-keep", "oidc_issuer": "https://auth.x.ai" }
        }"#,
        );

        let event = RefreshEvent {
            access_token: "eyJ.new".into(),
            new_refresh_token: None,
            expires_at: None,
        };
        write_refreshed_token(&path, "oidc", &event).unwrap();

        let updated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(updated["oidc"]["key"], "eyJ.new");
        assert_eq!(updated["oidc"]["refresh_token"], "rt-keep");
    }

    const LOCKED_FIXTURE: &str = r#"{
            "oidc": { "key": "eyJ.old", "user_id": "u1", "refresh_token": "rt-old", "oidc_issuer": "https://auth.x.ai" }
        }"#;

    fn locked_event() -> RefreshEvent {
        RefreshEvent {
            access_token: "eyJ.new".into(),
            new_refresh_token: Some("rt-new".into()),
            expires_at: None,
        }
    }

    /// Takes the shared `auth.json.lock` the way the shell does, from a separate open file description.
    fn hold_shared_lock(auth_path: &Path) -> std::fs::File {
        use fs2::FileExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(auth_path.with_file_name("auth.json.lock"))
            .unwrap();
        file.lock_exclusive().unwrap();
        file
    }

    #[test]
    fn auth_lock_timeout_matches_the_shell_bound() {
        assert_eq!(AUTH_LOCK_TIMEOUT, std::time::Duration::from_secs(10));
    }

    #[test]
    fn write_refreshed_token_waits_for_a_held_lock_then_fails_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_auth_json(dir.path(), LOCKED_FIXTURE);
        let before = std::fs::read(&path).unwrap();
        let _held = hold_shared_lock(&path);

        let wait = std::time::Duration::from_millis(400);
        let started = std::time::Instant::now();
        let result = write_refreshed_token_within(&path, "oidc", &locked_event(), wait);
        let waited = started.elapsed();

        let err = result.expect_err("a held lock must fail the write");
        assert!(err.to_string().contains("auth.json.lock"), "{err}");
        assert!(waited >= wait, "returned after {waited:?}, before the {wait:?} bound");
        assert_eq!(std::fs::read(&path).unwrap(), before, "auth.json must be untouched");
    }

    #[test]
    fn write_refreshed_token_waits_out_a_lock_released_within_the_bound() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_auth_json(dir.path(), LOCKED_FIXTURE);
        let held = hold_shared_lock(&path);
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            drop(held);
        });

        let started = std::time::Instant::now();
        write_refreshed_token_within(&path, "oidc", &locked_event(), std::time::Duration::from_secs(5))
            .unwrap();
        assert!(started.elapsed() >= std::time::Duration::from_millis(250), "must have waited for the holder");
        releaser.join().unwrap();

        let updated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(updated["oidc"]["key"], "eyJ.new");
    }

    #[test]
    fn a_failed_persist_is_kept_unsaved_and_retried_until_it_lands() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_auth_json(dir.path(), LOCKED_FIXTURE);
        let held = hold_shared_lock(&path);
        let unsaved: UnsavedSlot = Arc::new(parking_lot::Mutex::new(None));
        let short = std::time::Duration::from_millis(100);

        let retry = persist_event(&path, "oidc", &locked_event(), &unsaved, short, short, 50)
            .expect("a failed write must start a retry");
        assert_eq!(
            unsaved.lock().as_ref().map(|e| e.access_token.as_str()),
            Some("eyJ.new"),
            "the unsaved event must be kept"
        );
        let on_disk: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(on_disk["oidc"]["key"], "eyJ.old", "nothing written while the lock is held");

        drop(held);
        retry.join().unwrap();
        assert!(unsaved.lock().is_none(), "a landed retry clears the unsaved slot");
        let on_disk: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(on_disk["oidc"]["key"], "eyJ.new");
        assert_eq!(on_disk["oidc"]["refresh_token"], "rt-new");
    }

    #[test]
    fn an_unsaved_event_stands_down_when_a_newer_one_replaces_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_auth_json(dir.path(), LOCKED_FIXTURE);
        let _held = hold_shared_lock(&path);
        let unsaved: UnsavedSlot = Arc::new(parking_lot::Mutex::new(None));
        let short = std::time::Duration::from_millis(50);

        let retry = persist_event(&path, "oidc", &locked_event(), &unsaved, short, short, 3).unwrap();
        *unsaved.lock() = Some(RefreshEvent {
            access_token: "eyJ.newer".into(),
            new_refresh_token: Some("rt-newer".into()),
            expires_at: None,
        });
        retry.join().unwrap();
        assert_eq!(
            unsaved.lock().as_ref().map(|e| e.access_token.as_str()),
            Some("eyJ.newer"),
            "the stale retry must not clear or overwrite the newer unsaved event"
        );
    }

    /// P47: a cleartext or loopback hub is refused before auth.json is read (the old local-dev path handed it the
    /// plain session bearer); the error names the refused origin and the remedy. Positive control: a `wss` hub on a
    /// public host builds the OIDC provider from the same auth.json.
    #[test]
    fn p47_provider_refuses_a_cleartext_or_loopback_hub() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_auth_json(
            dir.path(),
            r#"{ "oidc": { "key": "eyJ.tok", "user_id": "u1", "refresh_token": "rt", "oidc_issuer": "https://auth.x.ai", "oidc_client_id": "c1" } }"#,
        );
        for hub in [
            "ws://localhost:9988/v1/tools",
            // P55 fixed the IPv6 arm of the old local-dev path; P47 removes that path, so `::1` is refused like the rest.
            "ws://[::1]:9988/v1/tools",
            "wss://[::1]:9988/v1/tools",
            "wss://localhost:9988/v1/tools",
            "wss://127.0.0.1:9988/v1/tools",
            "ws://hub.example.test/v1/tools",
        ] {
            let url = Url::parse(hub).unwrap();
            let err = provider(&url, Some(&path), &ProactiveRefreshConfig::default())
                .err()
                .unwrap_or_else(|| panic!("{hub} must be refused"));
            let text = err.to_string();
            assert!(text.contains("The request was not made"), "{hub}: {text}");
            assert!(!text.contains("eyJ.tok"), "{text}");
        }
        // A missing auth.json is not even read for a refused hub: the refusal wins.
        let missing = dir.path().join("absent.json");
        let err = provider(
            &Url::parse("ws://localhost:1/x").unwrap(),
            Some(&missing),
            &ProactiveRefreshConfig::default(),
        )
        .err()
        .unwrap();
        assert!(err.to_string().contains("The request was not made"), "{err}");
        let ok = provider(
            &Url::parse("wss://hub.example.test/v1/tools").unwrap(),
            Some(&path),
            &ProactiveRefreshConfig {
                enabled: false,
                ..ProactiveRefreshConfig::default()
            },
        )
        .expect("a wss hub on a public host gets the OIDC provider");
        assert!(matches!(ok.current(), AuthCredential::Bearer { .. }));
    }

    fn complete_oidc_entry() -> AuthEntry {
        AuthEntry {
            key: "eyJ.tok".into(),
            user_id: "u1".into(),
            refresh_token: Some("rt".into()),
            oidc_issuer: Some("https://auth.x.ai".into()),
            oidc_client_id: Some("c1".into()),
            principal_type: Some("Team".into()),
            principal_id: Some("t1".into()),
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        }
    }

    #[test]
    fn build_oidc_provider_flag_off_uses_sdk_provider() {
        let (provider, kind) = build_oidc_provider(
            "oidc".into(),
            &complete_oidc_entry(),
            PathBuf::from("/tmp/x"),
            &ProactiveRefreshConfig {
                enabled: false,
                ..ProactiveRefreshConfig::default()
            },
        )
        .unwrap();
        assert_eq!(kind, OidcProviderKind::Sdk);
        match provider.current() {
            AuthCredential::Bearer { token } => assert_eq!(token, "eyJ.tok"),
            _ => panic!("expected Bearer"),
        }
    }

    #[test]
    fn sdk_factory_egress_policy_blocks_legacy_refresh() {
        const CHILD: &str = "FUIGO_SDK_FACTORY_POLICY_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let mut entry = complete_oidc_entry();
            entry.expires_at = Some(chrono::Utc::now() - chrono::Duration::minutes(1));
            let path = PathBuf::from(std::env::var_os("HOME").unwrap()).join("unused-auth.json");
            let (provider, kind) = build_oidc_provider(
                "oidc".into(),
                &entry,
                path.clone(),
                &ProactiveRefreshConfig {
                    enabled: false,
                    ..ProactiveRefreshConfig::default()
                },
            )
            .unwrap();
            assert_eq!(kind, OidcProviderKind::Sdk);
            let started = std::time::Instant::now();
            let _ = provider.current();
            assert!(
                started.elapsed() < std::time::Duration::from_secs(3),
                "policy denial must precede network timeout"
            );
            assert!(
                !path.exists(),
                "denied refresh must not persist credentials"
            );
            println!("sdk-factory-policy-child-entered");
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let proxy = format!("http://{}", listener.local_addr().unwrap());
        let home = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "hub_auth::tests::sdk_factory_egress_policy_blocks_legacy_refresh",
                "--nocapture",
            ])
            .env_clear()
            .env("HOME", home.path())
            .env(CHILD, "1")
            .env("HTTP_PROXY", &proxy)
            .env("HTTPS_PROXY", &proxy)
            .env("ALL_PROXY", &proxy)
            .env("NO_PROXY", "")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("sdk-factory-policy-child-entered")
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn build_oidc_provider_flag_on_uses_proactive_provider() {
        let refresh = ProactiveRefreshConfig {
            enabled: true,
            ..ProactiveRefreshConfig::default()
        };
        let (provider, kind) = build_oidc_provider(
            "oidc".into(),
            &complete_oidc_entry(),
            PathBuf::from("/tmp/x"),
            &refresh,
        )
        .unwrap();
        assert_eq!(kind, OidcProviderKind::Proactive);
        match provider.current() {
            AuthCredential::Bearer { token } => assert_eq!(token, "eyJ.tok"),
            _ => panic!("expected Bearer"),
        }
    }

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
    fn auth_entry_debug_redacts_key_and_refresh_token() {
        let entry: AuthEntry = serde_json::from_value(serde_json::json!({
            "key": "p70hk-FAKE-4f5a6b7c",
            "user_id": "p70-user",
            "refresh_token": "p70rt-FAKE-8d9e0f1a",
        }))
        .expect("auth entry");
        assert_redacted(&entry, &["p70hk-FAKE-4f5a6b7c", "p70rt-FAKE-8d9e0f1a"]);
    }
}
