//! Persistent credential storage for MCP server OAuth tokens.
//!
//! Credentials are stored in `$FUIGO_HOME/mcp_credentials.json`, keyed by a composite key derived from the server name and URL.
//! This keeps MCP OAuth tokens isolated from the user's Ferrox Labs auth (`auth.json`).
//!
//! Stores rmcp's `StoredCredentials` type directly, the same type that rmcp's `AuthorizationManager` uses internally.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::rmcp;

/// Ensure credential paths are owner-only (Unix `0o600`).
///
/// Local helper, not shell-base's: `fuigo-mcp` sits below `config-types` in the dep graph.
/// Shell-base pulls shared, then config-types, then mcp, so this crate linking shell-base would be a cycle.
/// Windows ACL tightening stays on auth via shell-base; MCP is Unix-first here.
fn ensure_owner_only_permissions(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(metadata) => {
                let mode = metadata.permissions().mode();
                if mode & 0o777 != 0o600 {
                    let mut perms = metadata.permissions();
                    perms.set_mode(0o600);
                    std::fs::set_permissions(path, perms)?;
                }
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

type Result<T> = std::result::Result<T, McpCredentialError>;

#[derive(Debug, thiserror::Error)]
pub enum McpCredentialError {
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

impl McpCredentialError {
    /// A description that never holds file content: the JSON and OS texts can quote a value from the store.
    pub fn safe_summary(&self) -> &'static str {
        match self {
            Self::Json(_) => "the credentials file is damaged (it is not valid credential JSON)",
            Self::Io(_) => "the credentials file could not be read or written",
            Self::Other(_) => "the credentials store could not be updated",
        }
    }
}

/// File name for the credential store inside `$FUIGO_HOME`.
const CREDENTIALS_FILENAME: &str = "mcp_credentials.json";

/// On-disk credential store: `$FUIGO_HOME/mcp_credentials.json`.
///
/// Stores rmcp `StoredCredentials` per MCP server, keyed by `"{server_name}:{server_url}"`.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct McpCredentialStore {
    #[serde(flatten)]
    entries: BTreeMap<String, rmcp::transport::auth::StoredCredentials>,
}

impl std::fmt::Debug for McpCredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpCredentialStore")
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

impl McpCredentialStore {
    /// Build the composite key for a credential entry.
    pub fn key(server_name: &str, server_url: &Url) -> String {
        format!("{}:{}", server_name, server_url)
    }

    /// Load the credential store from the default path (`$FUIGO_HOME/mcp_credentials.json`).
    ///
    /// Returns an empty store if the file does not exist.
    pub fn load_default() -> Result<Self> {
        match Self::default_path() {
            Some(path) => Self::load_from(&path),
            None => Ok(Self::default()),
        }
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        // Only a MISSING file is an empty store; a permission error or link loop is reported as itself.
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => {
                return Err(McpCredentialError::Other(format!(
                    "cannot read the MCP credential store {}: {e}",
                    path.display()
                )));
            }
        };
        // Tighten world-readable credential files on load (hand copies, etc.).
        // Best-effort: chmod failure must not block using existing tokens.
        if let Err(e) = ensure_owner_only_permissions(path) {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "mcp credentials: failed to enforce owner-only permissions"
            );
        }
        let store: McpCredentialStore = serde_json::from_str(&content)?;
        Ok(store)
    }

    fn locked_mutate_and_save(&mut self, mutate: &dyn Fn(&mut Self)) -> Result<()> {
        let path = Self::default_path().ok_or_else(|| {
            McpCredentialError::Other("no user fuigo home (set $FUIGO_HOME or $HOME)".into())
        })?;
        self.locked_mutate_and_save_at(&path, mutate)
    }

    /// One read-modify-write of `path` under the store lock, on every platform.
    ///
    /// Only a MISSING file is an empty store. Any other read error fails the write with the file untouched.
    /// An unparsable file is copied aside (see [`copy_corrupt_aside`]) and then treated as empty,
    /// so a damaged store never silently overwrites tokens and never blocks sign-in.
    /// If the lock cannot be taken the write fails; there is no unlocked fallback.
    fn locked_mutate_and_save_at(
        &mut self,
        path: &Path,
        mutate: &dyn Fn(&mut Self),
    ) -> Result<()> {
        use fuigo_config::fs_atomic::{Edit, EditError, edit_under_lock, stage_atomically};

        // The edit closure runs exactly once, under the lock (`edit_under_lock`): the aside copy it makes is a side
        // effect that is only valid there. Do not move this to an optimistic `edit_locked`, which may rerun it.
        let fresh = edit_under_lock(
            path,
            &path.with_extension("lock"),
            |contents| stage_atomically(path, contents, Some(0o600)),
            |current| {
                let mut fresh = match current {
                    Ok(None) => Self::default(),
                    Ok(Some(bytes)) => match serde_json::from_slice::<Self>(bytes) {
                        Ok(store) => store,
                        Err(e) => {
                            copy_corrupt_aside(path, bytes, &e.to_string())?;
                            Self::default()
                        }
                    },
                    Err(e) => {
                        return Err(McpCredentialError::Io(std::io::Error::new(
                            e.kind(),
                            format!("cannot read {}: {e}", path.display()),
                        )));
                    }
                };
                mutate(&mut fresh);
                let contents = serde_json::to_vec_pretty(&fresh)?;
                Ok(Edit::Replace {
                    contents,
                    value: fresh,
                })
            },
        )
        .map_err(|e| match e {
            EditError::Lock(e) => McpCredentialError::Io(std::io::Error::new(
                e.kind(),
                format!("could not lock {}: {e}", path.display()),
            )),
            EditError::Write(e) => McpCredentialError::Io(e),
            EditError::Edit(e) => e,
        })?;
        *self = fresh;
        Ok(())
    }

    /// Locked insert ([`Self::locked_mutate_and_save`]) with a freshness guard.
    /// The write is skipped when the disk entry is strictly newer by `token_received_at` (see [`disk_entry_is_newer`]).
    /// Otherwise a slow writer rolls the stored refresh token back to a rotated-out value (`invalid_grant` on its next use).
    /// The canonical slow writer is a refresh suspended across system sleep that completes after wake.
    pub fn insert_and_save(
        &mut self,
        server_name: &str,
        server_url: &url::Url,
        creds: rmcp::transport::auth::StoredCredentials,
    ) -> Result<()> {
        let key = Self::key(server_name, server_url);
        self.locked_mutate_and_save(&move |store: &mut Self| {
            if disk_entry_is_newer(store.entries.get(&key), &creds) {
                tracing::info!(
                    key = key.as_str(),
                    "mcp credentials: skipping stale save (disk entry is newer)"
                );
                return;
            }
            store.entries.insert(key.clone(), creds.clone());
        })
    }

    /// Whole-file write of this in-memory snapshot, unlocked: tests only. Production writes go through the locked
    /// `insert_and_save` / `remove_and_save` / `remove_by_server_name_and_save`, which reload under the lock.
    #[cfg(test)]
    pub fn save_to(&self, path: &Path) -> Result<()> {
        write_owner_only_atomic(path, &serde_json::to_string_pretty(self)?)
    }

    pub fn get(
        &self,
        server_name: &str,
        server_url: &Url,
    ) -> Option<&rmcp::transport::auth::StoredCredentials> {
        self.entries.get(&Self::key(server_name, server_url))
    }

    pub fn insert_rmcp(
        &mut self,
        server_name: &str,
        server_url: &Url,
        creds: rmcp::transport::auth::StoredCredentials,
    ) {
        self.entries
            .insert(Self::key(server_name, server_url), creds);
    }

    /// Check if credentials exist for a server (regardless of expiry).
    pub fn has_credentials(&self, server_name: &str, server_url: &Url) -> bool {
        self.entries
            .contains_key(&Self::key(server_name, server_url))
    }

    pub fn remove(&mut self, server_name: &str, server_url: &Url) {
        self.entries.remove(&Self::key(server_name, server_url));
    }

    /// Remove a server's credentials and persist, under the cross-process file lock (reload and merge, remove, then atomic save).
    /// The locked counterpart of [`Self::remove`] for callers that persist the removal.
    /// An unlocked whole-file rewrite can drop other processes' concurrent writes for unrelated servers.
    pub fn remove_and_save(&mut self, server_name: &str, server_url: &Url) -> Result<()> {
        let key = Self::key(server_name, server_url);
        self.locked_mutate_and_save(&move |store: &mut Self| {
            store.entries.remove(&key);
        })
    }

    /// Remove all credentials for a server by name (any URL).
    pub fn remove_by_server_name(&mut self, server_name: &str) -> usize {
        let prefix = format!("{server_name}:");
        let before = self.entries.len();
        self.entries.retain(|k, _| !k.starts_with(&prefix));
        before - self.entries.len()
    }

    /// Remove all credentials for a server by name (any URL) and persist, under the cross-process file lock.
    /// The store is reloaded under the lock, so entries other processes saved since this snapshot was loaded survive.
    /// Nothing is written when the reloaded store has no entry for the server. Returns the number of entries removed.
    /// Blocks while the lock is held elsewhere: call it from `spawn_blocking` in async code.
    pub fn remove_by_server_name_and_save(&mut self, server_name: &str) -> Result<usize> {
        let path = Self::default_path().ok_or_else(|| {
            McpCredentialError::Other("no user fuigo home (set $FUIGO_HOME or $HOME)".into())
        })?;
        self.remove_by_server_name_and_save_at(&path, server_name)
    }

    fn remove_by_server_name_and_save_at(
        &mut self,
        path: &Path,
        server_name: &str,
    ) -> Result<usize> {
        use fuigo_config::fs_atomic::{Edit, EditError, edit_under_lock, stage_atomically};

        let (fresh, removed) = edit_under_lock(
            path,
            &path.with_extension("lock"),
            |contents| stage_atomically(path, contents, Some(0o600)),
            |current| {
                // Runs exactly once, under the lock (see `locked_mutate_and_save_at`).
                let mut fresh = match current {
                    Ok(None) => return Ok(Edit::Keep((Self::default(), 0))),
                    Ok(Some(bytes)) => match serde_json::from_slice::<Self>(bytes) {
                        Ok(store) => store,
                        Err(e) => {
                            // Not ours to repair here: leave the damaged file for the next write to set aside.
                            return Err(McpCredentialError::Json(e));
                        }
                    },
                    Err(e) => {
                        return Err(McpCredentialError::Io(std::io::Error::new(
                            e.kind(),
                            format!("cannot read {}: {e}", path.display()),
                        )));
                    }
                };
                let removed = fresh.remove_by_server_name(server_name);
                if removed == 0 {
                    return Ok(Edit::Keep((fresh, 0)));
                }
                let contents = serde_json::to_vec_pretty(&fresh)?;
                Ok(Edit::Replace {
                    contents,
                    value: (fresh, removed),
                })
            },
        )
        .map_err(|e| match e {
            EditError::Lock(e) => McpCredentialError::Io(std::io::Error::new(
                e.kind(),
                format!("could not lock {}: {e}", path.display()),
            )),
            EditError::Write(e) => McpCredentialError::Io(e),
            EditError::Edit(e) => e,
        })?;
        *self = fresh;
        Ok(removed)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Default path: `$FUIGO_HOME/mcp_credentials.json`.
    fn default_path() -> Option<PathBuf> {
        Some(fuigo_config::user_fuigo_home()?.join(CREDENTIALS_FILENAME))
    }
}

/// `true` when the on-disk `existing` entry is strictly newer than the `incoming` credentials by `token_received_at`.
/// This is the [`Self::insert_and_save`] freshness guard.
/// Missing timestamps on either side compare as "not newer" (the write proceeds), preserving pre-guard behavior for expiry-less tokens.
fn disk_entry_is_newer(
    existing: Option<&rmcp::transport::auth::StoredCredentials>,
    incoming: &rmcp::transport::auth::StoredCredentials,
) -> bool {
    match (
        existing.and_then(|e| e.token_received_at),
        incoming.token_received_at,
    ) {
        (Some(existing), Some(incoming)) => existing > incoming,
        _ => false,
    }
}

/// Keep a copy of an unparsable credential file's bytes (already read under the lock) in a NEW owner-only file
/// `<name>.corrupt-<unix-nanos>` and log a warning. The damaged file itself is not renamed or chmodded (it may be a
/// symlink); the caller's normal atomic write replaces it. An existing aside copy is never replaced.
fn copy_corrupt_aside(path: &Path, bytes: &[u8], reason: &str) -> Result<()> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let aside = write_aside_copy(path, nanos, bytes)?;
    prune_aside_copies(path, &aside, KEEP_ASIDE_COPIES);
    fuigo_config::mcp_bearer_file::record_note(format!(
        "the saved MCP sign-in file could not be read, so MCP servers will ask you to sign in again. A copy of the damaged file was kept next to it as {}",
        aside.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned())
    ));
    tracing::warn!(
        path = %path.display(),
        aside = %aside.display(),
        reason,
        "mcp credentials: store could not be parsed; a copy was kept aside and the store starts empty (re-authenticate MCP servers)"
    );
    Ok(())
}

/// How many `.corrupt-*` copies stay beside the store: each holds live refresh tokens, so older ones are deleted.
const KEEP_ASIDE_COPIES: usize = 2;

/// Delete all but the newest `keep` aside copies of `path` (the one just written, `just_written`, always stays).
/// Newest is by the numeric stamp in the name, then the suffix. Best-effort: a failed delete is only logged.
fn prune_aside_copies(path: &Path, just_written: &Path, keep: usize) {
    let (Some(dir), Some(base)) = (path.parent(), path.file_name()) else {
        return;
    };
    let prefix = format!("{}.corrupt-", base.to_string_lossy());
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    let mut found: Vec<((u128, u32), PathBuf)> = read
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let rest = name.strip_prefix(&prefix)?;
            let (stamp, suffix) = match rest.split_once('-') {
                Some((stamp, suffix)) => (stamp, suffix.parse::<u32>().ok()?),
                None => (rest, 0),
            };
            Some(((stamp.parse::<u128>().ok()?, suffix), entry.path()))
        })
        .collect();
    // The copy just written always stays and takes one slot; keep the newest `keep - 1` of the rest.
    found.retain(|(_, p)| p != just_written);
    found.sort();
    let excess = found.len().saturating_sub(keep.saturating_sub(1));
    for (_, old) in found.into_iter().take(excess) {
        if let Err(e) = std::fs::remove_file(&old) {
            tracing::warn!(path = %old.display(), error = %e, "mcp credentials: could not delete an old aside copy");
        }
    }
}

/// Write `bytes` to a new file `<path>.corrupt-<stamp>` (mode 0600 on Unix), with a numeric suffix `-1`, `-2`, ...
/// when the name is taken. `create_new` never replaces an existing file and does not follow a symlink at the name.
fn write_aside_copy(path: &Path, stamp: u128, bytes: &[u8]) -> Result<PathBuf> {
    use std::io::Write;

    let mut attempt = 0u32;
    loop {
        let mut name = path.as_os_str().to_owned();
        name.push(format!(".corrupt-{stamp}"));
        if attempt > 0 {
            name.push(format!("-{attempt}"));
        }
        let aside = PathBuf::from(name);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&aside) {
            Ok(mut file) => {
                if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
                    let _ = std::fs::remove_file(&aside);
                    return Err(e.into());
                }
                return Ok(aside);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt < 10_000 => {
                attempt += 1;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Config URLs can embed secrets.
#[cfg(test)]
fn write_owner_only_atomic(path: &Path, content: &str) -> Result<()> {
    use std::io::Write;

    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    std::fs::create_dir_all(parent)?;

    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    tmp.write_all(content.as_bytes())?;
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// Last access token an adapter served.
/// Reauth compares the store against this to tell a fresh token apart from one this client already failed with.
#[derive(Clone, Default)]
pub(crate) struct ObservedAccessToken(Arc<parking_lot::Mutex<Option<String>>>);

/// Hand-written `Debug` (P70): reports whether a token was observed, never the token. The destructure is exhaustive,
/// so a new field fails to compile here until its Debug output is decided (Astra r6).
impl std::fmt::Debug for ObservedAccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(observed) = self;
        let observed = observed.lock().as_ref().map(|_| "<redacted>");
        f.debug_tuple("ObservedAccessToken").field(&observed).finish()
    }
}

impl ObservedAccessToken {
    pub(crate) fn snapshot(&self) -> Option<String> {
        self.0.lock().clone()
    }

    pub(crate) fn record(&self, token: Option<String>) {
        *self.0.lock() = token;
    }
}

fn access_token_secret(creds: Option<&rmcp::transport::auth::StoredCredentials>) -> Option<String> {
    use oauth2::TokenResponse as _;
    creds
        .and_then(|c| c.token_response.as_ref())
        .map(|t| t.access_token().secret().clone())
}

/// Record the OAuth access and refresh tokens as credentials sent (audit S11-F4), so exact-value scrubbing covers an
/// error or log line that echoes one. Called on every load and save of the adapter.
fn record_sent_tokens(creds: Option<&rmcp::transport::auth::StoredCredentials>) {
    use oauth2::TokenResponse as _;
    let Some(token) = creds.and_then(|c| c.token_response.as_ref()) else {
        return;
    };
    fuigo_telemetry::sent_credentials::record(token.access_token().secret());
    if let Some(refresh) = token.refresh_token() {
        fuigo_telemetry::sent_credentials::record(refresh.secret());
    }
}

/// Every load records the served token in `observed`.
pub struct McpCredentialStoreAdapter {
    server_name: String,
    server_url: url::Url,
    observed: ObservedAccessToken,
}

impl McpCredentialStoreAdapter {
    pub fn new(server_name: String, server_url: url::Url) -> Self {
        Self {
            server_name,
            server_url,
            observed: ObservedAccessToken::default(),
        }
    }

    pub(crate) fn observed(&self) -> ObservedAccessToken {
        self.observed.clone()
    }
}

#[async_trait::async_trait]
impl rmcp::transport::auth::CredentialStore for McpCredentialStoreAdapter {
    async fn load(
        &self,
    ) -> std::result::Result<
        Option<rmcp::transport::auth::StoredCredentials>,
        rmcp::transport::auth::AuthError,
    > {
        let name = self.server_name.clone();
        let url = self.server_url.clone();
        let result = tokio::task::spawn_blocking(move || {
            let store = McpCredentialStore::load_default()
                .map_err(|e| rmcp::transport::auth::AuthError::InternalError(e.to_string()))?;
            Ok(store.get(&name, &url).cloned())
        })
        .await
        .map_err(|e| rmcp::transport::auth::AuthError::InternalError(e.to_string()))?;
        if let Ok(creds) = &result {
            record_sent_tokens(creds.as_ref());
            self.observed.record(access_token_secret(creds.as_ref()));
        }
        result
    }

    async fn save(
        &self,
        credentials: rmcp::transport::auth::StoredCredentials,
    ) -> std::result::Result<(), rmcp::transport::auth::AuthError> {
        record_sent_tokens(Some(&credentials));
        let name = self.server_name.clone();
        let url = self.server_url.clone();
        tokio::task::spawn_blocking(move || {
            let mut store = McpCredentialStore::default();
            store
                .insert_and_save(&name, &url, credentials)
                .map_err(|e| rmcp::transport::auth::AuthError::InternalError(e.to_string()))
        })
        .await
        .map_err(|e| rmcp::transport::auth::AuthError::InternalError(e.to_string()))?
    }

    async fn clear(&self) -> std::result::Result<(), rmcp::transport::auth::AuthError> {
        let name = self.server_name.clone();
        let url = self.server_url.clone();
        tokio::task::spawn_blocking(move || {
            // Under the same flock as `insert_and_save`: this is a whole-file read-modify-write
            // An unlocked snapshot here could silently drop *other servers'* entries another process wrote concurrently
            // Their just-rotated refresh tokens would go with them
            let mut store = McpCredentialStore::default();
            store
                .remove_and_save(&name, &url)
                .map_err(|e| rmcp::transport::auth::AuthError::InternalError(e.to_string()))
        })
        .await
        .map_err(|e| rmcp::transport::auth::AuthError::InternalError(e.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_stored_creds(client_id: &str) -> rmcp::transport::auth::StoredCredentials {
        rmcp::transport::auth::StoredCredentials::new(client_id.to_string(), None, Vec::new(), None)
    }

    /// Audit S11-F4: the OAuth tokens the adapter serves and saves are recorded as sent.
    #[test]
    fn oauth_tokens_are_recorded_as_sent() {
        use fuigo_telemetry::sent_credentials::scrub;
        let fixture = r#"{
            "srv:https://mcp.example.com/mcp": {
                "client_id": "c",
                "token_response": {
                    "access_token": "s11f4-oauth-access-FAKE-0001",
                    "token_type": "bearer",
                    "refresh_token": "s11f4-oauth-refresh-FAKE-0002"
                }
            }
        }"#;
        let store: McpCredentialStore = serde_json::from_str(fixture).unwrap();
        let url = Url::parse("https://mcp.example.com/mcp").unwrap();
        record_sent_tokens(store.get("srv", &url));
        for token in ["s11f4-oauth-access-FAKE-0001", "s11f4-oauth-refresh-FAKE-0002"] {
            assert!(!scrub(&format!("upstream echoed {token}")).contains(token), "{token}");
        }
    }

    #[test]
    fn insert_and_get() {
        let mut store = McpCredentialStore::default();
        let url = Url::parse("https://test.example.com/mcp").unwrap();
        store.insert_rmcp("test", &url, test_stored_creds("test-client"));
        assert!(store.get("test", &url).is_some());
        assert_eq!(store.get("test", &url).unwrap().client_id, "test-client");
    }

    #[test]
    fn remove_entry() {
        let mut store = McpCredentialStore::default();
        let url = Url::parse("https://test.example.com/mcp").unwrap();
        store.insert_rmcp("test", &url, test_stored_creds("test-client"));
        store.remove("test", &url);
        assert!(store.get("test", &url).is_none());
    }

    #[test]
    fn has_credentials() {
        let mut store = McpCredentialStore::default();
        let url = Url::parse("https://test.example.com/mcp").unwrap();
        assert!(!store.has_credentials("test", &url));
        store.insert_rmcp("test", &url, test_stored_creds("c"));
        assert!(store.has_credentials("test", &url));
    }

    #[test]
    fn roundtrip_serialization() {
        let mut store = McpCredentialStore::default();
        let url = Url::parse("https://test.example.com/mcp").unwrap();
        store.insert_rmcp("test", &url, test_stored_creds("test-client"));

        let json = serde_json::to_string(&store).unwrap();
        let loaded: McpCredentialStore = serde_json::from_str(&json).unwrap();
        assert!(loaded.get("test", &url).is_some());
    }

    /// Raw JSON fixture in the exact shape rmcp 0.17 persisted to `$FUIGO_HOME/mcp_credentials.json`.
    /// Existing credential files must keep loading across rmcp upgrades (2.1's `OAuthTokenResponse` gained vendor extra token fields).
    /// So this must be a string literal, never JSON serialized by the current code.
    #[test]
    fn legacy_on_disk_fixture_still_deserializes() {
        use oauth2::TokenResponse as _;

        let fixture = r#"{
            "linear:https://mcp.example.com/mcp": {
                "client_id": "legacy-client-id",
                "token_response": {
                    "access_token": "at-123",
                    "token_type": "bearer",
                    "expires_in": 3600,
                    "refresh_token": "rt-456",
                    "scope": "read write"
                },
                "granted_scopes": ["read", "write"],
                "token_received_at": 1730000000
            },
            "noauth:https://example.com/mcp": {
                "client_id": "c2",
                "token_response": null
            }
        }"#;

        let store: McpCredentialStore = serde_json::from_str(fixture).unwrap();
        let url = Url::parse("https://mcp.example.com/mcp").unwrap();
        let creds = store.get("linear", &url).expect("legacy entry loads");
        assert_eq!(creds.client_id, "legacy-client-id");
        let token = creds.token_response.as_ref().expect("token loads");
        assert_eq!(token.access_token().secret(), "at-123");
        assert_eq!(token.refresh_token().unwrap().secret(), "rt-456");
        assert_eq!(creds.granted_scopes, vec!["read", "write"]);
        assert_eq!(creds.token_received_at, Some(1730000000));

        // Entry without the `#[serde(default)]` fields on disk still loads.
        let url2 = Url::parse("https://example.com/mcp").unwrap();
        let creds2 = store.get("noauth", &url2).expect("minimal entry loads");
        assert!(creds2.token_response.is_none());
        assert!(creds2.granted_scopes.is_empty());
        assert!(creds2.token_received_at.is_none());

        // Round-trip through the current serializer and reload.
        let json = serde_json::to_string(&store).unwrap();
        let reloaded: McpCredentialStore = serde_json::from_str(&json).unwrap();
        let re = reloaded
            .get("linear", &url)
            .expect("round-trip keeps entry");
        assert_eq!(re.client_id, "legacy-client-id");
        let re_token = re.token_response.as_ref().expect("round-trip keeps token");
        assert_eq!(re_token.access_token().secret(), "at-123");
        assert_eq!(re_token.refresh_token().unwrap().secret(), "rt-456");
        assert_eq!(re.granted_scopes, vec!["read", "write"]);
        assert_eq!(re.token_received_at, Some(1730000000));
    }

    #[test]
    fn save_and_load_from_file() {
        let dir = std::env::temp_dir().join("fuigo-mcp-credentials-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_creds.json");

        let mut store = McpCredentialStore::default();
        let url = Url::parse("https://test.example.com/mcp").unwrap();
        store.insert_rmcp("test", &url, test_stored_creds("test-client"));
        store.save_to(&path).unwrap();

        let loaded = McpCredentialStore::load_from(&path).unwrap();
        assert!(loaded.get("test", &url).is_some());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn save_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds.json");
        let mut store = McpCredentialStore::default();
        let url = Url::parse("https://test.example.com/mcp").unwrap();
        store.insert_rmcp("test", &url, test_stored_creds("c"));
        store.save_to(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn load_tightens_world_readable_credentials() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds.json");
        let mut store = McpCredentialStore::default();
        let url = Url::parse("https://test.example.com/mcp").unwrap();
        store.insert_rmcp("test", &url, test_stored_creds("c"));
        store.save_to(&path).unwrap();
        let mut loose = std::fs::metadata(&path).unwrap().permissions();
        loose.set_mode(0o644);
        std::fs::set_permissions(&path, loose).unwrap();

        let _ = McpCredentialStore::load_from(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// The `insert_and_save` freshness guard: a save older (by `token_received_at`) than the on-disk entry must be skipped.
    #[test]
    fn stale_save_does_not_clobber_newer_disk_entry() {
        // `StoredCredentials` is #[non_exhaustive]; construct via `new` and set the (public) timestamp field afterwards
        let mut older = test_stored_creds("c");
        older.token_received_at = Some(1_000);
        let mut newer = test_stored_creds("c");
        newer.token_received_at = Some(2_000);
        let no_ts = test_stored_creds("c");

        assert!(
            disk_entry_is_newer(Some(&newer), &older),
            "older incoming vs newer disk → skip the write"
        );
        assert!(
            !disk_entry_is_newer(Some(&older), &newer),
            "newer incoming vs older disk → write proceeds"
        );
        assert!(
            !disk_entry_is_newer(Some(&older), &older),
            "equal timestamps → write proceeds (idempotent re-save)"
        );
        assert!(
            !disk_entry_is_newer(None, &older),
            "no disk entry → write proceeds"
        );
        assert!(
            !disk_entry_is_newer(Some(&newer), &no_ts),
            "timestamp-less incoming keeps pre-guard behavior (writes)"
        );
        assert!(
            !disk_entry_is_newer(Some(&no_ts), &older),
            "timestamp-less disk entry keeps pre-guard behavior (writes)"
        );
    }

    #[test]
    fn unparsable_store_is_moved_aside_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CREDENTIALS_FILENAME);
        let garbage = b"{ not json, but someone's only copy of tokens";
        std::fs::write(&path, garbage).unwrap();

        let mut store = McpCredentialStore::default();
        let url = Url::parse("https://example.com/mcp").unwrap();
        store
            .locked_mutate_and_save_at(&path, &|s: &mut McpCredentialStore| {
                s.insert_rmcp("new", &url, test_stored_creds("new"));
            })
            .unwrap();

        let asides: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("mcp_credentials.json.corrupt-")
            })
            .collect();
        assert_eq!(asides.len(), 1, "exactly one moved-aside file");
        assert_eq!(std::fs::read(&asides[0]).unwrap(), garbage);
        let loaded = McpCredentialStore::load_from(&path).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert!(loaded.has_credentials("new", &url));
    }

    fn aside_files(dir: &Path) -> Vec<PathBuf> {
        let mut v: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("mcp_credentials.json.corrupt-")
            })
            .collect();
        v.sort();
        v
    }

    /// Unparsable stores in a row (no matter how close in time) keep the newest two recovery copies, never overwriting.
    #[test]
    fn corruptions_keep_the_newest_aside_copies_and_prune_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CREDENTIALS_FILENAME);
        let url = Url::parse("https://example.com/mcp").unwrap();
        let mut seen = Vec::new();
        for i in 0..5 {
            let garbage = format!("{{ broken {i}");
            std::fs::write(&path, &garbage).unwrap();
            let mut store = McpCredentialStore::default();
            store
                .locked_mutate_and_save_at(&path, &|s: &mut McpCredentialStore| {
                    s.insert_rmcp("n", &url, test_stored_creds("n"));
                })
                .unwrap();
            seen.push(garbage);
        }
        let mut contents: Vec<String> = aside_files(dir.path())
            .iter()
            .map(|p| std::fs::read_to_string(p).unwrap())
            .collect();
        contents.sort();
        let mut newest: Vec<String> = seen[seen.len() - KEEP_ASIDE_COPIES..].to_vec();
        newest.sort();
        assert_eq!(contents, newest, "only the newest copies stay (review L2)");
    }

    /// review L4: a store that cannot be statted or read is an error, not an empty store.
    #[cfg(unix)]
    #[test]
    fn load_from_reports_a_read_error_instead_of_an_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CREDENTIALS_FILENAME);
        // A link loop: `exists()` is false for it, `read` fails with a non-NotFound error.
        std::os::unix::fs::symlink(&path, &path).unwrap();
        assert!(McpCredentialStore::load_from(&path).is_err());
        let missing = dir.path().join("absent.json");
        assert!(McpCredentialStore::load_from(&missing).unwrap().is_empty());
    }

    /// C7-03: the safe summary of a damaged-store error never holds file content.
    #[test]
    fn safe_summary_never_holds_store_contents() {
        let e = McpCredentialError::Json(
            serde_json::from_str::<McpCredentialStore>(r#"{"srv:https://h.invalid/mcp":"SECRET-C703-TOKEN"}"#).unwrap_err(),
        );
        assert!(e.to_string().contains("SECRET-C703-TOKEN"), "premise: the raw text quotes the value");
        assert!(!e.safe_summary().contains("SECRET-C703-TOKEN"));
    }

    /// C7-04: the copy just written takes one retention slot even when it sorts oldest.
    #[test]
    fn prune_keeps_the_just_written_copy_and_the_newest_of_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CREDENTIALS_FILENAME);
        let aside = |stamp: u32| dir.path().join(format!("{CREDENTIALS_FILENAME}.corrupt-{stamp}"));
        for stamp in [1, 5, 6, 7] {
            std::fs::write(aside(stamp), b"x").unwrap();
        }
        prune_aside_copies(&path, &aside(1), KEEP_ASIDE_COPIES);
        let left: Vec<u32> = [1, 5, 6, 7].into_iter().filter(|s| aside(*s).exists()).collect();
        assert_eq!(left, vec![1, 7]);
    }

    /// A read error names the store file, so a user at sign-in knows which file to look at.
    #[cfg(unix)]
    #[test]
    fn load_from_read_error_names_the_store_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CREDENTIALS_FILENAME);
        std::os::unix::fs::symlink(&path, &path).unwrap();
        let text = match McpCredentialStore::load_from(&path) {
            Ok(_) => panic!("a link loop must not load"),
            Err(e) => e.to_string(),
        };
        assert!(text.contains(CREDENTIALS_FILENAME), "{text}");
    }

    /// A name that is already taken is never replaced: the next free numeric suffix is used.
    #[test]
    fn aside_name_collision_never_replaces_an_existing_copy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CREDENTIALS_FILENAME);
        let first = dir.path().join("mcp_credentials.json.corrupt-5");
        std::fs::write(&first, b"first").unwrap();
        let second = write_aside_copy(&path, 5, b"second").unwrap();
        assert_eq!(std::fs::read(&first).unwrap(), b"first");
        assert_eq!(std::fs::read(&second).unwrap(), b"second");
        assert_ne!(first, second);
    }

    #[cfg(unix)]
    #[test]
    fn aside_copy_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CREDENTIALS_FILENAME);
        std::fs::write(&path, b"{ broken").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut store = McpCredentialStore::default();
        store.locked_mutate_and_save_at(&path, &|_| {}).unwrap();
        let asides = aside_files(dir.path());
        assert_eq!(asides.len(), 1);
        let mode = std::fs::metadata(&asides[0]).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// A symlinked store whose target is damaged: the target is neither renamed nor chmodded, and its bytes stay.
    #[cfg(unix)]
    #[test]
    fn symlinked_damaged_store_target_is_left_alone() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere.json");
        std::fs::write(&target, b"{ broken").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let path = dir.path().join(CREDENTIALS_FILENAME);
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let mut store = McpCredentialStore::default();
        store.locked_mutate_and_save_at(&path, &|_| {}).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"{ broken");
        assert_eq!(std::fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o644);
        let asides = aside_files(dir.path());
        assert_eq!(asides.len(), 1);
        assert!(!std::fs::symlink_metadata(&asides[0]).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(&asides[0]).unwrap(), b"{ broken");
    }

    /// Removing a server reloads under the lock: an entry another writer saved after this snapshot was loaded survives.
    #[test]
    fn server_removal_keeps_entries_written_after_the_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CREDENTIALS_FILENAME);
        let url = Url::parse("https://example.com/mcp").unwrap();
        let mut seed = McpCredentialStore::default();
        seed.locked_mutate_and_save_at(&path, &|s: &mut McpCredentialStore| {
            s.insert_rmcp("a", &url, test_stored_creds("a"));
            s.insert_rmcp("b", &url, test_stored_creds("b"));
        })
        .unwrap();
        let mut snapshot = McpCredentialStore::load_from(&path).unwrap();
        let mut other = McpCredentialStore::default();
        other
            .locked_mutate_and_save_at(&path, &|s: &mut McpCredentialStore| {
                s.insert_rmcp("c", &url, test_stored_creds("c"));
            })
            .unwrap();

        let removed = snapshot.remove_by_server_name_and_save_at(&path, "a").unwrap();
        assert_eq!(removed, 1);
        let loaded = McpCredentialStore::load_from(&path).unwrap();
        assert!(!loaded.has_credentials("a", &url));
        assert!(loaded.has_credentials("b", &url));
        assert!(loaded.has_credentials("c", &url), "a concurrent write must not be rolled back");
    }

    /// Removing a server that has no entry writes nothing (no empty store is created).
    #[test]
    fn server_removal_with_nothing_to_remove_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CREDENTIALS_FILENAME);
        let mut store = McpCredentialStore::default();
        assert_eq!(store.remove_by_server_name_and_save_at(&path, "a").unwrap(), 0);
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_store_fails_the_write_and_stays_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CREDENTIALS_FILENAME);
        // A symlink loop: reading it fails with ELOOP (not NotFound, and independent of root),
        // while a rename over it would succeed, so an overwrite would be possible.
        std::os::unix::fs::symlink(&path, &path).unwrap();

        let mut store = McpCredentialStore::default();
        let url = Url::parse("https://example.com/mcp").unwrap();
        let result = store.locked_mutate_and_save_at(&path, &|s: &mut McpCredentialStore| {
            s.insert_rmcp("new", &url, test_stored_creds("new"));
        });
        assert!(result.is_err(), "an unreadable store must fail the write");
        assert_eq!(
            std::fs::read_link(&path).unwrap(),
            path,
            "the unreadable path is left untouched"
        );
    }

    /// The adapter's `save` and `clear` go through the default path.
    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn adapter_clear_and_save_fail_on_unreadable_store_and_keep_it() {
        use rmcp::transport::auth::CredentialStore;
        crate::isolate_fuigo_home_for_tests();
        let path = McpCredentialStore::default_path().unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&path);
        std::os::unix::fs::symlink(&path, &path).unwrap();

        let url = Url::parse("https://example.com/mcp").unwrap();
        let adapter = McpCredentialStoreAdapter::new("srv".into(), url);
        assert!(adapter.clear().await.is_err(), "clear must error");
        assert!(adapter.save(test_stored_creds("c")).await.is_err(), "save must error");
        assert_eq!(
            std::fs::read_link(&path).unwrap(),
            path,
            "the unreadable path is left untouched"
        );
        std::fs::remove_file(&path).unwrap();
    }

    /// Audit S11-F4: an OAuth access token the adapter serves or saves is recorded as sent, so an upstream that echoes
    /// it back has it replaced by the exact-match scrub.
    #[tokio::test]
    #[serial_test::serial]
    async fn adapter_records_served_and_saved_access_tokens_as_sent() {
        use rmcp::transport::auth::CredentialStore;
        crate::isolate_fuigo_home_for_tests();
        let creds = |token: &str| -> rmcp::transport::auth::StoredCredentials {
            serde_json::from_str(&format!(
                r#"{{"client_id":"c","token_response":{{"access_token":"{token}","token_type":"bearer","expires_in":3600}}}}"#
            ))
            .unwrap()
        };
        let echoed = |token: &str| format!("401 from upstream: invalid token {token}");
        let recorded = |token: &str| fuigo_telemetry::sent_credentials::scrub(&echoed(token)).as_ref() != echoed(token);

        let url = Url::parse("https://s11f4.example.com/mcp").unwrap();
        let adapter = McpCredentialStoreAdapter::new("s11f4".into(), url);
        const SAVED: &str = "s11f4-oauth-saved-FAKE-0001";
        assert!(!recorded(SAVED));
        adapter.save(creds(SAVED)).await.unwrap();
        assert!(recorded(SAVED), "a saved access token was not recorded");

        const LOADED: &str = "s11f4-oauth-loaded-FAKE-0002";
        let mut store = McpCredentialStore::default();
        store
            .insert_and_save("s11f4", &Url::parse("https://s11f4.example.com/mcp").unwrap(), creds(LOADED))
            .unwrap();
        assert!(!recorded(LOADED));
        assert!(adapter.load().await.unwrap().is_some());
        assert!(recorded(LOADED), "a served access token was not recorded");
    }

    #[test]
    fn concurrent_writers_on_different_servers_both_survive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CREDENTIALS_FILENAME);
        let url = Url::parse("https://example.com/mcp").unwrap();
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let path = path.clone();
                let url = url.clone();
                std::thread::spawn(move || {
                    let mut store = McpCredentialStore::default();
                    let name = format!("srv{i}");
                    store
                        .locked_mutate_and_save_at(&path, &|s: &mut McpCredentialStore| {
                            s.insert_rmcp(&name, &url, test_stored_creds("c"));
                        })
                        .unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let loaded = McpCredentialStore::load_from(&path).unwrap();
        assert_eq!(loaded.entries.len(), 8, "no writer's entry may be lost");
    }

    /// The refresh-failure classifier gates browser escalation (`force_reauth`).
    /// Network-level failures (the `oauth2` crate's `Display` for request/parse errors) are transient.
    /// IdP rejections and missing-credential states stay terminal and escalate.
    #[test]
    fn refresh_failure_transient_classification() {
        use crate::servers::mcp_refresh_failure_is_transient;
        use rmcp::transport::auth::AuthError;

        // oauth2 RequestTokenError::Request renders exactly "Request failed".
        assert!(mcp_refresh_failure_is_transient(
            &AuthError::TokenRefreshFailed("Request failed".into())
        ));
        // "Failed to parse server response" covers 5xx/proxy bodies that aren't OAuth JSON
        assert!(mcp_refresh_failure_is_transient(
            &AuthError::TokenRefreshFailed("Failed to parse server response".into())
        ));

        // IdP rejections carry the RFC 6749 code, so they stay terminal
        assert!(!mcp_refresh_failure_is_transient(
            &AuthError::TokenRefreshFailed(
                "Server returned error response: invalid_grant: token revoked".into()
            )
        ));
        // With no refresh token at all, only the browser flow can help
        assert!(!mcp_refresh_failure_is_transient(
            &AuthError::TokenRefreshFailed("No refresh token available".into())
        ));
        // An empty credential store requires interactive auth
        assert!(!mcp_refresh_failure_is_transient(
            &AuthError::AuthorizationRequired
        ));
    }
}
