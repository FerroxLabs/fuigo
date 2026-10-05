use super::*;
use crate::util::secure_file::ensure_owner_only_permissions;
use fs2::FileExt;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

#[derive(Default, Serialize, Deserialize)]
struct ProviderAccounts {
    selected: Option<String>,
    accounts: BTreeMap<String, Credential>,
}
type Records = BTreeMap<SubscriptionProvider, ProviderAccounts>;

/// Back-off between attempts to persist a credential the provider has already issued.
/// Only a transient fault (a full disk briefly freed, a momentary I/O error) is covered;
/// anything longer falls back to the in-process stash below.
const PERSIST_RETRY_DELAYS: [Duration; 2] = [Duration::from_millis(50), Duration::from_millis(250)];

/// Credentials a SUCCESSFUL refresh issued but the store could not write.
///
/// By then the provider has rotated the refresh token. The record on disk holds either the
/// rotated-away token behind `refresh_pending: true` (written before the exchange), or, if
/// the failure struck after the atomic rename (the directory fsync), the new record not yet
/// known durable. Neither lets any process present the old token: the latch refuses it, and
/// a reverted rename falls back to the latch. Dropping the new tokens
/// as well would sign the user out for a local disk fault, so this process keeps them,
/// keeps trying to write them, and stops honouring them the moment the disk shows anything
/// other than the latched record they supersede, or themselves (a fresh login or a logout
/// won; see `Stash`).
/// A process exit before the disk recovers loses them; the latch then forces a re-login,
/// which is the fail-closed outcome.
struct Unpersisted {
    credential: Credential,
    /// The refresh token the latched on-disk record holds; the stash supersedes only that.
    rotated_from: String,
    /// The access token of that latched record. A refresh token alone does not identify it:
    /// a provider that does not rotate leaves the same refresh token in this credential, and
    /// another process may later latch THIS credential's record over that same token.
    latched_access: String,
}
impl Unpersisted {
    /// Whether the on-disk record is one this stash may replace: the latched record it was
    /// rotated from, or its own record left by a write that renamed but never confirmed
    /// durability (a failed directory fsync), which must still be re-saved.
    fn supersedes(&self, on_disk: &Credential) -> bool {
        let latched = on_disk.refresh_pending
            && on_disk.refresh_token.as_deref() == Some(self.rotated_from.as_str())
            && on_disk.access_token == self.latched_access;
        let unconfirmed = !on_disk.refresh_pending
            && on_disk.refresh_token == self.credential.refresh_token
            && on_disk.access_token == self.credential.access_token;
        (latched || unconfirmed)
            && on_disk.account == self.credential.account
            && on_disk.provider == self.credential.provider
    }
}
type StashKey = (PathBuf, SubscriptionProvider, String);
/// What a logout guarantees for it. Every refresh holds the cross-process file lock for its
/// whole take / re-persist / put-back window, and `logout` clears this process's stash
/// before and again after taking that lock, so a logout in this process that takes the lock
/// ends this process's stash even if its own disk write then fails. A SUCCESSFUL logout
/// from any process ends every process's stash: the record it superseded is gone from disk,
/// so `supersedes` no longer matches. A logout that fails (no lock, or no write) from another
/// process is reported as failed and leaves that process's view, and ours, as before; this is
/// the pre-existing meaning of a failed logout for the on-disk record too. Nothing here can
/// make a rotated-away token usable: that is decided by the latch and `supersedes`.
#[derive(Default)]
struct Stash {
    entries: BTreeMap<StashKey, Unpersisted>,
}
impl Stash {
    fn take(&mut self, key: &StashKey) -> Option<Unpersisted> {
        self.entries.remove(key)
    }
    fn put(&mut self, key: StashKey, entry: Unpersisted) {
        self.entries.insert(key, entry);
    }
    fn forget(&mut self, root: &Path, provider: SubscriptionProvider, account: Option<&str>) {
        self.entries.retain(|(r, p, a), _| {
            !(r == root && *p == provider && account.is_none_or(|account| a == account))
        });
    }
}
fn stash() -> std::sync::MutexGuard<'static, Stash> {
    static STASH: OnceLock<Mutex<Stash>> = OnceLock::new();
    STASH
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Separate file and stable advisory lock shared by all Fuigo processes.
#[derive(Clone)]
pub struct SubscriptionStore {
    root: PathBuf,
    /// Test-only fault injection: while non-zero, each `write` fails and decrements it.
    #[cfg(test)]
    pub(super) write_faults: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Test-only: while non-zero, each `write` fails AFTER the atomic rename, as a failed
    /// directory fsync would, and decrements it.
    #[cfg(test)]
    pub(super) fsync_faults: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
impl SubscriptionStore {
    pub fn new(fuigo_home: &Path) -> Self {
        Self {
            root: fuigo_home.join("subscriptions"),
            #[cfg(test)]
            write_faults: Default::default(),
            #[cfg(test)]
            fsync_faults: Default::default(),
        }
    }
    fn stash_key(&self, provider: SubscriptionProvider, account: &str) -> StashKey {
        (self.root.clone(), provider, account.to_owned())
    }
    fn forget_unpersisted(&self, provider: SubscriptionProvider, account: Option<&str>) {
        stash().forget(&self.root, provider, account);
    }
    fn path(&self) -> PathBuf {
        self.root.join("credentials.json")
    }
    fn prepare(&self) -> Result<()> {
        std::fs::create_dir_all(self.root.parent().ok_or(SubscriptionError::Storage)?)
            .map_err(|_| SubscriptionError::Storage)?;
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&self.root) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(SubscriptionError::Storage),
        }
        let meta = std::fs::symlink_metadata(&self.root).map_err(|_| SubscriptionError::Storage)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(SubscriptionError::Storage);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            // SAFETY: geteuid has no preconditions.
            if meta.uid() != unsafe { libc::geteuid() } {
                return Err(SubscriptionError::Storage);
            }
            std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| SubscriptionError::Storage)?;
        }
        Ok(())
    }
    async fn lock(&self) -> Result<File> {
        self.prepare()?;
        let path = self.root.join("credentials.lock");
        reject_symlink(&path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options
            .open(&path)
            .map_err(|_| SubscriptionError::Storage)?;
        ensure_owner_only_permissions(&path).map_err(|_| SubscriptionError::Storage)?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(35);
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => return Ok(file),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return Err(SubscriptionError::Storage),
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(SubscriptionError::LockTimeout);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    fn read(&self) -> Result<Records> {
        reject_symlink(&self.path())?;
        ensure_owner_only_permissions(&self.path()).map_err(|_| SubscriptionError::Storage)?;
        match std::fs::read(self.path()) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| SubscriptionError::Storage),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Records::new()),
            Err(_) => Err(SubscriptionError::Storage),
        }
    }
    fn write(&self, records: &Records) -> Result<()> {
        #[cfg(test)]
        if self
            .write_faults
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |n| n.checked_sub(1),
            )
            .is_ok()
        {
            return Err(SubscriptionError::Storage);
        }
        reject_symlink(&self.path())?;
        let mut temp =
            tempfile::NamedTempFile::new_in(&self.root).map_err(|_| SubscriptionError::Storage)?;
        // Windows ACL is tightened before any secret bytes are written.
        ensure_owner_only_permissions(temp.path()).map_err(|_| SubscriptionError::Storage)?;
        let bytes = serde_json::to_vec(records).map_err(|_| SubscriptionError::Storage)?;
        temp.write_all(&bytes)
            .and_then(|_| temp.as_file().sync_all())
            .map_err(|_| SubscriptionError::Storage)?;
        temp.persist(self.path())
            .map_err(|_| SubscriptionError::Storage)?;
        #[cfg(test)]
        if self
            .fsync_faults
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |n| n.checked_sub(1),
            )
            .is_ok()
        {
            return Err(SubscriptionError::Storage);
        }
        #[cfg(unix)]
        File::open(&self.root)
            .and_then(|f| f.sync_all())
            .map_err(|_| SubscriptionError::Storage)?;
        Ok(())
    }
    /// `write`, retried across a short transient fault. Used only where the provider has
    /// already issued the credential being written, so giving up early would lose it.
    async fn write_retrying(&self, records: &Records) -> Result<()> {
        let mut result = self.write(records);
        for delay in PERSIST_RETRY_DELAYS {
            if result.is_ok() {
                break;
            }
            tokio::time::sleep(delay).await;
            result = self.write(records);
        }
        result
    }
    pub(super) async fn save(&self, credential: Credential) -> Result<()> {
        credential.validate(credential.provider, &credential.account)?;
        credential.access()?;
        let _lock = self.lock().await?;
        let mut records = self.read()?;
        let key = self.stash_key(credential.provider, &credential.account);
        let entry = records.entry(credential.provider).or_default();
        entry.selected = Some(credential.account.clone());
        entry
            .accounts
            .insert(credential.account.clone(), credential);
        self.write(&records)?;
        // A fresh login supersedes anything a failed refresh left in memory.
        stash().entries.remove(&key);
        Ok(())
    }
    pub async fn status(&self, provider: SubscriptionProvider) -> Result<Vec<SubscriptionStatus>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let _lock = self.lock().await?;
        let records = self.read()?;
        let Some(entry) = records.get(&provider) else {
            return Ok(Vec::new());
        };
        entry
            .accounts
            .iter()
            .map(|(account, c)| {
                c.validate(provider, account)?;
                Ok(SubscriptionStatus {
                    provider,
                    account: account.clone(),
                    selected: entry.selected.as_ref() == Some(account),
                    expires_at: c.expires_at,
                    login_required: c.refresh_pending
                        || (c.expires_at <= now() && c.refresh_token.is_none()),
                })
            })
            .collect()
    }
    /// Remove every local subscription credential, retaining the stable lock file.
    ///
    /// Takes the same cross-process lock every refresh holds for its whole read / exchange /
    /// write window, so no refresh can write a credential back after this returns. Deletes
    /// only inside this store's directory: `credentials.json`, and any `.tmp*` file a write
    /// interrupted by a crash left behind (each is a full copy of the records; no write is
    /// in flight while the lock is held). Nothing is revoked at the provider.
    pub async fn logout_all(&self) -> Result<()> {
        let forget_all = || {
            stash().entries.retain(|(root, _, _), _| root != &self.root);
        };
        forget_all();
        if !self.root.exists() {
            return Ok(());
        }
        let _lock = self.lock().await?;
        // A refresh may have returned a credential to the stash while we waited.
        forget_all();
        reject_symlink(&self.path())?;
        let mut removed = match std::fs::remove_file(self.path()) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(SubscriptionError::Storage),
        };
        for entry in std::fs::read_dir(&self.root).map_err(|_| SubscriptionError::Storage)? {
            let entry = entry.map_err(|_| SubscriptionError::Storage)?;
            let orphan = entry.file_name().to_string_lossy().starts_with(".tmp")
                && entry.file_type().is_ok_and(|kind| kind.is_file());
            if orphan {
                std::fs::remove_file(entry.path()).map_err(|_| SubscriptionError::Storage)?;
                removed = true;
            }
        }
        #[cfg(unix)]
        if removed {
            File::open(&self.root)
                .and_then(|file| file.sync_all())
                .map_err(|_| SubscriptionError::Storage)?;
        }
        let _ = removed;
        Ok(())
    }
    /// Omitted account removes only this provider; named logout preserves siblings.
    pub async fn logout(
        &self,
        provider: SubscriptionProvider,
        account: Option<&str>,
    ) -> Result<()> {
        // An explicit sign-out also ends any session-only credential. Cleared again once the
        // lock is held: a refresh holds it while it has the stash out and may put it back
        // before releasing (see `Stash`). From then on this process's session-only credential
        // is gone even if the write below fails; the disk then keeps what it held (a latch,
        // or a renamed-but-unconfirmed record) and the caller is told the logout failed.
        self.forget_unpersisted(provider, account);
        if !self.root.exists() {
            return Ok(());
        }
        let _lock = self.lock().await?;
        self.forget_unpersisted(provider, account);
        let mut records = self.read()?;
        if let Some(account) = account {
            if let Some(entry) = records.get_mut(&provider) {
                entry.accounts.remove(account);
                if entry.selected.as_deref() == Some(account) {
                    entry.selected = None;
                }
            }
        } else {
            records.remove(&provider);
        }
        self.write(&records)
    }
    /// Refresh completes/persists even if the requesting turn is cancelled.
    /// A durable pending marker prevents reuse after process death or ambiguous failure.
    pub async fn access(
        &self,
        provider: SubscriptionProvider,
        account: Option<&str>,
    ) -> Result<SubscriptionAccess> {
        self.access_with(provider, account, flow::TokenClient::new(provider)?)
            .await
    }
    pub(super) async fn access_with(
        &self,
        provider: SubscriptionProvider,
        account: Option<&str>,
        client: flow::TokenClient,
    ) -> Result<SubscriptionAccess> {
        let store = self.clone();
        let account = account.map(str::to_owned);
        tokio::spawn(async move {
            store
                .refresh_locked(provider, account.as_deref(), client)
                .await
        })
        .await
        // The refresh task died without reporting: how far the exchange got is unknown,
        // which is not the same claim as "the request was never sent".
        .map_err(|_| SubscriptionError::AmbiguousExchange)?
    }
    async fn refresh_locked(
        &self,
        provider: SubscriptionProvider,
        account: Option<&str>,
        client: flow::TokenClient,
    ) -> Result<SubscriptionAccess> {
        let _lock = self.lock().await?;
        let mut records = self.read()?; // Always reload AFTER acquiring the cross-process lock.
        let entry = records
            .get(&provider)
            .ok_or(SubscriptionError::LoginRequired)?;
        let account = account
            .or(entry.selected.as_deref())
            .ok_or(SubscriptionError::LoginRequired)?
            .to_owned();
        let mut current = entry
            .accounts
            .get(&account)
            .ok_or(SubscriptionError::LoginRequired)?
            .clone();
        current.validate(provider, &account)?;
        let key = self.stash_key(provider, &account);
        // Take the stash out whatever happens: it is either re-persisted, put back after
        // another failed write, or dropped because the disk has moved past it.
        let stashed = stash().take(&key);
        let stashed = stashed.filter(|stashed| stashed.supersedes(&current));
        if let Some(stashed) = stashed {
            records
                .get_mut(&provider)
                .unwrap()
                .accounts
                .insert(account.clone(), stashed.credential.clone());
            match self.write_retrying(&records).await {
                Ok(()) => {
                    tracing::info!(
                        provider = provider.name(),
                        "subscription credential refreshed earlier has now been saved"
                    );
                    current = stashed.credential;
                }
                Err(error) => {
                    // Refreshing again would rotate a token only memory holds, so an unsaved
                    // credential is served only while it needs no refresh.
                    let usable = stashed.credential.expires_at > now().saturating_add(120);
                    let access = stashed.credential.access();
                    stash().put(key, stashed);
                    if usable {
                        tracing::warn!(
                            provider = provider.name(),
                            %error,
                            "subscription credential still cannot be saved; using it for this session only"
                        );
                        return access.map(SubscriptionAccess::unpersisted);
                    }
                    tracing::warn!(
                        provider = provider.name(),
                        %error,
                        "unsaved subscription credential is about to expire and cannot be \
                         refreshed until it is saved; fix the disk, or `fuigo login`"
                    );
                    return Err(error);
                }
            }
        }
        if current.refresh_pending {
            return Err(SubscriptionError::LoginRequired);
        }
        if current.expires_at > now().saturating_add(120) {
            return current.access();
        }
        let refresh = current
            .refresh_token
            .as_deref()
            .ok_or(SubscriptionError::LoginRequired)?
            .to_owned();
        current.refresh_pending = true;
        records
            .get_mut(&provider)
            .unwrap()
            .accounts
            .insert(account.clone(), current.clone());
        self.write(&records)?; // Fail before exchange if rotation cannot be recorded safely.
        let mut next = match client.refresh(&refresh).await {
            Ok(next) => next,
            // The marker is a record of "this token may already be rotated", not of
            // "this credential is invalid". When the failure proves the provider issued
            // nothing, clear it: otherwise one refused or undelivered request would sign
            // the user out for good. When the outcome is unknown, it stays set and only a
            // fresh login recovers. A failure to persist the clear leaves the marker set,
            // which is the safe direction, and is reported as the persistence failure it is.
            Err(error) if !error.may_have_consumed_refresh_token() => {
                current.refresh_pending = false;
                records
                    .get_mut(&provider)
                    .unwrap()
                    .accounts
                    .insert(account, current);
                self.write(&records)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if next.account != current.account {
            return Err(SubscriptionError::InvalidCredentials);
        }
        if next.refresh_token.is_none() {
            next.refresh_token = Some(refresh.clone());
        }
        records
            .get_mut(&provider)
            .unwrap()
            .accounts
            .insert(account, next.clone());
        // No non-atomic fallback. The provider has already rotated the token, so a failed
        // write must not discard what it issued: the disk keeps the latch (or, after a failed
        // directory fsync, the new record; see `Unpersisted`), so the old token is never
        // presented again, and this process keeps the new credential, loudly.
        if let Err(error) = self.write_retrying(&records).await {
            tracing::warn!(
                provider = provider.name(),
                %error,
                "subscription refresh succeeded but the new credential could not be saved; \
                 using it for this session only. Fix the disk and Fuigo will save it on next \
                 use; restarting first will require `fuigo login`"
            );
            let access = next.access();
            stash().put(
                key,
                Unpersisted {
                    credential: next,
                    rotated_from: refresh,
                    latched_access: current.access_token,
                },
            );
            return access.map(SubscriptionAccess::unpersisted);
        }
        next.access()
    }
}
fn reject_symlink(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
            Err(SubscriptionError::Storage)
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(SubscriptionError::Storage),
    }
}

#[cfg(test)]
mod stash_tests {
    use super::*;

    #[tokio::test]
    async fn a_logout_that_waited_for_a_refresh_still_ends_the_stash_it_put_back() {
        for all in [false, true] {
            let provider = SubscriptionProvider::Xai;
            let temp = tempfile::tempdir().unwrap();
            let store = SubscriptionStore::new(temp.path());
            let key = store.stash_key(provider, "a");
            let entry = Unpersisted {
                credential: Credential {
                    provider,
                    issuer: provider.issuer().into(),
                    client_id: provider.client_id().into(),
                    account: "a".into(),
                    access_token: "fake-access".into(),
                    refresh_token: Some("fake-refresh-2".into()),
                    expires_at: now() + 3600,
                    refresh_pending: false,
                },
                rotated_from: "fake-refresh-1".into(),
                latched_access: "fake-access-0".into(),
            };
            // A refresh holds the file lock and has the stash out while it retries saving it ...
            let refresh_lock = store.lock().await.unwrap();
            // ... a logout starts meanwhile and has to wait for that lock ...
            let logout = tokio::spawn({
                let store = store.clone();
                async move {
                    if all {
                        store.logout_all().await
                    } else {
                        store.logout(provider, None).await
                    }
                }
            });
            // On this single-threaded test runtime, the sleep lets the logout run its pre-lock
            // clear and park in its lock-retry loop.
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(!logout.is_finished());
            // ... the refresh gives up saving and puts the stash back, then releases the lock.
            stash().put(key.clone(), entry);
            drop(refresh_lock);
            logout.await.unwrap().unwrap();
            assert!(stash().take(&key).is_none());
        }
    }
}
