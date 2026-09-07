use super::*;
use crate::util::secure_file::ensure_owner_only_permissions;
use fs2::FileExt;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Default, Serialize, Deserialize)]
struct ProviderAccounts {
    selected: Option<String>,
    accounts: BTreeMap<String, Credential>,
}
type Records = BTreeMap<SubscriptionProvider, ProviderAccounts>;

/// Separate file and stable advisory lock shared by all Fuigo processes.
#[derive(Clone)]
pub struct SubscriptionStore {
    root: PathBuf,
}
impl SubscriptionStore {
    pub fn new(fuigo_home: &Path) -> Self {
        Self {
            root: fuigo_home.join("subscriptions"),
        }
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
        #[cfg(unix)]
        File::open(&self.root)
            .and_then(|f| f.sync_all())
            .map_err(|_| SubscriptionError::Storage)?;
        Ok(())
    }
    pub(super) async fn save(&self, credential: Credential) -> Result<()> {
        credential.validate(credential.provider, &credential.account)?;
        credential.access()?;
        let _lock = self.lock().await?;
        let mut records = self.read()?;
        let entry = records.entry(credential.provider).or_default();
        entry.selected = Some(credential.account.clone());
        entry
            .accounts
            .insert(credential.account.clone(), credential);
        self.write(&records)
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
    /// Omitted account removes only this provider; named logout preserves siblings.
    pub async fn logout(
        &self,
        provider: SubscriptionProvider,
        account: Option<&str>,
    ) -> Result<()> {
        if !self.root.exists() {
            return Ok(());
        }
        let _lock = self.lock().await?;
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
        .map_err(|_| SubscriptionError::Network)?
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
        let mut next = client.refresh(&refresh).await?;
        if next.account != current.account {
            return Err(SubscriptionError::InvalidCredentials);
        }
        if next.refresh_token.is_none() {
            next.refresh_token = Some(refresh);
        }
        records
            .get_mut(&provider)
            .unwrap()
            .accounts
            .insert(account, next.clone());
        self.write(&records)?; // No non-atomic fallback and no success on write failure.
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
