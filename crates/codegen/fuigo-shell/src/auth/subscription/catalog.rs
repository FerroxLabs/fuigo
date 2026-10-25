//! What a signed-in subscription can run: the cached model list and the shared
//! "who is signed in" read that `/model`, `/provider`, `/login`, the welcome screen
//! and `fuigo login --status` all use.
//!
//! The cache holds model IDs only, never a credential. It is written atomically with
//! owner-only permissions beside the credential store and refreshed from the provider's
//! own model endpoint (the exact-recipient client in `inference`).
// CLI printer: stdout goes through `fuigo_tty_utils::cli_println!`.
#![deny(clippy::print_stdout)]
use super::*;

/// A cache older than this is refreshed in the background.
pub const CATALOG_STALE_SECS: u64 = 24 * 60 * 60;
/// Most IDs kept per provider; a hostile or broken response cannot grow the cache or the picker.
const MAX_MODEL_IDS: usize = 200;

#[derive(Serialize, Deserialize)]
struct Cache {
    fetched_at: u64,
    ids: Vec<String>,
}

impl SubscriptionProvider {
    pub const ALL: [SubscriptionProvider; 2] = [Self::Chatgpt, Self::Xai];
    /// Human name used by every surface.
    pub fn label(self) -> &'static str {
        match self {
            Self::Chatgpt => "ChatGPT subscription",
            Self::Xai => "Grok subscription",
        }
    }
    /// The `/provider` spelling.
    pub fn provider_slug(self) -> &'static str {
        match self {
            Self::Chatgpt => "chatgpt-subscription",
            Self::Xai => "grok-subscription",
        }
    }
    pub fn from_provider_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.provider_slug() == slug)
    }
    /// The inference endpoint (an exact-recipient subscription endpoint).
    pub fn endpoint(self) -> &'static str {
        self.sampling_kind().base_url()
    }
    /// Catalogue key of one of this provider's models, e.g. `xai/grok-4`.
    pub fn model_key(self, id: &str) -> String {
        format!("{}/{}", self.name(), id)
    }
}

/// IDs are shown in menus and written into config keys, so only plain identifier text is kept.
pub fn sanitize_ids(ids: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for id in ids {
        let ok = !id.is_empty()
            && id.len() <= 128
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/'));
        if ok && !out.contains(&id) {
            out.push(id);
        }
        if out.len() >= MAX_MODEL_IDS {
            break;
        }
    }
    out
}

fn cache_path(home: &Path, provider: SubscriptionProvider) -> std::path::PathBuf {
    home.join("subscriptions")
        .join(format!("models-{}.json", provider.name()))
}

/// Cached model IDs in catalogue order (best first). Empty when never fetched.
pub fn cached_model_ids(home: &Path, provider: SubscriptionProvider) -> Vec<String> {
    let Ok(bytes) = std::fs::read(cache_path(home, provider)) else {
        return Vec::new();
    };
    if bytes.len() > 1024 * 1024 {
        return Vec::new();
    }
    serde_json::from_slice::<Cache>(&bytes)
        .map(|c| sanitize_ids(c.ids))
        .unwrap_or_default()
}

pub fn write_cached_model_ids(
    home: &Path,
    provider: SubscriptionProvider,
    ids: &[String],
) -> std::io::Result<()> {
    let path = cache_path(home, provider);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let body = serde_json::to_string(&Cache {
        fetched_at: now(),
        ids: sanitize_ids(ids.iter().cloned()),
    })
    .map_err(std::io::Error::other)?;
    fuigo_config::fs_atomic::write_atomically(&path, &body, Some(0o600))
}

pub fn catalog_is_stale(home: &Path, provider: SubscriptionProvider) -> bool {
    let Ok(bytes) = std::fs::read(cache_path(home, provider)) else {
        return true;
    };
    serde_json::from_slice::<Cache>(&bytes)
        .map(|c| now().saturating_sub(c.fetched_at) > CATALOG_STALE_SECS)
        .unwrap_or(true)
}

/// One signed-in subscription, as every surface sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedIn {
    pub provider: SubscriptionProvider,
    /// Account IDs (display-only), selected account first.
    pub accounts: Vec<String>,
    /// Model IDs, best first; empty until the first catalogue fetch lands.
    pub model_ids: Vec<String>,
}

/// Every subscription with a usable stored credential (`login_required == false`).
pub fn signed_in(home: &Path) -> Vec<SignedIn> {
    let store = SubscriptionStore::new(home);
    SubscriptionProvider::ALL
        .into_iter()
        .filter_map(|provider| {
            let mut live: Vec<_> = store
                .status_sync(provider)
                .into_iter()
                .filter(|s| !s.login_required)
                .collect();
            if live.is_empty() {
                return None;
            }
            live.sort_by_key(|s| !s.selected);
            Some(SignedIn {
                provider,
                accounts: live.into_iter().map(|s| s.account).collect(),
                model_ids: cached_model_ids(home, provider),
            })
        })
        .collect()
}

/// Fetch the live list and cache it. The only network call is the existing exact-recipient one.
pub async fn refresh_catalog(provider: SubscriptionProvider) -> Result<Vec<String>> {
    let ids = sanitize_ids(super::inference::model_ids(provider).await?);
    if ids.is_empty() {
        return Err(SubscriptionError::InvalidCredentials);
    }
    let home = fuigo_dirs::resolve_fuigo_home().ok_or(SubscriptionError::Storage)?;
    write_cached_model_ids(Path::new(&home), provider, &ids)
        .map_err(|_| SubscriptionError::Storage)?;
    Ok(ids)
}

/// Background refresh used at startup: refreshes only signed-in providers whose cache is stale.
/// Errors are dropped on purpose: the cached list keeps working and the next start tries again.
pub async fn refresh_stale_catalogs() {
    let Some(home) = fuigo_dirs::resolve_fuigo_home() else {
        return;
    };
    refresh_stale_catalogs_with(Path::new(&home), |provider| async move {
        super::inference::model_ids(provider).await
    })
    .await;
}

/// The refresh loop with the fetch injected: every signed-in provider whose cache is older than
/// [`CATALOG_STALE_SECS`] (or missing) is fetched and its cache rewritten. A failed or empty fetch
/// leaves the old cache alone. Returns how many caches were refreshed.
pub async fn refresh_stale_catalogs_with<F, Fut>(home: &Path, mut fetch: F) -> usize
where
    F: FnMut(SubscriptionProvider) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<String>>>,
{
    let mut refreshed = 0;
    for entry in signed_in(home) {
        if !catalog_is_stale(home, entry.provider) {
            continue;
        }
        let Ok(ids) = fetch(entry.provider).await else {
            continue;
        };
        let ids = sanitize_ids(ids);
        if !ids.is_empty() && write_cached_model_ids(home, entry.provider, &ids).is_ok() {
            refreshed += 1;
        }
    }
    refreshed
}

/// Whether the startup refresh may run. The only endpoints are the providers' own
/// exact-recipient ones, so there is no mock endpoint to point a test at: debug builds (every
/// `cargo test` binary) never refresh, and `FUIGO_DISABLE_MODEL_REFRESH` turns it off in release.
pub fn startup_refresh_allowed(debug_build: bool, disabled_by_env: bool) -> bool {
    !debug_build && !disabled_by_env
}

/// Start the stale-cache refresh in the background; never blocks, never in a debug build.
/// Call from inside the tokio runtime.
pub fn spawn_startup_refresh() {
    let disabled = crate::auth::key_models::model_refresh_disabled(
        std::env::var_os("FUIGO_DISABLE_MODEL_REFRESH").as_deref(),
    );
    if startup_refresh_allowed(cfg!(debug_assertions), disabled) {
        tokio::spawn(refresh_stale_catalogs());
    }
}

/// Test fixture: a stored credential (fake tokens) plus a cached model list, as a finished
/// sign-in leaves them. No network, no real account.
#[cfg(test)]
pub(crate) async fn test_sign_in(
    home: &Path,
    provider: SubscriptionProvider,
    account: &str,
    ids: &[&str],
) {
    let credential = Credential {
        provider,
        issuer: provider.issuer().into(),
        client_id: provider.client_id().into(),
        account: account.into(),
        access_token: "fake-access-token".into(),
        refresh_token: Some("fake-refresh-token".into()),
        expires_at: now() + 3600,
        refresh_pending: false,
    };
    SubscriptionStore::new(home)
        .save(credential)
        .await
        .expect("fixture credential saved");
    let ids: Vec<String> = ids.iter().map(|s| (*s).to_owned()).collect();
    write_cached_model_ids(home, provider, &ids).expect("fixture cache written");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_sanitised_deduped_and_bounded() {
        let ids = sanitize_ids(
            ["grok-4", "grok-4", "bad id", "", "gpt-5.1-codex", "x\u{1b}[31m"]
                .map(String::from),
        );
        assert_eq!(ids, vec!["grok-4", "gpt-5.1-codex"]);
        let many = sanitize_ids((0..500).map(|i| format!("m{i}")));
        assert_eq!(many.len(), MAX_MODEL_IDS);
    }

    #[tokio::test]
    async fn cache_round_trips_owner_only_and_never_holds_a_credential() {
        let dir = tempfile::tempdir().unwrap();
        test_sign_in(dir.path(), SubscriptionProvider::Xai, "acct-1", &["grok-4", "grok-3"]).await;
        assert_eq!(
            cached_model_ids(dir.path(), SubscriptionProvider::Xai),
            vec!["grok-4", "grok-3"]
        );
        let raw = std::fs::read_to_string(cache_path(dir.path(), SubscriptionProvider::Xai)).unwrap();
        assert!(!raw.contains("fake-access-token") && !raw.contains("fake-refresh-token"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(cache_path(dir.path(), SubscriptionProvider::Xai))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "cache must be owner-only, got {mode:o}");
        }
        assert!(!catalog_is_stale(dir.path(), SubscriptionProvider::Xai));
        assert!(catalog_is_stale(dir.path(), SubscriptionProvider::Chatgpt));
    }

    /// The cache lives only as long as the sign-in it belongs to.
    #[tokio::test]
    async fn logging_out_drops_the_cached_model_list() {
        let dir = tempfile::tempdir().unwrap();
        test_sign_in(dir.path(), SubscriptionProvider::Xai, "a", &["grok-4"]).await;
        test_sign_in(dir.path(), SubscriptionProvider::Chatgpt, "b", &["gpt-5"]).await;
        let store = SubscriptionStore::new(dir.path());
        store.logout(SubscriptionProvider::Xai, None).await.unwrap();
        assert!(cached_model_ids(dir.path(), SubscriptionProvider::Xai).is_empty());
        assert_eq!(cached_model_ids(dir.path(), SubscriptionProvider::Chatgpt), vec!["gpt-5"]);
        assert!(signed_in(dir.path()).iter().all(|s| s.provider == SubscriptionProvider::Chatgpt));
        store.logout_all().await.unwrap();
        assert!(cached_model_ids(dir.path(), SubscriptionProvider::Chatgpt).is_empty());
        assert!(signed_in(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn signed_in_lists_only_providers_with_a_credential() {
        let dir = tempfile::tempdir().unwrap();
        assert!(signed_in(dir.path()).is_empty());
        test_sign_in(dir.path(), SubscriptionProvider::Xai, "acct-1", &["grok-4"]).await;
        let found = signed_in(dir.path());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].provider, SubscriptionProvider::Xai);
        assert_eq!(found[0].accounts, vec!["acct-1"]);
        assert_eq!(found[0].model_ids, vec!["grok-4"]);
    }

    fn write_aged(home: &Path, provider: SubscriptionProvider, age: u64, ids: &[&str]) {
        let path = cache_path(home, provider);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let body = serde_json::to_string(&Cache {
            fetched_at: now() - age,
            ids: ids.iter().map(|s| (*s).to_owned()).collect(),
        })
        .unwrap();
        std::fs::write(path, body).unwrap();
    }

    /// The stale-refresh has a caller's worth of behaviour: a cache over a day old is refetched
    /// and rewritten, a fresh one and a signed-out provider are left alone. The fetch is a mock;
    /// nothing is sent to xAI or OpenAI.
    #[tokio::test]
    async fn stale_catalogs_are_refreshed_and_fresh_ones_are_not() {
        let dir = tempfile::tempdir().unwrap();
        test_sign_in(dir.path(), SubscriptionProvider::Xai, "a", &["grok-old"]).await;
        test_sign_in(dir.path(), SubscriptionProvider::Chatgpt, "b", &["gpt-fresh"]).await;
        write_aged(dir.path(), SubscriptionProvider::Xai, CATALOG_STALE_SECS + 60, &["grok-old"]);
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = asked.clone();
        let n = refresh_stale_catalogs_with(dir.path(), move |p| {
            log.lock().unwrap().push(p);
            async move { Ok(vec!["grok-5".to_owned(), "grok-4".to_owned()]) }
        })
        .await;
        assert_eq!(n, 1);
        assert_eq!(*asked.lock().unwrap(), vec![SubscriptionProvider::Xai]);
        assert_eq!(cached_model_ids(dir.path(), SubscriptionProvider::Xai), vec!["grok-5", "grok-4"]);
        assert_eq!(cached_model_ids(dir.path(), SubscriptionProvider::Chatgpt), vec!["gpt-fresh"]);
        assert!(!catalog_is_stale(dir.path(), SubscriptionProvider::Xai));
    }

    #[tokio::test]
    async fn a_failed_refresh_keeps_the_old_cache() {
        let dir = tempfile::tempdir().unwrap();
        test_sign_in(dir.path(), SubscriptionProvider::Xai, "a", &["grok-old"]).await;
        write_aged(dir.path(), SubscriptionProvider::Xai, CATALOG_STALE_SECS + 60, &["grok-old"]);
        let n = refresh_stale_catalogs_with(dir.path(), |_| async { Err(SubscriptionError::Network) }).await;
        assert_eq!(n, 0);
        assert_eq!(cached_model_ids(dir.path(), SubscriptionProvider::Xai), vec!["grok-old"]);
    }

    #[tokio::test]
    async fn nothing_is_fetched_when_nobody_is_signed_in() {
        let dir = tempfile::tempdir().unwrap();
        let n = refresh_stale_catalogs_with(dir.path(), |_| async {
            panic!("no fetch without a sign-in")
        })
        .await;
        assert_eq!(n, 0);
    }

    #[test]
    fn startup_refresh_never_runs_in_a_debug_build_or_when_disabled() {
        assert!(!startup_refresh_allowed(true, false), "tests are debug builds");
        assert!(!startup_refresh_allowed(false, true));
        assert!(startup_refresh_allowed(false, false));
    }
}
