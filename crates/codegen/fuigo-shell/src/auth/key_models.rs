//! What a provider API key can run.
//!
//! A key found in the environment is a connection, and a connection's models should be
//! listed with no setup. After a key is seen, Fuigo asks that provider's standard `GET {base_url}/models`
//! endpoint, caches the model IDs (IDs only, never the key) under `~/.fuigo/provider-keys/`, and the
//! resolved catalogue then carries one entry per model, routed with the key's variable NAME (the secret
//! stays in the environment). Those entries join the de-duplicated ranked list: a model that a key
//! reaches and Flux Router also serves is one row, with Flux Router first.
//!
//! The list is fetched at most once a day per provider, in the background, and on `fuigo login
//! --provider <id>`. A failure keeps whatever list was cached. Nothing is sent without a key, and a
//! destination the egress guard denies (the xAI API host) is skipped, never forced.
use crate::agent::config::{ConfigModelOverride, EnvKeys};
use crate::agent::key_discovery::{self, Provider};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A cache older than this is refreshed.
pub const STALE_SECS: u64 = 24 * 60 * 60;
/// A hostile or broken `/models` answer cannot grow memory or the cache.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Serialize, Deserialize)]
struct Cache {
    fetched_at: u64,
    ids: Vec<String>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn cache_path(home: &Path, provider_id: &str) -> PathBuf {
    home.join("provider-keys")
        .join(format!("models-{provider_id}.json"))
}

/// Cached model IDs for a provider, in the order the provider listed them (newest first where it says).
pub fn cached_model_ids(home: &Path, provider_id: &str) -> Vec<String> {
    let Ok(bytes) = std::fs::read(cache_path(home, provider_id)) else {
        return Vec::new();
    };
    if bytes.len() > 1024 * 1024 {
        return Vec::new();
    }
    serde_json::from_slice::<Cache>(&bytes)
        .map(|c| crate::auth::subscription::catalog::sanitize_ids(c.ids))
        .unwrap_or_default()
}

pub fn write_cached_model_ids(home: &Path, provider_id: &str, ids: &[String]) -> std::io::Result<()> {
    let path = cache_path(home, provider_id);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let body = serde_json::to_string(&Cache {
        fetched_at: now(),
        ids: crate::auth::subscription::catalog::sanitize_ids(ids.iter().cloned()),
    })
    .map_err(std::io::Error::other)?;
    fuigo_config::fs_atomic::write_atomically(&path, &body, Some(0o600))
}

pub fn cache_is_stale(home: &Path, provider_id: &str) -> bool {
    let Ok(bytes) = std::fs::read(cache_path(home, provider_id)) else {
        return true;
    };
    serde_json::from_slice::<Cache>(&bytes)
        .map(|c| now().saturating_sub(c.fetched_at) > STALE_SECS)
        .unwrap_or(true)
}

/// A model that cannot hold a chat is not offered: embeddings, speech, image and moderation models.
fn is_chat_model(id: &str) -> bool {
    let id = id.to_ascii_lowercase();
    ![
        "embed", "whisper", "tts", "dall-e", "moderation", "transcribe", "realtime", "audio",
        "image", "davinci", "babbage", "rerank",
    ]
    .iter()
    .any(|bad| id.contains(bad))
}

/// The model IDs in a provider `/models` body: `{"data": [{"id": ..., "created": ...}]}`. Newest
/// first when the provider gives creation times, otherwise in its own order. A leading `models/`
/// (the Gemini spelling) is dropped.
pub fn parse_model_ids(body: &serde_json::Value) -> Vec<String> {
    let Some(list) = body.get("data").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut rows: Vec<(String, Option<i64>)> = list
        .iter()
        .filter_map(|item| {
            let id = item.get("id")?.as_str()?;
            let id = id.strip_prefix("models/").unwrap_or(id);
            let created = item.get("created").and_then(|c| c.as_i64());
            Some((id.to_owned(), created))
        })
        .filter(|(id, _)| is_chat_model(id))
        .collect();
    // Stable: ids without a creation time keep the provider's order.
    if rows.iter().any(|(_, c)| c.is_some()) {
        rows.sort_by_key(|(_, c)| std::cmp::Reverse(c.unwrap_or(i64::MIN)));
    }
    crate::auth::subscription::catalog::sanitize_ids(rows.into_iter().map(|(id, _)| id))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    /// The egress guard does not allow this destination.
    Blocked,
    Transport,
    Status(u16),
    BadBody,
}

/// `GET {base_url}/models` with the provider's own credential scheme. The key is used for this one
/// request and is not logged.
pub async fn fetch_model_ids(
    provider: &Provider,
    base_url: &str,
    key: &str,
) -> Result<Vec<String>, FetchError> {
    use fuigo_extra_ca::dispatch::{AsyncRequestBuilderExt as _, DispatchError};
    let url = format!("{}/models", base_url.trim().trim_end_matches('/'));
    let mut request = crate::http::shared_client().get(&url).timeout(TIMEOUT);
    request = if provider.auth_scheme == "x_api_key" {
        request.header("x-api-key", key)
    } else {
        request.bearer_auth(key)
    };
    for (name, value) in provider.extra_headers {
        request = request.header(*name, *value);
    }
    if provider.id == "anthropic" {
        request = request.query(&[("limit", "1000")]);
    }
    let response = request.send_checked().await.map_err(|e| match e {
        DispatchError::Denied(_) => FetchError::Blocked,
        DispatchError::Transport(_) => FetchError::Transport,
    })?;
    let status = response.status();
    if !status.is_success() {
        return Err(FetchError::Status(status.as_u16()));
    }
    let bytes = response.bytes().await.map_err(|_| FetchError::Transport)?;
    if bytes.len() > MAX_BODY_BYTES {
        return Err(FetchError::BadBody);
    }
    let body: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| FetchError::BadBody)?;
    let ids = parse_model_ids(&body);
    if ids.is_empty() {
        return Err(FetchError::BadBody);
    }
    Ok(ids)
}

/// Where this provider's models are asked for: its public API, or the `base_url` the user gave in
/// `[model_providers.<id>]` (a proxy, or a test server).
pub fn base_url_for(provider: &Provider, user_base_url: Option<&str>) -> String {
    user_base_url
        .filter(|u| !u.trim().is_empty())
        .unwrap_or(provider.base_url)
        .to_owned()
}

/// One provider refreshed: how many models were listed, or why not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refreshed {
    pub provider_id: &'static str,
    pub label: &'static str,
    pub result: Result<usize, FetchError>,
}

/// Refresh the model list of each provider whose key is found. `only` limits it to one provider;
/// `force` ignores the cache age. `base_url` maps a provider to the URL to ask. A provider that is
/// fresh, or has no key, is skipped (absent from the result).
pub async fn refresh(
    home: &Path,
    lookup: impl Fn(&str) -> Option<String>,
    only: Option<&str>,
    force: bool,
    base_url: impl Fn(&Provider) -> String,
) -> Vec<Refreshed> {
    let mut out = Vec::new();
    for found in key_discovery::discover_with(&lookup) {
        let p = found.provider;
        if p.applies_to_configured_endpoint || only.is_some_and(|id| id != p.id) {
            continue;
        }
        if !force && !cache_is_stale(home, p.id) {
            continue;
        }
        let result = match fetch_model_ids(p, &base_url(p), found.key()).await {
            Ok(ids) => write_cached_model_ids(home, p.id, &ids)
                .map(|()| ids.len())
                .map_err(|_| FetchError::BadBody),
            Err(e) => Err(e),
        };
        out.push(Refreshed {
            provider_id: p.id,
            label: p.label,
            result,
        });
    }
    out
}

/// Whether `FUIGO_DISABLE_MODEL_REFRESH` turns the background model-list fetches off: any
/// non-empty value except `0`. Shared with the subscription catalogue refresh so both fetches
/// read the switch the same way.
pub fn model_refresh_disabled(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|v| !v.is_empty() && v != "0")
}

/// Background refresh at startup: real environment, real home, the providers' own endpoints (or
/// the user's `[model_providers.<id>].base_url`). Returns whether any list changed. With
/// `FUIGO_DISABLE_MODEL_REFRESH` set it makes no request and the cache (or built-in list) stands.
pub async fn refresh_stale(user_base_urls: impl Fn(&str) -> Option<String>) -> bool {
    let Some(home) = fuigo_dirs::resolve_fuigo_home() else {
        return false;
    };
    let disabled = model_refresh_disabled(
        std::env::var_os("FUIGO_DISABLE_MODEL_REFRESH").as_deref(),
    );
    refresh_stale_in(
        Path::new(&home),
        |name| std::env::var(name).ok(),
        disabled,
        user_base_urls,
    )
    .await
}

/// `refresh_stale` with its home, environment and switch passed in.
async fn refresh_stale_in(
    home: &Path,
    lookup: impl Fn(&str) -> Option<String>,
    disabled: bool,
    user_base_urls: impl Fn(&str) -> Option<String>,
) -> bool {
    if disabled {
        return false;
    }
    refresh(home, lookup, None, false, |p| {
        base_url_for(p, user_base_urls(p.id).as_deref())
    })
    .await
    .iter()
    .any(|r| r.result.is_ok())
}

fn parse_serde<T: serde::de::DeserializeOwned>(spelling: &str) -> Option<T> {
    serde_json::from_value(serde_json::Value::String(spelling.to_owned())).ok()
}

/// `[model.<key>]` overrides for the models each found key reaches: keys `<provider>-key/<id>`.
/// Routed with the variable NAME (`env_key`), the provider's own wire protocol and credential scheme.
/// Local state only (the cache next to the credential store); an id the user already routes
/// through that provider by hand is not repeated. `user_models` is the user's own `[model.*]`.
pub fn model_overrides(
    home: &Path,
    lookup: impl Fn(&str) -> Option<String>,
    user_base_urls: impl Fn(&str) -> Option<String>,
    user_models: &indexmap::IndexMap<String, ConfigModelOverride>,
) -> Vec<(String, ConfigModelOverride)> {
    let mut out = Vec::new();
    for found in key_discovery::discover_with(&lookup) {
        let p = found.provider;
        if p.applies_to_configured_endpoint {
            continue;
        }
        let base = base_url_for(p, user_base_urls(p.id).as_deref());
        for id in cached_model_ids(home, p.id) {
            let by_hand = user_models.values().any(|m| {
                m.model.as_deref() == Some(id.as_str())
                    && (m.model_provider.as_deref() == Some(p.id)
                        || m.env_key.as_ref().and_then(|e| e.primary()) == Some(found.env_var))
            });
            if by_hand {
                continue;
            }
            out.push((
                format!("{}-key/{id}", p.id),
                ConfigModelOverride {
                    model: Some(id.clone()),
                    base_url: Some(base.clone()),
                    name: Some(format!("{id} ({} key)", p.label)),
                    env_key: Some(EnvKeys::single(found.env_var)),
                    api_backend: parse_serde(p.api_backend),
                    auth_scheme: parse_serde(p.auth_scheme),
                    extra_headers: p
                        .extra_headers
                        .iter()
                        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                        .collect(),
                    max_completion_tokens: p.max_completion_tokens,
                    ..Default::default()
                },
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, extract::State, http::HeaderMap, routing::get};
    use std::sync::{Arc, Mutex};

    const OPENAI_KEY: &str = "sk-test-openai-key-0123456789";
    const ANTHROPIC_KEY: &str = "sk-ant-test-key-0123456789";

    /// One recorded request: its path and its headers.
    type Request = (String, Vec<(String, String)>);

    #[derive(Clone, Default)]
    struct Seen(Arc<Mutex<Vec<Request>>>);

    /// A mock provider: records the path and headers of each request and answers `body`.
    async fn mock(body: serde_json::Value) -> (String, Seen) {
        let seen = Seen::default();
        let app = Router::new()
            .route(
                "/v1/models",
                get(
                    |State((seen, body)): State<(Seen, serde_json::Value)>, headers: HeaderMap| async move {
                        let hs = headers
                            .iter()
                            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_owned()))
                            .collect();
                        seen.0.lock().unwrap().push(("/v1/models".into(), hs));
                        axum::Json(body)
                    },
                ),
            )
            .with_state((seen.clone(), body));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}/v1"), seen)
    }

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| pairs.iter().find(|(k, _)| *k == name).map(|(_, v)| (*v).to_owned())
    }

    fn provider(id: &str) -> &'static Provider {
        key_discovery::PROVIDERS.iter().find(|p| p.id == id).unwrap()
    }

    #[test]
    fn the_models_body_keeps_chat_models_newest_first_and_drops_the_rest() {
        let body = serde_json::json!({ "data": [
            { "id": "gpt-4o", "created": 100 },
            { "id": "text-embedding-3-small", "created": 400 },
            { "id": "gpt-5", "created": 300 },
            { "id": "whisper-1", "created": 50 },
            { "id": "models/gemini-2.5-pro", "created": 200 },
            { "id": "bad id with spaces", "created": 999 },
        ]});
        assert_eq!(parse_model_ids(&body), ["gpt-5", "gemini-2.5-pro", "gpt-4o"]);
        // No creation times: the provider's own order stands.
        let plain = serde_json::json!({ "data": [{ "id": "b" }, { "id": "a" }] });
        assert_eq!(parse_model_ids(&plain), ["b", "a"]);
        assert!(parse_model_ids(&serde_json::json!({ "nope": 1 })).is_empty());
    }

    #[tokio::test]
    async fn a_key_lists_its_providers_models_from_the_mock_and_caches_ids_only() {
        let home = tempfile::tempdir().unwrap();
        let (base, seen) = mock(serde_json::json!({ "data": [
            { "id": "gpt-5", "created": 2 }, { "id": "gpt-4o", "created": 1 }
        ]})).await;
        let pairs = [("OPENAI_API_KEY", OPENAI_KEY)];
        let got = refresh(home.path(), env(&pairs), None, false, |_| base.clone()).await;
        assert_eq!(got.len(), 1, "only the provider whose key is set is asked: {got:?}");
        assert_eq!((got[0].provider_id, got[0].result), ("openai", Ok(2)));
        // The provider was asked once, with the bearer scheme.
        let seen = seen.0.lock().unwrap();
        assert_eq!(seen.len(), 1);
        let auth = seen[0].1.iter().find(|(k, _)| k == "authorization").map(|(_, v)| v.as_str());
        assert_eq!(auth, Some(format!("Bearer {OPENAI_KEY}").as_str()));
        // Cached IDs, and no secret anywhere in the cache.
        assert_eq!(cached_model_ids(home.path(), "openai"), ["gpt-5", "gpt-4o"]);
        let raw = std::fs::read_to_string(cache_path(home.path(), "openai")).unwrap();
        assert!(!raw.contains(OPENAI_KEY) && !raw.contains("sk-"), "{raw}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(cache_path(home.path(), "openai")).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "owner-only cache");
        }
    }

    #[tokio::test]
    async fn a_fresh_cache_is_not_asked_again_and_no_key_asks_nobody() {
        let home = tempfile::tempdir().unwrap();
        let (base, seen) = mock(serde_json::json!({ "data": [{ "id": "gpt-5" }] })).await;
        let pairs = [("OPENAI_API_KEY", OPENAI_KEY)];
        refresh(home.path(), env(&pairs), None, false, |_| base.clone()).await;
        let again = refresh(home.path(), env(&pairs), None, false, |_| base.clone()).await;
        assert!(again.is_empty(), "fresh cache: not asked again");
        assert_eq!(seen.0.lock().unwrap().len(), 1);
        // `force` (a login) asks again.
        let forced = refresh(home.path(), env(&pairs), Some("openai"), true, |_| base.clone()).await;
        assert_eq!(forced.len(), 1);
        assert_eq!(seen.0.lock().unwrap().len(), 2);
        // No key: nothing is sent.
        let other = tempfile::tempdir().unwrap();
        let none = refresh(other.path(), env(&[]), None, true, |_| base.clone()).await;
        assert!(none.is_empty());
        assert_eq!(seen.0.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn anthropic_is_asked_with_its_own_key_header_and_a_failure_keeps_the_cache() {
        let home = tempfile::tempdir().unwrap();
        write_cached_model_ids(home.path(), "anthropic", &["claude-old".to_owned()]).unwrap();
        let (base, seen) = mock(serde_json::json!({ "data": [{ "id": "claude-new" }] })).await;
        let pairs = [("ANTHROPIC_API_KEY", ANTHROPIC_KEY)];
        let got = refresh(home.path(), env(&pairs), Some("anthropic"), true, |_| base.clone()).await;
        assert_eq!(got[0].result, Ok(1));
        let headers = seen.0.lock().unwrap()[0].1.clone();
        let find = |n: &str| headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
        assert_eq!(find("x-api-key").as_deref(), Some(ANTHROPIC_KEY));
        assert!(find("anthropic-version").is_some());
        assert!(find("authorization").is_none(), "Anthropic does not take a bearer");
        // The server goes away: the refresh fails and the earlier list stands.
        let dead = "http://127.0.0.1:9/v1".to_owned();
        let failed = refresh(home.path(), env(&pairs), Some("anthropic"), true, |_| dead.clone()).await;
        assert!(failed[0].result.is_err());
        assert_eq!(cached_model_ids(home.path(), "anthropic"), ["claude-new"]);
    }

    #[test]
    fn listed_models_become_env_key_routes_without_the_secret_and_skip_hand_written_ones() {
        let home = tempfile::tempdir().unwrap();
        write_cached_model_ids(home.path(), "openai", &["gpt-5".into(), "gpt-4o".into()]).unwrap();
        write_cached_model_ids(home.path(), "anthropic", &["claude-x".into()]).unwrap();
        let pairs = [("OPENAI_API_KEY", OPENAI_KEY), ("ANTHROPIC_API_KEY", ANTHROPIC_KEY)];
        let mut mine = indexmap::IndexMap::new();
        mine.insert(
            "my-gpt-4o".to_owned(),
            ConfigModelOverride {
                model: Some("gpt-4o".into()),
                model_provider: Some("openai".into()),
                ..Default::default()
            },
        );
        let got = model_overrides(home.path(), env(&pairs), |_| None, &mine);
        let keys: Vec<&str> = got.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["anthropic-key/claude-x", "openai-key/gpt-5"], "hand-written gpt-4o is not repeated");
        let (_, openai) = got.iter().find(|(k, _)| k == "openai-key/gpt-5").unwrap();
        assert_eq!(openai.base_url.as_deref(), Some(provider("openai").base_url));
        assert_eq!(openai.env_key.as_ref().and_then(|e| e.primary()), Some("OPENAI_API_KEY"));
        assert_eq!(openai.name.as_deref(), Some("gpt-5 (OpenAI key)"));
        assert!(openai.api_key.is_none(), "the secret never enters the override");
        let (_, anthropic) = got.iter().find(|(k, _)| k == "anthropic-key/claude-x").unwrap();
        assert!(anthropic.api_backend.is_some() && anthropic.auth_scheme.is_some());
        assert!(anthropic.extra_headers.contains_key("anthropic-version"));
        // A user's [model_providers.openai].base_url wins; no key means no entries.
        let proxied = model_overrides(home.path(), env(&pairs), |id| (id == "openai").then(|| "http://proxy.test/v1".to_owned()), &Default::default());
        assert_eq!(proxied.iter().find(|(k, _)| k == "openai-key/gpt-5").unwrap().1.base_url.as_deref(), Some("http://proxy.test/v1"));
        assert!(model_overrides(home.path(), env(&[]), |_| None, &Default::default()).is_empty());
    }

    #[tokio::test]
    async fn the_disable_switch_stops_the_background_fetch_and_keeps_the_cache() {
        let home = tempfile::tempdir().unwrap();
        write_cached_model_ids(home.path(), "openai", &["cached-model".to_owned()]).unwrap();
        // Make the cache stale so only the switch can stop the request.
        let stale = now() - STALE_SECS - 10;
        let path = cache_path(home.path(), "openai");
        let mut raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        raw["fetched_at"] = stale.into();
        std::fs::write(&path, raw.to_string()).unwrap();
        assert!(cache_is_stale(home.path(), "openai"), "{raw}");
        let (base, seen) = mock(serde_json::json!({ "data": [{ "id": "gpt-5", "created": 1 }]})).await;
        let pairs = [("OPENAI_API_KEY", OPENAI_KEY)];
        let url = |_: &str| Some(base.clone());

        let changed = refresh_stale_in(home.path(), env(&pairs), true, url).await;
        assert!(!changed);
        assert!(seen.0.lock().unwrap().is_empty(), "switch on: no request");
        assert_eq!(cached_model_ids(home.path(), "openai"), ["cached-model"]);

        // Control: the same setup with the switch off does ask.
        let changed = refresh_stale_in(home.path(), env(&pairs), false, url).await;
        assert!(changed);
        assert_eq!(seen.0.lock().unwrap().len(), 1);
    }

    #[test]
    fn the_switch_reads_any_non_empty_value_but_zero() {
        use std::ffi::OsStr;
        assert!(!model_refresh_disabled(None));
        assert!(!model_refresh_disabled(Some(OsStr::new(""))));
        assert!(!model_refresh_disabled(Some(OsStr::new("0"))));
        assert!(model_refresh_disabled(Some(OsStr::new("1"))));
        assert!(model_refresh_disabled(Some(OsStr::new("true"))));
    }
}
