//! FLUX-TRAFFIC part C: the model-list 401 backoff survives a process restart.
//! Every "process" below is a fresh in-memory state (new `ModelsManager`) over the same on-disk memory file, with a
//! pinned wall clock and a loopback mock that counts requests. Nothing leaves 127.0.0.1.
use super::*;
use crate::auth::api_key_probe::probe_fuigo_api_key;
use crate::auth::api_key_route_memory::test_clock;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::Mutex as StdMutex;

const KEY: &str = "fuigo-test-not-a-key";
const T0: u64 = 1_800_000_000;

struct Mock {
    port: u16,
    log: Arc<StdMutex<Vec<String>>>,
    models_status: Arc<AtomicU16>,
    stop: Arc<AtomicBool>,
}
impl Mock {
    fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let log = Arc::new(StdMutex::new(Vec::new()));
        let models_status = Arc::new(AtomicU16::new(401));
        let stop = Arc::new(AtomicBool::new(false));
        let (l, m, s) = (log.clone(), models_status.clone(), stop.clone());
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                if s.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(mut c) = conn else { continue };
                use std::io::{Read, Write};
                let mut buf = [0u8; 4096];
                let n = c.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let mut it = head.lines().next().unwrap_or("").split(' ');
                let (method, path) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
                l.lock().unwrap().push(format!("{method} {path}"));
                let (status, body) = match path {
                    "/v1/models" if m.load(Ordering::SeqCst) == 200 => ("200 OK", r#"{"data":[]}"#),
                    "/v1/models" | "/key/info" => ("401 Unauthorized", r#"{"error":"bad key"}"#),
                    _ => ("404 Not Found", "{}"),
                };
                let _ = c.write_all(
                    format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                        .as_bytes(),
                );
            }
        });
        Self { port, log, models_status, stop }
    }
    fn base(&self) -> String {
        format!("http://127.0.0.1:{}/v1", self.port)
    }
    fn count(&self, path: &str) -> usize {
        self.log.lock().unwrap().iter().filter(|l| l.ends_with(path) && l.starts_with("GET")).count()
    }
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

struct World {
    _home: tempfile::TempDir,
    _env: [EnvGuard; 3],
    mock: Mock,
}
impl World {
    fn new() -> Self {
        let home = tempfile::TempDir::new().unwrap();
        let env = [
            EnvGuard::set("FUIGO_HOME", home.path()),
            EnvGuard::set("FUIGO_API_KEY", KEY),
            EnvGuard::unset("FUIGO_CODE_API_KEY"),
        ];
        test_clock::NOW.store(T0, Ordering::SeqCst);
        test_clock::PROBE_MEMORY_OFF.store(false, Ordering::SeqCst);
        test_clock::MODELS_MEMORY_OFF.store(false, Ordering::SeqCst);
        Self { _home: home, _env: env, mock: Mock::start() }
    }
    fn file(&self) -> std::path::PathBuf {
        fuigo_dirs::fuigo_home().join("api-key-probe-state.json")
    }
    fn at(&self, secs: u64) {
        test_clock::NOW.store(T0 + secs, Ordering::SeqCst);
    }
    fn entries(&self) -> Vec<serde_json::Value> {
        let Ok(b) = std::fs::read(self.file()) else { return vec![] };
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap_or_default();
        v["models_401"].as_array().cloned().unwrap_or_default()
    }
    /// What a Fuigo start sends in its first second: the key probe, the startup model-list fetch, and the first rung
    /// of the catalog ladder (a fresh manager, so a fresh in-memory gate).
    async fn start_process(&self, probe: bool) {
        let base = self.mock.base();
        if probe {
            probe_fuigo_api_key(KEY, &base, std::time::Duration::from_secs(5)).await;
        }
        let mut cfg = config::Config::default();
        cfg.endpoints.fuigo_api_base_url = base;
        let eps = cfg.endpoints.clone();
        let fa = ModelFetchAuth::resolve(&eps, false);
        let _ = tokio::task::spawn_blocking(move || prefetch_models_blocking(&eps, None, fa)).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let auth_manager = Arc::new(AuthManager::new(tmp.path(), FuigoComConfig::default()));
        let mgr = ModelsManagerBuilder::new(None, IndexMap::new(), acp::ModelId::new("default"), auth_manager, cfg)
            .cache(test_cache_manager(tmp.path()))
            .build();
        mgr.fetch_and_apply_inner(true).await;
    }
}

const WAITS_MIN: [u64; 7] = [1, 2, 4, 8, 16, 30, 30];

#[tokio::test]
#[serial]
async fn a_new_process_inside_the_wait_sends_nothing_and_the_table_climbs() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = World::new();
    let mut t = 0u64;
    for (i, wait) in WAITS_MIN.iter().enumerate() {
        let before = w.mock.count("/v1/models");
        w.at(t);
        w.start_process(false).await;
        assert_eq!(w.mock.count("/v1/models") - before, 1, "attempt {i}: one request per start that is due");
        let e = w.entries();
        assert_eq!(e.len(), 1, "attempt {i}: one entry");
        assert_eq!(e[0]["n"].as_u64(), Some(i as u64 + 1), "attempt {i}: count");
        let before = w.mock.count("/v1/models");
        w.at(t + wait * 60 - 1);
        w.start_process(false).await;
        assert_eq!(w.mock.count("/v1/models"), before, "attempt {i}: a start inside the wait sends nothing");
        t += wait * 60 + 1;
    }
}

#[tokio::test]
#[serial]
async fn ten_seconds_later_a_new_process_sends_zero_and_sixty_one_seconds_later_one() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = World::new();
    w.start_process(false).await;
    assert_eq!(w.mock.count("/v1/models"), 1);
    w.at(10);
    w.start_process(false).await;
    assert_eq!(w.mock.count("/v1/models"), 1, "10 s later: nothing");
    w.at(61);
    w.start_process(false).await;
    assert_eq!(w.mock.count("/v1/models"), 2, "61 s later: one");
    assert_eq!(w.entries()[0]["n"].as_u64(), Some(2));
}

#[tokio::test]
#[serial]
async fn a_200_removes_the_entry_and_the_next_process_fetches_at_once() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = World::new();
    w.start_process(false).await;
    assert_eq!(w.entries().len(), 1);
    w.mock.models_status.store(200, Ordering::SeqCst);
    w.at(61);
    w.start_process(false).await;
    assert!(w.entries().is_empty(), "a 200 clears the memory");
    let n = w.mock.count("/v1/models");
    w.at(62);
    w.start_process(false).await;
    assert!(w.mock.count("/v1/models") > n, "no wait after a 200");
}

#[tokio::test]
#[serial]
async fn a_different_credential_fetches_at_once() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = World::new();
    w.start_process(false).await;
    let n = w.mock.count("/v1/models");
    w.at(5);
    let _other = EnvGuard::set("FUIGO_API_KEY", "fuigo-test-not-a-key-2");
    w.start_process(false).await;
    assert!(w.mock.count("/v1/models") > n, "another key has its own (empty) memory");
}

#[tokio::test]
#[serial]
async fn unreadable_future_dated_and_older_files_never_block() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = World::new();
    std::fs::write(w.file(), b"{ not json").unwrap();
    w.start_process(false).await;
    assert_eq!(w.mock.count("/v1/models"), 1, "a corrupt file is no memory");
    assert_eq!(w.entries().len(), 1, "and it is overwritten with a valid file");
    // A file written by part A alone (no models_401 field) parses and keeps its lists.
    std::fs::write(w.file(), br#"{"unsupported":[{"h":"aa","t":1800000001}],"verdicts":[]}"#).unwrap();
    w.at(1);
    w.start_process(false).await;
    assert_eq!(w.mock.count("/v1/models"), 2);
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(w.file()).unwrap()).unwrap();
    assert_eq!(v["models_401"].as_array().unwrap().len(), 1);
    // Clock set backwards: the entry looks future-dated and is ignored (fetch).
    w.at(0);
    let before = w.mock.count("/v1/models");
    w.start_process(false).await;
    assert_eq!(w.mock.count("/v1/models") - before, 1, "a future-dated entry is ignored");
    // Oversized file: no memory.
    std::fs::write(w.file(), vec![b' '; 70 * 1024]).unwrap();
    let before = w.mock.count("/v1/models");
    w.start_process(false).await;
    assert_eq!(w.mock.count("/v1/models") - before, 1);
}

#[tokio::test]
#[serial]
async fn the_file_holds_no_key_no_url_and_no_response_data() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = World::new();
    w.start_process(true).await;
    let bytes = std::fs::read(w.file()).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    for bad in [KEY, "127.0.0.1", "http", "bad key", &w.mock.port.to_string()] {
        assert!(!text.contains(bad), "the memory file must not contain {bad:?}");
    }
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let e = &v["models_401"][0];
    assert_eq!(e["h"].as_str().map(str::len), Some(64));
    assert!(e["n"].is_u64() && e["t"].is_u64());
}

/// The reported shape: a start every 65 s for 60 simulated minutes (56 starts) against a mock that answers
/// `/v1/models` with 401 and `/api-key` with 404. Totals per path for three configurations.
#[tokio::test]
#[serial]
async fn fifty_six_starts_in_an_hour_before_and_after() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let mut rows = Vec::new();
    for (name, probe_off, models_off) in [("BEFORE (no memory)", true, true), ("A+B (no disk backoff)", false, true), ("A+B+C", false, false)] {
        let w = World::new();
        test_clock::PROBE_MEMORY_OFF.store(probe_off, Ordering::SeqCst);
        test_clock::MODELS_MEMORY_OFF.store(models_off, Ordering::SeqCst);
        for k in 0..56u64 {
            w.at(k * 65);
            w.start_process(true).await;
        }
        let (p, m) = (w.mock.count("/v1/api-key"), w.mock.count("/v1/models"));
        eprintln!("SIM60 {name}: /v1/api-key={p} /v1/models={m} total={}", w.mock.log.lock().unwrap().len());
        rows.push((p, m));
    }
    assert_eq!(rows[0], (56, 112), "before: a probe and two model requests per start");
    assert_eq!(rows[1], (1, 112), "A+B: the probe is remembered, every start still fetches twice");
    assert_eq!(rows[2], (1, 6), "A+B+C: one attempt each time the wait expires (starts 0,1,3,7,15,30)");
}

/// An auth command that returns a NEW rejected token every call must not restart the fast loop: 56 starts, 65 s apart,
/// each with a different rejected key. The first three go through at once, then the URL-level table applies.
#[tokio::test]
#[serial]
async fn a_flapping_credential_is_capped_by_the_url_level_table() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = World::new();
    let mut first_three = 0;
    for k in 0..56u64 {
        w.at(k * 65);
        let _key = EnvGuard::set("FUIGO_API_KEY", format!("fuigo-test-not-a-key-{k}"));
        let before = w.mock.count("/v1/models");
        w.start_process(false).await;
        if k < 3 {
            first_three += w.mock.count("/v1/models") - before;
        }
    }
    let total = w.mock.count("/v1/models");
    eprintln!("FLAP60: 56 starts with 56 different rejected keys -> {total} /v1/models requests");
    assert_eq!(first_three, 3, "a credential never seen before fetches at once while the URL count is below 3");
    // 3 free; then URL counts 3.. give waits 1, 2, 4, 8, 16, 30 min: starts at 195, 325+, ...
    assert_eq!(total, 8, "starts 0,1,2 free, then 3,5,9,17,32 on the URL table");
}

/// A successful sign-in clears the URL-level run and every credential's run: the next fetch happens at once.
#[tokio::test]
#[serial]
async fn a_successful_sign_in_clears_the_url_level_entry() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = World::new();
    for k in 0..4u64 {
        w.at(k * 130);
        let _key = EnvGuard::set("FUIGO_API_KEY", format!("fuigo-test-not-a-key-{k}"));
        w.start_process(false).await;
    }
    let n = w.mock.count("/v1/models");
    w.at(3 * 130 + 60);
    let _key = EnvGuard::set("FUIGO_API_KEY", "fuigo-test-not-a-key-new");
    w.start_process(false).await;
    assert_eq!(w.mock.count("/v1/models"), n, "the URL-level wait holds a new unseen token");
    crate::auth::api_key_route_memory::RouteMemory::models_location()
        .unwrap()
        .clear_all_models_401(crate::auth::api_key_route_memory::unix_now());
    w.start_process(false).await;
    assert_eq!(w.mock.count("/v1/models"), n + 1, "after a sign-in the next fetch is at once");
    assert!(w.entries().len() <= 1);
}

/// Only a network 200 lifts a wait: a fresh disk catalog neither clears it nor extends it.
#[tokio::test(start_paused = true)]
#[serial]
async fn a_cache_hit_does_not_clear_the_wait() {
    
    let _api_key = api_key_env_unset();
    let (mgr, calls) = cached_after_reject_manager();
    mgr.fetch_and_apply_inner(true).await;
    assert_eq!(mgr.inner.auth_gate.lock().rejections, 1);
    tokio::time::sleep(std::time::Duration::from_secs(61)).await;
    mgr.fetch_and_apply_inner(true).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(mgr.inner.auth_gate.lock().rejections, 1, "a cache hit leaves the rejection run alone");
}

/// First answer 401, every later one a fresh-cache hit.
struct RejectThenCached(Arc<std::sync::atomic::AtomicUsize>);
impl ModelsEndpoint for RejectThenCached {
    fn fetch_models(&self, _e: config::EndpointsConfig, _a: Option<FuigoAuth>, _f: ModelFetchAuth) -> ModelsFetchFuture {
        Box::pin(async { None })
    }
    fn fetch_models_outcome(&self, _e: config::EndpointsConfig, _a: Option<FuigoAuth>, _f: ModelFetchAuth) -> ModelsOutcomeFuture {
        let n = self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if n == 0 { ModelsFetchOutcome::AuthRejected } else { ModelsFetchOutcome::Cached(IndexMap::new()) }
        })
    }
}
fn cached_after_reject_manager() -> (ModelsManager, Arc<std::sync::atomic::AtomicUsize>) {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let tmp = tempfile::TempDir::new().unwrap();
    let auth_manager = Arc::new(AuthManager::new(tmp.path(), FuigoComConfig::default()));
    let mgr = ModelsManagerBuilder::new(None, IndexMap::new(), acp::ModelId::new("default"), auth_manager, config::Config::default())
        .endpoint(Arc::new(RejectThenCached(calls.clone())))
        .cache(test_cache_manager(tmp.path()))
        .build();
    (mgr, calls)
}

// ---- Follow-up D, item 1: a different credential arriving through the auth-changed path lifts the URL wait ----

struct NoNet;
impl ModelsEndpoint for NoNet {
    fn fetch_models(&self, _e: config::EndpointsConfig, _a: Option<FuigoAuth>, _f: ModelFetchAuth) -> ModelsFetchFuture {
        Box::pin(async { None })
    }
    fn fetch_models_outcome(&self, _e: config::EndpointsConfig, _a: Option<FuigoAuth>, _f: ModelFetchAuth) -> ModelsOutcomeFuture {
        Box::pin(async { ModelsFetchOutcome::Unavailable })
    }
}

impl World {
    /// Three starts with three different rejected keys: the URL-level count is 3 and its wait is running at +140 s.
    async fn url_wait_running(&self) {
        for k in 0..3u64 {
            self.at(k * 65);
            let _key = EnvGuard::set("FUIGO_API_KEY", format!("fuigo-test-not-a-key-{k}"));
            self.start_process(false).await;
        }
        self.at(140);
    }
    fn url_entries(&self) -> usize {
        let Ok(b) = std::fs::read(self.file()) else { return 0 };
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap_or_default();
        v["models_401_url"].as_array().map_or(0, |a| a.len())
    }
    /// A manager whose in-memory credential baseline is `first_token` (a session token, or none), on the mock.
    fn manager(&self, first_token: Option<&str>) -> (ModelsManager, Arc<AuthManager>) {
        let tmp = tempfile::TempDir::new().unwrap();
        let auth_manager = Arc::new(AuthManager::new(tmp.path(), FuigoComConfig::default()));
        if let Some(t) = first_token {
            auth_manager.hot_swap(FuigoAuth { key: t.to_owned(), ..FuigoAuth::test_default() });
        }
        let mut cfg = config::Config::default();
        cfg.endpoints.fuigo_api_base_url = self.mock.base();
        let mgr = ModelsManagerBuilder::new(None, IndexMap::new(), acp::ModelId::new("default"), auth_manager.clone(), cfg)
            .endpoint(Arc::new(NoNet))
            .cache(test_cache_manager(tmp.path()))
            .build();
        std::mem::forget(tmp);
        (mgr, auth_manager)
    }
}

/// (i) `fuigo login` in another window: the watcher hot-swaps a NEW token and calls `on_auth_changed`.
#[tokio::test]
#[serial]
async fn an_auth_file_change_to_a_new_credential_clears_the_url_wait() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = World::new();
    w.url_wait_running().await;
    let (mgr, am) = w.manager(Some("fuigo-test-not-a-token-old"));
    assert_eq!(w.url_entries(), 1, "precondition: the URL-level entry exists");
    let n = w.mock.count("/v1/models");
    w.start_process(false).await;
    assert_eq!(w.mock.count("/v1/models"), n, "precondition: the URL wait holds");
    am.hot_swap(FuigoAuth { key: "fuigo-test-not-a-token-new".into(), ..FuigoAuth::test_default() });
    mgr.on_auth_changed().await;
    assert_eq!(w.url_entries(), 0, "a new credential is a sign-in: the URL entry is gone");
    w.start_process(false).await;
    assert_eq!(w.mock.count("/v1/models"), n + 1, "the next background fetch happens at once");
}

/// (ii) The watcher also fires for unrelated rewrites of `auth.json`: the SAME credential must not clear the wait.
#[tokio::test]
#[serial]
async fn an_auth_file_touch_with_the_same_credential_keeps_the_url_wait() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = World::new();
    w.url_wait_running().await;
    let (mgr, am) = w.manager(Some("fuigo-test-not-a-token-old"));
    am.hot_swap(FuigoAuth { key: "fuigo-test-not-a-token-old".into(), ..FuigoAuth::test_default() });
    mgr.on_auth_changed().await;
    mgr.on_auth_changed().await;
    assert_eq!(w.url_entries(), 1, "the same credential does not clear the URL entry");
    let n = w.mock.count("/v1/models");
    w.start_process(false).await;
    assert_eq!(w.mock.count("/v1/models"), n, "and the wait still holds");
}

/// (iii) The subscription-unblock refresh swaps in the re-issued token, then calls `on_auth_changed`; same rule.
#[tokio::test]
#[serial]
async fn the_subscription_unblock_refresh_clears_the_wait_only_for_a_new_token() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = World::new();
    w.url_wait_running().await;
    let (mgr, am) = w.manager(Some("fuigo-test-not-a-token-old"));
    mgr.on_auth_changed().await;
    assert_eq!(w.url_entries(), 1, "refresh gave back the same token: still waiting");
    am.hot_swap(FuigoAuth { key: "fuigo-test-not-a-token-reissued".into(), ..FuigoAuth::test_default() });
    mgr.on_auth_changed().await;
    assert_eq!(w.url_entries(), 0, "a re-issued token is a new credential: cleared");
}

/// Signing out (no credential left) is not a sign-in.
#[tokio::test]
#[serial]
async fn signing_out_does_not_clear_the_url_wait() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = World::new();
    w.url_wait_running().await;
    let (mgr, am) = w.manager(Some("fuigo-test-not-a-token-old"));
    am.clear_in_memory();
    mgr.on_auth_changed().await;
    assert_eq!(w.url_entries(), 1);
}
