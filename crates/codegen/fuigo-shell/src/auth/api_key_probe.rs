//! Probes the first-party env key (`GET {fuigo_api_base_url}/api-key`) before `initialize` advertises `fuigo.api_key`.
//! BYOK keys are never probed.
//!
//! The base URL is the caller's effective `endpoints.fuigo_api_base_url`, so the probe hits the same host turn traffic uses.
//! That value comes from `FUIGO_API_BASE_URL` or `[endpoints] fuigo_api_base_url`.
//!
//! Unusable (an auth error, or a 200 with a blocked, disabled, or team_blocked flag) means the key is not advertised.
//! Unknown (a timeout, a network error, or exhausted retries) fails open and the key is still advertised.
//!
//! The probe retries once within the wall budget on 429, 5xx, or transport errors.
//! The default timeout is 400ms for the whole probe including retries; live round trips run about 250ms at p95.

use fuigo_extra_ca::dispatch::AsyncRequestBuilderExt as _;
use std::time::{Duration, Instant};

use serde::Deserialize;

/// Wall-clock budget for the entire probe, covering all attempts and backoff.
pub(crate) const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_millis(400);


/// Whether `initialize` should HTTP-probe the first-party env key.
///
/// Skip (and treat as usable) when:
/// - the kill switch is on: the key will not be advertised either way,
/// - BYOK is present: it is advertised without probing the first-party env key,
/// - no env key is set,
/// - `preferred_method` is pinned: OIDC never advertises the key, and ApiKey fails closed.
///   A false-negative probe under an ApiKey pin would empty `auth_methods` with no login method to fall back to.
pub(crate) fn should_probe_first_party_env_key(
    disable_api_key_auth: bool,
    has_byok: bool,
    has_env_key: bool,
    preferred_method_pinned: bool,
) -> bool {
    !disable_api_key_auth && !has_byok && has_env_key && !preferred_method_pinned
}

/// How many retries follow the initial attempt.
const MAX_RETRIES: u32 = 1;

/// Fixed backoff before the single retry.
const RETRY_BACKOFF: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApiKeyProbeVerdict {
    Usable,
    /// An auth error, or a 200 with a blocked, disabled, or team_blocked flag.
    Unusable,
    /// A timeout, a network error, or exhausted retries; the probe fails open.
    Unknown,
}

impl ApiKeyProbeVerdict {
    pub(crate) fn allows_advertise(self) -> bool {
        match self {
            Self::Usable | Self::Unknown => true,
            Self::Unusable => false,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ApiKeyInfoBody {
    #[serde(default)]
    api_key_blocked: bool,
    #[serde(default)]
    api_key_disabled: bool,
    #[serde(default)]
    team_blocked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttemptOutcome {
    Done(ApiKeyProbeVerdict),
    Retry,
}

/// Joins `/api-key` onto the base URL, dropping any trailing slash first.
fn api_key_info_url(api_base_url: &str) -> String {
    let base = api_base_url.trim().trim_end_matches('/');
    format!("{base}/api-key")
}

/// Classifies the status and body; kept pure so unit tests can call it directly.
fn classify_probe_attempt(status: u16, body: &[u8]) -> AttemptOutcome {
    match status {
        200 => match serde_json::from_slice::<ApiKeyInfoBody>(body) {
            Ok(info) if info.api_key_blocked || info.api_key_disabled || info.team_blocked => {
                AttemptOutcome::Done(ApiKeyProbeVerdict::Unusable)
            }
            // An unparseable 200 fails open in case the API response shape changed
            Ok(_) | Err(_) => AttemptOutcome::Done(ApiKeyProbeVerdict::Usable),
        },
        // Permanent client and auth failures are not retried
        400..=403 => AttemptOutcome::Done(ApiKeyProbeVerdict::Unusable),
        // Rate limiting and server errors are retried once
        429 => AttemptOutcome::Retry,
        s if (500..600).contains(&s) => AttemptOutcome::Retry,
        // Any other 4xx fails open (e.g. a 404 from test mocks that lack this route).
        _ => AttemptOutcome::Done(ApiKeyProbeVerdict::Unknown),
    }
}

/// The only field of the Flux `GET /key/info` answer that is read. Everything else in the body (`key`, the rest of `info`)
/// is ignored by the parser and never stored, logged or shown.
#[derive(Deserialize)]
struct KeyInfoBody {
    #[serde(default)]
    info: Option<KeyInfoFields>,
}

#[derive(Deserialize)]
struct KeyInfoFields {
    /// A missing or non-boolean value counts as not blocked.
    #[serde(default)]
    blocked: Option<serde_json::Value>,
}

/// Flux `GET /key/info`: 200 with `info.blocked == true` is Unusable, any other parseable 200 is Usable, 401 is Unusable;
/// 429 and 5xx retry once; every other status, and a 200 that does not parse, is Unknown (fails open).
fn classify_key_info_attempt(status: u16, body: &[u8]) -> AttemptOutcome {
    match status {
        200 => match serde_json::from_slice::<KeyInfoBody>(body) {
            Ok(b) if b.info.as_ref().and_then(|i| i.blocked.as_ref()) == Some(&serde_json::Value::Bool(true)) => {
                AttemptOutcome::Done(ApiKeyProbeVerdict::Unusable)
            }
            Ok(_) => AttemptOutcome::Done(ApiKeyProbeVerdict::Usable),
            Err(_) => AttemptOutcome::Done(ApiKeyProbeVerdict::Unknown),
        },
        401 => AttemptOutcome::Done(ApiKeyProbeVerdict::Unusable),
        429 => AttemptOutcome::Retry,
        s if (500..600).contains(&s) => AttemptOutcome::Retry,
        _ => AttemptOutcome::Done(ApiKeyProbeVerdict::Unknown),
    }
}

/// Terminal view of [`classify_probe_attempt`]; a retryable outcome becomes Unknown.
#[cfg(test)]
fn classify_probe_response(status: u16, body: &[u8]) -> ApiKeyProbeVerdict {
    match classify_probe_attempt(status, body) {
        AttemptOutcome::Done(v) => v,
        AttemptOutcome::Retry => ApiKeyProbeVerdict::Unknown,
    }
}

/// Fails open on a timeout or transport error after retries; the raw key is never logged.
///
/// `api_base_url` must be the endpoint the env key is actually sent to (`endpoints.fuigo_api_base_url`), not a hardcoded public default.
pub(crate) async fn probe_fuigo_api_key(
    key: &str,
    api_base_url: &str,
    timeout: Duration,
) -> ApiKeyProbeVerdict {
    probe_remembering(
        key,
        api_base_url,
        timeout,
        route_for_base(api_base_url),
        &super::api_key_route_memory::RouteMemory::default_location(),
        unix_now(),
    )
    .await
}

/// Which key-information route a base URL is probed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    /// `GET {base}/api-key` (inherited upstream route).
    ApiKey,
    /// `GET {origin}/key/info` (the Flux route: no `/v1` prefix).
    KeyInfo,
}

/// Host of the default API base (`FUIGO_API_BASE_URL_DEFAULT`, https://api.fluxrouter.ai/v1); a test pins the two together.
/// Matched exactly, never by suffix.
const FLUX_API_HOST: &str = "api.fluxrouter.ai";

/// True when `base` is an http(s) URL whose host is exactly [`FLUX_API_HOST`].
fn is_flux_base(base: &str) -> bool {
    url::Url::parse(base.trim())
        .is_ok_and(|u| matches!(u.scheme(), "http" | "https") && u.host_str() == Some(FLUX_API_HOST))
}

fn route_for_base(base: &str) -> Route {
    if is_flux_base(base) { Route::KeyInfo } else { Route::ApiKey }
}

/// The URL probed for `base` on `route`. The Flux route is `{scheme}://{host}[:port]/key/info`.
fn probe_url(base: &str, route: Route) -> String {
    match route {
        Route::ApiKey => api_key_info_url(base),
        Route::KeyInfo => match url::Url::parse(base.trim()) {
            Ok(u) => format!("{}/key/info", u.origin().ascii_serialization()),
            Err(_) => format!("{}/key/info", base.trim().trim_end_matches('/')),
        },
    }
}

use super::api_key_route_memory::unix_now;

/// The probe with its on-disk memory: skips a route known to be missing (24 h), reuses a Usable or Unusable verdict
/// for the same key (1 h), and otherwise asks once and remembers the answer. `now_secs` is injected so tests need no sleep.
async fn probe_remembering(
    key: &str,
    api_base_url: &str,
    timeout: Duration,
    route: Route,
    memory: &super::api_key_route_memory::RouteMemory,
    now_secs: u64,
) -> ApiKeyProbeVerdict {
    if key.trim().is_empty() {
        return ApiKeyProbeVerdict::Unusable;
    }
    let url = probe_url(api_base_url, route);
    if memory.unsupported(&url, now_secs) {
        return ApiKeyProbeVerdict::Unknown;
    }
    if let Some(v) = memory.verdict(&url, key, now_secs) {
        return v;
    }
    let out = probe_detailed(key, &url, timeout, route).await;
    if out.route_missing {
        memory.remember_unsupported(&url, now_secs);
    } else if out.cacheable {
        memory.store_verdict(&url, key, out.verdict, now_secs);
    }
    out.verdict
}

/// Takes the full URL so tests can point the probe at a local server.
async fn probe_fuigo_api_key_at_url(key: &str, url: &str, timeout: Duration) -> ApiKeyProbeVerdict {
    probe_detailed(key, url, timeout, Route::ApiKey).await.verdict
}

/// What one probe learned: the verdict, whether the route is missing (404 or 405), and whether the verdict came from a
/// real answer (Usable or Unusable) that may be cached.
struct ProbeOutcome {
    verdict: ApiKeyProbeVerdict,
    route_missing: bool,
    cacheable: bool,
}

async fn probe_detailed(key: &str, url: &str, timeout: Duration, route: Route) -> ProbeOutcome {
    let unknown = |verdict| ProbeOutcome { verdict, route_missing: false, cacheable: false };
    if key.trim().is_empty() {
        return unknown(ApiKeyProbeVerdict::Unusable);
    }
    let mut route_missing = false;

    let client = crate::http::shared_client();
    let started = Instant::now();
    let deadline = started + timeout;
    let mut attempts: u32 = 0;
    let mut last_verdict = ApiKeyProbeVerdict::Unknown;

    loop {
        attempts += 1;
        let now = Instant::now();
        let remaining = deadline.saturating_duration_since(now);
        if remaining.is_zero() {
            break;
        }

        let request = client
            .get(url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {key}"))
            .timeout(remaining);

        let outcome = match request.send_checked().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.bytes().await.unwrap_or_default();
                if matches!(status, 404 | 405) {
                    route_missing = true;
                }
                match route {
                    Route::ApiKey => classify_probe_attempt(status, &body),
                    Route::KeyInfo => classify_key_info_attempt(status, &body),
                }
            }
            // A locally blocked destination says nothing about key validity.
            Err(fuigo_extra_ca::dispatch::DispatchError::Denied(_)) => {
                return unknown(ApiKeyProbeVerdict::Unknown);
            }
            Err(fuigo_extra_ca::dispatch::DispatchError::Transport(_)) => AttemptOutcome::Retry,
        };

        match outcome {
            AttemptOutcome::Done(v) => {
                last_verdict = v;
                break;
            }
            AttemptOutcome::Retry => {
                route_missing = false;
                last_verdict = ApiKeyProbeVerdict::Unknown;
                if attempts > MAX_RETRIES {
                    break;
                }
                let now = Instant::now();
                let remaining = deadline.saturating_duration_since(now);
                if remaining.is_zero() {
                    break;
                }
                tokio::time::sleep(RETRY_BACKOFF.min(remaining)).await;
            }
        }
    }

    let elapsed_ms = started.elapsed().as_millis() as u64;
    fuigo_telemetry::unified_log::info(
        "auth: first-party API key probe",
        None,
        Some(serde_json::json!({
            "verdict": format!("{last_verdict:?}"),
            "allows_advertise": last_verdict.allows_advertise(),
            "elapsed_ms": elapsed_ms,
            "timeout_ms": timeout.as_millis() as u64,
            "attempts": attempts,
            "route": format!("{route:?}"),
            // P70: a fingerprint, not the key's last 12 characters (the whole of a short key)
            "key_suffix": fuigo_auth::bearer_fingerprint(key),
        })),
    );

    ProbeOutcome {
        verdict: last_verdict,
        route_missing: route_missing && last_verdict == ApiKeyProbeVerdict::Unknown,
        cacheable: matches!(last_verdict, ApiKeyProbeVerdict::Usable | ApiKeyProbeVerdict::Unusable),
    }
}

/// Probes the env key when one is set; without an env key this returns false and the caller combines the result with BYOK.
///
/// `api_base_url` is the caller's effective `endpoints.fuigo_api_base_url`, so the probe follows the same endpoint as turn traffic.
/// In tests that is the mock server the fixtures already set via `FUIGO_API_BASE_URL`.
pub(crate) async fn first_party_env_key_allows_advertise(
    api_base_url: &str,
    timeout: Duration,
) -> bool {
    let Ok(key) = crate::agent::auth_method::read_fuigo_api_key_env() else {
        return false;
    };
    probe_fuigo_api_key(&key, api_base_url, timeout)
        .await
        .allows_advertise()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn egress_policy_denial_is_unknown_without_probe_retries() {
        let verdict = tokio::time::timeout(
            Duration::from_secs(2),
            probe_fuigo_api_key_at_url(
                "fake-key",
                "https://api.x.ai/v1/api-key",
                Duration::from_secs(60),
            ),
        )
        .await
        .expect("policy denial must not enter network retry backoff");
        assert_eq!(verdict, ApiKeyProbeVerdict::Unknown);
    }

    #[test]
    fn probes_only_when_env_key_alone_would_suppress_login() {
        // Happy path: env key present, nothing else blocking.
        assert!(should_probe_first_party_env_key(false, false, true, false));
        // A kill switch, BYOK, a missing env key, or any pin each skip the probe and treat the key as usable
        assert!(!should_probe_first_party_env_key(true, false, true, false));
        assert!(!should_probe_first_party_env_key(false, true, true, false));
        assert!(!should_probe_first_party_env_key(
            false, false, false, false
        ));
        assert!(!should_probe_first_party_env_key(false, false, true, true));
    }

    #[test]
    fn joins_api_key_path_onto_base() {
        assert_eq!(
            api_key_info_url("https://api.x.ai/v1"),
            "https://api.x.ai/v1/api-key"
        );
        assert_eq!(
            api_key_info_url("https://api.x.ai/v1/"),
            "https://api.x.ai/v1/api-key"
        );
        assert_eq!(
            api_key_info_url("https://enterprise-api.acme.com/v1"),
            "https://enterprise-api.acme.com/v1/api-key"
        );
    }

    #[test]
    fn usable_on_200_clear_flags() {
        let body = br#"{"api_key_id":"k","api_key_blocked":false,"api_key_disabled":false,"team_blocked":false}"#;
        assert_eq!(
            classify_probe_response(200, body),
            ApiKeyProbeVerdict::Usable
        );
    }

    #[test]
    fn unusable_on_200_blocked() {
        let body = br#"{"api_key_blocked":true,"api_key_disabled":false}"#;
        assert_eq!(
            classify_probe_response(200, body),
            ApiKeyProbeVerdict::Unusable
        );
    }

    #[test]
    fn unusable_on_200_disabled() {
        let body = br#"{"api_key_blocked":false,"api_key_disabled":true}"#;
        assert_eq!(
            classify_probe_response(200, body),
            ApiKeyProbeVerdict::Unusable
        );
    }

    #[test]
    fn unusable_on_200_team_blocked() {
        let body = br#"{"api_key_blocked":false,"api_key_disabled":false,"team_blocked":true}"#;
        assert_eq!(
            classify_probe_response(200, body),
            ApiKeyProbeVerdict::Unusable
        );
    }

    #[test]
    fn usable_on_200_unparseable_body_fail_open() {
        assert_eq!(
            classify_probe_response(200, b"not-json"),
            ApiKeyProbeVerdict::Usable
        );
    }

    #[test]
    fn unusable_on_auth_errors() {
        for status in [400u16, 401, 402, 403] {
            assert_eq!(
                classify_probe_response(status, br#"{"error":"Incorrect API key"}"#),
                ApiKeyProbeVerdict::Unusable,
                "status {status}"
            );
        }
    }

    #[test]
    fn rate_limit_and_5xx_are_retryable() {
        assert_eq!(classify_probe_attempt(429, b""), AttemptOutcome::Retry);
        assert_eq!(classify_probe_attempt(503, b""), AttemptOutcome::Retry);
        assert_eq!(
            classify_probe_response(429, b""),
            ApiKeyProbeVerdict::Unknown
        );
    }

    #[test]
    fn unknown_on_other_4xx_fail_open() {
        assert_eq!(
            classify_probe_response(404, b""),
            ApiKeyProbeVerdict::Unknown
        );
    }

    #[tokio::test]
    async fn empty_key_is_unusable_without_network() {
        assert_eq!(
            probe_fuigo_api_key(
                "   ",
                "https://example.invalid/v1",
                Duration::from_millis(50)
            )
            .await,
            ApiKeyProbeVerdict::Unusable
        );
    }

    /// Serves sequential responses (one connection per attempt).
    fn serve_sequence(responses: Vec<(String, Vec<u8>)>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for (status_line, body) in responses {
                if let Ok((mut stream, _)) = listener.accept() {
                    use std::io::{Read, Write};
                    let _ = stream.read(&mut [0u8; 2048]);
                    let resp = format!(
                        "{status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        String::from_utf8_lossy(&body)
                    );
                    let _ = stream.write_all(resp.as_bytes());
                }
            }
        });
        format!("http://{addr}/v1/api-key")
    }

    fn serve_one_http_response(status_line: &str, body: &[u8]) -> String {
        serve_sequence(vec![(status_line.to_string(), body.to_vec())])
    }

    #[tokio::test]
    async fn local_server_invalid_key_is_unusable() {
        let url = serve_one_http_response(
            "HTTP/1.1 400 Bad Request",
            br#"{"error":"Incorrect API key"}"#,
        );
        let v = probe_fuigo_api_key_at_url("fuigo-bad", &url, Duration::from_secs(2)).await;
        assert_eq!(v, ApiKeyProbeVerdict::Unusable);
    }

    #[tokio::test]
    async fn local_server_blocked_key_is_unusable() {
        let url = serve_one_http_response(
            "HTTP/1.1 200 OK",
            br#"{"api_key_blocked":true,"api_key_disabled":false}"#,
        );
        let v = probe_fuigo_api_key_at_url("fuigo-blocked", &url, Duration::from_secs(2)).await;
        assert_eq!(v, ApiKeyProbeVerdict::Unusable);
    }

    #[tokio::test]
    async fn local_server_ok_key_is_usable() {
        let url = serve_one_http_response(
            "HTTP/1.1 200 OK",
            br#"{"api_key_id":"abc","api_key_blocked":false,"api_key_disabled":false}"#,
        );
        let v = probe_fuigo_api_key_at_url("fuigo-good", &url, Duration::from_secs(2)).await;
        assert_eq!(v, ApiKeyProbeVerdict::Usable);
    }

    /// P70: the probe's unified-log line used to carry the key's last 12 characters (all of a short key). A short
    /// key's probe line now carries its fingerprint and no run of four of its characters.
    #[tokio::test]
    async fn probe_log_line_holds_a_fingerprint_not_the_key() {
        const SHORT_KEY: &str = "q7zX9w";
        let url = serve_one_http_response(
            "HTTP/1.1 200 OK",
            br#"{"api_key_id":"abc","api_key_blocked":false,"api_key_disabled":false}"#,
        );
        let v = probe_fuigo_api_key_at_url(SHORT_KEY, &url, Duration::from_secs(2)).await;
        assert_eq!(v, ApiKeyProbeVerdict::Usable);
        // The unit-test binary's unified log is a private temp file (`test_support` ctor) that every test writes, so
        // judge only the probe lines this test's key produced: the probe's fixed message and this key's fingerprint.
        let all = String::from_utf8(fuigo_telemetry::unified_log::snapshot_log().expect("the probe logged")).unwrap();
        let fp = fuigo_auth::bearer_fingerprint(SHORT_KEY);
        let fp_field = format!("\"key_suffix\":\"{fp}\"");
        let log: String = all
            .lines()
            .filter(|l| l.contains("auth: first-party API key probe") && l.contains(&fp_field))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!log.is_empty(), "control: the probe line carries the fingerprint");
        let chars: Vec<char> = SHORT_KEY.chars().collect();
        for w in chars.windows(4) {
            let frag: String = w.iter().collect();
            assert!(!log.contains(&frag), "the unified log holds {frag:?} of the probed key");
        }
    }

    #[tokio::test]
    async fn probes_joined_base_url_path() {
        let url = serve_one_http_response(
            "HTTP/1.1 200 OK",
            br#"{"api_key_id":"abc","api_key_blocked":false,"api_key_disabled":false}"#,
        );
        // serve_sequence returns the full .../v1/api-key URL; strip it back to the base the way config stores it
        let base = url.trim_end_matches("/api-key");
        let v = probe_fuigo_api_key("fuigo-good", base, Duration::from_secs(2)).await;
        assert_eq!(v, ApiKeyProbeVerdict::Usable);
    }

    #[tokio::test]
    async fn retries_429_then_succeeds() {
        let url = serve_sequence(vec![
            (
                "HTTP/1.1 429 Too Many Requests".into(),
                br#"{"error":"rate limited"}"#.to_vec(),
            ),
            (
                "HTTP/1.1 200 OK".into(),
                br#"{"api_key_id":"ok","api_key_blocked":false,"api_key_disabled":false}"#.to_vec(),
            ),
        ]);
        let v = probe_fuigo_api_key_at_url("fuigo-retry", &url, Duration::from_secs(2)).await;
        assert_eq!(v, ApiKeyProbeVerdict::Usable);
    }

    #[tokio::test]
    async fn timeout_is_unknown_fail_open() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            // Accept and stall past the client timeout (both attempts).
            for _ in 0..2 {
                if let Ok((_stream, _)) = listener.accept() {
                    std::thread::sleep(Duration::from_secs(2));
                }
            }
        });

        let url = format!("http://{addr}/v1/api-key");
        let v = probe_fuigo_api_key_at_url("fuigo-slow", &url, Duration::from_millis(80)).await;
        assert_eq!(v, ApiKeyProbeVerdict::Unknown);
        assert!(v.allows_advertise());
    }

    // ---- FLUX-TRAFFIC part A: Flux key route, 24 h route memory, 1 h verdict cache ----

    use super::super::api_key_route_memory::RouteMemory;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    const T0: u64 = 1_800_000_000;
    const HOUR: u64 = 60 * 60;
    const DAY: u64 = 24 * HOUR;
    const T: Duration = Duration::from_secs(2);

    struct Mock {
        base: String,
        count: Arc<AtomicUsize>,
        paths: Arc<Mutex<Vec<String>>>,
    }

    /// A loopback server that answers every request with `status_line` and `body`, counting requests and paths.
    fn mock(status_line: &'static str, body: &'static str) -> Mock {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let paths = Arc::new(Mutex::new(Vec::new()));
        let (seen, seen_paths) = (Arc::clone(&count), Arc::clone(&paths));
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                use std::io::{Read, Write};
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
                seen_paths.lock().unwrap().push(path);
                seen.fetch_add(1, Ordering::SeqCst);
                let resp = format!(
                    "{status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        Mock { base: format!("http://{addr}/v1"), count, paths }
    }

    fn memory() -> (tempfile::TempDir, RouteMemory) {
        let dir = tempfile::tempdir().unwrap();
        let mem = RouteMemory::at(dir.path().join("api-key-probe-state.json"));
        (dir, mem)
    }

    async fn probe(m: &Mock, mem: &RouteMemory, route: Route, key: &str, now: u64) -> ApiKeyProbeVerdict {
        probe_remembering(key, &m.base, T, route, mem, now).await
    }

    #[test]
    fn the_flux_host_is_the_default_base_host_and_matches_exactly() {
        let default = reqwest::Url::parse(crate::agent::config::FUIGO_API_BASE_URL_DEFAULT).unwrap();
        assert_eq!(default.host_str(), Some(FLUX_API_HOST));
        for yes in [
            "https://api.fluxrouter.ai/v1",
            "https://api.fluxrouter.ai/v1/",
            "https://API.FluxRouter.ai:8443/x",
            "https://api.fluxrouter.ai",
        ] {
            assert!(is_flux_base(yes), "{yes}");
            assert_eq!(route_for_base(yes), Route::KeyInfo);
        }
        for no in [
            "https://api.fluxrouter.ai.evil.example/v1",
            "https://evil-api.fluxrouter.ai/v1",
            "https://sub.api.fluxrouter.ai/v1",
            "https://fluxrouter.ai/v1",
            "https://api.x.ai/v1",
            "http://127.0.0.1:1/v1",
            "https://u@evil.example/api.fluxrouter.ai",
            "not a url",
            "",
        ] {
            assert!(!is_flux_base(no), "{no}");
            assert_eq!(route_for_base(no), Route::ApiKey);
        }
    }

    #[test]
    fn the_key_info_url_is_the_origin_plus_key_info() {
        assert_eq!(probe_url("https://h.example/v1", Route::KeyInfo), "https://h.example/key/info");
        assert_eq!(probe_url("https://h.example/v1/", Route::KeyInfo), "https://h.example/key/info");
        assert_eq!(
            probe_url("https://u:p@h.example:8443/a/b?x=1", Route::KeyInfo),
            "https://h.example:8443/key/info"
        );
        assert_eq!(probe_url("https://h.example/v1/", Route::ApiKey), "https://h.example/v1/api-key");
    }

    #[tokio::test]
    async fn the_key_info_request_path_is_exactly_key_info() {
        for suffix in ["/v1", "/v1/", ""] {
            let m = mock("HTTP/1.1 200 OK", r#"{"key":"k","info":{"blocked":false}}"#);
            let (_d, mem) = memory();
            let base = format!("{}{suffix}", m.base.trim_end_matches("/v1"));
            probe_remembering("fake-key", &base, T, Route::KeyInfo, &mem, T0).await;
            assert_eq!(m.paths.lock().unwrap().as_slice(), ["/key/info"], "base {base}");
        }
    }

    #[tokio::test]
    async fn key_info_verdicts() {
        let cases: [(&str, &str, ApiKeyProbeVerdict, bool); 9] = [
            ("HTTP/1.1 200 OK", r#"{"key":"k","info":{"blocked":false,"spend":1}}"#, ApiKeyProbeVerdict::Usable, true),
            ("HTTP/1.1 200 OK", r#"{"key":"k","info":{"blocked":true}}"#, ApiKeyProbeVerdict::Unusable, true),
            ("HTTP/1.1 200 OK", r#"{"key":"k","info":{"spend":1}}"#, ApiKeyProbeVerdict::Usable, true),
            ("HTTP/1.1 200 OK", r#"{"key":"k","info":{"blocked":"yes"}}"#, ApiKeyProbeVerdict::Usable, true),
            ("HTTP/1.1 401 Unauthorized", "{}", ApiKeyProbeVerdict::Unusable, true),
            ("HTTP/1.1 403 Forbidden", "{}", ApiKeyProbeVerdict::Unknown, false),
            ("HTTP/1.1 500 Internal Server Error", "{}", ApiKeyProbeVerdict::Unknown, false),
            ("HTTP/1.1 200 OK", "<html>garbage", ApiKeyProbeVerdict::Unknown, false),
            ("HTTP/1.1 429 Too Many Requests", "{}", ApiKeyProbeVerdict::Unknown, false),
        ];
        for (line, body, want, cached) in cases {
            let m = mock(line, body);
            let (_d, mem) = memory();
            assert_eq!(probe(&m, &mem, Route::KeyInfo, "fake-key", T0).await, want, "{line} {body}");
            let after_first = m.count.load(Ordering::SeqCst);
            assert_eq!(probe(&m, &mem, Route::KeyInfo, "fake-key", T0 + 5).await, want);
            let second_sent = m.count.load(Ordering::SeqCst) - after_first;
            assert_eq!(second_sent == 0, cached, "cached? {line} {body}");
        }
    }

    #[tokio::test]
    async fn a_missing_route_404_or_405_is_asked_once_a_day_on_either_route() {
        for route in [Route::ApiKey, Route::KeyInfo] {
            for line in ["HTTP/1.1 404 Not Found", "HTTP/1.1 405 Method Not Allowed"] {
                let m = mock(line, "{}");
                let (_d, mem) = memory();
                assert_eq!(probe(&m, &mem, route, "fake-key", T0).await, ApiKeyProbeVerdict::Unknown);
                assert_eq!(m.count.load(Ordering::SeqCst), 1);
                for i in 1..=5 {
                    // Another key: the route is missing for every key.
                    probe(&m, &mem, route, "other-key", T0 + i * 60).await;
                }
                assert_eq!(m.count.load(Ordering::SeqCst), 1, "{route:?} {line}");
                let other = mock(line, "{}");
                probe(&other, &mem, route, "fake-key", T0 + 120).await;
                assert_eq!(other.count.load(Ordering::SeqCst), 1, "a different base still probes");
                probe(&m, &mem, route, "fake-key", T0 + DAY + 1).await;
                assert_eq!(m.count.load(Ordering::SeqCst), 2, "after 24 h it probes again");
            }
        }
    }

    #[tokio::test]
    async fn a_hundred_initializes_in_an_hour_send_one_request_per_key() {
        let m = mock("HTTP/1.1 200 OK", r#"{"key":"k","info":{"blocked":false}}"#);
        let (_d, mem) = memory();
        for i in 0..100 {
            let v = probe(&m, &mem, Route::KeyInfo, "fake-key-1", T0 + i * 30).await;
            assert_eq!(v, ApiKeyProbeVerdict::Usable);
        }
        assert_eq!(m.count.load(Ordering::SeqCst), 1);
        probe(&m, &mem, Route::KeyInfo, "fake-key-1", T0 + HOUR + 1).await;
        assert_eq!(m.count.load(Ordering::SeqCst), 2, "one more after the hour");
        probe(&m, &mem, Route::KeyInfo, "fake-key-2", T0 + HOUR + 2).await;
        assert_eq!(m.count.load(Ordering::SeqCst), 3, "a different key has its own entry");
    }

    #[tokio::test]
    async fn a_hundred_initializes_against_a_404_server_send_one_request() {
        let m = mock("HTTP/1.1 404 Not Found", "{}");
        let (_d, mem) = memory();
        for i in 0..100 {
            probe(&m, &mem, Route::ApiKey, "fake-key", T0 + i).await;
        }
        assert_eq!(m.count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn the_memory_file_is_owner_only_and_holds_only_hashes_verdict_and_time() {
        let body = r#"{"key":"KEYFIELDMARK","info":{"blocked":false,"user_id":"UIDMARK","spend":"SPENDMARK"}}"#;
        let m = mock("HTTP/1.1 200 OK", body);
        let (_d, mem) = memory();
        probe(&m, &mem, Route::KeyInfo, "fake-key-SECRETMARK-123", T0).await;
        let text = String::from_utf8(std::fs::read(mem.path()).expect("written")).unwrap();
        for bad in ["SECRETMARK", "KEYFIELDMARK", "UIDMARK", "SPENDMARK", "127.0.0.1", "http", "blocked"] {
            assert!(!text.contains(bad), "{bad} found in {text}");
        }
        assert!(text.contains("usable"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(mem.path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[tokio::test]
    async fn a_corrupt_oversized_or_future_dated_file_is_ignored_and_overwritten() {
        let m = mock("HTTP/1.1 200 OK", r#"{"info":{"blocked":false}}"#);
        let (_d, mem) = memory();
        std::fs::write(mem.path(), b"\xff\xfe not json {{{").unwrap();
        assert_eq!(probe(&m, &mem, Route::KeyInfo, "fake-key", T0).await, ApiKeyProbeVerdict::Usable);
        probe(&m, &mem, Route::KeyInfo, "fake-key", T0 + 1).await;
        assert_eq!(m.count.load(Ordering::SeqCst), 1, "overwritten with a valid file");
        std::fs::write(mem.path(), vec![b'x'; 1 << 20]).unwrap();
        probe(&m, &mem, Route::KeyInfo, "fake-key", T0 + 2).await;
        assert_eq!(m.count.load(Ordering::SeqCst), 2);
        // An entry dated in the future (clock skew or tampering) is not trusted.
        probe(&m, &mem, Route::KeyInfo, "fake-key", T0 + 10 * DAY).await;
        assert_eq!(m.count.load(Ordering::SeqCst), 3);
        probe(&m, &mem, Route::KeyInfo, "fake-key", T0).await;
        assert_eq!(m.count.load(Ordering::SeqCst), 4, "entry from T0+10d is future-dated at T0");
    }

    #[test]
    fn the_memory_is_bounded_and_normalises_the_base() {
        let (_d, mem) = memory();
        for i in 0..100u64 {
            mem.remember_unsupported(&format!("https://host{i}.example/v1/api-key"), T0 + i);
            mem.store_verdict(&format!("https://host{i}.example/key/info"), "k", ApiKeyProbeVerdict::Usable, T0 + i);
        }
        let text = std::fs::read_to_string(mem.path()).unwrap();
        assert!(text.matches("\"t\"").count() <= 128);
        assert!(mem.unsupported("https://host99.example/v1/api-key", T0 + 100));
        assert!(!mem.unsupported("https://host0.example/v1/api-key", T0 + 100));
        let (_d2, mem2) = memory();
        mem2.remember_unsupported("https://user:pw-SECRETMARK@Host.Example/v1/api-key?token=SECRETMARK", T0);
        assert!(mem2.unsupported("https://host.example/v1/api-key", T0 + 1));
        assert!(!std::fs::read_to_string(mem2.path()).unwrap().contains("SECRETMARK"));
    }

    #[tokio::test]
    async fn an_x_ai_base_is_denied_locally_on_both_routes_and_nothing_is_remembered() {
        for route in [Route::ApiKey, Route::KeyInfo] {
            let (_d, mem) = memory();
            let v = tokio::time::timeout(
                Duration::from_secs(2),
                probe_remembering("fake-key", "https://api.x.ai/v1", Duration::from_secs(60), route, &mem, T0),
            )
            .await
            .expect("a policy denial must not enter network retry backoff");
            assert_eq!(v, ApiKeyProbeVerdict::Unknown);
            assert!(!mem.path().exists(), "a local denial is neither a verdict nor a missing route");
        }
    }

    #[tokio::test]
    async fn the_key_info_probe_log_line_holds_nothing_from_the_response() {
        let body = r#"{"key":"KEYFIELDLOG","info":{"blocked":false,"user_id":"UIDLOG","spend":"SPENDLOG"}}"#;
        let m = mock("HTTP/1.1 200 OK", body);
        let (_d, mem) = memory();
        let key = "fake-key-logtest-9c1";
        probe(&m, &mem, Route::KeyInfo, key, T0).await;
        let all = String::from_utf8(fuigo_telemetry::unified_log::snapshot_log().expect("logged")).unwrap();
        let fp_field = format!("\"key_suffix\":\"{}\"", fuigo_auth::bearer_fingerprint(key));
        let log: String = all
            .lines()
            .filter(|l| l.contains("auth: first-party API key probe") && l.contains(&fp_field))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!log.is_empty(), "control: the probe line carries the fingerprint");
        for bad in ["KEYFIELDLOG", "UIDLOG", "SPENDLOG", key] {
            assert!(!log.contains(bad), "{bad} in the log");
        }
    }
}
