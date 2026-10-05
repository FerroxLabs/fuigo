//! What the sampler records as "credentials actually sent" (P70b, option A), for the exact-match scrub that
//! display and log sinks apply ([`fuigo_secrets::sent_credentials`]).
//!
//! Recorded at the last point before a request goes on the wire, from the request itself, so whatever path put a
//! value there (`api_key`, a bearer resolver, `extra_headers`, `env_http_headers`, a header injector, the
//! subscription transport, a query parameter, URL userinfo) is covered without each path having to remember.
//!
//! Every header value is treated as a credential except the ones this client composes itself and knows to be
//! non-secret: a fixed protocol constant under the name the client writes it to ([`STATIC_CLIENT_HEADERS`]), and the
//! value under a name the client itself always writes ([`CLIENT_WRITTEN_HEADERS`]). Any other header may have been mapped to a secret by configuration
//! (`x-openrouter-api-key`, a proxy's `cookie`), and its name says nothing reliable. A value configuration put under
//! one of the client-written names and that is really sent is recorded too (`configured`, see
//! [`surviving_configured_values`]). Every query value, the URL's userinfo and the credentials of a proxy configured
//! in the environment are treated the same way. Over-recording costs only a `<redacted>` in displayed or logged
//! error text; nothing in the agent classifies on the scrubbed text.

use crate::client::{
    H_AGENT_ID, H_CLIENT_IDENTIFIER, H_CLIENT_VERSION, H_CONV_ID, H_DEPLOYMENT_ID,
    H_MODEL_OVERRIDE, H_REQ_ID, H_SESSION_ID, H_TRANSIENT_RETRY, H_TURN_IDX, H_USER_ID,
};

/// Fixed protocol constants the sampler writes, with the header each travels under. Only that pair is skipped: the
/// same text under another name (an API key that happens to read `2023-06-01`) is a credential like any other.
const STATIC_CLIENT_HEADERS: &[(&str, &str)] = &[
    ("content-type", "application/json"),
    ("accept", "text/event-stream"),
    (
        crate::client::ANTHROPIC_VERSION_HEADER,
        crate::client::ANTHROPIC_VERSION,
    ),
];

fn is_static_client_header(name: &str, value: &str) -> bool {
    STATIC_CLIENT_HEADERS
        .iter()
        .any(|(n, v)| name.eq_ignore_ascii_case(n) && value == *v)
}

/// Header NAMES whose value on the wire is written by this client itself, after configuration (lowercase, as
/// `HeaderName` stores them): the User-Agent, the trace context the injector stamps, and the per-request and identity
/// `x-fuigo-*` headers (ids, a model name, a version). None is a credential. A value configuration managed to put
/// under one of these names is recorded separately, by provenance.
const CLIENT_WRITTEN_HEADERS: &[&str] = &[
    "user-agent",
    "traceparent",
    H_CONV_ID,
    H_REQ_ID,
    H_SESSION_ID,
    H_TURN_IDX,
    H_TRANSIENT_RETRY,
    H_MODEL_OVERRIDE,
    H_AGENT_ID,
    H_DEPLOYMENT_ID,
    H_USER_ID,
    H_CLIENT_VERSION,
    H_CLIENT_IDENTIFIER,
];

/// The environment variables reqwest reads a system proxy from.
const PROXY_ENV_VARS: &[&str] = &[
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
];

/// Record every credential `request` carries. Call it on the final request, immediately before it is sent.
/// `configured` is the client's [`surviving_configured_values`]; recording them here, on every request, keeps a
/// long-lived client's credentials inside the registry's retention window.
pub(crate) fn record_request(request: &reqwest::Request, configured: &[String]) {
    for value in configured {
        // Only when it is on THIS request: a bearer resolver or the header injector can replace a configured
        // value after the client was built, and a replaced value is not sent.
        if request
            .headers()
            .values()
            .any(|sent| sent.as_bytes() == value.as_bytes())
        {
            fuigo_secrets::sent_credentials::record_header_value(value);
        }
    }
    for (name, value) in request.headers() {
        if CLIENT_WRITTEN_HEADERS.contains(&name.as_str()) {
            continue;
        }
        record_header(name.as_str(), value);
    }
    record_url(request.url());
    // `Proxy-Authorization` is added inside the HTTP client, after this point; a proxy's error body is upstream
    // text like any other.
    record_proxies(request.url(), |var| std::env::var(var).ok());
}

/// The proxy variables that can apply to a request to a URL of `scheme`: that scheme's own variables and
/// `ALL_PROXY`, never the other scheme's. An unknown scheme could use any of them.
fn proxy_vars_for(scheme: &str) -> Vec<&'static str> {
    PROXY_ENV_VARS
        .iter()
        .copied()
        .filter(|var| {
            let specific = var.to_ascii_lowercase();
            match scheme {
                "https" => specific != "http_proxy",
                "http" => specific != "https_proxy",
                _ => true,
            }
        })
        .collect()
}

/// Record the credentials of the proxies `lookup` returns that this request can go through (P119): the variables for
/// the request's scheme and `ALL_PROXY`, never the other scheme's. `NO_PROXY` is deliberately NOT consulted: the HTTP
/// stack's matching of its entries (wildcards, address ranges, IP literals) is its own, and a guess that differs
/// from it would leave a proxy credential that IS sent unrecorded. A proxy exempted by `NO_PROXY` stays recorded
/// (known limit K5: that over-hiding remains).
fn record_proxies(url: &reqwest::Url, lookup: impl Fn(&str) -> Option<String>) {
    for var in proxy_vars_for(url.scheme()) {
        if let Some(proxy) = lookup(var) {
            fuigo_secrets::sent_credentials::record_proxy_url(&proxy);
        }
    }
}

fn record_header(name: &str, value: &reqwest::header::HeaderValue) {
    // A non-ASCII value is still sent; record what a receiver would read back as text.
    let text = String::from_utf8_lossy(value.as_bytes());
    if is_static_client_header(name, &text) {
        return;
    }
    fuigo_secrets::sent_credentials::record_header_value(&text);
}

/// What configuration put into `headers` under each configured name, read before the client composes its own.
pub(crate) fn configured_snapshot<'a>(
    headers: &reqwest::header::HeaderMap,
    names: impl Iterator<Item = &'a String>,
) -> Vec<(String, reqwest::header::HeaderValue)> {
    names
        .flat_map(|name| {
            headers
                .get_all(name.as_str())
                .iter()
                .map(move |value| (name.clone(), value.clone()))
        })
        .collect()
}

/// The configured values that are still in the final default `headers`: a client-composed header written afterwards
/// (the User-Agent, an identity header) replaces a configured one of the same name, and a replaced value is never
/// sent, so it is not a sent credential.
pub(crate) fn surviving_configured_values(
    snapshot: Vec<(String, reqwest::header::HeaderValue)>,
    headers: &reqwest::header::HeaderMap,
) -> Vec<String> {
    snapshot
        .into_iter()
        .filter(|(name, value)| headers.get_all(name.as_str()).iter().any(|v| v == value))
        .map(|(name, value)| (name, String::from_utf8_lossy(value.as_bytes()).into_owned()))
        .filter(|(name, text)| !is_static_client_header(name, text))
        .map(|(_, text)| text)
        .collect()
}

fn record_url(url: &reqwest::Url) {
    let record_both = |raw: &str| {
        fuigo_secrets::sent_credentials::record(raw);
        if let Ok(decoded) = percent_decode(raw) {
            fuigo_secrets::sent_credentials::record(&decoded);
        }
    };
    record_both(url.username());
    if let Some(password) = url.password() {
        record_both(password);
    }
    if let Some(query) = url.query() {
        for pair in query.split('&') {
            let value = pair.split_once('=').map_or("", |(_, v)| v);
            record_both(value);
            // `application/x-www-form-urlencoded` spells a space as `+`.
            if value.contains('+') {
                record_both(&value.replace('+', " "));
            }
        }
    }
}

/// Percent-decode `raw` as UTF-8; `Err` for an invalid escape or invalid UTF-8.
fn percent_decode(raw: &str) -> Result<String, ()> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3).ok_or(())?;
            let hex = std::str::from_utf8(hex).map_err(|_| ())?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| ())?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| ())
}

/// The registry is process-wide: tests in this crate that reset it or assert on it hold this lock.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use fuigo_secrets::sent_credentials::{clear_for_tests, scrub};

    use super::TEST_LOCK as LOCK;

    /// Built directly, not through a `reqwest::Client` (a disallowed method in this crate): nothing is sent.
    fn request(url: &str, headers: &[(&str, &str)]) -> reqwest::Request {
        let mut req = reqwest::Request::new(
            reqwest::Method::POST,
            reqwest::Url::parse(url).expect("url"),
        );
        for (k, v) in headers {
            req.headers_mut().insert(
                reqwest::header::HeaderName::from_bytes(k.as_bytes()).expect("header name"),
                reqwest::header::HeaderValue::from_str(v).expect("header value"),
            );
        }
        req
    }

    #[test]
    fn every_header_but_the_client_composed_ones_is_recorded() {
        let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_for_tests();
        let req = request(
            "https://example.invalid/v1/chat/completions",
            &[
                ("authorization", "Bearer sk-live-0123456789"),
                ("x-api-key", "anthropic-key-0123"),
                ("x-openrouter-api-key", "or-key-abcdefgh"),
                ("cookie", "session=cookie-value-1234"),
                ("content-type", "application/json"),
                ("user-agent", "fuigo/1.2.3 (linux)"),
                (H_CONV_ID, "conv-0123456789"),
                (H_MODEL_OVERRIDE, "claude-sonnet-4-5-20250929"),
            ],
        );
        record_request(&req, &[]);
        for secret in [
            "sk-live-0123456789",
            "anthropic-key-0123",
            "or-key-abcdefgh",
            "session=cookie-value-1234",
        ] {
            assert_eq!(
                scrub(&format!("echo {secret}")),
                "echo <redacted>",
                "{secret}"
            );
        }
        for public in [
            "application/json",
            "fuigo/1.2.3 (linux)",
            "conv-0123456789",
            "claude-sonnet-4-5-20250929",
        ] {
            assert_eq!(scrub(public), public, "{public}");
        }
        clear_for_tests();
    }

    #[test]
    fn a_client_written_name_is_skipped_and_cookie_values_are_recorded_on_their_own() {
        let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_for_tests();
        let req = request(
            "https://example.invalid/v1",
            &[
                ("user-agent", "p70b-client-user-agent/1.0"),
                ("originator", "p70b-secret-originator"),
                ("tracestate", "vendor=p70b-secret-tracestate"),
                ("accept", "text/event-stream"),
                ("cookie", "session=cookievalue-0001; theme=dark"),
            ],
        );
        // A configured value is recorded only when it is on this request.
        record_request(&req, &["p70b-replaced-configured-value".to_owned()]);
        assert_eq!(
            scrub("p70b-replaced-configured-value"),
            "p70b-replaced-configured-value"
        );
        record_request(&req, &["p70b-client-user-agent/1.0".to_owned()]);
        assert_eq!(scrub("p70b-client-user-agent/1.0"), "<redacted>");
        clear_for_tests();
        record_request(&req, &[]);
        // Written by the client itself: not a credential.
        assert_eq!(
            scrub("p70b-client-user-agent/1.0"),
            "p70b-client-user-agent/1.0"
        );
        assert_eq!(scrub("text/event-stream"), "text/event-stream");
        // Names the client does not write are recorded whatever they are called.
        assert_eq!(scrub("echo p70b-secret-originator"), "echo <redacted>");
        assert_eq!(scrub("echo p70b-secret-tracestate"), "echo <redacted>");
        assert_eq!(scrub("echo cookievalue-0001"), "echo <redacted>");
        // The same constant under a credential's name IS a credential.
        let key_req = request(
            "https://example.invalid/v1",
            &[("x-api-key", "text/event-stream")],
        );
        record_request(&key_req, &[]);
        assert_eq!(scrub("text/event-stream"), "<redacted>");
        clear_for_tests();
    }

    fn url(raw: &str) -> reqwest::Url {
        reqwest::Url::parse(raw).expect("url")
    }

    #[test]
    fn a_proxy_configured_in_the_environment_is_recorded() {
        let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_for_tests();
        // The lookup stands in for the process environment (not mutated here: other tests build HTTP clients).
        record_proxies(&url("https://example.invalid/v1"), |var| {
            (var == "all_proxy").then(|| {
                "http://p70b-envproxy-user:p70b-envproxy-pass@proxy.invalid:3128".to_owned()
            })
        });
        assert_eq!(scrub("407 p70b-envproxy-pass"), "407 <redacted>");
        assert_eq!(scrub("user p70b-envproxy-user"), "user <redacted>");
        clear_for_tests();
        record_proxies(&url("https://example.invalid/v1"), |_| None);
        assert_eq!(scrub("407 p70b-envproxy-pass"), "407 p70b-envproxy-pass");
    }

    /// P119 (R088 R3-4): only a proxy the request can go through is recorded.
    #[test]
    fn a_proxy_the_request_does_not_use_is_not_recorded() {
        let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let env = |var: &str| match var {
            "HTTP_PROXY" => Some("http://p119-http-user:p119-http-pass@h.invalid:1".to_owned()),
            "HTTPS_PROXY" => Some("http://p119-tls-user:p119-tls-pass@t.invalid:1".to_owned()),
            _ => None,
        };
        // An https request goes through HTTPS_PROXY only.
        clear_for_tests();
        record_proxies(&url("https://example.invalid/v1"), env);
        assert_eq!(scrub("p119-tls-pass"), "<redacted>");
        assert_eq!(scrub("p119-http-pass"), "p119-http-pass");
        // An http request goes through HTTP_PROXY only.
        clear_for_tests();
        record_proxies(&url("http://example.invalid/v1"), env);
        assert_eq!(scrub("p119-http-pass"), "<redacted>");
        assert_eq!(scrub("p119-tls-pass"), "p119-tls-pass");
        // NO_PROXY is not consulted: the HTTP stack matches its entries its own way, and a guess that differs would
        // leave a sent credential unrecorded.
        for no_proxy in ["*", "example.invalid", ".example.invalid", "*.invalid", "10.0.0.0/8"] {
            clear_for_tests();
            let with_no_proxy = |var: &str| match var {
                "NO_PROXY" => Some(no_proxy.to_owned()),
                other => env(other),
            };
            record_proxies(&url("https://example.invalid/v1"), with_no_proxy);
            assert_eq!(scrub("p119-tls-pass"), "<redacted>", "NO_PROXY={no_proxy}");
        }
        clear_for_tests();
    }

    /// A query value is recorded whatever its name or shape: `api-version=2024-10-21` is public on the endpoints
    /// that define it, but a gateway can authenticate by that very parameter, and nothing here can tell which. (Left
    /// as it was: K5 keeps hiding long non-secret sent values.)
    #[test]
    fn an_api_version_query_value_is_recorded_like_any_other() {
        let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_for_tests();
        let req = request("https://example.invalid/v1?api-version=2024-10-21", &[]);
        record_request(&req, &[]);
        assert_eq!(scrub("api-version 2024-10-21"), "api-version <redacted>");
        clear_for_tests();
    }

    #[test]
    fn url_userinfo_and_query_values_are_recorded_raw_and_decoded() {
        let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_for_tests();
        let req = request(
            "https://proxyuser1:p%40ss-word-9@example.invalid/v1?key=AIza%2Bkey-0123&api-version=2024-10-21",
            &[],
        );
        record_request(&req, &[]);
        assert_eq!(scrub("user proxyuser1"), "user <redacted>");
        assert_eq!(scrub("p@ss-word-9"), "<redacted>");
        assert_eq!(scrub("p%40ss-word-9"), "<redacted>");
        assert_eq!(scrub("AIza+key-0123"), "<redacted>");
        assert_eq!(scrub("AIza%2Bkey-0123"), "<redacted>");
        assert_eq!(scrub("2024-10-21"), "<redacted>");
        // `application/x-www-form-urlencoded` spells a space as `+`.
        let req = request("https://example.invalid/v1?note=pass+phrase+one", &[]);
        record_request(&req, &[]);
        assert_eq!(scrub("pass phrase one"), "<redacted>");
        assert_eq!(scrub("pass+phrase+one"), "<redacted>");
        clear_for_tests();
    }

    #[test]
    fn percent_decoding_rejects_bad_escapes() {
        assert_eq!(percent_decode("a%41b").as_deref(), Ok("aAb"));
        assert!(percent_decode("a%4").is_err());
        assert!(percent_decode("a%zz").is_err());
        assert!(percent_decode("%ff").is_err());
    }
}
