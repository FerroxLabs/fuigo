#![no_main]
//! The NO_PROXY matcher fuigo-file-utils uses to decide whether a proxy carries a signed URL
//! (`proxy_carries_signed_url` is `Matcher::intercept(..).is_some()` on the library matcher, read from the
//! environment). Fuzzed here through its builder, so the environment is never touched.
//! Properties: never panics; no proxy configured means nothing is intercepted; an entry that is exactly the host
//! (plain name, no wildcard or port) always connects directly; `*` exempts everything.

use hyper_util::client::proxy::matcher::Matcher;
use libfuzzer_sys::fuzz_target;

fn plain_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() < 100
        && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !h.starts_with(['.', '-'])
        && !h.ends_with(['.', '-'])
        && !h.contains("..")
        // an all-numeric-and-dot host is an address, matched by the IP rules instead
        && h.bytes().any(|b| b.is_ascii_alphabetic())
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    // Layout: <no_proxy list>\n<uri>
    let (no, uri) = s.split_once('\n').unwrap_or((s, "http://example.com/"));
    let Ok(uri) = uri.parse::<http::Uri>() else {
        // still exercise the builder on whatever came in
        let _ = Matcher::builder().all("http://127.0.0.1:3128").no(no).build();
        return;
    };

    let none = Matcher::builder().no(no).build();
    assert!(none.intercept(&uri).is_none(), "no proxy configured, yet intercepted");

    let m = Matcher::builder().all("http://127.0.0.1:3128").no(no).build();
    let hit = m.intercept(&uri).is_some();

    if let Some(host) = uri.host() {
        let host = host.to_ascii_lowercase();
        if plain_host(&host) && no.split(',').any(|e| e.trim().eq_ignore_ascii_case(&host)) {
            assert!(!hit, "NO_PROXY entry equal to host {host:?} still intercepted (no={no:?})");
        }
    }
    // `*` exempts every name. It does NOT exempt an IP-literal host in hyper-util 0.1.20 (those are matched against the
    // address and network entries only), so literals are left out of this property; see NOTES.md.
    let is_literal = uri.host().is_some_and(|h| h.starts_with('[') || h.parse::<std::net::IpAddr>().is_ok());
    // A host with `*` in it is not a DNS name (`http::Uri` allows the sub-delim). When it ends in `*`, hyper-util 0.1.20
    // takes the `*` entry for a suffix match and never reaches its wildcard branch. The product makes the decision and
    // the connection with that same matcher, so they agree; such hosts are left out of this property (u46 fuzzfix).
    let star_host = uri.host().is_some_and(|h| h.contains('*'));
    if !is_literal && !star_host && no.split(',').any(|e| e.trim() == "*") {
        assert!(!hit, "NO_PROXY=* still intercepted");
    }
});
