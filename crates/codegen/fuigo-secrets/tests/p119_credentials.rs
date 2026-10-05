//! P119 (P70c): the two spellings of a credential that the exact-match scrub used to miss (R088 K5).
//! Public API only; one lock because the registry is process-wide.

use fuigo_secrets::sent_credentials::{
    clear_for_tests, record, record_proxy_url, record_transformed, scrub,
};
use std::sync::Mutex;

static LOCK: Mutex<()> = Mutex::new(());

fn fresh() -> std::sync::MutexGuard<'static, ()> {
    let guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_for_tests();
    guard
}

/// Standard base64 with padding, as an HTTP client builds a `Basic` token.
fn base64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b)) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A scheme-less proxy setting whose user name is a URL scheme word. A URL parser reads `http:secret@proxy` as the
/// scheme `http` with user `secret`; the setting means user `http`, password `secret`, and the `Basic` token the
/// HTTP client builds is for THAT pair.
#[test]
fn a_proxy_whose_user_name_is_a_scheme_word_is_recorded_as_user_and_password() {
    let _g = fresh();
    for scheme_word in ["http", "https", "ftp", "ws", "socks5"] {
        clear_for_tests();
        record_proxy_url(&format!(
            "{scheme_word}:p119-scheme-pass-word@proxy.invalid:3128"
        ));
        assert_eq!(
            scrub("bad password p119-scheme-pass-word"),
            "bad password <redacted>",
            "{scheme_word}"
        );
        let token = base64(format!("{scheme_word}:p119-scheme-pass-word").as_bytes());
        assert_eq!(
            scrub(&format!("Basic {token} rejected")),
            "Basic <redacted> rejected",
            "{scheme_word}: the Basic token of the user:password pair"
        );
    }
    // A real URL is still a URL: its scheme is not a user name.
    clear_for_tests();
    record_proxy_url("http://p119-url-user:p119-url-pass@proxy.invalid:3128");
    assert_eq!(scrub("p119-url-pass"), "<redacted>");
    assert_eq!(scrub(&base64(b"p119-url-user:p119-url-pass")), "<redacted>");
}

/// R088 R3-3: a cap that cut through a credential, then a rewrite that respells the cut beginning. The text holds
/// only a prefix of the credential, so only the respelled prefix identifies it.
#[test]
fn a_credential_cut_by_a_cap_and_then_respelled_is_still_hidden() {
    let _g = fresh();
    record("p119  spaced   credential-value-9");
    let collapse = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    let capped = "upstream said: bad key p119  spaced   cred\u{2026}";
    record_transformed(capped, collapse);
    assert_eq!(
        scrub(&collapse(capped)),
        "upstream said: bad key <redacted>\u{2026}"
    );
    // Text that does not begin any recorded credential stays as it is.
    let other = "upstream said: p119 unrelated\u{2026}";
    record_transformed(other, collapse);
    assert_eq!(scrub(&collapse(other)), collapse(other));
}

/// A rewrite that spans the text in front of the credential and the credential's beginning: the surrounding word
/// `inference-` plus the credential's `api-...` is a service name, rewritten whole.
#[test]
fn a_rewrite_that_straddles_the_start_of_a_cut_credential_is_still_hidden() {
    let _g = fresh();
    record("api-p119abcdefghijklmno");
    let rewrite = |s: &str| s.replace("inference-api", "inference backend");
    let capped = "upstream said: inference-api-p119abcdefgh\u{2026}";
    record_transformed(capped, rewrite);
    let shown = rewrite(capped);
    assert_eq!(shown, "upstream said: inference backend-p119abcdefgh\u{2026}");
    let out = scrub(&shown);
    assert!(!out.contains("p119abcdefgh"), "{out}");
}

/// The rewrite completes a service name with text AFTER the credential: `...-inference-ap` + `i`.
#[test]
fn a_rewrite_that_straddles_the_end_of_a_credential_is_still_hidden() {
    let _g = fresh();
    record("p119abcdefgh-inference-ap");
    let rewrite = |s: &str| s.replace("inference-api", "inference backend");
    let text = "upstream rejected key p119abcdefgh-inference-api";
    record_transformed(text, rewrite);
    let shown = rewrite(text);
    assert_eq!(shown, "upstream rejected key p119abcdefgh-inference backend");
    let out = scrub(&shown);
    assert!(!out.contains("p119abcdefgh"), "{out}");
}
