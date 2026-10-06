//! The credential fingerprint every log, telemetry and 401-attribution site records in place of a credential.
//! One definition, because comparing two fingerprints only works if both sides reduce the credential alike.
//!
//! P70: this replaced a 12-character tail. A tail is the credential itself for a key of 12 characters or fewer, and
//! 12 characters of any key is more than a diagnostic needs. A fingerprint is the first [`FINGERPRINT_HEX_LEN`] hex
//! digits of the credential's SHA-256 plus its length in characters: enough to tell "the same credential" from "a
//! different one" in a log, never enough to recover or use it. 16 bits of hash leave every credential of five or more
//! characters with many other credentials that print alike, so a fingerprint does not even confirm a guess reliably.

use sha2::{Digest, Sha256};

/// Hex digits of SHA-256 a fingerprint keeps (16 bits).
pub const FINGERPRINT_HEX_LEN: usize = 4;

/// A credential's fingerprint: `sha256:<4 hex>/len=<chars>`. Built only by [`BearerFingerprint::of`], so a value of
/// this type never holds a credential, and an API that takes one cannot be handed a raw secret by mistake.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BearerFingerprint(String);

impl BearerFingerprint {
    /// Fingerprint `credential` (a bearer, an API key, a refresh token).
    pub fn of(credential: &str) -> Self {
        let digest = Sha256::digest(credential.as_bytes());
        let mut hex = String::with_capacity(FINGERPRINT_HEX_LEN);
        for byte in digest.iter().take(FINGERPRINT_HEX_LEN.div_ceil(2)) {
            hex.push_str(&format!("{byte:02x}"));
        }
        hex.truncate(FINGERPRINT_HEX_LEN);
        Self(format!("sha256:{hex}/len={}", credential.chars().count()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for BearerFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Debug for BearerFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// [`BearerFingerprint::of`] as a `String`, for structured-log fields.
pub fn bearer_fingerprint(credential: &str) -> String {
    BearerFingerprint::of(credential).into_string()
}

/// `url` for a log line or a `Debug` print (P70): userinfo and every query and fragment value become `<redacted>`, since a
/// base URL may carry a credential (`https://user:pass@host`, `?key=…`). The URL is parsed with the same parser the
/// HTTP transport uses, so spellings it normalizes (`https:/user:pw@host`, backslashes, extra slashes) are recognised;
/// scheme, host, port and path are kept. Input that does not parse as a URL is returned unchanged unless it contains
/// `@`, `?`, `#` or `\\`, in which case it fails closed to `<redacted url>`.
pub fn redact_url(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(parsed) if !parsed.cannot_be_a_base() => {
            let mut out = format!("{}://", parsed.scheme());
            if !parsed.username().is_empty() || parsed.password().is_some() {
                out.push_str("<redacted>@");
            }
            if let Some(host) = parsed.host_str() {
                out.push_str(host);
            }
            if let Some(port) = parsed.port() {
                out.push_str(&format!(":{port}"));
            }
            out.push_str(parsed.path());
            if let Some(query) = parsed.query() {
                out.push('?');
                let pairs: Vec<String> = query
                    .split('&')
                    .map(|pair| match pair.split_once('=') {
                        Some((name, _)) => format!("{name}=<redacted>"),
                        None if pair.is_empty() => String::new(),
                        None => "<redacted>".to_owned(),
                    })
                    .collect();
                out.push_str(&pairs.join("&"));
            }
            if parsed.fragment().is_some() {
                out.push_str("#<redacted>");
            }
            out
        }
        _ if url.contains(['@', '?', '#', '\\']) => "<redacted url>".to_owned(),
        _ => url.to_owned(),
    }
}

/// `text` with every URL in it passed through [`redact_url`] (P70): for error strings that embed a request URL.
///
/// A URL starts at a `scheme://` and runs to the next whitespace or `"` (neither can appear in a serialized URL).
/// Nothing else ends it: `)`, `]`, `'`, `,` and `.` are all legal in a path or a query value, so stopping at one
/// would leave everything after it, a query credential included, unredacted (`/tenant(foo)/v1?key=…`). The price is
/// that punctuation which merely follows a URL in prose is taken as part of it: after a URL with no userinfo, query
/// or fragment it is printed back unchanged; after one that has them it disappears into the last `<redacted>`.
/// Where the exact URL is known (a `reqwest::Error`), replace that string instead of scanning for it.
pub fn redact_urls_in_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(sep) = rest.find("://") {
        // Byte index just after the last character that cannot be part of a scheme (multi-byte safe).
        let start = rest[..sep]
            .char_indices()
            .rev()
            .find(|&(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
            .map_or(0, |(i, c)| i + c.len_utf8());
        let end = rest[sep..]
            .char_indices()
            .find(|&(_, c)| c.is_whitespace() || c == '"')
            .map_or(rest.len(), |(i, _)| sep + i);
        out.push_str(&rest[..start]);
        out.push_str(&redact_url(&rest[start..end]));
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_urls_in_text_keeps_ipv6_authorities_whole() {
        assert_eq!(
            redact_urls_in_text("error (http://[::1]:8080/v1?key=FAKEsecret123) refused"),
            "error (http://[::1]:8080/v1?key=<redacted> refused"
        );
    }

    /// Astra r1 (P70a): `)`, `]`, `'`, `,` and `.` are legal in a URL's path and query, so none of them ends the URL:
    /// a path with parentheses must not leave the query that follows it unredacted. Text after a URL that carries
    /// no credential is printed back as it was, and a second pass changes nothing.
    #[test]
    fn redact_urls_in_text_does_not_stop_at_punctuation_a_url_may_contain() {
        for (input, expected) in [
            (
                "error sending request for url (http://127.0.0.1:1/tenant(foo)/v1/responses?key=p70-FAKE-SECRET&sig=p70-FAKE-SIG): refused",
                "error sending request for url (http://127.0.0.1:1/tenant(foo)/v1/responses?key=<redacted>&sig=<redacted> refused",
            ),
            ("at 'http://h/a]b/c,d.e?k=p70-FAKE-SECRET', retrying", "at 'http://h/a]b/c,d.e?k=<redacted> retrying"),
            // (the parser percent-encodes the `>` it was handed as part of the path)
            ("<http://u:p70-FAKE-SECRET@h/p> gone", "<http://<redacted>@h/p%3E gone"),
            (r#"{"url":"http://h/p?k=p70-FAKE-SECRET","n":1}"#, r#"{"url":"http://h/p?k=<redacted>","n":1}"#),
            ("see (https://h/docs), then https://h/v1.", "see (https://h/docs), then https://h/v1."),
        ] {
            let once = redact_urls_in_text(input);
            assert_eq!(once, expected, "input={input:?}");
            assert!(!once.contains("FAKE"), "a credential survived: {once}");
            assert_eq!(redact_urls_in_text(&once), once, "not idempotent for {input:?}");
        }
    }

    #[test]
    fn redact_urls_in_text_redacts_each_url_and_keeps_the_rest() {
        assert_eq!(
            redact_urls_in_text("error sending request for url (https://h/v1?key=FAKE123): refused"),
            "error sending request for url (https://h/v1?key=<redacted> refused"
        );
        assert_eq!(redact_urls_in_text("no url here"), "no url here");
        assert_eq!(redact_urls_in_text("éhttps://h/?k=FAKE1 ü"), "éhttps://h/?k=<redacted> ü");
    }

    #[test]
    fn redact_url_hides_userinfo_query_and_fragment_values() {
        for (input, expected) in [
            ("https://api.example/v1", "https://api.example/v1"),
            ("https://api.example/v1?key=FAKE123&alt=sse", "https://api.example/v1?key=<redacted>&alt=<redacted>"),
            ("https://user:FAKEpass@host:8443/p?x", "https://<redacted>@host:8443/p?<redacted>"),
            ("http://h/p#access_token=FAKE", "http://h/p#<redacted>"),
            ("not a url ?token=FAKE", "<redacted url>"),
            ("https:/user:pw9Zk@example.com/v1", "https://<redacted>@example.com/v1"),
            ("https:\\\\user:pw9Zk@example.com\\v1", "https://<redacted>@example.com/v1"),
            ("https:///user:pw9Zk@example.com/v1", "https://<redacted>@example.com/v1"),
            ("plain-text", "plain-text"),
            ("", ""),
        ] {
            assert_eq!(redact_url(input), expected, "input={input:?}");
        }
    }

    #[test]
    fn fingerprint_shape_and_stability() {
        // sha256("abc") = ba7816bf...
        assert_eq!(bearer_fingerprint("abc"), "sha256:ba78/len=3");
        // sha256("") = e3b0c442...
        assert_eq!(bearer_fingerprint(""), "sha256:e3b0/len=0");
        // Characters, not bytes.
        assert!(bearer_fingerprint("🔑🔑").ends_with("/len=2"));
        assert_eq!(bearer_fingerprint("same-FAKE-key"), bearer_fingerprint("same-FAKE-key"));
        assert_ne!(bearer_fingerprint("one-FAKE-key"), bearer_fingerprint("two-FAKE-key"));
    }

    /// No fingerprint contains any run of its credential longer than three characters: neither a short key (which the
    /// old 12-character tail printed whole) nor a fragment of a long one.
    #[test]
    fn fingerprint_discloses_no_fragment_of_the_credential() {
        for key in [
            "k1",
            "short-FAKE",
            "123456789012",
            "eyJ0eXAiOiJh.shared-head.tail-distinct-FAKE",
            "fuigo-key-aaaaaaaaaaadistinct1",
        ] {
            let fp = bearer_fingerprint(key);
            let chars: Vec<char> = key.chars().collect();
            for w in chars.windows(4) {
                let frag: String = w.iter().collect();
                assert!(!fp.contains(&frag), "fingerprint {fp:?} of {key:?} contains {frag:?}");
            }
        }
    }
}
