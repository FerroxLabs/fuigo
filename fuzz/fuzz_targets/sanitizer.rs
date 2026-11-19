#![no_main]
//! The secret sanitizer, fuzzed against the safety contract (Sean, 2026-11-18; also in RELEASE.md, fuzz step).
//!
//! BLOCKING (an artifact; the release does not ship with one):
//! - a panic, anywhere in the sanitizer;
//! - a secret still visible: a known secret shape or a URL userinfo that survives, a credential the independent
//!   `url`-crate oracle reads out of the input, or a value hidden by the assignment oracle (a last line's
//!   `KEY=secret` behind earlier text), over arbitrary bytes and over complete URLs the fuzz bytes build;
//! - super-linear time: libFuzzer's `-timeout` (10 s in `scripts/fuzz/run-all.sh`) on any input, and output that
//!   grows beyond `4 * input + 256` bytes;
//! - a regression against the frozen 1.0.45 redactor: anything 1.0.45 removed that survives. That oracle is the
//!   frozen copy compiled only into the crate's tests, so it is gated by the differential unit test
//!   (`cargo test -p fuigo-secrets`, plus one `SANITIZER_DIFFERENTIAL_INPUTS=100000` run per change), not here.
//!
//! NOT BLOCKING: idempotence (`redact(redact(x)) != redact(x)`). Each distinct input that breaks it is counted and
//! printed once to stderr as `IDEMPOTENCE_WARN <hex16> <function>` (FNV-1a of the input), and the run goes on;
//! `run-all.sh` reports the count per target. A second pass that still changes something can only redact more:
//! the callers that re-scrub (fuigo-telemetry `sentry.rs`, fuigo-memory `safety.rs`) treat any change as "still
//! secret" and block the text, which fails safe.

use fuigo_secrets::*;
use libfuzzer_sys::fuzz_target;

/// Idempotence is a warning, not a crash (see the contract above): one stderr line per distinct input and function.
fn idempotence_warn(name: &str, input: &str) {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<HashSet<u64>>> = OnceLock::new();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.bytes().chain([0]).chain(input.bytes()) {
        hash = (hash ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    let mut seen = SEEN
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if seen.len() < 1 << 16 && seen.insert(hash) {
        eprintln!("IDEMPOTENCE_WARN {hash:016x} {name}");
    }
}

fn check(name: &str, input: &str, f: impl Fn(&str) -> String) {
    let once = f(input);
    assert!(
        once.len() <= input.len() * 4 + 256,
        "{name}: {} bytes grew to {}",
        input.len(),
        once.len()
    );
    if f(&once) != once {
        idempotence_warn(name, input);
    }
}

fuzz_target!(|data: &[u8]| {
    check_generated(data);
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = opens_private_key_block(s);
    check_no_leak(s, &redact_secrets(s));
    // u46 r4: what a last line loses to the scrub on its own (a `KEY=secret` value) stays hidden behind arbitrary
    // earlier text (a path-less URL line used to eat the key name, and the value then survived). Keeping the key name
    // is pinned by unit tests; it cannot be required here, because an earlier line can open an authority that the
    // parser continues into this line, and that line is then a userinfo removed whole.
    if let Some((head, line)) = s.rsplit_once('\n') {
        if !head.contains("-----") && !line.contains("[REDACTED") {
            let alone = redact_secrets(line);
            let prefix = line
                .bytes()
                .zip(alone.bytes())
                .take_while(|(a, b)| a == b)
                .count();
            let suffix = line.as_bytes()[prefix..]
                .iter()
                .rev()
                .zip(alone.as_bytes()[prefix.min(alone.len())..].iter().rev())
                .take_while(|(a, b)| a == b)
                .count();
            let hidden = line.get(prefix..line.len() - suffix).unwrap_or("");
            // The byte diff cannot tell input from marker: a line that ends in part of a marker (`#redac://h/#redacte`)
            // yields a "hidden" span that the line scrubbed alone also prints (`://h/#redacted`). Only text the line alone
            // really hides is checked.
            if hidden.chars().count() >= 3
                && s.matches(hidden).count() == 1
                && !alone.contains(hidden)
            {
                let whole = redact_secrets(s);
                assert!(
                    !whole.contains(hidden),
                    "{hidden:?} survived behind earlier text for {s:?}: {whole:?}"
                );
            }
        }
    }
    if s.len() <= 512 {
        check_parsed_credentials(s, &redact_secrets(s));
    }
    check("redact_secrets", s, |x| redact_secrets(x).into_owned());
    check("redact_credential_shapes", s, |x| {
        redact_credential_shapes(x).into_owned()
    });
    check("redact_private_key_blocks", s, |x| {
        redact_private_key_blocks(x).into_owned()
    });
    check("redact_user_paths", s, |x| {
        redact_user_paths(x).into_owned()
    });

    let mut value = serde_json::Value::String(s.to_owned());
    redact_json_string_values(&mut value);
    let mut again = value.clone();
    redact_json_string_values(&mut again);
    if value != again {
        idempotence_warn("redact_json_string_values", s);
    }

    if let Ok(mut url) = url::Url::parse(s) {
        redact_url(&mut url);
    }
});

/// The leak check stays strict and does not go through the normaliser: a secret of a shape this target knows that is in the
/// input must not be in the output, and no `scheme://user@` authority may survive `redact_secrets`.
fn check_no_leak(input: &str, output: &str) {
    use std::sync::LazyLock;
    static SECRETS: LazyLock<regex::Regex> = LazyLock::new(|| {
        // Word-anchored like the sanitizer's own patterns (`BEAKIA...` glued to a word is not a key ID to it).
        regex::Regex::new(concat!(
            r"\bAKIA",
            r"[0-9A-Z]{16}\b|\bgh",
            "p_[A-Za-z0-9]{36}"
        ))
        .unwrap()
    });
    static USERINFO: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"([A-Za-z][A-Za-z0-9+.\-]*):([/\\]{2,})([^/?#\s]*)@").unwrap()
    });
    for m in SECRETS.find_iter(input) {
        // A key repeated inside a longer glued run (`AKIA...EXAKIA...`, no word boundary) is not one to the sanitizer.
        if input.matches(m.as_str()).count() != 1 {
            continue;
        }
        assert!(
            !output.contains(m.as_str()),
            "secret survived for {input:?}: {output:?}"
        );
    }
    // As the scanner reads it (sanitizer.rs `strip_userinfo`): after a special scheme any run of `/` and `\` starts the
    // authority and `\` ends it; after any other scheme only `//` starts one and `\` is part of it (`ab:\\u@h` has none).
    for caps in USERINFO.captures_iter(output) {
        let scheme = caps[1].to_ascii_lowercase();
        let special = ["http", "https", "ws", "wss", "ftp", "file"].contains(&scheme.as_str());
        let authority = &caps[3];
        let leak = if special {
            authority
                .split('\\')
                .next()
                .is_some_and(|head| head.contains('@'))
                || !authority.contains('\\')
        } else {
            // `//` then a further `/` is an empty authority (`ab:///x@y` has no userinfo, as for the parser).
            caps[2].starts_with("//") && !caps[2][2..].contains('/')
        };
        assert!(!leak, "userinfo survived for {input:?}: {output:?}");
    }
}

/// Differential property against the `url` crate (the reader a real client uses): if the parser reads a username or
/// password of three or more characters out of the input, or out of a suffix that starts at a scheme token, that
/// credential followed by its delimiter must not survive in the output when it occurs once in the input.
/// TAB, LF and CR are ignored throughout, as the parser ignores them; there is no exception (u46 r3).
fn check_parsed_credentials(input: &str, output: &str) {
    let strip = |t: &str| t.replace(['\t', '\n', '\r'], "");
    let (flat, out) = (strip(input), strip(output));
    let word_start = |i: usize| {
        input[..i]
            .chars()
            .rev()
            .filter(|ch| *ch != '\t')
            .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-'))
            .all(|ch| !ch.is_ascii_alphabetic())
    };
    let starts = std::iter::once(0).chain(
        input
            .char_indices()
            .filter(|(i, ch)| ch.is_ascii_alphabetic() && word_start(*i))
            .map(|(i, _)| i),
    );
    for i in starts {
        let Ok(url) = url::Url::parse(&input[i..]) else {
            continue;
        };
        // The parser's own form of a credential is percent-encoded (`\u{4}` reads as `%04`); that form is looked for
        // only when it is written so before the URL's first `@`, or it can match unrelated literal text later on.
        let head = input[i..].split('@').next().unwrap_or("");
        for cred in [url.username(), url.password().unwrap_or("")] {
            let decoded = percent_decode(cred);
            let raw = (decoded == cred || head.contains(cred)).then(|| cred.to_owned());
            for cred in raw.into_iter().chain(std::iter::once(decoded)) {
                // The credential itself must occur once: otherwise `{cred}:` can be an unrelated occurrence.
                if cred.chars().count() < 3 || flat.matches(cred.as_str()).count() != 1 {
                    continue;
                }
                for delim in ["@", ":"] {
                    let needle = format!("{cred}{delim}");
                    if flat.matches(&needle).count() == 1 && flat.contains(&format!("{cred}@")) {
                        assert!(
                            !out.contains(&needle),
                            "{cred:?} survived in {output:?} for {input:?}"
                        );
                    }
                }
            }
        }
    }
}

/// The query values the oracle treats as secret: its own copy of the sanitizer's list.
const ORACLE_SECRET_KEYS: [&str; 16] = [
    "access_token",
    "api_key",
    "assertion",
    "auth",
    "client_secret",
    "code",
    "code_verifier",
    "id_token",
    "key",
    "password",
    "refresh_token",
    "requested_token",
    "session_id",
    "state",
    "subject_token",
    "token",
];

/// Structured half of the target (u46 r7): the fuzz bytes drive a generator of complete URLs in prose, and the
/// [`generated_url_leak`] oracle parses each URL it built (no boundary rule shared with the sanitizer); an output that
/// is not a fixed point is an idempotence warning.
fn check_generated(data: &[u8]) {
    // Text between URLs: separators that end a URL, and junk that may glue to its neighbours inside one segment.
    const SEPARATORS: &[&str] = &[" ", "\u{a0}", "\n ", " \t", "\" ", "'", "<", "> ", " | "];
    const AROUND: &[&str] = &["", "", "(", "TOKEN=", "next=", "url:"];
    const AFTER: &[&str] = &["", "", ")", ".", ",", ").", ";"];
    const JUNK: &[&str] = &[
        "see",
        "mail alice@example.com",
        "TOKEN=[REDACTED_SECRET]",
        "DB_PASSWORD=",
        r"C:\Users\me\@types",
        "std::vec::Vec#push",
        "ab:",
        "https://",
        "x://",
        "@",
        "p@ss",
        "#",
        "?code=",
        "\n",
        "%40",
    ];
    let mut at = 0usize;
    let mut next = move || {
        let mut v = 0u64;
        for _ in 0..2 {
            v = v << 8 | u64::from(data.get(at).copied().unwrap_or(0));
            at += 1;
        }
        v
    };
    let mut serial = 0;
    let mut input = String::new();
    let mut urls = Vec::new();
    for segment in 0..1 + next() % 4 {
        if segment > 0 {
            input += SEPARATORS[(next() % SEPARATORS.len() as u64) as usize];
        }
        if next().is_multiple_of(3) {
            input += JUNK[(next() % JUNK.len() as u64) as usize];
            continue;
        }
        let url = generated_url(&mut next, &mut serial);
        input += AROUND[(next() % AROUND.len() as u64) as usize];
        input += &url;
        input += AFTER[(next() % AFTER.len() as u64) as usize];
        urls.push(url);
    }
    let out = redact_secrets(&input).into_owned();
    if let Some(secret) = generated_url_leak(&urls, &input, &out) {
        panic!("oracle: {secret:?} survived in {out:?} for {input:?}");
    }
    if redact_secrets(&out) != out {
        idempotence_warn("generated", &input);
    }
}

/// One complete URL, built part by part (scheme, optional userinfo, host, path, optional query and fragment), so
/// the oracle knows where it ends without any boundary rule of its own (u46 r7: the previous window oracle copied
/// the sanitizer's whitespace cutoff and so missed `?x=1<TAB>&code=`). TAB, LF and CR are dropped in at random
/// places, as the parser ignores them; nothing else that ends a URL in text (a space, a quote, `<`, `>`, a
/// backtick) is ever inside. `serial` makes every secret-looking piece unique.
fn generated_url(next: &mut impl FnMut() -> u64, serial: &mut u32) -> String {
    const SCHEMES: &[&str] = &[
        "https://",
        "HTTPS://",
        "http://",
        "https:",
        "https:/",
        "ftp://",
        "ws://",
        "postgres://",
        "myapp://",
        "Ab+c.d-e://",
    ];
    const HOSTS: &[&str] = &["h", "example.com", "[::1]", "[::1]:8443", "10.0.0.1:5432"];
    const PATHS: &[&str] = &["", "/", "/cb", "/a/b.txt", "/v1/", "/%7Eme"];
    const KEYS: &[&str] = &[
        "token",
        "code",
        "password",
        "api_key",
        "state",
        "Code",
        "to%6Ben",
        "id_token",
        "access_token",
        "a",
        "page",
        "next",
    ];
    fn pick(next: &mut impl FnMut() -> u64, list: &[&'static str]) -> &'static str {
        list[(next() % list.len() as u64) as usize]
    }
    fn secret(serial: &mut u32, shape: &str) -> String {
        *serial += 1;
        match shape {
            "plain" => format!("Sq{serial}xk9"),
            "punct" => format!("S.q{serial}-x_9~"),
            "pct" => format!("Sq%20{serial}x"),
            "pw" => format!("P{serial}w%40rd"),
            "user" => format!("U{serial}name"),
            "frag" => format!("F{serial}opaque"),
            other => other.to_owned(),
        }
    }
    fn pairs(next: &mut impl FnMut() -> u64, serial: &mut u32, url: &mut String) {
        const VALUES: &[&str] = &[
            "plain",
            "plain",
            "punct",
            "pct",
            "[REDACTED_SECRET]",
            "redacted",
            "",
        ];
        for k in 0..1 + next() % 3 {
            if k > 0 {
                url.push('&');
            }
            let key = pick(next, KEYS);
            let value = secret(serial, pick(next, VALUES));
            url.push_str(&format!("{key}={value}"));
        }
    }
    let mut url = pick(next, SCHEMES).to_owned();
    match pick(next, &["none", "user", "both", "pw"]) {
        "user" => url += &format!("{}@", secret(serial, "user")),
        "both" => url += &format!("{}:{}@", secret(serial, "user"), secret(serial, "pw")),
        "pw" => url += &format!(":{}@", secret(serial, "pw")),
        _ => {}
    }
    url += pick(next, HOSTS);
    url += pick(next, PATHS);
    if next().is_multiple_of(2) {
        url.push('?');
        pairs(next, serial, &mut url);
    }
    if next().is_multiple_of(2) {
        url.push('#');
        match pick(next, &["opaque", "pairs", "path"]) {
            "opaque" => url += &secret(serial, "frag"),
            "pairs" => pairs(next, serial, &mut url),
            _ => url += &format!("/route?q={}", secret(serial, "plain")),
        }
    }
    for _ in 0..next() % 4 {
        let at = (next() % (url.len() as u64 + 1)) as usize;
        url.insert(at, ['\t', '\n', '\r'][(next() % 3) as usize]);
    }
    url
}

/// Independent oracle over the [`generated_url`]s of an input: `url::Url::parse` reads each one (the parser drops
/// TAB/LF/CR itself), and its username, password, every query or fragment value under a secret key and, for a URL
/// that is not cannot-be-a-base, its whole fragment (and every piece of it) must be absent from the output with
/// TAB/LF/CR removed. Pieces of fewer than three characters besides any marker, placeholders, and pieces that occur
/// more than once in the input are not looked for. No sanitizer pattern or boundary is reused.
fn generated_url_leak(urls: &[String], input: &str, output: &str) -> Option<String> {
    const MARKER: &str = "[REDACTED_SECRET]";
    let strip = |s: &str| s.replace(['\t', '\n', '\r'], "");
    let (input, output) = (strip(input), strip(output));
    for raw in urls {
        let Ok(url) = url::Url::parse(raw) else {
            continue;
        };
        let mut secrets = Vec::new();
        for cred in [url.username(), url.password().unwrap_or("")] {
            secrets.push(cred.to_owned());
            secrets.push(percent_decode(cred));
        }
        for part in [url.query(), url.fragment()].into_iter().flatten() {
            for pair in part.split('&') {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                if ORACLE_SECRET_KEYS
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case(&percent_decode(k)))
                {
                    secrets.push(v.to_owned());
                    secrets.push(percent_decode(v));
                }
            }
        }
        if let Some(fragment) = url.fragment().filter(|_| !url.cannot_be_a_base()) {
            secrets.push(fragment.to_owned());
            secrets.extend(fragment.split(['&', '=', '/', '?', '#']).map(str::to_owned));
        }
        for secret in secrets {
            if secret.replace(MARKER, "").chars().count() >= 3
                && !MARKER.contains(&secret)
                && !"redacted".contains(&secret)
                && !secret.contains("redacted")
                && !secret.contains(MARKER)
                && input.matches(&secret).count() == 1
                && output.contains(&secret)
            {
                return Some(secret);
            }
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        let pair = if bytes[i] == b'%' && i + 2 < bytes.len() {
            hex(bytes[i + 1]).zip(hex(bytes[i + 2]))
        } else {
            None
        };
        if let Some((h, l)) = pair {
            out.push((h * 16 + l) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
