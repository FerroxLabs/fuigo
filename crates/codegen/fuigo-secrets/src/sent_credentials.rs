//! Exact-match scrub of the credentials this process actually sent upstream (P70b, option A).
//!
//! The threat: an upstream (a model provider, a proxy) echoes a credential the client sent back in its error text, and
//! that text is shown to the user, written to a log or exported as telemetry. The design Sean accepted for P70b:
//!
//! 1. **Classify first.** Nothing here runs before the error is classified. Error text stays byte-for-byte what the
//!    upstream sent while the sampler and the shell decide what the error is (retry, compact, strip images, re-auth).
//! 2. **Scrub only at display and log sinks.** [`scrub`] / [`scrub_bytes`] / [`ScrubWriter`] are called where text
//!    leaves the process or reaches a person: log writers, telemetry exporters, the ACP error and notification rails.
//! 3. **Exact match on credentials actually sent.** [`record`] is called with the values the client put on the wire;
//!    only those values, verbatim, are replaced. Values shorter than [`MIN_CREDENTIAL_CHARS`] are not recorded.
//! 4. **No token-shaped heuristic.** Nothing here guesses that a string "looks like" a key.
//!
//! Two spellings other than the value itself are matched, because the code this process runs produces them:
//! the value's JSON string escaping, once and twice (a JSON log record, a `{:?}` field, a JSON string logged inside a
//! JSON record); and the beginning of the value cut off by a truncation mark (`…`), because error text is capped
//! before it is classified and the cap can fall inside an echoed credential (see [`MIN_TRUNCATED_PREFIX_CHARS`]).
//!
//! What this does NOT cover, by design: a credential re-encoded by the upstream (base64, percent-encoding, case
//! changes), a credential split across two separately written log records, and a credential that was never recorded
//! (a request made by code that does not call [`record`]).

use std::borrow::Cow;
use std::collections::VecDeque;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Credentials shorter than this (in `char`s) are not recorded, so they are never scrubbed.
/// An exact match on a short value would rewrite ordinary words in error text, and a short value is guessable anyway.
pub const MIN_CREDENTIAL_CHARS: usize = 8;

/// What a scrubbed credential is replaced with.
pub const PLACEHOLDER: &str = "<redacted>";

/// Returned in place of the whole text when replacing every recorded credential still leaves one in the output
/// (a credential that is itself, or is formed by, the placeholder). See [`scrub`].
pub const WITHHELD: &str = "<text withheld: it contained a credential>";

/// The mark this codebase's text caps append (`fuigo-sampling-types` user-facing error cap, `fuigo-tools`
/// `truncate_str_with_marker`, the hook payload clips).
pub const TRUNCATION_MARK: &str = "\u{2026}";

/// A cap that falls inside an echoed credential leaves its beginning followed by [`TRUNCATION_MARK`]. That prefix is
/// replaced when it is at least this many `char`s long: the same floor as for a whole credential, so ordinary text
/// that happens to end in a mark is rewritten only if it ends with eight characters of something that was sent.
/// A shorter cut-off beginning (seven characters of a key at most) stays.
pub const MIN_TRUNCATED_PREFIX_CHARS: usize = MIN_CREDENTIAL_CHARS;

/// How many spellings older than [`RETAIN`] are remembered. The oldest is forgotten first.
pub const CAPACITY: usize = 256;

/// Hard bound on remembered spellings whatever their age, so a process that sends an endless stream of distinct
/// values cannot grow the registry (and the per-record scan) without limit. Beyond it the oldest is forgotten even
/// within [`RETAIN`].
pub const MAX_SPELLINGS: usize = 4096;

/// A spelling recorded (or recorded again) within this long is never forgotten, whatever the count: a request in
/// flight, or an error still on its way to a sink, must find its credential. Older ones are bounded by [`CAPACITY`].
pub const RETAIN: Duration = Duration::from_secs(60 * 60);

struct Entry {
    value: Box<str>,
    recorded: Instant,
}

/// Most recently recorded at the back.
static SENT: RwLock<VecDeque<Entry>> = RwLock::new(VecDeque::new());

/// Remember `value` as a credential this process sent upstream.
/// No-op for values shorter than [`MIN_CREDENTIAL_CHARS`]. Recording a value again moves it to the back.
///
/// The value's JSON string escaping (`"` → `\"`, `\` → `\\`) is recorded too when it differs, once and twice over:
/// that is how the same value appears in a JSON log record or a `{:?}` log field, and in a JSON string logged inside
/// a JSON record (the sampler logs raw SSE JSON through a JSON log layer).
pub fn record(value: &str) {
    if value.chars().count() < MIN_CREDENTIAL_CHARS {
        return;
    }
    let now = Instant::now();
    let mut sent = SENT
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    insert(&mut sent, value, now);
    let once = json_escaped(value);
    if once != value {
        let twice = json_escaped(&once);
        insert(&mut sent, &once, now);
        insert(&mut sent, &twice, now);
    }
    evict(&mut sent, now);
}

/// `value` as it reads inside a JSON string (without the surrounding quotes).
fn json_escaped(value: &str) -> String {
    let quoted = serde_json::to_string(value).unwrap_or_default();
    quoted
        .get(1..quoted.len().saturating_sub(1))
        .unwrap_or(value)
        .to_owned()
}

fn insert(sent: &mut VecDeque<Entry>, value: &str, now: Instant) {
    if let Some(pos) = sent.iter().position(|e| &*e.value == value) {
        sent.remove(pos);
    }
    sent.push_back(Entry {
        value: value.into(),
        recorded: now,
    });
}

/// Forget the oldest spellings beyond [`CAPACITY`], but never one recorded within [`RETAIN`] of `now`.
fn evict(sent: &mut VecDeque<Entry>, now: Instant) {
    while sent.len() > MAX_SPELLINGS
        || (sent.len() > CAPACITY
            && sent
                .front()
                .is_some_and(|e| now.saturating_duration_since(e.recorded) > RETAIN))
    {
        sent.pop_front();
    }
}

/// Record the credential material in one HTTP header value: the whole value and each credential it is composed of.
///
/// An upstream echoes the credential, not the header: `Bearer abc…` comes back as `abc…`, and
/// `Cookie: session=abc…; theme=dark` as `abc…`. So besides the whole value this records the text after the first
/// space (the token after an auth scheme), every `;`- or `,`-separated part (separators inside a double-quoted
/// string do not split), and for a `name=value` part the value, with a quoted string also recorded without its
/// quotes and backslash escapes. Each is subject to the [`MIN_CREDENTIAL_CHARS`] floor.
pub fn record_header_value(value: &str) {
    record(value);
    if let Some((scheme, token)) = value.split_once(' ') {
        let token = token.trim();
        record(token);
        // `Basic` is base64 of `user:password` (also what reqwest builds from URL userinfo). A server decodes it
        // and can echo either half, so both are recorded as well as the pair.
        if scheme.eq_ignore_ascii_case("basic")
            && let Some(pair) = base64_decode(token).and_then(|b| String::from_utf8(b).ok())
        {
            record_user_password_pair(&pair);
        }
    }
    for part in split_outside_quotes(value) {
        let part = part.trim();
        if part.len() != value.len() {
            record(part);
        }
        if let Some((_, rhs)) = part.split_once('=') {
            let rhs = rhs.trim();
            record(rhs);
            if let Some(quoted) = rhs.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
                record(quoted);
                record(&unescape_quoted_pairs(quoted));
            }
        }
    }
}

/// `user:password`, and each half (split at the first `:`, as HTTP Basic defines it).
fn record_user_password_pair(pair: &str) {
    record(pair);
    if let Some((user, password)) = pair.split_once(':') {
        record(user);
        record(password);
    }
}

/// `value` split at `;` and `,`, except inside a double-quoted string (where `\` escapes the next character).
fn split_outside_quotes(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (i, c) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if quoted && c == '\\' {
            escaped = true;
        } else if c == '"' {
            quoted = !quoted;
        } else if !quoted && (c == ';' || c == ',') {
            parts.push(&value[start..i]);
            start = i + c.len_utf8();
        }
    }
    parts.push(&value[start..]);
    parts
}

/// The content of an HTTP quoted-string with its `\x` quoted-pairs resolved to `x`.
fn unescape_quoted_pairs(quoted: &str) -> String {
    let mut out = String::with_capacity(quoted.len());
    let mut chars = quoted.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.extend(chars.next()),
            c => out.push(c),
        }
    }
    out
}

/// Record the credentials in a proxy URL's userinfo (`http://user:password@proxy:3128`): each half as written and
/// percent-decoded, the pair, and the `Basic` token an HTTP client builds from them.
///
/// The HTTP client adds `Proxy-Authorization` itself, after the request leaves the code that records headers, so a
/// caller that knows the proxy configuration records it here.
pub fn record_proxy_url(proxy_url: &str) {
    // A proxy setting may omit the scheme (`user:password@proxy:3128`; the HTTP stack defaults it to `http`). A
    // URL parser cannot tell such a value from a URL whose scheme is its first word: `http:secret@proxy:3128`
    // parses as the scheme `http` with user name `secret`, while the setting means user `http`, password `secret`.
    // So a value that does not start with `scheme://` is read both ways and both readings are recorded; a value with `://` is a URL.
    let parsed = url::Url::parse(proxy_url).ok().filter(url::Url::has_host);
    let has_scheme = proxy_url.split_once("://").is_some_and(|(scheme, _)| {
        scheme.starts_with(|c: char| c.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    });
    let schemeless = (!has_scheme)
        .then(|| url::Url::parse(&format!("http://{proxy_url}")).ok())
        .flatten();
    for url in parsed.into_iter().chain(schemeless) {
        record_proxy_userinfo(&url);
    }
}

fn record_proxy_userinfo(url: &url::Url) {
    let decode = |raw: &str| -> String {
        let mut out = Vec::with_capacity(raw.len());
        let bytes = raw.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hex = (bytes[i] == b'%')
                .then(|| bytes.get(i + 1..i + 3))
                .flatten()
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok());
            match hex {
                Some(byte) => {
                    out.push(byte);
                    i += 3;
                }
                None => {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    };
    let user = decode(url.username());
    let password = url.password().map(decode).unwrap_or_default();
    if user.is_empty() && password.is_empty() {
        return;
    }
    record(url.username());
    record(url.password().unwrap_or_default());
    let pair = format!("{user}:{password}");
    record_user_password_pair(&pair);
    record(&base64_encode(pair.as_bytes()));
}

/// Record how each recorded credential that occurs in `text` reads after `transform`, when that differs.
///
/// For code that rewrites text BEFORE it reaches a sink and whose output is still classified (so it cannot be
/// scrubbed there): the rewritten spelling is recorded as one more exact match for the sinks. `transform` must be the
/// rewrite applied to the text, minus any length cap (a cap is recognised by its truncation mark).
pub fn record_transformed(text: &str, transform: impl Fn(&str) -> String) {
    let aliases: Vec<String> = {
        let sent = SENT.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        let marks: Vec<usize> = occurrences(text.as_bytes(), TRUNCATION_MARK.as_bytes()).collect();
        let mut aliases = Vec::new();
        for entry in sent.iter() {
            let value: &str = &entry.value;
            for start in occurrences(text.as_bytes(), value.as_bytes()) {
                aliases.push(transform(value));
                aliases.extend(respelled_span(text, start, start + value.len(), &transform));
            }
            // A cap that fell inside the credential left its beginning before a truncation mark (the sinks
            // recognise it by that mark). The rewrite respells that beginning, and the whole credential's
            // respelling need not start with the same text (a service name is rewritten only as a whole word),
            // so the cut beginning is recorded respelled on its own, and the whole credential too.
            for &mark in &marks {
                if let Some(len) = truncated_prefix_len(&text.as_bytes()[..mark], value) {
                    aliases.push(transform(&value[..len]));
                    aliases.push(transform(value));
                    aliases.extend(respelled_span(text, mark - len, mark, &transform));
                }
            }
        }
        aliases
    };
    for alias in aliases {
        record(&alias);
    }
}

/// How the span `text[start..end]` reads in `transform(text)` when the rewrite also takes in text NEXT to the span
/// (a service name that straddles the start of a credential, `inference-` + `api-...`, or its end,
/// `...-inference-ap` + `i`). The span's own respelling cannot show that, so the rewrite is also applied to the text
/// before the span and to the text after it: what `transform(text)` shares with the first at its start and with the
/// second at its end is untouched context, and what lies between is the span as it now reads, together with any
/// rewritten neighbour words. `None` when nothing lies between.
fn respelled_span(
    text: &str,
    start: usize,
    end: usize,
    transform: &impl Fn(&str) -> String,
) -> Option<String> {
    let whole = transform(text);
    let before = transform(text.get(..start)?);
    let after = transform(text.get(end..)?);
    let head: usize = before
        .chars()
        .zip(whole.chars())
        .take_while(|(a, b)| a == b)
        .map(|(c, _)| c.len_utf8())
        .sum();
    let tail: usize = after
        .chars()
        .rev()
        .zip(whole.chars().rev())
        .take_while(|(a, b)| a == b)
        .map(|(c, _)| c.len_utf8())
        .sum();
    let tail = tail.min(whole.len().saturating_sub(head));
    let between = whole.get(head..whole.len() - tail)?.trim();
    (!between.is_empty()).then(|| between.to_owned())
}

/// Standard-alphabet base64 (padding optional); `None` for any other character or an impossible length.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim_end_matches('=');
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for byte in text.bytes() {
        let six = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(six);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from(acc >> bits).ok()?);
            acc &= (1 << bits) - 1;
        }
    }
    (text.len() % 4 != 1).then_some(out)
}

/// Standard-alphabet base64 with padding.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n =
            chunk.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b)) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// True when no credential has been recorded yet; sinks use it to skip work.
pub fn is_empty() -> bool {
    SENT.read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_empty()
}

/// Replace every occurrence of every recorded credential in `text` with [`PLACEHOLDER`].
///
/// Occurrences are found on the original text, overlapping ones included, and every byte any occurrence covers is
/// replaced: a run of covered bytes becomes one placeholder. The beginning of a credential cut off by
/// [`TRUNCATION_MARK`] is covered the same way. If the result still contains a recorded credential (only possible
/// when a credential is, or is formed around, the placeholder text), the whole text is replaced by [`WITHHELD`], or
/// by the empty string if even that contains one. Postcondition: the returned text contains no recorded credential.
pub fn scrub(text: &str) -> Cow<'_, str> {
    match scrub_bytes(text.as_bytes()) {
        // Every replaced range is a whole occurrence of a UTF-8 needle (or of a char-boundary prefix of one) in a
        // UTF-8 haystack, so it starts and ends on char boundaries; the placeholder is ASCII. The result is UTF-8.
        Some(out) => Cow::Owned(
            String::from_utf8(out)
                .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()),
        ),
        None => Cow::Borrowed(text),
    }
}

/// [`scrub`] for an owned string; returns it unchanged when nothing was recorded or nothing matched.
pub fn scrub_owned(text: String) -> String {
    match scrub(&text) {
        Cow::Borrowed(_) => text,
        Cow::Owned(out) => out,
    }
}

/// [`scrub`] in place; returns whether `text` changed.
pub fn scrub_in_place(text: &mut String) -> bool {
    match scrub(text) {
        Cow::Borrowed(_) => false,
        Cow::Owned(out) => {
            *text = out;
            true
        }
    }
}

/// [`scrub`] every string in a JSON value (object keys are left alone); returns whether anything changed.
pub fn scrub_json_strings(value: &mut serde_json::Value) -> bool {
    if is_empty() {
        return false;
    }
    let mut changed = false;
    crate::walk_json_strings(value, &mut |s| changed |= scrub_in_place(s));
    changed
}

/// Byte-level [`scrub`]: `None` when `bytes` contains no recorded credential.
/// Works on bytes that are not UTF-8 (a log record may carry lossy text).
pub fn scrub_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    let sent = SENT.read().unwrap_or_else(|poisoned| poisoned.into_inner());
    if sent.is_empty() {
        return None;
    }
    let marks: Vec<usize> = occurrences(bytes, TRUNCATION_MARK.as_bytes()).collect();
    let mut covered: Vec<(usize, usize)> = Vec::new();
    for entry in sent.iter() {
        let cred = entry.value.as_bytes();
        // Occurrences come in ascending order: merge overlapping ones as they are found, so a dense haystack
        // yields at most one range per disjoint run and not one per occurrence.
        let mut run: Option<(usize, usize)> = None;
        for start in occurrences(bytes, cred) {
            let end = start + cred.len();
            run = match run {
                Some((s, e)) if start <= e => Some((s, e.max(end))),
                Some(done) => {
                    covered.push(done);
                    Some((start, end))
                }
                None => Some((start, end)),
            };
        }
        covered.extend(run);
        for &mark in &marks {
            if let Some(len) = truncated_prefix_len(&bytes[..mark], &entry.value) {
                covered.push((mark - len, mark));
            }
        }
    }
    if covered.is_empty() {
        return None;
    }
    covered.sort_unstable();
    let mut out = Vec::with_capacity(bytes.len());
    let mut cursor = 0;
    let mut i = 0;
    while i < covered.len() {
        let (start, mut end) = covered[i];
        i += 1;
        while i < covered.len() && covered[i].0 <= end {
            end = end.max(covered[i].1);
            i += 1;
        }
        out.extend_from_slice(&bytes[cursor..start]);
        out.extend_from_slice(PLACEHOLDER.as_bytes());
        cursor = end;
    }
    out.extend_from_slice(&bytes[cursor..]);
    if contains_any(&sent, &out) {
        out = if contains_any(&sent, WITHHELD.as_bytes()) {
            Vec::new()
        } else {
            WITHHELD.as_bytes().to_vec()
        };
    }
    Some(out)
}

/// [`scrub_bytes`] for one whole log record: a record that ended with a newline still does (a withheld record must
/// not swallow the line break and join the next record).
pub fn scrub_record(record: &[u8]) -> Option<Vec<u8>> {
    let mut scrubbed = scrub_bytes(record)?;
    if record.ends_with(b"\n") && !scrubbed.ends_with(b"\n") {
        scrubbed.push(b'\n');
    }
    Some(scrubbed)
}

/// Length in bytes of the longest proper prefix of `cred`, at least [`MIN_TRUNCATED_PREFIX_CHARS`] chars long, that
/// `before` (the text up to a truncation mark) ends with.
fn truncated_prefix_len(before: &[u8], cred: &str) -> Option<usize> {
    let floor = cred
        .char_indices()
        .nth(MIN_TRUNCATED_PREFIX_CHARS)
        .map(|(i, _)| i)?;
    cred.char_indices()
        .map(|(i, _)| i)
        .rev()
        .take_while(|&len| len >= floor)
        .find(|&len| before.ends_with(&cred.as_bytes()[..len]))
}

/// The smallest cut point `>= cut` that does not fall strictly inside an occurrence of a recorded credential.
///
/// For code that shortens text ON ITS WAY INTO A LOG (never text that is classified afterwards): a cut through the
/// middle of a credential leaves a prefix with nothing after it to recognise it by. Moving the cut forward to the
/// end of the occurrence keeps the credential whole, so the sink's exact match replaces it. `cut` must be a char
/// boundary of `text`; the result is one too (it is either `cut` or the end of an occurrence).
pub fn safe_cut(text: &str, cut: usize) -> usize {
    let mut cut = cut.min(text.len());
    let sent = SENT.read().unwrap_or_else(|poisoned| poisoned.into_inner());
    if sent.is_empty() {
        return cut;
    }
    // Moving the cut right can land it inside a later, overlapping occurrence: repeat until stable.
    loop {
        let mut moved = false;
        for entry in sent.iter() {
            for start in occurrences(text.as_bytes(), entry.value.as_bytes()) {
                let end = start + entry.value.len();
                if start < cut && cut < end {
                    cut = end;
                    moved = true;
                }
            }
        }
        if !moved {
            return cut;
        }
    }
}

/// `text` shortened to about `max_chars` chars for a log field, never cutting through a recorded credential (the cut
/// moves past it, see [`safe_cut`]). Returns the kept prefix and whether anything was dropped.
pub fn truncate_chars(text: &str, max_chars: usize) -> (&str, bool) {
    match text.char_indices().nth(max_chars) {
        None => (text, false),
        Some((byte_idx, _)) => {
            let cut = safe_cut(text, byte_idx);
            (&text[..cut], cut < text.len())
        }
    }
}

/// Start offsets of every occurrence of `needle` in `hay`, ascending, overlapping occurrences included.
fn occurrences<'a>(hay: &'a [u8], needle: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    let n = needle.len();
    let last = if n == 0 || n > hay.len() {
        None
    } else {
        Some(hay.len() - n)
    };
    let first = needle.first().copied();
    (0..=last.unwrap_or(0))
        .filter(move |_| last.is_some())
        .filter(move |&i| Some(hay[i]) == first && &hay[i..i + n] == needle)
}

fn contains_any(sent: &VecDeque<Entry>, bytes: &[u8]) -> bool {
    sent.iter()
        .any(|e| occurrences(bytes, e.value.as_bytes()).next().is_some())
}

/// An [`std::io::Write`] that scrubs recorded credentials out of every buffer before passing it on.
///
/// Each `write` call is scrubbed on its own and passed to the inner writer whole (`write_all`); it always reports
/// the full input length, so a caller's `write_all` never splits one buffer across two calls. A formatted log record
/// is written in one call by `tracing_subscriber`'s fmt layer and by `tracing_appender`'s worker, so a record is
/// scrubbed as a whole. A credential split across two separate `write` calls is not found (see the module docs).
/// A buffer that ended with a newline still does after scrubbing, so a withheld record stays one line.
pub struct ScrubWriter<W> {
    inner: W,
}

impl<W> ScrubWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: std::io::Write> std::io::Write for ScrubWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match scrub_record(buf) {
            Some(scrubbed) => self.inner.write_all(&scrubbed)?,
            None => self.inner.write_all(buf)?,
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Test-only: forget every recorded credential. The registry is process-wide; tests that assert on it reset it.
#[doc(hidden)]
pub fn clear_for_tests() {
    SENT.write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::sync::Mutex;

    /// The registry is process-wide; serialize the tests that reset it. Every value recorded here is distinctive
    /// (`p70b…`, mixed-case runs) so the sanitizer tests running beside these never contain one.
    static LOCK: Mutex<()> = Mutex::new(());

    const KEY: &str = "p70b-key-Xq7Lm2Vz";

    fn fresh() -> std::sync::MutexGuard<'static, ()> {
        let guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_for_tests();
        guard
    }

    #[test]
    fn nothing_recorded_changes_nothing() {
        let _g = fresh();
        assert!(matches!(
            scrub("Incorrect API key p70b-key-Xq7Lm2Vz"),
            Cow::Borrowed(_)
        ));
        assert!(is_empty());
    }

    #[test]
    fn a_recorded_credential_is_replaced_everywhere_it_occurs() {
        let _g = fresh();
        record(KEY);
        assert_eq!(
            scrub(&format!("key {KEY} rejected; {KEY} again")),
            "key <redacted> rejected; <redacted> again"
        );
    }

    #[test]
    fn a_short_value_is_not_recorded() {
        let _g = fresh();
        record("QwErTy0");
        assert!(is_empty());
        assert_eq!(scrub("QwErTy0"), "QwErTy0");
        record("QwErTy01");
        assert_eq!(scrub("QwErTy01"), PLACEHOLDER);
    }

    #[test]
    fn the_minimum_is_counted_in_chars_not_bytes() {
        let _g = fresh();
        // 7 chars, 14 bytes: below the minimum.
        record("ééééééé");
        assert!(is_empty());
    }

    #[test]
    fn only_the_exact_value_matches_no_token_heuristic() {
        let _g = fresh();
        record(KEY);
        // Token-shaped text that is not a recorded credential stays.
        let text = "gpt-4o-mini-2024-07-18 sk-other-9876543210 messages.0.content.4.image.source.base64.data";
        assert_eq!(scrub(text), text);
        // Case and encoding variants are not the value that was sent.
        assert_eq!(scrub("P70B-KEY-XQ7LM2VZ"), "P70B-KEY-XQ7LM2VZ");
    }

    #[test]
    fn overlapping_credentials_are_covered_as_one_run() {
        let _g = fresh();
        record("QwErTy01");
        record("Ty01UiOp");
        assert_eq!(scrub("x QwErTy01UiOp y"), "x <redacted> y");
    }

    #[test]
    fn overlapping_occurrences_of_one_credential_are_all_covered() {
        let _g = fresh();
        record("ZqZqZqZq");
        assert_eq!(scrub("ZqZqZqZqZq!"), "<redacted>!");
    }

    #[test]
    fn adjacent_occurrences_become_one_placeholder_and_separated_ones_two() {
        let _g = fresh();
        record(KEY);
        assert_eq!(scrub(&format!("{KEY}{KEY}")), "<redacted>");
        assert_eq!(scrub(&format!("{KEY} {KEY}")), "<redacted> <redacted>");
        // Two different credentials that touch are one covered run too.
        record("QwErTy01");
        assert_eq!(scrub(&format!("a QwErTy01{KEY} b")), "a <redacted> b");
    }

    #[test]
    fn a_credential_that_is_the_placeholder_withholds_the_text() {
        let _g = fresh();
        record(PLACEHOLDER);
        assert_eq!(scrub("echo <redacted> back"), WITHHELD);
    }

    #[test]
    fn a_credential_formed_by_the_placeholder_withholds_the_text() {
        let _g = fresh();
        record("QwErTy01");
        record("x<redacted>y");
        // Replacing `QwErTy01` alone would produce `x<redacted>y`.
        let out = scrub("xQwErTy01y");
        assert!(!out.contains("x<redacted>y"), "{out}");
        assert_eq!(out, WITHHELD);
    }

    #[test]
    fn a_credential_inside_the_withheld_text_yields_empty() {
        let _g = fresh();
        record(PLACEHOLDER);
        record("withheld");
        assert_eq!(scrub("<redacted>"), "");
    }

    #[test]
    fn a_header_value_records_the_token_after_the_scheme() {
        let _g = fresh();
        record_header_value("Bearer   p70b-tok-Hs8Kd3Wn ");
        assert_eq!(scrub("bad token p70b-tok-Hs8Kd3Wn"), "bad token <redacted>");
        assert_eq!(scrub("[p70b-tok-Hs8Kd3Wn]"), "[<redacted>]");
    }

    #[test]
    fn a_basic_header_records_the_pair_and_both_halves() {
        let _g = fresh();
        // base64("p70b-proxy-user:p70b-proxy-pass-9")
        record_header_value("Basic cDcwYi1wcm94eS11c2VyOnA3MGItcHJveHktcGFzcy05");
        assert_eq!(
            scrub("user p70b-proxy-user denied"),
            "user <redacted> denied"
        );
        assert_eq!(
            scrub("bad password p70b-proxy-pass-9"),
            "bad password <redacted>"
        );
        assert_eq!(
            scrub("cDcwYi1wcm94eS11c2VyOnA3MGItcHJveHktcGFzcy05"),
            "<redacted>"
        );
        assert_eq!(base64_decode("Zm9vYg=="), Some(b"foob".to_vec()));
        assert_eq!(base64_decode("Zm9vYg"), Some(b"foob".to_vec()));
        assert_eq!(base64_decode("Zm9v"), Some(b"foo".to_vec()));
        assert_eq!(base64_decode("Zm9vY"), None);
        assert_eq!(base64_decode("Zm9v!"), None);
        assert_eq!(scrub("p70b-proxy-user:p70b-proxy-pass-9"), "<redacted>");
        // Not Basic: the token is not decoded.
        clear_for_tests();
        record_header_value("Bearer cDcwYi1wcm94eS11c2VyOnA3MGItcHJveHktcGFzcy05");
        assert_eq!(scrub("p70b-proxy-user"), "p70b-proxy-user");
        // Any letter case of the scheme; `+` and `/` of the alphabet; the password keeps its own colons.
        clear_for_tests();
        let token = base64_encode("p70b~~user?>:p70b:pass:with~~colons?>".as_bytes());
        assert!(token.contains('+') && token.contains('/'), "{token}");
        record_header_value(&format!("bAsIc {token}"));
        assert_eq!(scrub("user p70b~~user?>"), "user <redacted>");
        assert_eq!(scrub("p70b:pass:with~~colons?>"), "<redacted>");
        assert_eq!(
            base64_decode(&token).unwrap(),
            b"p70b~~user?>:p70b:pass:with~~colons?>"
        );
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
    }

    #[test]
    fn a_quoted_header_parameter_keeps_its_separators_and_loses_its_escapes() {
        let _g = fresh();
        record_header_value(
            r#"scheme token="p70b-alpha,beta;gamma", other="p70b-esc\"aped\\value""#,
        );
        assert_eq!(
            scrub("bad credential p70b-alpha,beta;gamma"),
            "bad credential <redacted>"
        );
        assert_eq!(scrub(r#"bad p70b-esc"aped\value"#), "bad <redacted>");
        // ... and as it was written inside the quotes, escapes included.
        assert_eq!(
            scrub(r#"bad p70b-esc\"aped\\value here"#),
            "bad <redacted> here"
        );
        assert_eq!(
            split_outside_quotes(r#"a="x,y";b=1, c"#),
            vec![r#"a="x,y""#, "b=1", " c"]
        );
    }

    #[test]
    fn a_proxy_url_records_its_userinfo_and_the_basic_token_built_from_it() {
        let _g = fresh();
        record_proxy_url("http://p70b-proxy-user:p%40ss-p70b-word@proxy.invalid:3128");
        assert_eq!(scrub("407 for p70b-proxy-user"), "407 for <redacted>");
        assert_eq!(
            scrub("bad password p@ss-p70b-word"),
            "bad password <redacted>"
        );
        assert_eq!(scrub("p%40ss-p70b-word"), "<redacted>");
        let token = base64_encode(b"p70b-proxy-user:p@ss-p70b-word");
        assert_eq!(
            scrub(&format!("Basic {token} rejected")),
            "Basic <redacted> rejected"
        );
        // The scheme may be omitted, as the HTTP stack accepts it.
        clear_for_tests();
        record_proxy_url("p70b-bare-user:p70b-bare-password@proxy.invalid:3128");
        assert_eq!(scrub("407 p70b-bare-password"), "407 <redacted>");
        assert_eq!(scrub("user p70b-bare-user"), "user <redacted>");
        // No userinfo, or not a URL: nothing recorded.
        clear_for_tests();
        record_proxy_url("http://proxy.invalid:3128");
        record_proxy_url("proxy.invalid:3128");
        record_proxy_url("not a url");
        assert!(is_empty());
    }

    #[test]
    fn a_rewritten_spelling_is_recorded_for_credentials_the_text_contains() {
        let _g = fresh();
        record("p70b  spaced   credential");
        record("p70b-absent-credential");
        let collapse = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
        let raw = "upstream said: p70b  spaced   credential rejected";
        record_transformed(raw, collapse);
        assert_eq!(scrub(&collapse(raw)), "upstream said: <redacted> rejected");
        // Only credentials present in the text get an alias; an unchanged spelling adds nothing.
        assert_eq!(SENT.read().unwrap().len(), 3);
    }

    #[test]
    fn a_header_value_records_each_cookie_and_parameter_value() {
        let _g = fresh();
        record_header_value(r#"session=p70bsessionvalue; theme=dark, token="p70bquotedvalue""#);
        assert_eq!(scrub("echo p70bsessionvalue"), "echo <redacted>");
        assert_eq!(scrub("echo p70bquotedvalue"), "echo <redacted>");
        assert_eq!(scrub("session=p70bsessionvalue"), "<redacted>");
        // A short value stays unrecorded on its own.
        assert_eq!(scrub("mode: dark"), "mode: dark");
    }

    #[test]
    fn eviction_spares_everything_recorded_within_the_retention_window() {
        let _g = fresh();
        let t0 = Instant::now();
        let mut sent = VecDeque::new();
        for i in 0..CAPACITY + 50 {
            insert(&mut sent, &format!("p70b-cred-{i:04}"), t0);
        }
        // All fresh: nothing is forgotten, whatever the count (a request in flight keeps its credential).
        evict(&mut sent, t0 + RETAIN);
        assert_eq!(sent.len(), CAPACITY + 50);
        // ... up to the hard bound: beyond MAX_SPELLINGS the oldest goes even inside the window.
        let mut flood = VecDeque::new();
        for i in 0..MAX_SPELLINGS + 3 {
            insert(&mut flood, &format!("p70b-flood-{i:05}"), t0);
        }
        evict(&mut flood, t0);
        assert_eq!(flood.len(), MAX_SPELLINGS);
        assert_eq!(&*flood.front().unwrap().value, "p70b-flood-00003");
        // Past the window, the oldest beyond the capacity go.
        evict(&mut sent, t0 + RETAIN + Duration::from_secs(1));
        assert_eq!(sent.len(), CAPACITY);
        assert_eq!(&*sent.front().unwrap().value, "p70b-cred-0050");
        // Recording a value again refreshes it: it moves to the back with the new time.
        let later = t0 + RETAIN + Duration::from_secs(2);
        insert(&mut sent, "p70b-cred-0050", later);
        insert(&mut sent, "p70b-one-more", later);
        evict(&mut sent, later);
        assert_eq!(sent.len(), CAPACITY);
        assert_eq!(&*sent.front().unwrap().value, "p70b-cred-0052");
        assert_eq!(&*sent.back().unwrap().value, "p70b-one-more");
    }

    /// Through `record` itself: the hard bound holds for the process-wide registry.
    #[test]
    fn recording_enforces_the_hard_bound() {
        let _g = fresh();
        for i in 0..MAX_SPELLINGS + 5 {
            record(&format!("p70b-bound-{i:05}"));
        }
        assert_eq!(SENT.read().unwrap().len(), MAX_SPELLINGS);
        assert_eq!(scrub("p70b-bound-00004"), "p70b-bound-00004");
        assert_eq!(scrub("p70b-bound-00005"), PLACEHOLDER);
    }

    #[test]
    fn recording_does_not_duplicate_a_value() {
        let _g = fresh();
        record(KEY);
        record("p70b-other-credential");
        record(KEY);
        let sent = SENT.read().unwrap();
        assert_eq!(sent.len(), 2);
        assert_eq!(&*sent.back().unwrap().value, KEY);
    }

    #[test]
    fn safe_cut_never_splits_a_credential() {
        let _g = fresh();
        record("P70B-SECRET-Jw5");
        let text = "prefix P70B-SECRET-Jw5 suffix";
        let start = text.find("P70B").unwrap();
        let end = start + "P70B-SECRET-Jw5".len();
        assert_eq!(safe_cut(text, start + 3), end);
        assert_eq!(safe_cut(text, start), start);
        assert_eq!(safe_cut(text, end), end);
        assert_eq!(safe_cut(text, 2), 2);
        let (kept, cut) = truncate_chars(text, start + 4);
        assert!(cut);
        assert_eq!(kept, "prefix P70B-SECRET-Jw5");
        assert_eq!(truncate_chars(text, 1000), (text, false));
        // A cut moved to the very end drops nothing.
        assert_eq!(
            truncate_chars("x P70B-SECRET-Jw5", 4),
            ("x P70B-SECRET-Jw5", false)
        );
    }

    #[test]
    fn safe_cut_follows_a_chain_of_overlapping_occurrences_in_either_recording_order() {
        for order in [["QwErTy01", "Ty01UiOp"], ["Ty01UiOp", "QwErTy01"]] {
            let _g = fresh();
            for cred in order {
                record(cred);
            }
            let text = "__QwErTy01UiOp__";
            // Cut inside `QwErTy01` (ends at 10); moving to 10 lands inside `Ty01UiOp` (ends at 14).
            assert_eq!(safe_cut(text, 5), 14, "{order:?}");
        }
    }

    #[test]
    fn the_beginning_of_a_credential_cut_off_by_a_truncation_mark_is_replaced() {
        let _g = fresh();
        record(KEY);
        // A cap fell inside the echoed key: `p70b-key-Xq` then the mark.
        assert_eq!(
            scrub("Incorrect API key provided: p70b-key-Xq\u{2026}"),
            "Incorrect API key provided: <redacted>\u{2026}"
        );
        assert_eq!(
            scrub("bad p70b-key\u{2026} [+42 chars]"),
            "bad <redacted>\u{2026} [+42 chars]"
        );
        // Fewer than MIN_TRUNCATED_PREFIX_CHARS (8) chars of it: left alone.
        assert_eq!(scrub("bad p70b-ke\u{2026}"), "bad p70b-ke\u{2026}");
        // Text that merely ends with a truncation mark is untouched.
        assert_eq!(scrub("something else\u{2026}"), "something else\u{2026}");
        // The same prefix with no mark after it is not a truncated credential.
        assert_eq!(scrub("p70b-key-Xq and more"), "p70b-key-Xq and more");
    }

    #[test]
    fn the_longest_cut_off_beginning_is_the_one_replaced() {
        let _g = fresh();
        record("QwErTy01QwErTy01-tail");
        // Both `QwErTy01` and `QwErTy01QwErTy01` are beginnings of the credential that the text ends with.
        assert_eq!(scrub("x QwErTy01QwErTy01\u{2026}"), "x <redacted>\u{2026}");
    }

    #[test]
    fn scrub_writer_scrubs_each_buffer_and_reports_its_full_length() {
        let _g = fresh();
        record(KEY);
        let mut w = ScrubWriter::new(Vec::new());
        let line = format!("ERROR upstream said: {KEY}\n");
        assert_eq!(w.write(line.as_bytes()).unwrap(), line.len());
        w.write_all(b"clean line\n").unwrap();
        assert_eq!(
            String::from_utf8(w.into_inner()).unwrap(),
            "ERROR upstream said: <redacted>\nclean line\n"
        );
    }

    #[test]
    fn scrub_writer_keeps_a_withheld_record_on_its_own_line() {
        let _g = fresh();
        record(PLACEHOLDER);
        let mut w = ScrubWriter::new(Vec::new());
        w.write_all(b"said <redacted>\n").unwrap();
        w.write_all(b"next\n").unwrap();
        assert_eq!(
            String::from_utf8(w.into_inner()).unwrap(),
            format!("{WITHHELD}\nnext\n")
        );
        assert_eq!(
            scrub_record(b"said <redacted>\n"),
            Some(format!("{WITHHELD}\n").into_bytes())
        );
        assert_eq!(
            scrub_record(b"said <redacted>"),
            Some(WITHHELD.as_bytes().to_vec())
        );
        assert_eq!(scrub_record(b"clean\n"), None);
    }

    #[test]
    fn scrub_bytes_handles_text_that_is_not_utf8() {
        let _g = fresh();
        record(KEY);
        let mut bytes = b"\xff\xfe key=".to_vec();
        bytes.extend_from_slice(KEY.as_bytes());
        bytes.push(0xff);
        let out = scrub_bytes(&bytes).expect("matched");
        assert_eq!(out, b"\xff\xfe key=<redacted>\xff");
    }

    /// A JSON log record or a `{:?}` field escapes `"` and `\`; a JSON string logged inside a JSON record escapes
    /// them twice. Those spellings are matched too.
    #[test]
    fn a_credential_needing_json_escapes_is_found_in_its_escaped_forms() {
        let _g = fresh();
        let cred = r#"p70b"pa\ss-word"#;
        record(cred);
        let json_line = serde_json::json!({ "msg": format!("rejected {cred}") }).to_string();
        let out = String::from_utf8(scrub_bytes(json_line.as_bytes()).expect("matched")).unwrap();
        assert_eq!(out, r#"{"msg":"rejected <redacted>"}"#);
        assert_eq!(
            scrub(&format!("{:?}", format!("x {cred}"))),
            r#""x <redacted>""#
        );
        assert_eq!(scrub(&format!("raw {cred}")), "raw <redacted>");
        // JSON inside JSON: an SSE payload logged as a string field of a JSON log record.
        let nested = serde_json::json!({ "data": json_line }).to_string();
        let out = scrub(&nested).into_owned();
        assert!(!out.contains("pa"), "{out}");
        let parsed: serde_json::Value = serde_json::from_str(&out).expect("still JSON");
        let inner: serde_json::Value =
            serde_json::from_str(parsed["data"].as_str().unwrap()).expect("inner still JSON");
        assert_eq!(inner["msg"], "rejected <redacted>");
    }

    /// The telemetry chokepoint (`redact_secrets`, used by the OTLP, Sentry and Mixpanel scrubs) applies the exact
    /// match too, including to a credential no secret-shape pattern recognises.
    #[test]
    fn the_telemetry_scrub_replaces_a_recorded_credential_of_no_known_shape() {
        let _g = fresh();
        let text = "upstream: proxy word p70bplainword12 rejected";
        assert_eq!(crate::redact_secrets(text), text);
        record("p70bplainword12");
        assert_eq!(
            crate::redact_secrets(text),
            "upstream: proxy word <redacted> rejected"
        );
        let mut value = serde_json::json!({"error": {"message": text}});
        crate::redact_json_string_values(&mut value);
        assert_eq!(
            value["error"]["message"],
            "upstream: proxy word <redacted> rejected"
        );
    }

    #[test]
    fn json_strings_are_scrubbed_in_place_and_keys_are_left_alone() {
        let _g = fresh();
        let mut clean = serde_json::json!({"message": "nothing recorded yet"});
        assert!(!scrub_json_strings(&mut clean));
        record("p70b-json-cred-01");
        let mut value = serde_json::json!({
            "p70b-json-cred-01": "key position",
            "message": "bad p70b-json-cred-01",
            "list": ["p70b-json-cred-01", 3, {"deep": "x p70b-json-cred-01 y"}],
        });
        assert!(scrub_json_strings(&mut value));
        assert_eq!(
            value,
            serde_json::json!({
                "p70b-json-cred-01": "key position",
                "message": "bad <redacted>",
                "list": ["<redacted>", 3, {"deep": "x <redacted> y"}],
            })
        );
        assert!(!scrub_json_strings(&mut value));
        let mut text = String::from("plain");
        assert!(!scrub_in_place(&mut text));
        let mut text = String::from("see p70b-json-cred-01");
        assert!(scrub_in_place(&mut text));
        assert_eq!(text, "see <redacted>");
        assert_eq!(
            scrub_owned("see p70b-json-cred-01".to_owned()),
            "see <redacted>"
        );
        assert_eq!(scrub_owned("plain".to_owned()), "plain");
    }

    #[test]
    fn a_multibyte_credential_is_replaced_on_char_boundaries() {
        let _g = fresh();
        record("clé-secrète-été");
        assert_eq!(scrub("é clé-secrète-été é"), "é <redacted> é");
        // Truncated inside it, on a char boundary of the credential (8 chars kept).
        assert_eq!(scrub("é clé-secr\u{2026}"), "é <redacted>\u{2026}");
    }
}
