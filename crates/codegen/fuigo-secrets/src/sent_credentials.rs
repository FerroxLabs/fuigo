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
//! Spellings other than the value itself are matched too:
//! - the value's JSON string escaping, once and twice (a JSON log record, a `{:?}` field, a JSON string logged inside
//!   a JSON record), and the beginning of the value cut off by a truncation mark (`…`), because error text is capped
//!   before it is classified and the cap can fall inside an echoed credential (see [`MIN_TRUNCATED_PREFIX_CHARS`]);
//! - (P163, 1.0.21 K24) the value re-encoded:
//!   - base64, computed once when the value is recorded ([`MAX_ENCODINGS`] forms): the standard and the URL-safe
//!     alphabet, alone (with or without padding) and at each of the three byte alignments inside a larger base64 blob
//!     (HTTP `Basic` of `user:key`, a key inside an encoded JSON document). Inside a blob, the one or two characters
//!     the key shares with its neighbouring bytes stay (at most 4 bits of the key at each end), but the key's bits in
//!     them are checked (an escaped neighbour is read as what it decodes to), so the base64 of a different value that
//!     shares all but those bits is not taken for the key;
//!   - percent-encoding (either hex case, `+` for a space when a recorded spelling has one) and JSON string escaping
//!     (`\uXXXX` in either hex case, `\/`, `\"`, ...), whichever characters the encoder chose to escape, and JSON
//!     escaping applied twice (a JSON string inside JSON). Each is decoded in one linear pass over a text that holds a
//!     `%` or `\`, piece by piece ([`VIEW_WINDOW`]) with no decoding state lost between pieces, and every spelling
//!     above is looked for in the decoded text, so a base64 form percent-encoded in a query string, or written with
//!     `\/` in JSON, is found too.
//!
//!   Each is still an exact match on text derived from a value that was sent, never a guess at what looks like a key.
//!
//! What this does NOT cover, by design: case changes of the value, other encodings (base64 broken across lines, two
//! encodings stacked other than those above), a credential split across two separately written log records, and a
//! credential that was never recorded (a request made by code that does not call [`record`]).

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

/// The most base64 forms derived from one recorded spelling (see the module docs): padded, unpadded and the three
/// in-blob alignments, each in the standard and the URL-safe alphabet. They are computed once, when it is recorded.
pub const MAX_ENCODINGS: usize = 5 * 2;

/// Percent-encoding and JSON escapes are decoded (see the module docs) this many source bytes at a time, keeping only
/// a tail of the decoded text between pieces, so the memory a decoded view takes stays bounded whatever the size of
/// the text.
pub const VIEW_WINDOW: usize = 64 * 1024;

/// How many spellings older than [`RETAIN`] are remembered. The oldest is forgotten first.
pub const CAPACITY: usize = 256;

/// Hard bound on remembered spellings whatever their age, so a process that sends an endless stream of distinct
/// values cannot grow the registry (and the per-record scan) without limit. Beyond it the oldest is forgotten even
/// within [`RETAIN`]. Each spelling carries at most [`MAX_ENCODINGS`] re-encodings.
pub const MAX_SPELLINGS: usize = 4096;

/// A spelling recorded (or recorded again) within this long is never forgotten, whatever the count: a request in
/// flight, or an error still on its way to a sink, must find its credential. Older ones are bounded by [`CAPACITY`].
pub const RETAIN: Duration = Duration::from_secs(60 * 60);

struct Entry {
    value: Box<str>,
    /// Re-encodings of `value`, computed once by [`encodings`] when it was recorded.
    encoded: Box<[Encoded]>,
    recorded: Instant,
}

/// One base64 form of a recorded spelling.
struct Encoded {
    text: Box<str>,
    /// The shortest beginning of `text`, in `char`s, that is replaced when a truncation mark follows it: as many
    /// characters as the value's first [`MIN_TRUNCATED_PREFIX_CHARS`] chars take in base64, so a cut-off form is
    /// recognised on no less of the key than a cut-off value is.
    prefix_floor: usize,
    edges: Edges,
}

/// For a base64 form taken from inside a blob: the key bits that the character just before it and the one just after
/// it carry, as `(bit count, bits)` (a count of 0 checks nothing). A neighbour that is a base64 character must carry
/// those bits; a missing one (the text ends, or is not base64 there) is accepted, since what is there is still the key.
#[derive(Clone, Copy, Default, Debug, PartialEq)]
struct Edges {
    before: (u8, u8),
    after: (u8, u8),
}

/// What stands next to an occurrence, for [`Edges::accept`].
#[derive(Clone, Copy, Debug, PartialEq)]
enum Side {
    /// Nothing: the text ends there.
    Missing,
    /// This byte, or the byte the escape written there decodes to.
    Byte(u8),
    /// An escaped backslash (a JSON string inside JSON): only a view that decodes twice can read what it stands for.
    Unresolved,
}

impl Edges {
    /// Whether the occurrence `hay[start..end]` has neighbours that carry this form's edge bits.
    ///
    /// Before it: the byte there, or (when an escape such as `%57` ends there) the byte that escape decodes to; either
    /// reading may carry the bits, since escape-like text can sit next to a raw blob (round 3 of the P163 audit).
    /// After it: an escape there (`%2F`, `\/`, a `\u` escape) is read as the byte it decodes to; one that decodes to a
    /// backslash is left to the view that decodes twice (round 2).
    fn accept(self, hay: &[u8], start: usize, end: usize) -> bool {
        let fits = |side: Side, (count, bits): (u8, u8), low: bool| match (count, side) {
            (0, _) | (_, Side::Missing) => true,
            (_, Side::Unresolved) => false,
            (count, Side::Byte(c)) => match base64_value(c) {
                None => true,
                Some(v) if low => v & ((1 << count) - 1) == bits,
                Some(v) => v >> (6 - count) == bits,
            },
        };
        let before = start
            .checked_sub(1)
            .map_or(Side::Missing, |i| Side::Byte(hay[i]));
        (fits(before, self.before, true)
            || escaped_before(hay, start).is_some_and(|b| fits(Side::Byte(b), self.before, true)))
            && fits(side_after(hay, end), self.after, false)
    }
}

/// The escape written at `hay[i..]`, if any (`%XX`, or a JSON string escape): the first and the last byte it decodes
/// to, and its length.
fn escape_at(hay: &[u8], i: usize) -> Option<(u8, u8, usize)> {
    let mut out = Vec::new();
    let len = percent_escape(hay, i, &mut out).or_else(|| json_escape(hay, i, &mut out))?;
    Some((*out.first()?, *out.last()?, len))
}

/// What stands just after `hay[..end]`.
fn side_after(hay: &[u8], end: usize) -> Side {
    match (hay.get(end), escape_at(hay, end)) {
        (None, _) => Side::Missing,
        (_, Some((b'\\', _, _))) => Side::Unresolved,
        (_, Some((first, _, _))) => Side::Byte(first),
        (Some(&c), None) => Side::Byte(c),
    }
}

/// The last byte that an escape ending just before `hay[start..]` decodes to (`%XX`, a two-byte JSON escape, a `\u`
/// escape, a surrogate pair), if one ends there.
fn escaped_before(hay: &[u8], start: usize) -> Option<u8> {
    [3, 2, 6, 12].into_iter().find_map(|len| {
        let (_, last, n) = escape_at(hay, start.checked_sub(len)?)?;
        (n == len).then_some(last)
    })
}

/// One spelling to look for: its text, its truncated-prefix floor in `char`s, and for an in-blob base64 form its edges.
#[derive(Clone, Copy)]
struct Spelling<'a> {
    text: &'a str,
    floor: usize,
    edges: Edges,
}

impl Entry {
    /// Every spelling this entry matches: the value, then its base64 forms.
    fn spellings(&self) -> impl Iterator<Item = Spelling<'_>> {
        std::iter::once(Spelling {
            text: &self.value,
            floor: MIN_TRUNCATED_PREFIX_CHARS,
            edges: Edges::default(),
        })
        .chain(self.encoded.iter().map(|e| Spelling {
            text: &e.text,
            floor: e.prefix_floor,
            edges: e.edges,
        }))
    }
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
    // A value recorded again keeps the forms computed the first time.
    let encoded = match sent.iter().position(|e| &*e.value == value) {
        Some(pos) => sent.remove(pos).map(|e| e.encoded),
        None => None,
    }
    .unwrap_or_else(|| encodings(value).into_boxed_slice());
    sent.push_back(Entry {
        value: value.into(),
        encoded,
        recorded: now,
    });
}

/// The base64 forms of `value` that are matched as well as `value` itself (see the module docs), at most
/// [`MAX_ENCODINGS`], none equal to `value`, none shorter than [`MIN_CREDENTIAL_CHARS`], no two alike.
fn encodings(value: &str) -> Vec<Encoded> {
    // A cut-off form is replaced from as many characters as the value's first MIN_TRUNCATED_PREFIX_CHARS chars take.
    let head = value
        .char_indices()
        .nth(MIN_TRUNCATED_PREFIX_CHARS)
        .map_or(value, |(i, _)| &value[..i]);
    let prefix_floor = (head.len() * 4).div_ceil(3);
    let bytes = value.as_bytes();
    let first = bytes.first().copied().unwrap_or(0);
    let last = bytes.last().copied().unwrap_or(0);
    let mut forms = vec![
        (base64_encode(bytes), Edges::default()),
        (base64_encode_unpadded(bytes), Edges::default()),
    ];
    for offset in 0..3 {
        // The character before the form holds the low 4 (offset 1) or 2 (offset 2) bits of the group's first
        // character pair, i.e. the key's first bits; the character after it, the key's last 2 or 4 bits.
        let before = match offset {
            1 => (4, first >> 4),
            2 => (2, first >> 6),
            _ => (0, 0),
        };
        let rest = u8::try_from((offset + bytes.len()) * 8 % 6).unwrap_or(0);
        let after = (rest, last & ((1u8 << rest) - 1));
        forms.push((base64_embedded(bytes, offset), Edges { before, after }));
    }
    let mut out: Vec<Encoded> = Vec::new();
    for (form, edges) in forms {
        let url_safe = form.replace('+', "-").replace('/', "_");
        for text in [form, url_safe] {
            if text != value
                && text.chars().count() >= MIN_CREDENTIAL_CHARS
                // Alignments can share a text but not their edges (Astra r3 #1): keep each pair.
                && !out.iter().any(|e| *e.text == *text && e.edges == edges)
            {
                out.push(Encoded {
                    text: text.into(),
                    prefix_floor,
                    edges,
                });
            }
        }
    }
    out
}

/// The 6-bit value of a base64 character in either alphabet.
fn base64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// `%XX` (either hex case) at `src[i..]`: pushes the byte it stands for and returns 3.
fn percent_escape(src: &[u8], i: usize, out: &mut Vec<u8>) -> Option<usize> {
    if src.get(i) != Some(&b'%') {
        return None;
    }
    let high = hex_digit(*src.get(i + 1)?)?;
    let low = hex_digit(*src.get(i + 2)?)?;
    out.push((high << 4) | low);
    Some(3)
}

/// A JSON string escape at `src[i..]` (two bytes, a `\u` escape of six, or a surrogate pair of twelve): pushes the
/// UTF-8 bytes it stands for and returns its length. A lone surrogate is not an escape here.
fn json_escape(src: &[u8], i: usize, out: &mut Vec<u8>) -> Option<usize> {
    if src.get(i) != Some(&b'\\') {
        return None;
    }
    let hex4 = |at: usize| -> Option<u32> {
        src.get(at..at + 4)?
            .iter()
            .try_fold(0u32, |acc, &d| Some((acc << 4) | u32::from(hex_digit(d)?)))
    };
    let (c, len) = match src.get(i + 1).copied()? {
        b'"' => ('"', 2),
        b'\\' => ('\\', 2),
        b'/' => ('/', 2),
        b'b' => ('\u{8}', 2),
        b'f' => ('\u{c}', 2),
        b'n' => ('\n', 2),
        b'r' => ('\r', 2),
        b't' => ('\t', 2),
        b'u' => {
            let unit = hex4(i + 2)?;
            if (0xD800..0xDC00).contains(&unit) {
                // A high surrogate decodes only with the low one that follows it.
                if src.get(i + 6..i + 8) != Some(&b"\\u"[..]) {
                    return None;
                }
                let low = hex4(i + 8).filter(|low| (0xDC00..0xE000).contains(low))?;
                (
                    char::from_u32(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00))?,
                    12,
                )
            } else {
                (char::from_u32(unit)?, 6)
            }
        }
        _ => return None,
    };
    out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
    Some(len)
}

/// One level of escape decoding.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Escapes {
    /// `%XX` in either hex case; with `plus`, `+` is a space too.
    Percent { plus: bool },
    /// JSON string escapes.
    Json,
}

impl Escapes {
    /// How many bytes at the start of `src[from..to]` are plain tokens: bytes that begin no escape and decode to
    /// themselves, so a run of them is copied as it is (P179: the per-token path costs several times a copy).
    fn plain_run(self, src: &[u8], from: usize, to: usize) -> usize {
        #[cfg(test)]
        if PLAIN_RUNS_OFF.with(std::cell::Cell::get) {
            return 0;
        }
        let begins_token = |b: u8| match self {
            Escapes::Percent { plus } => b == b'%' || (plus && b == b'+'),
            Escapes::Json => b == b'\\',
        };
        src[from..to]
            .iter()
            .position(|&b| begins_token(b))
            .unwrap_or(to - from)
    }

    /// Decode the token at `src[i..]` (an escape, or one plain byte) onto `out`; returns its length in `src`.
    fn token(self, src: &[u8], i: usize, out: &mut Vec<u8>) -> usize {
        let escape = match self {
            Escapes::Percent { .. } => percent_escape(src, i, out),
            Escapes::Json => json_escape(src, i, out),
        };
        escape.unwrap_or_else(|| {
            out.push(match (self, src[i]) {
                (Escapes::Percent { plus: true }, b'+') => b' ',
                (_, b) => b,
            });
            1
        })
    }
}

/// The longest token: a surrogate pair, two `\u` escapes.
const MAX_TOKEN: usize = 12;

/// How a decoded view of a text reads its escapes (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq)]
enum View {
    Percent {
        plus: bool,
    },
    Json,
    /// JSON string escapes decoded twice (a JSON string written inside another JSON string).
    JsonTwice,
}

impl View {
    /// A text without this byte has nothing for the view to decode.
    fn trigger(self, b: u8) -> bool {
        match self {
            View::Percent { plus } => b == b'%' || (plus && b == b'+'),
            View::Json | View::JsonTwice => b == b'\\',
        }
    }

    /// The first decoding level, and the second for a view that decodes twice.
    fn levels(self) -> (Escapes, Option<Escapes>) {
        match self {
            View::Percent { plus } => (Escapes::Percent { plus }, None),
            View::Json => (Escapes::Json, None),
            View::JsonTwice => (Escapes::Json, Some(Escapes::Json)),
        }
    }
}

fn hex_digit(b: u8) -> Option<u8> {
    char::from(b)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
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
        // The values themselves: a rewrite of words leaves base64 and escapes as they are.
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
                if let Some(len) = truncated_prefix_len(
                    &text.as_bytes()[..mark],
                    value,
                    MIN_TRUNCATED_PREFIX_CHARS,
                ) {
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

/// Standard-alphabet base64 without padding.
fn base64_encode_unpadded(bytes: &[u8]) -> String {
    let mut out = base64_encode(bytes);
    out.truncate(out.trim_end_matches('=').len());
    out
}

/// The standard-alphabet base64 characters that `bytes` alone determine when they sit `offset` bytes (0, 1 or 2)
/// into a 3-byte group of a larger base64 blob: the characters shared with the bytes before (2 for offset 1, 3 for
/// offset 2) or after them are left out.
fn base64_embedded(bytes: &[u8], offset: usize) -> String {
    let mut shifted = vec![0u8; offset];
    shifted.extend_from_slice(bytes);
    let whole = (shifted.len() * 8) / 6;
    let skip = [0, 2, 3][offset % 3];
    base64_encode(&shifted)
        .get(skip..whole)
        .unwrap_or_default()
        .to_owned()
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
    let index = Index::new(&sent);
    // Matches in the text as it is come in ascending order of start: merge overlapping ones as they are found, so a
    // dense haystack yields one range per disjoint run and not one per occurrence. The rest are merged below.
    let mut covered: Vec<(usize, usize)> = Vec::new();
    index.for_each_match(bytes, true, &mut |start, end| {
        if let Some(last) = covered.last_mut()
            && last.0 <= start
            && start <= last.1
        {
            last.1 = last.1.max(end);
        } else {
            covered.push((start, end));
        }
        true
    });
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
    if index.contains_any(&out) {
        out = if index.contains_any(WITHHELD.as_bytes()) {
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

/// Length in bytes of the longest proper prefix of `cred`, at least `floor_chars` chars long (for a recorded value,
/// [`MIN_TRUNCATED_PREFIX_CHARS`]), that `before` (the text up to a truncation mark) ends with.
fn truncated_prefix_len(before: &[u8], cred: &str, floor_chars: usize) -> Option<usize> {
    let floor = cred.char_indices().nth(floor_chars).map(|(i, _)| i)?;
    let last = *before.last()?;
    cred.char_indices()
        .map(|(i, _)| i)
        .rev()
        .take_while(|&len| len >= floor)
        // Cheap first: the prefix's last byte must be the one just before the mark.
        .filter(|&len| cred.as_bytes()[len - 1] == last)
        .find(|&len| before.ends_with(&cred.as_bytes()[..len]))
}

/// How many bytes at the end of `before` are the beginning of an escape that a cut left incomplete: `%`, `%X`, `\`,
/// `\u`, `\uX`, `\uXX` or `\uXXX` (X a hex digit). 0 when there is none.
fn incomplete_escape_len(before: &[u8]) -> usize {
    let hex_tail = before
        .iter()
        .rev()
        .take(3)
        .take_while(|&&b| hex_digit(b).is_some())
        .count();
    let rest = &before[..before.len() - hex_tail];
    if hex_tail <= 1 && rest.ends_with(b"%") {
        hex_tail + 1
    } else if rest.ends_with(b"\\u") {
        hex_tail + 2
    } else if before.ends_with(b"\\") || before.ends_with(b"%") {
        1
    } else {
        0
    }
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
    let index = Index::new(&sent);
    // Moving the cut right can land it inside a later, overlapping occurrence: repeat until stable. Occurrences in the
    // text as it is come in ascending order, so one pass follows a chain of them; nothing is stored per occurrence.
    loop {
        let mut moved = false;
        index.for_each_match(text.as_bytes(), false, &mut |start, end| {
            if start < cut && cut < end {
                cut = end;
                moved = true;
            }
            true
        });
        if !moved {
            break;
        }
    }
    // An occurrence found in a decoded view ends where an escape or a plain byte starts; stay on a char boundary.
    while !text.is_char_boundary(cut) {
        cut += 1;
    }
    cut
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

/// The needles' first two bytes, for [`find_all`]: `(prefix, needle index)` pairs sorted by prefix, and a bitmap of
/// the prefixes. A needle shorter than two bytes is left out (none is: every spelling has at least
/// [`MIN_CREDENTIAL_CHARS`] chars).
struct Prefixes {
    sorted: Vec<(u16, usize)>,
    seen: Vec<u64>,
}

impl Prefixes {
    fn new(needles: &[&[u8]]) -> Self {
        let mut sorted: Vec<(u16, usize)> = needles
            .iter()
            .enumerate()
            .filter(|(_, n)| n.len() >= 2)
            .map(|(i, n)| (u16::from_be_bytes([n[0], n[1]]), i))
            .collect();
        sorted.sort_unstable();
        let mut seen = vec![0u64; 1 << 10];
        for &(prefix, _) in &sorted {
            seen[usize::from(prefix >> 6)] |= 1 << (prefix & 63);
        }
        Self { sorted, seen }
    }
}

/// Every occurrence of every needle in `hay`, overlapping ones included, in ascending order of start, as
/// `found(needle index, start)`; `found` returns `false` to stop early, and then so does this.
///
/// One pass over `hay` whatever the number of needles: a position is compared only with the needles that begin with
/// the two bytes found there, found through the bitmap of the needles' first two bytes.
fn find_all(
    hay: &[u8],
    needles: &[&[u8]],
    prefixes: &Prefixes,
    mut found: impl FnMut(usize, usize) -> bool,
) -> bool {
    if prefixes.sorted.is_empty() {
        return true;
    }
    for (i, pair) in hay.windows(2).enumerate() {
        let prefix = u16::from_be_bytes([pair[0], pair[1]]);
        if prefixes.seen[usize::from(prefix >> 6)] & (1 << (prefix & 63)) == 0 {
            continue;
        }
        let first = prefixes.sorted.partition_point(|&(p, _)| p < prefix);
        for &(_, idx) in prefixes.sorted[first..]
            .iter()
            .take_while(|&&(p, _)| p == prefix)
        {
            if hay[i..].starts_with(needles[idx]) && !found(idx, i) {
                return false;
            }
        }
    }
    true
}

/// The most `(last two bytes, spelling)` pairs [`CutOffTails`] stores (32 MB); past it the table is dropped and a
/// mark whose two bytes are in the bitmap is checked against every spelling, so memory stays bounded however long
/// the recorded values are.
const MAX_TAIL_PAIRS: usize = 1 << 22;

/// Which spellings can have a cut-off beginning that ends in a given two bytes, for [`Index::cut_off`] (P179): a
/// bitmap of the last two bytes of every admissible beginning of every spelling (each char boundary at or after its
/// floor), and the `(last two bytes, spelling index)` pairs sorted, so that a truncation mark is checked only against
/// the spellings that can end the way the text before it does. A beginning shorter than two bytes has no such pair:
/// its spelling is in `always` and is checked at every mark.
struct CutOffTails {
    sorted: Vec<(u16, u32)>,
    seen: Vec<u64>,
    always: Vec<u32>,
    /// More than [`MAX_TAIL_PAIRS`] pairs: `sorted` is empty and a bitmap hit stands for every spelling.
    overflow: Option<u32>,
}

impl CutOffTails {
    fn new(spellings: &[Spelling<'_>]) -> Self {
        Self::with_limit(spellings, MAX_TAIL_PAIRS)
    }

    fn with_limit(spellings: &[Spelling<'_>], limit: usize) -> Self {
        let (mut sorted, mut always) = (Vec::new(), Vec::new());
        let mut seen = vec![0u64; 1 << 10];
        let mut overflow = None;
        let mut pairs: Vec<u16> = Vec::new();
        for (idx, spelling) in spellings.iter().enumerate() {
            let text = spelling.text.as_bytes();
            let Some(floor) = spelling
                .text
                .char_indices()
                .nth(spelling.floor)
                .map(|(i, _)| i)
            else {
                continue; // shorter than its floor: no cut-off beginning
            };
            pairs.clear();
            for (len, _) in spelling.text.char_indices().filter(|&(i, _)| i >= floor) {
                if len < 2 {
                    always.push(idx as u32);
                    pairs.clear();
                    break;
                }
                pairs.push(u16::from_be_bytes([text[len - 2], text[len - 1]]));
            }
            pairs.sort_unstable();
            pairs.dedup();
            for &pair in &pairs {
                seen[usize::from(pair >> 6)] |= 1 << (pair & 63);
                if overflow.is_none() {
                    sorted.push((pair, idx as u32));
                }
            }
            if sorted.len() > limit {
                sorted = Vec::new();
                overflow = Some(spellings.len() as u32);
            }
        }
        sorted.sort_unstable();
        Self {
            sorted,
            seen,
            always,
            overflow,
        }
    }

    /// Adds to `out` the spellings that a cut-off beginning ending `before` can belong to.
    fn candidates(&self, before: &[u8], out: &mut Vec<u32>) {
        out.extend_from_slice(&self.always);
        let [.., a, b] = *before else { return };
        let pair = u16::from_be_bytes([a, b]);
        if self.seen[usize::from(pair >> 6)] & (1 << (pair & 63)) == 0 {
            return;
        }
        if let Some(all) = self.overflow {
            out.extend(0..all);
            return;
        }
        let first = self.sorted.partition_point(|&(p, _)| p < pair);
        out.extend(
            self.sorted[first..]
                .iter()
                .take_while(|&&(p, _)| p == pair)
                .map(|&(_, idx)| idx),
        );
    }
}

#[cfg(test)]
thread_local! {
    /// Test-only: decode every token one at a time, as before P179 ([`Escapes::plain_run`] finds none).
    static PLAIN_RUNS_OFF: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
thread_local! {
    /// Test-only: make [`Index::cut_off`] check every spelling at every mark, the way it did before P179.
    static CUT_OFF_UNFILTERED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Every recorded spelling, indexed once per scrub for one pass over the text and over each decoded view of it.
struct Index<'a> {
    spellings: Vec<Spelling<'a>>,
    needles: Vec<&'a [u8]>,
    prefixes: Prefixes,
    views: Vec<View>,
    /// The longest spelling, in bytes.
    longest: usize,
    /// Built when the first truncation mark is met: most text has none.
    tails: std::cell::OnceCell<CutOffTails>,
}

impl<'a> Index<'a> {
    fn new(sent: &'a VecDeque<Entry>) -> Self {
        let spellings: Vec<Spelling<'a>> = sent.iter().flat_map(Entry::spellings).collect();
        let needles: Vec<&'a [u8]> = spellings.iter().map(|s| s.text.as_bytes()).collect();
        let prefixes = Prefixes::new(&needles);
        let mut views = vec![View::Percent { plus: false }];
        if spellings.iter().any(|s| s.text.contains(' ')) {
            views.push(View::Percent { plus: true });
        }
        views.extend([View::Json, View::JsonTwice]);
        let longest = needles.iter().map(|n| n.len()).max().unwrap_or(0);
        Self {
            spellings,
            needles,
            prefixes,
            views,
            longest,
            tails: std::cell::OnceCell::new(),
        }
    }

    /// `found(spelling index, start)` for every occurrence in `hay` whose neighbours fit the spelling's edges, in
    /// ascending order of start. `found` returns false to stop; returns false when stopped.
    fn find(&self, hay: &[u8], mut found: impl FnMut(usize, usize) -> bool) -> bool {
        find_all(hay, &self.needles, &self.prefixes, |idx, start| {
            let spelling = self.spellings[idx];
            !spelling
                .edges
                .accept(hay, start, start + spelling.text.len())
                || found(idx, start)
        })
    }

    /// `found(start, end)` for every cut-off beginning of a spelling just before a truncation mark in `hay` (see
    /// [`truncated_prefix_len`]). `found` returns false to stop; returns false when stopped.
    fn cut_off(&self, hay: &[u8], mut found: impl FnMut(usize, usize) -> bool) -> bool {
        #[cfg(test)]
        let unfiltered = CUT_OFF_UNFILTERED.with(std::cell::Cell::get);
        #[cfg(not(test))]
        let unfiltered = false;
        let mut candidates: Vec<u32> = Vec::new();
        for mark in occurrences(hay, TRUNCATION_MARK.as_bytes()) {
            // A cap can also fall inside an escape (`%7…`, `\u00…`): what is left of it is covered with the prefix.
            let trim = incomplete_escape_len(&hay[..mark]);
            // Only the spellings with a cut-off beginning that ends the way the text before the mark ends (either
            // end considered below) can match; for ordinary text that is none, and nothing else is looked at.
            candidates.clear();
            if unfiltered {
                candidates.extend(0..self.spellings.len() as u32);
            } else {
                let tails = self.tails.get_or_init(|| CutOffTails::new(&self.spellings));
                tails.candidates(&hay[..mark], &mut candidates);
                if trim > 0 {
                    tails.candidates(&hay[..mark - trim], &mut candidates);
                }
                candidates.sort_unstable();
                candidates.dedup();
            }
            for &idx in &candidates {
                let spelling = &self.spellings[idx as usize];
                let prefix = [mark, mark - trim].into_iter().find_map(|end| {
                    truncated_prefix_len(&hay[..end], spelling.text, spelling.floor)
                        .map(|len| end - len)
                        .filter(|&start| spelling.edges.accept(hay, start, end))
                });
                if let Some(start) = prefix
                    && !found(start, mark)
                {
                    return false;
                }
            }
        }
        true
    }

    /// `found(start, end)` for every occurrence of a recorded spelling in `bytes`, as a byte range of `bytes`: first in
    /// the text as it is (in ascending order of start), then in each decoded view of it (see the module docs); with
    /// `marks`, also every cut-off beginning before a truncation mark. `found` returns false to stop; returns false
    /// when stopped.
    fn for_each_match(
        &self,
        bytes: &[u8],
        marks: bool,
        found: &mut dyn FnMut(usize, usize) -> bool,
    ) -> bool {
        if !self.find(bytes, |idx, start| {
            found(start, start + self.needles[idx].len())
        }) {
            return false;
        }
        if marks && !self.cut_off(bytes, &mut *found) {
            return false;
        }
        self.views.iter().all(|&view| {
            !bytes.iter().any(|&b| view.trigger(b))
                || self.scan_view(bytes, view, marks, &mut *found)
        })
    }

    /// [`Index::for_each_match`] in one decoded view of `bytes`. The text is decoded in a single pass, token after
    /// token, so no escape is read differently from how the whole text reads it; [`VIEW_WINDOW`] source bytes at a
    /// time, the decoded text searched holding only the new piece and a tail of the one before (enough for the
    /// longest spelling, a cut-off one with its truncation mark, and a left neighbour). A match is reported once, in
    /// the piece that decodes its last byte (and the token after it, its right neighbour), as the source range it was
    /// decoded from.
    fn scan_view(
        &self,
        bytes: &[u8],
        view: View,
        marks: bool,
        found: &mut dyn FnMut(usize, usize) -> bool,
    ) -> bool {
        let (first, second) = view.levels();
        let carry = self.longest + 16;
        // First-level output still to be decoded again (a view that decodes twice), with its source offsets.
        let (mut mid, mut mid_map): (Vec<u8>, Vec<usize>) = (Vec::new(), Vec::new());
        // The decoded text searched: `buf[k]` came from source offset `map[k]` and is decoded byte `base + k`.
        let (mut buf, mut map): (Vec<u8>, Vec<usize>) = (Vec::new(), Vec::new());
        let (mut base, mut done, mut pos) = (0usize, 0usize, 0usize);
        loop {
            let until = (pos + VIEW_WINDOW).min(bytes.len());
            {
                let (out, out_map) = if second.is_some() {
                    (&mut mid, &mut mid_map)
                } else {
                    (&mut buf, &mut map)
                };
                while pos < until {
                    let plain = first.plain_run(bytes, pos, until);
                    if plain > 0 {
                        out.extend_from_slice(&bytes[pos..pos + plain]);
                        out_map.extend(pos..pos + plain);
                        pos += plain;
                        continue;
                    }
                    let source = pos;
                    pos += first.token(bytes, pos, out);
                    out_map.resize(out.len(), source);
                }
            }
            let last = pos >= bytes.len();
            let mut end_offset = pos;
            if let Some(second) = second {
                // A token takes up to MAX_TOKEN bytes: decode only whole ones until the input ends.
                let stop = if last {
                    mid.len()
                } else {
                    mid.len().saturating_sub(MAX_TOKEN)
                };
                let mut i = 0;
                while i < stop {
                    let plain = second.plain_run(&mid, i, stop);
                    if plain > 0 {
                        buf.extend_from_slice(&mid[i..i + plain]);
                        map.extend_from_slice(&mid_map[i..i + plain]);
                        i += plain;
                        continue;
                    }
                    let source = mid_map[i];
                    i += second.token(&mid, i, &mut buf);
                    map.resize(buf.len(), source);
                }
                mid.drain(..i);
                mid_map.drain(..i);
                end_offset = mid_map.first().copied().unwrap_or(pos);
            }
            // The last MAX_TOKEN decoded bytes wait for the next piece, which holds a right neighbour written as an
            // escape whole (Astra r3 #4), unless the input ended.
            let held = if last { 0 } else { buf.len().min(MAX_TOKEN) };
            let limit = base + buf.len() - held;
            let at = |k: usize| map.get(k).copied().unwrap_or(end_offset);
            let mut report = |start: usize, end: usize, owner: usize| {
                let owner = base + owner;
                owner <= done || owner > limit || found(at(start), at(end))
            };
            if !self.find(&buf, |idx, start| {
                let end = start + self.needles[idx].len();
                report(start, end, end)
            }) {
                return false;
            }
            if marks
                && !self.cut_off(&buf, |start, mark| {
                    report(start, mark, mark + TRUNCATION_MARK.len())
                })
            {
                return false;
            }
            done = limit;
            if last {
                return true;
            }
            let keep = buf.len().min(carry + (base + buf.len() - limit));
            let drop = buf.len() - keep;
            buf.drain(..drop);
            map.drain(..drop);
            base += drop;
        }
    }

    /// Whether `bytes` holds any recorded spelling, as it is or in a decoded view (cut-off beginnings aside).
    fn contains_any(&self, bytes: &[u8]) -> bool {
        !self.for_each_match(bytes, false, &mut |_, _| false)
    }
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
        // Case variants are not the value that was sent (re-encodings are: see the P163 tests).
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

    // ---- P163 (1.0.21 K24): a recorded credential is found in its standard re-encodings too. ----

    /// Keys whose base64 uses `+` and `/` (so the URL-safe alphabet differs), of each length modulo 3, and one at the
    /// recording floor.
    const P163_KEYS: [&str; 4] = [
        "p163-key-Qz8Wm4Xr",
        "p163~~key?>Zx9Wm4~?>",
        "p163?>~~Kq7?>~~Lm2Vz",
        "p163Ab9Z",
    ];

    /// An oracle independent of the scrub: does `text` still give away 3 consecutive bytes of `key` when any run of
    /// base64 characters in it (either alphabet) is decoded at any of the 4 character alignments?
    fn p163_base64_leaks(text: &str, key: &str) -> bool {
        let normal: String = text
            .chars()
            .map(|c| match c {
                '-' => '+',
                '_' => '/',
                c => c,
            })
            .collect();
        let windows: Vec<&[u8]> = key.as_bytes().windows(3).collect();
        normal
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '+' || c == '/'))
            .any(|run| {
                (0..4.min(run.len())).any(|start| {
                    let run = &run[start..];
                    base64_decode(&run[..run.len() / 4 * 4]).is_some_and(|decoded| {
                        windows.iter().any(|w| decoded.windows(3).any(|d| d == *w))
                    })
                })
            })
    }

    fn p163_url_safe(text: &str) -> String {
        text.replace('+', "-").replace('/', "_")
    }

    #[test]
    fn p163_base64_of_a_recorded_key_is_replaced_alone_and_inside_a_blob() {
        let _g = fresh();
        for key in P163_KEYS {
            clear_for_tests();
            record(key);
            let alone = base64_encode(key.as_bytes());
            for blob in [
                alone.clone(),
                alone.trim_end_matches('=').to_owned(),
                p163_url_safe(&alone),
                p163_url_safe(alone.trim_end_matches('=')),
            ] {
                assert_eq!(scrub(&blob), PLACEHOLDER, "{key}: {blob}");
                assert_eq!(scrub(&format!("[{blob}]")), "[<redacted>]", "{key}: {blob}");
            }
            // Inside a larger blob, at every byte alignment, in both alphabets.
            // (No `before` shares 3 bytes with a key: the oracle would see those bytes in the untouched prefix.)
            for before in ["", "a", "ab", "abc", "abcd", "{\"tok\":\""] {
                for after in ["", "!", "!!", "\"}"] {
                    let inner = format!("{before}{key}{after}");
                    let blob = base64_encode(inner.as_bytes());
                    for blob in [blob.clone(), p163_url_safe(&blob)] {
                        let text = format!("payload {blob} end");
                        assert!(p163_base64_leaks(&text, key), "oracle control: {text}");
                        let out = scrub(&text);
                        assert!(!p163_base64_leaks(&out, key), "{key} {inner:?}: {out}");
                        assert!(out.contains(PLACEHOLDER), "{out}");
                    }
                }
            }
        }
    }

    /// HTTP `Basic` carries base64 of `user:password`; a recorded key in either half is replaced, wherever the
    /// colon puts it in the 3-byte groups.
    #[test]
    fn p163_a_basic_header_embedding_a_recorded_key_is_replaced() {
        let _g = fresh();
        for key in P163_KEYS {
            clear_for_tests();
            record(key);
            for pair in [
                format!("alice:{key}"),
                format!("bob:{key}"),
                format!("x:{key}"),
                format!("{key}:"),
                format!("{key}:x"),
                format!("carol:{key}:tail"),
            ] {
                let header = format!("Authorization: Basic {}", base64_encode(pair.as_bytes()));
                assert!(p163_base64_leaks(&header, key), "oracle control: {header}");
                let out = scrub(&header);
                assert!(!p163_base64_leaks(&out, key), "{pair}: {out}");
                assert!(out.starts_with("Authorization: Basic "), "{out}");
            }
        }
    }

    #[test]
    fn p163_a_percent_encoded_recorded_key_is_replaced_in_every_common_style() {
        let _g = fresh();
        let key = "p163+key/Zx9=Qw é!*'()~x";
        record(key);
        let every = |upper: bool| -> String {
            key.bytes()
                .map(|b| {
                    if upper {
                        format!("%{b:02X}")
                    } else {
                        format!("%{b:02x}")
                    }
                })
                .collect()
        };
        let forms = [
            // RFC 3986 unreserved kept (Rust `urlencoding`, Python `quote(safe='')`).
            "p163%2Bkey%2FZx9%3DQw%20%C3%A9%21%2A%27%28%29~x".to_owned(),
            "p163%2bkey%2fZx9%3dQw%20%c3%a9%21%2a%27%28%29~x".to_owned(),
            // Python `quote` (keeps `/`).
            "p163%2Bkey/Zx9%3DQw%20%C3%A9%21%2A%27%28%29~x".to_owned(),
            "p163%2bkey/Zx9%3dQw%20%c3%a9%21%2a%27%28%29~x".to_owned(),
            // JavaScript `encodeURIComponent`.
            "p163%2Bkey%2FZx9%3DQw%20%C3%A9!*'()~x".to_owned(),
            "p163%2bkey%2fZx9%3dQw%20%c3%a9!*'()~x".to_owned(),
            // HTML form encoding (space as `+`, `~` encoded).
            "p163%2Bkey%2FZx9%3DQw+%C3%A9%21*%27%28%29%7Ex".to_owned(),
            "p163%2bkey%2fZx9%3dQw+%c3%a9%21*%27%28%29%7ex".to_owned(),
            // Python `quote_plus` / `urlencode`, Go `url.QueryEscape` (space as `+`, `~` kept).
            "p163%2Bkey%2FZx9%3DQw+%C3%A9%21%2A%27%28%29~x".to_owned(),
            // PHP `urlencode` (space as `+`, `~` and `*` encoded).
            "p163%2Bkey%2FZx9%3DQw+%C3%A9%21%2A%27%28%29%7Ex".to_owned(),
            // Any mix: some characters escaped and some not, both hex cases.
            "%70163%2bkey/Zx9%3DQw é!*%27()%7ex".to_owned(),
            every(true),
            every(false),
        ];
        for form in forms {
            assert_eq!(
                scrub(&format!("GET /v1?api_key={form}&x=1")),
                "GET /v1?api_key=<redacted>&x=1",
                "{form}"
            );
        }
        // The base64 of a key, percent-encoded in a query string.
        let b64 = base64_encode(key.as_bytes());
        assert!(b64.contains(['+', '/', '=']), "{b64}");
        let query = b64
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");
        assert_eq!(scrub(&format!("?t={query}&x")), "?t=<redacted>&x");
        let lower = b64
            .replace('+', "%2b")
            .replace('/', "%2f")
            .replace('=', "%3d");
        assert_eq!(scrub(&format!("?t={lower}&x")), "?t=<redacted>&x");
        // A key of only unreserved characters, one character escaped.
        clear_for_tests();
        record("p163-AbCd-key-123");
        assert_eq!(scrub("k=p163%2DAbCd-key-123&x"), "k=<redacted>&x");
        assert_eq!(scrub("k=%70163-AbCd-key-123"), "k=<redacted>");
        // A `+` is a space only when a recorded spelling has a space: here it stays a `+`.
        assert_eq!(scrub("p163+AbCd-key-123"), "p163+AbCd-key-123");
    }

    #[test]
    fn p163_a_unicode_escaped_recorded_key_is_replaced_in_every_common_style() {
        let _g = fresh();
        let key = "p163<uni>&Key+é'🔑";
        record(key);
        let every = |upper: bool| -> String {
            key.encode_utf16()
                .map(|u| {
                    if upper {
                        format!("\\u{u:04X}")
                    } else {
                        format!("\\u{u:04x}")
                    }
                })
                .collect()
        };
        let forms = [
            // Python `json.dumps` (ensure_ascii), Jackson ESCAPE_NON_ASCII.
            r"p163<uni>&Key+\u00e9'\ud83d\udd11".to_owned(),
            r"p163<uni>&Key+\u00E9'\uD83D\uDD11".to_owned(),
            // Go `encoding/json` (HTML-safe).
            r"p163\u003cuni\u003e\u0026Key+é'🔑".to_owned(),
            // .NET System.Text.Json default.
            r"p163\u003Cuni\u003E\u0026Key\u002B\u00E9\u0027\uD83D\uDD11".to_owned(),
            // Any single character escaped.
            r"\u0070163<uni>&Key+é'🔑".to_owned(),
            every(true),
            every(false),
        ];
        // The fixtures really are escaped: none is the key as written.
        assert!(forms.iter().all(|f| f.contains(r"\u") && f != key));
        for form in forms {
            let line = format!("{{\"msg\":\"bad key {form}\"}}");
            assert_eq!(scrub(&line), "{\"msg\":\"bad key <redacted>\"}", "{form}");
            // The same JSON string logged inside another JSON record: its backslashes are escaped once more.
            let nested = serde_json::json!({ "data": line }).to_string();
            let out = scrub(&nested).into_owned();
            assert!(!out.contains("u00"), "{out}");
            assert!(out.contains(PLACEHOLDER), "{out}");
        }
        // Python escapes DEL; PHP also writes `/` as `\/`.
        clear_for_tests();
        let key = "p163/del\u{7f}-key";
        record(key);
        for form in [
            r"p163/del\u007f-key",
            r"p163\/del\u007f-key",
            r"p163\/del\u007F-key",
        ] {
            assert_eq!(scrub(&format!("x {form} y")), "x <redacted> y", "{form}");
            let nested = serde_json::json!({ "data": format!("x {form} y") }).to_string();
            assert_eq!(scrub(&nested), r#"{"data":"x <redacted> y"}"#, "{form}");
        }
        // Astra r1 #2: a plain key with only its first character escaped.
        clear_for_tests();
        record("p163-AbCd-key-123");
        assert_eq!(scrub(r"err \u0070163-AbCd-key-123"), "err <redacted>");
    }

    /// A cap that cut a base64 or percent-encoded key short leaves its beginning before the truncation mark; that is
    /// replaced too (from as many characters as 8 characters of the key take in that encoding).
    #[test]
    fn p163_a_cut_off_re_encoded_key_is_replaced() {
        let _g = fresh();
        let key = "p163-key-Qz8Wm4Xr-and-more-key";
        record(key);
        let blob = base64_encode(format!("alice:{key}").as_bytes());
        let cut = &blob[..blob.len() - 6];
        let out = scrub(&format!("Basic {cut}\u{2026}")).into_owned();
        assert!(!p163_base64_leaks(&out, key), "{out}");
        assert!(out.ends_with("<redacted>\u{2026}"), "{out}");
        let every: String = key.bytes().map(|b| format!("%{b:02X}")).collect();
        let cut = &every[..every.len() - 4];
        assert_eq!(scrub(&format!("k={cut}\u{2026}")), "k=<redacted>\u{2026}");
    }

    /// Every sink function sees the re-encodings: the byte scrub, the log writer and the JSON-string walk.
    #[test]
    fn p163_every_scrub_entry_point_replaces_a_re_encoded_key() {
        let _g = fresh();
        let key = P163_KEYS[0];
        record(key);
        let basic = base64_encode(format!("svc:{key}").as_bytes());
        let line = format!("{{\"header\":\"Basic {basic}\"}}\n");
        let mut writer = ScrubWriter::new(Vec::new());
        writer.write_all(line.as_bytes()).unwrap();
        let written = String::from_utf8(writer.into_inner()).unwrap();
        assert!(!p163_base64_leaks(&written, key), "{written}");
        assert!(written.ends_with('\n'), "{written}");
        let bytes = scrub_bytes(line.as_bytes()).expect("matched");
        assert!(!p163_base64_leaks(&String::from_utf8(bytes).unwrap(), key));
        let mut value = serde_json::json!({ "list": [format!("Basic {basic}")] });
        assert!(scrub_json_strings(&mut value));
        assert!(!p163_base64_leaks(&value.to_string(), key), "{value}");
        let pct: String = key.bytes().map(|b| format!("%{b:02x}")).collect();
        assert!(crate::redact_secrets(&format!("url k={pct}")).contains(PLACEHOLDER));
    }

    /// No false positives: random base64, hex, percent-encoded and `\u`-escaped data is left alone, byte for byte.
    #[test]
    fn p163_random_encoded_data_is_left_alone() {
        let _g = fresh();
        for key in P163_KEYS {
            record(key);
        }
        record("p163+key/Zx9=Qw é!*'()~x");
        record("p163<uni>&Key+é'🔑");
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut random = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let bytes: Vec<u8> = (0..24 * 1024).map(|_| random().to_le_bytes()[3]).collect();
        let b64 = base64_encode(&bytes);
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let hex_upper = hex.to_ascii_uppercase();
        let pct: String = bytes[..12 * 1024]
            .iter()
            .map(|b| format!("%{b:02X}"))
            .collect();
        let pct_lower = pct.to_ascii_lowercase();
        let uni: String = bytes[..8 * 1024]
            .chunks(2)
            .map(|c| format!("\\u{:02x}{:02x}", c[0], c.get(1).copied().unwrap_or(0)))
            .collect();
        for text in [
            b64.clone(),
            p163_url_safe(&b64),
            hex,
            hex_upper,
            pct,
            pct_lower,
            uni,
        ] {
            assert!(matches!(scrub(&text), Cow::Borrowed(_)), "{}", &text[..64]);
            let wrapped: String = text
                .as_bytes()
                .chunks(76)
                .map(|line| format!("{}\n", String::from_utf8_lossy(line)))
                .collect();
            assert!(matches!(scrub(&wrapped), Cow::Borrowed(_)));
        }
    }

    /// The re-encodings are computed once per recorded spelling (a value recorded again keeps them) and are bounded.
    #[test]
    fn p163_re_encodings_are_bounded_and_computed_once_per_spelling() {
        let _g = fresh();
        for value in [
            "p163+key/Zx9=Qw é!*'()~x",
            "p163<uni>&Key+é'🔑",
            "p163\"quote\\back<>&'+`~ é🔑",
            "p163Ab9Z",
        ] {
            let forms = encodings(value);
            assert!(
                !forms.is_empty() && forms.len() <= MAX_ENCODINGS,
                "{value}: {}",
                forms.len()
            );
            assert!(forms.iter().all(|f| &*f.text != value));
            assert!(
                forms
                    .iter()
                    .all(|f| f.text.chars().count() >= MIN_CREDENTIAL_CHARS)
            );
            for (i, a) in forms.iter().enumerate() {
                assert!(
                    forms[i + 1..]
                        .iter()
                        .all(|b| a.text != b.text || a.edges != b.edges),
                    "{value}: duplicate forms"
                );
            }
        }
        record(P163_KEYS[0]);
        let first: Vec<*const str> = SENT.read().unwrap()[0]
            .encoded
            .iter()
            .map(|e| &*e.text as *const str)
            .collect();
        record(P163_KEYS[0]);
        let again: Vec<*const str> = SENT.read().unwrap()[0]
            .encoded
            .iter()
            .map(|e| &*e.text as *const str)
            .collect();
        assert_eq!(
            first, again,
            "re-recording must reuse the forms, not recompute them"
        );
        assert_eq!(base64_embedded(b"abcdef", 0), "YWJjZGVm");
        // "abcd" is "YWJjZA==": the last "A" also carries the byte after it.
        assert_eq!(base64_embedded(b"abcd", 0), "YWJjZ");
        // "?abcde" is "?GFiY2Rl" and "??abcde" is "???hYmNkZQ": the leading chars carry the bytes before.
        assert_eq!(base64_embedded(b"abcde", 1), "FiY2Rl");
        assert_eq!(base64_embedded(b"abcde", 2), "hYmNkZ");
        assert_eq!(base64_encode_unpadded(b"foob"), "Zm9vYg");
    }

    /// The single-pass search finds exactly what a per-needle scan finds, overlapping and shared-prefix needles
    /// included, and stops when asked to.
    #[test]
    fn p163_find_all_matches_a_per_needle_scan() {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut random = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        // A 3-letter alphabet makes matches, overlaps and shared prefixes common.
        let hay: Vec<u8> = (0..4000).map(|_| b"abc"[(random() % 3) as usize]).collect();
        let owned: Vec<Vec<u8>> = (0..40)
            .map(|i| {
                (0..2 + i % 7)
                    .map(|_| b"abc"[(random() % 3) as usize])
                    .collect()
            })
            .chain([
                b"abcabcab".to_vec(),
                b"abcabcab".to_vec(),
                b"x".to_vec(),
                Vec::new(),
            ])
            .collect();
        let needles: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
        let prefixes = Prefixes::new(&needles);
        let mut fast: Vec<(usize, usize)> = Vec::new();
        find_all(&hay, &needles, &prefixes, |idx, start| {
            fast.push((idx, start));
            true
        });
        let mut slow: Vec<(usize, usize)> = needles
            .iter()
            .enumerate()
            .filter(|(_, n)| n.len() >= 2)
            .flat_map(|(idx, n)| occurrences(&hay, n).map(move |start| (idx, start)))
            .collect();
        assert!(fast.windows(2).all(|w| w[0].1 <= w[1].1), "ascending start");
        fast.sort_unstable();
        slow.sort_unstable();
        assert!(!slow.is_empty());
        assert_eq!(fast, slow);
        let mut calls = 0;
        assert!(!find_all(&hay, &needles, &prefixes, |_, _| {
            calls += 1;
            false
        }));
        assert_eq!(calls, 1);
        assert!(find_all(b"a", &needles, &prefixes, |_, _| panic!(
            "shorter than every needle"
        )));
    }

    /// Astra r1 #4: the base64 of a different value that shares all of the key but the bits of its last (or first)
    /// character is not taken for the key: the key's bits in the neighbouring characters are checked.
    #[test]
    fn p163_an_in_blob_form_checks_the_key_bits_its_neighbours_carry() {
        let _g = fresh();
        record("abcdefgh");
        // base64("abcdefgi"): the in-blob form `YWJjZGVmZ2` is followed by `k`, whose top 4 bits are not h's last 4.
        assert_eq!(scrub("YWJjZGVmZ2k="), "YWJjZGVmZ2k=");
        assert_eq!(scrub("YWJjZGVmZ2g="), PLACEHOLDER);
        for (other, near) in [("abcdefgi", "!!abcdefgh"), ("abcdefgx", "x:abcdefgh")] {
            for (inner, redacted) in [(format!("x:{other}"), false), (near.to_owned(), true)] {
                let blob = base64_encode(inner.as_bytes());
                let out = scrub(&blob).into_owned();
                assert_eq!(
                    out.contains(PLACEHOLDER),
                    redacted,
                    "{inner}: {blob} -> {out}"
                );
            }
        }
        // ... and at the front: `aabcdefgh` vs `a` + a first byte that differs only in the bits shared with `a`.
        clear_for_tests();
        record("q163-front-key");
        let near = base64_encode(b"aq163-front-key");
        let other = base64_encode(b"aQ163-front-key"); // 'q' 0x71 and 'Q' 0x51 differ in a top bit.
        assert_eq!(scrub(&near), "YX<redacted>", "{near}");
        assert_eq!(scrub(&other), other);
    }

    /// Astra r1 #5: a cut-off base64 form is replaced from as many characters as the key's first 8 chars take in
    /// base64, multibyte chars included, not from 11 characters.
    #[test]
    fn p163_a_cut_off_base64_form_needs_eight_chars_of_the_key() {
        let _g = fresh();
        let key = "🔑🔑🔑🔑🔑🔑🔑🔑-p163-tail";
        record(key);
        let blob = base64_encode(key.as_bytes());
        // 8 keys are 32 bytes, 43 base64 characters.
        let short = format!("{}\u{2026}", &blob[..42]);
        assert_eq!(scrub(&short), short);
        let long = format!("{}\u{2026}", &blob[..44]);
        assert_eq!(scrub(&long), "<redacted>\u{2026}");
    }

    /// A cap that fell inside an escape (`%7…`, `\u00…`) leaves the rest of the escape before the mark.
    #[test]
    fn p163_a_cap_inside_an_escape_is_covered_with_the_prefix() {
        let _g = fresh();
        let key = "p163-key-Qz8Wm4Xr-and-more-key";
        record(key);
        let every: String = key.bytes().map(|b| format!("%{b:02X}")).collect();
        for cut in [every.len() - 1, every.len() - 2, every.len() - 3] {
            let text = format!("k={}\u{2026}", &every[..cut]);
            assert_eq!(scrub(&text), "k=<redacted>\u{2026}", "{text}");
        }
        let escaped: String = key
            .chars()
            .map(|c| format!("\\u{:04x}", u32::from(c)))
            .collect();
        for cut in [escaped.len() - 1, escaped.len() - 3, escaped.len() - 5] {
            let text = format!("k={}\u{2026}", &escaped[..cut]);
            assert_eq!(scrub(&text), "k=<redacted>\u{2026}", "{text}");
        }
    }

    /// A decoded view is built over bounded windows; an encoded key that straddles a window boundary is still found,
    /// once, and the text around it is kept byte for byte.
    #[test]
    fn p163_an_encoded_key_across_a_view_window_boundary_is_found() {
        let _g = fresh();
        let key = "p163-window-key-Zq9";
        record(key);
        let encoded: String = key.bytes().map(|b| format!("%{b:02x}")).collect();
        let escaped: String = key
            .chars()
            .map(|c| format!("\\u{:04X}", u32::from(c)))
            .collect();
        for form in [&encoded, &escaped] {
            for shift in [0, 1, 7, form.len() / 2, form.len() - 1, form.len()] {
                // Escape-like bytes that decode to nothing, and a space so no `\` joins the form's first escape.
                let pad = "%zz\\q".repeat((VIEW_WINDOW - shift) / 5 + 1);
                let pad = format!("{} ", &pad[..VIEW_WINDOW - shift - 1]);
                let text = format!("{pad}{form} tail {form}");
                let want = format!("{pad}<redacted> tail <redacted>");
                assert!(scrub(&text) == want, "shift {shift}");
            }
        }
    }

    /// `safe_cut` keeps an encoded key whole, and never stores one span per occurrence (Astra r1 #3).
    #[test]
    fn p163_safe_cut_keeps_an_encoded_key_whole() {
        let _g = fresh();
        let key = "p163-cut-key-Wq2";
        record(key);
        let encoded: String = key.bytes().map(|b| format!("%{b:02X}")).collect();
        let text = format!("head {encoded} tail");
        let start = text.find('%').unwrap();
        assert_eq!(safe_cut(&text, start + 10), start + encoded.len());
        assert_eq!(safe_cut(&text, start), start);
        let basic = base64_encode(format!("u:{key}").as_bytes());
        let text = format!("Basic {basic}");
        let cut = safe_cut(&text, 10);
        assert!(cut >= text.len() - 2, "{cut} of {}", text.len());
        // A long run of one recorded credential: the cut moves to its end.
        clear_for_tests();
        record("AAAAAAAA");
        let run = "A".repeat(1 << 20);
        assert_eq!(safe_cut(&run, 200), run.len());
    }

    /// Astra r2 #1/#2: decoding state carries from one piece to the next. A key right after an escaped backslash
    /// that straddles a piece boundary, and a key escaped character by character twice over (every character, then
    /// every character of that), are found at every offset around the boundary.
    #[test]
    fn p163_decoding_state_carries_across_pieces() {
        let _g = fresh();
        let u = |s: &str| -> String {
            s.chars()
                .map(|c| format!("\\u{:04x}", u32::from(c)))
                .collect()
        };
        record("n163-window-key");
        // Read as a whole: an escaped backslash, then `n163-`, an escaped `w`, and `indow-key`.
        let after_backslash = format!(r"\\n163-{}indow-key", u("w"));
        let twice = u(&u("n163-window-key"));
        assert_eq!(twice.len(), 36 * "n163-window-key".len());
        for form in [&after_backslash, &twice] {
            for shift in [0, 1, 2, 3, 7, 300, form.len() - 1] {
                let text = format!(
                    "{}{form}{}",
                    " ".repeat(VIEW_WINDOW - shift),
                    " ".repeat(VIEW_WINDOW)
                );
                let out = scrub(&text);
                assert!(
                    out.contains(PLACEHOLDER)
                        && !out.contains("indow-key")
                        && !out.contains("u0077"),
                    "shift {shift}: {}",
                    out.trim()
                );
                assert!(
                    out.starts_with(&" ".repeat(VIEW_WINDOW - shift)),
                    "shift {shift}"
                );
            }
        }
    }

    /// Astra r2 #3/#4: an in-blob form whose neighbour is escaped is checked against what the escape decodes to: the
    /// key's own neighbour is accepted (whichever of the text and its decoded views sees it), another value's is not.
    #[test]
    fn p163_an_escaped_neighbour_is_read_as_what_it_decodes_to() {
        let _g = fresh();
        record("abcdefgh");
        // base64("aabcdefgh") with its `W` percent-encoded: the key's bits are in that `W`.
        let out = scrub("Y%57FiY2RlZmdo").into_owned();
        assert!(
            out.contains(PLACEHOLDER) && !out.contains("FiY2RlZmdo"),
            "{out}"
        );
        // base64("abcdefgo" + "é") with its `/` (and padding) escaped: `/` does not carry h's last bits.
        for other in [
            "YWJjZGVmZ2%2FDqQ%3D%3D",
            r"YWJjZGVmZ2\/DqQ==",
            r"YWJjZGVmZ2\\/DqQ==",
        ] {
            assert_eq!(scrub(other), other);
        }
        // ... but it does carry o's.
        clear_for_tests();
        record("abcdefgo");
        for own in ["YWJjZGVmZ2%2FDqQ%3D%3D", r"YWJjZGVmZ2\/DqQ=="] {
            assert!(scrub(own).starts_with(PLACEHOLDER), "{own}");
        }
        // base64("?" + key) with its `/` percent-encoded.
        clear_for_tests();
        record("\u{1f511}abcdefg");
        let out = scrub("P%2FCflJFhYmNkZWZn").into_owned();
        assert!(
            out.contains(PLACEHOLDER) && !out.contains("CflJFhYmNkZWZn"),
            "{out}"
        );
    }

    /// Astra r3: alignments that share a text keep their own edges (#1); escape-like text just before a raw blob may
    /// be read either way (#2); a backslash written as a `\u` escape is left to the view that decodes twice (#3); a
    /// piece that ends inside an escaped right neighbour waits for the whole escape (#4).
    #[test]
    fn p163_edges_hold_across_shared_texts_escape_like_text_and_pieces() {
        let _g = fresh();
        record("UUUUUUUU");
        // Every alignment of `UUUUUUUU` reads `VVVVVVVVVV`; here it is the one after `bob:`.
        let basic = base64_encode(b"bob:UUUUUUUU:tail");
        assert_eq!(basic, "Ym9iOlVVVVVVVVVVOnRhaWw=");
        let out = scrub(&format!("Authorization: Basic {basic}")).into_owned();
        assert!(
            out.contains(PLACEHOLDER) && !out.contains("VVVVVVVVVV"),
            "{out}"
        );
        clear_for_tests();
        record("abcdefgh");
        // A literal `%` before the base64 of "\xe3abcdefgh": `%42` is not an escape here.
        let out = scrub("%42FiY2RlZmdo").into_owned();
        assert!(
            out.contains(PLACEHOLDER) && !out.contains("FiY2RlZmdo"),
            "{out}"
        );
        // base64("abcdefgo" + "e-acute") with its `/` after a backslash written as a `\u` escape: not this key.
        let bs = '\\';
        let unicode_backslash = format!("YWJjZGVmZ2{bs}u005c/DqQ==");
        assert_eq!(scrub(&unicode_backslash), unicode_backslash);
        // The first piece of the JSON view ends on the `%` of `%2F`.
        let split = format!(
            "{}YWJjZGVmZ2%2FDqQ%3D%3D {bs}n",
            " ".repeat(VIEW_WINDOW - 11)
        );
        assert_eq!(scrub(&split), split);
    }

    // ---- P179: the cut-off check looks only at spellings whose beginning can end where the text before a mark ends. ----

    /// Restores the check of every spelling at every mark when dropped.
    struct Unfiltered;

    impl Unfiltered {
        fn on() -> Self {
            CUT_OFF_UNFILTERED.with(|c| c.set(true));
            Self
        }
    }

    impl Drop for Unfiltered {
        fn drop(&mut self) {
            CUT_OFF_UNFILTERED.with(|c| c.set(false));
        }
    }

    fn p179_scrub_both_ways(text: &str) -> (String, String) {
        let fast = scrub(text).into_owned();
        let slow = {
            let _all = Unfiltered::on();
            scrub(text).into_owned()
        };
        (fast, slow)
    }

    /// Every `(start, mark)` that [`Index::cut_off`] reports for `text`, in order, with or without the tail bitmap.
    fn p179_cut_off_calls(text: &str, unfiltered: bool) -> Vec<(usize, usize)> {
        let sent = SENT.read().unwrap();
        let index = Index::new(&sent);
        let _all = unfiltered.then(Unfiltered::on);
        let mut calls = Vec::new();
        index.cut_off(text.as_bytes(), |start, mark| {
            calls.push((start, mark));
            true
        });
        calls
    }

    /// The registry's spellings with their cut-off tails, as the scrub builds them.
    fn p179_tails_of_registry() -> (Vec<String>, Vec<usize>) {
        let sent = SENT.read().unwrap();
        let index = Index::new(&sent);
        (
            index.spellings.iter().map(|s| s.text.to_owned()).collect(),
            index.spellings.iter().map(|s| s.floor).collect(),
        )
    }

    /// Every admissible cut-off beginning of every spelling (each char boundary at or after its floor) followed by a
    /// mark is found, and the check that only looks at the spellings ending that way gives what the one that looks at
    /// all of them gives.
    #[test]
    fn p179_every_admissible_cut_off_beginning_is_found_through_the_tail_bitmap() {
        let _g = fresh();
        for key in [
            "p179-key-Qz8Wm4Xr",
            "p179?>~~Kq7?>~~Lm2Vz",
            "clé-secrète-été-x",
        ] {
            record(key);
        }
        let (texts, floors) = p179_tails_of_registry();
        assert!(texts.len() > 15, "{}", texts.len());
        let mut checked = 0;
        for (text, floor) in texts.iter().zip(floors) {
            let Some(first) = text.char_indices().nth(floor).map(|(i, _)| i) else {
                continue;
            };
            for (len, _) in text.char_indices().filter(|&(i, _)| i >= first) {
                let probe = format!("x {}\u{2026} y", &text[..len]);
                let (fast, slow) = p179_scrub_both_ways(&probe);
                assert_eq!(fast, slow, "{probe}");
                assert!(fast.contains(PLACEHOLDER), "{probe} -> {fast}");
                assert!(!fast.contains(&text[..len]), "{probe} -> {fast}");
                checked += 1;
            }
        }
        assert!(checked > 100, "{checked}");
    }

    /// A beginning too short to have a last-two-bytes pair (floor 0 or 1 char) is checked at every mark; a spelling
    /// shorter than its floor never matches; the bitmap says no to text that cannot end a beginning.
    #[test]
    fn p179_short_beginnings_are_always_candidates_and_ordinary_text_none() {
        let spellings = [
            Spelling {
                text: "abcdefgh",
                floor: 2,
                edges: Edges::default(),
            },
            Spelling {
                text: "xyz",
                floor: 5,
                edges: Edges::default(),
            },
            Spelling {
                text: "\u{e9}tuvwxyz",
                floor: 0,
                edges: Edges::default(),
            },
        ];
        let tails = CutOffTails::new(&spellings);
        assert_eq!(
            tails.always,
            vec![2],
            "only floor 0 gives a 0-byte beginning"
        );
        let mut out = Vec::new();
        tails.candidates(b"zzzz", &mut out);
        assert_eq!(out, vec![2]);
        // `abcdefgh` from a 2-char floor: beginnings `ab` .. `abcdefg`, ending `ab`, `bc`, .. `fg`.
        for pair in [b"ab", b"bc", b"cd", b"de", b"ef", b"fg"] {
            out.clear();
            tails.candidates(pair, &mut out);
            assert!(out.contains(&0), "{pair:?}");
        }
        out.clear();
        tails.candidates(b"gh", &mut out);
        assert!(
            !out.contains(&0),
            "the whole spelling is not a cut-off beginning"
        );
        out.clear();
        tails.candidates(b"yz", &mut out);
        assert!(!out.contains(&1), "`xyz` is shorter than its floor");
        // Too short a text to end a two-byte beginning: only the always-checked ones.
        out.clear();
        tails.candidates(b"a", &mut out);
        assert_eq!(out, vec![2]);
    }

    /// Randomized differential: with the bitmap and without it, the scrub gives byte-identical output, on random text
    /// of keys, their beginnings (raw, base64, percent- and `\u`-cut) and marks, over a small alphabet that makes
    /// shared tails common.
    #[test]
    fn p179_the_scrub_is_byte_identical_with_and_without_the_tail_bitmap() {
        let _g = fresh();
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut random = move |n: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 11) as usize % n
        };
        let alphabet: Vec<char> = "abcd\u{e9} +/%\\u0A".chars().collect();
        let mut keys: Vec<String> = Vec::new();
        for _ in 0..12 {
            let len = 8 + random(8);
            let key: String = (0..len).map(|_| alphabet[random(alphabet.len())]).collect();
            record(&key);
            keys.push(key);
        }
        let (mut changed, mut with_mark) = (0, 0);
        for _ in 0..600 {
            let mut text = String::new();
            for _ in 0..1 + random(8) {
                let key = &keys[random(keys.len())];
                let chars: Vec<char> = key.chars().collect();
                let cut: String = chars[..1 + random(chars.len())].iter().collect();
                match random(9) {
                    0 => text.push_str(key),
                    1 => text.push_str(&format!("{cut}\u{2026}")),
                    2 => text.push_str(&format!("{}\u{2026}", base64_encode(cut.as_bytes()))),
                    3 => text.push_str(&format!("{cut}%\u{2026}")),
                    4 => text.push_str(&format!("{cut}\\u00\u{2026}")),
                    5 => text.push_str(&format!("{cut}%4\u{2026}")),
                    6 => text.push('\u{2026}'),
                    _ => (0..random(6)).for_each(|_| text.push(alphabet[random(alphabet.len())])),
                }
            }
            let (fast, slow) = p179_scrub_both_ways(&text);
            assert_eq!(fast, slow, "{text:?}");
            // The matches themselves, in order and as often as found, not only what they leave.
            assert_eq!(
                p179_cut_off_calls(&text, false),
                p179_cut_off_calls(&text, true),
                "{text:?}"
            );
            changed += usize::from(fast != text);
            with_mark += usize::from(text.contains('\u{2026}'));
            // The bytes entry point too.
            let fast_bytes = scrub_bytes(text.as_bytes());
            let slow_bytes = {
                let _all = Unfiltered::on();
                scrub_bytes(text.as_bytes())
            };
            assert_eq!(fast_bytes, slow_bytes, "{text:?}");
        }
        assert!(changed > 100 && with_mark > 300, "{changed} {with_mark}");
    }

    /// Fable's P163 audit (LOW): what stands right after an in-blob form. Text that is not an escape, or a cut escape,
    /// does not carry other bits and the form is replaced. A complete escape is read as the byte it decodes to, so a
    /// wrong-bits escape (`%41`, `%2F`) is another value's base64 and stays: the opposite choice (read the raw `%`
    /// too, as the left neighbour is read) would replace the base64 of `abcdefgo` + `e-acute` that Astra r2 #3 requires
    /// to stay unchanged (`p163_an_escaped_neighbour_is_read_as_what_it_decodes_to`).
    #[test]
    fn p179_the_right_neighbour_of_an_in_blob_form() {
        let _g = fresh();
        record("abcdefgh");
        let form = "YWJjZGVmZ2";
        for tail in ["", "%", "%3", "%3D", "\n", "\"", "g", "g=", "\\"] {
            let text = format!("{form}{tail}");
            let out = scrub(&text).into_owned();
            assert!(
                out.contains(PLACEHOLDER) && !out.contains(form),
                "{text:?} -> {out:?}"
            );
        }
        for tail in ["k", "k=", "%41", "%2F", "A", "B", "-"] {
            let text = format!("{form}{tail}");
            assert_eq!(scrub(&text), text, "{tail:?}");
        }
    }

    /// A byte that [`Escapes::plain_run`] takes for plain decodes to itself as one token whatever follows it.
    #[test]
    fn p179_a_plain_run_is_what_the_token_decoder_copies() {
        for level in [
            Escapes::Percent { plus: false },
            Escapes::Percent { plus: true },
            Escapes::Json,
        ] {
            for b in 0..=255u8 {
                for tail in [&b"41"[..], b"u0041", b"2F", b"\\", b"", b"zz"] {
                    let src = [&[b][..], tail].concat();
                    let plain = level.plain_run(&src, 0, src.len()) > 0;
                    let mut out = Vec::new();
                    let used = level.token(&src, 0, &mut out);
                    if plain {
                        assert_eq!((used, out.as_slice()), (1, &[b][..]), "{level:?} {b}");
                    }
                }
            }
            // The run stops at the first byte that can begin an escape, and at the bound.
            let first_escape = if level == Escapes::Json { 3 } else { 4 };
            assert_eq!(level.plain_run(b"abc\\%+d", 0, 7), first_escape);
            assert_eq!(level.plain_run(b"abcdef", 1, 4), 3);
            assert_eq!(level.plain_run(b"abc", 3, 3), 0);
        }
    }

    /// A table past its size limit is dropped: a bitmap hit then stands for every spelling, a miss for none, and
    /// every spelling that has a match is still a candidate.
    #[test]
    fn p179_a_tail_table_past_its_limit_falls_back_to_the_bitmap() {
        let spellings = [
            Spelling {
                text: "abcdefgh",
                floor: 1,
                edges: Edges::default(),
            },
            Spelling {
                text: "wxyzwxyz",
                floor: 2,
                edges: Edges::default(),
            },
            Spelling {
                text: "mnopqrst",
                floor: 3,
                edges: Edges::default(),
            },
        ];
        let table = CutOffTails::with_limit(&spellings, 1 << 20);
        let bitmap_only = CutOffTails::with_limit(&spellings, 3);
        assert!(table.overflow.is_none() && !table.sorted.is_empty());
        assert!(bitmap_only.overflow.is_some() && bitmap_only.sorted.is_empty());
        // `abcdefgh` from a 1-char floor has a 1-byte beginning: always checked, in either mode.
        assert_eq!(table.always, vec![0]);
        assert_eq!(bitmap_only.always, vec![0]);
        for a in 0..=255u8 {
            for b in [b'a', b'c', b'x', b'z', b'n', b'p', b'q', b'\xe2'] {
                let (mut exact, mut loose) = (Vec::new(), Vec::new());
                table.candidates(&[a, b], &mut exact);
                bitmap_only.candidates(&[a, b], &mut loose);
                exact.sort_unstable();
                loose.sort_unstable();
                assert!(
                    exact.iter().all(|i| loose.contains(i)),
                    "{a} {b}: {exact:?} not within {loose:?}"
                );
            }
        }
        let (mut hit, mut miss) = (Vec::new(), Vec::new());
        bitmap_only.candidates(b"yz", &mut hit);
        bitmap_only.candidates(b"!!", &mut miss);
        assert_eq!(hit, vec![0, 0, 1, 2]);
        assert_eq!(miss, vec![0]);
    }

    /// Randomized differential: with the runs of plain bytes copied and with every token decoded on its own (the
    /// decoder before P179), the scrub is byte-identical, on escape-rich text of encoded keys, short and across the
    /// 64 KiB pieces of the decoded views, so the decoded text and its source map are the same too.
    #[test]
    fn p179_the_scrub_is_byte_identical_with_and_without_bulk_copying() {
        let _g = fresh();
        let mut state = 0xD1B5_4A32_D192_ED03u64;
        let mut random = move |n: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 11) as usize % n
        };
        let keys = [
            "p179-bulk-Qz8Wm4Xr",
            "p179 bulk ?>~~ Kq7Lm2Vz",
            "p179\"q\"\\b-Zq9w",
        ];
        for key in keys {
            record(key);
        }
        let percent = |s: &str| s.bytes().map(|b| format!("%{b:02x}")).collect::<String>();
        let unicode = |s: &str| {
            s.chars()
                .map(|c| format!("\\u{:04x}", c as u32))
                .collect::<String>()
        };
        let atoms = [
            "plain text ",
            "0123456789abcdef",
            "%41",
            "%2",
            "%zz",
            "+",
            "\\n",
            "\\\"",
            "\\u00e9",
            "\\ud83d\\udd11",
            "\\ud800",
            "\\u005c",
            "\\\\",
            "\\\\u0041",
            "\\/",
            "%",
            "\\",
            "\u{e9}",
            "\u{2026}",
            "\u{1f511}",
        ];
        let (mut changed, mut windows) = (0, 0);
        for round in 0..120 {
            let long = round % 6 == 0;
            let mut text = String::new();
            let target = if long { 2 * VIEW_WINDOW + 40 } else { 400 };
            while text.len() < target {
                let key = keys[random(keys.len())];
                match random(10) {
                    0 => text.push_str(&percent(key)),
                    1 => text.push_str(&unicode(key)),
                    2 => text.push_str(&base64_encode(key.as_bytes())),
                    3 => text.push_str(&percent(&key[..8 + random(key.len() - 8)])),
                    4 => text.push_str(key),
                    5..=7 => text.push_str(atoms[random(atoms.len())]),
                    _ => text.push_str(&"x".repeat(random(if long { 9000 } else { 30 }))),
                }
            }
            let fast = scrub(&text).into_owned();
            let slow = {
                let _tokens = PlainRunsOff::on();
                scrub(&text).into_owned()
            };
            assert_eq!(fast, slow, "round {round}");
            changed += usize::from(fast != text);
            windows += usize::from(long);
        }
        assert!(changed > 100 && windows >= 20, "{changed} {windows}");
    }

    /// Restores the plain-run copy when dropped.
    struct PlainRunsOff;

    impl PlainRunsOff {
        fn on() -> Self {
            PLAIN_RUNS_OFF.with(|c| c.set(true));
            Self
        }
    }

    impl Drop for PlainRunsOff {
        fn drop(&mut self) {
            PLAIN_RUNS_OFF.with(|c| c.set(false));
        }
    }
}
