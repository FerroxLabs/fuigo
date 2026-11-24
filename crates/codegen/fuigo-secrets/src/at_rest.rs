//! Secrets at rest (1.0.47 S2, SL-06): the one byte layer for every file Fuigo writes under its session and log roots
//! (`$FUIGO_HOME/sessions/**`, `$FUIGO_HOME/logs/**`).
//!
//! - **What is recorded.** The values of Fuigo's own secret-named environment variables ([`is_secret_env_name`]),
//!   captured at process start ([`capture_env`]) and before the first transform as a backstop; the current values of
//!   names a config registers later ([`record_env_names`]); and every credential this process sends
//!   ([`crate::sent_credentials::record`] pins it here). A value is recorded only when [`recordable`]. The set is never
//!   evicted (unlike the display registry).
//! - **How it is applied.** [`transform_whole`] for a whole file or one record, [`AtRestStream`] for appends that arrive
//!   in pieces, [`AtRestFile`] around a `Write`. Exact match only, in every spelling `sent_credentials` covers (raw, JSON
//!   escaped once and twice, percent, base64). JSON is edited in place inside its string tokens, at whole escape atoms,
//!   so keys, numbers, order and formatting stay byte-identical; a record that still holds a value afterwards (one in a
//!   key, a number, or across tokens) is replaced by [`WITHHELD_MARKER`], never written raw.
//! - **What it leaves alone.** Display sinks (TUI, headless stdout, ACP) keep using the sent registry only; what the
//!   model receives in the live turn is never touched. The two verbatim stores are [`Verbatim`].

use std::borrow::Cow;
use std::ffi::OsStr;
use std::io::{self, Write};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};

use crate::sent_credentials::{
    CutOffTails, Entry, Index, MIN_CREDENTIAL_CHARS, MIN_TRUNCATED_PREFIX_CHARS, PLACEHOLDER,
    Spelling, WITHHELD, incomplete_escape_len, json_escape, percent_escape, truncated_prefix_len,
};

/// What a JSON record that would still hold a recorded value after the in-place edit is written as (design §2.1). The
/// chat loader reads it as a known placeholder, not as corruption.
pub const WITHHELD_MARKER: &str = r#"{"fuigo_withheld_at_rest":true}"#;

/// Whether a whole-file JSON store holds only [`WITHHELD_MARKER`]: its readers treat it as absent (a rebuild or a
/// fresh default), not as corruption (Fable code review #6).
pub fn is_withheld(bytes: &[u8]) -> bool {
    bytes.trim_ascii() == WITHHELD_MARKER.as_bytes()
}

/// The terminal fallback when a recorded value is itself inside [`WITHHELD_MARKER`] (Astra r2 A#9): it holds no string,
/// so it can hold no recorded value.
const EMPTY_RECORD: &str = "{}";

/// Values shorter than this whose letters and digits are all one class (all lowercase, all uppercase or all digits)
/// are not recorded (coordinator decision 1): `postgres`, `assistant` and `12345678` would rewrite ordinary words,
/// schema tags and JSON numbers.
pub const ONE_CLASS_FLOOR_CHARS: usize = 16;

/// A stream holds back a suffix only once it is the beginning of a recorded spelling at least this many key characters
/// long (Fable r2 #5), so between pushes at most three characters of a value split by a write boundary are on disk
/// before [`PLACEHOLDER`]. [`AtRestStream::finish`] replaces a held beginning only from
/// [`MIN_TRUNCATED_PREFIX_CHARS`] (eight) key characters, so a finish on a held beginning of four to seven writes those
/// characters raw: too short to tell a value from ordinary text.
pub const HOLD_CHARS: usize = 4;

/// Past this many recorded spellings a warning is logged once (design §4; the set itself has no cap).
const WARN_PAST: usize = 4096;

/// Raw bytes a stream keeps of what it already wrote, to see a value that starts there. Enough for three held-back key
/// characters in their longest spelling (`\\u0041` twice-escaped, 7 bytes each) and an escape around them.
const CONTEXT: usize = 64;

/// The stores that are written exactly (design §2.4, Astra N3). This enum is the only way to skip the transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verbatim {
    /// `rewind_points.jsonl`, its pre-rewind copy and the rewind journal (coordinator decision: `/rewind` copies stay
    /// verbatim; the journal fingerprints these exact bytes for kill recovery).
    RewindStore,
    /// The always-allow grant stores under `sessions/<cwd>/` (coordinator decision: a grant is matched byte for byte, so
    /// redacting it would make an approved command prompt again).
    PermissionGrants,
    /// Generated and downloaded media in the session folder (`images/`, `videos/`, `downloads/`): binary files read back
    /// as model input, which a byte edit would corrupt (Astra N3). Only bytes that begin with a known image, video or
    /// PDF signature ([`Verbatim::holds`]): anything else written there is transformed like every other file.
    Media,
}

impl Verbatim {
    /// The verbatim store a session-folder file belongs to, from its path relative to the folder; `None` for every other
    /// file (transformed).
    pub fn for_session_rel(rel: &std::path::Path) -> Option<Self> {
        let mut parts = rel.components();
        let first = parts.next()?.as_os_str().to_str()?;
        match first {
            "rewind_points.jsonl"
            | "rewind_points.jsonl.pre-rewind"
            | "rewind_points.jsonl.pre-rewind.journal"
                if parts.next().is_none() =>
            {
                Some(Self::RewindStore)
            }
            "images" | "videos" | "downloads" if parts.next().is_some() => Some(Self::Media),
            _ => None,
        }
    }

    /// Whether bytes beginning with `head` are what this store keeps verbatim. For [`Verbatim::Media`], by content, not
    /// by path (Fable S2 confirm review): PNG, JPEG, GIF, WebP, ISO media (MP4/MOV/HEIC/AVIF), WebM/Matroska or PDF.
    /// Twelve bytes are enough to decide.
    pub fn holds(self, head: &[u8]) -> bool {
        self != Self::Media || is_media(head)
    }

    /// [`Verbatim::for_session_rel`], kept only when [`Verbatim::holds`] the bytes that begin with `head`.
    pub fn for_session_write(rel: &std::path::Path, head: &[u8]) -> Option<Self> {
        Self::for_session_rel(rel).filter(|store| store.holds(head))
    }
}

/// A media file signature at the start of `b`.
fn is_media(b: &[u8]) -> bool {
    const SIGNATURES: [&[u8]; 6] = [
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8\xff",
        b"GIF87a",
        b"GIF89a",
        b"%PDF-",
        b"\x1a\x45\xdf\xa3",
    ];
    SIGNATURES.iter().any(|sig| b.starts_with(sig))
        || (b.starts_with(b"RIFF") && b.get(8..12) == Some(b"WEBP"))
        || b.get(4..8) == Some(b"ftyp")
}

// ---- the at-rest set ------------------------------------------------------------------------------------------------

#[derive(Default)]
struct State {
    /// The values recorded (each once), for dedup.
    values: std::collections::HashSet<Box<str>>,
    /// Non-UTF-8 environment values, matched by their exact bytes (Astra code review High 3). Leaked like the entries.
    raw: Vec<&'static [u8]>,
    /// Their entries (the value and its JSON escapings, each with base64 forms). Leaked on purpose: the set is never
    /// evicted, so an entry lives as long as the process, and the cached index can borrow it for `'static`.
    entries: Vec<&'static Entry>,
    cached: Option<Arc<Snapshot>>,
    env_captured: bool,
    warned: bool,
}

static STATE: LazyLock<Mutex<State>> = LazyLock::new(Mutex::default);

fn state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One generation of the set, indexed once (design test 11: the index is cached per generation).
struct Snapshot {
    index: Index<'static>,
    /// The spellings with their own truncated-prefix floors ([`MIN_TRUNCATED_PREFIX_CHARS`]): a held prefix this long is
    /// replaced when a stream finishes.
    cut: Vec<Spelling<'static>>,
    cut_tails: CutOffTails,
    /// The spellings with the [`HOLD_CHARS`] floor: a stream holds back a suffix that begins one of these.
    hold: Vec<Spelling<'static>>,
    hold_tails: CutOffTails,
    /// Whether a spelling holds a space (the percent view that reads `+` as a space is then searched too).
    plus: bool,
    /// [`State::raw`]: searched as exact bytes beside the index.
    raw: Vec<&'static [u8]>,
    /// The longest spelling or raw value, in bytes.
    longest: usize,
}

impl Snapshot {
    /// Every match of a recorded spelling or raw value in `bytes`, sorted and merged.
    fn find(&self, bytes: &[u8]) -> Vec<(usize, usize)> {
        let mut found = matches(&self.index, bytes);
        if !self.raw.is_empty() {
            for value in &self.raw {
                found.extend(
                    memchr::memmem::find_iter(bytes, value).map(|at| (at, at + value.len())),
                );
            }
            found = merge(found);
        }
        found
    }

    /// Whether `bytes` holds a recorded spelling or raw value.
    fn any(&self, bytes: &[u8]) -> bool {
        self.index.contains_any(bytes)
            || self
                .raw
                .iter()
                .any(|value| memchr::memmem::find(bytes, value).is_some())
    }

    /// The smallest `h >= from` where `buf[h..]` is the beginning of a raw value at least `floor` bytes long (one that
    /// began before `from` holds from `from`). `earliest` is lowered to where such a beginning starts, unclamped.
    fn raw_live_start(
        &self,
        buf: &[u8],
        from: usize,
        floor: usize,
        earliest: &mut usize,
    ) -> Option<usize> {
        self.raw
            .iter()
            .filter_map(|value| {
                (floor..value.len().min(buf.len() + 1))
                    .rev()
                    .find(|&len| buf.ends_with(&value[..len]))
                    .map(|len| {
                        *earliest = (*earliest).min(buf.len() - len);
                        (buf.len() - len).max(from)
                    })
            })
            .min()
    }
}

/// Whether `value` is recorded at all: at least [`MIN_CREDENTIAL_CHARS`] chars, and not under [`ONE_CLASS_FLOOR_CHARS`]
/// with all its letters and digits in one class. A value that is (a piece of) a schema word is recorded too: the JSON
/// edit protects the schema's own tokens instead (Astra code review High 2).
pub fn recordable(value: &str) -> bool {
    let chars = value.chars().count();
    if chars < MIN_CREDENTIAL_CHARS {
        return false;
    }
    if chars < ONE_CLASS_FLOOR_CHARS {
        let (mut lower, mut upper, mut digit) = (false, false, false);
        for c in value.chars() {
            lower |= c.is_lowercase();
            upper |= c.is_uppercase();
            digit |= c.is_numeric();
        }
        if u8::from(lower) + u8::from(upper) + u8::from(digit) <= 1 {
            return false;
        }
    }
    true
}

/// Record `value` in the at-rest set (no-op unless [`recordable`]). Its JSON escaping, once and twice, is recorded too.
pub fn record(value: &str) {
    if !recordable(value) {
        return;
    }
    let warn = {
        let mut state = state();
        if !state.values.insert(value.into()) {
            return;
        }
        let once = json_escaped(value);
        let mut spellings = vec![value.to_owned()];
        if once != value {
            spellings.push(json_escaped(&once));
            spellings.push(once);
        }
        for spelling in spellings {
            let entry: &'static Entry = Box::leak(Box::new(Entry::new(&spelling)));
            state.entries.push(entry);
        }
        state.cached = None;
        let warn = state.entries.len() > WARN_PAST && !state.warned;
        state.warned |= warn;
        warn
    };
    // Logged with the set unlocked: the log writer transforms through this set.
    if warn {
        tracing::warn!(
            limit = WARN_PAST,
            "the at-rest secret set holds many values; session writes may slow down"
        );
    }
}

/// [`record`] for an environment value: a non-UTF-8 value never panics. Its lossy spelling (how it reads in any text
/// Fuigo writes: transcripts, JSON, search) is recorded whole, and so is each long-enough valid UTF-8 run.
// The exact bytes are matched whole too ([`record_raw`]). shortcut: escaped spellings of the non-UTF-8 bytes (`\xff`,
// `%FF`) are not matched; upgrade to byte spellings in the matcher if a writer ever escapes raw bytes that way.
pub fn record_os(value: &OsStr) {
    match value.to_str() {
        Some(text) => record(text),
        None => {
            record_raw(value.as_encoded_bytes());
            record(&value.to_string_lossy());
            for chunk in value.as_encoded_bytes().utf8_chunks() {
                record(chunk.valid());
            }
        }
    }
}

/// Record a non-UTF-8 value by its exact bytes (at least [`MIN_CREDENTIAL_CHARS`] of them).
fn record_raw(bytes: &[u8]) {
    if bytes.len() < MIN_CREDENTIAL_CHARS {
        return;
    }
    let mut state = state();
    if state.raw.contains(&bytes) {
        return;
    }
    state.raw.push(Box::leak(bytes.to_vec().into_boxed_slice()));
    state.cached = None;
}

/// `value` as it reads inside a JSON string, without the quotes.
fn json_escaped(value: &str) -> String {
    let quoted = serde_json::to_string(value).unwrap_or_default();
    quoted
        .get(1..quoted.len().saturating_sub(1))
        .unwrap_or(value)
        .to_owned()
}

/// The name rule (design §4, the plan's rule unmodified): case-insensitive contains `TOKEN`, `SECRET`, `PASSWORD`,
/// `PASSWD`, `API_KEY`, `APIKEY`, `ACCESS_KEY`, `PRIVATE_KEY` or `CREDENTIAL`, or a known or configured credential name.
pub fn is_secret_env_name(name: &str) -> bool {
    // The launch policy path and hash are kept from children for integrity, not secrecy, and the session record
    // stores them as its policy marker: recording them made every cold session/load a `session_policy_conflict`.
    if ["FUIGO_POLICY_PATH", "FUIGO_POLICY_SHA256"]
        .iter()
        .any(|policy| policy.eq_ignore_ascii_case(name))
    {
        return false;
    }
    const PARTS: [&str; 9] = [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "API_KEY",
        "APIKEY",
        "ACCESS_KEY",
        "PRIVATE_KEY",
        "CREDENTIAL",
    ];
    let upper = name.to_ascii_uppercase();
    PARTS.iter().any(|part| upper.contains(part)) || crate::child_env::is_provider_credential(name)
}

/// Record the value of every secret-named variable in this process's environment. Called explicitly at process start;
/// the first transform also calls it once, so nothing is written before the environment is in the set.
pub fn capture_env() {
    for (name, value) in std::env::vars_os() {
        if is_secret_env_name(&name.to_string_lossy()) {
            record_os(&value);
        }
    }
    // Only after the values are in: a concurrent first transform that saw the flag earlier would have used an empty
    // set (Grok S2 confirm review, Medium). One that sees it unset captures too; recording is idempotent.
    state().env_captured = true;
}

/// Record the current values of `names` (a config registered them as credential names, or Fuigo set them itself).
pub fn record_env_names<I, S>(names: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    for name in names {
        if let Some(value) = std::env::var_os(name.as_ref()) {
            record_os(&value);
        }
    }
}

/// The current generation, or `None` when nothing is recorded.
fn snapshot() -> Option<Arc<Snapshot>> {
    let captured = state().env_captured;
    if !captured {
        capture_env();
    }
    let mut state = state();
    if state.entries.is_empty() && state.raw.is_empty() {
        return None;
    }
    if let Some(cached) = &state.cached {
        return Some(cached.clone());
    }
    let cut: Vec<Spelling<'static>> = state
        .entries
        .iter()
        .flat_map(|entry| entry.spellings())
        .collect();
    let hold: Vec<Spelling<'static>> = cut
        .iter()
        .map(|s| Spelling {
            // A value's own floor (eight chars) becomes HOLD_CHARS; a base64 form's floor scales the same way.
            floor: if s.floor == MIN_TRUNCATED_PREFIX_CHARS {
                HOLD_CHARS
            } else {
                s.floor.div_ceil(2)
            },
            ..*s
        })
        .collect();
    let snapshot = Arc::new(Snapshot {
        index: Index::from_spellings(cut.clone()),
        cut_tails: CutOffTails::new(&cut),
        hold_tails: CutOffTails::new(&hold),
        plus: cut.iter().any(|s| s.text.contains(' ')),
        longest: cut
            .iter()
            .map(|s| s.text.len())
            .chain(state.raw.iter().map(|r| r.len()))
            .max()
            .unwrap_or(0),
        raw: state.raw.clone(),
        cut,
        hold,
    });
    state.cached = Some(snapshot.clone());
    Some(snapshot)
}

/// Whether `bytes` holds a recorded value in any spelling (tests, the canary census).
pub fn contains_any(bytes: &[u8]) -> bool {
    snapshot().is_some_and(|snap| snap.any(bytes))
}

/// Test-only: forget the whole set (and mark the environment captured, so a test controls exactly what is recorded).
#[doc(hidden)]
pub fn clear_for_tests() {
    let mut state = state();
    state.values.clear();
    state.entries.clear();
    state.raw.clear();
    state.cached = None;
    state.env_captured = true;
}

// ---- whole files and records ----------------------------------------------------------------------------------------

/// Every match of a recorded spelling in `bytes`, sorted and merged. Allocates nothing when there is none.
fn matches(index: &Index<'_>, bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut found: Vec<(usize, usize)> = Vec::new();
    index.for_each_match(bytes, true, &mut |start, end| {
        found.push((start, end));
        true
    });
    merge(found)
}

fn merge(mut ranges: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// `bytes` as written at rest: unchanged (borrowed) when it holds no recorded value. JSON (one document, or JSON lines)
/// is edited inside its string tokens only; anything else is text. See the module docs.
pub fn transform_whole(bytes: &[u8]) -> Cow<'_, [u8]> {
    let Some(snap) = snapshot() else {
        return Cow::Borrowed(bytes);
    };
    let ranges = snap.find(bytes);
    if ranges.is_empty() {
        return Cow::Borrowed(bytes);
    }
    // The kind is decided only now, on the match path, by the lexer's own pass (Fable r2 #4).
    if let Some(lexed) = lex(bytes)
        && lexed.records_parse(bytes, &ranges)
    {
        return Cow::Owned(transform_json(&snap, bytes, &lexed, &ranges));
    }
    if let Some(mixed) = transform_mixed_lines(&snap, bytes) {
        return Cow::Owned(mixed);
    }
    Cow::Owned(transform_text(&snap, bytes, &ranges))
}

/// Whether `line` is one JSON record (an object or an array) on its own.
pub fn is_json_line(line: &[u8]) -> bool {
    let line = line.trim_ascii();
    matches!(line.first(), Some(b'{' | b'['))
        && serde_json::from_slice::<serde_json::Value>(line).is_ok()
}

/// JSON lines where some lines do not parse (a torn tail, a hand edit; Sean's S2 decision): each line that parses is
/// still edited as JSON, its format labels kept, and each run of the others is one text, so a value spread over such
/// lines is still caught. `None` (then the whole is text) when no line parses, or when the result still holds a value
/// outside a label position (one spanning a JSON line and the text after it). Nothing is ever written raw.
fn transform_mixed_lines(snap: &Snapshot, bytes: &[u8]) -> Option<Vec<u8>> {
    let lines: Vec<&[u8]> = bytes.split_inclusive(|&c| c == b'\n').collect();
    if lines.len() < 2 || !lines.iter().any(|line| is_json_line(line)) {
        return None;
    }
    let text = |run: &[u8], out: &mut Vec<u8>| {
        let ranges = snap.find(run);
        if ranges.is_empty() {
            out.extend_from_slice(run);
        } else {
            out.extend_from_slice(&transform_text(snap, run, &ranges));
        }
    };
    let mut out = Vec::with_capacity(bytes.len());
    let mut run_start = 0;
    let mut at = 0;
    for line in &lines {
        if is_json_line(line) {
            text(&bytes[run_start..at], &mut out);
            let ranges = snap.find(line);
            match lex(line) {
                Some(lexed) if !ranges.is_empty() => {
                    out.extend_from_slice(&transform_json(snap, line, &lexed, &ranges));
                }
                _ => out.extend_from_slice(line),
            }
            run_start = at + line.len();
        }
        at += line.len();
    }
    text(&bytes[run_start..], &mut out);
    // The postcondition, with no exemption outside label positions: a match is allowed only inside one JSON line, in a
    // label token there.
    let mut starts = Vec::new();
    let mut offset = 0;
    for line in out.split_inclusive(|&c| c == b'\n') {
        starts.push(offset);
        offset += line.len();
    }
    let clean = snap.find(&out).iter().all(|&(start, end)| {
        let i = starts.partition_point(|&s| s <= start) - 1;
        let line_end = starts.get(i + 1).copied().unwrap_or(out.len());
        let line = &out[starts[i]..line_end];
        end <= line_end
            && is_json_line(line)
            && lex(line)
                .is_some_and(|lexed| lexed.in_schema_word(line, start - starts[i], end - starts[i]))
    });
    clean.then_some(out)
}

/// [`transform_whole`] on an owned buffer, returning it unchanged when nothing matched.
pub fn transform_owned(bytes: Vec<u8>) -> Vec<u8> {
    match transform_whole(&bytes) {
        Cow::Borrowed(_) => bytes,
        Cow::Owned(out) => out,
    }
}

/// A JSON string token: its content `start..end` (inside the quotes), and whether it is the value of an id key.
#[derive(Debug, Clone, Copy)]
struct Str {
    start: usize,
    end: usize,
    id: bool,
    /// An object key.
    key: bool,
    /// A label position of Fuigo's own record schema (Sean's S2 decision, Astra round-3 High 1): a key of the record's
    /// top-level object (never edited: a match there withholds the record), or the value of a serde tag key
    /// ([`crate::at_rest_schema::TAG_KEYS`]) at the top level or at a [`NESTED_LABELS`] path. Every other key and tag
    /// value, inside nested user JSON (tool arguments and results, MCP payloads, pasted JSON), is edited like any string.
    label: bool,
}

/// The nested paths (object keys from the record root, `[]` for an array element) at which Fuigo's persisted records
/// carry a serde tag: a backend tool call's `kind`, an assistant turn's `output_order`, a tool result's `images`, an
/// `updates.jsonl` notification's `sessionUpdate`. Top-level tag keys are labels without being listed.
const NESTED_LABELS: &[&str] = &[
    "kind.tool_type",
    "kind.type",
    "output_order[].kind",
    "images[].type",
    "params.update.sessionUpdate",
];

#[derive(Debug, Default)]
struct Lexed {
    strings: Vec<Str>,
    /// Top-level values, `start..end`; between them only whitespace.
    records: Vec<(usize, usize)>,
}

/// A label token ([`Str::label`]) that is exactly a word Fuigo's persisted schema writes (such as `backend_tool_call`):
/// it is never edited, so a recorded value equal to (or inside) it cannot turn a valid record into one that does not
/// load (Astra r2 A#10, code review High 2). Any other string, user text and nested user JSON included, is edited even
/// when it equals a schema word (Astra code review rounds 2 and 3, High 1).
fn is_schema_word(content: &[u8]) -> bool {
    crate::at_rest_schema::WORDS
        .iter()
        .any(|word| word.as_bytes() == content)
}

impl Lexed {
    /// The label token ([`Str::label`]: by position, not by word) holding all of `start..end`, if it is a schema word.
    fn in_schema_word(&self, b: &[u8], start: usize, end: usize) -> bool {
        let at = self.strings.partition_point(|s| s.end < start);
        self.strings.get(at).is_some_and(|s| {
            s.label && s.start <= start && end <= s.end && is_schema_word(&b[s.start..s.end])
        })
    }

    /// The records a match touches parse as JSON (the lexer alone accepts some text that is not JSON).
    fn records_parse(&self, bytes: &[u8], ranges: &[(usize, usize)]) -> bool {
        self.records
            .iter()
            .filter(|&&(start, end)| ranges.iter().any(|&(s, e)| s < end && start < e))
            .all(|&(start, end)| {
                serde_json::from_slice::<serde_json::Value>(&bytes[start..end]).is_ok()
            })
    }
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

/// Whether a key names an id (`id`, `call_id`, `toolUseId`, ...): its string values get distinct placeholders.
fn is_id_key(key: &[u8]) -> bool {
    key == b"id" || key.ends_with(b"_id") || key.ends_with(b"Id") || key.ends_with(b"ID")
}

/// Whether the tag key closing `frames` (the open containers, each object with its current key) sits at a
/// [`NESTED_LABELS`] path.
fn nested_label(b: &[u8], frames: &[Option<(usize, usize)>]) -> bool {
    let mut path = Vec::new();
    for frame in frames {
        match frame {
            Some((start, end)) => {
                if !path.is_empty() {
                    path.push(b'.');
                }
                path.extend_from_slice(&b[*start..*end]);
            }
            None => path.extend_from_slice(b"[]"),
        }
    }
    NESTED_LABELS.iter().any(|label| label.as_bytes() == path)
}

/// One pass over `bytes` as a sequence of JSON values separated by whitespace: the string tokens and the top-level
/// values. `None` when it is not that shape (then it is text).
fn lex(b: &[u8]) -> Option<Lexed> {
    let mut lexed = Lexed::default();
    // The open containers: an object with its current key's range (`Some((0, 0))` before the first), or an array.
    let mut frames: Vec<Option<(usize, usize)>> = Vec::new();
    let (mut i, mut depth, mut record_start) = (0usize, 0usize, 0usize);
    let (mut after_colon, mut key_is_id, mut key_is_tag) = (false, false, false);
    while i < b.len() {
        let c = b[i];
        match c {
            _ if is_ws(c) => i += 1,
            b'"' => {
                let mut j = i + 1;
                while j < b.len() && b[j] != b'"' {
                    j += if b[j] == b'\\' { 2 } else { 1 };
                }
                if j >= b.len() {
                    return None;
                }
                let next = (j + 1..b.len()).find(|&k| !is_ws(b[k]));
                let is_key = depth > 0 && next.is_some_and(|k| b[k] == b':');
                if is_key {
                    key_is_id = is_id_key(&b[i + 1..j]);
                    key_is_tag = crate::at_rest_schema::TAG_KEYS
                        .iter()
                        .any(|tag| tag.as_bytes() == &b[i + 1..j]);
                    if let Some(Some(key)) = frames.last_mut() {
                        *key = (i + 1, j);
                    }
                }
                let top_object = matches!(frames.as_slice(), [Some(_)]);
                let label = if is_key {
                    top_object
                } else {
                    after_colon && key_is_tag && (top_object || nested_label(b, &frames))
                };
                lexed.strings.push(Str {
                    start: i + 1,
                    end: j,
                    id: !is_key && after_colon && key_is_id,
                    key: is_key,
                    label,
                });
                after_colon = false;
                if depth == 0 {
                    lexed.records.push((i, j + 1));
                }
                i = j + 1;
            }
            b'{' | b'[' => {
                if depth == 0 {
                    record_start = i;
                }
                frames.push((c == b'{').then_some((0, 0)));
                depth += 1;
                after_colon = false;
                i += 1;
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1)?;
                frames.pop();
                if depth == 0 {
                    lexed.records.push((record_start, i + 1));
                }
                after_colon = false;
                i += 1;
            }
            b':' | b',' if depth > 0 => {
                after_colon = c == b':';
                i += 1;
            }
            _ if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'+' | b'.') => {
                let start = i;
                while i < b.len()
                    && (b[i].is_ascii_alphanumeric() || matches!(b[i], b'-' | b'+' | b'.'))
                {
                    i += 1;
                }
                if depth == 0 {
                    let word = &b[start..i];
                    let scalar = matches!(word, b"true" | b"false" | b"null")
                        || word.iter().all(|&d| {
                            d.is_ascii_digit() || matches!(d, b'-' | b'+' | b'.' | b'e' | b'E')
                        });
                    if !scalar {
                        return None;
                    }
                    lexed.records.push((start, i));
                }
                after_colon = false;
            }
            _ => return None,
        }
    }
    (depth == 0).then_some(lexed)
}

/// The length of the atom (escape or UTF-8 char) at `b[i..]` inside a JSON string.
fn atom_len(b: &[u8], i: usize) -> usize {
    if b[i] == b'\\' {
        let mut scratch = Vec::new();
        json_escape(b, i, &mut scratch).unwrap_or(2)
    } else {
        match b[i] {
            0xF0..=0xF7 => 4,
            0xE0..=0xEF => 3,
            0xC0..=0xDF => 2,
            _ => 1,
        }
    }
}

/// An id placeholder: 48 bits of a domain-separated BLAKE3 digest of the matched id, so the same id gives the same
/// placeholder in every process (one id written by two processes still pairs, Grok round-1 Medium 1) and two ids give
/// different ones (Astra r2 A#10). The digest is not a spelling of the value; for a credential drawn from a space far
/// larger than 2^48 the tag fits countless candidates, so it does not confirm a guess.
fn id_placeholder(matched: &[u8]) -> String {
    let digest = blake3::derive_key("fuigo at-rest id placeholder v1", matched);
    let tag: String = digest[..6].iter().map(|b| format!("{b:02x}")).collect();
    format!("<redacted-{tag}>")
}

/// The JSON edit: each match inside one string token is widened to whole escape atoms and replaced; a record with a
/// match outside a string token, or that still holds a value afterwards, or that no longer parses, is withheld.
fn transform_json(snap: &Snapshot, b: &[u8], lexed: &Lexed, ranges: &[(usize, usize)]) -> Vec<u8> {
    // Replacements (start, end, placeholder), and the records to withhold.
    let mut edits: Vec<(usize, usize, Cow<'static, str>)> = Vec::new();
    let mut withhold: Vec<(usize, usize)> = Vec::new();
    for &(start, end) in ranges {
        if lexed.in_schema_word(b, start, end) {
            continue;
        }
        let at = lexed.strings.partition_point(|s| s.end < start);
        match lexed.strings.get(at) {
            Some(s) if !(s.key && s.label) && s.start <= start && end <= s.end => {
                let (mut i, mut from, mut to) = (s.start, s.start, s.end);
                while i < s.end {
                    let next = i + atom_len(b, i);
                    if i <= start {
                        from = i;
                    }
                    if next >= end {
                        to = next.min(s.end);
                        break;
                    }
                    i = next;
                }
                let placeholder = if s.id {
                    Cow::Owned(id_placeholder(&b[from..to]))
                } else {
                    Cow::Borrowed(PLACEHOLDER)
                };
                match edits.last_mut() {
                    Some(last) if from <= last.1 => last.1 = last.1.max(to),
                    _ => edits.push((from, to, placeholder)),
                }
            }
            _ => withhold.push((start, end)),
        }
    }
    let marker = if snap.any(WITHHELD_MARKER.as_bytes()) {
        EMPTY_RECORD
    } else {
        WITHHELD_MARKER
    };
    let mut out = Vec::with_capacity(b.len());
    let mut cursor = 0;
    let mut edit = 0;
    for &(start, end) in &lexed.records {
        out.extend_from_slice(&b[cursor..start]);
        cursor = end;
        let touched = |&(s, e): &(usize, usize)| s < end && start < e;
        let mut record = Vec::new();
        let mut at = start;
        while edit < edits.len() && edits[edit].0 < end {
            let (s, e, ref placeholder) = edits[edit];
            record.extend_from_slice(&b[at..s]);
            record.extend_from_slice(placeholder.as_bytes());
            at = e;
            edit += 1;
        }
        record.extend_from_slice(&b[at..end]);
        let changed = record.len() != end - start || record != b[start..end];
        let bad = withhold.iter().any(touched)
            || (changed
                && (holds_unprotected(snap, &record)
                    || serde_json::from_slice::<serde_json::Value>(&record).is_err()));
        out.extend_from_slice(if bad { marker.as_bytes() } else { &record });
    }
    out.extend_from_slice(&b[cursor..]);
    // A value spelled across records (whitespace between them) is the one case the per-record check cannot see.
    if holds_unprotected(snap, &out) {
        return withhold_lines(snap, out, marker);
    }
    out
}

/// Whether JSON `b` still holds a recorded value outside the schema's own tokens.
fn holds_unprotected(snap: &Snapshot, b: &[u8]) -> bool {
    let found = snap.find(b);
    if found.is_empty() {
        return false;
    }
    let Some(lexed) = lex(b) else { return true };
    found
        .iter()
        .any(|&(start, end)| !lexed.in_schema_word(b, start, end))
}

/// Text: matches widened to whole escapes (a backslash run's parity decides where an escape begins), then each line
/// that still holds a value is withheld, then the whole text if a value spans lines.
fn transform_text(snap: &Snapshot, b: &[u8], ranges: &[(usize, usize)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut cursor = 0;
    for (start, end) in merge(
        ranges
            .iter()
            .map(|&(s, e)| widen_text(b, s, e, 0))
            .collect(),
    ) {
        let start = start.max(cursor);
        out.extend_from_slice(&b[cursor..start]);
        out.extend_from_slice(PLACEHOLDER.as_bytes());
        cursor = end.max(cursor);
    }
    out.extend_from_slice(&b[cursor..]);
    if !snap.any(&out) {
        return out;
    }
    let withheld = if snap.any(WITHHELD.as_bytes()) {
        ""
    } else {
        WITHHELD
    };
    withhold_lines(snap, out, withheld)
}

/// Each line of `out` that holds a recorded value becomes `replacement` (keeping its newline); if a value still spans
/// lines, the whole text does.
fn withhold_lines(snap: &Snapshot, out: Vec<u8>, replacement: &str) -> Vec<u8> {
    let mut lines = Vec::with_capacity(out.len());
    for line in out.split_inclusive(|&c| c == b'\n') {
        if snap.any(line) {
            lines.extend_from_slice(replacement.as_bytes());
            if line.ends_with(b"\n") {
                lines.push(b'\n');
            }
        } else {
            lines.extend_from_slice(line);
        }
    }
    if snap.any(&lines) {
        let mut whole = replacement.as_bytes().to_vec();
        if out.ends_with(b"\n") {
            whole.push(b'\n');
        }
        return whole;
    }
    lines
}

/// Where an escape that begins at `j` ends, if one begins there: `\` with an even run of backslashes before it, or
/// `%XX`.
fn escape_end(b: &[u8], j: usize) -> Option<usize> {
    let mut scratch = Vec::new();
    match b[j] {
        b'\\' => {
            let run = b[..j].iter().rev().take_while(|&&c| c == b'\\').count();
            (run % 2 == 0).then(|| {
                j + json_escape(b, j, &mut scratch)
                    .unwrap_or(2)
                    .min(b.len() - j)
            })
        }
        b'%' => percent_escape(b, j, &mut scratch).map(|len| j + len),
        _ => None,
    }
}

/// `start..end` widened so it neither begins nor ends inside an escape, never below `floor` (Astra r2 N2).
fn widen_text(b: &[u8], start: usize, end: usize, floor: usize) -> (usize, usize) {
    let mut from = start;
    for j in start.saturating_sub(12).max(floor)..start {
        if escape_end(b, j).is_some_and(|e| e > start) {
            from = j;
            break;
        }
    }
    let mut to = end;
    for j in end.saturating_sub(12).max(from)..end {
        if let Some(e) = escape_end(b, j)
            && e > to
        {
            to = e;
        }
    }
    (from, to.min(b.len()))
}

// ---- streams --------------------------------------------------------------------------------------------------------

/// The decoded views searched for a held-back prefix: percent (and percent with `+` for a space), JSON once, JSON twice.
#[derive(Clone, Copy)]
enum Level {
    Percent { plus: bool },
    Json,
}

/// `src` decoded one level, with each decoded byte's source offset. An escape cut off at the end stays as plain bytes.
fn decode(src: &[u8], map: &[usize], level: Level) -> (Vec<u8>, Vec<usize>) {
    let (mut out, mut out_map) = (Vec::with_capacity(src.len()), Vec::with_capacity(src.len()));
    let mut i = 0;
    while i < src.len() {
        let len = match level {
            Level::Percent { .. } => percent_escape(src, i, &mut out),
            Level::Json => json_escape(src, i, &mut out),
        };
        let len = len.unwrap_or_else(|| {
            out.push(match (level, src[i]) {
                (Level::Percent { plus: true }, b'+') => b' ',
                (_, c) => c,
            });
            1
        });
        out_map.resize(out.len(), map[i]);
        i += len;
    }
    (out, out_map)
}

/// The smallest `h >= from` where `buf[h..]` begins (in some view) a spelling of `spellings` on at least its floor, or
/// is an escape cut off by the write boundary. `earliest` is lowered to where such a beginning starts, unclamped: the
/// context must keep that span, or a later write cannot see the value whole (Astra code review round 3, High 2).
fn live_start(
    spellings: &[Spelling<'_>],
    tails: &CutOffTails,
    plus: bool,
    buf: &[u8],
    from: usize,
    earliest: &mut usize,
) -> Option<usize> {
    let cut = cut_escape_len(buf);
    let body = &buf[..buf.len() - cut];
    let mut best = (cut > 0 && buf.len() - cut >= from).then_some(buf.len() - cut);
    // A beginning that started before `from` (in what is already written) still holds back its unwritten rest, or a
    // value written in small pieces reaches disk whole once the context loses its start (Astra code review High 1).
    let mut consider = |h: usize| {
        *earliest = (*earliest).min(h);
        let h = h.max(from);
        if best.is_none_or(|b| h < b) {
            best = Some(h);
        }
    };
    let mut candidates: Vec<u32> = Vec::new();
    let mut check = |text: &[u8], offset: &dyn Fn(usize) -> usize| {
        // A view that ends inside a UTF-8 char (a percent or `\u` escape cut between the bytes of an emoji) is matched
        // up to that char and then byte for byte (Astra code review round 3, High 2).
        let partial = incomplete_utf8_len(text);
        for body_len in [text.len(), text.len() - partial] {
            let (body, tail) = text.split_at(body_len);
            candidates.clear();
            tails.candidates(body, &mut candidates);
            for &idx in &candidates {
                let spelling = &spellings[idx as usize];
                if let Some(len) = truncated_prefix_len(body, spelling.text, spelling.floor)
                    && spelling.text.as_bytes().get(len..len + tail.len()) == Some(tail)
                {
                    consider(offset(body_len - len));
                }
            }
            if partial == 0 {
                break;
            }
        }
    };
    check(body, &|k| k);
    if memchr::memchr3(b'%', b'\\', b'+', body).is_some() {
        let map: Vec<usize> = (0..body.len()).collect();
        let mut levels = vec![
            vec![Level::Percent { plus: false }],
            vec![Level::Json],
            vec![Level::Json, Level::Json],
        ];
        if plus {
            levels.push(vec![Level::Percent { plus: true }]);
        }
        for view in levels {
            let (mut text, mut text_map) = (body.to_vec(), map.clone());
            for level in view {
                (text, text_map) = decode(&text, &text_map, level);
            }
            check(&text, &|k| text_map.get(k).copied().unwrap_or(body.len()));
        }
    }
    best
}

/// [`incomplete_escape_len`], together with a JSON high-surrogate escape (`\uD83D`, once or twice escaped) just before
/// it: the low half is still to come, so that is cut off too (Astra code review round 3, High 2).
fn cut_escape_len(b: &[u8]) -> usize {
    let cut = incomplete_escape_len(b);
    let rest = &b[..b.len() - cut];
    if rest.len() < 6 {
        return cut;
    }
    let tail = &rest[rest.len() - 6..];
    let high = tail.starts_with(b"\\u")
        && matches!(tail[2], b'd' | b'D')
        && matches!(tail[3], b'8' | b'9' | b'a' | b'b' | b'A' | b'B')
        && tail[4..].iter().all(u8::is_ascii_hexdigit);
    match high {
        false => cut,
        true if rest.len() > 6 && rest[rest.len() - 7] == b'\\' => cut + 7,
        true => cut + 6,
    }
}

/// How many bytes at the end of `b` begin a UTF-8 char that is not complete there.
fn incomplete_utf8_len(b: &[u8]) -> usize {
    for back in 1..=b.len().min(3) {
        let lead = b[b.len() - back];
        let need = match lead {
            0xC0..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF7 => 4,
            0x80..=0xBF => continue,
            _ => return 0,
        };
        return if need > back { back } else { 0 };
    }
    0
}

/// An append that arrives in pieces (terminal logs, MCP stderr): no recorded value, nor more than three of its key
/// characters, is ever written raw, however the writes split it (design §2.5, Fable r2 #4/#5).
///
/// Each [`push`](Self::push) searches only the bytes held back, the new chunk and [`CONTEXT`] bytes already written, so
/// the cost does not grow with the longest recorded value; output that is not printing a value holds nothing back.
/// [`finish`](Self::finish) releases what is held (a held beginning of eight or more key characters becomes
/// [`PLACEHOLDER`]) and keeps the context, so a value whose rest arrives after it is still caught.
#[derive(Debug, Default)]
pub struct AtRestStream {
    /// The last raw bytes already released.
    context: Vec<u8>,
    /// Raw bytes held back: the beginning of a spelling, or an escape cut off.
    pending: Vec<u8>,
    /// `pending` was already written as [`PLACEHOLDER`] by a [`finish`](Self::finish) mid-value: later pushes keep it
    /// held, so the rest of that value is dropped rather than written raw (Fable code review #2).
    masked: bool,
    scratch: Vec<u8>,
}

impl AtRestStream {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether bytes are held back that are not yet written in any form.
    pub fn holding(&self) -> bool {
        !self.pending.is_empty() && !self.masked
    }

    /// Feed `chunk`; what may be written now is appended to `out`.
    pub fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        let Some(snap) = snapshot() else {
            if !std::mem::take(&mut self.masked) {
                out.extend_from_slice(&self.pending);
            }
            out.extend_from_slice(chunk);
            self.pending.clear();
            self.remember(chunk);
            return;
        };
        let mut buf = std::mem::take(&mut self.scratch);
        buf.clear();
        buf.extend_from_slice(&self.context);
        buf.extend_from_slice(&self.pending);
        buf.extend_from_slice(chunk);
        let boundary = self.context.len();
        // Everything before `written` is already on disk (raw context, or a masked beginning as its placeholder).
        let written = boundary + if self.masked { self.pending.len() } else { 0 };
        let found = snap.find(&buf);
        // A match that began in the masked beginning already has its placeholder: its rest is dropped.
        let mut continued = self.masked && found.iter().any(|&(s, e)| s < written && e > written);
        let ranges: Vec<(usize, usize)> = merge(
            found
                .into_iter()
                .filter(|&(_, end)| end > written)
                .map(|(start, end)| widen_text(&buf, start.max(written), end, written))
                .collect(),
        );
        let last_end = ranges.last().map_or(boundary, |r| r.1);
        let mut earliest = buf.len();
        let hold = live_start(
            &snap.hold,
            &snap.hold_tails,
            snap.plus,
            &buf,
            last_end,
            &mut earliest,
        )
        .into_iter()
        .chain(snap.raw_live_start(&buf, last_end, HOLD_CHARS, &mut earliest))
        .min()
        .unwrap_or(buf.len());
        let mut cursor = written;
        for &(start, end) in &ranges {
            out.extend_from_slice(&buf[cursor..start]);
            if !std::mem::take(&mut continued) {
                out.extend_from_slice(PLACEHOLDER.as_bytes());
            }
            cursor = end;
        }
        // `hold < written` only when a spelling still continues from the masked beginning: it stays masked and its new
        // bytes are not written.
        self.masked = hold < written;
        if hold > cursor {
            out.extend_from_slice(&buf[cursor..hold]);
        }
        self.pending.clear();
        self.pending.extend_from_slice(&buf[hold..]);
        // The context keeps a live beginning whole, however long its spelling (Astra code review round 3, High 2).
        let keep = hold.saturating_sub(CONTEXT).min(earliest);
        self.context.clear();
        self.context.extend_from_slice(&buf[keep..hold]);
        self.scratch = buf;
    }

    /// Release what is held into `out`; the context is kept (a later write still sees a value begun before).
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        if self.pending.is_empty() || self.masked {
            return;
        }
        let pending = std::mem::take(&mut self.pending);
        if let Some(snap) = snapshot() {
            let mut buf = self.context.clone();
            let boundary = buf.len();
            buf.extend_from_slice(&pending);
            let mut unused = buf.len();
            if let Some(h) = live_start(
                &snap.cut,
                &snap.cut_tails,
                snap.plus,
                &buf,
                boundary,
                &mut unused,
            )
            .into_iter()
            .chain(snap.raw_live_start(&buf, boundary, MIN_TRUNCATED_PREFIX_CHARS, &mut unused))
            .min()
                && cut_escape_len(&buf) != buf.len() - h
            {
                out.extend_from_slice(&buf[boundary..h]);
                out.extend_from_slice(PLACEHOLDER.as_bytes());
                self.remember(&buf[boundary..h]);
                self.pending = buf.split_off(h);
                self.masked = true;
                return;
            }
            // Released raw (too short to tell from text), but the context keeps all of it and what was before it (both
            // bounded by a live beginning's span), so a later write that completes the value is still caught (Astra
            // code review round 3, High 2). The next push trims the context again.
            out.extend_from_slice(&pending);
            self.context = buf;
            return;
        }
        out.extend_from_slice(&pending);
        self.remember(&pending);
    }

    fn remember(&mut self, written: &[u8]) {
        self.context.extend_from_slice(written);
        let excess = self.context.len().saturating_sub(CONTEXT);
        self.context.drain(..excess);
    }
}

/// JSON lines copied into the session folder (an import, a fork's sidecar, a load-repair backup; Astra code review round
/// 3, High 3): each line is transformed as one record ([`transform_whole`], so a JSON record keeps its labels and loads),
/// and the lines are then checked together, so a value spanning records (two JSON records, a record and a text line, a
/// multi-line value one of whose lines is itself JSON) withholds every record it touches. A line is published once no
/// later match can reach it: the last [`AtRestLines`] window of bytes stays held until then. Lines arrive raw and are
/// settled a batch at a time: one search over the batch and the window before it; with no match there every line is
/// its own transform and nothing spans, so it is published as is, and only a batch with a match is transformed line by
/// line and cross-checked. Memory is a batch ([`BATCH`] or the window, whichever is larger) plus the window.
#[derive(Debug, Default)]
pub struct AtRestLines {
    /// Transformed lines not yet published, back to back.
    held: Vec<u8>,
    /// Where each held line starts in `held`.
    starts: std::collections::VecDeque<usize>,
    /// `held[..checked]` is transformed and was already searched across its lines; the lines after it are raw.
    checked: usize,
}

/// Raw bytes [`AtRestLines`] gathers before settling them with one search.
const BATCH: usize = 1 << 20;

impl AtRestLines {
    pub fn new() -> Self {
        Self::default()
    }

    /// The bytes a match can span in source form (the longest spelling, decoded twice at up to seven bytes a byte),
    /// with margin for one cascade of withheld records.
    fn window(snap: &Snapshot) -> usize {
        16 * snap.longest + 256
    }

    /// Feed one line (with its newline, if any); what may be published now is appended to `out`.
    pub fn push(&mut self, line: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let Some(snap) = snapshot() else {
            self.drain(out);
            out.extend_from_slice(line);
            return Ok(());
        };
        self.starts.push_back(self.held.len());
        self.held.extend_from_slice(line);
        let window = Self::window(&snap);
        if self.held.len() - self.checked >= window.max(BATCH) {
            self.settle(&snap, window)?;
            self.publish(window, out);
        }
        Ok(())
    }

    /// Transform and cross-check the raw lines after `checked`. One search covers them and the `window` bytes before
    /// them: when it finds nothing, each raw line is already its own transform and no value spans lines.
    fn settle(&mut self, snap: &Snapshot, window: usize) -> io::Result<()> {
        if self.checked == self.held.len() {
            return Ok(());
        }
        let from = self.starts[self.line_of(self.checked.saturating_sub(window))];
        if snap.find(&self.held[from..]).is_empty() {
            self.checked = self.held.len();
            return Ok(());
        }
        let first = self.line_of(self.checked);
        let raw = self.held.split_off(self.checked);
        let base = self.checked;
        for i in first..self.starts.len() {
            let (start, end) = (
                self.starts[i] - base,
                self.starts.get(i + 1).map_or(raw.len(), |&s| s - base),
            );
            self.starts[i] = self.held.len();
            self.held
                .extend_from_slice(&transform_whole(&raw[start..end]));
        }
        self.check(snap, window)
    }

    /// Publish everything held into `out`.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        if let Some(snap) = snapshot() {
            self.settle(&snap, Self::window(&snap))?;
        }
        self.drain(out);
        Ok(())
    }

    /// The held line holding byte `at`.
    fn line_of(&self, at: usize) -> usize {
        self.starts.partition_point(|&s| s <= at) - 1
    }

    /// Search the unchecked lines, and `window` bytes before them (from a line start), for a match spanning lines;
    /// withhold every line one touches, until none is left.
    fn check(&mut self, snap: &Snapshot, window: usize) -> io::Result<()> {
        if self.checked == self.held.len() {
            return Ok(());
        }
        let first_new = self.line_of(self.checked);
        let first = self.line_of(self.checked.saturating_sub(window));
        let from = self.starts[first];
        let mut withheld = vec![false; self.starts.len()];
        loop {
            let mut changed = false;
            let mut spans = false;
            for (start, end) in snap.find(&self.held[from..]) {
                let (a, z) = (self.line_of(from + start), self.line_of(from + end - 1));
                if a == z || z < first_new {
                    continue;
                }
                spans = true;
                for gone in &mut withheld[a..=z] {
                    changed |= !*gone;
                    *gone = true;
                }
            }
            if !spans {
                break;
            }
            if !changed {
                // A value spelled across the fallbacks themselves: never publish rather than guess.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "a recorded value spans withheld records",
                ));
            }
            self.rebuild(snap, &withheld);
        }
        self.checked = self.held.len();
        Ok(())
    }

    /// `held` with each line marked in `withheld` replaced by its fallback (a JSON record by [`WITHHELD_MARKER`], text by
    /// [`WITHHELD`]), keeping its newline.
    fn rebuild(&mut self, snap: &Snapshot, withheld: &[bool]) {
        let marker = if snap.any(WITHHELD_MARKER.as_bytes()) {
            EMPTY_RECORD
        } else {
            WITHHELD_MARKER
        };
        let text = if snap.any(WITHHELD.as_bytes()) {
            ""
        } else {
            WITHHELD
        };
        let mut held = Vec::with_capacity(self.held.len());
        for (i, &gone) in withheld.iter().enumerate() {
            let start = std::mem::replace(&mut self.starts[i], held.len());
            let end = withheld
                .get(i + 1)
                .map_or(self.held.len(), |_| self.starts[i + 1]);
            let line = &self.held[start..end];
            if !gone {
                held.extend_from_slice(line);
                continue;
            }
            let newline = line.ends_with(b"\n");
            held.extend_from_slice(if is_json_line(line) { marker } else { text }.as_bytes());
            if newline {
                held.push(b'\n');
            }
        }
        self.held = held;
    }

    /// Publish checked lines from the front while at least `keep` bytes stay held after them.
    fn publish(&mut self, keep: usize, out: &mut Vec<u8>) {
        let mut cut = 0;
        while self.starts.front().is_some() {
            let end = self.starts.get(1).copied().unwrap_or(self.held.len());
            if end > self.checked || self.held.len() - end < keep {
                break;
            }
            self.starts.pop_front();
            cut = end;
        }
        out.extend_from_slice(&self.held[..cut]);
        self.held.drain(..cut);
        for start in &mut self.starts {
            *start -= cut;
        }
        self.checked -= cut;
    }

    fn drain(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.held);
        self.starts.clear();
        self.checked = 0;
    }
}

/// A `Write` whose bytes go through the layer: [`AtRestFile::records`] transforms each `write` call as one whole record
/// (a tracing appender writes one record per call); [`AtRestFile::stream`] runs an [`AtRestStream`]. `flush` never
/// releases held bytes; [`finish`](Self::finish) does, and `Drop` finishes too, so held bytes are never written raw.
pub struct AtRestFile<W: Write> {
    inner: W,
    stream: Option<AtRestStream>,
    out: Vec<u8>,
}

impl<W: Write> AtRestFile<W> {
    pub fn records(inner: W) -> Self {
        Self {
            inner,
            stream: None,
            out: Vec::new(),
        }
    }

    pub fn stream(inner: W) -> Self {
        Self {
            inner,
            stream: Some(AtRestStream::new()),
            out: Vec::new(),
        }
    }

    /// Release held bytes and flush.
    pub fn finish(&mut self) -> io::Result<()> {
        if let Some(stream) = &mut self.stream {
            self.out.clear();
            stream.finish(&mut self.out);
            self.inner.write_all(&self.out)?;
        }
        self.inner.flush()
    }
}

impl<W: Write> Write for AtRestFile<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.stream {
            None => self.inner.write_all(&transform_whole(buf))?,
            Some(stream) => {
                self.out.clear();
                stream.push(buf, &mut self.out);
                self.inner.write_all(&self.out)?;
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write> Drop for AtRestFile<W> {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

#[cfg(test)]
#[path = "at_rest_tests.rs"]
mod tests;
