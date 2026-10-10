//! Read-rule filtering of a ripgrep SEARCH by its typed `--json` records (P198 round 4).
//!
//! Text output cannot be parsed safely: a notice such as `X: binary file matches (...)` is a newline-terminated line
//! that glues onto the next record, and a file name may hold `:`, `|` or a newline. With `--json` every emitted line
//! belongs to the file of its enclosing `begin`..`end` pair, whatever the line says. This stream
//!
//! 1. attributes every `match` / `context` record to the file of the enclosing `begin` (a record naming another path
//!    is malformed and drops the rest of that file),
//! 2. judges that file ONCE with the [`ResultFilter`] (as written and by canonical place),
//! 3. re-renders the output format the tool already parses (`--heading` content, `path:count`, `path`, or the
//!    `path|line|text` pipe form), for allowed files only. A record that cannot be decoded (bad JSON, a path that is
//!    neither `text` nor valid base64 `bytes`, anything outside `begin`..`end`) is dropped: fail closed.
//!
//! Binary files: ripgrep reports them as `binary_offset` on the `end` record. They are re-rendered as the same
//! `path: binary file matches (...)` / `path: WARNING: stopped searching binary file after match (...)` line the text
//! form printed, under the file's own name, and dropped with the file when it is denied.
use base64::Engine as _;
use serde_json::Value;
use std::collections::HashMap;

use crate::util::read_deny::ResultFilter;

/// The output form to render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RgJsonMode {
    /// `--heading --line-number`: `path\n`, `N:text` / `N-text` lines, `--` between context groups, blank line between files.
    Heading { context: bool },
    /// `-c`: `path:count\n`.
    Count,
    /// `-c --null`: ripgrep's own count records `path NUL count \n`, filtered by path only. The count is exactly what
    /// `rg -c` prints (it is a count of matches, not lines, when the pattern can match a newline under `-U`, which the
    /// `--json` stats do not tell), and a denied file's record is dropped whole.
    CountNull,
    /// `-l`: `path\n`.
    Files,
    /// `-n -H --field-match-separator=|`: `path|N|text\n`.
    Pipe,
}

/// Most bytes of rendered lines kept for ONE file while it is open. The grep tools stop reading at 5 MB of stdout
/// (`MAX_STDOUT_BYTES`), so a single file's block can never be shown past this anyway; lines beyond it are dropped
/// while buffering, not after.
pub const MAX_FILE_BUFFER_BYTES: usize = 5_000_000;
/// Most bytes buffered over ALL open files at once (ripgrep has one open file per search thread).
pub const MAX_TOTAL_BUFFER_BYTES: usize = 32_000_000;

/// One buffered output line: line number, whether it is a `match` (else `context`), text with its terminator.
#[derive(Debug)]
struct BufLine {
    n: u64,
    is_match: bool,
    text: Vec<u8>,
}

/// Per-path state. Judged ONCE when the path is first seen; every record is attributed by the `path` it carries.
#[derive(Debug)]
struct FileState {
    seq: u64,
    path: Vec<u8>,
    allowed: bool,
    lines: Vec<BufLine>,
    bytes: usize,
    /// Any line was seen (even one dropped by the buffer cap): decides the binary-notice wording.
    any_line: bool,
    /// Matched lines seen in `match` records (used only when the stream ends without this file's `end` record).
    matched_seen: u64,
}

/// Streaming `--json` to text converter; see the module docs.
#[derive(Debug)]
pub struct RgJsonStream {
    mode: RgJsonMode,
    results: ResultFilter,
    buf: Vec<u8>,
    files: HashMap<Vec<u8>, FileState>,
    next_seq: u64,
    total_bytes: usize,
    /// Something was already written for an earlier file (a blank line goes between heading blocks).
    emitted: bool,
    /// Allowed paths found, in order (`Files` mode), for callers that want the paths themselves.
    found: Vec<Vec<u8>>,
    /// `--max-columns` of the text form being reproduced (`--max-columns-preview` is on whenever this is set).
    max_columns: Option<usize>,
}

/// ripgrep's marker after a previewed long line.
const OMITTED: &[u8] = b" [... omitted end of long line]";

/// What ripgrep's text printer shows for `raw` (a line with its terminator) under `--max-columns N
/// --max-columns-preview`: a line longer than N bytes WITH its terminator is cut after its first N bytes (extended to
/// the end of a UTF-8 character it splits) and gets the marker. Observed with ripgrep 14.1.0.
fn preview(raw: &[u8], max: usize) -> Vec<u8> {
    if raw.len() <= max {
        return raw.to_vec();
    }
    let mut end = max;
    while end < raw.len() && raw[end] & 0xC0 == 0x80 {
        end += 1;
    }
    let mut out = raw[..end].to_vec();
    out.extend_from_slice(OMITTED);
    out.push(b'\n');
    out
}

/// Whether ripgrep's stderr is its OWN pattern or flag error (it names no file): exit 2, nothing on stdout and a
/// first line of the regex / flag diagnostic form. Such an error comes before any file is opened, so no path can follow.
pub fn is_own_error(exit_code: i32, stdout_empty: bool, stderr: &[u8]) -> bool {
    if exit_code != 2 || !stdout_empty {
        return false;
    }
    let first = stderr.split(|b| *b == b'\n').find(|l| !l.is_empty()).unwrap_or(b"");
    [&b"rg: regex parse error:"[..], b"rg: error parsing flag", b"rg: error parsing regex"]
        .iter()
        .any(|p| first.starts_with(p))
}

fn decode_path(v: &Value) -> Option<Vec<u8>> {
    if let Some(t) = v.get("text").and_then(Value::as_str) {
        return Some(t.as_bytes().to_vec());
    }
    let b = v.get("bytes").and_then(Value::as_str)?;
    base64::engine::general_purpose::STANDARD.decode(b).ok()
}

fn decode_lines(v: &Value) -> Option<Vec<u8>> {
    decode_path(v)
}

impl RgJsonStream {
    pub fn new(mode: RgJsonMode, results: ResultFilter) -> Self {
        Self {
            mode,
            results,
            buf: Vec::new(),
            files: HashMap::new(),
            next_seq: 0,
            total_bytes: 0,
            emitted: false,
            found: Vec::new(),
            max_columns: None,
        }
    }

    /// Reproduce `--max-columns N --max-columns-preview` for the lines of the text form.
    pub fn with_max_columns(mut self, max: usize) -> Self {
        self.max_columns = Some(max);
        self
    }

    /// Whether any rule exists (otherwise the caller should not ask ripgrep for `--json`).
    pub fn is_active(&self) -> bool {
        self.results.is_active()
    }

    /// The allowed file paths seen so far (taken).
    pub fn take_found(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.found)
    }

    /// Feed a chunk of ripgrep's JSON output; returns the text to show so far.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        if self.mode == RgJsonMode::CountNull {
            self.feed_count_null(&mut out);
            return out;
        }
        while let Some(i) = self.buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=i).collect();
            if let Ok(v) = serde_json::from_slice::<Value>(&line) {
                self.record(&v, &mut out);
            }
        }
        out
    }

    /// `path NUL count \n` records. A path holds no NUL, so the first NUL ends the path (even if the path has a newline).
    fn feed_count_null(&mut self, out: &mut Vec<u8>) {
        while let Some(z) = self.buf.iter().position(|b| *b == 0) {
            let Some(nl) = self.buf[z..].iter().position(|b| *b == b'\n').map(|i| z + i) else { return };
            let rec: Vec<u8> = self.buf.drain(..=nl).collect();
            if !self.results.denies_bytes(&rec[..z]) {
                out.extend_from_slice(&rec[..z]);
                out.push(b':');
                out.extend_from_slice(&rec[z + 1..]);
            }
        }
    }

    /// The end of the output. An unterminated tail is not a complete record and is dropped. A file that had a `begin`
    /// (or records) but no `end` record is decided here: an ALLOWED file shows what was received (its lines, or its
    /// path / count of the matches seen); a DENIED file shows nothing. Files come out in the order first seen.
    pub fn finish(&mut self) -> Vec<u8> {
        self.buf.clear();
        let mut rest: Vec<FileState> = self.files.drain().map(|(_, f)| f).collect();
        rest.sort_by_key(|f| f.seq);
        self.total_bytes = 0;
        let mut out = Vec::new();
        for f in rest {
            if f.allowed {
                let matched = f.matched_seen;
                self.render(f, matched, None, &mut out);
            }
        }
        out
    }

    /// Make sure `path` has a state, judging it on first sight (a record for a path with no `begin` is attributed by
    /// its own path).
    fn ensure(&mut self, path: &[u8]) {
        if !self.files.contains_key(path) {
            let allowed = !self.results.denies_bytes(path);
            let seq = self.next_seq;
            self.next_seq += 1;
            self.files.insert(
                path.to_vec(),
                FileState { seq, path: path.to_vec(), allowed, lines: Vec::new(), bytes: 0, any_line: false, matched_seen: 0 },
            );
        }
    }

    fn record(&mut self, v: &Value, out: &mut Vec<u8>) {
        let (Some(kind), Some(data)) = (v.get("type").and_then(Value::as_str), v.get("data")) else {
            return;
        };
        if !matches!(kind, "begin" | "match" | "context" | "end") {
            return;
        }
        // Every record names its own file; a record whose path cannot be decoded is dropped (fail closed).
        let Some(path) = data.get("path").and_then(decode_path) else { return };
        self.ensure(&path);
        match kind {
            "begin" => {}
            "match" | "context" => {
                let st = self.files.get_mut(&path).expect("ensured");
                let (Some(text), Some(number)) =
                    (data.get("lines").and_then(decode_lines), data.get("line_number").and_then(Value::as_u64))
                else {
                    return;
                };
                let is_match = kind == "match";
                if is_match {
                    st.matched_seen += text.split_inclusive(|b| *b == b'\n').count() as u64;
                }
                if !st.allowed || !matches!(self.mode, RgJsonMode::Heading { .. } | RgJsonMode::Pipe) {
                    return;
                }
                if !is_match && matches!(self.mode, RgJsonMode::Pipe) {
                    return;
                }
                for (k, raw) in text.split_inclusive(|b| *b == b'\n').enumerate() {
                    if raw.contains(&0) {
                        // The text form never prints a line holding the NUL that made the file binary.
                        continue;
                    }
                    st.any_line = true;
                    // The bound is applied here, while buffering.
                    let cost = raw.len() + 24;
                    if st.bytes + cost > MAX_FILE_BUFFER_BYTES || self.total_bytes + cost > MAX_TOTAL_BUFFER_BYTES {
                        continue;
                    }
                    st.bytes += cost;
                    self.total_bytes += cost;
                    let mut text = match self.max_columns {
                        Some(max) => preview(raw, max),
                        None => raw.to_vec(),
                    };
                    if !text.ends_with(b"\n") {
                        text.push(b'\n');
                    }
                    st.lines.push(BufLine { n: number + k as u64, is_match, text });
                }
            }
            _ => {
                // "end": the block of this file is complete.
                let st = self.files.remove(&path).expect("ensured");
                self.total_bytes = self.total_bytes.saturating_sub(st.bytes);
                if !st.allowed {
                    return;
                }
                let stats = data.get("stats");
                let matched = stats.and_then(|s| s.get("matched_lines")).and_then(Value::as_u64).unwrap_or(0);
                let binary = data.get("binary_offset").and_then(Value::as_u64);
                self.render(st, matched, binary, out);
            }
        }
    }

    /// Render one finished (or, at stream end, unfinished) allowed file. `binary` is the `end` record's offset.
    fn render(&mut self, mut st: FileState, matched: u64, binary: Option<u64>, out: &mut Vec<u8>) {
        match self.mode {
            RgJsonMode::Files => {
                if matched > 0 {
                    self.found.push(st.path.clone());
                    out.extend_from_slice(&st.path);
                    out.push(b'\n');
                    self.emitted = true;
                }
            }
            RgJsonMode::Count | RgJsonMode::CountNull => {
                // A directory search omits a binary file from `-c`.
                if matched > 0 && binary.is_none() {
                    out.extend_from_slice(&st.path);
                    out.extend_from_slice(format!(":{matched}\n").as_bytes());
                }
                if matched > 0 {
                    self.emitted = true;
                }
            }
            RgJsonMode::Heading { .. } | RgJsonMode::Pipe => {
                let mut block = Vec::new();
                let mut last_line: Option<u64> = None;
                for (i, l) in st.lines.iter().enumerate() {
                    match self.mode {
                        RgJsonMode::Heading { context } => {
                            if i == 0 {
                                if self.emitted {
                                    block.push(b'\n');
                                }
                                block.extend_from_slice(&st.path);
                                block.push(b'\n');
                            } else if context && last_line.is_some_and(|p| l.n != p + 1) {
                                block.extend_from_slice(b"--\n");
                            }
                            block.extend_from_slice(format!("{}{}", l.n, if l.is_match { ':' } else { '-' }).as_bytes());
                        }
                        _ => {
                            block.extend_from_slice(&st.path);
                            block.extend_from_slice(format!("|{}|", l.n).as_bytes());
                        }
                    }
                    block.extend_from_slice(&l.text);
                    last_line = Some(l.n);
                }
                if let Some(off) = binary {
                    let heading = matches!(self.mode, RgJsonMode::Heading { .. });
                    let notice = if st.any_line {
                        format!(": WARNING: stopped searching binary file after match (found \"\\0\" byte around offset {off})\n")
                    } else {
                        format!(": binary file matches (found \"\\0\" byte around offset {off})\n")
                    };
                    if heading && !st.any_line && self.emitted {
                        block.push(b'\n');
                    }
                    block.extend_from_slice(&st.path);
                    block.extend_from_slice(notice.as_bytes());
                    st.any_line = true;
                }
                out.extend_from_slice(&block);
                if st.any_line {
                    self.emitted = true;
                }
            }
        }
    }
}
