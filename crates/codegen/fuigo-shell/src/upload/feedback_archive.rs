//! Capped tar.gz archive of a session directory for a user-consented `/feedback` trace upload.

pub(crate) struct ArchiveCaps {
    /// Total packed bytes; packing stops (truncating the archive) once hit.
    pub(crate) archive_bytes: u64,
    /// Per-file bytes; larger files are skipped.
    pub(crate) file_bytes: u64,
}

pub(crate) const FEEDBACK_ARCHIVE_CAPS: ArchiveCaps = ArchiveCaps {
    archive_bytes: 50 * 1024 * 1024,
    file_bytes: 10 * 1024 * 1024,
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum ArchiveError {
    #[error("pack session file: {0}")]
    Pack(#[from] std::io::Error),
    #[error("finalize archive: {0}")]
    Finalize(#[source] std::io::Error),
    #[error("session archive would be empty")]
    Empty,
}

/// Build the archive for upload to `destination` (P54: identity in packed files follows it).
///
/// P113 (Astra r1 #2): the first-party key this agent holds is recorded as a sent credential first (it is sent with
/// every first-party request, and a server whose config names `${FUIGO_API_KEY}` is handed it), so the pack-time
/// scrub also replaces it in session files written by an earlier process, before this one sent anything.
pub(crate) fn build_session_archive(
    session_dir: &std::path::Path,
    session_id: &str,
    destination: &str,
) -> Result<Vec<u8>, ArchiveError> {
    for key in held_first_party_keys() {
        fuigo_telemetry::sent_credentials::record(&key);
    }
    build_session_archive_with_caps(session_dir, session_id, destination, &FEEDBACK_ARCHIVE_CAPS)
}

/// P149 (D2): `buf` as a trace upload may send it: the same scrub the `/feedback` archive applies to each packed file
/// ([`scrub_sent_credentials`]: every credential this process sent, credential shapes, private-key blocks), after
/// recording the first-party keys this process holds and the values of the variables it holds Fuigo's own secrets
/// in (its key variables and every name a loaded config registered: a model `env_key`, an MCP bearer variable). A
/// `fuigo trace` run sent nothing itself, so without the held values a key a session sent would leave in its files.
/// Text only: the caller keeps binary payloads (images, archives) away from it. The local files are not changed.
pub fn scrub_upload_text(buf: Vec<u8>) -> Vec<u8> {
    for key in held_first_party_keys() {
        fuigo_telemetry::sent_credentials::record(&key);
    }
    for name in fuigo_secrets::child_env::inherited_fuigo_secret_names() {
        if let Some(value) = std::env::var_os(&name).and_then(|v| v.into_string().ok()) {
            fuigo_telemetry::sent_credentials::record(&value);
        }
    }
    scrub_sent_credentials(buf)
}

/// P149 (S14/K16, Astra r1 #2): a gzipped tar built elsewhere (the memory archive) as a trace upload may send it:
/// every text member through [`scrub_upload_text`], every other member (by extension, or not UTF-8) byte for byte.
/// Member names, modes and times are kept. An archive that cannot be read is an error, so the caller does not
/// upload it unscrubbed.
pub(crate) fn scrub_upload_tar_gz(archive: &[u8]) -> std::io::Result<Vec<u8>> {
    use flate2::Compression;
    use flate2::read::GzDecoder;
    use flate2::write::GzEncoder;
    const BINARY: &[&str] = &[
        "png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "tif", "tiff", "avif", "heic", "mp4", "mov", "webm",
        "mp3", "wav", "pdf", "gz", "tgz", "zip", "zst", "sqlite", "db", "bin",
    ];
    let mut out = Vec::new();
    {
        let mut builder = tar::Builder::new(GzEncoder::new(&mut out, Compression::default()));
        let mut input = tar::Archive::new(GzDecoder::new(archive));
        for entry in input.entries()? {
            let mut entry = entry?;
            let mut header = entry.header().clone();
            let path = entry.path()?.into_owned();
            let mut data = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut data)?;
            if header.entry_type().is_file() {
                let binary = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| BINARY.iter().any(|b| b.eq_ignore_ascii_case(e)));
                if !binary {
                    data = scrub_upload_text(data);
                }
                header.set_size(data.len() as u64);
                header.set_cksum();
            }
            builder.append_data(&mut header, &path, data.as_slice())?;
        }
        builder.into_inner()?.finish()?;
    }
    Ok(out)
}

/// Every first-party key this agent holds (Astra r2 #3): the runtime key a client supplied, the exported
/// `FUIGO_API_KEY` and legacy `FUIGO_CODE_API_KEY`, and the saved key held in memory.
fn held_first_party_keys() -> Vec<String> {
    use crate::agent::auth_method as auth;
    let mut keys: Vec<String> = [auth::read_fuigo_api_key_env(), auth::read_fuigo_api_key_echoable()]
        .into_iter()
        .filter_map(Result::ok)
        .collect();
    keys.extend(
        [auth::FUIGO_API_KEY_ENV_VAR, auth::LEGACY_FUIGO_API_KEY_ENV_VAR]
            .into_iter()
            .filter_map(|name| std::env::var(name).ok()),
    );
    keys
}

/// The LOC sink's per-session file (`fuigo_hunk_tracker`'s `HunkRecord` lines, camelCase).
pub(crate) const LOC_RECORDS_FILE: &str = "hunk_records.jsonl";

/// P54: identity in `hunk_records.jsonl` as it leaves the machine for `destination`.
///
/// The records carry the persisted machine id (`agentId`, and `authorId` on agent-authored
/// hunks) and the account id (`authorId` on human-authored hunks). They are written when the
/// session runs, possibly before P54 or under another destination, so the decision is taken
/// here, on the archive's actual destination, for every record including old ones: a
/// FluxRouter-operated destination receives the file unchanged; any other gets the machine id
/// replaced by `destination_pseudonym(destination, id)` and the account id removed. A line that
/// is not a JSON object cannot be checked and is dropped (fails closed).
pub(crate) fn withhold_loc_identity(destination: &str, bytes: Vec<u8>) -> Vec<u8> {
    use fuigo_extra_ca::fluxrouter::{IdentityDisclosure, destination_pseudonym};
    use serde_json::Value;
    if IdentityDisclosure::for_destination(destination).is_permitted() {
        return bytes;
    }
    let text = String::from_utf8_lossy(&bytes);
    let mut out = String::with_capacity(text.len());
    let mut dropped = 0usize;
    for line in text.split_inclusive('\n') {
        let body = line.trim_end_matches(['\n', '\r']);
        if body.trim().is_empty() {
            out.push_str(line);
            continue;
        }
        let Ok(Value::Object(mut record)) = serde_json::from_str::<Value>(body) else {
            dropped += 1;
            continue;
        };
        let agent_authored = ["authorType", "author_type"].iter().any(|key| {
            record
                .get(*key)
                .and_then(Value::as_str)
                .is_some_and(|t| t.eq_ignore_ascii_case("agent"))
        });
        for key in ["agentId", "agent_id"] {
            if let Some(Value::String(id)) = record.get(key).cloned() {
                record.insert(key.into(), Value::String(destination_pseudonym(destination, &id)));
            }
        }
        for key in ["authorId", "author_id"] {
            if let Some(Value::String(id)) = record.get(key).cloned() {
                let kept = if agent_authored {
                    Value::String(destination_pseudonym(destination, &id))
                } else {
                    Value::Null
                };
                record.insert(key.into(), kept);
            }
        }
        for key in ["userId", "user_id"] {
            record.remove(key);
        }
        if let Ok(serialized) = serde_json::to_string(&record) {
            out.push_str(&serialized);
            out.push('\n');
        }
    }
    if dropped > 0 {
        // P54-K: the drop is deliberate (fails closed) but must not be silent — a live writer's
        // half-written last line is expected, a corrupt file is not, and support reading the
        // archive needs to know records are missing. The local file is untouched.
        tracing::warn!(
            dropped,
            file = LOC_RECORDS_FILE,
            "feedback archive: unparseable LOC records left out of the upload (identity cannot be \
             checked on them); the local file is unchanged"
        );
    }
    out.into_bytes()
}

fn build_session_archive_with_caps(
    session_dir: &std::path::Path,
    session_id: &str,
    destination: &str,
    caps: &ArchiveCaps,
) -> Result<Vec<u8>, ArchiveError> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let mut archive_data = Vec::new();
    {
        let encoder = GzEncoder::new(&mut archive_data, Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let packed = add_dir_to_tar(&mut archive, session_dir, session_id, destination, caps)?;
        // Skips (oversized files, races with live writers) can leave nothing packed; an empty gzip helps nobody and must not report `uploaded`
        if packed == 0 {
            return Err(ArchiveError::Empty);
        }
        archive
            .into_inner()
            .and_then(|encoder| encoder.finish())
            .map_err(ArchiveError::Finalize)?;
    }
    Ok(archive_data)
}

/// Pack `dir` into `archive`, returning how many files were packed.
fn add_dir_to_tar<W: std::io::Write>(
    archive: &mut tar::Builder<W>,
    dir: &std::path::Path,
    prefix: &str,
    destination: &str,
    caps: &ArchiveCaps,
) -> Result<usize, ArchiveError> {
    use std::path::Component;

    let mut total = 0u64;
    let mut packed = 0usize;
    for entry in walkdir::WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.path_is_symlink() || entry.file_type().is_dir() || !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let Ok(rel) = path.strip_prefix(dir) else {
            continue;
        };
        if !rel.components().all(|c| matches!(c, Component::Normal(_))) {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.is_file() {
            continue;
        }
        let room = caps.archive_bytes.saturating_sub(total);
        let limit = caps.file_bytes.min(room);
        if limit == 0 {
            // The cap truncates the archive; what is already packed is still useful for debugging, so stop instead of failing the upload
            break;
        }
        // Skip-on-error: the session dir has live writers, so entries can be deleted or swapped for symlinks between the lstat and the open
        let Ok(mut file) = open_regular_nofollow(path) else {
            continue;
        };
        let mut buf = Vec::new();
        let n = std::io::copy(&mut std::io::Read::take(&mut file, limit + 1), &mut buf)?;
        if n > limit {
            continue;
        }
        if rel.file_name().is_some_and(|f| f == LOC_RECORDS_FILE) {
            buf = withhold_loc_identity(destination, buf);
        }
        buf = scrub_sent_credentials(buf);
        let n = buf.len() as u64;
        total = total.saturating_add(n);
        let name = format!("{prefix}/{}", rel.to_string_lossy());
        let mut header = tar::Header::new_gnu();
        header.set_size(n);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append_data(&mut header, name, buf.as_slice())?;
        packed += 1;
    }
    Ok(packed)
}

/// `buf` with every credential this process sent replaced, one line at a time (P113, CIE-01).
///
/// The session directory holds text from children, servers and providers (`events.jsonl`, `updates.jsonl`, logs,
/// transcripts), and a line written before its credential was recorded (an earlier run of the session, output
/// printed before the key was sent) was not scrubbed when it was written. Line by line, so a JSON-lines file stays
/// one record per line and a withheld record does not take the rest of the file with it. The file on disk is not
/// changed.
///
/// P113 r3: a credential this process never recorded and does not hold (an old, rotated key echoed into a
/// transcript) is replaced by its SHAPE too ([`fuigo_secrets::redact_credential_shapes`], the detector list the
/// telemetry scrub uses, without its URL rewriting). A JSON line is scrubbed value by value (property names
/// included) and written back only when something was replaced, so it stays valid JSON; a file that is one JSON
/// document over several lines (pretty-printed `summary.json`) likewise, as a whole. Other lines are scrubbed as text,
/// valid UTF-8 stretch by stretch around any invalid byte; a PEM private-key block split over consecutive text lines
/// (a run of lines that are not JSON, so records are never spliced) is replaced first, a torn one (no END line) from
/// its BEGIN line through its base64 body.
fn scrub_sent_credentials(buf: Vec<u8>) -> Vec<u8> {
    let recorded = !fuigo_telemetry::sent_credentials::is_empty();
    if let Some(document) = scrub_json_document(&buf, recorded) {
        return document;
    }
    let lines: Vec<&[u8]> = buf.split_inclusive(|&b| b == b'\n').collect();
    let mut out = Vec::with_capacity(buf.len());
    let mut changed = false;
    // A PEM block opened in one JSON record and continued in the next (Astra r4 #1).
    let mut json = JsonScrub { recorded, pem: fuigo_secrets::PrivateKeyJoin::default() };
    let mut i = 0;
    while i < lines.len() {
        if parse_json_line(lines[i]).is_some() {
            let scrubbed = match scrub_exact_line(lines[i], recorded) {
                Some(exact) => scrub_json_line_shapes(&exact, &mut json).or(Some(exact)),
                None => scrub_json_line_shapes(lines[i], &mut json),
            };
            match scrubbed {
                Some(scrubbed) => {
                    out.extend_from_slice(&scrubbed);
                    changed = true;
                }
                None => out.extend_from_slice(lines[i]),
            }
            i += 1;
            continue;
        }
        json.pem.reset();
        let start = i;
        while i < lines.len() && parse_json_line(lines[i]).is_none() {
            i += 1;
        }
        let block = lines[start..i].concat();
        let keyless = scrub_utf8_stretches(&block, fuigo_secrets::redact_private_key_blocks);
        changed |= keyless.is_some();
        for line in keyless.as_deref().unwrap_or(&block).split_inclusive(|&b| b == b'\n') {
            let exact = scrub_exact_line(line, recorded);
            let text = exact.as_deref().unwrap_or(line);
            match scrub_utf8_stretches(text, fuigo_secrets::redact_credential_shapes).or(exact) {
                Some(scrubbed) => {
                    out.extend_from_slice(&scrubbed);
                    changed = true;
                }
                None => out.extend_from_slice(line),
            }
        }
    }
    if changed { out } else { buf }
}

/// The line as a JSON value, when it is one (any JSON value: an object, an array, a bare string).
fn parse_json_line(line: &[u8]) -> Option<serde_json::Value> {
    let body = std::str::from_utf8(line).ok()?.trim_end_matches(['\n', '\r']);
    if body.trim().is_empty() {
        return None;
    }
    serde_json::from_str(body).ok()
}

/// A file that is ONE JSON document over several lines (Astra r3 #8: `summary.json` is pretty-printed, so no single
/// line of it is JSON): recorded credentials replaced line by line, then credential shapes value by value over the
/// parsed document, written back pretty-printed only when a shape was replaced. `None` when the file is not such a
/// document.
fn scrub_json_document(buf: &[u8], recorded: bool) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(buf).ok()?;
    if text.trim().lines().count() < 2 {
        return None;
    }
    serde_json::from_str::<serde_json::Value>(text).ok()?;
    let mut exact = Vec::with_capacity(buf.len());
    for line in buf.split_inclusive(|&b| b == b'\n') {
        match scrub_exact_line(line, recorded) {
            Some(scrubbed) => exact.extend_from_slice(&scrubbed),
            None => exact.extend_from_slice(line),
        }
    }
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&exact) else {
        // Not expected (the exact scrub keeps JSON intact); never let a shape leave unscrubbed.
        return Some(scrub_utf8_stretches(&exact, fuigo_secrets::redact_credential_shapes).unwrap_or(exact));
    };
    if !(JsonScrub { recorded, pem: fuigo_secrets::PrivateKeyJoin::default() }).value(&mut value, None) {
        return Some(exact);
    }
    let mut pretty = serde_json::to_vec_pretty(&value).ok()?;
    if text.ends_with('\n') {
        pretty.push(b'\n');
    }
    Some(pretty)
}

/// A JSON line with credential shapes replaced value by value and property name by property name, re-serialised
/// (so a replacement can never cut an escape sequence); `None` when it holds none or is not JSON.
fn scrub_json_line_shapes(line: &[u8], json: &mut JsonScrub) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(line).ok()?;
    let body = text.trim_end_matches(['\n', '\r']);
    let ending = &text[body.len()..];
    let mut value = serde_json::from_str::<serde_json::Value>(body).ok()?;
    if !json.value(&mut value, None) {
        return None;
    }
    let json = serde_json::to_string(&value).ok()?;
    Some(format!("{json}{ending}").into_bytes())
}

/// The structural scrub of parsed JSON: every string value and property name by credential shape (Astra r3 #4), every
/// array of byte values decoded and scrubbed whole (recorded credentials and shapes, wherever its numbers sit on
/// physical lines, Astra r4 #3), and a PEM private-key block whose BEGIN marker, body and END marker sit in separate
/// strings, of one record or of consecutive records ([`fuigo_secrets::PrivateKeyJoin`]: P113 Astra r4 #1, P120, K16).
/// The strings are fed to it in document order with the name of the property that holds each, so the record envelope
/// between two chunks of a key neither ends the block nor is taken for its body.
struct JsonScrub {
    /// Whether this process has recorded any sent credential (the exact-match scrub runs only then).
    recorded: bool,
    /// A PEM block opened and not closed by the strings seen so far.
    pem: fuigo_secrets::PrivateKeyJoin,
}

impl JsonScrub {
    /// Scrub `value` in place; `true` when something was replaced. `property` names the property holding it.
    fn value(&mut self, value: &mut serde_json::Value, property: Option<&str>) -> bool {
        use serde_json::Value;
        match value {
            Value::String(s) => self.string(s, property),
            Value::Array(items) => {
                let bytes: Option<Vec<u8>> = (!items.is_empty())
                    .then(|| items.iter().map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok())).collect())
                    .flatten();
                if let Some(bytes) = bytes {
                    let Some(scrubbed) = scrub_byte_value_run(&bytes, self.recorded) else {
                        return false;
                    };
                    *items = scrubbed.into_iter().map(Value::from).collect();
                    return true;
                }
                items.iter_mut().fold(false, |changed, item| self.value(item, property) | changed)
            }
            Value::Object(map) => {
                let mut changed = false;
                for (name, mut item) in std::mem::take(map) {
                    changed |= self.value(&mut item, Some(&name));
                    let mut name = match fuigo_secrets::redact_credential_shapes(&name) {
                        std::borrow::Cow::Owned(scrubbed) => {
                            changed = true;
                            scrubbed
                        }
                        std::borrow::Cow::Borrowed(_) => name,
                    };
                    // Two names redacted alike must not overwrite each other's data (Astra r4 #5).
                    let base = name.clone();
                    let mut n = 2;
                    while map.contains_key(&name) {
                        name = format!("{base}#{n}");
                        n += 1;
                    }
                    map.insert(name, item);
                }
                changed
            }
            _ => false,
        }
    }

    fn string(&mut self, s: &mut String, property: Option<&str>) -> bool {
        let mut changed = self.pem.feed(property, s);
        if let std::borrow::Cow::Owned(scrubbed) = fuigo_secrets::redact_credential_shapes(s) {
            *s = scrubbed;
            changed = true;
        }
        changed
    }
}

/// `bytes` with `scrub` applied to every valid UTF-8 stretch and every invalid byte kept as it is (Astra r3 #3: one
/// stray byte must not switch the scrub off for the rest of the line); `None` when nothing was replaced. A
/// credential never holds an invalid byte, so none is split by the stretching.
fn scrub_utf8_stretches(
    bytes: &[u8],
    scrub: impl Fn(&str) -> std::borrow::Cow<'_, str>,
) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut changed = false;
    for chunk in bytes.utf8_chunks() {
        match scrub(chunk.valid()) {
            std::borrow::Cow::Owned(scrubbed) => {
                out.extend_from_slice(scrubbed.as_bytes());
                changed = true;
            }
            std::borrow::Cow::Borrowed(valid) => out.extend_from_slice(valid.as_bytes()),
        }
        out.extend_from_slice(chunk.invalid());
    }
    changed.then_some(out)
}

/// One archived line with every RECORDED credential replaced (Astra r1 #1 / r2 #2: in its text, and inside byte-value
/// arrays, which also get the shape scrub), or `None` when it holds none.
///
/// A JSON line can carry output as an array of byte values (a bash tool result's `rawOutput.output` is the command's
/// raw output, `Vec<u8>`), where no text match finds it. Every run of decimal byte values after a `[` is decoded,
/// scrubbed and written back as byte values, found textually so a torn record (a writer that died mid-line) is
/// covered too; then the line's text is scrubbed as a whole.
fn scrub_exact_line(line: &[u8], recorded: bool) -> Option<Vec<u8>> {
    let decoded = scrub_decimal_byte_runs(line, recorded);
    let text = decoded.as_deref().unwrap_or(line);
    let exact = recorded
        .then(|| fuigo_telemetry::sent_credentials::scrub_record(text))
        .flatten();
    exact.or(decoded)
}

/// One run of byte values with recorded credentials, then credential shapes, replaced.
fn scrub_byte_value_run(bytes: &[u8], recorded: bool) -> Option<Vec<u8>> {
    let exact = recorded
        .then(|| fuigo_telemetry::sent_credentials::scrub_bytes(bytes))
        .flatten();
    let current = exact.as_deref().unwrap_or(bytes);
    scrub_utf8_stretches(current, fuigo_secrets::redact_credential_shapes).or(exact)
}

/// `line` with recorded credentials and credential shapes replaced inside every run of comma-separated decimal byte
/// values (0 to 255) that follows a `[`, the way serde writes a `Vec<u8>` (compact, or with whitespace around the
/// values as a pretty or hand-written array has it, Astra r3 #5); `None` when no run held one.
fn scrub_decimal_byte_runs(line: &[u8], recorded: bool) -> Option<Vec<u8>> {
    let skip_space = |mut j: usize| {
        while line.get(j).is_some_and(u8::is_ascii_whitespace) {
            j += 1;
        }
        j
    };
    let mut out = Vec::with_capacity(line.len());
    let mut changed = false;
    let mut i = 0;
    while i < line.len() {
        out.push(line[i]);
        i += 1;
        if line[i - 1] != b'[' {
            continue;
        }
        // Parse `n, n, ..., n` from `i`; `end` is just past the last whole number.
        let mut bytes = Vec::new();
        let mut j = skip_space(i);
        let mut end = i;
        loop {
            let digits = line[j..].iter().take_while(|b| b.is_ascii_digit()).count();
            let value = std::str::from_utf8(&line[j..j + digits])
                .ok()
                .and_then(|d| d.parse::<u8>().ok());
            let Some(value) = value.filter(|_| digits > 0 && digits <= 3) else {
                break;
            };
            bytes.push(value);
            j += digits;
            end = j;
            j = skip_space(j);
            if line.get(j) != Some(&b',') {
                break;
            }
            j = skip_space(j + 1);
        }
        if let Some(scrubbed) = scrub_byte_value_run(&bytes, recorded) {
            let numbers: Vec<String> = scrubbed.iter().map(u8::to_string).collect();
            out.extend_from_slice(numbers.join(",").as_bytes());
            i = end;
            changed = true;
        }
    }
    changed.then_some(out)
}

/// Open without following symlinks (TOCTOU: a walk entry can be replaced by a symlink after `symlink_metadata`).
/// Then re-check the opened fd is a regular file, for platforms without `O_NOFOLLOW`.
pub(crate) fn open_regular_nofollow(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLUX: &str = "https://api.fluxrouter.ai/v1";

    fn tar_file(bytes: &[u8], suffix: &str) -> String {
        use flate2::read::GzDecoder;
        use std::io::Read as _;
        let mut archive = tar::Archive::new(GzDecoder::new(bytes));
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap().to_string_lossy().ends_with(suffix) {
                let mut text = String::new();
                entry.read_to_string(&mut text).unwrap();
                return text;
            }
        }
        panic!("{suffix} not in archive");
    }

    /// P54 hostile: a feedback trace archive bound for a storage proxy that is not
    /// FluxRouter-operated carries no machine id and no account id in `hunk_records.jsonl`, for
    /// records written at any time (the file on disk is untouched); FluxRouter gets the file as is.
    #[test]
    fn loc_records_in_an_archive_carry_identity_only_to_fluxrouter() {
        const MACHINE_ID: &str = "5d1f0c2a-7a7a-4b4b-8c8c-0123456789ab";
        let dir = tempfile::tempdir().unwrap();
        let records = format!(
            "{}\n{}\nnot json acct-1\n",
            serde_json::json!({"hunkId": "h1", "authorType": "agent", "authorId": MACHINE_ID, "agentId": MACHINE_ID, "sessionId": "sid"}),
            serde_json::json!({"hunkId": "h2", "authorType": "human", "authorId": "acct-1", "agentId": MACHINE_ID, "sessionId": "sid"}),
        );
        std::fs::write(dir.path().join(LOC_RECORDS_FILE), &records).unwrap();
        std::fs::write(dir.path().join("other.txt"), "kept").unwrap();
        for proxy in ["https://cli-proxy.example/v1", "http://api.fluxrouter.ai/v1"] {
            let bytes = build_session_archive(dir.path(), "sid", proxy).unwrap();
            let loc = tar_file(&bytes, LOC_RECORDS_FILE);
            assert!(!loc.contains(MACHINE_ID) && !loc.contains("acct-1"), "{proxy}: {loc}");
            let lines: Vec<serde_json::Value> =
                loc.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
            assert_eq!(lines.len(), 2, "the unparseable line is dropped");
            let pseudonym = fuigo_extra_ca::fluxrouter::destination_pseudonym(proxy, MACHINE_ID);
            assert_eq!(lines[0]["agentId"], pseudonym.as_str());
            assert_eq!(lines[0]["authorId"], pseudonym.as_str());
            assert_eq!(lines[1]["authorId"], serde_json::Value::Null);
            assert_eq!(lines[1]["hunkId"], "h2");
            assert_eq!(tar_file(&bytes, "other.txt"), "kept");
        }
        let bytes = build_session_archive(dir.path(), "sid", FLUX).unwrap();
        assert_eq!(tar_file(&bytes, LOC_RECORDS_FILE), records);
        assert_eq!(std::fs::read_to_string(dir.path().join(LOC_RECORDS_FILE)).unwrap(), records);
    }

    fn tar_names(bytes: &[u8]) -> Vec<String> {
        use flate2::read::GzDecoder;
        let mut archive = tar::Archive::new(GzDecoder::new(bytes));
        archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn session_archive_skips_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("chat_history.jsonl"), b"ok").unwrap();
        let secret = dir.path().join("secret.txt");
        std::fs::write(&secret, b"do-not-upload").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&secret, dir.path().join("leak")).unwrap();

        let bytes = build_session_archive(dir.path(), "sid", FLUX).unwrap();
        let names = tar_names(&bytes);
        assert!(
            names.iter().any(|n| n.ends_with("chat_history.jsonl")),
            "{names:?}"
        );
        assert!(
            names.iter().all(|n| !n.ends_with("leak")),
            "symlink must not be packed: {names:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn archive_open_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, b"secret").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open_regular_nofollow(&link).is_err());
        assert!(open_regular_nofollow(&target).is_ok());
    }

    /// Hitting the total cap truncates the archive instead of failing it: a session just over the cap still uploads what was packed.
    #[test]
    fn archive_truncates_at_total_cap_instead_of_failing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.jsonl"), vec![b'x'; 8]).unwrap();
        std::fs::write(dir.path().join("b.jsonl"), vec![b'y'; 8]).unwrap();
        std::fs::write(dir.path().join("c.jsonl"), vec![b'z'; 8]).unwrap();

        let caps = ArchiveCaps {
            archive_bytes: 10,
            file_bytes: 10,
        };
        let bytes = build_session_archive_with_caps(dir.path(), "sid", FLUX, &caps)
            .expect("capped archive must still build");
        let names = tar_names(&bytes);
        assert!(
            !names.is_empty() && names.len() < 3,
            "expected a truncated (but non-empty) archive: {names:?}"
        );
    }

    /// P113 (CIE-01): a feedback archive holds no credential this process sent, in any packed file: not in an
    /// `events.jsonl` line written before the key was recorded (an earlier run of the session, or a server that
    /// printed it before it was sent anywhere), not in one the production `EventWriter` writes now, not in another
    /// session file. The files on disk are left as they are.
    #[test]
    fn p113_archive_holds_no_sent_credential() {
        const KEY: &str = "p113-FAKE-archived-key-4d8e2b6c1a";
        let dir = tempfile::tempdir().unwrap();
        let raw_event = format!(
            "{}\n",
            serde_json::json!({"ts": "t", "type": "mcp_transport_decode_error", "server_name": "s", "error": "e", "sample": format!("key {KEY}")})
        );
        std::fs::write(dir.path().join("events.jsonl"), &raw_event).unwrap();
        std::fs::write(dir.path().join("debug.log"), format!("child said {KEY}\nother line\n")).unwrap();
        // Astra r1 #1: a bash tool result keeps the command's raw output as byte values.
        let raw_output: Vec<u8> = format!("$ cat key\n{KEY}\n").into_bytes();
        let update = format!(
            "{}\n",
            serde_json::json!({"update": {"rawOutput": {"Bash": {"output": raw_output, "output_for_prompt": format!("{KEY}")}}}})
        );
        // Astra r2 #2: a torn record (a writer that died mid-line, then terminated by the next append) keeps the array.
        let torn = update.trim_end().split("\"output_for_prompt\"").next().unwrap().to_owned();
        std::fs::write(dir.path().join("updates.jsonl"), format!("{update}{torn}\n")).unwrap();
        // What P70a does when a server's config hands it the key.
        fuigo_telemetry::sent_credentials::record(KEY);
        fuigo_session_events::EventWriter::open(dir.path()).emit(
            fuigo_session_events::Event::McpTransportDecodeError {
                server_name: "s".into(),
                error: "e".into(),
                sample: format!("printed {KEY}"),
            },
        );

        let bytes = build_session_archive(dir.path(), "sid", FLUX).unwrap();
        let events = tar_file(&bytes, "events.jsonl");
        let log = tar_file(&bytes, "debug.log");
        for (name, text) in [("events.jsonl", &events), ("debug.log", &log)] {
            assert!(!text.contains(KEY), "{name} in the archive holds the key: {text}");
            assert!(text.contains("<redacted>"), "control: {name} keeps its record: {text}");
        }
        assert_eq!(events.lines().count(), 2, "{events}");
        for line in events.lines() {
            serde_json::from_str::<serde_json::Value>(line).expect("each archived event is still JSON");
        }
        assert!(log.ends_with("other line\n"), "{log}");
        let archived_updates = tar_file(&bytes, "updates.jsonl");
        let key_as_byte_values: String = KEY.bytes().map(|b| b.to_string()).collect::<Vec<_>>().join(",");
        assert!(!archived_updates.contains(&key_as_byte_values), "a byte array keeps the key: {archived_updates}");
        assert_eq!(archived_updates.lines().count(), 2, "{archived_updates}");
        let update: serde_json::Value = serde_json::from_str(archived_updates.lines().next().unwrap())
            .expect("the archived update is still JSON");
        let bash = &update["update"]["rawOutput"]["Bash"];
        let output: Vec<u8> = serde_json::from_value(bash["output"].clone()).expect("still byte values");
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output, "$ cat key\n<redacted>\n", "the raw output bytes are scrubbed");
        assert_eq!(bash["output_for_prompt"], "<redacted>");
        assert!(
            std::fs::read_to_string(dir.path().join("events.jsonl")).unwrap().starts_with(&raw_event),
            "the file on disk is not rewritten"
        );
    }

    /// P113 (Astra r1 #2): a session file written by an earlier process holds the first-party key, and this process
    /// has sent nothing yet (nothing recorded). Packing still replaces the key the agent holds. Its own process, so
    /// the key can sit in the environment, where the agent reads it, without touching other tests.
    #[test]
    fn p113_archive_scrubs_the_held_first_party_key() {
        const NAME: &str = "p113_archive_scrubs_the_held_first_party_key";
        const KEY: &str = "p113-FAKE-held-first-party-key-5e1f";
        const LEGACY: &str = "p113-FAKE-held-legacy-key-8a2c";
        if std::env::var("P113_CHILD_TEST").as_deref() != Ok(NAME) {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .arg(NAME)
                .args(["--test-threads=1", "--nocapture"])
                .env("P113_CHILD_TEST", NAME)
                .env("FUIGO_API_KEY", KEY)
                .env("FUIGO_CODE_API_KEY", LEGACY)
                .output()
                .unwrap();
            let text = format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .replace(KEY, "[key]")
            .replace(LEGACY, "[legacy]");
            assert!(output.status.success(), "isolated P113 archive probe failed: {text}");
            assert!(text.contains("test result: ok. 1 passed"), "the child must run exactly one test: {text}");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("updates.jsonl"),
            format!("{}\n", serde_json::json!({"text": format!("server echoed {KEY} and {LEGACY}")})),
        )
        .unwrap();
        let bytes = build_session_archive(dir.path(), "sid", FLUX).unwrap();
        let updates = tar_file(&bytes, "updates.jsonl");
        assert!(!updates.contains(KEY) && !updates.contains(LEGACY), "the archive holds a held key");
        assert!(updates.contains("server echoed <redacted> and <redacted>"), "control: {updates}");
    }

    /// P113 r3 (receipt R113, Not met 2): a credential this process neither sent nor holds (an old, rotated key echoed
    /// into a transcript or a log) still leaves the archive replaced, by its shape (the `fuigo-secrets` detector list
    /// the telemetry scrub uses): in text, in a JSON string, in a raw-output byte array, and as a multi-line PEM block
    /// in a plain log. Ordinary text that merely resembles a key is left exactly as it was. The fake keys are built at
    /// run time so the source holds no key-shaped literal.
    #[test]
    fn p113_archive_scrubs_credential_shaped_strings_it_never_recorded() {
        let openai = format!("{}{}", "sk-proj-", "p113FakeRotatedKey0aB1cD2eF3gH4iJ5");
        let fuigo = format!("{}{}", "fuigo-", "p113FakeOldFirstPartyKey9z8y7x");
        let github = format!("{}{}", "ghp_", "p113FakeGithubTokenAbCdEf0123456789");
        let aws = format!("{}{}", "AKIA", "P113FAKEROTATED7");
        let jwt = format!("{}.{}.{}", "eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJwMTEzIn0", "p113FakeSignature_0123");
        let pem_body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\np113FakePemBodyLineTwo0123456789";
        let pem = format!("-----BEGIN {0}-----\n{pem_body}\n-----END {0}-----", "PRIVATE KEY");
        let ordinary = [
            "task-0123456789abcdefghijklmn finished",
            "disk-usage is 42%",
            "commit 4d8e2b6c1a9f0e7d3b5a2c4e6f8a0b1c2d3e4f5a",
            "session 5d1f0c2a-7a7a-4b4b-8c8c-0123456789ab",
            "the token count is 12345678",
            "/home/dev/sk-notes/readme.md",
            "see https://example.com/docs?page=2&lang=en",
            "docs at https://Example.COM",
            "Bearer of bad news",
        ];
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("debug.log"),
            format!("{}\nold key {openai} and {fuigo}\n{pem}\nexport AWS_ACCESS_KEY_ID={aws}\n", ordinary.join("\n")),
        )
        .unwrap();
        let raw_output: Vec<u8> = format!("$ env\nGITHUB_TOKEN={github}\n").into_bytes();
        std::fs::write(
            dir.path().join("updates.jsonl"),
            format!(
                "{}\n{}\n{}\n",
                serde_json::json!({"update": {"rawOutput": {"Bash": {"output": raw_output}}}}),
                serde_json::json!({"text": format!("tool said {jwt}"), "notes": ordinary}),
                // Scrubbed as raw text, the value would take the `\` of the escaped quote with it.
                serde_json::json!({"cfg": "password=p113FakePassw0rd\" end"}),
            ),
        )
        .unwrap();

        let bytes = build_session_archive(dir.path(), "sid", FLUX).unwrap();
        let log = tar_file(&bytes, "debug.log");
        let updates = tar_file(&bytes, "updates.jsonl");
        for secret in [&openai, &fuigo, &github, &aws, &jwt] {
            assert!(!log.contains(secret.as_str()) && !updates.contains(secret.as_str()), "a key-shaped string left the archive");
        }
        assert!(!log.contains("p113FakePemBody"), "the PEM block left the archive: {log}");
        for line in ordinary {
            assert!(log.contains(line), "ordinary log text was rewritten: {line:?} in {log}");
        }
        let lines: Vec<serde_json::Value> = updates
            .lines()
            .map(|l| serde_json::from_str(l).expect("each archived update is still JSON"))
            .collect();
        assert_eq!(lines.len(), 3, "{updates}");
        assert!(!updates.contains("p113FakePassw0rd"), "a secret assignment left the archive: {updates}");
        assert_eq!(lines[2]["cfg"], "password=[REDACTED_SECRET]\" end");
        let output: Vec<u8> =
            serde_json::from_value(lines[0]["update"]["rawOutput"]["Bash"]["output"].clone()).expect("still byte values");
        let output = String::from_utf8(output).unwrap();
        assert!(output.starts_with("$ env\nGITHUB_TOKEN=") && !output.contains("p113Fake"), "raw output bytes: {output}");
        assert_eq!(lines[1]["notes"], serde_json::json!(ordinary), "ordinary JSON text was rewritten");
        assert!(
            std::fs::read_to_string(dir.path().join("debug.log")).unwrap().contains(&openai),
            "the file on disk is not rewritten"
        );
    }

    /// P113 Astra r3 #3-#8: the archive scrub holds where a stray byte, a property name, whitespace in a byte array, a
    /// torn PEM block, PEM markers in separate JSON records or a pretty-printed JSON document used to defeat it, and
    /// every JSON file stays JSON.
    #[test]
    fn p113_archive_scrub_holds_on_the_astra_r3_cases() {
        let old = format!("{}{}", "sk-proj-", "p113FakeAfterStrayByte0aB1cD2eF3g");
        let named = format!("{}{}", "ghp_", "p113FakePropertyNameToken0123456789");
        let recorded = "p113-FAKE-spaced-array-key-71c4";
        let pretty = format!("{}{}", "fuigo-", "p113FakePrettyDocumentKey4x5y6z");
        let dir = tempfile::tempdir().unwrap();
        // #3: an invalid byte before the key, in a text line and inside a raw-output byte array.
        let mut log = b"bin \xff then ".to_vec();
        log.extend_from_slice(old.as_bytes());
        log.extend_from_slice(b"\n");
        // #6: a torn PEM block (no END line) in a plain log.
        log.extend_from_slice(b"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANp113FakeTornBodyOne\np113FakeTornBodyTwo==\n");
        std::fs::write(dir.path().join("debug.log"), &log).unwrap();
        let mut raw_output = b"\xfe ".to_vec();
        raw_output.extend_from_slice(old.as_bytes());
        // #5: a recorded key in a byte array written with spaces.
        fuigo_telemetry::sent_credentials::record(recorded);
        let spaced = format!(
            "[{}]",
            recorded.bytes().map(|b| b.to_string()).collect::<Vec<_>>().join(", ")
        );
        let records = [
            serde_json::json!({"update": {"rawOutput": {"Bash": {"output": raw_output}}}}).to_string(),
            // #4: a credential as a property name.
            serde_json::json!({"env": serde_json::Map::from_iter([(named.clone(), serde_json::json!("x"))])}).to_string(),
            format!("{{\"spaced\": {spaced}}}"),
            // #6 in a JSON string, and #7: BEGIN and END markers in different records, a record between them.
            serde_json::json!({"out": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANp113FakeTornBodyJson\n"}).to_string(),
            serde_json::json!({"between": "kept"}).to_string(),
            serde_json::json!({"tail": "-----END PRIVATE KEY----- done"}).to_string(),
        ];
        std::fs::write(dir.path().join("updates.jsonl"), format!("{}\n", records.join("\n"))).unwrap();
        // #8: a pretty-printed document (no single line of it is JSON).
        let summary = serde_json::to_string_pretty(&serde_json::json!({
            "session_summary": "password=p113FakePrettyPassw0rd\" end",
            "key": pretty,
        }))
        .unwrap();
        std::fs::write(dir.path().join("summary.json"), format!("{summary}\n")).unwrap();

        let bytes = build_session_archive(dir.path(), "sid", FLUX).unwrap();
        let archived_log = {
            use flate2::read::GzDecoder;
            use std::io::Read as _;
            let mut archive = tar::Archive::new(GzDecoder::new(bytes.as_slice()));
            let mut found = Vec::new();
            for entry in archive.entries().unwrap() {
                let mut entry = entry.unwrap();
                if entry.path().unwrap().to_string_lossy().ends_with("debug.log") {
                    entry.read_to_end(&mut found).unwrap();
                }
            }
            found
        };
        let log_text = String::from_utf8_lossy(&archived_log);
        assert!(!log_text.contains(&old), "#3: the key after a stray byte left the archive");
        assert!(archived_log.starts_with(b"bin \xff then "), "#3: the stray byte is kept");
        assert!(!log_text.contains("p113FakeTornBody"), "#6: the torn PEM body left the archive");
        let updates = tar_file(&bytes, "updates.jsonl");
        let lines: Vec<serde_json::Value> = updates
            .lines()
            .map(|l| serde_json::from_str(l).expect("#7: each archived record is still JSON"))
            .collect();
        assert_eq!(lines.len(), 6, "#7: no record was spliced away: {updates}");
        let output: Vec<u8> = serde_json::from_value(lines[0]["update"]["rawOutput"]["Bash"]["output"].clone()).unwrap();
        assert!(output.starts_with(b"\xfe ") && !String::from_utf8_lossy(&output).contains(&old), "#3: byte array");
        assert!(!updates.contains(&named), "#4: the property name left the archive: {updates}");
        let spaced_bytes: Vec<u8> = serde_json::from_value(lines[2]["spaced"].clone()).unwrap();
        assert_eq!(spaced_bytes, b"<redacted>", "#5: the spaced byte array keeps the recorded key");
        assert!(!updates.contains("p113FakeTornBody"), "#6: the torn PEM body in JSON left the archive");
        assert_eq!(lines[4]["between"], "kept", "#7");
        let archived_summary = tar_file(&bytes, "summary.json");
        let summary: serde_json::Value =
            serde_json::from_str(&archived_summary).expect("#8: the pretty document is still JSON");
        assert!(!archived_summary.contains("p113FakePretty"), "#8: {archived_summary}");
        assert_eq!(summary["session_summary"], "password=[REDACTED_SECRET]\" end");
    }

    /// P113 Astra r4 #1/#3-#6: a PEM block split over JSON strings (one record, or consecutive records), a byte array
    /// spread over the lines of a pretty document, an indented torn PEM body, two property names redacted alike, and
    /// the ordinary line after a torn block.
    #[test]
    fn p113_archive_scrub_holds_on_the_astra_r4_cases() {
        let body = format!("{}{}", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", "p113FakeSplitBody0123456789abcdef");
        let (begin, end) = ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");
        let first = format!("{}{}", "sk-proj-", "p113FakeNameOne0aB1cD2eF3gH4iJ5kL");
        let second = format!("{}{}", "sk-proj-", "p113FakeNameTwo0aB1cD2eF3gH4iJ5kL");
        let recorded = "p113-FAKE-pretty-array-key-93d1";
        fuigo_telemetry::sent_credentials::record(recorded);
        let dir = tempfile::tempdir().unwrap();
        let records = [
            serde_json::json!({"chunks": [begin, body.clone(), end]}).to_string(),
            serde_json::json!({"o": begin}).to_string(),
            serde_json::json!({"o": body.clone()}).to_string(),
            serde_json::json!({"o": format!("{end} done")}).to_string(),
            serde_json::json!({"env": serde_json::Map::from_iter([
                (first.clone(), serde_json::json!(1)),
                (second.clone(), serde_json::json!(2)),
            ])})
            .to_string(),
        ];
        std::fs::write(dir.path().join("updates.jsonl"), format!("{}\n", records.join("\n"))).unwrap();
        let summary = serde_json::to_string_pretty(&serde_json::json!({"bytes": recorded.as_bytes()})).unwrap();
        assert!(summary.lines().count() > 3, "the array is spread over lines: {summary}");
        std::fs::write(dir.path().join("summary.json"), &summary).unwrap();
        std::fs::write(
            dir.path().join("debug.log"),
            format!("{begin}\n    MIIEvQIBp113FakeIndentedBody\n    QUJDp113FakeIndentedTail==\nrequest failed: timeout\n"),
        )
        .unwrap();

        let bytes = build_session_archive(dir.path(), "sid", FLUX).unwrap();
        let updates = tar_file(&bytes, "updates.jsonl");
        assert!(!updates.contains("p113FakeSplitBody"), "#1: a split PEM body left the archive: {updates}");
        let lines: Vec<serde_json::Value> =
            updates.lines().map(|l| serde_json::from_str(l).expect("still JSON")).collect();
        assert_eq!(lines.len(), 5, "{updates}");
        assert_eq!(lines[3]["o"], "[REDACTED_SECRET] done");
        let env = lines[4]["env"].as_object().unwrap();
        assert_eq!(env.len(), 2, "#5: two redacted names kept apart: {env:?}");
        assert!(!updates.contains("p113FakeName"), "{updates}");
        let summary: serde_json::Value = serde_json::from_str(&tar_file(&bytes, "summary.json")).unwrap();
        let archived: Vec<u8> = serde_json::from_value(summary["bytes"].clone()).unwrap();
        assert_eq!(archived, b"<redacted>", "#3: the spread byte array keeps the recorded key");
        let log = tar_file(&bytes, "debug.log");
        assert!(!log.contains("p113FakeIndented"), "#4: the indented torn body left the archive: {log}");
        assert!(log.ends_with("\nrequest failed: timeout\n"), "#6: the ordinary line was eaten: {log}");
    }

    /// One `session/update` record the way `updates.jsonl` writes it: the envelope strings (`method`, `sessionId`,
    /// `sessionUpdate`, `type`) around a `text` chunk.
    #[cfg(test)]
    fn p120_chunk_record(n: usize, text: &str) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "sessionId": "0b1c2d3e-p120-4f5a-8b6c-7d8e9f0a1b2c",
                "update": {
                    "sessionUpdate": "agent_message_chunk",
                    "content": {"type": "text", "text": text},
                    "n": n,
                }
            }
        })
        .to_string()
    }

    /// P120 (R113 r5 #1 and K16): a private key whose text arrives in separate `text` chunks of separate records, with
    /// the record envelope between the BEGIN line and the body, is redacted whether it ends or is torn off; the chunks
    /// may be shorter than a base64 line; the envelope itself is kept.
    #[test]
    fn p120_archive_scrubs_a_key_split_across_joined_records() {
        let (begin, end) = ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");
        let dir = tempfile::tempdir().unwrap();
        let records = [
            p120_chunk_record(1, &format!("Here is the key:\n{begin}\n")),
            p120_chunk_record(2, "MIIEp120SplitA"),
            p120_chunk_record(3, "vQIBADANBgkqhkiG9w0BAQEFAASCp120SplitB\n"),
            p120_chunk_record(4, "p120SplitCZ"),
            p120_chunk_record(5, &format!("{end}\nThat was the key.")),
            // A second key that is torn off and never ends.
            p120_chunk_record(6, &format!("Another:\n{begin}\n")),
            p120_chunk_record(7, "MIIEp120TornDGhpcyBpcyBub3QgYSBrZXk"),
            p120_chunk_record(8, "p120TornE"),
            p120_chunk_record(9, "Moving on to something else."),
        ];
        std::fs::write(dir.path().join("updates.jsonl"), format!("{}\n", records.join("\n"))).unwrap();
        let bytes = build_session_archive(dir.path(), "sid", FLUX).unwrap();
        let updates = tar_file(&bytes, "updates.jsonl");
        for fragment in ["p120SplitA", "p120SplitB", "p120SplitC", "p120TornD", "p120TornE"] {
            assert!(!updates.contains(fragment), "{fragment} of a split key left the archive: {updates}");
        }
        let lines: Vec<serde_json::Value> =
            updates.lines().map(|l| serde_json::from_str(l).expect("still JSON")).collect();
        assert_eq!(lines.len(), 9, "{updates}");
        assert!(updates.contains("session/update"), "the envelope is kept: {updates}");
        assert!(updates.contains("agent_message_chunk"), "the envelope is kept: {updates}");
        assert_eq!(lines[4]["params"]["update"]["content"]["text"], "[REDACTED_SECRET]\nThat was the key.");
        assert_eq!(lines[8]["params"]["update"]["content"]["text"], "Moving on to something else.");
    }

    /// P120 (R113 r5 #3): a torn key body followed on its line by terminal colour codes, in a JSON string (alone, or
    /// as the next chunk of an open block) and in a plain-text line.
    #[test]
    fn p120_archive_scrubs_a_torn_key_followed_by_colour_codes() {
        let begin = "-----BEGIN PRIVATE KEY-----";
        let dir = tempfile::tempdir().unwrap();
        let records = [
            p120_chunk_record(1, &format!("{begin}\nMIIEp120AnsiOne0123456789abcdefghij\u{1b}[0m")),
            p120_chunk_record(2, &format!("\u{1b}[31m{begin}\u{1b}[0m\n")),
            p120_chunk_record(3, "\u{1b}[32mMIIEp120AnsiTwo0123456789abcdefghij\u{1b}[0m"),
        ];
        std::fs::write(dir.path().join("updates.jsonl"), format!("{}\n", records.join("\n"))).unwrap();
        std::fs::write(
            dir.path().join("debug.log"),
            format!("{begin}\nMIIEp120AnsiThree0123456789abcdefghij\u{1b}[0m\nafter the key\n"),
        )
        .unwrap();
        let bytes = build_session_archive(dir.path(), "sid", FLUX).unwrap();
        let updates = tar_file(&bytes, "updates.jsonl");
        let log = tar_file(&bytes, "debug.log");
        for fragment in ["p120AnsiOne", "p120AnsiTwo"] {
            assert!(!updates.contains(fragment), "{fragment} left the archive: {updates}");
        }
        assert!(!log.contains("p120AnsiThree"), "a torn body followed by colour codes left the archive: {log}");
        assert!(log.ends_with("after the key\n"), "the ordinary line after the key is kept: {log}");
    }

    /// P120 (R113 r5 #4): a long alphanumeric string after a BEGIN marker that is not followed by a key (the marker is
    /// quoted in prose, or ordinary text comes before the string) is not redacted.
    #[test]
    fn p120_archive_keeps_a_long_string_after_a_marker_that_opens_no_key() {
        let begin = "-----BEGIN PRIVATE KEY-----";
        let digest = "d41d8cd98f00b204e9800998ecf8427ep120Digest0123456789";
        let dir = tempfile::tempdir().unwrap();
        let bare = |text: &str| serde_json::json!({"text": text}).to_string();
        let records = [
            bare(&format!("The docs show {begin} as the first line of a key file.")),
            bare(digest),
            bare(&format!("{begin}\n")),
            bare("That marker had no key after it, sorry."),
            bare(digest),
        ];
        std::fs::write(dir.path().join("updates.jsonl"), format!("{}\n", records.join("\n"))).unwrap();
        let bytes = build_session_archive(dir.path(), "sid", FLUX).unwrap();
        let updates = tar_file(&bytes, "updates.jsonl");
        let lines: Vec<serde_json::Value> =
            updates.lines().map(|l| serde_json::from_str(l).expect("still JSON")).collect();
        assert_eq!(lines.len(), 5, "{updates}");
        for n in [1, 4] {
            assert_eq!(lines[n]["text"], digest, "record {n}: {updates}");
        }
    }

    /// P120 (Astra r1 #1): the strings of a key may sit under DIFFERENT properties of one record or of consecutive
    /// records; a body under another property than the BEGIN marker is still body.
    #[test]
    fn p120_archive_scrubs_a_key_split_across_properties() {
        let (begin, end) = ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");
        let dir = tempfile::tempdir().unwrap();
        let records = [
            serde_json::json!({"a": format!("{begin}\n"), "b": "MIIEp120PropertyBodyOneAAAAAAAA", "c": end}).to_string(),
            serde_json::json!({"a": format!("{begin}\n")}).to_string(),
            serde_json::json!({"b": "MIIEp120PropertyBodyTwoBBBBBBBB", "z": "kept here"}).to_string(),
        ];
        std::fs::write(dir.path().join("updates.jsonl"), format!("{}\n", records.join("\n"))).unwrap();
        let bytes = build_session_archive(dir.path(), "sid", FLUX).unwrap();
        let updates = tar_file(&bytes, "updates.jsonl");
        assert!(!updates.contains("p120PropertyBody"), "a body under another property left the archive: {updates}");
        assert!(updates.contains("\"z\":\"kept here\""), "{updates}");
    }

    /// P120 (Astra r1 #2): a BEGIN marker that is itself split across chunks still opens the block.
    #[test]
    fn p120_archive_scrubs_a_key_whose_marker_is_split_across_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let records = [
            p120_chunk_record(1, "Key follows:\n-----BEGIN PRI"),
            p120_chunk_record(2, "VATE KEY-----\n"),
            p120_chunk_record(3, "MIIEp120MarkerSplitBodyCCCCCCCC"),
            p120_chunk_record(4, "-----BEGIN RSA PRIVATE"),
            p120_chunk_record(5, " KEY-----\n"),
            p120_chunk_record(6, "MIIEp120MarkerSplitBodyDDDDDDDD"),
        ];
        std::fs::write(dir.path().join("updates.jsonl"), format!("{}\n", records.join("\n"))).unwrap();
        let bytes = build_session_archive(dir.path(), "sid", FLUX).unwrap();
        let updates = tar_file(&bytes, "updates.jsonl");
        assert!(!updates.contains("p120MarkerSplitBody"), "a body after a split marker left the archive: {updates}");
    }

    /// P120 (Astra r1 #4): a short ordinary word after an opening marker closes the block; the long string after it
    /// is not redacted.
    #[test]
    fn p120_archive_keeps_a_word_and_a_digest_after_a_marker() {
        let digest = "d41d8cd98f00b204e9800998ecf8427ep120Digest0123456789";
        let dir = tempfile::tempdir().unwrap();
        let bare = |text: &str| serde_json::json!({"text": text}).to_string();
        let records = [bare("-----BEGIN PRIVATE KEY-----\n"), bare("Sorry"), bare(digest)];
        std::fs::write(dir.path().join("updates.jsonl"), format!("{}\n", records.join("\n"))).unwrap();
        let bytes = build_session_archive(dir.path(), "sid", FLUX).unwrap();
        let updates = tar_file(&bytes, "updates.jsonl");
        let lines: Vec<serde_json::Value> =
            updates.lines().map(|l| serde_json::from_str(l).expect("still JSON")).collect();
        assert_eq!(lines[1]["text"], "Sorry", "{updates}");
        assert_eq!(lines[2]["text"], digest, "{updates}");
    }

    /// P120 (Astra r2 #1, #2, #4): short alphabetic chunks of a key, a marker split in three, and prose that is not a
    /// key (terminal colour codes in it, or under another property).
    #[test]
    fn p120_archive_scrubs_the_astra_r2_cases() {
        let begin = "-----BEGIN PRIVATE KEY-----";
        let digest = "d41d8cd98f00b204e9800998ecf8427ep120Digest0123456789";
        let bare = |text: &str| serde_json::json!({"text": text}).to_string();
        let dir = tempfile::tempdir().unwrap();
        let records = [
            bare(&format!("{begin}\n")),
            bare("MIIE"),
            bare("vQIBp120AlphaChunkRemainderAAAAAA"),
            bare("-----END PRIVATE KEY-----"),
            bare("-----BEGIN "),
            bare("PRIVATE "),
            bare("KEY-----\n"),
            bare("MIIEp120ThreePieceMarkerBodyEEEE"),
            bare("-----END PRIVATE KEY-----"),
            bare(&format!("{begin}\n")),
            bare("Sorry\u{1b}[0m"),
            bare(digest),
            serde_json::json!({"a": format!("{begin}\n"), "b": "Thanks for waiting here", "c": digest}).to_string(),
        ];
        std::fs::write(dir.path().join("updates.jsonl"), format!("{}\n", records.join("\n"))).unwrap();
        let bytes = build_session_archive(dir.path(), "sid", FLUX).unwrap();
        let updates = tar_file(&bytes, "updates.jsonl");
        for fragment in ["p120AlphaChunk", "p120ThreePiece"] {
            assert!(!updates.contains(fragment), "{fragment} left the archive: {updates}");
        }
        let lines: Vec<serde_json::Value> =
            updates.lines().map(|l| serde_json::from_str(l).expect("still JSON")).collect();
        assert_eq!(lines[11]["text"], digest, "a digest after coloured prose: {updates}");
        assert_eq!(lines[12]["c"], digest, "a digest after prose under another property: {updates}");
    }

    /// P120 (Astra r3 #1, #2, #5, #6): short chunks under another property or starting with one letter, a delimiter split
    /// from its first dash, an ordinary word with colour codes, and a word that merely starts like a key.
    #[test]
    fn p120_archive_scrubs_the_astra_r3_cases() {
        let begin = "-----BEGIN PRIVATE KEY-----";
        let digest = "d41d8cd98f00b204e9800998ecf8427ep120Digest0123456789";
        let bare = |text: &str| serde_json::json!({"text": text}).to_string();
        let dir = tempfile::tempdir().unwrap();
        let records = [
            // 0: other property, short chunks in an array
            serde_json::json!({"a": format!("{begin}\n"), "b": ["MIIE", "vQIB", "p120ShortOtherX"], "c": "-----END PRIVATE KEY-----"}).to_string(),
            // 1-4: one letter first, same property
            bare(&format!("{begin}\n")),
            bare("M"),
            bare("IIEp120OneLetterFirstBody"),
            bare("-----END PRIVATE KEY-----"),
            // 5-9: ordinary text first (nothing of the END above is left over), then the delimiter split from its first dash
            bare("some ordinary text here"),
            bare("---"),
            bare("--BEGIN "),
            bare("PRIVATE KEY-----\n"),
            bare("MIIEp120DelimiterSplitBodyFFFF"),
            // 10-12: a word with colour codes is kept, so is the digest after it
            bare(&format!("{begin}\n")),
            bare("Sorry\u{1b}[0m"),
            bare(digest),
            // 13-15: a word that starts like a key is kept, so is the digest after it
            bare(&format!("{begin}\n")),
            bare("MISSING"),
            bare(digest),
        ];
        std::fs::write(dir.path().join("updates.jsonl"), format!("{}\n", records.join("\n"))).unwrap();
        let bytes = build_session_archive(dir.path(), "sid", FLUX).unwrap();
        let updates = tar_file(&bytes, "updates.jsonl");
        for fragment in ["p120ShortOther", "p120OneLetterFirst", "p120DelimiterSplit"] {
            assert!(!updates.contains(fragment), "{fragment} left the archive: {updates}");
        }
        let lines: Vec<serde_json::Value> =
            updates.lines().map(|l| serde_json::from_str(l).expect("still JSON")).collect();
        assert_eq!(lines[11]["text"], "Sorry\u{1b}[0m", "{updates}");
        assert_eq!(lines[12]["text"], digest, "{updates}");
        assert_eq!(lines[14]["text"], "MISSING", "{updates}");
        assert_eq!(lines[15]["text"], digest, "{updates}");
    }

    /// An archive where every file was skipped must fail, not upload an empty gzip while reporting success.
    #[test]
    fn archive_with_nothing_packed_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("huge.jsonl"), vec![b'x'; 32]).unwrap();

        let caps = ArchiveCaps {
            archive_bytes: 64,
            file_bytes: 8,
        };
        let err = build_session_archive_with_caps(dir.path(), "sid", FLUX, &caps)
            .expect_err("all-skipped session must not produce an archive");
        assert!(err.to_string().contains("empty"), "{err}");
    }

    /// P149 (S14/K16, Astra r1 #2): the memory archive (`memory.tar.gz`) was uploaded as `application/gzip`, which no
    /// text scrub reads. Its text members now carry `<redacted>` for a sent key, a `ghp_` shape and a private key;
    /// an image member is kept byte for byte; names survive.
    #[test]
    fn p149_memory_archive_members_are_scrubbed_for_upload() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        const SENT: &str = "fuigo-p149-SYNTH-memory-archive-key1";
        const GHP: &str = "ghp_p149SYNTHp149SYNTHp149SYNTHp149SYNTH";
        const PEM_BODY: &str = "MIIEp149SYNTHPEMBODYp149SYNTHPEMBODYp149SYNTHPEMBODYp149SYNTHAA";
        fuigo_telemetry::sent_credentials::record(SENT);
        let memory = format!(
            "# Notes\n- key {SENT}\n- token {GHP}\n-----BEGIN PRIVATE KEY-----\n{PEM_BODY}\n-----END PRIVATE KEY-----\n"
        );
        let image: Vec<u8> = [&[0x89u8, b'P', b'N', b'G'][..], SENT.as_bytes()].concat();
        let mut gz = Vec::new();
        {
            let mut b = tar::Builder::new(GzEncoder::new(&mut gz, Compression::default()));
            for (name, data) in [("memory/MEMORY.md", memory.as_bytes()), ("memory/shot.png", image.as_slice())] {
                let mut h = tar::Header::new_gnu();
                h.set_size(data.len() as u64);
                h.set_mode(0o600);
                h.set_cksum();
                b.append_data(&mut h, name, data).unwrap();
            }
            b.into_inner().unwrap().finish().unwrap();
        }
        let scrubbed = scrub_upload_tar_gz(&gz).expect("a readable archive");
        let mut members = std::collections::BTreeMap::new();
        let mut a = tar::Archive::new(flate2::read::GzDecoder::new(scrubbed.as_slice()));
        for e in a.entries().unwrap() {
            let mut e = e.unwrap();
            let name = e.path().unwrap().to_string_lossy().into_owned();
            let mut data = Vec::new();
            std::io::Read::read_to_end(&mut e, &mut data).unwrap();
            members.insert(name, data);
        }
        let md = String::from_utf8(members["memory/MEMORY.md"].clone()).unwrap();
        for secret in [SENT, GHP, PEM_BODY] {
            assert!(!md.contains(secret), "MEMORY.md carries {secret}: {md}");
        }
        assert!(md.contains("# Notes") && md.contains("<redacted>"), "control: {md}");
        assert_eq!(members["memory/shot.png"], image, "an image member is kept byte for byte");
        assert!(scrub_upload_tar_gz(b"not a gzip").is_err(), "an unreadable archive is an error, not a pass-through");
    }
}
