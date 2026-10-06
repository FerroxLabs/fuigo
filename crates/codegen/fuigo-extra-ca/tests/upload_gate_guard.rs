//! P71 guard: file content reaches a storage proxy only through the destination gate.
//!
//! `fuigo_file_utils::destination_gate` decides, per destination, whether file content may be sent
//! (FluxRouter-operated proxy: yes; the operator's own Direct GCS or S3 bucket: yes; any other
//! storage proxy: no). The gate is enforced at the sink: it is the first statement of every public
//! `StorageClient` method that moves content to the proxy or names an object to it for upload, so a
//! caller cannot get past it by how it calls, whatever the syntax. What is left to pin is the SOURCE
//! of the sink and the review of new callers. This test reads `crates/` and `prod/` through a small
//! lexer (comments and literals are not code; `#[cfg(test)]` items are not production) and pins:
//!
//! 1. that the gate is the FIRST statement of each of those public `StorageClient` methods, and that
//!    the client's gate helper is the destination gate on the client's own base URL;
//! 2. every function of the sink files (`gcs.rs`, `s3.rs`, `storage_client.rs`), with its visibility:
//!    a new function, or a private one made public, is a new way to reach storage and must be gated
//!    or shown to move no content before it is added to the list;
//! 3. every file that calls or names a `fuigo_file_utils::gcs` dispatcher (each is covered by the
//!    gate beneath it; a NEW caller must be added here and given a wire test);
//! 4. that nothing outside the sink files spells a `/storage` route or the `X-Storage-Path` header
//!    itself (an upload written straight onto an HTTP client would not pass the gate);
//! 5. that the loopback test seam cannot be in a shipped build: it is compiled only with debug
//!    assertions, no profile turns those on, and the feature that enables it outside `cfg(test)` is
//!    requested only from `[dev-dependencies]`.
//!
//! This is a review tripwire for honest changes, not a defence against someone who edits the sink
//! AND this file's blind spots on purpose (that is what code review of the sink files is for).
//! Points 3 and 4 force review of the ordinary ways to add an upload; they are not proofs. What this
//! file cannot see (also in the receipt, R073): a route assembled without the literal `/storage` or
//! the header name and sent with an HTTP client directly; anything a macro generates; a production
//! module whose FILE is named like a test, which the scan skips.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Files that call `fuigo_file_utils::gcs::upload_*` (or `crate::gcs::upload_*` inside file-utils),
/// with the number of production call sites in each. Each is covered by the gate in the storage client.
///
/// * `fuigo-file-utils/src/queue.rs`: the upload queue worker, its zstd stream path, the four inline
///   fallbacks, and (through `enqueue_recovered`) startup recovery of spilled items;
/// * `fuigo-shell/src/upload/trace.rs`: tool definitions, subagent metadata, per-turn artifacts
///   incl. `metadata.json` (`upload_artifact_to_gcs`);
/// * `fuigo-shell/src/upload/gcs.rs`: the auth-diagnostics upload (body and object path);
/// * `fuigo-shell/src/extensions/feedback.rs`: the one-shot feedback archive (also gated early, so the
///   session directory is never packed for a withheld destination), and the review-comment record
///   (`upload_review_record`, which both `fuigo/review/*` handlers send through);
/// * `fuigo-shell/src/extensions/share.rs`: the share bundle (signed URL);
/// * `fuigo-shell/src/heap_profile/monitor.rs`: heap profile and its metadata;
/// * `fuigo-pager/src/trace_cmd.rs`: `fuigo trace`.
const CALLERS: &[(&str, usize)] = &[
    ("crates/codegen/fuigo-file-utils/src/queue.rs", 6),
    ("crates/codegen/fuigo-pager/src/trace_cmd.rs", 1),
    ("crates/codegen/fuigo-shell/src/extensions/feedback.rs", 2),
    ("crates/codegen/fuigo-shell/src/extensions/share.rs", 1),
    ("crates/codegen/fuigo-shell/src/heap_profile/monitor.rs", 2),
    ("crates/codegen/fuigo-shell/src/upload/gcs.rs", 1),
    ("crates/codegen/fuigo-shell/src/upload/trace.rs", 3),
];

/// Names of the `fuigo_file_utils::gcs` dispatchers and of the signed-URL helper beneath `upload_bytes_signed`.
const DISPATCHERS: [&str; 5] =
    ["upload_bytes", "upload_bytes_signed", "upload_file", "upload_stream", "upload_bytes_via_signed_url"];

/// The public `StorageClient` methods that move content to the proxy or name an object to it for
/// upload, with the gate each must open with. (The signed-URL flow has ONE public entry,
/// `upload_bytes_signed`; its two steps are private, so the PUT only ever goes to the URL the gated
/// proxy returned. The public readers `check_exists`, `batch_check_exists`, `download_blob` and
/// `get_upload_limits` send no content.)
const GATED_CLIENT_METHODS: &[(&str, &str)] = &[
    ("batch_upload", "self.gate(\"batch upload\").ok()?;"),
    ("batch_upload_json", "self.gate(\"batch upload\").ok()?;"),
    ("upload", "self.gate(path)?;"),
    ("upload_file", "self.gate(dest_path)?;"),
    ("upload_stream", "self.gate(path)?;"),
    ("upload_multipart", "self.gate(path)?;"),
    ("upload_bytes_signed", "self.gate(path)?;"),
];

const GCS: &str = "crates/codegen/fuigo-file-utils/src/gcs.rs";
const S3: &str = "crates/codegen/fuigo-file-utils/src/s3.rs";
const STORAGE_CLIENT: &str = "crates/codegen/fuigo-file-utils/src/storage_client.rs";
const GATE: &str = "crates/codegen/fuigo-file-utils/src/destination_gate.rs";

/// Every production function of the sink files, sorted; `pub ` marks any `pub` visibility. A new
/// function, or a change of visibility, is a new way to reach storage: gate it (or show it moves no
/// content), then update the list.
#[rustfmt::skip]
const SINK_FUNCTIONS: &[(&str, &[&str])] = &[
    (GCS, &[
        "bucket_url", "bucket_url", "build_gcs_client", "build_proxy_client_with_fallback",
        "proxy_attribution", "proxy_credentials", "proxy_http_client", "pub upload_bytes",
        "pub upload_bytes_signed", "pub upload_bytes_via_signed_url", "pub upload_file", "pub upload_stream",
        "upload_bytes_direct", "upload_bytes_via_proxy", "upload_file_direct", "upload_file_via_proxy",
        "upload_method", "upload_method", "upload_stream_direct",
    ]),
    (S3, &[
        "abort", "classify_head_error", "disarm", "drop", "fmt", "multipart_upload_bytes",
        "parse_aws_credentials", "pub batch_check_exists", "pub batch_upload", "pub bucket_name",
        "pub build_s3_client", "pub check_exists", "pub new", "pub presign_get_url", "pub presign_put_url",
        "pub upload_bytes", "pub upload_file", "pub upload_stream", "to_credentials_content",
    ]),
    (STORAGE_CLIENT, &[
        "add_common_headers", "apply", "calculate_delay", "calculate_delay_with_retry_after",
        "collect_upload_results", "create_read_at_stream", "default", "default", "default_upload_client",
        "fire_401_attribution", "fmt", "from_response", "gate", "generate_jitter", "get_signed_upload_url",
        "is_retryable_status", "multipart_complete", "multipart_init", "parse_retry_after",
        "pub batch_check_exists", "pub batch_upload", "pub batch_upload_json", "pub bearer_destination",
        "pub check_exists", "pub conservative", "pub download_blob", "pub get_upload_limits", "pub new",
        "pub new", "pub new", "pub new", "pub service_session_destination", "pub storage_breaker_is_open",
        "pub upload", "pub upload_bytes_signed", "pub upload_file", "pub upload_multipart",
        "pub upload_stream", "pub wire_bearer", "pub with_attribution", "pub with_client_identity",
        "pub with_client_mode", "pub with_initial_delay", "pub with_jitter_factor", "pub with_max_concurrent",
        "pub with_max_delay", "pub with_max_retries", "pub with_multiplier", "pub with_part_size",
        "pub with_provider", "pub with_retry_config", "pub with_static_key", "record_401",
        "storage_breaker_config", "upload_part_direct", "upload_part_streaming", "upload_parts_direct",
        "upload_parts_via_proxy", "upload_via_signed_url", "wait_for_network_retry", "wait_for_retry",
        "with_static",
    ]),
];

/// Crates that are test infrastructure (mock storage servers): they spell `/storage` routes to SERVE them.
const TEST_INFRASTRUCTURE: [&str; 2] =
    ["crates/codegen/fuigo-test-support/", "crates/codegen/fuigo-pager-pty-harness/"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn files_with_extension(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if name != "target" && name != ".git" {
                files_with_extension(&path, ext, out);
            }
        } else if path.file_name().is_some_and(|n| n == ext) || path.extension().is_some_and(|e| e == ext) {
            out.push(path);
        }
    }
}

fn rust_sources() -> Vec<PathBuf> {
    let mut files = Vec::new();
    for top in ["crates", "prod"] {
        files_with_extension(&repo_root().join(top), "rs", &mut files);
    }
    files
}

/// `path` relative to the repo root, with `/` separators. Every path this test handles is built from
/// [`repo_root`], so the prefix is stripped as written (no `canonicalize`: it is a workspace-disallowed
/// method, and it returns verbatim paths on Windows).
fn relative(path: &Path) -> String {
    path.strip_prefix(repo_root())
        .expect("a path under the repo root")
        .to_string_lossy()
        .replace('\\', "/")
}

/// The files that implement the sinks: the dispatchers, and the clients beneath them.
fn is_sink_implementation(rel: &str) -> bool {
    rel == GCS || rel == S3 || rel == STORAGE_CLIENT
}

fn is_identifier_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// One character of a source file with its comments removed; `literal` marks the CONTENTS of a
/// string, raw-string or char literal (the quotes themselves are code).
#[derive(Clone, Copy)]
struct Lexed {
    c: char,
    literal: bool,
}

/// `text` without its comments (line, and block with nesting), each remaining character marked as
/// code or as the contents of a literal. A `/*`, a brace or a function name inside a literal or a
/// comment is then never mistaken for one in the program.
fn lex(text: &str) -> Vec<Lexed> {
    let chars: Vec<char> = text.chars().collect();
    let mut out: Vec<Lexed> = Vec::with_capacity(chars.len());
    let code = |out: &mut Vec<Lexed>, text: &str| out.extend(text.chars().map(|c| Lexed { c, literal: false }));
    let literal = |out: &mut Vec<Lexed>, body: &[char]| out.extend(body.iter().map(|c| Lexed { c: *c, literal: true }));
    let mut at = 0;
    while at < chars.len() {
        let c = chars[at];
        let next = chars.get(at + 1).copied();
        if c == '/' && next == Some('/') {
            while at < chars.len() && chars[at] != '\n' {
                at += 1;
            }
            continue;
        }
        if c == '/' && next == Some('*') {
            let mut depth = 1;
            at += 2;
            while at < chars.len() && depth > 0 {
                if chars[at] == '/' && chars.get(at + 1) == Some(&'*') {
                    depth += 1;
                    at += 2;
                } else if chars[at] == '*' && chars.get(at + 1) == Some(&'/') {
                    depth -= 1;
                    at += 2;
                } else {
                    if chars[at] == '\n' {
                        code(&mut out, "\n");
                    }
                    at += 1;
                }
            }
            code(&mut out, " ");
            continue;
        }
        // A raw string `r"…"` / `r#"…"#` (also `br…`), not a raw identifier (`r#name`) nor an `r` inside a word.
        if c == 'r' && !(at > 0 && is_identifier_char(chars[at - 1]) && chars[at - 1] != 'b') {
            let mut hashes = 0;
            while chars.get(at + 1 + hashes) == Some(&'#') {
                hashes += 1;
            }
            if chars.get(at + 1 + hashes) == Some(&'"') {
                let start = at + 2 + hashes;
                let mut end = start;
                while end < chars.len()
                    && !(chars[end] == '"' && (1..=hashes).all(|h| chars.get(end + h) == Some(&'#')))
                {
                    end += 1;
                }
                code(&mut out, "r\"");
                literal(&mut out, &chars[start..end.min(chars.len())]);
                code(&mut out, "\"");
                at = (end + 1 + hashes).min(chars.len());
                continue;
            }
        }
        if c == '"' {
            let mut end = at + 1;
            while end < chars.len() && chars[end] != '"' {
                end += if chars[end] == '\\' { 2 } else { 1 };
            }
            code(&mut out, "\"");
            literal(&mut out, &chars[(at + 1).min(chars.len())..end.min(chars.len())]);
            code(&mut out, "\"");
            at = (end + 1).min(chars.len());
            continue;
        }
        if c == '\'' {
            // A char literal (`'x'`, `'\n'`, `'\''`), not a lifetime or a label (`'a`).
            if next == Some('\\') {
                let mut end = at + 3;
                while end < chars.len() && chars[end] != '\'' {
                    end += 1;
                }
                code(&mut out, "''");
                at = (end + 1).min(chars.len());
                continue;
            }
            if chars.get(at + 2) == Some(&'\'') {
                code(&mut out, "''");
                at += 3;
                continue;
            }
        }
        out.push(Lexed { c, literal: false });
        at += 1;
    }
    out
}

/// The text of a lexed file: with `keep_literals`, everything; without, the program text alone
/// (literal contents dropped, their line breaks kept so both views stay line-aligned).
fn view(lexed: &[Lexed], keep_literals: bool) -> String {
    lexed.iter().filter(|l| keep_literals || !l.literal || l.c == '\n').map(|l| l.c).collect()
}

fn code_only(text: &str, keep_literals: bool) -> String {
    view(&lex(text), keep_literals)
}

/// `lexed` without its `#[cfg(test)]` items: the attribute, any further attributes, then the item
/// itself, exactly to where it ends (the `;` at its own nesting level, or the `}` that closes the
/// brace it opened) and not a character further, so production code that follows on the same line
/// stays production. Line breaks inside a removed item are kept.
fn drop_test_items(lexed: Vec<Lexed>) -> Vec<Lexed> {
    const ATTRIBUTE: &str = "#[cfg(test)]";
    // The program text with, for each of its characters, its index in `lexed`.
    let bare: Vec<(usize, char)> =
        lexed.iter().enumerate().filter(|(_, l)| !l.literal).map(|(at, l)| (at, l.c)).collect();
    let attribute: Vec<char> = ATTRIBUTE.chars().collect();
    let starts_with = |at: usize, pattern: &[char]| {
        bare.len() >= at + pattern.len() && bare[at..at + pattern.len()].iter().map(|(_, c)| c).eq(pattern.iter())
    };
    let mut dropped = vec![false; lexed.len()];
    let mut at = 0;
    while at < bare.len() {
        if !starts_with(at, &attribute) {
            at += 1;
            continue;
        }
        let start = at;
        at += attribute.len();
        // Further attributes on the item.
        loop {
            while at < bare.len() && bare[at].1.is_whitespace() {
                at += 1;
            }
            if !starts_with(at, &['#', '[']) {
                break;
            }
            let mut depth = 0;
            while at < bare.len() {
                let c = bare[at].1;
                at += 1;
                if c == '[' {
                    depth += 1;
                } else if c == ']' {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
            }
        }
        // The item: to its `;` at depth 0, or to the `}` that brings the depth back to 0. A closer
        // at depth 0 belongs to whatever encloses the item (a field in a struct, an arm in a match).
        let mut depth = 0;
        let mut end = bare.len();
        while at < bare.len() {
            match bare[at].1 {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' if depth == 0 => {
                    end = at;
                    break;
                }
                ')' | ']' => depth -= 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = at + 1;
                        break;
                    }
                }
                ';' if depth == 0 => {
                    end = at + 1;
                    break;
                }
                _ => {}
            }
            at += 1;
        }
        let from = bare[start].0;
        let to = bare.get(end).map_or(lexed.len(), |(index, _)| *index);
        dropped[from..to].fill(true);
        at = end.max(start + 1);
    }
    lexed.into_iter().zip(dropped).filter(|(l, dropped)| !*dropped || l.c == '\n').map(|(l, _)| l).collect()
}

/// The production part of a source file, as lines.
struct Production {
    /// Comments removed, literals kept (for scans that look INTO string literals: routes, headers).
    code: Vec<String>,
    /// Comments and literal contents removed (for scans of the program text itself).
    bare: Vec<String>,
}

impl Production {
    fn bare_text(&self) -> String {
        self.bare.join("\n")
    }
}

fn production_of(text: &str) -> Production {
    let lexed = drop_test_items(lex(text));
    let lines = |keep_literals: bool| -> Vec<String> {
        view(&lexed, keep_literals).split('\n').map(str::to_string).collect()
    };
    let (code, bare) = (lines(true), lines(false));
    assert_eq!(code.len(), bare.len(), "the two views of a file must stay line-aligned");
    Production { code, bare }
}

/// The production part of the file at `path`; `None` for a file that is itself a test file.
fn production(path: &Path) -> Option<Production> {
    let name = path.file_name()?.to_string_lossy().into_owned();
    let rel = relative(path);
    if name.ends_with("_tests.rs")
        || name == "tests.rs"
        || name == "testkit.rs"
        || name.ends_with("_testkit.rs")
        || rel.contains("/tests/")
        || rel.contains("/benches/")
    {
        return None;
    }
    Some(production_of(&std::fs::read_to_string(path).ok()?))
}

/// Every place `name` stands in `text` as a whole identifier: `(what precedes it, what follows it)`.
fn identifier_uses<'a>(text: &'a str, name: &str) -> Vec<(&'a str, &'a str)> {
    text.match_indices(name)
        .filter_map(|(at, _)| {
            let (before, after) = (&text[..at], &text[at + name.len()..]);
            let whole = !before.chars().next_back().is_some_and(is_identifier_char)
                && !after.chars().next().is_some_and(is_identifier_char);
            whole.then_some((before, after))
        })
        .collect()
}

/// How many times the program text `bare` uses a dispatcher as a free function: a call
/// (`upload_bytes(`, `gcs::upload_bytes::<C>(`) or any other mention of the bare name
/// (`let send = upload_bytes;`: a function value is counted, so a call through one cannot hide).
/// Not counted: a definition (`fn upload_bytes`), a method (`.upload_bytes(`: the storage client's
/// own, gated at the sink), and a mention inside a `use` declaration (an import is not a use; an
/// import under another name is refused by [`aliased_dispatchers`]).
fn dispatcher_uses(bare: &str) -> usize {
    let code = without_imports(bare);
    DISPATCHERS
        .iter()
        .map(|name| {
            identifier_uses(&code, name)
                .into_iter()
                .filter(|(before, _)| {
                    let before = before.trim_end();
                    !before.ends_with('.') && !before.ends_with("fn")
                })
                .count()
        })
        .sum()
}

/// `bare` without its `use` declarations (each from the `use` keyword that starts an item, with or
/// without a visibility before it, to the `;` that ends it, however many lines it spans).
fn without_imports(bare: &str) -> String {
    let mut out = String::new();
    let mut rest = bare;
    loop {
        let import = identifier_uses(rest, "use").into_iter().find(|(before, after)| {
            let head = before.trim_end();
            let head = match head.strip_suffix(')').and_then(|h| h.rfind('(').map(|open| h[..open].trim_end())) {
                Some(visibility) if visibility.ends_with("pub") => visibility,
                _ => head,
            };
            let head = head.strip_suffix("pub").map_or(head, str::trim_end);
            after.starts_with(char::is_whitespace) && (head.is_empty() || head.ends_with([';', '}', '{', ']']))
        });
        let Some((before, after)) = import else {
            out.push_str(rest);
            return out;
        };
        out.push_str(before);
        rest = after.split_once(';').map_or("", |(_, tail)| tail);
    }
}

/// The dispatchers `bare` imports or re-exports under another name (`upload_bytes as send`, however
/// the declaration is laid out): their call sites would be invisible to [`dispatcher_uses`].
fn aliased_dispatchers(bare: &str) -> Vec<&'static str> {
    DISPATCHERS
        .into_iter()
        .filter(|name| {
            identifier_uses(bare, name).into_iter().any(|(_, after)| {
                let after = after.trim_start();
                after.strip_prefix("as").is_some_and(|rest| rest.starts_with(char::is_whitespace))
            })
        })
        .collect()
}

#[test]
fn only_the_pinned_files_call_the_dispatchers() {
    let mut found: BTreeMap<String, usize> = BTreeMap::new();
    for path in rust_sources() {
        let rel = relative(&path);
        // `gcs.rs` defines the dispatchers; `s3.rs` and `storage_client.rs` define the same-named
        // functions beneath them. Every other file is read, whatever it imports.
        if is_sink_implementation(&rel) {
            continue;
        }
        let Some(source) = production(&path) else { continue };
        let bare = source.bare_text();
        let aliased = aliased_dispatchers(&bare);
        assert!(
            aliased.is_empty(),
            "{rel}: imports {aliased:?} under another name, which hides its call sites from this guard"
        );
        let n = dispatcher_uses(&bare);
        if n > 0 {
            found.insert(rel, n);
        }
    }
    let expected: BTreeMap<String, usize> =
        CALLERS.iter().map(|(p, n)| (p.to_string(), *n)).collect();
    assert_eq!(
        found, expected,
        "\nA caller of a storage dispatcher changed. Each caller is covered by the destination gate in the \
         storage client; a NEW caller still needs a wire test (a class 3 mock that receives nothing, a class 1 \
         mock that receives the bytes) and a line in CALLERS. Actual:\n{found:#?}"
    );
}

#[test]
fn nothing_outside_the_sink_files_spells_a_storage_route() {
    let mut offenders = Vec::new();
    for path in rust_sources() {
        let rel = relative(&path);
        if is_sink_implementation(&rel) || TEST_INFRASTRUCTURE.iter().any(|krate| rel.starts_with(krate)) {
            continue;
        }
        let Some(source) = production(&path) else { continue };
        for line in &source.code {
            if line.contains("/storage") || line.to_ascii_lowercase().contains("x-storage-path") {
                offenders.push(format!("{rel}: {}", line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these lines spell a storage route or header themselves; an upload written straight onto an HTTP \
         client does not pass the destination gate (use fuigo_file_utils::gcs::upload_*):\n{offenders:#?}"
    );
}

/// Every function declared in the program text `bare`, sorted: its name, prefixed `pub ` when it has
/// any `pub` visibility (`pub`, `pub(crate)`, `pub (in path)`), whatever qualifiers (`async`,
/// `const`, `unsafe`, `extern "C"`) or line breaks stand between.
fn functions(bare: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (before, after) in identifier_uses(bare, "fn") {
        if !after.starts_with(char::is_whitespace) {
            continue; // a function-pointer type: `fn(u8) -> u8`
        }
        let after = after.trim_start();
        let name: String =
            after.strip_prefix("r#").unwrap_or(after).chars().take_while(|c| is_identifier_char(*c)).collect();
        if name.is_empty() {
            continue;
        }
        let mut head = before.trim_end();
        while let Some(rest) = ["async", "const", "unsafe", "extern", "\"\""].iter().find_map(|qualifier| {
            let rest = head.strip_suffix(qualifier)?;
            let word = qualifier.starts_with(|c: char| c.is_ascii_alphabetic());
            (!word || !rest.chars().next_back().is_some_and(is_identifier_char)).then_some(rest)
        }) {
            head = rest.trim_end();
        }
        if head.ends_with(')') {
            head = head.rfind('(').map_or(head, |open| head[..open].trim_end());
        }
        let public = head
            .strip_suffix("pub")
            .is_some_and(|rest| !rest.chars().next_back().is_some_and(is_identifier_char));
        found.push(if public { format!("pub {name}") } else { name });
    }
    found.sort();
    found
}

#[test]
fn the_sink_files_hold_only_the_reviewed_functions() {
    for (rel, expected) in SINK_FUNCTIONS {
        let source = production(&repo_root().join(rel)).expect("sink file production text");
        assert_eq!(
            functions(&source.bare_text()),
            expected.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
            "\n{rel}: its functions changed. A new function, or a private one made public, is a new way to \
             reach storage: it must pass the destination gate (or move no content) before SINK_FUNCTIONS is updated."
        );
    }
}

/// The first statement of the function whose header line (trimmed) starts with `header`: the first
/// non-blank line after the line that opens its body. That line must open the body and nothing else
/// (exactly one `{`, at its end), so no code can sit between the signature and the statement returned.
fn first_statement<'a>(source: &'a Production, header: &str) -> &'a str {
    let start = source.code.iter().position(|l| l.trim_start().starts_with(header));
    let Some(start) = start else { panic!("{header}: not found") };
    let opens = (start..source.bare.len()).find(|at| source.bare[*at].contains('{'));
    let Some(opens) = opens else { panic!("{header}: body not found") };
    let opening = source.bare[opens].trim_end();
    assert!(
        opening.ends_with('{') && opening.matches('{').count() == 1 && !opening.contains('}'),
        "{header}: the line that opens the body carries more than the opening brace: {opening}"
    );
    source.code[opens + 1..].iter().map(|l| l.trim()).find(|l| !l.is_empty()).unwrap_or_default()
}

#[test]
fn each_public_storage_client_upload_opens_with_the_gate() {
    let source = production(&repo_root().join(STORAGE_CLIENT)).expect("storage_client.rs production text");
    for (function, gate) in GATED_CLIENT_METHODS {
        // Its header is `pub async fn name(` or `pub async fn name<`, on one line (anything else fails here).
        let statement = ["(", "<"]
            .iter()
            .map(|open| format!("pub async fn {function}{open}"))
            .find(|header| source.code.iter().any(|l| l.trim_start().starts_with(header.as_str())))
            .map(|header| first_statement(&source, &header).to_string());
        assert_eq!(
            statement.as_deref(),
            Some(*gate),
            "StorageClient::{function}: the destination gate must run before anything else"
        );
    }
    // The helper every one of them calls is the destination gate on the client's own base URL.
    let helper: Vec<&str> = source
        .code
        .iter()
        .map(|l| l.trim())
        .skip_while(|l| *l != "fn gate(&self, object_path: &str) -> Result<()> {")
        .take(3)
        .collect();
    assert_eq!(
        helper,
        [
            "fn gate(&self, object_path: &str) -> Result<()> {",
            "crate::destination_gate::gate_proxy_url(&self.base_url, object_path)",
            "}",
        ],
        "StorageClient::gate is no longer the destination gate on the client's base URL"
    );
}

#[test]
fn the_loopback_test_seam_cannot_be_in_a_shipped_build() {
    // 1. The seam is compiled only with debug assertions AND (cfg(test) or the feature): both places.
    let gate = std::fs::read_to_string(repo_root().join(GATE)).unwrap();
    assert_eq!(
        gate.matches("#[cfg(all(debug_assertions, any(test, feature = \"test-loopback-operator\")))]").count(),
        2,
        "the seam function and its one call site are both compiled only with debug assertions"
    );
    assert_eq!(
        code_only(&gate, false).matches("test_loopback_operator(").count(),
        2,
        "the seam has exactly one definition and one call"
    );
    // 2. No profile turns debug assertions on (a release-profile build has none by default).
    let root_manifest = std::fs::read_to_string(repo_root().join("Cargo.toml")).unwrap();
    assert!(
        !root_manifest.lines().any(|l| !l.trim_start().starts_with('#') && l.contains("debug-assertions")),
        "a profile sets debug-assertions: a release-family profile with them on could carry the test seam"
    );
    // 3. The feature is requested only from `[dev-dependencies]`, in every manifest incl. the workspace root.
    let mut manifests = vec![repo_root().join("Cargo.toml")];
    for top in ["crates", "prod"] {
        files_with_extension(&repo_root().join(top), "Cargo.toml", &mut manifests);
    }
    let mut enabled_in = Vec::new();
    for path in manifests {
        let rel = relative(&path);
        let text = std::fs::read_to_string(&path).unwrap();
        let mut section = String::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                section = trimmed.to_string();
                continue;
            }
            if trimmed.starts_with('#') || !trimmed.contains("test-loopback-operator") {
                continue;
            }
            if rel == "crates/codegen/fuigo-file-utils/Cargo.toml" && section == "[features]" {
                continue; // the definition
            }
            enabled_in.push((rel.clone(), section.clone()));
        }
    }
    assert!(!enabled_in.is_empty(), "the seam is enabled nowhere: tests would fail closed");
    for (rel, section) in &enabled_in {
        assert!(
            section.ends_with("dev-dependencies]"),
            "{rel}: `test-loopback-operator` enabled under {section}; it may only be a dev-dependency feature"
        );
    }
}

/// Positive control: the scanners see the spellings they exist to catch, and skip what they must.
#[test]
fn the_scanners_see_what_they_must() {
    // The lexer: comments and literal contents are not code.
    let source = "let a = \"src/*\"; // gone\nlet b = r#\"x \" /* y\"#; /* c1 /* nested */ c2 */ let c = '\\''; let d: &'a str = b\"z\";";
    assert_eq!(code_only(source, false), "let a = \"\"; \nlet b = r\"\";   let c = ''; let d: &'a str = b\"\";");
    assert_eq!(code_only(source, true), "let a = \"src/*\"; \nlet b = r\"x \" /* y\";   let c = ''; let d: &'a str = b\"z\";");
    assert_eq!(code_only("a /* 1\n2 */ b \"x\ny\" c", false), "a \n  b \"\n\" c");
    // Dispatcher calls and names.
    assert_eq!(dispatcher_uses("    let u = fuigo_file_utils::gcs::upload_bytes(&c, p, b, t).await;"), 1);
    assert_eq!(dispatcher_uses("    match upload_file(&config, path, file, ct).await {"), 1);
    assert_eq!(dispatcher_uses("    upload_bytes_signed(&c, p, b, t).await?; upload_stream(&c, p, r, t).await?;"), 2);
    assert_eq!(dispatcher_uses("    gcs::upload_bytes::<Config>(&c, p, b, t).await"), 1);
    assert_eq!(dispatcher_uses("    let send = upload_bytes; send(&c, p, b, t).await"), 1);
    assert_eq!(dispatcher_uses("    gcs::upload_bytes_via_signed_url(base, t, None, p, b, ct, None, None, None).await"), 1);
    assert_eq!(dispatcher_uses("pub async fn upload_bytes<C: StorageConfig>("), 0);
    assert_eq!(dispatcher_uses("pub async fn upload_file("), 0);
    assert_eq!(dispatcher_uses("    client.upload_file(path, file, ct).await"), 0);
    assert_eq!(dispatcher_uses("use fuigo_file_utils::gcs::upload_bytes;\nuse a::{\n    b,\n    gcs::upload_file,\n};"), 0);
    assert_eq!(dispatcher_uses("fn f() {\n}\nuse fuigo_file_utils::gcs::upload_bytes;\nfn g() { upload_bytes(c) }"), 1);
    assert_eq!(dispatcher_uses("    my_upload_bytes(x); upload_bytes_direct(y)"), 0);
    assert_eq!(aliased_dispatchers("use fuigo_file_utils::gcs::upload_bytes as\n    send;"), ["upload_bytes"]);
    assert_eq!(aliased_dispatchers("use a::{upload_file  as  put, upload_stream};"), ["upload_file"]);
    assert!(aliased_dispatchers("use fuigo_file_utils::gcs::upload_bytes;\nlet assigned = upload_bytes;").is_empty());
    // Functions, with their visibility, however they are laid out.
    assert_eq!(
        functions(
            "pub async fn b(\n    pub(crate) async fn a<T>(\nasync fn c(\npub fn d(\nfn e(\npub struct F;\n\
             pub\n    async fn g(\npub (crate) async fn h(\npub(in crate::x) const unsafe fn i()\npub(crate)\nfn j<T>(\n\
             pub   extern \"\" fn k(\nlet p: fn(u8) -> u8;\npub fn r#l(\nfn pubfn(\ntrait T { fn m(&self); }"
        ),
        ["c", "e", "m", "pub a", "pub b", "pub d", "pub g", "pub h", "pub i", "pub j", "pub k", "pub l", "pubfn"]
    );
    assert_eq!(functions(&code_only("pub /* why */ async fn n() {} // fn o()\nlet s = \"fn q()\";", false)), ["pub n"]);
    // Test items are not production; a test file has none.
    let stripped = production_of(
        "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn b() { let s = \"}\"; x.upload(1) }\n} pub async fn after() {}\nfn c() {}\n",
    );
    assert_eq!(stripped.bare, ["fn a() {}", "", "", "", " pub async fn after() {}", "fn c() {}", ""]);
    assert_eq!(functions(&stripped.bare_text()), ["a", "c", "pub after"]);
    let members = production_of(
        "impl S {\n    #[cfg(test)]\n    #[allow(x)]\n    fn t(&self) -> Result<A, B> { 1 }\n    fn p(&self) {}\n}\n\
         #[cfg(test)]\nmod m;\nfn z() {}\nstruct T {\n    #[cfg(test)]\n    t: u8,\n}\nfn y() {}",
    );
    assert_eq!(functions(&members.bare_text()), ["p", "y", "z"]);
    let gcs = production(&repo_root().join(GCS)).unwrap();
    assert!(gcs.bare_text().contains("pub async fn upload_bytes"), "production text lost the dispatchers");
    assert!(!gcs.bare_text().contains("mod p71_gate_tests"), "production text kept a #[cfg(test)] module");
    assert!(production(&repo_root().join("crates/codegen/fuigo-file-utils/src/queue_tests.rs")).is_none());
    // The signature walker: the body's first statement, and nothing allowed on the line that opens the body.
    let sample = production_of(
        "    pub async fn upload_stream<C, R>(\n    c: &C,\n) -> R\nwhere\n    R: X,\n    {\n\n    gate()?;\n    rest();\n}\n",
    );
    assert_eq!(first_statement(&sample, "pub async fn upload_stream<"), "gate()?;");
    let conditional = production_of("pub async fn upload(p: &str) -> R { if p.is_empty() {\n    gate()?;\n    }\n}\n");
    assert!(std::panic::catch_unwind(|| first_statement(&conditional, "pub async fn upload(").to_string()).is_err());
}
