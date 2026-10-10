//! P70 guard: no struct or enum in the workspace may `#[derive(Debug)]` while holding a credential.
//!
//! A derived `Debug` prints every field, so one `tracing::debug!(?config)` or `{:?}` in an error message writes the
//! credential to the logs. Secret-bearing types implement `Debug` by hand instead (see `SamplerConfig`), printing
//! `<redacted>` for the secret fields. This test scans the workspace source (`crates/`, `prod/`) for a derived-`Debug`
//! struct, or enum variant, with a field whose NAME says it holds a credential (api_key, secret, password, bearer,
//! *_token, headers, authorization, …) and fails on any that is not in [`ALLOWED`] with a reason. It also fails on an
//! `ALLOWED` entry that no longer matches anything, so the list cannot rot.
//!
//! Scope and limits: named struct fields, struct-like enum variants, tuple structs and tuple variants named for a
//! credential. Test-only code is skipped (`tests/` dirs, `*_tests.rs`, `tests.rs`, test-support crates and the bodies
//! of `#[cfg(test)] mod … { … }`); vendored `third_party/` is out of scope. A field named for something else that still
//! holds a secret is not caught: name it for what it is.
//!
//! URLs: a field whose name says it is a signed, pre-signed, download or upload URL (`signed_url`, `download_url`)
//! is a bearer capability and is flagged. Any OTHER `*_url` field is treated as benign by name, although a user can
//! put a key into a base URL's userinfo or query (`https://user:key@host`, `?key=…`): the types known to hold such
//! a URL print it through `fuigo_auth::redact_url`, but this guard does not find a new one.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use regex::Regex;

/// `path::Type[::Variant]::field` (path relative to the workspace root) → why the derived `Debug` is safe.
const ALLOWED: &[(&str, &str)] = &[
    (
        "crates/codegen/fuigo-shell/src/leader/peer_auth.rs::PeerFacts::peer_token",
        "the user account (a SID string) read from the peer process's Windows access token, or a Win32 error code; not a credential",
    ),
    (
        "crates/codegen/fuigo-chat-state/src/types.rs::ChatStateSnapshot::credentials",
        "`Credentials` implements a redacting Debug",
    ),
    (
        "prod/mc/cli-chat-proxy-types/src/sandbox_types.rs::SandboxCreateEnvironmentRequest::secrets",
        "`SandboxSecretInput` implements a redacting Debug",
    ),
    (
        "prod/mc/cli-chat-proxy-types/src/sandbox_types.rs::SandboxUpdateEnvironmentRequest::secrets",
        "`SandboxSecretInput` implements a redacting Debug",
    ),
    (
        "crates/codegen/fuigo-config-types/src/registry.rs::FeatureSpec::env",
        "the NAME of a feature's env switch (a `&'static str`), not its value",
    ),
    (
        "crates/codegen/fuigo-pager-pty-harness/src/scripted.rs::EnvVar::value",
        "PTY test harness: the fake environment of a scripted scenario",
    ),
    (
        "crates/codegen/fuigo-pager-pty-harness/src/scripted.rs::EnvironmentConfig::env",
        "PTY test harness: the fake environment of a scripted scenario",
    ),
    (
        "crates/codegen/fuigo-pager-pty-harness/src/scroll_matrix/cells.rs::MatrixCell::env",
        "PTY test harness: static, compiled-in scenario variables",
    ),
    (
        "crates/codegen/fuigo-shell/src/agent/key_discovery.rs::Provider::extra_headers",
        "static, public per-provider headers (API version and the like)",
    ),
    (
        "crates/codegen/fuigo-hooks/src/runner/mod.rs::DecisionToken::Unknown::token",
        "an unrecognised hook decision word, not a credential",
    ),
    (
        "crates/codegen/fuigo-pager/src/acp/model_state.rs::EffortTokenError::UnknownToken::token",
        "an unrecognised reasoning-effort word, not a credential",
    ),
    (
        "crates/codegen/fuigo-pager/src/views/suggestion_controller/mod.rs::CompletionSplice::Token::0",
        "a lexical token of the composer line",
    ),
    (
        "crates/codegen/fuigo-pager/src/diagnostics/fix.rs::TmuxCommandToken::value",
        "a lexical token of a tmux command line",
    ),
    (
        "crates/codegen/fuigo-shell/src/extensions/suggest/shell_token.rs::CurrentToken::value",
        "a lexical token of the shell line being completed",
    ),
    (
        "crates/codegen/fuigo-shell/src/extensions/suggest/shell_token.rs::TokenBuild::value",
        "a lexical token of the shell line being completed",
    ),
    (
        "crates/codegen/fuigo-shell/src/extensions/suggest/shell_token.rs::CurrentToken::command",
        "the command word of the shell line being completed (the owner is a lexical token, not an auth type)",
    ),
    (
        "crates/codegen/fuigo-shell/src/session/slash_authority.rs::AuthorityResolution::HumanIntent::args",
        "the argument text of a slash command the user typed (the owner decides input authority, not auth)",
    ),
    (
        "crates/codegen/fuigo-shell/src/session/slash_authority.rs::AuthorityResolution::ModelAuthoredSkillCandidate::args",
        "the argument text of a slash command (the owner decides input authority, not auth)",
    ),
];

struct Rules {
    secret: Regex,
    benign: Regex,
    authy: Regex,
    secret_variant: Regex,
    nonsecret_ty: Regex,
    carrier: Regex,
    stringy: Regex,
    map_carrier: Regex,
    maplike: Regex,
    capability_url: Regex,
    debug: Regex,
    item: Regex,
    field: Regex,
    vis: Regex,
    variant: Regex,
    test_mod: Regex,
}

impl Rules {
    fn new() -> Self {
        let re = |s: &str| Regex::new(s).unwrap();
        Self {
            secret: re(
                r"(?i)(api_?key|secret|password|passwd|bearer|device_code|refresh_token|access_token|id_token|jwt|authorization|credential|private_key|cookie|(^|_)token$|(^|_)headers?$|^envs?$|auth_provider_command$|(^|_)(test|deployment|account|session|access|signing|master|user|server)_(key|token)$)",
            ),
            // Anchored to identifier components, so `service_account_key` is not excused by containing "count".
            benign: re(
                r"(?i)((^|_)(env_var|file|path|url|id|ids|len|count|budget|limit|ttl|ms|secs|range|ranges|kind|text|name|names|endpoint|supported|label|scheme|mode|source|type|hint|hash|fingerprint|tokens|page_token)$|_header$|_env$|^(has|disable|cancel|cancellation|lease|sticky|max|min|num)_)",
            ),
            authy: re(r"(?i)(secret|credential|token|password|auth)"),
            secret_variant: re(
                r"(?i)^(api_?key|bearer|token|secret|password|access_?token|refresh_?token|jwt|basic|credentials?)$",
            ),
            nonsecret_ty: re(
                r"^(bool|u8|u16|u32|u64|usize|i32|i64|f32|f64|Option<(bool|u8|u16|u32|u64|usize|i32|i64)>|Duration|Instant|[A-Za-z_:]*CancellationToken|Option<[A-Za-z_:]*CancellationToken>|SentCredential)$",
            ),
            // `header`/`headers`/`env`/`envs` hold credentials only when they hold text (not a layout `Rect`, say).
            carrier: re(r"(?i)^(headers?|envs?)$"),
            stringy: re(r"String|EnvVar|\bstr\b"),
            // Any `…headers` / `…env` field holding a map or pair list of values (`extra_env`, `extra_headers`).
            map_carrier: re(r"(?i)(^|_)(headers?|envs?)$"),
            maplike: re(r"Map<|Vec<\(|EnvVar|\bHeaderMap\b"),
            // A URL that is itself the authorization: pre-signed object URLs.
            capability_url: re(r"(?i)(^|_)(signed|presigned|download|upload)_url$"),
            debug: re(r"\bDebug\b"),
            item: re(r"^(pub(\([^)]*\))?\s+)?(struct|enum)\s+(\w+)"),
            field: re(r"(?s)^(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+)$"),
            vis: re(r"^pub(\([^)]*\))?\s+"),
            variant: re(r"^([A-Za-z_]\w*)\s*([{(])?"),
            test_mod: re(r"^\s*(#\[[^\]]*\]\s*)*(pub(\([^)]*\))?\s+)?mod\s+\w+\s*\{"),
        }
    }
}

/// Source with comments removed and the contents of string, raw-string and char literals blanked (newlines kept), so
/// brackets inside literals do not unbalance the scan.
fn normalize(src: &str) -> String {
    let b = src.as_bytes();
    let n = b.len();
    let mut out = String::with_capacity(n);
    let blank = |s: &str, out: &mut String| out.extend(s.chars().map(|c| if c == '\n' { '\n' } else { ' ' }));
    let mut i = 0;
    while i < n {
        let rest = &src[i..];
        if rest.starts_with("//") {
            i = rest.find('\n').map_or(n, |k| i + k);
            continue;
        }
        if rest.starts_with("/*") {
            i = rest.find("*/").map_or(n, |k| i + k + 2);
            continue;
        }
        if b[i] == b'r' && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')) {
            let hashes = rest[1..].bytes().take_while(|&h| h == b'#').count();
            if rest[1 + hashes..].starts_with('"') {
                let close = format!("\"{}", "#".repeat(hashes));
                let body = 2 + hashes;
                let end = rest[body..].find(&close).map_or(rest.len(), |k| body + k);
                out.push_str(&rest[..body]);
                blank(&rest[body..end], &mut out);
                out.push_str(&rest[end..(end + close.len()).min(rest.len())]);
                i += (end + close.len()).min(rest.len());
                continue;
            }
        }
        if b[i] == b'"' {
            let mut j = i + 1;
            while j < n && b[j] != b'"' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            let j = j.min(n);
            out.push('"');
            blank(&src[i + 1..j], &mut out);
            if j < n {
                out.push('"');
            }
            i = j + 1;
            continue;
        }
        if b[i] == b'\'' {
            // A char literal ('x', '\n', '\u{..}', '"'), not a lifetime.
            let lit_len = if rest[1..].starts_with('\\') {
                rest[2..].find('\'').map(|k| k + 3)
            } else {
                rest[1..].chars().next().and_then(|c| rest[1 + c.len_utf8()..].starts_with('\'').then(|| 2 + c.len_utf8()))
            };
            if let Some(len) = lit_len {
                out.push_str("' '");
                i += len;
                continue;
            }
        }
        let ch = rest.chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Index of the bracket closing the one at `open` (which must be `o`).
fn close_of(s: &str, open: usize, o: u8, c: u8) -> Option<usize> {
    let mut depth = 0i32;
    for (j, &ch) in s.as_bytes().iter().enumerate().skip(open) {
        if ch == o {
            depth += 1;
        } else if ch == c {
            depth -= 1;
            if depth == 0 {
                return Some(j);
            }
        }
    }
    None
}

/// The index just past the generic parameter list `<…>` that starts (after whitespace) at `j`, or `j` when there is
/// none. Its bounds may hold `(` (`F: Fn() -> bool`), which must not be taken for a tuple body, and the `>` of a `->`
/// closes nothing (Astra r6, P70a).
fn skip_generics(s: &str, j: usize) -> usize {
    let b = s.as_bytes();
    let k = j + (s[j..].len() - s[j..].trim_start().len());
    if b.get(k) != Some(&b'<') {
        return j;
    }
    let mut depth = 0i32;
    for idx in k..b.len() {
        match b[idx] {
            b'<' => depth += 1,
            b'>' if b[idx - 1] == b'-' => {}
            b'>' => {
                depth -= 1;
                if depth == 0 {
                    return idx + 1;
                }
            }
            _ => {}
        }
    }
    j
}

/// Blank the bodies of `#[cfg(test)] mod … { … }` (code after a test module is still scanned).
fn blank_test_mods(rules: &Rules, mut s: String) -> String {
    let mut from = 0;
    while let Some(k) = s[from..].find("#[cfg(test)]").map(|k| k + from) {
        let after = k + "#[cfg(test)]".len();
        if let Some(m) = rules.test_mod.find(&s[after..]) {
            let open = after + m.end() - 1;
            if let Some(close) = close_of(&s, open, b'{', b'}') {
                let blanked: String = s[k..=close].chars().map(|c| if c == '\n' { '\n' } else { ' ' }).collect();
                s.replace_range(k..=close, &blanked);
            }
        }
        from = k + 1;
    }
    s
}

/// Top-level comma-separated segments of `body`.
fn split_top(body: &str) -> Vec<String> {
    let (mut segs, mut cur, mut depth) = (Vec::new(), String::new(), 0i32);
    let mut prev = '\0';
    for ch in body.chars() {
        match ch {
            '<' | '(' | '[' | '{' => depth += 1,
            // The `>` of a `->` (a function-pointer or closure type) closes nothing (Astra r5, P70a).
            '>' if prev == '-' => {}
            '>' | ')' | ']' | '}' => depth -= 1,
            _ => {}
        }
        prev = ch;
        if ch == ',' && depth == 0 {
            segs.push(std::mem::take(&mut cur));
        } else {
            cur.push(ch);
        }
    }
    segs.push(cur);
    segs
}

fn strip_attrs(rules: &Rules, seg: &str) -> String {
    let mut t = seg.trim().to_owned();
    while t.starts_with("#[") {
        let Some(c) = close_of(&t, 1, b'[', b']') else { break };
        t = t[c + 1..].trim().to_owned();
    }
    rules.vis.replace(&t, "").into_owned()
}

fn field_hits(rules: &Rules, owner: &str, body: &str, authy_owner: bool, hits: &mut Vec<(String, String, String)>) {
    for seg in split_top(body) {
        let t = strip_attrs(rules, &seg);
        let Some(f) = rules.field.captures(&t) else { continue };
        let field = f[1].to_owned();
        let ty = f[2].split_whitespace().collect::<Vec<_>>().join(" ");
        let named_secret = rules.secret.is_match(&field)
            && !rules.benign.is_match(&field)
            && !rules.nonsecret_ty.is_match(&ty)
            && (!rules.carrier.is_match(&field) || rules.stringy.is_match(&ty));
        // A helper's command line in an auth-ish type (`AuthProviderConfig { command, args }`) carries whatever the
        // user wrote, `--token …` included (Astra r2, P70a).
        let generic_in_auth_type =
            authy_owner && matches!(field.as_str(), "key" | "value" | "token" | "command" | "args" | "cmd");
        // The value half of an environment-variable pair (`McpEnvVar`, `EnvVar`, `SandboxEnvironmentVariable`).
        let env_value = (owner.ends_with("EnvVar") || owner.ends_with("EnvironmentVariable")) && field == "value";
        let value_map = rules.map_carrier.is_match(&field) && rules.maplike.is_match(&ty);
        let capability_url = rules.capability_url.is_match(&field) && rules.stringy.is_match(&ty);
        if named_secret || generic_in_auth_type || env_value || value_map || capability_url {
            hits.push((owner.to_owned(), field, ty));
        }
    }
}

/// `(Type[::Variant], field, type)` for every flagged field in `src`.
fn scan(rules: &Rules, src: &str) -> Vec<(String, String, String)> {
    let s = blank_test_mods(rules, normalize(src));
    let mut hits = Vec::new();
    let mut i = 0;
    while let Some(d) = s[i..].find("#[derive(").map(|d| d + i) {
        let Some(e) = close_of(&s, d + 1, b'[', b']') else { break };
        let derive = &s[d..=e];
        i = e + 1;
        if !rules.debug.is_match(derive) {
            continue;
        }
        let mut j = i;
        loop {
            j += s[j..].len() - s[j..].trim_start().len();
            if s[j..].starts_with("#[") {
                match close_of(&s, j + 1, b'[', b']') {
                    Some(c) => j = c + 1,
                    None => break,
                }
                continue;
            }
            break;
        }
        let Some(m) = rules.item.captures(&s[j..]) else { continue };
        let (kind, name) = (m[3].to_owned(), m[4].to_owned());
        j = skip_generics(&s, j + m[0].len());
        // A `where` clause before a braced body may hold `(` (`F: Fn() -> bool`): the body is then the `{` (or `;`).
        let delimiters: &[&str] = if s[j..].trim_start().starts_with("where") { &["{", ";"] } else { &["{", ";", "("] };
        let Some(k) = delimiters.iter().filter_map(|t| s[j..].find(t).map(|k| k + j)).min() else { continue };
        if kind == "struct" {
            match s.as_bytes()[k] {
                b'(' => {
                    if rules.authy.is_match(&name)
                        && let Some(c) = close_of(&s, k, b'(', b')')
                        && s[k + 1..c].contains("String")
                    {
                        hits.push((name, "0".to_owned(), s[k + 1..c].trim().to_owned()));
                    }
                }
                b'{' => {
                    if let Some(end) = close_of(&s, k, b'{', b'}') {
                        let authy = rules.authy.is_match(&name);
                        field_hits(rules, &name, &s[k + 1..end], authy, &mut hits);
                    }
                }
                _ => {}
            }
            continue;
        }
        let Some(open) = s[j..].find('{').map(|o| o + j) else { continue };
        let Some(end) = close_of(&s, open, b'{', b'}') else { continue };
        for seg in split_top(&s[open + 1..end]) {
            let t = strip_attrs(rules, &seg);
            let Some(v) = rules.variant.captures(&t) else { continue };
            let variant = v[1].to_owned();
            let owner = format!("{name}::{variant}");
            match v.get(2).map(|g| g.as_str()) {
                Some("{") => {
                    let b = t.find('{').unwrap();
                    if let Some(c) = close_of(&t, b, b'{', b'}') {
                        let authy = rules.authy.is_match(&name) || rules.authy.is_match(&variant);
                        field_hits(rules, &owner, &t[b + 1..c], authy, &mut hits);
                    }
                }
                Some("(") => {
                    let b = t.find('(').unwrap();
                    if let Some(c) = close_of(&t, b, b'(', b')')
                        && rules.secret_variant.is_match(&variant)
                        && t[b + 1..c].contains("String")
                    {
                        hits.push((owner, "0".to_owned(), t[b + 1..c].trim().to_owned()));
                    }
                }
                _ => {}
            }
        }
    }
    hits
}

fn workspace_root() -> PathBuf {
    // `<root>/crates/codegen/fuigo-auth` -> `<root>`, without `canonicalize` (banned by the workspace clippy.toml).
    Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(3).expect("workspace root").to_path_buf()
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            let skip = ["target", "node_modules", ".git", "third_party", "tests", "test_support", "testkit", "fuigo-test-support"];
            if !skip.contains(&name.as_str()) {
                rust_sources(&path, out);
            }
        } else if ft.is_file() && name.ends_with(".rs") && !name.ends_with("_tests.rs") && name != "tests.rs" {
            out.push(path);
        }
    }
}

#[test]
fn no_secret_bearing_type_derives_debug() {
    let rules = Rules::new();
    let root = workspace_root();
    let mut files = Vec::new();
    for top in ["crates", "prod"] {
        rust_sources(&root.join(top), &mut files);
    }
    assert!(files.len() > 500, "control: the scan must see the workspace, found {} files under {}", files.len(), root.display());
    let allowed: BTreeSet<&str> = ALLOWED.iter().map(|(k, _)| *k).collect();
    let (mut violations, mut seen) = (Vec::new(), BTreeSet::new());
    for file in &files {
        let Ok(src) = std::fs::read_to_string(file) else { continue };
        let rel = file.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        for (owner, field, ty) in scan(&rules, &src) {
            let key = format!("{rel}::{owner}::{field}");
            if allowed.contains(key.as_str()) {
                seen.insert(key);
            } else {
                violations.push(format!("{key} ({ty})"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "secret-bearing types derive Debug; implement Debug by hand and print the secret as \"<redacted>\" \
         (or, if the field holds no secret, add it to ALLOWED with a reason):\n  {}",
        violations.join("\n  ")
    );
    let stale: Vec<&&str> = allowed.iter().filter(|k| !seen.contains(**k)).collect();
    assert!(stale.is_empty(), "ALLOWED entries that no longer match anything (remove them): {stale:?}");
}

/// The scanner's own control. It flags: a multi-line derive with attributes, `service_account_key` (whose name
/// contains "count"), a tuple struct with an auth-ish name, generic key/value fields in an auth-ish type, struct and
/// tuple enum variants, a leaking struct placed AFTER a test module, and structs whose generic bounds or `where`
/// clause hold `Fn() -> …` (Astra r6). It passes: a hand-written Debug, benign
/// names, braces inside literals, and the test module's own fixtures.
#[test]
fn scanner_flags_secret_fields_and_passes_benign_ones() {
    let rules = Rules::new();
    let src = r##"
        /// docs with api_key: String, in prose
        #[derive(
            Clone,
            Debug,
        )]
        #[serde(rename_all = "camelCase")]
        pub(crate) struct Leaky {
            #[serde(default = "brace_{")]
            pub api_key: Option<String>,
            pub extra_headers: IndexMap<String, String>, // trailing comment, token: String
            pub api_key_env: Option<String>,
            pub max_tokens: u32,
            pub has_secret: bool,
            pub refresh_token: Option<String>,
            pub service_account_key: Option<String>,
            pub next_page_token: Option<String>,
        }
        const BRACE: char = '{';
        const RAW: &str = r#"}{ "quoted" }"#;
        #[derive(Debug)]
        struct AuthBlob(String);
        #[derive(Debug)]
        struct SecretPair { key: Option<String>, value: Option<String> }
        #[derive(Debug)]
        struct AuthHelper { command: String, args: Option<Vec<String>>, timeout_secs: Option<u64> }
        #[derive(Debug)]
        struct Callbacks { on_ready: fn() -> bool, map: Box<dyn Fn(u32) -> Vec<u8>>, api_key: String }
        #[derive(Debug)]
        struct BuildStep { command: String, args: Vec<String> }
        #[derive(Clone)]
        struct Manual { api_key: String }
        impl std::fmt::Debug for Manual { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("Manual") } }
        #[derive(Debug)]
        struct Url { base_url: String, page_token: Option<String>, custom_upload_url: bool }
        #[derive(Debug)]
        struct Signed { signed_url: String, download_url: Option<String>, trace_upload_url: Option<String> }
        #[derive(Debug, Clone)]
        pub enum Upload {
            /// A comment, with a comma
            Direct { service_account_key: Option<String> },
            Bearer(String),
            Off,
            Named(String),
        }
        #[cfg(test)]
        #[allow(dead_code)]
        mod tests {
            #[derive(Debug)]
            struct Fixture { authorization: Option<String>, brace: char = '}' }
        }
        #[derive(Debug)]
        struct AfterTests { password: String }
        #[derive(Debug)]
        struct Carriers {
            header: Vec<String>,
            env: HashMap<String, String>,
            auth_provider_command: Option<String>,
            token_header: String,
            layout_header: Rect,
            header_rect: Rect,
            fuigo_env: String,
            extra_env: BTreeMap<String, String>,
            server_key: Option<String>,
            device_code: String,
            api_key_env_name: Option<String>,
        }
        #[derive(Debug)]
        struct Layout { header: Rect }
        #[derive(Debug)]
        struct Outbound { headers: reqwest::header::HeaderMap, request_headers: HeaderMap<HeaderValue> }
        #[derive(Debug)]
        pub struct McpEnvVar { pub name: String, pub value: String }
        #[derive(Debug)]
        pub struct SandboxEnvironmentVariable { pub key: Option<String>, pub value: Option<String> }
        #[derive(Debug)]
        struct Bounded<F: Fn() -> bool, T = Vec<u8>> { api_key: String, on: F, t: T }
        #[derive(Debug)]
        struct Whered<F> where F: Fn(u32) -> bool { password: String, f: F }
        #[derive(Debug)]
        struct TupleBounded<F: Fn() -> bool>(F, u32);
    "##;
    let hits: BTreeSet<String> = scan(&rules, src).into_iter().map(|(s, f, _)| format!("{s}::{f}")).collect();
    let expected: BTreeSet<String> = [
        "Leaky::api_key",
        "Leaky::extra_headers",
        "Leaky::refresh_token",
        "Leaky::service_account_key",
        "AuthBlob::0",
        "SecretPair::key",
        "SecretPair::value",
        "AuthHelper::command",
        "AuthHelper::args",
        "Callbacks::api_key",
        "Signed::signed_url",
        "Signed::download_url",
        "Signed::trace_upload_url",
        "Upload::Direct::service_account_key",
        "Upload::Bearer::0",
        "AfterTests::password",
        "Carriers::header",
        "Carriers::env",
        "Carriers::auth_provider_command",
        "Carriers::extra_env",
        "Outbound::headers",
        "Outbound::request_headers",
        "Carriers::server_key",
        "Carriers::device_code",
        "McpEnvVar::value",
        "SandboxEnvironmentVariable::value",
        "Bounded::api_key",
        "Whered::password",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(hits, expected);
}
