//! Guard: every `acp::Error` the shell builds carries `data` produced by a typed helper, so it is an object with `message` and `error_kind`.
//! JSON clients read `data.message` / `data.error_kind` and drop anything else; a bare string there left the user with a generic "Internal error".
//! The scan covers non-test source under `src/`. It also rejects the two schema constructors that build ad-hoc `data`
//! (`into_internal_error` and `resource_not_found(Some(..))`).
//!
//! `.data(..)` is not the only way a bare string gets on the wire. The schema crate converts implicitly —
//! `impl From<serde_json::Error> for acp::Error` is `Error::invalid_params().data(error.to_string())`, and
//! `impl From<anyhow::Error>` is `into_internal_error` — so a plain `?` inside a function that returns
//! `Result<_, acp::Error>` ships one without a `.data(` anywhere in sight. The second scan below rejects those:
//! inside an `acp::Error`-returning function, `?` may not be applied to an expression whose error type is
//! recognisably `serde_json::Error` or `anyhow::Error`. Map it through `crate::acp_error` instead
//! (`parse_params_str`, `invalid_params_from`, `internal_from`).
//! Its reach is textual: it sees the error type where the expression names it (`serde_json::…`, `anyhow!`,
//! `.context(..)`). A `?` on a crate-local helper that returns `anyhow::Result` names nothing, so those were
//! enumerated once by compiling the tree against a schema crate with `impl From<anyhow::Error> for acp::Error`
//! deleted; keep new helpers of that shape out of `acp::Error`-returning functions.

use std::path::{Path, PathBuf};

/// Functions whose return value is a typed `data` object (see `crate::acp_error`).
const TYPED_DATA_HELPERS: &[&str] = &[
    "error_data",
    "error_data_with_fields",
    "terminal_error_data",
    "compact_error_data",
    "typed_error_data",
];

fn is_test_path(rel: &str) -> bool {
    let file = rel.rsplit('/').next().unwrap_or(rel);
    file.ends_with("tests.rs")
        || rel
            .split('/')
            .any(|part| part == "tests" || part.ends_with("_tests"))
}

/// A file the guard cannot read as Rust text: an AppleDouble sidecar (`._foo.rs`, left next to real
/// sources by a macOS tar) or any other non-UTF-8 content. Reading one used to abort the whole test
/// inside `expect("read source")` with a message about the wrong thing, masking the guard's own verdict.
fn unreadable_as_rust(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("._"))
        || std::fs::read_to_string(path).is_err()
}

fn rust_sources(dir: &Path, root: &Path, out: &mut Vec<(String, PathBuf)>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| entry.expect("dir entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rust_sources(&path, root, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") && !unreadable_as_rust(&path) {
            let rel = path
                .strip_prefix(root)
                .expect("under src")
                .to_string_lossy()
                .replace('\\', "/");
            if !is_test_path(&rel) {
                out.push((rel, path));
            }
        }
    }
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn blank(chars: &mut [char], from: usize, to: usize) {
    let end = to.min(chars.len());
    for c in &mut chars[from..end] {
        if *c != '\n' {
            *c = ' ';
        }
    }
}

/// `src` with comments and string/char literal contents replaced by spaces; newlines stay, so offsets still map to lines.
fn code_only(src: &str) -> Vec<char> {
    let b: Vec<char> = src.chars().collect();
    let mut out = b.clone();
    let mut i = 0;
    while i < b.len() {
        let next = b.get(i + 1).copied();
        if b[i] == '/' && next == Some('/') {
            let start = i;
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
            blank(&mut out, start, i);
        } else if b[i] == '/' && next == Some('*') {
            let start = i;
            let mut depth = 0usize;
            while i < b.len() {
                if b[i] == '/' && b.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == '*' && b.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            blank(&mut out, start, i);
        } else if b[i] == 'r'
            && (i == 0
                || !is_ident(b[i - 1])
                || (b[i - 1] == 'b' && (i < 2 || !is_ident(b[i - 2]))))
            && matches!(next, Some('"') | Some('#'))
        {
            let mut j = i + 1;
            let mut hashes = 0;
            while b.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if b.get(j) != Some(&'"') {
                i += 1;
                continue;
            }
            let start = j + 1;
            j += 1;
            'raw: while j < b.len() {
                if b[j] == '"' && (1..=hashes).all(|k| b.get(j + k) == Some(&'#')) {
                    break 'raw;
                }
                j += 1;
            }
            blank(&mut out, start, j);
            i = j + 1 + hashes;
        } else if b[i] == '"' {
            let start = i + 1;
            i += 1;
            while i < b.len() && b[i] != '"' {
                if b[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            blank(&mut out, start, i);
            i += 1;
        } else if b[i] == '\'' {
            if next == Some('\\') {
                let start = i + 1;
                i += 2;
                while i < b.len() && b[i] != '\'' {
                    i += 1;
                }
                blank(&mut out, start, i);
                i += 1;
            } else if b.get(i + 2) == Some(&'\'') {
                blank(&mut out, i + 1, i + 2);
                i += 3;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    out
}

fn find(hay: &[char], needle: &str, from: usize) -> Option<usize> {
    let needle: Vec<char> = needle.chars().collect();
    (from..hay.len().saturating_sub(needle.len() - 1)).find(|&i| hay[i..].starts_with(&needle))
}

/// Blank every `#[cfg(test)]` item: up to its `;`, or to the brace that closes its body.
fn strip_cfg_test_items(code: &mut [char]) {
    let mut from = 0;
    while let Some(pos) = find(code, "#[cfg(test)]", from) {
        let mut j = pos + "#[cfg(test)]".len();
        let mut depth = 0i32;
        let mut end = code.len();
        while j < code.len() {
            match code[j] {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = j + 1;
                        break;
                    }
                }
                ';' if depth == 0 => {
                    end = j + 1;
                    break;
                }
                _ => {}
            }
            j += 1;
        }
        blank(code, pos, end);
        from = end;
    }
}

fn line_of(code: &[char], offset: usize) -> usize {
    code[..offset].iter().filter(|&&c| c == '\n').count() + 1
}

/// A return type whose error is `acp::Error`, so `?` inside the body converts through the schema
/// crate's `From` impls. `ExtResult` and `AcpResult<T>` are the crate's aliases for exactly that.
fn returns_acp_error(ret: &str) -> bool {
    let ret = ret.trim();
    ret.starts_with("ExtResult")
        || ret.starts_with("AcpResult<")
        || ret.starts_with("acp::Result<")
        || (ret.starts_with("Result<") && ret.contains("acp::Error"))
}

/// `(start, end)` of the body braces of every function whose error type is `acp::Error`.
fn acp_error_fn_bodies(code: &[char]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = find(code, "fn ", from) {
        from = pos + 3;
        if pos > 0 && is_ident(code[pos - 1]) {
            continue;
        }
        let mut j = pos + 3;
        while j < code.len() && code[j].is_whitespace() {
            j += 1;
        }
        while j < code.len() && is_ident(code[j]) {
            j += 1;
        }
        // Generics: `->` inside a bound (`F: Fn() -> T`) is not a closing angle bracket
        while j < code.len() && code[j].is_whitespace() {
            j += 1;
        }
        if code.get(j) == Some(&'<') {
            let mut depth = 0i32;
            while j < code.len() {
                if code[j] == '-' && code.get(j + 1) == Some(&'>') {
                    j += 2;
                    continue;
                }
                match code[j] {
                    '<' => depth += 1,
                    '>' => {
                        depth -= 1;
                        if depth == 0 {
                            j += 1;
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
        }
        while j < code.len() && code[j].is_whitespace() {
            j += 1;
        }
        if code.get(j) != Some(&'(') {
            continue;
        }
        let mut depth = 0i32;
        while j < code.len() {
            match code[j] {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        j += 1;
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        let sig_start = j;
        while j < code.len() && code[j] != '{' && code[j] != ';' {
            j += 1;
        }
        // A trait method declaration has no body to scan
        if code.get(j) != Some(&'{') {
            continue;
        }
        let sig: String = code[sig_start..j].iter().collect();
        let Some((_, ret)) = sig.split_once("->") else {
            continue;
        };
        let ret = ret.split("where").next().unwrap_or(ret);
        if !returns_acp_error(ret) {
            continue;
        }
        let start = j;
        let mut depth = 0i32;
        while j < code.len() {
            match code[j] {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        out.push((start, j.min(code.len())));
        from = j;
    }
    out
}

/// The expression a `?` at `q` is applied to, verbatim: walk back over one primary expression chain.
fn try_chain(code: &[char], q: usize) -> String {
    let mut j = q as isize - 1;
    while j >= 0 && code[j as usize].is_whitespace() {
        j -= 1;
    }
    let end = (j + 1) as usize;
    while j >= 0 {
        let c = code[j as usize];
        if matches!(c, ')' | ']' | '}') {
            let open = match c {
                ')' => '(',
                ']' => '[',
                _ => '{',
            };
            let mut depth = 0i32;
            while j >= 0 {
                let cc = code[j as usize];
                if cc == c {
                    depth += 1;
                } else if cc == open {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                j -= 1;
            }
            j -= 1;
        } else if c == '>' {
            // `->` / `=>` end the chain; anything else is a turbofish
            if j > 0 && matches!(code[(j - 1) as usize], '-' | '=') {
                break;
            }
            let mut depth = 0i32;
            while j >= 0 {
                let cc = code[j as usize];
                if cc == '>' {
                    depth += 1;
                } else if cc == '<' {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                j -= 1;
            }
            j -= 1;
        } else if is_ident(c) || matches!(c, '.' | ':' | '?' | '&' | '*') {
            j -= 1;
        } else if c.is_whitespace() {
            let mut k = j;
            while k >= 0 && code[k as usize].is_whitespace() {
                k -= 1;
            }
            // Whitespace continues the chain only between its own pieces (a wrapped `.method()` call)
            if k >= 0
                && (is_ident(code[k as usize])
                    || matches!(code[k as usize], ')' | ']' | '}' | '.' | ':'))
            {
                j = k;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    // An unbalanced walk runs off the front of the file; clamp rather than index negatively.
    let start = (j + 1).max(0) as usize;
    code[start..end.max(start)].iter().collect()
}

/// The non-`acp::Error` error type this chain hands `?`, when the expression names it.
/// A chain that already went through `map_err` produced an `acp::Error` itself, whatever it started as.
fn implicit_conversion_source(chain: &str) -> Option<&'static str> {
    if chain.contains(".map_err(") {
        return None;
    }
    for (needle, source) in [
        ("serde_json::", "serde_json::Error"),
        ("anyhow::", "anyhow::Error"),
        ("anyhow!", "anyhow::Error"),
        (".context(", "anyhow::Error"),
        (".with_context(", "anyhow::Error"),
    ] {
        if chain.contains(needle) {
            return Some(source);
        }
    }
    None
}

/// Offending sites in one file, as `rel:line: reason`.
fn offenders(rel: &str, src: &str) -> Vec<String> {
    let mut code = code_only(src);
    strip_cfg_test_items(&mut code);
    let lines: Vec<&str> = src.lines().collect();
    let site = |offset: usize, what: &str| {
        let line = line_of(&code, offset);
        format!(
            "{rel}:{line}: {what}: {}",
            lines.get(line - 1).map(|l| l.trim()).unwrap_or("")
        )
    };
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(pos) = find(&code, ".data(", from) {
        from = pos + ".data(".len();
        let mut j = from;
        while j < code.len() && code[j].is_whitespace() {
            j += 1;
        }
        let head_start = j;
        while j < code.len() && (is_ident(code[j]) || code[j] == ':') {
            j += 1;
        }
        let head: String = code[head_start..j].iter().collect();
        while j < code.len() && code[j].is_whitespace() {
            j += 1;
        }
        let name = head.rsplit("::").next().unwrap_or("");
        let is_call = code.get(j) == Some(&'(');
        if !(is_call && TYPED_DATA_HELPERS.contains(&name)) {
            found.push(site(pos, "`.data(..)` argument is not a typed helper"));
        }
    }
    for banned in ["into_internal_error(", "resource_not_found(Some"] {
        let mut from = 0;
        while let Some(pos) = find(&code, banned, from) {
            from = pos + banned.len();
            found.push(site(pos, "schema constructor builds untyped `data`"));
        }
    }
    let mut implicit = Vec::new();
    for (start, end) in acp_error_fn_bodies(&code) {
        for q in start..end {
            if code[q] != '?' {
                continue;
            }
            // `?Sized` is a bound, not the operator
            if code[q + 1..end.min(q + 8)]
                .iter()
                .collect::<String>()
                .trim_start()
                .starts_with("Sized")
            {
                continue;
            }
            if let Some(source) = implicit_conversion_source(&try_chain(&code, q)) {
                implicit.push(site(
                    q,
                    &format!("`?` converts {source} implicitly into a bare-string `data`"),
                ));
            }
        }
    }
    found.extend(implicit);
    found
}

#[test]
fn every_acp_error_data_in_shell_source_comes_from_a_typed_helper() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources(&root, &root, &mut files);
    assert!(files.len() > 100, "scan found only {} files", files.len());
    let mut all = Vec::new();
    for (rel, path) in files {
        let src = std::fs::read_to_string(&path).expect("read source");
        all.extend(offenders(&rel, &src));
    }
    assert!(
        all.is_empty(),
        "{} acp::Error data site(s) bypass the typed helpers (use crate::acp_error):\n{}",
        all.len(),
        all.join("\n")
    );
}

/// Whatever the walker hands the guard must be readable as Rust text.
/// A non-UTF-8 file under `src/` (an AppleDouble `._*.rs` sibling from a macOS tar, say) used to
/// kill the suite inside `read_to_string(..).expect("read source")` with a message about the wrong
/// thing, masking whether the guard itself passed.
#[test]
fn the_walker_only_hands_the_guard_files_it_can_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    std::fs::write(root.join("real.rs"), "fn a() {}").expect("write real.rs");
    std::fs::write(root.join("._real.rs"), [0xffu8, 0xfe, 0x00]).expect("write sidecar");
    std::fs::write(root.join("blob.rs"), [0xffu8, 0xfe, 0x00]).expect("write blob");
    let mut files = Vec::new();
    rust_sources(root, root, &mut files);
    for (rel, path) in &files {
        assert!(
            std::fs::read_to_string(path).is_ok(),
            "the guard would die reading {rel}, not reporting on the thing it guards"
        );
    }
    assert_eq!(
        files
            .iter()
            .map(|(rel, _)| rel.as_str())
            .collect::<Vec<_>>(),
        ["real.rs"],
        "only readable Rust sources reach the guard"
    );
}

/// `?` inside a function returning `Result<_, acp::Error>` converts through the schema crate's
/// `From<serde_json::Error>` / `From<anyhow::Error>` impls, both of which put a BARE STRING in
/// `data` — the exact shape an embedding client drops. The scanner must notice those, and must not
/// flag a `?` that already went through `map_err` into a typed helper.
#[test]
fn the_scanner_flags_implicit_error_conversions_in_acp_returning_functions() {
    let src = r##"
type ExtResult = Result<acp::ExtResponse, acp::Error>;
async fn handle(args: &acp::ExtRequest) -> ExtResult {
    let req = serde_json::from_str::<Req>(args.params.get())?;
    let ok = parse_params_str::<Req>(args.params.get())?;
    let mapped = serde_json::from_str::<Req>(args.params.get())
        .map_err(crate::acp_error::invalid_params_from)?;
    let raw = serde_json::value::to_raw_value(&req)?;
    let ctx = do_io().context("reading the thing")?;
    Ok(acp::ExtResponse::new(raw))
}
fn plain(args: &str) -> anyhow::Result<u8> { serde_json::from_str(args)? }
"##;
    let found = offenders("x.rs", src);
    let lines: Vec<&str> = found
        .iter()
        .map(|f| f.split(": ").next().unwrap())
        .collect();
    assert_eq!(lines, ["x.rs:4", "x.rs:8", "x.rs:9"], "{found:#?}");
}

/// The scanner itself: literals, comments and test items are ignored; untyped and typed arguments are told apart.
#[test]
fn the_scanner_flags_untyped_data_and_ignores_literals_comments_and_tests() {
    let src = r##"
fn a() { let _ = acp::Error::internal_error().data("bare"); }
fn b() { let _ = acp::Error::internal_error().data(crate::acp_error::error_data(K, "ok")); }
fn c() { let _ = "not code .data(\"x\")"; let _ = r#"raw .data(y)"#; let _ = '"'; }
// acp::Error::internal_error().data("comment")
fn d<'a>(x: &'a str) { let _ = acp::Error::invalid_params()
    .data(format!("{x}")); }
fn e() { let _ = acp::Error::resource_not_found(Some("u".into())); }
#[cfg(test)]
mod tests { fn t() { let _ = acp::Error::internal_error().data("test only"); } }
"##;
    let found = offenders("x.rs", src);
    let lines: Vec<&str> = found
        .iter()
        .map(|f| f.split(": ").next().unwrap())
        .collect();
    assert_eq!(lines, ["x.rs:2", "x.rs:7", "x.rs:8"], "{found:#?}");
}
