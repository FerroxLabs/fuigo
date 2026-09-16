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
//! deleted. That enumeration was a one-time act, not a gate, so a second scan now covers the same shape from
//! the other end: collect every `fn .. -> anyhow::Result<..>` declared in the crate, then reject a call to one
//! under `?` inside an `acp::Error`-returning function (`crate_local_anyhow_try_sites`). It is WEAKER THAN
//! COMPILING AGAINST A STRIPPED SCHEMA CRATE -- it reads declarations textually, so it misses a helper whose
//! return type is spelled `Result<T>` behind `use anyhow::Result`, one reached as a method or a trait call, and
//! one declared in another crate. Keep new helpers of that shape out of `acp::Error`-returning functions.
//!
//! TODO(1.0.19): replace that scan with the durable check -- a CI job that builds the tree against a schema
//! crate with `impl From<anyhow::Error> for acp::Error` deleted and fails on the type errors, which is the
//! enumeration above, automated. Deferred out of 1.0.18 because it needs a patched vendored copy of the schema
//! crate and a new CI job, and this release ships days after a customer incident; the textual scan closes the
//! same hole for every shape the crate writes today.
//!
//! TODO(1.0.19), same root cause and the same vendored copy, so do them together: the schema crate's OTHER
//! implicit conversion, `impl From<serde_json::Error> for acp::Error`, also fires during request DECODE, before
//! any shell code runs. Malformed params on a core ACP method (`session/prompt`, `session/new`, `session/load`,
//! `session/set_mode`, `session/set_model`, `authenticate`) therefore answer `-32602` with a bare-string `data`
//! that no scan in this file can see, because the call site is in the schema crate. 1.0.17 answers identically,
//! so it is not a regression -- but `session/prompt` is sent every turn, and a content-block shape skew between
//! a client's ACP version and this build's lands there, which is the exact silence 1.0.18 exists to kill.
//! Fix: decode core requests through a wrapper that re-shapes the rejection into object `data` with
//! `error_kind: "invalid_request"`. 1.0.18 documents the shape instead (`15-agent-mode.md`, fourth note on the
//! class), because a decode wrapper reaches every core method days before a customer-incident release.
//!
//! A third way to reach a client with nothing readable is to build an error and give it NO `data` at all:
//! `acp::Error::method_not_found()` answers `data: null`, which a client that renders only object-shaped `data`
//! shows as a blank. Mutating `err.message` in place has the same effect and hides from both scans above,
//! because no `.data(` is ever written. The third scan rejects both: in non-test shell source an
//! `acp::Error::<ctor>(..)` must continue into `.data(..)` (or merely read `.code`), and `message` is never
//! assigned in place. Build the error with a `crate::acp_error` constructor instead.

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

/// A return type whose error is `anyhow::Error`, spelled so the text says so: `anyhow::Result<..>`
/// or `Result<.., anyhow::Error>`. A crate that imports `anyhow::Result` and writes a bare
/// `Result<T>` is indistinguishable from `std::result::Result` in text, and is not collected.
fn returns_anyhow_error(ret: &str) -> bool {
    let ret = ret.trim();
    ret.starts_with("anyhow::Result")
        || (ret.starts_with("Result<") && ret.contains("anyhow::Error"))
}

/// `(name, body start, body end)` of every function with a body whose return type satisfies `keep`.
/// The body of a kept function is not re-scanned for nested declarations: a `fn` nested inside one
/// belongs to the enclosing body, which the callers scan whole.
fn fn_decls(code: &[char], keep: impl Fn(&str) -> bool) -> Vec<(String, usize, usize)> {
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
        let name_start = j;
        while j < code.len() && is_ident(code[j]) {
            j += 1;
        }
        let name: String = code[name_start..j].iter().collect();
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
        if !keep(ret) {
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
        out.push((name, start, j.min(code.len())));
        from = j;
    }
    out
}

/// `(start, end)` of the body braces of every function whose error type is `acp::Error`.
fn acp_error_fn_bodies(code: &[char]) -> Vec<(usize, usize)> {
    fn_decls(code, returns_acp_error)
        .into_iter()
        .map(|(_, start, end)| (start, end))
        .collect()
}

/// The names of every `fn .. -> anyhow::Result<..>` declared in one file.
fn anyhow_returning_fn_names(src: &str) -> Vec<String> {
    let mut code = code_only(src);
    strip_cfg_test_items(&mut code);
    fn_decls(&code, returns_anyhow_error)
        .into_iter()
        .map(|(name, _, _)| name)
        .collect()
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

/// A `?` applied to a call to one of `helpers` -- crate-local functions returning `anyhow::Result` --
/// inside a function whose error type is `acp::Error`. The schema crate's `From<anyhow::Error>` is
/// `into_internal_error`, which puts a BARE STRING in `data`, and the call names no error type, so the
/// `implicit_conversion_source` scan above cannot see it. Map it through `crate::acp_error` instead.
///
/// This gate is WEAKER THAN COMPILING AGAINST A STRIPPED SCHEMA CRATE (the one-off enumeration that
/// found the sites this branch fixed: build the tree with `impl From<anyhow::Error> for acp::Error`
/// deleted and read the type errors). It sees only helpers DECLARED in this crate, only where the
/// declaration spells `anyhow::Result` / `Result<.., anyhow::Error>`, and only where the `?` is applied
/// to a direct call by name -- not to a method on a value, a trait method, or a helper from another
/// crate. It is a real gate in the pattern already here; the durable replacement is a 1.0.19 item
/// (see the module header).
fn crate_local_anyhow_try_sites(rel: &str, src: &str, helpers: &[String]) -> Vec<String> {
    let mut code = code_only(src);
    strip_cfg_test_items(&mut code);
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    for (start, end) in acp_error_fn_bodies(&code) {
        for q in start..end {
            if code[q] != '?' {
                continue;
            }
            if code[q + 1..end.min(q + 8)]
                .iter()
                .collect::<String>()
                .trim_start()
                .starts_with("Sized")
            {
                continue;
            }
            let chain = try_chain(&code, q);
            // A chain that already went through `map_err` produced an `acp::Error` itself
            if chain.contains(".map_err(") {
                continue;
            }
            let Some(helper) = helpers.iter().find(|h| calls_by_name(&chain, h)) else {
                continue;
            };
            let line = line_of(&code, q);
            out.push(format!(
                "{rel}:{line}: `?` on the crate-local `anyhow::Result` helper `{helper}` converts \
                 implicitly into a bare-string `data`: {}",
                lines.get(line - 1).map(|l| l.trim()).unwrap_or("")
            ));
        }
    }
    out
}

/// Does `chain` call `name` as a function -- the whole identifier, followed by `(` or a turbofish?
/// `foo(..)`, `crate::x::foo(..)` and `self.foo(..)` all count; `foobar(..)` and `NAME_FOO` do not.
fn calls_by_name(chain: &str, name: &str) -> bool {
    let bytes: Vec<char> = chain.chars().collect();
    let needle: Vec<char> = name.chars().collect();
    if needle.is_empty() {
        return false;
    }
    (0..bytes.len().saturating_sub(needle.len() - 1)).any(|i| {
        if !bytes[i..].starts_with(&needle) {
            return false;
        }
        if i > 0 && is_ident(bytes[i - 1]) {
            return false;
        }
        let after: String = bytes[i + needle.len()..].iter().collect();
        let after = after.trim_start();
        after.starts_with('(') || after.starts_with("::<")
    })
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
    let mut banned_sites = Vec::new();
    for banned in ["into_internal_error(", "resource_not_found(Some"] {
        let mut from = 0;
        while let Some(pos) = find(&code, banned, from) {
            from = pos + banned.len();
            banned_sites.push(pos);
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
    // Third scan: an `acp::Error` that is built and never given `data`. Every `crate::acp_error`
    // constructor takes the message and builds the typed object, so a bare schema-crate constructor
    // here means the reply goes out as `data: null` — nothing for a JSON client to render.
    // `acp_error.rs` is where the typed constructors wrap the bare ones, so it is the one exemption.
    if !rel.ends_with("acp_error.rs") {
        let ctor = "acp::Error::";
        let mut from = 0;
        while let Some(pos) = find(&code, ctor, from) {
            from = pos + ctor.len();
            let mut j = from;
            while j < code.len() && is_ident(code[j]) {
                j += 1;
            }
            // Only a call builds an error; a bare path (a `use`, an associated constant) does not
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
            while j < code.len() && code[j].is_whitespace() {
                j += 1;
            }
            let tail: String = code[j..code.len().min(j + ".data(".len())].iter().collect();
            // `.data(..)` is the first scan's business; `.code` only reads the JSON-RPC class back
            if tail.starts_with(".data(") || tail.starts_with(".code") {
                continue;
            }
            // Already named by the banned-constructor scan above; one site, one reason
            if banned_sites.contains(&from) {
                continue;
            }
            // `crate::acp_error::typed(acp::Error::x(), ..)` hands the bare error straight to a typed helper
            let mut k = pos;
            while k > 0 && code[k - 1].is_whitespace() {
                k -= 1;
            }
            let typed_call = "typed(";
            if k >= typed_call.len()
                && code[k - typed_call.len()..k].iter().collect::<String>() == typed_call
            {
                continue;
            }
            found.push(site(pos, "`acp::Error` built with no typed `data`"));
        }
    }
    // `err.message = ..` sets the message in place, so the error keeps `data: null` and neither scan
    // above has a `.data(` to look at. (`fuigo-shell` has no other type with a writable `message`.)
    let mut from = 0;
    while let Some(pos) = find(&code, ".message", from) {
        from = pos + ".message".len();
        let mut j = from;
        while j < code.len() && code[j].is_whitespace() {
            j += 1;
        }
        // `=` alone is the assignment; `==` is a comparison and `=>` is a match arm after one
        let next = code.get(j + 1);
        if code.get(j) == Some(&'=') && next != Some(&'=') && next != Some(&'>') {
            found.push(site(
                pos,
                "`message` assigned in place, so the error keeps untyped `data`",
            ));
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

/// A-R7-2: the `?`-conversion blind spot, closed with the gate that is achievable now.
/// `?` on a crate-local helper that returns `anyhow::Result` names no error type, so
/// `implicit_conversion_source` cannot see it, yet it ships a bare-string `data` exactly like an
/// inline `anyhow!`. The scan collects the helpers by declaration and flags the calls.
#[test]
fn the_anyhow_helper_scan_sees_a_call_the_named_type_scan_cannot() {
    let src = concat!(
        "fn load_thing(p: &str) -> anyhow::Result<String> { Ok(p.to_owned()) }\n",
        "fn boxed(p: &str) -> Result<String, anyhow::Error> { Ok(p.to_owned()) }\n",
        "fn io_thing(p: &str) -> Result<String, std::io::Error> { Ok(p.to_owned()) }\n",
        "async fn handler(p: &str) -> ExtResult { let v = load_thing(p)?; io_thing(p)?; Ok(v) }\n",
        "fn two(p: &str) -> AcpResult<String> { Ok(boxed(p)?) }\n",
        "fn mapped(p: &str) -> ExtResult { Ok(load_thing(p).map_err(crate::acp_error::internal_from)?) }\n",
        "fn plain(p: &str) -> anyhow::Result<String> { load_thing(p) }\n",
        "fn similar(p: &str) -> ExtResult { Ok(load_thing_else(p)?) }\n",
    );
    assert_eq!(
        anyhow_returning_fn_names(src),
        ["load_thing", "boxed", "plain"],
        "the helpers are collected by the spelling of their declared return type"
    );
    let helpers = anyhow_returning_fn_names(src);
    let found = crate_local_anyhow_try_sites("x.rs", src, &helpers);
    assert_eq!(found.len(), 2, "{found:#?}");
    assert!(
        found[0].contains("x.rs:4") && found[0].contains("`load_thing`"),
        "{found:#?}"
    );
    assert!(
        found[1].contains("x.rs:5") && found[1].contains("`boxed`"),
        "{found:#?}"
    );
    assert!(
        offenders("x.rs", src).is_empty(),
        "the named-type scan is blind to these, which is why this one exists: {:#?}",
        offenders("x.rs", src)
    );
}

/// No `acp::Error`-returning function in the shell hands `?` a crate-local `anyhow::Result` helper.
/// The scan is proved live on real sources in the same test, by mutation: a call injected into a real
/// `acp::Error`-returning body is found.
#[test]
fn no_acp_returning_function_swallows_a_crate_local_anyhow_helper() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources(&root, &root, &mut files);
    let sources: Vec<(String, String)> = files
        .iter()
        .filter_map(|(rel, path)| {
            std::fs::read_to_string(path)
                .ok()
                .map(|src| (rel.clone(), src))
        })
        .collect();
    let mut helpers: Vec<String> = Vec::new();
    for (_, src) in &sources {
        helpers.extend(anyhow_returning_fn_names(src));
    }
    helpers.sort();
    helpers.dedup();
    assert!(
        helpers.len() > 20,
        "the scan collected only {} `anyhow::Result` helpers, so it is watching nothing",
        helpers.len()
    );
    let mut found: Vec<String> = Vec::new();
    for (rel, src) in &sources {
        found.extend(crate_local_anyhow_try_sites(rel, src, &helpers));
    }
    assert!(
        found.is_empty(),
        "{} site(s) let `?` convert a crate-local `anyhow::Result` helper into a bare-string `data`; \
         map it through `crate::acp_error::internal_from` instead:\n{}",
        found.len(),
        found.join("\n")
    );
    // Live on real sources: inject a call to a real helper at the top of a real acp-returning body.
    let helper = helpers.first().expect("the crate declares anyhow helpers");
    let (rel, src, at) = sources
        .iter()
        .find_map(|(rel, src)| {
            let mut code = code_only(src);
            strip_cfg_test_items(&mut code);
            acp_error_fn_bodies(&code)
                .first()
                .map(|&(start, _)| (rel.clone(), src.clone(), start))
        })
        .expect("the shell has `acp::Error`-returning functions");
    let mut chars: Vec<char> = src.chars().collect();
    let injected: Vec<char> = format!(" let _injected = {helper}()?;").chars().collect();
    chars.splice(at + 1..at + 1, injected);
    let mutated: String = chars.into_iter().collect();
    assert!(
        !crate_local_anyhow_try_sites(&rel, &mutated, &helpers).is_empty(),
        "the scan must find a crate-local anyhow helper called under `?` in {rel}"
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

/// An `acp::Error` with no `data` at all reaches a client as `data: null`, which is exactly as blank as
/// a bare string — the class this release exists to kill. The scanner must see a constructor that never
/// continues into `.data(..)`, and the in-place `err.message = ..` shape that writes no `.data(` anywhere.
#[test]
fn the_scanner_flags_errors_built_without_any_data() {
    let src = r##"
fn a() -> Result<(), acp::Error> { Err(acp::Error::method_not_found()) }
fn b() -> Result<(), acp::Error> { Err(crate::acp_error::method_not_found("no such method")) }
fn c() -> Result<(), acp::Error> { Err(acp::Error::internal_error().data(crate::acp_error::error_data(K, "ok"))) }
fn d(e: &E) -> acp::Error { let mut err = acp::Error::auth_required(); err.message = e.to_string(); err }
fn f(e: &acp::Error) -> bool { e.code == acp::Error::method_not_found().code }
fn g() -> acp::Error { crate::acp_error::typed(acp::Error::internal_error(), K, "ok") }
fn h(e: &acp::Error, d: &str) -> String { match Some(d) { Some(detail) if detail == e.message => detail.into(), _ => String::new() } }
"##;
    let found = offenders("x.rs", src);
    let lines: Vec<&str> = found
        .iter()
        .map(|f| f.split(": ").next().unwrap())
        .collect();
    // line 2: the bare constructor; line 5 twice: the constructor and the in-place message write
    assert_eq!(lines, ["x.rs:2", "x.rs:5", "x.rs:5"], "{found:#?}");
}

/// The `?`-boundary conversions also changed a JSON-RPC class on the wire: a failure to serialize the
/// agent's OWN data used to reach the client as `-32602 invalid params` through the schema crate's
/// `From<serde_json::Error>`, and now answers `-32603 internal`. 15-agent-mode.md publishes a code table
/// for third-party client authors, so every site that flipped has to be named there. An incomplete record
/// of a wire change is the same class of defect as an error reply a client cannot read.
///
/// The scan used to recognise one literal spelling (`map_err(crate::acp_error::internal_from)`) and to
/// check only that each site's FILE appeared somewhere in the guide. A flip written any other way --
/// a shorter path, an imported name, an explicit closure -- was invisible to it, and a sixth flip added
/// to a file the guide already named passed unnoticed. It now recognises the conversion by name however
/// it is spelled, and holds the guide to the per-file COUNT it publishes.
///
/// The conversion is recognised, not the `serde_json` call: a `serde_json` value in the statement that
/// ends at the conversion is what tells a serialization failure (`-32602` before 1.0.18) apart from an
/// `anyhow` one (`into_internal_error`, `-32603` all along -- `extensions/git.rs` is that case).
fn serialization_flips_in(rel: &str, src: &str) -> Vec<String> {
    const NEEDLE: &str = "internal_from";
    let mut code = code_only(src);
    strip_cfg_test_items(&mut code);
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = find(&code, NEEDLE, from) {
        from = pos + NEEDLE.len();
        if pos > 0 && is_ident(code[pos - 1]) {
            continue;
        }
        if code.get(pos + NEEDLE.len()).is_some_and(|&c| is_ident(c)) {
            continue;
        }
        if declares_the_helper(&code, pos) {
            continue;
        }
        if statement_ending_at(&code, pos).contains("serde_json") {
            out.push(format!("{rel}:{}", line_of(&code, pos)));
        }
    }
    out
}

/// `fn internal_from(..)` -- the declaration of the conversion, not a use of it.
fn declares_the_helper(code: &[char], pos: usize) -> bool {
    let mut i = pos;
    while i > 0 && code[i - 1].is_whitespace() {
        i -= 1;
    }
    i >= 2 && code[i - 2] == 'f' && code[i - 1] == 'n' && (i == 2 || !is_ident(code[i - 3]))
}

/// The text of the statement that ends at `pos`: back to the nearest `;`, `{` or `}`, capped so a
/// file-length scan back can never make the check quadratic.
fn statement_ending_at(code: &[char], pos: usize) -> String {
    let floor = pos.saturating_sub(600);
    let mut begin = floor;
    for i in (floor..pos).rev() {
        if matches!(code[i], ';' | '{' | '}') {
            begin = i + 1;
            break;
        }
    }
    code[begin..pos].iter().collect()
}

/// How the guide spells a count of replies.
const COUNT_WORDS: [&str; 10] = [
    "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
];

/// Every way 15-agent-mode.md can be out of step with the sites the scan found: a file it does not
/// name at all, or a file whose published count of changed replies is not the count in the tree.
fn guide_gaps(sites: &[String], guide: &str) -> Vec<String> {
    let mut per_file: Vec<(String, usize)> = Vec::new();
    for site in sites {
        let file = site.split(':').next().unwrap_or_default().to_owned();
        match per_file.iter_mut().find(|(f, _)| *f == file) {
            Some((_, n)) => *n += 1,
            None => per_file.push((file, 1)),
        }
    }
    let mut gaps = Vec::new();
    for (file, count) in &per_file {
        let Some(at) = guide.find(file.as_str()) else {
            gaps.push(format!(
                "{file}: {count} repl(y/ies) changed class, and the guide does not name the file"
            ));
            continue;
        };
        // by chars, so a window that lands mid-codepoint cannot panic the guard
        let window: String = guide[at + file.len()..].chars().take(80).collect();
        let Some(word) = COUNT_WORDS.get(count - 1) else {
            // the guide spells counts in words, so a file with more than ten flips needs a new form
            gaps.push(format!(
                "{file}: {count} sites is past what the guide spells in words"
            ));
            continue;
        };
        if !window.contains(&format!("{word} site")) {
            gaps.push(format!(
                "{file}: {count} sites in the tree, but the guide says `{}`",
                window.replace('\n', " ")
            ));
        }
    }
    let total = sites.len();
    let files = per_file.len();
    let word_for = |n: usize| n.checked_sub(1).and_then(|i| COUNT_WORDS.get(i));
    if let (Some(t), Some(f)) = (word_for(total), word_for(files)) {
        let sentence = format!("{t} replies changed class, in {f} file");
        if !guide.to_lowercase().contains(&sentence) {
            gaps.push(format!(
                "the guide's summary does not say `{sentence}s`, which is what the tree holds"
            ));
        }
    }
    gaps
}

/// The conversion is recognised however it is written, not only as the one literal the round-5 scan knew.
#[test]
fn the_flip_scan_sees_every_spelling_of_the_conversion() {
    let src = concat!(
        "fn a() -> ExtResult { Ok(serde_json::value::to_raw_value(&r).map_err(crate::acp_error::internal_from)?) }\n",
        "fn b() -> ExtResult { Ok(serde_json::to_value(&r).map_err(acp_error::internal_from)?) }\n",
        "fn c() -> ExtResult { Ok(serde_json::to_value(&r).map_err(internal_from)?) }\n",
        "fn d() -> ExtResult { Ok(serde_json::to_vec(&r)\n",
        "    .map_err(|e| crate::acp_error::internal_from(e))?) }\n",
        "fn e() -> ExtResult { Ok(run().await.map_err(crate::acp_error::internal_from)?) }\n",
        "fn f() { let _ = \"serde_json .map_err(internal_from)\"; }\n",
        // deliberately not valid Rust: the shape that puts a `serde_json` value in front of the
        // DECLARATION of the conversion, which is the one occurrence of the name that is not a use.
        "let v = serde_json::to_value(&r) pub fn internal_from(e: E) -> acp::Error\n",
    );
    assert_eq!(
        serialization_flips_in("x.rs", src),
        ["x.rs:1", "x.rs:2", "x.rs:3", "x.rs:5"],
        "every spelling of the serialization conversion is a flip; an `anyhow` one (line 6), a string \
         literal (line 7) and the declaration itself (line 8) are not"
    );
}

/// The guide publishes a count per file, so the check has to hold it to the count -- naming the file
/// is not enough once a sixth reply flips inside a file the guide already mentions.
#[test]
fn the_guide_check_bites_on_the_site_count_not_just_the_file_name() {
    let sites: Vec<String> = ["a.rs:1", "a.rs:2", "b.rs:9"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let good = "a.rs`, two sites) and b.rs`, one site). three replies changed class, in two files.";
    assert!(
        guide_gaps(&sites, good).is_empty(),
        "{:?}",
        guide_gaps(&sites, good)
    );
    let stale = "a.rs`, one site) and b.rs`, one site). two replies changed class, in two files.";
    let gaps = guide_gaps(&sites, stale);
    assert_eq!(gaps.len(), 2, "{gaps:#?}");
    assert!(gaps[0].contains("a.rs: 2 sites in the tree"), "{gaps:#?}");
    assert!(
        gaps[1].contains("three replies changed class, in two files"),
        "{gaps:#?}"
    );
    let unnamed = "b.rs`, one site). one replies changed class, in one files.";
    assert!(
        guide_gaps(&sites, unnamed)
            .iter()
            .any(|g| g.contains("a.rs") && g.contains("does not name the file")),
        "{:#?}",
        guide_gaps(&sites, unnamed)
    );
}

#[test]
fn every_serialization_code_flip_is_named_in_the_agent_mode_guide() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources(&root, &root, &mut files);
    let mut flipped: Vec<String> = Vec::new();
    for (rel, path) in files {
        let Ok(src) = std::fs::read_to_string(&path) else {
            continue;
        };
        flipped.extend(serialization_flips_in(&rel, &src));
    }
    assert!(
        flipped.len() >= 5,
        "the scan lost sight of the conversions it checks: {flipped:?}"
    );
    let doc = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fuigo-pager/docs/user-guide/15-agent-mode.md");
    let guide = std::fs::read_to_string(&doc).expect("read 15-agent-mode.md");
    let gaps = guide_gaps(&flipped, &guide);
    assert!(
        gaps.is_empty(),
        "15-agent-mode.md no longer records the replies that changed JSON-RPC class ({}):\n{}\nsites: {flipped:#?}",
        gaps.len(),
        gaps.join("\n")
    );
}

/// The two `-32601 data: null` replies the branch deliberately leaves alone are explained in the guide,
/// and the round-5 wire probe found the explanation incomplete: `session/cancel` is a notification-only
/// method, so sending it as a REQUEST also answers `-32601` with no `data`, and it is neither an unknown
/// method nor an extension call. A client author reading the old sentence would conclude their `-32601`
/// could not have come from a method we implement.
#[test]
fn the_guide_explains_every_reply_that_still_comes_back_without_data() {
    let doc = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fuigo-pager/docs/user-guide/15-agent-mode.md");
    let guide = std::fs::read_to_string(&doc).expect("read 15-agent-mode.md");
    let para = guide
        .split("\n\n")
        .find(|p| p.contains("`-32601 Method not found` with no `data`"))
        .expect("the guide explains the data-less -32601 replies");
    for expected in [
        "unknown top-level JSON-RPC method",
        "`session/cancel`",
        "notification",
    ] {
        assert!(
            para.contains(expected),
            "the data-less `-32601` explanation does not cover {expected}:\n{para}"
        );
    }
}

/// A-R7-4: the same login-failure fix moved the reason out of `message` and into `data.message`, leaving
/// `message` as the class name. For a client that reads only `message` -- on the one method every
/// embedding client calls on connect -- that is a reduction against shipped 1.0.17, so the published
/// guide records it beside the other class changes. `a_failed_login_answers_with_typed_data_not_a_bare_message`
/// pins the reply itself; this pins the record of it.
#[test]
fn the_guide_records_the_auth_required_message_change() {
    let doc = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fuigo-pager/docs/user-guide/15-agent-mode.md");
    let guide = std::fs::read_to_string(&doc).expect("read 15-agent-mode.md");
    let note = guide
        .split("\n\n")
        .find(|p| p.contains("a failed `authenticate`"))
        .expect("the guide records the `authenticate` reply change next to the other class notes");
    for expected in ["`data.message`", "Authentication required", "Before 1.0.18"] {
        assert!(
            note.contains(expected),
            "the `authenticate` note does not say {expected}:\n{note}"
        );
    }
}

/// The login-failure reply is the whole reason the third scan exists (A-R4-2), and the test that pins it
/// (`a_failed_login_answers_with_typed_data_not_a_bare_message`) pins the HELPER: re-inlining the pre-fix
/// `let mut err = acp::Error::auth_required(); err.message = e.to_string(); err` at the `authenticate`
/// call site would leave that test green. The guard is what has to bite there, so assert that it does --
/// on the real file, at the real call site, by putting the pre-fix shape back and running the scan.
#[test]
fn the_guard_bites_when_the_authenticate_call_site_re_inlines_its_error() {
    const CALL_SITE: &str = "auth_flow_error(&e)";
    let rel = "agent/mvp_agent/acp_agent.rs";
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(rel);
    let src = std::fs::read_to_string(&path).expect("read acp_agent.rs");
    assert_eq!(
        src.matches(CALL_SITE).count(),
        1,
        "`authenticate` must build its login failure through the typed helper, at one call site"
    );
    assert!(
        offenders(rel, &src).is_empty(),
        "the shipped file is clean before the mutation"
    );
    let re_inlined = src.replace(
        CALL_SITE,
        "{ let mut err = acp::Error::auth_required(); err.message = e.to_string(); err }",
    );
    let found = offenders(rel, &re_inlined);
    assert!(
        found
            .iter()
            .any(|f| f.contains("`acp::Error` built with no typed `data`")),
        "the guard must see the untyped constructor at the call site: {found:#?}"
    );
    assert!(
        found
            .iter()
            .any(|f| f.contains("`message` assigned in place")),
        "the guard must see the in-place message write at the call site: {found:#?}"
    );
}

/// The exemption is by file, so the typed constructors themselves may wrap the bare schema ones.
#[test]
fn the_no_data_scan_exempts_the_typed_constructor_module() {
    let src = "pub fn method_not_found(m: impl Into<String>) -> acp::Error { typed(acp::Error::method_not_found(), K, m) }\n";
    assert!(offenders("acp_error.rs", src).is_empty());
    assert_eq!(
        offenders("extensions/x.rs", src).len(),
        0,
        "the `typed(..)` argument is exempt everywhere"
    );
}

/// The body braces of the first `fn <name>` declared in `code`, or `None` when the file has no such
/// function. Used to scope an exemption to one function instead of a whole file.
fn fn_body_span(code: &[char], name: &str) -> Option<(usize, usize)> {
    let needle = format!("fn {name}");
    let mut from = 0;
    while let Some(pos) = find(code, &needle, from) {
        from = pos + needle.chars().count();
        if pos > 0 && is_ident(code[pos - 1]) {
            continue;
        }
        if code.get(from).is_some_and(|&c| is_ident(c)) {
            continue;
        }
        let mut j = from;
        while j < code.len() && code[j] != '{' && code[j] != ';' {
            j += 1;
        }
        // A trait method declaration has no body
        if code.get(j) != Some(&'{') {
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
                        return Some((start, j));
                    }
                }
                _ => {}
            }
            j += 1;
        }
        return Some((start, code.len()));
    }
    None
}

/// The one function allowed to read a whole `data` as a string: `error_detail_from_data`, which reads
/// both shapes so an error built by a pre-1.0.18 agent still yields its detail.
fn legacy_string_read_exemption(rel: &str, code: &[char]) -> Option<(usize, usize)> {
    (rel == "sampling/error.rs")
        .then(|| fn_body_span(code, "error_detail_from_data"))
        .flatten()
}

/// A fourth way a client-visible failure loses its reason, and the one the three scans above cannot
/// see: not building a bad `data`, but READING a good one as if it were the bare string it used to be.
/// `err.data.as_ref().and_then(|d| d.as_str())` yields `None` against every error the shell builds
/// since 1.0.18 typed `data` as an object, so the caller silently records its placeholder instead --
/// `<no error data>` in the compaction request artifact, `memory flush failed` in the memory-flush
/// outcome. Both were live defects on this branch until `9432302`.
///
/// Exactly one whole-value read in the tree is deliberate: `error_detail_from_data` in
/// `sampling/error.rs` accepts the pre-1.0.18 string shape on purpose, because a client may hand back
/// an error built by an agent older than 1.0.18. The exemption is THAT FUNCTION'S BODY, not the file:
/// `sampling/error.rs` also holds `acp_error_text`, `acp_error_message`, `error_kind_str_from_error`
/// and `http_status_from_error` -- the likeliest place a future whole-value read is added, and a
/// file-wide exemption made every one of them invisible to this scan forever.
fn string_shaped_data_reads(rel: &str, src: &str) -> Vec<String> {
    let mut code = code_only(src);
    strip_cfg_test_items(&mut code);
    let exempt = legacy_string_read_exemption(rel, &code);
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = find(&code, "data", from) {
        from = pos + 4;
        if pos > 0 && is_ident(code[pos - 1]) {
            continue;
        }
        if exempt.is_some_and(|(start, end)| pos > start && pos < end) {
            continue;
        }
        if code.get(pos + 4).is_some_and(|&c| is_ident(c)) {
            continue;
        }
        let end = (pos + 4 + 140).min(code.len());
        let tail: String = code[pos + 4..end].iter().collect();
        if reads_the_whole_value_as_a_string(&tail) {
            out.push(format!("{rel}:{}", line_of(&code, pos)));
        }
    }
    out
}

/// `tail` begins just after a `data` identifier. Does what follows turn the WHOLE value into a string?
/// `.as_str()` directly, or through a closure that does nothing else. Reading a FIELD as a string
/// (`.get("message").and_then(|v| v.as_str())`) is the correct shape and is not flagged.
fn reads_the_whole_value_as_a_string(tail: &str) -> bool {
    let compact: String = tail.chars().filter(|c| !c.is_whitespace()).collect();
    let mut rest = compact.as_str();
    loop {
        let hop = [".as_ref()", ".as_deref()", ".clone()", "?"]
            .into_iter()
            .find_map(|h| rest.strip_prefix(h));
        match hop {
            Some(next) => rest = next,
            None => break,
        }
    }
    if rest.starts_with(".as_str()") {
        return true;
    }
    [".and_then(|", ".map(|"].into_iter().any(|verb| {
        rest.strip_prefix(verb).is_some_and(|r| {
            r.split_once('|').is_some_and(|(bind, body)| {
                !bind.is_empty()
                    && bind.chars().all(is_ident)
                    && body.starts_with(&format!("{bind}.as_str()"))
            })
        })
    })
}

#[test]
fn the_string_data_scan_flags_a_whole_value_read_and_leaves_field_reads_alone() {
    let offending = concat!(
        "fn a(e: &acp::Error) -> String { e.data.as_ref().and_then(|d| d.as_str()).unwrap_or(\"x\").into() }\n",
        "fn b(e: &acp::Error) -> String { e\n",
        "    .data\n",
        "    .as_ref()\n",
        "    .and_then(|d| d.as_str())\n",
        "    .unwrap_or(\"<no error data>\")\n",
        "    .to_owned() }\n",
        "fn c(v: &serde_json::Value) -> Option<&str> { v.data.as_str() }\n",
    );
    assert_eq!(
        string_shaped_data_reads("x.rs", offending),
        ["x.rs:1", "x.rs:3", "x.rs:8"],
        "every read of a whole `data` as a string is flagged, wherever the chain is broken across lines"
    );
    let fine = concat!(
        "fn d(data: &serde_json::Value) -> Option<&str> { data.get(\"message\").and_then(|v| v.as_str()) }\n",
        "fn e(e: &acp::Error) -> bool { e.data.as_ref().is_some_and(|d| d.is_object()) }\n",
        "fn f() { let _ = \"e.data.as_ref().and_then(|d| d.as_str())\"; }\n",
        "fn g(metadata: &str) -> &str { metadata }\n",
    );
    assert!(
        string_shaped_data_reads("x.rs", fine).is_empty(),
        "{:#?}",
        string_shaped_data_reads("x.rs", fine)
    );
    let in_error_rs: Vec<String> = string_shaped_data_reads("sampling/error.rs", offending);
    assert_eq!(
        in_error_rs,
        [
            "sampling/error.rs:1",
            "sampling/error.rs:3",
            "sampling/error.rs:8"
        ],
        "the module that reads both shapes is not exempt wholesale"
    );
    let deliberate = concat!(
        "pub fn error_detail_from_data(data: &serde_json::Value) -> Option<String> {\n",
        "    if let Some(s) = data.as_str() {\n",
        "        return Some(s.to_owned());\n",
        "    }\n",
        "    None\n",
        "}\n",
        "fn later(e: &acp::Error) -> Option<&str> { e.data.as_ref().and_then(|d| d.as_str()) }\n",
    );
    assert_eq!(
        string_shaped_data_reads("sampling/error.rs", deliberate),
        ["sampling/error.rs:7"],
        "the exemption is the body of `error_detail_from_data`, not the file around it"
    );
    assert_eq!(
        string_shaped_data_reads("x.rs", deliberate).len(),
        2,
        "the exemption is keyed to the one module that owns the compatibility read"
    );
}

/// A-R7-1: the exemption used to be the whole FILE, so every read in `sampling/error.rs` -- the module
/// that holds `acp_error_text`, `acp_error_message`, `error_kind_str_from_error` and
/// `http_status_from_error`, the likeliest place a whole-value read is added next -- was invisible to
/// the guard forever. Prove the scoped exemption by mutation, on the real file: the deliberate read
/// stays exempt (the shipped file is clean) and a read added ANYWHERE ELSE in the module is seen.
#[test]
fn the_string_data_scan_sees_a_whole_value_read_elsewhere_in_the_error_module() {
    let rel = "sampling/error.rs";
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(rel);
    let src = std::fs::read_to_string(&path).expect("read error.rs");
    assert!(
        src.contains("pub fn error_detail_from_data("),
        "the exemption names a function this module must still declare"
    );
    assert!(
        string_shaped_data_reads(rel, &src).is_empty(),
        "the shipped module is clean: its one whole-value read is the deliberate compatibility read, \
         and it is inside `error_detail_from_data`"
    );
    const ANCHOR: &str = "pub fn http_status_from_error(err: &acp::Error) -> Option<u16> {";
    assert_eq!(
        src.matches(ANCHOR).count(),
        1,
        "the mutation needs one anchor outside the exempt function"
    );
    let mutated = src.replace(
        ANCHOR,
        &format!("{ANCHOR}\n    let _legacy = err.data.as_ref().and_then(|d| d.as_str());"),
    );
    assert!(
        !string_shaped_data_reads(rel, &mutated).is_empty(),
        "a whole-value read added outside `error_detail_from_data` must be flagged, in this module \
         like in every other"
    );
}

#[test]
fn no_shell_source_reads_an_error_data_as_a_bare_string() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources(&root, &root, &mut files);
    let mut found: Vec<String> = Vec::new();
    for (rel, path) in files {
        let Ok(src) = std::fs::read_to_string(&path) else {
            continue;
        };
        found.extend(string_shaped_data_reads(&rel, &src));
    }
    assert!(
        found.is_empty(),
        "{} site(s) read an `acp::Error`'s `data` as a bare string, a shape nothing has carried since \
         1.0.18; read `data.message` (`crate::sampling::error::acp_error_message`) instead:\n{}",
        found.len(),
        found.join("\n")
    );
}

/// `compaction_artifact_error_text` is a one-line pass-through that exists only to make the read
/// unit-testable, so `artifact_error_text_tests` pins the HELPER: re-inlining the pre-fix
/// `e.data.as_ref().and_then(|d| d.as_str()).unwrap_or("<no error data>")` at the call site would leave
/// every one of those tests green while the artifact went back to recording `<no error data>` for every
/// failure. Same blind spot A-R5-3 closed for `authenticate`; close it the same way, at the real call
/// site, on the real file.
#[test]
fn the_guard_bites_when_the_compaction_artifact_call_site_re_inlines_its_read() {
    const CALL_SITE: &str = "let error_str = error.map(compaction_artifact_error_text);";
    let rel = "session/compaction.rs";
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(rel);
    let src = std::fs::read_to_string(&path).expect("read compaction.rs");
    assert_eq!(
        src.matches(CALL_SITE).count(),
        1,
        "the compaction request artifact must take its failure text from the typed read, at one call site"
    );
    assert!(
        string_shaped_data_reads(rel, &src).is_empty(),
        "the shipped file is clean before the mutation"
    );
    let re_inlined = src.replace(
        CALL_SITE,
        "let error_str = error.map(|e| e.data.as_ref().and_then(|d| d.as_str()).unwrap_or(\"<no error data>\").to_owned());",
    );
    assert!(
        !string_shaped_data_reads(rel, &re_inlined).is_empty(),
        "the guard must see the bare-string read put back at the call site"
    );
}

/// `memory_flush_error_detail` has the same shape and the same blind spot, and a wider blast radius
/// than the commit that introduced it recorded: the `detail` it returns is not only the `warn` line.
/// It is formatted into `skipped: {detail}`, which becomes the `outcome` sent to the client as
/// `FuigoSessionUpdate::MemoryFlushCompleted { result }` on `_fuigo/session_notification`, and printed
/// in headless JSON output as `AcpLine::MemoryFlushCompleted`. A placeholder there is a client-visible
/// failure with no reason in it, not a thin log line -- so pin the call site AND the path from the
/// detail to the notification.
#[test]
fn the_guard_bites_when_the_memory_flush_call_site_re_inlines_its_read() {
    const CALL_SITE: &str = "let detail = memory_flush_error_detail(&e);";
    let rel = "session/acp_session_impl/memory_dream.rs";
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(rel);
    let src = std::fs::read_to_string(&path).expect("read memory_dream.rs");
    assert_eq!(
        src.matches(CALL_SITE).count(),
        1,
        "the skipped-flush record must take its reason from the typed read, at one call site"
    );
    assert!(
        src.contains("(format!(\"skipped: {detail}\")"),
        "the detail this call site reads is what the client is told, so the two must stay wired together"
    );
    assert!(
        src.contains("FuigoSessionUpdate::MemoryFlushCompleted {")
            && src.contains("result: outcome,"),
        "`outcome` -- the `skipped: {{detail}}` string -- is what goes out on `_fuigo/session_notification`"
    );
    assert!(
        string_shaped_data_reads(rel, &src).is_empty(),
        "the shipped file is clean before the mutation"
    );
    let re_inlined = src.replace(
        CALL_SITE,
        "let detail = e.data.as_ref().and_then(|d| d.as_str()).unwrap_or(\"memory flush failed\");",
    );
    assert!(
        !string_shaped_data_reads(rel, &re_inlined).is_empty(),
        "the guard must see the bare-string read put back at the call site"
    );
}
