//! Guard: a test that mutates the process-global theme state must hold the shared theme test lock.
//!
//! The theme (`theme::cache`), the terminal-native lock, the rollout gate and the color level are process globals.
//! A test that writes them without [`crate::theme::cache::pin_theme`] (or the `with_test_env` helpers that hold `test_lock`) races every pinned test: it flips the theme mid-assertion, which shows up as a flake under load, not as a failure.
//! This scans the test code of `fuigo-pager`, `fuigo-pager-render` and `fuigo-pager-minimal` and fails when a test-side `fn` calls a theme mutator without taking the lock.
//!
//! Test-side means: a `fn` carrying `#[test]`, or any `fn` in a test file (`tests.rs`, `*_tests.rs`, a `tests/` directory), or any `fn` inside a `#[cfg(test)] mod` block (any visibility).
//! Comments and string literals are blanked before matching, so a `// pin_theme()` note neither grants nor revokes the lock.
//!
//! A helper `fn` that mutates but whose every caller already holds the lock opts out with a `// theme-pin: caller holds` comment on or just above the `fn`.
//!
//! Known limits of this source scan: it does not see a bare imported `set(kind)` whose argument is not a `ThemeKind::` literal, nor a mutation hidden inside a product helper (such as `apply_screen_mode_globals`) that a test calls; those tests must hold the pin by convention.
//!
//! Reading is the other half: a test that only READS the theme but asserts exact colors races every lock-holding mutator.
//! Readers cannot be found by a call scan, so the ones seen failing under load are listed in [`PINNED_READERS`] and must hold the lock.
//!
//! It also guards the shared temp dir: no fixed file name under `std::env::temp_dir()` (see [`fixed_temp_names`]).
//!
//! The same scan also guards the dashboard flag: `dashboard_enabled()` reads the `FUIGO_AGENT_DASHBOARD` env var, which sibling tests set to `0`, so a `#[test]` that opens the dashboard must be `#[serial_test::serial(FUIGO_AGENT_DASHBOARD)]` or it sees the dashboard disabled whenever one of them is mid-test.

use std::path::{Path, PathBuf};

/// Calls that write process-global theme state. Matched against whitespace-stripped code, so a rustfmt line break cannot hide one.
/// A directly imported bare `set(ThemeKind::..)` is matched separately by [`has_bare_set`] (an instance `cell.set(..)` is not a global write).
const MUTATORS: &[&str] = &[
    "cache::set(",
    "cache::set_auto_mode(",
    "cache::set_terminal_native_lock(",
    "cache::set_terminal_theme_enabled(",
    "cache::reset_for_test(",
    "cache::seed_auto_theme_defaults_for_test(",
    "reset_for_test(",
    "set_terminal_native_lock(",
    "set_terminal_theme_enabled(",
    "set_level_for_test(",
    "set_auto_mode(",
    "apply_kind(",
    "dispatch(Action::SetTheme(",
    "dispatch(Action::PreviewTheme(",
    "dispatch(Action::SetAutoDarkTheme(",
    "dispatch(Action::SetAutoLightTheme(",
];

/// Anything in a `fn` that proves it holds the shared lock for its whole body.
const LOCKS: &[&str] = &[
    "pin_theme(",
    "test_lock()",
    "with_test_env(",
    "with_theme_test_env(",
];

const OPT_OUT: &str = "theme-pin:";

#[derive(Debug, PartialEq, Eq)]
struct Violation {
    line: usize,
    name: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Code,
    Comment,
    Literal,
}

/// Classify every char of `src` as code, comment, or string/char literal.
/// Handles nested block comments, raw strings (`r"`, `r#"`, `br#"`), escaped quotes and char literals versus lifetimes.
fn classify(c: &[char]) -> Vec<Class> {
    let mut class = vec![Class::Code; c.len()];
    let ident = |ch: char| ch.is_alphanumeric() || ch == '_';
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            '/' if c.get(i + 1) == Some(&'/') => {
                while i < c.len() && c[i] != '\n' {
                    class[i] = Class::Comment;
                    i += 1;
                }
            }
            '/' if c.get(i + 1) == Some(&'*') => {
                let mut depth = 0;
                while i < c.len() {
                    if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                        depth += 1;
                        class[i] = Class::Comment;
                        class[i + 1] = Class::Comment;
                        i += 2;
                    } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                        depth -= 1;
                        class[i] = Class::Comment;
                        class[i + 1] = Class::Comment;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        class[i] = Class::Comment;
                        i += 1;
                    }
                }
            }
            'r' if matches!(c.get(i + 1).copied(), Some('"' | '#'))
                && (i == 0
                    || !ident(c[i - 1])
                    || (c[i - 1] == 'b' && (i < 2 || !ident(c[i - 2])))) =>
            {
                // Raw string r"..." / r#"..."# (also br"..." / br#"..."#).
                let mut j = i + 1;
                let mut hashes = 0;
                while c.get(j) == Some(&'#') {
                    hashes += 1;
                    j += 1;
                }
                if c.get(j) != Some(&'"') {
                    i += 1;
                    continue;
                }
                j += 1;
                while j < c.len() {
                    if c[j] == '"' && (0..hashes).all(|h| c.get(j + 1 + h) == Some(&'#')) {
                        j += 1 + hashes;
                        break;
                    }
                    j += 1;
                }
                for slot in &mut class[i..j.min(c.len())] {
                    *slot = Class::Literal;
                }
                i = j;
            }
            '"' => {
                class[i] = Class::Literal;
                i += 1;
                while i < c.len() && c[i] != '"' {
                    if c[i] == '\\' && i + 1 < c.len() {
                        class[i] = Class::Literal;
                        i += 1;
                    }
                    class[i] = Class::Literal;
                    i += 1;
                }
                if i < c.len() {
                    class[i] = Class::Literal;
                    i += 1;
                }
            }
            '\'' => {
                // A char literal ('x' or '\n' / '\'') versus a lifetime ('a).
                let end = if c.get(i + 1) == Some(&'\\') {
                    (i + 3..c.len().min(i + 12)).find(|&k| c[k] == '\'')
                } else if c.get(i + 2) == Some(&'\'') {
                    Some(i + 2)
                } else {
                    None
                };
                match end {
                    Some(e) => {
                        for slot in &mut class[i..=e] {
                            *slot = Class::Literal;
                        }
                        i = e + 1;
                    }
                    None => i += 1,
                }
            }
            _ => i += 1,
        }
    }
    class
}

/// `src` with everything of class `keep` preserved and every other char blanked (newlines always kept), so line numbers and columns survive.
fn view(src: &str, keep: Class) -> String {
    let c: Vec<char> = src.chars().collect();
    let class = classify(&c);
    c.iter()
        .zip(&class)
        .map(|(&ch, &cl)| if ch == '\n' || cl == keep { ch } else { ' ' })
        .collect()
}

/// Comments and string literals blanked: what is left is code.
fn blank_non_code(src: &str) -> String {
    view(src, Class::Code)
}

/// Only comment text kept (an exemption marker must be a real comment, not a string).
fn comments_only(src: &str) -> String {
    view(src, Class::Comment)
}

fn strip_ws(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// A bare `set(ThemeKind::..)` call (a directly imported `set`), not an instance method such as `cell.set(ThemeKind::..)` on a private `KindCell`.
fn has_bare_set(flat: &str) -> bool {
    flat.match_indices("set(ThemeKind::").any(|(i, _)| {
        !matches!(
            flat[..i].chars().next_back(),
            Some(c) if c == '.' || c == '_' || c.is_alphanumeric()
        )
    })
}

/// A mutator hit counts unless it is the unrelated `appearance::cache::set(`.
fn has_mutator(code: &str) -> bool {
    let flat = strip_ws(code).replace("appearance::cache::set(", "");
    MUTATORS.iter().any(|m| flat.contains(m)) || has_bare_set(&flat)
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Name of the `fn` declared on `line`, if it is a declaration.
fn fn_name(line: &str) -> Option<&str> {
    let t = line.trim_start();
    let t = t.strip_prefix("pub").map_or(t, |r| {
        let r = r.trim_start();
        if r.starts_with('(') {
            r.split_once(')').map_or(r, |(_, rest)| rest.trim_start())
        } else {
            r
        }
    });
    let t = t.strip_prefix("async ").unwrap_or(t);
    let t = t.strip_prefix("fn ")?;
    let end = t.find(|c: char| !(c.is_alphanumeric() || c == '_'))?;
    (end > 0).then(|| &t[..end])
}

/// A `mod name {` line of any visibility (`mod`, `pub mod`, `pub(super) mod`, `pub(crate) mod`).
fn is_inline_mod(line: &str) -> bool {
    let t = line.trim();
    if !t.ends_with('{') {
        return false;
    }
    let t = t.strip_prefix("pub").map_or(t, |r| {
        let r = r.trim_start();
        if r.starts_with('(') {
            r.split_once(')').map_or(r, |(_, rest)| rest.trim_start())
        } else {
            r
        }
    });
    t.starts_with("mod ")
}

/// One `#[...]` attribute: the lines it spans and its text with whitespace removed.
struct Attr {
    start: usize,
    end: usize,
    flat: String,
}

/// Every outer attribute in `code_text` (strings and comments already blanked, so a `]` inside one cannot close it early).
/// Multi-line attributes are one span.
fn attr_spans(code_text: &str) -> Vec<Attr> {
    let c: Vec<char> = code_text.chars().collect();
    let mut out = Vec::new();
    let mut line = 0;
    let mut i = 0;
    while i < c.len() {
        if c[i] == '\n' {
            line += 1;
        } else if c[i] == '#' && c.get(i + 1) == Some(&'[') {
            let start = line;
            let mut depth = 0;
            let mut opened = false;
            let mut flat = String::new();
            while i < c.len() {
                match c[i] {
                    '\n' => line += 1,
                    '[' => {
                        depth += 1;
                        opened = true;
                    }
                    ']' => depth -= 1,
                    _ => {}
                }
                if !c[i].is_whitespace() {
                    flat.push(c[i]);
                }
                i += 1;
                if opened && depth == 0 {
                    break;
                }
            }
            out.push(Attr {
                start,
                end: line,
                flat,
            });
            continue;
        }
        i += 1;
    }
    out
}

/// A parsed source file: blanked code lines, its attributes, and where each `fn` starts and ends.
struct Source {
    code: Vec<String>,
    comments: Vec<String>,
    attrs: Vec<Attr>,
    fns: Vec<(usize, usize, String)>,
}

fn parse(src: &str) -> Source {
    let code_text = blank_non_code(src);
    let code: Vec<String> = code_text.lines().map(str::to_owned).collect();
    let comments: Vec<String> = comments_only(src).lines().map(str::to_owned).collect();
    let attrs = attr_spans(&code_text);
    let mut fns = Vec::new();
    let mut i = 0;
    while i < code.len() {
        let Some(name) = fn_name(&code[i]) else {
            i += 1;
            continue;
        };
        let ind = indent_of(&code[i]);
        // The signature may span lines; the body opens at the first line ending in `{`; a `;` or one-line `}` ends a bodiless / one-line fn.
        let mut open = i;
        while open < code.len()
            && !code[open].trim_end().ends_with('{')
            && !code[open].trim_end().ends_with(';')
            && !code[open].trim_end().ends_with('}')
        {
            open += 1;
        }
        let end = if open >= code.len() || !code[open].trim_end().ends_with('{') {
            open.min(code.len() - 1)
        } else {
            let mut k = open + 1;
            while k < code.len()
                && !(indent_of(&code[k]) == ind && code[k].trim_start().starts_with('}'))
            {
                k += 1;
            }
            k.min(code.len() - 1)
        };
        fns.push((i, end, name.to_owned()));
        // Skip the body: a fn nested in a pinned test (a Drop guard) is covered by its enclosing fn's lock.
        i = end.max(i) + 1;
    }
    Source {
        code,
        comments,
        attrs,
        fns,
    }
}

impl Source {
    /// Attributes attached to the item starting on line `i`: the contiguous run directly above it, blank (comment) lines allowed between.
    fn attrs_above(&self, i: usize) -> Vec<&Attr> {
        let mut out = Vec::new();
        let mut k = i;
        loop {
            let mut j = k;
            while j > 0 && self.code[j - 1].trim().is_empty() {
                j -= 1;
            }
            if j == 0 {
                break;
            }
            match self.attrs.iter().find(|a| a.end == j - 1) {
                Some(a) => {
                    out.push(a);
                    k = a.start;
                }
                None => break,
            }
        }
        out
    }

    /// Does the `fn` on line `i` carry a test attribute (`#[test]`, `#[tokio::test..]`)?
    fn has_test_attr(&self, i: usize) -> bool {
        self.attrs_above(i).iter().any(|a| {
            a.flat == "#[test]"
                || a.flat.starts_with("#[tokio::test")
                || a.flat.starts_with("#[test_case")
        })
    }

    /// Does the `fn` on line `i` carry a live `#[serial_test::serial(.., KEY, ..)]` for `key`?
    /// A `cfg_attr(..)` wrapper does not count: its condition may never hold.
    fn has_serial_key(&self, i: usize, key: &str) -> bool {
        self.attrs_above(i).iter().any(|a| {
            let inner = a
                .flat
                .strip_prefix("#[serial_test::serial(")
                .or_else(|| a.flat.strip_prefix("#[serial("))
                .and_then(|r| r.strip_suffix(")]"));
            inner.is_some_and(|keys| keys.split(',').any(|k| k == key))
        })
    }

    /// Mark the lines inside a `#[cfg(test)] mod x { .. }` block.
    /// Other attributes and comments between the cfg and the `mod` are allowed.
    fn cfg_test_mod_lines(&self) -> Vec<bool> {
        let mut side = vec![false; self.code.len()];
        for cfg in self.attrs.iter().filter(|a| a.flat == "#[cfg(test)]") {
            let mut m = cfg.end + 1;
            loop {
                if m >= self.code.len() {
                    break;
                }
                if self.code[m].trim().is_empty() {
                    m += 1;
                } else if let Some(a) = self.attrs.iter().find(|a| a.start == m) {
                    m = a.end + 1;
                } else {
                    break;
                }
            }
            if m >= self.code.len() || !is_inline_mod(&self.code[m]) {
                continue;
            }
            let ind = indent_of(&self.code[m]);
            let mut j = m + 1;
            while j < self.code.len()
                && !(indent_of(&self.code[j]) == ind && self.code[j].trim_start().starts_with('}'))
            {
                j += 1;
            }
            for flag in side
                .iter_mut()
                .take((j + 1).min(self.code.len()))
                .skip(cfg.start)
            {
                *flag = true;
            }
        }
        side
    }
}

/// Find test-side `fn`s that mutate theme globals without holding the lock.
/// `whole_file`: the file is a test module (`tests.rs`, `*_tests.rs`, `tests/`).
fn scan_source(src: &str, whole_file: bool) -> Vec<Violation> {
    let parsed = parse(src);
    let in_test_mod = parsed.cfg_test_mod_lines();
    let mut out = Vec::new();
    for (start, end, name) in &parsed.fns {
        let test_side = whole_file || in_test_mod[*start] || parsed.has_test_attr(*start);
        if !test_side {
            continue;
        }
        let body = parsed.code[*start..=*end].join("\n");
        let flat = strip_ws(&body);
        let held = LOCKS.iter().any(|l| flat.contains(l));
        // The opt-out must be a real comment on or just above the fn (or inside it), never a string.
        let opted_out = parsed.comments[start.saturating_sub(4)..=*end]
            .iter()
            .any(|l| l.contains(OPT_OUT));
        if has_mutator(&body) && !held && !opted_out {
            out.push(Violation {
                line: start + 1,
                name: name.clone(),
            });
        }
    }
    out
}

/// Calls that reach `dashboard_enabled()`.
/// `open_dashboard(` is the dispatch tests' helper around `dispatch_open_dashboard`; a test that opens the dashboard through it reads the flag just the same (P78: `x11_primary_hint_routes_to_originating_dashboard`).
const DASHBOARD_READERS: &[&str] = &[
    "open_dashboard(",
    "dispatch_open_dashboard(",
    "dispatch(Action::OpenDashboard",
    "dashboard_enabled(",
];

const DASHBOARD_KEY: &str = "FUIGO_AGENT_DASHBOARD";

/// Find `#[test]` fns that open the dashboard without serializing on `FUIGO_AGENT_DASHBOARD`.
fn scan_dashboard_serial(src: &str) -> Vec<Violation> {
    let parsed = parse(src);
    let mut out = Vec::new();
    for (start, end, name) in &parsed.fns {
        if !parsed.has_test_attr(*start) || parsed.has_serial_key(*start, DASHBOARD_KEY) {
            continue;
        }
        // Search the BODY only: the signature would make a test merely NAMED `.._open_dashboard()` look like a caller.
        // (A token-boundary test on whitespace-stripped code is not an option: `if dashboard_enabled()` strips to `ifdashboard_enabled()`.)
        // A fn written on one line has no separate body lines and is searched whole.
        let body_from = (*start..=*end)
            .find(|&i| parsed.code[i].trim_end().ends_with('{'))
            .map_or(*start, |open| open + 1);
        let flat = strip_ws(&parsed.code[body_from..=*end].join("\n"));
        if DASHBOARD_READERS.iter().any(|r| flat.contains(r)) {
            out.push(Violation {
                line: start + 1,
                name: name.clone(),
            });
        }
    }
    out
}

/// Tests that only READ the theme globals, assert exact colors, and failed on loaded gate runs because a lock-holding theme test ran beside them (P78, receipt R083).
/// A reader cannot be found by scanning for a call (every render reads the theme), so the ones that have bitten are listed by name and must hold the lock.
/// Path is relative to this crate's `src`. A renamed or moved test must be renamed here; a missing one fails the guard.
const PINNED_READERS: &[(&str, &str)] = &[
    (
        "views/queue_pane.rs",
        "hover_paints_dim_hover_bg_on_hovered_row",
    ),
    (
        "views/queue_pane.rs",
        "interject_button_brightens_fg_on_hover",
    ),
    (
        "views/tasks_pane.rs",
        "subagent_activity_suffix_renders_while_running_only",
    ),
    (
        "scrollback/wrappers/entry_renderer.rs",
        "gutter_keeps_code_block_background_on_no_background_block",
    ),
    (
        "scrollback/entry.rs",
        "test_truncated_height_cache_hits_when_key_unchanged",
    ),
];

/// If `stmt` (whitespace-stripped code) is `let _name = [path::]pin_theme();`, the name of the guard it binds.
/// `let _ = pin_theme();` and `drop(pin_theme())` release the lock at once and do not count.
fn held_pin_binding(stmt: &str) -> Option<&str> {
    let rest = stmt.strip_prefix("let")?;
    let call = rest.trim_start_matches(|c: char| c.is_alphanumeric() || c == '_');
    let name = &rest[..rest.len() - call.len()];
    // The right-hand side must be the call itself, by a plain path: `|| pin_theme()` builds a closure and takes no lock.
    let path = call.strip_prefix('=')?.strip_suffix("pin_theme();")?;
    let plain_path = (path.is_empty() || path.ends_with("::"))
        && path
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == ':');
    (name.starts_with('_') && name.len() > 1 && plain_path).then_some(name)
}

/// Does `code` mention the identifier `name` (as a whole token)?
fn mentions(code: &str, name: &str) -> bool {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    code.match_indices(name).any(|(at, _)| {
        !code[..at].chars().next_back().is_some_and(ident)
            && !code[at + name.len()..].chars().next().is_some_and(ident)
    })
}

/// Why the `#[test] fn` called `name` in `src` does not hold the theme lock, or `None` when it does.
/// Holding it means the FIRST statement of the body binds `pin_theme()` to a named guard: every read and assertion after it is then under the lock, which a token search anywhere in the body cannot show (a pin taken after the assertions, inside a closure, or dropped at once).
fn reader_pin_problem(src: &str, name: &str) -> Option<&'static str> {
    let parsed = parse(src);
    let mut found = false;
    for (start, end, fn_name) in &parsed.fns {
        if fn_name != name || !parsed.has_test_attr(*start) {
            continue;
        }
        found = true;
        let open = (*start..=*end).find(|&i| parsed.code[i].trim_end().ends_with('{'));
        // The first statement: everything after the opening brace up to the first line that ends it (rustfmt may break a long `let` after the `=`).
        let body = open.map_or(&[][..], |open| &parsed.code[open + 1..=*end]);
        let mut first = String::new();
        let mut rest_from = 0;
        for line in body {
            first.push_str(&strip_ws(line));
            rest_from += 1;
            if first.ends_with(';') || first.ends_with('{') || first.ends_with('}') {
                break;
            }
        }
        let Some(guard) = held_pin_binding(&first) else {
            return Some("does not open with `let _theme = pin_theme();`");
        };
        // Bound, and then left alone: a later `drop(_theme)` (or any other use that could move it) ends the lock before the assertions.
        // Deliberately conservative: this is a token scan, so an unrelated later binding of the same name (a nested fn's parameter, a shadowing `let`) is reported too. Rename it; a listed reader has no reason to touch its guard.
        if body[rest_from..].iter().any(|line| mentions(line, guard)) {
            return Some(
                "uses its pin guard after binding it (a moved or dropped guard no longer holds the lock)",
            );
        }
    }
    if found {
        None
    } else {
        Some("is not a `#[test] fn` in that file (renamed or moved? update PINNED_READERS)")
    }
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

fn is_test_module_file(p: &Path) -> bool {
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name == "tests.rs"
        || name.ends_with("_tests.rs")
        || p.components().any(|c| c.as_os_str() == "tests")
}

#[test]
fn no_unpinned_theme_mutation_in_pager_tests() {
    let me = Path::new(env!("CARGO_MANIFEST_DIR"));
    let own_src = me.join("src");
    let mut roots = vec![own_src.clone()];
    for sib in ["../fuigo-pager-render/src", "../fuigo-pager-minimal/src"] {
        let p = me.join(sib);
        if p.is_dir() {
            roots.push(p);
        }
    }
    let mut files = Vec::new();
    for r in &roots {
        rust_files(r, &mut files);
    }
    assert!(
        files.len() > 100,
        "scanner found only {} files; wrong root?",
        files.len()
    );
    let guard = own_src.join("theme_pin_guard_tests.rs");
    let mut bad = Vec::new();
    let mut unserialized = Vec::new();
    for f in &files {
        if *f == guard {
            continue;
        }
        let src = std::fs::read_to_string(f).unwrap_or_default();
        for v in scan_source(&src, is_test_module_file(f)) {
            bad.push(format!("{}:{} fn {}", f.display(), v.line, v.name));
        }
        for v in scan_dashboard_serial(&src) {
            unserialized.push(format!("{}:{} fn {}", f.display(), v.line, v.name));
        }
    }
    assert!(
        unserialized.is_empty(),
        "tests open the dashboard without `#[serial_test::serial(FUIGO_AGENT_DASHBOARD)]` (a sibling's FUIGO_AGENT_DASHBOARD=0 disables it mid-test):\n{}",
        unserialized.join("\n")
    );
    assert!(
        bad.is_empty(),
        "tests mutate the process-global theme without `pin_theme()` / the shared test lock (they race pinned tests):\n{}",
        bad.join("\n")
    );
}

#[test]
fn listed_theme_readers_hold_the_pin() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut bad = Vec::new();
    for (file, name) in PINNED_READERS {
        let path = src_dir.join(file);
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        if let Some(why) = reader_pin_problem(&src, name) {
            bad.push(format!("{file}: fn {name} {why}"));
        }
    }
    assert!(
        bad.is_empty(),
        "tests that assert exact theme colors must hold the theme lock (a theme test running beside them changes the palette mid-assertion):\n{}",
        bad.join("\n")
    );
}

#[test]
fn reader_guard_accepts_a_pinned_test_and_rejects_the_rest() {
    let src = r#"
#[cfg(test)]
mod tests {
    #[test]
    fn pinned() {
        // a comment before the pin is fine
        let _theme = crate::theme::cache::pin_theme();
        assert_eq!(cell.fg, theme.gray);
    }

    #[test]
    fn pinned_bare() {
        let _guard = pin_theme();
        assert_eq!(cell.fg, theme.gray);
    }

    #[test]
    fn pinned_across_lines() {
        let _theme = /* still one statement */
            crate::theme::cache::pin_theme();
        assert_eq!(cell.fg, theme.gray);
    }

    #[test]
    fn closure_that_would_pin() {
        let _theme = || crate::theme::cache::pin_theme();
        assert_eq!(cell.fg, theme.gray);
    }

    #[test]
    fn pin_of_something_else() {
        let _theme = other(crate::theme::cache::pin_theme());
        assert_eq!(cell.fg, theme.gray);
    }

    #[test]
    fn unpinned() {
        // pin_theme() in a comment does not count
        assert_eq!(cell.fg, theme.gray);
    }

    #[test]
    fn pinned_too_late() {
        assert_eq!(cell.fg, theme.gray);
        let _theme = pin_theme();
    }

    #[test]
    fn pin_dropped_at_once() {
        let _ = pin_theme();
        assert_eq!(cell.fg, theme.gray);
    }

    #[test]
    fn pin_dropped_explicitly() {
        drop(pin_theme());
        assert_eq!(cell.fg, theme.gray);
    }

    #[test]
    fn pin_bound_then_dropped() {
        let _theme = pin_theme();
        drop(_theme);
        assert_eq!(cell.fg, theme.gray);
    }

    #[test]
    fn pin_named_like_a_longer_identifier() {
        let _theme = pin_theme();
        let _theme_name = theme.name();
        assert_eq!(cell.fg, theme.gray);
    }

    #[test]
    fn pin_only_in_a_closure() {
        let pin = || {
            let _theme = pin_theme();
        };
        assert_eq!(cell.fg, theme.gray);
    }

    #[test]
    fn lock_named_but_not_taken() {
        let lock = test_lock();
        assert_eq!(cell.fg, theme.gray);
    }

    fn helper_not_a_test() {
        let _theme = pin_theme();
    }
}
"#;
    for held in [
        "pinned",
        "pinned_bare",
        "pinned_across_lines",
        "pin_named_like_a_longer_identifier",
    ] {
        assert_eq!(reader_pin_problem(src, held), None, "{held}");
    }
    for loose in [
        "unpinned",
        "closure_that_would_pin",
        "pin_of_something_else",
        "pinned_too_late",
        "pin_dropped_at_once",
        "pin_dropped_explicitly",
        "pin_only_in_a_closure",
        "lock_named_but_not_taken",
    ] {
        assert!(
            reader_pin_problem(src, loose).is_some_and(|w| w.contains("does not open with")),
            "{loose} does not hold the pin over its assertions and must be reported"
        );
    }
    assert!(
        reader_pin_problem(src, "pin_bound_then_dropped")
            .is_some_and(|w| w.contains("uses its pin guard")),
        "a guard dropped before the assertions must be reported"
    );
    for absent in ["helper_not_a_test", "gone"] {
        assert!(
            reader_pin_problem(src, absent).is_some_and(|w| w.contains("is not a")),
            "{absent}: only a `#[test] fn` of that name satisfies the list"
        );
    }
}

/// Lines of `src` that put a FIXED name under the shared temp dir: `temp_dir().join("literal")`.
/// Every suite on the host shares that directory, and gate lanes run the same test at the same time, so one run's write or cleanup lands in another's fixture (P78: "the preview is open", "off-state button missing").
/// A name built with `format!` (pid, uuid) or passed in a variable is not flagged; `tempfile::tempdir()` is the way out.
fn fixed_temp_names(src: &str) -> Vec<usize> {
    // String literals are blanked in the code view, so a literal argument leaves `join()` behind once whitespace is stripped.
    let code = blank_non_code(src);
    let lines: Vec<&str> = code.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if !line.contains("temp_dir()") {
            continue;
        }
        // rustfmt may put `.join(..)` on the following lines of the same expression.
        let stmt = strip_ws(&lines[i..lines.len().min(i + 3)].join(""));
        if stmt.contains("temp_dir().join()") {
            out.push(i + 1);
        }
    }
    out
}

#[test]
fn no_fixed_names_in_the_shared_temp_dir() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src_dir, &mut files);
    let guard = src_dir.join("theme_pin_guard_tests.rs");
    let mut bad = Vec::new();
    for f in files.iter().filter(|f| **f != guard) {
        let src = std::fs::read_to_string(f).unwrap_or_default();
        for line in fixed_temp_names(&src) {
            bad.push(format!("{}:{line}", f.display()));
        }
    }
    assert!(
        bad.is_empty(),
        "a fixed file name under the shared temp dir is shared with every other suite on the host; use `tempfile::tempdir()`:\n{}",
        bad.join("\n")
    );
}

#[test]
fn temp_name_guard_flags_a_literal_and_accepts_unique_names() {
    let fixed = "let path = std::env::temp_dir().join(\"viewer.txt\");\n";
    assert_eq!(fixed_temp_names(fixed), vec![1]);
    let fixed_wrapped = "let path = std::env::temp_dir()\n    .join(\"viewer.txt\");\n";
    assert_eq!(fixed_temp_names(fixed_wrapped), vec![1]);
    let by_pid =
        "let p = std::env::temp_dir().join(format!(\"out-{}.txt\", std::process::id()));\n";
    assert!(fixed_temp_names(by_pid).is_empty());
    let whole_dir = "let dir = std::env::temp_dir();\nlet t = dunce::canonicalize(&dir);\n";
    assert!(fixed_temp_names(whole_dir).is_empty());
    let own_dir =
        "let dir = tempfile::tempdir().unwrap();\nlet p = dir.path().join(\"viewer.txt\");\n";
    assert!(fixed_temp_names(own_dir).is_empty());
    let in_comment = "// std::env::temp_dir().join(\"viewer.txt\")\n";
    assert!(fixed_temp_names(in_comment).is_empty());
}

fn violations(src: &str, whole_file: bool) -> Vec<(usize, String)> {
    scan_source(src, whole_file)
        .into_iter()
        .map(|v| (v.line, v.name))
        .collect()
}

#[test]
fn guard_flags_an_unpinned_set_and_accepts_the_pinned_forms() {
    let unpinned = "#[test]\nfn t() {\n    crate::theme::cache::set(ThemeKind::FuigoNight);\n}\n";
    assert_eq!(violations(unpinned, true), vec![(2, "t".to_owned())]);
    // A rustfmt line break between `dispatch(` and the action must not hide it.
    let wrapped = "#[test]\nfn t() {\n    let _ = dispatch(\n        Action::SetTheme(\"x\".into()),\n        &mut app,\n    );\n}\n";
    assert_eq!(violations(wrapped, true).len(), 1);
    let pinned = "#[test]\nfn t() {\n    let _theme = crate::theme::cache::pin_theme();\n    crate::theme::cache::set(ThemeKind::FuigoDay);\n}\n";
    assert!(violations(pinned, true).is_empty());
    let env = "#[test]\nfn t() {\n    with_theme_test_env(|| {\n        cache::set(ThemeKind::FuigoDay);\n    });\n}\n";
    assert!(violations(env, true).is_empty());
    let opted =
        "// theme-pin: caller holds\nfn helper() {\n    cache::set(ThemeKind::FuigoDay);\n}\n";
    assert!(violations(opted, true).is_empty());
    // The unrelated appearance cache is not theme state.
    let appearance = "#[test]\nfn t() {\n    crate::appearance::cache::set(false);\n}\n";
    assert!(violations(appearance, true).is_empty());
    // Non-test code in a non-test file is out of scope (production code legitimately sets the theme).
    let prod = "fn startup() {\n    cache::set(initial);\n}\n";
    assert!(violations(prod, false).is_empty());
}

#[test]
fn guard_recognises_every_test_side_form() {
    // A `#[cfg(test)] mod` of any visibility, including `pub(super)`.
    for vis in ["mod", "pub mod", "pub(super) mod", "pub(crate) mod"] {
        let src = format!(
            "fn startup() {{\n    cache::set(initial);\n}}\n#[cfg(test)]\n{vis} tests {{\n    #[test]\n    fn t() {{\n        cache::set(x);\n    }}\n}}\n"
        );
        assert_eq!(violations(&src, false), vec![(7, "t".to_owned())], "{vis}");
    }
    // A standalone `#[test]` in an ordinary source file, with and without stacked attributes and docs.
    let standalone = "fn startup() {\n    cache::set(initial);\n}\n/// docs\n#[test]\n#[serial]\nfn t() {\n    cache::set(x);\n}\n";
    assert_eq!(violations(standalone, false), vec![(7, "t".to_owned())]);
    // An attribute between the cfg and the mod.
    let attr = "#[cfg(test)]\n#[allow(dead_code)]\nmod tests {\n    fn helper() {\n        cache::set(x);\n    }\n}\n";
    assert_eq!(violations(attr, false), vec![(4, "helper".to_owned())]);
    // A bare, directly imported setter.
    let bare = "#[test]\nfn t() {\n    set(ThemeKind::FuigoDay);\n}\n";
    assert_eq!(violations(bare, true), vec![(2, "t".to_owned())]);
}

#[test]
fn guard_ignores_instance_set_on_a_private_cell() {
    // `cell.set(..)` writes a private `KindCell`, not the process-global theme.
    let private = "#[test]\nfn t() {\n    let cell = KindCell::new(ThemeKind::FuigoNight);\n    cell.set(ThemeKind::FuigoDay, || {});\n}\n";
    assert!(violations(private, true).is_empty());
    // A bare `set(..)` right after other punctuation is still a global write.
    let bare_after_block =
        "#[test]\nfn t() {\n    if x {\n        set(ThemeKind::FuigoDay);\n    }\n}\n";
    assert_eq!(
        violations(bare_after_block, true),
        vec![(2, "t".to_owned())]
    );
    // ... as is one at the start of the body, or after `;`.
    let after_semi = "#[test]\nfn t() {\n    let a = 1; set(ThemeKind::FuigoDay);\n}\n";
    assert_eq!(violations(after_semi, true), vec![(2, "t".to_owned())]);
}

#[test]
fn guard_ignores_comments_and_strings() {
    // A comment naming the lock does not grant it.
    let fake_lock = "#[test]\nfn t() {\n    // TODO: pin_theme()\n    cache::set(x);\n}\n";
    assert_eq!(violations(fake_lock, true), vec![(2, "t".to_owned())]);
    // A string naming the lock does not grant it either.
    let fake_str = "#[test]\nfn t() {\n    let _ = \"pin_theme()\";\n    cache::set(x);\n}\n";
    assert_eq!(violations(fake_str, true), vec![(2, "t".to_owned())]);
    // A comment or string naming a mutator is not a mutation.
    let note = "#[test]\nfn t() {\n    // No cache::set() here\n    /* cache::set(y) */\n    let s = \"cache::set(z)\";\n    let r = r#\"cache::set(\"w\")\"#;\n    assert!(s.len() > 0 && r.len() > 0);\n}\n";
    assert!(violations(note, true).is_empty());
    // Char literals and lifetimes do not derail the blanking.
    let chars = "#[test]\nfn t<'a>(x: &'a str) {\n    let q = '\"';\n    let b = '\\'';\n    cache::set(x);\n}\n";
    assert_eq!(violations(chars, true), vec![(2, "t".to_owned())]);
}

#[test]
fn guard_flags_an_unserialized_dashboard_opener() {
    let bare = "#[test]\nfn t() {\n    let _ = dispatch_open_dashboard(&mut app);\n}\n";
    assert_eq!(
        scan_dashboard_serial(bare)
            .into_iter()
            .map(|v| (v.line, v.name))
            .collect::<Vec<_>>(),
        vec![(2, "t".to_owned())]
    );
    let routed = "#[test]\nfn t() {\n    let _ = dispatch(\n        Action::OpenDashboard,\n        &mut app,\n    );\n}\n";
    assert_eq!(scan_dashboard_serial(routed).len(), 1);
    let serial = "#[serial_test::serial(FUIGO_AGENT_DASHBOARD)]\n#[test]\nfn t() {\n    let _ = dispatch_open_dashboard(&mut app);\n}\n";
    assert!(scan_dashboard_serial(serial).is_empty());
    // Opening it through the dispatch tests' `open_dashboard` helper reads the flag all the same.
    let via_helper = "#[test]\nfn t() {\n    open_dashboard(&mut app);\n}\n";
    assert_eq!(scan_dashboard_serial(via_helper).len(), 1);
    let via_helper_serial = "#[serial_test::serial(FUIGO_AGENT_DASHBOARD)]\n#[test]\nfn t() {\n    open_dashboard(&mut app);\n}\n";
    assert!(scan_dashboard_serial(via_helper_serial).is_empty());
    // A test whose NAME ends in `open_dashboard` does not open it.
    let named = "#[test]\nfn ctrl_4_does_not_open_dashboard() {\n    assert!(true);\n}\n";
    assert!(scan_dashboard_serial(named).is_empty());
    // A reader directly after a keyword is still a reader once whitespace is stripped.
    for stmt in [
        "if dashboard_enabled() {\n        return;\n    }",
        "while !dashboard_enabled() {}",
        "return dispatch_open_dashboard(&mut app);",
    ] {
        let src = format!("#[test]\nfn t() {{\n    {stmt}\n}}\n");
        assert_eq!(scan_dashboard_serial(&src).len(), 1, "{stmt}");
    }
    // A helper that is not itself a test is out of scope; so is a test that never opens the dashboard.
    let helper = "fn open(app: &mut AppView) {\n    let _ = dispatch_open_dashboard(app);\n}\n";
    assert!(scan_dashboard_serial(helper).is_empty());
    let other = "#[test]\nfn t() {\n    let _ = dispatch_exit_dashboard(&mut app);\n}\n";
    assert!(scan_dashboard_serial(other).is_empty());
}

#[test]
fn guard_handles_multiline_attributes_comments_and_byte_strings() {
    // A multi-line attribute between `#[test]` and the fn must not hide the test.
    let multiline = "fn startup() {\n    cache::set(initial);\n}\n#[test]\n#[cfg_attr(\n    all(),\n    allow(dead_code)\n)]\nfn t() {\n    cache::set(x);\n}\n";
    assert_eq!(violations(multiline, false), vec![(9, "t".to_owned())]);
    // A comment between `#[cfg(test)]` and the mod must not hide the module.
    let commented = "#[cfg(test)]\n// note\npub(super) mod tests {\n    fn helper() {\n        cache::set(x);\n    }\n}\n";
    assert_eq!(violations(commented, false), vec![(4, "helper".to_owned())]);
    // Raw byte strings neither grant a lock nor fake a mutation.
    let fake_lock = "#[test]\nfn t() {\n    let _ = br#\"pin_theme()\"#;\n    cache::set(x);\n}\n";
    assert_eq!(violations(fake_lock, true), vec![(2, "t".to_owned())]);
    let fake_mut = "#[test]\nfn t() {\n    let _ = br#\"cache::set(x)\"#;\n}\n";
    assert!(violations(fake_mut, true).is_empty());
    // An exemption marker inside a string is not an exemption.
    let fake_optout =
        "#[test]\nfn t() {\n    let _ = \"theme-pin: caller holds\";\n    cache::set(x);\n}\n";
    assert_eq!(violations(fake_optout, true), vec![(2, "t".to_owned())]);
    // A real comment exemption inside the fn body counts.
    let real_optout = "#[test]\nfn t() {\n    // theme-pin: caller holds\n    cache::set(x);\n}\n";
    assert!(violations(real_optout, true).is_empty());
}

#[test]
fn guard_dashboard_serial_key_matching() {
    let dash = |attr: &str| {
        format!("{attr}\n#[test]\nfn t() {{\n    let _ = dispatch_open_dashboard(&mut app);\n}}\n")
    };
    // Other keys alongside the dashboard key still count.
    assert!(
        scan_dashboard_serial(&dash(
            "#[serial_test::serial(FUIGO_AGENT_DASHBOARD, CONFIG)]"
        ))
        .is_empty()
    );
    assert!(
        scan_dashboard_serial(&dash(
            "#[serial_test::serial(CONFIG, FUIGO_AGENT_DASHBOARD)]"
        ))
        .is_empty()
    );
    // A different key, a bare `#[serial]`, or a conditional `cfg_attr` wrapper does not.
    assert_eq!(
        scan_dashboard_serial(&dash("#[serial_test::serial(CONFIG)]")).len(),
        1
    );
    assert_eq!(
        scan_dashboard_serial(&dash("#[serial_test::serial]")).len(),
        1
    );
    assert_eq!(
        scan_dashboard_serial(&dash(
            "#[cfg_attr(any(), serial_test::serial(FUIGO_AGENT_DASHBOARD))]"
        ))
        .len(),
        1
    );
}
