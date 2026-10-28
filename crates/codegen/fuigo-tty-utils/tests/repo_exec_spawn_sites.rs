//! u35 t1 (T2b): every production `git`, `jj` and `direnv` Fuigo starts goes through the judged builders in
//! `fuigo_tty_utils::repo_exec`. This scans the non-test Rust of every crate under `crates/codegen` and `crates/common`
//! and fails on a raw spawn, a use of the dirless builders, a re-targeted judged command, an unjudged builder outside its
//! allow-list, and a binary entry that never installs the judge. Each violation prints as `path:line: text`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use regex::Regex;

/// Crates that are test support (never shipped), skipped whole.
const SKIPPED_CRATES: &[&str] = &["fuigo-test-support", "fuigo-test-utils", "fuigo-pager-pty-harness"];

/// The only files that implement the plugin install/publish commands the user typed (`git_command_user_invoked`).
const USER_INVOKED_FILES: &[&str] = &[
    "crates/codegen/fuigo-plugin-marketplace/src/installer.rs",
    "crates/codegen/fuigo-plugin-marketplace/src/git.rs",
    "crates/codegen/fuigo-agent/src/plugins/git_install.rs",
    "crates/codegen/fuigo-pager/src/plugin_cmd.rs",
];

/// The only file that reads the user's global git settings (`git_command_global`).
const GLOBAL_GIT_FILES: &[&str] = &["crates/codegen/fuigo-shell/src/util/user_identity.rs"];

/// Non-spawn mentions of `GIT_BIN_PATH` (reading it to judge a user's command, never to start a process).
const GIT_BIN_PATH_READS: &[(&str, &str)] = &[(
    "crates/codegen/fuigo-workspace/src/permission/exec_risk.rs",
    "reads GIT_BIN_PATH to recognise the user's own git in a command it is classifying, not to spawn one",
)];

/// Binary entries that must install the process judge before anything spawns.
const JUDGE_INSTALLERS: &[(&str, &str)] = &[
    ("crates/codegen/fuigo-pager-bin/src/main.rs", "install_process_judges"),
    ("crates/codegen/fuigo-workspace/src/bin/workspace_server.rs", "install_process_judges"),
    ("crates/codegen/fuigo-shell/src/bin/p15d-stdio-agent.rs", "install_process_judges"),
    ("crates/codegen/fuigo-fast-worktree/src/bin/cli.rs", "install_repo_exec_judge"),
];

fn repo_root() -> PathBuf {
    dunce::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")).expect("repo root")
}

/// Blank comments (keeping strings) into `code`, and comments plus string/char contents into `shape`; both keep every
/// byte offset and newline, so offsets and line numbers agree with the source.
fn lex(src: &str) -> (String, String) {
    let b = src.as_bytes();
    let mut code = b.to_vec();
    let mut shape = b.to_vec();
    let blank = |v: &mut Vec<u8>, from: usize, to: usize| {
        for byte in &mut v[from..to] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    };
    let n = b.len();
    let mut i = 0;
    while i < n {
        let c = b[i];
        if c == b'/' && i + 1 < n && b[i + 1] == b'/' {
            let end = src[i..].find('\n').map_or(n, |p| i + p);
            blank(&mut code, i, end);
            blank(&mut shape, i, end);
            i = end;
        } else if c == b'/' && i + 1 < n && b[i + 1] == b'*' {
            let mut depth = 1;
            let mut j = i + 2;
            while j < n && depth > 0 {
                if b[j] == b'/' && j + 1 < n && b[j + 1] == b'*' {
                    depth += 1;
                    j += 2;
                } else if b[j] == b'*' && j + 1 < n && b[j + 1] == b'/' {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut code, i, j);
            blank(&mut shape, i, j);
            i = j;
        } else if c == b'r' && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')) && {
            let mut j = i + 1;
            while j < n && b[j] == b'#' {
                j += 1;
            }
            j < n && b[j] == b'"'
        } {
            let mut j = i + 1;
            let mut hashes = 0;
            while b[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            let close: Vec<u8> = std::iter::once(b'"').chain(std::iter::repeat_n(b'#', hashes)).collect();
            let end = src[j + 1..].find(std::str::from_utf8(&close).unwrap()).map_or(n, |p| j + 1 + p + close.len());
            blank(&mut shape, j + 1, end.saturating_sub(close.len()).max(j + 1));
            i = end;
        } else if c == b'"' {
            let mut j = i + 1;
            while j < n && b[j] != b'"' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            let j = j.min(n);
            blank(&mut shape, i + 1, j);
            i = (j + 1).min(n);
        } else if c == b'\'' {
            // A char literal ('x', '\n', '\u{..}') versus a lifetime ('a).
            let rest = &src[i + 1..];
            let mut it = rest.char_indices();
            let lit_end = match it.next() {
                Some((_, '\\')) => rest[2..].find('\'').map(|p| i + 1 + 2 + p),
                Some((_, ch)) if ch != '\'' => match it.next() {
                    Some((p, '\'')) => Some(i + 1 + p),
                    _ => None,
                },
                _ => None,
            };
            match lit_end {
                Some(end) => {
                    blank(&mut shape, i + 1, end);
                    i = end + 1;
                }
                None => i += 1,
            }
        } else {
            i += 1;
        }
    }
    (String::from_utf8(code).unwrap(), String::from_utf8(shape).unwrap())
}

/// The byte range of the item following offset `from` (up to its closing `}` or terminating `;`), by `shape`.
fn item_end(shape: &str, from: usize) -> usize {
    let b = shape.as_bytes();
    let mut depth = 0i32;
    let mut paren = 0i32;
    for (k, &c) in b.iter().enumerate().skip(from) {
        match c {
            b'(' | b'[' => paren += 1,
            b')' | b']' => paren -= 1,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth <= 0 {
                    return k + 1;
                }
            }
            b';' if depth == 0 && paren <= 0 => return k + 1,
            _ => {}
        }
    }
    b.len()
}

fn is_test_cfg(attr: &str) -> bool {
    let a: String = attr.chars().filter(|c| !c.is_whitespace()).collect();
    a == "#[cfg(test)]" || a.starts_with("#[cfg(all(test,") || a == "#![cfg(test)]"
}

struct Scanned {
    /// `code` with every `#[cfg(test)]` item blanked.
    code: String,
    shape: String,
    /// `mod name;` declarations that are `#[cfg(test)]` (their files are skipped).
    test_mods: Vec<String>,
    whole_file_test: bool,
}

fn scan_file(src: &str) -> Scanned {
    let (mut code, mut shape) = lex(src);
    let attr_re = Regex::new(r"#!?\[cfg\([^\]\n]*\)\]").unwrap();
    let mod_re = Regex::new(r"^\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;").unwrap();
    let mut test_mods = Vec::new();
    let mut whole_file_test = false;
    let mut blanks: Vec<(usize, usize)> = Vec::new();
    for m in attr_re.find_iter(&shape.clone()) {
        let text = &src[m.start()..m.end()];
        // Attribute text lives in `shape` untouched (brackets/parens are not blanked), but compare on the source.
        if !is_test_cfg(text) {
            continue;
        }
        if text.starts_with("#!") {
            whole_file_test = true;
            continue;
        }
        let end = item_end(&shape, m.end());
        if let Some(c) = mod_re.captures(&shape[m.end()..end.min(shape.len())]) {
            test_mods.push(c[1].to_string());
        }
        // Later attributes between this cfg and the item are part of the item range already.
        blanks.push((m.start(), end));
    }
    for (from, to) in blanks {
        for v in [&mut code, &mut shape] {
            // Safety: only ASCII spaces are written over whole bytes of a UTF-8 string at char boundaries, so go
            // through a byte vector and re-validate.
            let mut bytes = std::mem::take(v).into_bytes();
            for byte in &mut bytes[from..to] {
                if *byte != b'\n' {
                    *byte = b' ';
                }
            }
            *v = String::from_utf8(bytes).unwrap();
        }
    }
    Scanned { code, shape, test_mods, whole_file_test }
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = read.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            if name == "tests" || name == "benches" || name == "examples" || name == "target" || name.ends_with("_tests") {
                continue;
            }
            collect_rs(&p, out);
        } else if name.ends_with(".rs") && !name.ends_with("_tests.rs") && name != "build.rs" && name != "tests.rs" {
            out.push(p);
        }
    }
}

struct Source {
    rel: String,
    scanned: Scanned,
}

fn production_sources() -> Vec<Source> {
    let root = repo_root();
    let mut files = Vec::new();
    for group in ["crates/codegen", "crates/common"] {
        let mut crates: Vec<_> = std::fs::read_dir(root.join(group)).expect(group).flatten().collect();
        crates.sort_by_key(|e| e.file_name());
        for c in crates {
            let name = c.file_name().to_string_lossy().to_string();
            if !c.path().is_dir() || SKIPPED_CRATES.contains(&name.as_str()) {
                continue;
            }
            collect_rs(&c.path().join("src"), &mut files);
        }
    }
    let mut scanned: Vec<(PathBuf, Scanned)> = Vec::new();
    for f in files {
        let rel = f.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        // The judged builders live here; test-only binaries are not shipped.
        if rel.starts_with("crates/codegen/fuigo-tty-utils/src/")
            || (rel.contains("/src/bin/") && rel.rsplit('/').next().is_some_and(|n| n.contains("bench")))
        {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(&f) else { continue };
        scanned.push((f, scan_file(&src)));
    }
    // Files and directories only reached through `#[cfg(test)] mod name;`.
    let mut skipped_files: BTreeSet<PathBuf> = BTreeSet::new();
    let mut skipped_dirs: Vec<PathBuf> = Vec::new();
    for (f, s) in &scanned {
        let stem = f.file_stem().unwrap().to_string_lossy().to_string();
        let parent = f.parent().unwrap();
        let base = if matches!(stem.as_str(), "mod" | "lib" | "main") { parent.to_path_buf() } else { parent.join(&stem) };
        for m in &s.test_mods {
            skipped_files.insert(base.join(format!("{m}.rs")));
            skipped_files.insert(base.join(m).join("mod.rs"));
            skipped_dirs.push(base.join(m));
        }
        if s.whole_file_test {
            skipped_files.insert(f.clone());
        }
    }
    scanned
        .into_iter()
        .filter(|(f, _)| !skipped_files.contains(f) && !skipped_dirs.iter().any(|d| f.starts_with(d)))
        .map(|(f, scanned)| Source { rel: f.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/"), scanned })
        .collect()
}

fn line_of(text: &str, offset: usize) -> usize {
    text[..offset].bytes().filter(|b| *b == b'\n').count() + 1
}

fn line_text(text: &str, line: usize) -> String {
    text.lines().nth(line - 1).unwrap_or("").trim().to_string()
}

#[test]
fn the_scanner_sees_the_codebase() {
    let sources = production_sources();
    assert!(sources.len() > 500, "scanned only {} files; the scan is not reaching the crates", sources.len());
    for expect in ["crates/codegen/fuigo-workspace/src/session/git.rs", "crates/codegen/fuigo-fast-worktree/src/sync.rs"] {
        assert!(sources.iter().any(|s| s.rel == expect), "{expect} was not scanned");
    }
}

#[test]
fn the_scanner_skips_test_items_and_comments() {
    let src = "fn a() {}\n// Command::new(\"git\")\n#[cfg(test)]\nmod tests {\n    fn t() { Command::new(\"git\"); }\n}\nfn b() {\n    let s = \"}{\";\n}\n";
    let s = scan_file(src);
    assert!(!s.code.contains("Command::new"), "{}", s.code);
    let s = scan_file("#[cfg(test)]\nmod tests_in_file;\nfn c() { Command::new(\"jj\"); }\n");
    assert_eq!(s.test_mods, vec!["tests_in_file".to_string()]);
    assert!(s.code.contains("Command::new(\"jj\")"));
}

struct Rules {
    raw_literal: Regex,
    raw_expr: Regex,
    names_tool: Regex,
    git_bin_call: Regex,
    git_bin_path: Regex,
    dirless: Regex,
    user_invoked: Regex,
    global: Regex,
    judged_bind: Regex,
    judged_chain: Regex,
}

const JUDGED: &str = "git_command_in|git_command_locking_in|git_command_at_in|jj_command_in|direnv_command_in|git_command_for_worktree|git_command_locking_for_worktree";

static RULES: std::sync::LazyLock<Rules> = std::sync::LazyLock::new(|| Rules {
    raw_literal: Regex::new(r#"Command\s*::\s*new\s*\(\s*"(?:git|jj|direnv)(?:\.exe)?"\s*\)"#).unwrap(),
    raw_expr: Regex::new(r#"Command\s*::\s*new\s*\(\s*([^"\s)][^)]*)\)"#).unwrap(),
    names_tool: Regex::new(r"(^|[^A-Za-z0-9])(git|jj|direnv)($|[^A-Za-z0-9])").unwrap(),
    git_bin_call: Regex::new(r"\bgit_bin\s*\(").unwrap(),
    git_bin_path: Regex::new(r"GIT_BIN_PATH").unwrap(),
    dirless: Regex::new(r"(^|[^.\w])git_command(_locking|_at)?\(").unwrap(),
    user_invoked: Regex::new(r"git_command(_locking)?_user_invoked").unwrap(),
    global: Regex::new(r"git_command_global").unwrap(),
    judged_bind: Regex::new(&format!(
        r"let\s+(?:mut\s+)?(\w+)\s*(?::[^=;]+)?=\s*(?:\w+::)*(?:{JUDGED})\s*\("
    ))
    .unwrap(),
    judged_chain: Regex::new(&format!(
        r"(?:{JUDGED})\s*\([^;]*?\)\s*(?:\?|\.map_err\([^;]*?\)\?|\.ok\(\)|\.expect\([^;]*?\))?\s*\.current_dir\s*\("
    ))
    .unwrap(),
});

/// Every violation in one scanned file, as `path:line: text [why]`.
fn violations_in(rel: &str, scanned: &Scanned) -> Vec<String> {
    let rules = &*RULES;
    let code = &scanned.code;
    let shape = &scanned.shape;
    let mut violations: Vec<String> = Vec::new();
    let mut report = |offset: usize, why: &str| {
        let line = line_of(code, offset);
        violations.push(format!("{rel}:{line}: {} [{why}]", line_text(code, line)));
    };
    for m in rules.raw_literal.find_iter(code) {
        report(m.start(), "raw spawn of git/jj/direnv");
    }
    for c in rules.raw_expr.captures_iter(code) {
        if rules.names_tool.is_match(&c[1]) {
            report(c.get(0).unwrap().start(), "Command::new on an expression naming git/jj/direnv");
        }
    }
    for m in rules.git_bin_call.find_iter(code) {
        report(m.start(), "git_bin()");
    }
    if !GIT_BIN_PATH_READS.iter().any(|(f, _)| *f == rel) {
        for m in rules.git_bin_path.find_iter(code) {
            report(m.start(), "GIT_BIN_PATH read outside tty-utils");
        }
    }
    for m in rules.dirless.find_iter(code) {
        report(m.start(), "dirless git_command builder (test-only)");
    }
    if !USER_INVOKED_FILES.contains(&rel) {
        for m in rules.user_invoked.find_iter(code) {
            report(m.start(), "user-invoked git builder outside the install/publish files");
        }
    }
    if !GLOBAL_GIT_FILES.contains(&rel) {
        for m in rules.global.find_iter(code) {
            report(m.start(), "git_command_global outside user_identity.rs");
        }
    }
    for m in rules.judged_chain.find_iter(code) {
        report(m.start(), "current_dir on a judged builder");
    }
    for c in rules.judged_bind.captures_iter(code) {
        let at = c.get(0).unwrap().end();
        // The rest of the enclosing block.
        let mut depth = 0i32;
        let mut end = shape.len();
        for (k, ch) in shape.bytes().enumerate().skip(at) {
            if ch == b'{' {
                depth += 1;
            } else if ch == b'}' {
                depth -= 1;
                if depth < 0 {
                    end = k;
                    break;
                }
            }
        }
        let retarget = Regex::new(&format!(r"\b{}\s*\.\s*current_dir\s*\(", regex::escape(&c[1]))).unwrap();
        if let Some(m) = retarget.find(&code[at..end]) {
            report(at + m.start(), "current_dir on a variable bound from a judged builder");
        }
    }
    violations
}

#[test]
fn no_production_spawn_bypasses_the_judged_builders() {
    let mut violations: Vec<String> = Vec::new();
    for s in production_sources() {
        violations.extend(violations_in(&s.rel, &s.scanned));
    }
    assert!(
        violations.is_empty(),
        "{} production spawn-site violation(s):\n{}",
        violations.len(),
        violations.join("\n")
    );
}

/// Each rule fires on a known-bad snippet and stays quiet on its allowed form (the scan could otherwise pass vacuously).
#[test]
fn every_rule_fires_on_a_known_bad_snippet() {
    let bad = |src: &str| violations_in("crates/codegen/fuigo-x/src/lib.rs", &scan_file(src));
    for src in [
        "fn f() { std::process::Command::new(\"git\"); }",
        "fn f() { tokio::process::Command :: new ( \"jj\" ); }",
        "fn f() { Command::new(\n    \"direnv\"\n); }",
        "fn f(git: &Path) { Command::new(git); }",
        "fn f() { Command::new(&git_bin); }",
        "fn f() { let p = git_bin(); }",
        "fn f() { std::env::var_os(\"GIT_BIN_PATH\"); }",
        "fn f() { let c = fuigo_tty_utils::git_command(); }",
        "fn f() { let c = git_command_locking(); }",
        "fn f() { let c = git_command_at(p); }",
        "fn f() { let c = git_command_user_invoked(d); }",
        "fn f() { let c = git_command_global(); }",
        "fn f(d: &Path) { let mut c = git_command_in(d)?; c.current_dir(\"/x\"); }",
        "fn f(d: &Path) { git_command_in(d)?.current_dir(\"/x\"); }",
    ] {
        assert!(!bad(src).is_empty(), "no violation for: {src}");
    }
    for src in [
        "fn f(d: &Path) { let mut c = git_command_in(d)?; c.arg(\"x\"); }",
        "fn f() { sandbox.git_command(); }",
        "// Command::new(\"git\")\nfn f() {}",
        "#[cfg(test)]\nmod tests { fn t() { Command::new(\"git\"); } }",
        "fn f() { Command::new(\"github\"); Command::new(program); }",
    ] {
        assert!(bad(src).is_empty(), "unexpected violation for: {src}: {:?}", bad(src));
    }
    let allowed = violations_in(USER_INVOKED_FILES[0], &scan_file("fn f() { git_command_user_invoked(d); }"));
    assert!(allowed.is_empty(), "{allowed:?}");
    let allowed = violations_in(GLOBAL_GIT_FILES[0], &scan_file("fn f() { git_command_global(); }"));
    assert!(allowed.is_empty(), "{allowed:?}");
    let allowed = violations_in(GIT_BIN_PATH_READS[0].0, &scan_file("fn f() { env::var_os(\"GIT_BIN_PATH\"); }"));
    assert!(allowed.is_empty(), "{allowed:?}");
}

#[test]
fn every_binary_entry_installs_the_judge() {
    let root = repo_root();
    let mut missing = Vec::new();
    for (rel, installer) in JUDGE_INSTALLERS {
        let src = std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
        let (code, _) = lex(&src);
        if !code.contains(installer) {
            missing.push(format!("{rel}:1: never calls {installer}"));
        }
    }
    assert!(missing.is_empty(), "binary entries without the judge:\n{}", missing.join("\n"));
}
