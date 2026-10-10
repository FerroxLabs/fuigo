//! P198 part G proof tests, shared by the four search tools (fuigo grep, OpenCode grep and glob, Codex grep_files).
//!
//! This module uses only the tools' public entry points, so the same file also compiles on the base branch
//! `hub/strike/p198-hl`, where `P198_WRITE_GOLDEN=<file>` writes `search_proof_golden.txt` (the no-rules outputs of the
//! base code). At the tip the test `no_rules_outputs_are_the_bases` compares byte for byte.
use std::path::{Path, PathBuf};

use crate::implementations::codex::grep_files::{CodexGrepFilesInput, CodexGrepFilesTool};
use crate::implementations::fuigo_build::grep::{GrepSearchInput, GrepTool as FuigoGrep, OutputMode};
use crate::implementations::opencode::glob::{GlobInput, GlobTool};
use crate::implementations::opencode::grep::{GrepInput, GrepTool as OcGrep};
use crate::types::resources::{Cwd, DenyReadGlobs, Resources};
use crate::types::tool_metadata::test_ctx;

pub(crate) struct Fx {
    _tmp: tempfile::TempDir,
    pub root: PathBuf,
}

/// The proof tree. `secrets/` is the directory the rules deny in the error tests; it exists in every tree so that
/// the no-rules outputs of the base and of the tip are over the same files.
pub(crate) fn fx() -> Fx {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = dunce::canonicalize(tmp.path()).unwrap().join("w");
    let put = |rel: &str, body: Vec<u8>| {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    };
    let filler: String = (0..5000).map(|_| format!("{}\n", "a".repeat(99))).collect(); // ~500 KB, beyond the first buffer
    put("README", b"FAKE root readme\n".to_vec());
    put("src/README", b"FAKE src readme\n".to_vec());
    put("src/a.txt", b"one\nFAKE in src a\nthree\nFAKE two words here\n".to_vec());
    put("src/sub/b.txt", b"FAKE in sub b\n".to_vec());
    put("text.txt", b"FAKE text\nother\n".to_vec());
    put("sp ace.txt", b"FAKE spaced name\n".to_vec());
    put("long.txt", format!("FAKE{}\nFAKE short\n", "x".repeat(2000)).into_bytes());
    put("bin_before.bin", b"FAKE before\0tail\n".to_vec());
    put("bin_both.bin", b"FAKE one\0FAKE two\n".to_vec());
    put("bin_off7.bin", b"abcdefg\0FAKE after\n".to_vec());
    put("far.bin", format!("FAKE early\n{filler}\0 tail\n").into_bytes());
    put("secrets/k.txt", b"FAKE_DENIED\n".to_vec());
    std::os::unix::fs::symlink("src/sub", root.join("link")).unwrap();
    Fx { _tmp: tmp, root }
}

pub(crate) const BIN_FILES: [&str; 4] = ["bin_before.bin", "bin_both.bin", "bin_off7.bin", "far.bin"];

fn resources(cwd: &Path, deny: &Option<Vec<String>>) -> Resources {
    let mut r = Resources::new();
    r.insert(Cwd(cwd.to_path_buf()));
    if let Some(d) = deny {
        r.insert(DenyReadGlobs(d.clone()));
    }
    r
}

/// One search, as the text a model sees.
#[derive(Clone)]
pub(crate) struct Call {
    pub path: Option<String>,
    pub pattern: String,
    pub deny: Option<Vec<String>>,
}

pub(crate) async fn fuigo_text(cwd: &Path, c: &Call, mode: OutputMode, extra: u8) -> String {
    let mut input = GrepSearchInput {
        pattern: c.pattern.clone(),
        path: c.path.clone(),
        glob: None,
        output_mode: Some(mode),
        before_context: None,
        after_context: None,
        context: None,
        case_insensitive: false,
        r#type: None,
        head_limit: None,
        multiline: false,
    };
    match extra {
        1 => input.context = Some(1),
        2 => input.glob = Some("*.txt".to_string()),
        3 => input.case_insensitive = true,
        _ => {}
    }
    let out = fuigo_tool_runtime::Tool::run(&FuigoGrep, test_ctx(resources(cwd, &c.deny).into_shared()), input)
        .await
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

pub(crate) async fn oc_grep_text(cwd: &Path, c: &Call, include: Option<&str>) -> String {
    let out = fuigo_tool_runtime::Tool::run(
        &OcGrep,
        test_ctx(resources(cwd, &c.deny).into_shared()),
        GrepInput { pattern: c.pattern.clone(), path: c.path.clone(), include: include.map(str::to_string) },
    )
    .await
    .unwrap();
    // stdout and the stderr the model is shown
    format!("{}\n--stderr--\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

pub(crate) async fn oc_glob_text(cwd: &Path, c: &Call) -> String {
    let out = fuigo_tool_runtime::Tool::run(
        &GlobTool,
        test_ctx(resources(cwd, &c.deny).into_shared()),
        GlobInput { pattern: c.pattern.clone(), path: c.path.clone() },
    )
    .await
    .unwrap();
    format!("{}\ncount={} total={}", out.tool_output_for_prompt, out.count, out.total_count)
}

pub(crate) async fn codex_text(cwd: &Path, c: &Call, include: Option<&str>) -> String {
    let out = fuigo_tool_runtime::Tool::run(
        &CodexGrepFilesTool,
        test_ctx(resources(cwd, &c.deny).into_shared()),
        CodexGrepFilesInput { pattern: c.pattern.clone(), include: include.map(str::to_string), path: c.path.clone(), limit: 100 },
    )
    .await
    .unwrap();
    use crate::types::output::CodexGrepFilesOutput as O;
    match out {
        O::Matches { content, file_count } => format!("{content}\ncount={file_count}"),
        other => format!("{other:?}"),
    }
}

/// Every output a tool gives for the call, labelled; ripgrep walks in parallel, so lines are sorted.
pub(crate) async fn all_outputs(root: &Path, c: &Call) -> Vec<(String, String)> {
    let norm = |s: String| {
        let mut lines: Vec<String> = s.replace(root.to_str().unwrap(), "<CWD>").lines().map(str::to_string).collect();
        lines.sort();
        lines.join("\n")
    };
    let mut v = Vec::new();
    for (name, mode) in [("content", OutputMode::Content), ("files", OutputMode::FilesWithMatches), ("count", OutputMode::Count)] {
        for extra in 0..4u8 {
            v.push((format!("fuigo-{name}-{extra}"), norm(fuigo_text(root, c, mode.clone(), extra).await)));
        }
    }
    v.push(("oc-grep".into(), norm(oc_grep_text(root, c, None).await)));
    v.push(("oc-grep-include".into(), norm(oc_grep_text(root, c, Some("*.txt")).await)));
    v.push(("codex".into(), norm(codex_text(root, c, None).await)));
    v.push(("codex-include".into(), norm(codex_text(root, c, Some("*.txt")).await)));
    v
}

/// The search paths the proofs use: no path, `.`, `./src`, `link/../README` (a symlink in the middle), an absolute
/// directory, a plain file and every binary shape as an explicit file.
pub(crate) fn path_table(root: &Path) -> Vec<Option<String>> {
    let mut v: Vec<Option<String>> = vec![
        None,
        Some(".".into()),
        Some("./src".into()),
        Some("link/../README".into()),
        Some(root.join("src").display().to_string()),
        Some("text.txt".into()),
        Some("sp ace.txt".into()),
        Some("long.txt".into()),
    ];
    v.extend(BIN_FILES.iter().map(|b| Some((*b).to_string())));
    v
}

pub(crate) const PATTERNS: [&str; 2] = ["FAKE", "FAKE two words"];

/// The whole table for `deny`: `label -> output`.
pub(crate) async fn table(root: &Path, deny: &Option<Vec<String>>) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    for path in path_table(root) {
        for pat in PATTERNS {
            let c = Call { path: path.clone(), pattern: pat.to_string(), deny: deny.clone() };
            for (tool, out) in all_outputs(root, &c).await {
                rows.push((format!("{tool} | path={path:?} | pat={pat:?}").replace(root.to_str().unwrap(), "<CWD>"), out));
            }
        }
    }
    for path in [None, Some(".".to_string()), Some("./src".to_string()), Some("link/../README".to_string()), Some("src".to_string())] {
        for pat in ["**/*", "*.txt", "*.bin", "sp ace*"] {
            let c = Call { path: path.clone(), pattern: pat.to_string(), deny: deny.clone() };
            let out = oc_glob_text(root, &c).await;
            let mut lines: Vec<String> = out.replace(root.to_str().unwrap(), "<CWD>").lines().map(str::to_string).collect();
            lines.sort();
            rows.push((format!("glob | path={path:?} | pat={pat:?}"), lines.join("\n")));
        }
    }
    rows
}

fn render(rows: &[(String, String)]) -> String {
    rows.iter().map(|(k, v)| format!("=== {k}\n{v}\n")).collect()
}

const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/util/search_proof_golden.txt");

/// Writes the golden file when `P198_WRITE_GOLDEN` names one (run once on the base branch); otherwise it is a no-op.
#[tokio::test(flavor = "current_thread")]
async fn write_golden_when_asked() {
    if let Ok(dest) = std::env::var("P198_WRITE_GOLDEN") {
        let f = fx();
        std::fs::write(dest, render(&table(&f.root, &None).await)).unwrap();
    }
}

/// ITEM 1: with no rules (no object, and an empty list) every tool prints byte for byte what the BASE code printed
/// for the same tree (`search_proof_golden.txt`, captured at `hub/strike/p198-hl`).
#[tokio::test(flavor = "current_thread")]
async fn no_rules_outputs_are_the_bases() {
    let golden = std::fs::read_to_string(GOLDEN).expect("golden file captured on the base branch");
    let f = fx();
    for deny in [None, Some(Vec::new())] {
        let got = render(&table(&f.root, &deny).await);
        if got != golden {
            let (g, w): (Vec<&str>, Vec<&str>) = (got.lines().collect(), golden.lines().collect());
            let i = g.iter().zip(&w).position(|(a, b)| a != b).unwrap_or(g.len().min(w.len()));
            panic!("differs from the base at line {i}: got {:?} want {:?}", g.get(i), w.get(i));
        }
    }
}

/// ITEM 2: a rule that denies nothing prints what no rule prints, for every tool, mode, path and binary shape.
#[tokio::test(flavor = "current_thread")]
async fn a_rule_that_denies_nothing_prints_the_no_rules_text() {
    let f = fx();
    let none = table(&f.root, &None).await;
    let rule = table(&f.root, &Some(vec!["nothing-here/**".to_string()])).await;
    assert_eq!(none.len(), rule.len());
    let mut bad = Vec::new();
    for ((k, a), (_, b)) in none.iter().zip(&rule) {
        if a != b {
            bad.push(format!("{k}\n--- none\n{a}\n--- rule\n{b}"));
        }
    }
    assert!(bad.is_empty(), "{} of {} differ:\n{}", bad.len(), none.len(), bad.iter().take(3).cloned().collect::<Vec<_>>().join("\n=====\n"));
}

/// ITEM 3: ripgrep's own regex error is passed through with a rule present exactly as without one.
#[tokio::test(flavor = "current_thread")]
async fn a_regex_error_is_the_same_with_and_without_rules() {
    let f = fx();
    for path in [None, Some("src".to_string())] {
        let plain = Call { path: path.clone(), pattern: "(".into(), deny: None };
        let ruled = Call { deny: Some(vec!["secrets/**".to_string()]), ..plain.clone() };
        let (a, b) = (all_outputs(&f.root, &plain).await, all_outputs(&f.root, &ruled).await);
        for ((k, x), (_, y)) in a.iter().zip(&b) {
            assert_eq!(x, y, "{k} path={path:?}");
        }
        // control: the error text really is ripgrep's (not an empty result on both sides)
        let oc = &a.iter().find(|(k, _)| k == "oc-grep").unwrap().1;
        assert!(oc.contains("regex parse error") || oc.contains("No files found"), "{oc}");
    }
}

/// Re-runs `test` as the user `nobody` when the process is root (root bypasses mode 000). Returns true when it did.
pub(crate) fn reexec_as_nobody(test: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } != 0 {
        return false;
    }
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    let exe = dir.path().join("testbin");
    std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    // Another test thread may fork while the copy is still open for writing ("Text file busy"): retry.
    let (out, text) = (0..20)
        .map(|_| {
            let out = std::process::Command::new("setpriv")
                .args(["--reuid=nobody", "--regid=nogroup", "--clear-groups"])
                .arg(&exe)
                .args(["--exact", test, "--nocapture", "--test-threads=1"])
                .env("TMPDIR", dir.path())
                .output()
                .expect("setpriv is required for this test");
            let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
            if text.contains("Text file busy") {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            (out, text)
        })
        .find(|(_, t)| !t.contains("Text file busy"))
        .expect("the test binary stayed busy");
    assert!(out.status.success() && text.contains("1 passed"), "as nobody: {text}");
    true
}

/// ITEM 3: a mode-000 file and directory under a DENIED directory make ripgrep fail with permission errors; the output
/// shows neither the denied path nor ripgrep's stderr text. Runs as `nobody` (root bypasses mode 000).
#[tokio::test(flavor = "current_thread")]
async fn a_unreadable_file_under_a_denied_directory_shows_nothing() {
    use std::os::unix::fs::PermissionsExt;
    if reexec_as_nobody("util::search_proof_tests::a_unreadable_file_under_a_denied_directory_shows_nothing") {
        return;
    }
    let f = fx();
    let locked = f.root.join("secrets/locked.txt");
    std::fs::write(&locked, "FAKE_LOCKED\n").unwrap();
    std::fs::create_dir_all(f.root.join("secrets/lockeddir")).unwrap();
    std::fs::write(f.root.join("secrets/lockeddir/in.txt"), "FAKE_LOCKED_IN\n").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    std::fs::set_permissions(f.root.join("secrets/lockeddir"), std::fs::Permissions::from_mode(0o000)).unwrap();
    // control (no rules): ripgrep's stderr does name the locked path, so the assertions below are not vacuous
    let plain = Call { path: None, pattern: "FAKE".into(), deny: None };
    let rg = std::process::Command::new(std::env::var("RG_BIN_PATH").unwrap_or_else(|_| "rg".into()))
        .args(["FAKE", "."])
        .current_dir(&f.root)
        .output()
        .unwrap();
    let control = String::from_utf8_lossy(&rg.stderr).into_owned();
    // No rules: the tools behave as the base. ripgrep's stderr is shown (fuigo grep; OpenCode and Codex pass --no-messages) and Codex reports the failure
    // although files matched. A tool that took the rules path with no rules would hide both.
    let fuigo_none = fuigo_text(&f.root, &plain, OutputMode::Content, 0).await;
    assert!(fuigo_none.contains("Permission denied"), "fuigo grep, no rules: {fuigo_none}");
    let codex_none = codex_text(&f.root, &plain, None).await;
    assert!(codex_none.contains("rg failed"), "codex, no rules: {codex_none}");
    let ruled = Call { deny: Some(vec!["secrets/**".to_string()]), ..plain };
    let outs = all_outputs(&f.root, &ruled).await;
    std::fs::set_permissions(f.root.join("secrets/lockeddir"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(control.contains("locked") || control.contains("Permission denied"), "control: {control}");
    for (k, out) in outs {
        for bad in ["locked", "Permission denied", "secrets", "FAKE_DENIED", "k.txt"] {
            assert!(!out.contains(bad), "{k}: `{bad}` leaked: {out}");
        }
    }
}

/// The one KNOWN difference between the two paths: a file name holding a newline. Without rules the text output is cut
/// at the newline (the base behaviour, two entries); with rules the typed records carry the whole name (one entry) for
/// Codex (glob and OpenCode grep re-parse text by lines in both paths).
#[tokio::test(flavor = "current_thread")]
async fn a_newline_in_a_name_is_one_entry_only_under_rules() {
    let f = fx();
    std::fs::write(f.root.join("nl\nname.txt"), "FAKE newline name\n").unwrap();
    let count = |s: &str| s.rsplit("count=").next().unwrap().split_whitespace().next().unwrap().parse::<usize>().unwrap();
    for deny in [None, Some(vec!["nothing-here/**".to_string()])] {
        let g = oc_glob_text(&f.root, &Call { path: None, pattern: "**/*.txt".into(), deny: deny.clone() }).await;
        let c = codex_text(&f.root, &Call { path: None, pattern: "FAKE".into(), deny: deny.clone() }, Some("*.txt")).await;
        let (g, c) = (count(&g), count(&c));
        // text.txt, sp ace.txt, long.txt, secrets/k.txt, src/a.txt, src/sub/b.txt and the newline name (one or two)
        // glob parses the (re-rendered) text by lines again, so it counts the split name in both paths
        let want_codex = if deny.is_none() { 8 } else { 7 };
        assert_eq!((g, c), (8, want_codex), "deny={deny:?}");
    }
}

// ── ITEM 1: the argv every tool hands to ripgrep with no rules is the base's ──────────────────────────────────────

const GOLDEN_ARGV: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/util/search_proof_golden_argv.txt");

/// Child half: runs the whole table with the env-named rules and a wrapper `rg` that logs its argv. Does nothing unless
/// `P198_ARGV_OUT` is set (it is set only by the parent below, or by hand on the base branch).
#[tokio::test(flavor = "current_thread")]
async fn argv_child() {
    let Ok(out) = std::env::var("P198_ARGV_OUT") else { return };
    let deny = match std::env::var("P198_ARGV_DENY").as_deref() {
        Ok("empty") => Some(Vec::new()),
        Ok("nothing") => Some(vec!["nothing-here/**".to_string()]),
        _ => None,
    };
    let f = fx();
    let _ = table(&f.root, &deny).await;
    let raw = std::fs::read_to_string(std::env::var("P198_ARGV_LOG").unwrap()).unwrap_or_default();
    std::fs::write(out, raw.replace(f.root.to_str().unwrap(), "<CWD>")).unwrap();
}

/// Runs `argv_child` in a fresh process (the ripgrep path is cached per process) with a logging wrapper as `rg`.
pub(crate) fn argv_of_run(test: &str, deny: &str) -> String {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::TempDir::new().unwrap();
    let (log, out, wrapper) = (dir.path().join("log"), dir.path().join("out"), dir.path().join("rg"));
    let rg = std::env::var("RG_BIN_PATH").unwrap_or_else(|_| "/usr/bin/rg".into());
    std::fs::write(
        &wrapper,
        format!("#!/bin/sh\n{{ for a in \"$@\"; do printf '%s\\037' \"$a\"; done; printf '\\n'; }} >> '{}'\nexec '{rg}' \"$@\"\n", log.display()),
    )
    .unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
    let st = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--test-threads=1"])
        .env("RG_BIN_PATH", &wrapper)
        .env("P198_ARGV_OUT", &out)
        .env("P198_ARGV_LOG", &log)
        .env("P198_ARGV_DENY", deny)
        .output()
        .unwrap();
    assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stdout));
    std::fs::read_to_string(out).expect("the child wrote the argv log")
}

/// Writes the base's argv log when `P198_WRITE_GOLDEN_ARGV` names a file (run once on the base branch).
#[test]
fn write_golden_argv_when_asked() {
    if let Ok(dest) = std::env::var("P198_WRITE_GOLDEN_ARGV") {
        std::fs::write(dest, argv_of_run("util::search_proof_tests::argv_child", "none")).unwrap();
    }
}

/// With no rules (no object, and an empty list) every call of every tool spawns ripgrep with exactly the argv the base
/// code used, for the whole path / pattern / flag table (`search_proof_golden_argv.txt`, captured at `hub/strike/p198-hl`).
#[test]
fn no_rules_spawn_ripgrep_with_the_bases_argv() {
    let golden = std::fs::read_to_string(GOLDEN_ARGV).expect("argv golden captured on the base branch");
    assert!(golden.lines().count() > 300, "{} lines", golden.lines().count());
    for deny in ["none", "empty"] {
        let got = argv_of_run("util::search_proof_tests::argv_child", deny);
        assert!(got == golden, "argv differs from the base ({deny}): first difference at line {:?}", got.lines().zip(golden.lines()).position(|(a, b)| a != b));
    }
    // control: with a rule ripgrep gets `--json` (the argv log really tells the two paths apart)
    let ruled = argv_of_run("util::search_proof_tests::argv_child", "nothing");
    assert!(ruled.contains("--json") && !golden.contains("--json"));
}

/// P198 part G, count mode (owner override). One count-mode search of `root` with a pattern, `-U` or not, and a rule list.
async fn count_text(root: &Path, pattern: &str, multiline: bool, deny: &Option<Vec<String>>) -> String {
    let input = GrepSearchInput {
        pattern: pattern.to_string(),
        path: None,
        glob: None,
        output_mode: Some(OutputMode::Count),
        before_context: None,
        after_context: None,
        context: None,
        case_insensitive: false,
        r#type: None,
        head_limit: None,
        multiline,
    };
    let out = fuigo_tool_runtime::Tool::run(&FuigoGrep, test_ctx(resources(root, deny).into_shared()), input)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut lines: Vec<&str> = text.lines().collect();
    lines.sort_unstable();
    lines.join("\n")
}

fn count_tree() -> Fx {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = dunce::canonicalize(tmp.path()).unwrap().join("w");
    std::fs::create_dir_all(&root).unwrap();
    for (n, b) in [
        ("s.txt", &b"FAKE FAKE FAKE\n"[..]),
        ("m.txt", b"FAKE a\nX\nZZZ\nFAKE c\nY\n"),
        ("e.txt", b"a\nb\nc\n"),
        ("t.txt", b"ab\nab ab\n"),
        ("bin.txt", b"FAKE x\0FAKE\nFAKE\n"),
    ] {
        std::fs::write(root.join(n), b).unwrap();
    }
    Fx { _tmp: tmp, root }
}

const COUNT_CASES: [(&str, bool); 9] = [
    ("FAKE", false),
    ("FAKE", true),
    ("FAKE|\\n", true),
    ("FAKE a\\nX|FAKE c\\nY", true),
    ("ab", true),
    ("^", false),
    ("x*", true),
    ("FAKE.*FAKE", true),
    ("FAKE|ab", false),
];

/// What the REAL ripgrep binary prints for the count flag fuigo grep exposes (`-c`), run with the flags the tool passes
/// (`-U --multiline-dotall` for a multiline search): file name -> count. This is the oracle; no number is written here.
fn real_rg_counts(root: &Path, pattern: &str, multiline: bool) -> std::collections::BTreeMap<String, String> {
    let mut cmd = std::process::Command::new(std::env::var("RG_BIN_PATH").unwrap_or_else(|_| "rg".into()));
    cmd.arg("-c");
    if multiline {
        cmd.arg("-U").arg("--multiline-dotall");
    }
    let out = cmd.arg("-e").arg(pattern).arg(root).output().unwrap();
    count_lines(&String::from_utf8_lossy(&out.stdout))
}

/// The `path:count` lines of a count-mode output, keyed by file name.
fn count_lines(text: &str) -> std::collections::BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| l.rsplit_once(':'))
        .filter(|(path, n)| path.ends_with(".txt") && n.parse::<usize>().is_ok())
        .map(|(path, n)| (path.rsplit(['/', '\\']).next().unwrap().to_string(), n.to_string()))
        .collect()
}

/// With a rule that denies nothing, count mode prints exactly what the real `rg -c` prints on the same fixture: a
/// single-line pattern, a multiline pattern that crosses a newline (where `rg -c` counts matches), and files with
/// several matches on one line (`s.txt`, `t.txt`; where `rg -c` counts lines). Compared against the binary itself.
#[tokio::test(flavor = "current_thread")]
async fn count_mode_under_rules_equals_rg_dash_c() {
    let f = count_tree();
    let rule = Some(vec!["nothing-here/**".to_string()]);
    let mut differing = std::collections::BTreeSet::new();
    for (pat, ml) in COUNT_CASES {
        let oracle = real_rg_counts(&f.root, pat, ml);
        let none = count_text(&f.root, pat, ml, &None).await;
        let with = count_text(&f.root, pat, ml, &rule).await;
        assert_eq!(count_lines(&with), oracle, "pattern {pat:?} multiline {ml}: {with}");
        assert_eq!(none, with, "pattern {pat:?} multiline {ml}");
        differing.insert(oracle);
    }
    // Not vacuous: ripgrep found something, and the cases do not all give one answer.
    assert!(differing.iter().any(|m| !m.is_empty()) && differing.len() > 1, "{differing:?}");
}

/// A denied file has no count line; every other line is what it was.
#[tokio::test(flavor = "current_thread")]
async fn count_mode_under_a_deny_rule_drops_only_the_denied_file() {
    let f = count_tree();
    let rule = Some(vec!["**/m.txt".to_string()]);
    for (pat, ml) in COUNT_CASES {
        let none = count_text(&f.root, pat, ml, &None).await;
        let with = count_text(&f.root, pat, ml, &rule).await;
        let counts = |t: &str| -> Vec<String> { t.lines().filter(|l| l.contains(".txt:")).map(str::to_string).collect() };
        let want: Vec<String> = counts(&none).into_iter().filter(|l| !l.contains("m.txt")).collect();
        assert_eq!(want, counts(&with), "pattern {pat:?} multiline {ml}");
        // The total the tool prints leaves the denied file out.
        let sum: usize = want.iter().map(|l| l.rsplit(':').next().unwrap().parse::<usize>().unwrap()).sum();
        if !want.is_empty() {
            assert!(with.contains(&format!("Found {sum} across {} files", want.len())), "pattern {pat:?}: {with}");
        }
        assert!(!with.contains("m.txt"));
    }
}
