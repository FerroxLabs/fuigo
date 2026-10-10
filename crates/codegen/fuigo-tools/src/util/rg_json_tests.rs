//! P198 part G reopened: `RgJsonStream` attributes every record by the `path` it carries (fake ripgrep streams).
use super::rg_json::{RgJsonMode, RgJsonStream};
use crate::util::read_deny::ResultFilter;
use base64::Engine as _;

pub(crate) struct Fx {
    pub(crate) _tmp: tempfile::TempDir,
    pub(crate) cwd: std::path::PathBuf,
}

pub(crate) fn fx() -> Fx {
    let tmp = tempfile::TempDir::new().unwrap();
    let cwd = dunce::canonicalize(tmp.path()).unwrap();
    for rel in ["src/a.rs", "src/b.rs", "src/c.rs", "secrets/s.txt", "secrets/t.txt"] {
        let p = cwd.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, "x\n").unwrap();
    }
    Fx { _tmp: tmp, cwd }
}

fn stream(f: &Fx, mode: RgJsonMode) -> RgJsonStream {
    RgJsonStream::new(mode, ResultFilter::new(&f.cwd, &["secrets/**".to_string()]))
}

fn p(path: &str) -> String {
    format!("{{\"text\":\"{path}\"}}")
}
fn pb(path: &str) -> String {
    format!("{{\"bytes\":\"{}\"}}", base64::engine::general_purpose::STANDARD.encode(path))
}
fn begin(path: &str) -> String {
    format!("{{\"type\":\"begin\",\"data\":{{\"path\":{}}}}}", p(path))
}
fn rec(kind: &str, path: &str, n: u64, text: &str) -> String {
    format!(
        "{{\"type\":\"{kind}\",\"data\":{{\"path\":{},\"lines\":{{\"text\":\"{text}\\n\"}},\"line_number\":{n},\"absolute_offset\":0,\"submatches\":[]}}}}",
        p(path)
    )
}
fn end(path: &str, matched: u64) -> String {
    format!(
        "{{\"type\":\"end\",\"data\":{{\"path\":{},\"binary_offset\":null,\"stats\":{{\"matched_lines\":{matched},\"matches\":{matched}}}}}}}",
        p(path)
    )
}
pub(crate) fn run(f: &Fx, mode: RgJsonMode, lines: &[String]) -> String {
    let mut s = stream(f, mode);
    let mut text = lines.join("\n");
    text.push('\n');
    let mut out = s.feed(text.as_bytes());
    out.extend(s.finish());
    String::from_utf8(out).unwrap()
}
fn count(hay: &str, needle: &str) -> usize {
    hay.matches(needle).count()
}

pub(crate) fn interleaved_allowed() -> Vec<String> {
    vec![
        begin("src/a.rs"),
        begin("src/b.rs"),
        rec("match", "src/a.rs", 1, "A1"),
        rec("match", "src/b.rs", 5, "B5"),
        rec("context", "src/b.rs", 6, "B6ctx"),
        rec("match", "src/a.rs", 2, "A2"),
        end("src/b.rs", 1),
        end("src/a.rs", 2),
    ]
}

pub(crate) fn interleaved_with_denied() -> Vec<String> {
    vec![
        begin("secrets/s.txt"),
        begin("src/a.rs"),
        rec("match", "secrets/s.txt", 1, "DENIEDLINE1"),
        rec("match", "src/a.rs", 1, "A1"),
        rec("match", "secrets/s.txt", 2, "DENIEDLINE2"),
        rec("match", "src/a.rs", 2, "A2"),
        end("secrets/s.txt", 2),
        rec("context", "src/a.rs", 3, "A3ctx"),
        end("src/a.rs", 2),
    ]
}

#[test]
fn interleaved_records_of_two_allowed_files_all_appear_once_under_their_file() {
    let f = fx();
    let out = run(&f, RgJsonMode::Heading { context: true }, &interleaved_allowed());
    for needle in ["A1", "A2", "B5", "B6ctx"] {
        assert_eq!(count(&out, needle), 1, "{needle} once in {out:?}");
    }
    let blocks: Vec<&str> = out.trim_end().split("\n\n").collect();
    assert_eq!(blocks.len(), 2, "{out:?}");
    let ablock = blocks.iter().find(|b| b.starts_with("src/a.rs\n")).expect("a block");
    let bblock = blocks.iter().find(|b| b.starts_with("src/b.rs\n")).expect("b block");
    assert!(ablock.contains("1:A1") && ablock.contains("2:A2") && !ablock.contains("B5"), "{out:?}");
    assert!(bblock.contains("5:B5") && bblock.contains("6-B6ctx") && !bblock.contains("A1"), "{out:?}");
    assert_eq!(count(&out, "src/a.rs"), 1, "{out:?}");
    assert_eq!(count(&out, "src/b.rs"), 1, "{out:?}");
    let pipe = run(&f, RgJsonMode::Pipe, &interleaved_allowed());
    for line in ["src/a.rs|1|A1", "src/a.rs|2|A2", "src/b.rs|5|B5"] {
        assert_eq!(count(&pipe, &format!("{line}\n")), 1, "{pipe:?}");
    }
    let files = run(&f, RgJsonMode::Files, &interleaved_allowed());
    assert_eq!(count(&files, "src/a.rs\n"), 1);
    assert_eq!(count(&files, "src/b.rs\n"), 1);
    let counts = run(&f, RgJsonMode::Count, &interleaved_allowed());
    assert!(counts.contains("src/a.rs:2\n") && counts.contains("src/b.rs:1\n"), "{counts:?}");
}

#[test]
fn a_denied_file_interleaved_with_an_allowed_one_leaves_no_trace_and_the_allowed_file_is_complete() {
    let f = fx();
    for mode in [RgJsonMode::Heading { context: true }, RgJsonMode::Pipe, RgJsonMode::Files, RgJsonMode::Count] {
        let out = run(&f, mode, &interleaved_with_denied());
        for hidden in ["DENIEDLINE", "secrets", "s.txt"] {
            assert!(!out.contains(hidden), "{mode:?} leaked {hidden}: {out:?}");
        }
        assert!(out.contains("src/a.rs"), "{mode:?}: {out:?}");
    }
    let out = run(&f, RgJsonMode::Heading { context: true }, &interleaved_with_denied());
    assert!(out.contains("1:A1") && out.contains("2:A2") && out.contains("3-A3ctx"), "{out:?}");
    assert!(run(&f, RgJsonMode::Count, &interleaved_with_denied()).contains("src/a.rs:2\n"));
}

#[test]
fn a_match_for_a_path_that_never_had_a_begin_is_judged_by_its_own_path() {
    let f = fx();
    let lines = vec![
        rec("match", "src/c.rs", 4, "C4"),
        rec("match", "secrets/t.txt", 1, "DENIEDLINE"),
        end("src/c.rs", 1),
        end("secrets/t.txt", 1),
    ];
    let out = run(&f, RgJsonMode::Heading { context: false }, &lines);
    assert!(out.contains("src/c.rs\n4:C4\n"), "{out:?}");
    assert!(!out.contains("DENIEDLINE") && !out.contains("secrets"), "{out:?}");
    // and with no `end` at all: still the allowed one only
    let out = run(&f, RgJsonMode::Heading { context: false }, &lines[..2]);
    assert!(out.contains("src/c.rs\n4:C4\n") && !out.contains("secrets"), "{out:?}");
}

#[test]
fn paths_given_as_base64_bytes_are_attributed_and_judged_like_text_paths() {
    let f = fx();
    let b = |kind: &str, path: &str, extra: &str| {
        format!("{{\"type\":\"{kind}\",\"data\":{{\"path\":{}{extra}}}}}", pb(path))
    };
    let m = |path: &str, n: u64, text: &str| {
        b("match", path, &format!(",\"lines\":{{\"text\":\"{text}\\n\"}},\"line_number\":{n},\"absolute_offset\":0,\"submatches\":[]"))
    };
    let e = |path: &str| b("end", path, ",\"binary_offset\":null,\"stats\":{\"matched_lines\":1,\"matches\":1}");
    let lines = vec![
        b("begin", "src/a.rs", ""),
        b("begin", "secrets/s.txt", ""),
        m("secrets/s.txt", 1, "DENIEDLINE"),
        m("src/a.rs", 1, "A1"),
        e("secrets/s.txt"),
        e("src/a.rs"),
    ];
    let out = run(&f, RgJsonMode::Heading { context: false }, &lines);
    assert_eq!(out, "src/a.rs\n1:A1\n");
}

#[test]
fn a_begin_without_an_end_at_stream_end_shows_what_was_received_for_allowed_files_only() {
    let f = fx();
    let lines = vec![
        begin("src/a.rs"),
        begin("secrets/s.txt"),
        rec("match", "src/a.rs", 1, "A1"),
        rec("match", "secrets/s.txt", 1, "DENIEDLINE"),
    ];
    let out = run(&f, RgJsonMode::Heading { context: false }, &lines);
    assert_eq!(out, "src/a.rs\n1:A1\n");
    assert_eq!(run(&f, RgJsonMode::Files, &lines), "src/a.rs\n");
    assert_eq!(run(&f, RgJsonMode::Count, &lines), "src/a.rs:1\n");
    assert_eq!(run(&f, RgJsonMode::Pipe, &lines), "src/a.rs|1|A1\n");
}
#[test]
fn buffering_is_bounded_per_file_while_it_is_open() {
    let f = fx();
    let mut s = stream(&f, RgJsonMode::Pipe);
    let big = "x".repeat(100_000);
    let mut text = begin("src/a.rs");
    text.push('\n');
    for n in 1..=200u64 {
        text.push_str(&rec("match", "src/a.rs", n, &big));
        text.push('\n');
    }
    text.push_str(&end("src/a.rs", 200));
    text.push('\n');
    let out = s.feed(text.as_bytes());
    assert!(out.len() <= super::rg_json::MAX_FILE_BUFFER_BYTES, "{}", out.len());
    assert!(out.starts_with(b"src/a.rs|1|"));
}
