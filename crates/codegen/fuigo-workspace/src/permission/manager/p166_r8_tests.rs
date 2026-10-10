//! P166 round 8A (Grok r7 re-audit): the class tripwire judges a DECODED VIEW of the command (ANSI-C decoded, brace
//! and glob expanded, assignment values, `env -C`, here-strings and here-documents, undecodable words), and skips only
//! positively identified input operands. Rows are `(command, blocked)`.

use super::{PermissionState, bash_protected_write_target, evaluate_bash};

fn floor_in(cwd: &std::path::Path, cmd: &str) -> Option<crate::permission::shell_access::ProtectedEditReason> {
    let state = PermissionState::default();
    let evaluation = evaluate_bash(cmd, &state, true);
    bash_protected_write_target(&evaluation, cwd, None)
}

fn check(rows: &[(&str, bool)]) {
    let project = tempfile::tempdir().unwrap();
    let cwd = project.path();
    std::fs::create_dir_all(cwd.join("out")).unwrap();
    std::fs::create_dir_all(cwd.join("src")).unwrap();
    let mut wrong = Vec::new();
    for (cmd, blocked) in rows {
        let got = floor_in(cwd, cmd);
        if got.is_some() != *blocked {
            wrong.push(format!("{cmd}: expected blocked={blocked}, got {got:?}"));
        }
    }
    assert!(wrong.is_empty(), "protected floor mismatches:\n{}", wrong.join("\n"));
}

const PY_ENV: &str = "python3 -c 'import os; open(os.environ[\"VAR\"],\"w\").write(\"p\")'";
const PY_STDIN: &str = "python3 -c 'import sys; open(sys.stdin.read().strip(),\"w\").write(\"x\")'";

/// A1 (audit HIGH 1): brace expansion of a split path.
#[test]
fn p166_r8_a1_brace_expansion() {
    check(&[
        ("touch {x,.git}/hooks/pre-commit", true),
        ("touch .{mcp,zz}.json", true),
        ("touch {x,{y,.git}}/hooks/pre-commit", true),
        ("touch {.git/hooks/pre-commit,x}", true),
        ("python3 -c 'import sys; [open(a,\"w\") for a in sys.argv[1:]]' {x,.git}/hooks/pre-commit", true),
        ("gunzip -k .{mcp,zz}.json.gz", true),
        ("touch {x,y}/hooks/pre-commit", false),
        ("printf '%s\\n' {a,b,c}", false),
        ("touch {a,b}.txt", false),
    ]);
}

/// A1: an over-cap expansion fails closed when a fragment could form a protected name.
#[test]
fn p166_r8_a1_brace_over_cap_fails_closed() {
    let many = "{a,b}".repeat(10);
    check(&[
        (&format!("touch {many}.git/hooks/pre-commit"), true),
        // P166 r9 (Grok r8 HIGH 2): an over-cap word cannot be judged, so it takes the floor even without a protected
        // name (round 8 let it through on a needle check that a split name defeats).
        (&format!("touch {many}x"), true),
    ]);
}

/// A2 (HIGH 2): ANSI-C quoting is decoded, not dropped.
#[test]
fn p166_r8_a2_ansi_c_quoting() {
    check(&[
        ("touch $'.git/hooks/pre-commit'", true),
        ("touch $'.git\\x2fhooks\\x2fpre-commit'", true),
        ("touch $'.mcp.json'", true),
        ("gunzip -k $'.mcp.json'.gz", true),
        ("python3 -c $'open(\".git/hooks/pre-commit\",\"w\").write(\"p\")'", true),
        ("touch $'a\\n'", false),
        ("echo $'a\\n'", false),
        ("python3 -c $'print(1)'", false),
    ]);
}

/// A3 (HIGH 3): same-command assignments and `env` assignments.
#[test]
fn p166_r8_a3_assignment_values() {
    let rows = [
        (format!("VAR=.git/hooks/pre-commit {PY_ENV}"), true),
        (format!("env VAR=.git/hooks/pre-commit {PY_ENV}"), true),
        (format!("VAR=.mcp.json {PY_ENV}"), true),
        (format!("VAR='.mcp.json' {PY_ENV}"), true),
        (format!("VAR=$'.mcp.json' {PY_ENV}"), true),
        (format!("env VAR=.mcp.json {PY_ENV}"), true),
        ("FOO=bar make".to_owned(), false),
        ("env NODE_ENV=production node build.js".to_owned(), false),
        (format!("VAR=out/x {PY_ENV}"), false),
    ];
    let refs: Vec<(&str, bool)> = rows.iter().map(|(c, b)| (c.as_str(), *b)).collect();
    check(&refs);
}

/// A4 (HIGH 4): here-strings and here-documents (quoted and unquoted delimiter).
#[test]
fn p166_r8_a4_here_strings_and_documents() {
    let rows = [
        (format!("{PY_STDIN} <<< .mcp.json"), true),
        (format!("{PY_STDIN} <<< '.git/hooks/pre-commit'"), true),
        (format!("{PY_STDIN} <<EOF\n.mcp.json\nEOF"), true),
        (format!("{PY_STDIN} <<'EOF'\n.mcp.json\nEOF"), true),
        (format!("{PY_STDIN} <<-EOF\n\t.git/hooks/pre-commit\nEOF"), true),
        (format!("{PY_STDIN} <<EOF | cat\n.mcp.json\nEOF"), true),
        ("bash <<< 'cp evil .git/hooks/pre-commit'".to_owned(), true),
        ("cat <<< hello".to_owned(), false),
        ("cat <<< .mcp.json".to_owned(), false),
        (format!("{PY_STDIN} <<< hello"), false),
    ];
    let refs: Vec<(&str, bool)> = rows.iter().map(|(c, b)| (c.as_str(), *b)).collect();
    check(&refs);
}

/// A5 (HIGH 5): `env -C DIR` moves the cwd; relative targets are judged against it.
#[test]
fn p166_r8_a5_env_chdir() {
    check(&[
        ("env -C .git/hooks python3 -c 'open(\"pre-commit\",\"w\").write(\"p\")'", true),
        ("env --chdir=.git/hooks python3 -c 'open(\"pre-commit\",\"w\")'", true),
        ("env --chdir .git/hooks python3 x.py pre-commit", true),
        ("env -C.git/hooks python3 x.py pre-commit", true),
        ("env -C src python3 -c 'open(\"../.mcp.json\",\"w\")'", true),
        ("env -C src python3 -c 'open(\"a.txt\",\"w\")'", false),
        ("env -C .git/hooks cat pre-commit", false),
    ]);
}

/// A6 (HIGH 7 and the r7 sweep gap): a separate option value of an options-only program is scanned.
#[test]
fn p166_r8_a6_separate_option_values() {
    check(&[
        ("docker run -v .git/hooks:/h --rm alpine touch /h/pre-commit", true),
        ("podman run --volume .git/hooks:/h alpine ls", true),
        ("scp -o 'UserKnownHostsFile=.mcp.json' host:x out/", true),
        ("wget https://x.invalid -P .mcp.json", true),
        ("docker -H unix:///x cp c:/x .mcp.json", true),
        ("docker --context c cp c:/x .mcp.json", true),
        ("tar -cf a.tar src --index-file .mcp.json", true),
        ("curl --output-dir .mcp.json -O https://x.invalid/f", true),
        ("rsync -a src/ out/ --temp-dir .mcp.json", true),
        ("rsync -a src/ out/ -e 'ssh -E .mcp.json'", true),
        ("rsync -a -b --backup-dir .git/hooks src/ dest/", true),
        ("rsync -a --partial-dir .git/hooks src/ dest/", true),
        ("docker run --rm -v \"$PWD\":/w alpine ls /w", false),
        ("docker run --rm -v \"$PWD/.git/hooks\":/h alpine ls /h", true),
        ("docker build -t x .", false),
        ("tar -cf out.tar src", false),
        ("tar -cf out.tar .mcp.json", false),
        ("curl -o out.bin https://x.invalid/f", false),
        ("wget -P downloads https://x.invalid/f", false),
        ("scp host:x out/", false),
        ("rsync -a src/ dst/ --exclude .git", false),
        // Copying a file NAMED .mcp.json into dest/ creates dest/.mcp.json, a protected name (unchanged from the base).
        ("rsync .mcp.json dest/", true),
        ("rsync -a --verbose .mcp.json dest/", true),
        ("git add .mcp.json", false),
        ("docker cp .mcp.json c:/x", false),
    ]);
}

/// A7 (MEDIUM 4): a reader whose options run commands or write files is a reader for plain operands only.
#[test]
fn p166_r8_a7_reader_options() {
    check(&[
        ("less '+!cp evil .git/hooks/pre-commit' README", true),
        ("less +'!touch .mcp.json' README", true),
        ("less -o .mcp.json README", true),
        ("less --log-file .mcp.json README", true),
        ("rg --pre 'cp x .git/hooks/pre-commit' foo .", true),
        ("bat --pager 'tee .mcp.json' README", true),
        ("awk 'BEGIN{system(\"touch .mcp.json\")}'", true),
        ("sed -n 'e touch .mcp.json' README", true),
        ("less README.md", false),
        ("less .mcp.json", false),
        ("more .mcp.json", false),
        ("sed -n 1,5p .mcp.json", false),
        ("awk '{print $1}' .mcp.json", false),
        ("grep -r hooks .git/hooks", false),
        ("jq . .mcp.json", false),
        ("wc -l ~/.bashrc", false),
    ]);
}

/// A8 (LOW 1): a glob word that can match a protected name names it (decision: the pattern is matched against the
/// names the protected matcher knows; a dot-name needs a leading dot in the pattern, as in bash).
#[test]
fn p166_r8_a8_globs() {
    check(&[
        ("touch .git/hook?", true),
        ("touch .g*/hooks/pre-commit", true),
        ("touch .git/hooks/pre-comm*", true),
        ("touch .mcp.js*", true),
        ("touch .claude/*", true),
        ("touch .git/[h]ooks/x", true),
        ("ls src/*.rs", false),
        ("touch src/*.rs", false),
        ("touch *.txt", false),
        ("cp src/*.rs out/", false),
    ]);
}

/// Item 2: an undecodable word is scanned when decodable, floors only when a protected name remains in its text.
#[test]
fn p166_r8_undecodable_words() {
    check(&[
        ("touch \"$d\"/.git/hooks/pre-commit", true),
        ("touch \"$(pwd)/.mcp.json\"", true),
        ("touch \"$x\"", false),
        ("printf '%s\\n' \"$x\"", false),
        ("python3 -c 'print(1)' \"$x\"", false),
        ("vim docs/my.mcp.json.md", false),
    ]);
}

/// The false-positive suite of round 7 plus the round-8 additions. Prints `FP <command> => <floor>` per command
/// (compare base and tip with `--nocapture`) and asserts the floor stays silent for the non-git commands.
#[test]
fn p166_r8_false_positive_suite() {
    let project = tempfile::tempdir().unwrap();
    let cwd = project.path();
    std::fs::create_dir_all(cwd.join("out")).unwrap();
    std::fs::create_dir_all(cwd.join("src")).unwrap();
    let suite = [
        "ffmpeg -i a.mp4 out/b.mp4", "convert a.png b.png", "zip out.zip src/*", "vim README.md",
        "docker cp c:/x ./out", "git checkout main", "git switch main", "git pull", "git stash pop", "cat ~/.bashrc",
        "grep -r hooks .git/hooks", "ls -la .git/hooks", "rsync -a src/ dst/", "python3 script.py", "node build.js",
        "cp a b", "sed -n 1,5p .mcp.json", "echo $'a\\n'", "printf '%s\\n' {a,b,c}", "FOO=bar make",
        "env NODE_ENV=production node build.js", "cat <<< hello", "ls src/*.rs",
        "docker run --rm -v \"$PWD\":/w alpine ls /w", "docker build -t x .", "tar -cf out.tar src",
        "curl -o out.bin https://x.invalid/f", "wget -P downloads https://x.invalid/f", "scp host:x out/",
        "rsync -a src/ dst/ --exclude .git", "less README.md", "git add .mcp.json", "grep -r hooks .git/hooks",
        "wc -l ~/.bashrc", "jq . .mcp.json", "python3 tools/lint.py src", "vim docs/my.mcp.json.md",
    ];
    let git_rows = ["git checkout main", "git switch main", "git pull", "git stash pop"];
    let mut loud = Vec::new();
    for cmd in suite {
        let got = floor_in(cwd, cmd);
        eprintln!("FP {cmd} => {got:?}");
        if got.is_some() && !git_rows.contains(&cmd) {
            loud.push(cmd);
        }
    }
    assert!(loud.is_empty(), "false positives: {loud:?}");
}
