//! P166 round 9 (Grok r8). Rows are `(command, blocked)`: `blocked` means the protected floor must fire, `false`
//! means it must stay silent. `exec` rows assert the `ExecOrAmbientGit` finding instead.

use super::p166_r7_sweep_tests::WRITERS;
use super::p166_r8_sweep_tests::{floor, plain_slot};
use super::{PermissionState, evaluate_bash};
use super::ClassifierSecurityFinding;

fn project() -> tempfile::TempDir {
    let project = tempfile::tempdir().unwrap();
    for dir in ["out", "src", "scripts", ".git/hooks"] {
        std::fs::create_dir_all(project.path().join(dir)).unwrap();
    }
    project
}

fn check(rows: &[(String, bool)]) {
    let project = project();
    let wrong: Vec<String> = rows
        .iter()
        .filter_map(|(cmd, blocked)| {
            let got = floor(project.path(), cmd);
            (got.is_some() != *blocked).then(|| format!("{}: expected blocked={blocked}, got {got:?}", &cmd[..cmd.len().min(120)]))
        })
        .collect();
    assert!(wrong.is_empty(), "protected floor mismatches:\n{}", wrong.join("\n"));
}

fn rows(list: &[(&str, bool)]) -> Vec<(String, bool)> {
    list.iter().map(|(cmd, blocked)| ((*cmd).to_owned(), *blocked)).collect()
}

fn exec(cmd: &str) -> bool {
    evaluate_bash(cmd, &PermissionState::default(), true)
        .assessment
        .contains(ClassifierSecurityFinding::ExecOrAmbientGit)
}

fn alternatives(first: &str) -> String {
    format!("{{{first}{}}}", ",a".repeat(256))
}

/// HIGH 1: sequence braces, one-step ranges, steps, zero padding, inside `bash -c`, `eval` and a here-document.
#[test]
fn p166_r9_h1_sequence_braces() {
    check(&rows(&[
        ("touch .g{i..i}t/hooks/pre-commit", true),
        ("touch .git/hook{s..s}/pre-commit", true),
        ("touch .g{a..k..8}t/hooks/pre-commit", true),
        ("touch .g{k..a..-2}t/hooks/pre-commit", true),
        ("touch .mc{p..p}.json", true),
        ("touch .git/hooks/pre-commit{01..03}", true),
        ("touch .git/hooks/{1..3}", true),
        ("bash -c 'touch .g{i..i}t/hooks/pre-commit'", true),
        ("eval 'touch .git/hook{s..s}/pre-commit'", true),
        ("sh <<EOF\ntouch .g{i..i}t/hooks/pre-commit\nEOF", true),
        ("sh -c \"touch .mc{p..p}.json\"", true),
        // Not a simple range: bash leaves the braces literal, so the directory is named `.g{i..ii}t`.
        ("touch .g{i..ii}t/hooks/pre-commit", false),
        ("touch .g{i..}t/hooks/pre-commit", false),
        ("touch .g{i..1}t/hooks/pre-commit", false),
        ("touch .g{i..i..x}t/hooks/pre-commit", false),
        ("touch .mcp{0..0}.json", false),
        ("touch out/{1..3}.txt", false),
    ]));
}

/// HIGH 2: an over-cap brace word whose protected name is split across alternatives takes the protected floor.
#[test]
fn p166_r9_h2_over_cap_split_name() {
    let split = alternatives(".gi");
    let mcp = alternatives(".mc");
    let mut list = rows(&[]);
    list.push((format!("touch {split}t/hooks/pre-commit"), true));
    list.push((format!("touch {mcp}p.json"), true));
    list.push((format!("bash -c 'touch {split}t/hooks/pre-commit'"), true));
    list.push((format!("touch {split}x/y"), true)); // fail closed: cannot tell, takes the floor
    // An over-cap INTEGER range holds only digits, which no protected name contains: judged by a representative.
    list.push(("touch out/file{1..300}.txt".to_owned(), false));
    list.push(("touch .git/hooks/file{1..300}".to_owned(), true));
    list.push(("echo {1..300}".to_owned(), false));
    check(&list);
}

/// HIGH 3: loopback hosts and a drive letter are local destinations; other hosts stay remote.
#[test]
fn p166_r9_h3_local_hosts() {
    check(&rows(&[
        ("rsync -a evil/ localhost:.git/hooks/", true),
        ("scp evil 127.0.0.1:.git/hooks/pre-commit", true),
        ("scp evil [::1]:.git/hooks/pre-commit", true),
        ("scp evil LOCALHOST:.mcp.json", true),
        ("scp evil c:.mcp.json", true),
        ("rsync -a evil/ 127.0.0.1:.mcp.json", true),
        ("scp evil host:.git/hooks/pre-commit", true),
        ("scp evil user@host:.git/hooks/pre-commit", true),
        ("rsync -a evil/ host:.git/hooks/", true),
        ("scp -3 host1:a host2:b", false),
        ("scp build.tar host:/srv/", false),
        ("rsync -a ./ user@host:proj/", false),
        ("scp host:file .", false),
        // The host part contains a slash: a local file name with a colon in it.
        ("rsync -a src/ ./host:.git/hooks/x", false),
        ("scp evil ./host:.git/hooks/x", false),
    ]));
}

/// MEDIUM 4: git environment variables that retarget the repository or name a program.
#[test]
fn p166_r9_m4_git_env_assignments() {
    for name in [
        "GIT_DIR", "GIT_WORK_TREE", "GIT_EXEC_PATH", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_EDITOR", "GIT_PAGER",
        "GIT_ASKPASS", "GIT_EXTERNAL_DIFF", "GIT_PROXY_COMMAND", "GIT_TEMPLATE_DIR", "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
    ] {
        for cmd in [
            format!("{name}=/tmp/evil git commit -m x"),
            format!("env {name}=/tmp/evil git status"),
            format!("export {name}=/tmp/evil; git commit -m x"),
        ] {
            assert!(exec(&cmd), "{cmd}");
        }
    }
    for cmd in ["FOO=1 git status", "git log", "GIT_AUTHOR_NAME=x git commit -m y", "RUST_LOG=debug git status"] {
        assert!(!exec(cmd), "{cmd}");
    }
}

/// MEDIUM 5: `--exec-path`; `--namespace`, `--super-prefix` and `--list-cmds` are harmless.
#[test]
fn p166_r9_m5_exec_path_flag() {
    for cmd in [
        "git --exec-path=/tmp/evil status",
        "git --exec-path /tmp/evil status",
        "git --exec-p=/tmp/evil status",
        "git -C . --exec-path=/tmp/evil log",
    ] {
        assert!(exec(cmd), "{cmd}");
    }
    for cmd in [
        "git --namespace=x status",
        "git --namespace x status",
        "git --super-prefix=x/ status",
        "git --list-cmds=main",
    ] {
        assert!(!exec(cmd), "{cmd}");
    }
}

/// MEDIUM 6: command-valued config keys other than `core.hooksPath`, SET (the ambient scan is in `shell_access` tests).
#[test]
fn p166_r9_m6_command_valued_config_set() {
    check(&rows(&[
        ("git config core.sshCommand /tmp/evil", true),
        ("git config --global core.pager /tmp/evil", true),
        ("git config core.editor /tmp/evil", true),
        ("git config credential.helper '!/tmp/evil'", true),
        ("git config credential.https://x.example.helper /tmp/evil", true),
        ("git config uploadpack.packObjectsHook /tmp/evil", true),
        ("git config remote.origin.receivepack /tmp/evil", true),
        ("git config sequence.editor /tmp/evil", true),
        ("git config gpg.program /tmp/evil", true),
        ("git config gpg.openpgp.program /tmp/evil", true),
        ("git config merge.x.driver /tmp/evil", true),
        ("git config mergetool.x.cmd /tmp/evil", true),
        ("git config difftool.x.cmd /tmp/evil", true),
        ("git config pager.log /tmp/evil", true),
        ("git config browser.x.cmd /tmp/evil", true),
        ("git config sendemail.smtpServer /tmp/evil", true),
        ("git config core.gitProxy /tmp/evil", true),
        ("git config protocol.ext.allow always", true),
        // P166 r10 (H2): the command of `url.<base>.insteadOf` is `<base>` (the key), so the value test was backwards.
        // Before r10: this row was `true`. After: `false`; the key form is in `p166_r10_h2_insteadof_key_segment`.
        ("git config url.https://x/.insteadOf 'ext::sh -c evil'", false),
        ("git config core.hooksPath /tmp/evil", true),
        // Not command-valued, or a harmless value.
        ("git config user.name x", false),
        ("git config pull.rebase true", false),
        ("git config pager.log false", false),
        ("git config sendemail.smtpServer smtp.example.com", false),
        ("git config protocol.ext.allow never", false),
        ("git config url.https://a/.insteadOf https://b/", false),
        ("git config --get core.editor", false),
        ("git config --get credential.helper", false),
    ]));
}

/// MEDIUM 6, `-c` form: already a blanket exec risk (classifier), unchanged.
#[test]
fn p166_r9_m6_dash_c_command_valued_stays_exec_risk() {
    assert!(exec("git -c core.sshCommand=/tmp/evil fetch"));
    assert!(exec("git -c credential.helper=/tmp/evil fetch"));
}

/// MEDIUM 7: recursive chmod of a directory that can hold a hooks directory below a `.git`.
#[test]
fn p166_r9_m7_recursive_chmod_submodule_hooks() {
    check(&rows(&[
        ("chmod -R +x .git/modules", true),
        ("chmod -R +x .git/modules/foo", true),
        ("chmod -R +x .git/modules/foo/modules/bar", true),
        ("chmod -R +x .git/worktrees", true),
        ("chmod -R +x .git/worktrees/w", true),
        ("chmod -R 755 .git", true),
        ("chmod -R +x .git/refs", false),
        ("chmod -R +x .git/modules/foo/objects", false),
        ("chmod -R +x scripts", false),
        ("chmod +x scripts/build.sh", false),
    ]));
}

/// MEDIUM 8: `~+` is the working directory after any `cd`, `~-` fails closed, `~user` is judged as written.
#[test]
fn p166_r9_m8_tilde_plus_minus() {
    check(&rows(&[
        ("cd .git/hooks && touch ~+/pre-commit", true),
        ("cd .git/hooks && touch ~+", true),
        ("cd .git && touch ~+/hooks/pre-commit", true),
        ("touch ~+/.git/hooks/pre-commit", true),
        ("touch ~-/pre-commit", true),
        ("touch ~root/.git/hooks/pre-commit", true),
        ("cd src && touch ~+/x", false),
        ("cd .git/hooks && touch ~+/../../README", false),
        ("touch ~+/out/x", false),
    ]));
}

/// LOW 9: a glob that hits the match cap is not examined further: fail closed.
#[test]
fn p166_r9_l9_glob_cap() {
    // P166 r10 (L7): `*` cannot match a dot-name, so `touch */*` is no longer a protected write (before r10: true).
    check(&rows(&[("touch */*", false), ("touch */*/*", false), ("touch .git/*/*", true), ("touch out/*.txt", false)]));
}

/// (a) `git -C {a,.git/hooks} checkout main`: the second alternative becomes the git verb, so git runs nothing, but
/// the hooks directory is named on the command line and takes the protected floor (fail closed) when it sits where
/// the verb belongs. When the hooks directory is the `-C` value and the other alternative is the verb, git runs nothing.
#[test]
fn p166_r9_a_git_dash_c_brace_checkout() {
    check(&rows(&[
        ("git -C {a,.git/hooks} checkout main", true),
        // `-C .git/hooks` then verb `a`: git rejects `a` as a command and runs nothing (not a bypass, documented residual).
        // P166 r10 (M6): the `-C` directory is protected, so this takes the floor now (before r10: false).
        ("git -C {.git/hooks,a} checkout main", true),
        ("git -C {.git,zz}/hooks checkout main", true),
        ("git -C .git/hooks checkout main", true),
        ("git -C {a,b} checkout main", false),
    ]));
    let over = alternatives("a");
    check(&[(format!("git -C {over}/hooks checkout main"), true)]);
}

/// Sweep: every plain-slot writer program with a sequence-brace and an over-cap spelling, plus loopback scp/rsync.
#[cfg(unix)]
#[test]
fn p166_r9_sweep_sequence_overcap_and_loopback() {
    let project = project();
    let cwd = project.path();
    let (mut cases, mut wrong) = (0usize, Vec::new());
    let spellings = [
        (".mcp.json", ".mc{p..p}.json".to_owned(), format!("{}p.json", alternatives(".mc"))),
        (
            ".git/hooks/pre-commit",
            ".g{i..i}t/hooks/pre-commit".to_owned(),
            format!("{}t/hooks/pre-commit", alternatives(".gi")),
        ),
    ];
    for (program, templates) in WRITERS {
        for template in templates.iter().filter(|t| plain_slot(t)) {
            for (_, sequence, over) in &spellings {
                for (kind, spelling) in [("sequence", sequence), ("over-cap", over)] {
                    let cmd = template.replace("{P}", spelling);
                    cases += 1;
                    if floor(cwd, &cmd).is_none() {
                        wrong.push(format!("[{program}/{kind}] {}", &cmd[..cmd.len().min(100)]));
                    }
                }
            }
        }
    }
    for host in ["localhost", "127.0.0.1", "[::1]", "LocalHost", "c", "user@localhost", "user@127.0.0.1", "user@[::1]", "127.1", "127.0.1", "localhost.", "0", "[0:0:0:0:0:0:0:1]", "0x7f.1", "017700000001", "2130706433"] {
        for dest in [".git/hooks/pre-commit", ".mcp.json"] {
            for cmd in [
                format!("scp evil {host}:{dest}"),
                format!("scp -r evil {host}:{dest}"),
                format!("rsync -a evil/ {host}:{dest}"),
                format!("rsync -avz -e ssh evil {host}:{dest}"),
            ] {
                cases += 1;
                if floor(cwd, &cmd).is_none() {
                    wrong.push(format!("[loopback] {cmd}"));
                }
            }
        }
    }
    eprintln!("SWEEP r9 cases={cases} wrong={}", wrong.len());
    assert!(wrong.is_empty(), "{} of {cases} generated cases wrong:\n{}", wrong.len(), wrong.join("\n"));
}
