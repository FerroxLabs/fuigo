//! P166 round 12 (Grok r11). Redirect targets fold `$HOME` / `$PWD` and fail closed when undecodable (item 1), `~name`
//! words (item 2), every scp/rsync destination path is judged whatever the host (item 3), non-setting `git config`
//! forms (item 6), URLs that run code (item 4), undecodable words in readers (item 5). Rows are
//! `(command, blocked)`: `blocked` means the protected floor must fire, `false` that it stays silent.

use super::p166_r7_sweep_tests::WRITERS;
use super::p166_r8_sweep_tests::floor;
use super::{ClassifierSecurityFinding, PermissionState, evaluate_bash};

fn project() -> tempfile::TempDir {
    let project = tempfile::tempdir().unwrap();
    for dir in ["out", "src", "sub", ".git/hooks"] {
        std::fs::create_dir_all(project.path().join(dir)).unwrap();
    }
    project
}

fn check(rows: &[&str], blocked: bool) {
    let project = project();
    let wrong: Vec<String> = rows
        .iter()
        .filter_map(|cmd| {
            let got = floor(project.path(), cmd);
            (got.is_some() != blocked).then(|| format!("{cmd}: expected blocked={blocked}, got {got:?}"))
        })
        .collect();
    assert!(wrong.is_empty(), "protected floor mismatches:\n{}", wrong.join("\n"));
}

/// Item 1 (HIGH 1): `$HOME` / `$PWD` fold on every redirect operator; an undecodable target that still shows a
/// protected name takes the floor.
#[test]
fn p166_r12_item1_redirect_targets_fold_and_fail_closed() {
    check(
        &[
            "echo x > $PWD/.git/hooks/pre-commit",
            "echo x > \"$HOME\"/.bashrc",
            "cat <<EOF > \"$HOME\"/.bashrc\nx\nEOF",
            "echo x >> \"${PWD}/.git/hooks/pre-commit\"",
            "cmd 2> $HOME/.zshrc",
            ": > \"$UNKNOWN/.git/hooks/x\"",
            "echo x >| $HOME/.bashrc",
            "echo x &> $HOME/.bashrc",
            "cmd <> $HOME/.bashrc",
            "exec > $HOME/.bashrc",
            "echo x > ${HOME}/.zshrc",
            "echo x > \"$x\"/.ssh/authorized_keys",
        ],
        true,
    );
    check(
        &[
            "echo hi > out.txt",
            "echo hi > \"$PWD/out.txt\"",
            "echo hi >> \"$HOME/notes.txt\"",
            "make > build.log 2>&1",
            "cmd > /dev/null",
            "cat > \"$TMPDIR/x\" <<EOF\nx\nEOF",
            ": > \"$UNKNOWN/x\"",
        ],
        false,
    );
}

/// Item 2 (HIGH 2): `~name` is the home only for the current user; any other name fails closed for a write.
#[test]
fn p166_r12_item2_tilde_user_words() {
    check(
        &[
            "touch ~nobody/x",
            "touch ~nobody/../../etc/passwd",
            "cd ~nobody && touch .bashrc",
            "cd ~nobody && touch notes.txt",
            "pushd ~nobody && touch x",
        ],
        true,
    );
    check(&["touch ~/notes.txt", "cd ~/src && touch a", "ls ~root", "cat ~alice/notes", "ls ~"], false);
    // The current user's own name is the home (whoever runs the tests; `~root` on the build box).
    for key in ["USER", "LOGNAME"] {
        if let Some(user) = std::env::var(key).ok().filter(|u| !u.is_empty()) {
            check(&[&format!("touch ~{user}/notes.txt")], false);
        }
    }
}

/// Item 3 (HIGH 3, HIGH 4, LOW 10): the path part of every scp/rsync destination is judged, whatever the host.
#[test]
fn p166_r12_item3_destination_paths_are_judged_for_every_host() {
    check(
        &[
            "scp x 192.168.1.5:.git/hooks/pre-commit",
            "scp x foo.localhost:.mcp.json",
            "rsync -a x/ buildhost:.ssh/",
            "scp x user@host:.bashrc",
            "scp id.pub host:.ssh/authorized_keys",
            "rsync -a dotfiles/.bashrc host:",
            "scp x my_host:.bashrc",
            "scp x 'sftp://user@10.0.0.5:2222/.mcp.json'",
            "scp x scp://build.example.com/.mcp.json",
            "scp x '[2001:db8::1]:.mcp.json'",
            "scp host:.bashrc .",
            "scp host:.bashrc ~/",
            "rsync host:.git/hooks/ .git/hooks/",
        ],
        true,
    );
    check(
        &[
            "scp build.tar host:/srv/",
            "scp build.tar user@build.example.com:/srv/app/",
            "rsync -a ./ user@host:proj/",
            "rsync -a ./ 192.168.1.5:backup/",
            "scp host:file .",
            "scp host:.bashrc ./their-bashrc",
        ],
        false,
    );
}

/// Sweep: every writer row that can take a redirect gets a `$HOME` and a `$PWD` redirect target; every scp/rsync row
/// gets a remote-host destination with a protected path.
#[test]
fn p166_r12_sweep_redirect_targets_and_remote_destinations() {
    let project = project();
    let cwd = project.path();
    let (mut cases, mut wrong) = (0usize, Vec::new());
    for (program, templates) in WRITERS {
        for template in templates.iter().filter(|t| !t.contains("<<")) {
            let base = template.replace("{P}", "out/x");
            let mut variants = vec![
                format!("{base} > \"$HOME/.bashrc\""),
                format!("{base} 2> $PWD/.git/hooks/pre-commit"),
            ];
            if matches!(*program, "scp" | "rsync") && template.ends_with(" {P}") {
                for host in ["host:", "192.168.1.5:", "foo.localhost:", "user@buildhost:", "my_host:", "scp://build.example.com/"] {
                    for path in [".mcp.json", ".git/hooks/pre-commit"] {
                        variants.push(template.replace("{P}", &format!("'{host}{path}'")));
                    }
                }
            }
            for cmd in variants {
                cases += 1;
                if floor(cwd, &cmd).is_none() {
                    wrong.push(format!("[{program}] {cmd}"));
                }
            }
        }
    }
    eprintln!("SWEEP r12 cases={cases} wrong={}", wrong.len());
    assert!(wrong.is_empty(), "{} of {cases} generated cases wrong:\n{}", wrong.len(), wrong.join("\n"));
}

fn exec(cmd: &str) -> bool {
    evaluate_bash(cmd, &PermissionState::default(), true)
        .assessment
        .contains(ClassifierSecurityFinding::ExecOrAmbientGit)
}

fn check_exec(rows: &[&str], risky: bool) {
    let wrong: Vec<&&str> = rows.iter().filter(|cmd| exec(cmd) != risky).collect();
    assert!(wrong.is_empty(), "expected exec risk={risky}:\n{wrong:#?}");
}

/// Item 6 (LOW 9): the forms that never set a value are not command-valued whatever the key; a boolean for a key matched
/// only by the suffix rule is not a command.
#[test]
fn p166_r12_item6_config_forms_that_set_nothing() {
    let quiet = [
        "git config --unset core.editor",
        "git config --unset-all core.hooksPath",
        "git config --global --unset gui.editor",
        "git config --get core.hooksPath",
        "git config --get-all core.editor",
        "git config --get-regexp 'core\\..*'",
        "git config -l",
        "git config --list",
        "git config --name-only --list",
        "git config --show-origin --list",
        "git config unset core.editor",
        "git config get core.hooksPath",
        "git config list",
        "git config gui.editor true",
        "git config pager.log false",
    ];
    check(&quiet, false);
    check_exec(&quiet, false);
    check(&["git config core.editor vim", "git config set core.editor vim", "git config core.hooksPath .githooks"], true);
}

/// Item 4 (HIGH 5, MEDIUM 7, LOW 8): one predicate for every git URL; a URL that runs code is exec risk, and a SET of
/// one takes the protected floor.
#[test]
fn p166_r12_item4_urls_that_run_code() {
    let commands = [
        "git remote add o 'ext::sh -c id'",
        "git remote set-url origin 'ext::sh -c id'",
        "git remote add o 'ssh://-oProxyCommand=x/y'",
        "git clone 'ext::sh -c id' d",
        "git clone 'ssh://-oProxyCommand=touch%20x/repo' d",
        "git clone --depth 1 -b main 'foo::bar' d",
        "git fetch 'foo::bar'",
        "git pull 'foo::bar'",
        "git push 'foo::bar' main",
        "git submodule add 'ext::sh -c id' lib",
        "git ls-remote 'ext::sh -c id'",
        "git archive --remote='ext::sh -c id' HEAD",
        "git archive --remote 'ext::sh -c id' HEAD",
    ];
    check_exec(&commands, true);
    let sets = [
        "git remote add o 'ext::sh -c id'",
        "git remote set-url origin 'ext::sh -c id'",
        "git config remote.origin.url 'ext::sh -c id'",
        "git config remote.origin.pushurl 'foo::x'",
        "git config submodule.lib.url 'ext::sh -c id'",
        "git config remote.origin.url 'ssh://-oProxyCommand=x/y'",
        "git config url.\"file:///tmp/evil.git\".insteadOf https://github.com/a/b.git",
        "git config url.\"ssh://-oProxyCommand=x/\".insteadOf https://github.com/a/b.git",
    ];
    check(&sets, true);
    let ordinary = [
        "git clone https://github.com/a/b",
        "git clone git@github.com:a/b.git",
        "git clone file:///srv/git/x.git",
        "git clone ../other",
        "git clone ssh://git@host:2222/a/b.git d",
        "git remote add origin git@github.com:a/b.git",
        "git remote set-url origin https://github.com/a/b",
        "git fetch origin",
        "git fetch ../other",
        "git pull",
        "git push origin main",
        "git submodule add https://github.com/a/lib",
        "git ls-remote origin",
        "git archive --remote=ssh://host/repo HEAD",
        "git config remote.origin.url https://github.com/a/b",
        "git config remote.origin.url git@github.com:a/b.git",
        "git config remote.origin.url ../other",
        "git config url.\"https://github.com/\".insteadOf git@github.com:",
    ];
    check_exec(&ordinary, false);
}

/// Item 5 (HIGH 6): readers and Skip-shape programs run the undecodable-word scan where the program can write.
#[test]
fn p166_r12_item5_undecodable_words_in_readers() {
    check(
        &[
            "chmod +x \"$x/.git/hooks/pre-commit\"",
            "chown me \"$x/.git/hooks/pre-commit\"",
            "chgrp g \"$x/.git/hooks/pre-commit\"",
            "less -o \"$x/.git/hooks/pre-commit\" README",
            "diff --output=\"$x/.git/hooks/x\" a b",
            "sort -o \"$x/.git/hooks/pre-commit\" a",
            "find . -fprint \"$x/.git/hooks/pre-commit\"",
            "find . -fprintf \"$x/.git/hooks/pre-commit\" %p",
            "find . -fls \"$x/.git/hooks/pre-commit\"",
            "find \"$x/.git/hooks\" -delete",
            "find . -exec chmod +x \"$x/.git/hooks/pre-commit\" \\;",
            "dir=.git/hooks chmod +x \"$dir/pre-commit\"",
        ],
        true,
    );
    check(
        &[
            "cat \"$x/.git/hooks/pre-commit\"",
            "ls \"$dir\"",
            "ls \"$x/.git/hooks\"",
            "grep -r foo \"$HOME/.ssh\"",
            "find . -name '*.rs' -print",
            "find \"$x/.git/hooks\" -name x -print",
            "diff a b",
            "diff \"$x/.git/hooks/a\" b",
            "less README.md",
            "chmod +x \"$dir/build.sh\"",
        ],
        false,
    );
}

/// Item 4, ambient form: a repo whose config file already holds a command URL is exec risk; ordinary URLs are not.
#[test]
fn p166_r12_item4_ambient_config_urls() {
    use crate::permission::exec_risk::local_repo_config_has_exec_risk;
    for (section, risky) in [
        ("[remote \"o\"]\n\turl = ext::sh -c id\n", true),
        ("[remote \"o\"]\n\tpushurl = foo::x\n", true),
        ("[remote \"o\"]\n\turl = ssh://-oProxyCommand=x/y\n", true),
        ("[submodule \"lib\"]\n\turl = ext::sh -c id\n", true),
        ("[url \"file:///tmp/evil.git\"]\n\tinsteadOf = https://github.com/a/b.git\n", true),
        ("[remote \"o\"]\n\turl = https://github.com/a/b\n", false),
        ("[remote \"o\"]\n\turl = git@github.com:a/b.git\n", false),
        ("[remote \"o\"]\n\turl = ../other\n", false),
        ("[remote \"o\"]\n\turl = file:///srv/git/x.git\n", false),
        ("[submodule \"lib\"]\n\turl = https://github.com/a/lib\n", false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        git2::Repository::init(dir.path()).unwrap();
        let config = dir.path().join(".git/config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str(section);
        std::fs::write(&config, text).unwrap();
        assert_eq!(local_repo_config_has_exec_risk(dir.path()), risky, "{section}");
    }
}
