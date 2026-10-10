//! P166 round 10 (Grok r9). Rows are `(command, blocked)` as in `p166_r9_tests`: `blocked` means the protected floor
//! must fire, `false` means it must stay silent.

use super::p166_r8_sweep_tests::floor;
use super::{ClassifierSecurityFinding, PermissionState, evaluate_bash};

fn project() -> tempfile::TempDir {
    let project = tempfile::tempdir().unwrap();
    for dir in ["out", "src", "scripts", "sub", ".git/hooks", ".git/modules/foo/hooks"] {
        std::fs::create_dir_all(project.path().join(dir)).unwrap();
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(project.path().join(".git"), project.path().join("lnk")).unwrap();
    project
}

fn check(rows: &[(&str, bool)]) {
    let project = project();
    let wrong: Vec<String> = rows
        .iter()
        .filter_map(|(cmd, blocked)| {
            let got = floor(project.path(), cmd);
            (got.is_some() != *blocked).then(|| format!("{cmd}: expected blocked={blocked}, got {got:?}"))
        })
        .collect();
    assert!(wrong.is_empty(), "protected floor mismatches:\n{}", wrong.join("\n"));
}

fn exec(cmd: &str) -> bool {
    evaluate_bash(cmd, &PermissionState::default(), true)
        .assessment
        .contains(ClassifierSecurityFinding::ExecOrAmbientGit)
}

/// HIGH 1: loopback spellings with a `user@`, abbreviated IPv4, a trailing dot, `0`, expanded IPv6.
#[test]
fn p166_r10_h1_loopback_spellings() {
    let mut rows: Vec<(String, bool)> = Vec::new();
    for host in [
        "user@localhost", "user@127.0.0.1", "user@[::1]", "127.1", "127.0.1", "localhost.", "0", "[0:0:0:0:0:0:0:1]",
        "0:0:0:0:0:0:0:1", "[::ffff:127.0.0.1]", "0x7f.1", "017700000001", "2130706433", "root@LOCALHOST.", "::1",
    ] {
        // Unbracketed IPv6 has no `host:path` form; those rows only exist for the bracketed spellings.
        if host.matches(':').count() > 1 && !host.starts_with('[') && !host.contains('@') {
            continue;
        }
        rows.push((format!("scp evil {host}:.git/hooks/pre-commit"), true));
        rows.push((format!("scp evil {host}:.mcp.json"), true));
        rows.push((format!("rsync -a evil/ {host}:.git/hooks/"), true));
    }
    for (cmd, blocked) in [
        ("scp evil user@host:.git/hooks/pre-commit", true),
        ("scp evil user@build.example.com:.git/hooks/pre-commit", true),
        ("scp evil 10.0.0.5:.git/hooks/pre-commit", true),
        ("scp evil 128.0.0.1:.mcp.json", true),
        ("scp evil user@8.8.8.8:.mcp.json", true),
        ("scp evil [2001:db8::1]:.mcp.json", true),
        ("scp evil user@[2001:db8::1]:.mcp.json", true),
        ("scp build.tar host:/srv/", false),
        ("scp build.tar user@host:/srv/", false),
        ("rsync -a ./ user@build.example.com:proj/", false),
        ("scp file 10.0.0.5:/tmp/", false),
    ] {
        rows.push((cmd.to_owned(), blocked));
    }
    let borrowed: Vec<(&str, bool)> = rows.iter().map(|(c, b)| (c.as_str(), *b)).collect();
    check(&borrowed);
}

/// HIGH 2: the command of `url.<base>.insteadOf` is the key's middle segment, not the value.
#[test]
fn p166_r10_h2_insteadof_key_segment() {
    check(&[
        ("git config url.\"ext::sh -c id\".insteadOf https://github.com/", true),
        ("git config url.\"ext::sh -c id\".pushInsteadOf https://github.com/", true),
        ("git config --global url.'ext::sh -c id'.insteadOf https://github.com/", true),
        ("git config 'url.ext::sh -c id.insteadOf' https://github.com/", true),
        // Before r10 this blocked (value tested); the rewrite goes the other way, so it is harmless.
        ("git config url.https://x/.insteadOf 'ext::sh -c evil'", false),
        ("git config url.\"https://github.com/\".insteadOf git@github.com:", false),
        ("git config url.\"ssh://git@github.com/\".pushInsteadOf https://github.com/", false),
        ("git config url.https://a/.insteadOf https://b/", false),
    ]);
}

/// HIGH 2, ambient form: a repo whose config file already holds `[url "ext::..."]`.
#[test]
fn p166_r10_h2_insteadof_ambient_config_file() {
    use crate::permission::exec_risk::local_repo_config_has_exec_risk;
    for (section, risky) in [
        ("[url \"ext::sh -c id\"]\n\tinsteadOf = https://github.com/\n", true),
        ("[url \"ext::sh -c id\"]\n\tpushInsteadOf = https://github.com/\n", true),
        ("[url \"https://github.com/\"]\n\tinsteadOf = git@github.com:\n", false),
        ("[url \"https://x/\"]\n\tinsteadOf = ext::sh -c id\n", false),
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

/// HIGH 3: `~+0` is `$PWD`; other stack forms fail closed; `~+` alone and an unrelated cwd stay as they were.
#[test]
fn p166_r10_h3_tilde_plus_zero() {
    check(&[
        ("cd .git && touch ~+0/hooks/pre-commit", true),
        ("cd .git && touch ~+/hooks/pre-commit", true),
        ("cd .git/hooks && touch ~+1/pre-commit", true),
        ("cd .git/hooks && touch ~-0/pre-commit", true),
        ("cd .git/hooks && touch ~-1/pre-commit", true),
        ("cd .git/hooks && touch ~-/pre-commit", true),
        ("cd src && touch ~+0/a", false),
        ("cd src && ls ~+", false),
        ("cd src && ls ~+0", false),
        ("echo ~", false),
    ]);
}

/// HIGH 4: `chmod -R` folds `.` and `..` and follows a symlinked component.
#[test]
fn p166_r10_h4_chmod_dot_components() {
    check(&[
        ("chmod -R +x .git/modules/foo/.", true),
        ("chmod -R +x .git/./modules", true),
        ("chmod -R +x .git/modules/foo/..", true),
        ("chmod -R +x .git/modules/foo/../foo", true),
        ("chmod -R +x lnk/modules/foo", true),
        // Unchanged since r8B: the fixture project really holds `.git/hooks`, so `-R .` reaches it.
        ("chmod -R go-w .", true),
        ("chmod -R +x scripts/.", false),
        ("chmod -R +x scripts/../src", false),
    ]);
}

/// MEDIUM 5: command-valued keys beyond the r9 table, SET (and their text goes through the tripwire).
#[test]
fn p166_r10_m5_more_command_keys() {
    check(&[
        ("git config trailer.sign.command /tmp/evil", true),
        ("git config trailer.sign.cmd 'touch .git/hooks/pre-commit'", true),
        ("git config submodule.lib.update '!/tmp/evil'", true),
        ("git config interactive.diffFilter /tmp/evil", true),
        ("git config init.templateDir /tmp/evil", true),
        ("git config remote.origin.vcs evil", true),
        ("git config man.x.cmd /tmp/evil", true),
        ("git config man.x.path /tmp/evil", true),
        ("git config instaweb.httpd /tmp/evil", true),
        ("git config guitool.x.cmd /tmp/evil", true),
        ("git config submodule.lib.update merge", false),
        ("git config submodule.lib.update rebase", false),
        ("git config submodule.lib.update checkout", false),
        ("git config trailer.sign.key Signed-off-by", false),
        ("git config remote.origin.url https://x", false),
        ("git config init.defaultBranch main", false),
    ]);
}

/// MEDIUM 5, ambient: the same keys in a repo config are exec risk.
#[test]
fn p166_r10_m5_ambient_keys() {
    use crate::permission::exec_risk::local_git_config_entry_is_exec;
    for (key, value, risky) in [
        ("trailer.s.command", "x", true),
        ("trailer.s.cmd", "x", true),
        ("submodule.lib.update", "!x", true),
        ("submodule.lib.update", "merge", false),
        ("interactive.difffilter", "x", true),
        ("init.templatedir", "x", true),
        ("remote.o.vcs", "x", true),
        ("man.x.cmd", "x", true),
        ("man.x.path", "x", true),
        ("instaweb.httpd", "x", true),
        ("guitool.x.cmd", "x", true),
        ("init.defaultbranch", "main", false),
    ] {
        assert_eq!(local_git_config_entry_is_exec(key, value), risky, "{key}={value}");
    }
}

/// MEDIUM 6: a protected directory given to `-C`, `--work-tree` or `--git-dir` unpins every verb.
#[test]
fn p166_r10_m6_protected_directory_option() {
    check(&[
        ("git -C .git/hooks init", true),
        ("git -C {.git/hooks,init}", true),
        ("git --git-dir=.git/hooks fetch", true),
        ("git --git-dir .git/hooks frobnicate", true),
        ("git --work-tree=.git/hooks frobnicate", true),
        ("git -C .git/hooks frobnicate", true),
        // r9 pinned this as silent (verb `a` is not a git command); the `-C` directory is protected, so it is blocked now.
        ("git -C {.git/hooks,a} checkout main", true),
        ("git -C ../other status", false),
        ("git -C ../other checkout main", false),
        ("git init newrepo", false),
        ("git -C sub init", false),
    ]);
}

/// LOW 7: a pattern that cannot reach a dot-name is not a protected write because it is wide.
#[test]
fn p166_r10_l7_glob_cap_false_positive() {
    check(&[
        ("rm */*", false),
        ("rm -rf build/*/*.o", false),
        ("ls */*", false),
        ("touch */*", false),
        ("touch */*/*", false),
        ("touch out/*.txt", false),
        // A literal dot-name or absolute root keeps the cap as a reason to stop.
        ("touch .git/*/*", true),
        ("touch .*/*/*", true),
        ("touch .git/hooks/*", true),
        ("touch /*/*/*", true),
    ]);
}

/// False-positive suite: every command here must stay silent (floor and exec risk). Printed with `--nocapture`.
#[test]
fn p166_r10_false_positive_suite() {
    let project = project();
    let suite = [
        "scp build.tar host:/srv/", "scp build.tar user@host:/srv/", "rsync -a ./ user@build.example.com:proj/",
        "scp file 10.0.0.5:/tmp/", "git config url.\"https://github.com/\".insteadOf git@github.com:",
        "git config url.\"ssh://git@github.com/\".pushInsteadOf https://github.com/",
        "git config remote.origin.url https://x", "git config submodule.lib.update merge",
        "git config submodule.lib.update rebase", "git config init.defaultBranch main", "cd src && ls ~+", "echo ~",
        "chmod -R +x scripts/.", "rm */*", "rm -rf build/*/*.o", "ls */*", "git -C ../other status",
        "git -C ../other checkout main", "git init newrepo", "git -C sub init",
    ];
    // Informational, not asserted: both are unchanged by r10. `chmod -R go-w .` takes the floor only because the
    // fixture project really holds `.git/hooks` (r8B rule); the two retarget flags are exec risk since round 7.
    for cmd in ["chmod -R go-w .", "git --git-dir=.git status", "git --work-tree=. status"] {
        eprintln!("FP-info {cmd} => floor={:?} exec={}", floor(project.path(), cmd), exec(cmd));
    }
    let mut wrong = Vec::new();
    for cmd in suite {
        let got = floor(project.path(), cmd);
        let risky = exec(cmd);
        eprintln!("FP {cmd} => floor={got:?} exec={risky}");
        if got.is_some() || risky {
            wrong.push(format!("{cmd}: floor={got:?} exec={risky}"));
        }
    }
    assert!(wrong.is_empty(), "false positives:\n{}", wrong.join("\n"));
}
