//! P166 round 11 (Grok r10). Fail-closed class rules: scp/rsync destinations (rule 1), tilde words (rule 2), git
//! configuration that runs commands (rule 3), variables the checker already knows (rule 4). Rows are
//! `(command, blocked)`: `blocked` means the protected floor must fire, `false` that it stays silent.

use super::p166_r8_sweep_tests::floor;
use super::{ClassifierSecurityFinding, PermissionState, evaluate_bash};

fn project() -> tempfile::TempDir {
    let project = tempfile::tempdir().unwrap();
    for dir in ["out", "src", "scripts", "sub", ".git/hooks", ".git/modules/foo/hooks"] {
        std::fs::create_dir_all(project.path().join(dir)).unwrap();
    }
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

fn check_exec(rows: &[(&str, bool)]) {
    let wrong: Vec<String> = rows
        .iter()
        .filter(|(cmd, risky)| exec(cmd) != *risky)
        .map(|(cmd, risky)| format!("{cmd}: expected exec={risky}"))
        .collect();
    assert!(wrong.is_empty(), "exec risk mismatches:\n{}", wrong.join("\n"));
}

/// HIGH 1 and 2 plus neighbours: a destination is skipped only for a positively remote host.
#[test]
fn p166_r11_rule1_destinations_fail_closed() {
    check(&[
        ("scp evil '[::1%1]:.git/hooks/pre-commit'", true),
        ("scp evil 'user@[::1%1]:.git/hooks/pre-commit'", true),
        ("scp x 'user@[::1%lo0]:.mcp.json'", true),
        ("scp x '[::1%251]:.mcp.json'", true),
        ("scp x '[::ffff:127.0.0.1%1]:.mcp.json'", true),
        ("scp evil scp://localhost/.git/hooks/pre-commit", true),
        ("scp evil 'scp://[::1]/.git/hooks/pre-commit'", true),
        ("scp x sftp://127.0.0.1/.mcp.json", true),
        ("scp x 'sftp://user@localhost:22/.mcp.json'", true),
        ("scp x ssh://localhost/.mcp.json", true),
        ("scp x 'scp://[::1%1]/.mcp.json'", true),
        ("scp x 'scp://we!rd/.mcp.json'", true),
        ("scp x scp://:22/.mcp.json", true),
        ("rsync -a x/ localhost::mod/.git/hooks/", true),
        ("rsync -a x/ rsync://localhost/.git/hooks/", true),
        ("scp x 'we!rd:.mcp.json'", true),
        ("scp x 'we_rd:.mcp.json'", true),
        ("scp x 'host name:.mcp.json'", true),
        ("scp x '[::1]x:.mcp.json'", true),
        ("scp x 'user@:.mcp.json'", true),
        // r12: a remote host no longer exempts the path (was `false`)
        ("scp x host:.mcp.json", true),
        ("scp x user@build.example.com:.mcp.json", true),
        ("scp x 10.0.0.5:.mcp.json", true),
        ("scp x '[2001:db8::1]:.mcp.json'", true),
        ("scp x scp://build.example.com/.mcp.json", true),
        ("scp x sftp://user@10.0.0.5:2222/.mcp.json", true),
        ("scp x 'scp://[2001:db8::1]/.mcp.json'", true),
    ]);
}

/// HIGH 3, MEDIUM 7, LOW 10 plus neighbours: one function decides every tilde word.
#[test]
fn p166_r11_rule2_tilde_words() {
    check(&[
        ("cd .git/hooks && touch ~0/pre-commit", true),
        ("cd .git/hooks && touch ~00/pre-commit", true),
        ("cd .git/hooks && touch ~+00/pre-commit", true),
        ("cd .git/hooks && touch ~+0/pre-commit", true),
        ("cd .git/hooks && touch ~+/pre-commit", true),
        ("pushd .git/hooks && touch ~1/pre-commit", true),
        ("pushd .git/hooks && touch ~0/pre-commit", true),
        ("touch ~-/x", true),
        ("touch ~2/x", true),
        ("touch ~-1/x", true),
        ("touch ~+1/x", true),
        ("touch ~+x/x", true),
        ("touch '~!x/x'", true),
        // ordinary
        ("cd src && touch ~+00/a", false),
        ("cd src && touch ~0/a", false),
        ("touch ~+/out/a", false),
        ("touch ~/notes.txt", false),
        ("touch ~nobody/notes.txt", true), // r12: was false (`~name` is no longer a pinned home)
    ]);
}

/// HIGH 4, HIGH 5, MEDIUM 8 plus neighbours.
#[test]
fn p166_r11_rule3_git_config_commands() {
    check(&[
        ("git config url.\"foo::bar\".insteadOf https://github.com/", true),
        ("git config url.\"helper::x\".pushInsteadOf https://a/", true),
        ("git config url.\"external::x\".insteadOf https://a/", true),
        ("git config url.\"/tmp/x\".insteadOf https://a/", true),
        ("git config url.\"ssh://git@github.com/\".pushInsteadOf https://github.com/", false),
        ("git config url.\"https://github.com/\".insteadOf git@github.com:", false),
        ("git config url.\"git@github.com:\".insteadOf https://github.com/", false),
        ("git config tar.tar.xz.command 'xz -c'", true),
        ("git config imap.tunnel 'sh -c id'", true),
        ("git config sendemail.tocmd x", true),
        ("git config sendemail.cccmd x", true),
        ("git config sendemail.headercmd x", true),
        ("git config protocol.allow always", true),
        ("git config protocol.allow never", false),
        ("git config protocol.foo.allow always", true),
        ("git config foo.bar.command 'sh -c id'", true),
        ("git config foo.helper x", true),
        ("git config foo.program x", true),
        ("git config foo.bar.textconv x", true),
        ("git config foo.hooksPath x", true),
        ("git config foo.editor x", true),
        ("git config foo.bar.driver x", true),
    ]);
    check_exec(&[
        ("GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0='url.ext::sh -c id.insteadof' GIT_CONFIG_VALUE_0='https://github.com/' git fetch", true),
        ("GIT_CONFIG_COUNT=0 git log", true),
        ("GIT_CONFIG_KEY_3=user.name git log", true),
        ("GIT_CONFIG_VALUE_7=x git log", true),
        ("GIT_CONFIG_PARAMETERS=\"'core.pager=sh -c id'\" git log", true),
        ("env GIT_CONFIG_COUNT=1 git log", true),
    ]);
    check(&[
        ("GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=.git/hooks git log", true),
        ("GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=x.y GIT_CONFIG_VALUE_0=.git/hooks git log", true),
    ]);
}

/// HIGH 6 plus neighbours: `$PWD` folds to the tracked cwd; undecodable git words do not vanish.
#[test]
fn p166_r11_rule4_known_variables() {
    check(&[
        ("git --work-tree=$PWD/.git/hooks checkout main", true),
        ("git -C \"$PWD/.git/hooks\" checkout main", true),
        ("git -C \"${PWD}/.git/hooks\" init", true),
        ("git --git-dir=\"$(pwd)/.git/hooks\" status", true),
        ("git -C \"$OLDPWD/.git/hooks\" init", true),
        ("git -C \"${PWD%/*}/.git/hooks\" init", true),
        ("git -C `pwd`/.git/hooks init", true),
        ("git -C \"$dir\" init", true),
        ("git --work-tree=\"$dir\" checkout main", true),
        ("git --exec-path=\"$dir\" status", true),
        ("touch \"$PWD/.git/hooks/pre-commit\"", true),
        ("touch ${PWD}/.mcp.json", true),
        ("cp x \"$PWD/.mcp.json\"", true),
        ("git -C \"$PWD\" status", false),
        ("git -C \"$PWD/sub\" status", false),
        ("touch \"$PWD/out.txt\"", false),
        ("git commit -m \"$msg\"", false),
    ]);
}

/// The false-positive suite of the brief: every row stays silent (floor and exec risk).
#[test]
fn p166_r11_false_positive_suite() {
    let project = project();
    let suite = [
        "scp build.tar host:/srv/", "scp build.tar user@build.example.com:/srv/", "scp file 10.0.0.5:/tmp/",
        "scp file '[2001:db8::1]:/tmp/'", "rsync -a ./ user@host:proj/", "rsync -a rsync://mirror.example.org/pub/ ./mirror/",
        "scp host:file .", "sftp host", "ls ~", "cd ~/src", "echo ~root", "cd src && ls ~+",
        "git config url.\"https://github.com/\".insteadOf git@github.com:",
        "git config url.\"ssh://git@github.com/\".pushInsteadOf https://github.com/", "git config user.name x",
        "git config pull.rebase true", "git config init.defaultBranch main", "git config core.autocrlf input",
        "git config merge.conflictstyle zdiff3", "git config diff.algorithm histogram", "git config rerere.enabled true",
        "git config push.autoSetupRemote true", "git config color.ui auto", "git config alias.st status",
        "git config alias.cmd status", "git config branch.main.rebase true", "git config core.whitespace trailing-space",
        "git config commit.verbose true", "git config fetch.prune true", "git config status.short true",
        "ls \"$PWD\"", "cat \"$PWD/README.md\"",
        "touch \"$PWD/out.txt\"", "make -C \"$PWD/build\"", "docker run -v \"$PWD\":/w img", "echo $HOME",
    ];
    // Informational: exec risk on an undecodable `-C` value is unchanged by r11 (it predates the packet).
    for cmd in ["git -C \"$PWD\" status", "git -C \"$PWD/sub\" status"] {
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
