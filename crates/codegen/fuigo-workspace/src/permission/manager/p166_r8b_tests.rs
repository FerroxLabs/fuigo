//! P166 round 8B (Grok r7, git and metadata findings). Rows are `(command, blocked)`: `blocked` means the protected
//! floor must fire, `false` means it must stay silent.

use super::{PermissionState, bash_protected_write_target, evaluate_bash};
use super::ClassifierSecurityFinding;

fn floor_in(cwd: &std::path::Path, cmd: &str) -> Option<crate::permission::shell_access::ProtectedEditReason> {
    let state = PermissionState::default();
    let evaluation = evaluate_bash(cmd, &state, true);
    bash_protected_write_target(&evaluation, cwd, None)
}

fn project() -> tempfile::TempDir {
    let project = tempfile::tempdir().unwrap();
    for dir in ["out", "src", "scripts", ".git/hooks"] {
        std::fs::create_dir_all(project.path().join(dir)).unwrap();
    }
    project
}

fn check(rows: &[(&str, bool)]) {
    let project = project();
    let mut wrong = Vec::new();
    for (cmd, blocked) in rows {
        let got = floor_in(project.path(), cmd);
        if got.is_some() != *blocked {
            wrong.push(format!("{cmd}: expected blocked={blocked}, got {got:?}"));
        }
    }
    assert!(wrong.is_empty(), "protected floor mismatches:\n{}", wrong.join("\n"));
}

fn file_write(cmd: &str) -> bool {
    let state = PermissionState::default();
    evaluate_bash(cmd, &state, true)
        .assessment
        .contains(ClassifierSecurityFinding::FileWrite)
}

/// B1 (HIGH 6): every spelling git accepts for a hooks redirect, in any letter case.
#[test]
fn p166_r8b_b1_hooks_path_spellings() {
    check(&[
        ("git -ccore.hooksPath=/tmp/evil commit", true),
        ("git -cCORE.HOOKSPATH=/tmp/evil commit", true),
        ("git --config-e=core.hooksPath=/tmp/evil commit", true),
        ("git --config-env=core.hooksPath=EVIL commit", true),
        ("git --config-env core.hooksPath=EVIL commit", true),
        ("git --config-env=Core.HooksPath=EVIL commit", true),
        ("git --conf=core.hooksPath=EVIL commit", true),
        ("git -c core.hooksPath=/tmp/evil commit", true),
        ("git -c include.path=/tmp/evil.cfg commit", true),
        ("git -cinclude.path=/tmp/evil.cfg commit", true),
        ("git -c includeIf.gitdir:/x.path=/tmp/evil.cfg commit", true),
        ("git -c user.name=x -ccore.hooksPath=/tmp/evil commit -m y", true),
        ("git -c user.name=x commit -m y", false),
        ("git -cuser.name=x commit -m y", false),
        ("git -c color.ui=never log", false),
        ("git --config-env=user.name=NAME log", false),
    ]);
}

/// B2 (MEDIUM 1): a branch-wide git verb is on the ordinary FileWrite floor, not the protected floor.
#[test]
fn p166_r8b_b2_branch_wide_git_is_file_write() {
    for cmd in [
        "git checkout main",
        "git switch main",
        "git pull",
        "git pull origin main",
        "git stash pop",
        "git stash apply",
        "git merge main",
        "git rebase main",
        "git reset --hard HEAD~1",
        "git restore src/a.rs",
        "git -c user.name=x checkout main",
        "env FOO=1 git checkout main",
    ] {
        assert!(file_write(cmd), "{cmd}: expected the FileWrite finding");
    }
    for cmd in [
        "git status",
        "git log",
        "git diff",
        "git commit -m x",
        "git add -A",
        "git fetch",
        "git stash list",
        "git restore --staged src/a.rs",
        "git config user.email a@b",
        "git -C ../other status",
    ] {
        assert!(!file_write(cmd), "{cmd}: expected no FileWrite finding");
    }
    // The ordinary floor is not the protected floor; literal protected pathspecs stay protected.
    check(&[
        ("git checkout main", false),
        ("git switch main", false),
        ("git pull", false),
        ("git stash pop", false),
        ("git checkout main -- .mcp.json", true),
        ("git checkout .mcp.json", true),
        ("git restore .git/hooks/x", true),
        ("git restore --source=main -- .mcp.json", true),
        ("git checkout-index -a -f", true),
        ("git checkout-index -f -- .mcp.json", true),
        ("git apply fix.patch", true),
        ("git am fix.patch", true),
    ]);
}

/// B3 (MEDIUM 2): a metadata change on a hook is a protected hit; elsewhere it stays silent.
#[test]
fn p166_r8b_b3_chmod_on_hooks() {
    check(&[
        ("chmod +x .git/hooks/pre-commit", true),
        ("chmod 755 .git/hooks/pre-commit", true),
        ("chmod -x .git/hooks/pre-commit", true),
        ("chown root .git/hooks/pre-commit", true),
        ("chgrp wheel .git/hooks/pre-commit", true),
        ("chmod +x .git/hooks", true),
        ("chmod -R +x .git", true),
        ("chmod -R +x .", true),
        ("chmod --recursive +x .git", true),
        ("chmod -vR a+x .git", true),
        ("chmod --reference=README.md .git/hooks/pre-commit", true),
        ("chmod +x ~/.fuigo/hooks/post-tool", true),
        ("chmod -R +x ~/.fuigo", true),
        ("cd .git/hooks && chmod +x pre-commit", true),
        ("install -m 755 build/hook .git/hooks/pre-commit", true),
        ("chmod 600 .mcp.json", false),
        ("chmod +x scripts/build.sh", false),
        ("chmod -R go-w src", false),
        ("chmod --reference=.git/hooks/pre-commit README.md", false),
        ("chmod +x .git/hooks-notes", false),
        ("chown -R me out", false),
    ]);
}

/// B4 (MEDIUM 5): `-C` does not turn a lone branch name into a path.
#[test]
fn p166_r8b_b4_git_dash_c_branch_operand() {
    check(&[
        ("git -C ../other checkout main", false),
        ("git -C ../other switch main", false),
        ("git -C ../other switch -c feature/x", false),
        ("git -C ../other checkout release-1.2", false),
        ("git -C ../other status", false),
        ("git -C ../other checkout main -- .mcp.json", true),
        ("git -C ../other checkout main .mcp.json", true),
        ("git -C ../other checkout .mcp.json", true),
        ("git -C ../other checkout -- .", true),
        ("git -C ../other restore .mcp.json", true),
        ("git -C .git/hooks checkout main", true),
        ("git -C.git/hooks checkout main", true),
        ("git --git-dir=.git/hooks checkout main", true),
        ("git --work-tree=.git/hooks checkout main", true),
        ("git -C ../other merge main", true),
    ]);
    assert!(file_write("git -C ../other checkout main"));
}

/// B5 (LOW 2): a `!` alias is stored shell text: exec risk, tripwired; a non-verb is never a safe query.
#[test]
fn p166_r8b_b5_shell_alias() {
    check(&[
        ("git config alias.x '!sh -c \"cp e .git/hooks/pre-commit\"'", true),
        ("git config --global alias.x '!cp e .mcp.json'", true),
        ("git config alias.co checkout", false),
        ("git config alias.lg '!git log --oneline'", false),
        ("git config user.email a@b", false),
        ("git config --get core.hooksPath", false),
    ]);
    let state = PermissionState::default();
    for cmd in ["git config alias.x '!echo hi'", "git config --global alias.lg '!git log'"] {
        assert!(
            evaluate_bash(cmd, &state, true).assessment.contains(ClassifierSecurityFinding::ExecOrAmbientGit),
            "{cmd}: expected exec risk"
        );
    }
    for cmd in ["git config alias.co checkout", "git config --get alias.x", "git status"] {
        assert!(
            !evaluate_bash(cmd, &state, true).assessment.contains(ClassifierSecurityFinding::ExecOrAmbientGit),
            "{cmd}: expected no exec risk"
        );
    }
    // An unknown verb (possibly an alias) is neither a read-only query nor routine.
    for cmd in ["git x", "git deploy --now", "git -C ../o x"] {
        let words: Vec<String> = cmd.split(' ').map(str::to_owned).collect();
        assert!(!crate::permission::exec_risk::git_words_are_read_only_query(&words), "{cmd}");
    }
}

/// The false-positive suite for this round. Prints `FP8B <command> => <floor> filewrite=<bool>` per command (run at the
/// base and at the tip with `--nocapture`); asserts the protected floor stays silent.
#[test]
fn p166_r8b_false_positive_suite() {
    let project = project();
    let suite = [
        "git status",
        "git log",
        "git diff",
        "git -C ../other status",
        "git -C ../other checkout main",
        "git commit -m x",
        "git -c user.name=x commit -m y",
        "git -c color.ui=never log",
        "git config user.email a@b",
        "git config --get core.hooksPath",
        "git config alias.co checkout",
        "chmod 600 .mcp.json",
        "chmod +x scripts/build.sh",
        "chmod -R go-w src",
    ];
    let mut loud = Vec::new();
    for cmd in suite {
        let got = floor_in(project.path(), cmd);
        eprintln!("FP8B {cmd} => {got:?} filewrite={}", file_write(cmd));
        if got.is_some() {
            loud.push(cmd);
        }
    }
    assert!(loud.is_empty(), "false positives: {loud:?}");
}
