//! P166 round 12 false-positive suite: every ordinary command of the brief, floor and exec risk printed as
//! `FP12 <command> => floor=<..> exec=<..>` so the same file can run at an older commit for a before/after diff. Rows in
//! `EXPECT_PROMPT` are the intended new prompts; every other row stays silent.

use super::p166_r8_sweep_tests::floor;
use super::{ClassifierSecurityFinding, PermissionState, evaluate_bash};

const EXPECT_PROMPT: &[&str] = &["scp id.pub host:.ssh/authorized_keys"];

/// `clone` and `submodule add` write an unknown tree, so they already took the `Sensitive` floor at `39c6d45d`
/// (unchanged by round 12): only their exec risk is asserted.
const FLOOR_UNCHANGED: &[&str] = &[
    "git clone https://github.com/a/b", "git clone git@github.com:a/b.git", "git clone file:///srv/git/x.git",
    "git clone ../other", "git submodule add https://github.com/a/lib",
];

const SUITE: &[&str] = &[
    "echo hi > out.txt", "echo hi > \"$PWD/out.txt\"", "echo hi >> \"$HOME/notes.txt\"", "make > build.log 2>&1",
    "cmd > /dev/null", "ls ~", "ls ~root", "cat ~alice/notes", "cd ~/src", "scp build.tar host:/srv/",
    "scp build.tar user@build.example.com:/srv/app/", "rsync -a ./ user@host:proj/", "rsync -a ./ 192.168.1.5:backup/",
    "scp host:file .", "scp host:.bashrc ./their-bashrc", "scp id.pub host:.ssh/authorized_keys",
    "git clone https://github.com/a/b", "git clone git@github.com:a/b.git", "git clone file:///srv/git/x.git",
    "git clone ../other", "git remote add origin git@github.com:a/b.git", "git remote set-url origin https://github.com/a/b",
    "git fetch origin", "git pull", "git push origin main", "git submodule add https://github.com/a/lib",
    "git ls-remote origin", "git config --unset core.editor", "git config --get core.hooksPath", "git config -l",
    "git config remote.origin.url https://github.com/a/b", "chmod +x \"$dir/build.sh\"", "cat \"$x/.git/hooks/pre-commit\"",
    "ls \"$dir\"", "grep -r foo \"$HOME/.ssh\"", "find . -name '*.rs' -print", "diff a b", "less README.md",
];

#[test]
fn p166_r12_false_positive_suite_rows() {
    let project = tempfile::tempdir().unwrap();
    for dir in ["out", "src", "sub", ".git/hooks"] {
        std::fs::create_dir_all(project.path().join(dir)).unwrap();
    }
    let mut wrong = Vec::new();
    for cmd in SUITE {
        let got = floor(project.path(), cmd);
        let risky = evaluate_bash(cmd, &PermissionState::default(), true)
            .assessment
            .contains(ClassifierSecurityFinding::ExecOrAmbientGit);
        eprintln!("FP12 {cmd} => floor={got:?} exec={risky}");
        let prompts = (got.is_some() && !FLOOR_UNCHANGED.contains(cmd)) || risky;
        if prompts != EXPECT_PROMPT.contains(cmd) {
            wrong.push(format!("{cmd}: floor={got:?} exec={risky}"));
        }
    }
    assert!(wrong.is_empty(), "false-positive suite differs:\n{}", wrong.join("\n"));
}
