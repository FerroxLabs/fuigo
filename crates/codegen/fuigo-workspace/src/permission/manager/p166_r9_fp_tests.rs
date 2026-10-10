//! P166 round 9 false-positive suite. Prints `FP9 <command> => floor=<..> exec=<bool> filewrite=<bool>` per command (run
//! at the round-8 tip and at this tip with `--nocapture`). A command may prompt (protected floor or exec finding)
//! only when it is listed in `INTENDED`: the cost of the round-9 fixes that Sean decides on.

use super::{PermissionState, bash_protected_write_target, evaluate_bash};
use super::ClassifierSecurityFinding;

/// Commands that prompt at the round-9 tip BY DESIGN (audit fixes MEDIUM 4 and 6, and the round-8B recursive chmod).
const INTENDED: &[&str] = &[
    "GIT_PAGER=cat git log",
    "GIT_EDITOR=true git commit --amend --no-edit",
    "GIT_SSH_COMMAND='ssh -i key' git fetch",
    "git config core.editor vim",
    "git config credential.helper store",
    "chmod -R go-w .",
];

#[test]
fn p166_r9_false_positive_suite() {
    let project = tempfile::tempdir().unwrap();
    let cwd = project.path();
    for dir in ["out", "src", "scripts", ".git/hooks"] {
        std::fs::create_dir_all(cwd.join(dir)).unwrap();
    }
    let suite = [
        // round 9
        "echo {1..10}", "for i in {a..c}; do echo $i; done", "mkdir -p src/{a,b,c}", "touch file{1..300}.txt",
        "scp build.tar host:/srv/", "rsync -a ./ user@host:proj/", "scp host:file .", "GIT_PAGER=cat git log",
        "GIT_EDITOR=true git commit --amend --no-edit", "GIT_SSH_COMMAND='ssh -i key' git fetch",
        "git config user.name x", "git config core.editor vim", "git config pull.rebase true",
        "git config credential.helper store", "chmod -R go-w .", "chmod -R +x scripts", "cd src && ls ~+",
        // the earlier 36 (round 8)
        "ffmpeg -i a.mp4 out/b.mp4", "convert a.png b.png", "zip out.zip src/*", "vim README.md",
        "docker cp c:/x ./out", "git checkout main", "git switch main", "git pull", "git stash pop", "cat ~/.bashrc",
        "grep -r hooks .git/hooks", "ls -la .git/hooks", "rsync -a src/ dst/", "python3 script.py", "node build.js",
        "cp a b", "sed -n 1,5p .mcp.json", "echo $'a\\n'", "printf '%s\\n' {a,b,c}", "FOO=bar make",
        "env NODE_ENV=production node build.js", "cat <<< hello", "ls src/*.rs",
        "docker run --rm -v \"$PWD\":/w alpine ls /w", "docker build -t x .", "tar -cf out.tar src",
        "curl -o out.bin https://x.invalid/f", "wget -P downloads https://x.invalid/f", "scp host:x out/",
        "rsync -a src/ dst/ --exclude .git", "less README.md", "git add .mcp.json", "wc -l ~/.bashrc",
        "jq . .mcp.json", "python3 tools/lint.py src", "vim docs/my.mcp.json.md",
        // round 8B
        "git status", "git log", "git diff", "git -C ../other status", "git commit -m x",
        "git -c user.name=x commit -m y", "git config --get core.hooksPath", "git config alias.co checkout",
        "chmod 600 .mcp.json", "chmod -R go-w src",
    ];
    // Prompt already at round 8 (`-c` is a blanket exec risk) or FileWrite-only git rows, unchanged by round 9.
    let git_rows = ["git checkout main", "git switch main", "git pull", "git stash pop", "git -c user.name=x commit -m y"];
    let mut loud = Vec::new();
    for cmd in suite {
        let evaluation = evaluate_bash(cmd, &PermissionState::default(), true);
        let floor = bash_protected_write_target(&evaluation, cwd, None);
        let exec = evaluation.assessment.contains(ClassifierSecurityFinding::ExecOrAmbientGit);
        let filewrite = evaluation.assessment.contains(ClassifierSecurityFinding::FileWrite);
        eprintln!("FP9 {cmd} => floor={floor:?} exec={exec} filewrite={filewrite}");
        if (floor.is_some() || exec) && !INTENDED.contains(&cmd) && !git_rows.contains(&cmd) {
            loud.push(cmd);
        }
    }
    assert!(loud.is_empty(), "unintended false positives: {loud:?}");
}
