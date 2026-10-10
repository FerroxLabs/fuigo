//! P166 round 13A (Grok r12): ordinary remote copies stay out of the local write assessment (item 1), git options that
//! run a command (item 2), current-user `~name` (items 3 and 7), reader output options (item 4), IPv6 URLs (item 5),
//! `file:` insteadOf bases (item 6), and the false-positive suite (`FP13` lines for a before/after diff).

use super::p166_r8_sweep_tests::floor;
use super::{ClassifierSecurityFinding, PermissionState, evaluate_bash};
use crate::permission::shell_access::current_user_name;

fn exec(cmd: &str) -> bool {
    evaluate_bash(cmd, &PermissionState::default(), true)
        .assessment
        .contains(ClassifierSecurityFinding::ExecOrAmbientGit)
}

fn check_exec(rows: &[&str], risky: bool) {
    let wrong: Vec<&&str> = rows.iter().filter(|cmd| exec(cmd) != risky).collect();
    assert!(wrong.is_empty(), "expected exec risk={risky}:\n{wrong:#?}");
}

/// A project directory far below the filesystem root, so a wrong `~name` base never reaches `/etc` by `..` alone.
pub(super) fn deep_project() -> (tempfile::TempDir, std::path::PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let deep = root.path().join("a/b/c/d/e/f/g/h");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::create_dir_all(deep.join(".git/hooks")).unwrap();
    (root, deep)
}

pub(super) fn check_floor(cwd: &std::path::Path, rows: &[String], blocked: bool) {
    let wrong: Vec<String> = rows
        .iter()
        .filter_map(|cmd| {
            let got = floor(cwd, cmd);
            (got.is_some() != blocked).then(|| format!("{cmd}: expected blocked={blocked}, got {got:?}"))
        })
        .collect();
    assert!(wrong.is_empty(), "protected floor mismatches:\n{}", wrong.join("\n"));
}

/// Item 1 (HIGH 1): a host destination writes no local file; its path is still judged by the protected floor.
#[test]
fn p166_r13_item1_remote_destination_is_not_a_local_write() {
    let state = PermissionState::default();
    for cmd in [
        "scp a.txt host:b.txt",
        "scp -r dist/ user@host:/srv/app/",
        "rsync -a ./ host:proj/",
        "rsync -az --delete build/ deploy@web:/var/www/",
        "scp build.tar host:/srv/",
    ] {
        let e = evaluate_bash(cmd, &state, true);
        assert!(!e.assessment.contains(ClassifierSecurityFinding::FileWrite), "{cmd}: writes no local file");
    }
    let (_root, deep) = deep_project();
    let rows = ["scp id.pub host:.ssh/authorized_keys", "scp x host:.bashrc", "rsync -a x/ host:.git/hooks/"]
        .map(String::from);
    check_floor(&deep, &rows, true);
    // A local destination is still a FileWrite.
    let e = evaluate_bash("scp host:a.txt b.txt", &state, true);
    assert!(e.assessment.contains(ClassifierSecurityFinding::FileWrite), "a local destination stays a FileWrite");
}

/// Item 2 (HIGH 2): options that run a command are exec risk whatever the value and form.
#[test]
fn p166_r13_item2_git_command_options_are_exec_risk() {
    check_exec(
        &[
            "git fetch --upload-pack=touch .",
            "git fetch --upload-pack touch .",
            "git fetch --upload-pack 'sh -c id' origin",
            "git ls-remote --upload-pack=touch .",
            "git pull --upload-pack=touch .",
            "git clone -u touch /local",
            "git clone -u 'sh -c id' https://x/y",
            "git clone -ush https://x/y",
            "git clone --upload-pack='sh -c id' https://x/y",
            "git push --receive-pack='sh -c id' origin",
            "git push --receive-pack 'sh -c id' origin",
            "git push --exec='sh -c id' origin",
            "git push --repo='ext::sh -c id'",
            "git archive --remote=. --exec=touch HEAD",
            "git archive --remote=https://x/y --exec='sh -c id' HEAD",
            "git archive --remote https://x/y --exec 'sh -c id' HEAD",
            "git clone --config core.sshCommand='sh -c id' https://x/y",
            "git clone -c core.sshCommand='sh -c id' https://x/y",
            "git clone -ccore.sshCommand=x https://x/y",
            "git clone --template=/tmp/evil https://x/y",
            "git clone --template /tmp/evil https://x/y",
            "git fetch --unknown-opt 'ext::sh -c id'",
            "git fetch --unknown-opt VALUE 'ext::sh -c id'",
            "git clone --unknown-opt 'ext::sh -c id'",
        ],
        true,
    );
}

/// Item 2, the other side: ordinary options and values stay silent.
#[test]
fn p166_r13_item2_ordinary_git_options_are_not_exec_risk() {
    check_exec(
        &[
            "git fetch origin",
            "git fetch --all --prune",
            "git fetch --depth 1 origin main",
            "git clone --depth 1 https://github.com/a/b",
            "git clone -b main https://github.com/a/b dir",
            "git clone --recurse-submodules git@github.com:a/b.git",
            "git clone -c user.name=x https://github.com/a/b",
            "git push -u origin main",
            "git push --force-with-lease origin main",
            "git push origin :old-branch",
            "git pull --rebase origin main",
            "git ls-remote --heads origin",
            "git archive --format=tar HEAD",
            "git archive --remote=https://github.com/a/b HEAD",
            "git fetch -u origin",
            "git fetch 'ssh://[2001:db8::1]/repo.git'",
            "git fetch ssh://git@github.com:22/a/b.git",
        ],
        false,
    );
}

/// Items 5 and 6 (LOW): a bracketed IPv6 host is ordinary; `file:` with any slash count is a command insteadOf base.
#[test]
fn p166_r13_items5_6_ipv6_and_file_scheme() {
    check_exec(
        &[
            "git fetch 'ssh://[2001:db8::1]/repo.git'",
            "git clone 'https://[::1]:8080/a.git'",
            "git remote add o 'ssh://git@[2001:db8::1]/a.git'",
        ],
        false,
    );
    check_exec(
        &[
            "git fetch 'ext::sh -c id'",
            "git fetch 'a::b'",
        ],
        true,
    );
    // Config SET rows are judged by the protected floor.
    let (_root, deep) = deep_project();
    let sets = [
        "git config url.\"file:/tmp/evil.git\".insteadOf https://github.com/a/b.git",
        "git config url.\"FILE:/tmp/evil.git\".insteadOf https://github.com/a/b.git",
        "git config url.\"file:///tmp/evil.git\".insteadOf https://github.com/a/b.git",
    ]
    .map(String::from);
    check_floor(&deep, &sets, true);
}

/// Items 3 and 7 (HIGH 3, LOW 7): a current-user `~name` is the home for the base; another user's stays fail-closed.
#[test]
fn p166_r13_item3_current_user_tilde_resolves_to_home() {
    let Some(user) = current_user_name() else {
        // The user cannot be determined: every `~name` write fails closed (stated in the receipt).
        let (_root, deep) = deep_project();
        check_floor(&deep, &["touch ~alice/x".to_owned()], true);
        return;
    };
    let (_root, deep) = deep_project();
    // `~name` must resolve against the home: exactly as many `..` as the home has components reach `/etc`, while a
    // base one component deeper (the unresolved `~name` word) stops at the first component.
    let home_depth = std::env::var("HOME").map_or(2, |home| home.split('/').filter(|c| !c.is_empty()).count());
    let up = "../".repeat(home_depth);
    let blocked = [
        format!("cd ~{user} && touch {up}etc/passwd"),
        format!("touch ~{user}/{up}etc/x"),
        format!("touch ~{user}/.bashrc"),
        format!("cd ~{user}/proj && touch ../.bashrc"),
        format!("pushd ~{user} && touch {up}etc/passwd"),
        "cd ~nobody-such-user && touch notes.txt".to_owned(),
        "touch ~nobody-such-user/x".to_owned(),
        // A same-command assignment cannot redefine the current user.
        "USER=nobody-such-user touch ~nobody-such-user/x".to_owned(),
    ];
    check_floor(&deep, &blocked, true);
    let silent = [
        format!("touch ~{user}/notes.txt"),
        format!("cd ~{user}/src && make"),
        format!("ls ~{user}"),
        "touch ~/notes.txt".to_owned(),
    ];
    check_floor(&deep, &silent, false);
}

/// Item 4 (MEDIUM): a reader's output option takes the undecodable-value scan in every spelling.
#[test]
fn p166_r13_item4_reader_output_options_scan_undecodable_values() {
    let (_root, deep) = deep_project();
    let blocked = [
        "less --log-file=\"$x/.bashrc\" README",
        "less --log-file \"$x/.git/hooks/pre-commit\" README",
        "less --LOG-FILE \"$x/.bashrc\" README",
        "less -o \"$x/.bashrc\" README",
        "less -O \"$x/.bashrc\" README",
        "less -o\"$x/.bashrc\" README",
        "tree -o \"$x/.bashrc\"",
        "diff --output=\"$x/.bashrc\" a b",
        "sort --output=\"$x/.git/hooks/x\" a",
        "sort -o \"$x/.git/hooks/x\" a",
        "uniq a \"$x/.bashrc\"",
    ]
    .map(String::from);
    check_floor(&deep, &blocked, true);
    let silent = [
        "less -N \"$x/README\"",
        "less -L \"$x/.bashrc\"",
        "cat \"$x/.git/hooks/pre-commit\"",
        "grep -o foo \"$x/.git/hooks/pre-commit\"",
        "head -n 3 \"$x/.bashrc\"",
        "diff \"$x/.bashrc\" b",
        "less README.md",
    ]
    .map(String::from);
    check_floor(&deep, &silent, false);
}

const FP13: &[&str] = &[
    "scp a.txt host:b.txt", "scp -r dist/ user@host:/srv/app/", "rsync -a ./ host:proj/",
    "rsync -az --delete build/ deploy@web:/var/www/", "scp id.pub host:.ssh/authorized_keys", "git fetch origin",
    "git fetch --all --prune", "git fetch --depth 1 origin main", "git clone --depth 1 https://github.com/a/b",
    "git clone -b main https://github.com/a/b dir", "git clone --recurse-submodules git@github.com:a/b.git",
    "git push -u origin main", "git push --force-with-lease origin main", "git pull --rebase origin main",
    "git ls-remote --heads origin", "git archive --format=tar HEAD", "git fetch 'ssh://[2001:db8::1]/repo.git'",
    "git fetch ssh://git@github.com:22/a/b.git", "ls ~", "ls ~{U}", "touch ~{U}/notes.txt", "touch ~/notes.txt",
    "cd ~{U}/src && make", "less README.md", "less -N README.md", "sort -u names.txt", "sort -o sorted.txt names.txt",
    "diff a b", "uniq a b",
];

/// `clone` writes an unknown tree, so it takes the `Sensitive` floor at `39c6d45d` too: only exec risk is asserted.
const FP13_FLOOR_UNCHANGED: &[&str] = &[
    "git clone --depth 1 https://github.com/a/b", "git clone -b main https://github.com/a/b dir",
    "git clone --recurse-submodules git@github.com:a/b.git",
];

#[test]
fn p166_r13_false_positive_suite_rows() {
    let (_root, deep) = deep_project();
    let user = current_user_name().unwrap_or_else(|| "nobody-such-user".to_owned());
    let mut wrong = Vec::new();
    for template in FP13 {
        let cmd = template.replace("{U}", &user);
        let got = floor(&deep, &cmd);
        let risky = exec(&cmd);
        let file_write = evaluate_bash(&cmd, &PermissionState::default(), true)
            .assessment
            .contains(ClassifierSecurityFinding::FileWrite);
        eprintln!("FP13 {template} => floor={got:?} exec={risky} filewrite={file_write}");
        let prompts = (got.is_some() && !FP13_FLOOR_UNCHANGED.contains(template)) || risky;
        if prompts != (*template == "scp id.pub host:.ssh/authorized_keys") {
            wrong.push(format!("{template}: floor={got:?} exec={risky}"));
        }
    }
    assert!(wrong.is_empty(), "false-positive suite differs:\n{}", wrong.join("\n"));
}
