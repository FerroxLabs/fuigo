//! P166 round 13B feature 1: the protected-file check for branch switches under a narrow git grant.
//! Plan shapes (pure), the bounded git lister against real temporary repositories (including a hostile
//! `.git/config` and a poisoned parent environment), and the false-positive table (`FP13B` lines).

use crate::permission::branch_switch::{
    BranchSwitchPlan, GitTreeLister, TreeListing, TreeLister, plan_keeps_floor, read_capped, run_git_for_tests,
};
use crate::permission::exec_risk::branch_switch_plan;
use std::path::{Path, PathBuf};
use std::io::Read;
use std::process::Command;

/// Run real `git` in `dir` with a fixed identity; panics on failure.
pub(crate) fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .current_dir(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"])
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("git runs");
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

/// A repository whose `main` tracks `files` (plus a readme), HEAD on `main`.
pub(crate) fn real_repo(files: &[&str]) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    git(dir, &["init", "-q", "-b", "main"]);
    std::fs::write(dir.join("README.md"), "x").unwrap();
    for file in files {
        let path = dir.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "{}").unwrap();
    }
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "-m", "init"]);
    tmp
}

fn words(cmd: &str) -> Vec<String> {
    cmd.split_whitespace().map(str::to_owned).collect()
}

fn plan_of(script: &[&str], cwd: &Path) -> BranchSwitchPlan {
    let raw: Vec<Vec<String>> = script.iter().map(|cmd| words(cmd)).collect();
    branch_switch_plan(&raw, cwd)
}

fn revs(plan: &BranchSwitchPlan) -> Vec<Vec<String>> {
    match plan {
        BranchSwitchPlan::Probe(probes) => probes.iter().map(|p| p.trees.iter().map(|t| t.rev.clone()).collect()).collect(),
        other => panic!("expected a probe, got {other:?}"),
    }
}

fn keep(cwd: &Path, cmd: &str) -> bool {
    plan_keeps_floor(&plan_of(&[cmd], cwd), &GitTreeLister)
}

/// The verbs and the trees they involve; every other form is undetermined; harmless forms need no probe.
#[test]
fn p166_r13b_plan_shapes() {
    let cwd = Path::new("/work/repo");
    let probe = |cmd: &str| revs(&plan_of(&[cmd], cwd));
    assert_eq!(probe("git checkout main"), vec![vec!["HEAD", "main"]]);
    assert_eq!(probe("git switch main"), vec![vec!["HEAD", "main"]]);
    assert_eq!(probe("git merge feature"), vec![vec!["HEAD", "feature"]]);
    assert_eq!(probe("git rebase main"), vec![vec!["HEAD", "main"]]);
    assert_eq!(probe("git checkout -"), vec![vec!["HEAD", "@{-1}"]]);
    assert_eq!(probe("git switch -"), vec![vec!["HEAD", "@{-1}"]]);
    assert_eq!(probe("git pull"), vec![vec!["HEAD", "@{upstream}"]]);
    assert_eq!(probe("git pull --rebase origin main"), vec![vec!["HEAD", "@{upstream}", "refs/remotes/origin/main"]]);
    assert_eq!(probe("git stash pop"), vec![vec!["stash@{0}", "HEAD", "stash@{0}^3"]]);
    // P175 item 4e: a new branch at a start point probes HEAD and the start point.
    assert_eq!(probe("git checkout -b new main"), vec![vec!["HEAD", "main"]]);
    assert_eq!(probe("git switch -c new origin/main"), vec![vec!["HEAD", "origin/main"]]);
    assert_eq!(probe("git stash apply stash@{2}"), vec![vec!["stash@{2}", "HEAD", "stash@{2}^3"]]);
    // cd and -C move the directory git runs in.
    match plan_of(&["cd sub", "git checkout main"], cwd) {
        BranchSwitchPlan::Probe(p) => assert_eq!(p[0].cwd, cwd.join("sub")),
        other => panic!("{other:?}"),
    }
    match plan_of(&["git -C other checkout main"], cwd) {
        BranchSwitchPlan::Probe(p) => assert_eq!(p[0].cwd, cwd.join("other")),
        other => panic!("{other:?}"),
    }
    for cmd in [
        "git checkout --detach main",
        "git switch --detach main",
        "git checkout --orphan x",
        "git checkout main -- file",
        "git checkout -m main",
        "git checkout",
        "git checkout HEAD~2",
        "git checkout main:file",
        "git merge --no-ff feature",
        "git merge",
        "git rebase",
        "git rebase -i main",
        "git pull --depth=1",
        "git pull https://example.com/r.git",
        "git pull origin main extra",
        "git stash pop --weird",
        "git stash pop a b",
    ] {
        let plan = plan_of(&[cmd], cwd);
        assert!(matches!(plan, BranchSwitchPlan::Undetermined), "{cmd}: {plan:?}");
    }
    // `-C` plus a value-less global is still modelled.
    assert!(matches!(plan_of(&["git -C ../x -P checkout -"], cwd), BranchSwitchPlan::Probe(_)));
    // A new branch at HEAD rewrites nothing.
    for cmd in ["git switch -c feature", "git switch -C feature", "git checkout -b feature", "git stash", "git stash list"] {
        assert_eq!(plan_of(&[cmd], cwd), BranchSwitchPlan::NotApplicable, "{cmd}");
    }
    for cmd in [
        "git status", "git log", "git diff", "git add -A", "git commit -m x", "git fetch", "git push", "git reset --hard",
        "git cherry-pick abc", "ls", "git config user.name x",
    ] {
        assert_eq!(plan_of(&[cmd], cwd), BranchSwitchPlan::NotApplicable, "{cmd}");
    }
    // One undetermined segment decides the whole script.
    assert_eq!(plan_of(&["git checkout main", "git merge --no-ff x"], cwd), BranchSwitchPlan::Undetermined);
}

/// Real repositories: tracked protected name means keep; none means clear; unresolvable means keep.
#[test]
fn p166_r13b_real_repository_verdicts() {
    let none = real_repo(&[]);
    let cwd = none.path();
    git(cwd, &["branch", "feature"]);
    for cmd in ["git checkout main", "git checkout feature", "git switch feature", "git merge feature", "git rebase main", "git switch -c x"] {
        assert!(!keep(cwd, cmd), "no protected name: {cmd}");
    }
    // Unresolvable: no such ref, no upstream-less pull problem (optional), unborn stash, no stash.
    assert!(keep(cwd, "git checkout nosuchbranch"), "no local ref and no unique remote-tracking ref");
    assert!(keep(cwd, "git merge nosuchbranch"));
    // P175 item 4d (before: keep, "required tree does not resolve"): no stash means nothing can be rewritten.
    assert!(!keep(cwd, "git stash pop"), "no stash: git errors out, nothing rewritten");
    assert!(keep(cwd, "git checkout -"), "no previous branch");
    assert!(!keep(cwd, "git pull"), "no upstream: optional tree skipped, HEAD has no protected name");
    // Every protected name the matcher knows, tracked on `main`.
    for name in [".mcp.json", ".claude/settings.json", ".cursor/mcp.json", ".cursor/hooks.json", "deep/dir/.bashrc"] {
        let repo = real_repo(&[name]);
        git(repo.path(), &["branch", "other", "HEAD"]);
        assert!(keep(repo.path(), "git checkout other"), "HEAD tracks {name}");
        assert!(keep(repo.path(), "git checkout main"), "{name}");
    }
    // The target branch tracks it and HEAD does not.
    git(cwd, &["checkout", "-q", "-b", "risky"]);
    std::fs::write(cwd.join(".mcp.json"), "{}").unwrap();
    git(cwd, &["add", ".mcp.json"]);
    git(cwd, &["commit", "-q", "-m", "mcp"]);
    git(cwd, &["checkout", "-q", "main"]);
    assert!(keep(cwd, "git checkout risky"), "target tracks .mcp.json");
    assert!(keep(cwd, "git merge risky"));
    assert!(keep(cwd, "git rebase risky"));
    assert!(!keep(cwd, "git checkout feature"));
    // Stash: the stash commit's tree is involved.
    std::fs::write(cwd.join("README.md"), "changed").unwrap();
    git(cwd, &["stash", "-q"]);
    assert!(!keep(cwd, "git stash pop"));
    // Previous branch.
    git(cwd, &["checkout", "-q", "risky"]);
    assert!(keep(cwd, "git checkout -"), "HEAD (risky) tracks it");
    // A subdirectory still lists the whole repository (--full-tree).
    git(cwd, &["checkout", "-q", "main"]);
    std::fs::create_dir_all(cwd.join("sub")).unwrap();
    assert!(keep(&cwd.join("sub"), "git checkout risky"), "run from a subdirectory");
    // Not a repository: undetermined.
    let outside = tempfile::tempdir().unwrap();
    assert!(keep(outside.path(), "git checkout main"));
}

/// An injected lister. Outcomes per tree: not present (skipped only when the tree is optional), listed (a protected
/// name keeps), undetermined (over the cap, timeout, git error: keeps, optional or not).
/// P175 item 1, before: the optional `@{upstream}` tree answered `None` for both "absent" and "over the cap" and was
/// skipped. After: only `NotPresent` is skipped; `Undetermined` keeps the floor.
#[test]
fn p166_r13b_injected_listings() {
    struct Fake {
        head: Option<Vec<Vec<u8>>>,
        upstream: TreeListing,
    }
    impl TreeLister for Fake {
        fn repo_root(&self, _cwd: &Path) -> Option<PathBuf> {
            Some(PathBuf::from("/work/repo"))
        }
        fn names(&self, _cwd: &Path, rev: &str) -> TreeListing {
            if rev == "@{upstream}" {
                self.upstream.clone()
            } else {
                self.head.clone().map_or(TreeListing::Undetermined, TreeListing::Listed)
            }
        }
    }
    let clean = Some(vec![b"src/lib.rs".to_vec()]);
    let plan = plan_of(&["git pull"], Path::new("/work/repo"));
    let fake = |head: Option<Vec<Vec<u8>>>, upstream: TreeListing| Fake { head, upstream };
    assert!(!plan_keeps_floor(&plan, &fake(clean.clone(), TreeListing::NotPresent)), "optional upstream not present: skipped");
    assert!(plan_keeps_floor(&plan, &fake(clean.clone(), TreeListing::Undetermined)), "optional upstream over the cap or timed out");
    assert!(!plan_keeps_floor(&plan, &fake(clean.clone(), TreeListing::Listed(vec![b"src/a.rs".to_vec()]))));
    assert!(plan_keeps_floor(&plan, &fake(clean.clone(), TreeListing::Listed(vec![b"a/.mcp.json".to_vec()]))), "protected name");
    assert!(plan_keeps_floor(&plan, &fake(Some(vec![b"a/.mcp.json".to_vec()]), TreeListing::NotPresent)));
    assert!(plan_keeps_floor(&plan, &fake(Some(vec![b"x/.claude/settings.json".to_vec()]), TreeListing::NotPresent)));
    assert!(plan_keeps_floor(&plan, &fake(None, TreeListing::NotPresent)), "required HEAD tree unavailable");
    assert!(!plan_keeps_floor(&BranchSwitchPlan::NotApplicable, &fake(None, TreeListing::NotPresent)));
    assert!(plan_keeps_floor(&BranchSwitchPlan::Undetermined, &fake(clean, TreeListing::NotPresent)));
}

/// The caps: over the byte cap is undetermined; the timeout kills the child.
#[test]
fn p166_r13b_bounds() {
    let repo = real_repo(&["a.txt", "b.txt", "c.txt"]);
    let cwd = repo.path();
    let args = ["ls-tree", "-r", "--name-only", "-z", "--full-tree", "HEAD"];
    assert!(run_git_for_tests(cwd, &args, 1 << 20).is_some());
    assert!(run_git_for_tests(cwd, &args, 8).is_none(), "listing over the cap");
    assert!(run_git_for_tests(cwd, &["rev-parse", "--verify", "--quiet", "nosuch^{tree}"], 4096).is_none());
}

/// P175 item 4g: the cap at its real size, through the reader seam with a generated 16 MiB stream.
#[test]
fn p175_item4g_cap_near_its_real_size() {
    use crate::permission::branch_switch::MAX_LISTING_BYTES;
    assert_eq!(MAX_LISTING_BYTES, 16 * 1024 * 1024);
    let at = read_capped(std::io::repeat(b'a').take(MAX_LISTING_BYTES as u64), MAX_LISTING_BYTES);
    assert_eq!(at.map(|d| d.len()), Some(MAX_LISTING_BYTES), "exactly at the cap is accepted");
    let over = read_capped(std::io::repeat(b'a').take(MAX_LISTING_BYTES as u64 + 1), MAX_LISTING_BYTES);
    assert!(over.is_none(), "one byte over the cap is undetermined");
}

fn hostile_repo(marker: &Path) -> tempfile::TempDir {
    let repo = real_repo(&[]);
    let dir = repo.path();
    let script = dir.join("evil.sh");
    std::fs::write(&script, format!("#!/bin/sh\necho ran >> {}\n", marker.display())).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let hooks = dir.join("hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    for hook in ["post-checkout", "post-merge", "reference-transaction", "pre-auto-gc", "post-index-change"] {
        std::fs::copy(&script, hooks.join(hook)).unwrap();
    }
    let s = script.display();
    let config = format!(
        "\n[core]\n\tfsmonitor = {s}\n\tpager = {s}\n\thooksPath = {}\n\tsshCommand = {s}\n\taskpass = {s}\n\talternateRefsCommand = {s}\n\teditor = {s}\n\
[alias]\n\tls-tree = !{s}\n\trev-parse = !{s}\n[diff]\n\texternal = {s}\n[uploadpack]\n\tpackObjectsHook = {s}\n[gc]\n\tauto = 1\n",
        hooks.display()
    );
    let path = dir.join(".git/config");
    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str(&config);
    std::fs::write(path, text).unwrap();
    repo
}

/// A repository whose own config names programs everywhere git might run one: none runs.
#[test]
fn p166_r13b_hostile_repository_config_runs_nothing() {
    let scratch = tempfile::tempdir().unwrap();
    let marker = scratch.path().join("marker");
    let repo = hostile_repo(&marker);
    let cwd = repo.path();
    for cmd in ["git checkout main", "git pull", "git merge main", "git rebase main", "git stash pop"] {
        let _ = keep(cwd, cmd);
    }
    assert!(!keep(cwd, "git checkout main"), "the verdict itself is unaffected by the hostile config");
    assert!(!marker.exists(), "a repository-configured program ran during the check");
}

/// Runs inside a child process whose environment the parent poisoned (see the next test).
#[test]
fn p166_r13b_poisoned_env_child() {
    let Ok(repo) = std::env::var("P166_R13B_REPO") else { return };
    let cwd = PathBuf::from(repo);
    let clean = !keep(&cwd, "git checkout main");
    let tracked = keep(&cwd.join("tracked"), "git checkout main");
    println!("R13B_CHILD clean_repo_cleared={clean} tracked_repo_kept={tracked}");
    assert!(clean && tracked);
}

/// A `GIT_DIR`-style poisoned environment in the parent process must not reach the child git.
#[test]
fn p166_r13b_poisoned_parent_environment_is_ignored() {
    let clean = real_repo(&[]);
    let tracked = clean.path().join("tracked");
    std::fs::create_dir_all(&tracked).unwrap();
    // The tracked repository lives inside the clean one's directory: separate repository (its own .git).
    git(&tracked, &["init", "-q", "-b", "main"]);
    std::fs::write(tracked.join(".mcp.json"), "{}").unwrap();
    git(&tracked, &["add", "-A"]);
    git(&tracked, &["commit", "-q", "-m", "m"]);
    let scratch = tempfile::tempdir().unwrap();
    let marker = scratch.path().join("marker");
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["p166_r13b_poisoned_env_child", "--nocapture", "--test-threads=1"])
        .env("P166_R13B_REPO", clean.path())
        .env("GIT_DIR", "/nonexistent/.git")
        .env("GIT_WORK_TREE", "/nonexistent")
        .env("GIT_INDEX_FILE", "/nonexistent/index")
        .env("GIT_OBJECT_DIRECTORY", "/nonexistent/objects")
        .env("GIT_EXEC_PATH", "/nonexistent")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_0", scratch.path())
        .env("GIT_CONFIG_PARAMETERS", format!("'core.fsmonitor={}'", marker.display()))
        .env("GIT_NAMESPACE", "zzz")
        .output()
        .expect("child test binary runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "child failed:\n{stdout}\n{}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("R13B_CHILD clean_repo_cleared=true tracked_repo_kept=true"), "{stdout}");
    assert!(!marker.exists());
}

fn narrow_git_policy() -> crate::permission::policy::CompiledPolicy {
    use crate::permission::rules::parse_permission_rule;
    use crate::permission::types::{PermissionConfig, RuleAction};
    let rule = parse_permission_rule("Bash(git:*)", RuleAction::Allow).unwrap();
    crate::permission::policy::CompiledPolicy::new(PermissionConfig::new(vec![rule]))
}

/// A repository with a branch `feature`, a stash, and (optionally) a tracked `.mcp.json`.
pub(crate) fn table_repo(tracked: bool) -> tempfile::TempDir {
    let repo = real_repo(if tracked { &[".mcp.json"] } else { &[] });
    let cwd = repo.path();
    git(cwd, &["branch", "feature"]);
    std::fs::write(cwd.join("README.md"), "changed").unwrap();
    git(cwd, &["stash", "-q"]);
    repo
}

/// Whether `cmd` prompts under `Bash(git:*)` on the hub path (the sync form of the shared decision).
pub(crate) fn hub_prompts(cmd: &str, cwd: &Path) -> bool {
    // A git child that hits its 2 s cap under whole-crate load makes the plan Undetermined, which prompts. A command
    // that really prompts does so on every run, so a "does not prompt" expectation gets up to three attempts
    // (production timeout unchanged); `true` is returned only when all attempts prompted.
    let policy = narrow_git_policy();
    (0..3).all(|_| super::hub_needs_default_prompt(&super::AccessKind::Bash(cmd.to_owned()), Some(&policy), true, cwd))
}

/// False-positive table under `Bash(git:*)`: only the listed branch-moving verbs change, only where the repository
/// tracks a protected name. Prints `FP13B2 <cmd> => none=<prompts> tracked=<prompts>`.
#[test]
fn p166_r13b_false_positive_table() {
    let none = table_repo(false);
    let tracked = table_repo(true);
    // Changed by r13B: prompt only where a protected name is tracked.
    // `merge` and `rebase` also carry the unpinned protected floor (r8B) that asks in every repository; that is judged
    // before this function (see the hub test), so here they only show the FileWrite part.
    let moving = [
        "git checkout main", "git pull", "git pull --rebase origin main", "git stash pop", "git merge feature",
        "git rebase main",
    ];
    let always: [&str; 0] = [];
    let others = [
        "git switch -c feature2", "git status", "git log", "git diff", "git add -A", "git commit -m x", "git fetch",
        "git push",
    ];
    let mut wrong = Vec::new();
    for cmd in moving.iter().chain(always.iter()).chain(others.iter()) {
        let (a, b) = (hub_prompts(cmd, none.path()), hub_prompts(cmd, tracked.path()));
        eprintln!("FP13B2 {cmd} => none={a} tracked={b}");
        let always_prompts = always.contains(cmd);
        // `merge`/`rebase` never reach `hub_needs_default_prompt` as a FileWrite-only floor: they are protected hits
        // judged before it (see the hub test), so this function sees them as cleared.
        if a || b != moving.contains(cmd) {
            wrong.push(format!("{cmd}: none={a} tracked={b} (always={always_prompts})"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
    // Undetermined forms keep the floor even in a clean repository.
    for cmd in ["git checkout --detach main", "git checkout nosuchbranch"] {
        assert!(hub_prompts(cmd, none.path()), "{cmd}");
    }
}
