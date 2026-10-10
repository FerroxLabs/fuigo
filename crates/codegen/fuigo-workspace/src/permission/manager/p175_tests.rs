//! P175 part A: leftovers of the P166 branch-switch check. Three-outcome tree listing (an optional tree that cannot
//! be listed keeps the floor), lazy fetch never starts a transport, remote-only `checkout <name>` is judged by its
//! unique remote-tracking tree. Every case asserts the end-to-end decision under `Bash(git:*)`.

use super::p166_r13b_branch_tests::{git, hub_prompts, real_repo};
use std::path::Path;

fn git_out(dir: &Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git").current_dir(dir).args(args).env("GIT_CONFIG_NOSYSTEM", "1").output().unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// Remove the loose object `sha` (a tree) so that listing it fails while a commit naming it still resolves.
fn delete_loose_object(repo: &Path, sha: &str) {
    let path = repo.join(".git/objects").join(&sha[..2]).join(&sha[2..]);
    assert!(path.exists(), "loose object {sha} expected");
    std::fs::remove_file(path).unwrap();
}

/// A clean `main`; remote-tracking `origin/up` is one commit that adds `.mcp.json` and is `main`'s upstream.
fn repo_with_upstream() -> (tempfile::TempDir, String) {
    let repo = real_repo(&[]);
    let dir = repo.path();
    git(dir, &["checkout", "-q", "-b", "up"]);
    std::fs::write(dir.join(".mcp.json"), "{}").unwrap();
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "-m", "mcp"]);
    let tree = git_out(dir, &["rev-parse", "HEAD^{tree}"]);
    git(dir, &["update-ref", "refs/remotes/origin/up", "HEAD"]);
    git(dir, &["checkout", "-q", "main"]);
    git(dir, &["branch", "-q", "-D", "up"]);
    git(dir, &["config", "remote.origin.url", "."]);
    git(dir, &["config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"]);
    git(dir, &["config", "branch.main.remote", "origin"]);
    git(dir, &["config", "branch.main.merge", "refs/heads/up"]);
    (repo, tree)
}

/// Item 1: the optional upstream tree tracks `.mcp.json`. Listable: prompt. Its listing fails (here: the tree object is
/// gone): the floor is kept as well (before: the optional tree was skipped and the prompt cleared).
#[test]
fn p175_item1_optional_tree_that_cannot_be_listed_keeps_the_floor() {
    let (repo, tree) = repo_with_upstream();
    let dir = repo.path();
    assert!(hub_prompts("git pull", dir), "listable upstream tree tracks .mcp.json");
    delete_loose_object(dir, &tree);
    assert!(hub_prompts("git pull", dir), "upstream listing failed: undetermined, floor kept");
    // A pull whose optional tree really does not exist is still cleared.
    let plain = real_repo(&[]);
    assert!(!hub_prompts("git pull", plain.path()), "no upstream: optional tree not present, skipped");
}

/// Item 1, stash flavour: `stash^3` (untracked files) cannot be listed.
#[test]
fn p175_item1_stash_untracked_tree_that_cannot_be_listed_keeps_the_floor() {
    let repo = real_repo(&[]);
    let dir = repo.path();
    std::fs::write(dir.join(".mcp.json"), "{}").unwrap();
    git(dir, &["stash", "push", "-q", "-u"]);
    let tree = git_out(dir, &["rev-parse", "stash@{0}^3^{tree}"]);
    assert!(hub_prompts("git stash pop", dir), "untracked part of the stash tracks .mcp.json");
    delete_loose_object(dir, &tree);
    assert!(hub_prompts("git stash pop", dir), "stash^3 listing failed: floor kept");
}

/// Item 2: a partial clone whose promisor remote would run a program if contacted. The check must fail instead
/// (undetermined, floor kept) and must not contact it.
#[test]
fn p175_item2_partial_clone_check_never_contacts_the_promisor_remote() {
    let scratch = tempfile::tempdir().unwrap();
    let src = scratch.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    git(&src, &["init", "-q", "-b", "main"]);
    git(&src, &["config", "uploadpack.allowFilter", "true"]);
    git(&src, &["config", "uploadpack.allowAnySHA1InWant", "true"]);
    std::fs::write(src.join("README.md"), "x").unwrap();
    git(&src, &["add", "-A"]);
    git(&src, &["commit", "-q", "-m", "init"]);
    git(&src, &["checkout", "-q", "-b", "feature"]);
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("sub/file.txt"), "y").unwrap();
    git(&src, &["add", "-A"]);
    git(&src, &["commit", "-q", "-m", "feature"]);
    git(&src, &["checkout", "-q", "main"]);
    let dst = scratch.path().join("dst");
    let url = format!("file://{}", src.display());
    git(scratch.path(), &["clone", "-q", "--filter=tree:0", &url, "dst"]);
    // Control: main's trees were fetched by the clone's checkout, so no remote is needed.
    assert!(!hub_prompts("git checkout main", &dst), "partial clone, trees present: cleared");
    // Now the promisor remote is a program that leaves a marker.
    let marker = scratch.path().join("marker");
    let prog = scratch.path().join("remote.sh");
    std::fs::write(&prog, format!("#!/bin/sh\ntouch {}\nexit 1\n", marker.display())).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    git(&dst, &["config", "remote.origin.url", &format!("ext::{}", prog.display())]);
    git(&dst, &["config", "protocol.ext.allow", "always"]);
    // The listing child itself (the hub path flags the repository's `protocol.ext.allow` as ambient config and prompts
    // before any probe, so the probe is driven directly here).
    let plan = crate::permission::exec_risk::branch_switch_plan(
        &[vec!["git".to_owned(), "checkout".to_owned(), "origin/feature".to_owned()]],
        &dst,
    );
    assert!(
        crate::permission::branch_switch::plan_keeps_floor(&plan, &crate::permission::branch_switch::GitTreeLister),
        "missing tree: undetermined, floor kept"
    );
    assert!(hub_prompts("git checkout origin/feature", &dst), "hub path: floor kept");
    assert!(!marker.exists(), "the check contacted the promisor remote");
}

/// A clone of `src_files`' repository (branch `feature` tracks `feature_files`), so that `feature` exists only as
/// `refs/remotes/origin/feature` in the clone.
fn clone_with_remote_only_feature(feature_files: &[&str]) -> (tempfile::TempDir, std::path::PathBuf) {
    let scratch = tempfile::tempdir().unwrap();
    let src = scratch.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    git(&src, &["init", "-q", "-b", "main"]);
    std::fs::write(src.join("README.md"), "x").unwrap();
    git(&src, &["add", "-A"]);
    git(&src, &["commit", "-q", "-m", "init"]);
    git(&src, &["checkout", "-q", "-b", "feature"]);
    for f in feature_files {
        std::fs::write(src.join(f), "{}").unwrap();
    }
    std::fs::write(src.join("f.txt"), "f").unwrap();
    git(&src, &["add", "-A"]);
    git(&src, &["commit", "-q", "-m", "feature"]);
    git(&src, &["checkout", "-q", "main"]);
    git(scratch.path(), &["clone", "-q", &format!("file://{}", src.display()), "dst"]);
    let dst = scratch.path().join("dst");
    (scratch, dst)
}

/// Item 3: `git checkout feature` where `feature` exists only as `origin/feature`.
#[test]
fn p175_item3_remote_only_branch_is_judged_by_its_remote_tracking_tree() {
    let (_keep, clean) = clone_with_remote_only_feature(&[]);
    assert!(!hub_prompts("git checkout feature", &clean), "clean remote-only branch: cleared");
    assert!(!hub_prompts("git switch feature", &clean));
    let (_keep2, risky) = clone_with_remote_only_feature(&[".mcp.json"]);
    assert!(hub_prompts("git checkout feature", &risky), "remote-only branch tracks .mcp.json");
    // No such branch anywhere: undetermined.
    assert!(hub_prompts("git checkout nosuch", &clean));
    // Two remotes with the same short name: git would need checkout.defaultRemote; undetermined.
    let origin_feature = git_out(&clean, &["rev-parse", "refs/remotes/origin/feature"]);
    git(&clean, &["update-ref", "refs/remotes/other/feature", &origin_feature]);
    assert!(hub_prompts("git checkout feature", &clean), "ambiguous remote-tracking name");
}

/// Item 4d: `git stash pop|apply` when no stash exists rewrites nothing (git errors out): cleared, also where a
/// protected name is tracked.
#[test]
fn p175_item4d_stash_pop_without_a_stash_is_not_applicable() {
    let none = real_repo(&[]);
    let tracked = real_repo(&[".mcp.json"]);
    for cmd in ["git stash pop", "git stash apply", "git stash pop stash@{3}"] {
        assert!(!hub_prompts(cmd, none.path()), "{cmd}: no stash, clean repo");
        assert!(!hub_prompts(cmd, tracked.path()), "{cmd}: no stash, nothing can be rewritten");
    }
}

/// Item 4e: a new branch at a start point probes HEAD and the start point.
#[test]
fn p175_item4e_new_branch_at_a_start_point_probes_head_and_start() {
    let (_keep, clean) = clone_with_remote_only_feature(&[]);
    assert!(!hub_prompts("git checkout -b new origin/main", &clean));
    assert!(!hub_prompts("git switch -c new origin/feature", &clean));
    let (_keep2, risky) = clone_with_remote_only_feature(&[".mcp.json"]);
    assert!(hub_prompts("git checkout -b new origin/feature", &risky), "start point tracks .mcp.json");
    assert!(hub_prompts("git switch -c new nosuchstart", &risky), "start point unresolved");
    assert!(!hub_prompts("git switch -c new", &risky), "new branch at HEAD still rewrites nothing");
}

/// Item 4f: an unborn HEAD with a resolvable target probes only the target; a bare repository has no working tree.
#[test]
fn p175_item4f_unborn_head_and_bare_repository() {
    for (files, expect_prompt) in [(&[][..], false), (&[".mcp.json"][..], true)] {
        let repo = real_repo(files);
        git(repo.path(), &["symbolic-ref", "HEAD", "refs/heads/unborn"]);
        assert_eq!(hub_prompts("git checkout main", repo.path()), expect_prompt, "unborn HEAD, files {files:?}");
    }
    let (_keep, clone) = clone_with_remote_only_feature(&[".mcp.json"]);
    let bare = clone.parent().unwrap().join("bare.git");
    git(clone.parent().unwrap(), &["clone", "-q", "--bare", clone.to_str().unwrap(), "bare.git"]);
    assert!(!hub_prompts("git checkout main", &bare), "bare repository: nothing to rewrite");
}

/// Item 4a: an earlier segment that can move refs makes the probe stale: undetermined.
#[test]
fn p175_item4a_earlier_ref_moving_segment_is_undetermined() {
    let repo = real_repo(&[]);
    for cmd in ["git fetch origin && git checkout main", "git pull; git checkout main", "git remote update && git checkout main"] {
        assert!(hub_prompts(cmd, repo.path()), "{cmd}");
    }
    for cmd in ["git status && git checkout main", "git log && git checkout main"] {
        assert!(!hub_prompts(cmd, repo.path()), "{cmd}: read-only earlier segment");
    }
}

/// Item 4c: a replace ref that hides a protected name in the real tree.
#[test]
fn p175_item4c_replace_refs_do_not_hide_the_real_tree() {
    let repo = real_repo(&[]);
    let dir = repo.path();
    git(dir, &["checkout", "-q", "-b", "risky"]);
    std::fs::write(dir.join(".mcp.json"), "{}").unwrap();
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "-m", "mcp"]);
    let risky = git_out(dir, &["rev-parse", "HEAD"]);
    git(dir, &["checkout", "-q", "main"]);
    git(dir, &["checkout", "-q", "-b", "clean-twin"]);
    git(dir, &["commit", "-q", "--allow-empty", "-m", "twin"]);
    let twin = git_out(dir, &["rev-parse", "HEAD"]);
    git(dir, &["checkout", "-q", "main"]);
    git(dir, &["replace", &risky, &twin]);
    assert!(hub_prompts("git checkout risky", dir), "the real tree of risky tracks .mcp.json");
}

/// The listing child's guards: the lazy-fetch switch, an empty protocol allow-list and every transport denied.
#[test]
fn p175_item2_hardened_command_denies_lazy_fetch_and_every_transport() {
    let command = crate::permission::branch_switch::hardened_git_command(Path::new("/"), &["rev-parse", "HEAD"]);
    let env: Vec<(String, Option<String>)> = command
        .get_envs()
        .map(|(k, v)| (k.to_string_lossy().into_owned(), v.map(|v| v.to_string_lossy().into_owned())))
        .collect();
    let has = |k: &str, v: &str| env.iter().any(|(key, val)| key == k && val.as_deref() == Some(v));
    assert!(has("GIT_NO_LAZY_FETCH", "1"), "git 2.45+ lazy-fetch switch");
    assert!(has("GIT_ALLOW_PROTOCOL", ""), "empty allow-list: no transport");
    let args: Vec<String> = command.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
    assert!(args.iter().any(|a| a == "protocol.allow=never"));
    for name in ["file", "git", "ssh", "http", "https", "ext"] {
        assert!(args.iter().any(|a| *a == format!("protocol.{name}.allow=never")), "{name}");
    }
}

/// False-positive table under `Bash(git:*)`, after P175. Prints `FP175 <cmd> => none=<prompts> tracked=<prompts>`.
#[test]
fn p175_false_positive_table() {
    let none = super::p166_r13b_branch_tests::table_repo(false);
    let tracked = super::p166_r13b_branch_tests::table_repo(true);
    let rows: [(&str, bool, bool); 14] = [
        ("git checkout main", false, true),
        ("git switch -c new", false, false),
        ("git pull", false, true),
        ("git pull --rebase origin main", false, true),
        ("git merge feature", false, true),
        ("git rebase main", false, true),
        ("git stash pop", false, true),
        ("git fetch && git checkout main", true, true),
        ("git status", false, false),
        ("git log", false, false),
        ("git commit -m x", false, false),
        ("git fetch", false, false),
        ("git push", false, false),
        ("git checkout feature", false, true),
    ];
    let mut wrong = Vec::new();
    for (cmd, a, b) in rows {
        let (x, y) = (hub_prompts(cmd, none.path()), hub_prompts(cmd, tracked.path()));
        eprintln!("FP175 {cmd} => none={x} tracked={y}");
        if (x, y) != (a, b) {
            wrong.push(format!("{cmd}: none={x} tracked={y}, expected {a}/{b}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

// ---- Problem 1: child count -------------------------------------------------------------------------------------

fn plan_for(cmds: &[&str], cwd: &Path) -> crate::permission::branch_switch::BranchSwitchPlan {
    let raw: Vec<Vec<String>> = cmds.iter().map(|c| c.split_whitespace().map(str::to_owned).collect()).collect();
    crate::permission::exec_risk::branch_switch_plan(&raw, cwd)
}

/// (keeps floor, git children spawned for `cwd`, listing children among them).
fn run_counted(cmds: &[&str], cwd: &Path) -> (bool, usize, usize) {
    let plan = plan_for(cmds, cwd);
    let before = crate::permission::branch_switch::SPAWNED.lock().unwrap().len();
    let started = std::time::Instant::now();
    let keeps = crate::permission::branch_switch::plan_keeps_floor(&plan, &crate::permission::branch_switch::GitTreeLister);
    eprintln!("P175 check {cmds:?} took {:?}", started.elapsed());
    let log = crate::permission::branch_switch::SPAWNED.lock().unwrap();
    let mine: Vec<&Vec<String>> = log.iter().skip(before).filter(|(dir, _)| dir == cwd).map(|(_, args)| args).collect();
    let listings = mine.iter().filter(|a| a.iter().any(|x| x == "ls-tree" || x == "ls-files")).count();
    (keeps, mine.len(), listings)
}

/// Common case: a plain `git checkout main` spawns at most 3 children when HEAD and `main` are the same tree (one
/// discovery, one batched resolve, ONE listing: equal tree ids are listed once) and at most 4 when the trees differ.
#[test]
fn p175_item1_common_case_child_count_is_bounded() {
    let repo = real_repo(&[]);
    let dir = repo.path();
    let (keeps, children, listings) = run_counted(&["git checkout main"], dir);
    assert!(!keeps);
    assert!(children <= 3, "same tree: {children} children");
    assert_eq!(listings, 1, "equal tree ids are listed once");
    git(dir, &["checkout", "-q", "-b", "other"]);
    std::fs::write(dir.join("a.txt"), "a").unwrap();
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "-m", "a"]);
    let (keeps, children, listings) = run_counted(&["git checkout main"], dir);
    assert!(!keeps);
    assert!(children <= 4, "two trees: {children} children");
    assert_eq!(listings, 2);
}

// ---- Problem 2: submodule recursion -------------------------------------------------------------------------------

fn repo_with_gitmodules() -> tempfile::TempDir {
    let repo = real_repo(&[".gitmodules"]);
    git(repo.path(), &["branch", "feature"]);
    repo
}

fn config_children(dir: &Path) -> usize {
    let log = crate::permission::branch_switch::SPAWNED.lock().unwrap();
    log.iter().filter(|(d, a)| d == dir && a.iter().any(|x| x == "config")).count()
}

#[test]
fn p175_item4b_submodule_recursion_flag_is_undetermined() {
    let repo = repo_with_gitmodules();
    for cmd in [
        "git checkout --recurse-submodules feature",
        "git -c submodule.recurse=true checkout feature",
        "git pull --recurse-submodules",
        "git switch --recurse-submodules feature",
    ] {
        assert!(hub_prompts(cmd, repo.path()), "{cmd}");
    }
}

#[test]
fn p175_item4b_local_config_recursion_keeps_the_floor() {
    let repo = repo_with_gitmodules();
    let dir = repo.path();
    assert!(!hub_prompts("git checkout feature", dir), "no recursion configured");
    git(dir, &["config", "submodule.recurse", "true"]);
    assert!(hub_prompts("git checkout feature", dir), "submodule.recurse=true");
    git(dir, &["config", "--unset", "submodule.recurse"]);
    git(dir, &["config", "checkout.recurseSubmodules", "true"]);
    assert!(hub_prompts("git checkout feature", dir), "checkout.recurseSubmodules=true");
    git(dir, &["config", "checkout.recurseSubmodules", "false"]);
    assert!(!hub_prompts("git checkout feature", dir), "explicitly false");
}

/// The global config is visible to the one config child, through a fixture HOME.
#[test]
fn p175_item4b_global_config_recursion_keeps_the_floor() {
    let repo = repo_with_gitmodules();
    let home = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join(".gitconfig"), "[submodule]\n\trecurse = true\n").unwrap();
    assert_eq!(
        crate::permission::branch_switch::submodule_recursion_with_home(repo.path(), Some(home.path().as_os_str())),
        Some(true)
    );
    let clean_home = tempfile::tempdir().unwrap();
    assert_eq!(
        crate::permission::branch_switch::submodule_recursion_with_home(repo.path(), Some(clean_home.path().as_os_str())),
        Some(false)
    );
    // End to end: a lister whose config child sees the fixture HOME.
    struct WithHome(std::path::PathBuf);
    impl crate::permission::branch_switch::TreeLister for WithHome {
        fn repo_root(&self, cwd: &Path) -> Option<std::path::PathBuf> {
            crate::permission::branch_switch::GitTreeLister.repo_root(cwd)
        }
        fn names(&self, cwd: &Path, rev: &str) -> crate::permission::branch_switch::TreeListing {
            crate::permission::branch_switch::GitTreeLister.names(cwd, rev)
        }
        fn resolve_probe(
            &self,
            probe: &crate::permission::branch_switch::TreeProbe,
        ) -> Option<crate::permission::branch_switch::ProbeResolution> {
            crate::permission::branch_switch::GitTreeLister.resolve_probe(probe)
        }
        fn submodule_recursion(&self, cwd: &Path) -> Option<bool> {
            crate::permission::branch_switch::submodule_recursion_with_home(cwd, Some(self.0.as_os_str()))
        }
    }
    use crate::permission::branch_switch::TreeLister as _;
    let plan = plan_for(&["git checkout feature"], repo.path());
    assert!(crate::permission::branch_switch::plan_keeps_floor(&plan, &WithHome(home.path().to_path_buf())));
    assert!(!crate::permission::branch_switch::plan_keeps_floor(&plan, &WithHome(clean_home.path().to_path_buf())));
}

#[test]
fn p175_item4b_no_gitmodules_means_no_config_child() {
    let repo = real_repo(&[]);
    git(repo.path(), &["branch", "feature"]);
    let (keeps, _, _) = run_counted(&["git checkout feature"], repo.path());
    assert!(!keeps);
    assert_eq!(config_children(repo.path()), 0, "no .gitmodules: nothing read");
    let with = repo_with_gitmodules();
    let (_, _, _) = run_counted(&["git checkout feature"], with.path());
    assert_eq!(config_children(with.path()), 1, "a .gitmodules at the top: one config child");
}

// ---- Earlier-segment verb rule ----------------------------------------------------------------------------------

/// Round 2: `commit` unsettles the plan again (hooks can move any ref), so a later checkout keeps the floor, as in
/// integration before P175. Before round 2 the first three clear; after, every line prompts.
#[test]
fn p175_earlier_commit_segment_keeps_the_plan_determinable() {
    let repo = real_repo(&[]);
    let dir = repo.path();
    for cmd in [
        "git add -A && git commit -m x && git checkout main",
        "git commit -m x && git checkout main",
        "git status && git commit -m x && git checkout main",
        "git fetch && git checkout main",
        "git pull && git checkout main",
        "git add -f . && git commit -m x && git checkout main",
    ] {
        assert!(hub_prompts(cmd, dir), "{cmd}");
    }
    // A commit alone stays cleared.
    assert!(!hub_prompts("git commit -m x", dir));
}

/// Round 2 fix 1: every spelling of `git add --force` stages an ignored, not-yet-indexed `.mcp.json`.
#[test]
fn p175_r2_add_force_spellings_keep_the_floor() {
    let repo = real_repo(&[]);
    let dir = repo.path();
    git(dir, &["branch", "other"]);
    std::fs::write(dir.join(".gitignore"), ".mcp.json\n").unwrap();
    std::fs::write(dir.join(".mcp.json"), "{}").unwrap();
    for spelling in ["-f", "--force", "--force=true", "--force=yes", "--forc", "--for", "--fo", "--f", "-Af"] {
        let cmd = format!("git add {spelling} .mcp.json && git commit -m x && git checkout other");
        assert!(hub_prompts(&cmd, dir), "{cmd}");
    }
}

#[test]
fn p175_r2_add_force_detector_unit() {
    let v = |s: &[&str]| s.iter().map(|a| a.to_string()).collect::<Vec<_>>();
    for yes in ["--f", "--fo", "--for", "--forc", "--force", "--force=true", "--for=yes", "-f", "-Af"] {
        assert!(super::super::exec_risk::git_add_is_force_for_tests(&v(&[yes, "x"])), "{yes}");
    }
    for no in ["--no-ignore-removal", "--ignore-removal", "--all", "-A", "-n", "--dry-run", "--intent-to-add"] {
        assert!(!super::super::exec_risk::git_add_is_force_for_tests(&v(&[no, "x"])), "{no}");
    }
}

/// Round 2 fix 3: `git stash -u` / `-a` removes untracked (and ignored) files.
#[test]
fn p175_r2_stash_untracked_flags_keep_the_floor() {
    let repo = real_repo(&[]);
    let dir = repo.path();
    git(dir, &["branch", "other"]);
    std::fs::write(dir.join(".mcp.json"), "{}").unwrap();
    for cmd in [
        "git stash push -u",
        "git stash -u",
        "git stash save -u",
        "git stash push --include-untracked",
        "git stash push --include",
        "git stash push -a",
        "git stash --all",
        "git stash push -ku",
        "git stash push -u && git checkout other",
    ] {
        assert!(hub_prompts(cmd, dir), "{cmd}");
    }
    // Plain stash does not prompt, and neither does -u in a clean repository.
    assert!(!hub_prompts("git stash", dir));
    assert!(!hub_prompts("git stash push", dir));
    assert!(!hub_prompts("git stash list", dir));
    let clean = real_repo(&[]);
    assert!(!hub_prompts("git stash push -u", clean.path()));
}

/// An ignored protected file is removed by `-a` but not by `-u`.
#[test]
fn p175_r2_stash_all_judges_ignored_files() {
    let repo = real_repo(&[]);
    let dir = repo.path();
    std::fs::write(dir.join(".gitignore"), ".mcp.json\n").unwrap();
    std::fs::write(dir.join(".mcp.json"), "{}").unwrap();
    assert!(hub_prompts("git stash push -a", dir));
    assert!(hub_prompts("git stash push --all", dir));
    assert!(!hub_prompts("git stash push -u", dir));
}

/// Round 2 fix 4: bare read-only forms do not unsettle a later checkout; anything else on those verbs does.
#[test]
fn p175_r2_readonly_listing_forms_do_not_unsettle() {
    let repo = real_repo(&[]);
    let dir = repo.path();
    git(dir, &["branch", "feature"]);
    for pre in [
        "git branch", "git branch --list", "git branch -l", "git branch -a", "git branch -r", "git branch -v", "git branch -vv",
        "git branch -avv", "git branch --show-current", "git branch --contains HEAD", "git branch --merged", "git branch --no-merged main",
        "git branch --format='%(refname)'", "git branch --format '%(refname)'", "git branch --sort=-committerdate", "git branch --color",
        "git branch --list feat*", "git tag", "git tag -l", "git tag --list", "git tag -n", "git tag -n5", "git tag -l v*",
        "git reflog", "git reflog show",
        "git reflog main", "git reflog show main", "git reflog HEAD", "git reflog show HEAD", "git tag -ln", "git tag -nl",
        "git tag -ln5", "git tag -n3", "git tag -ln v*",
    ] {
        let cmd = format!("{pre} && git checkout feature");
        assert!(!hub_prompts(&cmd, dir), "{cmd}");
    }
}

/// Classifier level (no repository contents involved): a mutating branch/tag/reflog form followed by a checkout makes
/// the plan Undetermined, while the listing forms leave it determined.
#[test]
fn p175_r3_mutating_forms_make_the_plan_undetermined() {
    use crate::permission::branch_switch::BranchSwitchPlan;
    let dir = tempfile::tempdir().unwrap();
    for pre in [
        "git branch -d x", "git branch -m a b", "git branch -c a b", "git branch new", "git branch -f main x",
        "git branch --set-upstream-to=o/m", "git tag -d v1", "git tag v1", "git reflog expire --all",
        "git reflog delete main@{0}", "git tag -a v1", "git reflog drop",
    ] {
        let plan = plan_for(&[pre, "git checkout main"], dir.path());
        assert_eq!(plan, BranchSwitchPlan::Undetermined, "{pre}");
    }
    for pre in ["git branch", "git branch -l", "git tag -ln", "git tag -n3", "git reflog main", "git reflog show main"] {
        let plan = plan_for(&[pre, "git checkout main"], dir.path());
        assert_ne!(plan, BranchSwitchPlan::Undetermined, "{pre}");
    }
    // Reflog forms that are not a listing: flags and subcommand names in the revision slot.
    for pre in ["git reflog -p", "git reflog --all", "git reflog show -p", "git reflog exists main", "git reflog show expire"] {
        let plan = plan_for(&[pre, "git checkout main"], dir.path());
        assert_eq!(plan, BranchSwitchPlan::Undetermined, "{pre}");
    }
    for pre in ["git tag -d", "git tag -a", "git tag -f", "git tag -s", "git tag -m", "git tag -dn"] {
        let plan = plan_for(&[pre, "git checkout main"], dir.path());
        assert_eq!(plan, BranchSwitchPlan::Undetermined, "{pre}");
    }
}

#[test]
fn p175_r2_mutating_forms_stay_unsettled() {
    let repo = real_repo(&[]);
    let dir = repo.path();
    git(dir, &["branch", "feature"]);
    std::fs::write(dir.join(".mcp.json"), "{}").unwrap();
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "-m", "mcp"]);
    git(dir, &["branch", "tracked"]);
    for pre in [
        "git branch -f main x", "git branch new", "git branch -d feature", "git branch -m a b", "git branch --set-upstream-to=x", "git branch --bogus",
        "git branch -a foo", "git tag v1", "git tag -d v1", "git tag -a v1 -m x", "git tag --bogus", "git reflog expire --all", "git reflog delete HEAD@{0}",
        "git restore x", "git gc", "git notes add -m x", "git apply p.diff",
    ] {
        let cmd = format!("{pre} && git checkout feature");
        assert!(hub_prompts(&cmd, dir), "{cmd}");
    }
}

/// Round 2 fix 6: a work-tree path holding a newline breaks the discovery line structure: undetermined.
#[test]
fn p175_r2_newline_in_worktree_path_is_undetermined() {
    let parent = tempfile::tempdir().unwrap();
    let odd = parent.path().join("a\nb");
    std::fs::create_dir(&odd).unwrap();
    git(&odd, &["init", "-q", "-b", "main"]);
    git(&odd, &["-c", "user.name=t", "-c", "user.email=t@e.com", "commit", "-q", "--allow-empty", "-m", "i"]);
    git(&odd, &["branch", "feature"]);
    assert!(hub_prompts("git checkout feature", &odd));
}

// ---- Problem 3: shallow home ------------------------------------------------------------------------------------

/// Inner half, run in a child test process with `HOME=/u USER=u` (see the outer test).
#[test]
fn p175_item4g_shallow_home_inner() {
    if std::env::var("P175_SHALLOW_HOME").as_deref() != Ok("1") {
        return;
    }
    let (_root, deep) = super::p166_r13_tests::deep_project();
    // A real directory literally named `~u` under the project: without the rewrite the symlink walk finds it, so the
    // words resolve to `<cwd>/etc/x` (outside nothing, not blocked) instead of failing closed on a missing component.
    std::fs::create_dir(deep.join("~u")).unwrap();
    // One component of home: a single `..` from `~u` reaches `/`, so `../etc/x` is `/etc/x`. Unrewritten, `~u` would
    // be an ordinary directory under the project and the same words would stay inside it.
    let blocked = [
        "cd ~u && touch ../etc/passwd".to_owned(),
        "touch ~u/../etc/x".to_owned(),
        "pushd ~u && touch ../etc/passwd".to_owned(),
    ];
    super::p166_r13_tests::check_floor(&deep, &blocked, true);
    super::p166_r13_tests::check_floor(&deep, &["touch ~u/notes.txt".to_owned()], false);
    eprintln!(
        "P175_SHALLOW_HOME_INNER_DONE home={} user={}",
        std::env::var("HOME").unwrap_or_default(),
        std::env::var("USER").unwrap_or_default()
    );
}

#[test]
fn p175_item4g_shallow_home_tilde_name_is_rewritten_to_home() {
    let exe = std::env::current_exe().unwrap();
    let out = std::process::Command::new(exe)
        .args(["--exact", "permission::manager::p175_tests::p175_item4g_shallow_home_inner", "--nocapture"])
        .env("P175_SHALLOW_HOME", "1")
        .env("HOME", "/u")
        .env("USER", "u")
        .env_remove("LOGNAME")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success() && text.contains("1 passed"), "{text}");
    // The inner body ran to its end with the env the outer set (a silent early return prints neither marker).
    assert!(text.contains("P175_SHALLOW_HOME_INNER_DONE home=/u user=u"), "inner body did not run to the end: {text}");
}

// ---- Part B (decision 11): an earlier non-git write into the git directory unsettles the switch plan ----------------

fn plan_with_facts(cmd: &str, cwd: &Path) -> crate::permission::branch_switch::BranchSwitchPlan {
    let mut evaluation = super::evaluate_bash(cmd, &super::PermissionState::default(), true);
    let raw = evaluation.ambient_segments.take().expect("git command gives segments");
    crate::permission::exec_risk::branch_switch_plan_with(&raw, cwd, Some(&evaluation.write_facts))
}

/// Whether `cmd` prompts under a policy that allows the git verbs AND the writer commands used by the shapes.
fn prompts_allowing_writers(cmd: &str, cwd: &Path) -> bool {
    use crate::permission::rules::parse_permission_rule;
    use crate::permission::types::{PermissionConfig, RuleAction};
    let rules = ["git", "cp", "mv", "echo", "tee", "ln", "install", "npm", "cat", "cd", "rm", "ls", "nohup", "time", "caffeinate", "mkdir", "touch"]
        .iter()
        .map(|c| parse_permission_rule(&format!("Bash({c}:*)"), RuleAction::Allow).unwrap())
        .collect();
    let policy = crate::permission::policy::CompiledPolicy::new(PermissionConfig::new(rules));
    (0..3).all(|_| super::hub_needs_default_prompt(&super::AccessKind::Bash(cmd.to_owned()), Some(&policy), true, cwd))
}

fn part_b_repo() -> tempfile::TempDir {
    let repo = real_repo(&[]);
    std::fs::create_dir_all(repo.path().join("sub")).unwrap();
    std::fs::create_dir_all(repo.path().join("other-repo/.git/refs/heads")).unwrap();
    repo
}

#[test]
fn p175b_earlier_write_into_git_dir_unsettles_the_switch() {
    let repo = part_b_repo();
    let cwd = repo.path();
    let rows = [
        ("cp x .git/refs/heads/main && git checkout main", cwd),
        ("mv x .git/refs/heads/main && git checkout main", cwd),
        ("echo sha > .git/refs/heads/main && git checkout main", cwd),
        ("echo sha | tee .git/packed-refs && git checkout main", cwd),
        ("ln -sf x .git/refs/heads/main && git checkout main", cwd),
        ("install x .git/refs/heads/main && git checkout main", cwd),
        ("echo ref: > .git/HEAD && git checkout main", cwd),
        ("cd sub && cp x ../.git/refs/heads/main && git checkout main", cwd),
        ("cp x /ABS/.git/refs/heads/main && git checkout main", cwd),
    ];
    let mut wrong = Vec::new();
    for (cmd, dir) in rows {
        let cmd = cmd.replace("/ABS", &cwd.to_string_lossy());
        let plan = plan_with_facts(&cmd, dir);
        let prompts = prompts_allowing_writers(&cmd, dir);
        if plan != crate::permission::branch_switch::BranchSwitchPlan::Undetermined || !prompts {
            wrong.push(format!("{cmd}: plan={plan:?} prompts={prompts}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn p175b_other_writes_do_not_unsettle_the_switch() {
    let repo = part_b_repo();
    let cwd = repo.path();
    let mut wrong = Vec::new();
    for cmd in [
        "npm test && git checkout main",
        "cp a b && git checkout main",
        "cat .git/HEAD && git checkout main",
        "cp x other-repo/.git/refs/heads/main && git checkout main",
        "git checkout main && cp x .git/refs/heads/main",
        "ls .git && git switch main",
        "cp x docs/note.txt && git checkout main",
    ] {
        let plan = plan_with_facts(cmd, cwd);
        let prompts = prompts_allowing_writers(cmd, cwd);
        if matches!(plan, crate::permission::branch_switch::BranchSwitchPlan::Undetermined) || prompts {
            wrong.push(format!("{cmd}: plan={plan:?} prompts={prompts}"));
        }
    }
    // A plain output redirect already prompts on its own (the redirect-write floor, unrelated to the branch check), so
    // this shape is judged on the plan only.
    let plan = plan_with_facts("echo hi > notes.txt && git checkout main", cwd);
    assert!(matches!(plan, crate::permission::branch_switch::BranchSwitchPlan::Probe(_)), "{plan:?}");
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[cfg(unix)]
fn part_b_links(repo: &Path) {
    use std::os::unix::fs::symlink;
    std::fs::create_dir_all(repo.join("docs-site")).unwrap();
    symlink(".git", repo.join("pg")).unwrap();
    symlink(".git/refs/heads/main", repo.join("pref")).unwrap();
    symlink("other-repo", repo.join("link")).unwrap();
    symlink("docs-site", repo.join("docs")).unwrap();
}

fn assert_rows(repo: &Path, rows: &[&str], undetermined: bool) {
    let mut wrong = Vec::new();
    for cmd in rows {
        let plan = plan_with_facts(cmd, repo);
        let prompts = prompts_allowing_writers(cmd, repo);
        let is_und = matches!(plan, crate::permission::branch_switch::BranchSwitchPlan::Undetermined);
        if is_und != undetermined || prompts != undetermined {
            wrong.push(format!("{cmd}: plan={plan:?} prompts={prompts}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[cfg(unix)]
#[test]
fn p175b_r2_symlink_spelling_of_the_git_dir_unsettles_the_switch() {
    let repo = part_b_repo();
    part_b_links(repo.path());
    assert_rows(
        repo.path(),
        &[
            "cp x pg/refs/heads/main && git checkout main",
            "cp x pref && git checkout main",
            "rm pg/refs/heads/main && git checkout main",
            "cp x other-repo/.git/refs/heads/main && git -C link checkout main",
            "cp x link/.git/refs/heads/main && git -C link checkout main",
        ],
        true,
    );
}

#[cfg(unix)]
#[test]
fn p175b_r2_same_line_symlink_to_the_git_dir_unsettles_the_switch() {
    let repo = part_b_repo();
    assert_rows(
        repo.path(),
        &[
            "ln -s .git g && cp x g/refs/heads/main && git checkout main",
            "ln -s .git/refs/heads/main ref && cp x ref && git checkout main",
            "ln -s .git g && rm g/refs/heads/main && git checkout main",
        ],
        true,
    );
}

#[cfg(unix)]
#[test]
fn p175b_r2_symlink_negatives_stay_silent() {
    let repo = part_b_repo();
    part_b_links(repo.path());
    assert_rows(
        repo.path(),
        &[
            "cp x docs/note.txt && git checkout main",
            "ln -s docs-site d2 && cp x d2/note.txt && git checkout main",
            "cp x link/note.txt && git checkout main",
        ],
        false,
    );
}

#[test]
fn p175b_r3_copy_onto_an_existing_file_does_not_unsettle_the_switch() {
    let repo = part_b_repo();
    for name in ["README.md", "notes.txt", "existing", "a"] {
        std::fs::write(repo.path().join(name), "x").unwrap();
    }
    assert_rows(
        repo.path(),
        &[
            "cp notes.txt README.md && git checkout main",
            "cp a existing && git checkout main",
            "mv a existing && git checkout main",
            "install a existing && git checkout main",
            "cp a b && git checkout main",
            "npm test && git checkout main",
            "mkdir -p build/out && git switch main",
            "touch newfile && git checkout main",
        ],
        false,
    );
    // Writing the ref itself still unsettles the plan.
    assert_rows(repo.path(), &["cp x .git/refs/heads/main && git checkout main"], true);
}

#[cfg(unix)]
#[test]
fn p175b_r3_ln_forms_that_point_into_the_git_dir_unsettle_the_switch() {
    let repo = part_b_repo();
    let cwd = repo.path();
    std::fs::create_dir_all(cwd.join("linkdir")).unwrap();
    let abs_git = format!("{}/.git", cwd.display());
    let rows = [
        "ln -s .git/refs/heads/main decoy . && cp x main && git checkout main".to_owned(),
        format!("ln -s -t /tmp {abs_git} && cp x /tmp/.git/refs/heads/main && git checkout main"),
        format!("ln -s --target-directory=/tmp {abs_git} && git checkout main"),
        format!("ln -s --target-directory /tmp {abs_git} && git checkout main"),
        "ln -sfn .git g && cp x g/HEAD && git checkout main".to_owned(),
        "ln -snf .git g && cp x g/HEAD && git checkout main".to_owned(),
        "ln -s -- .git g && cp x g/HEAD && git checkout main".to_owned(),
        "ln -s -S .bak .git g && git checkout main".to_owned(),
        "ln -s -T .git g && git checkout main".to_owned(),
        "ln -s .git mylink && git checkout main".to_owned(),
        "ln -s ../.git linkdir/g && git checkout main".to_owned(),
        "ln -s ../.git linkdir && git checkout main".to_owned(),
        "ln -s --weird .git g && git checkout main".to_owned(),
    ];
    let rows: Vec<&str> = rows.iter().map(String::as_str).collect();
    assert_rows(cwd, &rows, true);
}

#[cfg(unix)]
#[test]
fn p175b_r3_harmless_ln_forms_stay_silent() {
    let repo = part_b_repo();
    let cwd = repo.path();
    assert_rows(
        cwd,
        &[
            "ln -s .git /tmp/out && git checkout main",
            "ln -s ../shared node_modules/shared && git checkout main",
            "ln -sf target/release/app app && git switch main",
            "ln -s --weird foo g && git checkout main",
            "ln -s -t build foo bar && git checkout main",
            "ln a b && git checkout main",
        ],
        false,
    );
}

#[cfg(unix)]
fn r4_repo() -> tempfile::TempDir {
    use std::os::unix::fs::symlink;
    let repo = part_b_repo();
    let cwd = repo.path();
    for dir in [".git/objects", "sub", "docs2", "build"] {
        std::fs::create_dir_all(cwd.join(dir)).unwrap();
    }
    std::fs::write(cwd.join("README.md"), "x").unwrap();
    symlink(".git", cwd.join("pg")).unwrap();
    symlink(".git/objects", cwd.join("deep")).unwrap();
    repo
}

#[cfg(unix)]
#[test]
fn p175b_r4_dotdot_after_a_symlink_is_resolved_in_kernel_order() {
    let repo = r4_repo();
    assert_rows(
        repo.path(),
        &[
            "cp payload deep/../config && git checkout main",
            "cp payload deep/../HEAD && git checkout main",
            "cp payload docs2/../deep/../config && git checkout main",
        ],
        true,
    );
    assert_rows(
        repo.path(),
        &["cp a docs2/../README.md && git checkout main", "cp a docs2/../newfile && git checkout main"],
        false,
    );
}

#[cfg(unix)]
#[test]
fn p175b_r4_ln_long_option_prefixes_are_parsed() {
    let repo = r4_repo();
    assert_rows(
        repo.path(),
        &[
            "ln -s --target-dir=.git payload && git checkout main",
            "ln -s --target-d pg payload && git checkout main",
            "ln --sym .git g && cp x g/HEAD && git checkout main",
            "ln --symb --rel .git g && git checkout main",
            "ln --sym --no-target-dir .git g && git checkout main",
            "ln --sym --suf=x .git g && git checkout main",
            "ln --sym --suf x .git g && git checkout main",
            "ln --symbolic --target-directory=pg payload && git checkout main",
        ],
        true,
    );
    assert_rows(
        repo.path(),
        &[
            "ln --symbolic ../x y && git checkout main",
            "ln --sym --target-dir=build foo && git checkout main",
            "ln --sym --suf=x ../shared sub/shared && git checkout main",
        ],
        false,
    );
}

#[cfg(unix)]
#[test]
fn p175b_r4_ln_bsd_short_flags_are_parsed() {
    let repo = r4_repo();
    assert_rows(
        repo.path(),
        &["ln -sfh ../pg sub/g && git checkout main", "ln -sfhw ../pg sub/g && git checkout main", "ln -sFivbLP ../pg sub/g && git checkout main"],
        true,
    );
    assert_rows(repo.path(), &["ln -sfh ../x sub/g && git checkout main"], false);
}

#[cfg(unix)]
#[test]
fn p175b_r4_unparsed_ln_resolves_every_word_both_ways() {
    let repo = r4_repo();
    assert_rows(
        repo.path(),
        &[
            "ln -s --weird pg payload && git checkout main",
            "ln -s --weird=pg payload && git checkout main",
            "ln -s --weird ../pg sub/g && git checkout main",
            "ln -s --s .git g && git checkout main",
            "ln -s --weird ../.git sub && git checkout main",
        ],
        true,
    );
    assert_rows(
        repo.path(),
        &[
            "ln -s --weird ../x node_modules/x && git checkout main",
            "ln -s --weird=build foo && git checkout main",
            "ln -s --weird foo sub/ && git checkout main",
        ],
        false,
    );
}

#[cfg(unix)]
#[test]
fn p175b_r4_ln_cwd_tilde_source_is_the_cwd() {
    let repo = r4_repo();
    assert_rows(
        repo.path(),
        &["ln -s ~+/.git /tmp/out && git checkout main", "ln -s ~+/pg /tmp/out && git checkout main"],
        true,
    );
    assert_rows(repo.path(), &["ln -s ~+/build /tmp/out && git checkout main"], false);
}

/// `ln -s .git sub/` makes `sub/.git -> .git`, which resolves to `sub/.git` (not this repository's `.git`): silent.
/// `ln -s ../.git sub/` makes `sub/.git -> ../.git`, which IS this repository's `.git`: unsettled.
#[cfg(unix)]
#[test]
fn p175b_r4_ln_trailing_slash_destination_is_a_directory() {
    let repo = r4_repo();
    assert_rows(repo.path(), &["ln -s .git sub/ && git checkout main"], false);
    assert_rows(repo.path(), &["ln -s ../.git sub/ && git checkout main"], true);
}

#[cfg(unix)]
#[test]
fn p175b_r4_everyday_lines_stay_silent() {
    let repo = r4_repo();
    std::fs::write(repo.path().join("existing-file"), "x").unwrap();
    assert_rows(
        repo.path(),
        &[
            "npm test && git checkout main",
            "cp a existing-file && git checkout main",
            "cp a missing && git checkout main",
            "mv a b && git checkout main",
            "mkdir -p build/out && git switch main",
            "touch newfile && git checkout main",
            "ln -s ../shared node_modules/shared && git checkout main",
            "ln -sf target/release/app app && git checkout main",
            "ln -sfn releases/42 current && git checkout main",
            "ln --symbolic ../x y && git checkout main",
            "cp a docs2/../README.md && git checkout main",
        ],
        false,
    );
}

/// On a case-sensitive volume `.GIT` is a different directory from `.git`.
#[cfg(not(any(target_os = "macos", windows)))]
#[test]
fn p175b_r2_distinct_upper_case_git_dir_is_not_this_git_dir() {
    let repo = part_b_repo();
    std::fs::create_dir_all(repo.path().join(".GIT/refs/heads")).unwrap();
    assert_rows(repo.path(), &["cp x .GIT/refs/heads/main && git checkout main"], false);
}

/// Compile-only on Linux: on APFS / Windows `.GIT` is this repository's `.git`.
#[cfg(any(target_os = "macos", windows))]
#[test]
fn p175b_r2_case_insensitive_volume_upper_case_git_is_this_git_dir() {
    let repo = part_b_repo();
    assert_rows(
        repo.path(),
        &["cp x .GIT/refs/heads/main && git checkout main", "cp -r evil .GIT && git checkout main"],
        true,
    );
}

#[test]
fn p175b_r2_launcher_before_git_keeps_the_ordinal_aligned() {
    let repo = part_b_repo();
    assert_rows(
        repo.path(),
        &[
            "nohup git status && cp x .git/refs/heads/main && git checkout main",
            "/usr/bin/time -p git status && cp x .git/refs/heads/main && git checkout main",
            "caffeinate git status && cp x .git/refs/heads/main && git checkout main",
        ],
        true,
    );
}

#[test]
fn p175b_r2_git_count_mismatch_between_parsers_is_undetermined() {
    use crate::permission::branch_switch::BranchSwitchPlan;
    let cwd = part_b_repo();
    let mut two = super::evaluate_bash("git status && git checkout main", &super::PermissionState::default(), true);
    let mut one = super::evaluate_bash("git checkout main", &super::PermissionState::default(), true);
    let raw_one = one.ambient_segments.take().unwrap();
    let raw_two = two.ambient_segments.take().unwrap();
    let plan = |raw: &Vec<Vec<String>>, facts: &super::BashEvaluation| {
        crate::permission::exec_risk::branch_switch_plan_with(raw, cwd.path(), Some(&facts.write_facts))
    };
    assert!(matches!(plan(&raw_one, &one), BranchSwitchPlan::Probe(_)), "agreeing counts must plan normally");
    assert!(matches!(plan(&raw_one, &two), BranchSwitchPlan::Undetermined), "planner saw fewer gits than facts");
    assert!(matches!(plan(&raw_two, &one), BranchSwitchPlan::Undetermined), "planner saw more gits than facts");
}

#[cfg(unix)]
#[test]
fn p175b_r5_abbreviated_target_directory_is_a_write_target() {
    let repo = part_b_repo();
    let cwd = repo.path();
    std::os::unix::fs::symlink(".git/objects", cwd.join("deep")).unwrap();
    assert_rows(
        cwd,
        &[
            "cp --target-dir=.git payload && git checkout main",
            "cp --target-dir .git payload && git checkout main",
            "cp --t=.git payload && git checkout main",
            "cp --target-dir=deep payload && git checkout main",
            "mv --t=.git x && git checkout main",
            "mv --target-d .git x && git checkout main",
            "install --target-directory=.git x && git checkout main",
            "install --target-dir=.git x && git checkout main",
            "ln --target-dir=.git x && git checkout main",
        ],
        true,
    );
    assert_rows(
        cwd,
        &[
            "cp --target-directory=build a && git checkout main",
            "cp --target-dir=build a && git checkout main",
            "cp -t build a && git checkout main",
            "cp a b && git checkout main",
            "npm test && git checkout main",
        ],
        false,
    );
}

#[cfg(unix)]
#[test]
fn p175b_r5_ln_target_directory_inside_git_is_a_write_into_it() {
    let repo = part_b_repo();
    assert_rows(
        repo.path(),
        &[
            "ln -s --target-dir=.git/refs/heads /tmp/main && git checkout main",
            "ln -s -t .git/refs/heads /tmp/main && git checkout main",
            "ln -s --target-directory=.git/refs/heads /tmp/main && git checkout main",
            "ln -s --target-directory .git/refs/heads /tmp/main && git checkout main",
        ],
        true,
    );
    assert_rows(repo.path(), &["ln -s -t build /tmp/main && git checkout main"], false);
}

/// The P166 protected-file floor with an abbreviated `--target-directory`.
#[test]
fn p175b_r5_abbreviated_target_directory_keeps_the_protected_floor() {
    let (_root, deep) = super::p166_r13_tests::deep_project();
    std::fs::create_dir_all(deep.join("sub")).unwrap();
    let rows: Vec<String> = [
        "cp --target-directory=. x/.mcp.json",
        "cp --target-dir=. x/.mcp.json",
        "mv --target-dir=sub evil/.mcp.json",
        "mv --t sub evil/.mcp.json",
        "install --target-dir=.git/hooks hook",
        "cp --target-dir=.git/hooks hook",
    ]
    .iter()
    .map(|row| (*row).to_owned())
    .collect();
    super::p166_r13_tests::check_floor(&deep, &rows, true);
}

/// Part B round 6 (Grok r5): `cp --parents` keeps the source path under the destination directory.
#[test]
fn p175b_r6_cp_parents_writes_the_full_source_path() {
    let repo = part_b_repo();
    // The source need not exist for the plan. A `sub/.git` directory without a HEAD would be taken as the switch's
    // own git dir by Fuigo's discovery (git itself skips it), which is a different question from this one.
    assert_rows(
        repo.path(),
        &[
            "cd sub && cp --parents .git/config .. && git checkout main",
            "cp --parents .git/config . && git checkout main",
            "cp --par .git/config . && git checkout main",
            "cp --pare .git/config . && git checkout main",
            "cp --p .git/config . && git checkout main",
            "cp -r --parents .git/config . && git checkout main",
        ],
        true,
    );
    assert_rows(
        repo.path(),
        &[
            "cp -r src dist && git checkout main",
            "cp --parents docs/a.md build && git checkout main",
            "cp --preserve=mode a build && git checkout main",
        ],
        false,
    );
}

/// `--parents` and the P166 protected-file floor.
#[test]
fn p175b_r6_cp_parents_keeps_the_protected_floor() {
    let (_root, deep) = super::p166_r13_tests::deep_project();
    std::fs::create_dir_all(deep.join("evil")).unwrap();
    let rows: Vec<String> = ["cp --parents evil/.mcp.json .", "cd evil && cp --parents .mcp.json .."]
        .iter()
        .map(|row| (*row).to_owned())
        .collect();
    super::p166_r13_tests::check_floor(&deep, &rows, true);
}

/// Part B round 6: `install -d` makes every operand.
#[test]
fn p175b_r6_install_directory_writes_every_operand() {
    let repo = part_b_repo();
    assert_rows(
        repo.path(),
        &[
            "install -d .git/hooks /tmp/out && git checkout main",
            "install --directory .git/hooks /tmp/out && git checkout main",
            "install --dir .git/hooks /tmp/out && git checkout main",
            "install -d -m 755 .git/hooks /tmp/out && git checkout main",
            "install -dm755 .git/hooks /tmp/out && git checkout main",
        ],
        true,
    );
    assert_rows(
        repo.path(),
        &[
            "install -d build/out && git checkout main",
            "install -d -m 755 a b && git checkout main",
            "install -m 755 a /usr/local/bin/a && git switch main",
            "mkdir -p a/b && git checkout main",
        ],
        false,
    );
}

// ---- Part B, `.git` is a file (P175d): a linked worktree or a submodule checkout ---------------------------------------

/// `<tmp>/main/.git` (a real layout built by hand) with a linked worktree `<tmp>/wt` and a submodule `<tmp>/main/sub`.
#[cfg(unix)]
fn gitfile_fixture() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(tmp.path()).unwrap();
    let main = root.join("main");
    for dir in [".git/refs/heads", ".git/worktrees/wt1", ".git/modules/sub/refs/heads", "sub", "other/.git/refs/heads"] {
        std::fs::create_dir_all(main.join(dir)).unwrap();
    }
    std::fs::create_dir_all(root.join("wt/src")).unwrap();
    // Git's own validity test for a git directory is a `HEAD` file; the fixture has one in every directory it names.
    for head in [".git/HEAD", ".git/worktrees/wt1/HEAD", ".git/modules/sub/HEAD"] {
        std::fs::write(main.join(head), "ref: refs/heads/main\n").unwrap();
    }
    std::fs::create_dir_all(root.join("detached/gits/sub")).unwrap();
    std::fs::write(root.join("detached/gits/sub/HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::write(main.join(".git/worktrees/wt1/commondir"), "../..\n").unwrap();
    std::fs::write(root.join("wt/.git"), format!("gitdir: {}\n", main.join(".git/worktrees/wt1").display())).unwrap();
    std::fs::write(main.join("sub/.git"), "gitdir: ../.git/modules/sub\n").unwrap();
    // A checkout whose git directory is NOT under any ancestor (a relative `gitdir:` that leaves the tree).
    std::fs::create_dir_all(root.join("detached/gits/sub/refs/heads")).unwrap();
    std::fs::create_dir_all(root.join("detached/co")).unwrap();
    std::fs::write(root.join("detached/co/.git"), "gitdir: ../gits/sub\n").unwrap();
    tmp
}

#[cfg(unix)]
#[test]
fn p175d_linked_worktree_write_into_gitdir_or_common_dir_unsettles_the_switch() {
    let tmp = gitfile_fixture();
    let root = dunce::canonicalize(tmp.path()).unwrap();
    let main = root.display().to_string() + "/main";
    let rows = [
        format!("cp x {main}/.git/worktrees/wt1/HEAD && git checkout x"),
        format!("echo sha > {main}/.git/refs/heads/x && git checkout x"),
        format!("cp x {main}/.git/packed-refs && git switch x"),
        format!("cd src && cp x {main}/.git/refs/heads/x && git checkout x"),
    ];
    let rows: Vec<&str> = rows.iter().map(String::as_str).collect();
    assert_rows(&root.join("wt"), &rows, true);
}

#[cfg(unix)]
#[test]
fn p175d_submodule_relative_gitdir_write_unsettles_the_switch() {
    let tmp = gitfile_fixture();
    let root = dunce::canonicalize(tmp.path()).unwrap();
    let main = root.join("main");
    let abs = main.display().to_string();
    let rows = [
        format!("cp x {abs}/.git/modules/sub/HEAD && git checkout x"),
        format!("echo sha > {abs}/.git/modules/sub/refs/heads/x && git checkout x"),
        "cp x ../.git/modules/sub/HEAD && git checkout x".to_owned(),
    ];
    let rows: Vec<&str> = rows.iter().map(String::as_str).collect();
    assert_rows(&main.join("sub"), &rows, true);
    let abs = root.join("detached").display().to_string();
    let rows = [
        format!("cp x {abs}/gits/sub/HEAD && git checkout x"),
        format!("echo sha > {abs}/gits/sub/refs/heads/x && git checkout x"),
        "cp x ../gits/sub/HEAD && git checkout x".to_owned(),
    ];
    let rows: Vec<&str> = rows.iter().map(String::as_str).collect();
    assert_rows(&root.join("detached/co"), &rows, true);
}

#[cfg(unix)]
#[test]
fn p175d_gitfile_guards_keep_today_verdicts() {
    use std::os::unix::fs::symlink;
    let tmp = gitfile_fixture();
    let root = dunce::canonicalize(tmp.path()).unwrap();
    let main = root.display().to_string() + "/main";
    // No git-dir write, a write into some OTHER repository's `.git`, and writes elsewhere: settled, no prompt.
    let rows = [
        "npm test && git checkout x".to_owned(),
        "cp a b && git checkout x".to_owned(),
        format!("cp x {main}/other/.git/refs/heads/x && git checkout x"),
        format!("cp x {main}/notes.txt && git checkout x"),
        "git checkout x && cp x ../main/.git/refs/heads/x".to_owned(),
    ];
    let rows: Vec<&str> = rows.iter().map(String::as_str).collect();
    for cmd in rows {
        // Judged on the plan: the hand-built repository cannot be probed, so the final prompt is not its verdict.
        let plan = plan_with_facts(cmd, &root.join("wt"));
        assert!(matches!(plan, crate::permission::branch_switch::BranchSwitchPlan::Probe(_)), "{cmd}: {plan:?}");
    }
    // Hostile `.git` files never panic and add no gitdir (so nothing is weaker than before: the write below is not
    // recognised, exactly as today).
    let write = format!("cp x {main}/.git/refs/heads/x && git checkout x");
    for (name, content) in [
        ("malformed", "garbage".to_owned()),
        ("missing", "gitdir: /nonexistent/zzz\n".to_owned()),
        ("huge", format!("gitdir: {}", "a".repeat(2 << 20))),
        ("empty", String::new()),
        ("nul", "gitdir: \0\0\n".to_owned()),
    ] {
        let dir = root.join(format!("h-{name}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".git"), content).unwrap();
        let plan = plan_with_facts(&write, &dir);
        assert!(!matches!(plan, crate::permission::branch_switch::BranchSwitchPlan::Undetermined), "{name}: {plan:?}");
    }
    let dir = root.join("h-symlink");
    std::fs::create_dir_all(&dir).unwrap();
    symlink(root.join("wt/.git"), dir.join(".git")).unwrap();
    plan_with_facts(&write, &dir);
}

// ---- P175d round 2: hostile `.git` / `commondir` shapes -----------------------------------------------------------------

/// Runs the plan on a thread so a hang is a failed assertion, not a hung suite.
#[cfg(unix)]
fn plan_within(cmd: &str, cwd: &Path, secs: u64) -> Option<crate::permission::branch_switch::BranchSwitchPlan> {
    let (tx, rx) = std::sync::mpsc::channel();
    let (cmd, cwd) = (cmd.to_owned(), cwd.to_path_buf());
    std::thread::spawn(move || {
        let _ = tx.send(plan_with_facts(&cmd, &cwd));
    });
    rx.recv_timeout(std::time::Duration::from_secs(secs)).ok()
}

/// Every row plans as a probe (settled), judged on the plan: the hand-built repository cannot be probed.
#[cfg(unix)]
fn assert_plans_settled(cwd: &Path, rows: &[&str]) {
    for cmd in rows {
        let plan = plan_with_facts(cmd, cwd);
        assert!(matches!(plan, crate::permission::branch_switch::BranchSwitchPlan::Probe(_)), "{cmd}: {plan:?}");
    }
}

#[cfg(unix)]
fn mkfifo_at(path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
}

#[cfg(unix)]
#[test]
fn p175d_r2_fifo_commondir_does_not_hang_and_keeps_the_integration_verdict() {
    let tmp = gitfile_fixture();
    let root = dunce::canonicalize(tmp.path()).unwrap();
    let main = root.join("main");
    let common = main.join(".git/worktrees/wt1/commondir");
    std::fs::remove_file(&common).unwrap();
    mkfifo_at(&common);
    // Plain switch: integration settles it (a probe), and so must this.
    let plan = plan_within("git checkout x", &root.join("wt"), 2).expect("a FIFO commondir hung the check");
    assert!(matches!(plan, crate::permission::branch_switch::BranchSwitchPlan::Probe(_)), "{plan:?}");
    // The same through a symlink to a FIFO.
    std::fs::remove_file(&common).unwrap();
    mkfifo_at(&main.join("ff"));
    std::os::unix::fs::symlink(main.join("ff"), &common).unwrap();
    let plan = plan_within("git checkout x", &root.join("wt"), 2).expect("a symlinked FIFO commondir hung the check");
    assert!(matches!(plan, crate::permission::branch_switch::BranchSwitchPlan::Probe(_)), "{plan:?}");
}

#[cfg(unix)]
#[test]
fn p175d_r2_fifo_swapped_in_for_the_git_file_does_not_hang() {
    let tmp = gitfile_fixture();
    let root = dunce::canonicalize(tmp.path()).unwrap();
    let dot_git = root.join("wt/.git");
    std::fs::remove_file(&dot_git).unwrap();
    mkfifo_at(&dot_git);
    let plan = plan_within("git checkout x", &root.join("wt"), 2).expect("a FIFO .git hung the check");
    assert!(matches!(plan, crate::permission::branch_switch::BranchSwitchPlan::Probe(_)), "{plan:?}");
}

#[cfg(unix)]
#[test]
fn p175d_r2_non_utf8_bytes_in_the_git_file_do_not_hide_the_gitdir() {
    use std::os::unix::ffi::OsStrExt;
    let tmp = gitfile_fixture();
    let root = dunce::canonicalize(tmp.path()).unwrap();
    let main = root.join("main");
    let gitdir = main.join(".git/worktrees/wt1");
    let rows = [format!("cp x {}/HEAD && git checkout x", gitdir.display())];
    let rows: Vec<&str> = rows.iter().map(String::as_str).collect();
    // Valid first line, junk (0xFF) later in the file.
    let mut body = format!("gitdir: {}\n", gitdir.display()).into_bytes();
    body.extend_from_slice(b"\xff\xfe trailing junk\n");
    std::fs::write(root.join("wt/.git"), &body).unwrap();
    assert_rows(&root.join("wt"), &rows, true);
    // A path with a non-UTF-8 component on the first line.
    std::fs::create_dir_all(main.join(".git/worktrees").join(std::ffi::OsStr::from_bytes(b"\xff"))).unwrap();
    let mut body = b"gitdir: ".to_vec();
    body.extend_from_slice(main.join(".git/worktrees").as_os_str().as_bytes());
    body.extend_from_slice(b"/\xff/../wt1\r\n");
    std::fs::write(root.join("wt/.git"), &body).unwrap();
    assert_rows(&root.join("wt"), &rows, true);
}

#[cfg(unix)]
#[test]
fn p175d_r2_bogus_gitdir_targets_add_no_prompt_to_unrelated_writes() {
    let tmp = gitfile_fixture();
    let root = dunce::canonicalize(tmp.path()).unwrap();
    // Give the ancestors a HEAD so only the "not the worktree or an ancestor" rule can reject them.
    std::fs::write(root.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    for (name, target) in [("root", "/".to_owned()), ("self", String::new()), ("parent", "..".to_owned()), ("home", root.display().to_string())] {
        let dir = root.join("wt").join(format!("bog-{name}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        let target = if name == "self" { dir.display().to_string() } else { target };
        std::fs::write(dir.join(".git"), format!("gitdir: {target}\n")).unwrap();
        assert_plans_settled(&dir, &["cp x notes.txt && git checkout x", "echo a > ../unrelated && git checkout x"]);
    }
}

#[cfg(unix)]
#[test]
fn p175d_r2_gitdir_without_a_head_file_is_not_a_git_directory() {
    let tmp = gitfile_fixture();
    let root = dunce::canonicalize(tmp.path()).unwrap();
    let plain = root.join("plain");
    std::fs::create_dir_all(root.join("wt/nohead")).unwrap();
    std::fs::create_dir_all(&plain).unwrap();
    std::fs::write(root.join("wt/nohead/.git"), format!("gitdir: {}\n", plain.display())).unwrap();
    assert_plans_settled(&root.join("wt/nohead"), &[&format!("cp x {}/f && git checkout x", plain.display())]);
}

#[cfg(unix)]
#[test]
fn p175d_r2_symlinked_git_file_is_followed() {
    let tmp = gitfile_fixture();
    let root = dunce::canonicalize(tmp.path()).unwrap();
    let main = root.display().to_string() + "/main";
    std::fs::create_dir_all(root.join("wt2")).unwrap();
    std::os::unix::fs::symlink(root.join("wt/.git"), root.join("wt2/.git")).unwrap();
    let rows = [format!("cp x {main}/.git/worktrees/wt1/HEAD && git checkout x")];
    let rows: Vec<&str> = rows.iter().map(String::as_str).collect();
    assert_rows(&root.join("wt2"), &rows, true);
}

// ---- P175f: a symlinked `commondir` and a symlinked `HEAD` are followed as git follows them -----------------------------

#[cfg(unix)]
#[test]
fn p175f_symlinked_commondir_is_followed() {
    let tmp = gitfile_fixture();
    let root = dunce::canonicalize(tmp.path()).unwrap();
    let main = root.display().to_string() + "/main";
    let common = root.join("main/.git/worktrees/wt1/commondir");
    std::fs::remove_file(&common).unwrap();
    std::fs::write(root.join("main/cd"), "../..\n").unwrap();
    std::os::unix::fs::symlink(root.join("main/cd"), &common).unwrap();
    let rows = [format!("cp x {main}/.git/refs/heads/x && git checkout x")];
    let rows: Vec<&str> = rows.iter().map(String::as_str).collect();
    assert_rows(&root.join("wt"), &rows, true);
}

#[cfg(unix)]
#[test]
fn p175f_gitdir_with_a_symlinked_head_is_a_git_directory() {
    let tmp = gitfile_fixture();
    let root = dunce::canonicalize(tmp.path()).unwrap();
    let main = root.display().to_string() + "/main";
    let head = root.join("main/.git/worktrees/wt1/HEAD");
    std::fs::remove_file(&head).unwrap();
    std::os::unix::fs::symlink(root.join("main/.git/HEAD"), &head).unwrap();
    let rows = [
        format!("cp x {main}/.git/worktrees/wt1/index && git checkout x"),
        format!("cp x {main}/.git/refs/heads/x && git checkout x"),
    ];
    let rows: Vec<&str> = rows.iter().map(String::as_str).collect();
    assert_rows(&root.join("wt"), &rows, true);
}

#[cfg(unix)]
#[test]
fn p175f_gitdir_whose_head_is_a_directory_or_fifo_is_still_not_a_git_directory() {
    let tmp = gitfile_fixture();
    let root = dunce::canonicalize(tmp.path()).unwrap();
    let plain = root.join("plain");
    std::fs::create_dir_all(root.join("wt/hd")).unwrap();
    std::fs::create_dir_all(root.join("wt/hf")).unwrap();
    std::fs::create_dir_all(plain.join("HEAD")).unwrap();
    std::fs::write(root.join("wt/hd/.git"), format!("gitdir: {}\n", plain.display())).unwrap();
    assert_plans_settled(&root.join("wt/hd"), &[&format!("cp x {}/f && git checkout x", plain.display())]);
    let fifo_dir = root.join("plain2");
    std::fs::create_dir_all(&fifo_dir).unwrap();
    mkfifo_at(&fifo_dir.join("HEAD"));
    std::fs::write(root.join("wt/hf/.git"), format!("gitdir: {}\n", fifo_dir.display())).unwrap();
    assert_plans_settled(&root.join("wt/hf"), &[&format!("cp x {}/f && git checkout x", fifo_dir.display())]);
}
