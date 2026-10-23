//! ROWS-A2 (1.0.32) worktree rows: 50.15 a repository with a separate git directory, 51.11 a worktree folder that was
//! deleted by hand, 59.5 a refusal that `--force` cannot lift never offers `--force`.

use super::*;
use std::path::{Path, PathBuf};

fn git(dir: &Path, args: &[&str]) {
    #[allow(clippy::disallowed_methods)] // test fixture; no sandbox or env policy applies
    let out = std::process::Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run git");
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

fn canon(p: &Path) -> PathBuf {
    dunce::canonicalize(p).unwrap()
}

/// `git init --separate-git-dir`: the working tree holds a `.git` FILE, and the git directory lives elsewhere with a name
/// that is not `.git`.
#[test]
fn a_repository_with_a_separate_git_dir_has_its_working_tree_as_main_root() {
    fuigo_test_utils::require_git!();
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    let gitdir = root.path().join("elsewhere").join("repo-data");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(gitdir.parent().unwrap()).unwrap();
    git(&work, &["init", "-q", "-b", "main", "--separate-git-dir", gitdir.to_str().unwrap(), work.to_str().unwrap()]);
    std::fs::create_dir_all(work.join("sub")).unwrap();
    std::fs::write(work.join("sub").join("a.txt"), "a").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "init"]);

    for start in [work.clone(), work.join("sub")] {
        let found = find_main_repo_root_from_path(&start).unwrap();
        assert_eq!(canon(&found), canon(&work), "from {}", start.display());
        // `fuigo -w` starts from the git root: it must be the checkout too.
        let root = crate::session::git::find_git_root_from_path(&start).unwrap();
        assert_eq!(canon(&root), canon(&work), "git root from {}", start.display());
    }
}

#[test]
fn an_ordinary_repository_and_its_linked_worktree_still_resolve_to_the_main_root() {
    fuigo_test_utils::require_git!();
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("a.txt"), "a").unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "init"]);
    let wt = root.path().join("wt");
    git(&repo, &["worktree", "add", "-q", "-b", "feature", wt.to_str().unwrap()]);
    assert_eq!(canon(&find_main_repo_root_from_path(&repo).unwrap()), canon(&repo));
    assert_eq!(canon(&find_main_repo_root_from_path(&wt).unwrap()), canon(&repo));
}

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let root = tempfile::tempdir().expect("tempdir");
    let home = root.path().join("fuigo-home");
    let repo = root.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("a.txt"), "a").unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "init"]);
    let wt = home.join("worktrees").join("demo").join("wt");
    std::fs::create_dir_all(wt.parent().unwrap()).unwrap();
    git(&repo, &["worktree", "add", "-q", "-b", "feature", wt.to_str().unwrap()]);
    (root, home, repo, wt)
}

/// `rm` of a worktree whose folder was deleted by hand drops its record AND git's registration of it, so the path and
/// branch can be used again at once. Before, the registration stayed and `git worktree add` refused the same path.
#[test]
fn removing_a_hand_deleted_worktree_clears_its_git_registration_and_record() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    fuigo_test_utils::require_git!();
    let (_root, home, repo, wt) = fixture();
    let env = crate::LockedTestEnv::lock().set("FUIGO_HOME", &home);
    let db = open_db().unwrap();
    db.register(&fuigo_fast_worktree::WorktreeRecord {
        id: "wt-hand-deleted".into(),
        path: wt.clone(),
        source_repo: repo.clone(),
        repo_name: "repo".into(),
        kind: fuigo_fast_worktree::WorktreeKind::Session,
        creation_mode: "linked".into(),
        git_ref: Some("feature".into()),
        head_commit: None,
        session_id: None,
        creator_pid: None,
        created_at: 0,
        last_accessed_at: None,
        status: fuigo_fast_worktree::WorktreeStatus::Alive,
        metadata: None,
    })
    .unwrap();
    std::fs::remove_dir_all(&wt).unwrap();

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let response = runtime
        .block_on(remove_worktree(
            &RemoveWorktreeRequest {
                worktree_path: None,
                id_or_path: Some("wt-hand-deleted".into()),
                force: false,
                dry_run: false,
            },
            &BackgroundCopyContext::new(),
        ))
        .expect("a worktree whose folder is already gone can be removed");
    assert!(response.removed);
    assert!(open_db().unwrap().get("wt-hand-deleted").unwrap().is_none(), "the record is dropped");
    drop(env);

    // Git forgot it too: the same path and branch are free again.
    git(&repo, &["worktree", "add", "-q", "-b", "feature-again", wt.to_str().unwrap()]);
    assert!(wt.join("a.txt").is_file());
}

/// The refusals `--force` never lifts must not offer it as the way out.
#[test]
fn a_refusal_that_force_cannot_lift_does_not_suggest_force() {
    fuigo_test_utils::require_git!();
    let (_root, home, repo, wt) = fixture();
    let stranger = tempfile::tempdir().unwrap();
    for (path, why) in [
        (repo.join(".git"), ".git folder"),
        (repo.clone(), "git repository"),
        (stranger.path().to_path_buf(), "not created by Fuigo"),
    ] {
        for force in [false, true] {
            let reason = removal_refusal(&path, force, None, &home).unwrap_or_else(|| panic!("{why} must be refused"));
            assert!(!reason.contains("--force") && !reason.contains(" -f"), "{why} (force={force}): {reason}");
        }
    }
    // And the soft refusals still name the way out, which really works.
    std::fs::write(wt.join("new.txt"), "unsaved").unwrap();
    let soft = removal_refusal(&wt, false, None, &home).expect("dirty worktree refused");
    assert!(soft.contains("--force"), "{soft}");
    assert_eq!(removal_refusal(&wt, true, None, &home), None);
}

/// 51.10: removing a Jujutsu workspace must forget THAT workspace. It was forgotten by the folder's name, but the
/// workspace is registered under the name it was created with (the session id), so the forget matched nothing and the
/// repository kept listing a workspace whose folder was gone. `jj workspace forget` run inside the workspace names the
/// current one whatever it is called.
#[cfg(unix)]
#[test]
fn removing_a_jj_workspace_forgets_the_workspace_it_runs_in() {
    use std::os::unix::fs::PermissionsExt;
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let log = root.path().join("jj-calls.log");
    let fake = bin.join("jj");
    std::fs::write(&fake, format!("#!/bin/sh\necho \"$PWD|$*\" >> '{}'\nexit 0\n", log.display())).unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let workspace = dunce::canonicalize(root.path()).unwrap().join("wts").join("slug").join("mylabel");
    std::fs::create_dir_all(workspace.join(".jj")).unwrap();
    std::fs::write(workspace.join(".jj").join("repo"), "../../main/.jj/repo").unwrap();

    let _env = crate::LockedTestEnv::lock().set("PATH", &bin);
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(remove_jj_workspace(workspace.to_str().unwrap())).unwrap();

    let calls = std::fs::read_to_string(&log).unwrap_or_default();
    let expected = format!("{}|workspace forget", workspace.display());
    assert!(
        calls.lines().any(|l| l == expected),
        "`jj workspace forget` must run inside the workspace, with no name; calls: {calls:?}"
    );
    assert!(!workspace.exists(), "the folder is removed too");
}

#[test]
fn a_folder_with_a_jj_directory_is_a_jujutsu_repository() {
    let dir = tempfile::tempdir().unwrap();
    assert!(!crate::session::git::detect_vcs_kind(dir.path()).is_jj());
    std::fs::create_dir_all(dir.path().join(".jj")).unwrap();
    assert!(crate::session::git::detect_vcs_kind(dir.path()).is_jj());
}

/// 53.9: a worktree made from a folder inside a repository reports the repository root as its source in
/// `worktree list` and `worktree show`, not the subfolder it happened to be made from.
#[test]
fn a_worktree_made_from_a_repo_subfolder_reports_the_repo_root_as_its_source() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    fuigo_test_utils::require_git!();
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("fuigo-home");
    let repo = root.path().join("project");
    std::fs::create_dir_all(repo.join("services").join("api")).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("services").join("api").join("main.rs"), "fn main() {}").unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "init"]);
    let _env = crate::LockedTestEnv::lock().set("FUIGO_HOME", &home);
    let dest = home.join("worktrees").join("project").join("from-sub");
    WorktreeBuilder::new(repo.join("services").join("api"), &dest)
        .worktree_kind(fuigo_fast_worktree::WorktreeKind::Session)
        .create().expect("worktree from a subfolder");

    let record = open_db()
        .unwrap()
        .get(dest.to_str().unwrap())
        .unwrap()
        .expect("the worktree is registered");
    assert_eq!(canon(&record.source_repo), canon(&repo), "the source is the repository root");
    assert_eq!(record.repo_name, "project");
}

/// 51.11: empty folders are not unsaved work; a worktree whose only untracked content is empty folders is removable
/// without `--force`.
#[test]
fn a_worktree_holding_only_empty_folders_is_removable_without_force() {
    fuigo_test_utils::require_git!();
    let (_root, home, _repo, wt) = fixture();
    std::fs::create_dir_all(wt.join("build").join("out").join("deep")).unwrap();
    std::fs::create_dir_all(wt.join("empty")).unwrap();
    assert_eq!(removal_refusal(&wt, false, None, &home), None);
}

/// 51.2: from a folder inside the repository, `sessions list` and `/resume` look for sessions started from that same
/// folder in each worktree too.
#[test]
fn the_same_subfolder_in_every_worktree_is_a_session_candidate() {
    let roots = vec!["/wts/repo/a".to_owned(), "/wts/repo/b".to_owned()];
    assert_eq!(
        same_subfolder_candidates("/work/repo/services/api", "/work/repo", &roots),
        vec!["/wts/repo/a/services/api".to_owned(), "/wts/repo/b/services/api".to_owned()]
    );
    // From inside a worktree, the main checkout and the other worktrees are the others.
    assert_eq!(
        same_subfolder_candidates("/wts/repo/a/services/api", "/work/repo", &roots),
        vec!["/work/repo/services/api".to_owned(), "/wts/repo/b/services/api".to_owned()]
    );
    // A root itself, or a folder outside every checkout, has no subfolder to repeat.
    assert!(same_subfolder_candidates("/work/repo", "/work/repo", &roots).is_empty());
    assert!(same_subfolder_candidates("/elsewhere", "/work/repo", &roots).is_empty());
}

/// 51.2: worktrees of another repository that has the same folder name share the worktree directory on disk; their sessions
/// are not this repository's.
#[test]
fn a_same_named_sibling_repository_does_not_contribute_its_worktrees() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    fuigo_test_utils::require_git!();
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("fuigo-home");
    let make_repo = |parent: &str| {
        let repo = root.path().join(parent).join("team").join("lib");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);
        std::fs::write(repo.join("a.txt"), "a").unwrap();
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-q", "-m", "init"]);
        repo
    };
    let (mine, other) = (make_repo("one"), make_repo("two"));
    let _env = crate::LockedTestEnv::lock().set("FUIGO_HOME", &home);
    // Both repositories end in `team/lib`, so they share one worktree directory
    let shared = worktree_base_dir(&mine);
    assert_eq!(shared, worktree_base_dir(&other));
    std::fs::create_dir_all(&shared).unwrap();
    let (mine_wt, other_wt) = (shared.join("mine"), shared.join("theirs"));
    git(&mine, &["worktree", "add", "-q", "-b", "m", mine_wt.to_str().unwrap()]);
    git(&other, &["worktree", "add", "-q", "-b", "t", other_wt.to_str().unwrap()]);

    let candidates = candidate_worktree_cwds_for_same_repo(&mine).unwrap();
    let canon_list: Vec<PathBuf> = candidates.iter().map(|c| canon(Path::new(c))).collect();
    assert!(canon_list.contains(&canon(&mine_wt)), "own worktree is a candidate: {candidates:?}");
    assert!(!canon_list.contains(&canon(&other_wt)), "the sibling repository's worktree is not: {candidates:?}");
}


/// 51.2: a repository's submodule folder is itself a repository, so a session started in it found no worktrees of its
/// own. The superproject's worktrees each hold that submodule at the same path; sessions started there are the same
/// project's, and `sessions list` and `/resume` from any of them must see the others.
#[test]
fn a_submodule_folder_sees_the_sessions_of_the_same_submodule_in_the_superprojects_worktrees() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    fuigo_test_utils::require_git!();
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("fuigo-home");
    let sub_origin = root.path().join("origin").join("core");
    std::fs::create_dir_all(&sub_origin).unwrap();
    git(&sub_origin, &["init", "-q", "-b", "main"]);
    std::fs::write(sub_origin.join("lib.rs"), "pub fn core() {}").unwrap();
    git(&sub_origin, &["add", "-A"]);
    git(&sub_origin, &["commit", "-q", "-m", "init"]);

    let app = root.path().join("work").join("app");
    std::fs::create_dir_all(&app).unwrap();
    git(&app, &["init", "-q", "-b", "main"]);
    std::fs::write(app.join("main.rs"), "fn main() {}").unwrap();
    git(&app, &["add", "-A"]);
    git(&app, &["commit", "-q", "-m", "init"]);
    git(&app, &["-c", "protocol.file.allow=always", "submodule", "add", "-q", sub_origin.to_str().unwrap(), "libs/core"]);
    git(&app, &["commit", "-q", "-m", "add the submodule"]);

    let _env = crate::LockedTestEnv::lock().set("FUIGO_HOME", &home);
    let base = worktree_base_dir(&app);
    std::fs::create_dir_all(&base).unwrap();
    let wt = base.join("feature");
    git(&app, &["worktree", "add", "-q", "-b", "feature", wt.to_str().unwrap()]);
    git(&wt, &["-c", "protocol.file.allow=always", "submodule", "update", "--init", "-q"]);
    assert!(wt.join("libs").join("core").join("lib.rs").exists(), "fixture: the worktree holds the submodule");

    // From the submodule of the main checkout: the worktree's copy of it is a candidate
    let main_sub = app.join("libs").join("core");
    let candidates = candidate_worktree_cwds_for_same_repo(&main_sub).unwrap();
    let canon_list: Vec<PathBuf> = candidates.iter().map(|c| canon(Path::new(c))).collect();
    assert!(
        canon_list.contains(&canon(&wt.join("libs").join("core"))),
        "the worktree's copy of the submodule is a candidate: {candidates:?}"
    );

    // From the worktree's submodule: the main checkout's copy is
    let wt_sub = wt.join("libs").join("core");
    let candidates = candidate_worktree_cwds_for_same_repo(&wt_sub).unwrap();
    let canon_list: Vec<PathBuf> = candidates.iter().map(|c| canon(Path::new(c))).collect();
    assert!(canon_list.contains(&canon(&main_sub)), "the main checkout's copy is a candidate: {candidates:?}");
    assert_eq!(candidates[0], wt_sub.to_string_lossy(), "the folder itself still comes first");

    // A plain repository (no superproject) is unchanged
    let plain = candidate_worktree_cwds_for_same_repo(&app).unwrap();
    assert!(!plain.iter().any(|c| c.contains("libs")), "{plain:?}");
}
