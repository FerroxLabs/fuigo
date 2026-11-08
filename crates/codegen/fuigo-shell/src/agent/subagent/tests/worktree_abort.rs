//! 1.0.39 item 7 (B2): an isolated subagent worktree that cannot be made on a tracked-file copy failure
//! or a full disk fails the subagent cleanly and leaves nothing behind; every other error falls back.

use super::super::handle_request::{create_isolated_worktree, isolated_worktree_abort_message};
use fuigo_test_utils::git::{git_commit_all, init_git_repo};
use std::path::{Path, PathBuf};

#[allow(clippy::disallowed_methods, reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there")]
fn repo(temp: &tempfile::TempDir) -> PathBuf {
    let repo = temp.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    init_git_repo(&repo);
    std::fs::write(repo.join("ok.txt"), "ok").unwrap();
    std::fs::write(repo.join("secret.txt"), "secret").unwrap();
    git_commit_all(&repo, "initial");
    repo
}

fn registrations(repo: &Path) -> usize {
    let out = std::process::Command::new("git")
        .args(["worktree", "list", "--porcelain"])
        .current_dir(repo)
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .matches("worktree ")
        .count()
}

fn builder(
    repo: &Path,
    dest: &Path,
    mode: fuigo_fast_worktree::CreationMode,
) -> fuigo_fast_worktree::WorktreeBuilder {
    fuigo_fast_worktree::WorktreeBuilder::new(repo, dest)
        .working_tree_mode(fuigo_fast_worktree::WorkingTreeMode::PreserveWorkingTree)
        .creation_mode(mode)
}

fn assert_nothing_left(repo: &Path, dest: &Path) {
    assert!(!dest.exists(), "dest must be reclaimed: {}", dest.display());
    assert_eq!(
        registrations(repo),
        1,
        "no worktree registration may be left"
    );
    let reg = repo.join(".git/worktrees").join(dest.file_name().unwrap());
    assert!(!reg.exists(), "no .git/worktrees entry may be left");
}

/// (a) A tracked file that cannot be copied: failed result naming the file, parent untouched, nothing left.
#[allow(clippy::disallowed_methods, reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there")]
#[cfg(unix)]
#[test]
fn socket_tracked_file_fails_cleanly_and_leaves_nothing() {
    fuigo_test_utils::require_git!();
    let temp = tempfile::TempDir::new().unwrap();
    let repo = repo(&temp);
    std::fs::remove_file(repo.join("secret.txt")).unwrap();
    let _socket = std::os::unix::net::UnixListener::bind(repo.join("secret.txt")).unwrap();
    let dest = temp.path().join("subagent-a");
    let b = builder(&repo, &dest, fuigo_fast_worktree::CreationMode::Linked);
    let err = create_isolated_worktree(&repo, &dest, || b.create()).unwrap_err();
    let msg = isolated_worktree_abort_message(&err).expect("a typed copy abort fails the subagent");
    assert!(
        msg.starts_with("Couldn't create this subagent's isolated worktree: "),
        "{msg}"
    );
    assert!(msg.contains("secret.txt"), "{msg}");
    assert!(msg.ends_with(
        "Nothing ran. Free disk space or fix the file and retry, or use isolation=\"none\"."
    ));
    assert_eq!(
        std::fs::read_to_string(repo.join("ok.txt")).unwrap(),
        "ok",
        "parent tree untouched"
    );
    assert_nothing_left(&repo, &dest);
}

/// A repo whose `post-checkout` hook runs `body` and exits 1, and a probe that reports a nearly full disk.
#[allow(clippy::disallowed_methods, reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there")]
#[cfg(unix)]
fn failing_hook_under_low_probe(
    temp: &tempfile::TempDir,
    body: &str,
) -> (PathBuf, fuigo_fast_worktree::storage_seam::SeamGuard) {
    use std::os::unix::fs::PermissionsExt;
    let repo = repo(temp);
    let hook = repo.join(".git/hooks/post-checkout");
    std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
    std::fs::write(&hook, format!("#!/bin/sh\n{body}\nexit 1\n")).unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    let guard = fuigo_fast_worktree::storage_seam::install(
        Some(Box::new(|_: &Path| {
            Ok(fuigo_fast_worktree::Avail {
                bytes: 1024,
                inodes: Some(10),
            })
        })),
        None,
    );
    (repo, guard)
}

/// (b) A low probe plus a silent failing `post-checkout` hook: git names no write failure, so it is not a full disk.
/// The error is the ordinary one and the subagent stays eligible for the 1.0.38 fallback. (A hook that prints
/// anything else is class O and falls back too.)
#[cfg(unix)]
#[test]
fn low_probe_and_a_silent_hook_failure_is_an_ordinary_error() {
    fuigo_test_utils::require_git!();
    let temp = tempfile::TempDir::new().unwrap();
    let (repo, _g) = failing_hook_under_low_probe(&temp, ":");
    let dest = temp.path().join("subagent-b");
    let b = builder(&repo, &dest, fuigo_fast_worktree::CreationMode::GitCheckout);
    let err = create_isolated_worktree(&repo, &dest, || b.create()).unwrap_err();
    assert!(
        err.chain().all(|c| c
            .downcast_ref::<fuigo_fast_worktree::GitStorageFull>()
            .is_none()),
        "a silent hook failure is not a full disk: {err:#}"
    );
    assert!(
        isolated_worktree_abort_message(&err).is_none(),
        "the fallback stays available: {err:#}"
    );
}

/// (b2) A low probe plus a git write-failure line: typed by the floor, and the tree git left behind and its
/// registration are reclaimed.
#[cfg(unix)]
#[test]
fn low_probe_and_a_write_failure_line_leaves_nothing() {
    fuigo_test_utils::require_git!();
    let temp = tempfile::TempDir::new().unwrap();
    let (repo, _g) =
        failing_hook_under_low_probe(&temp, "echo 'error: unable to write file ok.txt' >&2");
    let dest = temp.path().join("subagent-b2");
    let b = builder(&repo, &dest, fuigo_fast_worktree::CreationMode::GitCheckout);
    let err = create_isolated_worktree(&repo, &dest, || b.create()).unwrap_err();
    let typed = err
        .chain()
        .find_map(|c| c.downcast_ref::<fuigo_fast_worktree::GitStorageFull>())
        .unwrap_or_else(|| panic!("a write failure under the floor must classify: {err:#}"));
    assert_eq!(typed.by, fuigo_fast_worktree::StorageFullBy::Floor);
    assert!(isolated_worktree_abort_message(&err).is_some());
    assert_nothing_left(&repo, &dest);
}

/// (c) A `StorageFull` before the guard with `dest` absent (the create made a partial `dest`): reclaimed.
#[allow(clippy::disallowed_methods, reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there")]
#[test]
fn storage_full_before_the_guard_reclaims_a_dest_this_create_made() {
    fuigo_test_utils::require_git!();
    let temp = tempfile::TempDir::new().unwrap();
    let repo = repo(&temp);
    let dest = temp.path().join("subagent-c");
    let err = create_isolated_worktree(&repo, &dest, || {
        std::fs::create_dir_all(dest.join("partial")).unwrap();
        Err(
            anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::StorageFull))
                .context("failed to create parent directory for worktree dest"),
        )
    })
    .unwrap_err();
    assert!(isolated_worktree_abort_message(&err).is_some());
    assert_nothing_left(&repo, &dest);
}

/// (d) A `dest` that existed before this create is never removed, even on an abort.
#[allow(clippy::disallowed_methods, reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there")]
#[test]
fn pre_existing_dest_is_not_removed_on_an_abort() {
    fuigo_test_utils::require_git!();
    let temp = tempfile::TempDir::new().unwrap();
    let repo = repo(&temp);
    let dest = temp.path().join("subagent-d");
    std::fs::create_dir(&dest).unwrap();
    std::fs::write(dest.join("keep.txt"), "mine").unwrap();
    let err = create_isolated_worktree(&repo, &dest, || {
        Err(anyhow::Error::new(std::io::Error::from(
            std::io::ErrorKind::StorageFull,
        )))
    })
    .unwrap_err();
    assert!(isolated_worktree_abort_message(&err).is_some());
    assert_eq!(
        std::fs::read_to_string(dest.join("keep.txt")).unwrap(),
        "mine"
    );
}

/// (e) A non-git folder named after the ENOSPC sentence: an ordinary error, so the 1.0.38 fallback.
#[allow(clippy::disallowed_methods, reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there")]
#[test]
fn non_git_folder_named_after_the_sentence_falls_back() {
    let temp = tempfile::TempDir::new().unwrap();
    let source = temp.path().join("No space left on device");
    std::fs::create_dir(&source).unwrap();
    let dest = temp.path().join("subagent-e");
    let b = builder(&source, &dest, fuigo_fast_worktree::CreationMode::Linked);
    let err = create_isolated_worktree(&source, &dest, || b.create()).unwrap_err();
    assert!(isolated_worktree_abort_message(&err).is_none(), "{err:#}");
    assert!(!dest.exists());
}
