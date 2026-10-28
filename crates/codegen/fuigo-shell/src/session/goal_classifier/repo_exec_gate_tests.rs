//! u35 t1: the goal baseline starts no git in a folder the judge refuses. The judge is process-global, so the test
//! refuses only a directory unique to this process and puts an allow-all judge back when it finishes.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

fn refused_root() -> &'static PathBuf {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| std::env::temp_dir().join(format!("fuigo-t1-goal-untrusted-{}", std::process::id())))
}

fn judge(dir: &Path) -> bool {
    !dir.starts_with(refused_root())
}

struct RestoreAllowAll;

impl Drop for RestoreAllowAll {
    fn drop(&mut self) {
        fuigo_tty_utils::install_repo_exec_judge(|_| true);
    }
}

fn seeded_repo(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    fuigo_test_utils::git::init_git_repo(dir);
    std::fs::write(dir.join("a.txt"), "a").unwrap();
    fuigo_test_utils::git::git_commit_all(dir, "first");
}

#[tokio::test]
async fn the_goal_baseline_is_absent_in_an_untrusted_folder() {
    fuigo_test_utils::require_git!();
    let untrusted = refused_root().join("repo");
    seeded_repo(&untrusted);
    let trusted = tempfile::tempdir().unwrap();
    seeded_repo(trusted.path());

    fuigo_tty_utils::install_repo_exec_judge(judge);
    let _restore = RestoreAllowAll;
    assert!(super::capture_git_baseline(&untrusted).await.is_none(), "no git runs in the refused folder");
    assert!(super::capture_git_baseline(trusted.path()).await.is_some(), "a trusted folder still gets its baseline");
}
