//! u35 t1: with a judge that refuses a folder, fast-worktree starts no git there. The judge is process-global, so the
//! test refuses only a directory unique to this process and puts an allow-all judge back when it finishes.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use super::checkout::{git_command_judged, git_reset_hard_command};

fn refused_root() -> &'static PathBuf {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| std::env::temp_dir().join(format!("fuigo-t1-fw-untrusted-{}", std::process::id())))
}

fn judge(dir: &Path) -> bool {
    !dir.starts_with(refused_root())
}

/// The judge is process-global: the tests here hold this lock while theirs is installed (u35 t3: one test restoring
/// allow-all while the other still relied on its refusing judge made the first flaky).
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct RestoreAllowAll;

impl Drop for RestoreAllowAll {
    fn drop(&mut self) {
        fuigo_tty_utils::install_repo_exec_judge(|_| true);
    }
}

#[test]
fn an_untrusted_folder_gets_no_git() {
    let untrusted = refused_root().join("repo");
    std::fs::create_dir_all(&untrusted).unwrap();
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fuigo_tty_utils::install_repo_exec_judge(judge);
    let _restore = RestoreAllowAll;

    assert!(git_command_judged(&untrusted).is_err());
    let err = git_reset_hard_command(&untrusted, None).unwrap_err();
    assert!(err.to_string().contains("not a trusted folder"), "{err}");
    assert!(super::worktree_add_no_checkout(&untrusted, "dest", "HEAD").is_err());
    assert!(crate::sync::collect_source_dirty_state(&untrusted).is_err());

    let trusted = tempfile::tempdir().unwrap();
    assert!(git_command_judged(trusted.path()).is_ok());
}

/// u35 t2 (Grok 2): a worktree whose claimed source repository is refused is refused; the operation is not retried
/// as git in the run directory.
#[test]
fn a_refused_source_is_not_retried_in_the_run_dir() {
    let source = refused_root().join("source");
    std::fs::create_dir_all(source.join(".git").join("worktrees").join("wt")).unwrap();
    let trusted = tempfile::tempdir().unwrap();
    std::fs::write(
        trusted.path().join(".git"),
        format!("gitdir: {}\n", source.join(".git").join("worktrees").join("wt").display()),
    )
    .unwrap();
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fuigo_tty_utils::install_repo_exec_judge(judge);
    let _restore = RestoreAllowAll;
    assert!(git_command_judged(trusted.path()).is_err(), "the source decides; no retry in the run dir");
}
