//! u35 t1: with a judge that refuses a folder, the workspace starts no git, jj or direnv there and every caller reads
//! the refusal as "absent". The judge is process-global, so these tests serialise, refuse only a directory unique to
//! this process, and put an allow-all judge back when they finish.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

static SERIAL: Mutex<()> = Mutex::new(());

fn refused_root() -> &'static PathBuf {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| std::env::temp_dir().join(format!("fuigo-t1-untrusted-{}", std::process::id())))
}

fn judge(dir: &Path) -> bool {
    !dir.starts_with(refused_root())
}

/// Holds the serial lock and the refusing judge; restores an allow-all judge on drop.
struct RefusingJudge(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

impl RefusingJudge {
    fn install() -> Self {
        let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        fuigo_tty_utils::install_repo_exec_judge(judge);
        Self(guard)
    }
}

impl Drop for RefusingJudge {
    fn drop(&mut self) {
        fuigo_tty_utils::install_repo_exec_judge(|_| true);
    }
}

fn untrusted_dir(name: &str) -> PathBuf {
    let dir = refused_root().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn an_untrusted_folder_starts_no_git_or_jj() {
    let _judge = RefusingJudge::install();
    let dir = untrusted_dir("git-jj");
    git2::Repository::init(&dir).unwrap();

    let err = crate::session::git::git_cli(&dir, &["status"]).await.unwrap_err();
    assert!(err.to_string().contains("not a trusted folder"), "{err}");
    assert!(crate::session::git::jj_cli(&dir, &["st"]).await.is_err());
    assert!(
        crate::file_system::git_status_short_pinned(&dir, crate::file_system::FsmonitorOverride::Disabled)
            .await
            .is_err(),
        "no status prefix"
    );
    assert!(crate::file_system::jj_status(&dir).await.is_err(), "no jj status");
    assert!(!crate::git_object_exists(&dir, "HEAD"));
    assert!(crate::permission::hardened_git_command_for_gate_tests(&dir, &["rev-parse", "HEAD"]).is_none());
    assert!(fuigo_tty_utils::git_command_in(&dir).is_err());
    assert!(fuigo_tty_utils::jj_command_in(&dir).is_err());
    assert!(fuigo_tty_utils::direnv_command_in(&dir).is_err());
}

#[tokio::test]
async fn a_trusted_folder_still_gets_git() {
    let _judge = RefusingJudge::install();
    let dir = tempfile::tempdir().unwrap();
    let out = crate::session::git::git_cli(dir.path(), &["--version"]).await.unwrap();
    assert!(out.starts_with("git version"), "{out}");
}

#[test]
fn an_untrusted_folder_evaluates_no_envrc() {
    let _judge = RefusingJudge::install();
    let dir = untrusted_dir("envrc");
    let marker = dir.join("ran");
    std::fs::write(dir.join(".envrc"), format!("touch '{}'\nexport FUIGO_T1_ENVRC=1\n", marker.display())).unwrap();

    assert!(crate::envrc::load_envrc(&dir).is_none(), "neither direnv nor the bash evaluator loaded it");
    assert!(!marker.exists(), "the .envrc must not have run");
}
