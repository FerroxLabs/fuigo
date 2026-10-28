//! u35 t1 (folder trust): the one gate in front of every `git`, `jj` and `direnv` Fuigo itself starts.
//!
//! A repository's own files choose programs those tools run (`core.fsmonitor`, a filter driver, an alias, hooks, a
//! `.envrc`). In a folder the user has not trusted, Fuigo starts none of them. Every production spawn goes through a
//! builder here that takes the directory the tool runs in, asks the installed judge about that directory, and only
//! then returns a command whose working directory is already set to it, so the directory checked is the one used.
//!
//! The judge is installed once per process by the binary entry (`fuigo_workspace::folder_trust::install_process_judges`):
//! the folder-trust decision for the directory. With no judge installed every judged builder refuses, unless this crate
//! is built with the `unjudged-repo-exec` feature (test builds only, enabled as a dev-dependency).
//!
//! Two builders are not judged, each for one stated reason: [`git_command_global`] reads the user's own global git
//! settings from a directory outside every repository, and [`git_command_user_invoked`] is the plugin install/publish
//! path the user typed. A source test (`tests/repo_exec_spawn_sites.rs`) keeps every other production spawn on the
//! judged builders.

use std::path::{Path, PathBuf};
use std::sync::RwLock;

/// The folder-trust judge: true when Fuigo may start repository tools in `dir`.
pub type RepoExecJudge = fn(&Path) -> bool;

static JUDGE: RwLock<Option<RepoExecJudge>> = RwLock::new(None);

/// Install the process's repository-execution judge (idempotent; the last install wins).
pub fn install_repo_exec_judge(judge: RepoExecJudge) {
    *JUDGE.write().unwrap_or_else(|e| e.into_inner()) = Some(judge);
}

/// Whether a judge is installed (tests and startup checks).
pub fn repo_exec_judge_installed() -> bool {
    JUDGE.read().unwrap_or_else(|e| e.into_inner()).is_some()
}

/// Whether the installed judge lets Fuigo start repository tools in `dir`. No judge: refused, except in test builds
/// (`unjudged-repo-exec`).
pub fn repo_exec_allowed(dir: &Path) -> bool {
    let judge = *JUDGE.read().unwrap_or_else(|e| e.into_inner());
    match judge {
        Some(judge) => judge(dir),
        None => cfg!(any(test, feature = "unjudged-repo-exec")),
    }
}

/// A gated builder refused: `dir` is not a trusted folder (or no judge is installed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoUntrusted {
    /// The directory the tool would have run in.
    pub dir: PathBuf,
}

impl std::fmt::Display for RepoUntrusted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} is not a trusted folder, so Fuigo runs no git, jj or direnv there",
            self.dir.display()
        )
    }
}

impl std::error::Error for RepoUntrusted {}

impl From<RepoUntrusted> for std::io::Error {
    fn from(err: RepoUntrusted) -> Self {
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, err.to_string())
    }
}

fn judged(dir: &Path, cmd: std::process::Command) -> Result<std::process::Command, RepoUntrusted> {
    if !repo_exec_allowed(dir) {
        tracing::debug!(dir = %dir.display(), "folder trust: repository tool not started in an untrusted folder");
        return Err(RepoUntrusted { dir: dir.to_path_buf() });
    }
    let mut cmd = cmd;
    cmd.current_dir(dir);
    Ok(cmd)
}

/// [`crate::git_command`] (a reader: `--no-optional-locks`) that runs in `dir`, judged on `dir`.
pub fn git_command_in(dir: &Path) -> Result<std::process::Command, RepoUntrusted> {
    judged(dir, crate::git_command_reader_unjudged())
}

/// [`crate::git_command_locking`] (a writer) that runs in `dir`, judged on `dir`.
pub fn git_command_locking_in(dir: &Path) -> Result<std::process::Command, RepoUntrusted> {
    judged(dir, crate::git_command_locking_unjudged())
}

/// The git at `program` (an absolute path the caller vetted) that runs in `dir`, judged on `dir`.
pub fn git_command_at_in(program: &Path, dir: &Path) -> Result<std::process::Command, RepoUntrusted> {
    judged(dir, crate::git_command_at_unjudged(program))
}

/// `jj` that runs in `dir`, judged on `dir` (stdin null, secrets removed, pager suppressed).
pub fn jj_command_in(dir: &Path) -> Result<std::process::Command, RepoUntrusted> {
    judged(dir, tool_command("jj"))
}

/// `direnv` that runs in `dir`, judged on `dir` (stdin null, secrets removed). The caller adds its own environment.
pub fn direnv_command_in(dir: &Path) -> Result<std::process::Command, RepoUntrusted> {
    judged(dir, tool_command("direnv"))
}

/// Git for a Fuigo-managed worktree operation: judged on `source_repo` (the repository the worktree belongs to) AND
/// on `run_dir` itself, which must physically be that repository (or inside it) or inside `managed_root` (the user's
/// Fuigo worktree directory). An untrusted source repository gets no managed worktree.
///
/// u35 t2 (Fable M1, Grok 2): the source named by a worktree's own `.git` file is repository-supplied, so the run
/// directory is judged too: the folder-trust judge gives a validated linked or registered managed worktree its source's
/// key, and a forged one its own. A path that does not resolve physically is refused, never compared lexically.
pub fn git_command_for_worktree(
    source_repo: &Path,
    run_dir: &Path,
    managed_root: &Path,
) -> Result<std::process::Command, RepoUntrusted> {
    let refuse = || RepoUntrusted { dir: run_dir.to_path_buf() };
    if !repo_exec_allowed(source_repo) {
        return Err(RepoUntrusted { dir: source_repo.to_path_buf() });
    }
    let (Ok(run), Ok(source)) = (dunce::canonicalize(run_dir), dunce::canonicalize(source_repo)) else {
        return Err(refuse());
    };
    let in_managed_root = dunce::canonicalize(managed_root).is_ok_and(|root| run.starts_with(root));
    let run_allowed = repo_exec_allowed(&run) || worktree_creation_source(&run).is_some_and(|s| s == source);
    if !(run.starts_with(&source) || in_managed_root) || !run_allowed {
        return Err(refuse());
    }
    let mut cmd = crate::git_command_reader_unjudged();
    cmd.current_dir(run_dir);
    Ok(cmd)
}

/// Worktrees Fuigo is building right now: (canonical destination, canonical source repository).
static CREATING: std::sync::Mutex<Vec<(PathBuf, PathBuf)>> = std::sync::Mutex::new(Vec::new());

fn creating() -> std::sync::MutexGuard<'static, Vec<(PathBuf, PathBuf)>> {
    CREATING.lock().unwrap_or_else(|e| e.into_inner())
}

/// Creation authority for a worktree Fuigo itself builds, from [`begin_worktree_creation`]. While it lives, the
/// managed-worktree builders treat git in exactly that destination as git in its source repository; dropping it (the
/// worktree finished, or creation failed and is being torn down) withdraws that.
#[must_use = "the authority ends when this is dropped"]
#[derive(Debug)]
pub struct WorktreeCreation {
    dest: Option<PathBuf>,
}

impl WorktreeCreation {
    /// Whether the destination was validated (otherwise git there is judged on the destination itself, as before).
    pub fn is_granted(&self) -> bool {
        self.dest.is_some()
    }
}

impl Drop for WorktreeCreation {
    fn drop(&mut self) {
        if let Some(dest) = self.dest.take() {
            let mut list = creating();
            if let Some(i) = list.iter().position(|(d, _)| *d == dest) {
                list.remove(i);
            }
        }
    }
}

/// u35 t3 (Astra r2 H3): authority for Fuigo to run git in a worktree it is creating, before the worktree database
/// records it (until then the folder-trust judge sees the new destination as a folder of its own and refuses it).
///
/// Refused when the judge refuses `source_repo`: an untrusted repository gets no managed worktree. Granted only for a
/// destination that is a real directory (not a symlink), physically inside `managed_root` (the user's Fuigo worktree
/// directory) and not that directory itself, outside the source, owned by this user, and still empty, so everything in
/// it is what Fuigo copies from the trusted source. Any other destination gets an inert authority and git there is
/// judged on the destination itself.
pub fn begin_worktree_creation(
    source_repo: &Path,
    dest: &Path,
    managed_root: &Path,
) -> Result<WorktreeCreation, RepoUntrusted> {
    if !repo_exec_allowed(source_repo) {
        return Err(RepoUntrusted { dir: source_repo.to_path_buf() });
    }
    let validated = (|| {
        let meta = std::fs::symlink_metadata(dest).ok()?;
        if !meta.is_dir() || !owned_by_this_user(&meta) {
            return None;
        }
        let source = dunce::canonicalize(source_repo).ok()?;
        let root = dunce::canonicalize(managed_root).ok()?;
        let dest = dunce::canonicalize(dest).ok()?;
        let fresh = std::fs::read_dir(&dest).ok()?.next().is_none();
        let placed = dest.starts_with(&root) && dest != root && !dest.starts_with(&source) && !source.starts_with(&dest);
        (fresh && placed).then_some((dest, source))
    })();
    let Some((dest, source)) = validated else {
        return Ok(WorktreeCreation { dest: None });
    };
    let mut list = creating();
    list.retain(|(d, _)| *d != dest);
    list.push((dest.clone(), source));
    Ok(WorktreeCreation { dest: Some(dest) })
}

/// The source repository of the worktree Fuigo is creating at exactly `run_dir`, while its [`WorktreeCreation`] lives.
pub fn worktree_creation_source(run_dir: &Path) -> Option<PathBuf> {
    let run = dunce::canonicalize(run_dir).ok()?;
    creating().iter().find(|(d, _)| *d == run).map(|(_, s)| s.clone())
}

#[cfg(unix)]
fn owned_by_this_user(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions.
    meta.uid() == unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn owned_by_this_user(_meta: &std::fs::Metadata) -> bool {
    // The directory was just created under the user's own Fuigo home; Windows has no cheap owner check here.
    true
}

/// [`git_command_for_worktree`] without `--no-optional-locks` (worktree writers).
pub fn git_command_locking_for_worktree(
    source_repo: &Path,
    run_dir: &Path,
    managed_root: &Path,
) -> Result<std::process::Command, RepoUntrusted> {
    let reader = git_command_for_worktree(source_repo, run_dir, managed_root)?;
    let mut cmd = crate::git_command_locking_unjudged();
    if let Some(dir) = reader.get_current_dir() {
        cmd.current_dir(dir);
    }
    Ok(cmd)
}

/// Not judged: git reading the user's own global settings (`git config --global ...`). It runs from a directory outside
/// every repository (the filesystem root, with `GIT_CEILING_DIRECTORIES` there), so git's repository discovery never
/// lands in the session folder. (Git never lets an alias replace a built-in command such as `config`.)
pub fn git_command_global() -> std::process::Command {
    let mut cmd = crate::git_command_reader_unjudged();
    let outside = outside_every_repository();
    cmd.current_dir(&outside);
    cmd.env("GIT_CEILING_DIRECTORIES", &outside);
    cmd
}

/// Not judged: git for the plugin install/publish commands the user typed (`fuigo plugin install|publish|tag`). Only
/// the files that implement those commands may call it (the source test holds the list).
pub fn git_command_user_invoked(dir: &Path) -> std::process::Command {
    let mut cmd = crate::git_command_reader_unjudged();
    cmd.current_dir(dir);
    cmd
}

/// [`git_command_user_invoked`] without `--no-optional-locks`.
pub fn git_command_locking_user_invoked(dir: &Path) -> std::process::Command {
    let mut cmd = crate::git_command_locking_unjudged();
    cmd.current_dir(dir);
    cmd
}

fn outside_every_repository() -> PathBuf {
    let tmp = std::env::temp_dir();
    tmp.ancestors()
        .last()
        .map(Path::to_path_buf)
        .unwrap_or(tmp)
}

fn tool_command(program: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new(program);
    crate::remove_fuigo_owned_secrets(&mut cmd);
    crate::detach_std_command(&mut cmd);
    cmd.stdin(std::process::Stdio::null());
    cmd.envs(crate::pager_env());
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The judge is process-global: tests that install one serialise on this lock.
    static JUDGE_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn builders_set_the_judged_directory() {
        let dir = std::env::temp_dir();
        let cmd = git_command_in(&dir).expect("test builds allow without a judge");
        assert_eq!(cmd.get_current_dir(), Some(dir.as_path()));
        let cmd = jj_command_in(&dir).expect("allowed");
        assert_eq!(cmd.get_program(), "jj");
        assert_eq!(cmd.get_current_dir(), Some(dir.as_path()));
    }

    #[test]
    fn global_git_runs_outside_every_repository() {
        let cmd = git_command_global();
        let dir = cmd.get_current_dir().expect("a directory is set");
        assert_eq!(dir.parent(), None, "a filesystem root");
    }

    #[test]
    fn worktree_builder_refuses_a_run_dir_outside_the_repo_and_root() {
        let repo = std::env::temp_dir().join("fuigo-t1-repo-exec-src");
        let root = std::env::temp_dir().join("fuigo-t1-repo-exec-root");
        let elsewhere = std::env::temp_dir().join("fuigo-t1-repo-exec-elsewhere");
        for d in [&repo, &root, &elsewhere] {
            std::fs::create_dir_all(d).unwrap();
        }
        assert!(git_command_for_worktree(&repo, &repo, &root).is_ok());
        assert!(git_command_for_worktree(&repo, &root, &root).is_ok());
        assert!(git_command_for_worktree(&repo, &elsewhere, &root).is_err());
    }

    /// u35 t2 (Fable M1, Grok 2): the run directory of a managed-worktree operation is judged itself (so a forged
    /// worktree under the managed root does not borrow its claimed source's trust), and one that does not resolve
    /// to a physical path is refused, never compared lexically.
    #[test]
    fn worktree_builder_judges_the_run_dir_and_refuses_one_that_does_not_resolve() {
        let _serial = JUDGE_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        fn refused_root() -> PathBuf {
            std::env::temp_dir().join(format!("fuigo-t2-repo-exec-untrusted-{}", std::process::id()))
        }
        struct RestoreAllowAll;
        impl Drop for RestoreAllowAll {
            fn drop(&mut self) {
                install_repo_exec_judge(|_| true);
            }
        }
        let scratch = std::env::temp_dir().join(format!("fuigo-t2-repo-exec-trusted-{}", std::process::id()));
        let source = scratch.join("source");
        std::fs::create_dir_all(&source).unwrap();
        let managed = refused_root().join("worktrees");
        let forged = managed.join("wt");
        std::fs::create_dir_all(&forged).unwrap();
        install_repo_exec_judge(|dir| {
            let physical = dunce::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
            !physical.starts_with(dunce::canonicalize(refused_root()).unwrap_or_else(|_| refused_root()))
        });
        let _restore = RestoreAllowAll;
        assert!(git_command_for_worktree(&source, &source, &managed).is_ok());
        assert!(
            git_command_for_worktree(&source, &forged, &managed).is_err(),
            "a run dir the judge refuses is refused even under the managed root"
        );
        let missing = scratch.join("root").join("missing");
        std::fs::create_dir_all(scratch.join("root")).unwrap();
        assert!(
            git_command_for_worktree(&source, &missing, &scratch.join("root")).is_err(),
            "a run dir that does not resolve is refused"
        );
        let _ = std::fs::remove_dir_all(refused_root());
        let _ = std::fs::remove_dir_all(&scratch);
    }

    /// u35 t3 (Astra r2 H3): creation authority is refused for an untrusted source, granted only for a fresh, real
    /// directory inside the managed root, honoured by the managed-worktree builder for exactly that destination and
    /// source, and withdrawn when dropped.
    #[test]
    fn creation_authority_covers_only_a_fresh_managed_destination_while_it_lives() {
        fn refused() -> PathBuf {
            std::env::temp_dir().join(format!("fuigo-t3-creation-refused-{}", std::process::id()))
        }
        struct RestoreAllowAll;
        impl Drop for RestoreAllowAll {
            fn drop(&mut self) {
                install_repo_exec_judge(|_| true);
            }
        }
        let _serial = JUDGE_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let scratch = std::env::temp_dir().join(format!("fuigo-t3-creation-{}", std::process::id()));
        let source = scratch.join("source");
        let other = scratch.join("other");
        let untrusted_source = refused().join("source");
        let root = refused().join("worktrees");
        let dest = root.join("repo").join("wt");
        let used = root.join("repo").join("used");
        for dir in [&source, &other, &untrusted_source, &dest, &used] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(used.join("planted"), "x").unwrap();
        install_repo_exec_judge(|dir| {
            let physical = dunce::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
            !physical.starts_with(dunce::canonicalize(refused()).unwrap_or_else(|_| refused()))
        });
        let _restore = RestoreAllowAll;

        assert!(begin_worktree_creation(&untrusted_source, &dest, &root).is_err(), "untrusted source: no worktree");
        assert!(git_command_for_worktree(&source, &dest, &root).is_err(), "no authority yet");
        {
            let authority = begin_worktree_creation(&source, &dest, &root).unwrap();
            assert!(authority.is_granted());
            assert_eq!(worktree_creation_source(&dest), Some(dunce::canonicalize(&source).unwrap()));
            assert!(git_command_for_worktree(&source, &dest, &root).is_ok(), "creation authority covers the dest");
            assert!(git_command_for_worktree(&other, &dest, &root).is_err(), "only for its own source");
            let used_authority = begin_worktree_creation(&source, &used, &root).unwrap();
            assert!(!used_authority.is_granted(), "a destination that already has content gets no authority");
            let outside = begin_worktree_creation(&source, &other, &root).unwrap();
            assert!(!outside.is_granted(), "a destination outside the managed root gets no authority");
        }
        assert_eq!(worktree_creation_source(&dest), None, "dropped: authority withdrawn");
        assert!(git_command_for_worktree(&source, &dest, &root).is_err());
        let _ = std::fs::remove_dir_all(refused());
        let _ = std::fs::remove_dir_all(&scratch);
    }
}
