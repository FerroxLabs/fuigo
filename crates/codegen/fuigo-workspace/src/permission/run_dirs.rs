//! u35 t3 (design d2 §3.2 as narrowed after review t1r2): which directories a shell command's folder trust is judged
//! on.
//!
//! A folder's trust covers the commands that start there. A command is Trusted only if every directory it starts in is
//! in a trusted folder ([`crate::folder_trust::command_trust`]): the request's directory and the tool's own working
//! directory (OpenCode bash `workdir`, the runner's `exec_cwd`). Naming another folder in the command (`cd`, `git -C`,
//! `GIT_DIR=`, `make -C`, ...) does not change the answer, as upstream and other coding agents judge it: from a trusted
//! start folder that is the folder's own content steering the command (residual R2), and from an untrusted start folder
//! the command asks anyway. Pure: it starts nothing and reads no command text.

use std::path::PathBuf;

/// [`crate::folder_trust::command_trust`] over `run_dirs`, each judged as itself. u35 t4b (Astra r3): a directory that
/// does not exist or does not resolve is not trusted (no ancestor stands in for it), so the command asks; a command
/// cannot start there anyway.
pub(crate) fn run_dirs_trust(run_dirs: &[PathBuf]) -> crate::folder_trust::CommandTrust {
    crate::folder_trust::command_trust(run_dirs.iter().map(PathBuf::as_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::folder_trust::TestFolderTrust;

    /// u35 t4b (Astra r3 Medium): a run directory is judged as itself. One that does not exist or does not resolve
    /// (missing, a dangling link) is not trusted, even under a trusted folder, so the command asks; an existing
    /// directory of a trusted folder stays trusted.
    #[test]
    fn a_missing_or_unresolvable_run_dir_is_not_trusted() {
        let tmp = tempfile::tempdir().unwrap();
        let r = dunce::canonicalize(tmp.path()).unwrap();
        std::fs::create_dir(r.join("sub")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(r.join("nowhere"), r.join("dangling")).unwrap();
        let _trust = TestFolderTrust::only(&[r.as_path()]);
        assert!(run_dirs_trust(std::slice::from_ref(&r)).is_trusted(), "an existing cwd of a trusted folder");
        assert!(run_dirs_trust(&[r.clone(), r.join("sub")]).is_trusted(), "an existing workdir of a trusted folder");
        assert!(!run_dirs_trust(&[r.join("gone")]).is_trusted(), "a missing cwd under a trusted folder");
        assert!(
            !run_dirs_trust(&[r.clone(), r.join("gone").join("deeper")]).is_trusted(),
            "a missing workdir under a trusted folder"
        );
        #[cfg(unix)]
        assert!(!run_dirs_trust(&[r.clone(), r.join("dangling")]).is_trusted(), "a workdir that does not resolve");
    }
}
