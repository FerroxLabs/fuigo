use std::path::{Path, PathBuf};

/// The git repo root project config is written under; `cwd` itself when there is no repo.
/// Uses `git2::Repository::discover`, as project config discovery does, so an import never creates config in an
/// unexpected subdirectory.
#[must_use]
pub fn find_project_root(cwd: &Path) -> PathBuf {
    git2::Repository::discover(cwd)
        .ok()
        .and_then(|repo| repo.workdir().map(Path::to_path_buf))
        .unwrap_or_else(|| cwd.to_path_buf())
}
