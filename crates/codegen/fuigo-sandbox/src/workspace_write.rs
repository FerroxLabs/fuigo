//! Explicit launch-folder write boundaries. Omitted custom options keep legacy grants.
use std::path::{Path, PathBuf};

use crate::git_write_deny::canonical_path;
use crate::{ProfileName, SandboxConfig, SandboxProfile};

impl ProfileName {
    /// Whether the selected profile requires an explicit read-only launch-folder boundary.
    pub fn denies_workspace_write(&self, config: &SandboxConfig) -> bool {
        match self.selected(config).as_ref() {
            Self::Minimal => true,
            Self::Custom(name) => config.profiles.get(name).is_some_and(|profile| {
                !profile
                    .workspace_write
                    .unwrap_or(profile.extends.as_deref() != Some("minimal"))
            }),
            _ => false,
        }
    }
}

pub(crate) fn resolve_boundary(
    name: &ProfileName,
    workspace: &Path,
    config: &SandboxConfig,
    profile: &mut SandboxProfile,
) {
    let selected = name.selected(config);
    let name = selected.as_ref();
    if name.denies_workspace_write(config) {
        let root = canonical_path(workspace);
        let sessions = canonical_path(&crate::paths::sessions_root());
        if sessions.starts_with(&root) {
            if crate::startup_warnings::first("nested-sessions".into()) {
                fuigo_tty_utils::cli_eprintln!(
                    "WARNING: Fuigo sessions resolves inside the read-only launch folder; session persistence may fail. Keep FUIGO_HOME outside the launch folder."
                );
            }
        }
        // Resolve missing relative entries against the launch folder, not the caller's
        // current directory, before any grant materialization can create them.
        profile.read_write = profile
            .read_write
            .iter()
            .map(|path| workspace.join(path))
            .filter(|path| !canonical_path(path).starts_with(&root))
            .collect();
        if !profile.read_only.contains(&root) {
            profile.read_only.push(root);
        }
    } else if let ProfileName::Custom(name) = name
        && config
            .profiles
            .get(name)
            .is_some_and(|p| p.workspace_write == Some(true))
        && !profile.read_write.iter().any(|path| path == workspace)
    {
        profile.read_write.push(workspace.to_path_buf());
    }
}

#[cfg(all(feature = "enforce", unix, test))]
type AppliedBoundary = Vec<String>;
#[cfg(all(feature = "enforce", unix, not(test)))]
type AppliedBoundary = ();

/// Landlock is additive: temp/parent grants cannot express a read-only subtree.
/// Seatbelt's specific deny actions and Linux's final bwrap mount supply that boundary.
#[cfg(all(feature = "enforce", unix))]
pub(crate) fn apply_seatbelt_boundary(
    name: &ProfileName,
    workspace: &Path,
    config: &SandboxConfig,
    profile: &SandboxProfile,
    caps: &mut nono::CapabilitySet,
) -> anyhow::Result<AppliedBoundary> {
    #[cfg(any(target_os = "macos", test))]
    if name.denies_workspace_write(config) {
        let (entries, roots) = seatbelt_boundary_inputs(workspace, &profile.read_write);
        let rules = crate::deny::render_write_deny_rules(&entries, &roots)?;
        #[cfg(test)]
        let rendered = rules.rules.clone();
        #[cfg(target_os = "macos")]
        rules.add_to(caps)?;
        #[cfg(test)]
        return Ok(rendered);
    }
    Ok(AppliedBoundary::default())
}

#[cfg(all(feature = "enforce", unix, any(target_os = "macos", test)))]
fn seatbelt_boundary_inputs(
    workspace: &Path,
    writable: &[PathBuf],
) -> (Vec<(PathBuf, bool)>, Vec<PathBuf>) {
    // Parent rename protection must use the same canonical roots as the
    // kernel grants, including custom roots spelled with symlinks or `..`.
    let canonical_roots: Vec<_> = writable.iter().map(|path| canonical_path(path)).collect();
    // A narrower grant must not shorten ancestor protection when a broader
    // grant also permits relocating its parent. Keep the broadest roots.
    let mut roots: Vec<_> = canonical_roots
        .iter()
        .filter(|root| {
            !canonical_roots
                .iter()
                .any(|other| other != *root && root.starts_with(other))
        })
        .cloned()
        .collect();
    roots.sort();
    roots.dedup();
    let canonical = canonical_path(workspace);
    let mut entries = vec![(workspace.to_path_buf(), true)];
    if canonical != workspace {
        entries.push((canonical, true));
    }
    (entries, roots)
}

#[cfg(target_os = "linux")]
pub(crate) fn boundary_path(
    name: &ProfileName,
    workspace: &Path,
    config: &SandboxConfig,
) -> Option<PathBuf> {
    name.denies_workspace_write(config)
        .then(|| canonical_path(workspace))
}

/// Pin ancestors before other mounts, so the workspace cannot be relocated through a parent.
#[cfg(target_os = "linux")]
pub(crate) fn append_ancestor_binds(cmd: &mut std::process::Command, workspace: &Path) {
    let ancestors: Vec<_> = workspace
        .ancestors()
        .skip(1)
        .filter(|p| p.parent().is_some())
        .collect();
    for ancestor in ancestors.into_iter().rev() {
        cmd.arg("--bind").arg(ancestor).arg(ancestor);
    }
}

/// Run after every writable bind, including /dev and /proc, so none can reopen the tree.
#[cfg(target_os = "linux")]
pub(crate) fn append_readonly_bind(cmd: &mut std::process::Command, workspace: &Path) {
    cmd.arg("--ro-bind").arg(workspace).arg(workspace);
}

#[cfg(all(feature = "enforce", target_os = "linux"))]
pub(crate) fn verify_boundary(
    name: &ProfileName,
    workspace: &Path,
    config: &SandboxConfig,
) -> anyhow::Result<()> {
    if name.denies_workspace_write(config) {
        crate::hook_write_deny::ensure_namespace_lockdown().map_err(anyhow::Error::msg)?;
        let workspace = dunce::canonicalize(workspace)?;
        anyhow::ensure!(
            crate::hook_write_deny::path_is_effectively_readonly(&workspace)?,
            "workspace_write=false requires a verified read-only launch-folder mount"
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "workspace_write_tests.rs"]
mod tests;
