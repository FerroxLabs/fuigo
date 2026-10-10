//! Fuigo-owned hook write-deny: plan, identity revalidation, and post-reexec checks.
//! Namespace lockdown is in [`crate::child_net`].

use std::path::Path;
use std::path::PathBuf;

use fuigo_config::{
    GlobalHookSource, missing_configured_sources, resolve_global_hook_sources,
    resolve_trust_boundary_sources,
};

#[cfg(unix)]
use fuigo_config::validated_hook_json_files_for_sources;
#[cfg(target_os = "linux")]
use fuigo_config::{ensure_fuigo_hook_slots, unique_ancestors_rootward};

#[cfg(target_os = "linux")]
use crate::git_write_deny::{GitPathKind, GitProtectedPath, canonical_path, is_within};
use crate::paths::fuigo_home;
use crate::profiles::ProfileName;

pub fn profile_enforces_hook_write_deny(profile: &ProfileName) -> bool {
    !matches!(profile, ProfileName::Devbox | ProfileName::Off)
}

#[derive(Debug, thiserror::Error)]
pub enum HookWriteDenyError {
    #[error("{0}")]
    Resolve(String),
    #[error(
        "configured absolute hooks-paths target(s) do not exist: {0}. \
             Create them outside the sandbox or remove them from hooks-paths."
    )]
    MissingConfigured(String),
    #[cfg(target_os = "linux")]
    #[error("required hook write-deny path is not effectively read-only: {path}")]
    NotReadOnly { path: PathBuf },
    #[error("cannot verify hook write-deny path {path}: {detail}")]
    VerifyIo { path: PathBuf, detail: String },
    #[cfg(any(target_os = "linux", all(unix, test)))]
    #[error("hook write-deny path identity changed before apply (possible rename race): {path}")]
    IdentityChanged { path: PathBuf },
    #[cfg(any(target_os = "linux", all(unix, test)))]
    #[error("hook write-deny path is a symlink (retargetable): {path}")]
    Symlink { path: PathBuf },
    #[error(
        "protected regular file has hard-link aliases (st_nlink={nlink}): {path}; \
         refuse sandbox rather than leave a writable alias"
    )]
    HardLink { path: PathBuf, nlink: u64 },
    #[cfg(target_os = "linux")]
    #[error("hook directory JSON snapshot changed before apply: {dir}")]
    JsonSnapshotChanged { dir: PathBuf },
    #[cfg(target_os = "linux")]
    #[error(
        "git or home write-deny path is reached through a symlink inside a writable root: \
         {path}; the Linux sandbox cannot pin a symlink, so it refuses rather than leave it \
         re-pointable"
    )]
    GitSymlink { path: PathBuf },
    #[cfg(target_os = "linux")]
    #[error(
        "git hook {path} is named by a core.hooksPath (or an init.templateDir) that holds a \
         writable root and does not exist; the Linux sandbox can only protect existing files \
         there. Point the setting at a dedicated directory or create the file outside the sandbox"
    )]
    GitHookMissing { path: PathBuf },
    #[cfg(target_os = "linux")]
    #[error("required git or home write-deny path is missing inside bwrap: {path}")]
    GitMissing { path: PathBuf },
}

impl From<fuigo_config::GlobalHookSourceError> for HookWriteDenyError {
    fn from(e: fuigo_config::GlobalHookSourceError) -> Self {
        Self::Resolve(e.to_string())
    }
}

#[cfg(any(target_os = "linux", all(unix, test)))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathIdentity {
    pub path: PathBuf,
    pub dev: u64,
    pub ino: u64,
    pub is_dir: bool,
    /// Regular files must stay `1` (no hard-link aliases).
    pub nlink: u64,
}

/// Captures identity without following symlinks; regular files require `st_nlink == 1`.
#[cfg(any(target_os = "linux", all(unix, test)))]
pub fn capture_path_identity(path: &Path) -> Result<PathIdentity, HookWriteDenyError> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path).map_err(|e| HookWriteDenyError::VerifyIo {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;
    if meta.file_type().is_symlink() {
        return Err(HookWriteDenyError::Symlink {
            path: path.to_path_buf(),
        });
    }
    let is_dir = meta.file_type().is_dir();
    let nlink = meta.nlink();
    if !is_dir && nlink != 1 {
        return Err(HookWriteDenyError::HardLink {
            path: path.to_path_buf(),
            nlink,
        });
    }
    Ok(PathIdentity {
        path: path.to_path_buf(),
        dev: meta.dev(),
        ino: meta.ino(),
        is_dir,
        nlink,
    })
}

#[cfg(any(target_os = "linux", all(unix, test)))]
pub fn revalidate_path_identity(id: &PathIdentity) -> Result<(), HookWriteDenyError> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(&id.path).map_err(|e| HookWriteDenyError::VerifyIo {
        path: id.path.clone(),
        detail: e.to_string(),
    })?;
    if meta.file_type().is_symlink() {
        return Err(HookWriteDenyError::Symlink {
            path: id.path.clone(),
        });
    }
    let is_dir = meta.file_type().is_dir();
    let nlink = meta.nlink();
    if !is_dir && nlink != 1 {
        return Err(HookWriteDenyError::HardLink {
            path: id.path.clone(),
            nlink,
        });
    }
    if meta.dev() != id.dev || meta.ino() != id.ino || is_dir != id.is_dir || nlink != id.nlink {
        return Err(HookWriteDenyError::IdentityChanged {
            path: id.path.clone(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn reject_hardlinked_files(sources: &[GlobalHookSource]) -> Result<(), HookWriteDenyError> {
    use std::os::unix::fs::MetadataExt;
    use fuigo_config::GlobalHookSourceKind;
    for s in sources {
        let is_file_slot = matches!(
            s.kind,
            GlobalHookSourceKind::RegistryFile
                | GlobalHookSourceKind::ConfiguredSource
                | GlobalHookSourceKind::TrustBoundaryFile
        );
        if !is_file_slot || !s.path.exists() || s.path.is_dir() {
            continue;
        }
        let meta =
            std::fs::symlink_metadata(&s.path).map_err(|e| HookWriteDenyError::VerifyIo {
                path: s.path.clone(),
                detail: e.to_string(),
            })?;
        if meta.file_type().is_file() && meta.nlink() != 1 {
            return Err(HookWriteDenyError::HardLink {
                path: s.path.clone(),
                nlink: meta.nlink(),
            });
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_hardlinked_files(_sources: &[GlobalHookSource]) -> Result<(), HookWriteDenyError> {
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct DirJsonSnapshot {
    pub dir: PathBuf,
    pub files: Vec<PathIdentity>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct HookWriteDenyBwrapPlan {
    pub ancestor_rw_binds: Vec<PathBuf>,
    pub leaves: Vec<PathIdentity>,
    pub dir_json_snapshots: Vec<DirJsonSnapshot>,
    /// Tool directories bound read-only as a whole ([`GitPathKind::PinnedDir`]), before
    /// [`Self::rebinds`] and the leaves.
    pub pinned: Vec<PathIdentity>,
    /// Children of a pinned directory bound writable again on top of it; never a protected
    /// name (their identity is checked without the one-link rule: they stay writable).
    pub rebinds: Vec<PathIdentity>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub enum HookWriteDenyPrepare {
    NotRequired,
    Plan(HookWriteDenyBwrapPlan),
}

pub fn resolve_hook_write_deny_snapshot() -> Result<Vec<GlobalHookSource>, HookWriteDenyError> {
    let fuigo = fuigo_home();
    let resolved =
        resolve_global_hook_sources(Some(fuigo.as_path()), /* reject_symlinks */ true)?;
    if let Some(e) = resolved.configured_error {
        return Err(HookWriteDenyError::Resolve(e.to_string()));
    }
    let missing = missing_configured_sources(&resolved.sources);
    if !missing.is_empty() {
        return Err(HookWriteDenyError::MissingConfigured(
            missing
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    let mut sources = resolved.sources;
    sources.extend(resolve_trust_boundary_sources(fuigo.as_path())?);
    reject_hardlinked_files(&sources)?;
    #[cfg(unix)]
    {
        validated_hook_json_files_for_sources(&sources)?;
    }
    Ok(sources)
}

#[cfg(target_os = "linux")]
pub fn prepare_hook_write_deny(
    profile: &ProfileName,
) -> Result<HookWriteDenyPrepare, HookWriteDenyError> {
    if !profile_enforces_hook_write_deny(profile) {
        return Ok(HookWriteDenyPrepare::NotRequired);
    }
    let fuigo = fuigo_home();
    ensure_fuigo_hook_slots(fuigo.as_path())?;
    let sources = resolve_hook_write_deny_snapshot()?;
    let plan = build_bwrap_plan(&sources)?;
    Ok(HookWriteDenyPrepare::Plan(plan))
}

pub fn profile_hook_write_deny(profile: &ProfileName) -> anyhow::Result<Vec<GlobalHookSource>> {
    if !profile_enforces_hook_write_deny(profile) {
        return Ok(Vec::new());
    }
    resolve_hook_write_deny_snapshot().map_err(|e| anyhow::anyhow!("{e}"))
}

/// Returns the top-level source paths plus the validated hook JSON files directly under each directory source.
#[cfg(target_os = "linux")]
pub fn enforcement_leaf_paths(
    sources: &[GlobalHookSource],
) -> Result<Vec<PathBuf>, HookWriteDenyError> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for s in sources {
        if seen.insert(s.path.clone()) {
            out.push(s.path.clone());
        }
    }
    for f in validated_hook_json_files_for_sources(sources)? {
        if seen.insert(f.clone()) {
            out.push(f);
        }
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn capture_dir_json_snapshot(dir: &Path) -> Result<DirJsonSnapshot, HookWriteDenyError> {
    use fuigo_config::{list_direct_hook_json_files, validate_direct_hook_json_file};
    let listed = list_direct_hook_json_files(dir).map_err(|e| HookWriteDenyError::VerifyIo {
        path: dir.to_path_buf(),
        detail: e.to_string(),
    })?;
    let mut files = Vec::new();
    for f in listed {
        validate_direct_hook_json_file(&f)?;
        files.push(capture_path_identity(&f)?);
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(DirJsonSnapshot {
        dir: dir.to_path_buf(),
        files,
    })
}

#[cfg(target_os = "linux")]
pub fn build_bwrap_plan(
    sources: &[GlobalHookSource],
) -> Result<HookWriteDenyBwrapPlan, HookWriteDenyError> {
    let mut leaves = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut dir_json_snapshots = Vec::new();

    for src in sources {
        if !src.path.exists() {
            return Err(HookWriteDenyError::Resolve(format!(
                "required hook write-deny path is missing: {}",
                src.path.display()
            )));
        }
        if seen.insert(src.path.clone()) {
            leaves.push(capture_path_identity(&src.path)?);
        }
        if src.is_dir() && src.path.is_dir() {
            let snap = capture_dir_json_snapshot(&src.path)?;
            for f in &snap.files {
                if seen.insert(f.path.clone()) {
                    leaves.push(f.clone());
                }
            }
            dir_json_snapshots.push(snap);
        }
    }

    let leaf_paths: Vec<PathBuf> = leaves.iter().map(|l| l.path.clone()).collect();
    let ancestor_rw_binds = unique_ancestors_rootward(sources)
        .into_iter()
        .filter(|a| !leaf_paths.iter().any(|l| l == a))
        .collect();
    Ok(HookWriteDenyBwrapPlan {
        ancestor_rw_binds,
        leaves,
        dir_json_snapshots,
        pinned: Vec::new(),
        rebinds: Vec::new(),
    })
}

/// The git write-deny leaves the Linux bwrap plan binds read-only: each entry's canonical path
/// inside a writable root (outside them Landlock already denies the write), as `(path, kind)`.
/// A link node inside a writable root refuses: bwrap cannot pin a symlink.
#[cfg(target_os = "linux")]
pub(crate) fn git_bind_targets(
    entries: &[GitProtectedPath],
    write_roots: &[PathBuf],
) -> Result<Vec<(PathBuf, GitPathKind)>, HookWriteDenyError> {
    let roots: Vec<PathBuf> = write_roots.iter().map(|root| canonical_path(root)).collect();
    let within = |path: &Path| roots.iter().any(|root| is_within(path, root));
    // A link inside a tree bound read-only cannot be re-pointed (a symlinked hook in `hooks/`)
    let trees: Vec<PathBuf> = entries
        .iter()
        .filter(|entry| matches!(entry.kind, GitPathKind::Dir | GitPathKind::PinnedDir))
        .map(|entry| canonical_path(&entry.path))
        .filter(|tree| within(tree))
        .collect();
    let mut out: Vec<(PathBuf, GitPathKind)> = Vec::new();
    for entry in entries {
        // Kept writable under a pin, never bound read-only (see `add_git_leaves_to_plan`)
        if matches!(
            entry.kind,
            GitPathKind::CacheDir | GitPathKind::CacheFile | GitPathKind::MissingAncestor
        ) {
            continue;
        }
        if entry.kind == GitPathKind::LinkNode {
            // Spelled `<canonical parent>/<name>`: the node a command would re-point
            let pinned = trees
                .iter()
                .any(|tree| entry.path != *tree && is_within(&entry.path, tree));
            if within(&entry.path) && !pinned {
                return Err(HookWriteDenyError::GitSymlink {
                    path: entry.path.clone(),
                });
            }
            continue;
        }
        let canonical = canonical_path(&entry.path);
        if !within(&canonical) || out.iter().any(|(known, _)| known == &canonical) {
            continue;
        }
        // A link that never resolves (a loop) under a tree bound read-only names no writable
        // file and cannot be re-pointed: that bind already covers it
        let unresolved = std::fs::symlink_metadata(&canonical)
            .is_ok_and(|meta| meta.file_type().is_symlink());
        if unresolved && trees.iter().any(|tree| canonical != *tree && is_within(&canonical, tree)) {
            continue;
        }
        out.push((canonical, entry.kind));
    }
    Ok(out)
}

/// Adds the git write-deny leaves to the hook plan: each target is made to exist (git's own
/// layout: an empty `hooks/` or `info/`, an empty config file) so it can be bound read-only,
/// its identity captured, and its ancestors pinned as mount points so no rename swaps it out.
#[cfg(target_os = "linux")]
pub fn add_git_leaves_to_plan(
    plan: &mut HookWriteDenyBwrapPlan,
    entries: &[GitProtectedPath],
    write_roots: &[PathBuf],
) -> Result<(), HookWriteDenyError> {
    let mut added = Vec::new();
    let targets = git_bind_targets(entries, write_roots)?;
    // Every missing target is made first: creating one in a pinned directory changes its link
    // count, which the pin's identity records
    let mut leaves = Vec::new();
    for (path, kind) in &targets {
        if *kind != GitPathKind::PinnedDir && ensure_git_target(path, *kind)? {
            leaves.push(path.clone());
        }
    }
    // Every pin and its caches are made before any identity is captured: making a nested pin
    // changes its parent pin's link count
    let mut pins = Vec::new();
    for (path, kind) in &targets {
        if *kind == GitPathKind::PinnedDir && prepare_pinned_dir(path, entries)? {
            pins.push(path.clone());
        }
    }
    for path in pins {
        if add_pinned_dir(plan, &path, entries, &targets)? {
            added.push(path);
        }
    }
    for path in leaves {
        if plan.leaves.iter().any(|leaf| leaf.path == path) {
            continue;
        }
        plan.leaves.push(capture_path_identity(&path)?);
        added.push(path);
    }
    // The kind is irrelevant to the ancestor walk; only the path is read
    let as_sources: Vec<GlobalHookSource> = added
        .iter()
        .map(|path| GlobalHookSource {
            path: path.clone(),
            kind: fuigo_config::GlobalHookSourceKind::ConfiguredSource,
        })
        .collect();
    for anc in unique_ancestors_rootward(&as_sources) {
        if !plan.ancestor_rw_binds.contains(&anc) {
            plan.ancestor_rw_binds.push(anc);
        }
    }
    let leaf_paths: Vec<PathBuf> = plan
        .leaves
        .iter()
        .chain(&plan.pinned)
        .map(|l| l.path.clone())
        .collect();
    plan.ancestor_rw_binds.retain(|a| !leaf_paths.contains(a));
    plan.ancestor_rw_binds.sort_by_key(|p| p.components().count());
    Ok(())
}

/// Makes a pinned tool directory and its caches exist (a grant the profile creates at apply may
/// not exist yet; cargo's `registry/` and lock files, so a first build can use them). `false`
/// when it is not a directory.
#[cfg(target_os = "linux")]
fn prepare_pinned_dir(dir: &Path, entries: &[GitProtectedPath]) -> Result<bool, HookWriteDenyError> {
    let io = |path: &Path, e: std::io::Error| HookWriteDenyError::VerifyIo {
        path: path.to_path_buf(),
        detail: e.to_string(),
    };
    if std::fs::symlink_metadata(dir).is_err() {
        std::fs::create_dir_all(dir).map_err(|e| io(dir, e))?;
    }
    if !std::fs::symlink_metadata(dir).is_ok_and(|meta| meta.file_type().is_dir()) {
        return Ok(false);
    }
    for entry in entries {
        let cache = canonical_path(&entry.path);
        if cache.parent() != Some(dir) || std::fs::symlink_metadata(&cache).is_ok() {
            continue;
        }
        match entry.kind {
            GitPathKind::CacheDir => std::fs::create_dir(&cache).map_err(|e| io(&cache, e))?,
            GitPathKind::CacheFile => {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o644)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&cache)
                    .map_err(|e| io(&cache, e))?;
            }
            _ => {}
        }
    }
    Ok(true)
}

/// Pins a prepared tool directory: bound read-only, and each existing child that is neither a
/// protected target nor holds one is bound writable again. A symlinked child is not re-bound: in
/// a read-only directory it cannot be re-pointed, and what it leads to keeps its own access.
#[cfg(target_os = "linux")]
fn add_pinned_dir(
    plan: &mut HookWriteDenyBwrapPlan,
    dir: &Path,
    entries: &[GitProtectedPath],
    targets: &[(PathBuf, GitPathKind)],
) -> Result<bool, HookWriteDenyError> {
    let io = |path: &Path, e: std::io::Error| HookWriteDenyError::VerifyIo {
        path: path.to_path_buf(),
        detail: e.to_string(),
    };
    if plan.pinned.iter().any(|pin| pin.path == dir) {
        return Ok(false);
    }
    plan.pinned.push(capture_path_identity(dir)?);
    // A child stays read-only when it is protected, lies in a protected tree, or holds anything
    // protected: a target, a link node on the way to one (a re-bound parent would let it be
    // re-pointed), or a nested pin (whose own children are re-bound after every pin)
    let protected = |child: &Path| {
        entries.iter().any(|entry| {
            let at = match entry.kind {
                GitPathKind::CacheDir | GitPathKind::CacheFile | GitPathKind::MissingAncestor => {
                    return false;
                }
                GitPathKind::LinkNode => entry.path.clone(),
                _ => canonical_path(&entry.path),
            };
            if at.as_path() == dir {
                return false;
            }
            let covers = entry.kind != GitPathKind::PinnedDir
                && entry.kind != GitPathKind::LinkNode
                && entry.kind.is_dir()
                && is_within(child, &at);
            at == child || covers || is_within(&at, child)
        }) || targets.iter().any(|(target, _)| target.as_path() != dir && target == child)
    };
    let children = std::fs::read_dir(dir).map_err(|e| io(dir, e))?;
    let mut rebinds = Vec::new();
    for child in children {
        let child = child.map_err(|e| io(dir, e))?.path();
        let meta = std::fs::symlink_metadata(&child).map_err(|e| io(&child, e))?;
        if meta.file_type().is_symlink() || protected(&child) {
            continue;
        }
        rebinds.push(capture_rebind_identity(&child)?);
    }
    rebinds.sort_by(|a, b| a.path.cmp(&b.path));
    plan.rebinds.extend(rebinds);
    Ok(true)
}

/// A re-bound child's identity: not a symlink; any link count (it stays writable).
#[cfg(target_os = "linux")]
fn capture_rebind_identity(path: &Path) -> Result<PathIdentity, HookWriteDenyError> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path).map_err(|e| HookWriteDenyError::VerifyIo {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;
    if meta.file_type().is_symlink() {
        return Err(HookWriteDenyError::Symlink {
            path: path.to_path_buf(),
        });
    }
    Ok(PathIdentity {
        path: path.to_path_buf(),
        dev: meta.dev(),
        ino: meta.ino(),
        is_dir: meta.file_type().is_dir(),
        nlink: meta.nlink(),
    })
}

/// Makes a missing git target exist; `false` when it is left alone (an optional file).
#[cfg(target_os = "linux")]
fn ensure_git_target(path: &Path, kind: GitPathKind) -> Result<bool, HookWriteDenyError> {
    let io = |e: std::io::Error| HookWriteDenyError::VerifyIo {
        path: path.to_path_buf(),
        detail: e.to_string(),
    };
    match std::fs::symlink_metadata(path) {
        Ok(_) => return Ok(true),
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(io(e)),
        Err(_) => {}
    }
    match kind {
        GitPathKind::Dir => std::fs::create_dir_all(path).map_err(io)?,
        GitPathKind::File => {
            use std::os::unix::fs::OpenOptionsExt;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(io)?;
            }
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
                .map_err(io)?;
        }
        GitPathKind::OptionalFile
        | GitPathKind::OptionalDir
        | GitPathKind::PinnedDir
        | GitPathKind::CacheDir
        | GitPathKind::CacheFile
        | GitPathKind::MissingAncestor => return Ok(false),
        GitPathKind::HookFile => {
            return Err(HookWriteDenyError::GitHookMissing {
                path: path.to_path_buf(),
            });
        }
        GitPathKind::LinkNode => return Ok(false),
    }
    Ok(true)
}

/// Inside bwrap: every git write-deny target the plan bound is a read-only mount. A required
/// target that is missing fails too (a forged `__FUIGO_INSIDE_BWRAP` never ran the plan).
#[cfg(target_os = "linux")]
pub fn verify_git_write_deny_enforced(
    profile: &ProfileName,
    workspace: &Path,
) -> Result<(), String> {
    if !crate::requires_hook_write_deny(profile, workspace) {
        return Ok(());
    }
    ensure_namespace_lockdown()?;
    let config = crate::profiles::load_sandbox_config(workspace);
    let resolved = profile
        .resolve_profile(workspace, &config)
        .map_err(|e| e.to_string())?;
    let targets =
        git_bind_targets(&resolved.git_write_deny, &resolved.read_write).map_err(|e| e.to_string())?;
    let mut paths = Vec::new();
    for (path, kind) in targets {
        if std::fs::symlink_metadata(&path).is_err() {
            if kind.is_optional() {
                continue;
            }
            return Err(HookWriteDenyError::GitMissing { path }.to_string());
        }
        paths.push(path);
    }
    verify_required_hook_write_denies(&paths).map_err(|e| e.to_string())
}

#[cfg(not(target_os = "linux"))]
pub fn verify_git_write_deny_enforced(
    _profile: &ProfileName,
    _workspace: &Path,
) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn revalidate_plan(plan: &HookWriteDenyBwrapPlan) -> Result<(), HookWriteDenyError> {
    for leaf in plan.leaves.iter().chain(&plan.pinned) {
        revalidate_path_identity(leaf)?;
    }
    for rebind in &plan.rebinds {
        let changed = || HookWriteDenyError::IdentityChanged {
            path: rebind.path.clone(),
        };
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(&rebind.path).map_err(|_| changed())?;
        if meta.file_type().is_symlink()
            || meta.dev() != rebind.dev
            || meta.ino() != rebind.ino
            || meta.file_type().is_dir() != rebind.is_dir
        {
            return Err(changed());
        }
    }
    for snap in &plan.dir_json_snapshots {
        let now = capture_dir_json_snapshot(&snap.dir)?;
        if now.files.len() != snap.files.len() {
            return Err(HookWriteDenyError::JsonSnapshotChanged {
                dir: snap.dir.clone(),
            });
        }
        for (a, b) in snap.files.iter().zip(now.files.iter()) {
            if a.path != b.path || a.dev != b.dev || a.ino != b.ino || a.nlink != b.nlink {
                return Err(HookWriteDenyError::JsonSnapshotChanged {
                    dir: snap.dir.clone(),
                });
            }
        }
    }
    for anc in &plan.ancestor_rw_binds {
        let meta = std::fs::symlink_metadata(anc).map_err(|e| HookWriteDenyError::VerifyIo {
            path: anc.clone(),
            detail: e.to_string(),
        })?;
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            return Err(HookWriteDenyError::IdentityChanged { path: anc.clone() });
        }
        if !anc.exists() {
            return Err(HookWriteDenyError::Resolve(format!(
                "required ancestor for hook write-deny is missing: {}",
                anc.display()
            )));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn append_hook_plan_binds(
    cmd: &mut std::process::Command,
    plan: &HookWriteDenyBwrapPlan,
) -> Result<(), HookWriteDenyError> {
    revalidate_plan(plan)?;
    for anc in &plan.ancestor_rw_binds {
        cmd.arg("--bind").arg(anc).arg(anc);
    }
    // A pin first, then its writable children on top, then every leaf (one inside a re-bound
    // child stays read-only)
    for pin in &plan.pinned {
        cmd.arg("--ro-bind").arg(&pin.path).arg(&pin.path);
    }
    for rebind in &plan.rebinds {
        cmd.arg("--bind").arg(&rebind.path).arg(&rebind.path);
    }
    for leaf in &plan.leaves {
        cmd.arg("--ro-bind").arg(&leaf.path).arg(&leaf.path);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn path_is_effectively_readonly(path: &Path) -> Result<bool, HookWriteDenyError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| HookWriteDenyError::VerifyIo {
            path: path.to_path_buf(),
            detail: "path contains interior NUL".into(),
        })?;
    let mut buf: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut buf) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(HookWriteDenyError::VerifyIo {
            path: path.to_path_buf(),
            detail: err.to_string(),
        });
    }
    Ok(buf.f_flag & libc::ST_RDONLY != 0)
}

#[cfg(target_os = "linux")]
pub fn verify_required_hook_write_denies(paths: &[PathBuf]) -> Result<(), HookWriteDenyError> {
    for path in paths {
        if !path_is_effectively_readonly(path)? {
            return Err(HookWriteDenyError::NotReadOnly { path: path.clone() });
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn ensure_namespace_lockdown() -> Result<(), String> {
    use std::sync::OnceLock;
    static INSTALLED: OnceLock<Result<(), String>> = OnceLock::new();
    INSTALLED
        .get_or_init(|| {
            // SAFETY: after bwrap re-exec / at apply; TSYNC covers all threads.
            unsafe { crate::child_net::install_namespace_lockdown_filter() }
                .map_err(|e| format!("namespace lockdown seccomp failed: {e}"))
        })
        .clone()
}

#[cfg(target_os = "linux")]
pub fn verify_hook_write_deny_enforced() -> Result<(), String> {
    ensure_namespace_lockdown()?;
    let sources = resolve_hook_write_deny_snapshot().map_err(|e| e.to_string())?;
    let paths = enforcement_leaf_paths(&sources).map_err(|e| e.to_string())?;
    verify_required_hook_write_denies(&paths).map_err(|e| e.to_string())
}

#[cfg(not(target_os = "linux"))]
pub fn verify_hook_write_deny_enforced() -> Result<(), String> {
    Ok(())
}

#[cfg(all(feature = "enforce", target_os = "linux"))]
pub fn maybe_install_namespace_lockdown_inside_bwrap(
    profile: &ProfileName,
    workspace: &Path,
) -> Result<(), String> {
    let protects_mounts = crate::requires_hook_write_deny(profile, workspace)
        || crate::requires_read_deny(profile, workspace)
        || crate::requires_data_write_deny(profile, workspace);
    if protects_mounts && crate::is_inside_bwrap() {
        ensure_namespace_lockdown()?;
    }
    Ok(())
}

#[cfg(all(feature = "enforce", unix, not(target_os = "linux")))]
pub fn maybe_install_namespace_lockdown_inside_bwrap(
    _profile: &ProfileName,
    _workspace: &Path,
) -> Result<(), String> {
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "hook_write_deny_tests.rs"]
mod tests;
