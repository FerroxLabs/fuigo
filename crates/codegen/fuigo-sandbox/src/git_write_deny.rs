//! Git write-deny: the git files that run or reconfigure code on the user's next git command,
//! which a sandboxed agent must not be able to plant (P158, ported from upstream's protected
//! floor, `sandbox/src/command/{protected,git_config}.rs`, adapted to Fuigo's process sandbox).
//!
//! Protected, as their write-deny: the workspace repository's `.git/{hooks/, config,
//! config.worktree}` and the `commondir` pointer a git directory must not grow, the same
//! entries in every submodule git directory present under `.git/modules` with each submodule
//! checkout's `.git` pointer, the `.git` file and pointer files of a workspace that is a linked
//! worktree (or a submodule checkout) and the entries of the git directories they name, the tree
//! every `core.hooksPath` names (read as git reads it: `config` then `config.worktree`, includes
//! followed in place, the last assignment winning; a hook in it that is a symlink is protected
//! where it leads), and the system and global git configs where git looks for them
//! (`GIT_CONFIG_SYSTEM` or the well-known system files; `GIT_CONFIG_GLOBAL`, else
//! `$XDG_CONFIG_HOME/git/config` or `~/.config/git/config`, and `~/.gitconfig`) with every file
//! they include, and the template directory `git init` and `git clone` copy into each new
//! repository (`GIT_TEMPLATE_DIR`, and every `init.templateDir` those configs name, read as
//! `core.hooksPath` is). Fuigo's own trust-boundary files and hook sources are protected by
//! [`crate::hook_write_deny`].
//!
//! Symlinks are followed as git follows them (a `..` after a link resolves where the kernel puts
//! it), and a protected path is protected in each spelling a command could reach it by: as named,
//! its canonical path, and each link on the way ([`GitPathKind::LinkNode`]). What git would read
//! and this scan cannot read as git reads it ([`GitMetadataUnread`]) refuses the sandbox: the
//! hooks tree such a file names is unknown.
//!
//! A protected file or a file in a protected tree with a hard-link alias refuses the sandbox too
//! (a write through the alias would change it). On Linux a protected path reached through a
//! symlink that lies inside a writable root refuses, unless the link itself lies inside a tree
//! bound read-only (a symlinked hook in `hooks/`); a dangling hook link refuses there as well.
//!
//! Accepted limits (as upstream, plus Fuigo's for a sandbox with no grant cards): only a `.git`
//! directly in the workspace is covered, so a workspace with no `.git` at start (a new project,
//! or a subdirectory of a repository whose `.git` lies above it, outside the writable roots) gets
//! no repository entries and `git init` stays possible; a repository nested in the workspace or
//! created during the session (`git init`, `git clone`, a submodule added after start) is not
//! covered; the repository's other linked worktrees are not covered (Fuigo creates and removes its
//! own worktrees); on Linux a missing pointer file (`commondir`) cannot be bound, so only macOS
//! denies creating one; `info/` stays writable (see [`GIT_DIR_PROTECTED_ENTRIES`]); `.gitmodules`
//! stays writable: git refuses a command (`update = !cmd`) from it and copies only a non-command
//! update method into the protected `.git/config`, and `git mv`/`git rm` of a submodule edit it.

use std::ffi::OsString;
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

/// Largest `.git` file, pointer file or git config file (an included one too) read. A larger one
/// is [`GitMetadataUnread::TooLarge`], never a prefix.
pub(crate) const GIT_METADATA_READ_LIMIT: u64 = 1024 * 1024;

/// The one global config git reads instead of the home files when set (empty: none).
pub(crate) const GIT_CONFIG_GLOBAL_ENV: &str = "GIT_CONFIG_GLOBAL";

/// Where git reads `git/config` from instead of `~/.config` when set and not empty.
pub(crate) const XDG_CONFIG_HOME_ENV: &str = "XDG_CONFIG_HOME";

/// Nesting bound on followed config includes.
pub(crate) const GIT_CONFIG_INCLUDE_DEPTH: usize = 10;

/// Config files read per resolution, so a file that includes itself cannot fan out.
const GIT_CONFIG_FILES_LIMIT: usize = 64;

/// Directories listed under `.git/modules` and `.git/worktrees`.
pub(crate) const GIT_DIRS_LIMIT: usize = 512;

/// Symlinks followed resolving one path (the kernel's bound), so a link loop ends.
const SYMLINK_HOPS: usize = 40;

/// The entries of a git directory that run or reconfigure code on the user's next git command.
/// `info/` (attributes, excludes) is left writable, unlike upstream: an attribute can only select
/// a driver the protected configs define, and Fuigo's own commit workflow seeds `info/exclude`.
/// `commondir` is denied as a pointer (never created; see [`required_if_present`]).
pub(crate) const GIT_DIR_PROTECTED_ENTRIES: &[&str] = &["hooks", "config", "config.worktree"];

/// The pointer files of a linked worktree's git directory.
const WORKTREE_POINTER_FILES: &[&str] = &["commondir", "gitdir"];

/// The per-worktree config git reads after `config` under `extensions.worktreeConfig`.
const WORKTREE_CONFIG: &str = "config.worktree";

/// The hooks git runs by name from a hooks directory (githooks(5)).
pub(crate) const GIT_HOOK_NAMES: &str = "applypatch-msg pre-applypatch post-applypatch pre-commit \
    pre-merge-commit prepare-commit-msg commit-msg post-commit pre-rebase post-checkout \
    post-merge pre-push pre-receive update proc-receive post-receive post-update \
    reference-transaction push-to-checkout pre-auto-gc post-rewrite sendemail-validate \
    fsmonitor-watchman post-index-change p4-changelist p4-prepare-changelist \
    p4-post-changelist p4-pre-submit";

/// What `git init` and `git clone` copy from a template directory and the new repository then
/// reads or runs: its `config` and the hooks (a tree holding a write root is narrowed to these).
pub(crate) const TEMPLATE_READ_BENEATH: &str = "config hooks/applypatch-msg \
    hooks/pre-applypatch hooks/post-applypatch hooks/pre-commit hooks/pre-merge-commit \
    hooks/prepare-commit-msg hooks/commit-msg hooks/post-commit hooks/pre-rebase \
    hooks/post-checkout hooks/post-merge hooks/pre-push hooks/pre-receive hooks/update \
    hooks/proc-receive hooks/post-receive hooks/post-update hooks/reference-transaction \
    hooks/push-to-checkout hooks/pre-auto-gc hooks/post-rewrite hooks/sendemail-validate \
    hooks/fsmonitor-watchman hooks/post-index-change hooks/p4-changelist \
    hooks/p4-prepare-changelist hooks/p4-post-changelist hooks/p4-pre-submit";

/// The template entries a new repository runs or reads as config once copied (`config.worktree`
/// under `extensions.worktreeConfig`, `commondir` as a pointer): followed when they are symlinks.
/// `info/` and `description` are not (see [`GIT_DIR_PROTECTED_ENTRIES`]).
const TEMPLATE_LINKED_ENTRIES: &[&str] = &["hooks", "config", "config.worktree", "commondir"];

/// How a protected path is denied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GitPathKind {
    /// A directory and everything beneath it (`hooks/`, `info/`, a `core.hooksPath` tree).
    Dir,
    /// A file git reads (a config, an include, a `.git` or pointer file).
    File,
    /// `config.worktree` where `extensions.worktreeConfig` is off: git does not read it, so on
    /// Linux a missing one is not created to be bound (macOS denies it as a file regardless).
    OptionalFile,
    /// A home tree that does not exist yet and must not be created (a tool tree an installer
    /// checks for, a macOS-only tree on Linux): macOS denies it as a tree, Linux leaves it
    /// unbound ([`crate::home_write_deny`]).
    OptionalDir,
    /// Linux only (macOS denies each protected name in it instead): a tool's own directory inside
    /// a writable root that holds a protected name not yet created (`~/.cargo` without
    /// `config`). Bound read-only so no name can be created in it, with each existing child that
    /// is not protected bound writable again on top ([`crate::home_write_deny`]).
    PinnedDir,
    /// A cache directory a [`GitPathKind::PinnedDir`] keeps writable, created when missing
    /// (`~/.cargo/registry`): never denied.
    CacheDir,
    /// A cache or lock file a [`GitPathKind::PinnedDir`] keeps writable, created empty when
    /// missing (`~/.cargo/.package-cache`): never denied.
    CacheFile,
    /// macOS only (Linux binds the leaves and refuses or pins instead): a directory on the way to a
    /// protected name that does not exist yet (`~/.cargo` for `~/.cargo/config`). Its creation and
    /// unlink are denied as a node, so a prepared directory holding the name cannot be renamed
    /// into place.
    MissingAncestor,
    /// A hook git runs by name beneath a `core.hooksPath` that holds the workspace, the home or a
    /// write root, where the whole tree cannot be denied.
    HookFile,
    /// A symlink on the way to a protected path: the link itself, never what it points to.
    LinkNode,
}

impl GitPathKind {
    pub fn is_dir(self) -> bool {
        matches!(
            self,
            GitPathKind::Dir
                | GitPathKind::OptionalDir
                | GitPathKind::PinnedDir
                | GitPathKind::CacheDir
        )
    }

    /// A path a macOS write-deny rule names: not a Linux-only pin or a cache kept writable.
    pub fn is_denied_by_name(self) -> bool {
        !matches!(
            self,
            GitPathKind::PinnedDir | GitPathKind::CacheDir | GitPathKind::CacheFile
        )
    }

    /// A missing target of this kind is neither created nor required on Linux.
    pub fn is_optional(self) -> bool {
        matches!(self, GitPathKind::OptionalFile | GitPathKind::OptionalDir)
    }
}

/// One protected git path.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GitProtectedPath {
    pub path: PathBuf,
    pub kind: GitPathKind,
}

/// A file or tree git reads that this scan could not read as git reads it.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GitMetadataUnread {
    #[error("{path} is larger than {limit} bytes")]
    TooLarge { path: PathBuf, limit: u64 },
    #[error("{path} cannot be read: {reason}")]
    Unreadable { path: PathBuf, reason: String },
    #[error("{path} names a path that is not UTF-8")]
    NotUtf8 { path: PathBuf },
    #[error("{path} is included deeper than {depth} levels or past the {files}th config file")]
    IncludesUnfollowed {
        path: PathBuf,
        depth: usize,
        files: usize,
    },
    #[error("{tree} holds more than {limit} directories")]
    GitDirsUnlisted { tree: PathBuf, limit: usize },
    #[error("{path} has a hard-link alias, a write to which would change what git runs")]
    HardLinked { path: PathBuf },
}

/// The environment git resolves its global config from, injected so the scan is testable.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct GitConfigEnv {
    pub config_global: Option<OsString>,
    pub xdg_config_home: Option<OsString>,
    /// The system configs git reads (`GIT_CONFIG_SYSTEM`, else the well-known ones present),
    /// empty under `GIT_CONFIG_NOSYSTEM`. Resolved by [`GitConfigEnv::from_host`]; empty in a
    /// test's default.
    pub system_configs: Vec<PathBuf>,
    /// A `GIT_CONFIG_SYSTEM` the scan cannot resolve (relative).
    pub system_unread: Option<GitMetadataUnread>,
    /// `GIT_TEMPLATE_DIR`, which git reads before `init.templateDir`.
    pub template_dir: Option<OsString>,
}

impl GitConfigEnv {
    /// This process's environment, which the user's own git inherits.
    pub(crate) fn from_host() -> GitConfigEnv {
        GitConfigEnv::from_lookup(|name| std::env::var_os(name))
    }

    pub(crate) fn from_lookup(lookup: impl Fn(&str) -> Option<OsString>) -> GitConfigEnv {
        let (system_configs, system_unread) = system_configs(
            lookup(GIT_CONFIG_SYSTEM_ENV),
            lookup(GIT_CONFIG_NOSYSTEM_ENV).is_some_and(|value| config_bool(value.to_str())),
            |path| std::fs::metadata(path).is_ok_and(|meta| meta.is_file()),
        );
        GitConfigEnv {
            config_global: lookup(GIT_CONFIG_GLOBAL_ENV),
            xdg_config_home: lookup(XDG_CONFIG_HOME_ENV),
            system_configs,
            system_unread,
            template_dir: lookup(GIT_TEMPLATE_DIR_ENV),
        }
    }

    /// The global config files git reads under this environment, and what could not be
    /// resolved (a relative value, read from each command's working directory).
    fn global_configs(&self, user_home: Option<&Path>) -> (Vec<PathBuf>, Option<GitMetadataUnread>) {
        let relative = |name: &str, value: &OsString| GitMetadataUnread::Unreadable {
            path: PathBuf::from(value),
            reason: format!(
                "{name} is a relative path, which git reads from each command's working directory"
            ),
        };
        if let Some(global) = &self.config_global {
            if global.is_empty() {
                return (Vec::new(), None);
            }
            let path = PathBuf::from(global);
            return if path.is_absolute() {
                (vec![path], None)
            } else {
                (Vec::new(), Some(relative(GIT_CONFIG_GLOBAL_ENV, global)))
            };
        }
        let mut configs = Vec::new();
        let mut unread = None;
        match self.xdg_config_home.as_ref().filter(|xdg| !xdg.is_empty()) {
            Some(xdg) if Path::new(xdg).is_absolute() => {
                configs.push(Path::new(xdg).join("git").join("config"));
            }
            Some(xdg) => unread = Some(relative(XDG_CONFIG_HOME_ENV, xdg)),
            None => configs.extend(user_home.map(|home| home.join(".config/git/config"))),
        }
        configs.extend(user_home.map(|home| home.join(".gitconfig")));
        (configs, unread)
    }
}

/// Where git's system config lives across the usual installs: the distribution's, Homebrew's
/// (Apple silicon and Intel) and Apple's command-line tools and Xcode.
const SYSTEM_CONFIG_CANDIDATES: &[&str] = &[
    "/etc/gitconfig",
    "/opt/homebrew/etc/gitconfig",
    "/usr/local/etc/gitconfig",
    "/Library/Developer/CommandLineTools/usr/share/git-core/gitconfig",
    "/Applications/Xcode.app/Contents/Developer/usr/share/git-core/gitconfig",
];

/// Git reads `GIT_CONFIG_SYSTEM` in place of its system config when set (empty: none).
pub(crate) const GIT_CONFIG_SYSTEM_ENV: &str = "GIT_CONFIG_SYSTEM";

/// The template directory `git init` and `git clone` copy from, read before `init.templateDir`.
pub(crate) const GIT_TEMPLATE_DIR_ENV: &str = "GIT_TEMPLATE_DIR";

/// Git skips its system config when this is true.
pub(crate) const GIT_CONFIG_NOSYSTEM_ENV: &str = "GIT_CONFIG_NOSYSTEM";

/// The system configs git reads: none under `GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_SYSTEM` alone when
/// set, else every well-known one present (which one an install reads is its build prefix).
fn system_configs(
    config_system: Option<OsString>,
    nosystem: bool,
    present: impl Fn(&Path) -> bool,
) -> (Vec<PathBuf>, Option<GitMetadataUnread>) {
    if nosystem {
        return (Vec::new(), None);
    }
    if let Some(value) = config_system {
        if value.is_empty() {
            return (Vec::new(), None);
        }
        let path = PathBuf::from(&value);
        return if path.is_absolute() {
            (vec![path], None)
        } else {
            (
                Vec::new(),
                Some(GitMetadataUnread::Unreadable {
                    path,
                    reason: format!(
                        "{GIT_CONFIG_SYSTEM_ENV} is a relative path, which git reads from each \
                         command's working directory"
                    ),
                }),
            )
        };
    }
    let configs = SYSTEM_CONFIG_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .filter(|path| present(path))
        .collect();
    (configs, None)
}

/// What [`git_entries_in`] derives.
#[derive(Debug, Default)]
pub(crate) struct GitEntries {
    pub protected: Vec<GitProtectedPath>,
    pub unread: Vec<GitMetadataUnread>,
}

/// `..` and `.` folded lexically (no filesystem access).
pub(crate) fn fold_dots(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// The canonical spelling of `path` as the kernel resolves it: its longest existing prefix
/// canonicalised (symlinks resolved before a following `..`, as the kernel does), the rest
/// appended and folded, so a path that does not exist yet is spelled as it will be seen.
pub(crate) fn canonical_path(path: &Path) -> PathBuf {
    canonical_path_within(path, SYMLINK_HOPS)
}

/// [`canonical_path`] with a bound on the dangling links followed, so a loop ends.
fn canonical_path_within(path: &Path, hops: usize) -> PathBuf {
    let components: Vec<Component<'_>> = path.components().collect();
    for split in (1..=components.len()).rev() {
        let prefix: PathBuf = components[..split].iter().collect();
        // A dangling link is followed to where a write through it lands
        if hops > 0
            && dunce::canonicalize(&prefix).is_err()
            && let Ok(target) = std::fs::read_link(&prefix)
        {
            let base = prefix.parent().unwrap_or(Path::new("/"));
            let mut next = base.join(target);
            for component in &components[split..] {
                next.push(component.as_os_str());
            }
            return canonical_path_within(&next, hops - 1);
        }
        if let Ok(real) = dunce::canonicalize(&prefix) {
            let mut out = real;
            for component in &components[split..] {
                match component {
                    Component::CurDir => {}
                    Component::ParentDir => {
                        out.pop();
                    }
                    other => out.push(other.as_os_str()),
                }
            }
            return out;
        }
    }
    fold_dots(path)
}

/// Whether `path` holds a `..`, which only the kernel can resolve past a symlink.
fn has_parent_dir(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

/// Whether `path` is `root` or lies beneath it, component-wise.
pub(crate) fn is_within(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}

/// Whether `entries` deny writing `path` (as spelled): a directory entry covers its tree, every
/// other entry exactly its own path.
#[cfg(test)]
pub(crate) fn denies(entries: &[GitProtectedPath], path: &Path) -> bool {
    entries.iter().any(|entry| {
        if entry.kind.is_dir() {
            is_within(path, &entry.path)
        } else {
            path == entry.path
        }
    })
}

/// The git entries of the workspace's repository (module doc).
pub(crate) fn git_entries_in(
    ws: &Path,
    user_home: Option<&Path>,
    write_roots: &[PathBuf],
    env: &GitConfigEnv,
) -> GitEntries {
    let mut scan = GitScan {
        user_home: user_home.map(Path::to_path_buf),
        ..GitScan::default()
    };
    let workspace = [ws.to_path_buf()];
    let dot_git = ws.join(".git");
    // The entry point itself: a link there would be re-pointed to other metadata
    scan.add_link_nodes(&dot_git);
    match std::fs::metadata(&dot_git) {
        Ok(meta) if meta.is_file() => {
            scan.protect(&dot_git, GitPathKind::File, "");
            if let Some(git_dir) = scan.pointer_target(&dot_git, ws, Some("gitdir: ")) {
                // A missing pointer (a submodule or `--separate-git-dir` checkout has none) is
                // denied where it can be, never created empty: git refuses an empty `commondir`
                for file in WORKTREE_POINTER_FILES {
                    let pointer = git_dir.join(file);
                    scan.protect(&pointer, required_if_present(&pointer), "");
                }
                let common = scan.pointer_target(&git_dir.join("commondir"), &git_dir, None);
                match common {
                    // A linked worktree: its own git directory holds only `config.worktree`
                    Some(common) => {
                        let enabled = scan.worktree_config_enabled(&common.join("config"));
                        scan.protect(
                            &git_dir.join(WORKTREE_CONFIG),
                            worktree_config_kind(enabled),
                            "",
                        );
                        scan.git_dir_entries(&common);
                        scan.hooks_path_entries(&common, &workspace, user_home);
                        scan.hooks_path_in(&git_dir.join(WORKTREE_CONFIG), &workspace, user_home);
                        scan.present_submodules(&git_dir, &workspace, user_home);
                        scan.present_submodules(&common, &workspace, user_home);
                    }
                    // A submodule or separate-git-dir checkout: the git directory is a whole one
                    None => {
                        scan.git_dir_entries(&git_dir);
                        scan.hooks_path_entries(&git_dir, &workspace, user_home);
                        scan.present_submodules(&git_dir, &workspace, user_home);
                    }
                }
            }
        }
        Ok(meta) if meta.is_dir() => {
            let git_dir = canonical_path(&dot_git);
            // An ordinary git directory has no `commondir`; `git_dir_entries` denies creating one
            // (macOS; Linux cannot bind a name that does not exist)
            scan.present_submodules(&git_dir, &workspace, user_home);
            scan.git_dir_entries(&git_dir);
            scan.hooks_path_entries(&git_dir, &workspace, user_home);
            // An existing `commondir` sends git to another directory for config and hooks
            if let Some(common) = scan.pointer_target(&git_dir.join("commondir"), &git_dir, None) {
                scan.git_dir_entries(&common);
                scan.hooks_path_entries(&common, &workspace, user_home);
                scan.present_submodules(&common, &workspace, user_home);
            }
        }
        // No repository at start: nothing of the workspace layout (accepted limit, module doc)
        _ => {}
    }
    // Git also honours a `core.hooksPath` in the system and global configs, in every checkout
    let mut inherited_anchors = workspace.to_vec();
    inherited_anchors.extend(scan.checkouts.iter().cloned());
    scan.unread.extend(env.system_unread.clone());
    for config in &env.system_configs {
        if let Some(kind) = file_dir_or_missing(config) {
            scan.protect(config, kind, "");
        }
        scan.hooks_path_in(config, &inherited_anchors, user_home);
    }
    // Git also honours a `core.hooksPath` in the user's global config
    let (global_configs, unresolved) = env.global_configs(user_home);
    scan.unread.extend(unresolved);
    for config in &global_configs {
        if let Some(kind) = file_dir_or_missing(config) {
            scan.protect(config, kind, "");
        }
        scan.hooks_path_in(config, &inherited_anchors, user_home);
    }
    // The template directory the environment names (empty: none)
    if let Some(value) = env.template_dir.as_ref().filter(|value| !value.is_empty()) {
        let dir = PathBuf::from(value);
        if dir.is_absolute() {
            scan.protect_template(&dir);
        } else {
            scan.unread.push(GitMetadataUnread::Unreadable {
                path: dir,
                reason: format!(
                    "{GIT_TEMPLATE_DIR_ENV} is a relative path, which git reads from each \
                     command's working directory"
                ),
            });
        }
    }
    let roots: Vec<PathBuf> = std::iter::once(ws)
        .chain(user_home)
        .chain(write_roots.iter().map(PathBuf::as_path))
        .map(canonical_path)
        .collect();
    let mut out = Vec::new();
    for (path, kind, beneath) in scan.paths {
        out.extend(narrowed(path, kind, beneath, &roots));
    }
    out.extend(scan.nodes.into_iter().map(|path| GitProtectedPath {
        path,
        kind: GitPathKind::LinkNode,
    }));
    out.sort();
    out.dedup();
    let mut unread = scan.unread;
    unread.extend(hard_linked(&out));
    GitEntries {
        protected: out,
        unread,
    }
}

/// `path` as a `kind` entry in each spelling a command could reach it by: as named (when that is
/// the kernel's spelling), its canonical path, and each symlink on the way as a link node. The
/// home write-deny ([`crate::home_write_deny`]) protects its entries through this.
pub(crate) fn protect_spellings(path: &Path, kind: GitPathKind) -> Vec<GitProtectedPath> {
    let mut scan = GitScan::default();
    scan.protect(path, kind, "");
    scan.paths
        .into_iter()
        .map(|(path, kind, _)| GitProtectedPath { path, kind })
        .chain(scan.nodes.into_iter().map(|path| GitProtectedPath {
            path,
            kind: GitPathKind::LinkNode,
        }))
        .collect()
}

/// A file git reads when it exists; one that does not is denied but never created.
fn required_if_present(path: &Path) -> GitPathKind {
    if std::fs::symlink_metadata(path).is_ok() {
        GitPathKind::File
    } else {
        GitPathKind::OptionalFile
    }
}

/// The kind a `core.hooksPath` target stands for: a directory or nothing yet is a tree, a regular
/// file a file; a device (`/dev/null`, git's way to disable hooks) is never protected.
fn hooks_tree_kind(path: &Path) -> Option<GitPathKind> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_dir() => Some(GitPathKind::Dir),
        Ok(meta) if meta.is_file() => Some(GitPathKind::File),
        Ok(_) => None,
        Err(_) => Some(GitPathKind::Dir),
    }
}

fn worktree_config_kind(enabled: bool) -> GitPathKind {
    if enabled {
        GitPathKind::File
    } else {
        GitPathKind::OptionalFile
    }
}

/// The kind a global config path stands for: a regular file or nothing yet is a file, a
/// directory a tree; a device (`/dev/null`, git's "no config") is never protected.
fn file_dir_or_missing(path: &Path) -> Option<GitPathKind> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_dir() => Some(GitPathKind::Dir),
        Ok(meta) if meta.is_file() => Some(GitPathKind::File),
        Ok(_) => None,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(GitPathKind::File),
        Err(_) => None,
    }
}

/// `path` as an entry, unless it is a tree at or above one of `roots` (or, outside them, leads
/// there): then only the files git reads or runs beneath it (`beneath`).
fn narrowed(
    path: PathBuf,
    kind: GitPathKind,
    beneath: &str,
    roots: &[PathBuf],
) -> Vec<GitProtectedPath> {
    let holds_a_root = |path: &Path| roots.iter().any(|root| is_within(root, path));
    let outside = !roots.iter().any(|root| is_within(&path, root));
    if !kind.is_dir() || !(holds_a_root(&path) || (outside && holds_a_root(&canonical_path(&path))))
    {
        return vec![GitProtectedPath { path, kind }];
    }
    beneath
        .split_whitespace()
        .map(|name| GitProtectedPath {
            path: path.join(name),
            kind: GitPathKind::HookFile,
        })
        .collect()
}

/// Regular files a protected entry covers that have a hard-link alias (`st_nlink > 1`): a write
/// through the alias, wherever it lies, changes what git reads or runs, so the scan refuses.
/// A tree is walked to [`HARD_LINK_WALK_LIMIT`] entries; past that it refuses too.
fn hard_linked(entries: &[GitProtectedPath]) -> Vec<GitMetadataUnread> {
    let mut out = Vec::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let aliased = |path: &Path| {
            std::fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.nlink() > 1)
        };
        let unread = |path: &Path| GitMetadataUnread::HardLinked {
            path: path.to_path_buf(),
        };
        for entry in entries {
            match entry.kind {
                GitPathKind::LinkNode
                | GitPathKind::OptionalFile
                | GitPathKind::OptionalDir
                | GitPathKind::PinnedDir
                | GitPathKind::CacheDir
                | GitPathKind::CacheFile
                | GitPathKind::MissingAncestor => {}
                GitPathKind::File | GitPathKind::HookFile => {
                    if aliased(&entry.path) {
                        out.push(unread(&entry.path));
                    }
                }
                GitPathKind::Dir => {
                    let mut pending = vec![entry.path.clone()];
                    let mut seen = 0usize;
                    while let Some(dir) = pending.pop() {
                        let children = match std::fs::read_dir(&dir) {
                            Ok(children) => children,
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                            // A tree that cannot be listed may hide an aliased hook: refuse
                            Err(error) => {
                                out.push(GitMetadataUnread::Unreadable {
                                    path: dir.clone(),
                                    reason: format!("cannot list it for hard-link aliases: {error}"),
                                });
                                continue;
                            }
                        };
                        for child in children.flatten() {
                            seen += 1;
                            if seen > HARD_LINK_WALK_LIMIT {
                                out.push(GitMetadataUnread::GitDirsUnlisted {
                                    tree: entry.path.clone(),
                                    limit: HARD_LINK_WALK_LIMIT,
                                });
                                pending.clear();
                                break;
                            }
                            let path = child.path();
                            match child.file_type() {
                                Ok(kind) if kind.is_dir() => pending.push(path),
                                Ok(kind) if kind.is_file() && aliased(&path) => {
                                    out.push(unread(&path));
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = entries;
    }
    out
}

/// Entries walked in one protected tree for hard-link aliases.
const HARD_LINK_WALK_LIMIT: usize = 4096;

/// What git reads or runs beneath a git directory's entry.
fn read_beneath(entry: &str) -> &'static str {
    match entry {
        "hooks" => GIT_HOOK_NAMES,
        _ => "",
    }
}

fn entry_kind(entry: &str) -> GitPathKind {
    match entry {
        "hooks" => GitPathKind::Dir,
        _ => GitPathKind::File,
    }
}

#[derive(Default)]
struct GitScan {
    /// The home `~` resolves under in an include read for `extensions.worktreeConfig`.
    user_home: Option<PathBuf>,
    /// The present submodule checkouts: a relative system or global `core.hooksPath` is
    /// resolved in each of them too (git runs a hook from the working tree it commits in).
    checkouts: Vec<PathBuf>,
    paths: Vec<(PathBuf, GitPathKind, &'static str)>,
    nodes: Vec<PathBuf>,
    unread: Vec<GitMetadataUnread>,
}

impl GitScan {
    fn push(&mut self, path: PathBuf, kind: GitPathKind, beneath: &'static str) {
        if let Some(known) = self.paths.iter_mut().find(|(known, _, _)| known == &path) {
            // The stronger reading wins: a tree over a file, a required file over an optional one
            if kind < known.1 {
                known.1 = kind;
                known.2 = beneath;
            }
            return;
        }
        self.paths.push((path, kind, beneath));
    }

    /// `path` as named and in the spellings a link adds. A hooks tree also protects where each
    /// hook in it that is a symlink leads: editing that target changes what git runs.
    fn protect(&mut self, path: &Path, kind: GitPathKind, beneath: &'static str) {
        // As named only when the spelling is the kernel's: past a symlink, `..` is not lexical
        if !has_parent_dir(path) {
            self.push(fold_dots(path), kind, beneath);
        }
        self.protect_links(path, kind, beneath);
        if kind == GitPathKind::Dir && beneath == GIT_HOOK_NAMES {
            self.protect_hook_links(path);
        } else if kind == GitPathKind::Dir && beneath == TEMPLATE_READ_BENEATH {
            // A copied repository keeps a template's hook link (a linked `hooks` itself is
            // copied as one link: `protect_template` follows it)
            let hooks = path.join("hooks");
            if !is_symlink(&hooks) {
                self.protect_hook_links_copied(&hooks);
            }
        }
    }

    /// Where each hook in `hooks` that is a symlink leads: editing that changes what git runs.
    fn protect_hook_links(&mut self, hooks: &Path) {
        for name in GIT_HOOK_NAMES.split_whitespace() {
            let hook = hooks.join(name);
            if is_symlink(&hook) {
                // A dangling hook link: the agent could create what it leads to
                let kind = if std::fs::metadata(&hook).is_ok() {
                    GitPathKind::File
                } else {
                    GitPathKind::HookFile
                };
                self.protect_links(&hook, kind, "");
            }
        }
    }

    /// [`Self::protect_hook_links`] for a template's real `hooks` directory, whose hook links git
    /// copies as text: a relative one refuses ([`Self::copied_link_is_absolute`]).
    fn protect_hook_links_copied(&mut self, hooks: &Path) {
        for name in GIT_HOOK_NAMES.split_whitespace() {
            let hook = hooks.join(name);
            if is_symlink(&hook) && !self.copied_link_is_absolute(&hook) {
                return;
            }
        }
        self.protect_hook_links(hooks);
    }

    /// Whether a template symlink names an absolute target. Git copies the link text into each
    /// new git directory, where a relative target resolves to a path not known here: unread.
    fn copied_link_is_absolute(&mut self, link: &Path) -> bool {
        match std::fs::read_link(link) {
            Ok(target) if target.is_absolute() => true,
            Ok(target) => {
                self.unread.push(GitMetadataUnread::Unreadable {
                    path: link.to_path_buf(),
                    reason: format!(
                        "is a template symlink to the relative {}, which git init and git clone \
                         copy as text and resolve from each new repository",
                        target.display()
                    ),
                });
                false
            }
            Err(error) => {
                self.unread.push(GitMetadataUnread::Unreadable {
                    path: link.to_path_buf(),
                    reason: error.to_string(),
                });
                false
            }
        }
    }

    /// A template directory `git init` and `git clone` copy into each new repository: as a
    /// hooks tree, narrowed to what git then reads or runs when it holds a write root.
    fn protect_template(&mut self, dir: &Path) {
        match hooks_tree_kind(dir) {
            Some(GitPathKind::Dir) => {
                self.protect(dir, GitPathKind::Dir, TEMPLATE_READ_BENEATH);
                // The copy keeps a link (git copies a template with `lstat`): where a linked
                // entry git runs or reads as config leads is protected too
                for entry in TEMPLATE_LINKED_ENTRIES {
                    let path = dir.join(entry);
                    if !is_symlink(&path) || !self.copied_link_is_absolute(&path) {
                        continue;
                    }
                    if *entry == "hooks" {
                        match hooks_tree_kind(&path) {
                            Some(GitPathKind::Dir) => {
                                self.protect(&path, GitPathKind::Dir, GIT_HOOK_NAMES);
                            }
                            Some(kind) => self.protect(&path, kind, ""),
                            None => {}
                        }
                    } else {
                        self.protect(&path, GitPathKind::File, "");
                    }
                }
            }
            Some(kind) => self.protect(dir, kind, ""),
            None => {}
        }
    }

    /// The canonical spelling of `path` (where a link leads) and each link on the way.
    fn protect_links(&mut self, path: &Path, kind: GitPathKind, beneath: &'static str) {
        let canonical = canonical_path(path);
        if (has_parent_dir(path) || canonical != fold_dots(path))
            && file_dir_or_missing(&canonical).is_some()
        {
            self.push(canonical, kind, beneath);
        }
        self.add_link_nodes(path);
    }

    /// Each link the kernel meets resolving `path`, as a link node.
    fn add_link_nodes(&mut self, path: &Path) {
        for node in link_nodes(path) {
            if !self.nodes.contains(&node) {
                self.nodes.push(node);
            }
        }
    }

    /// The `core.worktree` a git directory's config names, resolved as git resolves it.
    fn config_worktree(&mut self, git_dir: &Path) -> Option<PathBuf> {
        let config = git_dir.join("config");
        let mut hooks = ConfigHooksPath::default();
        let mut quiet = GitScan::default();
        hooks.visit(&mut quiet, &config, self.user_home.as_deref(), 0, false);
        let value = hooks.worktree?;
        include_path(&value, &config, self.user_home.as_deref()).ok()
    }

    /// The submodules present under `git_dir/modules`: each git directory's entries and hooks
    /// paths, and the `.git` pointer of its checkout (re-pointing it redirects git there).
    fn present_submodules(&mut self, git_dir: &Path, anchors: &[PathBuf], user_home: Option<&Path>) {
        for module in self.submodule_git_dirs(&git_dir.join("modules")) {
            self.git_dir_entries(&module);
            self.hooks_path_entries(&module, anchors, user_home);
            if let Some(checkout) = self.config_worktree(&module) {
                let pointer = checkout.join(".git");
                self.protect(&pointer, required_if_present(&pointer), "");
                if !self.checkouts.contains(&checkout) {
                    self.checkouts.push(checkout);
                }
            }
        }
    }

    /// The text of a file git reads, through a symlink as git reads it, or `None` for a missing
    /// one; the spellings a link adds are protected.
    fn read(&mut self, file: &Path) -> Option<String> {
        self.protect_links(file, GitPathKind::File, "");
        match read_git_file(file) {
            Ok(text) => text,
            Err(unread) => {
                self.unread.push(unread);
                None
            }
        }
    }

    fn git_dir_entries(&mut self, git_dir: &Path) {
        // A `commondir` there would send git to other metadata
        let pointer = git_dir.join("commondir");
        self.protect(&pointer, required_if_present(&pointer), "");
        let enabled = self.worktree_config_enabled(&git_dir.join("config"));
        for entry in GIT_DIR_PROTECTED_ENTRIES {
            let kind = if *entry == WORKTREE_CONFIG {
                worktree_config_kind(enabled)
            } else {
                entry_kind(entry)
            };
            self.protect(&git_dir.join(entry), kind, read_beneath(entry));
        }
    }

    /// Whether `config` (with its includes) turns `extensions.worktreeConfig` on.
    fn worktree_config_enabled(&mut self, config: &Path) -> bool {
        let mut hooks = ConfigHooksPath::default();
        // Read apart: every file it reads is protected where the hooks path is resolved
        let mut quiet = GitScan::default();
        hooks.visit(&mut quiet, config, self.user_home.as_deref(), 0, false);
        hooks.worktree_config
    }

    fn hooks_path_entries(&mut self, git_dir: &Path, anchors: &[PathBuf], user_home: Option<&Path>) {
        for config in ["config", WORKTREE_CONFIG] {
            self.hooks_path_in(&git_dir.join(config), anchors, user_home);
        }
    }

    fn hooks_path_in(&mut self, config: &Path, anchors: &[PathBuf], user_home: Option<&Path>) {
        let mut hooks = ConfigHooksPath::default();
        hooks.visit(self, config, user_home, 0, false);
        let mut anchors = anchors.to_vec();
        if let Some(worktree) = hooks
            .worktree
            .as_deref()
            .and_then(|value| include_path(value, config, user_home).ok())
        {
            anchors.push(worktree);
        }
        for tree in hooks.trees(&anchors, user_home) {
            match hooks_tree_kind(&tree) {
                Some(GitPathKind::Dir) => self.protect(&tree, GitPathKind::Dir, GIT_HOOK_NAMES),
                Some(kind) => self.protect(&tree, kind, ""),
                None => {}
            }
        }
        // `init.templateDir`, read through the same include walk
        for value in hooks.template.iter().chain(&hooks.template_conditional) {
            match template_dirs(value, user_home) {
                Ok(dirs) => {
                    for dir in dirs {
                        self.protect_template(&dir);
                    }
                }
                Err(reason) => self.unread.push(GitMetadataUnread::Unreadable {
                    path: config.to_path_buf(),
                    reason: format!("its init.templateDir {value:?} {reason}, not resolved here"),
                }),
            }
        }
    }

    /// The directory a one-line pointer file names, resolved against `base`, when it exists as a
    /// directory: canonical, with every link on the way protected.
    fn pointer_target(&mut self, file: &Path, base: &Path, prefix: Option<&str>) -> Option<PathBuf> {
        let text = self.read(file)?;
        // As git reads a pointer: the first line, only its trailing CR/LF dropped; a `.git`
        // file's `gitdir: ` prefix exactly (a space in a name is part of the name)
        let line = text
            .split('\n')
            .next()?
            .trim_end_matches(['\r', '\n']);
        // Git reads the bytes; the lossy spelling would miss the directory it uses
        if line.contains('\u{fffd}') {
            self.unread.push(GitMetadataUnread::NotUtf8 {
                path: file.to_path_buf(),
            });
            return None;
        }
        let target = match prefix {
            Some(prefix) => line.strip_prefix(prefix)?,
            None => line,
        };
        if target.is_empty() {
            return None;
        }
        let target = base.join(target);
        if !std::fs::metadata(&target).is_ok_and(|meta| meta.is_dir()) {
            return None;
        }
        self.add_link_nodes(&target);
        Some(canonical_path(&target))
    }

    /// The submodule git directories under `modules` now (a directory holding a `HEAD` file),
    /// each walked further only into its own `modules`. A directory on the way that exists and
    /// cannot be listed may hide one: it is unread, so the sandbox refuses.
    fn submodule_git_dirs(&mut self, modules: &Path) -> Vec<PathBuf> {
        let mut pending = std::collections::VecDeque::from([modules.to_path_buf()]);
        let mut out = Vec::new();
        let mut listed = 0usize;
        while let Some(dir) = pending.pop_front() {
            let children = match child_dirs(&dir) {
                Ok(children) => children,
                Err((path, error)) => {
                    self.unread.push(GitMetadataUnread::Unreadable {
                        path,
                        reason: format!("cannot list it for submodule git directories: {error}"),
                    });
                    continue;
                }
            };
            for child in children {
                // A linked module directory is followed, and the link itself protected
                self.add_link_nodes(&child);
                listed += 1;
                if listed > GIT_DIRS_LIMIT {
                    self.unread.push(GitMetadataUnread::GitDirsUnlisted {
                        tree: modules.to_path_buf(),
                        limit: GIT_DIRS_LIMIT,
                    });
                    return out;
                }
                let is_git_dir = std::fs::metadata(child.join("HEAD")).is_ok_and(|meta| meta.is_file());
                if is_git_dir {
                    pending.push_back(child.join("modules"));
                    out.push(child);
                } else {
                    pending.push_back(child);
                }
            }
        }
        out
    }
}

/// The subdirectories of `dir`, a symlink to a directory included (git follows one), sorted;
/// none when `dir` does not exist or is not a directory. Anything else that stops the listing
/// (or the look at a child) is the path and the error.
fn child_dirs(dir: &Path) -> Result<Vec<PathBuf>, (PathBuf, std::io::Error)> {
    let absent = |error: &std::io::Error| {
        matches!(
            error.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
        )
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if absent(&error) => return Ok(Vec::new()),
        Err(error) => return Err((dir.to_path_buf(), error)),
    };
    let mut out = Vec::new();
    for entry in entries {
        let path = entry.map_err(|error| (dir.to_path_buf(), error))?.path();
        match std::fs::metadata(&path) {
            Ok(meta) if meta.is_dir() => out.push(path),
            Ok(_) => {}
            // A dangling link names nothing git could use
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err((path, error)),
        }
    }
    out.sort();
    Ok(out)
}

/// Whether `path` itself is a symlink.
fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
}

/// Each symlink the kernel meets resolving `path` (`..` applied after a link resolves), in a
/// link's target too, as the node it sees (`<canonical parent>/<name>`).
fn link_nodes(path: &Path) -> Vec<PathBuf> {
    let components = |path: &Path| -> Vec<OsString> {
        path.components()
            .rev()
            .map(|c| c.as_os_str().into())
            .collect()
    };
    let mut rest = components(path);
    let mut prefix = PathBuf::new();
    let mut out = Vec::new();
    let mut hops = 0;
    while let Some(name) = rest.pop() {
        if name == ".." {
            prefix.pop();
        } else if name != "." {
            prefix.push(&name);
        }
        let Ok(target) = std::fs::read_link(&prefix) else {
            continue;
        };
        if let (Some(parent), Some(node)) = (prefix.parent(), prefix.file_name()) {
            let node = canonical_path(parent).join(node);
            if !out.contains(&node) {
                out.push(node);
            }
        }
        prefix.pop();
        hops += 1;
        if hops > SYMLINK_HOPS {
            break;
        }
        if target.is_absolute() {
            prefix = PathBuf::new();
        }
        rest.extend(components(&target));
    }
    out
}

/// One bounded read of a file git reads: `Ok(None)` for a missing file or a directory, `Err` for
/// one larger than [`GIT_METADATA_READ_LIMIT`] or unreadable. Opened `O_NONBLOCK` so a FIFO cannot
/// stall startup.
fn read_git_file(file: &Path) -> Result<Option<String>, GitMetadataUnread> {
    let unreadable = |error: &std::io::Error| GitMetadataUnread::Unreadable {
        path: file.to_path_buf(),
        reason: error.to_string(),
    };
    let too_large = || GitMetadataUnread::TooLarge {
        path: file.to_path_buf(),
        limit: GIT_METADATA_READ_LIMIT,
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut handle = match options.open(file) {
        Ok(handle) => handle,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(unreadable(&error)),
    };
    let meta = handle.metadata().map_err(|error| unreadable(&error))?;
    if meta.is_dir() {
        return Ok(None);
    }
    if meta.len() > GIT_METADATA_READ_LIMIT {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    (&mut handle)
        .take(GIT_METADATA_READ_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| unreadable(&error))?;
    if u64::try_from(bytes.len()).is_ok_and(|len| len > GIT_METADATA_READ_LIMIT) {
        return Err(too_large());
    }
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}

/// The trees a `core.hooksPath` value names as git reads it: `~` and `~/…` under the user's home,
/// `~user/…` under both homes it can name on the usual layout, an absolute path as is, a relative
/// one under each working tree in `anchors`.
fn hooks_path_trees(value: &str, anchors: &[PathBuf], user_home: Option<&Path>) -> Vec<PathBuf> {
    match (value.strip_prefix('~'), user_home) {
        (Some(_), None) => Vec::new(),
        (Some(rest), Some(home)) => {
            let (user, rest) = rest.split_once('/').unwrap_or((rest, ""));
            let mut homes = vec![home.to_path_buf()];
            if !user.is_empty() {
                homes.extend(home.parent().map(|parent| parent.join(user)));
            }
            homes.iter().map(|home| home.join(rest)).collect()
        }
        (None, _) if Path::new(value).is_absolute() => vec![PathBuf::from(value)],
        (None, _) => anchors.iter().map(|anchor| anchor.join(value)).collect(),
    }
}

/// `core.hooksPath` as git reads one config file: in file order, following `[include]` and
/// `[includeIf]` files in place. The last assignment wins and an empty one unsets.
#[derive(Default)]
struct ConfigHooksPath {
    effective: Option<String>,
    /// Values set under an `[includeIf]` (its condition is not evaluated here).
    conditional: Vec<String>,
    /// `init.templateDir`, read as `core.hooksPath` is.
    template: Option<String>,
    template_conditional: Vec<String>,
    worktree: Option<String>,
    /// `extensions.worktreeConfig`, the last assignment winning (any include counts).
    worktree_config: bool,
    files_read: usize,
}

impl ConfigHooksPath {
    fn visit(
        &mut self,
        scan: &mut GitScan,
        config: &Path,
        user_home: Option<&Path>,
        depth: usize,
        conditional: bool,
    ) {
        if depth > GIT_CONFIG_INCLUDE_DEPTH || self.files_read >= GIT_CONFIG_FILES_LIMIT {
            scan.unread.push(GitMetadataUnread::IncludesUnfollowed {
                path: config.to_path_buf(),
                depth: GIT_CONFIG_INCLUDE_DEPTH,
                files: GIT_CONFIG_FILES_LIMIT,
            });
            return;
        }
        let Some(text) = scan.read(config) else {
            return;
        };
        self.files_read += 1;
        let (entries, rejected_line) = config_entries(&text);
        if let Some(line) = rejected_line {
            scan.unread.push(GitMetadataUnread::Unreadable {
                path: config.to_path_buf(),
                reason: format!(
                    "its line {line} does not parse as git config, so nothing from there on is read"
                ),
            });
        }
        for entry in entries {
            let name = (
                entry.section.as_str(),
                entry.subsection.as_deref(),
                entry.key.as_str(),
            );
            let include_is_conditional = match name {
                ("core", None, "hookspath") => {
                    assign_path(
                        (&mut self.effective, &mut self.conditional),
                        scan,
                        config,
                        entry.value,
                        conditional,
                    );
                    continue;
                }
                ("init", None, "templatedir") => {
                    assign_path(
                        (&mut self.template, &mut self.template_conditional),
                        scan,
                        config,
                        entry.value,
                        conditional,
                    );
                    continue;
                }
                ("core", None, "worktree") => {
                    if let Some(value) = entry.value.filter(|value| !value.is_empty()) {
                        self.worktree = Some(value);
                    }
                    continue;
                }
                ("extensions", None, "worktreeconfig") => {
                    // A conditional `true` counts: its condition is not evaluated here
                    let on = config_bool(entry.value.as_deref());
                    if conditional {
                        self.worktree_config |= on;
                    } else {
                        self.worktree_config = on;
                    }
                    continue;
                }
                ("include", None, "path") => conditional,
                ("includeif", Some(_), "path") => true,
                _ => continue,
            };
            let Some(value) = entry.value.as_deref() else {
                continue;
            };
            if value.contains('\u{fffd}') {
                scan.unread.push(GitMetadataUnread::NotUtf8 {
                    path: config.to_path_buf(),
                });
                continue;
            }
            // Git expands `%(prefix)/` to its own install prefix, which is not known here
            let include = match value.strip_prefix("%(prefix)/") {
                Some(_) => Err("is under git's install prefix"),
                None => include_path(value, config, user_home),
            };
            let include = match include {
                Ok(include) => include,
                Err(reason) => {
                    scan.unread.push(GitMetadataUnread::Unreadable {
                        path: config.to_path_buf(),
                        reason: format!("its include {value:?} {reason}, not resolved here"),
                    });
                    continue;
                }
            };
            // Protected whether or not it exists yet, so no command can create it
            // The spelling older git reads (tabs as spaces) is read too, as a conditional file
            for variant in whitespace_variants(value).iter().skip(1) {
                if let Ok(other) = include_path(variant, config, user_home) {
                    scan.protect(&other, GitPathKind::File, "");
                    self.visit(scan, &other, user_home, depth + 1, true);
                }
            }
            scan.protect(&include, GitPathKind::File, "");
            self.visit(scan, &include, user_home, depth + 1, include_is_conditional);
        }
    }

    fn trees(&self, anchors: &[PathBuf], user_home: Option<&Path>) -> Vec<PathBuf> {
        self.effective
            .iter()
            .chain(&self.conditional)
            .flat_map(|value| hooks_path_trees(value, anchors, user_home))
            .collect()
    }
}

/// One assignment of a path-valued key (`core.hooksPath`, `init.templateDir`) into its effective
/// value and the values kept beside it: the last assignment wins and an empty one unsets; one
/// under an `[includeIf]`, and the other whitespace spelling, are kept beside the effective one.
fn assign_path(
    (effective, kept): (&mut Option<String>, &mut Vec<String>),
    scan: &mut GitScan,
    config: &Path,
    value: Option<String>,
    conditional: bool,
) {
    let Some(value) = value else {
        return;
    };
    if value.contains('\u{fffd}') {
        scan.unread.push(GitMetadataUnread::NotUtf8 {
            path: config.to_path_buf(),
        });
        return;
    }
    let mut variants = whitespace_variants(&value).into_iter();
    let written = variants.next().unwrap_or_default();
    // The other spellings are protected beside the effective one
    for variant in variants {
        if !kept.contains(&variant) {
            kept.push(variant);
        }
    }
    if !conditional {
        *effective = (!written.is_empty()).then_some(written);
    } else if !written.is_empty() && !kept.contains(&written) {
        kept.push(written);
    }
}

/// The directories an `init.templateDir` value names as git reads it: `~` and `~user` as a hooks
/// path, an absolute path as is. A relative value (read from each command's working directory)
/// or one under git's install prefix is not known here.
fn template_dirs(value: &str, user_home: Option<&Path>) -> Result<Vec<PathBuf>, &'static str> {
    if value.starts_with("%(prefix)/") {
        return Err("is under git's install prefix");
    }
    match value.strip_prefix('~') {
        Some(_) if user_home.is_none() => Err("is under a home directory that is not known"),
        Some(_) => Ok(hooks_path_trees(value, &[], user_home)),
        None if Path::new(value).is_absolute() => Ok(vec![PathBuf::from(value)]),
        None => Err("is relative, which git reads from each command's working directory"),
    }
}

/// The spellings a value with inner tabs can have across git versions: as written, and with each
/// tab read as a space (older git), so both are protected.
fn whitespace_variants(value: &str) -> Vec<String> {
    let mut out = vec![value.to_owned()];
    if value.contains('\t') {
        out.push(value.replace('\t', " "));
    }
    out
}

/// A git boolean: a bare key is true; `true`/`yes`/`on` and a non-zero integer are true.
fn config_bool(value: Option<&str>) -> bool {
    match value {
        None => true,
        Some(value) => {
            let value = value.trim().to_ascii_lowercase();
            matches!(value.as_str(), "true" | "yes" | "on")
                || value.parse::<i64>().is_ok_and(|number| number != 0)
        }
    }
}

/// An include's `path` as git resolves it: `~` and `~/…` under the user's home, an absolute path
/// as is, a relative one beside the including file.
fn include_path(value: &str, config: &Path, user_home: Option<&Path>) -> Result<PathBuf, &'static str> {
    match value.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => user_home
            .map(|home| home.join(rest.trim_start_matches('/')))
            .ok_or("is under a home directory that is not known"),
        Some(_) => Err("is under another user's home"),
        None if value.is_empty() => Err("is empty"),
        None if Path::new(value).is_absolute() => Ok(PathBuf::from(value)),
        None => config
            .parent()
            .map(|dir| dir.join(value))
            .ok_or("is relative to no directory"),
    }
}

/// One `key [= value]` under its `[section "subsection"]`.
struct ConfigEntry {
    section: String,
    subsection: Option<String>,
    key: String,
    value: Option<String>,
}

/// The entries of a git config file in order, tokenised as git does. Parsing stops at a line git
/// rejects (git then runs no command), returned so the file is unread.
fn config_entries(text: &str) -> (Vec<ConfigEntry>, Option<usize>) {
    let text = text
        .strip_prefix('\u{feff}')
        .unwrap_or(text)
        .replace("\r\n", "\n");
    let mut chars = text.chars();
    let mut header: Option<(String, Option<String>)> = None;
    let mut out = Vec::new();
    while let Some(c) = chars.next() {
        match c {
            c if is_git_space(c) => {}
            '#' | ';' => {
                chars.find(|&c| c == '\n');
            }
            '[' => match config_header(&mut chars) {
                Some(parsed) => header = Some(parsed),
                None => return (out, Some(line_read(&text, &chars))),
            },
            c if c.is_ascii_alphabetic() => {
                let Some((key, value)) = config_key_value(c, &mut chars) else {
                    return (out, Some(line_read(&text, &chars)));
                };
                if let Some((section, subsection)) = &header {
                    out.push(ConfigEntry {
                        section: section.clone(),
                        subsection: subsection.clone(),
                        key,
                        value,
                    });
                }
            }
            _ => return (out, Some(line_read(&text, &chars))),
        }
    }
    (out, None)
}

fn line_read(text: &str, chars: &std::str::Chars<'_>) -> usize {
    let read = &text[..text.len() - chars.as_str().len()];
    read.strip_suffix('\n')
        .unwrap_or(read)
        .matches('\n')
        .count()
        + 1
}

fn is_git_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

fn config_header(chars: &mut std::str::Chars<'_>) -> Option<(String, Option<String>)> {
    let mut name = String::new();
    let quoted = loop {
        match chars.next()? {
            ']' if name.is_empty() => return None,
            ']' => break None,
            '\n' => return None,
            c if is_git_space(c) => break Some(config_subsection(chars)?),
            c if c.is_ascii_alphanumeric() || c == '-' || c == '.' => {
                name.push(c.to_ascii_lowercase());
            }
            _ => return None,
        }
    };
    let (section, dotted) = match name.split_once('.') {
        Some((section, dotted)) => (section.to_owned(), Some(dotted.to_owned())),
        None => (name, None),
    };
    let subsection = match (dotted, quoted) {
        (Some(dotted), Some(quoted)) => Some(format!("{dotted}.{quoted}")),
        (dotted, quoted) => dotted.or(quoted),
    };
    Some((section, subsection))
}

fn config_subsection(chars: &mut std::str::Chars<'_>) -> Option<String> {
    let mut c = chars.next()?;
    while c != '\n' && is_git_space(c) {
        c = chars.next()?;
    }
    if c != '"' {
        return None;
    }
    let mut subsection = String::new();
    loop {
        match chars.next()? {
            '"' => break,
            '\n' => return None,
            '\\' => subsection.push(chars.next().filter(|&c| c != '\n')?),
            c => subsection.push(c),
        }
    }
    (chars.next()? == ']').then_some(subsection)
}

fn config_key_value(first: char, chars: &mut std::str::Chars<'_>) -> Option<(String, Option<String>)> {
    let mut key = first.to_ascii_lowercase().to_string();
    let mut c = chars.next();
    while let Some(k) = c.filter(|k| k.is_ascii_alphanumeric() || *k == '-') {
        key.push(k.to_ascii_lowercase());
        c = chars.next();
    }
    while matches!(c, Some(' ' | '\t')) {
        c = chars.next();
    }
    match c {
        None | Some('\n') => Some((key, None)),
        Some('=') => Some((key, Some(config_value(chars)?))),
        Some(_) => None,
    }
}

/// Inner whitespace is kept as written (as current git keeps it); see [`whitespace_variants`].
fn config_value(chars: &mut std::str::Chars<'_>) -> Option<String> {
    let mut value = String::new();
    let (mut quoted, mut comment) = (false, false);
    let mut spaces = String::new();
    loop {
        let c = chars.next().unwrap_or('\n');
        if c == '\n' {
            return (!quoted).then_some(value);
        }
        if comment {
            continue;
        }
        if is_git_space(c) && !quoted {
            if !value.is_empty() {
                spaces.push(c);
            }
            continue;
        }
        if !quoted && matches!(c, '#' | ';') {
            comment = true;
            continue;
        }
        value.push_str(&spaces);
        spaces.clear();
        match c {
            '\\' => match chars.next().unwrap_or('\n') {
                '\n' => {}
                't' => value.push('\t'),
                'b' => value.push('\u{8}'),
                'n' => value.push('\n'),
                escaped @ ('\\' | '"') => value.push(escaped),
                _ => return None,
            },
            '"' => quoted = !quoted,
            c => value.push(c),
        }
    }
}

/// The git write-deny for a sandbox whose writable roots are `write_roots`, resolved against this
/// process's home and environment. Fails closed on anything unread.
pub(crate) fn resolve_git_write_deny(
    workspace: &Path,
    write_roots: &[PathBuf],
) -> anyhow::Result<Vec<GitProtectedPath>> {
    let home = fuigo_dirs::home_dir();
    let got = git_entries_in(workspace, home.as_deref(), write_roots, &GitConfigEnv::from_host());
    if !got.unread.is_empty() {
        let detail = got
            .unread
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        anyhow::bail!(
            "git write-deny cannot read a git file git would read, so the hooks it names are \
             unknown: {detail}. Fix or remove it, or run with the sandbox off."
        );
    }
    Ok(got.protected)
}

#[cfg(test)]
#[path = "git_write_deny_tests.rs"]
mod tests;
