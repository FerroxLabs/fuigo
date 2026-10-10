//! Home write-deny: the files and trees in the user's home that run or reconfigure code on the
//! next login, shell, build, install or editor start, which a sandboxed agent must not be able to
//! rewrite (P177, ported from upstream's protected floor, `sandbox/src/command/protected.rs`:
//! `HOME_PROTECTED_FILES`, `HOME_PROTECTED_DIRS`, `HOME_PROTECTED_TOOL_TREES` and the secret
//! stores, which upstream also puts in the floor). Write-denied, still readable, through the same
//! mechanism as the git write-deny ([`crate::git_write_deny`]): macOS Seatbelt write-deny rules,
//! Linux read-only bwrap binds for the entries inside a writable root (outside them Landlock
//! already denies the write), verified inside bwrap. Every profile that enforces the hook
//! write-deny gets it; devbox does not.
//!
//! Each entry is protected in each spelling a command could reach it by (as named, canonical, and
//! each symlink on the way as a link node). Fuigo adds the places the same tools read when the
//! environment moves them ([`RELOCATIONS`]), more shell and X session startup files, emacs's and
//! vi's other startup files, more `PATH` directories, desktop entries and direnv's library
//! ([`FUIGO_HOME_PROTECTED_FILES`], [`FUIGO_HOME_PROTECTED_DIRS`],
//! [`FUIGO_HOME_PROTECTED_TOOL_TREES`]).
//!
//! A name that does not exist yet: macOS denies creating it. Linux cannot bind a name that does
//! not exist, and Fuigo never creates a placeholder file (an empty `~/.bash_profile` would stop
//! bash reading `~/.profile`, an empty `~/.cargo/config` would shadow `config.toml`), so where a
//! command could create it (its nearest existing directory lies inside a writable root):
//! - a missing startup directory ([`HOME_PROTECTED_DIRS`] but the macOS ones) is created empty
//!   and bound, as the git write-deny creates `hooks/`;
//! - the tool's own directory holding the name (`~/.cargo` without `config`) is pinned: bound
//!   read-only, so no name can be created in it, with each existing child that is not protected
//!   bound writable again ([`GitPathKind::PinnedDir`]); cargo's registry, git checkouts and lock
//!   files are made to exist first, so builds keep working;
//! - a shared directory (the home, `~/.config`, `~/.local`, the workspace), or an ancestor above
//!   the name's own missing directory, cannot be pinned without stopping every new file there:
//!   when the workspace or a configured `read_write` grant makes it writable, the sandbox refuses
//!   to start; when only a temp directory the sandbox always keeps writable holds it (a home under
//!   `/tmp`), the name stays creatable (accepted limit).
//!
//! Fails closed (the sandbox refuses to start): a relative home or relocating variable (each tool
//! resolves it from its own working directory; a name variable such as `NVIM_APPNAME` that is
//! absolute or holds `..`), an entry whose type cannot be read, a workspace inside a protected tree
//! (it would be read-only), a writable root inside a protected tree, existing or not (judged on
//! its spelling before the profile creates the grant), the shared-directory case above, a protected
//! file inside a writable root with a second hard link, a protected file with a hard link that no
//! protected name accounts for when a writable root holds (or is too large to search for) that
//! link, and a startup tree inside a writable root that cannot be listed for hard links. On Linux
//! a symlink on the way that lies inside a writable root refuses too ([`crate::hook_write_deny`]).
//!
//! The build caches stay writable: cargo's registry, git checkouts and lock files, npm's and
//! pip's caches (`~/.cargo` itself is not an entry, only its config, credentials, `env` and `bin`).
//!
//! Accepted limits (as upstream): a symlink inside a protected tree that leads outside it
//! (`~/.local/bin/x -> ~/proj/x`) is not followed, so its target stays writable where a profile
//! grants it; a tool tree or secret store is listed for hard links only as far as a bound (it can
//! hold 10⁵ files), past which its files are not checked.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::git_write_deny::{
    GitMetadataUnread, GitPathKind, GitProtectedPath, canonical_path, fold_dots, is_within,
    protect_spellings,
};

/// Upstream `HOME_PROTECTED_FILES`: home-relative files that run or reconfigure code on the next
/// login, build, install or editor start.
pub(crate) const HOME_PROTECTED_FILES: &[&str] = &[
    ".bashrc",
    ".bash_aliases",
    ".bash_login",
    ".bash_logout",
    ".bash_profile",
    ".profile",
    ".pam_environment",
    ".zshenv",
    ".zprofile",
    ".zshrc",
    ".zlogin",
    ".zlogout",
    ".config/fish/config.fish",
    ".gitconfig",
    ".config/git/config",
    ".cargo/config.toml",
    ".cargo/config",
    ".cargo/credentials.toml",
    ".cargo/credentials",
    ".cargo/env",
    ".gradle/init.gradle",
    ".gradle/gradle.properties",
    ".m2/settings.xml",
    ".pip/pip.conf",
    ".config/pip/pip.conf",
    ".yarnrc",
    ".yarnrc.yml",
    ".vimrc",
    ".tmux.conf",
];

/// Upstream `HOME_PROTECTED_DIRS`: `PATH` entries, fish's snippets and functions, gradle's init
/// scripts, neovim's config, the desktop session's autostart entries, user services and
/// environment, and macOS's persistence trees.
pub(crate) const HOME_PROTECTED_DIRS: &[&str] = &[
    ".local/bin",
    ".cargo/bin",
    ".config/fish/conf.d",
    ".config/fish/functions",
    ".gradle/init.d",
    ".config/nvim",
    ".config/autostart",
    ".config/systemd/user",
    ".config/environment.d",
    "Library/LaunchAgents",
    "Library/LaunchDaemons",
    "Library/Application Support/com.apple.backgroundtaskmanagementagent",
];

/// Upstream `HOME_PROTECTED_TOOL_TREES`: toolchains, shell frameworks and editor and CLI plugins
/// the user runs next, unsandboxed. Never created when missing.
pub(crate) const HOME_PROTECTED_TOOL_TREES: &[&str] = &[
    ".rustup/toolchains",
    ".nvm",
    ".oh-my-zsh",
    ".vim",
    ".vscode/extensions",
    ".docker/cli-plugins",
];

/// Upstream `SECRET_READ_DENY_DIRS`, which upstream also puts in the write floor: protected here
/// for write only (ssh and gpg still read them). `~/.ssh` holds `config` and `rc`, which run
/// commands on the next connection.
pub(crate) const HOME_SECRET_DIRS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    "Library/Keychains",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Firefox",
    ".config/google-chrome",
    ".config/chromium",
    ".mozilla",
];

/// Upstream `SECRET_READ_DENY_FILES`, likewise write-protected only: registry, container, cluster
/// and forge credentials, several of which name a helper command (`credHelpers`, `exec`).
pub(crate) const HOME_SECRET_FILES: &[&str] = &[
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".docker/config.json",
    ".kube/config",
    ".config/gh/hosts.yml",
    ".git-credentials",
];

/// Fuigo-added files: csh/tcsh/ksh startup files, the X session scripts run at a graphical login,
/// emacs's and vi's other startup files, and direnv's rc (sourced on every `cd` into an allowed
/// directory).
pub(crate) const FUIGO_HOME_PROTECTED_FILES: &[&str] = &[
    ".cshrc",
    ".tcshrc",
    ".login",
    ".kshrc",
    ".xprofile",
    ".xsessionrc",
    ".xinitrc",
    ".xsession",
    ".gvimrc",
    ".exrc",
    ".emacs",
    ".emacs.el",
    ".direnvrc",
];

/// Fuigo-added startup directories: `~/bin` (a `PATH` entry in the default Debian and Ubuntu
/// `~/.profile`), desktop entries (an `Exec` line run from the menu, which can shadow an
/// installed application's), KDE's login environment scripts, and direnv's library.
pub(crate) const FUIGO_HOME_PROTECTED_DIRS: &[&str] = &[
    "bin",
    ".local/share/applications",
    ".config/plasma-workspace/env",
    ".config/direnv",
];

/// Fuigo-added tool trees: emacs's init trees (they hold its packages) and the `PATH` directories
/// of go, deno and bun. Never created.
pub(crate) const FUIGO_HOME_PROTECTED_TOOL_TREES: &[&str] = &[
    ".emacs.d",
    ".config/emacs",
    "go/bin",
    ".deno/bin",
    ".bun/bin",
];

/// Home-relative directories many tools share, which a pin would close to every new file: a
/// protected name missing beneath one is never pinned (module doc).
const SHARED_DIRS: &[&str] = &[
    ".config",
    ".local",
    ".local/share",
    "Library",
    "Library/Application Support",
];

/// What cargo writes directly in its home on a build, made to exist before the home is pinned so
/// it can be bound writable again: the registry and git caches and the package-cache locks.
const CARGO_CACHE_DIRS: &[&str] = &["registry", "git"];
const CARGO_CACHE_FILES: &[&str] = &[".package-cache", ".package-cache-mutate"];

/// What a missing entry of a class becomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    /// A file: never created (module doc).
    File,
    /// A startup directory: created empty on Linux, so it can be bound.
    StartupDir,
    /// A tool tree, a secret store, or a macOS-only tree: never created.
    Tree,
}

impl Class {
    fn missing_kind(self, rel: &str) -> GitPathKind {
        match self {
            Class::File => GitPathKind::OptionalFile,
            Class::StartupDir if !rel.starts_with("Library/") => GitPathKind::Dir,
            Class::StartupDir | Class::Tree => GitPathKind::OptionalDir,
        }
    }
}

/// How a relocating variable's value names a place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value {
    /// One absolute path; a relative one refuses.
    Path,
    /// Absolute paths separated as `PATH` is (`KUBECONFIG`, `GOPATH`); a relative one refuses, an
    /// empty one is skipped (as the tools skip it).
    List,
    /// A name under the user's config directories (`NVIM_APPNAME`): `~/.config/<name>`, and
    /// `$XDG_CONFIG_HOME/<name>` when set. An absolute name or one with `..` refuses.
    ConfigName,
    /// A name under the home (`YARN_RC_FILENAME`); an absolute name or one with `..` refuses.
    HomeName,
}

/// One row of [`RELOCATIONS`].
type Relocation = (&'static str, Value, &'static [(&'static str, Class)]);

/// `(variable, value shape, [(relative path, class)])`: where a tool reads what
/// [`HOME_PROTECTED_FILES`] and the others name when the environment moves it (Fuigo-added). An
/// empty relative path is the place itself (a variable that names a file or a tree).
const RELOCATIONS: &[Relocation] = &[
    (
        "CARGO_HOME",
        Value::Path,
        &[
            ("config.toml", Class::File),
            ("config", Class::File),
            ("credentials.toml", Class::File),
            ("credentials", Class::File),
            ("env", Class::File),
            ("bin", Class::StartupDir),
        ],
    ),
    ("RUSTUP_HOME", Value::Path, &[("toolchains", Class::Tree)]),
    (
        "ZDOTDIR",
        Value::Path,
        &[
            (".zshenv", Class::File),
            (".zprofile", Class::File),
            (".zshrc", Class::File),
            (".zlogin", Class::File),
            (".zlogout", Class::File),
        ],
    ),
    (
        "XDG_CONFIG_HOME",
        Value::Path,
        &[
            ("fish/config.fish", Class::File),
            ("pip/pip.conf", Class::File),
            ("gh/hosts.yml", Class::File),
            ("fish/conf.d", Class::StartupDir),
            ("fish/functions", Class::StartupDir),
            ("nvim", Class::StartupDir),
            ("autostart", Class::StartupDir),
            ("systemd/user", Class::StartupDir),
            ("environment.d", Class::StartupDir),
            ("plasma-workspace/env", Class::StartupDir),
            ("direnv", Class::StartupDir),
            ("emacs", Class::Tree),
            ("google-chrome", Class::Tree),
            ("chromium", Class::Tree),
        ],
    ),
    // `~/.local/share/applications`
    (
        "XDG_DATA_HOME",
        Value::Path,
        &[("applications", Class::StartupDir)],
    ),
    (
        "GRADLE_USER_HOME",
        Value::Path,
        &[
            ("init.gradle", Class::File),
            ("gradle.properties", Class::File),
            ("init.d", Class::StartupDir),
        ],
    ),
    (
        "DOCKER_CONFIG",
        Value::Path,
        &[("config.json", Class::File), ("cli-plugins", Class::Tree)],
    ),
    ("NVM_DIR", Value::Path, &[("", Class::Tree)]),
    // npm reads its configuration variables in either case
    ("NPM_CONFIG_USERCONFIG", Value::Path, &[("", Class::File)]),
    ("npm_config_userconfig", Value::Path, &[("", Class::File)]),
    ("PIP_CONFIG_FILE", Value::Path, &[("", Class::File)]),
    // `~/.gnupg`, `~/.aws/{config,credentials}`, `~/.kube/config`, `~/.netrc`, gh's `hosts.yml`
    ("GNUPGHOME", Value::Path, &[("", Class::Tree)]),
    ("AWS_CONFIG_FILE", Value::Path, &[("", Class::File)]),
    (
        "AWS_SHARED_CREDENTIALS_FILE",
        Value::Path,
        &[("", Class::File)],
    ),
    ("KUBECONFIG", Value::List, &[("", Class::File)]),
    ("NETRC", Value::Path, &[("", Class::File)]),
    ("GH_CONFIG_DIR", Value::Path, &[("hosts.yml", Class::File)]),
    // `~/.vimrc` (as vim and neovim export it) and neovim's config under another name
    ("MYVIMRC", Value::Path, &[("", Class::File)]),
    (
        "NVIM_APPNAME",
        Value::ConfigName,
        &[("", Class::StartupDir)],
    ),
    // `~/.yarnrc.yml` under another name
    ("YARN_RC_FILENAME", Value::HomeName, &[("", Class::File)]),
    // The startup file every non-interactive bash sources, and python's interactive one
    ("BASH_ENV", Value::Path, &[("", Class::File)]),
    ("PYTHONSTARTUP", Value::Path, &[("", Class::File)]),
    // `~/.oh-my-zsh` and its custom tree, `~/.vscode/extensions`, `~/.config/direnv`
    ("ZSH", Value::Path, &[("", Class::Tree)]),
    ("ZSH_CUSTOM", Value::Path, &[("", Class::Tree)]),
    ("VSCODE_EXTENSIONS", Value::Path, &[("", Class::Tree)]),
    ("DIRENV_CONFIG", Value::Path, &[("", Class::StartupDir)]),
    // The `PATH` directories `~/go/bin`, `~/.deno/bin` and `~/.bun/bin` move with
    ("GOPATH", Value::List, &[("bin", Class::Tree)]),
    ("GOBIN", Value::Path, &[("", Class::Tree)]),
    ("DENO_INSTALL_ROOT", Value::Path, &[("bin", Class::Tree)]),
    ("DENO_INSTALL", Value::Path, &[("bin", Class::Tree)]),
    ("BUN_INSTALL", Value::Path, &[("bin", Class::Tree)]),
];

/// Relocations of a secret store listed for hard links wherever it lies, as [`ALWAYS_LISTED`].
const ALWAYS_LISTED_RELOCATIONS: &[&str] = &["GNUPGHOME"];

/// The relocating variables' values, injected so the scan is testable.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct HomeEnv {
    pub vars: Vec<(&'static str, OsString)>,
}

impl HomeEnv {
    pub(crate) fn from_host() -> HomeEnv {
        HomeEnv::from_lookup(|name| std::env::var_os(name))
    }

    pub(crate) fn from_lookup(lookup: impl Fn(&str) -> Option<OsString>) -> HomeEnv {
        HomeEnv {
            vars: RELOCATIONS
                .iter()
                .filter_map(|(name, _, _)| lookup(name).map(|value| (*name, value)))
                .collect(),
        }
    }

    /// The absolute value of `name`, when set and not empty.
    fn absolute(&self, name: &str) -> Option<PathBuf> {
        self.vars
            .iter()
            .find(|(known, value)| *known == name && !value.is_empty())
            .map(|(_, value)| PathBuf::from(value))
            .filter(|path| path.is_absolute())
    }
}

/// The writable roots a scan judges against: all of them (`write`), those the sandbox always
/// grants whatever the user configures (`essential`: the temp directories and the Fuigo home),
/// and those the user configured (`configured`: the workspace and the profile's `read_write`
/// grants). A path in both keeps its configured provenance.
#[derive(Clone, Debug, Default)]
pub(crate) struct Roots {
    pub write: Vec<PathBuf>,
    pub essential: Vec<PathBuf>,
    pub configured: Vec<PathBuf>,
    /// The temp directories among `essential`: the only roots under which a missing name that
    /// cannot be pinned stays an accepted limit (a home under `/tmp`).
    pub temp: Vec<PathBuf>,
}

impl Roots {
    fn canonical(&self) -> [Vec<PathBuf>; 4] {
        let spell = |roots: &[PathBuf]| -> Vec<PathBuf> {
            roots.iter().map(|root| canonical_path(root)).collect()
        };
        [
            spell(&self.write),
            spell(&self.essential),
            spell(&self.configured),
            spell(&self.temp),
        ]
    }
}

/// Secret stores small enough to list for hard links wherever they lie (a link from one into a
/// writable root changes it); larger trees are listed only inside a writable root (module doc).
const ALWAYS_LISTED: &[&str] = &[".ssh", ".aws", ".gnupg"];

/// What [`home_entries_in`] derives.
#[derive(Debug, Default)]
pub(crate) struct HomeEntries {
    pub protected: Vec<GitProtectedPath>,
    pub unread: Vec<GitMetadataUnread>,
}

/// One entry before its kind is read.
struct Candidate {
    path: PathBuf,
    rel: String,
    class: Class,
    /// Listed for hard links wherever it lies (a small secret store).
    always: bool,
}

/// A relocating variable whose value cannot be resolved the way its tool resolves it.
fn unresolvable(name: &str, value: &std::ffi::OsStr, why: &str) -> GitMetadataUnread {
    GitMetadataUnread::Unreadable {
        path: PathBuf::from(value),
        reason: format!("{name} is {why}, so the startup files it names cannot be protected"),
    }
}

/// The places one relocating variable names (module doc), or why it cannot be resolved.
fn relocated_bases(
    name: &str,
    shape: Value,
    value: &std::ffi::OsStr,
    home: &Path,
    env: &HomeEnv,
) -> Result<Vec<PathBuf>, GitMetadataUnread> {
    let relative = "a relative path, which each tool reads from its own working directory";
    match shape {
        Value::Path => {
            let base = PathBuf::from(value);
            if base.is_absolute() {
                Ok(vec![base])
            } else {
                Err(unresolvable(name, value, relative))
            }
        }
        Value::List => {
            let mut bases = Vec::new();
            for base in std::env::split_paths(value) {
                if base.as_os_str().is_empty() {
                    continue;
                }
                if !base.is_absolute() {
                    return Err(unresolvable(name, base.as_os_str(), relative));
                }
                bases.push(base);
            }
            Ok(bases)
        }
        Value::ConfigName | Value::HomeName => {
            let rel = Path::new(value);
            let escapes = rel
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)));
            if escapes {
                return Err(unresolvable(
                    name,
                    value,
                    "not a plain name beneath its directory (absolute, or with `..`)",
                ));
            }
            if shape == Value::HomeName {
                return Ok(vec![home.join(rel)]);
            }
            let mut bases = vec![home.join(".config").join(rel)];
            bases.extend(env.absolute("XDG_CONFIG_HOME").map(|xdg| xdg.join(rel)));
            Ok(bases)
        }
    }
}

fn candidates(home: &Path, env: &HomeEnv, unread: &mut Vec<GitMetadataUnread>) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    let mut add = |base: &Path, rels: &[&str], class: Class| {
        out.extend(rels.iter().map(|rel| Candidate {
            path: base.join(rel),
            rel: (*rel).to_string(),
            class,
            always: ALWAYS_LISTED.contains(rel),
        }));
    };
    add(home, HOME_PROTECTED_FILES, Class::File);
    add(home, HOME_SECRET_FILES, Class::File);
    add(home, FUIGO_HOME_PROTECTED_FILES, Class::File);
    add(home, HOME_PROTECTED_DIRS, Class::StartupDir);
    add(home, FUIGO_HOME_PROTECTED_DIRS, Class::StartupDir);
    add(home, HOME_PROTECTED_TOOL_TREES, Class::Tree);
    add(home, HOME_SECRET_DIRS, Class::Tree);
    add(home, FUIGO_HOME_PROTECTED_TOOL_TREES, Class::Tree);
    for (name, value) in &env.vars {
        // Empty is unset to these tools
        if value.is_empty() {
            continue;
        }
        let Some((_, shape, rels)) = RELOCATIONS.iter().find(|(known, _, _)| known == name) else {
            continue;
        };
        let bases = match relocated_bases(name, *shape, value, home, env) {
            Ok(bases) => bases,
            Err(error) => {
                unread.push(error);
                continue;
            }
        };
        for base in bases {
            for (rel, class) in rels.iter() {
                out.push(Candidate {
                    path: if rel.is_empty() {
                        base.clone()
                    } else {
                        base.join(rel)
                    },
                    rel: String::new(),
                    class: *class,
                    always: ALWAYS_LISTED_RELOCATIONS.contains(name),
                });
            }
        }
    }
    out
}

/// The kind an entry stands for now: what exists (a directory is a tree; a regular file, or any
/// other node a command could replace with one, a file), else its class's missing kind. A link to
/// a device (`~/.bashrc -> /dev/null`) is a file too: its link node is protected with it, so it
/// cannot be re-pointed. A type that cannot be read refuses.
fn entry_kind(path: &Path, rel: &str, class: Class) -> Result<GitPathKind, GitMetadataUnread> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_dir() => Ok(GitPathKind::Dir),
        Ok(meta) if meta.is_file() => Ok(GitPathKind::File),
        Ok(_) => Ok(GitPathKind::File),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(class.missing_kind(rel))
        }
        Err(error) => Err(GitMetadataUnread::Unreadable {
            path: path.to_path_buf(),
            reason: error.to_string(),
        }),
    }
}

/// The nearest directory of `path` that exists (as the kernel resolves it), or that the Linux
/// plan creates before the sandbox starts (`created`: missing startup directories inside a
/// writable root, with their parents), so the scan inside the sandbox reads the same layout.
fn nearest_existing(path: &Path, created: &[PathBuf]) -> PathBuf {
    let mut dir = canonical_path(path);
    dir.pop();
    while std::fs::symlink_metadata(&dir).is_err() && !created.iter().any(|c| is_within(c, &dir)) {
        if !dir.pop() {
            break;
        }
    }
    dir
}

/// The home entries for a sandbox whose workspace is `ws` (module doc).
pub(crate) fn home_entries_in(
    ws: &Path,
    user_home: Option<&Path>,
    roots: &Roots,
    env: &HomeEnv,
) -> HomeEntries {
    let mut unread = Vec::new();
    let Some(home) = user_home.filter(|home| !home.as_os_str().is_empty()) else {
        return HomeEntries::default();
    };
    if !home.is_absolute() {
        unread.push(GitMetadataUnread::Unreadable {
            path: home.to_path_buf(),
            reason: "the home directory is a relative path".to_string(),
        });
        return HomeEntries {
            protected: Vec::new(),
            unread,
        };
    }
    let workspace = canonical_path(ws);
    let home_canonical = canonical_path(home);
    let [write_roots, essential, configured, temp] = roots.canonical();
    let within = |path: &Path, roots: &[PathBuf]| roots.iter().any(|root| is_within(path, root));
    let mut shared: Vec<PathBuf> = SHARED_DIRS
        .iter()
        .map(|rel| canonical_path(&home.join(rel)))
        .collect();
    shared.extend(
        ["XDG_CONFIG_HOME", "XDG_DATA_HOME"]
            .iter()
            .filter_map(|name| env.absolute(name))
            .map(|dir| canonical_path(&dir)),
    );
    let cargo_homes: Vec<PathBuf> = std::iter::once(home.join(".cargo"))
        .chain(env.absolute("CARGO_HOME"))
        .map(|dir| canonical_path(&dir))
        .collect();
    let mut protected = Vec::new();
    let mut listed_trees: Vec<ListedTree> = Vec::new();
    let mut pins: Vec<PathBuf> = Vec::new();
    let mut scanned = Vec::new();
    for candidate in candidates(home, env, &mut unread) {
        match entry_kind(&candidate.path, &candidate.rel, candidate.class) {
            Ok(kind) => scanned.push((candidate, kind)),
            Err(error) => unread.push(error),
        }
    }
    // What exists by the time the sandbox starts: the startup directories the Linux plan creates
    // (and so their parents), and the grants the profile creates
    let mut created: Vec<PathBuf> = scanned
        .iter()
        .filter(|(candidate, kind)| {
            *kind == GitPathKind::Dir && std::fs::symlink_metadata(&candidate.path).is_err()
        })
        .map(|(candidate, _)| canonical_path(&candidate.path))
        .filter(|dir| within(dir, &write_roots))
        .collect();
    created.extend(
        write_roots
            .iter()
            .filter(|root| std::fs::symlink_metadata(root).is_err())
            .cloned(),
    );
    for (candidate, kind) in &scanned {
        let (path, kind) = (&candidate.path, *kind);
        protected.extend(protect_spellings(path, kind));
        // macOS: a missing directory on the way cannot be created (or renamed) into place
        if kind.is_optional() || kind == GitPathKind::Dir {
            let mut dir = fold_dots(path);
            while dir.pop() && dir != home && std::fs::symlink_metadata(&dir).is_err() {
                protected.push(GitProtectedPath {
                    path: dir.clone(),
                    kind: GitPathKind::MissingAncestor,
                });
            }
        }
        // A tree, existing or not (a missing tool tree, secret store or `Library/` dir is
        // `OptionalDir`): judged on its spelling before the profile makes any grant, so a grant
        // the profile would create inside a missing tree refuses too (Grok HIGH 2)
        if matches!(kind, GitPathKind::Dir | GitPathKind::OptionalDir) {
            let tree = canonical_path(path);
            // A workspace in a protected tree would be read-only: refuse rather than start one
            if is_within(&workspace, &fold_dots(path)) || is_within(&workspace, &tree) {
                unread.push(GitMetadataUnread::Unreadable {
                    path: path.clone(),
                    reason: format!(
                        "holds the workspace {}, and the sandbox keeps it read-only; run Fuigo \
                         in another directory or with the sandbox off",
                        ws.display()
                    ),
                });
            } else if let Some(root) = write_roots
                .iter()
                .find(|root| is_within(root, &tree) || is_within(root, &fold_dots(path)))
            {
                // Any other writable root inside it (a grant of `~/.config/nvim/lua`): the Linux
                // plan binds only what lies inside a root, so the tree would stay writable there
                unread.push(GitMetadataUnread::Unreadable {
                    path: path.clone(),
                    reason: format!(
                        "holds the writable root {}, which the sandbox cannot keep read-only \
                         inside a protected tree; remove the grant or run with the sandbox off",
                        root.display()
                    ),
                });
            }
            // Only a tree that exists by the start is listed (and binds a pin inside it)
            if kind == GitPathKind::Dir {
                listed_trees.push(ListedTree {
                    path: tree,
                    refuses: candidate.class == Class::StartupDir,
                    always: candidate.class == Class::StartupDir || candidate.always,
                });
            }
        }
        // Linux: a name not created at start (module doc)
        let creatable = kind.is_optional()
            && cfg!(target_os = "linux")
            && !candidate.rel.starts_with("Library/");
        if !creatable {
            continue;
        }
        let dir = nearest_existing(path, &created);
        if !within(&dir, &write_roots) {
            continue;
        }
        // Only the name's own directory (`~/.cargo` for `~/.cargo/config`) is a tool's to pin
        let parent = canonical_path(path).parent().map(Path::to_path_buf);
        let pinnable = parent.as_ref() == Some(&dir)
            && !is_within(&workspace, &dir)
            && !is_within(&home_canonical, &dir)
            && !shared.contains(&dir)
            && !essential.iter().any(|root| is_within(root, &dir));
        if pinnable {
            if !pins.contains(&dir) {
                pins.push(dir);
            }
        } else if within(&dir, &configured) || !within(&dir, &temp) {
            unread.push(GitMetadataUnread::Unreadable {
                path: path.clone(),
                reason: format!(
                    "does not exist and {} is writable in this profile (the workspace, a \
                     read_write grant or the Fuigo home); the Linux sandbox cannot stop a command \
                     creating it there. \
                     Run Fuigo in a project directory, grant only the subdirectories a tool \
                     needs (~/.cargo, ~/.cargo/registry), or create the file outside the sandbox",
                    dir.display()
                ),
            });
        }
    }
    for pin in pins {
        // A pin inside a protected tree is that tree's bind already
        if listed_trees.iter().any(|tree| is_within(&pin, &tree.path)) {
            continue;
        }
        if cargo_homes.contains(&pin) {
            protected.extend(CARGO_CACHE_DIRS.iter().map(|name| GitProtectedPath {
                path: pin.join(name),
                kind: GitPathKind::CacheDir,
            }));
            protected.extend(CARGO_CACHE_FILES.iter().map(|name| GitProtectedPath {
                path: pin.join(name),
                kind: GitPathKind::CacheFile,
            }));
        }
        protected.push(GitProtectedPath {
            path: pin,
            kind: GitPathKind::PinnedDir,
        });
    }
    protected.sort();
    protected.dedup();
    for refusal in hard_link_refusals(&protected, &listed_trees, &write_roots) {
        if !unread.contains(&refusal) {
            unread.push(refusal);
        }
    }
    HomeEntries { protected, unread }
}

/// Entries one protected tree's listing reads: past it a startup tree refuses, a tool tree or
/// secret store is left unlisted (module doc).
const HARD_LINK_WALK_LIMIT: usize = 4096;

/// Entries one writable root's search for an alias reads before it refuses.
const ALIAS_SEARCH_LIMIT: usize = 65536;

/// Protected regular files a command could change through another hard link:
/// - a protected file inside a writable root with a second link refuses outright (the Linux bind
///   requires one link, and the link may lie anywhere);
/// - any protected file whose links are not all protected names found here (rustup's
///   `~/.cargo/bin` proxies are links of one another) has every writable root searched for the
///   other link (a mount beneath a root may hold another device), which refuses when found, or
///   when the search cannot finish.
///
/// Files come from every file entry and from `listed_trees`: the protected trees inside a
/// writable root, and startup trees and small secret stores wherever they lie.
fn hard_link_refusals(
    entries: &[GitProtectedPath],
    listed_trees: &[ListedTree],
    write_roots: &[PathBuf],
) -> Vec<GitMetadataUnread> {
    let mut out = Vec::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let within_a_root = |path: &Path| write_roots.iter().any(|root| is_within(path, root));
        let linked = |path: &Path, nlink: u64, reason: String| GitMetadataUnread::Unreadable {
            path: path.to_path_buf(),
            reason: format!(
                "has a hard link (st_nlink={nlink}) {reason}; a write through it would change a \
                 file that runs code outside the sandbox. Remove the extra link"
            ),
        };
        // (dev, ino) -> (nlink, owner, protected names)
        let mut rows: Vec<LinkedFile> = Vec::new();
        let mut add = |path: &Path, meta: &std::fs::Metadata| {
            if !meta.is_file() || meta.nlink() < 2 {
                return;
            }
            let inode = (meta.dev(), meta.ino());
            let name = canonical_path(path);
            match rows.iter_mut().find(|row| row.inode == inode) {
                Some(row) if row.names.contains(&name) => {}
                Some(row) => row.names.push(name),
                None => rows.push(LinkedFile {
                    inode,
                    nlink: meta.nlink(),
                    owner: meta.uid(),
                    names: vec![name],
                }),
            }
        };
        for entry in entries {
            if entry.kind != GitPathKind::File {
                continue;
            }
            let Ok(meta) = std::fs::metadata(&entry.path) else {
                continue;
            };
            if meta.is_file() && meta.nlink() > 1 && within_a_root(&canonical_path(&entry.path)) {
                out.push(linked(
                    &entry.path,
                    meta.nlink(),
                    "and lies inside a writable root".to_string(),
                ));
            }
            add(&entry.path, &meta);
        }
        for listed in listed_trees {
            let tree = &listed.path;
            let inside = within_a_root(tree);
            if !inside && !listed.always {
                continue;
            }
            // A listing error refuses wherever the tree is walked (a known name in an unlistable
            // tree is still reachable); running past the bound refuses only a startup tree inside
            // a writable root (outside, it is listed as far as the bound)
            let refuses = &(listed.refuses && inside);
            let mut pending = vec![tree.clone()];
            let mut seen = 0usize;
            'walk: while let Some(dir) = pending.pop() {
                let unlisted = |error: &dyn std::fmt::Display| GitMetadataUnread::Unreadable {
                    path: dir.clone(),
                    reason: format!("cannot list it for hard-link aliases: {error}"),
                };
                let children = match std::fs::read_dir(&dir) {
                    Ok(children) => children,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => {
                        out.push(unlisted(&error));
                        continue;
                    }
                };
                for child in children {
                    let child = match child {
                        Ok(child) => child,
                        Err(error) => {
                            out.push(unlisted(&error));
                            continue 'walk;
                        }
                    };
                    seen += 1;
                    if seen > HARD_LINK_WALK_LIMIT {
                        if *refuses {
                            out.push(GitMetadataUnread::GitDirsUnlisted {
                                tree: tree.clone(),
                                limit: HARD_LINK_WALK_LIMIT,
                            });
                        }
                        break 'walk;
                    }
                    let path = child.path();
                    let Ok(meta) = std::fs::symlink_metadata(&path) else {
                        continue;
                    };
                    if meta.is_dir() {
                        pending.push(path);
                    } else {
                        add(&path, &meta);
                    }
                }
            }
        }
        let open: Vec<_> = rows
            .iter()
            .filter(|row| (row.names.len() as u64) < row.nlink)
            .collect();
        if open.is_empty() {
            return out;
        }
        let protected_name = |path: &Path| {
            let name = canonical_path(path);
            entries.iter().any(|entry| {
                let at = canonical_path(&entry.path);
                entry.kind.is_denied_by_name()
                    && entry.kind != GitPathKind::LinkNode
                    && (at == name || (entry.kind.is_dir() && is_within(&name, &at)))
            })
        };
        for root in write_roots {
            // Every root is searched: a mount beneath it can hold another device's alias
            if std::fs::symlink_metadata(root).is_err() {
                continue;
            }
            let mut pending = std::collections::VecDeque::from([root.clone()]);
            let mut read = 0usize;
            'search: while let Some(dir) = pending.pop_front() {
                let entries_here = match std::fs::read_dir(&dir) {
                    Ok(entries_here) => entries_here,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    // Another user's directory a command can neither list nor search holds no
                    // name it could write; one it can search (mode 0711) may
                    Err(_) if !owned_by(&dir, &open) && !searchable(&dir) => continue,
                    Err(error) => {
                        out.push(GitMetadataUnread::Unreadable {
                            path: dir.clone(),
                            reason: format!(
                                "cannot be searched for a hard link of a protected file: {error}"
                            ),
                        });
                        break 'search;
                    }
                };
                for child in entries_here {
                    let child = match child {
                        Ok(child) => child,
                        Err(error) => {
                            out.push(GitMetadataUnread::Unreadable {
                                path: dir.clone(),
                                reason: format!(
                                    "cannot be searched for a hard link of a protected file: \
                                     {error}"
                                ),
                            });
                            break 'search;
                        }
                    };
                    read += 1;
                    if read > ALIAS_SEARCH_LIMIT {
                        let row = open[0];
                        out.push(linked(
                            &row.names[0],
                            row.nlink,
                            format!(
                                "that no protected name accounts for, and {} is too large to \
                                 search for it",
                                root.display()
                            ),
                        ));
                        break 'search;
                    }
                    let path = child.path();
                    let meta = match std::fs::symlink_metadata(&path) {
                        Ok(meta) => meta,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(error) => {
                            out.push(GitMetadataUnread::Unreadable {
                                path: path.clone(),
                                reason: format!(
                                    "cannot be checked for a hard link of a protected file: \
                                     {error}"
                                ),
                            });
                            break 'search;
                        }
                    };
                    if meta.file_type().is_symlink() {
                        continue;
                    }
                    if meta.is_dir() {
                        pending.push_back(path);
                        continue;
                    }
                    let inode = (meta.dev(), meta.ino());
                    if let Some(row) = open.iter().find(|row| row.inode == inode)
                        && !protected_name(&path)
                    {
                        let at = format!("at {}", path.display());
                        out.push(linked(&row.names[0], row.nlink, at));
                        break 'search;
                    }
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (entries, listed_trees, write_roots);
    }
    out
}

/// Whether a command could reach a name beneath `dir` it cannot list.
#[cfg(unix)]
fn searchable(dir: &Path) -> bool {
    std::fs::symlink_metadata(dir.join(".")).is_ok()
}

/// A tree listed for hard links: refused on when it cannot be listed (a startup tree inside a
/// writable root), or listed wherever it lies (a startup tree, a small secret store).
struct ListedTree {
    path: PathBuf,
    refuses: bool,
    always: bool,
}

/// A protected regular file with more than one link: one row per inode, with every protected name
/// found for it.
#[cfg(unix)]
struct LinkedFile {
    inode: (u64, u64),
    nlink: u64,
    owner: u32,
    names: Vec<PathBuf>,
}

/// Whether `dir` belongs to the owner of one of the `open` files (a name beneath it could be
/// made reachable).
#[cfg(unix)]
fn owned_by(dir: &Path, open: &[&LinkedFile]) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::symlink_metadata(dir).is_ok_and(|meta| open.iter().any(|row| row.owner == meta.uid()))
}

/// The roots every profile keeps writable whatever the user configures: the temp directories and
/// the Fuigo home (and its sessions).
fn essential_roots() -> Vec<PathBuf> {
    let fuigo = crate::paths::fuigo_home();
    let mut roots = crate::paths::temp_writable_paths();
    roots.push(fuigo.join("sessions"));
    roots.push(fuigo);
    roots
}

/// The home write-deny for a sandbox whose writable roots are `write_roots` (of which the user
/// configured `configured`: the workspace and the profile's `read_write` grants), resolved
/// against this process's home and environment. Fails closed on anything unread.
pub(crate) fn resolve_home_write_deny(
    workspace: &Path,
    write_roots: &[PathBuf],
    configured: &[PathBuf],
) -> anyhow::Result<Vec<GitProtectedPath>> {
    let home = fuigo_dirs::home_dir();
    let roots = Roots {
        write: write_roots.to_vec(),
        essential: essential_roots(),
        configured: configured.to_vec(),
        temp: crate::paths::temp_writable_paths(),
    };
    let got = home_entries_in(workspace, home.as_deref(), &roots, &HomeEnv::from_host());
    if !got.unread.is_empty() {
        let detail = got
            .unread
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        anyhow::bail!(
            "home write-deny cannot protect a startup file that runs code outside the sandbox: \
             {detail}. Fix or remove it, or run with the sandbox off."
        );
    }
    Ok(got.protected)
}

#[cfg(test)]
#[path = "home_write_deny_tests.rs"]
mod tests;
