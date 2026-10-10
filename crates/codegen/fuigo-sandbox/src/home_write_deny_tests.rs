//! P177: the home write-deny entry list (ported from upstream `protected.rs`'s home tables), its
//! fail-closed cases, the Linux pins and refusals for names not yet created, and the Linux bwrap
//! plan for home entries.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::{
    FUIGO_HOME_PROTECTED_DIRS, FUIGO_HOME_PROTECTED_FILES, FUIGO_HOME_PROTECTED_TOOL_TREES,
    HOME_PROTECTED_DIRS, HOME_PROTECTED_FILES, HOME_PROTECTED_TOOL_TREES, HOME_SECRET_DIRS,
    HOME_SECRET_FILES, HomeEntries, HomeEnv, Roots, home_entries_in,
};
use crate::git_write_deny::{GitPathKind, GitProtectedPath};

fn scratch(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "fuigo-p177-home-{}-{tag}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    dunce::canonicalize(&root).unwrap()
}

/// `(root, home, workspace)`: the home and a workspace beside it.
fn layout(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
    let root = scratch(tag);
    let home = root.join("home");
    let ws = root.join("ws");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&ws).unwrap();
    (root, home, ws)
}

/// Writable roots the user configured (the workspace, a `read_write` grant).
fn configured(roots: &[&Path]) -> Roots {
    let write: Vec<PathBuf> = roots.iter().map(|root| root.to_path_buf()).collect();
    Roots {
        configured: write.clone(),
        write,
        essential: Vec::new(),
        temp: Vec::new(),
    }
}

/// Writable roots the sandbox always keeps (a home under a temp directory).
fn essential(roots: &[&Path]) -> Roots {
    let write: Vec<PathBuf> = roots.iter().map(|root| root.to_path_buf()).collect();
    Roots {
        essential: write.clone(),
        temp: write.clone(),
        write,
        configured: Vec::new(),
    }
}

fn scan(ws: &Path, home: &Path, roots: &Roots, env: &HomeEnv) -> HomeEntries {
    home_entries_in(ws, Some(home), roots, env)
}

fn entries(ws: &Path, home: &Path, roots: &Roots) -> Vec<GitProtectedPath> {
    let got = scan(ws, home, roots, &HomeEnv::default());
    assert!(got.unread.is_empty(), "{:?}", got.unread);
    got.protected
}

fn refusals(got: &HomeEntries) -> String {
    got.unread
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

fn has(got: &[GitProtectedPath], path: impl AsRef<Path>, kind: GitPathKind) -> bool {
    got.iter()
        .any(|entry| entry.path == path.as_ref() && entry.kind == kind)
}

fn named(got: &[GitProtectedPath], path: impl AsRef<Path>) -> bool {
    got.iter().any(|entry| entry.path == path.as_ref())
}

fn env(vars: &[(&'static str, &str)]) -> HomeEnv {
    HomeEnv {
        vars: vars
            .iter()
            .map(|(name, value)| (*name, OsString::from(value)))
            .collect(),
    }
}

/// The upstream tables are ported entry for entry (counts and spellings pinned), and the brief's
/// named files are among them.
#[test]
fn p177_upstream_home_tables_are_ported_whole() {
    assert_eq!(HOME_PROTECTED_FILES.len(), 29);
    assert_eq!(HOME_PROTECTED_DIRS.len(), 12);
    assert_eq!(HOME_PROTECTED_TOOL_TREES.len(), 6);
    assert_eq!(HOME_SECRET_DIRS.len(), 9);
    assert_eq!(HOME_SECRET_FILES.len(), 7);
    for name in [
        ".bashrc",
        ".zshrc",
        ".profile",
        ".cargo/config.toml",
        ".cargo/config",
        ".pip/pip.conf",
        ".gitconfig",
        ".vimrc",
    ] {
        assert!(HOME_PROTECTED_FILES.contains(&name), "{name}");
    }
    assert!(HOME_SECRET_FILES.contains(&".npmrc"));
    assert!(HOME_SECRET_DIRS.contains(&".ssh"));
}

/// Every table entry is protected under the home; what is missing takes its class's kind: a file
/// is optional (never created), a startup directory a tree (created on Linux), a macOS-only one,
/// a tool tree and a secret store optional trees. The home lies in a temp root here, so no
/// missing name refuses.
#[test]
fn p177_every_home_entry_is_protected_with_its_missing_kind() {
    let (root, home, ws) = layout("missing");
    let got = entries(&ws, &home, &essential(&[&home]));
    for rel in HOME_PROTECTED_FILES
        .iter()
        .chain(HOME_SECRET_FILES)
        .chain(FUIGO_HOME_PROTECTED_FILES)
    {
        assert!(
            has(&got, home.join(rel), GitPathKind::OptionalFile),
            "{rel}: {got:?}"
        );
    }
    for rel in HOME_PROTECTED_DIRS.iter().chain(FUIGO_HOME_PROTECTED_DIRS) {
        let kind = if rel.starts_with("Library/") {
            GitPathKind::OptionalDir
        } else {
            GitPathKind::Dir
        };
        assert!(has(&got, home.join(rel), kind), "{rel}: {got:?}");
    }
    for rel in HOME_PROTECTED_TOOL_TREES
        .iter()
        .chain(HOME_SECRET_DIRS)
        .chain(FUIGO_HOME_PROTECTED_TOOL_TREES)
    {
        assert!(
            has(&got, home.join(rel), GitPathKind::OptionalDir),
            "{rel}: {got:?}"
        );
    }
    // The caches cargo writes on every build are never denied (on Linux `~/.cargo` is pinned,
    // its caches kept writable)
    for rel in [".cargo", ".cargo/registry", ".cargo/git", ".npm", ".cache"] {
        let denied = got
            .iter()
            .any(|entry| {
                entry.path == home.join(rel)
                    && entry.kind.is_denied_by_name()
                    && entry.kind != GitPathKind::MissingAncestor
            });
        assert!(!denied, "{rel} must stay writable: {got:?}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// An existing entry is protected as what it is: a file as a file, a directory as a tree.
#[test]
fn p177_existing_entries_take_their_type() {
    let (root, home, ws) = layout("existing");
    std::fs::write(home.join(".bashrc"), "x").unwrap();
    std::fs::create_dir_all(home.join(".cargo/registry/cache")).unwrap();
    std::fs::write(home.join(".cargo/config.toml"), "x").unwrap();
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::create_dir_all(home.join(".nvm")).unwrap();
    // A directory where a file is listed is a tree
    std::fs::create_dir_all(home.join(".cargo/config")).unwrap();
    let got = entries(&ws, &home, &configured(&[&ws]));
    assert!(
        has(&got, home.join(".bashrc"), GitPathKind::File),
        "{got:?}"
    );
    assert!(
        has(&got, home.join(".cargo/config.toml"), GitPathKind::File),
        "{got:?}"
    );
    assert!(
        has(&got, home.join(".cargo/config"), GitPathKind::Dir),
        "{got:?}"
    );
    assert!(has(&got, home.join(".ssh"), GitPathKind::Dir), "{got:?}");
    assert!(has(&got, home.join(".nvm"), GitPathKind::Dir), "{got:?}");
    assert!(!named(&got, home.join(".cargo/registry")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r1 #4: a startup name held by another kind of node (a FIFO) is protected as a file, so
/// it cannot be swapped for a regular one.
#[cfg(unix)]
#[test]
fn p177_a_special_file_entry_is_protected_as_a_file() {
    let (root, home, ws) = layout("fifo");
    let fifo = home.join(".bashrc");
    let c_path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    // SAFETY: a valid NUL-terminated path
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) }, 0);
    let got = entries(&ws, &home, &configured(&[&ws]));
    assert!(has(&got, &fifo, GitPathKind::File), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// A symlinked startup file is protected where it leads, and the link itself as a link node.
#[cfg(unix)]
#[test]
fn p177_a_symlinked_entry_is_protected_where_it_leads() {
    let (root, home, ws) = layout("symlinked");
    std::fs::create_dir_all(root.join("dotfiles")).unwrap();
    std::fs::write(root.join("dotfiles/bashrc"), "x").unwrap();
    std::os::unix::fs::symlink(root.join("dotfiles/bashrc"), home.join(".bashrc")).unwrap();
    let got = entries(&ws, &home, &configured(&[]));
    assert!(
        has(&got, root.join("dotfiles/bashrc"), GitPathKind::File),
        "{got:?}"
    );
    assert!(
        has(&got, home.join(".bashrc"), GitPathKind::LinkNode),
        "{got:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A link to a device carries no code, but the link is protected so it cannot be re-pointed.
#[cfg(unix)]
#[test]
fn p177_a_link_to_a_device_is_protected_as_a_link_node() {
    let (root, home, ws) = layout("devlink");
    std::os::unix::fs::symlink("/dev/null", home.join(".bashrc")).unwrap();
    let got = entries(&ws, &home, &configured(&[]));
    assert!(
        has(&got, home.join(".bashrc"), GitPathKind::LinkNode),
        "{got:?}"
    );
    assert!(!named(&got, "/dev/null"), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r1 #2: a workspace inside a protected tree refuses (the tree stays protected, so the
/// workspace would be read-only); the home as workspace is not inside one.
#[test]
fn p177_a_workspace_inside_a_protected_tree_refuses() {
    let (root, home, _) = layout("wsinside");
    for tree in [".config/nvim", ".ssh"] {
        let ws = home.join(tree).join("sub");
        std::fs::create_dir_all(&ws).unwrap();
        let got = scan(&ws, &home, &configured(&[&ws]), &HomeEnv::default());
        let text = refusals(&got);
        assert!(text.contains("holds the workspace"), "{tree}: {text}");
        assert!(
            has(&got.protected, home.join(tree), GitPathKind::Dir),
            "{tree}"
        );
    }
    let got = scan(&home, &home, &essential(&[&home]), &HomeEnv::default());
    assert!(
        !refusals(&got).contains("holds the workspace"),
        "{}",
        refusals(&got)
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The variables that move a tool's startup files are followed (Fuigo-added).
#[test]
fn p177_relocated_startup_files_are_protected() {
    let (root, home, ws) = layout("relocated");
    let elsewhere = root.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let cargo = elsewhere.join("cargo");
    let xdg = elsewhere.join("xdg");
    let zdot = elsewhere.join("zdot");
    let rustup = elsewhere.join("rustup");
    let gradle = elsewhere.join("gradle");
    let docker = elsewhere.join("docker");
    let nvm = elsewhere.join("nvm");
    let npmrc = elsewhere.join("npmrc");
    let pipconf = elsewhere.join("pip.conf");
    let vars = env(&[
        ("CARGO_HOME", cargo.to_str().unwrap()),
        ("XDG_CONFIG_HOME", xdg.to_str().unwrap()),
        ("ZDOTDIR", zdot.to_str().unwrap()),
        ("RUSTUP_HOME", rustup.to_str().unwrap()),
        ("GRADLE_USER_HOME", gradle.to_str().unwrap()),
        ("DOCKER_CONFIG", docker.to_str().unwrap()),
        ("NVM_DIR", nvm.to_str().unwrap()),
        ("NPM_CONFIG_USERCONFIG", npmrc.to_str().unwrap()),
        ("PIP_CONFIG_FILE", pipconf.to_str().unwrap()),
    ]);
    let got = scan(&ws, &home, &essential(&[&elsewhere]), &vars);
    assert!(got.unread.is_empty(), "{}", refusals(&got));
    let got = got.protected;
    for file in [
        cargo.join("config.toml"),
        cargo.join("config"),
        cargo.join("credentials.toml"),
        cargo.join("env"),
        xdg.join("fish/config.fish"),
        xdg.join("pip/pip.conf"),
        zdot.join(".zshrc"),
        zdot.join(".zshenv"),
        gradle.join("init.gradle"),
        docker.join("config.json"),
        npmrc.clone(),
        pipconf.clone(),
    ] {
        assert!(
            has(&got, &file, GitPathKind::OptionalFile),
            "{}: {got:?}",
            file.display()
        );
    }
    for dir in [
        cargo.join("bin"),
        xdg.join("autostart"),
        xdg.join("systemd/user"),
        xdg.join("nvim"),
        gradle.join("init.d"),
    ] {
        assert!(
            has(&got, &dir, GitPathKind::Dir),
            "{}: {got:?}",
            dir.display()
        );
    }
    assert!(
        has(&got, rustup.join("toolchains"), GitPathKind::OptionalDir),
        "{got:?}"
    );
    assert!(has(&got, &nvm, GitPathKind::OptionalDir), "{got:?}");
    // The home's own entries stay
    assert!(
        has(
            &got,
            home.join(".cargo/config.toml"),
            GitPathKind::OptionalFile
        ),
        "{got:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A relative relocating variable or home refuses (each tool resolves it from its own working
/// directory); an empty one is unset.
#[test]
fn p177_a_relative_home_or_relocation_refuses() {
    let (root, home, ws) = layout("relative");
    let none = configured(&[]);
    for name in ["CARGO_HOME", "ZDOTDIR", "XDG_CONFIG_HOME", "RUSTUP_HOME"] {
        let got = scan(&ws, &home, &none, &env(&[(name, "rel/dir")]));
        assert_eq!(got.unread.len(), 1, "{name}: {}", refusals(&got));
        assert!(refusals(&got).contains(name), "{}", refusals(&got));
    }
    let got = scan(&ws, &home, &none, &env(&[("CARGO_HOME", "")]));
    assert!(got.unread.is_empty(), "{}", refusals(&got));
    let got = home_entries_in(&ws, Some(Path::new("rel/home")), &none, &HomeEnv::default());
    assert_eq!(got.unread.len(), 1, "{}", refusals(&got));
    // No home: nothing to protect, nothing refused
    let got = home_entries_in(&ws, None, &none, &HomeEnv::default());
    assert!(got.unread.is_empty() && got.protected.is_empty(), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// The relocating variables are read from the environment by name.
#[test]
fn p177_home_env_reads_the_relocating_variables() {
    let got = HomeEnv::from_lookup(|name| (name == "CARGO_HOME").then(|| OsString::from("/c")));
    assert_eq!(got.vars, vec![("CARGO_HOME", OsString::from("/c"))]);
}

/// A protected file with a hard link inside a writable root refuses; one whose other link lies
/// outside every writable root does not (Astra r1 #6), whatever device the roots are on.
#[cfg(unix)]
#[test]
fn p177_a_hard_link_refuses_only_where_a_command_could_write_it() {
    let (root, home, ws) = layout("hardlink");
    std::fs::write(home.join(".bashrc"), "x").unwrap();
    std::fs::hard_link(home.join(".bashrc"), ws.join("innocent.txt")).unwrap();
    let got = scan(&ws, &home, &configured(&[&ws]), &HomeEnv::default());
    assert!(
        refusals(&got).contains("innocent.txt"),
        "{}",
        refusals(&got)
    );
    // The other link is a backup outside the workspace: the search finds nothing
    std::fs::remove_file(ws.join("innocent.txt")).unwrap();
    std::fs::hard_link(home.join(".bashrc"), root.join("bashrc.bak")).unwrap();
    let got = scan(&ws, &home, &configured(&[&ws]), &HomeEnv::default());
    assert!(got.unread.is_empty(), "{}", refusals(&got));
    // No writable root at all
    let got = scan(&ws, &home, &configured(&[]), &HomeEnv::default());
    assert!(got.unread.is_empty(), "{}", refusals(&got));
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r1 #3: files in a secret store inside a writable root are checked too.
#[cfg(unix)]
#[test]
fn p177_a_hard_linked_file_in_a_secret_store_refuses() {
    let (root, home, ws) = layout("secretlink");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::write(home.join(".ssh/config"), "Host *\n").unwrap();
    std::fs::create_dir_all(home.join("project")).unwrap();
    std::fs::hard_link(home.join(".ssh/config"), home.join("project/ssh-alias")).unwrap();
    let got = scan(&ws, &home, &essential(&[&home]), &HomeEnv::default());
    assert!(refusals(&got).contains("ssh-alias"), "{}", refusals(&got));
    let _ = std::fs::remove_dir_all(&root);
}

/// Links among protected names inside a protected tree (rustup's proxies) are accounted for; a
/// protected file entry inside a writable root with a second link refuses (Astra r1 #5: the
/// Linux bind needs one link), and outside every root it is accounted for.
#[cfg(unix)]
#[test]
fn p177_links_among_protected_names_are_accounted_for() {
    let (root, home, ws) = layout("proxies");
    let bin = home.join(".cargo/bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(bin.join("rustup"), "x").unwrap();
    for proxy in ["cargo", "rustc", "rustdoc"] {
        std::fs::hard_link(bin.join("rustup"), bin.join(proxy)).unwrap();
    }
    let got = scan(&ws, &home, &essential(&[&home]), &HomeEnv::default());
    assert!(got.unread.is_empty(), "{}", refusals(&got));
    // A proxy linked out of the protected tree into the root is an alias
    std::fs::hard_link(bin.join("rustup"), home.join("stray")).unwrap();
    let got = scan(&ws, &home, &essential(&[&home]), &HomeEnv::default());
    assert!(refusals(&got).contains("stray"), "{}", refusals(&got));
    std::fs::remove_file(home.join("stray")).unwrap();
    // Two protected file entries linked to each other
    std::fs::write(home.join(".bashrc"), "x").unwrap();
    std::fs::hard_link(home.join(".bashrc"), home.join(".bash_profile")).unwrap();
    let got = scan(&ws, &home, &configured(&[]), &HomeEnv::default());
    assert!(got.unread.is_empty(), "{}", refusals(&got));
    let got = scan(&ws, &home, &essential(&[&home]), &HomeEnv::default());
    assert!(
        refusals(&got).contains("inside a writable root"),
        "{}",
        refusals(&got)
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A startup tree inside a writable root that cannot be listed may hide an alias: refuses. Run
/// with an unprivileged user's permissions, also as root.
#[cfg(unix)]
#[test]
fn p177_an_unlistable_startup_tree_refuses() {
    use std::os::unix::fs::PermissionsExt;
    let (root, home, ws) = layout("unlistable");
    let bin = home.join(".local/bin");
    std::fs::create_dir_all(bin.join("sub")).unwrap();
    std::fs::set_permissions(bin.join("sub"), std::fs::Permissions::from_mode(0o111)).unwrap();
    let unlistable = bin.join("sub");
    let got = unprivileged(&unlistable, || {
        scan(&ws, &home, &essential(&[&home]), &HomeEnv::default())
    });
    std::fs::set_permissions(&unlistable, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(refusals(&got).contains("hard-link"), "{}", refusals(&got));
    let _ = std::fs::remove_dir_all(&root);
}

/// Runs `scan` with an unprivileged user's file permissions (as in the git write-deny tests).
#[cfg(unix)]
fn unprivileged<T: Send>(unlistable: &Path, scan: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                // SAFETY: geteuid is always safe.
                if unsafe { libc::geteuid() } == 0 {
                    drop_file_identity();
                }
                assert!(
                    std::fs::read_dir(unlistable).is_err(),
                    "{} is still listable, so this test cannot assert",
                    unlistable.display()
                );
                scan()
            })
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

#[cfg(target_os = "linux")]
fn drop_file_identity() {
    const NOBODY: libc::uid_t = 65534;
    // SAFETY: setfsgid/setfsuid change only the calling thread's filesystem ids; the thread
    // ends with the scan.
    unsafe {
        libc::setfsgid(NOBODY);
        libc::setfsuid(NOBODY);
    }
    // SAFETY: an invalid id changes nothing and returns the current one
    let now = unsafe { libc::setfsuid(libc::uid_t::MAX) };
    assert_eq!(
        u32::try_from(now).ok(),
        Some(NOBODY),
        "filesystem uid not dropped"
    );
}

#[cfg(all(unix, not(target_os = "linux")))]
fn drop_file_identity() {
    panic!(
        "root lists every directory and this host has no per-thread filesystem id: run unprivileged"
    );
}

/// Astra r1 #1 (Linux): a missing startup name whose directory the workspace or a grant makes
/// writable refuses when that directory is shared (the home, `~/.config`) or above the name's own
/// directory; under a temp root it stays an accepted limit.
#[cfg(target_os = "linux")]
#[test]
fn p177_linux_a_creatable_name_in_a_shared_writable_dir_refuses() {
    let (root, home, ws) = layout("shared");
    // The workspace is the home
    let got = scan(&home, &home, &configured(&[&home]), &HomeEnv::default());
    assert!(
        refusals(&got).contains(".bash_profile"),
        "{}",
        refusals(&got)
    );
    // A grant of the home
    let got = scan(&ws, &home, &configured(&[&ws, &home]), &HomeEnv::default());
    assert!(
        refusals(&got).contains(".bash_profile"),
        "{}",
        refusals(&got)
    );
    // A grant of ~/.config
    std::fs::create_dir_all(home.join(".config")).unwrap();
    let config = home.join(".config");
    let got = scan(
        &ws,
        &home,
        &configured(&[&ws, &config]),
        &HomeEnv::default(),
    );
    assert!(
        refusals(&got).contains("google-chrome"),
        "{}",
        refusals(&got)
    );
    assert!(
        !refusals(&got).contains(".bash_profile"),
        "{}",
        refusals(&got)
    );
    // A relocated zsh directory that does not exist under a grant: its files would be created
    // in the grant itself
    let build = root.join("build");
    std::fs::create_dir_all(&build).unwrap();
    let vars = env(&[("ZDOTDIR", build.join("zdot").to_str().unwrap())]);
    let got = scan(&ws, &home, &configured(&[&ws, &build]), &vars);
    assert!(refusals(&got).contains("zdot/.zshrc"), "{}", refusals(&got));
    // A relocated cargo home that does not exist: the plan makes it (for `bin`), so it is pinned
    let vars = env(&[("CARGO_HOME", build.join("cargo").to_str().unwrap())]);
    let got = scan(&ws, &home, &configured(&[&ws, &build]), &vars);
    assert!(got.unread.is_empty(), "{}", refusals(&got));
    assert!(has(
        &got.protected,
        build.join("cargo"),
        GitPathKind::PinnedDir
    ));
    // The home under a temp root the sandbox always keeps writable: the accepted limit
    let got = scan(&ws, &home, &essential(&[&home]), &HomeEnv::default());
    assert!(got.unread.is_empty(), "{}", refusals(&got));
    let _ = std::fs::remove_dir_all(&root);
}

/// Linux: a granted `~/.cargo` missing `config` is pinned with cargo's caches, not refused.
#[cfg(target_os = "linux")]
#[test]
fn p177_linux_a_granted_cargo_home_is_pinned() {
    let (root, home, ws) = layout("pin");
    let cargo = home.join(".cargo");
    std::fs::create_dir_all(&cargo).unwrap();
    std::fs::write(cargo.join("config.toml"), "x").unwrap();
    let got = entries(&ws, &home, &configured(&[&ws, &cargo]));
    assert!(has(&got, &cargo, GitPathKind::PinnedDir), "{got:?}");
    for cache in ["registry", "git"] {
        assert!(
            has(&got, cargo.join(cache), GitPathKind::CacheDir),
            "{got:?}"
        );
    }
    for lock in [".package-cache", ".package-cache-mutate"] {
        assert!(
            has(&got, cargo.join(lock), GitPathKind::CacheFile),
            "{got:?}"
        );
    }
    // Every name in it exists: no pin needed, each file is bound
    for name in ["config", "credentials", "credentials.toml", "env"] {
        std::fs::write(cargo.join(name), "x").unwrap();
    }
    std::fs::create_dir_all(cargo.join("bin")).unwrap();
    let got = entries(&ws, &home, &configured(&[&ws, &cargo]));
    assert!(!has(&got, &cargo, GitPathKind::PinnedDir), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Linux: the plan binds existing entries inside a writable root, creates and binds a missing
/// startup directory, creates neither a missing file nor a tool tree, and pins a tool directory:
/// read-only, its caches made to exist and bound writable again with its other children, its
/// protected names left read-only.
#[cfg(target_os = "linux")]
#[test]
fn p177_linux_plan_binds_home_entries_pins_and_creates_only_startup_dirs() {
    use crate::hook_write_deny::{HookWriteDenyBwrapPlan, add_git_leaves_to_plan};
    let (root, home, ws) = layout("plan");
    std::fs::write(home.join(".bashrc"), "x").unwrap();
    let cargo = home.join(".cargo");
    std::fs::create_dir_all(cargo.join("advisory-db")).unwrap();
    std::fs::write(cargo.join("config.toml"), "x").unwrap();
    let roots = essential(&[&home]);
    let got = entries(&ws, &home, &roots);
    let empty = || HookWriteDenyBwrapPlan {
        ancestor_rw_binds: Vec::new(),
        leaves: Vec::new(),
        dir_json_snapshots: Vec::new(),
        pinned: Vec::new(),
        rebinds: Vec::new(),
    };
    let mut plan = empty();
    add_git_leaves_to_plan(&mut plan, &got, &roots.write).unwrap();
    let bound = |path: PathBuf| plan.leaves.iter().any(|leaf| leaf.path == path);
    let rebound = |path: PathBuf| plan.rebinds.iter().any(|leaf| leaf.path == path);
    assert!(bound(home.join(".bashrc")));
    assert!(bound(cargo.join("config.toml")));
    assert!(bound(cargo.join("bin")));
    assert!(bound(home.join(".config/autostart")));
    assert!(home.join(".config/systemd/user").is_dir());
    assert!(
        plan.pinned.iter().any(|pin| pin.path == cargo),
        "{:?}",
        plan.pinned
    );
    for writable in [
        "registry",
        "git",
        ".package-cache",
        ".package-cache-mutate",
        "advisory-db",
    ] {
        assert!(cargo.join(writable).exists(), "{writable} not made");
        assert!(
            rebound(cargo.join(writable)),
            "{writable}: {:?}",
            plan.rebinds
        );
    }
    for protected in ["config.toml", "bin", "config"] {
        assert!(
            !rebound(cargo.join(protected)),
            "{protected}: {:?}",
            plan.rebinds
        );
    }
    assert!(
        !plan.ancestor_rw_binds.contains(&cargo),
        "{:?}",
        plan.ancestor_rw_binds
    );
    for never in [
        ".bash_profile",
        ".cargo/config",
        ".vimrc",
        ".nvm",
        ".oh-my-zsh",
        "Library",
    ] {
        assert!(!home.join(never).exists(), "{never} was created");
    }
    // Outside the writable roots nothing is bound (Landlock already denies the write)
    let mut plan = empty();
    add_git_leaves_to_plan(&mut plan, &got, std::slice::from_ref(&ws)).unwrap();
    assert!(
        plan.leaves.is_empty() && plan.pinned.is_empty(),
        "{:?}",
        plan.leaves
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Linux: a symlinked startup file inside a writable root refuses (bwrap cannot pin a link),
/// unless it lies in a pinned directory, where it cannot be re-pointed.
#[cfg(target_os = "linux")]
#[test]
fn p177_linux_a_symlinked_entry_inside_a_root_refuses() {
    use crate::hook_write_deny::{HookWriteDenyError, git_bind_targets};
    let (root, home, ws) = layout("linkroot");
    std::fs::write(home.join("real-bashrc"), "x").unwrap();
    std::os::unix::fs::symlink(home.join("real-bashrc"), home.join(".bashrc")).unwrap();
    let roots = essential(&[&home]);
    let got = entries(&ws, &home, &roots);
    let err = git_bind_targets(&got, &roots.write).unwrap_err();
    assert!(
        matches!(err, HookWriteDenyError::GitSymlink { .. }),
        "{err:?}"
    );
    // The same link outside every root is fine: it cannot be re-pointed
    assert!(git_bind_targets(&got, std::slice::from_ref(&ws)).is_ok());
    std::fs::remove_file(home.join(".bashrc")).unwrap();
    // A linked cargo config in a pinned ~/.cargo
    let cargo = home.join(".cargo");
    std::fs::create_dir_all(&cargo).unwrap();
    std::fs::write(home.join("real-cargo"), "x").unwrap();
    std::os::unix::fs::symlink(home.join("real-cargo"), cargo.join("config.toml")).unwrap();
    let got = entries(&ws, &home, &roots);
    assert!(has(&got, &cargo, GitPathKind::PinnedDir), "{got:?}");
    assert!(git_bind_targets(&got, &roots.write).is_ok());
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r2 N2: the default git config names are pinned like any other (no exemption), so a
/// missing `~/.config/git/config` in a granted `~/.config/git` cannot be created.
#[cfg(target_os = "linux")]
#[test]
fn p177_linux_a_granted_git_config_dir_is_pinned() {
    let (root, home, ws) = layout("gitdir");
    let git = home.join(".config/git");
    std::fs::create_dir_all(&git).unwrap();
    let got = entries(&ws, &home, &configured(&[&ws, &git]));
    assert!(has(&got, &git, GitPathKind::PinnedDir), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r2 N5: a grant that is also an always-writable root ($TMPDIR inside `~/.cargo`) keeps
/// its configured provenance: the missing `config` refuses (a pin would close the temp dir).
#[cfg(target_os = "linux")]
#[test]
fn p177_linux_a_grant_that_is_also_a_temp_root_refuses() {
    let (root, home, ws) = layout("tmpgrant");
    let cargo = home.join(".cargo");
    std::fs::create_dir_all(&cargo).unwrap();
    let roots = Roots {
        write: vec![ws.clone(), cargo.clone()],
        essential: vec![cargo.clone()],
        configured: vec![ws.clone(), cargo.clone()],
        temp: vec![cargo.clone()],
    };
    let got = scan(&ws, &home, &roots, &HomeEnv::default());
    assert!(refusals(&got).contains(".cargo/config"), "{}", refusals(&got));
    assert!(!has(&got.protected, &cargo, GitPathKind::PinnedDir));
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r2 N7: a grant the profile creates at apply (`~/.m2` not there yet) is pinned by the
/// scan and made by the plan, so the scan inside the sandbox agrees.
#[cfg(target_os = "linux")]
#[test]
fn p177_linux_a_grant_not_yet_made_is_pinned_and_made() {
    use crate::hook_write_deny::{HookWriteDenyBwrapPlan, add_git_leaves_to_plan};
    let (root, home, ws) = layout("m2");
    let m2 = home.join(".m2");
    let roots = configured(&[&ws, &m2]);
    let got = entries(&ws, &home, &roots);
    assert!(has(&got, &m2, GitPathKind::PinnedDir), "{got:?}");
    let mut plan = HookWriteDenyBwrapPlan {
        ancestor_rw_binds: Vec::new(),
        leaves: Vec::new(),
        dir_json_snapshots: Vec::new(),
        pinned: Vec::new(),
        rebinds: Vec::new(),
    };
    add_git_leaves_to_plan(&mut plan, &got, &roots.write).unwrap();
    assert!(m2.is_dir());
    assert!(plan.pinned.iter().any(|pin| pin.path == m2), "{:?}", plan.pinned);
    // The scan after the plan sees the same pin
    let again = entries(&ws, &home, &roots);
    assert!(has(&again, &m2, GitPathKind::PinnedDir), "{again:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r2 N1 and N6 (Linux plan): a child of a pin that holds a link on the way to a protected
/// file stays read-only; a nested cargo pin under a pinned `~/.gradle` keeps its caches writable.
#[cfg(target_os = "linux")]
#[test]
fn p177_linux_pin_rebinds_skip_link_parents_and_survive_nesting() {
    use crate::hook_write_deny::{HookWriteDenyBwrapPlan, add_git_leaves_to_plan};
    let empty = || HookWriteDenyBwrapPlan {
        ancestor_rw_binds: Vec::new(),
        leaves: Vec::new(),
        dir_json_snapshots: Vec::new(),
        pinned: Vec::new(),
        rebinds: Vec::new(),
    };
    let (root, home, ws) = layout("rebind");
    let cargo = home.join(".cargo");
    std::fs::create_dir_all(cargo.join("aux")).unwrap();
    std::fs::write(root.join("safe-cargo.toml"), "x").unwrap();
    std::os::unix::fs::symlink(root.join("safe-cargo.toml"), cargo.join("aux/current")).unwrap();
    std::os::unix::fs::symlink("aux/current", cargo.join("config.toml")).unwrap();
    let roots = configured(&[&ws, &cargo]);
    let got = entries(&ws, &home, &roots);
    assert!(has(&got, &cargo, GitPathKind::PinnedDir), "{got:?}");
    let mut plan = empty();
    add_git_leaves_to_plan(&mut plan, &got, &roots.write).unwrap();
    let rebound = |plan: &HookWriteDenyBwrapPlan, path: PathBuf| {
        plan.rebinds.iter().any(|leaf| leaf.path == path)
    };
    assert!(!rebound(&plan, cargo.join("aux")), "{:?}", plan.rebinds);
    assert!(rebound(&plan, cargo.join("registry")), "{:?}", plan.rebinds);
    // Nested: CARGO_HOME inside a granted ~/.gradle
    let gradle = home.join(".gradle");
    let inner = gradle.join("cargo");
    std::fs::create_dir_all(inner.join("registry")).unwrap();
    let vars = env(&[("CARGO_HOME", inner.to_str().unwrap())]);
    let roots = configured(&[&ws, &gradle]);
    let got = scan(&ws, &home, &roots, &vars);
    assert!(got.unread.is_empty(), "{}", refusals(&got));
    let got = got.protected;
    assert!(has(&got, &gradle, GitPathKind::PinnedDir), "{got:?}");
    assert!(has(&got, &inner, GitPathKind::PinnedDir), "{got:?}");
    let mut plan = empty();
    add_git_leaves_to_plan(&mut plan, &got, &roots.write).unwrap();
    assert!(rebound(&plan, inner.join("registry")), "{:?}", plan.rebinds);
    assert!(rebound(&plan, inner.join(".package-cache")), "{:?}", plan.rebinds);
    assert!(!rebound(&plan, inner.clone()), "{:?}", plan.rebinds);
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r2 N3: the alias search refuses on a directory it cannot list but a command can search
/// (another user's mode-0711 directory): a known name beneath it stays writable. Run with an
/// unprivileged user's permissions, also as root.
#[cfg(target_os = "linux")]
#[test]
fn p177_an_unlistable_but_searchable_dir_in_a_root_refuses_the_alias_search() {
    use std::os::unix::fs::PermissionsExt;
    let (root, home, ws) = layout("searchable");
    std::fs::write(home.join(".bashrc"), "x").unwrap();
    let drop_dir = ws.join("drop");
    std::fs::create_dir_all(&drop_dir).unwrap();
    std::fs::hard_link(home.join(".bashrc"), drop_dir.join("alias")).unwrap();
    // SAFETY: valid NUL-terminated path; another user's directory, as root on the gate
    let c_path = std::ffi::CString::new(drop_dir.to_str().unwrap()).unwrap();
    if unsafe { libc::geteuid() } == 0 {
        assert_eq!(unsafe { libc::chown(c_path.as_ptr(), 65533, 65533) }, 0);
    }
    std::fs::set_permissions(&drop_dir, std::fs::Permissions::from_mode(0o711)).unwrap();
    let got = unprivileged(&drop_dir, || {
        scan(&ws, &home, &configured(&[&ws]), &HomeEnv::default())
    });
    std::fs::set_permissions(&drop_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(refusals(&got).contains("cannot be searched"), "{}", refusals(&got));
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r1/r2 #3: a small secret store outside every root is listed too, so an alias of a file
/// in it inside the workspace refuses.
#[cfg(unix)]
#[test]
fn p177_a_secret_store_outside_the_roots_is_listed_for_aliases() {
    let (root, home, ws) = layout("sshout");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::write(home.join(".ssh/config"), "Host *\n").unwrap();
    std::fs::hard_link(home.join(".ssh/config"), ws.join("ssh-alias")).unwrap();
    let got = scan(&ws, &home, &configured(&[&ws]), &HomeEnv::default());
    assert!(refusals(&got).contains("ssh-alias"), "{}", refusals(&got));
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r3 N8: a writable root inside a protected tree (a grant of `~/.config/nvim/lua`) refuses:
/// the Linux plan binds only what lies inside a root.
#[test]
fn p177_a_grant_inside_a_protected_tree_refuses() {
    let (root, home, ws) = layout("grantin");
    let lua = home.join(".config/nvim/lua");
    std::fs::create_dir_all(&lua).unwrap();
    let got = scan(&ws, &home, &configured(&[&ws, &lua]), &HomeEnv::default());
    assert!(refusals(&got).contains("holds the writable root"), "{}", refusals(&got));
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r3 N9 (Linux): only a temp root keeps an unpinnable missing name an accepted limit; the
/// Fuigo home (`FUIGO_HOME=~/.cargo`) refuses like a grant.
#[cfg(target_os = "linux")]
#[test]
fn p177_linux_a_fuigo_home_holding_a_missing_name_refuses() {
    let (root, home, ws) = layout("fuigohome");
    let cargo = home.join(".cargo");
    std::fs::create_dir_all(&cargo).unwrap();
    let roots = Roots {
        write: vec![ws.clone(), cargo.clone()],
        essential: vec![cargo.clone()],
        configured: vec![ws.clone()],
        temp: Vec::new(),
    };
    let got = scan(&ws, &home, &roots, &HomeEnv::default());
    assert!(refusals(&got).contains(".cargo/config"), "{}", refusals(&got));
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r3 N10: an always-listed secret store that cannot be listed refuses, even outside every
/// writable root (a known name in it stays reachable for a hard link). Run unprivileged.
#[cfg(unix)]
#[test]
fn p177_an_unlistable_secret_store_refuses() {
    use std::os::unix::fs::PermissionsExt;
    let (root, home, ws) = layout("sshlocked");
    let ssh = home.join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::write(ssh.join("config"), "Host *\n").unwrap();
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o111)).unwrap();
    let got = unprivileged(&ssh, || {
        scan(&ws, &home, &configured(&[&ws]), &HomeEnv::default())
    });
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(refusals(&got).contains("cannot list it"), "{}", refusals(&got));
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r3 N11: each missing directory on the way to a protected name is a macOS node deny, so
/// a prepared `~/.cargo` cannot be renamed into place (Linux skips the kind).
#[test]
fn p177_missing_ancestors_are_node_entries() {
    let (root, home, ws) = layout("ancestors");
    let got = entries(&ws, &home, &configured(&[&ws]));
    for dir in [".cargo", ".config/fish", ".config", ".gradle"] {
        assert!(has(&got, home.join(dir), GitPathKind::MissingAncestor), "{dir}: {got:?}");
    }
    assert!(!has(&got, &home, GitPathKind::MissingAncestor));
    std::fs::create_dir_all(home.join(".cargo")).unwrap();
    let got = entries(&ws, &home, &configured(&[&ws]));
    assert!(!has(&got, home.join(".cargo"), GitPathKind::MissingAncestor));
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r3 N13 (Linux): a nested pin the plan has to make (`ZDOTDIR=~/.cargo/zsh`, not there
/// yet) is made before its parent pin's identity is taken, so the plan revalidates.
#[cfg(target_os = "linux")]
#[test]
fn p177_linux_a_nested_pin_made_by_the_plan_revalidates() {
    use crate::hook_write_deny::{HookWriteDenyBwrapPlan, add_git_leaves_to_plan, revalidate_plan};
    let (root, home, ws) = layout("nestmake");
    let cargo = home.join(".cargo");
    std::fs::create_dir_all(&cargo).unwrap();
    let zsh = cargo.join("zsh");
    let vars = env(&[("ZDOTDIR", zsh.to_str().unwrap())]);
    let roots = configured(&[&ws, &cargo, &zsh]);
    let got = scan(&ws, &home, &roots, &vars);
    assert!(got.unread.is_empty(), "{}", refusals(&got));
    assert!(has(&got.protected, &zsh, GitPathKind::PinnedDir), "{:?}", got.protected);
    let mut plan = HookWriteDenyBwrapPlan {
        ancestor_rw_binds: Vec::new(),
        leaves: Vec::new(),
        dir_json_snapshots: Vec::new(),
        pinned: Vec::new(),
        rebinds: Vec::new(),
    };
    add_git_leaves_to_plan(&mut plan, &got.protected, &roots.write).unwrap();
    revalidate_plan(&plan).unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

/// `base` with `rel` beneath it; an empty `rel` is `base` itself (a variable naming the place).
fn at(base: &Path, rel: &str) -> PathBuf {
    if rel.is_empty() {
        base.to_path_buf()
    } else {
        base.join(rel)
    }
}

/// Grok HIGH 2: a grant strictly inside a protected tree that does not exist yet refuses as one
/// inside an existing tree does, judged on its spelling before the profile creates the grant:
/// tool trees, secret stores, startup and `Library/` dirs, and a relocated store.
#[test]
fn p177_a_grant_inside_a_missing_protected_tree_refuses() {
    for tree in [
        ".vim",
        ".rustup/toolchains",
        ".oh-my-zsh",
        ".vscode/extensions",
        ".emacs.d",
        ".ssh",
        ".gnupg",
        ".aws",
        "Library/LaunchAgents",
        "Library/Keychains",
        "Library/Application Support/Google/Chrome",
        ".config/nvim",
        ".local/bin",
    ] {
        let (root, home, ws) = layout("grantmissing");
        let grant = home.join(tree).join("pack");
        assert!(!home.join(tree).exists());
        let got = scan(&ws, &home, &configured(&[&ws, &grant]), &HomeEnv::default());
        assert!(
            refusals(&got).contains("holds the writable root"),
            "{tree}: {}",
            refusals(&got)
        );
        assert!(!grant.exists(), "{tree}: the scan made the grant");
        let _ = std::fs::remove_dir_all(&root);
    }
    // A relocated store that does not exist yet
    let (root, home, ws) = layout("grantmissingreloc");
    let gnupg = root.join("elsewhere/gnupg");
    let grant = gnupg.join("private-keys-v1.d");
    let vars = env(&[("GNUPGHOME", gnupg.to_str().unwrap())]);
    let got = scan(&ws, &home, &configured(&[&ws, &grant]), &vars);
    assert!(
        refusals(&got).contains("holds the writable root"),
        "{}",
        refusals(&got)
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// One relocating variable (Grok MEDIUM 3 and the relocation sweep): set to an absolute place, the
/// files and trees beneath it are protected with their kinds; a relative value refuses.
fn relocation_case(var: &'static str, value: &str, expect: &[(&str, GitPathKind)]) {
    let (root, home, ws) = layout(&format!("reloc-{}", var.to_lowercase()));
    let elsewhere = root.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let place = elsewhere.join(value);
    let got = scan(
        &ws,
        &home,
        &essential(&[&elsewhere]),
        &env(&[(var, place.to_str().unwrap())]),
    );
    assert!(got.unread.is_empty(), "{var}: {}", refusals(&got));
    for (rel, kind) in expect {
        assert!(
            has(&got.protected, at(&place, rel), *kind),
            "{var}: {} as {kind:?}: {:?}",
            at(&place, rel).display(),
            got.protected
        );
    }
    let got = scan(&ws, &home, &configured(&[]), &env(&[(var, "rel/dir")]));
    assert!(refusals(&got).contains(var), "{var}: {}", refusals(&got));
    let _ = std::fs::remove_dir_all(&root);
}

macro_rules! relocation_tests {
    ($($test:ident: $var:literal at $value:literal => [$($rel:literal as $kind:ident),+ $(,)?];)+) => {
        $(
            #[test]
            fn $test() {
                relocation_case($var, $value, &[$(($rel, GitPathKind::$kind)),+]);
            }
        )+
    };
}

relocation_tests! {
    p177_relocated_gnupghome_is_protected: "GNUPGHOME" at "gnupg" => ["" as OptionalDir];
    p177_relocated_aws_config_file_is_protected: "AWS_CONFIG_FILE" at "aws.config" => ["" as OptionalFile];
    p177_relocated_aws_shared_credentials_file_is_protected:
        "AWS_SHARED_CREDENTIALS_FILE" at "aws.credentials" => ["" as OptionalFile];
    p177_relocated_xdg_data_home_is_protected: "XDG_DATA_HOME" at "share" => ["applications" as Dir];
    p177_relocated_myvimrc_is_protected: "MYVIMRC" at "vimrc" => ["" as OptionalFile];
    p177_relocated_netrc_is_protected: "NETRC" at "netrc" => ["" as OptionalFile];
    p177_relocated_gh_config_dir_is_protected: "GH_CONFIG_DIR" at "gh" => ["hosts.yml" as OptionalFile];
    p177_relocated_lowercase_npm_userconfig_is_protected:
        "npm_config_userconfig" at "npmrc" => ["" as OptionalFile];
    p177_relocated_bash_env_is_protected: "BASH_ENV" at "bash_env" => ["" as OptionalFile];
    p177_relocated_pythonstartup_is_protected: "PYTHONSTARTUP" at "startup.py" => ["" as OptionalFile];
    p177_relocated_zsh_is_protected: "ZSH" at "omz" => ["" as OptionalDir];
    p177_relocated_zsh_custom_is_protected: "ZSH_CUSTOM" at "omz-custom" => ["" as OptionalDir];
    p177_relocated_vscode_extensions_is_protected:
        "VSCODE_EXTENSIONS" at "vscode-ext" => ["" as OptionalDir];
    p177_relocated_direnv_config_is_protected: "DIRENV_CONFIG" at "direnv" => ["" as Dir];
    p177_relocated_gobin_is_protected: "GOBIN" at "gobin" => ["" as OptionalDir];
    p177_relocated_deno_install_root_is_protected: "DENO_INSTALL_ROOT" at "deno" => ["bin" as OptionalDir];
    p177_relocated_deno_install_is_protected: "DENO_INSTALL" at "deno-install" => ["bin" as OptionalDir];
    p177_relocated_bun_install_is_protected: "BUN_INSTALL" at "bun" => ["bin" as OptionalDir];
}

/// `KUBECONFIG` is a list: every absolute entry is protected, an empty one skipped, a relative one
/// refuses.
#[test]
fn p177_relocated_kubeconfig_list_is_protected() {
    let (root, home, ws) = layout("reloc-kube");
    let elsewhere = root.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let (a, b) = (elsewhere.join("kube-a"), elsewhere.join("kube-b"));
    let list = format!("{}::{}", a.display(), b.display());
    let got = scan(
        &ws,
        &home,
        &essential(&[&elsewhere]),
        &env(&[("KUBECONFIG", &list)]),
    );
    assert!(got.unread.is_empty(), "{}", refusals(&got));
    for file in [&a, &b] {
        assert!(
            has(&got.protected, file, GitPathKind::OptionalFile),
            "{:?}",
            got.protected
        );
    }
    let list = format!("{}:rel/kube", a.display());
    let got = scan(&ws, &home, &configured(&[]), &env(&[("KUBECONFIG", &list)]));
    assert!(refusals(&got).contains("KUBECONFIG"), "{}", refusals(&got));
    let _ = std::fs::remove_dir_all(&root);
}

/// `GOPATH` is a list too: each entry's `bin` is protected.
#[test]
fn p177_relocated_gopath_list_is_protected() {
    let (root, home, ws) = layout("reloc-gopath");
    let elsewhere = root.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let (a, b) = (elsewhere.join("go-a"), elsewhere.join("go-b"));
    let list = format!("{}:{}", a.display(), b.display());
    let got = scan(
        &ws,
        &home,
        &essential(&[&elsewhere]),
        &env(&[("GOPATH", &list)]),
    );
    assert!(got.unread.is_empty(), "{}", refusals(&got));
    for dir in [&a, &b] {
        assert!(
            has(&got.protected, dir.join("bin"), GitPathKind::OptionalDir),
            "{:?}",
            got.protected
        );
    }
    let got = scan(&ws, &home, &configured(&[]), &env(&[("GOPATH", "go")]));
    assert!(refusals(&got).contains("GOPATH"), "{}", refusals(&got));
    let _ = std::fs::remove_dir_all(&root);
}

/// `NVIM_APPNAME` names neovim's config directory under `~/.config` and `$XDG_CONFIG_HOME`; an
/// absolute name or one with `..` refuses.
#[test]
fn p177_relocated_nvim_appname_is_protected() {
    let (root, home, ws) = layout("reloc-nvim");
    let xdg = root.join("xdg");
    std::fs::create_dir_all(&xdg).unwrap();
    let got = scan(
        &ws,
        &home,
        &configured(&[]),
        &env(&[("NVIM_APPNAME", "lazyvim")]),
    );
    assert!(got.unread.is_empty(), "{}", refusals(&got));
    assert!(
        has(
            &got.protected,
            home.join(".config/lazyvim"),
            GitPathKind::Dir
        ),
        "{:?}",
        got.protected
    );
    let vars = env(&[
        ("XDG_CONFIG_HOME", xdg.to_str().unwrap()),
        ("NVIM_APPNAME", "lazyvim"),
    ]);
    let got = scan(&ws, &home, &configured(&[]), &vars);
    assert!(got.unread.is_empty(), "{}", refusals(&got));
    assert!(
        has(&got.protected, xdg.join("lazyvim"), GitPathKind::Dir),
        "{:?}",
        got.protected
    );
    for bad in ["/abs/nvim", "../nvim", "a/../../b"] {
        let got = scan(&ws, &home, &configured(&[]), &env(&[("NVIM_APPNAME", bad)]));
        assert!(
            refusals(&got).contains("NVIM_APPNAME"),
            "{bad}: {}",
            refusals(&got)
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// `YARN_RC_FILENAME` renames `~/.yarnrc.yml`; an absolute name refuses.
#[test]
fn p177_relocated_yarn_rc_filename_is_protected() {
    let (root, home, ws) = layout("reloc-yarn");
    let got = scan(
        &ws,
        &home,
        &configured(&[]),
        &env(&[("YARN_RC_FILENAME", ".yarnrc.ci.yml")]),
    );
    assert!(got.unread.is_empty(), "{}", refusals(&got));
    assert!(
        has(
            &got.protected,
            home.join(".yarnrc.ci.yml"),
            GitPathKind::OptionalFile
        ),
        "{:?}",
        got.protected
    );
    let got = scan(
        &ws,
        &home,
        &configured(&[]),
        &env(&[("YARN_RC_FILENAME", "/etc/yarnrc")]),
    );
    assert!(
        refusals(&got).contains("YARN_RC_FILENAME"),
        "{}",
        refusals(&got)
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The relocating variables added for Grok MEDIUM 3 are read from the environment by name.
#[test]
fn p177_home_env_reads_the_added_relocating_variables() {
    for name in [
        "GNUPGHOME",
        "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "KUBECONFIG",
        "XDG_DATA_HOME",
        "MYVIMRC",
        "NVIM_APPNAME",
    ] {
        let got = HomeEnv::from_lookup(|asked| (asked == name).then(|| OsString::from("/x")));
        assert_eq!(got.vars, vec![(name, OsString::from("/x"))], "{name}");
    }
}

/// A relocated GnuPG home is listed for hard links wherever it lies, as `~/.gnupg` is.
#[cfg(unix)]
#[test]
fn p177_a_hard_linked_file_in_a_relocated_gnupghome_refuses() {
    let (root, home, ws) = layout("gnupglink");
    let gnupg = root.join("elsewhere/gnupg");
    std::fs::create_dir_all(&gnupg).unwrap();
    std::fs::write(gnupg.join("gpg.conf"), "x").unwrap();
    std::fs::hard_link(gnupg.join("gpg.conf"), ws.join("gpg-alias")).unwrap();
    let vars = env(&[("GNUPGHOME", gnupg.to_str().unwrap())]);
    let got = scan(&ws, &home, &configured(&[&ws]), &vars);
    assert!(refusals(&got).contains("gpg-alias"), "{}", refusals(&got));
    let _ = std::fs::remove_dir_all(&root);
}

/// The Seatbelt rules macOS applies for the home entries, rendered as strings (so they are pinned
/// on every Unix host, not only on a Mac).
#[cfg(all(feature = "enforce", unix))]
fn rendered(entries: &[GitProtectedPath], roots: &[&Path]) -> Vec<String> {
    let roots: Vec<PathBuf> = roots.iter().map(|root| root.to_path_buf()).collect();
    crate::deny::render_git_write_deny_rules(entries, &roots)
        .expect("rules render")
        .rules
}

/// Grok LOW 5 (Astra r3 N11's apply path): a missing `~/.cargo` on the way to `~/.cargo/config`
/// renders as a node deny (create and unlink of that one literal), never as a write-denied tree.
#[cfg(all(feature = "enforce", unix))]
#[test]
fn p177_rendered_missing_ancestor_is_a_node_deny() {
    let (root, home, ws) = layout("rendanc");
    let got = entries(&ws, &home, &configured(&[&ws]));
    let rules = rendered(&got, &[&ws]);
    let cargo = home.join(".cargo");
    let literal = format!("(literal \"{}\")", cargo.display());
    for action in ["file-write-create", "file-write-unlink"] {
        let rule = format!("(deny {action} {literal})");
        assert!(rules.contains(&rule), "missing {rule}: {rules:#?}");
    }
    let tree = format!("(deny file-write* {literal})");
    assert!(
        !rules.contains(&tree),
        "~/.cargo is denied as a tree: {rules:#?}"
    );
    let subpath = format!("(subpath \"{}\")", cargo.display());
    assert!(
        !rules.iter().any(|rule| rule.contains(&subpath)),
        "{rules:#?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Grok LOW 5 (Astra r3 N12): `~/.cargo/config.toml -> $WS/state/disabled -> /dev/null` renders a
/// node deny for the link in the workspace and for its parent `$WS/state`, so the parent cannot be
/// swapped for a prepared one holding another target.
#[cfg(all(feature = "enforce", unix))]
#[test]
fn p177_rendered_link_node_parents_are_node_denies() {
    let (root, home, ws) = layout("rendlink");
    let state = ws.join("state");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::create_dir_all(home.join(".cargo")).unwrap();
    std::os::unix::fs::symlink("/dev/null", state.join("disabled")).unwrap();
    std::os::unix::fs::symlink(state.join("disabled"), home.join(".cargo/config.toml")).unwrap();
    let got = scan(&ws, &home, &configured(&[&ws]), &HomeEnv::default());
    assert!(
        has(
            &got.protected,
            state.join("disabled"),
            GitPathKind::LinkNode
        ),
        "{:?}",
        got.protected
    );
    let rules = rendered(&got.protected, &[&ws]);
    for node in [state.join("disabled"), state.clone()] {
        for action in ["file-write-create", "file-write-unlink"] {
            let rule = format!("(deny {action} (literal \"{}\"))", node.display());
            assert!(rules.contains(&rule), "missing {rule}: {rules:#?}");
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// Grok MEDIUM 4: a protected file and a protected tree each deny `file-link`, so no hard link of
/// them can be made in a writable root on the same volume (macOS 26.3, `sandbox-exec`: a lone
/// `(deny file-link (literal F))` blocks `ln F $WS/alias` under a later `file-write*` grant).
#[cfg(all(feature = "enforce", unix))]
#[test]
fn p177_rendered_protected_names_deny_hard_links() {
    let (root, home, ws) = layout("rendln");
    std::fs::write(home.join(".bashrc"), "x").unwrap();
    std::fs::create_dir_all(home.join(".local/bin")).unwrap();
    let got = entries(&ws, &home, &configured(&[&ws]));
    let rules = rendered(&got, &[&ws]);
    for rule in [
        format!(
            "(deny file-link (literal \"{}\"))",
            home.join(".bashrc").display()
        ),
        format!(
            "(deny file-link (subpath \"{}\"))",
            home.join(".local/bin").display()
        ),
    ] {
        assert!(rules.contains(&rule), "missing {rule}: {rules:#?}");
    }
    let _ = std::fs::remove_dir_all(&root);
}
