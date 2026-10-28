//! Repo-local content-filter pins for unattended git (P158, ported from upstream 75810042).
//! A repository's `filter.<driver>.{clean,smudge,process}` runs on a plain `git status`/`diff`, so
//! every git command Fuigo runs on its own pins each local driver empty, and the exec-risk scan
//! counts one as exec.

use std::collections::BTreeSet;
use std::path::Path;

pub(crate) fn filter_command_driver(name: &str) -> Option<&str> {
    // `get` is None on a non-char boundary; a byte slice would panic.
    let head = name.get(..7)?;
    if !head.eq_ignore_ascii_case("filter.") {
        return None;
    }
    let rest = name.get(7..)?;
    let (driver, prop) = rest.rsplit_once('.')?;
    if !driver.is_empty()
        && (prop.eq_ignore_ascii_case("clean")
            || prop.eq_ignore_ascii_case("smudge")
            || prop.eq_ignore_ascii_case("process"))
    {
        Some(driver)
    } else {
        None
    }
}

/// Whether `git -c filter.<driver>.<key>=` can name this driver: git splits a `-c` argument at
/// its first `=` and reads the subsection between the first and the last dot verbatim, so any
/// name but one holding `=`, a newline or NUL can be pinned (dots and spaces included).
fn filter_driver_name_is_pinnable(driver: &str) -> bool {
    !driver.is_empty() && !driver.contains(['=', '\n', '\0'])
}

fn local_includeif_unsupported(name: &str) -> bool {
    let Some(head) = name.get(..10) else {
        return false;
    };
    if !head.eq_ignore_ascii_case("includeif.") {
        return false;
    }
    let condition = name.get(10..).unwrap_or("").split(':').next().unwrap_or("");
    !matches!(
        condition.to_ascii_lowercase().as_str(),
        "gitdir" | "gitdir/i" | "onbranch"
    )
}

fn path_unreadable(path: &Path) -> bool {
    // Directories open on Linux, so require a readable regular file after following symlinks.
    match std::fs::File::open(path) {
        Ok(f) => match f.metadata() {
            Ok(meta) => !meta.is_file(),
            Err(_) => true,
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true,
    }
}

/// Populated submodules read, across all levels, before the scan gives up (fail closed).
const SUBMODULE_SCAN_LIMIT: usize = 64;

/// Submodule nesting followed before the scan gives up (fail closed).
const SUBMODULE_DEPTH_LIMIT: usize = 4;

/// The index mode of a submodule (gitlink) entry.
const GITLINK_MODE: u32 = 0o160_000;

/// Local/worktree only (include/includeIf), of the repository and of every populated submodule
/// (a parent `git status` runs status inside each, which reads that submodule's filters; `-c`
/// pins reach it through `GIT_CONFIG_PARAMETERS`). `None` on read errors; empty if not a repo.
pub(crate) fn read_local_git_config_entries(cwd: &Path) -> Option<Vec<(String, String)>> {
    read_local_git_config_entries_with(cwd, None)
}

/// [`read_local_git_config_entries`], running `git` (an absolute path) for the CLI reading instead
/// of the default git (u35 g7: the permission scan runs only a git it trusts).
pub(crate) fn read_local_git_config_entries_with(
    cwd: &Path,
    git: Option<&Path>,
) -> Option<Vec<(String, String)>> {
    read_entries(cwd, Reader::Cli(git))
}

/// u35 t1 (design d2 §3.3-5): [`read_local_git_config_entries`] for a folder that is not trusted: libgit2 only, no
/// git process. A configuration that libgit2 may read differently from git (any `include`/`includeIf`) is `None`
/// (fail closed), so the grant floors still see what git would run.
pub(crate) fn read_local_git_config_entries_git2_only(cwd: &Path) -> Option<Vec<(String, String)>> {
    read_entries(cwd, Reader::Git2Only)
}

/// How a repository's local configuration is read.
#[derive(Clone, Copy)]
enum Reader<'a> {
    /// libgit2 and the git binary (the union); `Some`: that git program.
    Cli(Option<&'a Path>),
    /// libgit2 alone (an untrusted folder: Fuigo starts no git there).
    Git2Only,
}

fn read_entries(cwd: &Path, git: Reader<'_>) -> Option<Vec<(String, String)>> {
    let repo = match git2::Repository::discover(cwd) {
        Ok(repo) => repo,
        Err(e)
            if e.code() == git2::ErrorCode::NotFound
                && e.class() == git2::ErrorClass::Repository =>
        {
            return Some(Vec::new());
        }
        Err(_) => return None,
    };
    let mut out = repo_local_config_entries(&repo, git)?;
    let mut budget = SUBMODULE_SCAN_LIMIT;
    append_submodule_entries(&repo, 0, &mut budget, &mut out, git)?;
    Some(out)
}

/// The local entries of each populated submodule, recursively; `None` past the bounds or when a
/// populated submodule cannot be opened or read.
fn append_submodule_entries(
    repo: &git2::Repository,
    depth: usize,
    budget: &mut usize,
    out: &mut Vec<(String, String)>,
    git: Reader<'_>,
) -> Option<()> {
    let Some(workdir) = repo.workdir() else {
        return Some(());
    };
    // The index's gitlinks, not `.gitmodules`: status visits every indexed submodule checkout,
    // and a deleted or edited `.gitmodules` must not hide one
    let index = repo.index().ok()?;
    let mut gitlinks = Vec::new();
    for entry in index.iter() {
        if entry.mode == GITLINK_MODE {
            gitlinks.push(String::from_utf8(entry.path).ok()?);
        }
    }
    if gitlinks.is_empty() {
        return Some(());
    }
    if depth >= SUBMODULE_DEPTH_LIMIT {
        return None;
    }
    for path in gitlinks {
        let checkout = workdir.join(path);
        // Not populated: git runs nothing there
        if std::fs::symlink_metadata(checkout.join(".git")).is_err() {
            continue;
        }
        *budget = budget.checked_sub(1)?;
        let sub = git2::Repository::open(&checkout).ok()?;
        out.extend(repo_local_config_entries(&sub, git)?);
        append_submodule_entries(&sub, depth + 1, budget, out, git)?;
    }
    Some(())
}

/// One repository's local/worktree config entries, as libgit2 reads them and as git itself reads
/// them (the union: where the two parsers disagree on an include, the entries git would act on
/// must not be lost). `None` on read errors.
fn repo_local_config_entries(
    repo: &git2::Repository,
    git: Reader<'_>,
) -> Option<Vec<(String, String)>> {
    let mut out = libgit2_local_config_entries(repo)?;
    let cli = match git {
        Reader::Cli(git) => git_cli_local_config_entries(repo, git)?,
        Reader::Git2Only => {
            if config_has_include(repo, &out) {
                return None;
            }
            Vec::new()
        }
    };
    for entry in cli {
        if !out.contains(&entry) {
            out.push(entry);
        }
    }
    out.extend(hooks_entry(repo)?);
    Some(out)
}

/// u35 t1: whether a repository's local configuration includes another file (`include.path`, `includeIf.*`), which
/// only the git binary reads exactly as git does (e.g. `includeIf.hasconfig:`).
fn config_has_include(repo: &git2::Repository, entries: &[(String, String)]) -> bool {
    let named = entries.iter().any(|(name, _)| {
        let name = name.to_ascii_lowercase();
        name.starts_with("include.") || name.starts_with("includeif.")
    });
    let in_files = ["config", "config.worktree"].iter().any(|file| {
        std::fs::read(repo.path().join(file))
            .map(|bytes| String::from_utf8_lossy(&bytes).to_ascii_lowercase().contains("include"))
            .unwrap_or(false)
    });
    named || in_files
}

/// u35 g8 (Grok r7): git runs hooks on safe verbs too (`post-index-change` when `git status` refreshes the index, in
/// the repository and in each populated submodule). The effective hooks directory is `core.hooksPath` from any scope
/// (a relative one taken from the work tree), else the common git directory's `hooks`, shared by linked worktrees. A
/// hook found there is reported as a `core.hookspath` entry naming that directory, a command-valued key, so every git
/// command there asks, grants included.
///
/// u35 g9 (Fable r8 Medium): only the hooks a read-only command can fire count ([`SAFE_VERB_HOOKS`]):
/// `post-index-change`, and `fsmonitor-watchman` (also covered by `core.fsmonitor`). The hooks `git lfs install`,
/// `pre-commit install`, lefthook or overcommit write (`pre-commit`, `post-checkout`, `pre-push`, ...) never run on a
/// safe verb. On unix git skips a hook without an execute bit (`find_hook`: `access(X_OK)`), so such a file does not
/// count; Git for Windows runs one without it. A missing directory adds nothing; a directory or hook that cannot be read
/// is `None` (fail closed).
///
/// u35 g10 (Astra r9 High): a command that is not a read-only query runs the other hooks (`git commit` runs
/// `pre-commit`, `checkout` runs `post-checkout`, ...). Any other hook git would run (every file but a `*.sample`) is
/// reported as a [`REPOSITORY_HOOK_KEY`] entry naming the directory; the ambient scan turns it into a finding only
/// for such a command, so it switches off approval without a grant for `git commit` and leaves `git status` alone.
fn hooks_entry(repo: &git2::Repository) -> Option<Vec<(String, String)>> {
    let configured = repo.config().ok()?.get_path("core.hooksPath").ok();
    let dir = match configured {
        Some(path) if path.is_absolute() => path,
        Some(path) => repo.workdir().unwrap_or_else(|| repo.path()).join(path),
        None => repo.commondir().join("hooks"),
    };
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Some(Vec::new());
        }
        Err(_) => return None,
    };
    let (mut safe_verb, mut other) = (false, false);
    for entry in entries {
        let entry = entry.ok()?;
        let name = entry.file_name();
        let is_safe_verb_hook = names_safe_verb_hook(&name.to_string_lossy(), cfg!(windows));
        // git looks a hook up by its name; a `*.sample` is never one (u35 g12, Fable r11 Low: in any letter case).
        if !is_safe_verb_hook && is_sample_hook(&name.to_string_lossy()) {
            continue;
        }
        if hook_would_run(&entry.path())? {
            if is_safe_verb_hook {
                safe_verb = true;
            } else {
                other = true;
            }
        }
    }
    let dir = dir.display().to_string();
    let mut out = Vec::new();
    if safe_verb {
        out.push(("core.hookspath".to_owned(), dir.clone()));
    }
    if other {
        out.push((REPOSITORY_HOOK_KEY.to_owned(), dir));
    }
    Some(out)
}

/// u35 g12 (Fable r11 Low): a `*.sample` file of the hooks directory, the extension in any letter case (git finds no
/// hook by that name, so `pre-commit.SAMPLE` is not one).
pub(crate) fn is_sample_hook(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".sample")
}

/// u35 g10: the pseudo config entry [`hooks_entry`] reports for a hook only a command that is not a read-only query
/// runs. Not a git config key (it has no section git reads), so no config-key check matches it.
pub(crate) const REPOSITORY_HOOK_KEY: &str = "fuigo.repository-hook";

/// u35 g9: the hooks git can run for a command Fuigo approves without asking ([`hooks_entry`]).
const SAFE_VERB_HOOKS: &[&str] = &["post-index-change", "fsmonitor-watchman"];

/// u35 g11 (Grok r10 High): whether a hooks-directory file named `name` is one of [`SAFE_VERB_HOOKS`] as git finds
/// it. `find_hook` opens the hook by name, so on a case-insensitive volume (the macOS and Windows defaults) any casing
/// is that hook: names are compared ASCII case-insensitively everywhere (on a case-sensitive volume this only asks
/// more). Git for Windows also runs `<name>.exe`, and runs scripts through their `#!` line; on Windows
/// (`windows`) any extension after the name counts, except `.sample`. In doubt, the file is the hook.
pub(crate) fn names_safe_verb_hook(name: &str, windows: bool) -> bool {
    let name = name.to_ascii_lowercase();
    SAFE_VERB_HOOKS.iter().any(|hook| {
        name == *hook
            || (windows
                && name
                    .strip_prefix(hook)
                    .and_then(|rest| rest.strip_prefix('.'))
                    .is_some_and(|extension| extension != "sample"))
    })
}

/// Whether git would run the hook file at `path`: on unix a file with an execute bit (a dangling link or other
/// unreadable entry is `None`); elsewhere any file.
fn hook_would_run(path: &std::path::Path) -> Option<bool> {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(false),
        Err(_) => return None,
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Some(meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        Some(meta.is_file())
    }
}

/// The local and worktree entries as the git binary reads them (`config --list --show-scope
/// --show-origin --includes -z`: `scope NUL origin NUL key LF value NUL`, a bare key without the
/// LF), plus every entry of another scope that comes from a file inside the repository (u35 g6,
/// Astra r5: the user's global config or an environment `include.path` that pulls in a tracked
/// file makes that file's settings the repository's). `None` when git fails or prints what cannot
/// be parsed.
fn git_cli_local_config_entries(
    repo: &git2::Repository,
    git: Option<&Path>,
) -> Option<Vec<(String, String)>> {
    // Judged on the repository's own directory (the work tree, else the git directory). An untrusted folder gets no
    // git CLI read: the config is unreadable, which every caller already treats as "cannot tell".
    let dir = repo.workdir().unwrap_or_else(|| repo.path());
    let mut cmd = match git {
        Some(git) => fuigo_tty_utils::git_command_at_in(git, dir),
        None => fuigo_tty_utils::git_command_in(dir),
    }
    .ok()?;
    cmd.arg(format!("--git-dir={}", repo.path().display()));
    if let Some(workdir) = repo.workdir() {
        cmd.arg(format!("--work-tree={}", workdir.display()));
    }
    #[cfg(test)]
    cmd.envs(crate::permission::exec_risk::test_inherited_env());
    for name in crate::permission::exec_risk::scan_env_removals() {
        cmd.env_remove(name);
    }
    let output = cmd
        .args(["config", "--list", "--show-scope", "--show-origin", "--includes", "-z"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let mut fields = text.split('\0');
    let mut out = Vec::new();
    while let Some(scope) = fields.next() {
        if scope.is_empty() {
            break;
        }
        let origin = fields.next()?;
        let record = fields.next()?;
        if !matches!(scope, "local" | "worktree") && !origin_is_in_repository(origin, repo) {
            continue;
        }
        let (name, value) = record.split_once('\n').unwrap_or((record, "true"));
        out.push((name.to_owned(), value.to_owned()));
    }
    Some(out)
}

/// A `--show-origin` origin that is a file in the repository's work tree or git directory (a
/// relative file name counts as inside). `command line:` and other non-file origins are not.
fn origin_is_in_repository(origin: &str, repo: &git2::Repository) -> bool {
    let Some(path) = origin.strip_prefix("file:") else {
        return false;
    };
    let path = std::path::Path::new(path);
    if !path.is_absolute() {
        return true;
    }
    let resolved = dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    [Some(repo.path()), repo.workdir()].into_iter().flatten().any(|root| {
        let root_resolved = dunce::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
        path.starts_with(root) || resolved.starts_with(&root_resolved)
    })
}

/// One repository's local/worktree config entries as libgit2 reads them. `None` on read errors.
fn libgit2_local_config_entries(repo: &git2::Repository) -> Option<Vec<(String, String)>> {
    // `repo.config()` can still open global levels when local is unreadable.
    let git_dir = repo.path();
    let common = repo.commondir();
    if path_unreadable(&common.join("config"))
        || path_unreadable(&git_dir.join("config"))
        || path_unreadable(&git_dir.join("config.worktree"))
    {
        return None;
    }
    let config = match repo.config() {
        Ok(c) => c,
        Err(_) => return None,
    };
    let mut entries = match config.entries(None) {
        Ok(e) => e,
        Err(_) => return None,
    };
    let mut out = Vec::new();
    while let Some(entry) = entries.next() {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => return None,
        };
        match entry.level() {
            git2::ConfigLevel::Local | git2::ConfigLevel::Worktree => {}
            _ => continue,
        }
        // git2 yields None for non-UTF-8. Dropping that entry would hide a filter Git can still run.
        let name = entry.name()?;
        // libgit2 does not evaluate `includeIf.hasconfig:remote.*.url`.
        if local_includeif_unsupported(name) {
            return None;
        }
        // A bare key is boolean true. `value()` panics when no value is defined.
        let value = if entry.has_value() {
            let Some(value) = entry.value() else {
                if filter_command_driver(name).is_some() {
                    return None;
                }
                continue;
            };
            value
        } else if filter_command_driver(name).is_some() {
            return None;
        } else {
            "true"
        };
        out.push((name.to_owned(), value.to_owned()));
    }
    Some(out)
}

pub(crate) fn local_content_filter_drivers(cwd: &Path) -> Option<Vec<String>> {
    let entries = read_local_git_config_entries(cwd)?;
    let mut drivers = BTreeSet::new();
    for (name, value) in entries {
        if value.trim().is_empty() {
            continue;
        }
        let Some(driver) = filter_command_driver(&name) else {
            continue;
        };
        // Hostile names cannot be expressed as `git -c filter.<name>.*` (splits on first `=`).
        if !filter_driver_name_is_pinnable(driver) {
            return None;
        }
        drivers.insert(driver.to_owned());
    }
    Some(drivers.into_iter().collect())
}

pub(crate) fn content_filter_config_pins(cwd: &Path) -> Option<Vec<String>> {
    let drivers = local_content_filter_drivers(cwd)?;
    let mut pins = Vec::with_capacity(drivers.len() * 4);
    for driver in drivers {
        // required=false avoids status erroring into still invoking a required filter.
        pins.push(format!("filter.{driver}.clean="));
        pins.push(format!("filter.{driver}.smudge="));
        pins.push(format!("filter.{driver}.process="));
        pins.push(format!("filter.{driver}.required=false"));
    }
    Some(pins)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_command_driver_does_not_panic_on_multibyte() {
        assert!(filter_command_driver("alias.éxxx").is_none());
    }

    #[test]
    fn pins_unsupported_includeif_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        git2::Repository::init(tmp.path()).unwrap();
        std::fs::write(
            tmp.path().join(".git/config"),
            "[core]\n\trepositoryformatversion = 0\n\
             [includeIf \"hasconfig:remote.*.url:https://example.com/**\"]\n\
             \tpath = ../filters.gitconfig\n",
        )
        .unwrap();
        assert!(content_filter_config_pins(tmp.path()).is_none());
    }

    #[test]
    fn pins_valueless_boolean_key_does_not_panic() {
        let tmp = tempfile::tempdir().unwrap();
        git2::Repository::init(tmp.path()).unwrap();
        std::fs::write(
            tmp.path().join(".git/config"),
            "[core]\n\trepositoryformatversion = 0\n\tignorecase\n\
             [filter \"lfs\"]\n\tprocess = git-lfs filter-process\n",
        )
        .unwrap();
        let pins = content_filter_config_pins(tmp.path()).expect("bare boolean is readable");
        assert!(pins.iter().any(|p| p == "filter.lfs.process="), "{pins:?}");
    }

    #[test]
    fn pins_valueless_filter_command_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        git2::Repository::init(tmp.path()).unwrap();
        std::fs::write(
            tmp.path().join(".git/config"),
            "[core]\n\trepositoryformatversion = 0\n\
             [filter \"pwn\"]\n\tclean\n",
        )
        .unwrap();
        assert!(content_filter_config_pins(tmp.path()).is_none());
    }

    #[test]
    fn pins_unreadable_config_are_none() {
        let tmp = tempfile::tempdir().unwrap();
        git2::Repository::init(tmp.path()).unwrap();
        let cfg = tmp.path().join(".git/config");
        std::fs::remove_file(&cfg).unwrap();
        std::fs::create_dir(&cfg).unwrap();
        assert!(content_filter_config_pins(tmp.path()).is_none());
    }

    #[test]
    fn pins_safe_lfs_process_driver() {
        let tmp = tempfile::tempdir().unwrap();
        git2::Repository::init(tmp.path()).unwrap();
        std::fs::write(
            tmp.path().join(".git/config"),
            "[core]\n\trepositoryformatversion = 0\n\
             [filter \"lfs\"]\n\tprocess = git-lfs filter-process\n",
        )
        .unwrap();
        let pins = content_filter_config_pins(tmp.path()).expect("readable");
        assert_eq!(
            pins,
            vec![
                "filter.lfs.clean=".to_owned(),
                "filter.lfs.smudge=".to_owned(),
                "filter.lfs.process=".to_owned(),
                "filter.lfs.required=false".to_owned(),
            ]
        );
    }

    #[test]
    fn pins_non_utf8_filter_value_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        git2::Repository::init(tmp.path()).unwrap();
        let mut cfg =
            b"[core]\n\trepositoryformatversion = 0\n[filter \"pwn\"]\n\tclean = ".to_vec();
        cfg.extend_from_slice(&[0xff, 0xfe]);
        cfg.push(b'\n');
        std::fs::write(tmp.path().join(".git/config"), cfg).unwrap();
        assert!(content_filter_config_pins(tmp.path()).is_none());
    }

    #[test]
    fn pins_mixed_case_driver_keeps_spelling() {
        let tmp = tempfile::tempdir().unwrap();
        git2::Repository::init(tmp.path()).unwrap();
        std::fs::write(
            tmp.path().join(".git/config"),
            "[core]\n\trepositoryformatversion = 0\n\
             [filter \"Pwn\"]\n\tclean = /tmp/pwn\n",
        )
        .unwrap();
        let pins = content_filter_config_pins(tmp.path()).expect("readable");
        assert!(pins.iter().any(|p| p == "filter.Pwn.clean="), "{pins:?}");
        assert!(!pins.iter().any(|p| p.starts_with("filter.pwn.")));
    }

    /// Astra r2 N9: a dotted or spaced driver name is pinned as written, not refused.
    #[test]
    fn pins_dotted_and_spaced_driver_names() {
        for section in ["pwn x", "pwn.x"] {
            let tmp = tempfile::tempdir().unwrap();
            git2::Repository::init(tmp.path()).unwrap();
            std::fs::write(
                tmp.path().join(".git/config"),
                format!(
                    "[core]\n\trepositoryformatversion = 0\n\
                     [filter \"{section}\"]\n\tclean = /tmp/pwn\n"
                ),
            )
            .unwrap();
            let pins = content_filter_config_pins(tmp.path()).expect("pinnable");
            assert!(
                pins.contains(&format!("filter.{section}.clean=")),
                "section={section:?}: {pins:?}"
            );
        }
    }

    /// Astra r3 N14: where libgit2 and git disagree on an include, the filters git reads are
    /// still pinned.
    #[test]
    fn pins_filters_git_reads_through_an_include_libgit2_misreads() {
        let tmp = tempfile::tempdir().unwrap();
        git2::Repository::init(tmp.path()).unwrap();
        std::fs::write(
            tmp.path().join(".git/config"),
            "[core]\n\trepositoryformatversion = 0\n[include]\n\tpath = \"\" ../filters.gitconfig\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("filters.gitconfig"),
            "[filter \"pwn\"]\n\tclean = /tmp/pwn\n",
        )
        .unwrap();
        let git_reads = fuigo_tty_utils::git_command()
            .args(["config", "--includes", "--get", "filter.pwn.clean"])
            .current_dir(tmp.path())
            .output()
            .expect("git config runs");
        let pins = content_filter_config_pins(tmp.path()).expect("readable");
        if git_reads.status.success() {
            assert!(pins.iter().any(|p| p == "filter.pwn.clean="), "{pins:?}");
        }
        // The CLI reading alone finds it (whatever libgit2 makes of the include)
        let repo = git2::Repository::open(tmp.path()).unwrap();
        let cli = git_cli_local_config_entries(&repo, None).expect("git config --list");
        assert_eq!(
            git_reads.status.success(),
            cli.iter().any(|(name, _)| name == "filter.pwn.clean"),
            "{cli:?}"
        );
    }

    #[test]
    fn pins_hostile_driver_names_fail_closed() {
        // `-c` splits at the first `=`, so this name cannot be spelled
        let section = "pwn=x";
        let tmp = tempfile::tempdir().unwrap();
        git2::Repository::init(tmp.path()).unwrap();
        std::fs::write(
            tmp.path().join(".git/config"),
            format!(
                "[core]\n\trepositoryformatversion = 0\n\
                 [filter \"{section}\"]\n\tclean = /tmp/pwn\n"
            ),
        )
        .unwrap();
        assert!(
            content_filter_config_pins(tmp.path()).is_none(),
            "section={section:?}"
        );
    }

    /// u35 g12 (Fable r11 Low): a `*.sample` file is no hook in any letter case; a hook name that merely contains
    /// `sample` is one.
    #[test]
    fn u35_g12_sample_hooks_are_skipped_in_any_case() {
        for name in ["pre-commit.sample", "pre-commit.SAMPLE", "Post-Index-Change.Sample"] {
            assert!(is_sample_hook(name), "{name}");
        }
        for name in ["pre-commit", "sample-hook", "pre-commit.samples"] {
            assert!(!is_sample_hook(name), "{name}");
        }
        let tmp = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init(tmp.path()).unwrap();
        let hooks = tmp.path().join(".git/hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        for name in ["pre-commit.SAMPLE", "post-checkout.Sample"] {
            let hook = hooks.join(name);
            std::fs::write(&hook, "#!/bin/sh\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        assert_eq!(hooks_entry(&repo), Some(Vec::new()), "samples in any case are no hooks");
    }

    /// u35 g12 (Fable r11 Low): on Windows, Git for Windows runs `post-index-change.exe` for `git status`, so the
    /// hooks directory reports it as a safe-verb hook (`core.hookspath`); a `.sample` of it is not one.
    #[cfg(windows)]
    #[test]
    fn u35_g12_windows_exe_safe_verb_hook_is_found() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init(tmp.path()).unwrap();
        let hooks = tmp.path().join(".git/hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        std::fs::write(hooks.join("post-index-change.sample"), "#!/bin/sh\n").unwrap();
        assert_eq!(hooks_entry(&repo), Some(Vec::new()));
        std::fs::write(hooks.join("Post-Index-Change.EXE"), "MZ").unwrap();
        let entries = hooks_entry(&repo).expect("readable");
        assert!(entries.iter().any(|(name, _)| name == "core.hookspath"), "{entries:?}");
    }
}
