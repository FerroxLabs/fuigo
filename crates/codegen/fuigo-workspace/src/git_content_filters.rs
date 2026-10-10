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
    let mut out = repo_local_config_entries(&repo)?;
    let mut budget = SUBMODULE_SCAN_LIMIT;
    append_submodule_entries(&repo, 0, &mut budget, &mut out)?;
    Some(out)
}

/// The local entries of each populated submodule, recursively; `None` past the bounds or when a
/// populated submodule cannot be opened or read.
fn append_submodule_entries(
    repo: &git2::Repository,
    depth: usize,
    budget: &mut usize,
    out: &mut Vec<(String, String)>,
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
        out.extend(repo_local_config_entries(&sub)?);
        append_submodule_entries(&sub, depth + 1, budget, out)?;
    }
    Some(())
}

/// One repository's local/worktree config entries, as libgit2 reads them and as git itself reads
/// them (the union: where the two parsers disagree on an include, the entries git would act on
/// must not be lost). `None` on read errors.
fn repo_local_config_entries(repo: &git2::Repository) -> Option<Vec<(String, String)>> {
    let mut out = libgit2_local_config_entries(repo)?;
    for entry in git_cli_local_config_entries(repo)? {
        if !out.contains(&entry) {
            out.push(entry);
        }
    }
    Some(out)
}

/// The local and worktree entries as the git binary reads them (`config --list --show-scope
/// --includes -z`: `scope NUL key LF value NUL`, a bare key without the LF). `None` when git
/// fails or prints what cannot be parsed.
fn git_cli_local_config_entries(repo: &git2::Repository) -> Option<Vec<(String, String)>> {
    let mut cmd = fuigo_tty_utils::git_command();
    cmd.arg(format!("--git-dir={}", repo.path().display()));
    if let Some(workdir) = repo.workdir() {
        cmd.arg(format!("--work-tree={}", workdir.display()));
    }
    let output = cmd
        .args(["config", "--list", "--show-scope", "--includes", "-z"])
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
        let record = fields.next()?;
        if !matches!(scope, "local" | "worktree") {
            continue;
        }
        let (name, value) = record.split_once('\n').unwrap_or((record, "true"));
        out.push((name.to_owned(), value.to_owned()));
    }
    Some(out)
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
        let cli = git_cli_local_config_entries(&repo).expect("git config --list");
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
}
