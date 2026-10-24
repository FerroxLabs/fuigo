//! Another `fuigo` on PATH that is a different version.
//!
//! A stale copy earlier on PATH (an old package-manager install ahead of a newer one) silently
//! runs instead of the version the user thinks they have. `fuigo doctor` and the welcome screen
//! name both paths so the user can remove one.
//!
//! The scan itself is pure over an injected PATH and an injected "run `--version`" so it is tested
//! without touching the machine.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// A `fuigo` on PATH that is not this executable and reports a different version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtherInstall {
    pub path: PathBuf,
    pub version: String,
}

/// Most candidates inspected: each one is a child process.
const MAX_CANDIDATES: usize = 4;

/// The first `major.minor.patch` token in `text` (with an optional leading `v` and a pre-release
/// or build suffix kept), e.g. `"fuigo 1.0.19 (abc123)"` gives `1.0.19`.
pub fn parse_version(text: &str) -> Option<String> {
    text.split_whitespace().find_map(|token| {
        let token = token.trim_start_matches('v');
        let core: String = token
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
            .collect();
        let mut parts = core.splitn(3, '.');
        let (a, b, c) = (parts.next()?, parts.next()?, parts.next()?);
        let digits = |s: &str| !s.is_empty() && s.chars().all(|ch| ch.is_ascii_digit());
        let patch: String = c.chars().take_while(char::is_ascii_digit).collect();
        (digits(a) && digits(b) && !patch.is_empty()).then(|| {
            let rest = &c[patch.len()..];
            format!("{a}.{b}.{patch}{rest}")
        })
    })
}

/// Every other `fuigo` on `path_var` whose `--version` differs from `current_version`.
/// `run_version` runs the candidate and returns its output; a candidate that cannot be run is skipped.
pub fn find_other_installs(
    path_var: &OsStr,
    current_exe: &Path,
    current_version: &str,
    run_version: impl Fn(&Path) -> Option<String>,
) -> Vec<OtherInstall> {
    let name = if cfg!(windows) { "fuigo.exe" } else { "fuigo" };
    let current = dunce::canonicalize(current_exe).unwrap_or_else(|_| current_exe.to_path_buf());
    let mut seen: Vec<PathBuf> = vec![current];
    let mut out = Vec::new();
    for dir in std::env::split_paths(path_var) {
        if seen.len() > MAX_CANDIDATES {
            break;
        }
        let candidate = dir.join(name);
        if !candidate.is_file() {
            continue;
        }
        let real = dunce::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
        if seen.contains(&real) {
            continue;
        }
        seen.push(real);
        let Some(version) = run_version(&candidate).and_then(|o| parse_version(&o)) else {
            continue;
        };
        if version != current_version {
            out.push(OtherInstall {
                path: candidate,
                version,
            });
        }
    }
    out
}

/// The one-line warning for the welcome screen, or the doctor line.
pub fn warning_text(current_exe: &Path, current_version: &str, other: &OtherInstall) -> String {
    format!(
        "Another fuigo on your PATH is a different version: {} is {}, this one ({}) is {}. \
         Remove or reorder one so `fuigo` starts the version you expect.",
        other.path.display(),
        other.version,
        current_exe.display(),
        current_version
    )
}

/// Run `path --version` with a clean environment and a hard time limit.
#[cfg(unix)]
pub fn run_version_with_limit(path: &Path) -> Option<String> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    let mut command = Command::new(path);
    command
        .arg("--version")
        .env_clear()
        .env("PATH", std::env::var_os("PATH")?)
        .env("HOME", std::env::var_os("HOME").unwrap_or_default())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    fuigo_tty_utils::detach_std_command(&mut command);
    // A crashed or killed fuigo must not leave a probe behind.
    fuigo_tty_utils::kill_on_parent_death_std(&mut command);
    #[allow(clippy::disallowed_methods)] // bound by kill-on-parent-death, killed below at the deadline
    let mut child = command.spawn().ok()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(1500);
    loop {
        match child.try_wait().ok()? {
            Some(status) if status.success() => break,
            Some(_) => return None,
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            None => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    }
    let mut text = String::new();
    child.stdout.take()?.take(4096).read_to_string(&mut text).ok()?;
    Some(text)
}

#[cfg(not(unix))]
pub fn run_version_with_limit(_path: &Path) -> Option<String> {
    None
}

/// Every other-version `fuigo` on this machine's PATH, for `doctor` and the welcome screen.
pub fn other_installs_on_path() -> Vec<OtherInstall> {
    let (Some(path_var), Ok(exe)) = (std::env::var_os("PATH"), std::env::current_exe()) else {
        return Vec::new();
    };
    find_other_installs(&path_var, &exe, fuigo_version::VERSION, run_version_with_limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_install(dir: &Path, name: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, b"#!/bin/sh\n").unwrap();
        p
    }

    fn path_of(dirs: &[&Path]) -> std::ffi::OsString {
        std::env::join_paths(dirs).unwrap()
    }

    #[test]
    fn parse_version_reads_the_first_semver_token() {
        assert_eq!(parse_version("fuigo 1.0.19 (abc123)").as_deref(), Some("1.0.19"));
        assert_eq!(parse_version("v1.0.31\n").as_deref(), Some("1.0.31"));
        assert_eq!(parse_version("fuigo 1.0.32-rc.1+build").as_deref(), Some("1.0.32-rc.1+build"));
        assert_eq!(parse_version("no version here"), None);
        assert_eq!(parse_version("1.0"), None);
    }

    /// Sean's Mac: a stale Homebrew-node 1.0.19 ahead of nvm 1.0.31.
    #[test]
    fn a_stale_copy_on_path_is_reported_with_both_paths() {
        let dir = tempfile::tempdir().unwrap();
        let stale = fake_install(&dir.path().join("homebrew/bin"), "fuigo");
        let current = fake_install(&dir.path().join("nvm/bin"), "fuigo");
        let found = find_other_installs(
            &path_of(&[stale.parent().unwrap(), current.parent().unwrap()]),
            &current,
            "1.0.31",
            |p| Some(if p == stale { "fuigo 1.0.19".into() } else { "fuigo 1.0.31".into() }),
        );
        assert_eq!(
            found,
            vec![OtherInstall {
                path: stale.clone(),
                version: "1.0.19".into()
            }]
        );
        let text = warning_text(&current, "1.0.31", &found[0]);
        assert!(text.contains(&stale.display().to_string()), "{text}");
        assert!(text.contains(&current.display().to_string()), "{text}");
        assert!(text.contains("1.0.19") && text.contains("1.0.31"), "{text}");
    }

    #[test]
    fn the_same_version_a_symlink_to_this_binary_and_unrunnable_copies_are_not_reported() {
        let dir = tempfile::tempdir().unwrap();
        let current = fake_install(&dir.path().join("a"), "fuigo");
        let same_version = fake_install(&dir.path().join("b"), "fuigo");
        let broken = fake_install(&dir.path().join("c"), "fuigo");
        #[cfg(unix)]
        {
            std::fs::create_dir_all(dir.path().join("d")).unwrap();
            std::os::unix::fs::symlink(&current, dir.path().join("d/fuigo")).unwrap();
        }
        let dirs: Vec<PathBuf> = ["a", "b", "c", "d"].iter().map(|d| dir.path().join(d)).collect();
        let refs: Vec<&Path> = dirs.iter().map(PathBuf::as_path).collect();
        let found = find_other_installs(&path_of(&refs), &current, "1.0.31", |p| {
            if p == broken {
                None
            } else if p == same_version || p.ends_with("d/fuigo") {
                Some("fuigo 1.0.31".into())
            } else {
                Some("fuigo 9.9.9".into())
            }
        });
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn the_scan_inspects_a_bounded_number_of_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let current = fake_install(&dir.path().join("cur"), "fuigo");
        let mut dirs = vec![dir.path().join("cur")];
        for i in 0..12 {
            fake_install(&dir.path().join(format!("d{i}")), "fuigo");
            dirs.push(dir.path().join(format!("d{i}")));
        }
        let ran = std::cell::Cell::new(0usize);
        let refs: Vec<&Path> = dirs.iter().map(PathBuf::as_path).collect();
        let found = find_other_installs(&path_of(&refs), &current, "1.0.31", |_| {
            ran.set(ran.get() + 1);
            Some("fuigo 2.0.0".into())
        });
        assert!(ran.get() <= MAX_CANDIDATES, "ran {} candidates", ran.get());
        assert_eq!(found.len(), ran.get());
    }

    #[cfg(unix)]
    #[test]
    fn a_hung_candidate_is_killed_within_the_limit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let hang = dir.path().join("fuigo");
        std::fs::write(&hang, "#!/bin/sh\nsleep 30\n").unwrap();
        std::fs::set_permissions(&hang, std::fs::Permissions::from_mode(0o755)).unwrap();
        let started = std::time::Instant::now();
        assert_eq!(run_version_with_limit(&hang), None);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }
}
