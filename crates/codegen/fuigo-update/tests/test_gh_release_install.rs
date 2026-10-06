//! R110: the gh-release installer and the gh-release choice of "latest".
//!
//! - U1: the binary is downloaded to a temp file next to its final path, checked (size, executable,
//!   its `SHA256SUMS` entry from the same release) and only then renamed into place. A download that
//!   dies part way leaves the binary the live `bin/fuigo` points at untouched.
//! - U2: "latest" is the highest version among the stable releases, not the newest created one, and an
//!   automatic update never installs a version lower than the one running. An explicit
//!   `fuigo update --version X` or `--force` can still go down.
//!
//! The fake `gh` writes downloads IN PLACE (`cat > "$out"`), which is the worst case for a reinstall
//! whose `--output` is the live binary.

#![cfg(unix)]

mod common;

use std::io::Read;
use std::path::{Path, PathBuf};

use serial_test::serial;

use common::{
    FakeBinGuard, can_exec_shell_scripts, host_platform, make_update_config, reset_home,
    set_test_version, small_good_artifact, test_home,
};
use fuigo_update::auto_update::{
    CliUpdateTrigger, auto_update_target, check_update_status, ensure_latest_on_disk, run_update,
};

/// The binary the fake release serves: runs and exits 0, and differs from [`small_good_artifact`].
const NEW_BINARY: &[u8] = b"#!/bin/sh\n# new build\nexit 0\n";

/// sha256 of [`NEW_BINARY`] (`printf '#!/bin/sh\n# new build\nexit 0\n' | sha256sum`).
const NEW_BINARY_SHA256: &str = "9c718d4ad7a84572f2812eb5c4190f0f172cb30d7bf1fde047426fdaa7003218";

/// Fake `gh`: `release list` answers from `gh-stable-only-stdout` / `gh-with-pre-stdout`;
/// `release download <tag> ... --pattern P --output O` writes `gh-sums` for `SHA256SUMS` (fails when
/// that file is absent, as gh does when no asset matches) and `gh-binary` otherwise. With
/// `gh-interrupt` present a binary download writes 10 bytes and fails, like a download killed part way.
fn fake_gh(dir: &Path) -> String {
    let dq = format!("'{}'", dir.to_string_lossy().replace('\'', "'\\''"));
    format!(
        r#"#!/bin/sh
echo "$@" >> {dq}/gh-args.log
case "$*" in
  *"release list"*)
    case "$*" in
      *--exclude-pre-releases*) f={dq}/gh-stable-only-stdout ;;
      *) f={dq}/gh-with-pre-stdout ;;
    esac
    if [ -f "$f" ]; then cat "$f"; fi
    exit 0
    ;;
  *"release download"*)
    out=""; pat=""; prev=""
    for a in "$@"; do
      if [ "$prev" = "--output" ]; then out="$a"; fi
      if [ "$prev" = "--pattern" ]; then pat="$a"; fi
      prev="$a"
    done
    if [ "$pat" = "SHA256SUMS" ]; then
      if [ ! -f {dq}/gh-sums ]; then echo "no assets match the file pattern" >&2; exit 1; fi
      cat {dq}/gh-sums > "$out"
      exit 0
    fi
    if [ -f {dq}/gh-interrupt ]; then
      head -c 10 {dq}/gh-binary > "$out"
      exit 1
    fi
    cat {dq}/gh-binary > "$out"
    chmod +x "$out"
    exit 0
    ;;
esac
exit 0
"#
    )
}

struct Release {
    gh: FakeBinGuard,
}

impl Release {
    /// A gh-release install running `running`, whose release list (newest created first) is `tags`.
    fn new(running: &str, tags: &[&str]) -> Self {
        let _ = test_home();
        reset_home();
        set_test_version(running);
        // Serial test: no other thread reads the environment; reset_home clears this between tests.
        unsafe { std::env::set_var("FUIGO_INSTALLER", "gh-release") };
        let gh = FakeBinGuard::install("gh", fake_gh);
        let list: String = tags.iter().map(|t| format!("{t}\n")).collect();
        gh.set_stable_only_stdout(&list);
        gh.set_with_pre_stdout(&list);
        std::fs::write(gh.dir().join("gh-binary"), NEW_BINARY).unwrap();
        Self { gh }
    }

    /// Publish a `SHA256SUMS` listing `NEW_BINARY` under each version's asset name.
    fn with_sums(self, versions: &[&str]) -> Self {
        let platform = host_platform();
        let sums: String = versions
            .iter()
            .map(|v| format!("{NEW_BINARY_SHA256}  fuigo-{v}-{platform}\n"))
            .collect();
        std::fs::write(self.gh.dir().join("gh-sums"), sums).unwrap();
        self
    }

    fn set(&self, name: &str, content: &[u8]) {
        std::fs::write(self.gh.dir().join(name), content).unwrap();
    }

    fn downloads(&self) -> Vec<String> {
        self.gh
            .args_log()
            .into_iter()
            .filter(|l| l.contains("release download"))
            .collect()
    }
}

/// `bin/fuigo -> ../downloads/fuigo-<version>-<platform>` holding [`small_good_artifact`].
fn managed_install(version: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let home = test_home();
    let downloads = home.join("downloads");
    let bin = home.join("bin");
    std::fs::create_dir_all(&downloads).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    let name = format!("fuigo-{version}-{}", host_platform());
    let path = downloads.join(&name);
    std::fs::write(&path, small_good_artifact()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::symlink(Path::new("../downloads").join(&name), bin.join("fuigo")).unwrap();
    path
}

/// The live `bin/fuigo`: its resolved file name, its bytes, and whether it runs.
fn live_binary() -> (String, Vec<u8>, bool) {
    let link = test_home().join("bin").join("fuigo");
    let resolved = dunce::canonicalize(&link).expect("bin/fuigo must resolve");
    let runs = std::process::Command::new(&link)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    (
        resolved.file_name().unwrap().to_string_lossy().into_owned(),
        std::fs::read(&resolved).unwrap(),
        runs,
    )
}

/// Temp files left in `downloads/` (anything that is not a final `fuigo-*` binary or link).
fn temp_leftovers() -> Vec<String> {
    std::fs::read_dir(test_home().join("downloads"))
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".tmp") || n.ends_with(".part") || n.contains("SHA256SUMS"))
                .collect()
        })
        .unwrap_or_default()
}

// ── U1 ──────────────────────────────────────────────────────────────────────

/// A `--force` reinstall of the running version whose download dies part way must leave the binary
/// `bin/fuigo` points at exactly as it was, and runnable.
#[tokio::test]
#[serial]
async fn interrupted_gh_download_leaves_the_live_binary_runnable() {
    if !can_exec_shell_scripts() {
        eprintln!("skipping: shell scripts cannot execute in this sandbox");
        return;
    }
    let release = Release::new("0.2.7", &["v0.2.7"]).with_sums(&["0.2.7"]);
    release.set("gh-interrupt", b"");
    managed_install("0.2.7");
    let mut cfg = make_update_config("stable");

    let result = run_update(true, None, None, &mut cfg, CliUpdateTrigger::UserCommand).await;

    assert!(result.is_err(), "an interrupted download must fail the update");
    assert_eq!(release.downloads().len(), 1, "{:?}", release.downloads());
    let (name, bytes, runs) = live_binary();
    assert_eq!(name, format!("fuigo-0.2.7-{}", host_platform()));
    assert_eq!(bytes, small_good_artifact(), "the live binary must be untouched");
    assert!(runs, "the live binary must still run");
    assert!(temp_leftovers().is_empty(), "{:?}", temp_leftovers());
}

/// The success path writes a NEW file and renames it into place: a handle opened on the old binary
/// before the update still reads the old bytes, and the release's `SHA256SUMS` was consulted.
#[tokio::test]
#[serial]
async fn gh_release_install_renames_a_verified_download_into_place() {
    if !can_exec_shell_scripts() {
        eprintln!("skipping: shell scripts cannot execute in this sandbox");
        return;
    }
    let release = Release::new("0.2.7", &["v0.2.7"]).with_sums(&["0.2.7"]);
    let old_path = managed_install("0.2.7");
    let mut old_handle = std::fs::File::open(&old_path).unwrap();
    let mut cfg = make_update_config("stable");

    let result = run_update(true, None, None, &mut cfg, CliUpdateTrigger::UserCommand).await;

    assert_eq!(result.unwrap().as_deref(), Some("0.2.7"));
    let (name, bytes, runs) = live_binary();
    assert_eq!(name, format!("fuigo-0.2.7-{}", host_platform()));
    assert_eq!(bytes, NEW_BINARY, "the new build must be live");
    assert!(runs);
    let mut seen = Vec::new();
    old_handle.read_to_end(&mut seen).unwrap();
    assert_eq!(seen, small_good_artifact(), "the old file must have been replaced by rename, not rewritten");
    let downloads = release.downloads();
    assert!(downloads.iter().any(|l| l.contains("--pattern SHA256SUMS")), "{downloads:?}");
    let live = old_path.to_string_lossy().into_owned();
    assert!(
        downloads.iter().all(|l| !l.ends_with(&live) && !l.contains(&format!("{live} "))),
        "gh must never write to the live path: {downloads:?}"
    );
    assert!(temp_leftovers().is_empty(), "{:?}", temp_leftovers());
}

/// A download whose bytes do not match the release's `SHA256SUMS`, an asset the file does not list,
/// a release without `SHA256SUMS`, and an empty download are all refused; the live binary stays.
#[tokio::test]
#[serial]
async fn gh_release_install_refuses_an_unverified_download() {
    if !can_exec_shell_scripts() {
        eprintln!("skipping: shell scripts cannot execute in this sandbox");
        return;
    }
    let platform = host_platform();
    let cases: [(&str, Option<String>, &[u8]); 4] = [
        (
            "checksum mismatch",
            Some(format!("{}  fuigo-0.2.7-{platform}\n", "0".repeat(64))),
            NEW_BINARY,
        ),
        ("asset not listed", Some(format!("{NEW_BINARY_SHA256}  fuigo-0.2.6-{platform}\n")), NEW_BINARY),
        ("no SHA256SUMS", None, NEW_BINARY),
        (
            "empty download",
            Some(format!(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  fuigo-0.2.7-{platform}\n"
            )),
            b"",
        ),
    ];
    for (label, sums, binary) in cases {
        let release = Release::new("0.2.7", &["v0.2.7"]);
        if let Some(sums) = sums {
            release.set("gh-sums", sums.as_bytes());
        }
        release.set("gh-binary", binary);
        managed_install("0.2.7");
        let mut cfg = make_update_config("stable");

        let result = run_update(true, None, None, &mut cfg, CliUpdateTrigger::UserCommand).await;

        assert!(result.is_err(), "{label}: must be refused");
        let (_, bytes, runs) = live_binary();
        assert_eq!(bytes, small_good_artifact(), "{label}: the live binary must be untouched");
        assert!(runs, "{label}");
        assert!(temp_leftovers().is_empty(), "{label}: {:?}", temp_leftovers());
    }
}

// ── U2 ──────────────────────────────────────────────────────────────────────

/// An older-line release created after the running one (listed first, as gh lists newest created
/// first) is not "latest": the highest stable version is.
#[tokio::test]
#[serial]
async fn newest_created_lower_release_is_not_chosen() {
    let _release = Release::new("1.0.21", &["v1.0.19", "v1.0.21", "v1.0.20"]);

    let status = check_update_status(&make_update_config("stable")).await;
    assert_eq!(status.error, None);
    assert_eq!(status.latest_version.as_deref(), Some("1.0.21"));
    assert!(!status.update_available);
    assert_eq!(auto_update_target(&make_update_config("stable")).await, None);

    // And a newer release created before an older-line hotfix is still found.
    let _release = Release::new("1.0.20", &["v1.0.19", "v1.0.21", "v1.0.20"]);
    assert_eq!(
        auto_update_target(&make_update_config("stable")).await,
        Some(("gh-release", "1.0.21".to_string()))
    );
}

/// The automatic paths never go below the running version, even when the highest release is lower
/// (the newer one was deleted or demoted).
#[tokio::test]
#[serial]
async fn automatic_update_never_downgrades_a_gh_release_install() {
    if !can_exec_shell_scripts() {
        eprintln!("skipping: shell scripts cannot execute in this sandbox");
        return;
    }
    let release = Release::new("1.0.21", &["v1.0.19"]).with_sums(&["1.0.19"]);
    managed_install("1.0.21");
    let cfg = make_update_config("stable");

    assert_eq!(auto_update_target(&cfg).await, None);
    let outcome = ensure_latest_on_disk(&cfg).await.unwrap();
    assert_eq!(outcome.installed, None);
    assert!(!outcome.relaunch_needed);
    let mut cfg = make_update_config("stable");
    let plain = run_update(false, None, None, &mut cfg, CliUpdateTrigger::AutoBackground).await;
    // It reports what is on disk (not the lower release), so the caller signals only leaders older than that
    // (Astra P110 r3 #2).
    assert_eq!(plain.unwrap().as_deref(), Some("1.0.21"));
    assert!(release.downloads().is_empty(), "{:?}", release.downloads());
    let (name, _, _) = live_binary();
    assert_eq!(name, format!("fuigo-1.0.21-{}", host_platform()));
}

/// `fuigo update --version X` still installs a lower version.
#[tokio::test]
#[serial]
async fn explicit_version_downgrade_still_installs() {
    if !can_exec_shell_scripts() {
        eprintln!("skipping: shell scripts cannot execute in this sandbox");
        return;
    }
    let release = Release::new("1.0.21", &["v1.0.21", "v1.0.19"]).with_sums(&["1.0.19"]);
    managed_install("1.0.21");
    let mut cfg = make_update_config("stable");

    let result = run_update(false, Some("1.0.19"), None, &mut cfg, CliUpdateTrigger::UserCommand).await;

    assert_eq!(result.unwrap().as_deref(), Some("1.0.19"));
    assert!(release.downloads().iter().any(|l| l.contains("release download v1.0.19")));
    let (name, bytes, _) = live_binary();
    assert_eq!(name, format!("fuigo-1.0.19-{}", host_platform()));
    assert_eq!(bytes, NEW_BINARY);
}

/// `fuigo update --force` still goes down to the highest release when that is lower.
#[tokio::test]
#[serial]
async fn forced_update_still_downgrades_to_the_highest_release() {
    if !can_exec_shell_scripts() {
        eprintln!("skipping: shell scripts cannot execute in this sandbox");
        return;
    }
    let release = Release::new("1.0.21", &["v1.0.19"]).with_sums(&["1.0.19"]);
    managed_install("1.0.21");
    let mut cfg = make_update_config("stable");

    let result = run_update(true, None, None, &mut cfg, CliUpdateTrigger::UserCommand).await;

    assert_eq!(result.unwrap().as_deref(), Some("1.0.19"));
    assert!(release.downloads().iter().any(|l| l.contains("release download v1.0.19")));
    let (name, _, _) = live_binary();
    assert_eq!(name, format!("fuigo-1.0.19-{}", host_platform()));
}
