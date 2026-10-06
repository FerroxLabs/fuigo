use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};

fn workspace_root() -> Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .map(|p| p.to_path_buf())
        .context("failed to resolve workspace root from CARGO_MANIFEST_DIR")
}

/// The arguments of the build that produces the local `fuigo-pager`. `--locked`: a test must never
/// rewrite `Cargo.lock`. The JSON messages name the executable cargo actually produced, so its
/// location is never guessed: `CARGO_BUILD_TARGET`, `build.target-dir` and similar configuration
/// all move it away from `<CARGO_TARGET_DIR>/debug/`, where an older binary could otherwise be
/// picked up although the build itself succeeded. (Same resolution as
/// `fuigo_test_support::env::fuigo_binary`, P69.)
const PAGER_BUILD_ARGS: &[&str] = &[
    "build",
    "--locked",
    "--message-format=json-render-diagnostics",
    "-p",
    "fuigo-pager-bin",
    "--bin",
    "fuigo-pager",
];

/// The `executable` of the `fuigo-pager` bin artifact in cargo's JSON message stream.
fn pager_executable_from_messages(stdout: &str) -> Result<PathBuf> {
    let mut found = Vec::new();
    for line in stdout.lines() {
        let Ok(message) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if message["reason"] != "compiler-artifact" || message["target"]["name"] != "fuigo-pager" {
            continue;
        }
        let is_bin = message["target"]["kind"]
            .as_array()
            .is_some_and(|kinds| kinds.iter().any(|kind| kind == "bin"));
        if let (true, Some(executable)) = (is_bin, message["executable"].as_str()) {
            found.push(PathBuf::from(executable));
        }
    }
    match found.as_slice() {
        [executable] => Ok(executable.clone()),
        [] => bail!("cargo reported no `fuigo-pager` executable artifact; stdout:\n{stdout}"),
        _ => bail!("cargo reported several `fuigo-pager` executables {found:?}; refusing to guess"),
    }
}

/// Run `launcher` + [`PAGER_BUILD_ARGS`] in `workspace` and return the executable cargo built.
///
/// ALWAYS builds: a `fuigo-pager` already in the target dir may come from another commit, and its
/// path alone cannot tell. Cargo's fingerprinting makes the build a no-op when it is fresh.
fn build_local_pager_binary(mut launcher: Command, workspace: &Path) -> Result<PathBuf> {
    launcher
        .current_dir(workspace)
        .args(PAGER_BUILD_ARGS)
        .stdin(Stdio::null())
        .envs(fuigo_tty_utils::pager_env());
    fuigo_tty_utils::detach_std_command(&mut launcher);
    let program = launcher.get_program().to_string_lossy().into_owned();
    let output = launcher
        .output()
        .with_context(|| format!("failed to spawn {program} to build fuigo-pager"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        bail!(
            "failed to build fuigo-pager (exit {:?})\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            stdout,
            String::from_utf8_lossy(&output.stderr),
        );
    }
    let binary = pager_executable_from_messages(&stdout)?;
    if !binary.exists() {
        bail!(
            "fuigo-pager build completed but binary missing at {}",
            binary.display()
        );
    }
    Ok(binary)
}

/// The locally built `fuigo-pager`, built at most once per process. The outcome -- the binary or
/// the build error -- is latched: every caller in the process gets the same binary, and a failed
/// build is reported to each caller without being retried by each.
fn local_pager_binary() -> Result<PathBuf> {
    static LOCAL: OnceLock<std::result::Result<PathBuf, String>> = OnceLock::new();
    LOCAL
        .get_or_init(|| {
            let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
            workspace_root()
                .and_then(|root| build_local_pager_binary(Command::new(cargo), &root))
                .map_err(|error| format!("{error:#}"))
        })
        .clone()
        .map_err(anyhow::Error::msg)
}

/// Resolve the pager binary path.
///
/// Resolution order:
/// 1. `PAGER_BINARY` env var (for CI / explicit override)
/// 2. `CARGO_BIN_EXE_fuigo-pager` (set by `cargo test`)
/// 3. Build locally via `cargo build -p fuigo-pager-bin` (the composition-root package that owns the `fuigo-pager` binary),
///    once per process, at the path cargo reports for the artifact (never a guessed `target/debug` path)
pub fn pager_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("PAGER_BINARY") {
        let p = PathBuf::from(path);
        if !p.exists() {
            bail!("PAGER_BINARY does not exist: {}", p.display());
        }
        // Bazel sets PAGER_BINARY to a runfiles-relative path; portable_pty resolves non-absolute paths via PATH lookup instead of the cwd
        return std::path::absolute(&p)
            .with_context(|| format!("failed to absolutize PAGER_BINARY: {}", p.display()));
    }

    if let Ok(path) = std::env::var("CARGO_BIN_EXE_fuigo-pager") {
        let p = PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
    }

    local_pager_binary()
}

#[cfg(all(test, unix))]
mod local_binary_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// The JSON line cargo prints for the built `fuigo-pager`.
    fn artifact_line(executable: &Path) -> String {
        serde_json::json!({
            "reason": "compiler-artifact",
            "target": {"name": "fuigo-pager", "kind": ["bin"]},
            "executable": executable,
            "fresh": false,
        })
        .to_string()
    }

    /// A stand-in for cargo: records its arguments, writes "fresh" to `writes` (if any), prints
    /// `stdout` and exits with `exit`. Run as `/bin/sh <script>` (not exec'd), so a sibling test
    /// thread forking while the script is written cannot cause ETXTBSY.
    fn fake_cargo(
        dir: &Path,
        writes: Option<&Path>,
        stdout: &str,
        exit: i32,
    ) -> (Command, PathBuf) {
        let args = dir.join("args.txt");
        let messages = dir.join("messages.jsonl");
        std::fs::write(&messages, stdout).unwrap();
        let write = writes
            .map(|binary| {
                format!(
                    "mkdir -p '{0}' && printf fresh > '{1}'\n",
                    binary.parent().unwrap().display(),
                    binary.display()
                )
            })
            .unwrap_or_default();
        let script = dir.join("fake-cargo.sh");
        std::fs::write(
            &script,
            format!(
                "printf '%s ' \"$@\" > '{}'\n{write}cat '{}'\nexit {exit}\n",
                args.display(),
                messages.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut launcher = Command::new("/bin/sh");
        launcher.arg(&script);
        (launcher, args)
    }

    /// The pre-P74 resolver returned `<CARGO_TARGET_DIR>/debug/fuigo-pager` after building, so a
    /// build that wrote elsewhere (`CARGO_BUILD_TARGET`, `build.target-dir`) left a stale file there
    /// to be spawned.
    #[test]
    fn the_executable_cargo_reports_wins_over_a_stale_file_at_the_default_path() {
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join("debug/fuigo-pager");
        std::fs::create_dir_all(stale.parent().unwrap()).unwrap();
        std::fs::write(&stale, "stale").unwrap();
        let built_at = dir
            .path()
            .join("x86_64-unknown-linux-gnu/debug/fuigo-pager");
        let messages = format!(
            "{{\"reason\":\"build-script-executed\"}}\nnot json\n{}\n{{\"reason\":\"build-finished\",\"success\":true}}\n",
            artifact_line(&built_at)
        );
        let (launcher, args) = fake_cargo(dir.path(), Some(&built_at), &messages, 0);

        let built = build_local_pager_binary(launcher, dir.path()).expect("build succeeds");

        assert_eq!(built, built_at);
        assert_eq!(std::fs::read_to_string(&built).unwrap(), "fresh");
        assert_eq!(std::fs::read_to_string(&stale).unwrap(), "stale");
        assert_eq!(
            std::fs::read_to_string(&args).unwrap(),
            "build --locked --message-format=json-render-diagnostics -p fuigo-pager-bin --bin fuigo-pager "
        );
    }

    #[test]
    fn a_failed_build_is_an_error_even_with_a_stale_binary_present() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("debug/fuigo-pager");
        std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
        std::fs::write(&binary, "stale").unwrap();
        let (launcher, _) = fake_cargo(dir.path(), None, &artifact_line(&binary), 3);

        let error = build_local_pager_binary(launcher, dir.path())
            .expect_err("a failed build must not fall back to the stale binary");
        assert!(format!("{error:#}").contains("exit Some(3)"), "{error:#}");
    }

    #[test]
    fn a_build_that_reports_no_executable_is_an_error_even_with_a_stale_binary_present() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("debug/fuigo-pager");
        std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
        std::fs::write(&binary, "stale").unwrap();
        let (launcher, _) = fake_cargo(dir.path(), None, "{\"reason\":\"build-finished\"}\n", 0);

        let error = build_local_pager_binary(launcher, dir.path()).unwrap_err();
        assert!(
            format!("{error:#}").contains("no `fuigo-pager` executable"),
            "{error:#}"
        );
    }

    #[test]
    fn several_reported_executables_are_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a/fuigo-pager");
        let b = dir.path().join("b/fuigo-pager");
        let messages = format!("{}\n{}\n", artifact_line(&a), artifact_line(&b));
        let (launcher, _) = fake_cargo(dir.path(), Some(&a), &messages, 0);

        let error = build_local_pager_binary(launcher, dir.path()).unwrap_err();
        assert!(
            format!("{error:#}").contains("refusing to guess"),
            "{error:#}"
        );
    }

    #[test]
    fn a_reported_executable_that_does_not_exist_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("debug/fuigo-pager");
        let (launcher, _) = fake_cargo(dir.path(), None, &artifact_line(&binary), 0);

        let error = build_local_pager_binary(launcher, dir.path()).unwrap_err();
        assert!(format!("{error:#}").contains("binary missing"), "{error:#}");
    }
}
