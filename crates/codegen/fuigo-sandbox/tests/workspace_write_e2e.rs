//! Whole-process enforcement, including a workspace beneath the writable temp grant.
#![cfg(all(unix, feature = "enforce"))]
use std::{fs, path::PathBuf, process::Command};

const CHILD: &str = "FUIGO_WORKSPACE_WRITE_E2E";

#[test]
fn workspace_write_subprocess() {
    let Ok(profile_name) = std::env::var(CHILD) else {
        return;
    };
    let ws = std::env::current_dir().unwrap();
    let alias = PathBuf::from(std::env::var_os("FUIGO_TEST_WORKSPACE").unwrap());
    let legacy_minimal = profile_name == "legacy-minimal";
    let profile = if legacy_minimal {
        "minimal"
    } else {
        &profile_name
    }
    .parse()
    .unwrap();
    if legacy_minimal {
        assert!(fuigo_sandbox::requires_read_deny(&profile, &ws));
    }
    #[cfg(target_os = "linux")]
    if !fuigo_sandbox::is_inside_bwrap() {
        use std::os::unix::process::CommandExt;
        let mut command =
            fuigo_sandbox::bwrap_reexec_for_profile(&profile, &ws).expect("bwrap plan");
        panic!("bwrap exec failed: {}", command.exec());
    }
    let mut sandbox = fuigo_sandbox::SandboxManager::new(profile, &ws);
    sandbox.apply(&ws).expect("apply sandbox");
    assert!(sandbox.is_applied(), "kernel enforcement must be active");
    if profile_name == "review" || legacy_minimal {
        assert!(
            fs::read(ws.join("secret")).is_err(),
            "workspace mount must preserve nested read-deny masks"
        );
    }
    let result = fs::write(ws.join("created"), "new");
    if profile_name == "writable" || legacy_minimal {
        result.expect("workspace_write=true allows launch writes");
    } else {
        let error = result.expect_err("launch write must fail");
        assert!(
            matches!(
                error.raw_os_error(),
                Some(libc::EACCES | libc::EPERM | libc::EROFS)
            ),
            "{error}"
        );
        assert!(fs::write("relative-created", "changed").is_err());
        assert!(fs::write(alias.join("alias-created"), "changed").is_err());
        assert!(!ws.join("build/out").exists());
        assert!(fs::create_dir_all(ws.join("build/out")).is_err());
        let parent = dunce::canonicalize(&ws)
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        assert!(
            fs::rename(&parent, parent.with_extension("renamed")).is_err(),
            "workspace parent rename must fail"
        );
        assert!(fs::write(ws.join("existing"), "changed").is_err());
        assert!(fs::rename(ws.join("existing"), ws.join("moved")).is_err());
        assert!(fs::remove_file(ws.join("existing")).is_err());
        assert_eq!(fs::read_to_string(ws.join("existing")).unwrap(), "original");
        #[cfg(target_os = "linux")]
        {
            // The destination is outside the read-only workspace but on the same
            // underlying filesystem. Check it is writable before testing escapes.
            let scratch = PathBuf::from(std::env::var_os("FUIGO_TEST_SCRATCH").unwrap());
            fs::write(scratch.join("writable-proof"), "writable").unwrap();
            let source = ws.join("existing");
            for (operation, destination, result) in [
                (
                    "hard_link",
                    scratch.join("linked"),
                    fs::hard_link(&source, scratch.join("linked")),
                ),
                (
                    "rename_out",
                    scratch.join("moved"),
                    fs::rename(&source, scratch.join("moved")),
                ),
            ] {
                // Attempt writes even if a regression unexpectedly created an alias.
                if destination.exists() {
                    let _ = fs::write(&destination, "changed through alias");
                }
                let errno = result.as_ref().err().and_then(|error| error.raw_os_error());
                println!("{profile_name} {operation}: errno={errno:?}");
                assert_eq!(fs::read_to_string(&source).unwrap(), "original");
                assert!(
                    matches!(
                        errno,
                        Some(libc::EACCES | libc::EPERM | libc::EROFS | libc::EXDEV)
                    ),
                    "{operation} must fail: {result:?}"
                );
                assert!(
                    !destination.exists(),
                    "{operation} created a writable alias"
                );
            }
        }
    }
    let state = PathBuf::from(std::env::var_os("FUIGO_HOME").unwrap())
        .join("sessions")
        .join("workspace-write-test");
    let writer =
        fuigo_session_writer::SessionWriter::try_claim("workspace-write-test", &state).unwrap();
    writer
        .create_new_sync("proof", b"state remains writable")
        .expect("state write");
    assert_eq!(
        fs::read(state.join("proof")).unwrap(),
        b"state remains writable"
    );
    writer.delete_tree_sync().unwrap();
}

fn run(profile: &str) {
    let supported = fuigo_sandbox::SandboxManager::support_info().is_supported;
    #[cfg(target_os = "linux")]
    let supported = supported
        && Command::new("bwrap")
            .args(["--bind", "/", "/", "--", "true"])
            .status()
            .is_ok_and(|s| s.success());
    if !supported {
        assert!(
            std::env::var_os("SANDBOX_E2E_REQUIRE_ENFORCEMENT").is_none(),
            "kernel enforcement required"
        );
        return;
    }
    run_layout(profile, false, false);
    run_layout(profile, true, false);
}

fn run_layout(profile: &str, outside_temp: bool, symlink: bool) {
    let root = if outside_temp {
        let base = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(base).unwrap();
        let base = dunce::canonicalize(base).unwrap();
        for temp in [
            Some(PathBuf::from("/tmp")),
            Some(PathBuf::from("/var/tmp")),
            std::env::var_os("TMPDIR").map(PathBuf::from),
        ]
        .into_iter()
        .flatten()
        {
            assert!(
                !base.starts_with(dunce::canonicalize(temp).unwrap()),
                "layout must be outside every temp grant"
            );
        }
        tempfile::tempdir_in(base).unwrap()
    } else {
        tempfile::tempdir().unwrap()
    };
    let scratch = tempfile::tempdir().unwrap();
    let ws = root.path().join("workspace");
    let state = root.path().join("fuigo");
    fs::create_dir(&ws).unwrap();
    fs::create_dir(&state).unwrap();

    fs::write(ws.join("existing"), "original").unwrap();
    fs::write(ws.join("secret"), "private fixture").unwrap();
    fs::write(state.join("sandbox.toml"), "[profiles.review]\nworkspace-writes = false\nworkspace_write = false\nread_write = [\"build/out\"]\ndeny = [\"./secret\", \"./missing-secret\"]\n[profiles.writable]\nextends = \"minimal\"\nworkspace_write = true\n[profiles.devreview]\nextends = \"devbox\"\nworkspace_write = false\n").unwrap();
    if profile == "legacy-minimal" {
        use std::io::Write;
        fs::OpenOptions::new()
            .append(true)
            .open(state.join("sandbox.toml"))
            .unwrap()
            .write_all(b"[profiles.minimal]\nread_write = [\"/var/tmp\"]\ndeny = [\"./secret\"]\n")
            .unwrap();
    }
    let ws = if symlink {
        let alias = scratch.path().join("workspace-alias");
        std::os::unix::fs::symlink(&ws, &alias).unwrap();
        alias
    } else {
        ws
    };
    println!("profile={profile} outside_temp={outside_temp} symlink={symlink}");
    let output = Command::new(std::env::current_exe().unwrap())
        .current_dir(&ws)
        .env(CHILD, profile)
        .env("FUIGO_TEST_WORKSPACE", &ws)
        .env("FUIGO_TEST_SCRATCH", scratch.path())
        .env("FUIGO_HOME", &state)
        .env_remove("__FUIGO_INSIDE_BWRAP")
        .args(["--exact", "workspace_write_subprocess", "--nocapture"])
        .output()
        .unwrap();
    print!("{}", String::from_utf8_lossy(&output.stdout));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.contains("WARNING") && line.contains("workspace-writes"))
            .count(),
        1,
        "{stderr}"
    );
    if profile == "legacy-minimal" {
        assert_eq!(
            stderr
                .lines()
                .filter(|line| line.contains("WARNING") && line.contains("built-in"))
                .count(),
            1,
            "{stderr}"
        );
    }
    assert!(
        output.status.success(),
        "{profile}: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn minimal_launch_denied_state_writable() {
    run("minimal");
}
#[test]
fn custom_launch_denied_state_writable() {
    run("review");
}
#[test]
fn custom_launch_writable_state_writable() {
    run("writable");
}
#[test]
fn devbox_custom_launch_denied_state_writable() {
    run("devreview");
}

#[test]
fn legacy_minimal_launch_writable_deny_enforced() {
    run("legacy-minimal");
}

#[cfg(target_os = "linux")]
#[test]
fn symlink_workspace_and_parent_rename_denied() {
    run_layout("minimal", true, true);
    run_layout("review", true, true);
}
