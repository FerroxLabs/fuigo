//! A launch-folder write boundary must never take the optional bwrap fallback.
#![cfg(target_os = "linux")]

use std::{fs, path::Path, process::Command};

const CHILD: &str = "FUIGO_TEST_BOUNDARY_STARTUP";

#[test]
fn sandbox_workspace_startup_child() {
    let Ok(profile) = std::env::var(CHILD) else {
        return;
    };
    let workspace = std::env::current_dir().unwrap();
    assert!(!Path::new("/data").exists(), "fixture must exclude /data");
    let name = profile.parse().unwrap();
    if profile == "devreview" {
        assert!(!fuigo_sandbox::requires_read_deny(&name, &workspace));
        assert!(!fuigo_sandbox::requires_hook_write_deny(&name, &workspace));
        assert!(!fuigo_sandbox::requires_data_write_deny(&name, &workspace));
    }
    fuigo_shell::config::apply_sandbox(Some(&Default::default()), Some(&profile), Some(&workspace));
    panic!("startup continued without the required bubblewrap boundary");
}

fn unavailable_bwrap_refuses(profile: &str) {
    if !Command::new("bwrap")
        .args(["--bind", "/", "/", "--", "true"])
        .status()
        .is_ok_and(|status| status.success())
    {
        assert!(
            std::env::var_os("SANDBOX_E2E_REQUIRE_ENFORCEMENT").is_none(),
            "bubblewrap required to construct the no-/data test namespace"
        );
        eprintln!("SKIP: bubblewrap unavailable for startup fixture");
        return;
    }
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(base).unwrap();
    let root = tempfile::tempdir_in(base).unwrap();
    let workspace = root.path().join("workspace");
    let state = root.path().join("fuigo");
    let empty_bin = root.path().join("empty-bin");
    for dir in [&workspace, &state, &empty_bin] {
        fs::create_dir(dir).unwrap();
    }
    fs::write(
        state.join("sandbox.toml"),
        "[profiles.devreview]\nextends = \"devbox\"\nworkspace_write = false\n",
    )
    .unwrap();
    // Reproduce hosts without /data even when the test host has that directory.
    // The outer namespace is only a fixture; PATH prevents production re-exec.
    let mut command = Command::new("bwrap");
    command.args(["--die-with-parent", "--tmpfs", "/"]);
    for entry in fs::read_dir("/").unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path == Path::new("/data") {
            continue;
        }
        if entry.file_type().unwrap().is_symlink() {
            command
                .arg("--symlink")
                .arg(fs::read_link(&path).unwrap())
                .arg(&path);
        } else {
            command.arg("--dev-bind").arg(&path).arg(&path);
        }
    }
    let output = command
        .arg("--setenv")
        .arg("PATH")
        .arg(&empty_bin)
        .arg("--chdir")
        .arg(&workspace)
        .arg("--")
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "sandbox_workspace_startup_child", "--nocapture"])
        .env_clear()
        .env("HOME", root.path())
        .env("FUIGO_HOME", &state)
        .env(CHILD, profile)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("{profile}: {stderr}");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(stderr.contains("bwrap exec failed"), "{output:?}");
    assert!(stderr.contains("Refusing to start"), "{output:?}");
    assert!(!stderr.contains("Falling back to Landlock"), "{output:?}");
}

#[test]
fn minimal_requires_bwrap_when_unavailable() {
    unavailable_bwrap_refuses("minimal");
}

#[test]
fn devbox_workspace_readonly_requires_bwrap_when_unavailable() {
    unavailable_bwrap_refuses("devreview");
}
