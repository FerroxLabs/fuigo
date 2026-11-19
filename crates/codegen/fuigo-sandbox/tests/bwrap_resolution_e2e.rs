//! Which `bwrap` launches the sandbox: a replaceable candidate is skipped with a warning, and a `PATH` hit warns.
#![cfg(all(target_os = "linux", feature = "enforce"))]
#![allow(clippy::print_stdout, clippy::print_stderr)]
use std::{os::unix::fs::PermissionsExt, path::Path, process::Command};

const CHILD: &str = "FUIGO_BWRAP_RESOLUTION_CHILD";
const SYSTEM_BWRAP: &str = "/usr/bin/bwrap";

/// Runs inside a fresh process so the per-process warning dedupe starts clean.
#[test]
fn resolution_child() {
    if std::env::var_os(CHILD).is_none() {
        return;
    }
    let cmd = fuigo_sandbox::bwrap_reexec_command(&["/tmp"], &[]).expect("bwrap command");
    println!("PROGRAM={}", Path::new(cmd.get_program()).display());
}

fn run_child(test_dirs: &str, path: &str) -> (String, String) {
    let home = tempfile::tempdir().unwrap();
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "resolution_child", "--nocapture"])
        .env_clear()
        .env(CHILD, "1")
        .env("HOME", home.path())
        .env("FUIGO_HOME", home.path())
        .env(fuigo_sandbox::TEST_BWRAP_DIRS_ENV, test_dirs)
        .env("PATH", path)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn fake_bwrap_in_world_writable_dir(root: &Path) -> std::path::PathBuf {
    let dir = root.join("writable");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("bwrap");
    std::fs::write(&file, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    dir
}

#[test]
fn a_bwrap_in_a_writable_directory_is_skipped_with_a_warning() {
    if !Path::new(SYSTEM_BWRAP).is_file() {
        eprintln!("skipped: bwrap not found at {SYSTEM_BWRAP}");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let bad = fake_bwrap_in_world_writable_dir(root.path());
    let dirs = format!("{}:/usr/bin", bad.display());
    let (stdout, stderr) = run_child(&dirs, "/nonexistent");
    assert!(
        stdout.contains(&format!("PROGRAM={SYSTEM_BWRAP}")),
        "{stdout}\n{stderr}"
    );
    assert!(
        stderr.contains("ignoring bubblewrap")
            && stderr.contains(bad.join("bwrap").to_str().unwrap()),
        "{stderr}"
    );
}

#[test]
fn a_bwrap_found_only_on_path_is_used_with_a_warning() {
    if !Path::new(SYSTEM_BWRAP).is_file() {
        eprintln!("skipped: bwrap not found at {SYSTEM_BWRAP}");
        return;
    }
    let empty = tempfile::tempdir().unwrap();
    let (stdout, stderr) = run_child(empty.path().to_str().unwrap(), "/usr/bin");
    assert!(
        stdout.contains(&format!("PROGRAM={SYSTEM_BWRAP}")),
        "{stdout}\n{stderr}"
    );
    assert!(stderr.contains("from PATH"), "{stderr}");
}

#[test]
fn a_bwrap_in_a_system_directory_prints_no_warning() {
    if !Path::new(SYSTEM_BWRAP).is_file() {
        eprintln!("skipped: bwrap not found at {SYSTEM_BWRAP}");
        return;
    }
    let (stdout, stderr) = run_child("/usr/bin", "/usr/bin");
    assert!(
        stdout.contains(&format!("PROGRAM={SYSTEM_BWRAP}")),
        "{stdout}\n{stderr}"
    );
    assert!(!stderr.contains("WARNING"), "{stderr}");
}
