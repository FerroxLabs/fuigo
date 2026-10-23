//! `--help` and `--version` only print: they must not create the Fuigo home (or anything in it) as a side effect.
#![cfg(unix)]

use std::process::{Command, Stdio};

fn pager_binary() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("PAGER_BINARY") {
        return std::path::absolute(&p).unwrap_or_else(|e| panic!("failed to absolutize PAGER_BINARY {p}: {e}"));
    }
    option_env!("CARGO_BIN_EXE_fuigo-pager")
        .map(std::path::PathBuf::from)
        .expect("PAGER_BINARY is unset and this build is not `cargo test`")
}

fn run_and_list_home(args: &[&str]) -> (bool, Vec<String>) {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("fuigo-home");
    let mut command = Command::new(pager_binary());
    command
        .args(args)
        .current_dir(root.path())
        .env("HOME", root.path())
        .env("FUIGO_HOME", &home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("FUIGO_") && key != "FUIGO_HOME" {
            command.env_remove(key);
        }
    }
    let status = command.status().expect("run the fuigo binary");
    let created: Vec<String> = std::fs::read_dir(root.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    (status.success(), created)
}

#[test]
fn help_and_version_create_no_fuigo_home() {
    for args in [&["--help"][..], &["--version"], &["-V"], &["worktree", "--help"], &["mcp", "--help"]] {
        let (ok, created) = run_and_list_home(args);
        assert!(ok, "{args:?} should exit 0");
        assert!(created.is_empty(), "{args:?} left files behind: {created:?}");
    }
}
