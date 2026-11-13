//! Compatibility snapshot captured from the pre-minimal implementation.
#![cfg(target_os = "linux")]
use fuigo_sandbox::{ProfileName, SandboxConfig};
use std::{
    path::{Path, PathBuf},
    process::Command,
};

#[test]
fn builtin_grants_match_baseline() {
    if std::env::var_os("FUIGO_GRANTS_CHILD").is_none() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("workspace")).unwrap();
        let out = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "builtin_grants_match_baseline", "--nocapture"])
            .env("FUIGO_GRANTS_CHILD", "1")
            .env("FUIGO_HOME", root.path().join("state"))
            .env("HOME", root.path().join("home"))
            .env_remove("TMPDIR")
            .current_dir(root.path().join("workspace"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .any(|line| line == "BUILTIN_GRANTS_CHECKED"),
            "{out:?}"
        );
        return;
    }
    let workspace = std::env::current_dir().unwrap();
    let state = PathBuf::from(std::env::var_os("FUIGO_HOME").unwrap());
    let normalize = |paths: Vec<PathBuf>| {
        let mut paths: Vec<_> = paths
            .iter()
            .map(|p| {
                if p.starts_with(&state) {
                    format!("<state>/{}", p.strip_prefix(&state).unwrap().display())
                        .trim_end_matches('/')
                        .to_owned()
                } else if p == &workspace {
                    "<workspace>".to_string()
                } else {
                    p.display().to_string()
                }
            })
            .collect();
        paths.sort();
        paths
    };
    let mut snapshot = String::new();
    for base in ["workspace", "devbox", "read-only", "strict"] {
        let profile = base
            .parse::<ProfileName>()
            .unwrap()
            .resolve_profile(&workspace, &SandboxConfig::default())
            .unwrap();
        let writes = if base == "devbox" {
            let mut expected = vec![workspace.clone()];
            expected.extend(
                std::fs::read_dir("/")
                    .unwrap()
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| {
                        p.is_dir()
                            && ![
                                Path::new("/data"),
                                Path::new("/proc"),
                                Path::new("/sys"),
                                Path::new("/dev"),
                            ]
                            .contains(&p.as_path())
                    }),
            );
            let mut actual = profile.read_write;
            actual.sort();
            expected.sort();
            assert_eq!(actual, expected);
            vec![
                "<workspace>".to_string(),
                "<existing top-level directories except data, proc, sys, dev>".to_string(),
            ]
        } else {
            normalize(profile.read_write)
        };
        let reads = if base == "strict" {
            let mut expected: Vec<_> = [
                "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/dev", "/proc", "/sys", "/tmp",
                "/run", "/var", "/System", "/Library", "/private",
            ]
            .into_iter()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .collect();
            expected.extend([workspace.clone(), state.clone()]);
            assert_eq!(profile.read_only, expected);
            vec![
                "<existing strict system paths>".to_string(),
                "<workspace>".to_string(),
                "<state>".to_string(),
            ]
        } else {
            normalize(profile.read_only)
        };
        snapshot.push_str(&format!(
            "{base}: read={reads:?} write={writes:?} default_read={} restrict_network={}\n",
            profile.default_read, profile.restrict_network
        ));
    }
    assert!(
        ProfileName::Off
            .resolve_profile(&workspace, &SandboxConfig::default())
            .is_err()
    );
    if let Some(path) = std::env::var_os("FUIGO_CAPTURE_BASELINE") {
        std::fs::write(path, &snapshot).unwrap();
    } else {
        assert_eq!(snapshot, include_str!("fixtures/builtin-grants-linux.txt"));
    }
    println!("BUILTIN_GRANTS_CHECKED");
}
