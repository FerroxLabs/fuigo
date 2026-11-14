//! New aliases must be denied even when source and destination share a filesystem.
#![cfg(all(target_os = "linux", feature = "enforce"))]

use std::{fs, os::unix::fs::MetadataExt, path::Path, process::Command};

const CHILD: &str = "FUIGO_TEST_WORKSPACE_ALIAS_PROFILE";

#[test]
fn workspace_alias_child() {
    let Ok(profile) = std::env::var(CHILD) else {
        return;
    };
    let workspace = std::env::current_dir().unwrap();
    let source = workspace.join("original");
    let profile: fuigo_sandbox::ProfileName = profile.parse().unwrap();
    let config = fuigo_sandbox::load_sandbox_config(&workspace);
    let resolved = profile.resolve_profile(&workspace, &config).unwrap();
    let inside = fuigo_sandbox::is_inside_bwrap();
    let source_device = fs::metadata(&source).unwrap().dev();
    let mut destinations = Vec::new();
    for root in &resolved.read_write {
        if root.starts_with(&workspace) {
            continue;
        }
        if !inside {
            // sessions/ itself is a grant root; no individual session folder is used.
            fs::create_dir_all(root).unwrap();
        }
        let device = fs::metadata(root).unwrap().dev();
        println!(
            "{profile}: inside={inside} source_dev={source_device} destination_dev={device} root={}",
            root.display()
        );
        if device != source_device {
            println!("Different filesystem: {}", root.display());
            continue;
        }
        let destination = root.join(".fuigo-workspace-alias-proof");
        if !inside {
            // Positive control: same st_dev alone does not rule out existing bind
            // boundaries. Prove link + write actually work before confinement.
            fs::hard_link(&source, &destination).expect("unconfined same-filesystem link");
            fs::write(&destination, "control").unwrap();
            assert_eq!(fs::read_to_string(&source).unwrap(), "control");
            fs::remove_file(&destination).unwrap();
            fs::write(&source, "original").unwrap();
            println!("CONTROL link and alias write succeeded: {}", root.display());
        }
        destinations.push(destination);
    }
    assert!(
        !destinations.is_empty(),
        "fixture requires a same-filesystem write grant"
    );
    assert!(destinations.iter().any(|p| p.starts_with("/var/tmp")));
    if !inside {
        use std::os::unix::process::CommandExt;
        let mut command = fuigo_sandbox::bwrap_reexec_for_profile(&profile, &workspace)
            .expect("workspace boundary plan");
        panic!("bwrap exec failed: {}", command.exec());
    }
    let mut sandbox = fuigo_sandbox::SandboxManager::new(profile, &workspace);
    sandbox.apply(&workspace).unwrap();
    assert!(sandbox.is_applied(), "kernel enforcement must be active");
    let under_write_grant = workspace.starts_with("/var/tmp");
    if under_write_grant {
        assert!(
            resolved
                .read_write
                .iter()
                .any(|root| workspace.starts_with(root))
        );
    }
    for destination in destinations {
        let proof = destination.with_extension("writable");
        fs::write(&proof, "destination is writable").unwrap();
        fs::remove_file(proof).unwrap();
        let link = fs::hard_link(&source, &destination);
        // Even if link creation regresses, attempt the attack before checking it.
        if destination.exists() {
            let _ = fs::write(&destination, "changed through new alias");
        }
        let errno = link.as_ref().err().and_then(|error| error.raw_os_error());
        println!(
            "DENIED new alias {}: errno={errno:?}",
            destination.display()
        );
        assert_eq!(fs::read_to_string(&source).unwrap(), "original");
        if under_write_grant {
            // Landlock grants the parent, so EACCES cannot prove this mount boundary.
            assert_eq!(errno, Some(libc::EXDEV), "{link:?}");
        } else {
            assert!(
                matches!(errno, Some(libc::EXDEV | libc::EACCES)),
                "{link:?}"
            );
        }
        assert!(!destination.exists(), "hard link created a new alias");
    }
    println!("WORKSPACE_ALIAS_CHECKED");
}

fn same_filesystem_alias_denied(profile: &str, under_write_grant: bool) {
    if !fuigo_sandbox::SandboxManager::support_info().is_supported
        || !Command::new("bwrap")
            .args(["--bind", "/", "/", "--", "true"])
            .status()
            .is_ok_and(|status| status.success())
    {
        assert!(std::env::var_os("SANDBOX_E2E_REQUIRE_ENFORCEMENT").is_none());
        eprintln!("SKIP: kernel sandbox or bubblewrap unavailable");
        return;
    }
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(base).unwrap();
    let root = tempfile::tempdir_in(base).unwrap();
    let launch_folder = if under_write_grant {
        "/var/tmp/workspace"
    } else {
        "/workspace"
    };
    let workspace = root.path().join(launch_folder.trim_start_matches('/'));
    let state = root.path().join("fuigo");
    let var_tmp = root.path().join("var/tmp");
    let extra = root.path().join("extra-grant");
    fs::create_dir(root.path().join("home")).unwrap();
    for dir in [&workspace, &state, &var_tmp, &extra] {
        fs::create_dir_all(dir).unwrap();
        assert_eq!(
            fs::metadata(dir).unwrap().dev(),
            fs::metadata(root.path()).unwrap().dev()
        );
    }
    fs::write(workspace.join("original"), "original").unwrap();
    fs::write(
        state.join("sandbox.toml"),
        "[profiles.review]\nworkspace_write = false\nread_write = [\"/extra-grant\"]\n",
    )
    .unwrap();
    // A single fixture-root bind keeps workspace, /var/tmp, state and the custom
    // grant on the SAME mount before confinement. Separately binding /var/tmp
    // would itself cause EXDEV and invalidate the positive control.
    let executable = std::env::current_exe().unwrap();
    let mut command = Command::new("bwrap");
    command
        .args(["--die-with-parent", "--bind"])
        .arg(root.path())
        .arg("/");
    for path in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"] {
        if Path::new(path).exists() {
            command.args(["--ro-bind", path, path]);
        }
    }
    let output = command
        .args([
            "--dev-bind",
            "/dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            "--ro-bind",
        ])
        .arg(executable.parent().unwrap())
        .arg("/testbin")
        .args(["--chdir", launch_folder, "--"])
        .arg(Path::new("/testbin").join(executable.file_name().unwrap()))
        .args(["--exact", "workspace_alias_child", "--nocapture"])
        .env("HOME", "/home")
        .env("FUIGO_HOME", "/fuigo")
        .env(CHILD, profile)
        .env_remove("__FUIGO_INSIDE_BWRAP")
        .output()
        .unwrap();
    println!("{}", String::from_utf8_lossy(&output.stdout));
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line == "WORKSPACE_ALIAS_CHECKED"),
        "{output:?}"
    );
    assert_eq!(
        fs::read_to_string(workspace.join("original")).unwrap(),
        "original"
    );
}

#[test]
fn minimal_new_same_filesystem_alias_denied() {
    same_filesystem_alias_denied("minimal", false);
}

#[test]
fn custom_new_same_filesystem_alias_denied() {
    same_filesystem_alias_denied("review", false);
}

#[test]
fn minimal_new_alias_under_writable_parent_denied_by_mount() {
    same_filesystem_alias_denied("minimal", true);
}

#[test]
fn custom_new_alias_under_writable_parent_denied_by_mount() {
    same_filesystem_alias_denied("review", true);
}
