use fuigo_sandbox::{ProfileName, ProfileSource, SandboxConfig};

#[test]
fn project_profile_source_child() {
    let Ok(kind) = std::env::var("FUIGO_PROFILE_SOURCE_TEST") else {
        return;
    };
    let workspace = std::env::current_dir().unwrap();
    for _ in 0..3 {
        let config = fuigo_sandbox::load_sandbox_config(&workspace);
        if kind == "global" {
            assert!(matches!(
                config.sources.get("minimal"),
                Some(ProfileSource::UserGlobal(_))
            ));
            assert!(matches!(
                ProfileName::Minimal.selected(&config).as_ref(),
                ProfileName::Custom(_)
            ));
            assert!(!ProfileName::Minimal.denies_workspace_write(&config));
        } else {
            assert!(
                ProfileName::Minimal.denies_workspace_write(&config),
                "project minimal must not replace the built-in"
            );
            for name in [
                "minimal",
                "workspace",
                "devbox",
                "read-only",
                "readonly",
                "strict",
                "off",
                "none",
            ] {
                assert!(
                    !config.profiles.contains_key(name),
                    "project built-in {name} must be ignored"
                );
            }
        }
        assert!(matches!(
            config.sources.get("mine"),
            Some(ProfileSource::Project(_))
        ));
        let mine = ProfileName::Custom("mine".into())
            .resolve_profile(&workspace, &config)
            .unwrap();
        assert!(mine.default_read);
        assert!(mine.read_write.contains(&workspace));
        assert_eq!(config.profiles["mine"].deny, ["./secret"]);
        assert!(mine.deny.contains(&std::path::PathBuf::from("./secret")));
    }
}

#[test]
fn project_builtin_names_cannot_shadow_and_global_minimal_still_wins() {
    for kind in ["project", "global"] {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        let home = root.path().join("state");
        std::fs::create_dir_all(workspace.join(".fuigo")).unwrap();
        std::fs::create_dir(&home).unwrap();
        let project = workspace.join(".fuigo/sandbox.toml");
        let mut content =
            String::from("[profiles.mine]\nextends = \"workspace\"\ndeny = [\"./secret\"]\n");
        for name in [
            "minimal",
            "workspace",
            "devbox",
            "read-only",
            "readonly",
            "strict",
            "off",
            "none",
        ] {
            content.push_str(&format!("[profiles.{name}]\nextends = \"devbox\"\n"));
        }
        std::fs::write(&project, content).unwrap();
        if kind == "global" {
            std::fs::write(
                home.join("sandbox.toml"),
                "[profiles.minimal]\nextends = \"devbox\"\n",
            )
            .unwrap();
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "project_profile_source_child", "--nocapture"])
            .current_dir(&workspace)
            .env("FUIGO_HOME", &home)
            .env("FUIGO_PROFILE_SOURCE_TEST", kind)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let stderr = String::from_utf8(out.stderr).unwrap();
        for name in [
            "minimal",
            "workspace",
            "devbox",
            "read-only",
            "readonly",
            "strict",
            "off",
            "none",
        ] {
            assert_eq!(
                stderr
                    .lines()
                    .filter(|line| line.contains("WARNING")
                        && line.contains(&format!("'{name}'"))
                        && line.contains(&project.display().to_string())
                        && line.contains("rename"))
                    .count(),
                1,
                "{stderr}"
            );
        }
        assert_eq!(
            stderr
                .lines()
                .filter(|line| line.contains("shadows the built-in"))
                .count(),
            usize::from(kind == "global"),
            "{stderr}"
        );
    }
}

#[test]
fn warning_handoff_is_consumed() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("sandbox.toml"), "[profiles.minimal]\n").unwrap();
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "warning_handoff_child", "--nocapture"])
        .env("FUIGO_HOME", root.path())
        .env("__FUIGO_SANDBOX_STARTUP_WARNINGS", "[\"shadowed-minimal\"]")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(!String::from_utf8_lossy(&out.stderr).contains("shadows the built-in"));
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .any(|line| line == "WARNING_HANDOFF_CONSUMED")
    );
}

#[test]
fn warning_handoff_child() {
    if std::env::var_os("__FUIGO_SANDBOX_STARTUP_WARNINGS").is_none() {
        return;
    }
    // This isolated child runs only this test; no concurrent environment access.
    unsafe { fuigo_sandbox::consume_startup_warnings() };
    assert!(std::env::var_os("__FUIGO_SANDBOX_STARTUP_WARNINGS").is_none());
    // Repeated startup consumption is harmless, even after warning state is initialized.
    unsafe { fuigo_sandbox::consume_startup_warnings() };
    let config = fuigo_sandbox::load_sandbox_config(&std::env::current_dir().unwrap());
    let _ = ProfileName::Minimal.selected(&config);
    assert!(
        std::env::var_os("__FUIGO_SANDBOX_STARTUP_WARNINGS").is_none(),
        "diagnostic handoff must not reach descendants"
    );
    println!("WARNING_HANDOFF_CONSUMED");
}

#[test]
fn minimal_is_a_builtin_profile() {
    let profile: ProfileName = "minimal".parse().unwrap();
    assert!(!matches!(profile, ProfileName::Custom(_)));
    let workspace = std::env::current_dir().unwrap();
    let resolved = profile
        .resolve_profile(&workspace, &SandboxConfig::default())
        .unwrap();
    assert!(!resolved.default_read);
    assert!(resolved.restrict_network);
    assert!(!resolved.read_write.contains(&workspace));
}

#[test]
fn workspace_write_false_removes_launch_grant() {
    let config: SandboxConfig =
        toml::from_str("[profiles.review]\nworkspace_write = false\n").unwrap();
    let workspace = std::env::current_dir().unwrap();
    let resolved = ProfileName::Custom("review".into())
        .resolve_profile(&workspace, &config)
        .unwrap();
    assert!(!resolved.read_write.contains(&workspace));
}

#[test]
fn workspace_write_rejects_non_boolean() {
    for value in ["\"false\"", "0", "[]"] {
        let result = toml::from_str::<SandboxConfig>(&format!(
            "[profiles.review]\nworkspace_write = {value}\n"
        ));
        assert!(result.is_err(), "accepted workspace_write = {value}");
    }
}

#[test]
fn legacy_minimal_definition_keeps_grants_and_deny() {
    let workspace = std::env::current_dir().unwrap();
    let config: SandboxConfig =
        toml::from_str("[profiles.minimal]\nread_write = [\"/var/tmp\"]\ndeny = [\"./secret\"]\n")
            .unwrap();
    let selected: ProfileName = "minimal".parse().unwrap();
    let resolved = selected.resolve_profile(&workspace, &config).unwrap();
    assert!(
        resolved.deny.contains(&"./secret".into()),
        "legacy deny must survive selection"
    );
    assert!(resolved.read_write.contains(&workspace));
    assert!(resolved.read_write.contains(&"/var/tmp".into()));
    assert!(resolved.default_read);
    assert!(!resolved.restrict_network);
}

#[test]
fn shadowed_minimal_cannot_be_used_as_a_builtin_base() {
    let config: SandboxConfig = toml::from_str(
        "[profiles.minimal]\ndeny = [\"./secret\"]\n[profiles.review]\nextends = \"minimal\"\n",
    )
    .unwrap();
    let result = ProfileName::Custom("review".into())
        .resolve_profile(&std::env::current_dir().unwrap(), &config);
    let error = result.expect_err("a shadowed custom name is not a built-in base");
    assert!(
        error
            .to_string()
            .contains("custom profiles cannot extend other custom profiles")
    );
}

#[test]
fn startup_warning_child() {
    let Ok(kind) = std::env::var("FUIGO_WARNING_TEST") else {
        return;
    };
    let workspace = std::env::current_dir().unwrap();
    for _ in 0..3 {
        let config = fuigo_sandbox::load_sandbox_config(&workspace);
        let name: ProfileName = if kind == "unknown" {
            "review"
        } else {
            "minimal"
        }
        .parse()
        .unwrap();
        name.resolve_profile(&workspace, &config).unwrap();
    }
}

fn warning_output(kind: &str) -> String {
    let root = tempfile::tempdir().unwrap();
    let workspace = root.path().join("workspace");
    let home = if kind == "nested" || (kind == "nested-alias" && !cfg!(unix)) {
        workspace.join("state")
    } else {
        root.path().join("state")
    };
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    #[cfg(unix)]
    if kind == "nested-alias" {
        std::os::unix::fs::symlink(&workspace, home.join("sessions")).unwrap();
    }
    let content = match kind {
        "shadow" => "[profiles.minimal]\nextends = \"workspace\"\n",
        "unknown" => "[profiles.review]\nworkspace-write = false\nworkspace_writes = false\n",
        _ => "",
    };
    std::fs::write(home.join("sandbox.toml"), content).unwrap();
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "startup_warning_child", "--nocapture"])
        .current_dir(&workspace)
        .env("FUIGO_HOME", home)
        .env("FUIGO_WARNING_TEST", kind)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    String::from_utf8(out.stderr).unwrap()
}

#[test]
fn shadowed_minimal_warns_once_on_stderr() {
    let stderr = warning_output("shadow");
    let warnings: Vec<_> = stderr
        .lines()
        .filter(|line| {
            line.contains("WARNING") && line.contains("minimal") && line.contains("built-in")
        })
        .collect();
    assert_eq!(warnings.len(), 1, "{stderr}");
}

#[test]
fn unknown_profile_keys_warn_once_and_keep_starting() {
    let stderr = warning_output("unknown");
    for key in ["workspace-write", "workspace_writes"] {
        assert_eq!(
            stderr
                .lines()
                .filter(|line| line.contains("WARNING") && line.contains(key))
                .count(),
            1,
            "{stderr}"
        );
    }
}

#[test]
fn nested_sessions_warn_once_and_keep_starting() {
    for kind in ["nested", "nested-alias"] {
        let stderr = warning_output(kind);
        assert_eq!(
            stderr
                .lines()
                .filter(|line| line.contains("WARNING")
                    && line.contains("sessions")
                    && line.contains("read-only"))
                .count(),
            1,
            "{stderr}"
        );
    }
}
