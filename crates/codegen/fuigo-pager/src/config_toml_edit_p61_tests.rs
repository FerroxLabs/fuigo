//! P61: the pager's `config.toml` writers -- `set_hint_at`, the dashboard
//! persist, `fuigo plugin marketplace add` -- run from separate processes at
//! once (this test binary re-executed as children), all on the shared
//! read-modify-write: none loses another's update, and no temp is left.

use std::path::Path;

const EACH: usize = 12;

fn spawn_role(home: &Path, role: &str) -> std::process::Child {
    #[allow(clippy::disallowed_methods)] // test fixture; waited for by the caller
    std::process::Command::new(std::env::current_exe().unwrap())
        .env("FUIGO_HOME", home)
        .env("FUIGO_P61_PAGER_ROLE", role)
        .args([
            "--ignored",
            "--exact",
            "--nocapture",
            "--test-threads",
            "1",
            "config_toml_edit::p61_tests::p61_pager_child_role",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap()
}

#[test]
fn three_pager_writers_in_three_processes_lose_nothing() {
    let home = tempfile::tempdir().unwrap();
    let sources = tempfile::tempdir().unwrap();
    let roles = [
        "hints".to_owned(),
        "dashboard".to_owned(),
        format!("market|{}", sources.path().display()),
    ];
    let children: Vec<_> = roles.iter().map(|r| (r, spawn_role(home.path(), r))).collect();
    for (role, child) in children {
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "role {role} failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let path = home.path().join(fuigo_config::USER_CONFIG_FILENAME);
    let v: toml::Value = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let sources_list = v["marketplace"]["sources"].as_array().unwrap();
    for i in 0..EACH {
        assert_eq!(v["hints"][format!("h{i}")].as_bool(), Some(true), "hint h{i}");
        let want = sources.path().join(format!("m{i}")).display().to_string();
        assert!(
            sources_list
                .iter()
                .any(|t| t.get("path").and_then(toml::Value::as_str) == Some(want.as_str())),
            "source {want}"
        );
    }
    assert_eq!(v["dashboard"]["enabled"].as_bool(), Some(true), "dashboard persist lost");
    let temps: Vec<String> = std::fs::read_dir(home.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp"))
        .collect();
    assert!(temps.is_empty(), "{temps:?}");
}

/// Run one write, retrying it while it is REFUSED because the lock wait gave
/// up (`TimedOut`): between processes the `flock` is not FIFO (R046 §0.2), and
/// a refusal is reported, never a lost update -- which is what is checked.
/// Nothing is printed (the crate denies `print_stdout`); exhausting the retries
/// fails the role with the last refusal, which the parent test shows.
fn retrying<T, E: std::fmt::Display>(mut write: impl FnMut() -> Result<T, E>) -> T {
    let mut last = String::new();
    for _ in 0..50 {
        match write() {
            Ok(v) => return v,
            Err(e) if e.to_string().contains("is locked by another Fuigo writer") => {
                last = e.to_string();
            }
            Err(e) => panic!("{e}"),
        }
    }
    panic!("still refused after 50 lock waits: {last}");
}

/// Child-process roles; does nothing unless `FUIGO_P61_PAGER_ROLE` is set.
#[test]
#[ignore = "child-process role for the P61 two-process tests"]
fn p61_pager_child_role() {
    let Ok(role) = std::env::var("FUIGO_P61_PAGER_ROLE") else {
        return;
    };
    let path = fuigo_config::fuigo_home().join(fuigo_config::USER_CONFIG_FILENAME);
    let parts: Vec<&str> = role.split('|').collect();
    match parts.as_slice() {
        ["hints"] => {
            for i in 0..EACH {
                retrying(|| super::set_hint_at(&path, &format!("h{i}"), true));
            }
        }
        ["dashboard"] => {
            for i in 0..EACH {
                let p = crate::views::dashboard::state::PersistedDashboard {
                    enabled: i + 1 == EACH || i % 2 == 0,
                    grouping: crate::views::dashboard::state::Grouping::State,
                    pinned: std::collections::BTreeSet::new(),
                    reorder: Vec::new(),
                };
                retrying(|| crate::views::dashboard::state::write_persisted_to_path(&path, &p));
            }
        }
        ["market", base] => {
            for i in 0..EACH {
                let dir = Path::new(base).join(format!("m{i}"));
                std::fs::create_dir_all(&dir).unwrap();
                retrying(|| crate::plugin_cmd::marketplace_add(&[], &dir.display().to_string(), false));
            }
        }
        ["fail-market", source] => {
            let err = crate::plugin_cmd::marketplace_add(&[], source, false).unwrap_err();
            assert!(err.to_string().contains("injected"), "{err}");
        }
        _ => panic!("unknown role {role}"),
    }
}

// ---- a write that fails mid-way leaves the original and no temp ----

const ORIGINAL: &str = "[ui]\ntheme = \"dark\"\n";

fn assert_untouched(dir: &Path, path: &Path) {
    assert_eq!(std::fs::read_to_string(path).unwrap(), ORIGINAL);
    let temps: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp"))
        .collect();
    assert!(temps.is_empty(), "{temps:?}");
}

#[test]
fn a_failed_hint_or_dashboard_write_leaves_the_config_and_no_temp() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, ORIGINAL).unwrap();
    let _fail = fuigo_config::fs_atomic::stage_fault::fail_writes_under(dir.path());
    super::set_hint_at(&path, "h", true).unwrap_err();
    assert_untouched(dir.path(), &path);
    crate::views::dashboard::state::write_persisted_to_path(
        &path,
        &crate::views::dashboard::state::PersistedDashboard {
            enabled: true,
            grouping: crate::views::dashboard::state::Grouping::State,
            pinned: std::collections::BTreeSet::new(),
            reorder: Vec::new(),
        },
    )
    .unwrap_err();
    assert_untouched(dir.path(), &path);
}

#[test]
fn a_failed_marketplace_add_leaves_the_config_and_no_temp() {
    let home = tempfile::tempdir().unwrap();
    let source = tempfile::tempdir().unwrap();
    let path = home.path().join(fuigo_config::USER_CONFIG_FILENAME);
    std::fs::write(&path, ORIGINAL).unwrap();
    #[allow(clippy::disallowed_methods)] // test fixture
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .env("FUIGO_HOME", home.path())
        .env("FUIGO_TEST_FAIL_STAGE_UNDER", home.path())
        .env(
            "FUIGO_P61_PAGER_ROLE",
            format!("fail-market|{}", source.path().display()),
        )
        .args([
            "--ignored",
            "--exact",
            "--nocapture",
            "config_toml_edit::p61_tests::p61_pager_child_role",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    assert_untouched(home.path(), &path);
}
