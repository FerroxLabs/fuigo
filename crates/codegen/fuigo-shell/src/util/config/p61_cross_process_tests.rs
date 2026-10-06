//! P61: the config writers migrated onto `fuigo_config::fs_atomic`'s shared
//! read-modify-write, run from TWO PROCESSES at once (this test binary
//! re-executed as children). No writer may lose another's update, whichever
//! pair of writers shares the file, and nothing may leave a temp behind.

use std::path::{Path, PathBuf};

const EACH: usize = 12;

/// Re-run this test binary as a child in `role`, with `FUIGO_HOME` = `home`.
fn spawn_role(home: &Path, role: &str) -> std::process::Child {
    #[allow(clippy::disallowed_methods)] // test fixture; waited for by the caller
    std::process::Command::new(std::env::current_exe().unwrap())
        .env("FUIGO_HOME", home)
        .env("FUIGO_P61_SHELL_ROLE", role)
        .args([
            "--ignored",
            "--exact",
            "--nocapture",
            "--test-threads",
            "1",
            "util::config::persist::p61_cross_process_tests::p61_shell_child_role",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap()
}

/// Start every role at once, wait for all, and fail with their output if any failed.
fn run_together(home: &Path, roles: &[String]) {
    let children: Vec<_> = roles.iter().map(|r| (r, spawn_role(home, r))).collect();
    for (role, child) in children {
        let out = child.wait_with_output().unwrap();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Some(at) = line.find("P61_RETRIES") {
                println!("{}", &line[at..]);
            }
        }
        assert!(
            out.status.success(),
            "role {role} failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn toml_at(path: &Path) -> toml::Value {
    toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn no_temps(dir: &Path) {
    let temps: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp"))
        .collect();
    assert!(temps.is_empty(), "temps left in {}: {temps:?}", dir.display());
}

/// Five different writers of the user's `config.toml` -- MCP server save,
/// marketplace add, plugin-path add, Claude import, settings save -- each in
/// its own process, all at once: every one of their entries survives.
#[test]
fn five_writers_of_the_user_config_in_five_processes_lose_nothing() {
    let home = tempfile::tempdir().unwrap();
    let roles: Vec<String> = ["mcp", "market", "plugins", "import", "settings"]
        .iter()
        .map(|r| (*r).to_owned())
        .collect();
    run_together(home.path(), &roles);
    let v = toml_at(&home.path().join("config.toml"));
    let mut missing = Vec::new();
    for i in 0..EACH {
        if v["mcp_servers"].get(format!("srv{i}")).is_none() {
            missing.push(format!("mcp srv{i}"));
        }
        let want = format!("/m/{i}");
        if !v["marketplace"]["sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t.get("path").and_then(toml::Value::as_str) == Some(want.as_str()))
        {
            missing.push(format!("market {want}"));
        }
        let want = format!("/p/{i}");
        if !v["plugins"]["paths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p.as_str() == Some(want.as_str()))
        {
            missing.push(format!("plugin {want}"));
        }
        if v["env"].get(format!("P61_{i}")).is_none() {
            missing.push(format!("import P61_{i}"));
        }
    }
    assert!(missing.is_empty(), "lost updates: {missing:?}");
    assert_eq!(v["ui"]["compact_mode"].as_bool(), Some(true), "settings save lost");
    no_temps(home.path());
}

/// A project's `.fuigo/config.toml`, written by the MCP writer and the Claude
/// import from two processes: both take the same (out-of-tree) lock, so
/// neither loses the other's entries, and no lock file lands in the project.
#[test]
fn two_writers_of_a_project_config_in_two_processes_lose_nothing() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let path = project.path().join(".fuigo/config.toml");
    run_together(
        home.path(),
        &[
            format!("project-mcp|{}", path.display()),
            format!("project-import|{}", path.display()),
        ],
    );
    let v = toml_at(&path);
    for i in 0..EACH {
        assert!(v["mcp_servers"].get(format!("srv{i}")).is_some(), "srv{i}");
        assert!(v["env"].get(format!("P61_{i}")).is_some(), "P61_{i}");
    }
    let entries: Vec<String> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(entries, ["config.toml"], "nothing but the config in the repo");
}

/// `hooks-paths`: adds from one process and adds-then-removes from another;
/// every add of the first survives, and every line the second removed is gone.
#[test]
fn hooks_paths_edited_from_two_processes_lose_nothing() {
    let home = tempfile::tempdir().unwrap();
    let file = home.path().join("hooks-paths");
    run_together(
        home.path(),
        &[
            format!("hooks-add|{}", file.display()),
            format!("hooks-churn|{}", file.display()),
        ],
    );
    let content = std::fs::read_to_string(&file).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    for i in 0..EACH {
        assert!(lines.contains(&format!("/keep/{i}").as_str()), "/keep/{i}");
        assert!(!lines.contains(&format!("/gone/{i}").as_str()), "/gone/{i}");
    }
    no_temps(home.path());
}

/// `mcp_preferences.json` and `claude_import_state.json`: two processes saving
/// different entries keep each other's.
#[test]
fn json_state_files_edited_from_two_processes_lose_nothing() {
    let home = tempfile::tempdir().unwrap();
    let prefs = home.path().join("mcp_preferences.json");
    let state = home.path().join("claude_import_state.json");
    run_together(
        home.path(),
        &[
            format!("prefs|{}|a", prefs.display()),
            format!("prefs|{}|b", prefs.display()),
            format!("state|{}|a", state.display()),
            format!("state|{}|b", state.display()),
        ],
    );
    let p: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&prefs).unwrap()).unwrap();
    let s: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
    for who in ["a", "b"] {
        for i in 0..EACH {
            assert!(p["servers"].get(format!("{who}{i}")).is_some(), "prefs {who}{i}");
            assert!(s["projects"].get(format!("/{who}/{i}")).is_some(), "state /{who}/{i}");
        }
    }
    no_temps(home.path());
}

/// Lock-wait refusals a child role retried (see [`retrying`]).
static RETRIES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Run one write, retrying it while it is REFUSED because the lock wait gave
/// up (`TimedOut`). Between processes the `flock` is not FIFO (R046 §0.2), so
/// with five processes writing back to back on a loaded host one can be
/// refused; a refusal is reported, never a lost update, which is what these
/// tests check. Any other error fails the role.
fn retrying<T, E: std::fmt::Display>(mut write: impl FnMut() -> Result<T, E>) -> T {
    for _ in 0..50 {
        match write() {
            Ok(v) => return v,
            Err(e) if e.to_string().contains("is locked by another Fuigo writer") => {
                RETRIES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Err(e) => panic!("{e}"),
        }
    }
    panic!("still refused after 50 lock waits");
}

/// Child-process roles for the tests above; does nothing unless
/// `FUIGO_P61_SHELL_ROLE` is set.
#[test]
#[ignore = "child-process role for the P61 two-process tests"]
fn p61_shell_child_role() {
    let Ok(role) = std::env::var("FUIGO_P61_SHELL_ROLE") else {
        return;
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let home = crate::util::fuigo_home::fuigo_home();
    let user_config = home.join("config.toml");
    let server: fuigo_config_types::McpServerConfig = toml::from_str("command = \"echo\"\n").unwrap();
    let env_item = |i: usize| crate::claude_import::ImportableItem::EnvVar {
        key: format!("P61_{i}"),
        value: "v".to_owned(),
    };
    let parts: Vec<&str> = role.split('|').collect();
    match parts.as_slice() {
        ["mcp"] => {
            for i in 0..EACH {
                retrying(|| {
                    rt.block_on(super::super::mcp::save_mcp_server_config_at(
                        &user_config,
                        &format!("srv{i}"),
                        &server,
                    ))
                });
            }
        }
        ["market"] => {
            for i in 0..EACH {
                retrying(|| {
                    crate::extensions::marketplace::add_marketplace_source(
                        &user_config,
                        &format!("m{i}"),
                        &crate::plugin::MarketplaceAddInput::LocalPath(PathBuf::from(format!(
                            "/m/{i}"
                        ))),
                        false,
                    )
                });
            }
        }
        ["plugins"] => {
            for i in 0..EACH {
                retrying(|| crate::config::add_plugin_path_in(&format!("/p/{i}"), &user_config));
            }
        }
        ["import"] => {
            for i in 0..EACH {
                retrying(|| crate::claude_import::apply_items_to_config(&user_config, &[env_item(i)]));
            }
        }
        ["settings"] => {
            for i in 0..EACH {
                let on = i + 1 == EACH || i % 2 == 0;
                retrying(|| {
                    rt.block_on(crate::util::config::update_config(move |cfg| {
                        cfg.ui.compact_mode = on;
                    }))
                });
            }
        }
        ["project-mcp", path] => {
            for i in 0..EACH {
                retrying(|| {
                    rt.block_on(super::super::mcp::save_mcp_server_config_at(
                        Path::new(path),
                        &format!("srv{i}"),
                        &server,
                    ))
                });
            }
        }
        ["project-import", path] => {
            for i in 0..EACH {
                retrying(|| crate::claude_import::apply_items_to_config(Path::new(path), &[env_item(i)]));
            }
        }
        ["hooks-add", file] => {
            for i in 0..EACH {
                retrying(|| crate::config::add_hooks_path_to_file(&format!("/keep/{i}"), Path::new(file)));
            }
        }
        ["hooks-churn", file] => {
            for i in 0..EACH {
                let line = format!("/gone/{i}");
                retrying(|| crate::config::add_hooks_path_to_file(&line, Path::new(file)));
                assert!(retrying(|| crate::config::remove_hooks_path_from_file(&line, Path::new(file))));
            }
        }
        ["prefs", path, who] => {
            for i in 0..EACH {
                let name = format!("{who}{i}");
                retrying(|| {
                    let name = name.clone();
                    rt.block_on(super::super::mcp::update_mcp_preferences_at(Path::new(path), move |p| {
                        p.servers.insert(
                            name.clone(),
                            crate::util::config::McpServerPreferences {
                                values: std::collections::HashMap::new(),
                                source: None,
                                updated_at: None,
                            },
                        );
                    }))
                });
            }
        }
        ["state", path, who] => {
            for i in 0..EACH {
                let key = format!("/{who}/{i}");
                retrying(|| {
                    crate::claude_import_state::update_import_state_at(Path::new(path), |s| {
                        s.projects.insert(
                            key.clone(),
                            crate::claude_import_state::ScopeState {
                                last_hash: "h".to_owned(),
                                last_checked: "t".to_owned(),
                            },
                        );
                    })
                });
            }
        }
        ["fail-user"] => rt.block_on(async {
            let err = crate::util::config::update_config(|cfg| cfg.ui.compact_mode = true)
                .await
                .unwrap_err();
            assert!(err.to_string().contains("injected"), "{err}");
            super::super::mcp::save_mcp_disabled_tools("srv", &["t".to_owned()])
                .await
                .unwrap_err();
        }),
        _ => panic!("unknown role {role}"),
    }
    println!(
        "P61_RETRIES {role} {}",
        RETRIES.load(std::sync::atomic::Ordering::Relaxed)
    );
}

// ---- a write that fails mid-way leaves the original and no temp ----

/// `dir`'s entries, sorted.
fn entries(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

const ORIGINAL: &str = "[ui]\ntheme = \"dark\"\n";

/// A directory holding `name` = [`ORIGINAL`], every stage under it failing.
fn failing_dir(name: &str) -> (tempfile::TempDir, PathBuf, fuigo_config::fs_atomic::stage_fault::FailUnder) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    std::fs::write(&path, ORIGINAL).unwrap();
    let guard = fuigo_config::fs_atomic::stage_fault::fail_writes_under(dir.path());
    (dir, path, guard)
}

fn assert_untouched(dir: &Path, path: &Path, original: &str) {
    assert_eq!(std::fs::read_to_string(path).unwrap(), original);
    let temps: Vec<String> = entries(dir).into_iter().filter(|n| n.contains(".tmp")).collect();
    assert!(temps.is_empty(), "{temps:?}");
}

#[tokio::test]
async fn a_failed_mcp_write_leaves_the_config_and_no_temp() {
    let (dir, path, _fail) = failing_dir("config.toml");
    let server: fuigo_config_types::McpServerConfig = toml::from_str("command = \"echo\"\n").unwrap();
    let err = super::super::mcp::save_mcp_server_config_at(&path, "srv", &server)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("failed to write"), "{err}");
    assert_untouched(dir.path(), &path, ORIGINAL);
    let with_server = "[mcp_servers.srv]\ncommand = \"echo\"\n";
    std::fs::write(&path, with_server).unwrap();
    super::super::mcp::delete_mcp_server_config_at(&path, "srv")
        .await
        .unwrap_err();
    assert_untouched(dir.path(), &path, with_server);
}

#[tokio::test]
async fn a_failed_project_flag_flip_leaves_the_config_and_no_temp() {
    let original = "# keep me\n[mcp_servers.svc]\ncommand = \"x\"\nenabled = false\n";
    let (dir, path, _fail) = failing_dir("config.toml");
    std::fs::write(&path, original).unwrap();
    super::super::mcp::clear_sticky_project_disabled_at(&path, "svc")
        .await
        .unwrap_err();
    assert_untouched(dir.path(), &path, original);
}

#[test]
fn a_failed_marketplace_write_leaves_the_config_and_no_temp() {
    let (dir, path, _fail) = failing_dir("config.toml");
    crate::extensions::marketplace::add_marketplace_source(
        &path,
        "m",
        &crate::plugin::MarketplaceAddInput::LocalPath(PathBuf::from("/m")),
        true,
    )
    .unwrap_err();
    assert_untouched(dir.path(), &path, ORIGINAL);
}

#[test]
fn a_failed_import_write_leaves_the_config_and_no_temp() {
    let (dir, path, _fail) = failing_dir("config.toml");
    crate::claude_import::apply_items_to_config(
        &path,
        &[crate::claude_import::ImportableItem::EnvVar {
            key: "K".to_owned(),
            value: "v".to_owned(),
        }],
    )
    .unwrap_err();
    assert_untouched(dir.path(), &path, ORIGINAL);
}

#[test]
fn a_failed_hooks_paths_write_leaves_the_file_and_no_temp() {
    let (dir, path, _fail) = failing_dir("hooks-paths");
    std::fs::write(&path, "/a\n").unwrap();
    crate::config::add_hooks_path_to_file("/b", &path).unwrap_err();
    crate::config::remove_hooks_path_from_file("/a", &path).unwrap_err();
    assert_untouched(dir.path(), &path, "/a\n");
}

#[tokio::test]
async fn a_failed_state_file_write_leaves_the_file_and_no_temp() {
    let (dir, path, _fail) = failing_dir("mcp_preferences.json");
    std::fs::write(&path, "{\"version\":1,\"servers\":{}}").unwrap();
    super::super::mcp::update_mcp_preferences_at(&path, |p| p.version = 2)
        .await
        .unwrap_err();
    assert_untouched(dir.path(), &path, "{\"version\":1,\"servers\":{}}");
    let state = dir.path().join("claude_import_state.json");
    std::fs::write(&state, "{}").unwrap();
    crate::claude_import_state::update_import_state_at(&state, |s| s.version = 9).unwrap_err();
    assert_untouched(dir.path(), &state, "{}");
}

/// The settings save (`update_config`) and the MCP tool writer act on the
/// user's own config (`$FUIGO_HOME`), so they fail in a child process.
#[test]
fn a_failed_settings_write_leaves_the_user_config_and_no_temp() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("config.toml");
    std::fs::write(&path, ORIGINAL).unwrap();
    #[allow(clippy::disallowed_methods)] // test fixture
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .env("FUIGO_HOME", home.path())
        .env("FUIGO_TEST_FAIL_STAGE_UNDER", home.path())
        .env("FUIGO_P61_SHELL_ROLE", "fail-user")
        .args([
            "--ignored",
            "--exact",
            "--nocapture",
            "util::config::persist::p61_cross_process_tests::p61_shell_child_role",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    assert_untouched(home.path(), &path, ORIGINAL);
}

/// A project file's lock lives under `~/.fuigo/locks/`, the user config's
/// beside it, and two spellings of one project directory share one lock.
#[test]
fn project_files_lock_out_of_tree_and_by_identity() {
    let project = tempfile::tempdir().unwrap();
    let a = project.path().join(".fuigo/config.toml");
    std::fs::create_dir_all(a.parent().unwrap()).unwrap();
    let b = project.path().join(".fuigo/../.fuigo/config.toml");
    let lock = super::rmw_lock_path(&a);
    assert_eq!(lock, super::rmw_lock_path(&b));
    assert!(!lock.starts_with(project.path()), "{}", lock.display());
    assert!(lock.starts_with(crate::util::fuigo_home::fuigo_home().join("locks")));
    let user = super::user_config_path();
    assert_eq!(super::rmw_lock_path(&user), fuigo_config::fs_atomic::config_lock_path(&user));
}

/// A project reached through a symlinked directory and through its real path
/// takes ONE lock, before and after the first writer creates `.fuigo`.
#[cfg(unix)]
#[test]
fn a_symlinked_project_shares_its_lock_before_and_after_fuigo_exists() {
    let root = tempfile::tempdir().unwrap();
    let real = root.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let via_alias = alias.join(".fuigo/config.toml");
    let via_real = real.join(".fuigo/config.toml");
    let before = super::rmw_lock_path(&via_alias);
    assert_eq!(before, super::rmw_lock_path(&via_real));
    std::fs::create_dir(real.join(".fuigo")).unwrap();
    assert_eq!(before, super::rmw_lock_path(&via_alias));
    assert_eq!(before, super::rmw_lock_path(&via_real));
    assert_eq!(
        before,
        super::rmw_lock_path(&real.join(".fuigo/../.fuigo/config.toml"))
    );
    // A link reached after backing out of a MISSING directory resolves too,
    // and keeps resolving the same once that directory exists.
    let around = root.path().join("missing/../alias/.fuigo/config.toml");
    assert_eq!(before, super::rmw_lock_path(&around));
    std::fs::create_dir(root.path().join("missing")).unwrap();
    assert_eq!(before, super::rmw_lock_path(&around));
}
