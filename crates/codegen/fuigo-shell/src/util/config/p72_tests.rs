//! P72: the settings save (`update_config`) on the shared optimistic
//! read-modify-write (its `fsync` outside the lock, `f` re-run on the file's
//! current version when another writer got in first), and `delete_mcp_server_config_at` refusing an
//! unparseable config like its siblings.

use std::path::Path;

use toml::Value as TomlValue;

const EACH: usize = 12;

fn spawn_role(home: &Path, role: &str) -> std::process::Child {
    #[allow(clippy::disallowed_methods)] // test fixture; waited for by the caller
    std::process::Command::new(std::env::current_exe().unwrap())
        .env("FUIGO_HOME", home)
        .env("FUIGO_P72_SHELL_ROLE", role)
        .args([
            "--ignored",
            "--exact",
            "--nocapture",
            "--test-threads",
            "1",
            "util::config::persist::p72_tests::p72_shell_child_role",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap()
}

fn wait_ok(child: std::process::Child, what: &str) {
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{what} failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn toml_at(path: &Path) -> TomlValue {
    toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// The settings save fills and syncs its temp while ANOTHER writer holds
/// `config.toml.lock`, and renames only once it gets the lock; the other
/// writer's change to a different modeled field (`ui.yolo`) and to an
/// unmodeled key, made under that lock after the save had read the file, both
/// survive, and the save's READ-DEPENDENT change (an increment) lands on the
/// other writer's value -- the save runs `f` again on the newer version.
// macOS stages inside a private subdirectory; Windows has no optimistic pass.
#[cfg(not(any(target_os = "macos", windows)))]
#[test]
fn the_settings_save_stages_outside_the_lock_and_keeps_a_concurrent_change() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("config.toml");
    std::fs::write(&path, "[ui]\nyolo = false\nmax_thoughts_width = 100\n").unwrap();
    let held = fuigo_config::fs_atomic::lock_config_for_write(&path).unwrap();
    let child = spawn_role(home.path(), "settings-compact");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let staged = names_in(home.path())
            .iter()
            .any(|n| n.starts_with("config.toml.") && n.ends_with(".tmp"));
        if staged {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no temp staged while the lock was held: {:?}",
            names_in(home.path())
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    // Not renamed yet; now change the file under the lock, as another writer.
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "[ui]\nyolo = false\nmax_thoughts_width = 100\n"
    );
    std::fs::write(
        &path,
        "[ui]\nyolo = true\nmax_thoughts_width = 101\n\n[p72_other]\nkept = 1\n",
    )
    .unwrap();
    drop(held);
    wait_ok(child, "settings save");
    let v = toml_at(&path);
    assert_eq!(v["ui"]["compact_mode"].as_bool(), Some(true), "the save's own change");
    assert_eq!(v["ui"]["yolo"].as_bool(), Some(true), "the other writer's modeled field");
    assert_eq!(v["p72_other"]["kept"].as_integer(), Some(1), "the other writer's key");
    // The save's increment was decided again on the other writer's 101: a
    // replay of the value it first computed (101) would lose that increment.
    assert_eq!(v["ui"]["max_thoughts_width"].as_integer(), Some(102), "read-dependent change");
    assert!(
        !names_in(home.path()).iter().any(|n| n.contains(".tmp")),
        "{:?}",
        names_in(home.path())
    );
}

/// Settings saves of two different fields from two processes at once keep
/// both (each applies only the field it changed).
#[test]
fn settings_saves_of_different_fields_in_two_processes_keep_both() {
    let home = tempfile::tempdir().unwrap();
    let a = spawn_role(home.path(), "settings-field|compact");
    let b = spawn_role(home.path(), "settings-field|yolo");
    wait_ok(a, "compact writer");
    wait_ok(b, "yolo writer");
    let v = toml_at(&home.path().join("config.toml"));
    assert_eq!(v["ui"]["compact_mode"].as_bool(), Some(true));
    assert_eq!(v["ui"]["yolo"].as_bool(), Some(true));
}

/// A READ-DEPENDENT settings change (an increment, like a notice-version bump
/// or an append to a list) from two processes at once: every increment lands,
/// because `f` runs on exactly the version its result replaces.
#[test]
fn read_dependent_settings_saves_in_two_processes_lose_no_increment() {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join("config.toml"), "[ui]\nmax_thoughts_width = 100\n").unwrap();
    let a = spawn_role(home.path(), "settings-incr");
    let b = spawn_role(home.path(), "settings-incr");
    wait_ok(a, "incrementer a");
    wait_ok(b, "incrementer b");
    let v = toml_at(&home.path().join("config.toml"));
    assert_eq!(
        v["ui"]["max_thoughts_width"].as_integer(),
        Some(100 + 2 * EACH as i64)
    );
}

/// P72 F6: deleting an MCP server from a config that cannot be parsed is
/// refused (it was read as empty, so it reported "not found"), and the file
/// is left as it was; a missing file still has nothing to delete.
#[tokio::test]
#[serial_test::serial] // the lock lives under the (env-derived) fuigo home
async fn deleting_an_mcp_server_from_an_unparseable_config_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".fuigo/config.toml");
    assert!(
        !super::super::mcp::delete_mcp_server_config_at(&path, "srv")
            .await
            .unwrap()
    );
    assert!(!path.exists(), "nothing is created for a missing file");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let broken = "[mcp_servers.srv]\ncommand = \"echo\"\n[[[broken\n";
    std::fs::write(&path, broken).unwrap();
    let err = super::super::mcp::delete_mcp_server_config_at(&path, "srv")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("unparseable"), "{err}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), broken);
}

/// Child-process roles; does nothing unless `FUIGO_P72_SHELL_ROLE` is set.
#[test]
#[ignore = "child-process role for the P72 shell tests"]
fn p72_shell_child_role() {
    let Ok(role) = std::env::var("FUIGO_P72_SHELL_ROLE") else {
        return;
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let parts: Vec<&str> = role.split('|').collect();
    match parts.as_slice() {
        ["settings-compact"] => {
            rt.block_on(crate::util::config::update_config(|cfg| {
                cfg.ui.compact_mode = true;
                cfg.ui.max_thoughts_width += 1;
            }))
            .unwrap();
        }
        ["settings-field", which] => {
            for i in 0..EACH {
                let on = i + 1 == EACH || i % 2 == 0;
                let which = (*which).to_owned();
                rt.block_on(crate::util::config::update_config(move |cfg| {
                    if which == "compact" {
                        cfg.ui.compact_mode = on;
                    } else {
                        cfg.ui.yolo = on;
                    }
                }))
                .unwrap();
            }
        }
        ["settings-incr"] => {
            for _ in 0..EACH {
                rt.block_on(crate::util::config::update_config(|cfg| {
                    cfg.ui.max_thoughts_width += 1;
                }))
                .unwrap();
            }
        }
        _ => panic!("unknown role {role}"),
    }
}
