//! P61: `disabled-hooks` is read-modify-written through the shared helper.
//! Two processes disabling and enabling hooks at once lose no change, and a
//! write that fails mid-way leaves the file and no temp.

use super::*;

const EACH: usize = 15;

fn spawn_role(role: &str) -> std::process::Child {
    #[allow(clippy::disallowed_methods)] // test fixture; waited for by the caller
    std::process::Command::new(std::env::current_exe().unwrap())
        .env("FUIGO_P61_HOOKS_ROLE", role)
        .args([
            "--ignored",
            "--exact",
            "--nocapture",
            "trust::p61_tests::p61_hooks_child_role",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap()
}

#[test]
fn two_processes_disabling_and_enabling_lose_no_change() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("disabled-hooks");
    let children = [
        spawn_role(&format!("keep|{}", file.display())),
        spawn_role(&format!("churn|{}", file.display())),
    ];
    for c in children {
        let out = c.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    for i in 0..EACH {
        assert!(is_hook_disabled_with_file(&format!("keep{i}"), &file), "keep{i}");
        assert!(!is_hook_disabled_with_file(&format!("churn{i}"), &file), "churn{i}");
    }
    let temps: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp"))
        .collect();
    assert!(temps.is_empty(), "{temps:?}");
}

#[test]
fn a_failed_write_leaves_the_file_and_no_temp() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("disabled-hooks");
    std::fs::write(&file, "a\n").unwrap();
    let _fail = fuigo_config::fs_atomic::stage_fault::fail_writes_under(dir.path());
    disable_hook_with_file("b", &file).unwrap_err();
    enable_hook_with_file("a", &file).unwrap_err();
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "a\n");
    let names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp"))
        .collect();
    assert!(names.is_empty(), "{names:?}");
}

/// The file is replaced, never truncated in place: a reader holding the old
/// inode still reads the whole old list, and the new list is whole.
#[cfg(unix)]
#[test]
fn enabling_replaces_the_file_rather_than_truncating_it() {
    use std::os::unix::fs::MetadataExt as _;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("disabled-hooks");
    std::fs::write(&file, "a\nb\n").unwrap();
    let before = std::fs::metadata(&file).unwrap().ino();
    assert!(enable_hook_with_file("a", &file).unwrap());
    assert_ne!(std::fs::metadata(&file).unwrap().ino(), before);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "b\n");
}

/// Run one write, retrying it while it is REFUSED because the lock wait gave
/// up (`TimedOut`): between processes the `flock` is not FIFO (R046 §0.2), and
/// a refusal is reported, never a lost update -- which is what is checked.
fn retrying<T, E: std::fmt::Display>(mut write: impl FnMut() -> Result<T, E>) -> T {
    for _ in 0..50 {
        match write() {
            Ok(v) => return v,
            Err(e) if e.to_string().contains("is locked by another Fuigo writer") => {
                println!("P61_RETRY");
            }
            Err(e) => panic!("{e}"),
        }
    }
    panic!("still refused after 50 lock waits");
}

/// Child-process roles; does nothing unless `FUIGO_P61_HOOKS_ROLE` is set.
#[test]
#[ignore = "child-process role for the P61 two-process tests"]
fn p61_hooks_child_role() {
    let Ok(role) = std::env::var("FUIGO_P61_HOOKS_ROLE") else {
        return;
    };
    let parts: Vec<&str> = role.split('|').collect();
    match parts.as_slice() {
        ["keep", file] => {
            for i in 0..EACH {
                retrying(|| disable_hook_with_file(&format!("keep{i}"), Path::new(file)));
            }
        }
        ["churn", file] => {
            for i in 0..EACH {
                let name = format!("churn{i}");
                retrying(|| disable_hook_with_file(&name, Path::new(file)));
                assert!(retrying(|| enable_hook_with_file(&name, Path::new(file))));
            }
        }
        _ => panic!("unknown role {role}"),
    }
}
