//! P61: temp cleanup through a directory handle, the stale-temp sweep, the
//! exact-mode stage, the locked-only edit, explicit lock files, and
//! cross-process lost-update checks of the shared helper.

use super::*;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Every entry name in `dir`, sorted.
fn names_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn append_line_with(
    path: &Path,
    lock: &Path,
    line: &str,
) -> Result<(), EditError<std::io::Error>> {
    edit_locked_with_lock(
        path,
        lock,
        |bytes| stage_atomically_from_existing(path, bytes, 0o600),
        |current| {
            let mut s = match current {
                Ok(bytes) => String::from_utf8_lossy(bytes.unwrap_or_default()).into_owned(),
                Err(e) => return Err(std::io::Error::new(e.kind(), e.to_string())),
            };
            s.push_str(line);
            s.push('\n');
            Ok(Edit::Replace {
                contents: s.into_bytes(),
                value: (),
            })
        },
    )
}

/// Set `path`'s mtime `ago` in the past.
fn age(path: &Path, ago: Duration) {
    let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    f.set_modified(std::time::SystemTime::now() - ago).unwrap();
}

/// A pid that belonged to a process which has exited (and been reaped).
#[cfg(unix)]
fn dead_pid() -> u32 {
    #[allow(clippy::disallowed_methods)] // test fixture
    let mut child = std::process::Command::new("true").spawn().unwrap();
    let pid = child.id();
    child.wait().unwrap();
    pid
}

/// A running process, killed when dropped.
#[cfg(unix)]
struct LiveProcess(std::process::Child);

#[cfg(unix)]
impl LiveProcess {
    fn start() -> Self {
        #[allow(clippy::disallowed_methods)] // test fixture; killed on drop
        let child = std::process::Command::new("sleep").arg("60").spawn().unwrap();
        Self(child)
    }
    fn pid(&self) -> u32 {
        self.0.id()
    }
}

#[cfg(unix)]
impl Drop for LiveProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// ---- cleanup through the directory handle (P49 accepted LOW) ----

/// A staged temp whose directory is moved away before the temp is dropped is
/// removed from where it ended up, not looked for at its old path.
#[cfg(unix)]
#[test]
fn a_temp_whose_directory_moved_away_is_removed_on_drop() {
    let root = tempfile::tempdir().unwrap();
    let live = root.path().join("live");
    std::fs::create_dir(&live).unwrap();
    let staged = stage_atomically(&live.join("config.toml"), b"x", Some(0o600)).unwrap();
    std::fs::rename(&live, root.path().join("moved")).unwrap();
    // And a different directory now sits at the old path.
    std::fs::create_dir(&live).unwrap();
    drop(staged);
    assert!(names_in(&root.path().join("moved")).is_empty());
    assert!(names_in(&live).is_empty());
}

/// A commit whose rename fails because the directory moved away removes the
/// temp from the moved directory.
#[cfg(unix)]
#[test]
fn a_failed_commit_after_the_directory_moved_removes_the_temp() {
    let root = tempfile::tempdir().unwrap();
    let live = root.path().join("live");
    std::fs::create_dir(&live).unwrap();
    let staged = stage_atomically(&live.join("config.toml"), b"x", Some(0o600)).unwrap();
    std::fs::rename(&live, root.path().join("moved")).unwrap();
    staged.commit().expect_err("the directory is gone");
    assert!(names_in(&root.path().join("moved")).is_empty());
}

/// The same for `write_through`'s temps.
#[cfg(unix)]
#[test]
fn a_write_through_temp_whose_directory_moved_away_is_removed() {
    let root = tempfile::tempdir().unwrap();
    let live = root.path().join("live");
    std::fs::create_dir(&live).unwrap();
    let path = live.join("config.toml");
    std::fs::write(&path, "a\n").unwrap();
    let staged = crate::write_through::stage_file_atomically(&path, b"b\n").unwrap();
    std::fs::rename(&live, root.path().join("moved")).unwrap();
    drop(staged);
    assert_eq!(names_in(&root.path().join("moved")), ["config.toml"]);
}

/// The P49 scenario itself: another lock holder swaps the directory while the
/// temp is staged and restores it, leaving the temp in the decoy. The edit
/// still succeeds, and the decoy keeps no temp.
#[cfg(unix)]
#[test]
fn a_temp_staged_in_a_swapped_directory_is_removed_from_the_decoy() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    let live = root.join("live");
    std::fs::create_dir(&live).unwrap();
    let path = live.join("config.toml");
    std::fs::write(&path, "a\n").unwrap();
    let mut first = true;
    edit_locked(
        &path,
        |bytes| {
            if first {
                first = false;
                std::fs::rename(&live, root.join("live.aside")).unwrap();
                std::fs::create_dir(&live).unwrap();
                std::fs::write(&path, "a\n").unwrap();
                let staged = stage_atomically_from_existing(&path, bytes, 0o600);
                std::fs::rename(&live, root.join("live.decoy")).unwrap();
                std::fs::rename(root.join("live.aside"), &live).unwrap();
                return staged;
            }
            stage_atomically_from_existing(&path, bytes, 0o600)
        },
        |_| {
            Ok::<_, std::io::Error>(Edit::Replace {
                contents: b"b\n".to_vec(),
                value: (),
            })
        },
    )
    .unwrap();
    assert_eq!(lines(&path), ["b"]);
    assert_eq!(names_in(&root.join("live.decoy")), ["config.toml"]);
    assert_eq!(names_in(&live), ["config.toml", "config.toml.lock"]);
}

// ---- temp names ----

/// A leftover temp at the next name (a crashed writer under a reused pid) is
/// skipped, not reused and not deleted.
#[test]
fn staging_skips_a_leftover_temp_name() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("config.toml");
    let next = WRITE_NONCE.load(Ordering::Relaxed);
    let pid = std::process::id();
    let leftovers: Vec<PathBuf> = (next..next + 8)
        .map(|n| dir.path().join(format!("config.toml.{pid}.{n}.tmp")))
        .collect();
    for l in &leftovers {
        std::fs::write(l, "leftover").unwrap();
    }
    let staged = stage_atomically(&target, b"new", None).expect("moves on to a free name");
    staged.commit().unwrap();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "new");
    for l in &leftovers {
        assert_eq!(std::fs::read_to_string(l).unwrap(), "leftover");
    }
}

#[test]
fn temp_names_are_recognised_and_nothing_else() {
    let name = "config.toml";
    assert_eq!(temp_owner_pid("config.toml.12.3.tmp", name), Some(12));
    assert_eq!(temp_owner_pid(".config.toml.12.3.tmp", name), Some(12));
    assert_eq!(temp_owner_pid("config.toml.tmp.12.99999", name), Some(12));
    assert_eq!(temp_owner_pid("config.toml.dashboard.tmp.12", name), Some(12));
    for other in [
        "config.toml",
        "config.toml.lock",
        "config.toml.bak",
        "config.toml.12.tmp",
        "config.toml.x.3.tmp",
        "config.toml.12.3.tmp.bak",
        "config.toml.12.3",
        "notes.12.3.tmp",
        "other.toml.12.3.tmp",
        ".config.toml.12.3.staging",
        "config.toml.dashboard.tmp.",
        "config.toml.tmp.12",
        "xconfig.toml.12.3.tmp",
    ] {
        assert_eq!(temp_owner_pid(other, name), None, "{other}");
    }
    // A long name is cut to 64 bytes in temp names, as the writers cut it.
    let long = "a".repeat(100);
    let cut = "a".repeat(64);
    assert_eq!(temp_owner_pid(&format!("{cut}.7.1.tmp"), &long), Some(7));
    assert_eq!(temp_owner_pid(&format!(".{cut}.7.1.tmp"), &long), Some(7));
}

// ---- the stale-temp sweep ----

/// Old temps of a dead writer go (every one of our name patterns); a fresh
/// one of a dead writer, old ones of a live writer or of this process, and
/// anything that is not our temp name all stay.
#[cfg(unix)]
#[test]
fn the_sweep_removes_only_old_temps_of_dead_writers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "keep\n").unwrap();
    let dead = dead_pid();
    let live = LiveProcess::start();
    let me = std::process::id();
    let old = Duration::from_secs(2 * 60 * 60);
    let mk = |name: String, ago: Option<Duration>| {
        let p = dir.path().join(name);
        std::fs::write(&p, "t").unwrap();
        if let Some(ago) = ago {
            age(&p, ago);
        }
        p
    };
    let gone = [
        mk(format!("config.toml.{dead}.1.tmp"), Some(old)),
        mk(format!(".config.toml.{dead}.2.tmp"), Some(old)),
        mk(format!("config.toml.tmp.{dead}.123456"), Some(old)),
        mk(format!("config.toml.dashboard.tmp.{dead}"), Some(old)),
    ];
    let kept = [
        mk(format!("config.toml.{dead}.3.tmp"), None),
        mk(format!("config.toml.{}.4.tmp", live.pid()), Some(old)),
        mk(format!(".config.toml.{me}.5.tmp"), Some(old)),
        mk(format!("other.toml.{dead}.6.tmp"), Some(old)),
        mk(format!("notes.{dead}.7.tmp"), Some(old)),
        mk("config.toml.bak".to_owned(), Some(old)),
        mk("config.toml.lock".to_owned(), Some(old)),
    ];
    let mut removed = sweep_stale_temps(&path, STALE_TEMP_AGE);
    removed.sort();
    let mut want = gone.to_vec();
    want.sort();
    assert_eq!(removed, want);
    for p in &gone {
        assert!(!p.exists(), "{}", p.display());
    }
    for p in &kept {
        assert!(p.exists(), "{}", p.display());
    }
    assert_eq!(lines(&path), ["keep"]);
}

/// A live writer's temp survives the sweep however old it is -- even with the
/// age bound switched off.
#[cfg(unix)]
#[test]
fn a_live_writers_temp_is_never_swept() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let live = LiveProcess::start();
    let tmp = dir.path().join(format!("config.toml.{}.9.tmp", live.pid()));
    std::fs::write(&tmp, "t").unwrap();
    age(&tmp, Duration::from_secs(48 * 60 * 60));
    assert!(sweep_stale_temps(&path, Duration::ZERO).is_empty());
    assert!(tmp.exists());
    // Once that writer is gone, the same temp is stale.
    drop(live);
    assert_eq!(sweep_stale_temps(&path, Duration::ZERO), std::slice::from_ref(&tmp));
}

/// A fresh temp is never swept, even when its writer is gone.
#[cfg(unix)]
#[test]
fn a_fresh_temp_is_never_swept() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let tmp = dir.path().join(format!(".config.toml.{}.1.tmp", dead_pid()));
    std::fs::write(&tmp, "t").unwrap();
    assert!(sweep_stale_temps(&path, STALE_TEMP_AGE).is_empty());
    assert!(tmp.exists());
}

/// Only regular files are removed: a directory or a symlink with a temp name
/// stays (here with the age bound off, so only the type decides).
#[cfg(unix)]
#[test]
fn the_sweep_removes_regular_files_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let dead = dead_pid();
    let as_dir = dir.path().join(format!("config.toml.{dead}.1.tmp"));
    std::fs::create_dir(&as_dir).unwrap();
    let target = dir.path().join("precious");
    std::fs::write(&target, "p").unwrap();
    let as_link = dir.path().join(format!("config.toml.{dead}.2.tmp"));
    std::os::unix::fs::symlink(&target, &as_link).unwrap();
    assert!(sweep_stale_temps(&path, Duration::ZERO).is_empty());
    assert!(as_dir.is_dir());
    assert!(as_link.symlink_metadata().unwrap().file_type().is_symlink());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "p");
}

/// The first edit of a file sweeps the stale temps beside it.
#[cfg(unix)]
#[test]
fn the_first_edit_of_a_file_sweeps_its_stale_temps() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let stale = dir.path().join(format!("config.toml.{}.1.tmp", dead_pid()));
    std::fs::write(&stale, "t").unwrap();
    age(&stale, Duration::from_secs(2 * 60 * 60));
    append_line_with(&path, &config_lock_path(&path), "x").unwrap();
    assert!(!stale.exists());
    assert_eq!(names_in(dir.path()), ["config.toml", "config.toml.lock"]);
}

/// A writer in ANOTHER process holding a freshly staged temp (stopped between
/// staging and its commit) keeps it through a sweep with the age bound off,
/// and then commits it.
#[cfg(unix)]
#[test]
fn a_sweep_never_removes_another_processs_staged_temp() {
    use std::io::{BufRead as _, Write as _};
    let dir = tempfile::tempdir().unwrap();
    let path = dunce::canonicalize(dir.path()).unwrap().join("config.toml");
    std::fs::write(&path, "a\n").unwrap();
    let mut child = spawn_role(&format!("stall|{}", path.display()));
    let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert!(out.read_line(&mut line).unwrap() > 0, "child exited early");
        // libtest prints `test <name> ... ` without a newline before the
        // role's own output, so the marker can sit mid-line.
        if line.contains("STAGED ") {
            break;
        }
    }
    let tmp = PathBuf::from(line.split("STAGED ").nth(1).unwrap().trim());
    assert!(tmp.exists(), "{}", tmp.display());
    assert!(sweep_stale_temps(&path, Duration::ZERO).is_empty());
    assert!(tmp.exists());
    child.stdin.take().unwrap().write_all(b"go\n").unwrap();
    assert!(child.wait().unwrap().success());
    assert_eq!(lines(&path), ["a", "stalled"]);
    assert!(!tmp.exists());
}

/// A macOS write-through staging directory a dead writer left: our temp in it
/// and then the directory go; one holding anything else keeps that and itself.
#[cfg(unix)]
#[test]
fn the_sweep_clears_a_dead_writers_staging_directory_and_only_ours() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let dead = dead_pid();
    let old = Duration::from_secs(2 * 60 * 60);
    let empty_after = dir.path().join(format!(".config.toml.{dead}.1.staging"));
    std::fs::create_dir(&empty_after).unwrap();
    let ours = empty_after.join(format!(".config.toml.{dead}.2.tmp"));
    std::fs::write(&ours, "t").unwrap();
    age(&ours, old);
    let busy = dir.path().join(format!(".config.toml.{dead}.3.staging"));
    std::fs::create_dir(&busy).unwrap();
    let foreign = busy.join("not-ours");
    std::fs::write(&foreign, "keep").unwrap();
    // In the dead writer's old staging directory: a live writer's temp, and a
    // fresh temp of the dead writer itself -- neither may go.
    let live = LiveProcess::start();
    let mixed = dir.path().join(format!(".config.toml.{dead}.4.staging"));
    std::fs::create_dir(&mixed).unwrap();
    let live_temp = mixed.join(format!(".config.toml.{}.5.tmp", live.pid()));
    std::fs::write(&live_temp, "t").unwrap();
    age(&live_temp, old);
    let fresh_temp = mixed.join(format!(".config.toml.{dead}.6.tmp"));
    std::fs::write(&fresh_temp, "t").unwrap();
    for d in [&empty_after, &busy, &mixed] {
        std::fs::File::open(d)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - old)
            .unwrap();
    }
    let removed = sweep_stale_temps(&path, STALE_TEMP_AGE);
    assert!(removed.contains(&ours) && removed.contains(&empty_after), "{removed:?}");
    assert!(!empty_after.exists());
    assert!(foreign.exists() && busy.is_dir());
    assert!(live_temp.exists() && fresh_temp.exists() && mixed.is_dir());
}

/// The requested mode is the temp's EXACT mode, whatever the umask: a
/// restrictive umask must not publish a config its owner cannot read.
#[cfg(unix)]
#[test]
fn a_restrictive_umask_does_not_change_the_replacement_mode() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "a").unwrap();
    chmod(&path, 0o600);
    let out = spawn_role(&format!("umask|{}", path.display()))
        .wait_with_output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "b");
    assert_eq!(mode_of(&path), 0o600);
}

// ---- stage_atomically_keeping_mode ----

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

#[cfg(unix)]
fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// The replaced file's mode is kept exactly (group/world bits too), but the
/// temp is owner-only until the commit puts the mode on it.
#[cfg(unix)]
#[test]
fn keeping_mode_keeps_the_mode_exactly_and_the_temp_private_until_commit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "a").unwrap();
    chmod(&path, 0o644);
    let staged = stage_atomically_keeping_mode(&path, b"b").unwrap();
    assert_eq!(mode_of(staged.temp_path().unwrap()), 0o600);
    staged.commit().unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "b");
    assert_eq!(mode_of(&path), 0o644);
}

/// The mode is the target's AT THE COMMIT, not at staging.
#[cfg(unix)]
#[test]
fn keeping_mode_takes_the_mode_at_commit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "a").unwrap();
    chmod(&path, 0o600);
    let staged = stage_atomically_keeping_mode(&path, b"b").unwrap();
    chmod(&path, 0o640);
    staged.commit().unwrap();
    assert_eq!(mode_of(&path), 0o640);
}

/// A new file is owner-only.
#[cfg(unix)]
#[test]
fn keeping_mode_creates_a_new_file_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    stage_atomically_keeping_mode(&path, b"b")
        .unwrap()
        .commit()
        .unwrap();
    assert_eq!(mode_of(&path), 0o600);
}

/// A failed write leaves no temp and the original untouched.
#[test]
fn keeping_mode_failure_leaves_no_temp() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "a").unwrap();
    stage_fault::FAIL_WRITE.with(|f| f.set(true));
    let r = stage_atomically_keeping_mode(&path, b"0123456789abcdef");
    stage_fault::FAIL_WRITE.with(|f| f.set(false));
    r.expect_err("injected");
    assert_eq!(names_in(dir.path()), ["config.toml"]);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "a");
}

// ---- edit_under_lock / explicit lock files ----

/// The edit runs exactly once, under the lock.
#[test]
fn edit_under_lock_runs_the_edit_once_under_the_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "a\n").unwrap();
    let lock = config_lock_path(&path);
    let mut calls = 0;
    edit_under_lock(
        &path,
        &lock,
        |bytes| stage_atomically_from_existing(&path, bytes, 0o600),
        |current| {
            calls += 1;
            assert!(
                lock_at_within(&lock, Duration::from_millis(50)).is_err(),
                "the edit must run under the lock"
            );
            let mut s = String::from_utf8(current.unwrap().unwrap().to_vec()).unwrap();
            s.push_str("b\n");
            Ok::<_, std::io::Error>(Edit::Replace {
                contents: s.into_bytes(),
                value: (),
            })
        },
    )
    .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(lines(&path), ["a", "b"]);
}

/// A write that fails mid-way leaves the original intact and no temp, through
/// the optimistic and the locked-only entry points alike.
#[test]
fn an_edit_whose_write_fails_leaves_the_original_and_no_temp() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "a\n").unwrap();
    let lock = config_lock_path(&path);
    let replace = |_: Current<'_>| {
        Ok::<_, std::io::Error>(Edit::Replace {
            contents: b"0123456789abcdef\n".to_vec(),
            value: (),
        })
    };
    stage_fault::FAIL_WRITE.with(|f| f.set(true));
    let a = edit_locked(
        &path,
        |bytes| stage_atomically_keeping_mode(&path, bytes),
        replace,
    );
    let b = edit_under_lock(
        &path,
        &lock,
        |bytes| stage_atomically_from_existing(&path, bytes, 0o600),
        replace,
    );
    stage_fault::FAIL_WRITE.with(|f| f.set(false));
    assert!(matches!(a, Err(EditError::Write(_))), "{a:?}");
    assert!(matches!(b, Err(EditError::Write(_))), "{b:?}");
    assert_eq!(lines(&path), ["a"]);
    assert_eq!(names_in(dir.path()), ["config.toml", "config.toml.lock"]);
}

/// A commit whose rename fails (the target became a non-empty directory)
/// leaves no temp either.
#[test]
fn an_edit_whose_rename_fails_leaves_no_temp() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::create_dir(&path).unwrap();
    std::fs::write(path.join("inner"), "").unwrap();
    let r = edit_under_lock(
        &path,
        &dir.path().join("x.lock"),
        |bytes| stage_atomically_keeping_mode(&path, bytes),
        |_| {
            Ok::<_, std::io::Error>(Edit::Replace {
                contents: b"x".to_vec(),
                value: (),
            })
        },
    );
    assert!(matches!(r, Err(EditError::Write(_))), "{r:?}");
    assert_eq!(names_in(dir.path()), ["config.toml", "x.lock"]);
}

/// An explicit lock file is the one contended on; none is made beside the file.
#[test]
fn an_explicit_lock_file_is_the_one_taken() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("project/config.toml");
    let lock = dir.path().join("home/locks/p.lock");
    let held = lock_file_for_write(&lock).unwrap();
    let err = std::thread::scope(|s| {
        s.spawn(|| append_line_with(&path, &lock, "x"))
            .join()
            .unwrap()
    })
    .expect_err("the explicit lock is held");
    assert!(matches!(err, EditError::Lock(ref e) if e.kind() == std::io::ErrorKind::TimedOut));
    drop(held);
    append_line_with(&path, &lock, "y").unwrap();
    assert_eq!(lines(&path), ["y"]);
    assert_eq!(names_in(&dir.path().join("project")), ["config.toml"]);
}

// ---- two processes ----

/// Re-run this test binary as a child in `role` (see [`p61_child_role`]).
fn spawn_role(role: &str) -> std::process::Child {
    #[allow(clippy::disallowed_methods)] // test fixture; waited for by the caller
    std::process::Command::new(std::env::current_exe().unwrap())
        .env("FUIGO_P61_ROLE", role)
        .args([
            "--ignored",
            "--exact",
            "--nocapture",
            "--test-threads",
            "1",
            "fs_atomic::p61_tests::p61_child_role",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .unwrap()
}

/// Two processes appending to one file through the helper, at once, lose no
/// line -- on the default lock and on an explicit one.
#[test]
fn two_processes_editing_one_file_lose_no_update() {
    let _alone = HEAVY_IO
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    const EACH: usize = 40;
    for explicit in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let lock = if explicit {
            dir.path().join("elsewhere/locks/x.lock")
        } else {
            config_lock_path(&path)
        };
        let children: Vec<_> = ["a", "b"]
            .iter()
            .map(|p| {
                spawn_role(&format!(
                    "append|{}|{}|{p}|{EACH}",
                    path.display(),
                    lock.display()
                ))
            })
            .collect();
        for mut c in children {
            drop(c.stdin.take());
            let out = c.wait_with_output().unwrap();
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
        }
        let mut got = lines(&path);
        got.sort();
        let mut want: Vec<String> = ["a", "b"]
            .iter()
            .flat_map(|p| (0..EACH).map(move |i| format!("{p}-{i}")))
            .collect();
        want.sort();
        assert_eq!(got, want, "explicit lock: {explicit}");
        let leftovers: Vec<String> = names_in(dir.path())
            .into_iter()
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }
}

/// Child-process roles for the tests above; does nothing unless
/// `FUIGO_P61_ROLE` is set (so a plain `--ignored` run is harmless).
#[test]
#[ignore = "child-process role for the P61 two-process tests"]
fn p61_child_role() {
    let Ok(role) = std::env::var("FUIGO_P61_ROLE") else {
        return;
    };
    let parts: Vec<&str> = role.split('|').collect();
    match parts.as_slice() {
        ["append", path, lock, prefix, n] => {
            let (path, lock) = (Path::new(path), Path::new(lock));
            for i in 0..n.parse::<usize>().unwrap() {
                // A lock wait that gives up is a refusal, never a lost update
                // (between processes the flock is not FIFO, R046 §0.2): retry it.
                let mut tries = 0;
                loop {
                    match append_line_with(path, lock, &format!("{prefix}-{i}")) {
                        Ok(()) => break,
                        Err(EditError::Lock(e))
                            if e.kind() == std::io::ErrorKind::TimedOut && tries < 50 =>
                        {
                            tries += 1;
                            println!("P61_RETRY");
                        }
                        Err(e) => panic!("{prefix}-{i}: {e}"),
                    }
                }
            }
        }
        ["stall", path] => {
            use std::io::{BufRead as _, Write as _};
            let path = Path::new(path);
            // Stop between staging and the commit, report the temp, wait.
            let staged = stage_atomically_from_existing(path, b"a\nstalled\n", 0o600).unwrap();
            println!("STAGED {}", staged.temp_path().unwrap().display());
            std::io::stdout().flush().unwrap();
            let mut go = String::new();
            std::io::stdin().lock().read_line(&mut go).unwrap();
            let _lock = lock_config_for_write(path).unwrap();
            staged.commit().unwrap();
        }
        // (The test that spawns it is unix-only; `libc` is a unix dependency.)
        #[cfg(unix)]
        ["umask", path] => {
            // SAFETY: sets this (child) process's umask.
            unsafe {
                libc::umask(0o277);
            }
            stage_atomically_from_existing(Path::new(path), b"b", 0o600)
                .unwrap()
                .commit()
                .unwrap();
        }
        _ => panic!("unknown role {role}"),
    }
}
