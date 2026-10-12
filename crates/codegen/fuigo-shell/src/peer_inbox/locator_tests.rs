//! Tests for packet 8b. Everything happens inside a private `tempfile::tempdir()`; the second-uid tests chown
//! only paths inside it (and skip when not root).
#![cfg(unix)]

use super::*;
use std::fs;
use std::os::unix::fs::{symlink, DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

fn mkdir(p: &Path, mode: u32) {
    fs::DirBuilder::new().mode(mode).create(p).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
}

fn setup() -> (tempfile::TempDir, PathBuf, CheckedDir) {
    let td = tempfile::tempdir().unwrap();
    let home = td.path().join("home");
    mkdir(&home, 0o700);
    let dir = CheckedDir::create_or_open(&home).unwrap();
    (td, home, dir)
}

fn write_file(p: &Path, bytes: &[u8], mode: u32) {
    fs::write(p, bytes).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
}

fn names(p: &Path) -> Vec<String> {
    let mut v: Vec<_> = fs::read_dir(p)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    v.sort();
    v
}

fn chown_nobody(p: &Path) -> bool {
    let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
    // SAFETY: valid path inside our temp dir.
    unsafe { libc::chown(c.as_ptr(), 65534, 65534) == 0 }
}

#[test]
fn symlinked_home_fails_closed_with_fixed_text() {
    let td = tempfile::tempdir().unwrap();
    let real = td.path().join("real");
    mkdir(&real, 0o700);
    mkdir(&real.join("peers"), 0o700);
    let link = td.path().join("link");
    symlink(&real, &link).unwrap();
    assert_eq!(CheckedDir::open(&link).unwrap_err(), Disabled::SymlinkedHome);
    let e = CheckedDir::create_or_open(&link).unwrap_err();
    assert_eq!(e, Disabled::SymlinkedHome);
    assert_eq!(
        e.reason_text(),
        "peer messaging is unavailable: the Fuigo home is a symbolic link"
    );
    // creates nothing: the real dir holds only the peers dir we made
    assert_eq!(names(&real), vec!["peers"]);
}

#[test]
fn symlinked_peers_refused() {
    let td = tempfile::tempdir().unwrap();
    let home = td.path().join("home");
    mkdir(&home, 0o700);
    mkdir(&td.path().join("elsewhere"), 0o700);
    symlink(td.path().join("elsewhere"), home.join("peers")).unwrap();
    assert_eq!(CheckedDir::open(&home).unwrap_err(), Disabled::PeersSymlink);
    assert_eq!(CheckedDir::create_or_open(&home).unwrap_err(), Disabled::PeersSymlink);
}

#[test]
fn symlinked_locator_refused() {
    let (td, home, dir) = setup();
    write_file(&td.path().join("target"), b"x", 0o600);
    symlink(td.path().join("target"), home.join("peers/hosts.json")).unwrap();
    assert_eq!(read_locator(&dir, "hosts.json"), Err(Disabled::Rejected(Reject::Symlink)));
}

#[test]
fn hard_linked_locator_refused() {
    let (td, home, dir) = setup();
    let p = home.join("peers/hosts.json");
    write_file(&p, b"x", 0o600);
    fs::hard_link(&p, td.path().join("other")).unwrap();
    assert_eq!(fs::metadata(&p).unwrap().nlink(), 2);
    assert_eq!(read_locator(&dir, "hosts.json"), Err(Disabled::Rejected(Reject::HardLinked)));
}

#[test]
fn wrong_file_mode_refused() {
    let (_td, home, dir) = setup();
    write_file(&home.join("peers/hosts.json"), b"x", 0o644);
    assert_eq!(read_locator(&dir, "hosts.json"), Err(Disabled::Rejected(Reject::WrongMode)));
}

#[test]
fn wrong_dir_mode_refused() {
    let td = tempfile::tempdir().unwrap();
    let home = td.path().join("home");
    mkdir(&home, 0o700);
    mkdir(&home.join("peers"), 0o755);
    assert_eq!(CheckedDir::open(&home).unwrap_err(), Disabled::PeersWrongMode);
    assert_eq!(CheckedDir::create_or_open(&home).unwrap_err(), Disabled::PeersWrongMode);
}

#[test]
fn fifo_does_not_block() {
    let (_td, home, dir) = setup();
    let p = home.join("peers/hosts.json");
    let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
    // SAFETY: valid path inside the temp dir.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let r = read_locator(&dir, "hosts.json");
        let u = update_locator(&dir, "hosts.json", |_| Some(b"y".to_vec()));
        let _ = tx.send((r, u));
    });
    let (r, u) = rx.recv_timeout(Duration::from_secs(10)).expect("read blocked on FIFO");
    assert_eq!(r, Err(Disabled::Rejected(Reject::NotRegular)));
    assert_eq!(u, Err(Disabled::Rejected(Reject::NotRegular)));
}

#[test]
fn size_cap_is_exact() {
    let (_td, home, dir) = setup();
    let p = home.join("peers/hosts.json");
    write_file(&p, &vec![b'a'; 64 * 1024], 0o600);
    assert_eq!(read_locator(&dir, "hosts.json").unwrap().unwrap().len(), 64 * 1024);
    write_file(&p, &vec![b'a'; 64 * 1024 + 1], 0o600);
    assert_eq!(read_locator(&dir, "hosts.json"), Err(Disabled::Rejected(Reject::TooLarge)));
    let big = update_locator_rewriting(&dir, "hosts.json", |_| Some(vec![0; 64 * 1024 + 1]));
    assert_eq!(big, Err(Disabled::OutputTooLarge));
}

#[test]
fn directory_in_place_of_file_refused() {
    let (_td, home, dir) = setup();
    mkdir(&home.join("peers/hosts.json"), 0o700);
    assert_eq!(read_locator(&dir, "hosts.json"), Err(Disabled::Rejected(Reject::NotRegular)));
    assert_eq!(
        update_locator(&dir, "hosts.json", |_| Some(vec![1])),
        Err(Disabled::Rejected(Reject::NotRegular))
    );
}

#[test]
fn ancestor_owned_by_other_uid_refused() {
    let td = tempfile::tempdir().unwrap();
    let a = td.path().join("a");
    mkdir(&a, 0o755);
    let home = a.join("home");
    mkdir(&home, 0o700);
    if !chown_nobody(&a) {
        eprintln!("skipped: not root");
        return;
    }
    assert_eq!(CheckedDir::open(&home).unwrap_err(), Disabled::AncestorWrongOwner);
}

#[test]
fn world_writable_ancestor_refused_sticky_allowed() {
    let td = tempfile::tempdir().unwrap();
    let a = td.path().join("a");
    mkdir(&a, 0o777);
    let home = a.join("home");
    mkdir(&home, 0o700);
    mkdir(&home.join("peers"), 0o700);
    assert_eq!(CheckedDir::open(&home).unwrap_err(), Disabled::AncestorWritableByOthers);
    fs::set_permissions(&a, fs::Permissions::from_mode(0o1777)).unwrap();
    CheckedDir::open(&home).unwrap();
    // group-writable non-sticky is refused too
    fs::set_permissions(&a, fs::Permissions::from_mode(0o770)).unwrap();
    assert_eq!(CheckedDir::open(&home).unwrap_err(), Disabled::AncestorWritableByOthers);
}

#[test]
fn a_group_or_world_writable_home_is_refused_even_when_sticky() {
    let td = tempfile::tempdir().unwrap();
    let home = td.path().join("home");
    mkdir(&home, 0o700);
    mkdir(&home.join("peers"), 0o700);
    CheckedDir::open(&home).unwrap();
    for mode in [0o1777, 0o1770, 0o777, 0o770, 0o720, 0o702] {
        fs::set_permissions(&home, fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(CheckedDir::open(&home).unwrap_err(), Disabled::HomeWritableByOthers, "mode {mode:o}");
        assert_eq!(CheckedDir::create_or_open(&home).unwrap_err(), Disabled::HomeWritableByOthers, "mode {mode:o}");
    }
    // an ordinary 0755 home keeps working
    fs::set_permissions(&home, fs::Permissions::from_mode(0o755)).unwrap();
    CheckedDir::open(&home).unwrap();
}

#[test]
fn replaced_by_symlink_between_updates_is_refused() {
    let (td, home, dir) = setup();
    update_locator(&dir, "hosts.json", |c| {
        assert!(c.is_none());
        Some(b"one".to_vec())
    })
    .unwrap();
    let decoy = td.path().join("decoy");
    write_file(&decoy, b"decoy", 0o600);
    let p = home.join("peers/hosts.json");
    fs::remove_file(&p).unwrap();
    symlink(&decoy, &p).unwrap();
    let r = update_locator(&dir, "hosts.json", |_| panic!("f must not run"));
    assert_eq!(r, Err(Disabled::Rejected(Reject::Symlink)));
    assert_eq!(fs::read(&decoy).unwrap(), b"decoy");
    // the rewriting variant replaces the symlink itself and never writes through it
    update_locator_rewriting(&dir, "hosts.json", |c| {
        assert!(c.is_none());
        Some(b"two".to_vec())
    })
    .unwrap();
    assert_eq!(fs::read(&decoy).unwrap(), b"decoy");
    assert_eq!(read_locator(&dir, "hosts.json").unwrap().unwrap(), b"two");
}

#[test]
fn two_threads_lose_no_row() {
    let (_td, home, _dir) = setup();
    let hs: Vec<_> = (0..2)
        .map(|t| {
            let home = home.clone();
            std::thread::spawn(move || {
                let dir = CheckedDir::open(&home).unwrap();
                for i in 0..200 {
                    // The lock wait is bounded (2 s); under a heavily loaded disk a stress loop may meet `LockBusy`
                    // and simply tries again. The closure only runs once the lock is held, so no row is doubled.
                    loop {
                        let r = update_locator(&dir, "hosts.json", |c| {
                            let mut v = c.map(<[u8]>::to_vec).unwrap_or_default();
                            v.extend_from_slice(format!("t{t}-{i}\n").as_bytes());
                            Some(v)
                        });
                        match r {
                            Err(Disabled::LockBusy) => continue,
                            other => break other.unwrap(),
                        }
                    }
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    let dir = CheckedDir::open(&home).unwrap();
    let data = read_locator(&dir, "hosts.json").unwrap().unwrap();
    let text = String::from_utf8(data).unwrap();
    let lines: std::collections::HashSet<_> = text.lines().collect();
    assert_eq!(text.lines().count(), 400);
    assert_eq!(lines.len(), 400);
    assert_eq!(names(&home.join("peers")), vec![".lock", "hosts.json"]);
}

#[test]
fn symlinked_lock_file_refused() {
    let (td, home, dir) = setup();
    write_file(&td.path().join("lk"), b"", 0o600);
    symlink(td.path().join("lk"), home.join("peers/.lock")).unwrap();
    assert_eq!(
        update_locator(&dir, "hosts.json", |_| Some(vec![1])),
        Err(Disabled::LockRejected(Reject::Symlink))
    );
    assert_eq!(read_locator(&dir, "hosts.json"), Ok(None));
}

#[test]
fn panic_in_f_leaves_no_temp_and_releases_lock() {
    let (_td, home, dir) = setup();
    let dir = std::sync::Arc::new(dir);
    let d2 = dir.clone();
    let r = std::thread::spawn(move || {
        let _ = update_locator(&d2, "hosts.json", |_| panic!("boom"));
    })
    .join();
    assert!(r.is_err());
    assert!(!names(&home.join("peers")).iter().any(|n| n.starts_with(".tmp-")));
    // lock is free again: this would hang otherwise
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(update_locator(&dir, "hosts.json", |_| Some(b"ok".to_vec())));
    });
    rx.recv_timeout(Duration::from_secs(10)).expect("lock leaked").unwrap();
}

#[test]
fn none_removes_the_file() {
    let (_td, home, dir) = setup();
    update_locator(&dir, "hosts.json", |_| Some(b"x".to_vec())).unwrap();
    update_locator(&dir, "hosts.json", |c| {
        assert_eq!(c, Some(&b"x"[..]));
        None
    })
    .unwrap();
    assert!(!home.join("peers/hosts.json").exists());
    assert!(!names(&home.join("peers")).iter().any(|n| n.starts_with(".tmp-")));
}

#[test]
fn only_create_or_open_creates_peers() {
    let td = tempfile::tempdir().unwrap();
    let home = td.path().join("home");
    mkdir(&home, 0o700);
    assert_eq!(CheckedDir::open(&home).unwrap_err(), Disabled::PeersMissing);
    assert!(!home.join("peers").exists());
    let d = CheckedDir::create_or_open(&home).unwrap();
    assert_eq!(fs::metadata(home.join("peers")).unwrap().mode() & 0o7777, 0o700);
    drop(d);
    CheckedDir::open(&home).unwrap();
}

#[test]
fn invalid_names_refused() {
    let (_td, _home, dir) = setup();
    for n in ["", ".", "..", "a/b", ".lock", ".tmp-1", "a\0b"] {
        assert_eq!(read_locator(&dir, n), Err(Disabled::InvalidName), "{n:?}");
    }
}

/// A normal Ubuntu user has umask 002. The home Fuigo creates must still pass the inbox's own directory checks.
/// The umask is process-wide, so the body runs in a child copy of this test binary: changing it here would make
/// the temp dirs of the tests running beside this one group-writable.
#[test]
fn home_created_under_umask_002_is_private_and_accepted() {
    const CHILD: &str = "FUIGO_TEST_UMASK_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "peer_inbox::locator_tests::home_created_under_umask_002_is_private_and_accepted", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(out.status.success(), "child failed:\n{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(String::from_utf8_lossy(&out.stdout).contains("1 passed"), "the child test did not run");
        return;
    }
    let td = tempfile::tempdir().unwrap();
    let home = td.path().join(".fuigo");
    // SAFETY: umask only; this is the child process and nothing else runs in it.
    unsafe { libc::umask(0o002) };
    fuigo_dirs::ensure_private_home(&home).unwrap();
    assert_eq!(fs::metadata(&home).unwrap().permissions().mode() & 0o7777, 0o700);
    drop(CheckedDir::create_or_open(&home).expect("the inbox accepts a home made under umask 002"));
}

/// A home that already exists (775, made by an older version) is never modified; the reason names the fix and the path.
#[test]
fn existing_group_writable_home_is_not_modified_and_reason_names_chmod() {
    let td = tempfile::tempdir().unwrap();
    let home = td.path().join(".fuigo");
    mkdir(&home, 0o775);
    fuigo_dirs::ensure_private_home(&home).unwrap();
    assert_eq!(fs::metadata(&home).unwrap().permissions().mode() & 0o7777, 0o775);
    let e = CheckedDir::open(&home).unwrap_err();
    assert_eq!(e, Disabled::HomeWritableByOthers);
    let text = super::host::reason_message_for(e, Some(&home));
    assert_eq!(
        text,
        format!(
            "peer messaging is unavailable: the Fuigo home is not private to this user (run: chmod go-w {})",
            home.display()
        )
    );
    // Without a known path the fixed text is used.
    assert_eq!(super::host::reason_message_for(e, None), e.reason_text());
}

/// A home that cannot be pasted into a shell word unquoted gets no command, only the escaped path on one line.
#[test]
fn reason_message_prints_a_command_only_for_a_shell_safe_path() {
    let e = Disabled::HomeWritableByOthers;
    let plain = "peer messaging is unavailable: the Fuigo home is not private to this user (run: chmod go-w ";
    let none = "peer messaging is unavailable: remove write access for group and others from the Fuigo home: ";
    for ok in ["/home/u/.fuigo", "/tmp/a_b-c.d/~x+y@z:1", "rel/path"] {
        let m = super::host::reason_message_for(e, Some(Path::new(ok)));
        assert_eq!(m, format!("{plain}{ok})"));
    }
    for bad in ["/tmp/a b", "/tmp/a;b", "/tmp/$(x)", "/tmp/`x`", "/tmp/it's", "/tmp/a\nb", "-rf", "/tmp/a\"b", "/tmp/a*", "/tmp/\u{e9}"] {
        let m = super::host::reason_message_for(e, Some(Path::new(bad)));
        assert!(m.starts_with(none), "{bad:?}: {m}");
        assert!(!m.contains("chmod"), "{bad:?}: {m}");
        // The path is shown as text only (no command to paste), on one line.
        assert!(!m.contains('\n'), "{bad:?}: {m}");
    }
    // Empty path: generic text.
    assert_eq!(super::host::reason_message_for(e, Some(Path::new(""))), e.reason_text());
}
