//! P79: two paths naming one state file always meet on one lock (the identity
//! of `identity`): the name lock, also on a case-insensitive volume, through
//! links, and when the file does not exist yet; and the inode lock, for every
//! other way two names can be one file (hard links above all). An identity
//! that cannot be established is refused, not guessed.
//!
//! The case rules are tested two ways: with an INJECTED probe (any host can
//! play a case-insensitive volume, so Linux CI covers the APFS rules), and
//! on the REAL filesystem when the test directory is case-insensitive (NTFS,
//! APFS) or `FUIGO_P79_CI_DIR` names a directory on one (a vfat loop mount on
//! Linux). A case-sensitive directory makes the real-filesystem test a no-op
//! and says so on stderr.
//!
//! "This writer waits" is never tested with a sleep: the test waits until
//! that very thread is in a lock's queue (`thread_is_queued_for_a_lock`), and
//! fails if it finishes instead.

use super::*;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn id_with(path: &Path, insensitive: bool) -> identity::Identity {
    identity::identity_with(path, &|_| Ok(insensitive)).unwrap()
}

/// The name part of [`id_with`] (what the case rules are about).
fn name_with(path: &Path, insensitive: bool) -> Vec<u8> {
    id_with(path, insensitive).name
}

/// The inode part of the real identity of `path`.
fn inode_of(path: &Path) -> Option<Vec<u8>> {
    identity::identity(path).unwrap().inode
}

/// Block until `thread` is queued for a lock; fail if `finished` says it got
/// through instead, or if it never queues.
fn wait_until_queued(thread: &std::thread::Thread, finished: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !thread_is_queued_for_a_lock(thread.id()) {
        assert!(!finished(), "the writer got through instead of waiting");
        assert!(Instant::now() < deadline, "the writer never queued");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(!finished(), "the writer got through instead of waiting");
}

/// A thread that takes `path`'s state lock, says so, and holds it until told.
struct Writer {
    got: std::sync::mpsc::Receiver<()>,
    release: std::sync::mpsc::Sender<()>,
    thread: std::thread::JoinHandle<()>,
}

impl Writer {
    fn start(path: &Path) -> Self {
        let (got_tx, got) = std::sync::mpsc::channel();
        let (release, release_rx) = std::sync::mpsc::channel::<()>();
        let path = path.to_path_buf();
        let thread = std::thread::spawn(move || {
            let lock = lock_state_file(&path).unwrap();
            got_tx.send(()).unwrap();
            let _ = release_rx.recv();
            drop(lock);
        });
        Self {
            got,
            release,
            thread,
        }
    }

    /// Block until this writer is queued for a lock (it must not get one).
    fn wait_until_queued(&self) {
        wait_until_queued(self.thread.thread(), || self.got.try_recv().is_ok());
    }

    fn wait_for_the_lock(&self) {
        self.got
            .recv_timeout(Duration::from_secs(20))
            .expect("the queued writer is served once the holder is done");
    }

    fn finish(self) {
        let _ = self.release.send(());
        self.thread.join().unwrap();
    }
}

/// `lock` is held by somebody: taking it gives up.
fn assert_held(lock: &Path, what: &str) {
    let err = lock_at_within(lock, Duration::from_millis(300)).expect_err(what);
    assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{what}");
}

/// The directory the real-filesystem tests work in: under `FUIGO_P79_CI_DIR`
/// when set (a case-insensitive volume on a host whose own is sensitive),
/// else in the test's temp directory. Removed on drop.
fn real_fs_dir(tmp_dir: &Path, what: &str) -> (RemoveOnDrop, PathBuf) {
    let dir = match std::env::var_os("FUIGO_P79_CI_DIR") {
        Some(d) => PathBuf::from(d).join(format!("p79-{what}-{}", std::process::id())),
        None => tmp_dir.join(what),
    };
    std::fs::create_dir_all(&dir).unwrap();
    let dir = dunce::canonicalize(&dir).unwrap();
    (RemoveOnDrop(dir.clone()), dir)
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// Append `line` to the state file at `path` (missing = empty) through the
/// shared read-modify-write, the replacement staged for the spelling given.
fn append_through(path: &Path, line: &str) -> Result<(), EditError<io::Error>> {
    edit_state_file(
        path,
        |bytes| stage_atomically(path, bytes, None),
        |current| {
            let mut contents = match current {
                Ok(bytes) => bytes.unwrap_or_default().to_vec(),
                Err(e) => return Err(io::Error::new(e.kind(), e.to_string())),
            };
            contents.extend_from_slice(line.as_bytes());
            Ok(Edit::Replace {
                contents,
                value: (),
            })
        },
    )
}

/// A real directory to write in, canonical (a symlinked temp root would blur
/// what is being tested).
fn real_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let dir = dunce::canonicalize(tmp.path()).unwrap();
    (tmp, dir)
}

#[test]
fn case_differing_spellings_share_a_lock_when_the_volume_is_insensitive() {
    let (_tmp, dir) = real_dir();
    // Neither exists, one exists, both spellings.
    let (a, b) = (dir.join("Agent.toml"), dir.join("agent.toml"));
    assert_eq!(name_with(&a, true), name_with(&b, true), "missing file");
    std::fs::write(&a, "x").unwrap();
    assert_eq!(name_with(&a, true), name_with(&b, true), "existing file");
    assert_eq!(
        name_with(&a, true),
        name_with(&dir.join("AGENT.TOML"), true)
    );
    // ...and the lock FILE is the same.
    assert_eq!(
        name_lock_path(&name_with(&a, true)),
        name_lock_path(&name_with(&b, true))
    );
    // Other names stay other.
    assert_ne!(
        name_with(&a, true),
        name_with(&dir.join("agent2.toml"), true)
    );
    assert_ne!(
        name_with(&a, true),
        name_with(&dir.join("sub").join("agent.toml"), true)
    );
}

#[test]
fn case_differing_spellings_stay_apart_when_the_volume_is_sensitive() {
    let (_tmp, dir) = real_dir();
    assert_ne!(
        name_with(&dir.join("Agent.toml"), false),
        name_with(&dir.join("agent.toml"), false)
    );
}

#[test]
fn a_missing_directory_in_another_case_folds_with_the_file_name() {
    let (_tmp, dir) = real_dir();
    let a = dir.join("Personas").join("Agent.toml");
    let b = dir.join("personas").join("agent.toml");
    assert_eq!(name_with(&a, true), name_with(&b, true));
    assert_ne!(name_with(&a, false), name_with(&b, false));
    // Creating the directory does not move the name.
    let before = name_with(&a, true);
    std::fs::create_dir(dir.join("Personas")).unwrap();
    assert_eq!(name_with(&a, true), before);
    std::fs::write(&a, "x").unwrap();
    assert_eq!(name_with(&a, true), before);
}

#[cfg(unix)]
#[test]
fn symlinks_in_another_case_resolve_to_one_lock() {
    let (_tmp, dir) = real_dir();
    let real = dir.join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::write(real.join("Agent.toml"), "x").unwrap();
    // a final link named in one case pointing at the file spelled in another
    std::os::unix::fs::symlink("agent.toml", real.join("Link")).unwrap();
    // a linked directory
    std::os::unix::fs::symlink(&real, dir.join("DirLink")).unwrap();
    let want = name_with(&real.join("Agent.toml"), true);
    assert_eq!(name_with(&real.join("Link"), true), want);
    assert_eq!(
        name_with(&dir.join("DirLink").join("Agent.toml"), true),
        want
    );
    assert_eq!(name_with(&dir.join("DirLink").join("Link"), true), want);
    // a link chain through a dangling name
    std::os::unix::fs::symlink(real.join("New.toml"), dir.join("dangling")).unwrap();
    assert_eq!(
        name_with(&dir.join("dangling"), true),
        name_with(&real.join("new.toml"), true)
    );
}

/// Once the path is back on what exists (`..` out of a missing directory),
/// it is resolved again: a link after it is followed, as the kernel will
/// follow it once the missing directory has been created.
#[cfg(unix)]
#[test]
fn a_link_after_dot_dot_out_of_a_missing_directory_is_followed() {
    let (_tmp, dir) = real_dir();
    let real = dir.join("real");
    std::fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, dir.join("link")).unwrap();
    let through = dir
        .join("missing")
        .join("..")
        .join("link")
        .join("state.json");
    for insensitive in [false, true] {
        assert_eq!(
            name_with(&through, insensitive),
            name_with(&real.join("state.json"), insensitive)
        );
    }
    // ...and creating the missing directory does not move it.
    let before = name_with(&through, false);
    std::fs::create_dir(dir.join("missing")).unwrap();
    assert_eq!(name_with(&through, false), before);
    // A FINAL link after it is followed too (the kernel cannot see it while
    // the directory is missing; the writers will write through it once it is
    // there), also a relative one, also a dangling one.
    std::fs::write(real.join("target.json"), "x").unwrap();
    std::os::unix::fs::symlink(real.join("target.json"), dir.join("final")).unwrap();
    std::os::unix::fs::symlink("real/target.json", dir.join("final-rel")).unwrap();
    std::os::unix::fs::symlink("real/not-yet.json", dir.join("final-dangling")).unwrap();
    for (link, target) in [
        ("final", "target.json"),
        ("final-rel", "target.json"),
        ("final-dangling", "not-yet.json"),
    ] {
        let through = dir.join("gone").join("..").join(link);
        let id = id_with(&through, false);
        assert_eq!(id, id_with(&real.join(target), false), "{link}");
        assert_eq!(id, id_with(&dir.join(link), false), "{link}");
    }
    // Two levels down and back up, then into a missing directory again.
    let deep = dir
        .join("m1")
        .join("m2")
        .join("..")
        .join("..")
        .join("link")
        .join("new")
        .join("state.json");
    assert_eq!(
        name_with(&deep, false),
        name_with(&real.join("new").join("state.json"), false)
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_loop_is_refused_and_forty_links_are_followed() {
    let (_tmp, dir) = real_dir();
    std::os::unix::fs::symlink("b", dir.join("a")).unwrap();
    std::os::unix::fs::symlink("a", dir.join("b")).unwrap();
    assert!(identity::identity_with(&dir.join("a"), &|_| Ok(false)).is_err());
    // A chain of exactly 40 links ends at the file (what `write_through`
    // follows); 41 is refused.
    std::fs::write(dir.join("l0"), "x").unwrap();
    for i in 1..=41 {
        std::os::unix::fs::symlink(format!("l{}", i - 1), dir.join(format!("l{i}"))).unwrap();
    }
    assert_eq!(
        name_with(&dir.join("l40"), false),
        name_with(&dir.join("l0"), false)
    );
    assert!(identity::identity_with(&dir.join("l41"), &|_| Ok(false)).is_err());
}

/// Where nothing is folded, the name lock is the lock file P72 used, so a
/// P72 process and this one exclude each other. (For a path with a plain
/// spelling, as here; a Windows path that only the verbatim form can name
/// keeps its prefix in P79's name and not in P72's. Not tested: no such path
/// can be made on the hosts this runs on.)
#[test]
fn an_unfolded_name_is_the_lock_file_of_p72() {
    let (_tmp, dir) = real_dir();
    let path = dir.join("sub").join("state.json");
    let p72 = lock_path_in(&state_locks_dir(), "state", &path);
    assert_eq!(name_lock_path(&name_with(&path, false)), p72);
    // Also on a case-insensitive volume, for a path that is its own fold.
    // (Byte for byte: `Path` equality does not tell `c:` from `C:`, and a
    // temp directory whose random name has no capital letter would pass for
    // its own fold on Windows.)
    if identity::fold(&path).as_os_str() == path.as_os_str() {
        assert_eq!(name_lock_path(&name_with(&path, true)), p72);
    }
}

#[test]
fn hard_links_share_one_inode_lock_whatever_their_names() {
    let (_tmp, dir) = real_dir();
    let (a, b) = (dir.join("Agent.toml"), dir.join("other-name.toml"));
    // A missing file has a name and nothing else.
    assert_eq!(id_with(&a, false).inode, None);
    std::fs::write(&a, "x").unwrap();
    std::fs::hard_link(&a, &b).unwrap();
    for insensitive in [false, true] {
        let (ia, ib) = (id_with(&a, insensitive), id_with(&b, insensitive));
        assert!(ia.inode.is_some());
        assert_eq!(ia.inode, ib.inode);
        // ...while each keeps its own name lock.
        assert_ne!(ia.name, ib.name);
    }
    // another directory too
    std::fs::create_dir(dir.join("elsewhere")).unwrap();
    let c = dir.join("elsewhere").join("c.toml");
    std::fs::hard_link(&a, &c).unwrap();
    assert_eq!(id_with(&a, false).inode, id_with(&c, false).inode);
    // and not with a stranger
    std::fs::write(dir.join("stranger.toml"), "x").unwrap();
    assert_ne!(
        id_with(&a, false).inode,
        id_with(&dir.join("stranger.toml"), false).inode
    );
    // A directory at the name is not a file to lock by inode.
    assert_eq!(id_with(&dir.join("elsewhere"), false).inode, None);
    // The lock really excludes: a writer on one name makes the other wait.
    let held = lock_state_file(&a).unwrap();
    // A writer through another hard link must wait.
    let other = Writer::start(&c);
    other.wait_until_queued();
    drop(held);
    other.wait_for_the_lock();
    other.finish();
}

/// A hard link can appear under a writer (an outsider's `ln`, a hard-link
/// snapshot). The writer that took the file's lock before it must still
/// exclude one that arrives after it, by the old name AND by the new one.
#[test]
fn a_holder_from_before_a_hard_link_excludes_writers_by_either_name() {
    let (_tmp, dir) = real_dir();
    let (a, b) = (dir.join("a.toml"), dir.join("snapshot-of-a.toml"));
    std::fs::write(&a, "x").unwrap();
    let held = lock_state_file(&a).unwrap();
    std::fs::hard_link(&a, &b).unwrap();
    assert_eq!(inode_of(&a), inode_of(&b));
    let by_new_name = Writer::start(&b);
    by_new_name.wait_until_queued();
    let by_old_name = Writer::start(&a);
    by_old_name.wait_until_queued();
    by_new_name.wait_until_queued();
    drop(held);
    // One after the other: they share the inode lock.
    by_new_name.wait_for_the_lock();
    by_new_name.finish();
    by_old_name.wait_for_the_lock();
    by_old_name.finish();
}

/// A missing file has no inode: its name lock alone must exclude.
#[test]
fn a_missing_file_is_locked_by_its_name() {
    let (_tmp, dir) = real_dir();
    let path = dir.join("new").join("state.json");
    assert_eq!(inode_of(&path), None);
    let held = lock_state_file(&path).unwrap();
    let other = Writer::start(&dir.join("new").join(".").join("state.json"));
    other.wait_until_queued();
    drop(held);
    other.wait_for_the_lock();
    other.finish();
}

/// The inode at a name can change while a writer is queued on its lock (here
/// an outsider renames another file over the name). The writer must end up
/// holding the lock of the inode the name has NOW, not the old one's.
#[test]
fn a_writer_queued_on_an_inode_lock_moves_to_the_inode_the_name_has_now() {
    let (_tmp, dir) = real_dir();
    let (a, b) = (dir.join("a.toml"), dir.join("b.toml"));
    std::fs::write(&a, "x").unwrap();
    std::fs::hard_link(&a, &b).unwrap();
    let old = inode_lock_path(&inode_of(&a).unwrap());
    let held = lock_state_file(&a).unwrap();
    let queued = Writer::start(&b);
    // It has b's name lock and waits for the inode lock the holder has.
    queued.wait_until_queued();
    let tmp = dir.join("b.toml.new");
    std::fs::write(&tmp, "y").unwrap();
    std::fs::rename(&tmp, &b).unwrap();
    let new = inode_lock_path(&inode_of(&b).unwrap());
    drop(held);
    queued.wait_for_the_lock();
    assert_held(&state_lock_path(&b).unwrap(), "b's name lock is held");
    if new == old {
        eprintln!("P79_STRIPES_COLLIDED: old and new inode share a stripe; not told apart");
    } else {
        assert_held(&new, "the lock of b's inode now is held");
        // (Long enough for another test's writer on the same stripe to be
        // done; the queued writer holds what it has until `finish`.)
        drop(
            lock_at_within(&old, Duration::from_secs(20))
                .expect("the lock of the inode b no longer has must have been let go"),
        );
    }
    queued.finish();
}

/// The name of a file reached through a symlink moves when the link is
/// re-pointed. A writer queued on the old target's lock must end up holding
/// the new target's, and not the old one's.
#[cfg(unix)]
#[test]
fn a_writer_queued_through_a_link_follows_it_when_it_is_repointed() {
    let (_tmp, dir) = real_dir();
    let (a, b, link) = (
        dir.join("a.toml"),
        dir.join("b.toml"),
        dir.join("link.toml"),
    );
    std::fs::write(&a, "a").unwrap();
    std::fs::write(&b, "b").unwrap();
    std::os::unix::fs::symlink(&a, &link).unwrap();
    let (lock_a, lock_b) = (state_lock_path(&a).unwrap(), state_lock_path(&b).unwrap());
    assert_eq!(state_lock_path(&link).unwrap(), lock_a);
    let held = lock_state_file(&a).unwrap();
    let queued = Writer::start(&link);
    queued.wait_until_queued();
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&b, &link).unwrap();
    drop(held);
    queued.wait_for_the_lock();
    assert_held(&lock_b, "b's lock is held");
    drop(lock_at_within(&lock_a, Duration::from_secs(20)).expect("a's lock must have been let go"));
    queued.finish();
}

/// The shared read-modify-write takes the inode lock too: an edit through
/// one hard link waits for a writer holding the file through another (the
/// in-place append of the prompt history is such a writer).
#[test]
fn an_edit_through_one_hard_link_waits_for_a_holder_on_another() {
    let (_tmp, dir) = real_dir();
    let (a, b) = (dir.join("a.jsonl"), dir.join("b.jsonl"));
    std::fs::write(&a, "1\n").unwrap();
    std::fs::hard_link(&a, &b).unwrap();
    let held = lock_state_file(&a).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let editor = {
        let b = b.clone();
        std::thread::spawn(move || {
            edit_state_file(
                &b,
                |bytes| stage_atomically(&b, bytes, None),
                |current| {
                    let mut contents = match current {
                        Ok(bytes) => bytes.unwrap_or_default().to_vec(),
                        Err(e) => return Err(std::io::Error::new(e.kind(), e.to_string())),
                    };
                    contents.extend_from_slice(b"edited\n");
                    Ok::<_, std::io::Error>(Edit::Replace {
                        contents,
                        value: (),
                    })
                },
            )
            .unwrap();
            tx.send(()).unwrap();
        })
    };
    // The edit must not commit while the file is held through its other name.
    wait_until_queued(editor.thread(), || rx.try_recv().is_ok());
    // The holder appends in place (to the inode both names still share).
    {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new().append(true).open(&a).unwrap();
        f.write_all(b"2\n").unwrap();
    }
    drop(held);
    rx.recv_timeout(Duration::from_secs(20))
        .expect("the edit goes through once released");
    editor.join().unwrap();
    assert_eq!(std::fs::read_to_string(&b).unwrap(), "1\n2\nedited\n");
}

/// A lock is granted for what the path named then. If an outsider re-points
/// a link on the path while the edit runs under the lock, the edit must not
/// write what it read from one file over another the lock does not cover.
#[cfg(unix)]
#[test]
fn an_edit_whose_path_was_repointed_under_the_lock_writes_nothing() {
    let (_tmp, dir) = real_dir();
    let (a, b, link) = (
        dir.join("a.toml"),
        dir.join("b.toml"),
        dir.join("link.toml"),
    );
    std::fs::write(&a, "a").unwrap();
    std::fs::write(&b, "b").unwrap();
    std::os::unix::fs::symlink(&a, &link).unwrap();
    let ran = std::cell::Cell::new(0u32);
    let result = edit_state_file(
        &link,
        |bytes| stage_atomically(&dunce::canonicalize(&link).unwrap(), bytes, None),
        |current| {
            // Under the lock (a path through a link has no optimistic pass).
            ran.set(ran.get() + 1);
            let mut contents = current.unwrap().unwrap().to_vec();
            std::fs::remove_file(&link).unwrap();
            std::os::unix::fs::symlink(&b, &link).unwrap();
            contents.extend_from_slice(b"+edit");
            Ok::<_, std::io::Error>(Edit::Replace {
                contents,
                value: (),
            })
        },
    );
    assert_eq!(ran.get(), 1);
    assert!(
        matches!(result, Err(EditError::Lock(_))),
        "{:?}",
        result.map_err(|e| e.to_string())
    );
    assert_eq!(std::fs::read_to_string(&a).unwrap(), "a");
    assert_eq!(std::fs::read_to_string(&b).unwrap(), "b");
    assert_eq!(names_in(&dir), ["a.toml", "b.toml", "link.toml"]);

    // Re-pointed and put BACK: the replacement was staged for the other
    // file while the path names the locked one again. Still refused.
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&a, &link).unwrap();
    let result = edit_state_file(
        &link,
        |bytes| {
            std::fs::remove_file(&link).unwrap();
            std::os::unix::fs::symlink(&b, &link).unwrap();
            let staged = stage_atomically(&dunce::canonicalize(&link).unwrap(), bytes, None);
            std::fs::remove_file(&link).unwrap();
            std::os::unix::fs::symlink(&a, &link).unwrap();
            staged
        },
        |current| {
            let mut contents = current.unwrap().unwrap().to_vec();
            contents.extend_from_slice(b"+edit");
            Ok::<_, std::io::Error>(Edit::Replace {
                contents,
                value: (),
            })
        },
    );
    assert!(
        matches!(result, Err(EditError::Lock(_))),
        "{:?}",
        result.map_err(|e| e.to_string())
    );
    assert_eq!(std::fs::read_to_string(&a).unwrap(), "a");
    assert_eq!(std::fs::read_to_string(&b).unwrap(), "b");
    assert_eq!(names_in(&dir), ["a.toml", "b.toml", "link.toml"]);
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&b, &link).unwrap();
    // Left alone, the same edit goes through (to what the link names now).
    edit_state_file(
        &link,
        |bytes| stage_atomically(&dunce::canonicalize(&link).unwrap(), bytes, None),
        |current| {
            let mut contents = current.unwrap().unwrap().to_vec();
            contents.extend_from_slice(b"+edit");
            Ok::<_, std::io::Error>(Edit::Replace {
                contents,
                value: (),
            })
        },
    )
    .unwrap();
    assert_eq!(std::fs::read_to_string(&b).unwrap(), "b+edit");
}

/// What taking the state lock costs (no assertion: a figure for the receipt).
#[test]
fn the_cost_of_a_state_lock() {
    let (_tmp, dir) = real_dir();
    for i in 0..40 {
        std::fs::write(dir.join(format!("other-{i}.json")), "x").unwrap();
    }
    let path = dir.join("state.json");
    std::fs::write(&path, "x").unwrap();
    const TAKES: u32 = 200;
    let started = Instant::now();
    for _ in 0..TAKES {
        drop(lock_state_file(&path).unwrap());
    }
    let state = started.elapsed() / TAKES;
    let plain = state_lock_path(&path).unwrap();
    let started = Instant::now();
    for _ in 0..TAKES {
        drop(lock_file_for_write(&plain).unwrap());
    }
    let one = started.elapsed() / TAKES;
    let started = Instant::now();
    for _ in 0..TAKES {
        identity::identity(&path).unwrap();
    }
    let identity = started.elapsed() / TAKES;
    eprintln!(
        "P79_COST: state lock {state:?} per take (one plain lock {one:?}, one identity {identity:?}) \
         in a directory of 41 entries"
    );
}

#[test]
fn an_identity_that_cannot_be_established_is_an_error() {
    let (_tmp, dir) = real_dir();
    let denied = |_: &Path| -> io::Result<bool> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "no"))
    };
    // A directory that cannot be asked about case, and a file to CREATE in it.
    let failing = identity::identity_with(&dir.join("f.toml"), &denied);
    assert_eq!(failing.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    // ...while a file that EXISTS there is named as spelled and locked by
    // inode (its writers can only write in place, and meet on that lock).
    let existing = dir.join("Existing.toml");
    std::fs::write(&existing, "x").unwrap();
    let id = identity::identity_with(&existing, &denied).unwrap();
    assert_eq!(id.name, existing.as_os_str().as_encoded_bytes());
    assert!(id.inode.is_some());
    // Any other probe failure is an error whether or not the file exists.
    let broken = identity::identity_with(&existing, &|_| Err(io::Error::other("broken")));
    assert!(broken.is_err());
    // a directory part that is a file
    std::fs::write(dir.join("file"), "x").unwrap();
    assert!(identity::identity_with(&dir.join("file").join("f.toml"), &|_| Ok(false)).is_err());
    // and the lock functions pass it on
    assert!(state_lock_path(&dir.join("file").join("f.toml")).is_err());
    assert!(lock_state_file(&dir.join("file").join("f.toml")).is_err());
    // ...also with "missing directories" below the file. (Windows reports a
    // path through a regular file as not found, as it does a missing one:
    // the identity must not take the file for a directory to be created.)
    let below = dir.join("file").join("missing").join("f.toml");
    assert!(identity::identity_with(&below, &|_| Ok(false)).is_err());
    assert!(identity::identity_with(&below, &|_| Ok(true)).is_err());
    assert!(state_lock_path(&below).is_err());
    assert!(lock_state_file(&below).is_err());
    // `..` out of a file is refused as the kernel refuses it (the lexical
    // step would hide it; Windows makes such a path absolute before it is
    // looked at, and opens it).
    #[cfg(unix)]
    {
        let out_of_a_file = dir.join("file").join("..").join("f.toml");
        assert!(std::fs::symlink_metadata(&out_of_a_file).is_err());
        assert!(identity::identity_with(&out_of_a_file, &|_| Ok(false)).is_err());
        assert!(lock_state_file(&out_of_a_file).is_err());
        // ...while `..` out of a directory, existing or not, is fine.
        std::fs::create_dir(dir.join("sub")).unwrap();
        for through in ["sub", "missing"] {
            assert_eq!(
                id_with(&dir.join(through).join("..").join("f.toml"), false),
                id_with(&dir.join("f.toml"), false),
                "{through}"
            );
        }
    }
    // A refused path does not get as far as the lock directory (in
    // production: the fuigo home, which asking for creates).
    let asked = std::cell::Cell::new(false);
    let refused = take_state_lock_in(&below, Duration::from_secs(1), &|| {
        asked.set(true);
        dir.join("locks")
    });
    assert!(refused.is_err() && !asked.get());
    assert!(!dir.join("locks").exists());
    // An edit there is refused before anything is read or staged.
    let refused = append_through(&dir.join("file").join("f.toml"), "x\n");
    assert!(matches!(refused, Err(EditError::Lock(_))), "{refused:?}");
    assert_eq!(std::fs::read_to_string(dir.join("file")).unwrap(), "x");
}

/// The real thing, where the test is not root: an existing file in a
/// directory that may be neither listed nor written in is still locked (it
/// could be appended to before P79); a directory that may be written in but
/// not listed is probed with a file.
#[cfg(unix)]
#[test]
fn directories_that_cannot_be_listed_still_lock() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_tmp, dir) = real_dir();
    // SAFETY: no arguments, no failure mode.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("P79_PERMS_SKIPPED: running as root, permissions do not bind");
        return;
    }
    let set = |p: &Path, mode: u32| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    // search only
    let closed = dir.join("Closed");
    std::fs::create_dir(&closed).unwrap();
    std::fs::write(closed.join("history.jsonl"), "1\n").unwrap();
    set(&closed, 0o100);
    let existing = lock_state_file(&closed.join("history.jsonl"));
    let missing = lock_state_file(&closed.join("new.jsonl"));
    set(&closed, 0o700);
    drop(existing.expect("an existing file in an unlistable, unwritable directory locks"));
    assert_eq!(missing.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    // write + search, no listing: the probe file decides and is removed
    let dropbox = dir.join("Dropbox");
    std::fs::create_dir(&dropbox).unwrap();
    set(&dropbox, 0o300);
    let verdict = identity::dir_is_case_insensitive(&dropbox);
    let lock = lock_state_file(&dropbox.join("new.jsonl"));
    set(&dropbox, 0o700);
    assert_eq!(
        verdict.unwrap(),
        identity::dir_is_case_insensitive(&dir).unwrap()
    );
    drop(lock.expect("a writable, unlistable directory locks"));
    assert!(
        names_in(&dropbox).is_empty(),
        "the probe left {:?}",
        names_in(&dropbox)
    );
    eprintln!("P79_PERMS_RAN");
}

/// The probe agrees with what the filesystem does when two names that differ
/// only in case are created.
#[test]
fn the_probe_matches_what_the_filesystem_does() {
    let (_tmp, tmp_dir) = real_dir();
    let (_cleanup, dir) = real_fs_dir(&tmp_dir, "probe");
    // Empty directory: a probe file is made and removed.
    let verdict = identity::dir_is_case_insensitive(&dir).unwrap();
    assert!(
        names_in(&dir).is_empty(),
        "the probe left {:?}",
        names_in(&dir)
    );
    eprintln!("P79_PROBE: {} insensitive={verdict}", dir.display());
    std::fs::write(dir.join("Foo"), "1").unwrap();
    let second = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dir.join("foo"));
    assert_eq!(
        verdict,
        second.is_err(),
        "probe says insensitive={verdict}, creating `foo` beside `Foo` {}",
        if second.is_ok() {
            "worked (sensitive)"
        } else {
            "collided (insensitive)"
        }
    );
    // With entries in the directory it still agrees (and leaves nothing).
    assert_eq!(identity::dir_is_case_insensitive(&dir).unwrap(), verdict);
    assert_eq!(names_in(&dir).len(), if verdict { 1 } else { 2 });
    // Entries without an ASCII letter say nothing; the probe file decides.
    let digits = dir.join("digits");
    std::fs::create_dir(&digits).unwrap();
    std::fs::write(digits.join("1234"), "1").unwrap();
    assert_eq!(identity::dir_is_case_insensitive(&digits).unwrap(), verdict);
    assert_eq!(names_in(&digits), ["1234"]);
    // Only ASCII letters are swapped: an entry with a letter whose other
    // case is a matter of the volume's table (sharp s: `SS`? itself?) must
    // not read as "sensitive" because the volume spells it another way.
    let sharp = dir.join("sharp");
    std::fs::create_dir(&sharp).unwrap();
    if std::fs::write(sharp.join("stra\u{df}e.toml"), "1").is_ok() {
        assert_eq!(identity::dir_is_case_insensitive(&sharp).unwrap(), verdict);
        assert_eq!(names_in(&sharp).len(), 1);
    }
}

/// Two hard links of one file whose names differ only in case (possible only
/// on a case-sensitive volume) must not read as "insensitive".
#[test]
fn hard_links_differing_only_in_case_do_not_fool_the_probe() {
    let (_tmp, dir) = real_dir();
    std::fs::write(dir.join("FOO"), "1").unwrap();
    if std::fs::hard_link(dir.join("FOO"), dir.join("foo")).is_err() {
        eprintln!(
            "P79_CASE_LINKS_SKIPPED: {} is case-insensitive",
            dir.display()
        );
        return;
    }
    // Each is the other's swapped spelling: neither entry can say anything...
    assert_eq!(
        identity::verdict_of(&dir.join("FOO"), &dir.join("foo")).unwrap(),
        None
    );
    assert_eq!(
        identity::verdict_of(&dir.join("foo"), &dir.join("FOO")).unwrap(),
        None
    );
    // ...a spelling that is not there can...
    assert_eq!(
        identity::verdict_of(&dir.join("FOO"), &dir.join("Foo")).unwrap(),
        Some(false)
    );
    // ...and the directory's verdict comes from the probe file.
    assert!(!identity::dir_is_case_insensitive(&dir).unwrap());
    assert_eq!(names_in(&dir), ["FOO", "foo"]);
}

/// A probe racing a writer: the entry it is asking about is replaced by
/// rename, or removed, between its two looks. On a case-insensitive volume
/// the other-case spelling then is "another file" or "missing", which must
/// not be read as "sensitive" (the lock would split). Such an entry says
/// nothing; one left alone still answers.
#[test]
fn an_entry_that_changed_under_the_probe_says_nothing() {
    let (_tmp, tmp_dir) = real_dir();
    let (_cleanup, dir) = real_fs_dir(&tmp_dir, "race");
    let insensitive = identity::dir_is_case_insensitive(&dir).unwrap();
    let (entry, alt) = (dir.join("State.toml"), dir.join("STATE.TOML"));
    std::fs::write(&entry, "1").unwrap();
    assert_eq!(
        identity::verdict_of(&entry, &alt).unwrap(),
        Some(insensitive)
    );

    // Replaced by rename mid-probe (what every writer here does).
    let ran = std::rc::Rc::new(std::cell::Cell::new(0u32));
    {
        let (ran, entry, new) = (ran.clone(), entry.clone(), dir.join("staged.tmp"));
        identity::probe_seam::set(Some(Box::new(move || {
            ran.set(ran.get() + 1);
            std::fs::write(&new, "2").unwrap();
            std::fs::rename(&new, &entry).unwrap();
        })));
    }
    let replaced = identity::verdict_of(&entry, &alt);
    identity::probe_seam::set(None);
    assert_eq!(ran.get(), 1);
    assert_eq!(replaced.unwrap(), None, "a replaced entry must say nothing");

    // Removed mid-probe (a temp that was committed or cleaned up).
    {
        let entry = entry.clone();
        identity::probe_seam::set(Some(Box::new(move || {
            let _ = std::fs::remove_file(&entry);
        })));
    }
    let removed = identity::verdict_of(&entry, &alt);
    identity::probe_seam::set(None);
    assert_eq!(removed.unwrap(), None, "a removed entry must say nothing");

    // And the directory's verdict survives a racing replace of its only
    // entry: the probe falls back to its own file.
    std::fs::write(&entry, "3").unwrap();
    {
        let (entry, new) = (entry.clone(), dir.join("staged.tmp"));
        identity::probe_seam::set(Some(Box::new(move || {
            std::fs::write(&new, "4").unwrap();
            std::fs::rename(&new, &entry).unwrap();
        })));
    }
    let verdict = identity::dir_is_case_insensitive(&dir);
    identity::probe_seam::set(None);
    assert_eq!(verdict.unwrap(), insensitive);
    assert_eq!(names_in(&dir), ["State.toml"]);
}

/// The probe's own file is looked at twice as well: if somebody replaces it
/// mid-probe there is no answer, and that is an error, not "sensitive".
#[test]
fn a_probe_file_that_was_interfered_with_is_an_error() {
    let (_tmp, tmp_dir) = real_dir();
    let (_cleanup, dir) = real_fs_dir(&tmp_dir, "tamper");
    {
        let dir = dir.clone();
        identity::probe_seam::set(Some(Box::new(move || {
            for name in names_in(&dir) {
                if name.starts_with(".Fuigo-Case-Probe-") {
                    let new = dir.join("intruder.tmp");
                    std::fs::write(&new, "x").unwrap();
                    std::fs::rename(&new, dir.join(name)).unwrap();
                }
            }
        })));
    }
    let verdict = identity::dir_is_case_insensitive(&dir);
    identity::probe_seam::set(None);
    assert!(verdict.is_err(), "{verdict:?}");
    assert!(names_in(&dir).is_empty(), "left {:?}", names_in(&dir));
}

/// The same race without a seam: probes while another thread keeps replacing
/// the file and staging temps beside it. Every probe gives the one verdict.
#[test]
fn the_probe_is_steady_while_writers_replace_the_file() {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    let (_tmp, tmp_dir) = real_dir();
    let (_cleanup, dir) = real_fs_dir(&tmp_dir, "steady");
    let verdict = identity::dir_is_case_insensitive(&dir).unwrap();
    let file = dir.join("Pager.toml");
    std::fs::write(&file, "0").unwrap();
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let replaces = std::sync::Arc::new(AtomicU32::new(0));
    let writer = {
        let (stop, replaces, dir, file) = (stop.clone(), replaces.clone(), dir.clone(), file);
        std::thread::spawn(move || {
            let mut n = 0u32;
            while !stop.load(Ordering::SeqCst) {
                n += 1;
                let tmp = dir.join(format!(".Pager.toml.Tmp{n}"));
                std::fs::write(&tmp, n.to_string()).unwrap();
                std::fs::rename(&tmp, &file).unwrap();
                replaces.store(n, Ordering::SeqCst);
            }
        })
    };
    // At least 400 probes, and until the writer has replaced the file 100
    // times alongside them.
    let deadline = Instant::now() + Duration::from_secs(60);
    let (mut probes, mut wrong) = (0u32, 0u32);
    while probes < 400 || replaces.load(Ordering::SeqCst) < 100 {
        assert!(Instant::now() < deadline, "the writer made no progress");
        probes += 1;
        if identity::dir_is_case_insensitive(&dir).unwrap() != verdict {
            wrong += 1;
        }
    }
    stop.store(true, Ordering::SeqCst);
    writer.join().unwrap();
    let replaced = replaces.load(Ordering::SeqCst);
    eprintln!(
        "P79_STEADY: insensitive={verdict} probes={probes} replaces={replaced} wrong={wrong}"
    );
    assert_eq!(wrong, 0, "of {probes} probes beside {replaced} replaces");
}

/// The fold is at least as coarse as full case folding, idempotent, and
/// leaves a path that is its own fold byte for byte.
#[test]
fn the_fold_joins_case_and_normalisation_variants() {
    let fold = |s: &str| identity::fold(Path::new(s));
    for (a, b) in [
        ("/x/Agent.TOML", "/X/agent.toml"),
        ("/x/STRASSE", "/x/stra\u{df}e"), // sharp s (full folding)
        ("/x/STRA\u{1e9e}E", "/x/stra\u{df}e"), // capital sharp s: two steps
        ("/x/\u{c5}ngstr\u{f6}m", "/x/A\u{30a}NGSTRO\u{308}M"), // NFC vs NFD, case
        ("/x/\u{212a}elvin", "/x/kelvin"), // Kelvin sign
        ("/x/\u{3a3}\u{3c2}", "/x/\u{3c3}\u{3c3}"), // final sigma
        ("/x/\u{17f}et", "/x/SET"),       // long s
        // Canonically equivalent, and only the decomposition BEFORE the case
        // mapping shows it (the iota subscript changes its combining class).
        ("/x/\u{1fb4}", "/x/\u{1fb3}\u{301}"),
    ] {
        assert_eq!(fold(a), fold(b), "{a:?} / {b:?}");
        assert_eq!(fold(a), identity::fold(&fold(a)), "idempotent on {a:?}");
    }
    assert_ne!(fold("/x/agent.toml"), fold("/x/agent2.toml"));
    // Byte for byte (the separator is the platform's, hence unix).
    #[cfg(unix)]
    assert_eq!(
        fold("/tmp/abc/d-1.toml").as_os_str(),
        "/tmp/abc/d-1.toml",
        "its own fold"
    );
}

/// One component that is not Unicode does not switch the Unicode fold off
/// for the others.
#[cfg(unix)]
#[test]
fn a_non_unicode_ancestor_does_not_stop_the_fold_of_the_name() {
    use std::os::unix::ffi::OsStrExt as _;
    let path = |bytes: &[u8]| PathBuf::from(std::ffi::OsStr::from_bytes(bytes));
    // `Ä.toml` / `ä.toml` under a directory named by the byte 0xFF
    assert_eq!(
        identity::fold(&path(b"/x/\xff/\xc3\x84.toml")),
        identity::fold(&path(b"/x/\xff/\xc3\xa4.toml"))
    );
    // the non-Unicode component itself folds its ASCII letters only
    assert_eq!(
        identity::fold(&path(b"/x/A\xff/f")),
        identity::fold(&path(b"/x/a\xff/f"))
    );
    assert_ne!(
        identity::fold(&path(b"/x/\xff/f")),
        identity::fold(&path(b"/x/\xfe/f"))
    );
}

/// On a case-insensitive directory (NTFS, APFS, or `FUIGO_P79_CI_DIR`), the
/// real filesystem: every spelling is one lock, through links and when the
/// file is missing.
#[test]
fn on_a_case_insensitive_directory_every_spelling_is_one_lock() {
    let (_tmp, tmp_dir) = real_dir();
    let (_cleanup, dir) = real_fs_dir(&tmp_dir, "ci");
    if !identity::dir_is_case_insensitive(&dir).unwrap() {
        // A case-sensitive directory: the two spellings are two files and
        // must not share a lock (the rest of this test does not apply).
        eprintln!("P79_CI_REAL_SKIPPED: {} is case-sensitive", dir.display());
        assert_ne!(
            state_lock_path(&dir.join("Agent.toml")).unwrap(),
            state_lock_path(&dir.join("agent.toml")).unwrap()
        );
        return;
    }
    eprintln!("P79_CI_REAL_RAN: {} is case-insensitive", dir.display());
    let lock = |p: &Path| state_lock_path(p).unwrap();
    // missing file, differing case
    assert_eq!(lock(&dir.join("Agent.toml")), lock(&dir.join("agent.toml")));
    assert_eq!(
        lock(&dir.join("Sub").join("Agent.toml")),
        lock(&dir.join("sub").join("AGENT.toml"))
    );
    // a missing file is locked by that one name
    let held = lock_state_file(&dir.join("Missing.toml")).unwrap();
    let other = Writer::start(&dir.join("MISSING.TOML"));
    other.wait_until_queued(); // the other spelling of a missing file waits
    drop(held);
    other.wait_for_the_lock();
    other.finish();
    // existing file
    std::fs::write(dir.join("Agent.toml"), "x").unwrap();
    assert_eq!(lock(&dir.join("Agent.toml")), lock(&dir.join("aGENT.toml")));
    assert_eq!(
        inode_of(&dir.join("Agent.toml")),
        inode_of(&dir.join("AGENT.TOML"))
    );
    // the lock really excludes: a writer on one spelling makes the other wait
    let held = lock_state_file(&dir.join("Agent.toml")).unwrap();
    let other = Writer::start(&dir.join("AGENT.TOML"));
    other.wait_until_queued(); // the other spelling waits
    drop(held);
    other.wait_for_the_lock();
    other.finish();
    // a hard link (where the volume has them: vfat does not)
    if std::fs::hard_link(dir.join("Agent.toml"), dir.join("Linked.toml")).is_ok() {
        assert_eq!(
            inode_of(&dir.join("agent.toml")),
            inode_of(&dir.join("LINKED.toml"))
        );
    }
    // a symlink (where the platform and the account let a test make one:
    // not vfat; on Windows only with the symlink privilege or developer mode)
    match symlink_file(&dir.join("agent.toml"), &dir.join("Sym.toml")) {
        Ok(()) => {
            // `Sym.toml` -> `agent.toml` -> the same file as `Agent.toml`
            assert_eq!(lock(&dir.join("sym.TOML")), lock(&dir.join("AGENT.toml")));
            eprintln!("P79_SYMLINK_RAN");
        }
        Err(e) => eprintln!("P79_SYMLINK_SKIPPED: cannot create a file symlink here: {e}"),
    }
    // other files stay other
    assert_ne!(
        lock(&dir.join("Agent.toml")),
        lock(&dir.join("Agent2.toml"))
    );
}

#[cfg(unix)]
fn symlink_file(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn symlink_file(target: &Path, link: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

struct RemoveOnDrop(PathBuf);
impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// The Windows round: what a native run on NTFS found, and what it asked for.
// ---------------------------------------------------------------------------

/// The state locks of this test binary are private to it: a test run must
/// create nothing in the home of whoever runs it. (A native Windows run of
/// these tests left a thousand lock files in the user's real `.fuigo\locks`:
/// there the home is the profile directory unless the harness redirects it.)
#[test]
fn the_state_locks_of_these_tests_are_not_in_the_users_home() {
    let (_tmp, dir) = real_dir();
    let file = dir.join("f.toml");
    std::fs::write(&file, "x").unwrap();
    let name_lock = state_lock_path(&file).unwrap();
    let inode_lock = inode_lock_path(&inode_of(&file).unwrap());
    drop(lock_state_file(&file).unwrap());
    for lock in [&name_lock, &inode_lock] {
        assert!(lock.exists(), "{} was taken", lock.display());
        assert_eq!(lock.parent().unwrap(), state_locks_dir());
        // (`resolve`, not `fuigo_home()`: that one creates the directory.)
        if let Some(home) = fuigo_dirs::resolve_fuigo_home() {
            assert!(
                !lock.starts_with(&home),
                "{} is in the fuigo home {}",
                lock.display(),
                home.display()
            );
        }
    }
}

/// Who is ahead of the holder on its inode stripe in
/// [`a_holder_moving_up_its_inode_stripe`].
#[derive(Clone, Copy)]
enum AheadOnTheStripe {
    /// Two threads of this process (the in-process turn queue).
    Threads,
    /// Two tickets in the stripe's cross-process queue, as two other
    /// processes hold them.
    Processes,
    /// A thread of this process, and behind it another process's ticket:
    /// the holder reaches its turn in this process and then queues again,
    /// across processes.
    ThreadThenProcess,
    /// Nobody in either queue: another process holds the stripe's `flock`
    /// without having queued (an older Fuigo), so the holder blocks in the
    /// kernel with no move to hand on until it is granted the lock.
    OutsideTheQueue,
}

/// Astra r2 MEDIUM 6. A writer holds its file's name lock while it queues
/// for the inode stripe, which other files share. The writers queued behind
/// it on the name lock must not give up while that stripe's queue MOVES, nor
/// count the holder's wait there against the time it may then hold the lock.
///
/// Two holders are ahead on the stripe. Give-up time `stall` = 4 s for the
/// writers behind; they queue at 0. At 2 s the first holder ahead leaves
/// (the stripe's queue moves); at 4.5 s the second (the holder gets the
/// stripe); the holder then keeps both locks for 2.5 s, until 7 s. Without
/// the hand-over the writers behind give up at 4 s (nothing moved on the
/// name lock); with the first move handed over but not the second, at 6 s.
///
/// [`AheadOnTheStripe::OutsideTheQueue`] has one holder ahead and no move:
/// it lets go at 3 s, and the holder keeps the locks until 5.5 s. Without
/// the grant handed over the writers behind give up at 4 s.
fn a_holder_moving_up_its_inode_stripe(ahead: AheadOnTheStripe) {
    let (_tmp, dir) = real_dir();
    let x = dir.join("x.toml");
    std::fs::write(&x, "x").unwrap();
    // A lock directory of this test's own: the stripe is kept busy for
    // seconds, and in the shared directory every other test's file has one
    // chance in 1024 of being on it (and would then wait here, and take
    // turns in this schedule).
    let locks = dir.join("locks");
    std::fs::create_dir_all(&locks).unwrap();
    let stripe = inode_lock_path_in(&locks, &inode_of(&x).unwrap());
    let stall = Duration::from_secs(4);
    let long = Duration::from_secs(60);
    // The two ahead; each `leave` lets one go.
    type Leave = Box<dyn FnOnce()>;
    let second_leaves_after = match ahead {
        AheadOnTheStripe::OutsideTheQueue => Duration::from_secs(1),
        _ => Duration::from_millis(2500),
    };
    let (first_leave, second_leave): (Leave, Leave) = match ahead {
        AheadOnTheStripe::Threads => {
            let first = lock_at_within(&stripe, long).unwrap();
            let (release, released) = std::sync::mpsc::channel::<()>();
            let second = {
                let stripe = stripe.clone();
                std::thread::spawn(move || {
                    let lock = lock_at_within(&stripe, long).unwrap();
                    let _ = released.recv();
                    drop(lock);
                })
            };
            wait_until_queued(second.thread(), || second.is_finished());
            (
                Box::new(move || drop(first)),
                Box::new(move || {
                    release.send(()).unwrap();
                    second.join().unwrap();
                }),
            )
        }
        AheadOnTheStripe::Processes => {
            let first = xq::register(&stripe).unwrap();
            let second = xq::register(&stripe).unwrap();
            (Box::new(move || drop(first)), Box::new(move || drop(second)))
        }
        AheadOnTheStripe::ThreadThenProcess => {
            let first = lock_at_within(&stripe, long).unwrap();
            let second = xq::register(&stripe).unwrap();
            (Box::new(move || drop(first)), Box::new(move || drop(second)))
        }
        AheadOnTheStripe::OutsideTheQueue => {
            use fs2::FileExt as _;
            let foreign = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&stripe)
                .unwrap();
            foreign.lock_exclusive().unwrap();
            (
                Box::new(|| {}),
                Box::new(move || fs2::FileExt::unlock(&foreign).unwrap()),
            )
        }
    };
    // The holder: it gets x's name lock, queues for the stripe, and once it
    // has both keeps them for 2.5 s.
    let (holder_got_tx, holder_got) = std::sync::mpsc::channel();
    let holder = {
        let (x, locks) = (x.clone(), locks.clone());
        std::thread::spawn(move || {
            let (lock, _) = take_state_lock_in(&x, long, &|| locks.clone()).unwrap();
            holder_got_tx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(2500));
            drop(lock);
        })
    };
    // It is waiting with the name lock held (in the stripe's turn queue, or,
    // behind other processes' tickets, in its cross-process queue).
    let name_lock = name_lock_path_in(&locks, &identity::identity(&x).unwrap().name);
    let deadline = Instant::now() + Duration::from_secs(20);
    while turn::outstanding(&turn::key_for(&name_lock)) == 0 {
        assert!(Instant::now() < deadline, "the holder never took the name lock");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(holder_got.try_recv().is_err(), "the holder got through");
    // A writer of ANOTHER process behind it on the name lock: all such a
    // writer sees of the holder is its ticket in the name lock's queue, so
    // it waits here exactly as that process would, behind the holder's
    // ticket (which is there once the holder has the name lock).
    let queue = xq::dir_for(&name_lock);
    let has_a_ticket = || {
        std::fs::read_dir(&queue).is_ok_and(|entries| {
            entries
                .flatten()
                .any(|e| e.file_name().to_string_lossy().ends_with(".t"))
        })
    };
    while !has_a_ticket() {
        assert!(Instant::now() < deadline, "the holder never queued for the name lock");
        std::thread::sleep(Duration::from_millis(1));
    }
    // The holder's ticket is the only one there now; what production does
    // to it is read off the ticket itself, below.
    let holders_ticket = {
        let mut tickets: Vec<PathBuf> = std::fs::read_dir(&queue)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.to_string_lossy().ends_with(".t"))
            .collect();
        assert_eq!(tickets.len(), 1, "{tickets:?}");
        tickets.remove(0)
    };
    let touched = |ticket: &Path| std::fs::metadata(ticket).and_then(|md| md.modified()).ok();
    let before_the_schedule = touched(&holders_ticket);
    assert!(before_the_schedule.is_some());
    // The waiter's first look at the queue is established before the
    // schedule starts: a ticket of the test's own is ahead of it too, and is
    // touched until the waiter reports progress, then removed.
    let seen_by_other_process = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let acknowledge = xq::register(&name_lock).unwrap();
    let other_process = {
        let ticket = xq::register(&name_lock).unwrap();
        let seen = seen_by_other_process.clone();
        std::thread::spawn(move || {
            xq::wait_for_head(&ticket, stall, || {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        })
    };
    while seen_by_other_process.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        assert!(!other_process.is_finished() && Instant::now() < deadline);
        acknowledge.touch();
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(acknowledge);
    // The writer behind it on the name lock in this process, with the short
    // give-up time.
    let behind = {
        let (x, locks) = (x.clone(), locks.clone());
        std::thread::spawn(move || take_state_lock_in(&x, stall, &|| locks.clone()).map(drop))
    };
    wait_until_queued(behind.thread(), || behind.is_finished());
    let started = Instant::now();
    assert!(holder_got.try_recv().is_err(), "the holder got through");
    std::thread::sleep(Duration::from_secs(2));
    first_leave();
    std::thread::sleep(second_leaves_after);
    assert!(holder_got.try_recv().is_err(), "the holder got through");
    second_leave();
    holder_got
        .recv_timeout(Duration::from_secs(20))
        .expect("the holder is served once the stripe is free");
    // The holder has handed on what there was to hand on, and still holds
    // the locks: its ticket must have been touched, which is all a writer
    // of another process can see of that (that such a writer counts a touch
    // as progress is `a_ticket_touched_by_its_writer...`'s to show; that
    // the one here is served, below, is the two together).
    let after_the_schedule = touched(&holders_ticket);
    assert!(!holder.is_finished(), "this test proves nothing");
    assert!(
        after_the_schedule.is_some() && after_the_schedule != before_the_schedule,
        "the holder's ticket was never touched: nothing reached the other processes"
    );
    holder.join().unwrap();
    assert!(
        started.elapsed() > stall + Duration::from_secs(1),
        "this test proves nothing"
    );
    assert!(
        other_process.join().unwrap(),
        "a writer of another process behind the name lock must not give up: \
         the holder's ticket must say that it moved up the stripe's queue"
    );
    behind.join().unwrap().expect(
        "the writer behind must not give up: its holder moved up the stripe's queue, \
         and then held the lock for less than the give-up time",
    );
}

#[test]
fn a_holder_moving_up_its_inode_stripe_behind_threads_keeps_its_waiters() {
    a_holder_moving_up_its_inode_stripe(AheadOnTheStripe::Threads);
}

#[test]
fn a_holder_moving_up_its_inode_stripe_behind_processes_keeps_its_waiters() {
    a_holder_moving_up_its_inode_stripe(AheadOnTheStripe::Processes);
}

#[test]
fn a_holder_moving_up_its_inode_stripe_behind_a_thread_then_a_process_keeps_its_waiters() {
    a_holder_moving_up_its_inode_stripe(AheadOnTheStripe::ThreadThenProcess);
}

#[test]
fn a_holder_granted_its_inode_stripe_from_outside_the_queue_keeps_its_waiters() {
    a_holder_moving_up_its_inode_stripe(AheadOnTheStripe::OutsideTheQueue);
}

/// What a writer of another process sees: a ticket ahead whose writer
/// touches it counts as progress and restarts the wait; a ticket nobody
/// touches is still given up on.
///
/// Give-up time 3 s. The ticket ahead is touched until the waiter reports
/// it (T1: it has started by then, so its first deadline is at T1 + 3 s at
/// the latest), again 2 s later until it reports that (T2 = T1 + 2 s), and
/// is removed at T2 + 2 s = T1 + 4 s: past the first deadline, and past the
/// one a waiter that reported the touches without restarting its wait
/// would have.
#[test]
fn a_ticket_touched_by_its_writer_restarts_the_wait_of_the_processes_behind_it() {
    use std::sync::atomic::{AtomicU32, Ordering};
    let dir = tempfile::tempdir().unwrap();
    let lock = dir.path().join("relay.lock");
    let stall = Duration::from_secs(3);
    let ahead = xq::register(&lock).unwrap();
    let mine = xq::register(&lock).unwrap();
    let progress = AtomicU32::new(0);
    let served = std::thread::scope(|s| {
        let waiter = s.spawn(|| {
            xq::wait_for_head(&mine, stall, || {
                progress.fetch_add(1, Ordering::SeqCst);
            })
        });
        // Touched, at least once, until the waiter reports something new (a
        // touch from before its first look at the queue is nothing it can
        // see; a report still on its way from an earlier touch may end the
        // loop early, but never before this phase's own touch was made).
        let touch_until_seen = || {
            let reported = progress.load(Ordering::SeqCst);
            loop {
                assert!(
                    !waiter.is_finished(),
                    "the waiter gave up, or was served, without seeing the touch"
                );
                ahead.touch();
                std::thread::sleep(Duration::from_millis(20));
                if progress.load(Ordering::SeqCst) > reported {
                    break Instant::now();
                }
            }
        };
        let first = touch_until_seen();
        std::thread::sleep(Duration::from_secs(2));
        touch_until_seen();
        std::thread::sleep(Duration::from_secs(2));
        assert!(first.elapsed() > stall, "this test proves nothing");
        assert!(!waiter.is_finished(), "the waiter gave up after a touch");
        drop(ahead);
        waiter.join().unwrap()
    });
    assert!(served, "the touches must have restarted the wait");
    drop(mine);
    // Untouched: given up on.
    let ahead = xq::register(&lock).unwrap();
    let mine = xq::register(&lock).unwrap();
    assert!(!xq::wait_for_head(&mine, Duration::from_millis(300), || {}));
    drop(ahead);
}

/// The lock directory of a test process that is gone is removed by the next
/// one; that of a live process (its marker is locked) never is, however old,
/// nor one whose owner has not published its marker yet.
#[test]
fn only_a_dead_test_process_s_lock_directory_is_swept() {
    let temp = tempfile::tempdir().unwrap();
    let (live, live_marker) = test_locks::create(temp.path());
    std::thread::sleep(Duration::from_millis(2)); // (the names carry the time)
    let (dead, dead_marker) = test_locks::create(temp.path());
    assert_ne!(live, dead);
    std::fs::write(dead.join("state-0.lock"), "").unwrap();
    drop(dead_marker);
    let unmarked = temp.path().join("fuigo-config-test-locks-1-1");
    std::fs::create_dir(&unmarked).unwrap();
    // An owner still starting: its marker is there but has no name yet.
    let starting = temp.path().join("fuigo-config-test-locks-2-2");
    std::fs::create_dir(&starting).unwrap();
    std::fs::write(starting.join("owner.lock.new"), "").unwrap();
    let stranger = temp.path().join("somebody-elses");
    std::fs::create_dir(&stranger).unwrap();
    // (Swept until gone: a marker's lock is the open file's, and a child
    // process another test starts holds a copy of every open file of this
    // process between its fork and its exec, so a lock just dropped can
    // look held for that instant. Such a sweep leaves the directory alone,
    // which is the safe side.)
    let sweep_until_gone = |dir: &Path| {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            test_locks::sweep(temp.path());
            if !dir.exists() {
                break;
            }
            assert!(Instant::now() < deadline, "{} was never swept", dir.display());
            std::thread::sleep(Duration::from_millis(5));
        }
    };
    sweep_until_gone(&dead);
    assert!(live.exists(), "the live owner's directory stays");
    assert!(unmarked.exists() && starting.exists() && stranger.exists());
    for _ in 0..20 {
        test_locks::sweep(temp.path());
    }
    assert!(live.exists(), "the live owner's directory stays, however often it is asked");
    drop(live_marker);
    sweep_until_gone(&live);
    assert!(unmarked.exists() && starting.exists() && stranger.exists());
}

/// A lookup of the on-disk spelling that fails is a refusal, whatever the
/// reason (on Windows: a directory the writer may not list). Landing on the
/// spelling given instead would keep the short-name loss for exactly such a
/// directory.
#[test]
fn an_on_disk_name_that_cannot_be_established_is_a_refusal() {
    let target = Path::new("state.toml");
    for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::Other] {
        let refused = entry_to_land_on(target, Err(io::Error::new(kind, "no"))).unwrap_err();
        assert_eq!(refused.kind(), kind);
        assert!(refused.to_string().contains("state.toml"), "{refused}");
    }
    assert_eq!(entry_to_land_on(target, Ok(None)).unwrap(), None);
    let entry = PathBuf::from("State.toml");
    assert_eq!(
        entry_to_land_on(target, Ok(Some(entry.clone()))).unwrap(),
        Some(entry)
    );
    // Where the platform has nothing to look up, there is nothing to refuse.
    #[cfg(not(windows))]
    assert_eq!(identity::entry_as_on_disk(target).unwrap(), None);
}

/// Spellings that share a lock end up in ONE file: an edit through another
/// spelling of the name replaces the file's own directory entry, which keeps
/// its on-disk name, and no edit starts from an empty file. (Windows renames
/// onto the spelling it is given: after an edit through `AGENT.TOML` the
/// file was called that.) Real filesystem, case-insensitive directory only.
#[test]
fn an_edit_through_another_case_keeps_the_files_name_and_every_edit() {
    let (_tmp, tmp_dir) = real_dir();
    let (_cleanup, dir) = real_fs_dir(&tmp_dir, "respell");
    if !identity::dir_is_case_insensitive(&dir).unwrap() {
        eprintln!("P79_RESPELL_SKIPPED: {} is case-sensitive", dir.display());
        return;
    }
    eprintln!("P79_RESPELL_RAN: {}", dir.display());
    let file = dir.join("Agent.toml");
    std::fs::write(&file, "0\n").unwrap();
    append_through(&dir.join("AGENT.TOML"), "upper\n").unwrap();
    assert_eq!(names_in(&dir), ["Agent.toml"]);
    append_through(&dir.join("agent.toml"), "lower\n").unwrap();
    append_through(&file, "own\n").unwrap();
    // The write-through writer (prompt history, settings) too.
    let through = dir.join("aGENT.tOML");
    edit_state_file(
        &through,
        |bytes| crate::write_through::stage_file_atomically(&through, bytes),
        |current| {
            let mut contents = current.unwrap().unwrap().to_vec();
            contents.extend_from_slice(b"write-through\n");
            Ok::<_, io::Error>(Edit::Replace {
                contents,
                value: (),
            })
        },
    )
    .unwrap();
    assert_eq!(names_in(&dir), ["Agent.toml"]);
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "0\nupper\nlower\nown\nwrite-through\n"
    );
}

#[cfg(windows)]
mod windows_spellings {
    use super::*;

    /// The exact (`\\?\`) spelling of a drive path.
    fn verbatim(path: &Path) -> PathBuf {
        PathBuf::from(format!(r"\\?\{}", path.display()))
    }

    /// One identity (name and inode) and one name lock file.
    fn assert_one_file(a: &Path, b: &Path) {
        assert_eq!(
            identity::identity(a).unwrap(),
            identity::identity(b).unwrap(),
            "{} / {}",
            a.display(),
            b.display()
        );
        assert_eq!(state_lock_path(a).unwrap(), state_lock_path(b).unwrap());
    }

    /// While `holder` is locked, a writer through `writer` queues; it is
    /// served once the holder lets go.
    fn assert_excludes(holder: &Path, writer: &Path) {
        let held = lock_state_file(holder).unwrap();
        let other = Writer::start(writer);
        other.wait_until_queued();
        drop(held);
        other.wait_for_the_lock();
        other.finish();
    }

    /// `path` with every component in its 8.3 short form, where the volume
    /// has short names.
    fn short_path(path: &Path) -> Option<PathBuf> {
        use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
        use windows::Win32::Storage::FileSystem::GetShortPathNameW;
        use windows::core::PCWSTR;
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut buf = vec![0u16; 1024];
        // SAFETY: `wide` is NUL-terminated and outlives the call; `buf` is a
        // valid buffer of the length passed.
        let len = unsafe { GetShortPathNameW(PCWSTR(wide.as_ptr()), Some(&mut buf)) };
        let len = usize::try_from(len).unwrap();
        (len > 0 && len < buf.len())
            .then(|| PathBuf::from(std::ffi::OsString::from_wide(&buf[..len])))
    }

    /// `mklink` (a junction needs no privilege; std has no call for one).
    fn mklink(kind: &str, link: &Path, target: &Path) -> bool {
        use std::os::windows::process::CommandExt as _;
        #[allow(clippy::disallowed_methods)] // test fixture, waited for
        std::process::Command::new("cmd")
            .args(["/d", "/c"])
            .raw_arg(format!(
                "mklink {kind} \"{}\" \"{}\"",
                link.display(),
                target.display()
            ))
            .output()
            .is_ok_and(|out| out.status.success())
    }

    /// The verbatim spelling of a path is the same file as the plain one:
    /// one identity and one lock before the file or its directories exist
    /// and after, exclusion both ways, and edits through each (the locked
    /// pass re-derives the identity of the path and of the staged target:
    /// an unstable identity would refuse them).
    #[test]
    fn the_verbatim_spelling_is_the_same_file() {
        let (_tmp, dir) = real_dir();
        let agent = dir.join("Agent.toml");
        assert_one_file(&agent, &verbatim(&agent));
        let deep = dir.join("Sub").join("Deep").join("Agent.toml");
        assert_one_file(&deep, &verbatim(&deep));
        assert_excludes(&deep, &verbatim(&deep));
        assert_eq!(names_in(&dir), Vec::<String>::new(), "locking creates nothing");
        std::fs::write(&agent, "0\n").unwrap();
        assert_one_file(&agent, &verbatim(&agent));
        assert_excludes(&verbatim(&agent), &agent);
        assert_excludes(&agent, &verbatim(&agent));
        append_through(&verbatim(&agent), "verbatim\n").unwrap();
        append_through(&agent, "plain\n").unwrap();
        // ...and in another case, each way.
        assert_one_file(&agent, &dir.join("AGENT.TOML"));
        assert_one_file(&agent, &verbatim(&dir.join("agent.toml")));
        assert_one_file(
            &dir.join("New").join("State.toml"),
            &verbatim(&dir.join("NEW").join("STATE.TOML")),
        );
        assert_excludes(&agent, &verbatim(&dir.join("AGENT.TOML")));
        append_through(&verbatim(&dir.join("AGENT.TOML")), "verbatim-upper\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&agent).unwrap(),
            "0\nverbatim\nplain\nverbatim-upper\n"
        );
        assert_eq!(names_in(&dir), ["Agent.toml"], "the file keeps its name");
    }

    /// A junction in the directory part is the directory it points at.
    #[test]
    fn a_junction_is_the_directory_it_points_at() {
        let (_tmp, dir) = real_dir();
        let (real, junction) = (dir.join("Real"), dir.join("Jct"));
        std::fs::create_dir(&real).unwrap();
        assert!(mklink("/J", &junction, &real), "mklink /J failed");
        let (direct, via) = (real.join("state.toml"), junction.join("state.toml"));
        assert_one_file(&direct, &via);
        assert_excludes(&direct, &via);
        std::fs::write(&direct, "0\n").unwrap();
        assert_one_file(&direct, &via);
        assert_one_file(&direct, &verbatim(&dir.join("JCT").join("STATE.TOML")));
        assert_excludes(&direct, &via);
        assert_excludes(&verbatim(&via), &direct);
        append_through(&via, "junction\n").unwrap();
        append_through(&verbatim(&via), "verbatim-junction\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&direct).unwrap(),
            "0\njunction\nverbatim-junction\n"
        );
        assert_eq!(names_in(&real), ["state.toml"]);
        assert!(
            std::fs::symlink_metadata(&junction)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the junction is still a junction"
        );
    }

    /// Hard links share the inode lock through the verbatim spelling too.
    #[test]
    fn a_hard_link_excludes_through_the_verbatim_spelling() {
        let (_tmp, dir) = real_dir();
        let (a, b) = (dir.join("hl-a.toml"), dir.join("hl-b.toml"));
        std::fs::write(&a, "0\n").unwrap();
        std::fs::hard_link(&a, &b).unwrap();
        let inode = inode_of(&a);
        assert!(inode.is_some());
        assert_eq!(inode, inode_of(&b));
        assert_eq!(inode, inode_of(&verbatim(&b)));
        assert_excludes(&a, &b);
        assert_excludes(&b, &verbatim(&a));
        append_through(&b, "through-b\n").unwrap();
        // (The replace separates the links, as on every platform: the lock
        // orders the writers, it does not keep the link.)
        assert_eq!(std::fs::read_to_string(&b).unwrap(), "0\nthrough-b\n");
    }

    /// An 8.3 short name is another spelling of the long name. The two share
    /// the inode lock, and an edit through the short FILE name must land on
    /// the long name's entry: renamed onto the short spelling, the long name
    /// was gone, and the next writer through it started from an empty file.
    #[test]
    fn an_edit_through_a_short_name_lands_on_the_long_name() {
        let (_tmp, dir) = real_dir();
        let long_dir = dir.join("Long Directory Name For Fuigo");
        std::fs::create_dir(&long_dir).unwrap();
        let long_name = "LongFileName.settings.toml";
        let long = long_dir.join(long_name);
        std::fs::write(&long, "0\n").unwrap();
        let short = short_path(&long).filter(|short| short.file_name() != long.file_name());
        let Some(short) = short else {
            eprintln!(
                "P79_SHORT_NAMES_SKIPPED: no 8.3 short names on the volume of {}",
                dir.display()
            );
            return;
        };
        eprintln!("P79_SHORT_NAMES_RAN: {} is {}", long.display(), short.display());
        // The short DIRECTORY name resolves away: one name, one lock.
        assert_one_file(&long, &short.parent().unwrap().join(long_name));
        // The short FILE name is not equated by name (the module docs), but
        // it is the same inode, so the writers exclude each other.
        let short_file = long_dir.join(short.file_name().unwrap());
        assert_eq!(inode_of(&long), inode_of(&short_file));
        assert!(inode_of(&long).is_some());
        assert_excludes(&long, &short_file);
        assert_excludes(&short, &long);
        append_through(&short_file, "short\n").unwrap();
        assert_eq!(names_in(&long_dir), [long_name], "the long name is the file's name");
        append_through(&long, "long\n").unwrap();
        append_through(&short, "all-short\n").unwrap();
        // The write-through writer (prompt history, settings) too.
        let through = long_dir.join(short_path(&long).unwrap().file_name().unwrap());
        edit_state_file(
            &through,
            |bytes| crate::write_through::stage_file_atomically(&through, bytes),
            |current| {
                let mut contents = current.unwrap().unwrap().to_vec();
                contents.extend_from_slice(b"write-through\n");
                Ok::<_, io::Error>(Edit::Replace {
                    contents,
                    value: (),
                })
            },
        )
        .unwrap();
        assert_eq!(names_in(&long_dir), [long_name]);
        assert_eq!(
            std::fs::read_to_string(&long).unwrap(),
            "0\nshort\nlong\nall-short\nwrite-through\n"
        );
    }

    /// `icacls <dir> <args>`.
    fn icacls(dir: &Path, args: &[&str]) -> bool {
        #[allow(clippy::disallowed_methods)] // test fixture, waited for
        std::process::Command::new("icacls")
            .arg(dir)
            .args(args)
            .output()
            .is_ok_and(|out| out.status.success())
    }

    /// Where the on-disk spelling cannot be established (the directory may
    /// not be listed), nothing is written: landing on the spelling given
    /// would keep the short-name loss for exactly such a directory.
    #[test]
    fn a_directory_that_may_not_be_listed_refuses_the_write() {
        let (_tmp, dir) = real_dir();
        let closed = dir.join("Closed");
        std::fs::create_dir(&closed).unwrap();
        let file = closed.join("State.toml");
        std::fs::write(&file, "0\n").unwrap();
        // Everyone is denied "list folder" on it; files in it can still be
        // opened, created and replaced.
        assert!(icacls(&closed, &["/deny", "*S-1-1-0:(RD)"]), "icacls /deny failed");
        let listing = std::fs::read_dir(&closed).map(|_| ());
        let own = append_through(&file, "own\n");
        let other = append_through(&closed.join("STATE.TOML"), "other\n");
        let contents = std::fs::read_to_string(&file);
        assert!(icacls(&closed, &["/remove:d", "*S-1-1-0"]), "icacls /remove:d failed");
        if listing.is_ok() {
            // An account with the backup privilege enabled (an elevated
            // session) lists what it is denied, as root does on unix.
            eprintln!("P79_WIN_PERMS_SKIPPED: this account lists a directory it is denied");
            return;
        }
        eprintln!("P79_WIN_PERMS_RAN");
        assert_eq!(listing.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        for refused in [own, other] {
            match refused {
                Err(EditError::Write(e)) => {
                    assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
                }
                other => panic!("not refused as a write error: {other:?}"),
            }
        }
        assert_eq!(contents.unwrap(), "0\n");
        assert_eq!(names_in(&closed), ["State.toml"], "no temp is left");
        // Listable again, it is written.
        append_through(&closed.join("STATE.TOML"), "other\n").unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "0\nother\n");
        assert_eq!(names_in(&closed), ["State.toml"]);
    }

    /// The on-disk spelling found for a path is used only if it is the very
    /// file the path names; if it is another file, the name is not
    /// established, which is a refusal.
    #[test]
    fn an_entry_that_is_another_file_is_refused() {
        let (_tmp, dir) = real_dir();
        let (a, b) = (dir.join("a.toml"), dir.join("b.toml"));
        std::fs::write(&a, "a").unwrap();
        std::fs::write(&b, "b").unwrap();
        let exact = |name: &str| verbatim(&dir).join(name);
        let entry = |asked: &str, entry: &str| {
            identity::entry_if_same_file(&exact(asked), &exact(entry))
        };
        assert_eq!(entry("a.toml", "A.TOML").unwrap(), Some(exact("A.TOML")));
        assert!(entry("a.toml", "b.toml").is_err(), "another file");
        assert!(entry("a.toml", "missing.toml").is_err(), "no such entry");
        assert_eq!(entry("missing.toml", "a.toml").unwrap(), None, "nothing to replace");
        // And the whole question, for the spelling the entry has and for
        // another one (the answer is in the exact form).
        assert_eq!(identity::entry_as_on_disk(&a).unwrap(), None);
        assert_eq!(
            identity::entry_as_on_disk(&dir.join("A.TOML")).unwrap(),
            Some(exact("a.toml"))
        );
        assert_eq!(identity::entry_as_on_disk(&dir.join("none.toml")).unwrap(), None);
    }

    /// A long name only the exact form can spell (a trailing dot), beside
    /// its namesake without the dot, edited through its 8.3 short name in a
    /// PLAIN path: the replacement must land on the dotted long name. Put
    /// back into the plain spelling it would be read as the namesake.
    #[test]
    fn a_short_name_of_a_verbatim_only_long_name_lands_on_that_name() {
        let (_tmp, dir) = real_dir();
        let plain_name = "LongFileName.settings.toml";
        let dotted_name = "LongFileName.settings.toml.";
        let namesake = dir.join(plain_name);
        let dotted = verbatim(&dir).join(dotted_name);
        std::fs::write(&namesake, "namesake\n").unwrap();
        std::fs::write(&dotted, "dotted\n").unwrap();
        assert_eq!(names_in(&dir), [plain_name, dotted_name]);
        let short = short_path(&dotted)
            .and_then(|short| short.file_name().map(std::ffi::OsStr::to_owned))
            .filter(|short| short.as_os_str() != dotted_name);
        let Some(short) = short else {
            eprintln!(
                "P79_SHORT_DOTTED_SKIPPED: no 8.3 short name for {} on this volume",
                dotted.display()
            );
            std::fs::remove_file(&dotted).unwrap();
            return;
        };
        eprintln!("P79_SHORT_DOTTED_RAN: {dotted_name} is {}", short.to_string_lossy());
        let through = dir.join(&short);
        assert_eq!(inode_of(&through), inode_of(&dotted));
        assert_ne!(inode_of(&through), inode_of(&namesake));
        append_through(&through, "short\n").unwrap();
        assert_eq!(names_in(&dir), [plain_name, dotted_name]);
        assert_eq!(std::fs::read_to_string(&dotted).unwrap(), "dotted\nshort\n");
        assert_eq!(std::fs::read_to_string(&namesake).unwrap(), "namesake\n");
        // (Removed through the exact form: the temp directory's own cleanup
        // spells it plainly.)
        std::fs::remove_file(&dotted).unwrap();
    }

    /// The identity of one file is the same however often and through
    /// whichever spelling it is asked, and edits through alternating
    /// spellings, also from several threads at once, are neither refused
    /// (the locked pass refuses a moved identity) nor lost.
    #[test]
    fn the_identity_is_steady_through_every_spelling() {
        let (_tmp, dir) = real_dir();
        let spellings = |name: &str| {
            let file = dir.join(name);
            [
                file.clone(),
                verbatim(&file),
                dir.join(name.to_uppercase()),
                verbatim(&dir.join(name.to_lowercase())),
            ]
        };
        let asked = spellings("Asked.toml");
        std::fs::write(&asked[0], "0\n").unwrap();
        let first = identity::identity(&asked[0]).unwrap();
        for i in 0..2000 {
            assert_eq!(identity::identity(&asked[i % 4]).unwrap(), first, "ask {i}");
        }
        let stable = spellings("Stable.toml");
        for i in 0..400 {
            append_through(&stable[i % 4], &format!("{i}\n")).unwrap();
        }
        let want: String = (0..400).map(|i| format!("{i}\n")).collect();
        assert_eq!(std::fs::read_to_string(&stable[0]).unwrap(), want);
        // (It exists first: a missing file is named by whoever creates it.)
        let shared = spellings("Shared.toml");
        std::fs::write(&shared[0], "").unwrap();
        std::thread::scope(|scope| {
            for (t, path) in shared.iter().enumerate() {
                scope.spawn(move || {
                    for i in 0..100 {
                        append_through(path, &format!("{t}-{i}\n")).unwrap();
                    }
                });
            }
        });
        let mut got: Vec<String> = std::fs::read_to_string(&shared[0])
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        got.sort();
        let mut want: Vec<String> = (0..4)
            .flat_map(|t| (0..100).map(move |i| format!("{t}-{i}")))
            .collect();
        want.sort();
        assert_eq!(got, want);
        assert_eq!(names_in(&dir), ["Asked.toml", "Shared.toml", "Stable.toml"]);
    }

    /// Names only the verbatim form can spell (`Odd.` is not `Odd`, `state.`
    /// is not `state`) are files of their own: their own locks, and each
    /// edit in its own file.
    #[test]
    fn names_only_the_verbatim_form_can_spell_are_their_own_files() {
        let (_tmp, dir) = real_dir();
        let odd = dir.join("Odd");
        let odd_dot = verbatim(&dir).join("Odd.");
        std::fs::create_dir(&odd).unwrap();
        std::fs::create_dir(&odd_dot).unwrap();
        let (in_odd, in_dot) = (odd.join("state.toml"), odd_dot.join("state.toml"));
        assert_ne!(
            state_lock_path(&in_odd).unwrap(),
            state_lock_path(&in_dot).unwrap()
        );
        append_through(&in_dot, "dot\n").unwrap();
        append_through(&in_odd, "plain\n").unwrap();
        assert_eq!(std::fs::read_to_string(&in_dot).unwrap(), "dot\n");
        assert_eq!(std::fs::read_to_string(&in_odd).unwrap(), "plain\n");
        // The same for a FILE name with a trailing dot, beside its namesake.
        let (plain, dotted) = (dir.join("state"), verbatim(&dir).join("state."));
        append_through(&plain, "plain\n").unwrap();
        append_through(&dotted, "dotted\n").unwrap();
        append_through(&plain, "plain again\n").unwrap();
        append_through(&dotted, "dotted again\n").unwrap();
        assert_eq!(std::fs::read_to_string(&plain).unwrap(), "plain\nplain again\n");
        assert_eq!(
            std::fs::read_to_string(&dotted).unwrap(),
            "dotted\ndotted again\n"
        );
        // (Removed through the verbatim form: the temp directory's own
        // cleanup spells them plainly.)
        std::fs::remove_file(&dotted).unwrap();
        std::fs::remove_dir_all(&odd_dot).unwrap();
    }
}
