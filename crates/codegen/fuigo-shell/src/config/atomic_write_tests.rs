//! P17-F1: every writer of `config.toml` / `hooks-paths` in `crate::config`
//! replaces its file atomically. Each property is checked against all eight
//! writers through their path-parameterized entry points, so a writer that
//! regresses to an in-place write fails by name.

use super::super::{
    add_disabled_plugin_in, add_dismissed_plugin_cta_to_file, add_enabled_plugin_in,
    add_hooks_path_to_file, add_plugin_path_in, remove_disabled_plugin_in,
    remove_enabled_plugin_in, remove_hooks_path_from_file, remove_plugin_path_in,
};
use super::fault::with_write_failing_after;
use super::write_file_atomically;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

type WriteResult = Result<(), Box<dyn std::error::Error>>;

/// Size of the padding that makes an in-place rewrite slow enough to be caught.
const PADDING: usize = 512 * 1024;
/// Lines of padding in the `hooks-paths` seed (~16 bytes each).
const HOOK_PAD_LINES: usize = 32 * 1024;

struct Writer {
    name: &'static str,
    file_name: &'static str,
    seed: fn() -> String,
    run: fn(&Path) -> WriteResult,
    /// Whether `content` is a complete file this writer could have produced.
    complete: fn(&str) -> bool,
}

fn config_seed() -> String {
    format!(
        "[plugins]\npaths = [\"/p/old\"]\ndisabled = [\"d-old\"]\nenabled = [\"e-old\"]\n\n\
         [plugin_cta]\ndismissed = []\n\n[padding]\nblob = \"{}\"\n\n\
         [endpoints]\nsentinel = \"end\"\n",
        "x".repeat(PADDING)
    )
}

/// The whole file parsed, and both the padding and the section after it survived.
fn config_complete(content: &str) -> bool {
    let Ok(v) = toml::from_str::<toml::Value>(content) else {
        return false;
    };
    let blob_ok = v
        .get("padding")
        .and_then(|t| t.get("blob"))
        .and_then(toml::Value::as_str)
        .is_some_and(|b| b.len() == PADDING);
    let end_ok = v
        .get("endpoints")
        .and_then(|t| t.get("sentinel"))
        .and_then(toml::Value::as_str)
        == Some("end");
    blob_ok && end_ok
}

fn hooks_seed() -> String {
    let mut s = String::with_capacity(HOOK_PAD_LINES * 20);
    for i in 0..HOOK_PAD_LINES {
        s.push_str(&format!("/hooks/pad/{i}\n"));
    }
    s.push_str("/hooks/remove-me\n/hooks/end\n");
    s
}

/// No trailing-newline check: the re-add before each removal is an append, which
/// a reader may legitimately catch half-way through its one short line.
fn hooks_complete(content: &str) -> bool {
    content
        .lines()
        .filter(|l| l.starts_with("/hooks/pad/"))
        .count()
        == HOOK_PAD_LINES
        && content.lines().any(|l| l == "/hooks/end")
}

fn writers() -> Vec<Writer> {
    fn cfg(name: &'static str, run: fn(&Path) -> WriteResult) -> Writer {
        Writer {
            name,
            file_name: "config.toml",
            seed: config_seed,
            run,
            complete: config_complete,
        }
    }
    vec![
        cfg("add_plugin_path", |p| add_plugin_path_in("/p/new", p)),
        cfg("remove_plugin_path", |p| remove_plugin_path_in("/p/old", p)),
        cfg("add_disabled_plugin", |p| {
            add_disabled_plugin_in("d-new", p)
        }),
        cfg("remove_disabled_plugin", |p| {
            remove_disabled_plugin_in("d-old", p)
        }),
        cfg("add_dismissed_plugin_cta", |p| {
            add_dismissed_plugin_cta_to_file("c-new", p)
        }),
        cfg("add_enabled_plugin", |p| add_enabled_plugin_in("e-new", p)),
        cfg("remove_enabled_plugin", |p| {
            remove_enabled_plugin_in("e-old", p)
        }),
        Writer {
            name: "remove_hooks_path",
            file_name: "hooks-paths",
            seed: hooks_seed,
            // Re-add first (a no-op while present) so every call really rewrites the file.
            run: |p| {
                add_hooks_path_to_file("/hooks/remove-me", p)?;
                if remove_hooks_path_from_file("/hooks/remove-me", p)? {
                    Ok(())
                } else {
                    Err("remove_hooks_path found nothing to remove".into())
                }
            },
            complete: hooks_complete,
        },
    ]
}

fn seeded(w: &Writer) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(w.file_name);
    std::fs::write(&path, (w.seed)()).unwrap();
    (dir, path)
}

fn stray_temp_files(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        // `.staging`: the macOS staging directory (see `atomic_write::staging`).
        .filter(|n| n.ends_with(".tmp") || n.ends_with(".staging"))
        .collect()
}

/// A reader polling the file while a writer rewrites it in a loop must only ever
/// see a complete file. An in-place `std::fs::write` truncates first, so the
/// reader catches an empty or half-written file -- the state that loads as an
/// empty config and resets the trust set.
#[test]
fn a_concurrent_reader_never_observes_a_partial_file() {
    const MIN_WRITES: usize = 100;
    const MIN_READS: usize = 300;
    const MAX_WRITES: usize = 5_000;
    for w in writers() {
        let (_dir, path) = seeded(&w);
        let stop = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(AtomicUsize::new(0));
        let reader = {
            let (stop, reads, path, complete) = (
                Arc::clone(&stop),
                Arc::clone(&reads),
                path.clone(),
                w.complete,
            );
            std::thread::spawn(move || {
                let mut torn: Vec<usize> = Vec::new();
                while !stop.load(Ordering::Relaxed) {
                    match std::fs::read(&path) {
                        Ok(bytes) => {
                            if !String::from_utf8(bytes.clone()).is_ok_and(|s| complete(&s)) {
                                torn.push(bytes.len());
                            }
                        }
                        // The path must never vanish either.
                        Err(_) => torn.push(usize::MAX),
                    }
                    reads.fetch_add(1, Ordering::Relaxed);
                }
                torn
            })
        };
        let mut writes = 0;
        while writes < MAX_WRITES
            && (writes < MIN_WRITES || reads.load(Ordering::Relaxed) < MIN_READS)
        {
            (w.run)(&path).unwrap_or_else(|e| panic!("{}: write failed: {e}", w.name));
            writes += 1;
        }
        stop.store(true, Ordering::Relaxed);
        let torn = reader.join().unwrap();
        let reads = reads.load(Ordering::Relaxed);
        assert!(
            reads >= MIN_READS,
            "{}: reader only got {reads} reads in {writes} writes; the test proved nothing",
            w.name
        );
        assert!(
            torn.is_empty(),
            "{}: {} of {reads} reads (over {writes} writes) saw a partial file; first lengths: {:?}",
            w.name,
            torn.len(),
            &torn[..torn.len().min(5)]
        );
        assert!(
            (w.complete)(&std::fs::read_to_string(&path).unwrap()),
            "{}",
            w.name
        );
    }
}

/// The file is replaced (new inode), and the replacement carries the original
/// mode exactly -- including group/world bits, which an in-place write never
/// touched either, and a setuid bit, which a write before the chmod would clear.
#[cfg(unix)]
#[test]
fn each_writer_replaces_the_file_and_keeps_its_permissions() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    for mode in [0o640, 0o604, 0o600, 0o4640] {
        for w in writers() {
            let (_dir, path) = seeded(&w);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let before = std::fs::metadata(&path).unwrap();

            (w.run)(&path).unwrap_or_else(|e| panic!("{}: write failed: {e}", w.name));

            let after = std::fs::metadata(&path).unwrap();
            assert_ne!(
                before.ino(),
                after.ino(),
                "{}: rewritten in place, not replaced atomically",
                w.name
            );
            assert_eq!(
                after.mode() & 0o7777,
                mode,
                "{}: mode {:o} became {:o}",
                w.name,
                mode,
                after.mode() & 0o7777
            );
            assert_eq!(
                (before.uid(), before.gid()),
                (after.uid(), after.gid()),
                "{}",
                w.name
            );
        }
    }
}

/// A write that fails part-way (disk full, I/O error) leaves the original file
/// byte-for-byte as it was, and no temp file behind.
#[test]
fn a_failed_write_leaves_the_old_file_intact() {
    for w in writers() {
        let (dir, path) = seeded(&w);
        let original = std::fs::read(&path).unwrap();

        let result = with_write_failing_after(64, || (w.run)(&path));

        assert!(
            result.is_err(),
            "{}: injected failure was swallowed",
            w.name
        );
        assert!(
            std::fs::read(&path).unwrap() == original,
            "{}: the failed write changed the file (now {} bytes, was {})",
            w.name,
            std::fs::read(&path).unwrap().len(),
            original.len()
        );
        assert_eq!(
            stray_temp_files(dir.path()),
            Vec::<String>::new(),
            "{}",
            w.name
        );
    }
}

/// A symlinked `config.toml` is written THROUGH, as the old in-place write did:
/// the link stays a link and the file it points at gets the new content.
#[cfg(unix)]
#[test]
fn a_symlinked_file_is_written_through_and_the_link_kept() {
    for w in writers() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("dotfiles")).unwrap();
        let real = dir.path().join("dotfiles").join(w.file_name);
        std::fs::write(&real, (w.seed)()).unwrap();
        let link = dir.path().join(w.file_name);
        std::os::unix::fs::symlink(Path::new("dotfiles").join(w.file_name), &link).unwrap();

        (w.run)(&link).unwrap_or_else(|e| panic!("{}: write failed: {e}", w.name));

        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "{}: the symlink was replaced by a regular file",
            w.name
        );
        let content = std::fs::read_to_string(&real).unwrap();
        assert!((w.complete)(&content), "{}", w.name);
        assert_ne!(
            content,
            (w.seed)(),
            "{}: the link target was not updated",
            w.name
        );
        assert_eq!(
            stray_temp_files(dir.path()),
            Vec::<String>::new(),
            "{}",
            w.name
        );
    }
}

/// A file that exists but cannot be read as text is not "empty": rewriting it
/// would replace the user's whole config with a single list. Every writer
/// refuses and leaves it alone. (`hooks-paths` is excluded: its removal already
/// refused such a file, and the append that re-adds a line before it is not one
/// of the replacing writers.)
#[test]
fn an_unreadable_file_is_refused_not_replaced() {
    let garbage: &[u8] = b"[plugins]\npaths = [\"\xff\xfe\"]\n";
    for w in writers()
        .into_iter()
        .filter(|w| w.file_name == "config.toml")
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(w.file_name);
        std::fs::write(&path, garbage).unwrap();

        assert!(
            (w.run)(&path).is_err(),
            "{}: wrote over an unreadable file",
            w.name
        );
        assert_eq!(std::fs::read(&path).unwrap(), garbage, "{}", w.name);
    }
}

/// A dangling link is followed and its target created, as `std::fs::write` did.
#[cfg(unix)]
#[test]
fn a_dangling_symlink_creates_its_target() {
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("config.toml");
    std::os::unix::fs::symlink("elsewhere.toml", &link).unwrap();

    write_file_atomically(&link, b"a = 1\n").unwrap();

    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("elsewhere.toml")).unwrap(),
        "a = 1\n"
    );
}

/// A missing file is created; one that already exists is replaced whole.
#[test]
fn write_file_atomically_creates_then_replaces() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    write_file_atomically(&path, b"a = 1\n").unwrap();
    write_file_atomically(&path, b"b = 2\n").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "b = 2\n");
    assert_eq!(stray_temp_files(dir.path()), Vec::<String>::new());
}

/// Two writers editing the same file concurrently both land: the read-modify-
/// write runs under the `config.toml` lock, so neither renames a document built
/// from a stale read over the other's change.
#[test]
fn concurrent_writers_do_not_lose_updates() {
    const EACH: usize = 40;
    let dir = tempfile::tempdir().unwrap();
    let path = Arc::new(dir.path().join("config.toml"));
    let spawn = |prefix: &'static str| {
        let path = Arc::clone(&path);
        std::thread::spawn(move || {
            for i in 0..EACH {
                // No retry: the lock is FIFO and the fsync runs outside it
                // (P49), so back-to-back holds by the other thread can no
                // longer starve this one into a `TimedOut`.
                add_plugin_path_in(&format!("/{prefix}/{i}"), &path)
                    .unwrap_or_else(|e| panic!("/{prefix}/{i}: {e}"));
            }
        })
    };
    let (a, b) = (spawn("a"), spawn("b"));
    a.join().unwrap();
    b.join().unwrap();

    let v: toml::Value = toml::from_str(&std::fs::read_to_string(&*path).unwrap()).unwrap();
    let paths: std::collections::HashSet<&str> = v["plugins"]["paths"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(toml::Value::as_str)
        .collect();
    let missing: Vec<String> = ["a", "b"]
        .iter()
        .flat_map(|p| (0..EACH).map(move |i| format!("/{p}/{i}")))
        .filter(|want| !paths.contains(want.as_str()))
        .collect();
    assert!(missing.is_empty(), "lost updates: {missing:?}");
}

/// A new file is created `0600`, never world-readable under a loose umask.
#[cfg(unix)]
#[test]
fn a_new_file_is_created_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    write_file_atomically(&path, b"a = 1\n").unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o600
    );
}

/// A temp name already taken (a crashed writer's leftover under a reused pid)
/// is neither reused nor deleted; creation moves on to the next name.
#[test]
fn a_leftover_temp_file_is_neither_reused_nor_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let name = std::ffi::OsStr::new("config.toml");
    let candidate = |n: u64| {
        dir.path()
            .join(format!(".config.toml.{}.{n}.tmp", std::process::id()))
    };
    for n in 0..8 {
        std::fs::write(candidate(n), "leftover").unwrap();
    }
    let mut next = 0u64;

    let (tmp, file) = super::create_temp_with(dir.path(), name, || {
        next += 1;
        next - 1
    })
    .unwrap();
    drop(file);

    assert_eq!(tmp, candidate(8), "the eight taken names must be skipped");
    for n in 0..8 {
        assert_eq!(std::fs::read_to_string(candidate(n)).unwrap(), "leftover");
    }
}

/// Every name taken: creation fails, and still deletes nothing it did not create.
#[test]
fn exhausted_temp_names_fail_without_deleting_anything() {
    let dir = tempfile::tempdir().unwrap();
    let name = std::ffi::OsStr::new("config.toml");
    let taken = dir
        .path()
        .join(format!(".config.toml.{}.7.tmp", std::process::id()));
    std::fs::write(&taken, "leftover").unwrap();

    let err = super::create_temp_with(dir.path(), name, || 7).unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read_to_string(&taken).unwrap(), "leftover");
}

/// Exactly 40 links are followed, as the kernel allows; a 41st is refused.
#[cfg(unix)]
#[test]
fn symlink_chains_follow_the_kernel_limit() {
    let dir = tempfile::tempdir().unwrap();
    let link = |i: usize| dir.path().join(format!("l{i}"));
    // l0 -> l1 -> ... -> l40 -> real (41 links); start at l1 for exactly 40.
    for i in 0..=40 {
        let to = if i == 40 {
            "real".to_string()
        } else {
            format!("l{}", i + 1)
        };
        std::os::unix::fs::symlink(&to, link(i)).unwrap();
    }
    write_file_atomically(&link(1), b"a = 1\n").unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("real")).unwrap(),
        "a = 1\n"
    );
    assert!(write_file_atomically(&link(0), b"b = 2\n").is_err());
}

/// A POSIX access ACL on the replaced file survives, so the group bits of the
/// mode (the ACL mask) are not handed to the whole owning group. Skips where
/// `setfacl` or ACL support is unavailable, saying so.
#[cfg(target_os = "linux")]
#[test]
fn an_access_acl_survives_the_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "a = 1\n").unwrap();
    // Named user `nobody` gets rw; the owning group gets nothing; mask rw.
    let set = std::process::Command::new("setfacl")
        .args(["-m", "u:nobody:rw-,g::---,m::rw-"])
        .arg(&path)
        .status();
    if !set.is_ok_and(|s| s.success()) {
        eprintln!(
            "SKIP an_access_acl_survives_the_replacement: setfacl unavailable or unsupported here"
        );
        return;
    }
    let acl = |p: &std::path::Path| {
        let out = std::process::Command::new("getfacl")
            .args(["--omit-header", "--absolute-names"])
            .arg(p)
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap()
    };
    let before = acl(&path);

    add_plugin_path_in("/p/new", &path).unwrap();

    assert_eq!(
        acl(&path),
        before,
        "the access ACL changed across the rewrite"
    );
}
/// Removing from a missing file is a no-op that creates nothing -- not even a lock file.
#[test]
fn removing_from_a_missing_file_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested").join("config.toml");
    remove_plugin_path_in("/p/x", &path).unwrap();
    remove_disabled_plugin_in("x", &path).unwrap();
    remove_enabled_plugin_in("x", &path).unwrap();
    assert!(!dir.path().join("nested").exists());
}

/// An access ACL the temp file inherits from a DEFAULT ACL on the directory is
/// stripped when the original had none, so the replacement grants nobody more
/// than the original did. Skips where `setfacl` or ACL support is unavailable.
#[cfg(target_os = "linux")]
#[test]
fn an_inherited_default_acl_is_not_added_to_the_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "a = 1\n").unwrap();
    let set = std::process::Command::new("setfacl")
        .args(["-d", "-m", "u:nobody:rw-"])
        .arg(dir.path())
        .status();
    if !set.is_ok_and(|s| s.success()) {
        eprintln!(
            "SKIP an_inherited_default_acl_is_not_added_to_the_replacement: setfacl unavailable"
        );
        return;
    }
    let acl_of = |p: &std::path::Path| {
        let out = std::process::Command::new("getfacl")
            .args(["--omit-header", "--absolute-names"])
            .arg(p)
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap()
    };
    let before = acl_of(&path);
    assert!(
        !before.contains("nobody"),
        "precondition: the original has no ACL entry"
    );

    add_plugin_path_in("/p/new", &path).unwrap();

    assert_eq!(
        acl_of(&path),
        before,
        "the replacement picked up the directory's default ACL"
    );
}

/// On a current-thread runtime (the session's), a plugin-list edit routed
/// through `off_reactor` queues behind a task that holds the `config.toml`
/// lock across an `.await`. Run inline, its blocking wait would freeze that
/// task, which then could never release the lock, and the edit would time out.
#[tokio::test(flavor = "current_thread")]
async fn a_plugin_edit_waits_for_an_async_lock_holder_instead_of_starving_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let (locked_tx, locked_rx) = tokio::sync::oneshot::channel();
    let holder = {
        let path = path.clone();
        tokio::spawn(async move {
            let lock = fuigo_config::fs_atomic::lock_config_for_write(&path).unwrap();
            locked_tx.send(()).unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            drop(lock);
        })
    };
    // The holder has the lock before the edit starts.
    locked_rx.await.unwrap();

    let edit = {
        let path = path.clone();
        super::super::off_reactor(move || add_plugin_path_in("/p/queued", &path)).await
    };

    holder.await.unwrap();
    edit.expect("the edit must queue behind the async holder, not time out");
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("/p/queued")
    );
}

/// An access ACL listed on the original but gone before it could be read is
/// not "copied": an ACL the temp inherited from the directory's default ACL is
/// still stripped, so the replacement never grants that inherited entry.
#[cfg(target_os = "linux")]
#[test]
fn a_vanished_original_acl_still_strips_the_inherited_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "a = 1\n").unwrap();
    let setfacl = |args: &[&str], p: &std::path::Path| {
        std::process::Command::new("setfacl")
            .args(args)
            .arg(p)
            .status()
            .is_ok_and(|s| s.success())
    };
    if !(setfacl(&["-m", "u:nobody:rw-"], &path)
        && setfacl(&["-d", "-m", "u:daemon:rw-"], dir.path()))
    {
        eprintln!(
            "SKIP a_vanished_original_acl_still_strips_the_inherited_one: setfacl unavailable"
        );
        return;
    }
    let acl_of = |p: &std::path::Path| {
        let out = std::process::Command::new("getfacl")
            .args(["--omit-header", "--absolute-names"])
            .arg(p)
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap()
    };

    super::fault::ACL_VANISHES.with(|c| c.set(true));
    let result = add_plugin_path_in("/p/new", &path);
    super::fault::ACL_VANISHES.with(|c| c.set(false));
    result.unwrap();

    let after = acl_of(&path);
    assert!(
        !after.contains("daemon"),
        "the inherited default ACL leaked onto the replacement:\n{after}"
    );
}

/// Windows: `icacls` entries of `p` (path prefix and summary line dropped), sorted.
#[cfg(windows)]
fn icacls_entries(p: &Path) -> Vec<String> {
    let out = std::process::Command::new("icacls")
        .arg(p)
        .output()
        .unwrap();
    assert!(out.status.success(), "icacls failed");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let path = p.to_str().unwrap();
    let mut v: Vec<String> = text
        .lines()
        .map(|l| l.trim_start_matches(path).trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with("Successfully"))
        .collect();
    v.sort();
    v
}

/// Windows: a directory handing Everyone inheritable read, and a config.toml in it.
#[cfg(windows)]
fn everyone_readable_dir() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let ok = std::process::Command::new("icacls")
        .arg(dir.path())
        .args(["/grant", "*S-1-1-0:(OI)(CI)R"])
        .status()
        .unwrap()
        .success();
    assert!(ok, "icacls /grant failed");
    let file = dir.path().join("config.toml");
    std::fs::write(&file, "a = 1\n").unwrap();
    (dir, file)
}

/// Windows: a protected owner-only DACL survives the replacement exactly, even
/// in a directory that would hand the temp file Everyone:read.
#[cfg(windows)]
#[test]
fn a_protected_dacl_is_kept_exactly() {
    let (_dir, file) = everyone_readable_dir();
    let me = std::env::var("USERNAME").unwrap();
    let ok = std::process::Command::new("icacls")
        .arg(&file)
        .args(["/inheritance:r", "/grant:r", &format!("{me}:F")])
        .status()
        .unwrap()
        .success();
    assert!(ok, "icacls /inheritance:r failed");
    let before = icacls_entries(&file);

    write_file_atomically(&file, b"b = 2\n").unwrap();

    assert_eq!(std::fs::read_to_string(&file).unwrap(), "b = 2\n");
    assert_eq!(icacls_entries(&file), before);
}

/// P49: the plugin-list writer fills and syncs its temp while ANOTHER writer
/// holds the `config.toml` lock, and only renames once it gets the lock. The
/// temp therefore shows up while the lock is still held by someone else.
// macOS stages inside a private subdirectory; Windows has no optimistic pass.
#[cfg(not(any(target_os = "macos", windows)))]
#[test]
fn the_plugin_list_writer_stages_outside_the_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "[plugins]\npaths = [\"/old\"]\n").unwrap();
    let held = fuigo_config::fs_atomic::lock_config_for_write(&path).unwrap();
    let writer = {
        let path = path.clone();
        std::thread::spawn(move || add_plugin_path_in("/new", &path).map_err(|e| e.to_string()))
    };
    let temp_seen = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            let staged = std::fs::read_dir(dir.path()).unwrap().any(|e| {
                let n = e.unwrap().file_name().to_string_lossy().into_owned();
                n.starts_with(".config.toml.") && n.ends_with(".tmp")
            });
            if staged || std::time::Instant::now() >= deadline {
                break staged;
            }
            std::thread::yield_now();
        }
    };
    // Not renamed yet: the old file is still in place while the lock is held.
    let during = std::fs::read_to_string(&path).unwrap();
    drop(held);
    writer.join().unwrap().unwrap();
    assert!(temp_seen, "the temp must be staged while another writer holds the lock");
    assert!(!during.contains("/new"), "renamed without the lock: {during}");
    let v: toml::Value = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let paths: Vec<&str> = v["plugins"]["paths"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(toml::Value::as_str)
        .collect();
    assert_eq!(paths, ["/old", "/new"]);
}
