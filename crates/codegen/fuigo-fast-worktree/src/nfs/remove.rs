//! NFS worktree removal: daemon-first, verified-unmount, then confined backing delete.
//!
//! Never `umount -f`. Unverifiable unmount retains backing + pin.
use super::NfsWorktreeOpts;
use super::client::NfsWorktreeClient;
use super::confined::is_safe_worktree_id;
use super::liveness::{BACKING_MARKER_FILE, BackingMarker};
use super::mount_table::{dest_is_mountpoint, dest_is_projected_mount};
use crate::RemoveReport;
use anyhow::Context;
use anyhow::{Result, bail};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
pub fn try_nfs_remove(worktree_path: &Path) -> Result<Option<RemoveReport>> {
    if !dest_is_mountpoint(worktree_path) && !super::dest_is_known_unmounted(worktree_path) {
        bail!(
            "mount table inconclusive for {}; refusing remove",
            worktree_path.display()
        );
    }
    let is_projected = dest_is_projected_mount(worktree_path);
    if is_projected {
        if lookup_from_markers(worktree_path).is_none() {
            bail!(
                "{} is a live grove mount without a backing marker; refusing rm -rf",
                worktree_path.display()
            );
        }
    } else if dest_is_mountpoint(worktree_path) || lookup_nfs_meta(worktree_path).is_none() {
        return Ok(None);
    }
    remove_nfs_worktree(worktree_path)
}
fn remove_nfs_worktree(worktree_path: &Path) -> Result<Option<RemoveReport>> {
    let opts = nfs_opts_from_env_and_meta(None);
    let client = NfsWorktreeClient::from_opts(&opts);
    if client.ping() {
        match client.remove_worktree(worktree_path, false) {
            Ok(()) => return report_after_daemon_unmount(worktree_path),
            Err(e) => {
                bail!("daemon RemoveWorktree failed: {e}");
            }
        }
    }
    if dest_is_mountpoint(worktree_path) {
        if lookup_from_markers(worktree_path).is_none() {
            bail!(
                "{} is still a mountpoint without a grove marker; refusing umount/rm",
                worktree_path.display()
            );
        }
        plain_umount(worktree_path)?;
    }
    if !super::dest_is_known_unmounted(worktree_path) {
        bail!(
            "unmount of {} could not be verified (still mounted or mount table \
             inconclusive); retaining backing and pin",
            worktree_path.display()
        );
    }
    let meta = lookup_nfs_meta(worktree_path);
    if let Some(m) = meta.as_ref() {
        let Some(id) = m.worktree_id.as_deref() else {
            bail!(
                "unmounted dest {} has grove metadata without a worktree id; \
                 retaining pin and dest",
                worktree_path.display()
            );
        };
        if !is_safe_worktree_id(id) {
            bail!(
                "unmounted dest {} has unsafe worktree id {id:?}; retaining pin and dest",
                worktree_path.display()
            );
        }
        // Pin first, backing second, and both fail closed. A failed pin delete
        // leaves the backing dir in place, which keeps `gc_orphan_pins` calling the
        // id live, so nothing is half-collected between the operator's retries; a
        // failed backing delete leaves no pin to leak, and `git update-ref -d` is a
        // no-op on an absent ref, so the retry is clean either way.
        if let Some(src) = m.source.as_ref() {
            // A source repo that is no longer on disk has no refdb and therefore no
            // pin: `git update-ref` there would fail to even spawn and strand the
            // dest forever. Absent source = nothing pinned.
            if src.exists() {
                super::liveness::delete_pin_ref_gated(src, id).with_context(|| {
                    format!(
                        "deleting pin for {id} in {}; retaining backing and dest",
                        src.display()
                    )
                })?;
            }
        }
        if let Some(data_dir) = m.data_dir.as_ref() {
            delete_backing_dir_gated(data_dir, id).with_context(|| {
                format!(
                    "deleting backing for {id} under {}; retaining dest",
                    data_dir.display()
                )
            })?;
        }
    }
    if !super::dest_is_known_unmounted(worktree_path) {
        bail!(
            "mount table inconclusive for {}; refusing dest delete",
            worktree_path.display()
        );
    }
    if worktree_path.is_dir() {
        return Ok(None);
    }
    Ok(Some(RemoveReport {
        used_btrfs_delete: false,
        unmounted_bind: false,
        unmounted_overlay: false,
    }))
}
/// Delete exactly `<data_dir>/worktree-backing/<id>`, and only after the unmount
/// above was verified.
///
/// This is the deleter that runs with the daemon down, so it re-validates the id
/// and refuses anything at that path that is not a real directory: the entry is
/// read back with `symlink_metadata`, never `metadata`, so a symlink planted in a
/// grove data dir cannot redirect the delete out of `worktree-backing/`. An entry
/// that is already gone is success — `rm` is retried after a partial failure.
///
/// The backing dir must go: [`super::liveness::gc_orphan_pins`] treats a surviving
/// backing dir as proof the id is live, so leaving it behind pins the worktree's
/// objects for good even once the ref is deleted.
fn delete_backing_dir_gated(data_dir: &Path, worktree_id: &str) -> Result<()> {
    if !is_safe_worktree_id(worktree_id) {
        bail!("refusing backing delete for unsafe worktree id {worktree_id:?}");
    }
    let backing = data_dir
        .join(super::liveness::WORKTREE_BACKING_DIR)
        .join(worktree_id);
    match std::fs::symlink_metadata(&backing) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(e).context(format!("stat backing {}", backing.display()));
        }
        Ok(md) if md.file_type().is_symlink() => {
            bail!(
                "backing {} is a symlink; refusing to follow it out of {}",
                backing.display(),
                super::liveness::WORKTREE_BACKING_DIR
            );
        }
        Ok(md) if !md.is_dir() => {
            bail!(
                "backing {} is not a directory; refusing delete",
                backing.display()
            );
        }
        Ok(_) => {}
    }
    std::fs::remove_dir_all(&backing)
        .with_context(|| format!("removing backing {}", backing.display()))
}

/// After a successful daemon `RemoveWorktree`, dest is no longer a mount.
/// The daemon already deleted backing/pin; a leftover dest directory must
/// be `Ok(None)` so the caller `rm -rf`s and unregisters. When dest is fully
/// gone, return `Ok(Some(...))` so the caller does not need a second delete.
fn report_after_daemon_unmount(worktree_path: &Path) -> Result<Option<RemoveReport>> {
    if !super::dest_is_known_unmounted(worktree_path) {
        bail!(
            "RemoveWorktree returned ok but {} is still a mount or the mount table is inconclusive",
            worktree_path.display()
        );
    }
    if worktree_path.is_dir() {
        return Ok(None);
    }
    Ok(Some(RemoveReport {
        used_btrfs_delete: false,
        unmounted_bind: false,
        unmounted_overlay: false,
    }))
}
fn plain_umount(dest: &Path) -> Result<()> {
    {
        let mut cmd = std::process::Command::new("umount");
        fuigo_tty_utils::detach_std_command(&mut cmd);
        cmd.arg(dest).stdin(Stdio::null());
        #[allow(clippy::disallowed_methods)]
        let child = cmd.spawn().context("umount")?;
        let group = fuigo_tty_utils::global_process_scope()
            .enroll_std(&child)
            .context("enroll umount")?;
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&done);
        let group_kill = std::sync::Arc::clone(&group);
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(5));
            if !flag.load(std::sync::atomic::Ordering::SeqCst) {
                let _ = group_kill.kill();
            }
        });
        let out = child.wait_with_output().context("umount wait")?;
        done.store(true, std::sync::atomic::Ordering::SeqCst);
        drop(group);
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            tracing::warn!(dest = %dest.display(), error = %err, "umount failed");
        }
        Ok(())
    }
}
const MAX_MARKER_BYTES: u64 = 64 * 1024;
struct NfsRemoveMeta {
    worktree_id: Option<String>,
    data_dir: Option<PathBuf>,
    source: Option<PathBuf>,
    control_sock: Option<PathBuf>,
    runtime_dir: Option<PathBuf>,
}
fn lookup_nfs_meta(worktree_path: &Path) -> Option<NfsRemoveMeta> {
    #[cfg(feature = "metadata")]
    {
        if let Ok(db) = crate::db::WorktreeDb::open_default()
            && let Ok(Some(rec)) = db.get(&worktree_path.to_string_lossy())
            && crate::worktree::is_grove_strategy(&rec.creation_mode)
        {
            let nfs = rec
                .metadata
                .as_ref()
                .and_then(|m| m.get("grove").or_else(|| m.get("nfs")));
            let backing = nfs
                .and_then(|n| n.get("backing"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(PathBuf::from);
            let data_dir = backing
                .as_ref()
                .and_then(|b| b.parent())
                .and_then(|p| p.parent())
                .map(Path::to_path_buf);
            let from_db = NfsRemoveMeta {
                worktree_id: Some(rec.id),
                data_dir,
                source: Some(rec.source_repo),
                control_sock: std::env::var_os("GROVE_CONTROL_SOCK").map(PathBuf::from),
                runtime_dir: None,
            };
            if from_db.data_dir.is_some() {
                return Some(from_db);
            }
            if let Some(from_marker) = lookup_from_markers(worktree_path) {
                return Some(NfsRemoveMeta {
                    worktree_id: from_marker.worktree_id.or(from_db.worktree_id),
                    data_dir: from_marker.data_dir,
                    source: from_marker.source.or(from_db.source),
                    control_sock: from_db.control_sock.or(from_marker.control_sock),
                    runtime_dir: from_db.runtime_dir.or(from_marker.runtime_dir),
                });
            }
            return Some(from_db);
        }
    }
    lookup_from_markers(worktree_path)
}
fn lookup_from_markers(worktree_path: &Path) -> Option<NfsRemoveMeta> {
    for data in super::liveness::candidate_data_dirs() {
        let root = data.join(super::liveness::WORKTREE_BACKING_DIR);
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for ent in entries.flatten() {
            let dirent = ent.file_name().to_string_lossy().into_owned();
            if !is_safe_worktree_id(&dirent) {
                continue;
            }
            let bytes = match std::fs::read(ent.path().join(BACKING_MARKER_FILE)) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let Some(marker) = super::liveness::marker_from_dirent(&dirent, &bytes) else {
                continue;
            };
            if super::mount_table::dest_paths_equivalent(&marker.dest, worktree_path) {
                return Some(NfsRemoveMeta {
                    worktree_id: Some(dirent),
                    data_dir: Some(data),
                    source: Some(marker.source_repo),
                    control_sock: std::env::var_os("GROVE_CONTROL_SOCK").map(PathBuf::from),
                    runtime_dir: None,
                });
            }
        }
    }
    None
}
fn nfs_opts_from_env_and_meta(meta: Option<&NfsRemoveMeta>) -> NfsWorktreeOpts {
    NfsWorktreeOpts {
        enabled: true,
        control_sock: meta
            .and_then(|m| m.control_sock.clone())
            .or_else(|| std::env::var_os("GROVE_CONTROL_SOCK").map(PathBuf::from)),
        data_dir: meta.and_then(|m| m.data_dir.clone()),
        runtime_dir: meta.and_then(|m| m.runtime_dir.clone()),
        ..NfsWorktreeOpts::default()
    }
}
/// Read a backing marker from an already-open backing dir (tests / rebuild).
#[allow(dead_code)]
pub fn read_backing_marker(backing: &Path) -> Option<BackingMarker> {
    let file = std::fs::File::open(backing.join(BACKING_MARKER_FILE)).ok()?;
    let mut buf = Vec::new();
    Read::take(file, MAX_MARKER_BYTES.saturating_add(1))
        .read_to_end(&mut buf)
        .ok()?;
    if buf.len() as u64 > MAX_MARKER_BYTES {
        return None;
    }
    serde_json::from_slice(&buf).ok()
}
#[cfg(test)]
mod tests {
    use super::super::liveness::WORKTREE_BACKING_DIR;
    use super::*;
    use tempfile::TempDir;
    #[test]
    fn non_nfs_path_returns_none() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("plain");
        std::fs::create_dir(&p).unwrap();
        assert!(try_nfs_remove(&p).unwrap().is_none());
    }
    // REMOVED: this test drove `crate::nfs::confined::tests::plant_journal`.
    // `confined.rs` in the public sync is a 9-line stub — the owned deleter and
    // its journal were never published, so the behaviour under test does not
    // exist in this tree and the reference broke the whole crate test build.
    #[test]
    fn marker_lookup_finds_dest() {
        let tmp = TempDir::new().unwrap();
        let data = tmp.path().join("grove");
        let dest = tmp.path().join("wt");
        std::fs::create_dir(&dest).unwrap();
        let id = "wt-rm1";
        let backing = data.join(WORKTREE_BACKING_DIR).join(id);
        std::fs::create_dir_all(&backing).unwrap();
        let marker = BackingMarker {
            schema: 1,
            worktree_id: id.into(),
            dest: dest.clone(),
            source_repo: tmp.path().join("repo"),
            pin_ref: format!("refs/fuigo/worktrees/{id}"),
            mount_id: 1,
            created_at: 1,
        };
        std::fs::write(
            backing.join(BACKING_MARKER_FILE),
            serde_json::to_vec(&marker).unwrap(),
        )
        .unwrap();
        let _env = crate::nfs::GROVE_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("GROVE_DATA_DIR", &data) };
        let found = lookup_nfs_meta(&dest);
        unsafe { std::env::remove_var("GROVE_DATA_DIR") };
        let found = found.expect("marker must resolve dest");
        assert_eq!(found.worktree_id.as_deref(), Some(id));
    }
    #[test]
    fn empty_backing_falls_through_to_marker() {
        let tmp = TempDir::new().unwrap();
        let data = tmp.path().join("grove");
        let dest = tmp.path().join("wt");
        std::fs::create_dir(&dest).unwrap();
        let id = "wt-empty-back";
        let backing = data.join(WORKTREE_BACKING_DIR).join(id);
        std::fs::create_dir_all(&backing).unwrap();
        let marker = BackingMarker {
            schema: 1,
            worktree_id: id.into(),
            dest: dest.clone(),
            source_repo: tmp.path().join("repo"),
            pin_ref: format!("refs/fuigo/worktrees/{id}"),
            mount_id: 1,
            created_at: 1,
        };
        std::fs::write(
            backing.join(BACKING_MARKER_FILE),
            serde_json::to_vec(&marker).unwrap(),
        )
        .unwrap();
        let _env = crate::nfs::GROVE_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("GROVE_DATA_DIR", &data) };
        let found = lookup_from_markers(&dest);
        unsafe { std::env::remove_var("GROVE_DATA_DIR") };
        let found = found.expect("marker recovery");
        assert_eq!(found.worktree_id.as_deref(), Some(id));
        assert_eq!(found.data_dir.as_deref(), Some(data.as_path()));
    }
    #[test]
    fn leftover_dest_after_daemon_unmount_is_ok_none() {
        let tmp = TempDir::new().unwrap();
        let dest = tmp.path().join("wt");
        std::fs::create_dir(&dest).unwrap();
        assert!(report_after_daemon_unmount(&dest).unwrap().is_none());
        assert!(dest.is_dir(), "helper must not delete leftover dest");
    }
    #[test]
    fn absent_dest_after_daemon_unmount_is_some() {
        let tmp = TempDir::new().unwrap();
        let dest = tmp.path().join("gone");
        assert!(report_after_daemon_unmount(&dest).unwrap().is_some());
    }

    /// Plant a backing dir with a marker naming `dest` and return `(data, backing)`.
    fn plant_backing(root: &Path, id: &str, dest: &Path, source: &Path) -> (PathBuf, PathBuf) {
        let data = root.join("grove");
        let backing = data.join(WORKTREE_BACKING_DIR).join(id);
        std::fs::create_dir_all(&backing).unwrap();
        let marker = BackingMarker {
            schema: 1,
            worktree_id: id.into(),
            dest: dest.to_path_buf(),
            source_repo: source.to_path_buf(),
            pin_ref: format!("refs/fuigo/worktrees/{id}"),
            mount_id: 3,
            created_at: 1,
        };
        std::fs::write(
            backing.join(BACKING_MARKER_FILE),
            serde_json::to_vec(&marker).unwrap(),
        )
        .unwrap();
        (data, backing)
    }

    fn pin_present(repo: &Path, pin: &str) -> bool {
        crate::git::checkout::git_command()
            .current_dir(repo)
            .args(["show-ref", "--verify", "--quiet", pin])
            .status()
            .unwrap()
            .success()
    }

    /// With the daemon down, an already-unmounted grove dest must still have its
    /// pin ref and its backing dir deleted. Before the fix both arms were the
    /// bare block of a deleted `#[cfg]` pair and `bail!`d, so `rm` failed outright
    /// and left `refs/fuigo/worktrees/<id>` — and every object it kept reachable —
    /// pinned forever, with the surviving backing dir making pin GC call the id live.
    #[test]
    fn daemon_down_rm_deletes_pin_ref_and_backing() {
        fuigo_test_utils::require_git!();
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        fuigo_test_utils::git::init_git_repo(&repo);
        std::fs::write(repo.join("a.txt"), "a").unwrap();
        fuigo_test_utils::git::git_commit_all(&repo, "seed");
        let head = fuigo_test_utils::git::run_git(&repo, &["rev-parse", "HEAD"]);

        let id = "wt-rm-daemon-down";
        let pin = format!("refs/fuigo/worktrees/{id}");
        fuigo_test_utils::git::run_git(&repo, &["update-ref", &pin, &head]);
        assert!(pin_present(&repo, &pin), "fixture must start pinned");

        let dest = tmp.path().join("wt");
        std::fs::create_dir(&dest).unwrap();
        let (data, backing) = plant_backing(tmp.path(), id, &dest, &repo);

        let _env = crate::nfs::GROVE_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("GROVE_DATA_DIR", &data) };
        unsafe { std::env::set_var("GROVE_CONTROL_SOCK", tmp.path().join("absent.sock")) };
        let out = remove_nfs_worktree(&dest);
        unsafe { std::env::remove_var("GROVE_CONTROL_SOCK") };
        unsafe { std::env::remove_var("GROVE_DATA_DIR") };

        out.expect("daemon-down rm of an unmounted grove dest must complete");
        assert!(
            !pin_present(&repo, &pin),
            "pin {pin} must be deleted, not retained"
        );
        assert!(
            !backing.exists(),
            "backing {} must be deleted after a verified unmount",
            backing.display()
        );
    }

    /// The daemon-down deleter must not be a weaker sibling of the daemon's own:
    /// a symlink planted where `worktree-backing/<id>` belongs is refused, never
    /// followed, so a poisoned grove data dir cannot turn `rm` into a deleter of
    /// an arbitrary tree.
    #[test]
    fn daemon_down_rm_refuses_a_symlinked_backing_entry() {
        fuigo_test_utils::require_git!();
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        fuigo_test_utils::git::init_git_repo(&repo);
        std::fs::write(repo.join("a.txt"), "a").unwrap();
        fuigo_test_utils::git::git_commit_all(&repo, "seed");

        let id = "wt-rm-symlinked";
        let dest = tmp.path().join("wt");
        std::fs::create_dir(&dest).unwrap();

        // The marker lives in a tree outside the grove data dir, reachable only
        // through the planted link.
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir_all(elsewhere.join("precious")).unwrap();
        let marker = BackingMarker {
            schema: 1,
            worktree_id: id.into(),
            dest: dest.clone(),
            source_repo: repo.clone(),
            pin_ref: format!("refs/fuigo/worktrees/{id}"),
            mount_id: 4,
            created_at: 1,
        };
        std::fs::write(
            elsewhere.join(BACKING_MARKER_FILE),
            serde_json::to_vec(&marker).unwrap(),
        )
        .unwrap();
        let data = tmp.path().join("grove");
        std::fs::create_dir_all(data.join(WORKTREE_BACKING_DIR)).unwrap();
        let link = data.join(WORKTREE_BACKING_DIR).join(id);
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();

        let _env = crate::nfs::GROVE_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("GROVE_DATA_DIR", &data) };
        unsafe { std::env::set_var("GROVE_CONTROL_SOCK", tmp.path().join("absent.sock")) };
        let out = remove_nfs_worktree(&dest);
        unsafe { std::env::remove_var("GROVE_CONTROL_SOCK") };
        unsafe { std::env::remove_var("GROVE_DATA_DIR") };

        let err = out.expect_err("a symlinked backing entry must be refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("symlink"),
            "the refusal must name the symlink, got: {msg}"
        );
        assert!(
            elsewhere.join("precious").is_dir(),
            "the symlink target must be untouched"
        );
        assert!(
            link.symlink_metadata().is_ok(),
            "the planted link itself stays for the operator to see"
        );
    }
}
