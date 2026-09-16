//! NFS worktree removal: daemon-first, verified-unmount, then confined backing delete.
//!
//! Never `umount -f`. Unverifiable unmount retains backing + pin. With the
//! daemon down, the pin is deleted through `liveness::delete_pin_ref_gated`
//! (the gate pin GC deletes through as well) and the backing dir through
//! `confined::delete_backing_dir_confined`, whose only caller this is — so
//! neither delete has a weaker sibling here. A grove record with no known
//! backing location fails closed before either runs.
use super::NfsWorktreeOpts;
use super::client::NfsWorktreeClient;
use super::confined::{delete_backing_dir_confined, is_safe_worktree_id};
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
        // The backing dir is the worktree's actual content; dest is only the
        // mount view of it. Without a known backing location — no `grove.backing`
        // in the DB row and no marker under any candidate data dir naming this
        // dest — proceeding would delete the pin, let the caller `rm -rf` dest and
        // unregister the record, and leave that content on disk with nothing
        // tracking it (and nothing to GC it: the daemon owns backing dirs). So
        // fail closed here, BEFORE the pin is touched, and let the daemon-up
        // retry do it; the daemon knows where its backing lives.
        let Some(data_dir) = m.data_dir.as_ref() else {
            bail!(
                "unmounted dest {} has grove metadata for {id} but no backing \
                 location (no recorded backing path and no marker names it); \
                 retaining pin and dest — rm again with the grove daemon running",
                worktree_path.display()
            );
        };
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
        delete_backing_dir_confined(data_dir, id).with_context(|| {
            format!(
                "deleting backing for {id} under {}; retaining dest",
                data_dir.display()
            )
        })?;
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
    // The upstream journal-driven remove test (`confined::tests::plant_journal`)
    // was never published with this tree; the daemon-down path is covered by the
    // `daemon_down_rm_*` tests below instead.
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
        let found = with_daemon_down(&data, tmp.path(), || lookup_nfs_meta(&dest));
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
        let found = with_daemon_down(&data, tmp.path(), || lookup_from_markers(&dest));
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

    // ---- daemon-down `rm` -------------------------------------------------------
    //
    // Every test below drives the PUBLIC entry point, `try_nfs_remove`, with the
    // daemon unreachable (`GROVE_CONTROL_SOCK` points at a socket that does not
    // exist) and dest a plain directory the mount table shows as unmounted. That
    // is the exact path `remove_worktree_from_disk` takes for a grove worktree
    // whose daemon is down, so the `dest_is_mountpoint` / `dest_is_known_unmounted`
    // / `dest_is_projected_mount` triage in `try_nfs_remove` is under test too,
    // not only the arm behind it.

    /// Write a backing marker naming `dest` into `backing_dir`.
    fn write_marker(backing_dir: &Path, id: &str, dest: &Path, source: &Path) {
        std::fs::create_dir_all(backing_dir).unwrap();
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
            backing_dir.join(BACKING_MARKER_FILE),
            serde_json::to_vec(&marker).unwrap(),
        )
        .unwrap();
    }

    /// Plant a real backing dir with a marker naming `dest` and return `(data, backing)`.
    fn plant_backing(root: &Path, id: &str, dest: &Path, source: &Path) -> (PathBuf, PathBuf) {
        let data = root.join("grove");
        let backing = data.join(WORKTREE_BACKING_DIR).join(id);
        write_marker(&backing, id, dest, source);
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

    /// A seeded source repo with `refs/fuigo/worktrees/<id>` pinned at HEAD, and
    /// an existing plain dest dir. Returns `(repo, pin, dest)`.
    fn pinned_repo_and_dest(tmp: &Path, id: &str) -> (PathBuf, String, PathBuf) {
        let repo = tmp.join("repo");
        std::fs::create_dir(&repo).unwrap();
        fuigo_test_utils::git::init_git_repo(&repo);
        std::fs::write(repo.join("a.txt"), "a").unwrap();
        fuigo_test_utils::git::git_commit_all(&repo, "seed");
        let head = fuigo_test_utils::git::run_git(&repo, &["rev-parse", "HEAD"]);
        let pin = format!("refs/fuigo/worktrees/{id}");
        fuigo_test_utils::git::run_git(&repo, &["update-ref", &pin, &head]);
        assert!(pin_present(&repo, &pin), "fixture must start pinned");
        let dest = tmp.join("wt");
        std::fs::create_dir(&dest).unwrap();
        (repo, pin, dest)
    }

    /// Run `f` with the daemon down (`GROVE_CONTROL_SOCK` -> a socket that does
    /// not exist) and grove lookup pointed at `data`. Under `metadata` the
    /// registry is isolated as well, through `FuigoHomeFixture`, so
    /// `lookup_nfs_meta`'s DB probe never opens the developer's own; the fixture
    /// owns the grove env lock for its lifetime, so the env is set through it.
    fn with_daemon_down<T>(data: &Path, tmp: &Path, f: impl FnOnce() -> T) -> T {
        let sock = tmp.join("absent.sock");
        #[cfg(feature = "metadata")]
        {
            let mut fx = crate::db::FuigoHomeFixture::new();
            fx.set_grove_env(data, &sock);
            f()
        }
        #[cfg(not(feature = "metadata"))]
        {
            let _env = crate::nfs::GroveEnvGuard::set(data, &sock);
            f()
        }
    }

    /// The public `try_nfs_remove` on `dest`, daemon down, grove at `data`.
    fn daemon_down_rm(dest: &Path, data: &Path, tmp: &Path) -> Result<Option<RemoveReport>> {
        with_daemon_down(data, tmp, || try_nfs_remove(dest))
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
        let id = "wt-rm-daemon-down";
        let (repo, pin, dest) = pinned_repo_and_dest(tmp.path(), id);
        let (data, backing) = plant_backing(tmp.path(), id, &dest, &repo);
        // Nested content, including a symlink pointing OUT of the backing dir:
        // the deleter must unlink the link, never follow it.
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir_all(elsewhere.join("precious")).unwrap();
        std::fs::create_dir_all(backing.join("objects/aa")).unwrap();
        std::fs::write(backing.join("objects/aa/blob"), b"x").unwrap();
        std::os::unix::fs::symlink(&elsewhere, backing.join("escape")).unwrap();

        let out = daemon_down_rm(&dest, &data, tmp.path());

        let report = out.expect("daemon-down rm of an unmounted grove dest must complete");
        assert!(
            report.is_none(),
            "dest still exists, so the caller must rm -rf it and unregister"
        );
        assert!(
            !pin_present(&repo, &pin),
            "pin {pin} must be deleted, not retained"
        );
        assert!(
            !backing.exists(),
            "backing {} must be deleted after a verified unmount",
            backing.display()
        );
        assert!(
            elsewhere.join("precious").is_dir(),
            "a symlink inside the backing dir is unlinked, never followed"
        );
        assert!(dest.is_dir(), "dest itself is the caller's to remove");
    }

    /// Lay out `<data>/worktree-backing/<id>` where ONE component is a symlink
    /// into `elsewhere`, with the marker naming `dest` at the far end so the
    /// lookup reaches it exactly the way the round-2 auditor reproduced. Returns
    /// `(data, link, target)`: the data dir to point grove at, the planted link,
    /// and the out-of-tree directory that must survive.
    #[derive(Clone, Copy, Debug)]
    enum Linked {
        /// `<data>/worktree-backing/<id>` -> `elsewhere/<id>`
        Id,
        /// `<data>/worktree-backing` -> `elsewhere/backing-root`
        BackingRoot,
        /// `<data>` -> `elsewhere/grove`
        DataDir,
    }
    fn plant_escape(
        tmp: &Path,
        id: &str,
        dest: &Path,
        source: &Path,
        which: Linked,
    ) -> (PathBuf, PathBuf, PathBuf) {
        let elsewhere = tmp.join("elsewhere");
        let data = tmp.join("grove");
        match which {
            Linked::Id => {
                let target = elsewhere.join(id);
                write_marker(&target, id, dest, source);
                std::fs::create_dir_all(target.join("precious")).unwrap();
                std::fs::create_dir_all(data.join(WORKTREE_BACKING_DIR)).unwrap();
                let link = data.join(WORKTREE_BACKING_DIR).join(id);
                std::os::unix::fs::symlink(&target, &link).unwrap();
                (data, link, target)
            }
            Linked::BackingRoot => {
                let target = elsewhere.join("backing-root");
                write_marker(&target.join(id), id, dest, source);
                std::fs::create_dir_all(target.join(id).join("precious")).unwrap();
                std::fs::create_dir_all(&data).unwrap();
                let link = data.join(WORKTREE_BACKING_DIR);
                std::os::unix::fs::symlink(&target, &link).unwrap();
                (data, link, target.join(id))
            }
            Linked::DataDir => {
                let target = elsewhere.join("grove");
                let backing = target.join(WORKTREE_BACKING_DIR).join(id);
                write_marker(&backing, id, dest, source);
                std::fs::create_dir_all(backing.join("precious")).unwrap();
                std::os::unix::fs::symlink(&target, &data).unwrap();
                (data.clone(), data, backing)
            }
        }
    }

    fn assert_escape_refused(which: Linked) {
        fuigo_test_utils::require_git!();
        let tmp = TempDir::new().unwrap();
        let id = "wt-rm-escape";
        let (repo, _pin, dest) = pinned_repo_and_dest(tmp.path(), id);
        let (data, link, target) = plant_escape(tmp.path(), id, &dest, &repo, which);
        assert!(
            target.join("precious").is_dir(),
            "{which:?}: fixture must start with the out-of-tree target present"
        );

        let out = daemon_down_rm(&dest, &data, tmp.path());

        let err = match out {
            Err(e) => e,
            Ok(report) => panic!(
                "{which:?}: a symlinked component must be refused, not followed; \
                 got {report:?} and the out-of-tree target {} {}",
                target.display(),
                if target.join("precious").is_dir() {
                    "survived"
                } else {
                    "WAS DELETED"
                }
            ),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("symlink"),
            "{which:?}: the refusal must name the symlink, got: {msg}"
        );
        assert!(
            target.join("precious").is_dir(),
            "{which:?}: the out-of-tree target {} must be untouched",
            target.display()
        );
        assert!(
            target.join(BACKING_MARKER_FILE).is_file(),
            "{which:?}: nothing behind the link may be deleted, not even the marker"
        );
        assert!(
            link.symlink_metadata()
                .is_ok_and(|m| m.file_type().is_symlink()),
            "{which:?}: the planted link itself stays for the operator to see"
        );
    }

    /// `<data>/worktree-backing/<id>` is itself a symlink out of the data dir.
    #[test]
    fn daemon_down_rm_refuses_a_symlinked_backing_entry() {
        assert_escape_refused(Linked::Id);
    }

    /// `<data>/worktree-backing` is a symlink: `symlink_metadata` on the full
    /// path declines to follow only the FINAL component, so before the fix the
    /// walk went through this link, the marker was found behind it, and
    /// `remove_dir_all` deleted the out-of-tree `<id>` directory.
    #[test]
    fn daemon_down_rm_refuses_a_symlinked_worktree_backing_dir() {
        assert_escape_refused(Linked::BackingRoot);
    }

    /// `<data>` itself is a symlink. The data dir's ANCESTORS are trusted and
    /// followed (macOS's `/var` -> `/private/var` is one), but the data dir
    /// entry is where confinement starts, so a link there is refused too.
    #[test]
    fn daemon_down_rm_refuses_a_symlinked_data_dir() {
        assert_escape_refused(Linked::DataDir);
    }

    /// The boundary of the gate, pinned so it cannot silently widen or narrow:
    /// a symlink on a component ABOVE the data dir is followed. This is what
    /// every tempdir on macOS looks like (`/var` -> `/private/var`), and the
    /// canonical location of what is deleted is still
    /// `<canonical data dir>/worktree-backing/<id>`.
    #[test]
    fn daemon_down_rm_follows_a_symlinked_ancestor_of_the_data_dir() {
        fuigo_test_utils::require_git!();
        let tmp = TempDir::new().unwrap();
        let id = "wt-rm-ancestor-link";
        let (repo, pin, dest) = pinned_repo_and_dest(tmp.path(), id);
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let (_, backing) = plant_backing(&real, id, &dest, &repo);
        let via_link = tmp.path().join("via-link");
        std::os::unix::fs::symlink(&real, &via_link).unwrap();
        let data = via_link.join("grove");

        let out = daemon_down_rm(&dest, &data, tmp.path());

        out.expect("an ancestor symlink is the trusted root's own location");
        assert!(!pin_present(&repo, &pin), "pin must be deleted");
        assert!(
            !backing.exists(),
            "backing {} must be deleted through the ancestor link",
            backing.display()
        );
        assert!(
            real.join("grove").join(WORKTREE_BACKING_DIR).is_dir(),
            "only `<id>` goes; `worktree-backing` stays"
        );
    }

    /// A grove record whose backing location is UNKNOWN (no `grove.backing` in
    /// the DB row and no marker under any candidate data dir naming this dest)
    /// must fail closed BEFORE the pin is touched. Proceeding would delete the
    /// pin, hand dest to the caller's `rm -rf` and unregister the record while
    /// the backing dir — the worktree's actual content — stays on disk with
    /// nothing tracking it.
    #[cfg(feature = "metadata")]
    #[test]
    fn daemon_down_rm_with_unknown_backing_location_retains_pin_and_dest() {
        fuigo_test_utils::require_git!();
        let tmp = TempDir::new().unwrap();
        let id = "wt-rm-no-backing-path";
        let (repo, pin, dest) = pinned_repo_and_dest(tmp.path(), id);
        // A data dir with no marker for this dest, so marker lookup misses.
        let data = tmp.path().join("grove");
        std::fs::create_dir_all(data.join(WORKTREE_BACKING_DIR)).unwrap();

        let mut fx = crate::db::FuigoHomeFixture::new();
        let db = crate::db::WorktreeDb::open(&fx.home).unwrap();
        // `WorktreeDb::get` canonicalises a path before lookup, so the record
        // is stored the way a real registration would be found.
        let registered = dunce::canonicalize(&dest).unwrap();
        db.register(&crate::db::WorktreeRecord {
            source_repo: repo.clone(),
            creation_mode: crate::worktree::STRATEGY_GROVE_NFS.to_string(),
            metadata: Some(serde_json::json!({
                "grove": { "transport": "nfs", "mount_id": 7, "source_pin": pin }
            })),
            ..crate::test_support::worktree_record(id, registered)
        })
        .unwrap();
        fx.set_grove_env(&data, &tmp.path().join("absent.sock"));
        let out = try_nfs_remove(&dest);

        let err = match out {
            Err(e) => e,
            Ok(report) => panic!(
                "unknown backing location must fail closed; got {report:?}, pin {pin} {}, \
                 dest {}",
                if pin_present(&repo, &pin) {
                    "still present"
                } else {
                    "WAS DELETED"
                },
                if dest.is_dir() { "present" } else { "gone" }
            ),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("backing") && msg.contains("retaining pin and dest"),
            "the refusal must say what is retained and why, got: {msg}"
        );
        assert!(
            pin_present(&repo, &pin),
            "the pin must survive: nothing may be half-collected"
        );
        assert!(dest.is_dir(), "dest must survive for the daemon-up retry");
        assert!(
            db.get(&dest.to_string_lossy()).unwrap().is_some(),
            "try_nfs_remove never touches the registry"
        );
    }
}
