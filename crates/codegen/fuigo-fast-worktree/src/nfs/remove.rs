//! NFS worktree removal: daemon-first, verified-unmount, then confined backing delete.
//!
//! Never `umount -f`. Unverifiable unmount retains backing + pin. With the
//! daemon down, the pin is deleted through `liveness::delete_pin_ref_gated`
//! (the gate pin GC deletes through as well) and the backing dir through
//! `confined::open_backing_dir_confined` + `ConfinedBackingDir::delete`, whose
//! only caller this is — so neither delete has a weaker sibling here. The
//! backing dir is opened (and every confinement refusal taken) BEFORE the pin
//! is touched. A grove record with no VERIFIED backing location — no recorded
//! `grove.backing` whose marker names this dest, and no marker under any
//! candidate data dir naming it — fails closed before either runs.
use super::NfsWorktreeOpts;
use super::client::NfsWorktreeClient;
use super::confined::{is_safe_worktree_id, open_backing_dir_confined};
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
        // mount view of it. Without a VERIFIED backing location — no
        // `grove.backing` in the DB row whose marker names this dest, and no
        // marker under any candidate data dir naming it — proceeding would
        // delete the pin, let the caller `rm -rf` dest and unregister the record,
        // and leave that content on disk with nothing tracking it (and nothing
        // to GC it: the daemon owns backing dirs). So fail closed here, BEFORE
        // the pin is touched, and let the daemon-up retry do it; the daemon
        // knows where its backing lives.
        let Some(data_dir) = m.data_dir.as_ref() else {
            let why = match m.stale_backing.as_ref() {
                None => "no recorded backing path and no marker names it".to_string(),
                Some(StaleBacking::Absent(p)) => format!(
                    "recorded backing {} does not exist and no marker names it",
                    p.display()
                ),
                Some(StaleBacking::Unmarked(p)) => format!(
                    "recorded backing {} carries no marker for this dest and no \
                     marker names it",
                    p.display()
                ),
            };
            bail!(
                "unmounted dest {} has grove metadata for {id} but no usable backing \
                 location ({why}); retaining pin and dest — rm again with the grove \
                 daemon running",
                worktree_path.display()
            );
        };
        // Open the backing dir first: every confinement refusal (a data dir or
        // backing root that does not exist, a symlink on any component, a
        // non-directory) is taken here, before the pin is touched, so a refused
        // `rm` leaves pin, backing and dest exactly as they were. `None` is the
        // one shape that proceeds without a backing dir to delete: `<id>` is
        // already gone from a previous partial `rm`.
        let backing = open_backing_dir_confined(data_dir, id).with_context(|| {
            format!(
                "opening backing for {id} under {}; retaining pin and dest",
                data_dir.display()
            )
        })?;
        // Pin first, backing second, and both fail closed. A failed pin delete
        // leaves the backing dir in place, which keeps `gc_orphan_pins` calling the
        // id live, so nothing is half-collected between the operator's retries; a
        // failed backing delete leaves no pin to leak, and `git update-ref -d` is a
        // no-op on an absent ref, so the retry is clean either way. The backing
        // delete goes through the fds opened above, so no rename of a component
        // above `<id>` between the open and the delete can redirect it.
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
        if let Some(backing) = backing {
            let shown = backing.shown().to_path_buf();
            backing.delete().with_context(|| {
                format!(
                    "deleting backing {} for {id}; retaining dest",
                    shown.display()
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
    /// A data dir whose `worktree-backing/<id>` was seen to carry a marker
    /// naming dest — either read through the DB-recorded `grove.backing`, or the
    /// candidate data dir a marker was found under. Never a bare recorded path.
    data_dir: Option<PathBuf>,
    source: Option<PathBuf>,
    control_sock: Option<PathBuf>,
    runtime_dir: Option<PathBuf>,
    /// The DB-recorded `grove.backing` when it could NOT be trusted, for the
    /// refusal message.
    stale_backing: Option<StaleBacking>,
}
/// Why a DB-recorded `grove.backing` was not used as the backing location.
#[derive(Debug)]
enum StaleBacking {
    /// The recorded backing dir does not exist (the operator moved
    /// `GROVE_DATA_DIR`, or the row outlived the data dir).
    Absent(PathBuf),
    /// The recorded backing dir exists but carries no marker naming this dest
    /// and this id, so nothing proves it is this worktree's content.
    Unmarked(PathBuf),
}
/// Whether `backing` (a DB-recorded `<data_dir>/worktree-backing/<id>`) carries
/// a marker that names this `id` and `dest`. Only then is the row's location
/// trusted for a delete: the marker is what the daemon writes into every
/// backing dir it owns, and it is the same proof `lookup_from_markers` demands.
fn recorded_backing_names_dest(backing: &Path, id: &str, dest: &Path) -> Result<(), StaleBacking> {
    if backing.symlink_metadata().is_err() {
        return Err(StaleBacking::Absent(backing.to_path_buf()));
    }
    let named = backing.file_name().and_then(|n| n.to_str()) == Some(id);
    let marker_ok = named
        && read_backing_marker(backing).is_some_and(|m| {
            m.worktree_id == id && super::mount_table::dest_paths_equivalent(&m.dest, dest)
        });
    if marker_ok {
        Ok(())
    } else {
        Err(StaleBacking::Unmarked(backing.to_path_buf()))
    }
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
            // The row's location is trusted only once its marker has been read:
            // a recorded path that no longer exists, or that holds no marker
            // naming this dest, is a "known but wrong" location, and deleting
            // relative to it (or calling its absence success) is how the pin got
            // deleted and dest unregistered while the REAL backing — found by
            // its marker under the live data dir — survived untracked.
            let (data_dir, stale_backing) = match backing.as_ref() {
                None => (None, None),
                Some(b) => match recorded_backing_names_dest(b, &rec.id, worktree_path) {
                    Ok(()) => (
                        b.parent().and_then(Path::parent).map(Path::to_path_buf),
                        None,
                    ),
                    Err(stale) => {
                        tracing::warn!(
                            dest = %worktree_path.display(),
                            recorded = %b.display(),
                            reason = ?stale,
                            "recorded grove backing path not trusted; falling back to markers"
                        );
                        (None, Some(stale))
                    }
                },
            };
            let from_db = NfsRemoveMeta {
                worktree_id: Some(rec.id),
                data_dir,
                source: Some(rec.source_repo),
                control_sock: std::env::var_os("GROVE_CONTROL_SOCK").map(PathBuf::from),
                runtime_dir: None,
                stale_backing,
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
                    stale_backing: from_db.stale_backing,
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
                    stale_backing: None,
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
/// Read a backing marker from a backing dir (`rm`'s DB-row verification, tests,
/// rebuild). Capped at `MAX_MARKER_BYTES`; anything larger or unparsable is `None`.
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
        let (repo, pin, dest) = pinned_repo_and_dest(tmp.path(), id);
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
        // The backing dir is opened, and every refusal taken, before the pin is
        // touched, so a refused rm leaves the pin exactly as it was.
        assert!(
            pin_present(&repo, &pin),
            "{which:?}: a refused rm must leave the pin in place"
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

    // ---- round 4: spelling-independence of the data dir gate ------------------

    /// `try_nfs_remove` with `GROVE_DATA_DIR` set to an ARBITRARY byte string
    /// (so a trailing `/`, `/.` or `//` survives into the env), daemon down.
    fn daemon_down_rm_spelled(
        dest: &Path,
        raw_data: &std::ffi::OsStr,
        tmp: &Path,
    ) -> Result<Option<RemoveReport>> {
        with_daemon_down(Path::new(raw_data), tmp, || try_nfs_remove(dest))
    }

    /// `data` with `suffix` appended byte-for-byte: `Path::join` would normalise
    /// the spelling away, which is the whole point of these tests.
    fn spelled(data: &Path, suffix: &str) -> std::ffi::OsString {
        let mut raw = data.as_os_str().to_os_string();
        raw.push(suffix);
        raw
    }

    /// The `Linked` escape arrangement with the data dir spelled `<data><suffix>`.
    /// POSIX resolves a trailing `/` (or `/.`) as "the directory this names" and
    /// FOLLOWS a symlink there even under `O_NOFOLLOW` — `open("<link>/",
    /// O_DIRECTORY|O_NOFOLLOW)` opens the target on Linux 6.8 and macOS 25 —
    /// so before the fix `GROVE_DATA_DIR=<link>/` went through the symlinked data
    /// dir the bare `<link>` spelling refuses, and deleted the out-of-tree target.
    fn assert_escape_refused_spelled(which: Linked, suffix: &str) {
        fuigo_test_utils::require_git!();
        let tmp = TempDir::new().unwrap();
        let id = "wt-rm-escape";
        let (repo, pin, dest) = pinned_repo_and_dest(tmp.path(), id);
        let (data, link, target) = plant_escape(tmp.path(), id, &dest, &repo, which);
        let raw = spelled(&data, suffix);

        let out = daemon_down_rm_spelled(&dest, &raw, tmp.path());

        let err = match out {
            Err(e) => e,
            Ok(report) => panic!(
                "{which:?} spelled {raw:?}: a symlinked component must be refused \
                 however the data dir is spelled; got {report:?}, the out-of-tree \
                 target {} {}, pin {}",
                target.display(),
                if target.join("precious").is_dir() {
                    "survived"
                } else {
                    "WAS DELETED"
                },
                if pin_present(&repo, &pin) {
                    "present"
                } else {
                    "WAS DELETED"
                }
            ),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("symlink"),
            "{which:?} spelled {raw:?}: the refusal must name the symlink, got: {msg}"
        );
        assert!(
            target.join("precious").is_dir() && target.join(BACKING_MARKER_FILE).is_file(),
            "{which:?} spelled {raw:?}: nothing behind the link may be deleted"
        );
        assert!(
            pin_present(&repo, &pin),
            "{which:?} spelled {raw:?}: a refused rm leaves the pin in place"
        );
        assert!(
            link.symlink_metadata()
                .is_ok_and(|m| m.file_type().is_symlink()),
            "{which:?} spelled {raw:?}: the planted link itself stays"
        );
    }

    #[test]
    fn daemon_down_rm_refuses_a_symlinked_data_dir_spelled_with_trailing_slash() {
        assert_escape_refused_spelled(Linked::DataDir, "/");
    }
    #[test]
    fn daemon_down_rm_refuses_a_symlinked_data_dir_spelled_with_trailing_dot() {
        assert_escape_refused_spelled(Linked::DataDir, "/.");
    }
    #[test]
    fn daemon_down_rm_refuses_a_symlinked_data_dir_spelled_with_double_slash() {
        assert_escape_refused_spelled(Linked::DataDir, "//");
    }
    #[test]
    fn daemon_down_rm_refuses_a_symlinked_worktree_backing_dir_spelled_with_trailing_slash() {
        assert_escape_refused_spelled(Linked::BackingRoot, "/");
    }
    #[test]
    fn daemon_down_rm_refuses_a_symlinked_worktree_backing_dir_spelled_with_trailing_dot() {
        assert_escape_refused_spelled(Linked::BackingRoot, "/.");
    }
    #[test]
    fn daemon_down_rm_refuses_a_symlinked_worktree_backing_dir_spelled_with_double_slash() {
        assert_escape_refused_spelled(Linked::BackingRoot, "//");
    }
    #[test]
    fn daemon_down_rm_refuses_a_symlinked_backing_entry_spelled_with_trailing_slash() {
        assert_escape_refused_spelled(Linked::Id, "/");
    }
    #[test]
    fn daemon_down_rm_refuses_a_symlinked_backing_entry_spelled_with_trailing_dot() {
        assert_escape_refused_spelled(Linked::Id, "/.");
    }
    #[test]
    fn daemon_down_rm_refuses_a_symlinked_backing_entry_spelled_with_double_slash() {
        assert_escape_refused_spelled(Linked::Id, "//");
    }

    /// `GROVE_DATA_DIR=<link>/worktree-backing/..`: the kernel resolves `..`
    /// physically, through the link, so this spelling names the link's TARGET
    /// and would be followed while `<link>` is refused. The gate refuses the
    /// spelling itself, so it is spelling-independent rather than merely
    /// trailing-slash-proof.
    #[test]
    fn daemon_down_rm_refuses_a_data_dir_spelled_with_parent_dir() {
        fuigo_test_utils::require_git!();
        let tmp = TempDir::new().unwrap();
        let id = "wt-rm-escape";
        let (repo, pin, dest) = pinned_repo_and_dest(tmp.path(), id);
        let (data, _link, target) = plant_escape(tmp.path(), id, &dest, &repo, Linked::DataDir);
        let raw = spelled(&data, &format!("/{WORKTREE_BACKING_DIR}/.."));

        let out = daemon_down_rm_spelled(&dest, &raw, tmp.path());

        let err = match out {
            Err(e) => e,
            Ok(report) => panic!(
                "spelled {raw:?}: `..` must be refused, not resolved through the \
                 link; got {report:?}, target {} {}, pin {}",
                target.display(),
                if target.join("precious").is_dir() {
                    "survived"
                } else {
                    "WAS DELETED"
                },
                if pin_present(&repo, &pin) {
                    "present"
                } else {
                    "WAS DELETED"
                }
            ),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains(".."),
            "the refusal must name the spelling, got: {msg}"
        );
        assert!(
            target.join("precious").is_dir(),
            "nothing behind the link is deleted"
        );
        assert!(
            pin_present(&repo, &pin),
            "a refused rm leaves the pin in place"
        );
    }

    /// The other half of spelling-independence: a REAL data dir spelled with a
    /// trailing slash (what shell tab-completion writes) is allowed exactly as
    /// the bare spelling is — the normalisation refuses spellings of a symlink,
    /// not spellings as such.
    #[test]
    fn daemon_down_rm_accepts_a_real_data_dir_spelled_with_trailing_slash() {
        fuigo_test_utils::require_git!();
        let tmp = TempDir::new().unwrap();
        let id = "wt-rm-spelled-real";
        let (repo, pin, dest) = pinned_repo_and_dest(tmp.path(), id);
        let (data, backing) = plant_backing(tmp.path(), id, &dest, &repo);
        let raw = spelled(&data, "/");

        let out = daemon_down_rm_spelled(&dest, &raw, tmp.path());

        let report = out.expect("a real data dir is allowed however it is spelled");
        assert!(
            report.is_none(),
            "dest still exists, so the caller removes it"
        );
        assert!(!pin_present(&repo, &pin), "pin deleted");
        assert!(!backing.exists(), "backing {} deleted", backing.display());
        assert!(
            data.join(WORKTREE_BACKING_DIR).is_dir(),
            "only `<id>` goes; `worktree-backing` stays"
        );
    }

    // ---- round 4: a DB-recorded backing path is trusted only through its marker ----

    /// Register `dest` as a grove worktree whose row records `backing` (if any),
    /// under the fixture's isolated registry, then point grove lookup at `data`
    /// with the daemon down. Returns the fixture (it owns the env for its
    /// lifetime) and the open DB.
    #[cfg(feature = "metadata")]
    fn register_grove_row(
        dest: &Path,
        id: &str,
        repo: &Path,
        pin: &str,
        backing: Option<&Path>,
        data: &Path,
        tmp: &Path,
    ) -> (crate::db::FuigoHomeFixture, crate::db::WorktreeDb) {
        let mut fx = crate::db::FuigoHomeFixture::new();
        let db = crate::db::WorktreeDb::open(&fx.home).unwrap();
        let mut grove = serde_json::json!({
            "transport": "nfs", "mount_id": 7, "source_pin": pin
        });
        if let Some(b) = backing {
            grove["backing"] = serde_json::Value::String(b.display().to_string());
        }
        // `WorktreeDb::get` canonicalises a path before lookup, so the record
        // is stored the way a real registration would be found.
        let registered = dunce::canonicalize(dest).unwrap();
        db.register(&crate::db::WorktreeRecord {
            source_repo: repo.to_path_buf(),
            creation_mode: crate::worktree::STRATEGY_GROVE_NFS.to_string(),
            metadata: Some(serde_json::json!({ "grove": grove })),
            ..crate::test_support::worktree_record(id, registered)
        })
        .unwrap();
        fx.set_grove_env(data, &tmp.join("absent.sock"));
        (fx, db)
    }

    /// The operator moved `GROVE_DATA_DIR`. The DB row still records the OLD
    /// backing path, which no longer exists; the REAL backing, with a marker
    /// naming this dest, sits under the live data dir. Before the fix the row
    /// was trusted without reading a marker and the absent data dir was
    /// "success": pin deleted, dest handed to the caller's `rm -rf`, record
    /// unregistered, and the real content left on disk with nothing tracking it.
    /// A stale row must fall through to the markers exactly as no row does.
    #[cfg(feature = "metadata")]
    #[test]
    fn daemon_down_rm_with_stale_db_backing_path_finds_the_real_backing_by_marker() {
        fuigo_test_utils::require_git!();
        let tmp = TempDir::new().unwrap();
        let id = "wt-rm-stale-db";
        let (repo, pin, dest) = pinned_repo_and_dest(tmp.path(), id);
        let (data, backing) = plant_backing(tmp.path(), id, &dest, &repo);
        std::fs::create_dir_all(backing.join("objects")).unwrap();
        std::fs::write(backing.join("objects/blob"), b"content").unwrap();
        let stale = tmp
            .path()
            .join("old-grove")
            .join(WORKTREE_BACKING_DIR)
            .join(id);
        let (_fx, _db) =
            register_grove_row(&dest, id, &repo, &pin, Some(&stale), &data, tmp.path());

        let out = try_nfs_remove(&dest);

        let report = out.unwrap_or_else(|e| {
            panic!(
                "a stale row must fall through to the marker, not refuse: {e:#}; \
                 real backing present={}",
                backing.exists()
            )
        });
        assert!(
            report.is_none(),
            "dest still exists, so the caller removes it"
        );
        assert!(
            !backing.exists(),
            "the REAL backing {} must be found via its marker and deleted, not left \
             untracked behind a 'success' (pin {})",
            backing.display(),
            if pin_present(&repo, &pin) {
                "present"
            } else {
                "WAS DELETED"
            }
        );
        assert!(!pin_present(&repo, &pin), "pin deleted with the backing");
    }

    /// The stale row again, but this time NO marker anywhere names dest. The
    /// only right answer is a refusal that leaves pin, dest and registry alone
    /// — never "success" with the pin gone.
    #[cfg(feature = "metadata")]
    fn assert_untrusted_row_refused(stale: &Path, expect_in_msg: &str, tag: &str) {
        fuigo_test_utils::require_git!();
        let tmp = TempDir::new().unwrap();
        let id = "wt-rm-stale-db-nomark";
        let (repo, pin, dest) = pinned_repo_and_dest(tmp.path(), id);
        let data = tmp.path().join("grove");
        std::fs::create_dir_all(data.join(WORKTREE_BACKING_DIR)).unwrap();
        let stale = tmp.path().join(stale);
        let (_fx, db) = register_grove_row(&dest, id, &repo, &pin, Some(&stale), &data, tmp.path());

        let out = try_nfs_remove(&dest);

        let err = match out {
            Err(e) => e,
            Ok(report) => panic!(
                "{tag}: an untrusted recorded backing path must be refused; got \
                 {report:?}, pin {pin} {}, dest {}",
                if pin_present(&repo, &pin) {
                    "present"
                } else {
                    "WAS DELETED"
                },
                if dest.is_dir() { "present" } else { "gone" }
            ),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("backing") && msg.contains("retaining pin and dest"),
            "{tag}: the refusal must say what is retained and why, got: {msg}"
        );
        assert!(
            msg.contains(expect_in_msg),
            "{tag}: the refusal must say why the recorded path was not trusted \
             (expected {expect_in_msg:?}), got: {msg}"
        );
        assert!(
            pin_present(&repo, &pin),
            "{tag}: the pin must survive a refusal"
        );
        assert!(
            dest.is_dir(),
            "{tag}: dest must survive for the daemon-up retry"
        );
        assert!(
            db.get(&dest.to_string_lossy()).unwrap().is_some(),
            "{tag}: try_nfs_remove never touches the registry"
        );
    }

    /// Recorded data dir absent (moved away), no marker anywhere.
    #[cfg(feature = "metadata")]
    #[test]
    fn daemon_down_rm_with_stale_db_backing_path_and_no_marker_retains_pin_and_dest() {
        assert_untrusted_row_refused(
            &Path::new("old-grove")
                .join(WORKTREE_BACKING_DIR)
                .join("wt-rm-stale-db-nomark"),
            "does not exist",
            "absent data dir",
        );
    }

    /// Recorded data dir exists but has no `worktree-backing` under it.
    #[cfg(feature = "metadata")]
    #[test]
    fn daemon_down_rm_with_db_backing_root_absent_retains_pin_and_dest() {
        // `grove` exists (it is the live data dir); the row names a backing
        // under a sibling that exists but was never a data dir.
        assert_untrusted_row_refused(
            &Path::new("repo")
                .join(WORKTREE_BACKING_DIR)
                .join("wt-rm-stale-db-nomark"),
            "does not exist",
            "absent backing root",
        );
    }

    /// A DB-recorded `grove.backing` that exists — outside every candidate data
    /// dir — but carries no marker for this dest. Before the fix the fd walk
    /// confined the delete to whatever `worktrees.db` said and removed it. The
    /// marker is the proof the directory is this worktree's; without it the row
    /// is not trusted and the directory is left alone.
    #[cfg(feature = "metadata")]
    #[test]
    fn daemon_down_rm_refuses_a_db_backing_path_without_a_marker_for_dest() {
        fuigo_test_utils::require_git!();
        let tmp = TempDir::new().unwrap();
        let id = "wt-rm-foreign-db";
        let (repo, pin, dest) = pinned_repo_and_dest(tmp.path(), id);
        let data = tmp.path().join("grove");
        std::fs::create_dir_all(data.join(WORKTREE_BACKING_DIR)).unwrap();
        let foreign = tmp
            .path()
            .join("foreign")
            .join(WORKTREE_BACKING_DIR)
            .join(id);
        std::fs::create_dir_all(foreign.join("precious")).unwrap();
        // A marker for ANOTHER dest with the same id must not count either.
        write_marker(&foreign, id, &tmp.path().join("someone-elses-wt"), &repo);
        let (_fx, _db) =
            register_grove_row(&dest, id, &repo, &pin, Some(&foreign), &data, tmp.path());

        let out = try_nfs_remove(&dest);

        let err = match out {
            Err(e) => e,
            Ok(report) => panic!(
                "a recorded backing path with no marker for this dest must be \
                 refused; got {report:?}, {} {}, pin {}",
                foreign.display(),
                if foreign.join("precious").is_dir() {
                    "survived"
                } else {
                    "WAS DELETED"
                },
                if pin_present(&repo, &pin) {
                    "present"
                } else {
                    "WAS DELETED"
                }
            ),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("carries no marker") && msg.contains("retaining pin and dest"),
            "the refusal must say the recorded path is unproven, got: {msg}"
        );
        assert!(
            foreign.join("precious").is_dir(),
            "the unproven directory is untouched"
        );
        assert!(pin_present(&repo, &pin), "the pin survives a refusal");
    }

    /// The legitimate moved-data-dir case: the row records a backing that is
    /// outside every candidate data dir, and it DOES carry a marker naming this
    /// dest. That is this worktree's content wherever it lives, and the row is
    /// the only pointer to it, so it is deleted — confined to the data dir the
    /// row names, which the marker has just proven is the right one.
    #[cfg(feature = "metadata")]
    #[test]
    fn daemon_down_rm_deletes_a_marked_db_backing_path_outside_the_candidate_data_dirs() {
        fuigo_test_utils::require_git!();
        let tmp = TempDir::new().unwrap();
        let id = "wt-rm-moved-db";
        let (repo, pin, dest) = pinned_repo_and_dest(tmp.path(), id);
        let data = tmp.path().join("grove");
        std::fs::create_dir_all(data.join(WORKTREE_BACKING_DIR)).unwrap();
        let old = tmp.path().join("old-grove");
        let backing = old.join(WORKTREE_BACKING_DIR).join(id);
        write_marker(&backing, id, &dest, &repo);
        std::fs::write(backing.join("blob"), b"content").unwrap();
        let (_fx, _db) =
            register_grove_row(&dest, id, &repo, &pin, Some(&backing), &data, tmp.path());

        let out = try_nfs_remove(&dest);

        let report = out.expect("a marker-proven recorded backing is this worktree's");
        assert!(report.is_none());
        assert!(!backing.exists(), "backing {} deleted", backing.display());
        assert!(old.join(WORKTREE_BACKING_DIR).is_dir(), "only `<id>` goes");
        assert!(!pin_present(&repo, &pin), "pin deleted with the backing");
    }
}
