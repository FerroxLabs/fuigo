//! Reaping stale locator rows and their socket files (packet 8d; DESIGN S3.6, owner decision 51 (e)).
//!
//! The decision is `fuigo_peer::reap_decision` and nothing else: a pid is never consulted, a timeout or a version
//! mismatch never reaps, a `runtime` row is reaped on "no such file" only when our own checked runtime directory for this home opens. A row is removed only under the
//! locator lock and only if it is byte-for-byte the row that was read; its `<host-id>.sock` is unlinked in the same
//! critical section, only if `lstat` shows a socket owned by us.
// Inert until packet 8e; only the tests reap.
#![cfg_attr(not(test), allow(dead_code))]

use std::sync::Arc;
use std::time::Duration;

use fuigo_peer::locator_row::MAX_ROWS;
use fuigo_peer::{HostDir, HostId, HostRow, Reap, TryResult, reap_decision, socket_path};

use super::dial::{Locations, try_hello};
use super::dirs::cstr;
use super::{CheckedDir, Disabled, read_locator, update_locator};

pub(crate) use super::rows::LOCATOR_NAME;
/// The gap between the two tries (S3.6).
pub(crate) const TRY_GAP: Duration = Duration::from_secs(1);

/// `lstat` of `<dir>/<name>` through the directory fd: is it a SOCKET owned by us (never follows a link)?
pub(super) fn is_our_socket(dir: &CheckedDir, name: &str) -> bool {
    let Ok(c) = cstr(name) else { return false };
    // SAFETY: zeroed stat is a valid out-parameter; the fd and the NUL-terminated name are valid.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::fstatat(dir.raw(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    // SAFETY: geteuid cannot fail.
    r == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFSOCK && st.st_uid == unsafe { libc::geteuid() }
}

/// The permission bits of `<dir>/<name>` (no-follow), or `None` if it is missing.
// `st_mode` is u16 on macOS and u32 on Linux, so the cast is a same-type cast on one of them.
#[allow(clippy::unnecessary_cast)]
pub(super) fn mode_of(dir: &CheckedDir, name: &str) -> Option<u32> {
    let c = cstr(name).ok()?;
    // SAFETY: as above.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::fstatat(dir.raw(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    (r == 0).then_some(st.st_mode as u32 & 0o7777)
}

/// Unlink `<dir>/<name>` only if it is a socket owned by us. Returns whether it was removed.
pub(super) fn unlink_if_our_socket(dir: &CheckedDir, name: &str) -> bool {
    if !is_our_socket(dir, name) {
        return false;
    }
    let Ok(c) = cstr(name) else { return false };
    // SAFETY: valid fd and name.
    unsafe { libc::unlinkat(dir.raw(), c.as_ptr(), 0) == 0 }
}

/// (device, inode) of `<dir>/<name>` (no-follow), if it exists.
pub(super) fn identity_of(dir: &CheckedDir, name: &str) -> Option<(u64, u64)> {
    let c = cstr(name).ok()?;
    // SAFETY: as above.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::fstatat(dir.raw(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    #[allow(clippy::unnecessary_cast, reason = "dev_t and ino_t widths differ per platform")]
    (r == 0).then_some((st.st_dev as u64, st.st_ino as u64))
}

/// Unlink `<dir>/<name>` only if it is STILL the file recorded at bind time (same device and inode) and a socket
/// owned by us. A different socket that took the path is left alone.
pub(super) fn unlink_if_identity(dir: &CheckedDir, name: &str, bound: Option<(u64, u64)>) -> bool {
    if bound.is_none() || identity_of(dir, name) != bound {
        return false;
    }
    unlink_if_our_socket(dir, name)
}

pub(super) fn sock_name(host: &HostId) -> String {
    socket_path(std::path::Path::new(""), host).to_string_lossy().into_owned()
}

pub(super) use super::rows::{decode_rows, encode_rows};

/// What one pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ReapReport {
    pub reaped: Vec<HostId>,
    pub kept: usize,
}

/// Probes in flight at once (S5.5).
pub(crate) const MAX_PROBES: usize = 8;
/// One probe is cut off after this long (a host that accepts and never answers must not hold the pass): the try then
/// counts as `Timeout`, which never condemns a row.
pub(crate) const PROBE_CAP: Duration = Duration::from_secs(3);

async fn capped_hello(loc: &Locations, our: &HostId, row: &HostRow) -> TryResult {
    tokio::time::timeout(PROBE_CAP, try_hello(loc, our, &row.host_id, row.dir)).await.unwrap_or(TryResult::Timeout)
}

/// Is the runtime peers directory of THIS home (the one a `runtime` row's host used) ours to open, with the S3.3
/// checks? Then "no such file" in it is evidence about that very directory. Never creates anything.
fn runtime_dir_verified(loc: &Locations) -> bool {
    loc.runtime_home().is_some_and(|r| CheckedDir::open(&r).is_ok())
}

/// Judge every row but ours with at most two tries `gap` apart, and remove the ones `reap_decision` condemns.
/// `home_dir` is the checked `<home>/peers` that holds the locator file.
///
/// Phase 1 runs the first try of every row, at most [`MAX_PROBES`] at once, each under [`PROBE_CAP`]. After ONE gap,
/// phase 2 runs the second try only for rows a first result could condemn, and removes each condemned row as soon as
/// its own second try is done: when the caller's budget cuts the pass short, every row already removed stays removed.
pub(crate) async fn reap_pass(
    loc: &Locations,
    home_dir: &Arc<CheckedDir>,
    our: &HostId,
    gap: Duration,
) -> Result<ReapReport, Disabled> {
    use futures::StreamExt;
    let d = home_dir.clone();
    let bytes = tokio::task::spawn_blocking(move || read_locator(&d, LOCATOR_NAME))
        .await
        .map_err(|_| Disabled::Io(libc::EIO))??;
    let rows: Vec<HostRow> = decode_rows(bytes.as_deref()).into_iter().filter(|r| &r.host_id != our).collect();
    let same_runtime_dir = {
        let l = loc.clone();
        rows.iter().any(|r| r.dir == HostDir::Runtime)
            && tokio::task::spawn_blocking(move || runtime_dir_verified(&l)).await.unwrap_or(false)
    };
    let mut report = ReapReport::default();
    let firsts: Vec<(HostRow, TryResult)> = futures::stream::iter(rows)
        .map(|row| async move {
            let first = capped_hello(loc, our, &row).await;
            (row, first)
        })
        .buffer_unordered(MAX_PROBES)
        .collect()
        .await;
    // A hello that names the row's own host cannot condemn it (`reap_decision` needs a different id twice), and
    // `reap_decision` keeps the row for every other first result whatever the second says: only the rest get a second try.
    let (candidates, kept_now): (Vec<_>, Vec<_>) = firsts.into_iter().partition(|(row, first)| match first {
        TryResult::Refused | TryResult::NoSuchFile => true,
        TryResult::Hello(h) => h != &row.host_id,
        _ => false,
    });
    report.kept += kept_now.len();
    if !candidates.is_empty() {
        tokio::time::sleep(gap).await;
    }
    // Second tries, at most MAX_PROBES at once. Condemned rows are removed in batches under ONE lock acquisition each, as the
    // tries finish: a budget that cuts the pass short keeps every batch already applied.
    let mut seconds = futures::stream::iter(candidates)
        .map(|(row, first)| async move {
            let second = capped_hello(loc, our, &row).await;
            let condemned = reap_decision(row.dir, &row.host_id, &first, &second, same_runtime_dir) == Reap::Reap;
            (row, condemned)
        })
        .buffer_unordered(MAX_PROBES)
        .ready_chunks(MAX_ROWS);
    let mut failure = None;
    while let Some(chunk) = seconds.next().await {
        let (condemned, spared): (Vec<_>, Vec<_>) = chunk.into_iter().partition(|(_, c)| *c);
        report.kept += spared.len();
        let rows: Vec<HostRow> = condemned.into_iter().map(|(r, _)| r).collect();
        if rows.is_empty() {
            continue;
        }
        match remove_rows(loc, home_dir, &rows).await {
            Ok(removed) => {
                report.kept += rows.len() - removed.len();
                report.reaped.extend(removed);
            }
            Err(e) => {
                report.kept += rows.len();
                failure.get_or_insert(e);
            }
        }
    }
    failure.map_or(Ok(report), Err)
}

/// Under the lock: remove `row` only if it is still present unchanged, and unlink its socket if it is ours.
pub(super) async fn remove_row(loc: &Locations, home_dir: &Arc<CheckedDir>, row: &HostRow) -> Result<bool, Disabled> {
    Ok(!remove_rows(loc, home_dir, std::slice::from_ref(row)).await?.is_empty())
}

/// [`remove_row`] for several rows under one lock acquisition. Returns the host ids actually removed.
pub(super) async fn remove_rows(loc: &Locations, home_dir: &Arc<CheckedDir>, victims: &[HostRow]) -> Result<Vec<HostId>, Disabled> {
    let (d, victims, runtime_home) = (home_dir.clone(), victims.to_vec(), loc.runtime_home());
    tokio::task::spawn_blocking(move || {
        let mut removed = Vec::new();
        update_locator(&d, LOCATOR_NAME, |cur| {
            let mut rows = decode_rows(cur);
            let before = rows.len();
            // Only rows byte-for-byte unchanged are removed; a changed or gone row is left alone.
            for row in &victims {
                if let Some(i) = rows.iter().position(|r| r == row) {
                    rows.remove(i);
                    removed.push(row.host_id.clone());
                    let name = sock_name(&row.host_id);
                    match row.dir {
                        HostDir::Home => {
                            unlink_if_our_socket(&d, &name);
                        }
                        HostDir::Runtime => {
                            if let Some(rt) = runtime_home.as_ref().and_then(|r| CheckedDir::open(r).ok()) {
                                unlink_if_our_socket(&rt, &name);
                            }
                        }
                    }
                }
            }
            if rows.len() == before {
                // Nothing to remove: touch nothing. (Rewrites the same bytes.)
                return cur.map(<[u8]>::to_vec);
            }
            encode_rows(&rows)
        })?;
        Ok(removed)
    })
    .await
    .map_err(|_| Disabled::Io(libc::EIO))?
}
