//! The unix inbox: bind, publish a locator row, accept, serve (packet 8d; DESIGN S3.1, S3.5, S5.5).
//!
//! INERT: nothing outside the tests calls [`PeerInbox::start`] until packet 8e. With the feature flag off `start`
//! returns [`Disabled::FeatureOff`] before any file system call: no directory, no file, no socket, no task.
//!
//! Over-capacity choice (S5.5): the 33rd concurrent connection is accepted and CLOSED at once, unread. Waiting would
//! leave unread connections piling up in the kernel backlog and make the dialer sit out its whole 10 s deadline;
//! a closed connection tells it immediately and it can try again.
// Inert until packet 8e; only the tests construct these.
#![cfg_attr(not(test), allow(dead_code))]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fuigo_peer::locator_row::MAX_ROWS;
use fuigo_peer::{DirChoice, Hello, HostDir, HostId, HostRow, socket_path};
use tokio::net::UnixListener;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use super::conn::serve_one;
use super::dial::Locations;
use super::directory::{ConnHost, PeerDirectory};
use super::reap::{
    LOCATOR_NAME, ReapReport, TRY_GAP, decode_rows, encode_rows, is_our_socket, mode_of, reap_pass, sock_name,
    unlink_if_identity,
};
use super::{CheckedDir, Disabled, update_locator, update_locator_rewriting};
use crate::leader::peer_check::{PeerVerdict, Side, bind_private_with, verdict_for};
use crate::session::peer_message::peer_messaging_enabled;

/// How long a shutting-down host waits for its `exited` notices to be delivered (S9.2).
pub(crate) const ANNOUNCE_BUDGET: Duration = Duration::from_secs(3);

/// The whole reap pass at start is cut off after this long (each probe is also under its own 2 s connect timeout).
pub(crate) const REAP_BUDGET: Duration = Duration::from_secs(5);

/// Concurrent connections served at once (S5.5).
pub(crate) const MAX_CONNECTIONS: usize = 32;

/// Start-up inputs that are normally read from the process. Tests pass their own so they never touch globals.
#[derive(Debug, Clone)]
pub(crate) struct StartOptions {
    /// `features.peer_messaging`.
    pub enabled: bool,
    /// `$XDG_RUNTIME_DIR`.
    pub runtime_dir: Option<PathBuf>,
}

fn io_err(e: &std::io::Error) -> Disabled {
    Disabled::Io(e.raw_os_error().unwrap_or(libc::EIO))
}

/// 32 lower-case hex characters from the thread CSPRNG.
fn mint_host_id() -> HostId {
    let n: u128 = rand::random();
    HostId::new(&format!("{n:032x}")).unwrap_or_else(|_| unreachable!("32 lower-case hex characters"))
}

/// Create and check `<runtime>/fuigo/<hash>/peers` one component at a time relative to a directory fd, with
/// no-follow opens and owner and mode checks at every level (S3.3). The runtime directory itself must be absolute,
/// ours and not group- or world-writable, else the runtime branch is unavailable.
/// `lstat(path)` (no follow) names the inode and device recorded for the socket file we created. (`fstat` on the
/// socket fd cannot be used: it reports the socket file system, not the bound path.)
fn same_file_as_bound(bound: Option<(u64, u64)>, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(on_disk) = std::fs::symlink_metadata(path) else { return false };
    bound == Some((on_disk.dev(), on_disk.ino()))
}

fn open_runtime_peers(loc: &Locations) -> Result<CheckedDir, Disabled> {
    let rt_home = loc.runtime_home().ok_or(Disabled::SocketDirUnavailable)?;
    let base = loc.runtime_base().ok_or(Disabled::SocketDirUnavailable)?;
    let rel = rt_home.strip_prefix(base).map_err(|_| Disabled::SocketDirUnavailable)?;
    let levels: Vec<&str> = rel.components().filter_map(|c| c.as_os_str().to_str()).collect();
    if levels.len() != 2 {
        return Err(Disabled::SocketDirUnavailable);
    }
    CheckedDir::create_under(base, &levels)
}

/// Remove our socket (only while it is still ours) and our row. Bounded: the lock wait gives up after 2 s and the
/// stale row is then left for the reaper.
fn undo_all(sock_dir: &CheckedDir, home_dir: &CheckedDir, host_id: &HostId, bound: Option<(u64, u64)>) {
    unlink_if_identity(sock_dir, &sock_name(host_id), bound);
    remove_own_row(home_dir, host_id);
}

fn remove_own_row(home_dir: &CheckedDir, host_id: &HostId) {
    let mine = host_id.clone();
    let _ = update_locator(home_dir, LOCATOR_NAME, |cur| {
        let mut rows = decode_rows(cur);
        let before = rows.len();
        rows.retain(|r| r.host_id != mine);
        if rows.len() == before {
            return cur.map(<[u8]>::to_vec);
        }
        encode_rows(&rows)
    });
}

/// A running inbox. Dropping it (or [`PeerInbox::shutdown`]) stops accepting, unlinks our socket and removes our row.
pub(crate) struct PeerInbox {
    host_id: HostId,
    directory: Arc<PeerDirectory>,
    loc: Locations,
    /// `<home>/peers`: the locator file lives here.
    home_dir: Arc<CheckedDir>,
    /// The directory that holds our socket (`home_dir` or the runtime one).
    sock_dir: Arc<CheckedDir>,
    row: HostRow,
    token: CancellationToken,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Packet 11: the notice pump (delivers the notices this host's sessions produce) and the once-a-minute watch ticker.
    pump: Mutex<Option<tokio::task::JoinHandle<()>>>,
    ticker: Mutex<Option<tokio::task::JoinHandle<()>>>,
    closed: AtomicBool,
    /// (device, inode) of the socket file we bound: cleanup only removes that file.
    bound: Option<(u64, u64)>,
}

struct Prepared {
    host_id: HostId,
    loc: Locations,
    home_dir: Arc<CheckedDir>,
    sock_dir: Arc<CheckedDir>,
    row: HostRow,
    listener: std::os::unix::net::UnixListener,
    sock_path: PathBuf,
    bound: Option<(u64, u64)>,
    /// Unlinks the bound-but-unpublished socket if the start is dropped (cancelled) before it finishes.
    guard: SocketGuard,
}

/// Owns the cleanup of a socket that is bound but whose inbox is not yet built. Dropping an armed guard (a start
/// cancelled after the bind, or its result dropped) unlinks the socket if it is STILL the file we bound.
struct SocketGuard {
    sock_dir: Arc<CheckedDir>,
    name: String,
    bound: Option<(u64, u64)>,
    armed: bool,
}

impl SocketGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if self.armed {
            unlink_if_identity(&self.sock_dir, &self.name, self.bound);
        }
    }
}

/// Every blocking step of `start`, in order. Runs in `spawn_blocking`.
fn prepare(home: &Path, runtime_dir: Option<&Path>, host_id: HostId) -> Result<Prepared, Disabled> {
    let loc = Locations::new(home, runtime_dir);
    // Decide the directory FIRST: when it is unavailable nothing is created.
    let choice = loc.choose();
    if matches!(choice, DirChoice::Unavailable(_)) {
        return Err(Disabled::SocketDirUnavailable);
    }
    // The runtime directory is made BEFORE anything under the home, so its failure leaves no `<home>/peers` behind.
    let runtime_dir = match choice {
        DirChoice::Home => None,
        _ => Some(Arc::new(open_runtime_peers(&loc)?)),
    };
    let home_dir = Arc::new(CheckedDir::create_or_open(home)?);
    let (sock_dir, dir_tag) = match runtime_dir {
        None => (home_dir.clone(), HostDir::Home),
        Some(rt) => (rt, HostDir::Runtime),
    };
    let peers = loc.peers_path(dir_tag).ok_or(Disabled::SocketDirUnavailable)?;
    let sock_path = socket_path(&peers, &host_id);
    let name = sock_name(&host_id);
    // Fail closed on anything already at the path (a planted file or link); `bind_private_with` would rename over it.
    match std::fs::symlink_metadata(&sock_path) {
        Ok(_) => return Err(Disabled::SocketPathExists),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err(&e)),
    }
    // Record the identity (device, inode) of the socket file right after the bind, at its temporary name.
    let mut bound: Option<(u64, u64)> = None;
    let listener = bind_private_with(&sock_path, |p: &Path| {
        use std::os::unix::fs::MetadataExt;
        let l = std::os::unix::net::UnixListener::bind(p)?;
        bound = std::fs::symlink_metadata(p).ok().map(|m| (m.dev(), m.ino()));
        Ok(l)
    })
    .map_err(|e| io_err(&e))?;
    // Undo only the file we bound: compare (device, inode) first, never remove some other socket at the path.
    let undo = |reason: Disabled| {
        unlink_if_identity(&sock_dir, &name, bound);
        reason
    };
    #[cfg(test)]
    if fault::is(&host_id, fault::Fault::SwapAfterBind) {
        // Another socket takes the path (mode 0600, ours) after our bind.
        let _ = std::fs::remove_file(&sock_path);
        if let Ok(other) = std::os::unix::net::UnixListener::bind(&sock_path) {
            let _ = std::fs::set_permissions(&sock_path, std::os::unix::fs::PermissionsExt::from_mode(0o600));
            std::mem::forget(other);
        }
    }
    // The existence check above lost any race to the rename inside the bind:     // inode and device with the socket we hold.
    if !same_file_as_bound(bound, &sock_path) {
        return Err(undo(Disabled::SocketCheckFailed));
    }
    // lstat the result: a socket, ours, mode 0600 (and nothing else, in particular not a link).
    if !is_our_socket(&sock_dir, &name) || mode_of(&sock_dir, &name).map(|m| m & 0o7777) != Some(0o600) {
        return Err(undo(Disabled::SocketCheckFailed));
    }
    listener.set_nonblocking(true).map_err(|e| undo(io_err(&e)))?;
    let row = HostRow { host_id: host_id.clone(), pid: std::process::id(), started: now_secs(), dir: dir_tag };
    let guard = SocketGuard { sock_dir: sock_dir.clone(), name, bound, armed: true };
    Ok(Prepared { host_id, loc, home_dir, sock_dir, row, listener, sock_path, bound, guard })
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Write our row (after the reap pass). On failure the socket (identity-checked) is undone.
fn publish_row(
    sock_dir: &CheckedDir,
    home_dir: &CheckedDir,
    host_id: &HostId,
    mine: HostRow,
    bound: Option<(u64, u64)>,
) -> Result<(), Disabled> {
    let name = sock_name(host_id);
    let undo = |reason: Disabled| {
        unlink_if_identity(sock_dir, &name, bound);
        reason
    };
    let mut full = false;
    update_locator_rewriting(home_dir, LOCATOR_NAME, |cur| {
        let mut rows = decode_rows(cur);
        rows.retain(|r| r.host_id != mine.host_id);
        if rows.len() >= MAX_ROWS {
            full = true;
            return cur.map(<[u8]>::to_vec);
        }
        rows.push(mine);
        encode_rows(&rows)
    })
    .map_err(undo)?;
    if full {
        return Err(undo(Disabled::LocatorFull));
    }
    Ok(())
}

impl PeerInbox {
    /// Start the inbox for the Fuigo home `home` with the process settings (flag, `XDG_RUNTIME_DIR`).
    pub(crate) async fn start(home: &Path) -> Result<PeerInbox, Disabled> {
        Self::start_with(
            home,
            StartOptions {
                enabled: peer_messaging_enabled(),
                runtime_dir: std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
            },
        )
        .await
    }

    pub(crate) async fn start_with(home: &Path, opts: StartOptions) -> Result<PeerInbox, Disabled> {
        Self::start_inner(home, opts, mint_host_id()).await
    }

    /// `start_with` with a chosen host id (tests plant a file at the socket path of a known id).
    pub(crate) async fn start_inner(home: &Path, opts: StartOptions, host_id: HostId) -> Result<PeerInbox, Disabled> {
        // Before ANY file system call, thread or task.
        if !opts.enabled {
            return Err(Disabled::FeatureOff);
        }
        let (h, rt) = (home.to_path_buf(), opts.runtime_dir);
        let p = tokio::task::spawn_blocking(move || prepare(&h, rt.as_deref(), host_id))
            .await
            .map_err(|_| Disabled::Io(libc::EIO))??;
        // From here to the end of the start the guard owns the socket: a dropped (cancelled) future unlinks it.
        let mut guard = p.guard;
        #[cfg(test)]
        if fault::is(&p.host_id, fault::Fault::PauseAfterBind) {
            std::future::pending::<()>().await;
        }
        #[cfg(test)]
        let forced = fault::is(&p.host_id, fault::Fault::FromStd);
        #[cfg(not(test))]
        let forced = false;
        let converted = if forced {
            Err(std::io::Error::from_raw_os_error(libc::EMFILE))
        } else {
            UnixListener::from_std(p.listener)
        };
        let listener = match converted {
            Ok(l) => l,
            Err(e) => {
                // Every failure after the bind undoes the socket and the row.
                let (sd, hd, id, bound) = (p.sock_dir.clone(), p.home_dir.clone(), p.host_id.clone(), p.bound);
                let _ = tokio::task::spawn_blocking(move || undo_all(&sd, &hd, &id, bound)).await;
                return Err(io_err(&e));
            }
        };
        // One bounded reap pass BEFORE our row is written (a full locator would otherwise refuse us). Never repeated on a
        // timer. Probes are async (no thread is blocked); each is under its 2 s connect timeout and the whole pass
        // under REAP_BUDGET. A failed or cut-short pass changes nothing else.
        let _ = tokio::time::timeout(REAP_BUDGET, reap_pass(&p.loc, &p.home_dir, &p.host_id, TRY_GAP)).await;
        let (sd, hd, hid, row, bound) = (p.sock_dir.clone(), p.home_dir.clone(), p.host_id.clone(), p.row.clone(), p.bound);
        tokio::task::spawn_blocking(move || publish_row(&sd, &hd, &hid, row, bound))
            .await
            .map_err(|_| Disabled::Io(libc::EIO))??;
        let directory = PeerDirectory::new(p.host_id.clone());
        let token = CancellationToken::new();
        let task = tokio::spawn(accept_loop(
            listener,
            p.sock_path,
            Hello::new(p.host_id.clone()),
            directory.clone(),
            token.clone(),
        ));
        // Packet 11: notices produced by this host's sessions go out through one pump; watches are probed once a minute.
        let (notice_tx, notice_rx) = tokio::sync::mpsc::unbounded_channel();
        directory.set_notice_out(notice_tx);
        let pump = tokio::spawn(super::watch::io::pump(notice_rx, directory.clone(), p.loc.clone(), p.home_dir.clone(), None));
        let ticker = tokio::spawn(super::watch::io::ticker(
            directory.clone(),
            super::watch::io::SocketProber { loc: p.loc.clone(), home_dir: p.home_dir.clone(), own: p.host_id.clone() },
            token.clone(),
        ));
        // The inbox owns the cleanup from here on (shutdown / Drop).
        guard.disarm();
        Ok(PeerInbox {
            host_id: p.host_id,
            directory,
            loc: p.loc,
            home_dir: p.home_dir,
            sock_dir: p.sock_dir,
            row: p.row,
            token,
            task: Mutex::new(Some(task)),
            pump: Mutex::new(Some(pump)),
            ticker: Mutex::new(Some(ticker)),
            closed: AtomicBool::new(false),
            bound: p.bound,
        })
    }

    pub(crate) fn host_id(&self) -> &HostId {
        &self.host_id
    }

    pub(crate) fn directory(&self) -> &Arc<PeerDirectory> {
        &self.directory
    }

    pub(crate) fn locations(&self) -> &Locations {
        &self.loc
    }

    pub(crate) fn row(&self) -> &HostRow {
        &self.row
    }

    pub(crate) fn peers_dir(&self) -> &Arc<CheckedDir> {
        &self.home_dir
    }

    /// Judge the other rows (S3.6) and remove the dead ones.
    pub(crate) async fn reap(&self, gap: Duration) -> Result<ReapReport, Disabled> {
        reap_pass(&self.loc, &self.home_dir, &self.host_id, gap).await
    }

    /// `reap` with the production gap of one second.
    pub(crate) async fn reap_stale(&self) -> Result<ReapReport, Disabled> {
        self.reap(TRY_GAP).await
    }

    /// Stop accepting, unlink OUR socket (only while `lstat` still shows a socket owned by us) and remove OUR row
    /// under the lock. Idempotent. The file work runs on a blocking thread; the lock wait is bounded (2 s), after
    /// which the row is left for the reaper and the socket is gone anyway.
    pub(crate) async fn shutdown(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        // Packet 11 (S9.2): tell every sender still waiting that this host is going away cleanly (`exited`), while the sockets
        // still work; bounded to `ANNOUNCE_BUDGET`.
        self.announce_exit().await;
        self.stop_accepting();
        let (sd, hd, id, bound) = (self.sock_dir.clone(), self.home_dir.clone(), self.host_id.clone(), self.bound);
        let _ = tokio::task::spawn_blocking(move || undo_all(&sd, &hd, &id, bound)).await;
    }

    /// Every outstanding record of every session is told `exited`; the pump gets `ANNOUNCE_BUDGET` to deliver them.
    async fn announce_exit(&self) {
        self.directory.announce_exit();
        // Dropping the directory's sender lets the pump end once it has delivered what is queued (the sessions' records are gone).
        drop(self.directory.take_notice_out());
        let pump = self.pump.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        if let Some(p) = pump {
            let _ = tokio::time::timeout(ANNOUNCE_BUDGET, p).await;
        }
    }

    fn stop_accepting(&self) {
        self.token.cancel();
        if let Some(t) = self.ticker.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take() {
            t.abort();
        }
        if let Some(t) = self.pump.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take() {
            t.abort();
        }
        if let Some(t) = self.task.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take() {
            t.abort();
        }
    }
}

impl Drop for PeerInbox {
    /// Best effort and non-blocking: cancel, then unlink our socket (a few syscalls, no lock). The row removal
    /// takes the locator lock, which may wait, so it is never done here on a runtime thread: it is handed to a
    /// blocking thread when a runtime is available (fire and forget), else left for the reaper. Call
    /// [`PeerInbox::shutdown`] for the full, awaited cleanup.
    fn drop(&mut self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.stop_accepting();
        unlink_if_identity(&self.sock_dir, &sock_name(&self.host_id), self.bound);
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            let (hd, id) = (self.home_dir.clone(), self.host_id.clone());
            drop(h.spawn_blocking(move || remove_own_row(&hd, &id)));
        }
    }
}

async fn accept_loop(
    listener: UnixListener,
    sock_path: PathBuf,
    our: Hello,
    directory: Arc<PeerDirectory>,
    token: CancellationToken,
) {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let stream = tokio::select! {
            () = token.cancelled() => return,
            r = listener.accept() => match r {
                Ok((s, _)) => s,
                Err(_) => {
                    // EMFILE and friends: do not spin.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        // Over capacity: close at once, unread (see the module comment).
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let (our, directory, token, path) = (our.clone(), directory.clone(), token.clone(), sock_path.clone());
        // One task per connection. A panic stays inside it (the runtime catches it; the permit is released on
        // unwind), so the loop never goes down with a connection.
        tokio::spawn(async move {
            let _permit = permit;
            // The uid check comes BEFORE the first read: a peer of another account is dropped unread.
            if verdict_for(Side::Server, &stream, &path) != PeerVerdict::Accept {
                return;
            }
            let host = ConnHost::new(directory);
            tokio::select! {
                () = token.cancelled() => {}
                // `serve_one` bounds the whole exchange, host call included, by the 10 s deadline and drops the
                // host future when it fires.
                r = serve_one(stream, our, &host) => { let _ = r; }
            }
        });
    }
}

/// Test-only fault injection keyed by host id, so parallel tests never see each other's setting.
#[cfg(test)]
pub(super) mod fault {
    use fuigo_peer::HostId;
    use std::sync::Mutex;

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Fault {
        /// `UnixListener::from_std` fails.
        FromStd,
        /// The socket path is swapped for another socket between the bind and the check.
        SwapAfterBind,
        /// The start never continues after the bind (a cancelled start).
        PauseAfterBind,
    }
    static FAULTS: Mutex<Vec<(HostId, Fault)>> = Mutex::new(Vec::new());
    pub(crate) fn set(id: &HostId, f: Fault) {
        FAULTS.lock().unwrap().push((id.clone(), f));
    }
    pub(crate) fn is(id: &HostId, f: Fault) -> bool {
        FAULTS.lock().unwrap().iter().any(|(i, x)| i == id && *x == f)
    }
}
