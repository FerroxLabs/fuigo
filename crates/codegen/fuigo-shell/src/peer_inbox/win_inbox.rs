//! The Windows inbox: `PeerInbox` for Windows (packet 15c; DESIGN S3.1, S3.8).
//!
//! Same method names and meanings as the unix `inbox::PeerInbox` wherever `host.rs` and `tool_host.rs` use them. The start
//! order (every failure undoes what came before it):
//!   a. flag off -> `Disabled::FeatureOff` before ANY OS call;
//!   b. `CheckedDir::create_or_open(home)` on a blocking thread (the 15a home rules), then the stale `.tmp-*` sweep;
//!   c. a network-logon session is refused; mint a host id; start the pipe (`WinPeerInbox`, its failures mapped to `Disabled`);
//!   d. ONE bounded reap pass by dial, BEFORE our row is written;
//!   e. publish our row in `hosts.json` (a full locator -> `Disabled::LocatorFull`, not terminal);
//!   f. the notice pump and the once-a-minute watch ticker;
//!   g. `shutdown` / `Drop` stop accepting, remove OUR row only, stop pump and ticker. Idempotent. A cancelled start leaves no
//!      row (the row guard) and no pipe (the dropped `WinPeerInbox`).
//!
//! There is no socket file: the pipe name derives from the host id and our SID, so a host id is enough to dial, and a row's
//! liveness is the pipe itself (see [`reap_pass`]).

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fuigo_peer::{HostDir, HostId, HostRow, Op, Reply, TryResult};
use tokio_util::sync::CancellationToken;

use super::directory::PeerDirectory;
use super::rows::LOCATOR_NAME;
use super::win_logic::{
    DialClass, MAX_PROBES, PROBE_CAP, REAP_BUDGET, ReapReport, TRY_GAP, classify, disabled_of, others, win_reap_decision,
    with_row_added, without_exact, without_host,
};
use super::win_pipe::{self, WinPeerInbox};
use super::win_watch::{self, PipeProber};
use super::{CheckedDir, Disabled, read_locator, update_locator, update_locator_rewriting};
use crate::session::peer_message::peer_messaging_enabled;

/// How long a shutting-down host waits for its `exited` notices to be delivered (S9.2).
pub(crate) const ANNOUNCE_BUDGET: Duration = Duration::from_secs(3);
/// Leftover temp files older than this are swept at start.
const STALE_TEMP_AGE: Duration = Duration::from_secs(10 * 60);
/// At most this many leftover temp files are removed per start.
const STALE_TEMP_MAX: usize = 64;
/// Rows of other hosts read for listing.
const MAX_OTHER_ROWS: usize = fuigo_peer::locator_row::MAX_ROWS;

/// Start-up inputs that are normally read from the process. Tests pass their own so they never touch globals.
#[derive(Debug, Clone)]
pub(crate) struct StartOptions {
    /// `features.peer_messaging`.
    pub enabled: bool,
    /// Tests only: the number of leading path components of the test's temp root, whose DACLs are not judged (the machine's
    /// shared temp directories are exactly what the ancestor rule refuses). Production has no such field.
    #[cfg(test)]
    pub trusted_ancestors: usize,
}

fn mint_host_id() -> HostId {
    let n: u128 = rand::random();
    HostId::new(&format!("{n:032x}")).unwrap_or_else(|_| unreachable!("32 lower-case hex characters"))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg_attr(not(test), allow(unused_variables))]
fn open_home(home: &Path, opts: &StartOptions) -> Result<CheckedDir, Disabled> {
    #[cfg(test)]
    if opts.trusted_ancestors > 0 {
        return CheckedDir::create_or_open_trusting(home, opts.trusted_ancestors);
    }
    CheckedDir::create_or_open(home)
}

/// Remove our row (and no other). Bounded: the lock wait gives up after 2 s and the stale row is left for the reaper.
fn remove_own_row(dir: &CheckedDir, host_id: &HostId) {
    let _ = update_locator(dir, LOCATOR_NAME, |cur| without_host(cur, host_id));
}

/// Write our row (after the reap pass). A full locator is `LocatorFull`.
fn publish_row(dir: &CheckedDir, mine: HostRow) -> Result<(), Disabled> {
    let mut full = false;
    update_locator_rewriting(dir, LOCATOR_NAME, |cur| match with_row_added(cur, mine) {
        Ok(next) => next,
        Err(_) => {
            full = true;
            cur.map(<[u8]>::to_vec)
        }
    })?;
    if full { Err(Disabled::LocatorFull) } else { Ok(()) }
}

/// Orders one start's publish against the undo of that publish. The publish holds `lock` for its whole write and does
/// nothing if `cancelled` is already set; the undo sets `cancelled` first and then removes the row while holding `lock`.
/// So either the publish ran completely before the undo (the undo then removes its row) or it never writes at all.
#[derive(Default)]
struct PublishGate {
    lock: Mutex<()>,
    cancelled: AtomicBool,
}

impl PublishGate {
    fn publish(&self, dir: &CheckedDir, mine: HostRow) -> Result<(), Disabled> {
        let _held = self.lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.cancelled.load(Ordering::SeqCst) {
            return Ok(());
        }
        publish_row(dir, mine)
    }

    fn undo(&self, dir: &CheckedDir, host_id: &HostId) {
        self.cancelled.store(true, Ordering::SeqCst);
        let _held = self.lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        remove_own_row(dir, host_id);
    }
}

/// Removes our row if the start is dropped (cancelled) after the publish began, or fails after it. The removal is ordered
/// after the publish by the [`PublishGate`]; with no tokio runtime it runs synchronously (bounded by the lock's 2 s wait).
struct RowGuard {
    dir: Arc<CheckedDir>,
    host_id: HostId,
    gate: Arc<PublishGate>,
    armed: bool,
}

impl Drop for RowGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let (dir, id, gate) = (self.dir.clone(), self.host_id.clone(), self.gate.clone());
        match tokio::runtime::Handle::try_current() {
            Ok(h) => drop(h.spawn_blocking(move || gate.undo(&dir, &id))),
            Err(_) => gate.undo(&dir, &id),
        }
    }
}

/// The rows of other hosts from the locator, at most `cap`. A rejected, unreadable or garbage file is an error (rejected)
/// or no rows (garbage): never a panic.
pub(crate) async fn read_others(dir: &Arc<CheckedDir>, own: &HostId, cap: usize) -> Result<Vec<HostRow>, Disabled> {
    let d = dir.clone();
    let bytes = tokio::task::spawn_blocking(move || read_locator(&d, LOCATOR_NAME))
        .await
        .map_err(|_| Disabled::StartPanicked)??;
    Ok(others(bytes.as_deref(), own, cap))
}

/// One dial to a host on this machine; the failure is already classified (the one mapping, `win_logic::classify`).
pub(crate) async fn dial_class(our: &HostId, host: &HostId, op: Op) -> Result<Reply, DialClass> {
    win_pipe::dial(our, host, op).await.map_err(|e| classify(&e))
}

/// One reaping or watch try: open the pipe, hello each way (the server must announce `host`), a `List`, close.
pub(crate) async fn try_hello(our: &HostId, host: &HostId) -> TryResult {
    match dial_class(our, host, Op::List { page: 0 }).await {
        Ok(Reply::List { .. }) => TryResult::Hello(host.clone()),
        Ok(_) => TryResult::Other,
        Err(c) => c.try_result(),
    }
}

async fn capped_hello(our: &HostId, row: &HostRow) -> TryResult {
    tokio::time::timeout(PROBE_CAP, try_hello(our, &row.host_id)).await.unwrap_or(TryResult::Timeout)
}

/// Judge every row but ours with at most two tries `gap` apart and remove the rows [`win_reap_decision`] condemns (both
/// tries found no pipe). Same shape as the unix pass: phase 1 the first try of every row, at most `MAX_PROBES` at once,
/// each under `PROBE_CAP`; after ONE gap phase 2 for the rows whose first try found no pipe; each condemned row is removed
/// under the locator lock, only if it is still the very row that was read.
pub(crate) async fn reap_pass(dir: &Arc<CheckedDir>, our: &HostId, gap: Duration) -> Result<ReapReport, Disabled> {
    use futures::StreamExt;
    let rows = read_others(dir, our, MAX_OTHER_ROWS).await?;
    let mut report = ReapReport::default();
    let firsts: Vec<(HostRow, TryResult)> = futures::stream::iter(rows)
        .map(|row| async move {
            let first = capped_hello(our, &row).await;
            (row, first)
        })
        .buffer_unordered(MAX_PROBES)
        .collect()
        .await;
    let (candidates, kept_now): (Vec<_>, Vec<_>) = firsts.into_iter().partition(|(_, first)| *first == TryResult::NoSuchFile);
    report.kept += kept_now.len();
    if !candidates.is_empty() {
        tokio::time::sleep(gap).await;
    }
    let mut seconds = futures::stream::iter(candidates)
        .map(|(row, first)| async move {
            let second = capped_hello(our, &row).await;
            let condemned = win_reap_decision(&first, &second);
            (row, condemned)
        })
        .buffer_unordered(MAX_PROBES)
        .ready_chunks(MAX_OTHER_ROWS);
    let mut failure = None;
    while let Some(chunk) = seconds.next().await {
        let (condemned, spared): (Vec<_>, Vec<_>) = chunk.into_iter().partition(|(_, c)| *c);
        report.kept += spared.len();
        let victims: Vec<HostRow> = condemned.into_iter().map(|(r, _)| r).collect();
        if victims.is_empty() {
            continue;
        }
        match remove_rows(dir, &victims).await {
            Ok(removed) => {
                report.kept += victims.len() - removed.len();
                report.reaped.extend(removed);
            }
            Err(e) => {
                report.kept += victims.len();
                failure.get_or_insert(e);
            }
        }
    }
    failure.map_or(Ok(report), Err)
}

/// Under the lock: remove each of `victims` only if it is still present unchanged. Returns the host ids actually removed.
async fn remove_rows(dir: &Arc<CheckedDir>, victims: &[HostRow]) -> Result<Vec<HostId>, Disabled> {
    let (d, victims) = (dir.clone(), victims.to_vec());
    tokio::task::spawn_blocking(move || {
        let mut removed = Vec::new();
        update_locator(&d, LOCATOR_NAME, |cur| {
            let (next, gone) = without_exact(cur, &victims);
            removed = gone;
            next
        })?;
        Ok(removed)
    })
    .await
    .map_err(|_| Disabled::StartPanicked)?
}

/// A running Windows inbox. Dropping it (or [`PeerInbox::shutdown`]) stops accepting, removes our row and stops the pipe.
pub(crate) struct PeerInbox {
    host_id: HostId,
    directory: Arc<PeerDirectory>,
    /// `<home>\peers`: the locator file lives here.
    home_dir: Arc<CheckedDir>,
    row: HostRow,
    inner: WinPeerInbox,
    token: CancellationToken,
    pump: Mutex<Option<tokio::task::JoinHandle<()>>>,
    ticker: Mutex<Option<tokio::task::JoinHandle<()>>>,
    closed: AtomicBool,
    /// Why the last read of the locator failed (a rejected file), for status. `None` after a good read.
    locator_problem: Mutex<Option<Disabled>>,
}

impl PeerInbox {
    /// Start the inbox for the Fuigo home `home` with the process settings (the flag).
    pub(crate) async fn start(home: &Path) -> Result<PeerInbox, Disabled> {
        Self::start_with(
            home,
            StartOptions {
                enabled: peer_messaging_enabled(),
                #[cfg(test)]
                trusted_ancestors: 0,
            },
        )
        .await
    }

    pub(crate) async fn start_with(home: &Path, opts: StartOptions) -> Result<PeerInbox, Disabled> {
        Self::start_inner(home, opts, mint_host_id()).await
    }

    /// `start_with` with a chosen host id.
    pub(crate) async fn start_inner(home: &Path, opts: StartOptions, host_id: HostId) -> Result<PeerInbox, Disabled> {
        // a. Before ANY OS call, thread or task.
        if !opts.enabled {
            return Err(Disabled::FeatureOff);
        }
        // b. The checked directory, then the leftover-temp sweep under the locator lock.
        let h = home.to_path_buf();
        let o = opts.clone();
        let home_dir = tokio::task::spawn_blocking(move || open_home(&h, &o))
            .await
            .map_err(|_| Disabled::StartPanicked)??;
        let home_dir = Arc::new(home_dir);
        let d = home_dir.clone();
        let _ = tokio::task::spawn_blocking(move || {
            super::win_locator::sweep_stale_temps(&d, STALE_TEMP_AGE, STALE_TEMP_MAX)
        })
        .await;
        // c. A network-logon session cannot use its own pipe (decision 56): say so instead of starting a useless inbox.
        match tokio::task::spawn_blocking(win_pipe::sys::own_token_is_network).await {
            Ok(Ok(false)) => {}
            Ok(Ok(true)) => return Err(Disabled::NetworkLogon),
            Ok(Err(_)) => return Err(Disabled::IdentityUnreadable),
            Err(_) => return Err(Disabled::StartPanicked),
        }
        // A failure from here on drops `inner`, which closes the pipe.
        let inner = WinPeerInbox::start_inner(win_pipe::StartOptions { enabled: true, evidence_open_acl: false }, host_id.clone())
            .await
            .map_err(disabled_of)?;
        // d. One bounded reap pass BEFORE our row is written (a full locator would otherwise refuse us). Never repeated on a
        // timer; a failed or cut-short pass changes nothing else.
        let _ = tokio::time::timeout(REAP_BUDGET, reap_pass(&home_dir, &host_id, TRY_GAP)).await;
        // e. Our row. The guard exists BEFORE the publish begins: a start dropped while the blocking publish runs still
        // removes the row that publish writes (its removal queues behind the publish on the locator lock).
        let row = HostRow { host_id: host_id.clone(), pid: std::process::id(), started: now_secs(), dir: HostDir::Home };
        let gate = Arc::new(PublishGate::default());
        let mut row_guard = RowGuard { dir: home_dir.clone(), host_id: host_id.clone(), gate: gate.clone(), armed: true };
        let (d, r) = (home_dir.clone(), row.clone());
        tokio::task::spawn_blocking(move || gate.publish(&d, r)).await.map_err(|_| Disabled::StartPanicked)??;
        #[cfg(test)]
        if fault::is(&host_id, fault::Fault::PauseAfterPublish) {
            std::future::pending::<()>().await;
        }
        // f. Notices produced by this host's sessions go out through one pump; watches are probed once a minute.
        let directory = inner.directory().clone();
        let token = CancellationToken::new();
        let (notice_tx, notice_rx) = tokio::sync::mpsc::unbounded_channel();
        directory.set_notice_out(notice_tx);
        let pump = tokio::spawn(win_watch::pump(notice_rx, directory.clone(), home_dir.clone(), None));
        let ticker = tokio::spawn(win_watch::ticker(
            directory.clone(),
            PipeProber { home_dir: home_dir.clone(), own: host_id.clone() },
            token.clone(),
        ));
        // The inbox owns the cleanup from here on (shutdown / Drop).
        row_guard.armed = false;
        Ok(PeerInbox {
            host_id,
            directory,
            home_dir,
            row,
            inner,
            token,
            pump: Mutex::new(Some(pump)),
            ticker: Mutex::new(Some(ticker)),
            closed: AtomicBool::new(false),
            locator_problem: Mutex::new(None),
        })
    }

    pub(crate) fn host_id(&self) -> &HostId {
        &self.host_id
    }

    pub(crate) fn directory(&self) -> &Arc<PeerDirectory> {
        &self.directory
    }

    pub(crate) fn row(&self) -> &HostRow {
        &self.row
    }

    pub(crate) fn peers_dir(&self) -> &Arc<CheckedDir> {
        &self.home_dir
    }

    pub(crate) fn pipe_name(&self) -> &str {
        self.inner.pipe_name()
    }

    /// The typed reason the locator could not be read the last time (a rejected file), for status. `None` when it read fine.
    pub(crate) fn locator_problem(&self) -> Option<Disabled> {
        *self.locator_problem.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Other hosts' rows from the locator (display data only), minus ours, at most `cap`. A rejected locator gives no rows
    /// and is remembered in [`PeerInbox::locator_problem`].
    pub(crate) async fn other_hosts(&self, cap: usize) -> Vec<HostRow> {
        let r = read_others(&self.home_dir, &self.host_id, cap).await;
        *self.locator_problem.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = r.as_ref().err().copied();
        r.unwrap_or_default()
    }

    /// One operation against another host of this user: the pipe dial, failure classified.
    pub(crate) async fn dial(&self, host: &HostId, op: Op) -> Result<Reply, DialClass> {
        dial_class(&self.host_id, host, op).await
    }

    /// Judge the other rows and remove the dead ones.
    pub(crate) async fn reap(&self, gap: Duration) -> Result<ReapReport, Disabled> {
        reap_pass(&self.home_dir, &self.host_id, gap).await
    }

    /// `reap` with the production gap of one second.
    pub(crate) async fn reap_stale(&self) -> Result<ReapReport, Disabled> {
        self.reap(TRY_GAP).await
    }

    /// Stop accepting, remove OUR row under the lock. Idempotent. The file work runs on a blocking thread; the lock wait is
    /// bounded (2 s), after which the row is left for the reaper (the pipe is gone anyway).
    pub(crate) async fn shutdown(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        // Packet 11 (S9.2): tell every sender still waiting that this host is going away cleanly (`exited`), while the pipe
        // still works; bounded to `ANNOUNCE_BUDGET`.
        self.announce_exit().await;
        self.stop_accepting();
        self.inner.shutdown().await;
        let (hd, id) = (self.home_dir.clone(), self.host_id.clone());
        let _ = tokio::task::spawn_blocking(move || remove_own_row(&hd, &id)).await;
    }

    /// Every outstanding record of every session is told `exited`; the pump gets `ANNOUNCE_BUDGET` to deliver them.
    async fn announce_exit(&self) {
        self.directory.announce_exit();
        // Dropping the directory's sender lets the pump end once it has delivered what is queued.
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
    }
}

impl Drop for PeerInbox {
    /// Best effort and non-blocking: cancel and stop the pipe (`inner` drops with us); the row removal takes the locator
    /// lock, which may wait, so it is handed to a blocking thread when a runtime is available (fire and forget), else
    /// removed synchronously (bounded by the 2 s lock wait). Call [`PeerInbox::shutdown`] for the full, awaited cleanup.
    fn drop(&mut self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.stop_accepting();
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            let (hd, id) = (self.home_dir.clone(), self.host_id.clone());
            drop(h.spawn_blocking(move || remove_own_row(&hd, &id)));
        } else {
            // No runtime to hand the work to: remove the row here (bounded by the locator lock's 2 s wait).
            remove_own_row(&self.home_dir, &self.host_id);
        }
    }
}

/// Test-only fault injection keyed by host id, so parallel tests never see each other's setting.
#[cfg(test)]
pub(super) mod fault {
    use fuigo_peer::HostId;
    use std::sync::Mutex;

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Fault {
        /// The start never continues after the row is written (a cancelled start).
        PauseAfterPublish,
    }
    static FAULTS: Mutex<Vec<(HostId, Fault)>> = Mutex::new(Vec::new());
    pub(crate) fn set(id: &HostId, f: Fault) {
        FAULTS.lock().unwrap().push((id.clone(), f));
    }
    pub(crate) fn is(id: &HostId, f: Fault) -> bool {
        FAULTS.lock().unwrap().iter().any(|(i, x)| i == id && *x == f)
    }
}

#[cfg(test)]
#[path = "win_inbox_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "win_inbox_pipe_tests.rs"]
mod pipe_tests;
