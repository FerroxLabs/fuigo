//! The Windows versions of the notice pump and the once-a-minute watch ticker (packet 15c).
//!
//! DUPLICATED from `watch::io` (which is `cfg(unix)` and unchanged): the same logic with the pipe dial in place of the socket
//! dial and no `Locations`. The decision code (`probe_pass`, `WatchTable`, `Prober`, `Probe`) is the shared one in `watch.rs`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use fuigo_peer::limits::{WATCH_PROBE_CAP_MS, WATCH_PROBE_SECS};
use fuigo_peer::{BoundedId, HostId, HostRow, Op, Reply, TryResult};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_util::sync::CancellationToken;

use super::directory::PeerDirectory;
use super::rows::{LOCATOR_NAME, decode_rows};
use super::watch::{Probe, Prober, probe_pass};
use super::win_pipe;
use super::{CheckedDir, read_locator};
use crate::session::peer_watch::Outbound;

/// One notice delivery attempt is cut off after this long; one retry follows after `RETRY_GAP`.
const NOTICE_ATTEMPT: Duration = Duration::from_secs(5);
const RETRY_GAP: Duration = Duration::from_secs(2);
/// Notice deliveries in flight at once.
const PUMP_PARALLEL: usize = 8;

/// The locator rows (display data only) from the home's locator file; an unreadable or rejected file gives none.
pub(crate) async fn rows(home_dir: &Arc<CheckedDir>) -> Vec<HostRow> {
    let dir = home_dir.clone();
    let bytes = tokio::task::spawn_blocking(move || read_locator(&dir, LOCATOR_NAME)).await.ok().and_then(Result::ok).flatten();
    decode_rows(bytes.as_deref())
}

pub(crate) struct PipeProber {
    pub home_dir: Arc<CheckedDir>,
    pub own: HostId,
}

impl Prober for PipeProber {
    async fn probe(&self, host: &HostId) -> Probe {
        if !rows(&self.home_dir).await.iter().any(|r| &r.host_id == host) {
            return Probe::Gone { row_present: false };
        }
        let one = super::win_inbox::try_hello(&self.own, host);
        match tokio::time::timeout(Duration::from_millis(WATCH_PROBE_CAP_MS), one).await {
            Ok(TryResult::Hello(h)) if &h == host => Probe::Alive,
            _ => Probe::Gone { row_present: true },
        }
    }
}

/// Send one notice to the host that sent the message. A same-host target is routed in process.
async fn deliver(dir: &Arc<PeerDirectory>, home_dir: &Arc<CheckedDir>, out: &Outbound) {
    let own = dir.host_id().clone();
    let target = HostId::of(&out.to);
    let Ok(id) = BoundedId::new(&out.message_id) else { return };
    if target == own {
        dir.route_notice(&id, out.kind, Some(&own));
        return;
    }
    for attempt in 0..2 {
        if rows(home_dir).await.iter().any(|r| r.host_id == target) {
            let op = Op::Notice { message_id: id.clone(), kind: out.kind };
            let call = win_pipe::dial(&own, &target, op);
            if let Ok(Ok(Reply::Notice {})) = tokio::time::timeout(NOTICE_ATTEMPT, call).await {
                return;
            }
        }
        if attempt == 0 {
            tokio::time::sleep(RETRY_GAP).await;
        }
    }
    // Unanswered after the retry: the sender's own watch ends with `outcome unknown` (or a probe verdict).
}

/// Drain `rx` until every sender is gone or `token` is cancelled; deliveries run up to 8 at once.
pub(crate) async fn pump(
    mut rx: UnboundedReceiver<Outbound>,
    dir: Arc<PeerDirectory>,
    home_dir: Arc<CheckedDir>,
    token: Option<CancellationToken>,
) {
    let gate = Arc::new(tokio::sync::Semaphore::new(PUMP_PARALLEL));
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        let next = match &token {
            Some(t) => tokio::select! { () = t.cancelled() => None, n = rx.recv() => n },
            None => rx.recv().await,
        };
        let Some(out) = next else { break };
        let Ok(permit) = gate.clone().acquire_owned().await else { break };
        let (dir, home_dir) = (dir.clone(), home_dir.clone());
        tasks.spawn(async move {
            deliver(&dir, &home_dir, &out).await;
            drop(permit);
        });
    }
    while tasks.join_next().await.is_some() {}
}

/// Once a minute until `token` is cancelled.
pub(crate) async fn ticker(dir: Arc<PeerDirectory>, prober: PipeProber, token: CancellationToken) {
    let mut tick = tokio::time::interval(Duration::from_secs(WATCH_PROBE_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tokio::select! { () = token.cancelled() => return, _ = tick.tick() => {} }
        probe_pass(&dir, &prober, Instant::now()).await;
    }
}
