//! The sending host's side of an idle watch, and the delivery of notices (packet 11; DESIGN S9.2, S9.3).
//!
//! The host keeps its outstanding watches in a [`WatchTable`] (at most 64 per sending session and 256 per host; past a cap the
//! OLDEST ends with a local `unavailable` notice). Once a minute [`probe_pass`] asks each watched target HOST for a hello (no
//! model, no message; at most 8 at once, 3 s each) and decides per watch:
//! - the host answers: nothing, the watch stays;
//! - it does not answer and its locator row is still there: `unavailable` ("target unavailable (not a confirmed exit)"), because a
//!   killed host leaves its row until the reaper runs and nothing proves it exited;
//! - it does not answer, its row is gone, and that has been seen on two passes in a row: `exited` (a host that shut down removes
//!   its row; it also announces `exited` itself before it goes);
//! - a watch of the same host is `exited` once its session is no longer registered;
//! - a watch older than `WATCH_EXPIRY_SECS` (12 h) ends with the local `outcome unknown` notice.
//!
//! A notice reaches the sending session only through `MessageDeliveryHandle::record_sent_notice_wake`. The pump that sends the
//! notices a RECEIVING session produced (`Outbound`) retries an unanswered delivery once.

use std::future::Future;
use std::time::{Duration, Instant};

use fuigo_peer::limits::{MAX_WATCHES_PER_HOST, MAX_WATCHES_PER_SESSION, WATCH_EXPIRY_SECS, WATCH_PROBES_AT_ONCE};
use fuigo_peer::{Address, HostId, NoticeKind};

use super::directory::PeerDirectory;

/// One outstanding watch of a message this host's session sent.
#[derive(Debug, Clone)]
pub(crate) struct SentWatch {
    pub session_id: String,
    pub message_id: String,
    pub target: Address,
    pub since: Instant,
    /// Passes on which the target host did not answer AND its row was gone.
    pub gone_passes: u8,
}

#[derive(Default)]
pub(crate) struct WatchTable {
    items: Vec<SentWatch>,
}

impl WatchTable {
    /// Add a watch; returns the watches pushed out by the caps (oldest first), which the caller ends with `unavailable`.
    pub(crate) fn add(&mut self, w: SentWatch) -> Vec<SentWatch> {
        let mut out = Vec::new();
        while self.items.iter().filter(|i| i.session_id == w.session_id).count() >= MAX_WATCHES_PER_SESSION {
            if let Some(pos) = self.items.iter().position(|i| i.session_id == w.session_id) {
                out.push(self.items.remove(pos));
            }
        }
        while self.items.len() >= MAX_WATCHES_PER_HOST {
            out.push(self.items.remove(0));
        }
        self.items.push(w);
        out
    }

    pub(crate) fn remove(&mut self, message_id: &str) {
        self.items.retain(|i| i.message_id != message_id);
    }

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn snapshot(&self) -> Vec<SentWatch> {
        self.items.clone()
    }

    fn set_gone(&mut self, message_id: &str, passes: u8) {
        if let Some(i) = self.items.iter_mut().find(|i| i.message_id == message_id) {
            i.gone_passes = passes;
        }
    }
}

/// What one hello probe of a target host found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Probe {
    /// The host answered with its own hello.
    Alive,
    /// No answer; `row_present` says whether its locator row still exists.
    Gone { row_present: bool },
}

pub(crate) trait Prober: Send + Sync {
    fn probe(&self, host: &HostId) -> impl Future<Output = Probe> + Send;
}

/// The fixed local verdict for a watch (`None` = `outcome unknown`).
type Verdict = Option<NoticeKind>;

/// One pass over every outstanding watch. Pure apart from the prober and the directory's local notice delivery.
pub(crate) async fn probe_pass<P: Prober>(dir: &PeerDirectory, prober: &P, now: Instant) {
    let watches = dir.with_watches(|t| t.snapshot());
    let own = dir.host_id().clone();
    let mut verdicts: Vec<(SentWatch, Verdict)> = Vec::new();
    let mut remote: Vec<SentWatch> = Vec::new();
    for w in watches {
        if now.saturating_duration_since(w.since) >= Duration::from_secs(WATCH_EXPIRY_SECS) {
            verdicts.push((w, None));
        } else if HostId::of(&w.target) == own {
            if !dir.target_alive(&w.target) {
                verdicts.push((w, Some(NoticeKind::Exited)));
            }
        } else {
            remote.push(w);
        }
    }
    let mut hosts: Vec<HostId> = remote.iter().map(|w| HostId::of(&w.target)).collect();
    hosts.sort();
    hosts.dedup();
    let mut found: std::collections::HashMap<HostId, Probe> = std::collections::HashMap::new();
    for chunk in hosts.chunks(WATCH_PROBES_AT_ONCE) {
        let results = futures::future::join_all(chunk.iter().map(|h| async move { (h.clone(), prober.probe(h).await) })).await;
        found.extend(results);
    }
    for w in remote {
        match found.get(&HostId::of(&w.target)).copied().unwrap_or(Probe::Alive) {
            Probe::Alive => dir.with_watches(|t| t.set_gone(&w.message_id, 0)),
            Probe::Gone { row_present: true } => verdicts.push((w, Some(NoticeKind::Unavailable))),
            Probe::Gone { row_present: false } => {
                let passes = w.gone_passes.saturating_add(1);
                if passes >= 2 {
                    verdicts.push((w, Some(NoticeKind::Exited)));
                } else {
                    dir.with_watches(|t| t.set_gone(&w.message_id, passes));
                }
            }
        }
    }
    for (w, v) in verdicts {
        dir.notify_local(&w.session_id, &w.message_id, v);
    }
}

#[cfg(unix)]
pub(super) mod io {
    //! The sockets: the real prober, the notice pump and the once-a-minute ticker.
    use std::sync::Arc;

    use fuigo_peer::limits::{WATCH_PROBE_CAP_MS, WATCH_PROBE_SECS};
    use fuigo_peer::{BoundedId, HostId, HostRow, Op, Reply};
    use tokio::sync::mpsc::UnboundedReceiver;
    use tokio_util::sync::CancellationToken;

    use super::super::dial::{Locations, dial, try_hello};
    use super::super::directory::PeerDirectory;
    use super::super::{CheckedDir, reap};
    use super::{Duration, Instant, Probe, Prober, probe_pass};
    use crate::session::peer_watch::Outbound;

    /// One notice delivery attempt is cut off after this long; one retry follows after `RETRY_GAP`.
    const NOTICE_ATTEMPT: Duration = Duration::from_secs(5);
    const RETRY_GAP: Duration = Duration::from_secs(2);
    /// Notice deliveries in flight at once.
    const PUMP_PARALLEL: usize = 8;

    /// The locator rows (display data only) from the home's locator file.
    pub(crate) async fn rows(home_dir: &Arc<CheckedDir>) -> Vec<HostRow> {
        let dir = home_dir.clone();
        let bytes = tokio::task::spawn_blocking(move || super::super::locator::read_locator(&dir, reap::LOCATOR_NAME))
            .await
            .ok()
            .and_then(Result::ok)
            .flatten();
        reap::decode_rows(bytes.as_deref())
    }

    pub(crate) struct SocketProber {
        pub loc: Locations,
        pub home_dir: Arc<CheckedDir>,
        pub own: HostId,
    }

    impl Prober for SocketProber {
        async fn probe(&self, host: &HostId) -> Probe {
            let row = rows(&self.home_dir).await.into_iter().find(|r| &r.host_id == host);
            let Some(row) = row else {
                // No row: still look for a socket (the row file can lag), in the home's own directory choice.
                return Probe::Gone { row_present: false };
            };
            let one = try_hello(&self.loc, &self.own, host, row.dir);
            match tokio::time::timeout(Duration::from_millis(WATCH_PROBE_CAP_MS), one).await {
                Ok(fuigo_peer::TryResult::Hello(h)) if &h == host => Probe::Alive,
                _ => Probe::Gone { row_present: true },
            }
        }
    }

    /// Send one notice to the host that sent the message. A same-host target is routed in process.
    async fn deliver(dir: &Arc<PeerDirectory>, loc: &Locations, home_dir: &Arc<CheckedDir>, out: &Outbound) {
        let own = dir.host_id().clone();
        let target = HostId::of(&out.to);
        let Ok(id) = BoundedId::new(&out.message_id) else { return };
        if target == own {
            dir.route_notice(&id, out.kind, Some(&own));
            return;
        }
        for attempt in 0..2 {
            if let Some(row) = rows(home_dir).await.into_iter().find(|r| r.host_id == target) {
                let op = Op::Notice { message_id: id.clone(), kind: out.kind };
                let call = dial(loc, &own, &row.host_id, row.dir, op);
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
        loc: Locations,
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
            let (dir, loc, home_dir) = (dir.clone(), loc.clone(), home_dir.clone());
            tasks.spawn(async move {
                deliver(&dir, &loc, &home_dir, &out).await;
                drop(permit);
            });
        }
        while tasks.join_next().await.is_some() {}
    }

    /// Once a minute until `token` is cancelled.
    pub(crate) async fn ticker(dir: Arc<PeerDirectory>, prober: SocketProber, token: CancellationToken) {
        let mut tick = tokio::time::interval(Duration::from_secs(WATCH_PROBE_SECS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tokio::select! { () = token.cancelled() => return, _ = tick.tick() => {} }
            probe_pass(&dir, &prober, Instant::now()).await;
        }
    }
}
