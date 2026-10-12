//! Host wiring for the peer inbox (packet 8e): ONE inbox per host process, started lazily, never fatal.
//!
//! A host entry point ([`arm`]) records the Fuigo home, nothing more. The inbox starts when the first main session of
//! that host registers ([`session_started`]): there is no production opt-in yet (`configure_peer_admission` has no
//! production caller), so the first registration with `features.peer_messaging` on is the trigger. A failed start is
//! stored as a typed [`Disabled`] reason. Only a full locator ([`Disabled::LocatorFull`]) or a busy lock may be retried,
//! by a later session registration and at most once per [`RETRY_GAP`]; every other reason is final. With the flag off nothing here creates a
//! directory, file, socket, task or thread: every entry point returns first.
//! Non-unix: `PeerInbox::start` reports `UnsupportedPlatform`, so the status is `Unavailable` and nothing else happens.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fuigo_peer::HostId;

use super::{Disabled, PeerInbox};
use crate::session::message_delivery::MessageDeliveryHandle;
use crate::session::peer_message::peer_messaging_enabled;

/// What `/peers` and `list_agents` show later (packets 9 and 12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PeerInboxStatus {
    /// No session has registered yet (or the host shut down): nothing was attempted.
    NotStarted,
    Available { host_id: HostId },
    Unavailable { reason: Disabled },
}

/// The fixed display name offered for a main session. Titles are not offered until packet 9.
const SESSION_NAME: &str = "session";

/// The least time between two start attempts after a retryable failure.
pub(crate) const RETRY_GAP: std::time::Duration = std::time::Duration::from_secs(60);
/// How long `shutdown` waits for a start that is still running.
const SHUTDOWN_START_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

fn retryable(reason: Disabled) -> bool {
    matches!(reason, Disabled::LocatorFull | Disabled::LockBusy)
}

struct Desired {
    handle: MessageDeliveryHandle,
    name: &'static str,
}

enum Phase {
    NotStarted,
    Starting,
    Running(Arc<PeerInbox>),
    /// The reason, and when the attempt ended.
    Failed(Disabled, std::time::Instant),
    Closed,
}

struct State {
    home: Option<PathBuf>,
    phase: Phase,
    /// Main sessions that want to be offered; registered as soon as the inbox runs.
    desired: HashMap<String, Desired>,
}

struct StartPanicGuard {
    host: Arc<PeerHost>,
    done: bool,
}

impl Drop for StartPanicGuard {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let mut g = self.host.lock();
        if matches!(g.phase, Phase::Starting) {
            g.phase = Phase::Failed(Disabled::StartPanicked, std::time::Instant::now());
        }
        drop(g);
        self.host.start_done.notify_one();
    }
}

/// One per host process ([`global`]); tests make their own.
pub(crate) struct PeerHost {
    state: Mutex<State>,
    /// Told when a start that finished after `shutdown` has cleaned up.
    start_done: tokio::sync::Notify,
    retry_gap: std::time::Duration,
    #[cfg(all(test, any(unix, windows)))]
    force: Option<super::StartOptions>,
}

impl PeerHost {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(State { home: None, phase: Phase::NotStarted, desired: HashMap::new() }),
            start_done: tokio::sync::Notify::new(),
            retry_gap: RETRY_GAP,
            #[cfg(all(test, any(unix, windows)))]
            force: None,
        }
    }

    #[cfg(all(test, any(unix, windows)))]
    pub(crate) fn with_options(opts: super::StartOptions) -> Self {
        let mut h = Self::new();
        h.force = Some(opts);
        h
    }

    #[cfg(test)]
    pub(crate) fn with_retry_gap(mut self, gap: std::time::Duration) -> Self {
        self.retry_gap = gap;
        self
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn enabled(&self) -> bool {
        #[cfg(all(test, any(unix, windows)))]
        if let Some(o) = &self.force {
            return o.enabled;
        }
        peer_messaging_enabled()
    }

    /// A host entry point calls this once at start. Records the home only; with the flag off it does nothing at all.
    pub(crate) fn arm(&self, home: PathBuf) {
        if !self.enabled() {
            return;
        }
        let mut g = self.lock();
        if g.home.is_none() {
            g.home = Some(home);
        }
    }

    /// A main session registered (insert_resident). Subagents never come here.
    pub(crate) fn session_started(self: &Arc<Self>, session_id: &str, handle: MessageDeliveryHandle) {
        if !self.enabled() {
            return;
        }
        let mut g = self.lock();
        let Some(home) = g.home.clone() else { return };
        g.desired.insert(session_id.to_owned(), Desired { handle: handle.clone(), name: SESSION_NAME });
        match &g.phase {
            // Registering again raises the incarnation: an address of the replaced session is stale.
            Phase::Running(inbox) => {
                let _ = inbox.directory().register(session_id, handle, SESSION_NAME, session_id);
            }
            Phase::NotStarted => {
                let Ok(rt) = tokio::runtime::Handle::try_current() else { return };
                g.phase = Phase::Starting;
                let me = self.clone();
                drop(g);
                drop(rt.spawn(async move { me.run_start(home).await }));
            }
            // A full locator (or a busy lock) may clear: one new attempt per retry gap, never a loop.
            Phase::Failed(reason, at) if retryable(*reason) && at.elapsed() >= self.retry_gap => {
                let Ok(rt) = tokio::runtime::Handle::try_current() else { return };
                g.phase = Phase::Starting;
                let me = self.clone();
                drop(g);
                drop(rt.spawn(async move { me.run_start(home).await }));
            }
            Phase::Starting | Phase::Failed(..) | Phase::Closed => {}
        }
    }

    async fn run_start(self: Arc<Self>, home: PathBuf) {
        // A panic below leaves no stuck `Starting`: the guard stores a fixed reason while unwinding.
        let mut panic_guard = StartPanicGuard { host: self.clone(), done: false };
        #[cfg(all(test, any(unix, windows)))]
        let started = match &self.force {
            Some(o) => PeerInbox::start_with(&home, o.clone()).await,
            None => PeerInbox::start(&home).await,
        };
        #[cfg(not(all(test, any(unix, windows))))]
        let started = PeerInbox::start(&home).await;
        let closed_meanwhile;
        let late = {
            let mut g = self.lock();
            closed_meanwhile = matches!(g.phase, Phase::Closed);
            match started {
                Ok(inbox) if matches!(g.phase, Phase::Closed) => Some(inbox),
                Ok(inbox) => {
                    let inbox = Arc::new(inbox);
                    for (id, d) in &g.desired {
                        let _ = inbox.directory().register(id, d.handle.clone(), d.name, id);
                    }
                    g.phase = Phase::Running(inbox);
                    None
                }
                Err(reason) => {
                    if !matches!(g.phase, Phase::Closed) {
                        g.phase = Phase::Failed(reason, std::time::Instant::now());
                    }
                    None
                }
            }
        };
        // The host shut down while we were starting: undo at once.
        if let Some(inbox) = late {
            inbox.shutdown().await;
        }
        panic_guard.done = true;
        if closed_meanwhile {
            self.start_done.notify_one();
        }
    }

    /// A main session ended (take_session): replaced, closed, unloaded or crashed.
    pub(crate) fn session_ended(&self, session_id: &str) {
        let mut g = self.lock();
        if g.desired.remove(session_id).is_none() {
            return;
        }
        if let Phase::Running(inbox) = &g.phase {
            inbox.directory().unregister(session_id);
        }
    }

    /// Host exit: bounded shutdown (socket and row removed).
    pub(crate) async fn shutdown(&self) {
        let (inbox, was_starting) = {
            let mut g = self.lock();
            g.desired.clear();
            match std::mem::replace(&mut g.phase, Phase::Closed) {
                Phase::Running(i) => (Some(i), false),
                Phase::Starting => (None, true),
                _ => (None, false),
            }
        };
        if let Some(i) = inbox {
            i.shutdown().await;
        }
        // A start that is still running sees `Closed` when it finishes and undoes itself; give it a bounded moment.
        // If it is cut off instead (the runtime drops it), its socket guard unlinks the socket.
        if was_starting {
            let _ = tokio::time::timeout(SHUTDOWN_START_WAIT, self.start_done.notified()).await;
        }
    }

    pub(crate) fn status(&self) -> PeerInboxStatus {
        if !self.enabled() {
            return PeerInboxStatus::Unavailable { reason: Disabled::FeatureOff };
        }
        match &self.lock().phase {
            Phase::Running(i) => PeerInboxStatus::Available { host_id: i.host_id().clone() },
            Phase::Failed(reason, _) => PeerInboxStatus::Unavailable { reason: *reason },
            Phase::NotStarted | Phase::Starting | Phase::Closed => PeerInboxStatus::NotStarted,
        }
    }

    /// [`reason_message_for`] with the home this host was armed with (every `Failed` phase was started from it).
    /// When no home is recorded the generic text is used.
    pub(crate) fn reason_message(&self, reason: Disabled) -> String {
        let home = match reason {
            Disabled::HomeWritableByOthers => self.lock().home.clone(),
            _ => None,
        };
        reason_message_for(reason, home.as_deref())
    }

    pub(crate) fn has_session(&self, session_id: &str) -> bool {
        self.lock().desired.contains_key(session_id)
    }

    /// The running inbox's directory, for the outstanding-id book (packet 9 records sends here).
    pub(crate) fn inbox(&self) -> Option<Arc<PeerInbox>> {
        match &self.lock().phase {
            Phase::Running(i) => Some(i.clone()),
            _ => None,
        }
    }
}

static GLOBAL: std::sync::OnceLock<Arc<PeerHost>> = std::sync::OnceLock::new();

pub(crate) fn global() -> &'static Arc<PeerHost> {
    GLOBAL.get_or_init(|| Arc::new(PeerHost::new()))
}

/// Used by `MvpAgent::insert_resident` / `take_session`. With the flag off (or an unarmed host, such as headless)
/// the call returns before touching anything, and `global()` is not even created when the flag is off.
pub(crate) fn session_started(session_id: &str, handle: MessageDeliveryHandle) {
    if peer_messaging_enabled() {
        global().session_started(session_id, handle);
    }
}

pub(crate) fn session_ended(session_id: &str) {
    if peer_messaging_enabled() {
        global().session_ended(session_id);
    }
}

/// Host entry points: `run_leader`, `run_stdio_agent`, the pager's leader-off thread. NOT `run_headless` (packet 13).
pub fn arm_peer_host() {
    if peer_messaging_enabled() {
        global().arm(crate::util::fuigo_home::fuigo_home());
    }
}

/// Packet 13: an ACP or headless client opted this session in. Arms the host if no entry point did (headless), and registers
/// the session if the host was not armed when it started. A session already registered keeps its address (no re-register).
pub(crate) fn ensure_session_registered(session_id: &str, handle: MessageDeliveryHandle) {
    if !peer_messaging_enabled() {
        return;
    }
    let host = global();
    host.arm(crate::util::fuigo_home::fuigo_home());
    if !host.has_session(session_id) {
        host.session_started(session_id, handle);
    }
}

/// Bounded shutdown at host exit.
pub async fn shutdown_peer_host() {
    if peer_messaging_enabled() {
        global().shutdown().await;
    }
}

/// The user-facing text for a failed start: [`Disabled::reason_text`], and for a home that other users can write to the
/// real home path and the one command that fixes it. The path is escaped and capped like any displayed reason.
pub(crate) fn reason_message(reason: Disabled) -> String {
    global().reason_message(reason)
}

/// True when `home` can be pasted into a shell word unquoted and unchanged: only `[A-Za-z0-9_./~+@:-]`, not starting with `-`.
fn shell_safe_path(home: &str) -> bool {
    !home.is_empty()
        && !home.starts_with('-')
        && home.chars().all(|c| c.is_ascii_alphanumeric() || "_./~+@:-".contains(c))
}

pub(crate) fn reason_message_for(reason: Disabled, home: Option<&std::path::Path>) -> String {
    match (reason, home) {
        (Disabled::HomeWritableByOthers, Some(home)) if !home.as_os_str().is_empty() => {
            let raw = home.to_string_lossy();
            let shown = fuigo_peer::host::display_escape(&raw, 160);
            // A command is printed only when the path is safe to paste unquoted (and not truncated).
            if cfg!(unix) && shell_safe_path(&raw) && shown == *raw {
                format!(
                    "peer messaging is unavailable: the Fuigo home is not private to this user (run: chmod go-w {shown})"
                )
            } else {
                format!(
                    "peer messaging is unavailable: remove write access for group and others from the Fuigo home: {shown}"
                )
            }
        }
        _ => reason.reason_text().to_owned(),
    }
}

/// `Available { host_id }` or `Unavailable { reason }` for `/peers` and `list_agents` (packets 9 and 12).
pub(crate) fn peer_inbox_status() -> PeerInboxStatus {
    // With the flag off the process global is never created.
    if !peer_messaging_enabled() {
        return PeerInboxStatus::Unavailable { reason: Disabled::FeatureOff };
    }
    if super::driver::remote_attached() {
        return PeerInboxStatus::Unavailable { reason: Disabled::RemoteClientAttached };
    }
    global().status()
}
