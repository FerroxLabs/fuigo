use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fuigo_sandbox::command::CommandTag;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::JoinSet;

use crate::error::{ConnectionError, ProxyError, write_error};
use crate::metrics::ProxyOutcome;
use crate::request::{ParsedRequest, read_head};
use crate::{ProxyIo, ProxyState, ShutdownMode};

/// Where the serve loop takes connections from.
#[async_trait]
pub(crate) trait Acceptor: Send + Sync + 'static {
    async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)>;
}

/// The IPv4 loopback listener, and the `::1` one on the same port when the host has it. The
/// sandbox's network rule names `localhost`, which covers both families, so a peer on `::1` at the
/// proxy's port must reach this proxy and not some other process.
pub(crate) struct Listeners {
    v4: TcpListener,
    v6: Option<TcpListener>,
}

impl Listeners {
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.v4.local_addr()
    }

    #[cfg(test)]
    pub(crate) fn serves_ipv6(&self) -> bool {
        self.v6.is_some()
    }
}

#[async_trait]
impl Acceptor for Listeners {
    async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        match &self.v6 {
            None => self.v4.accept().await,
            Some(v6) => {
                tokio::select! {
                    accepted = self.v4.accept() => accepted,
                    accepted = v6.accept() => accepted,
                }
            }
        }
    }
}

/// Binds `127.0.0.1` on a free port and `::1` on the same port. A host with no IPv6 loopback
/// serves IPv4 only; a port another process already holds on `::1` is skipped for another, and
/// when every port tried is held there, the proxy serves IPv4 only (silently: no warning is logged).
pub(crate) async fn bind_loopback() -> io::Result<Listeners> {
    bind_loopback_with(|port| TcpListener::bind((Ipv6Addr::LOCALHOST, port))).await
}

/// [`bind_loopback`] with the `::1` bind injected, so tests can occupy it.
pub(crate) async fn bind_loopback_with<F, Fut>(bind_v6: F) -> io::Result<Listeners>
where
    F: Fn(u16) -> Fut,
    Fut: std::future::Future<Output = io::Result<TcpListener>>,
{
    for _ in 0..16 {
        let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = v4.local_addr()?.port();
        match bind_v6(port).await {
            Ok(v6) => return Ok(Listeners { v4, v6: Some(v6) }),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
            Err(_) => return Ok(Listeners { v4, v6: None }),
        }
    }
    // Every port tried is held on `::1`: serve IPv4 loopback only, as on a host without IPv6,
    // rather than not at all.
    let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    Ok(Listeners { v4, v6: None })
}

/// Connections that have not yet presented a valid credential, oldest first. When every slot is
/// taken, the oldest one past the grace period is dropped for a newcomer, so peers that hold
/// connections open and say nothing cannot keep the wrapped commands off the proxy.
#[derive(Default)]
pub(crate) struct PreAuth {
    next: AtomicU64,
    entries: Mutex<VecDeque<PreAuthEntry>>,
}

struct PreAuthEntry {
    id: u64,
    since: Instant,
    evict: oneshot::Sender<()>,
}

impl PreAuth {
    pub(crate) fn enter(self: &Arc<Self>) -> (PreAuthGuard, oneshot::Receiver<()>) {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (evict, evicted) = oneshot::channel();
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(PreAuthEntry {
                id,
                since: Instant::now(),
                evict,
            });
        (
            PreAuthGuard {
                id,
                registry: self.clone(),
            },
            evicted,
        )
    }

    /// Drops the oldest unauthenticated connection if it is older than `grace`.
    fn evict_stale(&self, grace: Duration) -> bool {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries
            .front()
            .is_some_and(|entry| entry.since.elapsed() >= grace)
            && let Some(entry) = entries.pop_front()
        {
            let _ = entry.evict.send(());
            return true;
        }
        false
    }

    fn remove(&self, id: u64) {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|entry| entry.id != id);
    }
}

/// Removes the connection from the pre-authentication list when it authenticates or ends.
pub(crate) struct PreAuthGuard {
    id: u64,
    registry: Arc<PreAuth>,
}

impl PreAuthGuard {
    fn leave(&self) {
        self.registry.remove(self.id);
    }
}

impl Drop for PreAuthGuard {
    fn drop(&mut self) {
        self.leave();
    }
}

pub(crate) async fn serve<L: Acceptor>(
    listener: L,
    state: Arc<ProxyState>,
    #[cfg(test)] task_observer: Arc<std::sync::atomic::AtomicUsize>,
    mut shutdown: mpsc::Receiver<ShutdownMode>,
) {
    let semaphore = Arc::new(Semaphore::new(state.options.max_connections));
    let mut tasks = JoinSet::new();
    #[cfg(test)]
    observe_tasks(&tasks, &task_observer);
    let mode = loop {
        tokio::select! {
            biased;
            mode = shutdown.recv() => break mode.unwrap_or(ShutdownMode::Abort),
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {
                #[cfg(test)]
                observe_tasks(&tasks, &task_observer);
            }
            accepted = listener.accept() => {
                let (mut stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(_) => {
                        // A failed accept (a connection reset before it was taken, no free
                        // descriptors for a moment) is not the end of the proxy.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                if !peer.ip().is_loopback() {
                    continue;
                }
                let Some(permit) = admit_connection(&semaphore, &state, &mut stream).await else {
                    continue;
                };
                let state = state.clone();
                let (guard, evicted) = state.pre_auth.enter();
                tasks.spawn(async move {
                    let _permit = permit;
                    serve_connection(&mut stream, &state, guard, evicted).await;
                });
                #[cfg(test)]
                observe_tasks(&tasks, &task_observer);
            }
        }
    };
    drop(listener);
    // Fail closed before anything is waited for: every parked connection answers itself with a
    // deny, and the decider withdraws what it raised for them, so a drain never waits out a hold
    state.stopping.send_replace(true);
    state.decider.stopping();
    if matches!(mode, ShutdownMode::Abort) {
        tasks.shutdown().await;
        #[cfg(test)]
        observe_tasks(&tasks, &task_observer);
        return;
    }
    while tasks.join_next().await.is_some() {
        #[cfg(test)]
        observe_tasks(&tasks, &task_observer);
    }
}

async fn admit_connection<S: ProxyIo>(
    semaphore: &Arc<Semaphore>,
    state: &ProxyState,
    stream: &mut S,
) -> Option<OwnedSemaphorePermit> {
    match semaphore.clone().try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(_) => {
            // Full: drop a long-silent unauthenticated peer for this one if there is one.
            if state.pre_auth.evict_stale(state.options.pre_auth_grace)
                && let Ok(Ok(permit)) = tokio::time::timeout(
                    Duration::from_millis(250),
                    semaphore.clone().acquire_owned(),
                )
                .await
            {
                return Some(permit);
            }
            state.metrics.record(ProxyOutcome::Overloaded);
            // The client may already be gone; there is nothing further to do with the failure.
            let _ = write_error(
                stream,
                &ProxyError::Overloaded,
                state.options.request_timeout,
            )
            .await;
            None
        }
    }
}

#[cfg(test)]
fn observe_tasks(tasks: &JoinSet<()>, observer: &std::sync::atomic::AtomicUsize) {
    observer.store(tasks.len(), std::sync::atomic::Ordering::Relaxed);
}

async fn serve_connection<S: ProxyIo>(
    client: &mut S,
    state: &ProxyState,
    guard: PreAuthGuard,
    evicted: oneshot::Receiver<()>,
) {
    match handle_connection(client, state, guard, evicted).await {
        Ok(()) => {}
        Err(ConnectionError::Precommit(error)) => {
            state.metrics.record(error.outcome());
            let _ = write_error(client, &error, state.options.request_timeout).await;
        }
        Err(error @ ConnectionError::Committed(_)) => {
            state.metrics.record(error.outcome());
        }
    }
}

async fn handle_connection<S: ProxyIo>(
    client: &mut S,
    state: &ProxyState,
    guard: PreAuthGuard,
    evicted: oneshot::Receiver<()>,
) -> Result<(), ConnectionError> {
    let until_authenticated = async {
        let (head, buffered) = tokio::time::timeout(
            state.options.request_timeout,
            read_head(client, state.options.max_header_bytes),
        )
        .await
        .map_err(|_| ConnectionError::Precommit(ProxyError::Timeout))?
        .map_err(ConnectionError::Precommit)?;
        let request = ParsedRequest::parse(&head, state.options.max_headers)
            .map_err(ConnectionError::Precommit)?;
        let call = authenticate(&request, state).map_err(ConnectionError::Precommit)?;
        Ok::<_, ConnectionError>((request, buffered, call))
    };
    // Evicted while still unauthenticated: the connection is simply dropped.
    let dropped = async {
        if evicted.await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    let (request, buffered, call) = tokio::select! {
        () = dropped => return Ok(()),
        result = until_authenticated => result?,
    };
    guard.leave();
    if request.method.eq_ignore_ascii_case("CONNECT") {
        return crate::connect::handle(client, request, buffered, state, call.as_ref()).await;
    }
    if request.method.eq_ignore_ascii_case("TRACE") {
        return Err(ConnectionError::Precommit(ProxyError::Malformed));
    }
    crate::http::handle(client, request, buffered, state, call.as_ref()).await
}

fn authenticate(
    request: &ParsedRequest,
    state: &ProxyState,
) -> Result<Option<CommandTag>, ProxyError> {
    let authenticated = request
        .single_header("proxy-authorization")?
        .ok_or(ProxyError::Authentication)
        .and_then(|header| state.credentials.authenticate(header));
    match authenticated {
        Err(ProxyError::Authentication) if state.decider.admits_unauthenticated() => Ok(None),
        other => other,
    }
}
