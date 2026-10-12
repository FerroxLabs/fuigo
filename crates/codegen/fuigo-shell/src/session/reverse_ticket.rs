//! Tickets for reverse MCP calls (`fuigo/mcp/sdk_call`), P189 round 4 (audit F5).
//!
//! A reverse call carries no session id on the wire, so the park hold could only judge it by the connection. A
//! ticket gives it an identity inside the process: [`GatewayAcpInvoker::invoke`] creates one (the admission
//! decision is taken once, here), sends its id as `params._meta["fuigo/internal/ticket"]`, and
//! `ParkHoldClient::ext_method` strips that key before the inner client is called, so it is never written.
//!
//! [`Ticket::wait_admitted`] is the single wait, used at the invoker and at delivery: it waits on the ticket's
//! OWN session (not on "any park here"), lets a call created inside a parked load's window go out, and ends
//! `Err(Cancelled)` when an implicit unpark cancelled the park it waited under or its guard was dropped.
//!
//! [`GatewayAcpInvoker::invoke`]: crate::session::acp_mcp::GatewayAcpInvoker

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use crate::session::quiesce;

/// `params._meta` key that carries the ticket id from the invoker to the park hold. Internal: never written.
pub(crate) const TICKET_META_KEY: &str = "fuigo/internal/ticket";

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static TABLE: LazyLock<Mutex<HashMap<u64, Arc<Ticket>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// The ticket was cancelled (its invoker gave up) or the park it waited under was cancelled by a new prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cancelled;

#[derive(Default)]
struct State {
    /// The (tree root, cancel generation) seen when the call first met a park.
    generation: Option<(String, u64)>,
    /// Created while a parked load of its root was being answered: never held (decided once, at creation).
    in_load_window: bool,
    /// The call waited out a park: it is written marked `fuigo/released`.
    released: bool,
}

pub(crate) struct Ticket {
    session: String,
    state: Mutex<State>,
    cancelled: tokio::sync::watch::Sender<bool>,
}

fn table() -> std::sync::MutexGuard<'static, HashMap<u64, Arc<Ticket>>> {
    TABLE.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Owns a ticket for the life of one reverse call; dropping it removes the ticket and cancels the held request.
pub(crate) struct TicketGuard {
    id: u64,
    ticket: Arc<Ticket>,
}

/// Create the ticket of a reverse call made now by `session_id`. The admission decision is taken here, once:
/// a call created while its tree is parked remembers the park's cancel generation and whether a parked load of
/// the root is being answered (such a call is part of that load and goes out).
pub(crate) fn create(session_id: &str) -> TicketGuard {
    let mut state = State::default();
    if quiesce::is_parked(session_id) {
        let root = quiesce::root_of(session_id);
        state.in_load_window = quiesce::is_loading(&root);
        state.generation = Some((root.clone(), quiesce::cancel_generation(&root)));
    }
    let ticket = Arc::new(Ticket {
        session: session_id.to_owned(),
        state: Mutex::new(state),
        cancelled: tokio::sync::watch::channel(false).0,
    });
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    table().insert(id, ticket.clone());
    TicketGuard { id, ticket }
}

/// The live ticket `id`, or `None` when its call is over (its guard was dropped).
pub(crate) fn lookup(id: u64) -> Option<Arc<Ticket>> {
    table().get(&id).cloned()
}

impl TicketGuard {
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn ticket(&self) -> &Ticket {
        &self.ticket
    }
}

impl Drop for TicketGuard {
    fn drop(&mut self) {
        table().remove(&self.id);
        self.ticket.cancelled.send_replace(true);
    }
}

impl Ticket {
    /// Wait until the call may go out: its session's tree is not parked, or it was created inside a parked load
    /// window. `Ok(released)` says whether it waited out a park (so it goes out marked `fuigo/released`).
    pub(crate) async fn wait_admitted(&self) -> Result<bool, Cancelled> {
        let mut changes = quiesce::subscribe();
        let mut cancel = self.cancelled.subscribe();
        loop {
            if *cancel.borrow() {
                return Err(Cancelled);
            }
            {
                let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let parked = quiesce::is_parked(&self.session);
                if parked && state.generation.is_none() {
                    let root = quiesce::root_of(&self.session);
                    let generation = quiesce::cancel_generation(&root);
                    state.generation = Some((root, generation));
                }
                if let Some((root, generation)) = &state.generation
                    && quiesce::cancel_generation(root) != *generation
                {
                    return Err(Cancelled);
                }
                if !parked || state.in_load_window {
                    // Grok r4 #6: a call created while its tree was parked (outside a load window) belongs to
                    // the park even if an unpark won before the first check here: it goes out marked released.
                    return Ok(state.released || (state.generation.is_some() && !state.in_load_window));
                }
                state.released = true;
            }
            tokio::select! {
                changed = changes.changed() => {
                    if changed.is_err() {
                        return Ok(true);
                    }
                }
                _ = cancel.changed() => {}
            }
        }
    }
}
