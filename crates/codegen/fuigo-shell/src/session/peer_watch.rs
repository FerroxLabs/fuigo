//! Receiver side of an idle watch and of the delivery notices for held messages (packet 11; DESIGN S9.1, S9.3).
//!
//! One [`WatchBook`] per session, shared through the session's `PeerGate`. The inbox (`ConnHost`) registers a record BEFORE it
//! hands a watched send to the session, so a turn that ends before the reply cannot miss it. The session calls back in three
//! places only: a held message's typed notice (`Inner::notice`), a peer message starting or joining a turn
//! ([`WatchBook::bind_turn`]) and a turn ending (the `TurnConvGuard` drop).
//!
//! What goes back to the sender is an [`Outbound`]: a bounded message id, the sender's address and a typed kind. Never text.
//! Records are bounded: at most `MAX_WATCHES_PER_SESSION` watches per session (the same sender's oldest is ended with
//! `unavailable`; a sender with none gets `rate_limited`, nobody else's is evicted) and
//! `MAX_WATCHES_PER_HOST` per host (a new watch past it is refused), plus at most the same number of plain held records.
//! Nothing here reads a notice: a notice RECEIVED by this session never reaches this module, so a notice cannot cause one.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use fuigo_peer::limits::{MAX_WATCHES_PER_HOST, MAX_WATCHES_PER_SESSION};
use fuigo_peer::{Address, NoticeKind, RejectReason};

use super::peer_admission::NoticeKind as SessionNotice;

/// A notice to send to the host that sent `message_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Outbound {
    pub to: Address,
    pub message_id: String,
    pub kind: NoticeKind,
}

pub(crate) type NoticeOut = tokio::sync::mpsc::UnboundedSender<Outbound>;

/// Counts one armed watch against the host total; frees it on drop, by any path.
#[derive(Debug)]
pub(crate) struct WatchTicket(Arc<AtomicUsize>);

impl WatchTicket {
    fn take(total: &Arc<AtomicUsize>) -> Option<Self> {
        let mut cur = total.load(Ordering::SeqCst);
        loop {
            if cur >= MAX_WATCHES_PER_HOST {
                return None;
            }
            match total.compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return Some(Self(total.clone())),
                Err(now) => cur = now,
            }
        }
    }
}

impl Drop for WatchTicket {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Rec {
    message_id: String,
    from: Address,
    /// The sender asked for an idle notice.
    watch: bool,
    /// The message started or joined a turn: the watch fires when that turn ends.
    bound: bool,
    /// The message was held for its receiver's user. A plain record that is NOT held (delivered, or not yet settled) only lets
    /// a refusal reach the sender: it is dropped silently when its turn ends or the session ends, and goes first at the cap.
    held: bool,
    out: NoticeOut,
    _ticket: Option<WatchTicket>,
}

#[derive(Default)]
struct BookInner {
    recs: VecDeque<Rec>,
    turns_active: u32,
}

/// See the module docs.
#[derive(Default)]
pub(crate) struct WatchBook {
    inner: Mutex<BookInner>,
}

/// Plain held records kept per session (those without a watch).
const MAX_HELD_RECORDS: usize = MAX_WATCHES_PER_SESSION;

fn emit(out: &NoticeOut, rec: &Rec, kind: NoticeKind) {
    let _ = out.send(Outbound { to: rec.from.clone(), message_id: rec.message_id.clone(), kind });
}

impl std::fmt::Debug for WatchBook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WatchBook({} records)", self.lock().recs.len())
    }
}

impl WatchBook {
    fn lock(&self) -> std::sync::MutexGuard<'_, BookInner> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Register a watched send before it is delivered. `Err` = refused: `rate_limited` at the per-session cap when the sender has
    /// no watch of its own to replace, `unavailable` at the host total or when the id belongs to another sender. At the
    /// per-session cap the sender's OWN oldest watch is ended with `unavailable` and this one takes its place; another sender's
    /// watch is never evicted.
    pub(crate) fn register_watch(
        &self,
        message_id: &str,
        from: &Address,
        out: &NoticeOut,
        host_total: &Arc<AtomicUsize>,
    ) -> Result<(), RejectReason> {
        let mut g = self.lock();
        if let Some(r) = g.recs.iter().find(|r| r.message_id == message_id) {
            // The same id from the same sender is a retry; from another sender it is never merged.
            return if r.from == *from { Ok(()) } else { Err(RejectReason::Unavailable) };
        }
        if g.recs.iter().filter(|r| r.watch).count() >= MAX_WATCHES_PER_SESSION {
            let own = g.recs.iter().position(|r| r.watch && r.from == *from).ok_or(RejectReason::RateLimited)?;
            if let Some(old) = g.recs.remove(own) {
                emit(&old.out, &old, NoticeKind::Unavailable);
            }
        }
        let ticket = WatchTicket::take(host_total).ok_or(RejectReason::Unavailable)?;
        g.recs.push_back(Rec {
            message_id: message_id.to_owned(),
            from: from.clone(),
            watch: true,
            bound: false,
            held: false,
            out: out.clone(),
            _ticket: Some(ticket),
        });
        Ok(())
    }

    /// Remove the record for `message_id` whatever its state: used when the call that registered it is dropped before it settled.
    pub(crate) fn forget(&self, message_id: &str) {
        self.lock().recs.retain(|r| r.message_id != message_id);
    }

    /// A watch-only call: fires at once when no turn is running, else when the current turn ends.
    pub(crate) fn watch_only(
        &self,
        message_id: &str,
        from: &Address,
        out: &NoticeOut,
        host_total: &Arc<AtomicUsize>,
    ) -> Result<(), RejectReason> {
        {
            let g = self.lock();
            if g.turns_active == 0 {
                let _ = out.send(Outbound { to: from.clone(), message_id: message_id.to_owned(), kind: NoticeKind::Idle });
                return Ok(());
            }
        }
        self.register_watch(message_id, from, out, host_total)?;
        let mut g = self.lock();
        let idle_now = g.turns_active == 0;
        if let Some(r) = g.recs.iter_mut().find(|r| r.message_id == message_id) {
            r.bound = true;
        }
        if idle_now {
            // The turn ended between the two locks.
            Self::fire_bound(&mut g);
        }
        Ok(())
    }

    /// Register a plain (unwatched) record BEFORE the send, so a turn that starts at once cannot miss it. Best effort: at the
    /// plain-record cap the oldest delivered plain record is dropped; when none can go (all held) nothing is added.
    pub(crate) fn register_plain(&self, message_id: &str, from: &Address, out: &NoticeOut) {
        let mut g = self.lock();
        if g.recs.iter().any(|r| r.message_id == message_id) {
            return;
        }
        if g.recs.iter().filter(|r| !r.watch).count() >= MAX_HELD_RECORDS {
            let Some(old) = g.recs.iter().position(|r| !r.watch && !r.held) else { return };
            g.recs.remove(old);
        }
        g.recs.push_back(Rec {
            message_id: message_id.to_owned(),
            from: from.clone(),
            watch: false,
            bound: false,
            held: false,
            out: out.clone(),
            _ticket: None,
        });
    }

    /// The outcome of the delivery: a rejected send forgets its record; a held one keeps it (it arms at release); a plain held
    /// message (no watch) gets a record so its release, expiry or refusal reaches the sender; a delivered one is marked so, which
    /// keeps a plain record until its turn ends (an explicit refusal of it still reaches the sender).
    pub(crate) fn settled(&self, message_id: &str, from: &Address, held: bool, rejected: bool, out: &NoticeOut) {
        let mut g = self.lock();
        let known = g.recs.iter().any(|r| r.message_id == message_id);
        if rejected {
            g.recs.retain(|r| r.message_id != message_id);
        } else if !known {
            if held && g.recs.iter().filter(|r| !r.watch).count() < MAX_HELD_RECORDS {
                g.recs.push_back(Rec {
                    message_id: message_id.to_owned(),
                    from: from.clone(),
                    watch: false,
                    bound: false,
                    held: true,
                    out: out.clone(),
                    _ticket: None,
                });
            }
        } else if held && let Some(r) = g.recs.iter_mut().find(|r| r.message_id == message_id) {
            r.held = true;
        }
    }

    /// A peer message started or joined a turn.
    pub(crate) fn bind_turn(&self, message_id: &str) {
        let mut g = self.lock();
        if let Some(r) = g.recs.iter_mut().find(|r| r.message_id == message_id) {
            r.bound = true;
        }
    }

    /// Did the sender ask for an idle notice about `message_id` (a watched send)? Only then does a text-only reply count as a
    /// refusal the sender is told about.
    pub(crate) fn is_watched(&self, message_id: &str) -> bool {
        self.lock().recs.iter().any(|r| r.watch && r.message_id == message_id)
    }

    pub(crate) fn turn_started(&self) {
        let mut g = self.lock();
        g.turns_active = g.turns_active.saturating_add(1);
    }

    /// A turn ended (normally, cancelled, failed or panicked): every watch bound to it fires ONCE with `idle`.
    pub(crate) fn turn_ended(&self) {
        let mut g = self.lock();
        g.turns_active = g.turns_active.saturating_sub(1);
        if g.turns_active == 0 {
            Self::fire_bound(&mut g);
        }
    }

    fn fire_bound(g: &mut BookInner) {
        let (fire, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut g.recs).into_iter().partition(|r| r.bound);
        g.recs = keep.into();
        // A plain record bound to the turn ends with it, silently.
        for r in fire.into_iter().filter(|r| r.watch) {
            emit(&r.out, &r, NoticeKind::Idle);
        }
    }

    /// The session's typed notice for a held (or refused) message. `Released` keeps a watch armed; every other kind is terminal.
    /// Returns true when a notice went to the sender.
    pub(crate) fn on_session_notice(&self, message_id: &str, kind: &SessionNotice) -> bool {
        let Some(wire) = held_wire_kind(kind) else { return false };
        let mut g = self.lock();
        let Some(pos) = g.recs.iter().position(|r| r.message_id == message_id) else { return false };
        if wire == NoticeKind::Released {
            // A watch stays armed. A plain record stays too, no longer held: the message is delivered at the next drain, and
            // an explicit refusal of it (the model's tool) must still reach the sender. It ends silently with its turn.
            let r = &mut g.recs[pos];
            r.held = false;
            emit(&r.out, r, wire);
            return true;
        }
        if let Some(r) = g.recs.remove(pos) {
            emit(&r.out, &r, wire);
        }
        true
    }

    /// The session or the host is ending: every outstanding record is told `kind` (`exited`).
    pub(crate) fn end_all(&self, kind: NoticeKind) {
        let mut g = self.lock();
        // A plain record of a delivered message is not told: it never asked, and 1.0.27 told it nothing either.
        for r in std::mem::take(&mut g.recs).into_iter().filter(|r| r.watch || r.held) {
            emit(&r.out, &r, kind);
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().recs.len()
    }
}

/// The wire kind a session notice maps to, if it is one the sender is told about.
pub(crate) fn held_wire_kind(k: &SessionNotice) -> Option<NoticeKind> {
    match k {
        SessionNotice::Released => Some(NoticeKind::Released),
        SessionNotice::Expired => Some(NoticeKind::Expired),
        SessionNotice::Refused(_) => Some(NoticeKind::Refused),
        SessionNotice::ModelRefused => Some(NoticeKind::Denied),
        _ => None,
    }
}

#[cfg(test)]
#[path = "peer_watch_tests.rs"]
mod tests;
