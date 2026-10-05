//! `LocalRef`: a `'static` handle to the agent for its background tasks, and the task set that makes it sound.
//!
//! Background work on the agent's `LocalSet` needs `&MvpAgent` in a `'static` future, so it carries a raw pointer
//! ([`LocalRef`]). A pointer alone dangled at teardown (P83, R090): the agent is owned by whoever holds it (the ACP
//! connection's request task, an `Rc` in the pager), and when that owner drops it -- a `LocalSet` shutting its tasks
//! down in spawn order, or a caller aborting the agent's task -- the futures still holding a `LocalRef` were dropped
//! LATER, and their drop code (a guard such as the settings single-flight `LeaderGuard`) wrote into the freed agent.
//!
//! So a `LocalRef` exists only inside a future the agent itself owns: [`MvpAgent::spawn_bound`] is the only way to
//! obtain one. The future is parked in a slot that the agent's first field ([`BoundTasks`]) can reach; a thin driver
//! task on the `LocalSet` polls it. When the agent is dropped, `BoundTasks` is dropped first (fields drop in declaration
//! order) and drops every bound future that is still pending, while every other field of the agent is still intact,
//! then wakes their drivers, which complete. A `LocalSet` that drops a driver first drops the future with the agent
//! still alive. Either way a bound future never outlives the agent it points to.
//!
//! The pointer is the agent's address, so the agent must never move once it has spawned bound work. Since P84 that is
//! enforced by construction: `MvpAgent::new` / `MvpAgent::with_models` return a [`super::MvpAgentHandle`], which boxes
//! and pins the agent before it can spawn anything and drops it in place; no `MvpAgent` value exists anywhere else, and
//! `MvpAgent` is `!Unpin` (the marker in [`BoundTasks`]), so safe code cannot move it out of its pin. The handle itself
//! moves freely.
//!
//! P101 (P122): a `LocalRef<'a, T>` is branded with a lifetime. [`MvpAgent::spawn_bound`] takes
//! `for<'a> FnOnce(LocalRef<'a, MvpAgent>) -> LocalBoxFuture<'a, ()>`, so the `'a` is chosen by `spawn_bound`, not by
//! its caller, and the future the closure returns may use the ref but nothing may outlive `'a`: the ref cannot be
//! stored from the closure into a variable that outlives the call, sent through a channel into a task the agent does
//! not own (those need `'static`), or kept in a `Box::leak`ed value (that is `&'a mut`, not `&'static`). Handed to
//! ANOTHER agent's `spawn_bound`, it cannot be kept in the future that call returns (the type must be valid for every
//! `'a`); a builder could still hold it synchronously while building, where the id check refuses any use of it. The
//! `&MvpAgent` that `get` returns is bounded by the same `'a`. This closes P84 Astra r2 HIGH and r3 HIGH 1 by the type system.
//!
//! `spawn_bound` erases `'a` to store the future (the `LocalSet` driver is `'static`). That is the one `unsafe` step,
//! and it is sound for the reason above: the future is polled and dropped only while the agent is alive.
//!
//! Defence in depth, kept: [`LocalRef::get`] still checks that the thread is running one of that agent's bound futures
//! right now (polling it, dropping it, or building it in `spawn_bound`) and panics otherwise, before dereferencing
//! anything. The agent is identified by a never-reused id, not its address (P84 r3), so a ref for a dropped agent is
//! refused by a later agent allocated in the same place. Safe code can no longer make such a ref; the check guards
//! against `unsafe` code and against a future change that weakens the brand.

use std::marker::{PhantomData, PhantomPinned};

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::Pin;
use std::rc::{Rc, Weak};
use std::task::{Context, Poll, Waker};

use futures::future::LocalBoxFuture;

use super::MvpAgent;

/// A reference to the agent, valid inside the bound future it was handed to and branded with that future's lifetime
/// `'a` (see the module docs).
///
/// `!Send` (raw pointer), so it never leaves the agent's thread.
pub(crate) struct LocalRef<'a, T> {
    ptr: *const T,
    /// The [`BoundTasks::id`] of the agent it was created for.
    agent: u64,
    /// The brand: the ref cannot outlive `'a`.
    _brand: PhantomData<&'a T>,
}

impl<'a, T> LocalRef<'a, T> {
    /// A ref to `target`, for the agent with id `agent`.
    fn new(target: &'a T, agent: u64) -> Self {
        Self { ptr: target, agent, _brand: PhantomData }
    }

    /// Dereference back to `&T`.
    ///
    /// Panics, without dereferencing, if the thread is not running one of this agent's bound futures (module docs).
    pub(crate) fn get(&self) -> &T {
        if BOUND_CONTEXT.with(Cell::get) != self.agent {
            used_outside_its_bound_tasks();
        }
        // SAFETY: a `LocalRef` is created only by `MvpAgent::spawn_bound`, from `&self` of an agent that lives pinned in
        // its handle's box until it is dropped in place (module docs). The check above puts us inside one of that
        // agent's bound futures (being built, polled or dropped), and the agent drops those before any of its own
        // fields, so the pointee is alive and whole; no `&mut` to it exists while a bound future is pending (the
        // handle's setters refuse). The returned borrow is tied to `self`, whose lifetime brand `'a` no reference can
        // outlive, and which that future (or its builder) owns.
        unsafe { &*self.ptr }
    }

    /// A copy with the brand removed: what `unsafe` code could still make. Safe code cannot, so this exists only to
    /// test the runtime agent-id check that backs the brand.
    #[cfg(test)]
    pub(crate) fn escaped(&self) -> LocalRef<'static, T> {
        LocalRef { ptr: self.ptr, agent: self.agent, _brand: PhantomData }
    }

    /// The address it holds, without dereferencing it (tests).
    #[cfg(test)]
    pub(crate) fn as_ptr(&self) -> *const T {
        self.ptr
    }
}

impl<T> Clone for LocalRef<'_, T> {
    fn clone(&self) -> Self {
        Self { ptr: self.ptr, agent: self.agent, _brand: PhantomData }
    }
}

/// No agent: the bound context outside every bound future, and the id of nothing.
const NO_AGENT: u64 = 0;

/// Source of [`BoundTasks::id`]s. An id is never reused, unlike an address: a stale `LocalRef` to a dropped agent must
/// not pass for one to a later agent that happens to be allocated in the same place (P84 Astra r3).
static NEXT_AGENT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(NO_AGENT + 1);

thread_local! {
    /// The agent (id) whose bound future this thread is building, polling or dropping right now; `NO_AGENT` outside.
    static BOUND_CONTEXT: Cell<u64> = const { Cell::new(NO_AGENT) };
}

/// Marks the thread as running one of `agent`'s bound futures until dropped (restores the previous mark: nesting).
struct InBoundContext(u64);

impl InBoundContext {
    fn enter(agent: u64) -> Self {
        Self(BOUND_CONTEXT.with(|current| current.replace(agent)))
    }
}

impl Drop for InBoundContext {
    fn drop(&mut self) {
        BOUND_CONTEXT.with(|current| current.set(self.0));
    }
}

#[cold]
#[inline(never)]
fn used_outside_its_bound_tasks() -> ! {
    panic!("a LocalRef was used outside its agent's bound tasks (it must not leave the future `spawn_bound` gave it to)")
}

struct SlotState {
    /// The agent this future is bound to (its [`BoundTasks::id`], for [`InBoundContext`]).
    agent: u64,
    future: Option<LocalBoxFuture<'static, ()>>,
    /// The driver's waker from its last `Pending`, to wake it once the agent has taken the future away.
    waker: Option<Waker>,
}

type Slot = RefCell<SlotState>;

/// The agent's background futures that hold a [`LocalRef`]. MUST stay the first field of [`MvpAgent`].
pub(crate) struct BoundTasks {
    /// Identifies this agent to its `LocalRef`s; unique for the life of the process.
    id: u64,
    slots: RefCell<Vec<Weak<Slot>>>,
    closed: Cell<bool>,
    /// Makes the agent `!Unpin`: its address is in every `LocalRef`, so it must not be moved out of its pin (P84).
    _pinned: PhantomPinned,
}

impl Default for BoundTasks {
    fn default() -> Self {
        Self {
            id: NEXT_AGENT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            slots: RefCell::default(),
            closed: Cell::new(false),
            _pinned: PhantomPinned,
        }
    }
}

impl BoundTasks {
    fn spawn(&self, future: LocalBoxFuture<'static, ()>) -> tokio::task::JoinHandle<()> {
        let agent = self.id;
        let slot = Rc::new(RefCell::new(SlotState {
            agent,
            future: Some(future),
            waker: None,
        }));
        if self.closed.get() {
            // Spawned from a bound future being dropped with the agent: never started, dropped now, agent still alive.
            let _context = InBoundContext::enter(agent);
            drop(slot);
            return tokio::task::spawn_local(async {});
        }
        {
            let mut slots = self.slots.borrow_mut();
            slots.retain(|slot| slot.strong_count() > 0);
            slots.push(Rc::downgrade(&slot));
        }
        tokio::task::spawn_local(Driver(slot))
    }

    /// Bound futures still pending (a future being polled right now counts).
    pub(crate) fn pending(&self) -> usize {
        self.slots
            .borrow()
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|slot| slot.try_borrow().map_or(true, |state| state.future.is_some()))
            .count()
    }

    /// Whether any bound future is still pending, i.e. may hold a borrow of the agent.
    pub(crate) fn has_pending(&self) -> bool {
        self.pending() > 0
    }
}

/// Fail-stop for an agent dropped from inside one of its own bound futures. Nothing may run first: a logging callback
/// could unwind (r3) and a write to stderr could block on another thread's lock (r4), either keeping the abort from
/// happening. The core dump / SIGABRT is the diagnostic.
fn abort_reentrant_drop() -> ! {
    std::process::abort()
}

/// Keeps the first panic of a teardown to resume once it is complete. A later payload is forgotten, not dropped: dropping
/// a payload can itself panic, and nothing may unwind before every bound future is gone.
fn keep_first_panic(first: &mut Option<Box<dyn Any + Send>>, panic: Box<dyn Any + Send>) {
    if first.is_none() {
        *first = Some(panic);
    } else {
        std::mem::forget(panic);
    }
}

impl Drop for BoundTasks {
    fn drop(&mut self) {
        self.closed.set(true);
        let mut first_panic = None;
        let mut wakers = Vec::new();
        // 1. Drop every bound future, even if a destructor panics. A future's drop may spawn again; `closed` makes that
        //    a no-op, the loop makes sure.
        loop {
            let slots = std::mem::take(&mut *self.slots.borrow_mut());
            if slots.is_empty() {
                break;
            }
            for slot in slots.iter().filter_map(Weak::upgrade) {
                let (agent, future, waker) = match slot.try_borrow_mut() {
                    Ok(mut state) => (state.agent, state.future.take(), state.waker.take()),
                    // Being polled or destroyed right now (the driver holds the slot for both), i.e. the agent is being
                    // dropped from inside one of its own bound futures. A bound future never owns the agent, so this
                    // should not happen; if it does, carrying on would let that future run on a freed agent.
                    Err(_) => abort_reentrant_drop(),
                };
                let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _context = InBoundContext::enter(agent);
                    drop(future);
                }));
                if let Err(panic) = dropped {
                    keep_first_panic(&mut first_panic, panic);
                }
                wakers.extend(waker);
            }
        }
        // 2. Only now, with no bound future left, wake their drivers so they complete (their `JoinHandle`s resolve).
        for waker in wakers {
            if let Err(panic) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waker.wake())) {
                keep_first_panic(&mut first_panic, panic);
            }
        }
        if let Some(panic) = first_panic {
            std::panic::resume_unwind(panic);
        }
    }
}

/// Polls one bound future on the `LocalSet`; completes when the future does or when the agent has dropped it.
///
/// The future is polled AND destroyed with the slot borrowed (on completion here, on cancellation in `Drop`), so an
/// agent dropped from inside either finds the slot busy and aborts rather than freeing itself under a live future.
struct Driver(Rc<Slot>);

impl Future for Driver {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut state = self.0.borrow_mut();
        let _context = InBoundContext::enter(state.agent);
        let Some(future) = state.future.as_mut() else {
            return Poll::Ready(());
        };
        if future.as_mut().poll(cx).is_pending() {
            if !state.waker.as_ref().is_some_and(|waker| waker.will_wake(cx.waker())) {
                state.waker = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }
        state.waker = None;
        state.future = None;
        Poll::Ready(())
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        // Cancelled by its `LocalSet` with the future still pending (the agent is alive: it would have taken it).
        if let Ok(mut state) = self.0.try_borrow_mut() {
            let _context = InBoundContext::enter(state.agent);
            state.waker = None;
            state.future = None;
        }
    }
}

impl MvpAgent {
    /// Spawns `make(agent_ref)` on the current `LocalSet` as a background task the agent owns: it may hold the
    /// [`LocalRef`] it is given, and it is dropped no later than the agent (see the module docs). The returned handle
    /// completes when the future does, or when the agent drops it.
    ///
    /// The ref's lifetime is higher-ranked: the future the closure returns (`Box::pin(async move { .. })`) may borrow
    /// from the ref only for that `'a`, and cannot carry any other short-lived borrow (its type must be valid for
    /// every `'a`), so what it keeps from the closure's captures must be `'static`. The closure itself may use a
    /// short-lived borrow synchronously while it builds the future.
    pub(crate) fn spawn_bound<F>(&self, make: F) -> tokio::task::JoinHandle<()>
    where
        F: for<'a> FnOnce(LocalRef<'a, MvpAgent>) -> LocalBoxFuture<'a, ()>,
    {
        let agent = self.bound_tasks.id;
        let future = {
            let _context = InBoundContext::enter(agent);
            make(LocalRef::new(self, agent))
        };
        // SAFETY: only the lifetime is changed (same type and layout). The future may borrow the agent (through its
        // `LocalRef`) for `'a`, a lifetime the closure cannot name, and it can hold no other borrow that is shorter
        // than `'static` (its type must be valid for every `'a`). It is stored in a slot the agent's first field ([`BoundTasks`]) reaches, and is polled and
        // dropped only while the agent is alive: `BoundTasks::drop` drops every pending one before any other field of
        // the agent, and a `Driver` that the `LocalSet` drops first drops its future with the agent still alive.
        let future = unsafe { std::mem::transmute::<LocalBoxFuture<'_, ()>, LocalBoxFuture<'static, ()>>(future) };
        self.bound_tasks.spawn(future)
    }
}

#[cfg(test)]
mod tests {
    use std::panic::AssertUnwindSafe;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    /// P132 (P122 follow-up): fields drop in declaration order, and the soundness of `spawn_bound`'s lifetime erasure rests
    /// on `BoundTasks` dropping (and so dropping every bound future) while every other field of `MvpAgent` is still alive.
    /// The comment "MUST stay the first field" is enforced here: the first field declared in `MvpAgent` is `bound_tasks`.
    #[test]
    fn bound_tasks_is_the_first_field_of_mvp_agent() {
        let source = include_str!("mod.rs");
        let body = source
            .split("pub struct MvpAgent {")
            .nth(1)
            .expect("MvpAgent is declared in mod.rs")
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.starts_with("//") && !line.starts_with("#["))
            .expect("MvpAgent has fields");
        assert_eq!(
            body, "bound_tasks: local_ref::BoundTasks,",
            "BoundTasks must be the FIRST field of MvpAgent (see the doc on BoundTasks); found {body:?}"
        );
    }

    /// Sets its flag when dropped.
    struct Flag(Rc<Cell<bool>>);
    impl Drop for Flag {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    /// Panics (with an ordinary message) when dropped.
    struct PanicsOnDrop;
    impl Drop for PanicsOnDrop {
        fn drop(&mut self) {
            panic!("p83: a bound future's destructor panics");
        }
    }

    /// A panic payload whose own destructor panics.
    struct PayloadPanicsOnDrop;
    impl Drop for PayloadPanicsOnDrop {
        fn drop(&mut self) {
            panic!("p83: dropping this panic payload panics");
        }
    }

    /// Panics, when dropped, with a [`PayloadPanicsOnDrop`] payload.
    struct PanicsWithABadPayload;
    impl Drop for PanicsWithABadPayload {
        fn drop(&mut self) {
            std::panic::panic_any(PayloadPanicsOnDrop);
        }
    }

    /// Sets its flag when dropped (thread-safe, for a waker to read).
    struct SyncFlag(Arc<AtomicBool>);
    impl Drop for SyncFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// On wake: records whether the other bound future was already dropped, then panics.
    struct PanickyWake {
        other_dropped: Arc<AtomicBool>,
        seen_at_wake: Arc<AtomicBool>,
    }
    impl futures::task::ArcWake for PanickyWake {
        fn wake_by_ref(this: &Arc<Self>) {
            this.seen_at_wake.store(this.other_dropped.load(Ordering::SeqCst), Ordering::SeqCst);
            panic!("p83: a driver's wake panics");
        }
    }

    /// Registers a pending future holding `held` as a bound task, without a `LocalSet` (the slot is returned in place
    /// of its driver).
    fn register<H: 'static>(tasks: &BoundTasks, held: H) -> Rc<Slot> {
        let slot = Rc::new(RefCell::new(SlotState {
            agent: tasks.id,
            future: Some(Box::pin(async move {
                let _held = held;
                std::future::pending::<()>().await;
            })),
            waker: None,
        }));
        tasks.slots.borrow_mut().push(Rc::downgrade(&slot));
        slot
    }

    #[test]
    fn a_second_panic_with_a_payload_that_panics_on_drop_does_not_stop_the_drain() {
        let tasks = BoundTasks::default();
        let _first = register(&tasks, PanicsOnDrop);
        let _second = register(&tasks, PanicsWithABadPayload);
        let dropped = Rc::new(Cell::new(false));
        let third = register(&tasks, Flag(Rc::clone(&dropped)));
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| drop(tasks)));
        let payload = result.expect_err("the first panic resumes once the drain is complete");
        assert_eq!(payload.downcast_ref::<&str>(), Some(&"p83: a bound future's destructor panics"));
        assert!(dropped.get(), "the third bound future was dropped too");
        assert!(third.borrow().future.is_none());
    }

    #[test]
    fn a_panicking_wake_runs_only_after_every_bound_future_is_dropped() {
        let tasks = BoundTasks::default();
        let first = register(&tasks, ());
        // Its driver parked with a waker that panics.
        let mut driver = Driver(Rc::clone(&first));
        let other_dropped = Arc::new(AtomicBool::new(false));
        let seen_at_wake = Arc::new(AtomicBool::new(false));
        let waker = futures::task::waker(Arc::new(PanickyWake {
            other_dropped: Arc::clone(&other_dropped),
            seen_at_wake: Arc::clone(&seen_at_wake),
        }));
        assert!(Pin::new(&mut driver).poll(&mut Context::from_waker(&waker)).is_pending());
        let second = register(&tasks, SyncFlag(Arc::clone(&other_dropped)));
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| drop(tasks)));
        let payload = result.expect_err("the wake's panic resumes once the drain is complete");
        assert_eq!(payload.downcast_ref::<&str>(), Some(&"p83: a driver's wake panics"));
        assert!(seen_at_wake.load(Ordering::SeqCst), "the second bound future was dropped before the wake ran");
        assert!(first.borrow().future.is_none() && second.borrow().future.is_none());
        // The emptied driver completes.
        assert!(Pin::new(&mut driver).poll(&mut Context::from_waker(futures::task::noop_waker_ref())).is_ready());
    }

    /// P122 (P101): the brand is a lifetime, so a `LocalRef<'a, T>` is a type that cannot be named outside the future
    /// `spawn_bound` hands it to. The runtime agent-id check stays as the second line of defence; these two tests
    /// reach it with refs that safe code can no longer build.
    ///
    /// A ref made for an agent that is gone is refused inside a LATER agent's bound future, even when that agent
    /// lives at the very same address. The address is the same by construction (one `Cell`, one place), so nothing
    /// here depends on what the allocator hands out. Mutant discriminated: `get` accepting any bound context, or
    /// comparing addresses instead of ids.
    #[test]
    fn a_ref_for_a_dropped_agent_is_refused_in_a_later_agent_at_the_same_address() {
        let place = Cell::new(7_u64);
        let first = BoundTasks::default();
        let stale = LocalRef::<'_, Cell<u64>>::new(&place, first.id);
        drop(first);
        let later = BoundTasks::default();
        assert_ne!(later.id, NO_AGENT);
        let in_later_agents_task = {
            let _context = InBoundContext::enter(later.id);
            let fresh = LocalRef::<'_, Cell<u64>>::new(&place, later.id);
            assert_eq!(fresh.get().get(), 7, "a ref for the running agent works");
            std::panic::catch_unwind(AssertUnwindSafe(|| stale.get().get()))
        };
        assert!(
            in_later_agents_task.is_err(),
            "the stale ref is refused although the address is identical"
        );
        assert_eq!(stale.as_ptr(), &place as *const Cell<u64>, "the pointer really was the same");
    }

    /// Outside every bound future nothing is dereferenced, whatever id the ref carries.
    #[test]
    fn a_ref_is_refused_outside_every_bound_future() {
        let place = Cell::new(1_u64);
        let tasks = BoundTasks::default();
        let outside = LocalRef::<'_, Cell<u64>>::new(&place, tasks.id);
        assert!(std::panic::catch_unwind(AssertUnwindSafe(|| outside.get().get())).is_err());
    }
}
