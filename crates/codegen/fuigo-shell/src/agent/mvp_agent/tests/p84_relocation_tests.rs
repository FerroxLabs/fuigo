//! P84: moving an agent after it has spawned bound work must not leave that work pointing at the old place.
//!
//! A `LocalRef` is the address of the agent's state. Before P84 the agent's state WAS the value `MvpAgent::new` returned,
//! so any move of that value (out of a `Box`, into a `Vec`, a `std::mem::swap`) relocated the state and left every bound
//! task with a stale pointer: a read or write into freed memory (the `Box` case; AddressSanitizer: heap-use-after-free)
//! or into the OTHER agent (the swap case). Since P84 `MvpAgent::new` returns a handle that owns the state in pinned heap
//! storage, so the handle may move freely and the state never does.
//!
//! The tests compare the address a bound task holds with the address of the agent's state as seen through its current
//! owner, and check that a write made through the task's `LocalRef` lands in that agent.

use std::rc::Rc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use super::MvpAgent;

/// What a bound task observed: the address it holds and the value it wrote through it.
type Report = (*const MvpAgent, u64);

/// Spawns a bound task on `agent` that, for every value it receives, writes it into the agent (through its `LocalRef`)
/// and reports the address it holds.
fn spawn_writer(agent: &MvpAgent) -> (mpsc::UnboundedSender<u64>, mpsc::UnboundedReceiver<Report>) {
    let (poke_tx, mut poke_rx) = mpsc::unbounded_channel::<u64>();
    let (report_tx, report_rx) = mpsc::unbounded_channel::<Report>();
    agent.spawn_bound(move |agent_ref| Box::pin(async move {
        while let Some(value) = poke_rx.recv().await {
            let held = agent_ref.as_ptr();
            agent_ref.get().announcements_gen.set(value);
            if report_tx.send((held, value)).is_err() {
                break;
            }
        }
    }));
    (poke_tx, report_rx)
}

async fn poke(tx: &mpsc::UnboundedSender<u64>, rx: &mut mpsc::UnboundedReceiver<Report>, value: u64) -> Report {
    tx.send(value).expect("the bound task is alive");
    tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("the bound task answers")
        .expect("the bound task is alive")
}

#[test]
fn moving_the_agent_out_of_its_box_after_it_spawned_work_keeps_that_work_on_the_agent() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let boxed = Box::new(super::build_minimal_agent_for_tests());
        let (tx, mut rx) = spawn_writer(&boxed);
        let (held_before, _) = poke(&tx, &mut rx, 1).await;
        // Move what `MvpAgent::new` returned out of its box and into a `Vec`; the box's allocation is freed at the end of
        // the block (before P84 that allocation WAS the agent, so the bound task then wrote into freed memory).
        let moved = {
            let boxed = boxed;
            vec![*boxed]
        };
        let agent: &MvpAgent = &moved[0];
        let (held_after, written) = poke(&tx, &mut rx, 7).await;
        assert_eq!(held_after, held_before, "a bound task's pointer never changes");
        assert_eq!(held_after, std::ptr::from_ref(agent), "the bound task points at the moved agent's state");
        assert_eq!(agent.announcements_gen.get(), written, "a write through the bound task lands in the moved agent");
        // Teardown still drops the bound task with the agent (its receiver closes).
        drop(moved);
        assert!(
            tokio::time::timeout(Duration::from_secs(10), rx.recv()).await.expect("the task is gone").is_none(),
            "the bound task was dropped with the moved agent"
        );
    });
}

#[test]
fn swapping_two_agents_after_both_spawned_work_keeps_each_task_on_its_own_agent() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let mut first = super::build_minimal_agent_for_tests();
        let mut second = super::build_minimal_agent_for_tests();
        let (first_tx, mut first_rx) = spawn_writer(&first);
        let (second_tx, mut second_rx) = spawn_writer(&second);
        let (first_held, _) = poke(&first_tx, &mut first_rx, 1).await;
        let (second_held, _) = poke(&second_tx, &mut second_rx, 2).await;
        assert_ne!(first_held, second_held);
        std::mem::swap(&mut first, &mut second);
        // The agent that spawned `first_tx`'s task is now owned by `second`, and vice versa.
        poke(&first_tx, &mut first_rx, 11).await;
        poke(&second_tx, &mut second_rx, 22).await;
        let (now_second, now_first): (&MvpAgent, &MvpAgent) = (&second, &first);
        assert_eq!(std::ptr::from_ref(now_second), first_held, "the first agent's state did not move");
        assert_eq!(std::ptr::from_ref(now_first), second_held, "the second agent's state did not move");
        assert_eq!(now_second.announcements_gen.get(), 11, "the first agent's task writes into the first agent");
        assert_eq!(now_first.announcements_gen.get(), 22, "the second agent's task writes into the second agent");
    });
}

#[test]
fn an_agent_moved_into_an_rc_after_it_spawned_work_still_drops_that_work_first() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let agent = super::build_minimal_agent_for_tests();
        let (tx, mut rx) = spawn_writer(&agent);
        poke(&tx, &mut rx, 3).await;
        let shared = Rc::new(agent);
        let target: &MvpAgent = &shared;
        let (held, written) = poke(&tx, &mut rx, 5).await;
        assert_eq!(held, std::ptr::from_ref(target));
        assert_eq!(target.announcements_gen.get(), written);
        let unwrapped = Rc::try_unwrap(shared).ok().expect("the only owner");
        let target: &MvpAgent = &unwrapped;
        let (held, written) = poke(&tx, &mut rx, 9).await;
        assert_eq!(held, std::ptr::from_ref(target), "unwrapping the Rc does not move the state either");
        assert_eq!(target.announcements_gen.get(), written);
        drop(unwrapped);
        assert!(tx.send(1).is_err(), "the bound task (and its receiver) was dropped with the agent");
    });
}

/// `MvpAgent` must stay `!Unpin`, or `Pin::get_mut` / `Pin::into_inner` would hand out a movable agent. This does not
/// compile if `MvpAgent: Unpin` (the two blanket impls then both apply and the call is ambiguous).
#[test]
fn the_agent_state_is_not_unpin() {
    trait AmbiguousIfUnpin<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfUnpin<()> for T {}
    #[allow(dead_code)]
    struct IsUnpin;
    impl<T: ?Sized + Unpin> AmbiguousIfUnpin<IsUnpin> for T {}
    <MvpAgent as AmbiguousIfUnpin<_>>::check();
}

#[test]
fn configuring_an_agent_through_mut_with_bound_work_pending_panics() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let mut agent = super::build_minimal_agent_for_tests();
        // Before any bound work: allowed, as every production caller does it.
        agent.set_config_watcher_path_tx(mpsc::unbounded_channel().0);
        // A bound task that is running and holds `&MvpAgent` across an `.await`: a `&mut` now would alias it.
        let (held_tx, held_rx) = oneshot::channel();
        agent.spawn_bound(move |agent_ref| Box::pin(async move {
            let agent = agent_ref.get();
            let _ = held_tx.send(());
            std::future::pending::<()>().await;
            let _ = agent.announcements_gen.get();
        }));
        held_rx.await.expect("the bound task runs and holds a borrow of the agent");
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            agent.set_config_watcher_path_tx(mpsc::unbounded_channel().0);
        }));
        assert!(refused.is_err(), "`&mut` access is refused while a bound future may hold `&MvpAgent`");
    });
}

/// A `LocalRef` carried out of its bound future (here: an unbranded copy, which safe code can no longer make since
/// P122, stored by the `spawn_bound` closure) cannot be dereferenced
/// outside that agent's bound tasks: `get` panics before touching the agent, whether the agent is alive (a `&mut`
/// setter could be running) or already dropped (the pointer would dangle). Inside a bound task of the same agent it
/// still works. (Astra r2 HIGH.)
#[test]
fn a_local_ref_that_escaped_its_bound_future_cannot_be_dereferenced() {
    use std::cell::RefCell;
    let outside = |escaped: &super::super::LocalRef<'static, MvpAgent>| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = escaped.get().announcements_gen.get();
        }))
    };
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let agent = super::build_minimal_agent_for_tests();
        let stash = Rc::new(RefCell::new(None));
        let stash_in_closure = Rc::clone(&stash);
        agent
            .spawn_bound(move |agent_ref| {
                *stash_in_closure.borrow_mut() = Some(agent_ref.escaped());
                Box::pin(async {})
            })
            .await
            .expect("the bound task completes");
        let escaped = stash.borrow_mut().take().expect("the closure stored its LocalRef");
        assert!(outside(&escaped).is_err(), "refused while the agent is alive");
        // From another task the agent does not own: refused too.
        let in_foreign_task = escaped.clone();
        let foreign = tokio::task::spawn_local(async move {
            let _ = in_foreign_task.get().announcements_gen.get();
        })
        .await;
        assert!(foreign.expect_err("the foreign task panics").is_panic());
        // Cloned into another bound task of the same agent: allowed.
        let in_bound_task = escaped.clone();
        let (seen_tx, seen_rx) = oneshot::channel();
        agent.spawn_bound(move |_agent_ref| Box::pin(async move {
            let _ = seen_tx.send(in_bound_task.get().announcements_gen.get());
        }));
        agent.announcements_gen.set(4);
        assert_eq!(seen_rx.await.expect("the bound task ran"), 4);
        drop(agent);
        assert!(outside(&escaped).is_err(), "refused once the agent is gone, without touching freed memory");
    });
}

/// A bound future's destructor may still use its `LocalRef` (as P83's `LeaderGuard` uses the agent): whether the agent
/// drops the future (its owner let go) or the `LocalSet` does (driver cancelled), the context check lets it through.
#[test]
fn a_bound_futures_destructor_may_use_its_local_ref() {
    use std::cell::Cell;
    struct ReadsOnDrop<'a>(super::super::LocalRef<'a, MvpAgent>, Rc<Cell<Option<u64>>>);
    impl Drop for ReadsOnDrop<'_> {
        fn drop(&mut self) {
            self.1.set(Some(self.0.get().announcements_gen.get()));
        }
    }
    fn spawn_reader(agent: &MvpAgent) -> Rc<Cell<Option<u64>>> {
        let seen = Rc::new(Cell::new(None));
        let seen_in_task = Rc::clone(&seen);
        agent.spawn_bound(move |agent_ref| Box::pin(async move {
            let _reads = ReadsOnDrop(agent_ref, seen_in_task);
            std::future::pending::<()>().await;
        }));
        seen
    }
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    // The agent drops its bound future.
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let agent = super::build_minimal_agent_for_tests();
        let seen = spawn_reader(&agent);
        agent.announcements_gen.set(6);
        tokio::task::yield_now().await;
        drop(agent);
        assert_eq!(seen.get(), Some(6));
    });
    // The `LocalSet` drops the driver first (the agent's owner is an older task, still alive at that point).
    let local = tokio::task::LocalSet::new();
    let (seen, _agent) = local.block_on(&rt, async {
        let agent = Rc::new(super::build_minimal_agent_for_tests());
        let seen = spawn_reader(&agent);
        agent.announcements_gen.set(8);
        tokio::task::yield_now().await;
        (seen, agent)
    });
    drop(local);
    assert_eq!(seen.get(), Some(8));
}

/// A stale `LocalRef` (its agent is gone; an unbranded copy, as above) smuggled into a LATER agent's bound task is
/// refused, even when that agent is allocated where the first one was: agents are told apart by a never-reused id, not
/// by address. (Astra r3 HIGH.) The same-address case is made deterministic in `local_ref`'s own tests.
#[test]
fn a_stale_local_ref_is_refused_inside_a_later_agents_bound_task() {
    use std::cell::RefCell;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let first = super::build_minimal_agent_for_tests();
        let stash = Rc::new(RefCell::new(None));
        let stash_in_closure = Rc::clone(&stash);
        first
            .spawn_bound(move |agent_ref| {
                *stash_in_closure.borrow_mut() = Some(agent_ref.escaped());
                Box::pin(async {})
            })
            .await
            .expect("the bound task completes");
        let stale = stash.borrow_mut().take().expect("the closure stored its LocalRef");
        drop(first);
        // Several later agents of the same size: the allocator usually hands one of them the freed address.
        for _ in 0..4 {
            let later = super::build_minimal_agent_for_tests();
            let smuggled = stale.clone();
            let joined = later
                .spawn_bound(move |_agent_ref| Box::pin(async move {
                    let _ = smuggled.get().announcements_gen.get();
                }))
                .await;
            assert!(joined.expect_err("the stale LocalRef is refused").is_panic());
        }
    });
}

/// P122 (P101): the brand is the lifetime of the bound future: a function can name it, and the future it returns
/// borrows it. Before P122 `LocalRef` had no lifetime, so this did not compile.
#[test]
fn a_bound_future_can_name_the_lifetime_of_its_ref() {
    fn reads<'a>(agent_ref: super::super::LocalRef<'a, MvpAgent>) -> futures::future::LocalBoxFuture<'a, ()> {
        Box::pin(async move {
            let _ = agent_ref.get().announcements_gen.get();
        })
    }
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let agent = super::build_minimal_agent_for_tests();
        agent.spawn_bound(reads).await.expect("the bound future completes");
    });
}
