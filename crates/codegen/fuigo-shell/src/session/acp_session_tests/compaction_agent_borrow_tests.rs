//! The zero-turn harness rebuild (`/model` to an incompatible agent type,
//! `handle_rebuild_agent_for_definition`) replaces the session's agent with
//! `*self.agent.borrow_mut() = new_agent`. A manual `/compact` runs as its own `spawn_local` task
//! on the same `LocalSet` (`run_loop.rs`, `SessionCommand::Compact`), so the two interleave at
//! every await inside compaction. While compaction waits on the toolset's resource lock
//! (`ToolBridge::render_prompt`) it must not hold a `RefCell::Ref<Agent>`: that `Ref` would make
//! the rebuild's `borrow_mut` panic with `BorrowMutError`, a SIGABRT under `panic = "abort"`.
//!
//! The test parks the toolset lock, polls the compaction helper by hand until it is `Pending` on
//! that lock (no scheduler involved, so the suspension point is exact), and then takes the write
//! borrow the rebuild takes.

use super::support::*;
use super::*;
use std::future::Future;

#[tokio::test(flavor = "current_thread")]
async fn a_rebuild_can_take_the_agent_while_compaction_waits_on_the_toolset() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (gateway_tx, _gateway_rx) =
                tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
            let (persistence_tx, _persistence_rx) =
                tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
            let (actor, _events) =
                create_test_actor_ex(0, 500_000, 95, gateway_tx, persistence_tx).await;

            // Park the toolset: `render_prompt` waits for this lock, which is exactly where the
            // compaction task sits when a rebuild can run.
            let toolset = actor.agent.borrow().tool_bridge().toolset();
            let parked = toolset.resources.lock().await;

            // Drive the helper to its suspension point ourselves: `Pending` here means it is
            // waiting on the parked lock with whatever state it holds across that await.
            let mut helper = std::pin::pin!(actor.tool_names_by_kind(
                "${{ tools.by_kind.execute }}",
                "${{ tools.by_kind.monitor }}",
            ));
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(
                helper.as_mut().poll(&mut cx).is_pending(),
                "the compaction helper must be parked on the toolset lock for this test to mean anything"
            );

            // The rebuild's write. With a `Ref<Agent>` parked inside the helper this is
            // `BorrowMutError` (`already borrowed`).
            assert!(
                actor.agent.try_borrow_mut().is_ok(),
                "compaction holds `self.agent.borrow()` across an await: a zero-turn harness \
                 rebuild running now would panic with BorrowMutError"
            );

            drop(parked);
            let (first, second) = helper.await;
            // Whether the templates resolve depends on the test toolset; what matters is that
            // the helper completed after the borrow collision window.
            let _ = (first, second);
        })
        .await;
}

/// Control for the helper itself: without contention it resolves and returns.
#[tokio::test(flavor = "current_thread")]
async fn tool_names_by_kind_returns_when_the_toolset_is_free() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (gateway_tx, _gateway_rx) =
                tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
            let (persistence_tx, _persistence_rx) =
                tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
            let (actor, _events) =
                create_test_actor_ex(0, 500_000, 95, gateway_tx, persistence_tx).await;
            let (first, second) = actor
                .tool_names_by_kind("${{ tools.by_kind.execute }}", "${{ tools.by_kind.monitor }}")
                .await;
            // An unresolved template never leaks the raw `by_kind` placeholder.
            for name in [first, second].into_iter().flatten() {
                assert!(!name.is_empty() && !name.contains("by_kind"), "{name}");
            }
        })
        .await;
}
