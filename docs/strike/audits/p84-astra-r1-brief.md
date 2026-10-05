# P84 Astra round 1 brief

Audit the diff `git diff e0145e0f8e4776227af2964c1867b83381cd5fb7..386b2015` in this repository (fuigo, Rust). Read-only; do not run cargo.

Context: P83 (receipt docs/strike/receipts/R090-p83.md) made background tasks reach the agent through `LocalRef` (a raw pointer, crates/codegen/fuigo-shell/src/agent/mvp_agent/local_ref.rs), created only by `MvpAgent::spawn_bound`, with `BoundTasks` as MvpAgent's first field so bound futures drop before the agent's other fields. Open HIGH left by P83: the pointer is the agent's address, so moving an MvpAgent after it has spawned bound work dangles.

P84 claims:
1. `MvpAgent::new` / `MvpAgent::with_models` now return `MvpAgentHandle` (new file mvp_agent/handle.rs) which owns the agent in `Pin<Box<MvpAgent>>`, pinned before any bound work can be spawned, dropped in place. No `MvpAgent` value exists outside such a box (struct literal needs the private `bound_tasks` field; the only literal is in `with_models`).
2. `MvpAgent` is `!Unpin` (PhantomPinned in `BoundTasks`), so safe code cannot obtain `&mut MvpAgent` / move it out of the pin. The handle may move, swap, go behind an Rc and be unwrapped freely.
3. The three construction-time `&mut` setters (set_memory_config, set_activity, set_config_watcher_path_tx) moved to the handle; they use `Pin::get_unchecked_mut` to assign one field and assert no bound future is pending (so no `&MvpAgent` from a bound future can alias the `&mut`). All production callers call them right after construction (agent/app.rs, fuigo-pager/src/acp/spawn.rs).
4. `acp::Agent for MvpAgentHandle` forwards every method `MvpAgent` implements; the rest keep trait defaults as on MvpAgent. No user-visible behaviour change.
5. P83's teardown ordering is unchanged (BoundTasks still first field; dropping the handle drops the boxed agent in place).
6. Tests: mvp_agent/tests/p84_relocation_tests.rs (move out of Box into Vec, mem::swap of two agents, into Rc and Rc::try_unwrap; a compile-time !Unpin check; the setter refusal). The first three fail at the parent with the test commit 43511dea alone.

Find defects: soundness holes that still let the agent's state move or be freed while a LocalRef is live, aliasing UB from the `&mut` setters, behaviour changes, forwarding mistakes in the acp::Agent impl (missing/extra methods vs MvpAgent's impl in acp_agent.rs, cfg features), test weaknesses (tests that would pass at the parent, or don't exercise production paths). For each: severity BLOCKER/HIGH/MEDIUM/LOW, file:line, concrete scenario, whether a test catches it. End with one verdict line: LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
