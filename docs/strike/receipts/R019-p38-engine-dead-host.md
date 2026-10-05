# Receipt R019 — P38: the workflow engine waited forever on a request stranded in a closed host channel

**Date:** 2026-10-01 · **Base:** `f89618efccc2` · **Branch:** `strike/p38` · **Box:** hetzner-dsm
**Code commit gated:** `c422704798957b22c30a8f2897b7772d12229af1` (tree `65bae969fc88df7360d0cc76a129fef130cf5fd1`) on base `f89618ef`. *Corrected by the coordinator after landing prep:* the branch was then rebased onto integration `cca0969f` (P09 and P17-R landed in between); the fix commit's `engine.rs` diff is byte-identical to `c4227047`'s, but the tree differs because the base moved, so §6's gate applies to the pre-rebase commit and the post-rebase re-proof is recorded in §6a. The fix commit's message was reworded from a `WIP` placeholder; its tree was not changed.

P37 found a production liveness bug: in every captured wedge, a live `gdb` showed the workflow engine
thread parked in `release_agent_calls` (`fuigo-workflow/src/engine.rs:439` at baseline) inside
`oneshot::Receiver::blocking_recv`, waiting for an acknowledgement the host would never send, with the
host channel already closed. A cancel or pause could then never finish, and a `#[tokio::test]` runtime
drop waited on that thread forever. P37's uncommitted proof of concept (poll `try_recv` every 2 ms,
give up once `host_tx.is_closed()`) took 6/150 wedging runs to 0/300.

## 1. Mechanism

### 1.1 PROVEN — tokio 1.52.3 can strand a request after the receiver is gone

`UnboundedSender::send` is two steps: `inc_num_messages()` (fails if the receiver closed) and then
`chan.send()` → `list::Tx::push` (claim a slot, maybe allocate a block, write the value). `Rx::drop`
calls `close()` and then drains with `list.pop()`, which stops at the first slot that is not yet
written. A send that passed `inc_num_messages` before the close and writes its slot after the drain
leaves its value in the channel. Nothing drains the list again until `Chan` itself is dropped
(`Chan::drop` pops everything left). `Chan` sits behind an `Arc` held by every `UnboundedSender`,
every `WeakUnboundedSender` and the receiver, so it is dropped only when the **last strong sender and
the last weak sender** are both gone (the receiver already is). Dropping the last strong sender alone
only closes the list and wakes the receiver (`Tx::drop`); it drains nothing. *(Corrected by P38-F,
R021 §4: this paragraph first said "the last sender", which omitted weak senders.)*

Experiment (`/root/fuigo-builds/p38/race/src/main.rs`, tokio `=1.52.3`, release build): one thread drops
the receiver while another sends a `oneshot::Sender` through it, released by a barrier, 3 × 200,000
iterations. After both threads finish, the reply receiver is checked:

| run | iterations | send rejected (closed first) | request dropped by `Rx::drop` | **request stranded, receiver gone** |
|---|---:|---:|---:|---:|
| 1 | 200,000 | 199,980 | 20 | **0** |
| 2 | 200,000 | 199,937 | 61 | **2** |
| 3 | 200,000 | 199,983 | 17 | **0** |

In both stranded cases the program asserted that the channel reported closed, then dropped its sender
and asserted that the reply receiver immediately saw `Closed`: with no weak sender in the experiment,
the stranded request lives exactly as long as the last sender, and dropping that sender frees it. Both
assertions held. A retained `WeakUnboundedSender` would keep `Chan`, and so the stranded request,
allocated after that drop. No production code downgrades the host channel (R021 §4).

### 1.2 PROVEN — the engine holds that last sender while it waits

`Ctx.host_tx` is the engine's only long-lived `UnboundedSender` (the manager moves it into
`run_workflow`; `host_emit` clones it only for the duration of one `send`), and no production code holds
a `WeakUnboundedSender` to the host channel. A request stranded as in 1.1 is therefore freed only when
that sender drops, and the engine drops it only when `run_workflow` returns —
which it cannot do while it waits on the stranded request's reply. The wait is on itself.

### 1.3 INFERRED — why the manager tests hit it so often (~4%)

The window in 1.1 is nanoseconds, but in the cancel path the two sides are driven by the same event.
On cancel, the host loop (`host_service.rs`) drains the queue with `try_recv`, breaks, drains children
and ends its task, dropping the receiver; in tests whose subagent channel answers at once, that is
immediate. At the same moment the engine, woken by the cancelled `SpawnAgent` reply, sends
`ReleaseAgentCalls`. At runtime teardown the same pairing happens between the scheduler dropping the
host task and the engine thread. Correlated timing plus 96 test threads on 96 cores is the likely
reason for the rate; I did not instrument a wedge to show the stranded slot directly. What P37 showed
and I did not re-show: the engine parked in `release_agent_calls` with the channel closed (gdb), and
33 closed-while-waiting detections in P37's 300 patched runs.

## 2. The fix — decided and why

`engine.rs` gains `await_host_reply(ctx, reply_rx)`, used by **every** place the engine waits for a
host reply. It blocks on whichever comes first: the reply, or `host_tx.closed()`.

* Reply first → returned unchanged.
* Channel closed first → nothing still queued can ever be received, so the engine replaces its sender
  with a dead one and drops the original. That frees any stranded request, whose dropped reply sender
  ends the wait with `RecvError` — the same answer the engine already gives any dropped reply. A
  request the host had **already received** keeps its reply sender and is still awaited, so a reply
  in flight when the host stops serving (for example a scratch write finishing in a spawned task) is
  still delivered and journaled. Later sends fail as they would on the closed channel.

The wait is driven by a small `block_on` (thread park/unpark waker). tokio's `sync` primitives need
only a waker, and there is no sync `select` on a oneshot plus a channel closure in tokio's API.

**Rejected: P37's give-up-on-close.** It stops waiting as soon as the channel is closed, so it also
discards a reply the host already has in hand; the mutant `giveup` in §4 shows that costs a real
result (`Completed` becomes `Failed: workflow host dropped reply`). It also busy-polls.

**Rejected: make the host guarantee a reply or a drop on every path.** The host cannot. The stranding
happens after its receiver is gone, and it has no handle on the channel's list; only the last sender
can free it, and the engine owns that. The host can shrink the window (keep answering `Cancelled`
until the engine drops its sender instead of ending at cancel), but it cannot close it: a runtime
shutdown still drops the host task at an arbitrary point. I left `host_service.rs` unchanged; that
change is offered as a proposal (§8), not needed for liveness.

### 2.1 Found by the gate, fixed before the gated commit

My first version (`708a034d`, not landed) kept the old call shape
`c.borrow_mut().next_seq().inspect_err(|_| drain_parallel_replies(..))` and
`if let Err(e) = c.borrow_mut().journal.dispatch(..) { drain_parallel_replies(..) }`. Draining now
borrows `ctx` to watch the channel, and both sites still held a `borrow_mut`, so the existing
`parallel_setup_error_drains_already_sent_replies` panicked with `RefCell already mutably borrowed`
(40/40 local runs). `c4227047` binds each result before draining. No other caller holds a borrow
across a wait (checked: `host_call`, `reserve_agent_calls`, `release_agent_calls`, the parallel reply
loop, and all `host_call` callers).

## 3. Every blocking host-reply site

| # | site (baseline `f89618ef`) | waits for | verdict |
|---|---|---|---|
| 1 | `engine.rs:99` `drain_parallel_replies` | `SpawnAgent` replies already sent when `parallel()` setup fails | **same class, fixed** |
| 2 | `engine.rs:309` `host_call` | `SpawnAgent`, `BudgetQuery`, `RenderTemplate`, `Write/ReadScratchFile`, `GitDiffSince` | **same class, fixed**; stranded → `Failed: workflow host dropped reply` |
| 3 | `engine.rs:401` `reserve_agent_calls` | `ReserveAgentCalls` | **same class, fixed**; stranded → `Failed: workflow host dropped reply` |
| 4 | `engine.rs:439` `release_agent_calls` | `ReleaseAgentCalls` ack (the P37 wedge) | **same class, fixed**; result ignored as before |
| 5 | `engine.rs:636` `parallel()` live-reply loop | each live `SpawnAgent` | **same class, fixed**; stranded → `dropped_reply` terminal, as for any dropped reply |
| 6 | `engine.rs:891`, `:909` test mock hosts | `host_rx.blocking_recv()` | not the class: the receiving side; ends when the engine drops its sender |
| 7 | `validate.rs:75` validation stub host | `host_rx.blocking_recv()` | not the class: the receiving side of a thread that never drops its receiver before the engine's sender goes, so nothing can strand |
| 8 | `fuigo-shell/src/session/workflow/*` | — | no `blocking_recv`/`block_on` on a host reply. The host is the receiving side (`rx.recv()` in a `select!`, cancel-safe); the watcher awaits `exec` and `host_drained` (the latter bounded 25 s). Not the class. |

`host_emit` (`Phase`, `Log`, `Telemetry`) sends without a reply and never waits.

## 4. Tests and mutants

Five deterministic tests use a host that serves normally until it meets the named request, then drops
its receiver and holds that request until `WeakUnboundedSender::upgrade()` fails, i.e. until the
channel's last sender is gone. That is the lifetime tokio gives a stranded request (§1.1), made
deterministic. Each run is bounded at 20 s on its own thread, so a wedge fails with a named message
instead of hanging:

* `stranded_release_ack_does_not_wedge_a_cancelled_agent` — the P37 shape; outcome stays `Cancelled`;
* `stranded_release_ack_does_not_wedge_a_cancelled_parallel`;
* `stranded_reservation_fails_the_run_instead_of_wedging_it`;
* `stranded_host_call_fails_the_run_instead_of_wedging_it`;
* `stranded_parallel_agent_fails_the_run_instead_of_wedging_it` — depending on interleaving, the second
  request is dropped with the receiver (pending-reply loop) or its send fails (`drain_parallel_replies`);
  the test accepts either error message and asserts liveness;

plus `a_reply_the_host_already_received_is_still_awaited_after_its_channel_closes`, which pins the
design choice against give-up-on-close.

Mutants, each in its own worktree and target dir (`/root/fuigo-builds/p38/mut`, `target-mut`), filter
`stranded a_reply_the_host`:

| mutant | change | result | log sha256 |
|---|---|---|---|
| `none` | fix as committed | 6 passed, 0 failed | `b72a660fd265e4c2a653079ee1575b0dd59e98a37261dfccb48948027c86a6a8` |
| `revert` | `await_host_reply` body → `reply_rx.blocking_recv()` (the pre-fix wait at every site) | **5 failed**, all five `stranded_*`, each by the 20 s bound with the named P38 message; `a_reply…` passes | `5c1df821689c87d5b4292c4a42525a8ba6bd06f62424636e56ca4a7c31ad3dec` |
| `nodetach` | watch for closure but keep the engine's sender | **5 failed**, the same five: noticing the closure is not enough; the sender has to go | `cd4518a1bc376d9560bd94db2770fb51a97a77f7f54e15c1e5f68be946ecf095` |
| `giveup` | P37 PoC shape: on closure, report a dropped reply at once | **1 failed**: `a_reply_the_host_already_received…` (`Failed: workflow host dropped reply` instead of `Completed`) | `8b23ac65f8db31df4343ab6ddfbea3a354754eb545b8cc5f986f141e57b7faab` |

An earlier `revert`/`giveup`/`nodetach` round against `708a034d` (same test code, before the §2.1 borrow
fix) gave the same verdicts: `mutant.log` `477c01f0…`, `mutant-nodetach.log` `a313f0b1…`,
`mutant-giveup.log` `162b84dc…`. The first `giveup` attempt in that round was itself wrong (it blocked
on a fresh oneshot whose sender was alive, so everything hung) and was discarded (`03f5ddb8…`).

## 5. Stress (P37's recipe)

`fuigo_shell` lib test binary, `session::workflow::manager::tests`, `--test-threads=96`, 150 runs each,
`timeout -k 10 300` per run, `.shell-test.lock` taken per run, cwd `crates/codegen/fuigo-shell`. Note:
at `f89618ef` the manager tests do not carry P37's bounded teardown (`e713e086`, not integrated), so a
wedge at the parent shows as a run killed at 300 s rather than a named failure.

| rev | runs | failing runs | of which killed at 300 s (wedge) | evidence |
|---|---|---|---|---|
| parent `f89618ef` | 150 | **2** (runs 50 and 113) | 2 | `stress-parent-fail-50.log` `6fd08b21663e2466dc72684e6f18e8e69db86a3689a4c6ea01e31ef1147f8499`, `stress-parent-fail-113.log` `ce246c2c64b53ee422368097efafb679b490ad87bbc4b0646b86be0757d94f0b` |
| tip `c4227047` | 150 | **0** | 0 | `p38-run.out` 23:33:22–23:34:11Z |

Parent 2/150 is within P37's measured rate (6/150); tip 0/150. At this sample size 0 vs 2 is suggestive, not
statistically decisive on its own; the deterministic `stranded_*` tests and their mutants (§4) carry the proof.
(Filled in by the coordinator from `p38-run.out`.) Later tip batches by the author: **0/600 more, 0/750 total** at the tip. An extra parent batch was stopped early because of lock contention: **5 wedges by run 163** (runs 19, 29, 62, 110, 163); its completed-run count was not recorded, so it is reported as an incomplete batch, not a rate.

## 6. Gate (contract A.2.1)

`cargo test --locked --no-fail-fast -p <pkg>`, env `RUST_MIN_STACK=16777216 RG_BIN_PATH=/usr/bin/rg
CARGO_TERM_COLOR=never`, rustc 1.94.0, `nice -n 10`, `CARGO_BUILD_JOBS=16`; `fuigo-shell` under
`flock /root/fuigo-builds/.shell-test.lock`; `P38_DONE` appended after cargo exits. Parent built in
`target-parent`, tip in `target` (see §7.1 for why).

| pkg | rev | exit | derived | headers / unfinished | failing | log sha256 |
|---|---|---:|---:|---|---:|---|
| fuigo-workflow | parent `f89618ef` | 0 | 2 | 2 / 0 | 0 | `7b18c3a9babdc6e3eecc204778d2bda7f087b413d2469ca8be2bd92d1ed533ef` |
| fuigo-workflow | tip `c4227047` | 0 | 2 | 2 / 0 | 0 | `0f3f14dda78a2f081146970819b6f8971cc17add3e424ddb9080b5d501818c54` |
| fuigo-shell | parent `f89618ef` | 101 | 37 | 37 / 0 | 2 | `19cec39695c3ff7a74b064b3c624500f837f520fcf79fb0f0fe086099f3f9442` |
| fuigo-shell | tip `c4227047` | 101 | 37 | 37 / 0 | 6 | `dc6bc5e139dc3e68db4d8c7ae53d8522c355e72ac71daa0d5546d2b0c0cfc7ec` |

All four runs are admissible (headers equal derived, 0 unfinished, exit neither a signal nor 124,
DONE marker present, failing set from the `failures:` block).

`fuigo-shell` parent failing: `agent::config::tests::configured_endpoints_become_the_trusted_origins`,
`extensions::session_updates::tests::handle_falls_back_to_id_lookup_for_divergent_cwd`.
Tip failing: `handle_falls_back_to_id_lookup_for_divergent_cwd` plus five tip-only names. **The tip
set is not a subset of the parent's**, so each tip-only name was checked. None is in
`fuigo-workflow` or `session/workflow`, and the diff touches only `fuigo-workflow/src/engine.rs`.

| tip-only name | sightings in other `/root/fuigo-builds/**/*.failset` (of them labelled parent/base) | 3 × `--exact` at tip |
|---|---|---|
| `agent::models::startup_prefetch::tests::no_auth_boot_is_not_a_degraded_start` | 6 (2) | 3/3 pass |
| `agent::models::startup_prefetch::tests::wait_settings_leaves_the_fetch_for_accept` | 22 (11) | 3/3 pass |
| `inspect::tests::describe_requirements_file_flags_invalid_version_overrides_as_parse_error` | 12 (3) | 3/3 pass |
| `session::managed_mcp::tests::client_cursor_server_kept_when_cursor_mcps_enabled` | 6 (4) | 3/3 pass |
| `session::managed_mcp::tests::toml_claim_survives_when_client_cursor_insert_skipped` | 5 (3) | 3/3 pass |

Every one has failed before at other bases, including parent/base runs of earlier packets, and passes
in isolation at the tip (`iso.out` `5819ed59c49adae4683e0e4e18703eb9bfe49f289ae180dfc4299bee8dfe28b6`, 15/15 `rc=0`). I read them as the known load-dependent flakes of the full `fuigo-shell`
suite, not a regression from this change. The `parent` failing
`configured_endpoints_become_the_trusted_origins` did not recur at the tip.

**Clippy** `--locked --all-targets -p fuigo-workflow -p fuigo-shell`: parent exit 0, 23 warnings
(`733c43fd…`); tip exit 0, 23 warnings (`fc9cfa00…`). The set diff is one line each way, and it is
the same warning (`tokio::process::Command::spawn does not refer to a reachable function` from
`clippy.toml`) whose path differs only by worktree (`p38/parent/` vs `p38/src/`). **0 new warnings.**

## 6a. Post-rebase re-proof on `cca0969f`

Rebased onto P04's landing tip `8d250586` (stack P04 → P38 → P02f+g). Re-proof with `rp.sh` (slot-run, private HOME,
ulimit 65536; `fuigo-shell` with `--skip session::workflow::manager::tests` at both sides, labelled):
`fuigo-workflow` parent 0 / tip 0 failures (2/2 targets, 0 unfinished); `fuigo-shell` tip 6 failures, 38/38 targets, 0 unfinished;
clippy 23 = 23, 0 new. Tip-only `fuigo-shell` names: `embedded_otel_gate_keeps_a_session_user_fail_closed` (6 prior sightings),
`client_cursor_server_kept_when_cursor_mcps_enabled` (9), `toml_claim_survives_when_client_cursor_insert_skipped` (11),
`attempted_settings_fetch_failure_is_a_degraded_start` (0 prior sightings) — each passed 3/3 `--exact` at the tip, and the
unsighted one also 3/3 at the parent `cca0969f`. Logs: `/root/fuigo-builds/p38rp2.out`.

An earlier re-proof at `cca0969f` (`p38rp.out`) had 3/150 tip stress failures, all `expected spawn, timed out` (the test
helper's 2 s bound), under host load ~100. To attribute them, a controlled **interleaved A/B** of the manager module
(`--test-threads=96`, 90 s per run, same host, alternating parent/tip binaries; `p38ab.out`):

| binary | runs | ok | spawn-timeout | wedge (killed at 90 s) |
|---|---|---|---|---|
| parent `cca0969f` | 75 | 72 | 0 | **3** (runs 30, 56, 62) |
| tip `22715add` (P04 + P38) | 75 | **75** | 0 | **0** |

No spawn-timeouts on either side under equal load: the earlier three were load, not P38. `await_host_reply` is a
waker-driven park/unpark with no polling, so it adds no latency by construction. The tip side includes P04
(`ask_user_question` only; not reachable from the manager tests).

## 7. Runs not counted, and why

### 7.1 First launch discarded: the parent run executed the tip's mutant binary

The first gate launch shared one `CARGO_TARGET_DIR` between the parent and tip worktrees. Cargo's
metadata hash for workspace path packages does not depend on the worktree path, and the tip
worktree's last `fuigo-workflow` build was the `giveup` mutant. The parent's source files were older
than that artifact, so cargo reused it: the "parent" run took 3 s, compiled nothing, and failed
`a_reply_the_host_already_received…` with the mutant's exact message. Logs
`316a255d6655412617dee5512b99a9aa0107fcb7e03620945cd48f203328fe27` (labelled parent; really the mutant)
and `7775c7e6feaaba4e417187915ca3a455546791d0bf5c6104ab6442bf51f47697` (tip `708a034d`, which found
the `RefCell` bug in §2.1). I killed that launch by process group and relaunched with separate target
dirs. Neither log is a gate result. Other packets sharing a target dir across worktrees should check
for the same reuse.

## 8. Proposals (outside this packet)

* **Host keeps its receiver until the engine lets go** (`host_service.rs`): after cancel, answer each
  request with `Cancelled` until `rx.recv()` returns `None`, with children draining concurrently. This
  removes the cancel-path trigger at the source, so a cancelled run records `Cancelled` instead of the
  occasional `Failed: dropped reply` the engine now reports when it frees a stranded request. It
  changes the host's lifetime and needs its own tests.
* **Integrate P37's bounded manager-test teardown** (`e713e086`) so any future wedge fails by name.

## 9. Unverified

* §1.3's causal link between the tokio race and each observed wedge is inferred. The race is proven
  (§1.1), and the fixed code removes the wedge under stress (§5), but I did not capture a stranded
  slot inside a real wedge.
* The engine's last wait (after freeing its sender) is still unbounded if a host **receives** a request
  and then holds its reply sender forever without answering or dropping it. The production host does
  neither: synchronous arms reply at once, and spawned arms reply at the end of the task, or drop the
  sender when the runtime drops the task. That is a host bug class, not this one, and it is not
  bounded here.
* If some other code kept a clone of the engine's `host_tx` alive, **or a `WeakUnboundedSender` to it**,
  dropping the engine's copy would not free a stranded request (a weak sender holds the same
  `Arc<Chan>`). There is neither in production (checked again in R021 §4). The test stranding hosts do
  hold a `WeakUnboundedSender`, which is harmless there only because they model the stranded request by
  holding it themselves, outside the channel, and drop it when `upgrade()` fails; a request really
  stranded inside a channel with a live weak sender would outlive the engine's sender.
