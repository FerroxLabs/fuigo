# R-fsatomic-grant: late-grant flock outlived its release

Failure: `fs_atomic::tests::timed_out_cross_process_waits_share_one_helper_and_release_a_late_grant` (WouldBlock at
the "late grant must have been released" check), once, on a loaded box.

## Cause (PRODUCT bug, same class as rows 190/193/194)
Every flock in `fs_atomic.rs` was released by dropping/closing the File. A flock belongs to the open file
description; a child forked by another thread (`Command::spawn`) between our open and its exec holds a copy of the
descriptor and keeps the lock until it execs. The helper's too-late grant (`drop(too_late)`) therefore could stay held.
The same applied to a real `ConfigWriteLock`: a config write lock could stay held briefly after its holder dropped it.

## Site table (before the change)
| Site | Released by |
|---|---|
| `ConfigWriteLock._file` (stage-3 try-lock and helper grant) | drop only |
| `turn` helper, too-late / failed grant (`drop(too_late)`) | drop only |
| `turn` queue `granted` handed to the waiter | drop only |
| `xq::Ticket.file` (liveness lock on the ticket) | drop only |
| test-lock-dir marker (`OWNED`, ~912/944), test support only | drop only (unchanged; not a config write lock) |
After: `open_lock_file` returns `HeldFlock` (new local guard, explicit `unlock` in Drop, as `HeldLock` in fuigo-shell);
`ConfigWriteLock._file`, `granted`, `await_flock` and `Ticket.file` carry it, so every site above unlocks first.

## Hypotheses
- H1 (drop + forked child): CONFIRMED. Test `a_late_grant_is_released_while_another_thread_keeps_forking_children`
  (a thread spawns `true` in a loop while the target body runs): before the fix 5 of 5 runs failed at
  fs_atomic.rs:3114 (stressor version, 300 iterations); after the fix 5 of 5 runs of 200 iterations passed.
- H2 (test race): rejected by reading: the test spins on `!is_tracked(key)`, and the helper drops the file before
  removing the idle queue, so the test waits for exactly the release.
- H3 (helper releases after returning): rejected, same ordering.

## Proof (fuigo-config, Hetzner lane fsatomic, base cd903597)
- target test alone, 100 runs: 100 pass; whole `-p fuigo-config --lib`, 10 runs: 10 x 455 passed, 0 failed.
- stress test final form 50 iterations (red fails within ~1 s; kept short).
- clippy `--all-targets -p fuigo-config`: 2 warnings, both `managed_text/tests.rs` canonicalize (not my lines).
- The red commit holds the test alone; I ran the 300-iteration stressor form on the unfixed code (5/5 red), not the
  committed 50-iteration form.

## Unverified
Windows (`unlock` on drop is a no-op-safe call there but not exercised); the stress test is probabilistic, not
deterministic (the helper's descriptor is not reachable to hold a `try_clone`); not rerun against fuigo-shell users.

## Follow-up (audit notes of grok-fsatomic-r2, stress strength)

Timing of `a_late_grant_is_released_while_another_thread_keeps_forking_children` at integration cd9d3eab (Hetzner, 3 runs each, slot-run):

| iterations | wall (3 runs) |
|---|---|
| 50 | 10.35 / 10.49 / 10.58 s |
| 150 | 31.5 / 31.8 / 31.8 s |
| 300 | 62.4 / 62.6 / 63.5 s |

Catch rate with `HeldFlock::drop` made a no-op (lane worktree only, reverted with `git checkout`, status clean):

| iterations | failures out of 10 |
|---|---|
| 50 | 10 |
| 150 | 10 |
| 300 | 10 |

Choice: 300 does not fit under 10 s (one iteration is about 0.21 s: 20 timed-out waits plus a 500 ms wait). 50 is the largest count near 10 s and it caught the bug 10 of 10, so the normal suite keeps 50 (`stress(50)`); the 300-iteration run is added as `..._keeping_forking_children_300`, `#[ignore = "RC checklist: run with --ignored"]`, sharing `fn stress(iterations)`. Suite wall time unchanged (the stress test already dominated): 10.5 s before and after.

Item 2: `is_live` and `sweep_private` wrap the file in `HeldFlock` right after `try_lock_*`. Old effect: a probe lock kept alive by a forked child's descriptor copy made a later probe see the ticket as live (is_live) or the private file as busy (sweep_private), so a dead writer's ticket could stay in the queue and block the writers behind it until that child exec'd (milliseconds); no data loss. Red-first test `a_probe_lock_is_released_while_another_thread_keeps_forking_children` (3 s; `is_live` made `pub(super)` for it): 10 of 10 red on the unfixed `is_live` (fails in milliseconds, WouldBlock), 0 of 3 red with the fix. No red test for `sweep_private` (fixed by construction; same wrapper).

Item 3: `xq::register` wraps the file in `HeldFlock` as soon as `lock_exclusive` returns; order lock, stamp, hard_link, remove private unchanged. No test (a panic there cannot be forced simply).

Green: whole `fuigo-config --lib` 5/5, the stress test 5/5, probe test 5/5, `--ignored` 300 run 1/1, `timed_out_cross_process_waits_...` 30/30, clippy: only 2 pre-existing `canonicalize` warnings in managed_text/tests.rs.

Unverified: macOS and Windows (the new tests are Linux only; the unlock changes there rely on the audit's reading of flock/LockFileEx).
