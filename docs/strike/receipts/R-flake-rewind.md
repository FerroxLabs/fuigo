# R-flake-rewind: intermittent `rewind_reconcile` tests

## Facts
Five different tests of `session::storage::jsonl::rewind_reconcile::tests` failed once each in unrelated two-sided lanes
(whole `fuigo-shell` lib suite in parallel). Test setup is already isolated (`TempDir` + `JsonlStorageAdapter::with_root`
per test, no env/HOME/statics), so shared test state is ruled out.

## Reproduction (base `fb0a5316`, Hetzner lane flakerw)
- Module alone, `--test-threads 16`, 8 processes at a time: 200 runs, 0 failures.
- Whole lib suite: 6 runs, 1 failure: `killed_before_the_swap_the_leftover_goes_and_nothing_changed`,
  `rewind_reconcile_tests.rs:190` `expect("the user is told")` (reconcile returned `None`).
  So it needs other tests of the crate running (they spawn child processes).

## Cause: PRODUCT defect (lock hygiene), not shared test state
`lock_bounded` (`jsonl/mod.rs`, was ~762) returned a plain `std::fs::File` for the rewrite/append lock files. A `flock`
belongs to the open file description: a child forked by another thread (`Command::spawn`) between open and exec holds a
copy of the descriptor, so closing ours does not release the lock until the child execs. `reconcile_interrupted_rewind`
takes the rewrite lock with a zero wait (`rewind_reconcile.rs:455`) and treats "held" as "a rewind is running" and returns
`None`; the test (and a user's load) is silently skipped. `turn_owner_lock.rs:77` (`unlock_on_drop`) already documents and
handles exactly this for the session lock; the rewind locks did not. `auth::manager::lock::tests::a_forked_child_transiently_keeps_a_dropped_lock_held` shows the same effect elsewhere.
User-visible consequence: after a Fuigo kill in the middle of a rewind, the recovery on load can skip with no notice
(leftover copy/journal stay until the next load), and a rewind started just after another is refused as "being written
by another process" for the instant a fork is in flight. No corruption or doubling: the skip path changes nothing.

## Fix
`HeldLock` (`jsonl/mod.rs`): wraps the locked file, `Deref<File>`, and unlocks explicitly on drop. `lock_bounded` and
`lock_rewrite_bounded` return it, `RewindPointsRewriteLock.rewrite` (`storage/mod.rs`) holds it, `bounded_lock`
(`rewind_reconcile.rs`) returns it. Regression test (RED at `e04473e7` by assertion, green at `064fc283`):
`a_finished_rewind_is_not_running_because_a_forked_child_holds_a_copy_of_its_lock` (a `try_clone` stands in for the child's copy).

## Before / after (same commands)
| command | before (`fb0a5316`) | after (`064fc283`) |
|---|---|---|
| whole `fuigo-shell` lib suite x6 | 1 failed | 0 failed |
| `rewind_reconcile` module, 16 threads, 200 runs | 0 failed | (300 runs) 0 failed |

Proof: lib x6 all green (>= 3 required); module x300 zero failures; `cargo clippy --locked --all-targets -p fuigo-shell` rc 0,
no warning on a line added (pre-existing warnings elsewhere).

## Unverified
- The module alone never failed in 200 runs; the before-count of 300 module runs was not taken (it is 0/200).
- Only one organic failure was captured, so the other four tests' failures are attributed to the same cause by the same
  mechanism (all call `reconcile_interrupted_rewind` through the zero-wait rewrite lock), not observed.
- `the_snapshot_releases_its_locks_before_it_reads_the_history` and `a_held_mark_keeps_a_session_whose_load_outlives_the_ttl`
  were not reproduced; they use other lock helpers (`snapshot_lock`, `lock_append_for_snapshot`, the session mark) that may still close plain `File`s. Not changed.
