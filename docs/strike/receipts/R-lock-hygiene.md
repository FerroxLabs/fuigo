# R-lock-hygiene: explicit unlock on the remaining flock helpers

Cause (from R-flake-rewind): a `flock` belongs to the open file description; a forked child that inherited the
descriptor keeps the lock after our handle is closed. Fix: reuse `HeldLock` (`session/storage/jsonl/mod.rs`, added
`HeldLock::new`), which unlocks in `Drop`. No second guard type; lock kind, order and timeouts unchanged.

## Sites (fuigo-shell/src/session)
| site | verdict |
|---|---|
| `storage/snapshot_lock.rs` `acquire_blocking` (returned bare File) | SAME-FLAW, fixed (returns HeldLock) |
| `storage/snapshot_lock.rs` `acquire_async` + `SnapshotHold._file` | SAME-FLAW, fixed |
| `storage/jsonl/copy.rs` `lock_append_for_snapshot` | SAME-FLAW, fixed |
| `storage/jsonl/copy.rs` `ForkStaging._lock` | same pattern, low impact (dir is removed with it); fixed, no test |
| `storage/jsonl/copy.rs` stale-staging sweep `drop(lock)` | same pattern, wrapped; no test |
| `persistence.rs` `LiveMark._sweep_lock` (shared) | SAME-FLAW, fixed; no direct test (field private) |
| `persistence.rs` summary lock in `mark_session_live_with` | SAME-FLAW, fixed (guard only once taken); no test |
| `persistence.rs` `try_lock_exclusive_pinned` (sweep lock, turn-owner lock, orphan lock) | SAME-FLAW, fixed |
| `storage/jsonl/mod.rs` `lock_append` (append/tail-heal lock, 2 callers + tests) | SAME-FLAW, FOUND, NOT changed (outside the brief; follow-up) |

## Evidence (Hetzner lane lockhyg, `-p fuigo-shell --lib`)
Tests (inherited copy simulated by `try_clone`, released guard, second locker must get the lock):
- `session::acp_session::turn_start_snapshot_tests::a_released_snapshot_lock_is_free_although_a_copy_of_its_descriptor_lives_on`
- `session::storage::jsonl::copy::tests::a_released_append_lock_is_free_although_a_copy_of_its_descriptor_lives_on`
- `session::persistence::cleanup_stale_sessions_tests::a_released_sweep_lock_is_free_although_a_copy_of_its_descriptor_lives_on`

| run | commit | result |
|---|---|---|
| RED, filter `a_released_` | 8f1f69b3 (tests only) | 3 failed by assertion, 1 passed (pre-existing) |
| GREEN x3, same filter | 94fb6640 | 4 passed each, rc 0 |
| whole lib | 94fb6640 | 8223 passed, 0 failed, 10 ignored |
| clippy `--locked --all-targets -p fuigo-shell` | 94fb6640 | rc 0; 34 pre-existing warnings, none in touched files |
Fix commit a7c85032 did not compile the lib tests (a copy test needed the guard type); 94fb6640 adapts that one line
(`copy_tests.rs` ~3030: wraps `lock_append`'s File in `HeldLock`; the expectation is unchanged).

## Unverified
- Windows and macOS not run (LockFileEx is per-handle, so the flaw is unix-specific; tests would pass there regardless).
- `try_clone` simulates the child's copy; a real fork/exec race was not reproduced.
- LiveMark, summary lock, ForkStaging and the stale-staging sweep have no red test of their own.
- `lock_append` remains bare-File (see table).

## Follow-up 2

An audit named two leftovers of the same hazard (a forked child holding a copy of the descriptor keeps the flock alive after our close).

- `lock_append` (jsonl/mod.rs) returned a bare `File`; a panic or early return before the caller's explicit unlock released only by close. It now returns `HeldLock`; both production callers keep their release point (`drop(lock)` where `lock.unlock()` stood), so timing on the normal path is unchanged.
- `private_staging_dir` (jsonl/copy.rs): the staging lock is wrapped in `HeldLock` right after `lock_exclusive`, before the rename, so a failed rename unlocks explicitly.
- Test callers: copy_tests.rs no longer wraps `lock_append` in `HeldLock::new` (it already returns one); what they assert is unchanged.
- Red test `a_dropped_lock_append_guard_is_free_although_a_copy_of_its_descriptor_lives_on` (copy_tests.rs): commit 6506440b failed by assertion before the fix; green after.
- Untested: the `private_staging_dir` rename failure (not simply forceable); covered by construction only.
