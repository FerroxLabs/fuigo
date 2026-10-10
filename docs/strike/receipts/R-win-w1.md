# R-win-w1: file-lock contention on Windows (product fix)

Base strike/land-batch2 b6ff8c11. Tests-only commit 8dacd3aa; fix commit d280a352 (tip before this receipt).
Bug: after a failed non-blocking fs2 lock, only `ErrorKind::WouldBlock` meant "someone else holds it". On Windows fs2 reports
ERROR_LOCK_VIOLATION (os 33, kind Uncategorized), so contention became a hard error instead of a wait / "busy".

## Sweep (non-test code, every `WouldBlock` match on a lock result)
| site | API | same bug | Windows effect before |
|---|---|---|---|
| fuigo-shell auth/subscription/storage.rs:176 | fs2 try_lock_exclusive | YES | second process fails sign-in/refresh at once with Storage instead of waiting up to 35 s |
| fuigo-shell auth/manager/lock.rs:273 | fs2 | YES | auth.json.lock held by another process = LockAttempt::Failed, not Busy: no wait, no stale-holder handling |
| fuigo-shell extensions/marketplace.rs:1286 | fs2 | YES | first-run config-init lock: os 33 error returned (caller drops it with .ok(), so no serialisation) |
| fuigo-active-sessions lib.rs:117 | fs2 | YES | signal-handler registry update returns Err instead of Ok(None) (skip) |
| fuigo-plugin-marketplace git.rs:130 | fs2 | YES | marketplace cache sync fails "failed to lock cache" instead of waiting for the other process |
| fuigo-shell session/storage/jsonl/mod.rs:822 | fs2, already `lock_contended_error().kind()` | no | (the WouldBlock there is the error it RETURNS after the deadline) |
| fuigo-mcp oauth.rs:199 | libc::flock, unix only | no | not compiled/used on Windows |
| fuigo-fast-worktree nfs/client.rs:676,701 | unix socket / libc flock, unix only | no | n/a |
| fuigo-memory dream_lock.rs:54 | std TryLockError | no | already correct |
| fuigo-workspace-daemon daemonize.rs, fuigo-config fs_atomic.rs, managed_config/store.rs, snapshot_lock.rs | fs2, already handle os 33 | no | none |
Other WouldBlock hits (tty/stdout, http policy, sockets, mixpanel, retry middleware, workspace-types) are not file locks: untouched.
Not fixed, other bug: auth/manager/lock.rs holder info unreadable while locked (os 33, baseline PRODUCT item 2/3), leader/lock.rs pid read.

## Fix
Five sites: `Err(e) if lock_is_contended(&e)` with a local copy of the repo's helper (same comment): kind AND raw_os_error equal
`fs2::lock_contended_error()`. On unix that is EWOULDBLOCK/WouldBlock, so unix behaviour is unchanged; other errors still error.
No new dependency, no change to lock kind, order, timeouts, retries or messages.

## Windows lane evidence (run.ps1 logs in C:\fuigo-win-lane)
- RED (w1red, w1red2, at 8dacd3aa, tests only): fuigo-shell 6 of 7 failed: refresh_is_serialized_across_processes,
  concurrent_refresh_reloads_rotated_record_after_lock, logout_all_waits_for_an_in_flight_refresh..., a_logout_that_waited_for_a_refresh...,
  new a_lock_held_through_another_handle_is_busy_not_failed, new a_held_init_lock_is_waited... ("os error 33"); fuigo-active-sessions new
  test: `Err(Os { code: 33, kind: Uncategorized })`; fuigo-plugin-marketplace new test: "failed to lock cache ... (os error 33)".
  (The child helper test subscription_refresh_child_process passes alone.) New tests pass on unix by construction.
- GREEN at d280a352: w1g1, w1g2, w1g3: fuigo-shell 7 passed each (3 runs); w1o1-3: active-sessions 6/6, plugin-marketplace 150/150 (3 runs).
- Whole suite (w1n, nextest, 8039 run): 7937 passed, 102 failed, 7 skipped. Baseline 107 -> 102.
  Left the failing list (5): the 4 subscription tests above and auth::manager::tests::enrichment_task_preserves_interleaved_token_rotation
  (that "probable" item was this bug: mgr.update() hit os 33). NEW failures: none.

## Windows user: before / now
Before: two Fuigo processes refreshing or signing in at once: the second failed immediately (Storage error); marketplace cache sync and
first-run init failed or skipped serialisation under contention. Now: they wait for the lock as on macOS/Linux.

## Unverified
Two real Fuigo processes were not run against each other. Linux lanes (fuigo-shell, fuigo-active-sessions, fuigo-plugin-marketplace) are
the coordinator's to run; macOS not run. Test count differs from baseline tip (8033) by the tests landed on this base plus 2 new.
