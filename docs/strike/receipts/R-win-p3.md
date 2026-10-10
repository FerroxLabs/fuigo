# R-win-p3: starter-side identity check, hardened (Windows). The delete moved to the next release

Branch `strike/win-p3r2-starter` (base `4649dbc7`, windows lane on SeanDesktop). Owner decision (DECISIONS Section 30):
1.0.24 keeps ONLY the starter check; the delete of stale lock files is not in this release.

## What lands
After the starter takes the lock it compares the 128-bit id (`GetFileInformationByHandleEx(FileIdInfo)`, `FILE_ID_INFO`,
24 bytes) of its handle with that of a fresh open of the path (`lock.rs`, `win::decide`). Handles close on every path.
| held id / fresh open of the path | verdict |
|---|---|
| both obtained, non-zero, equal | Same: leader |
| both obtained, non-zero, different | Replaced: drop the lock, re-open |
| path missing (`ERROR_FILE_NOT_FOUND`/`PATH_NOT_FOUND`) | Replaced |
| query fails, an id is all zeros, or the open fails otherwise | NoCheck: leader, as before packet 3 |
NoCheck is safe only because nothing in 1.0.24 deletes lock files (code comment says so for the next release).
After `Replaced` the contended-case 200 ms pause now applies before the retry (was a busy loop to the 15 s deadline).
Unix unchanged (check is `NoCheck`); lock byte range and file format unchanged. `Cargo.toml` keeps the `windows`
feature `Win32_Storage_FileSystem` (needed for `FileIdInfo`).

## Removed from packet 3 (62b120ff)
Discovery prune in `leader/mod.rs`; `prune_dead_lock_file`, name filter and delete helpers in `lock.rs`; tests t1 (two),
t2b, t3, t4, t5 of `prune_tests.rs` (they tested the product prune). Replacement `e_dead_leader_files_stay_and_are_listed_stale`.
Proof of removal: `git diff 210aa6de HEAD -- crates/codegen/fuigo-shell/src/leader/mod.rs` has no prune code.

## Tests (`starter_identity_tests.rs`; logs in `C:\fuigo-win-lane\`)
| test | RED (`p3r2-red-kept`, commit 28b5db3f) | GREEN x3 (`p3r2-g1..g3`, b635c056) |
|---|---|---|
| a two starters, file deleted under one (TEST-ONLY helper): one leader; `a_without_the_check_two_leaders_happen` shows the hazard | hazard shown | ok |
| b decision table; equal low 64 bits but different 128-bit ids -> Replaced; zero id -> NoCheck | FAIL, FAIL | ok |
| c Replaced repeated: 3..8 attempts in 1 s, ends with Timeout | FAIL (spin) | ok |
| d normal start on NTFS: id usable, Same, leads | ok | ok |
| e dead leader files stay, listed Stale | ok | ok |
Whole suite (`p3r2-suite`): 8078 run, 7984 passed, 94 failed = exactly the 94 names of `fails-after-p4.txt`, no new name;
179 `leader::` tests passed. Peer-auth audit notes: see `R-win-pipe.md` "After the audit".

## Moved to the next release (proven delete design, commit `62b120ff` on hub branch `strike/win-p3-prune`)
- Open the file with DELETE access (no create, reparse point not followed, refuse directory/link), then `try_lock_exclusive`.
- Delete THROUGH the locking handle (`FileDispositionInfoEx`, DELETE|POSIX_SEMANTICS); the name goes at once.
- Exact name filter `leader-<8 lowercase hex>.lock`; never `leader.lock`; no pid read.
- Only when the pipe probe said unreachable AND the lock could be taken; a slow-but-alive leader holds the lock: kept (T1b).
- Open problem 1: mixed versions. An older starter has no identity check and could lead on a deleted file.
- Open problem 2: volumes without a usable 128-bit id (ReFS/network): the delete must skip them.

## Unverified
ReFS and network volumes were not on the lane; real leader binaries not run against each other; Linux lanes and clippy not run.
