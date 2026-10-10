# R-win-p4: lossy case fold, vacuous junction tests, two auth-lock tests (Windows lane)
Branch `strike/win-p4-casefold` (base `strike/win-p2-leader` 229a0c15). Crate touched: fuigo-shell only. Native Windows lane only; nothing built in WSL or on Hetzner.

## A. Lossy case fold (security, tighten only, `cfg(windows)`)
- Compared: in `is_direct_child_windows` (session/storage/mod.rs), the final path's last name (from `GetFinalPathNameByHandleW`, on-disk case) against the leaf name the caller asked for, to decide the opened file is "the expected leaf, directly in the held folder". The fallback used `String::from_utf16_lossy(..).to_lowercase()`.
- Wrong "equal": every lone surrogate becomes U+FFFD, so a file named `f<D800>.txt` was accepted as the expected `f<D801>.txt` (or `f<FFFD>.txt`). That lets a different, broken-named sibling stand in for the expected leaf. Realism: low (needs an attacker-created sibling with an unpaired-surrogate name next to the expected one, and the expected name itself to be broken); the other checks (parent unit-for-unit, no reparse) still hold. Tightened anyway.
- Chosen compare: exact UTF-16 units first, else `CompareStringOrdinal(.., ignore_case = TRUE)` (kernel32, declared like the file's other kernel32 calls; no new crate). The requested name can differ in non-ASCII case from the on-disk one (the OS returns on-disk case, the caller may hold another case), so ASCII-only would refuse legitimate names; the OS ordinal rule is the one Windows uses, and it leaves lone surrogates untouched, so they stay different.
- Tests: `leaf_names_differing_only_in_an_isolated_surrogate_are_different` (RED lane log `a-red.log`: FAILED, exit 101; GREEN `a-green.log`: 11 passed, exit 0) and guard `leaf_names_compare_without_regard_to_case_the_way_windows_does` (F.TXT/f.txt, self-equal accented name, U+00C9/U+00E9 in other case equal, cafe != cafe-accent): passed before and after.

## B. Vacuous junction tests (test only)
- Before: the in-place conversion tests asserted only inside `if let Ok(..)`. After: `a_folder_turned_into_a_junction_between_two_folder_opens_is_refused` is unchanged in logic; the two `open_leaf_beneath_windows` tests (in-place, lookalike) now `assert!(opened.is_err())` unconditionally (the trusted folder holds no f.txt, so any success is a read through the junction) and print `P154 SKIPPED-JUNCTION` if the lane could not convert.
- Lane (`b-green.log`, `--nocapture`): `P154 in-place conversion succeeded: true`, `P154 lookalike conversion succeeded: true`, `P154 lookalike open refused: a folder on its path is not a real directory (a symlink is never followed)`; 11 passed. The junction is really made here and the assertion runs.

## C. Auth-lock tests (tests only)
- Cause: reading the holder line through a second handle while the lock is held fails on Windows (os error 33). Holder info is telemetry only (owner decision).
- Fix: both tests read the file AFTER release (the line stays; Drop does not touch it), on every OS; the original while-held read stays under `#[cfg(unix)]`, so unix is strictly stronger than before. No product API added.
- RED `c-red.log`: both FAILED (exit 101). GREEN three runs `c-g1/c-g2/c-g3.log`: 6 passed each, exit 0.

## Baseline diff (`suite-p4.log`, nextest --lib --no-fail-fast, 8043 run, 7949 passed, 94 failed, 7 skipped)
- `fails-after-p4.txt` = 94 names; vs `fails-after-p2.txt` (96): LEFT = `auth::manager::lock::tests::acquire_release_and_reacquire_succeed`, `auth::manager::lock::tests::nonblocking_acquire_writes_holder_info`. NEW = none.

## Unverified
- Linux/unix lanes (the cfg(unix) blocks and unix behaviour) are for the coordinator; no clippy run. A real junction escape beyond these tests was not attempted. Test files for B and C were also not re-run three times beyond the logs above.
