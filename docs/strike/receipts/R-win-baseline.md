# R-win-baseline: fuigo-shell lib tests on native Windows (2026-10-09/10)

Branch strike/win-baseline (from win-testbuild 99debc9c). Test-code only. Linux not built by me: the Linux lanes must still run on this branch
(every unix value is unchanged: abs_tmp() returns exactly "/tmp" off Windows; the other edits are cfg gates / an import split).

## Changes
1. `test_support::abs_tmp()` (C:\tmp on Windows, "/tmp" elsewhere); 24 `AbsPathBuf::new(PathBuf::from("/tmp"))` sites now use it (12 files).
2. `session/signals_tests.rs`: 3 RSS tests gated `#[cfg(unix)]` (subject is getrusage; product returns 0 on Windows, see PRODUCT list).
3. `fuigo-pager-pty-harness/src/pty.rs:10`: `process_has_exited_without_reap` import gated `#[cfg(unix)]` (its uses were already unix-gated).
   `cargo test --locked -p fuigo-pager-pty-harness --lib --no-run` now builds on Windows (exit 0). On Windows the harness compiles; the
   exit-observation-before-reap path and its tests are unix only (no stub added); PTY spawn itself goes through portable-pty/ConPTY, not exercised.
Lane env change (not run.ps1): `core.autocrlf` was true in C:\fuigo-win, so sources were CRLF and source-text tests (`agent/config_tests.rs:3955`
splits on "\n}\n") failed. Set to false + re-checkout: fixes 2 tests (agent::config x2). The RC lane should keep autocrlf=false.

## Numbers (fuigo-shell --lib, 8036 tests)
Before (99debc9c): 7110 passed, 923 failed, hang. After (nextest, whole suite, 85 s wall): **7922 passed, 107 failed, 0 timed out, 7 skipped**.
cargo-test slices after fixes (passed/failed): session::acp_session 1298/44, agent:: 1581/5, auth:: 458/31 (+1 hang, skipped), extensions:: 486/17,
util:: 410/12, leader:: 302/1, config:: 1092/2, rest 3071/9. Wall: ~4 min (build 126 s incl.).
Hang: `auth::oidc::login::tests::login_flow_opens_the_browser_when_the_token_endpoint_is_on_the_issuer_origin` under plain `cargo test`: after printing
"Paste the URL here if it doesn't connect:" the flow blocks reading stdin; the lane's hidden powershell gives an open, never-ending stdin. TEST/lane
(label TEST: lane environment). Under nextest (stdin null) the test passes, no hang.
nextest vs cargo: nextest fails 107, cargo-test slices fail ~121 distinct; the oidc hang test and the folder_trust (4), several subscription tests
pass under nextest only (shared process state / HOME). Not diffed name by name (nextest log wraps names) - Unverified.

## RC gate command (settled)
`run.ps1 <name> "nextest run --locked -p fuigo-shell --lib --no-fail-fast --config-file C:/fuigo-win-lane/nextest.toml"` (forward slashes; no -E with
quotes through run.ps1: it never started; use positional filters). nextest.toml: `slow-timeout = { period = "60s", terminate-after = 2 }`, `fail-fast = false`.
Wall 85 s warm after a build (build 126 s). Still start without -Wait and bound the wait.

## Classification (panic text read; I did NOT rerun each alone, so labels are from message + code, "probable" where noted)
TEST ~86 (unix assumption or lane env), PRODUCT 12, UNKNOWN ~22 (of ~120 distinct cargo-run failures, hang counted TEST).
- TEST unix assumption: pre_tool_use_decision_tests (14) and prompt_gate_tests (10), client_hooks, turn_end_reporting, stream_retry (hook commands via sh,
  probable); util::subprocess (5), util::user_identity (6) (sh/exit-code scripts, "Some(0) vs Some(3)"); auth::auth_provider (19), external_auth, flow (3),
  pre_tui, auth_error_no_retry_tests (7) (provider shell commands, probable); parallel_dispatch lock_path (5: expects "/repo/src/main.rs", gets C:\repo\...);
  extensions::suggest (15: unix path expectations, probable); image_describe ("/assets/image-" separator); unified_list::row (CwdNotAbsolute, a "/..." cwd).
- TEST lane env: folder_trust x4 ("HOME redirect did not take effect": Windows reads USERPROFILE); config::validate_hooks_path (unix path in test); oidc hang (stdin).
- UNKNOWN (not analysed): extensions::share x2, p07/p141 plugin hook "fixture" asserts x4, goal_planner_e2e x2, plan_mode_edit_gate, laziness debug_mode,
  managed_mcp p118/p141, util::config::mcp plugin registry, subagent_override_provider_model, manager::enrichment_task, durable_update_tests (nextest only),
  agent::config::resolve_credentials_sets_auth_type (nextest only).

## The three asked analyses
(i) leader::lock write_and_read_pid: PRODUCT. `write_pid` (leader/lock.rs:230) writes the pid into the file it holds LockFileEx-locked; `read_pid_from_path`
(lock.rs:244) opens a SECOND handle and reads: ERROR_LOCK_VIOLATION (33), swallowed by `.ok()?` -> None. Product callers: leader/mod.rs:704, 1532, 1617,
1798, 1837, 1855, 1934 (leader discovery, "who holds the lock", vacate request, liveness). On Windows a client can see the lock is held (try_acquire false,
lock.rs:185 handles contention correctly) but never learns the pid: stale-leader detection (is_process_alive of the pid) cannot run and the vacate request
gets None. Expected user effect (inferred, not run): a dead leader's held-then-orphaned state cannot be pruned by pid; connect falls to socket probing
or a wait/timeout; not a crash. This is exactly the area of the planned stale-leader packet.
(ii) auth::manager::lock tests: the failing read at lock_tests.rs:278 is test code (second handle, `fs::read_to_string`), but the PRODUCT does the same:
`read_holder_at` (auth/manager/lock.rs:626) and `read_holder` (lock.rs:166, on a contender's own non-locking handle) hit os error 33 and fall back to the
"unidentifiable holder, classify by mtime" branch. Holder info is telemetry/stale classification only: acquisition (try_lock_exclusive, lock.rs:232) works.
Effect on Windows: a stuck/stale holder is judged by file age instead of pid liveness, so a crashed holder is waited out to the deadline rather than
salvaged early (salvage_at_deadline, lock.rs:595). Test is wrong on Windows too; product degrades. Label PRODUCT (degraded diagnostics).
(iii) subscription: PRODUCT, real. `storage.rs:174-178` (lock()) treats only `ErrorKind::WouldBlock` as contention; on Windows fs2 try_lock_exclusive returns
ERROR_LOCK_VIOLATION (33, kind Uncategorized), which falls into `Err(_) => Err(SubscriptionError::Storage)`. So when another process holds credentials.lock the
second process FAILS with Storage instead of waiting up to 35 s: cross-process refresh serialisation does not exist on Windows (two processes refreshing
at once: one errors "Storage" -> sign-in/refresh failure; also in-flight-refresh vs logout tests). Not a lane problem (child fails the same way with the
private profile). Fix pattern already in the repo: `fs2::lock_contended_error().kind()` (session/storage/snapshot_lock.rs:105, leader is_lock_contended).

## PRODUCT list (not fixed)
- auth/subscription/storage.rs:176  contention not recognised on Windows -> Storage error instead of wait (5 tests: refresh_is_serialized_across_processes, child_process, concurrent_refresh_reloads..., logout_all_waits..., stash_tests).
- leader/lock.rs:244  pid unreadable while locked (LockFileEx), used at leader/mod.rs:704,1532,1617,1798,1837,1934 (1 test).
- auth/manager/lock.rs:166,626  holder info unreadable while locked -> mtime-only stale logic (2 tests: acquire_release_and_reacquire_succeed, nonblocking_acquire_writes_holder_info).
- session/persistence.rs:2921  `rel_path.to_str()` keeps backslashes in copied-session file names ("a\b\deep.txt"); a session copied on Windows carries non-portable names (4 collect_session_files tests).
- session/signals.rs:43-46  `sample_rss_bytes` returns 0 on Windows: peak RSS telemetry always 0 (3 tests gated, not failing).
Gated tests: signals_tests.rs test_sample_rss_bytes_returns_nonzero, test_sample_rss_bytes_is_stable, test_peak_rss_recorded_at_turn_end.
Not reached: per-test rerun with --nocapture of the UNKNOWN group; shell-vs-path split of the TEST group is by message, not by fix; no (b) unix-path
test fixes beyond the /tmp helper (stopped at the cap, 107 remain).
