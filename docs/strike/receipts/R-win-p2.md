# R-win-p2: leader lock holder pid on Windows (packet 2)

Branch `strike/win-p2-leader`, base `strike/win-w2-copynames` 546295ea. Crate touched: `fuigo-shell` only
(`leader/lock.rs`, `leader/mod.rs`, `leader/test_support.rs`). No lock byte range, no on-disk format, no file deleted.

## Callers of the pid read (leader/mod.rs)
| Site | Process | Windows pid source before | Windows after | Unix |
|---|---|---|---|---|
| ~704 discovery `read_pid_from_path` | other | path, `None` while held | unchanged (pipe pid already used for reachable leaders) | unchanged |
| ~1798 fast path `lock.read_pid()` | not holder (lock not taken yet) | path, `None` if held | unchanged | unchanged |
| ~1837 after `try_acquire` Ok(true) | HOLDER | path read refused by own handle (os 33): `None`, branch never taken | gate is the answering pipe (`listener_is_ready` + connect); pid from the pipe | unchanged (file pid alive check) |
| ~1855 sibling-adopted telemetry | holder | `None` | pid from the pipe, read before `release()` | unchanged (file) |
| `evict_leader` (~1532) | holder | `None` | pid from the pipe (`GetLeaderInfo`, 2 s limit) | unchanged (file) |
| ~1934 vacate too-old leader | other (holds lock) | `None` | pid from the pipe, so a leader without relaunch gets a kill by its own reported pid | unchanged (file) |
| ~1617 zombie net | other | Linux only | unchanged | unchanged |
Own-handle read: `LeaderLock::read_pid` on Windows reads through the locking handle (seek 0, read) when this object holds the lock, else by path.
Choice for the pipe source: `cfg!(windows)` (pipe only, no file fallback, so nothing is ever killed on a stale file pid), not "file first": on unix "file then pipe" would change what happens when the file has no pid.

## ~1837 state
A live leader that owns the pipe but not the lock, found by a client that has just taken the lock. Not shown reachable by code
alone (the leader holds the lock for life); the old Windows code skipped it silently, the new code now connects, adopts or evicts it. What is spawned or adopted is unchanged.

## Vacate loop (~1934)
Reachability: `relaunch_v1` is in the first Fuigo history commit (b5e43b9e, tag v1.0.1); history before the rebrand is not in this repo: before that, unknown.
So no shipped Fuigo release known to lack it; reachable only by a legacy leader with no capabilities. The spin is also reachable with relaunch_v1: a leader answering `RelaunchDeclined` (or never exiting, or ignoring SIGTERM on unix) is asked again every 100 ms forever (unix spun the same way before).
Bound: `VACATE_WAIT_TIMEOUT` = `ZOMBIE_EVICT_DEADLINE` (30 s; `EVICT_WAIT_TIMEOUT` 8 s is shorter than the leader's 10 s relaunch grace so it would cut a working relaunch). After it: `ConnectionError::SpawnFailed("could not replace the old Fuigo leader (version <untrusted> ) that holds the lock: it did not exit within 30 seconds. Close the other Fuigo windows and try again.")`. Unchanged when the signal works (leader exits well inside 30 s).

## Evidence (Windows lane, nextest, 120 s per-test timeout)
- RED `p2-red`: `leader::lock::tests::write_and_read_pid` FAIL (os error 33).
- RED `p2-red3` (commit 2a0ca833): `a_too_old_leader_that_never_vacates_ends_in_an_error_within_the_budget` FAIL, loop still running at the test's 20 s limit. (`p2-red`, `p2-red2` first failed on the fake serving one client at a time; fixed by `FakeLeaderBehavior::NormalPerClient`.)
- GREEN `p2-green` (5379a7a9): `leader::` 304 run, 304 passed (both tests above pass; vacate test returns the error after the 2 s test budget).
- Test change listed: `write_and_read_pid` last assertion read the path while held and expected `Some`; on Windows now `None` (refused), `Some` on unix, then after `release()` both reads give the pid.
- Baseline `p2-full`: 8041 run, 7945 passed, 96 failed (before 97). Left the list: `leader::lock::tests::write_and_read_pid` (plus the ten fixed by W-1/W-2). New failures: none. Full names: `/mnt/c/fuigo-win-lane/fails-after-p2.txt`.

## Unverified
No real two-version upgrade run. Linux lanes (unix unchanged by cfg, the new vacate test also runs there) are for the coordinator; macOS not run. Pipe pid answer from a real leader on Windows covered only by existing GetLeaderInfo tests, not by a new end-to-end test.

## Round 2 (audit HIGH: payload pid terminated; NOTE: write_pid seek)
Branch `strike/win-p2r2-pipepid` (base 9754ccfb). Files: `leader/act_on.rs` (new), `transport.rs`, `client.rs`, `mod.rs`, `lock.rs`, `test_support.rs`.
- a. The client reads `GetNamedPipeServerProcessId` on its own `NamedPipeClient` handle right after connecting (`LeaderStream::os_server_pid`, stored in `LeaderClient`, windows only), so the pid is from the same connection used to talk to the leader; no second connect. Uses the `windows` crate already depended on (`Win32_System_Pipes` was enabled); no new dependency.
- b. Split by name: `leader_pid_to_show` (payload on Windows, lock file on unix; telemetry only) and `leader_target_to_act_on` (returns an `ActTarget`; the only input to `request_leader_vacate` and `evict_leader`). The payload pid never reaches a kill.
- c. OS call fails, process gone, cannot be opened, or image not Fuigo: `None`, a warn log, no kill; the vacate loop ends in the existing 30 s timeout error.
- d. Handle-based: `CheckedProcess::open_if` does ONE `OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION)`, `QueryFullProcessImageNameW` on that handle, and `TerminateProcess` and liveness (`GetExitCodeProcess`) through the same handle. `util::is_fuigo_process`/`kill_process_by_pid` are by pid and are not used on this path. Pid reuse between the connect and the open is possible but only a Fuigo-named image can then be hit.
- e. `util::is_fuigo_process` on Windows compares "fuigo" ANYWHERE in the full image path (so `C:\Users\fuigo\evil.exe` passes): too weak. The new `is_fuigo_image` compares the FILE NAME only: starts with `fuigo`, ends `.exe`, case-insensitive; the directory is ignored and not compared to the current executable (a user's second install is accepted; `cmd.exe`/`ping.exe` are refused). A squatter named `fuigo*.exe` run by another user cannot be opened with PROCESS_TERMINATE; one of the same user is the same trust level as the user's own Fuigo.
- Unix: `ActTarget` wraps the lock-file pid; `terminate`/`is_alive` call `kill_process_by_pid`/`is_process_alive` exactly as before. NOTE: `write_pid` now seeks to 0 after `set_len(0)`; unix never reads through the handle, so its cursor is already 0 (no effect).
## Round 2 tests and evidence (Windows lane)
- RED `p2r2-red` (688aaadb): `leader::tests::the_pid_from_the_pipe_payload_is_never_the_pid_to_act_on` FAIL, `left: Some(7777)` (the payload pid) at 9754ccfb logic.
- GREEN `p2r2-green1` (a0e5c6e5): 7/7 pass: that test (act-on pid = this process, the OS server pid, not 7777), `leader::transport::os_server_pid_tests::the_client_handle_reports_the_pid_of_the_process_serving_the_pipe` (real pipe, test is the server), `leader::act_on::tests::{only_a_fuigo_file_name_is_a_fuigo_image, a_process_that_is_not_fuigo_is_refused_and_keeps_running (child `ping`, killed by the test through its own child handle), a_gone_process_gives_no_target_and_this_fuigo_test_binary_is_accepted}`, `write_and_read_pid`.
- `a_too_old_leader_that_never_vacates_ends_in_an_error_within_the_budget` is the 7th test of `p2r2-green1` and passes; also not in the full-suite failing set.
- Baseline `p2r2-full` (a0e5c6e5): 8048 run, 7954 passed, 94 failed; failing names identical to `fails-after-p4.txt` (94), none new, none gone.
## Pipe security reading (not changed)
- (i) VERIFIED-BY-READING: `ServerOptions::new().first_pipe_instance(true).create(..)` (`transport.rs` ~200), no security descriptor passed; tokio passes null security attributes (tokio-1.53.1 named_pipe.rs ~2276), so the default DACL applies (full control to creator, SYSTEM, Administrators; read to Everyone and Anonymous per MS docs: the MS part is NOT-VERIFIED on this machine). `reject_remote_clients` defaults to true in tokio (line ~1773), so network clients are refused; local users are not refused by code. A different local user can create the name first (before the leader) and can open/read the pipe; whether they can WRITE depends on the default DACL (NOT-VERIFIED).
- (ii) VERIFIED-BY-READING for the first frame: `Register { client_type, mode, capabilities }`. After that the client sends ACP JSON-RPC payloads (the session's prompts and content); what a squatter may send back is ACP payloads the TUI/headless client acts on (agent-to-client requests such as file or terminal calls): NOT-VERIFIED which ones are honoured without a prompt.
- (iii) VERIFIED-BY-READING: none. No peer credential check (`GetNamedPipeClientProcessId`/token) on either side, no token file; `grep` for peer_cred/PEERCRED finds nothing in `leader/`.
## Unverified
No end-to-end run against a real squatting second user or a low-integrity process. Linux/macOS not run (unix compiled path unchanged by cfg; coordinator runs the Linux lanes). A real two-process leader eviction on Windows not run.
