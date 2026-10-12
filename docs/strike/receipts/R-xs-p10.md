# R-xs-p10: Windows inbox (packet 10; DESIGN S3.8)

Crate `fuigo-shell`, `src/peer_inbox/{win_policy,win_pipe,win_evidence}.rs`, `tests/win_peer_inbox_evidence.rs`.
INERT: no host calls `WinPeerInbox::start` (that is 8e). Behind `features.peer_messaging` (`start` returns
`WinUnavailable::FeatureOff` before any OS call). **Not run on Windows by the builder.** Windows code was only
`cargo check`ed (lane `w10-check2`, exit=0 at 618cd25d); the pure parts ran on Linux (Hetzner).

## Files
- `win_policy.rs` (every OS, 18 table tests): `win_peer_verdict`, `win_server_verdict`, `pipe_name`, SID text check,
  SDDL parser for the read-back owner and DACL, `WinUnavailable` (fixed texts).
- `win_pipe.rs` (`cfg(windows)`): `create_instance`, `WinPeerInbox` (`start`, `start_with`, `shutdown`, `host_id`,
  `directory`, as the unix `PeerInbox`; `home` is unused), `dial` / `dial_at`, `sys` (the only OS reads).
- `win_evidence.rs` (`cfg(windows)`, `pub mod`, re-exported doc-hidden as `fuigo_shell::win_peer_evidence`): the narrow
  door the integration test needs because `peer_inbox` is crate-private. No host code uses it.
- `leader/peer_auth.rs`: helpers made `pub(crate)` (`code`, `Owned`, `sid_to_string`, `peer_token_sid`,
  `PipeSecurity::from_sddl/as_raw`), plus `token_info_buf` / `token_user_sid` factored out of `process_token_user_sid`
  (same behaviour). `leader/mod.rs`: `mod peer_auth` -> `pub(crate) mod peer_auth`. `lib.rs`: the one re-export above.

## Rule table (server: `win_peer_verdict`, checked in this order, any `Err` fact refuses)
| Fact | Accept only if | Refusal |
|---|---|---|
| our own SID | readable and SID-shaped | OurIdentityUnknown |
| first instance | we claimed the name with FIRST_PIPE_INSTANCE | NotFirstInstance |
| pipe owner (read back) | our SID | PipeOwnerNotUs |
| pipe DACL (read back) | flags exactly `P`, ONE ACE, type `A`, no ACE flags, trustee our SID | PipeDaclNotOwnerOnly |
| client user SID | readable, SID-shaped | ClientUnreadable |
| client remote | `GetNamedPipeClientComputerName` = ERROR_PIPE_LOCAL and no NETWORK (S-1-5-2) group | ClientRemote / ClientUnreadable |
| client SYSTEM/service | not S-1-5-18/19/20, S-1-5-80-*, no SERVICE (S-1-5-6) group | ClientSystemOrService |
| client anonymous | not S-1-5-7, level not Anonymous | ClientAnonymous |
| impersonation level | readable | ClientLevelUnknown |
| client user == our user | equal | DifferentAccount |
Client (`win_server_verdict`): handle is a pipe (`GetFileType`), server process token user == ours AND pipe owner ==
ours; an unreadable server token is NOT rescued by a matching owner (unlike `peer_auth::decide`). Checked BEFORE any write.
Integrity level is not used (S3.8 does not name it).

## Pipe flags and why
Name `\\.\pipe\fuigo-peer-<32 hex of SHA-256(SID)>-<host-id>` (`pipe_name`; the SID must be SID text, so no input
leaves the prefix; the raw SID never appears). Every instance via `create_instance`: `first_pipe_instance(true)` on the
first (a squatter makes `start` fail `NameInUse`, nothing falls back); `reject_remote_clients(true)` explicitly on all;
`max_instances(33)` (32 served + 1 waiting); SECURITY_ATTRIBUTES from `O:<me>D:P(A;;GA;;;<me>)` (owner us, protected
DACL, one ACE for us, no SYSTEM, unlike the leader's), `bInheritHandle = false`; owner and DACL are read back for EVERY
instance and must match, else `ReadbackFailed`. Later instances need FILE_CREATE_PIPE_INSTANCE on our owner-only DACL,
so no other account can add one. Client opens with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` (tokio sets the
first), retries ERROR_PIPE_BUSY for 2 s, refuses a non-pipe (file, directory/junction fails to open).
After `ConnectNamedPipe` the client token is read on a `spawn_blocking` thread: `ImpersonateNamedPipeClient`,
`OpenThreadToken(OpenAsSelf=TRUE)`, `RevertToSelf` (RAII guard), then queries on the token. Verdict, then `serve_one`.
Over 32 connections: closed unread. No error or log line contains peer bytes (fixed enums; `tracing::debug` logs the
refusal enum only).

## Tested on Linux (Hetzner)
18 `win_policy` tests: every verdict row with fake accounts and each fact unreadable, the server verdict table, SID
classification, name prefix / hash / hostile inputs, SDDL round trip and malformed input.

## Windows-only, compile-checked only (never run)
Server, dialer, all Win32 reads. Uncertain until the evidence run: (1) and (2) are SUPERSEDED by "After the first Windows run" below (READ_CONTROL must not be passed; the read-back no longer uses SDDL text); (3) `GetNamedPipeClientComputerNameW` must return ERROR_PIPE_LOCAL (229) for local clients, else all clients are
refused as unreadable; (4) SUPERSEDED in round 2: a failed `RevertToSelf` now aborts the process (the earlier claim that it "can only lose
rights" was WRONG: the pool thread would stay the client, whose impersonation level the client chose). `unsafe` blocks: win_pipe.rs 13, win_policy.rs 0, win_evidence.rs 0,
peer_auth.rs +3 (`token_info_buf` x2, `token_user_sid`), each with a SAFETY comment.

## Evidence (run on a separate Windows machine)
```
cargo test --locked -p fuigo-shell --test win_peer_inbox_evidence -- --ignored --nocapture --test-threads=1
```
Prints `P10-EVIDENCE <case> PASS|FAIL <detail>`. Needs:
| Case | Needs |
|---|---|
| same_user_round_trip | nothing |
| second_local_account | env `FUIGO_P10_USER2`, `FUIGO_P10_PASS2` (second local account); missing = FAIL |
| system_client | env `FUIGO_P10_SYSTEM_LAUNCHER` = `psexec.exe`-compatible (`-accepteula -s prog args`, returns the exit code); missing = FAIL |
| remote_client | SMB / File and Printer Sharing on (connects to `\\<COMPUTERNAME>\pipe\...`); "network path not found" = FAIL (inconclusive) |
| pre_created_pipe | nothing (a squatter pipe is made first; `start` must say "already in use") |
| feature_off | nothing |
| non_pipe_and_reparse | nothing (a regular file and a `mklink /J` junction; the file must give `NotAPipe`, the junction an error) |
For the foreign-account cases, PASS = the pipe's own access list denied the open (child exit 5) or the server refused
before reading. S3.8 names a reparse point only for directories and locators, which the Windows pipe does not use; the
case above covers a non-pipe or reparse point at the dialled name.

## Round 2 (audit fixes; still not run on Windows by the builder)
Nothing below has run on Windows. `cargo check` on the Windows lane and the Linux unit tests are the only checks.

1. **RevertToSelf (HIGH).** Chose to KEEP impersonation and ABORT on a failed revert: `Impersonating::drop` calls
   `std::process::abort()` after one fixed-text `tracing::error!` (no peer data) before the closure can return. Why not the
   pid route (`GetNamedPipeClientProcessId` + `OpenProcessToken`): it names the process that opened the handle, not the
   token the connection presents; it has a pid-reuse window if the client exits; and it gives no impersonation level,
   which the verdict needs (`ClientAnonymous`/level facts). The impersonation route needs the abort and now has it. The
   `spawn_blocking` closure also OWNS the `NamedPipeServer` now (returned with the facts), so a cancelled task cannot close
   the handle under the blocking read.
2. **Read-back access.** Handle route: the first and every later instance is created by `CreateNamedPipeW`
   (`PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED [| FILE_FLAG_FIRST_PIPE_INSTANCE]`, byte mode, wait,
   `PIPE_REJECT_REMOTE_CLIENTS`, 33 instances, our SECURITY_ATTRIBUTES) and handed to tokio with
   `NamedPipeServer::from_raw_handle` (closing the handle if tokio refuses it). No by-name path (`SE_FILE_OBJECT` on a pipe
   name) is used: I could not cite documentation that it works. WRONG, FIXED: `READ_CONTROL` in `dwOpenMode` is invalid (`ERROR_INVALID_PARAMETER`, 87, verified on Windows Server
   2022); a `PIPE_ACCESS_DUPLEX` server handle already carries `READ_CONTROL`. See "After the first Windows run".
3. **`listener_owns_name`** replaces `first_instance_ours` (policy input, `Refusal::ListenerDoesNotOwnName`, test rows).
   It is a fact about the listener, set once in `start_inner` after the first instance was created with
   `FILE_FLAG_FIRST_PIPE_INSTANCE`. Later instances are created (flag off) only while the listener holds the connected
   instance. If the listener ever holds NO instance (the waiting one failed to be made), the fact is set false and it
   re-claims the name with the first-instance flag; while that fails, no client is served.
4. **ACE mask.** `AceSummary` now carries `rights`. `dacl_owner_only` = protected DACL, ONE ACE, kind `A`, no flags, trustee
   our SID, and rights in {`GA`, `FA`, `0x10000000`, `0x1f01ff`} (generic all as set, or the pipe's all-access it may be mapped
   to; masks are not compared as a superset: anything else, narrower or broader, refuses). Table tests: empty DACL, deny,
   object ACE, inherited (`ID`, `OICI`), `AI`/unprotected, extra trustees, `GR`/`GRGW`/`FAWO`/odd hex/empty rights, and a
   NULL DACL (`D:NO_ACCESS_CONTROL` does not parse). UNCERTAIN: whether the read-back renders `GA` or `FA`; both accepted.
5. **`dial_at`** is `#[cfg(debug_assertions)]` (and `win_evidence::dial_list_at` too); a release build cannot dial a name
   that `pipe_name` did not build. `dial` goes through `dial_checked`, which also requires the `\\.\pipe\fuigo-peer-`
   prefix. No `FILE_FLAG_OPEN_REPARSE_POINT` is needed: the pipe namespace is flat. `GetFileType == FILE_TYPE_PIPE` is
   still checked on the opened handle (`win_server_verdict`) before any byte is written. The evidence test file is
   `cfg(all(windows, debug_assertions))`.
6. **Foreign token reaches the verdict.** New case `foreign_token_reaches_the_verdict`, debug-only. `win_evidence::start_open_acl`
   starts the inbox only if the process env has `FUIGO_P10_EVIDENCE_OPEN_ACL=1` (read by `evidence_open_acl_requested`, which
   is `false` in release; it is the only reader). The pipe then also allows Authenticated Users and SYSTEM
   (`GRGW`), the owner is still checked on read-back, and the DACL fact handed to the verdict is replaced by the
   owner-only summary (otherwise the DACL check would refuse first and hide the layer under test). The case runs user2 and
   SYSTEM, requires exit 0, `accepted == 0`, exactly one new refusal, and the exact reason (`DifferentAccount`,
   `ClientSystemOrService`), and prints `refused_by_layer=server verdict function` (or the pipe ACL, if the widened DACL
   did not apply, which FAILS the case). Unit tests: the production SDDL has no other trustee; `evidence_open_sddl` is
   `None` unless requested and in release; `win_pipe.rs` source contains neither the variable name, `env::var`, nor the
   reader (`include_str!` test), and production `start` passes `evidence_open_acl: false`. The existing cases still prove
   the ACL layer.
7. **Checks.** `peer_auth.rs` before/after (`git diff e6e8b0e3`): (a) before, `process_token_user_sid` inlined
   `OpenProcessToken(TOKEN_QUERY)` -> `GetTokenInformation(TokenUser)` size probe (`needed == 0` -> `Err(0)`) -> `Vec<u64>` of
   `needed.div_ceil(8)` -> fill call -> deref `TOKEN_USER` -> `sid_to_string`; after, the same calls in the same order live in
   `token_info_buf` + `token_user_sid`, called by `process_token_user_sid`; (b) the error mapping (`code(&e)`, `Err(0)`) is
   unchanged; (c) the other edits are only `pub(crate)` on `code`, `Owned`, `sid_to_string`, `peer_token_sid`,
   `PipeSecurity::from_sddl`, `as_raw`. `TOKEN_GROUPS` is `{ GroupCount: u32, Groups: [SID_AND_ATTRIBUTES; 1] }` with
   `GroupCount` real entries; the array offset is now `offset_of!(TOKEN_GROUPS, Groups)` (not a hard-coded 8), the
   buffer is a `Vec<u64>` (8-aligned), count and extent are bounds-checked before the slice is made (SAFETY comments in
   `token_groups`). Dropping a `NamedPipeServer` drops tokio's `PollEvented<mio NamedPipe>`, which closes the server
   handle; closing the last handle of an instance disconnects its client (documented Win32 behaviour; the evidence run
   does not test it separately).

`unsafe` blocks: win_pipe.rs 15 (was 13: `create_with_security_attributes_raw` gone; `CreateNamedPipeW`,
`NamedPipeServer::from_raw_handle`, `CloseHandle` added), win_policy.rs 0, win_evidence.rs 0, peer_auth.rs +3 (unchanged).

### Evidence command and prerequisites (final)
```
cargo test --locked -p fuigo-shell --test win_peer_inbox_evidence -- --ignored --nocapture --test-threads=1
```
(debug build; the file does not compile in release.) Prints `P10-EVIDENCE <case> PASS|FAIL <detail>`. Env: `FUIGO_P10_USER2`,
`FUIGO_P10_PASS2` (second local account), `FUIGO_P10_SYSTEM_LAUNCHER` (psexec-compatible: `-accepteula -s prog args`, returns
the exit code), and for the new case also `FUIGO_P10_EVIDENCE_OPEN_ACL=1`; `COMPUTERNAME` and SMB / File and Printer
Sharing for `remote_client`. New case `foreign_token_verdict` proves the SERVER's verdict function refuses a second
account (`DifferentAccount`) and SYSTEM (`ClientSystemOrService`) when the pipe's ACL lets them connect; the other cases
prove the ACL layer and the start-up rules. Missing prerequisites FAIL (never skip). Not run on Windows by the builder.

## Round 2 follow-up (audit `grok-xs-p10-r2`, fixed by the coordinator; not run on Windows)

- HIGH fixed: `create_instance` closed the pipe handle a second time when `NamedPipeServer::from_raw_handle`
  returned an error. Tokio has already moved the handle into the mio pipe at that point and a failed registration
  drops it, which closes it; the extra `CloseHandle` was a double close. It is removed (15 -> 14 unsafe blocks in
  `win_pipe.rs`).
- `GroupCount` is now read as the `u32` at offset 0, not through a `TOKEN_GROUPS` place.
- Noted, not changed: when creating the NEXT instance fails while a connected instance is still held by its task,
  the listener marks the name as not owned and retries with the first-instance flag, which cannot succeed until
  that connection ends: fail closed, the inbox stalls for that time. The name of the evidence switch and the widened
  SDDL text are compiled into a release binary as strings; the read of the variable and the branch that uses the
  text are behind `cfg!(debug_assertions)`.

## After the first Windows run (Windows Server 2022, other session; results in `WIN-P10-RESULT.txt`)

**Blocker 1 (fixed).** `create_raw` passed `READ_CONTROL` in `dwOpenMode`; `CreateNamedPipeW` answers
`ERROR_INVALID_PARAMETER` (87), so every start failed. The flag is gone. A `PIPE_ACCESS_DUPLEX` server handle already
carries `READ_CONTROL` (verified there: `GetSecurityInfo` on the server handle succeeded without the flag). The earlier
sentences here that said the open mode must carry `READ_CONTROL`, or that it was merely "not in the documented list",
were wrong and are corrected above.

**Blocker 2 (fixed).** The read-back compared SDDL TEXT, and Windows renders well-known SIDs as aliases (the built-in
Administrator read back as `O:LAD:P(A;;FA;;;LA)`), so `owner == sid` failed and start was refused for such accounts.
Chosen approach: no SDDL text is parsed in production any more. `sys::owner_and_dacl` takes the owner PSID and the DACL
from `GetSecurityInfo`, reads "protected" from the `SE_DACL_PROTECTED` bit of `GetSecurityDescriptorControl`, walks the
ACL with `GetAclInformation`/`GetAce` (at most 16 ACEs, each at least header + mask + a minimal SID), and renders the
owner and every trustee with `ConvertSidToStringSidW` (never an alias). The pure `win_policy::dacl_summary_from_binary`
turns `RawAce { ace_type, flags, mask, trustee_sid }` into the existing `DaclSummary` (type 0 = `A`, flags empty only
when zero, mask as `0x...` hex), and the unchanged `dacl_owner_only` judges it; `rights_are_ours` already accepts exactly
`0x1f01ff` (what `GA` maps to) and `0x10000000`. A NULL DACL, a missing owner or any unreadable piece is an error, so
start is refused. New Linux unit rows: the built-in Administrator (RID 500) binary summary passes; unprotected, inherited
flag, deny type, broader mask, other trustee, extra ACE and empty DACL each fail; and the aliased text
`O:LAD:P(A;;FA;;;LA)` never passes the old SDDL parser (it is kept, unused in production, only for those tests).

**Harness (`tests/win_peer_inbox_evidence.rs`).** The second-account helper died with `0xC0000142` when started as another
user from a non-interactive session. It is now launched as a one-shot scheduled task registered for `FUIGO_P10_USER2`
(`schtasks /Create /RU /RP /SC ONCE /ST 00:00 /TN p10-ev-<pid>-<nanos> /TR ...`, `/Run`, bounded 60 s poll of a result
file and of "Last Result" in `schtasks /Query /FO LIST /V`, then `/Delete /F`). The helper script is written to a fresh
directory under `%PUBLIC%` (Everyone: modify) and writes its exit code (0 connected, 5 denied, 9 other) to
`result.txt` there; the task and the directory are removed by a drop guard on every path. Only if the task cannot be
created does it fall back to `Start-Process -Credential -LoadUserProfile` (CreateProcessWithLogonW; no explicit
`lpDesktop` is set, because PowerShell does not expose it). The password goes to `schtasks` on its command line (test
machine only) and is never printed. The helper now opens the pipe with `TokenImpersonationLevel.Identification`
(`SECURITY_IDENTIFICATION`, as production does). Missing prerequisites still FAIL.

**SYSTEM client read as `ClientUnreadable` (not determined).** The old helper used .NET's default pipe client, which sets no
SQOS flags; the server then impersonates at the level the OS picks, and `OpenThreadToken`/the level query may fail on
that token. I cannot tell without running it. The change that could matter is the identification-level dial above, so the
verdict path is the production one. `foreign_token_verdict` now accepts EITHER `ClientSystemOrService` or `ClientUnreadable`
for SYSTEM (both are refusals by the server's verdict function, "unreadable => refuse" stays) and prints which one.

**Stated limit (owner decision, behaviour unchanged).** On Windows, a Fuigo process started from an SSH session or any other network logon cannot use peer messaging: its token carries the NETWORK group and it is refused as a remote client, also when it is the same user. This fails closed and is intended.
The same-user evidence case must therefore be run from an interactive or batch logon (a scheduled task), not from sshd.

`unsafe` blocks: `win_pipe.rs` 17 (was 14: the SDDL conversion and its frees are gone; `GetSecurityDescriptorControl`,
`GetAclInformation`, `GetAce` and the ACE reads are new), `win_policy.rs` 0, `win_evidence.rs` 0, `peer_auth.rs` unchanged. Each keeps a SAFETY comment.

### Evidence command and prerequisites (final, after the first Windows run)
```
cargo test --locked -p fuigo-shell --test win_peer_inbox_evidence -- --ignored --nocapture --test-threads=1
```
Debug build only. Run from an interactive or batch logon, not from sshd. Prints `P10-EVIDENCE <case> PASS|FAIL <detail>`.
Env: `FUIGO_P10_USER2`, `FUIGO_P10_PASS2` (a second LOCAL account; the running account must be able to create scheduled
tasks), `FUIGO_P10_SYSTEM_LAUNCHER` (psexec-compatible: `-accepteula -s prog args`, returns the exit code),
`FUIGO_P10_EVIDENCE_OPEN_ACL=1` for `foreign_token_verdict`; `COMPUTERNAME` and SMB / File and Printer Sharing for
`remote_client`. Missing prerequisites FAIL (never skip).

## Round 3 audit follow-up (`grok-xs-p10-r3`, fixed by the coordinator on `strike/xs-p10-next`; not run on Windows)

- HIGH fixed: the read-back read `Mask` and a SID from every ACE type and handed the SID to
  `ConvertSidToStringSidW` without checking that it fits inside the ACE. Now only the two basic ACE kinds (allow 0,
  deny 1) are read; for those the SID's sub-authority count is read from inside the guaranteed first 8 bytes and
  the whole SID length (8 + 4 * count, count <= 15) must fit in `AceSize`, else the read-back fails (refused).
  Object and unknown ACE types are reported by type alone and the policy refuses them. No authorisation result
  changes: the audit confirmed non-allow types already failed the policy.
- Noted, not changed: only the protected control bit is passed to the policy (auto-inherit bits are not);
  evidence only: the helper's result file under `%PUBLIC%` is writable by everyone, so another local user could
  plant a result (a planted value could turn that one evidence case from FAIL to PASS; the run is on a machine
  with no other users); task and directory removal is best effort.
