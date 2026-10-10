# R-win-pipe: Windows leader pipe limited to the current user (owner-approved, tighten only)
Branch `strike/win-pipe-auth` (base `62b120ff`). Commits: tests with the seams as no-ops `971e9784`, fix `b401c157`, then docs.

## Final rule (client, after connect, BEFORE any byte is sent)
| own account | serving process token | pipe owner | verdict |
|---|---|---|---|
| unknown | any | any | Refuse |
| known | readable, equals ours | not consulted | Accept |
| known | readable, differs | not consulted | Refuse (the owner cannot rescue it) |
| known | unreadable (any error) | equals ours | Accept (elevated same-user leader) |
| known | unreadable | differs or unreadable | Refuse |
Follows (b) to the letter whenever the token is readable. The owner is only a FALLBACK when the token cannot be read (the
untested elevated case): the server sets owner = current user in its descriptor, and only that user or an administrator can
make the owner that SID. So the accepted peer is the same user, or an administrator acting for that user.
Server: every instance (first and re-created, one function `peer_auth::win::create_secure_server`) is created with
`O:<user>D:P(A;;GA;;;SY)(A;;GA;;;<user>)` through `ServerOptions::create_with_security_attributes_raw`; failure to build the
descriptor fails the bind (no fallback to the default). `first_pipe_instance` and remote-client rejection unchanged.
APIs: `GetNamedPipeServerProcessId`, `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, `OpenProcessToken(TOKEN_QUERY)`,
`GetTokenInformation(TokenUser)`, `GetSecurityInfo(SE_KERNEL_OBJECT, OWNER)`, `ConvertSidToStringSidW`,
`ConvertStringSecurityDescriptorToSecurityDescriptorW`, `LocalFree`. SIDs are compared as strings (equal text = `EqualSid`).
Refusal: `ClientError::PeerRefused`, text "The Fuigo background process on this computer is running under a different user
account, so this window will not connect to it. Close Fuigo in the other account and try again." Debug log has Win32 codes only.
It is treated as a terminal refusal (no reconnect loop, no zombie eviction).

## RUN on the lane vs BY REASONING
RUN (same user, same integrity level, one process tree): token of the serving process is readable (`t2b`), pipe owner = our
account, descriptor read back from real handles (`t1`, `t1b`), real client connects and registers (`t2`), 178 existing leader
tests connect same-user clients in process. BY REASONING (not run, no UAC prompt and no second account allowed): (1) whether a
medium-integrity process may open the token of an elevated process of the same user: not established; the rule does not depend
on it (fallback to the owner, which needs no process access); (2) a second account: covered by the decision function with fake
SIDs (T5) and an injected "other account" at the seam (T3); the DACL denying other accounts is read back (T1) but no other
account ever tried to connect; (3) that an elevated leader's pipe owner is the user (we set it in the descriptor; Windows lets
a user assign their own SID as owner; read back only for the non-elevated case).

## Tests (lane logs in `C:\fuigo-win-lane\`)
| test | RED `wpipe-red` @971e9784 | GREEN `wpipe-g1..g3` @b401c157 (21 passed each) |
|---|---|---|
| T1 `t1_...restricted_descriptor`, `t1b_...listener...re_creates...` (owner, exactly 2 allow entries SY + user, no WD/AN/BA/AU/BU) | FAILED (default DACL) | ok |
| T2 `t2_same_user_is_accepted_and_nothing_is_written_before_the_check` (server byte count 0 at check, >0 after) | FAILED | ok |
| T3 `t3_a_leader_of_another_account_is_refused_before_anything_is_sent` (zero bytes) | FAILED (client sends) | ok |
| T4 `t4_failing_os_queries_refuse_and_send_nothing`; `t4b` real failing queries (null handle) -> Refuse | T4 FAILED; t4b ok (pure) | ok |
| T5 `decision_tests::*` (7: same, other, SYSTEM, unreadable token, unreadable all, own unknown) | ok (pure) | ok |
| T6 (h) `h_the_pid_is_acted_on_only_if...`, `h_the_duplicate_handle...`; (i) `i_a_long_image_path...`, `i_other_errors...`; (g) `g_leader_kill_never_terminates...` | new pure fns, no red possible | ok |
Baseline: `wpipe-full` nextest `-p fuigo-shell --lib`: 8075 run, 7981 passed, 94 failed, 7 skipped; failing set IDENTICAL to
`fails-after-p4.txt` (94 names, 0 new, 0 missing). 178 `leader::` tests passed, 0 failed. Pager binary: `wpipe-pager`
(`test -p fuigo-pager-bin --no-run`) exit 0, no warning from changed files. Tests used unique pipe names, no real home, spawned
no children.

## Items (g)(h)(i)
(g) `fuigo leader kill`: `leader_kill_plan` (leader/mod.rs). Windows: only a leader whose pipe answered is acted on, through
`kill_leader_by_connection` (OS server pid of that connection, Fuigo image, one handle); a payload pid or lock-file pid is never
terminated and no lock file is removed; otherwise it prints that the process cannot be identified safely, the lock path, and to
close the other windows. Unix path unchanged (same code, now inside the `ByPid` arm). (h) the client keeps a duplicate of its pipe
handle and re-asks the serving pid right before `OpenProcess` (`pid_to_act_on`: failure or a different pid -> no action).
(i) `read_image_with_retry`: 1024 units, retry once with 32768 on ERROR_INSUFFICIENT_BUFFER.

## Unix reading (no change made)
Socket: `<fuigo_home>/leader*.sock` (lock.rs:86-90, default `~/.fuigo`; `FUIGO_LEADER_SOCKET` can place it anywhere), bound by
`UnixListener::bind` via server.rs:1851 after `remove_file`. The home dir is created with plain `create_dir_all`
(fuigo-dirs/src/lib.rs:117): NO explicit 0700, so its mode follows umask/parent (usually 0755). No `chmod` on the socket (mode
from umask). NO peer-credential check (`SO_PEERCRED`/`getpeereid`): grep over fuigo-shell finds none. FINDING FOR THE OWNER: on
unix the directory is not forced to 0700 and there is no peer check; protection rests on umask/socket-file write bit (Linux
needs write permission to connect; macOS largely ignores it) and on the home directory mode. Not verified by running.

## After the audit
Two hardening notes of the W-pipe audit (`peer_auth.rs`), fixed on `strike/win-p3r2-starter`. Truth table now:
| own account | serving token | pipe owner | verdict |
|---|---|---|---|
| unknown | any | any | Refuse |
| known | readable, equals ours | equals ours | Accept |
| known | readable, equals ours | differs or unreadable | Refuse (new) |
| known | readable, differs | any | Refuse |
| known | unreadable | equals ours | Accept (unchanged) |
| known | unreadable | differs or unreadable | Refuse |
A client stream without an OS handle is now Refuse (was Ok; unreachable today). The only product pipe creation site is
`peer_auth::win::create_secure_server` (owner = current user); the test pipe in `transport.rs` is default-descriptor and
same user. Lane: the red/green pairs `p3r2-pa-red` / `p3r2-pa-g1..3`, and 179 `leader::` tests pass in the whole suite.

## Unverified
Elevated vs non-elevated connect; any real second account; the unix reading is by reading only; Linux/macOS builds not run
(pure tests are cross-platform; the coordinator runs the Linux lanes); a real `fuigo leader kill` against a live Windows leader.
