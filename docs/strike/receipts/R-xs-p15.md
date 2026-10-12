# R-xs-p15: Windows peer inbox, packet 15

## 15a: `CheckedDir` on Windows (`peer_inbox/win_dirs.rs`, pure rules in `win_policy.rs`)

Interface (same as unix): `CheckedDir::open(home)`, `create_or_open(home)`, `path()`, `#[cfg(test)] for_test(path)`;
`create_under` returns `Disabled::RuntimeDirUnavailable` (no runtime directory on Windows). Other targets keep the
`UnsupportedPlatform` stub. The unix build is unchanged.

### Rules
1. Path (`parse_home_path`, pure): drive-absolute (`C:\...`), no `.`/`..`/empty parts; refuses UNC, `\\.\`, `\\?\`, `\??\`
   (`HomePathNotNormal`), relative / rooted / drive-relative paths (`HomeNotAbsolute`), `:` (alternate data streams),
   wildcards, control characters, trailing dot or space, reserved device names, paths over 240 characters, a drive root as
   home. A home whose drive is not `DRIVE_FIXED` (`GetDriveTypeW`) is `HomePathNotNormal`.
2. Home and `peers` are opened once with `CreateFileW(BACKUP_SEMANTICS | OPEN_REPARSE_POINT)`; reparse point and
   directory are read from the handle (`GetFileInformationByHandle`): `SymlinkedHome` / `PeersSymlink` /
   `HomeNotDirectory` / `PeersNotDirectory`. The two handles are kept in the struct with share mode READ|WRITE (no
   `FILE_SHARE_DELETE`): the directories cannot be renamed or replaced while the struct lives. Every ancestor from the
   drive root down is opened, must be a directory and not a reparse point (`AncestorSymlink`).
3. Owner (from the handle, `GetSecurityInfo`): our user SID (`EqualSid`), or BUILTIN\Administrators when the process
   token is elevated and the group is enabled and not deny-only. Reason: a directory created by an elevated
   administrator is owned by the Administrators group by default. Else `HomeWrongOwner` / `PeersWrongOwner`.
4. DACL (from the handle). Writer rule for home: refuse (`HomeWritableByOthers`) if the DACL is NULL, or if any
   access-allowed ACE that applies to the object (not inherit-only) grants FILE_WRITE_DATA / ADD_FILE, FILE_APPEND_DATA /
   ADD_SUBDIRECTORY, FILE_WRITE_EA, FILE_WRITE_ATTRIBUTES, FILE_DELETE_CHILD, DELETE, WRITE_DAC, WRITE_OWNER,
   GENERIC_WRITE or GENERIC_ALL to a principal other than our SID, SYSTEM (S-1-5-18) or BUILTIN\Administrators
   (S-1-5-32-544). Deny ACEs (types 1, 6, 10, 12) are ignored. Any other non-plain-allow type (object, callback,
   compound, unknown) refuses. A trustee that cannot be rendered counts as a stranger. SYSTEM and Administrators are
   allowed because every default profile directory grants them full control and both can take ownership anyway (coordinator
   decision, recorded here against owner decision 65, "no write/delete ACE for any other principal").
   Ancestor rule (`AncestorWritableByOthers`): the same principals are trusted; a stranger with FILE_DELETE_CHILD,
   WRITE_DAC, WRITE_OWNER, GENERIC_ALL or GENERIC_WRITE on an ancestor refuses, and DELETE also refuses on the direct
   parent of the home. `Authenticated Users` with add-subdirectory on a drive root (Windows default) is accepted: it cannot
   replace an existing directory it does not own. Table-driven test over the default ACLs of `C:\`, `C:\Users` and a profile.
5. `create_or_open`: a missing `peers` is created with `CreateDirectoryW` and a PROTECTED DACL (`D:P(A;OICI;FA;;;<our SID>)`,
   built by `PipeSecurity::from_sddl`, no inheritance from the home; the entry is inherited by files created inside),
   then opened and checked like an existing one. `peers` is STRICT (`PeersWrongMode`): DACL protected, we hold full
   control, and NO other principal (not SYSTEM, not Administrators, not even an inherit-only ACE, which would reach files
   created inside) has any allow ACE. The ACL of an existing directory is never changed.
6. Every Win32 failure is `Disabled::Io(code)`; handles are closed on drop; nothing is logged or built from file content.

A volume without ACL support (`FILE_PERSISTENT_ACLS` absent from `GetVolumeInformationByHandleW`: FAT, exFAT) is refused
with `HomeWritableByOthers`.

### Not checked (stated limits)
- SACL and mandatory integrity labels.
- Effective access through group membership of our own token (the DACL is judged by trustee SID, not by evaluating access for each principal).
- Files inside `peers` (15b).
- Alternate data streams on the directories themselves (`:` is refused in the path, nothing else is looked at).
- The owner of ancestors (only their DACL and reparse status).
- A DACL with more than 16 ACEs (the shared reader of `win_pipe.rs` refuses it: `Io(0)`).
- Races on ancestors are closed by the open home handle (an open handle below a directory blocks its rename), not by holding every ancestor.

### Reuse and changes elsewhere
`win_pipe.rs`: `mod sys` is now `pub(super)` and `sys::read_owner_dacl` is `pub(in crate::peer_inbox)` (no behaviour change).
Reused: `auth::{code, Owned, sid_to_string, token_info_buf, PipeSecurity}`, `RawAce`, `dacl_summary_from_binary`,
`is_sid_text`. `Cargo.toml`: no change (all `windows` features already enabled).

### Tests
- Pure (Linux and Windows), `win_policy::dir_tests`: writer rule, peers rule, ancestor table of default ACLs (`C:\`, `C:\Users`, profile), path rules, handle facts, summary round trip.
- Native Windows (`win_dirs::tests`, files only, no pipe, no Fuigo binary): owner-only home accepted and `peers` created, re-opened, and not renameable while held; default-profile-like home; `Users:(M)` home refused; read-only and inherit-only strangers accepted; extra access or unprotected `peers` refused; missing / not-a-directory; ancestor rules below the test root; junction (`mklink /J`) and symlink as home or ancestor refused (symlink skipped with a message if the account lacks the privilege); relative, `..`, UNC, `\\?\`, `\\.\` refused.
- Finding on this desktop: the machine's temp root (`F:\Temp`, `F:\Temp\Codex`) grants Authenticated Users Modify (including FILE_DELETE_CHILD) and another account Modify. The ancestor rule correctly refuses any home below it. The native tests therefore trust the ancestors at and above their temp root for the DACL check only (`open_inner(.., dacl_from)`, production passes 0) and still enforce reparse/directory checks everywhere and the DACL rule below the root.

## 15b: Windows locator file (`hosts.json`)

Code: `peer_inbox/win_locator.rs` (new, `cfg(windows)`), `peer_inbox/rows.rs` (new: `LOCATOR_NAME`, `encode_rows`,
`decode_rows`, re-exported from `reap.rs`), pure policy `locator_owner_ok` / `locator_dacl_ok` appended to `win_policy.rs`
(tested on Linux too), non-unix stubs in `locator.rs` (Windows delegates, other targets keep `UnsupportedPlatform`),
minimal Windows `CheckedDir` shape in `dirs.rs` (`path()`, `for_test`; 15a replaces it). Reused: `win_pipe::sys::owner_and_dacl`
(made `pub(in peer_inbox)`, module `sys` made `pub(super)`; behaviour untouched), `peer_auth::win::{own_sid, PipeSecurity, Owned,
token_info_buf}`. Cargo: `windows` feature `Win32_System_IO` added to `fuigo-shell` (needed by `LockFileEx`); no new crate version.

Rules.
1. Names: unix rules plus `:` (streams), `\`, `<>"|?*`, control characters, trailing dot or space, Windows device names
   (CON PRN AUX NUL CONIN$ CONOUT$ COM0-9 LPT0-9, also with an extension), `.lock` and `.tmp-*` compared case-insensitively.
2. Every open is `CreateFileW(<checked dir path>\<name>)` with `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS`
   (the latter only so a directory can be opened and classified). On the HANDLE: reparse point -> `Symlink`; directory or not a
   disk file -> `NotRegular`; `nNumberOfLinks != 1` -> `HardLinked`; size over 64 KiB -> `TooLarge`; owner not our SID
   (BUILTIN\Administrators accepted only when our token is elevated) -> `WrongOwner`; any DACL ACE that is not a plain allow
   for us, SYSTEM or BUILTIN\Administrators (a NULL DACL, a deny, or any other trustee, e.g. `Users`) -> `WrongMode`.
   New files (lock, temp, locator via the temp) are created with an explicit descriptor `O:<us>D:P(A;;GA;;;<us>)`: protected,
   nothing inherited, one ACE.
3. Lock: `.lock` opened with `OPEN_ALWAYS` (same checks, failure -> `LockRejected`), then `LockFileEx(EXCLUSIVE | FAIL_IMMEDIATELY)`
   on byte 0, retried every 10 ms for at most 2 s -> `LockBusy`. A drop guard unlocks and closes on every path.
4. Update: under the lock read the current bytes (missing = `None`), call `f`, refuse over-cap output (`OutputTooLarge`),
   create `.tmp-<pid>-<seq>` (`CREATE_NEW`, owner-only DACL, share mode 0), write, `FlushFileBuffers`, close, then
   `MoveFileExW(temp, locator, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`. `f` returning `None` deletes the file
   (`DeleteFileW`, which removes a link, never its target).
5. Errors: every Win32 failure is `Disabled::Io(code)`; handles are `OwnedHandle` (closed on every path); no content is parsed
   before the checks, nothing is logged.

`update_locator_rewriting`: as on unix, a present file that fails its checks is treated as absent (`f` gets `None`) and the entry
NAME is replaced by the move. On Windows that replaces a reparse-point name (the link, never its target), a hard-linked name (the
other link keeps its content), or a file with a wrong owner or DACL. A directory cannot be replaced: `Io(ERROR_ACCESS_DENIED)`.

Share modes. Plain read: `READ | WRITE | DELETE`, so a replace can proceed while a reader has the old file open and the reader
sees the old content whole. The read inside an update (writer holding the lock) is `READ` only, closed before the replace.
Lock file: `READ | WRITE` (others must open it to wait). Temp file: share 0 while it is written.

Crash between write and replace: the locator is untouched (still the old, complete file); a stray `.tmp-<pid>-<seq>` stays (owner-only,
never read, the name is refused as a locator name). Nothing removes it yet; a later cleaning pass may. A crash during the replace is
the file system's atomic rename: old or new, never partial. A crash while holding the lock releases it with the handle.

Limits. An antivirus scanner or indexer holding the file without `FILE_SHARE_DELETE` makes open, delete or replace fail with a
sharing violation, lock violation or access denied: retried every 5 ms for up to 750 ms, then `Io(code)` (a failed replace removes
the temp file). `LockFileEx` is not reliable across network shares and SMB redirectors: the home must be on a fixed local volume
(checked by 15a). NTFS is assumed (hard link count, ACLs); on a volume without ACLs the owner and DACL read fails -> `Io`.

## 15c: the peer inbox works on Windows (`peer_inbox/win_inbox.rs`, `win_logic.rs`, `win_watch.rs`)

`PeerInbox` on Windows (`#[cfg(windows)] pub(crate) use win_inbox::{PeerInbox, StartOptions}`) has the unix method names:
`start`, `start_with`, `start_inner(home, opts, host_id)`, `host_id`, `directory`, `row`, `peers_dir`, `reap`, `reap_stale`,
`shutdown`, `Drop`; plus `pipe_name`, `other_hosts(cap)`, `dial(host, op)`, `locator_problem()`. `host.rs` needed no per-call
cfg (it only had its test-only `force` option widened from `unix` to `unix or windows`). The uninhabited stub remains only for
targets that are neither unix nor windows.

### Start order (every failure undoes what came before it)

a. flag off -> `Disabled::FeatureOff` before any OS call, thread or task.
b. `CheckedDir::create_or_open(home)` in `spawn_blocking` (the 15a home rules, typed `Disabled`), then the leftover-temp sweep
   (item 8 below).
c. a process whose token carries the NETWORK group (a network logon, for example ssh) -> `Disabled::NetworkLogon`, text
   "peer messaging is unavailable in a remote (network) logon session" (decision 56: the pipe policy refuses remote clients,
   so such a process could never be reached; it says so instead of starting a useless inbox). Then mint a host id and start
   `WinPeerInbox` (pipe policy unchanged); `WinUnavailable` maps to `Disabled` in ONE function (`win_logic::disabled_of`).
d. ONE bounded reap pass by dial (`REAP_BUDGET` 5 s) BEFORE our row is written.
e. publish our row with `update_locator_rewriting` (our older row of the same id replaced; a locator already holding
   `MAX_ROWS` rows of others -> `Disabled::LocatorFull`, not terminal, retried by `host.rs` as on unix). A `RowGuard` exists
   before the blocking publish starts: a start dropped meanwhile removes the row the publish writes.
f. the notice pump and the once-a-minute watch ticker (`win_watch.rs`).
g. `shutdown`: announce `exited` (bounded 3 s), stop pump and ticker, stop the pipe, remove OUR row only. `Drop`: the same
   without awaiting (row removal handed to a blocking thread). Idempotent. A cancelled start leaves no row (the guard) and no
   pipe (the dropped `WinPeerInbox`).

`Disabled` variants added, each with a FIXED text and never text from the OS: `IdentityUnreadable` ("this user account could
not be read"), `PipeNameInUse` ("the inbox pipe name is already in use"), `PipeCreateFailed` ("the inbox pipe could not be
created"), `PipeCheckFailed` ("the inbox pipe failed its safety checks"), `NetworkLogon` (above). `WinUnavailable` gained
`NetworkLogon` with the same text.

### Reap rule (no file exists to unlink)

A row is removed only when TWO tries, `TRY_GAP` (1 s) apart, BOTH say the pipe does not exist (`ERROR_FILE_NOT_FOUND` on open,
`WinDialError::NoServer`). `win_logic::win_reap_decision(first, second)` is that rule and nothing else; every other pair keeps
the row: pipe busy (`Timeout` after the 2 s connect deadline), access denied or any other error (`Other`), a refusal by policy,
a version mismatch, a timeout, a hello of any host. A try is a `List` dial (the server must announce the row's host id). Removal
is `update_locator` with `without_exact`: the row goes only if it is still present unchanged (host id, pid, start marker, dir
all equal to the row read). Bounds as unix: `MAX_PROBES` 8 at once, `PROBE_CAP` 3 s each, `REAP_BUDGET` 5 s per pass, second
tries only for rows whose first try found no pipe, condemned rows removed in batches as their second tries finish.

### Dial mapping (ONE function, `win_logic::classify`, table-tested on every OS)

| `WinDialError` | class | reap try | send outcome |
|---|---|---|---|
| `NoServer` | `Gone` | `NoSuchFile` | `Rejected(Unavailable)` |
| `Timeout` | `Timeout` | `Timeout` | `Rejected(Unavailable)` |
| `VersionMismatch` | `VersionMismatch` | `VersionMismatch` | `Rejected(Unavailable)` |
| `IdentityUnreadable`, `NotAPipe`, `WrongServer(_)`, `ForeignHello`, `Other` | `Unavailable` | `Other` | `Rejected(Unavailable)` |

`tool_host.rs`: `deliver_local` is ungated for Windows; `other_hosts`, `remote_rows`, `remote_send` are real on Windows. The
unix and Windows paths share one body (`remote_rows`, `remote_send`) over a per-platform `dial_row`; the bounds are the unix
ones (`REMOTE_ONE` 1 s per host, `REMOTE_LIST_TOTAL` 3 s, `REMOTE_SEND` 5 s). A rejected or garbage locator gives no rows
(`other_hosts`), and the typed reason is kept in `PeerInbox::locator_problem()`; nothing panics.

### Shared with unix, duplicated

Shared (one copy): the decision code of the watch (`watch::probe_pass`, `WatchTable`, `Prober`, `Probe`), the row format
(`rows.rs`), the connection/exchange code (`conn`), the directory, the tool code above, `Disabled`. Duplicated on purpose:
`win_watch.rs` (pump, `deliver`, ticker, prober) is a copy of `watch::io` with the pipe dial in place of the socket dial and no
`Locations`: making the unix module generic would have touched the unix tests' call signatures (more than the ~120 lines
allowed), and unix behaviour had to stay byte-identical. `win_inbox::reap_pass` mirrors `reap::reap_pass` (different decision,
no socket unlink, no runtime-dir branch). `WinDialError` moved from `win_pipe.rs` to `win_policy.rs` (re-exported from
`win_pipe`) so the mapping can be tested on Linux; no logic changed.

### Item 8: leftover temp files

`win_locator::sweep_stale_temps(dir, 10 min, 64)` runs at start under the locator lock: only entries named `.tmp-*`, plain files
whose last write is older than 10 minutes, that open with full sharing (a file someone still holds is skipped) and pass the
handle checks (one link, owner us, DACL for nobody else), at most 64 removed; a link or anything not ours is left. Unix unchanged.

### Tests

A (every OS, `win_logic::tests`): dial table, reap decision over all 7x7 try pairs, `WinUnavailable` -> `Disabled` with equal
texts, row add/replace/full, remove own / exact / others on byte buffers. B (Windows, file-only, `win_inbox::tests`): rows of
others from a locator, our row added and removed, full locator, rejected locator (a directory), garbage locator, temp sweep with
bounds. C (Windows, real pipes, `win_inbox::pipe_tests`, BATCH logon only): start/row/pipe/shutdown, status through `PeerHost`,
list + send + watch notice between two inboxes in one home, reap after two tries and not after one (and a live host never),
start-time reap, flag off, cancelled start.

### Stated limits

- A network-logon session (ssh, `WNetAddConnection`) cannot use peer messaging: `NetworkLogon`, by decision 56 unchanged.
- The pipe name derives from the host id and the user SID: a host id alone is enough to dial, and a row only says which ids exist.
- No runtime-directory branch on Windows: rows are always `dir: home`; `CheckedDir::create_under` stays unavailable.
- The locator lock is advisory against other programs of the same user (`LockFileEx` on `.lock`; a program that ignores it can
  still replace `hosts.json`, subject to the file's own owner-only DACL).
- A reap try is a `List` request, not a bare hello (the 15b/10 pipe code exposes only whole exchanges).
- The unavailable reason of a rejected locator is exposed by `locator_problem()` but not yet shown by `/peers status`.

## 15d: two real processes on Windows, and the Windows documentation

Tests and documentation only. No product source changed. Added: `crates/codegen/fuigo-shell/tests/win_peer_two_process.rs`
(`cfg(windows)`, one `#[ignore]` test), the helper binary `src/bin/p15d-stdio-agent.rs` (`required-features = ["test-support"]`, a
`[[bin]]` entry in `Cargo.toml`; `main` builds a default `Config` with local titles and calls the real `run_stdio_agent`).

### Variant built: the ACP stdio variant, with real processes

The in-process ACP harness (`tests/acp_harness`) cannot give two host ids (one process has one `PeerHost`), and the production
binary is built by another crate (`fuigo-pager-bin`), so a `fuigo-shell` test has no `CARGO_BIN_EXE_` for it. The helper bin runs
the same entry point the production `fuigo agent stdio` command runs (`run_stdio_agent`: `arm_peer_host`, the registry, the
session actors, the inbox) as a separate process, and the test is its ACP client over stdin/stdout, so the model tool call
(`send_message`) and the `fuigo/peer/*` (the wire adds the underscore) surface are exercised. Each process has its own mock model endpoint on 127.0.0.1 (fake key),
its own `HOME`/`USERPROFILE`, and shares one fresh `FUIGO_HOME` that the test creates under the current user's temp directory
(`tempfile` in `%TEMP%`), with `FUIGO_PEER_MESSAGING=1`. Children are killed by their own handle (`kill_on_drop` and a drop guard);
the whole test has a 15 minute bound; every wait is bounded.

### What it asserts

1. Both sessions `configure {optIn:true, operator:"attended"}`; two different host ids; A lists B and B lists A; `hosts.json` has both.
2. Same mode: A's scripted model calls `send_message`; the tool result says `Delivered`; B's next model request holds the marker inside a
   `cross-session-message`.
3. B set to yolo (the `fuigo/yolo_mode_changed` client notification; `session/set_mode` plan only goes pending until the next turn and does not change the compared mode); A sends again: tool result `Held for the receiver...`; B gets a `peer_held` event;
   `list_held` shows one row with a token; the marker is not in B's requests.
4. `release {action:"release"}` answers `delivered`; the second marker reaches B's model.
5. Third send held; `release {action:"refuse"}` answers `refused`; the marker never reaches B's model; A's model is shown the notice
   "was held and then refused" (on A's next turn if it did not arrive on its own).
6. B is killed: A stops listing B within 30 s. The row stays in `hosts.json` until a reap: reaps run at the start of an inbox (15c,
   start order step d), not on a timer, so the test starts a third process C and asserts B's row is gone (two tries) and A's row is kept.

### What it does not cover

The production `fuigo` binary and its full config loading (the helper uses a default config); the terminal UI and `/peers`; a
second user account; the network-logon refusal (see 15c and the packet 10 evidence); antivirus or locking interference; a crash of A.

### How to run

On the Windows test box, from a batch or interactive logon (never ssh):

```text
cargo test --locked -p fuigo-shell --features test-support --test win_peer_two_process -- --ignored --nocapture --test-threads=1
```

Output lines: `P15D-EVIDENCE <step> PASS|FAIL <detail>`.

### Documentation changes

`crates/codegen/fuigo-pager/docs/user-guide/28-named-sessions.md`: Platforms (Windows supported, named pipe, local fixed NTFS-style
volume, owned by you); Limits (the "unavailable on Windows" sentence removed; network logon, ownership and write access rule, less
testing); Troubleshooting rows for the five Windows reasons exactly as printed (pipe name in use, pipe could not be created, pipe
failed its safety checks, user account could not be read, remote (network) logon) and the Windows remedy for "not private to this
user". `docs/release-notes-1.0.25.md`: the "not available on Windows" line replaced by the working-with-limits line. Not touched:
`release-notes-1.0.24.md`, `.github/workflows/`.

### Result on the Windows test box

Batch logon as `p15user` (`NT AUTHORITY\BATCH`, not NETWORK), commit `1290da51`, run `p15d-two4`:
`test result: ok. 1 passed; 0 failed; 0 ignored; finished in 37.52s`. Two earlier runs failed on the test's own set-up (main-thread
stack of the helper, then the ext method name with the wire underscore; and the plan-mode set-up above) and were fixed in the test
and helper, not in product code. No product fault was found.


### Live default ACLs observed on the test box (Windows Server 2022, normal user), coordinator, from the round-1 probe
All three pass the ancestor rule (`ok=true`). Format: `(ace type; ace flags; access mask; trustee)`; SY = SYSTEM, BA =
Administrators, BU = Users, WD = Everyone, CO = CREATOR OWNER; flags 0x8 = inherit-only.
- `C:\`: `(0;0x3;0x1f01ff;SY)(0;0x3;0x1f01ff;BA)(0;0x3;0x1200a9;BU)(0;0x2;0x4;BU)(0;0xa;0x2;BU)(0;0xb;0x10000000;CO)`:
  Users may read, and create folders on the drive root (0x4, applies to the object); no stranger has DELETE,
  DELETE_CHILD, WRITE_DAC, WRITE_OWNER or a generic write on the object itself.
- `C:\Users`: `(0;0x3;0x1f01ff;SY)(0;0x3;0x1f01ff;BA)(0;0x0;0x1200a9;BU)(0;0xb;0xa0000000;BU)(0;0x0;0x1200a9;WD)(0;0xb;0xa0000000;WD)`:
  read and execute for Users and Everyone on the object; their generic entries are inherit-only.
- the profile directory: `(0;0x3;0x1f01ff;SY)(0;0x3;0x1f01ff;BA)(0;0x3;0x1f01ff;<the user>)`.
The probe test that printed these was removed; `live_default_acls_pass_the_ancestor_rule` stays and asserts acceptance.

### After the focused audit (round 2, LAND-OK)
Stated, not changed: `acquire_lock` can leave a created `.lock` file behind when its check fails; a `Drop` without a runtime is
bounded by the 2 s lock wait plus two 750 ms sharing retries; the 15d helper binary `p15d-stdio-agent` exists only with the
`test-support` feature, is not shipped, and does not install the managed pin; reaping on Windows happens at an inbox start,
not on a timer; the pinned-ancestor test accepts error 5 or 32 for the blocked rename.
