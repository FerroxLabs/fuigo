# R-1027 b27-1b MCP-WIN: `bearer_token_file` on Windows

Base 103cf933 (b27-1a). Branch `strike/b27-1b`.

## What changed
- `fuigo-mcp/src/bearer_token_file.rs`: Windows `read_checked_bytes` (open, judge the open handle with
  `fuigo_win_acl::check_owner_only_file_capped(&file, Some(16 KiB))`, then the same bounded `take(MAX+1)` read as unix; the bounded read
  is now the shared `read_bounded`). `BearerTokenPath::parse` no longer refuses Windows. `UnsupportedPlatform` remains for
  `not(any(unix, windows))`. New: `refusal_text(error, path)`, `BearerTokenFile::refusal_text`, `preflight(path)`.
- `fuigo-mcp/src/bearer_token_file_windows.rs` (new): pure path rules (all OSes) and the Windows opener.
- `fuigo-config-types/src/mcp.rs`: after parsing the path, `preflight` runs; a refusal skips that server with
  "MCP server `x` skipped: <text>" (on Windows the text carries the configured path and the fix).
- `fuigo-mcp/src/mcp_http_client.rs`: the per-request failure (log line and the error returned) uses `refusal_text`.
- `fuigo-win-acl`: `owner_only_sddl` moved here from `fuigo-shell` (shell re-exports it, same name); new feature `test-support`
  with `test_support.rs` (create a file or folder WITH a given DACL). The checker itself is untouched: no rule forked or weakened.
- Dependencies: `fuigo-win-acl` as a `cfg(windows)` dependency of `fuigo-mcp` (and a `test-support` dev-dependency of `fuigo-mcp` and
  `fuigo-shell`); it depends only on `windows`, so no cycle. Cargo.lock: one line.
- Docs: user guide `07-mcp-servers.md` (Windows rule, `icacls` fix), `docs/release-notes-1.0.27.md` (added with the skeleton headings
  of the version-bump commit 76ad5f05 on `strike/b27-0`; this branch does not contain that commit, so expect an add/add merge on that file).

## Open flags and share mode
`OpenOptions::read(true)`, `custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)`, `share_mode(READ | WRITE | DELETE)`. No
`FILE_FLAG_BACKUP_SEMANTICS`.
- OPEN_REPARSE_POINT: a symlink or junction in the FINAL component is opened as itself, so the checker sees the reparse attribute and
  refuses (it does not follow). Intermediate directory links are followed, as on unix (`O_NOFOLLOW` covers the last component only).
- Share READ|WRITE|DELETE: a rotating program can overwrite, rename over or delete the file while we hold it for one read. A stricter
  mode would turn a rotation into a sharing violation. No safety cost: judging and reading use the one handle.
- No backup semantics: a directory cannot be opened (access denied); the opener then looks the path up (`symlink_metadata`) only to
  say `NotRegular` instead of `Unreadable`. Both refuse.

## Refusal to error mapping
| checker result | `BearerTokenFileError` | Windows warning text |
|---|---|---|
| `OtherPrincipals` (extra or inherited ACE, NULL DACL) | `TooPermissive` (text differs per OS) | "... accessible to users other than you, SYSTEM and Administrators: remove access for other users from <path>" |
| `ReparsePoint` | `Symlink` ("is a symbolic link"; also junctions) | "...: <path>" |
| `NotRegular` / directory | `NotRegular` | "...: <path>" |
| `MultipleLinks` | `MultipleLinks` (new) | "bearer_token_file has more than one hard link: <path>" |
| `TooLarge` | `TooLarge` | "...: <path>" |
| `WrongOwner` | `WrongOwner` | "...: <path>" |
| `Io(code)`, open failure | `Unreadable` | "...: <path>" |
New variant `UnsupportedPath` (path rules below). Unix texts are unchanged except `UnsupportedPlatform` ("... on this platform" instead of
"... on Windows in this release"). Errors carry no payload; the path is added by `refusal_text` from the configured value (never file
content). `preflight` treats `Unreadable` (missing file) as no refusal, so a file a rotating agent creates later still works.

## Device, pipe, UNC, directory, stream behaviour
Refused by `path_problem` before anything is opened (`BearerTokenPath::parse`, both `\` and `/`): any path starting with two separators
(`\\.\pipe\x`, `\\.\NUL`, `\\?\...`, `\\server\share\x`), any component that is a device name (CON, PRN, AUX, NUL, COM1-9, LPT1-9, CONIN$,
CONOUT$, with or without extension, any folder), any `:` other than the drive colon (file streams). Reason: opening a pipe would connect to
its server; a UNC path authenticates to a host and can stall. Defence in depth if such a path reaches the opener anyway: nothing is read
until the checker accepts `FILE_TYPE_DISK`; a pipe/char device fails it; opening never waits. Tested: `\\.\NUL` is refused, a pipe
path with no server is `Unreadable`, both at once. A directory is `NotRegular`. Mapped network drives (`Z:`) are local-looking paths and
are judged by the same ACL rule (and the existing 5 s read timeout applies).

## Tests
- `fuigo-mcp` `bearer_token_file_win_tests.rs` (Windows): owner-only accepted (LF, CRLF, none); folder granting only us accepted;
  extra ACE for Users, Everyone, Authenticated Users refused with fix and path, no content; ACE inherited from the folder refused; 16 KiB
  limit; directory; second hard link (both names); symlink (skips cleanly if the privilege is missing; see below); content rules; missing
  file; path rules (device, pipe, UNC, stream, reserved names, relative); device that skips parse; `preflight`; rotation by rewrite and by
  rename-over, then a shared file refused on the next request, then a vanished file; Debug/scrubber. Pure `path_problem` tests run on every OS.
- `fuigo-shell` `util/config/mcp_bearer_file_tests.rs`: the four tests that were `#[cfg(unix)]` now run on every OS (`FILE` is a per-OS fake
  path; the templated config text uses a placeholder); `on_windows_a_server_that_sets_it_is_skipped` replaced by module `windows_files`:
  owner-only keeps its server with the path carried unchanged; shared, inherited-shared and device-path servers are skipped (that server
  only; the good one and a not-yet-existing file start), note names path and fix, never the content.
- How files are made owner-only: `fuigo_win_acl::test_support` creates them with `CreateFileW` and an SDDL descriptor
  (`owner_only_sddl`: owner us, protected DACL, one ACE for us) at creation. No `icacls`. Inheritance case: a folder created with a
  protected DACL holding inheritable ACEs for us and `BU`; a file created inside with default security inherits both.

## Counts
Linux (build box, lane b27-1b, `slot-run.sh`, no network): `-p fuigo-mcp -p fuigo-win-acl -p fuigo-config-types -p fuigo-config`
866 passed, 0 failed, 3 ignored; `-p fuigo-shell --lib bearer_file_tests` 15 passed (the 4 un-gated tests included); `-p fuigo-extra-ca
-p fuigo-auth` 91 passed (Debug-secret guard intact); clippy `--locked -p fuigo-mcp -p fuigo-win-acl --all-targets`: no warning in these
crates (one `collapsible_if` of mine was fixed).
Windows (native, non-elevated user, USERPROFILE redirected by run.ps1, `--skip pipe_tests`): `check --locked -p fuigo-win-acl -p fuigo-mcp
-p fuigo-shell --lib --tests` exit 0; nextest `-p fuigo-mcp -p fuigo-win-acl -- bearer owner_rule dacl_rule sid_text_check` 20 passed, 0
failed (17 `bearer` + 3 win-acl policy tests; the symlink test did create a symlink here and ran, no skip message); nextest `-p fuigo-shell
--lib -- bearer_file_tests` 17 passed, 0 failed. (A first shell run with filter `mcp_bearer` matched one unrelated test only; the module is
`util::config::mcp::bearer_file_tests`.)

## Limits, not verified
- Non-elevated user only: the "owner is BUILTIN\Administrators when the token is elevated" arm and an elevated session's files were not
  exercised on Windows (pure policy tests cover the rule).
- No test for a file owned by another user (needs a second account) and none for a UNC/network share target or a mapped network drive.
- Only the final path component is protected against links; a junction or symlink in a parent folder is followed (same as unix).
- `Symlink` is the error for any reparse point, so a junction reads "is a symbolic link".
- A file on a filesystem without ACLs (FAT/exFAT) cannot be judged and is `Unreadable` per request; the load-time check lets it through.
- The load-time check is a snapshot; every request checks again.
- Other `fuigo-mcp` Windows tests were not run (filter kept to `bearer`).

## Round 2 (tighten-only)
- Mapped network drives: `fuigo_win_acl::drive_is_remote(root)` (`sys.rs`, `GetDriveTypeW`, true only for DRIVE_REMOTE; not an ACL rule, checker untouched; feature `Win32_Storage_FileSystem` already enabled). `bearer_token_file_windows.rs` has the pure `drive_root` (`X:\` from a path, tested on every OS). A remote drive returns `UnsupportedPath` before any open. DRIVE_NO_ROOT_DIR / unknown are not refused: the normal open fails as before.
- Single enforcement point: Windows `open_checked` in `bearer_token_file_windows.rs` now runs `path_problem` and the remote-drive refusal itself, then `open_judged`. `preflight`, `read_token_sync`/`read_checked_bytes` and so every per-request read all open only through it; `BearerTokenPath::parse` keeps its own early `path_problem` for load-time messages. `open_judged` (open + checker, no path rules) is test-only reachable.
- Preflight bound: `preflight_within(bound, judge)` runs the open+check on a std thread and waits `recv_timeout(TOKEN_READ_TIMEOUT)`; the caller (sync config load) is held at most 5 s. Timeout, thread-spawn failure and `Unreadable` are "not judged now": server not skipped, every request re-checks with its own bound. Tested with an injected slow closure and a 50 ms bound (all platforms).
- Tests: device test asserts `Unreadable` for both the NUL device and a pipe with no server through `open_judged`; new Windows test that `read_token_sync` and `open_checked` refuse `\\.\NUL`, a pipe path, `...\NUL`, `com1.txt`, UNC and stream paths with `UnsupportedPath`; symlink test skip now prints "skipped: cannot create symlinks without the privilege".
- `fuigo-shell` `peer_inbox/win_pipe.rs`: removed the imports the ACE reader move left unused.
- Docs: guide and release notes made exact (network locations and mapped drives; folder link to a network location not detected; hard link limit; ownership wording).
- Counts (round 2): Linux `-p fuigo-mcp -p fuigo-win-acl -p fuigo-config-types -p fuigo-config` 869 passed, 0 failed; `-p fuigo-shell --lib bearer_file` 15 passed; `-p fuigo-extra-ca -p fuigo-auth` all passed; clippy clean in touched crates. Windows: `check --locked -p fuigo-win-acl -p fuigo-mcp -p fuigo-shell --lib --tests` exit 0; nextest fuigo-mcp + fuigo-win-acl (`bearer drive preflight`) 22 passed, 0 failed; nextest fuigo-shell lib (`bearer_file peer_inbox`) 125 passed, 0 failed (`--skip pipe_tests`). Not tested: a real mapped network drive.
