# R-xs-p8b: hardened locator files (packet 8b)

Crate `fuigo-shell`, module `peer_inbox/{mod,dirs,locator,locator_tests}.rs`, one `mod peer_inbox;` line in `lib.rs`.
Inert: no caller outside tests, no socket, no listener. Synchronous blocking I/O: callers must use `spawn_blocking`.

## Functions
- `CheckedDir::open(home)`: never creates anything. `CheckedDir::create_or_open(home)`: the only function that
  creates a directory (`<home>/peers`, mkdirat 0700, fchmod 0700, re-checked through the fd). The home must exist.
- `read_locator(&CheckedDir, name) -> Result<Option<Vec<u8>>, Disabled>`.
- `update_locator(&CheckedDir, name, f)`: strict, refuses on a bad existing file. `update_locator_rewriting`: same,
  but a bad existing file is treated as absent and replaced by `renameat` (never followed or written through).
  Added beyond the plan so "ignored and rewritten" (S3.4) and "refused" (test list) are both available.

## Checks and typed reasons (all `Disabled::...`, no strings from file content)
- Home: absolute, no `.`/`..` (`HomeNotAbsolute`, `HomePathNotNormal`); missing (`HomeMissing`); symlink
  (`SymlinkedHome`); not a dir (`HomeNotDirectory`); owner not us (`HomeWrongOwner`); group/world-writable
  (`HomeWritableByOthers`). The home is never resolved. Deviation: the home needs only "not writable by others",
  not mode 0700, so existing 0755 homes keep working.
- Ancestors: the home's parent path is canonicalised once (so a root-owned `/home` symlink is fine), then walked from
  `/` with no-follow opens; each must be owned by us or root (`AncestorWrongOwner`) and not group/world-writable
  unless sticky (`AncestorWritableByOthers`); also `AncestorMissing/Symlink/NotDirectory`.
- `peers`: `PeersMissing`, `PeersSymlink`, `PeersNotDirectory`, `PeersWrongOwner`, `PeersWrongMode` (exactly 0700).
- Locator file (`Rejected(Reject)`): `Symlink`, `NotRegular` (FIFO, dir), `WrongOwner`, `WrongMode` (exactly 0600),
  `HardLinked` (nlink != 1), `TooLarge` (> 64 KiB, checked from fstat before reading; read capped at 64 KiB + 1).
  Opened `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, relative to the directory fd.
- Lock file `.lock` (`LockRejected(Reject)`): same checks except size; created `O_EXCL` 0600 or opened no-follow;
  blocking `flock(LOCK_EX)`, released by RAII on every path including a panic in `f`.
- Writes: `.tmp-<pid>-<seq>` created `O_EXCL|O_NOFOLLOW` 0600, fsync, `renameat`, directory fsync; temp removed by
  RAII on failure. Output over 64 KiB is `OutputTooLarge`. Names: `InvalidName` (empty, separator, NUL, `.`, `..`,
  `.lock`, `.tmp-*`). Other OS errors: `Io(errno)`. Non-unix: every entry point returns `UnsupportedPlatform`.

## Symlinked home (owner decision 51)
A symlinked home returns `Disabled::SymlinkedHome` from both `open` and `create_or_open`; `reason_text()` gives the
fixed text "peer messaging is unavailable: the Fuigo home is a symbolic link". No panic, no logging, nothing created.
It only makes the peer inbox unavailable. Later packets 8d/8e show this reason in `/peers` and `list_agents`;
nothing else depends on it and nothing else (startup, other features) may change because of it.

## Not covered
- `bind(2)` is path-based: verifying the socket path and stale sockets is packet 8d's job.
- macOS and Windows were not run (Windows compiles to stubs only by design; not built here).
- Ancestor swaps between the walk and use by the same uid are not defended (S3.3 rests on the ownership rule).

## Tests (module `peer_inbox::locator_tests`; counts only, run on Linux as root)
18 tests: symlinked home (with reason text, creates nothing), symlinked peers, symlinked locator, hard link, wrong
file mode, wrong dir mode, FIFO (with timeout), 64 KiB boundary, directory in place of file, ancestor owned by uid
65534 (chown inside the temp dir), world-writable vs sticky ancestor, symlink swap between updates, two threads x 200
appends (400 present), symlinked lock file, panic in `f`, `None` removes, only `create_or_open` creates, invalid names.

## Round 2 (audit `grok-xs-p8b-r1`)

- HIGH fixed: the home check reused the ancestor rule, which excuses a group- or world-writable directory when it
  is sticky. For the HOME that is wrong (another user could create `peers` in it): any group or other write bit on
  the home is now `HomeWritableByOthers`, sticky or not. Test
  `a_group_or_world_writable_home_is_refused_even_when_sticky` (six modes refused, 0755 still accepted).
- Noted, not changed: temp names are `.tmp-<pid>-<seq>` (opened `O_EXCL|O_NOFOLLOW` in a 0700 directory); a
  directory in place of the lock file gives an `Io` reason, not a `LockRejected` one; a directory `fsync` error is
  ignored.
