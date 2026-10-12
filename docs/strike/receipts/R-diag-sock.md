# R-diag-sock: tighten the standalone workspace server diagnostics socket

Branch `strike/diag-sock` (base `hub/strike/integration` 7f3c5972). Owner decision 32.

## Client of the socket (step-0 evidence)
No in-repo client was found. `grep` for `workspace-server.sock`, `diag_socket`, `workspace-server-probe` finds only
the server (`workspace_server.rs`), `DEFAULT_DIAG_SOCKET_PATH` in the diag crate, the 1.0.24 release note, and
`workspace_server_probe.rs`, which does not touch the socket (the probe is a sandbox e2e tool). The sandbox
readiness gate is external to this repo; its uid is unknown (root in the same guest is plausible).

## Changes (`crates/codegen/fuigo-diag-server/src/lib.rs`, unix listener only)
- `bind_unix_private`: temp name in a fresh 0700 dir beside the path, chmod 0600, rename into place (recipe copied
  from `fuigo-shell` `leader/peer_check.rs::bind_private`). The socket is never visible with a wider mode.
- Fail closed: chmod (or rename) failure is a bind error; `EXIT_DIAG_BIND_FAILED` and `DIAG_BIND_FAILED_MARKER` unchanged.
- Pre-existing path: `symlink_metadata`; only a socket owned by the current uid (taken from the owner of our own
  fresh 0700 dir) is replaced. Directory, regular file, symlink, other user's socket: refused, untouched. A stale
  socket of the same user from a crash is replaced by the rename (still works). In sticky `/tmp`, renaming over another
  user's entry fails and is reported as a bind error.
- TCP listener (Windows) and `/ready`, `/statusz`, `/logs` handlers unchanged; `/ready` frozen-contract test untouched.

## `/logs` peer check: NOT added
The client uid is unknown, and a same-uid-or-root check could break a gate running as another uid. Open question
for the owner: which uid does the readiness gate connect as? If it is always root or the server's uid, a
`SO_PEERCRED` (linux) check on the unix listener could be added later.

## Tests (new, `private_bind` module)
mode 0600 at first observation and temp name gone; injected chmod failure returns error, nothing listens, no leftovers;
regular file / directory / symlink refused and untouched; stale own socket replaced.
Not verified: macOS (the recipe is the same one the leader uses there; LOCAL_PEERCRED not involved).

## Round 2

Audit gaps closed (Hetzner lane `diag`, network namespace, loopback only). A test-only seam
(`test_uid_override`, `cfg(test)`) makes our uid look different from the socket owner's.

- `socket_owned_by_another_uid_is_refused_and_untouched`
  - red (uid comparison disabled: `if false && meta.uid() != our_uid`): `socket_owned_by_another_uid_is_refused_and_untouched ... FAILED`, `5 passed; 1 failed`
  - green: `... ok`, `6 passed; 0 failed`
- `symlink_to_our_own_socket_is_refused_and_both_untouched`
  - red (`symlink_metadata` switched to `metadata`): `symlink_to_our_own_socket_is_refused_and_both_untouched ... FAILED`, `5 passed; 1 failed`
  - green: `... ok`, `6 passed; 0 failed`
- Full: `fuigo-diag-server` 27 passed, `fuigo-extra-ca` and `fuigo-auth --test secret_debug_guard` all ok, clippy `fuigo-diag-server --all-targets` no warnings.
- Merged `hub/strike/integration`; release notes keep integration's header and Known limits, entry between them.
