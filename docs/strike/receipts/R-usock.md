# R-usock: the unix leader socket is private to one account (owner decision Section 31, tighten only)

## Reading (base c98e7546)
- Path: `leader/lock.rs:86-90` (`<fuigo_home>/leader<suffix>.sock`); bound at `leader/server.rs` (`run_leader_server`, was `LeaderListener::bind`), accepted in the `LeaderServerPoll::Accept` arm; unix `LeaderStream/LeaderListener` are tokio aliases (`transport.rs:8-10`).
- Client: the only connect site is `connect_with_retry` (`leader/client.rs`); the first bytes are the `Register` frame in `register()`.
- Other unix sockets: `fuigo-diag-server/src/lib.rs:412` (diagnostics UnixListener, same class, NOT changed); `fuigo-fast-worktree/src/nfs/client.rs:571` (nfs client; server side in another crate, NOT changed); the rest are tests. Reported, not fixed (do not share this code path).
- Root/sudo: `git grep -i 'sudo\|euid\|root'` in `leader/` finds no supported root-to-user flow. `sudo fuigo` in a user's home now gets the neutral refusal (uids differ). No STOP.

## Change
- New `leader/peer_check.rs`. Bind: `bind_private` creates `<parent>/.lXXXX` with mode 0700 (DirBuilder mode), binds `s` inside, chmod 0600, renames over the final path, removes the dir. Nobody else can reach the socket before the rename, so no wider-mode window; no process-wide umask change (threads unaffected). The scratch name is short so the path is never longer than `leader.sock`.
- Checks: `server_accepts` (server.rs Accept arm guard, before any client state or read; drop, nothing sent: the protocol has no refusal frame) and `client_accepts` (client.rs `connect_with_retry`, right after connect, before the Register write). Query = tokio `peer_cred()` (SO_PEERCRED on Linux, getpeereid on macOS/BSD; tokio 1.52.3) in one tiny fn; decision = pure `peer_is_same_user`. Any query error refuses. Windows: stubs accept, no cfg(windows) block touched.
- Client refusal = `ClientError::PeerRefused` (shared with the Windows pipe check after the merge; one message for both) with the neutral message (not a connect-level failure, so no zombie eviction). If W-pipe adds a variant of its own, merge them into one.
- Test seam: `peer_check::seam`, cfg(test), keyed by (side, socket path) so parallel tests do not interact.
- Existing test edit: `server_tests.rs` gained `use crate::leader::transport::LeaderListener;` (the server.rs import went away; no expectation changed).

## Commits (branch strike/usock)
red 9cda1547 (stubs accept everything; T1/T3/T4/T5 fail by assertion, T1: left 511 right 384), fix 44ba1e9e, tidy fac1fbbc (tip).

## Evidence (Hetzner, tip fac1fbbc)
- `peer_check` tests 3 runs exit 0 (T1..T6). Whole `fuigo-shell --lib`: 8263 passed, 0 failed, 10 ignored (about 306 `leader::` tests, incl. the same-uid ones). `fuigo-extra-ca` exit 0 (no re-pin needed). Clippy `--all-targets -p fuigo-shell` exit 0, no warning on added lines.
- Mutations: client check off -> T3 and T5 fail; server check off -> T4 and T5 fail; chmod 0600 off -> T1 fails (left 511, right 384).
- Real-foreign-uid test (setuid 65534 child): skipped, not simple (a child needs the test binary and a mode-0600 socket refuses it before the uid check).

## Unverified
macOS was not built or run (the call is tokio `peer_cred`, the decision function is tested on Linux). No real second account was used; foreign uid is injected. Fuigo home dir mode is untouched (separate question).
