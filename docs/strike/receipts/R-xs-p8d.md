# R-xs-p8d: unix inbox, dialer, session directory, reaping (packet 8d)

Crate `fuigo-shell`, `src/peer_inbox/{inbox,dial,directory,reap}.rs` plus `inbox_tests.rs`, `uid_tests.rs`.
INERT: nothing outside the tests calls `PeerInbox::start` (that is 8e); every module is
`cfg_attr(not(test), allow(dead_code))`; a socket is opened only by tests. Non-unix: `PeerInbox::start` returns
`Disabled::UnsupportedPlatform`, no listener, no dialer.

## What is built
- `PeerInbox::start(home)` / `start_with(home, StartOptions{enabled, runtime_dir})`: flag off returns
  `Disabled::FeatureOff` before any filesystem call, thread or task. Else `CheckedDir::create_or_open` (symlinked home =
  `SymlinkedHome`, nothing created), host id (32 hex from `rand`), `choose_dir`, the socket path must not exist
  (`SocketPathExists`, fail closed), `bind_private_with` (0700 scratch dir, bind, 0600, rename), `lstat` through the
  directory fd (socket, ours, mode 0600), our row via `update_locator_rewriting`, accept loop. Drop and `shutdown()` stop
  accepting, unlink our socket only if `lstat` still shows a socket owned by us, and remove our row under the lock.
- Runtime directory (S3.5, owner decision 51): `$XDG_RUNTIME_DIR/fuigo/<16 hex FNV-1a of the home path>/peers`, created
  0700 and checked by the same `CheckedDir` code (that directory plays the part of the "home"). `fuigo-peer`'s
  `RUNTIME_SUFFIX_LEN` does not know the hash level, so the length given to `choose_dir` is the runtime length + 17.
- Accept loop: 32 permits. The 33rd connection is ACCEPTED AND CLOSED AT ONCE, unread (waiting would pile unread
  connections in the kernel backlog and make the dialer sit out its 10 s deadline). `verdict_for(Side::Server)` runs
  before the first read; then `conn::serve_one` (10 s exchange deadline, host call inside it) in one task per
  connection; the permit is released on unwind, so a panicking task never takes the loop down.
- `PeerDirectory`: session id -> (incarnation, `MessageDeliveryHandle`, name, ref). `register` raises a per-id counter that
  survives `unregister`; `list_page` gives 64-row pages. `ConnHost` (per connection) implements `InboxHost`: `send`
  refuses unless `to.host_id` is ours and the incarnation is current, and `envelope.from` host id equals the hello host
  id (consistency check, not a security claim); then it calls `deliver_peer_message` and nothing else.
  `notice` goes to an optional sink the host sets in 8e. There is NO notice entry in the session yet, so without a
  sink a notice is acknowledged and dropped.
- `dial(loc, our, host_id, dir, op)`: path only from `socket_path`, connect 2 s, `verdict_for(Side::Client)` before
  the first write, then `conn::exchange`. `DialError::try_result()` maps onto `TryResult`; `try_hello` (a hello-only
  probe) keeps the announced host id for the reaper.
- Reaping (`reap_pass`): `reap_decision` only; the second try (1 s later) is made only when the first could condemn the
  row; the row goes only if unchanged under the lock (`remove_row`); `<id>.sock` is unlinked in the same critical section
  only if `lstat` shows a socket owned by us. The pid is never read.
- Item 7: `peers` removed from `FUIGO_HOME_LISTS` in `session/peer_integrity.rs`.

## Changes outside the owned files (each small, each needed)
- `conn.rs` (8c): `InboxHost::peer_hello` (default no-op, called with the hello host id) so `send` can check
  `envelope.from`; `probe()` (hello-only exchange) for the reaper. No behaviour change for existing callers.
- `peer_inbox/mod.rs`: `mod` lines, and four new `Disabled` variants (`FeatureOff`, `SocketDirUnavailable`,
  `SocketPathExists`, `SocketCheckFailed`) with fixed texts.
- `session/message_delivery.rs`: `#[cfg(test)] peer_test_session` so the inbox sources never name the command type.

## Security properties and their tests (`peer_inbox::inbox_tests` unless noted)
| Property | Test |
|---|---|
| S3.1 socket 0600, directory 0700 at first visibility | `socket_mode_0600_and_directory_mode_0700_at_first_visibility` |
| Flag off: no `peers/`, no runtime dir, no task | `flag_off_leaves_no_peers_dir_and_spawns_no_task` |
| Symlinked home: typed reason, nothing created | `a_symlinked_home_gives_the_typed_reason_and_creates_nothing` |
| Pre-existing file or link at the socket path: fail closed | `a_preexisting_file_or_link_at_the_socket_path_makes_start_fail_closed` |
| Drop unlinks only our socket, removes our row | `row_is_written_and_removed_with_the_socket_on_drop`, `drop_does_not_unlink_something_that_is_no_longer_our_socket` |
| S3.4 oversized and hard-linked locator ignored and rewritten | `an_oversized_and_a_hard_linked_locator_file_are_ignored_and_rewritten` |
| S3.5 120-byte home uses the runtime directory, works, same checks | `a_home_path_of_120_bytes_selects_the_runtime_directory_and_still_works`, `no_usable_directory_for_a_long_home_is_a_typed_reason` |
| Two homes never list each other; end to end list and send | `start_list_and_send_end_to_end_and_two_homes_never_list_each_other` |
| Other host, unknown session, old incarnation, lying `from`: `unavailable`, nothing delivered | `send_to_another_host_unknown_session_or_old_incarnation_is_unavailable_and_delivers_nothing` |
| Bounded list pages | `list_pages_are_bounded` |
| S5.5 33rd connection closed, permit reused; panic does not stop the loop | `the_33rd_connection_is_closed_at_once_and_a_freed_permit_is_reused`, `notices_reach_only_the_sink_and_a_panicking_connection_does_not_stop_the_loop` |
| S3.1 another uid cannot traverse the directory (real uid 65534) | `uid_tests::a_second_uid_cannot_traverse_the_peers_directory` |
| Another uid that does connect (test-only chmod) is dropped unread, host never called | `uid_tests::with_a_test_only_chmod_a_second_uid_connects_and_is_dropped_unread` |
| Client refuses a server of another uid via a symlinked `<id>.sock`, writes nothing | `uid_tests::a_client_refuses_a_server_of_the_second_uid_reached_through_a_symlinked_sock` |
| S3.6 stale socket reaped with its row after two tries | `a_stale_socket_file_with_no_listener_is_reaped_with_its_row_after_two_tries` |
| Home row reaped, runtime row kept on "no such file" | `a_row_without_a_socket_file_is_reaped_when_home_and_kept_when_runtime` |
| Replaced socket: two tries, only if the row is unchanged, socket unlinked | `a_replaced_socket_is_reaped_only_after_two_tries_and_only_if_the_row_is_unchanged` |
| Version mismatch never reaps | `a_version_mismatch_never_reaps` |
| Timeout never reaps (one try only) | `a_timeout_does_not_reap` |
| Dial errors map onto `TryResult` | `dial_errors_map_onto_the_reap_inputs` |
| 8c audit: host call cancelled by the 10 s deadline | `a_host_call_that_never_returns_is_cancelled_by_the_exchange_deadline` |
| 8c audit: close mid-frame never calls the host | `a_close_in_the_middle_of_a_frame_never_calls_the_host` |
| 8c audit: delivery is one channel send, so a cancelled send is whole or absent | `a_delivery_is_one_channel_send_so_a_cancelled_send_is_whole_or_absent` |
| One entry point: no `SessionCommand`, `cmd_tx`, `.submit(`, `host_ingress` under `peer_inbox/` | `peer_inbox_sources_never_name_the_session_command_path` |
| Item 7: a file in `<home>/peers` does not trip the integrity hold | `session::peer_integrity_tests::a_file_created_in_the_peers_directory_does_not_trip_the_hold` |

Cancellation, said plainly: `deliver_peer_message` does one `send` on an unbounded channel and then awaits the
session's answer. If the future is dropped before the send, nothing was delivered; after it, the whole command was
delivered (the sender just never learns the outcome). There is no half-delivered state.

## Stated limits (word for word)
- A same-uid hostile process can forge envelopes and spend the host rate allowance.
- Mixed versions after an auto-update reject each other and never reap.
- `bind(2)` is path-based and safe only because of the 8b ancestor rule.

Also: the host-id check on `envelope.from` is a consistency check, not a security claim; a locator file that fails its
checks is never parsed; no error, log line or reason contains peer bytes or locator content.

## Tests that need a second uid
Run as root on the build box with `setpriv --reuid=65534 --regid=65534 --clear-groups python3 -I <helper>`. The helper
is a small Python script written into the test's temp directory, because the test binary sits under `/root`, which uid
65534 cannot enter. The host side is the test process (root); the peer is 65534. If `setpriv` or `python3` cannot run
as 65534 the tests FAIL, unless `FUIGO_TEST_ALLOW_NO_SETPRIV=1`, in which case they print `P8D-UID-SKIP` and return.

## NOT wired (8e)
Nobody calls `PeerInbox::start`; no host registers sessions; the notice sink and the cross-host `list` fan-out are
8e; the `allow(dead_code)` at `message_delivery.rs` `deliver_peer_message` stays. `reap_stale` has no caller. A full
locator (64 rows) makes `start` fail with `OutputTooLarge` until a reap pass has run.

## Not run
macOS (104-byte path limit, `getpeereid`) and Windows (non-unix returns `UnsupportedPlatform`; not built here).
Both ends as two non-root uids were not run: the host side is root. Real-time tests: the timeout test waits the 10 s
exchange deadline.

## Round 2
Changed (counts only; test names below):
- Locator lock: `flock(LOCK_EX | LOCK_NB)` in a 10 ms retry loop, total bound 2 s, then the typed `Disabled::LockBusy`.
  `start` undoes its socket and temp dir and fails closed; `shutdown` is now `async` (blocking thread, same bound)
  and still unlinks our socket when the row cannot be removed; `Drop` only cancels and unlinks the socket (no lock),
  and hands the row removal to a blocking thread when a runtime exists, else the reaper removes it.
- Every failure after the bind (`from_std` included) undoes socket and row (`undo_all`).
- Runtime directory levels (`fuigo`, 16-hex, `peers`) are made one component at a time with `mkdirat` and no-follow
  opens (`CheckedDir::create_under`); the base must be absolute, ours, not group/world-writable
  (`Disabled::RuntimeDirUnavailable`); `peers` exactly 0700.
- `choose_dir` runs first: an unavailable result creates nothing (no `peers/`).
- After the bind the final path's (dev, inode) is compared with the socket file recorded at its temporary name
  (an `fstat` on the socket fd reports the socket file system, so it cannot be used); a mismatch undoes and returns
  `SocketCheckFailed`.
- `close` is bounded to 250 ms (the permit is no longer held up to 5 s after the reply). `peer_hello` runs after the
  version matched.
- Notice sink type is `Fn(&HostId, &BoundedId, NoticeKind)`; the trait takes `BoundedId`; doc says 8e must never
  render a peer string from it.
Tests (13 new): r2_a_held_lock_makes_start_fail_closed_and_shutdown_bounded, r2_from_std_failure_undoes_the_socket_and_the_row,
r2_a_path_swapped_between_bind_and_check_fails_closed, r2_no_usable_directory_creates_no_peers_dir,
r2_a_symlink_at_each_runtime_level_is_refused_and_nothing_is_created_through_it,
r2_the_runtime_directory_itself_must_be_absolute_ours_and_private, r2_start_through_a_symlinked_runtime_level_is_refused,
r2_drop_unlinks_the_socket_at_once_without_taking_the_lock, r2_a_dead_pid_beside_a_live_socket_is_never_reaped,
r2_the_notice_sink_carries_only_a_typed_kind_and_a_bounded_id, r2_peer_hello_runs_only_after_the_version_matched,
r2_a_finished_exchange_does_not_hold_its_permit_for_the_write_deadline (conn_tests). Not added: send-during-unregister,
probe frame cap.
