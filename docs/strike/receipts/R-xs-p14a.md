# R-xs-p14a: real-process gate tests for peer messaging

File: `crates/codegen/fuigo-pager/tests/peer_real_process.rs` (dev-dependency `fuigo-peer` added to `fuigo-pager`). No product code touched.

Opt-in path: real `fuigo-pager --no-leader` children on a PTY with `FUIGO_PEER_MESSAGING=1` (pager driver => sessions opted in). A raw
client in the test speaks the wire protocol (u32 BE length + JSON, hello each way, one op) on the child's real unix socket, with a real
connect timeout (helper thread). Mock model on 127.0.0.1 with fake keys; temp HOME per test.

Signalling (round 3): no raw pid is ever passed to a signal call by the test. Pids are read only (1) to open the pidfd right after the spawn, while the child is unreaped (`PtyHarness::register_pid(child_pid())`, `child.id()` for the leader), and (2) for `/proc/<pid>/fd` reads (`fd_count`) through `child_pid()`, which is `None` once the child is reaped; the harness owns the child for the whole test and only `drop` reaps it, so a read can never hit a recycled pid (and a read is harmless anyway). Every child gets a pidfd (`pidfd_open`) right after the spawn; SIGKILL/SIGSTOP/SIGCONT
and the watchdog's abort signals go only through `pidfd_send_signal`. A pidfd names that process for good: after the child is reaped
(`drop(b)`) the call fails with ESRCH, so a recycled pid cannot be hit. `pidfd_open` failure fails the test (no raw-pid fallback). The file is
Linux only (`cfg(target_os = "linux")`, also needed for `/proc`). The PTY helper's drop `killpg` targets only the child's own session:
`ProcessGroupId::new` (`fuigo-tty-utils/src/lib.rs:802-830`) rejects pid 0, pid 1, values over `i32::MAX` and the caller's own group;
`killpg_unix` (`lib.rs:1083-1092`) signals only an enrolled, validated leader. The leader (`std::process::Child`) is killed on drop through `Child::kill`, a raw-pid SIGKILL inside std that std only sends while the child has not been reaped: `Child::kill` docs "If the child has already exited, `Ok(())` is returned", and std's `send_signal` returns before signalling once `status` is set (by `try_wait`/`wait`), with its comment "the pid can be recycled ... we probably shouldn't be sending signals to random processes". The test only reaps through that same `Child`.

Slash results: `run_slash` records the length of the child's raw terminal output before it sends the command and uses only the output written
after that offset (escape sequences stripped). It returns once that slice holds the marker and `Worked for` and has stopped changing (two equal
polls, no fixed sleep). EVERY `shows`/`lacks` assertion ("the fresh list shows / does not show X") reads ONLY that slice; the screen/scrollback text is
kept for failure messages and read by no assertion, so older output can satisfy none of them.

## Built
| Test | Asserts |
|---|---|
| two_processes_list_send_kill9_and_sigstop | (a) two processes share one home; A's fresh `/peers list` shows B's host id; a raw send to B is exactly `delivered` and B's model request carries the body. (b) SIGKILL B: A's fresh `/peers list` (new output only) shows no B id; a dial to B's stale socket ends `ConnectionRefused`/`NotFound` (classified as the product's `DialError::Refused`/`NoSuchFile`); B's row stays until the next start; B2's start reaps B's row and socket. (c) SIGSTOP B2: (c1) THE PRODUCT: A's fresh `/peers list` dials the stopped B2 itself (`tool_host.rs:158-176` `remote_rows`, per host `dial` under `REMOTE_ONE` 1 s, whole remote part under `REMOTE_LIST_TOTAL` 3 s, `tool_host.rs:45-46`; a host that does not answer is skipped, `tool_host.rs:167`). Asserted on the fresh slice: A's own `This session is` is present, B2's host id is ABSENT (the product shows nothing for an unresponsive host), and the time from typing the command to complete output is >= 1 s (lower bound: the dial must run into `REMOTE_ONE`; an earlier return means the stopped host was not dialled) and < 3 s + 8 s slack. Measured in 3 runs: 1.60 s each (1 s deadline plus poll/render latency of the harness). The product's `CONNECT_DEADLINE` 2 s (`dial.rs:24`) and `EXCHANGE_DEADLINE` 10 s (`conn.rs:28`) are NOT measured: a list dial is cut earlier by `REMOTE_ONE`. (c2) The raw client's own view: its 12 s socket timeout expires because the stopped process never answers (ends `TimedOut`/`WouldBlock`, 11 s to 20 s). That proves B2 does not answer and that the client is not hung; it says nothing about the product's deadlines. A still answers `/peers status` and serves its socket; after SIGCONT B2 answers again. |
| leader_with_two_windows_list_each_other_and_receive_messages | (a) an `fuigo-pager agent leader` process (default start, no `--relay-on-demand`; no relay exists in this netns, so the eager connect is not observed) with two pager windows (`--leader --leader-socket`, own sessions): one host row, the inbox lists two sessions, each window's fresh `/peers list` names both, a raw send to each session is exactly `delivered` (both windows idle, same mode), and both bodies reach a model request. |
| socket_flood_against_a_real_session | Per assertion, the product defect it catches: (1) 200 idle connections held (connect timeout 3 s, >= 150 must connect, so the flood is real; this alone catches nothing); sampled 6 times in about 4 s (well inside the 10 s `EXCHANGE_DEADLINE`, so idle sockets are not closed by it): a non-blocking read finds at most `MAX_CONNECTIONS` (32, `peer_inbox/inbox.rs:38`) + 2 still open. CATCHES a missing/raised connection cap (about 200 would stay open). Child fds <= baseline + 32 + 8 per sample also catch it (fd leak/no cap); a `/proc` read failure fails the test. (2) Garbage, 4 GiB and 70000-byte prefixes, bad JSON, slow-loris: the SERVER closes each (EOF/reset; the 40 s client read timeout fails) within 10 s + 8 s. CATCHES a missing frame cap or read deadline. (3) 40 valid sends from one sender pair within a minute: every answer typed, <= 10 accepted (pair cap 10, `fuigo-peer` `limits.rs:22`), >= 20 answer `rate_limited`/`saturated`, accepted + rejected = 40. CATCHES a missing/raised rate limit (40 accepted fails). (4) The set reaching the mock model equals the accepted set: CATCHES a message accepted but dropped, or delivered although rejected; it does NOT detect a missing rate limit or cap (assertion 3 and 1 do). Then fds return to baseline + 4, pager alive, legit list and `/peers status` work. |

## NOT built / limits
- Test 2 parts (b) remote attach closes everything and (c) detach reopens: NOT asserted in a real process. Findings:
  - A loopback mock WebSocket server cannot be a relay: the relay refuses its URL before any socket. `relay_destination_gate`
    (`fuigo-shell/src/agent/relay.rs:364` and `:476`) -> `service_trust` ("no exception for loopback or cleartext",
    `fuigo-extra-ca/src/service_trust.rs:30`): relay URL must be `wss` and not loopback. With `ws://127.0.0.1:N` the relay task ends at once
    ("Fuigo relay disabled") and the attach guard is dropped at once (`hold_peer_attach` after `finished`), so nothing stays attached.
  - A relay needs a first-party session (`RelayConfig::for_session`, `is_fuigo_auth`: x.ai-issuer OIDC). Seeding one with
    `seed_fake_oauth` and removing `FUIGO_API_KEY` makes this build's pager window stop at "Paste your FluxRouter API key" (the window never
    reaches a session). With the API key kept the leader did not install the relay (`/peers status` stayed `Peer inbox: ready`).
  - Needed to finish: a first-party session the window accepts plus a `wss` relay host (TLS mock with a trusted CA) in the netns. Not available here.
  - (c) detach: `run_relay_loop` (relay.rs:355) never returns on a failed connect (reconnect loop), only `cancel` ends it, which is leader shutdown,
    so no outside-observable detach exists. Covered only in-process by packet 9:
    `peer_attach_is_held_until_the_relay_task_finishes_and_stop_alone_does_not_clear_it` (relay.rs:1107), plus
    `tool_host_tests::p9c_remote_attached`, `peer_admission_tests::remote_attached_*`, `hardening_tests::remote_attached_a_notice_is_dropped_...`.
- `Cargo.lock` only gained the `fuigo-peer` line of the existing `fuigo-pager` dev-dependency (it was missing; `--locked` failed without it).
- Sends are made by the raw client, not by a session's `send_message` tool, so A's own send path (dial, timeouts) is covered only through A's `list`.
- Memory is checked by fd count only, not RSS; flood stays at 40 valid messages, not 10,000.

## Run
Build `cargo build -p fuigo-pager-bin`, then in an empty netns (loopback up):
`PAGER_BINARY=<target>/debug/fuigo-pager cargo test --offline -p fuigo-pager --test peer_real_process -- --test-threads=1`
