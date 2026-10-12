# R-xs-p8e: host wiring for the peer inbox (packet 8e)

Crates `fuigo-shell` (`src/peer_inbox/host.rs`, `host_tests.rs`, and small edits) and `fuigo-pager` (`src/acp/spawn.rs`).
Everything is behind `features.peer_messaging` (default off). With the flag off `arm_peer_host`, `session_started`,
`session_ended` and `shutdown_peer_host` return before touching anything: no directory, file, socket, task or thread,
and the process-wide host object is not even created.

## What is wired
- One `PeerInbox` per host process, held by `peer_inbox::host::PeerHost` (a process global, `host::global()`).
  A host entry point calls `arm_peer_host()` (records the home only); the inbox STARTS LAZILY at the first main-session
  registration with the flag on. There is no production opt-in today (`configure_peer_admission` has no production
  caller), so first registration is the trigger. Registration does NOT opt a session in: admission still refuses or
  holds until something sets `opted_in` (a later packet).
  - leader: `run_leader` (`agent/app.rs`), armed after the leader lock is won; shutdown after the select that ends it.
  - leader-off pager: `spawn_agent_thread_direct` (`fuigo-pager/src/acp/spawn.rs`), armed after the agent is built,
    shutdown after `flush_all_sessions`.
  - `agent --no-leader stdio`: `run_stdio_agent`, armed at the top, shutdown after the agent returns.
  - `run_headless`: NOT wired (packet 13). Headless never arms, so its sessions are never registered.
- Session registration: `MvpAgent::insert_resident` (every main session create/load; a replaced resident registers
  again and so gets a new incarnation) and `take_session` (every handle leaving residency: close, delete, idle unload,
  crash reap via `remove_session`). Subagents do not pass through either.
- Failed start: any `Disabled` reason (SymlinkedHome, LockBusy, SocketDirUnavailable, a refused `bind`, ...) is stored,
  the host runs on, and the start is NOT retried (I chose no retry at all in this packet; the reason is terminal for the
  process). `peer_inbox_status()` returns `NotStarted`, `Available { host_id }` or `Unavailable { reason }`
  (flag off gives `Unavailable { FeatureOff }`). Three variants rather than two: "nothing attempted yet" is a real state.
- Reaping: `PeerInbox::start` runs ONE `reap_pass` before writing our row, under a 5 s budget (`REAP_BUDGET`), async
  (no thread blocked; file work on blocking threads). Never on a timer. `reap_pass` now judges rows concurrently (at
  most 64) so 64 dead rows cost one 1 s gap, and a hello that names the row's own host skips the second try.
- 8d audit fixes: the undo after a bind mismatch / row failure unlinks only if (device, inode) still equal the file
  recorded at bind time (`unlink_if_identity`); the runtime directory is made BEFORE `<home>/peers`, so its failure
  leaves nothing in the home.
- Notice sink: `PeerDirectory::note_sent(session, message_id)` keeps a bounded ring (64) of ids per session (packet 9
  calls it when it sends). An incoming notice goes to `MessageDeliveryHandle::record_sent_notice` of the session that
  sent that id and nowhere else; unknown ids are acknowledged and dropped. The session notice ring gets a typed
  `NoticeKind::SentMessage(kind)`; no peer string is rendered.
- `deliver_peer_message`: `allow(dead_code)` removed (the inbox host calls it).
- Source pin (`peer_inbox_sources_never_name_the_session_command_path`) untouched and green; the new session-side
  command lives in `session/`, not `peer_inbox/`.

## Tests (`peer_inbox::host_tests`, all in `unshare -n`, own temp home, in-process `PeerHost` over real sockets)
| Test | Proves |
|---|---|
| flag_off_arm_and_session_start_create_nothing | flag off: empty home, no task spawned, status `Unavailable(FeatureOff)` |
| the_inbox_starts_lazily_at_the_first_session_and_serves_list_and_send | arming creates nothing; first session starts it; list and send arrive through the delivery handle only; second session shares the one inbox/row |
| a_restarted_session_gets_a_new_incarnation_and_the_old_address_is_refused | replaced resident and end/restart raise the incarnation; old address refused, nothing delivered to either |
| shutdown_removes_the_socket_and_the_row | host exit removes socket and row; late sessions do nothing |
| a_symlinked_home_starts_normally_reports_unavailable_and_is_not_retried | owner condition: `Unavailable(SymlinkedHome)`, nothing created through the link, no retry |
| a_crashed_hosts_row_is_reaped_by_the_next_start_even_when_the_locator_is_full | 64 dead rows reaped at start (start would otherwise fail), under 5 s |
| a_live_hosts_row_is_not_reaped_and_costs_no_second_try | live row kept, one probe |
| a_runtime_directory_failure_leaves_no_peers_directory_in_the_home | item 4b |
| a_notice_reaches_only_the_session_that_sent_that_message_id | item 5, unknown id dropped |
| (8d test amended) r2_a_path_swapped_between_bind_and_check_fails_closed | item 4a: the foreign socket is left in place |

## NOT done
- Real two-PROCESS tests (two hosts, leader off, same `FUIGO_HOME`) and the two-window leader-on test: not written; the
  tests above run two inboxes in one process over real unix sockets. A host-wide flood over the socket hitting
  `rate_limited` with flat memory: not written (needs real sessions with `PeerIngress`; the test session helper bypasses it).
- Tools and `/peers` (packet 9), headless (packet 13), Windows (unavailable until packet 10; `cargo check` by the
  coordinator), macOS (not run).

## Stated limits (word for word from R-xs-p8d.md)
- A same-uid hostile process can forge envelopes and spend the host rate allowance.
- Mixed versions after an auto-update reject each other and never reap.
- `bind(2)` is path-based and safe only because of the 8b ancestor rule.

## Files that now call into `peer_inbox`
`agent/app.rs` (arm, shutdown; leader and stdio), `agent/mod.rs` (re-export `arm_peer_host`, `shutdown_peer_host`),
`agent/mvp_agent/session_lifecycle.rs` (`session_started`, `session_ended`), `fuigo-pager/src/acp/spawn.rs` (through the
re-export). `session/message_delivery.rs`, `session/peer_admission.rs`, `session/acp_session_impl/peer_admit.rs` gained
the typed sent-message notice path (called from `peer_inbox/directory.rs`).

## 8f: hardening after the Opus review
Counts only; names in the code. 11 new tests (prefix `xs_p8f_`) plus 3 amended.

| Finding | What changed | Tests |
|---|---|---|
| 1 not-opted-in listed/addressable | `PeerGate` (opt-in `AtomicBool`) shared by the admission state, `SessionHandle` and the directory entry; `configure` updates it; `list_page` and `handle_for` honour it; `send` to a hidden session answers `unavailable` like an unknown one | 1 |
| 2 reap stalls | probes capped at 3 s, 8 at once, one gap, second tries then batched removals under one lock each (kept when the budget cuts); `LocatorFull` is a typed status and retryable once per 60 s by a later registration | 2 (63 dead + 1 stuck host; full locator retry) |
| 3 runtime row never reaped | `reap_decision` takes `same_runtime_dir`; the pass sets it when our own checked runtime peers dir for this home opens; table test extended | 1 + `reap_table` |
| 4 orphan socket | `SocketGuard` drop guard in `Prepared`/`start_inner` (synchronous `unlink_if_identity`); `shutdown` waits up to 3 s for `Starting`; `undo_all` and `Drop` use the identity check; a panic in `run_start` stores `Unavailable(StartPanicked)` (guard, untested) | 2 |
| 5 runtime peers dir unprotected | pure `fuigo_peer::runtime_peers_dir` (hash moved from `dial.rs`); added to the protected set | 1 (through `PermissionHandle::request`, every mode) |
| 6 flag env-only | `Config::resolve_runtime_fields` installs the config and managed-pin tiers; `peer_messaging_enabled()` resolves pin, env, config, default off; managed off wins | 1 |
| 7 baseline before opt-in | not opted in (or relay driven) answers `unavailable` first | 1 |
| 8 unbounded hand-in | per-session cap of 32 in flight; slot travels inside the command, freed when the actor is done | 2 |
| 9 notices | duplicate sent ids dropped; a notice consumes its id; re-registering clears the ring; `peer_inbox_status()` no longer creates the global with the flag off (not observable in a test) | 2 |

NOT done (still required before enablement, from the review): the three real-process tests (two hosts with `kill -9` and a
SIGSTOPped host; leader-on two windows in all six modes; the 10,000-send flood with flat RSS). The panic guard for
`run_start` has no test. macOS and Windows were not built here. A config reload re-installs the flag tiers only when
`resolve_runtime_fields` runs again.
