# R-xs-p11: idle watch and delivery notices (packet 11, DESIGN S9)

Branch `strike/xs-p11` from `strike/xs-p9c`. Behind `features.peer_messaging` (default off). Flag off: the tools are not registered (tool list
unchanged), `deliver_peer_message` and `record_sent_notice_wake` return before doing anything, no schema byte changes.

## Built
- Wire (`fuigo-peer/src/wire.rs`): `Op::Send { to, envelope, watch }`; `watch` is omitted from the bytes when false (`skip_serializing_if`),
  so a plain send is byte-identical. An older peer rejects the unknown field; the sender then reports `unavailable` and the tool text says an older
  receiver cannot watch. `SendRequest.watch`, `notice_text()` (fixed texts), `limits`: `MAX_WATCHES_PER_SESSION` 64, `MAX_WATCHES_PER_HOST` 256,
  `WATCH_PROBE_SECS` 60, `WATCH_PROBES_AT_ONCE` 8, `WATCH_PROBE_CAP_MS` 3000 (the 12 h `WATCH_EXPIRY_SECS` already existed).
- Tool (`peer_tools.rs`): `send_message { to, message?, summary?, notify_when_idle? }`. No `message` needs `notify_when_idle: true` (watch only: empty body
  on the wire). Sender, hop, conversation, denials still cannot be set. Outcome `watching` is shown ("Watching: delivered ...").
- Receiver (`session/peer_watch.rs`, `WatchBook` in `PeerGate`): the inbox registers the watch BEFORE delivery. `delivered` -> reply `watching`; held ->
  record kept and armed at release (`released` notice, then `idle`); rejected -> record dropped; refused/expired/model-refused -> typed notice
  (`refused`/`expired`/`denied`), no watch. Fires once, `idle`, when the turn that consumed the message ends (`TurnConvGuard` drop: normal, cancel,
  error, panic). Watch only: at once if no turn runs, else at turn end. Held messages WITHOUT a watch also report released/expired/refused (S9.3).
  A session that ends tells its waiting senders `exited`. Hooks in `peer_admission.rs` (small): `Inner::notice` feeds the book, `begin_turn` /
  `TurnConvGuard` mark turn start/end, `note_turn_peer_message` binds, plus `consume_notice_turn`, `record_sent_notice_opt`.
- Sender (`peer_inbox/watch.rs`, `directory.rs`, `inbox.rs`, `tool_host.rs`): the sent ring now keeps the target address; a notice is accepted only when the
  id is outstanding AND comes from the target's host (hello). `WatchTable` (64/session, 256/host; the oldest ends with a local `unavailable`). Once a minute
  `probe_pass` hello-probes each watched target host (8 at once, 3 s each, reuses `try_hello`): no answer + row present -> `unavailable` ("target
  unavailable (not a confirmed exit)"); no answer + row gone on two passes -> `exited`; same-host target no longer registered -> `exited`; a host that shuts
  down announces `exited` for every outstanding record (3 s budget, `ANNOUNCE_BUDGET`) before closing; a record older than 12 h ends with the local
  `outcome unknown` notice. Notices produced by receiving sessions go out through one pump (8 at once, 5 s per attempt, ONE retry after 2 s).
- Wake (`acp_session_impl/peer_admit.rs`): `PeerAdminCmd::SentNoticeWake` records the typed notice (`SentMessage(kind)` or `SentOutcomeUnknown`) and queues a
  HIDDEN runtime-control row (`PromptOrigin::PeerNotice`, tag `peer_notice`, prompt id `peer-notice-<id>`, same class as workflow completion, exhaustive
  matches updated) with fixed text from `notice_text`: "Fuigo runtime notice (written by Fuigo, not by a peer): <fixed sentence with the escaped target
  address>. This is a status notice only ...". The turn consumes one of the 20 peer-started turns (`consume_notice_turn`; none left -> the notice stays in the
  ring, no wake) and is not human typed, so it inherits the peer chain (hop not reset). A received notice never emits a notice (the book is only fed by
  held-message notices and turn events).

## Fixed texts (after the prefix)
released: "your message to T was held and its user released it" | expired: "... was held and expired before its user released it; it was not delivered" |
refused: "... was held and then refused; it was not delivered" | denied: "the model in T refused your message" | idle: "T finished the turn that handled your
message and is now idle" | exited: "T exited" | unavailable: "target unavailable (not a confirmed exit): T" | unknown: "outcome unknown for your message to T: no notice
arrived within 12 hours". T is `display_escape`d, cap 200.

## Tests
fuigo-peer wire_tests (Op::Send updated). fuigo-tools: `p11_notify_when_idle_sets_watch_and_a_messageless_call_is_a_watch_only`,
`p11_a_messageless_call_without_the_watch_flag_is_still_an_error_and_nothing_is_dialed`, `p11_unavailable_with_a_watch_says_an_older_receiver_cannot_watch`
(the old `notify_when_idle` rejection case was replaced by `conversation_id`). fuigo-shell `session::peer_watch::tests`: p11_one_notice_per_watch,
p11_an_idle_session_answers_a_watch_only_at_once_a_busy_one_at_turn_end, p11_held_then_released_arms_at_release_and_sends_released_then_idle,
p11_refused_and_expired_arm_no_watch_and_send_that_notice_instead, p11_a_plain_held_message_still_reports_release_and_expiry_but_never_idle,
p11_the_65th_watch_ends_the_oldest_with_unavailable_and_the_host_cap_refuses, p11_an_id_owned_by_another_sender_is_never_merged,
p11_a_session_notice_about_a_sent_message_never_produces_a_notice, p11_ending_a_session_tells_every_waiting_sender_exited,
p11_the_admission_state_feeds_the_book_on_release_and_on_expiry, p11_a_notice_woken_turn_counts_against_the_budget_and_keeps_the_peer_chain,
p11_the_notice_origin_is_runtime_control_with_its_own_hook_tag_and_never_peer, p11_the_wake_text_is_fixed_and_escapes_the_address.
`peer_inbox::watch_tests` (real sockets): p11_a_watched_delivery_sends_one_idle_notice_when_the_turn_ends, p11_a_watch_only_on_an_idle_session_fires_at_once,
p11_a_held_watched_message_arms_at_release_and_sends_released_then_idle, p11_a_held_message_that_expires_sends_expired_and_no_watch_remains,
p11_a_rejected_watched_send_arms_nothing_and_a_plain_held_one_still_reports_release, p11_a_notice_for_an_unknown_id_or_from_the_wrong_host_is_dropped,
p11_a_clean_exit_announces_exited_and_a_killed_host_is_only_unavailable, p11_a_missing_row_is_exited_only_after_two_passes_a_live_host_is_left_alone,
p11_the_real_prober_sees_a_live_host_and_a_shut_down_one, p11_a_watch_that_never_resolves_ends_with_outcome_unknown_after_twelve_hours,
p11_sender_side_watches_are_bounded_64_per_session_256_per_host, p11_the_wire_carries_watch_only_when_true_and_the_tool_input_cannot_set_it_otherwise.
Round 2: `peer_admission_tests` p11_probe_* (admitted stores nothing, policy refuse, would-hold, integrity hold, pair rate 11th, not opted in); `peer_watch_tests` p11_at_the_session_cap_a_sender_evicts_only_its_own_oldest_watch, p11_forget_removes_an_unsettled_registration; `watch_tests` p11_a_watch_only_the_session_refuses_registers_nothing_and_never_notifies, p11_a_dropped_watched_send_leaves_no_unbound_watch, p11_a_replayed_released_notice_is_dropped_and_the_watch_stays_armed; `peer_admit_tests` p11_a_notice_wakes_an_idle_session_inherits_the_chain_and_stops_at_the_budget.

## Limits / not done
- Actor level: `p11_a_notice_wakes_an_idle_session_inherits_the_chain_and_stops_at_the_budget` drives a real `SessionActor` from a
  `SentNoticeWake` to a started turn (the hidden `PeerNotice` row runs, the chain is kept, one peer-started turn is spent, the 21st wake queues
  nothing). Not covered at actor level: the model actually issuing a send from that turn (hop + 1 is checked as `next_hop` on the kept chain, and
  the send path is unit-tested in packet 9), and slash / `!` / `@file` handling inside the running turn (the text is fixed and cannot begin with
  those characters, asserted on `notice_text`; the origin is runtime control, which forces slash inert and skips `!`/`@file`, per the unit tests).
  `outcome unknown` is not observable through the test notice session (it forwards typed kinds only); the test checks the record ends.
- The retry is on the receiving host's pump (one retry, 2 s); an unanswered notice is then covered by the sender's probe verdict or the 12 h unknown.
- A watch on a delivered message whose turn never starts (queue cleared) stays until the 64-cap, session end or 12 h.
- Model-refusal `denied` is sent only for messages with a record (watched or held).
- Watch-only now takes the SAME gate as a message (`PeerAdmissionState::probe_watch`, called from `SessionActor::probe_peer_watch` through
  `MessageDeliveryHandle::probe_peer_watch`): ingress sizes and remembered ids are checked and the pair and host rate slots are consumed (the id itself is NOT recorded, so a later real
  message with that id is judged fresh), then the admission
  decision runs. Only `Admit` registers a watch and answers `watching`; a refusal is returned as is; a would-be hold (mode mismatch, denied sender,
  policy hold, integrity hold, hop or turn budget) is refused `policy_refused` (`no_operator` when nobody could answer a hold): no held row,
  no watch, no timing revealed. Nothing is inserted into the conversation and no turn starts. Not opted in or remote attached: `unavailable`.
- The immediate `idle` for an idle session still uses the notice pump's unbounded channel; its producer is bounded by those rate slots (10 per
  minute per pair, 60 per minute per host), so the channel cannot grow without limit.
- At the per-session cap (64) a sender evicts only ITS OWN oldest watch (`unavailable` to it); a sender with none is refused `rate_limited`,
  and another sender's watch is never evicted. The host total (256) refuses as before. A send dropped between registering and settling removes
  its watch (drop guard). A `released` notice is accepted once per id; a replay is dropped and the watch stays armed for the final kind.
- Same-user limit of the design: a process that claims the recorded target's host id in its hello can inject a notice for an id the sender really
  sent (ids are random UUIDs; ids never sent are dropped). Each notice wake spends one of the receiving session's 20 peer-started turns.
- Windows: `watch::io` and the pump are `cfg(unix)`; `Op::Send.watch` is plain data.
- Not wired in ACP/headless presentation (packet 13) or the TUI (packet 12).
