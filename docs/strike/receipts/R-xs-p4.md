# R-xs-p4: peer messaging packet 4 (admission, in-process only)

Branch `strike/xs-p4` from `hub/strike/land-batch10` (+ merge of `hub/strike/xs-p3` for the base test compile fix; my own one-line fix was reverted as instructed). No listener, socket, tool or UI. With `features.peer_messaging` off nothing is stored and every entry point refuses. No existing condition for existing origins was changed: new branches for the peer origin only (`notification_drain.rs` and `prompt_queue.rs` each gained one call that is a no-op unless a tracked peer row is queued).

## Built
- `fuigo-config-types/src/peer.rs`: `PeerInboundPolicy {accept|hold|refuse}` (default **accept**, still equality-gated), `PeerConfig {inbound}`. Documented as `peer.inbound` in `fuigo-pager/docs/user-guide/26-config-reference.md`. Not yet read from the file (host sets it on the session).
- `fuigo-peer`: additive `HoldReason::PolicyHold`.
- `session/peer_admission.rs`: pure `decide()`, `OperatorPresence`, `PeerAdmissionState` (held store, approved list, tracked queue rows, notices), tokens (2x uuid v4, constant-time compare), `now_secs()` with test clock.
- `session/handle.rs`: `submit_peer_message`, `release_peer_message`, `reject_peer_message`, `list_held_peer_messages` (rotates tokens), `configure_peer_admission`, `take_peer_notices`; one new `SessionCommand::PeerAdmission`.
- `acp_session_impl/peer_admit.rs`: actor glue; recheck hooks in `maybe_start_running_task` (front row) and `promote_parent_agent_messages` (all peer rows).
- Operator rule: S4.2 compares sender `from_operator` with the receiver kind (`Present`/`MayReturn` = human, `Auto`, `None`).

## Operator predicate
No in-process signal exists that says a client able to show prompts is attached. `gateway_enabled` (`session/notifications.rs:29`) is true from spawn (`agent/mvp_agent/agent_ops.rs:3792`) and is a replay gate, so it is not presence. So presence is host-declared via `configure_peer_admission` (default `None`: fails closed). Packets 8/13 set it (TUI window, ACP `peerAdmission`).

## Bounds
Held + released-awaiting-drain + queued-tracked per session: 64 messages, 1 MiB of bodies (`fuigo-peer::limits`). Over either: `rejected{saturated}`, nothing evicted. Hold expiry 300 s, expired when `now >= expires_at`. Duplicate id is idempotent.

## Rules (Hetzner lane xs4; red = mutation of the fix, reverted)
| Rule | Test | Red / green |
|---|---|---|
| S4.1 off/not opted in/relay | `s4_1_unavailable_stores_nothing`, `s4_1_flag_off_every_entry_point_refuses_and_stores_nothing`, `s4_1_session_not_opted_in_is_unavailable` | green |
| S4.2 matrix 37x37x3x4 | `s4_2_table_every_mode_pair_x_policy_x_operator` | red under M3 (plan/grant ignored); green |
| S4.2 plan/grant, Unknown, operator kinds | `s4_2_plan_flag_and_edit_grant_differences_hold`, `s4_2_unparseable_sender_mode_holds`, `s4_2_and_s4_5_operator_kind_must_match`, `s4_2_equal_modes_admit_and_a_difference_holds` | red M3; green |
| S4.4/S4.5 operator | `s4_4_*`, `s4_5_*` | green |
| S4.6 tokens, replay, stale, two releasers | `s4_6_replayed_and_stale_tokens_are_refused`, `s4_6_two_releasers_first_wins` (50 thread races), `s4_6_reject_*` | red M4 (token compare); green |
| S4.7 mode change release->drain | pure `s4_7_mode_change_between_release_and_drain_returns_to_held`, actor `s4_7_mode_change_between_release_and_drain_does_not_enter_the_queue` | red M2; green |
| S4.7 after direct admission, before promote / before turn start | `s4_7_mode_change_after_admission_is_caught_before_promotion`, `..._before_a_turn_starts` | red M1; green |
| S4.7 policy/opt-in/operator/flag/expiry at drain | `s4_7_policy_optin_operator_flag_change_before_drain`, `s4_7_a_mode_change_never_releases_anything` | green |
| S4.8 / S5.2 bounds | `s4_8_store_count_bound_*`, `s4_8_store_byte_bound_*`, `s4_8_duplicate_*` | red M5; green |
| Expiry boundary (test clock) | `s5_5_expiry_at_the_boundary` | red M6; green |
| S2.1 S2.2 S2.4 S4.8 | `s2_1_s2_2_s2_4_s4_8_peer_traffic_resolves_nothing_and_changes_nothing` (open Permission + PlanApproval prompts, mode, yolo/auto, config unchanged across hold, admit, release, expiry), `s2_2_a_message_body_cannot_change_policy_or_release_itself` | red M6 (expiry); green |

## Tests (Hetzner, via slot-run)
`fuigo-shell --lib peer` 75; `acp_session` 1372; `session` 4336 (0 failed; the known unrelated failure did not appear); `fuigo-config-types` 62; `fuigo-config` 457; `fuigo-peer` 18; `fuigo-extra-ca` all pass; `secret_debug_guard` 2 (release tokens print as `<redacted>`, hand Debug). Clippy: see report.

## Deviations / not covered
- S4.3 loop_guard / sender_denied / integrity holds: packets 5/7/6. `HoldReason::PolicyHold` added because no listed reason fits policy `hold`.
- `deliver_peer_message` (packet 3 raw path) is unchanged and bypasses admission; it is test-only/dead in production. Production entry is `submit_peer_message`.
- Rows from the raw path are untracked and never rechecked.
- `peer.inbound` is not read from config.toml; the flag is still read from process sources (packet 3 deviation).
- Handle-level round trip (handle -> command -> actor) is not tested end to end; tests drive `handle_peer_admin` on the actor. Notices (released/expired/refused/reheld) are recorded, no transport.
- A message expiring while already queued (admitted) is not a concept; only holds expire.

## Round 2 (review fixes)

Unattended case, plainly: A session in the same permission mode as the sender accepts the message and acts on it even when no window is attached; a session in a different mode holds it. `None`==`None` and `Auto`==`Auto` at equal modes ADMIT by design S4.2; `MayReturn` counts as attended (owner decision 38, 2026-10-10, one switch: `may_return_admits()` in `peer_admission.rs`).

Red/green: green lines are from the Hetzner run after the last edit (below). Red lines (the new tests run against the round-1 code) were NOT captured: the new tests use new APIs and do not compile against round 1. NOT VERIFIED as red.

| Item | Test (file) | Result |
|---|---|---|
| A one entry: `SessionCommand::PeerMessage` and `deliver_peer_message` now go through `submit_peer_message`; the raw enqueue is private (`enqueue_admitted_peer_row`) | `a_peer_message_command_cannot_reach_the_queue_without_the_admission_decision` (peer_admit_tests.rs) | green. The run-loop arm is a one-line forward to the function the test calls; the arm itself is not driven by a test |
| B untracked peer row is not qualified; rows rebuilt from stranded interjections are tracked again (`retrack_stranded`, via a bounded in-flight ring) | `b_untracked_peer_row_is_not_qualified`, `b_stranded_row_is_tracked_again_and_rechecked` (peer_admission_tests.rs); `b_an_untracked_peer_row_is_removed_and_never_starts_a_turn`, `b_a_stranded_peer_interjection_is_rechecked_when_it_runs` | green |
| C recheck after the stale pops, repeated until the front is stable | `c_a_stale_front_pop_does_not_expose_an_unchecked_peer_row` | green |
| D re-evaluate after the `update_resource` await, same lock, abort and re-hold | `d_a_mode_flip_during_the_start_await_aborts_the_peer_turn` (seam: `set_after_resource_hook`) | green |
| E `MayReturn` admits equal modes, holds different ones | `e_may_return_admits_equal_modes_and_holds_different_ones`; table test updated | green |
| F sender-operator dimension in the S4.2 table (37x37x3x4x3); unattended admits asserted; S2.1 test with a message that enters a turn | `s4_2_table_every_mode_pair_x_policy_x_operator`, `s4_2_unattended_equal_operators_admit_by_design`, `s2_1_a_peer_message_entering_a_turn_resolves_no_prompt_and_moves_no_presence_marker` | green |
| G dedup on (from, id) and same-id different body refused (`Ambiguous`); monotonic deadlines (`now_mono`, wall time only for reported `expires_at`); pruning of rows that left the queue (also on every admin call); `configure` / `take_peer_notices` gated on the flag | `g_same_id_from_another_sender_is_not_a_duplicate`, `g_same_id_with_a_different_body_is_refused`, `g_rows_that_left_the_queue_are_pruned_and_free_their_space`, `g_a_dropped_queue_row_is_pruned_from_the_store`, `g_configure_and_notices_are_noops_with_the_flag_off` | green |

Finding (not changed): a peer turn DOES bump the persisted activity marker. Every appended session update records activity with no check of the prompt origin: `crates/codegen/fuigo-shell/src/session/storage/jsonl/mod.rs:908` (and `:1587`, `:581`) set `record_activity: true`, which moves `last_active_at` (`storage/summary_write.rs:116`). The in-memory presence marker (`notifications_suppressed`, cleared only for human-intent origins in `notification_drain.rs`) does not move; that is what the S2.1 test asserts.

Not verified: the monotonic clock is exercised only through the test clock (which sets both clocks to one value); no test steps the wall clock.

Deferred: operator preview and hash on release (packet 13); replay memory and rate/hop budgets (packet 5); notice-ring eviction and a host tick (packet 8); token exposure only on the client channel (packets 8 and 13).
