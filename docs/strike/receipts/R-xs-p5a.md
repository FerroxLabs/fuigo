# R-xs-p5a: peer messaging packet 5 part A (ingress bounds, rate limits, idempotency, loop budget)

Branch `strike/xs-p5a`, base integration `d94f2cb1`. Part B (audit log) is a different builder; no log code here.

## Where things are
- `fuigo-peer/src/ingress.rs`: pure, clock-injected `PeerIngress` (sizes, replay memory, rate), `HostLedger` + `Ticket` (per-host totals), `next_hop`, `hop_exhausted`, `PeerTurnBudget`, `frame_within_limit`/`check_frame`/`check_body`.
- `fuigo-shell/src/session/peer_admission.rs`: `PeerAdmissionState::submit` runs ingress FIRST, then the S4 decision, then the loop guard, then the store bounds. `with_host(host_ingress())` (spawn.rs) shares the ingress across the process; `Default` has a private one (tests).
- Human-prompt reset hooks: `acp_session_impl/prompt_queue.rs:173-179` (`queue_input`) and `acp_session_impl/interjection.rs:88-93` (the fallback path that skips `queue_input`), next to `invalidate_side_calls_for_new_prompt`, under `policy.authority.is_human_intent()` and the flag.

## Rules and tests (names)
| Rule | Numbers | Tests |
|---|---|---|
| S5.1 | body 32 KiB (N ok, N+1 `too_large`), frame 64 KiB const + `frame_within_limit` | `ingress_tests::s5_1_body_and_frame_caps_at_n_and_n_plus_1`, `ingress_tests::s5_1_receiver_rechecks_body_size` |
| S5.2 | host 256 msgs / 4 MiB across sessions, over = `saturated`; accounting by drop-freed tickets | `s5_2_host_total_256_messages_across_sessions`, `s5_2_host_total_4_mib_across_sessions`, `s5_2_accounting_returns_to_zero_on_every_exit_path` (promote, release+start, reject, expire, session end, untrack, prune, rehold+expire), `s5_2_host_ledger_bounds_and_exact_release` |
| S5.3 | 10/min per pair, 60/min per host, sliding window, table 1,024 | `s5_3_pair_rate_ten_per_minute_with_clock`, `s5_3_host_rate_sixty_per_minute_across_pairs`, `s5_3_pair_table_cycling_cannot_exceed_host_total` (5,000 senders: exactly 60 pass; 20 minutes: exactly 1,200), `s5_3_full_table_of_live_pairs_refuses_unknown_pair`, `s5_3_pair_rate_through_state` |
| S5.4 | 1,024 ids, 10 min; repeat = original outcome, no rate cost; same id + other body = `ambiguous` | `s5_4_repeat_answers_original_outcome_without_rate_cost`, `s5_4_rejected_id_resent_1000_times_memory_flat`, `s5_4_rejected_id_resent_1000_times_creates_no_hold`, `s5_4_capacity_1024_and_ten_minute_expiry`, `s5_4_expired_id_resent_is_answered_from_memory`, `s5_4_memory_is_per_receiving_session`, `s5_4_transient_refusals_are_not_remembered` |
| S5.5 | hold 5 min (existing), watch 12 h, id memory 10 min: constants | `s5_5_expiry_constants` |
| S5.6 | hop 7 admits, hop 8 `loop_guard`; 20 admitted, 21st `loop_guard`, human prompt resets; `next_hop`; ping-pong stops | `s5_6_next_hop_stamps`, `s5_6_turn_budget_20_then_exhausted_then_reset`, `s5_6_hop_7_admits_hop_8_holds_loop_guard`, `s5_6_turn_budget_20_admitted_21st_held_human_resets`, `s5_6_alternating_reply_loop_stops_at_hop_budget` (hops 0..7 delivered, 9th message held), `s5_6_forged_low_hop_is_bounded_by_the_turn_budget` (stops at message 40 = B's 21st) |
| S5.7 | nothing persisted (nothing in this packet writes; held store is in memory) | `s5_7_restart_loses_held_messages` |
| flood / flag | 100,000 envelopes: pairs <= 1,024, host log <= 60, replay <= 1,024, order <= 4,096 | `flood_100k_envelopes_keep_tables_bounded`, `flood_100k_refused_envelopes_bounded_tables`, `flag_off_tracks_nothing` |

## Forged hop: what the receiver cannot detect
`hop` and `conversation-id` are claims by a same-user process (S3.7). The receiver cannot tell a forged low hop (a sender stamping hop 0 on every reply, or a fresh conversation-id each time) from a genuine new conversation, so the hop check alone is defeated. It CAN bound the damage: the per-session 20-peer-messages-per-human-prompt budget does not read the hop, and the rate limits (10/min/pair, 60/min/host) bound the pace. A looping pair with forged hops stops after 20 admitted messages per receiving session. No cross-message conversation tracking was added (a lower hop in a known conversation can be legitimate: parallel branches).

## Order, outcomes, decisions
- Order: size, remembered id (no rate cost), rate (both windows checked before either is charged), then S4 decision, loop guard, session bound, host bound. A refusal at an earlier step stores nothing.
- Outcomes: `too_large`, `ambiguous`, `rate_limited`, `saturated` (session and host alike: names nothing about other sessions), `held{loop_guard}`. With nobody able to answer a hold the loop-guard case is `rejected{no_operator}` (same as every would-be hold in S4).
- Memory keyed by (receiving session, sender, id): a repeat never answers with another session's traffic. `rate_limited`, `saturated`, `too_large` are NOT remembered (transient); everything else is, so an operator-rejected or expired id resent within 10 minutes gets the ORIGINAL outcome (e.g. `held`, with the original expiry) and creates no hold.

## Deviations from the design / code wins
- S5.3 "10-minute idle lifetime": pairs with an empty one-minute window are dropped when the table is full (they hold a full allowance anyway, so no fresh allowance is handed out); live pairs are never evicted. Since the host total admits at most 60 pairs/minute the table cannot fill with live pairs in practice. `PAIR_IDLE_SECS` is exported but not otherwise used.
- The body check in `submit_peer_message` now precedes `validate()`, so an over-size body is `rejected{too_large}` instead of `PeerSubmit::Invalid`. Flag off still answers `unavailable` first.
- The turn budget counts admitted peer MESSAGES (queue entries), not started turns: never lower than the turn count (conservative). Released-then-drained messages count too but are never blocked by the budget (a human approved them). Notices are not yet in the budget (watches/notices are a later packet).
- An enqueue that fails after admission (`untrack`) frees the reservation and forgets the remembered id but does not refund one budget unit.
- A remembered `held` is not updated when the hold is later released/expired; a live entry is answered from its current state (packet 4), otherwise from memory.
- Existing tests: `store()` in `peer_admission_tests.rs` and the actor test support use `PeerAdmissionState::unmetered()` (rate lifted) so store-bound tests can send 65 messages; `g_rows_that_left_the_queue...` calls `human_prompt()` between messages because the new 20-turn budget would otherwise hold the 21st.
- Not red-then-green: no old behaviour existed for ingress; the one changed old behaviour (21+ admitted peer messages) is covered by the adjusted test above.

## Not verified
- No end-to-end test with two real `SessionActor`s sharing `host_ingress()` (state-level two-session tests only). The human-prompt hook is not covered by an actor-level test; it is a two-line call under `is_human_intent()`.
- Frame check has no caller yet (transport packet).
