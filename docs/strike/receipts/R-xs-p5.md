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

---

# R-xs-p5b: peer audit log (packet 5 part B; S8.1-S8.4)

Branch `strike/xs-p5b`, base `d94f2cb1`. New module `fuigo-shell/src/session/peer_audit.rs` (+ `peer_audit_tests.rs`).

## Line format
File `<fuigo home>/peer-audit.jsonl` (0600; Windows: `fuigo_secrets::owner_only::restrict_to_owner`), one rotated file
`peer-audit.jsonl.1`. Every line has EXACTLY these 11 keys, always present, `null` when unknown (a test fails if a key is
added or missing):

    {"t":1800000000,"msg":"m-1","from_host":"0123456789abcdef0123456789abcdef","from_session":"sender-session","to_host":null,"to_session":"recv-session","mode":"acceptEdits","bytes":42,"outcome":"held","reason":"mode_mismatch","count":1}

- `t` unix seconds (for an aggregate line: the first event in the minute, not before the minute start).
- `outcome`: admitted, held, released, reheld, expired, rejected_by_operator, refused, saturated, duplicate, suppressed.
- `reason`: the serde name of the HoldReason / RejectReason, else null. `mode`: the sender's CLAIMED mode (null when only the key is at hand).
- `bytes`: body length only. `count`: 1, or the aggregate count. `to_host` is null until the transport packet gives the receiving process a host id.
- Never: body, any name or title, token, path, address string. Not hashed ids: ids are written RAW (random host id; session id is already a file name in the same home; the log exists to be matched against transcripts and the peer's log).
  Every string is restricted to `[A-Za-z0-9._:-]`, 64 chars; anything else (message id is peer text) becomes `sha256:<16 hex>`.

## Call sites (all in `session/peer_admission.rs`, inside the existing decision points; no decision changed)
`PeerAdmissionState::submit`: refuse (policy/flag/etc.) -> refused/saturated, same id different body -> refused/ambiguous,
repeat -> duplicate, over session bounds -> saturated, hold -> held+reason, admit -> admitted.
`release`: refused/unavailable, released. `reject`: rejected_by_operator. `Inner::sweep`: expired. `Inner::check_at_drain`:
expired, reheld+reason, refused+reason, refused/unavailable. `recheck_queued` (untracked row): refused/unavailable.
`untrack` (enqueue failed after an admit): refused/unavailable.
Other edits: `session/mod.rs` (module), `acp_session_impl/spawn.rs` (one line: `PeerAdmissionState::for_session(id)` names the receiver; `peer_admit.rs` is NOT touched).

## Bounds
- 8 MiB per file, rotate at cap minus 64 KiB headroom, one rotated file: total under 16 MiB.
- Rejections (refused/saturated/duplicate) of one (pair, outcome, reason): one line per minute with a count. Table capped at 256 keys; overflow counted into one `suppressed` line per minute. Individual events (admitted, held, ...) capped at 600/minute, overflow into the same `suppressed` line. Worst case about 860 lines/minute for the whole host.
- Queue to the writer: 1024, then dropped with a counter (`Sink::dropped`). Write errors counted (`Sink::write_errors`); ONE `tracing::warn` per 5 minutes with the error kind only. (`/peers` display of the counters is a later packet.)
- Writes never block the session: `AuditCtx::emit` is `try_send` only; the admission mutex is held only for that. One writer thread per home per process. Flag off: `emit` returns first; no thread, no directory, no file.
- Cross-process: `O_APPEND`, `O_NOFOLLOW`, one `write_all` per line; the handle is re-opened when the path's inode changed; rotation takes `fuigo_config::fs_atomic::lock_file_for_write(<home>/.peer-audit.lock)` and re-checks the size under it. `rename` replaces the old rotated file atomically.

## Verification
See the tip commit report for test totals. Canary test (`canary_and_exact_field_set_across_every_outcome`): admit, duplicate, hold, release, reheld, operator reject, expire, refuse, saturate with a marker in body and name, plus the real release tokens: zero hits in every file under the temp home; only `peer-audit*` / `.peer-audit*` files exist (the held store has no on-disk state).
Two-process test re-executes the test binary twice, 100 lines each, cap 64 KiB: 200 distinct lines survive, rotated once.

## Not verified / limits
- Windows owner-only ACL path (`restrict_to_owner`) is compiled-in but UNRUN. `O_NOFOLLOW` is unix only.
- The existing session-title log line is untouched (design section 7). No debug log is added by this code.
- The session-level canary (full actor) was not added; the canary runs at the admission-state level, where every call site lives.
- Part A may add new outcomes (rate limit, totals); they need one `audit_*` call each at their decision points.
- Receiving `to_host` is null (no host id exists in this tree). Rotation under a stalled lock holder: the lock helper gives up after its own wait and the line is dropped (counted).

---

## Merge (parts A + B on `strike/xs-p5`)
Normal merge of `strike/xs-p5b` into `strike/xs-p5a`; the two originals are kept beside this file.

Conflicts and resolutions
- `peer_admission.rs` `check_at_drain` re-hold: kept A's `hold(.., p.ticket.take())` and B's `audit_reheld` before it.
- `peer_admission.rs` `store`: kept A's whole body in A's order (decision, loop guard, ambiguous/duplicate, session bounds, host ledger) and put B's `audit_*` calls beside each outcome.
- `peer_admission.rs` `untrack`: B's `Refused/unavailable` audit when a queued row is removed, then A's `ingress.forget(..)`.
- `spawn.rs`: A built `with_host(host_ingress())`, B built `for_session(id)`. `for_session` now builds on `with_host(host_ingress())` outside tests (private ingress in tests) and sets the audit receiver.
- Build fix: `with_host` also initialises B's `Inner.audit`.

Audit call per part-A outcome (`peer_admission.rs`, no decision changed)
| Outcome | Line | Call |
|---|---|---|
| `too_large`, `rate_limited` (pair and host) | 618 | `audit_refused` on the ingress `Refuse` (outcome `refused`, reason as in the answer; aggregated) |
| replay-memory answer | 626 | `audit_duplicate` (outcome `duplicate`; aggregated) |
| loop-guard hold | 687 (decision at ~641) | `audit_hold` with reason `loop_guard` (the shared hold branch) |
| session `saturated` | 676 | `audit_refused(Saturated)` |
| host-total `saturated` | 681 | `audit_refused(Saturated)` |
No new outcome name and no new JSON key: the new reasons ride the existing `refused`/`duplicate`/`held`/`saturated` outcomes (`refused` and `saturated` and `duplicate` are aggregated per sender/receiver/outcome/reason).

New/changed tests (`peer_audit_tests.rs`, `peer_admit_tests.rs`)
- `part_a_outcomes_are_audited_with_the_documented_keys_only`, `host_total_saturation_is_audited`: exact 11-key set, reasons present, no body or name text.
- `flood_100k_rate_limited_bounds_tables_and_audit_file`: 100,000 rate-limited envelopes; ingress tables within bounds and the audit file under 5,000 lines / 2 MiB.
- `merged_loop_guard_then_human_reset_is_audited_without_text`: real `SessionActor`; 20 admitted, 21st `loop_guard`, `human_prompt()` resets, matching log lines, no text marker. The reset is the `human_prompt()` call itself, not the full prompt path.
- Part B's canary and write-failure tests: ingress now lifted (`unmetered`), the oversize "saturated" case became session-fill (a 1 MiB body is now `too_large`), and the write-failure loop resets the turn budget each message.

Not verified (merged)
- The actor test uses a private ingress (tests only); two real actors sharing `host_ingress()` are still untested. Frame check still has no caller. Windows ACL path unrun. `to_host` null.
