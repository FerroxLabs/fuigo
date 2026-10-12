# R-xs-p7: peer messaging packet 7 (laundering refusal, S7)

Branch `strike/xs-p7` from `hub/strike/land-batch22`. Everything is behind `features.peer_messaging` (default off).

## Built
- S7.1 `fuigo-workspace/src/permission/peer_denials.rs`: `DenialLog` (ring of the last 16 denials, kind + hash, with a mono-clock time), held inside `PeerInfluence` (the object a session already shares with its subagents, so subagents use the root's ring). In memory, not in the transcript. `PermissionHandle::request` wraps the old body (`request_decided`) and records a denial when the decision is `PolicyDeny` (policy, `dontAsk`, packet 6 guard, laundering), `Reject` or `FollowupMessage` (the human). A manager failure and `Cancelled` are not denials.
- S7.2 send side: `peer_message::stamp_outgoing(&mut Envelope, &DenialLog, now)` fills `denied_recently` with the denials younger than 30 minutes (inject `now`). With none, the field is absent (`skip_serializing_if`), so envelope bytes are unchanged. Receive side: `AdmissionInputs.sender_denied` (a non-empty stamp, or a refused sender) makes `decide` return `Hold(SenderDenied)` in every mode and under policy `accept` and `hold`; policy `refuse` still refuses; nobody able to answer -> `Refuse(NoOperator)`. The held row has `HeldSummary.detail` = "the sender was recently denied: <kinds>" (kinds from the audit alphabet, at most 32 chars, else `other`; no hash). A human release works as for any hold.
- S7.3: carried denials are kept by `DenialLog::carry` when a message enters the session (`enqueue_admitted_peer_row`), cleared by `/peers clear-influence` (`clear_peer_influence`). In `PermissionHandle::request`, before the packet 6 guard and every approving path, a request whose kind and hash match is denied `PolicyDeny("Denied (laundering_refused): ...")`. The hit is queued; `flush_laundering_hits` (after each permission decision and on `TakeNotices`) writes an audit line (`laundering_refused`, message id + tool kind) and a `NoticeKind::LaunderingRefused` notice. The sender notice goes into the existing notice ring only: no in-process notice path to a sender exists until the transport packet.
- S7.4 behaviour: `SessionActor::refuse_peer_message(&RefusePeerMessageArgs)`: available only with the feature on and a received peer message (`refuse_peer_message_available`); unknown id -> `Err`, no panic; the reason is cut to 200 characters and escaped for display, never audited; audit line `model_refused` (ids only); `ModelRefused` notice; the sender goes in `refused_senders` and every further message from it is held with the SAME reason `sender_denied` (row text "your session refused an earlier message from this sender"). The runtime note (`PEER_NOTE`) now tells the model to use the tool when a peer says it was denied something and asks for it here, including shell and network actions.
- S7.5 fixture only: `fuigo-shell/tests/peer_laundering/{prompts.json,README.md}` (20 prompts; run on Hetzner with a mock or recorded model in packet 14; no model is called).

## Not built (cut, with reason)
- Registering `refuse_peer_message` in the model's tool list: the `ToolInput`/`ToolOutput` variants, normalisation, presentation and telemetry matches touch about ten files in four crates, and neither `list_agents` nor `send_message` is registered yet either. The behaviour and gate are built and tested at the actor; the registration belongs with the packet that registers the tool set.
- `/peers clear-influence` clearing carried denials is a one-line call in `clear_peer_influence`; it is covered by `DenialLog` tests, not an actor-level test.
- Red-first runs: the new code and tests were written together; no red run was kept.

## Hash normalisation (what "the same action" means)
Hash = `sha256:` + first 16 hex of SHA-256 (as the audit log). Kind: `bash`, `read`, `grep`, `edit`, `web_fetch`, `web_search`, `mcp:<tool>`, `agent_message`, `tool:<id>`. Target: bash = whitespace runs collapsed to one space, ends trimmed (case, quoting, order kept); paths = made absolute against the request cwd and lexically normalised (grep adds its glob; a multi-file edit hashes its sorted paths); web_fetch = trimmed, trailing `/` removed; web_search = whitespace collapsed, lower-cased; MCP = canonical JSON (keys sorted).

## Stated limits (S7.5, word for word)
S7.1-S7.3 catch the same action re-sent by a cooperative host; a reworded action or a hostile same-user process is not caught. Refusing a denial disclosed only in prose depends on the model; it is measured by a scripted behaviour suite (20 laundering prompts, each must end in a refusal and a human-visible row), not proven.

## Older builds
No wire change: `denied_recently` (with `deny_unknown_fields` on `DenialStamp`) has been in the envelope since packet 1, and is omitted when empty. A build that has the envelope accepts it; a build without peer messaging has no listener. The design's `denied_recently: true` is represented by a non-empty list.

## Tests (counts at the end of the run, see the report)
fuigo-peer: `s7_2_stamp_is_absent_when_empty_and_malformed_stamps_are_rejected` (bounds tests from packet 1 stay). fuigo-workspace `peer_denials_tests`: `s7_1_ring_keeps_last_16_in_order`, `s7_1_hash_is_stable_normalised_and_holds_no_text`, `s7_1_paths_resolve_against_the_working_directory`, `s7_2_stamps_present_for_30_minutes_then_gone`, `s7_3_carry_is_deduplicated_bounded_and_cleared`, `s7_3_matching_request_is_denied_in_every_mode_and_others_pass` (11 modes incl. allow-all and yolo; different and reworded commands pass), `s7_1_denials_by_policy_and_guard_are_recorded_allows_are_not`, `s7_1_subagent_handles_share_the_root_ring`. fuigo-shell: `s7_2_denied_sender_is_held_in_every_mode_and_policy`, `s7_2_stamped_message_is_held_with_a_kind_only_row_and_rejected_without_an_operator`, `s7_2_send_side_stamps_for_30_minutes_and_leaves_no_trace_otherwise`, `s7_4_refused_sender_is_held_for_the_rest_of_the_session_others_are_not`, `s7_3_released_message_carries_denials_and_a_matching_request_is_denied_and_reported`, `s7_4_refuse_tool_availability_happy_path_unknown_id_and_sender_held`.

## Round 2 (permission side)

A denial now holds a SET of keys (kind + truncated hash; at most 8 per denial, lexical spellings first, symlink spellings after,
the extras dropped first). A request matches a carried denial when ANY of its keys equals a carried key. Ring stays 16 denials;
an envelope still carries at most 16 stamps (each denial's first key goes first).

| Tool kind | Keys (one per target) | Normalisation |
|---|---|---|
| bash | 1 | whitespace collapsed, trimmed |
| read | one per file of `read_targets` (else the path) | packet 6 `resolve_model_path` (quotes, `~`, display cwd), lexical normalise, plus symlink-resolved spelling |
| edit | one per patch target (else the path) | same path rule |
| grep | path spellings x glob | same path rule |
| web_fetch | 1 | scheme and host lower-cased, trailing `/` removed |
| web_search | 1 | whitespace collapsed, lower-cased |
| mcp:<tool> | 1 | canonical JSON, integral numbers as integers |
| agent_message | 1 | subagent id |

Skipped as targetless (never recorded, carried or matched): `Read(None)`, `Tool(id)`, unparseable or empty patch, empty command,
query, URL or subagent id, a carried key with an empty hash.

Other changes: the hub-routed path (`enforce_hub_policy`) matches the carried list and records its refusals; a prompt shown and
then dismissed is a denial, a prompt error or never-shown prompt is not; a repeat key refreshes its time; `carry` never evicts
(newest dropped and counted, `carried_stats()`); the packet 6 guard runs before the laundering match; keys are computed only when
a list is carried or a denial is recorded, and `has_carried()` is an atomic load (no lock).

Tests (fuigo-workspace): `p7r2_same_action_pairs_match_and_different_ones_do_not`,
`p7r2_targetless_requests_have_no_key_are_not_recorded_and_never_match`,
`p7r2_record_refreshes_a_repeat_and_stamps_cap_at_the_envelope_limit`,
`p7r2_shown_then_cancelled_prompt_is_a_denial_unshown_is_not`, `p7r2_denial_recording_table_over_every_prompt_outcome`,
`p7r2_request_computes_no_keys_for_an_allowed_request_with_nothing_carried`,
`p7r2_peer_guard_text_wins_over_laundering_for_a_protected_write`,
`p7r2_carried_multi_file_read_denies_a_read_of_one_file_through_request`, `p7r2_has_carried_is_an_atomic_flag_that_follows_the_list`,
`p7_hub_path_refuses_carried_denial_and_records_hub_denials`; `s7_3_carry_is_deduplicated_bounded_and_cleared` updated (no eviction).
Hub-routed laundering hits are queued in the log; flushing them to a notice is the shell side.

## Round 2 (session side)

Marker kinds (new `SyntheticReason`s, built like `peer_integrity_tripped`; item kinds in `fuigo-sampling-types`):
- `peer_denial` (sender side): one per recorded denial, tool kind + truncated hash + wall-clock seconds. Last 16 restored. Not cleared by clear-influence (the session's own ring stays).
- `peer_carried_denials` (receiver side): carried list (kind, hash, message id; at most 64) and the refused-sender addresses (S7.4 hold; at most 256). Last marker wins; a `peer_influence_cleared` after it empties both.
- Both are dropped from model requests (`request_builder.rs`), carried through both compaction paths, counted as state markers (not prompts). Feature off: nothing is written (`persist_peer_state` returns first); a stored carried list is still restored (fail closed, as for the flag).
- Older build: both kinds load as `SyntheticReason::Unknown` through the existing `serde(other)` fallback (the load does not fail). Limit: an older build treats an unknown reason as a turn boundary (`starts_prompt_turn`) and its model sees the fixed marker text (kinds, hashes, ids, never a path or command).

What survives a resume: the receiver's carried list and refused-sender holds (restored in `spawn.rs` through `PeerStoredState::apply`, before any request); the sender's ring (entries up to 30 minutes old by wall-clock; a future time counts as now). Limits: `mono_secs()` starts at 0 per process, so in the first minutes of a process a restored entry can stamp slightly longer than 30 minutes (errs toward holding); the `received` id ring (256) is unchanged, so `refuse_peer_message` on an id older than that still returns unknown-id (G2 not built); the release notice does not show counts, the held row does (G3 row only). Markers are written at tool-batch ends and at admission, not at the instant of a denial (a crash inside a batch can lose that batch's denials).

Other round-2 changes: `build_outgoing_envelope(parts, ring, now)` is the only constructor (`stamp_outgoing` is private to the session module; pin test); `/peers clear-influence` clears the carried list and refused senders only after the append ack and only if no peer message re-flagged meanwhile; a subagent never flushes hits (the root flushes them); one notice per (message, kind); a `sender_denied` row also lists a co-occurring reason ("; also: mode_mismatch"); held row counts per kind ("bash x2"). Unattended receivers: `MayReturn` already holds; `Auto`/`None` still reject (nobody can release), and the human's clear-influence now lifts the refused-sender hold.

Needed from `peer_denials.rs` (not built there): a monotonic clock that does not start at 0 (for example `mono_secs()` offset by `DENIAL_STAMP_SECS`) so a restored entry's age is exact in a young process.

Tests (shell lib, `session::acp_session::peer_admit::tests::p7s::`): `owner_a_resumed_sender_stamps_its_outgoing_envelope`, `owner_b_resumed_receiver_still_refuses_a_matching_request`, `end_to_end_denial_in_a_stamps_holds_in_b_and_refuses_the_laundered_request`, `clear_influence_clears_carried_only_after_the_ack_and_releases_refused_senders`, `a_subagent_hit_is_left_for_the_root_to_flush`, `a_repeated_laundering_hit_gives_one_notice`; `peer_admission::laundering_tests::s7_2_no_envelope_literal_outside_the_stamping_constructor`, `s7_2_held_row_shows_a_co_occurring_reason`.

## Round 2 (combined)

Merge of the two sides (`c76c982e`): it compiled as it was (no code change needed to build). The first test run found one test that
assumed the old order: `end_to_end_denial_in_a_stamps_holds_in_b_and_refuses_the_laundered_request` expected a `laundering_refused` denial
for a protected file, but the permission side runs the packet 6 guard first (its own pinned test `p7r2_peer_guard_text_wins_over_laundering_for_a_protected_write`),
so B's request is now denied by the guard and the test asserts that, plus that the stamp is carried. Nothing in production code changed for this.

Flaky `p6a_peer_message_after_a_clear_reflags_and_is_stored_after_the_marker`: fuigo-shell lib suite 4 full runs in a row on the merged tip (the
test passed in all 4) and the test alone 20 times (20 passed). It did not fail; the first failure was not reproduced and its panic text is not in any
log kept here, so no cause is claimed and the test is unchanged. (The lib binary run directly also shows `cli_models::tests::auth_path_write_in_the_shared_process_is_refused`
failing because it needs its own process; see the final test lines.)

Changes:
- Sender-side persistence keeps a denial's whole key set: `DenialLog::entries()`; the `peer_denial` marker text is `kind hash [kind hash ...] secs`
  (1 to 8 pairs; one pair is the old text, so older markers still load); `PeerDenialRecord.keys`; restore records the set as ONE denial (`record_keys`);
  `new_denials` compares key sets. Receiver side already stored one `(kind, hash, id)` per key, so every key of a multi-file denial is restored.
- Held row and release notice: counts per kind from the stamp ("the sender was recently denied: bash x2, edit x1") and, when the carried list was full,
  "; N more denial keys were not kept (carried list full)" (N from `carried_stats().overflow`, synced to admission before `ListHeld`/`Release`). `PeerNotice` has a new
  `detail` (human only): the release counts, or the refusal reason. The admission mirror of the carried list now drops the newest when full (it used to evict the
  oldest, unlike the denial log).
- Flush: `persist_peer_state` now flushes first (also with the feature off or for a hub call) and runs after each local permission decision and at the start of
  `handle_bridge_tool_success` and `handle_tool_error` (a hub-routed call returns through one of them), so hub hits give the notice and audit line, and denials are stored
  right after the decision, before the tool batch ends (item 7 done for both paths; a crash between the decision and that append can still lose one denial).
- Received ids: the 256 ring is now a map id -> sender (same bound); beyond it an id is unknown and the sender is NOT held. Exception: a message that carried
  denials stays nameable (at most 64, until `/peers clear-influence`).
- `refuse_peer_message`: the `ModelRefused` row carries the reason (escaped, cut to 200 characters before escaping); the audit line and the sender never get it.
  Unattended: `MayReturn` holds, `Auto`/`None` reject (tested).
- Lint: `is_multiple_of` in the marker parser, an unneeded borrow in `spawn.rs`, an empty struct update in a `request_builder.rs` test.

Tests: fuigo-shell `p7s::`: `p7r2c_a_multi_file_read_denial_keeps_all_its_keys_across_a_resume`, `p7r2c_hub_path_hits_and_denials_are_flushed_when_the_bridge_result_arrives`,
`p7r2c_held_row_and_release_notice_show_counts_per_kind_and_the_overflow`, `p7r2c_refuse_by_id_works_inside_the_bounded_map_and_unknown_beyond_it`,
`p7r2c_refusal_row_shows_the_reason_and_an_unattended_receiver_holds_or_rejects`, `p7r2c_feature_off_writes_no_marker_and_leaves_the_envelope_bytes_alone`; the
rewritten `a_subagent_hit_is_left_for_the_root_to_flush` (one actor, flag on then off) FAILS with the root flush removed (`the root reports the subagent's hit: []`) and passes with it.
fuigo-workspace: `p7r2_a_human_reject_through_a_real_prompt_is_recorded_and_stamps` (ACP client answering reject-once). fuigo-sampling-types: the marker test now covers 10 keys cut to 8.

Limits: an id older than the 256 map and not a denial carrier is unknown-id (nobody is held). A restored sender entry can stamp slightly over 30 minutes in a young process
(`mono_secs()` starts at 0; the offset fix belongs to `peer_denials.rs` and is not built). The sender notice for a laundering hit is still only in the human notice ring.

## Round 3 (permission side)

One recording rule, `peer_denials::records_denial(DenialCause)`, used by `request()` (`is_recordable_denial` maps a resolution to a cause) and by the hub path
(`enforce_hub_policy` maps the internal `(ToolError, DenialCause)` result; no wire change):

| Outcome | request() | hub path | Recorded |
|---|---|---|---|
| policy deny, `dontAsk` deny, packet 6 guard, laundering refusal | Policy | Policy | yes |
| human reject / deny (once, always) | HumanReject | HumanReject | yes |
| human follow-up message instead of approval (the human saying no) | HumanFollowup | HumanFollowup | yes |
| prompt shown, then cancelled by the human | ShownThenCancelled | ShownThenCancelled (a hub reply came from a client) | yes |
| prompt error or timeout | PromptError | PromptError | no |
| prompt never shown / no hub prompt | NotShown | NotShown | no |
| requester gone | RequesterGone | (transport error = PromptError) | no |
| manager failure / permission check join error | ManagerFailure | ManagerFailure | no |

- Stamps (item 2): `stamps()` sends EVERY key of every live denial. Envelope bound `MAX_DENIAL_STAMPS` = `DENIAL_RING` x `MAX_KEYS_PER_DENIAL` = 16 x 8 = 128 (new in `fuigo-peer::limits`, with
  `MAX_KEYS_PER_DENIAL` = 8 moved there; the workspace constant is an alias). Each entry keeps `MAX_DENIAL_FIELD_BYTES` = 128. A real full stamp (longest kind 128 bytes, hash `sha256:` + 16 hex)
  is 185 bytes per entry, about 23.7 KB for 128; with a maximum 32768-byte body the envelope is about 56 KB, under `MAX_FRAME_BYTES` (64 KB). (A hostile 128+128 byte entry would not fit the frame; the frame check rejects it.)
  Receiver carried total: `MAX_CARRIED_KEYS` = 128 (was 64), newest dropped and counted. Fuigo-shell `peer_admission.rs` `mirror_carry` still has a literal `64` that must become `fuigo_peer::limits::MAX_CARRIED_KEYS` (that crate is the other builder's).
- Item 3: a join error while computing the carried-list keys, with a list carried, fails closed with the `laundering_refused` text (kind `(unchecked)`); it is a ManagerFailure, so it is not recorded and queues no hit.
- Item 4: no display signal exists in the prompter (`user_prompted` is set for the whole prompt section), so on `request()` "shown" stays inferred (prompt section ran and the requester stayed); on the hub path a cancel reply proves a client answered.
- Item 5: more than 8 targets => first 7 keys + one `many-targets` marker per tool kind (`MANY_TARGETS_HASH`); the marker survives the cap, and a carried marker matches any request of that kind with more than 8 targets.

Tests: fuigo-peer `p7r3_full_denial_stamp_list_with_maximum_body_fits_a_frame` (128 ok, 129 rejected in `envelope_caps_hold_at_cap_and_cap_plus_one`); fuigo-workspace
`p7r3_hub_denial_recording_table_over_every_outcome`, `p7r3_hub_records_a_guard_denial_but_not_an_unshown_prompt`, `p7r3_hub_key_computation_panic_fails_closed_with_a_carried_list`,
`p7r3_sixteen_denials_of_eight_keys_send_and_carry_all_128`, `p7r3_more_than_eight_targets_use_a_many_targets_marker`; `s7_3_carry_...` now expects 128 carried and 72 dropped.

## Round 3 (session side)

Branch `strike/xs-p7r3s`. Counts, kinds and ids only; no payload text anywhere.

**Items.**
1. Clear window (BLOCKER): after the cleared marker, when memory keeps the lists (re-flag in the window, or the ack failed),
   `rewrite_kept_peer_state` appends a fresh `peer_carried_denials` marker AFTER it (nothing when both lists are empty; a failed
   append marks the state dirty). Restore reads the LAST relevant marker in order (`history_peer_carried`, test
   `p7r3_carried_state_comes_from_the_last_relevant_marker`). Compaction put the carried marker FIRST in the carried tail, so a
   retained cleared marker sat after it; it now goes LAST (`p7r3_compaction_keeps_a_carried_marker_that_follows_a_cleared_marker`).
   Test: `p7r3_reflag_during_a_clear_keeps_the_lists_in_the_stored_history` (interleaving hook, production restore, matching
   request refused, refused sender back).
2. Marker choke point: `fuigo_chat_state::compaction_utils::drop_peer_state_markers` (all five kinds, via
   `is_peer_influence_marker`). Stored history is not touched; compaction still carries the markers.
   Test: `p7r3_summarizer_inputs_hold_no_marker_text_and_compaction_keeps_the_markers`.
3. A failed denial-marker append now un-syncs that entry and the rest (`unsync_tail`); they are written at the next persist
   point. Test: `p7r3_a_failed_denial_marker_append_is_written_at_the_next_persist`.
4. `peer_denial_keys_marker` returns `None` for zero keys (no marker is written); the parser skips a marker with no pair, junk or
   a garbled carried marker. Test: `p7r3_zero_key_denial_has_no_marker_and_a_pairless_marker_is_skipped`.
5. Envelope pin scans the whole text (multi-line literals, `Envelope::<fn>` calls) and pins the first site inside
   `build_outgoing_envelope`; `s7_2_the_envelope_pin_catches_a_planted_second_site` plants fixtures (one-line, multi-line,
   `default()`, `new()`) and checks declarations and comments are not sites.
6. Wall clock rule: age = now_wall - stored (a stored time later than now is age 0); age >= 30 minutes is dropped; a restored
   entry is recorded at `now_mono - age` (saturating at 0), so it never stamps for more than 30 minutes of process time after the
   resume. Test: `p7r3_a_restored_entry_never_stamps_longer_than_the_window_after_resume` (characterization; the code already held).

**History-to-model paths and coverage** (all through `drop_peer_state_markers`):
- request builder `fuigo-chat-state/src/actor/request_builder.rs:91-93` (`ModelRequestHistory::from_raw` + retain);
- `ModelRequestHistory::from_raw` users: `side_call.rs:117`, `memory_flush_window.rs:79`, `prepared_compaction_history.rs:66`, `memory_dream.rs:664`;
- `prepare_conversation_for_summarization` (compaction.rs:1039, memory_dream.rs:900, compaction.rs:1266), `_for_segment` (compaction.rs:1025), `_for_verbatim_summarization` (compaction.rs:277, 374, 1034, 1255; session_recap.rs:143);
- `build_instruction_items` (session_recap.rs, recap paths) now drops them first;
- not a model path: `storage/jsonl/copy.rs:474` (fork copy of stored history; markers must be kept).

## Round 3 follow-up (markers never reach a model)

Rule: a peer state marker (five kinds, `ConversationItem::is_peer_influence_marker()`) is persisted state and is never given to a model.
`ChatStateHandle::get_conversation_for_model()` (fuigo-chat-state `handle.rs`) is the one model-facing read: the stored conversation
through `drop_peer_state_markers`. `ModelRequestHistory::from_raw` now calls the same function. The source pin
`session::model_facing_reads::tests::no_raw_conversation_read_outside_the_allow_list` fails on any new raw `get_conversation()` in
non-test `fuigo-shell/src` code that is not in its allow-list (`RAW_READ_ALLOW`, with a reason per entry); a planted-fixture test proves the pin.
Classes: M = result can reach a model (accessor); S = state logic that must see the markers (raw read kept).

| # | Site (fuigo-shell/src) | Class | Reason / what it feeds |
|---|---|---|---|
| 1 | agent/subagent/mod.rs:1273 | M | forked context for a subagent (becomes the child's model history) |
| 2 | session/acp_session_impl/turn_summary.rs:73 | M | turn summary side call (via `model_facing_reads::turn_summary_conversation`) |
| 3 | session/acp_session_impl/recap.rs:145 | M | /btw side question |
| 4 | session/acp_session_impl/recap.rs:324 | M | recap request (turn count + recap input) |
| 5 | session/acp_session_impl/recap.rs:757 | M | prompt suggestion transcript |
| 6 | session/acp_session_impl/goal.rs:86 | M | goal evaluator transcript (via `model_facing_reads::goal_transcript`) |
| 7 | session/acp_session_impl/goal.rs:496 | M | final response sent to the goal verifier |
| 8 | session/acp_session_impl/goal.rs:1079 | S | read-modify-replace of stored history (removes old goal directives); markers must survive |
| 9 | session/acp_session_impl/memory_dream.rs:126 | M | session-end memory extraction (text is later shown to models) |
| 10 | session/acp_session_impl/memory_dream.rs:897 | M | memory flush snapshot (already filtered by `prepare_*`; accessor makes it explicit) |
| 11 | session/acp_session_impl/tool_calls.rs:552 | M | auto-mode permission classifier transcript |
| 12 | session/acp_session_impl/run_loop.rs:2078 | M | feedback turn texts (leaves the process; doubt means M) |
| 13 | session/acp_session_impl/prompt_build.rs:936 | M | image-describe conversation outline (side model call) |
| 14 | session/acp_session_impl/laziness.rs:399 | M | laziness classifier source items (via `model_facing_reads::laziness_source_items`); this was the audit finding |
| 15 | session/acp_session_impl/title_refresh.rs:93 | M | title refresh input (via `model_facing_reads::title_refresh_conversation`) |
| 16 | session/acp_session_impl/model_switch.rs:100 | S | read-modify-replace of the stored system head |
| 17 | session/acp_session_impl/model_switch.rs:395 | S | read-modify-replace of stored history on agent switch |
| 18 | session/acp_session_impl/model_switch.rs:417 | S | persistence snapshot (chat history jsonl); markers are persisted |
| 19 | session/acp_session_impl/model_switch.rs:472 | S | predicate "has model-minted items"; nothing leaves |
| 20 | session/acp_session_impl/rewind.rs:683 | S | rewind/replay rewrites stored history |
| 21 | session/acp_session_impl/rewind.rs:815 | S | user-turn count for the title watermark |
| 22 | session/acp_session_impl/turn.rs:2425 | S | predicate "memory context block present"; nothing leaves |
| 23 | session/acp_session_impl/turn.rs:2700 | S | read-modify-replace of stored history (stale memory context) |
| 24 | session/acp_session_impl/read_dedupe_hook.rs:220 | S | tool-result presence check; nothing leaves |
| 25 | session/acp_session_impl/session_mode.rs:148 | S | read-modify-replace of the stored system head |
| 26 | session/acp_session_impl/session_setup.rs:155 | S | read-modify-replace of stored history at setup |
| 27 | session/compaction.rs:259 | S | two-pass prefire: indices must align with raw history; the prefix goes through `prepare_conversation_for_verbatim_summarization` |
| 28 | session/compaction.rs:352 | S | prefire cache fingerprint compare against the raw prefix |
| 29 | session/compaction.rs:1249 | S | overflow ladder; both branches go through `prepare_conversation_*`, which drop markers |
| 30 | session/acp_session_impl/tool_dispatch.rs:1026 | S | test-only code (inside `#[cfg(test)]`), not scanned |

Result: 15 M, 15 S. Other chat-state readers (not `get_conversation`): `take_turn_messages` / `take_harness_trace_turns` (run_loop.rs:2304/2308) feed the harness
trace and feedback exports, not a model; `compaction_snapshot` (compaction.rs:1015) feeds compaction, which goes through `prepare_*`.

Tests: `model_facing_reads::tests::{laziness_classifier_input_holds_no_marker, title_refresh_input_holds_no_marker, turn_summary_input_holds_no_marker,
goal_transcript_holds_no_marker}` (RED on the raw reads, green with the accessor), `a_history_without_markers_is_returned_unchanged_in_order`
(no-op proof), `no_raw_conversation_read_outside_the_allow_list`, `the_pin_catches_a_planted_raw_read`; fuigo-chat-state
`p7r4_from_raw_is_a_no_op_for_a_history_without_markers`.

### Stored carried cap

`MAX_STORED_CARRIED` was 64 while the live cap `fuigo_peer::limits::MAX_CARRIED_KEYS` is 128, so restore and compaction cut a full list.
It is now 128. `fuigo-sampling-types` does not depend on `fuigo-peer`, so a compile-time check in `fuigo-shell/src/session/peer_admission.rs` pins
`MAX_STORED_CARRIED`, `MAX_STORED_KEYS` (8 = `MAX_KEYS_PER_DENIAL`) and `MAX_STORED_DENIALS` (16 = `DENIAL_RING`). Stale "64 keys" comment in
`fuigo-workspace/.../peer_denials.rs` fixed. Tests: `p7r4_carried_list_of_128_keys_survives_store_and_restore` (sampling-types) and
`p7r4_a_full_carried_list_of_128_keys_survives_compaction` (chat-state), both RED at 64.

## Close-out after the last focused audit (`grok-xs-p7-r4`, owner decision 55)

The focused run confirmed the cap (128 / 8 / 16 with the compile-time asserts; no second truncation found) and the
filtered model paths, and was NOT-LAND-OK on ONE in-scope finding. Decision 55: fix what is in scope, state the rest,
land without another round.

- FIXED (in scope): `extract_last_user_query` returned the last `User` item, and markers are `User` items, so the
  feedback context without a turn number (`run_loop.rs` about 2081) could carry marker text out of the process. It
  now skips marker items. Test `get_last_user_query_text_skips_peer_state_markers` (chat-state actor tests).
- FIXED (same class, named by the audit): the turn capture taken for traces and feedback (`TakeTurnMessages`) drops
  marker items; the compaction step that reads item 1 as "the original user text" ignores a marker there.
- STATED, not verified by the audit and not changed: the harness trace turns come from a side buffer, not from stored
  history (whether an append can copy a marker was not read); JSONL resume, fork and export paths; a subagent's use
  of history after the filtered read; `prune_conversation` and the image budget before `from_raw`; the source-pin
  test covers `get_conversation()` only, not `get_conversation_item_at`, `snapshot().conversation` or
  `take_turn_messages` (the last is now filtered at its source). Marker text is tool kinds, truncated hashes,
  timestamps and fixed notes: never a path, a command or prompt text.

## Path spelling (decision 63)

Cause: three `p7s` tests failed on macOS (and Windows) but passed on the Linux box. `path_spellings` in
`fuigo-workspace/src/permission/peer_denials.rs` (before this change, about line 165) returned TWO targets for a path
whose resolution differed from its lexical spelling: the lexical form and the symlink-resolved form, and
`denial_keys_for` (about line 245) hashed both. On macOS `/tmp` is a symlink to `/private/tmp`, so every denied file
had two keys (hence 2 stamps instead of 1, 6 keys instead of 3); on Linux the temp paths have no symlink, so the two
forms were equal. Reproduced on Linux by giving the tests a denied file below a symlinked directory
(`peer_admit_tests.rs` `p7s_dir`): 2 vs 1 and 6 vs 3, exactly as on macOS. The key creation, comparison, persistence
and restore already all went through `denial_keys_for`; the fault was the deliberate two-key set, not two code sites.

Rule: ONE function, `path_key_target` (same file), builds the target of a path key: `resolve_model_path`, then
`resolve_following_symlinks` (`dunce::canonicalize` of the path, or of the longest existing ancestor with the rest
re-appended and links followed), then lexical normalisation. One path target is one key. Read, grep, edit and patch
targets all use it; the carried-denial match uses the same keys on both ends (the same machine and user), so a denial of
the link spelling is refused for the real spelling and the reverse (test
`d63_a_carried_denial_is_refused_whichever_spelling_the_sender_or_the_receiver_used`). The cross-session match was NOT
broken before: it matched on any shared key and the resolved key was in both sets; only the key COUNT was wrong.

Final rule (round 3). RECORDING: one key per target, the resolved spelling, or the lexical spelling only when
resolution fails (symlink loop, unreadable link, depth cap of 40, a directory on the path that cannot be searched); one
denied file is one stamp. MATCHING: a request is checked with `match_keys_for` (`match_keys` for a `PermissionRequest`),
which returns BOTH spellings of every path target (the lexical one and the resolved one, when they differ), and it
matches when EITHER equals a stored or carried key. The one-key change alone left a hole: a denial stored under the
lexical key (resolution failed, which a peer can force with a directory mode or a deep missing tail) was not found by
a later request of the same spelling once resolution succeeded through a symlinked ancestor, because the request then
computed only the resolved key. The earlier sentence "the same spelling is still refused" was therefore false for that
case; with `match_keys_for` it is true. Request-side comparison sites: `PermissionHandle::request`
(`permission/manager/mod.rs`, `match_keys` then `match_carried_any`) and the hub path (`hub.rs`, `hub_denial_keys` with
`matching = true` then `match_carried_any`). Recording sites (`KeyBasis::keys`, `hub_denial_keys` with `matching =
false`) stay one key. The sender ring only records and de-duplicates by the recorded key sets; it has no match against a
re-ask. Tests: `d63r3_*` in `permission/manager/peer_denials_tests.rs`; the hole is forced root-proof with a symlink
loop that is then replaced by a real link, and with a missing tail deeper than 40 components that is then created, plus
an unsearchable directory when not root.

Reverse failure: the denial resolved (key R stored) but the request's resolution fails. The request then has only the
lexical key and does not match R. The fault that makes resolution fail (an unsearchable directory, a loop, a too-deep
tail) also makes the tool's own open of that spelling fail while it holds, so the action does not proceed; once the fault
clears, resolution succeeds and R matches. No path was found where the action proceeds.

Old markers: they hold both keys (lexical and resolved), or only the lexical key (a failed resolution before this change).
Hashes are not reversible, so restore keeps them as stored, and
matching is any-key: the resolved key a request now produces is in the old set, so both spellings still match (test
`d63_a_marker_written_before_the_fix_with_both_spellings_still_matches`; a lexical-only marker matches a request by that
spelling: `d63r3_an_old_marker_with_only_a_lexical_key_matches_a_request_by_that_spelling`). Old markers still stamp two keys until they age out
of the 30-minute window.

Limits: a link re-pointed after the denial names a different file (the original file stays refused by any spelling, the
re-pointed spelling is not); hard links are different names and are not unified; case-insensitive file systems are not folded (macOS default
volumes, Windows); a reworded command is still a different action. Windows is NOT claimed fixed: `dunce` drops a `\\?\`
prefix when a plain path exists, but this was not measured on Windows, and the Windows inbox is not in 1.0.25; Windows
is re-measured separately.
