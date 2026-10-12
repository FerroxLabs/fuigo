# R-xs-p3: peer messaging packet 3 (receive path, in-process only)

Branch `strike/xs-p3` from `hub/strike/land-batch8` 2ab15eab. Design: DESIGN v2 (packet-3 row, S1.1-S1.7, S2.3). No listener, socket or model tool. With `features.peer_messaging` off (default) `deliver_peer_message` refuses before any command is sent and nothing is queued; no existing code path changes behaviour.

## Built
- `InputAuthority::PeerUntrusted`, `AnalyticsClass::PeerMessage`, `CompactionClass::ConversationalPeerAnchor` (`fuigo-agent-lifecycle/.../turn_lifecycle.rs`).
- `PromptOrigin::PeerMessage { message_id, from }` (`session/mod.rs`): prompt id prefix `peer-message-`, queue policy VisibleProtected, `is_peer()`.
- `session/peer_message.rs`: `wrap_peer_message`, `escape_attr`/`escape_body`, fixed note `PEER_NOTE`, `peer_messaging_enabled`, `PeerAdmission`/`PeerRefusal`. `acp_session_impl/peer_admit.rs`: `admit_peer_message` (flag, `Envelope::validate`, wrap, protected verbatim row kind `peer_message`, wake). `MessageDeliveryHandle::deliver_peer_message` + `SessionCommand::PeerMessage` + run_loop arm.
- Mid-turn: `promote_parent_agent_messages` also takes peer rows (protected rows only); `InterjectionAuthority::Peer` (new, in `fuigo-interjection-core`) carries the origin through promotion and the stranded-entry fallback; `format_peer_interjection` returns the wrapped text untouched (no truncation, no sanitiser, no skill scan).
- Transcript: `SyntheticReason::PeerMessage` (`peer_message`), `ConversationItem::peer_message`; `starts_prompt_turn` true (fail-safe boundary, same as `AgentMessage`).
- Pager (needed to keep a peer row un-editable and non-adopted): `queue_pane.rs` kind `peer_message` is PROTECTED; `prompt_origin.rs::is_wake_prompt` includes it.
- `fuigo-peer`: `BIDI_CONTROLS` made `pub` (re-used for the body rule). `fuigo-shell` depends on `fuigo-peer` (Cargo.toml, Cargo.lock edited by hand).

## Rules (Hetzner lane xs3; red = mutation of the fix, reverted; green = test passes)
| Rule | Test | Red / green |
|---|---|---|
| S1.1 | `acp_session::peer_admit::tests::s1_1_admitted_row_is_a_protected_peer_origin_with_peer_authority`; `s1_s2_peer_turn_is_inert_text_and_recorded_as_peer_message` (policy recorder == PeerUntrusted) | green (no red run) |
| S1.2 | `slash_authority::tests::s1_2_peer_untrusted_slash_is_inert_for_every_command` (every builtin by name, plugin/skill names, `/compact`) and the turn test | red: peer arm mapped to HumanIntent -> test failed at `slash_authority_tests.rs:72`; green |
| S1.3 | `prompt_parser::tests::s1_3_file_expansion_is_an_allow_list_peer_and_model_authored_are_excluded`, `s1_3_peer_prompt_does_not_expand_file_references_or_links`, turn test (`@/etc/passwd` not read) | red: PeerUntrusted added to the allow-list -> both failed (`prompt_parser.rs:640`, `:677`); green |
| S1.4 | turn test: `hook_rx.try_recv().is_err()` for three peer turns | red: gate condition without PeerUntrusted -> `S1.4: no UserPromptSubmit gate for peer text`; green |
| S1.5 | `fuigo-sampling-types` `s1_5_peer_message_has_its_own_reason_and_round_trips`, `s1_5_old_transcript_without_peer_kind_still_loads`; `peer_admit::s1_5_stranded_peer_entry_requeues_as_peer_origin`; `busy_session_gets_the_peer_message_...` (tail item reason PeerMessage); turn test (3 items PeerMessage, none AgentMessage, none user) | green |
| S1.6 | `peer_message::tests::s1_6_*` (closing tag, forged system note, quotes/`>`/`'`/`&` in a name, every attribute, controls/U+2028/9/bidi/ZW, body at the cap) | green |
| S1.7 | `s1_7_a_valid_64_char_name_...`, `s1_7_the_fixed_note_...` | green |
| S2.3 | turn test: raw `!echo forged` with bash meta on a peer block, `!ls` in a body: terminal calls == 0 | red: bash exclusion without PeerUntrusted -> `S2.3: no shell left: 1 right: 0`; green |
| idle wake | `idle_session_is_woken_by_a_peer_message` | green |
| busy session | `busy_session_gets_the_peer_message_at_the_next_safe_point_and_user_rows_keep_their_order` | green |
| flag off | `flag_off_refuses_and_queues_nothing`, `oversize_body_is_refused_and_queues_nothing` | green |

Ordering rule applied (design row 3b: "sibling path ... same queue mechanics"): a peer row is promoted at the next safe point regardless of `follow_up_behavior`, ahead of earlier-queued user rows, which keep their relative order in the queue.

## "The user typed" sites and how the new origin is treated
Almost all key on `is_synthetic()`, `authority.is_human_intent()` or `analytics.is_human_prompt()`; the new origin is synthetic, not human intent, not a human prompt, so these need no change (and are exhaustive matches that false for it):
- `acp_session_impl/turn.rs:566` (invalidate side calls), `:748`, `:839` (redirect kind), `:1191` (task-wake gate clear, deferred completions): human intent only -> not run.
- `turn.rs:1171` PromptSubmitted telemetry: `is_human_prompt` -> not logged.
- `prompt_queue.rs:173` side-call invalidate, `:178` prompt history, `:247` auto-wake preemption: all human-gated -> peer neither writes prompt history nor preempts runtime wakes.
- `prompt_queue.rs:612` (`has_runnable_queued_user_row`), `:865`, `cancel.rs:664` (`had_queued_user_prompt`), `session_mode.rs:173` (plan-mode reconcile), `run_loop.rs:700,729` (task-wake un-suppress, `user_input_generation` bump, hook-block hold release): `!is_synthetic()` -> peer does not count as the user re-engaging.
- `notification_drain.rs:340`, `interjection.rs:79`: human-intent gates -> peer does not clear the wake gate or cancel recaps.
- `hook_dispatch.rs:416` `should_enforce_prompt_block`: human only. CHANGED: `turn.rs` no longer dispatches `UserPromptSubmit` for `PeerUntrusted` (like `ModelAuthoredUntrusted`), `turn.rs:~975`.
- Changed: direct bash (`!cmd`) skipped for `PeerUntrusted` (`turn.rs:~596`; it was skipped only for model-authored); orphan-image placeholder recovery and inline base64 image extraction skipped for peer (`turn.rs:~1066`, `~1097`).
- Changed: title. The first-prompt title generator and search index are fed by the `ContentChunk` the turn persists; for a peer turn it is sent empty (`turn.rs:~1166`), so a peer cannot title the session. The 3rd/6th-turn title refresh is skipped when the completed turn was a peer turn (`run_loop.rs:~2467`).
- Permission prompts "user is present": no site in the shell keys on the origin. Prompts are answered by the driving client only; a peer turn changes no permission state (S2.1/S2.2/S2.4 are packet 4). Not changed here.
- `analytics`/`compaction` classes are carried in the policy but have no readers beyond the above.

## Deviations / choices
- The flag is read at call time from the process sources (`FUIGO_PEER_MESSAGING`, registry default off) via `Feature::resolve(FeatureSources::from_process_env)`; the config-file / requirements tiers are not plumbed into `SessionActor` (spawn args and ~6 literal constructors). Enabling only in config fails closed (refuses). The packet that opens a listener must plumb the full resolution.
- `from-name` that fails `is_valid_display_name` (including 65+ chars) is shown as `""`, not cut to 64: the envelope's own `validate` already refuses it upstream, and truncation would invent a name. `from-auto-title` is emitted only when valid.
- The design text says "exhaustive match" for S1.3; I used an ALLOW-list `matches!` (excludes unknown authorities by construction) because the brief asked for unknown authorities to be excluded; both are compile-visible.
- Hold reasons, rate limits, message-id idempotency, hop/denial stamps in the wrapper (`denied_recently`, `from-operator`) are later packets and not rendered.
- No wake of in-flight tool waits (`ParentMessageSignal`) for peer messages: its interrupt hint is worded for a parent; a busy session blocked in `get_task_output` sees the peer message when the wait returns. Follow-up.
- Compaction: a peer message is NOT an anchor (`compaction_utils.rs` anchors only `AgentMessage`) and gets no model-side `AGENT_MESSAGE_MODEL_LABEL` (the wrapper carries its own note). It keeps its reason while it stays in history; whether the summary keeps its content is the summariser's.
- `from_prompt_id("peer-message-...")` maps to `PeerMessage` so the pager classifies it as server-initiated; a client could therefore send a prompt with that id and get a (more restricted) peer origin. S2.6 (public ACP path cannot produce a peer origin) belongs to packet 8.

## Tests run on Hetzner lane xs3 (all via slot-run.sh)
- `fuigo-shell --lib session`: 4300 passed, 1 failed (`agent::config::tests::resolve_credentials_empty_api_key_falls_through_to_session`: ApiKey vs SessionToken; credentials/env, no file touched by this packet; not re-run on the base).
- `fuigo-shell --lib acp_session`: 1359 passed, 0 failed (was 1352 + 7 new).
- `fuigo-peer` 18, `fuigo-sampling-types` 328, `fuigo-interjection-core` and `fuigo-agent-lifecycle` (19 and 5 tests, all pass), `fuigo-extra-ca` all, `fuigo-auth --test secret_debug_guard` 2: all pass.
- `fuigo-pager --lib peer_message`: 2 passed (queue pane protection, wake prompt).
- clippy on shell, peer, sampling-types, interjection-core, agent-lifecycle (`--all-targets`): no warning in touched files after one fix (`== false` in a new test).

## Not verified
- Persisted-chunk replay in the pager UI (a resumed session renders the peer row's user chunk as before; a peer mark in the TUI is a later packet). Conversation-level resume is covered by the serde tests, not by an end-to-end session resume.
- Windows/macOS builds; full workspace and full pager suites; `s1_6` against a real client.

## Round 2 (audit fixes)
Tip: see the commit that carries this section. Base `2ab15eab` unchanged (`hub/strike/land-batch8` has not moved).

1. HIGH client-supplied `peer-message-` id (reachable with the flag OFF). RED: `session::tests::client_prompt_id_never_yields_the_peer_origin`, `acp_session::slash_authority_turn_tests::r2_client_supplied_peer_prompt_id_is_an_ordinary_user_prompt` failed with the old mapping. GREEN after: new `PromptOrigin::from_client_prompt_id` (`session/mod.rs`) maps the reserved peer prefix to `User`; `SessionCommand::Prompt` (`run_loop.rs:683`) and the id-only wrapper `InputOrigin::from_prompt_id` (`queue_mutation.rs:10`, used by `QueueInputRequest::from_legacy_prompt_id`) use it. The id stays opaque (no rejection: rejecting could break a client that reuses ids). The peer origin now exists only via `admit_peer_message` / the stranded-entry rebuild (`interjection.rs:78`). The two other shell uses that read an origin back from an id were changed to carry the real origin: `turn.rs` goal-round check uses `input_origin.is_synthetic()`; the title-refresh skip uses a new `TurnCompletionMsg.completed_by_peer` set from the request origin in `turn_task.rs`. `PromptOrigin::from_prompt_id` remains for DISPLAY only (pager `prompt_origin.rs`, `tracker.rs:1809`; tests): a client cannot reach an authority decision through it. Queue rows are in memory only (no persisted queue exists), so there is no stored row to reload; a resumed transcript restores peer from `synthetic_reason` (stored kind), never from the id. Test: the client prompt runs the `UserPromptSubmit` hook, gets `HumanIntent` (slash and `!` handling key off that authority, covered by the existing human-authority tests) and expands `@file`; real admit still gives `PeerMessage` (`peer_admit_tests`, unchanged and green).
2. OTHER reserved prefixes a client can still choose (NOT fixed, existing behaviour, for the coordinator). All in `session/mod.rs` `from_prompt_id`: `task-completed-` :146 and `subagent-completed-` :150 and `workflow-completed-` :164 and `scheduler-fired-` :174 (RuntimeControl: `UserPromptSubmit` runs but a Block is not enforced, `hook_dispatch.rs:416`; user text also gets no human slash gate); `parent-message-` :154 (ModelAuthoredUntrusted: hook skipped, `turn.rs:~977`); `notifications-` :168, `goal-summary-` :170, `goal-classifier-nudge-` :172, `plan-resume-` :176 (RuntimeControl, hidden queue, user echo hidden for the first three). The Prompt arm that consumes them is `run_loop.rs:683`.
3. `hop` is now formatted through a typed `hop_attr(u32)` (`peer_message.rs`); every other attribute goes through `escape_attr`. Test `r2_no_attribute_value_can_carry_quote_angle_ampersand_or_newline` (hostile id/ref, `hop=u32::MAX`) passes; it was green before as well (the hop was already a `u32`), so it is a regression guard, not a red.
4. Queue protection IS enforced in the shell (`editable_queue_meta_matches` / `has_editable_row` in `prompt_queue.rs`, driven by `QueueMutationPolicy`): `r2_shell_refuses_every_queue_mutation_of_a_peer_row` calls the raw handlers (remove, edit, interject/send-now, hold/release, reorder, clear) on an admitted peer row and the row, text and version survive. Guard test, no code change needed.
5. `parse_prompt_with_skills` now drops `Image` and `Resource` blocks for `PeerUntrusted` (tighten-only; other authorities unchanged). RED: `prompt_parser::tests::r2_peer_prompt_drops_resource_and_image_blocks` failed without the guard. Also `r2_admitted_peer_row_is_a_single_text_block`: an admitted row is exactly one Text block (the envelope has no block fields).
6. No rebase needed.

Hooks for a REAL peer turn (unchanged this round): `UserPromptSubmit` does NOT run (`turn.rs:~975-980`, the gate is skipped for `ModelAuthoredUntrusted | PeerUntrusted`); a Block would also never be enforced (`hook_dispatch.rs:416`, human intent only). Hooks keyed to the turn rather than the prompt origin still run: `Stop` / `SubagentStop` (`stop_gate.rs:122,227,236`), `StopFailure` / `StopCancelled` (`turn_end_hooks.rs:59,71`), `PreToolUse` / `PostToolUse` (`extensions/hooks.rs:583`, `hook_dispatch.rs:287`), `PreCompact` (`compaction.rs:1005`). Open owner decision stays open.

Tests (Hetzner xs3, via slot-run): `fuigo-shell --lib acp_session` 1362 pass; `--lib session` 4307 pass; fuigo-peer 18, agent-lifecycle 5, interjection-core 19, extra-ca all, `fuigo-auth --test secret_debug_guard` 2: pass. Clippy on shell: the only warnings in touched files were in my new test and are fixed.
`agent::config::tests::resolve_credentials_empty_api_key_falls_through_to_session`: fails 3/3 on this tip AND 1/1 on base `2ab15eab` (same panic, `config_tests.rs:1473`): NOT caused by this packet (environment-dependent on the build box).

Not verified: the clippy rerun after the 3 test-lint fixes and a re-run of the two suites after that edit (lint-only change in a test file; re-run of `r2_shell_refuses...` below); the pager crate was not re-tested (display-only `from_prompt_id` is untouched); no end-to-end ACP wire test of `session/prompt` (the derivation function and the turn are tested separately).
