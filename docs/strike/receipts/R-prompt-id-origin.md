# R-prompt-id-origin (1.0.25, tighten-only)

Branch `strike/prompt-id-origin` on `hub`, based on integration `6e4901b2`. Paths below are under `crates/codegen/`.

## Bug
A client-chosen ACP `meta.promptId` was classified by prefix into a `PromptOrigin` (`session/mod.rs`
`from_client_prompt_id`), so a custom client could send `parent-message-...` (hook skipped) or a runtime-control prefix
(hook runs, Block not enforced) and bypass an admin prompt-block hook.

## Senders re-verified (base `6e4901b2`, file:line)
- `task-completed-`: `fuigo-shell/src/tools/notification_bridge.rs:417` (id), `:434` (internal `SessionCommand::Prompt`), `:446` (`admission: Some(TaskWakeAdmission)`); origin consumed by `admit_task_completion_wake(&origin, ..)` in `session/acp_session_impl/run_loop.rs` ~686.
- `subagent-completed-`: `agent/subagent/spawn.rs:482` (id), `:495` (internal Prompt), `:506` (`admission: None`).
- `scheduler-fired-`: only shipped CLIENT sender, `fuigo-pager/src/app/dispatch/queue.rs:632` (`QueueEntryKind::Cron`); entry enqueued at `fuigo-pager/src/app/acp_handler/background.rs:501` from the shell notification emitted at `fuigo-shell/src/tools/notification_bridge.rs:706` (`fuigo/scheduled_task_inject_prompt`).
- `plan-resume-`: `session/acp_session_impl/tool_calls.rs:2112-2116` via `queue_input`.
- `parent-message-`, `workflow-completed-`, `notifications-`, `goal-summary-`: explicit origin on other paths. `goal-classifier-nudge-`: no creator found.
- Headless / subagent child prompts (`agent/subagent/attempt_runner.rs:89`) send UUIDs; they pass `origin: None` (= user prompt).

## Fix
1. `SessionCommand::Prompt` gains `origin: Option<PromptOrigin>` (`session/commands.rs`). `run_loop.rs` uses `origin.unwrap_or(User)`; the id is never consulted.
2. Internal senders set it: `notification_bridge.rs` (`TaskCompleted`), `subagent/spawn.rs` (`SubagentCompleted`), plan-resume via `QueueInputRequest::from_input_origin(.., InputOrigin::new(PlanResume))` (`plan_resume_request` in `tool_calls.rs`).
3. ACP boundary (`agent/mvp_agent/acp_agent.rs`, both the send_now and the queued `HumanPromptContent` paths, new field `HumanPromptContent::origin` in `session/message_delivery.rs`): `cron_fire_tickets::client_prompt_origin(session, prompt_id)` = `User`, or `SchedulerFired` for a redeemed ticket. `PromptOrigin::from_client_prompt_id` now always returns `User`.
4. `persist_host_turn_user_echo` takes the stored origin instead of the id; the goal round-end check (`turn.rs` ~1450) requires the stored origin to be synthetic as well as the id.

## Cron ticket design (`session/cron_fire_tickets.rs`)
- On `ScheduledTaskFired` the shell mints a random single-use ticket (UUIDv4, 128 bit), keeps it in memory with the session id, and adds it to the inject notification as `fireTicket`. The leader forwards the payload unchanged (`leader/server.rs` ~2519 `payload.clone()`), so it survives the single-driver route.
- The pager stores it on the queued cron row (`QueuedPrompt::fire_ticket`) and sends the prompt id `scheduler-fired-<ticket>` (prefix kept, so pager display classification is unchanged). The shell accepts `SchedulerFired` only for a live ticket issued to that session, once.
- Bounds: at most 256 unredeemed tickets process-wide (oldest evicted first); TTL 2 hours (a fire can wait behind a long turn); in memory only, never persisted. Unknown, reused, expired, foreign-session or old-style ids are an ordinary user prompt, never an error. No `Debug` derive on the entry (field names `ticket`; `secret_debug_guard` passes).

## Mixed versions
- Old pager + new shell: the pager ignores `fireTicket` and sends `scheduler-fired-<uuid>`; the shell treats it as a user prompt. Consequence: cron fires run as user prompts (hook runs and can block, shown as an ordinary user prompt in the transcript, counts as user re-engagement) until the pager is updated.
- New pager + old shell: the pager finds no `fireTicket`, keeps the old generated suffix; the old shell classifies by prefix as before. No change.

## Remaining `from_prompt_id` callers (display only unless noted)
- `fuigo-pager/src/acp/tracker.rs:1809`: scrollback echo hiding. `fuigo-pager/src/app/acp_handler/prompt_origin.rs:5,15,85`: pager synthetic-turn display classification.
- `fuigo-shell/src/session/acp_session_impl/turn.rs` ~1450: `id_origin` for goal round-end; ANDed with the stored origin, so a client id cannot make a turn look synthetic.
- `turn.rs` `user_echo_mode`: `is_interject_fallback(prompt_id)` id-prefix check chooses persist-only vs broadcast echo (display only; open item below).
- Test-only: `InputOrigin::from_prompt_id`, `QueueInputRequest::from_legacy_prompt_id` (now `#[cfg(test)]`), `turn.rs` `handle_prompt` (cfg test), `prompt_mode_transition_tests.rs`, `session/mod.rs` tests.

## Tests (Hetzner lane `pido`)
RED on base `d7444983` (test only): `session::tests::client_prompt_id_is_always_a_user_prompt` FAILED at `assertion left == right failed: task-completed-x-1` (`session/mod.rs:326`); all ten prefixes are covered by the loop.
GREEN at `cf1b8bb4` (after the last edit): `acp_session` 1365 passed; `session` 4316 passed; `agent` 1829 passed; `tools` 197 passed; pager `queue cron scheduler` 431 passed; `fuigo-extra-ca` all ok; `secret_debug_guard` 2 passed; clippy: no new warnings in touched files (remaining ones are pre-existing, e.g. `acp_agent.rs:3046` items-after-test-module).
New tests: `session::tests::client_prompt_id_is_always_a_user_prompt`; `r3_every_reserved_prefix_from_a_client_is_an_ordinary_user_prompt` (hook runs, HumanIntent, `@file` expands, stored as user turn); `r3_cron_fire_with_an_issued_ticket_is_recorded_as_scheduler_fired`; `cron_fire_tickets::tests` (once, forged, old-style, foreign session, expiry, bound, boundary origin); `task_wake_prompt_carries_an_explicit_task_completed_origin`; `scheduled_task_inject_notification_carries_a_redeemable_fire_ticket`; `subagent_completed_prompt_carries_an_explicit_origin`; `plan_resume_request_has_the_plan_resume_origin_whatever_the_id_says`; pager `cron_prompt_echoes_the_shell_fire_ticket_in_the_prompt_id`, `cron_prompt_without_a_ticket_keeps_the_prefix_for_display`.

## Open items (not changed)
- Hook enforcement for runtime-control origins is unchanged: `fuigo-shell/src/session/acp_session_impl/hook_dispatch.rs:412-417` (`should_enforce_prompt_block` requires human intent), so internal wake origins still run the hook observe-only.
- `is_interject_fallback(prompt_id)` in `turn.rs` `user_echo_mode` still reads the id (display: persist-only vs broadcast echo).
- The peer-adjacent files `session/message_delivery.rs` and `message_delivery_tests.rs` each got a one-line `origin` field edit.

## Round 2: the fire ticket is bound to the prompt text
Finding (HIGH, grok r1a): the ticket was a bearer capability. A client receiving `fuigo/scheduled_task_inject_prompt` could redeem it once through `session/prompt` with text of its own and get `SchedulerFired` (a `UserPromptSubmit` Block not enforced).

Fix (`session/cron_fire_tickets.rs`, `agent/mvp_agent/acp_agent.rs`, `tools/notification_bridge.rs`):
- At mint the shell stores SHA-256 of the exact text the pager sends, next to the session id. `scheduled_prompt_text(prompt, task_id, human_schedule)` is `fuigo_tools::reminders::format_scheduled_task_prompt(prompt, task_id, None, human_schedule)`: the very call the pager makes in `format_cron_prompt` (`dispatch/queue.rs`), so both sides agree byte for byte.
- Canonical form at redeem: the incoming `session/prompt` blocks must be EXACTLY ONE `Text` block; its `text` (meta ignored) is hashed. Zero or several blocks, any image/resource block, split text, or different text => the ticket is consumed and the prompt is an ordinary `User` prompt (never an error). The ticket is consumed whenever it was live (session + unexpired), so a probe cannot retry.
- What the pager sends today (`queue.rs` Cron arm ~631): one `Text` block = the framed text, with only `displayText`/`displayAsCron` in the block `meta` (not hashed; display only). No trimming, no attached context, no image blocks (cron rows carry none). So real fires are unchanged; pinned by the pager test `cron_fire_sends_exactly_the_text_the_shell_binds_the_ticket_to`.
- Edited cron row: `queue_edit.rs:430` rewrites `entry.text` in place and keeps the ticket, so the pager frames the edited text, the hash differs, and the run is an ordinary USER prompt (the hook can block it). That is the intended consequence and is in the release note. A shell/pager pair where framing diverges would also degrade to user prompts, never to escalation.
- Redaction: `QueuedPrompt::fire_ticket` is now `FireTicket` (hand-written Debug prints `FireTicket(<redacted>)`); `Entry` has no Debug; `scheduler-fired-<ticket>` is logged as `scheduler-fired-<redacted>` (shell: `loggable_prompt_id` at `prompt_queue.rs` 146/734, `run_loop.rs` 735/2270, `turn.rs` 1344/1351/1933 span, `turn_end.rs` 196/248; pager: `prompt.acp_send.start` ulog). Not audited: other `{:?}` print sites of `Effect::SendPromptBlocks`, whose `prompt_id` still holds the ticket until sent (no site found that prints an Effect).

Checks asked for:
- `turn.rs:463` `InputOrigin::from_prompt_id` is inside `handle_prompt`, which is `#[cfg(test)]` (turn.rs:445). Not product code; the build is not affected.
- Leader: `fuigo/scheduled_task_inject_prompt` is routed ONLY to the session driver (`leader/server.rs:529` `is_scheduled_task_inject_prompt`, routing at `server.rs` ~2519-2556: `session_driver.get(sid)` then `client.tx.send` to that one client; no driver => dropped, never broadcast, and it skips the load-live buffer). So one client gets the ticket. Even if a second one did, the ticket is single-use and text-bound.
- Not verified: whether the gateway persists/replays the ext notification to later `session/load` attachers (no replay path found in the leader; not traced in persistence).

Tests (Hetzner lane `pido`, commit 8c904023 plus this docs-only receipt edit).
RED on 7c90b2d2 (old API has no text parameter, so the red test redeems a live ticket with no text binding at all): `session::cron_fire_tickets::red_round2::redeem_with_client_chosen_text_must_not_be_a_scheduler_fire` FAILED `left: SchedulerFired right: User` (cron_fire_tickets.rs:162). Different-text, extra-block and image-block cases cannot be written against the old signature; they are the new tests below.
GREEN after the last code edit: `acp_session` 1367 passed; `session` 4323 passed on one run, and 4322 + 1 FAILED on two others (`agent::config::tests::resolve_credentials_empty_api_key_falls_through_to_session`, untouched code in `agent/config_tests.rs`, env-dependent; passes in isolation of the run order and does not touch cron/ticket code; flaky, not caused by this change); `agent` 1829; `tools` 197; pager `queue cron scheduler` 434; `fuigo-extra-ca` ok (45+...); `secret_debug_guard` 2; clippy `-p fuigo-shell -p fuigo-pager --lib --tests`: no warning in touched lines (pre-existing warnings elsewhere).
New tests: `cron_fire_tickets::tests::{redeem_with_different_text_is_a_user_prompt_and_burns_the_ticket, extra_or_non_text_blocks_are_a_user_prompt (extra text, image appended, image only, no blocks, split text), real_fire_text_with_block_meta_is_still_a_fire, scheduled_prompt_text_matches_the_pager_framing, loggable_prompt_id_hides_only_the_ticket}`; `prompt_gate_tests::blocking_hook_blocks_client_prompts_with_reserved_ids_and_forged_or_misused_tickets` (real on-disk blocking hook, shipped `client_prompt_origin` then `handle_turn_input`: eight reserved prefixes incl. `parent-message-`, `task-completed-`, `scheduler-fired-` forged; a real ticket redeemed with other text; the spent ticket) and `real_cron_fire_is_not_subject_to_the_prompt_block` (right text: observe-only annotation, no cancel, no queue hold); pager `cron_fire_sends_exactly_the_text_the_shell_binds_the_ticket_to`, `queued_cron_row_debug_never_prints_the_fire_ticket`, `cron_prompt_ids_are_logged_without_the_ticket`.
