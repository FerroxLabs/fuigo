# R-runtime-text-authority

Security fix (tighten-only). Base `hub/strike/land-batch15` 8d1efca2. Code commit ce81ccbe.

## Facts re-verified on the base
- `file_expansion_allowed` allowed `HumanIntent | RuntimeControl`; `RuntimeControl` is the authority of SchedulerFired, TaskCompleted, SubagentCompleted, WorkflowCompleted, NotificationDrain, GoalSummary, GoalClassifierNudge, PlanResume (`session/mod.rs` policy()). The turn passes `policy.authority` to the parser. `render_file_reference` is a bare read.
- A client prompt that failed the ticket check was `PromptOrigin::User` (`from_client_prompt_id` always User): human slash and `@file`.
- Not re-traced line by line: who writes each runtime text (taken from the brief).

## Fix
1. `file_expansion_allowed` = `HumanIntent` only. Orphan image-placeholder recovery (reads image files from workspace and home image dirs) is also human-only now (was: everything except model-authored and peer).
2. Plan revision choice: DROPPED expansion for the PlanResume revision too (it is `RuntimeControl`, and the human revision text and the fixed approval text share one origin; a separate origin was not clean). A human `@file` typed in a resumed-plan revision is no longer expanded.
3. New `PromptOrigin::UnverifiedScheduled`, produced only by `cron_fire_tickets::client_prompt_origin` (prompt id starts with `scheduler-fired-` and does not redeem). Policy: authority `ModelAuthoredUntrusted` (slash arm: `/compact` + available skills only; no `!` line; no `@file`; no placeholder recovery), analytics `AgentMessage`, compaction `HumanAnchor`, queue `VisibleEditable`, shutdown `Drain`, not synthetic, not user re-engagement, echo shown. `UserPromptSubmit` runs and a Block IS enforced on a top-level session (`PromptOrigin::enforces_prompt_block`, replaces `should_enforce_prompt_block(policy)`). Recorded as `ConversationItem::scheduler_fired` (closest kind). Interjection authority: model-authored `ParentAgent` (exhaustive match). Rewind-poppable front row: kept.
4. Docs: release notes entry plus corrected the two sentences about edited scheduled rows and older pagers. No user guide documents `@file` in `/loop`.

## Step 3: parser features by authority (after the fix)
| Feature | Human | RuntimeControl | ModelAuthored (incl. SubagentTask, UnverifiedScheduled) | Peer |
|---|---|---|---|---|
| `@file` text expansion, ResourceLink to `@path` | yes | no (fixed) | no | no |
| orphan `[Image #N: path]` disk recovery | yes | no (fixed) | no | no |
| slash builtins / `!` line | yes | model arm (existing) | model arm | model arm |
| inline base64 image extraction from text | yes | yes | yes | no | (data only, no file read: left, reported)
| embedded Resource / Image blocks | yes | yes | yes | dropped | (client blocks, not text: left)

## Tests (all on Hetzner, after the last code edit)
RED on the base-behaviour variant (arm removed / `RuntimeControl` re-allowed): `test_runtime_control_prompt_does_not_expand_file_references`, `runtime_origins_do_not_expand_file_mentions` (scheduled fire, subagent completion, notification drain, task completion; absolute path plus `@relative.txt` plus `@/etc/hostname`), `unverified_scheduled_prompt_has_no_slash_or_file_authority` (`/always-approve on` with a real permission manager), `unverified_scheduled_prompt_is_blocked_by_a_blocking_prompt_hook`. GREEN on the fix; `human_file_mention_still_expands_and_verified_fire_slash_stays_inert` and the existing `real_cron_fire_is_not_subject_to_the_prompt_block` pass in both. Updated: cron_fire_tickets and r3 prefix tests (a replayed or forged `scheduler-fired-` id is `UnverifiedScheduled`).
Totals: prompt_parser 26; acp_session 1424 (1 ignored); session 4463 (3 ignored); agent 1865; tools 197; pager 436; fuigo-tools 172; extra-ca all ok; auth secret_debug_guard 2. 0 failures. Clippy: no warnings in touched files (existing warnings elsewhere).

## Not verified
Red for the unverified tests was shown by removing the new `client_prompt_origin` arm (origin becomes `User`), failing at the origin assertion, not on a literal base checkout (the tests need the new variant).

## Round 2 (audit side routes)
Code `7eb107d3`. New `PromptOrigin::may_ride_as_interjection()` (false for `UnverifiedScheduled`, `SubagentTask`).
1. Combine: `combine_gate` makes a row combinable only if its origin is `User` (front or follower); other origins break the run. Tests `combine_never_folds_model_authored_rows_into_a_user_row` (follower, front, middle; both origins; text and origin pinned), `combine_still_merges_two_user_rows_exactly_as_before` (pins "text for p1\n\ntext for p2").
2. Promotion: excluded from `promote_queued_as_interjections` (prefix stops), the `queue_input` goal send-now merge and the `handle_interject_queued_prompt` goal merge. Such a row runs as its own turn with its origin, so `UserPromptSubmit` is enforced (existing `unverified_scheduled_prompt_is_blocked_by_a_blocking_prompt_hook`). `SubagentTask`: cannot be promoted in practice (the child has no running turn when the task arrives); excluded anyway, the ParentAgent mapping remains an unreachable fallback. Tests: `queued_model_authored_rows_are_never_promoted_as_interjections`, `unverified_scheduled_send_now_during_a_goal_runs_as_its_own_turn_not_an_interjection`, `interject_queued_unverified_scheduled_row_during_a_goal_is_not_merged`.
Red/green: green run on Hetzner after the last edit. Red was NOT run against the old tip (by construction: old code combined, promoted and merged these rows; the tests assert the opposite).

### Step 3: operations that can move a row's text between turns or change its origin
| Operation | Origins accepted | Origin and authority preserved |
|---|---|---|
| combine (`combine_front_pending_inputs`) | `User` only (fixed) | yes; combined text keeps front User |
| promote queued as interjection | everything except `UnverifiedScheduled`/`SubagentTask` (fixed) | `User`/synthetic map to User interjection (existing) |
| promote parent/peer messages | `ParentAgentMessage`, `PeerMessage` protected rows | keeps ParentAgent/Peer authority |
| stranded rebuild (`queue_interjection_fallback_prompt`) | User, ParentAgent, Peer authority | origin rebuilt from authority; unverified/task rows no longer reach it |
| send-now (`queue_input`) and goal merge | editable rows; goal merge excludes the two origins (fixed) | send-now keeps origin |
| interject-queued (with or without new text) | editable rows; goal merge excludes the two origins (fixed) | origin kept |
| edit (`apply_queued_prompt_edit`) | any editable row | origin kept (an edited unverified row stays model-level; fine, tighten-only) |
| reorder, hold/release edit, remove, clear | any row | origin untouched (position/removal only) |
| steer (`follow_up_steer`) | via promote above | see promote |
| resume of pending rows | persisted rows keep stored origin | not changed here; not traced in depth (report) |

### Full-package result
`cargo test --locked --no-fail-fast -p fuigo-shell` in an empty network namespace: 67 result lines, 0 failed (the known unrelated/timing tests also passed this run). `--features test-support`: 73 result lines, 0 failed. `a_subagents_task_text_cannot_run_hook_commands` passes. Filtered runs: prompt_parser 26, acp_session 1429, agent 1865, pager 436, tools 172, extra-ca ok, secret_debug_guard 2. Clippy: no warning lines from touched files in the filtered output (not independently re-read).
