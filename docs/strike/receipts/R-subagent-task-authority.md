# R-subagent-task-authority

Security fix (tighten-only). Base `hub/strike/integration` 9d57c315. Existing bug in 1.0.23/1.0.24.

## Origin chosen
New `PromptOrigin::SubagentTask`, stamped on the child's initial task prompt in `agent/subagent/attempt_runner.rs` (was `origin: None` => `User`).
Policy: authority `ModelAuthoredUntrusted` (slash arm = `/compact` + available skills only; no `!` line), analytics `AgentMessage`,
compaction `HumanAnchor`, queue `VisibleEditable`, shutdown `Drain`. `is_synthetic()` is false. Not derivable from a prompt id.
`ParentAgentMessage` was NOT reused: it is `VisibleProtected`, renders as `parent_agent_message`, records an agent-message
conversation item and has message-delivery bookkeeping, all wrong for a task.

## Site table (step 2)
| Site | Today (User) | After (SubagentTask) |
|---|---|---|
| turn.rs slash resolve (`policy.authority` match, ~:622) | `resolve_human_intent`, builtins run | model arm: `/compact` + available skills only (CHANGED, the fix) |
| turn.rs `!` line (~:600) | runs shell | refused (CHANGED) |
| turn.rs `UserPromptSubmit` gate (~:976) | runs, observe-only in a subagent | runs as before (kept; condition widened to the new origin) |
| turn.rs parse authority (~:1063, `@file` expansion via `file_expansion_allowed`) | expands | NOT expanded since Round 2 (parsed with the origin's own model-authored authority) |
| turn.rs orphan image placeholder recovery (~:1077) | recovers | skipped since Round 2 |
| turn.rs conversation item (~:1293) | `ConversationItem::user` + interrupt envelope | identical (kept: `User \| SubagentTask` arm) |
| turn.rs `invalidate_side_calls` (:566), redirect kind (:844), task-wake gate clear + `consume_deferred_completions` (:1212) | run (human intent) | skipped (model-authored; no-ops in a fresh child) |
| turn.rs builtin echo (:753) | echo for human | no echo (model-authored; only `/compact` reaches here) |
| turn.rs PromptSubmitted telemetry (:1192) | emitted | not emitted (analytics `AgentMessage`; ambiguous, telemetry only) |
| turn.rs `TurnStartInput.synthetic` (:579) | false | false (kept) |
| run_loop.rs :700 re-engagement (clear suppression, hook-block hold, bump `user_input_generation`) | runs | skipped via new `is_user_reengagement()` (CHANGED) |
| run_loop.rs :729 synthetic log | no | no (kept) |
| prompt_queue.rs :174 `invalidate_side_calls`, :248 preempt synthetic wakes | runs | skipped (model-authored; queue empty in a fresh child) |
| prompt_queue.rs :179 prompt history | skipped for subagents already | unchanged |
| prompt_queue.rs :215 trace template, :615/:878 `is_synthetic` | non-synthetic | non-synthetic (kept) |
| prompt_queue.rs :283 queue kind | `prompt` | `prompt` (kept) |
| queue_mutation.rs (`policy().queue`) | VisibleEditable | VisibleEditable (kept) |
| notification_drain.rs :352 (human-intent gate clear on promotion) | runs | skipped (model-authored) |
| interjection.rs :88 | separate origin per call | n/a (task never an interjection) |
| hook_dispatch.rs :415 `should_enforce_prompt_block` | false for subagents | false (unchanged) |
| cancel.rs :52 rewind-poppable front row | User only | `User \| SubagentTask` (kept) |
| cancel.rs :664 `had_queued_user_prompt` | non-synthetic | same (kept) |
| session_mode.rs :173 plan-mode reconcile | runs | runs (kept, non-synthetic) |
| `hide_user_echo_from_scrollback`, `completion_id` | false / None | false / None (kept) |
| Pager `prompt_origin.rs` (`from_prompt_id`) | by id, UUID => not synthetic | unchanged (variant never derived from an id) |
| compaction (`CompactionClass`, `compaction_utils`) | HumanAnchor | HumanAnchor (kept) |
| title generation (`ContentChunk`) | sent | sent (kept) |

## Defence in depth (step 3)
`BuiltinAction::changes_permissions_or_config()` (SetYolo, HooksTrust/Add/Remove/Untrust, PluginsReload/Trust/Add/Remove/Install/
Uninstall/Update, MemoryToggle) is refused in `turn.rs` when `startup_hints.is_subagent`, for EVERY origin, with
"/<cmd> is not available in a subagent session." (host-turn output, normal end of turn). `/peers` does not exist on this base.
Can a human type into a subagent session? Not established by reading (no dashboard reply / attach path checked end to end); the refusal
applies regardless (stricter).

## Step 4: `SessionCommand::Prompt` constructions (production)
| File:line | origin | Text written by |
|---|---|---|
| agent/subagent/attempt_runner.rs:89 | was `None`, now `SubagentTask` | parent MODEL (task prompt); also carries workflow agent steps and deep-research workers, which spawn through this one path |
| agent/subagent/spawn.rs:495 | `SubagentCompleted` | shell template |
| tools/notification_bridge.rs:434 | `TaskCompleted` | shell template |
| agent/mvp_agent/acp_agent.rs:1382 / 1419 (via message_delivery.rs:52) | client-supplied => `User`, or ticket-verified `SchedulerFired` | human / pager; `/loop` fires come back as `SchedulerFired` (runtime control, slash inert) |
| pager agent_view/modals.rs:2241, 3175 (`origin: None`) | n/a: this is a plugin origin field, not a prompt origin | not a `SessionCommand::Prompt` (earlier row was wrong) |
| `send_subagent_message` (message_delivery.rs:214, parent_message.rs:55) | `ParentAgentMessage` | confirmed model-authored untrusted |
| goal continuations | injected mid-turn (`inject_goal_continuation_message`), not a `Prompt` command | shell/model; not changed |
Nothing else leaves `origin: None` with model-written text. Not changed, flagged: model-written `/loop` prompt TEXT later fires as `SchedulerFired`
(RuntimeControl, slash inert, already safe).

## Red / green
Red (base 9d57c315, tests with `task_origin()` = `PromptOrigin::User`, i.e. the old `origin: None` behaviour):
- `subagent_task_prompt_cannot_run_permission_or_config_slashes` FAILED: `task prompt "/always-approve on" turned always-approve on for the shared permission handle`
- `subagent_task_prompt_never_runs_a_bang_shell_line` FAILED: terminal calls left 1 right 0
- `subagent_session_refuses_permission_and_config_slashes_for_a_user_origin_prompt` FAILED: `"/always-approve on" changed permissions in a subagent`
- compact/skill and plain+`@file` tests pass on base (they pin unchanged behaviour).
Green (this commit): all of the above pass; `cargo test -p fuigo-shell --lib` filters acp_session 1392, session 4375, agent 1836, subagent 460 pass;
pager `prompt_origin queue` 426; fuigo-extra-ca; fuigo-auth secret_debug_guard; clippy -p fuigo-shell -p fuigo-pager --lib --tests: no warning in touched files.
Added: `task_prompt_is_sent_with_the_subagent_task_origin` (real `run_one_turn_attempt`, asserts the sent command), `session::tests::subagent_task_is_model_authored_with_user_turn_mechanics`,
`builtin_classification_covers_the_permission_and_config_families`, `human_prompt_in_a_top_level_session_still_runs_always_approve`.

## Not verified
- Red lines for `/hooks-add`, `/plugins`, `/memory` on base: the red run stops at the first assertion (`/always-approve on`). In the fixture `/plugins` and `/memory` are availability-gated out (covered by the classification test only); `/hooks-add` is reachable (registry installed) and is covered green.
- Fixture's default `allow_all` permission handle cannot observe a toggle (the older parent test's yolo assertion is vacuous); the new tests install a real permission manager.
- Hook-block/`UserPromptSubmit` and `recover_orphan_placeholders` kept as today (flagged above).
- Whether any UI path lets a human type into a subagent session.

## Round 2 (Opus review follow-ups)
- Finding: `render_file_reference` (`fuigo-workspace/src/file_system/attach_file.rs:49`) is a bare `tokio::fs::read`; its only caller is `session/prompt_parser.rs:140`. No permission, deny-rule or protected-path check applies to a human `@file` either (a human typing `@path` is the user choosing the file). For a model-written task that was a bypass.
- `@file` in a `SubagentTask` prompt is no longer expanded (the parse override to `HumanIntent` in `turn.rs` is removed). Tests: `subagent_task_prompt_does_not_expand_file_mentions_but_a_user_prompt_does`, `subagent_task_prompt_does_not_read_absolute_paths_or_files_under_a_read_deny_path`.
- Orphan image placeholder recovery is skipped for `SubagentTask`. Test: `subagent_task_prompt_skips_orphan_image_placeholder_recovery_but_a_user_prompt_keeps_it`.
- `prompt_queue.rs` origin-to-interjection-authority match is exhaustive; `SubagentTask` maps to `ParentAgent` (model-authored), never `User`. Test: `promoted_then_stranded_subagent_task_row_is_not_requeued_as_a_user_prompt`.
- Added `subagent_task_prompt_in_a_subagent_session_refuses_permission_and_config_slashes` (`SubagentTask` plus `is_subagent = true`).
- Not done: the subagent slash refusal remains a deny-list, not an allow-list (follow-up).

## Round 3 (landing-lane failure: P07a F1 integration test relied on the bug)
- Test rewritten: `a_subagents_typed_hook_command_reloads_no_process_snapshot_plugins` is now `a_subagents_task_text_cannot_run_hook_commands` (`crates/codegen/fuigo-shell/tests/plugin_hooks_child_slash_acp.rs`). The old test spawned a child whose task text was `/hooks-untrust` / `/hooks-trust` and expected the child to execute it (zero model turns). That text is model-written, so executing it was the escalation this branch removes.
- It now asserts, per task text: the child makes its own scripted model turn (the mock's child step is consumed) and a non-parent user message in the request log carries the task text as plain text; no "Hooks reloaded: N hook(s) loaded." reply in any session transcript (after waiting for the child's model reply to be persisted, so the check is not vacuous); `$FUIGO_HOME/trusted_folders.toml` byte-identical before and after.
- Fails on reverted code: there the child runs the slash command with no model turn, so the scripted child step is not consumed by the child (the parent's "done" step lands on it, mock steps go out of order and the prompt/`assert_satisfied` fails) and the reply count is 2 ("Hooks reloaded: 1 hook(s) loaded." twice). Not executed as a red run (no revert lane run); the failure is by the old test's own measured count of 2.
- Step 2, can a hook reload still happen in a child? Yes, one path remains: ACP ext `hooks/action` with a child's session id (`extensions/hooks.rs:260` -> `agent_ops.rs:2645` -> `SessionCommand::HooksAction`, `run_loop.rs:921` -> `handle_hooks_action` `hooks_plugins.rs:349` -> `reload_hooks_impl`). It needs a live child session id and a client calling the method; no model or task text can reach it. The P07a property is held in code at `hooks_plugins.rs:1009` (a subagent's reload passes no plugins) and `plugins_for_hook_reload` (`hooks_plugins.rs:94`), and pinned by the existing unit test `a_reload_without_a_session_plugin_view_installs_no_plugin_hooks` (`hooks_plugins.rs:1651`, subagent=true with a registry handle). The typed `/hooks-*` route and `fuigo/plugins/reload` do not reach a child's `reload_hooks_impl`: the plugins fan-out `ReloadPlugins` and `ReloadHooks` both skip subagents (`run_loop.rs:1160-1176`). Left as is; no product code changed.
- Full package on Hetzner (`/root/fuigo-builds/sata`, empty netns, slot-run): `cargo test --locked --no-fail-fast -p fuigo-shell`: 1 failure, `auth::refresh::oidc_refresher::auth_backend_contract_tests::auth_backend_contract_concurrent_401s_hit_idp_once` (lib; unrelated, auth refresh concurrency; passed in the second run). `... --features test-support`: 0 failures (exit 0), 69 targets, rewritten test ok in both runs. No other test needed changing.
