# R-1026 (packet 26-6b): Bash tool `block_until_ms`

Base `hub/strike/integration` at `dd2978d5`; branch `strike/b26-6b`.

## Upstream files read (read-only, `~/upstream-grok-build` at `2bdd1d6`)
- `xai-grok-tools/src/implementations/grok_build/bash/mod.rs`: input struct (273), `BashVersion` (463), `resolve_block_until_ms`, `block_until_ceiling_ms`, `fold_single_knob_into_legacy_knobs` (1196-1260), schema export (1352-1480), description template (1505).
- `xai-grok-tools/src/implementations/grok_build/task_output/{mod,wait_tasks}.rs`, `xai-tool-types/src/task.rs` (`bash_block_param`, `background_sources`).
- `xai-grok-shell/src/tools/config.rs` (`default_block_until_ms`), `xai-grok-agent/src/config.rs:119` (no rename of `block_until_ms`).
- `xai-grok-pager/src/acp/tracker.rs` (`raw_input_requests_background`, 2558).
- `xai-grok-shell/.../wait_interrupt_tests.rs` is the separate wait-tasks tool; nothing to port.

## The parameter (round 2: lifetime rules unchanged)
`block_until_ms` (integer, optional): how long the call blocks for the command. Default = the old default foreground timeout, `effective_default_timeout_ms` (120 s; `toolset.bash.timeout_secs`), or `toolset.bash.default_block_until_ms` when the user sets it. Minimum 0, maximum = the block ceiling. `0` = an explicit background task, never clamped, with the same limits, registry and disabled-setting refusal as `is_background: true`. A positive value is the foreground `timeout` and nothing else: the user's `auto_background_on_timeout` is NOT switched on by the call. When the wait ends with the command still running: setting ON (production default `true` in `fuigo-shell/src/tools/config.rs`, struct default `false`) it continues in the background exactly as that setting always did (same budget, same 10 h background lifetime); setting OFF it is killed exactly as a foreground timeout killed it and the result gets the note `stopped_after_wait_note` (stopped after the wait; run it with `block_until_ms: 0`). Interactive cancel and turn end act on it as on a foreground command (killed during the wait; after an opt-in auto-background it is a background task, as before). Advertised only while background commands are enabled.

Ceiling = min(`max_timeout_secs` [default 5 min, production 10h], 10 h, `max_block_until_ms` if > 0), then: setting ON, the operator `foreground_block_budget_ms` if set, else the 300 s transport cap; setting OFF, `max(300 s, default timeout)`, the figure the runner's `clamp_foreground_block` always applied to a non-backgroundable foreground call (so a wait is never shorter than the old timeout could be). In production that is 300000 ms. Larger values are clamped. A negative or non-integer `block_until_ms` fails to parse and the call is rejected (fail-closed); round 1 wrongly said it was ignored.

## Mapping table (old call -> new meaning)
| Old input | Meaning now |
|---|---|
| `is_background: true` (also `background: true`) | `block_until_ms: 0`, untouched fields: an explicit background task |
| `is_background: true` + `timeout: N` | background with lifetime N (kept) |
| blocking call, no `timeout`, no `block_until_ms` | untouched: the 120 s default foreground timeout, then the user's `auto_background_on_timeout` rule (test `a_call_with_no_arguments_behaves_as_before`) |
| blocking call with `timeout: N` | untouched: wait N, then the user's rule |
| `block_until_ms: N > 0` | `timeout = N` (clamped), then the user's rule: auto-background ON continues in background, OFF kills with a note |
| `timeout: 0` on a foreground call | the default (always was) |
| `block_until_ms` with any of the above | `block_until_ms` wins |
| background commands disabled | no field advertised, `timeout` kept; `block_until_ms: 0` refused with "Background execution is disabled." |

## Compatibility decision
Fuigo's parser ignores unknown fields (no `deny_unknown_fields`), so a dropped field would silently turn a resumed background call into a foreground one. Therefore `BashToolInput` keeps `is_background` (hidden from the schema with `schemars(skip)`, lenient bool, `alias = "background"` for transcripts recorded under the former model-facing name) and `timeout`, and `fold_block_until` maps them onto the new knob. Both set: the new one wins. No resumed session errors (tests below).
Hooks: for a shell-command input (string `command` plus any of `block_until_ms`, `is_background`, `background`) PreToolUse, PostToolUse and PostToolUseFailure payloads get two computed fields, overriding whatever the model sent (`hook_dispatch.rs:with_retired_bash_background_field`, fed the user's setting by `SessionActor::bash_auto_background_enabled`, which reads the same resolved `[toolset.bash]` params the tool runs with). `is_background` = `fuigo_tools::...::bash::raw_input_requests_background`, the Value form of `BashTool::requests_background`, the rule `execute` routes by (tests assert equality against the runner for every block/boolean combination, including string booleans). `may_background_after_wait` = foreground call AND `auto_background_on_timeout` effective; `false` for a background task. An input with none of the three keys is passed through unchanged.
ACP hosts: `rawInput` is the model's arguments; the pager calls the same `raw_input_requests_background` (numeric strings, `"true"`/`"yes"`/`1`) as the runner and hooks.

## Consumers changed
- `fuigo-tools/.../fuigo_build/bash/mod.rs`: input struct, `BashParams.default_block_until_ms`, `requests_background`, `resolve_block_until_ms`, `block_until_ceiling_ms`, `fold_block_until` (called at the top of `run`), `execute` routing, schema export (adds `block_until_ms` with default/min/max, removes `timeout`), description template (enabled), `&`-rejection messages ("set block_until_ms=0"), tracing field.
- `fuigo-tool-types/src/task.rs`: `bash_block_param` in the task-output and wait-tasks naming structs; `task_output/{mod,wait_tasks,terminal_command}.rs` pass it.
- `fuigo-agent/src/config.rs`: the `is_background -> background` rename removed; `templates/subagent_prompt.md` + regenerated `SUBAGENT_PROMPT_ENC` (same XOR scheme, only that constant changed).
- `fuigo-shell/src/tools/config.rs` (user setting), `session/acp_session_impl/{hook_dispatch,tool_calls}.rs` (hook compat), struct literals in `tool_dispatch.rs`, `bang_controls_tests.rs`, `tool_calls.rs`.
- `fuigo-pager/src/acp/tracker.rs`: `raw_input_requests_background`.
- Docs: `20-background-tasks.md`, `05-configuration.md`, `26-config-reference.md`, `README.md` of the user guide; `docs/release-notes-1.0.26.md`.
- Permission summaries: none read `is_background`; unchanged.

## Pins / tests changed
- `fuigo-pager/src/acp/tracker_tests.rs`: the P195 guard test replaced by `block_until_ms_zero_and_the_retired_flags_defer_an_execute_call_as_a_background_task` (R195 U11 is now implemented).
- `fuigo-tools/.../bash/mod.rs` tests: renderer maps (`is_background` -> `block_until_ms`), `description_states_block_then_background`, `description_names_the_single_block_knob` (was `description_tracks_renamed_timeout`), `schema_block_until_ms_numbers_track_config` (was `schema_timeout_numbers_track_config`), `tool_description_block_numbers_track_config`, rename / kind-wide-alias tests now use background-disabled params (where `timeout` is still advertised), rejection-message and PowerShell message tests (`=0`), plus a new `block_until_ms_tests` module.
- `fuigo-tools/src/registry/types.rs`: `bash_descriptions_track_system_reminders_setting`, `bash_definition_*` (enabled/disabled), `background_param_templates_reference_real_schema_keys`.
- `fuigo-tool-types/src/task.rs`: new naming test; existing literals gained `bash_block_param: None`.
- `fuigo-shell`: `default_block_until_ms_emitted_only_when_set`, hook compat tests.
- No pin in `fuigo-agent/src/builder.rs` referenced the bash schema; `prompt::template::test_encrypted_templates_not_stale` pinned the subagent prompt (regenerated).

## Not ported / differences from upstream
- Upstream also hides and raises the foreground kill ceiling to 10h and sets the block budget to 0 (no 300 s cap). Not ported: Fuigo keeps its 300 s transport cap and the operator's `foreground_block_budget_ms` and `max_timeout_secs`, so the largest block is 300000 ms in production (upstream: 10h). Raising it is a one-line change to `block_until_ceiling_ms` if the owner wants it.
- Upstream treats `timeout: 0` as background; Fuigo keeps it as the default (see table).
- Upstream's `PreBlockUntilMs` / contract-version switch not ported (Fuigo has no contract pin for this).
- `max_block_until_ms` already existed in `BashParams` (unused wording from an earlier import); it now actually bounds the field. It has no user-facing config key.
- No real model or network used; behaviour with a real model and the prompt-cache reset are checked on the owner's side.

## Round 2 (audit findings, base `d3339938`)
1. Forced auto-background removed: `fold_block_until` no longer sets `auto_background_on_timeout`; default wait raised from 30 s to the old default foreground timeout (found: `DEFAULT_TIMEOUT = 120 s` in `dd2978d5` bash/mod.rs:986); description and schema text now say a positive wait stops the command unless the user enabled auto-background.
2. Hooks truthful (above), tests in `hook_dispatch.rs::retired_bash_background_field_tests` and `bash/mod.rs::block_until_ms_tests::background_decision_matrix`.
3. Pager shares `raw_input_requests_background` (tests with `"true"`, `"yes"`, `"1"`, `"false"`, `"no"`, `"0"`).
4. Audit notes: the `BackgroundTaskRegistry` (`fuigo-shell-terminal/src/background_task.rs:54-71`, max 10) is in a crate the tool path does not use; it has no production caller before or after the port (file untouched since the base), and the production terminal (`fuigo-tools/src/computer/local/terminal.rs`) has never capped the count of running background tasks (only `MAX_COMPLETED_TASK_SNAPSHOTS = 100`, line 79): nothing removed or bypassed, nothing to restore. Plan mode: `plan_mode_edit_gate` at `tool_calls.rs:1580` runs on the parsed input before any foreground/background routing; the peer-influence remark at 1596 and the peer-command guard (`workspace/permission/shell_access/peer_cmd.rs`, reached from `shell_access.rs:3194`) read only the command string; the permission key is the command (`permission/types.rs`), none read `block_until_ms`. Sandbox is applied by the terminal backend when it spawns, for both paths. Session drop: `terminal.rs:1025/1033` (`shutdown_all` on cancel token / command channel closed) is unchanged.
5. Pins run explicitly on the box (inside `unshare -n`): `fuigo-agent prompt::template` (49 passed, includes `test_encrypted_templates_not_stale`; the subagent prompt text is unchanged this round, so no regeneration), `fuigo-tools fuigo_build::bash` (all passed after the two test fixes), registry tool-definition pins in the full `fuigo-tools` run. Full runs: tools+agent+pager+hooks 14617 passed, 1 flaky LSP test (`a_productive_server_still_lets_go_of_a_file_it_never_answers_for`, passes alone, unrelated); shell 9093 passed; extra-ca+auth 91 passed.

Note: the shipped app's `auto_background_on_timeout` default is `true` (`fuigo-shell/src/tools/config.rs`: local config, then remote, then `true`); only the bare `BashParams` struct default is `false`. So by default a positive wait that expires still continues in the background, as a foreground timeout already did; with the setting off it is killed.
