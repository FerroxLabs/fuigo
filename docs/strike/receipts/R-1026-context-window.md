# R-1026-context-window: `/context-window` (packet 26-6d(a))

Branch `strike/b26-6d`, base `hub/strike/integration` at `dd2978d5`. Local sources only.

## Upstream files read (read-only, `~/upstream-grok-build` at `2bdd1d6`)

`xai-grok-pager`: `slash/commands/context_window.rs` and its tests, `acp/model_state.rs`, `app/actions.rs`, `app/dispatch/router.rs`, `app/dispatch/session/lifecycle.rs`, `app/effects/mod.rs`, `app/acp_handler/session_notification.rs`, `slash/commands/model.rs` (read only).
`xai-grok-shell`: `agent/config.rs`, `agent/model_providers.rs`, `agent/handlers/model_switch.rs`, `agent/mvp_agent/{acp_agent,agent_ops,session_setup}.rs`, `session/acp_session_impl/{model_switch,session_setup,sampler_turn,turn,spawn}.rs`, `session/{commands,handle,compaction_config,persistence,slash_commands}.rs`, `session/storage/*` (summary patch), `extensions/notification.rs`.
`xai-grok-sampling-types/src/types.rs`.

## What was ported

| Piece | Fuigo location |
|---|---|
| Meta keys and parsers (`contextWindow`, `contextWindows`), bounds constants | `fuigo-sampling-types/src/types.rs` |
| `context_windows` on `[model.<id>]`, `[model_providers.<id>]`, `ModelEntryConfig`, `ModelInfo`; `context_window_choices`; `ModelInfo::supports_context_window`; `contextWindows` in the ACP model meta (more than one size only) | `fuigo-shell/src/agent/config.rs`, `agent/model_providers.rs` |
| Config bounds (see below) | `agent/model_providers.rs` `sanitize_context_windows`, `agent/config_model_override_parse.rs` |
| Selection state: atomic on `SessionHandle` and `CompactionConfig`; `SwitchContextWindow`, `ContextWindowSwitch` | `session/{handle,compaction_config,commands}.rs`, `acp_session_impl/spawn.rs` |
| Switch applies the selection to the sampling config (`Preserve` for a plain switch, `Set` for a request or restore; an unsupported value is dropped) | `acp_session_impl/model_switch.rs`, `agent/handlers/model_switch.rs` |
| Request `_meta.contextWindow` validated against the model (refused with `invalid_params` when not listed or malformed) | `agent/mvp_agent/acp_agent.rs` `resolve_switch_window` |
| Selection kept against server-reported windows, cleared when the server reports a smaller window; re-applied at turn start after a resume without a catalog | `acp_session_impl/{session_setup,sampler_turn,turn}.rs` |
| Persisted in the session summary (`context_window`) and restored on resume; copied by fork | `session/{persistence,storage/*}.rs`, `agent/mvp_agent/session_setup.rs` |
| Current model's meta carries the session's `contextWindow` | `agent/mvp_agent/agent_ops.rs` `model_state` |
| ACP: `ModelChanged.context_window_selection` (additive, optional, skipped when absent) | `extensions/notification.rs`, `agent/handlers/model_switch.rs` |
| Command, picker rows, parsing and formatting | `fuigo-pager/src/slash/commands/context_window.rs` |
| Pager state (`context_window_selection`, `get_context_window`, `window_after_switch_to`, options) | `fuigo-pager/src/acp/model_state.rs` |
| Action / Effect / TaskResult, completion handler, `ModelChanged` mirroring, context total refresh | `app/actions.rs`, `app/dispatch/{router,task_result}.rs`, `session/lifecycle.rs`, `app/effects/mod.rs`, `app/acp_handler/session_notification.rs`, `app/agent_view/session.rs` |
| Reserved name for skills | `fuigo-shell/src/session/slash_commands.rs` (`PAGER_COMMAND_KEYS`) |

## Local config form and bounds

```toml
[model.my-model]
context_window = 100000            # default (optional; first listed size otherwise)
context_windows = [100000, 400000] # sizes /context-window can select
```

Also under `[model_providers.<id>]` (inherited by a model that sets neither key). Each value is a positive integer (zero or a non-number skips the field with a configuration warning). Values above 16,000,000 tokens, repeated values and values beyond the first 16 are dropped with a warning; a list left empty is no list. Choices are the default (listed first) plus the list. A request or `/context-window` value is accepted only when it equals the default or a listed size.

## Rules that hold

- Managed pin: `/context-window` goes through the same `session/set_model` gate as `/model` (`set_model_gated`): `user_selectable` (the admin allowlist) is checked before the window is looked at, so a model the policy refuses cannot be reached through this command; the list a user can pick from is only the configured one, so a managed configuration decides the sizes. No new bypass exists because the command never changes the model.
- Human command: the command is pager-only (`PAGER_COMMAND_KEYS`), not a shell built-in, so the authority resolver never resolves it for model-authored text (only `ExactCanonical` built-ins resolve there), peer text and runtime-control text are inert, and a skill cannot take the name. Test: `slash_authority_tests::context_window_command_is_human_only`.
- Nothing new is sent to any server: the selection only sets the `context_window` of the local sampling configuration used for compaction thresholds; the request parameters are the ones already sent.

## Not ported / differences

- Remote model catalog source (`remote/client.rs` `contextWindows`): not ported. Fuigo takes nothing from xAI services; `remote/client.rs` sets `context_windows: Vec::new()` for a catalog entry. A natural place for a server-supplied list would be a field on the FluxRouter model catalog or `default_models.json`; none was invented. (`DefaultModelJson` does not read `context_windows`; a user adds the list under `[model.<id>]`, which also applies to catalog models of the same id.)
- `Action::SwitchModel` was not turned into `SwitchModel(ModelChoice)`. A separate `Action::SetContextWindow` / `Effect::SetContextWindow` / `TaskResult::ContextWindowSet` carries the request, so no existing action pattern or test changed. Behaviour is the same.
- `/model` argument syntax and picker rows for sizes (`slash/commands/model.rs`) are not ported. `/model <name>` keeps a selection the new model lists.
- The command is always visible (upstream hides it for models with one size) so that it can say there is nothing to choose; with no argument it lists the choices.
- Upstream's catalog-key lookups (`catalog_key`, `model_supports_context_window` on the models manager) are replaced by `find_model_by_id` and `ModelInfo::supports_context_window`.

## Tests

Ported and adapted: command tests (supported, unsupported, empty-args, single-window, suggest rows, missing model/session, format/parse), `ModelState` selection tests, `ModelChanged` serialization and round trip.
Added: config list parse, default and choices, provider inheritance, zero / absurd / repeated / excess bounds, meta emission only for more than one size, `supports_context_window`; sampling-types meta helpers; `resolve_switch_window` (absent, listed, unlisted, zero, malformed); session-actor tests (selection applied and persisted, unsupported refused and forgotten, plain switch carries or not, compaction basis and overflow clearing); authority test (model, peer, runtime input); `ModelChanged` without the field parses; pager `ModelChanged` carries the selection, `ModelChanged` during a local switch, router and completion handler tests.
Changed existing tests only to add the new fields to struct literals and the new arguments (`handle_set_session_model`, `update_current_model_and_agent`).
