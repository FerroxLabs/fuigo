# P141 Astra round 1 (gpt-6-astra, read-only) on 23fdb621

Final report only (the full codex transcript, 1.4 MB, is not kept in the public tree). Brief: scratchpad `p141/astra-r1.txt`.

Audited `23fdb621` against `7f766889` and `v1.0.20`. Static review only; no cargo or edits. **Two new regressions prevent landing.**

| Reported item | Verdict | Evidence |
|---|---|---|
| MEDIUM 1: ingress pruning allows later plugin takeover | **FIXED for the stated session/new scenario** | Copies remain marked at [managed_mcp.rs:181](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:181); reload substitutes current disk content at line 387. Update/reconnect propagation remains incomplete below. |
| LOW 2: duplicate sourced merge | **FIXED** | One merge at [managed_mcp.rs:182](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:182); `agent_ops.rs:559` and `extensions/session_admin.rs:574` consume its result directly. |
| LOW 3: retained copies ignore edits/deletes | **FIXED for marked seeds** | [managed_mcp.rs:240](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:240) resolves the original disk name, preserves the forwarded name, and returns nothing after deletion. |

New regressions:

- **HIGH — marked copies bypass user-definition precedence.** [managed_mcp.rs:389](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:389) inserts copies directly; the protection at line 406 applies only to unmarked entries. Scenario: user config defines `com-example → U`; project config defines `com.example → P`; ACP forwards P as `com-example`. Alias matching marks it, and P replaces U. `7f766889` applies the trusted-definition check and restores U. **New versus `7f766889`; reopens behavior already possible in v1.0.20. Tests do not catch it:** no marked-copy collision with an existing trusted name.
- **MEDIUM — partitioning changes duplicate-client precedence.** [managed_mcp.rs:376](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:376) processes every copy before every supplied entry. Scenario: trusted folder’s project `.mcp.json` defines `corp=A`; client sends `[corp=B, corp=A]`. Both baselines select the final entry A at ingress; P141 selects B. **New versus both baselines. Tests do not catch it:** no mixed marked/unmarked duplicate-name case.

Required guarantees still have these inherited gaps:

- **MEDIUM — update/reconnect changes the handle seed, not the actor seed.** [session_admin.rs:606](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-shell/src/extensions/session_admin.rs:606) and [session_setup.rs:1146](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-shell/src/agent/mvp_agent/session_setup.rs:1146) update only the handle. `UpdateMcpServers` carries no seed (`session/commands.rs:551`); [hooks_plugins.rs:1152](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-shell/src/session/acp_session_impl/hooks_plugins.rs:1152) reuses the actor’s original seed. Start without a forwarded copy, add one through update/load, then reload plugins: the plugin can replace it again. **Present in both baselines; not caught by tests.**
- **MEDIUM — vendor check examines stale content.** [managed_mcp.rs:383](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:383) checks the stored URL before resolving the current definition. Edit forwarded TOML `com.example` from A to B while disabled Cursor configuration names B: the alias can resolve to B without checking B. **Also possible through P136’s trusted-definition replacement in `7f766889`; not a new P141 regression.** The kill-switch test covers an unchanged URL only.

Other seed paths preserve the typed seed: `session_setup.rs:253`, `agent_ops.rs:4393`, `spawn.rs:1881/2426`, config reloads at `session_admin.rs:658/716`, and trust grants at `folder_trust_prompt.rs:271`. Subagents retain their previous empty-seed behavior (`handle_request.rs:1237`), with inline servers scrubbed at line 2117.

**No new saved-key disclosure path found.** ACP reference/value scrubbing remains at [key_naming.rs:541](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-config/src/key_naming.rs:541); project/plugin materialization retains final scrubbing at [mcp.rs:491](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-config-types/src/mcp.rs:491). Copy marks cannot be supplied over ACP: seed entries are private, there is no deserializer, and conversion from a plain list creates only unmarked entries (`managed_mcp.rs:133/157`).

**Tests are useful but insufficient.** Managed P141 tests cover renamed/plugin-shadowing edit/delete behavior and a static kill switch. The plugin test manually assigns the actor seed (`hooks_plugins_p141_tests.rs:111`), missing update/reconnect divergence. The single-merge test exercises `resolve_mcp_servers`, not the update endpoint. Updated P138/P136 assertions preserve their intended coverage, but existing raw-vector precedence tests bypass the new marked-copy branch. Red/green execution was not verified.

**DO-NOT-LAND**
