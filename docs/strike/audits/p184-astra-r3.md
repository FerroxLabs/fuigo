# P184 Astra round 3 (gpt-6-astra, read-only) - final report

Full transcript kept off-repo (it echoes local memory files); sha256 4d6e819c77610a581096716956dc144aada964969f1ebdcdbe986b280fc3cbc1.

Audited `1010250ff..4357af418`, compared with `de6ca7dd` (v1.0.21). **One HIGH and one MEDIUM regression remain.** Read-only; no cargo or runtime tests. Reproductions below are source-derived.

| Requirement | Result | Evidence |
|---|---|---|
| Enumerate Add/Update/Delete and both move endpoints; judge the actual written paths | **NOT FIXED** | Enumeration is complete at [tool.rs:232](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-tools/src/implementations/codex/apply_patch/tool.rs:232), but the Allow escape below remains. |
| Strictest decision wins; Ask identifies every target | **FIXED for aggregation** | Deny/Ask/all-target-Allow aggregation at [gate_preflight.rs:175](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/gate_preflight.rs:175); complete prompt locations at [manager/mod.rs:1306](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:1306). This cannot correct an erroneous individual Allow. |
| Refuse unparseable/empty patches | **FIXED for manager/ACP** | Refusal precedes approval shortcuts at [manager/mod.rs:1667](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:1667). |
| Refuse changes outside the parsed target list | **FIXED at the accepted lexical level** | Every computed write/delete is checked before execution at [tool.rs:448](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-tools/src/implementations/codex/apply_patch/tool.rs:448). |
| ACP sends targets from the execution input | **FIXED** | Target extraction follows hook rewriting at [tool_calls.rs:1693](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-shell/src/session/acp_session_impl/tool_calls.rs:1693). |
| Hub mapping-only change; ownership fences preserved | **FIXED** | Only the mapping line changes in [hub_permission.rs:261](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/hub_permission.rs:261). `hub.rs`, `policy.rs`, and `shell_access.rs` are unchanged. |
| Ordinary allowed/auto/session-granted patches remain prompt-free | **NOT FIXED** | The new physical-Allow condition at [gate_preflight.rs:154](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/gate_preflight.rs:154) introduces the `/tmp` regression below. Ordinary auto/session-grant paths remain available. |

**Round-2 H1: its exact reproduction is resolved.** With `Allow(Edit(safe/**))`, the backslash-named symlink’s ordinary outside destination receives no Allow; `plain=false` causes the written Allow to be dropped. Both named regression tests are present, but were not executed. The broader Allow-escape class remains open.

**1. HIGH — An absolute Unix backslash path still escapes a scoped Allow. New versus both baselines.**

Use a canonical writable temporary root `<T>`. Create two distinct ordinary directories:

- `<T>/ws/safe`
- `<T>/ws\safe` — a sibling of `ws`, with a literal backslash in its name.

Set cwd to `<T>/ws`, configure only `Allow(Edit(<T>/ws/safe/**))`, disable auto/YOLO, and have no session edit grant. Submit:

```text
*** Begin Patch
*** Add File: <T>/ws\safe/key
+changed
*** End Patch
```

The writer targets `<T>/ws\safe/key`, outside both the workspace and allowed subtree. However:

- Physical and lexical paths are identical, so `plain=true` at [gate_preflight.rs:51](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/gate_preflight.rs:51).
- The policy evaluation called at [gate_preflight.rs:126](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/gate_preflight.rs:126) converts the literal backslash into `/` through [policy.rs:1066](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/policy.rs:1066).
- The resulting spelling `<T>/ws/safe/key` matches the Allow. The new condition retains it, and execution proceeds without prompting.

This requires **no symlink and no race**. Both baselines evaluate `Edit("apply_patch")`, which does not match this scoped rule, and therefore prompt. The separator conversion is inherited; exposing this unattended `apply_patch` write is a P184 regression. Literal physical resolution alone does not establish that the subsequent policy match preserved that identity.

**2. MEDIUM — Explicitly allowed absolute `/tmp` targets acquire a new prompt. Introduced by `4357af418`; regression versus both baselines.**

On macOS, with `/tmp -> /private/tmp`, create ordinary directories `/tmp/p184-ws` and `/tmp/p184-other`. Set cwd to `/tmp/p184-ws`, configure only `Allow(Edit(/tmp/**))`, disable auto/YOLO, and have no session edit grant. Submit:

```text
*** Begin Patch
*** Add File: /tmp/p184-other/key
+changed
*** End Patch
```

The written path receives Allow. Its physical destination is `/private/tmp/p184-other/key`.

Because the target is outside the cwd prefix, [gate_preflight.rs:46](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/gate_preflight.rs:46) uses the unchanged lexical path as `expected`; consequently `plain=false`. The physical spelling does not match `/tmp/**`, because Allow evaluation deliberately withholds physical-cwd aliases at [policy.rs:370](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/policy.rs:370). The new condition drops the valid written Allow and prompts.

Both baselines allow their placeholder `/tmp/p184-ws/apply_patch` under the same rule without prompting. The actual requested target also lies explicitly within `/tmp/**`; the symlink is above the cwd, with no link crossed below it.

Ordinary relative or absolute descendants of a symlinked cwd retain the intended `plain` exemption. This failure concerns allowed absolute targets outside that cwd prefix.

`git diff --check` passes; reviewed files match `4357af418`, and the worktree is unchanged. Accepted P173 reconciliation, lexical binding/TOCTOU, and YOLO/prompt-policy residuals remain excluded from this verdict.

VERDICT: NOT-LAND-OK
