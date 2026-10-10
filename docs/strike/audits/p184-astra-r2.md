# P184 Astra round 2 (gpt-6-astra, read-only) - final report

Full transcript kept off-repo (it echoes local memory files); sha256 5053d6a691aaf971c0f76b6cbc1d8085d4a6ce6a2e99b57806b1e700053815c0.

Audited `1010250ff..d7eac3f12`, with baseline comparison to `de6ca7dd` (v1.0.21). **One HIGH attributable to P184 remains.** Read-only; no Cargo or runtime tests.

| Requirement | Result | Evidence |
|---|---|---|
| Parse first; enumerate every target; judge the actual destination | **NOT FIXED** | Enumeration covers Add/Update/Delete and both move endpoints at [tool.rs:232](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-tools/src/implementations/codex/apply_patch/tool.rs:232). Writer spelling is restored, but the scoped-Allow escape below remains in [gate_preflight.rs:119](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/gate_preflight.rs:119). |
| Strictest result wins; Ask lists every target; malformed patches refused | **FIXED for manager/ACP decision aggregation** | Deny/Ask aggregation at [gate_preflight.rs:132](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/gate_preflight.rs:132); malformed/empty refusal at [manager/mod.rs:1667](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:1667); complete prompt locations/title at [manager/mod.rs:1306](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:1306). This does not correct H1’s erroneous individual Allow. |
| Tool writes only the judged target set | **FIXED at the lexical target-set level; physical race remains an acceptable residual** | The shared parser enumerates targets; execution uses baseline `cwd.join(path)` and checks every computed write/delete against that set at [tool.rs:441](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-tools/src/implementations/codex/apply_patch/tool.rs:441). This is an internal consistency guard, not an approved physical-target capability. |
| Local manager, ACP, hub mapping; ownership fences | **FIXED within P184’s specified scope** | ACP supplies targets at [tool_calls.rs:1693](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-shell/src/session/acp_session_impl/tool_calls.rs:1693). Only the mapping line changes in [hub_permission.rs:261](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/hub_permission.rs:261). `hub.rs`, `policy.rs`, and `shell_access.rs` are untouched. Full hub enforcement remains a P173 reconciliation item. |
| Ordinary allowed/auto/session-granted patches stay prompt-free | **FIXED for local manager/ACP** | Session-grant, auto-edit, and policy-Allow paths remain at [manager/mod.rs:1833](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:1833), [manager/mod.rs:1883](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:1883), and [manager/mod.rs:2171](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:2171). |

**NEW regression versus both baselines — H1, HIGH: a backslash-named symlink lets a scoped Allow authorize an outside-workspace write.**

Location: [gate_preflight.rs:119](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/gate_preflight.rs:119), particularly the restrictive-only handling of other spellings at line 122.

Concrete reproduction, derived from source and **not executed**:

1. On Unix, use a canonical temporary root `<T>`. Create directories `<T>/ws/safe/alias` and `<T>/outside`. Create a separate directory entry literally named `<T>/ws/safe\alias`, symlinked to `<T>/outside`.
2. Set cwd to `<T>/ws`; configure only `Allow(Edit(safe/**))`. Disable auto/YOLO, use the default Ask prompt policy, and have no session edit grant.
3. Submit:

```text
*** Begin Patch
*** Add File: safe\alias/key
+changed
*** End Patch
```

The resulting path decisions are:

| Evaluation | Result |
|---|---|
| Written path `<T>/ws/safe\alias/key` | Policy rewrites `\` to `/`, matches `safe/**`, and follows the separate `safe/alias` directory: **Allow**. |
| Literal physical destination `<T>/outside/key` | No rule matches: **None**. |
| P184 aggregation | Discards that physical `None`, retains the written-path **Allow**, and executes without prompting. |

The rewriting occurs in [policy.rs:1053](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/policy.rs:1053), using `path_match_string` at line 1066. P184 correctly discovers the literal physical destination, but only imports Ask/Deny from it. Consequently, the existing workspace-escape Allow revocation never sees the actual symlink destination.

The writer follows the literal symlink and writes `<T>/outside/key`. This requires a stable symlink; no race or retargeting is needed.

Both `1010250ff` and `de6ca7dd` classify this call as `Edit("apply_patch")`, which does not match `safe/**`, so the same configuration prompts. P184 therefore introduces an unattended write outside the scoped allowance.

The correction belongs in P184’s preflight/tests: apply the workspace-escape check to the **literally resolved destination** before retaining an Allow. The existing backslash regression tests explicit Deny, not this allow-only case.

| Round-1 finding | Round-2 disposition |
|---|---|
| Looser spelling authorizes a different file | **Still open as a failure class.** The original `w/../allowed/key` trigger is removed by the resolver reversion, but H1 demonstrates another spelling-based Allow escape. |
| Quote stripping deletes the wrong file | **Resolved.** Literal filenames survive `cwd.join(path)` at [tool.rs:441](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-tools/src/implementations/codex/apply_patch/tool.rs:441); regression coverage is present at [tool.rs:879](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-tools/src/implementations/codex/apply_patch/tool.rs:879). |
| Display-cwd mapping creates a destructive self-move | **Resolved for the reported trigger.** Absolute move destinations remain absolute; display-cwd remapping is removed. Destination construction is at [tool.rs:313](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-tools/src/implementations/codex/apply_patch/tool.rs:313). |
| Session edit grant defeats per-target Ask | **Resolved.** The later edit-grant branch now requires `!policy_forced_prompt` at [manager/mod.rs:2221](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:2221). |
| Unix backslash-named symlink bypasses an explicit Deny | **Resolved for the reported Deny case.** Literal physical resolution at [gate_preflight.rs:40](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/gate_preflight.rs:40) supplies the restrictive check. H1 concerns Allow propagation instead. |
| Hub bypass, including ordinary hub prompting behavior | **Still open on the audited tip; P173 reconciliation item.** Dispatch still bypasses per-target policy at [hub.rs:484](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/hub.rs:484). P173’s separate checkout contains `hub_input_accesses`; its combined integration is not proven here. This is outside P184’s mapping-only ownership. |
| “Write only what was judged” binds only lexically | **Residual-acceptable for this packet.** The normal ACP route retains the same patch input, and [tool.rs:448](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-tools/src/implementations/codex/apply_patch/tool.rs:448) checks internal target consistency. It does not receive an independently approved physical-target set. |
| Symlink retargeting after permission | **Residual-acceptable, inherited.** Filesystem writes still resolve paths at execution through [file_system.rs:148](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-tools/src/computer/local/file_system.rs:148). No race-free physical binding is claimed. |
| YOLO / `prompt_policy=allow` bypass ordinary Ask | **Residual-acceptable as the stated product design.** These branches remain at [manager/mod.rs:1822](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:1822) and [manager/mod.rs:2362](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:2362); managed denies precede them. |

Hook rewriting still occurs before target extraction. `git diff --check` passes, HEAD remained `d7eac3f12`, and reviewed files match that commit. Build, runtime, and visual prompt behavior were not tested.

VERDICT: NOT-LAND-OK
