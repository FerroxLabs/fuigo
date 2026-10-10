# P184 Astra round 1 (gpt-6-astra, read-only) - final report

Full transcript kept off-repo (it echoes local memory files); sha256 02d1bbb3dd412d91aa0336a0ab6b98a4faaaaf76d08f3a6947075eeb5e7d44a4.

Audited `1010250ff..870e2d721`. The branch advanced during review, adding `0cd3e0013` and `870e2d721` after the two supplied commits. Baseline comparisons also used `de6ca7dd` (v1.0.21 code). **Read-only; no Cargo or runtime tests.** Reproductions below are source-derived.

| Requirement | Result | Evidence |
|---|---|---|
| **1. Parse first; enumerate every target; judge the written paths** | **NOT FIXED** | Parsing and Add/Update/Delete/move enumeration are implemented in [tool.rs:235](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-tools/src/implementations/codex/apply_patch/tool.rs:235). `870e2d721` adds resolved spellings, but combines permissions for spellings that can identify different files. Unix backslash/symlink handling also remains bypassable. See findings below. |
| **2. Strictest decision wins; Ask prompts with every target; malformed patches refused** | **NOT FIXED** | Aggregation and malformed-patch refusal work in [gate_preflight.rs:80](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/gate_preflight.rs:80) and [manager/mod.rs:1666](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:1666). Prompt locations enumerate targets at [manager/mod.rs:1305](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:1305). However, a session edit grant can subsequently override Ask at [manager/mod.rs:2231](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:2231). |
| **3. Write only what was judged** | **NOT FIXED** | The writer constructs `judged` from its own execution-time patch, rather than receiving approved targets: [tool.rs:454](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-tools/src/implementations/codex/apply_patch/tool.rs:454). This checks internal consistency, but does not bind execution to the permission decision or the physical targets checked earlier. |
| **4. Cover manager, ACP and hub; preserve ownership fences** | **NOT FIXED** | ACP supplies targets at [tool_calls.rs:1693](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-shell/src/session/acp_session_impl/tool_calls.rs:1693). The hub helper produces one comma-joined `Edit` display string, with malformed input falling back to the placeholder: [types.rs:274](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/types.rs:274). The hub dispatch does not invoke per-target policy evaluation. The ownership fences **are respected**: only its mapping line changes; `hub.rs`, `policy.rs` and `shell_access.rs` remain untouched. |
| **5. Ordinary allowed/auto/session-granted patches remain prompt-free** | **NOT FIXED across all required routes** | Local/ACP no-prompt paths remain available at [manager/mod.rs:1844](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:1844), `:1894` and `:2182`. The live hub route still prompts every mapped edit when not YOLO, without consulting those rules/grants: [hub.rs:484](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/hub.rs:484). |

**New regressions versus both baselines:**

1. **HIGH — A scoped Allow can authorize a different, out-of-scope file.**  
   Use writable, non-symlink fixture directories with `cwd=/w`, allow rule `Edit(allowed/**)`, auto disabled and no session grant. Submit an Add hunk targeting `w/../allowed/key`.

   The raw policy spelling normalizes to `/w/allowed/key` and receives Allow. The writer’s missing-leading-slash correction resolves it to `/w/../allowed/key`, physically `/allowed/key`, which the rule does not allow. `combine_decisions(Allow, None)` retains Allow.

   Evidence: [manager/mod.rs:1784](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:1784), [gate_preflight.rs:89](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/gate_preflight.rs:89), [resources.rs:495](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-tools/src/types/resources.rs:495).

   Both baselines prompt because the placeholder does not match `allowed/**`, and their writer targets `/w/allowed/key`. Allow must be justified for the actual destination; the unresolved spelling cannot independently confer authority.

2. **HIGH — Literal patch filenames can now delete the wrong file.**  
   On Unix, create distinct files named `report` and `report'`. Submit `*** Delete File: report'`. Both baselines delete `report'`. P184 strips the apostrophe and deletes `report`, leaving the requested file untouched.

   Evidence: the new resolver call at [tool.rs:446](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-tools/src/implementations/codex/apply_patch/tool.rs:446), quote stripping at [resources.rs:519](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-tools/src/types/resources.rs:519), and deletion at `tool.rs:500`. This behavior extends beyond the stated display-cwd and tilde changes.

3. **HIGH — Newly equivalent move endpoints destroy the resulting file.**  
   With real cwd `/w` and display cwd `/display`, update `a.txt` and move it to `/display/a.txt`. P184 resolves both endpoints to `/w/a.txt`, writes the destination, then deletes that same file and reports success.

   Evidence: destination resolution at [tool.rs:315](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-tools/src/implementations/codex/apply_patch/tool.rs:315), write/delete sequence at [tool.rs:561](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-tools/src/implementations/codex/apply_patch/tool.rs:561) and `:569`. Both baselines leave the result at `/display/a.txt`. The general self-move defect predates P184; display-cwd mapping introduces this new destructive trigger.

**Remaining bypasses and acceptance failures, distinguished from new regressions:**

- **HIGH — Session edit grants defeat per-target Ask.** Grant session edits on an ordinary `src/a.rs` patch, then submit a patch touching `docs/b.md` under `Ask(Edit(docs/**))`. Preflight returns Ask, but the later edit-grant branch returns Allow without prompting (`manager/mod.rs:2231`). This branch predates P184. YOLO also bypasses ordinary policy Ask at `:1833`; `prompt_policy=allow` does so at `:2369`. Denies and malformed-patch refusals precede the actor’s YOLO shortcut.

- **HIGH — Hub calls still bypass per-file enforcement.** With live permission prompting disabled—or session YOLO enabled—the hub proceeds directly to tool execution. With prompting enabled, approval permits execution without evaluating managed per-file denies. Evidence: `hub.rs:484`, `:499`, and [hub.rs:550](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/hub.rs:550). This is inherited and remains a **P173/P184 integration gate**; fixing it must respect P173 ownership.

- **HIGH — Unix backslash-named symlinks evade path denies.** Let the literal directory entry `safe\alias` be a symlink to `secrets`, and deny `Edit(secrets/**)`. Patch `safe\alias/key` in auto mode. Policy converts backslashes to separators before following the path, inspecting `safe/alias/key`; the Unix writer follows the actual `safe\alias` symlink into `secrets`. Evidence: [policy.rs:1053](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-workspace/src/permission/policy.rs:1053), `:1066`, and `gate_preflight.rs:85`. The protected-file floor does not cover arbitrary user-defined `secrets/**` rules. This policy behavior is inherited.

- **HIGH — Symlink retargeting after permission remains possible.** Judge `alias/key` while `alias` points into an allowed directory, then retarget it to a denied directory before execution. The writer’s reconstructed list still contains the same lexical path, so its guard passes and the write follows the new target. Evidence: `tool.rs:454`, `:473`, and [file_system.rs:148](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-tools/src/computer/local/file_system.rs:148). No approved physical-target binding reaches the writer. This is an inherited race, not a demonstrated runtime exploit in this audit.

The normal ACP hook rewrite occurs **before** target extraction ([tool_calls.rs:1556](/Volumes/Mando/WaylandBots/Fuigo/wt-p184/crates/codegen/fuigo-shell/src/session/acp_session_impl/tool_calls.rs:1556)); I found no post-check hook rewrite in that route. ACP plan mode continues rejecting `apply_patch` through its placeholder gate (`tool_calls.rs:225`). `git diff --check` passes; compilation, runtime behavior and visual prompt rendering remain untested.

VERDICT: NOT-LAND-OK
