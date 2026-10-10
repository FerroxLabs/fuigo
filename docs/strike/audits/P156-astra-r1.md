# P156 Astra round 1 (gpt-6-astra, read-only) — final verdict

Full transcript sha256: ae9529b82a012b0c4e78d60af1d5d21b83573c8486bebaecd1a24d631056caa2 (kept off-repo).

Audited `strike/p156` at `e26d3d155e42e4b72c7f3e0ed1ca47435b37fa44` against `de6ca7dd`, including upstream. Read-only; no cargo or tests run. `git diff --check` passed.

**Two HIGH findings remain. Both are pre-existing gaps retained by P156, not newly introduced regressions.**

| Requirement | Verdict | Evidence |
|---|---|---|
| 1. Deny/Ask matches written and real cwd spellings, native and shell | **NOT FIXED** | Ordinary symlinked-cwd cases are covered, but overlapping lexical/physical bases still lose the physical-relative spelling. See finding 1 and [policy.rs:860](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:860). Shell shares this matcher through [shell_access.rs:205](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/shell_access.rs:205). |
| 2. Allow never becomes broader | **FIXED** | Allow receives `without_physical()`, preserving its former matching forms; target rechecks accept only Reject/Ask. [policy.rs:292](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:292), [policy.rs:258](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:258). |
| 3. Workspace Allow cannot cover an outward symlink’s target | **NOT FIXED** | A matching Allow on the written alias survives resolution outside the workspace. See finding 2 and [policy.rs:265](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:265). |
| 4. Windows/WSL spellings unaffected | **FIXED — source review** | Existing slash/drive normalization is unchanged. Added spelling tests cover drive, verbatim and WSL UNC inputs, plus Windows-relative denies. Native Windows/WSL execution remains unverified. [policy.rs:2822](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:2822), [shell_access.rs:1257](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/shell_access.rs:1257). |
| 5. Other Fuigo semantics preserved | **FIXED — relative to base** | Tilde handling remains literal; `..` physical rechecks only escalate; unresolvable operand symlinks retain Ask; unpinned shell operands retain their Ask floor; shell Allow is discarded. [policy.rs:893](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:893), [policy.rs:250](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:250), [shell_access.rs:199](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/shell_access.rs:199), [shell_access.rs:254](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/shell_access.rs:254). |

Findings:

1. **HIGH — Physical-relative Deny/Ask still bypassed when the lexical cwd contains the physical cwd.**
   Concrete source counterexample: `cwd="/tmp/.."`, rule `Deny(Read(./tmp/**))`, operand `/private/tmp/key`. Read-only filesystem inspection confirmed this Mac resolves `/tmp/..` to `/private`, while lexical normalization produces `/`. At [policy.rs:860](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:860), stripping `/` succeeds, producing `./private/tmp/key`; `.or_else(...)` therefore never considers the physical-relative `./tmp/key`. The already-real operand does not trigger another target check. Ask has the same gap, as do native Edit/Grep and shell accesses using this matcher.

   Cwd overrides are retained without normalization at [handle.rs:775](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/handle.rs:775). This is an **unfixed existing restriction bypass**. Deny/Ask must consider both relative forms when both prefixes match; add coverage for a symlink followed by `..` in the cwd itself.

2. **HIGH — Written outward-symlink aliases retain workspace Allow.**
   Using the supplied fixture and `Allow(Edit(./**))`, the omitted call `edit("escape/x")` matches the written workspace. Resolution reaches `outside/x`, but an unmatched target produces `None`, and `combine_decisions(Allow, None)` preserves Allow. See [policy.rs:242](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:242), [policy.rs:258](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:258), and [policy.rs:1050](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:1050).

   The new test checks outside and physical spellings but omits the written alias under its Allow policy: [policy_symlink_cwd_tests.rs:196](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy_symlink_cwd_tests.rs:196). Ordinary targets can reach the manager’s approval branch at [manager/mod.rs:2084](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:2084). This also exists in the base. Requirement 3 needs resolved-target containment for workspace-rooted allows, including relative and written-absolute alias tests.

3. **LOW — NEW synchronous filesystem work during permission evaluation.**
   A restriction matching a path outside the lexical cwd can now trigger an additional cwd-resolution walk. `OnceCell` limits it to once per evaluation, shared across shell operands/recursion, but subsequent requests repeat it. [policy.rs:836](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:836), [shell_access.rs:35](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/shell_access.rs:35). The added I/O is established; its latency impact was not measured.

No new Allow widening, lost existing Deny, or `..` bypass was identified. Check/use symlink races remain inherited; this patch does not pin filesystem handles.

**NOT-LAND-OK**


