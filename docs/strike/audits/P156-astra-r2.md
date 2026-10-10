# P156 Astra round 2 (gpt-6-astra, read-only) — final verdict

Full transcript sha256: 83e34922ea8c629dc8691d564490489c6702edeba324e3e86026da95aa02af7e (kept off-repo).

Audited clean `strike/p156` at `5dba40490a42027236dbfcc4050e4edbb6560f66` against `de6ca7dda4a0d0983664c18ab0daec46956cae6c`.

**Two HIGH issues remain, plus one new MEDIUM regression.** Findings below are source-derived, cross-checked with an in-memory path model. No Cargo or Rust tests ran; no files changed.

| Round-1 finding | Verdict | Evidence |
|---|---|---|
| HIGH #1: overlapping cwd prefixes lose physical-relative spelling | **FIXED** | Both relative forms are now accumulated independently at [policy.rs:893](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:893). Regression coverage includes native Deny/Ask and shell at [policy_symlink_cwd_tests.rs:279](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy_symlink_cwd_tests.rs:279). |
| HIGH #2: workspace Allow survives an outward symlink | **NOT FIXED** | The original `escape/x` reproducer is addressed, but overlapping bases and physical workspace operands still bypass containment. See finding 1 below; [policy.rs:267](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:267). |
| LOW #3: synchronous filesystem work | **NOT FIXED** | Cwd resolution remains synchronous and cached only within an evaluation. It is now consulted even when the written prefix matches: [policy.rs:869](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:869), [policy.rs:901](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:901). Latency impact remains unmeasured. |

1. **HIGH — R1 #2 remains incomplete: target rule matching does not establish workspace containment.**

   Using the checked-in fixture, set `cwd = root/link/..`, which resolves to `root/b/c`. With `Allow(Edit(./**))`, edit `real/ws/escape/x`. It resolves to `root/outside/x`, outside the physical workspace.

   Nevertheless, `allow_rule_matches` offers the target relative to the **lexically normalized** cwd, `root`, producing `./outside/x`. The same workspace allow matches again, so **Allow survives**. The relevant branches are [policy.rs:267](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:267), [policy.rs:288](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:288), and [policy.rs:893](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:893). The fixture already supplies these links at [policy_symlink_cwd_tests.rs:371](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy_symlink_cwd_tests.rs:371).

   A second omitted case uses the ordinary fixture cwd: `Allow(Edit(<physical_ws>/**))` with operand `<physical_ws>/escape/x`. The operand fails the guard’s **written-cwd-only** prefix check, so its Allow also survives resolution outside.

   Both are retained baseline gaps, not new Allow widening. Requirement 3 remains unmet.

2. **HIGH — NEW finding: absolute written Deny/Ask still disappears with overlapping cwd bases.**

   On this Mac, read-only inspection confirmed `/tmp/..` resolves to `/private` while normalizing lexically to `/`. Consider:

   ```text
   cwd:     /tmp/..
   rule:    Deny(Read(/tmp/p156-key))
   operand: tmp/p156-key          → Reject
   operand: /private/tmp/p156-key → no matching decision
   ```

   Both operands name the same target. For the physical operand, the new matcher supplies `./tmp/p156-key`, but suppresses the absolute written form `/tmp/p156-key` because `rels` is already nonempty. See [policy.rs:909](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:909).

   The already-physical operand needs no further symlink resolution. Ask, Edit/Grep, and shell file access share the gap through [policy.rs:804](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:804) and [shell_access.rs:205](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/shell_access.rs:205).

   This is **newly identified but inherited from v1.0.21**, and remains an unmet requirement 1.

3. **MEDIUM — NEW regression: narrow allows stop working for entirely in-workspace symlinks.**

   In the existing fixture, `alias → notes.toml`, both inside the workspace. With `Allow(Edit(alias))`, `Edit("alias")` returns **Allow in the base**, but **None at HEAD**: the resolved basename does not match `alias`, so [policy.rs:267](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:267) revokes the allow despite the target remaining inside the workspace.

   Without a session edit grant, this introduces confirmation prompts; with `PromptPolicy::Deny`, it blocks previously approved work. See [manager/mod.rs:2132](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:2132) and [manager/mod.rs:2256](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:2256). Added in-workspace tests use broad `./**` allows and miss this case: [policy_symlink_cwd_tests.rs:257](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy_symlink_cwd_tests.rs:257).

| Requirement | Verdict | Evidence |
|---|---|---|
| 1. Deny/Ask covers written and real spellings, native and shell | **NOT FIXED** | Relative overlap is fixed; absolute-pattern bypass remains in finding 2. |
| 2. Allow never broader than v1.0.21 | **FIXED** | Initial Allow matching retains written-only forms; target checks cannot grant Allow. [policy.rs:325](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:325), [policy.rs:261](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:261). |
| 3. Workspace Allow cannot authorize an outward symlink target | **NOT FIXED** | Finding 1. |
| 4. Windows/WSL spellings unaffected | **FIXED — source review** | Existing slash/drive normalization is unchanged: [policy.rs:998](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:998), [shell_access.rs:1257](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/shell_access.rs:1257). Native Windows/WSL execution remains unverified. |
| 5. Other Fuigo semantics unchanged | **NOT FIXED** | Finding 3 introduces extra prompts. Tilde handling, uncollapsed symlink traversal, unpinned-cwd Ask, escalate-only shell decisions, and restriction-triggered unresolvable-symlink Ask remain preserved at [policy.rs:938](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:938), [policy.rs:279](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:279), and [shell_access.rs:199](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/shell_access.rs:199). |

No newly widened Allow or loss of a previously working Deny was identified. Inherited TOCTOU races are not findings here. Code-only `git diff --check` passed; the full diff flags whitespace in the committed round-1 report.

**NOT-LAND-OK**


