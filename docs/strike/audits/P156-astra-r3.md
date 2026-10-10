# P156 Astra round 3 (gpt-6-astra, read-only, final round) — verdict

Full transcript sha256: 7d495ae032173a905eb4ba05891fb1d6fc9c8d76ff9dbb179dceef02173ba02f (kept off-repo).

**One HIGH remains, plus one MEDIUM regression. No BLOCKER or LOW findings.**

Audited clean `strike/p156` at `562936d7` against the supplied `de6ca7dda4a0d0983664c18ab0daec46956cae6c` base. Findings are source-derived, cross-checked with an in-memory POSIX path model. No Cargo or Rust tests ran; no files changed. Changed-code `git diff --check` passed.

| Round-2 finding | Verdict | Evidence |
|---|---|---|
| HIGH #1: incomplete outward-link containment | **NOT FIXED** | Both original examples are addressed, but physical-workspace operands containing `..` bypass containment. See new finding 1 and [policy.rs:296](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:296). |
| HIGH #2: missing written absolute form with overlapping bases | **FIXED** | A distinct physical-relative match now always contributes its written absolute spelling, regardless of existing lexical-relative forms. [policy.rs:924](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:924). Regression case: [policy_symlink_cwd_tests.rs:344](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy_symlink_cwd_tests.rs:344). |
| MEDIUM #3: narrow allows lost on internal links | **FIXED** | A target inside the physical workspace retains the direct Allow without requiring its resolved basename to match. [policy.rs:303](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:303). Narrow file/directory cases: [policy_symlink_cwd_tests.rs:335](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy_symlink_cwd_tests.rs:335). |

1. **HIGH — NEW counterexample: harmless `sub/../` defeats physical-workspace containment.**

   Use the existing fixture: `L = fixture.cwd()`, `W = fixture.physical_ws()`. It already supplies `W/sub/` and `W/escape → outside`. [Fixture construction:419](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy_symlink_cwd_tests.rs:419).

   ```text
   cwd:     L
   rule:    Allow(Edit(<W>/**))
   operand: <W>/sub/../escape/x
   target:  <fixture-root>/outside/x
   ```

   Initial matching normalizes the operand to `W/escape/x`, so the absolute workspace Allow matches. Resolution correctly reaches the outside target. However, `written` is outside the **written** cwd, and the presence of `..` disables the **physical** cwd containment check. `allow_leaves_workspace` therefore returns false at [policy.rs:297](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:297), preserving Allow through [policy.rs:267](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:267).

   **Result:** `W/escape/x` loses Allow, but adding the harmless `sub/../` restores it. This is a newly identified **retained baseline gap**, not new widening against v1.0.21. It leaves requirement 3 unmet.

   The P156 correction needs containment for this physical-rooted traversal case and a regression beside the existing physical-absolute case.

2. **MEDIUM — NEW regression versus base: explicitly allowed outside targets lose approval under `/tmp` spelling.**

   Concrete fixture:

   ```text
   cwd:   /tmp/p156/ws
   link:  /tmp/p156/ws/escape → /tmp/p156/outside
   rules: Allow(Edit(./**))
          Allow(Edit(/tmp/p156/outside/**))
   edit:  escape/x
   ```

   On this Mac, read-only inspection confirms `/tmp → /private/tmp`. The resolved target is `/private/tmp/p156/outside/x`.

   At [policy.rs:306](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:306), the preservation check uses only the physical workspace as its base. Because the target is outside that base, it receives no written `/tmp/p156/outside/x` form. The explicit outside Allow therefore fails to match, and the direct Allow is discarded.

   **Base: Allow. HEAD: None.** Naming `/tmp/p156/outside/x` directly still retains Allow. Through the link, ordinary Edit requests now prompt without a session grant; `PromptPolicy::Deny` rejects them. [manager/mod.rs:2132](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:2132), [manager/mod.rs:2256](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:2256).

   This also affects a single parent-scoped `Allow(Edit(/tmp/p156/**))`. The fixture’s canonicalized temporary root hides this case. [policy_symlink_cwd_tests.rs:417](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy_symlink_cwd_tests.rs:417). The correction must preserve separately authorized outside targets across these spellings while retaining the workspace-only containment restriction.

| Requirement | Verdict | Evidence |
|---|---|---|
| 1. Deny/Ask matches written and real cwd spellings for native tools and shell gate | **FIXED — source review** | Native Read/Edit/Grep share the matcher; both relative forms and the written absolute form are retained. [policy.rs:830](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:830), [policy.rs:911](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:911). Shell uses it for direct and resolved operands. [shell_access.rs:205](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/shell_access.rs:205). |
| 2. Allow never broader than v1.0.21 | **FIXED** | Initial Allow matching retains written-only forms; resolved evaluation cannot grant Allow. [policy.rs:348](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:348), [policy.rs:261](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:261). Finding 1 is inherited. |
| 3. Workspace Allow cannot cover an outward-link target | **NOT FIXED** | Finding 1: the `..` exemption preserves an otherwise revoked workspace Allow. [policy.rs:297](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:297). |
| 4. Windows/WSL unaffected | **FIXED — source review only** | Existing path-string and shell drive/slash normalization remain unchanged. [policy.rs:1018](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:1018), [shell_access.rs:1257](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/shell_access.rs:1257). Windows/WSL runtime behavior was not executed. |
| 5. Other Fuigo semantics unchanged | **NOT FIXED** | Finding 2 introduces additional prompts/rejections despite explicit outside authorization. [policy.rs:306](/Volumes/Mando/WaylandBots/Fuigo/wt-p156/crates/codegen/fuigo-workspace/src/permission/policy.rs:306). |

No newly lost existing Deny or widened Allow was identified against the supplied base. Plain in-workspace edits under a symlinked `/tmp` cwd retain their allows.

**NOT-LAND-OK**
