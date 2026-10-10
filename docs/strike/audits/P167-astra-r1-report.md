# P167 Astra round 1 report (gpt-6-astra, read-only, against 0fbcfb5c3)

Full transcript sha256: 2b2c06362807bff969e21015e74614ac07cc3168dc7b121e749f770f6ccd2bcf (kept outside the repo; 29k lines).

Reviewed `strike/p167@0fbcfb5c3` against `f5e6cfdfb`, the supplied v1.0.21 baseline, and the upstream references. No files modified; no Cargo or native tests run. `git diff --check` passed.

| Item | Result | Evidence |
|---|---|---|
| **S8** | **NOT FIXED** | Ordinary corruption/read failures now refuse writes, and relative homes are rejected: [trust.rs:136](/Volumes/Mando/WaylandBots/Fuigo/wt-p167/crates/codegen/fuigo-workspace/src/trust.rs:136), [trust.rs:191](/Volumes/Mando/WaylandBots/Fuigo/wt-p167/crates/codegen/fuigo-workspace/src/trust.rs:191), [trust.rs:356](/Volumes/Mando/WaylandBots/Fuigo/wt-p167/crates/codegen/fuigo-workspace/src/trust.rs:356). However, the strict reader still follows symlinks and has a check/open race, detailed below. The full stated security contract remains unmet. |
| **S9** | **NOT FIXED** | Canonical-key checks and `GrantOutcome` are implemented. CLI and hooks callers report outcomes. Embedded `SessionLocal` correctly continues without quitting: [lifecycle.rs:714](/Volumes/Mando/WaylandBots/Fuigo/wt-p167/crates/codegen/fuigo-pager/src/app/dispatch/session/lifecycle.rs:714). But the stderr caller still converts a refused grant into cached trust, and GUI failures remain log-only. |
| **S17** | **FIXED** | AuthManager and all three managed-policy identity readers now share the resolver: [auth/storage.rs:45](/Volumes/Mando/WaylandBots/Fuigo/wt-p167/crates/codegen/fuigo-shell/src/auth/storage.rs:45), [auth/manager.rs:396](/Volumes/Mando/WaylandBots/Fuigo/wt-p167/crates/codegen/fuigo-shell/src/auth/manager.rs:396), [managed_config/store.rs:165](/Volumes/Mando/WaylandBots/Fuigo/wt-p167/crates/codegen/fuigo-shell/src/managed_config/store.rs:165), [store.rs:693](/Volumes/Mando/WaylandBots/Fuigo/wt-p167/crates/codegen/fuigo-shell/src/managed_config/store.rs:693). `clear_orphan` retains policy for that login. [back_up_unsynced_policy_files:28](/Volumes/Mando/WaylandBots/Fuigo/wt-p167/crates/codegen/fuigo-shell/src/managed_config/store.rs:28) and its removal-path invocation are unchanged. |

New regressions and test defects relative to the supplied baseline:

1. **HIGH — The new corruption test should fail with the fix too.**
   [folder_trust_grant_tests.rs:33](/Volumes/Mando/WaylandBots/Fuigo/wt-p167/crates/codegen/fuigo-workspace/src/folder_trust_grant_tests.rs:33) puts the supposed corruption after `#`. This is valid TOML; an independent, read-only Python TOML parse confirmed it. Granting the new repository should therefore rewrite the document and record trust, contradicting assertions at lines 41–48. Both baseline and fixed implementations fail this fixture; its red result cannot demonstrate the intended defect.

2. **MEDIUM — An existing Windows test now fails.**
   [trust.rs:792](/Volumes/Mando/WaylandBots/Fuigo/wt-p167/crates/codegen/fuigo-workspace/src/trust.rs:792) expects `/home/alice/.fuigo` to produce a store path. The newly added `is_absolute()` check rejects that drive-less path on Windows, returning `None`. Use a platform-valid absolute fixture. [Rust’s documented Windows path semantics](https://doc.rust-lang.org/std/path/struct.Path.html#method.is_absolute) establish this source-level failure; Windows tests were not executed.

3. **MEDIUM — Valid standalone worktrees can become impossible to trust after their source repository is deleted.**
   Fuigo deliberately retains the recorded, possibly missing source path as the workspace key: [trust.rs:469](/Volumes/Mando/WaylandBots/Fuigo/wt-p167/crates/codegen/fuigo-workspace/src/trust.rs:469). The new [canonicalization precheck:359](/Volumes/Mando/WaylandBots/Fuigo/wt-p167/crates/codegen/fuigo-workspace/src/folder_trust.rs:359) rejects it before granting. Consequently, an otherwise usable standalone checkout without an existing grant remains at the TUI trust question. The parent permitted the explicit grant. This needs a safe live-worktree key fallback, while retaining the canonical check.

4. **MEDIUM — GUI acceptance can now leave the workspace gated without telling the client why.**
   The new `Unrecorded` branch only logs, removes the dedup key, and returns; `SessionLocal` also only logs its durability warning: [folder_trust_prompt.rs:224](/Volumes/Mando/WaylandBots/Fuigo/wt-p167/crates/codegen/fuigo-shell/src/agent/mvp_agent/folder_trust_prompt.rs:224). Neither branch sends client-visible outcome feedback. Previously these persistence failures produced process-local grants and continued; now refusal introduces an unexplained gated state.

5. **MEDIUM — Empty auth overrides now select different credentials.**
   [auth/storage.rs:50](/Volumes/Mando/WaylandBots/Fuigo/wt-p167/crates/codegen/fuigo-shell/src/auth/storage.rs:50) treats `FUIGO_AUTH_PATH=""` as unset. The parent AuthManager attempted the empty filename and loaded no file-backed login; HEAD instead loads `<home>/auth.json`. A launcher exporting an empty override can therefore reuse an existing login unexpectedly. Sharing the resolver did not require changing this behavior. Non-UTF-8 overrides also change behavior: HEAD honors them instead of falling back.

6. **MEDIUM — Some regression coverage does not exercise the claimed failure.**
   The “shown path, not rederived root” fixture creates `other-root` as a sibling, so ordinary root derivation from `shown-repo` would still yield the shown path: [grant_tests:168](/Volumes/Mando/WaylandBots/Fuigo/wt-p167/crates/codegen/fuigo-workspace/src/folder_trust_grant_tests.rs:168). Also, existing write-failure tests now stop at unreadable-store rejection rather than reaching publication: [trust.rs:754](/Volumes/Mando/WaylandBots/Fuigo/wt-p167/crates/codegen/fuigo-workspace/src/trust.rs:754), [trust.rs:1388](/Volumes/Mando/WaylandBots/Fuigo/wt-p167/crates/codegen/fuigo-workspace/src/trust.rs:1388).

Remaining acceptance gaps, distinguished from newly introduced regressions:

- **HIGH — Stderr acceptance still fails open after refusal.** [agent/folder_trust.rs:324](/Volumes/Mando/WaylandBots/Fuigo/wt-p167/crates/codegen/fuigo-shell/src/agent/folder_trust.rs:324) reports `persist_trust`’s failure, then unconditionally returns `(true, true)`. [The caller caches that allow:275](/Volumes/Mando/WaylandBots/Fuigo/wt-p167/crates/codegen/fuigo-shell/src/agent/folder_trust.rs:275), permitting project-scoped configuration despite an `Unrecorded` outcome. The underlying allowance predates P167; P167 has not closed it.

- **MEDIUM — Strict-read symlink/TOCTOU protection is incomplete.** [trust.rs:380](/Volumes/Mando/WaylandBots/Fuigo/wt-p167/crates/codegen/fuigo-workspace/src/trust.rs:380) probes metadata, then separately calls `read_to_string`, which follows links. A readable symlink is accepted outright. Replacing an observed regular file with a dangling link between those operations makes the stale `is_symlink=false` branch classify the failed read as `Missing`, allowing publication from an empty document. The advisory lock does not protect against non-cooperating replacements. These risks existed in the parent; the new strict reader does not eliminate them. [Rust documents this metadata/use race](https://doc.rust-lang.org/std/fs/#time-of-check-to-time-of-use-toctou).

The genuine malformed-TOML, dangling-link, relative-home, TUI-refusal, and custom-auth tests are discriminating against the parent by inspection. The sandbox test’s continuation behavior already worked in the parent; its new toast assertion supplies the difference. Changing the older denied-write fixture to block the lock file is appropriate, but it is not native sandbox qualification.

Unix owner-only publication remains intact through `NamedTempFile`; Windows ACL enforcement is not established by the Unix-only permission assertion. macOS canonicalization consistently uses `dunce`; no macOS-specific regression was identified. No new xAI transmission path or user-facing Grok branding was found. P166 presence checks were excluded.

VERDICT: NOT LAND-OK
exit=0
