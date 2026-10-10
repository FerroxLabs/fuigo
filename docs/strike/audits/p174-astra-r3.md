Audited clean `wt-p174` at `540721bc2` against `d1496d0fd`, `6221893ca`, and `de6ca7dda`. Source review only; no cargo or file changes. P173 hub files are untouched.

| Round-2 finding | Result |
|---|---|
| 1 — HIGH: dedupe hashes its own path resolution | **FIXED.** Both hash passes use the carried reader-resolved path. Ordinary relative/absolute reads retain their range, hash, and context checks. [read_dedupe_hook.rs:183](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-shell/src/session/acp_session_impl/read_dedupe_hook.rs:183) |
| 2 — MEDIUM: filesystem work stalls permission actor | **NOT FIXED completely.** The no-policy skip works, but the five-second timeout cannot interrupt the synchronous filesystem work described below. |
| 3 — MEDIUM: single-entry lists omit prompt listing | **FIXED.** One-entry read lists and image-tool local-file lists receive titles and locations. [manager/mod.rs:1618](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:1618) |

Two findings remain:

1. **HIGH — Timeout can permit an unjudged, denied resolved target. NEW regression versus round 2; reopens an exposure inherited from both older baselines.**  
   [manager/mod.rs:1881](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:1881) discards resolution on timeout and retains only the original spelling. [gate_preflight.rs:195](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/gate_preflight.rs:195) converts that uncertainty into an approvable Ask.

   Concrete scenario: `Read(secrets/**)` is denied; the stable symlink `public/k\u00a0ey` points to `secrets/key`; the model requests `public/k ey`. If Unicode sibling resolution takes six seconds, the manager abandons it after five seconds and prompts for the nonexistent ASCII spelling. Following approval, [read_dedupe_hook.rs:58](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-shell/src/session/acp_session_impl/read_dedupe_hook.rs:58) resolves again and labels the result “judged” without another policy evaluation. The reader—and dedupe hashing—can then open `secrets/key`.

   This needs neither symlink retargeting nor YOLO. Round 2 waited for resolution and would deny this stable target. Execution must refuse unresolved targets or complete resolution and policy evaluation before any reader/dedupe open.

2. **MEDIUM — The actor timeout is not an effective filesystem bound. Inherited round-2 residual.**  
   [manager/mod.rs:1332](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:1332) invokes synchronous `resolve_following_symlinks`; [policy.rs:1107](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/policy.rs:1107) calls synchronous `dunce::canonicalize`. A stalled filesystem can block inside that call indefinitely. For literal targets, the wrapped future has no asynchronous yield before this work, so Tokio’s timeout cannot interrupt it. Subsequent policy evaluation also performs synchronous filesystem resolution outside the timeout.

   Additionally, the new [tool_calls.rs:1960](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-shell/src/session/acp_session_impl/tool_calls.rs:1960) performs another unbounded resolution during preparation, including without policy or when the batch later disables dedupe. The no-policy manager improvement therefore does not establish bounded preparation.

I found no additional ordinary-read dedupe correctness regression or newly introduced prompt-listing regression. The intentional whitespace exclusion remains. Apart from the timeout bypass above, I found no further in-scope unjudged model-selected opens in native Codex/Fuigo reads, dedupe, or the three image tools under your stated exclusions.

**NOT-LAND-OK**
