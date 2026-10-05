# P111 Astra round 8 (gpt-6-astra, read-only) on 3c73a123 (HEAD 35c52f98)

Brief: p111-astra-r8-brief.md. Final report, verbatim:

**R7 #1 is FIXED. R7 #2a is NOT FIXED end-to-end.** One new HIGH defect is introduced by the fallback.

Reviewed `35c52f98` (code tip `3c73a123`) against the response commits and `v1.0.20`. No builds, tests or modifications performed; worktree remains clean. Supplied execution results were not independently rerun.

| R7 HIGH | Assessment | Evidence |
|---|---|---|
| #1 Witness eviction | **FIXED** | [compaction_witness.rs:158](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:158) selects the protected checkpoint from the transcript; retention at line 167 no longer depends on pruning succeeding. Read errors retain all entries. |
| #2a Compaction fork coherence | **NOT FIXED** | [copy.rs:367](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:367) catches the reported newly appended marker, but misses the already-committed-marker interleaving below. |

1. **HIGH — Residual #2a: a prefix-preserving compaction rewrite can still produce a stale fork. REGRESSION versus v1.0.20.**

   Concrete sequence: C’s marker commits before the initial marker scan. The source still contains `H`, and the fork fingerprints and reads `H` at [copy.rs:307](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:307). Before witness recovery, C’s separate rewrite lands as `H + Q`. This is the supported system-head-only compaction shape already covered by [compaction_witness.rs:560](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:560).

   Recovery reads the **new** file, recognizes the landed rewrite at [compaction_witness.rs:249](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:249), and returns `None`. The fork consequently keeps its **earlier** `H`. C was already in `markers_seen`, and [copy.rs:749](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:749) accepts `H + Q` because it starts with `H`.

   The child receives C’s transcript/checkpoint but pre-compaction history and no witness. No I/O failure is required. `v1.0.20:crates/codegen/fuigo-shell/src/session/persistence.rs:2961–2975` reconstructed C on load, preventing this stale-history outcome.

   The new test seam at [copy.rs:322](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:322) runs **after recovery**, so it cannot exercise this interleaving. Recovery and validation must refer to the same captured history, including when replacement preserves its prefix.

2. **HIGH — NEW: the fallback can discard valid tool history in a filtered fork. REGRESSION versus v1.0.20 for this copy path.**

   Concrete scenario: C0 successfully compacts a subagent. A subsequent resume installs a different system head at [prompt_build.rs:297](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/acp_session_impl/prompt_build.rs:297); its successful persistence legitimately clears the witness through [acp_session.rs:1513](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/acp_session.rs:1513). The resumed session then completes a tool turn T. Later, C1 writes its witness but fails to append its activation marker.

   A filtered disk fork now finds C1’s matching candidate but no entry for C0. [compaction_witness.rs:324](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:324) invokes the new fallback. The changed system head fails the serialized-prefix comparison at line 373, although C0’s rewrite succeeded. Line 383 therefore replays C0 and the transcript, dropping T’s tool calls/results through [replay.rs:289](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/helpers/replay.rs:289). The child silently loses valid saved context.

   In `v1.0.20:crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:287`, filtered copies read the saved history directly; lines 295–296 preserve complete tool exchanges, and lines 348–351 create an empty transcript. Release therefore preserved T on this path. Ordinary resume’s similar text-only loss was pre-existing, but extending it to these copies is a regression.

   Missing witness entries do not establish eviction: successful rewrites deliberately remove them. The fallback needs evidence distinguishing those states.

3. **HIGH — R7 #2b remains: ordinary concurrent appends produce inconsistent forks. PRE-EXISTING in v1.0.20; intentionally unaddressed.**

   In an uncompacted session, a complete turn appended after [copy.rs:309](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:309) but before transcript staging appears in the child’s transcript and is absent from its model history. The prefix check accepts it. Release already separated those reads at `v1.0.20:crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:287` and `:353`.

4. **MEDIUM — NEW: filtered copies unnecessarily depend on reading the entire transcript. REGRESSION versus v1.0.20.**

   [copy.rs:305](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:305) scans unconditionally, including `fork_filter=true`, whose transcript is discarded and whose marker comparison never runs. This adds O(transcript-size) I/O and makes an unreadable `updates.jsonl` fail a copy with otherwise readable history. The subagent caller can then fall back to fresh context at [subagent/mod.rs:1319](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/agent/subagent/mod.rs:1319). Release explicitly skipped transcript reads for filtered copies at `copy.rs:348–351`. No timing measurements were performed.

DO-NOT-LAND
