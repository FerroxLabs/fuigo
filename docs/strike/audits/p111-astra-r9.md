# P111 Astra round 9 (gpt-6-astra, read-only, final round) on 5d5a00ac (HEAD 302c96d9)

Brief: p111-astra-r9-brief.md. Final report, verbatim:

**R8 #1, #2 and #4 are FIXED.** I identified no new independent defect introduced by `d5ad49a0` / `5d5a00ac`.

Reviewed HEAD `302c96d9`, implementation `5d5a00ac`, and `v1.0.20`. No builds, tests or modifications performed; worktree remains clean. Supplied execution results were not independently rerun.

| R8 finding | Assessment | Evidence |
|---|---|---|
| #1 Prefix-preserving compaction rewrite mid-copy | **FIXED** | [copy.rs:314](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:314) captures the bytes used for both fingerprinting and recovery at line 323. [compaction_witness.rs:286](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:286) judges those captured bytes, so the subsequent rewrite cannot make the earlier history appear current. The test seam now precedes recovery. |
| #2 Fallback without eviction evidence | **FIXED** | Actual eviction records the checkpoint ID at [compaction_witness.rs:181](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:181). The fallback requires that ID at [line 380](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:380). The reported cleared-witness scenario therefore preserves saved tool history. |
| #4 Unconditional transcript scan for filtered copies | **FIXED** | [copy.rs:306](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:306) skips the marker inventory for `fork_filter`. Conditional witness recovery can still inspect the transcript when needed. |

One precision correction: fingerprinting and recovery share captured bytes, but parsing still separately rereads the file through [copy.rs:317](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:317).

**Remaining HIGH — R8 #3 / R7 #2b: ordinary concurrent appends produce inconsistent forks. PRE-EXISTING in v1.0.20; intentionally outside this packet.**

Concrete scenario: an uncompacted source completes turn T after the history read at line 317 but before transcript staging at [copy.rs:366](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:366). The child’s transcript includes T, while its model history omits T. No new compaction marker triggers rejection, and [copy.rs:769](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:769) accepts appended bytes.

Release already separated these reads at `v1.0.20:crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:287` and `:353`. This is **not a regression introduced by these commits**.

The three requested fixes pass this source review. The explicitly retained HIGH prevents a landing verdict under your stated “LAND-* only with no BLOCKER/HIGH” rule.

DO-NOT-LAND
