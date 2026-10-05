# P111 Astra round 7 (gpt-6-astra, read-only) on 76bbecdf (HEAD 8dd3bd49)

Brief: p111-astra-r7-brief.md. Final report, verbatim:

**Four r6 findings are FIXED; #4 and #5 remain HIGH.**

Reviewed implementation `76bbecdf` at actual HEAD `8dd3bd49`—the additional commit contains only the r7 brief. No builds, tests, or modifications performed; worktree remains clean.

| R6 finding | Assessment | Evidence |
|---|---|---|
| #1 Successful rewrite duplicates compacted payload | **FIXED** | [compaction_witness.rs:225](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:225) recognizes the expected rewrite before reconstructing projection plus tail. |
| #2 Recovered corruption bypasses P96 repair | **FIXED** | Recovery supplies its skipped-line count at [jsonl/mod.rs:1638](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/mod.rs:1638); P96 rereads through that function at [load_repair.rs:370](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/load_repair.rs:370). Fork recovery invokes structural repair at [copy.rs:298](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:298). |
| #3 Post-rename error classified as not committed | **FIXED** | [storage/mod.rs:109](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/mod.rs:109) preserves the rename outcome; [jsonl/mod.rs:1817](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/mod.rs:1817) maps it directly to `Committed`. |
| #4 Required witness can be evicted | **NOT FIXED** | Protecting the first entry at [compaction_witness.rs:146](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:146) depends on best-effort pruning succeeding. |
| #5 Fork combines source generations | **NOT FIXED** | [copy.rs:346](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:346) checks only the original chat prefix, not coherence with the staged transcript. |
| #6 Unconditional additional transcript scan | **FIXED** | [compaction_witness.rs:281](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:281) exits before scanning when no fingerprint candidate matches. |

1. **HIGH — R6 #4: failed pruning still permits eviction of the active witness. REGRESSION versus 1.0.20.**

   Concrete scenario: the witness contains `[C0, C1]`; C1’s activation commits, but pruning fails before replacement—for example, temporary-file creation fails with ENOSPC. [compaction_witness.rs:159](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:159) only logs this failure, and [persistence.rs:2420](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/persistence.rs:2420) still acknowledges the committed compaction.

   If C1’s history rewrite also fails, its witness remains essential. Fifteen subsequent preparations whose activation markers fail grow the list past 16. Eviction removes **C1 at index 1**, preserving C0. Recovery then finds no candidate for the latest committed marker at [compaction_witness.rs:293](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:293), and resumes pre-C1 history.

   In **`v1.0.20`, `crates/codegen/fuigo-shell/src/session/persistence.rs:2961–2975`**, ordinary resume reconstructed the latest active modern checkpoint independently of this witness. This scenario therefore regresses release behavior.

   The protected entry must be determined from durable activation evidence, including when pruning fails. The added retention test assumes successful pruning at [compaction_witness.rs:511](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:511).

2. **HIGH — R6 #5: the prefix check does not establish a coherent fork snapshot. Two surviving cases have different release classifications.**

   **REGRESSION versus 1.0.20 — compaction crosses the copy boundary.** The fork reads history `H` and completes witness recovery at [copy.rs:289](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:289). A source compaction then commits its checkpoint and marker, before its separate history rewrite runs. The fork stages that new marker at [copy.rs:336](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:336). Its final check accepts the still-unchanged `H`.

   The child consequently contains pre-compaction model history alongside the committed compaction transcript. It has no recovery witness, and current resume keeps its chat file authoritative at [persistence.rs:3080](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/persistence.rs:3080). No I/O failure is required. A completed rewrite from `H` to `H + Q` also passes the prefix check.

   Release **`v1.0.20`’s `persistence.rs:2961–2975`** reconstructed the copied modern checkpoint on load, preventing this stale-history outcome.

   **PRE-EXISTING gap in 1.0.20 — ordinary concurrent appends.** In an uncompacted session, a complete turn can append after chat is read but before the transcript is staged. [copy.rs:703](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:703) accepts those appended bytes, but never adds them to `chat_to_copy`. The child displays that turn in its transcript while omitting it from model history. **`v1.0.20:crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:287` and `:353`** already performed these separate reads without source serialization.

   Closure requires a consistent boundary across chat, activation state, and transcript. The new standalone prefix test at [copy_tests.rs:2538](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy_tests.rs:2538) does not exercise either interleaving.

These are incomplete r6 fixes. I identified no additional independent defect introduced by `76bbecdf`.

DO-NOT-LAND
