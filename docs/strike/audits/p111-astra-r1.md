# P111 Astra round 1: final report (gpt-6-astra, read-only; raw transcript sha256 c998d3fc328be043, kept outside the repo)

Audited `d1b6ba58..9b0cf538` on `strike/p111`. No builds, tests, or modifications performed. The worktree remains clean.

1. **HIGH — New regression: compaction fails on Windows.**  
   [compaction_witness.rs:63](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:63) opens the history read-only, then calls `sync_file_durable`. On Windows this reaches `FlushFileBuffers`, which requires write access. Consequently, ordinary manual and automatic compaction return `NotCommitted` before activation whenever the history exists. Use a write-capable, nontruncating handle. [Microsoft’s requirement](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers), [Rust implementation](https://github.com/rust-lang/rust/blob/main/library/std/src/sys/fs/windows.rs).  
   **Existing test:** `projection_only_while_the_chat_file_is_unchanged_since_the_commit` should catch this when executed natively on Windows; Linux/macOS execution cannot establish that.

2. **HIGH — New regression: refused-fork cleanup can delete another successful session.**  
   [copy.rs:281](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:281) checks existence separately from nonexclusive directory creation; [copy.rs:323](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:323) subsequently treats that observation as ownership. Concrete interleaving: fork A observes target X absent; another request using the supported `new_session_id=X` creates and completes X; A continues, encounters the missing-checkpoint refusal, and recursively deletes X. Neither the fork handler nor directory creator reserves that identity exclusively. Cleanup needs actual exclusive ownership.  
   **Existing test:** No. The added refusal test uses one fresh, uncontended destination.

3. **HIGH — Retained defect: snapshot-loading failure bypasses the new rewind failure handling.**  
   [rewind.rs:216](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/acp_session_impl/rewind.rs:216) accepts `get_rewind_points()` as complete, but [file_state.rs:515](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-workspace/src/session/file_state.rs:515) swallows historical-load errors. After resume, a transient read failure therefore produces an empty or partial restore plan. No file operation fails, so the conversation is rewound. Then [rewind.rs:419](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/acp_session_impl/rewind.rs:419) retries loading inside `truncate_from`; if that read succeeds, it loads and immediately discards snapshots for files never restored. Persistence likewise truncates them, and the response reports success. Snapshot acquisition must fail the operation explicitly.  
   **Existing test:** No. The new partial-revert test supplies snapshots directly in memory and injects filesystem operation failures, not lazy-load failures.

4. **HIGH — Retained defect: a fork before the first compaction still inherits a later summary.**  
   [copy.rs:559](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:559) accepts `Ok(None)` without checking whether source-history truncation is valid. Example: prompts P0–P2 are compacted into summary C; fork at P0. The copied transcript contains no compaction marker, so replay returns `None`. [copy.rs:318](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:318) truncates the current chat, retaining C and therefore information from P1/P2. The new marker comparison only handles replay errors. This case needs reconstruction from the earlier transcript or refusal.  
   **Existing test:** No. Both new fork tests cut after a retained compaction.

| Defect | Closure assessment |
|---|---|
| DI-01 | **Closed for the reported scenario.** Replay planning precedes project writes/deletes; failure preserves files, conversation and snapshots. |
| DI-02 | **Reported restore/delete failures are fixed.** Errors are reported, failed files excluded, and snapshots retained for retry. Finding 3 remains a separate route to the same snapshot-loss outcome. |
| DI-03 | **The described crash window is addressed where witness syncing succeeds.** Witness durability precedes activation; recovery checks checkpoint identity and exact history fingerprint. Finding 1 prevents cross-platform acceptance. |
| DI-04 | **The reported between-compactions scenario is refused correctly.** Safe cleanup is incomplete under finding 2; the earlier-cut case remains under finding 4. |

P88’s normal history-authority rule remains intact outside matching-witness recovery. P96’s rewind/compaction refusal checks and history rewrite gates remain present; load repair is skipped when the witness projection replaces history.

The negative regression tests exercise the original failure paths meaningfully by inspection. The rewind tests observe persistence messages rather than actual persisted snapshot survival. The DI-03 integration test uses production commit/load paths but synthesizes the crash’s disk state; it does not exercise an actual interrupted process or power loss.

DO-NOT-LAND
