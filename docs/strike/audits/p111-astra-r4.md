# P111 Astra round 4 report (gpt-6-astra, read-only, coordinator run on 09db59dc)

Raw transcript sha256: 8fcfbf705422c1359e2dd512528e5978650fc2956f2d7952ad264867c2e2f29b

Reviewed clean `strike/p111` at `09db59dca3b5905b604fcf3b61f18ac2a27efbf2`, including round 3, `git show 22c46956`, the packet diff and relevant callers. Read-only inspection only; no builds, tests, cargo or modifications.

1. **R3 finding 1 — PARTIALLY FIXED; HIGH remains.**

   The new condition at [copy.rs:580](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:580) rejects completely unmarked compacted histories, but accepts **any** marked turn at or after the target.

   **Scenario:** checkpoint at prompt 5 is missing; saved chat contains its summary, unmarked P5/A5, P6/A6 and P7/A7, followed by marked P8/A8 after upgrading. Fork at P5. Marker 8 satisfies the new condition. [copy.rs:311](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:311) truncates at index 6, but [conversation.rs:2044](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-sampling-types/src/conversation.rs:2044) selects marker-only truncation because the unmarked prefix count differs from 8. It cuts immediately before P8, retaining P6/P7.

   The child’s transcript ends at P5 while its model history includes future turns. The added regression covers wholly unmarked history, missing this mixed-history case.

2. **R3 finding 2 — FIXED for the reported shell rewind path.**

   [file_state.rs:395](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-workspace/src/session/file_state.rs:395) now rejects malformed rows. [file_state.rs:589](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-workspace/src/session/file_state.rs:589) returns errors before merging points or consuming `lazy_source`. If an earlier lenient load skipped rows, [file_state.rs:779](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-workspace/src/session/file_state.rs:779) refuses the incomplete set.

   [rewind.rs:219](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/acp_session_impl/rewind.rs:219) propagates that refusal before project-file mutations. A lenient-load corruption flag remains permanent for that tracker, so repairing the file requires recreating the tracker; it cannot silently proceed.

Additional remaining paths:

3. **HIGH — Failed compaction rewrites become unrecoverable by the witness after another append. Retained DI-03 gap.**

   [persistence.rs:2087](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/persistence.rs:2087) only logs `ReplaceChatHistory` failures. The commit has already been acknowledged, and subsequent messages can append to the old history.

   **Scenario:** compaction commits, its atomic history replacement fails, then a later message append succeeds. Disk now contains pre-compaction history plus later messages. [compaction_witness.rs:101](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:101) rejects the changed fingerprint, so reload silently resumes that history instead of the committed compacted conversation. The receipt acknowledges this gap; the crash fixture does not cover it.

4. **HIGH — Rewind reports success without establishing that its history replacement persisted. Retained.**

   [rewind.rs:419](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/acp_session_impl/rewind.rs:419) requests an unacknowledged replacement, then [rewind.rs:439](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/acp_session_impl/rewind.rs:439) drops snapshots and ultimately returns success. The same persistence handler above merely logs replacement failure.

   **Scenario:** project-file restoration succeeds, replacing `chat_history.jsonl` fails, and snapshot truncation succeeds. The response says success, but reopening restores the old model history alongside the rewound project files; the removed snapshots are unavailable. Planning the conversation before file writes fixes DI-01’s replay-error case, but does not close this persistence failure.

5. **HIGH — Workspace rewind still treats an existence-check error as successful deletion. Retained DI-02 path.**

   The reachable `workspace.rewind_to` caller invokes `rewind_files` at [checkpoint.rs:409](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-workspace/src/session/checkpoint.rs:409). That helper still uses `exists(...).await.unwrap_or(false)` at [file_state.rs:997](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-workspace/src/session/file_state.rs:997).

   **Scenario:** a prompt creates `dir/new.txt`; directory permissions subsequently prevent traversal. During rewind, the existence check errors and becomes `false`. No deletion occurs, but the file is listed as reverted, snapshots are truncated, and success is returned. The shell-handler correction does not cover this caller.

6. **HIGH — Forking into an existing session overwrites user history. Retained.**

   [fork.rs:71](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/fork.rs:71) accepts an explicit destination ID. Directory creation at [jsonl/mod.rs:188](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/mod.rs:188) permits an existing directory, after which [copy.rs:326](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:326) replaces its transcript and subsequent code overwrites its chat and summary.

   **Scenario:** fork A using existing session B’s ID and working directory. B’s history is overwritten without collision refusal. A later sidecar-copy failure can additionally return failure after that destruction. Private staging protects refused history cuts, but does not reserve the destination.

No separate data-loss regression was identified in `22c46956` beyond its incomplete fork correction. The unresolved HIGH above is sufficient to retain the landing rejection.

DO-NOT-LAND
