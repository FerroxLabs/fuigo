# P111 Astra round 5 (gpt-6-astra, read-only) on a154fa5a

Brief: p111-astra-r5-brief.md. Final report, verbatim:

Reviewed `strike/p111` at `a154fa5ade2da4d083082a0a06e8f19535915b88`, including the full packet diff, ten Round 5 commits, Round 4 report and receipt. Read-only inspection; no builds, tests or modifications.

| Round 4 HIGH | Result | Evidence |
|---|---|---|
| #1 Mixed-history fork cut | **FIXED** | [copy.rs:668](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:668) checks the actual truncation boundary. Refusal precedes target creation. |
| #3 Failed compaction rewrite followed by append | **NOT FIXED end-to-end** | The live actor now holds and retries the replacement, but cold load discards that obligation at [persistence.rs:3224](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/persistence.rs:3224). See finding 1. |
| #4 Rewind succeeds without persisted replacement | **FIXED for the reported false-success path** | [rewind.rs:417](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/acp_session_impl/rewind.rs:417) awaits persistence and returns before snapshot truncation or tracker merging on failure. A separate failure-path defect remains below. |
| #5 Workspace existence-check error | **FIXED** | [file_state.rs:937](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-workspace/src/session/file_state.rs:937) reads snapshots strictly; [file_state.rs:1019](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-workspace/src/session/file_state.rs:1019) records existence-check failures and prevents truncation. |
| #6 Existing destination session overwritten | **FIXED** | [copy.rs:547](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:547) refuses existing history files and exclusively creates the summary before copying. Empty pre-created directories remain permitted. |

1. **HIGH — Cold recovery reopens the failed-rewrite/append hole.**

   `load_light` selects the witness projection at [persistence.rs:3147](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/persistence.rs:3147), but initializes `unapplied_history: None` and `rewrite_must_land: false`. Startup then uses two best-effort rewrites at [spawn.rs:1311](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/acp_session_impl/spawn.rs:1311).

   **Scenario:** restart after a committed compaction whose replacement failed. Both startup replacements also fail, while a subsequent append succeeds. The actor appends to the pre-compaction file, invalidating the witness; the following reload resumes pre-compaction history again. This exceeds the acknowledged residual of losing only post-compaction messages.

   Carry the recovered replacement obligation into the persistence actor until it lands.

2. **HIGH — A whole-session fork can successfully omit messages held in the live actor. New Round 5 interaction.**

   Later messages accumulate in `unapplied_history` at [persistence.rs:2069](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/persistence.rs:2069). However, [copy.rs:287](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:287) substitutes only the checkpoint projection, and a whole-session copy skips replay. The fork endpoint calls storage directly without a source persistence barrier at [session_admin.rs:953](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/extensions/session_admin.rs:953).

   **Scenario:** compaction commits; replacement remains owed; subsequent prompt/response messages reach the transcript but remain in memory for chat persistence. A full fork succeeds with those messages in its transcript but absent from its model history. Later recovery of the source does not repair the child. No process crash is required.

   Obtain a coherent persisted source snapshot, or refuse the fork while that replacement remains unresolved.

3. **HIGH — A failed rewind can leave shortened history on disk while reporting that the conversation was not rewound. New Round 5 failure path.**

   [jsonl/mod.rs:1791](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/mod.rs:1791) replaces chat history **before** updating summary metadata. Therefore an error can follow a committed replacement. [actor/mod.rs:307](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-chat-state/src/actor/mod.rs:307) merely queues restoration of the original history, then replies with failure.

   **Scenario:** the shortened history lands, summary bookkeeping fails, and the restoration fails before replacing the file—or the process stops before restoration. Reload sees shortened chat history, while the transcript has no rewind marker and the response promised an unchanged conversation. The original model history existed only in memory during rollback.

   Replacement needs a commit-aware outcome and durable recovery semantics; an unacknowledged compensating write does not establish rollback.

4. **HIGH — A subsequent compaction can destroy the only usable recovery witness. Retained packet defect.**

   [persistence.rs:2454](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/persistence.rs:2454) overwrites the single witness before activating the next checkpoint. Recovery rejects a witness naming anything other than the latest committed marker at [compaction_witness.rs:123](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:123).

   **Scenario:** C1 committed but its history replacement remains owed. C2 writes its witness, then the process stops before C2’s activation—or activation returns `NotCommitted`. The transcript’s latest marker remains C1, but its witness has been replaced by C2’s. Reload consequently trusts the pre-C1 chat file.

   Preserve C1’s recovery evidence until C2 activates, or resolve the owed replacement before replacing its witness.

5. **MEDIUM — Owed-history cwd-switch appends misclassify committed errors. New Round 5 API regression.**

   [persistence.rs:2555](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/persistence.rs:2555) treats every replacement error as `NotCommitted` and removes the switch from the owed history.

   **Scenario:** replacement containing the switch lands, then summary bookkeeping fails. Chat-state does not adopt the switch because it receives `NotCommitted`; a later successful retry writes the owed history without it, deleting the committed switch. This breaks the existing strict-append contract. I found no current production caller of the public chat-state switch method, so this is MEDIUM rather than HIGH.

I found no production actor wait cycle in the new acknowledgement path. The added failure seam returns before touching disk, so it does not exercise the post-replacement failures above. The reported existing test results were not rerun.

DO-NOT-LAND
