# P111 Astra round 6 (gpt-6-astra, read-only) on 2fe70fa2

Brief: p111-astra-r6-brief.md. Final report, verbatim:

Reviewed `strike/p111` at `2fe70fa2b1277005fb9ef3604252cf096c57d7b8`, including the packet diff, rebuilt commits, prior reports and receipt. **Five HIGH findings and one MEDIUM remain.** No builds, tests or modifications performed; worktree status is unchanged.

The following assessments distinguish closure of the reported scenario from overall packet acceptance.

| Prior finding | Result | Current evidence |
|---|---|---|
| R5 #1 — Cold recovery loses owed replacement | **FIXED** | Recovery reconstructs projection plus persisted appends at [compaction_witness.rs:213](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:213), selected by [persistence.rs:3065](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/persistence.rs:3065). |
| R5 #2 — Fork omits messages held in memory | **FIXED for the reported scenario** | Ordinary messages append directly at [persistence.rs:2059](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/persistence.rs:2059); forks recover the persisted tail at [copy.rs:287](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:287). A separate snapshot race remains below. |
| R5 #3 — Failed rewind leaves replaced history | **NOT FIXED end-to-end** | Summary failures correctly become `Committed`, but an unsuccessful verification read becomes `NotCommitted` at [jsonl/mod.rs:1806](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/mod.rs:1806). Finding 3 below. |
| R5 #4 — Later unactivated compaction destroys witness | **NOT FIXED end-to-end** | One successor is handled; eight successors evict the needed entry at [compaction_witness.rs:111](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:111). |
| R5 #5 — Owed-history cwd-switch classification | **FIXED** | That machinery is gone; the original strict append classification is used at [persistence.rs:2080](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/persistence.rs:2080). |
| R4 HIGH #1 — Mixed-history fork cut | **FIXED** | [copy.rs:668](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:668) checks the actual truncation boundary and rejects ambiguous intervening unmarked turns. |
| R4 HIGH #3 — Append invalidates failed-rewrite recovery | **FIXED for the reported scenario** | [compaction_witness.rs:118](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:118) matches the recorded prefix and extracts later bytes. |
| R4 HIGH #4 — Rewind succeeds despite replacement failure | **FIXED for the reported false-success path** | [rewind.rs:417](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/acp_session_impl/rewind.rs:417) awaits replacement and returns failure before snapshot truncation. |
| R4 HIGH #5 — Workspace existence-check error | **FIXED** | Strict planning at [file_state.rs:938](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-workspace/src/session/file_state.rs:938); existence errors fail the file at [file_state.rs:1019](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-workspace/src/session/file_state.rs:1019), preventing truncation. |
| R4 HIGH #6 — Existing destination overwritten | **FIXED** | [copy.rs:559](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:559) rejects existing histories and exclusively creates the summary before copying. |

1. **HIGH — A successful rewrite can match the witness and duplicate its own compacted payload. New regression.**

   [compaction_witness.rs:139](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:139) treats prefix equality as proof that replacement never landed, then appends everything beyond that prefix to the checkpoint projection.

   **Concrete scenario:** create a session without project instructions and compact before its first prompt. New-session history starts empty at [session_setup.rs:530](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/agent/mvp_agent/session_setup.rs:530); startup installs and persists the system head. Compaction preserves that exact head and adds its payload at [compaction_utils.rs:1011](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-chat-state/src/compaction_utils.rs:1011).

   Let the recorded file be `H`, and the successfully written projection be `H + Q`. Recovery returns **`H + Q + Q`**. Startup persists that at [spawn.rs:1311](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/acp_session_impl/spawn.rs:1311); subsequent loads add another copy. No write failure or crash is required. Rejecting an empty recorded file does not address a nonempty preserved prefix.

   Recovery needs evidence distinguishing replacement from append; prefix equality alone cannot establish that distinction.

2. **HIGH — Recovered-tail corruption bypasses P96 repair. New regression.**

   [compaction_witness.rs:153](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:153) skips malformed appended items. [persistence.rs:3069](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/persistence.rs:3069) then clears the skipped-line count and entirely bypasses `repair_after_corrupt_load`.

   **Concrete scenario:** compaction commits, its replacement fails, and subsequent appends contain a torn assistant/tool-call row followed by a valid `ToolResult`. Recovery retains the result without its call. The next provider request receives that invalid history; ordinary chat-state integrity repair explicitly does not remove orphan results ([mutations.rs:173](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-chat-state/src/actor/mutations.rs:173)).

   Startup writes the invalid recovered history. A whole-session fork also writes it without carrying the source’s corruption evidence, leaving the child ineligible for P96’s automatic repair.

   Repair and corruption accounting must apply to the assembled projection **and tail**, while preserving P96’s backup requirements.

3. **HIGH — An inconclusive read still produces a false “not committed” rewind result. Residual R5 #3.**

   At [jsonl/mod.rs:1806](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/mod.rs:1806), `read(...).await.is_ok_and(...)` conflates unreadability with proof that replacement did not commit.

   **Concrete scenario:** rename succeeds, parent-directory sync fails, and the verification read also fails with an I/O error. The atomic writer permits this post-rename error at [storage/mod.rs:69](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/mod.rs:69). Classification becomes `NotCommitted`; chat-state retains the original conversation, and rewind reports that it was not rewound. When storage becomes readable again, the file contains the shortened history, without a rewind marker.

   Carry the rename outcome from the atomic writer. An unsuccessful reread cannot prove rollback.

4. **HIGH — Eight unactivated attempts evict the still-required committed witness. Residual R5 #4.**

   [compaction_witness.rs:111](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:111) evicts entries solely by insertion age.

   **Concrete scenario:** C1 commits but its replacement fails. Eight subsequent compaction attempts durably write their checkpoints and witnesses, but cannot append activation markers—for example, `updates.jsonl` remains unwritable while sibling files can be replaced. C1 remains the latest committed marker, but its witness is removed. Lookup at [compaction_witness.rs:183](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:183) returns `None`, silently restoring pre-C1 history on load or fork.

   Preserve the entry required by the latest committed marker independently of the bounded unactivated-entry list.

5. **HIGH — Whole-session forks still combine different source generations. Retained integrity gap.**

   [copy.rs:283](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:283) reads chat history first. Witness recovery separately rereads the source; when it returns `None`, the earlier chat vector remains. The transcript is copied later at [copy.rs:340](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:340). The endpoint provides no source serialization ([session_admin.rs:953](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/extensions/session_admin.rs:953)).

   **Concrete interleaving:** the fork reads the old conversation; a source rewind successfully replaces history; witness recovery checks the shortened file and returns `None`; the fork retains the old conversation while copying the transcript containing the rewind marker. The child successfully loads with discarded turns in its model history.

   The same race can retain pre-compaction history after the compaction replacement lands. Copy needs one coherent source snapshot.

6. **MEDIUM — Healthy loads now incur another complete transcript allocation and scan. New regression.**

   [compaction_witness.rs:175](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/compaction_witness.rs:175) finds the latest marker **before** testing history length or the 4 KiB sample. That helper reads the entire transcript into a string at [replay.rs:35](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/helpers/replay.rs:35).

   Thus every ordinary load with a witness pays an additional O(transcript-size) allocation and scan even when replacement succeeded. The later checkpoint warning scans it again. Large, tool-heavy transcripts incur this cost despite having small compacted histories. Check bounded fingerprint candidates first and reuse or stream the marker scan. No timing measurements were run.

I found no production wait cycle in the new acknowledgement path: chat-state waits for persistence, whose replacement handler does not call back into chat-state. The added tests were inspected, not executed; they do not exercise the failure combinations above.

DO-NOT-LAND
