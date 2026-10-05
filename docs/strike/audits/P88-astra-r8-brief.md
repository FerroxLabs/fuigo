Audit brief (P88, round 8). Read-only. Branch strike/p88; range 84569ea8..strike/p88. Prior rounds: docs/strike/audits/P88-astra-r{1..7}.txt.
Round-7 findings and what was done:
- MEDIUM-2 (reducer merges consecutive prompts): fixed (commit after ff5bfc81): ChatReducer starts a new user item on
  a changed _meta.promptIndex and stamps the index on rebuilt user items. Test: replay.rs
  chat_rebuild_keeps_consecutive_prompts_apart_with_their_indexes.
- HIGH-1 (torn assistant row in chat_history leaves an orphan ToolResult): NOT fixed in P88. Evidence: this state is
  identical for every non-compacted session in 1.0.17 and for compacted sessions before 1.0.10; the codebase handles it
  deliberately out of band (`fuigo/session/repair` -> compaction_utils::repair_history; chat-state test
  repair_history_command_strips_orphan_and_persists documents that load-time repair leaves it), and applying the strict
  adjacency strip at every load is a behaviour change beyond this packet. 1.0.17 "fixed" it only for compacted sessions
  by discarding every tool record. Recorded as a proposal for Sean; re-rate if you think that reasoning is wrong.
Bar for blocking: worse than release/1.0.17 (bdb5ccec) for a reachable state AND not equally present in 1.0.17 for
non-compacted sessions, or a defect in code P88 added. Check the whole diff. For each: severity, file:line, scenario,
test catches it?, regression? End LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
