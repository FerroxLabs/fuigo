Audit brief (P88, round 2). Read-only. Branch strike/p88; full range 84569ea8..strike/p88. Round 1 (docs/strike/audits/P88-astra-r1.txt)
found: HIGH-1 point-in-time fork across a later compaction; HIGH-2 chat_history rebuild (missing/empty cache) dropped the
checkpoint projection; MEDIUM-3 tests did not load 1.0.17-keyed checkpoints. Fixes in commit 7b201e12 and later:
- storage/jsonl/copy.rs: with target_prompt_index, if the source's latest compaction marker has
  prompt_index_at_compaction > target, chat is rebuilt with replay_to_prompt(source updates, source dir, target+1)
  (the cross-compaction rewind machinery); otherwise the truncation as before. Errors propagate (fork fails).
- storage/mod.rs chat_rebuild: at a compaction marker the rebuild restarts from the checkpoint file's compacted_history
  (warn + tail only if unreadable).
- tests/compacted_resume_history_acp.rs: every loaded session's checkpoints are rewritten to the 1.0.17 key; new
  scenarios for lost chat_history and a fork at prompt 0 of a twice-compacted session.
Round-1 note accepted: ReplaceChatHistory is unacknowledged; a failed rewrite leaves chat_history pre-compaction +
later appends (pre-existing; documented, not fixed here).
Re-check the whole diff, verify the round-1 fixes, and look for regressions they introduce (prompt-index coordinate
mismatch between replay_to_prompt and the copy's updates cut / surviving_line_indexes, rewind markers, fork_filter
copies, worktree forks, the chat_rebuild item_count, remote pull which has no checkpoint files). For each defect:
severity BLOCKER/HIGH/MEDIUM/LOW, file:line, concrete scenario, whether a test catches it. End LAND /
LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
