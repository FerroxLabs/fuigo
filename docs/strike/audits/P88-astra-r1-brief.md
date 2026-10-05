Audit brief (P88, round 1). Read-only. Repo: this worktree, branch strike/p88; diff range 84569ea8..strike/p88 (2 commits).

Defect being fixed (H-1): since a7a17ff8 (1.0.10), `persist_compaction_checkpoint` writes `inherited_prefix_len: Some(..)`
on every checkpoint, and `load_light` (crates/codegen/fuigo-shell/src/session/persistence.rs) then replaced the resumed
session's `chat_history.jsonl` with `replay_to_prompt(updates.jsonl)` — a text-only rebuild that drops tool calls/results
and merges assistant text around them; spawn then persisted it over the real history. L-1: a missing/corrupt latest
checkpoint file `?`-failed the load.

Claims:
1. chat_history.jsonl is the authoritative model view on resume in every case (never compacted, compacted 1x/2x, forked
   after compaction, damaged checkpoint, sessions written by 1.0.17). After a committed compaction the chat-state actor
   rewrites chat_history to the exact compacted projection (ReplaceChatHistory follows CommitCompactionAndAck FIFO on
   the same persistence channel) and appends every later item to it.
2. The only window where chat_history lags the activation marker is a crash between the marker append and the
   ReplaceChatHistory write; there chat_history holds the pre-compaction history the model last saw (lossless; the next
   turn may re-compact). The pre-P88 rebuild in that window handed the model a projection it never saw, and lossy.
3. The removed `persisted.summary.inherited_prefix_len = ...` write was dead (nothing on the load path reads
   summary.inherited_prefix_len; startup hints come from request meta).
4. Load never fails because of a checkpoint file now; an unreadable one is logged.
5. CompactionCheckpointFile now serializes the prefix as `resolved_prefix_len` (alias `inherited_prefix_len` read), so
   1.0.10-1.0.19 binaries see None and keep chat_history for compactions made by this version.
6. Tests: tests/compacted_resume_history_acp.rs drives real session/load (fresh agent) and compares the next foreground
   request's `messages` to a live twin's; durable_tests.rs checks the serde key.

Find defects; for each: severity BLOCKER/HIGH/MEDIUM/LOW, file:line, concrete scenario, whether a test catches it.
Specifically check: anything else that relied on the rebuild (rewind, read-dedupe, last_compaction_prompt_index,
subagent resume, remote pull, worktree/fork copy); any reader of the checkpoint JSON key `inherited_prefix_len`
(Rust, JS scripts, pager); whether the test can pass for the wrong reason (e.g. the normalization of session ids, the
twin design, the 1.0.17 simulation). End with LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
