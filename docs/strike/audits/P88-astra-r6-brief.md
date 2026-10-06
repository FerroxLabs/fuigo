Audit brief (P88, round 6). Read-only. Branch strike/p88; range 84569ea8..strike/p88. Prior rounds: docs/strike/audits/P88-astra-r{1..5}.txt.
Round-5 findings and what was done (commit ce4138a2): new helper helpers/replay.rs `replay_if_latest_compaction_active`
is release/1.0.17 load_light's rule verbatim (latest marker's checkpoint file schema 1 + marker schema 1, file carries a
resolved prefix, replay(MAX).last_compaction_prompt_index == file.prompt_index_at_compaction). Used by:
(a) copy.rs `chat_for_compacted_cut` (point-in-time copies only; on the copied transcript; errors -> truncation + warn);
(b) storage/mod.rs chat_rebuild, only when a RewindMarker follows the latest compaction marker: Some -> replay output;
None or error -> drop the inserted projection lines, leaving the reducer's tail (its pre-P88 output).
Bar for a finding to block: behaviour WORSE than release/1.0.17 (bdb5ccec) for some reachable on-disk state, or a
defect in code P88 added. Equal-to-1.0.17 limitations go to the receipt as proposals. Check the whole diff. For each:
severity, file:line, concrete scenario, test catches it?, regression vs 1.0.17? End LAND / LAND-WITH-FOLLOWUPS /
DO-NOT-LAND.
