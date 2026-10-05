Audit brief (P88, round 5). Read-only. Branch strike/p88; range 84569ea8..strike/p88. Prior rounds: docs/strike/audits/P88-astra-r{1..4}.txt.
Round-4 findings and what was done (commit c7ca0a7e): the fork heuristics are gone. storage/jsonl/copy.rs
`chat_for_compacted_cut` now applies, at copy time and only for point-in-time copies (target_prompt_index set, not
fork_filter), exactly the rule 1.0.10-1.0.19's load_light applied at the child's first load, on the same input (the
copied, cut, rewind-filtered updates.jsonl): if its latest compaction marker is the active one after
replay_to_prompt(copied, source dir, MAX), the child's chat is that replay; else the source chat is truncated as
always. Errors degrade to truncation with a warning (the old load failed). No whole-source read remains (r4 MEDIUM-3).
r4 HIGH-1 (cross-compaction rewind forgets an earlier checkpoint) and HIGH-2 (reducer-recovered chat lacks
prompt_index) are, under this rule, identical to 1.0.17 behaviour for forks: judge whether any case is now WORSE than
release/1.0.17 (that is the bar for a regression; cases equal to 1.0.17 are pre-existing and go to the receipt as
proposals). A cut before the first compaction keeps 1.0.17 behaviour (truncation).
Re-check the whole diff. For each defect: severity BLOCKER/HIGH/MEDIUM/LOW, file:line, concrete scenario, whether a
test catches it, and whether it is a regression versus release/1.0.17. End LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
