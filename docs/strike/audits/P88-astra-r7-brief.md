Audit brief (P88, round 7). Read-only. Branch strike/p88; range 84569ea8..strike/p88. Prior rounds: docs/strike/audits/P88-astra-r{1..6}.txt.
Round-6 MEDIUM (reducer emits a tool call before the user prompt that caused it when the model wrote no text first):
fixed in the ChatReducer (storage/mod.rs on_tool_call flushes and ends the user run), test
helpers/replay.rs chat_rebuild_puts_a_prompt_before_the_tool_call_it_caused.
Bar for blocking: behaviour WORSE than release/1.0.17 (bdb5ccec) for a reachable on-disk state, or a defect in code P88
added. Equal-to-1.0.17 limitations are proposals. Check the whole diff once more. For each: severity, file:line,
concrete scenario, test catches it?, regression vs 1.0.17? End LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
