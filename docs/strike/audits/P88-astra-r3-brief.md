Audit brief (P88, round 3). Read-only. Branch strike/p88; range 84569ea8..strike/p88. Prior rounds: docs/strike/audits/P88-astra-r1.txt, P88-astra-r2.txt.
Round-2 findings and what was done (commit 2c20d6c5):
- HIGH-1 (rewound-away checkpoint), HIGH-2 (image-only prompt coordinate mismatch), MEDIUM-5 (torn line fails copy),
  MEDIUM-6 (preamble lost): storage/jsonl/copy.rs now copies updates first and, only when the copied transcript's latest
  compaction marker differs from the source's, rebuilds chat with replay_to_prompt(COPIED updates, source dir, MAX)
  (the same input 1.0.10-1.0.19's child load replayed), restoring System + original user_info like rewind.rs when no
  checkpoint survives; scan errors fall back to truncation.
- HIGH-3 (chat_rebuild ignores RewindMarker) and HIGH-4 (remote pull has no checkpoint files): NOT fixed here, judged
  pre-existing: the ChatReducer has ignored rewind markers since before 1.0.10, and in 1.0.10-1.0.19 a pulled compacted
  session failed to load at all (L-1: missing checkpoint `?`); P88 makes it resume with a warning (summary missing),
  which is the pre-1.0.10 behaviour and what the brief asks for L-1. Re-rate these if you disagree, with reasons.
Re-check the whole diff and these fixes for new defects. For each: severity BLOCKER/HIGH/MEDIUM/LOW, file:line,
concrete scenario, whether a test catches it. End LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
