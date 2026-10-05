# P123 Astra round 2 brief

Read-only checkout `/Volumes/Mando/WaylandBots/Fuigo/wt-p123`, branch `strike/p123`. Do NOT run cargo, do not modify anything.
Parent `strike/integration` = `bfb0ffa4d329155ce83e5552a468b375505826c7`; also compare with tag `v1.0.20`.
This is a re-audit after round 1 (`docs/strike/audits/p123-astra-r1-brief.md` has the three items; the report is
`docs/strike/audits/p123-astra-r1-report.md`). Audit `git log bfb0ffa4..HEAD`; the round-1 fixes are the last two commits
(red tests, then fixes). Hetzner results, for your information: focused tests 3x green, whole `fuigo-shell` lib 7743 passed
on the earlier tip; mutants are being run.

## Round 1 findings and what was done (verify each, with file:line)
- H1 HIGH (K17 not coherent: a prompt's transcript echo is buffered while its chat item is already on disk, so two exactly
  snapshotted files can hold a prompt in one only): `copy.rs` `align_to_one_prompt_axis` + `UpdateLineWriter` live-prompt
  tracking. A whole copy whose transcript and chat history end one prompt apart (indexes differ by one AND the two last
  prompts read differently, no unreadable line on either side) leaves the extra prompt out of the side that has it.
  The prompt indexes of the two files can drift in a healthy session (see `UserItem::prompt_index` doc), hence the text guard.
  Known and stated: a gap of more than one prompt (a multi-prompt rewind whose marker is not written yet) and two identical
  prompt texts in a row are not handled.
- H2 HIGH (my own regression: unbounded `lock_exclusive` in the rewind-points rewrite on the persistence queue):
  `jsonl/mod.rs` `lock_append_bounded` (10 s, then `WouldBlock`, the file untouched).
- M1 (false-success when the lock file cannot be opened): the rewrite now goes ahead without the lock when the lock file
  cannot be opened or locked (the readers do the same), so it fails no more often than before.
- M2 (a subagent context copy, `fork_filter`, waited for the transcript lock it does not use): it takes the chat lock only.
- M3 (reconnect/delta replay dropped the repair note): only a FULL replay drops it (`replay.rs`
  `line_is_dropped_on_full_replay`); the cursor and delta paths keep it.
- M4 (system prompt override had no refusal note): `model_switch.rs` `handle_replace_system_prompt`.
- M5 (prefire guard retried the backup copy every turn): `load_repair::backup_is_owed` only looks (already in the audited tree
  as a concurrent edit).
- Test findings: the sleep-based lock assertions are replaced by deterministic ones (the held write seam plus a probe of the
  append lock; the copy records the lock files it found held); `damaged_rewind_lines` is asserted.
- Not changed, by design (say if you disagree): a cold load while the backup is still blocked repairs in memory again and
  shows the "could not be backed up" note again (the state is live each load; the transcript copy of the note is not replayed).

## What I want back
FIXED / NOT FIXED per finding, NEW regressions against `bfb0ffa4` and `v1.0.20` with severity BLOCKER/HIGH/MEDIUM/LOW and a
concrete scenario, and a verdict (LAND-OK only with zero BLOCKER and zero HIGH). Pay special attention to: false positives
of the prompt alignment (a healthy session losing its last prompt in a fork), the staged-transcript trim (`set_len`, line and
byte bookkeeping, the compaction-marker refusal), and anything in the bounded lock paths that can still hang or fail more
often than the parent.
