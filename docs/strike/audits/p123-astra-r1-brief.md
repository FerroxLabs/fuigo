# P123 Astra round 1 brief

You are auditing a read-only checkout: `/Volumes/Mando/WaylandBots/Fuigo/wt-p123`, branch `strike/p123`. Do NOT run cargo
and do not modify anything. Parent (`strike/integration`) is `bfb0ffa4d329155ce83e5552a468b375505826c7`; compare also with
tag `v1.0.20` (`git show v1.0.20:<path>` works in this worktree). Commits to audit: `git log bfb0ffa4..HEAD` (a red-tests
commit, then the fix commit). Hetzner results are not yours to run; read the code and tests.

## What was asked (three items)
1. **K14 / backlog P104** (sources: `docs/strike/receipts/R103-p96.md`, handoff UPDATE 272 "Astra r3"). While the
   load-time history repair still owes its `.pre-repair` backup (the backup could not be made, so `chat_history.jsonl` is not
   rewritten, see `crates/codegen/fuigo-shell/src/session/storage/jsonl/load_repair.rs`):
   - a memory-save request must not go to the model just before the compaction refusal (manual, automatic, and the prefire
     pass);
   - an automatic compaction must show its failure note once per session, then quietly stay off until the backup can be made;
   - the other rewrites of the history file in that run (model or mode switch, image strip) must be saved or refused with a
     clear note, never silently lost;
   - the repair note must not repeat each time the session loads;
   - the repair must also run for a subagent resume and for a fork of a damaged session.
   K14 sentences kept as true limits: no hard links / advisory locks (the repair stays in memory: the backup is published with
   a hard link so it never replaces an existing file, and the lock is the only proof nobody else writes the file); the backup is
   made once (first copy wins, Sean-approved); an older client does not show the note (new wire variant, `serde(other)`).
2. **K17 / "Fork snapshot"** (source: `docs/strike/receipts/R111-p111.md` Round 8, Astra r7 #2b / r9): a fork copies one
   coherent snapshot of its source, so a turn added mid-fork is in both the fork's transcript and its model history, or in
   neither. Code: `crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs` (`snapshot_source`,
   `copy_session_data_sync`, `copy_updates_streaming`).
3. **Two open items from P114** (`docs/strike/receipts/R114-p114.md`, "Proposals"): (a) `load_session` read
   `rewind_points.jsonl` strictly, so export and the writeback backfill failed on a damaged row; they must tolerate it the
   way rewind now does (keep it, report it, never abort); (b) the truncate/merge rewrite of `rewind_points.jsonl` could lose
   another process's append made between its read and its rename: hold the append lock across read, write and rename.
   Code: `jsonl/mod.rs` (`rewrite_rewind_points`, `read_rewind_points_tolerant`, `load_session`) and
   `crates/codegen/fuigo-workspace/src/session/file_state.rs` (`read_rewind_points_lines_holding_append_lock`).

## What I want back
- For each of the three items (and each K14 bullet): FIXED or NOT FIXED, with file:line evidence.
- NEW regressions compared with `bfb0ffa4` and with `v1.0.20`, each with a severity BLOCKER / HIGH / MEDIUM / LOW and a
  concrete scenario (what the user or the data sees). Think about: lock ordering and deadlock between the snapshot's two
  append locks and any other lock holder; a stuck or slow writer; sources whose directory is read-only; Windows; the
  coherence of the snapshot against rewrites (rewind, compaction) and the compaction witness; fork_filter copies (subagent
  spawn) that now take the source's append locks; `replay` dropping a line type (cursor and delta paths); the once-per-debt
  notes (a debt that ends and returns); rewrites that are refused but not noted; the rewind-points rewrite when the append
  lock cannot be opened; test quality (can a test pass without the fix?).
- A verdict: LAND-OK only with zero BLOCKER and zero HIGH.
