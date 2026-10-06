# Astra round 2 brief — P92 (memory filter hardening), receipt R099

You are an independent read-only auditor. Do NOT build, compile or run anything. Audit the diff
`fc3ccb94..a71654f0` in this worktree (branch `codex/fuigo-p92`), focusing on what changed since round 1
(`8735c062..a71654f0`). Same files and background as round 1 (brief: `docs/strike/audits/p92-astra-r2-brief.md`'s
sibling `p92-astra-r1-brief.md`; findings R3/R4 in
`/Volumes/Mando/WaylandBots/Fuigo/.ijfw/memory/codex-audit/238791e1-rest.md`). Ignore `P92-CODEX-NOTES.md`.

Round 1 findings and what the gate did (verify each fix, and look for what the fix broke):
1. MEDIUM credential regressions vs the old filter (JSON `"password": "..."`, `password: hunter2`, `Bearer 123456789012`,
   `sk-123456789012345678`, a >50-char JWT with a short segment): new `SHAPED` rule in `contains_credentials` with
   value predicates; `sk-` added to `EXTRA`. Bare `secret`/`token` keep the shared 8-char floor; `...` placeholders pass.
2. MEDIUM private-key header with an invisible character left the body readable: block tracking now uses every
   reading (`Readings::any_folded`).
3. MEDIUM CRLF / whitespace-only paragraph breaks: `filter_memory_lines` now works on line ranges; a paragraph is a
   run of non-blank lines.
4. MEDIUM `=redacted` marker counting: dropped; only `[REDACTED_SECRET]` counts; credential query params need 8+.
5. LOW mixed invisible usage: a third, compact reading (all spaces removed) is checked with `OVERRIDE_COMPACT`, the
   private-key header and the needles, only when invisible characters are present.
6. LOW privileged imperative false positives: evaluated per sentence, and a negation in the two words before `sudo`
   ("without", "no", "never", "not") exempts it.
7. LOW workspace initialization writes the workspace path into the MEMORY.md scaffold without `validate_entry`:
   DECLINED (reads are filtered; validating would make a weirdly named workspace unable to initialize memory).
8. LOW dream session file name injected: a flagged stem is replaced in the dream header.
9. LOW index test did not protect the empty-view guard: test now writes a trailing newline and asserts zero chunks.
10. LOW `exfiltrate` removal: new `EXFILTRATE_TO` rule (exfiltrate ... to/into/via URL-or-domain, same sentence).
Also: a whole-repo probe (30,017 Markdown lines) found `fuigo-` crate slugs, `TOKEN=$(...)` and `token::Path`
rejected by the shared patterns; `mask_benign` neutralizes those before credential matching.

Find defects: bypasses that still work against the stated goals (especially new ones the masking or the placeholder
exemption opened, e.g. a real key shaped like a slug, or `...` inside a real secret); false positives on ordinary
engineering text; any path that persists, indexes, embeds or injects flagged content; any path where a flagged
historical line still disables a whole file; offset/range bugs in the filtered read; panics (regex capture indexing,
slicing); performance traps (catastrophic regex cost on long lines). Do NOT report the P91-owned regions
(`storage.rs` ~816-895, `index.rs` `chunk_source_revision`).

For each finding: severity BLOCKER/HIGH/MEDIUM/LOW, file:line, a concrete scenario (exact input text), and whether
a test catches it. End with LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
