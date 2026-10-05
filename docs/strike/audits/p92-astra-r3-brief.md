# Astra round 3 brief — P92 (memory filter hardening), receipt R099

You are an independent read-only auditor. Do NOT build, compile or run anything. Audit the diff
`fc3ccb94..900d7434` in this worktree (branch `codex/fuigo-p92`), focusing on `a71654f0..900d7434` (the round-2
fixes). Background and earlier briefs: `docs/strike/audits/p92-astra-r1-brief.md`, `p92-astra-r2-brief.md`; findings
R3/R4 in `/Volumes/Mando/WaylandBots/Fuigo/.ijfw/memory/codex-audit/238791e1-rest.md`. Ignore `P92-CODEX-NOTES.md`.

Round 2 findings and the gate's fixes (verify each, and what it broke):
1. MEDIUM slug masking hid `fuigo-abcd1234-...` keys: slug parts must now be all letters or all digits.
2. MEDIUM masking rewrote literal values: `mask_benign` now feeds ONLY the shared `redact_secrets`; `EXTRA` and
   `SHAPED` run on the unmasked (percent-decoded) text; a `SHAPED` value may not start with `:`, and a value starting
   with `$(` is treated as command substitution.
3. MEDIUM any `...` exempted a value: only a value ENDING in `...`/`…` is a placeholder.
4. MEDIUM percent-encoded query names: `decode_word_escapes` decodes `%XX` letters/digits/`_` first.
5. MEDIUM private-key header split across lines: block tracking also tests windows of the previous one or two lines.
6. LOW first negated `sudo` hid a later one: every `sudo` after "always run/execute" is checked (`privileged_imperative`).
7. LOW stem + content assembly: dream judges the assembled input and filters it (`filter_memory_lines`) if rejected.
8. LOW unrelated invisible character enabled compact matching across the text: compact readings are now windows of
   +-3 words around each word that contains an invisible character.
9. LOW `exfiltration` noun: `EXFILTRATE_TO` now needs the verb forms (exfiltrate/-s/-d/-ing).
Earlier-declined: workspace initialization writes the path into the MEMORY.md scaffold unvalidated (reads filter it).

This filter is a heuristic and will never be complete. Prioritise: (a) regressions vs the ORIGINAL filter at fc3ccb94
(something it rejected that is now admitted), (b) any path where filtered content still reaches persistence, the index,
embeddings, injection or the dream model, (c) availability: a flagged or false-positive line that still disables a
whole file or blocks writes, (d) false positives on ordinary engineering text, (e) panics or pathological cost.
Report new bypass phrasings only if they are close variants of what the filter claims to cover.

For each finding: severity BLOCKER/HIGH/MEDIUM/LOW, file:line, a concrete scenario (exact input text), and whether a
test catches it. End with LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
