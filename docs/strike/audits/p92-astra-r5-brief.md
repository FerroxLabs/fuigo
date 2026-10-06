# Astra round 5 brief — P92 (memory filter hardening), receipt R099

You are an independent read-only auditor. Do NOT build, compile or run anything. Audit `fc3ccb94..89451a69` in this
worktree (branch `codex/fuigo-p92`), focusing on `6cdc2bec..89451a69` (round-4 fixes, commits 5e223fce, 89451a69).
Earlier briefs: `docs/strike/audits/p92-astra-r{1,2,3,4}-brief.md`. Ignore `P92-CODEX-NOTES.md`.

Round 4 findings and the gate's fixes:
1. MEDIUM a zero-width character in a key body line ended the block: `private_key_body_line` removes invisible
   characters before classifying.
2. MEDIUM `PASSWORD='$(...)'` got the shell exemption: it now needs an unquoted name AND a value not opened by `'`;
   `mask_benign` no longer masks `'$(`.
3. MEDIUM short plain-word values: in a quoted context (quoted name or quoted value) the previous filter's floor of 4
   applies to the password/api-key/token-name family; unquoted short (6-7) values and 12-15 char bearer values count
   unless they read as a word (`reads_as_word`: letters only, no capital after the first). A short all-lower-case
   word after an unquoted name (`password: letmein`) is admitted ON PURPOSE: it cannot be told from
   `password: hidden`; the original filter's rule (any value longer than 3) was the R4 false positive.
Also: `==` is a comparison, not an assignment; the dream file-name guard was removed because the assembled-input check
(round 2) subsumes it.

To converge, report ONLY: (a) BLOCKER/HIGH/MEDIUM defects in the round-4 changes; (b) regressions vs fc3ccb94 other
than the documented trade-off above; (c) any path where filtered content reaches persistence, the index, embeddings,
injection or the dream model; (d) availability (a line that disables a whole file or blocks writes); (e) panics or
super-linear cost. List at most three other observations as LOW. For each: severity, file:line, exact input, test
coverage. End with LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
