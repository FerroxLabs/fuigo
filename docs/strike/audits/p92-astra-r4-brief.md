# Astra round 4 brief — P92 (memory filter hardening), receipt R099

You are an independent read-only auditor. Do NOT build, compile or run anything. Audit the diff
`fc3ccb94..6cdc2bec` in this worktree (branch `codex/fuigo-p92`; history was rebased onto e0145e0f, which touched
none of these files), focusing on `900d7434..6cdc2bec` (the round-3 fixes, commit 6cdc2bec). Earlier briefs:
`docs/strike/audits/p92-astra-r{1,2,3}-brief.md`. Ignore `P92-CODEX-NOTES.md`.

Round 3 findings and the gate's fixes:
1. MEDIUM `{"password": ":Q7..."}` / `{"password": "$(Q7...)"}` admitted: the `SHAPED` value may start with `:`
   again; only a `::` separator (Rust path) is exempt, and `$(` is exempt only after an UNQUOTED name.
2. MEDIUM slug masking matched a prefix of `fuigo-abcdefgh-ijklmnop-qrst1234`: a slug is masked only when the next
   character is not alphanumeric, `-` or `_` (whole token).
3. MEDIUM header split over four lines; 4. MEDIUM lookback reopened a closed block: a key block now starts at a header
   (one line, or completed within a look-back of up to five lines that never reaches before the previous block's end,
   `floor`) and ends at its END line or at the first line that is not blank, base64 or an RFC 1421 header field
   (`private_key_body_line`), so a header quoted in prose no longer blanks the rest of the file.
5. LOW long override phrase with mixed invisibles: compact windows are +-12 words, and open only around a word with an
   invisible character between two letters (`INNER_INVISIBLE`), not for a BOM, emoji joiner or trailing ZWSP.
6. LOW quadratic sudo search: the search region is bounded to ~205 bytes after each "always run".

This filter is a heuristic and the gate has now run three audit rounds. To converge, report ONLY:
(a) BLOCKER/HIGH/MEDIUM defects in the round-3 changes themselves;
(b) regressions vs the ORIGINAL filter at fc3ccb94 (it rejected X, the tip admits X) that are not paraphrases;
(c) any path where filtered content reaches persistence, the index, embeddings, injection or the dream model;
(d) availability: a flagged or false-positive line that still disables a whole file or blocks writes;
(e) panics or super-linear cost.
New bypass phrasings outside what the filter claims to cover are out of scope (list at most three, as LOW).

For each finding: severity, file:line, exact input, whether a test catches it. End with LAND / LAND-WITH-FOLLOWUPS /
DO-NOT-LAND.
