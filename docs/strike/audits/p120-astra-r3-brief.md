# P120 Astra audit brief, round 3 (final; read-only; no cargo, no builds)

Scope as in docs/strike/audits/p120-astra-r1-brief.md; reports: p120-astra-r1.md, p120-astra-r2.md (DO-NOT-LAND, 3 HIGH, 4 MEDIUM, 1 LOW).
Fixes since round 2 (`git log 6cbd74d2..HEAD`):
- r2 #1 short alphabetic key chunks: after the opener, a same-property chunk that starts like a key (MI, MH, b3Bl) or has a digit or + / =, and every
  same-property base64 token once body was seen, is body; a short plain word closes the block.
- r2 #2 marker split in more than two pieces: the fragment accumulates.
- r2 #4 ANSI digits no longer count; ordinary text (whitespace) of ANY property closes the block.
- r2 #3 Windows: the creation-time cache is gone; the ACL is re-applied at most once a minute per path and for every empty file.
- r2 #6 pre-strip, pre-repair and quarantine copies use owner_only::copy.
- r2 #7 Windows status line: filter before inv.env.
- r2 #5 Windows events.jsonl ACL: NOT changed (fuigo-session-events has no Windows ACL helper; inherited gap; listed in the receipt).
Answer FIXED / NOT FIXED per round-2 finding; list NEW regressions vs 9381f19c and v1.0.20 with BLOCKER / HIGH / MEDIUM / LOW. LAND-OK needs zero BLOCKER and zero HIGH.
