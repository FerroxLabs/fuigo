# P120 Astra audit brief, round 2 (read-only; no cargo, no builds)

Same scope as docs/strike/audits/p120-astra-r1-brief.md (read it first). Round 1 report: docs/strike/audits/p120-astra-r1.md
(verdict DO-NOT-LAND, 3 HIGH, 3 MEDIUM). Since then, fixes (see `git log 5e2c58d3..HEAD`):
- #1 HIGH key spread over different properties: body of 16+ base64 chars is redacted whatever property holds it.
- #2 HIGH BEGIN marker split across chunks: PrivateKeyJoin keeps a marker fragment per property (kept across envelope strings).
- #3 HIGH Windows ACL cache: keyed by path + creation time, recorded only after success.
- #4 MEDIUM short word after a marker: a short string is body only with a digit or + / = in it, same property; a word closes the block.
- #5 MEDIUM auth-provider: the shared filter now runs before the explicit FUIGO_AUTH_PROVIDER_* variables.
- #6 MEDIUM events.jsonl and fork/sidecar/compaction/checkpoint copies are owner-only (owner_only::copy, log.rs open_owner_only).
- Git credential-helper note: accepted as the requested shared filter; reported to Sean as a decision.

For each item answer FIXED / NOT FIXED, verify each round-1 finding, and list NEW regressions versus 9381f19c and v1.0.20 with
BLOCKER / HIGH / MEDIUM / LOW. LAND-OK needs zero BLOCKER and zero HIGH.
