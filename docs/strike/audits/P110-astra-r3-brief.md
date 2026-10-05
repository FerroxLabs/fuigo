# P110 Astra round 3 brief

Read-only; do not build. Audit `git diff d1b6ba580eb587594d52b5a2550c1bd82a8bcd60..3edbfea4` on `strike/p110`, focusing on
the round 2 fixes `23dd9176` (test) and `3edbfea4` (code). Round 2 (docs/strike/audits/P110-astra-r2-report.md) found:
#1 HIGH downward leader relaunch loops; #2 `--version` rollback never converges a newer leader; #3 adoption after a P97
refusal kept stale markers; #4 LOW residual of the 1000-release window.
Dispositions: #1 the round 1 change was reverted: for gh-release `ensure_latest_on_disk` never sets relaunch_needed for a
LOWER disk version (a newer leader keeps running after an explicit `--force`/`--version` downgrade, the lesser evil; the
pager-side leader/client version handshake is outside this packet and is written up as a follow-up). #2 not changed (same
pre-existing pager-side limitation, follow-up). #3 a successful adoption removes that folder's P97 and stranded markers.
#4 accepted residual.

Find defects in the whole diff, especially any the round 2 fixes introduce. For each: severity BLOCKER/HIGH/MEDIUM/LOW,
file:line, concrete scenario, whether a test catches it. End with exactly one of LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
