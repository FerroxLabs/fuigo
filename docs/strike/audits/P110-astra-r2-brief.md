# P110 Astra round 2 brief

Read-only; do not build. Audit `git diff d1b6ba580eb587594d52b5a2550c1bd82a8bcd60..b0b9a302` on `strike/p110`, with
emphasis on the round 1 fixes `f46aa099` (tests) and `b0b9a302` (code). Round 1 (docs/strike/audits/P110-astra-r1-report.md)
found: #1 HIGH prerelease-current bypass, #2 leader not following an explicit gh-release downgrade, #3 P97-era marker
re-announced, #4 marker not cleared when both folders are absent, #5 100-release window, #6 broken fixture (fixed in 7eebd98f).
Dispositions: #2 ensure_latest_on_disk's relaunch now follows a lower disk version for gh-release (only an explicit
`--force`/`--version` puts one there); #3 the stranded check skips (and marks) a folder whose P97 marker exists; #4 markers
of absent legacy candidates are removed at the top of migrate_legacy_workspace_dirs, before any early return (the P97
marker too, so a reappearing legacy folder is news again for P97 as well); #5 window raised to 1000.
#1 NOT changed: `needs_update` deliberately treats a prerelease build on the stable/enterprise channel as inadmissible and
installs the channel's version even when semver-lower, for every installer (explicit tests auto_update_tests.rs ~515-523,
68). It cannot be reached from a stable running version, which is the U2 threat (an older-line release created later).
Challenge that judgement if you think it is wrong.

Find defects in the whole diff, especially regressions introduced by the round 1 fixes (repeat notices, lost notices,
P97 behaviour change from clearing its marker, relaunch loops or wrong relaunch for gh-release/internal/npm, tests that do
not exercise production code). For each: severity BLOCKER/HIGH/MEDIUM/LOW, file:line, concrete scenario, whether a test
catches it. End with exactly one of LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
