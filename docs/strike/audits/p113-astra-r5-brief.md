# P113 Astra r5 brief (independent audit, read-only; the last round)

Worktree `/Volumes/Mando/WaylandBots/Fuigo/wt-p113`, branch `strike/p113`. Source inspection only: do not build, run
tests, or modify any file. Packet P113: credentials Fuigo sends or holds must not reach child processes it spawns, the
session event log, the `/feedback` trace archive, or proxy logs/errors.

Your round-4 report is `docs/strike/audits/p113-astra-r4.md` (7 findings). The fixes are `git diff d9eb19dd..451ae5a8`
(`dc13c62a` regression test, `451ae5a8` fixes) in `fuigo-secrets/src/sanitizer.rs` (telemetry keeps unterminated
BEGIN lines; archive-only torn-PEM regex, indented and line-anchored; `opens_private_key_block`),
`fuigo-shell/src/upload/feedback_archive.rs` (`JsonScrub`: structural byte arrays, PEM state across strings and
records, distinct names for colliding redacted property names) and `fuigo-shell-terminal/src/pty_session.rs`
(`remove_fuigo_secrets` + builder-only test).

1. For EACH r4 finding say FIXED or NOT FIXED with file:line evidence.
2. NEW defects introduced by these fixes only (a credential that still leaves the archive; an archived JSON file no
   longer valid or losing records/data; ordinary text rewritten; a telemetry/Sentry regression; a regression of r1-r3
   behaviour; tests that pass with a fix reverted). Rate severity honestly: reserve HIGH for a concrete, reachable
   credential disclosure or data corruption.

Out of scope (decided, do not report): the local on-disk chat transcript written raw; spawn sites other than `!` /
client terminals / PTYs / workspace search; r3 #9 (LOW, ambient preferences in one test).

Output: numbered findings with severity (BLOCKER/HIGH/MEDIUM/LOW), file:line, concrete failure, test coverage; then
the per-r4-finding FIXED / NOT FIXED list. End with exactly one line: `LAND-OK` (only if no BLOCKER or HIGH) or
`DO-NOT-LAND`.
