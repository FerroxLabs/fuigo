# P113 Astra r4 brief (independent audit, read-only)

Worktree `/Volumes/Mando/WaylandBots/Fuigo/wt-p113`, branch `strike/p113`. Source inspection only: do not build, run
tests, or modify any file. Packet P113: credentials Fuigo sends or holds must not reach child processes it spawns, the
session event log, the `/feedback` trace archive, or proxy logs/errors.

Your round-3 report is `docs/strike/audits/p113-astra-r3.md` (9 findings). The fixes are
`git diff 39bafe90..d9eb19dd` (`0576f6bd` regression tests, `d9eb19dd` fixes) in
`fuigo-tools/src/util/shell_env_policy.rs` (registration, `is_fuigo_secret`), `fuigo-shell-terminal/src/pty_session.rs`,
`fuigo-secrets/src/sanitizer.rs` (`redact_credential_shapes`, `redact_private_key_blocks`, unterminated PEM) and
`fuigo-shell/src/upload/feedback_archive.rs` (archive scrub rewritten: JSON lines, multi-line JSON documents, text
runs, UTF-8 stretches, byte-value arrays).

1. For EACH r3 finding say FIXED or NOT FIXED with file:line evidence. #9 (LOW, test reads ambient preferences) was
   deliberately not changed: say whether you still rate it LOW.
2. Look for NEW defects introduced by these fixes: a credential (recorded, or credential-shaped) that still leaves the
   archive; an archived JSON/JSONL file that is no longer valid JSON or loses/splices records; ordinary text rewritten
   (false positives); a regression of r1/r2 behaviour (exact-match scrub, torn records, byte arrays); a `!` command /
   client terminal / PTY that still inherits a Fuigo secret or loses an explicit variable; denylist generation /
   persistent-shell snapshot behaviour broken by the registration change; telemetry `redact_secrets` behaviour changed
   in a harmful way; tests that would pass with a fix reverted.

Out of scope (decided, do not report): the local on-disk chat transcript written raw; spawn sites other than `!` /
client terminals / PTYs / workspace search.

Output: numbered findings, each with severity (BLOCKER/HIGH/MEDIUM/LOW), file:line, the concrete failure and test
coverage; then the per-r3-finding FIXED / NOT FIXED list. End with exactly one line: `LAND-OK` (only if no BLOCKER or
HIGH) or `DO-NOT-LAND`.
