# P113 Astra r3 brief (independent audit, read-only)

You are auditing branch `strike/p113` in the worktree `/Volumes/Mando/WaylandBots/Fuigo/wt-p113` (Rust workspace,
crates under `crates/codegen/`). Source inspection only: do not build, run tests, or modify any file.

Packet P113 fixes credential egress: credentials Fuigo sends or holds must not reach (a) child processes it spawns,
(b) the session event log, (c) the `/feedback` trace archive, (d) proxy logs/errors.

## Scope

1. `git diff 32dcc563..f2c0804f`: the fixes for your round-2 findings, never audited. Your r2 report is
   `docs/strike/audits/p113-astra-r2.md` (7 findings). For EACH r2 finding say FIXED or NOT FIXED, with file:line
   evidence. Note: the round-2 receipt answer for #4 left two routes open; they are addressed in scope 2.
2. `git diff f2c0804f..39bafe90` (round 3 commits `5e0200d5` tests, `5ca761c1` fix, `39bafe90` test):
   - `fuigo-workspace/src/file_system/content.rs`: content search `rg` now spawned through
     `fuigo_tools::util::spawn::detach_search_command` (policy environment).
   - `!` commands (`fuigo-shell-terminal` `LocalTerminalRunner`, `StreamingLocalTerminalRunner`), client terminals
     (`create_terminal`) and PTYs (`pty_session::create_pty`) now remove Fuigo's own secrets
     (`shell_env_policy::is_fuigo_secret` / `inherited_fuigo_secret_names`: FluxRouter first-party keys,
     `FUIGO_INTERNAL_CREDENTIAL_ENV_VARS`, every config-registered credential name) from the user's otherwise
     inherited environment, before explicit variables. Other provider keys are deliberately kept for the user's own
     `!` commands.
   - `/feedback` archive (`fuigo-shell/src/upload/feedback_archive.rs`): besides the exact-match scrub of recorded
     credentials, every line is now scrubbed by credential SHAPE using `fuigo_secrets::redact_credential_shapes`
     (new; the existing telemetry detector list in `fuigo-secrets/src/sanitizer.rs`, without URL re-serialisation);
     JSON lines value by value; decimal byte-value runs; multi-line PEM blocks over the whole file
     (`redact_private_key_blocks`).

Out of scope by decision (do not report as new defects, but you may comment): the local on-disk chat transcript
(`chat_history` / `updates.jsonl` written raw; another packet owns that code); spawn sites that are not `!`/client
terminal/search (git, direnv, pager $EDITOR, status-line commands) are listed in the receipt as proposals.

## Look for

Remaining inheritance of Fuigo secrets on the in-scope routes (any spawn path in `fuigo-shell-terminal` or the
workspace search that bypasses the new removal; ordering bugs where removal deletes an explicit variable;
Windows/case-sensitivity of names); archive scrub defects (a credential shape surviving; a scrub that corrupts JSON
or rewrites ordinary text; non-UTF-8 lines; torn records; regressions of the r1/r2 exact-match behaviour); test
weaknesses (a test that would pass with the fix reverted).

## Output

Numbered findings, each with severity (BLOCKER/HIGH/MEDIUM/LOW), file:line, the concrete failure, and test-coverage
note. Then the per-r2-finding FIXED / NOT FIXED list. End with exactly one line: `LAND-OK` (only if there is no
BLOCKER or HIGH) or `DO-NOT-LAND`.
