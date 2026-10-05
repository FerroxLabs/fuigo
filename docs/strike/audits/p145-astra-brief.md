# P145 Astra audit brief (Fuigo 1.0.21 strike, Windows)

You are auditing branch strike/p145 in this repository (cwd). Base (parent) is 71a99f8d. Commits: 1bac863e (red tests + stubs
marked "P145 RED stub"), e891c9de (fix), and any later p145 commits (`git log --oneline 71a99f8d..HEAD`). Read-only; do not
build. Review the diff `git diff 71a99f8d..HEAD -- crates Cargo.lock`.

Backlog items (from live Windows e2e lane E, RC 1.0.21; evidence summarised in docs/strike/receipts/R145-p145.md when present):
1. `fuigo update`, `update --check` and auto-update failed on Windows npm installs with "program not found": the updater
   spawned `Command::new("npm")`, which cannot launch npm.cmd. Required: resolve npm.cmd/npm.exe via PATH+PATHEXT the safe
   way, with no cmd.exe argument-injection hazard, covering auto-update too. Files: crates/codegen/fuigo-update/src/npm_command.rs,
   version.rs, auto_update.rs.
2. Registry down: `update --force-reinstall` printed "Forcing reinstall" and hung silently > 400 s; `update --check` took 72 s
   and reported npm's cached latest as success. Required: bounded, clear error, install left intact.
3. S14/K18: on Windows prompt_context.json, system_prompt.txt, turn_owner.lock (and resources_state.json, events.jsonl) kept the
   folder's inherited ACL. Required: owner-only like other session files (fuigo-shell session/storage/owner_only.rs is the
   existing S14 mechanism). The Windows ACL helper moved to crates/codegen/fuigo-secrets/src/owner_only.rs; fuigo-shell-base
   secure_file delegates; fuigo-session-events/src/log.rs and fuigo-tools/src/persistence.rs use it.
4. `fuigo leader list` showed a live Windows leader as "PID ? (Stale)", `leader info` found no leader. Root cause found: no
   `leader*.sock` file exists on Windows (named pipe), so discovery never probed. Fix in fuigo-shell/src/leader/mod.rs
   (discover_leaders_in_with). Live verification then showed `leader info` failing with "Connection closed": the Windows
   named-pipe accept took the pending instance out of its slot before awaiting, and the leader polls accept() inside a
   biased select!, so a dropped accept destroyed an instance a client had just opened. Fix: transport.rs accept_from_slot.

Answer, per item 1-4: FIXED or NOT FIXED, with reasons. Then list NEW regressions compared with 71a99f8d and with v1.0.20
(behaviour on Linux/macOS must be unchanged except: session files above now 0600; npm view now passes --prefer-online,
--fetch-retries=1, --fetch-retry-mintimeout/maxtimeout, --fetch-timeout=15000 and a private empty --cache; npm i -g is preceded
by an `npm view fuigo@<ver>` preflight). Look hard at: Windows PATH/PATHEXT resolution and planting (cwd, relative entries),
cmd.exe fallback safety, npm-cli.js/node.exe choice, temp cache dir creation (races, symlinks, cleanup), timeouts and
kill_on_drop (orphaned npm/node children on Windows), the NPM_TOKEN temp .npmrc in the preflight, private registries,
offline/proxy users, alpha channel, SetNamedSecurityInfoW on a file another process holds open/locked (turn_owner.lock,
events.jsonl opened per append), shared FUIGO_HOME across users, cost of the ACL call per events.jsonl open, discovery of a
stale lock on Windows (latency, misclassification), kill_leaders on Windows, accept_from_slot correctness (instance reuse
after a connected-but-unaccepted client, error paths, slot refill), tests that really fail without the fix.
Classify each finding BLOCKER / HIGH / MEDIUM / LOW with file:line. End with a verdict line: LAND-OK (zero BLOCKER and zero
HIGH) or DO-NOT-LAND.
