# P86 Astra round 2 brief

Same packet, same read-only rules as `docs/strike/audits/P86-astra-r1-brief.md` (read it; do not run cargo). Diff
range now `84569ea8..HEAD`. Round 1's report is `docs/strike/audits/P86-astra-r1.txt`. What changed in response
(commit "Astra r1"):
1. r1 #1: after a persistent-shell snapshot is restored, the wrapper runs the CURRENT credential scrub and redefines
   the dump function (`ShellKind::after_restore`, `shell_state.rs`); test
   `p86_persistent_shell_drops_a_name_registered_after_it_started` (terminal.rs).
2. r1 #2: `ConfigReloader::reload_config` registers the new global config's names (`deny_credentials_named_in`) before
   any `ConfigUpdate` is sent. Known gap, stated: no test pins the ORDER (the later effective-config parse registers
   too); project-scoped `ProjectMcpServersChanged` reloads are not covered by this call.
3. r1 #3: registration keeps names exactly (no trim); blank-only names rejected.
4. r1 #4: the probe's rc file exports an rc-only credential (`GROQ_API_KEY`) and a sentinel that routes 1-2 assert;
   `.bash_profile` sources `.bashrc` for the login shell.
5. r1 #5: `NEVER_CREDENTIAL_NAMES` covers both platforms' core lists; a test registers `CORE_ENV_VARS` and asserts none
   is denied.
6. r1 #6: user guide states the exception and the process lifetime.

Re-audit the whole diff (not only the deltas). Check especially: the new wrapper text in `prepare_command` for both
bash and zsh is syntactically valid and cannot break a user's command or exit code (allexport, nounset, readonly
variables, `set -e` restored from a snapshot, an empty denylist pattern); the scrub loop variable cannot leak into the
user's environment or the next snapshot; anything still reaching a child. Same output format: severity, file:line,
scenario, test coverage; final verdict line LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
