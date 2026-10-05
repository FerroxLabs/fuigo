# P86 Astra round 3 brief

Same packet and rules as `docs/strike/audits/P86-astra-r1-brief.md` (read it; read-only; no cargo). The branch was
rebased onto `strike/integration` fc3ccb94 (P85, unrelated files). Diff range now `fc3ccb94..HEAD`. Reports so far:
`docs/strike/audits/P86-astra-r1.txt`, `P86-astra-r2.txt`. Response to r2 (commit "Astra r2"):
1. r2 #1-#3 (persistent mode removed an explicit `set` key; old snapshot readable in `$snap`; readonly vars): r1's
   wrapper scrub (`after_restore`) is GONE. Instead `register_credential_env_names` bumps a generation counter;
   `LocalTerminalActor::ensure_persistent_shell_initialized` discards a snapshot taken under an older generation and
   re-initializes the shell (same cwd) before the next command; the fd-4 dump task discards a dump from a command
   spawned under an older generation. Cost (documented in the user guide): the session's exports/functions/aliases
   are lost when a config change adds a credential name while a persistent shell is live.
2. r2 #4: the bash scrub sets IFS inside its capture subshell; test `p86_bash_scrub_ignores_a_changed_ifs`.
3. r2 #5: `reload_config` registers names from the effective config (campaign patches) as well as the global file,
   before any `ConfigUpdate` is sent. Still no test pins the ORDER (stated, mutant MI expected to survive).
4. r2 #6: only the empty name is refused; `"   "` registers.
5. r2 #7: the probe fixture removes `GROQ_API_KEY` / `P86_RC_BENIGN` from the inherited env; explicit `set` is
   tested on the persistent backend, two commands in a row.

Re-audit the whole diff. Check especially the generation logic in `terminal.rs` (races between registration, init,
spawn and dump collection; background commands; the static-shell and login-env paths; whether a re-init can lose
the cwd or hang), and anything still reaching a child. Same output format; final verdict line
LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
