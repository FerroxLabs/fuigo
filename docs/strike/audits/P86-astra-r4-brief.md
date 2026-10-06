# P86 Astra round 4 brief

Same packet and rules as `docs/strike/audits/P86-astra-r1-brief.md` (read it; read-only; no cargo). Diff range
`fc3ccb94..HEAD`. Reports so far: `docs/strike/audits/P86-astra-r{1,2,3}.txt`. Response to r3 (commit "Astra r3"):
1. r3 #1: `spawn_persistent_command` loops `ensure_persistent_shell_initialized` + the cwd `metadata` await until the
   denylist generation equals the state's generation, so no await separates the final check from the spawn.
2. r3 #2: each dump is tagged with the generation its command ran under (`tag_dump_generation`) and
   `install_persistent_dump` installs it only onto the state of that generation; if the denylist grew since, only
   the dump's cwd is kept (`ShellState::update_cwd_from_dump`).
3. r3 #3: the scrub no longer filters names to ASCII identifiers; every non-alphanumeric character of a name is
   single-quoted (`'` as `\'`), ASCII letters become `[aA]`; executed test with letter-free payloads.
4. r3 #4: a re-init keeps the previous cwd over a login file's `cd`; a stale dump's cwd is kept (item 2).
5. r3 #5: the generation moves only when the registry grows.
6. r3 #6 (pre-existing unbounded `child.wait()` in `ShellState::init`): not changed; proposal.

Re-audit the whole diff; report only defects you can tie to a concrete scenario. Same output format; final verdict
line LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
