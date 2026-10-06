# P86 Astra round 5 brief

Same packet and rules as `docs/strike/audits/P86-astra-r1-brief.md` (read it; read-only; no cargo). Diff range
`fc3ccb94..HEAD`. Reports so far: `docs/strike/audits/P86-astra-r{1,2,3,4}.txt`. Response to r4 (commit "Astra r4"):
1. r4 #1: `DENYLIST_FENCE` (`shell_env_policy.rs`): `register_credential_env_names` holds it for writing while it
   grows the registry and bumps the generation; `spawn_persistent_command` takes it for reading after its last await,
   re-checks the generation under it, and drops it right after `cmd.spawn()` returns. The child env is built under
   the registry's own lock (a different lock), so there is no recursive read.
2. r4 #2: `install_persistent_dump` keeps a foreground dump's cwd whenever it does not install the snapshot.
3. r4 #3 (pre-existing unbounded `child.wait()` in `ShellState::init`): unchanged; proposal.

Re-audit the whole diff, in particular deadlock or Send problems from the fence (a `std::sync::RwLockReadGuard` in an
async fn; registration called from async contexts) and anything still reaching a child. Report only defects tied to
a concrete scenario. Same output format; final verdict line LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
