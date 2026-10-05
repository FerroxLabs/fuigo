# P110 Astra round 2 report (gpt-6-astra, read-only, on d1b6ba58..b0b9a302)

Raw transcript sha256: 6872f193c7acf93ff73a5216a4e4cccc0a9ab64e05d67404b746408ae6323c4f

Reviewed `d1b6ba58..b0b9a302` read-only. No builds, tests or file changes.

1. **HIGH — Downward leader relaunch can cause repeated eviction/restart cycles.**  
   [auto_update.rs:434](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-update/src/auto_update.rs:434).

   With two connected `1.0.21` stdio clients, explicitly force-install `1.0.19`. The repaired hourly path shuts down the leader. One client spawns and accepts `1.0.19`; the other rejects it because [leader/mod.rs:1145](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-shell/src/leader/mod.rs:1145) compares against its compiled `1.0.21`. It requests another relaunch, but [leader/mod.rs:1675](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-shell/src/leader/mod.rs:1675) again selects the downgraded managed binary. The clients can repeatedly disconnect each other.

   This is a **pre-existing consumer incompatibility**, also relevant to internal rollbacks; round 2 restores the gh-release route into it. It prevents treating r1 #2 as safely integrated.

   **Tests:** Not caught. `ensure_latest_relaunches_onto_rolled_back_disk` checks only `relaunch_needed`; it never starts a leader or reconnects clients.

2. **MEDIUM — `--version` rollback never reaches the repaired convergence path.**  
   [auto_update.rs:2642](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-update/src/auto_update.rs:2642), [main.rs:1647](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-pager-bin/src/main.rs:1647).

   `fuigo update --version 1.0.19` installs the binary and persists `auto_update=false`. A running `1.0.21` leader then skips `ensure_latest_on_disk` entirely. The immediate notification also skips newer leaders at [main.rs:2880](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-pager-bin/src/main.rs:2880). Restarting a lower-version client retains that newer leader.

   This is another **existing caller limitation left unresolved by the stated rollback disposition**, rather than a newly introduced regression.

   **Tests:** Not caught. The explicit-version test checks installation only; the convergence test calls the helper directly, bypassing the production configuration gate.

3. **MEDIUM — Successful adoption leaves stale markers that suppress genuinely new legacy notes.**  
   [storage.rs:1184](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1184), [storage.rs:1227](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1227).

   P97 previously refuses adoption because the recorded clone is missing and writes its marker. Restore that clone, with the destination absent, and a later start successfully adopts the legacy directory. The initial cleanup retained the marker because the legacy directory existed; successful adoption never clears it. If `1.0.20` next recreates the legacy directory and writes fresh notes, P110 suppresses their notice using the old marker.

   Clearing markers only on a subsequent observed absence misses this sequential downgrade round trip. Successful adoption needs to retire the previous notice markers.

   **Tests:** Not caught. The P97 compatibility test preserves the original rejected directory; the recreation tests start with an adoption that had no previous rejection marker.

4. **LOW — The 1,000-release window mitigates r1 #5 without eliminating it.**  
   [version.rs:260](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-update/src/version.rs:260).

   Publish `v2.0.0`, then create 1,000 older-line releases: `v2.0.0` falls outside the query, so an eligible client can miss that upgrade. GitHub CLI stops when it reaches the requested count; pagination does not make the search exhaustive. [GitHub CLI implementation](https://github.com/cli/cli/blob/trunk/pkg/cmd/release/list/http.go).

   **Tests:** Not caught. Fake `gh` returns short prepared lists and does not enforce `--limit`.

I accept the intended prerelease-to-stable recovery policy and do not retain r1 #1 as a HIGH finding. The ordinary P97 suppression, both-folders-absent cleanup and fixture correction look consistent by inspection. No additional U1 defect was established; native behavior remains unexecuted.

DO-NOT-LAND
