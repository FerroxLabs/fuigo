# P110 Astra round 1 report (gpt-6-astra, read-only, on d1b6ba58..b1234f13)

Raw transcript sha256: 72e7f618e00d182b7fe782d142115e1390616eafe247322ee446ae3ce543d956

Reviewed `d1b6ba58..b1234f13` and relevant callers read-only. No builds or tests were run.

1. **HIGH — Automatic prerelease downgrades still bypass U2.**  
   [auto_update.rs:542](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-update/src/auto_update.rs:542), with the bypass at line 517.  
   Running `1.0.22-alpha.1` with channel `stable` and latest release `1.0.21` still permits an automatic download and downgrade relaunch. `needs_update()` returns `true` for a prerelease current version before consulting `allow_downgrade`. Setting the gh-release flag to `false` therefore does not establish the claimed invariant.  
   **Tests:** Not caught. The new integration case uses plain stable versions; existing unit tests explicitly expect this bypass. The gh-specific correction must preserve npm/internal behavior.

2. **MEDIUM — Explicit forced rollback no longer converges an existing leader.**  
   [auto_update.rs:432](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-update/src/auto_update.rs:432), affected by the changed installer policy; [main.rs:2880](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-pager-bin/src/main.rs:2880).  
   With a `1.0.21` leader and highest release `1.0.19`, `update --force` installs `1.0.19`, but the explicit notification skips newer leaders. Previously, hourly gh-release convergence could perform the rollback relaunch; now it returns `false`. The leader keeps running `1.0.21`, and restarting a client does not evict that newer leader.  
   **Tests:** Not caught end-to-end. The force test checks the installed file; the changed matrix test asserts no automatic downgrade relaunch without providing an explicit rollback relaunch path.

3. **MEDIUM — Existing P97 notices are announced again after upgrading.**  
   [storage.rs:1217](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1217).  
   A pre-P110 run can leave `.legacy-notice-<hash>`, the rejected legacy folder, and an initialized host-qualified folder. P110 checks only `.legacy-stranded-notice-<hash>`, so it announces the same folder again—incorrectly describing it as memory written after a move. Creating both markers during future migration attempts does not handle existing P97 state.  
   **Tests:** Not caught. The duplicate-notice fixture creates its first notice using P110 code, which writes both markers.

4. **MEDIUM — Marker reset misses absence when the new folder is also absent.**  
   [storage.rs:1147](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1147).  
   After a stranded notice, remove the legacy folder and clear workspace memory using the existing clear operation. On the next start, both folders are absent: migration returns before clearing the stranded marker, then initialization recreates the new folder. If an older binary subsequently recreates the legacy folder with notes, the surviving marker suppresses its notice indefinitely.  
   **Tests:** Not caught. The recreation test removes only the legacy folder and retains the host-qualified folder throughout.

5. **MEDIUM — “Highest semver” is limited to 100 releases.**  
   [version.rs:258](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-update/src/version.rs:258).  
   If `v2.0.0` is followed by 100 older-line `v1.x` releases/backfills, it falls outside the query. The updater selects a lower `v1.x` release and can miss the available `v2.0.0` upgrade. GitHub CLI stops at the requested number of eligible releases; this is not an exhaustive search. [GitHub CLI implementation](https://github.com/cli/cli/blob/trunk/pkg/cmd/release/list/http.go).  
   **Tests:** Not caught. Fixtures contain small lists, and fake `gh` does not enforce `--limit`.

6. **MEDIUM — The requested commit contains a broken M1 test fixture.**  
   [p91_identity_tests.rs:531](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/p91_identity_tests.rs:531).  
   `attacker` resides under `tempfile::tempdir()`, so storage marks it ephemeral. `ensure_initialized()` skips workspace creation; the following `is_dir()` assertion fails before the second-start suppression check.  
   **Tests:** The test itself exposes this fixture failure. Checkout commit `7eebd98f` repairs it, but that commit is outside the requested review endpoint.

No additional U1 defect was established by inspection. Checksum validation, ordinary failure cleanup, and the new temp names’ compatibility with the stale-file sweep look consistent. Native Windows and interruption behavior remain unexecuted.

DO-NOT-LAND
