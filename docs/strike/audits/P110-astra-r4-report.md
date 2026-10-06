# P110 Astra round 4 report (gpt-6-astra, read-only, coordinator run)

Raw transcript sha256: cd7e54cd964b3e29f9ff942187197489499178ad6a41aed8832cf15f9022a041

Reviewed `git show 3997af51 38fe231c` and surrounding code on `strike/p110` at `ac87a528`. No builds, tests, cargo, or file modifications.

1. **PARTIALLY FIXED — MEDIUM remains: marker retirement race.**

   Reversing the removals at [storage.rs:1190](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1190) closes the previously described interleaving, but the [published-directory path remains unlocked](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1156).

   Concrete surviving scenario: A adopts the directory; an older process recreates the legacy directory with notes. Startup B observes P97 at [storage.rs:1234](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1234), then pauses. A removes **both** markers. B resumes at line 1237, recreates the stranded marker and skips notification. Subsequent starts suppress the notice at line 1240 indefinitely while that directory remains.

   Marker retirement and suppression decisions still need shared synchronization. The existing adoption regression is sequential; neither reviewed commit adds coverage for this interleaving.

2. **FIXED — skipped gh-release update reports the retained higher version.**

   [auto_update.rs:2691](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-update/src/auto_update.rs:2691) obtains the managed on-disk version. The new comparison and return at [auto_update.rs:2719](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-update/src/auto_update.rs:2719) return `1.0.21` when the available target is `1.0.19`. Consequently, the notifier’s directional guard at [main.rs:2880](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-pager-bin/src/main.rs:2880) permits signalling a `1.0.20` leader.

   Commit `3997af51` adds the relevant returned-version assertion at [test_gh_release_install.rs:321](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-update/tests/test_gh_release_install.rs:321). Inspected only; not executed.

**New defects:** No distinct defect introduced by these changes was established. The remaining MEDIUM is round 3 finding #1.

DO-NOT-LAND
