# P110 Astra round 3 report (gpt-6-astra, read-only, on d1b6ba58..3edbfea4)

Raw transcript sha256: 5213e9776888bd692e525f13ae3187795d3abd4480c2baea42793c07f13a9678

Reviewed `d1b6ba58..3edbfea4` read-only. No builds, tests or file changes. Two MEDIUM findings remain.

1. **MEDIUM — Adoption cleanup can still leave a marker that permanently suppresses new notes.**  
   [storage.rs:1188](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1188), interacting with [storage.rs:1232](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1232).

   After adoption, an older process recreates the legacy folder. The adopter removes the stranded marker. Before it removes the P97 marker, another startup enters the unlocked `published()` path, sees P97, recreates the stranded marker and skips notification. The adopter then removes P97. The surviving stranded marker suppresses the recreated folder’s notes indefinitely.

   This leaves round 2 #3 incompletely fixed under concurrency. Marker retirement and suppression decisions need the same migration lock.

   **Tests:** Not caught. `adoption_after_an_earlier_refusal_forgets_the_old_notice` is sequential; `migration_waits_for_the_lock` exercises an absent destination, not the unlocked published-directory path.

2. **MEDIUM — A skipped gh-release update reports an uninstalled version, suppressing a valid upward leader relaunch.**  
   [auto_update.rs:2717](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-update/src/auto_update.rs:2717), newly exposed for gh-release by [auto_update.rs:544](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-update/src/auto_update.rs:544).

   Suppose disk holds `1.0.21`, a leader still runs `1.0.20`, and the highest remaining release is `1.0.19`. Ordinary `fuigo update` correctly preserves disk but returns `Some("1.0.19")`. The notifier at [main.rs:2880](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-pager-bin/src/main.rs:2880) consequently skips that leader. With automatic updates disabled, it remains stale despite the available upward target. The skip path should report the retained on-disk version.

   **Tests:** Not caught. `automatic_update_never_downgrades_a_gh_release_install` checks `is_ok()`, downloads and disk contents, but not the returned version. The existing convergence test uses equal disk/latest versions.

The stable-version downward-relaunch revert looks correct. I retain the stated downgrade/pager and 1,000-release dispositions; these findings are separate from those accepted follow-ups. No additional U1 defect was established by inspection.

DO-NOT-LAND
