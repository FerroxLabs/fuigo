# P110 Astra round 6 report (gpt-6-astra, read-only, coordinator run)

Raw transcript sha256: b2b58c390edfb46262e0a4a2a95db96824aecf3101cb4c15f719f29670e982aa

**Both round-5 findings are FIXED. One NEW MEDIUM still permits permanent silence.**

Reviewed all three requested commits and the complete migration function/helpers at `d76c362e`. Read-only; no builds, tests, cargo, or file modifications.

Every production notice-marker mutation is accounted for:

| Operation | Location | Behavior |
|---|---|---|
| Create P97 marker | [storage.rs:1223](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1223) | `first_notice`, called after refusal/move failure. |
| Create stranded marker after refusal/failure | [storage.rs:1193](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1193) | Runs only when `first_notice` permits a notice; immediately appends that notice. |
| Create stranded marker for published destination | [storage.rs:1251](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1251) | Requires notes and no P97 suppression; successful creation appends a notice. |
| Remove markers after observing absence | [storage.rs:1152](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1152) | Removes stranded, then P97, outside the lock. |
| Remove markers after adoption | [storage.rs:1186](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1186) | Removes P97, then stranded, for the adopter’s destination. |

All creation uses atomic `create_new`; `AlreadyExists` suppresses, while other creation errors allow a notice ([storage.rs:1277](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1277)).

- **Round 5 #1 — FIXED.** The published path still proceeds when locking fails, but its P97 branch now only skips notification ([storage.rs:1244](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1244)). It cannot manufacture a stranded marker from P97. During same-destination adoption, a suppressed fallback leaves nothing new behind; retirement removes the old markers. A fallback that creates a marker also emits a notice.
- **Round 5 #2 — FIXED.** Unlocked absence cleanup can still interleave with either startup path, but neither P97-suppressed path creates a stranded marker. If cleanup overlaps an announcing start, it can remove that start’s marker and permit repetition; a surviving newly created marker belongs to an emitted notice.

For two starts targeting the **same destination**, successful locking serializes their decisions; lock-failing published starts use atomic marker creation, with the winning creator announcing. An unpublished start whose lock fails writes no notice marker ([storage.rs:1172](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1172)). These interleavings no longer reproduce either round-5 defect.

**NEW — MEDIUM: adoption by another host leaves stale suppression markers for the recreated legacy folder.**

Legacy directory names omit the host, while destination names include it ([storage.rs:946](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:946)). Both marker keys include the destination ([storage.rs:1228](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1228), [storage.rs:1271](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1271)). Consequently:

1. Legacy folder `L` contains notes proven to belong to `github.com/acme/widgets`.
2. A 1.0.21 start for `gitlab.com/acme/widgets` refuses adoption, announces those original notes, and creates `P97(L, GitLab)` and `stranded(L, GitLab)`. Normal initialization creates the GitLab destination.
3. A GitHub adopter moves `L` into its GitHub destination. Its cleanup removes only **GitHub-keyed** markers at lines 1186–1187. Both GitLab markers survive.
4. Before another GitLab start observes absence, an older binary recreates `L` and writes fresh **GitLab** notes.
5. The second GitLab 1.0.21 start sees `L` present, retains its markers, then suppresses at line 1244. Every subsequent GitLab start does likewise.

The user was told about the original GitHub folder, never this recreated folder containing fresh GitLab notes. This is permanent silence without crashes, failed filesystem operations, or failed locking. Serialization cannot fix the destination mismatch.

The regression added in `4791fe96` manually retires one destination’s P97 marker; it does not cover adoption by a different destination. Marker suppression must distinguish legacy-folder generations, or adoption must invalidate suppression associated with that source across destinations.

DO-NOT-LAND
