# P110 Astra round 5 report (gpt-6-astra, read-only, coordinator run)

Raw transcript sha256: 64fb104038e1a6f7fa164696e52f1a25931a9bd61450ce7fb06a5343ad220b26

**NOT FIXED completely.** At `06d75197`, successful acquisition closes Round 4’s adopter interleaving, but two MEDIUM paths remain.

1. **MEDIUM — Lock failure preserves the original race.** [storage.rs:1164](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1164) accepts `None` and still calls the suppression logic at [storage.rs:1244](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1244).

   Concrete scenario: the memory root is writable to both starters, but the lock file is writable only to the adopter. The observer cannot open it, reads P97, pauses while the adopter removes both markers, then recreates the stranded marker. Subsequent starts suppress the recreated notes indefinitely. The fallback must avoid persisting suppression derived from an unlocked P97 read.

2. **MEDIUM — Absent-folder cleanup still races with suppression.** Newly identified, but present before these commits: [storage.rs:1151](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1151) removes both markers outside the lock.

   Concrete sequence: with both markers present, startup A observes the legacy folder absent, removes the stranded marker, then pauses. An older binary recreates the folder with notes. Startup B acquires the migration lock, sees P97 and recreates the stranded marker. A resumes and removes P97. The surviving stranded marker suppresses notices indefinitely—even though B successfully acquired the lock. Marker retirement needs the same synchronization.

The other requested checks found no additional defect:

- No nested acquisition in the traced paths; the published branch returns before the adoption branch. The guard remains scoped to the call; closing it releases the lock. [Rust documentation](https://doc.rust-lang.org/std/fs/struct.File.html#method.lock)
- [storage.rs:1156](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1156) skips acquisition when no legacy directory exists, including a missing root.
- Remaining legacy directories cause acquisition on every launch, with waiting during contention; the lock is not retained by `MemoryStorage`.

Reviewed both requested commits and the surrounding code. The new test covers successful acquisition, not either interleaving above. No builds, tests, Cargo commands, or file modifications.

DO-NOT-LAND
