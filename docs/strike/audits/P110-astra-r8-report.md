# P110 Astra round 8 report (gpt-6-astra, read-only, coordinator run)

Raw transcript sha256: 750767c0ef64b9e58ec7266b0a86d0895ea586e62d102e2bd9ccf7c4566e65ed

Reviewed both commits and the complete migration/helpers at clean `strike/p110@3ed57cdc`. No builds, tests, Cargo commands, or edits.

1. **MEDIUM — NEW: failed index moves can announce unchanged notes on every start.**  
   [storage.rs:1482](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1482) creates a fresh `.pre-p91-index-<pid>-<time>` directory before renaming the index. If that rename fails, the directory remains. The fingerprint includes its name, even when empty (lines 1308–1316). Every retry therefore changes the fingerprint. Concrete scenario: a proven legacy folder has an index held open on Windows without delete sharing; a temporary worktree starts repeatedly. Workspace initialization skips temporary worktrees (lines 533–535), so the destination remains absent and each start retries migration, creates another directory, and announces identical notes. Windows handles can prevent rename this way. [Microsoft documentation](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew). Failed attempts must leave the notes fingerprint stable.

2. **MEDIUM — NEW: a FIFO can indefinitely block startup.**  
   [storage.rs:1325](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1325) treats every non-directory, non-symlink entry as a readable file without checking `is_file()`. A leftover `legacy/sessions/capture.pipe` with no writer blocks `File::open`, before any notice, while holding the root migration lock. Other migrations then wait behind it. [FIFO semantics](https://www.man7.org/linux/man-pages/man7/fifo.7.html). Unsupported file types should produce an unknown fingerprint without opening them.

3. **MEDIUM — NEW: lossy path encoding permits permanent suppression of changed symlink targets.**  
   [storage.rs:1324](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1324) hashes `target.to_string_lossy()`; filenames receive the same conversion at line 1297. On Unix, retargeting an announced symlink from raw `/archive/\x80.md` to `/archive/\x81.md` produces identical hash input despite pointing at different notes. Subsequent starts remain silent. This requires no BLAKE3 collision: both invalid bytes become the same replacement character. [Rust conversion semantics](https://doc.rust-lang.org/std/ffi/struct.OsStr.html#method.to_string_lossy). Hash lossless path representations.

4. **MEDIUM — retained: suppression is persisted before announcement.**  
   [storage.rs:1253](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1253) writes the marker before constructing the notice; actual announcement happens later at line 128. Killing the process after the successful marker write but before announcement leaves a complete, matching marker for notes never announced. Every later start suppresses them. The refusal branch has the same ordering. This predates the fingerprint change but still violates the requested permanent-silence invariant.

5. **MEDIUM — retained: inability to acquire the migration lock can remain permanently silent.**  
   [storage.rs:1172](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1172) returns an empty notice list when locking fails and the destination is absent. For example, an inaccessible `.memory-migrate.lock` left by another user plus repeated temporary-worktree starts keeps the destination absent and produces no notice indefinitely. Unlike the published branch, this branch has no notice fallback.

6. **LOW — NEW: failed staging writes leave temporary files.**  
   [storage.rs:1371](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1371) only attempts cleanup when writing succeeds and renaming fails. A write that creates the file and then fails—for example, quota exhaustion—leaves `.tmp-<pid>` behind. Interruption before rename does likewise; subsequent processes use different filenames. These files sit outside the legacy folder, so they do **not** themselves change its fingerprint or suppress notices.

7. **Rounds 6–7 scenarios: fixed at source level.**  
   [storage.rs:1350](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1350) requires a nonempty matching fingerprint. Inode reuse, unavailable/coarse creation times, empty markers, and another destination’s stale markers no longer suppress different ordinary note contents. The added regression tests cover changed notes and empty markers; I read them but did not execute them.

8. **Large-folder cost: full traversal on every relevant initialization.**  
   [storage.rs:1245](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1245) fingerprints before checking existing markers. Cost is total included bytes plus per-directory sorting; contents stream, while directory entries are collected. A newly announced refusal scans twice, at lines 1224 and 1193. There are no byte/depth limits, and traversal holds the root migration lock. No legacy folder means this work is skipped. No latency measurements were made.

9. **Windows replacement: no unconditional overwrite defect found.**  
   [storage.rs:1371](/Volumes/Mando/WaylandBots/Fuigo/wt-p110/crates/codegen/fuigo-memory/src/storage.rs:1371) uses a sibling staging file, with its write handle closed before rename. Rust 1.94 implements replacement using `MOVEFILE_REPLACE_EXISTING`; an existing marker alone does not prevent replacement. [Pinned Rust source](https://raw.githubusercontent.com/rust-lang/rust/1.94.0/library/std/src/sys/fs/windows.rs). Native Windows execution remains unverified; the index-sharing failure in item 1 remains relevant.

DO-NOT-LAND
