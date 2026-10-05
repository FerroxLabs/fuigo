# P114 Astra round 2 (gpt-6-astra, read-only) on 15a4a847 — final report section

Brief: p114-astra-r2-brief.md. (Two earlier r2 attempts audited another packet's brief: a shared scratchpad file was overwritten; discarded.)

Audited `15a4a847564f61508c7bea181e66dbe0f6fab344` against `9381f19c`, with comparisons to `6144dc1d` and `9ad4fe3d`. **One HIGH and three MEDIUM findings remain.** No builds, tests, or file modifications were performed.

| Prior finding | Assessment | Current evidence |
|---|---|---|
| Fable #1 — damaged rewind rows | **NOT FIXED safely** | Ordinary torn rows improve, but the replacement parser can still permit an incomplete restore; see finding 1 below. |
| Fable #2 — system-temp staging | **FIXED** | Staging uses the target CWD directory and `tempdir_in`: [copy.rs:884](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:884), [copy.rs:945](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:945). |
| Fable #3 — unmarked-history fork advice | **FIXED** | The same-compaction refusal offers only a whole-session fork: [copy.rs:697](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:697). |
| R1 #1 — unsound position-based bound | **FIXED** | The specific concurrent-ordering counterexample is closed by reading the row’s own index: [file_state.rs:454](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:454). The new parser has a separate defect below. |
| R1 #2 — temporary append cached as damage | **NOT FIXED** | Lock acquisition failures still permit an unlocked read: [file_state.rs:393](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:393). See finding 3. |
| R1 #3 — memory/disk rebounding disagreement | **FIXED** | Rewrites preserve damaged bytes, and memory no longer rebounds their indices: [file_state.rs:437](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:437), [file_state.rs:1009](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:1009). |
| R1 #4 — root-level staging breaks scans | **FIXED** | Staging moved beneath the CWD directory, where relocation skips dot entries: [copy.rs:884](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:884), [relocation/mod.rs:151](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/relocation/mod.rs:151). |
| R1 #5 — sweep deletes live staging | **NOT FIXED** | Failure to open the lock is treated as permission to delete: [copy.rs:924](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:924). See finding 4. |
| R1 #6 — staging precedes permission repair | **FIXED** | Canonical directory creation now precedes staging: [copy.rs:884](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:884), [paths.rs:157](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-config/src/paths.rs:157). |
| R1 #7 — stale physical line number | **FIXED** | The location explicitly says “when this session read it”: [file_state.rs:496](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:496). |
| R1 #8 — conversation-only success promise | **FIXED** | The replacement sentence states the snapshot dependency correctly: [file_state.rs:1089](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:1089). |

1. **HIGH — an incomplete subsequent record marker defeats the damaged-row bound.**

   [file_state.rs:461](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:461) searches only for the **complete** byte sequence `{"prompt_index":`. It cannot detect a subsequent record cut inside that sequence.

   Consider the legacy concatenated-line case that this implementation explicitly supports:

   ```text
   line 1 = ASCII prefix of serialized P2, including its complete index
            + first 12 bytes of serialized P7: {"prompt_ind
   line 2 = complete P8
   ```

   P7 edited `x`; P8 edited `y`. The second append stopped before its index survived. The parser nevertheless returns `Some(2)`, because its search never finds a second complete marker. Consequently, [file_state.rs:487](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:487) declares the damage irrelevant to target 7. FilesOnly rewind restores `y`, leaves P7’s change to `x`, and returns success through [rewind.rs:482](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/acp_session_impl/rewind.rs:482).

   JSON quote escaping does prevent saved contents from containing the complete marker. It does **not** establish that every concatenated record’s marker survived.

   **Coverage:** [file_state.rs:2215](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:2215) tests a complete second marker and an incomplete *first* marker, but not an incomplete subsequent marker. This is a static counterexample; it was not executed.

   **Regression:** new versus `6144dc1d`, which refuses the malformed line; the silent-partial-restore behavior existed in `9ad4fe3d`. The current newline-healing appender prevents new concatenations; this finding concerns the legacy concatenated input expressly supported by P114. Such ambiguous rows must remain unidentifiable rather than receive the lower bound.

2. **MEDIUM — the new blocking read lock can freeze the session’s event loop indefinitely.**

   [file_state.rs:402](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:402) calls blocking `lock_shared`. [file_state.rs:708](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:708) reaches it directly from an async method, without offloading or a deadline. Production sessions use a current-thread runtime ([spawn.rs:39](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/acp_session_impl/spawn.rs:39)); rewind runs on that session’s `LocalSet` ([run_loop.rs:1237](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/acp_session_impl/run_loop.rs:1237)).

   **Scenario:** process A is suspended while holding the append lock. Process B requests a rewind preview of the same session. B blocks its session thread inside the OS lock call, preventing that session’s turn, cancellation, and other local tasks from progressing until A releases the lock.

   The persistence rewrite uses `spawn_blocking`, so it avoids this particular event-loop freeze. Nevertheless, an unbounded wait there stalls its FIFO and later `FlushAndAck` requests.

   **Coverage:** [file_state.rs:2298](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:2298) proves that reading waits and eventually finishes when an external thread unlocks. It does not check session responsiveness or a permanently suspended holder.

   **Regression:** the read-side lock dependency is new versus both baselines. Use a bounded, yielding acquisition path and retain the lazy source when the lock remains busy.

3. **MEDIUM — lock failure still turns temporary EOF into permanent “damage.”**

   [file_state.rs:399](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:399) and line 402 convert open/lock failures into `None`; [file_state.rs:417](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:417) proceeds unlocked. Successful reading then records malformed rows and consumes the lazy source at [file_state.rs:728](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:728).

   **Scenario:** an appender already holds an open lock descriptor, but the lock file’s permissions subsequently prevent another process from reopening it read/write. The snapshot file remains readable. A rewind reads temporary EOF during that append, caches damage, and continues refusing after the writer finishes a valid record. Reloading can recover; the permanent-damage diagnosis remains misleading.

   **Coverage:** the new append-overlap test exercises successful lock acquisition only. No lock-open/lock-acquisition failure test covers this fallback.

   **Regression:** unresolved R1 #2. Versus `6144dc1d`, first strict access retained the source after a parse failure. Versus `9ad4fe3d`, a temporary EOF inside UTF-8 also retained the source for retry. An unavailable coordination lock must not justify permanently classifying an unstable read.

4. **MEDIUM — staging cleanup still deletes directories without establishing that their owner is dead.**

   At [copy.rs:924](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:924), **every lock-open error** makes `live == false`; removal follows at line 929.

   **Scenario:** a live fork retains its lock descriptor, but `.lock` becomes non-writable. Another process cannot reopen it read/write and therefore deletes the old staging directory despite the held lock. There is also a source-visible creation window: suspend the first process for over 24 hours between [copy.rs:945](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:945) and lock-file creation. A second fork sweeps its directory; the first fails when resumed.

   **Coverage:** [copy_tests.rs:2817](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy_tests.rs:2817) covers an old, successfully opened locked directory, an unlocked one, and a young directory. It does not cover lock-open errors or suspension before lock creation.

   **Regression:** unresolved R1 #5, introduced by P114 versus both baselines. Source sessions survive, but live forks can fail. Cleanup should require positive ownership evidence; failure to open a lock is not that evidence.

I found **no ordinary same-process append/read lock cycle**: appending acquires and releases its lock entirely inside the blocking closure ([jsonl/mod.rs:425](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/mod.rs:425), line 463). The rewrite releases its shared read lock before its separate atomic write. The existing read–rename window can still lose another process’s append, but that window exists in both baselines and is not a new P114 finding.

For Windows cleanup, `ForkStaging` declares `_lock` before `dir`, so the lock handle closes before `TempDir` removal; the sweep also explicitly closes its handle before removal ([copy.rs:870](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:870), line 928). I found no additional held-handle cleanup defect in that ordering. Windows locking/removal behavior was not executed or qualified natively.

DO-NOT-LAND
