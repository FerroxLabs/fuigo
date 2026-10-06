# P114 Astra round 3 (gpt-6-astra, read-only) on ca511384 — final report section

Brief: p114-astra-r3-brief.md.

Audited `ca511384901f1e691951806242ba9dbe6d0e3cbc` against `9381f19c`, with comparisons to `6144dc1d` and `9ad4fe3d`. **One HIGH and one MEDIUM remain.** No builds, tests, or file modifications were performed.

1. **HIGH — a complete second key without its colon still hides a needed damaged record.**

   The validator counts a completed key at [file_state.rs:618](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:618), and its final check requires only that the innermost object have a completed key at [file_state.rs:658](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:658). However, the marker scan requires the following colon at [file_state.rs:511](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:511).

   This damaged line passes that combination:

   ```text
   {"prompt_index":2,"created_at":{"prompt_index"
   ```

   It consists entirely of real serialized-row prefixes: P2 cut immediately after `"created_at":`, followed by P3 cut immediately after its first key’s closing quote. This is the legacy concatenation case P114 explicitly supports.

   The validator returns `true`; the marker scan sees only P2 and returns `Some(2)`. Suppose P3 changed `x`, and a subsequent complete P4 row captures changes to `y`. After loading this history, FilesOnly rewind to 3 ignores the damaged line, restores `y`, leaves P3’s change to `x`, and returns success through [rewind.rs:482](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/acp_session_impl/rewind.rs:482). The exclusion happens at [file_state.rs:687](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:687).

   **Coverage:** [file_state.rs:2435](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:2435) tests `{`, `{"prompt_ind`, and `{"prompt_index":`, but omits `{"prompt_index"`.

   **Classification:** unresolved R2 #1, with a newly identified counterexample. Regression versus `6144dc1d`, which refuses this malformed line; reintroduces the silent partial restore present in `9ad4fe3d`. A completed key must not establish a safe bound when its record header remains incomplete.

2. **MEDIUM — the staging sweep can still delete a live directory during initialization.**

   Creating `.lock` and acquiring its exclusive lock are separate operations at [copy.rs:950](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:950). The sweep treats an old directory with an available lock as abandoned at [copy.rs:925](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:925).

   **Scenario:** on Unix, suspend process A after `.lock` creation but before `lock_exclusive`. After 24 hours, process B starts another fork. Its sweep successfully opens and locks A’s `.lock`, then removes A’s directory. A resumes, acquires the lock on its already-open, unlinked file, and subsequently fails creating the staged transcript at [copy.rs:177](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:177).

   The permission-error and missing-lock cases are corrected, but lock-file existence does not prove initialization finished.

   **Coverage:** [copy_tests.rs:2817](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy_tests.rs:2817) covers initialized locked directories, unlocked directories, young directories, and missing locks. It does not cover suspension between lock creation and acquisition.

   **Classification:** remaining initialization variant of R1 #5 / R2 #4; introduced by P114 versus both baselines. Impact is a failed live fork, not source-session loss. Initialization must participate in the sweep’s ownership protocol.

| Prior finding | Assessment | Current evidence |
|---|---|---|
| Fable #1 — damaged rows | **NOT FIXED safely** | Finding 1: [file_state.rs:658](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:658). |
| Fable #2 — system-temp staging | **FIXED** | Canonical target parent and `tempdir_in`: [copy.rs:884](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:884), line 945. |
| Fable #3 — unmarked-history advice | **FIXED** | Same-compaction refusal offers the whole-session fork: [copy.rs:697](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:697). |
| R1 #1 — neighbor-based bound | **FIXED** | Reads the damaged row’s own index: [file_state.rs:510](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:510). Finding 1 concerns incomplete concatenated headers. |
| R1 #2 — temporary append cached as damage | **FIXED** | Coordinated read; unlocked malformed EOF remains retryable: [file_state.rs:450](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:450), line 470. |
| R1 #3 — memory/disk rebounding disagreement | **FIXED** | Rewrites retain damaged bytes without rebounding: [file_state.rs:733](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:733); memory retains their original metadata at line 1214. |
| R1 #4 — root staging breaks scans | **FIXED** | Staging is beneath the CWD directory: [copy.rs:884](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:884); relocation skips dot entries at [relocation/mod.rs:151](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/relocation/mod.rs:151). |
| R1 #5 — sweep deletes live staging | **NOT FIXED** | Initialization window in finding 2: [copy.rs:950](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:950). |
| R1 #6 — staging before permission repair | **FIXED** | Canonical directory creation precedes staging: [copy.rs:884](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:884). |
| R1 #7 — stale physical line number | **FIXED** | Location explicitly describes when the session read it: [file_state.rs:696](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:696). |
| R1 #8 — conversation-only success promise | **FIXED** | Advice states the snapshot dependency: [file_state.rs:1294](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:1294). |
| R2 #1 — hidden subsequent record | **NOT FIXED** | Finding 1: [file_state.rs:618](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:618). |
| R2 #2 — indefinite event-loop lock wait | **FIXED** | Ten-second contention deadline at [file_state.rs:419](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:419); read offloaded at line 910. |
| R2 #3 — unlocked temporary EOF becomes damage | **FIXED** | Returns `WouldBlock` before recording damage: [file_state.rs:470](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:470); source retained at line 921. |
| R2 #4 — cleanup without ownership proof | **NOT FIXED** | Open failures now preserve staging, but finding 2 survives: [copy.rs:922](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:922), line 950. |

The serialization review found no additional demonstrated incompatibility in flexible-path strings/map keys, `Option<String>` contents, or timestamp strings. Finding 1 uses the actual serialized field order and the same timestamp-value boundary exercised by the added test; it does not depend on fabricated serialization.

The new lock tests cover event-loop responsiveness, contention timeout, and retry after unlocked incomplete input. These were inspected, not executed. Refusal messages now distinguish retryable reads from damage, but the unsafe bound in finding 1 can still produce incorrect “later rewind works” advice. Native Windows behavior remains unverified.

DO-NOT-LAND
