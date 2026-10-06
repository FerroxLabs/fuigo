# P114 Astra round 1 (gpt-6-astra, read-only) on af250c35 — final report section

Full codex log (1.2 MB, not committed) sha256 recorded in R114.

**P114 contains a HIGH regression: concurrent writers can make the new bound accept an incomplete file restore.**

| Fable item | Assessment | Evidence |
|---|---|---|
| #1 — damaged rewind rows | **NOT FIXED safely** | Ordinary ordered-file cases improve, but the bound is unsound under reachable concurrent appends. False permanent refusals also remain. See findings 1–3. |
| #2 — system-temp staging | **FIXED** | Staging uses `tempdir_in(parent)`, with Unix mode `0700`: [copy.rs:871](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:871), [copy.rs:907](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:907). The original TMPDIR dependency is removed; the replacement introduces findings 4–6. |
| #3 — unmarked-history fork advice | **FIXED** | The same-compaction refusal now offers only a whole-session fork: [copy.rs:697](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:697). The added test checks both the advice and the offered fork: [copy_tests.rs:2683](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy_tests.rs:2683). |

1. **HIGH — readable ordering does not prove the damaged row’s upper bound.**

   [file_state.rs:459](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:459) permits equal readable indices and assigns damage the next readable index. Concurrent session actors are permitted: the lifetime lock is **shared**, including across processes ([turn_owner_lock.rs:123](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/turn_owner_lock.rs:123)). The append lock serializes writes, not prompt indices ([jsonl/mod.rs:425](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/mod.rs:425)).

   Concrete scenario: two processes load the same session with next prompt index 1. Process A completes prompt 1, edits `x` at prompt 2, then dies during that snapshot append. Process B subsequently completes its prompts 1 and 2, editing a different file, `y`. The file can contain:

   ```text
   P0, P1(A), damaged-P2(A), P1(B), P2(B)
   ```

   The readable indices `0,1,1,2` pass the ordering check. Damage gets `AtMost(1)`. After a cold resume, FilesOnly rewind to 2 restores `y`, ignores the missing saved version of `x`, and reports success. The shell consumes precisely this accepted plan at [rewind.rs:220](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/acp_session_impl/rewind.rs:220). FilesOnly bypasses conversation-index validation, so that validation cannot prevent this scenario.

   **Tests:** no covering test found. The new disorder test supplies an observable descending pair; it does not test damage hiding that descent between duplicate indices.

   **Regression:** **yes versus `6144dc1d`**, which refused any damaged row. Versus `9ad4fe3d`, this reintroduces the pre-existing silent-partial-restore defect that P111 intentionally closed. Such files can also have been produced before P114.

2. **MEDIUM — an append still in progress becomes permanently cached “damage.”**

   [file_state.rs:339](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:339) reads without the append lock and accepts an unterminated EOF fragment as a damaged record. [file_state.rs:750](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:750) then records it and consumes the lazy source.

   A user requests a rewind preview while another process is writing a large snapshot. The reader reaches temporary EOF midway through that record. The writer subsequently finishes successfully, but this tracker never rereads the now-valid row. Affected rewinds continue refusing, and [file_state.rs:1149](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:1149) falsely says the contents are damaged and reading again cannot help. Reloading the session can help.

   **Tests:** the added fixtures contain already-finished damaged files; none exercises a reader overlapping an append.

   **Regression:** **yes versus `6144dc1d`** for a first strict access: its parse failure retained the lazy source for retry. Also **yes versus `9ad4fe3d` for a temporary EOF inside UTF-8**: its `read_line` error retained the source, allowing a subsequent access after the append completed.

3. **MEDIUM — the in-memory tracker does not mirror rewrites of `Unknown` damage.**

   [file_state.rs:758](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:758) explicitly leaves `Unknown` unchanged. Disk rewriting instead moves that damaged row to the end and sorts/merges readable points: [file_state.rs:505](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:505), [file_state.rs:545](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:545).

   For an older out-of-order file such as `P0,P3,damaged,P1`, ConversationOnly rewind to 2 produces `P0,P1,damaged` on disk. After new prompts 2 and 3, a cold tracker bounds the damage by 2 and permits rewind 3. The resident tracker retains `Unknown` and refuses that same rewind indefinitely. Its “none can restore files any more” message is therefore misleading.

   **Tests:** the disorder test checks only the initial refusal. The additional merge test starts with ordered rows; neither compares the resident tracker with a cold load after rewriting.

   **Regression:** the **memory/disk disagreement is new versus both baselines**. The blanket refusal itself is residual P111 behavior, not a new P114 capability loss versus `6144dc1d`.

4. **MEDIUM — staging cleanup can break session listing and relocation scans.**

   The claim at [copy.rs:859](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:859) that the leading dot excludes staging from scans is incorrect. [relocation/mod.rs:130](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/relocation/mod.rs:130) traverses every top-level directory; dot filtering happens only at the nested session-ID level.

   A session listing enumerates `.fuigo-fork-staging-*`; the fork finishes and drops that directory before the scan opens it. The `read_dir` failure propagates through `?` at line 140, failing the entire scan. Both listing APIs use it through [jsonl/mod.rs:264](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/mod.rs:264).

   **Tests:** no overlapping listing/cleanup test found. The new staging test inspects directories only after the copies finish.

   **Regression:** **new versus both baselines**; neither placed these short-lived directories at the scanned root.

5. **MEDIUM — the stale sweep can delete another process’s live staging directory.**

   [copy.rs:893](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:893) decides ownership/liveness solely from the name, directory type and directory modification time. There is no live-owner lock or enforced copy-duration limit.

   Suspend a process during staging for more than 24 hours, then fork another session from a different process. The second process deletes the first process’s staging directory. On resumption, the first fork fails when accessing or moving its transcript. On the whole-copy path, removal after staging can cause failure after the target summary has already been claimed ([copy.rs:396](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:396)). Writing an existing transcript file also does not refresh its parent directory’s modification time.

   **Tests:** no sweep/liveness test found.

   **Regression:** **new versus both baselines**. The source transcript survives, so this is a failed-fork/resource-ownership defect rather than source-session data loss.

6. **MEDIUM — staging runs before the existing sessions-directory permission repair.**

   [copy.rs:876](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:876) uses ordinary `create_dir_all`, then requires permission to create a sibling directly under `sessions/`. The canonical creation/permission-repair path runs later, at line 392.

   Concrete Unix scenario: the user owns `sessions/`, its mode is `0500`, and an existing encoded-CWD directory beneath it remains writable. Reading the source succeeds. Previously, creating the target under that CWD reached `ensure_sessions_cwd_dir_in`, which repairs the sessions root to `0700` ([paths.rs:157](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-config/src/paths.rs:157)). P114 fails creating staging before reaching that repair.

   **Tests:** the `0700` test checks the newly created staging directory, not a non-writable existing parent.

   **Regression:** **new versus both baselines**.

7. **LOW — refusal messages can name the wrong physical line after a rewrite.**

   Damage retains its original line number ([file_state.rs:491](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:491)); rebounding updates only the bound. Rewrites can move damaged rows and remove blank lines.

   For example, ConversationOnly rewind to 1 transforms `P0,P1,damaged-P2,P3` into `P0,damaged`. The resident tracker still reports line 3, although the damaged record is now line 2. The message does not qualify the location as historical: [file_state.rs:454](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:454).

   **Tests:** no post-rewrite diagnostic-location assertion found.

   **Regression:** **new versus both baselines**.

8. **LOW — conversation-only advice promises an outcome that has not been checked.**

   [file_state.rs:1143](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/file_state.rs:1143) unconditionally says a conversation-only rewind “still works.” The shell emits this before planning the conversation.

   A session can have both a damaged snapshot row and a missing compaction checkpoint. All rewind first offers ConversationOnly; following that advice reaches replay and refuses because the checkpoint is missing ([rewind.rs:518](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/acp_session_impl/rewind.rs:518), [helpers/replay.rs:362](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-shell/src/session/helpers/replay.rs:362)). The truthful claim is that ConversationOnly does not require these file snapshots.

   **Tests:** the added advice test uses a conversation that can be rewound; it does not combine the two failures.

   **Regression:** **the unconditional advice is new versus both baselines**; checkpoint refusal is pre-existing.

The ordered, single-writer paths otherwise preserve the intended safeguards: byte-based reading handles torn UTF-8; relevant damage refuses before shell file writes; ConversationOnly preserves damage instead of quarantining it away; partial file failures retain conversation and snapshots.

I also traced the workspace hub path. It calls the shared checker at [checkpoint.rs:409](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/checkpoint.rs:409), but its production tracker starts with `FileStateTracker::new()` ([session/mod.rs:314](/Volumes/Mando/WaylandBots/Fuigo/wt-p114/crates/codegen/fuigo-workspace/src/session/mod.rs:314)); checkpoint persistence is explicitly a mirror, with restore remaining in-process. I did not establish a new hub-specific damaged-JSONL refusal after Git restoration. That ordering is unchanged in both baselines.

Unix staging permissions and normal RAII cleanup are evident in source. Windows privacy is inherited from the parent ACL; this patch adds no Windows ACL enforcement. These are source findings, not native or crash-injection verification.

DO-NOT-LAND
ASTRA_EXIT=0
