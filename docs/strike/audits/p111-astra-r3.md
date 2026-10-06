# P111 Astra round 3: final report (gpt-6-astra, read-only; raw transcript sha256 80cb45dc66b4b848, kept outside the repo)

Two **HIGH** integrity gaps remain. These are retained failure paths, not regressions introduced by the round-2 correction.

Reviewed `d1b6ba58..0b7f8a99`. Worktree remains clean. No builds, tests, or modifications performed.

1. **HIGH — Matching compaction markers does not make truncation safe for legacy chat without prompt indices.**  
   [copy.rs:575](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:575) accepts the fallback when checkpoint IDs match. [copy.rs:311](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:311) then passes an absolute prompt index to a helper that [counts from zero when chat markers are absent](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-sampling-types/src/conversation.rs:2040).

   **Scenario:** compaction at prompt 5, missing checkpoint, saved chat containing the summary followed by unmarked P5/A5, P6/A6 and P7/A7. Fork at P5. Both transcripts identify the same compaction, so fallback proceeds; truncating at absolute index 6 retains P6/P7 because the shortened conversation never reaches six counted turns. The child’s transcript ends at P5, but its model history includes future turns.

   **Coverage:** the [missing-checkpoint fallback regression](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy_tests.rs:2216) stamps explicit prompt indices with `chat_user`; it does not catch this. Require a provable cut boundary, or refuse this fallback.

2. **HIGH — The fallible snapshot accessor still accepts incomplete data after JSON parsing failures.**  
   [file_state.rs:518](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-workspace/src/session/file_state.rs:518) calls the existing [lenient reader](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-workspace/src/session/file_state.rs:348), which logs malformed rows and returns the remaining points successfully. The loader then clears `lazy_source`.

   **Scenario:** a resumed session has valid snapshots plus a damaged row describing another prompt’s file changes. “Rewind all” restores only the readable points, leaves the skipped files unchanged, rewinds the conversation, truncates the in-memory tracker and reports success. The subsequent disk truncation uses a strict reader and can fail, but that asynchronous failure does not alter the successful response. Repairing the snapshot file also cannot reload the missing points through this tracker because its lazy source was consumed.

   **Coverage:** [the new unreadable-snapshot regression](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/acp_session_tests/rewind_cross_compaction_tests.rs:758) exercises a directory/I/O failure, not malformed rows. The destructive rewind path needs strict or corruption-aware materialization that preserves retry state.

The remaining requested checks support these conclusions from source inspection:

| Work item | Status | Progress / pending work |
|---|---|---|
| Overall execution goal | ✅ Done | Final read-only audit complete; two HIGH findings remain. |
| DI-01 | ✅ Done | Conversation planning and replay precede project-file writes/deletes. Replay errors return before those mutations. |
| DI-02 | ⬜ Pending | Restore/delete/existence errors are reported correctly and retain snapshots; malformed snapshot loading remains unsafe. |
| DI-03 | ✅ Done | Write-capable fsync, durable witness before activation, fingerprint/checkpoint matching, load and source-copy projection, and conditional repair skipping are implemented. |
| DI-04 | ⬜ Pending | Different live compaction markers correctly refuse before target creation; markerless-chat fallback remains unsafe. |
| Round-2 corrections | ✅ Done | Shared live-timeline filtering replaces full-source replay; abandoned checkpoints are not opened by that comparison; Unix staging explicitly uses `0700`. Added fixtures cover the stated cases, and the checkpoint-copy assertions remain intact. |
| P88 / P96 constraints | ✅ Done | Normal resume retains chat-file authority; rewind/compaction refusal checks and storage/spawn rewrite gates remain present. |

DO-NOT-LAND
