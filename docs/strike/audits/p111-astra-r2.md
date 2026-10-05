# P111 Astra round 2: final report (gpt-6-astra, read-only; raw transcript sha256 efc3f0d7e8212d63, kept outside the repo)

Read-only audit of `d1b6ba58..70bc5880`. No builds, tests, or modifications. **Two HIGH findings and one MEDIUM.**

1. **HIGH — Round 1 #4 remains incomplete: a rewind between compactions can still produce a fork containing future history.** [copy.rs:575](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:575)

   Concrete sequence: compact C1 at prompt index 2, compact C2 at 4, rewind to 3, then fork at prompt 0. The parent now correctly holds C1’s summary plus P2. However, replaying the whole source with `usize::MAX` processes C2 and then the rewind; [replay.rs:504](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/helpers/replay.rs:504) clears `checkpoint_active` without restoring C1’s marker. Both comparison results become `None`, so truncation is accepted. The child retains C1’s summary of P0 **and P1**, although its cut includes only P0.

   Existing tests do not combine two compactions, a rewind between them, and a fork before the surviving compaction. Determine the source’s surviving compaction from its live timeline before authorizing truncation.

2. **HIGH — NEW: the staged transcript is readable by other users under ordinary Unix permissions.** [copy.rs:299](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:299)

   The pinned `tempfile 3.27.0` creates directories with `0777 & !umask`; this builder requests no private permissions. The transcript uses ordinary `File::create`. On Linux with shared `/tmp` and umask `022`, the directory is `0755` and `updates.jsonl` is `0644`. Another local user can read prompts and tool output while staging and replay run, including for forks ultimately refused.

   The target-session deletion race is removed, but staging introduces this exposure. Create staging with owner-only access **before writing content**. Existing tests do not check staging permissions.

3. **MEDIUM — NEW: an unreadable abandoned checkpoint unnecessarily blocks a valid fork.** [copy.rs:580](/Volumes/Mando/WaylandBots/Fuigo/wt-p111/crates/codegen/fuigo-shell/src/session/storage/jsonl/copy.rs:580)

   Take P88’s rewound-away-compaction fixture, then remove the abandoned checkpoint before copying. The filtered cut has no compaction and the parent’s authoritative chat contains the correct live branch. Replaying the unfiltered source nevertheless fails on the abandoned checkpoint. The fallback compares `None` against that abandoned marker and refuses the fork.

   P88 previously preserved this valid copy. Its existing rewound-away test keeps the checkpoint readable, so it misses the regression. Discarded checkpoints should not determine the source’s active compaction.

The other checks hold by source inspection: the Windows handle is write-capable without truncation; lazy snapshot I/O failures propagate; DI-01 plans replay before project writes; DI-02 retains snapshots and reports partial failures accurately. DI-03’s witness ordering, fingerprint checks, load/copy recovery, and repair skip match the claim. P88’s ordinary resume authority and P96’s rewrite gates remain intact. The three named P88 copy fixtures retain their expected paths, but do not cover the failures above.

DO-NOT-LAND
