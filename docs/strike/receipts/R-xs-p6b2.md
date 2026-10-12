# R-xs-p6b2: peer messaging packet 6 part B2

Base 42adeae1. Everything is behind `features.peer_messaging` (default off) except item 3.

## Built
1. S6.6 change detection. `fuigo-shell/src/session/peer_integrity.rs` (pure watch) and `acp_session_impl/peer_integrity.rs`
   (actor glue). When a session becomes influenced (`mark_peer_influenced`) the watch records size, mtime and SHA-256 plus an
   in-memory copy of each existing well-known instruction/config file in the cwd, its ancestors (16 max), the user home and the
   Fuigo home, plus the top level of the rule/command/agent dirs and `<fuigo home>/{rules,hooks,peers}`. Fixed well-known names that
   do not exist are recorded "absent" (a later appearance is a change); other new files are not. After every tool batch
   (`execute_tool_calls`) the watch stats each file and hashes only when size or mtime moved. On a change: the `integrity` hold
   (`HoldReason::Integrity`, applied in `decide_live` to every admit or hold; refusals stand; a human release of an already held
   message still works) lasts until the human's `/peers clear-influence`; one audit line per changed file (outcome
   `integrity_changed`, `msg` = path hash, `reason` = `chg:<old16>:<new16>`, no path, no content; the key set is unchanged); one
   `NoticeKind::ProtectedFileChanged` notice naming the path and one host-turn message to the human. A tripped watch reads nothing
   and warns once.
2. S6.7. `PeerInfluence` carries a second shared flag, `peer_turn` (set where `set_peer_turn_in_flight` is). `payload_note()` is
   `Some` only when influenced or a peer-origin turn. `PreToolUse` payload gains `origin` and `peerInfluenced` (absent when `None`;
   byte-identical otherwise). The classifier gets a trusted system message (`peer_influenced`, `turn origin`) only when the note
   is `Some`; the permission handle fills it from the session's own flag (`PermissionRequest.peer_note`), never from the caller.
   The `PreToolUse` fields exist only with the feature on.
3. Feature-off resume: smaller option chosen (guard stays on, not refuse). `restore_peer_influence` no longer needs the feature; a
   stored influenced history sets the flag, and a `GuardKeptFeatureOff` notice is queued.

## Limits (stated)
- Restore of a changed file is NOT offered; the in-memory copy is kept (`Watch::copy_of`).
- At most 64 files read, 256 KiB each; larger or surplus files are skipped (`Watch::skipped`), never watched. A directory listing is
  capped at 64 names. Absent well-known names: at most 256.
- Stat-first: a rewrite that keeps size and mtime is not seen (pinned by a test).
- The baseline read happens synchronously under the state lock when the session first becomes influenced (up to 64 x 256 KiB).
- A tool batch that errors out early skips that batch's recheck; the next one catches it.
- Item 3: `/peers` is gated by the feature, so with the feature off the notice says why, but clearing needs the feature on (or a
  fresh session). The notice goes to the admission notice ring and is not pushed to the client at resume.
- Not covered by an actor-level test: the `execute_tool_calls` hook call (state-level tests cover arm, check, hold, audit, notice).

## Tests
- `session::peer_integrity::tests::*` (7): hidden write detected (hold `integrity`, one audit line, one notice, no duplicate on a
  second change, clear lifts it), new well-known file, no hashing beyond stat, touched-but-identical, over-cap skipped, 64-file cap,
  copy kept and deletion.
- `permission::manager::peer_note_tests::*` (4): classifier request carries the fields when influenced, unchanged otherwise,
  `payload_note`, message builder.
- `fuigo-hooks event::tests::pre_tool_use_peer_fields_are_absent_unless_set` (byte-identical payload).
- `peer_admit_tests::r3_restore_flag_off_*` rewritten for item 3.
- Red evidence: the new tests do not compile on 42adeae1 (the APIs are new); the changed restore test fails there.

## Round 2

Changed: `Stat` adds ctime, inode, device (unix); each watched directory's name set is recorded (capped read of 64 names) and an added or removed name is a change (a new name is watched from then on); lists extended to `.claude/skills` and `.fuigo/skills` (each `SKILL.md`), `.fuigo/{commands,agents,hooks}`, `.git/hooks`, Fuigo home `{commands,agents,skills}`, `~/.claude/{rules,commands,agents,skills}` and the Fuigo memory dir. Over the 64-file cap the later entries are dropped first: memory dir, then `~/.claude/*`, then the Fuigo home lists, then ancestors farthest from the cwd. Only the root actor sets `peer_turn` (`set_root_peer_turn`). `/peers` stays available with the feature off while the session flag is set (`CommandAvailability.peers_influenced`); the `GuardKeptFeatureOff` notice is sent as a visible host message at `run_session` start. The watch is armed at actor build for a restored session; a subagent never arms or rechecks. Rechecks added: before `submit_peer_message`, before `drain_peer_approved`, at turn start, and in a wrapper around `execute_tool_calls` (early-return paths). Generation counter on `IntegrityState` (clear between take and put-back stands). Classifier note says "not peer_message". Released (already approved) rows are held while the hold is up. The `!` command PreToolUse payload carries `peerInfluenced`. Warning paths are escaped (control, bidi, zero-width) and capped (200 chars, 8 paths). Oversized files are stat-watched (no content, no hash).

Tests (new): `equal_length_rewrite_with_reset_mtime_is_detected`, `an_added_or_removed_name_in_a_watched_directory_is_a_change`, `a_clear_between_take_and_put_back_is_not_undone`, `an_oversized_file_is_stat_watched` (and `files_over_the_cap_are_skipped_and_listed` changed), `a_subagent_turn_end_does_not_clear_the_parents_peer_turn`, `hidden_write_is_seen_by_execute_tool_calls_and_before_admission`, `a_subagent_does_not_arm_a_watch`, `feature_off_resume_can_clear_and_the_notice_is_delivered`, `pre_tool_use_envelope_carries_origin_and_flag`, `integrity_warning_path_is_escaped_and_capped`, `git_checkout_rewriting_claude_md_trips_the_integrity_hold` (real git, private HOME; skips with a visible message only without a git binary), `dot_git_config_is_watched_so_git_remote_add_trips`.

Finisher (round 2, three items):

1. The integrity hold survives a restart. A third state-marker kind, `peer_integrity_tripped` (`SyntheticReason::PeerIntegrityTripped`, `ConversationItem::peer_integrity_tripped_marker`), is stored when the hold is set (after the in-memory hold, outside any state lock). Like the other two it is decided by item KIND (`history_has_peer_integrity_hold`: the last tripped or cleared marker wins), counts as a state marker (dropped from model requests, not a prompt turn, not counted in the prompt index), and is carried through compaction in both views (`build`, `for_compaction`). Restore: `peer_integrity_hold_from_history` is read at actor build before the history moves, and the hold is set on the admission state when it is built, before the actor can decide any message; a subagent never restores. `/peers clear-influence` appends the cleared marker, which ends the hold on the next restore too. An older build reading the new tag: the `synthetic_reason` enum has `#[serde(other)] Unknown`, so the load does not fail; the item is a user item with fixed harmless text and, as `Unknown` starts a prompt turn, it is a turn boundary there and the text is visible to the model (no state effect). Tests: `the_integrity_hold_survives_a_restart`, `r3_integrity_tripped_marker_round_trips_and_last_marker_wins`, `r3_integrity_hold_survives_compaction`.
2. Baseline and recheck file work moved off the async thread. `arm_peer_integrity` (reached with the state lock held) now only starts `spawn_blocking` and returns; the finished baseline waits in a slot and every recheck first waits for it (`integrity_wait_armed`, no lock held), so the baseline is complete before the first tool call of the influenced turn (turn-start recheck) and the arm-at-restore behaviour stands. The recheck runs in `spawn_blocking` under the watch's own mutex; the result is applied under the short admission lock; findings are parked in the watch, so a cancelled recheck loses nothing; a panicked file task fails closed (hold up). Without a runtime (sync tests) the snapshot is inline. Test: `the_baseline_is_read_off_the_async_thread_and_rechecks_wait_for_it` (arming while the state lock is held).
3. `stat_of` uses `symlink_metadata`. A symlink is recorded as (symlink, hash of the target string) and compared by target string on every recheck; a swap between file and symlink, or a retarget, is a change; a symlink's target is never opened or read. A FIFO, socket or device is recorded as `special` (stat only, never opened); regular files are opened with `O_NONBLOCK|O_NOFOLLOW` and checked regular on the handle; a read that fails after a stat change is a change (`unreadable`), not a skip. A symlinked watched directory is recorded as the link itself and never listed through (nor is a symlinked skill directory joined). A symlink to a file outside the watched set is watched as a link only: an edit of its target is not seen. Tests: `links::a_regular_file_replaced_by_a_symlink_with_the_same_content_is_detected`, `links::a_watched_name_that_is_a_fifo_does_not_block` (10 s timeout), `links::a_symlinked_directory_is_watched_as_the_link_and_never_listed_through`.

Limits that remain: an edit inside the kernel clock tick (a few ms) of the previous stat shares its ctime and, with an equal length and a reset mtime, is not seen by the stat check (symlinks are exempt: their target is always compared); a trip is stored after the in-memory hold, so a crash in that instant loses the stored marker; the feature-off history scan at spawn is unchanged; the production `run_task`/`prompt_queue` calls of `set_root_peer_turn` are covered through the helper, not by a spawned subagent; the `executing a real tool batch` recheck is covered with an empty batch.

git commands that rewrite the working tree (checkout, switch, restore, reset, merge, pull, rebase, stash, apply, am, cherry-pick, revert) are not denied by the shell guard; a protected file they change is caught by this change detection.

## Round 3

What changed (7 items; counts and names only):
1. Baseline before delivery: `enqueue_admitted_peer_row` calls `ensure_peer_baseline` before the row is queued. It starts the baseline on a blocking thread and awaits it with no state lock held, so the first admitted message is never visible to the model (drained into a turn or promoted as an interjection) before the baseline is complete. A tool batch already running when the message arrives was decided before the model saw the message: a write of that batch is either inside the baseline (not attributable) or after it, where the batch-end recheck reports it (a possible false trip, which fails closed). Test: `r3_the_first_peer_message_waits_for_the_baseline` (cfg(test) hook writes a protected file mid-baseline).
2. Turn-start hold: a peer-started turn whose start recheck finds the hold up does not enter `handle_turn_input`; the row goes back to held (reason `integrity`) and the turn completes as `RemovedFromQueue`. A human-started turn continues (unchanged code path). Test: `r3_a_peer_turn_stops_at_start_when_the_recheck_trips` (red on 9ba402d2).
3. Fail closed: a baseline panic is adopted empty and raises the hold; a recheck panic raises the hold and returns one finding, so the marker and the warning are written. Tests: `r3_a_baseline_panic_raises_the_hold`, `r3_a_recheck_panic_raises_the_hold_and_writes_the_marker` (cfg(test) panic hooks).
4. The admission notice stores `display_path` (moved to `session/peer_integrity.rs`); it escapes U+2028 and U+2029 and the result, `...` included, never exceeds 200 characters. Tests: `display_path_escapes_line_separators_and_never_exceeds_its_cap`, `the_integrity_notice_stores_the_escaped_capped_path`.
5. A watched directory records its own (mtime, ctime, inode) next to the capped name set; when the listing is cut at 64 names, a change of it is a change. Test: `a_new_or_removed_name_in_a_directory_over_the_name_cap_is_a_change` (70 files, then one more, then removal).
6. The two real-git tests fail when git is absent unless `FUIGO_TEST_ALLOW_NO_GIT=1` (then a `P6B2-GIT-SKIP` line is printed).

Tests added: 7 (4 actor-level, 3 unit). Limits listed above remain; in addition, a directory with 64 or more entries now treats any create, delete or rename in it as a change, including by unrelated tools.

## Round 3 follow-up

Bound: `INTEGRITY_WAIT` = 3 s (`peer_admission.rs`; cfg(test) override `hooks.wait_ms`).
1. Bounded sites (both required by owner decision 50): (a) the baseline wait, `integrity_await_baseline` (replaces the unbounded `integrity_wait_armed`; used by `ensure_peer_baseline` and by `integrity_check_async`); (b) the recheck file work, the `spawn_blocking` join in `integrity_check_async` (used after every tool batch, before admission, at turn start). `drain_peer_approved` also calls `ensure_peer_baseline`. On timeout: fail closed without blocking the actor or the turn task; the hold goes up, one "unreadable" finding is returned, so the marker and the human warning ("could not be read in time", no path) are written once (`persist_integrity_trip`). The parked blocking task holds no session lock (a late baseline is adopted as a watch and never lifts the hold; a late recheck result is never drained). Once the hold is up `begin_arming` and `take_for_check` refuse, so no second blocking task starts: at most one per session until a human clear.
2. `submit_peer_message` now runs `ensure_peer_baseline` before the S4 decision, so a timed-out first message is HELD with reason `integrity` (not delivered, not lost, not refused). The enqueue path keeps its call as a no-op safety net (refuses `policy` if a clear raced in and the read now times out).
3. A baseline panic now also writes the marker and the warning (same finding path).
4. `decide_live` holds with `integrity` also when nobody can answer, and `check_at_drain` turns a `no_operator` refusal of an already admitted row into a hold while the hold is up; so the stopped-at-start row (`recheck_queued`) and a new message are held, waiting for the human-typed `/peers clear-influence` or expiry. Refusals by policy still stand.
Tests added: 4 (`r3f_a_hung_baseline_holds_the_message_and_frees_the_actor`, `r3f_a_hung_recheck_fails_closed_without_parking`, `r3f_a_baseline_panic_writes_the_marker_and_warning`, `r3f_stopped_row_with_no_operator_is_held_not_refused`). The two hang tests and the item-4 test fail with the waits unbounded and the old no-operator refusal (3 of 4 red). Limit: the hang tests show the actor-side call returns and the state lock is free; the `run_loop` command arm itself is not driven.
