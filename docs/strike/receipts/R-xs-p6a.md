# R-xs-p6a: peer messaging packet 6 part A (guard for file-write tools, influenced state, blocking prompt hook)

Branch `strike/xs-p6a` on `hub`, base `d94f2cb1`. Built and tested on Hetzner lane `xs6a` only.

## Protected set (`is_peer_protected_path`, `fuigo-workspace/src/permission/peer_guard.rs`)
Existing floor (reused as-is through `edit_target_protection`, `shell_access.rs:4320`; it resolves `..` and symlinks of leaf and
parents, fails closed on relative or unresolvable paths): Fuigo config/sandbox/managed/requirements and `permission*.toml`, hook roots,
`.claude/settings*.json`, `.cursor/hooks.json`, vendor MCP lists (`.mcp.json`, `.claude.json`, `.cursor/mcp.json`, `mcp.json`, `lsp.json`),
`.git/hooks`, `.ssh`, shell startup files, `/etc`, container dirs (`.fuigo`, `.claude`, `.cursor`).
Added by this packet (matched on the lexical AND the symlink-resolved path, case-insensitive):
- instruction files `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `AGENT.md` at any depth (read by `fuigo-tools/src/types/compat.rs:425-440`,
  `agents_md_tracker.rs:20-31`; the walk covers cwd, ancestors, subdirectories, home);
- `.claude|.fuigo|.cursor` + `rules|skills|skills-cursor|agents|commands` (`agents_md_tracker.rs` RULES_DIRS, `skills/discovery.rs:26-29`);
- peer config, held store, audit log: `.fuigo/peers/**` and `<fuigo home>/peers/**` (that directory does not exist yet; later packets create it);
- git config: `.git/config`, `.git/modules/**/config`, `.git/**/config.worktree`, `.gitconfig`, `.config/git/config`.

## Auto-approving entry points and where the guard sits
- `PermissionHandle::request` (`manager/mod.rs`, first statement): runs before the allow-all arm, before the actor receives the request
  (so before yolo, auto/classifier fast path, acceptEdits, dontAsk, bypassPermissions, AlwaysAllow, catch-all allow rule, saved always-allow
  grants, the session edit grant). Result `Decision::PolicyDeny(text)`, never a prompt. One atomic load when not influenced.
- Allow-all handle: variant is now `AllowAll(PeerInfluence)` so it carries the flag.
- Hub-routed path: `hub.rs::enforce_hub_policy`, before the policy verdict (denies single edits and every `apply_patch` target).
- Plan-file auto-approve (`tool_calls.rs`, `plan_file_auto_approve`) is a shell-side bypass of `request`; the plan file is not in the set
  (`.fuigo/plans`), so no change. Not hardened further.
- Not covered (Part B): `AccessKind::Bash` (S6.4), hidden writes (S6.5), change detection (S6.6), classifier/PreToolUse payloads (S6.7).
  Stubs: comment in `peer_guard_denial` (`AccessKind::Bash` arm), `peer_guard.rs` module doc, `hub.rs` guard comment.

## Influenced state
Set in `enqueue_admitted_peer_row` (the single choke point for submit and drain) after the hook passes and the row is committed
(`mark_peer_influenced`), stored as one shared `PeerInfluence` atomic in the permission handle AND `ToolContext` (read live, no cache).
A subagent spawned afterwards starts from the parent's value (`SubagentSpawnContext.parent_peer_influenced`, `handle_request.rs`).
Exits: `/peers clear-influence` (new built-in, human intent only; peer text is inert, model-authored is denied) and a fresh context
(new session = new flag). An unrelated human prompt does not clear it. The guard does not look at the turn origin (a human-typed
request for a protected edit is denied while the state holds): the design's one-shot prompt for human-started turns was NOT built,
per the packet brief ("do not special-case the turn origin"). Deviation from S6.3 text, owner can reverse.

## Decision 35 (blocking hook on a peer message)
`peer_prompt_hook_refuses` (`hook_dispatch.rs`) runs `UserPromptSubmit` with `origin: "peer_message"`, `peerSender`, `peerClaimedMode`
(new optional payload fields, absent for every other prompt) on the wrapped text before the row is committed. Block -> refused,
outcome `rejected{policy_refused}` (`RejectReason::PolicyRefused`), nothing queued, state not set. The prompt gate carries no
approval, rewrite or context, so those are ignored. Failure rule: for a human prompt a failed or timed-out hook is FAIL-OPEN (decision
Allow, only a `Failed` result is recorded); for a peer message any `Failed` result REFUSES (fail closed). The turn-start skip for peer
text (S1.4) is unchanged, so the hook runs once. No hook configured: nothing runs.

## Deviations and not verified
- Resume: the flag is in memory. A resumed transcript that contains peer messages does NOT restore the state (S6.1 "survives resume"
  not built); compaction does not touch it. Left for a follow-up.
- Hub sessions: `WorkspaceSession::peer_influence()` exists and `enforce_hub_policy` honours it, but nothing in the shell sets it for a
  remote hub session (hub-routed prompts and Windows path handling not verified).
- Unparseable `apply_patch` targets keep the existing refusal.

## Round 2 (review findings)
Files: guard `fuigo-workspace/src/permission/peer_guard.rs`; state `fuigo-shell/src/session/peer_influence_state.rs`; actor `acp_session_impl/peer_admit.rs`.
- A (Opus 1): `/peers clear-influence` is refused when `startup_hints.is_subagent` (`slash_exec.rs` Peers arm), for every origin. Test `opus1_subagent_session_cannot_clear_influence` (drives the slash executor on a subagent-flagged actor; the real subagent prompt path was not driven). The task-prompt authority change is the other packet.
- B (Opus 2): the flag is also set when a turn starts with a peer input (`turn_task.rs` `run_task`) and when a peer row is promoted (`prompt_queue.rs` `promote_parent_agent_messages`); the clear is refused while a peer row is queued/running, held or approved (`has_peer_work_outstanding`, `PeerAdmission::has_undelivered`). Test `opus2_clear_refused_while_peer_row_queued_and_promotion_reflags`.
- C (Opus 3, Groks): persisted in a sidecar `<session dir>/peer_influence.json` `{influenced, cleared}` (`peer_influence_state.rs`), written on set and on clear (clear writes the marker). Restored in `spawn_session_actor` (`spawn.rs`, next to the permission handle), which every actor build from stored history goes through: `session/load`, `--resume`/`--continue`, crash recovery, leader restart. Fork copies the file (`fork.rs`) and the transcript rule backs it up. Transcript rule: any stored user item containing `<cross-session-message from=` and no `cleared` marker starts influenced; damaged or missing file falls back to it; old sessions load clean unless it applies; `/clear` and new sessions have no file. Subagents skip the restore (they share the parent's atomic). Test `s6_1_persisted_flag_marker_and_transcript_rule` (unit, all branches) and `opus3_state_is_persisted_and_cleared_with_a_marker`. Per-path tests through a real load/resume/fork were NOT written (all paths funnel into the one spawn site).
- D (Grok): (i) TRUE for the permission handle (shared `Arc<AtomicBool>` in the cloned mode view); FALSE for the tool context before this round (the child copied the bool into its own atomic). Now `SubagentContext.parent_peer_influence` carries the parent's `PeerInfluence` and the child's tool context uses the same atomic (`handle_request.rs`, `subagent_spawn.rs`). Test `grok_d_child_tool_context_shares_the_parents_atomic` (primitive level only). (ii) hub: `spawn.rs` takes the hub session's own `PeerInfluence` (`workspace.session(id).peer_influence()`) as THE flag for handle and tool context, so `enforce_hub_policy` sees it; if no hub session exists at spawn the flag stays local (hub then has no flag to check). `hub.rs` now checks EVERY access, not `accesses[0]`, inside `spawn_blocking`; a failed check denies. No hub-level test written.
- E (Opus 5): `tool_calls.rs` plan-file auto-approve is skipped for an influenced session, so the edit goes through `request()` and the guard. No dedicated test.
- F (Opus 8): `mark_peer_influenced` now runs before `commit_queued_delivery`, under the state lock (`peer_admit.rs`).
- G (Opus 7): `task:` pseudo-paths skipped in `peer_guard_denial`. Test `s6_3_task_pseudo_path_in_a_protected_cwd_is_not_denied`.
- H (Opus 4): added `.fuigo/{personas,roles,prompts,workflows,memory}`, `{.claude,.fuigo,.cursor}/plugins`, `known_marketplaces.json`, files named `peer-audit*.jsonl*` (packet 5's audit log is not in this tree: the name is a guess; remove or fix when it lands), and under the Fuigo home (via the floor's `fuigo_home_matches`, now `pub(crate)`): rules, skills, agents, commands, peers, plugins, hooks, memory and the home-level audit file. Tests `s6_2_round2_added_protected_paths_and_over_protection`, `s6_2_relocated_fuigo_home_dirs_are_protected` (`src/commands/x.rs`, `docs/rules.md` stay unprotected). Stated limit: hook scripts that settings reference but that live elsewhere are not protected.
- I (Opus 6): the all-modes table now asserts no TIMEOUT and compares `resolution.event`; new symlink-through-`request()` table `s6_3_symlink_into_set_is_denied_through_request`. NOT done: plan-mode row, and a test through the production `spawn` construction (`spawn.rs` sharing handle and tool context).
- J (Opus 10): peer hook results are redacted (`redact_peer_hook_results`) before the UI send and the log; the block reason is no longer traced; telemetry already carried names and outcome only. Test `opus10_peer_hook_results_carry_names_and_outcome_only`.
- K (decision 41): denial text names the situation and `/peers clear-influence`; test `s6_3_denial_text_says_what_and_how_to_lift`.
- Part B list: shell-command writes (S6.4, bash and any non-Edit access), MCP and `use_tool` writes and dynamic delete/rename tools (S6.5, S6.6), origin in classifier and `PreToolUse` payloads (S6.7), decision-35 ordering (Opus 11). `EditTargets::Unparseable` or empty: the guard returns None and the existing always-refuse applies; an influenced edit request with NO target at all cannot reach the guard (single-target `Edit(path)` always has a path), so fail-closed is already the case there. Guard path resolution in `request()` is still synchronous filesystem work.

## Round 3 (persistence redesign and audit findings)

**Persistence replaces the sidecar.** The session TRANSCRIPT is the only source of truth, decided by item KIND, never by text.
`peer_influence.json`, its fork copy and the `<cross-session-message from=` text matcher are removed.
- A session is influenced iff the last state item in its stored history is a `peer_message` item (`synthetic_reason: "peer_message"`, packet 3) or an influenced marker, not a cleared marker (`fuigo_sampling_types::history_is_peer_influenced`).
- Markers are user items with `synthetic_reason` `"peer_influenced"` (carried through compaction) and `"peer_influence_cleared"` (written by `/peers clear-influence`, appended and acked in the transcript BEFORE the live flags drop; a failed append leaves the session influenced). Fixed harmless text, so an older build that loads the unknown tag (`SyntheticReason::Unknown`, `#[serde(other)]`) shows a harmless note. An older build treats an `Unknown` item as a turn boundary for legacy prompt counting only.
- Never model-facing: `ModelRequestHistory::from_raw` (the request path) drops both kinds. Restore: `restore_peer_influence`, called once from `spawn_session_actor` (so load, resume, crash recovery, leader restart and fork) over the history already loaded for replay: no extra file read. It does nothing at all unless `features.peer_messaging` is on and the session is not a subagent.
- Compaction: `CompactionStateContext::build` and `for_compaction` carry exactly one influenced marker when the state holds but the tail lost the stored peer message; a cleared or never-influenced session carries none.
- Fixes: feature-off sessions are never scanned (cardinal rule); pasted text cannot flag a session; rewriting a file cannot clear it (no file); a missing or damaged file no longer matters.

**Hub guard.** `WorkspaceOps::bind_local_session` now REQUIRES the session's one `PeerInfluence` and the hub session adopts it (`bind_peer_influence`, carries over a set state), whatever the creation order; the main spawn and the rebind after a model switch pass `tool_context.peer_influence`; a subagent's is its parent's. Test through `enforce_hub_policy` for a session and a subagent.

**Clear refusal.** Also refused while a peer turn is in flight (`PeerAdmissionState::peer_turn`, set when a peer input starts or joins a turn, reset when the turn ends); held and approved cases tested.

**Protected set.** Relocated home adds `personas roles prompts workflows`. `known_marketplaces.json` is covered only through the `plugins` directories (`.fuigo`, `.cursor`, `.claude`, relocated home); the audit log only as `<fuigo home>/peer-audit.jsonl[.1]`. Table test over every entry plus negatives.

**Tests.** Decision comparisons assert no timeout (`decide_live`); a plan row joins the mode table.

**Left for part B (stated plainly).** Shell-command writes to protected files AND to the session's own transcript files: until part B, an influenced model with shell access can tamper with stored history (including the markers). Also MCP and dynamic tools, change detection, classifier and hook payloads. Not done this round (time-boxed): a test through the full `spawn_session_actor` (the restore and the bind are each tested; the call sites are one line each), and a shell-level test of the plan-file auto-approve skip (the skip is in `tool_calls.rs`).

### Round 3 finisher (compiled and run on the build box, lane xs6a)
Compile fixes (stale code after the integration merge): six test callers of `bind_local_session` lacked the new `PeerInfluence` argument; `HookPayload::UserPromptSubmit` literals in `tool_dispatch.rs` and `hook_dispatch.rs` lacked the new fields (`origin`, `peer_sender`, `peer_claimed_mode`, `shell_command`); a test used the private `root_cwd` and an unimported `now_secs`. Test fix: `r3_clear_refused_for_held_approved_and_in_flight` needed `set_test_clock` (the held list is keyed on the test clock, as in the p4 tests). Clippy: two `from_ref` warnings in the new sampling-types test fixed. No existing non-peer test expectation was touched.

New tests: `r3_permission_handle_tool_context_and_hub_session_share_one_flag` (the production wiring `with_peer_influence` plus `bind_local_session` over the test actor's tool-context flag; each of the three sets it, the other two see it) and `r3_plan_file_auto_approve_is_skipped_when_peer_influenced` (plan file in a protected rules dir, hub flag deliberately unbound so only the permission-handle guard can stop the write: influenced leaves the plan untouched, not influenced still auto-approves and writes). `r3_restore_flag_off_does_nothing_and_text_never_counts` asserts: feature off with a stored `peer_message` restores not influenced; pasted wrapper text never counts; a subagent never restores (restore is a pure function over the loaded history, it has no write path).

Totals (after the last edit): workspace `permission` 1040 pass; shell `peer` 136; `permission` 104; `acp_session` 1413 (1 ignored); `session` 4427 (3 ignored); `extensions` 508 pass, 2 fail (the known `share_*_5m_early_invalidation_window` timing tests); sampling-types 330; hooks 297+11+1; pager `compaction history` 99; extra-ca all pass; auth `secret_debug_guard` 2. Clippy: no warnings in touched code (remaining ones are pre-existing in other files).

Still unverified: no test drives the full `spawn_session_actor` (the new shared-flag test covers the same wiring calls on the test actor, which is built by struct literal); the restore call site in `spawn_session_actor` is one line, covered only by the pure-function tests.

## Round 3 follow-up (clear-influence race, proxy bind)

**The rule** (comment at `clear_peer_influence`, `peer_admit.rs`): the outstanding-work check and the clear are ONE critical section with every path that can set the flag (admission, safe-point promotion and turn-start recheck all run under the session state lock). Under that lock: verify no peer work is outstanding (queued, held, approved, in-flight ring, running peer turn), put the cleared marker on the chat-state queue, clear the flag. Release the lock, then await the append ack. A failed append sets the flag again (fail closed) and the user is told.

1. Order as above. `/peers clear-influence` is now one call returning `PeerClear::{Cleared, Outstanding, NotRecorded}`.
2. Marker before later peer items: the marker command is SENT to the chat-state actor's single FIFO (`cmd_tx`) while the state lock is held (`push_user_message_and_ack` sends before its first await; the future is polled once under the lock, awaited for the ack after). Any later peer item is queued after a later admission or promotion, which needs that lock, onto the same FIFO, so it is stored after the marker; a resume says influenced. Verified by `p6a_peer_message_after_a_clear_reflags_and_is_stored_after_the_marker` (marker index < peer item index, `history_is_peer_influenced` true).
3. `has_undelivered` counts the in-flight ring: new `in_flight_live` counter (set by the start/promotion recheck, reset when the turn ends or the row is re-tracked), since the ring itself also serves duplicate detection.
4. Belt and braces: `remark_if_peer_turn()` at the tool-call permission point (`tool_calls.rs`, before the plan-file bypass and the `request`), one atomic read when no peer turn runs.
5. Proxy: a remote hub session lives in another process and cannot share the atomic. `bind_local_session` Proxy arm now calls `proxy_note_peer_influence` (warn log when influenced, never alters the flag). Sound because the shell-side permission handle, which holds THE flag, judges every edit before dispatch (`tool_calls.rs` `permissions.request`, `peer_guard_denial_for` ahead of `AllowAll`). `workspace_ops.rs` ~2005 is a test with a fresh flag and no peer; the `agent_ops`/subagent site (`subagent_spawn.rs:235`) passes the PARENT's flag. Own test: `p6a_proxy_bind_notes_but_never_alters_the_peer_influence_flag` (a `Proxy` cannot be built without a live hub connection, so the test covers the proxy arm's function).

**Red / green** (test `p6a_peer_row_promoted_during_the_marker_append_keeps_the_flag`, hook `set_clear_pause_hook` at the append await):
- RED on 746ab710 plus only the cfg(test) hook and the test (scratch commit 1e9b2482, not pushed): `peer_admit_tests.rs:1137:13: flag SET after the race` (test FAILED).
- GREEN on the fix: `p6a_peer_row_promoted_during_the_marker_append_keeps_the_flag ... ok`. Full package `cargo test --locked --no-fail-fast -p fuigo-shell` (empty netns): 0 failing tests; peer/permission/acp_session/session/workspace-permission/extra-ca/secret_debug_guard all pass; clippy: no warnings in touched files.

Other new tests: `p6a_clear_refused_while_the_in_flight_ring_holds_a_peer_message`, `p6a_marker_append_failure_leaves_the_flag_set`, `p6a_peer_started_turn_remarks_at_a_permission_request`. Existing tests adapted to the new return type (the forced clear in `opus2_*` and `s6_1_admission_*` now removes the queued peer row first).
