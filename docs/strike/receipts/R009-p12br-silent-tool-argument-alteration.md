# Receipt R009 — P12b could execute a tool with silently altered arguments. Reproduced, then fixed.

**Date:** 2026-09-30 · **Box:** hetzner-dsm · **Lane:** `/root/fuigo-builds/integration` (shared, held
under `flock /root/fuigo-builds/.lane-integration.lock` for the whole run) · **Packet:** P12b-R,
reopening landed P12b (`74b0941`).

> Receipt-number collision warning: three packets were in flight when this was written. If a sibling
> renumbered to R009 by the integrator: R008 was already taken by the header-gate regression receipt (strike/contracts 815d3686), which this packet does not depend on.

## 1. The finding, reproduced rather than argued

The Phase 7 audit said P12b could finalize a tool call out of an argument stream with a fragment
silently missing. It can. Here is the product doing it, from the A-side log
(`p12br2-A-fuigo-sampler.log`), unedited:

```
---- stream::messages::tests::mid_sequence_unmodelled_delta_on_a_tool_use_block_fails_the_turn stdout ----
thread '...' panicked at crates/codegen/fuigo-sampler/src/stream/messages_tests.rs:887:13:
the turn completed with tool_calls [ToolCall { id: "call_edit", name: "Edit",
arguments: "{\"a\":1,\"c\":3}" }] after a delta was silently dropped from the middle of its
arguments; `{"a":1,"c":3}` is valid JSON missing a parameter the model sent, and executing it is
the whole defect
```

A tool named `Edit`, a completed turn, `StopReason::ToolCalls`, and arguments that are **not what the
model sent**. `{"a":1,` + ⟨dropped⟩ + `"c":3}` concatenates to `{"a":1,"c":3}`: syntactically valid
JSON, one parameter gone, no error anywhere. The mechanism is exactly as the audit described —
`messages.rs` dropped an `Open::Unknown` delta while the block state survived, so `content_block_stop`
built the `ToolCall` from whatever fragments happened to remain.

The **mid-sequence** position is what makes it silent. A trailing drop leaves invalid JSON, which is
loud at the tool boundary. Correctness cannot rest on where the provider chunked, so both now fail.

## 2. The A/B pair

Both sides ran in the same lane, under the same lock, with the same commands, back to back. The two
commits differ **only in non-test source**: `messages_tests.rs` is byte-identical at A and B
(`git diff --quiet A B -- .../messages_tests.rs` → clean). The tests are therefore the only controlled
variable, which is what R007 asked for and what the first draft of this run did not have.

```
commit:     37df1a3e53591292823ed591cb30ce894a160b6a   (A: 8e11724 + the tests, NO fix)
command:    cargo test --locked --no-fail-fast -p fuigo-sampling-types
exit_code:  101
log_digest: 56bf276b08e530eee7788d58a606f1fbb7e9cc02a30d35652deeb86a0149332e
timestamp:  2026-09-30T02:33:24Z
env_digest: rustc 1.94.0 (4a4ef493e 2026-03-02) / cargo 1.94.0 (85eff7c80 2026-01-15) / RUST_MIN_STACK=16777216

commit:     37df1a3e53591292823ed591cb30ce894a160b6a   (A)
command:    cargo test --locked --no-fail-fast -p fuigo-sampler
exit_code:  101
log_digest: d5e1336641725f4f338f0136a89e7aab1d3d1ffdeff539e94c851e9f9aeb6ac7
timestamp:  2026-09-30T02:33:24Z
env_digest: as above

commit:     985cdee132766e4dde8a1e77f7232fcdef088d6b   (B: A + the fix)
command:    cargo test --locked --no-fail-fast -p fuigo-sampling-types
exit_code:  0
log_digest: 2c21d378906f6104dc7c949d1613e8fd10ec8308f8d4348ec272b90f8a0edf45
timestamp:  2026-09-30T02:34:40Z
env_digest: as above

commit:     985cdee132766e4dde8a1e77f7232fcdef088d6b   (B)
command:    cargo test --locked --no-fail-fast -p fuigo-sampler
exit_code:  0
log_digest: 8cd187b32fbef92a49d522264192c091bc15ffd08baa150e940af6028a232d32
timestamp:  2026-09-30T02:34:40Z
env_digest: as above
```

Failing sets, derived from each log's `failures:` block — **not** from
`grep -cE '^test .* FAILED$'` and **not** from `binaries_run` vs `result_lines`, both of which this
strike has established are unreliable on this box:

```
awk '/^failures:$/{f=1;next} f&&/^ +[A-Za-z0-9_:]+$/{print $1} f&&/^$/{f=0}' "$LOG" | sort -u
```

| side | `-p fuigo-sampling-types` | `-p fuigo-sampler` |
|---|---|---|
| **A** (no fix) | 1 | 4 |
| **B** (fix) | **0** | **0** |

A's failing set, in full:

```
conversation::tests::unmodelled_token_limit_finish_reasons_normalize_to_length
stream::messages::tests::mid_sequence_unmodelled_delta_on_a_tool_use_block_fails_the_turn
stream::messages::tests::trailing_unmodelled_delta_on_a_tool_use_block_also_fails_the_turn
stream::messages::tests::an_untagged_unknown_delta_on_a_tool_use_block_still_fails_the_turn
stream::messages::tests::unmodelled_token_limit_stop_reason_maps_to_length
```

Every one of the five is a test of a defect, and every one passes at B. The four *tolerance* tests
added alongside them (a dropped delta on a text block, a dropped delta on an index no block opened,
one block's drop not poisoning another block's tool call, and the non-length unknown values still
falling back to `Stop`) pass on **both** sides — they exist to catch an over-firing fix, and they
confirm the fix does not over-fire.

## 3. Clippy — no new warnings, measured on both sides

```
commit:     37df1a3e (A) / 985cdee1 (B)
command:    cargo clippy --locked --all-targets -p fuigo-sampling-types -p fuigo-sampler
exit_code:  0 (both)
log_digest: A 3a8f0cd3e180dccfa3c3a933ced71c73454afc36bafb1c87980394b7ddcbb995
            B 7607cb2b9e6993af57b0dffe02dd68741b922dd9c0e81d76d6e5ae833cc5f6d3
timestamp:  2026-09-30T02:33Z / 02:34Z
env_digest: as above
```

14 warning lines on each side, and `diff` of the sorted warning texts is **empty** — the two logs
carry the identical warning set. All 14 are pre-existing and in code this packet does not touch
(`gcloud-auth`, the `fuigo-tools` build script, a `fuigo-sampler` example, an unrelated
`reqwest::Client::new`). The fix adds none. Counting warnings on one side only would not have
established this, which is why both sides were run.

## 4. What was changed

| file | change |
|---|---|
| `fuigo-sampler/src/stream/messages.rs` | `BlockState.dropped_unknown_delta`; record the drop on the block; `ToolUse` finalize refuses, `Text`/`Thinking` tolerate; length-alias arm on `messages::StopReason::Unknown` |
| `fuigo-sampling-types/src/types.rs` | `is_length_stop_alias` — one shared recognizer for the token-limit family |
| `fuigo-sampling-types/src/conversation.rs` | `FinishReason::Unknown` naming a token limit maps to `Length`, not `Stop` |
| `fuigo-sampling-types/src/serde_helpers.rs` | `Open::deserialize` tries the modelled parse first; the tag probe moves to the failure path |
| `fuigo-sampler/src/stream/messages_tests.rs` | the tests above |

**The asymmetry is deliberate and is the design decision of this packet.** A `ToolUse` block that lost
a delta fails the turn; a `Text` or `Thinking` block that lost one does not. Nothing executes prose:
the hole is a visible gap the log already warns about, and killing a complete, already-billed response
over cosmetic drift is precisely the harm P12b was written to prevent. A hole in tool arguments changes
what a program *does*, invisibly. Only the second is worth a dead turn.

**The forward-compatibility boundary was not loosened to close this.** `Open<T>` still fails closed on
a corrupt modelled body, `unknown_tag` still probes the tag alone so the decision stays at exactly one
level, and no tolerance was widened. The audit found this boundary sound; the gap was a semantic one
*above* it, and that is where it was fixed.

The error is `SamplingError::serialization_message(...)` — the same non-retryable `Serialization`
classification the pre-P12b abort had, because resending cannot un-drop a delta. It names the
unmodelled type and the tool, so the next incident is diagnosable from the log alone; "no diagnostic
at all" is what the packet's own design note calls strictly worse than a loud abort.

## 5. Three claims in the brief that the evidence contradicts

**1. `8e11724` builds.** The brief said "nobody has compiled `8e11724` anywhere, so you may be the
first to find out whether it builds at all." It builds. The A side is `8e11724` plus test files and it
compiled and ran 321 passing `fuigo-sampler` lib tests before reaching its 4 failures. Corollaries,
both of which the brief asked to be verified and both of which are settled by that compile:

  * **`FinishReason` losing `Copy` has no unfixed call sites.** P12b already adapted the only one that
    needed it (`session_compact.rs:611`, `choice.finish_reason.clone()`); `chat_completions.rs:141`
    moves out of an owned `choice`.
  * **The serde requirement was already met, twice over.** `Cargo.lock` pins serde **1.0.228**, well
    past the 1.0.181 that `#[serde(untagged)]`-on-a-variant needs. More decisively, the identical
    attribute is already on `messages::StopReason::Unknown` in the `2eb306e` baseline that shipped as
    v1.0.20 — so the feature was in production before P12b was written.

**2. The brief's file paths for `serde_helpers.rs` are wrong.** It cites
`crates/codegen/fuigo-sampler/src/stream/serde_helpers.rs:34-37` and `:45-47` and `:137-151`. That file
does not exist. The module is `crates/codegen/fuigo-sampling-types/src/serde_helpers.rs`; the design
note is at `:34-37` there, `is_unknown_variant` at `:45-47`, `Open::deserialize` at `:137-151`. The
line numbers were right, the crate was not.

**3. Half of M5 is not a P12b regression.** The brief frames the unmodelled-stop-reason defect as
P12b's, and for `FinishReason` it is: the baseline had a closed enum, so an unknown value aborted —
wrong, but loud — and P12b turned it into a silent `Stop`. But `messages::StopReason::Unknown` with the
same `#[serde(untagged)]` catch-all and the same `=> StopReason::Stop` mapping is **already in
`2eb306e`** (`messages.rs:236-240` and `messages.rs:413-419` at that commit). The Messages half is a
pre-existing silent-wrong shipped in v1.0.20, not a reopen finding. Both are fixed here because both
are one line through the same recognizer, but the provenance matters for the audit ledger.

## 6. What could not be verified, stated plainly

* **M21 was fixed, not measured.** The success path drops from three passes to two, with no clone, and
  the `json!({"type": …})` allocation and probe parse leave the hot path entirely. That the reorder is
  semantically identical is argued from the type system (an internally-tagged enum whose tag names no
  variant cannot parse, so every input the probe would have called unknown still reaches the probe) and
  is covered by the pre-existing hostile-shape tests, which pass. But **no benchmark was run, on either
  version.** The audit's "hottest loop in the product" is a plausible inference, not a measurement, and
  so is any claim that this reorder is a visible win. See packet proposal P-3.
* **`cargo fmt --all -- --check` cannot be used as a gate on this tree.** It exits 1 at `8e11724` with
  **381 dirty files**. Of the hunks inside the five files this packet touches, all but two were
  pre-existing drift; those two were mine and are fixed. No claim of "fmt clean" is made, because the
  repo is not. See packet proposal P-4.
* **The M6 guard is still prose-matching.** `is_unknown_variant` matches the substring
  `unknown variant` in serde_json's rendered error. serde exposes no structural way to ask "did this
  fail because the tag names no variant", so the dependency stays. What is new is an alarm: a canary
  test pins **both** directions — the unknown-variant wording that must be recognized and the
  missing-field wording that must not be mistaken for it — and fails with an explanation naming the
  consequence. It fails closed if serde reworders, so it is not a corruption risk; it is now also not
  a silent one.

## 7. Wider run — and criterion 3 cannot be met as written

Run in the same lane, BASE (`8e11724`) then B, same command each side. `fuigo-shell` additionally takes
`flock /root/fuigo-builds/.shell-test.lock`, so it serializes against the sibling packets' shell runs.
`env_digest` for every row: `rustc 1.94.0 (4a4ef493e 2026-03-02) / cargo 1.94.0 (85eff7c80 2026-01-15) /
RUST_MIN_STACK=16777216`. Failing sets from each log's `failures:` block, as in §2.

| package | BASE `8e11724` | B `985cdee1` | verdict |
|---|---|---|---|
| `-p fuigo-sampling-types` | — (see §2: A 1, B 0) | **0** | green |
| `-p fuigo-sampler` | — (see §2: A 4, B 0) | **0** | green |
| `-p fuigo-agent` | 1 | **0** | strict subset |
| `-p fuigo-shell-base` | 0 | **0** | equal, both green |
| `-p fuigo-shell` | 17 | **20** | **NOT a subset — see below** |

```
commit: 8e1172417a10a76b879cd9affeff20edf7fc0dbd (BASE)   commit: 985cdee132766e4dde8a1e77f7232fcdef088d6b (B)
  cargo test --locked --no-fail-fast -p fuigo-agent         cargo test --locked --no-fail-fast -p fuigo-agent
  exit_code:  101                                           exit_code:  0
  log_digest: 16b3b7751fec00edab398df6e2d0fff3b50b7ea6b90c32771cd70f1c07694418
              598ed215670c42925b341c4cc721a12fed84bbe76a9db1109da4dac4502631ed
  BASE's one failure: prompt::skills::discovery_budget_tests::an_overrun_scan_still_populates_the_cache_for_the_next_session

  cargo test --locked --no-fail-fast -p fuigo-shell-base    (same command at B)
  exit 0 / 7a1ebf49b2863a04b1f17109a36dd1dfc8252a548f54b1643ee4164226a1e7e2
  exit 0 / 7abc10c5861c6ccae9144382e2d5e6b1fe1ccb028f410440ff76bc891d307aa6

  cargo test --locked --no-fail-fast -p fuigo-shell         (same command at B, both under .shell-test.lock)
  exit 101, 17 failing / 121ff0af26c37224d5c1b5743f85810e4f1912cc0995642081f2483a6d5dc4ae   (BASE, 2026-09-30T02:41Z)
  exit 101, 20 failing / 1e0f48aa90227268bd47143442e89c24655bade592db4fb29ef3833bb82ca843   (B,    2026-09-30T03:13Z)
```

### `-p fuigo-shell` is not a strict subset, and saying so is the finding

BASE 17, B 20, 15 shared. Five entries are B-only and two are BASE-only — the set churns in **both**
directions, which is not what a regression looks like. But "it churns, so it's flaky" is precisely the
move R007 §5 named as this strike's recurring failure: stop at the first explanation that fits. So here
is the discriminating measurement instead.

**Two independent full runs of the SAME commit `8e11724`** — the `p09` recording
(`/root/fuigo-builds/p09-base-fuigo-shell.failset`, 16 failures) and this receipt's BASE run (17) —
share 14 entries and differ by **5**:

```
in p09 only:      agent::config::tests::configured_endpoints_become_the_trusted_origins
                  session::storage::jsonl::worktree_heal_tests::list_sessions_heal_does_not_evict_recent_sessions_from_mtime_window
in this BASE only: inspect::tests::describe_requirements_file_flags_invalid_version_overrides_as_parse_error
                  session::storage::jsonl::copy::tests::explicit_subagent_fork_kind_wins_over_worktree_target_cwd
                  session::storage::jsonl::worktree_heal_tests::init_session_load_backfills_worktree_identity_on_untagged_summary
```

| comparison | commits | symmetric difference |
|---|---|---|
| p09 run vs this BASE run | **same** (`8e11724`) | **5** |
| this BASE run vs B | different | **7** |

**The suite's run-to-run variance at a fixed commit is 5. The difference this packet makes is 7.** The
effect being measured is smaller than the instrument's noise. `-p fuigo-shell` therefore **cannot**
deliver "a failing set that is a strict subset of HEAD's" for this packet or any other on this box —
not because the packet is bad, but because the criterion is not satisfiable by this suite. Any packet
that reports a clean subset here got a lucky draw, not a result. See proposal P-5.

Three further checks, none of which rests on the churn argument:

1. **One of the five B-only tests flips at a fixed commit.**
   `agent::config::tests::configured_endpoints_become_the_trusted_origins` is the first line of the
   `p09` failing set at `8e11724` and **passes** in this receipt's BASE run at the same `8e11724`. A
   test that fails and passes at one commit cannot be attributed to a diff.
2. **Three of the five pass at BASE in serial isolation.** Re-run one per `cargo test` invocation with
   `--exact --test-threads=1` under the shell lock, at `8e11724`
   (`/root/fuigo-builds/p12br-discriminate.out`):
   ```
   BASE exit=0 ran=1 test result: ok  agent::config::tests::configured_endpoints_become_the_trusted_origins
   BASE exit=0 ran=1 test result: ok  auth::manager::lock::tests::dropping_the_guard_silences_the_heartbeat_before_anyone_else_can_hold_the_lock
   BASE exit=0 ran=1 test result: ok  session::storage::jsonl::worktree_heal_tests::list_sessions_fills_missing_label_on_kinded_fork_without_changing_kind
   ```
   The remaining two (`session::worktree::tests::cleanup_worktree_on_failure_removes_created_worktree`,
   `session::worktree::tests::create_worktree_for_resume_produces_independent_worktree`) were **not
   run**. The run sat 17 minutes holding the lane lock while queued behind two sibling packets on
   `.shell-test.lock`, which is a priority inversion this packet was causing, so it was terminated to
   free the lane. That is an unfinished check and is recorded as unfinished, not inferred.
3. **None of the five reaches any symbol this packet changed.** `grep` for
   `is_length_stop_alias`, `dropped_unknown_delta`, `stream_messages` and `Open<` across
   `fuigo-shell/src/session/worktree*`, `fuigo-shell/src/agent/config.rs` and
   `fuigo-shell/src/auth/manager/` returns nothing. The only `fuigo-shell` code that touches this
   packet's surface is `session/helpers/session_compact.rs`, whose tests are not in either failing set.

**Honest summary of the shell result:** no evidence connects any of the five to this packet, and three
independent lines of evidence point away from it — but the strict-subset property the brief asked for is
**not** demonstrated, and on this suite it is not demonstrable. Two of the five isolation checks remain
un-run.

The `fuigo-agent` failure is present **at the integration base, before this packet**, so it is inherited
and B is a strict subset there. Establishing that required running BASE in the same lane rather than
trusting a stored number — the mistake R005 made and R007 retracted.

## 8. Two things about the shared lane, for whoever reads this next

* **A sibling gate is running inside the shared lane `src` without the lane lock.**
  **[REFUTED by the integrator, 2026-09-30 — see the annotation at the end of this section.]** At 02:45
  `p15r-gate.sh` was executing `cargo test --locked --no-run -p fuigo-shell -p fuigo-extra-ca -p
  fuigo-sampler` in `/root/fuigo-builds/integration/src` while this packet held
  `.lane-integration.lock` and had that checkout at `985cdee1`. It was therefore **compiling this
  packet's commit**, not its own. `p02ar-gate.sh` does it correctly: its own `src-p02ar` checkout *and*
  the lane lock. Nothing was done to the sibling's processes; it is flagged because its results may not
  be about its own packet.

  > **Integrator annotation — this claim is wrong, and the timeline refutes it.**
  > `p15r-gate.sh` sets `SRC=$LANE/src-p15r`, its own private checkout, and ran there. The
  > discriminating evidence is file times on the box: `integration/src-p15r` was created at
  > **02:35:55Z**, and `p15r-gate.sh` was written at **02:41:01Z** — six minutes *later* — with an
  > mtime unchanged since, so the version running at 02:45 is the version that exists now and it
  > already pointed at the private checkout. P15-R's own run provenance confirms it independently:
  > `p15r-fix.out:1` stamps `src=/root/fuigo-builds/integration/src-p15r`.
  >
  > **Second annotation, correcting the first.** P15-R's own report (04:5xZ) supplies the piece I
  > was missing, and my "likely origin: `ps` hides the cwd" guess was wrong. What actually happened
  > is a genuine collision with the direction reversed:
  >
  > * **This packet was the one using the lane's shared `src`** — at its own commit `985cdee1`.
  >   P15-R independently reports the same thing from the other side.
  > * **P15-R did touch that shared checkout, at 02:31** — its locked run's checkout failed, and a
  >   manual `git checkout 8e11724` moved this packet's HEAD. It restored `985cdee13` within about
  >   90 seconds and then created `src-p15r` (02:35:55Z) and never left it.
  > * So the 02:45 observation above misattributes a real 02:31 event to the wrong script and the
  >   wrong minute. `p15r-gate.sh` (written 02:41:01Z, mtime unchanged) never used the shared `src`.
  >
  > Both packets' evidence survives — P15-R's because every run is provenance-stamped to
  > `src-p15r`, this packet's because its receipted runs postdate the window — but **this packet's
  > "first wider run was killed externally" is very likely the same collision**, not an unexplained
  > kill. `p02ar-gate.sh` was correct throughout: own `src-p02ar` plus the lane lock.
  >
  > Recorded at length because the integrator (me) then made the same class of error while
  > correcting it: I declared the claim refuted on evidence that established where one script ran,
  > which is not the same question as whether the two packets collided. Evidence that fits, again,
  > instead of evidence that discriminates — fourth instance in this strike.
  >
  > What remains true and worth acting on: all three packets share one `CARGO_TARGET_DIR`, so they
  > serialize on cargo's build lock and pay rebuild churn against each other. That is a throughput
  > cost, not a correctness one. Exclusive lanes would be better when disk allows.
* **This packet's first wider run was killed externally.** `p12br-ab3.sh`'s process group vanished after
  B's `fuigo-agent` log had completed cleanly, with no OOM in `dmesg` and 210 GB of RAM available. The
  two remaining packages were re-run by `p12br-shellb.sh`; B's `fuigo-agent` failing set was derived
  from the log the killed run had already finished writing. Cause unknown — most likely a broad `pkill`
  from another session.
* **The lane target dir is 164 GB and the box is at 84%.** Not deleted: two sibling packets were still
  building in it. Whoever finishes last should remove `/root/fuigo-builds/integration/target`.
