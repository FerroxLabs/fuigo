# Receipt R010 — P02a-R: exit 3 fired in both wrong directions, and the base had never been compiled

> **Numbering note:** written as R008 by the P02a-R agent and renumbered to **R010** by the
> integrator. Three packets were in flight and each independently claimed R008. R008 is the
> header-gate regression receipt (`strike/contracts` `815d3686`), R009 is P12b-R's tool-argument
> receipt. Nothing in this document depends on its number.


**Date:** 2026-09-30 · **Base:** `8e1172417a10` · **Branch:** `strike/p02ar` · **Box:** hetzner-dsm

P02a (`c43d96e`) gave a headless permission denial a dedicated exit code, `3`. A Phase 7 audit found
it fired wrongly in both directions and that the author's own tests pinned the wrong semantics. This
receipt records the reopen: what was actually wrong, what the code says rather than what the brief
said, and the A/B run.

## 1. The two false positives, and which one the brief got wrong

### 1.1 False positive on a crash — CONFIRMED, exactly as reported

`headless.rs` suppressed the mid-turn `Connection closed unexpectedly` bail whenever a denial was
latched, and `headless_run_outcome` put the denial ahead of both `flush_error` and the turn's own
error. So a crash, a `--timeout` and a `--max-turns` stop all exited `3` and printed the denial's
remedy — *"pre-approve it before the run"* — for something that was never the problem. The author's
own test pinned it (`Err("max turns reached") + denial → PermissionDenied`).

Contract D.2.1 asks for a code *"distinct from both success and a crash"*. That is symmetric: the
crash keeps its own code too.

### 1.2 False positive on success — REAL, but the brief's mechanism is REFUTED

The brief's example was `fuigo -p "summarise src/, and run cargo fmt if you can"`, where the model is
denied one tool, **adapts mid-turn, and succeeds**. **That cannot happen on this path.** Traced in
this tree:

```
handle_headless_acp_message answers acp::RequestPermissionOutcome::Cancelled
  -> PromptOutcome::Cancelled            fuigo-workspace/src/permission/prompter.rs:795
  -> Decision::Cancelled                 fuigo-workspace/src/permission/manager/mod.rs:2375, 2554
  -> ToolLoop::Cancelled                 fuigo-shell/src/session/acp_session_impl/tool_calls.rs:1775-1782
  -> return TurnOutcome::Cancelled { category: PermissionCancelled }
                                         fuigo-shell/src/session/acp_session_impl/turn.rs:3681-3688
```

`turn.rs` **returns** there. The denial is never fed back to the model, so the model never gets a
chance to route around it and finish. A denial answered through the ACP client always ends that turn.

The false positive on success is nonetheless real, by a different mechanism — one the code makes
certain rather than plausible: **the post-turn memory flush.** `run_single_turn` calls
`run_headless_memory_flush` only when the turn's outcome is already `Ok`, *after* the terminal
document has been emitted with `stopReason: end_turn`, and the flush drives the same
`handle_headless_acp_message`. A denial there is latched against a turn that succeeded. Anything else
that asks after the turn has ended (a background task; a subagent whose own turn was cancelled while
the parent's continued) lands in the same shape — not traced end to end here, so not claimed as
verified.

**So the defect stands and the brief's own example does not.** Believe the evidence.

### 1.3 The discriminator, which is better than the one the brief suggested

The brief proposed gating on "an unanswered tool call, or the turn's stop reason". The stop reason is
not enough: `StopReason::Cancelled` also covers `--max-turns`, a hook deny, a permission *reject* and
a mid-turn abort. `pending`/`completed` in `handle_headless_acp_message` track **background tasks**,
not tool calls, so the unanswered-tool-call route is not available cheaply either.

What *is* available is the shell's own positive statement:
`_meta.cancellationCategory == "PermissionCancelled"`
(`fuigo_shell::session::commands::PERMISSION_CANCELLED_CATEGORY`, `commands.rs:72,85`, pinned by
`commands.rs:905-940`). `emit_completed_response` already read that key for `--max-turns`; it now
returns a `TurnStop` and reports the category it found. Exit `3` fires only on
`TurnStop::PermissionCancelled`.

A useful side effect: on a blocked run the terminal document says `stopReason: cancelled`, so **stdout
and `$?` now agree**. Under P02a they contradicted each other — the success document plus exit 3.

## 2. Precedence, before and after

| # | P02a | P02a-R |
|---|---|---|
| 1 | dead stdout | dead stdout |
| 2 | **a denial** | memory-flush error |
| 3 | memory-flush error | the turn's own error |
| 4 | the turn's own outcome | a denial **that ended the run** |
| 5 | — | finished |

Plus one invariant that makes the narrower gate safe: **a latched denial always produces exactly one
line on stderr**, whatever the exit code turns out to be. `main` writes the fuller one (remedy plus
exit code) on the `PermissionDenied` arm; every other path — recovered, turn failed, flush failed —
writes the notice from `headless_run_outcome`. The single exception is a dead stdout, where the write
error is the louder fact, and a test states that rather than leaving it implied.

## 3. The run

```
receipt_id:   R010
packet:       P02a-R (reopen of P02a, c43d96e)
base:         8e1172417a10a76b879cd9affeff20edf7fc0dbd   (strike/integration HEAD)
fix:          78e457fbc6d1...                            (strike/p02ar)
lane:         /root/fuigo-builds/integration   (SHARED; its `src` held a sibling's uncommitted WIP,
              so this ran in the worktree `src-p02ar` sharing the lane CARGO_TARGET_DIR -- no new
              target dir. Every checkout+build+test block under flock .lane-integration.lock)
env_digest:   rustc 1.94.0 (4a4ef493e 2026-03-02)   [the repo's PINNED toolchain, per
              rust-toolchain.toml:11 -- NOT the box default 1.98.1]
              digest b75985398e5509a90a7d5d68f8ec6690675f703c5cfa11893b04fc9c3fceca69
              cargo 1.94.0 (85eff7c80 2026-01-15), RUST_MIN_STACK=16777216, hetzner-dsm
```

### 3.1 TOP-LINE: `8e11724` compiles, and it had never been compiled anywhere

Nobody had established this. It does. `cargo test --locked --no-fail-fast -p fuigo-pager` at
`8e1172417a10` ran **21 test binaries** and P02a's own denial tests all passed there. `-p
fuigo-pager-bin` is green at the base. So the reopen is a semantics fix, not a rescue.

### 3.2 The A/B pair — same lane, same command

| label | ref | command (verbatim) | cargo exit | failing set | binaries / results | log sha256 | UTC |
|---|---|---|---|---|---|---|---|
| base | `8e1172417` | `cargo test --locked --no-fail-fast -p fuigo-pager` | 101 | **18** | 21 / 21 | `e441293460d16cb813bb1760134bd12270f457676cadc9640be46cd74316ea0f` | 02:46:48 → 02:51:39 |
| fix | `78e457fbc` | `cargo test --locked --no-fail-fast -p fuigo-pager` | 101 | **19** | 22 / 22 | `73649bb0d5b2acaa6d2612358e0a457d7265f717524b56877d70f65c8b5181ae` | 02:51:39 → 02:54:14 |
| base | `8e1172417` | `cargo test --locked --no-fail-fast -p fuigo-pager-bin` | **0** | 0 | 3 / 3 | `79e9db78de9efd7dacb1c8f4d7181f1c04ae932c0d14ff843c75c12de824e6ab` | 02:54:14 → 02:59:00 |
| fix | `78e457fbc` | `cargo test --locked --no-fail-fast -p fuigo-pager-bin` | **0** | 0 | 3 / 3 | `b12ee87386e1bc8773a68969f0f590ee57bbc4b8373ac325f42ba21f3a6b139b` | 03:13:04 → 03:15:41 |

All 17 `headless::tests::permission_denial::*` tests pass at the fix, including the six new ones.

### 3.3 RED proof — the corrected semantics asserted against P02a's code

Two probes inserted into `8e1172417`'s own test module (working tree restored afterwards,
`restored_dirty=0`):

```
command:    cargo test --locked --no-fail-fast -p fuigo-pager --lib \
              headless::tests::permission_denial::red_probe
exit_code:  101
result:     FAILED. 0 passed; 2 failed
log_sha256: 7c15deeccbaf053087819025664412689b504f24caed2b039b08d94ebab7d6a5
timestamp:  2026-09-30T04:09:02Z
```

```
test ...::red_probe_a_crash_after_a_denial_is_still_a_crash ... FAILED
  a crash after a denial must keep exit 1, not be relabelled as a permission block

test ...::red_probe_a_denial_the_run_recovered_from_exits_zero ... FAILED
  assertion `left == right` failed: a denial the run did not end at must not produce the denial exit code
    left: PermissionDenied(HeadlessDenial { rule: HeadlessNeverApproves, tool_title: Some("Write src/main.rs"),
          tool_call_id: "tc-1", offered_option_kinds: ["reject_once"] })
   right: Finished
```

Both directions, red at the base. Their green counterparts at the fix are
`a_denial_the_run_recovered_from_exits_zero` and `a_crash_after_a_denial_is_still_a_crash`, which pass.
**They cannot be the same source**: the fix changes `headless_run_outcome`'s first parameter from
`Result<()>` to `Result<TurnStop>`. The assertions are identical in meaning; that is stated here rather
than hidden behind a "red/green" claim.

### 3.4 The process boundary — M15 closed

Nothing in the repo had ever spawned the binary and observed `3`. It does now.

```
command:    cargo build --locked -p fuigo-pager-bin --bin fuigo-pager            -> 0
command:    FUIGO_BINARY=<target/debug/fuigo-pager> cargo test --locked -p fuigo-pager \
              --test headless_denial_exit_code -- --ignored --test-threads=1 --nocapture
exit_code:  0
result:     ok. 2 passed; 0 failed        (~480 ms per spawned run, timed_out=false)
log_sha256: 090e25bbf4df82e359e14b5de56f81da32af07b2dc7198d479cadab7ea5018f0
```

| test | what it spawns | `$?` |
|---|---|---|
| `a_denied_headless_run_exits_three_and_says_why` | `fuigo -p … --trust --output-format json`, one scripted `search_replace` turn | **3** |
| `the_same_turn_approved_exits_zero` | the identical turn plus `--yolo` | **0** |

The denied run also asserts `headless_never_approves` on stderr and that stdout is still **exactly one
JSON value** carrying `permissionDenied.rule` / `.exitCode` and `stopReason: cancelled`. The pair is
what makes the `3` attributable to the denial rather than to anything in the fixture.

It uses `fuigo_test_support::run_headless` against `MockInferenceServer`, not the PTY harness. It is
`#[ignore]`d because the pager binary lives in another crate, so `CARGO_BIN_EXE_fuigo-pager` is unset
for `-p fuigo-pager` and `fuigo_binary()` would otherwise shell out to `cargo build` inside a test —
which on this project is a golden-rule hazard, not a convenience.

### 3.5 Clippy

```
command:    cargo clippy --locked -p fuigo-pager -p fuigo-pager-bin --all-targets
exit_code:  0        warnings: 31        errors: 0
log_sha256: afcafcc4037ab4da5bbf79221d940d3d1cd5740d9a0cc7a3f0060d8a77573901
```

**No new warnings.** Every `-->` location was checked against the diff. Not one is in `headless.rs`,
`tests/headless_denial_exit_code.rs`, or the code I changed. The only warning in a file I touched at all
is `headless_tests.rs:1028` (`called .err().expect() on a Result`), and those four lines are
**byte-identical at `8e11724`** — pre-existing.

### 3.6 Failing-set diff, and the one test I had to discriminate

| set | count | contents |
|---|---|---|
| my base, `-p fuigo-pager` | 18 | the `app::agent_view::paste` / `scrollback_paste_focus` family, in full — the known-unstable clipboard/paste population |
| HEAD's recorded set (`p09-base-fuigo-pager.failset`) | 20 | my 18, **plus** `app::edit_highlight_worker::tests::run_job_succeeds_on_temp_file` and `app::session_startup::tests::remote_miss_restore_code_**without**_worktree_errors` |
| my fix, `-p fuigo-pager` | 19 | my base 18, **plus** `app::session_startup::tests::remote_miss_restore_code_**with**_worktree_defers` |

So **my base 18 is a strict subset of HEAD's 20**, and the fix adds exactly one test that is not in
HEAD's recorded set. I am not going to hand-wave that. The discriminator:

```
command:    cargo test --locked --no-fail-fast -p fuigo-pager --lib app::session_startup::tests -- [--test-threads=1]
```

| run | ref | result | log sha256 |
|---|---|---|---|
| base, serial | `8e1172417` | **59 passed, 0 failed** | `423a0f7fa13a4773f5d830e22bc59934f7d16cc3d9e03ae24e5506b6cc1faad5` |
| fix, serial | `78e457fbc` | **59 passed, 0 failed** | `4cb97ca29a6d125e0f7acf6b0b82eef088c52b559f48ae45f6dfcb7ea6f1b347` |
| fix, parallel | `78e457fbc` | **59 passed, 0 failed** | `c56ddf79dab9d8bbb70d0c4fe1d6aa7146c5fcaa4e67d4ae4534986fe3cbf874` |

`remote_miss_restore_code_with_worktree_defers` **passes at the fix**, serially and in parallel, when the
module is run on its own. It fails only inside the whole `fuigo-pager --lib` binary. Three further facts:

1. My diff touches `headless.rs`, its test module, `docs/user-guide/14-headless-mode.md`, and one new
   test file. **Nothing in `app::session_startup`.**
2. Its sibling in the same module, `remote_miss_restore_code_**without**_worktree_errors`, is in HEAD's
   recorded 20 — so this pair already churns between runs at the integration base.
3. This exact test is independently recorded as failing at the integration base in packet **P16's**
   `p16-failset-pager-base.txt`.

**Verdict: inherited, order-dependent, and pre-existing — not caused by this packet.** It belongs to the
P20 flake population. I am reporting it as a strict-subset *miss* rather than claiming the criterion was
met, because it was not, literally.

### 3.7 Commit trail

`strike/p02ar`, five commits on `8e11724`:

| commit | what |
|---|---|
| `ba0601e7` | the gate itself: `TurnStop`, restored `Err` precedence, the crash bail un-suppressed, the `json` `permissionDenied` record, the two mis-pinned tests corrected, the counter-tests added |
| `e6a370a5` | `tests/headless_denial_exit_code.rs` — spawn the binary, read `$?` |
| `7fccccd2` | a latched denial is never silent, whatever the outcome (+ exhaustive test) |
| `a7f69a39` | docs: the two cases where exit 3 deliberately does not fire |
| `78e457fb` | docs/comments: name the recovered-denial case this tree actually verifies |

plus this receipt on top, which adds **only** `docs/strike/receipts/R010-…md`. So `78e457fbc6d1` is
the last commit that can change a build, and it is the one the gate ran. Nothing is merged to
`strike/integration` or `main`.

### 3.8 Housekeeping

The lane's own `src` was never touched (a sibling's uncommitted WIP lives there, and later a sibling
held `.lane-integration.lock` for ~40 minutes with a `-p fuigo-shell` run; this gate queued behind it as
intended). My worktree `/root/fuigo-builds/integration/src-p02ar` is **85 MB of source** and can be
removed with `git worktree remove`; the lane's shared `target/` was **not** deleted because siblings are
using it. Disk went 276 GB → 263 GB free (85%).

## 4. Counting: Contract A.2's two rules were not used

A.2 says to compare `binaries_run` with `result_lines` and count failures with
`grep -cE '^test .* FAILED$'`. Both are unreliable (per the brief). The failing **set** here is
derived from the `failures:` block:

```
awk '/^failures:$/{f=1;next} f&&/^ +[A-Za-z0-9_:]+$/{print $1} f&&/^$/{f=0}' "$LOG" | sort -u
```

The broken counters are printed alongside in `p02ar-gate.out` so the discrepancy is on the record
rather than trusted.

## 5. Two process failures of my own, recorded

1. **I recorded the wrong toolchain in the first script.** It ran `rustc --version` outside the source
   tree and got the box default, 1.98.1. `rust-toolchain.toml` pins **1.94.0**, which is what cargo
   actually used. R001 was retracted over an environment field; the digest is now taken from inside
   the source tree.
2. **`pkill -9 -f src-p02ar` voided a base run.** An orphaned `flock` holder from an earlier attempt
   still held the lane lock with a live cargo underneath; the broad pattern killed the *current* base
   build too, and it recorded `cargo_exit=` with `binaries_run=0`. Kill by **process group**
   (`setsid` gives the script its own PGID, so `kill -9 -<pgid>`) and verify with
   `fuser -v <lockfile>` before relaunching. The void run is not reported as evidence.

## 6. Packet proposals handed back

### P02h (NEW, verified here) — a **deny rule** in headless is still completely silent

Contract D.1 describes the defect as: *"the run continues, the model is told no, and nothing
distinguishes 'the work finished' from 'the work was blocked'."* **That is a literal description of the
deny-rule path, which neither P02a nor P02a-R touches.**

A `--deny-rules` / config deny never becomes an ACP permission request at all — it is decided inside
the shell:

```
deny rule matched (enforced before YOLO)   fuigo-workspace/src/permission/manager/mod.rs:1718-1725
  -> Decision::PolicyDeny(reason)
  -> ToolLoop::Continue                    fuigo-shell/src/session/acp_session_impl/tool_calls.rs:1741-1774
  -> the turn CONTINUES; the model is told "Tool `X` was not executed: <reason>"
```

`prompt_policy == Deny` takes the same path (`manager/mod.rs:2257-2262`), and a `pre_tool_use` hook
deny is the sibling case (`ToolLoop::HookDenied` → `Ok(…) => {}` → continue, `turn.rs:3680`).

Consequence: `handle_headless_acp_message` is never reached, so nothing is latched, **nothing goes to
stderr, there is no `permissionDenied` record, and the process exits `0`.** A CI job that hands Fuigo
a deny list gets exit 0 whether the work was done or refused — the original D.1 defect, untouched, in
the denial class operators are most likely to configure deliberately.

Recommendation: route `PolicyDeny` / `HookDenied` into the same `HeadlessDenial` latch from the tool-call
notification the pager already receives, with new `HeadlessDenialRule` variants (`deny_rule_matched`,
`prompt_policy_deny`, `hook_denied`). Note the exit code question is genuinely different here: these
denials do **not** end the turn, so by P02a-R's own gate they must exit `0` with a stderr notice and a
record — which is the right answer, and is exactly what the (Some(denial), TurnStop::Ended) arm already
does. So the packet is mostly plumbing, not new policy.

### P02b (NARROWED) — only the two streaming reducers remain

D.2.2 is now met on `--output-format json`: the terminal document carries a `permissionDenied` object.
It is an additive conditional field, like `thought`/`usage`/`error`, so the document is still exactly
one JSON value — no consumer that does a single `parse` breaks.

`stream-json` and `stream-json-messages` build their terminal line in `headless::reducer`
(`reducer/mod.rs` `Lifecycle`/`StreamEvent`, `reducer/acp.rs`, `reducer/messages/mod.rs`), which this
packet does not own — the brief scoped it to `headless.rs`. Emitting a hand-rolled NDJSON line from
`headless.rs` instead was rejected deliberately: those streams have typed envelopes, and adding an
unmodelled line type to them is a Contract E wire-schema question, not a local fix.

So P02b is now **one decision, not a gap**: is a new NDJSON event type on the streaming formats a
Contract E break? Not something to answer unilaterally.

### P02g (NARROWED) — the process-boundary matrix is half done

`fuigo-pager/tests/headless_denial_exit_code.rs` now spawns the real binary through
`fuigo_test_support::run_headless` against `MockInferenceServer` and reads `$?`: one scripted
`search_replace` turn, run twice, differing only in `--yolo` — refused exits `3`, approved exits `0`.
The PTY/mock-inference harness P02g was scoped around is **not** needed for that; `run_headless` is.

What remains for P02g: the **recovered-denial** case at the process boundary (exit `0` with the stderr
notice), which needs the mock to drive a denial *after* the turn ends — a memory-flush or background-task
script, not a plain foreground turn. Also worth noting for whoever picks it up: `run_headless` is used
today by exactly one `#[ignore]`d test, so the real-binary-through-mock path is barely exercised.

### P02e — unchanged, but its shape is now clear

The budget guard returns an `io::Error` out of `admit_attempt` and never becomes a permission request,
so it cannot reach the denial latch. Contract D.4 says budget denials *"use the same reporting contract
as D.2"*, which is unmet. P02a-R makes the fix shape explicit: route the budget denial so the turn ends
with a cancellation **category** (a new one, or `PermissionCancelled`), and latch a `HeadlessDenial` for
it. Then the gate added here catches it with no further change to the exit path.

### P02f — unchanged

A tokio-runtime startup failure and a run failure both exit `1`. Not touched. Note that exit `2`
(managed-policy requirement, `main.rs:2021-2028`) was **also undocumented** and is now in the table, so
the doc no longer implies `1` is the only failure code.

### P02i (NEW) — a foreign agent that does not stamp `cancellationCategory` will not exit 3

The gate reads `_meta.cancellationCategory`. The shell shipped in this binary always stamps it, and a
test pins the constant against the shell that writes it. A **foreign** agent (1.0.23 external-agent
mode) may not. Then a denial exits `0` — with the stderr notice and, on `json`, the record, so it is not
silent, but the dedicated code does not fire. That is a precondition to state in the 1.0.23 work
alongside S4's, not a defect in this packet.
