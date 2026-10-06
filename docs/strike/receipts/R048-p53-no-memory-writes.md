# R048 — P53: does `--no-memory` stop memory WRITES?

**Packet:** P53 (`strike/p53`). **Parent:** `45bd14ee6a0b2fecc57b844aa758a831c69051d2` (integration HEAD).
**Gated tip:** `d7c4a14bf0e396abf97f76d26ed21783542f7b2f`. The receipt commit follows it and touches only this file
and `docs/strike/audits/P53-astra.txt`. **Not landed.** The coordinator lands.
**Host:** `hetzner-dsm`, lane `/root/fuigo-builds/p53/`, `slot-run.sh p53`, `CARGO_BUILD_JOBS=16`,
`RUST_MIN_STACK=16777216 RG_BIN_PATH=/usr/bin/rg CARGO_TERM_COLOR=never`, builds under `nice -n 10`.
Toolchain read inside the tree: `rustc 1.94.0 (4a4ef493e 2026-03-02)`, digest
`b75985398e5509a90a7d5d68f8ec6690675f703c5cfa11893b04fc9c3fceca69` (`rustc -vV | sha256sum`).

## 0. Answer, and what is NOT met (read first)

**The brief's premise was wrong, and the evidence says so.** The brief expected that everything probably
already honours `--no-memory` and the packet would be "the test plus the evidence table". That held for the
core memory machinery: every write path that goes through the session's memory store is already gated by one
`Option`. It did **not** hold for three things that are memory-shaped but sit outside that store. Each wrote
or exposed memory under `--no-memory`, and each is now fixed with a mutant:

| # | Path | Before | Fix | Mutant |
|---|------|--------|-----|--------|
| F1 | process-memory trace, `$FUIGO_HOME/memtrace/*.jsonl` (`fuigo-pager-bin/src/main.rs`) | started unconditionally, one sample file per process every 30 s, whatever the flag | `memory_trace_wanted(Some(false)) == false`; no env var turns it back on | M3, M3u |
| F2 | per-turn `memory.tar.gz` upload (`fuigo-shell/src/upload/memory.rs`) | built from `~/.fuigo/memory` and uploaded whenever the session registry was on, whatever the flag | `PromptTraceContext.memory_enabled`, skip reason `memory_disabled` | M4, M5 |
| F3 | subagent agent-memory (`fuigo-shell/src/agent/subagent/handle_request.rs`) | a subagent whose definition says `memory: user\|project\|local` got `memory_search`/`memory_get`, the agent's `MEMORY.md` injected into its prompt, and an agent-memory store, even with the parent's memory off | the scope is ignored when the parent has no memory config | M6 |

What is **not** met, or not proven:

1. **F2 is not covered end to end.** The `memory.tar.gz` leg needs a session registry, which needs first-party
   OIDC auth (`agent_ops.rs:604-610`, `auth/model.rs` `is_fuigo_auth` is `false` for `AuthMode::ApiKey`). The
   harness authenticates with an API key, so the hostile test cannot reach it. Coverage is two unit tests
   (the decision function, and the `get_trace_context` wiring) and mutants M4 and M5. This is a documented gap.
2. **Four things are covered by code trace only**, because the harness cannot reach them (header of
   `no_memory_writes_acp.rs` says the same): (a) the 30 s startup dream timer (`run_loop.rs:468`; the explicit
   `/dream` reaches the same code); (b) config hot reload in leader mode, where the watcher lives (Murage runs
   `--no-leader`); (c) embeddings: the provider is only given credentials for a first-party base URL
   (`auth/credential_provider.rs:120`), so no embedding request is sent against the loopback mock, with or
   without the flag; (d) jemalloc heap profiles, which are RSS dumps, not conversational memory.
3. **The detector reads persistent end state**, not every syscall: a file created and deleted inside a
   directory that was itself created and deleted in between is not seen. Directory mtimes catch the ordinary
   create-and-delete case. Linux was the only host. Windows paths are normalised to `/` but never ran.
4. **The parent run used the tip's `fuigo` binary.** `FUIGO_BINARY` was set once for the whole gate, to a build of
   `12815476` (sha256 `504e7d56…`); `d7c4a14` differs from it only in a `tests/` file, so the product is the same.
   The parent's suites do not contain the P53 tests. Parent failing set was empty anyway.
5. **No third control run at `2eb306e`.** Parent and tip both have an empty failing set on both packages, so
   `tip ⊆ baseline` holds for any baseline by emptiness. I did not spend a run on it.
6. **The Astra audit was a source read**, not an execution (`--sandbox read-only`). Its last round says so.

Residual `--no-memory` behaviours I found and did **not** change (they are not file writes, or are outside
this packet's ownership), listed as proposals in §7.

## 1. The write-path trace

Method: `grep -rn` over `crates/` for every constructor and writer of the memory store
(`MemoryStorage::new`, `MemoryIndex::open_or_create`, `write_daily_log`, `ensure_initialized`, `DreamLock::new`,
`MemoryFileWatcher::start_scoped`, `.gc(`, `memory_trace::start`, the `fuigo/memory/*` extension methods, the
`memory.tar.gz` builder), cross-checked against `grep -rniE "no_memory|memory_enabled_override"`. Positive
control for the grep tool itself: it returned the known `memory_enabled_override` plumbing in
`fuigo-pager/src/app/cli.rs:846`, `agent/config.rs:2610`, `reloader.rs:80` (the macOS `rg` here is a wrapper that
exits silently, so every zero-result search used `grep`, which printed hits first).

The spine. `--no-memory` becomes `memory_enabled_override = Some(false)` (`fuigo-pager/src/app/cli.rs:846`),
which beats `FUIGO_MEMORY`, config and remote settings in `MemoryConfig::resolve_settings`
(`fuigo-config-types/src/memory.rs:623`, `BoolFlag::env(..).cli(override)`), so `MemoryConfig.enabled == false`.
Then `agent/config.rs:2612` and `agent_ops.rs:484` turn that into `memory_config: None`, and
`spawn.rs:867` builds `memory_storage_for_session` only from `Some` and `enabled`. `SessionMemory::is_enabled()`
is `storage.is_some()` (`memory_state.rs:49`). Everything below hangs off that `Option<MemoryStorage>`.

| Write path | Where | Honours `--no-memory`? | Evidence |
|---|---|---|---|
| memory store dirs, templates, `MEMORY.md`, `index.sqlite` | `spawn.rs:890` `ensure_initialized` | yes | only inside `if let Some(storage) = memory_storage_for_session` (`spawn.rs:887`) |
| memory garbage collection (deletes orphan workspace dirs) | `spawn.rs:903` `gc_storage.gc` | yes | same block; control deleted the planted `tmp-p53-orphan`, subject left it |
| file watcher / reindex claims | `spawn.rs:928` | yes | same block |
| startup reindex and embedding | `spawn.rs:2172` `if let Some(storage) = session.memory.storage()` | yes | `None` under the flag |
| compaction `memory_flush` | `compaction.rs:512` `memory_flush_enabled`, then `run_memory_flush` | yes, twice | `spawn.rs:849` is `memory_config.is_some_and(flush.enabled)`; and `run_memory_flush` returns at `memory_dream.rs:572` without storage |
| idle flush | `run_loop.rs:482` | yes | arm guard `session.memory.is_enabled()`; also `idle_flush_timeout` is `None` (`spawn.rs:1926`) |
| dream / consolidation (timer) | `run_loop.rs:513`, `maybe_run_dream` | yes | arm guard `is_enabled()`; `dream_context()` returns on `storage()?` (`memory_dream.rs:176`); `dream_check_timeout` `None` (`spawn.rs:1930`) |
| `/flush`, `/dream`, `fuigo/memory/flush` | `slash_exec.rs:51`, `:68`, `run_loop.rs:1167` | yes | each checks `is_enabled()`; the ext method answers `invalid_request` |
| `/memory on` (re-enable) | `slash_exec.rs:808` | yes | needs `backend_params`, which is `None`; answers "Memory cannot be enabled" |
| session-end save | `memory_dream.rs:104,119` | yes | `if let Some(storage) = self.memory.storage()` |
| first-turn memory injection and compaction recovery search | `turn.rs:2062`, `compaction.rs:1625` | yes (reads, but would index) | both need `storage` and `backend_params` |
| `fuigo/memory/rewrite` | `extensions/memory.rs:68`, `memory_dream.rs:865` | writes nothing | one model call, no file; see §7 |
| `memory.tar.gz` build and upload | `upload/memory.rs:113` | **no, fixed (F2)** | built from `~/.fuigo/memory` independent of the session |
| process-memory trace | `fuigo-pager-bin/src/main.rs:2037` | **no, fixed (F1)** | `start()` ran unconditionally |
| subagent agent-memory | `agent/subagent/handle_request.rs:999` | **no, fixed (F3)** | keyed off the agent definition only |
| pager `#` note → `MEMORY.md` | `fuigo-pager/src/app/dispatch/notes.rs:454` `SaveMemoryNote` | n/a, client side, user initiated | see §7 |

`--experimental-memory` beats `--no-memory` in `memory_enabled_override` (`cli.rs:847`), although clap declares
them conflicting (`cli.rs:657`, `:664`), so the case cannot occur on the command line. See §7.

## 2. The change

Four commits on `45bd14ee`, in this order, all trailers `Co-Authored-By: Claude Sonnet 5.5`:

| Commit | What |
|---|---|
| `c8232666` | F2: `PromptTraceContext.memory_enabled`, `memory_upload_skip_reason`, two unit tests |
| `174fcdf7` | F3: `agent_memory_scope = definition.memory.filter(\|_\| ctx.memory_config.is_some())` |
| `1710111b` | F1: `memory_trace_wanted(Some(false)) == false`, one unit test |
| `12815476` | the hostile end-to-end test file `crates/codegen/fuigo-shell/tests/no_memory_writes_acp.rs`, two tests |
| `d7c4a14b` | test only: `dunce::canonicalize` (the repo clippy ban; the first gate run caught it as 1 new warning) |

Behaviour change to flag: F3 also applies to a parent with `memory.enabled = false` in `config.toml`, not only
to `--no-memory`, because both give `ctx.memory_config == None`. A parent that turned memory off no longer gives
its `memory:` children agent memory either. I think that is right, and Astra rounds 3 and 4 did not object.

## 3. The hostile test

`crates/codegen/fuigo-shell/tests/no_memory_writes_acp.rs`, run with `FUIGO_BINARY` (the real `fuigo-pager`
binary, argv `--permission-mode default [--no-memory] agent stdio` as Murage sends it).

* **Subject and control.** Two agents run the identical scenario, each in its own `TestSandbox` and mock server.
  The subject has `--no-memory`; the control does not. Both get `FUIGO_MEMORY=1`, `FUIGO_MEMTRACE=1` and a
  `config.toml` with every memory feature on (`[memory] enabled`, `session.save_on_end`, `watcher`,
  `dream` with no gates, `compaction.memory_flush` with a threshold larger than any window).
* **Scenario.** 3 turns; `/flush`, `/memory on`, `/memory`, `/dream`; `fuigo/memory/flush`; `fuigo/memory/rewrite`;
  a second session and its `/dream`; `fuigo/compact_conversation` then a turn; `fuigo/session/close` on both
  sessions (the session-end save: a SIGTERM does not run it); agent restart in the same sandbox; resume;
  an 8 s idle window with a 2 s idle-flush timer; close again. Compaction, the turn after it, close, load and
  the resumed turn must succeed on both sides. Every extension call has a scaled 60 s deadline.
* **Detector.** Before/after snapshot of the sandbox root (HOME, FUIGO_HOME, TMPDIR) and of the project
  directory: kind, length, mtime, content hash, directory mtimes; only `NotFound` is tolerated, anything else
  panics. A path is memory if it contains `memory`, `memtrace`, `dream`, `consolidat`, `index.sqlite` or
  `embedding`, except the installed user-guide docs and the per-project session directories.
* **The project directory is outside the system temp dir** (`CARGO_TARGET_TMPDIR`), because
  `MemoryStorage::is_ephemeral` silently skips every daily-log write for a temp-dir cwd. In my first run the
  control wrote no flush logs at all for exactly that reason; the test asserts the directory is not ephemeral.
* **The control must write** (and the test fails otherwise): a memory index; a flush log for each of
  `interval` (phase 2, idle only), `pre_compaction`, `slash_command`, `user_requested`; a session-end log;
  the committed `.dream-consolidated` marker and a workspace `MEMORY.md` carrying the conversation sentinel;
  the sentinel in a memory log; a `memtrace/*.jsonl`; deletion of a planted orphan directory; `memory_*` tools
  offered; at least one `fuigo-flush-` and one `fuigo-dream-` model request.
* **The subject must show**: zero memory paths changed; the planted `MEMORY.md` byte-identical; the orphan
  directory still there; zero flush or dream model requests; no `memory_*` tool offered.
* **Second test**, `no_memory_withholds_agent_memory_from_subagents` (F3): a `memory: user` agent definition and
  a planted `MEMORY.md` canary; a scripted `spawn_subagent` turn. Both sides must show requests carrying the
  child's own system prompt (so the child ran). Asserted: the control child sees the canary; the subject child
  does not, and nothing under `agent-memory/` changes. The child's tool inventory is printed, not asserted: in
  the tip run the control child was offered `memory_get` and `memory_search` and the subject child was not.

Observed in the tip run (`f11`, `12815476`): subject `changed=87 memory_changed=0 memory_requests=0
memory_tools_offered=false`; control `changed=111 memory_changed=24 memory_requests=5 memory_tools_offered=true`;
agent-memory subject `child_requests=1 with_canary=0`, control `child_requests=1 with_canary=1`.

Flakiness: the focused tests passed in `f10`, `f11` and `tip1` (three consecutive runs, two tips) and in both
full-suite runs of the gate; `f8` passed and `f9` failed, for a test defect fixed before `f10`. It failed earlier only for reasons I then fixed in the test (the ephemeral
cwd, a mock reply under the 500-char compaction floor, an unreachable embeddings assertion). The settle and idle
sleeps are scaled by `FUIGO_TEST_TIMEOUT_SCALE`; they are still sleeps. That is a residual risk on a loaded host.

## 4. Gate (Contract A.2.1)

Command (`/root/fuigo-builds/p53-gate.sh`, which runs `rp.sh`):
`FUIGO_BINARY=/root/fuigo-builds/p53/fuigo-pager-tip /root/fuigo-builds/rp.sh p53 45bd14ee6a0b2fecc57b844aa758a831c69051d2 strike/p53 /root/fuigo-builds/p53.bundle fuigo-pager-bin fuigo-shell`
inside `slot-run.sh p53`, per package `cargo test --locked --no-fail-fast -p <pkg>`, then
`cargo clippy --locked --all-targets -p fuigo-pager-bin -p fuigo-shell`. Started `2026-10-01T14:38:41Z`,
ended `2026-10-01T15:34:20Z`, `rp_exit=0`, `DONE` marker present in `p53.out`.

| Run | Package | exit | derived (`derive.py`) | headers = `Running`/`Doc-tests` | unfinished | failing set | log sha256 |
|---|---|---|---|---|---|---|---|
| PARENT `45bd14ee` | fuigo-pager-bin | 0 | 5 | 5 | 0 | empty | `28107bfbb5bae6f688ad5f96aadb41036999cfa37b163bfd00bc89bda4147f73` |
| PARENT `45bd14ee` | fuigo-shell | 0 | 38 | 38 | 0 | empty | `b27b05eb696870cc92d501d43f4c4b750d5c6f3124e2d66f1902b182a6f71c61` |
| TIP `d7c4a14b` | fuigo-pager-bin | 0 | 5 | 5 | 0 | empty | `5eed595db90c184f18b1663e7493f1b4bcf74d6b8f4faddf46a8bf7f4faa0961` |
| TIP `d7c4a14b` | fuigo-shell | 0 | 39 | 39 | 0 | empty | `08bb796df1a57c791df24beb27826697592c4e48752b5fc831b9eaa4284c76ec` |

The tip's fuigo-shell count is one higher than the parent's because the packet adds one test binary
(`tests/no_memory_writes_acp.rs`). Derived from the candidate itself, as `cargo test --no-run --message-format=json`
counts, not from a remembered number. Headers were counted by `rp.sh`'s own `HU`. The three new/changed tests
ran and passed inside these logs: `no_memory_writes_nothing_and_the_control_proves_the_detector_sees_memory`,
`agent::mvp_agent::tests::trace_context_memory_enabled_follows_the_session_memory_config`,
`upload::memory::tests::memory_archive_is_skipped_when_the_session_has_memory_off`,
`tests::no_memory_turns_process_memory_tracing_off`. (`no_memory_withholds_agent_memory_from_subagents` is in the
same binary and the binary's `test result` line is `ok`.)

**TIP failing set ⊆ PARENT failing set: yes.** Both are empty on both packages (`comm` of the two `.failset`
files: `only-tip:` empty, `only-parent:` empty). There are no tip-only names, so there is no isolation table.
**Control labels:** the immediate parent is `45bd14ee` (the integration HEAD given in the brief). The accepted
baseline `2eb306e` was not run (§0 item 5). A claim about suite stability would need three consecutive
byte-identical runs (rule (a)); this gate is one run per side and **makes no such claim**.

**Clippy** (`--all-targets`, both packages): parent `exit=0 warnset=25`, tip `exit=0 warnset=25`,
`clippy new:` empty, `gone: 0`. Log sha256: parent `ba0f5e6ff9829d0a130083357202a640e2205b065ae725683cefe24d425c82e0`, tip
`a27337a784769a50772b91ef013e2ba49f9708d5714d1a6f2b04b7fb392b91cb`. A first gate run at `12815476` showed one new
warning (`disallowed_methods` on `std::fs::canonicalize` in my test); `d7c4a14b` fixes it and this table is the
re-run at the fixed tip. The first run's other numbers were the same: tip failing sets empty, `derived=hu` on all
four rows (`run1-*` files on the host).

## 5. Mutants

Each was applied by hand to a clean worktree at `12815476` (source identical to `d7c4a14b`), rebuilt in the lane
target dir, run against the covering test, and reverted (`git checkout -- .`). The diff is saved as
`/root/fuigo-builds/p53/mutant-<id>.diff`. Every one fails the test it is meant to fail:

| Id | Mutation | Covering test | Result | Log sha256 |
|---|---|---|---|---|
| M1 | `cli.rs` `else if false && self.no_memory` (flag no longer reaches the override) | e2e subject test + agent-memory test | both FAIL: "--no-memory still wrote memory" with the full store, flush logs, dream marker; "still injected the agent's MEMORY.md" | `97209cfd8ce9e513b188f9c339de8ff533abad9b49b5740091471e87b007ac99` |
| M2 | `agent/config.rs`, `agent_ops.rs`, `spawn.rs`: drop the three `enabled` gates | e2e subject test + agent-memory test | both FAIL (same messages) | `7ef3d72639c36b54a6e2c1d51268c8d5b45b4da9e50afb334c60a62b193bf247` |
| M2′ | `agent/config.rs` and `spawn.rs` only (two of the three layers) | e2e | **PASSES**, `exit=0`: `agent_ops.rs:484` is a redundant second gate | `9adb18651cb4eecdcb4b9ea73b37631adbd742d78495fb1ad289f51e9319fa19` |
| M3 | `main.rs`: `memory_trace_wanted` returns `true` | e2e subject test | FAIL: subject wrote `memtrace/*.jsonl` | `347fd8c6c5414a1a17c1d867bc189f73e88309cff82b1aafe60c9d8a80e173d2` |
| M3u | same mutation | `tests::no_memory_turns_process_memory_tracing_off` | FAIL: `assertion failed: !memory_trace_wanted(Some(false))` | `c2ef712138a8585650f22c3fcb63ea2efc0ceda9ac2c51033b847c88e6db3eae` |
| M4 | `upload/memory.rs`: `else if false && !memory_enabled` | `memory_archive_is_skipped_when_the_session_has_memory_off` | FAIL: `left: None, right: Some("memory_disabled")` | `cf8aace9b1cf0eed78f26518b6b61a7c2a397e14e77c7d83c46f50a2c622cce1` |
| M5 | `agent_ops.rs`: `memory_enabled: true` | `trace_context_memory_enabled_follows_the_session_memory_config` | FAIL: `never configured: trace context memory_enabled` left `true` right `false` | `c58bf127dbe48ce666fb99b906a6cf1b9ac969b27033e829dd465cf6f504464c` |
| M6 | `handle_request.rs`: `agent_memory_scope = definition.memory` | `no_memory_withholds_agent_memory_from_subagents` | FAIL: "--no-memory still injected the agent's MEMORY.md into a subagent prompt" | `3fcb8025395e63bde84ad236731b28fc14af32cb8f35cb9d15e271af063b9882` |

M2′ is a result, not a mistake: a first M2 that removed only two of the three gates left the test green. The
`agent_ops.rs` gate duplicates `agent/config.rs`. That is why the mutation that matters is the three-layer M2.
It also means this test, by design, proves the end-to-end property rather than each redundant layer.
`tip1.log` (a focused tip run at `12815476`, `exit=0`, 2 passed): `37c4b0ef0375507ce95fa06b35d65f3a76a6f7df1db12eee4825af8a4707e909`;
its `fuigo-pager` binary was 561045368 bytes.

## 6. Astra pre-gate audit

`codex exec --model gpt-6-astra --sandbox read-only --skip-git-repo-check … < /dev/null`, four rounds, text in
`docs/strike/audits/P53-astra.txt`. Final message of each round, verdict quoted:

| Round | Verdict | Findings and what I did |
|---|---|---|
| 1 (`0e5b957e`) | `VERDICT: DO-NOT-LAND.` | 3 HIGH: memtrace bypass (**real, F1, fixed**); e2e cannot see the F2 regression (**accepted as a gap**, §0 item 1); `close()` skips session end (**fixed**: ACP `fuigo/session/close`). 5 MEDIUM, 1 LOW: embeddings off in the fixture and hot reload has no watcher in standalone mode (**claims dropped**, §0 item 2), timing (phase split), Windows paths (normalised), final-state-only snapshot (stricter, narrowed in docs), stale binary (hash logged) |
| 2 (`16a5ce48`) | `VERDICT: LAND-WITH-FOLLOWUPS` | HIGH: subagent `memory:` bypass (**real, F3, fixed**). MEDIUM: dream control could pass on the empty template (**fixed**: marker + sentinel in `MEMORY.md`); lifecycle errors masked (**fixed**; this exposed the control's compaction had been failing on a sub-500-char mock reply); no extension deadline (**fixed**). LOW: F2 wiring coverable (**done**: `trace_context_memory_enabled_follows_…`) |
| 3 (`59674338`) | `VERDICT: LAND-WITH-FOLLOWUPS` | MEDIUM: `FUIGO_MEMTRACE=1` overrode the flag (**fixed**: no env escape; hostile env now sets it). MEDIUM: subject child might not have run (**fixed**: child-specific marker both sides). LOW: sleeps (**scaled**) |
| 4 (`12815476`) | `VERDICT: LAND` | no findings |

Round 4 reviewed `12815476`; `d7c4a14b` differs by one line (`std::fs::canonicalize` → `dunce::canonicalize`).

## 7. Proposals handed back (not done; outside ownership or not file writes)

1. **P-a: `fuigo/memory/rewrite` makes a model call under `--no-memory`.** `handle_rewrite_memory_note`
   (`memory_dream.rs:865`) does not check `is_enabled()`. It writes no file (the pager saves the result
   itself), so it is out of P53's question, but it sends the user's note to the model with memory off.
2. **P-b: `PagerArgs::memory_enabled_override` precedence** (`fuigo-pager/src/app/cli.rs:846`) puts
   `--experimental-memory` first although clap marks the two flags conflicting. Unreachable today. If clap's
   `conflicts_with` is ever dropped, `--no-memory` would lose. Make `--no-memory` win.
3. **P-c: pager `#` remember note** (`fuigo-pager/src/app/dispatch/notes.rs:454`, `SaveMemoryNote`) writes
   `MEMORY.md` from the client process whatever the agent's `--no-memory` says. User initiated, and Murage does
   not use the Fuigo pager UI, so I left it; a `--no-memory` pager should probably refuse it.
4. **P-d: the harness cannot reach the registry-gated upload leg.** A mock first-party OIDC login (or a test
   seam on `build_registry_config`) would let the F2 regression be seen end to end. Needs `fuigo-test-support`.
5. **P-e: the 30 s startup dream timer and leader-mode hot reload** have no end-to-end coverage for
   `--no-memory`; a leader-mode variant of the test would cover the second.

## 8. Host hygiene

Disk checked before the lane (`df -h /root`: 473 GB free, 72% used; peaked at 83% while other sessions' lanes
were building). I used the lane's own `target/`, not a shared one, and `touch`ed changed files before each
build. `rp.sh` removed `p53/target` and the `p53/src` worktree at the end of the gate. Remaining on the host in
`/root/fuigo-builds/p53*`: logs, `.failset` files, mutant diffs and `fuigo-pager-tip` (561 MB), deleted after
this receipt. Runs were aborted by session (`pkill -s <sid>`), never `pkill -f`; I confirmed `pgrep -s` was empty
each time (two driver runs were killed deliberately after I changed the code under test).

## 9. Follow-up round (coordinator's no-deferments request): proposals 1, 2, 3 and 5

Rebased onto integration `90c5a4af22cfc87ff98cd57c9ee56c5b5bab466f`. Commits after the receipt: `fuigo/memory/rewrite`
refusal, `--no-memory` precedence, pager note guard (shell `memoryEnabled` signal), startup-dream seam, tests.

| Proposal | Done | Test |
|---|---|---|
| 1. `fuigo/memory/rewrite` makes no model call under `--no-memory` | refused with a typed `invalid_request` ("memory is not enabled for this session"); `RewriteMemoryNote`'s reply now carries `acp::Error` | e2e: subject gets code -32600 with the reason in `data`, zero requests carrying the formatter prompt; control succeeds and does call the model |
| 2. precedence | `--no-memory` wins in `memory_enabled_override` and `memory_override_flag`; clap still rejects the pair | `no_memory_wins_over_experimental_memory_and_clap_rejects_both` |
| 3. pager `#` / `/remember` note | refused with a message unless the shell has said the session has memory on. First attempt keyed off "no `/flush` advertised"; Astra showed that is unsound (a skill named `flush`; `/flush` also needs the memory tools). Replaced by an authoritative `memoryEnabled` field in `AvailableCommandsUpdate.meta`, re-sent after `/memory on|off`; the tracker keeps it; unreported fails closed. Checked at send time and in the modal-save path | `a_remember_note_is_refused_unless_the_shell_says_memory_is_on` (Some(false) and None, `#` and `/remember`), `..._works_when_the_shell_says_memory_is_on`, `saving_a_remember_note_from_the_modal_is_refused_when_memory_is_not_on`, tracker and `build_tools_meta` tests |
| 5. startup dream timer | made controllable: `FUIGO_MEMORY_DREAM_STARTUP_SECS` (default 30) via `startup_dream_delay` | e2e `no_memory_stops_the_startup_dream_timer`: periodic check pushed to an hour, no `/dream`; the control's dream starts from the timer alone, the subject's never does. Passed in the run at `6190e127` |
| 5. leader-mode reload | **not end to end.** The only consumer of a reloaded memory config is `ConfigUpdate::Memory` in `agent/app.rs`, which only logs ("applies on next agent rebuild"), and Murage runs `--no-leader`. I pinned the one decision that matters, the reloader's use of the override | `memory_config_reload_keeps_honouring_no_memory` (subject: no change reported and never enabled; control: the same edit enables) |
| 4. mock first-party login for the upload leg | left unit-covered as instructed. **Residual.** | |

**Astra on this round:** first check on `6190e127` `VERDICT: LAND` was a misread of the receipt; the real second pass
returned `DO-NOT-LAND` on the "no /flush" signal (fixed as above). A re-check of the fix returned
`VERDICT: DO-NOT-LAND` with two findings I did **not** fix, and I want the coordinator to decide:
- **HIGH (cross-client race):** a note modal opened while memory is on, then memory turned off from another attached
  client after this pager disconnects, still saves, because the cached `Some(true)` survives disconnect and the
  `SaveMemoryNote` executor (`effects/mod.rs:3706`) writes locally without asking the shell. Fix would be to clear
  the tracker's state on disconnect and have the executor re-check. Needs a multi-client scenario to test.
- **MEDIUM (fail closed):** if a new session's first advertisement is dropped (user switches views mid-start), the
  tracker stays `None` and notes are refused in a memory-on session until the next advertisement.
Both are pager-client-only and need a leader with several clients; Murage uses neither. Not closed; proposal P-f.

**Gate for this round** is in the section below (against `90c5a4af`). One tip-only failure appeared in an earlier
run at `a7b9e05d` (`app::mermaid_worker::tests::mermaid_view_disk_hit_runs_action_without_dispatch`, a render-timing
test, unrelated files); isolated 3x with `--exact` at that tip and 3x at its parent `6492c803`, all six passed.

### 9.1 Gate against `90c5a4af22cfc87ff98cd57c9ee56c5b5bab466f` (tip `0ac782eec33b89696f9345246baa79cc7b9623d3`)

`FUIGO_BINARY` = a tip build (sha256 `e80f2e5a4f6396dd31bf89e02a230e8b586ef1e5b1f91d3f3eaf2bbbae39f162`), then
`rp.sh p53 90c5a4af… strike/p53 … fuigo-pager fuigo-pager-bin fuigo-shell`, 2026-10-01T21:31Z to 22:56Z, `DONE` present.
Same toolchain digest `b75985398e5509a90a7d5d68f8ec6690675f703c5cfa11893b04fc9c3fceca69`. As before, the parent run used the tip binary.

| Run | Package | exit | derived | headers | unfinished | failing set | log sha256 |
|---|---|---|---|---|---|---|---|
| PARENT | fuigo-pager | 0 | 21 | 21 | 0 | empty | `baffcb60f455799c942e99110c73cf6537bf7960578e2833f9c052023aed381a` |
| PARENT | fuigo-pager-bin | 0 | 5 | 5 | 0 | empty | `4bb56398f79cea844dbd2ae1515bef332bb15fab1112164de7240edc5c4a5b3d` |
| PARENT | fuigo-shell | 0 | 40 | 40 | 0 | empty | `6f6eb427bd2ecc0af3c07c781aa3cff6a932e7413e2b7a452a82d7e12a821639` |
| TIP | fuigo-pager | 0 | 21 | 21 | 0 | empty | `404a50634753d77c22a88801e85d66f41462ee96b69109f779c053ed821baa99` |
| TIP | fuigo-pager-bin | 0 | 5 | 5 | 0 | empty | `ec1654e1d483c64dd72eb3d8db564635807989073b5b12eff686bbbc931244bf` |
| TIP | fuigo-shell | 0 | 41 | 41 | 0 | empty | `5fe79918f1c2318193465dc71d0cbc1edf4243e7de83e515919065574f067f9f` |

fuigo-shell grows by one target (the P53 test binary), derived from the candidate. **TIP failing set ⊆ PARENT failing
set: yes** (all empty; `only-tip:` and `only-parent:` empty for all three packages). Clippy `--all-targets`: parent
`warnset=28`, tip `warnset=28`, `clippy new:` empty (parent `b5d7952c…a8e6`, tip `b03921c7…8f3e`, full digests in
`/root/fuigo-builds/p53-{parent,tip}-clippy.log`). All three P53 e2e tests, the reloader, startup-delay, cli and
pager note tests ran and passed in these logs. One-run-per-side; no suite-stability claim.

Not re-run after the rebase: mutants M1 to M6 (taken at `12815476`, unchanged code) and a mutant for each of the new
guards. The new behaviours are pinned by tests that fail without them only by construction, not by a recorded mutant;
that is a gap. Astra's last verdict on this round is `DO-NOT-LAND` on the two pager-only findings in §9, which I did
not fix; I am not claiming a clean audit for the follow-up commits.

Hetzner: `p53/target` and the worktree are deleted; the tip binary is deleted; only logs remain.

## 10. Second follow-up: the note write belongs to the shell (Astra HIGH and MEDIUM closed)

The coordinator ruled that an Astra HIGH cannot be scoped out. Both §9 findings are closed in this packet; §9's "I did
not fix" is superseded. Rebased onto integration `f82e6e331de6a4076a900602fdce9a470de452b2`. Tip
`0630b3b02d4a25f7cafbdeb5f4eef325429c3992` (gated code is the same as `28087dd9`; the last commit is the audit file).

**Design.** New extension `fuigo/memory/save_note {sessionId, text}`. The pager no longer writes `MEMORY.md`:
`Effect::SaveMemoryNote` now carries the session id and calls the shell. `SessionActor::save_memory_note`
(`memory_dream.rs`) refuses with a typed `invalid_request` ("memory is not enabled for this session") and writes
nothing unless the session's storage handle is present at write time. The pager's `memoryEnabled` cache is a hint
that only adds a notice; it never refuses. An unreported or stale state, in either direction, still reaches the shell.

**Race (Astra round 7 HIGH).** My first version put the append on `spawn_blocking` after the storage check, so
`/memory off` could land between them. The check and the append now run with no `.await` between them on the session's
single thread, and `/memory on|off` flips the storage `RefCell` synchronously on that same thread, so a toggle lands
entirely before or entirely after a save. This is a structural guarantee: **no test can force the interleaving**. The
e2e `a_memory_note_racing_memory_off_is_all_or_nothing` only checks the outcome is consistent under real concurrency
(never `Ok` without a write, never a write after a refusal). Astra round 9 accepted this reasoning.

**Tests.**
- e2e `a_memory_note_is_decided_by_the_shell_at_write_time`: the client holds no memory state at all (the
  dropped-first-update case), saves a note with memory on and it lands; `/memory off` (what another client does) and
  the same client's next save is refused with code -32600 and `MEMORY.md` unchanged; `/memory on` and it saves again;
  under `--no-memory` every note is refused and nothing memory-shaped is created.
- pager `a_remember_note_always_reaches_the_shell_whatever_the_cache_says` (Some(true), Some(false), None, `#` and
  `/remember`), `a_stale_cache_in_either_direction_does_not_change_what_the_pager_sends` (opens a modal, flips the
  cache, saves that modal), `the_modal_save_without_a_session_is_refused`, tracker and `build_tools_meta` tests.

**Mutants at `99129fde` (code equal to the tip), M1 to M12; each fails the test shown.** Base run first: all four focused
suites green (e2e 5 passed, shell unit, pager unit, bin unit).

| Id | Mutation | Failed test |
|---|---|---|
| M1 | `--no-memory` no longer reaches the override | e2e (several), and `no_memory_wins_over_experimental_memory_and_clap_rejects_both` |
| M2 | drop the three `enabled` gates | e2e (several incl. the note test) |
| M3 | `memory_trace_wanted` returns true | e2e subject writes memtrace; and `no_memory_turns_process_memory_tracing_off` |
| M4 | upload skip reason ignores memory | `memory_archive_is_skipped_when_the_session_has_memory_off` |
| M5 | `memory_enabled: true` on the trace context | `trace_context_memory_enabled_follows_the_session_memory_config` |
| M6 | agent-memory scope not gated | `no_memory_withholds_agent_memory_from_subagents` |
| M7 | **shell-side refusal removed** (`save_memory_note` writes to a fallback store when memory is off) | `a_memory_note_is_decided_by_the_shell_at_write_time`; run at the final base, log `/root/fuigo-builds/p53/m7.log` sha256 `42d5a568ca805adbb8a9ebebbfd2caac56ff5016305c28743c46069c77d41967` |
| M8 | pager refuses locally when the hint says off | `a_remember_note_always_reaches_the_shell_whatever_the_cache_says` |
| M9 | pager refuses the modal save when the hint says off | `a_stale_cache_in_either_direction_...` and `a_remember_note_always_reaches_the_shell_...` |
| M10 | shell always says `memoryEnabled: true` | `build_tools_meta_serialises_tool_names` |
| M11 | `fuigo/memory/rewrite` gate removed | e2e subject (rewrite no longer refused) |
| M12 | startup-dream delay ignores the env seam | `startup_dream_delay_tests::defaults_to_thirty_seconds_and_accepts_whole_seconds` |
| M1u / M3u | the same mutations against the pager and pager-bin unit tests | both fail |

M7 was first mis-specified (the replacement text did not match), reported `APPLYFAIL`, and was rerun with a corrected
patch; M13 (a variant) was dropped. The race itself has no mutant: see "Race" above. Log shas for M1 to M12 are in
`/root/fuigo-builds/p53/big-mut-*.log` (deleted with the lane; sha256 values are in the run output `big.out`).

**Astra rounds 5 to 9**, text in `docs/strike/audits/P53-astra.txt`: 5 `DO-NOT-LAND`, 6 `DO-NOT-LAND`, 7 `DO-NOT-LAND`
(HIGH race, MEDIUM stale off), 8 `LAND-WITH-FOLLOWUPS` (one LOW, fixed), 9 **`VERDICT: LAND`**. Nothing above LOW
remained at round 9.

**Gate against `f82e6e331de6a4076a900602fdce9a470de452b2`, tip `0630b3b0`.** The first attempt had 18 `fuigo-shell`
failures on the parent: my gate script had deleted the `FUIGO_BINARY` it pointed at (`FUIGO_BINARY does not exist`).
That run is void, not a flake, and I do not use it. The gate was re-run with the binary present
(`/root/fuigo-builds/p53-gate-final.out`, 02:14Z to 03:24Z, `DONE`, `rp_exit=0`):

| Run | Package | exit | derived | headers | unfinished | failing set | log sha256 |
|---|---|---|---|---|---|---|---|
| PARENT | fuigo-pager | 0 | 21 | 21 | 0 | empty | `956f11d9a38114f9df1f543d2f024c3c3bfbca1ffd6f514c9f2ea27f47b9ab08` |
| PARENT | fuigo-pager-bin | 0 | 5 | 5 | 0 | empty | `3953ca30368c8de4e39ce3d0e5235f652173891c1a5f2f3316b9b175f719ed5a` |
| PARENT | fuigo-shell | 0 | 40 | 40 | 0 | empty | `ba5fc2c4d2a04eab04a609dd9871034b70db9933b7bdc75555f86e768f4aeebb` |
| TIP | fuigo-pager | 101 | 21 | 21 | 0 | `app::mermaid_worker::tests::mermaid_view_disk_hit_runs_action_without_dispatch` | `76038001700903d7196cf6f6b747e0e24090156ab0d0ffab2cca9bf58c8fc5d8` |
| TIP | fuigo-pager-bin | 0 | 5 | 5 | 0 | empty | `696f47bb27844e1a9cb99293b34ac873dbeba426bcf82dee059b2232ba091634` |
| TIP | fuigo-shell | 0 | 41 | 41 | 0 | empty | `a527690856dcca14ba8c5e7c38476b668c3e78178a9cc6475f2a7ee16195e61c` |

Clippy `--all-targets`: parent and tip both `warnset=28`, `clippy new:` empty (parent `79267fa2…a6da938`, tip
`1d9a6f60…75206`, `/root/fuigo-builds/p53-{parent,tip}-clippy.log`). **Tip failing set is not a subset of the parent's:**
one tip-only name, the mermaid render-timing test. Isolation per A.2.1 is below.

**Isolation of the tip-only name (A.2.1), `iso.sh`, `--exact`, `-p fuigo-pager --lib`:**

| SHA | run 1 | run 2 | run 3 |
|---|---|---|---|
| tip `0630b3b0` | pass | pass | pass |
| parent `f82e6e33` | pass | pass | pass |

`mermaid_view_disk_hit_runs_action_without_dispatch` asserts that a disk-cached diagram shows its copy action at once and
got "Rendering diagram…" in the full parallel run: a render-timing race in a file P53 does not touch
(`app/mermaid_worker.rs`). It has now failed in the full pager suite at two different tips of this packet and passed
in all 12 isolated runs (6 at `a7b9e05d`/`6492c803`, 6 here). That is one unstable test, not a P53 effect, but this gate does
**not** show tip ⊆ parent for the full pager suite: the parent's full run happened to pass it. I report it as an inherited,
load-dependent flake; one run per side is not a stability claim (rule (a) would need three consecutive full runs).
`fuigo-pager-bin` and `fuigo-shell` tips have empty failing sets. Proposal: a packet to make that test deterministic.

Hetzner after the work: `p53/src`, `p53/target` and the tip binary are deleted; logs remain.
