# Receipt R022 — P00: Murage ACP conformance harness (Contract E gate)

**Date:** 2026-10-01 · **Parent:** `ac7bfe92` (strike/integration; rebased from `8d250586`, earlier `14cab7e7`) ·
**Branch:** `strike/p00` · **Code tip gated:** `6b942529` (+ `d620122c`, README prose only, not compiled) ·
**Box:** hetzner-dsm, lanes `p00`, `p00rp`, `p00iso` · **Not landed.**

P00 adds a fake-Murage ACP client. It spawns the real `fuigo` binary over stdio, using Murage's verbatim argv,
`initialize` payload and reply shapes, and pins Contract E in 18 tests. **No Contract E clause fails at HEAD,
so there are no product findings against Contract E.** The P04 and P02e consults are answered in §6.

## 0. Re-proof on `ac7bfe92`: the gate of record (coordinator decision after pass 7)

The coordinator decided:

- **Approved:** a `libc` dev-dependency for the leader-reaper probe. Not needed: `fuigo-test-support` already
  depends on `libc` (`[target.'cfg(unix)'.dependencies]`), so `Cargo.toml` and `Cargo.lock` are unchanged.
- **Approved:** P00 now owns `fuigo-test-support/README.md`.
- `FUIGO_BINARY` stays logged, not enforced.
- P00-F1 is routed as its own packet; this packet leaves it alone.
- Rebase onto `ac7bfe92`, then gate with `rp.sh`, with no skip (P38 fixed the wedge).

**New commits since §§1–6 below:**

- **`de1e3ec7`.** `pid_liveness` / `classify_kill_zero` / `sigkill` in `fuigo-test-support/src/process.rs`,
  all direct syscalls:
  - `kill(pid, 0)`: success or `EPERM` = Alive, only `ESRCH` = Gone, anything else Unknown (treated as alive).
  - Bounded by construction: no helper subprocess remains in the reaper.
  - PID 0 and PIDs beyond `pid_t` are never probed or signalled.
  - The README rows for `acp_client` and `process` now match `src`.
- **`6b942529`.** `sigkill` refuses PID 0 **and 1** in both modes. Without that, `sigkill(1, true)` was
  `kill(-1, SIGKILL)`, a host-wide broadcast (found by the Astra check). The README's deadline claim is
  narrowed to the bounded methods.
- **`d620122c`.** README wording for `sigkill` only.

**Mutants for the new code** (focused lane `p00`, `focused.out` `54f1a140`). Each was run with
`cargo test -p fuigo-test-support --lib pid_liveness_tests` via `slot-run`; without mutants that is 3/3 pass
(`7d6481ef`).

| Mutant | Change | Result |
|---|---|---|
| MA | `EPERM` → Gone | caught: `esrch_is_gone_eperm_is_alive_…` |
| MB | `ESRCH` → Alive | caught: `a_live_process_is_alive_and_a_killed_reaped_one_is_gone` and the classify test |
| MC | PID-0/range guard in `pid_liveness` removed | caught: `pid_zero_and_out_of_range_are_never_probed_or_signalled` |
| PID-1 guard in `sigkill` removed | — | **deliberately not executed**: on a root runner it would SIGKILL the host. Pinned by assertions that return before any syscall |
| "bounded" | — | **no mutant possible**: no blocking call or subprocess remains; the 10 s loop deadline is unchanged |
| TV4i | `--no-leader` dropped (reaper path) | fails as intended; **no surviving process** (`5ec66ffd`) |

The conformance binary at `6b942529` passed 18/18 (`0f46481c`).

**Astra checks of the new commits** (`codex exec --model gpt-6-astra --sandbox read-only … < /dev/null`):

- **`de1e3ec7`: DO-NOT-LAND.** Both pass-7 follow-ups FIXED. New HIGH: the `kill(-1)` broadcast via PID 1. New
  LOW: README deadline claim. Both fixed in `6b942529`. `git range-diff` showed the rebase left P00's patches
  unchanged.
- **`6b942529`: LAND-WITH-FOLLOWUPS.** Both FIXED. One LOW README wording item, fixed in `d620122c`. No runtime
  defect.

**Gate of record:** `rp.sh p00rp ac7bfe92ea6034f2d1efa348715e28d2d820dfd7 strike/p00 p00-rp.bundle
fuigo-test-support fuigo-shell fuigo-pager`.

- Tip in the bundle: `a168c2a7`, whose code equals `6b942529`.
- No `--skip`; `slot-run`.
- `p00rp.out` `054323eb`; toolchain digest `b7598539…`.

| pkg | run | exit | derived | headers/unfinished | failures | log sha256 |
|---|---|---|---|---|---|---|
| fuigo-test-support | parent | 0 | 2 | 2 0 | 0 | `b57626a8…` |
| fuigo-test-support | tip | 0 | 2 | 2 0 | 0 | `87612242…` |
| fuigo-shell | parent | 0 | 38 | 38 0 | 0 | `79426bb1…` |
| fuigo-shell | tip | 0 | 39 | 39 0 | 0 | `cd744049…` |
| fuigo-pager | parent | 101 | 21 | 21 0 | 18 | `252d6452…` |
| fuigo-pager | tip | 101 | 21 | 21 0 | 18 | `2807322a…` |

- **Tip-only names: none in any package. Parent-only: none.**
- **Clippy** (`--all-targets`, the three packages): exit 0 at both, warnset 27 = 27, **0 new**.
- `fuigo-shell` derives 39 at the tip against 38 at the parent; the +1 is `murage_conformance_acp`, green
  inside the full suite.

**Third-party consumers of the seam** (focused lane; full `cargo test --locked --no-fail-fast` via `slot-run`,
DONE appended, at tip `6b942529` and parent `ac7bfe92`):

| pkg | derived | tip exit / hu / failures | parent exit / hu / failures | log sha256 tip / parent |
|---|---|---|---|---|
| fuigo-sampler | 12 | 0 / 12 0 / 0 | 0 / 12 0 / 0 | `8226b504` / `d0264c20` |
| fuigo-tools | 8 | 101 / 8 0 / 1 | 0 / 8 0 / 0 | `7daec3a3` / `57edaeec` |
| fuigo-pager-pty-harness | 17 | 0 / 17 0 / 0 | 0 / 17 0 / 0 | `fc2994f3` / `a3caaed6` |

The one `fuigo-tools` tip-only name is
`implementations::lsp::tests::advertises_and_accepts_file_watch_registration_without_error`:

- **Failure:** `parse …/register_reply.json: EOF while parsing`, an empty reply file read too early.
- **Sightings:** 1 in another lane's failset.
- **Reach:** it is a `fuigo-tools` lib unit test, and P00 changes no `fuigo-tools` code.
- **Isolation:** `iso.sh p00iso fuigo-tools --lib <name> <tip> <parent>`: 3× `--exact` passes at tip `6b942529` and 3× at parent `ac7bfe92`, all exit 0 (`p00iso.out` `705fe9d8`). This is load-sensitive timing in that test, not a P00 effect.

**Still unverified:**

- No `FUIGO_VERSION`-stamped binary was run.
- Hermeticity and leader cleanup are observed on Linux only (off Linux, liveness is the `kill(pid, 0)`
  syscall and leaders are found only through `leader.lock`).
- `--no-memory` is pinned by tool availability.
- The P04 pin proves the 30 s boundary, not the full 30 minutes.

Sections 1–6 below are the history up to `3e711b9c` on `8d250586`, superseded as the gate of record by this
section.

## 1. What changed (R4 ownership proof)

`git diff --stat 8d250586..3e711b9c`:

```
 .../tests/fixtures/murage_model_state_golden.json  |   43 +
 .../fuigo-shell/tests/murage_conformance_acp.rs    | 1650 ++++++++++++++++++++
 .../codegen/fuigo-test-support/src/acp_client.rs   |  339 +++-
 crates/codegen/fuigo-test-support/src/lib.rs       |    3 +-
 4 files changed, 2013 insertions(+), 22 deletions(-)
```

All four paths are in brief §1. No production source, `Cargo.lock`, root `Cargo.toml` or `package.json`
changed. There is no new crate and no new dependency.

Commits:

| Commit | What it does |
|---|---|
| `c6031f12` | The harness |
| `15be0367` | Clippy `disallowed_methods` fix |
| `d2e1e5fe` | Astra passes 1 and 2 |
| `7ad4b38e` | P04 consult pin |
| `32521523` | Astra pass 3 |
| `18eded68` | Astra pass 4 |
| `9b4a9fae` | Astra pass 5 |
| `3e711b9c` | Astra pass 6 |

`git range-diff` showed the three pre-rebase patches unchanged.

**Seam (`fuigo-test-support`), additions only.** Every name `lib.rs` exported at the parent is still exported,
with the same signature and meaning. `spawn_with_sandbox_env_and_args` still places `leading_args` before
`agent`. `RawStdioClient::response_for_id` keeps its signature, messages and `-32601` refusals; it now shares
the cancellation-safe line framing.

New items:

- **`AgentSpawnSpec { leading_args, agent_args, extra_env, remove_env }`.** Covers both halves of
  `fuigo <global> agent <agent flags> stdio`, plus env removal applied last (Traps 3 and 4).
- **`RawReply { Result, Refuse, Defer }`.** `From<Option<Value>>` keeps `Option` callbacks working.
- **`FuigoStdioClient::spawn_with_spec`.**
- **`RawStdioClient::{spawn_with_spec, sandbox, transcript, request, wait_for_message,
  response_for_id_answering, respond}`.** One scaled deadline bounds every read and write of an exchange.
  Lines are framed with a persistent buffer and `read_until` (cancel-safe). Invalid UTF-8 is a hard failure.

## 2. Clause → test → mutant → result

Product mutants are applied by exact-string replacement (`p00/mutate.py`, every anchor count asserted). The
`fuigo` binary is rebuilt in a separate mutant lane, and the snapshotted tip test binary runs against it.
TV mutants edit the test. Every mutant listed was caught by the named test, with the quoted message.

| Clause | Test | Mutants (all caught) |
|---|---|---|
| E.1 Murage argv, full turn (default / bypassPermissions / +`--trust`), typed client | `murage_exact_argv_is_accepted` | M8, M5 |
| E.1 spellings/aliases parse and start cleanly (exit 0 on EOF); value validation; conflicts; typo controls | `murage_argv_flags_still_exist_with_their_spellings` | M1 (aliases renamed): `unexpected argument '--trust-folder'` |
| E.1 `--permission-mode` (an `rm` asks under `default`; nothing asks under bypass) | `permission_mode_flag_governs_tool_approval` | M2 (flag ignored) |
| E.1 `-m`, `--reasoning-effort`, `--effort` reach inference | `model_and_reasoning_effort_flags_reach_inference` | M3: `effort on the wire left: "low"` |
| E.1 `--no-leader` under `[cli] use_leader = true` | `no_leader_flag_keeps_the_agent_standalone_when_config_enables_leader` | M4; TV4…TV4h: `found ["leader.lock", "leader.log", "leader.sock"]` |
| E.1 `--no-memory` (no `memory_*` tool; same-argv control offers `memory_search`) | `no_memory_flag_withholds_memory_tools` | M14 |
| E.2 child-only `FUIGO_API_KEY` authenticates, and inference bills that key | `injected_fuigo_api_key_authenticates` | M5; TV5 (precondition guard) |
| E.3 `fuigo.api_key` first, and `defaultAuthMethodId` | `initialize_advertises_fuigo_api_key_and_names_it_default` | M6+M6x (`grok.com` first) |
| E.3 no credential → `[]`, `-32000 "Authentication required"` on `session/new` and `authenticate` | `no_credential_yields_empty_auth_methods_and_minus_32000` | M7, M6; TV3 (precondition guard) |
| E.4 `protocolVersion: 1` | `protocol_version_one_is_accepted` | M8 |
| E.5/E.5a `_fuigo/folder_trust/request`; config **stays gated while the decision is pending**, then applies | `folder_trust_round_trip_without_trust_flag` | M9; M19: `the project config was applied while the trust decision was still pending`; TV1 |
| E.5 `--trust` suppresses the request (whole transcript) and records the grant | `trust_flag_suppresses_the_round_trip` | M10b; TV1 |
| E.6/E.5a `_fuigo/mcp_initialized`, no-server path | `mcp_ready_notification_wire_name_is_pinned` | M11 |
| E.5a/E.6 Murage-passed MCP server: `_fuigo/mcp/elicit` round trip; populated readiness is a notification (unix) | `murage_mcp_server_elicit_and_ready_wire_names` | M16, M17 (background readiness site only; escapes the test above), M11 |
| E.5a `_fuigo/ask_user_question`, and Murage's `accepted` reply reaches the model | `ask_user_question_round_trip_wire_name_is_pinned` | M15 |
| P04 consult: Murage's owner is not cut off by the 30 s non-interactive cap | `ask_user_question_waits_for_murage_past_the_non_interactive_cap` | M20 (every session non-interactive): `Fuigo resolved the question before Murage answered`; M15 |
| E.7 `_meta.modelState` equals the wire-captured golden | `meta_model_state_matches_golden` | M12; TV2 |
| E.8 fields Murage reads; tool stamp `version` 1 + `namespace`; `availableCommands` | `murage_wire_path_fields_round_trip` | M13, M18 |

**Not caught or confounded, all explained:**

- **M10 (one `--trust` site).** `--trust` is granted at both `fuigo-pager-bin/src/main.rs:2163` and `:1213`.
  M10b disables both and is caught.
- **B1.** M6 tripped the debug `debug_assert!` at `acp_agent.rs:386`. The batch was re-run without M6, and
  M6 then ran with M6x, which neutralises that assert as a release build does.
- **TV3 and TV5** were caught by the tests' precondition guards. Product mutants M7/M6/M5 discriminate the
  behavioural halves.

**Lanes and binaries.**

| Base | Test binary | Runs |
|---|---|---|
| `14cab7e7` | v1 (`8b9e9b3e`) | M0 control 14/14; B1 (confounded); B1b; B2–B6 |
| `14cab7e7` | `001bb94e` | B7; I1 (merge onto `cca0969f`) 14/14 |
| `14cab7e7` | `a9c8760b` | R0 control 17/17; C1–C3 |
| `14cab7e7` | `d9e2253d` | D1 (M19) |
| `8d250586` | `7ad4b38e` (`f5e8835c`) | R4 control 18/18; E1 (M20); E2 (M15) |

TV4b leaked a leader, which was killed by PID after its `FUIGO_HOME` was confirmed as the run's own; that
prompted the reaper rework. TV4c through TV4h fail as intended with no surviving process. TV4h ran on
`3e711b9c`.

Log sha256 prefixes:

- **Mutants:** M0 `fbb8753a`, B1 `03f71c0b`, B1b `eda99cc8`, B2 `dbcdecac`, B3 `8ee2d0c2`, B4 `254ff223`,
  B5 `b28b62f9`, B6 `3a09de59`, B7 `e68976f3`, I1 `34f6ad6f`, R0 `552014fd`, C1 `5adc32fd`, C2 `6ac5e437`,
  C3 `8f6d2743`, D1 `8f05a4db`, R4 `8de2ef6b`, E1 `b6cfd18d`, E2 `1d91fe79`.
- **TV runs:** TV `d8c683f2`, TV4 `3592e45e`, TV4b `731f05d5`, TV4c `76d9ceb7`, TV4d `558e88e2`, TV4e
  `53111ffa`, TV4f `bf155c4b`, TV4h `9e082188`.

## 3. Pre-gate audit (lane protocol v2)

All passes ran as `codex exec --model gpt-6-astra --sandbox read-only` from the Mac worktree (no cargo).
Every finding was checked against the code; none was judged not real.

| Pass | On | Verdict | Findings → disposition |
|---|---|---|---|
| 1 | `1268b9cb` | DO-NOT-LAND | **H1** early messages lost/refused → `seen_or_wait`. **H2** leader cleanup skipped on panics → Drop guard. **H3** `--no-memory` untested → effect test with control. **H4** stamp/commands unpinned → asserted. **H5** ask/elicit/populated-MCP unpinned → two tests. **M6** `FUIGO_BINARY` fallback → logged, not enforced (CI never sets it, so enforcing it would turn P00 red in every other lane; `env.rs` is outside ownership; the auditor accepted this). **M7** CLI accept counted crashes → exit 0 required. **M8** unbounded writes → one deadline per exchange. **M9** self-compared hermeticity → reads `/proc/<pid>/environ` and requires `agent_id` (Linux). |
| 2 | `a9c8760b` | DO-NOT-LAND | **H2r** reaper needed a published PID → identity scan. **N1** ordering did not prove consent → decision **deferred**, gating asserted while pending. **N2** readiness not required to be a notification → asserted. **N3** `/bin/sh` on Windows → `#[cfg(unix)]`. |
| 3 | `7ad4b38e` | DO-NOT-LAND | **H2r** snapshot taken before follower kill → follower killed first. **N4** `read_line` not cancel-safe → persistent buffer + `read_until`. |
| 4 | `32521523` | DO-NOT-LAND | **H2r** settle heuristic → follower confirmed dead, then every process carrying the sandbox `FUIGO_HOME` is killed (exact). Mixed readers → `response_for_id` on shared framing. Lossy UTF-8 → hard error. |
| 5 | `18eded68` | LAND-WITH-FOLLOWUPS | MEDIUM: macOS zombies burnt the deadline. LOW: `/proc` decode errors read as "finished". Both fixed in `9b4a9fae`. |
| 6 | `9b4a9fae` | LAND-WITH-FOLLOWUPS | The new `ps` probe was unbounded (MEDIUM) and read empty output as absence (LOW) → `ps` removed in `3e711b9c`. |
| 7 | `3e711b9c` | **LAND-WITH-FOLLOWUPS** | **Open, non-Linux cleanup only:** the `kill -0` subprocess has no timeout, and any `kill` failure (not just ESRCH) counts as gone. The auditor's remedy is a direct `kill(pid, 0)` syscall, which needs `libc`, a dependency the brief forbids without escalation. **Not fixed; for the coordinator.** No landing blocker found. |

## 4. Gate (Contract A.2.1, lane protocol v2)

Env: `RUST_MIN_STACK=16777216 RG_BIN_PATH=/usr/bin/rg CARGO_TERM_COLOR=never CARGO_BUILD_JOBS=16`, `nice -n 10`,
rustc 1.94.0 (`rustc -vV` sha256 `b7598539…`).

- Every `cargo test` ran through `slot-run.sh p00` (private HOME) via `gate2.sh`, with a DONE marker appended
  to each log. `FUIGO_BINARY` was set to the lane's own build.
- **`fuigo-shell` ran with `-- --skip session::workflow::manager::tests`** (the P29 hang; P38 is not in
  `8d250586`).
- Derived counts come from `cargo test --locked -p <pkg> --no-run --message-format=json | P=<pkg> python3
  derive.py`.
- Failing sets come from the `failures:` block and are saved as `/root/fuigo-builds/p00-gate2-*.failset`.

### 4.1 Gate of record: parent `8d250586` vs tip `3e711b9c`

| pkg | run | exit | derived | headers/unfinished | failures | log sha256 |
|---|---|---|---|---|---|---|
| fuigo-test-support | parent | 0 | 2 | 2 0 | 0 | `4a534d0b…` |
| fuigo-test-support | tip | 0 | 2 | 2 0 | 0 | `83ab0a77…` |
| fuigo-pager | parent | 101 | 21 | 21 0 | 18 | `c0b8283d…` |
| fuigo-pager | tip | 101 | 21 | 21 0 | 21 | `9bbac2cd…` |
| fuigo-shell (skip) | parent | 101 | 38 | 38 0 | 5 | `77c895ca…` |
| fuigo-shell (skip) | tip | 101 | 39 | 39 0 | 10 | `92749767…` |

`fuigo-shell` derives 39 at the tip against 38 at the parent; the +1 is `murage_conformance_acp`, which passed
inside the full suite. Out files: `gate2-parent4.out` `b67255b0`, `gate2-tip6.out` `4814ea11`.

**Tip-only names, with sightings in other lanes' failsets on this host and 3× `--exact` at tip and parent
(via `slot-run`):**

| name (pkg) | sightings (other lanes) | 3× `--exact` at tip `3e711b9c` | 3× `--exact` at parent `8d250586` |
|---|---|---|---|
| `config_toml_edit::tests::concurrent_set_hint_at_writes_do_not_lose_each_other` (pager) | 2 | pass ×3 | pass ×3 |
| `provider_config_edit::tests::concurrent_writes_of_different_providers_all_survive` (pager) | 1 | pass ×3 | pass ×3 |
| `views::agents_modal::tests::concurrent_config_edits_do_not_lose_each_other` (pager) | 2 | pass ×3 | pass ×3 |
| `agent::app::tests::embedded_otel_gate_keeps_a_session_user_fail_closed` (shell) | 14 | pass ×3 | pass ×3 |
| `agent::models::startup_prefetch::tests::wait_settings_leaves_the_fetch_for_accept` (shell) | 40 | pass ×3 | pass ×3 |
| `auth::manager::lock::tests::dropping_the_guard_silences_the_heartbeat_before_anyone_else_can_hold_the_lock` (shell) | 14 | pass ×3 | pass ×3 |
| `inspect::tests::describe_requirements_file_flags_invalid_version_overrides_as_parse_error` (shell) | 19 | pass ×3 | pass ×3 |
| `session::managed_mcp::tests::client_cursor_server_kept_when_cursor_mcps_enabled` (shell) | 13 | pass ×3 | pass ×3 |
| `session::workflow::registry::tests::deterministic_scan_uses_git_root_and_skips_invalid_filename` (shell) | 8 | pass ×3 | pass ×3 |
| `session::workflow::registry::tests::save_is_validated_atomic_and_no_clobber` (shell) | 7 | pass ×3 | pass ×3 |
| `session::worktree::tests::create_worktree_for_resume_honors_git_ref` (shell) | 17 | pass ×3 | pass ×3 |

All 66 runs used `slot-run.sh p00 cargo test --locked -p <pkg> --lib -- --exact <name>`, and every one exited 0
with `1 passed` (`iso6.out` `de9764b9`). Sightings come from `/root/fuigo-builds/*.failset` and
`*/*.failset`, excluding P00's own.

Parent-only (they pass at the tip): `attempted_settings_fetch_failure_is_a_degraded_start`,
`same_credential_refresh_does_not_flap_resolved_gate`,
`init_session_load_fills_missing_label_on_kinded_fork_without_changing_kind`. Other lanes were running on the
host throughout. Both directions of drift are the load-sensitive population that R017/R017a recorded.

### 4.2 Clippy (`--locked --no-deps --all-targets -p fuigo-test-support -p fuigo-shell`)

- **Parent `8d250586`:** exit 0, 30 warnings (`77e4148f…`).
- **Tip `3e711b9c`:** exit 0, 30 warnings (`dae7c909…`).
- **New lint+file keys at the tip: none** (paths normalised).
- At `001bb94e`, clippy had flagged two of P00's own `disallowed_methods` uses. Both were fixed in `15be0367`.

### 4.3 R1 / R2: `slot-run.sh p00 env FUIGO_BINARY=… testlane.sh p00 <src-tip> <target-tip> 16 -- --locked -p fuigo-shell --test murage_conformance_acp` (`--network none`)

| Run | Commit | Exit | Headers | Result | Log sha256 | Timestamp |
|---|---|---|---|---|---|---|
| R1 | `3e711b9c` | 0 | 1 0 | 18 passed | `5c72e005…` | 2026-10-01T06:23:48Z |
| R2 | `3e711b9c` | 0 | 1 0 | 18 passed | `cb0423e7…` | 2026-10-01T06:26:22Z |

The derived count for this command is 1: one executable, and the `--test` filter runs no doc-tests.
`derive.py` prints `2 exe=1 doc=1` because it adds a doc-test whenever the library has doctests.
`finish6.out` `d56533a7`.

### 4.4 Superseded and inadmissible runs (every run is reported)

- **Gate v1 at `14cab7e7` vs `001bb94e`** (legacy flock, host HOME). All admissible:
  - test-support: 0 / 0 failures.
  - pager: 19 / 18.
  - shell: 5 / 4, with 3 tip-only names that passed 3× `--exact` at both revisions.
  - Out files: `gate-parent.out` `ec0dca9a`, `gate-tip.out` `80005566`.
  - R1 `eae44ee7` and R2 `d94cb74f`, 14/14 each.
- **Gate v2 at `14cab7e7`:** pager 20 failures, shell 2 (skip). Admissible. `gate2-parent.out` `6a31535a`.
- **Stopped deliberately by session kill when an audit made the commit stale.** These have no result and are
  not evidence:
  - `a9c8760b`: the shell run (`gate2-tip.out` `34073921`).
  - `7ad4b38e`: tip4.
  - `9b4a9fae`: tip5.
  - One probe aborted because it was using a pre-P04 binary.
- **Informative, not the gate:** P00 merged onto `cca0969f`, 14/14 (`34f6ad6f`).

## 5. Unverified

- **No release-stamped binary was run.**
- **Hermeticity** is observed only on Linux. Leader cleanup off Linux uses the lock PID only (pass-7
  residuals).
- **`--no-memory`** is pinned by tool availability; that memory is not written is not observed.
- **The P04 pin** proves the 30 s boundary (a 40 s hold), not the full 30-minute interactive allowance.
- **The leader-spawn races** that the reaper handles were not induced directly; TV4c–TV4h cover the respawn
  path.

## 6. Findings and consults

**Contract E: none.** All 18 tests pass against the real binary at `3e711b9c` on `8d250586`.

**Consult, P04 (`8d250586`), `ask_user_question` capped at 30 s for non-interactive clients: no finding.**

- **Murage implements `_fuigo/ask_user_question`.** `murage-0161-tsweep2` `34346be1`
  `server/drivers/acp/core.ts:861,1837` binds it. `handleQuestionRequest` never auto-answers and waits up to
  30 minutes (`:1651`).
- **Murage never sets `nonInteractive`.** `git grep nonInteractive|startupHints` over the tracked `.ts` finds
  nothing. Its `initialize` is `{protocolVersion: 1, clientCapabilities: {fs, elicitation,
  _meta: {"fuigo/folderTrust"}}}` and its `session/new` is `{cwd, mcpServers}`.
- **P04 keys only on `startupHints.nonInteractive`** (`session/acp_session_impl/spawn.rs:1112`), so Murage's
  owner keeps the interactive window.
- **Pinned** by `ask_user_question_waits_for_murage_past_the_non_interactive_cap`: hold 40 s, then Murage's
  answer must reach the model. M20 (every session non-interactive) is caught.

**Consult, P02e (`strike/p02e`, not landed), budget denial `error_kind` `api` → `execution_incomplete` plus
`data.code`: no finding.**

- Murage never branches on `error_kind == "api"`. The kind only selects user-facing copy
  (`src/lib/error-preview.ts:40` → `runtimeError.engineKind.<kind>`, list in `shared/provider-error.ts:148-157`).
- `execution_incomplete` is already a known category with "usually because a budget ran out" copy in every
  locale (`src/locales/*.json:322`). `data.code` is never read.
- The change alters only the explanation shown, and arguably improves it. Not pinned: P02e has not landed,
  and P00 pins current behaviour.

**P00-F1 (pre-filed; re-verified; a leader defect, not an E.7 breach).** `leader/server.rs:868,872` read and
write `result.meta…`; the wire key is `_meta`, as the live-captured golden shows. The patch never fires, and
its tests (`server_tests.rs:1640-1697`) build the same wrong shape. **Recommendation (E.7a):** a separate
packet deletes the patch and its tests.

**Observations:**

- The brief's citation for the `session/new` -32000 (`acp_agent.rs:2288…`) points at `fuigo/cloud/*` gates.
  The live site is `agent_ops.rs:4301`.
- `tool_call` has no top-level `kind`/`status`; the kind lives in `_meta["fuigo/tool"]`.
- Clap skips value validation when `--help` is present.
- `--trust` is granted twice.
- A killed leader is respawned by its follower. Any test that might start a leader must kill the follower
  first.

## 7. Judgment calls

- **Rebase.** The branch was rebased onto `8d250586` as instructed, and the gate was re-run there.
- **Timebox.** The packet was not split, and nothing is deferred to a P00b.
- **Raw vs typed client.** Raw is used where the wire must be read verbatim; typed is used for the E.1 full
  turn, so both helpers have consumers.
- **T2 parses at the binary**, because `fuigo-shell` cannot depend on `fuigo-pager`.
- **Murage source (read only):** `core.ts` and `question-normalize.ts` at `34346be1` supplied the payloads,
  the fields Murage reads, and the reply shapes. The tests do not need a Murage checkout.
- **Stray leaders from my own runs.** Mutant/TV runs that predate the final reaper leaked three leaders. Each
  was killed by PID after confirming its `FUIGO_HOME` was that run's sandbox.
