# R023: TRIO-FINAL. The fuigo-shell suite is deterministic at the tip: three identical, empty failing sets

**Date:** 2026-10-01 (box UTC) · **Lane:** `trio2` on hetzner-dsm (`/root/fuigo-builds/trio2/`)
**Parent:** `cca0969f505de7ef04480e676b71782c94600a7d` (integration HEAD: P09 v3 + P17-R v3 landed)
**Tip:** `fe4df7799e47d8ac2d378cee535efcf3e1dc6302` (`strike/trio`, this receipt adds one docs commit on top)
**Not landed.** The coordinator lands.
**Integration moved to `8d250586`** while this ran: P04 and P18+P20 landed. They touch `fuigo-tools` and two receipts, with **no file in common with this
branch**, but `fuigo-tools` is a `fuigo-shell` dependency. All evidence here is at parent `cca0969f`, as the brief
specified. Rebasing onto `8d250586` makes a new tip, and that needs a new series.

Runs were made **under shared host load**: other strike lanes ran on the same box throughout (load average 80 to 116 on
96 threads; the slot runner went from 3 to 5 slots mid-session). Every test invocation went through
`/root/fuigo-builds/slot-run.sh trio2 …`, so this lane had a private `HOME` and never shared `~/.fuigo` with another lane.

## Verdict

**The acceptance is met.** Three consecutive complete `-p fuigo-shell` runs at the tip each exited 0. Each has 38/38
headers and 0 unfinished, and each has an **empty** failing set (sha256 `e3b0c442…b855` ×3). The three sets are
byte-identical, and the empty set is a subset of the parent union. **One caveat that only P38 can remove:** in the module stress, 4 of 40 iterations failed one
`session::workflow::manager::tests` test with P37's named wedge diagnosis (P29, §7). Every other module ran 40/40 clean. The parent `cca0969f` ran 4 times: 3 admissible
runs (6, 3 and 3 failures; a 9-name union), plus 1 inadmissible run killed by the coordinator in the pre-P38 manager
wedge.

**What it took beyond the brief's three named fixes.** P36 (accepted as production) makes `fuigo_home()` follow
`$FUIGO_HOME`. That fixed P24 as observed. It also means every `FUIGO_HOME` redirect is now visible to every test
running beside the writer. A throwaway instrumented build (§4) measured the effect: **179 writers, and 568 other
tests that saw two different homes inside their own lifetime**. One pair of those, `session::prompt_history`, failed
in a probe run. The class fix runs every writer of `FUIGO_HOME`, `HOME` or an endpoint variable in **a process of its
own** (208 tests). It is enforced: such a write from the shared process panics in the fuigo-shell lib binary.

## 1. Branch construction

`git -C wt-trio rebase cca0969f505de7ef04480e676b71782c94600a7d`. The rebase was textually clean (12/12). **Semantic
conflicts were found and resolved by new commits, not inside the rebase.**

* P17-R's five new trust-set tests (four in `agent/mvp_agent/tests.rs` via `p17r_without_ambient_env`, and
  `agent/config_tests.rs::an_empty_reload_table_discards_the_configured_trust_set`) unset the proxy **anchor** key
  through `crate::env::EnvVarGuard`. That guard's `ENV_LOCK` does not take the trio's anchor lock, so they bypassed P35's
  mechanism from plain `#[test]`s. Fixed in `f17e8f55`, then made moot by own-process isolation (`3ac05c29`).
* P09's new code adds no `FUIGO_HOME`/endpoint writers to the lib binary. Its integration test
  `tests/interrupted_turn_acp.rs` is a single-test binary.
* `manager.rs`: every hunk of the trio's diff is inside `mod tests`. This packet does not touch `fuigo-workflow` or the
  manager outcome code (P38/P38-F own them), and does not touch `auth/subscription/*` (P25).

| # | commit (tip ancestry) | from | what |
|---|---|---|---|
| 1-12 | `333a62de` … `1829651c` | R018 `bd318996` … `3fa0428b` | the trio, rebased unchanged (P35 ×3, P36 ×4, P37 ×3, resolution, R018) |
| 13 | `f5ba3889` | new | fix 1: 11 cache-identity tests `#[serial]` + `FUIGO_API_KEY`/`FUIGO_CODE_API_KEY` held unset |
| 14 | `4ee57cb0` | new | P28: `configured_endpoints_become_the_trusted_origins` `#[serial]`; remote-disarm test stops raw-writing the anchor key |
| 15 | `fcdc450e` | new | `tests/ext_invalid_params_acp.rs`: its two `run_agent_test` tests `#[serial]` |
| 16 | `ae6f59c9` | new | flock deadline-salvage test: release after the waiter subscribed (a load-induced parent failure) |
| 17 | `f17e8f55` | new | P17-R trust-set tests: `#[serial]` + proxy via `EnvGuard` |
| 18 | `07d7b157` | new | embedded OTEL fail-closed test owns the process-global gate (`fresh_process_home` child) |
| 19 | `0634b043` | new | `fuigo-test-support`: `rerun_in_own_process()`, `OWN_PROCESS_KEYS`, enforcement |
| 20 | `3ac05c29` | new | 205 writer tests run in their own process |
| 21 | `6c53488a` | audit HIGH-1 | 4 raw-loop endpoint writers run in their own process |
| 22 | `f8ce590d` | audit MEDIUM-2, LOW-3, LOW-4 | strict enforcement; `should_panic` documented; `fresh_process_home` captures child output |
| 23 | `fe4df779` | audit round-2 MEDIUM | `rerun_in_own_process` refuses a main/unnamed thread outside a child |

## 2. P36 `abe7e0bf` (here `77aa90d7`) is a PRODUCTION change, accepted by Sean, and reviewed as one

`fuigo_dirs::fuigo_home()` goes from a `OnceLock<PathBuf>` to a `Mutex<Option<HomeMemo>>` memo keyed on
`($FUIGO_HOME, home_dir())`. The decision is recorded in `decisions-for-sean.md` (decision 2). My review, as shipped
code:

* **Behaviour in a shipped binary is unchanged** unless the process rewrites `FUIGO_HOME`/`HOME`/`USERPROFILE` at
  runtime. I searched the workspace: every `set_var`/`remove_var` of those keys is in test code (`fuigo-dirs` tests,
  `fuigo-fast-worktree` `db` test fixture, `fuigo-pager` tests, `fuigo-mcp::isolate_fuigo_home_for_tests`
  (`#[doc(hidden)]`, test-only callers), `fuigo-pager-render` tests, `fuigo-shell` benches). So the memo resolves once
  and creates the directory once, as the `OnceLock` did. Astra's audit independently found no shipped runtime writer.
* **Cost:** every call now does two env reads plus a mutex (plus `getpwuid_r` when `HOME` is unset, via `home_dir()`).
  I found no call in a loop or a hot path (166 files call it; e.g. once per session in `run_loop.rs`). A miss holds the
  mutex across `create_dir_all`, which is bounded filesystem work.
* **Failure modes:** a poisoned mutex is recovered (`into_inner`). A failed `create_dir_all` is logged and the path is still
  memoised, the same as before. A directory deleted after the first call is not recreated, also the same as before.
* **Not atomic** with the env (it reads before it locks). That matters only to a process that rewrites `FUIGO_HOME`
  concurrently, and no shipped code does.
* **Residual risk:** the memo's tests cover redirect, restore and create, not concurrency or an OS-home change.
  `fuigo-pager`'s test `chat_resume_passthrough_keeps_cwd_collision_refusal` raw-sets `FUIGO_HOME` to a temp dir and
  never restores it. Under the `OnceLock` that was inert after the first call; under the memo, later `fuigo-pager` tests
  follow it into a deleted directory. **`fuigo-pager`, `fuigo-mcp` and `fuigo-fast-worktree` suites were not run by this
  lane (§9).**

## 3. The brief's named items

| item | status | evidence |
|---|---|---|
| 1. `reload_from_disk_cache_applies_external_catalog` | **fixed**, as briefed, plus its 10 siblings with the same double-identity pattern | `f5ba3889`; E2 (§6); 0 failures in 3 tip runs + stress |
| 2. P24 `worktree_heal_tests` | **fixed** by P36 (unpinned home) + P35 (anchor), and the wider class by own-process isolation | parent: fails in runs 1 and 4; tip: 0/3 + stress (§7) |
| 3. P28 `configured_endpoints_become_the_trusted_origins` | the trio fixed the **proxy** half (P35 anchor); **not** the other three keys it unsets, which needed `#[serial]` under `EnvGuard`'s contract. Fixed here; the test now also runs in its own process | `4ee57cb0`, `3ac05c29`; parent: fails in runs 1 and 3; E3 (§6) |
| 4. P29 manager deadlock | **not touched** (P38/P38-F). P37's bounded waits are in place at the tip | 0 manager failures in 3 tip runs; stress §7 |
| 5. `auth/subscription/*` (P25) | **not touched** | `cancelled_and_timed_out_login_release_listener` absent from all 3 tip runs (it is in R018's tip-3 set) |

**P28 proposal (not built; outside this packet's scope).** `EndpointsConfig::default()` (`agent/config.rs:535`) reads
about 20 environment variables (`FUIGO_CLI_CHAT_PROXY_BASE_URL`, `FUIGO_API_BASE_URL`, `FUIGO_MODELS_*`,
`FUIGO_DEPLOYMENT_KEY`, `OTEL_*`, …) **at `Default`/deserialize time**, and `from_config_value` calls it on every config
load. The consequences:
(a) parsing a TOML string is not a pure function. Every test that builds a `Config` silently depends on the process
environment, which is why this lane needed `OWN_PROCESS_KEYS`.
(b) the trust set's provenance mixes file and env inside serde. P17-R had to reason about "env fills only absent
fields" from the outside.
(c) a config reload reads whatever the environment says at reload time.
**Proposal:** deserialize `EndpointsConfig` with env-free defaults. Apply the env as an explicit overlay step,
`EndpointsConfig::apply_env(&EnvSnapshot)`, in the startup resolve and in `reapply_config_after_settings_refresh`.
`EnvSnapshot` is captured once at process start (production) or built by the test (tests). The overlay must keep
today's precedence exactly ("env fills a field the file left absent"), and must record env-sourced endpoints so that
`trusted_origins_from_endpoints` can say where an origin came from. Owner: whoever owns P17-R's config/trust area.
Effect: the 13 endpoint-writing tests could stop touching the process environment at all.

## 4. P24 class: every test that touches FUIGO_HOME, HOME or the endpoint vars without the matching key

**Writers (static scan).** I scanned fuigo-shell with `/tmp/trio2/envscan.py` (kept in the lane as
`trio2/envscan.py`). It finds `EnvGuard`, `FuigoHome`, raw `set_var`/`remove_var` (literal or through a variable or loop),
`crate::env::EnvVarGuard` and `isolate_fuigo_env`, and it resolves same-file helpers. Rule: an anchor key needs
`EnvGuard`/`FuigoHome`; any other key needs the unnamed `#[serial]`. **At the trio tip it found these lib-binary
violations, all fixed here:**

* `agent::config::tests::configured_endpoints_become_the_trusted_origins`: three non-anchor `EnvGuard`s, no `#[serial]` (P28)
* `agent::config::tests::remote_settings_disarm_requires_prod_proxy_when_keys_embedded`: raw `set_var` of the anchor
  key, in `#[serial(remote_sig_disarm)]` only. It set `https://attacker.example/v1` and never restored it.
* P17-R ×5 (§1): `EnvVarGuard` over the anchor and two non-anchor keys, no `#[serial]`
* `tests/ext_invalid_params_acp.rs` ×2: two `run_agent_test`s in one binary, unserialised (the harness says
  "one `#[test]` per binary")
* after the audit: `config::tests::enterprise_two_file_merge_routes_deployment_key_to_proxy`,
  `remote::model_source::oai::tests::models_fetch_endpoint_matches_auth_mode`,
  `agent::config::tests::aux_endpoints_resolve_to_proxy_never_inference`,
  `agent::config::tests::loader_managed_config_url_never_follows_inference_endpoint`. These remove keys in raw loops and
  never restore them (Astra HIGH-1; my first scan matched only literal keys).

The other integration-binary hits are single-test binaries whose harness sets env before any thread exists. Those are
not races.

**Readers (dynamic probe).** A reader of these variables takes no lock: it reaches them through production code. So
a static scan cannot see readers. I built an **instrumented copy of the tip (never committed)**: a probe in
`fuigo_dirs::fuigo_home`/`resolve_fuigo_home_with_source`/`home_dir`, in `read_fuigo_api_key_env`, in
`EndpointsConfig::default`, and in `EnvGuard` set/drop. It logs each event with its thread (libtest names a test's
thread after the test). I ran the lib binary 3× with the probe; the analysers are `trio2/probe_analyze.py` and
`probe_multi.py`. Results:

| measure | run 1 | runs 2+3 |
|---|---|---|
| tests that read `FUIGO_HOME` while ANOTHER test held a guard on it | 1403 | 1467 |
| … `HOME` | 9 | 11 |
| … `FUIGO_API_KEY` | 32 | 32 |
| … an endpoint var | 114 | 137 |
| tests holding a `FUIGO_HOME` guard (writers) | 179 | 179 |
| unguarded tests reading `FUIGO_HOME` ≥2 times (any run) | 1884 | |
| … of which **observed two different homes in their own lifetime** | **568** | |

Probe-run failures: run 1 `embedded_otel_gate…` (§5); run 2 none; run 3 `embedded_otel_gate…` plus
**`session::prompt_history::tests::{test_load_bash_prompts_filters_correctly, test_load_prompts_for_session_filters_by_session_id}`**.
Those two wrote their fixture under one home and read back under another; the probe shows them reading during
`agent_rebuild`/`managed_mcp` `FuigoHome` windows. That is P24's mechanism in its general form.

**Fix (the class, not the list).** Annotating 1884 readers is not tractable, so the 208 writers move out of the shared
process instead. `fuigo_test_support::env::rerun_in_own_process()` re-execs the calling test (its libtest thread
name, `--exact --include-ignored --test-threads=1`) in a child of the test binary, captures the output, checks an
"entered" marker so a zero-match filter cannot pass, and returns `true` in the parent. `OWN_PROCESS_KEYS` lists
`FUIGO_HOME`, `HOME`, `USERPROFILE` and all 21 `EndpointsConfig` env vars. In the `fuigo_shell` lib binary,
`EnvGuard::acquire` panics on one of those keys unless it is running in such a child (`FUIGO_TEST_OWN_PROCESS`).
`rerun_in_own_process` itself panics on a main/unnamed thread outside a child, because libtest's `WouldBlock`
fallback means "main" is not "alone". `fresh_process_home` children count as own-process. Other crates' binaries keep
their contract. With every writer in a child, the shared process's home, OS home and endpoints are constant for
the whole run.

**The list (208 tests, every one now starts with the early return; plus `embedded_otel_gate…`, isolated through `fresh_process_home`):** see Appendix A. The 13 `cli_models` deployment-key
tests and the 8 `HOME` writers are included. `FUIGO_API_KEY` writers stay in-process under the unnamed `#[serial]`
contract; fix 1 covers their readers.

## 5. Other flakes found and fixed (test-only)

* **`agent::app::tests::embedded_otel_gate_keeps_a_session_user_fail_closed`** (4 earlier sightings on the box; probe
  runs 1 and 3; parent runs 3 and 4). It asserts ONE process-global flag. Any test that authenticates an `MvpAgent`
  opens that flag (`spawn_post_auth_settings` → `OtelGate::resolve`), as do `run_leader`/`run_stdio_agent`. `#[serial]`
  cannot cover that. The test body now runs in a `fresh_process_home` child (`07d7b157`).
* **`auth::manager::lock::flock_wait::tests::freed_flock_at_the_deadline_is_acquired_through_the_public_api`** (parent
  run 1: "took 171.967907ms" against a 300 ms budget; first sighting on the box). The releaser slept a fixed 50 ms and
  assumed the acquirer's first attempt ran inside it. Under load, the attempt found the lock already free. The test now
  releases once the acquirer holds a `Ticket` (strong count 3), and the budget is 1 s (`ae6f59c9`). This is
  `auth/manager/lock`, not `auth/subscription`.

## 6. Mutants (race fixes need a race: one adversary build, fixed vs reverted)

Behavioural fixes for races cannot be reverted and then run plain, because the race is rare. So the experiment patch
`trio2/adv_patch.py` (never committed) adds an adversary per race, and the same filters run 10× at
`--test-threads=96` in two builds: **A = `3ac05c29` (fixed)** and **B = `1829651c` (R018 tip: no trio2 fix = the mutant)**.
Adversaries: E1 a `FuigoHome` toggled every 300 µs for 5 s (a compliant own-process writer in A, in-process in B); E2 a
`#[serial]` `FUIGO_API_KEY` toggler; E3 a `#[serial]` `FUIGO_MODELS_BASE_URL` toggler (own process in A); E4 a
non-serial loop opening the OTEL gate; E5 a 200 ms deschedule injected before the flock test's first acquire.
Each iteration took its own slot. The first attempt (`mutants.sh`) ran 10 iterations inside one slot, and its session
disappeared at 02:02 UTC after A-E1 and 8 iterations of A-E2. I assume the coordinator killed it under its new
no-loops-in-a-slot rule. `mutants2.sh` redid the rest with one slot per iteration.

| exp | race | A = fixed `3ac05c29` (clean / 10) | B = mutant `1829651c` (clean / 10) | B failing names (count over 10 runs) |
|---|---|---|---|---|
| E1 | a `FUIGO_HOME` redirect seen by readers (P24 class, own-process fix) | **10/10** | **0/10** | `prompt_history::tests::test_load_bash_prompts_filters_correctly` ×10, `…test_load_prompts_for_session_filters_by_session_id` ×10, `…test_append_prompt_async_round_trips_for_session` ×6, `…test_append_and_load` ×5, `…test_load_bash_prompts_deduplicates` ×1 |
| E2 | `FUIGO_API_KEY` flipping between two identity computations (fix 1) | **10/10** | **0/10** | `reload_from_disk_cache_resolves_default_on_first_catalog` ×6, `…applies_external_catalog` ×4, `…recomputes_allowlist_excludes_all` ×4, `disk_cache_reload_applies_without_fetching` ×4, `cache_identity_uses_the_same_auth_accessor_as_the_write_paths` ×4, `models_cache_identity_tracks_the_credential_without_naming_it` ×1, `…skips_identical_catalog_and_adopts_etag` ×1 |
| E3 | a serial endpoint writer vs P28's test | **10/10** | **5/10** | `configured_endpoints_become_the_trusted_origins` ×5 |
| E4 | a concurrent opener of the OTEL gate | **10/10** | **0/10** | `embedded_otel_gate_keeps_a_session_user_fail_closed` ×10 |
| E5 | a 200 ms deschedule before the flock test's first acquire | **10/10** | **0/10** | `freed_flock_at_the_deadline_is_acquired_through_the_public_api` ×10 |

Every fix is load-bearing: each one's removal makes its target fail under its race, and with the fix in place the same race does nothing. Not mutant-tested: the P17-R `#[serial]`/anchor change (`f17e8f55`, now subsumed by own-process isolation), `ext_invalid_params_acp` `#[serial]` (`fcdc450e`), and the main/unnamed-thread refusal (`fe4df779`, verified by inspection, §11). Logs: `trio2/mutants/{A,B}-E*-*.log`.

## 7. Stress at the tip (lib binary, `--test-threads=96`, 40 runs per filter, one slot per run, 600 s bound)

Every filter was checked against `--list` before running. A filter that matches 0 tests is reported, not run.

The first pass (`gate.sh`, one module per filter) finished `agent::config::tests::` (353 tests): 40/40 clean. Queued
for slots, the rest would have taken about 10 hours, so I stopped that session (`pkill -s`) and ran `stress2.sh`
instead. Each of 40 iterations runs ALL 28 filters (1445 distinct tests) in one invocation at `--test-threads=96`, one
slot per iteration. So every module ran 40× at 96 threads, alongside the others.

Filters (tests matched): `agent::init::tests::` 2, `agent::models::startup_prefetch::tests::` 9, `agent::app::tests::` 23,
`inspect::tests::` 25, `session::managed_mcp::tests::` 26, `session::worktree::tests::` 37,
`session::storage::jsonl::worktree_heal_tests::` 12, `util::config::consent::tests::` 3, `agent::mvp_agent::tests::` 304,
`workflow_write_smoke_check` 9, `session::agent_rebuild::tests::` 3, `rewind_cross_compaction_tests::` 5,
`session::worktree_pool::tests::` 2, `inline_auto_compact_flow_tests::` 53, `notification_drain` 10,
`extensions::session_updates::tests::` 11, `auth::manager::lock::` 32, `session::workflow::registry::tests::` 15,
`agent::folder_trust::` 42, `session::workflow::manager::tests::` 31, `agent::models::tests::` 91,
`session::prompt_history::tests::` 10, `config::tests::` 607 (includes `agent::config::tests::`),
`remote::model_source::oai::tests::` 1, `remote::client` 52, `util::config::mcp_reenable::tests::` 6,
`extensions::skills::tests::` 10, `cli_models::tests::` 14.

| result | count |
|---|---|
| iterations clean | **36 / 40** |
| iterations with a failure | 4 (iterations 4, 10, 18, 28), one failing test each, 0 timeouts |
| failures **outside** `session::workflow::manager::tests` | **0**. Every other module: 40/40 |
| `manager::tests::cancel_drops_queued_spawns_before_coordinator` | 2 (iterations 4, 18): "waited 40s for the run's WorkflowOutcome and it never arrived" (`manager.rs:2452`) |
| `manager::tests::active_run_admission_is_bounded_per_session` | 2 (iterations 10, 28): "runtime could not be torn down within 15s: 1 blocking thread … parked in `release_agent_calls`" (`manager.rs:972`) |

All four are **P29**: P37's bounded waits naming the `fuigo-workflow` `release_agent_calls` wedge, which **P38 fixes and
this packet must not touch**. The rate (4 module-failures in 40 runs, one 31-test module) is in line with R018's 5/150.
**Consequence for acceptance:** a full suite run at this tip can still fail one manager test at about this rate until
P38 lands. It did not happen in the three tip runs. Logs: `trio2/stress2/run-*.log`, `trio2/stress2.out`.

## 8. Gate (contract A.2.1)

Derived counts (`derive.py`): fuigo-shell **38** (`exe=37 doc=1`) at parent and tip; fuigo-dirs **2** (`exe=1 doc=1`).
Awk header check = `<derived> 0` on every admissible run. Exit is never a signal (`grep -c signal:` = 0), and the DONE
marker is present. Failsets are in `/root/fuigo-builds/trio2-{parent,tip}-*-fuigo-shell.failset`.

| run | rev | exit | hdr / unfinished | failing set | failset sha256 | log sha256 | admissible |
|---|---|---|---|---|---|---|---|
| parent-shell-1 | `cca0969f` | 101 | 38 / 0 | 6: `configured_endpoints_become_the_trusted_origins`, `freed_flock_at_the_deadline…`, `worktree_heal_tests::init_session_load_backfills_worktree_identity_on_untagged_summary`, `session::worktree::tests::{cleanup_worktree_on_failure_removes_created_worktree, create_worktree_for_resume_honors_git_ref, create_worktree_for_resume_produces_independent_worktree}` | `ad266a83…` | `30a32578…` | yes |
| parent-shell-2 | `cca0969f` | 101 | (38 / 0) | n/a | n/a | `04c8c4de…` | **NO**: the coordinator killed the lib binary (SIGTERM) after ~35 min wedged at 0 CPU in `session::workflow::manager::tests`, the pre-P38 defect. The awk check printed `38 0` anyway, because child `test result:` lines close the header (R018 warned) |
| parent-shell-3 | `cca0969f` | 101 | 38 / 0 | 3: `embedded_otel_gate…`, `configured_endpoints…`, `startup_prefetch::tests::wait_settings_leaves_the_fetch_for_accept` | `a2ef7e75…` | `31c86ec7…` | yes, **with `--skip session::workflow::manager::tests`** (coordinator instruction) |
| parent-shell-4 | `cca0969f` | 101 | 38 / 0 | 3: `embedded_otel_gate…`, `managed_mcp::tests::toml_claim_survives_when_client_cursor_insert_skipped`, `worktree_heal_tests::init_session_load_backfills…` | `787b08bf…` | `9670c021…` | yes, **with `--skip session::workflow::manager::tests`** |
| **tip-shell-1** | `fe4df779` | **0** | 38 / 0 | **∅** | `e3b0c442…b855` | `cc70e76e…` | yes |
| **tip-shell-2** | `fe4df779` | **0** | 38 / 0 | **∅** | `e3b0c442…b855` | `8c3b14c4…` | yes |
| **tip-shell-3** | `fe4df779` | **0** | 38 / 0 | **∅** | `e3b0c442…b855` | `cf5387a3…` | yes |
| parent-dirs | `cca0969f` | 0 | 2 / 0 | ∅ (5 passed) | `e3b0c442…` | `d02ba346…` | yes |
| tip-dirs | `fe4df779` | 0 | 2 / 0 | ∅ | `e3b0c442…` | `b248ac94…` | yes |

Parent union (runs 1, 3, 4): 9 names, sha256 `10b4a63a…`. Tip ⊆ parent: trivially (∅). The lib binary holds 7232 tests at
the parent and 7238 at the tip; the trio adds 6 (33 test attributes added and 27 removed in `src/`, mostly P37's
manager rework). Tip lib result, all three runs: `7231 passed; 0 failed; 7 ignored`. Each tip log has 40 `test result:`
lines, against 52 at the parent: `fresh_process_home` children no longer print into the cargo log (audit LOW-4). Two
child lines remain, from pre-existing subprocess-driving tests.

Full log sha256s: parent-shell-1 `30a325780165ecff766fc6eca9ed481e73b74e2a684c6b539df7ca5fe01ad016`,
parent-shell-2 `04c8c4ded64fd00209a7bcbd9b91b1f42ea1de77eeb1d6cdfe89bd7d12e06b77`,
parent-shell-3 `31c86ec7c0cbc8c0a2cbd5c849085f8681dd06274fe42bbc739e1e058c8dfdc6`,
parent-shell-4 `9670c0216a7124e167274cd6b5ac5a3dfa4db048c1226af4fb7c7c8feba691d5`,
tip-shell-1 `cc70e76e82f64a7de483ca5c331cfe526ce1fe192dc7eee6bc7956e01513e074`,
tip-shell-2 `8c3b14c44904fa0945f65afb5bd05e7060398f8ef7004c2e5cf4c811e471b545`,
tip-shell-3 `cf5387a3abcefdb259c0d9db682be1f4b875cec24c7771fd3e09328f5128b0bd`,
parent-dirs `d02ba346bdd838d3b50a199a3787ecc57d66b9605f498c0e3f28c34330c7ca78`.

Also run (not gate packages, sanity): `-p fuigo-test-support -p fuigo-dirs` and `--test ext_invalid_params_acp` at
`3ac05c29` and `f8ce590d`: all exit 0.

**Clippy** `--locked --all-targets -p fuigo-shell -p fuigo-dirs`: parent and tip both exit 0. Warnsets keyed by message + file, with worktree prefixes normalised: parent 23, tip 23, **new 0, gone 0**. Log sha256: parent `7e330826…f590`, tip `00eab5a3…d7d`.
`-p fuigo-test-support` (changed crate): 0 warnings at parent and tip.

Commands, verbatim (env for all: `RUST_MIN_STACK=16777216 RG_BIN_PATH=/usr/bin/rg CARGO_TERM_COLOR=never CARGO_BUILD_JOBS=16`,
`CARGO_TARGET_DIR=<lane>/target` (tip) or `<lane>/target-parent`, builds `nice -n 10`; toolchain read in-tree:
`rustc 1.94.0 (4a4ef493e 2026-03-02)`, LLVM 21.1.8, host x86_64-unknown-linux-gnu):
```
/root/fuigo-builds/slot-run.sh trio2 nice -n 10 timeout 3600 cargo test --locked --no-fail-fast -p fuigo-shell > LOG 2>&1; echo "DONE rc=$?" >> LOG
/root/fuigo-builds/slot-run.sh trio2 nice -n 10 timeout 3600 cargo test --locked --no-fail-fast -p fuigo-shell -- --skip session::workflow::manager::tests   # parent runs 3-4
/root/fuigo-builds/slot-run.sh trio2 nice -n 10 timeout 1800 cargo test --locked --no-fail-fast -p fuigo-dirs
cargo test --locked -p <pkg> --no-run --message-format=json | P=<pkg> python3 /root/fuigo-builds/derive.py
nice -n 10 cargo clippy --locked --all-targets -p fuigo-shell -p fuigo-dirs
/root/fuigo-builds/slot-run.sh trio2 nice -n 10 timeout 600 <tip lib binary> --test-threads=96 <filter>   # stress, ×40
```
Scripts: `trio2/{parent.sh,parent2.sh,probe.sh,probe_patch.py,focus.sh,mutants.sh,mutants2.sh,adv_patch.py,gate.sh}`.

## 9. Pre-gate audit (Astra, `codex exec --model gpt-6-astra --sandbox read-only`, from the Mac)

| round | audited | verdict | findings → action |
|---|---|---|---|
| 1 | `3ac05c29` + P36 as production | DO-NOT-LAND | **HIGH-1** 4 raw-loop endpoint writers lacked isolation → real, fixed `6c53488a` (and the scanner now counts variable-key writes); **MEDIUM-2** helper/enforcement permissive on main/unnamed threads (libtest `WouldBlock` fallback) → real, fixed `f8ce590d`; **LOW-3** `#[should_panic]` incompatibility → real, latent (no caller), documented; **LOW-4** `fresh_process_home` child output pollutes the cargo log → real, fixed. P36 production: "no additional concrete landing blocker" |
| 2 | `f8ce590d` | DO-NOT-LAND | **MEDIUM** residual: `rerun_in_own_process` still returned `false` on main/unnamed outside a child, so raw writers could run under the fallback → real, fixed `fe4df779`. HIGH-1/LOW-3/LOW-4 confirmed closed |
| 3 | `fe4df779` | **LAND** | round-2 MEDIUM closed; all 208 callers checked (first statement, none `should_panic`); no new BLOCKER/HIGH |

Audit outputs: `/tmp/trio2/audit-astra-{1,2,3}.txt` on the Mac (copied to the lane as `trio2/audit-astra-*.txt`).

## 10. Process notes (deviations, stated plainly)

* I used **`pkill -f` once**, against my own stuck waiter loop on the box (`while pgrep -f …` matched itself). The
  pattern was that loop's literal text, so it could match only that loop and the shell that ran it. It ran at 02:28 UTC;
  the first mutants script had already disappeared at 02:02. No lane other than trio2 was affected, as far as `ps` shows.
* The first parent script ran parent runs 1-2 without `--skip`. Run 2 wedged (above).
* The probe and experiment builds used `target-probe`. Disk on the box fell to 230 GB free (87%) during the session
  because of other lanes.

## 11. Unverified

* **Other crates under P36 and under the `fuigo-test-support` change.** I did not run `fuigo-pager`, `fuigo-mcp`,
  `fuigo-fast-worktree` or `fuigo-workspace`. `fuigo-pager` has an unrestored raw `FUIGO_HOME` writer (§2) that P36's
  memo now follows. The `fuigo-test-support` change is inert outside the `fuigo_shell` lib binary, except that
  `fresh_process_home` children now get `FUIGO_TEST_OWN_PROCESS` and capture their output (one `fuigo-pager` caller;
  Astra round 3 found nothing depending on inherited output).
* **Readers of non-own-process keys.** `FUIGO_API_KEY` (32 probe readers) and about 30 other `FUIGO_*` keys keep the
  `#[serial]` contract. A non-serial reader still sees a serial writer's value. None failed in any run here, but the
  probe shows the exposure.
* **Children inherit the parent's environment at spawn time.** That includes any non-own-process guard another test
  holds at that instant. This is the same exposure the test had in-process.
* **The manager wedge (P29) at the tip.** It did not fire in 3 full runs. It fired in 4 of 40 stress iterations (§7),
  always as P37's named diagnosis. P38 is the fix. Until P38 lands, a fourth full run could differ.
* **`--network none`** was not used (host network, as R018, for comparability).
* The libtest main-thread fallback path of `rerun_in_own_process` is verified by inspection (Astra round 3), not by a test.
* Time and rate: none of the newly fixed flakes has a measured pre-fix rate beyond its sightings and the adversary
  experiments.

## Appendix A: the 208 tests that run in their own process

Paths are under `crates/codegen/fuigo-shell/`.

- `src/agent/config_tests.rs` (5): `configured_endpoints_become_the_trusted_origins`, `an_empty_reload_table_discards_the_configured_trust_set`, `aux_endpoints_resolve_to_proxy_never_inference`, `loader_managed_config_url_never_follows_inference_endpoint`, `remote_settings_disarm_requires_prod_proxy_when_keys_embedded`
- `src/agent/folder_trust.rs` (28): `grant_folder_trust_seeds_decisions_cache`, `revoke_folder_trust_downgrades_cache`, `revoke_never_trusted_folder_writes_no_deny`, `revoke_on_unrecordable_home_root_records_no_deny`, `envrc_gate_drops_untrusted_then_loads_when_store_trusted`, `claude_env_gate_drops_project_env_when_untrusted`, `claude_env_gate_drops_subdir_project_env_when_untrusted`, `project_agent_inline_hooks_gated_when_untrusted_but_user_kept`, `project_scope_allowed_denies_untrusted_repo_with_configs`, `project_scope_allowed_allows_repo_without_configs`, `project_scope_allowed_allows_store_trusted_repo`, `project_scope_allowed_allows_inert_local_build`, `project_scope_allowed_denies_untrusted_plugin_only_repo`, `project_scope_allowed_denies_untrusted_permission_only_repo`, `project_scope_allowed_denies_untrusted_instruction_only_repo`, `project_scope_allowed_denies_untrusted_skill_only_repo`, `project_scope_allowed_denies_workspace_user_only_instructions`, `kill_switch_allows_untrusted_repo_after_authoritative_resolve`, `build_for_cwd_with_trust_verdict_gates_active_project_plugin`, `discover_hooks_gates_then_loads_project_hook_via_trust_verdict`, `claude_json_project_mcp_is_covered_by_the_project_scope`, `claude_json_entries_for_another_cwd_are_not_project_scoped_here`, `resolve_launch_dir_trust_matches_resolve_and_record`, `local_build_is_inert_launch_trust_auto_trusts`, `prompt_warranted_true_for_untrusted_repo_with_configs`, `prompt_warranted_false_when_feature_disabled`, `prompt_warranted_false_when_store_trusted`, `prompt_warranted_false_without_repo_configs`
- `src/agent/init_tests.rs` (2): `post_gate_pass_spends_at_most_one_settings_budget`, `supplied_settings_consume_the_pending_fetch`
- `src/agent/models/startup_prefetch_tests.rs` (9): `begin_does_not_replace_an_inflight_fetch`, `accept_discards_a_fetch_from_another_origin`, `accept_deadline_spends_the_budget`, `abandoned_fetch_commits_caches_when_the_worker_finishes`, `fallback_fetch_honors_the_caller_deadline`, `stale_origin_fetch_is_discarded_without_waiting`, `no_auth_boot_is_not_a_degraded_start`, `attempted_settings_fetch_failure_is_a_degraded_start`, `wait_settings_leaves_the_fetch_for_accept`
- `src/agent/mvp_agent/tests.rs` (22): `ensure_plugin_registry_lazily_populates_snapshot`, `search_index_honors_the_session_search_feature`, `auto_gc_declines_until_the_remote_answer_settles`, `search_before_the_decision_asks_the_caller_to_retry`, `read_before_the_remote_settings_land_does_not_decide`, `exhausted_fetch_decides_on_the_local_layers`, `kill_switch_after_the_decision_leaves_the_index_up`, `session_opened_before_the_decision_sees_it_land`, `subagent_spawn_context_reloads_project_definitions_after_trust_changes`, `project_roles_personas_gated_via_resolve_and_record_chain`, `interactive_trust_prompt_grant_reloads_project_mcp`, `interactive_trust_prompt_reject_keeps_gated`, `interactive_trust_prompt_dormant_when_feature_off`, `interactive_trust_prompt_no_request_without_capability`, `interactive_trust_prompt_client_error_fails_closed`, `interactive_trust_prompt_dedups_same_workspace`, `interactive_trust_prompt_reloads_all_same_workspace_sessions`, `interactive_trust_prompt_reprompts_after_untrust`, `a_failed_config_read_during_settings_refresh_keeps_the_configured_trust_set`, `a_failed_config_read_still_applies_freshly_fetched_remote_settings`, `a_failed_config_read_does_not_resurrect_a_withdrawn_remote_campaign`, `a_failed_config_read_before_any_successful_read_leaves_the_config_alone`
- `src/agent/mvp_agent/tests/list_running_heal_tests.rs` (4): `list_running_subagents_finalizes_orphan_on_live_session`, `list_running_subagents_skips_live_coordinator_child`, `release_evicts_the_registry_heal_lock`, `registry_heal_lock_reuses_the_same_arc_until_release`
- `src/agent/mvp_agent/tests/session_rename_tests.rs` (14): `rename_enqueues_manual_title_on_resident_persistence_tx`, `rename_non_resident_updates_summary_without_panic`, `rename_strips_ascii_controls_before_persist_and_enqueue`, `rename_rejects_title_over_max_scalars`, `rename_counts_scalars_after_control_strip`, `rename_rejects_overlong_after_control_strip`, `rename_rejects_title_over_max_bytes_before_strip`, `rename_fanout_stamps_title_is_manual_meta`, `reset_enqueues_reset_title_to_auto_on_resident_persistence_tx`, `reset_non_resident_updates_summary_without_panic`, `reset_rejects_nonempty_title`, `reset_rejects_chat_kind`, `reset_fanout_stamps_title_is_manual_false`, `reset_already_auto_is_idempotent_and_skips_persistence_msg`
- `src/agent/otel_gate.rs` (1): `configured_policy_authority_waits_and_rearms`
- `src/cli_models.rs` (13): `resolve_api_key_env`, `resolve_legacy_api_key_env`, `resolve_oauth_session`, `resolve_model_api_key_byok`, `resolve_model_env_key_byok`, `resolve_deployment_key`, `resolve_not_authenticated`, `resolve_priority_api_key_over_byok_and_deployment`, `resolve_priority_session_over_byok_and_deployment`, `resolve_priority_byok_over_deployment`, `resolve_disable_api_key_auth_suppresses_byok_banner`, `resolve_disable_api_key_auth_falls_through_to_deployment`, `resolve_model_credentials_uses_first_catalog_key`
- `src/config/tests.rs` (5): `enterprise_two_file_merge_routes_deployment_key_to_proxy`, `project_config_never_sources_feedback_user`, `resolve_effective_plugins_config_gates_project_paths_on_folder_trust`, `discover_plugins_excludes_untrusted_configpath_plugin_end_to_end`, `kill_switched_cold_cwd_stays_allowed_through_plugins_config_read`
- `src/extensions/session_updates.rs` (11): `handle_tail_request_matches_expected_tail_window`, `handle_tail_request_with_rewind_returns_only_live_timeline`, `handle_falls_back_to_id_lookup_for_divergent_cwd`, `stream_sends_correct_chunks`, `stream_empty_session_returns_metadata_shape`, `turn_index_returns_last_n_turns`, `turn_index_exceeding_turns_returns_all`, `turn_index_with_rewinds`, `turn_index_ignored_when_offset_set`, `prompt_starts_included_in_regular_response`, `prompt_starts_in_streamed_metadata`
- `src/extensions/skills.rs` (1): `test_resolve_tilde_path`
- `src/remote/client_tests.rs` (1): `deployment_config_url_uses_cli_chat_proxy_when_not_overridden`
- `src/remote/model_source/oai.rs` (1): `models_fetch_endpoint_matches_auth_mode`
- `src/remote/pull.rs` (1): `hydrated_summary_stamps_worktree_identity_for_worktree_cwd`
- `src/session/acp_session_impl/notification_drain.rs` (7): `emit_session_idle_finalizes_orphan_and_persists_finish`, `emit_session_idle_skips_live_coordinator_child`, `emit_session_idle_skips_reconcile_while_suppressed`, `list_running_subagents_finalizes_orphan_and_persists_finish`, `list_running_subagents_skips_live_coordinator_child`, `maybe_drain_finalizes_orphan_while_parent_turn_running`, `maybe_drain_throttles_live_orphan_reconcile`
- `src/session/acp_session_impl/workflow_write_smoke_check_tests.rs` (3): `valid_written_workflow_needs_no_warning`, `invalid_authored_workflow_returns_path_specific_warning`, `parse_failure_is_returned_during_snapshot`
- `src/session/acp_session_tests/rewind_cross_compaction_tests.rs` (1): `rewind_succeeds_in_forked_session_with_compaction_checkpoint`
- `src/session/agent_rebuild.rs` (1): `untrusted_cwd_omits_project_instructions_and_skills`
- `src/session/compaction_inline_auto_compact_flow_tests.rs` (32): `fork_reload_second_compaction_preserves_authority`, `suppression_gates_and_reset_is_reason_scoped`, `suppression_gates_prefire_two_pass`, `model_switch_clears_sticky_suppression`, `model_switch_keeps_account_state_suppression`, `auth_suppress_clears_on_credential_recovery`, `clear_auth_suppress_leaves_credit_suppress`, `clear_auth_suppress_rearms_pre_sampling_compact_gate`, `is_auth_compact_error_classifies_401_messages`, `surface_compact_auth_failure_emits_reauthable_retry_state`, `suppression_notification_message_is_reason_specific`, `suppression_emits_composed_notification`, `family_switch_compacts_lossy_with_new_model`, `e2e_auto_compact_401_suppresses_auth_and_surfaces_reauth`, `e2e_auto_compact_413_steps_ladder_then_sticky_size_suppress`, `e2e_model_switch_compact_401_surfaces_reauth`, `e2e_model_switch_compact_non_auth_failure_does_not_abort`, `clear_auth_suppress_allows_model_switch_compact_reeval`, `bare_manual_compact_failure_does_not_suppress_auto`, `transient_auto_compact_failure_notifies_with_real_error`, `compaction_rearms_failed_server_announcements`, `forked_prefix_released_under_pressure_and_stays_released`, `compaction_validation_requires_observed_pressure_reduction`, `forked_release_still_over_threshold_suppresses_auto`, `cancelled_error_is_typed_and_extracts_to_cancel_text`, `compact_error_data_scrubs_and_caps_raw_producer_input`, `user_facing_compact_error_strips_prefix_single_lines_and_caps`, `classify_suppress_reason_maps_error_text`, `suppress_reason_as_str_is_stable`, `test_pre_sampling_uses_estimated_tokens`, `test_model_switch_compaction_triggers_on_downgrade`, `get_transcript_path_returns_some_when_file_exists`
- `src/session/managed_mcp.rs` (14): `client_provided_servers_survive_merge`, `admit_renames_reverse_dns_client_servers`, `admit_is_identity_for_well_formed_client_names`, `admit_suffixes_a_renamed_server_that_collides`, `admit_blocks_by_raw_name_before_renaming`, `client_cursor_server_dropped_when_cursor_mcps_disabled`, `client_cursor_server_kept_when_cursor_mcps_enabled`, `unrelated_client_server_survives_when_cursor_mcps_disabled`, `toml_claim_survives_when_client_cursor_insert_skipped`, `admitted_seed_stays_blocked_after_vendor_disk_vanishes`, `client_cursor_http_dropped_by_normalized_url_when_mcps_disabled`, `same_url_different_names_both_survive_merge`, `same_url_different_names_both_sourced_from_toml`, `untrusted_workspace_drops_project_mcp_servers`
- `src/session/persistence_worktree_stamp_tests.rs` (3): `summary_new_stamps_kind_label_and_source_for_worktree_cwd`, `summary_new_leaves_worktree_fields_unset_for_plain_cwd`, `new_with_explicit_dir_overrides_worktree_stamp_so_subagent_stays_hidden`
- `src/session/storage/jsonl/copy_tests.rs` (2): `fork_with_default_kind_into_worktree_cwd_stamps_worktree_identity`, `explicit_subagent_fork_kind_wins_over_worktree_target_cwd`
- `src/session/storage/jsonl/worktree_heal_tests.rs` (12): `list_sessions_repairs_untagged_worktree_summary_in_rows_and_on_disk`, `list_sessions_fills_missing_label_on_kinded_fork_without_changing_kind`, `list_sessions_leaves_kinded_labeled_worktree_summary_untouched`, `list_sessions_leaves_untagged_summary_outside_worktrees_untouched`, `repair_keeps_summary_untagged_when_locked_write_fails`, `repair_adopts_kinded_summary_when_mtime_restore_fails`, `init_session_load_backfills_worktree_identity_on_untagged_summary`, `init_session_load_leaves_untagged_summary_outside_worktrees_untouched`, `init_session_load_fills_missing_label_on_kinded_fork_without_changing_kind`, `list_sessions_recent_fills_missing_label_on_kinded_fork_without_changing_kind`, `list_sessions_recent_repairs_untagged_worktree_summary_in_rows_and_on_disk`, `list_sessions_heal_does_not_evict_recent_sessions_from_mtime_window`
- `src/session/workflow/registry.rs` (1): `project_workflows_follow_folder_trust`
- `src/session/worktree.rs` (5): `resume_in_worktree_falls_through_to_remote_when_not_found_locally`, `create_worktree_for_resume_produces_independent_worktree`, `create_worktree_for_resume_honors_git_ref`, `cleanup_worktree_on_failure_removes_created_worktree`, `worktree_base_dir_extracts_repo_name`
- `src/session/worktree_pool.rs` (2): `test_pool_base_directory`, `test_cleanup_stale_only_removes_dead_instances`
- `src/util/config/consent_tests.rs` (2): `set_consent_answer_is_monotonic_per_account`, `consent_write_lands_in_the_guarded_home`
- `src/util/config/mcp.rs` (1): `load_cli_plugin_registry_includes_project_config_path_plugins`
- `src/util/config/mcp_reenable.rs` (4): `orphan_fuigo_com_name_is_not_a_definition`, `build_indexes_toml_enabled_false`, `discover_contains_merge_when_nothing_disabled`, `toml_duplicate_url_both_kept_matches_merge`

