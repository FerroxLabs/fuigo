# R012 — the `fuigo-shell` failing set churned for one reason, in four places

> **Numbering note:** written as R009 and renumbered to **R012** by the integrator. Four packets
> reported within a few hours and three of them independently claimed the next free number.
> Settled by landing order: R008 header-gate regression, R009 P12b-R, R010 P02a-R,
> R011 killed-run-reports-green, R012 this one. Nothing here depends on the number.


**Date:** 2026-09-30 · **Base:** `8e1172417` · **Fix:** `f9d75f6f` (`strike/p35`) · **Box:** hetzner-dsm
**Lane:** `/root/fuigo-builds/lane-p13` · `CARGO_TARGET_DIR=/root/fuigo-builds/lane-p13/target`

R008 §5 recorded that two identical full `-p fuigo-shell` runs at `8e11724` disagreed — 16 failures
then 18, churn +3/−1 — and concluded that until the churning clusters are hermetic, no packet in this
strike can produce a trustworthy full-suite failing-set diff.

**This receipt closes the four names R008 named, and two more, and does not close the suite.** The
measured churn is gone; a residual tail of pre-existing flakes, plus one liveness hang that produces
no failing set at all, is named in §9 and handed back. Read §5 before quoting any number from here.

The packet brief listed five candidate causes. **There is one cause**, and it appears in four
different globals: process-wide mutable state — three environment variables and one `static` — read
or written by tests whose exclusion does not cover every toucher of it. Of the brief's five, two
describe that one cause from different angles, one is a real property of the code that is not what
moved the failing set, one is refuted by measurement, and one is half right. §3 takes them one by
one.

## 1. What actually churned

The two P09 runs are on the box as `p09-base-fuigo-shell.failset` (16) and
`p09-base2-fuigo-shell.failset` (18). Their exact difference:

```
- session::storage::jsonl::worktree_heal_tests::list_sessions_heal_does_not_evict_recent_sessions_from_mtime_window
+ session::storage::jsonl::worktree_heal_tests::init_session_load_fills_missing_label_on_kinded_fork_without_changing_kind
+ session::worktree::tests::cleanup_worktree_on_failure_removes_created_worktree
+ session::worktree::tests::create_worktree_for_resume_produces_independent_worktree
```

**Four names, all in one family.** The other 15 names are identical in both runs.

**Correction to the brief.** It listed a second churning family —
`auth::subscription::tests::cancelled_and_timed_out_login_release_listener`,
`agent::models::startup_prefetch::tests::no_auth_boot_is_not_a_degraded_start`,
`session::acp_session::auth_error_no_retry_tests::sampler_401_recovery_returns_refresh_and_retry`.
**None of those three appears in either baseline failset.** They come from
`p09-gate-fuigo-shell.failset`, which is a run at `strike/p09` — a *different commit*. Comparing it
to a run at `8e11724` is not a same-tree comparison, and it is the R008 error (a reference taken at
the wrong revision) in a new place. What the gate run *does* legitimately show is that
`startup_prefetch::tests::wait_settings_leaves_the_fetch_for_accept` failed in both base runs and
passed in the gate run, and that `no_auth_boot_is_not_a_degraded_start` did the reverse — so those
two are unstable, just not on the evidence the brief cited. They share the single cause below, and
both are fixed here.

## 2. The cause, and the experiment that discriminates it

`FUIGO_HOME` is process-global, is resolved **fresh on every read**
(`fuigo_dirs::resolve_fuigo_home`, no cache), and the tests that touch it are split across **four
mutually-parallel populations**, because a `serial_test` *named* group excludes only its own members:

| population | count | attribute | touches `FUIGO_HOME` |
|---|---|---|---|
| unnamed `#[serial]` group | 85 | `#[serial]` | writes |
| `consent_tests::set_consent_answer_is_monotonic_per_account` | 1 | `#[serial(FUIGO_HOME)]` **only** | writes |
| `startup_prefetch_tests` + `init_tests` | 11 | `#[serial(remote_sig_disarm)]` | reads |
| `session::worktree::tests` | 5 | **no group at all** | reads *and writes the filesystem under it* |

The six other `#[serial(FUIGO_HOME)]` tests in the crate carry the unnamed attribute as well. The
consent test did not — a one-attribute omission that let it move `FUIGO_HOME` under any of the 85.

**The discriminating experiment.** Run those two modules and nothing else — 49 tests, one process,
96 test threads, unmodified tree at `8e11724`:

```
both-1  exit=101  47 passed; 2 failed   cleanup_worktree_on_failure_removes_created_worktree
                                        create_worktree_for_resume_produces_independent_worktree
both-2  exit=0    49 passed; 0 failed   ∅
both-3  exit=101  48 passed; 1 failed   create_worktree_for_resume_honors_git_ref
```

Three runs, three different answers, in **0.15 s each** instead of six minutes. That is the whole
churn, reproduced by two modules out of a 7190-test suite, and it names a **fifth** member of the
family that neither baseline run had caught yet (`create_worktree_for_resume_honors_git_ref`).
Raw output: `/root/fuigo-builds/p35-repro.out`, `p35-repro-both-{1,2,3}.{log,failset,meta}`.
Receipts, all three at the same commit, same command, same toolchain:

```
commit:     8e1172417a10a76b879cd9affeff20edf7fc0dbd
command:    TESTLANE_NET=host TESTLANE_TEST_THREADS=96 \
              TESTLANE_FILTERS='session::worktree::tests session::storage::jsonl::worktree_heal_tests' \
              testlane.sh lane-p13 - - 24 -- --locked --no-fail-fast -p fuigo-shell --lib
inner:      cargo test --offline --locked --no-fail-fast -p fuigo-shell --lib -j 24 \
              -- --test-threads=96 session::worktree::tests session::storage::jsonl::worktree_heal_tests
env_digest: rustc 1.94.0 (4a4ef493e 2026-03-02) | cargo 1.94.0 (85eff7c80 2026-01-15) | ripgrep 14.1.0
            RUST_MIN_STACK=16777216  RG_BIN_PATH=/usr/bin/rg
            lock=/root/fuigo-builds/.shell-test.lock
```

| run | exit_code | failset_count | timestamp (UTC) | log sha256 | failset sha256 |
|---|---|---|---|---|---|
| both-1 | 101 | **2** | 2026-09-30T02:59:12Z | `20a770cabfb03fb483f412ab502aeaa314296407d813967a40dcbb0711c65df5` | `9234f52ddc7b7ad37fe8ecce9de873cea9c29df98e358b2a319d71420408ba59` |
| both-2 | **0** | **0** | 2026-09-30T03:01:03Z | `fef8bbf0107d56bf57f2a46388db860d042310c562c3bfd1c2b5bd786061f2bd` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| both-3 | 101 | **1** | 2026-09-30T03:02:55Z | `02741433dddc44666225e52161b3f8908d66e15b01d684796d0daf429ddf52fb` | `426114643ef3440e0701b3e28daf9237cd27e27278e8a46ae1fe5cbea07995a0` |

**Mechanism, read from the code rather than inferred:**

- `create_worktree_for_resume` → `resolve_worktree_path` → `worktree_base_dir` →
  `fuigo_workspace::worktree::fuigo_home()` → `fuigo_fast_worktree::resolve_fuigo_home()` →
  `fuigo_dirs::resolve_fuigo_home()`, which reads `$FUIGO_HOME` at call time. So the worktree is
  created at `$FUIGO_HOME/worktrees/<slug>/<label>` — **inside the `TempDir` of whichever
  `worktree_heal_tests` case happened to hold `FUIGO_HOME`** — and vanishes when that test's
  `TempDir` drops. `assert!(wt_path.exists())` then fails. The same applies to
  `cleanup_worktree_on_failure_removes_created_worktree` in both directions.
- Symmetrically, `Summary::new` → `worktree_identity_for_cwd` → `super::fuigo_home().join("worktrees")`
  re-resolves `FUIGO_HOME` *during* the heal. A concurrent writer makes the session cwd stop looking
  like it is under `$FUIGO_HOME/worktrees/...`, so `worktree_label` stays `None` and
  `init_session_load_fills_missing_label_on_kinded_fork_without_changing_kind` and
  `list_sessions_heal_does_not_evict_recent_sessions_from_mtime_window` fail on exactly that field.
- And for the prefetch pair: `accept_within` → `still_accepted(origin)` compares the recorded origin
  against `resolve_startup_endpoints().proxy_url()`, re-derived from the effective config under
  `$FUIGO_HOME`, and also calls `resolve_remote_fetch_enabled()`, which loads the same layers. A
  concurrent `FUIGO_HOME` change between `register_finished` and `accept_within` turns `Consumed`
  into `Miss` — which is precisely `no_auth_boot_is_not_a_degraded_start` failing in a full run and
  passing alone.

One variable, three symptoms, five test names.

## 3. The four causes from the brief that this replaces

| brief's cause | verdict |
|---|---|
| 1. process-global env mutated at test time | **the cause**, refined: the problem is not the mutation, it is that the exclusion is partitioned |
| 2. `serial(name)` does not serialise against plain `#[test]` | **confirmed and load-bearing** — it is the mechanism by which cause 1 bites |
| 3. `#[serde(default)]` + `Default` reading `std::env` | **present, not the cause here.** `EndpointsConfig::default()` (`fuigo-shell/src/agent/config.rs:535`) reads 25 env vars at default/deserialize time and `from_config_value` calls it on every load. It is a real defect class and it is why the prefetch origin is env-derived at all, but no test in the churning set mutates those 25 variables. Sibling-owned file; filed as a proposal below, not touched. |
| 4. some of these tests reach the network | **measured, and it changes nothing** — see §6 |
| 5. shared on-disk state / wall-clock mtime | **half right.** The shared on-disk state is real and is the mechanism for two of the five names — but it is shared *because* `FUIGO_HOME` moved, not because two tests picked the same directory. There is no wall-clock dependence: `list_sessions_heal_does_not_evict_recent_sessions_from_mtime_window` sets every mtime explicitly (`now`, and `now − 10 days`) and fails on `session_kind`, not on the window. No clock injection was needed. |

## 4. The fix

### 4a. `FUIGO_HOME` — the lock, not the attribute

In `fuigo-test-support`, so it cannot be forgotten test-by-test:

- **`EnvGuard` holds one process-wide lock** for the whole lifetime of a guard over a key in the new
  `PROCESS_ANCHORS` (`FUIGO_HOME`, `FUIGO_CLI_CHAT_PROXY_BASE_URL`). The guarantee is the lock, not
  an attribute. All **107** `EnvGuard::set("FUIGO_HOME", …)` sites in the workspace get it without
  being edited — including `fuigo-pager/src/provider_config_edit.rs`'s **32** tests that are in
  `#[serial(FUIGO_HOME)]` and nothing else, and `fuigo-workspace/src/workspace_ops.rs`'s **4** with
  no serial attribute at all. One lock for all anchors, never one per key: per-key locks admit ABBA
  deadlock. Verified that **no function in the workspace holds two anchor guards at once**, so the
  single lock cannot deadlock. Hand-rolled over `Mutex<bool>` + `Condvar` rather than storing a
  `MutexGuard`, which would make `EnvGuard` `!Send` and break guards held across `.await`.
- The wait is **bounded** (300 s, scaled by `FUIGO_TEST_TIMEOUT_SCALE`) and panics with a named
  diagnosis. `fuigo-shell/tests/session_delete_evicts_index.rs` parks an `EnvGuard` in a `OnceLock`,
  so it is never dropped and holds this lock for the life of that binary. That binary has only one
  anchor guard, so it does not deadlock today — but a leaked guard must fail loudly rather than hang
  a gate, and a second one added later now says exactly what is wrong.
- **`FuigoHome`**: a `TempDir` plus that guard, with field order chosen so the variable is restored
  and the lock released *before* the directory it names is deleted.
- Taken by: the five `session::worktree::tests` that build fuigo-managed worktrees, the nine
  `startup_prefetch_tests`, the two `init_tests`, and every `session::managed_mcp::tests` case
  through its own `empty_cwd()` helper. `consent_tests::set_consent_answer_is_monotonic_per_account`
  joins the unnamed serial group, matching the six other `serial(FUIGO_HOME)` sites.

### 4b. `INFLIGHT` — a second global, and the one place production code was touched

Running the fix surfaced two more names the baseline runs had not caught, and both are the same
variable: `session::managed_mcp::tests::client_cursor_server_kept_when_cursor_mcps_enabled` and
`toml_claim_survives_when_client_cursor_insert_skipped` — that merge stamps
`fuigo_home().join("config.toml")` and gates the project `.fuigo/config.toml` on folder trust, whose
store is under the home. Fixed with 4a.

It also surfaced a genuinely different mechanism behind the prefetch pair.
`INFLIGHT` (the startup-prefetch registry) has **one slot**, and `accept_within` consumes it — and
`accept_within` is reached from **production boot code**
(`MvpAgent::new` → `agent::init::bootstrap` → `ensure_remote_settings_side_effects`) inside **57 lib
tests, 36 of which are in no serial group at all**. `Finished::take` does `mem::take(state)`, which
sets `finished: false` on the cell a registry test registered a microsecond earlier; the victim's own
`accept_within` then sees an unfinished cell, marks it abandoned and returns
`(Consumed(None), Some(DegradedStartCause::DeadlineMissed))`. Measured signature, from the run's own
log:

```
no_auth_boot_is_not_a_degraded_start   -> "a boot that never attempted settings
                                          must not record a degraded start"
wait_settings_leaves_the_fetch_for_accept -> left: None, right: Some(true)
```

Both are exactly what a blanked cell produces, and neither is what a wrong origin produces (that
path returns `Accept::Miss` and trips a different assertion).

**No `serial_test` group can express this exclusion**, because the consumers are reached through
production code from tests that have nothing to do with the prefetch. So `startup_prefetch.rs` gains
a `#[cfg(test)]` `REGISTRY_OWNER`: a registry test declares ownership for its duration and
`accept_within` on any other thread leaves the entry alone while it holds. It is the mirror of the
`cfg!(test)` guard `begin_inner` already carries — that one stops a test process from STARTING a
fetch, this one stops an unrelated test from CONSUMING one — and it is in no shipped binary. A second
owner asserts rather than queues, so an incomplete `#[serial(remote_sig_disarm)]` group says so
loudly instead of silently queueing.

This is the only production file touched, and only inside `#[cfg(test)]`.

**Nothing is silenced**: no `#[ignore]`, no retry wrapper, no loosened assertion, no widened
tolerance, no deleted test. The tests that fail deterministically at `8e11724` still fail.

## 5. Receipts, and the bar I did and did not meet

**Stated plainly first: I did not get three consecutive byte-identical FULL-SUITE failing sets at one
commit.** I got two, twice, and the same 13-name set recurs across four runs and two commits. Every
disagreement is one extra name, and every one of those names is a pre-existing flake this packet did
not target. The numbers are below verbatim; nothing is averaged, rerun-until-green or selected.

Common to every run: lane `/root/fuigo-builds/lane-p13`,
`CARGO_TARGET_DIR=/root/fuigo-builds/lane-p13/target`, `RUST_MIN_STACK=16777216`,
`RG_BIN_PATH=/usr/bin/rg`, `flock /root/fuigo-builds/.shell-test.lock`,
`env_digest: rustc 1.94.0 (4a4ef493e 2026-03-02) | cargo 1.94.0 (85eff7c80 2026-01-15) | ripgrep 14.1.0`.

### 5a. Three full-package runs at `f9d75f6f`

```
commit:  f9d75f6f2013e29c2ca14772794b80c088eaaa1f
command: TESTLANE_NET=host TESTLANE_TEST_THREADS=96 TESTLANE_TIMEOUT=1200 \
           testlane.sh lane-p13 - - 24 -- --locked --no-fail-fast -p fuigo-shell
inner:   cargo test --offline --locked --no-fail-fast -p fuigo-shell -j 24 -- --test-threads=96
```

| run | exit | count | bins/results | timestamp (UTC) | log sha256 | failset sha256 |
|---|---|---|---|---|---|---|
| full-1 | 101 | 14 | 52/52 | 2026-09-30T06:48:39Z | `a6f8a8ab852895b709d9596c655f8243542b2464502f3c6ce36aedbe403f75ac` | `d5cb13ebc8268c73e7044f49b66d9978999549b4eff2f49d000eb388afc9261b` |
| full-2 | 101 | 13 | 52/52 | 2026-09-30T06:54:06Z | `c6388486a4ae2636eaf3d9305f93d6004089b2592046800ac019d0c1d20dbbb5` | `d6f49327e4f17e208641494b90c087380eba23d1cdbe2d3191c4d7c180e592db` |
| full-3 | 101 | 13 | 52/52 | 2026-09-30T06:59:31Z | `c275dbaf8739277a516eee70d3651e8c0d588e42738d9d523a5a6e9f3409f418` | `d6f49327e4f17e208641494b90c087380eba23d1cdbe2d3191c4d7c180e592db` |

`full-2` and `full-3` are **byte-identical**. `full-1` is those 13 plus exactly one name:
`auth::manager::lock::tests::dropping_the_guard_silences_the_heartbeat_before_anyone_else_can_hold_the_lock`.

`binaries_run == result_lines == 52` in all three, so no binary died silently (R001's guard).

### 5b. The 13-name set, and it recurs across commits

```
cache_aligned_side_calls_replay_the_main_turn_tool_list
inherited_parent_pool_keeps_the_mcp_meta_tools_reachable_from_the_child
max_turns_with_a_foreground_child_stops_on_the_flag_for_both
non_interactive_sessions_skip_dashboard_side_calls                                   <- R008 regression
openai_models_default_to_codex_and_headless_sessions_hide_ask_user
repeat_read_of_unchanged_file_is_deduped_until_the_workspace_changes
responses_profile_keeps_the_tool_list_identical_on_every_request_including_finalize   <- R008 regression
session::acp_session::auth_retry_budget_tests::parked_turn_does_not_respawn_two_pass_prefire
session::acp_session::auth_retry_budget_tests::parked_turn_past_compact_threshold_does_not_auto_compact
session::acp_session::recap_display_only_tests::recap_request_rides_parent_prompt_cache
session::acp_session::recap_display_only_tests::side_question_request_rides_parent_prompt_cache
session::acp_session::recap_display_only_tests::side_question_routes_on_the_session_id_when_the_key_is_not_forwarded
stock_backend_finalize_advertises_no_action_tool                                     <- R008 regression
```

Failset digest `d6f49327e4…` was produced by **four** full-package runs across **two** commits
(`20b0b3ec` run 1; `5c687a42` full-1 and full-2; `f9d75f6f` full-2 and full-3 — five, counting both).
The three names marked are the confirmed separate regression R008 §1 records; they are not mine and
they are red in every run, as expected.

### 5c. Against the baseline

Against the union of P09's two runs at `8e11724` (the 16/18 pair):

```
- fixed by p35: session::worktree::tests::create_worktree_for_resume_produces_independent_worktree
- fixed by p35: session::worktree::tests::cleanup_worktree_on_failure_removes_created_worktree
- fixed by p35: session::storage::jsonl::worktree_heal_tests::init_session_load_fills_missing_label_on_kinded_fork_without_changing_kind
- fixed by p35: session::storage::jsonl::worktree_heal_tests::list_sessions_heal_does_not_evict_recent_sessions_from_mtime_window
- fixed by p35: agent::models::startup_prefetch::tests::wait_settings_leaves_the_fetch_for_accept
- fixed by p35: agent::config::tests::configured_endpoints_become_the_trusted_origins
+ new at p35:   auth::manager::lock::tests::dropping_the_guard_silences_the_heartbeat_before_anyone_else_can_hold_the_lock
```

**All four names R008 §5 measured as churning are gone, plus two more.**

**The one "+ new" is not new, and I want to be exact about that.** It also failed in a run at
`8e11724` in this packet's own base reference (`base-lib-3`, §5e). It looks new only because the P09
union is two runs, and a two-run union is not a complete control — which is R008's own lesson turned
on my evidence. A single "new" name in a diff against a two-run baseline of a suite this flaky is
within the noise the baseline itself has.

### 5d. Like-for-like reference at `8e11724`, same harness, same command

Three `-p fuigo-shell --lib` runs at the base, identical conditions to §5f:

| run | count | failset sha256 |
|---|---|---|
| base-lib-1 | 7 | `2d5890bc8e247954132adde3172d4b7e0ffb4a1e6b57b839fdc82b4af732055c` |
| base-lib-2 | **9** | `bb66ccdd0759c474af268ec693997f3e895220e593c339f870d6b99f9eee824b` |
| base-lib-3 | **6** | `534b48aef324969b81ab5e3e1cf72856c1bc40189afa20bb0093ff82f002ac2e` |

**All three different**, churning by five distinct names. Under the same harness at the fix the
`--lib` runs are 6 / 6 / 5 with a stable five-name core and one rotating name. That is the honest
comparison: the churn is not gone, it is much smaller and its remaining members are named in §9.

### 5e. The 0.15 s reproduction, before and after

Same two modules, same command, same box, same 49 tests:

| | run 1 | run 2 | run 3 |
|---|---|---|---|
| `8e11724` | **2 failed** | 0 failed | **1 failed** |
| `f9d75f6f` | **0 failed** | **0 failed** | **0 failed** |

The experiment that produced three different answers on an unchanged tree now produces the same
answer three times, in under half a second each.

### 5f. The eleven targeted names, each alone, all green

```
worktree_heal_tests::init_session_load_fills_missing_label_on_kinded_fork_without_changing_kind  ok 0.01s
worktree_heal_tests::list_sessions_heal_does_not_evict_recent_sessions_from_mtime_window          ok 0.02s
worktree_heal_tests::init_session_load_backfills_worktree_identity_on_untagged_summary            ok 0.02s
session::worktree::tests::cleanup_worktree_on_failure_removes_created_worktree                    ok 0.13s
session::worktree::tests::create_worktree_for_resume_produces_independent_worktree                ok 0.08s
session::worktree::tests::create_worktree_for_resume_honors_git_ref                               ok 0.14s
startup_prefetch::tests::no_auth_boot_is_not_a_degraded_start                                     ok 0.00s
startup_prefetch::tests::wait_settings_leaves_the_fetch_for_accept                                ok 0.00s
agent::config::tests::configured_endpoints_become_the_trusted_origins                             ok 0.01s
managed_mcp::tests::client_cursor_server_kept_when_cursor_mcps_enabled                            ok 0.01s
managed_mcp::tests::toml_claim_survives_when_client_cursor_insert_skipped                         ok 0.02s
```

and none of them appears in any of the three full-package runs in §5a.

## 6. `--network none`

**It does not change the failing set, and it took three runs to be allowed to say that.**

Three full-package runs at `f9d75f6f` inside a fresh network namespace (`unshare --net`, loopback up,
nothing else; `cargo --offline` inside, so a missed dependency errors instead of hanging):

| run | count | failset sha256 | same as |
|---|---|---|---|
| netnone-1 | 16 | `781173bbde64d968bb687373cfc29af627af3850cbafaa3ef058f0102ad990be` | — |
| netnone-2 | 13 | `d6f49327e4f17e208641494b90c087380eba23d1cdbe2d3191c4d7c180e592db` | **networked full-2 / full-3, exactly** |
| netnone-3 | 14 | `d5cb13ebc8268c73e7044f49b66d9978999549b4eff2f49d000eb388afc9261b` | **networked full-1, exactly** |

The set of names present in **all three** sandboxed runs but in **neither** networked run is
**empty**.

Two of the three sandboxed runs are bit-for-bit identical to networked runs, and the sandboxed runs
disagree with each other by exactly the same one-name margin the networked runs do. So the answer is:
**no `fuigo-shell` test's result depends on egress.** The suite's servers bind loopback, and loopback
inside a fresh namespace is all they need — which is why `testlane.sh` brings `lo` up and nothing
else. Verified independently: inside the namespace a loopback connect succeeds and
`curl https://static.crates.io/` cannot resolve.

At the `--lib` level the same holds even more cleanly: two sandboxed `--lib` runs produced failsets
`f6812f0b…` and `ae36e7e3…`, byte-identical to networked `lib-1` and `lib-3` respectively, with an
empty set-difference in both directions.

**The near-miss, recorded deliberately.** `netnone-1` alone added exactly three names —
`auth_error_no_retry_tests::sampler_401_recovery_returns_refresh_and_retry` and its two siblings.
Three auth-shaped names appearing only without a network is a compelling-looking result, and the
brief had flagged those very names. On one run I would have written "confirmed: the auth tests reach
the network". Two more runs refute it: neither reproduced them, and one of the three had already
failed in a *networked* run at the base (`base-lib-2`). They are the same flaky population, not a
network dependency. This is R007's pattern — stop at the first evidence that fits instead of the
evidence that discriminates — caught inside this receipt rather than after it.

**Contract A's sandboxed-suite requirement is met by a real run for the first time in this strike**,
and the answer it produces is that sandboxing changes nothing, which is the cheapest possible result
to adopt permanently.

## 7. `lane.sh` and `testlane.sh` now exist

`CLAUDE.md` has documented both for the whole strike and **neither was on the box**; seven agents
improvised around them, and Contract A's sandboxed-suite requirement had never been met by any run.
They are now at `/root/fuigo-builds/lane.sh` and `/root/fuigo-builds/testlane.sh`, and every run in
this receipt went through them.

- `lane.sh <lane> <cpus> <cmd…>` — network allowed. Sets the lane's own `CARGO_TARGET_DIR`,
  `RUST_MIN_STACK=16777216` (R001: omitting it tests the stack size, not the product) and
  `RG_BIN_PATH=/usr/bin/rg` (R007: `bundle_rg` is release-only, so a debug test build resolves
  ripgrep from `RG_BIN_PATH`/`PATH`, and its absence produced 34 ENOENT failures read as EMFILE for
  a day and a half).
- `testlane.sh <lane> <src> <target> <cpus> [-- <cargo test args>…]` — **no network.** Two phases,
  because compiling may need the network and running must not: the test binaries are built with
  `cargo test --no-run`, then executed inside a fresh network namespace (`unshare --net`) with only
  loopback brought up — loopback is required, because a fresh namespace has it `DOWN` and the
  suite's mock servers bind `127.0.0.1`. Inside the namespace cargo runs `--offline`, so a missing
  dependency is an error rather than a hang.
- It derives the failing set from the `failures:` block, never from `grep -cE '^test .* FAILED$'`,
  and writes a Contract A.3 receipt (`.meta`) beside the log. Env knobs: `TESTLANE_LOCK` (the
  host-wide `flock`, mandatory for `fuigo-shell`), `TESTLANE_NET`, `TESTLANE_TEST_THREADS`,
  `TESTLANE_FILTERS`.

## 8. Packet proposals — found, not fixed

1. **`fuigo_dirs::user_fuigo_home()` pins `FUIGO_HOME` for the process on first call.** It is
   `resolve_fuigo_home().is_some().then(fuigo_home)`, and `fuigo_home()` caches in a `OnceLock`. So
   in a test binary the *first* test to call it decides the home every later caller sees, whatever
   their guard says. `mvp_agent`'s own comment already knows this ("`bootstrap_once` takes the
   process-cached `fuigo_home()`, which these guards cannot redirect, so it could index the
   developer's own store"). Not in the churning set, so not fixed here; it is a live order-dependence
   and a way to index a developer's real session store from a test.
2. **`EndpointsConfig::default()` resolves 25 environment variables at `Default`/deserialize time**
   (`fuigo-shell/src/agent/config.rs:535`), and `from_config_value` calls it on every load. This is
   the exact pattern R008's cause-3 named. Fix is to thread the resolved endpoints in as a value the
   compiler forces every construction site to supply. Sibling-owned file; untouched.
3. **`worktree_identity_for_cwd` and `worktree_base_dir` read ambient `FUIGO_HOME` in production
   code.** `worktree_identity_in(worktrees_dir, cwd)` already exists as the explicit-parameter form;
   `worktree_base_dir` has no such twin. Threading the home through would remove the ambient read
   from the product, not just from the tests.
4. **Six more test modules record and read folder trust with no home guard.**
   `crate::agent::folder_trust::record_for_test` writes the trust store under `$FUIGO_HOME` and the
   code under test reads it back. Outside `agent/folder_trust.rs` (whose tests are all `#[serial]`
   plus an `EnvGuard`), it is called from `util/config/mcp_reenable.rs`,
   `agent/mvp_agent/tests.rs`, `session/acp_session_impl/workflow_write_smoke_check_tests.rs`,
   `session/workflow/registry.rs`, `session/agent_rebuild.rs` and `session/managed_mcp.rs`. This
   packet fixed the `managed_mcp` ones because they produced observed failures; the other five are
   the same defect and are unfixed. They are also how a test comes to write into a developer's real
   `~/.fuigo`: the box's own `~/.fuigo/config.toml` carries
   `[consent.answers.tos] account = "b@example.com"`, written there by
   `consent_tests::set_consent_answer_is_monotonic_per_account` despite its `EnvGuard`, because the
   write path resolves the cached `fuigo_home()` (proposal 1) rather than the guard's value.
5. **Audit every named `serial_test` group in the workspace.** This suite has
   `remote_sig_disarm` (13), `attribution_emit_count` (23), `heap_profile_monitor` (15),
   `FUIGO_HOME` (7), `archive_build_fault` (8), `remote_sig_disarm` (13), `force_dark_wake_env` (2),
   `heap_profile_hooks`, `disabled_hooks_file`. Each one is a claim that the global it guards is
   touched by nobody outside the group. Two of those claims were false. The rest are unverified.

## 9. What I could not make hermetic, named

### 9a. `auth::subscription::tests::cancelled_and_timed_out_login_release_listener` — propose, do not weaken

It binds an ephemeral port, cancels the login, and asserts the port rebinds:

```
assertion failed: TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await.is_ok()
```

The property — "a cancelled login released its listener" — is real and worth asserting. **The chosen
observation of it is not deterministically assertable**: in a process where ~100 other tests bind
port 0, any of them can take that exact port in the window between release and rebind, and the test
cannot tell "we leaked it" from "someone else took it". Nothing in the test can close that gap.

I did not weaken it, add a retry or ignore it. **Proposal:** observe the release directly instead of
inferring it from a rebind — have `LoginAttempt` hold its listener behind a handle whose drop is
observable under `cfg(test)`, and assert that. `auth/subscription` is P16's territory
(`P16-subscription-error-taxonomy.md`), so this is handed over rather than done here. A cheaper
interim that is strictly *more* deterministic, not less, is to bind a fixed high port the suite
reserves, so a collision fails loudly and repeatably instead of flakily.

Also feeding this: `auth::api_key_probe::tests::timeout_is_unknown_fail_open`
(`api_key_probe.rs:441-451`) moves a `TcpListener` into a detached `std::thread` that loops
`accept()` twice. The client makes two 80 ms attempts, so the second `accept()` usually never
returns — **the thread and its bound port leak for the life of the test binary.** Caught in the
backtrace of a hung run, parked in `inet_csk_accept`. It is a resource leak in every run and one more
consumer of the ephemeral-port space the test above depends on.

### 9b. A liveness hang in `session::workflow::manager::tests` — the most important finding here

Three of my full-package runs produced `test … has been running for over 60 seconds` and then sat
still for half an hour. `gdb -p` on the test binary (gdb had to be installed; the box had no
debugger) shows:

- **Thread 1** — libtest's main thread, blocked in `mpsc::Receiver::recv` waiting for the last test
  to report.
- **Thread 3** — the hung test's `current_thread` runtime, parked in the I/O driver with
  `timeout=-1`. Nothing is running and nothing will wake it: it is awaiting a channel message that
  will never be sent.
- Every other thread is idle or parked.

Two different tests in that one module hung on two different runs
(`cancel_drops_queued_spawns_before_coordinator`, then
`resume_reconciles_agents_used_from_journal_no_double_charge`). Both end in an **unbounded** await
(`let _ = outcome_rx.await;`, `recv_spawn(&mut subagent_rx).await`), so when the coordinator does not
send, the suite stops rather than fails.

Both tests pass alone and pass inside their own module: 3/3 and 2/2 at `5c687a42`, and 3/3 and 2/2 at
`8e11724`. A full `--lib` run did not reproduce it at either revision. So it needs the whole
package, and my sample is 3 hangs in my full-package runs against 0 in the two P09 baseline runs —
**too small to attribute, and I do not attribute it.** What I can name is a mechanism that would
amplify it, and it is proposal 1 below: `fuigo_dirs::fuigo_home()` caches the home in a `OnceLock`,
so whichever test calls it first pins it for the process — and this packet makes an early caller far
more likely to be holding a *temporary* home that is then deleted. Every later consumer of the cached
path then operates on a directory that no longer exists.

**Why this matters more than the failing-set diff:** a hang produces *no* failing set. A gate that
trusts `cargo_exit` and a `failures:` block cannot see it — the run simply never ends, or ends
truncated with `binaries_run != result_lines`. One of my earlier runs recorded exactly that (52
binaries, 51 result lines) because I killed the hung binary and cargo carried on. **Any full-suite
gate in this strike can be silently truncated this way.** `testlane.sh` now bounds the run
(`TESTLANE_TIMEOUT`, default 5400 s) and labels a timed-out log as *not* a failing set, which turns
the hang from an invisible wedge into a visible one. That is containment, not a fix.

### 9c. `agent::models::tests::reload_from_disk_cache_applies_external_catalog`

Appeared once in three `--lib` runs at the fix and in none of the base runs I took. It reads the
models disk cache under `$FUIGO_HOME` without a guard. I name it as **possibly made more likely by
this packet**, for the honest reason that the anchor lock makes *writers* of `FUIGO_HOME` mutually
exclusive but does nothing for unguarded *readers* — and this packet adds writers. One line
(`FuigoHome`) should fix it, on the same pattern as the eleven; it was found too late to land and
re-verify, and guessing is how this strike has gone wrong before.

