# R018: the P35/P36/P37 trio in one branch. Acceptance NOT met.

**Date:** 2026-09-30 (box UTC) · **Parent:** `f89618ef` (strike/integration) · **Tip:** `5524445a` (`strike/trio`) · **Box:** hetzner-dsm
**Lane:** `/root/fuigo-builds/trio/`. It had its own worktree (the bundle was fetched into `integration/src-p15r`) and its own
`CARGO_TARGET_DIR=/root/fuigo-builds/trio/target`. Env: `RUST_MIN_STACK=16777216 RG_BIN_PATH=/usr/bin/rg CARGO_TERM_COLOR=never`, toolchain 1.94.0 from `rust-toolchain.toml`.
Scripts and outputs stay in the lane dir: `accept.sh/.out`, `post.sh` + `post-partial.out`, `rest.sh/.out`, `stress/`, and `*.log`, `*.failset`.

## Verdict

**The A.2.1 rule-7 acceptance is NOT met.** The three consecutive complete tip runs have three different failing sets
(0, 1 and 2 names). Both names are pre-existing flakes that appear in failsets on this box before the trio existed. Neither comes
from a trio change (§4). Under the rule against rerunning until green, I report the series as it ran and did not restart it.

What the trio does achieve, measured:

* None of the parent's three named failures appears in any tip run (§3).
* All of P35/P36/P37's target modules ran 40× at 96 threads with 0 failing runs (§5).
* The workflow-manager wedge now always fails with a named diagnosis and never hangs. It failed 5 of 150 runs. At the parent the same wedge
  hung a full run for 13+ minutes, and I killed that run (§2).
* clippy shows 0 new warnings.

## 1. Branch construction (branched from `f89618ef`)

| # | commit | from | note |
|---|---|---|---|
| 1-3 | `bd318996` `4f5da57e` `b988c4cd` | P35 `f9d75f6f` `811d1b1f` `79439468` | clean |
| 4-7 | `e117e328` `1735d4be` `189f0d70` `14020a2c` | P36 `abe7e0bf` `737663b6` `1859fe0c` `042d7984` | clean |
| 8-10 | `0ce01965` `fdfef04c` `83fb4748` | P37 `3df667d3` `b1b49b71` `e713e086` | clean textually. The merge is semantic, see below |
| 11 | `5524445a` | resolution | comment-only fix in `session_updates.rs` |

**Receipts.** P36 and P37 carry R012 unchanged. Neither commits a change to it or adds a receipt of its own, so R012 stays P35's file verbatim.
Their additions live only in their commit messages, which are kept as-is: P36's finding that the unpinning exposed unguarded readers, and
P37's auth-lock fork-inheritance, registry `FUIGO_TEST_VERSION`, divergent-cwd history and manager-wedge findings. §6 corrects one statement in R012 §9c.

**Semantic merge, decided per test:**

* **`workflow::registry::tests`.** P36 put a `FuigoHome` on `project_workflows_follow_folder_trust`. P37 put `record_for_test(dir, true)` on
  five other tests. `record_for_test` writes the in-memory `DECISIONS` map (`agent/folder_trust.rs:167`), not the store under
  `$FUIGO_HOME`. A recorded `Some(true)` short-circuits before any home read. So P37's fix does not depend on whether `fuigo_home()` is pinned.
  P36's test records `false` and then re-reads the store, and that re-read is the part that needs the private home. The two edits touch
  different tests, so **both are kept**. Measured together: 40/40 clean, plus 25/25 with `agent::folder_trust` (P37's reproduction pairing).
* **`handle_falls_back_to_id_lookup_for_divergent_cwd`.** P36 gave it a `FuigoHome`. P37 gave it a unique id and a Drop guard.
  P37 rejected `FuigoHome` because the OnceLock pinned a temp dir that was later deleted (28/40 on a neighbour). That mechanism is exactly what P36's
  `abe7e0bf` removes. **Both are kept**, and they compose: the test gets a private sessions root *and* an id that cannot collide. P37's comment said
  the home "cannot be redirected", which is false once P36 lands, so commit 11 rewrites the comment only.
  Drop order is safe: `_cleanup` is declared after `_home`, so it drops first, while the home is still set.
  Measured: 40/40 clean in isolation, 40/40 clean mixed with the consent and managed_mcp FUIGO_HOME writers, and absent from all 3 tip full runs.
  The parent's `~/.fuigo/sessions` on the box holds **97** `divergent-cwd-fallback-*` leftovers, which is why the parent fails it.

**Scope flag (judgment call for the integrator).** P36's `abe7e0bf` changes **production code**. `fuigo_dirs::fuigo_home()` goes from a
`OnceLock` to a `Mutex` memo keyed on `$FUIGO_HOME` and the OS home, and it now reads both on every call. The commit is titled `test(...)`.
I kept it because the brief integrates P36 as-is. It is still outside test-only scope and should be ruled on as a production change.
P35's `startup_prefetch.rs` edit is inside `accept_within`, but it is entirely `#[cfg(test)]` and compiles out of shipped binaries.

## 2. Parent `f89618ef`: every complete (or killed) run

Full runs use `flock /root/fuigo-builds/.shell-test.lock`, taken per run, and `cargo test --locked --no-fail-fast -p fuigo-shell` with host network.
Host network matches the P12b-R precedent that produced the brief's "3 failures at 8b4b8f40".

| run | exit | derived / headers / unfinished | failures | failset sha256 | log sha256 | admissible |
|---|---|---|---|---|---|---|
| parent-shell-1 | 143 | 37 / 1 / 0 | (none; truncated) | `e3b0c442…` | `81804028…` | **NO**: killed. See below |
| parent-shell-2 | 101 | 37 / 37 / 0 | 5 | `ac77ffef…` | `9f004ccb…` | yes |
| parent-shell-3 | 101 | 37 / 37 / 0 | 8 | `d483d110…` | `2b1a1670…` | yes |
| parent-shell-4 | 101 | 37 / 37 / 0 | 7 | `926db7cc…` | `d6255288…` | yes |

**parent-shell-1** wedged in `session::workflow::manager::tests::cancel_drops_queued_spawns_before_coordinator`. It was 13+ min with no progress
and still holding the host-wide shell lock. gdb (`parent-shell-1.gdb`) shows the thread in `release_agent_calls` at
`fuigo-workflow/src/engine.rs:439` → `oneshot::Receiver::blocking_recv`, which is P37's diagnosis and the proposed P38.
I killed only that run's `timeout` process group (`kill -TERM -- -1610433`). The awk header check printed `1 0` for this truncated log
because the lib binary's subprocess-driving tests print child `test result:` lines, and those close the open header. Exit 143 is what disqualifies it.
**The awk header/unfinished check can be fooled by child output from the lib binary**, so do not rely on it alone.

Parent union over runs 2 to 4 (12 names, sha256 `01fd1afc…`) contains `configured_endpoints_become_the_trusted_origins`,
`wait_settings_leaves_the_fetch_for_accept`, `handle_falls_back_to_id_lookup_for_divergent_cwd` (all three runs),
`no_auth_boot_is_not_a_degraded_start`, the registry pair, the managed_mcp pair, three `session::worktree::tests`, and
`auth::manager::lock::tests::dropping_the_guard_silences_the_heartbeat…`. The parent is itself non-deterministic: 5, 8 and 7 names across runs.

`fuigo-dirs`: parent 5 passed, 0 failed, exit 0, log `8c09d38f…`. Tip 7 passed, 0 failed, exit 0, log `e021bd17…`. The tip adds P36's two new tests.

## 3. Tip `5524445a`: the acceptance series (3 consecutive complete runs)

| run | exit | derived / headers / unfinished | DONE | failing set | failset sha256 | log sha256 |
|---|---|---|---|---|---|---|
| tip-shell-1 | 0 | 37 / 37 / 0 | yes | ∅ | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `e573a905e8a6a990b914b8f0067ae0e01a9143bb55923f5b405d3a6ad2291a7d` |
| tip-shell-2 | 101 | 37 / 37 / 0 | yes | `agent::models::tests::reload_from_disk_cache_applies_external_catalog` | `17ff7208e2ec7aa4ccc48e3df55fc6b6e6e1d5d31edd1742c0ca12b386915898` | `80dac2cb88a33c46ab12000b11015448474fb562194bd9594814769e83c451e5` |
| tip-shell-3 | 101 | 37 / 37 / 0 | yes | the above + `auth::subscription::tests::cancelled_and_timed_out_login_release_listener` | `52179a103b4fd5a233443825c9e993f0299e6c7c431be934b1d3edf39be85823` | `e47f035bc11699385120d3fac3b7c4d113bc1e4701b442880bcdde8798eb9897` |

All three runs are admissible. **They are not byte-identical (1≠2, 2≠3), and the 2nd and 3rd are not subsets of the observed parent union.**
No tip run has a slow-test warning. The manager wedge did not fire in any tip full run.

What happened to each of the parent's three named failures:

| parent failure | parent runs 2/3/4 | tip runs 1/2/3 | fixed by |
|---|---|---|---|
| `agent::config::tests::configured_endpoints_become_the_trusted_origins` | –/F/F | –/–/– | P35 (proxy URL now an anchor EnvGuard) |
| `agent::models::startup_prefetch::tests::wait_settings_leaves_the_fetch_for_accept` | F/F/F | –/–/– | P35 (`REGISTRY_OWNER`) |
| `extensions::session_updates::tests::handle_falls_back_to_id_lookup_for_divergent_cwd` | F/F/F | –/–/– | P36 home + P37 unique id |

## 4. Why the tip series disagrees: two pre-existing flakes, neither from the trio

* **`reload_from_disk_cache_applies_external_catalog`.** The test computes `mgr.cache_identity()` to persist, and
  `reload_from_cache_manager` recomputes it to load. `models_cache_identity` (`agent/models/cache.rs:110`) hashes
  `read_fuigo_api_key_env()`, which is `FUIGO_API_KEY` at call time. About 15 tests set that variable, and all of them are in the unnamed
  `#[serial]` group (for example `agent/models/tests.rs:1914`, `auth/manager_tests.rs:3526`, `cli_models.rs:165`). The victim is a plain
  `#[test]` in no group, so a writer can land between the two calls. The result is an identity mismatch, `load_fresh` returns `None`, and
  `has_fetched_real_catalog()` is false. This is the same family as P37's registry/`FUIGO_TEST_VERSION` fix.
  None of `models*`, `cache.rs` or the writers is touched by the trio.
  It is already in `/root/fuigo-builds/p15r2-shell-8b4b8f407.failset`, `p17r-v3/baseline-fuigo-shell.failset` and `p35f-lib-2.failset`.
  **The R012 §9c mechanism is wrong.** The test's cache lives in its own tempdir, not under `$FUIGO_HOME`, so a `FuigoHome` would not fix it.
* **`cancelled_and_timed_out_login_release_listener`.** The test binds port 0, drops the listener, and asserts it can rebind the same port.
  Any concurrent bind of that ephemeral port fails the test. So does a concurrent `Command::spawn`'s fork-to-exec window holding a copy of
  the listener fd, which is P37's auth-lock mechanism. The trio does not touch it. It is in the P09 gate, P17r-v2, P35, P36 and P37 failsets on this box.

**Proposed packet (not built here; it needs a fresh series on a new tip):** make both tests state their preconditions.
For the first, `#[serial_test::serial]` plus `EnvGuard::unset("FUIGO_API_KEY")`, or persist/reload through a single identity.
For the second, stop asserting rebind of an ephemeral port and assert that the listener is dropped instead.
I did not add either to this branch. Changing the tip mid-series would amount to restarting the series to get a clean one.

## 5. Stress (tip lib binary `fuigo_shell-413df6bccc08d23c`, `--test-threads=96`, 600 s bound per run)

The shell lock was first taken per iteration (`post.sh`). Contention from other lanes cut throughput to about 1 iteration/min, so I killed
that script by its pgid and reran with the lock held **per module batch**: 40 iterations, or 25 for the manager batches (`rest.sh`).
Every result below is 0 failing runs and 0 timeouts unless the table says otherwise.

| packet | filter | tests | runs | failing runs |
|---|---|---|---|---|
| P35 | `agent::config::tests::` | 352 | 40 | 0 |
| P35 | `agent::init::tests::` | 2 | 40 | 0 |
| P35 | `agent::models::startup_prefetch::tests::` | 9 | 40 | 0 |
| P35 | `agent::app::tests::` | 23 | 40 | 0 |
| P35 | `inspect::tests::` | 25 | 40 | 0 |
| P35 | `session::managed_mcp::tests::` | 26 | 40 | 0 |
| P35 | `session::worktree::tests::` + `…worktree_heal_tests::` | 49 | 40 | 0 |
| P35/P36 | `util::config::consent::tests::` | 3 | 40 | 0 |
| P36 | `agent::mvp_agent::tests::` | 300 | 40 (+21 clean under the per-iteration lock) | 0 |
| P36 | `…workflow_write_smoke_check::tests::` | 9 | 40 | 0 |
| P36 | `session::agent_rebuild::tests::` | 3 | 40 | 0 |
| P36 | `rewind_cross_compaction_tests::` | 5 | 40 | 0 |
| P36 | `session::worktree_pool::tests::` | 2 | 40 | 0 |
| P36 | `inline_auto_compact_flow_tests::` | 53 | 40 | 0 |
| P36 | `notification_drain::` | 7 | 40 | 0 |
| P36/P37 | `extensions::session_updates::tests::` | 11 | 40 | 0 |
| P37 | `auth::manager::lock::tests::` | 23 | 40 | 0 |
| P36/P37 | `session::workflow::registry::tests::` | 15 | 40 | 0 |
| P37 | registry + `agent::folder_trust::` | 57 | 25 | 0 |
| cross | session_updates + consent + managed_mcp | 40 | 40 | 0 |
| P37 | `session::workflow::manager::tests::` | 31 | 150 | **5** (all named, none hung) |

The manager failures, every one of which says `waited 40s for the run's WorkflowOutcome and it never arrived`, with the tracker at `cancelled`:
`cancel_drops_queued_spawns_before_coordinator` ×4 (manager.rs:2452; batches b1 runs 1 and 20, b4 run 3, b5 run 19), and
`cancellation_uses_run_owned_cancel_event_without_parent_detach` ×1 (manager.rs:2331, b3 run 16). The rate is 5/150, in line with P37's 6/150.
The wedge itself is P38 (engine.rs:439), which this branch does not fix.

In the first `post.sh` pass, `consent_tests::` matched 0 tests (the module is `util::config::consent::tests`), and `post-partial.out` records that pass.
Three more filters in that script would also have matched 0 (smoke-check, inline-autocompact and auth-lock, which are `#[path]` modules), but the script was killed before it reached them.
Every filter in the table above was checked against `--list`.

## 6. clippy `--all-targets -p fuigo-shell -p fuigo-dirs`

The parent `f89618ef` and the tip `5524445a` both exit 0 with a warnset of 23 each. **New: 0. Gone: 0.** Logs are `clippy-<sha>.log`, and the tip log sha256 is `88509ffc…`.

## 7. Not verified

* Whether the tip's two residual flakes have a *lower* rate than at the parent. Neither appeared in parent runs 2 to 4. I have no rate estimate.
* `--network none`. All full runs used host network to stay comparable with the P12b-R parent numbers.
* R012 §5 and §9 statements beyond §9c were not re-derived.
* The `untrusted_workspace_drops_project_mcp_servers` comment from P35 says `record_for_test` writes the store under `$FUIGO_HOME`. The
  `agent::folder_trust::record_for_test` I read writes in-memory. I did not check which `record_for_test` that test resolves to.
