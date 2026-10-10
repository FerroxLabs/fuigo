# R-flaky-1024: intermittent test triage (base 38954e80)

All runs on Hetzner lane flaky24 via slot-run.sh. "alone" = test filter, "bin" = whole lib test binary of the crate.

| # | Test | Crate | Reproduced (fails/runs) | Cause class | Fix | Evidence |
|---|------|-------|-------------------------|-------------|-----|----------|
| 1 | probe_log_line_holds_a_fingerprint_not_the_key | fuigo-shell | no: 0/30 alone, 0/10 bin | unknown; reading says test isolation (shared per-process unified log) | not fixed | See note 1 |
| 2 | request_logs_hold_no_url_or_header_credentials_and_serde_errors_hold_no_body | fuigo-sampler | no: 0/30 alone, 0/10 bin | unknown; reading says test isolation (tracing callsite interest) | not fixed | See note 2 |
| 3 | cloud_cache_signature_invalid_when_armed | fuigo-config | no before fix: 0/20 alone, 0/30 bin; after: 0/30 alone, 0/30 bin | shared global (REMOTE_VERIFICATION_DISARMED atomic flipped by the kill-switch tests) | 136fc29a | Both tests that assert verification_active() now take with_remote_disarm_lock |
| 4 | a_held_mark_keeps_a_session_whose_load_outlives_the_ttl | fuigo-shell | not reproduced (0/20 alone, 0/5+10 bin) | likely already fixed | none | Mark is a held sweep lock; explicit-unlock fix (HeldLock) landed; a concurrent fork inheriting the fd was the old cause |
| 5 | the_snapshot_releases_its_locks_before_it_reads_the_history | fuigo-shell | not reproduced (0/20 alone, 0/5+10 bin) | likely already fixed (flock held by a forked child's inherited fd) | none | Same HeldLock fix; sibling tests assert the inherited-descriptor case |
| 6 | hidden_default_web_search_resolution_is_explicit_and_responses_only | fuigo-shell | YES: 20/20 alone fail, 0/5 bin; after fix 0/30 alone, 0/10 bin | shared global (process trust set seeded first-write-wins by other tests) | ebc34d37 | Failing assertion: "hidden default should still use normal credential resolution" (config_tests.rs:410). Session token only attached to a trusted origin; lone/early run has an empty set |
| 7 | pkce_exchange_uses_attempt_verifier_and_saves_binding | fuigo-shell | not reproduced (0/20 alone, 0/5+10 bin) | unknown | none | Binds port 0 on loopback and uses a local mock; no shared env/HOME seen. Not analysed further |
| 8 | fuigo-tools LSP timing tests | fuigo-tools | not run | timing | none | Listed below |

Note 1. Test asserts (a) the shared unified-log snapshot contains the key fingerprint and (b) no 4-char window of the fake short key appears anywhere in the log. The log is a per-process temp file that every test in the binary writes, so (b) scans other tests' lines too; a random alphanumeric token from another test containing one of 3 windows would fail it (rough chance a few percent per run of a large random-alnum log; not observed). No evidence the probe emits the key: the product line carries only the fingerprint (control assertion passes 40/40). Verdict: NOT a demonstrated leak; most likely TEST-ISOLATION, unreproduced. A deterministic variant would diff the log before/after the probe (not done: budget).

Note 2. Test installs a thread-local tracing subscriber (set_default) on a current-thread runtime and checks 6 fake secrets' 8-char runs are absent from every captured record, plus control assertions. Thread-local, so other tests' output cannot enter the capture. A flake here would more plausibly be a MISSED control record (callsite interest cache against other threads' dispatchers), which fails a control assertion, not the no-secret assertion. Verdict: NOT a demonstrated leak; likely TEST-ISOLATION, unreproduced.

LSP timing tests (crates/codegen/fuigo-tools/src/implementations/lsp/tests.rs), not fixed: WAIT_TIMEOUT 4s poll loops with 10ms sleeps; BRIEF_VERDICT_TTL 150ms and server_patience 80ms (wall-clock windows); drain_lsp_diagnostics 500ms/2s; sleeps of 1100/1200ms at lines ~976, 1006, 1221 that assume a 1s restart backoff; assertion start.elapsed() < 500ms (~1082) and >= 500ms (~1146); restart backoff 1s+2s+4s (~1230). All assume an unloaded host.

Other unlocked tests in fuigo-config signed_policy/tests.rs that call the public wrappers (verification_active gate) are not audited and may share the cause.

Lib suite once per changed crate: fuigo-config 30 bin runs green, fuigo-shell 10 bin runs green at ebc34d37 (post-fix).

## Packet 2 (branch strike/flaky-1024b)

Test code only. No product file changed.

| Item | Change | Evidence (Hetzner, lane flaky2) |
|---|---|---|
| 1 | `verification_armed_with_embedded_key` reads the flag under `with_remote_disarm_lock`; `signed_cache_compromised_is_no_authentic_sidecar_when_armed` holds it across the assert and the call. No re-entrant take found. | 30/30 each alone |
| 2 | Mutex and `with_remote_disarm_lock` moved to `fuigo-config/src/test_support.rs` (`#[cfg(test)]`, crate-visible); taken in `bump_rollback_floor_raises_when_verification_active` (across the tick) and `garbage_claim_without_fail_closed_is_not_imposing` (whole body). | 30/30 each alone |
| 3 | `probe_log_line_holds_a_fingerprint_not_the_key` scans only log lines with the probe's fixed message and this key's fingerprint field. The 4-character-window assertion is unchanged. | 30/30 alone |
| 4 | Sampler test is `#[tokio::test(flavor = "current_thread")]`, and calls `tracing::callsite::rebuild_interest_cache()` after `set_default`. All assertions kept. | 30/30 alone |

Whole-binary repeats: fuigo-config lib 10/10, fuigo-shell lib 10/10 (filtered run of the 8k-test binary), fuigo-sampler lib 10/10. Whole lib suites once: config 454 passed, sampler 352 passed, shell 8227 passed, 0 failed.
Item 3 mutation (lane worktree only, reverted, not committed): adding the key to the probe log line made the test FAIL on the 4-character-window assertion.
Clippy `--locked --all-targets -p fuigo-config -p fuigo-shell -p fuigo-sampler`: exit 0, no warning on changed lines.
Other flag readers left unlocked: tests that only call `with_dark` (thread-local, and `verification_active` is false under a disarm, so `!verification_active()` asserts are safe) and gate tests that read the flag implicitly without asserting on it (for example other `managed_cache` and `signed_policy` armed-path tests); not audited as flaky.
