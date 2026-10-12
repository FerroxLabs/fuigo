# R-flux-d-f2: bookkeeping file follow-ups from the Grok flux-d round 1 audit

Files: `auth/api_key_route_memory.rs` (+ `tests.rs`). Base: `hub/strike/integration` 7f3c5972.

## 1. `concurrent_writers_lose_no_401_count` (test-only fix)
- Cause: `update()` waits up to 200 ms for the flock, then proceeds without it (by design: a stuck lock must never
  block a fetch). On a loaded box a writer stalled for a peer's whole 200 ms and ran unlocked, losing a count.
- Product weakness? No. A lost 401 count means the wait for that URL is one step shorter than it should be, i.e. at
  most one extra request to a rejecting endpoint before the table catches up. It never wrongly clears a wait, and
  needs a 200 ms stall of a lock holder that normally holds it for microseconds.
- Fix: `test_clock::LOCK_WAIT_MS` (test-only) lets this test raise the give-up to 120 s, so no writer can give up; the
  `unlocked_updates()` counter (already recording an `update` that ran without the lock) is asserted to be 0 with a
  "MISSED LOCK" message before the counts. A real lost update under the lock still fails `n == 200`.
- Proof: 200 consecutive runs of the test binary on Hetzner (lane fld2) with 24 busy loops running, host load
  average about 55 on 96 cores: 200 ok, 0 failed.

## 2. UNSAVED row cleared by another process (LOW)
Rule (also in the code comment): a row kept in memory because our write failed is dropped after a SUCCESSFUL read of
the file that lacks it, but only when the file's (modified time, length) differs from the stamp taken when our write
failed. A changed file is another process's newer truth. An unchanged file, a missing or unreadable one, proves
nothing (our write failed and nobody else wrote), so the row stays. Cost of the rule: if another process rewrote the
file for an unrelated reason it also drops our row, a one-request loosening that the next 401 re-creates.
Red/green: `a_row_another_process_cleared_is_dropped_after_a_good_read` FAILED with the drop disabled, passes with it;
`a_row_nobody_cleared_stays_when_the_file_is_unchanged` passes both ways.

## 3. Windows lock file ACL (NOTE)
A lock file we just created gets `fuigo_secrets::owner_only::set_windows_owner_only_acl` (the helper `save` uses for the
data file), under `#[cfg(windows)]`; unix keeps 0600 via `owner_only_file_options`. UNRUN: not compiled or run on
Windows.

## Runs (Hetzner, lane fld2)
`api_key_route_memory` 6/6, `persist_401` 14/14, `fuigo-extra-ca` all ok, clippy fuigo-shell lib+tests: no
warnings in touched files. `fuigo-auth --test secret_debug_guard`: 1 FAILED, pre-existing and unrelated:
`leader/peer_auth.rs::PeerFacts::peer_token` derives Debug (file not touched here).
