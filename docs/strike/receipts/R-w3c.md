# R-w3c: update-check error names the package

Before: `npm view @latest failed: <npm error>` (version.rs `fetch_npm_tag`; no package name).
After:  `npm view fuigo@latest failed: <npm error>` (also `fuigo@alpha`), using the crate's `NPM_PACKAGE` constant.
Display: the check path prints the error through `fuigo_tty_utils::untrusted` (auto_update.rs:185), unchanged; the message
text is only reworded, nothing else changed (no installer, bootstrap, fetch or timing change). The install-path message
(auto_update.rs:2580) already names `{spec}`; the check path now matches it.

Commits: red 47c37dbf (test only), fix 9ab77327 (version.rs one line + release note).
Test: `fuigo-update/tests/test_subprocess.rs::fetch_npm_tag_failure_names_the_package_and_the_tag` (fake failing `npm`).

Evidence (Hetzner lane w3c):
- Red at 47c37dbf: FAILED by assertion `expected npm view fuigo@latest failed in: npm view @latest failed: npm failed without a message`.
- Fix 9ab77327: `--test test_subprocess fetch_npm_tag` 3 runs, 11 passed each; `fuigo-update --lib` 151 passed.
- `cargo clippy --locked --all-targets -p fuigo-update`: exit 0, no warning on changed lines.
- `cargo test -p fuigo-extra-ca`: `identity_body_guard::body_identity_sites_are_exactly_the_reviewed_ones` FAILS on files
  I did not touch (fuigo-pager key_owner_tests.rs 5->6, dispatch/queue.rs 4->5, dispatch/tests/session/load.rs 48->57):
  pre-existing in base cd9d3eab, not caused by this change; needs the P54 table updated by whoever added those sites.

Item 2 (SIGHUP crash file), read-only, no code changed:
- Slot `crash-<pid>-<start>.bin` is deleted by an `atexit` hook (fuigo-crash-handler/src/handler.rs:626, :665).
- The SIGHUP path (fuigo-pager/src/app/signal_handler.rs:89-93, then :191/:205 -> :253) ends in `std::process::exit`,
  which runs atexit, so by reading the slot is removed. A file can remain only if the process dies without exit:
  SIGHUP before the handler is registered (default action), a hung teardown followed by SIGKILL, or a forked child. The next
  launch sweeps dead owners' empty slots (`sweep_dead_slots`, main.rs:2248).
- Reproduction: not attempted. It needs a full pager-bin build plus a provider/TTY; not cheap. Result: could not run.

Unverified: macOS, Windows (Windows does not run atexit; slot is swept at next start).
