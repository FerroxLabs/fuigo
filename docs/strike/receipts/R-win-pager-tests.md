# R-win-pager-tests

Goal: `cargo check --locked -p fuigo-pager --tests` compiles on native Windows. Test-only change.

Base: 19085aab (hub/strike/integration).

Errors before: 1 (E0425 `dump_non_system_messages` not found), in the `pty_e2e_minimal` target, file
`crates/codegen/fuigo-pager/tests/pty_e2e/minimal/minimal_switch_mid_turn_keeps_streaming.rs:94`. The helper is
`#[cfg(unix)]` in `tests/pty_e2e/common.rs`; the test using it was ungated. No further waves: all other test targets
already compiled (only warnings).

Gates added: 1 `#[cfg(unix)]` on test fn `minimal_switch_mid_turn_keeps_streaming` (that file). Whole-file gates: none.

Windows results (native lane, `--locked`):
- `check -p fuigo-pager --tests`: exit=0 secs=2 (target already warm from baseline) @ 698891155e89
- `check -p fuigo-pager --lib`: exit=0 secs=128 @ 698891155e89
