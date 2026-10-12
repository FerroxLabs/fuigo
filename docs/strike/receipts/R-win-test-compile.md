# R-win-test-compile

Test-only change: `cfg(unix)` gates so `--lib --tests` compiles on native Windows. No production code changed; no assertion changed.

## fuigo-workspace (10 errors before, 0 after)
- permission/managed_policy_tests.rs: 2 gates (`mkfifo_at`, `replaced_admin_entry_..._p183r10`)
- permission/manager/p175_tests.rs: 1 gate (`p175_item2_partial_clone_check_...`)
- Windows: `check --locked -p fuigo-workspace --lib --tests` exit=0 secs=39 @ 11115b46 (first fix commit)

## fuigo-tools (30 error lines before, 0 after)
- util/mod.rs: 1 (whole `search_proof_tests` module, unix-only fixture/libc/PermissionsExt)
- util/read_deny.rs: `fixture` module now `cfg(all(test, unix))` (symlinks, OsStrExt, PermissionsExt)
- computer/local/terminal.rs: 2 (`test_parse_login_env_capture*`; the parser is `cfg(unix)`)
- tests that use `read_deny::fixture`: codex/grep_files/tool.rs 7, codex/list_dir/tool.rs 1, fuigo_build/grep/mod.rs 7, fuigo_build/list_dir/mod.rs 2, opencode/glob/mod.rs 5, opencode/grep/mod.rs 7
- Windows: `check --locked -p fuigo-tools --lib --tests` exit=0 secs=24 @ 46060f07

## fuigo-pager (not fixed)
`check --locked -p fuigo-pager --tests` exit=101 @ 46060f07: first failure `pty_e2e_minimal`: `dump_non_system_messages` not found (unix-gated helper used from a test). Warnings in several pty_e2e files suggest more errors after this one. Left for a separate task.
