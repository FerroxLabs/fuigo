# R-w3a: owner-only modes (tighten only)

Base: integration cd9d3eab. Red tests: efa4ad25 (first red 690fa4ec). Fixes: see git log (items 1-3, release note).

| Item | Site | Before | After | Existing wider file |
|---|---|---|---|---|
| 1 crash dir | fuigo-crash-handler handler.rs `install` (unix) via new `create_crash_dir` | 0755 (umask) | 0700 | tightened by fchmod on an O_NOFOLLOW|O_DIRECTORY handle, only if owned by us; symlink untouched |
| 2a active_sessions.lock | fuigo-active-sessions `open_lock_file` | 0644 | 0600 at creation | opened every call: fstat+fchmod via `tighten_own_regular_file_owner_only` (regular, ours, path is same inode, not a symlink) |
| 2b active_sessions.json | `write_data_file_atomic` | 0644 | 0600 (temp created create_new 0600 before content) | file is replaced by rename on every write, so healed at the next write; a stale/planted tmp is removed first |
| 3 managed_config.lock | fuigo-shell managed_config/store.rs `open_managed_config_lock` | 0644 | 0600 | same helper as 2a |

Directory for items 2: root is the shared Fuigo home; left to its owner (not changed here).
Helper: existing `owner_only_file_options`; one new fn `tighten_own_regular_file_owner_only` in fuigo-config/paths.rs,
because the existing `tighten_file_owner_only` would fchmod a symlink's target.

Exposure closed: active_sessions.json holds session ids, pids and working directories (readable by other local users
before); both lock files hold nothing (empty), the gain is closing a lock-file squat/inspect surface.

SIGHUP crash file (read only): the crash handler registers SIGSEGV/SIGBUS/SIGABRT only (register_crash_signals); the slot
is removed by release_slot / atexit. A bare SIGHUP with default disposition kills the process without atexit, so a
`crash-<pid>-<token>.bin` would remain in a process that only installed this crate. The pager installs its own
SIGINT/SIGTERM/SIGHUP handler (fuigo-pager signal_handler.rs) that routes to a graceful quit; not traced to the slot
removal, not changed. UNVERIFIED by test.

Tests: active-sessions `modes::*` (4), crash-handler `install_creates_owner_only_crash_dir`,
`install_tightens_preexisting_0755_crash_dir`, `install_does_not_chmod_a_symlinked_crash_dir_target`, shell
`lock_modes::*` (3). Red: 6 of 10 failed by assertion at 690fa4ec (symlink tests pass before, as guards).
Green: 3 runs; lib suites of active-sessions, crash-handler, config, shell all ok; clippy clean on my lines.
Guard: fuigo-extra-ca `body_identity_sites_are_exactly_the_reviewed_ones` fails on pager files I did not touch
(not mine, pre-existing at integration); no pinned count changed by me (no new test file).

Unverified: Windows ACLs unchanged (cfg(unix) only); macOS not run.
